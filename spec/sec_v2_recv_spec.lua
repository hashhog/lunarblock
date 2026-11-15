--- Security regression: BIP324 v2 receive path must drain every complete
-- packet from each read and keep its receive buffer bounded.
--
-- Finding H8 (fleet security audit, 2026-11-08): V2Transport:recv_bytes
-- stopped after ONE application packet (state APP_READY) and only resumed on
-- the next call, while Peer:recv_messages read up to 64 KB per tick. A peer
-- streaming small packets (a 29-byte ping is a full v2 packet) therefore
-- made us decode ~1 packet per tick and append ~2,000 more to recv_buffer,
-- which grew without bound and was re-concatenated / re-sliced (O(n) per
-- packet) every tick.
--
-- Core: CNode::ReceiveMsgBytes (net.cpp) loops `while (msg_bytes.size() > 0)`
-- over V2Transport::ReceivedBytes, moving every complete message out per read,
-- and V2Transport only ever buffers the packet currently being received.
--
-- These specs feed 10,000 small packets in a few reads and require that all
-- complete packets are decoded after each read and the leftover undecoded
-- buffer stays below one packet.

describe("BIP324 v2 receive drain (sec H8)", function()
  local bip324
  local peer_mod
  local consensus

  setup(function()
    package.path = "src/?.lua;" .. package.path
    bip324 = require("lunarblock.bip324")
    peer_mod = require("lunarblock.peer")
    consensus = require("lunarblock.consensus")
  end)

  local magic = "\xf9\xbe\xb4\xd9"
  local N = 10000

  local function must(ok, err)
    assert.is_true(ok, tostring(err))
  end

  -- Handshaked initiator/responder pair, both in APP state.
  local function pair()
    local i = bip324.V2Transport(magic, true)
    local r = bip324.V2Transport(magic, false)
    local i_hs, r_hs = i:get_handshake_bytes(), r:get_handshake_bytes()
    must(r:recv_bytes(i_hs))
    must(i:recv_bytes(r_hs))
    must(r:recv_bytes(i:make_version_packet()))
    must(i:recv_bytes(r:make_version_packet()))
    assert.equals(bip324.RecvState.APP, r.recv_state)
    return i, r
  end

  -- Undecoded bytes the transport is holding (buffer + any pending chunks).
  local function held(t)
    return #t.recv_buffer - ((t.recv_pos or 1) - 1) + (t.recv_pending_len or 0)
  end

  local function ping_payload(k)
    -- 8-byte nonce, distinct per packet so order can be checked.
    return string.format("%08d", k)
  end

  local function build_stream(i)
    local parts = {}
    for k = 1, N do
      parts[k] = i:encrypt_message("ping", ping_payload(k))
    end
    return table.concat(parts), #parts[1]
  end

  it("decodes every complete packet from each read; buffer stays below one packet", function()
    local i, r = pair()
    local stream, pkt = build_stream(i)
    assert.equals(N * pkt, #stream)

    local reads = 5
    local chunk = math.ceil(#stream / reads)
    local got = 0
    local fed = 0
    for c = 1, reads do
      local data = stream:sub((c - 1) * chunk + 1, c * chunk)
      fed = fed + #data
      must(r:recv_bytes(data))
      while r:message_ready() do
        local cmd, payload = r:get_message()
        got = got + 1
        assert.equals("ping", cmd)
        assert.equals(ping_payload(got), payload)
      end
      local complete = math.floor(fed / pkt)
      assert.equals(complete, got,
        string.format("read %d: %d complete packets fed, %d decoded", c, complete, got))
      assert.is_true(held(r) < pkt,
        string.format("read %d: %d undecoded bytes held, bound %d", c, held(r), pkt))
    end
    assert.equals(N, got)
  end)

  it("Peer:recv_messages returns all packets of each 64 KB read", function()
    local i, r = pair()
    local stream, pkt = build_stream(i)
    local mainnet = consensus.networks.mainnet
    local p = peer_mod.new("127.0.0.1", 0, mainnet, 0, true)
    p.state = peer_mod.STATE.CONNECTED
    p.v2_transport = r
    p.v2_active = true
    local pos = 1
    p.socket = {
      receive = function(_, n)
        if pos > #stream then return nil, "timeout", "" end
        local data = stream:sub(pos, pos + n - 1)
        pos = pos + #data
        return data
      end,
      close = function() end,
    }
    local got = 0
    local ticks = 0
    while pos <= #stream do
      ticks = ticks + 1
      assert.is_true(ticks <= 10, "too many ticks")
      local msgs = p:recv_messages()
      got = got + #msgs
      assert.equals(math.floor((pos - 1) / pkt), got,
        "tick " .. ticks .. ": not every complete packet was returned")
      assert.is_true(held(r) < pkt, "tick " .. ticks .. ": " .. held(r) .. " bytes held")
      assert.equals(0, #p.recv_buffer)
    end
    assert.equals(N, got)
    assert.is_true(ticks <= 5, "10,000 x 29-byte packets must fit in 5 reads")
  end)

  it("handshake, version and app packets coalesced in one read all decode", function()
    local i = bip324.V2Transport(magic, true)
    local r = bip324.V2Transport(magic, false)
    local i_hs, r_hs = i:get_handshake_bytes(), r:get_handshake_bytes()
    must(i:recv_bytes(r_hs))
    local wire = i_hs .. i:make_version_packet()
      .. i:encrypt_message("ping", "aaaaaaaa")
      .. i:encrypt_message("pong", "bbbbbbbb")
      .. i:encrypt_message("sendheaders", "")
    must(r:recv_bytes(wire))
    assert.equals(bip324.RecvState.APP, r.recv_state)
    local cmds = {}
    while r:message_ready() do
      local cmd, payload = r:get_message()
      cmds[#cmds + 1] = cmd .. ":" .. payload
    end
    assert.same({"ping:aaaaaaaa", "pong:bbbbbbbb", "sendheaders:"}, cmds)
    assert.equals(0, held(r))
  end)

  it("a large packet split across many small reads decodes once complete", function()
    local i, r = pair()
    local big = string.rep("\x5a", 1000000)
    local wire = i:encrypt_message("block", big) .. i:encrypt_message("ping", "cccccccc")
    local step = 4096
    local got = {}
    for off = 1, #wire, step do
      must(r:recv_bytes(wire:sub(off, off + step - 1)))
      while r:message_ready() do
        local cmd, payload = r:get_message()
        got[#got + 1] = {cmd, payload}
      end
    end
    assert.equals(2, #got)
    assert.equals("block", got[1][1])
    assert.is_true(got[1][2] == big, "block payload must round-trip")
    assert.same({"ping", "cccccccc"}, got[2])
    assert.equals(0, held(r))
  end)

  it("tampered packet in a coalesced read still fails the read", function()
    local i, r = pair()
    local a = i:encrypt_message("ping", "dddddddd")
    local b = i:encrypt_message("ping", "eeeeeeee")
    local bad = b:sub(1, #b - 1) .. string.char((b:byte(#b) + 1) % 256)
    local ok = r:recv_bytes(a .. bad)
    assert.is_false(ok, "AEAD failure in the second packet must fail recv_bytes")
  end)
end)
