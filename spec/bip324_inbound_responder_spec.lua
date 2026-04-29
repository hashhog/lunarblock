--- Regression test for BIP-324 v2 INBOUND (responder) handshake.
--
-- Background: prior to this change, lunarblock accepted inbound TCP
-- connections, set the new Peer to STATE.CONNECTED with use_v2=true,
-- but NEVER initialized a V2Transport for the inbound side.  An
-- incoming v2 peer would send 64 bytes of ElligatorSwift pubkey,
-- which lunarblock would parse as a v1 message header — fail the
-- magic check — and disconnect.  As a result, the BIP-324 v2 inbound
-- path was dead code.  See clearbit/src/peer.zig:899-930 for the
-- reference responder pattern (peek 16 bytes, classify v1 vs v2).
--
-- This test exercises the new wiring:
--   1. bip324.looks_like_v1: pure classifier — non-v1 ellswift bytes
--      must NOT be misclassified as v1.
--   2. drive_inbound_v2_handshake on a v2 peer: peek classifier sees
--      random ellswift pubkey, sends our pubkey+garbage on the wire,
--      transitions Peer state to V2_KEY_SENT.
--   3. drive_inbound_v2_handshake on a v1 peer: peek classifier sees
--      magic+"version\0\0\0\0\0", tears down v2_transport, leaves
--      bytes in recv_buffer for the v1 parser, no v2 bytes sent.
--   4. Full responder handshake in-process: pair an OUTBOUND-style
--      V2Transport (initiator=true) against a Peer in responder mode
--      and drive both sides over a TCP socket pair.  Verify the Peer
--      reaches STATE.CONNECTED with v2_active=true.

local socket = require("socket")

describe("BIP-324 v2 inbound responder", function()
  local bip324
  local peer_mod
  local p2p
  local consensus

  setup(function()
    package.path = "src/?.lua;" .. package.path
    bip324 = require("lunarblock.bip324")
    peer_mod = require("lunarblock.peer")
    p2p = require("lunarblock.p2p")
    consensus = require("lunarblock.consensus")
  end)

  -- Helper: create a TCP socket pair (server accepts client, returns
  -- (client_side, server_side)).  Both ends are non-blocking.
  local function tcp_pair()
    local listen = socket.tcp()
    listen:setoption("reuseaddr", true)
    local port = 19500
    while true do
      local ok = listen:bind("127.0.0.1", port)
      if ok then break end
      port = port + 1
      assert(port < 19600, "no free port for tcp_pair")
    end
    listen:listen(1)
    listen:settimeout(1)
    local client = socket.tcp()
    client:settimeout(0.5)
    assert(client:connect("127.0.0.1", port))
    local server, err = listen:accept()
    assert(server, "accept failed: " .. tostring(err))
    listen:close()
    client:settimeout(0)
    server:settimeout(0)
    return client, server
  end

  -- Helper: drain a non-blocking socket into a string buffer.
  local function read_some(sock, deadline_s)
    local buf = ""
    local end_time = socket.gettime() + (deadline_s or 0.5)
    while socket.gettime() < end_time do
      local data, err, partial = sock:receive(65536)
      data = data or partial
      if data and #data > 0 then
        buf = buf .. data
      elseif err == "closed" then
        break
      end
      if #buf > 0 then
        -- Allow a brief settle to coalesce kernel-side framing.
        socket.sleep(0.005)
        local more, _, mp = sock:receive(65536)
        more = more or mp
        if more and #more > 0 then buf = buf .. more end
        break
      end
      socket.sleep(0.01)
    end
    return buf
  end

  describe("bip324.looks_like_v1 classifier", function()
    it("recognizes a v1 mainnet version-message prefix", function()
      local prefix = "\xf9\xbe\xb4\xd9" .. "version\0\0\0\0\0"
      assert.is_true(bip324.looks_like_v1(prefix))
    end)

    it("recognizes a v1 testnet/regtest version-message prefix", function()
      -- Magic doesn't matter; only the command field is checked.
      local prefix = "\xfa\xbf\xb5\xda" .. "version\0\0\0\0\0"
      assert.is_true(bip324.looks_like_v1(prefix))
    end)

    it("rejects a 64-byte ellswift pubkey (random non-version bytes)", function()
      -- Repeat: 8 bytes A8 + 8 bytes 5C ... — definitely not "version\0\0\0\0\0".
      local prefix = string.rep("\xa8", 8) .. string.rep("\x5c", 8)
      assert.is_false(bip324.looks_like_v1(prefix))
    end)

    it("rejects a v1 prefix with the wrong command field", function()
      -- "verackXX..." is not "version\0\0\0\0\0".
      local prefix = "\xf9\xbe\xb4\xd9" .. "verack\0\0\0\0\0\0"
      assert.is_false(bip324.looks_like_v1(prefix))
    end)

    it("returns false on too-short input", function()
      assert.is_false(bip324.looks_like_v1(""))
      assert.is_false(bip324.looks_like_v1("short"))
      assert.is_false(bip324.looks_like_v1("0123456789abcde"))  -- 15 bytes
    end)
  end)

  describe("drive_inbound_v2_handshake (peek-and-classify)", function()
    local mainnet

    before_each(function()
      mainnet = consensus.networks.mainnet
    end)

    it("classifies v1 peer: tears down v2_transport, no v2 bytes sent", function()
      local client, server = tcp_pair()
      -- Build an inbound Peer like peerman:accept_inbound does.
      local p = peer_mod.new("127.0.0.1", 0, mainnet, 0, true)
      p.socket = server
      p.inbound = true
      p.state = peer_mod.STATE.CONNECTED
      p.v2_transport = bip324.V2Transport(mainnet.magic_bytes, false, "127.0.0.1", 0)
      assert.is_not_nil(p.v2_transport, "responder V2Transport must be constructed")
      assert.is_false(p.v2_handshake_started)

      -- Simulate a v1-only inbound: peer sends a v1 VERSION header.
      local v1_prefix = mainnet.magic_bytes .. "version\0\0\0\0\0"
      assert(client:send(v1_prefix))

      -- Drive the classifier.
      p:drive_inbound_v2_handshake()

      assert.is_true(p.v2_handshake_started, "classifier must mark started")
      assert.is_nil(p.v2_transport, "v2_transport must be torn down on v1")
      assert.is_false(p.use_v2, "use_v2 must be cleared on v1 fallback")
      -- recv_buffer keeps the bytes for the v1 parser.
      assert.equals(v1_prefix, p.recv_buffer)
      -- State stays CONNECTED so the v1 message-parse path takes over.
      assert.equals(peer_mod.STATE.CONNECTED, p.state)

      -- Critical: the responder must NOT have sent any v2 bytes (would
      -- corrupt v1 framing on the remote and trigger a ban).
      local got = read_some(client, 0.1)
      assert.equals("", got, "no bytes should be sent to a v1 peer; got " .. #got)

      client:close()
      server:close()
    end)

    it("classifies v2 peer: sends our pubkey+garbage, advances to V2_KEY_SENT", function()
      local client, server = tcp_pair()
      local p = peer_mod.new("127.0.0.1", 0, mainnet, 0, true)
      p.socket = server
      p.inbound = true
      p.state = peer_mod.STATE.CONNECTED
      p.v2_transport = bip324.V2Transport(mainnet.magic_bytes, false, "127.0.0.1", 0)

      -- Simulate the peer sending its 64-byte ellswift pubkey + small
      -- garbage.  We construct an initiator-side V2Transport in this
      -- test process so the bytes are valid ellswift output (not just
      -- random — though a non-version 16-byte prefix would also work
      -- for the classifier alone).
      local peer_init = bip324.V2Transport(mainnet.magic_bytes, true, "127.0.0.1", 0)
      local peer_hs_bytes = peer_init:get_handshake_bytes()
      assert.is_true(#peer_hs_bytes >= 64)
      assert(client:send(peer_hs_bytes))

      -- Drive: classifier should see non-v1 prefix, send our handshake,
      -- and transition state to V2_KEY_SENT.
      p:drive_inbound_v2_handshake()

      assert.is_true(p.v2_handshake_started)
      assert.is_not_nil(p.v2_transport, "v2_transport must remain on v2 path")
      assert.equals(peer_mod.STATE.V2_KEY_SENT, p.state,
        "must transition to V2_KEY_SENT after sending pubkey+garbage")

      -- Our 64-byte ellswift + garbage must have been written to the wire.
      local got = read_some(client, 0.5)
      assert.is_true(#got >= 64,
        "responder must send at least 64 bytes of ellswift; got " .. #got)
      -- First 64 bytes should equal our V2Transport's pubkey.
      local our_pubkey = p.v2_transport.cipher.our_ellswift
      assert.equals(64, #our_pubkey)
      assert.equals(our_pubkey, got:sub(1, 64),
        "first 64 bytes of wire output must be our ellswift pubkey")

      client:close()
      server:close()
    end)

    it("idempotent: second call after start does not re-send pubkey", function()
      local client, server = tcp_pair()
      local p = peer_mod.new("127.0.0.1", 0, mainnet, 0, true)
      p.socket = server
      p.inbound = true
      p.state = peer_mod.STATE.CONNECTED
      p.v2_transport = bip324.V2Transport(mainnet.magic_bytes, false, "127.0.0.1", 0)

      local peer_init = bip324.V2Transport(mainnet.magic_bytes, true, "127.0.0.1", 0)
      assert(client:send(peer_init:get_handshake_bytes()))

      p:drive_inbound_v2_handshake()
      assert.is_true(p.v2_handshake_started)
      local first_recv = read_some(client, 0.3)
      assert.is_true(#first_recv >= 64)

      -- Calling again must be a no-op (one-shot guard).  Don't crash,
      -- don't re-send.
      p:drive_inbound_v2_handshake()
      local second_recv = read_some(client, 0.1)
      assert.equals("", second_recv,
        "second call must not write any bytes; got " .. #second_recv)

      client:close()
      server:close()
    end)

    it("waits for 16 bytes before classifying (no early send)", function()
      local client, server = tcp_pair()
      local p = peer_mod.new("127.0.0.1", 0, mainnet, 0, true)
      p.socket = server
      p.inbound = true
      p.state = peer_mod.STATE.CONNECTED
      p.v2_transport = bip324.V2Transport(mainnet.magic_bytes, false, "127.0.0.1", 0)

      -- Send only 8 bytes (less than V1_PREFIX_LEN=16).
      assert(client:send(string.rep("\xab", 8)))

      p:drive_inbound_v2_handshake()
      -- Classifier should NOT have committed to either path yet.
      assert.is_false(p.v2_handshake_started,
        "must not classify with <16 bytes peeked")
      assert.equals(peer_mod.STATE.CONNECTED, p.state)
      -- And no bytes should be sent yet.
      local got = read_some(client, 0.1)
      assert.equals("", got)

      client:close()
      server:close()
    end)
  end)

  describe("end-to-end inbound v2 handshake via process_messages", function()
    local mainnet

    before_each(function()
      mainnet = consensus.networks.mainnet
    end)

    it("responder reaches v2_active=true with full cipher handshake", function()
      -- Pair an in-process initiator V2Transport (driving the wire from
      -- the "client" side) against an inbound Peer in responder mode.
      -- Walk both sides forward by alternating reads/writes, exactly
      -- as the lunarblock event loop would tick process_messages.
      local client, server = tcp_pair()

      -- Inbound peer setup mirrors peerman.accept_inbound.
      local p = peer_mod.new("127.0.0.1", 0, mainnet, 0, true)
      p.socket = server
      p.inbound = true
      p.state = peer_mod.STATE.CONNECTED
      p.v2_transport = bip324.V2Transport(mainnet.magic_bytes, false, "127.0.0.1", 0)

      -- Initiator side: build a V2Transport, send pubkey+garbage.
      local init = bip324.V2Transport(mainnet.magic_bytes, true, "127.0.0.1", 0)
      local init_hs = init:get_handshake_bytes()
      assert(client:send(init_hs))

      -- Tick 1: inbound peer peeks 16 bytes, classifies non-v1, sends our
      -- pubkey+garbage (transitioning to V2_KEY_SENT), falls through to
      -- the V2_KEY_SENT branch which feeds whatever else is in
      -- recv_buffer to V2Transport, runs cipher init, and may send the
      -- garbage_terminator+version packet — landing in V2_READY.  Either
      -- intermediate state is valid mid-handshake; assert progress.
      p:process_messages()
      assert.is_true(
        p.state == peer_mod.STATE.V2_KEY_SENT
        or p.state == peer_mod.STATE.V2_READY,
        "expected V2_KEY_SENT or V2_READY, got " .. tostring(p.state))

      -- Initiator reads responder's pubkey+garbage off the wire (may also
      -- include garbage_terminator+version_packet if responder advanced
      -- to V2_READY in tick 1).
      local resp_hs = read_some(client, 0.5)
      assert.is_true(#resp_hs >= 64,
        "should receive responder's >=64-byte ellswift; got " .. #resp_hs)

      -- Initiator processes responder's bytes.  This advances its
      -- recv_state past KEY (cipher initialized) and send_state to READY.
      local ok, err = init:recv_bytes(resp_hs)
      assert.is_true(ok, "initiator recv_bytes failed: " .. tostring(err))
      assert.is_true(init.cipher.initialized)

      -- Initiator sends its garbage_terminator + version packet.
      local init_vp = init:make_version_packet()
      assert(client:send(init_vp))

      -- Tick 2: inbound peer reads initiator's version packet.  At this
      -- point the responder must have already queued + sent its own
      -- version packet (made by process_v2_handshake when ready_to_send).
      -- After consuming the initiator's garb_term + version, recv_state
      -- advances to APP and the responder transitions to CONNECTED with
      -- v2_active=true.  We may need 1-2 ticks for everything to drain;
      -- loop with a timeout.
      local deadline = socket.gettime() + 3.0
      while socket.gettime() < deadline and not p.v2_active do
        p:process_messages()
        if p.state == peer_mod.STATE.DISCONNECTED then break end
        socket.sleep(0.01)
        -- Initiator drains anything the responder sent in the meantime.
        local more = read_some(client, 0.05)
        if more and #more > 0 then
          assert.is_true(init:recv_bytes(more))
        end
      end

      assert.is_true(p.v2_active,
        "responder peer must reach v2_active=true within deadline (state="
          .. tostring(p.state) .. ")")
      assert.equals(peer_mod.STATE.CONNECTED, p.state,
        "responder state after v2 handshake must be CONNECTED (await peer version)")
      assert.is_not_nil(p.session_id)
      assert.equals(32, #p.session_id)
      -- Both sides must have derived the same session ID.
      assert.equals(init:get_session_id(), p.session_id,
        "session IDs must match across initiator+responder")

      client:close()
      p:disconnect("test cleanup")
    end)
  end)
end)
