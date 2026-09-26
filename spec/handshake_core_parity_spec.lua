-- Handshake Core-parity (bitcoin-core/src/net_processing.cpp VERSION handling
-- ~3600-3700 and the pre-verack dispatch ~3890-4015).
--
--   * The ONLY version floor is MIN_PEER_PROTO_VERSION = 31800 (:3619), for
--     every peer.  lunarblock used a hard-coded 70015 in both directions.
--   * The desirable-services (NODE_WITNESS) requirement applies only to
--     automatic OUTBOUND peers (:3610, ExpectServicesFromConn).
--   * Between VERSION and VERACK Core PROCESSES version/verack/wtxidrelay/
--     sendaddrv2/sendtxrcncl/sendheaders/sendcmpct and LOGS AND IGNORES every
--     other message (:4010) — no disconnect, no misbehaviour.
--   * Post-verack feature messages are gated on the common version
--     (sendcmpct >= 70014, sendheaders >= 70012, feefilter >= 70013).
--   * Block bodies are only requested from peers that can serve witnesses
--     (Core CanServeWitnesses, :1501 / :1969).

local peer_module = require("lunarblock.peer")
local p2p = require("lunarblock.p2p")
local consensus = require("lunarblock.consensus")

local regtest = consensus.networks.regtest

-- Mock socket that records what the peer sends and never has data to read
-- (we inject bytes via recv_buffer).
local function mock_socket()
  local s = { sent = {}, closed = false }
  function s:send(data) self.sent[#self.sent + 1] = data; return #data end
  function s:receive() return nil, "timeout", "" end
  function s:close() self.closed = true end
  function s:settimeout() end
  return s
end

-- Commands the peer has written to the mock socket (v1 framing).
local function sent_commands(sock)
  local out = {}
  for _, raw in ipairs(sock.sent) do
    local pos = 1
    while pos + 23 <= #raw do
      local cmd = raw:sub(pos + 4, pos + 15):gsub("%z+$", "")
      local len = raw:byte(pos + 16) + raw:byte(pos + 17) * 256
                + raw:byte(pos + 18) * 65536 + raw:byte(pos + 19) * 16777216
      out[#out + 1] = cmd
      pos = pos + 24 + len
    end
  end
  return out
end

local function has(list, x)
  for _, v in ipairs(list) do if v == x then return true end end
  return false
end

local function version_msg(version, services)
  local payload = p2p.serialize_version({
    version = version,
    services = services,
    timestamp = os.time(),
    recv_services = 0,
    recv_ip = "127.0.0.1",
    recv_port = 0,
    from_services = services,
    from_ip = "0.0.0.0",
    from_port = 0,
    nonce = 424242,
    user_agent = "/test/",
    start_height = 0,
    relay = true,
  })
  return p2p.make_message(regtest.magic_bytes, "version", payload)
end

local function msg(cmd, payload)
  return p2p.make_message(regtest.magic_bytes, cmd, payload or "")
end

-- An inbound v1 peer that has just been accepted (Core: inbound waits for the
-- remote VERSION first).
local function new_inbound()
  local p = peer_module.new("127.0.0.1", 50000, regtest, 0, false)
  p.inbound = true
  p.state = peer_module.STATE.CONNECTED
  p.socket = mock_socket()
  return p
end

-- An automatic outbound v1 peer that has already sent its VERSION.
local function new_outbound()
  local p = peer_module.new("127.0.0.1", 18444, regtest, 0, false)
  p.state = peer_module.STATE.VERSION_SENT
  p.socket = mock_socket()
  return p
end

describe("handshake Core parity", function()
  describe("minimum peer version", function()
    it("an inbound VERSION(70002) completes the handshake", function()
      local p = new_inbound()
      p.recv_buffer = version_msg(70002, 1)  -- NODE_NETWORK only, no witness
      p:process_messages()
      assert.are_not.equal(peer_module.STATE.DISCONNECTED, p.state)
      assert.is_true(p.version_received)
      assert.equal(70002, p.common_version)
      local cmds = sent_commands(p.socket)
      assert.is_true(has(cmds, "version"))
      assert.is_true(has(cmds, "verack"))
      -- BIP155: no sendaddrv2 below 70016 (Core :3716).
      assert.is_false(has(cmds, "sendaddrv2"))

      p.recv_buffer = msg("verack")
      p:process_messages()
      assert.is_true(p.handshake_complete)
      assert.equal(peer_module.STATE.ESTABLISHED, p.state)
    end)

    it("never sends a 70002 peer sendheaders/sendcmpct/feefilter", function()
      local p = new_inbound()
      p.recv_buffer = version_msg(70002, 1) .. msg("verack")
      p:process_messages()
      assert.is_true(p.handshake_complete)
      local cmds = sent_commands(p.socket)
      assert.is_false(has(cmds, "sendheaders"))   -- needs 70012
      assert.is_false(has(cmds, "feefilter"))     -- needs 70013
      assert.is_false(has(cmds, "sendcmpct"))     -- needs 70014
    end)

    it("gates each post-verack feature message on the common version", function()
      -- 70012: sendheaders only.  70013: + feefilter.  70014: + sendcmpct.
      local expect = {
        [70012] = { sendheaders = true,  feefilter = false, sendcmpct = false },
        [70013] = { sendheaders = true,  feefilter = true,  sendcmpct = false },
        [70014] = { sendheaders = true,  feefilter = true,  sendcmpct = true  },
        [70016] = { sendheaders = true,  feefilter = true,  sendcmpct = true  },
      }
      for ver, want in pairs(expect) do
        local p = new_inbound()
        p.recv_buffer = version_msg(ver, 9) .. msg("verack")
        p:process_messages()
        assert.is_true(p.handshake_complete, "handshake for " .. ver)
        local cmds = sent_commands(p.socket)
        for cmd, present in pairs(want) do
          assert.equal(present, has(cmds, cmd), cmd .. " at version " .. ver)
        end
        assert.equal(ver >= 70016, has(cmds, "sendaddrv2"), "sendaddrv2 at " .. ver)
      end
    end)

    it("disconnects below MIN_PEER_PROTO_VERSION (31800), both directions", function()
      assert.equal(31800, peer_module.MIN_PEER_PROTO_VERSION)
      local p = new_inbound()
      p.recv_buffer = version_msg(31799, 9)
      p:process_messages()
      assert.equal(peer_module.STATE.DISCONNECTED, p.state)
      assert.is_truthy(p.disconnect_reason:find("obsolete version"))

      local o = new_outbound()
      o.recv_buffer = version_msg(31799, 9)
      o:process_messages()
      assert.equal(peer_module.STATE.DISCONNECTED, o.state)

      local ok = new_inbound()
      ok.recv_buffer = version_msg(31800, 1)
      ok:process_messages()
      assert.are_not.equal(peer_module.STATE.DISCONNECTED, ok.state)
    end)

    it("an outbound 70002 witness peer completes the handshake", function()
      local o = new_outbound()
      o.recv_buffer = version_msg(70002, 9) .. msg("verack")
      o:process_messages()
      assert.is_true(o.handshake_complete)
      assert.is_false(has(sent_commands(o.socket), "sendheaders"))
    end)
  end)

  describe("desirable services (outbound only)", function()
    it("keeps an inbound peer that lacks NODE_WITNESS", function()
      local p = new_inbound()
      p.recv_buffer = version_msg(70016, 1) .. msg("verack")
      p:process_messages()
      assert.is_true(p.handshake_complete)
    end)

    it("drops an automatic outbound peer that lacks NODE_WITNESS", function()
      local o = new_outbound()
      o.recv_buffer = version_msg(70016, 1)
      o:process_messages()
      assert.equal(peer_module.STATE.DISCONNECTED, o.state)
      assert.is_truthy(o.disconnect_reason:find("expected services"))
    end)

    it("exempts manual (-connect/-addnode) and feeler outbound peers", function()
      local m = new_outbound(); m.is_manual = true
      m.recv_buffer = version_msg(70016, 1) .. msg("verack")
      m:process_messages()
      assert.is_true(m.handshake_complete)

      local f = new_outbound(); f.is_feeler = true
      f.recv_buffer = version_msg(70016, 1) .. msg("verack")
      f:process_messages()
      assert.is_true(f.handshake_complete)
    end)

    it("accepts NODE_NETWORK_LIMITED|NODE_WITNESS outbound", function()
      local o = new_outbound()
      o.recv_buffer = version_msg(70016, 1024 + 8) .. msg("verack")
      o:process_messages()
      assert.is_true(o.handshake_complete)
    end)
  end)

  describe("messages between VERSION and VERACK", function()
    it("records a pre-verack sendheaders and does not disconnect", function()
      local p = new_inbound()
      p.recv_buffer = version_msg(70016, 9) .. msg("sendheaders")
      p:process_messages()
      assert.are_not.equal(peer_module.STATE.DISCONNECTED, p.state)
      assert.is_false(p.handshake_complete)
      assert.is_true(p.send_headers)
      assert.equal(0, p.ban_score)
    end)

    it("records a pre-verack sendcmpct (version 2) and does not disconnect", function()
      local p = new_inbound()
      p.recv_buffer = version_msg(70016, 9)
        .. msg("sendcmpct", p2p.serialize_sendcmpct(true, 2))
      p:process_messages()
      assert.are_not.equal(peer_module.STATE.DISCONNECTED, p.state)
      assert.is_true(p.provides_compact)
      assert.is_true(p.high_bandwidth)
    end)

    it("ignores pre-verack ping/inv without disconnecting (no cap)", function()
      local p = new_inbound()
      local handled = {}
      p:on("inv", function() handled[#handled + 1] = "inv" end)
      local buf = version_msg(70016, 9)
      for i = 1, 50 do
        buf = buf .. msg("ping", p2p.serialize_ping(i)) .. msg("inv", "\0")
          .. msg("feefilter", p2p.serialize_feefilter(1000))
          .. msg("getheaders", "")
      end
      p.recv_buffer = buf
      local processed = p:process_messages()
      assert.are_not.equal(peer_module.STATE.DISCONNECTED, p.state)
      assert.equal(0, p.ban_score)
      assert.equal(1, #processed)             -- only the version
      assert.equal(0, #handled)               -- inv never dispatched
      assert.equal(0, p.fee_filter)           -- feefilter ignored pre-verack
      assert.is_false(has(sent_commands(p.socket), "pong"))  -- ping ignored

      -- The handshake still completes afterwards.
      p.recv_buffer = msg("verack") .. msg("ping", p2p.serialize_ping(7))
      p:process_messages()
      assert.is_true(p.handshake_complete)
      assert.is_true(has(sent_commands(p.socket), "pong"))
    end)

    it("ignores non-version messages before VERSION without disconnecting", function()
      local p = new_inbound()
      p.recv_buffer = msg("ping", p2p.serialize_ping(1)) .. msg("inv", "\0")
      local processed = p:process_messages()
      assert.are_not.equal(peer_module.STATE.DISCONNECTED, p.state)
      assert.equal(0, #processed)
      assert.equal(0, p.ban_score)
      assert.is_false(p.version_received)
      -- A later VERSION is still accepted.
      p.recv_buffer = version_msg(70016, 9)
      p:process_messages()
      assert.is_true(p.version_received)
    end)

    it("ignores wtxidrelay when the common version is below 70016", function()
      local p = new_inbound()
      p.recv_buffer = version_msg(70015, 9) .. msg("wtxidrelay")
      p:process_messages()
      assert.are_not.equal(peer_module.STATE.DISCONNECTED, p.state)
      assert.is_false(p.wtxid_relay)

      local q = new_inbound()
      q.recv_buffer = version_msg(70016, 9) .. msg("wtxidrelay")
      q:process_messages()
      assert.is_true(q.wtxid_relay)
    end)
  end)

  describe("block download only from witness peers (CanServeWitnesses)", function()
    it("peer:can_serve_witnesses follows NODE_WITNESS", function()
      local p = new_inbound()
      p.recv_buffer = version_msg(70002, 1)
      p:process_messages()
      assert.is_false(p:can_serve_witnesses())
      local q = new_inbound()
      q.recv_buffer = version_msg(70016, 9)
      q:process_messages()
      assert.is_true(q:can_serve_witnesses())
    end)

    it("sync.witness_capable_peers drops non-witness peers", function()
      local sync = require("lunarblock.sync")
      local a, b, c = { services = 1 }, { services = 9 }, { services = 1024 + 8 }
      local out = sync.witness_capable_peers({ a, b, c, {} })
      assert.equal(2, #out)
      assert.equal(b, out[1])
      assert.equal(c, out[2])
    end)
  end)
end)
