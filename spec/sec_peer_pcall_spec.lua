-- spec/sec_peer_pcall_spec.lua
--
-- Security finding C5 (fleet security findings, 2026-11-08): one peer that
-- sends a malformed `version` (or `ping`) aborts every P2P tick.
--
-- The built-in handlers in Peer:process_messages (version / verack / ping /
-- pong / sendcmpct / feefilter / sendtxrcncl) ran outside _safe_dispatch, and
-- PeerManager:tick had no per-peer pcall.  p2p.deserialize_version on a short
-- payload hit serialize's read assert, the error unwound out of tick(), and
-- every peer after the offender plus all maintenance (handshake timeouts,
-- trickle, outbound maintenance) was skipped -- on every tick, for as long as
-- the peer kept the bytes coming.
--
-- Core: ProcessMessages wraps ProcessMessage in try/catch per message
-- (net_processing.cpp:5180-5198), so a deserialization failure is confined to
-- the message that caused it and the message handler thread moves on to the
-- next peer.  lunarblock's existing convention for a handler that raises
-- (Peer._safe_dispatch) is to disconnect the sender; this spec holds the
-- built-in handlers and the tick loop to the same rule.

package.path = "src/?.lua;" .. package.path

local peer_module = require("lunarblock.peer")
local peerman = require("lunarblock.peerman")
local p2p = require("lunarblock.p2p")
local consensus = require("lunarblock.consensus")

local regtest = consensus.networks.regtest
local STATE = peer_module.STATE

local function mock_socket()
  local s = { sent = {}, closed = false }
  function s:send(data) self.sent[#self.sent + 1] = data; return #data end
  function s:receive() return nil, "timeout", "" end
  function s:close() self.closed = true end
  function s:settimeout() end
  function s:getfd() return -1 end
  return s
end

local function version_payload()
  return p2p.serialize_version({
    version = p2p.PROTOCOL_VERSION,
    services = 9,
    timestamp = os.time(),
    recv_services = 0,
    recv_ip = "127.0.0.1",
    recv_port = 0,
    from_services = 9,
    from_ip = "0.0.0.0",
    from_port = 0,
    nonce = 777001,
    user_agent = "/sec-peer-pcall/",
    start_height = 0,
    relay = true,
  })
end

local function msg(cmd, payload)
  return p2p.make_message(regtest.magic_bytes, cmd, payload or "")
end

local function new_inbound(port)
  local p = peer_module.new("127.0.0." .. port, 50000 + port, regtest, 0, false)
  p.inbound = true
  p.state = STATE.CONNECTED
  p.socket = mock_socket()
  p.handshake_start_time = os.time()
  return p
end

-- A PeerManager with no listener and no outbound dialling: tick() only runs
-- the per-peer loop and the maintenance steps.  Each maintenance step that
-- would touch the network or the disk is replaced with a counter so the spec
-- can see whether the tick reached it.
local function new_pm()
  local pm = peerman.new(regtest, nil, { max_outbound = 0 })
  pm.network_active = false
  pm.maintenance_runs = 0
  pm.accept_inbound = function() end
  pm.maintain_connections = function(self) self.maintenance_runs = self.maintenance_runs + 1 end
  pm.maybe_open_feeler = function() end
  pm._save_addrman = function() end
  pm._reconnect_manual_peers = function() end
  pm.check_for_stale_tip_and_evict_peers = function() end
  return pm
end

local function add(pm, p)
  pm.peers[p.ip .. ":" .. p.port] = p
  pm.peer_list[#pm.peer_list + 1] = p
end

describe("C5: one peer's malformed message cannot abort the P2P tick", function()
  it("a short version payload parses as an error, not an exception", function()
    local ok, ver, err = pcall(p2p.deserialize_version, "")
    assert.is_true(ok, "deserialize_version raised: " .. tostring(ver))
    assert.is_nil(ver)
    assert.is_string(err)

    -- Truncated mid-field (inside the sender address) as well.
    local full = version_payload()
    ok, ver, err = pcall(p2p.deserialize_version, full:sub(1, 50))
    assert.is_true(ok, "deserialize_version raised: " .. tostring(ver))
    assert.is_nil(ver)
    assert.is_string(err)

    -- Control: the full payload still parses.
    local good = p2p.deserialize_version(full)
    assert.is_table(good)
    assert.equal(p2p.PROTOCOL_VERSION, good.version)
    assert.equal("/sec-peer-pcall/", good.user_agent)
  end)

  it("an empty version disconnects only that peer; the next peer handshakes in the same tick", function()
    local pm = new_pm()
    local bad = new_inbound(1)
    local good = new_inbound(2)
    add(pm, bad)
    add(pm, good)

    -- Peer 1 streams empty versions; peer 2 is a well-formed peer.
    bad.recv_buffer = msg("version") .. msg("version") .. msg("version")
    good.recv_buffer = msg("version", version_payload()) .. msg("verack")

    assert.has_no.errors(function() pm:tick() end)

    assert.equal(STATE.DISCONNECTED, bad.state)
    assert.is_nil(pm.peers[bad.ip .. ":" .. bad.port])
    assert.is_true(good.handshake_complete)
    assert.equal(STATE.ESTABLISHED, good.state)
    assert.equal(1, pm.maintenance_runs)
  end)

  it("an empty ping after the handshake disconnects only that peer", function()
    local pm = new_pm()
    local bad = new_inbound(3)
    local good = new_inbound(4)
    add(pm, bad)
    add(pm, good)

    bad.recv_buffer = msg("version", version_payload()) .. msg("verack")
    assert.has_no.errors(function() pm:tick() end)
    assert.is_true(bad.handshake_complete)

    bad.recv_buffer = msg("ping") .. msg("pong")
    good.recv_buffer = msg("version", version_payload()) .. msg("verack")
    assert.has_no.errors(function() pm:tick() end)

    assert.equal(STATE.DISCONNECTED, bad.state)
    assert.is_nil(pm.peers[bad.ip .. ":" .. bad.port])
    assert.equal(STATE.ESTABLISHED, good.state)
    assert.equal(2, pm.maintenance_runs)
  end)

  it("a peer whose processing raises does not stop the other peers' handshake timeouts", function()
    local pm = new_pm()
    local boom = new_inbound(5)
    local stale = new_inbound(6)
    add(pm, boom)
    add(pm, stale)

    -- Any error escaping a peer's processing (not only a deserializer) is
    -- contained to that peer.
    boom.process_messages = function() error("synthetic per-peer failure") end
    -- Peer 2 never finished its handshake and is past the timeout.
    stale.handshake_timeout = 1
    stale.handshake_start_time = os.time() - 10
    -- disconnect_peer() re-disconnects with its own reason, so record the
    -- first reason the peer was given (the one check_timeouts chose).
    local reasons = {}
    local orig_disconnect = stale.disconnect
    stale.disconnect = function(self, reason)
      reasons[#reasons + 1] = reason
      return orig_disconnect(self, reason)
    end

    assert.has_no.errors(function() pm:tick() end)

    assert.equal(STATE.DISCONNECTED, boom.state)
    assert.equal(STATE.DISCONNECTED, stale.state)
    assert.equal("handshake timeout", reasons[1])
    assert.equal(0, #pm.peer_list)
    assert.equal(1, pm.maintenance_runs)
  end)

  it("a well-formed version followed by verack still completes the handshake", function()
    local pm = new_pm()
    local p = new_inbound(7)
    add(pm, p)
    p.recv_buffer = msg("version", version_payload()) .. msg("verack") .. msg("ping", p2p.serialize_ping(5))
    assert.has_no.errors(function() pm:tick() end)
    assert.equal(STATE.ESTABLISHED, p.state)
    assert.equal(p2p.PROTOCOL_VERSION, p.common_version)
    assert.is_not_nil(pm.peers[p.ip .. ":" .. p.port])
  end)
end)
