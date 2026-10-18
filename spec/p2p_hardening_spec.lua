-- P2P hardening residuals:
--   LB-8   a partial non-blocking send dropped the peer
--   LB-11  every inv announcement of a tx drew its own getdata; the dedup
--          must still fall back to the other announcers (Core
--          TxRequestTracker) when the requested peer is silent, answers
--          notfound, or disconnects
--   LB-5   no headers-sync timeout (a silent sync peer pinned the latch);
--          disconnect only under Core's SendMessages conditions

local peer_module = require("lunarblock.peer")
local p2p = require("lunarblock.p2p")
local consensus = require("lunarblock.consensus")

local regtest = consensus.networks.regtest

local function new_peer(sock)
  local p = peer_module.new("127.0.0.1", 18444, regtest)
  p.socket = sock
  p.state = peer_module.STATE.ESTABLISHED
  return p
end

describe("LB-8 partial non-blocking send", function()
  -- Socket that accepts at most `cap` bytes per send() call, like a full
  -- kernel send buffer: nil, "timeout", <index of last byte accepted>.
  local function throttled_socket(cap)
    local s = { wire = {}, cap = cap, closed = false }
    function s:send(data)
      if self.cap == 0 then return nil, "timeout", 0 end
      if #data <= self.cap then
        self.wire[#self.wire + 1] = data
        return #data
      end
      self.wire[#self.wire + 1] = data:sub(1, self.cap)
      return nil, "timeout", self.cap
    end
    function s:receive() return nil, "timeout", "" end
    function s:close() self.closed = true end
    function s:settimeout() end
    return s
  end

  it("keeps the peer when the kernel accepts only part of a message", function()
    local sock = throttled_socket(10)
    local p = new_peer(sock)
    assert.is_true(p:send_message("ping", p2p.serialize_ping(1)))
    assert.is_not.equal(peer_module.STATE.DISCONNECTED, p.state)
    assert.is_false(sock.closed)
  end)

  it("delivers the whole stream, in order, once the socket drains", function()
    local sock = throttled_socket(7)
    local p = new_peer(sock)
    assert.is_true(p:send_message("ping", p2p.serialize_ping(1)))
    assert.is_true(p:send_message("ping", p2p.serialize_ping(2)))
    sock.cap = 1048576
    p:check_timeouts()
    local expect = p2p.make_message(regtest.magic_bytes, "ping", p2p.serialize_ping(1))
                .. p2p.make_message(regtest.magic_bytes, "ping", p2p.serialize_ping(2))
    assert.equal(expect, table.concat(sock.wire))
    assert.equal("", p.send_buffer)
  end)

  it("still disconnects on a real socket error", function()
    local sock = { send = function() return nil, "closed", 0 end,
                   close = function() end, settimeout = function() end }
    local p = new_peer(sock)
    assert.is_false(p:send_message("ping", p2p.serialize_ping(1)))
    assert.equal(peer_module.STATE.DISCONNECTED, p.state)
  end)

  it("drops a peer that never drains once the queue passes the cap", function()
    local sock = throttled_socket(0)
    local p = new_peer(sock)
    local big = string.rep("x", 1024 * 1024)
    local dropped = false
    for _ = 1, math.floor(peer_module.MAX_SEND_BUFFER / #big) + 2 do
      if not p:send_message("ping", big) then dropped = true; break end
    end
    assert.is_true(dropped)
    assert.equal(peer_module.STATE.DISCONNECTED, p.state)
  end)
end)

describe("LB-11 tx request dedup", function()
  local peerman = require("lunarblock.peerman")
  local function pm() return setmetatable({}, peerman.PeerManager) end
  local H = string.rep("\1", 32)
  local T = peerman.GETDATA_TX_INTERVAL

  -- Established peer that records every getdata it is sent.
  local function fake_peer(name)
    local p = { name = name, state = peer_module.STATE.ESTABLISHED, getdata = {} }
    function p:send_message(cmd, payload)
      if cmd == "getdata" then
        for _, item in ipairs(p2p.deserialize_inv(payload)) do
          self.getdata[#self.getdata + 1] = { type = item.type, hash = item.hash.bytes }
        end
      end
      return true
    end
    return p
  end

  it("requests an announced tx once, not once per announcing peer", function()
    local m = pm()
    local a, b, c = fake_peer("A"), fake_peer("B"), fake_peer("C")
    assert.is_true(m:claim_tx_request("txid", H, a, 1000))
    assert.is_false(m:claim_tx_request("txid", H, b, 1001))  -- second peer, same tx
    assert.is_false(m:claim_tx_request("txid", H, c, 1000 + T - 1))
  end)

  it("keeps txid and wtxid hash spaces apart", function()
    local m = pm()
    local a = fake_peer("A")
    assert.is_true(m:claim_tx_request("txid", H, a, 1000))
    assert.is_true(m:claim_tx_request("wtxid", H, a, 1000))
  end)

  it("re-requests from a new announcer after GETDATA_TX_INTERVAL if nobody else announced", function()
    local m = pm()
    local a, c = fake_peer("A"), fake_peer("C")
    assert.is_true(m:claim_tx_request("txid", H, a, 1000))
    assert.is_true(m:claim_tx_request("txid", H, c, 1000 + T))
  end)

  it("re-requests at once after receipt releases the claim", function()
    local m = pm()
    local a, b = fake_peer("A"), fake_peer("B")
    assert.is_true(m:claim_tx_request("txid", H, a, 1000))
    m:release_tx_request("txid", H)
    assert.is_true(m:claim_tx_request("txid", H, b, 1001))
  end)

  it("sends the getdata to the next announcer when the requested peer stays silent", function()
    local m = pm()
    local a, b = fake_peer("A"), fake_peer("B")
    assert.is_true(m:claim_tx_request("wtxid", H, a, 1000))
    assert.is_false(m:claim_tx_request("wtxid", H, b, 1010))
    m:expire_tx_requests(1000 + T - 1)
    assert.same({}, b.getdata)
    m:expire_tx_requests(1000 + T)
    assert.same({ { type = p2p.INV_TYPE.MSG_WTX, hash = H } }, b.getdata)
    assert.same({}, a.getdata)
    -- B is now the requested peer: a further announcement is still deduped.
    assert.is_false(m:claim_tx_request("wtxid", H, fake_peer("C"), 1000 + T + 1))
  end)

  it("sends the getdata to the next announcer when the requested peer disconnects", function()
    local m = pm()
    local a, b = fake_peer("A"), fake_peer("B")
    assert.is_true(m:claim_tx_request("txid", H, a, 1000))
    assert.is_false(m:claim_tx_request("txid", H, b, 1010))
    a.state = peer_module.STATE.DISCONNECTED
    m:tx_requests_drop_peer(a, 1020)
    assert.same({ { type = p2p.INV_TYPE.MSG_WITNESS_TX, hash = H } }, b.getdata)
  end)

  it("sends the getdata to the next announcer when the requested peer answers notfound", function()
    local m = pm()
    local a, b = fake_peer("A"), fake_peer("B")
    assert.is_true(m:claim_tx_request("txid", H, a, 1000))
    assert.is_false(m:claim_tx_request("txid", H, b, 1010))
    -- notfound from a peer we did not ask only drops that peer's announcement
    m:tx_request_notfound("txid", H, b, 1015)
    assert.same({}, b.getdata)
    assert.is_false(m:claim_tx_request("txid", H, b, 1016))
    m:tx_request_notfound("txid", H, a, 1020)
    assert.same({ { type = p2p.INV_TYPE.MSG_WITNESS_TX, hash = H } }, b.getdata)
  end)

  it("skips announcers that have since disconnected and forgets the tx when none remain", function()
    local m = pm()
    local a, b = fake_peer("A"), fake_peer("B")
    assert.is_true(m:claim_tx_request("txid", H, a, 1000))
    assert.is_false(m:claim_tx_request("txid", H, b, 1010))
    b.state = peer_module.STATE.DISCONNECTED
    m:tx_request_notfound("txid", H, a, 1020)
    assert.same({}, b.getdata)
    -- nothing outstanding any more: the next announcer is asked at once
    assert.is_true(m:claim_tx_request("txid", H, fake_peer("C"), 1021))
  end)
end)

describe("LB-5 headers-sync timeout", function()
  local sync = require("lunarblock.sync")
  local types = require("lunarblock.types")
  local DAY = 24 * 3600
  local FULL = p2p.SERVICES.NODE_NETWORK

  -- `tip_age` seconds old best header (nil: no header known).
  local function chain(peer, started, now, tip_age)
    local c = setmetatable({ headers = {}, syncing = true, sync_peer = peer,
                             sync_request_time = started }, sync.HeaderChain)
    if tip_age then
      local h = string.rep("\7", 32)
      c.header_tip_hash = types.hash256(h)
      c.headers[types.hash256_hex(c.header_tip_hash)] =
        { header = { timestamp = now - tip_age } }
    end
    return c
  end
  local function out_peer(extra)
    local p = { ip = "1.2.3.4", port = 8333, inbound = false, services = FULL,
                state = peer_module.STATE.ESTABLISHED }
    for k, v in pairs(extra or {}) do p[k] = v end
    return p
  end
  local LIMIT = 15 * 60

  it("releases the latch and asks to disconnect a stalling IBD sync peer when another outbound peer exists", function()
    local now = 10 ^ 9
    local peer, other = out_peer(), out_peer({ port = 8334 })
    local c = chain(peer, now - LIMIT - 3 * 3600, now, 30 * DAY)
    local limit = LIMIT + 0.001 * (30 * DAY / 600)
    c.sync_request_time = now - limit + 1
    assert.is_nil(c:check_sync_timeout(now, { peer, other }))
    assert.is_true(c.syncing)
    c.sync_request_time = now - limit - 1
    local p, disconnect = c:check_sync_timeout(now, { peer, other })
    assert.equal(peer, p)
    assert.is_true(disconnect)
    assert.is_false(c.syncing)
    assert.is_nil(c.sync_peer)
  end)

  it("keeps the only peer (e.g. --connect) and just releases the latch", function()
    local now = 10 ^ 9
    local peer = out_peer()
    local c = chain(peer, now - 2 * DAY, now, 30 * DAY)
    local p, disconnect = c:check_sync_timeout(now, { peer })
    assert.equal(peer, p)
    assert.is_false(disconnect)
    assert.is_false(c.syncing)
  end)

  it("does not count inbound or non-serving peers as an alternative", function()
    local now = 10 ^ 9
    local peer = out_peer()
    local inbound = out_peer({ port = 1, inbound = true })
    local spv = out_peer({ port = 2, services = 0 })
    local c = chain(peer, now - 2 * DAY, now, 30 * DAY)
    local _, disconnect = c:check_sync_timeout(now, { peer, inbound, spv })
    assert.is_false(disconnect)
    assert.is_false(c.syncing)
  end)

  it("never disconnects once the best header is less than 24 h old", function()
    local now = 10 ^ 9
    local peer, other = out_peer(), out_peer({ port = 8334 })
    local c = chain(peer, now - 2 * DAY, now, DAY - 60)
    local p, disconnect = c:check_sync_timeout(now, { peer, other })
    assert.equal(peer, p)
    assert.is_false(disconnect)
    assert.is_false(c.syncing)
  end)

  it("never disconnects a noban sync peer", function()
    local now = 10 ^ 9
    local peer, other = out_peer({ noban = true }), out_peer({ port = 8334 })
    local c = chain(peer, now - 2 * DAY, now, 30 * DAY)
    local p, disconnect = c:check_sync_timeout(now, { peer, other })
    assert.equal(peer, p)
    assert.is_false(disconnect)
    assert.is_false(c.syncing)
  end)

  it("does nothing when no sync is in progress", function()
    local c = chain(nil, nil)
    c.syncing = false
    assert.is_nil(c:check_sync_timeout(10 ^ 9, {}))
  end)
end)
