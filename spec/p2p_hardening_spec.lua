-- P2P residuals from the 2026-10-07 liveness audit (receipts/lunarblock-audit-
-- liveness-2026-10-07.md "Open"):
--   LB-8   a partial non-blocking send dropped the peer
--   LB-11  no tx request dedup across inv announcements
--   LB-5   no headers-sync timeout (a silent sync peer pinned the latch)

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

  it("requests an announced tx once, not once per announcing peer", function()
    local m = pm()
    assert.is_true(m:claim_tx_request("txid", H, 1000))
    assert.is_false(m:claim_tx_request("txid", H, 1001))  -- second peer, same tx
    assert.is_false(m:claim_tx_request("txid", H, 1059))
  end)

  it("keeps txid and wtxid hash spaces apart", function()
    local m = pm()
    assert.is_true(m:claim_tx_request("txid", H, 1000))
    assert.is_true(m:claim_tx_request("wtxid", H, 1000))
  end)

  it("re-requests after GETDATA_TX_INTERVAL if the peer never answered", function()
    local m = pm()
    assert.is_true(m:claim_tx_request("txid", H, 1000))
    assert.is_true(m:claim_tx_request("txid", H, 1000 + peerman.GETDATA_TX_INTERVAL))
  end)

  it("re-requests at once after notfound / receipt releases the claim", function()
    local m = pm()
    assert.is_true(m:claim_tx_request("txid", H, 1000))
    m:release_tx_request("txid", H)
    assert.is_true(m:claim_tx_request("txid", H, 1001))
  end)
end)

describe("LB-5 headers-sync timeout", function()
  local sync = require("lunarblock.sync")
  local function chain(peer, started)
    local c = setmetatable({ headers = {}, syncing = true, sync_peer = peer,
                             sync_request_time = started }, sync.HeaderChain)
    return c
  end

  it("releases the latch and names a sync peer silent past the timeout", function()
    local peer = { ip = "1.2.3.4", port = 8333 }
    local c = chain(peer, 1000)
    assert.is_nil(c:check_sync_timeout(1000 + 15 * 60 - 1))
    assert.is_true(c.syncing)
    assert.equal(peer, c:check_sync_timeout(1000 + 15 * 60 + 2))
    assert.is_false(c.syncing)
    assert.is_nil(c.sync_peer)
  end)

  it("does nothing when no sync is in progress", function()
    local c = chain(nil, nil)
    c.syncing = false
    assert.is_nil(c:check_sync_timeout(10 ^ 9))
  end)
end)
