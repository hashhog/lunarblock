-- H5: the tx-request table (LB-11) had one global bound (MAX_TX_REQUESTS =
-- 50,000) and no per-peer bound, so a single peer could fill it; once full,
-- every further inv item ran a forced expiry sweep over the whole table
-- (18.3 s stall from two 50,000-item invs).
--
-- Core: txrequest.cpp / net_processing.cpp bound each peer at
-- MAX_PEER_TX_ANNOUNCEMENTS = 5000 (net_processing.cpp: "if the peer already
-- has too many announcements, ignore this one"), and TxRequestTracker keeps
-- announcements in multi-indexes ordered by time, so expiry touches only what
-- has expired.
package.path = "src/?.lua;" .. package.path

local peer_module = require("lunarblock.peer")
local p2p = require("lunarblock.p2p")
local peerman = require("lunarblock.peerman")

local CAP = 5000  -- Core MAX_PEER_TX_ANNOUNCEMENTS (literal: master lacks the constant)
local T = peerman.GETDATA_TX_INTERVAL

local function pm() return setmetatable({}, peerman.PeerManager) end

local function fake_peer(name)
  local p = { name = name, state = peer_module.STATE.ESTABLISHED, getdata = {} }
  function p:send_message(cmd, payload)
    if cmd == "getdata" then
      for _, item in ipairs(p2p.deserialize_inv(payload)) do
        self.getdata[#self.getdata + 1] = item.hash.bytes
      end
    end
    return true
  end
  return p
end

local function h(tag, i) return string.format("%s%031d", tag, i) end

-- Count table entries the code under test walks with pairs() while fn runs.
local function count_scanned(fn)
  local real_pairs = pairs
  local visited = 0
  _G.pairs = function(t)
    local f, s, k = real_pairs(t)
    return function(st, key)
      local nk, nv = f(st, key)
      if nk ~= nil then visited = visited + 1 end
      return nk, nv
    end, s, k
  end
  local ok, err = pcall(fn)
  _G.pairs = real_pairs
  assert(ok, err)
  return visited
end

describe("H5 tx-request per-peer cap", function()
  it("tracks at most 5000 announcements from one peer", function()
    local m = pm()
    local a = fake_peer("A")
    local requested = 0
    for i = 1, 6000 do
      if m:claim_tx_request("wtxid", h("a", i), a, 1000) then
        requested = requested + 1
      end
    end
    assert.equal(CAP, requested)
    assert.equal(CAP, m._tx_requested_n)
  end)

  it("counts a peer's fallback announcements toward its cap", function()
    local m = pm()
    local a, b = fake_peer("A"), fake_peer("B")
    for i = 1, CAP do
      assert.is_true(m:claim_tx_request("txid", h("x", i), a, 1000))
      assert.is_false(m:claim_tx_request("txid", h("x", i), b, 1000))
    end
    -- B holds CAP fallback announcements: a new tx from B is ignored ...
    assert.is_false(m:claim_tx_request("txid", h("y", 1), b, 1000))
    -- ... and A is also at its cap.
    assert.is_false(m:claim_tx_request("txid", h("y", 2), a, 1000))
  end)

  it("still fetches an honest peer's tx while another peer sits at the cap", function()
    local m = pm()
    local a, c = fake_peer("A"), fake_peer("C")
    for i = 1, 6000 do m:claim_tx_request("txid", h("a", i), a, 1000) end
    assert.is_true(m:claim_tx_request("txid", h("c", 1), c, 1001))
  end)

  it("gives a capped peer room again when its txs arrive or it answers notfound", function()
    local m = pm()
    local a = fake_peer("A")
    for i = 1, CAP do assert.is_true(m:claim_tx_request("txid", h("a", i), a, 1000)) end
    assert.is_false(m:claim_tx_request("txid", h("n", 1), a, 1000))
    m:release_tx_request("txid", h("a", 1))
    assert.is_true(m:claim_tx_request("txid", h("n", 1), a, 1001))
    assert.is_false(m:claim_tx_request("txid", h("n", 2), a, 1001))
    m:tx_request_notfound("txid", h("a", 2), a, 1002)
    assert.is_true(m:claim_tx_request("txid", h("n", 2), a, 1003))
  end)

  it("frees a disconnected peer's budget and hands its requests on", function()
    local m = pm()
    local a, b = fake_peer("A"), fake_peer("B")
    for i = 1, CAP do assert.is_true(m:claim_tx_request("txid", h("a", i), a, 1000)) end
    assert.is_false(m:claim_tx_request("txid", h("a", 1), b, 1000))  -- B is a fallback
    a.state = peer_module.STATE.DISCONNECTED
    m:tx_requests_drop_peer(a, 1010)
    assert.same({ h("a", 1) }, b.getdata)
    -- Only the tx B announced survives; the rest are forgotten.
    assert.equal(1, m._tx_requested_n)
  end)

  it("handles an inv item on a full table without scanning the table", function()
    local m = pm()
    local peers = {}
    for p = 1, peerman.MAX_TX_REQUESTS / CAP do
      peers[p] = fake_peer("P" .. p)
      for i = 1, CAP do
        assert.is_true(m:claim_tx_request("wtxid", h("p" .. p .. "_", i), peers[p], 1000))
      end
    end
    assert.equal(peerman.MAX_TX_REQUESTS, m._tx_requested_n)
    local newcomer = fake_peer("N")
    local visited = count_scanned(function()
      for i = 1, 100 do m:claim_tx_request("wtxid", h("new", i), newcomer, 1001) end
    end)
    -- Master: a forced sweep of all 50,000 entries per item (5,000,000 here).
    assert.is_true(visited < 1000, "scanned " .. visited .. " table entries for 100 inv items")
  end)

  it("expiry touches only expired requests and still re-routes them in order", function()
    local m = pm()
    local a, b = fake_peer("A"), fake_peer("B")
    for i = 1, 3000 do m:claim_tx_request("txid", h("o", i), a, 1000) end
    for i = 1, 3000 do m:claim_tx_request("txid", h("o", i), b, 1000) end
    local c, d = fake_peer("C"), fake_peer("D")
    for i = 1, 1000 do m:claim_tx_request("txid", h("q", i), c, 1030) end
    m:claim_tx_request("txid", h("q", 1), d, 1030)
    local visited = count_scanned(function() m:expire_tx_requests(1000 + T, true) end)
    assert.is_true(visited < 100, "scanned " .. visited .. " entries")
    assert.equal(3000, #b.getdata)
    assert.same({}, d.getdata)
    m:expire_tx_requests(1030 + T, true)
    assert.same({ h("q", 1) }, d.getdata)
  end)

  it("re-requests a tx released and announced again at its new expiry, not the old one", function()
    local m = pm()
    local a, b = fake_peer("A"), fake_peer("B")
    assert.is_true(m:claim_tx_request("txid", h("r", 1), a, 1000))
    m:release_tx_request("txid", h("r", 1))
    assert.is_true(m:claim_tx_request("txid", h("r", 1), a, 1040))
    assert.is_false(m:claim_tx_request("txid", h("r", 1), b, 1041))
    m:expire_tx_requests(1000 + T, true)   -- the first claim's stale expiry
    assert.same({}, b.getdata)
    m:expire_tx_requests(1040 + T, true)
    assert.same({ h("r", 1) }, b.getdata)
  end)
end)
