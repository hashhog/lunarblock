-- Per-peer tx-announcement state must stay bounded for a long-lived peer.
--
-- Live 2026-10-18..25 (mainnet, 12G cgroup): lunarblock was oom-killed three
-- times (10-18 21:00, 10-21 09:55, 10-25 00:40 EDT). Its own [DIAG] line
-- showed the Lua heap floor (post-GC gc_kb) rising ~45 MB/h at tip, 1.07 GB
-- -> 2.9 GB in 40 h, independent of mempool size. Two causes in the trickle
-- relay state, both growing with (txs relayed x long-lived peers):
--
--   inv_known  was a plain set emptied only on disconnect, keyed by the
--              hash256 wrapper TABLE, so it kept one entry per tx ever
--              relayed to the peer (and pinned each hash object), and the
--              "already announced" check never matched a second object with
--              the same bytes. Core: TxRelay::m_tx_inventory_known_filter, a
--              CRollingBloomFilter{50000, 0.000001}.
--   inv_queue  drained at most MAX_INV_PER_MSG (35) entries per Poisson tick,
--              ~7/s for an inbound peer (5 s mean), below mainnet's ~8.5 tx/s
--              (30,611 tx/h over 973064..973099), so an inbound peer's queue
--              grew for as long as it stayed connected. Core sends up to
--              INVENTORY_BROADCAST_TARGET + (queue/1000)*5, capped at
--              INVENTORY_BROADCAST_MAX (net_processing.cpp SendMessages).

local peerman = require("lunarblock.peerman")
local peer_mod = require("lunarblock.peer")
local socket = require("socket")

local NET = {
  name = "regtest", magic_bytes = "\xfa\xbf\xb5\xda", port = 18444,
  default_port = 18444, dns_seeds = {},
}

local function mock_peer(i, inbound, wtxid_relay)
  local p = {
    ip = "10.9." .. i .. ".1", port = 8333, inbound = inbound,
    wtxid_relay = wtxid_relay, state = peer_mod.STATE.ESTABLISHED,
    sent_invs = 0, sent_msgs = 0,
  }
  function p:send_message(command, payload)
    if command == "inv" then
      self.sent_msgs = self.sent_msgs + 1
      -- compactsize count prefix (< 0xfd for every batch here)
      self.sent_invs = self.sent_invs + payload:byte(1)
    end
  end
  return p
end

local function new_pm(peers)
  local pm = peerman.new(NET, nil, {data_dir = "/nonexistent-inv-relay-bound"})
  for _, p in ipairs(peers) do
    pm.peer_list[#pm.peer_list + 1] = p
    pm.peers[p.ip .. ":" .. p.port] = p
    pm:_init_peer_trickle(p)
  end
  return pm
end

-- Production hands the trickle code the tx's cached hash256 wrapper tables
-- (main.lua tx handler -> validation.compute_txid / compute_wtxid).
local function hashes(n)
  local txid = {bytes = string.format("t%031d", n)}
  local wtxid = {bytes = string.format("w%031d", n)}
  return txid, wtxid
end

local function known_count(trickle)
  local n = 0
  for _ in pairs(trickle.inv_known) do n = n + 1 end
  for _ in pairs(trickle.inv_known_prev or {}) do n = n + 1 end
  return n
end

local function flush_all(pm)
  for _ = 1, 10000 do
    local pending = 0
    for _, tr in pairs(pm._peer_trickle) do
      tr.next_send_time = 0
      pending = pending + #tr.inv_queue
    end
    if pending == 0 then return end
    pm:_process_trickle()
  end
end

-- Relay n txs to every peer, draining every `every` txs.
local function relay(pm, first, last, every)
  for n = first, last do
    local txid, wtxid = hashes(n)
    pm:queue_tx_announcement(txid, wtxid, nil)
    if n % every == 0 then flush_all(pm) end
  end
  flush_all(pm)
end

local function heap_kb()
  collectgarbage("collect"); collectgarbage("collect")
  return collectgarbage("count")
end

describe("tx-announcement state stays bounded for a long-lived peer", function()
  local saved_gettime, saved_cap

  before_each(function()
    math.randomseed(20261025)
    saved_gettime = socket.gettime
    saved_cap = peerman.TRICKLE.INV_KNOWN_CAPACITY
  end)

  after_each(function()
    socket.gettime = saved_gettime
    peerman.TRICKLE.INV_KNOWN_CAPACITY = saved_cap
  end)

  it("uses Core's 50000-entry known-inventory capacity", function()
    assert.equals(50000, peerman.TRICKLE.INV_KNOWN_CAPACITY)
  end)

  it("inv_known holds at most 2x INV_KNOWN_CAPACITY hashes after 120000 relayed txs", function()
    local p = mock_peer(1, false, true)
    local pm = new_pm({p})
    relay(pm, 1, 120000, 30)
    local tr = pm._peer_trickle[p.ip .. ":" .. p.port]
    assert.equals(120000, p.sent_invs)
    assert.is_true(known_count(tr) <= 2 * 50000,
      "inv_known holds " .. known_count(tr) .. " hashes after 120000 relayed txs")
  end)

  it("the most recent INV_KNOWN_CAPACITY announcements are still recognised", function()
    local p = mock_peer(1, false, true)
    local pm = new_pm({p})
    relay(pm, 1, 120000, 30)
    -- re-announcing any of the last 50000 must not queue it again
    for n = 120000 - 50000 + 1, 120000, 997 do
      local txid, wtxid = hashes(n)
      pm:queue_tx_announcement(txid, wtxid, nil)
    end
    assert.equals(0, #pm:get_peer_inv_queue(p))
  end)

  it("recognises an announced hash through a different hash object with the same bytes", function()
    local p = mock_peer(1, false, false)  -- legacy peer: announced by txid
    local pm = new_pm({p})
    relay(pm, 1, 10, 10)
    assert.equals(10, p.sent_invs)
    local again = {bytes = string.format("t%031d", 7)}  -- fresh object, same txid
    pm:queue_tx_announcement(again, nil, nil)
    assert.equals(0, #pm:get_peer_inv_queue(p))
  end)

  it("retained heap does not grow with the number of txs relayed", function()
    peerman.TRICKLE.INV_KNOWN_CAPACITY = 2000
    local peers = {}
    for i = 1, 4 do peers[i] = mock_peer(i, i % 2 == 0, i % 2 == 0) end
    local pm = new_pm(peers)
    relay(pm, 1, 20000, 30)
    local h1 = heap_kb()
    relay(pm, 20001, 120000, 30)
    local h2 = heap_kb()
    -- before the bound: ~45 B per tx per peer -> ~17,000 KB for these 100000 txs
    assert.is_true(h2 - h1 < 2000,
      string.format("retained heap grew %.0f KB over 100000 more relayed txs", h2 - h1))
  end)

  it("an inbound peer's queue stays bounded at mainnet's tx rate", function()
    local now = 1000000
    socket.gettime = function() return now end
    local p = mock_peer(1, true, true)  -- inbound: 5 s mean trickle interval
    local pm = new_pm({p})
    local tr = pm._peer_trickle[p.ip .. ":" .. p.port]
    tr.next_send_time = now
    local rate = 8.5          -- tx/s
    local seconds = 2 * 3600  -- two simulated hours
    local n = 0
    for t = 1, seconds * 10 do      -- 100 ms steps
      now = now + 0.1
      while n < t * rate / 10 do
        n = n + 1
        local txid, wtxid = hashes(n)
        pm:queue_tx_announcement(txid, wtxid, nil)
      end
      pm:_process_trickle()
    end
    -- before the fix: about (8.5 - 7) * 7200 ~ 10,800 entries and still growing
    assert.is_true(#tr.inv_queue < 1000,
      "inbound inv_queue holds " .. #tr.inv_queue .. " entries after 2 h at 8.5 tx/s")
    assert.is_true(p.sent_invs > n - 1000)
  end)

  it("sends each queued hash once even when it was queued twice", function()
    local p = mock_peer(1, false, true)
    local pm = new_pm({p})
    local txid, wtxid = hashes(1)
    pm:queue_tx_announcement(txid, wtxid, nil)
    pm:queue_tx_announcement(txid, wtxid, nil)
    assert.equals(2, #pm:get_peer_inv_queue(p))  -- queued twice (not yet sent)
    flush_all(pm)
    assert.equals(1, p.sent_invs)
  end)
end)
