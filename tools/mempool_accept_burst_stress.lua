-- tools/mempool_accept_burst_stress.lua
--
-- Burst stress for the mempool accept path: fill a mempool with N unrelated
-- transactions, then accept a burst of K more under the default GC, and report
-- the burst's CPU time, Lua heap peak and process peak RSS (VmHWM is reset just
-- before the burst), then the Lua allocation of 200 more accepts with the
-- collector stopped.  No network, no datadir.
--
--   LD_LIBRARY_PATH=./lib luajit tools/mempool_accept_burst_stress.lua 70000 5000
--
-- Recorded 2026-11-18 (UTC) on one core, N=70000 K=5000:
--   master 439dbe1: per_tx_ms=7.806  burst gc +356778 KB  burst RSS +350224 KB
--                   alloc_per_accept_kb=1045.0 at pool=75200
--   this branch:    per_tx_ms=2.865  burst gc +108445 KB  burst RSS +0 KB
--                   alloc_per_accept_kb=21.7 at pool=75200
-- Run from a lunarblock checkout:  luajit <this> [N] [K]
package.path = "./src/?.lua;./?.lua;" .. package.path
local types      = require("lunarblock.types")
local mempool    = require("lunarblock.mempool")
local validation = require("lunarblock.validation")
local N = tonumber(arg[1]) or 30000
local K = tonumber(arg[2]) or 3000
local P2PKH = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"
local cv = { utxos = {}, get = function(self, h, v) return self.utxos[types.hash256_hex(h) .. ":" .. v] end }
local cs = { coin_view = cv, tip_height = 700000 }
local mp = mempool.new(cs, { max_mempool_size = 4 * 1024 * 1024 * 1024 })
local c = 0
local function tx()
  c = c + 1
  local coin = types.hash256(string.format("burst-stress-%019d", c))
  cv.utxos[types.hash256_hex(coin) .. ":0"] = { value = 1000000, script_pubkey = P2PKH, height = 699990, is_coinbase = false }
  return types.transaction(1, { types.txin(types.outpoint(coin, 0), "", 0xFFFFFFFE) }, { types.txout(900000, P2PKH) }, 0)
end
local function status(k)
  local f = io.open("/proc/self/status"); local s = f:read("*a"); f:close()
  return tonumber(s:match(k .. ":%s*(%d+)"))
end
local t0 = os.clock()
for _ = 1, N do assert(mp:accept_transaction(tx())) end
local fill_s = os.clock() - t0
local burst = {}
for i = 1, K do burst[i] = tx(); validation.compute_txid(burst[i]) end
collectgarbage("collect")
local f = io.open("/proc/self/clear_refs", "w"); f:write("5"); f:close()
local rss0, gc0 = status("VmRSS"), collectgarbage("count")
local gc_peak = gc0
t0 = os.clock()
for i = 1, K do
  assert(mp:accept_transaction(burst[i]))
  if i % 50 == 0 then local g = collectgarbage("count"); if g > gc_peak then gc_peak = g end end
end
local burst_s = os.clock() - t0
print(string.format("N=%d K=%d fill_cpu_s=%.1f burst_cpu_s=%.2f per_tx_ms=%.3f rss_before_kb=%d rss_peak_kb=%d (+%d) gc_before_kb=%d gc_peak_kb=%d (+%d) pool=%d",
  N, K, fill_s, burst_s, burst_s * 1000 / K, rss0, status("VmHWM"), status("VmHWM") - rss0,
  math.floor(gc0), math.floor(gc_peak), math.floor(gc_peak - gc0), mp.tx_count))
-- Allocation per accept at this pool size, collector stopped so garbage counts.
local M2 = 200
local more = {}
for i = 1, M2 do more[i] = tx(); validation.compute_txid(more[i]) end
collectgarbage("collect"); collectgarbage("stop")
local a0 = collectgarbage("count")
for i = 1, M2 do assert(mp:accept_transaction(more[i])) end
print(string.format("alloc_per_accept_kb=%.1f at pool=%d (gc stopped, %d accepts)",
  (collectgarbage("count") - a0) / M2, mp.tx_count, M2))
collectgarbage("restart")
