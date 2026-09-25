-- tests/test_coin_prefetch.lua
-- CoinView:prefetch (parallel coin reads before connect_block's tx loop) must
-- be verdict-neutral: every observable result of the serial pass — coin
-- returned by get, HaveCoin answer, FRESH/DIRTY flags chosen by add, the
-- delete/put set written by flush — must be identical with and without it.
--
-- Method: two RocksDB stores seeded with the same coins, the same scripted
-- "block" of operations run against each, one with prefetch (the helper
-- library, lib/coin_prefetch.so) and one without; then compare everything.
-- Core reference for the semantics being preserved: coins.cpp
-- CCoinsViewCache::AddCoin / SpendCoin / HaveCoin, validation.cpp ConnectBlock.
--
-- Run from the repo root:  luajit tests/test_coin_prefetch.lua

package.path = "./src/?.lua;" .. package.path
package.cpath = "./lib/?.so;" .. package.cpath

local utxo_mod    = require("lunarblock.utxo")
local types       = require("lunarblock.types")
local storage_mod = require("lunarblock.storage")

local pass, fail = 0, 0
local function check(name, cond, detail)
  if cond then
    io.write("PASS: " .. name .. "\n"); pass = pass + 1
  else
    io.write("FAIL: " .. name .. (detail and (" -- " .. tostring(detail)) or "") .. "\n")
    fail = fail + 1
  end
end

local function tmpdir(tag)
  local path = os.tmpname() .. "_prefetch_" .. tag
  os.execute("rm -f " .. path .. "; mkdir -p " .. path)
  return path
end

local function txid(n)
  return types.hash256(string.char(n % 256, math.floor(n / 256) % 256) .. string.rep("\171", 30))
end

local function coin(v, h, cb)
  return utxo_mod.utxo_entry(v, "\x00\x14" .. string.rep("\x42", 20), h, cb or false)
end

-- Seed a store with coins (txid n, vout 0..nout-1) directly on disk.
local function seed(stor, specs)
  local cv = utxo_mod.new_coin_view(stor)
  for _, s in ipairs(specs) do
    cv:add(txid(s[1]), s[2], coin(s[3], s[4]))
  end
  cv:flush(true)
end

check("helper library loaded (lib/coin_prefetch.so)", storage_mod.parallel_get_available,
  "build it with `make build`; without it this test proves nothing")

-- Disk: coins A(1:0), A(1:1), B(2:0), R(9:0) [R = an output this block will
-- re-create, i.e. the crash-replay case the FRESH probe exists for].
local SEED = {
  {1, 0, 1000, 100}, {1, 1, 2000, 100}, {2, 0, 3000, 101}, {9, 0, 4000, 102},
}

-- The scripted block.  Returns a trace of every observable result.
local function run_block(cv, use_prefetch)
  local trace = {}
  local function t(s) trace[#trace + 1] = s end
  -- a coin already spent in the cache (tombstone) must win over the disk copy
  cv:get(txid(2), 0); cv:spend(txid(2), 0)

  local in_keys = {
    utxo_mod.outpoint_key(txid(1), 0), utxo_mod.outpoint_key(txid(1), 1),
    utxo_mod.outpoint_key(txid(2), 0),        -- tombstoned in cache
    utxo_mod.outpoint_key(txid(5), 0),        -- created in this block
    utxo_mod.outpoint_key(txid(7), 0),        -- missing everywhere
  }
  local out_keys = {
    utxo_mod.outpoint_key(txid(5), 0), utxo_mod.outpoint_key(txid(5), 1),
    utxo_mod.outpoint_key(txid(9), 0),        -- present on disk (replay)
  }
  local absent = nil
  if use_prefetch then
    absent = cv:prefetch(in_keys, out_keys, 4)
    t("prefetch_ok=" .. tostring(absent ~= nil))
  end
  local function show(e) return e and (e.value .. "@" .. e.height) or "nil" end
  t("get A0=" .. show(cv:get(txid(1), 0)))
  t("get A1=" .. show(cv:get(txid(1), 1)))
  t("get B0=" .. show(cv:get(txid(2), 0)))
  t("get M0=" .. show(cv:get(txid(7), 0)))
  t("have R0=" .. tostring(cv:have(txid(9), 0, absent)))
  t("have N0=" .. tostring(cv:have(txid(5), 0, absent)))
  cv:spend(txid(1), 0)
  cv:add(txid(5), 0, coin(10, 200), absent)
  cv:add(txid(5), 1, coin(11, 200), absent)
  cv:add(txid(9), 0, coin(12, 200), absent)     -- replay overwrite: NOT fresh
  t("get N0=" .. show(cv:get(txid(5), 0)))
  cv:spend(txid(5), 0)                           -- fresh-spent: no disk op
  local keys = {}
  for k, e in pairs(cv.cache) do
    keys[#keys + 1] = string.format("tx%d:%d:flags=%d:spent=%s", k:byte(1) + 256 * k:byte(2),
      k:byte(33), e.flags or 0, tostring(e.spent or false))
  end
  table.sort(keys)
  t("cache=" .. table.concat(keys, ","))
  t("dirty=" .. cv.dirty_count)
  cv:flush(false)
  return trace
end

local function disk_dump(stor)
  local out = {}
  for _, s in ipairs({ {1, 0}, {1, 1}, {2, 0}, {5, 0}, {5, 1}, {7, 0}, {9, 0} }) do
    local v = stor.get(storage_mod.CF.UTXO, utxo_mod.outpoint_key(txid(s[1]), s[2]))
    out[#out + 1] = s[1] .. ":" .. s[2] .. "=" .. (v and utxo_mod.deserialize_utxo_entry(v).value or "-")
  end
  return table.concat(out, " ")
end

local d1, d2 = tmpdir("serial"), tmpdir("prefetch")
local s1, s2 = storage_mod.open(d1), storage_mod.open(d2)
seed(s1, SEED); seed(s2, SEED)

local cv1 = utxo_mod.new_coin_view(s1)
local cv2 = utxo_mod.new_coin_view(s2)
local tr1 = run_block(cv1, false)
local tr2 = run_block(cv2, true)
check("prefetch returned an absent-set", tr2[1] == "prefetch_ok=true", tr2[1])
table.remove(tr2, 1)
check("same number of observations", #tr1 == #tr2, #tr1 .. " vs " .. #tr2)
for i = 1, math.max(#tr1, #tr2) do
  check("observation " .. i .. " identical", tr1[i] == tr2[i],
    tostring(tr1[i]) .. " | " .. tostring(tr2[i]))
end
local dd1, dd2 = disk_dump(s1), disk_dump(s2)
check("post-flush disk identical", dd1 == dd2, dd1 .. " | " .. dd2)
-- Absolute expectations (so both arms cannot be wrong together):
check("spent coin deleted", dd1:find("1:0=-", 1, true) ~= nil, dd1)
check("replayed output overwritten on disk", dd1:find("9:0=12", 1, true) ~= nil, dd1)
check("fresh-spent output never written", dd1:find("5:0=-", 1, true) ~= nil, dd1)
check("fresh output written", dd1:find("5:1=11", 1, true) ~= nil, dd1)
check("tombstoned B0 read as spent", tr1[3] == "get B0=nil", tr1[3])

-- Prefetch must not override a cache tombstone, and must cache present inputs.
local cv3 = utxo_mod.new_coin_view(s2)
cv3:get(txid(1), 1); cv3:spend(txid(1), 1)
local ab = cv3:prefetch({ utxo_mod.outpoint_key(txid(1), 1) }, {}, 2)
check("tombstone untouched by prefetch", cv3.cache[utxo_mod.outpoint_key(txid(1), 1)].spent == true)
check("tombstoned key not reported absent", ab[utxo_mod.outpoint_key(txid(1), 1)] == nil)

-- Many keys across threads: every present key cached with the right value,
-- every absent key reported absent.
local d4 = tmpdir("many")
local s4 = storage_mod.open(d4)
local specs = {}
for i = 1, 3000 do specs[#specs + 1] = { 1000 + i, 0, i, 300 } end
seed(s4, specs)
local cv4 = utxo_mod.new_coin_view(s4)
local ik, ok_keys = {}, {}
for i = 1, 3000 do ik[#ik + 1] = utxo_mod.outpoint_key(txid(1000 + i), 0) end
for i = 1, 3000 do ok_keys[#ok_keys + 1] = utxo_mod.outpoint_key(txid(1000 + i), 1) end
local ab4 = cv4:prefetch(ik, ok_keys, 16) or {}
local bad = 0
for i = 1, 3000 do
  local e = cv4.cache[ik[i]]
  if not e or e.value ~= i or e.flags ~= 0 then bad = bad + 1 end
  if not ab4[ok_keys[i]] then bad = bad + 1 end
  if ab4[ik[i]] then bad = bad + 1 end
end
check("3000 present + 3000 absent keys classified correctly over 16 threads", bad == 0, bad)

os.execute("rm -rf " .. d1 .. " " .. d2 .. " " .. d4)
io.write(string.format("\n%d PASS / %d FAIL\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
