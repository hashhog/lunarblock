#!/usr/bin/env luajit
-- gettxoutsetinfo yields to tip_pump mid-walk (4fa6309). The pump can
-- connect blocks, so the coin set and the tip change UNDER the walk. The
-- reply must still be the set at the tip it names: the RocksDB iterator is
-- a point-in-time view and height/bestblock are sampled before it opens.
--
-- The pump here mutates the set on its first call: spends a coin that the
-- cursor has not reached yet, adds coins before and after the cursor,
-- flushes the coin view to RocksDB, and moves the tip. Checks:
--   1. pumped reply == the reply computed before the mutation (label+hash)
--   2. a fresh walk after the mutation differs (the mutation is real and
--      visible to a new iterator: instrument control)
--   3. NEGATIVE CONTROL: the same pumped walk over the in-memory backend
--      (its iterator snapshots keys but reads values live) is torn, so
--      check 1 can see a non-snapshot cursor.
--   4. gettxoutsetinfo schedules a checkpoint before it walks (Core
--      ForceFlushStateToDisk in rpc/blockchain.cpp gettxoutsetinfo).
--
-- Run from the lunarblock repo root:
--   luajit tests/test_walk_snapshot_consistency.lua

package.path = "./src/?.lua;./lunarblock/?.lua;" .. package.path

local rpc_mod = require("lunarblock.rpc")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local types = require("lunarblock.types")
local storage_mod = require("lunarblock.storage")
local script_mod = require("lunarblock.script")
local cjson = require("cjson")

local pass, fail = 0, 0
local function check(name, cond, detail)
  if cond then
    io.write("PASS: " .. name .. "\n")
    pass = pass + 1
  else
    io.write("FAIL: " .. name .. (detail and (" -- " .. tostring(detail)) or "") .. "\n")
    fail = fail + 1
  end
end

local NET = consensus.networks.regtest
local script = script_mod.make_p2pkh_script(string.rep("\x11", 20))

-- txid whose FIRST byte is `hi` so iteration order is controllable.
local function txid(hi, n)
  return types.hash256(string.char(hi) .. string.char(n % 256, math.floor(n / 256) % 256)
    .. string.rep("\x00", 29))
end

local function run(db, label, expect_snapshot)
  local cs = utxo.new_chain_state(db, NET)
  -- 600 txids with first byte 0x40..0x9f, two outputs each (vout 0, 300).
  for i = 0, 599 do
    local t = txid(0x40 + (i % 0x60), i)
    cs.coin_view:add(t, 0, utxo.utxo_entry(1000 + i, script, 5, false))
    cs.coin_view:add(t, 300, utxo.utxo_entry(7, script, 5, true))
  end
  cs.coin_view:flush()
  cs.tip_hash = types.hash256(string.rep("\xaa", 32))
  cs.tip_height = 5

  local server = rpc_mod.new({ chain_state = cs, storage = db, network = NET })
  server._utxo_walk_slice_groups = 10
  server._utxo_walk_slice_seconds = 0

  local function call()
    return cjson.decode(server.methods["gettxoutsetinfo"](server, {})._raw_json)
  end

  server.tip_pump = nil
  local before = call()

  local mutated = false
  server.tip_pump = function()
    if mutated then return end
    mutated = true
    -- spend a coin late in key order (first byte 0x9f), add coins at the
    -- very front (0x01) and very back (0xfe), then "connect" a block.
    cs.coin_view:spend(txid(0x9f, 0x5f), 0)
    cs.coin_view:add(txid(0x01, 1), 0, utxo.utxo_entry(123456, script, 6, true))
    cs.coin_view:add(txid(0xfe, 1), 0, utxo.utxo_entry(654321, script, 6, false))
    cs.coin_view:flush()
    cs.tip_hash = types.hash256(string.rep("\xbb", 32))
    cs.tip_height = 6
  end
  local pumped = call()
  server.tip_pump = nil
  local after = call()

  local same = pumped.height == before.height and pumped.bestblock == before.bestblock
    and pumped.txouts == before.txouts and pumped.hash_serialized_3 == before.hash_serialized_3
    and pumped.total_amount == before.total_amount
  local detail = string.format("before h=%s txouts=%s %s | pumped h=%s txouts=%s %s",
    tostring(before.height), tostring(before.txouts), tostring(before.hash_serialized_3),
    tostring(pumped.height), tostring(pumped.txouts), tostring(pumped.hash_serialized_3))
  check(label .. ": pump ran mid-walk", mutated)
  check(label .. ": fresh walk sees the mutation (instrument control)",
    after.height == 6 and after.txouts == before.txouts + 1
      and after.hash_serialized_3 ~= before.hash_serialized_3,
    string.format("after h=%s txouts=%s", tostring(after.height), tostring(after.txouts)))
  if expect_snapshot then
    check(label .. ": pumped reply == pre-mutation set and label", same, detail)
  else
    check(label .. ": NEGATIVE CONTROL non-snapshot cursor is torn", not same, detail)
  end
end

local dir = os.tmpname() .. "_snapwalk"
os.remove(dir)
os.execute("mkdir -p " .. dir)
local db = storage_mod.open(dir .. "/db", 16, { wal = false })
run(db, "rocksdb", true)
db.close()
os.execute("rm -rf " .. dir)

run(storage_mod.new_memory_storage(), "memory", false)

do
  local db = storage_mod.new_memory_storage()
  local cs = utxo.new_chain_state(db, NET)
  cs.coin_view:add(txid(0x40, 1), 0, utxo.utxo_entry(5, script, 1, false))
  cs.tip_hash = types.hash256(string.rep("\xcc", 32))
  cs.tip_height = 1
  local server = rpc_mod.new({ chain_state = cs, storage = db, network = NET })
  local cps0 = db.stats.checkpoints or 0
  server.methods["gettxoutsetinfo"](server, {})
  check("gettxoutsetinfo checkpoints before walking (Core ForceFlushStateToDisk)",
    (db.stats.checkpoints or 0) > cps0,
    "checkpoints " .. tostring(cps0) .. " -> " .. tostring(db.stats.checkpoints))
end

io.write(string.format("\n%d PASS, %d FAIL\n", pass, fail))
if fail > 0 then os.exit(1) end
