#!/usr/bin/env luajit
-- Control for two main-loop stalls that share one queue item:
--
--  1. gettxoutsetinfo walks the coin set inside the RPC tick, so the
--     single-threaded loop cannot service peers, other RPC, or block
--     connect until the walk returns. The walk must call tip_pump between
--     slices (the same pump waitfornewblock uses) and the hash must stay
--     the point-in-time set from before those slices.
--
--  2. storage.checkpoint() runs only from the P2P connect loop. A
--     submitblock-fed node (miner, range feeder) writes nosync batches
--     into the memtable and, with the WAL off, loses every block since
--     the last durable flush on SIGKILL. submitblock must arm the same
--     periodic checkpoint; once that flush has finished, SIGKILL keeps
--     the block.
--
-- PRE-FIX: pump count is 0, and the killed node reopens at the genesis
-- tip (the submitted block was never checkpointed).
-- POST-FIX: the pump runs once per txid group, the hash matches the
-- unpumped walk, a nested gettxoutsetinfo is refused, and the killed
-- node reopens at height 1.
--
-- Run from the lunarblock repo root:
--   luajit tests/test_walk_yield_submitblock_checkpoint.lua

package.path = "./src/?.lua;./lunarblock/?.lua;" .. package.path

local rpc_mod = require("lunarblock.rpc")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local types = require("lunarblock.types")
local validation = require("lunarblock.validation")
local crypto = require("lunarblock.crypto")
local serialize = require("lunarblock.serialize")
local storage_mod = require("lunarblock.storage")
local script_mod = require("lunarblock.script")
local cjson = require("cjson")
local ffi = require("ffi")

ffi.cdef[[
  int kill(int pid, int sig);
  int getpid(void);
]]

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

--------------------------------------------------------------------------------
-- 1. gettxoutsetinfo yields to tip_pump and does not change the hash.
--------------------------------------------------------------------------------

local function txid_of(b)
  return types.hash256(string.char(b) .. string.rep("\x00", 31))
end

do
  local db = storage_mod.new_memory_storage()
  local cs = utxo.new_chain_state(db, consensus.networks.regtest)
  local script = script_mod.make_p2pkh_script(string.rep("\x11", 20))
  local txid_a = txid_of(0x11)
  local txid_b = txid_of(0x22)
  cs.coin_view:add(txid_a, 0, utxo.utxo_entry(50, script, 1, true))
  cs.coin_view:add(txid_a, 1, utxo.utxo_entry(7, script, 1, false))
  cs.coin_view:add(txid_b, 0, utxo.utxo_entry(9, script, 2, false))
  cs.tip_hash = types.hash256(string.rep("\xab", 32))
  cs.tip_height = 2

  local server = rpc_mod.new({
    chain_state = cs,
    storage = db,
    network = consensus.networks.regtest,
  })
  -- One yield per txid group, no wall-clock wait, so a 2-group set is
  -- enough to prove the walk returns to the loop before it finishes.
  server._utxo_walk_slice_groups = 1
  server._utxo_walk_slice_seconds = 0

  local pumps = 0
  local nested_msg = nil
  local in_call = false
  server.tip_pump = function()
    pumps = pumps + 1
    check("pump ran before gettxoutsetinfo returned", in_call)
    if pumps == 1 then
      local ok, err = pcall(function()
        return server.methods["gettxoutsetinfo"](server, {})
      end)
      if ok then
        nested_msg = "nested call succeeded"
      elseif type(err) == "table" then
        nested_msg = err.message or cjson.encode(err)
      else
        nested_msg = tostring(err)
      end
    end
  end

  in_call = true
  local res = server.methods["gettxoutsetinfo"](server, {})
  in_call = false
  local decoded = cjson.decode(res._raw_json)
  local pumped_hash = decoded.hash_serialized_3

  check("gettxoutsetinfo called tip_pump mid-walk", pumps >= 2,
    "pumps=" .. tostring(pumps))
  check("nested gettxoutsetinfo refused while a walk is active",
    nested_msg ~= nil and nested_msg:find("already in progress", 1, true) ~= nil,
    "nested=" .. tostring(nested_msg))
  check("pumped walk still reports every coin", decoded.txouts == 3,
    "txouts=" .. tostring(decoded.txouts))

  server.tip_pump = nil
  local res2 = server.methods["gettxoutsetinfo"](server, {})
  local decoded2 = cjson.decode(res2._raw_json)
  check("yielding walk hash matches the unpumped walk",
    pumped_hash == decoded2.hash_serialized_3,
    pumped_hash .. " vs " .. tostring(decoded2.hash_serialized_3))
  check("hash is not the all-zero stub", pumped_hash ~= string.rep("0", 64))
end

--------------------------------------------------------------------------------
-- 2. submitblock checkpoints. SIGKILL after the flush keeps the block.
--------------------------------------------------------------------------------

local REGTEST = consensus.networks.regtest

local function tmpdir()
  local path = os.tmpname() .. "_sbcp"
  os.remove(path)
  os.execute("mkdir -p " .. path)
  return path
end

local function mine_pow(header)
  for n = 0, 0xFFFFFF do
    header.nonce = n
    local h = validation.compute_block_hash(header)
    if string.byte(h.bytes, 32) < 0x80 then return end
  end
  error("regtest PoW not found")
end

local function make_coinbase(height)
  local height_enc = validation.encode_bip34_height(height)
  return {
    version = 1, locktime = 0,
    inputs = {{
      prev_out = { hash = types.hash256(string.rep("\0", 32)), index = 0xFFFFFFFF },
      script_sig = height_enc .. "/ckpt-test/" .. string.rep("\0", 12),
      sequence = 0xFFFFFFFF, witness = {},
    }},
    outputs = {{ value = 5000000000, script_pubkey = "\x51" }},
  }
end

local function build_block(prev_hash, height, timestamp)
  local cb = make_coinbase(height)
  local txid = validation.compute_txid(cb)
  local merkle = crypto.compute_merkle_root({txid})
  local header = {
    version = 0x20000000, prev_hash = prev_hash, merkle_root = merkle,
    timestamp = timestamp, bits = REGTEST.pow_limit_bits, nonce = 0,
  }
  mine_pow(header)
  return { header = header, transactions = { cb } }
end

local function block_hex(block)
  return (serialize.serialize_block(block):gsub(".", function(c)
    return string.format("%02x", string.byte(c))
  end))
end

local dir = tmpdir()
local block = build_block(
  types.hash256_from_hex(REGTEST.genesis_hash),
  1,
  REGTEST.genesis.timestamp + 1)
local hex = block_hex(block)
local child_path = dir .. "/child.lua"
local child = assert(io.open(child_path, "w"))
child:write(string.format([=[
package.path = %q .. package.path
local ffi = require("ffi")
ffi.cdef("int kill(int pid, int sig); int getpid(void);")
local storage = require("lunarblock.storage")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local rpc_mod = require("lunarblock.rpc")
local socket = require("socket")
local db = storage.open(%q, 16, { wal = false })
-- One block is enough: the production cadence is 1000/300s, the bug is
-- that submitblock never consults it at all.
db.checkpoint_interval = 1
db.checkpoint_max_seconds = 1e9
local cs = utxo.new_chain_state(db, consensus.networks.regtest)
cs:init()
local rpc = rpc_mod.new({
  chain_state = cs, storage = db, network = consensus.networks.regtest,
})
local res = rpc.methods["submitblock"](rpc, { %q })
local sf = assert(io.open(%q, "w"))
if type(res) == "string" then
  sf:write("REJECT " .. res)
  sf:close()
  os.exit(0)
end
-- Wait for the scheduled flush to be INSTALLED for the META column family
-- (chain_tip). db.property() reads the default CF, which holds nothing here,
-- so its counters are zero before the background flush has even started;
-- under load that let SIGKILL land first (height 0). The non-blocking
-- checkpoint switches the memtables before it returns, so META's
-- immutable-memtable count is >= 1 until the flush is durable.
ffi.cdef("char* rocksdb_property_value_cf(void* db, void* cf, const char* name); void rocksdb_free(void* p);")
local rlib = ffi.load("rocksdb")
local function meta_prop(name)
  local v = rlib.rocksdb_property_value_cf(db._db, db._handles[storage.CF.META], name)
  if v == nil then return nil end
  local s = ffi.string(v)
  rlib.rocksdb_free(v)
  return s
end
local start = socket.gettime()
local deadline = start + 30
local polls, saw_imm = 0, "?"
while socket.gettime() < deadline do
  polls = polls + 1
  local cps = db.stats.checkpoints or 0
  if polls == 1 then saw_imm = tostring(meta_prop("rocksdb.num-immutable-mem-table")) end
  if cps == 0 and socket.gettime() > start + 0.2 then break end
  if cps >= 1 and meta_prop("rocksdb.num-immutable-mem-table") == "0"
     and meta_prop("rocksdb.mem-table-flush-pending") == "0"
     and db.property("rocksdb.num-running-flushes") == "0" then
    break
  end
  socket.sleep(0.01)
end
sf:write("checkpoints=" .. tostring(db.stats.checkpoints or 0)
  .. " meta_imm_first_poll=" .. saw_imm .. " polls=" .. polls)
sf:close()
ffi.C.kill(ffi.C.getpid(), 9)
]=],
  "./src/?.lua;./lunarblock/?.lua;",
  dir .. "/chainstate",
  hex,
  dir .. "/status"))
child:close()

local cr = os.execute("luajit " .. child_path .. " > " .. dir .. "/child.out 2> " .. dir .. "/child.err")
local status_f = io.open(dir .. "/status")
local status = status_f and status_f:read("*a") or ""
if status_f then status_f:close() end
local err_f = io.open(dir .. "/child.err")
local child_err = err_f and err_f:read("*a") or ""
if err_f then err_f:close() end

local db2 = storage_mod.open(dir .. "/chainstate", 16, { wal = false })
local _, height = db2.get_chain_tip()
db2.close()

io.write("submitblock crash: exit=" .. tostring(cr)
  .. " status=" .. status:gsub("\n", " ")
  .. " height=" .. tostring(height) .. "\n")
if #child_err > 0 then
  io.write("child stderr: " .. child_err:sub(1, 400) .. "\n")
end
check("submitblock did not reject the block", status:sub(1, 6) ~= "REJECT", status)
check("submitblock armed a checkpoint before SIGKILL",
  status:find("checkpoints=0") == nil and status:find("checkpoints=") ~= nil,
  status)
check("SIGKILL kept the submitblock block (height 1, not genesis)",
  height == 1, "height=" .. tostring(height))

os.execute("rm -rf " .. dir)

io.write(string.format("\n%d PASS, %d FAIL\n", pass, fail))
if fail > 0 then os.exit(1) end
