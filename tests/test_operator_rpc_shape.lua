#!/usr/bin/env luajit
-- Operator RPC shape parity vs Bitcoin Core v31.1 (core-regtest operator group):
--   * getblock verbosity >= 3 adds vin[].prevout (core_io.cpp TxToUniv,
--     SHOW_DETAILS_AND_PREVOUT); verbosity 2 does not.
--   * getrawtransaction miss without -txindex uses Core's "Use -txindex or
--     provide a block hash" wording (rpc/rawtransaction.cpp:320-327).
--   * getpeerinfo emits addrbind / addrlocal and only emits mapped_as when the
--     mapped AS is non-zero (rpc/net.cpp:229-236).
-- Pure RPC-output test; touches no validation or chainstate-write path.

package.path = "src/?.lua;" .. package.path

local loaders = package.loaders or package.searchers
table.insert(loaders, 2, function(module)
  local name = module:match("^lunarblock%.(.+)")
  if name then
    local filename = "src/" .. name .. ".lua"
    local f = io.open(filename)
    if f then
      f:close()
      return function() return dofile(filename) end
    end
  end
  return nil, "not found"
end)

local rpc = require("lunarblock.rpc")
local types = require("lunarblock.types")
local utxo = require("lunarblock.utxo")
local serialize = require("lunarblock.serialize")
local cjson = require("cjson")

local tests_passed = 0
local tests_failed = 0

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then
    io.write("PASS: " .. name .. "\n")
    tests_passed = tests_passed + 1
  else
    io.write("FAIL: " .. name .. "\n")
    io.write("      " .. tostring(err) .. "\n")
    tests_failed = tests_failed + 1
  end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) .. ", expected " .. tostring(b))
  end
end

local function expect_nil(v, msg)
  if v ~= nil then error((msg or "expected nil") .. ": got " .. tostring(v)) end
end

--------------------------------------------------------------------------------
-- getblock verbosity >= 3
--------------------------------------------------------------------------------

local function getblock_vin(verbosity)
  local spk = "\x00\x14" .. string.rep("\x11", 20)
  local cb = types.transaction(1,
    { types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), "\x01\x01", 0xFFFFFFFF) },
    { types.txout(50 * 100000000, spk) }, 0)
  local spend = types.transaction(2,
    { types.txin(types.outpoint(types.hash256(string.rep("\x22", 32)), 1), "", 0xFFFFFFFD) },
    { types.txout(4999990000, spk) }, 0)
  local block = types.block(types.block_header(1, types.hash256_zero(),
    types.hash256_zero(), 1700000000, 0x207fffff, 0), { cb, spend })
  local undo = utxo.serialize_block_undo(utxo.block_undo({
    utxo.tx_undo({ utxo.utxo_entry(5000000000, spk, 7, true) }) }))
  local bh = types.hash256(string.rep("\x33", 32))
  local storage = {
    get_block = function() return block end,
    get_undo = function() return undo end,
    get_hash_by_height = function(h) if h == 0 then return bh end end,
    get_header = function() return nil end,
  }
  local server = rpc.new({ storage = storage, chain_state = { tip_height = 0 } })
  local res = server.methods["getblock"](server, { types.hash256_hex(bh), verbosity })
  return cjson.decode(res._raw_json).tx[2].vin[1]
end

test("getblock verbosity 3 adds vin[].prevout", function()
  local vin = getblock_vin(3)
  local po = vin.prevout
  expect_eq(type(po), "table", "vin[1].prevout")
  expect_eq(po.generated, true, "prevout.generated")
  expect_eq(po.height, 7, "prevout.height")
  expect_eq(type(po.scriptPubKey), "table", "prevout.scriptPubKey")
  expect_eq(po.scriptPubKey.hex, "0014" .. string.rep("11", 20), "prevout spk hex")
end)

test("getblock verbosity 9 behaves like 3 (prevout present)", function()
  local vin = getblock_vin(9)
  expect_eq(type(vin.prevout), "table", "vin[1].prevout")
end)

test("getblock verbosity 2 has no vin[].prevout", function()
  local vin = getblock_vin(2)
  expect_nil(vin.prevout, "prevout")
end)

--------------------------------------------------------------------------------
-- getpeerinfo
--------------------------------------------------------------------------------

local function first_peer(extra)
  local peer = {
    ip = "1.2.3.4", port = 8333, services = 9,
    version_info = { relay = true, version = 70016, timestamp = 0,
                     recv_ip = "10.0.0.5", recv_port = 18444 },
    last_send = 100, last_recv = 200, bytes_sent = 5, bytes_recv = 6,
    conn_time = 50, latency_ms = 10, user_agent = "/x/",
    start_height = 1, inbound = true,
    socket = { getsockname = function() return "127.0.0.1", "18445" end },
  }
  for k, v in pairs(extra or {}) do peer[k] = v end
  local server = rpc.new({ peer_manager = { peer_list = { peer } } })
  return server.methods["getpeerinfo"](server, {})[1]
end

test("getpeerinfo emits addrbind from the local socket address", function()
  expect_eq(first_peer().addrbind, "127.0.0.1:18445")
end)

test("getpeerinfo emits addrlocal from the peer's reported address", function()
  expect_eq(first_peer().addrlocal, "10.0.0.5:18444")
end)

test("getpeerinfo omits addrbind/addrlocal when unknown", function()
  local p = first_peer({ socket = false,
    version_info = { relay = true, version = 1, timestamp = 0,
                     recv_ip = "0.0.0.0", recv_port = 0 } })
  expect_nil(p.addrbind, "addrbind")
  expect_nil(p.addrlocal, "addrlocal")
end)

test("getpeerinfo omits mapped_as when there is no asmap (AS 0)", function()
  expect_nil(first_peer().mapped_as, "mapped_as")
end)

--------------------------------------------------------------------------------
-- getrawtransaction
--------------------------------------------------------------------------------

local function gettx_error(chain_state)
  local server = rpc.new({
    chain_state = chain_state,
    storage = { get = function() return nil end },
  })
  local ok, err = pcall(server.methods["getrawtransaction"], server,
    { string.rep("ab", 32), true })
  expect_eq(ok, false, "getrawtransaction should fail")
  expect_eq(err.code, -5, "error code")
  return err.message
end

test("getrawtransaction miss without txindex names -txindex", function()
  expect_eq(gettx_error({ txindex_enabled = false }),
    "No such mempool transaction. Use -txindex or provide a block hash to " ..
    "enable blockchain transaction queries. Use gettransaction for wallet transactions.")
end)

test("getrawtransaction miss with txindex says mempool or blockchain", function()
  expect_eq(gettx_error({ txindex_enabled = true }),
    "No such mempool or blockchain transaction. Use gettransaction for wallet transactions.")
end)

io.write("\n")
io.write(string.format("Total: %d passed, %d failed\n", tests_passed, tests_failed))
os.exit(tests_failed == 0 and 0 or 1)
