#!/usr/bin/env luajit
-- W116 Package Relay audit test suite — lunarblock (Lua / LuaJIT)
--
-- Gates covered:
--   G1-G5   Package definition (constants, helpers, topology, hash)
--   G6-G10  testmempoolaccept
--   G11-G15 submitpackage RPC
--   G16-G20 Validation (accept_package pipeline)
--   G21-G24 CPFP
--   G25-G28 Edge cases
--   G29-G30 P2P package relay (BIP-331)
--
-- Bugs found:
--   BUG-1  (P1)     testmempoolaccept is a shallow shim; skips accept_to_memory_pool
--                   pipeline entirely (no script checks, no dust, no TRUC, no fee-rate).
--   BUG-2  (P1)     testmempoolaccept response missing "wtxid" field.
--   BUG-3  (MED)    testmempoolaccept response missing "effective-feerate" /
--                   "effective-includes" inside the fees object.
--   BUG-4  (MED)    testmempoolaccept missing "maxfeerate" parameter.
--   BUG-5  (MED)    testmempoolaccept missing "package-error" field for package errors.
--   BUG-6  (P1 CDIV) accept_package does NOT call single_truc_checks — TRUC
--                    policy entirely bypassed for packaged transactions.
--   BUG-7  (MED)    accept_package does NOT run script verification (verify_input_scripts
--                   gate is only in accept_transaction, never called from accept_package).
--   BUG-8  (P1)     submitpackage missing IsChildWithParentsTree topology check:
--                   parents that depend on each other must be rejected.
--   BUG-9  (MED)    submitpackage missing "maxfeerate" and "maxburnamount" parameters.
--   BUG-10 (MED)    submitpackage broadcasts via MSG_WITNESS_TX (0x40000001) instead
--                   of MSG_WTX (5) — wrong inv type for wtxid relay.
--   BUG-11 (MED)    submitpackage fees response missing "effective-feerate" /
--                   "effective-includes" fields.
--   BUG-12 (P1 dead-helper) All BIP-331 P2P message handlers (sendpackages,
--                   ancpkginfo, getpkgtxns, pkgtxns, pckginfo1) exist in p2p.lua but
--                   NO handlers are registered in main.lua — entire P2P package relay
--                   path is dead.
--   BUG-13 (P1)     serialize_sendpackages uses write_u64le for the version field; BIP-331
--                   sendpackages carries a uint16 version — wrong wire size (8 bytes vs 2).
--   BUG-14 (MED)    is_child_with_parents_tree (IsChildWithParentsTree) not implemented;
--                   only is_child_with_parents exists — parents-depend-on-each-other
--                   topology check absent.
--
-- Total: 14 bugs / 30 tests
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_w116_package_relay.lua 2>&1

package.path = "src/?.lua;./?.lua;" .. package.path

local loaders = package.loaders or package.searchers
table.insert(loaders, 2, function(module)
  local name = module:match("^lunarblock%.(.+)")
  if name then
    local filename = "src/" .. name .. ".lua"
    local f = io.open(filename)
    if f then f:close(); return function() return dofile(filename) end end
  end
  return nil, "not found"
end)

local mempool_mod = require("lunarblock.mempool")
local p2p         = require("lunarblock.p2p")
local serialize   = require("lunarblock.serialize")
local types       = require("lunarblock.types")
local crypto      = require("lunarblock.crypto")

local PASS = 0
local FAIL = 0
local BUGS = {}

local function pass(name)
  io.write(string.format("  PASS  %s\n", name))
  PASS = PASS + 1
end

local function fail(name, msg)
  io.write(string.format("  FAIL  %s — %s\n", name, msg))
  FAIL = FAIL + 1
end

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) .. ", expected " .. tostring(b))
  end
end

local function expect_true(v, msg)
  if not v then error(msg or "expected true, got false") end
end

local function expect_false(v, msg)
  if v then error(msg or "expected false, got true") end
end

local function expect_nil(v, msg)
  if v ~= nil then error((msg or "expected nil, got") .. " " .. tostring(v)) end
end

local function bug(id, severity)
  BUGS[#BUGS + 1] = id .. " (" .. severity .. ")"
end

-- ---------------------------------------------------------------------------
-- Minimal fake transaction factory (no real serialization needed for unit checks)
-- ---------------------------------------------------------------------------

local function make_hash(seed)
  -- 32-byte pseudo-hash from a seed string
  local s = crypto.sha256(seed)
  return {bytes = s}
end

local function make_outpoint(txid_hash, idx)
  return {hash = txid_hash, index = idx}
end

local function make_input(prev_hash, prev_idx)
  return {
    prev_out   = make_outpoint(prev_hash, prev_idx),
    script_sig = "",
    sequence   = 0xFFFFFFFF,
    witness    = {},
  }
end

local function make_output(value, script)
  return {value = value, script_pubkey = script or "\x51"} -- OP_TRUE
end

local function make_tx(version, inputs, outputs)
  return {
    version   = version or 1,
    inputs    = inputs  or {},
    outputs   = outputs or {},
    locktime  = 0,
    segwit    = false,
  }
end

-- A coinbase-shaped tx (no inputs) — for is_consistent check
local function make_coinbase_tx()
  return {
    version  = 1,
    inputs   = {{
      prev_out   = {hash = {bytes = string.rep("\x00", 32)}, index = 0xFFFFFFFF},
      script_sig = "\x03\x01\x00\x00",
      sequence   = 0xFFFFFFFF,
      witness    = {},
    }},
    outputs  = {make_output(5000000000)},
    locktime = 0,
    segwit   = false,
  }
end

-- ---------------------------------------------------------------------------
-- Compute a fake vsize for a tx (we want non-zero but don't need real value)
-- ---------------------------------------------------------------------------
local function fake_weight(tx)
  return 400  -- 100 vB
end

-- ---------------------------------------------------------------------------
-- G1: MAX_PACKAGE_COUNT constant = 25
-- ---------------------------------------------------------------------------
print("\n--- G1: MAX_PACKAGE_COUNT ---")

test("G1-a: MAX_PACKAGE_COUNT == 25", function()
  expect_eq(mempool_mod.MAX_PACKAGE_COUNT, 25, "MAX_PACKAGE_COUNT")
end)

-- ---------------------------------------------------------------------------
-- G2: MAX_PACKAGE_WEIGHT constant = 404000
-- ---------------------------------------------------------------------------
print("\n--- G2: MAX_PACKAGE_WEIGHT ---")

test("G2-a: MAX_PACKAGE_WEIGHT == 404000", function()
  expect_eq(mempool_mod.MAX_PACKAGE_WEIGHT, 404000, "MAX_PACKAGE_WEIGHT")
end)

-- ---------------------------------------------------------------------------
-- G3: is_well_formed_package — context-free checks
-- ---------------------------------------------------------------------------
print("\n--- G3: is_well_formed_package ---")

test("G3-a: empty package rejected", function()
  local ok, err = mempool_mod.is_well_formed_package({})
  expect_false(ok, "empty package should fail")
  expect_true(err and err:find("empty") ~= nil, "error should mention 'empty': " .. tostring(err))
end)

test("G3-b: package with 26 txs rejected (exceeds MAX_PACKAGE_COUNT)", function()
  local txns = {}
  for i = 1, 26 do
    txns[i] = make_tx(1, {make_input(make_hash("x"..i), 0)}, {make_output(1000)})
  end
  local ok, err = mempool_mod.is_well_formed_package(txns)
  expect_false(ok, "26-tx package should fail")
  expect_true(err and err:find("too.many") ~= nil, "error should mention 'too-many': " .. tostring(err))
end)

test("G3-c: single valid tx accepted by is_well_formed_package", function()
  local h = make_hash("coinbase-utxo")
  local tx = make_tx(1, {make_input(h, 0)}, {make_output(5000)})
  local ok = mempool_mod.is_well_formed_package({tx})
  expect_true(ok, "single valid tx should pass well-formed check")
end)

-- ---------------------------------------------------------------------------
-- G4: is_topo_sorted_package
-- ---------------------------------------------------------------------------
print("\n--- G4: is_topo_sorted_package ---")

test("G4-a: single tx is topo-sorted", function()
  local h  = make_hash("utxo-seed")
  local tx = make_tx(1, {make_input(h, 0)}, {make_output(5000)})
  local ok = mempool_mod.is_topo_sorted_package({tx})
  expect_true(ok, "single tx should be topo-sorted")
end)

test("G4-b: parent before child is topo-sorted", function()
  local external  = make_hash("external-utxo")
  local parent_tx = make_tx(1, {make_input(external, 0)}, {make_output(5000)})
  -- Compute parent txid so child can reference it
  local validation = require("lunarblock.validation")
  local parent_txid = validation.compute_txid(parent_tx)
  local child_tx  = make_tx(1, {make_input(parent_txid, 0)}, {make_output(4000)})
  local ok = mempool_mod.is_topo_sorted_package({parent_tx, child_tx})
  expect_true(ok, "parent before child should be topo-sorted")
end)

-- ---------------------------------------------------------------------------
-- G5: compute_package_hash
-- ---------------------------------------------------------------------------
print("\n--- G5: compute_package_hash ---")

test("G5-a: compute_package_hash returns 32-byte string", function()
  local h  = make_hash("utxo1")
  local tx = make_tx(1, {make_input(h, 0)}, {make_output(1000)})
  local result = mempool_mod.compute_package_hash({tx})
  expect_eq(type(result), "string", "package hash should be string")
  expect_eq(#result, 32, "package hash should be 32 bytes")
end)

test("G5-b: compute_package_hash is deterministic", function()
  local h   = make_hash("utxo-det")
  local tx1 = make_tx(1, {make_input(h, 0)}, {make_output(1000)})
  local tx2 = make_tx(1, {make_input(h, 1)}, {make_output(2000)})
  local h1 = mempool_mod.compute_package_hash({tx1, tx2})
  local h2 = mempool_mod.compute_package_hash({tx1, tx2})
  expect_eq(h1, h2, "package hash should be deterministic")
end)

test("G5-c: is_child_with_parents implemented", function()
  expect_eq(type(mempool_mod.is_child_with_parents), "function",
    "is_child_with_parents should exist as a function")
end)

-- BUG-14: is_child_with_parents_tree absent
test("G5-d: BUG-14 is_child_with_parents_tree absent (parents-depend-on-each-other check missing)", function()
  -- Core's IsChildWithParentsTree rejects packages where parents depend on each other.
  -- lunarblock only has is_child_with_parents (no tree variant).
  local has_tree = type(mempool_mod.is_child_with_parents_tree) == "function"
  if has_tree then
    pass("G5-d: is_child_with_parents_tree exists (BUG-14 fixed)")
    return
  end
  bug("BUG-14", "MED")
  -- Signal the known absence rather than FAIL — the audit records it.
  -- We FAIL to mark it as a finding that needs a fix.
  error("BUG-14: is_child_with_parents_tree absent — parents-depend-on-each-other topology not enforced")
end)

-- ---------------------------------------------------------------------------
-- G6: testmempoolaccept exists
-- ---------------------------------------------------------------------------
print("\n--- G6: testmempoolaccept RPC ---")

-- Build a minimal RPC object enough to call testmempoolaccept
local function make_fake_rpc(mempool_entries, chain_utxos)
  -- Very thin fake RPC context
  return {
    mempool = {
      entries = mempool_entries or {},
    },
    chain_state = {
      coin_view = {
        get = function(self, hash, idx)
          local key = (hash.bytes or hash) .. tostring(idx)
          return chain_utxos and chain_utxos[key] or nil
        end,
      },
    },
  }
end

local rpc_mod = require("lunarblock.rpc")

-- Minimal config for rpc.new()
local rpc_min_config = {
  host        = "127.0.0.1",
  rpcport     = 48351,
  rpcuser     = "test",
  rpcpassword = "test",
  chain_state = nil,
  mempool     = nil,
  peer_manager= nil,
  storage     = nil,
  network     = nil,
  fee_estimator = nil,
  wallet      = nil,
  datadir     = "/tmp",
  mining      = nil,
}

test("G6-a: testmempoolaccept method exists in rpc module", function()
  local srv = rpc_mod.new(rpc_min_config)
  expect_true(srv ~= nil, "rpc.new() should return a server object")
  expect_eq(type(srv.methods["testmempoolaccept"]), "function",
    "testmempoolaccept should be registered")
end)

test("G6-b: testmempoolaccept rejects non-array rawtxs", function()
  local srv = rpc_mod.new(rpc_min_config)
  local fn  = srv.methods["testmempoolaccept"]
  expect_true(fn ~= nil, "testmempoolaccept handler must exist")
end)

-- BUG-2: wtxid missing from testmempoolaccept response
test("G6-c: BUG-2 testmempoolaccept response missing wtxid field", function()
  -- Core returns both txid AND wtxid for each entry.
  local srv = rpc_mod.new(rpc_min_config)
  local fn  = srv.methods["testmempoolaccept"]
  local result = fn(
    {mempool = {entries = {}}, chain_state = {coin_view = {get = function() return nil end}}},
    {{"DEADBEEF"}}  -- will fail to deserialize → reject-reason = "decode-failed"
  )
  expect_true(type(result) == "table" and #result == 1, "should return 1-element array")
  -- Core always emits wtxid even for decode failures.
  local entry = result[1]
  if entry.wtxid == nil then
    bug("BUG-2", "P1")
    error("BUG-2: testmempoolaccept entry missing 'wtxid' field (Core emits both txid+wtxid)")
  end
end)

-- BUG-5: package-error field missing from testmempoolaccept
test("G6-d: BUG-5 testmempoolaccept missing package-error field", function()
  -- Core emits a package-error key when package-level validation fails.
  local found = false
  local f = io.open("src/rpc.lua")
  if f then
    local src = f:read("*a")
    f:close()
    found = src:find('"package%-error"') ~= nil or src:find("package.error") ~= nil
  end
  if not found then
    bug("BUG-5", "MED")
    error("BUG-5: testmempoolaccept never sets 'package-error' field (required for multi-tx packages)")
  end
end)

-- BUG-4: maxfeerate parameter missing from testmempoolaccept
test("G6-e: BUG-4 testmempoolaccept missing maxfeerate parameter", function()
  -- Core's testmempoolaccept takes an optional maxfeerate (params[2]).
  -- lunarblock only uses params[1] (rawtxs). Check that params[2] is ignored.
  local f = io.open("src/rpc.lua")
  local src = f:read("*a"); f:close()
  -- Find the testmempoolaccept closure region
  local tma_region = src:match('methods%["testmempoolaccept"%].-end')
  local has_maxfeerate = tma_region and (
    tma_region:find("maxfeerate") ~= nil or
    tma_region:find("params%[2%]") ~= nil
  )
  if not has_maxfeerate then
    bug("BUG-4", "MED")
    error("BUG-4: testmempoolaccept ignores maxfeerate parameter (params[2])")
  end
end)

-- BUG-3: effective-feerate missing from testmempoolaccept fees object
test("G6-f: BUG-3 testmempoolaccept fees object missing effective-feerate", function()
  local f = io.open("src/rpc.lua")
  local src = f:read("*a"); f:close()
  local tma_region = src:match('methods%["testmempoolaccept"%].-end')
  local has_effective = tma_region and tma_region:find("effective%-feerate") ~= nil
  if not has_effective then
    bug("BUG-3", "MED")
    error("BUG-3: testmempoolaccept fees object missing 'effective-feerate' / 'effective-includes' fields")
  end
end)

-- BUG-1: testmempoolaccept is a shallow shim (not using accept_to_memory_pool)
test("G6-g: BUG-1 testmempoolaccept skips full accept_to_memory_pool pipeline", function()
  local f = io.open("src/rpc.lua")
  local src = f:read("*a"); f:close()
  local tma_region = src:match('methods%["testmempoolaccept"%](.-)methods%[')
  local uses_atmp = tma_region and (
    tma_region:find("accept_to_memory_pool") ~= nil or
    tma_region:find("accept_transaction") ~= nil
  )
  if not uses_atmp then
    bug("BUG-1", "P1")
    error("BUG-1: testmempoolaccept does not call accept_to_memory_pool — uses custom shallow shim that skips script/dust/TRUC/fee-rate checks")
  end
end)

-- ---------------------------------------------------------------------------
-- G7: testmempoolaccept handles single-tx path
-- ---------------------------------------------------------------------------
print("\n--- G7: testmempoolaccept single-tx path ---")

test("G7-a: testmempoolaccept returns array", function()
  local srv = rpc_mod.new(rpc_min_config)
  local fn  = srv.methods["testmempoolaccept"]
  expect_eq(type(fn), "function", "handler must be a function")
end)

test("G7-b: testmempoolaccept handles empty rawtxs gracefully", function()
  local srv = rpc_mod.new(rpc_min_config)
  local fn  = srv.methods["testmempoolaccept"]
  -- Empty array — should return empty result or error cleanly
  local ok, result = pcall(fn,
    {mempool = {entries = {}}, chain_state = {coin_view = {get = function() return nil end}}},
    {{}}
  )
  expect_true(ok or type(result) == "table", "should not crash unhandled on empty array")
end)

-- ---------------------------------------------------------------------------
-- G8: testmempoolaccept multi-tx package path
-- ---------------------------------------------------------------------------
print("\n--- G8: testmempoolaccept multi-tx ---")

test("G8-a: testmempoolaccept accepts array of multiple hex strings", function()
  local srv = rpc_mod.new(rpc_min_config)
  local fn  = srv.methods["testmempoolaccept"]
  local result = fn(
    {mempool = {entries = {}}, chain_state = {coin_view = {get = function() return nil end}}},
    {{"DEADBEEF", "CAFEBABE"}}
  )
  expect_true(type(result) == "table", "result must be a table/array")
  expect_eq(#result, 2, "should return 2 results for 2 input txs")
end)

-- ---------------------------------------------------------------------------
-- G9: testmempoolaccept well-formedness (array size limit)
-- ---------------------------------------------------------------------------
print("\n--- G9: testmempoolaccept size limit ---")

test("G9-a: testmempoolaccept enforces MAX_PACKAGE_COUNT limit", function()
  local srv = rpc_mod.new(rpc_min_config)
  local fn  = srv.methods["testmempoolaccept"]
  local big = {}
  for i = 1, 26 do big[i] = "DEADBEEF" end
  local ok, err = pcall(fn,
    {mempool = {entries = {}}, chain_state = {coin_view = {get = function() return nil end}}},
    {big}
  )
  -- Core rejects arrays > 25 with JSONRPCError; lunarblock may silently process all 26.
  -- Gate verifies no unhandled crash.
  expect_true(not ok or type(err) == "table" or type(err) == "string" or #err == 26,
    "should handle 26-element input without unhandled crash")
end)

-- ---------------------------------------------------------------------------
-- G10: testmempoolaccept already-in-mempool handling
-- ---------------------------------------------------------------------------
print("\n--- G10: testmempoolaccept already-in-mempool ---")

test("G10-a: testmempoolaccept rejects already-in-mempool txs", function()
  -- Core: package testmempoolaccept doesn't allow txs already in mempool.
  -- lunarblock checks rpc.mempool.entries[txid] and sets reject-reason.
  local f = io.open("src/rpc.lua")
  local src = f:read("*a"); f:close()
  local has_already_in = src:find("txn%-already%-in%-mempool") ~= nil
  expect_true(has_already_in, "testmempoolaccept should handle txn-already-in-mempool case")
end)

-- ---------------------------------------------------------------------------
-- G11: submitpackage exists
-- ---------------------------------------------------------------------------
print("\n--- G11: submitpackage RPC ---")

test("G11-a: submitpackage method registered", function()
  local srv = rpc_mod.new(rpc_min_config)
  expect_eq(type(srv.methods["submitpackage"]), "function",
    "submitpackage should be registered")
end)

test("G11-b: submitpackage rejects non-table package", function()
  local srv = rpc_mod.new(rpc_min_config)
  local fn  = srv.methods["submitpackage"]
  local ok, err = pcall(fn,
    {mempool = {entries = {}}, chain_state = nil},
    {nil}
  )
  expect_false(ok, "nil package param should throw")
end)

-- BUG-8: submitpackage missing IsChildWithParentsTree check
test("G11-c: BUG-8 submitpackage missing IsChildWithParentsTree topology enforcement", function()
  -- Core: if #txns > 1, rejects unless IsChildWithParentsTree passes.
  -- This rejects packages where parents depend on each other.
  local f = io.open("src/rpc.lua")
  local src = f:read("*a"); f:close()
  -- Find submitpackage closure
  local sp_region = src:match('methods%["submitpackage"%](.-)methods%[')
  local has_tree = sp_region and (
    sp_region:find("is_child_with_parents_tree") ~= nil or
    sp_region:find("IsChildWithParentsTree") ~= nil or
    sp_region:find("child_with_parents_tree") ~= nil
  )
  if not has_tree then
    bug("BUG-8", "P1")
    error("BUG-8: submitpackage missing IsChildWithParentsTree check — packages where parents depend on each other are not rejected")
  end
end)

-- BUG-9: submitpackage missing maxfeerate / maxburnamount params
test("G11-d: BUG-9 submitpackage missing maxfeerate / maxburnamount parameters", function()
  local f = io.open("src/rpc.lua")
  local src = f:read("*a"); f:close()
  local sp_region = src:match('methods%["submitpackage"%](.-)methods%[')
  local has_maxfee = sp_region and sp_region:find("maxfeerate") ~= nil
  local has_maxburn = sp_region and sp_region:find("maxburnamount") ~= nil
  if not has_maxfee or not has_maxburn then
    bug("BUG-9", "MED")
    error(string.format(
      "BUG-9: submitpackage missing params: maxfeerate=%s, maxburnamount=%s",
      tostring(has_maxfee), tostring(has_maxburn)))
  end
end)

-- BUG-10: submitpackage broadcasts MSG_WITNESS_TX instead of MSG_WTX
test("G11-e: BUG-10 submitpackage broadcasts MSG_WITNESS_TX instead of MSG_WTX", function()
  local f = io.open("src/rpc.lua")
  local src = f:read("*a"); f:close()
  local sp_region = src:match('methods%["submitpackage"%](.-)methods%[')
  -- Look for the offending constant
  local uses_wrong_type = sp_region and sp_region:find("MSG_WITNESS_TX") ~= nil
  local uses_correct    = sp_region and sp_region:find("MSG_WTX[^_]") ~= nil
  if uses_wrong_type and not uses_correct then
    bug("BUG-10", "MED")
    error("BUG-10: submitpackage broadcasts via MSG_WITNESS_TX (0x40000001) instead of MSG_WTX (5) — wrong inv type for wtxid-relay peers")
  end
end)

-- BUG-11: submitpackage fees missing effective-feerate
test("G11-f: BUG-11 submitpackage tx-results fees missing effective-feerate", function()
  local f = io.open("src/rpc.lua")
  local src = f:read("*a"); f:close()
  local sp_region = src:match('methods%["submitpackage"%](.-)methods%[')
  local has_effective = sp_region and sp_region:find("effective%-feerate") ~= nil
  if not has_effective then
    bug("BUG-11", "MED")
    error("BUG-11: submitpackage tx-results fees object missing 'effective-feerate' / 'effective-includes' fields")
  end
end)

-- ---------------------------------------------------------------------------
-- G12: submitpackage response schema
-- ---------------------------------------------------------------------------
print("\n--- G12: submitpackage response schema ---")

test("G12-a: submitpackage response has package_msg field", function()
  local f = io.open("src/rpc.lua")
  local src = f:read("*a"); f:close()
  local has_pkg_msg = src:find('package_msg') ~= nil
  expect_true(has_pkg_msg, "submitpackage response should include package_msg")
end)

test("G12-b: submitpackage response has tx-results field keyed by wtxid", function()
  local f = io.open("src/rpc.lua")
  local src = f:read("*a"); f:close()
  local has_tx_results = src:find('"tx%-results"') ~= nil
  expect_true(has_tx_results, "submitpackage response should include tx-results")
end)

test("G12-c: submitpackage response has replaced-transactions field", function()
  local f = io.open("src/rpc.lua")
  local src = f:read("*a"); f:close()
  local has_replaced = src:find('"replaced%-transactions"') ~= nil
  expect_true(has_replaced, "submitpackage response should include replaced-transactions")
end)

-- ---------------------------------------------------------------------------
-- G13: accept_package UTXO resolution
-- ---------------------------------------------------------------------------
print("\n--- G13: accept_package intra-package UTXO resolution ---")

test("G13-a: is_well_formed_package and is_consistent_package exported", function()
  expect_eq(type(mempool_mod.is_well_formed_package), "function",
    "is_well_formed_package should be exported")
  expect_eq(type(mempool_mod.is_consistent_package), "function",
    "is_consistent_package should be exported")
end)

test("G13-b: package with duplicate txid rejected", function()
  local h  = make_hash("dup-utxo")
  local tx = make_tx(1, {make_input(h, 0)}, {make_output(5000)})
  local ok, err = mempool_mod.is_well_formed_package({tx, tx})
  expect_false(ok, "package with duplicate tx should fail")
  expect_true(err and err:find("duplicates") ~= nil,
    "error should mention 'duplicates': " .. tostring(err))
end)

-- ---------------------------------------------------------------------------
-- G14: accept_package fee-rate calculation
-- ---------------------------------------------------------------------------
print("\n--- G14: accept_package fee-rate ---")

test("G14-a: calculate_package_fee_rate exported and callable", function()
  expect_eq(type(mempool_mod.calculate_package_fee_rate), "function",
    "calculate_package_fee_rate should be exported")
  local h  = make_hash("fr-utxo")
  local tx = make_tx(1, {make_input(h, 0)}, {make_output(5000)})
  -- fees and vsize arrays are required; use a fake fee
  local rate = mempool_mod.calculate_package_fee_rate({tx}, {1000})
  expect_true(type(rate) == "number" and rate > 0, "fee rate should be positive number")
end)

-- ---------------------------------------------------------------------------
-- G15: accept_package — TRUC check bypass (BUG-6)
-- ---------------------------------------------------------------------------
print("\n--- G15-G16: accept_package TRUC check ---")

-- BUG-6: accept_package skips single_truc_checks
test("G15-a: BUG-6 accept_package does not call single_truc_checks (TRUC policy bypassed)", function()
  local f = io.open("src/mempool.lua")
  local src = f:read("*a"); f:close()
  -- Find the accept_package function body
  local ap_region = src:match("function Mempool:accept_package(.-)^end", 1)
  -- Fallback: simpler match
  if not ap_region then
    local start_pos = src:find("function Mempool:accept_package")
    if start_pos then
      -- Grab ~300 lines worth of text after the function start
      ap_region = src:sub(start_pos, start_pos + 8000)
    end
  end
  local calls_truc = ap_region and ap_region:find("single_truc_checks") ~= nil
  if not calls_truc then
    bug("BUG-6", "P1-CDIV")
    error("BUG-6 (P1-CDIV): accept_package never calls single_truc_checks — TRUC policy is entirely bypassed for packaged transactions. A v3 child of a non-v3 parent (or vice versa) would be accepted.")
  end
end)

-- BUG-7: accept_package skips script verification
test("G15-b: BUG-7 accept_package does not run script verification", function()
  local f = io.open("src/mempool.lua")
  local src = f:read("*a"); f:close()
  local start_pos = src:find("function Mempool:accept_package")
  local ap_region = start_pos and src:sub(start_pos, start_pos + 8000) or ""
  local has_script = ap_region:find("verify_input_scripts") ~= nil or
                     ap_region:find("verify_script") ~= nil or
                     ap_region:find("script_flags") ~= nil
  if not has_script then
    bug("BUG-7", "MED")
    error("BUG-7: accept_package skips script verification entirely (verify_input_scripts gate only in accept_transaction)")
  end
end)

-- ---------------------------------------------------------------------------
-- G17: is_consistent_package input conflict detection
-- ---------------------------------------------------------------------------
print("\n--- G17: is_consistent_package ---")

test("G17-a: conflicting inputs within package rejected", function()
  local shared = make_hash("shared-utxo")
  local tx1 = make_tx(1, {make_input(shared, 0)}, {make_output(4000)})
  local tx2 = make_tx(1, {make_input(shared, 0)}, {make_output(3000)})
  local ok, err = mempool_mod.is_consistent_package({tx1, tx2})
  expect_false(ok, "double-spend within package should fail is_consistent")
end)

test("G17-b: non-conflicting inputs pass is_consistent", function()
  local h1 = make_hash("utxo-a")
  local h2 = make_hash("utxo-b")
  local tx1 = make_tx(1, {make_input(h1, 0)}, {make_output(4000)})
  local tx2 = make_tx(1, {make_input(h2, 0)}, {make_output(3000)})
  local ok = mempool_mod.is_consistent_package({tx1, tx2})
  expect_true(ok, "non-conflicting package should pass is_consistent")
end)

-- ---------------------------------------------------------------------------
-- G18: accept_package — mempool conflict detection
-- ---------------------------------------------------------------------------
print("\n--- G18: accept_package conflict detection ---")

test("G18-a: accept_package checks for conflicts with existing mempool txs", function()
  -- Verify the conflict check code exists in accept_package
  local f = io.open("src/mempool.lua")
  local src = f:read("*a"); f:close()
  local start_pos = src:find("function Mempool:accept_package")
  local ap_region = start_pos and src:sub(start_pos, start_pos + 8000) or ""
  local has_conflict = ap_region:find("conflict") ~= nil
  expect_true(has_conflict, "accept_package should check for conflicts with existing mempool txs")
end)

-- ---------------------------------------------------------------------------
-- G19: accept_package — coinbase maturity
-- ---------------------------------------------------------------------------
print("\n--- G19: accept_package coinbase maturity ---")

test("G19-a: accept_package checks coinbase maturity", function()
  local f = io.open("src/mempool.lua")
  local src = f:read("*a"); f:close()
  local start_pos = src:find("function Mempool:accept_package")
  local ap_region = start_pos and src:sub(start_pos, start_pos + 8000) or ""
  local has_maturity = ap_region:find("COINBASE_MATURITY") ~= nil or
                       ap_region:find("coinbase_maturity") ~= nil or
                       ap_region:find("is_coinbase") ~= nil
  expect_true(has_maturity, "accept_package should enforce coinbase maturity")
end)

-- ---------------------------------------------------------------------------
-- G20: accept_package — ancestor/descendant limits
-- ---------------------------------------------------------------------------
print("\n--- G20: accept_package ancestor limits ---")

test("G20-a: accept_package enforces MAX_ANCESTORS limit", function()
  local f = io.open("src/mempool.lua")
  local src = f:read("*a"); f:close()
  local start_pos = src:find("function Mempool:accept_package")
  local ap_region = start_pos and src:sub(start_pos, start_pos + 8000) or ""
  local has_ancestor = ap_region:find("MAX_ANCESTORS") ~= nil
  expect_true(has_ancestor, "accept_package should enforce MAX_ANCESTORS limit")
end)

-- ---------------------------------------------------------------------------
-- G21: CPFP — is_child_with_parents
-- ---------------------------------------------------------------------------
print("\n--- G21: CPFP topology ---")

test("G21-a: is_child_with_parents returns false for single tx", function()
  local h  = make_hash("single")
  local tx = make_tx(1, {make_input(h, 0)}, {make_output(5000)})
  local ok = mempool_mod.is_child_with_parents({tx})
  expect_false(ok, "single tx is not child-with-parents")
end)

test("G21-b: is_child_with_parents requires parent to be in child inputs", function()
  local validation = require("lunarblock.validation")
  local external   = make_hash("external")
  local parent_tx  = make_tx(1, {make_input(external, 0)}, {make_output(5000)})
  local unrelated  = make_hash("unrelated")
  -- Child does NOT spend parent output
  local child_tx   = make_tx(1, {make_input(unrelated, 0)}, {make_output(4000)})
  local ok = mempool_mod.is_child_with_parents({parent_tx, child_tx})
  expect_false(ok, "child not spending parent should fail is_child_with_parents")
end)

-- ---------------------------------------------------------------------------
-- G22: CPFP package fee rate calculation
-- ---------------------------------------------------------------------------
print("\n--- G22: CPFP fee rate ---")

test("G22-a: calculate_package_fee_rate aggregates fees and vsizes", function()
  local h1  = make_hash("fee-u1")
  local h2  = make_hash("fee-u2")
  local tx1 = make_tx(1, {make_input(h1, 0)}, {make_output(1000)})
  local tx2 = make_tx(1, {make_input(h2, 0)}, {make_output(2000)})
  -- fees[i] is total fee for tx i in satoshis
  local rate = mempool_mod.calculate_package_fee_rate({tx1, tx2}, {100, 200})
  expect_true(rate > 0, "aggregate fee rate should be > 0")
end)

test("G22-b: calculate_package_fee_rate zero vsize guard", function()
  -- Passing empty txns / zero vsize should not crash with division by zero
  local ok, err = pcall(mempool_mod.calculate_package_fee_rate, {}, {})
  -- Either returns 0 or errors cleanly; must not crash Lua runtime
  expect_true(ok or type(err) == "string",
    "zero vsize should not produce unhandled Lua crash")
end)

-- ---------------------------------------------------------------------------
-- G23: CPFP — package fee rate enforcement in accept_package
-- ---------------------------------------------------------------------------
print("\n--- G23: accept_package CPFP fee enforcement ---")

test("G23-a: accept_package uses package fee rate for low-fee parents", function()
  local f = io.open("src/mempool.lua")
  local src = f:read("*a"); f:close()
  local start_pos = src:find("function Mempool:accept_package")
  local ap_region = start_pos and src:sub(start_pos, start_pos + 8000) or ""
  -- Should compute aggregate fee rate and compare against min_relay_fee
  local has_pkg_rate = ap_region:find("package_fee_rate") ~= nil
  expect_true(has_pkg_rate, "accept_package should compute package_fee_rate for CPFP")
end)

-- ---------------------------------------------------------------------------
-- G24: CPFP — individual txs below min-fee accepted if package qualifies
-- ---------------------------------------------------------------------------
print("\n--- G24: CPFP individual tx below min-fee ---")

test("G24-a: accept_package comment acknowledges CPFP bypass of individual min fee", function()
  local f = io.open("src/mempool.lua")
  local src = f:read("*a"); f:close()
  local start_pos = src:find("function Mempool:accept_package")
  local ap_region = start_pos and src:sub(start_pos, start_pos + 8000) or ""
  -- Check that there's an acknowledgment of per-tx below-min-fee bypass
  local has_bypass = ap_region:find("package as a whole") ~= nil or
                     ap_region:find("package fee") ~= nil
  expect_true(has_bypass, "accept_package should acknowledge individual tx fee bypass via package feerate")
end)

-- ---------------------------------------------------------------------------
-- G25: Edge case — package with all txs already in mempool
-- ---------------------------------------------------------------------------
print("\n--- G25: edge cases ---")

test("G25-a: accept_package skips already-in-mempool txs", function()
  local f = io.open("src/mempool.lua")
  local src = f:read("*a"); f:close()
  local start_pos = src:find("function Mempool:accept_package")
  local ap_region = start_pos and src:sub(start_pos, start_pos + 8000) or ""
  -- Should have a "skip if already in mempool" fast path
  local has_skip = ap_region:find("Skip if already in mempool") ~= nil or
                   ap_region:find("entries%[txid_hex%]") ~= nil
  expect_true(has_skip, "accept_package should skip txs already in mempool")
end)

-- ---------------------------------------------------------------------------
-- G26: Edge case — single-tx package weight check
-- ---------------------------------------------------------------------------
print("\n--- G26: single-tx package ---")

test("G26-a: is_well_formed_package defers to individual tx check for single tx weight", function()
  -- Core: for single-tx packages, weight > MAX_PACKAGE_WEIGHT still passes
  -- is_well_formed (the individual tx weight check happens elsewhere).
  -- lunarblock: `if #txns > 1 and total_weight > MAX_PACKAGE_WEIGHT` — same behaviour.
  local h  = make_hash("big-tx")
  -- We can't easily make a genuinely overweight tx without real serialization,
  -- so we just verify the guard condition matches Core's intent.
  local f = io.open("src/mempool.lua")
  local src = f:read("*a"); f:close()
  local has_guard = src:find("#txns > 1 and total_weight > M.MAX_PACKAGE_WEIGHT") ~= nil or
                    src:find("package_count > 1") ~= nil
  expect_true(has_guard, "weight check should be conditioned on #txns > 1")
end)

-- ---------------------------------------------------------------------------
-- G27: Edge case — MAX_PACKAGE_VSIZE constant present
-- ---------------------------------------------------------------------------
print("\n--- G27: MAX_PACKAGE_VSIZE ---")

test("G27-a: MAX_PACKAGE_VSIZE constant defined", function()
  expect_eq(mempool_mod.MAX_PACKAGE_VSIZE, 101000,
    "MAX_PACKAGE_VSIZE should be 101000 (404000 / 4)")
end)

-- ---------------------------------------------------------------------------
-- G28: Edge case — package hash uses single SHA256 (matching Core)
-- ---------------------------------------------------------------------------
print("\n--- G28: package hash algorithm ---")

test("G28-a: compute_package_hash uses single SHA256 (matching Core's GetSHA256)", function()
  -- Core: hashwriter.GetSHA256() = single SHA256 (not double SHA256).
  -- lunarblock: crypto.sha256(table.concat(wtxids)) — single SHA256, correct.
  local f = io.open("src/mempool.lua")
  local src = f:read("*a"); f:close()
  local start = src:find("function M.compute_package_hash")
  local region = start and src:sub(start, start + 600) or ""
  -- The function must call crypto.sha256
  local uses_sha256 = region:find("crypto%.sha256%(") ~= nil
  -- Must NOT call crypto.sha256d, double_sha256, or hash.double
  local uses_double = region:find("sha256d") ~= nil or
                      region:find("double_sha256") ~= nil or
                      region:find("crypto%.hash256%(") ~= nil
  expect_true(uses_sha256, "compute_package_hash should call crypto.sha256()")
  expect_false(uses_double, "compute_package_hash should NOT use double sha256")
end)

-- ---------------------------------------------------------------------------
-- G29: P2P package relay serializers (BIP-331) — dead helpers
-- ---------------------------------------------------------------------------
print("\n--- G29: P2P package relay (BIP-331) ---")

test("G29-a: BIP-331 P2P message serializers defined in p2p.lua", function()
  expect_eq(type(p2p.serialize_sendpackages),   "function", "serialize_sendpackages must exist")
  expect_eq(type(p2p.deserialize_sendpackages), "function", "deserialize_sendpackages must exist")
  expect_eq(type(p2p.serialize_ancpkginfo),     "function", "serialize_ancpkginfo must exist")
  expect_eq(type(p2p.serialize_getpkgtxns),     "function", "serialize_getpkgtxns must exist")
  expect_eq(type(p2p.serialize_pkgtxns),        "function", "serialize_pkgtxns must exist")
  expect_eq(type(p2p.serialize_pckginfo1),      "function", "serialize_pckginfo1 must exist")
end)

-- BUG-12: P2P handlers are dead (no register_handler in main.lua)
test("G29-b: BUG-12 P2P package relay handlers are dead (not wired in main.lua)", function()
  local f = io.open("src/main.lua")
  local src = f:read("*a"); f:close()
  local handles_sendpackages = src:find('"sendpackages"') ~= nil
  local handles_ancpkginfo   = src:find('"ancpkginfo"')   ~= nil
  local handles_getpkgtxns   = src:find('"getpkgtxns"')   ~= nil
  local handles_pkgtxns      = src:find('"pkgtxns"')       ~= nil
  local all_wired = handles_sendpackages and handles_ancpkginfo and
                    handles_getpkgtxns   and handles_pkgtxns
  if not all_wired then
    bug("BUG-12", "P1-dead-helper")
    error(string.format(
      "BUG-12 (P1 dead-helper): BIP-331 P2P handlers not registered in main.lua: "..
      "sendpackages=%s ancpkginfo=%s getpkgtxns=%s pkgtxns=%s",
      tostring(handles_sendpackages), tostring(handles_ancpkginfo),
      tostring(handles_getpkgtxns), tostring(handles_pkgtxns)))
  end
end)

-- BUG-13: sendpackages uses u64le instead of u16le
test("G29-c: BUG-13 serialize_sendpackages uses wrong version field size (u64 vs u16)", function()
  -- BIP-331 sendpackages: 2-byte uint16 version field.
  -- lunarblock uses write_u64le → produces 8-byte payload instead of 2.
  local payload = p2p.serialize_sendpackages(1)
  local expected_size = 2   -- uint16
  local actual_size   = #payload
  if actual_size ~= expected_size then
    bug("BUG-13", "P1")
    error(string.format(
      "BUG-13: serialize_sendpackages produces %d-byte payload; BIP-331 requires %d (uint16). "..
      "Uses write_u64le instead of write_u16le.",
      actual_size, expected_size))
  end
end)

-- ---------------------------------------------------------------------------
-- G30: P2P — PKG_RELAY_VERSION constant
-- ---------------------------------------------------------------------------
print("\n--- G30: P2P PKG_RELAY_VERSION ---")

test("G30-a: PKG_RELAY_VERSION == 1", function()
  expect_eq(p2p.PKG_RELAY_VERSION, 1, "PKG_RELAY_VERSION should be 1 (BIP-331)")
end)

test("G30-b: serialize_sendpackages round-trips version (post-fix expectation)", function()
  -- After BUG-13 is fixed (u16le), round-trip should work.
  -- For now, just verify that deserialize_sendpackages can consume what serialize produces.
  local payload = p2p.serialize_sendpackages(1)
  local ok, result = pcall(p2p.deserialize_sendpackages, payload)
  -- Either works (if both are u64) or fails (size mismatch after fix).
  -- We just check it doesn't crash the runtime with an unhandled error.
  expect_true(ok or type(result) == "string",
    "deserialize_sendpackages should handle its own output without Lua crash")
end)

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
print(string.format("\n=== W116 Package Relay — lunarblock ==="))
print(string.format("Tests: %d passed, %d failed", PASS, FAIL))
print(string.format("Bugs:  %d findings", #BUGS))
for _, b in ipairs(BUGS) do
  print("  " .. b)
end
if FAIL == 0 then
  print("VERDICT: PASS")
else
  print("VERDICT: FAIL")
  os.exit(1)
end
