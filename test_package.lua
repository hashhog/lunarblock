-- Test package validation
package.path = "./lunarblock/?.lua;" .. package.path
package.cpath = "./lib/?.so;" .. package.cpath

local types = require("lunarblock.types")
local mempool = require("lunarblock.mempool")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local p2p = require("lunarblock.p2p")

local function make_tx(version, inputs, outputs, locktime)
  return types.transaction(version or 1, inputs or {}, outputs or {}, locktime or 0)
end

local function make_input(txid_hash, vout, sequence)
  return types.txin(
    types.outpoint(txid_hash, vout),
    "",
    sequence or 0xFFFFFFFE
  )
end

local function make_output(value, script_pubkey)
  return types.txout(value, script_pubkey or string.rep("\x00", 25))
end

local function make_mock_chain_state(utxos)
  utxos = utxos or {}
  local mock_coin_view = {
    utxos = utxos,
    get = function(self, txid, vout)
      local key = types.hash256_hex(txid) .. ":" .. vout
      return self.utxos[key]
    end
  }
  return {
    coin_view = mock_coin_view,
    tip_height = 700000
  }
end

local function add_utxo(chain_state, txid_hex, vout, value, script_pubkey, height, is_coinbase)
  local key = txid_hex .. ":" .. vout
  chain_state.coin_view.utxos[key] = {
    value = value,
    script_pubkey = script_pubkey or string.rep("\x00", 25),
    height = height or 500000,
    is_coinbase = is_coinbase or false
  }
end

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then
    print("PASS: " .. name)
  else
    print("FAIL: " .. name)
    print("  Error: " .. tostring(err))
  end
end

local function assert_true(val, msg)
  if not val then error(msg or "Expected true but got false") end
end

local function assert_false(val, msg)
  if val then error(msg or "Expected false but got true") end
end

local function assert_equal(expected, actual, msg)
  if expected ~= actual then
    error((msg or "Assertion failed") .. ": expected " .. tostring(expected) .. " but got " .. tostring(actual))
  end
end

local function assert_match(pattern, str, msg)
  if not str:match(pattern) then
    error((msg or "Pattern not found") .. ": expected pattern '" .. pattern .. "' in '" .. str .. "'")
  end
end

print("\n=== Package Validation Tests ===\n")

-- Test MAX_PACKAGE_COUNT constant
test("MAX_PACKAGE_COUNT is 25", function()
  assert_equal(25, mempool.MAX_PACKAGE_COUNT)
end)

-- Test topological sort
test("is_topo_sorted_package accepts parent before child", function()
  local base_txid = types.hash256(string.rep("\x01", 32))
  local parent = make_tx(1, {}, {}, 0)
  parent.inputs[1] = make_input(base_txid, 0)
  parent.outputs[1] = make_output(99990000)
  local parent_txid = validation.compute_txid(parent)

  local child = make_tx(1, {}, {}, 0)
  child.inputs[1] = make_input(parent_txid, 0)
  child.outputs[1] = make_output(99980000)

  local ok = mempool.is_topo_sorted_package({parent, child})
  assert_true(ok)
end)

test("is_topo_sorted_package rejects child before parent", function()
  local base_txid = types.hash256(string.rep("\x01", 32))
  local parent = make_tx(1, {}, {}, 0)
  parent.inputs[1] = make_input(base_txid, 0)
  parent.outputs[1] = make_output(99990000)
  local parent_txid = validation.compute_txid(parent)

  local child = make_tx(1, {}, {}, 0)
  child.inputs[1] = make_input(parent_txid, 0)
  child.outputs[1] = make_output(99980000)

  -- Wrong order
  local ok = mempool.is_topo_sorted_package({child, parent})
  assert_false(ok)
end)

-- Test consistent package
test("is_consistent_package accepts non-conflicting txs", function()
  local txid1 = types.hash256(string.rep("\x01", 32))
  local txid2 = types.hash256(string.rep("\x02", 32))

  local tx1 = make_tx(1, {}, {}, 0)
  tx1.inputs[1] = make_input(txid1, 0)
  tx1.outputs[1] = make_output(50000)

  local tx2 = make_tx(1, {}, {}, 0)
  tx2.inputs[1] = make_input(txid2, 0)
  tx2.outputs[1] = make_output(50000)

  local ok = mempool.is_consistent_package({tx1, tx2})
  assert_true(ok)
end)

test("is_consistent_package rejects conflicting inputs", function()
  local txid1 = types.hash256(string.rep("\x01", 32))

  local tx1 = make_tx(1, {}, {}, 0)
  tx1.inputs[1] = make_input(txid1, 0)
  tx1.outputs[1] = make_output(50000)

  local tx2 = make_tx(1, {}, {}, 0)
  tx2.inputs[1] = make_input(txid1, 0)  -- Same outpoint!
  tx2.outputs[1] = make_output(50000)

  local ok, err = mempool.is_consistent_package({tx1, tx2})
  assert_false(ok)
  assert_equal("conflict in package", err)
end)

-- Test well-formed package
test("is_well_formed_package rejects empty package", function()
  local ok, err = mempool.is_well_formed_package({})
  assert_false(ok)
  assert_equal("empty package", err)
end)

test("is_well_formed_package rejects > 25 txs", function()
  local txns = {}
  for i = 1, 26 do
    local txid = types.hash256(string.rep(string.char(i), 32))
    local tx = make_tx(1, {}, {}, 0)
    tx.inputs[1] = make_input(txid, 0)
    tx.outputs[1] = make_output(50000)
    txns[i] = tx
  end

  local ok, err = mempool.is_well_formed_package(txns)
  assert_false(ok)
  assert_equal("package-too-many-transactions", err)
end)

-- Test child-with-parents
test("is_child_with_parents for valid package", function()
  local base_txid = types.hash256(string.rep("\x01", 32))
  local parent = make_tx(1, {}, {}, 0)
  parent.inputs[1] = make_input(base_txid, 0)
  parent.outputs[1] = make_output(50000)
  local parent_txid = validation.compute_txid(parent)

  local child = make_tx(1, {}, {}, 0)
  child.inputs[1] = make_input(parent_txid, 0)
  child.outputs[1] = make_output(40000)

  assert_true(mempool.is_child_with_parents({parent, child}))
end)

print("\n=== CPFP Package Acceptance Tests ===\n")

-- Test CPFP
test("CPFP: child pays for low-fee parent", function()
  local chain_state = make_mock_chain_state()
  local base_txid = types.hash256(string.rep("\x01", 32))
  local base_txid_hex = types.hash256_hex(base_txid)
  add_utxo(chain_state, base_txid_hex, 0, 100000000)

  local mp = mempool.new(chain_state)

  -- Parent with LOW fee (would be rejected individually)
  -- With ~85 vB tx, need fee < 85 sat for < 1 sat/vB (< 1000 sat/KB)
  local parent = make_tx(1, {}, {}, 0)
  parent.inputs[1] = make_input(base_txid, 0)
  parent.outputs[1] = make_output(99999980)  -- 20 sat fee (way below min)
  local parent_txid = validation.compute_txid(parent)

  -- Child with HIGH fee (pays for both)
  local child = make_tx(1, {}, {}, 0)
  child.inputs[1] = make_input(parent_txid, 0)
  child.outputs[1] = make_output(99899980)  -- 100000 sat fee (high)

  -- Parent alone should fail
  local ok_parent, err_parent = mp:accept_transaction(parent)
  assert_false(ok_parent, "Parent should be rejected alone")
  assert_match("fee rate too low", err_parent)

  -- Accept as package
  local ok, result = mp:accept_package({parent, child})
  assert_true(ok, "Package should be accepted")
  assert_equal(2, #result.txids)
  assert_equal(2, mp.tx_count)
end)

test("CPFP: rejects package with combined fee rate too low", function()
  local chain_state = make_mock_chain_state()
  local base_txid = types.hash256(string.rep("\x01", 32))
  add_utxo(chain_state, types.hash256_hex(base_txid), 0, 100000000)

  local mp = mempool.new(chain_state)

  local parent = make_tx(1, {}, {}, 0)
  parent.inputs[1] = make_input(base_txid, 0)
  parent.outputs[1] = make_output(99999990)  -- 10 sat fee
  local parent_txid = validation.compute_txid(parent)

  local child = make_tx(1, {}, {}, 0)
  child.inputs[1] = make_input(parent_txid, 0)
  child.outputs[1] = make_output(99999980)  -- 10 sat fee

  local ok, err = mp:accept_package({parent, child})
  assert_false(ok)
  assert_match("package fee rate too low", err)
end)

test("CPFP: tracks ancestor/descendant correctly", function()
  local chain_state = make_mock_chain_state()
  local base_txid = types.hash256(string.rep("\x01", 32))
  add_utxo(chain_state, types.hash256_hex(base_txid), 0, 100000000)

  local mp = mempool.new(chain_state)

  local parent = make_tx(1, {}, {}, 0)
  parent.inputs[1] = make_input(base_txid, 0)
  parent.outputs[1] = make_output(99990000)
  local parent_txid = validation.compute_txid(parent)

  local child = make_tx(1, {}, {}, 0)
  child.inputs[1] = make_input(parent_txid, 0)
  child.outputs[1] = make_output(99980000)

  local ok, result = mp:accept_package({parent, child})
  assert_true(ok)

  local parent_entry = mp:get_entry(result.txids[1])
  local child_entry = mp:get_entry(result.txids[2])

  assert_equal(0, parent_entry.ancestor_count)
  assert_equal(1, parent_entry.descendant_count)
  assert_equal(1, child_entry.ancestor_count)
  assert_equal(0, child_entry.descendant_count)
end)

print("\n=== P2P Package Relay Tests ===\n")

test("sendpackages serialization roundtrip", function()
  local payload = p2p.serialize_sendpackages(1)
  local result = p2p.deserialize_sendpackages(payload)
  assert_equal(1, result.version)
end)

test("ancpkginfo serialization roundtrip", function()
  local wtxid = types.hash256(string.rep("\xab", 32))
  local payload = p2p.serialize_ancpkginfo(wtxid)
  local result = p2p.deserialize_ancpkginfo(payload)
  assert_equal(wtxid.bytes, result.wtxid.bytes)
end)

test("getpkgtxns serialization roundtrip", function()
  local pkg_hash = types.hash256(string.rep("\xcd", 32))
  local wtxid1 = types.hash256(string.rep("\x01", 32))
  local wtxid2 = types.hash256(string.rep("\x02", 32))

  local payload = p2p.serialize_getpkgtxns(pkg_hash, {wtxid1, wtxid2})
  local result = p2p.deserialize_getpkgtxns(payload)

  assert_equal(pkg_hash.bytes, result.package_hash.bytes)
  assert_equal(2, #result.wtxids)
  assert_equal(wtxid1.bytes, result.wtxids[1].bytes)
  assert_equal(wtxid2.bytes, result.wtxids[2].bytes)
end)

test("pckginfo1 serialization roundtrip", function()
  local parent_wtxid = types.hash256(string.rep("\x01", 32))
  local child_wtxid = types.hash256(string.rep("\x02", 32))

  local payload = p2p.serialize_pckginfo1(parent_wtxid, child_wtxid)
  local result = p2p.deserialize_pckginfo1(payload)

  assert_equal(parent_wtxid.bytes, result.parent_wtxid.bytes)
  assert_equal(child_wtxid.bytes, result.child_wtxid.bytes)
end)

print("\n=== All Tests Complete ===\n")
