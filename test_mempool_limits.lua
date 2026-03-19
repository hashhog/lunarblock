#!/usr/bin/env luajit
-- Test script for mempool ancestor/descendant limits
-- Run: LD_LIBRARY_PATH=./lib luajit test_mempool_limits.lua

package.path = './src/?.lua;./lunarblock/?.lua;' .. package.path
package.cpath = './lib/?.so;' .. package.cpath

local types = require("types")
local mempool = require("mempool")
local validation = require("validation")

local passed = 0
local failed = 0

local function assert_eq(actual, expected, msg)
  if actual == expected then
    passed = passed + 1
    print("  PASS: " .. msg)
  else
    failed = failed + 1
    print("  FAIL: " .. msg .. " (expected " .. tostring(expected) .. ", got " .. tostring(actual) .. ")")
  end
end

local function assert_true(cond, msg)
  if cond then
    passed = passed + 1
    print("  PASS: " .. msg)
  else
    failed = failed + 1
    print("  FAIL: " .. msg)
  end
end

local function assert_match(str, pattern, msg)
  if str and str:match(pattern) then
    passed = passed + 1
    print("  PASS: " .. msg)
  else
    failed = failed + 1
    print("  FAIL: " .. msg .. " (string: " .. tostring(str) .. ")")
  end
end

-- Helper to create a simple transaction
local function make_tx(version, inputs, outputs, locktime)
  return types.transaction(version or 1, inputs or {}, outputs or {}, locktime or 0)
end

-- Helper to create input referencing an outpoint
local function make_input(txid_hash, vout, sequence)
  return types.txin(
    types.outpoint(txid_hash, vout),
    "",
    sequence or 0xFFFFFFFE
  )
end

-- Helper to create output
local function make_output(value, script_pubkey)
  return types.txout(value, script_pubkey or string.rep("\x00", 25))
end

-- Helper to create mock chain state
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

-- Add UTXO to mock chain state
local function add_utxo(chain_state, txid_hex, vout, value, script_pubkey, height, is_coinbase)
  local key = txid_hex .. ":" .. vout
  chain_state.coin_view.utxos[key] = {
    value = value,
    script_pubkey = script_pubkey or string.rep("\x00", 25),
    height = height or 500000,
    is_coinbase = is_coinbase or false
  }
end

print("=== Mempool Ancestor/Descendant Limits Tests ===\n")

-- Test 1: Chain of 25 transactions (should succeed)
print("TEST 1: Accept chain of 25 transactions (MAX_ANCESTORS)")
do
  local chain_state = make_mock_chain_state()
  local base_txid = types.hash256(string.rep("\x01", 32))
  local base_txid_hex = types.hash256_hex(base_txid)
  add_utxo(chain_state, base_txid_hex, 0, 500000000)

  local mp = mempool.new(chain_state)
  local current_txid = base_txid
  local all_accepted = true
  local last_hex = nil

  for i = 1, 25 do
    local tx = make_tx(1, {}, {}, 0)
    tx.inputs[1] = make_input(current_txid, 0)
    tx.outputs[1] = make_output(500000000 - i * 1000000)

    local ok, txid_hex = mp:accept_transaction(tx)
    if not ok then
      all_accepted = false
      print("    Failed at tx " .. i .. ": " .. tostring(txid_hex))
      break
    end
    last_hex = txid_hex
    current_txid = validation.compute_txid(tx)
  end

  assert_true(all_accepted, "All 25 transactions accepted")
  assert_eq(mp.tx_count, 25, "Mempool has 25 transactions")

  local last_entry = mp:get_entry(last_hex)
  assert_eq(last_entry.ancestor_count, 24, "Last tx has 24 ancestors")
end

-- Test 2: 26th transaction should be rejected
print("\nTEST 2: Reject 26th transaction (exceeds MAX_ANCESTORS)")
do
  local chain_state = make_mock_chain_state()
  local base_txid = types.hash256(string.rep("\x02", 32))
  local base_txid_hex = types.hash256_hex(base_txid)
  add_utxo(chain_state, base_txid_hex, 0, 600000000)

  local mp = mempool.new(chain_state)
  local current_txid = base_txid

  for i = 1, 25 do
    local tx = make_tx(1, {}, {}, 0)
    tx.inputs[1] = make_input(current_txid, 0)
    tx.outputs[1] = make_output(600000000 - i * 1000000)
    local ok, _ = mp:accept_transaction(tx)
    if ok then
      current_txid = validation.compute_txid(tx)
    end
  end

  -- 26th transaction
  local tx26 = make_tx(1, {}, {}, 0)
  tx26.inputs[1] = make_input(current_txid, 0)
  tx26.outputs[1] = make_output(600000000 - 26 * 1000000)

  local ok26, err26 = mp:accept_transaction(tx26)
  assert_true(not ok26, "26th transaction rejected")
  assert_match(err26, "too many ancestors", "Error mentions too many ancestors")
end

-- Test 3: Descendant limit enforcement
print("\nTEST 3: Enforce descendant limits")
do
  local chain_state = make_mock_chain_state()
  local root_txid = types.hash256(string.rep("\x03", 32))
  local root_txid_hex = types.hash256_hex(root_txid)
  for i = 0, 30 do
    add_utxo(chain_state, root_txid_hex, i, 10000000)
  end

  local mp = mempool.new(chain_state)

  -- Create parent with 30 outputs
  local parent_tx = make_tx(1, {}, {}, 0)
  parent_tx.inputs[1] = make_input(root_txid, 0)
  parent_tx.outputs = {}
  for i = 1, 30 do
    parent_tx.outputs[i] = make_output(300000)
  end

  local ok_parent, parent_hex = mp:accept_transaction(parent_tx)
  assert_true(ok_parent, "Parent transaction accepted")

  local parent_txid = validation.compute_txid(parent_tx)

  -- Create 25 children
  for i = 0, 24 do
    local child = make_tx(1, {}, {}, 0)
    child.inputs[1] = make_input(parent_txid, i)
    child.outputs[1] = make_output(290000)
    local ok, _ = mp:accept_transaction(child)
    assert_true(ok, "Child " .. i .. " accepted")
  end

  local parent_entry = mp:get_entry(parent_hex)
  assert_eq(parent_entry.descendant_count, 25, "Parent has 25 descendants")

  -- 26th child should fail
  local child26 = make_tx(1, {}, {}, 0)
  child26.inputs[1] = make_input(parent_txid, 25)
  child26.outputs[1] = make_output(290000)

  local ok26, err26 = mp:accept_transaction(child26)
  assert_true(not ok26, "26th child rejected")
  assert_match(err26, "too many descendants", "Error mentions too many descendants")
end

-- Test 4: Proper ancestor deduplication (diamond pattern)
print("\nTEST 4: Diamond dependency deduplication")
do
  local chain_state = make_mock_chain_state()
  local root_txid = types.hash256(string.rep("\x04", 32))
  local root_txid_hex = types.hash256_hex(root_txid)
  add_utxo(chain_state, root_txid_hex, 0, 10000000)
  add_utxo(chain_state, root_txid_hex, 1, 10000000)

  local mp = mempool.new(chain_state)

  -- Parent A
  local parent_a = make_tx(1, {}, {}, 0)
  parent_a.inputs[1] = make_input(root_txid, 0)
  parent_a.outputs[1] = make_output(9990000)
  local ok_a, hex_a = mp:accept_transaction(parent_a)
  assert_true(ok_a, "Parent A accepted")
  local txid_a = validation.compute_txid(parent_a)

  -- Parent B
  local parent_b = make_tx(1, {}, {}, 0)
  parent_b.inputs[1] = make_input(root_txid, 1)
  parent_b.outputs[1] = make_output(9990000)
  local ok_b, hex_b = mp:accept_transaction(parent_b)
  assert_true(ok_b, "Parent B accepted")
  local txid_b = validation.compute_txid(parent_b)

  -- Child spending both parents
  local child = make_tx(1, {}, {}, 0)
  child.inputs[1] = make_input(txid_a, 0)
  child.inputs[2] = make_input(txid_b, 0)
  child.outputs[1] = make_output(19960000)

  local ok_child, hex_child = mp:accept_transaction(child)
  assert_true(ok_child, "Diamond child accepted")

  local child_entry = mp:get_entry(hex_child)
  assert_eq(child_entry.ancestor_count, 2, "Child has exactly 2 ancestors (not double-counted)")

  -- Both parents should have 1 descendant
  local entry_a = mp:get_entry(hex_a)
  local entry_b = mp:get_entry(hex_b)
  assert_eq(entry_a.descendant_count, 1, "Parent A has 1 descendant")
  assert_eq(entry_b.descendant_count, 1, "Parent B has 1 descendant")
end

-- Test 5: Descendant propagation through chain
print("\nTEST 5: Descendant counts propagate to all ancestors")
do
  local chain_state = make_mock_chain_state()
  local base_txid = types.hash256(string.rep("\x05", 32))
  local base_txid_hex = types.hash256_hex(base_txid)
  add_utxo(chain_state, base_txid_hex, 0, 100000000)

  local mp = mempool.new(chain_state)

  -- tx1 -> tx2 -> tx3
  local tx1 = make_tx(1, {}, {}, 0)
  tx1.inputs[1] = make_input(base_txid, 0)
  tx1.outputs[1] = make_output(99990000)
  local ok1, hex1 = mp:accept_transaction(tx1)
  local txid1 = validation.compute_txid(tx1)

  local tx2 = make_tx(1, {}, {}, 0)
  tx2.inputs[1] = make_input(txid1, 0)
  tx2.outputs[1] = make_output(99980000)
  local ok2, hex2 = mp:accept_transaction(tx2)
  local txid2 = validation.compute_txid(tx2)

  local tx3 = make_tx(1, {}, {}, 0)
  tx3.inputs[1] = make_input(txid2, 0)
  tx3.outputs[1] = make_output(99970000)
  local ok3, hex3 = mp:accept_transaction(tx3)

  local entry1 = mp:get_entry(hex1)
  local entry2 = mp:get_entry(hex2)
  local entry3 = mp:get_entry(hex3)

  assert_eq(entry1.descendant_count, 2, "tx1 has 2 descendants (tx2, tx3)")
  assert_eq(entry2.descendant_count, 1, "tx2 has 1 descendant (tx3)")
  assert_eq(entry3.descendant_count, 0, "tx3 has 0 descendants")
end

-- Test 6: Ancestor updates on removal
print("\nTEST 6: Ancestor counts update on removal")
do
  local chain_state = make_mock_chain_state()
  local base_txid = types.hash256(string.rep("\x06", 32))
  local base_txid_hex = types.hash256_hex(base_txid)
  add_utxo(chain_state, base_txid_hex, 0, 100000000)

  local mp = mempool.new(chain_state)

  -- tx1 -> tx2 -> tx3
  local tx1 = make_tx(1, {}, {}, 0)
  tx1.inputs[1] = make_input(base_txid, 0)
  tx1.outputs[1] = make_output(99990000)
  local ok1, hex1 = mp:accept_transaction(tx1)
  local txid1 = validation.compute_txid(tx1)

  local tx2 = make_tx(1, {}, {}, 0)
  tx2.inputs[1] = make_input(txid1, 0)
  tx2.outputs[1] = make_output(99980000)
  local ok2, hex2 = mp:accept_transaction(tx2)
  local txid2 = validation.compute_txid(tx2)

  local tx3 = make_tx(1, {}, {}, 0)
  tx3.inputs[1] = make_input(txid2, 0)
  tx3.outputs[1] = make_output(99970000)
  local ok3, hex3 = mp:accept_transaction(tx3)

  -- Remove tx3
  mp:remove_transaction(hex3, "test")

  local entry1 = mp:get_entry(hex1)
  local entry2 = mp:get_entry(hex2)

  assert_eq(entry1.descendant_count, 1, "tx1 now has 1 descendant after tx3 removed")
  assert_eq(entry2.descendant_count, 0, "tx2 now has 0 descendants after tx3 removed")
  assert_eq(mp.tx_count, 2, "Mempool has 2 transactions")
end

print("\n=== Results ===")
print("Passed: " .. passed)
print("Failed: " .. failed)

if failed > 0 then
  os.exit(1)
else
  print("\nAll tests passed!")
  os.exit(0)
end
