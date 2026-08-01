#!/usr/bin/env luajit
-- Test script for mempool cluster limits (Core v31: ancestor/descendant
-- limits removed; cluster count (64) and cluster weight (404,000) are the only
-- connected-component bounds.  Ancestor/descendant bookkeeping is still
-- maintained for TRUC checks and the wallet-facing package-limits query.)
-- Run: LD_LIBRARY_PATH=./lib luajit test_mempool_limits.lua

package.path = './src/?.lua;./lunarblock/?.lua;' .. package.path
package.cpath = './lib/?.so;' .. package.cpath

local types = require("types")
local mempool = require("mempool")
local validation = require("validation")

-- Standard P2PKH scriptPubKey: OP_DUP OP_HASH160 <20 zero bytes> OP_EQUALVERIFY OP_CHECKSIG
local P2PKH_SCRIPT = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"

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
  return types.txout(value, script_pubkey or P2PKH_SCRIPT)
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
    script_pubkey = script_pubkey or P2PKH_SCRIPT,
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

-- Test 2: linear chain — Core v31 REMOVED the ancestor-count limit
-- (`too-long-mempool-chain` no longer exists anywhere in Core's tree); the
-- cluster count limit (DEFAULT_CLUSTER_LIMIT=64, policy/policy.h:72) is the
-- only bound on a connected component.  64 chained txs accept; the 65th is
-- rejected "too-large-cluster" (validation.cpp:1343, txgraph.cpp:2059 uses
-- strictly-greater-than, so 64 accept and 65 reject).
print("\nTEST 2: Linear chain — 64 accepted, 65th rejected (cluster limit, Core v31)")
do
  local chain_state = make_mock_chain_state()
  local base_txid = types.hash256(string.rep("\x02", 32))
  local base_txid_hex = types.hash256_hex(base_txid)
  add_utxo(chain_state, base_txid_hex, 0, 600000000)

  local mp = mempool.new(chain_state)
  local current_txid = base_txid

  for i = 1, 64 do
    local tx = make_tx(1, {}, {}, 0)
    tx.inputs[1] = make_input(current_txid, 0)
    tx.outputs[1] = make_output(600000000 - i * 1000000)
    local ok, _ = mp:accept_transaction(tx)
    assert_true(ok, "Chain tx " .. i .. " accepted (no ancestor limit in v31)")
    if ok then
      current_txid = validation.compute_txid(tx)
    end
  end
  assert_eq(mp.tx_count, 64, "Mempool has 64 chained transactions")

  -- 65th transaction would make the cluster 65 > 64
  local tx65 = make_tx(1, {}, {}, 0)
  tx65.inputs[1] = make_input(current_txid, 0)
  tx65.outputs[1] = make_output(600000000 - 65 * 1000000)

  local ok65, err65 = mp:accept_transaction(tx65)
  assert_true(not ok65, "65th transaction rejected")
  assert_match(err65, "too%-large%-cluster", "Error is too-large-cluster")
end

-- Test 3: fan-out — Core v31 REMOVED the descendant-count limit; the cluster
-- count limit (64) is the only bound.  Parent + 63 children = 64 cluster
-- members accept; the 64th child (65th member) is rejected
-- "too-large-cluster".  Descendant bookkeeping is still maintained (Core
-- keeps it for the wallet-facing getPackageLimits query).
print("\nTEST 3: Fan-out — 63 children accepted, 64th rejected (cluster limit, Core v31)")
do
  local chain_state = make_mock_chain_state()
  local root_txid = types.hash256(string.rep("\x03", 32))
  local root_txid_hex = types.hash256_hex(root_txid)
  add_utxo(chain_state, root_txid_hex, 0, 100000000)

  local mp = mempool.new(chain_state)

  -- Create parent with 70 outputs (70 x 300000 = 21M <= 100M input)
  local parent_tx = make_tx(1, {}, {}, 0)
  parent_tx.inputs[1] = make_input(root_txid, 0)
  parent_tx.outputs = {}
  for i = 1, 70 do
    parent_tx.outputs[i] = make_output(300000)
  end

  local ok_parent, parent_hex = mp:accept_transaction(parent_tx)
  assert_true(ok_parent, "Parent transaction accepted")

  local parent_txid = validation.compute_txid(parent_tx)

  -- Create 63 children (cluster = parent + 63 = 64 members)
  for i = 0, 62 do
    local child = make_tx(1, {}, {}, 0)
    child.inputs[1] = make_input(parent_txid, i)
    child.outputs[1] = make_output(290000)
    local ok, _ = mp:accept_transaction(child)
    assert_true(ok, "Child " .. i .. " accepted")
  end

  local parent_entry = mp:get_entry(parent_hex)
  assert_eq(parent_entry.descendant_count, 63, "Parent has 63 descendants")

  -- 64th child would make the cluster 65 > 64
  local child64 = make_tx(1, {}, {}, 0)
  child64.inputs[1] = make_input(parent_txid, 63)
  child64.outputs[1] = make_output(290000)

  local ok64, err64 = mp:accept_transaction(child64)
  assert_true(not ok64, "64th child rejected")
  assert_match(err64, "too%-large%-cluster", "Error is too-large-cluster")
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

-- Test 7: Cluster count limit — constant and get_cluster_size function
-- W75 fix: old code used MAX_CLUSTER_SIZE=101 as count limit (wrong).
-- Correct limit is MAX_CLUSTER_COUNT=64 (DEFAULT_CLUSTER_LIMIT, policy/policy.h:72).
-- Note: pre-v31 Core also had ancestor/descendant limits (25) which bound a
-- linear chain before the cluster limit could; v31 removed them, so the
-- cluster count limit is now the ONLY bound in every topology.
print("\nTEST 7: Cluster count limit constant and per-cluster counting (W75 fix)")
do
  -- Verify the constant is correct before touching the mempool
  assert_eq(mempool.MAX_CLUSTER_COUNT, 64, "MAX_CLUSTER_COUNT constant == 64")

  -- A chain of 25 txs (ancestor limit) forms a single cluster of 25.
  -- get_cluster_size via M.get_cluster_size should report 25 for the root's root.
  local chain_state = make_mock_chain_state()
  local base_txid = types.hash256(string.rep("\x07", 32))
  local base_txid_hex = types.hash256_hex(base_txid)
  add_utxo(chain_state, base_txid_hex, 0, 700000000)

  local mp = mempool.new(chain_state)
  local current_txid = base_txid
  local first_hex = nil

  for i = 1, 25 do
    local tx = make_tx(1, {}, {}, 0)
    tx.inputs[1] = make_input(current_txid, 0)
    tx.outputs[1] = make_output(700000000 - i * 1000000)
    local ok, txid_hex_or_err = mp:accept_transaction(tx)
    assert_true(ok, "Chain tx " .. i .. " accepted")
    if i == 1 then first_hex = txid_hex_or_err end
    current_txid = validation.compute_txid(tx)
  end
  assert_eq(mp.tx_count, 25, "Mempool contains 25 transactions")

  -- The cluster that contains the first tx should have 25 members
  local root = mempool.uf_find(first_hex)
  local cluster_n = mempool.get_cluster_size(root)
  assert_eq(cluster_n, 25, "Cluster of 25-chain has 25 members (not 101)")

  -- 26th chain tx is ACCEPTED in v31 (no ancestor limit); the cluster count
  -- limit (64) is the only bound.  Extend the chain to 64 (all accepted),
  -- then the 65th must be rejected with "too-large-cluster".
  for i = 26, 64 do
    local tx = make_tx(1, {}, {}, 0)
    tx.inputs[1] = make_input(current_txid, 0)
    tx.outputs[1] = make_output(700000000 - i * 1000000)
    local ok, _ = mp:accept_transaction(tx)
    assert_true(ok, "Chain tx " .. i .. " accepted (no ancestor limit in v31)")
    current_txid = validation.compute_txid(tx)
  end
  local tx65 = make_tx(1, {}, {}, 0)
  tx65.inputs[1] = make_input(current_txid, 0)
  tx65.outputs[1] = make_output(700000000 - 65 * 1000000)
  local ok65, err65 = mp:accept_transaction(tx65)
  assert_true(not ok65, "65th chain tx rejected (cluster limit)")
  assert_match(err65, "too%-large%-cluster", "65th chain tx rejected with too-large-cluster")
end

-- Test 8: Cluster vsize function (W75 fix: vsize check was not implemented).
-- We verify get_cluster_vsize sums correctly and that the limit is exported.
-- Also verify the limit value: 101000 vbytes (101 kvB, policy/policy.h:74).
print("\nTEST 8: Cluster vsize limit — get_cluster_vsize correctness and constant (W75 fix)")
do
  assert_eq(mempool.MAX_CLUSTER_VSIZE, 101000, "MAX_CLUSTER_VSIZE == 101000 vbytes")

  local chain_state = make_mock_chain_state()
  local base_txid = types.hash256(string.rep("\x08", 32))
  local base_txid_hex = types.hash256_hex(base_txid)
  add_utxo(chain_state, base_txid_hex, 0, 500000000)

  local mp = mempool.new(chain_state)

  -- Accept a chain of 3 transactions
  local current_txid = base_txid
  local hex1, hex2, hex3
  local vsize_sum = 0

  local tx1 = make_tx(1, {}, {}, 0)
  tx1.inputs[1] = make_input(current_txid, 0)
  tx1.outputs[1] = make_output(499000000)
  local ok1, h1 = mp:accept_transaction(tx1)
  assert_true(ok1, "tx1 accepted")
  hex1 = h1
  vsize_sum = vsize_sum + mp.entries[hex1].vsize
  current_txid = validation.compute_txid(tx1)

  local tx2 = make_tx(1, {}, {}, 0)
  tx2.inputs[1] = make_input(current_txid, 0)
  tx2.outputs[1] = make_output(498000000)
  local ok2, h2 = mp:accept_transaction(tx2)
  assert_true(ok2, "tx2 accepted")
  hex2 = h2
  vsize_sum = vsize_sum + mp.entries[hex2].vsize
  current_txid = validation.compute_txid(tx2)

  local tx3 = make_tx(1, {}, {}, 0)
  tx3.inputs[1] = make_input(current_txid, 0)
  tx3.outputs[1] = make_output(497000000)
  local ok3, h3 = mp:accept_transaction(tx3)
  assert_true(ok3, "tx3 accepted")
  hex3 = h3
  vsize_sum = vsize_sum + mp.entries[hex3].vsize

  -- get_cluster_vsize via exported function must equal sum of individual vsizes
  local cluster_root = mempool.uf_find(hex1)
  local computed_vsize = mempool.get_cluster_vsize(cluster_root, mp.entries)
  assert_eq(computed_vsize, vsize_sum,
    "get_cluster_vsize(" .. computed_vsize .. ") == sum of 3 vsizes (" .. vsize_sum .. ")")
  assert_true(computed_vsize <= mempool.MAX_CLUSTER_VSIZE,
    "3-tx cluster vsize " .. computed_vsize .. " is within 101000 limit")
end

-- Test 9: Star topology — pre-v31 the descendant limit (25) bound a fan-out
-- before the cluster count limit (64) could; v31 removed the descendant
-- limit, so the cluster count limit is now the binding constraint in this
-- topology too: root + 63 children = 64 cluster members accept, the 64th
-- child is rejected "too-large-cluster".
-- Root in-mempool tx has 70 outputs (70 × 30000 sat each = 2.1M out of 3M in).
print("\nTEST 9: Star topology — cluster limit (64) is binding in v31 (descendant limit removed)")
do
  local chain_state = make_mock_chain_state()
  local root_txid = types.hash256(string.rep("\x09", 32))
  local root_txid_hex = types.hash256_hex(root_txid)
  -- One large confirmed UTXO for the root in-mempool tx
  add_utxo(chain_state, root_txid_hex, 0, 3000000)

  local mp = mempool.new(chain_state)

  -- Root in-mempool tx: 1 input (3,000,000 sat), 70 outputs (30,000 each = 2,100,000 total)
  -- Fee = 900,000 sat.
  local root_tx = make_tx(1, {}, {}, 0)
  root_tx.inputs[1] = make_input(root_txid, 0)
  root_tx.outputs = {}
  for i = 1, 70 do
    root_tx.outputs[i] = make_output(30000)
  end
  local ok_r, root_hex = mp:accept_transaction(root_tx)
  assert_true(ok_r, "Root tx accepted (1 in, 70 out, fee=900000)")
  local root_txid2 = validation.compute_txid(root_tx)

  -- Add children that each spend one of root_tx's outputs
  -- Each child: 1 input (30,000), 1 output (29,000), fee=1000
  local accepted_children = 0
  local last_err = nil
  for i = 0, 69 do
    local child = make_tx(1, {}, {}, 0)
    child.inputs[1] = make_input(root_txid2, i)
    child.outputs[1] = make_output(29000)
    local ok_c, err_c = mp:accept_transaction(child)
    if not ok_c then
      -- Cluster reached root + 63 children = 64 members; the 64th child
      -- would make it 65 > MAX_CLUSTER_COUNT.
      last_err = err_c
      break
    end
    accepted_children = accepted_children + 1
  end
  assert_eq(accepted_children, 63,
    "Exactly 63 children accepted (cluster limit = 64, descendant limit removed in v31)")
  assert_match(last_err, "too%-large%-cluster",
    "Star rejection is too-large-cluster, not a descendant limit")
  -- Cluster has root + 63 children = 64 members, exactly at the limit
  local cluster_root = mempool.uf_find(root_hex)
  local cluster_n = mempool.get_cluster_size(cluster_root)
  assert_eq(cluster_n, mempool.MAX_CLUSTER_COUNT,
    "Cluster of " .. cluster_n .. " is exactly MAX_CLUSTER_COUNT=" .. mempool.MAX_CLUSTER_COUNT)
end

-- Test 10: Cluster count constant value is 64 (not 101 — regression check)
print("\nTEST 10: Constant values are correct (W75 regression guard)")
do
  assert_eq(mempool.MAX_CLUSTER_COUNT, 64,   "MAX_CLUSTER_COUNT == 64 (DEFAULT_CLUSTER_LIMIT)")
  assert_eq(mempool.MAX_CLUSTER_VSIZE, 101000, "MAX_CLUSTER_VSIZE == 101000 (101 kvB)")
  assert_eq(mempool.MAX_ANCESTORS,     25,   "MAX_ANCESTORS == 25 (DEFAULT_ANCESTOR_LIMIT)")
  assert_eq(mempool.MAX_DESCENDANTS,   25,   "MAX_DESCENDANTS == 25 (DEFAULT_DESCENDANT_LIMIT)")
  assert_eq(mempool.MAX_ANCESTOR_SIZE,   101000, "MAX_ANCESTOR_SIZE == 101000 vbytes")
  assert_eq(mempool.MAX_DESCENDANT_SIZE, 101000, "MAX_DESCENDANT_SIZE == 101000 vbytes")
  assert_eq(mempool.EXTRA_DESCENDANT_TX_SIZE_LIMIT, 10000,
    "EXTRA_DESCENDANT_TX_SIZE_LIMIT == 10000 (policy/policy.h:90)")
  -- Legacy alias still works and points to COUNT (not 101)
  assert_eq(mempool.MAX_CLUSTER_SIZE, 64,
    "MAX_CLUSTER_SIZE legacy alias == 64 (not stale 101)")
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
