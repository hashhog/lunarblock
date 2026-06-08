#!/usr/bin/env luajit
-- Roundtrip test for prioritisetransaction + getprioritisedtransactions.
-- Run: LD_LIBRARY_PATH=./lib luajit test_prioritise_transaction.lua
--
-- Covers the Core shape contract (rpc/mining.cpp + txmempool.cpp):
--   * prioritisetransaction STACKS deltas additively onto map_deltas
--   * GetModifiedFee = base_fee + delta
--   * getprioritisedtransactions returns a txid-keyed OBJECT; each value has
--       fee_delta (i64, ALWAYS present), in_mempool (bool),
--       modified_fee (i64, ONLY when in_mempool == true)
--   * a non-zero legacy `dummy` arg is REJECTED (RPC_INVALID_PARAMETER -8)
--   * a net delta of 0 ERASES the entry
--   * a delta on a txid NOT in the mempool appears with in_mempool=false and
--     NO modified_fee
--   * deltas survive a mempool.dat dump/load roundtrip
--
-- Reference: bitcoin-core/src/rpc/mining.cpp:{prioritisetransaction,
-- getprioritisedtransactions}, src/txmempool.cpp:{PrioritiseTransaction,
-- GetPrioritisedTransactions, GetModifiedFee, mapDeltas}.

package.path = './src/?.lua;./lunarblock/?.lua;' .. package.path
package.cpath = './lib/?.so;' .. package.cpath

local types = require("lunarblock.types")
local mempool = require("lunarblock.mempool")
local rpc = require("lunarblock.rpc")
local mempool_persist = require("lunarblock.mempool_persist")
local cjson = require("cjson")

-- Standard P2PKH scriptPubKey (mock; verify_input_scripts defaults off).
local P2PKH_SCRIPT = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"

local passed, failed = 0, 0

local function ok_(cond, msg)
  if cond then
    passed = passed + 1
    print("  PASS: " .. msg)
  else
    failed = failed + 1
    print("  FAIL: " .. msg)
  end
end

local function eq_(actual, expected, msg)
  if actual == expected then
    passed = passed + 1
    print("  PASS: " .. msg)
  else
    failed = failed + 1
    print(string.format("  FAIL: %s (expected %s, got %s)",
      msg, tostring(expected), tostring(actual)))
  end
end

--------------------------------------------------------------------------------
-- Fixtures: a mock chain state + a single accepted mempool tx T.
--------------------------------------------------------------------------------
local function make_mock_chain_state()
  local mock_coin_view = {
    utxos = {},
    get = function(self, txid, vout)
      return self.utxos[types.hash256_hex(txid) .. ":" .. vout]
    end,
  }
  return { coin_view = mock_coin_view, tip_height = 700000 }
end

local function add_utxo(cs, txid_hex, vout, value)
  cs.coin_view.utxos[txid_hex .. ":" .. vout] = {
    value = value, script_pubkey = P2PKH_SCRIPT, height = 500000, is_coinbase = false,
  }
end

-- Build a mempool with one accepted tx; returns mp, txid_hex, base_fee.
local function make_mp_with_tx(seed_byte, value, fee)
  value = value or 100000
  fee = fee or 12345
  local cs = make_mock_chain_state()
  local seed_txid = types.hash256(string.rep(seed_byte or "\xaa", 32))
  add_utxo(cs, types.hash256_hex(seed_txid), 0, value)
  local mp = mempool.new(cs, {})
  local tx = types.transaction(1, {}, {}, 0)
  tx.inputs[1] = types.txin(types.outpoint(seed_txid, 0), "", 0xFFFFFFFE)
  tx.outputs[1] = types.txout(value - fee, P2PKH_SCRIPT)
  local accepted, txid_hex = mp:accept_transaction(tx)
  assert(accepted, "fixture tx must be accepted: " .. tostring(txid_hex))
  return mp, txid_hex, mp:get_entry(txid_hex).fee
end

-- Drive a method through the full RPC dispatch (faithful black-box of the
-- shape contract).  Returns result, err (err is the structured {code,message}).
local function call_rpc(server, method, params)
  local resp = server:handle_single_request({
    jsonrpc = "2.0", id = 1, method = method, params = params,
  })
  if resp.error and resp.error ~= cjson.null then
    return nil, resp.error
  end
  return resp.result, nil
end

--------------------------------------------------------------------------------
print("=== prioritisetransaction / getprioritisedtransactions roundtrip ===\n")

print("TEST 1: prioritise(+1000) → fee_delta=1000, in_mempool=true, modified_fee=base+1000")
local mp, T, base = make_mp_with_tx()
local server = rpc.new({ mempool = mp })

do
  local r, e = call_rpc(server, "prioritisetransaction", { T, 0, 1000 })
  ok_(e == nil and r == true, "prioritisetransaction(T, 0, +1000) returns true")

  local gp = select(1, call_rpc(server, "getprioritisedtransactions", {}))
  local entry = gp[T]
  ok_(entry ~= nil, "getprioritisedtransactions has key T")
  eq_(entry and entry.fee_delta, 1000, "fee_delta == 1000")
  eq_(entry and entry.in_mempool, true, "in_mempool == true")
  eq_(entry and entry.modified_fee, base + 1000, "modified_fee == base + 1000")
  -- GetModifiedFee at the mempool layer must agree.
  eq_(mp:get_modified_fee(T), base + 1000, "Mempool:get_modified_fee == base + 1000")
end

print("\nTEST 2: prioritise(+500) STACKS additively → fee_delta=1500")
do
  call_rpc(server, "prioritisetransaction", { T, 0, 500 })
  local gp = select(1, call_rpc(server, "getprioritisedtransactions", {}))
  eq_(gp[T] and gp[T].fee_delta, 1500, "fee_delta stacked to 1500")
  eq_(gp[T] and gp[T].modified_fee, base + 1500, "modified_fee == base + 1500")
  eq_(mp:get_modified_fee(T), base + 1500, "get_modified_fee == base + 1500 after stack")
end

print("\nTEST 3: non-zero dummy is REJECTED (RPC_INVALID_PARAMETER -8)")
do
  local r, e = call_rpc(server, "prioritisetransaction", { T, 1.0, 100 })
  ok_(r == nil and e ~= nil, "request errored")
  eq_(e and e.code, -8, "error code is -8 (RPC_INVALID_PARAMETER)")
  -- The rejected call must not have mutated the delta.
  local gp = select(1, call_rpc(server, "getprioritisedtransactions", {}))
  eq_(gp[T] and gp[T].fee_delta, 1500, "delta unchanged after rejected call")
end

print("\nTEST 4: net delta back to 0 ERASES the entry")
do
  call_rpc(server, "prioritisetransaction", { T, 0, -1500 })
  local gp = select(1, call_rpc(server, "getprioritisedtransactions", {}))
  ok_(gp[T] == nil, "T absent from getprioritisedtransactions after net-zero")
  -- map_deltas key gone; modified fee falls back to base.
  ok_(mp.map_deltas[T] == nil, "map_deltas[T] erased")
  eq_(mp:get_modified_fee(T), base, "get_modified_fee back to base")
  -- The in-mempool entry's modified_fee is restored to base too.
  eq_(mp:get_entry(T).modified_fee, base, "entry.modified_fee restored to base")
end

print("\nTEST 5: delta on a txid NOT in mempool → in_mempool=false, NO modified_fee")
do
  local ghost = string.rep("ab", 32)  -- 64-char hex, not a real mempool tx
  call_rpc(server, "prioritisetransaction", { ghost, 0, 7777 })
  local gp = select(1, call_rpc(server, "getprioritisedtransactions", {}))
  local g = gp[ghost]
  ok_(g ~= nil, "ghost txid present in map")
  eq_(g and g.fee_delta, 7777, "ghost fee_delta == 7777 (always present)")
  eq_(g and g.in_mempool, false, "ghost in_mempool == false")
  ok_(g and g.modified_fee == nil, "ghost has NO modified_fee field")
end

print("\nTEST 6: JSON shape byte-match — encode the RPC result and inspect keys")
do
  -- Re-prioritise T so we have one in-mempool + one out-of-mempool entry.
  call_rpc(server, "prioritisetransaction", { T, 0, 2000 })
  local gp = select(1, call_rpc(server, "getprioritisedtransactions", {}))
  local encoded = cjson.encode(gp)
  -- in_mempool entry: has fee_delta + in_mempool + modified_fee
  local tin = gp[T]
  ok_(tin.fee_delta ~= nil and tin.in_mempool == true and tin.modified_fee ~= nil,
    "in-mempool entry has fee_delta + in_mempool + modified_fee")
  -- out-of-mempool entry: has fee_delta + in_mempool, NO modified_fee
  local tout = gp[string.rep("ab", 32)]
  ok_(tout.fee_delta ~= nil and tout.in_mempool == false and tout.modified_fee == nil,
    "out-of-mempool entry omits modified_fee")
  -- fee_delta is an integer satoshi value (signed i64 domain).
  ok_(tin.fee_delta == math.floor(tin.fee_delta), "fee_delta is integer satoshis")
  ok_(type(encoded) == "string" and #encoded > 0, "result JSON-encodes as an object")
  print("    encoded = " .. encoded)
end

print("\nTEST 7: empty map encodes as a JSON object {} (Core OBJ_DYN), not []")
do
  local mp2, _, _ = make_mp_with_tx("\xbb")
  local server2 = rpc.new({ mempool = mp2 })
  local gp = select(1, call_rpc(server2, "getprioritisedtransactions", {}))
  local encoded = cjson.encode(gp)
  eq_(encoded, "{}", "empty prioritised map encodes as {}")
end

print("\nTEST 8: deltas survive a mempool.dat dump/load roundtrip")
do
  -- Fresh mempool with one in-mempool tx (delta) + one ghost (standalone delta).
  local mpA, Ta, baseA = make_mp_with_tx("\xcc")
  mpA:prioritise_transaction(Ta, 4000)
  local ghost = string.rep("cd", 32)
  mpA:prioritise_transaction(ghost, -250)

  local tmp = os.tmpname()
  local dumped_ok, n = mempool_persist.dump(mpA, tmp)
  ok_(dumped_ok, "dump() succeeded (" .. tostring(n) .. " txs)")

  -- Load into a NEW mempool that shares the same chain state (so Ta re-accepts).
  -- Reuse mpA's chain_state by constructing a fresh mempool over it.
  local mpB = mempool.new(mpA.chain_state, {})
  local loaded_ok, stats = mempool_persist.load(mpB, tmp, { use_current_time = true })
  os.remove(tmp)
  ok_(loaded_ok, "load() succeeded")

  -- In-mempool delta restored onto the re-accepted tx.
  eq_(mpB.map_deltas[Ta], 4000, "in-mempool delta restored to 4000")
  ok_(mpB:get_entry(Ta) ~= nil, "tx Ta re-accepted into loaded mempool")
  eq_(mpB:get_modified_fee(Ta), baseA + 4000, "restored modified fee == base + 4000")
  -- Standalone (ghost) delta restored.
  eq_(mpB.map_deltas[ghost], -250, "standalone ghost delta restored to -250")

  -- getprioritisedtransactions on the loaded mempool shows both with the
  -- correct in_mempool flags.
  local serverB = rpc.new({ mempool = mpB })
  local gp = select(1, call_rpc(serverB, "getprioritisedtransactions", {}))
  eq_(gp[Ta] and gp[Ta].in_mempool, true, "restored Ta in_mempool == true")
  eq_(gp[Ta] and gp[Ta].modified_fee, baseA + 4000, "restored Ta modified_fee correct")
  eq_(gp[ghost] and gp[ghost].in_mempool, false, "restored ghost in_mempool == false")
  ok_(gp[ghost] and gp[ghost].modified_fee == nil, "restored ghost has NO modified_fee")
end

--------------------------------------------------------------------------------
-- EFFECT tests (FIX-72): the delta must drive MINING + EVICTION, not just RPC.
--
-- Helper: accept an independent (no-ancestor) tx into an EXISTING mempool by
-- spending a fresh confirmed seed UTXO.  Each tx has a single output, so the
-- base fee == value - output_value and there are no in-mempool ancestors —
-- exactly the single-entry case FIX-72 routes through the modified fee.
--------------------------------------------------------------------------------
local function add_independent_tx(mp, cs, seed_byte, value, fee)
  local seed_txid = types.hash256(string.rep(seed_byte, 32))
  add_utxo(cs, types.hash256_hex(seed_txid), 0, value)
  local tx = types.transaction(1, {}, {}, 0)
  tx.inputs[1] = types.txin(types.outpoint(seed_txid, 0), "", 0xFFFFFFFE)
  tx.outputs[1] = types.txout(value - fee, P2PKH_SCRIPT)
  local accepted, txid_hex = mp:accept_transaction(tx)
  assert(accepted, "independent tx must be accepted: " .. tostring(txid_hex))
  return txid_hex, mp:get_entry(txid_hex)
end

-- Index of a txid within an ordered list of entries (1-based), or nil.
local function rank_of(sorted_entries, txid_hex)
  for i, e in ipairs(sorted_entries) do
    if types.hash256_hex(e.txid) == txid_hex then return i end
  end
  return nil
end

print("\nTEST 9: MINING — prioritising a LOW-base-fee tx ranks it ABOVE a higher-base-fee tx")
do
  -- Same vsize for A and B (single P2PKH in/out), so feerate order == fee order.
  -- A has a LOWER base fee than B → before prioritise, B outranks A.
  local cs = make_mock_chain_state()
  local mp9 = mempool.new(cs, {})
  local A = add_independent_tx(mp9, cs, "\xa1", 100000, 1000)  -- low base fee
  local B = add_independent_tx(mp9, cs, "\xb2", 100000, 5000)  -- higher base fee

  -- Baseline: B (higher base fee) ranks ahead of A.
  local before = mp9:get_sorted_entries()
  local ra0, rb0 = rank_of(before, A), rank_of(before, B)
  ok_(ra0 and rb0, "both A and B present in baseline sort")
  ok_(rb0 < ra0, "baseline: B (higher base fee) ranks ahead of A")

  -- Prioritise A by +big so its MODIFIED fee exceeds B's base fee.
  -- A base 1000, B base 5000; +5000 makes A's modified fee 6000 > 5000.
  mp9:prioritise_transaction(A, 5000)
  eq_(mp9:get_modified_fee(A), 6000, "A modified fee == base 1000 + 5000 delta")

  local after = mp9:get_sorted_entries()
  local ra1, rb1 = rank_of(after, A), rank_of(after, B)
  ok_(ra1 < rb1, "after prioritise: A (modified feerate higher) ranks AHEAD of B")
  -- And A is now the top mining candidate.
  eq_(types.hash256_hex(after[1].txid), A, "A is the #1 block-template candidate")
end

print("\nTEST 10: MINING — un-prioritised order is byte-identical to base-fee order")
do
  -- Pure base-fee ordering with no deltas must be unchanged by FIX-72.
  local cs = make_mock_chain_state()
  local mp10 = mempool.new(cs, {})
  local hi  = add_independent_tx(mp10, cs, "\xc3", 100000, 9000)  -- highest fee
  local mid = add_independent_tx(mp10, cs, "\xd4", 100000, 5000)
  local lo  = add_independent_tx(mp10, cs, "\xe5", 100000, 1000)  -- lowest fee
  local s = mp10:get_sorted_entries()
  eq_(types.hash256_hex(s[1].txid), hi,  "no-delta sort: #1 is highest base fee")
  eq_(types.hash256_hex(s[2].txid), mid, "no-delta sort: #2 is middle base fee")
  eq_(types.hash256_hex(s[3].txid), lo,  "no-delta sort: #3 is lowest base fee")
end

print("\nTEST 11: EVICTION — a prioritised low-base-fee tx survives; lowest MODIFIED feerate is evicted")
do
  -- Two equal-vsize txs. A has the lower base fee → without prioritise A would
  -- be evicted first under pressure.  Prioritise A so its MODIFIED feerate
  -- exceeds B's → B (now lowest modified feerate) must be the eviction victim.
  local cs = make_mock_chain_state()
  local mp11 = mempool.new(cs, {})
  local A = add_independent_tx(mp11, cs, "\xf6", 100000, 1000)  -- low base fee
  local B = add_independent_tx(mp11, cs, "\x17", 100000, 5000)  -- higher base fee
  ok_(mp11:get_entry(A) ~= nil and mp11:get_entry(B) ~= nil, "A and B both resident")

  -- Prioritise A above B by modified fee (1000 + 5000 = 6000 > 5000).
  mp11:prioritise_transaction(A, 5000)

  -- Force eviction of exactly one entry: set max_size just below current total
  -- so a single trim() pass drops the single lowest-modified-feerate tx.
  -- A and B are independent (no descendants), so each is its own cluster.
  local sizeA = mp11:get_entry(A).size
  local sizeB = mp11:get_entry(B).size
  mp11.max_size = mp11.total_size - 1   -- must evict at least one
  mp11:trim()

  ok_(mp11:get_entry(A) ~= nil, "prioritised low-base-fee A SURVIVES eviction")
  ok_(mp11:get_entry(B) == nil, "higher-base-fee B (now lowest MODIFIED feerate) is EVICTED")
end

print("\nTEST 12: EVICTION — without prioritise, the lowest BASE-fee tx is evicted (unchanged)")
do
  -- Control for TEST 11: no deltas → the lowest base-fee tx is the victim,
  -- proving un-prioritised eviction behaviour is byte-identical.
  local cs = make_mock_chain_state()
  local mp12 = mempool.new(cs, {})
  local A = add_independent_tx(mp12, cs, "\x28", 100000, 1000)  -- low base fee
  local B = add_independent_tx(mp12, cs, "\x39", 100000, 5000)  -- higher base fee
  mp12.max_size = mp12.total_size - 1
  mp12:trim()
  ok_(mp12:get_entry(A) == nil, "no-delta: lowest BASE-fee A is evicted")
  ok_(mp12:get_entry(B) ~= nil, "no-delta: higher-base-fee B survives")
end

print(string.format("\n=== %d passed, %d failed ===", passed, failed))
os.exit(failed == 0 and 0 or 1)
