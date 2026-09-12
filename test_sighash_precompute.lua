#!/usr/bin/env luajit
-- Control for QUEUES.md lunarblock item 2 (validator throughput).
--
-- Script verification at 900k is dominated by BIP143/BIP341 sighash: lunarblock
-- recomputed hashPrevouts / hashSequence / hashOutputs (and the BIP341 single
-- SHA256 siblings) from scratch on every input. Core caches them once per tx
-- in PrecomputedTransactionData (script/interpreter.h, validation.cpp
-- CheckInputScripts). A consolidation tx with N inputs therefore hashed the
-- shared prefix N times — O(N²) over the prevout/output bytes.
--
-- This control:
--   1. Requires validation.precomputed_tx_data (the Core equivalent).
--   2. Asserts cached and uncached sighashes are byte-identical (consensus).
--   3. Asserts midstate hashing is O(1) in N, not O(N): wrapping crypto.hash256
--      / crypto.sha256, a 32-input SIGHASH_ALL walk must not issue 4N double
--      hashes of the shared prefix.
--   4. Prints a wall-clock rate so the commit body has a before/after number.
--
-- Run: luajit test_sighash_precompute.lua
-- Expected: PASS (after the cache lands). Before: FAIL.

package.path = "src/?.lua;lunarblock/?.lua;" .. package.path

local bit = require("bit")
local validation = require("lunarblock.validation")
local crypto = require("lunarblock.crypto")
local types = require("lunarblock.types")
local consensus = require("lunarblock.consensus")
local script = require("lunarblock.script")

local failed = 0
local passed = 0

local function test(name, fn)
  io.write("Testing: " .. name .. " ... ")
  io.flush()
  local ok, err = pcall(fn)
  if ok then
    print("PASS")
    passed = passed + 1
  else
    print("FAIL: " .. tostring(err))
    failed = failed + 1
  end
end

local function make_tx(n_in, n_out)
  local tx = types.transaction(2, {}, {}, 0)
  tx.segwit = true
  for i = 1, n_in do
    local prev = types.hash256(string.rep(string.char(i % 250 + 1), 32))
    local inp = types.txin(types.outpoint(prev, i - 1), "", 0xFFFFFFFE)
    inp.witness = {}
    tx.inputs[i] = inp
  end
  for i = 1, n_out do
    tx.outputs[i] = types.txout(1000 + i, script.make_p2wpkh_script(string.rep("\x11", 20)))
  end
  return tx
end

local function wrap_hash_counters()
  local n_hash256, n_sha256 = 0, 0
  local orig_hash256, orig_sha256 = crypto.hash256, crypto.sha256
  crypto.hash256 = function(...)
    n_hash256 = n_hash256 + 1
    return orig_hash256(...)
  end
  crypto.sha256 = function(...)
    n_sha256 = n_sha256 + 1
    return orig_sha256(...)
  end
  local function restore()
    crypto.hash256 = orig_hash256
    crypto.sha256 = orig_sha256
  end
  local function counts()
    return n_hash256, n_sha256
  end
  return restore, counts
end

-- ---------------------------------------------------------------------------
print("=== sighash PrecomputedTransactionData control ===\n")

test("precomputed_tx_data is exported", function()
  assert(type(validation.precomputed_tx_data) == "function",
    "validation.precomputed_tx_data missing — BIP143/BIP341 midstates are still recomputed per input")
end)

test("cached BIP143 sighash matches uncached (32-input SIGHASH_ALL)", function()
  assert(type(validation.precomputed_tx_data) == "function",
    "validation.precomputed_tx_data missing")
  local N = 32
  local tx = make_tx(N, N)
  local script_code = script.make_p2pkh_script(string.rep("\x22", 20))
  local value = 50000
  local cache = validation.precomputed_tx_data(tx)

  for i = 0, N - 1 do
    local uncached = validation.signature_hash_segwit_v0(tx, i, script_code, value, consensus.SIGHASH.ALL)
    local cached = validation.signature_hash_segwit_v0(tx, i, script_code, value, consensus.SIGHASH.ALL, cache)
    assert(#uncached == 32, "uncached sighash is not 32 bytes")
    assert(uncached == cached,
      string.format("consensus split at input %d: cached sighash differs from uncached", i))
  end
end)

test("cached BIP143 SIGHASH_NONE / SINGLE / ANYONECANPAY match uncached", function()
  assert(type(validation.precomputed_tx_data) == "function",
    "validation.precomputed_tx_data missing")
  local N = 8
  local tx = make_tx(N, N)
  local script_code = script.make_p2pkh_script(string.rep("\x22", 20))
  local cache = validation.precomputed_tx_data(tx)
  local types_ht = {
    consensus.SIGHASH.NONE,
    consensus.SIGHASH.SINGLE,
    bit.bor(consensus.SIGHASH.ALL, consensus.SIGHASH.ANYONECANPAY),
    bit.bor(consensus.SIGHASH.NONE, consensus.SIGHASH.ANYONECANPAY),
    bit.bor(consensus.SIGHASH.SINGLE, consensus.SIGHASH.ANYONECANPAY),
  }
  for _, ht in ipairs(types_ht) do
    for i = 0, N - 1 do
      local a = validation.signature_hash_segwit_v0(tx, i, script_code, 12345, ht)
      local b = validation.signature_hash_segwit_v0(tx, i, script_code, 12345, ht, cache)
      assert(a == b, string.format("hash_type=0x%02x input=%d cached != uncached", ht, i))
    end
  end
end)

test("32-input SIGHASH_ALL midstates are O(1) with the cache, O(N) without", function()
  assert(type(validation.precomputed_tx_data) == "function",
    "validation.precomputed_tx_data missing")
  local N = 32
  local tx = make_tx(N, N)
  local script_code = script.make_p2pkh_script(string.rep("\x22", 20))
  local value = 50000

  local restore, counts = wrap_hash_counters()
  for i = 0, N - 1 do
    validation.signature_hash_segwit_v0(tx, i, script_code, value, consensus.SIGHASH.ALL)
  end
  local unc_h, unc_s = counts()
  restore()

  restore, counts = wrap_hash_counters()
  local cache = validation.precomputed_tx_data(tx)
  for i = 0, N - 1 do
    validation.signature_hash_segwit_v0(tx, i, script_code, value, consensus.SIGHASH.ALL, cache)
  end
  local c_h, c_s = counts()
  restore()

  -- Uncached: each input double-hashes prevouts + sequences + outputs + preimage.
  -- That is 4 hash256 per input = 4N. (sha256 is not used on the uncached path.)
  assert(unc_h >= 4 * N,
    string.format("uncached hash256 count %d < 4N=%d — counter is not on the sighash path",
      unc_h, 4 * N))

  -- Cached: 3 shared midstates (single SHA256 + second SHA256 each, or one
  -- hash256 each) plus N preimage hash256. Bound the TOTAL digest calls
  -- (hash256 + sha256) to 3 midstates * 2 + N preimages + a small slack,
  -- which is O(1)+N, not 4N.
  local cached_digests = c_h + c_s
  local budget = 2 * 3 + N + 4  -- 6 midstate halves + N preimages + slack
  assert(cached_digests <= budget,
    string.format("cached digest count hash256=%d sha256=%d (total %d) exceeds O(1)+N budget %d; midstates are still recomputed",
      c_h, c_s, cached_digests, budget))
  assert(cached_digests < unc_h,
    string.format("cache did not reduce hashing: cached %d vs uncached hash256 %d",
      cached_digests, unc_h))
  print(string.format("\n    uncached hash256=%d sha256=%d  cached hash256=%d sha256=%d  (N=%d)",
    unc_h, unc_s, c_h, c_s, N))
end)

test("cached BIP341 sighash matches uncached and reuses singles", function()
  assert(type(validation.precomputed_tx_data) == "function",
    "validation.precomputed_tx_data missing")
  local N = 16
  local tx = make_tx(N, N)
  local spent = {}
  for i = 1, N do
    spent[i] = { value = 50000 + i, script_pubkey = script.make_p2tr_script
      and script.make_p2tr_script(string.rep("\x33", 32))
      or (string.char(0x51, 0x20) .. string.rep("\x33", 32)) }
  end
  local cache = validation.precomputed_tx_data(tx, spent)

  for i = 0, N - 1 do
    local uncached, uerr = validation.signature_hash_taproot(tx, i, 0x00, spent, 0, nil)
    assert(uncached, "uncached taproot sighash failed: " .. tostring(uerr))
    local cached, cerr = validation.signature_hash_taproot(tx, i, 0x00, spent, 0, nil, nil, nil, cache)
    assert(cached, "cached taproot sighash failed: " .. tostring(cerr))
    assert(uncached == cached,
      string.format("BIP341 consensus split at input %d", i))
  end

  local restore, counts = wrap_hash_counters()
  local cache2 = validation.precomputed_tx_data(tx, spent)
  for i = 0, N - 1 do
    validation.signature_hash_taproot(tx, i, 0x00, spent, 0, nil, nil, nil, cache2)
  end
  local c_h, c_s = counts()
  restore()

  -- Uncached BIP341 (SIGHASH_DEFAULT) does 5 single-SHA256 midstates per input
  -- (prevouts, amounts, scripts, sequences, outputs) plus the tagged hash.
  -- Cached must not redo those 5 per input: sha256 count should be well under 5N.
  assert(c_s < 5 * N,
    string.format("cached BIP341 sha256 count %d is not O(1) in N=%d (5N=%d)", c_s, N, 5 * N))
  print(string.format("\n    BIP341 cached hash256=%d sha256=%d (N=%d)", c_h, c_s, N))
end)

test("wall-clock: cached 64-input BIP143 walk beats the uncached 4N hash", function()
  assert(type(validation.precomputed_tx_data) == "function",
    "validation.precomputed_tx_data missing")
  local socket_ok, socket = pcall(require, "socket")
  local now = (socket_ok and socket.gettime) or function() return os.clock() end
  local N = 64
  local rounds = 8
  local tx = make_tx(N, N)
  local script_code = script.make_p2pkh_script(string.rep("\x22", 20))
  local value = 50000

  -- Warm the JIT on both paths.
  local cache_warm = validation.precomputed_tx_data(tx)
  for i = 0, 3 do
    validation.signature_hash_segwit_v0(tx, i, script_code, value, consensus.SIGHASH.ALL)
    validation.signature_hash_segwit_v0(tx, i, script_code, value, consensus.SIGHASH.ALL, cache_warm)
  end

  local t0 = now()
  for _ = 1, rounds do
    for i = 0, N - 1 do
      validation.signature_hash_segwit_v0(tx, i, script_code, value, consensus.SIGHASH.ALL)
    end
  end
  local unc_s = now() - t0
  local unc_rate = (rounds * N) / unc_s

  local t1 = now()
  for _ = 1, rounds do
    local cache = validation.precomputed_tx_data(tx)
    for i = 0, N - 1 do
      validation.signature_hash_segwit_v0(tx, i, script_code, value, consensus.SIGHASH.ALL, cache)
    end
  end
  local c_s = now() - t1
  local c_rate = (rounds * N) / c_s

  print(string.format("\n    uncached %.1f sighash/s (%.3fs)  cached %.1f sighash/s (%.3fs)  speedup %.2fx  N=%d rounds=%d",
    unc_rate, unc_s, c_rate, c_s, c_rate / unc_rate, N, rounds))

  -- The cache must actually win. A no-op cache that still rehashes would
  -- land at ~1.0x; the 32-input midstate saving is large enough that 1.5x
  -- is a conservative floor on this box even under load.
  assert(c_rate > unc_rate * 1.5,
    string.format("cached path is not faster: %.1f vs %.1f sighash/s (%.2fx, want >1.5x)",
      c_rate, unc_rate, c_rate / unc_rate))
end)

print(string.format("\n%d passed / %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
