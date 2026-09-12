#!/usr/bin/env luajit
-- Control for QUEUES.md lunarblock item 2 (validator throughput).
--
-- After PrecomputedTransactionData and the P2PKH-template fast path, the
-- remaining serial Lua around each P2WPKH input is:
--   1. serialize.buffer_writer() for the BIP143 per-input preimage
--      (~12 closures + string.char fragments + concat per CHECKSIG).
--      Profile at HEAD 87ee013: signature_hash_segwit_v0 cached = 2.16 us,
--      of which buffer_writer is 1.68 us. crypto.hash256 of the 182-byte
--      preimage is 0.18 us.
--   2. connect_block constructs TWO sig checkers per native P2WPKH input
--      (a legacy collecting checker that is immediately discarded, then
--      the real segwit checker). Profile: 8.16 us → 5.76 us dummy/input
--      once the unused ctor is skipped.
--
-- Bitcoin Core writes the BIP143 preimage into a CHashWriter (C++ bytes,
-- no per-call closures) and CheckInputScripts builds one CScriptCheck
-- per input. The equivalent win here is:
--   1. A reused FFI buffer + hash256_ptr so the per-input preimage never
--      becomes a Lua string and never goes through buffer_writer.
--   2. validation.verify_native_p2wpkh: one checker, used by connect_block.
--
-- This control:
--   1. Requires crypto.hash256_ptr and validation.use_fast_bip143_preimage.
--   2. Asserts fast and slow BIP143 hashes are byte-identical (ALL/NONE/
--      SINGLE/ANYONECANPAY, 32-input, long scriptCode).
--   3. Requires verify_native_p2wpkh and that it constructs exactly one
--      checker (the unused-ctor is the 900k connect_block leak).
--   4. Asserts the dummy-checker 32-input walk is actually faster with
--      the FFI preimage (the serial Lua cost left in 0.33 blk/s).
--
-- Run: luajit test_bip143_preimage.lua
-- Expected: PASS (after the hot path lands). Before: FAIL.

package.path = "src/?.lua;lunarblock/?.lua;" .. package.path

local bit = require("bit")
local crypto = require("lunarblock.crypto")
local script = require("lunarblock.script")
local validation = require("lunarblock.validation")
local types = require("lunarblock.types")
local consensus = require("lunarblock.consensus")

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

local function now()
  local sok, socket = pcall(require, "socket")
  if sok then return socket.gettime() end
  return os.clock()
end

print("=== BIP143 preimage / native-P2WPKH connect hot path control ===\n")
print("sha256_hw=" .. tostring(crypto.sha256_hw_info()))

local function make_tx(n_in, n_out)
  local tx = types.transaction(2, {}, {}, 0)
  tx.segwit = true
  for i = 1, n_in do
    local h = crypto.hash256(string.rep(string.char(i % 256), 32))
    tx.inputs[i] = types.txin(types.outpoint(types.hash256(h), i - 1), "", 0xFFFFFFFE)
    tx.inputs[i].witness = {}
  end
  for i = 1, n_out do
    tx.outputs[i] = types.txout(1000 + i, script.make_p2wpkh_script(string.rep(string.char(i), 20)))
  end
  return tx
end

test("hash256_ptr is exported", function()
  assert(type(crypto.hash256_ptr) == "function",
    "crypto.hash256_ptr missing — BIP143 preimage still materialises a Lua string")
end)

test("use_fast_bip143_preimage kill switch is exported", function()
  assert(validation.use_fast_bip143_preimage ~= nil,
    "validation.use_fast_bip143_preimage missing — per-input preimage still uses buffer_writer")
  assert(validation.use_fast_bip143_preimage ~= false,
    "validation.use_fast_bip143_preimage is disabled")
end)

test("hash256_ptr matches hash256(ffi.string)", function()
  local ffi = require("ffi")
  local samples = {
    "",
    "hello",
    string.rep("\x00", 32),
    string.rep("x", 182),
    string.rep("y", 1024),
  }
  for _, s in ipairs(samples) do
    local buf = ffi.new("uint8_t[?]", math.max(#s, 1))
    if #s > 0 then ffi.copy(buf, s, #s) end
    local a = crypto.hash256(s)
    local b = crypto.hash256_ptr(buf, #s)
    assert(a == b, string.format("hash256_ptr != hash256 for len=%d", #s))
  end
end)

local function all_hash_types()
  return {
    consensus.SIGHASH.ALL,
    consensus.SIGHASH.NONE,
    consensus.SIGHASH.SINGLE,
    bit.bor(consensus.SIGHASH.ALL, consensus.SIGHASH.ANYONECANPAY),
    bit.bor(consensus.SIGHASH.NONE, consensus.SIGHASH.ANYONECANPAY),
    bit.bor(consensus.SIGHASH.SINGLE, consensus.SIGHASH.ANYONECANPAY),
  }
end

test("fast BIP143 matches slow (32-input, all hash types)", function()
  local tx = make_tx(32, 8)
  local cache = validation.precomputed_tx_data(tx)
  local script_code = script.make_p2pkh_script(string.rep("\x42", 20))
  local saved = validation.use_fast_bip143_preimage
  for _, ht in ipairs(all_hash_types()) do
    for idx = 0, 31 do
      local value = 50000 + idx
      validation.use_fast_bip143_preimage = false
      local slow = validation.signature_hash_segwit_v0(tx, idx, script_code, value, ht, cache)
      validation.use_fast_bip143_preimage = true
      local fast = validation.signature_hash_segwit_v0(tx, idx, script_code, value, ht, cache)
      assert(slow == fast,
        string.format("fast/slow BIP143 mismatch ht=0x%02x vin=%d", ht, idx))
    end
  end
  validation.use_fast_bip143_preimage = saved
end)

test("fast BIP143 matches slow for a long (P2WSH-sized) scriptCode", function()
  local tx = make_tx(2, 2)
  local cache = validation.precomputed_tx_data(tx)
  -- 520-byte push + CHECKSIG: well above the 25-byte P2PKH template, still
  -- under MAX_SCRIPT_SIZE. Compact-size of 522 is 3 bytes (0xfd + u16).
  local long_code = string.rep("\x00", 520) .. "\xac"
  local saved = validation.use_fast_bip143_preimage
  validation.use_fast_bip143_preimage = false
  local slow = validation.signature_hash_segwit_v0(tx, 0, long_code, 123456789, 1, cache)
  validation.use_fast_bip143_preimage = true
  local fast = validation.signature_hash_segwit_v0(tx, 0, long_code, 123456789, 1, cache)
  validation.use_fast_bip143_preimage = saved
  assert(slow == fast, "fast/slow BIP143 mismatch on long scriptCode")
end)

test("verify_native_p2wpkh is exported", function()
  assert(type(validation.verify_native_p2wpkh) == "function",
    "validation.verify_native_p2wpkh missing — connect_block still builds two checkers per P2WPKH")
  assert(type(validation.checker_ctor_count) == "number",
    "validation.checker_ctor_count missing — cannot prove the unused ctor is gone")
end)

-- Signed P2WPKH fixture for the native-verify helper.
local priv = crypto.sha256("bip143-preimage-control-key")
local pub = crypto.pubkey_from_privkey(priv, true)
local pkh = crypto.hash160(pub)
local spk = script.make_p2wpkh_script(pkh)
local synthetic = script.make_p2pkh_script(pkh)
local tx1 = types.transaction(2, {}, {}, 0)
tx1.segwit = true
tx1.inputs[1] = types.txin(types.outpoint(types.hash256(string.rep("\xab", 32)), 0), "", 0xFFFFFFFE)
tx1.inputs[1].witness = {}
tx1.outputs[1] = types.txout(50000, script.make_p2wpkh_script(string.rep("\x11", 20)))
local value = 100000
local cache1 = validation.precomputed_tx_data(tx1)
local flags = {
  verify_p2sh = true,
  verify_witness = true,
  verify_dersig = true,
  verify_nulldummy = true,
  is_segwit = true,
  is_witness_v0 = true,
}
local sh = validation.signature_hash_segwit_v0(tx1, 0, synthetic, value, consensus.SIGHASH.ALL, cache1)
local der = crypto.ecdsa_sign(priv, sh)
local sig = der .. string.char(consensus.SIGHASH.ALL)
tx1.inputs[1].witness = {sig, pub}

test("verify_native_p2wpkh accepts a signed P2WPKH and constructs one checker", function()
  local n0 = validation.checker_ctor_count
  local ok, err = validation.verify_native_p2wpkh(tx1, 0, value, spk, flags, nil, cache1)
  assert(ok, "verify_native_p2wpkh rejected a valid spend: " .. tostring(err))
  local ctors = validation.checker_ctor_count - n0
  assert(ctors == 1,
    string.format("verify_native_p2wpkh constructed %d checkers (want 1)", ctors))
end)

test("verify_native_p2wpkh matches execute_witness_script on the same spend", function()
  local checker = validation.make_sig_checker(tx1, 0, value, spk, flags, nil, cache1)
  local slow_ok, slow_err = script.execute_witness_script(synthetic, {sig, pub}, flags, checker)
  local fast_ok, fast_err = validation.verify_native_p2wpkh(tx1, 0, value, spk, flags, nil, cache1)
  assert(slow_ok, "slow execute_witness_script failed: " .. tostring(slow_err))
  assert(fast_ok, "verify_native_p2wpkh failed: " .. tostring(fast_err))
end)

test("WITNESS_PROGRAM_MISMATCH: witness stack != 2", function()
  local saved = tx1.inputs[1].witness
  tx1.inputs[1].witness = {sig}
  local ok, err = validation.verify_native_p2wpkh(tx1, 0, value, spk, flags, nil, cache1)
  tx1.inputs[1].witness = saved
  assert(not ok, "1-item witness should fail")
  assert(tostring(err):find("WITNESS_PROGRAM_MISMATCH", 1, true),
    "error is not WITNESS_PROGRAM_MISMATCH: " .. tostring(err))
end)

test("wall-clock: FFI BIP143 preimage beats buffer_writer", function()
  local tx = make_tx(32, 8)
  local cache = validation.precomputed_tx_data(tx)
  local script_code = script.make_p2pkh_script(string.rep("\x42", 20))
  local rounds = 200
  local function bench(fast)
    validation.use_fast_bip143_preimage = fast
    -- Warm
    for idx = 0, 31 do
      validation.signature_hash_segwit_v0(tx, idx, script_code, 50000, 1, cache)
    end
    local t0 = now()
    for _ = 1, rounds do
      for idx = 0, 31 do
        validation.signature_hash_segwit_v0(tx, idx, script_code, 50000 + idx, 1, cache)
      end
    end
    return now() - t0
  end

  local n = 32 * rounds
  local slow_s = bench(false)
  local fast_s = bench(true)
  validation.use_fast_bip143_preimage = true
  local slow_rate = n / slow_s
  local fast_rate = n / fast_s

  print(string.format(
    "\n    slow %.0f sighash/s (%.3fs)  fast %.0f sighash/s (%.3fs)  speedup %.2fx  N=32 rounds=%d",
    slow_rate, slow_s, fast_rate, fast_s, fast_rate / slow_rate, rounds))

  -- Dummy numbers: buffer_writer is ~80% of the cached sighash. A no-op
  -- flag that still concatenates lands at ~1.0x. 2x is a conservative
  -- floor once the preimage is written into a reused FFI buffer.
  assert(fast_rate > slow_rate * 2,
    string.format("fast BIP143 is not faster: %.0f vs %.0f sighash/s (%.2fx, want >2x)",
      fast_rate, slow_rate, fast_rate / slow_rate))
end)

print(string.format("\n%d passed / %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
