#!/usr/bin/env luajit
-- Control for QUEUES.md lunarblock item 2 (validator throughput).
--
-- At 900k, connect_block's serial cost is the Lua interpreter around
-- script verification — not ECDSA. The dominant spend is P2WPKH, which
-- Core (and lunarblock) execute as the 25-byte synthetic P2PKH template
--   OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
-- via EvalScript / execute_script. That path:
--   * parse_script-allocates a 5-op table on every input
--   * creates ~8 nested closures (pop/push/is_executing/...) per call
--   * HASH160s the pubkey via two Lua digest calls (sha256 then ripemd160),
--     each allocating an FFI output buffer (and, for RIPEMD-160, a full
--     EVP_MD_CTX create/init/update/final/free)
--
-- Bitcoin Core's EvalScript is C++; the equivalent win here is:
--   1. A P2PKH-template fast path that does HASH160 + CHECKSIG without
--      the generic interpreter (same accept/reject as execute_script).
--   2. HASH160 as one C call (SHA-NI SHA-256 + RIPEMD-160) with reused
--      output buffers, so the commitment check is not two Lua hashes.
--
-- This control:
--   1. Requires the fast path (script.p2pkh_fastpath_hits) and the
--      oneshot HASH160 (crypto.hash160 must not call crypto.sha256).
--   2. Asserts fast and slow paths are byte-identical on valid P2WPKH,
--      HASH160 mismatch, SIG_DER, extra stack items, and STACK_SIZE.
--   3. Asserts the dummy-checker interpreter walk is actually faster
--      (the serial Lua cost the 0.33 blk/s number is made of).
--
-- Run: luajit test_script_verify_hotpath.lua
-- Expected: PASS (after the hot path lands). Before: FAIL.

package.path = "src/?.lua;lunarblock/?.lua;" .. package.path

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

print("=== script-verify hot path control ===\n")
print("sha256_hw=" .. tostring(crypto.sha256_hw_info()))

test("p2pkh template fast path is exported", function()
  assert(script.p2pkh_fastpath_hits ~= nil,
    "script.p2pkh_fastpath_hits missing — P2WPKH still goes through generic execute_script")
  assert(script.use_p2pkh_fastpath ~= false,
    "script.use_p2pkh_fastpath is disabled")
end)

test("hash160 is a oneshot C digest, not sha256+ripemd160", function()
  assert(type(crypto.hash160_oneshot_available) == "function",
    "crypto.hash160_oneshot_available missing — HASH160 is still two Lua digest calls")
  assert(crypto.hash160_oneshot_available(),
    "hash160 oneshot not wired (rebuild lib/sha256_accel.so)")

  local orig_sha, orig_ripe = crypto.sha256, crypto.ripemd160
  local n_sha, n_ripe = 0, 0
  crypto.sha256 = function(...)
    n_sha = n_sha + 1
    return orig_sha(...)
  end
  crypto.ripemd160 = function(...)
    n_ripe = n_ripe + 1
    return orig_ripe(...)
  end
  local pk = string.rep("\x02", 33)
  local h = crypto.hash160(pk)
  crypto.sha256, crypto.ripemd160 = orig_sha, orig_ripe
  assert(#h == 20, "hash160 did not return 20 bytes")
  assert(n_sha == 0 and n_ripe == 0,
    string.format("hash160 still calls sha256=%d ripemd160=%d (want 0,0 oneshot)", n_sha, n_ripe))
end)

test("hash160 oneshot matches the Lua sha256+ripemd160 composition", function()
  local samples = {
    "",
    "hello",
    string.rep("\x02", 33),
    string.rep("\x04", 65),
    string.rep("x", 520),
  }
  for _, s in ipairs(samples) do
    local oneshot = crypto.hash160(s)
    local composed = crypto.ripemd160(crypto.sha256(s))
    assert(oneshot == composed,
      string.format("hash160 oneshot != sha256+ripemd160 for len=%d", #s))
  end
  -- Compressed pubkey of privkey=1 (crypto_spec.lua vector).
  local pk1 = ("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    :gsub("..", function(cc) return string.char(tonumber(cc, 16)) end)
  local expected = ("751e76e8199196d454941c45d1b3a323f1433bd6")
    :gsub("..", function(cc) return string.char(tonumber(cc, 16)) end)
  assert(crypto.hash160(pk1) == expected, "hash160 oneshot disagrees with known HASH160")
end)

-- Shared P2WPKH fixture.
local priv = crypto.sha256("hotpath-control-key")
local pub = crypto.pubkey_from_privkey(priv, true)
local pkh = crypto.hash160(pub)
local spk = script.make_p2wpkh_script(pkh)
local synthetic = script.make_p2pkh_script(pkh)
assert(#synthetic == 25)

local tx = types.transaction(2, {}, {}, 0)
tx.segwit = true
tx.inputs[1] = types.txin(types.outpoint(types.hash256(string.rep("\xab", 32)), 0), "", 0xFFFFFFFE)
tx.inputs[1].witness = {}
tx.outputs[1] = types.txout(50000, script.make_p2wpkh_script(string.rep("\x11", 20)))
local value = 100000
local cache = validation.precomputed_tx_data(tx)
local flags = {
  verify_p2sh = true,
  verify_witness = true,
  verify_dersig = true,
  verify_nulldummy = true,
  verify_strictenc = true,
  verify_low_s = true,
  is_witness_v0 = true,
  is_segwit = true,
}
local checker_sign = validation.make_sig_checker(tx, 0, value, spk, flags, nil, cache)
checker_sign.set_segwit(true, pkh, nil)
local sh = validation.signature_hash_segwit_v0(tx, 0, synthetic, value, consensus.SIGHASH.ALL, cache)
local der = crypto.ecdsa_sign(priv, sh)
local sig = der .. string.char(consensus.SIGHASH.ALL)
tx.inputs[1].witness = {sig, pub}

local function dummy_checker()
  return {
    check_sig = function() return true end,
    set_codesep = function() end,
    set_segwit = function() end,
    get_witness = function() return {sig, pub} end,
  }
end

local function run_template(fast, stack)
  local saved = script.use_p2pkh_fastpath
  script.use_p2pkh_fastpath = fast
  local hits0 = script.p2pkh_fastpath_hits or 0
  local st = {}
  for i, v in ipairs(stack) do st[i] = v end
  local ok, a, b = pcall(script.execute_script, synthetic, st, flags, dummy_checker())
  script.use_p2pkh_fastpath = saved
  local hits = (script.p2pkh_fastpath_hits or 0) - hits0
  if not ok then
    return "throw", tostring(a), hits
  end
  if a == nil then
    return "err", tostring(b), hits
  end
  return "ok", a, hits
end

test("make_p2pkh_script is the 25-byte Core template", function()
  local s = script.make_p2pkh_script(string.rep("\x42", 20))
  assert(#s == 25, "P2PKH script is not 25 bytes")
  assert(s:byte(1) == 0x76 and s:byte(2) == 0xa9 and s:byte(3) == 0x14
      and s:byte(24) == 0x88 and s:byte(25) == 0xac,
    "P2PKH template bytes are not OP_DUP OP_HASH160 OP_PUSH20 OP_EQUALVERIFY OP_CHECKSIG")
  assert(s:sub(4, 23) == string.rep("\x42", 20))
end)

test("valid P2PKH template: fast path taken and stack matches slow path", function()
  local kind_s, slow, hits_s = run_template(false, {sig, pub})
  local kind_f, fast, hits_f = run_template(true, {sig, pub})
  assert(kind_s == "ok", "slow path rejected a valid P2PKH: " .. tostring(slow))
  assert(kind_f == "ok", "fast path rejected a valid P2PKH: " .. tostring(fast))
  assert(hits_s == 0, "slow path (use_p2pkh_fastpath=false) still incremented the hit counter")
  assert(hits_f >= 1, "fast path did not increment p2pkh_fastpath_hits")
  assert(#slow == 1 and #fast == 1, "result stack size mismatch")
  assert(slow[1] == fast[1], "fast/slow CHECKSIG result differs")
  assert(script.cast_to_bool(fast[1]), "valid P2PKH did not leave true on the stack")
end)

test("HASH160 mismatch: both paths throw OP_EQUALVERIFY", function()
  local bad_pub = string.rep("\x02", 33)
  local kind_s, err_s = run_template(false, {sig, bad_pub})
  local kind_f, err_f = run_template(true, {sig, bad_pub})
  assert(kind_s == "throw" and kind_f == "throw",
    string.format("EQUALVERIFY should throw, got slow=%s fast=%s", kind_s, kind_f))
  assert(tostring(err_s):find("OP_EQUALVERIFY", 1, true),
    "slow path error is not OP_EQUALVERIFY: " .. tostring(err_s))
  assert(tostring(err_f):find("OP_EQUALVERIFY", 1, true),
    "fast path error is not OP_EQUALVERIFY: " .. tostring(err_f))
end)

test("SIG_DER: both paths return the encoding error", function()
  -- Non-empty, non-DER sig. verify_dersig is set.
  local bad_sig = string.rep("\xff", 8)
  local kind_s, err_s = run_template(false, {bad_sig, pub})
  local kind_f, err_f = run_template(true, {bad_sig, pub})
  assert(kind_s == "err" and kind_f == "err",
    string.format("SIG_DER should return nil,err; got slow=%s fast=%s", kind_s, kind_f))
  assert(tostring(err_s):find("SIG_DER", 1, true), "slow path: " .. tostring(err_s))
  assert(tostring(err_f):find("SIG_DER", 1, true), "fast path: " .. tostring(err_f))
end)

test("extra stack items are preserved (native P2PKH CLEANSTACK is the caller's job)", function()
  local extra = "\x01"
  local kind_s, slow = run_template(false, {extra, sig, pub})
  local kind_f, fast = run_template(true, {extra, sig, pub})
  assert(kind_s == "ok" and kind_f == "ok")
  assert(#slow == 2 and #fast == 2, "extra item was dropped")
  assert(slow[1] == extra and fast[1] == extra)
end)

test("STACK_SIZE: DUP of a 1000-item stack fails on both paths", function()
  local big = {}
  for i = 1, 999 do big[i] = "" end
  big[1000] = pub
  -- DUP would make 1001 > MAX_STACK_SIZE=1000.
  local kind_s, err_s = run_template(false, big)
  local kind_f, err_f = run_template(true, big)
  -- slow path returns nil, "STACK_SIZE" (not a throw)
  assert(kind_s == "err" or (kind_s == "throw" and tostring(err_s):find("STACK_SIZE", 1, true)),
    "slow path did not hit STACK_SIZE: " .. kind_s .. " " .. tostring(err_s))
  assert(kind_f == "err" or (kind_f == "throw" and tostring(err_f):find("STACK_SIZE", 1, true)),
    "fast path missed the DUP STACK_SIZE check: " .. kind_f .. " " .. tostring(err_f))
  if kind_s == "err" then
    assert(tostring(err_s) == "STACK_SIZE", "slow err " .. tostring(err_s))
  end
  if kind_f == "err" then
    assert(tostring(err_f) == "STACK_SIZE", "fast err " .. tostring(err_f))
  end
end)

test("full P2WPKH verify_script still accepts the signed spend", function()
  local checker = validation.make_sig_checker(tx, 0, value, spk, flags, nil, cache)
  local ok, err = script.verify_script("", spk, flags, checker)
  assert(ok, "P2WPKH verify_script failed: " .. tostring(err))
end)

test("wall-clock: P2PKH-template walk is faster with the fast path", function()
  local rounds = 8000
  local chk = dummy_checker()
  local function bench(fast)
    script.use_p2pkh_fastpath = fast
    -- Warm
    for _ = 1, 100 do
      script.execute_script(synthetic, {sig, pub}, flags, chk)
    end
    local t0 = now()
    for _ = 1, rounds do
      script.execute_script(synthetic, {sig, pub}, flags, chk)
    end
    return now() - t0
  end

  local slow_s = bench(false)
  local fast_s = bench(true)
  script.use_p2pkh_fastpath = true
  local slow_rate = rounds / slow_s
  local fast_rate = rounds / fast_s

  print(string.format("\n    slow %.0f exec/s (%.3fs)  fast %.0f exec/s (%.3fs)  speedup %.2fx  rounds=%d",
    slow_rate, slow_s, fast_rate, fast_s, fast_rate / slow_rate, rounds))

  -- Dummy checker: no ECDSA. The generic interpreter is the whole cost.
  -- A no-op flag that still parses lands at ~1.0x. 3x is a conservative
  -- floor once the template walk skips parse_script + nested closures.
  assert(fast_rate > slow_rate * 3,
    string.format("fast path is not faster: %.0f vs %.0f exec/s (%.2fx, want >3x)",
      fast_rate, slow_rate, fast_rate / slow_rate))
end)

print(string.format("\n%d passed / %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
