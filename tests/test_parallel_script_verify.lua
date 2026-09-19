#!/usr/bin/env luajit
-- Parallel script verification — Core CCheckQueue shape for LuaJIT.
--
-- LuaJIT's lua_State is not thread-safe. The real (not fake) way to
-- parallelise VerifyScript is one lua_State per worker thread, a bounded
-- job queue of per-input checks, and a result that does not depend on how
-- the work was split. The existing ECDSA-only C pool (pv_verify_signatures)
-- is not this: connect_block still runs the interpreter on one core and
-- measured 1.01 cores during bulk validation.
--
-- REQUIRED (QUEUES.md 2026-09-19):
--   (1) decision identity — accept/reject AND reject reason identical at
--       1 worker and at N
--   (2) failure propagation — one failing check rejects the whole batch
--       with the same reason as the serial path
--   (3) measured scaling — wall-clock at 1, 2, 4, 8 workers on a batch of
--       post-segwit P2WPKH inputs, reported as numbers
--   (4) bounded RSS — more workers must not mean unbounded buffers
--
-- Control: luajit tests/test_parallel_script_verify.lua
-- BEFORE: FAIL (no per-input script-check queue / no --par / no 1-vs-N API).
-- AFTER:  all PASS.

package.path = "src/?.lua;src/?/init.lua;" .. package.path

local ffi        = require("ffi")
local bit        = require("bit")
local crypto     = require("lunarblock.crypto")
local script     = require("lunarblock.script")
local validation = require("lunarblock.validation")
local types      = require("lunarblock.types")
local serialize  = require("lunarblock.serialize")
local consensus  = require("lunarblock.consensus")
local main       = require("lunarblock.main")

local PASS, FAIL = 0, 0

local function pass(name)
  io.write(string.format("  PASS  %s\n", name)); io.flush(); PASS = PASS + 1
end
local function fail(name, msg)
  io.write(string.format("  FAIL  %s -- %s\n", name, msg)); io.flush(); FAIL = FAIL + 1
end
local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end
local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a)
      .. ", expected " .. tostring(b), 2)
  end
end
local function expect_true(v, msg)
  if not v then error((msg or "expected true") .. ": got " .. tostring(v), 2) end
end
local function expect_false(v, msg)
  if v then error((msg or "expected false") .. ": got " .. tostring(v), 2) end
end

local function wall_now()
  local sok, socket = pcall(require, "socket")
  if sok then return socket.gettime() end
  local t = ffi.new("struct timespec")
  ffi.cdef[[int clock_gettime(int clk_id, struct timespec *tp);]]
  pcall(function()
    ffi.C.clock_gettime(1, t) -- CLOCK_MONOTONIC
  end)
  if t.tv_sec ~= 0 or t.tv_nsec ~= 0 then
    return tonumber(t.tv_sec) + tonumber(t.tv_nsec) / 1e9
  end
  return os.clock()
end

local function rss_kb()
  local f = io.open("/proc/self/status", "r")
  if not f then return nil end
  for line in f:lines() do
    local v = line:match("^VmRSS:%s+(%d+)")
    if v then f:close(); return tonumber(v) end
  end
  f:close()
  return nil
end

--------------------------------------------------------------------------------
-- Fixtures
--------------------------------------------------------------------------------

local FLAGS = {
  verify_p2sh = true,
  verify_witness = true,
  verify_dersig = true,
  verify_nulldummy = true,
  verify_taproot = true,
  verify_checklocktimeverify = true,
  verify_checksequenceverify = true,
}

local function make_p2wpkh_job(i, corrupt)
  local priv = crypto.sha256("par-script-key-" .. tostring(i))
  local pub = crypto.pubkey_from_privkey(priv, true)
  local pkh = crypto.hash160(pub)
  local spk = script.make_p2wpkh_script(pkh)
  local synthetic = script.make_p2pkh_script(pkh)
  local prev = types.hash256(crypto.sha256("par-script-prev-" .. tostring(i)))
  local tx = types.transaction(2, {}, {}, 0)
  tx.segwit = true
  tx.inputs[1] = types.txin(types.outpoint(prev, 0), "", 0xFFFFFFFE)
  tx.outputs[1] = types.txout(50000, script.make_p2wpkh_script(string.rep("\x11", 20)))
  local value = 100000
  local cache = validation.precomputed_tx_data(tx)
  local sh = validation.signature_hash_segwit_v0(
    tx, 0, synthetic, value, consensus.SIGHASH.ALL, cache)
  local der = crypto.ecdsa_sign(priv, sh)
  if corrupt then
    der = string.rep("\x00", #der)
  end
  local sig = der .. string.char(consensus.SIGHASH.ALL)
  tx.inputs[1].witness = {sig, pub}
  return {
    tx = tx,
    input_index = 0,
    amount = value,
    script_pubkey = spk,
    flags = FLAGS,
    taproot_active = true,
  }
end

local function make_p2pkh_job(i, corrupt)
  local priv = crypto.sha256("par-script-legacy-" .. tostring(i))
  local pub = crypto.pubkey_from_privkey(priv, true)
  local pkh = crypto.hash160(pub)
  local spk = script.make_p2pkh_script(pkh)
  local prev = types.hash256(crypto.sha256("par-script-legacy-prev-" .. tostring(i)))
  local tx = types.transaction(1, {}, {}, 0)
  tx.inputs[1] = types.txin(types.outpoint(prev, 0), "", 0xFFFFFFFF)
  tx.outputs[1] = types.txout(40000, spk)
  local value = 80000
  local hash_type = 0x01
  local sh = validation.signature_hash_legacy(tx, 0, spk, hash_type, "")
  local der = crypto.ecdsa_sign(priv, sh)
  if corrupt then
    der = string.rep("\x00", #der)
  end
  local sig = der .. string.char(hash_type)
  tx.inputs[1].script_sig = string.char(#sig) .. sig .. string.char(#pub) .. pub
  return {
    tx = tx,
    input_index = 0,
    amount = value,
    script_pubkey = spk,
    flags = FLAGS,
    taproot_active = true,
  }
end

--------------------------------------------------------------------------------
print("=== parallel script verification (CCheckQueue shape) ===\n")

test("verify_script_checks API exists (not ECDSA-only batch)", function()
  expect_true(type(validation.verify_script_checks) == "function",
    "validation.verify_script_checks missing — still ECDSA-only parallel_verify")
  expect_true(type(validation.set_script_check_workers) == "function",
    "validation.set_script_check_workers missing — cannot set 1 vs N")
  expect_true(type(validation.script_check_workers) == "function",
    "validation.script_check_workers missing")
  expect_true(type(validation.verify_input_script) == "function",
    "validation.verify_input_script missing — connect_block still inlines")
end)

test("--par is parsed like Core (0=auto, 1=serial, N=N-1 extra workers)", function()
  expect_true(type(main.parse_args) == "function", "main.parse_args missing")
  local a0 = main.parse_args({})
  expect_eq(a0.par, 0, "default --par is 0 (auto), matching Core DEFAULT_SCRIPTCHECK_THREADS")
  local a1 = main.parse_args({"--par", "1"})
  expect_eq(a1.par, 1, "--par 1")
  local a8 = main.parse_args({"--par=8"})
  expect_eq(a8.par, 8, "--par=8")
  local an = main.parse_args({"--par", "-1"})
  expect_eq(an.par, -1, "--par -1 (leave 1 core free)")
end)

test("set_script_check_workers(1) and (4) actually change the pool size", function()
  local ok1 = validation.set_script_check_workers(1)
  expect_true(ok1, "set_script_check_workers(1) failed")
  expect_eq(validation.script_check_workers(), 1,
    "pool at 1 worker")
  local ok4 = validation.set_script_check_workers(4)
  expect_true(ok4, "set_script_check_workers(4) failed")
  expect_eq(validation.script_check_workers(), 4,
    "pool at 4 workers")
end)

-- Identity corpus: mix of valid P2WPKH, valid P2PKH, one invalid P2WPKH.
local function identity_jobs()
  local jobs = {}
  for i = 1, 8 do jobs[#jobs + 1] = make_p2wpkh_job(i, false) end
  for i = 1, 4 do jobs[#jobs + 1] = make_p2pkh_job(i, false) end
  jobs[#jobs + 1] = make_p2wpkh_job(99, true) -- invalid, last
  return jobs
end

local function run_batch(nworkers, jobs)
  expect_true(validation.set_script_check_workers(nworkers),
    "set_script_check_workers(" .. nworkers .. ") failed")
  expect_eq(validation.script_check_workers(), nworkers,
    "worker count after set")
  return validation.verify_script_checks(jobs)
end

test("decision identity: 1 worker and 8 workers agree on a mixed batch (valid+invalid)", function()
  local jobs = identity_jobs()
  local ok1, err1 = run_batch(1, jobs)
  local ok8, err8 = run_batch(8, jobs)
  expect_false(ok1, "1-worker path must reject the batch (contains one bad P2WPKH)")
  expect_false(ok8, "8-worker path must reject the batch")
  expect_eq(tostring(err1), tostring(err8),
    "reject reason must not depend on how the work was split")
end)

test("decision identity: all-valid batch accepted at 1 and at 8", function()
  local jobs = {}
  for i = 1, 16 do jobs[i] = make_p2wpkh_job(1000 + i, false) end
  local ok1, err1 = run_batch(1, jobs)
  local ok8, err8 = run_batch(8, jobs)
  expect_true(ok1, "1-worker rejected a valid batch: " .. tostring(err1))
  expect_true(ok8, "8-worker rejected a valid batch: " .. tostring(err8))
end)

test("failure propagation: a bad check in the middle rejects the whole batch", function()
  local jobs = {}
  for i = 1, 24 do jobs[i] = make_p2wpkh_job(2000 + i, false) end
  jobs[7] = make_p2wpkh_job(2000 + 7, true)
  local ok_s, err_s = run_batch(1, jobs)
  local ok_p, err_p = run_batch(8, jobs)
  expect_false(ok_s, "serial/1-worker must reject")
  expect_false(ok_p, "8-worker must reject — a failing check in one worker must not be lost")
  expect_eq(tostring(err_s), tostring(err_p),
    "failure reason must match the 1-worker path")
  -- Reason names the failing input (1-based index 7).
  expect_true(tostring(err_p):find("7", 1, true) ~= nil,
    "reject reason should identify the failing input: " .. tostring(err_p))
end)

test("serial verify_input_script matches the 1-worker queue on a valid P2WPKH", function()
  local job = make_p2wpkh_job(42, false)
  local ok_d, err_d = validation.verify_input_script(
    job.tx, job.input_index, job.amount, job.script_pubkey, job.flags,
    { taproot_active = job.taproot_active })
  expect_true(ok_d, "direct verify_input_script rejected valid P2WPKH: " .. tostring(err_d))
  local ok_q, err_q = run_batch(1, {job})
  expect_true(ok_q, "1-worker queue rejected valid P2WPKH: " .. tostring(err_q))
end)

test("serial verify_input_script matches the 1-worker queue on an invalid P2WPKH", function()
  local job = make_p2wpkh_job(43, true)
  local ok_d, err_d = validation.verify_input_script(
    job.tx, job.input_index, job.amount, job.script_pubkey, job.flags,
    { taproot_active = job.taproot_active })
  expect_false(ok_d, "direct path must reject corrupt P2WPKH")
  local ok_q, err_q = run_batch(1, {job})
  expect_false(ok_q, "1-worker queue must reject corrupt P2WPKH")
end)

--------------------------------------------------------------------------------
-- (3) measured scaling
--------------------------------------------------------------------------------

local SCALE_N = 256
local scale_jobs = {}
for i = 1, SCALE_N do
  scale_jobs[i] = make_p2wpkh_job(3000 + i, false)
end

local function bench(nworkers, jobs, rounds)
  expect_true(validation.set_script_check_workers(nworkers))
  -- Warm JIT / lua_State on this pool.
  local wok, werr = validation.verify_script_checks(jobs)
  expect_true(wok, "warmup failed at " .. nworkers .. " workers: " .. tostring(werr))
  local t0 = wall_now()
  for _ = 1, rounds do
    local ok, err = validation.verify_script_checks(jobs)
    expect_true(ok, "bench failed at " .. nworkers .. " workers: " .. tostring(err))
  end
  local elapsed = wall_now() - t0
  local checks = #jobs * rounds
  local per_sec = checks / elapsed
  -- Treat a "block" as 2500 inputs (busy post-segwit).
  local blk_per_h = (per_sec / 2500) * 3600
  return elapsed, per_sec, blk_per_h
end

local times = {}
test("measured scaling at 1, 2, 4, 8 workers on " .. SCALE_N .. " P2WPKH inputs", function()
  local rounds = 2
  print("")
  print(string.format("  scaling: %d P2WPKH inputs × %d rounds (wall clock)", SCALE_N, rounds))
  for _, n in ipairs({1, 2, 4, 8}) do
    local elapsed, per_sec, blk_h = bench(n, scale_jobs, rounds)
    times[n] = { elapsed = elapsed, per_sec = per_sec, blk_h = blk_h }
    print(string.format(
      "    workers=%d  wall=%.3fs  checks/s=%.0f  equiv blk/h@2500in=%.0f",
      n, elapsed, per_sec, blk_h))
  end
  expect_true(times[1].elapsed > 0, "1-worker bench produced no time")
  -- 4 workers must beat 1 worker. 1.5x is a low bar on a 32-core box if the
  -- interpreter actually runs in parallel; the ECDSA-only fake would sit at ~1x.
  local speedup4 = times[1].elapsed / times[4].elapsed
  print(string.format("    speedup 4/1 = %.2fx   8/1 = %.2fx",
    speedup4, times[1].elapsed / times[8].elapsed))
  expect_true(speedup4 >= 1.5,
    string.format("4 workers not faster than 1 (%.2fx) — parallel script verify is a fake",
      speedup4))
end)

--------------------------------------------------------------------------------
-- (4) bounded RSS
--------------------------------------------------------------------------------

test("bounded RSS: 8 workers do not grow an unbounded per-worker buffer", function()
  collectgarbage("collect")
  validation.set_script_check_workers(1)
  collectgarbage("collect")
  local rss1 = rss_kb()
  validation.set_script_check_workers(8)
  collectgarbage("collect")
  local rss8 = rss_kb()
  expect_true(rss1 ~= nil and rss8 ~= nil, "/proc/self/status VmRSS unreadable")
  local extra = rss8 - rss1
  print(string.format("    VmRSS 1 worker=%d kB  8 workers=%d kB  extra=%d kB",
    rss1, rss8, extra))
  -- 8 lua_States loading the interpreter are a bounded cost (tens of MB
  -- each, not a copy of the job list per worker). Cap at 768 MB extra.
  expect_true(extra < 768 * 1024,
    string.format("8 workers added %d kB over 1 worker (unbounded?)", extra))

  -- Repeated batches must not leak the job list.
  local rss_a = rss_kb()
  for _ = 1, 8 do
    local ok, err = validation.verify_script_checks(scale_jobs)
    expect_true(ok, "RSS batch failed: " .. tostring(err))
  end
  collectgarbage("collect")
  local rss_b = rss_kb()
  local grew = rss_b - rss_a
  print(string.format("    VmRSS after 8 batches=%d kB  delta=%d kB", rss_b, grew))
  expect_true(grew < 64 * 1024,
    string.format("RSS grew %d kB over 8 batches (job buffers leaking?)", grew))
end)

test("empty batch is success at any worker count", function()
  expect_true(validation.set_script_check_workers(4))
  local ok, err = validation.verify_script_checks({})
  expect_true(ok, "empty batch failed: " .. tostring(err))
end)

--------------------------------------------------------------------------------
if validation.parallel_verify_shutdown then
  validation.parallel_verify_shutdown()
end

print("")
print(string.format("=== %d PASS / %d FAIL ===", PASS, FAIL))
if FAIL > 0 then os.exit(1) end
os.exit(0)
