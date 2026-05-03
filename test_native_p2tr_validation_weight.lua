#!/usr/bin/env luajit
-- Regression test: native P2TR script-path BIP-342 validation-weight budget.
--
-- Pre-fix, utxo.lua:2173-2186 native P2TR script-path called the 3-arg
-- form of script.verify_tapscript which never seeded
-- validation_weight_init / validation_weight_left, so the per-sigop
-- deduction in OP_CHECKSIG / CHECKSIGVERIFY / CHECKSIGADD was a silent
-- no-op for the entire native P2TR script-path.
--
-- This test directly drives script.verify_tapscript with the new 4-arg
-- form, asserting that:
--   1) budget unseeded (3-arg form) → no deduction happens (legacy
--      behavior preserved for callers that don't pass the budget).
--   2) budget seeded → CHECKSIG decrements; budget-exhausted aborts.
--   3) An adversarial 4-CHECKSIG tapscript with budget = 50 + 50*3 = 200
--      passes the first 3 sigops then aborts on the 4th.
--
-- Run: luajit test_native_p2tr_validation_weight.lua

package.path = "lunarblock/?.lua;src/?.lua;" .. package.path

local script = require("lunarblock.script")

local pass = 0
local fail = 0

local function check(name, cond, detail)
  if cond then
    print("PASS: " .. name)
    pass = pass + 1
  else
    print("FAIL: " .. name .. (detail and (" — " .. tostring(detail)) or ""))
    fail = fail + 1
  end
end

local PK32 = string.rep("\x02", 32)
local SIG64 = string.rep("\x42", 64)

-- Build a tapscript with N successive (sig, pubkey, OP_CHECKSIG) groups.
-- After N CHECKSIGs the stack has N booleans; we need exactly 1 truthy
-- on top to satisfy CLEANSTACK + EVAL_FALSE inside execute_witness_script,
-- so we end with N-1 OP_DROPs to leave just the last result.
local function build_n_checksigs(n)
  local s = ""
  for i = 1, n do
    s = s .. string.char(#SIG64) .. SIG64
    s = s .. string.char(#PK32) .. PK32
    s = s .. "\xac"  -- OP_CHECKSIG
  end
  for i = 1, n - 1 do
    s = s .. "\x75"  -- OP_DROP
  end
  return s
end

-- 1) 3-arg form (legacy): budget NOT seeded, deduction is a silent no-op.
do
  local checker = {check_sig = function() return true end}
  local stack = {}  -- args already in script via push opcodes
  -- Build a witness stack of just 1 trivial item so verify_tapscript runs.
  local s = build_n_checksigs(2)
  -- The 3-arg form (no validation_weight_left) means validation_weight_init
  -- is not set, so per-sigop deduction is a no-op. The script should run
  -- to completion regardless of how small the would-be budget would be.
  local result, err = script.verify_tapscript(s, {}, checker)
  check("3-arg form: no budget gate enforcement (legacy callers preserved)",
        result == true, tostring(err))
end

-- 2) 4-arg form: budget seeded. budget=50 lets exactly one CHECKSIG pass.
do
  local checker = {check_sig = function() return true end}
  local s = build_n_checksigs(1)  -- one CHECKSIG, no DROP needed
  -- Budget = 50 means exactly one (non-empty sig) CHECKSIG gets through:
  -- 50 - 50 = 0, still >= 0 → OK.
  local result, err = script.verify_tapscript(s, {}, checker, 50)
  check("4-arg form, budget=50, 1 CHECKSIG: passes (50-50=0)",
        result == true, tostring(err))
end

-- 3) 4-arg form: budget=49 fails on the very first CHECKSIG (49-50<0).
do
  local checker = {check_sig = function() return true end}
  local s = build_n_checksigs(1)
  local result, err = script.verify_tapscript(s, {}, checker, 49)
  check("4-arg form, budget=49, 1 CHECKSIG: aborts TAPSCRIPT_VALIDATION_WEIGHT",
        result == nil and err == "TAPSCRIPT_VALIDATION_WEIGHT", tostring(err))
end

-- 4) THE ADVERSARIAL CASE: 4-CHECKSIG tapscript with budget = 150.
--    150 / 50 = 3 sigops fit; the 4th aborts.
do
  local checker = {check_sig = function() return true end}
  local s = build_n_checksigs(4)
  local result, err = script.verify_tapscript(s, {}, checker, 150)
  check("budget=150 (3 sigops fit) but tapscript has 4 CHECKSIGs: REJECTS",
        result == nil and err == "TAPSCRIPT_VALIDATION_WEIGHT", tostring(err))
end

-- 5) Same 4-CHECKSIG tapscript with budget = 200 → passes (4 * 50 = 200).
do
  local checker = {check_sig = function() return true end}
  local s = build_n_checksigs(4)
  local result, err = script.verify_tapscript(s, {}, checker, 200)
  check("budget=200 (4 sigops fit exactly): passes",
        result == true, tostring(err))
end

-- 6) Same 4-CHECKSIG tapscript with budget = 199 → fails on the 4th.
do
  local checker = {check_sig = function() return true end}
  local s = build_n_checksigs(4)
  local result, err = script.verify_tapscript(s, {}, checker, 199)
  check("budget=199 (one short of 4 sigops): REJECTS",
        result == nil and err == "TAPSCRIPT_VALIDATION_WEIGHT", tostring(err))
end

-- 7) Empty signatures consume no budget — N=4 with empty sigs and budget=0
--    should still pass (and return false-on-stack but that surfaces as
--    EVAL_FALSE from cleanstack, NOT TAPSCRIPT_VALIDATION_WEIGHT).
do
  local checker = {check_sig = function() return false end}
  -- One CHECKSIG with empty sig: pushes false; CLEANSTACK passes
  -- (1 elem) but EVAL_FALSE because stack[1] is empty.
  local s = "\x00" .. string.char(#PK32) .. PK32 .. "\xac"
  local result, err = script.verify_tapscript(s, {}, checker, 0)
  check("budget=0 with empty sig CHECKSIG: gate not tripped (EVAL_FALSE only)",
        result == nil and err == "EVAL_FALSE", tostring(err))
end

print(string.format("\n%d passed, %d failed", pass, fail))
if fail > 0 then
  os.exit(1)
end
