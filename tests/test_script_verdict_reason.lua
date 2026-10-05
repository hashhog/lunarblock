#!/usr/bin/env luajit
-- A connect-block script failure must surface as Core's single block-level
-- BIP-22 reason "block-script-verify-flag-failed", on the serial AND the
-- parallel (CCheckQueue) path.
--
-- Core: validation.cpp ConnectBlock -> CheckInputScripts failure ->
-- state.Invalid(BLOCK_CONSENSUS, "block-script-verify-flag-failed (...)").
--
-- Regression (94e8a32, 2026-09-19, parallel script verification): the
-- per-input check moved into validation.verify_input_script, whose verdict
-- message carried a Lua source position from its own assert
-- (".../validation.lua:3092: SIG_DER").  connect_block wraps that verdict in a
-- second assert, so the reject string held TWO position markers; the BIP-22
-- mapper strips through the innermost one and was left with the bare
-- "sig_der", which no pattern names -> generic "rejected".  The nightly
-- differential guard's dersig-non-canonical-signature entry diverged from
-- Core every night from 2026-09-19.
--
-- Control: luajit tests/test_script_verdict_reason.lua
-- BEFORE (guard-fix parent): FAIL (verdict carries a .lua:N: marker; both
--   paths classify as "rejected").
-- AFTER: all PASS.

package.path = "src/?.lua;src/?/init.lua;" .. package.path

local crypto     = require("lunarblock.crypto")
local script     = require("lunarblock.script")
local validation = require("lunarblock.validation")
local types      = require("lunarblock.types")
local rpc        = require("lunarblock.rpc")

local PASS, FAIL = 0, 0
local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then
    io.write("  PASS  " .. name .. "\n"); PASS = PASS + 1
  else
    io.write("  FAIL  " .. name .. " -- " .. tostring(err) .. "\n"); FAIL = FAIL + 1
  end
end
local function expect_eq(a, b, msg)
  if a ~= b then
    error(string.format("%s: got %s, expected %s", msg, tostring(a), tostring(b)), 2)
  end
end

local FLAGS = {
  verify_p2sh = true,
  verify_witness = true,
  verify_dersig = true,
  verify_nulldummy = true,
  verify_taproot = true,
  verify_checklocktimeverify = true,
  verify_checksequenceverify = true,
}

-- P2PKH spend whose signature is all-zero bytes: not strict DER, so with
-- DERSIG (BIP-66) CHECKSIG fails with SCRIPT_ERR_SIG_DER — the same failure
-- the diff-test dersig-non-canonical-signature block carries.
local function non_der_p2pkh_job()
  local priv = crypto.sha256("verdict-reason-key")
  local pub = crypto.pubkey_from_privkey(priv, true)
  local spk = script.make_p2pkh_script(crypto.hash160(pub))
  local prev = types.hash256(crypto.sha256("verdict-reason-prev"))
  local tx = types.transaction(1, {}, {}, 0)
  tx.inputs[1] = types.txin(types.outpoint(prev, 0), "", 0xFFFFFFFF)
  tx.outputs[1] = types.txout(40000, spk)
  local sig = string.rep("\x00", 71) .. "\x01"
  tx.inputs[1].script_sig = string.char(#sig) .. sig .. string.char(#pub) .. pub
  return { tx = tx, input_index = 0, amount = 80000, script_pubkey = spk,
           flags = FLAGS, taproot_active = true }
end

-- connect_block raises the verdict through assert() (utxo.lua serial path:
-- "Script verification failed for input %d of tx %s: %s"; parallel path:
-- "Parallel script verification failed: %s"), which prepends utxo.lua's own
-- position.  Reproduce that by raising from a function here (same shape: one
-- outer marker) and hand the caught string to the real submitblock mapper.
local function raise_like_connect_block(fmt, ...)
  local args = { ... }
  local ok, e = pcall(function() assert(false, string.format(fmt, unpack(args))) end)
  assert(not ok)
  return e
end

print("=== connect-block script verdict -> BIP-22 reason ===\n")

local job = non_der_p2pkh_job()

test("verify_input_script verdict is the script error, not a source position", function()
  local ok, err, internal = validation.verify_input_script(
    job.tx, job.input_index, job.amount, job.script_pubkey, job.flags,
    { taproot_active = true })
  expect_eq(not ok, true, "non-DER signature must fail")
  expect_eq(internal, nil, "a script error is a verdict, not INTERNAL")
  expect_eq(tostring(err):find("%.lua:%d+:") == nil, true,
    "verdict carries a Lua source position (" .. tostring(err) .. ")")
  expect_eq(tostring(err):find("SIG_DER", 1, true) ~= nil, true,
    "verdict names SCRIPT_ERR_SIG_DER (" .. tostring(err) .. ")")
end)

test("serial connect path maps to block-script-verify-flag-failed", function()
  local ok, err = validation.verify_input_script(
    job.tx, job.input_index, job.amount, job.script_pubkey, job.flags,
    { taproot_active = true })
  expect_eq(not ok, true, "non-DER signature must fail")
  local raised = raise_like_connect_block(
    "Script verification failed for input %d of tx %s: %s", 2, string.rep("ab", 32), err)
  expect_eq(rpc.classify_block_rejection(raised), "block-script-verify-flag-failed",
    "serial reject reason for " .. raised)
end)

for _, n in ipairs({ 1, 4 }) do
  test("parallel connect path (" .. n .. " workers) maps to block-script-verify-flag-failed", function()
    expect_eq(validation.set_script_check_workers(n), true, "set_script_check_workers")
    local ok, err = validation.verify_script_checks({ non_der_p2pkh_job() })
    expect_eq(not ok, true, "non-DER signature must fail")
    local raised = raise_like_connect_block(
      "Parallel script verification failed: %s", err or "unknown error")
    expect_eq(rpc.classify_block_rejection(raised), "block-script-verify-flag-failed",
      "parallel reject reason for " .. raised)
  end)
end

print(string.format("\n%d passed, %d failed", PASS, FAIL))
os.exit(FAIL == 0 and 0 or 1)
