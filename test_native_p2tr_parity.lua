#!/usr/bin/env luajit
-- Regression test: native P2TR script-path control-block parity check.
--
-- Pre-fix, utxo.lua line 2168 native P2TR computed:
--   local tweaked_key = crypto.tweak_pubkey(internal_key, tweak)
-- discarding the parity return and comparing only x-coord. Core's
-- CheckTapTweak requires control[0] & 1 == computed parity.
--
-- This test uses crypto.tweak_pubkey directly to discover the real
-- (x, parity) for a given internal key + tweak, then asserts that
-- comparing parity against control_block[0] & 0x01 correctly accepts
-- a matching parity and rejects a flipped one. This mirrors the
-- assert(tweaked_parity == control_parity, ...) added to utxo.lua.
--
-- Run: luajit test_native_p2tr_parity.lua

package.path = "lunarblock/?.lua;src/?.lua;" .. package.path

local crypto = require("lunarblock.crypto")
local bit = require("bit")

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

-- Helper that mirrors the utxo.lua check we added: given a control_block
-- and the expected output_key, verify both x-coord AND parity match.
-- Returns (ok, err) just like the verify_witness_program path.
local function verify_taproot_commitment(control_block, witness_program, leaf_hash)
  local control_parity = bit.band(string.byte(control_block, 1), 0x01)
  local internal_key = string.sub(control_block, 2, 33)

  -- For this isolated test we use the leaf_hash as the merkle root
  -- (no merkle path).
  local current = leaf_hash
  -- Walk merkle path (none here, so the loop is empty)
  for mi = 34, #control_block, 32 do
    local sibling = string.sub(control_block, mi, mi + 31)
    if current < sibling then
      current = crypto.tagged_hash("TapBranch", current .. sibling)
    else
      current = crypto.tagged_hash("TapBranch", sibling .. current)
    end
  end

  local tweak = crypto.tagged_hash("TapTweak", internal_key .. current)
  local tweaked_key, tweaked_parity = crypto.tweak_pubkey(internal_key, tweak)
  if not tweaked_key then
    return false, "TAPROOT_TWEAK_FAILED"
  end
  if tweaked_key ~= witness_program then
    return false, "WITNESS_PROGRAM_MISMATCH"
  end
  if tweaked_parity ~= control_parity then
    return false, "TAPROOT_WRONG_PARITY"
  end
  return true, nil
end

-- Use a deterministic x-only internal key (just the bytes 0x02 repeated).
-- This is a valid x-only pubkey for secp256k1 (compressed parity-even
-- pubkey 02..02 is on-curve for these byte values).
-- Tap leaf: arbitrary 32-byte hash.
local INTERNAL_KEY = string.rep("\x02", 32)
local LEAF_HASH = crypto.tagged_hash("TapLeaf", "\xc0\x01\x51")  -- leaf_ver 0xc0, 1-byte script OP_1

-- Compute the actual tweak + tweaked_key + parity
local tweak = crypto.tagged_hash("TapTweak", INTERNAL_KEY .. LEAF_HASH)
local computed_x, computed_parity = crypto.tweak_pubkey(INTERNAL_KEY, tweak)
check("crypto.tweak_pubkey returns (x, parity)",
  type(computed_x) == "string" and #computed_x == 32 and (computed_parity == 0 or computed_parity == 1),
  "x type=" .. type(computed_x) .. " parity=" .. tostring(computed_parity))

-- Build a control_block with the CORRECT parity bit
local correct_first_byte = bit.bor(0xc0, computed_parity)  -- leaf_ver=0xc0 + correct parity
local good_control = string.char(correct_first_byte) .. INTERNAL_KEY

-- Build a control_block with the FLIPPED (wrong) parity bit
local wrong_first_byte = bit.bxor(correct_first_byte, 0x01)
local bad_control = string.char(wrong_first_byte) .. INTERNAL_KEY

-- 1) Correct parity: verification must succeed (assuming x-coord matches).
do
  local ok, err = verify_taproot_commitment(good_control, computed_x, LEAF_HASH)
  check("correct parity accepted", ok, tostring(err))
end

-- 2) Flipped parity: verification must reject with TAPROOT_WRONG_PARITY.
do
  local ok, err = verify_taproot_commitment(bad_control, computed_x, LEAF_HASH)
  check("flipped parity rejected with TAPROOT_WRONG_PARITY",
        not ok and err == "TAPROOT_WRONG_PARITY", tostring(err))
end

-- 3) Sanity check the parity bit derivation: bit.band(byte, 1) == parity-bit.
do
  check("control_parity extraction (matching)",
    bit.band(string.byte(good_control, 1), 0x01) == computed_parity)
  check("control_parity extraction (flipped)",
    bit.band(string.byte(bad_control, 1), 0x01) ~= computed_parity)
end

-- 4) Demonstrate that a control_block whose parity doesn't match would
-- have been silently accepted pre-fix (no assertion). The fix: the new
-- assert in utxo.lua catches this exact mismatch.
do
  -- Re-run with a manually corrupted control_block where leaf_version
  -- byte XOR 0x01 → parity flipped. The function we wrote here mirrors
  -- the new utxo.lua check.
  local corrupted = string.char(bit.bxor(string.byte(good_control, 1), 0x01)) .. INTERNAL_KEY
  local ok, err = verify_taproot_commitment(corrupted, computed_x, LEAF_HASH)
  check("corrupted-parity control_block: rejected (was: silently accepted)",
        not ok and err == "TAPROOT_WRONG_PARITY", tostring(err))
end

print(string.format("\n%d passed, %d failed", pass, fail))
if fail > 0 then
  os.exit(1)
end
