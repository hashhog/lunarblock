#!/usr/bin/env luajit
-- test_witness_malleated_p2sh.lua
--
-- Regression test for WITNESS_MALLEATED_P2SH byte-exact check.
--
-- Bitcoin Core reference: interpreter.cpp:2082-2085
--   if (scriptSig != CScript() << std::vector<unsigned char>(pubKey2.begin(), pubKey2.end()))
--       return set_error(serror, SCRIPT_ERR_WITNESS_MALLEATED_P2SH);
--
-- A P2SH-wrapped witness spend whose scriptSig uses a NON-MINIMAL push
-- (e.g. OP_PUSHDATA1 0x16 <W> instead of the direct minimal 0x16 <W>)
-- evaluates identically on the stack (push-only, single element) but Core
-- rejects it because the raw scriptSig bytes differ from the canonical push.
-- A stack-size check alone cannot catch this divergence.
--
-- MINIMALDATA is a POLICY flag only (not in GetBlockScriptFlags), so the
-- byte-exact malleation check is the only consensus guard against this
-- chain-splitting input.
--
-- Test cases:
--   1. Canonical scriptSig (0x16 <W>) -> ACCEPT (block flags, MINIMALDATA off)
--   2. Non-minimal scriptSig (OP_PUSHDATA1 0x16 <W>) -> REJECT WITNESS_MALLEATED_P2SH
--   3. Non-minimal scriptSig with same stack but two extra bytes -> REJECT
--      (demonstrates that the old #sig_stack_copy==1 check was blind to this)
--
-- RedeemScript W = OP_0 <20-byte-hash> (a P2WPKH program, 22 bytes).
-- P2SH scriptPubKey = OP_HASH160 <HASH160(W)> OP_EQUAL.
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   LD_LIBRARY_PATH=./lib luajit tests/test_witness_malleated_p2sh.lua

package.path = "src/?.lua;./?.lua;" .. package.path

local loaders = package.loaders or package.searchers
table.insert(loaders, 2, function(module)
  local name = module:match("^lunarblock%.(.+)")
  if name then
    local filename = "src/" .. name .. ".lua"
    local f = io.open(filename)
    if f then f:close(); return loadfile(filename) end
  end
end)

local script_mod = require("lunarblock.script")
local crypto     = require("lunarblock.crypto")

local PASS, FAIL = 0, 0

local function expect(cond, name)
  if cond then
    PASS = PASS + 1
    io.write("PASS " .. name .. "\n")
  else
    FAIL = FAIL + 1
    io.write("FAIL " .. name .. "\n")
  end
end

local function hex(s)
  local out = {}
  for i = 1, #s do out[i] = string.format("%02x", s:byte(i)) end
  return table.concat(out)
end

-- --------------------------------------------------------------------------
-- Build a minimal P2SH-P2WPKH scenario.
--
-- redeemScript W = OP_0 (0x00) + push-20 (0x14) + 20-byte pubkey hash
-- This is exactly 22 bytes, so the canonical scriptSig push is:
--   0x16 <W>   (direct push, opcode == length, length=22=0x16)
-- The non-canonical (malleated) form is:
--   OP_PUSHDATA1 (0x4c) 0x16 <W>   (same data, non-minimal encoding)
-- --------------------------------------------------------------------------

-- Use a fixed 20-byte "pubkey hash" (all 0xaa for simplicity; no real key needed
-- because we only test the scriptSig malleation check, which fires before any
-- witness program execution).
local FAKE_HASH20 = string.rep("\xaa", 20)

-- redeemScript W = OP_0 <20-byte-hash>
local W = "\x00" .. "\x14" .. FAKE_HASH20   -- 22 bytes

-- P2SH scriptPubKey = OP_HASH160 <hash160(W)> OP_EQUAL
--   OP_HASH160 = 0xa9, OP_EQUAL = 0x87
local h160_W = crypto.hash160(W)
local script_pubkey = "\xa9" .. "\x14" .. h160_W .. "\x87"

-- Block-consensus flags: P2SH + WITNESS enabled; MINIMALDATA deliberately OFF
-- (MINIMALDATA is policy-only; consensus must NOT rely on it for this check).
local flags = {
  verify_p2sh    = true,
  verify_witness = true,
  verify_minimaldata = false,
}

-- Dummy checker that provides an empty witness stack.  The malleation check
-- fires before the witness program is executed, so no signatures are needed.
local checker = {
  get_witness = function() return {} end,
}

-- --------------------------------------------------------------------------
-- Case 1: CANONICAL scriptSig  ->  must be ACCEPTED.
--
-- scriptSig = 0x16 <W>   (minimal direct push of 22 bytes)
-- --------------------------------------------------------------------------
do
  -- Push opcode for 22 bytes is 0x16 (22 == 0x16, direct push).
  local canonical_sig = string.char(0x16) .. W

  -- The witness program execution will fail (empty witness for P2WPKH needs
  -- a pubkey+sig), but the malleation check must PASS first.  We only assert
  -- the error is NOT WITNESS_MALLEATED_P2SH.
  local ok, err = script_mod.verify_script(canonical_sig, script_pubkey, flags, checker)
  local not_malleated = (err ~= "WITNESS_MALLEATED_P2SH")
  expect(not_malleated,
    "canonical scriptSig (0x16 <W>) is NOT rejected as WITNESS_MALLEATED_P2SH")
end

-- --------------------------------------------------------------------------
-- Case 2: NON-MINIMAL scriptSig using OP_PUSHDATA1  ->  must be REJECTED.
--
-- scriptSig = OP_PUSHDATA1 (0x4c) 0x16 <W>
-- This pushes the same 22 bytes onto the stack (push-only, 1 element)
-- but the raw bytes differ from the canonical form.
-- The old stack-size check (#sig_stack_copy == 1) would let this through;
-- the byte-exact check must reject it.
-- --------------------------------------------------------------------------
do
  local malleated_sig = string.char(0x4c, 0x16) .. W  -- OP_PUSHDATA1 length=22 data=W

  local ok, err = script_mod.verify_script(malleated_sig, script_pubkey, flags, checker)
  expect(err == "WITNESS_MALLEATED_P2SH",
    "OP_PUSHDATA1-encoded scriptSig rejected as WITNESS_MALLEATED_P2SH (was: " .. tostring(err) .. ")")
end

-- --------------------------------------------------------------------------
-- Case 3: TWO-PUSH scriptSig (OP_1 <W>)  ->  must be REJECTED.
--
-- This is a different malleation: pushing a bogus dummy then W produces a
-- 2-element stack.  The old check catches this (size != 1), and the new
-- byte-exact check also catches it.  Confirms the new check is a strict
-- superset of the old guard.
-- --------------------------------------------------------------------------
do
  -- OP_1 (0x51) pushes integer 1.  Then 0x16 <W> pushes W.  Stack = {"\x01", W}.
  local two_push_sig = string.char(0x51) .. string.char(0x16) .. W

  local ok, err = script_mod.verify_script(two_push_sig, script_pubkey, flags, checker)
  expect(err == "WITNESS_MALLEATED_P2SH",
    "two-push scriptSig rejected as WITNESS_MALLEATED_P2SH (was: " .. tostring(err) .. ")")
end

-- --------------------------------------------------------------------------
-- Summary
-- --------------------------------------------------------------------------
io.write(string.format("\n%d passed, %d failed\n", PASS, FAIL))
if FAIL > 0 then os.exit(1) end
