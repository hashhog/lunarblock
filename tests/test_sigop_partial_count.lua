#!/usr/bin/env luajit
-- Regression test: count_script_sigops partial-count parity with Bitcoin Core.
--
-- Bitcoin Core CScript::GetSigOpCount (script/script.cpp:158-180) walks the
-- script opcode-by-opcode via GetOp and, on a malformed/truncated push (GetOp
-- returns false), STOPS and returns the count accumulated SO FAR. lunarblock
-- previously did `pcall(parse_script); if not ok then return 0`, which counted
-- ZERO sigops for ANY script that failed to fully parse. Because the sigop
-- count feeds the consensus MAX_BLOCK_SIGOPS_COST check (check_block +
-- get_legacy_sigop_count/get_transaction_sigop_cost on connect), an attacker
-- could stuff a block with malformed scripts (leading OP_CHECKSIGs + a truncated
-- push) so the TRUE (Core) sigop cost exceeds the cap while lunarblock counted
-- ~0 -> lunarblock accepts a block Core rejects -> chain split.
--
-- This test verifies the partial-count behavior matches Core: leading sigops
-- before a truncated push are counted; clean scripts are unchanged.
--
-- Run: luajit tests/test_sigop_partial_count.lua

package.path = "./src/?.lua;" .. package.path
package.cpath = "./lib/?.so;" .. package.cpath

local validation = require("validation")
local C = validation.count_script_sigops

local pass, fail = 0, 0
local function check(name, got, want)
  if got == want then
    io.write("PASS: " .. name .. " (= " .. tostring(got) .. ")\n")
    pass = pass + 1
  else
    io.write("FAIL: " .. name .. " -- got " .. tostring(got) .. ", want " .. tostring(want) .. "\n")
    fail = fail + 1
  end
end

-- Opcodes: OP_CHECKSIG=0xac, OP_CHECKMULTISIG=0xae, OP_1=0x51, OP_2=0x52
-- clean single OP_CHECKSIG
check("clean OP_CHECKSIG", C(string.char(0xac), false), 1)

-- THE FIX: OP_CHECKSIG OP_CHECKSIG <0x4b direct-push-75-bytes, truncated (no data)>
-- Core counts the two leading CHECKSIGs then GetOp fails on the bad push -> 2.
-- Old lunarblock: parse_script asserts -> pcall fails -> returned 0 (undercount).
check("partial count before truncated direct push", C(string.char(0xac, 0xac, 0x4b), false), 2)

-- CHECKSIG then a truncated OP_PUSHDATA2 (only one length byte) -> count 1, not 0
check("partial count before truncated PUSHDATA2", C(string.char(0xac, 0x4d, 0x10), false), 1)

-- CHECKSIG then truncated OP_PUSHDATA1 (declares 5 bytes, none follow) -> 1
check("partial count before truncated PUSHDATA1", C(string.char(0xac, 0x4c, 0x05), false), 1)

-- accurate multisig: OP_2 OP_CHECKMULTISIG -> 2 (prev OP_N decoded)
check("accurate OP_2 CHECKMULTISIG", C(string.char(0x52, 0xae), true), 2)

-- inaccurate multisig -> MAX_PUBKEYS_PER_MULTISIG (20)
check("inaccurate CHECKMULTISIG", C(string.char(0xae), false), 20)

-- a valid push followed by CHECKSIG counts the CHECKSIG (push skipped correctly)
-- 0x01 0xff (push 1 byte) then OP_CHECKSIG -> 1
check("valid 1-byte push then CHECKSIG", C(string.char(0x01, 0xff, 0xac), false), 1)

-- empty script -> 0
check("empty script", C("", false), 0)

io.write(string.format("\n%d passed, %d failed\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
