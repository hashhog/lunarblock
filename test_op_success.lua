#!/usr/bin/env luajit
-- BIP-342 OP_SUCCESS pre-scan tests.
--
-- Per Core script/interpreter.cpp:1836-1856 ExecuteWitnessScript,
-- a tapscript containing any IsOpSuccess opcode causes immediate
-- success (overrides every other check). Pre-fix, lunarblock would
-- error() on disabled opcodes (OP_CAT etc.) inside tapscript and
-- consensus-split from Core the moment a future soft fork used one
-- of those reserved bytes.
--
-- IsOpSuccess opcodes: 0x50 (OP_RESERVED), 0x62 (OP_VER),
-- 0x7e-0x81, 0x83-0x86, 0x89-0x8a, 0x8d-0x8e, 0x95-0x99, 0xbb-0xfe.
--
-- Run: luajit test_op_success.lua

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

-- 1. is_op_success matches Core's set
check("is_op_success: 0x50 (OP_RESERVED)", script.is_op_success(0x50))
check("is_op_success: 0x62 (OP_VER)", script.is_op_success(0x62))
check("is_op_success: 0x7e (OP_CAT)", script.is_op_success(0x7e))
check("is_op_success: 0x7f (OP_SUBSTR)", script.is_op_success(0x7f))
check("is_op_success: 0x80 (OP_LEFT)", script.is_op_success(0x80))
check("is_op_success: 0x81 (OP_RIGHT)", script.is_op_success(0x81))
check("is_op_success: 0x83 (OP_INVERT)", script.is_op_success(0x83))
check("is_op_success: 0x86 (OP_XOR)", script.is_op_success(0x86))
check("is_op_success: 0x89 (OP_RESERVED1)", script.is_op_success(0x89))
check("is_op_success: 0x8a (OP_RESERVED2)", script.is_op_success(0x8a))
check("is_op_success: 0x8d (OP_2MUL)", script.is_op_success(0x8d))
check("is_op_success: 0x8e (OP_2DIV)", script.is_op_success(0x8e))
check("is_op_success: 0x95 (OP_MUL)", script.is_op_success(0x95))
check("is_op_success: 0x99 (OP_RSHIFT)", script.is_op_success(0x99))
check("is_op_success: 0xbb", script.is_op_success(0xbb))
check("is_op_success: 0xfe", script.is_op_success(0xfe))

-- Negatives: things that are NOT OP_SUCCESS
check("is_op_success: 0x4f (OP_1NEGATE) is NOT", not script.is_op_success(0x4f))
check("is_op_success: 0x51 (OP_1) is NOT", not script.is_op_success(0x51))
check("is_op_success: 0x61 (OP_NOP) is NOT", not script.is_op_success(0x61))
check("is_op_success: 0x63 (OP_IF) is NOT", not script.is_op_success(0x63))
check("is_op_success: 0x82 (OP_SIZE) is NOT", not script.is_op_success(0x82))
check("is_op_success: 0x87 (OP_EQUAL) is NOT", not script.is_op_success(0x87))
check("is_op_success: 0x88 (OP_EQUALVERIFY) is NOT", not script.is_op_success(0x88))
check("is_op_success: 0x8b (OP_1ADD) is NOT", not script.is_op_success(0x8b))
check("is_op_success: 0x8c (OP_1SUB) is NOT", not script.is_op_success(0x8c))
check("is_op_success: 0x8f (OP_NEGATE) is NOT", not script.is_op_success(0x8f))
check("is_op_success: 0x94 (OP_SUB) is NOT", not script.is_op_success(0x94))
check("is_op_success: 0x9a (OP_BOOLAND) is NOT", not script.is_op_success(0x9a))
check("is_op_success: 0xba (OP_CHECKSIGADD) is NOT", not script.is_op_success(0xba))
check("is_op_success: 0xff is NOT (post-IsOpSuccess range)", not script.is_op_success(0xff))

-- 2. Tapscript starting with OP_SUCCESS80 (0x50) accepts immediately
do
  local s = "\x50"
  local result, err = script.execute_witness_script(s, {}, {is_tapscript = true}, {})
  check("OP_SUCCESS80 (0x50) alone: tapscript accepts", result == true, tostring(err))
end

-- 3. Tapscript starting with OP_CAT (0x7e) - which is_disabled_opcode would error()
do
  local s = "\x7e"
  local result, err = script.execute_witness_script(s, {}, {is_tapscript = true}, {})
  check("OP_CAT (0x7e) alone in tapscript: accepts (was: errors)",
        result == true, tostring(err))
end

-- 4. OP_SUCCESS in middle of script (after pushes) still accepts
do
  -- <push 5 bytes> <0x95 OP_MUL> ...
  local s = "\x05" .. string.rep("\xaa", 5) .. "\x95" .. "\xff\xff\xff"
  local result, err = script.execute_witness_script(s, {}, {is_tapscript = true}, {})
  check("OP_MUL (0x95) after 5-byte push: accepts",
        result == true, tostring(err))
end

-- 5. PUSHDATA1 followed by OP_SUCCESS — pre-scan must skip the payload
do
  local s = "\x4c\x10" .. string.rep("\xbb", 16) .. "\x7f"  -- PUSHDATA1 16 bytes, then OP_SUBSTR
  local result, err = script.execute_witness_script(s, {}, {is_tapscript = true}, {})
  check("PUSHDATA1(16) + OP_SUBSTR: accepts",
        result == true, tostring(err))
end

-- 6. PUSHDATA2 followed by OP_SUCCESS — pre-scan must skip the payload
do
  -- PUSHDATA2 0x0100 (256) bytes, then OP_BB
  local n = 256
  local s = "\x4d" .. string.char(n % 256, math.floor(n / 256)) .. string.rep("\x00", n) .. "\xbb"
  local result, err = script.execute_witness_script(s, {}, {is_tapscript = true}, {})
  check("PUSHDATA2(256) + 0xbb: accepts",
        result == true, tostring(err))
end

-- 7. Truncated push BEFORE OP_SUCCESS — BAD_OPCODE
do
  -- Direct push of 5 bytes, but only 3 follow:
  local s = "\x05\xaa\xaa\xaa"
  local result, err = script.execute_witness_script(s, {}, {is_tapscript = true}, {})
  check("Truncated direct push: BAD_OPCODE",
        result == nil and err == "BAD_OPCODE", tostring(err))
end

-- 8. Non-tapscript path is unaffected — OP_CAT (a disabled op) must still error
-- (CHECKSIG with empty stack would fail differently; just verify execute_witness_script
-- with is_tapscript=false doesn't OP_SUCCESS short-circuit on OP_CAT.)
do
  local s = "\x7e"
  local ok, err = pcall(script.execute_witness_script, s, {}, {}, {})
  check("Non-tapscript OP_CAT: still errors (NOT OP_SUCCESS short-circuit)",
        not ok or (err ~= nil), tostring(err))
end

-- 9. DISCOURAGE_OP_SUCCESS flag set — pre-scan rejects with the policy error
do
  local s = "\x50"
  local result, err = script.execute_witness_script(s, {}, {
    is_tapscript = true,
    verify_discourage_op_success = true,
  }, {})
  check("OP_SUCCESS80 + DISCOURAGE flag: rejects with DISCOURAGE_OP_SUCCESS",
        result == nil and err == "DISCOURAGE_OP_SUCCESS", tostring(err))
end

-- 10. Tapscript with OP_RETURN (which would error()) preceded by OP_SUCCESS
-- demonstrates short-circuit overrides every later op
do
  local s = "\x50\x6a"  -- OP_RESERVED then OP_RETURN
  local result, err = script.execute_witness_script(s, {}, {is_tapscript = true}, {})
  check("OP_SUCCESS short-circuits past OP_RETURN",
        result == true, tostring(err))
end

print(string.format("\n%d passed, %d failed", pass, fail))
if fail > 0 then
  os.exit(1)
end
