#!/usr/bin/env luajit
-- Test harness for Bitcoin Core script_tests.json vectors
-- Parses ASM notation, assembles to raw bytes, and runs verify_script
-- Uses real signature verification via secp256k1 (crediting/spending tx approach)

package.path = "lunarblock/?.lua;src/?.lua;" .. package.path

local cjson = require("cjson")
local script = require("lunarblock.script")
local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local crypto = require("lunarblock.crypto")
local validation = require("lunarblock.validation")

--------------------------------------------------------------------------------
-- Hex encode/decode helpers
--------------------------------------------------------------------------------

local function hex_decode(hex)
  if not hex or hex == "" then return "" end
  local bytes = {}
  for i = 1, #hex, 2 do
    bytes[#bytes + 1] = string.char(tonumber(hex:sub(i, i + 1), 16))
  end
  return table.concat(bytes)
end

--------------------------------------------------------------------------------
-- ASM parser: convert Bitcoin script assembly notation to raw script bytes
--------------------------------------------------------------------------------

-- Opcode name (without OP_ prefix) -> byte value
local opcode_map = {
  ["0"] = 0x00, ["FALSE"] = 0x00,
  ["1NEGATE"] = 0x4f,
  ["RESERVED"] = 0x50,
  ["1"] = 0x51, ["TRUE"] = 0x51,
  ["2"] = 0x52, ["3"] = 0x53, ["4"] = 0x54, ["5"] = 0x55,
  ["6"] = 0x56, ["7"] = 0x57, ["8"] = 0x58, ["9"] = 0x59,
  ["10"] = 0x5a, ["11"] = 0x5b, ["12"] = 0x5c, ["13"] = 0x5d,
  ["14"] = 0x5e, ["15"] = 0x5f, ["16"] = 0x60,
  ["NOP"] = 0x61, ["VER"] = 0x62,
  ["IF"] = 0x63, ["NOTIF"] = 0x64,
  ["VERIF"] = 0x65, ["VERNOTIF"] = 0x66,
  ["ELSE"] = 0x67, ["ENDIF"] = 0x68,
  ["VERIFY"] = 0x69, ["RETURN"] = 0x6a,
  ["TOALTSTACK"] = 0x6b, ["FROMALTSTACK"] = 0x6c,
  ["2DROP"] = 0x6d, ["2DUP"] = 0x6e, ["3DUP"] = 0x6f,
  ["2OVER"] = 0x70, ["2ROT"] = 0x71, ["2SWAP"] = 0x72,
  ["IFDUP"] = 0x73, ["DEPTH"] = 0x74,
  ["DROP"] = 0x75, ["DUP"] = 0x76,
  ["NIP"] = 0x77, ["OVER"] = 0x78,
  ["PICK"] = 0x79, ["ROLL"] = 0x7a,
  ["ROT"] = 0x7b, ["SWAP"] = 0x7c, ["TUCK"] = 0x7d,
  ["CAT"] = 0x7e, ["SUBSTR"] = 0x7f, ["LEFT"] = 0x80, ["RIGHT"] = 0x81,
  ["SIZE"] = 0x82,
  ["INVERT"] = 0x83, ["AND"] = 0x84, ["OR"] = 0x85, ["XOR"] = 0x86,
  ["EQUAL"] = 0x87, ["EQUALVERIFY"] = 0x88,
  ["RESERVED1"] = 0x89, ["RESERVED2"] = 0x8a,
  ["1ADD"] = 0x8b, ["1SUB"] = 0x8c,
  ["2MUL"] = 0x8d, ["2DIV"] = 0x8e,
  ["NEGATE"] = 0x8f, ["ABS"] = 0x90,
  ["NOT"] = 0x91, ["0NOTEQUAL"] = 0x92,
  ["ADD"] = 0x93, ["SUB"] = 0x94,
  ["MUL"] = 0x95, ["DIV"] = 0x96, ["MOD"] = 0x97,
  ["LSHIFT"] = 0x98, ["RSHIFT"] = 0x99,
  ["BOOLAND"] = 0x9a, ["BOOLOR"] = 0x9b,
  ["NUMEQUAL"] = 0x9c, ["NUMEQUALVERIFY"] = 0x9d,
  ["NUMNOTEQUAL"] = 0x9e,
  ["LESSTHAN"] = 0x9f, ["GREATERTHAN"] = 0xa0,
  ["LESSTHANOREQUAL"] = 0xa1, ["GREATERTHANOREQUAL"] = 0xa2,
  ["MIN"] = 0xa3, ["MAX"] = 0xa4, ["WITHIN"] = 0xa5,
  ["RIPEMD160"] = 0xa6, ["SHA1"] = 0xa7, ["SHA256"] = 0xa8,
  ["HASH160"] = 0xa9, ["HASH256"] = 0xaa,
  ["CODESEPARATOR"] = 0xab,
  ["CHECKSIG"] = 0xac, ["CHECKSIGVERIFY"] = 0xad,
  ["CHECKMULTISIG"] = 0xae, ["CHECKMULTISIGVERIFY"] = 0xaf,
  ["NOP1"] = 0xb0,
  ["CHECKLOCKTIMEVERIFY"] = 0xb1, ["NOP2"] = 0xb1,
  ["CHECKSEQUENCEVERIFY"] = 0xb2, ["NOP3"] = 0xb2,
  ["NOP4"] = 0xb3, ["NOP5"] = 0xb4, ["NOP6"] = 0xb5,
  ["NOP7"] = 0xb6, ["NOP8"] = 0xb7, ["NOP9"] = 0xb8, ["NOP10"] = 0xb9,
  ["CHECKSIGADD"] = 0xba,
  ["INVALIDOPCODE"] = 0xff,
}

-- Encode a number in Bitcoin script_num format (CScriptNum)
local function encode_script_num(n)
  if n == 0 then return "" end
  local neg = (n < 0)
  local abs_n = math.abs(n)
  local result = {}
  while abs_n > 0 do
    result[#result + 1] = string.char(abs_n % 256)
    abs_n = math.floor(abs_n / 256)
  end
  -- Check if we need a sign byte
  local last = result[#result]:byte(1)
  if last >= 0x80 then
    result[#result + 1] = string.char(neg and 0x80 or 0x00)
  elseif neg then
    result[#result] = string.char(last + 0x80)
  end
  return table.concat(result)
end

-- Push data with appropriate push opcode
local function push_data(buf, data)
  local len = #data
  if len >= 1 and len <= 0x4b then
    buf[#buf + 1] = string.char(len) .. data
  elseif len <= 0xff then
    buf[#buf + 1] = string.char(0x4c, len) .. data
  elseif len <= 0xffff then
    buf[#buf + 1] = string.char(0x4d, len % 256, math.floor(len / 256)) .. data
  else
    buf[#buf + 1] = string.char(0x4e,
      len % 256,
      math.floor(len / 256) % 256,
      math.floor(len / 65536) % 256,
      math.floor(len / 16777216) % 256) .. data
  end
end

-- Assemble script ASM string to raw script bytes
local function assemble_script(asm_str)
  asm_str = asm_str:match("^%s*(.-)%s*$") -- trim
  if asm_str == "" then return "" end

  local buf = {}
  for token in asm_str:gmatch("%S+") do
    -- Strip OP_ prefix
    local name = token:match("^OP_(.+)$") or token

    if name:sub(1, 2) == "0x" then
      -- Raw hex bytes: emit literally
      local hex = name:sub(3)
      buf[#buf + 1] = hex_decode(hex)
    elseif name:sub(1, 1) == "'" then
      -- Quoted string
      local str = name:match("^'(.*)'$") or name:sub(2)
      if str == "" then
        buf[#buf + 1] = string.char(0x00) -- OP_0 for empty string
      else
        push_data(buf, str)
      end
    elseif opcode_map[name] then
      buf[#buf + 1] = string.char(opcode_map[name])
    else
      -- Try as decimal number
      local n = tonumber(name)
      if n then
        if n == 0 then
          buf[#buf + 1] = string.char(0x00)
        elseif n == -1 then
          buf[#buf + 1] = string.char(0x4f)
        elseif n >= 1 and n <= 16 then
          buf[#buf + 1] = string.char(0x50 + n)
        else
          push_data(buf, encode_script_num(n))
        end
      else
        io.stderr:write("WARNING: Unknown token: " .. token .. "\n")
      end
    end
  end
  return table.concat(buf)
end

--------------------------------------------------------------------------------
-- Flag parsing: convert flag string to flags table for lunarblock
--------------------------------------------------------------------------------

local function parse_flags(flags_str)
  local flags = {}
  if not flags_str or flags_str == "" or flags_str == "NONE" then
    return flags
  end
  for flag in flags_str:gmatch("[^,]+") do
    flag = flag:match("^%s*(.-)%s*$") -- trim
    if flag == "P2SH" then flags.verify_p2sh = true
    elseif flag == "STRICTENC" then flags.verify_strictenc = true
    elseif flag == "DERSIG" then flags.verify_dersig = true
    elseif flag == "LOW_S" then flags.verify_low_s = true
    elseif flag == "NULLDUMMY" then flags.verify_nulldummy = true
    elseif flag == "SIGPUSHONLY" then flags.verify_sigpushonly = true
    elseif flag == "MINIMALDATA" then flags.verify_minimaldata = true
    elseif flag == "DISCOURAGE_UPGRADABLE_NOPS" then flags.verify_discourage_upgradable_nops = true
    elseif flag == "CLEANSTACK" then flags.verify_cleanstack = true
    elseif flag == "CHECKLOCKTIMEVERIFY" then flags.verify_checklocktimeverify = true
    elseif flag == "CHECKSEQUENCEVERIFY" then flags.verify_checksequenceverify = true
    elseif flag == "WITNESS" then flags.verify_witness = true
    elseif flag == "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" then flags.verify_discourage_upgradable_witness = true
    elseif flag == "MINIMALIF" then flags.verify_minimalif = true
    elseif flag == "NULLFAIL" then flags.verify_nullfail = true
    elseif flag == "WITNESS_PUBKEYTYPE" then flags.verify_witness_pubkeytype = true
    elseif flag == "CONST_SCRIPTCODE" then flags.verify_const_scriptcode = true
    elseif flag == "TAPROOT" then flags.verify_taproot = true
    elseif flag == "DISCOURAGE_OP_SUCCESS" then flags.verify_discourage_op_success = true
    elseif flag == "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" then flags.verify_discourage_upgradable_taproot_version = true
    elseif flag == "DISCOURAGE_UPGRADABLE_PUBKEYTYPE" then flags.verify_discourage_upgradable_pubkeytype = true
    elseif flag ~= "NONE" then
      io.stderr:write("WARNING: Unknown flag: " .. flag .. "\n")
    end
  end
  return flags
end

--------------------------------------------------------------------------------
-- Load test vectors
--------------------------------------------------------------------------------

local vector_paths = {
  "/home/max/hashhog/bitcoin/src/test/data/script_tests.json",
  "/home/max/hashhog/bitcoin/src/test/data/script_tests.json",
}

local f, json_text
for _, path in ipairs(vector_paths) do
  f = io.open(path, "r")
  if f then
    json_text = f:read("*a")
    f:close()
    io.write("Loaded test vectors from: " .. path .. "\n")
    break
  end
end
assert(json_text, "Cannot open script_tests.json from any known path")

local vectors = cjson.decode(json_text)

--------------------------------------------------------------------------------
-- Transaction builders (Bitcoin Core's crediting/spending tx approach)
--------------------------------------------------------------------------------

--- Build a "crediting transaction" per Bitcoin Core's script test framework.
-- Version 1, locktime 0, one input (null prevout, scriptSig = OP_0 OP_0,
-- sequence 0xFFFFFFFF), one output (scriptPubKey = test's scriptPubKey, value = 0).
-- @param script_pubkey string: raw scriptPubKey bytes
-- @return transaction: the crediting transaction
local function build_crediting_tx(script_pubkey)
  local null_hash = types.hash256(string.rep("\0", 32))
  local credit_script_sig = string.char(0x00, 0x00) -- OP_0 OP_0
  local tx = types.transaction(1, {}, {}, 0)
  tx.inputs[1] = types.txin(
    types.outpoint(null_hash, 0xFFFFFFFF),
    credit_script_sig,
    0xFFFFFFFF
  )
  tx.outputs[1] = types.txout(0, script_pubkey)
  return tx
end

--- Compute the txid (hash256 of non-witness serialization) of a transaction.
-- @param tx transaction: the transaction
-- @return hash256: the transaction hash
local function compute_txid(tx)
  local raw = serialize.serialize_transaction(tx, false)
  return crypto.hash256_type(raw)
end

--- Build a "spending transaction" per Bitcoin Core's script test framework.
-- Version 1, locktime 0, one input (prevout = crediting txid : 0,
-- scriptSig = test's scriptSig, sequence 0xFFFFFFFF), one output (empty, value = 0).
-- @param credit_tx transaction: the crediting transaction
-- @param script_sig string: raw scriptSig bytes
-- @return transaction: the spending transaction
local function build_spending_tx(credit_tx, script_sig)
  local credit_txid = compute_txid(credit_tx)
  local tx = types.transaction(1, {}, {}, 0)
  tx.inputs[1] = types.txin(
    types.outpoint(credit_txid, 0),
    script_sig,
    0xFFFFFFFF
  )
  tx.outputs[1] = types.txout(0, "")
  return tx
end

--------------------------------------------------------------------------------
-- Run tests
--------------------------------------------------------------------------------

local pass_count = 0
local fail_count = 0
local skip_count = 0
local error_count = 0
local total = 0

for idx, entry in ipairs(vectors) do
  if type(entry) == "table" then
    local n = #entry
    -- Skip comments (single-element) and witness tests (6+)
    if n == 1 or n == 2 or n == 3 then
      -- comment or malformed, skip
    elseif n >= 6 then
      -- Witness test, skip for now
      skip_count = skip_count + 1
    elseif n == 4 or n == 5 then
      total = total + 1
      local script_sig_asm = entry[1]
      local script_pubkey_asm = entry[2]
      local flags_str = entry[3]
      local expected = entry[4]
      local comment = entry[5] or ""

      local ok_call, result_or_err = pcall(function()
        local script_sig_bytes = assemble_script(script_sig_asm)
        local script_pubkey_bytes = assemble_script(script_pubkey_asm)
        local flags = parse_flags(flags_str)

        -- Build crediting and spending transactions (Bitcoin Core approach)
        local credit_tx = build_crediting_tx(script_pubkey_bytes)
        local spending_tx = build_spending_tx(credit_tx, script_sig_bytes)

        -- Create a real signature checker with transaction context
        local checker = validation.make_sig_checker(
          spending_tx,       -- the spending transaction
          0,                 -- input index (0-based)
          0,                 -- prev output value (0 satoshis)
          script_pubkey_bytes, -- scriptPubKey of the output being spent
          flags              -- verification flags
        )

        local result, err = script.verify_script(script_sig_bytes, script_pubkey_bytes, flags, checker)
        -- Note: verify_script returns true on success, false/nil on failure
        return result == true
      end)

      local expected_ok = (expected == "OK")

      if ok_call then
        local got_ok = result_or_err
        if got_ok == expected_ok then
          pass_count = pass_count + 1
        else
          fail_count = fail_count + 1
          io.write(string.format("FAIL test %d: expected=%s got=%s sig=[%s] pub=[%s] flags=%s %s\n",
            idx, expected, got_ok and "OK" or "FAIL",
            script_sig_asm, script_pubkey_asm, flags_str, comment))
        end
      else
        -- Exception/error during execution
        if not expected_ok then
          pass_count = pass_count + 1 -- expected failure
        else
          error_count = error_count + 1
          io.write(string.format("ERROR test %d: %s sig=[%s] pub=[%s] flags=%s %s\n",
            idx, tostring(result_or_err),
            script_sig_asm, script_pubkey_asm, flags_str, comment))
        end
      end
    end
  end
end

io.write("\n=== Script Test Vector Results ===\n")
io.write(string.format("Total non-witness tests: %d\n", total))
io.write(string.format("  PASS:  %d\n", pass_count))
io.write(string.format("  FAIL:  %d\n", fail_count))
io.write(string.format("  ERROR: %d\n", error_count))
io.write(string.format("  Skipped (witness): %d\n", skip_count))

if fail_count > 0 or error_count > 0 then
  os.exit(1)
else
  os.exit(0)
end
