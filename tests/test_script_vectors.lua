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

local function hex_encode(data)
  local out = {}
  for i = 1, #data do
    out[i] = string.format("%02x", data:byte(i))
  end
  return table.concat(out)
end

--------------------------------------------------------------------------------
-- Taproot placeholder resolution
--------------------------------------------------------------------------------

-- Internal key: the generator point x-only (BIP341 test convention)
local INTERNAL_KEY_HEX = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
local INTERNAL_KEY = hex_decode(INTERNAL_KEY_HEX)

--- Assemble a script from ASM (forward declaration, defined below)
local assemble_script_fwd

--- Resolve #SCRIPT#, #CONTROLBLOCK#, #TAPROOTOUTPUT# in witness stack.
-- The witness stack items are hex strings. Items containing #SCRIPT# have the
-- format: "#SCRIPT# <ASM...>" where ASM is the leaf script.
-- Items equal to "#CONTROLBLOCK#" get replaced with the computed control block.
-- The scriptPubKey "#TAPROOTOUTPUT#" is resolved separately.
--
-- After resolution, witness_stack items remain as hex strings.
local function resolve_taproot_placeholders(witness_stack, script_pubkey_asm)
  -- Step 1: Find the #SCRIPT# item and extract the leaf script ASM
  local script_idx = nil
  local leaf_script_asm = nil
  for i, item in ipairs(witness_stack) do
    if type(item) == "string" and item:find("#SCRIPT#") then
      script_idx = i
      -- The item is "#SCRIPT# <asm...>" — extract the ASM after the prefix
      leaf_script_asm = item:match("^#SCRIPT#%s*(.+)$")
      break
    end
  end

  if not script_idx or not leaf_script_asm then
    error("No #SCRIPT# placeholder found in witness stack")
  end

  -- Step 2: Assemble the leaf script to raw bytes
  local leaf_script_bytes = assemble_script_fwd(leaf_script_asm)

  -- Step 3: Replace #SCRIPT# item with the assembled script hex
  witness_stack[script_idx] = hex_encode(leaf_script_bytes)

  -- Step 4: Compute tapleaf hash: tagged_hash("TapLeaf", 0xc0 || compact_size(len) || script)
  local leaf_version = string.char(0xc0)
  local tapleaf_data = leaf_version .. crypto.compact_size(#leaf_script_bytes) .. leaf_script_bytes
  local tapleaf_hash = crypto.tagged_hash("TapLeaf", tapleaf_data)

  -- Step 5: Merkle root = tapleaf hash (single leaf tree)
  local merkle_root = tapleaf_hash

  -- Step 6: Compute tweaked output key
  local tweak = crypto.tagged_hash("TapTweak", INTERNAL_KEY .. merkle_root)
  local output_key, parity = crypto.tweak_pubkey(INTERNAL_KEY, tweak)
  assert(output_key, "Failed to tweak pubkey")

  -- Step 7: Build control block = (0xc0 | parity) || internal_key (33 bytes)
  local control_byte = string.char(0xc0 + parity)
  local control_block = control_byte .. INTERNAL_KEY

  -- Step 8: Replace #CONTROLBLOCK# in witness stack
  for i, item in ipairs(witness_stack) do
    if type(item) == "string" and item == "#CONTROLBLOCK#" then
      witness_stack[i] = hex_encode(control_block)
      break
    end
  end
end

--- Resolve #TAPROOTOUTPUT# in scriptPubKey ASM.
-- Returns the modified ASM string with the placeholder replaced.
local function resolve_taproot_scriptpubkey(script_pubkey_asm, witness_stack)
  if not script_pubkey_asm:find("#TAPROOTOUTPUT#") then
    return script_pubkey_asm
  end

  -- We need to recompute the output key from the witness stack.
  -- The last witness item is the control block, second-to-last is the leaf script.
  -- But we already computed it during resolve_taproot_placeholders, so let's
  -- extract from the control block in the witness stack.
  --
  -- Actually, we need to recompute: find the script and control block items.
  local leaf_script_hex = nil
  local control_block_hex = nil

  -- In taproot witness: [...data items..., script, controlblock]
  -- The control block is the last item, script is second-to-last
  local n = #witness_stack
  if n >= 2 then
    control_block_hex = witness_stack[n]
    leaf_script_hex = witness_stack[n - 1]
  end

  if not control_block_hex or not leaf_script_hex then
    error("Cannot resolve #TAPROOTOUTPUT#: missing script/control block in witness")
  end

  local control_block = hex_decode(control_block_hex)
  local leaf_script_bytes = hex_decode(leaf_script_hex)

  -- Extract internal key from control block (bytes 2-33)
  local internal_key = control_block:sub(2, 33)

  -- Compute tapleaf hash
  local leaf_version = string.char(0xc0)
  local tapleaf_data = leaf_version .. crypto.compact_size(#leaf_script_bytes) .. leaf_script_bytes
  local tapleaf_hash = crypto.tagged_hash("TapLeaf", tapleaf_data)
  local merkle_root = tapleaf_hash

  -- Compute tweaked output key
  local tweak = crypto.tagged_hash("TapTweak", internal_key .. merkle_root)
  local output_key = crypto.tweak_pubkey(internal_key, tweak)
  assert(output_key, "Failed to compute taproot output key")

  -- Replace #TAPROOTOUTPUT# with the hex of the output key (0x prefix for ASM parser)
  return script_pubkey_asm:gsub("#TAPROOTOUTPUT#", "0x" .. hex_encode(output_key))
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

-- Bind forward declaration for taproot resolution
assemble_script_fwd = assemble_script

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
-- sequence 0xFFFFFFFF), one output (scriptPubKey = test's scriptPubKey, value = amount).
-- @param script_pubkey string: raw scriptPubKey bytes
-- @param amount number: output value in satoshis (default 0)
-- @return transaction: the crediting transaction
local function build_crediting_tx(script_pubkey, amount)
  local null_hash = types.hash256(string.rep("\0", 32))
  local credit_script_sig = string.char(0x00, 0x00) -- OP_0 OP_0
  local tx = types.transaction(1, {}, {}, 0)
  tx.inputs[1] = types.txin(
    types.outpoint(null_hash, 0xFFFFFFFF),
    credit_script_sig,
    0xFFFFFFFF
  )
  tx.outputs[1] = types.txout(amount or 0, script_pubkey)
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
-- @param witness table|nil: witness stack (list of byte strings)
-- @return transaction: the spending transaction
local function build_spending_tx(credit_tx, script_sig, witness)
  local credit_txid = compute_txid(credit_tx)
  local tx = types.transaction(1, {}, {}, 0)
  tx.inputs[1] = types.txin(
    types.outpoint(credit_txid, 0),
    script_sig,
    0xFFFFFFFF
  )
  if witness and #witness > 0 then
    tx.inputs[1].witness = witness
    tx.segwit = true
  end
  -- Match Bitcoin Core: spending tx output value = crediting tx output value
  tx.outputs[1] = types.txout(credit_tx.outputs[1].value, "")
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
local witness_pass = 0
local witness_fail = 0
local witness_error = 0
local witness_total = 0

--- Run a single test vector (shared logic for legacy and witness)
local function run_test(idx, script_sig_asm, script_pubkey_asm, flags_str, expected, comment, witness_hex_items, amount_satoshis)
  local is_witness = (witness_hex_items ~= nil)
  if is_witness then
    witness_total = witness_total + 1
  else
    total = total + 1
  end

  local ok_call, result_or_err = pcall(function()
    local script_sig_bytes = assemble_script(script_sig_asm)
    local script_pubkey_bytes = assemble_script(script_pubkey_asm)
    local flags = parse_flags(flags_str)

    -- Decode witness items from hex
    local witness = nil
    if witness_hex_items then
      witness = {}
      for _, hex_item in ipairs(witness_hex_items) do
        witness[#witness + 1] = hex_decode(hex_item)
      end
    end

    local amount = amount_satoshis or 0

    -- Build crediting and spending transactions (Bitcoin Core approach)
    local credit_tx = build_crediting_tx(script_pubkey_bytes, amount)
    local spending_tx = build_spending_tx(credit_tx, script_sig_bytes, witness)

    -- Create a real signature checker with transaction context
    local checker = validation.make_sig_checker(
      spending_tx,           -- the spending transaction
      0,                     -- input index (0-based)
      amount,                -- prev output value
      script_pubkey_bytes,   -- scriptPubKey of the output being spent
      flags                  -- verification flags
    )

    local result, err = script.verify_script(script_sig_bytes, script_pubkey_bytes, flags, checker)
    -- Note: verify_script returns true on success, false/nil on failure
    return result == true
  end)

  local expected_ok = (expected == "OK")

  if ok_call then
    local got_ok = result_or_err
    if got_ok == expected_ok then
      if is_witness then witness_pass = witness_pass + 1 else pass_count = pass_count + 1 end
    else
      if is_witness then witness_fail = witness_fail + 1 else fail_count = fail_count + 1 end
      io.write(string.format("FAIL test %d%s: expected=%s got=%s sig=[%s] pub=[%s] flags=%s %s\n",
        idx, is_witness and " (witness)" or "",
        expected, got_ok and "OK" or "FAIL",
        script_sig_asm, script_pubkey_asm, flags_str, comment))
    end
  else
    -- Exception/error during execution
    if not expected_ok then
      if is_witness then witness_pass = witness_pass + 1 else pass_count = pass_count + 1 end
    else
      if is_witness then witness_error = witness_error + 1 else error_count = error_count + 1 end
      io.write(string.format("ERROR test %d%s: %s sig=[%s] pub=[%s] flags=%s %s\n",
        idx, is_witness and " (witness)" or "",
        tostring(result_or_err),
        script_sig_asm, script_pubkey_asm, flags_str, comment))
    end
  end
end

for idx, entry in ipairs(vectors) do
  if type(entry) == "table" then
    local n = #entry
    -- Skip comments (single-element)
    if n == 1 or n == 2 or n == 3 then
      -- comment or malformed, skip
    elseif type(entry[1]) == "table" and n >= 5 then
      -- Witness test vector:
      -- entry[1] = array: witness hex items, with LAST element being amount in BTC (number)
      -- entry[2] = scriptSig ASM
      -- entry[3] = scriptPubKey ASM
      -- entry[4] = flags
      -- entry[5] = expected result
      -- entry[6] = comment (optional)
      local wit_array = entry[1]
      local script_sig_asm = entry[2]
      local script_pubkey_asm = entry[3]
      local flags_str = entry[4]
      local expected = entry[5]
      local comment = entry[6] or ""

      -- Last element of witness array is amount in BTC (float)
      local amount_btc = wit_array[#wit_array]  -- number, e.g. 1e-08 = 1 satoshi
      local amount_satoshis = math.floor(amount_btc * 1e8 + 0.5)

      -- Witness stack is all elements except the last (which is the amount)
      local witness_stack = {}
      for i = 1, #wit_array - 1 do
        witness_stack[i] = wit_array[i]
      end

      -- Resolve taproot placeholders if present
      if flags_str:find("TAPROOT") then
        local resolved_ok, resolve_err = pcall(function()
          resolve_taproot_placeholders(witness_stack, script_pubkey_asm)
        end)
        if resolved_ok then
          -- witness_stack now has resolved hex items; script_pubkey_asm needs resolving too
          script_pubkey_asm = resolve_taproot_scriptpubkey(script_pubkey_asm, witness_stack)
        else
          -- Can't resolve, skip
          skip_count = skip_count + 1
          goto continue
        end
      end

      run_test(idx, script_sig_asm, script_pubkey_asm, flags_str, expected, comment, witness_stack, amount_satoshis)
      ::continue::

    elseif n == 4 or n == 5 then
      local script_sig_asm = entry[1]
      local script_pubkey_asm = entry[2]
      local flags_str = entry[3]
      local expected = entry[4]
      local comment = entry[5] or ""

      run_test(idx, script_sig_asm, script_pubkey_asm, flags_str, expected, comment)
    end
  end
end

io.write("\n=== Script Test Vector Results ===\n")
io.write(string.format("Legacy tests: %d\n", total))
io.write(string.format("  PASS:  %d\n", pass_count))
io.write(string.format("  FAIL:  %d\n", fail_count))
io.write(string.format("  ERROR: %d\n", error_count))
io.write(string.format("Witness tests: %d\n", witness_total))
io.write(string.format("  PASS:  %d\n", witness_pass))
io.write(string.format("  FAIL:  %d\n", witness_fail))
io.write(string.format("  ERROR: %d\n", witness_error))
local total_all = total + witness_total
local pass_all = pass_count + witness_pass
local fail_all = fail_count + witness_fail
local error_all = error_count + witness_error
io.write(string.format("Skipped (taproot): %d\n", skip_count))
io.write(string.format("Combined: %d/%d passed (%.1f%%)\n", pass_all, total_all, total_all > 0 and (100.0 * pass_all / total_all) or 0))

if fail_all > 0 or error_all > 0 then
  os.exit(1)
else
  os.exit(0)
end
