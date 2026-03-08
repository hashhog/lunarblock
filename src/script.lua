local crypto = require("lunarblock.crypto")
local serialize = require("lunarblock.serialize")
local types = require("lunarblock.types")
local M = {}

-- All Bitcoin Script opcodes
M.OP = {
  -- Push value
  OP_0 = 0x00, OP_FALSE = 0x00,
  OP_PUSHDATA1 = 0x4c, OP_PUSHDATA2 = 0x4d, OP_PUSHDATA4 = 0x4e,
  OP_1NEGATE = 0x4f,
  OP_RESERVED = 0x50,
  OP_1 = 0x51, OP_TRUE = 0x51,
  OP_2 = 0x52, OP_3 = 0x53, OP_4 = 0x54, OP_5 = 0x55,
  OP_6 = 0x56, OP_7 = 0x57, OP_8 = 0x58, OP_9 = 0x59,
  OP_10 = 0x5a, OP_11 = 0x5b, OP_12 = 0x5c, OP_13 = 0x5d,
  OP_14 = 0x5e, OP_15 = 0x5f, OP_16 = 0x60,
  -- Flow control
  OP_NOP = 0x61, OP_VER = 0x62,
  OP_IF = 0x63, OP_NOTIF = 0x64,
  OP_VERIF = 0x65, OP_VERNOTIF = 0x66,
  OP_ELSE = 0x67, OP_ENDIF = 0x68,
  OP_VERIFY = 0x69, OP_RETURN = 0x6a,
  -- Stack
  OP_TOALTSTACK = 0x6b, OP_FROMALTSTACK = 0x6c,
  OP_2DROP = 0x6d, OP_2DUP = 0x6e, OP_3DUP = 0x6f,
  OP_2OVER = 0x70, OP_2ROT = 0x71, OP_2SWAP = 0x72,
  OP_IFDUP = 0x73, OP_DEPTH = 0x74, OP_DROP = 0x75,
  OP_DUP = 0x76, OP_NIP = 0x77, OP_OVER = 0x78,
  OP_PICK = 0x79, OP_ROLL = 0x7a, OP_ROT = 0x7b,
  OP_SWAP = 0x7c, OP_TUCK = 0x7d,
  -- Splice (disabled)
  OP_CAT = 0x7e, OP_SUBSTR = 0x7f, OP_LEFT = 0x80, OP_RIGHT = 0x81,
  OP_SIZE = 0x82,
  -- Bitwise logic
  OP_INVERT = 0x83, OP_AND = 0x84, OP_OR = 0x85, OP_XOR = 0x86,
  OP_EQUAL = 0x87, OP_EQUALVERIFY = 0x88,
  OP_RESERVED1 = 0x89, OP_RESERVED2 = 0x8a,
  -- Arithmetic
  OP_1ADD = 0x8b, OP_1SUB = 0x8c,
  OP_2MUL = 0x8d, OP_2DIV = 0x8e,
  OP_NEGATE = 0x8f, OP_ABS = 0x90,
  OP_NOT = 0x91, OP_0NOTEQUAL = 0x92,
  OP_ADD = 0x93, OP_SUB = 0x94,
  OP_MUL = 0x95, OP_DIV = 0x96, OP_MOD = 0x97,
  OP_LSHIFT = 0x98, OP_RSHIFT = 0x99,
  OP_BOOLAND = 0x9a, OP_BOOLOR = 0x9b,
  OP_NUMEQUAL = 0x9c, OP_NUMEQUALVERIFY = 0x9d,
  OP_NUMNOTEQUAL = 0x9e,
  OP_LESSTHAN = 0x9f, OP_GREATERTHAN = 0xa0,
  OP_LESSTHANOREQUAL = 0xa1, OP_GREATERTHANOREQUAL = 0xa2,
  OP_MIN = 0xa3, OP_MAX = 0xa4,
  OP_WITHIN = 0xa5,
  -- Crypto
  OP_RIPEMD160 = 0xa6, OP_SHA1 = 0xa7, OP_SHA256 = 0xa8,
  OP_HASH160 = 0xa9, OP_HASH256 = 0xaa,
  OP_CODESEPARATOR = 0xab,
  OP_CHECKSIG = 0xac, OP_CHECKSIGVERIFY = 0xad,
  OP_CHECKMULTISIG = 0xae, OP_CHECKMULTISIGVERIFY = 0xaf,
  -- NOPs (reserved for future softforks)
  OP_NOP1 = 0xb0,
  OP_CHECKLOCKTIMEVERIFY = 0xb1, OP_NOP2 = 0xb1,
  OP_CHECKSEQUENCEVERIFY = 0xb2, OP_NOP3 = 0xb2,
  OP_NOP4 = 0xb3, OP_NOP5 = 0xb4, OP_NOP6 = 0xb5,
  OP_NOP7 = 0xb6, OP_NOP8 = 0xb7, OP_NOP9 = 0xb8, OP_NOP10 = 0xb9,
  -- Taproot
  OP_CHECKSIGADD = 0xba,
  -- Invalid opcodes (0xbb-0xff are OP_INVALIDOPCODE)
  OP_INVALIDOPCODE = 0xff,
}

-- Build reverse lookup table: opcode number -> name string
M.OP_NAMES = {}
for name, code in pairs(M.OP) do
  -- Store first name encountered (some codes have aliases)
  if not M.OP_NAMES[code] then
    M.OP_NAMES[code] = name
  end
end

-- Script limits
local MAX_OPS = 201
local MAX_STACK_SIZE = 1000
local MAX_SCRIPT_ELEMENT_SIZE = 520
local MAX_SCRIPT_SIZE = 10000

-- Encode a number as Bitcoin Script's variable-length little-endian signed integer
-- If n==0, return empty string
-- Otherwise encode absolute value as little-endian bytes, then set MSB of last byte if negative
function M.script_num_encode(n)
  if n == 0 then
    return ""
  end

  local negative = n < 0
  local abs_n = math.abs(n)

  -- Build little-endian bytes
  local bytes = {}
  while abs_n > 0 do
    bytes[#bytes + 1] = abs_n % 256
    abs_n = math.floor(abs_n / 256)
  end

  -- If the high bit of the last byte is set, we need a sign byte
  if bytes[#bytes] >= 0x80 then
    if negative then
      bytes[#bytes + 1] = 0x80
    else
      bytes[#bytes + 1] = 0x00
    end
  elseif negative then
    -- Set the sign bit on the last byte
    bytes[#bytes] = bytes[#bytes] + 0x80
  end

  -- Convert to string
  local result = {}
  for i = 1, #bytes do
    result[i] = string.char(bytes[i])
  end
  return table.concat(result)
end

-- Decode Bitcoin Script number from bytes
function M.script_num_decode(bytes, max_len)
  max_len = max_len or 4
  if #bytes == 0 then
    return 0
  end
  assert(#bytes <= max_len, "script number too long")

  -- Read as little-endian
  local result = 0
  for i = #bytes, 1, -1 do
    result = result * 256 + bytes:byte(i)
  end

  -- Check sign bit (MSB of last byte)
  local last_byte = bytes:byte(#bytes)
  if last_byte >= 0x80 then
    -- Negative: clear sign bit and negate
    result = result - (0x80 * (256 ^ (#bytes - 1)))
    result = -result
  end

  return result
end

-- Cast bytes to boolean
-- Empty string is false, all-zero bytes is false, negative zero is false
function M.cast_to_bool(bytes)
  if #bytes == 0 then
    return false
  end

  for i = 1, #bytes do
    local b = bytes:byte(i)
    if b ~= 0 then
      -- Check for negative zero: last byte is 0x80, all others are 0x00
      if i == #bytes and b == 0x80 then
        return false
      end
      return true
    end
  end

  return false
end

-- Parse a script into a list of {opcode=N, data=string_or_nil}
function M.parse_script(script_bytes)
  local ops = {}
  local pos = 1
  local len = #script_bytes

  while pos <= len do
    local opcode = script_bytes:byte(pos)
    pos = pos + 1

    if opcode >= 0x01 and opcode <= 0x4b then
      -- Direct push: next N bytes
      local data_len = opcode
      assert(pos + data_len - 1 <= len, "unexpected end of script in push")
      local data = script_bytes:sub(pos, pos + data_len - 1)
      pos = pos + data_len
      ops[#ops + 1] = {opcode = opcode, data = data}
    elseif opcode == 0x4c then
      -- OP_PUSHDATA1: read 1-byte length, then data
      assert(pos <= len, "unexpected end of script in PUSHDATA1")
      local data_len = script_bytes:byte(pos)
      pos = pos + 1
      assert(pos + data_len - 1 <= len, "unexpected end of script in PUSHDATA1 data")
      local data = script_bytes:sub(pos, pos + data_len - 1)
      pos = pos + data_len
      ops[#ops + 1] = {opcode = opcode, data = data}
    elseif opcode == 0x4d then
      -- OP_PUSHDATA2: read 2-byte length (little-endian), then data
      assert(pos + 1 <= len, "unexpected end of script in PUSHDATA2")
      local data_len = script_bytes:byte(pos) + script_bytes:byte(pos + 1) * 256
      pos = pos + 2
      assert(pos + data_len - 1 <= len, "unexpected end of script in PUSHDATA2 data")
      local data = script_bytes:sub(pos, pos + data_len - 1)
      pos = pos + data_len
      ops[#ops + 1] = {opcode = opcode, data = data}
    elseif opcode == 0x4e then
      -- OP_PUSHDATA4: read 4-byte length (little-endian), then data
      assert(pos + 3 <= len, "unexpected end of script in PUSHDATA4")
      local b1, b2, b3, b4 = script_bytes:byte(pos, pos + 3)
      local data_len = b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
      pos = pos + 4
      assert(pos + data_len - 1 <= len, "unexpected end of script in PUSHDATA4 data")
      local data = script_bytes:sub(pos, pos + data_len - 1)
      pos = pos + data_len
      ops[#ops + 1] = {opcode = opcode, data = data}
    else
      -- Regular opcode
      ops[#ops + 1] = {opcode = opcode, data = nil}
    end
  end

  return ops
end

-- Build a script from a list of {opcode=N, data=string_or_nil}
function M.build_script(ops)
  local parts = {}

  for _, op in ipairs(ops) do
    local opcode = op.opcode
    local data = op.data

    if opcode >= 0x01 and opcode <= 0x4b then
      -- Direct push
      assert(data and #data == opcode, "invalid push data length")
      parts[#parts + 1] = string.char(opcode) .. data
    elseif opcode == 0x4c then
      -- OP_PUSHDATA1
      assert(data, "PUSHDATA1 requires data")
      parts[#parts + 1] = string.char(0x4c, #data) .. data
    elseif opcode == 0x4d then
      -- OP_PUSHDATA2
      assert(data, "PUSHDATA2 requires data")
      local len = #data
      parts[#parts + 1] = string.char(0x4d, len % 256, math.floor(len / 256)) .. data
    elseif opcode == 0x4e then
      -- OP_PUSHDATA4
      assert(data, "PUSHDATA4 requires data")
      local len = #data
      parts[#parts + 1] = string.char(
        0x4e,
        len % 256,
        math.floor(len / 256) % 256,
        math.floor(len / 65536) % 256,
        math.floor(len / 16777216)
      ) .. data
    else
      -- Regular opcode
      parts[#parts + 1] = string.char(opcode)
    end
  end

  return table.concat(parts)
end

-- Helper: create a push opcode for data
local function make_push(data)
  local len = #data
  if len == 0 then
    return {opcode = M.OP.OP_0, data = nil}
  elseif len <= 0x4b then
    return {opcode = len, data = data}
  elseif len <= 0xff then
    return {opcode = 0x4c, data = data}
  elseif len <= 0xffff then
    return {opcode = 0x4d, data = data}
  else
    return {opcode = 0x4e, data = data}
  end
end

-- Standard script template builders

-- P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
function M.make_p2pkh_script(pubkey_hash20)
  assert(#pubkey_hash20 == 20, "P2PKH requires 20-byte pubkey hash")
  return M.build_script({
    {opcode = M.OP.OP_DUP, data = nil},
    {opcode = M.OP.OP_HASH160, data = nil},
    make_push(pubkey_hash20),
    {opcode = M.OP.OP_EQUALVERIFY, data = nil},
    {opcode = M.OP.OP_CHECKSIG, data = nil},
  })
end

-- P2SH: OP_HASH160 <20 bytes> OP_EQUAL
function M.make_p2sh_script(script_hash20)
  assert(#script_hash20 == 20, "P2SH requires 20-byte script hash")
  return M.build_script({
    {opcode = M.OP.OP_HASH160, data = nil},
    make_push(script_hash20),
    {opcode = M.OP.OP_EQUAL, data = nil},
  })
end

-- P2WPKH: OP_0 <20 bytes>
function M.make_p2wpkh_script(pubkey_hash20)
  assert(#pubkey_hash20 == 20, "P2WPKH requires 20-byte pubkey hash")
  return M.build_script({
    {opcode = M.OP.OP_0, data = nil},
    make_push(pubkey_hash20),
  })
end

-- P2WSH: OP_0 <32 bytes>
function M.make_p2wsh_script(script_hash32)
  assert(#script_hash32 == 32, "P2WSH requires 32-byte script hash")
  return M.build_script({
    {opcode = M.OP.OP_0, data = nil},
    make_push(script_hash32),
  })
end

-- P2TR: OP_1 <32 bytes>
function M.make_p2tr_script(xonly_pubkey32)
  assert(#xonly_pubkey32 == 32, "P2TR requires 32-byte x-only pubkey")
  return M.build_script({
    {opcode = M.OP.OP_1, data = nil},
    make_push(xonly_pubkey32),
  })
end

-- Classify a script and extract the hash/data
-- Returns type string ("p2pkh", "p2sh", "p2wpkh", "p2wsh", "p2tr", "nulldata", "nonstandard")
-- and the extracted hash (or nil for nulldata/nonstandard)
function M.classify_script(script)
  local len = #script

  -- P2PKH: 25 bytes: 76 a9 14 <20> 88 ac
  if len == 25 and
     script:byte(1) == 0x76 and
     script:byte(2) == 0xa9 and
     script:byte(3) == 0x14 and
     script:byte(24) == 0x88 and
     script:byte(25) == 0xac then
    return "p2pkh", script:sub(4, 23)
  end

  -- P2SH: 23 bytes: a9 14 <20> 87
  if len == 23 and
     script:byte(1) == 0xa9 and
     script:byte(2) == 0x14 and
     script:byte(23) == 0x87 then
    return "p2sh", script:sub(3, 22)
  end

  -- P2WPKH: 22 bytes: 00 14 <20>
  if len == 22 and
     script:byte(1) == 0x00 and
     script:byte(2) == 0x14 then
    return "p2wpkh", script:sub(3, 22)
  end

  -- P2WSH: 34 bytes: 00 20 <32>
  if len == 34 and
     script:byte(1) == 0x00 and
     script:byte(2) == 0x20 then
    return "p2wsh", script:sub(3, 34)
  end

  -- P2TR: 34 bytes: 51 20 <32>
  if len == 34 and
     script:byte(1) == 0x51 and
     script:byte(2) == 0x20 then
    return "p2tr", script:sub(3, 34)
  end

  -- Nulldata: starts with OP_RETURN (0x6a)
  if len >= 1 and script:byte(1) == 0x6a then
    return "nulldata", nil
  end

  return "nonstandard", nil
end

-- Check if an opcode counts towards the 201 limit (non-push opcodes)
local function is_counted_opcode(opcode)
  return opcode > M.OP.OP_16
end

-- Check if opcode is disabled
local function is_disabled_opcode(opcode)
  return opcode == M.OP.OP_CAT or
         opcode == M.OP.OP_SUBSTR or
         opcode == M.OP.OP_LEFT or
         opcode == M.OP.OP_RIGHT or
         opcode == M.OP.OP_INVERT or
         opcode == M.OP.OP_AND or
         opcode == M.OP.OP_OR or
         opcode == M.OP.OP_XOR or
         opcode == M.OP.OP_2MUL or
         opcode == M.OP.OP_2DIV or
         opcode == M.OP.OP_MUL or
         opcode == M.OP.OP_DIV or
         opcode == M.OP.OP_MOD or
         opcode == M.OP.OP_LSHIFT or
         opcode == M.OP.OP_RSHIFT
end

-- Execute a script
-- stack: initial stack (table of byte strings), defaults to {}
-- flags: table of boolean consensus flags
-- checker: table with check_sig, check_locktime, check_sequence, set_codesep methods
function M.execute_script(script_bytes, stack, flags, checker)
  stack = stack or {}
  flags = flags or {}
  checker = checker or {}

  local altstack = {}
  local if_stack = {}  -- tracks execution state: true = executing, false = not executing
  local op_count = 0
  local codesep_pos = 0xFFFFFFFF  -- BIP143/342: initialize to 0xFFFFFFFF

  -- Helper: check if we're in an executing branch
  local function is_executing()
    for _, v in ipairs(if_stack) do
      if not v then
        return false
      end
    end
    return true
  end

  -- Helper: pop from stack
  local function pop()
    assert(#stack > 0, "stack underflow")
    local val = stack[#stack]
    stack[#stack] = nil
    return val
  end

  -- Helper: peek at top of stack
  local function peek()
    assert(#stack > 0, "stack underflow")
    return stack[#stack]
  end

  -- Helper: push to stack
  local function push(val)
    assert(#stack < MAX_STACK_SIZE + #altstack, "stack overflow")
    assert(#val <= MAX_SCRIPT_ELEMENT_SIZE, "element too large")
    stack[#stack + 1] = val
  end

  -- Helper: pop a number from stack
  local function pop_num(max_len)
    local bytes = pop()
    return M.script_num_decode(bytes, max_len or 4)
  end

  -- Helper: push a number to stack
  local function push_num(n)
    push(M.script_num_encode(n))
  end

  -- Helper: push a boolean to stack
  local function push_bool(b)
    if b then
      push("\x01")
    else
      push("")
    end
  end

  -- Parse the script
  local ops = M.parse_script(script_bytes)

  -- Execute each operation
  local i = 1
  while i <= #ops do
    local op = ops[i]
    local opcode = op.opcode
    local data = op.data

    -- Count non-push opcodes
    if is_counted_opcode(opcode) then
      op_count = op_count + 1
      assert(op_count <= MAX_OPS, "too many opcodes")
    end

    -- OP_VERIF and OP_VERNOTIF always fail (even in non-executing branches)
    if opcode == M.OP.OP_VERIF or opcode == M.OP.OP_VERNOTIF then
      error("OP_VERIF/OP_VERNOTIF are invalid")
    end

    -- Handle IF/ELSE/ENDIF even in non-executing branches
    if opcode == M.OP.OP_IF then
      if is_executing() then
        local val = pop()
        if_stack[#if_stack + 1] = M.cast_to_bool(val)
      else
        if_stack[#if_stack + 1] = false
      end
      i = i + 1
      goto continue
    elseif opcode == M.OP.OP_NOTIF then
      if is_executing() then
        local val = pop()
        if_stack[#if_stack + 1] = not M.cast_to_bool(val)
      else
        if_stack[#if_stack + 1] = false
      end
      i = i + 1
      goto continue
    elseif opcode == M.OP.OP_ELSE then
      assert(#if_stack > 0, "OP_ELSE without OP_IF")
      -- Only flip if we're the inner-most if and parent is executing
      local parent_executing = true
      for j = 1, #if_stack - 1 do
        if not if_stack[j] then
          parent_executing = false
          break
        end
      end
      if parent_executing then
        if_stack[#if_stack] = not if_stack[#if_stack]
      end
      i = i + 1
      goto continue
    elseif opcode == M.OP.OP_ENDIF then
      assert(#if_stack > 0, "OP_ENDIF without OP_IF")
      if_stack[#if_stack] = nil
      i = i + 1
      goto continue
    end

    -- Skip non-executing branches (but OP_RETURN must NOT terminate)
    if not is_executing() then
      i = i + 1
      goto continue
    end

    -- Check for disabled opcodes
    if is_disabled_opcode(opcode) then
      error("disabled opcode: " .. (M.OP_NAMES[opcode] or string.format("0x%02x", opcode)))
    end

    -- Handle push operations
    if opcode == M.OP.OP_0 then
      push("")
    elseif opcode >= 0x01 and opcode <= 0x4e then
      -- All push variants (direct push, PUSHDATA1/2/4)
      push(data)
    elseif opcode == M.OP.OP_1NEGATE then
      push_num(-1)
    elseif opcode >= M.OP.OP_1 and opcode <= M.OP.OP_16 then
      push_num(opcode - M.OP.OP_1 + 1)

    -- Flow control
    elseif opcode == M.OP.OP_NOP then
      -- Do nothing
    elseif opcode == M.OP.OP_RESERVED then
      error("OP_RESERVED")
    elseif opcode == M.OP.OP_VER then
      error("OP_VER")
    elseif opcode == M.OP.OP_VERIFY then
      local val = pop()
      if not M.cast_to_bool(val) then
        error("OP_VERIFY failed")
      end
    elseif opcode == M.OP.OP_RETURN then
      error("OP_RETURN")

    -- Stack operations
    elseif opcode == M.OP.OP_TOALTSTACK then
      altstack[#altstack + 1] = pop()
    elseif opcode == M.OP.OP_FROMALTSTACK then
      assert(#altstack > 0, "altstack underflow")
      push(altstack[#altstack])
      altstack[#altstack] = nil
    elseif opcode == M.OP.OP_2DROP then
      pop()
      pop()
    elseif opcode == M.OP.OP_2DUP then
      assert(#stack >= 2, "stack too small for 2DUP")
      local a = stack[#stack - 1]
      local b = stack[#stack]
      push(a)
      push(b)
    elseif opcode == M.OP.OP_3DUP then
      assert(#stack >= 3, "stack too small for 3DUP")
      local a = stack[#stack - 2]
      local b = stack[#stack - 1]
      local c = stack[#stack]
      push(a)
      push(b)
      push(c)
    elseif opcode == M.OP.OP_2OVER then
      assert(#stack >= 4, "stack too small for 2OVER")
      local a = stack[#stack - 3]
      local b = stack[#stack - 2]
      push(a)
      push(b)
    elseif opcode == M.OP.OP_2ROT then
      assert(#stack >= 6, "stack too small for 2ROT")
      local a = stack[#stack - 5]
      local b = stack[#stack - 4]
      table.remove(stack, #stack - 5)
      table.remove(stack, #stack - 4)
      push(a)
      push(b)
    elseif opcode == M.OP.OP_2SWAP then
      assert(#stack >= 4, "stack too small for 2SWAP")
      local a = stack[#stack - 3]
      local b = stack[#stack - 2]
      local c = stack[#stack - 1]
      local d = stack[#stack]
      stack[#stack - 3] = c
      stack[#stack - 2] = d
      stack[#stack - 1] = a
      stack[#stack] = b
    elseif opcode == M.OP.OP_IFDUP then
      local val = peek()
      if M.cast_to_bool(val) then
        push(val)
      end
    elseif opcode == M.OP.OP_DEPTH then
      push_num(#stack)
    elseif opcode == M.OP.OP_DROP then
      pop()
    elseif opcode == M.OP.OP_DUP then
      push(peek())
    elseif opcode == M.OP.OP_NIP then
      assert(#stack >= 2, "stack too small for NIP")
      local top = pop()
      pop()
      push(top)
    elseif opcode == M.OP.OP_OVER then
      assert(#stack >= 2, "stack too small for OVER")
      push(stack[#stack - 1])
    elseif opcode == M.OP.OP_PICK then
      local n = pop_num()
      assert(n >= 0 and n < #stack, "PICK index out of range")
      push(stack[#stack - n])
    elseif opcode == M.OP.OP_ROLL then
      local n = pop_num()
      assert(n >= 0 and n < #stack, "ROLL index out of range")
      local val = table.remove(stack, #stack - n)
      push(val)
    elseif opcode == M.OP.OP_ROT then
      assert(#stack >= 3, "stack too small for ROT")
      local c = pop()
      local b = pop()
      local a = pop()
      push(b)
      push(c)
      push(a)
    elseif opcode == M.OP.OP_SWAP then
      assert(#stack >= 2, "stack too small for SWAP")
      local a = stack[#stack - 1]
      stack[#stack - 1] = stack[#stack]
      stack[#stack] = a
    elseif opcode == M.OP.OP_TUCK then
      assert(#stack >= 2, "stack too small for TUCK")
      local top = peek()
      table.insert(stack, #stack - 1, top)

    -- Splice operations (SIZE is the only one not disabled)
    elseif opcode == M.OP.OP_SIZE then
      local val = peek()
      push_num(#val)

    -- Bitwise logic
    elseif opcode == M.OP.OP_EQUAL then
      local b = pop()
      local a = pop()
      push_bool(a == b)
    elseif opcode == M.OP.OP_EQUALVERIFY then
      local b = pop()
      local a = pop()
      if a ~= b then
        error("OP_EQUALVERIFY failed")
      end
    elseif opcode == M.OP.OP_RESERVED1 then
      error("OP_RESERVED1")
    elseif opcode == M.OP.OP_RESERVED2 then
      error("OP_RESERVED2")

    -- Arithmetic
    elseif opcode == M.OP.OP_1ADD then
      push_num(pop_num() + 1)
    elseif opcode == M.OP.OP_1SUB then
      push_num(pop_num() - 1)
    elseif opcode == M.OP.OP_NEGATE then
      push_num(-pop_num())
    elseif opcode == M.OP.OP_ABS then
      push_num(math.abs(pop_num()))
    elseif opcode == M.OP.OP_NOT then
      local n = pop_num()
      push_bool(n == 0)
    elseif opcode == M.OP.OP_0NOTEQUAL then
      local n = pop_num()
      push_bool(n ~= 0)
    elseif opcode == M.OP.OP_ADD then
      local b = pop_num()
      local a = pop_num()
      push_num(a + b)
    elseif opcode == M.OP.OP_SUB then
      local b = pop_num()
      local a = pop_num()
      push_num(a - b)
    elseif opcode == M.OP.OP_BOOLAND then
      local b = pop_num()
      local a = pop_num()
      push_bool(a ~= 0 and b ~= 0)
    elseif opcode == M.OP.OP_BOOLOR then
      local b = pop_num()
      local a = pop_num()
      push_bool(a ~= 0 or b ~= 0)
    elseif opcode == M.OP.OP_NUMEQUAL then
      local b = pop_num()
      local a = pop_num()
      push_bool(a == b)
    elseif opcode == M.OP.OP_NUMEQUALVERIFY then
      local b = pop_num()
      local a = pop_num()
      if a ~= b then
        error("OP_NUMEQUALVERIFY failed")
      end
    elseif opcode == M.OP.OP_NUMNOTEQUAL then
      local b = pop_num()
      local a = pop_num()
      push_bool(a ~= b)
    elseif opcode == M.OP.OP_LESSTHAN then
      local b = pop_num()
      local a = pop_num()
      push_bool(a < b)
    elseif opcode == M.OP.OP_GREATERTHAN then
      local b = pop_num()
      local a = pop_num()
      push_bool(a > b)
    elseif opcode == M.OP.OP_LESSTHANOREQUAL then
      local b = pop_num()
      local a = pop_num()
      push_bool(a <= b)
    elseif opcode == M.OP.OP_GREATERTHANOREQUAL then
      local b = pop_num()
      local a = pop_num()
      push_bool(a >= b)
    elseif opcode == M.OP.OP_MIN then
      local b = pop_num()
      local a = pop_num()
      push_num(math.min(a, b))
    elseif opcode == M.OP.OP_MAX then
      local b = pop_num()
      local a = pop_num()
      push_num(math.max(a, b))
    elseif opcode == M.OP.OP_WITHIN then
      local max = pop_num()
      local min = pop_num()
      local x = pop_num()
      push_bool(x >= min and x < max)

    -- Crypto
    elseif opcode == M.OP.OP_RIPEMD160 then
      push(crypto.ripemd160(pop()))
    elseif opcode == M.OP.OP_SHA1 then
      -- SHA1 not commonly used, but included for completeness
      -- Use OpenSSL or a Lua implementation
      error("OP_SHA1 not implemented")
    elseif opcode == M.OP.OP_SHA256 then
      push(crypto.sha256(pop()))
    elseif opcode == M.OP.OP_HASH160 then
      push(crypto.hash160(pop()))
    elseif opcode == M.OP.OP_HASH256 then
      push(crypto.hash256(pop()))
    elseif opcode == M.OP.OP_CODESEPARATOR then
      codesep_pos = i
      if checker.set_codesep then
        checker.set_codesep(codesep_pos)
      end
    elseif opcode == M.OP.OP_CHECKSIG then
      -- Pop pubkey first (top of stack), then signature (deeper)
      local pubkey = pop()
      local sig = pop()
      local valid = false
      if checker.check_sig then
        valid = checker.check_sig(sig, pubkey)
      end
      push_bool(valid)
    elseif opcode == M.OP.OP_CHECKSIGVERIFY then
      local pubkey = pop()
      local sig = pop()
      local valid = false
      if checker.check_sig then
        valid = checker.check_sig(sig, pubkey)
      end
      if not valid then
        error("OP_CHECKSIGVERIFY failed")
      end
    elseif opcode == M.OP.OP_CHECKMULTISIG or opcode == M.OP.OP_CHECKMULTISIGVERIFY then
      -- Pop n pubkeys
      local n = pop_num()
      assert(n >= 0 and n <= 20, "invalid pubkey count")
      op_count = op_count + n
      assert(op_count <= MAX_OPS, "too many opcodes")

      local pubkeys = {}
      for j = 1, n do
        pubkeys[j] = pop()
      end

      -- Pop m signatures
      local m = pop_num()
      assert(m >= 0 and m <= n, "invalid signature count")

      local sigs = {}
      for j = 1, m do
        sigs[j] = pop()
      end

      -- Pop dummy element (off-by-one bug)
      local dummy = pop()
      if flags.verify_nulldummy and #dummy > 0 then
        error("CHECKMULTISIG dummy must be empty with NULLDUMMY flag")
      end

      -- Verify signatures
      -- Signatures must be in order matching pubkeys (can skip pubkeys but not reorder)
      local pk_idx = 1
      local sigs_valid = 0
      for j = 1, m do
        local sig = sigs[j]
        -- Find a matching pubkey
        while pk_idx <= n do
          local pubkey = pubkeys[pk_idx]
          pk_idx = pk_idx + 1
          if checker.check_sig and checker.check_sig(sig, pubkey) then
            sigs_valid = sigs_valid + 1
            break
          end
        end
      end

      local success = (sigs_valid == m)

      if opcode == M.OP.OP_CHECKMULTISIG then
        push_bool(success)
      else
        -- OP_CHECKMULTISIGVERIFY
        if not success then
          error("OP_CHECKMULTISIGVERIFY failed")
        end
      end

    -- Locktime opcodes
    elseif opcode == M.OP.OP_CHECKLOCKTIMEVERIFY then
      if flags.verify_checklocktimeverify then
        assert(#stack > 0, "CHECKLOCKTIMEVERIFY requires stack value")
        local locktime = pop_num(5)  -- Allow 5-byte numbers for locktime
        push(M.script_num_encode(locktime))  -- Don't consume from stack
        assert(locktime >= 0, "negative locktime")
        if checker.check_locktime then
          if not checker.check_locktime(locktime) then
            error("CHECKLOCKTIMEVERIFY failed")
          end
        end
      end
      -- Otherwise treat as NOP
    elseif opcode == M.OP.OP_CHECKSEQUENCEVERIFY then
      if flags.verify_checksequenceverify then
        assert(#stack > 0, "CHECKSEQUENCEVERIFY requires stack value")
        local sequence = pop_num(5)  -- Allow 5-byte numbers
        push(M.script_num_encode(sequence))  -- Don't consume from stack
        -- If the disable flag is set, treat as NOP
        if sequence >= 0 then
          -- Check disable flag (bit 31)
          if sequence < 0x80000000 then
            if checker.check_sequence then
              if not checker.check_sequence(sequence) then
                error("CHECKSEQUENCEVERIFY failed")
              end
            end
          end
        else
          error("negative sequence")
        end
      end
      -- Otherwise treat as NOP

    -- Taproot
    elseif opcode == M.OP.OP_CHECKSIGADD then
      -- BIP342: Pop pubkey, then sig, then n. Push n+1 if valid, else n
      local pubkey = pop()
      local sig = pop()
      local n = pop_num()
      local valid = false
      if checker.check_sig then
        valid = checker.check_sig(sig, pubkey)
      end
      if valid then
        push_num(n + 1)
      else
        -- For empty sig, don't increment and don't fail
        if #sig == 0 then
          push_num(n)
        else
          error("OP_CHECKSIGADD failed with non-empty invalid sig")
        end
      end

    -- Unknown NOPs (0xb0, 0xb3-0xb9): treat as NOP for softfork compatibility
    elseif opcode == M.OP.OP_NOP1 or
           (opcode >= 0xb3 and opcode <= 0xb9) then
      -- Do nothing

    else
      error("unknown opcode: " .. string.format("0x%02x", opcode))
    end

    i = i + 1
    ::continue::
  end

  -- Assert if_stack is empty at end
  assert(#if_stack == 0, "unbalanced IF/ENDIF")

  return stack
end

-- Verify script execution (scriptSig + scriptPubKey)
function M.verify_script(script_sig, script_pubkey, flags, checker)
  flags = flags or {}

  -- Execute scriptSig to get initial stack
  local stack = M.execute_script(script_sig, {}, flags, checker)

  -- Save a copy of the stack for P2SH
  local stack_copy = {}
  for i, v in ipairs(stack) do
    stack_copy[i] = v
  end

  -- Execute scriptPubKey with the resulting stack
  stack = M.execute_script(script_pubkey, stack, flags, checker)

  -- Check result
  if #stack == 0 then
    return false
  end
  if not M.cast_to_bool(stack[#stack]) then
    return false
  end

  -- P2SH handling
  if flags.verify_p2sh then
    local script_type = M.classify_script(script_pubkey)
    if script_type == "p2sh" then
      -- The scriptSig must be push-only for P2SH
      -- (We assume it is, since we're just validating, not checking policy)

      -- The top element of stack_copy is the serialized redeem script
      if #stack_copy == 0 then
        return false
      end
      local redeem_script = stack_copy[#stack_copy]

      -- Remove the redeem script from stack_copy to get remaining items
      table.remove(stack_copy)

      -- Execute the redeem script
      local redeem_stack = M.execute_script(redeem_script, stack_copy, flags, checker)

      if #redeem_stack == 0 then
        return false
      end
      if not M.cast_to_bool(redeem_stack[#redeem_stack]) then
        return false
      end
    end
  end

  return true
end

return M
