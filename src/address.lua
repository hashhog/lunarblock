local crypto = require("lunarblock.crypto")
local bit = require("bit")
local M = {}

-- Base58 alphabet (Bitcoin variant, no 0/O/I/l)
local BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
local BASE58_MAP = {}
for i = 1, #BASE58_ALPHABET do
  BASE58_MAP[BASE58_ALPHABET:byte(i)] = i - 1
end

-- Base58 encode a byte string
function M.base58_encode(data)
  -- Count leading zeros
  local leading_zeros = 0
  for i = 1, #data do
    if data:byte(i) == 0 then
      leading_zeros = leading_zeros + 1
    else
      break
    end
  end

  -- Convert to big integer and repeatedly divide by 58
  -- Work with a table of bytes for arbitrary precision
  local bytes = {}
  for i = 1, #data do bytes[i] = data:byte(i) end

  local result = {}
  while #bytes > 0 do
    local remainder = 0
    local new_bytes = {}
    for _, b in ipairs(bytes) do
      local val = remainder * 256 + b
      local div = math.floor(val / 58)
      remainder = val % 58
      if #new_bytes > 0 or div > 0 then
        new_bytes[#new_bytes + 1] = div
      end
    end
    result[#result + 1] = BASE58_ALPHABET:sub(remainder + 1, remainder + 1)
    bytes = new_bytes
  end

  -- Add leading '1's for leading zero bytes
  for _ = 1, leading_zeros do
    result[#result + 1] = "1"
  end

  -- Reverse the result
  local reversed = {}
  for i = #result, 1, -1 do
    reversed[#reversed + 1] = result[i]
  end
  return table.concat(reversed)
end

-- Base58 decode to byte string
function M.base58_decode(str)
  -- Count leading '1's
  local leading_ones = 0
  for i = 1, #str do
    if str:sub(i, i) == "1" then
      leading_ones = leading_ones + 1
    else
      break
    end
  end

  -- Convert from base58 to big integer (table of bytes)
  local bytes = {0}
  for i = 1, #str do
    local c = str:byte(i)
    local val = BASE58_MAP[c]
    assert(val ~= nil, "Invalid Base58 character: " .. str:sub(i, i))

    local carry = val
    for j = #bytes, 1, -1 do
      carry = carry + bytes[j] * 58
      bytes[j] = carry % 256
      carry = math.floor(carry / 256)
    end
    while carry > 0 do
      table.insert(bytes, 1, carry % 256)
      carry = math.floor(carry / 256)
    end
  end

  -- Remove leading zeros from conversion and add back leading_ones
  while #bytes > 0 and bytes[1] == 0 do
    table.remove(bytes, 1)
  end

  local result = {}
  for _ = 1, leading_ones do
    result[#result + 1] = string.char(0)
  end
  for _, b in ipairs(bytes) do
    result[#result + 1] = string.char(b)
  end
  return table.concat(result)
end

-- Base58Check encode: data with version byte prefix and 4-byte checksum suffix
function M.base58check_encode(version_byte, payload)
  local data = string.char(version_byte) .. payload
  local checksum = crypto.hash256(data):sub(1, 4)
  return M.base58_encode(data .. checksum)
end

-- Base58Check decode: returns version_byte, payload (or nil, error)
function M.base58check_decode(address)
  local decoded = M.base58_decode(address)
  if #decoded < 5 then
    return nil, "Base58Check data too short"
  end

  local payload_with_version = decoded:sub(1, -5)
  local checksum = decoded:sub(-4)
  local expected_checksum = crypto.hash256(payload_with_version):sub(1, 4)

  if checksum ~= expected_checksum then
    return nil, "Base58Check checksum mismatch"
  end

  local version = payload_with_version:byte(1)
  local payload = payload_with_version:sub(2)
  return version, payload
end

-- Bech32 character set
local BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
local BECH32_MAP = {}
for i = 1, #BECH32_CHARSET do
  BECH32_MAP[BECH32_CHARSET:byte(i)] = i - 1
end

-- Bech32 constants
local BECH32_CONST = 1       -- for Bech32 (witness v0)
local BECH32M_CONST = 0x2bc830a3  -- for Bech32m (witness v1+)

-- Bech32 polymod
local function bech32_polymod(values)
  local GEN = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
  local chk = 1
  for _, v in ipairs(values) do
    local b = math.floor(chk / 33554432)  -- chk >> 25
    chk = bit.bxor(bit.lshift(bit.band(chk, 0x1FFFFFF), 5), v)
    for i = 1, 5 do
      if bit.band(bit.rshift(b, i - 1), 1) == 1 then
        chk = bit.bxor(chk, GEN[i])
      end
    end
  end
  return chk
end

-- Expand HRP for checksum computation
local function bech32_hrp_expand(hrp)
  local values = {}
  for i = 1, #hrp do
    values[#values + 1] = bit.rshift(hrp:byte(i), 5)
  end
  values[#values + 1] = 0
  for i = 1, #hrp do
    values[#values + 1] = bit.band(hrp:byte(i), 31)
  end
  return values
end

-- Create Bech32 checksum
local function bech32_create_checksum(hrp, data, spec)
  local const = (spec == "bech32m") and BECH32M_CONST or BECH32_CONST
  local values = bech32_hrp_expand(hrp)
  for _, v in ipairs(data) do values[#values + 1] = v end
  for _ = 1, 6 do values[#values + 1] = 0 end
  local polymod = bit.bxor(bech32_polymod(values), const)
  local checksum = {}
  for i = 0, 5 do
    checksum[i + 1] = bit.band(bit.rshift(polymod, 5 * (5 - i)), 31)
  end
  return checksum
end

-- Verify Bech32 checksum
local function bech32_verify_checksum(hrp, data, spec)
  local const = (spec == "bech32m") and BECH32M_CONST or BECH32_CONST
  local values = bech32_hrp_expand(hrp)
  for _, v in ipairs(data) do values[#values + 1] = v end
  return bech32_polymod(values) == const
end

-- Bech32 encode
function M.bech32_encode(hrp, data, spec)
  spec = spec or "bech32"
  local checksum = bech32_create_checksum(hrp, data, spec)
  local result = hrp .. "1"
  for _, v in ipairs(data) do
    result = result .. BECH32_CHARSET:sub(v + 1, v + 1)
  end
  for _, v in ipairs(checksum) do
    result = result .. BECH32_CHARSET:sub(v + 1, v + 1)
  end
  return result
end

-- Bech32 decode: returns hrp, data (5-bit values), spec (or nil, nil, nil, error)
function M.bech32_decode(str)
  str = str:lower()
  local sep_pos = 0
  for i = #str, 1, -1 do
    if str:sub(i, i) == "1" then
      sep_pos = i
      break
    end
  end
  if sep_pos < 1 then
    return nil, nil, nil, "No separator found"
  end
  if #str - sep_pos < 6 then
    return nil, nil, nil, "Invalid bech32 length"
  end

  local hrp = str:sub(1, sep_pos - 1)
  local data = {}
  for i = sep_pos + 1, #str do
    local c = str:byte(i)
    local val = BECH32_MAP[c]
    if val == nil then
      return nil, nil, nil, "Invalid bech32 character"
    end
    data[#data + 1] = val
  end

  -- Try bech32 first, then bech32m
  local spec
  if bech32_verify_checksum(hrp, data, "bech32") then
    spec = "bech32"
  elseif bech32_verify_checksum(hrp, data, "bech32m") then
    spec = "bech32m"
  else
    return nil, nil, nil, "Invalid checksum"
  end

  -- Remove checksum (last 6 values)
  local payload = {}
  for i = 1, #data - 6 do
    payload[i] = data[i]
  end
  return hrp, payload, spec
end

-- Convert between 5-bit and 8-bit groups
function M.convert_bits(data, from_bits, to_bits, pad)
  if pad == nil then pad = true end
  local acc = 0
  local bits = 0
  local result = {}
  local maxv = bit.lshift(1, to_bits) - 1

  for _, v in ipairs(data) do
    assert(v >= 0 and v < bit.lshift(1, from_bits), "Invalid value for convert_bits")
    acc = bit.bor(bit.lshift(acc, from_bits), v)
    bits = bits + from_bits
    while bits >= to_bits do
      bits = bits - to_bits
      result[#result + 1] = bit.band(bit.rshift(acc, bits), maxv)
    end
  end

  if pad then
    if bits > 0 then
      result[#result + 1] = bit.band(bit.lshift(acc, to_bits - bits), maxv)
    end
  else
    if bits >= from_bits then
      return nil, "Invalid padding"
    end
    if bit.band(bit.lshift(acc, to_bits - bits), maxv) ~= 0 then
      return nil, "Non-zero padding"
    end
  end

  return result
end

-- Encode a SegWit address
function M.segwit_encode(hrp, witness_version, witness_program)
  local program_bytes = {}
  for i = 1, #witness_program do
    program_bytes[i] = witness_program:byte(i)
  end
  local conv = M.convert_bits(program_bytes, 8, 5, true)
  local data = {witness_version}
  for _, v in ipairs(conv) do
    data[#data + 1] = v
  end
  local spec = (witness_version == 0) and "bech32" or "bech32m"
  return M.bech32_encode(hrp, data, spec)
end

-- Decode a SegWit address: returns witness_version, witness_program (or nil, error)
function M.segwit_decode(hrp, addr)
  local decoded_hrp, data, spec = M.bech32_decode(addr)
  if not decoded_hrp then return nil, nil, "Invalid bech32" end
  if decoded_hrp ~= hrp then return nil, nil, "HRP mismatch" end
  if #data < 1 then return nil, nil, "Empty data" end

  local witness_version = data[1]
  if witness_version > 16 then return nil, nil, "Invalid witness version" end

  -- Check bech32 vs bech32m
  if witness_version == 0 and spec ~= "bech32" then
    return nil, nil, "Witness v0 must use bech32"
  end
  if witness_version ~= 0 and spec ~= "bech32m" then
    return nil, nil, "Witness v1+ must use bech32m"
  end

  local payload = {}
  for i = 2, #data do payload[#payload + 1] = data[i] end
  local program = M.convert_bits(payload, 5, 8, false)
  if not program then return nil, nil, "Invalid program" end

  -- Validate program length
  if #program < 2 or #program > 40 then
    return nil, nil, "Invalid program length"
  end
  if witness_version == 0 and #program ~= 20 and #program ~= 32 then
    return nil, nil, "Invalid v0 program length"
  end

  local program_str = {}
  for _, b in ipairs(program) do
    program_str[#program_str + 1] = string.char(b)
  end
  return witness_version, table.concat(program_str)
end

-- Address version bytes
M.VERSION = {
  MAINNET_P2PKH = 0x00,   -- '1' prefix
  MAINNET_P2SH  = 0x05,   -- '3' prefix
  TESTNET_P2PKH = 0x6F,   -- 'm' or 'n' prefix
  TESTNET_P2SH  = 0xC4,   -- '2' prefix
}

M.BECH32_HRP = {
  mainnet = "bc",
  testnet = "tb",
  regtest = "bcrt",
}

-- High-level: public key to P2PKH address
function M.pubkey_to_p2pkh(pubkey_bytes, network)
  network = network or "mainnet"
  local h = crypto.hash160(pubkey_bytes)
  local version = (network == "mainnet") and M.VERSION.MAINNET_P2PKH or M.VERSION.TESTNET_P2PKH
  return M.base58check_encode(version, h)
end

-- High-level: public key to P2WPKH (native SegWit) address
function M.pubkey_to_p2wpkh(pubkey_bytes, network)
  network = network or "mainnet"
  local h = crypto.hash160(pubkey_bytes)
  local hrp = M.BECH32_HRP[network] or "bc"
  return M.segwit_encode(hrp, 0, h)
end

-- High-level: script hash to P2SH address
function M.script_to_p2sh(script_bytes, network)
  network = network or "mainnet"
  local h = crypto.hash160(script_bytes)
  local version = (network == "mainnet") and M.VERSION.MAINNET_P2SH or M.VERSION.TESTNET_P2SH
  return M.base58check_encode(version, h)
end

-- High-level: witness script hash to P2WSH address
function M.script_to_p2wsh(script_bytes, network)
  network = network or "mainnet"
  local h = crypto.sha256(script_bytes)
  local hrp = M.BECH32_HRP[network] or "bc"
  return M.segwit_encode(hrp, 0, h)
end

-- High-level: x-only pubkey to P2TR (Taproot) address
function M.xonly_pubkey_to_p2tr(xonly_pubkey32, network)
  network = network or "mainnet"
  local hrp = M.BECH32_HRP[network] or "bc"
  return M.segwit_encode(hrp, 1, xonly_pubkey32)
end

-- Decode any address and return its type and hash/program
function M.decode_address(address, network)
  network = network or "mainnet"
  local hrp = M.BECH32_HRP[network] or "bc"

  -- Try SegWit first
  local witness_version, witness_program = M.segwit_decode(hrp, address)
  if witness_version then
    if witness_version == 0 and #witness_program == 20 then
      return "p2wpkh", witness_program
    elseif witness_version == 0 and #witness_program == 32 then
      return "p2wsh", witness_program
    elseif witness_version == 1 and #witness_program == 32 then
      return "p2tr", witness_program
    else
      return "witness_unknown", witness_program, witness_version
    end
  end

  -- Try Base58Check
  local version, payload = M.base58check_decode(address)
  if version then
    if version == M.VERSION.MAINNET_P2PKH or version == M.VERSION.TESTNET_P2PKH then
      return "p2pkh", payload
    elseif version == M.VERSION.MAINNET_P2SH or version == M.VERSION.TESTNET_P2SH then
      return "p2sh", payload
    end
  end

  return nil, "Unknown address format"
end

return M
