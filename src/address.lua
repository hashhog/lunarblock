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
-- BIP-173/350 character limit (Core bech32.h:38-40 CharLimit::BECH32 = 90):
-- beyond 89 chars the BCH code's 4-error-detection guarantee no longer holds,
-- so over-long strings are rejected in Decode regardless of checksum
-- (Core bech32.cpp:378 `if (str.size() > limit) return {};`).
local BECH32_MAX_LENGTH = 90

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
  -- BIP-173/350 90-char CharLimit (Core bech32.cpp:378): reject over-long
  -- strings regardless of checksum — past 89 chars the 4-error-detection
  -- guarantee fails. Checked before checksum work, like Core's Decode.
  if #str > BECH32_MAX_LENGTH then
    return nil, nil, nil, "Bech32 string too long"
  end
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

-- Decode any address and return its type and hash/program.
--
-- Per Bitcoin Core's CBitcoinAddress::IsValid / DecodeDestination
-- (src/key_io.cpp), the Base58 version byte MUST match the requested
-- network's PUBKEY_ADDRESS / SCRIPT_ADDRESS prefix.  An older revision
-- of this function accepted EITHER network's prefix regardless of
-- `network`, which silently let mainnet '1...' addresses parse on a
-- testnet wallet (and vice versa) — a cross-network payment hazard.
-- FIX-63 (2026-05-15): strict per-network prefix check, matching the
-- bech32 HRP check already enforced by segwit_decode below.
--
-- Bech32 addresses are already constrained correctly: segwit_decode
-- compares the decoded HRP against the network-derived `hrp` and
-- rejects mismatches (e.g. 'tb1...' on mainnet → HRP mismatch).
function M.decode_address(address, network)
  network = network or "mainnet"
  local hrp = M.BECH32_HRP[network] or "bc"

  -- Per-network Base58 prefix sets.  testnet/regtest/signet share
  -- prefixes — Core does the same: testnet4, signet, and regtest all
  -- use base58Prefixes = {0x6F, 0xC4} for PUBKEY_ADDRESS / SCRIPT_ADDRESS.
  local p2pkh_byte, p2sh_byte
  if network == "mainnet" then
    p2pkh_byte = M.VERSION.MAINNET_P2PKH
    p2sh_byte  = M.VERSION.MAINNET_P2SH
  else
    -- testnet | regtest | signet (and anything else falls through to
    -- the testnet prefix set, mirroring how M.BECH32_HRP defaults).
    p2pkh_byte = M.VERSION.TESTNET_P2PKH
    p2sh_byte  = M.VERSION.TESTNET_P2SH
  end

  -- Try SegWit first (HRP-checked by segwit_decode against `hrp`).
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

  -- If the input looks like a bech32 address for a DIFFERENT known
  -- network (e.g. 'tb1...' decoded on mainnet), the segwit_decode call
  -- above returned nil and we must NOT fall through to base58check_decode
  -- — base58_decode asserts on the '0' character which is legal in
  -- bech32 but not in Base58.  Probe the other HRPs explicitly so we
  -- can return "wrong-network" cleanly.
  local lower_addr = address:lower()
  for net, candidate_hrp in pairs(M.BECH32_HRP) do
    if net ~= network then
      local prefix = candidate_hrp .. "1"
      if lower_addr:sub(1, #prefix) == prefix then
        local wv = M.segwit_decode(candidate_hrp, address)
        if wv then
          return nil, "wrong-network address"
        end
      end
    end
  end

  -- Try Base58Check, then strictly check the version byte against the
  -- requested network's prefixes.
  local version, payload = M.base58check_decode(address)
  if version then
    if version == p2pkh_byte then
      return "p2pkh", payload
    elseif version == p2sh_byte then
      return "p2sh", payload
    end
    -- Version byte was recognised as a Bitcoin address prefix but
    -- belongs to the wrong network.  This is the FIX-63 hazard.
    if version == M.VERSION.MAINNET_P2PKH or version == M.VERSION.MAINNET_P2SH
        or version == M.VERSION.TESTNET_P2PKH or version == M.VERSION.TESTNET_P2SH then
      return nil, "wrong-network address"
    end
  end

  return nil, "Unknown address format"
end

--------------------------------------------------------------------------------
-- Output Descriptors (BIP380-386)
--------------------------------------------------------------------------------

-- Descriptor checksum character set (same as Bech32)
local DESC_CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

-- Input character set for descriptor checksum (from BIP380)
local DESC_INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "

-- Build reverse lookup for input charset
local DESC_INPUT_MAP = {}
for i = 1, #DESC_INPUT_CHARSET do
  DESC_INPUT_MAP[DESC_INPUT_CHARSET:byte(i)] = i - 1
end

-- 40-bit XOR helper.  LuaJIT's bit library is 32-bit only (wraps at 2^32),
-- so we cannot use bit.bxor directly on the BCH generator polynomials
-- (0xf5dee51989 etc.) that BIP-380 uses — they are 40-bit constants.
-- We split each operand into a high byte (bits 32-39) and a low dword
-- (bits 0-31), XOR the halves separately with the 32-bit-safe bit.bxor,
-- and recombine.  All intermediate values are ≤ 2^40 so they fit in a
-- 64-bit double without precision loss.
-- W51 fix: bit.bxor was silently truncating to 32 bits, producing wrong
-- BIP-380 descriptor checksums (e.g. #3pfrsrvg instead of #234qj6rv).
local function xor40(a, b)
  local a_lo = a % 0x100000000   -- bits 0-31
  local a_hi = math.floor(a / 0x100000000)  -- bits 32-39 (0-255)
  local b_lo = b % 0x100000000
  local b_hi = math.floor(b / 0x100000000)
  local lo = bit.bxor(a_lo, b_lo)
  if lo < 0 then lo = lo + 0x100000000 end  -- unsigned
  local hi = bit.bxor(a_hi, b_hi)
  if hi < 0 then hi = hi + 256 end
  return hi * 0x100000000 + lo
end

-- PolyMod for descriptor checksum (BCH code over GF(32)).
-- Uses xor40 instead of bit.bxor to avoid 32-bit truncation.
local function desc_polymod(c, val)
  local c0 = math.floor(c / 0x800000000)  -- c >> 35
  c = ((c % 0x800000000) * 32 + val) % 0x10000000000  -- ((c & 0x7ffffffff) << 5) + val

  if c0 % 2  >= 1  then c = xor40(c, 0xf5dee51989) end
  if c0 % 4  >= 2  then c = xor40(c, 0xa9fdca3312) end
  if c0 % 8  >= 4  then c = xor40(c, 0x1bab10e32d) end
  if c0 % 16 >= 8  then c = xor40(c, 0x3706b1677a) end
  if c0 % 32 >= 16 then c = xor40(c, 0x644d626ffd) end

  return c
end

-- Compute descriptor checksum
function M.descriptor_checksum(desc)
  local c = 1
  local cls = 0
  local clscount = 0

  for i = 1, #desc do
    local ch = desc:byte(i)
    local pos = DESC_INPUT_MAP[ch]
    if pos == nil then
      return nil, "invalid character in descriptor"
    end
    -- PolyMod with lower 5 bits (pos ≤ 94, so bit.band(pos,31) is safe)
    c = desc_polymod(c, bit.band(pos, 31))
    -- Accumulate class (upper bits)
    cls = cls * 3 + math.floor(pos / 32)
    clscount = clscount + 1
    if clscount == 3 then
      c = desc_polymod(c, cls)
      cls = 0
      clscount = 0
    end
  end

  -- Process remaining class accumulator
  if clscount > 0 then
    c = desc_polymod(c, cls)
  end

  -- Apply 8 additional rounds with zeros
  for _ = 1, 8 do
    c = desc_polymod(c, 0)
  end

  -- XOR with 1 (prevents appending zeros from being undetectable).
  -- c ≤ 2^40, so xor40 needed here too for correctness (though XOR with 1
  -- only affects bit 0, bit.bxor would coincidentally work here; use xor40
  -- for consistency).
  c = xor40(c, 1)

  -- Extract 8 groups of 5 bits from the 40-bit result.  bit.rshift is
  -- 32-bit only, so use arithmetic shifts instead.
  local checksum = {}
  for i = 0, 7 do
    local shift = 5 * (7 - i)
    local v = math.floor(c / (2 ^ shift)) % 32
    checksum[i + 1] = DESC_CHECKSUM_CHARSET:sub(v + 1, v + 1)
  end

  return table.concat(checksum)
end

-- Validate descriptor checksum
function M.validate_descriptor_checksum(desc_with_checksum)
  local sep = desc_with_checksum:find("#")
  if not sep then
    return false, "no checksum found"
  end

  local desc = desc_with_checksum:sub(1, sep - 1)
  local checksum = desc_with_checksum:sub(sep + 1)

  if #checksum ~= 8 then
    return false, "invalid checksum length"
  end

  local expected = M.descriptor_checksum(desc)
  if not expected then
    return false, "invalid descriptor"
  end

  return checksum == expected, desc
end

-- Parse a hex string to bytes
local function hex_decode(hex)
  local bytes = {}
  for i = 1, #hex, 2 do
    bytes[#bytes + 1] = string.char(tonumber(hex:sub(i, i + 1), 16))
  end
  return table.concat(bytes)
end

-- Encode bytes to hex string
local function hex_encode(data)
  local hex = {}
  for i = 1, #data do
    hex[i] = string.format("%02x", data:byte(i))
  end
  return table.concat(hex)
end

-- Parse a key expression (pubkey, WIF, xpub, xprv)
-- Returns: {type, data, derivation_path, is_range, is_hardened_range}
function M.parse_key_expression(key_str, network)
  network = network or "mainnet"
  local result = {
    type = nil,
    pubkey = nil,
    privkey = nil,
    xpub = nil,
    xprv = nil,
    path = {},
    origin = nil,
    is_range = false,
    is_hardened_range = false,
  }

  local key_part = key_str
  local path_part = nil

  -- Check for origin [fingerprint/path]
  if key_str:sub(1, 1) == "[" then
    local close = key_str:find("]")
    if not close then
      return nil, "unclosed origin bracket"
    end
    local origin_str = key_str:sub(2, close - 1)
    key_part = key_str:sub(close + 1)

    -- Parse origin: fingerprint/path
    local fingerprint, path_str = origin_str:match("^([0-9a-fA-F]+)/?(.*)$")
    if not fingerprint or #fingerprint ~= 8 then
      return nil, "invalid origin fingerprint"
    end

    result.origin = {
      fingerprint = hex_decode(fingerprint),
      path = {},
    }

    -- Parse origin path
    if path_str and #path_str > 0 then
      for step in path_str:gmatch("[^/]+") do
        local num, hardened = step:match("^(%d+)([h']?)$")
        if not num then
          return nil, "invalid origin path element: " .. step
        end
        local index = tonumber(num)
        if hardened and #hardened > 0 then
          index = index + 0x80000000
        end
        result.origin.path[#result.origin.path + 1] = index
      end
    end
  end

  -- Check for derivation path after key
  local slash_pos = key_part:find("/")
  if slash_pos then
    path_part = key_part:sub(slash_pos + 1)
    key_part = key_part:sub(1, slash_pos - 1)
  end

  -- Parse derivation path
  if path_part then
    for step in path_part:gmatch("[^/]+") do
      if step == "*" then
        result.is_range = true
        result.path[#result.path + 1] = "*"
      elseif step == "*'" or step == "*h" then
        result.is_range = true
        result.is_hardened_range = true
        result.path[#result.path + 1] = "*'"
      else
        local num, hardened = step:match("^(%d+)([h']?)$")
        if not num then
          return nil, "invalid path element: " .. step
        end
        local index = tonumber(num)
        if hardened and #hardened > 0 then
          index = index + 0x80000000
        end
        result.path[#result.path + 1] = index
      end
    end
  end

  -- Check key type
  -- Hex pubkey (33 bytes compressed or 65 bytes uncompressed)
  if key_part:match("^[0-9a-fA-F]+$") then
    local hex_len = #key_part
    if hex_len == 66 then  -- 33 bytes = compressed pubkey
      result.type = "pubkey"
      result.pubkey = hex_decode(key_part)
      return result
    elseif hex_len == 130 then  -- 65 bytes = uncompressed pubkey
      result.type = "pubkey"
      result.pubkey = hex_decode(key_part)
      return result
    elseif hex_len == 64 then  -- 32 bytes = x-only pubkey (Taproot)
      result.type = "xonly"
      result.pubkey = hex_decode(key_part)
      return result
    else
      return nil, "invalid hex key length"
    end
  end

  -- Try WIF decode
  local wif_ok, wif_version, wif_payload = pcall(function()
    return M.base58check_decode(key_part)
  end)
  if wif_ok and wif_version then
    local expected_version = (network == "mainnet") and 0x80 or 0xEF
    if wif_version == expected_version then
      -- WIF private key
      local privkey
      local compressed = false
      if #wif_payload == 33 and wif_payload:byte(33) == 0x01 then
        privkey = wif_payload:sub(1, 32)
        compressed = true
      elseif #wif_payload == 32 then
        privkey = wif_payload
        compressed = false
      else
        return nil, "invalid WIF payload length"
      end

      result.type = "wif"
      result.privkey = privkey
      result.compressed = compressed

      -- Derive public key (need crypto module)
      local crypto = require("lunarblock.crypto")
      result.pubkey = crypto.pubkey_from_privkey(privkey, compressed)

      return result
    end
  end

  -- Try xpub/xprv decode
  local xkey_ok, xkey_version, xkey_payload = pcall(function()
    return M.base58check_decode(key_part)
  end)
  if xkey_ok and xkey_version and #xkey_payload == 77 then
    -- BIP32 extended key: version(4) + depth(1) + fingerprint(4) + child(4) + chaincode(32) + key(33)
    local full = string.char(xkey_version) .. xkey_payload
    local version_bytes = full:sub(1, 4)

    -- Decode version
    local version_num = version_bytes:byte(1) * 16777216 + version_bytes:byte(2) * 65536 +
                        version_bytes:byte(3) * 256 + version_bytes:byte(4)

    local xpub_versions = {0x0488B21E, 0x043587CF}  -- mainnet, testnet
    local xprv_versions = {0x0488ADE4, 0x04358394}  -- mainnet, testnet

    local is_xpub = false
    local is_xprv = false
    for _, v in ipairs(xpub_versions) do
      if version_num == v then is_xpub = true break end
    end
    for _, v in ipairs(xprv_versions) do
      if version_num == v then is_xprv = true break end
    end

    if is_xpub then
      result.type = "xpub"
      result.xpub = full
      result.depth = full:byte(5)
      result.fingerprint = full:sub(6, 9)
      result.child_number = full:byte(10) * 16777216 + full:byte(11) * 65536 +
                            full:byte(12) * 256 + full:byte(13)
      result.chaincode = full:sub(14, 45)
      result.pubkey = full:sub(46, 78)
      return result
    elseif is_xprv then
      result.type = "xprv"
      result.xprv = full
      result.depth = full:byte(5)
      result.fingerprint = full:sub(6, 9)
      result.child_number = full:byte(10) * 16777216 + full:byte(11) * 65536 +
                            full:byte(12) * 256 + full:byte(13)
      result.chaincode = full:sub(14, 45)
      -- Private key is prefixed with 0x00
      if full:byte(46) ~= 0 then
        return nil, "invalid xprv key prefix"
      end
      result.privkey = full:sub(47, 78)
      -- Derive public key
      local crypto = require("lunarblock.crypto")
      result.pubkey = crypto.pubkey_from_privkey(result.privkey, true)
      return result
    end
  end

  return nil, "unrecognized key format: " .. key_part
end

-- BIP-32 child key derivation (CKDpriv + CKDpub).
--
-- Per BIP-32 §"Private parent key -> private child key" and
-- §"Public parent key -> public child key":
--
--   if hardened (i >= 2^31):
--     I = HMAC-SHA512(c_par, 0x00 || ser256(k_par) || ser32(i))
--   else:
--     I = HMAC-SHA512(c_par, ser_P(K_par) || ser32(i))
--   IL = I[0:32]; IR = I[32:64]
--   CKDpriv: k_i = (parse256(IL) + k_par) mod n
--   CKDpub:  K_i = parse256(IL) * G + K_par
--   c_i = IR
--
-- If parse256(IL) >= n OR the resulting key/point is invalid (k_i == 0
-- or K_i == point at infinity), the derivation is "invalid" and the
-- caller MUST advance to the next index. libsecp256k1's
-- ec_seckey_tweak_add / ec_pubkey_tweak_add already return 0 on these
-- conditions; we surface that as an error so the caller can retry.
--
-- Reference: bitcoin-core/src/key.cpp::CKey::Derive (priv) and
-- src/pubkey.cpp::CPubKey::Derive (pub).
function M.derive_child(parent_pubkey, parent_chaincode, child_index, parent_privkey)
  local crypto = require("lunarblock.crypto")
  local is_hardened = child_index >= 0x80000000

  local index_bytes = string.char(
    bit.band(bit.rshift(child_index, 24), 0xFF),
    bit.band(bit.rshift(child_index, 16), 0xFF),
    bit.band(bit.rshift(child_index, 8), 0xFF),
    bit.band(child_index, 0xFF)
  )

  local data
  if is_hardened then
    if not parent_privkey then
      return nil, nil, "hardened derivation requires private key"
    end
    -- Hardened: HMAC-SHA512(chaincode, 0x00 || privkey || index)
    data = "\x00" .. parent_privkey .. index_bytes
  else
    -- Normal: HMAC-SHA512(chaincode, ser_P(K_par) || index)
    -- ser_P expects the compressed 33-byte serialization. If the caller
    -- only has a private key, derive the matching compressed pubkey first.
    local pub_for_hmac = parent_pubkey
    if (not pub_for_hmac) and parent_privkey then
      pub_for_hmac = crypto.pubkey_from_privkey(parent_privkey, true)
    end
    if not pub_for_hmac then
      return nil, nil, "normal derivation requires parent pubkey or privkey"
    end
    data = pub_for_hmac .. index_bytes
  end

  local I = crypto.hmac_sha512(parent_chaincode, data)
  local IL = I:sub(1, 32)
  local IR = I:sub(33, 64)

  if parent_privkey then
    -- CKDpriv: child_priv = (parse256(IL) + parent_priv) mod n.
    -- libsecp256k1 enforces parse256(IL) < n and child_priv != 0; it
    -- returns 0 (signalling "invalid derivation") otherwise. Caller
    -- should advance to (child_index + 1) on this error per BIP-32.
    local child_privkey, err = crypto.ec_seckey_tweak_add(parent_privkey, IL)
    if not child_privkey then
      return nil, nil, err or "invalid CKDpriv derivation"
    end
    local child_pubkey = crypto.pubkey_from_privkey(child_privkey, true)
    return child_pubkey, IR, nil, child_privkey
  else
    -- CKDpub: child_pub = parent_pub + parse256(IL)*G  (non-hardened only;
    -- the is_hardened branch above already errored if privkey is nil).
    local child_pubkey, err = crypto.ec_pubkey_tweak_add(parent_pubkey, IL, true)
    if not child_pubkey then
      return nil, nil, err or "invalid CKDpub derivation"
    end
    return child_pubkey, IR, nil, nil
  end
end

-- Derive a key at a specific path
function M.derive_path(key_info, path, index)
  if key_info.type ~= "xpub" and key_info.type ~= "xprv" then
    -- For raw pubkeys, just return as-is
    return key_info.pubkey
  end

  local pubkey = key_info.pubkey
  local chaincode = key_info.chaincode
  local privkey = key_info.privkey

  for _, step in ipairs(path) do
    local child_index = step
    if step == "*" then
      child_index = index
    elseif step == "*'" then
      child_index = index + 0x80000000
    end

    local new_pubkey, new_chaincode, err, new_privkey = M.derive_child(
      pubkey, chaincode, child_index, privkey
    )
    if err then
      return nil, err
    end
    pubkey = new_pubkey
    chaincode = new_chaincode
    privkey = new_privkey
  end

  return pubkey
end

-- Descriptor types
M.DESCRIPTOR_TYPES = {
  "pk", "pkh", "wpkh", "sh", "wsh", "multi", "sortedmulti",
  "tr", "addr", "raw", "combo"
}

-- Parse a descriptor string
function M.parse_descriptor(desc_str)
  local desc = desc_str
  local checksum = nil

  -- Strip checksum if present
  local hash_pos = desc:find("#")
  if hash_pos then
    checksum = desc:sub(hash_pos + 1)
    desc = desc:sub(1, hash_pos - 1)

    -- Validate checksum
    local expected = M.descriptor_checksum(desc)
    if checksum ~= expected then
      return nil, "invalid checksum"
    end
  end

  -- Parse descriptor type
  local desc_type, inner = desc:match("^(%w+)%((.+)%)$")
  if not desc_type then
    return nil, "invalid descriptor format"
  end

  local result = {
    type = desc_type,
    checksum = checksum,
    raw = desc,
  }

  -- Handle different descriptor types
  if desc_type == "pk" then
    -- pk(KEY)
    local key, err = M.parse_key_expression(inner)
    if not key then return nil, err end
    result.key = key
    result.is_range = key.is_range

  elseif desc_type == "pkh" then
    -- pkh(KEY)
    local key, err = M.parse_key_expression(inner)
    if not key then return nil, err end
    result.key = key
    result.is_range = key.is_range

  elseif desc_type == "wpkh" then
    -- wpkh(KEY)
    local key, err = M.parse_key_expression(inner)
    if not key then return nil, err end
    result.key = key
    result.is_range = key.is_range

  elseif desc_type == "sh" then
    -- sh(SCRIPT)
    local inner_desc, err = M.parse_descriptor(inner .. ")") -- Re-add closing paren
    if not inner_desc then
      -- Try parsing as raw script descriptor
      inner_desc, err = M.parse_descriptor(inner)
    end
    if not inner_desc then return nil, "invalid sh inner: " .. (err or "unknown") end
    result.inner = inner_desc
    result.is_range = inner_desc.is_range

  elseif desc_type == "wsh" then
    -- wsh(SCRIPT)
    local inner_desc, err = M.parse_descriptor(inner)
    if not inner_desc then return nil, "invalid wsh inner: " .. (err or "unknown") end
    result.inner = inner_desc
    result.is_range = inner_desc.is_range

  elseif desc_type == "multi" or desc_type == "sortedmulti" then
    -- multi(k,KEY,KEY,...) or sortedmulti(k,KEY,KEY,...)
    local threshold, keys_str = inner:match("^(%d+),(.+)$")
    if not threshold then
      return nil, "invalid multi format"
    end
    result.threshold = tonumber(threshold)
    result.sorted = (desc_type == "sortedmulti")
    result.keys = {}
    result.is_range = false

    -- Parse keys (comma-separated, but need to handle nested brackets)
    local depth = 0
    local current = ""
    for i = 1, #keys_str do
      local ch = keys_str:sub(i, i)
      if ch == "[" or ch == "(" then
        depth = depth + 1
        current = current .. ch
      elseif ch == "]" or ch == ")" then
        depth = depth - 1
        current = current .. ch
      elseif ch == "," and depth == 0 then
        local key, err = M.parse_key_expression(current)
        if not key then return nil, "invalid key in multi: " .. (err or current) end
        result.keys[#result.keys + 1] = key
        if key.is_range then result.is_range = true end
        current = ""
      else
        current = current .. ch
      end
    end
    -- Don't forget the last key
    if #current > 0 then
      local key, err = M.parse_key_expression(current)
      if not key then return nil, "invalid key in multi: " .. (err or current) end
      result.keys[#result.keys + 1] = key
      if key.is_range then result.is_range = true end
    end

  elseif desc_type == "tr" then
    -- tr(KEY) or tr(KEY,SCRIPT_TREE)
    local comma_pos = nil
    local depth = 0
    for i = 1, #inner do
      local ch = inner:sub(i, i)
      if ch == "[" or ch == "(" or ch == "{" then
        depth = depth + 1
      elseif ch == "]" or ch == ")" or ch == "}" then
        depth = depth - 1
      elseif ch == "," and depth == 0 then
        comma_pos = i
        break
      end
    end

    local key_str, tree_str
    if comma_pos then
      key_str = inner:sub(1, comma_pos - 1)
      tree_str = inner:sub(comma_pos + 1)
    else
      key_str = inner
    end

    local key, err = M.parse_key_expression(key_str)
    if not key then return nil, "invalid tr key: " .. (err or key_str) end
    result.key = key
    result.is_range = key.is_range
    result.tree = tree_str  -- Store raw tree for now

  elseif desc_type == "rawtr" then
    -- rawtr(XONLY_HEX) — BIP-386: raw x-only taproot key, issolvable=true
    -- inner must be a 64-hex-char x-only pubkey (32 bytes)
    if not inner:match("^[0-9a-fA-F]+$") then
      return nil, "rawtr: inner must be hex"
    end
    if #inner ~= 64 then
      return nil, "rawtr: x-only pubkey must be 32 bytes (64 hex chars)"
    end
    result.xonly_hex = inner:lower()

  elseif desc_type == "addr" then
    -- addr(ADDRESS)
    result.address = inner

  elseif desc_type == "raw" then
    -- raw(HEX)
    if not inner:match("^[0-9a-fA-F]*$") then
      return nil, "invalid raw hex"
    end
    result.script = hex_decode(inner)

  elseif desc_type == "combo" then
    -- combo(KEY)
    local key, err = M.parse_key_expression(inner)
    if not key then return nil, err end
    result.key = key
    result.is_range = key.is_range

  else
    return nil, "unknown descriptor type: " .. desc_type
  end

  return result
end

-- Generate scriptPubKey from parsed descriptor
function M.descriptor_to_script(desc, index, network)
  network = network or "mainnet"
  index = index or 0
  local script_mod = require("lunarblock.script")
  local crypto = require("lunarblock.crypto")

  if desc.type == "pk" then
    -- P2PK: <pubkey> OP_CHECKSIG
    local pubkey = desc.key.pubkey
    if desc.key.is_range then
      pubkey = M.derive_path(desc.key, desc.key.path, index)
    end
    if not pubkey then return nil, "failed to derive key" end
    return string.char(#pubkey) .. pubkey .. "\xac"  -- push + OP_CHECKSIG

  elseif desc.type == "pkh" then
    -- P2PKH
    local pubkey = desc.key.pubkey
    if desc.key.is_range then
      pubkey = M.derive_path(desc.key, desc.key.path, index)
    end
    if not pubkey then return nil, "failed to derive key" end
    local hash = crypto.hash160(pubkey)
    return script_mod.make_p2pkh_script(hash)

  elseif desc.type == "wpkh" then
    -- P2WPKH
    local pubkey = desc.key.pubkey
    if desc.key.is_range then
      pubkey = M.derive_path(desc.key, desc.key.path, index)
    end
    if not pubkey then return nil, "failed to derive key" end
    local hash = crypto.hash160(pubkey)
    return script_mod.make_p2wpkh_script(hash)

  elseif desc.type == "sh" then
    -- P2SH
    local inner_script, err = M.descriptor_to_script(desc.inner, index, network)
    if not inner_script then return nil, err end
    local hash = crypto.hash160(inner_script)
    return script_mod.make_p2sh_script(hash)

  elseif desc.type == "wsh" then
    -- P2WSH
    local inner_script, err = M.descriptor_to_script(desc.inner, index, network)
    if not inner_script then return nil, err end
    local hash = crypto.sha256(inner_script)
    return script_mod.make_p2wsh_script(hash)

  elseif desc.type == "multi" or desc.type == "sortedmulti" then
    -- Multisig
    local pubkeys = {}
    for _, key_info in ipairs(desc.keys) do
      local pubkey = key_info.pubkey
      if key_info.is_range then
        pubkey = M.derive_path(key_info, key_info.path, index)
      end
      if not pubkey then return nil, "failed to derive key" end
      pubkeys[#pubkeys + 1] = pubkey
    end

    -- Sort if sortedmulti
    if desc.sorted then
      table.sort(pubkeys)
    end

    -- Build multisig script: OP_M <pubkeys> OP_N OP_CHECKMULTISIG
    local parts = {string.char(0x50 + desc.threshold)}  -- OP_M
    for _, pk in ipairs(pubkeys) do
      parts[#parts + 1] = string.char(#pk) .. pk
    end
    parts[#parts + 1] = string.char(0x50 + #pubkeys)  -- OP_N
    parts[#parts + 1] = "\xae"  -- OP_CHECKMULTISIG
    return table.concat(parts)

  elseif desc.type == "tr" then
    -- P2TR (Taproot)
    local pubkey = desc.key.pubkey
    if desc.key.is_range then
      pubkey = M.derive_path(desc.key, desc.key.path, index)
    end
    if not pubkey then return nil, "failed to derive key" end

    -- BIP-341 §4.2: output_key = lift_x(internal_key) + int(hashTapTweak(ser_xonly(internal_key)))*G
    -- For key-path-only (no script tree), merkle_root = "" so hash input is just the 32-byte x-only key.
    local xonly = pubkey
    if #pubkey == 33 then
      xonly = pubkey:sub(2)  -- Strip prefix byte to get 32-byte x-only form
    end
    local tweak = crypto.tagged_hash("TapTweak", xonly)
    local tweaked_xonly, _parity = crypto.tweak_pubkey(xonly, tweak)
    if not tweaked_xonly then
      return nil, "TapTweak failed: invalid internal pubkey"
    end
    return script_mod.make_p2tr_script(tweaked_xonly)

  elseif desc.type == "addr" then
    -- Decode address to script
    local addr_type, program = M.decode_address(desc.address, network)
    if not addr_type then
      return nil, "invalid address"
    end
    if addr_type == "p2pkh" then
      return script_mod.make_p2pkh_script(program)
    elseif addr_type == "p2sh" then
      return script_mod.make_p2sh_script(program)
    elseif addr_type == "p2wpkh" then
      return script_mod.make_p2wpkh_script(program)
    elseif addr_type == "p2wsh" then
      return script_mod.make_p2wsh_script(program)
    elseif addr_type == "p2tr" then
      return script_mod.make_p2tr_script(program)
    end
    return nil, "unsupported address type"

  elseif desc.type == "rawtr" then
    -- BIP-386: rawtr(XONLY) — script is OP_1 <32-byte x-only>, no tweak.
    -- xonly_hex was validated to 64 hex chars by parse_descriptor.
    local xonly_bytes = desc.xonly_hex:gsub("%x%x", function(h)
      return string.char(tonumber(h, 16))
    end)
    return script_mod.make_p2tr_script(xonly_bytes)

  elseif desc.type == "raw" then
    return desc.script

  elseif desc.type == "combo" then
    -- combo() returns multiple scripts - for now return P2PKH
    local pubkey = desc.key.pubkey
    if desc.key.is_range then
      pubkey = M.derive_path(desc.key, desc.key.path, index)
    end
    if not pubkey then return nil, "failed to derive key" end
    local hash = crypto.hash160(pubkey)
    return script_mod.make_p2pkh_script(hash)
  end

  return nil, "unknown descriptor type"
end

-- Derive address from descriptor at given index
function M.derive_address(desc, index, network)
  network = network or "mainnet"
  index = index or 0

  local script, err = M.descriptor_to_script(desc, index, network)
  if not script then
    return nil, err
  end

  local script_mod = require("lunarblock.script")
  local script_type, program = script_mod.classify_script(script)

  local hrp = M.BECH32_HRP[network] or "bc"

  if script_type == "p2pkh" then
    local version = (network == "mainnet") and M.VERSION.MAINNET_P2PKH or M.VERSION.TESTNET_P2PKH
    return M.base58check_encode(version, program)
  elseif script_type == "p2sh" then
    local version = (network == "mainnet") and M.VERSION.MAINNET_P2SH or M.VERSION.TESTNET_P2SH
    return M.base58check_encode(version, program)
  elseif script_type == "p2wpkh" then
    return M.segwit_encode(hrp, 0, program)
  elseif script_type == "p2wsh" then
    return M.segwit_encode(hrp, 0, program)
  elseif script_type == "p2tr" then
    return M.segwit_encode(hrp, 1, program)
  end

  return nil, "cannot derive address from script type: " .. (script_type or "unknown")
end

-- Derive a range of addresses from descriptor
function M.derive_addresses(desc_str, range_start, range_end, network)
  network = network or "mainnet"
  range_start = range_start or 0
  range_end = range_end or 0

  -- Parse descriptor
  local desc, err = M.parse_descriptor(desc_str)
  if not desc then
    return nil, err
  end

  -- If not a ranged descriptor, just return single address
  if not desc.is_range then
    local addr, addr_err = M.derive_address(desc, 0, network)
    if not addr then return nil, addr_err end
    return {addr}
  end

  -- Derive range
  local addresses = {}
  for i = range_start, range_end do
    local addr, addr_err = M.derive_address(desc, i, network)
    if not addr then return nil, addr_err end
    addresses[#addresses + 1] = addr
  end

  return addresses
end

-- Get descriptor info (canonicalize + add checksum)
function M.get_descriptor_info(desc_str)
  -- Strip existing checksum if present
  local desc = desc_str
  local hash_pos = desc:find("#")
  if hash_pos then
    desc = desc:sub(1, hash_pos - 1)
  end

  -- Parse descriptor
  local parsed, err = M.parse_descriptor(desc)
  if not parsed then
    return nil, err
  end

  -- Compute checksum
  local checksum = M.descriptor_checksum(desc)
  if not checksum then
    return nil, "failed to compute checksum"
  end

  -- Per BIP-380: addr() and raw() are not solvable (no signing info).
  -- All other descriptor types (pkh, wpkh, pk, sh, wsh, tr, rawtr,
  -- multi, sortedmulti, combo) are solvable.
  local not_solvable_types = { addr = true, raw = true }
  local issolvable = not not_solvable_types[parsed.type]

  return {
    descriptor = desc .. "#" .. checksum,
    checksum = checksum,
    isrange = parsed.is_range or false,
    issolvable = issolvable,
    hasprivatekeys = false,  -- Only true when WIF private key embedded
  }
end

--------------------------------------------------------------------------------
-- Descriptor checksum require-mode + single-key descriptor -> scriptPubKey
-- resolution, shared by importdescriptors (and reusable by scantxoutset).
--------------------------------------------------------------------------------

--- Validate a descriptor's checksum in REQUIRE mode (Core require_checksum=true,
--- backup.cpp:158 -> CheckChecksum, descriptor.cpp:2838-2869). Returns the
--- checksum-stripped descriptor body on success, or nil + the EXACT Core error
--- string the caller surfaces as RPC_INVALID_ADDRESS_OR_KEY (-5).
-- @param desc string  descriptor, with or without a #checksum suffix
-- @return string|nil stripped_desc, string|nil core_error_message
function M.require_descriptor_checksum(desc)
  -- Count '#' separators.
  local first = desc:find("#", 1, true)
  if not first then
    -- No '#' and require_checksum -> "Missing checksum" (descriptor.cpp:2845).
    return nil, "Missing checksum"
  end
  local second = desc:find("#", first + 1, true)
  if second then
    return nil, "Multiple '#' symbols"
  end
  local body = desc:sub(1, first - 1)
  local provided = desc:sub(first + 1)
  if #provided ~= 8 then
    return nil, string.format(
      "Expected 8 character checksum, not %u characters", #provided)
  end
  local computed, cerr = M.descriptor_checksum(body)
  if not computed then
    -- A bad character in the payload (descriptor.cpp:2857).
    return nil, "Invalid characters in payload"
  end
  if provided ~= computed then
    return nil, string.format(
      "Provided checksum '%s' does not match computed checksum '%s'",
      provided, computed)
  end
  return body, nil
end

--- Resolve a SINGLE-KEY descriptor body (checksum already stripped) to its
--- scriptPubKey. Covers the watch-only import surface: addr(<address>),
--- wpkh(<hexpub>), pkh(<hexpub>), raw(<hex>), tr(<xonly>) and bare hex (Core
--- raw() shorthand). Detects the PRIVATE-KEY form wpkh(<WIF>)/pkh(<WIF>) — a
--- base58 WIF where a hex pubkey is expected — and flags is_private so the
--- caller can reject it (-4 on a disable_private_keys wallet) WITHOUT needing
--- the key itself. Ranged xpub descriptors are out of scope (absent today).
-- @param body string  checksum-stripped descriptor
-- @param network string  network name ("regtest"/"testnet"/"mainnet"/...)
-- @return table|nil {spk=<bytes>, addr=<string|nil>, kind=<string>,
--                    is_private=<bool>}, string|nil error_message
function M.resolve_descriptor_spk(body, network)
  local script_mod = require("lunarblock.script")
  network = network or "mainnet"
  body = body:gsub("^%s+", ""):gsub("%s+$", "")

  local function is_hex(s)
    return s:match("^[0-9a-fA-F]+$") and (#s % 2 == 0)
  end
  local function hexbytes(h)
    return (h:gsub("..", function(cc) return string.char(tonumber(cc, 16)) end))
  end
  -- A WIF (base58check, 51-52 chars, leading 5/K/L/9/c) is NOT valid hex; if an
  -- inner key arg is not a hex pubkey we treat it as a private key (Core: the
  -- descriptor parser produces a key with private material).
  local function inner_is_private(inner)
    if is_hex(inner) and (#inner == 66 or #inner == 130 or #inner == 64) then
      return false  -- compressed/uncompressed pubkey, or x-only
    end
    return true
  end

  -- addr(<address>)
  local inner = body:match("^addr%((.+)%)$")
  if inner then
    local addr_type, addr_data = M.decode_address(inner, network)
    if not addr_type then
      return nil, "Invalid address in addr(): " .. tostring(addr_data)
    end
    local spk
    if addr_type == "p2pkh" then spk = script_mod.make_p2pkh_script(addr_data)
    elseif addr_type == "p2sh" then spk = script_mod.make_p2sh_script(addr_data)
    elseif addr_type == "p2wpkh" then spk = script_mod.make_p2wpkh_script(addr_data)
    elseif addr_type == "p2wsh" then spk = script_mod.make_p2wsh_script(addr_data)
    elseif addr_type == "p2tr" then spk = script_mod.make_p2tr_script(addr_data)
    else return nil, "Unsupported address type in addr(): " .. tostring(addr_type) end
    return {spk = spk, addr = inner, kind = "addr", is_private = false}
  end

  -- wpkh(<key>) / pkh(<key>) — public hex key (watch-only) or WIF (private).
  for fn, kind in pairs({wpkh = "wpkh", pkh = "pkh"}) do
    inner = body:match("^" .. fn .. "%((.+)%)$")
    if inner then
      if inner_is_private(inner) then
        -- A private-key descriptor: do NOT resolve a script (we never need the
        -- key). The caller rejects this on a watch-only wallet (-4).
        return {spk = nil, addr = nil, kind = kind, is_private = true}
      end
      local pub = hexbytes(inner)
      if #pub ~= 33 and #pub ~= 65 then
        return nil, fn .. "() expects a 33- or 65-byte public key"
      end
      local h = crypto.hash160(pub)
      local spk, addr
      if fn == "wpkh" then
        spk = script_mod.make_p2wpkh_script(h)
        addr = M.segwit_encode(M.BECH32_HRP[network] or "bc", 0, h)
      else
        spk = script_mod.make_p2pkh_script(h)
        local ver = (network == "mainnet") and M.VERSION.MAINNET_P2PKH
                                            or M.VERSION.TESTNET_P2PKH
        addr = M.base58check_encode(ver, h)
      end
      return {spk = spk, addr = addr, kind = kind, is_private = false}
    end
  end

  -- raw(<hex>)
  inner = body:match("^raw%((.+)%)$")
  if inner then
    if not is_hex(inner) then return nil, "Invalid hex in raw()" end
    return {spk = hexbytes(inner), addr = nil, kind = "raw", is_private = false}
  end

  -- tr(<xonly>) — x-only output key (32 bytes).
  inner = body:match("^tr%((.+)%)$")
  if inner then
    if inner_is_private(inner) then
      return {spk = nil, addr = nil, kind = "tr", is_private = true}
    end
    local xonly = hexbytes(inner)
    if #xonly ~= 32 then return nil, "tr() expects a 32-byte x-only output key" end
    local spk = script_mod.make_p2tr_script(xonly)
    local addr = M.xonly_pubkey_to_p2tr(xonly, network)
    return {spk = spk, addr = addr, kind = "tr", is_private = false}
  end

  -- bare hex == Core raw() shorthand
  if is_hex(body) then
    return {spk = hexbytes(body), addr = nil, kind = "raw", is_private = false}
  end

  return nil, "Unsupported descriptor: " .. body
end

return M
