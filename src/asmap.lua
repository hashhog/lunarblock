--- ASMap — Autonomous System Map interpreter for IP→ASN bucketing.
--
-- Port of Bitcoin Core src/util/asmap.cpp (Interpret, SanityCheckAsmap,
-- CheckStandardAsmap, DecodeAsmap, AsmapVersion) and the NetGroupManager
-- portions of src/netgroup.cpp (GetMappedAS, GetGroup, ASMapHealthCheck,
-- UsingASMap).
--
-- Encoding summary (LSB-first bytecode, MSB-first IP bits):
--   Instruction opcodes are decoded from the asmap bytes with ConsumeBitLE
--   (bit 0 of byte 0 is the first bit read).  IP address bits are consumed
--   with ConsumeBitBE (bit 7 of byte 0 is the first bit read, matching
--   network byte order).
--
-- 4 instructions:
--   RETURN  [0]       — leaf node: decode ASN and return it
--   JUMP    [1,0]     — branch: consume one IP bit; if 1, skip forward
--   MATCH   [1,1,0]   — multi-bit compare: if mismatch, return default_asn
--   DEFAULT [1,1,1]   — set fallback ASN and continue
--
-- Reference: bitcoin-core/src/util/asmap.cpp, bitcoin-core/src/netgroup.cpp
-- FIX-50 / W115 — implement ASMap subsystem from scratch.

local bit = require("bit")
local crypto = require("lunarblock.crypto")
local p2p_ok, p2p = pcall(require, "lunarblock.p2p")
if not p2p_ok then p2p = nil end

local M = {}

-- ---------------------------------------------------------------------------
-- Constants
-- ---------------------------------------------------------------------------

-- Maximum allowed asmap file size (8 MiB), mirroring Bitcoin Core init.cpp.
local MAX_ASMAP_FILE_SIZE = 8388608  -- 8 * 1024 * 1024
M.MAX_ASMAP_FILE_SIZE = MAX_ASMAP_FILE_SIZE

-- Internal sentinel for decoding errors (never a valid ASN).
local INVALID = 0xFFFFFFFF

-- Instruction type tags (match Core enum class Instruction).
local INSTR_RETURN  = 0
local INSTR_JUMP    = 1
local INSTR_MATCH   = 2
local INSTR_DEFAULT = 3

-- DecodeBits bit-size tables (identical to Core's constexpr arrays).
-- TYPE:   opcodes from 0-3 encoded in [0, 1+, 3+] bits
local TYPE_BIT_SIZES  = {0, 0, 1}   -- length = 3 (classes 0,1,2)
-- ASN:    minval=1; bit_sizes {15,16,...,24} → encodes 1..~16M
local ASN_BIT_SIZES   = {15,16,17,18,19,20,21,22,23,24}
-- MATCH:  minval=2; bit_sizes {1,2,...,8} → encodes 2..511
local MATCH_BIT_SIZES = {1,2,3,4,5,6,7,8}
-- JUMP:   minval=17; bit_sizes {5,6,...,30} → encodes 17..large
local JUMP_BIT_SIZES  = {5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
                          21,22,23,24,25,26,27,28,29,30}

-- IPv4-in-IPv6 prefix (::ffff:0:0/96 — RFC 4291 §2.5.5.2).
-- Used to normalise IPv4 addresses to 128-bit for Interpret().
local IPV4_IN_IPV6_PREFIX = string.char(
  0,0,0,0, 0,0,0,0, 0,0, 0xFF,0xFF)  -- 12 bytes

-- NET_IPV6 constant (matches Core NET_IPV6 = 2) for group bytes.
local NET_IPV6 = 2

-- ---------------------------------------------------------------------------
-- Low-level bit consumers
-- ---------------------------------------------------------------------------

--- Read one bit from asmap bytes at position bitpos (LSB-first / LE).
-- @param asmap string: raw asmap bytes
-- @param bitpos number: current bit position (0-based)
-- @return bit (0 or 1), new_bitpos
local function consume_bit_le(asmap, bitpos)
  local byte_idx = math.floor(bitpos / 8) + 1  -- Lua 1-based
  local bit_in_byte = bitpos % 8
  local b = asmap:byte(byte_idx) or 0
  return bit.band(bit.rshift(b, bit_in_byte), 1), bitpos + 1
end

--- Read one bit from ip bytes at ip_bitpos (MSB-first / BE, network order).
-- @param ip string: 16-byte IPv6 address (or mapped IPv4)
-- @param ip_bitpos number: current IP bit position (0-based)
-- @return bit (0 or 1), new_ip_bitpos
local function consume_bit_be(ip, ip_bitpos)
  local byte_idx = math.floor(ip_bitpos / 8) + 1
  local bit_in_byte = 7 - (ip_bitpos % 8)
  local b = ip:byte(byte_idx) or 0
  return bit.band(bit.rshift(b, bit_in_byte), 1), ip_bitpos + 1
end

-- ---------------------------------------------------------------------------
-- Variable-length integer decoder (DecodeBits)
-- ---------------------------------------------------------------------------

--- Decode a variable-length unsigned integer from asmap bytecode.
-- Matches Core's DecodeBits() exactly.
-- @param asmap string: raw asmap bytes
-- @param bitpos number: current bit position in asmap (modified in-place via
--        return value)
-- @param minval number: minimum encodable value for this field type
-- @param bit_sizes table: array of per-class mantissa widths
-- @return value (number) or INVALID, new_bitpos
local function decode_bits(asmap, bitpos, minval, bit_sizes)
  local endpos = #asmap * 8
  local val = minval

  for k = 1, #bit_sizes do
    local continuation_bit = 0
    if k < #bit_sizes then
      -- Read the continuation bit (unless we are in the last class).
      if bitpos >= endpos then
        return INVALID, bitpos  -- EOF in exponent
      end
      continuation_bit, bitpos = consume_bit_le(asmap, bitpos)
    end
    -- continuation_bit == 0: decode mantissa in this class (big-endian within class)
    -- continuation_bit == 1: skip this class, add its range to val and move on
    if continuation_bit == 0 then
      local nbits = bit_sizes[k]
      for b = 0, nbits - 1 do
        if bitpos >= endpos then
          return INVALID, bitpos  -- EOF in mantissa
        end
        local lsb_bit
        lsb_bit, bitpos = consume_bit_le(asmap, bitpos)
        val = val + lsb_bit * bit.lshift(1, nbits - 1 - b)
      end
      return val, bitpos
    else
      -- Value is not in this class; advance val by the class size and continue.
      val = val + bit.lshift(1, bit_sizes[k])
    end
  end
  return INVALID, bitpos  -- EOF in exponent (fell off the end)
end

--- Decode instruction type (RETURN/JUMP/MATCH/DEFAULT).
local function decode_type(asmap, bitpos)
  local v, new_bitpos = decode_bits(asmap, bitpos, 0, TYPE_BIT_SIZES)
  return v, new_bitpos
end

--- Decode an ASN value (minval=1).
local function decode_asn(asmap, bitpos)
  return decode_bits(asmap, bitpos, 1, ASN_BIT_SIZES)
end

--- Decode a MATCH argument (minval=2, encodes length+pattern).
local function decode_match(asmap, bitpos)
  return decode_bits(asmap, bitpos, 2, MATCH_BIT_SIZES)
end

--- Decode a JUMP offset (minval=17).
local function decode_jump(asmap, bitpos)
  return decode_bits(asmap, bitpos, 17, JUMP_BIT_SIZES)
end

-- ---------------------------------------------------------------------------
-- bit_width helper (equivalent to std::bit_width)
-- ---------------------------------------------------------------------------

--- Return the position of the highest set bit + 1 (bit width of a value).
-- bit_width(0) = 0, bit_width(1) = 1, bit_width(2) = 2, bit_width(3) = 2, etc.
local function bit_width(v)
  if v == 0 then return 0 end
  local w = 0
  local x = v
  while x ~= 0 do
    x = bit.rshift(x, 1)
    w = w + 1
  end
  return w
end

-- ---------------------------------------------------------------------------
-- Interpret — main IP→ASN trie walk
-- ---------------------------------------------------------------------------

--- Interpret the ASMap bytecode to look up the ASN for a 128-bit IP address.
-- @param asmap string: raw asmap bytes (validated by sanity_check_asmap first)
-- @param ip string: 16-byte IPv6 / mapped-IPv4 address in network byte order
-- @return number: ASN (0 if not mapped or error)
function M.interpret(asmap, ip)
  local pos = 0
  local endpos = #asmap * 8
  local ip_bitpos = 0
  local ip_bits_end = #ip * 8
  local default_asn = 0

  while pos < endpos do
    local opcode
    opcode, pos = decode_type(asmap, pos)

    if opcode == INSTR_RETURN then
      -- Leaf node: decode and return the mapped ASN.
      local asn
      asn, pos = decode_asn(asmap, pos)
      if asn == INVALID then break end
      return asn

    elseif opcode == INSTR_JUMP then
      -- Branch: consume one IP bit; jump forward if bit = 1.
      local jump
      jump, pos = decode_jump(asmap, pos)
      if jump == INVALID then break end
      if ip_bitpos >= ip_bits_end then break end
      -- Guard: jump must not reach past EOF
      if jump >= (endpos - pos) then break end
      local ip_bit
      ip_bit, ip_bitpos = consume_bit_be(ip, ip_bitpos)
      if ip_bit == 1 then
        pos = pos + jump  -- right subtree
      end
      -- ip_bit = 0: fall through to left subtree

    elseif opcode == INSTR_MATCH then
      -- Multi-bit prefix compare; mismatch returns default_asn.
      local match
      match, pos = decode_match(asmap, pos)
      if match == INVALID then break end
      local matchlen = bit_width(match) - 1  -- highest-set-bit pos = n-1 bits to consume
      if (ip_bits_end - ip_bitpos) < matchlen then break end
      local mismatch = false
      for b = 0, matchlen - 1 do
        local ip_bit
        ip_bit, ip_bitpos = consume_bit_be(ip, ip_bitpos)
        local pattern_bit = bit.band(bit.rshift(match, matchlen - 1 - b), 1)
        if ip_bit ~= pattern_bit then
          mismatch = true
          break
        end
      end
      if mismatch then
        return default_asn
      end

    elseif opcode == INSTR_DEFAULT then
      -- Update the fallback ASN.
      local asn
      asn, pos = decode_asn(asmap, pos)
      if asn == INVALID then break end
      default_asn = asn

    else
      break  -- opcode == INVALID (straddles EOF)
    end
  end

  -- Should have been caught by sanity_check_asmap; return 0 defensively.
  return 0
end

-- ---------------------------------------------------------------------------
-- SanityCheckAsmap — structural validator (all execution paths)
-- ---------------------------------------------------------------------------

--- Validate ASMap bytecode by simulating all possible execution paths.
-- Mirrors Core's SanityCheckAsmap() exactly.
-- @param asmap string: raw asmap bytes
-- @param bits number: number of IP input bits the trie accepts (128 for IPv6)
-- @return boolean: true if the asmap is well-formed
function M.sanity_check_asmap(asmap, bits)
  local pos = 0
  local endpos = #asmap * 8
  -- Stack of pending jump targets: each entry is {jump_offset, bits_remaining}
  local jumps = {}
  local prevopcode = INSTR_JUMP  -- synthetic initial "just jumped" state
  local had_incomplete_match = false

  while pos ~= endpos do
    -- If we are past the next queued jump target, the code is unreachable → invalid.
    if #jumps > 0 and pos >= jumps[#jumps][1] then
      return false
    end

    local opcode
    opcode, pos = decode_type(asmap, pos)

    if opcode == INSTR_RETURN then
      if prevopcode == INSTR_DEFAULT then return false end  -- could have been just RETURN
      local asn
      asn, pos = decode_asn(asmap, pos)
      if asn == INVALID then return false end

      if #jumps == 0 then
        -- Nothing left to execute; check padding.
        if (endpos - pos) > 7 then return false end  -- too much trailing data
        while pos ~= endpos do
          local pad_bit
          pad_bit, pos = consume_bit_le(asmap, pos)
          if pad_bit ~= 0 then return false end  -- non-zero padding
        end
        return true
      else
        -- Continue from the jump target, restoring bits count.
        if pos ~= jumps[#jumps][1] then return false end  -- unreachable code
        bits = jumps[#jumps][2]
        jumps[#jumps] = nil  -- pop
        prevopcode = INSTR_JUMP  -- pretend we just jumped
      end

    elseif opcode == INSTR_JUMP then
      local jump
      jump, pos = decode_jump(asmap, pos)
      if jump == INVALID then return false end
      if jump > (endpos - pos) then return false end  -- jump out of range
      if bits == 0 then return false end  -- consumed past end of input
      bits = bits - 1
      local jump_offset = pos + jump
      -- Intersecting-jumps guard (jump target must be strictly before previous one).
      if #jumps > 0 and jump_offset >= jumps[#jumps][1] then return false end
      jumps[#jumps + 1] = {jump_offset, bits}
      prevopcode = INSTR_JUMP

    elseif opcode == INSTR_MATCH then
      local match
      match, pos = decode_match(asmap, pos)
      if match == INVALID then return false end
      local matchlen = bit_width(match) - 1
      if prevopcode ~= INSTR_MATCH then had_incomplete_match = false end
      -- Within a run of MATCHes, at most one may be < 8 bits.
      if matchlen < 8 and had_incomplete_match then return false end
      had_incomplete_match = (matchlen < 8)
      if bits < matchlen then return false end
      bits = bits - matchlen
      prevopcode = INSTR_MATCH

    elseif opcode == INSTR_DEFAULT then
      if prevopcode == INSTR_DEFAULT then return false end  -- successive DEFAULTs redundant
      local asn
      asn, pos = decode_asn(asmap, pos)
      if asn == INVALID then return false end
      prevopcode = INSTR_DEFAULT

    else
      return false  -- INVALID opcode (straddles EOF)
    end
  end

  return false  -- Reached EOF without RETURN
end

--- Check a standard (128-bit) asmap (convenience wrapper matching Core's
-- CheckStandardAsmap).
-- @param asmap string: raw asmap bytes
-- @return boolean: true if valid
function M.check_standard_asmap(asmap)
  if not M.sanity_check_asmap(asmap, 128) then
    return false, "sanity check of asmap data failed"
  end
  return true
end

-- ---------------------------------------------------------------------------
-- load_asmap — read file from disk, enforce size limit, validate
-- ---------------------------------------------------------------------------

--- Load and validate an ASMap file from disk.
-- Returns the raw bytes on success, nil + error on failure.
-- MAX_ASMAP_FILE_SIZE = 8 MiB guard is enforced here.
-- @param path string: filesystem path to the .dat file
-- @return string|nil, string|nil: (asmap_bytes, nil) or (nil, errmsg)
function M.load_asmap(path)
  local f, err = io.open(path, "rb")
  if not f then
    return nil, "failed to open asmap file: " .. tostring(err)
  end

  -- Determine file size.
  local size = f:seek("end")
  f:seek("set", 0)

  if size == 0 then
    f:close()
    return nil, "asmap file is empty"
  end
  if size > MAX_ASMAP_FILE_SIZE then
    f:close()
    return nil, string.format(
      "asmap file too large (%d bytes, max %d)", size, MAX_ASMAP_FILE_SIZE)
  end

  local data = f:read(size)
  f:close()

  if not data or #data ~= size then
    return nil, "short read from asmap file"
  end

  -- Structural validation.
  local ok, chk_err = M.check_standard_asmap(data)
  if not ok then
    return nil, "asmap integrity check failed: " .. tostring(chk_err)
  end

  return data
end

-- ---------------------------------------------------------------------------
-- asmap_version — SHA-256 checksum of raw bytes
-- ---------------------------------------------------------------------------

--- Compute the asmap version: SHA-256 of the raw bytes.
-- Matches Core's AsmapVersion() / NetGroupManager::GetAsmapVersion().
-- Returns a 64-character lowercase hex string (or "" for nil/empty input).
-- @param asmap string|nil: raw asmap bytes
-- @return string: 64-char hex digest, or "" if empty
function M.get_asmap_version(asmap)
  if not asmap or #asmap == 0 then return "" end
  local hash = crypto.sha256(asmap)
  -- Encode 32 raw bytes as hex
  local hex = {}
  for i = 1, #hash do
    hex[i] = string.format("%02x", hash:byte(i))
  end
  return table.concat(hex)
end

-- Alias matching the Core naming convention used in test patterns.
M.asmap_version = M.get_asmap_version

-- ---------------------------------------------------------------------------
-- get_mapped_as — public IP→ASN interface
-- ---------------------------------------------------------------------------

--- Look up the ASN for an IP address using a loaded asmap.
-- Returns 0 when no asmap is loaded, or the address is not IPv4/IPv6, or
-- the trie returns the default (no mapping found).  ASN 0 is reserved per
-- RFC 7607 and is the safe sentinel for "unknown".
-- @param asmap string|nil: raw asmap bytes (from load_asmap), or nil
-- @param ip string: IPv4 ("1.2.3.4") or IPv6 dotted/colon notation
-- @param network_id number|nil: BIP-155 network type (for non-IP rejection)
-- @return number: ASN (0 = not mapped)
function M.get_mapped_as(asmap, ip, network_id)
  if not asmap or #asmap == 0 then return 0 end

  -- Only IPv4 and IPv6 are ASN-mappable (not Tor/I2P/CJDNS).
  if network_id and p2p then
    if network_id == p2p.NET_ID.TORV3 then return 0 end
    if network_id == p2p.NET_ID.I2P then return 0 end
    if network_id == p2p.NET_ID.CJDNS then return 0 end
  end

  local ip16 = _ip_to_16bytes(ip)
  if not ip16 then return 0 end

  return M.interpret(asmap, ip16)
end

-- ---------------------------------------------------------------------------
-- Internal: normalise IP to 16-byte representation
-- ---------------------------------------------------------------------------

--- Convert an IP address string to a 16-byte string (IPv6 / mapped IPv4).
-- Returns nil if the address cannot be parsed.
-- @param ip string
-- @return string|nil: 16 bytes in network byte order
function _ip_to_16bytes(ip)
  -- IPv4 dotted decimal
  local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if a then
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
    -- IPv4-mapped IPv6: ::ffff:a.b.c.d (12-byte prefix + 4 IPv4 bytes)
    return IPV4_IN_IPV6_PREFIX
      .. string.char(a, b, c, d)
  end

  -- IPv6: expand and convert
  local ip6 = _expand_ipv6(ip)
  if ip6 and #ip6 == 16 then return ip6 end

  return nil
end

--- Expand an IPv6 address string to 16 raw bytes.
-- Handles :: compression and ::ffff: mapped IPv4.
-- @param ip string: IPv6 address
-- @return string|nil: 16 bytes or nil on parse error
function _expand_ipv6(ip)
  -- Reject obviously non-IPv6 strings.
  if not ip:find(":") then return nil end

  -- Check for embedded IPv4 in IPv6 (e.g. "::ffff:192.0.2.1")
  local ipv4_tail = ip:match(":(%d+%.%d+%.%d+%.%d+)$")
  local prefix_part = ip
  local ipv4_bytes = nil
  if ipv4_tail then
    local a, b, c, d = ipv4_tail:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if a then
      ipv4_bytes = string.char(tonumber(a), tonumber(b), tonumber(c), tonumber(d))
      prefix_part = ip:sub(1, #ip - #ipv4_tail - 1)
    end
  end

  -- Split on "::" (at most one occurrence).
  local left_str, right_str = prefix_part:match("^(.*)::(.*)$")
  local left_groups, right_groups = {}, {}

  local function parse_groups(s, dest)
    if s == "" then return true end
    for g in (s .. ":"):gmatch("([^:]*):") do
      if #dest >= 8 then return false end
      local v = tonumber(g, 16)
      if not v then return false end
      dest[#dest + 1] = v
    end
    return true
  end

  if left_str then
    -- Has :: compression.
    if not parse_groups(left_str, left_groups) then return nil end
    if not parse_groups(right_str, right_groups) then return nil end
  else
    -- No compression: must be exactly 8 groups (or 6 + embedded IPv4).
    if not parse_groups(prefix_part, left_groups) then return nil end
    right_groups = {}
  end

  -- How many groups does the embedded IPv4 consume?
  local ipv4_group_count = ipv4_bytes and 2 or 0

  local total_groups = #left_groups + #right_groups + ipv4_group_count
  if total_groups > 8 then return nil end

  -- Expand :: to the required number of zero groups.
  local zero_count = 8 - total_groups
  local all_groups = {}
  for _, g in ipairs(left_groups) do all_groups[#all_groups + 1] = g end
  for _ = 1, zero_count do all_groups[#all_groups + 1] = 0 end
  for _, g in ipairs(right_groups) do all_groups[#all_groups + 1] = g end

  -- Build 16-byte string.
  local bytes = {}
  for _, g in ipairs(all_groups) do
    bytes[#bytes + 1] = string.char(bit.band(bit.rshift(g, 8), 0xFF))
    bytes[#bytes + 1] = string.char(bit.band(g, 0xFF))
  end
  local result = table.concat(bytes)

  -- If there was an embedded IPv4, replace the last 4 bytes.
  if ipv4_bytes then
    -- Replace the last 4 bytes (2 groups) with the IPv4 bytes.
    result = result:sub(1, 12) .. ipv4_bytes
  end

  if #result ~= 16 then return nil end
  return result
end

-- ---------------------------------------------------------------------------
-- get_addr_group — ASN-aware version of peerman's get_addr_group
-- ---------------------------------------------------------------------------

--- Compute the network group for an address (for AddrMan bucketing).
-- When an asmap is loaded and the address is IPv4/IPv6, returns
-- [NET_IPV6 (1 byte) + ASN (4 bytes LE)] mirroring Core's GetGroup().
-- Falls back to the /16 (IPv4) or /32 (IPv6) prefix otherwise.
-- @param asmap string|nil: loaded asmap bytes or nil
-- @param ip string: IP address
-- @param network_id number|nil: BIP-155 network type
-- @return string: group bytes
function M.get_addr_group(asmap, ip, network_id)
  -- Non-IP overlay networks: group by network type.
  if network_id then
    if p2p then
      if network_id == p2p.NET_ID.TORV3 then
        return string.char(p2p.NET_ID.TORV3)
      elseif network_id == p2p.NET_ID.I2P then
        return string.char(p2p.NET_ID.I2P)
      elseif network_id == p2p.NET_ID.CJDNS then
        return string.char(p2p.NET_ID.CJDNS)
      end
    else
      -- p2p not available: use network_id byte directly
      return string.char(network_id)
    end
  end

  -- Try ASN lookup when asmap is loaded.
  if asmap and #asmap > 0 then
    local asn = M.get_mapped_as(asmap, ip)
    if asn ~= 0 then
      -- [NET_IPV6] + 4 bytes of ASN (little-endian, matches Core GetGroup())
      return string.char(NET_IPV6)
        .. string.char(bit.band(asn, 0xFF))
        .. string.char(bit.band(bit.rshift(asn, 8), 0xFF))
        .. string.char(bit.band(bit.rshift(asn, 16), 0xFF))
        .. string.char(bit.band(bit.rshift(asn, 24), 0xFF))
    end
  end

  -- Fallback: /16 for IPv4, /32 for IPv6.
  local a, b = ip:match("^(%d+)%.(%d+)%.")
  if a then
    return string.char(4)
      .. string.char(tonumber(a))
      .. string.char(tonumber(b))
  end

  -- IPv6 simplified: first 32 bits (two 16-bit groups).
  local parts = {}
  for part in (ip .. ":"):gmatch("([^:]*):") do
    parts[#parts + 1] = part
  end
  if #parts >= 2 then
    local p1 = tonumber(parts[1], 16) or 0
    local p2 = tonumber(parts[2], 16) or 0
    local bit_lib = bit
    return string.char(6)
      .. string.char(bit_lib.rshift(p1, 8))
      .. string.char(bit_lib.band(p1, 0xFF))
      .. string.char(bit_lib.rshift(p2, 8))
      .. string.char(bit_lib.band(p2, 0xFF))
  end

  return string.char(0) .. ip
end

-- ---------------------------------------------------------------------------
-- asmap_health_check — logging helper
-- ---------------------------------------------------------------------------

--- Log ASN diversity statistics for a list of clearnet peer IPs.
-- Mirrors Core's NetGroupManager::ASMapHealthCheck().
-- @param asmap string|nil: loaded asmap bytes
-- @param peer_ips table: list of IP address strings
-- @return table: {total=N, mapped=M, unmapped=U, distinct_asns=D, asns={...}}
function M.asmap_health_check(asmap, peer_ips)
  local asn_set = {}
  local unmapped = 0
  for _, ip in ipairs(peer_ips or {}) do
    local asn = M.get_mapped_as(asmap, ip)
    if asn == 0 then
      unmapped = unmapped + 1
    else
      asn_set[asn] = true
    end
  end
  local distinct = 0
  for _ in pairs(asn_set) do distinct = distinct + 1 end
  return {
    total        = #(peer_ips or {}),
    mapped       = #(peer_ips or {}) - unmapped,
    unmapped     = unmapped,
    distinct_asns = distinct,
    asns         = asn_set,
  }
end

-- ---------------------------------------------------------------------------
-- using_asmap — state flag helper
-- ---------------------------------------------------------------------------

--- Return true when an asmap is loaded (size > 0).
-- Matches Core's NetGroupManager::UsingASMap().
-- @param asmap string|nil
-- @return boolean
function M.using_asmap(asmap)
  return asmap ~= nil and #asmap > 0
end

return M
