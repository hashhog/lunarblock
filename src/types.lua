local ffi = require("ffi")
local M = {}

-- Use FFI for precise 64-bit integer arithmetic
ffi.cdef[[
  typedef struct { uint8_t bytes[32]; } hash256_t;
  typedef struct { uint8_t bytes[20]; } hash160_t;
]]

-- Hash256: 32-byte hash used for txid, block hash, merkle nodes
-- Store internally as a 32-byte Lua string (binary, little-endian as on wire).
--
-- The wrapper is a single-field table; the prior `_type = "hash256"` field
-- was set on every allocation but never read (grep confirmed no dispatch on
-- _type for hash256 anywhere). Dropping it ~halves the allocation cost on
-- the hottest GC path — the 2026-04-23 LuaJIT profile recorded 18% of GC
-- time in this constructor and another 24% in serialize.read_hash256
-- (which calls this).
function M.hash256(bytes)
  assert(#bytes == 32, "hash256 requires exactly 32 bytes")
  return { bytes = bytes }
end

-- Reverse a hash for display (Bitcoin displays hashes in big-endian)
function M.hash256_hex(h)
  local reversed = h.bytes:reverse()
  local hex = {}
  for i = 1, 32 do
    hex[i] = string.format("%02x", reversed:byte(i))
  end
  return table.concat(hex)
end

-- Parse hex string (big-endian display format) into hash256 (little-endian internal)
function M.hash256_from_hex(hex_str)
  assert(#hex_str == 64, "hash256 hex must be 64 characters")
  local bytes = {}
  for i = 63, 1, -2 do
    bytes[#bytes + 1] = string.char(tonumber(hex_str:sub(i, i + 1), 16))
  end
  return M.hash256(table.concat(bytes))
end

function M.hash256_zero()
  return M.hash256(string.rep("\0", 32))
end

function M.hash256_eq(a, b)
  return a.bytes == b.bytes
end

-- Hash160: 20-byte hash used for addresses (RIPEMD160(SHA256(x))).
-- See hash256 above for why _type was dropped.
function M.hash160(bytes)
  assert(#bytes == 20, "hash160 requires exactly 20 bytes")
  return { bytes = bytes }
end

-- OutPoint: reference to a specific output of a previous transaction
function M.outpoint(hash, index)
  return { _type = "outpoint", hash = hash, index = index }
end

-- TxIn: transaction input
function M.txin(prev_out, script_sig, sequence)
  return {
    _type = "txin",
    prev_out = prev_out,
    script_sig = script_sig or "",
    sequence = sequence or 0xFFFFFFFF,
    witness = {}  -- segregated witness data, list of byte strings
  }
end

-- TxOut: transaction output
function M.txout(value, script_pubkey)
  return {
    _type = "txout",
    value = value,  -- int64, satoshis
    script_pubkey = script_pubkey or ""
  }
end

-- Transaction
function M.transaction(version, inputs, outputs, locktime)
  return {
    _type = "transaction",
    version = version or 1,
    inputs = inputs or {},
    outputs = outputs or {},
    locktime = locktime or 0,
    segwit = false  -- set to true if any witness data present
  }
end

-- Block Header (80 bytes)
function M.block_header(version, prev_hash, merkle_root, timestamp, bits, nonce)
  return {
    _type = "block_header",
    version = version or 1,
    prev_hash = prev_hash or M.hash256_zero(),
    merkle_root = merkle_root or M.hash256_zero(),
    timestamp = timestamp or 0,
    bits = bits or 0,
    nonce = nonce or 0
  }
end

-- Full Block
function M.block(header, transactions)
  return {
    _type = "block",
    header = header,
    transactions = transactions or {}
  }
end

return M
