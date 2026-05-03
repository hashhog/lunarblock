local ffi = require("ffi")
local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local crypto = require("lunarblock.crypto")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local script = require("lunarblock.script")
local storage_mod = require("lunarblock.storage")
local perf = require("lunarblock.perf")
local sig_cache = require("lunarblock.sig_cache")
local mining = require("lunarblock.mining")
local bit = require("bit")
local band, bor, rshift, lshift = bit.band, bit.bor, bit.rshift, bit.lshift
local M = {}

--------------------------------------------------------------------------------
-- Fast UTXO Serialization (FFI-based, avoids buffer_writer/reader overhead)
--------------------------------------------------------------------------------

-- Pre-allocated buffer for UTXO serialization (max: 8 + 5 + 10000 + 4 + 1)
local _utxo_buf = ffi.new("uint8_t[?]", 16384)

-- Write a 64-bit signed LE value into buf at offset, return new offset
local function _write_i64le(buf, off, val)
  local lo, hi
  if val < 0 then
    lo = val % 4294967296
    hi = math.floor(val / 4294967296)
    if lo < 0 then lo = lo + 4294967296; hi = hi - 1 end
    if hi < 0 then hi = hi + 4294967296 end
  else
    lo = val % 4294967296
    hi = math.floor(val / 4294967296)
  end
  buf[off]   = band(lo, 0xFF)
  buf[off+1] = band(rshift(lo, 8), 0xFF)
  buf[off+2] = band(rshift(lo, 16), 0xFF)
  buf[off+3] = band(rshift(lo, 24), 0xFF)
  buf[off+4] = band(hi, 0xFF)
  buf[off+5] = band(rshift(hi, 8), 0xFF)
  buf[off+6] = band(rshift(hi, 16), 0xFF)
  buf[off+7] = band(rshift(hi, 24), 0xFF)
  return off + 8
end

-- Write a varint into buf at offset, return new offset
local function _write_varint(buf, off, val)
  if val < 0xFD then
    buf[off] = val
    return off + 1
  elseif val <= 0xFFFF then
    buf[off] = 0xFD
    buf[off+1] = band(val, 0xFF)
    buf[off+2] = band(rshift(val, 8), 0xFF)
    return off + 3
  elseif val <= 0xFFFFFFFF then
    buf[off] = 0xFE
    buf[off+1] = band(val, 0xFF)
    buf[off+2] = band(rshift(val, 8), 0xFF)
    buf[off+3] = band(rshift(val, 16), 0xFF)
    buf[off+4] = band(rshift(val, 24), 0xFF)
    return off + 5
  end
  -- 8-byte varint (unlikely for script lengths)
  buf[off] = 0xFF
  return _write_i64le(buf, off + 1, val)
end

-- Write a uint32 LE into buf at offset, return new offset
local function _write_u32le(buf, off, val)
  buf[off]   = band(val, 0xFF)
  buf[off+1] = band(rshift(val, 8), 0xFF)
  buf[off+2] = band(rshift(val, 16), 0xFF)
  buf[off+3] = band(rshift(val, 24), 0xFF)
  return off + 4
end

--------------------------------------------------------------------------------
-- UTXO Entry
--------------------------------------------------------------------------------

-- A UTXO entry represents a single unspent transaction output
-- Stored in the database keyed by outpoint (txid + vout_index)
function M.utxo_entry(value, script_pubkey, height, is_coinbase)
  return {
    value = value,                 -- int64 satoshis
    script_pubkey = script_pubkey, -- raw script bytes
    height = height,               -- block height where this output was created
    is_coinbase = is_coinbase,     -- boolean, for maturity check
  }
end

--------------------------------------------------------------------------------
-- UTXO Entry Serialization
--------------------------------------------------------------------------------

function M.serialize_utxo_entry(entry)
  local buf = _utxo_buf
  local off = _write_i64le(buf, 0, entry.value)
  local sp = entry.script_pubkey
  local sp_len = #sp
  off = _write_varint(buf, off, sp_len)
  ffi.copy(buf + off, sp, sp_len)
  off = off + sp_len
  off = _write_u32le(buf, off, entry.height)
  buf[off] = entry.is_coinbase and 1 or 0
  off = off + 1
  return ffi.string(buf, off)
end

function M.deserialize_utxo_entry(data)
  -- Fast inline deserialization avoiding buffer_reader closure overhead
  local pos = 1
  -- read i64le (value)
  local b1, b2, b3, b4, b5, b6, b7, b8 = data:byte(pos, pos + 7)
  local lo = b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
  local hi = b5 + b6 * 256 + b7 * 65536 + b8 * 16777216
  local value
  if hi >= 2147483648 then
    local comp_lo = 4294967295 - lo
    local comp_hi = 4294967295 - hi
    value = -(comp_lo + comp_hi * 4294967296 + 1)
  else
    value = lo + hi * 4294967296
  end
  pos = pos + 8

  -- read varint (script length)
  local first = data:byte(pos)
  pos = pos + 1
  local script_len
  if first < 0xFD then
    script_len = first
  elseif first == 0xFD then
    local sb1, sb2 = data:byte(pos, pos + 1)
    script_len = sb1 + sb2 * 256
    pos = pos + 2
  elseif first == 0xFE then
    local sb1, sb2, sb3, sb4 = data:byte(pos, pos + 3)
    script_len = sb1 + sb2 * 256 + sb3 * 65536 + sb4 * 16777216
    pos = pos + 4
  else
    -- 8-byte varint (extremely unlikely)
    local r = serialize.buffer_reader(data:sub(pos))
    script_len = r.read_u64le()
    pos = pos + 8
  end

  -- read script bytes
  local script_pubkey = data:sub(pos, pos + script_len - 1)
  pos = pos + script_len

  -- read u32le (height)
  b1, b2, b3, b4 = data:byte(pos, pos + 3)
  local height = b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
  pos = pos + 4

  -- read u8 (is_coinbase)
  local is_coinbase = data:byte(pos) == 1

  return M.utxo_entry(value, script_pubkey, height, is_coinbase)
end

--------------------------------------------------------------------------------
-- Undo Data Types
--------------------------------------------------------------------------------

-- TxUndo: stores the UTXOs spent by a single transaction's inputs.
-- Each entry is a UTXO entry (value, script_pubkey, height, is_coinbase).
-- Format: { prev_outputs = { utxo_entry, ... } }
function M.tx_undo(prev_outputs)
  return {
    prev_outputs = prev_outputs or {},  -- array of utxo_entry
  }
end

-- BlockUndo: stores undo data for all non-coinbase transactions in a block.
-- The coinbase has no inputs to undo, so vtxundo[1] corresponds to block.transactions[2].
-- Format: { tx_undo = { TxUndo, ... } }
function M.block_undo(tx_undo)
  return {
    tx_undo = tx_undo or {},  -- array of tx_undo (one per non-coinbase tx)
  }
end

--------------------------------------------------------------------------------
-- Undo Data Serialization
--------------------------------------------------------------------------------

-- Serialize a single undo entry (spent UTXO).
-- Format matches Bitcoin Core's TxInUndoFormatter:
--   varint(height * 2 + coinbase_flag) | [dummy byte if height > 0] | value | script
function M.serialize_undo_entry(entry)
  local w = serialize.buffer_writer()
  -- Encode height and coinbase flag together: (height * 2) + coinbase_flag
  local code = entry.height * 2 + (entry.is_coinbase and 1 or 0)
  w.write_varint(code)
  -- For compatibility with older undo format, write a dummy byte if height > 0
  if entry.height > 0 then
    w.write_u8(0)  -- version dummy
  end
  -- Write the TxOut data: value + script
  w.write_i64le(entry.value)
  w.write_varstr(entry.script_pubkey)
  return w.result()
end

-- Deserialize a single undo entry (spent UTXO).
function M.deserialize_undo_entry(reader)
  if type(reader) == "string" then
    reader = serialize.buffer_reader(reader)
  end
  local code = reader.read_varint()
  local height = math.floor(code / 2)
  local is_coinbase = (code % 2) == 1
  -- Read and discard dummy byte if height > 0
  if height > 0 then
    reader.read_u8()  -- version dummy
  end
  local value = reader.read_i64le()
  local script_pubkey = reader.read_varstr()
  return M.utxo_entry(value, script_pubkey, height, is_coinbase)
end

-- Serialize TxUndo (undo data for one transaction).
-- Format: varint(num_inputs) | undo_entry | undo_entry | ...
function M.serialize_tx_undo(tx_undo)
  local w = serialize.buffer_writer()
  w.write_varint(#tx_undo.prev_outputs)
  for _, entry in ipairs(tx_undo.prev_outputs) do
    w.write_bytes(M.serialize_undo_entry(entry))
  end
  return w.result()
end

-- Deserialize TxUndo.
function M.deserialize_tx_undo(reader)
  if type(reader) == "string" then
    reader = serialize.buffer_reader(reader)
  end
  local count = reader.read_varint()
  local prev_outputs = {}
  for i = 1, count do
    prev_outputs[i] = M.deserialize_undo_entry(reader)
  end
  return M.tx_undo(prev_outputs)
end

-- Serialize BlockUndo (undo data for a full block).
-- Format: varint(num_tx) | tx_undo | tx_undo | ... | checksum (32 bytes SHA256)
function M.serialize_block_undo(block_undo)
  local w = serialize.buffer_writer()
  w.write_varint(#block_undo.tx_undo)
  for _, txu in ipairs(block_undo.tx_undo) do
    w.write_bytes(M.serialize_tx_undo(txu))
  end
  local data = w.result()
  -- Append SHA256 checksum of the data
  local checksum = crypto.sha256(data)
  return data .. checksum
end

-- Deserialize BlockUndo.
-- Verifies the SHA256 checksum at the end.
function M.deserialize_block_undo(data)
  if #data < 33 then  -- At minimum: 1 byte varint + 32 byte checksum
    return nil, "undo data too short"
  end
  -- Split data and checksum
  local payload = data:sub(1, -33)
  local stored_checksum = data:sub(-32)
  local computed_checksum = crypto.sha256(payload)
  if stored_checksum ~= computed_checksum then
    return nil, "undo data checksum mismatch"
  end
  local reader = serialize.buffer_reader(payload)
  local count = reader.read_varint()
  local tx_undo = {}
  for i = 1, count do
    tx_undo[i] = M.deserialize_tx_undo(reader)
  end
  return M.block_undo(tx_undo)
end

--------------------------------------------------------------------------------
-- AssumeUTXO Snapshot Format
--------------------------------------------------------------------------------

-- Snapshot wire format matching Bitcoin Core (bitcoin-core/src/node/utxo_snapshot.h
-- and bitcoin-core/src/rpc/blockchain.cpp WriteUTXOSnapshot).
--
-- Header (51 bytes, see SnapshotMetadata::Serialize):
--   magic_bytes[5]      = 'utxo' + 0xff   (SNAPSHOT_MAGIC_BYTES)
--   version[2]          = uint16 LE       (SnapshotMetadata::VERSION = 2)
--   network_magic[4]    = MessageStartChars
--   base_blockhash[32]  = uint256 (LE on the wire, matches storage order)
--   coins_count[8]      = uint64 LE
--
-- Body (grouped by txid; see WriteUTXOSnapshot in rpc/blockchain.cpp):
--   For each txid (in lexicographic key order from leveldb):
--     txid[32]                    = raw 32 bytes (no length prefix)
--     coins_per_txid (CompactSize)= number of coins for this txid
--     For each coin:
--       vout_index (CompactSize)
--       code (Core VARINT)        = (height * 2) + (coinbase ? 1 : 0)
--       compressed_amount (Core VARINT) = CompressAmount(value)
--       script_pubkey             = ScriptCompression (compressed type byte
--                                   + raw, OR Core VARINT(size+6) + raw bytes)
--
-- IMPORTANT: Core uses TWO different variable-length encodings:
--   1. CompactSize (Bitcoin's varint): 1/3/5/9 byte LE encoding used for
--      counts in the snapshot body (coins_per_txid, vout).  This matches
--      what serialize.lua:write_varint already does.
--   2. Core VARINT: MSB base-128 encoding (see serialize.h:WriteVarInt).
--      Used inside Coin::Serialize for `code` and inside AmountCompression
--      and ScriptCompression.  We implement this below as
--      _write_corevarint / _read_corevarint.
--
-- Mixing the two is the bug this commit fixes — the prior implementation
-- emitted coin data with `write_varint` (CompactSize) for `code`, no
-- amount compression, and a varstring for the script.

-- Snapshot magic bytes (Bitcoin Core compatible)
M.SNAPSHOT_MAGIC = "utxo\xff"
M.SNAPSHOT_VERSION = 2

-- ScriptCompression special-script count (compressor.h:ScriptCompression)
M.N_SPECIAL_SCRIPTS = 6
-- Maximum tx output script size that ScriptCompression accepts
-- (matches MAX_SCRIPT_SIZE in script.h).
M.MAX_SCRIPT_SIZE = 10000

--------------------------------------------------------------------------------
-- Core VARINT (MSB base-128) helpers
--
-- Bitcoin Core's WriteVarInt (serialize.h) is NOT the CompactSize encoding.
-- It writes 7 bits at a time, MSB-first, with the high bit of every byte
-- except the last set to 1.  After each non-final byte, the value is
-- decremented by 1 (Mode::DEFAULT) so that the encoding is unique.
-- This implementation accepts/produces uint64-range values via LuaJIT
-- cdata so it stays correct above 2^53 (snapshot reading hits 64-bit
-- intermediate values inside DecompressAmount).
--------------------------------------------------------------------------------

-- u64 cdata for >32-bit safe arithmetic (LuaJIT FFI).
local u64_t = ffi.typeof("uint64_t")

local function _to_u64(v)
  if type(v) == "cdata" then return ffi.cast(u64_t, v) end
  return ffi.cast(u64_t, v)
end

--- Write a Core VARINT (MSB base-128 with -1 carry).
-- @param w buffer_writer
-- @param val number|cdata: non-negative integer in uint64 range
function M.write_corevarint(w, val)
  local n = _to_u64(val)
  -- We need the bytes in MSB-first order.  Emit to a stack-like array,
  -- then write in reverse.
  local tmp = ffi.new("uint8_t[10]")
  local len = 0
  while true do
    -- low 7 bits
    local low7 = tonumber(n % u64_t(128))
    -- high bit set if this is not the final byte (we set it for every
    -- non-zero "len" because the loop reverses the byte order: the byte
    -- written FIRST in the buffer is the highest-order byte and must have
    -- 0x80 set; the byte written LAST must have 0x80 clear).
    tmp[len] = low7 + (len > 0 and 0x80 or 0)
    if n <= u64_t(0x7F) then break end
    n = (n / u64_t(128)) - u64_t(1)
    len = len + 1
  end
  -- Write bytes in reverse (most-significant first).
  for i = len, 0, -1 do
    w.write_u8(tmp[i])
  end
end

--- Read a Core VARINT.
-- @param r buffer_reader
-- @return cdata uint64_t
function M.read_corevarint(r)
  local n = u64_t(0)
  local guard = 0
  while true do
    guard = guard + 1
    if guard > 18 then
      error("read_corevarint: encoded length exceeds uint64 range")
    end
    local b = r.read_u8()
    -- size check matching ReadVarInt:
    -- if (n > (UINT64_MAX >> 7)) throw "size too large"
    -- UINT64_MAX >> 7 == 0x01FFFFFFFFFFFFFF
    if n > u64_t(0x01FFFFFFFFFFFFFFULL) then
      error("read_corevarint: size too large")
    end
    n = (n * u64_t(128)) + u64_t(b % 128)  -- band 0x7F
    if b >= 0x80 then
      -- not the final byte: increment carry and continue
      n = n + u64_t(1)
    else
      return n
    end
  end
end

--------------------------------------------------------------------------------
-- Amount compression (compressor.cpp:CompressAmount/DecompressAmount).
--
-- Pure integer arithmetic.  All intermediates fit in uint64 because amounts
-- are bounded by MAX_MONEY (21e6 * 1e8 = 2.1e15 < 2^53).  Returned values
-- are LuaJIT cdata uint64 so write_corevarint can consume them directly
-- and so we never lose bits when the compressed value drifts above 2^53.
--------------------------------------------------------------------------------

--- Compress an amount (in satoshis, must be 0 <= n <= MAX_MONEY).
-- @param n number|cdata
-- @return cdata uint64_t
function M.compress_amount(n)
  local v = _to_u64(n)
  if v == u64_t(0) then return u64_t(0) end
  local e = 0
  while (v % u64_t(10) == u64_t(0)) and e < 9 do
    v = v / u64_t(10)
    e = e + 1
  end
  if e < 9 then
    local d = tonumber(v % u64_t(10))
    -- d is in [1..9] because we just divided out all trailing zeros
    v = v / u64_t(10)
    return u64_t(1) + (v * u64_t(9) + u64_t(d - 1)) * u64_t(10) + u64_t(e)
  else
    return u64_t(1) + (v - u64_t(1)) * u64_t(10) + u64_t(9)
  end
end

--- Decompress an amount produced by compress_amount.
-- @param x number|cdata
-- @return number satoshis
function M.decompress_amount(x)
  local v = _to_u64(x)
  if v == u64_t(0) then return 0 end
  v = v - u64_t(1)
  local e = tonumber(v % u64_t(10))
  v = v / u64_t(10)
  local n
  if e < 9 then
    local d = tonumber(v % u64_t(9)) + 1
    v = v / u64_t(9)
    n = v * u64_t(10) + u64_t(d)
  else
    n = v + u64_t(1)
  end
  for _ = 1, e do
    n = n * u64_t(10)
  end
  return tonumber(n)
end

--------------------------------------------------------------------------------
-- Script compression (compressor.cpp:CompressScript/DecompressScript).
--
-- Phase 1 (this commit, per task TODO): we only emit the "raw" branch
--   VARINT(size + 6) + raw_bytes
-- which Core's DecompressScript handles (nSize >= nSpecialScripts case).
-- Compressed types 0x00 (P2PKH) / 0x01 (P2SH) / 0x02-0x05 (P2PK) are read
-- on the load path so we round-trip third-party snapshots, but we do not
-- yet emit them on dump.  This is honest: the file is bigger than Core's
-- but the format is byte-compatible.  TODO: detect the recognized types
-- on dump for byte-for-byte parity with Core.
--------------------------------------------------------------------------------

--- Detect a P2PKH script: OP_DUP OP_HASH160 0x14 <20> OP_EQUALVERIFY OP_CHECKSIG.
-- @param s string
-- @return string|nil 20-byte hash160 or nil
local function _is_p2pkh(s)
  if #s ~= 25 then return nil end
  if s:byte(1) ~= 0x76 or s:byte(2) ~= 0xA9 or s:byte(3) ~= 20
     or s:byte(24) ~= 0x88 or s:byte(25) ~= 0xAC then
    return nil
  end
  return s:sub(4, 23)
end

--- Detect a P2SH script: OP_HASH160 0x14 <20> OP_EQUAL.
-- @param s string
-- @return string|nil 20-byte hash160 or nil
local function _is_p2sh(s)
  if #s ~= 23 then return nil end
  if s:byte(1) ~= 0xA9 or s:byte(2) ~= 20 or s:byte(23) ~= 0x87 then
    return nil
  end
  return s:sub(3, 22)
end

--- Detect a compressed-pubkey-only P2PK: 0x21 <33> OP_CHECKSIG with prefix 0x02/0x03.
-- @param s string
-- @return number|nil prefix (0x02 or 0x03), string|nil 32-byte x-coord
local function _is_p2pk_compressed(s)
  if #s ~= 35 then return nil end
  if s:byte(1) ~= 33 or s:byte(35) ~= 0xAC then return nil end
  local prefix = s:byte(2)
  if prefix ~= 0x02 and prefix ~= 0x03 then return nil end
  return prefix, s:sub(3, 34)
end

--- Compress a scriptPubKey using ScriptCompression.
-- This emits the OUTPUT BYTES (no length prefix) — the caller has already
-- decided whether to lead with VARINT(size+6) or with one of the special
-- type bytes.
--
-- For Phase 1 we always take the "raw" branch.  Recognized types are
-- TODO; the comment above explains why.
--
-- @param script_bytes string
-- @return string serialized form (with size+6 VARINT prefix)
function M.compress_script(script_bytes)
  -- TODO(W-CORE-COMPRESS): emit type-byte forms (0x00..0x05) when
  -- script_bytes matches a recognized template.  For now always fall
  -- through to the raw path so the encoding is unambiguous and
  -- Core-readable.
  local _ = _is_p2pkh
  local _2 = _is_p2sh
  local _3 = _is_p2pk_compressed
  local w = serialize.buffer_writer()
  M.write_corevarint(w, #script_bytes + M.N_SPECIAL_SCRIPTS)
  w.write_bytes(script_bytes)
  return w.result()
end

--- Get the on-disk byte length for a recognized type byte.
-- Mirrors compressor.cpp:GetSpecialScriptSize.
-- @param nSize number type indicator (already in [0..5])
-- @return number raw payload length
local function _special_script_size(nSize)
  if nSize == 0 or nSize == 1 then return 20 end
  if nSize >= 2 and nSize <= 5 then return 32 end
  return 0
end

--- Decompress a scriptPubKey using ScriptCompression.
-- Reads from the buffer_reader and returns the reconstructed scriptPubKey.
-- For type 0x04/0x05 (uncompressed P2PK) we recover the full y-coordinate
-- via libsecp256k1 (compressor.cpp:DecompressScript): build a 33-byte
-- compressed pubkey `(0x02 | (tag & 1)) + x[32]`, parse, and re-serialize
-- as 65-byte uncompressed.  The reconstructed script is the 67-byte form
-- `0x41 + pubkey[65] + 0xAC`.  This matches Core 840k+ snapshots which
-- contain Satoshi-era P2PK coinbases using these tags.
-- @param r buffer_reader
-- @return string script_pubkey
function M.decompress_script(r)
  local nSize = tonumber(M.read_corevarint(r))
  if nSize == 0x00 then
    local h = r.read_bytes(20)
    return "\x76\xa9\x14" .. h .. "\x88\xac"  -- P2PKH
  elseif nSize == 0x01 then
    local h = r.read_bytes(20)
    return "\xa9\x14" .. h .. "\x87"  -- P2SH
  elseif nSize == 0x02 or nSize == 0x03 then
    local x = r.read_bytes(32)
    return "\x21" .. string.char(nSize) .. x .. "\xac"  -- compressed P2PK
  elseif nSize == 0x04 or nSize == 0x05 then
    -- Uncompressed P2PK: build SEC1 compressed input from (tag, x), then
    -- call libsecp256k1 to recover the 65-byte uncompressed pubkey.
    -- Per compressor.cpp:DecompressScript, the compressed prefix is
    --   0x02 | (nSize - 0x02)  == 0x02 for tag 0x04, 0x03 for tag 0x05.
    local x = r.read_bytes(32)
    local compressed = string.char(0x02 + (nSize - 0x04)) .. x
    local uncompressed, err = crypto.decompress_pubkey(compressed)
    if not uncompressed then
      -- Mirror Core: an invalid x-coordinate makes the coin unspendable.
      -- Core leaves the destination empty in that case (see ExtractDestination
      -- on a malformed script); we use OP_RETURN as a flagged-unspendable
      -- placeholder so downstream code can detect and skip it.
      return "\x6a"
    end
    return "\x41" .. uncompressed .. "\xac"  -- 67-byte uncompressed P2PK
  else
    local size = nSize - M.N_SPECIAL_SCRIPTS
    if size > M.MAX_SCRIPT_SIZE then
      -- Core skips overly-long scripts; we do the same for safety.
      r.read_bytes(size)
      return "\x6a"
    end
    return r.read_bytes(size)
  end
end

--- Create snapshot metadata structure.
-- @param network_magic string: 4-byte network identifier
-- @param base_blockhash hash256: hash of snapshot base block
-- @param coins_count number: total UTXO count
-- @return table: snapshot metadata
function M.snapshot_metadata(network_magic, base_blockhash, coins_count)
  return {
    magic = M.SNAPSHOT_MAGIC,
    version = M.SNAPSHOT_VERSION,
    network_magic = network_magic,
    base_blockhash = base_blockhash,
    coins_count = coins_count,
  }
end

--- Serialize snapshot metadata to binary format.
-- @param metadata table: snapshot metadata
-- @return string: serialized metadata
function M.serialize_snapshot_metadata(metadata)
  local w = serialize.buffer_writer()
  w.write_bytes(M.SNAPSHOT_MAGIC)  -- 5 bytes
  w.write_u16le(metadata.version)   -- 2 bytes
  w.write_bytes(metadata.network_magic)  -- 4 bytes
  w.write_hash256(metadata.base_blockhash)  -- 32 bytes
  w.write_u64le(metadata.coins_count)  -- 8 bytes
  return w.result()  -- Total: 51 bytes
end

--- Deserialize snapshot metadata from binary format.
-- @param data string: raw snapshot file header
-- @return table|nil, string|nil: metadata or nil, error message
function M.deserialize_snapshot_metadata(data)
  if #data < 51 then
    return nil, "snapshot metadata too short"
  end

  local r = serialize.buffer_reader(data)

  -- Validate magic bytes
  local magic = r.read_bytes(5)
  if magic ~= M.SNAPSHOT_MAGIC then
    return nil, "invalid snapshot magic bytes"
  end

  local version = r.read_u16le()
  if version > M.SNAPSHOT_VERSION then
    return nil, string.format("unsupported snapshot version %d (max %d)",
      version, M.SNAPSHOT_VERSION)
  end

  local network_magic = r.read_bytes(4)
  local base_blockhash = types.hash256(r.read_bytes(32))
  local coins_count = r.read_u64le()

  return {
    magic = magic,
    version = version,
    network_magic = network_magic,
    base_blockhash = base_blockhash,
    coins_count = coins_count,
  }
end

--- Serialize a coin for snapshot format (Core-byte-compatible).
-- Format matches bitcoin-core/src/coins.h Coin::Serialize:
--   VARINT_core(code = height*2 + coinbase)
--   VARINT_core(CompressAmount(value))
--   ScriptCompression(script_pubkey)
-- where ScriptCompression for the raw branch is VARINT_core(size+6) || raw.
-- @param entry table: UTXO entry
-- @return string: serialized coin (does NOT include vout prefix; the
--                 caller emits CompactSize(vout) before this byte string)
function M.serialize_snapshot_coin(entry)
  local w = serialize.buffer_writer()
  local code = entry.height * 2 + (entry.is_coinbase and 1 or 0)
  M.write_corevarint(w, code)
  M.write_corevarint(w, M.compress_amount(entry.value))
  w.write_bytes(M.compress_script(entry.script_pubkey))
  return w.result()
end

--- Deserialize a coin from Core snapshot format.
-- @param reader buffer_reader: reader positioned at coin data
-- @return table: UTXO entry
function M.deserialize_snapshot_coin(reader)
  local code = tonumber(M.read_corevarint(reader))
  local height = math.floor(code / 2)
  local is_coinbase = (code % 2) == 1
  local compressed_amount = M.read_corevarint(reader)
  local value = M.decompress_amount(compressed_amount)
  local script_pubkey = M.decompress_script(reader)
  return M.utxo_entry(value, script_pubkey, height, is_coinbase)
end

--------------------------------------------------------------------------------
-- Outpoint Key
--------------------------------------------------------------------------------

-- Pre-allocated 36-byte FFI buffer for outpoint key construction.
-- Using ffi.copy + ffi.string avoids the two Lua string allocations
-- (txid.bytes .. string.char(...)) that the old code produced per call.
local _outpoint_buf = ffi.new("uint8_t[36]")

-- Generate a 36-byte key for database lookups (32-byte txid + 4-byte vout index)
-- Hot path: uses FFI buffer to avoid intermediate string allocations.
function M.outpoint_key(txid_hash256, vout_index)
  ffi.copy(_outpoint_buf, txid_hash256.bytes, 32)
  _outpoint_buf[32] = band(vout_index, 0xFF)
  _outpoint_buf[33] = band(rshift(vout_index, 8), 0xFF)
  _outpoint_buf[34] = band(rshift(vout_index, 16), 0xFF)
  _outpoint_buf[35] = band(rshift(vout_index, 24), 0xFF)
  return ffi.string(_outpoint_buf, 36)
end

--------------------------------------------------------------------------------
-- CoinView Cache with Flush Strategy
--------------------------------------------------------------------------------

-- UTXO cache implementation matching Bitcoin Core's CCoinsViewCache.
-- Reference: /home/max/hashhog/bitcoin/src/coins.cpp
--
-- ## Cache Entry Flags
-- - dirty: Entry has been modified since last flush
-- - fresh: Entry was created since last flush (not in parent/disk)
--
-- ## Key Optimization
-- If an entry is FRESH and then spent before flush, we can skip the disk
-- write entirely (the entry never existed on disk, so no delete needed).
--
-- ## Memory Management
-- Track estimated memory usage. Flush when exceeding MAX_CACHE_SIZE.
-- Default: 450MB (configurable via --dbcache)
--
-- ## Cache sizing formula:
--   Base overhead per entry: ~100 bytes (key + metadata + pointers)
--   Script size: variable (avg ~34 bytes for P2WPKH/P2TR)
--   Total per entry: ~180 bytes average
--   450MB / 180 bytes ≈ 2.5M entries

-- Flag constants (matching Bitcoin Core's CCoinsCacheEntry::Flags)
local FLAG_DIRTY = 0x01  -- Entry differs from parent cache
local FLAG_FRESH = 0x02  -- Parent cache does not have this entry

-- Cache entry structure
-- {
--   value = int64,
--   script_pubkey = string,
--   height = uint32,
--   is_coinbase = bool,
--   flags = uint8 (DIRTY | FRESH)
-- }

local CoinView = {}
CoinView.__index = CoinView

-- Default cache size: 450MB — matches Bitcoin Core's default dbcache.
-- A larger cache reduces RocksDB reads and avoids frequent table rebuilds
-- that trigger expensive full GC cycles on large heaps.
local DEFAULT_CACHE_SIZE_MB = 450
local BYTES_PER_MB = 1024 * 1024

-- Estimated memory per cache entry (for memory tracking).
-- LuaJIT hash table entries use ~8-10KB actual RSS per entry due to
-- table node overhead, GC metadata, string interning, and allocator
-- fragmentation.  We use 8KB to trigger eviction early enough.
local BASE_ENTRY_OVERHEAD = 7800
local SCRIPT_OVERHEAD = 200

--- Estimate memory usage of a single cache entry.
-- @param entry table: UTXO entry with script_pubkey
-- @return number: estimated bytes
local function estimate_entry_memory(entry)
  local script_len = entry and entry.script_pubkey and #entry.script_pubkey or SCRIPT_OVERHEAD
  return BASE_ENTRY_OVERHEAD + script_len
end

--- Configure UTXO cache based on dbcache setting.
-- @param opts table: {dbcache=MB}
-- @return number: max cache size in bytes
function M.configure_cache_size(opts)
  local dbcache_mb = opts and opts.dbcache or DEFAULT_CACHE_SIZE_MB
  return dbcache_mb * BYTES_PER_MB
end

--- Create a new CoinView cache.
-- Uses a layered design with metatable fallback to disk.
-- @param storage: database handle
-- @param opts table: {dbcache=MB}
-- @return CoinView
function M.new_coin_view(storage, opts)
  local self = setmetatable({}, CoinView)
  self.storage = storage
  self.max_cache_bytes = M.configure_cache_size(opts)

  -- Main cache: outpoint_key -> {value, script_pubkey, height, is_coinbase, flags}
  -- Uses metatable to provide disk fallback
  self.cache = {}

  -- Track dirty entries in a linked list for efficient iteration during flush
  -- dirty_list[key] = true for all dirty entries
  self.dirty_list = {}
  self.dirty_count = 0

  -- Track memory usage
  self.cached_memory_usage = 0

  -- Persistent write batch: reused across flushes to avoid create/destroy overhead
  self._persistent_batch = storage.batch()

  -- Statistics
  self.stats = {
    hits = 0,
    misses = 0,
    fresh_spent_skipped = 0,  -- entries that were fresh and spent (no disk write)
    disk_reads = 0,
    disk_writes = 0,
    disk_deletes = 0,
    flushes = 0,
  }

  return self
end

--- Check if an entry has the DIRTY flag.
-- @param entry table: cache entry
-- @return boolean
local function is_dirty(entry)
  return entry and entry.flags and bit.band(entry.flags, FLAG_DIRTY) ~= 0
end

--- Check if an entry has the FRESH flag.
-- @param entry table: cache entry
-- @return boolean
local function is_fresh(entry)
  return entry and entry.flags and bit.band(entry.flags, FLAG_FRESH) ~= 0
end

--- Set the DIRTY flag on an entry.
-- @param entry table: cache entry
local function set_dirty(entry)
  entry.flags = bit.bor(entry.flags or 0, FLAG_DIRTY)
end

--- Set the FRESH flag on an entry.
-- @param entry table: cache entry
local function set_fresh(entry)
  entry.flags = bit.bor(entry.flags or 0, FLAG_FRESH)
end

--- Clear all flags on an entry.
-- @param entry table: cache entry
local function clear_flags(entry)
  entry.flags = 0
end

--- Fetch an entry from disk (cache miss).
-- @param self CoinView
-- @param key string: outpoint key
-- @return table|nil: UTXO entry or nil
function CoinView:_fetch_from_disk(key)
  local data = self.storage.get(storage_mod.CF.UTXO, key)
  if not data then return nil end

  self.stats.disk_reads = self.stats.disk_reads + 1
  local entry = M.deserialize_utxo_entry(data)
  entry.flags = 0  -- Not dirty, not fresh (it came from disk)

  return entry
end

--- Get a UTXO entry by txid and vout.
-- Looks up in cache first, falls back to disk.
-- @param txid hash256: transaction ID
-- @param vout number: output index
-- @return table|nil: UTXO entry or nil if spent/not found
function CoinView:get(txid, vout)
  local key = M.outpoint_key(txid, vout)

  -- Check in-memory cache first
  local entry = self.cache[key]
  if entry then
    -- Entry found in cache
    if entry.spent then
      -- Entry exists but is marked as spent
      return nil
    end
    self.stats.hits = self.stats.hits + 1
    return entry
  end

  -- Cache miss - try to load from disk
  self.stats.misses = self.stats.misses + 1
  entry = self:_fetch_from_disk(key)
  if not entry then return nil end

  -- Cache the entry for intra-block lookups.
  -- The cache is cleared completely after each block flush to prevent
  -- LuaJIT hash table memory from growing unboundedly.
  local mem_usage = estimate_entry_memory(entry)
  self.cache[key] = entry
  self.cached_memory_usage = self.cached_memory_usage + mem_usage

  return entry
end

--- Check if a UTXO exists without caching it (like Bitcoin Core's PeekCoin).
-- @param txid hash256: transaction ID
-- @param vout number: output index
-- @return boolean
function CoinView:have(txid, vout)
  local key = M.outpoint_key(txid, vout)

  -- Check cache first
  local entry = self.cache[key]
  if entry then
    return not entry.spent
  end

  -- Check disk
  local data = self.storage.get(storage_mod.CF.UTXO, key)
  return data ~= nil
end

--- Add a new UTXO to the cache.
-- Marks the entry as DIRTY and FRESH.
-- @param txid hash256: transaction ID
-- @param vout number: output index
-- @param entry table: UTXO entry (value, script_pubkey, height, is_coinbase)
function CoinView:add(txid, vout, entry)
  local key = M.outpoint_key(txid, vout)
  local existing = self.cache[key]

  -- Prepare the new entry with flags
  local new_entry = {
    value = entry.value,
    script_pubkey = entry.script_pubkey,
    height = entry.height,
    is_coinbase = entry.is_coinbase,
    flags = 0,
  }

  -- Determine FRESH flag
  -- An entry can only be marked FRESH if it doesn't exist in the parent
  -- (i.e., it was just created and never flushed to disk)
  local mark_fresh = true
  if existing then
    -- If the existing entry was dirty (but not fresh), we can't mark as fresh
    -- because the original might still be on disk
    if is_dirty(existing) and not is_fresh(existing) then
      mark_fresh = false
    end
    -- Update memory tracking
    self.cached_memory_usage = self.cached_memory_usage - estimate_entry_memory(existing)

    -- Remove from dirty list if it was there
    if is_dirty(existing) and self.dirty_list[key] then
      self.dirty_list[key] = nil
      self.dirty_count = self.dirty_count - 1
    end
  else
    -- New entry not in cache - could be on disk, can't assume fresh
    -- Actually, if we're adding, it's typically a new output, so mark fresh
    mark_fresh = true
  end

  -- Set flags
  set_dirty(new_entry)
  if mark_fresh then
    set_fresh(new_entry)
  end

  -- Add to cache and dirty list
  self.cache[key] = new_entry
  self.dirty_list[key] = true
  self.dirty_count = self.dirty_count + 1
  self.cached_memory_usage = self.cached_memory_usage + estimate_entry_memory(new_entry)
end

--- Spend a UTXO (mark as spent).
-- Returns the entry for undo data. The entry remains in cache marked as spent.
-- @param txid hash256: transaction ID
-- @param vout number: output index
-- @return table|nil: spent UTXO entry (for undo data) or nil if not found
-- @return string|nil: error message if not found
function CoinView:spend(txid, vout)
  local key = M.outpoint_key(txid, vout)

  -- First, make sure we have the entry (will fetch from disk if needed)
  local entry = self:get(txid, vout)
  if not entry then
    return nil, "UTXO not found"
  end

  -- Create a copy for undo data before modifying
  local undo_entry = M.utxo_entry(
    entry.value, entry.script_pubkey, entry.height, entry.is_coinbase
  )

  -- Check if this is a fresh entry being spent
  -- If FRESH, we can skip the disk write entirely!
  if is_fresh(entry) then
    self.stats.fresh_spent_skipped = self.stats.fresh_spent_skipped + 1
    -- Remove from cache and dirty list entirely - no disk operation needed
    if self.dirty_list[key] then
      self.dirty_list[key] = nil
      self.dirty_count = self.dirty_count - 1
    end
    self.cached_memory_usage = self.cached_memory_usage - estimate_entry_memory(entry)
    self.cache[key] = nil
    return undo_entry
  end

  -- Not fresh - mark as spent and dirty
  -- The entry stays in cache to track that we need to delete from disk
  entry.spent = true
  if not is_dirty(entry) then
    set_dirty(entry)
    self.dirty_list[key] = true
    self.dirty_count = self.dirty_count + 1
  end

  return undo_entry
end

--- Check if cache should be flushed based on memory usage.
-- @return boolean
function CoinView:should_flush()
  return self.cached_memory_usage >= self.max_cache_bytes
end

--- Flush dirty entries to disk.
-- Writes modified entries and deletes spent entries.
-- @param reallocate boolean: if true, clear cache after flush (default: false)
-- @param extra_batch_fn function|nil: optional callback(batch) to add extra
--        operations to the same atomic write batch (e.g. chain tip update)
-- @param sync boolean|nil: if true, force sync write (default: false)
function CoinView:flush(reallocate, extra_batch_fn, sync)
  if self.dirty_count == 0 and not extra_batch_fn then return end

  -- Reuse persistent batch to avoid create/destroy overhead per flush
  local batch = self._persistent_batch
  batch.clear()
  local writes = 0
  local deletes = 0

  for key, _ in pairs(self.dirty_list) do
    local entry = self.cache[key]
    if entry then
      if entry.spent then
        -- Delete from disk (entry was spent and was on disk)
        batch.delete(storage_mod.CF.UTXO, key)
        deletes = deletes + 1
        -- Remove from cache
        self.cached_memory_usage = self.cached_memory_usage - estimate_entry_memory(entry)
        self.cache[key] = nil
      else
        -- Write to disk
        local data = M.serialize_utxo_entry(entry)
        batch.put(storage_mod.CF.UTXO, key, data)
        writes = writes + 1
        -- Clear flags - entry is now clean and not fresh (it's on disk)
        clear_flags(entry)
      end
    end
  end

  -- Allow caller to add extra operations (e.g. chain tip) to the same batch
  if extra_batch_fn then
    extra_batch_fn(batch)
  end

  -- Execute batch
  batch.write(sync or false)

  -- Update stats
  self.stats.disk_writes = self.stats.disk_writes + writes
  self.stats.disk_deletes = self.stats.disk_deletes + deletes
  self.stats.flushes = self.stats.flushes + 1

  -- Clear dirty tracking
  self.dirty_list = {}
  self.dirty_count = 0

  -- Optionally reallocate (clear) the cache
  if reallocate then
    self.cache = {}
    self.cached_memory_usage = 0
    -- Incremental GC step to nudge collection without traversing the
    -- entire heap (full collect on a multi-GB heap causes GC thrashing).
    collectgarbage("step", 100)
  else
    -- Evict clean entries when cache exceeds the limit.
    -- LuaJIT doesn't shrink hash tables on deletion, so we rebuild
    -- the table with only the entries we want to keep.  This forces
    -- a fresh allocation and lets the old table be GC'd.
    if self.cached_memory_usage > self.max_cache_bytes then
      local new_cache = {}
      local new_usage = 0
      local target = self.max_cache_bytes / 4
      for key, entry in pairs(self.cache) do
        if is_dirty(entry) or (new_usage < target and not entry.spent) then
          new_cache[key] = entry
          new_usage = new_usage + estimate_entry_memory(entry)
        end
      end
      self.cache = new_cache
      self.cached_memory_usage = new_usage
      -- Incremental GC step to nudge collection of the old table
      collectgarbage("step", 100)
    end
  end
end

--- Sync dirty entries to disk without clearing the cache.
-- Like flush but keeps entries in cache (just clears dirty flags).
function CoinView:sync()
  self:flush(false)
end

--- Clear the cache without flushing.
-- WARNING: This will lose unflushed changes!
function CoinView:clear_cache()
  self.cache = {}
  self.dirty_list = {}
  self.dirty_count = 0
  self.cached_memory_usage = 0
end

--- Discard all dirty (uncommitted) cache mutations.
-- Used by connect_block on validation failure: if we're partway through a
-- block and `assert(...)` fires (e.g. tapscript SCRIPT_SIZE), the in-memory
-- cache has already been mutated by `:spend(...)` and `:add(...)` calls for
-- earlier transactions in the block. The flush at the end of connect_block
-- never ran, so on-disk state is still consistent — but the cache contains
-- spent entries and fresh adds that don't exist on disk. A retry of the same
-- block (or a sibling block) would then see "Missing UTXO" because spent
-- entries return nil from :get(). This method drops every dirty entry
-- (spent or fresh-added) so the cache mirrors disk again. Clean entries
-- are kept (they are read-only caches, not mutations).
--
-- Closes the secondary symptom of the 944,186 wedge: tapscript SCRIPT_SIZE
-- failed mid-block, then retries reported "Missing UTXO for input 1 of tx
-- 98a09ed2..." because that tx's input had been pre-spent in the cache by
-- the failed first attempt.
function CoinView:discard_dirty()
  for key, _ in pairs(self.dirty_list) do
    local entry = self.cache[key]
    if entry then
      self.cached_memory_usage = self.cached_memory_usage - estimate_entry_memory(entry)
      self.cache[key] = nil
    end
  end
  self.dirty_list = {}
  self.dirty_count = 0
end

--- Remove an entry from cache if it's not dirty.
-- Used to free memory for entries we don't need anymore.
-- @param txid hash256: transaction ID
-- @param vout number: output index
function CoinView:uncache(txid, vout)
  local key = M.outpoint_key(txid, vout)
  local entry = self.cache[key]
  if entry and not is_dirty(entry) then
    self.cached_memory_usage = self.cached_memory_usage - estimate_entry_memory(entry)
    self.cache[key] = nil
  end
end

--- Get the number of entries in cache.
-- @return number
function CoinView:get_cache_size()
  local count = 0
  for _ in pairs(self.cache) do
    count = count + 1
  end
  return count
end

--- Get the number of dirty entries.
-- @return number
function CoinView:get_dirty_count()
  return self.dirty_count
end

--- Get estimated memory usage in bytes.
-- @return number
function CoinView:get_memory_usage()
  return self.cached_memory_usage
end

--- Get cache statistics.
-- @return table: stats including hits, misses, disk operations, etc.
function CoinView:cache_stats()
  local total_lookups = self.stats.hits + self.stats.misses
  return {
    -- Lookup stats
    hits = self.stats.hits,
    misses = self.stats.misses,
    hit_rate = total_lookups > 0 and (self.stats.hits / total_lookups) or 0,

    -- Cache state
    count = self:get_cache_size(),
    dirty_count = self.dirty_count,
    memory_usage = self.cached_memory_usage,
    max_memory = self.max_cache_bytes,

    -- I/O stats
    disk_reads = self.stats.disk_reads,
    disk_writes = self.stats.disk_writes,
    disk_deletes = self.stats.disk_deletes,
    flushes = self.stats.flushes,

    -- Optimization stats
    fresh_spent_skipped = self.stats.fresh_spent_skipped,
  }
end

--- Perform a sanity check on the cache state.
-- Verifies internal consistency (for debugging).
-- @return boolean: true if consistent
-- @return string|nil: error message if inconsistent
function CoinView:sanity_check()
  local computed_dirty = 0
  local computed_memory = 0

  for key, entry in pairs(self.cache) do
    computed_memory = computed_memory + estimate_entry_memory(entry)

    if is_dirty(entry) then
      computed_dirty = computed_dirty + 1
      if not self.dirty_list[key] then
        return false, "dirty entry not in dirty_list: " .. key
      end
    end

    -- Spent entries must be dirty (unless fresh, in which case they're removed)
    if entry.spent and not is_dirty(entry) then
      return false, "spent entry not dirty: " .. key
    end

    -- An unspent entry shouldn't be fresh if not dirty
    if not entry.spent and is_fresh(entry) and not is_dirty(entry) then
      return false, "fresh but not dirty entry: " .. key
    end
  end

  -- Verify dirty list matches
  for key in pairs(self.dirty_list) do
    local entry = self.cache[key]
    if not entry or not is_dirty(entry) then
      return false, "dirty_list entry not in cache or not dirty: " .. key
    end
  end

  if computed_dirty ~= self.dirty_count then
    return false, string.format("dirty_count mismatch: computed=%d, tracked=%d",
      computed_dirty, self.dirty_count)
  end

  return true
end

--------------------------------------------------------------------------------
-- ChainState Manager
--------------------------------------------------------------------------------

local ChainState = {}
ChainState.__index = ChainState

function M.new_chain_state(storage, network)
  local self = setmetatable({}, ChainState)
  self.storage = storage
  self.network = network or consensus.networks.mainnet
  self.coin_view = M.new_coin_view(storage)
  self.tip_hash = nil
  self.tip_height = -1
  -- Set of invalidated block hashes (keyed by hash bytes for fast lookup)
  self.invalid_blocks = {}
  -- Signature verification cache (avoids re-verifying scripts during IBD/reorg)
  self.sig_cache = sig_cache.new(50000)
  -- Optional notification callbacks (for ZMQ, etc.)
  self.callbacks = {
    on_block_connected = nil,     -- function(block_hash, block_data)
    on_block_disconnected = nil,  -- function(block_hash)
  }
  -- W77-CB: rolling-window sub-phase breakdown of connect_block.  W75-CONN
  -- in sync.lua measures the callback as a black box (cb_avg ≈ 700–850ms
  -- during IBD, dominating the ~900ms/block budget).  This inner window
  -- breaks that time into tx_loop / parallel_verify / undo_write /
  -- utxo_flush / callback so we can identify which phase is actually slow.
  self.cb_log_every = 500
  self.cb_lifetime = 0
  self.cb_win = { n = 0, tx_loop_t = 0, parallel_t = 0, undo_t = 0,
                  flush_t = 0, cb_t = 0, total_t = 0,
                  tx_max = 0, flush_max = 0, total_max = 0 }
  return self
end

function ChainState:init()
  local hash, height = self.storage.get_chain_tip()
  if hash then
    self.tip_hash = hash
    self.tip_height = height
  else
    -- No chain tip stored yet: build and connect the genesis block
    self:connect_genesis()
  end
  -- Load invalid blocks set from storage
  self:load_invalid_blocks()
end

--- Build and connect the genesis block to initialize the chain.
-- Called when no chain tip is found in storage (fresh start).
function ChainState:connect_genesis()
  local gen = self.network.genesis

  -- Build the genesis coinbase transaction exactly matching Bitcoin Core
  -- scriptSig: PUSH4(486604799_le) PUSH1(0x04) PUSH_N(message)
  -- Note: Bitcoin Core always uses 486604799 (0x1d00ffff) in genesis scriptSig
  -- regardless of network, as it's hardcoded in CreateGenesisBlock.
  local msg = gen.coinbase_message
  -- 486604799 = 0x1d00ffff, LE = ff ff 00 1d
  local bits_le = "\xff\xff\x00\x1d"
  -- scriptSig: 04 <bits_le> 01 04 <len> <message>
  local script_sig = "\x04" .. bits_le .. "\x01\x04" .. string.char(#msg) .. msg

  local coinbase_input = types.txin(
    types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
    script_sig,
    0xFFFFFFFF
  )

  -- Genesis coinbase output: 50 BTC to pubkey
  -- Use network-specific pubkey if provided, otherwise default to Satoshi's key
  local subsidy = consensus.get_block_subsidy(0)
  local pubkey_hex = gen.coinbase_pubkey_hex or "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
  local pubkey = ""
  for i = 1, #pubkey_hex, 2 do
    pubkey = pubkey .. string.char(tonumber(pubkey_hex:sub(i, i+1), 16))
  end
  -- OP_PUSH<len> <pubkey> OP_CHECKSIG
  local output_script = string.char(#pubkey) .. pubkey .. "\xac"
  local coinbase_output = types.txout(subsidy, output_script)

  local coinbase_tx = types.transaction(1, {coinbase_input}, {coinbase_output}, 0)

  -- Compute merkle root (single tx)
  local txid = validation.compute_txid(coinbase_tx)
  local merkle_root = txid  -- single tx: merkle root == txid

  -- Build genesis block header with correct merkle root
  local header = types.block_header(
    gen.version,
    types.hash256_zero(),
    merkle_root,
    gen.timestamp,
    gen.bits,
    gen.nonce
  )

  local block_hash = validation.compute_block_hash(header)
  local block = types.block(header, {coinbase_tx})

  -- Store the full block and header
  self.storage.put_block(block_hash, block)
  self.storage.put_header(block_hash, header)
  self.storage.put_height_index(0, block_hash)

  -- Add the coinbase UTXO to the UTXO set
  -- Note: genesis coinbase is technically unspendable in Bitcoin Core,
  -- but we still add it for consistency
  for vout_idx, out in ipairs(coinbase_tx.outputs) do
    if #out.script_pubkey == 0 or out.script_pubkey:byte(1) ~= 0x6a then
      self.coin_view:add(txid, vout_idx - 1, M.utxo_entry(
        out.value, out.script_pubkey, 0, true
      ))
    end
  end
  self.coin_view:flush()

  -- Set chain tip to genesis
  self.tip_hash = block_hash
  self.tip_height = 0
  self.storage.set_chain_tip(block_hash, 0, true)
end

--- Reindex the chainstate from on-disk blocks. Used to recover from a
-- corrupt UTXO set (e.g., the post-EMFILE wedge documented in
-- project_lunarblock_wedge_2026_04_28).
--
-- Walks CF.UTXO and CF.UNDO and deletes everything, then iterates the
-- height-index from height 1 to header_tip_height, re-executing
-- connect_block on each block in order. The genesis block's UTXO set
-- is reseeded by re-applying the genesis coinbase outputs (same shape
-- as connect_genesis but without put_block, since genesis is already
-- in storage).
--
-- Script validation is skipped during reindex (the blocks were
-- validated when they were first downloaded and the chain tip the
-- header chain knows about is what we trust).
--
-- @param header_tip_height number: the height to replay up to (usually
--        the current header_chain.header_tip_height — the highest
--        block whose body lives in CF.BLOCKS).
-- @param progress_fn function|nil: optional callback (height, total)
--        invoked every 1000 blocks for progress logging.
function ChainState:reindex_chainstate(header_tip_height, progress_fn)
  local _t0 = perf.now()

  -- 1. Wipe CF.UTXO and CF.UNDO. We do this in 64k-key batches so a
  --    multi-million-row UTXO set doesn't become one giant write batch.
  local function wipe_cf(cf, label)
    local iter = self.storage.iterator(cf)
    iter.seek_to_first()
    local batch = self.storage.batch()
    local count = 0
    local total = 0
    while iter.valid() do
      batch.delete(cf, iter.key())
      count = count + 1
      total = total + 1
      if count >= 65536 then
        batch.write(false)
        batch.clear()
        count = 0
        if progress_fn then
          progress_fn(string.format("reindex: wiped %s %d keys", label, total), nil)
        end
      end
      iter.next()
    end
    if count > 0 then
      batch.write(false)
    end
    batch.destroy()
    iter.destroy()
    -- Final sync to make sure the wipe is durable.
    self.storage.set_chain_tip(types.hash256_zero(), 0, true)
    return total
  end

  local utxos_wiped = wipe_cf(storage_mod.CF.UTXO, "CF.UTXO")
  local undos_wiped = wipe_cf(storage_mod.CF.UNDO, "CF.UNDO")
  if progress_fn then
    progress_fn(string.format("reindex: wiped %d utxos, %d undos", utxos_wiped, undos_wiped), nil)
  end

  -- 2. Reset in-memory chainstate.
  self.coin_view:clear_cache()
  self.tip_hash = nil
  self.tip_height = -1

  -- 3. Reseed genesis. We can't call connect_genesis (it puts the
  --    block to storage; genesis is already there). Instead, replay
  --    the genesis coinbase output add and set chain_tip = 0.
  local gen_hash = self.storage.get_hash_by_height(0)
  if not gen_hash then
    return nil, "reindex: genesis block missing from height index"
  end
  local gen_block = self.storage.get_block(gen_hash)
  if not gen_block then
    return nil, "reindex: genesis block body missing from CF.BLOCKS"
  end
  local gen_coinbase = gen_block.transactions[1]
  local gen_txid = validation.compute_txid(gen_coinbase)
  for vout_idx, out in ipairs(gen_coinbase.outputs) do
    if #out.script_pubkey == 0 or out.script_pubkey:byte(1) ~= 0x6a then
      self.coin_view:add(gen_txid, vout_idx - 1, M.utxo_entry(
        out.value, out.script_pubkey, 0, true
      ))
    end
  end
  self.coin_view:flush(false, function(batch)
    local w = serialize.buffer_writer()
    w.write_hash256(gen_hash)
    w.write_u32le(0)
    batch.put(storage_mod.CF.META, "chain_tip", w.result())
  end, true)
  self.tip_hash = gen_hash
  self.tip_height = 0

  -- 4. Replay blocks 1 → header_tip_height.
  local _last_progress_t = perf.now()
  for height = 1, header_tip_height do
    local block_hash = self.storage.get_hash_by_height(height)
    if not block_hash then
      return nil, string.format("reindex: missing height index for h=%d (header_tip=%d)",
        height, header_tip_height)
    end
    local block = self.storage.get_block(block_hash)
    if not block then
      return nil, string.format("reindex: missing block body for h=%d hash=%s",
        height, types.hash256_hex(block_hash))
    end
    -- Skip script validation during reindex: blocks were validated when
    -- they were first downloaded. Use nosync=true (the periodic sync at
    -- every 200 blocks in the IBD loop is mirrored by the explicit
    -- sync flush below every 5000 blocks).
    local ok, err = self:connect_block(
      block, height, block_hash, nil, nil, true, nil, true, nil)
    if not ok then
      return nil, string.format("reindex: connect_block failed at h=%d: %s",
        height, tostring(err))
    end
    if height % 5000 == 0 then
      -- Force fsync to bound recovery cost if reindex is interrupted.
      self.coin_view:flush(false, nil, true)
    end
    if progress_fn and (height % 1000 == 0 or perf.now() - _last_progress_t > 5) then
      progress_fn(nil, height)
      _last_progress_t = perf.now()
    end
  end

  -- 5. Final sync.
  self.coin_view:flush(false, nil, true)
  local _t1 = perf.now()
  return true, string.format("reindex complete: %d blocks in %.1fs",
    header_tip_height, _t1 - _t0)
end

--- Verify post-restart chainstate consistency and auto-rollback if a
--- previously-applied block has missing UTXOs (BUG-REPORT.md fix #3).
---
--- Walks back `max_blocks` from the current tip; for each block, fetches
--- the block body from CF.BLOCKS and checks that every input in the first
--- `txs_per_block` non-coinbase transactions resolves to a UTXO either
--- still in CF.UTXO or in the block's own undo data (i.e. it WAS in
--- CF.UTXO before connect_block spent it). If a block fails the check,
--- we keep walking back (each failed block becomes a candidate for
--- rollback) until we find the highest height H where consistency holds.
--- We then disconnect every block from current tip down to H+1, leaving
--- chain_tip at H. On the next IBD pass, blocks H+1, H+2, ... will be
--- re-downloaded and re-applied — at which point the operator's choices
--- diverge:
---
---   - If the rollback restored consistency, IBD resumes cleanly.
---   - If even the rolled-back state fails to apply the next block (i.e.
---     the corruption is older than `max_blocks`), the bounded retry in
---     sync.lua's connect_pending_blocks (cb_fail_threshold) surfaces a
---     clear "run --reindex-chainstate" error.
---
--- Defence-in-depth: if disconnect_block fails (e.g. missing undo data),
--- we surface the partial-rollback height to the caller so the operator
--- knows the auto-recovery is incomplete and `--reindex-chainstate` is
--- needed.
---
--- @param max_blocks number|nil: how far back to scan (default 200).
---        Anything older than this predates a reasonable crash window;
---        if it's corrupt, --reindex-chainstate is the right tool, not
---        rollback.
--- @param txs_per_block number|nil: number of non-coinbase transactions
---        per block to spot-check (default 5). The wedge symptom (a
---        single tx with a missing input) is detectable from any tx; we
---        don't need to scan all of them on every restart.
--- @return number, number, table: (rolled_back_count, final_tip_height,
---        details_table). details_table has fields:
---          - found_inconsistency: bool
---          - first_bad_height: number|nil  (highest h with missing UTXO)
---          - reason: string|nil  (description of the miss)
---          - undo_missing: bool  (true if a rollback failed for lack of undo)
function ChainState:verify_chainstate_consistency(max_blocks, txs_per_block)
  max_blocks = max_blocks or 200
  txs_per_block = txs_per_block or 5

  local details = {
    found_inconsistency = false,
    first_bad_height = nil,
    reason = nil,
    undo_missing = false,
  }

  if not self.tip_hash or self.tip_height < 1 then
    return 0, self.tip_height or 0, details
  end

  -- Walk back from tip, looking for the highest block whose inputs are
  -- inconsistent with the chainstate. This is the "bad" block we'll roll
  -- back through. Stop at the first height where the invariant holds AND
  -- nothing above it has been flagged. (i.e. first_bad_height tracks the
  -- highest known-bad; we roll back to one below that.)
  local check_until_height = math.max(self.tip_height - max_blocks + 1, 1)
  local h = self.tip_height
  while h >= check_until_height do
    local block_hash = self.storage.get_hash_by_height(h)
    if not block_hash then
      -- Missing height-index entry — inconsistency, but unrelated to UTXO.
      -- Don't trigger rollback for this; it's a separate corruption mode.
      break
    end
    local block_data = self.storage.get(storage_mod.CF.BLOCKS, block_hash.bytes)
    if not block_data then
      -- Block body missing for an applied block: chain_tip diverged from
      -- block storage (Apr 28 wedge symptom). Mark as bad.
      details.found_inconsistency = true
      details.first_bad_height = h
      details.reason = string.format(
        "block body missing for applied height %d (hash=%s)",
        h, types.hash256_hex(block_hash))
      h = h - 1
      goto continue
    end
    local ok_d, block = pcall(serialize.deserialize_block, block_data)
    if not ok_d or not block then
      details.found_inconsistency = true
      details.first_bad_height = h
      details.reason = string.format(
        "block body unparseable at height %d: %s",
        h, tostring(block))
      h = h - 1
      goto continue
    end

    -- For each non-coinbase tx (up to txs_per_block), check inputs.
    -- An input is "consistent" iff its outpoint is either:
    --   (a) currently in CF.UTXO (hasn't been spent since), OR
    --   (b) recorded in this block's undo data (was spent BY this block,
    --       which means it was in CF.UTXO when we connected — fine).
    local block_undo_raw = self.storage.get_undo(block_hash)
    local block_undo = nil
    if block_undo_raw then
      local ok_u, parsed = pcall(M.deserialize_block_undo, block_undo_raw)
      if ok_u then block_undo = parsed end
    end

    local block_consistent = true
    local checked = 0
    for tx_idx = 2, #block.transactions do  -- skip coinbase
      if checked >= txs_per_block then break end
      local tx = block.transactions[tx_idx]
      checked = checked + 1
      for inp_idx, inp in ipairs(tx.inputs) do
        local in_utxo = self.coin_view:get(inp.prev_out.hash, inp.prev_out.index) ~= nil
        local in_undo = false
        if block_undo and block_undo.tx_undo then
          local tx_undo = block_undo.tx_undo[tx_idx - 1]
          if tx_undo and tx_undo.prev_outputs and tx_undo.prev_outputs[inp_idx] then
            in_undo = true
          end
        end
        if not in_utxo and not in_undo then
          block_consistent = false
          details.found_inconsistency = true
          details.first_bad_height = h
          details.reason = string.format(
            "h=%d tx=%s input %d: outpoint %s:%d not in UTXO or undo",
            h, types.hash256_hex(validation.compute_txid(tx)),
            inp_idx,
            types.hash256_hex(inp.prev_out.hash),
            inp.prev_out.index)
          break
        end
      end
      if not block_consistent then break end
    end

    if block_consistent then
      -- Found the highest known-good block. Stop walking back.
      break
    end

    h = h - 1
    ::continue::
  end

  if not details.found_inconsistency then
    return 0, self.tip_height, details
  end

  -- Roll back blocks from current tip down to first_bad_height (inclusive).
  -- Each disconnect uses the block's stored undo data to restore the UTXO
  -- set. If undo data is missing, we cannot safely roll back further; we
  -- stop and surface the partial-recovery height.
  local rollback_target = details.first_bad_height - 1
  if rollback_target < 0 then rollback_target = 0 end

  local rolled = 0
  while self.tip_height > rollback_target do
    local current_height = self.tip_height
    local current_hash = self.tip_hash
    local block_data = self.storage.get(storage_mod.CF.BLOCKS, current_hash.bytes)
    if not block_data then
      -- Missing block body for the current tip: cannot disconnect
      -- properly. Fall back to a manual chain_tip overwrite (advance
      -- the tip pointer down without disconnecting outputs/inputs).
      -- The result is a chainstate that may have stale UTXO entries,
      -- but it's no worse than what triggered the rollback. The
      -- bounded retry in sync.lua will re-download and re-apply.
      details.undo_missing = true
      break
    end
    local ok_d, block = pcall(serialize.deserialize_block, block_data)
    if not ok_d or not block then
      details.undo_missing = true
      break
    end
    -- Compute previous-block hash from the block header.
    local prev_hash = block.header.prev_hash
    local ok_dis, dis_err = self:disconnect_block(block, current_height,
      current_hash, prev_hash)
    if not ok_dis then
      details.undo_missing = true
      details.reason = (details.reason or "") ..
        string.format(" | disconnect_block failed at h=%d: %s",
          current_height, tostring(dis_err))
      break
    end
    rolled = rolled + 1
  end

  -- Make the rollback durable.
  self.coin_view:flush(false, nil, true)

  return rolled, self.tip_height, details
end

--- Load invalid blocks set from persistent storage.
function ChainState:load_invalid_blocks()
  local data = self.storage.get(storage_mod.CF.META, "invalid_blocks")
  if not data then
    self.invalid_blocks = {}
    return
  end

  -- Format: concatenation of 32-byte hashes
  self.invalid_blocks = {}
  local i = 1
  while i + 31 <= #data do
    local hash_bytes = data:sub(i, i + 31)
    self.invalid_blocks[hash_bytes] = true
    i = i + 32
  end
end

--- Save invalid blocks set to persistent storage.
function ChainState:save_invalid_blocks()
  local parts = {}
  for hash_bytes, _ in pairs(self.invalid_blocks) do
    parts[#parts + 1] = hash_bytes
  end
  -- Sort for deterministic ordering
  table.sort(parts)
  local data = table.concat(parts)
  self.storage.put(storage_mod.CF.META, "invalid_blocks", data, true)
end

--- Check if a block is marked as invalid.
-- @param block_hash hash256: The block hash to check
-- @return boolean: true if the block is invalid
function ChainState:is_block_invalid(block_hash)
  return self.invalid_blocks[block_hash.bytes] == true
end

--- Check if a block has an invalid ancestor.
-- @param block_hash hash256: The block hash to check
-- @return boolean: true if any ancestor is invalid
function ChainState:has_invalid_ancestor(block_hash)
  local current_hash = block_hash
  while current_hash do
    if self:is_block_invalid(current_hash) then
      return true
    end
    -- Get parent
    local header = self.storage.get_header(current_hash)
    if not header then
      break
    end
    -- Check if we've reached genesis (all-zero prev_hash)
    if header.prev_hash.bytes == string.rep("\0", 32) then
      break
    end
    current_hash = header.prev_hash
  end
  return false
end

--------------------------------------------------------------------------------
-- Connect Block
--------------------------------------------------------------------------------

--- Connect a block to the chain, updating the UTXO set.
-- @param block The block to connect
-- @param height The height of the block
-- @param block_hash The hash of the block
-- @param prev_block_mtp The median time past of the previous block (for BIP68)
-- @param get_block_mtp Function to get MTP for a given height (for BIP68)
-- @param skip_script_validation If true, skip script verification (assumevalid optimization)
-- @param use_parallel If true, attempt parallel signature verification (default: auto)
-- @param nosync If true, skip fsync on flush (caller is responsible for periodic sync)
-- @param caller_batch_fn function|nil: optional callback(batch) to add extra operations
--        (e.g. block/header/height_index storage) to the same atomic write batch
-- @return true on success, nil and error message on failure
function ChainState:connect_block(block, height, block_hash, prev_block_mtp, get_block_mtp, skip_script_validation, use_parallel, nosync, caller_batch_fn)
  local _cb_t0 = perf.now()

  -- Build undo data as we go - one TxUndo per non-coinbase transaction
  local block_undo = M.block_undo({})
  local total_fees = 0
  local total_sigop_cost = 0

  -- Check if BIP68 (CSV) is active at this height
  local enforce_bip68 = height >= self.network.csv_height

  -- ContextualCheckBlock: enforce IsFinalTx for every transaction
  -- (Bitcoin Core validation.cpp:4146). Consensus rule — runs even under
  -- skip_script_validation (assumevalid only skips script verification).
  -- lock_time_cutoff = MTP when BIP-113/CSV is active, block timestamp otherwise.
  local lock_time_cutoff
  if enforce_bip68 and prev_block_mtp then
    lock_time_cutoff = prev_block_mtp
  else
    lock_time_cutoff = block.header.timestamp
  end
  for _, tx in ipairs(block.transactions) do
    if not mining.is_final_tx(tx, height, lock_time_cutoff) then
      return nil, "non-final transaction: bad-txns-nonfinal"
    end
  end

  -- Flags for sigop counting (depends on height)
  local sigop_flags = {
    verify_p2sh = height >= self.network.bip34_height,
    verify_witness = height >= self.network.segwit_height,
  }

  -- Determine if we should use parallel verification
  -- Auto-detect: use parallel if available and block has enough inputs
  --
  -- 2026-05-02 (initial): deferred-collect was broken for OP_CHECKMULTISIG:
  -- make_collecting_sig_checker.check_sig returned true unconditionally so
  -- script.lua's OP_CHECKMULTISIG advanced isig/ikey on what would be a
  -- FAILING (sig, pubkey) pair under immediate-verify semantics, then the
  -- batch ECDSA pass at the end rejected those mismatched pairs. Symptom
  -- on mainnet block 944,184 (post-snapshot, post-assumevalid): "Parallel
  -- signature verification failed: signature verification failed at
  -- index 19".
  --
  -- 2026-05-02 (fix): script.has_multisig_op now lets the per-input call
  -- site detect CHECKMULTISIG-bearing scripts and pass inline_verify=true
  -- to make_collecting_sig_checker. The collector then verifies inline
  -- (returning the real result) for those inputs while non-multisig
  -- inputs (single-sig P2WPKH/P2PKH/P2TR keypath — the dominant case)
  -- still get the parallel batch speedup. Default flipped back ON.
  --
  -- The LUNARBLOCK_PARALLEL_VERIFY env var is preserved as a
  -- belt-and-suspenders kill switch:
  --   - "0" or "off" → force off (emergency disable, never use parallel)
  --   - unset / anything else → default on (auto-detect by input count)
  local parallel_available = validation.parallel_verify_available()
  local parallel_env = os.getenv("LUNARBLOCK_PARALLEL_VERIFY")
  local parallel_kill_switch = (parallel_env == "0") or (parallel_env == "off")
  local use_parallel_verify = false
  if use_parallel == nil then
    -- Auto: ON by default. Disabled only if kill switch set or pool unavailable.
    if not parallel_kill_switch and parallel_available and not skip_script_validation then
      local total_inputs = 0
      for i = 2, #block.transactions do  -- Skip coinbase
        total_inputs = total_inputs + #block.transactions[i].inputs
      end
      use_parallel_verify = total_inputs >= 16
    end
  else
    use_parallel_verify = use_parallel and parallel_available and not parallel_kill_switch
  end

  -- Collect signatures for parallel verification
  local parallel_sigs = use_parallel_verify and {} or nil

  for tx_idx, tx in ipairs(block.transactions) do
    local txid = validation.compute_txid(tx)
    local is_coinbase = (tx_idx == 1)

    if is_coinbase then
      -- Coinbase only has legacy sigops (no UTXOs to look up)
      local coinbase_sigops = validation.get_legacy_sigop_count(tx) * consensus.WITNESS_SCALE_FACTOR
      total_sigop_cost = total_sigop_cost + coinbase_sigops
    else
      -- First pass: collect UTXOs and check BIP68 sequence locks
      -- We need to look up all UTXOs before we can check sequence locks
      local utxo_cache = {}  -- inp_idx -> utxo

      for inp_idx, inp in ipairs(tx.inputs) do
        -- Look up the UTXO being spent
        local utxo = self.coin_view:get(inp.prev_out.hash, inp.prev_out.index)
        assert(utxo, string.format("Missing UTXO for input %d of tx %s",
          inp_idx, types.hash256_hex(txid)))
        utxo_cache[inp_idx] = utxo
      end

      -- Build a reverse map from input object identity to index for O(1) lookup.
      -- Avoids O(n) linear scan in get_prev_output / get_utxo_height callbacks.
      local inp_to_idx = {}
      for idx, input in ipairs(tx.inputs) do
        inp_to_idx[input] = idx
      end

      -- Calculate sigop cost for this transaction
      local function get_prev_output(inp)
        local idx = inp_to_idx[inp]
        return idx and utxo_cache[idx] or nil
      end
      local tx_sigop_cost = validation.get_transaction_sigop_cost(tx, get_prev_output, sigop_flags)
      total_sigop_cost = total_sigop_cost + tx_sigop_cost

      -- BIP68: Check relative lock-times (sequence locks)
      -- Only enforce if BIP68 is active and we have the required MTP information
      if enforce_bip68 and tx.version >= 2 and prev_block_mtp and get_block_mtp then
        -- Helper to get UTXO height for each input
        local function get_utxo_height(inp)
          local idx = inp_to_idx[inp]
          return idx and utxo_cache[idx].height or nil
        end

        -- Calculate and check sequence locks
        local min_height, min_time = validation.calculate_sequence_locks(
          tx, height, get_utxo_height, get_block_mtp, enforce_bip68
        )

        assert(validation.check_sequence_locks(min_height, min_time, height, prev_block_mtp),
          string.format("BIP68 sequence locks not satisfied for tx %s (min_height=%d >= %d or min_time=%d >= %d)",
            types.hash256_hex(txid), min_height, height, min_time, prev_block_mtp))
      end

      -- Second pass: validate each input and collect undo data
      local input_total = 0
      local tx_undo = M.tx_undo({})

      for inp_idx, inp in ipairs(tx.inputs) do
        local utxo = utxo_cache[inp_idx]

        -- Save the UTXO for undo data BEFORE spending
        tx_undo.prev_outputs[inp_idx] = M.utxo_entry(
          utxo.value, utxo.script_pubkey, utxo.height, utxo.is_coinbase
        )

        -- Coinbase maturity check
        if utxo.is_coinbase then
          assert(height - utxo.height >= consensus.COINBASE_MATURITY,
            "Coinbase output not mature")
        end

        -- Script verification (skip if assumevalid optimization is active)
        if not skip_script_validation then
          -- Compute cache key flags as a bitmask
          local cache_flags = 0
          if height >= self.network.bip34_height then cache_flags = cache_flags + 1 end     -- P2SH
          if height >= self.network.bip66_height then cache_flags = cache_flags + 2 end     -- DERSIG
          if height >= self.network.bip65_height then cache_flags = cache_flags + 4 end     -- CLTV
          if height >= self.network.csv_height then cache_flags = cache_flags + 8 end       -- CSV
          if height >= self.network.segwit_height then cache_flags = cache_flags + 16 end   -- WITNESS

          -- Check signature cache first
          local txid_bytes = txid.bytes
          if self.sig_cache:lookup(txid_bytes, inp_idx, cache_flags) then
            goto skip_verification
          end

          -- Consensus-only script flags (MANDATORY_SCRIPT_VERIFY_FLAGS parity).
          -- verify_nullfail and verify_witness_pubkeytype are policy-only
          -- (STANDARD_SCRIPT_VERIFY_FLAGS per Bitcoin Core policy/policy.h:125,128)
          -- and must NOT be set in the block-connect validation path.
          local flags = {
            verify_p2sh = height >= self.network.bip34_height,
            verify_dersig = height >= self.network.bip66_height,
            verify_checklocktimeverify = height >= self.network.bip65_height,
            verify_checksequenceverify = height >= self.network.csv_height,
            verify_witness = height >= self.network.segwit_height,
            verify_nulldummy = height >= self.network.segwit_height,
            verify_taproot = height >= self.network.taproot_height,
          }

          -- Build prev_outputs once per tx for Taproot key-path checker.
          -- (utxo_cache is built in the first pass above; lazy because
          -- only Taproot key-path actually needs it.)
          local tx_prev_outputs = nil
          local function get_tx_prev_outputs()
            if tx_prev_outputs then return tx_prev_outputs end
            tx_prev_outputs = {}
            for pi = 1, #tx.inputs do
              local pu = utxo_cache[pi]
              tx_prev_outputs[pi] = { value = pu.value, script_pubkey = pu.script_pubkey }
            end
            return tx_prev_outputs
          end

          -- Determine which scripts to run based on output type. We classify
          -- BEFORE creating the checker so we can decide inline_verify for
          -- the deferred-collect path (CHECKMULTISIG correctness gate, see
          -- make_collecting_sig_checker for full rationale).
          local script_type = script.classify_script(utxo.script_pubkey)

          -- Scan for OP_CHECKMULTISIG/CHECKMULTISIGVERIFY in any script that
          -- will be executed against the legacy/P2SH `checker` below. The
          -- script_sig itself is normally push-only sig+pubkey data, but
          -- two cases reach inner scripts that may contain multisig:
          --   (a) P2SH: the redeem script is the LAST push of script_sig.
          --   (b) P2SH-wrapped witness (P2SH-P2WPKH / P2SH-P2WSH): the
          --       redeem is a witness program; the actual sig-bearing script
          --       is then the witness script (last witness item) for P2WSH.
          --       P2SH-P2WPKH is synthetic P2PKH (no multisig). For P2SH-P2WSH
          --       we additionally scan the witness script.
          --   (c) Plain script_pubkey contains the multisig opcode (bare
          --       multisig, sometimes still seen on mainnet).
          local legacy_has_multisig = false
          if script.has_multisig_op(utxo.script_pubkey) then
            legacy_has_multisig = true
          elseif flags.verify_p2sh and script_type == "p2sh" then
            local redeem = script.extract_last_push(inp.script_sig)
            if redeem then
              if script.has_multisig_op(redeem) then
                legacy_has_multisig = true
              elseif flags.verify_witness then
                -- P2SH-P2WSH: redeem is a witness v0 program 0x00 0x20 <h32>;
                -- the actual sig-bearing script is the last witness item.
                local wv, wp = script.is_witness_program(redeem)
                if wv == 0 and wp and #wp == 32 then
                  -- P2WSH inner: witness script is the last witness item.
                  local witness_stack = inp.witness or {}
                  if #witness_stack > 0 then
                    local inner_ws = witness_stack[#witness_stack]
                    if inner_ws and script.has_multisig_op(inner_ws) then
                      legacy_has_multisig = true
                    end
                  end
                end
                -- P2SH-P2WPKH (wv=0, #wp=20) is synthetic P2PKH — no multisig.
                -- Witness v1 (taproot) doesn't use the legacy checker for
                -- ECDSA, and tapscript disables CHECKMULTISIG anyway.
              end
            end
          end

          -- Select checker: collecting (deferred ECDSA) when parallel mode
          -- is active, or immediate when serial.  Taproot (Schnorr) is always
          -- verified immediately — only ECDSA is deferred to the batch pass.
          -- Inline-verify is forced when CHECKMULTISIG is reachable so the
          -- script's m-of-n trial pairing sees real check_sig results.
          local checker
          if use_parallel_verify then
            checker = validation.make_collecting_sig_checker(
              tx, inp_idx - 1, utxo.value, utxo.script_pubkey, flags, parallel_sigs,
              get_tx_prev_outputs(), legacy_has_multisig
            )
          else
            checker = validation.make_sig_checker(
              tx, inp_idx - 1, utxo.value, utxo.script_pubkey, flags,
              get_tx_prev_outputs()
            )
          end

          if script_type == "p2wpkh" or script_type == "p2wsh" then
            -- SegWit: scriptSig must be empty, use witness stack
            assert(#inp.script_sig == 0, "SegWit input must have empty scriptSig")
            -- Execute witness program
            local witness_stack = inp.witness or {}
            if script_type == "p2wpkh" then
              -- P2WPKH: witness = {sig, pubkey}, execute synthetic P2PKH
              -- The synthetic script is OP_DUP OP_HASH160 <20> OP_EQUALVERIFY
              -- OP_CHECKSIG — never multisig — so inline_verify=false.
              assert(#witness_stack == 2, "P2WPKH requires exactly 2 witness items")
              local pkh = utxo.script_pubkey:sub(3, 22)
              local synthetic_script = script.make_p2pkh_script(pkh)
              local stack = {witness_stack[1], witness_stack[2]}
              local segwit_flags = {}
              for k, v in pairs(flags) do segwit_flags[k] = v end
              segwit_flags.is_segwit = true
              segwit_flags.is_witness_v0 = true  -- Enable WITNESS_PUBKEYTYPE check
              local segwit_checker
              if use_parallel_verify then
                segwit_checker = validation.make_collecting_sig_checker(
                  tx, inp_idx - 1, utxo.value, utxo.script_pubkey, segwit_flags, parallel_sigs,
                  nil, false
                )
              else
                segwit_checker = validation.make_sig_checker(
                  tx, inp_idx - 1, utxo.value, utxo.script_pubkey, segwit_flags
                )
              end
              -- BIP141: Use execute_witness_script which enforces cleanstack
              local ok, err = script.execute_witness_script(synthetic_script, stack, segwit_flags, segwit_checker)
              assert(ok, err or "P2WPKH script verification failed")
            elseif script_type == "p2wsh" then
              -- P2WSH: last witness item is the script
              local witness_script = witness_stack[#witness_stack]
              local script_hash = crypto.sha256(witness_script)
              assert(script_hash == utxo.script_pubkey:sub(3, 34),
                "P2WSH script hash mismatch")
              local stack = {}
              for i = 1, #witness_stack - 1 do
                stack[i] = witness_stack[i]
              end
              local segwit_flags = {}
              for k, v in pairs(flags) do segwit_flags[k] = v end
              segwit_flags.is_segwit = true
              segwit_flags.is_witness_v0 = true  -- Enable WITNESS_PUBKEYTYPE check
              segwit_flags.witness_script = witness_script
              -- Scan the witness script: P2WSH multisig is the canonical place
              -- for modern multisig. CHECKMULTISIG inside witness_script must
              -- gate inline verify or the m-of-n trial pairing breaks.
              local p2wsh_has_multisig = script.has_multisig_op(witness_script)
              local segwit_checker
              if use_parallel_verify then
                segwit_checker = validation.make_collecting_sig_checker(
                  tx, inp_idx - 1, utxo.value, utxo.script_pubkey, segwit_flags, parallel_sigs,
                  nil, p2wsh_has_multisig
                )
              else
                segwit_checker = validation.make_sig_checker(
                  tx, inp_idx - 1, utxo.value, utxo.script_pubkey, segwit_flags
                )
              end
              -- BIP141: Use execute_witness_script which enforces cleanstack
              local ok, err = script.execute_witness_script(witness_script, stack, segwit_flags, segwit_checker)
              assert(ok, err or "P2WSH script verification failed")
            end

          elseif script_type == "p2tr" and height >= self.network.taproot_height then
            -- P2TR (taproot) witness v1: scriptSig must be empty, use witness stack
            assert(#inp.script_sig == 0, "Taproot input must have empty scriptSig")
            local witness = inp.witness or {}
            assert(#witness > 0, "taproot witness empty")

            -- Witness program is the 32-byte x-only output key
            local witness_program = utxo.script_pubkey:sub(3, 34)

            -- Check for annex (last witness element starting with 0x50)
            local annex = nil
            if #witness >= 2 then
              local last = witness[#witness]
              if #last > 0 and string.byte(last, 1) == 0x50 then
                annex = last
                -- Remove annex from witness for processing
                local trimmed = {}
                for wi = 1, #witness - 1 do
                  trimmed[wi] = witness[wi]
                end
                witness = trimmed
              end
            end

            -- Collect prev_outputs for taproot sighash (needs all inputs' prevouts)
            local prev_outputs = {}
            for pi = 1, #tx.inputs do
              local pu = utxo_cache[pi]
              prev_outputs[pi] = { value = pu.value, script_pubkey = pu.script_pubkey }
            end

            if #witness == 1 then
              -- Key-path spend: single element is a Schnorr signature
              local sig = witness[1]
              assert(#sig == 64 or #sig == 65, "taproot invalid signature length")

              local hash_type = 0x00  -- SIGHASH_DEFAULT
              local sig_bytes = sig
              if #sig == 65 then
                hash_type = string.byte(sig, 65)
                sig_bytes = string.sub(sig, 1, 64)
                -- BIP341: 0x00 hash_type must not use 65-byte sig
                assert(hash_type ~= 0x00, "taproot invalid hash type with 65-byte sig")
              end

              -- Compute taproot sighash for key-path (ext_flag = 0)
              local sighash = validation.signature_hash_taproot(
                tx, inp_idx - 1, hash_type, prev_outputs, 0, annex)

              -- Verify Schnorr signature against the output key (witness_program)
              local ok = crypto.schnorr_verify(witness_program, sig_bytes, sighash)
              assert(ok, "taproot key-path signature verification failed")
            else
              -- Script-path spend: last element is control block, second-to-last is script
              local control_block = witness[#witness]
              local tapscript = witness[#witness - 1]

              assert(#control_block >= 33, "taproot invalid control block size")
              assert((#control_block - 33) % 32 == 0, "taproot invalid control block size")

              local leaf_version = bit.band(string.byte(control_block, 1), 0xFE)
              local internal_key = string.sub(control_block, 2, 33)

              -- Compute tapleaf hash
              local leaf_hash = crypto.tagged_hash("TapLeaf",
                string.char(leaf_version) .. crypto.compact_size(#tapscript) .. tapscript)

              -- Walk merkle path to compute root
              local current = leaf_hash
              for mi = 34, #control_block, 32 do
                local sibling = string.sub(control_block, mi, mi + 31)
                if current < sibling then
                  current = crypto.tagged_hash("TapBranch", current .. sibling)
                else
                  current = crypto.tagged_hash("TapBranch", sibling .. current)
                end
              end

              -- Compute tweaked key and verify it matches the output key
              local tweak = crypto.tagged_hash("TapTweak", internal_key .. current)
              local tweaked_key = crypto.tweak_pubkey(internal_key, tweak)
              assert(tweaked_key and tweaked_key == witness_program,
                "taproot commitment mismatch")

              -- Execute tapscript if leaf version is 0xC0 (BIP342)
              if leaf_version == 0xC0 then
                -- Build the script witness (all items except script and control block)
                local script_witness = {}
                for wi = 1, #witness - 2 do
                  script_witness[wi] = witness[wi]
                end

                -- Create tapscript-aware sig checker
                local tapscript_checker = validation.make_tapscript_checker(
                  tx, inp_idx - 1, prev_outputs, leaf_hash, annex)

                local ok, err = script.verify_tapscript(
                  tapscript, script_witness, tapscript_checker)
                assert(ok, "tapscript execution failed: " .. (err or "unknown"))
              end
              -- Other leaf versions: succeed unconditionally (future soft fork)
            end

          else
            -- Legacy or P2SH
            local ok, err = script.verify_script(inp.script_sig, utxo.script_pubkey, flags, checker)
            assert(ok, string.format("Script verification failed for input %d of tx %s: %s",
              inp_idx, types.hash256_hex(txid), err or "verify_script returned false"))
          end

          -- Cache successful verification
          self.sig_cache:insert(txid_bytes, inp_idx, cache_flags)
          ::skip_verification::
        end

        input_total = input_total + utxo.value

        -- Spend the UTXO
        self.coin_view:spend(inp.prev_out.hash, inp.prev_out.index)
      end

      -- Store this transaction's undo data
      -- block_undo.tx_undo[1] corresponds to block.transactions[2] (first non-coinbase)
      block_undo.tx_undo[#block_undo.tx_undo + 1] = tx_undo

      -- Check output total <= input total
      local output_total = 0
      for _, out in ipairs(tx.outputs) do
        output_total = output_total + out.value
      end
      assert(input_total >= output_total,
        "Transaction outputs exceed inputs")
      total_fees = total_fees + (input_total - output_total)
    end

    -- Add outputs to UTXO set
    for vout_idx, out in ipairs(tx.outputs) do
      -- Don't add provably unspendable outputs (OP_RETURN)
      if #out.script_pubkey == 0 or out.script_pubkey:byte(1) ~= 0x6a then
        self.coin_view:add(txid, vout_idx - 1, M.utxo_entry(
          out.value, out.script_pubkey, height, is_coinbase
        ))
      end
    end
  end

  local _cb_t_tx = perf.now()

  -- If we collected signatures for parallel verification, verify them now
  if parallel_sigs and #parallel_sigs > 0 then
    local ok, err = validation.verify_signatures_parallel(parallel_sigs)
    assert(ok, "Parallel signature verification failed: " .. (err or "unknown error"))
  end
  local _cb_t_parallel = perf.now()

  -- Check total sigop cost does not exceed limit
  assert(total_sigop_cost <= consensus.MAX_BLOCK_SIGOPS_COST,
    string.format("Block sigop cost %d exceeds maximum %d",
      total_sigop_cost, consensus.MAX_BLOCK_SIGOPS_COST))

  -- Verify coinbase value
  local subsidy = consensus.get_block_subsidy(height)
  local coinbase_value = 0
  for _, out in ipairs(block.transactions[1].outputs) do
    coinbase_value = coinbase_value + out.value
  end
  assert(coinbase_value <= subsidy + total_fees,
    string.format("Coinbase value too high: %d > %d + %d",
      coinbase_value, subsidy, total_fees))

  -- Serialize undo data (only if there are non-coinbase transactions). The
  -- actual write goes into the atomic batch below — pre-2026-04-30 this was
  -- a separate `self.storage.put_undo()` call OUTSIDE the atomic batch, which
  -- meant a hard crash between the undo write and the UTXO/chain_tip flush
  -- could leave undo missing for a block whose chain_tip update did land.
  -- Per BUG-REPORT.md fix #2, every block-connect mutation must commit as a
  -- single WriteBatch with the chain-tip update as the LAST operation.
  local undo_data_for_batch = nil
  if #block_undo.tx_undo > 0 then
    undo_data_for_batch = M.serialize_block_undo(block_undo)
  end
  local _cb_t_undo = perf.now()

  -- Flush dirty UTXO entries, undo data, caller extras (block body, etc.),
  -- and the chain-tip update — all in the SAME atomic batch. This is the
  -- per-block atomic write barrier. There is NO state on disk where chain_tip
  -- advanced but the UTXO mutations / undo / block body did not. This closes
  -- the post-EMFILE wedge documented in
  -- project_lunarblock_wedge_2026_04_28: pre-fix, chain_tip could advance
  -- past blocks whose put_block / put_undo had not yet been written.
  --
  -- Order inside the batch: UTXO writes/deletes (added by coin_view:flush) ->
  -- undo data -> caller extras (block body / height index) -> chain_tip.
  -- Chain-tip is written LAST so that any partial pre-commit visibility (none
  -- with WriteBatch under WAL semantics, but defence-in-depth) can never show
  -- a tip ahead of the data that backs it.
  --
  -- When nosync is true, skip the expensive fsync — the caller (e.g. the IBD
  -- loop) is responsible for issuing a periodic sync flush to bound data loss.
  local tip_hash_capture = block_hash
  local tip_height_capture = height
  local do_sync = not nosync
  -- Serialize chain tip using FFI buffer instead of buffer_writer
  local tip_buf = ffi.new("uint8_t[36]")
  ffi.copy(tip_buf, tip_hash_capture.bytes, 32)
  tip_buf[32] = band(tip_height_capture, 0xFF)
  tip_buf[33] = band(rshift(tip_height_capture, 8), 0xFF)
  tip_buf[34] = band(rshift(tip_height_capture, 16), 0xFF)
  tip_buf[35] = band(rshift(tip_height_capture, 24), 0xFF)
  local tip_data = ffi.string(tip_buf, 36)
  self.coin_view:flush(false, function(batch)
    -- Undo data into the same atomic batch (was a separate put before
    -- 2026-04-30; see comment block above).
    if undo_data_for_batch then
      batch.put(storage_mod.CF.UNDO, block_hash.bytes, undo_data_for_batch)
    end
    -- Include caller's extra operations (e.g. block body / height index from
    -- the IBD path, or block/header/height_index from submitblock) in the
    -- same atomic write batch BEFORE chain_tip — see ordering note above.
    if caller_batch_fn then
      caller_batch_fn(batch)
    end
    -- Chain-tip last in the batch (defence-in-depth ordering).
    batch.put(storage_mod.CF.META, "chain_tip", tip_data)
  end, do_sync)
  local _cb_t_flush = perf.now()

  -- Update in-memory tip (only after the atomic write succeeds)
  self.tip_hash = block_hash
  self.tip_height = height

  -- Invoke callback if registered (for ZMQ notifications, etc.)
  if self.callbacks.on_block_connected then
    self.callbacks.on_block_connected(block_hash, block)
  end
  local _cb_t_cb = perf.now()

  -- W77-CB: accumulate sub-phase timings and emit every cb_log_every blocks.
  do
    local w = self.cb_win
    local tx    = _cb_t_tx - _cb_t0
    local par   = _cb_t_parallel - _cb_t_tx
    local undo  = _cb_t_undo - _cb_t_parallel
    local flush = _cb_t_flush - _cb_t_undo
    local cb    = _cb_t_cb - _cb_t_flush
    local total = _cb_t_cb - _cb_t0
    w.n         = w.n + 1
    w.tx_loop_t = w.tx_loop_t + tx
    w.parallel_t = w.parallel_t + par
    w.undo_t    = w.undo_t + undo
    w.flush_t   = w.flush_t + flush
    w.cb_t      = w.cb_t + cb
    w.total_t   = w.total_t + total
    if tx    > w.tx_max    then w.tx_max    = tx end
    if flush > w.flush_max then w.flush_max = flush end
    if total > w.total_max then w.total_max = total end
    self.cb_lifetime = self.cb_lifetime + 1
    if w.n >= self.cb_log_every then
      print(string.format(
        "[W77-CB] window=%d total=%d tx_avg=%.1fms par_avg=%.1fms undo_avg=%.1fms flush_avg=%.1fms cb_avg=%.1fms total_avg=%.1fms tx_max=%.0fms flush_max=%.0fms total_max=%.0fms",
        w.n, self.cb_lifetime,
        (w.tx_loop_t / w.n) * 1000, (w.parallel_t / w.n) * 1000,
        (w.undo_t    / w.n) * 1000, (w.flush_t    / w.n) * 1000,
        (w.cb_t      / w.n) * 1000, (w.total_t    / w.n) * 1000,
        w.tx_max * 1000, w.flush_max * 1000, w.total_max * 1000))
      self.cb_win = { n = 0, tx_loop_t = 0, parallel_t = 0, undo_t = 0,
                      flush_t = 0, cb_t = 0, total_t = 0,
                      tx_max = 0, flush_max = 0, total_max = 0 }
    end
  end

  return true, total_fees
end

--------------------------------------------------------------------------------
-- Disconnect Block (for chain reorganization)
--------------------------------------------------------------------------------

--- Disconnect a block from the chain tip, restoring the UTXO set.
-- @param block The block to disconnect
-- @param height The height of the block
-- @param block_hash The hash of the block being disconnected
-- @param prev_hash The hash of the previous block (becomes new tip)
-- @return true on success, nil and error message on failure
function ChainState:disconnect_block(block, height, block_hash, prev_hash)
  -- Clear signature cache on reorg to avoid stale entries
  self.sig_cache:clear()

  -- Load undo data from storage
  local undo_data_raw = self.storage.get_undo(block_hash)
  local block_undo = nil

  -- Only non-genesis blocks with spending txs have undo data
  if undo_data_raw then
    local err
    block_undo, err = M.deserialize_block_undo(undo_data_raw)
    if not block_undo then
      return nil, "failed to deserialize undo data: " .. (err or "unknown")
    end
  end

  -- Process transactions in reverse order
  -- Note: block_undo.tx_undo[i] corresponds to block.transactions[i+1]
  -- because coinbase (tx index 1) has no undo data
  for tx_idx = #block.transactions, 1, -1 do
    local tx = block.transactions[tx_idx]
    local txid = validation.compute_txid(tx)
    local is_coinbase = (tx_idx == 1)

    -- Remove outputs from UTXO set (they were added during connect)
    for vout_idx = 1, #tx.outputs do
      local out = tx.outputs[vout_idx]
      -- Only remove if we added it (not OP_RETURN)
      if #out.script_pubkey == 0 or out.script_pubkey:byte(1) ~= 0x6a then
        self.coin_view:spend(txid, vout_idx - 1)
      end
    end

    -- Restore spent inputs using undo data
    if not is_coinbase and block_undo then
      -- tx_idx 2 -> block_undo.tx_undo[1], tx_idx 3 -> block_undo.tx_undo[2], etc.
      local undo_idx = tx_idx - 1
      local tx_undo = block_undo.tx_undo[undo_idx]
      if tx_undo then
        for inp_idx, inp in ipairs(tx.inputs) do
          local spent_utxo = tx_undo.prev_outputs[inp_idx]
          if spent_utxo then
            self.coin_view:add(inp.prev_out.hash, inp.prev_out.index, spent_utxo)
          end
        end
      end
    end
  end

  -- Flush dirty UTXO entries and update chain tip atomically.
  local new_tip_height = height - 1
  local new_tip_hash = prev_hash
  local had_undo = undo_data_raw ~= nil
  local disconnect_hash = block_hash
  self.coin_view:flush(false, function(batch)
    -- Remove undo data for this block
    if had_undo then
      batch.delete(storage_mod.CF.UNDO, disconnect_hash.bytes)
    end
    -- Update chain tip to the previous block
    if new_tip_hash then
      local w = serialize.buffer_writer()
      w.write_hash256(new_tip_hash)
      w.write_u32le(new_tip_height)
      batch.put(storage_mod.CF.META, "chain_tip", w.result())
    end
  end, true)

  -- Update in-memory tip
  self.tip_height = new_tip_height
  if new_tip_hash then
    self.tip_hash = new_tip_hash
  end

  -- Invoke callback if registered (for ZMQ notifications, etc.)
  if self.callbacks.on_block_disconnected then
    self.callbacks.on_block_disconnected(block_hash)
  end

  return true
end

--------------------------------------------------------------------------------
-- Temporary rollback support for dumptxoutset rollback mode.
-- Disconnects blocks from the current tip down to (but not including)
-- target_height, returning the ordered list of disconnected (hash, height)
-- pairs so callers can re-apply them in order via reapply_disconnected().
--
-- Mirrors the behavior of bitcoin-core's TemporaryRollback
-- (src/rpc/blockchain.cpp) -- it walks from tip back to target_index by
-- invalidating each block, dumps, then reconsiders to roll forward.  We
-- bypass the invalid_blocks bookkeeping because we control this rollback
-- end-to-end and only need the disconnect/reconnect dance.
--
-- Returns: list of {hash=hash256, height=int}, ordered from tip-down (so
-- index 1 was the original tip and the last entry is at target_height+1).
-- Caller can iterate in reverse to re-apply.
--------------------------------------------------------------------------------

--- Disconnect blocks from the current tip down to target_height.
-- After this call, self.tip_height == target_height and the UTXO state
-- reflects the chain at that height (assuming undo data is available).
-- The returned list captures the disconnected blocks so they can be
-- reconnected in order.
-- @param target_height number: height to roll back to (must be < tip_height)
-- @return table|nil, string|nil: list of {hash, height} or nil and error
function ChainState:rollback_chain_to(target_height)
  if type(target_height) ~= "number" then
    return nil, "rollback_chain_to: target_height must be a number"
  end
  if target_height < 0 then
    return nil, "rollback_chain_to: negative target height"
  end
  if not self.tip_height or not self.tip_hash then
    return nil, "rollback_chain_to: chain has no tip"
  end
  if target_height > self.tip_height then
    return nil, "rollback_chain_to: target above current tip"
  end

  local disconnected = {}
  while self.tip_height > target_height do
    local tip_hash = self.tip_hash
    local tip_height = self.tip_height
    local tip_block = self.storage.get_block(tip_hash)
    if not tip_block then
      return nil, string.format(
        "rollback_chain_to: block data missing at height %d", tip_height)
    end
    local tip_header = self.storage.get_header(tip_hash)
    if not tip_header then
      return nil, string.format(
        "rollback_chain_to: header missing at height %d", tip_height)
    end

    disconnected[#disconnected + 1] = {hash = tip_hash, height = tip_height}

    local prev_hash = tip_header.prev_hash
    local ok, err = self:disconnect_block(
      tip_block, tip_height, tip_hash, prev_hash)
    if not ok then
      return nil, "rollback_chain_to: disconnect failed at height "
        .. tostring(tip_height) .. ": " .. tostring(err)
    end
  end

  return disconnected
end

--- Re-apply a list of previously-disconnected blocks (LIFO).
-- @param disconnected table: list returned by rollback_chain_to()
-- @return boolean, string|nil: success flag, error message on failure
function ChainState:reapply_disconnected(disconnected)
  if type(disconnected) ~= "table" then
    return nil, "reapply_disconnected: expected list"
  end
  -- disconnected[#] was the deepest (lowest height) block; reapply LIFO.
  for i = #disconnected, 1, -1 do
    local entry = disconnected[i]
    local block = self.storage.get_block(entry.hash)
    if not block then
      return nil, string.format(
        "reapply_disconnected: block data missing for height %d",
        entry.height)
    end
    -- Skip BIP68 sequence-lock checks here: connect_block treats
    -- prev_block_mtp == nil as "do not enforce" which is safe for
    -- already-validated history we are simply reconnecting.
    local ok, err = self:connect_block(
      block, entry.height, entry.hash, nil, nil, true, false, false, nil)
    if not ok then
      return nil, string.format(
        "reapply_disconnected: connect failed at height %d: %s",
        entry.height, tostring(err))
    end
  end
  return true
end

--------------------------------------------------------------------------------
-- Block Invalidation (invalidateblock / reconsiderblock RPC support)
--------------------------------------------------------------------------------

--- Invalidate a block and all its descendants, triggering a reorg if needed.
-- This marks the block as invalid and disconnects it from the active chain.
-- @param block_hash hash256: The hash of the block to invalidate
-- @return boolean, string|nil: success flag, error message on failure
function ChainState:invalidate_block(block_hash)
  -- Cannot invalidate genesis block
  local header = self.storage.get_header(block_hash)
  if not header then
    return nil, "Block not found"
  end

  -- Check if this is the genesis block (prev_hash is all zeros)
  if header.prev_hash.bytes == string.rep("\0", 32) then
    return nil, "Cannot invalidate genesis block"
  end

  -- Mark this block as invalid
  self.invalid_blocks[block_hash.bytes] = true

  -- Check if the block is in the active chain
  local block_in_chain = false
  local block_height = nil

  -- Find the height of this block by searching from tip
  if self.tip_hash and types.hash256_eq(self.tip_hash, block_hash) then
    block_in_chain = true
    block_height = self.tip_height
  else
    -- Check if the block is an ancestor of the current tip
    local current_hash = self.tip_hash
    local current_height = self.tip_height
    while current_hash and current_height >= 0 do
      if types.hash256_eq(current_hash, block_hash) then
        block_in_chain = true
        block_height = current_height
        break
      end
      local h = self.storage.get_header(current_hash)
      if not h then
        break
      end
      if h.prev_hash.bytes == string.rep("\0", 32) then
        break
      end
      current_hash = h.prev_hash
      current_height = current_height - 1
    end
  end

  -- If the block is in the active chain, disconnect blocks from tip back to it
  if block_in_chain then
    while self.tip_height >= block_height do
      local tip_block = self.storage.get_block(self.tip_hash)
      if not tip_block then
        return nil, "Failed to load block for disconnection"
      end

      local tip_header = self.storage.get_header(self.tip_hash)
      if not tip_header then
        return nil, "Failed to load header for disconnection"
      end

      local prev_hash = tip_header.prev_hash
      local ok, err = self:disconnect_block(tip_block, self.tip_height, self.tip_hash, prev_hash)
      if not ok then
        return nil, "Failed to disconnect block: " .. (err or "unknown error")
      end
    end
  end

  -- Persist the invalid blocks set
  self:save_invalid_blocks()

  return true
end

--- Remove invalidity status from a block and its ancestors/descendants.
-- This clears the invalid flag and potentially allows re-activation.
-- @param block_hash hash256: The hash of the block to reconsider
-- @return boolean, string|nil: success flag, error message on failure
function ChainState:reconsider_block(block_hash)
  -- Check if the block exists
  local header = self.storage.get_header(block_hash)
  if not header then
    return nil, "Block not found"
  end

  -- Remove invalid flag from this block
  self.invalid_blocks[block_hash.bytes] = nil

  -- Also clear invalid flags from all ancestors
  local current_hash = header.prev_hash
  while current_hash and current_hash.bytes ~= string.rep("\0", 32) do
    self.invalid_blocks[current_hash.bytes] = nil
    local h = self.storage.get_header(current_hash)
    if not h then
      break
    end
    current_hash = h.prev_hash
  end

  -- Clear invalid flags from all descendants
  -- This requires iterating through all stored headers to find descendants
  self:clear_descendant_invalid_flags(block_hash)

  -- Persist the invalid blocks set
  self:save_invalid_blocks()

  return true
end

--- Clear invalid flags from all descendants of a block.
-- @param block_hash hash256: The parent block hash
function ChainState:clear_descendant_invalid_flags(block_hash)
  -- Iterate through all headers and check if they descend from block_hash
  local iter = self.storage.iterator(storage_mod.CF.HEADERS)
  iter.seek_to_first()

  local descendants = {}
  while iter.valid() do
    local hash_bytes = iter.key()
    if self.invalid_blocks[hash_bytes] then
      -- Check if this is a descendant of block_hash
      local candidate_hash = types.hash256(hash_bytes)
      local current = candidate_hash
      while current do
        local h = self.storage.get_header(current)
        if not h then
          break
        end
        if types.hash256_eq(h.prev_hash, block_hash) then
          -- This is a descendant
          descendants[hash_bytes] = true
          break
        end
        if h.prev_hash.bytes == string.rep("\0", 32) then
          break
        end
        current = h.prev_hash
      end
    end
    iter.next()
  end
  iter.destroy()

  -- Clear the invalid flag for all descendants
  for hash_bytes, _ in pairs(descendants) do
    self.invalid_blocks[hash_bytes] = nil
  end
end

--- Get the list of currently invalidated block hashes.
-- @return table: array of hash256 objects
function ChainState:get_invalid_blocks()
  local result = {}
  for hash_bytes, _ in pairs(self.invalid_blocks) do
    result[#result + 1] = types.hash256(hash_bytes)
  end
  return result
end

--------------------------------------------------------------------------------
-- UTXO Statistics
--------------------------------------------------------------------------------

function ChainState:get_utxo_stats()
  -- Iterate over the UTXO set and compute statistics
  local count = 0
  local total_value = 0
  local iter = self.storage.iterator(storage_mod.CF.UTXO)
  iter.seek_to_first()
  while iter.valid() do
    local data = iter.value()
    local entry = M.deserialize_utxo_entry(data)
    count = count + 1
    total_value = total_value + entry.value
    iter.next()
  end
  iter.destroy()
  return {
    utxo_count = count,
    total_value = total_value,
    total_btc = total_value / consensus.COIN,
  }
end

--------------------------------------------------------------------------------
-- AssumeUTXO Snapshot Operations
--------------------------------------------------------------------------------

--- Serialize one (outpoint, coin) tuple in Bitcoin Core's TxOutSer format
-- (bitcoin-core/src/kernel/coinstats.cpp:46).  This is the per-element
-- payload that ApplyCoinHash feeds into HashWriter (HASH_SERIALIZED) or
-- MuHash3072::Insert (MUHASH).
--
-- Layout (all little-endian):
--   txid    : 32 bytes (raw, on-disk byte order)
--   vout    : uint32 LE (4 bytes)
--   code    : uint32 LE = (nHeight << 1) | fCoinBase   (4 bytes)
--   value   : int64 LE  (8 bytes)
--   scriptPubKey : CompactSize len || raw bytes
--
-- The on-disk UTXO key already encodes (txid || vout LE), so we hand that
-- back unchanged for the first 36 bytes.
local function _serialize_txoutser(key, entry)
  -- key is exactly 36 bytes: 32 raw txid + 4 vout LE.
  assert(#key == 36, "txoutser: expected 36-byte UTXO key")

  local code = entry.height * 2 + (entry.is_coinbase and 1 or 0)
  local w = serialize.buffer_writer()
  w.write_bytes(key)
  w.write_u32le(code)
  w.write_i64le(entry.value)
  w.write_varint(#entry.script_pubkey)
  w.write_bytes(entry.script_pubkey)
  return w.result()
end
M.serialize_txoutser = _serialize_txoutser

--- Compute the HASH_SERIALIZED UTXO set hash for AssumeUTXO snapshot
-- validation, byte-compatible with Bitcoin Core's
-- CoinStatsHashType::HASH_SERIALIZED (kernel/coinstats.cpp:111-146,
-- 161-163, 182-184).
--
-- Algorithm (matches Core's HashWriter path):
--   for each (outpoint, coin) in canonical order:
--       update sha256 with TxOutSer(outpoint, coin)
--   return SHA256d(sha256_state)   -- HashWriter::GetHash() is double-SHA256
--
-- Canonical order = lex-ascending txid (RocksDB key order on the 32-byte
-- prefix), then ascending vout within each txid (Core groups by txid
-- via std::map<uint32_t,Coin>, which sorts vouts as ascending uint32).
--
-- This is what bitcoin-core/src/validation.cpp:5904-5915 (loadtxoutset
-- strict gate) hashes against au_data.hash_serialized — the values pinned
-- in chainparams.cpp m_assumeutxo_data. MuHash3072 is for gettxoutsetinfo
-- hash_type=muhash, NOT for assumeutxo.
--
-- @return string: 32 raw bytes (SHA256d output, natural little-endian
--                 order; reverse for uint256 hex display).
-- @return number: total UTXO count.
function ChainState:compute_utxo_hash()
  -- Flush any pending changes to ensure we're reading from disk.
  self.coin_view:flush()

  local hasher = crypto.sha256_init()
  local count = 0

  -- Core's coinstats.cpp:111-146 groups records by txid, builds a
  -- std::map<uint32_t,Coin> per txid (which iterates vouts in ascending
  -- uint32 order), then feeds ApplyHash(hash_obj, prevkey, outputs).
  --
  -- RocksDB iterates the 36-byte key (txid || vout_LE) bytewise. Bytewise
  -- iteration agrees with Core's per-txid grouping (txids are 32 raw bytes
  -- so the prefix sorts the same way), but per-vout LE bytewise sort
  -- diverges from numeric uint32 sort once vout crosses a byte boundary
  -- (vout=0x01 byte-LE = "01 00 00 00" sorts AFTER vout=0x100 byte-LE
  -- "00 01 00 00"). Real txs do have vout >= 256, so we must group by
  -- txid and re-sort vouts numerically before hashing — exactly what
  -- dump_snapshot already does for the on-wire body.
  local current_txid
  local outputs = {}
  local sorted_vouts = {}

  local function flush_txid()
    if current_txid == nil then return end
    table.sort(sorted_vouts)
    for i = 1, #sorted_vouts do
      local vout = sorted_vouts[i]
      local entry = outputs[vout]
      -- Reconstruct the 36-byte outpoint key (txid raw || vout LE)
      -- so _serialize_txoutser can emit the canonical TxOutSer bytes.
      local key = M.outpoint_key(types.hash256(current_txid), vout)
      hasher.update(_serialize_txoutser(key, entry))
      count = count + 1
    end
    outputs = {}
    sorted_vouts = {}
  end

  local iter = self.storage.iterator(storage_mod.CF.UTXO)
  iter.seek_to_first()

  while iter.valid() do
    local key = iter.key()
    local data = iter.value()

    local txid_bytes = key:sub(1, 32)
    local r = serialize.buffer_reader(key:sub(33, 36))
    local vout = r.read_u32le()

    if current_txid ~= txid_bytes then
      flush_txid()
      current_txid = txid_bytes
    end
    outputs[vout] = M.deserialize_utxo_entry(data)
    sorted_vouts[#sorted_vouts + 1] = vout

    iter.next()
  end
  iter.destroy()
  flush_txid()

  -- HashWriter::GetHash() = SHA256d. crypto.sha256_init().final() is
  -- single SHA256, so we hash once more to get the double.
  local single = hasher.final()
  return crypto.sha256(single), count
end

--- Compute the MuHash3072 set hash of the current UTXO set, byte-compatible
-- with Bitcoin Core's CoinStatsHashType::MUHASH (kernel/coinstats.cpp).
--
-- This is the value `gettxoutsetinfo hash_type=muhash` reports. It is NOT
-- what AssumeUTXO snapshot validation commits to (despite the field being
-- spelled "hash_serialized" in chainparams.cpp m_assumeutxo_data — those
-- entries are HASH_SERIALIZED / SHA256d-via-HashWriter values and live on
-- compute_utxo_hash). See validation.cpp:5904-5915 for the strict gate.
--
-- Order-independent (MuHash is a homomorphic set hash), but for sanity we
-- still iterate in canonical RocksDB key order.
--
-- @return string: 32 raw bytes (SHA256 of the canonical 384-byte Num3072
--                 packing, in the natural little-endian byte order).
-- @return number: number of UTXOs hashed.
function ChainState:compute_muhash()
  -- Flush any pending changes to ensure we're reading from disk.
  self.coin_view:flush()

  local muhash_mod = require("lunarblock.muhash")
  local mh = muhash_mod.new()

  local count = 0
  local iter = self.storage.iterator(storage_mod.CF.UTXO)
  iter.seek_to_first()

  while iter.valid() do
    local key = iter.key()
    local data = iter.value()
    local entry = M.deserialize_utxo_entry(data)
    mh:insert(_serialize_txoutser(key, entry))
    count = count + 1
    iter.next()
  end
  iter.destroy()

  return mh:finalize(), count
end

-- libc fsync/fileno bindings, declared lazily on first use. We avoid
-- forcing the cdef at module load so embedded LuaJIT environments
-- without libc symbols (uncommon but possible in static builds) can
-- still load lunarblock.utxo.
local _fsync_initialized = false
local function _ensure_fsync_cdef()
  if _fsync_initialized then return end
  pcall(function()
    ffi.cdef[[
      int fsync(int fd);
      int fileno(void *stream);
    ]]
  end)
  _fsync_initialized = true
end

--- Best-effort fsync of a Lua FILE* before close. Returns true on
-- success, false on failure (caller can treat as advisory; the data
-- is still in the kernel page cache after file:flush()). Mirrors
-- Bitcoin Core's Fdatasync/close pair before the atomic rename in
-- rpc/blockchain.cpp::dumptxoutset.
local function _fsync_file(file)
  _ensure_fsync_cdef()
  -- `file:flush()` flushes Lua's user-space buffer into the FILE*
  -- buffer, but FILE* itself buffers too. We drive both ends down to
  -- the OS layer here.
  local ok_flush = pcall(function() file:flush() end)
  if not ok_flush then return false end
  local ok = pcall(function()
    local fd = ffi.C.fileno(file)
    if fd >= 0 then
      ffi.C.fsync(fd)
    end
  end)
  return ok
end

--- Dump the UTXO set to a snapshot file in Bitcoin Core wire format.
-- Mirrors WriteUTXOSnapshot in bitcoin-core/src/rpc/blockchain.cpp.
-- Outer body loop is grouped by txid using CompactSize counts; inner
-- coin payload uses Core VARINTs and ScriptCompression.
-- @param file_path string: path to write snapshot file
-- @return table|nil, string|nil: {coins_count, hash, base_blockhash,
--                                  base_height, path} or nil, error message
function ChainState:dump_snapshot(file_path)
  -- Ensure coin view is flushed so the iterator sees a consistent state.
  self.coin_view:flush()

  -- Open output file
  local file, err = io.open(file_path, "wb")
  if not file then
    return nil, "failed to open file: " .. (err or "unknown error")
  end

  -- First pass: collect UTXOs grouped by txid.  The on-disk RocksDB key
  -- is already (txid || vout LE), so iterating the column family is
  -- naturally lex-sorted by txid then vout.  We still group in memory
  -- because lunarblock historically returns the per-txid bucket in one
  -- go to the writer.  TODO: stream this for >tens-of-millions UTXOs.
  --
  -- Genesis-coinbase exclusion: Bitcoin Core never adds the genesis
  -- block's coinbase output to the UTXO set
  -- (bitcoin-core/src/validation.cpp:2337-2343 short-circuits on the
  -- genesis hash and skips ConnectBlock for its transactions).
  -- lunarblock's connect_genesis() inserts it for "consistency", which
  -- diverged the dump's coins_count by 1 vs Core.  Compute the genesis
  -- coinbase txid here and skip exactly that entry so the wire format
  -- (51-byte metadata, coins_count=0 on a fresh chain) is byte-identical
  -- to Core's regtest dump.
  local genesis_coinbase_txid_bytes = nil
  do
    local ok, gen_block_hash = pcall(self.storage.get_hash_by_height, 0)
    if ok and gen_block_hash then
      local gok, gen_block = pcall(self.storage.get_block, gen_block_hash)
      if gok and gen_block and gen_block.transactions
          and gen_block.transactions[1] then
        local gtxid = validation.compute_txid(gen_block.transactions[1])
        if gtxid and gtxid.bytes then
          genesis_coinbase_txid_bytes = gtxid.bytes
        end
      end
    end
  end

  local utxos_by_txid = {}
  local total_count = 0

  local iter = self.storage.iterator(storage_mod.CF.UTXO)
  iter.seek_to_first()

  while iter.valid() do
    local key = iter.key()
    local data = iter.value()

    local txid_bytes = key:sub(1, 32)
    local r = serialize.buffer_reader(key:sub(33, 36))
    local vout = r.read_u32le()

    local entry = M.deserialize_utxo_entry(data)

    -- Skip the genesis coinbase, byte-matching Core which never
    -- inserts it (validation.cpp ConnectBlock fast-path).
    if txid_bytes ~= genesis_coinbase_txid_bytes then
      if not utxos_by_txid[txid_bytes] then
        utxos_by_txid[txid_bytes] = {}
      end
      utxos_by_txid[txid_bytes][vout] = entry
      total_count = total_count + 1
    end

    iter.next()
  end
  iter.destroy()

  -- Write metadata (51 bytes; serialize_snapshot_metadata matches
  -- SnapshotMetadata::Serialize byte-for-byte).
  local metadata = M.snapshot_metadata(
    self.network.magic_bytes,
    self.tip_hash,
    total_count
  )
  file:write(M.serialize_snapshot_metadata(metadata))

  -- Sort txids lexicographically (matches leveldb iteration order).
  local sorted_txids = {}
  for txid_bytes in pairs(utxos_by_txid) do
    sorted_txids[#sorted_txids + 1] = txid_bytes
  end
  table.sort(sorted_txids)

  -- Body: for each txid, write txid raw + CompactSize(coins) + per-coin
  -- (CompactSize(vout) + serialize_snapshot_coin).
  for _, txid_bytes in ipairs(sorted_txids) do
    local outputs = utxos_by_txid[txid_bytes]

    local sorted_vouts = {}
    for vout in pairs(outputs) do
      sorted_vouts[#sorted_vouts + 1] = vout
    end
    table.sort(sorted_vouts)

    -- Bundle the per-txid header into one writev to amortize Lua overhead.
    local w = serialize.buffer_writer()
    w.write_bytes(txid_bytes)            -- raw 32-byte txid
    w.write_varint(#sorted_vouts)        -- CompactSize, NOT Core VARINT
    file:write(w.result())

    for _, vout in ipairs(sorted_vouts) do
      local entry = outputs[vout]
      local ow = serialize.buffer_writer()
      ow.write_varint(vout)              -- CompactSize for vout index
      file:write(ow.result())
      file:write(M.serialize_snapshot_coin(entry))
    end
  end

  -- Durability barrier before close+rename. Mirrors Bitcoin Core's
  -- Fdatasync/close in rpc/blockchain.cpp::dumptxoutset; without this
  -- a power loss between close+rename and the OS flushing dirty pages
  -- could leave the renamed final path visible with zero-length /
  -- torn contents. Best-effort: failures fall back to close-and-pray.
  -- The atomic rename is performed by the caller (rpc.lua dumptxoutset
  -- handler) which writes us a `.incomplete` path and renames after.
  _fsync_file(file)

  file:close()

  -- Compute snapshot hash for verification.
  local hash, _ = self:compute_utxo_hash()

  return {
    coins_count = total_count,
    hash = hash,
    base_blockhash = self.tip_hash,
    base_height = self.tip_height,
    path = file_path,
  }
end

--- Build a buffer_reader-shaped object backed by a Lua file handle.
-- Reads ahead in REFILL_SIZE chunks so Core VARINT/CompactSize parsing
-- stays in pure-Lua arithmetic rather than per-byte file:read(1).
-- @param file file*: open binary file handle
-- @return reader: object with read_u8, read_bytes, read_u32le, read_i64le
local function _file_reader(file)
  local REFILL = 65536  -- 64 KiB
  local buf = ""
  local pos = 1

  local function ensure(n)
    if pos + n - 1 > #buf then
      local rest = buf:sub(pos)
      local extra = file:read(math.max(REFILL, n))
      if extra then
        buf = rest .. extra
      else
        buf = rest
      end
      pos = 1
      if pos + n - 1 > #buf then
        error("file_reader: unexpected end of file (need " .. n .. " bytes)")
      end
    end
  end

  local r = {}
  function r.read_u8()
    ensure(1)
    local v = buf:byte(pos)
    pos = pos + 1
    return v
  end
  function r.read_bytes(n)
    if n == 0 then return "" end
    ensure(n)
    local s = buf:sub(pos, pos + n - 1)
    pos = pos + n
    return s
  end
  function r.read_u16le()
    ensure(2)
    local b1, b2 = buf:byte(pos, pos + 1)
    pos = pos + 2
    return b1 + b2 * 256
  end
  function r.read_u32le()
    ensure(4)
    local b1, b2, b3, b4 = buf:byte(pos, pos + 3)
    pos = pos + 4
    return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
  end
  function r.read_u64le()
    local low = r.read_u32le()
    local high = r.read_u32le()
    return low + high * 4294967296
  end
  function r.read_i64le()
    local low = r.read_u32le()
    local high = r.read_u32le()
    if high >= 2147483648 then
      local cl = 4294967295 - low
      local ch = 4294967295 - high
      return -(cl + ch * 4294967296 + 1)
    else
      return low + high * 4294967296
    end
  end
  function r.read_varint()
    local first = r.read_u8()
    if first < 0xFD then return first
    elseif first == 0xFD then return r.read_u16le()
    elseif first == 0xFE then return r.read_u32le()
    else return r.read_u64le() end
  end
  return r
end

--- Load a UTXO snapshot file into this chainstate.
-- Accepts the Bitcoin Core wire format produced by dumptxoutset
-- (lunarblock's dump_snapshot is byte-compatible with this).
-- @param file_path string: path to snapshot file
-- @param expected_hash string|nil: expected HASH_SERIALIZED (SHA256d) of
--                                  the deserialized UTXO set, 32 raw bytes
--                                  in HashWriter natural-LE order. When
--                                  supplied, mirrors Core's loadtxoutset
--                                  strict gate (validation.cpp:5904-5915).
-- @return boolean, string|nil: success flag, error message
function ChainState:load_snapshot(file_path, expected_hash)
  local file, err = io.open(file_path, "rb")
  if not file then
    return false, "failed to open snapshot: " .. (err or "unknown error")
  end

  -- Read 51-byte metadata header.
  local header = file:read(51)
  if not header or #header < 51 then
    file:close()
    return false, "failed to read snapshot header"
  end

  local metadata, meta_err = M.deserialize_snapshot_metadata(header)
  if not metadata then
    file:close()
    return false, meta_err
  end

  if metadata.network_magic ~= self.network.magic_bytes then
    file:close()
    return false, "snapshot network magic mismatch"
  end

  -- Clear in-memory cache; the underlying CF is left untouched and the
  -- caller is expected to feed a fresh chainstate (Core does the same).
  self.coin_view:clear_cache()

  local coins_loaded = 0
  local coins_total = metadata.coins_count

  -- Wrap the file in a buffered reader so the new Core-format inner
  -- payload (Core VARINTs + ScriptCompression) can be parsed with the
  -- same primitives as buffer_reader.
  local r = _file_reader(file)

  local ok_outer, parse_err = pcall(function()
    while coins_loaded < coins_total do
      -- Per-txid header: raw 32-byte txid + CompactSize(coins_per_txid).
      local txid_bytes = r.read_bytes(32)
      local txid = types.hash256(txid_bytes)
      local num_outputs = r.read_varint()  -- CompactSize, see WriteUTXOSnapshot

      for _ = 1, num_outputs do
        local vout = r.read_varint()  -- CompactSize for vout
        local entry = M.deserialize_snapshot_coin(r)
        self.coin_view:add(txid, vout, entry)
        coins_loaded = coins_loaded + 1

        -- Periodic flush to keep the cache from running away on a 100M+
        -- UTXO load.
        if coins_loaded % 100000 == 0 then
          self.coin_view:flush()
        end
      end
    end
  end)

  file:close()

  if not ok_outer then
    return false, "snapshot parse error: " .. tostring(parse_err)
  end

  -- Final flush of the in-memory deltas.
  self.coin_view:flush()

  if expected_hash then
    -- bitcoin-core/src/validation.cpp:5904-5915 (loadtxoutset strict gate)
    -- calls ComputeUTXOStats(CoinStatsHashType::HASH_SERIALIZED, ...) and
    -- compares maybe_stats->hashSerialized (a SHA256d via HashWriter, see
    -- kernel/coinstats.cpp:161-163, 182-184) against au_data.hash_serialized
    -- — the values pinned in chainparams.cpp m_assumeutxo_data.
    --
    -- MuHash3072 is reserved for `gettxoutsetinfo hash_type=muhash` and is
    -- NOT what assumeutxo commitments are computed against. Reverting
    -- 25bdd7d which mistakenly switched this to compute_muhash.
    --
    -- Convention: expected_hash is 32 raw bytes in the natural
    -- (little-endian) HashWriter::GetHash() output order, matching what
    -- compute_utxo_hash returns. Callers passing a hex string from
    -- consensus.assumeutxo.hash_serialized must reverse the bytes first
    -- (uint256.ToString is big-endian display).
    local computed_hash, _ = self:compute_utxo_hash()
    if computed_hash ~= expected_hash then
      return false, "snapshot hash mismatch (hash_serialized)"
    end
  end

  -- Snapshot base block becomes the chainstate tip.  Height is filled in
  -- by the caller via assumeutxo lookup.
  self.tip_hash = metadata.base_blockhash

  return true
end

--------------------------------------------------------------------------------
-- Snapshot Chainstate Manager (for AssumeUTXO dual-chainstate)
--------------------------------------------------------------------------------

-- SnapshotChainstate wraps a ChainState with additional state for background validation
local SnapshotChainstate = {}
SnapshotChainstate.__index = SnapshotChainstate

--- Create a new snapshot chainstate for AssumeUTXO.
-- @param storage table: database handle
-- @param network table: network configuration
-- @param snapshot_height number: height of snapshot base block
-- @param snapshot_hash hash256: hash of snapshot base block
-- @return SnapshotChainstate
function M.new_snapshot_chainstate(storage, network, snapshot_height, snapshot_hash)
  local self = setmetatable({}, SnapshotChainstate)
  self.chain_state = M.new_chain_state(storage, network)
  self.snapshot_height = snapshot_height
  self.snapshot_hash = snapshot_hash
  self.is_snapshot = true
  self.background_validated = false
  return self
end

--- Check if background validation is complete.
-- @return boolean
function SnapshotChainstate:is_validated()
  return self.background_validated
end

--- Mark background validation as complete.
function SnapshotChainstate:set_validated()
  self.background_validated = true
end

--- Get the underlying chain state.
-- @return ChainState
function SnapshotChainstate:get_chain_state()
  return self.chain_state
end

-- Background validation coroutine state
local BackgroundValidator = {}
BackgroundValidator.__index = BackgroundValidator

--- Create a background validator for AssumeUTXO.
-- Validates the chain from genesis to snapshot height using a separate UTXO view.
-- @param storage table: database handle
-- @param network table: network configuration
-- @param target_height number: snapshot height to validate up to
-- @param target_hash string: expected UTXO hash at target height
-- @param get_block function: fn(height) -> block, hash
-- @return BackgroundValidator
function M.new_background_validator(storage, network, target_height, target_hash, get_block)
  local self = setmetatable({}, BackgroundValidator)
  self.chain_state = M.new_chain_state(storage, network)
  self.chain_state:init()
  self.target_height = target_height
  self.target_hash = target_hash
  self.get_block = get_block
  self.current_height = 0
  self.validated = false
  self.error = nil
  self.blocks_per_yield = 100  -- Process 100 blocks per coroutine resume
  return self
end

--- Run one iteration of background validation.
-- Processes blocks_per_yield blocks and returns progress.
-- @return number, number, boolean, string|nil: current_height, target_height, complete, error
function BackgroundValidator:step()
  if self.validated or self.error then
    return self.current_height, self.target_height, self.validated, self.error
  end

  local blocks_processed = 0
  while self.current_height < self.target_height and blocks_processed < self.blocks_per_yield do
    local block, block_hash = self.get_block(self.current_height)
    if not block then
      self.error = string.format("failed to get block at height %d", self.current_height)
      return self.current_height, self.target_height, false, self.error
    end

    -- Connect block (skip script validation for performance during background sync)
    local ok, err = pcall(function()
      self.chain_state:connect_block(block, self.current_height, block_hash, nil, nil, true)
    end)

    if not ok then
      self.error = string.format("failed to connect block %d: %s", self.current_height, err)
      return self.current_height, self.target_height, false, self.error
    end

    self.current_height = self.current_height + 1
    blocks_processed = blocks_processed + 1
  end

  -- Check if we reached target
  if self.current_height >= self.target_height then
    -- Compute UTXO hash and validate
    local computed_hash, _ = self.chain_state:compute_utxo_hash()
    if computed_hash == self.target_hash then
      self.validated = true
    else
      self.error = "background validation UTXO hash mismatch"
    end
  end

  return self.current_height, self.target_height, self.validated, self.error
end

--- Get validation progress as percentage.
-- @return number: 0-100
function BackgroundValidator:progress()
  if self.target_height == 0 then return 100 end
  return math.floor(self.current_height / self.target_height * 100)
end

--- Check if validation is complete.
-- @return boolean
function BackgroundValidator:is_complete()
  return self.validated
end

--- Check if validation encountered an error.
-- @return string|nil: error message or nil
function BackgroundValidator:get_error()
  return self.error
end

return M
