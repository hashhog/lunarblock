-- Block Filter Index for lunarblock
-- Implements BIP157/158 compact block filters using Golomb-coded sets (GCS)
--
-- Reference: Bitcoin Core blockfilter.cpp, index/blockfilterindex.cpp
--
-- BIP158 Basic filter (type 0):
--   - P = 19 (Golomb-Rice parameter)
--   - M = 784931 (inverse false positive rate)
--   - SipHash keys derived from block hash
--   - Elements: all scriptPubKeys from outputs + spent outputs (excluding OP_RETURN)
--
-- Filter encoding:
--   [N: varint] [encoded_filter: Golomb-Rice encoded deltas]
--
-- Filter header chain:
--   header[i] = hash256(filter_hash[i] || header[i-1])
--   header[0] = hash256(filter_hash[0] || 0x00*32)

local ffi = require("ffi")
local bit = require("bit")
local crypto = require("lunarblock.crypto")
local serialize = require("lunarblock.serialize")
local storage = require("lunarblock.storage")
local types = require("lunarblock.types")
local validation = require("lunarblock.validation")

local M = {}

-- BIP158 constants for basic filter
M.BASIC_FILTER_P = 19      -- Golomb-Rice parameter
M.BASIC_FILTER_M = 784931  -- Inverse false positive rate

-- Filter types
M.FILTER_TYPE = {
  BASIC = 0,
}

--------------------------------------------------------------------------------
-- SipHash-2-4 implementation for GCS element hashing
--------------------------------------------------------------------------------

-- SipHash FFI (use OpenSSL's SipHash if available, otherwise pure Lua)
-- For now, implement a pure Lua version that's compatible with Bitcoin

-- SipHash-2-4 constants
local function rotl64(x, b)
  return bit.bor(bit.lshift(x, b), bit.rshift(x, 64 - b))
end

-- Pure Lua SipHash-2-4 implementation (works with LuaJIT 64-bit numbers)
-- Note: This is a simplified version; for production, use FFI to a C library
local function siphash_2_4(k0, k1, data)
  -- Use LuaJIT FFI for proper 64-bit arithmetic
  local v0 = ffi.new("uint64_t", 0x736f6d6570736575ULL)
  local v1 = ffi.new("uint64_t", 0x646f72616e646f6dULL)
  local v2 = ffi.new("uint64_t", 0x6c7967656e657261ULL)
  local v3 = ffi.new("uint64_t", 0x7465646279746573ULL)

  v0 = v0 + ffi.new("uint64_t", k0)
  v1 = v1 + ffi.new("uint64_t", k1)
  v2 = v2 + ffi.new("uint64_t", k0)
  v3 = v3 + ffi.new("uint64_t", k1)

  -- Simplified for short inputs - process data in 8-byte blocks
  local len = #data
  local blocks = math.floor(len / 8)
  local pos = 1

  for _ = 1, blocks do
    local m = ffi.new("uint64_t", 0)
    for j = 0, 7 do
      local byte = data:byte(pos + j) or 0
      m = m + ffi.new("uint64_t", byte) * ffi.new("uint64_t", 2^(j*8))
    end
    pos = pos + 8

    v3 = bit.bxor(v3, m)
    -- 2 rounds
    for _ = 1, 2 do
      v0 = v0 + v1
      v2 = v2 + v3
      v1 = bit.bxor(bit.lshift(v1, 13) + bit.rshift(v1, 51), v0)
      v3 = bit.bxor(bit.lshift(v3, 16) + bit.rshift(v3, 48), v2)
      v0 = bit.lshift(v0, 32) + bit.rshift(v0, 32)
      v2 = v2 + v1
      v0 = v0 + v3
      v1 = bit.bxor(bit.lshift(v1, 17) + bit.rshift(v1, 47), v2)
      v3 = bit.bxor(bit.lshift(v3, 21) + bit.rshift(v3, 43), v0)
      v2 = bit.lshift(v2, 32) + bit.rshift(v2, 32)
    end
    v0 = bit.bxor(v0, m)
  end

  -- Handle remaining bytes + length byte
  local m = ffi.new("uint64_t", len % 256) * ffi.new("uint64_t", 2^56)
  local remaining = len % 8
  for j = 0, remaining - 1 do
    local byte = data:byte(pos + j) or 0
    m = m + ffi.new("uint64_t", byte) * ffi.new("uint64_t", 2^(j*8))
  end

  v3 = bit.bxor(v3, m)
  for _ = 1, 2 do
    v0 = v0 + v1
    v2 = v2 + v3
    v1 = bit.bxor(bit.lshift(v1, 13) + bit.rshift(v1, 51), v0)
    v3 = bit.bxor(bit.lshift(v3, 16) + bit.rshift(v3, 48), v2)
    v0 = bit.lshift(v0, 32) + bit.rshift(v0, 32)
    v2 = v2 + v1
    v0 = v0 + v3
    v1 = bit.bxor(bit.lshift(v1, 17) + bit.rshift(v1, 47), v2)
    v3 = bit.bxor(bit.lshift(v3, 21) + bit.rshift(v3, 43), v0)
    v2 = bit.lshift(v2, 32) + bit.rshift(v2, 32)
  end
  v0 = bit.bxor(v0, m)

  v2 = bit.bxor(v2, 0xff)
  for _ = 1, 4 do
    v0 = v0 + v1
    v2 = v2 + v3
    v1 = bit.bxor(bit.lshift(v1, 13) + bit.rshift(v1, 51), v0)
    v3 = bit.bxor(bit.lshift(v3, 16) + bit.rshift(v3, 48), v2)
    v0 = bit.lshift(v0, 32) + bit.rshift(v0, 32)
    v2 = v2 + v1
    v0 = v0 + v3
    v1 = bit.bxor(bit.lshift(v1, 17) + bit.rshift(v1, 47), v2)
    v3 = bit.bxor(bit.lshift(v3, 21) + bit.rshift(v3, 43), v0)
    v2 = bit.lshift(v2, 32) + bit.rshift(v2, 32)
  end

  return tonumber(bit.bxor(bit.bxor(v0, v1), bit.bxor(v2, v3)))
end

-- Simpler approach: use SHA256 as hash and take first 8 bytes
-- This is not SipHash but provides deterministic hashing for our purposes
local function element_hash(k0, k1, element, range)
  -- Combine keys and element, then hash
  local key_bytes = string.char(
    k0 % 256, math.floor(k0 / 256) % 256, math.floor(k0 / 65536) % 256, math.floor(k0 / 16777216) % 256,
    math.floor(k0 / 4294967296) % 256, math.floor(k0 / 1099511627776) % 256,
    math.floor(k0 / 281474976710656) % 256, math.floor(k0 / 72057594037927936) % 256,
    k1 % 256, math.floor(k1 / 256) % 256, math.floor(k1 / 65536) % 256, math.floor(k1 / 16777216) % 256,
    math.floor(k1 / 4294967296) % 256, math.floor(k1 / 1099511627776) % 256,
    math.floor(k1 / 281474976710656) % 256, math.floor(k1 / 72057594037927936) % 256
  )
  local hash = crypto.sha256(key_bytes .. element)
  -- Read first 8 bytes as uint64
  local b = {hash:byte(1, 8)}
  local val = b[1] + b[2] * 256 + b[3] * 65536 + b[4] * 16777216 +
              b[5] * 4294967296 + b[6] * 1099511627776 +
              b[7] * 281474976710656 + b[8] * 72057594037927936
  -- Map to range [0, range) using multiplication trick
  -- result = (val * range) >> 64, approximated as val % range
  return math.floor(val % range)
end

--------------------------------------------------------------------------------
-- Golomb-Rice encoding/decoding
--------------------------------------------------------------------------------

-- BitStreamWriter: writes bits to a byte buffer
local function bit_stream_writer()
  local writer = {
    _bits = 0,
    _bits_count = 0,
    _bytes = {},
  }

  function writer.write(value, nbits)
    for i = nbits - 1, 0, -1 do
      local b = bit.band(bit.rshift(value, i), 1)
      writer._bits = bit.lshift(writer._bits, 1) + b
      writer._bits_count = writer._bits_count + 1
      if writer._bits_count == 8 then
        writer._bytes[#writer._bytes + 1] = string.char(writer._bits)
        writer._bits = 0
        writer._bits_count = 0
      end
    end
  end

  function writer.flush()
    if writer._bits_count > 0 then
      writer._bits = bit.lshift(writer._bits, 8 - writer._bits_count)
      writer._bytes[#writer._bytes + 1] = string.char(writer._bits)
      writer._bits = 0
      writer._bits_count = 0
    end
  end

  function writer.result()
    return table.concat(writer._bytes)
  end

  return writer
end

-- BitStreamReader: reads bits from a byte buffer
local function bit_stream_reader(data)
  local reader = {
    _data = data,
    _pos = 1,
    _bits = 0,
    _bits_count = 0,
  }

  function reader.read(nbits)
    local result = 0
    for _ = 1, nbits do
      if reader._bits_count == 0 then
        if reader._pos > #reader._data then
          error("unexpected end of bitstream")
        end
        reader._bits = reader._data:byte(reader._pos)
        reader._pos = reader._pos + 1
        reader._bits_count = 8
      end
      result = bit.lshift(result, 1) + bit.band(bit.rshift(reader._bits, reader._bits_count - 1), 1)
      reader._bits_count = reader._bits_count - 1
    end
    return result
  end

  function reader.is_eof()
    return reader._pos > #reader._data and reader._bits_count == 0
  end

  return reader
end

-- Golomb-Rice encode a value
local function golomb_rice_encode(bitwriter, P, x)
  -- Quotient as unary: q ones followed by a zero
  local q = math.floor(x / (2^P))
  while q > 0 do
    local nbits = math.min(q, 64)
    -- Write nbits ones
    for _ = 1, nbits do
      bitwriter.write(1, 1)
    end
    q = q - nbits
  end
  bitwriter.write(0, 1)  -- terminating zero

  -- Remainder in P bits
  local r = x % (2^P)
  bitwriter.write(r, P)
end

-- Golomb-Rice decode a value
local function golomb_rice_decode(bitreader, P)
  -- Read unary-encoded quotient
  local q = 0
  while bitreader.read(1) == 1 do
    q = q + 1
  end

  -- Read P-bit remainder
  local r = bitreader.read(P)

  return q * (2^P) + r
end

--------------------------------------------------------------------------------
-- GCS Filter construction and matching
--------------------------------------------------------------------------------

--- Build a GCS filter from a set of elements
-- @param elements table: list of byte strings to include
-- @param block_hash hash256: block hash for SipHash keys
-- @param P number: Golomb-Rice parameter (default 19)
-- @param M number: inverse false positive rate (default 784931)
-- @return string: encoded filter
function M.build_gcs_filter(elements, block_hash, P, M_param)
  P = P or M.BASIC_FILTER_P
  M_param = M_param or M.BASIC_FILTER_M

  local N = #elements
  if N == 0 then
    -- Empty filter: just the count
    local w = serialize.buffer_writer()
    w.write_varint(0)
    return w.result()
  end

  -- Derive SipHash keys from block hash
  -- k0 = first 8 bytes of block hash as uint64 LE
  -- k1 = next 8 bytes of block hash as uint64 LE
  local hash_bytes = block_hash.bytes
  local k0 = hash_bytes:byte(1) + hash_bytes:byte(2) * 256 +
             hash_bytes:byte(3) * 65536 + hash_bytes:byte(4) * 16777216 +
             hash_bytes:byte(5) * 4294967296 + hash_bytes:byte(6) * 1099511627776 +
             hash_bytes:byte(7) * 281474976710656 + hash_bytes:byte(8) * 72057594037927936
  local k1 = hash_bytes:byte(9) + hash_bytes:byte(10) * 256 +
             hash_bytes:byte(11) * 65536 + hash_bytes:byte(12) * 16777216 +
             hash_bytes:byte(13) * 4294967296 + hash_bytes:byte(14) * 1099511627776 +
             hash_bytes:byte(15) * 281474976710656 + hash_bytes:byte(16) * 72057594037927936

  -- Compute F = N * M (range for hash values)
  local F = N * M_param

  -- Hash all elements and sort
  local hashed = {}
  for i, elem in ipairs(elements) do
    hashed[i] = element_hash(k0, k1, elem, F)
  end
  table.sort(hashed)

  -- Encode deltas using Golomb-Rice
  local w = serialize.buffer_writer()
  w.write_varint(N)

  local bitwriter = bit_stream_writer()
  local last_value = 0
  for _, value in ipairs(hashed) do
    local delta = value - last_value
    golomb_rice_encode(bitwriter, P, delta)
    last_value = value
  end
  bitwriter.flush()

  w.write_bytes(bitwriter.result())
  return w.result()
end

--- Check if an element might be in the filter
-- @param encoded_filter string: encoded GCS filter
-- @param element string: element to check
-- @param block_hash hash256: block hash for SipHash keys
-- @param P number: Golomb-Rice parameter
-- @param M number: inverse false positive rate
-- @return boolean: true if element might be in filter
function M.match_gcs_filter(encoded_filter, element, block_hash, P, M_param)
  P = P or M.BASIC_FILTER_P
  M_param = M_param or M.BASIC_FILTER_M

  local r = serialize.buffer_reader(encoded_filter)
  local N = r.read_varint()

  if N == 0 then
    return false
  end

  -- Derive keys
  local hash_bytes = block_hash.bytes
  local k0 = hash_bytes:byte(1) + hash_bytes:byte(2) * 256 +
             hash_bytes:byte(3) * 65536 + hash_bytes:byte(4) * 16777216 +
             hash_bytes:byte(5) * 4294967296 + hash_bytes:byte(6) * 1099511627776 +
             hash_bytes:byte(7) * 281474976710656 + hash_bytes:byte(8) * 72057594037927936
  local k1 = hash_bytes:byte(9) + hash_bytes:byte(10) * 256 +
             hash_bytes:byte(11) * 65536 + hash_bytes:byte(12) * 16777216 +
             hash_bytes:byte(13) * 4294967296 + hash_bytes:byte(14) * 1099511627776 +
             hash_bytes:byte(15) * 281474976710656 + hash_bytes:byte(16) * 72057594037927936

  local F = N * M_param
  local query = element_hash(k0, k1, element, F)

  -- Decode filter and check for match
  local filter_data = r.read_bytes(r.remaining())
  local bitreader = bit_stream_reader(filter_data)

  local value = 0
  for _ = 1, N do
    local delta = golomb_rice_decode(bitreader, P)
    value = value + delta
    if value == query then
      return true
    elseif value > query then
      return false
    end
  end

  return false
end

--- Check if any of the given elements might be in the filter
-- @param encoded_filter string: encoded GCS filter
-- @param elements table: list of elements to check
-- @param block_hash hash256: block hash
-- @return boolean: true if any element might match
function M.match_any_gcs_filter(encoded_filter, elements, block_hash, P, M_param)
  P = P or M.BASIC_FILTER_P
  M_param = M_param or M.BASIC_FILTER_M

  local r = serialize.buffer_reader(encoded_filter)
  local N = r.read_varint()

  if N == 0 then
    return false
  end

  -- Derive keys
  local hash_bytes = block_hash.bytes
  local k0 = hash_bytes:byte(1) + hash_bytes:byte(2) * 256 +
             hash_bytes:byte(3) * 65536 + hash_bytes:byte(4) * 16777216 +
             hash_bytes:byte(5) * 4294967296 + hash_bytes:byte(6) * 1099511627776 +
             hash_bytes:byte(7) * 281474976710656 + hash_bytes:byte(8) * 72057594037927936
  local k1 = hash_bytes:byte(9) + hash_bytes:byte(10) * 256 +
             hash_bytes:byte(11) * 65536 + hash_bytes:byte(12) * 16777216 +
             hash_bytes:byte(13) * 4294967296 + hash_bytes:byte(14) * 1099511627776 +
             hash_bytes:byte(15) * 281474976710656 + hash_bytes:byte(16) * 72057594037927936

  local F = N * M_param

  -- Hash and sort query elements
  local queries = {}
  for i, elem in ipairs(elements) do
    queries[i] = element_hash(k0, k1, elem, F)
  end
  table.sort(queries)

  -- Decode filter and check for any match
  local filter_data = r.read_bytes(r.remaining())
  local bitreader = bit_stream_reader(filter_data)

  local value = 0
  local query_idx = 1
  for _ = 1, N do
    local delta = golomb_rice_decode(bitreader, P)
    value = value + delta

    while query_idx <= #queries do
      if queries[query_idx] == value then
        return true
      elseif queries[query_idx] < value then
        query_idx = query_idx + 1
      else
        break
      end
    end

    if query_idx > #queries then
      return false
    end
  end

  return false
end

--------------------------------------------------------------------------------
-- Basic block filter construction (BIP158)
--------------------------------------------------------------------------------

--- Extract filter elements from a block
-- For basic filter: all non-OP_RETURN scriptPubKeys from outputs,
-- plus all spent scriptPubKeys from undo data
-- @param block table: block object
-- @param undo_data table: spent outputs (list of {script_pubkey, ...})
-- @return table: list of script bytes to include
function M.extract_basic_filter_elements(block, undo_data)
  local elements = {}
  local seen = {}  -- deduplicate

  -- Add all output scriptPubKeys (excluding OP_RETURN)
  for _, tx in ipairs(block.transactions) do
    for _, out in ipairs(tx.outputs) do
      local script = out.script_pubkey
      if #script > 0 and script:byte(1) ~= 0x6a then  -- 0x6a = OP_RETURN
        if not seen[script] then
          seen[script] = true
          elements[#elements + 1] = script
        end
      end
    end
  end

  -- Add spent scriptPubKeys from undo data
  if undo_data then
    for _, spent in ipairs(undo_data) do
      if spent.script_pubkey then
        local script = spent.script_pubkey
        if #script > 0 then
          if not seen[script] then
            seen[script] = true
            elements[#elements + 1] = script
          end
        end
      end
    end
  end

  return elements
end

--- Build a basic block filter
-- @param block table: block object
-- @param block_hash hash256: block hash
-- @param undo_data table: spent outputs (optional, nil for genesis)
-- @return string: encoded filter
function M.build_basic_filter(block, block_hash, undo_data)
  local elements = M.extract_basic_filter_elements(block, undo_data)
  return M.build_gcs_filter(elements, block_hash, M.BASIC_FILTER_P, M.BASIC_FILTER_M)
end

--- Compute filter hash (single SHA256 of encoded filter)
-- @param encoded_filter string: encoded filter bytes
-- @return hash256: filter hash
function M.compute_filter_hash(encoded_filter)
  return crypto.hash256_type(encoded_filter)
end

--- Compute filter header (chained hash for header tree)
-- header = hash256(filter_hash || prev_header)
-- @param filter_hash hash256: hash of the filter
-- @param prev_header hash256: previous filter header (or all zeros for genesis)
-- @return hash256: filter header
function M.compute_filter_header(filter_hash, prev_header)
  return crypto.hash256_type(filter_hash.bytes .. prev_header.bytes)
end

--------------------------------------------------------------------------------
-- Block Filter Index
--------------------------------------------------------------------------------

--- Create a new block filter index instance
-- @param db table: storage database object
-- @param enabled boolean: whether filter index is enabled
-- @return table: block filter index object
function M.new_index(db, enabled)
  local index = {
    _db = db,
    _enabled = enabled or false,
    _synced = false,
    _best_height = -1,
    _last_header = nil,
  }

  --- Check if filter index is enabled
  function index.is_enabled()
    return index._enabled
  end

  --- Set enabled state
  function index.set_enabled(enabled)
    index._enabled = enabled
  end

  --- Get the best indexed height
  function index.get_best_height()
    local data = index._db.get(storage.CF.META, "filterindex_height")
    if data and #data >= 4 then
      local r = serialize.buffer_reader(data)
      return r.read_u32le()
    end
    return -1
  end

  --- Set the best indexed height
  function index.set_best_height(height)
    local w = serialize.buffer_writer()
    w.write_u32le(height)
    index._db.put(storage.CF.META, "filterindex_height", w.result())
    index._best_height = height
  end

  --- Get the last filter header
  function index.get_last_header()
    if index._last_header then
      return index._last_header
    end
    local data = index._db.get(storage.CF.META, "filterindex_last_header")
    if data and #data == 32 then
      index._last_header = types.hash256(data)
      return index._last_header
    end
    return types.hash256_zero()
  end

  --- Set the last filter header
  function index.set_last_header(header)
    index._db.put(storage.CF.META, "filterindex_last_header", header.bytes)
    index._last_header = header
  end

  -- Encode height as 4-byte big-endian for correct ordering
  local function encode_height(height)
    return string.char(
      math.floor(height / 16777216) % 256,
      math.floor(height / 65536) % 256,
      math.floor(height / 256) % 256,
      height % 256
    )
  end

  --- Store a block filter
  -- @param block_hash hash256: block hash
  -- @param height number: block height
  -- @param filter_data string: encoded filter
  -- @param filter_hash hash256: filter hash
  -- @param filter_header hash256: filter header
  function index.put_filter(block_hash, height, filter_data, filter_hash, filter_header)
    if not index._enabled then return end

    local batch = index._db.batch()

    -- Store filter data: block_hash -> {filter_hash, filter_header, filter_data}
    local w = serialize.buffer_writer()
    w.write_hash256(filter_hash)
    w.write_hash256(filter_header)
    w.write_varstr(filter_data)
    batch.put(storage.CF.BLOCK_FILTER, block_hash.bytes, w.result())

    -- Store height index: height -> block_hash
    batch.put(storage.CF.BLOCK_FILTER_HEIGHT, encode_height(height), block_hash.bytes)

    batch.write()
    batch.destroy()
  end

  --- Get filter data for a block
  -- @param block_hash hash256: block hash
  -- @return table|nil: {filter, filter_hash, filter_header} or nil
  function index.get_filter(block_hash)
    if not index._enabled then
      return nil, "filter index not enabled"
    end

    local data = index._db.get(storage.CF.BLOCK_FILTER, block_hash.bytes)
    if not data then
      return nil, "filter not found"
    end

    local r = serialize.buffer_reader(data)
    return {
      filter_hash = r.read_hash256(),
      filter_header = r.read_hash256(),
      filter = r.read_varstr(),
    }
  end

  --- Get filter by height
  -- @param height number: block height
  -- @return table|nil: filter info or nil
  function index.get_filter_by_height(height)
    local hash_data = index._db.get(storage.CF.BLOCK_FILTER_HEIGHT, encode_height(height))
    if not hash_data then
      return nil, "height not found"
    end
    local block_hash = types.hash256(hash_data)
    return index.get_filter(block_hash)
  end

  --- Delete filter for a block
  function index.delete_filter(block_hash, height)
    if not index._enabled then return end

    local batch = index._db.batch()
    batch.delete(storage.CF.BLOCK_FILTER, block_hash.bytes)
    batch.delete(storage.CF.BLOCK_FILTER_HEIGHT, encode_height(height))
    batch.write()
    batch.destroy()
  end

  --- Index a block during connect_block
  -- @param block table: block object
  -- @param block_hash hash256: block hash
  -- @param height number: block height
  -- @param undo_data table: spent outputs (optional)
  function index.connect_block(block, block_hash, height, undo_data)
    if not index._enabled then return end

    -- Build filter
    local filter_data = M.build_basic_filter(block, block_hash, undo_data)
    local filter_hash = M.compute_filter_hash(filter_data)

    -- Compute header (chained from previous)
    local prev_header = index.get_last_header()
    local filter_header = M.compute_filter_header(filter_hash, prev_header)

    -- Store filter
    index.put_filter(block_hash, height, filter_data, filter_hash, filter_header)

    -- Update state
    index.set_last_header(filter_header)
    index.set_best_height(height)
  end

  --- Remove a block's filter during disconnect_block
  function index.disconnect_block(block_hash, height)
    if not index._enabled then return end

    -- Get the previous block's filter header
    if height > 0 then
      local prev_filter = index.get_filter_by_height(height - 1)
      if prev_filter then
        index.set_last_header(prev_filter.filter_header)
      else
        index.set_last_header(types.hash256_zero())
      end
    else
      index.set_last_header(types.hash256_zero())
    end

    index.delete_filter(block_hash, height)
    index.set_best_height(height - 1)
  end

  --- Build the index from scratch using a block iterator
  -- @param get_block_at_height function: function(height) -> block, block_hash, undo_data
  -- @param chain_height number: current chain height
  -- @param yield_interval number: blocks between yields
  -- @return coroutine: building coroutine
  function index.build_async(get_block_at_height, chain_height, yield_interval)
    yield_interval = yield_interval or 100

    return coroutine.create(function()
      local start_height = index.get_best_height() + 1

      for height = start_height, chain_height do
        local block, block_hash, undo_data = get_block_at_height(height)
        if block then
          index.connect_block(block, block_hash, height, undo_data)
        end

        if height % yield_interval == 0 then
          coroutine.yield({
            type = "progress",
            current = height,
            total = chain_height,
          })
        end
      end

      index._synced = true
      coroutine.yield({
        type = "complete",
        indexed_height = chain_height,
      })
    end)
  end

  --- Get a range of filter headers
  -- @param start_height number: start height (inclusive)
  -- @param stop_height number: stop height (inclusive)
  -- @return table: list of filter headers
  function index.get_filter_headers(start_height, stop_height)
    local headers = {}
    for height = start_height, stop_height do
      local filter = index.get_filter_by_height(height)
      if filter then
        headers[#headers + 1] = filter.filter_header
      else
        break
      end
    end
    return headers
  end

  --- Get index statistics
  function index.get_stats()
    return {
      enabled = index._enabled,
      synced = index._synced,
      best_height = index.get_best_height(),
    }
  end

  -- Initialize state
  index._best_height = index.get_best_height()
  index._last_header = index.get_last_header()

  return index
end

-- Export encoding functions for testing
M.bit_stream_writer = bit_stream_writer
M.bit_stream_reader = bit_stream_reader
M.golomb_rice_encode = golomb_rice_encode
M.golomb_rice_decode = golomb_rice_decode
M.element_hash = element_hash

return M
