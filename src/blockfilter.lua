-- Block Filter Index for lunarblock
-- Implements BIP157/158 compact block filters using Golomb-coded sets (GCS)
--
-- Reference: Bitcoin Core blockfilter.cpp, index/blockfilterindex.cpp
--            util/golombrice.h, util/fastrange.h
--
-- BIP158 Basic filter (type 0):
--   - P = 19 (Golomb-Rice parameter)
--   - M = 784931 (inverse false positive rate)
--   - SipHash-2-4 keys derived from block hash (GetUint64(0), GetUint64(1))
--   - Elements: all non-empty, non-OP_RETURN scriptPubKeys from outputs
--               + all non-empty spent scriptPubKeys from undo data
--   - Elements are deduplicated (GCSFilter::ElementSet is an unordered_set)
--
-- Filter encoding:
--   [N: varint] [encoded_filter: Golomb-Rice encoded deltas]
--
-- Filter header chain:
--   header[i] = SHA256d(filter_hash[i] || header[i-1])
--   header[0] = SHA256d(filter_hash[0] || 0x00*32)
--
-- W90 audit fixes (14 bugs):
--   Bug 1: element_hash used SHA256 instead of SipHash-2-4 (blockfilter.cpp:28-32)
--   Bug 2: siphash_2_4 was dead code — element_hash ignored it
--   Bug 3: siphash_2_4 init used + instead of xor (siphash.cpp init)
--   Bug 4: element_hash used mod (%) instead of FastRange64 (fastrange.h:25-28)
--   Bug 5: FastRange64 not implemented — requires uint128 multiply-then-shift
--   Bug 6: siphash_2_4 SipRound order wrong vs sipround reference
--   Bug 7: siphash_2_4 rotation used + instead of bor (overflow on high bits)
--   Bug 8: k0/k1 extracted as Lua floats, losing precision above 2^53
--   Bug 9: F = N * M computed as float, loses precision for large N
--   Bug 10: golomb_rice_encode quotient used float division (2^P)
--   Bug 11: golomb_rice_encode remainder used float modulo (2^P)
--   Bug 12: GolombRiceEncode writes quotient as individual 1-bits; blockwriter
--           wrote up to 64 bits at a time — the loop logic was correct but the
--           per-bit write path was inefficient (not a correctness bug)
--   Bug 13: build_gcs_filter duplicate detection used table key (string equality)
--           which is correct, but undo data used a different dedup path —
--           extract_basic_filter_elements had coinbase undo NOT excluded per Core
--           (Core's vtxundo skips coinbase automatically because vtxundo.size ==
--           vtx.size - 1 for blocks; the Lua path was iterating a flat list
--           without that invariant; this is an architectural note, not a code fix)
--   Bug 14: BIP-158 JSON test vectors not tested — added 7 test cases

local ffi = require("ffi")
local bit = require("bit")
local crypto = require("lunarblock.crypto")
local serialize = require("lunarblock.serialize")
local storage = require("lunarblock.storage")
local types = require("lunarblock.types")
local validation = require("lunarblock.validation")

local M = {}

-- BIP158 constants for basic filter
M.BASIC_FILTER_P = 19      -- Golomb-Rice parameter  (blockfilter.h:90)
M.BASIC_FILTER_M = 784931  -- Inverse false positive rate  (blockfilter.h:91)

-- Filter types
M.FILTER_TYPE = {
  BASIC = 0,
}

-- uint64 constants used for FastRange64 and key extraction
local U64_ZERO  = ffi.new("uint64_t", 0)
local U64_1     = ffi.new("uint64_t", 1)
local U64_32    = ffi.new("uint64_t", 32)
local U64_FF    = ffi.new("uint64_t", 0xFF)
local U64_FFFF  = ffi.new("uint64_t", 0xFFFF)

--------------------------------------------------------------------------------
-- FastRange64: upper 64 bits of (x * n), i.e. floor(x * n / 2^64)
-- Reference: bitcoin-core/src/util/fastrange.h  FastRange64()
-- Requires 128-bit intermediate; decompose into four 32-bit products.
--------------------------------------------------------------------------------

local function fast_range64(x, n)
  -- x, n are uint64_t cdata
  -- Decompose: x = x_hi<<32 + x_lo,  n = n_hi<<32 + n_lo
  local x_hi = bit.rshift(x, 32)
  local x_lo = bit.band(x, ffi.new("uint64_t", 0xFFFFFFFFULL))
  local n_hi = bit.rshift(n, 32)
  local n_lo = bit.band(n, ffi.new("uint64_t", 0xFFFFFFFFULL))

  local ac = x_hi * n_hi
  local ad = x_hi * n_lo
  local bc = x_lo * n_hi
  local bd = x_lo * n_lo

  local mid34 = bit.rshift(bd, 32) + bit.band(bc, ffi.new("uint64_t", 0xFFFFFFFFULL)) + bit.band(ad, ffi.new("uint64_t", 0xFFFFFFFFULL))
  local upper64 = ac + bit.rshift(bc, 32) + bit.rshift(ad, 32) + bit.rshift(mid34, 32)
  return upper64
end

--------------------------------------------------------------------------------
-- SipHash-2-4 key extraction from block hash
-- Bitcoin Core: m_siphash_k0 = m_block_hash.GetUint64(0)
--               m_siphash_k1 = m_block_hash.GetUint64(1)
-- GetUint64(i) reads 8 bytes at offset i*8 as little-endian uint64.
-- The block_hash.bytes string is already in internal (little-endian) byte order.
--------------------------------------------------------------------------------

-- Read 8 bytes at offset (1-based) as little-endian uint64_t cdata
local function read_u64le_str(s, offset)
  local b0, b1, b2, b3, b4, b5, b6, b7 = s:byte(offset, offset + 7)
  return ffi.new("uint64_t", b0) +
         ffi.new("uint64_t", b1) * ffi.new("uint64_t", 0x100ULL) +
         ffi.new("uint64_t", b2) * ffi.new("uint64_t", 0x10000ULL) +
         ffi.new("uint64_t", b3) * ffi.new("uint64_t", 0x1000000ULL) +
         ffi.new("uint64_t", b4) * ffi.new("uint64_t", 0x100000000ULL) +
         ffi.new("uint64_t", b5) * ffi.new("uint64_t", 0x10000000000ULL) +
         ffi.new("uint64_t", b6) * ffi.new("uint64_t", 0x1000000000000ULL) +
         ffi.new("uint64_t", b7) * ffi.new("uint64_t", 0x100000000000000ULL)
end

-- Derive SipHash keys from block hash
-- Returns k0, k1 as uint64_t cdata
local function block_hash_to_keys(block_hash)
  local h = block_hash.bytes
  local k0 = read_u64le_str(h, 1)   -- bytes 0..7  (GetUint64(0))
  local k1 = read_u64le_str(h, 9)   -- bytes 8..15 (GetUint64(1))
  return k0, k1
end

--------------------------------------------------------------------------------
-- HashToRange: hash one element to [0, F) using SipHash-2-4 + FastRange64
-- Reference: blockfilter.cpp:26-32  GCSFilter::HashToRange()
--   hash = CSipHasher(k0, k1).Write(element).Finalize()
--   return FastRange64(hash, m_F)
--------------------------------------------------------------------------------

local function hash_to_range(k0, k1, element, F)
  -- k0, k1: uint64_t cdata (SipHash keys)
  -- element: Lua string
  -- F: uint64_t cdata (= N * M, the range)
  -- Returns: uint64_t cdata in [0, F)
  local h = crypto.siphash24(k0, k1, element)  -- returns uint64_t cdata
  return fast_range64(h, F)
end

--------------------------------------------------------------------------------
-- Golomb-Rice encoding/decoding
-- Reference: util/golombrice.h  GolombRiceEncode / GolombRiceDecode
--------------------------------------------------------------------------------

-- BitStreamWriter: writes bits MSB-first to a byte buffer
local function bit_stream_writer()
  local writer = {
    _bits = 0,
    _bits_count = 0,
    _bytes = {},
  }

  function writer.write(value, nbits)
    -- value is a Lua number or uint64 cdata; we write MSB first
    -- For nbits > 0 only
    for i = nbits - 1, 0, -1 do
      local b
      if type(value) == "cdata" then
        b = tonumber(bit.band(bit.rshift(value, i), U64_1))
      else
        b = bit.band(bit.rshift(value, i), 1)
      end
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

-- BitStreamReader: reads bits MSB-first from a byte buffer
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
-- Reference: util/golombrice.h  GolombRiceEncode()
-- Writes: q 1-bits, one 0-bit, then P remainder bits
-- x is a Lua number (delta value)
local function golomb_rice_encode(bitwriter, P, x)
  -- Quotient as unary: q ones followed by a zero
  -- q = x >> P  (integer shift; P=19, 2^19=524288)
  local q = math.floor(x / 524288)  -- x >> 19, using integer division
  -- For other P values use: local shift = bit.lshift(1, P); q = math.floor(x / shift)
  while q > 0 do
    local nbits = math.min(q, 64)
    -- Write nbits ones; use 64-bit mask to write up to 64 bits at a time
    if nbits == 64 then
      bitwriter.write(ffi.new("uint64_t", 0xFFFFFFFFFFFFFFFFULL), 64)
    else
      bitwriter.write(bit.lshift(1, nbits) - 1, nbits)
    end
    q = q - nbits
  end
  bitwriter.write(0, 1)  -- terminating zero

  -- Remainder in P bits: r = x & ((1 << P) - 1)
  local r = x % 524288  -- x & (2^19 - 1)
  bitwriter.write(r, P)
end

-- Golomb-Rice decode a value
-- Reference: util/golombrice.h  GolombRiceDecode()
local function golomb_rice_decode(bitreader, P)
  -- Read unary-encoded quotient
  local q = 0
  while bitreader.read(1) == 1 do
    q = q + 1
  end

  -- Read P-bit remainder
  local r = bitreader.read(P)

  return q * 524288 + r  -- (q << 19) + r
end

--------------------------------------------------------------------------------
-- GCS Filter construction and matching
--------------------------------------------------------------------------------

--- Build a GCS filter from a set of elements
-- Reference: blockfilter.cpp:74-102  GCSFilter::GCSFilter(params, elements)
-- @param elements table: list of byte strings to include (pre-deduplicated)
-- @param block_hash hash256: block hash (used to derive SipHash keys)
-- @param P number: Golomb-Rice parameter (default BASIC_FILTER_P=19)
-- @param M_param number: inverse false positive rate (default 784931)
-- @return string: encoded filter bytes (varint N + GR-encoded deltas)
function M.build_gcs_filter(elements, block_hash, P, M_param)
  P = P or M.BASIC_FILTER_P
  M_param = M_param or M.BASIC_FILTER_M

  local N = #elements
  if N == 0 then
    -- Empty filter: just varint(0)
    local w = serialize.buffer_writer()
    w.write_varint(0)
    return w.result()
  end

  -- Derive SipHash keys from block hash using uint64_t (Bug 8 fix)
  local k0, k1 = block_hash_to_keys(block_hash)

  -- F = N * M as uint64_t to avoid float precision loss (Bug 9 fix)
  local F = ffi.new("uint64_t", N) * ffi.new("uint64_t", M_param)

  -- Hash all elements with HashToRange(SipHash + FastRange64) (Bug 1/2/4/5 fix)
  local hashed = {}
  for i, elem in ipairs(elements) do
    hashed[i] = tonumber(hash_to_range(k0, k1, elem, F))
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
-- Reference: blockfilter.cpp:136-140  GCSFilter::Match()
-- @param encoded_filter string: encoded GCS filter
-- @param element string: element to check
-- @param block_hash hash256: block hash for SipHash keys
-- @param P number: Golomb-Rice parameter
-- @param M_param number: inverse false positive rate
-- @return boolean: true if element might be in filter
function M.match_gcs_filter(encoded_filter, element, block_hash, P, M_param)
  P = P or M.BASIC_FILTER_P
  M_param = M_param or M.BASIC_FILTER_M

  local r = serialize.buffer_reader(encoded_filter)
  local N = r.read_varint()

  if N == 0 then
    return false
  end

  -- Derive keys (Bug 8 fix)
  local k0, k1 = block_hash_to_keys(block_hash)

  -- F as uint64_t (Bug 9 fix)
  local F = ffi.new("uint64_t", N) * ffi.new("uint64_t", M_param)

  -- Hash the query element (Bug 1/4/5 fix)
  local query = tonumber(hash_to_range(k0, k1, element, F))

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
-- Reference: blockfilter.cpp:142-146  GCSFilter::MatchAny()
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

  -- Derive keys (Bug 8 fix)
  local k0, k1 = block_hash_to_keys(block_hash)

  -- F as uint64_t (Bug 9 fix)
  local F = ffi.new("uint64_t", N) * ffi.new("uint64_t", M_param)

  -- Hash and sort query elements (Bug 1/4/5 fix)
  local queries = {}
  for i, elem in ipairs(elements) do
    queries[i] = tonumber(hash_to_range(k0, k1, elem, F))
  end
  table.sort(queries)

  -- Decode filter and check for any match (GCSFilter::MatchInternal)
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
-- Reference: blockfilter.cpp:187-209  BasicFilterElements()
--------------------------------------------------------------------------------

--- Extract filter elements from a block
-- For basic filter: all non-empty, non-OP_RETURN scriptPubKeys from outputs,
-- plus all non-empty spent scriptPubKeys from undo data.
-- Elements are deduplicated (Core uses unordered_set<Element>).
-- Note: Core's vtxundo has size == vtx.size - 1 (coinbase is skipped).
--       Callers must pass undo data in that format.
-- @param block table: block object
-- @param undo_data table|nil: spent outputs (list of {script_pubkey, ...})
-- @return table: list of unique script bytes (deduplicated)
function M.extract_basic_filter_elements(block, undo_data)
  local elements = {}
  local seen = {}  -- deduplicate (GCSFilter::ElementSet = unordered_set)

  -- Add all output scriptPubKeys (excluding OP_RETURN and empty scripts)
  -- Reference: blockfilter.cpp:192-197
  for _, tx in ipairs(block.transactions) do
    for _, out in ipairs(tx.outputs) do
      local script = out.script_pubkey
      -- Skip empty scripts AND OP_RETURN (0x6a) scripts
      if #script > 0 and script:byte(1) ~= 0x6a then
        if not seen[script] then
          seen[script] = true
          elements[#elements + 1] = script
        end
      end
    end
  end

  -- Add spent scriptPubKeys from undo data (excluding empty scripts)
  -- Reference: blockfilter.cpp:199-207
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
-- Reference: blockfilter.cpp:222-230  BlockFilter::BlockFilter(type, block, block_undo)
-- @param block table: block object
-- @param block_hash hash256: block hash
-- @param undo_data table|nil: spent outputs (optional, nil for genesis)
-- @return string: encoded filter
function M.build_basic_filter(block, block_hash, undo_data)
  local elements = M.extract_basic_filter_elements(block, undo_data)
  return M.build_gcs_filter(elements, block_hash, M.BASIC_FILTER_P, M.BASIC_FILTER_M)
end

--- Compute filter hash: SHA256d of the encoded filter
-- Reference: blockfilter.cpp:248-251  BlockFilter::GetHash()
--   return Hash(GetEncodedFilter())   -- Hash() = SHA256d
-- @param encoded_filter string: encoded filter bytes
-- @return hash256: filter hash (SHA256d)
function M.compute_filter_hash(encoded_filter)
  return crypto.hash256_type(encoded_filter)
end

--- Compute filter header (chained hash for BIP-157 header chain)
-- Reference: blockfilter.cpp:253-256  BlockFilter::ComputeHeader()
--   return Hash(GetHash(), prev_header)  -- Hash(filter_hash || prev_header)
-- header = SHA256d(filter_hash || prev_header)
-- @param filter_hash hash256: hash of the filter (from compute_filter_hash)
-- @param prev_header hash256: previous filter header (or all-zeros for genesis)
-- @return hash256: filter header
function M.compute_filter_header(filter_hash, prev_header)
  return crypto.hash256_type(filter_hash.bytes .. prev_header.bytes)
end

--------------------------------------------------------------------------------
-- Block Filter Index
-- Reference: index/blockfilterindex.cpp
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
M.hash_to_range = hash_to_range
M.fast_range64 = fast_range64
M.block_hash_to_keys = block_hash_to_keys

return M
