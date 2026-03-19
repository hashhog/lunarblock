-- Performance utilities for LunarBlock
-- Applies LuaJIT FFI best practices: avoid callbacks, batch FFI calls, reuse buffers
local ffi = require("ffi")
local bit = require("bit")
local M = {}

--------------------------------------------------------------------------------
-- Buffer Pool
--------------------------------------------------------------------------------

-- Pre-allocated buffer pool to avoid repeated ffi.new allocations in hot paths
local buffer_pool = {}
local POOL_SIZE = 16
local BUFFER_SIZE = 4096

for i = 1, POOL_SIZE do
  buffer_pool[i] = {
    buf = ffi.new("uint8_t[?]", BUFFER_SIZE),
    size = BUFFER_SIZE,
    in_use = false,
  }
end

--- Acquire a buffer from the pool.
-- @param min_size number: minimum buffer size (default 4096)
-- @return table: buffer entry {buf=cdata, size=number, in_use=bool}
function M.acquire_buffer(min_size)
  min_size = min_size or BUFFER_SIZE
  for i = 1, POOL_SIZE do
    local entry = buffer_pool[i]
    if not entry.in_use and entry.size >= min_size then
      entry.in_use = true
      return entry
    end
  end
  -- Fallback: allocate a new buffer (not pooled, will be GC'd)
  return {
    buf = ffi.new("uint8_t[?]", min_size),
    size = min_size,
    in_use = true,
    ephemeral = true,
  }
end

--- Release a buffer back to the pool.
-- @param entry table: buffer entry from acquire_buffer
function M.release_buffer(entry)
  if not entry.ephemeral then
    entry.in_use = false
  end
end

--- Get current pool statistics.
-- @return table: {total=number, in_use=number, available=number}
function M.pool_stats()
  local in_use = 0
  for i = 1, POOL_SIZE do
    if buffer_pool[i].in_use then
      in_use = in_use + 1
    end
  end
  return {
    total = POOL_SIZE,
    in_use = in_use,
    available = POOL_SIZE - in_use,
  }
end

--------------------------------------------------------------------------------
-- Table Pre-allocation
--------------------------------------------------------------------------------

-- LuaJIT's table.new is available via require("table.new")
-- Provides hints to the allocator about expected table sizes
local table_new_ok, table_new = pcall(require, "table.new")
if not table_new_ok then
  -- Fallback for environments without table.new
  table_new = function() return {} end
end

--- Pre-allocate a table for array usage (transaction lists, etc).
-- @param capacity number: expected number of array elements
-- @return table: pre-allocated table
function M.new_tx_list(capacity)
  return table_new(capacity, 0)
end

--- Pre-allocate a table for hash map usage (UTXO cache, etc).
-- @param capacity number: expected number of hash entries
-- @return table: pre-allocated table
function M.new_hash_map(capacity)
  return table_new(0, capacity)
end

--- Pre-allocate a table with both array and hash parts.
-- @param array_size number: expected array elements
-- @param hash_size number: expected hash entries
-- @return table: pre-allocated table
function M.new_table(array_size, hash_size)
  return table_new(array_size, hash_size)
end

--------------------------------------------------------------------------------
-- String Buffer (for serialization hot paths)
--------------------------------------------------------------------------------

-- LuaJIT 2.1+ provides string.buffer for efficient string building
local string_buffer_ok, string_buffer = pcall(require, "string.buffer")

--- Create a new serialize buffer.
-- Uses string.buffer if available, falls back to table-based buffer.
-- @param initial_size number: initial capacity (default 4096)
-- @return table: buffer object with put, get, reset methods
function M.new_serialize_buffer(initial_size)
  initial_size = initial_size or 4096

  if string_buffer_ok then
    -- Use LuaJIT's native string.buffer
    local buf = string_buffer.new(initial_size)
    return {
      put = function(self, ...)
        buf:put(...)
        return self
      end,
      get = function()
        return buf:get()
      end,
      reset = function()
        buf:reset()
      end,
      tostring = function()
        return buf:tostring()
      end,
      _native = true,
    }
  else
    -- Fallback: table-based buffer
    local parts = {}
    return {
      put = function(self, ...)
        for i = 1, select("#", ...) do
          parts[#parts + 1] = select(i, ...)
        end
        return self
      end,
      get = function()
        local result = table.concat(parts)
        parts = {}
        return result
      end,
      reset = function()
        parts = {}
      end,
      tostring = function()
        return table.concat(parts)
      end,
      _native = false,
    }
  end
end

--- Encode a 32-bit unsigned LE integer into a buffer.
-- @param buf table: serialize buffer
-- @param val number: value to encode
function M.put_u32_le(buf, val)
  buf:put(
    string.char(bit.band(val, 0xff)),
    string.char(bit.band(bit.rshift(val, 8), 0xff)),
    string.char(bit.band(bit.rshift(val, 16), 0xff)),
    string.char(bit.band(bit.rshift(val, 24), 0xff))
  )
end

--- Encode a 64-bit unsigned LE integer into a buffer.
-- @param buf table: serialize buffer
-- @param val number: value to encode (up to 2^53)
function M.put_u64_le(buf, val)
  local lo = val % 4294967296
  local hi = math.floor(val / 4294967296)
  M.put_u32_le(buf, lo)
  M.put_u32_le(buf, hi)
end

--- Encode a varint into a buffer.
-- @param buf table: serialize buffer
-- @param val number: value to encode
function M.put_varint(buf, val)
  if val < 0xFD then
    buf:put(string.char(val))
  elseif val <= 0xFFFF then
    buf:put(string.char(0xFD))
    buf:put(string.char(bit.band(val, 0xff)))
    buf:put(string.char(bit.band(bit.rshift(val, 8), 0xff)))
  elseif val <= 0xFFFFFFFF then
    buf:put(string.char(0xFE))
    M.put_u32_le(buf, val)
  else
    buf:put(string.char(0xFF))
    M.put_u64_le(buf, val)
  end
end

--------------------------------------------------------------------------------
-- LRU Cache
--------------------------------------------------------------------------------

-- Generic LRU cache with O(1) lookup, insert, and eviction
-- Uses a doubly-linked list for ordering and a hash table for lookups.

local LRUCache = {}
LRUCache.__index = LRUCache

--- Create a new LRU cache.
-- @param max_entries number: maximum cache entries (default 1000)
-- @return LRUCache: cache object
function M.new_lru_cache(max_entries)
  local self = setmetatable({}, LRUCache)
  self.entries = table_new(0, max_entries or 1000)  -- key -> node
  self.head = nil   -- most recently used
  self.tail = nil   -- least recently used
  self.count = 0
  self.max_entries = max_entries or 1000
  self.hits = 0
  self.misses = 0
  return self
end

--- Move a node to the head of the LRU list.
-- @param node table: the node to move
function LRUCache:_move_to_head(node)
  if node == self.head then return end

  -- Remove from current position
  if node.prev then node.prev.next = node.next end
  if node.next then node.next.prev = node.prev end
  if node == self.tail then self.tail = node.prev end

  -- Insert at head
  node.prev = nil
  node.next = self.head
  if self.head then self.head.prev = node end
  self.head = node
  if not self.tail then self.tail = node end
end

--- Evict the least recently used entry.
function LRUCache:_evict_tail()
  if not self.tail then return end

  local node = self.tail
  self.entries[node.key] = nil

  if node.prev then
    node.prev.next = nil
    self.tail = node.prev
  else
    self.head = nil
    self.tail = nil
  end

  self.count = self.count - 1
  return node.key, node.value
end

--- Get a value from the cache.
-- @param key string: cache key
-- @return any: cached value or nil
function LRUCache:get(key)
  local node = self.entries[key]
  if node then
    self.hits = self.hits + 1
    self:_move_to_head(node)
    return node.value
  end
  self.misses = self.misses + 1
  return nil
end

--- Put a value into the cache.
-- @param key string: cache key
-- @param value any: value to cache
function LRUCache:put(key, value)
  local existing = self.entries[key]
  if existing then
    existing.value = value
    self:_move_to_head(existing)
    return
  end

  -- Evict if at capacity
  if self.count >= self.max_entries then
    self:_evict_tail()
  end

  -- Create new node
  local node = { key = key, value = value, prev = nil, next = nil }
  self.entries[key] = node
  self:_move_to_head(node)
  self.count = self.count + 1
end

--- Remove a value from the cache.
-- @param key string: cache key
-- @return any: removed value or nil
function LRUCache:remove(key)
  local node = self.entries[key]
  if not node then return nil end

  -- Remove from list
  if node.prev then node.prev.next = node.next end
  if node.next then node.next.prev = node.prev end
  if node == self.head then self.head = node.next end
  if node == self.tail then self.tail = node.prev end

  self.entries[key] = nil
  self.count = self.count - 1
  return node.value
end

--- Get cache statistics.
-- @return table: {count, max_entries, hits, misses, hit_rate}
function LRUCache:stats()
  local total = self.hits + self.misses
  return {
    count = self.count,
    max_entries = self.max_entries,
    hits = self.hits,
    misses = self.misses,
    hit_rate = total > 0 and (self.hits / total) or 0,
  }
end

--- Clear the cache.
function LRUCache:clear()
  self.entries = table_new(0, self.max_entries)
  self.head = nil
  self.tail = nil
  self.count = 0
  -- Keep hit/miss stats
end

--------------------------------------------------------------------------------
-- Fast Copy Utilities
--------------------------------------------------------------------------------

--- Copy bytes from Lua string to FFI buffer.
-- @param dst cdata: destination buffer
-- @param src string: source data
-- @param len number: bytes to copy (default: #src)
-- @param dst_offset number: offset in destination (default: 0)
function M.copy_to_ffi(dst, src, len, dst_offset)
  len = len or #src
  dst_offset = dst_offset or 0
  ffi.copy(dst + dst_offset, src, len)
end

--- Copy bytes from FFI buffer to Lua string.
-- @param src cdata: source buffer
-- @param len number: bytes to copy
-- @param offset number: offset in source (default: 0)
-- @return string: copied data
function M.copy_from_ffi(src, len, offset)
  offset = offset or 0
  return ffi.string(src + offset, len)
end

--- Fill FFI buffer with a byte value.
-- @param dst cdata: destination buffer
-- @param len number: bytes to fill
-- @param val number: byte value (default: 0)
-- @param offset number: offset in destination (default: 0)
function M.fill_ffi(dst, len, val, offset)
  val = val or 0
  offset = offset or 0
  ffi.fill(dst + offset, len, val)
end

--------------------------------------------------------------------------------
-- Batch Serialization (minimize FFI calls)
--------------------------------------------------------------------------------

--- Serialize a block header efficiently.
-- Builds complete 80-byte header in a single buffer operation.
-- @param header table: block header {version, prev_hash, merkle_root, timestamp, bits, nonce}
-- @return string: serialized 80-byte header
function M.serialize_block_header_fast(header)
  local buf = M.new_serialize_buffer(80)
  M.put_u32_le(buf, header.version < 0 and header.version + 4294967296 or header.version)
  buf:put(header.prev_hash.bytes)
  buf:put(header.merkle_root.bytes)
  M.put_u32_le(buf, header.timestamp)
  M.put_u32_le(buf, header.bits)
  M.put_u32_le(buf, header.nonce)
  return buf:get()
end

--------------------------------------------------------------------------------
-- Benchmarking Utilities
--------------------------------------------------------------------------------

--- High-precision timer using LuaJIT FFI.
local clock_gettime
local CLOCK_MONOTONIC = 1

-- Try to use clock_gettime for sub-microsecond precision
pcall(function()
  ffi.cdef[[
    typedef long time_t;
    typedef struct timespec { time_t tv_sec; long tv_nsec; } timespec;
    int clock_gettime(int clk_id, struct timespec *tp);
  ]]
  local ts = ffi.new("struct timespec")
  clock_gettime = function()
    ffi.C.clock_gettime(CLOCK_MONOTONIC, ts)
    return tonumber(ts.tv_sec) + tonumber(ts.tv_nsec) / 1e9
  end
end)

-- Fallback to os.clock if clock_gettime is not available
if not clock_gettime then
  clock_gettime = os.clock
end

--- Get current time in seconds with high precision.
-- @return number: current time in seconds
function M.now()
  return clock_gettime()
end

--- Benchmark a function with the given number of iterations.
-- @param name string: benchmark name
-- @param fn function: function to benchmark
-- @param iterations number: number of iterations (default 1000)
-- @param warmup number: warmup iterations (default 10)
-- @return table: {name, iterations, total_time, avg_time, ops_per_sec}
function M.benchmark(name, fn, iterations, warmup)
  iterations = iterations or 1000
  warmup = warmup or 10

  -- Warmup: let JIT compile the code
  for _ = 1, warmup do
    fn()
  end

  -- Actual benchmark
  local start = M.now()
  for _ = 1, iterations do
    fn()
  end
  local elapsed = M.now() - start

  return {
    name = name,
    iterations = iterations,
    total_time = elapsed,
    avg_time = elapsed / iterations,
    ops_per_sec = iterations / elapsed,
  }
end

--- Run a series of benchmarks and return results.
-- @param benchmarks table: array of {name, fn, iterations, warmup}
-- @return table: array of benchmark results
function M.run_benchmarks(benchmarks)
  local results = {}
  for _, b in ipairs(benchmarks) do
    results[#results + 1] = M.benchmark(b.name, b.fn, b.iterations, b.warmup)
  end
  return results
end

--- Format benchmark results as a string.
-- @param results table: array of benchmark results
-- @return string: formatted results
function M.format_benchmark_results(results)
  local lines = { "Benchmark Results:", string.rep("-", 70) }
  for _, r in ipairs(results) do
    lines[#lines + 1] = string.format(
      "%-40s %10d iter %10.3f ms %12.0f ops/s",
      r.name, r.iterations, r.total_time * 1000, r.ops_per_sec
    )
  end
  lines[#lines + 1] = string.rep("-", 70)
  return table.concat(lines, "\n")
end

--------------------------------------------------------------------------------
-- Crypto Benchmarks
--------------------------------------------------------------------------------

--- Run SHA256 benchmark comparing FFI implementation.
-- @param iterations number: number of iterations (default 10000)
-- @return table: benchmark result
function M.benchmark_sha256(iterations)
  iterations = iterations or 10000
  local crypto = require("lunarblock.crypto")

  -- Generate random test data
  local test_data = crypto.random_bytes(256)

  return M.benchmark("SHA256 (FFI/OpenSSL)", function()
    crypto.sha256(test_data)
  end, iterations)
end

--- Run double-SHA256 (hash256) benchmark.
-- @param iterations number: number of iterations (default 10000)
-- @return table: benchmark result
function M.benchmark_hash256(iterations)
  iterations = iterations or 10000
  local crypto = require("lunarblock.crypto")

  local test_data = crypto.random_bytes(256)

  return M.benchmark("hash256/SHA256d (FFI)", function()
    crypto.hash256(test_data)
  end, iterations)
end

--- Run RIPEMD160 benchmark.
-- @param iterations number: number of iterations (default 10000)
-- @return table: benchmark result
function M.benchmark_ripemd160(iterations)
  iterations = iterations or 10000
  local crypto = require("lunarblock.crypto")

  local test_data = crypto.random_bytes(256)

  return M.benchmark("RIPEMD160 (FFI/OpenSSL)", function()
    crypto.ripemd160(test_data)
  end, iterations)
end

--- Run HASH160 benchmark (RIPEMD160(SHA256(x))).
-- @param iterations number: number of iterations (default 10000)
-- @return table: benchmark result
function M.benchmark_hash160(iterations)
  iterations = iterations or 10000
  local crypto = require("lunarblock.crypto")

  -- Typical pubkey size
  local test_data = crypto.random_bytes(33)

  return M.benchmark("HASH160 (FFI)", function()
    crypto.hash160(test_data)
  end, iterations)
end

--- Run ECDSA signature verification benchmark.
-- @param iterations number: number of iterations (default 1000)
-- @return table: benchmark result
function M.benchmark_ecdsa_verify(iterations)
  iterations = iterations or 1000
  local crypto = require("lunarblock.crypto")

  -- Generate a keypair and signature for testing
  local privkey = crypto.random_bytes(32)
  -- Ensure privkey is valid (not zero, not >= order)
  local pubkey = crypto.pubkey_from_privkey(privkey, true)
  if not pubkey then
    -- Try again with a different key
    privkey = ("\x00"):rep(31) .. "\x01"
    pubkey = crypto.pubkey_from_privkey(privkey, true)
  end

  local msg_hash = crypto.sha256("benchmark test message")
  local sig = crypto.ecdsa_sign(privkey, msg_hash)

  return M.benchmark("ECDSA verify (libsecp256k1)", function()
    crypto.ecdsa_verify(pubkey, sig, msg_hash)
  end, iterations)
end

--- Run ECDSA signing benchmark.
-- @param iterations number: number of iterations (default 1000)
-- @return table: benchmark result
function M.benchmark_ecdsa_sign(iterations)
  iterations = iterations or 1000
  local crypto = require("lunarblock.crypto")

  local privkey = ("\x00"):rep(31) .. "\x01"  -- Private key = 1
  local msg_hash = crypto.sha256("benchmark test message")

  return M.benchmark("ECDSA sign (libsecp256k1)", function()
    crypto.ecdsa_sign(privkey, msg_hash)
  end, iterations)
end

--- Run Schnorr signature verification benchmark.
-- @param iterations number: number of iterations (default 1000)
-- @return table: benchmark result
function M.benchmark_schnorr_verify(iterations)
  iterations = iterations or 1000
  local crypto = require("lunarblock.crypto")

  -- Use a known x-only pubkey (32 bytes) for BIP340 verification
  -- This is the x-coordinate of generator point G
  local xonly_pubkey = string.char(
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
    0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
    0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98
  )

  -- A valid BIP340 signature (64 bytes) - this is a test vector
  -- For benchmarking, we just need any valid format signature
  local sig64 = crypto.random_bytes(64)
  local msg = crypto.sha256("benchmark schnorr test")

  return M.benchmark("Schnorr verify (libsecp256k1)", function()
    -- This will return false since sig is random, but still benchmarks the verify path
    crypto.schnorr_verify(xonly_pubkey, sig64, msg)
  end, iterations)
end

--- Run all crypto benchmarks.
-- @return table: array of benchmark results
function M.run_crypto_benchmarks()
  local results = {}

  -- Hash benchmarks
  results[#results + 1] = M.benchmark_sha256(10000)
  results[#results + 1] = M.benchmark_hash256(10000)
  results[#results + 1] = M.benchmark_ripemd160(10000)
  results[#results + 1] = M.benchmark_hash160(10000)

  -- Signature benchmarks
  results[#results + 1] = M.benchmark_ecdsa_sign(1000)
  results[#results + 1] = M.benchmark_ecdsa_verify(1000)
  results[#results + 1] = M.benchmark_schnorr_verify(1000)

  return results
end

--- Print all crypto benchmark results to stdout.
function M.print_crypto_benchmarks()
  local results = M.run_crypto_benchmarks()
  print(M.format_benchmark_results(results))
end

return M
