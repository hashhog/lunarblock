local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local crypto = require("lunarblock.crypto")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local script = require("lunarblock.script")
local storage_mod = require("lunarblock.storage")
local perf = require("lunarblock.perf")
local sig_cache = require("sig_cache")
local bit = require("bit")
local M = {}

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
  local w = serialize.buffer_writer()
  w.write_i64le(entry.value)
  w.write_varstr(entry.script_pubkey)
  w.write_u32le(entry.height)
  w.write_u8(entry.is_coinbase and 1 or 0)
  return w.result()
end

function M.deserialize_utxo_entry(data)
  local r = serialize.buffer_reader(data)
  return M.utxo_entry(
    r.read_i64le(),
    r.read_varstr(),
    r.read_u32le(),
    r.read_u8() == 1
  )
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

-- Snapshot metadata structure matching Bitcoin Core's SnapshotMetadata
-- Reference: /home/max/hashhog/bitcoin/src/node/utxo_snapshot.h
--
-- Format:
--   magic_bytes[5]  = 'utxo' + 0xff
--   version[2]      = uint16 LE
--   network_magic[4] = 4-byte network identifier
--   base_blockhash[32] = hash of snapshot base block
--   coins_count[8]  = uint64 LE total number of UTXOs
--
-- Followed by UTXO data:
--   For each unique txid:
--     txid[32]         = transaction ID
--     num_outputs[var] = varint number of outputs for this txid
--     For each output:
--       vout_index[var] = varint output index
--       code[var]       = varint (height * 2 + is_coinbase)
--       value[8]        = int64 LE amount in satoshis
--       script[var]     = varstring script_pubkey

-- Snapshot magic bytes (Bitcoin Core compatible)
M.SNAPSHOT_MAGIC = "utxo\xff"
M.SNAPSHOT_VERSION = 2

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

--- Serialize a coin for snapshot format.
-- Uses compact encoding: code (height*2 + coinbase) + value + script
-- @param entry table: UTXO entry
-- @return string: serialized coin
function M.serialize_snapshot_coin(entry)
  local w = serialize.buffer_writer()
  -- Encode height and coinbase flag together: (height * 2) + coinbase_flag
  local code = entry.height * 2 + (entry.is_coinbase and 1 or 0)
  w.write_varint(code)
  w.write_i64le(entry.value)
  w.write_varstr(entry.script_pubkey)
  return w.result()
end

--- Deserialize a coin from snapshot format.
-- @param reader buffer_reader: reader positioned at coin data
-- @return table: UTXO entry
function M.deserialize_snapshot_coin(reader)
  local code = reader.read_varint()
  local height = math.floor(code / 2)
  local is_coinbase = (code % 2) == 1
  local value = reader.read_i64le()
  local script_pubkey = reader.read_varstr()
  return M.utxo_entry(value, script_pubkey, height, is_coinbase)
end

--------------------------------------------------------------------------------
-- Outpoint Key
--------------------------------------------------------------------------------

-- Generate a 36-byte key for database lookups (32-byte txid + 4-byte vout index)
function M.outpoint_key(txid_hash256, vout_index)
  local w = serialize.buffer_writer()
  w.write_hash256(txid_hash256)
  w.write_u32le(vout_index)
  return w.result()  -- 36 bytes
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

-- Default cache size: 450MB
local DEFAULT_CACHE_SIZE_MB = 450
local BYTES_PER_MB = 1024 * 1024

-- Estimated memory per cache entry (for memory tracking)
-- Key: 36 bytes (outpoint)
-- Value overhead: 8 (value) + 4 (height) + 1 (coinbase) + 1 (flags) + ~8 (table overhead)
-- Script: variable, average ~34 bytes
-- Lua table/GC overhead: ~40 bytes
-- Total estimate: ~130 bytes per entry
local BASE_ENTRY_OVERHEAD = 96
local SCRIPT_OVERHEAD = 34

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

  -- Cache the entry (not dirty, not fresh since it came from disk)
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
function CoinView:flush(reallocate)
  if self.dirty_count == 0 then return end

  local batch = self.storage.batch()
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

  -- Execute batch
  batch.write(false)
  batch.destroy()

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
-- @return true on success, nil and error message on failure
function ChainState:connect_block(block, height, block_hash, prev_block_mtp, get_block_mtp, skip_script_validation, use_parallel)
  -- Build undo data as we go - one TxUndo per non-coinbase transaction
  local block_undo = M.block_undo({})
  local total_fees = 0
  local total_sigop_cost = 0

  -- Check if BIP68 (CSV) is active at this height
  local enforce_bip68 = height >= self.network.csv_height

  -- Flags for sigop counting (depends on height)
  local sigop_flags = {
    verify_p2sh = height >= self.network.bip34_height,
    verify_witness = height >= self.network.segwit_height,
  }

  -- Determine if we should use parallel verification
  -- Auto-detect: use parallel if available and block has enough inputs
  local parallel_available = validation.parallel_verify_available()
  local use_parallel_verify = false
  if use_parallel == nil then
    -- Auto: use parallel if available and block has many inputs
    if parallel_available and not skip_script_validation then
      local total_inputs = 0
      for i = 2, #block.transactions do  -- Skip coinbase
        total_inputs = total_inputs + #block.transactions[i].inputs
      end
      use_parallel_verify = total_inputs >= 16
    end
  else
    use_parallel_verify = use_parallel and parallel_available
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

      -- Calculate sigop cost for this transaction
      local function get_prev_output(inp)
        for idx, input in ipairs(tx.inputs) do
          if input == inp then
            return utxo_cache[idx]
          end
        end
        return nil
      end
      local tx_sigop_cost = validation.get_transaction_sigop_cost(tx, get_prev_output, sigop_flags)
      total_sigop_cost = total_sigop_cost + tx_sigop_cost

      -- BIP68: Check relative lock-times (sequence locks)
      -- Only enforce if BIP68 is active and we have the required MTP information
      if enforce_bip68 and tx.version >= 2 and prev_block_mtp and get_block_mtp then
        -- Helper to get UTXO height for each input
        local function get_utxo_height(inp)
          for idx, input in ipairs(tx.inputs) do
            if input == inp then
              return utxo_cache[idx].height
            end
          end
          return nil
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

          local flags = {
            verify_p2sh = height >= self.network.bip34_height,
            verify_dersig = height >= self.network.bip66_height,
            verify_checklocktimeverify = height >= self.network.bip65_height,
            verify_checksequenceverify = height >= self.network.csv_height,
            verify_witness = height >= self.network.segwit_height,
            verify_nulldummy = height >= self.network.segwit_height,
            verify_nullfail = height >= self.network.segwit_height,
            verify_witness_pubkeytype = height >= self.network.segwit_height,
          }

          local checker = validation.make_sig_checker(
            tx, inp_idx - 1, utxo.value, utxo.script_pubkey, flags
          )

          -- Determine which scripts to run based on output type
          local script_type = script.classify_script(utxo.script_pubkey)

          if script_type == "p2wpkh" or script_type == "p2wsh" then
            -- SegWit: scriptSig must be empty, use witness stack
            assert(#inp.script_sig == 0, "SegWit input must have empty scriptSig")
            -- Execute witness program
            local witness_stack = inp.witness or {}
            if script_type == "p2wpkh" then
              -- P2WPKH: witness = {sig, pubkey}, execute synthetic P2PKH
              assert(#witness_stack == 2, "P2WPKH requires exactly 2 witness items")
              local pkh = utxo.script_pubkey:sub(3, 22)
              local synthetic_script = script.make_p2pkh_script(pkh)
              local stack = {witness_stack[1], witness_stack[2]}
              local segwit_flags = {}
              for k, v in pairs(flags) do segwit_flags[k] = v end
              segwit_flags.is_segwit = true
              segwit_flags.is_witness_v0 = true  -- Enable WITNESS_PUBKEYTYPE check
              local segwit_checker = validation.make_sig_checker(
                tx, inp_idx - 1, utxo.value, utxo.script_pubkey, segwit_flags
              )
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
              local segwit_checker = validation.make_sig_checker(
                tx, inp_idx - 1, utxo.value, utxo.script_pubkey, segwit_flags
              )
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
            local ok = script.verify_script(inp.script_sig, utxo.script_pubkey, flags, checker)
            assert(ok, "Script verification failed for input " .. inp_idx)
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

  -- If we collected signatures for parallel verification, verify them now
  if parallel_sigs and #parallel_sigs > 0 then
    local ok, err = validation.verify_signatures_parallel(parallel_sigs)
    assert(ok, "Parallel signature verification failed: " .. (err or "unknown error"))
  end

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

  -- Serialize and store undo data (only if there are non-coinbase transactions)
  if #block_undo.tx_undo > 0 then
    local undo_data = M.serialize_block_undo(block_undo)
    self.storage.put_undo(block_hash, undo_data)
  end

  -- Flush UTXO changes to database
  self.coin_view:flush()

  -- Update chain tip
  self.tip_hash = block_hash
  self.tip_height = height
  self.storage.set_chain_tip(block_hash, height, true)

  -- Invoke callback if registered (for ZMQ notifications, etc.)
  if self.callbacks.on_block_connected then
    self.callbacks.on_block_connected(block_hash, block)
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

  -- Flush UTXO changes to database
  self.coin_view:flush()

  -- Remove undo data for this block
  if undo_data_raw then
    self.storage.delete_undo(block_hash)
  end

  -- Update chain tip to the previous block
  self.tip_height = height - 1
  if prev_hash then
    self.tip_hash = prev_hash
    self.storage.set_chain_tip(prev_hash, height - 1, true)
  end

  -- Invoke callback if registered (for ZMQ notifications, etc.)
  if self.callbacks.on_block_disconnected then
    self.callbacks.on_block_disconnected(block_hash)
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

--- Compute the serialized UTXO set hash for AssumeUTXO validation.
-- This iterates all UTXOs in canonical order and computes SHA256 of the serialized set.
-- @return string: 32-byte hash
-- @return number: total UTXO count
function ChainState:compute_utxo_hash()
  -- Flush any pending changes to ensure we're reading from disk
  self.coin_view:flush()

  local count = 0
  local hasher = crypto.sha256_init()

  -- Iterate all UTXOs in key order (txid + vout)
  local iter = self.storage.iterator(storage_mod.CF.UTXO)
  iter.seek_to_first()

  while iter.valid() do
    local key = iter.key()
    local data = iter.value()

    -- Add key + serialized entry to hash
    hasher.update(key)
    hasher.update(data)

    count = count + 1
    iter.next()
  end
  iter.destroy()

  return hasher.final(), count
end

--- Dump the UTXO set to a snapshot file.
-- Format matches Bitcoin Core's dumptxoutset output.
-- @param file_path string: path to write snapshot file
-- @return table|nil, string|nil: {coins_count, hash} or nil, error message
function ChainState:dump_snapshot(file_path)
  -- Ensure coin view is flushed
  self.coin_view:flush()

  -- Open output file
  local file, err = io.open(file_path, "wb")
  if not file then
    return nil, "failed to open file: " .. (err or "unknown error")
  end

  -- First pass: count UTXOs and group by txid
  local utxos_by_txid = {}
  local total_count = 0

  local iter = self.storage.iterator(storage_mod.CF.UTXO)
  iter.seek_to_first()

  while iter.valid() do
    local key = iter.key()
    local data = iter.value()

    -- Parse outpoint from key: txid (32) + vout (4 LE)
    local txid_bytes = key:sub(1, 32)
    local r = serialize.buffer_reader(key:sub(33, 36))
    local vout = r.read_u32le()

    local entry = M.deserialize_utxo_entry(data)

    if not utxos_by_txid[txid_bytes] then
      utxos_by_txid[txid_bytes] = {}
    end
    utxos_by_txid[txid_bytes][vout] = entry
    total_count = total_count + 1

    iter.next()
  end
  iter.destroy()

  -- Write metadata
  local metadata = M.snapshot_metadata(
    self.network.magic_bytes,
    self.tip_hash,
    total_count
  )
  file:write(M.serialize_snapshot_metadata(metadata))

  -- Second pass: write UTXO data grouped by txid
  -- Iterate in sorted txid order for determinism
  local sorted_txids = {}
  for txid_bytes in pairs(utxos_by_txid) do
    sorted_txids[#sorted_txids + 1] = txid_bytes
  end
  table.sort(sorted_txids)

  for _, txid_bytes in ipairs(sorted_txids) do
    local outputs = utxos_by_txid[txid_bytes]

    -- Sort output indices
    local sorted_vouts = {}
    for vout in pairs(outputs) do
      sorted_vouts[#sorted_vouts + 1] = vout
    end
    table.sort(sorted_vouts)

    -- Write txid
    file:write(txid_bytes)

    -- Write number of outputs for this txid
    local w = serialize.buffer_writer()
    w.write_varint(#sorted_vouts)
    file:write(w.result())

    -- Write each output
    for _, vout in ipairs(sorted_vouts) do
      local entry = outputs[vout]

      local ow = serialize.buffer_writer()
      ow.write_varint(vout)  -- Output index
      file:write(ow.result())
      file:write(M.serialize_snapshot_coin(entry))
    end
  end

  file:close()

  -- Compute hash for verification
  local hash, _ = self:compute_utxo_hash()

  return {
    coins_count = total_count,
    hash = hash,
    base_blockhash = self.tip_hash,
    base_height = self.tip_height,
  }
end

--- Load a UTXO snapshot file into this chainstate.
-- Validates the snapshot hash against assumeutxo configuration.
-- @param file_path string: path to snapshot file
-- @param expected_hash string|nil: expected hash (from assumeutxo config), or nil to skip validation
-- @return boolean, string|nil: success flag, error message
function ChainState:load_snapshot(file_path, expected_hash)
  -- Open snapshot file
  local file, err = io.open(file_path, "rb")
  if not file then
    return false, "failed to open snapshot: " .. (err or "unknown error")
  end

  -- Read metadata
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

  -- Validate network magic
  if metadata.network_magic ~= self.network.magic_bytes then
    file:close()
    return false, "snapshot network magic mismatch"
  end

  -- Clear existing UTXO set
  self.coin_view:clear_cache()
  -- Note: For a full implementation, we'd also clear the UTXO column family in storage

  local coins_loaded = 0
  local coins_total = metadata.coins_count

  -- Read UTXO data
  while coins_loaded < coins_total do
    -- Read txid
    local txid_bytes = file:read(32)
    if not txid_bytes or #txid_bytes < 32 then
      file:close()
      return false, string.format("unexpected end of snapshot at coin %d", coins_loaded)
    end
    local txid = types.hash256(txid_bytes)

    -- Read number of outputs for this txid
    local count_byte = file:read(1)
    if not count_byte then
      file:close()
      return false, "unexpected end reading output count"
    end

    -- Handle varint reading from file
    local num_outputs
    local first = count_byte:byte(1)
    if first < 0xFD then
      num_outputs = first
    elseif first == 0xFD then
      local extra = file:read(2)
      if not extra or #extra < 2 then
        file:close()
        return false, "truncated varint"
      end
      local r = serialize.buffer_reader(extra)
      num_outputs = r.read_u16le()
    elseif first == 0xFE then
      local extra = file:read(4)
      if not extra or #extra < 4 then
        file:close()
        return false, "truncated varint"
      end
      local r = serialize.buffer_reader(extra)
      num_outputs = r.read_u32le()
    else
      local extra = file:read(8)
      if not extra or #extra < 8 then
        file:close()
        return false, "truncated varint"
      end
      local r = serialize.buffer_reader(extra)
      num_outputs = r.read_u64le()
    end

    -- Read each output
    for _ = 1, num_outputs do
      -- Read vout index (varint)
      local vout_byte = file:read(1)
      if not vout_byte then
        file:close()
        return false, "unexpected end reading vout"
      end

      local vout
      local vout_first = vout_byte:byte(1)
      if vout_first < 0xFD then
        vout = vout_first
      elseif vout_first == 0xFD then
        local extra = file:read(2)
        if not extra then file:close(); return false, "truncated" end
        local r = serialize.buffer_reader(extra)
        vout = r.read_u16le()
      elseif vout_first == 0xFE then
        local extra = file:read(4)
        if not extra then file:close(); return false, "truncated" end
        local r = serialize.buffer_reader(extra)
        vout = r.read_u32le()
      else
        local extra = file:read(8)
        if not extra then file:close(); return false, "truncated" end
        local r = serialize.buffer_reader(extra)
        vout = r.read_u64le()
      end

      -- Read code (height*2 + coinbase flag) as varint
      local code_byte = file:read(1)
      if not code_byte then
        file:close()
        return false, "unexpected end reading code"
      end

      local code
      local code_first = code_byte:byte(1)
      if code_first < 0xFD then
        code = code_first
      elseif code_first == 0xFD then
        local extra = file:read(2)
        if not extra then file:close(); return false, "truncated" end
        local r = serialize.buffer_reader(extra)
        code = r.read_u16le()
      elseif code_first == 0xFE then
        local extra = file:read(4)
        if not extra then file:close(); return false, "truncated" end
        local r = serialize.buffer_reader(extra)
        code = r.read_u32le()
      else
        local extra = file:read(8)
        if not extra then file:close(); return false, "truncated" end
        local r = serialize.buffer_reader(extra)
        code = r.read_u64le()
      end

      local height = math.floor(code / 2)
      local is_coinbase = (code % 2) == 1

      -- Read value (8 bytes i64 LE)
      local value_bytes = file:read(8)
      if not value_bytes or #value_bytes < 8 then
        file:close()
        return false, "unexpected end reading value"
      end
      local vr = serialize.buffer_reader(value_bytes)
      local value = vr.read_i64le()

      -- Read script (varstring)
      local script_len_byte = file:read(1)
      if not script_len_byte then
        file:close()
        return false, "unexpected end reading script length"
      end

      local script_len
      local sl_first = script_len_byte:byte(1)
      if sl_first < 0xFD then
        script_len = sl_first
      elseif sl_first == 0xFD then
        local extra = file:read(2)
        if not extra then file:close(); return false, "truncated" end
        local r = serialize.buffer_reader(extra)
        script_len = r.read_u16le()
      elseif sl_first == 0xFE then
        local extra = file:read(4)
        if not extra then file:close(); return false, "truncated" end
        local r = serialize.buffer_reader(extra)
        script_len = r.read_u32le()
      else
        local extra = file:read(8)
        if not extra then file:close(); return false, "truncated" end
        local r = serialize.buffer_reader(extra)
        script_len = r.read_u64le()
      end

      local script_pubkey = ""
      if script_len > 0 then
        script_pubkey = file:read(script_len)
        if not script_pubkey or #script_pubkey < script_len then
          file:close()
          return false, "unexpected end reading script"
        end
      end

      -- Add to UTXO set
      local entry = M.utxo_entry(value, script_pubkey, height, is_coinbase)
      self.coin_view:add(txid, vout, entry)

      coins_loaded = coins_loaded + 1

      -- Periodic flush to avoid memory pressure
      if coins_loaded % 100000 == 0 then
        self.coin_view:flush()
      end
    end
  end

  file:close()

  -- Final flush
  self.coin_view:flush()

  -- Validate hash if expected hash is provided
  if expected_hash then
    local computed_hash, _ = self:compute_utxo_hash()
    if computed_hash ~= expected_hash then
      return false, "snapshot hash mismatch"
    end
  end

  -- Update chain tip to snapshot base
  self.tip_hash = metadata.base_blockhash
  -- Note: We need to look up the height from storage or header chain
  -- For now, this will be set by the caller

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
