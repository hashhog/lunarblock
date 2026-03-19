local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local crypto = require("lunarblock.crypto")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local script = require("lunarblock.script")
local storage_mod = require("lunarblock.storage")
local perf = require("lunarblock.perf")
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
  return self
end

function ChainState:init()
  local hash, height = self.storage.get_chain_tip()
  if hash then
    self.tip_hash = hash
    self.tip_height = height
  end
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
-- @return true on success, nil and error message on failure
function ChainState:connect_block(block, height, block_hash, prev_block_mtp, get_block_mtp, skip_script_validation)
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
          else
            -- Legacy or P2SH
            local ok = script.verify_script(inp.script_sig, utxo.script_pubkey, flags, checker)
            assert(ok, "Script verification failed for input " .. inp_idx)
          end
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

  return true
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

return M
