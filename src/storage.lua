local ffi = require("ffi")
local fault = require("lunarblock.fault")
local serialize = require("lunarblock.serialize")
local types = require("lunarblock.types")
local M = {}

-- RocksDB C API FFI declarations
ffi.cdef[[
  /* Opaque types */
  typedef struct rocksdb_t rocksdb_t;
  typedef struct rocksdb_options_t rocksdb_options_t;
  typedef struct rocksdb_readoptions_t rocksdb_readoptions_t;
  typedef struct rocksdb_writeoptions_t rocksdb_writeoptions_t;
  typedef struct rocksdb_writebatch_t rocksdb_writebatch_t;
  typedef struct rocksdb_iterator_t rocksdb_iterator_t;
  typedef struct rocksdb_column_family_handle_t rocksdb_column_family_handle_t;
  typedef struct rocksdb_block_based_table_options_t rocksdb_block_based_table_options_t;
  typedef struct rocksdb_cache_t rocksdb_cache_t;

  /* Options */
  rocksdb_options_t* rocksdb_options_create(void);
  void rocksdb_options_destroy(rocksdb_options_t* options);
  void rocksdb_options_set_create_if_missing(rocksdb_options_t* options, unsigned char v);
  void rocksdb_options_set_max_open_files(rocksdb_options_t* options, int n);
  void rocksdb_options_set_write_buffer_size(rocksdb_options_t* options, size_t s);
  void rocksdb_options_set_max_write_buffer_number(rocksdb_options_t* options, int n);
  void rocksdb_options_set_compression(rocksdb_options_t* options, int t);
  /* Leveled-compaction tuning (used to relieve the AssumeUTXO snapshot-import
   * write-amp stall — see M.open). */
  void rocksdb_options_set_max_bytes_for_level_base(rocksdb_options_t* options, uint64_t n);
  void rocksdb_options_set_level0_slowdown_writes_trigger(rocksdb_options_t* options, int n);
  void rocksdb_options_set_level0_stop_writes_trigger(rocksdb_options_t* options, int n);
  void rocksdb_options_set_max_background_jobs(rocksdb_options_t* options, int n);
  void rocksdb_options_set_block_based_table_factory(
    rocksdb_options_t* options,
    rocksdb_block_based_table_options_t* table_options
  );
  void rocksdb_options_set_create_missing_column_families(
    rocksdb_options_t* options, unsigned char v
  );

  /* Block-based table options */
  rocksdb_block_based_table_options_t* rocksdb_block_based_options_create(void);
  void rocksdb_block_based_options_destroy(rocksdb_block_based_table_options_t* options);
  void rocksdb_block_based_options_set_block_cache(
    rocksdb_block_based_table_options_t* options,
    rocksdb_cache_t* block_cache
  );
  void rocksdb_block_based_options_set_block_size(
    rocksdb_block_based_table_options_t* options,
    size_t block_size
  );

  /* Cache */
  rocksdb_cache_t* rocksdb_cache_create_lru(size_t capacity);
  void rocksdb_cache_destroy(rocksdb_cache_t* cache);

  /* Database operations */
  rocksdb_t* rocksdb_open(
    const rocksdb_options_t* options,
    const char* name,
    char** errptr
  );
  rocksdb_t* rocksdb_open_column_families(
    const rocksdb_options_t* options,
    const char* name,
    int num_column_families,
    const char* const* column_family_names,
    const rocksdb_options_t* const* column_family_options,
    rocksdb_column_family_handle_t** column_family_handles,
    char** errptr
  );
  void rocksdb_close(rocksdb_t* db);

  /* Column families */
  rocksdb_column_family_handle_t* rocksdb_create_column_family(
    rocksdb_t* db,
    const rocksdb_options_t* column_family_options,
    const char* column_family_name,
    char** errptr
  );
  void rocksdb_column_family_handle_destroy(rocksdb_column_family_handle_t* handle);
  char** rocksdb_list_column_families(
    const rocksdb_options_t* options,
    const char* name,
    size_t* lencf,
    char** errptr
  );
  void rocksdb_list_column_families_destroy(char** list, size_t len);

  /* Read/Write options */
  rocksdb_readoptions_t* rocksdb_readoptions_create(void);
  void rocksdb_readoptions_destroy(rocksdb_readoptions_t* options);
  rocksdb_writeoptions_t* rocksdb_writeoptions_create(void);
  void rocksdb_writeoptions_destroy(rocksdb_writeoptions_t* options);
  void rocksdb_writeoptions_set_sync(rocksdb_writeoptions_t* options, unsigned char v);

  /* Get/Put/Delete with column families */
  char* rocksdb_get_cf(
    rocksdb_t* db,
    const rocksdb_readoptions_t* options,
    rocksdb_column_family_handle_t* column_family,
    const char* key, size_t keylen,
    size_t* vallen,
    char** errptr
  );
  void rocksdb_put_cf(
    rocksdb_t* db,
    const rocksdb_writeoptions_t* options,
    rocksdb_column_family_handle_t* column_family,
    const char* key, size_t keylen,
    const char* val, size_t vallen,
    char** errptr
  );
  void rocksdb_delete_cf(
    rocksdb_t* db,
    const rocksdb_writeoptions_t* options,
    rocksdb_column_family_handle_t* column_family,
    const char* key, size_t keylen,
    char** errptr
  );

  /* Write batch */
  rocksdb_writebatch_t* rocksdb_writebatch_create(void);
  void rocksdb_writebatch_destroy(rocksdb_writebatch_t* batch);
  void rocksdb_writebatch_clear(rocksdb_writebatch_t* batch);
  void rocksdb_writebatch_put_cf(
    rocksdb_writebatch_t* batch,
    rocksdb_column_family_handle_t* column_family,
    const char* key, size_t keylen,
    const char* val, size_t vallen
  );
  void rocksdb_writebatch_delete_cf(
    rocksdb_writebatch_t* batch,
    rocksdb_column_family_handle_t* column_family,
    const char* key, size_t keylen
  );
  void rocksdb_write(
    rocksdb_t* db,
    const rocksdb_writeoptions_t* options,
    rocksdb_writebatch_t* batch,
    char** errptr
  );

  /* Iterator */
  rocksdb_iterator_t* rocksdb_create_iterator_cf(
    rocksdb_t* db,
    const rocksdb_readoptions_t* options,
    rocksdb_column_family_handle_t* column_family
  );
  void rocksdb_iter_destroy(rocksdb_iterator_t* iter);
  void rocksdb_iter_seek(rocksdb_iterator_t* iter, const char* key, size_t keylen);
  void rocksdb_iter_seek_to_first(rocksdb_iterator_t* iter);
  void rocksdb_iter_seek_to_last(rocksdb_iterator_t* iter);
  void rocksdb_iter_next(rocksdb_iterator_t* iter);
  void rocksdb_iter_prev(rocksdb_iterator_t* iter);
  unsigned char rocksdb_iter_valid(const rocksdb_iterator_t* iter);
  const char* rocksdb_iter_key(const rocksdb_iterator_t* iter, size_t* klen);
  const char* rocksdb_iter_value(const rocksdb_iterator_t* iter, size_t* vlen);

  /* Memory */
  void rocksdb_free(void* ptr);

  /* Write-path durability model (see M.open "Durability model") */
  typedef struct rocksdb_flushoptions_t rocksdb_flushoptions_t;
  rocksdb_flushoptions_t* rocksdb_flushoptions_create(void);
  void rocksdb_flushoptions_destroy(rocksdb_flushoptions_t* options);
  void rocksdb_flushoptions_set_wait(rocksdb_flushoptions_t* options, unsigned char v);
  void rocksdb_flush_cfs(rocksdb_t* db, const rocksdb_flushoptions_t* options,
                         rocksdb_column_family_handle_t** column_family,
                         int num_column_families, char** errptr);
  void rocksdb_flush_wal(rocksdb_t* db, unsigned char sync, char** errptr);
  void rocksdb_writeoptions_disable_WAL(rocksdb_writeoptions_t* opt, int disable);
  void rocksdb_options_set_atomic_flush(rocksdb_options_t* opt, unsigned char v);
  void rocksdb_options_set_bytes_per_sync(rocksdb_options_t* opt, uint64_t v);
  char* rocksdb_property_value(rocksdb_t* db, const char* propname);

  /* Integrated BlobDB (block bodies, see blocks_cf_options) */
  void rocksdb_options_set_enable_blob_files(rocksdb_options_t* opt, unsigned char val);
  void rocksdb_options_set_min_blob_size(rocksdb_options_t* opt, uint64_t val);
  void rocksdb_options_set_blob_file_size(rocksdb_options_t* opt, uint64_t val);
  void rocksdb_options_set_blob_compression_type(rocksdb_options_t* opt, int val);
  void rocksdb_options_set_enable_blob_gc(rocksdb_options_t* opt, unsigned char val);

  /* Bloom filter policy (block-based tables) */
  typedef struct rocksdb_filterpolicy_t rocksdb_filterpolicy_t;
  rocksdb_filterpolicy_t* rocksdb_filterpolicy_create_bloom_full(double bits_per_key);
  void rocksdb_block_based_options_set_filter_policy(
    rocksdb_block_based_table_options_t* options,
    rocksdb_filterpolicy_t* policy
  );

  /* csrc/coin_prefetch.c (lib/coin_prefetch.so) */
  int coin_prefetch_get(rocksdb_t* db, const rocksdb_readoptions_t* ro,
                        rocksdb_column_family_handle_t* cf,
                        const char* keys, size_t keylen, int n,
                        char** vals, size_t* lens, int nthreads);
]]

local librocksdb = ffi.load("rocksdb")

-- Optional parallel point-read helper (csrc/coin_prefetch.c).  Built by
-- `make build`; when absent, dbobj.parallel_get returns nil and callers keep
-- their serial reads (identical results, just slower).
local prefetch_lib = nil
do
  local paths = {
    "./lib/coin_prefetch.so",
    "lunarblock/coin_prefetch",
    "./lunarblock/coin_prefetch.so",
    "./coin_prefetch.so",
    "coin_prefetch",
  }
  for _, path in ipairs(paths) do
    local ok, lib = pcall(ffi.load, path)
    if ok then
      local ok_sym = pcall(function() return lib.coin_prefetch_get end)
      if ok_sym then prefetch_lib = lib; break end
    end
  end
end
M.parallel_get_available = prefetch_lib ~= nil
local SIZE_MAX_CDATA = ffi.cast("size_t", -1)

-- Column family names
M.CF = {
  DEFAULT = "default",
  HEADERS = "headers",       -- block_hash -> serialized header (80 bytes)
  BLOCKS = "blocks",         -- block_hash -> serialized full block
  UTXO = "utxo",             -- outpoint (txid 32 bytes + vout 4 bytes LE) -> utxo entry
  TX_INDEX = "tx_index",     -- txid -> {file_num, block_pos, tx_offset}
  HEIGHT_INDEX = "height",   -- height (4 bytes big-endian) -> block_hash
  META = "meta",             -- string key -> arbitrary value
  UNDO = "undo",             -- block_hash -> serialized undo data (spent UTXOs)
  BLOCK_FILTER = "block_filter",         -- block_hash -> {filter_hash, filter_header, filter_pos}
  BLOCK_FILTER_HEIGHT = "filter_height", -- height (4B BE) -> block_hash (for filter lookups by height)
  -- coinstatsindex: per-height un-finalized MuHash3072 accumulator +
  -- cumulative UTXO-set statistics (txouts/total_amount/bogosize).
  -- Height key: 4-byte big-endian (same encoding as HEIGHT_INDEX).
  -- Only written when coinstatsindex_enabled; fully inert otherwise.
  COIN_STATS = "coin_stats",
  -- txospenderindex (default-off, mirrors bitcoin-core's TxoSpenderIndex):
  -- maps a SPENT outpoint -> the on-chain tx that spent it.
  --   key   = spent outpoint: txid(32) || vout(4 LE)  (36 bytes, same layout
  --           as the CF.UTXO key)
  --   value = spending_txid(32) || block_hash(32) || u32 LE tx_len || tx_bytes
  -- Written inline in connect_block's atomic batch when txospenderindex_enabled
  -- and re-derived + deleted in disconnect_block (reorg / invalidateblock).
  -- Fully inert otherwise.  See utxo.lua + rpc.lua gettxspendingprevout.
  TXO_SPENDER = "txo_spender",
}

-- List of all column families in order
local CF_LIST = {
  M.CF.DEFAULT,
  M.CF.HEADERS,
  M.CF.BLOCKS,
  M.CF.UTXO,
  M.CF.TX_INDEX,
  M.CF.HEIGHT_INDEX,
  M.CF.META,
  M.CF.UNDO,
  M.CF.BLOCK_FILTER,
  M.CF.BLOCK_FILTER_HEIGHT,
  M.CF.COIN_STATS,
  M.CF.TXO_SPENDER,
}

-- Helper: check error and throw if set.
-- Every RocksDB error (ENOSPC, EIO, EMFILE, corruption, a background error
-- left by a failed flush) is a SYSTEM fault: it is raised with fault.TAG so
-- no classifier on the way up can read it as a verdict on a block or a tx
-- (Core: dbwrapper HandleError throws; CCoinsViewErrorCatcher aborts).
local function raise_db_error(msg)
  fault.raise("RocksDB error: " .. msg)
end

local function check_error(errptr)
  if errptr[0] ~= nil then
    local msg = ffi.string(errptr[0])
    librocksdb.rocksdb_free(errptr[0])
    -- Reset the slot.  RocksDB's C API (SaveError) free()s a non-NULL
    -- *errptr before storing the next error, so leaving the freed pointer
    -- here turned the SECOND RocksDB error of the process into
    -- "free(): double free detected" -> SIGABRT (seen on the first retry of
    -- a disk-full write).
    errptr[0] = nil
    raise_db_error(msg)
  end
end

-- Helper: encode height as 4-byte big-endian for correct ordering
local function encode_height(height)
  return string.char(
    math.floor(height / 16777216) % 256,
    math.floor(height / 65536) % 256,
    math.floor(height / 256) % 256,
    height % 256
  )
end

--------------------------------------------------------------------------------
-- High-level helpers shared by the RocksDB-backed store (M.open) and the
-- in-memory store (M.new_memory_storage).
--
-- These build chain-tip / chaintx-count / header / block / height-index / undo
-- accessors purely in terms of the low-level dbobj.get/put/delete primitives, so
-- the SAME serialization + key layout is used regardless of whether the bytes
-- live in RocksDB SSTs or a Lua table.  Factored out of M.open so the AssumeUTXO
-- background chainstate (utxo.lua BackgroundValidator) can be given a genuinely
-- separate coins DB without a second RocksDB instance on disk — mirroring Core's
-- InitCoinsDB(..., in_memory=true) for an in-memory chainstate
-- (bitcoin-core/src/validation.cpp:5670-5674).
--------------------------------------------------------------------------------
local CHAINTX_PREFIX = "chaintx:"

local function attach_high_level_helpers(dbobj)
  -- High-level helpers: chain tip
  function dbobj.get_chain_tip()
    local data = dbobj.get(M.CF.META, "chain_tip")
    if not data or #data < 36 then
      return nil, nil
    end
    local hash = types.hash256(data:sub(1, 32))
    local r = serialize.buffer_reader(data:sub(33, 36))
    local height = r.read_u32le()
    return hash, height
  end

  function dbobj.set_chain_tip(hash, height, sync)
    local w = serialize.buffer_writer()
    w.write_hash256(hash)
    w.write_u32le(height)
    dbobj.put(M.CF.META, "chain_tip", w.result(), sync)
  end

  -- High-level helpers: cumulative transaction count by height
  -- (Bitcoin Core's CBlockIndex::m_chain_tx_count analogue).
  local function chaintx_key(height)
    return CHAINTX_PREFIX .. encode_height(height)
  end

  function dbobj.get_chaintx_at_height(height)
    if type(height) ~= "number" or height < 0 then return nil end
    local data = dbobj.get(M.CF.META, chaintx_key(height))
    if not data or #data ~= 8 then return nil end
    local n = 0
    for i = 8, 1, -1 do
      n = n * 256 + data:byte(i)
    end
    return n
  end

  -- Encode an 8-byte little-endian count from a Lua number.
  local function encode_count8(n)
    local b = {}
    local v = n
    for i = 1, 8 do
      b[i] = string.char(v % 256)
      v = math.floor(v / 256)
    end
    return table.concat(b)
  end

  -- Direct (non-batched) write — used by genesis seeding paths.
  function dbobj.put_chaintx_at_height(height, count, sync)
    dbobj.put(M.CF.META, chaintx_key(height), encode_count8(count), sync)
  end

  -- Expose the key + encoder so connect_block can fold the cumulative-count
  -- write into its existing atomic WriteBatch (chain_tip is the last op).
  dbobj.chaintx_meta_key = chaintx_key
  dbobj.encode_chaintx_count = encode_count8

  -- High-level helpers: block headers
  function dbobj.get_header(block_hash)
    local data = dbobj.get(M.CF.HEADERS, block_hash.bytes)
    if not data then return nil end
    return serialize.deserialize_block_header(data)
  end

  function dbobj.put_header(block_hash, header)
    local data = serialize.serialize_block_header(header)
    dbobj.put(M.CF.HEADERS, block_hash.bytes, data)
  end

  -- High-level helpers: full blocks
  function dbobj.get_block(block_hash)
    local data = dbobj.get(M.CF.BLOCKS, block_hash.bytes)
    if not data then return nil end
    return serialize.deserialize_block(data)
  end

  function dbobj.put_block(block_hash, blk)
    local data = serialize.serialize_block(blk)
    dbobj.put(M.CF.BLOCKS, block_hash.bytes, data)
  end

  -- High-level helpers: height index
  function dbobj.get_hash_by_height(height)
    local key = encode_height(height)
    local data = dbobj.get(M.CF.HEIGHT_INDEX, key)
    if not data or #data ~= 32 then return nil end
    return types.hash256(data)
  end

  function dbobj.put_height_index(height, block_hash)
    local key = encode_height(height)
    dbobj.put(M.CF.HEIGHT_INDEX, key, block_hash.bytes)
  end

  -- High-level helpers: undo data
  function dbobj.get_undo(block_hash)
    return dbobj.get(M.CF.UNDO, block_hash.bytes)
  end

  function dbobj.put_undo(block_hash, undo_data, sync)
    dbobj.put(M.CF.UNDO, block_hash.bytes, undo_data, sync)
  end

  function dbobj.delete_undo(block_hash, sync)
    dbobj.delete(M.CF.UNDO, block_hash.bytes, sync)
  end

  return dbobj
end

--------------------------------------------------------------------------------
-- Periodic durability point shared by the P2P connect loop and submitblock.
--
-- checkpoint() itself is the flush. This decides WHEN, so a miner-style
-- node (blocks only via submitblock, never the P2P connect loop) bounds
-- SIGKILL loss the same way IBD does: checkpoint_interval blocks or
-- checkpoint_max_seconds, whichever comes first. A non-blocking checkpoint
-- that finds a flush already running returns false and leaves the window
-- armed for the next block. nil means "not due" (no flush was attempted).
-- First call arms the timer without counting as a time trigger, matching
-- the old sync.lua latch.
--------------------------------------------------------------------------------
local function attach_periodic_checkpoint(dbobj, wal_enabled)
  if wal_enabled then
    dbobj.checkpoint_interval = 200
    dbobj.checkpoint_max_seconds = 60
  else
    dbobj.checkpoint_interval = 1000
    dbobj.checkpoint_max_seconds = 300
  end
  dbobj.checkpoint_last_height = 0
  dbobj.checkpoint_last_time = 0
  function dbobj.maybe_periodic_checkpoint(height, now)
    now = now or os.time()
    height = height or 0
    if (dbobj.checkpoint_last_time or 0) == 0 then
      dbobj.checkpoint_last_time = now
    end
    local interval = dbobj.checkpoint_interval or 1000
    if interval < 1 then interval = 1 end
    local max_s = dbobj.checkpoint_max_seconds or 300
    local block_trigger = height - (dbobj.checkpoint_last_height or 0) >= interval
    local time_trigger = (now - dbobj.checkpoint_last_time) >= max_s
    if not block_trigger and not time_trigger then
      return nil
    end
    -- false: a flush is already running; caller keeps the trigger armed.
    local done = dbobj.checkpoint(false) ~= false
    if done then
      dbobj.checkpoint_last_height = height
      dbobj.checkpoint_last_time = now
    end
    return done
  end
end

--------------------------------------------------------------------------------
-- In-memory storage backend.
--
-- Implements the exact same dbobj interface as M.open (get/put/delete/batch/
-- iterator + the high-level helpers above), but stores values in a per-CF Lua
-- table instead of RocksDB.  Iteration returns keys in bytewise-ascending order
-- to match RocksDB's leveldb-comparator semantics, which compute_utxo_hash and
-- dump_snapshot rely on (utxo.lua:5041, 5197).
--
-- This is the lunarblock analog of a Core in-memory CCoinsViewDB.  Its only
-- production use today is the AssumeUTXO BACKGROUND chainstate, which needs its
-- OWN coins DB that is a genuinely separate object from the active (snapshot)
-- chainstate's UTXO store — see utxo.lua activate_snapshot_with_background /
-- BackgroundValidator and bitcoin-core/src/validation.cpp:6170 AddChainstate
-- (which demotes the genesis-validated chainstate to a background chainstate
-- keeping its own m_coins_views).
--------------------------------------------------------------------------------
function M.new_memory_storage()
  -- One sorted-on-iteration map per column family.
  local cfs = {}
  for _, cf_name in ipairs(CF_LIST) do
    cfs[cf_name] = {}
  end

  local function cf_table(cf)
    local t = cfs[cf]
    if not t then
      error("Unknown column family: " .. tostring(cf))
    end
    return t
  end

  local dbobj = {
    _memory = true,
    _cfs = cfs,
    -- Surfaced by getchainstates as coins_db_cache_bytes; an in-memory store
    -- has no RocksDB LRU block cache, so report 0 (Core reports the configured
    -- cache for the chainstate; an in-memory bg chainstate's is negligible).
    _block_cache_bytes = 0,
    CF = M.CF,
  }

  function dbobj.get(cf, key)
    return cf_table(cf)[key]
  end

  function dbobj.put(cf, key, value, _sync)
    cf_table(cf)[key] = value
  end

  function dbobj.delete(cf, key, _sync)
    cf_table(cf)[key] = nil
  end

  function dbobj.batch()
    -- Buffer ops and apply atomically on write() (RocksDB WriteBatch parity).
    local ops = {}
    local batch = {}

    function batch.put(cf, key, value)
      cf_table(cf)  -- validate CF eagerly, like the RocksDB batch
      ops[#ops + 1] = { kind = "put", cf = cf, key = key, value = value }
    end

    function batch.delete(cf, key)
      cf_table(cf)
      ops[#ops + 1] = { kind = "del", cf = cf, key = key }
    end

    function batch.write(_sync)
      for _, op in ipairs(ops) do
        if op.kind == "put" then
          cfs[op.cf][op.key] = op.value
        else
          cfs[op.cf][op.key] = nil
        end
      end
    end

    function batch.clear()
      ops = {}
    end

    function batch.destroy()
      ops = nil
    end

    return batch
  end

  function dbobj.iterator(cf)
    local t = cf_table(cf)
    -- Snapshot the keys in bytewise order at construction (RocksDB iterators
    -- are point-in-time snapshots; the bg validator never mutates a CF while
    -- iterating it, so a one-shot sorted key list is faithful and simple).
    local keys = {}
    for k in pairs(t) do keys[#keys + 1] = k end
    table.sort(keys)  -- Lua string '<' is bytewise/lexicographic == leveldb cmp
    local pos = 0
    local iter = {}

    function iter.seek_to_first() pos = 1 end
    function iter.seek_to_last() pos = #keys end

    function iter.seek(key)
      -- First key >= `key` (RocksDB Seek semantics).
      pos = #keys + 1
      for i = 1, #keys do
        if keys[i] >= key then pos = i; break end
      end
    end

    function iter.valid() return pos >= 1 and pos <= #keys end
    function iter.next() pos = pos + 1 end
    function iter.prev() pos = pos - 1 end

    function iter.key()
      if pos < 1 or pos > #keys then return nil end
      return keys[pos]
    end

    function iter.value()
      local k = iter.key()
      if k == nil then return nil end
      return t[k]
    end

    function iter.destroy() keys = nil end

    return iter
  end

  -- Durability hooks (see M.open): nothing to persist for a memory store.
  dbobj.wal_enabled = false
  dbobj.stats = { checkpoints = 0, durable_flushes = 0 }
  function dbobj.checkpoint(_wait)
    dbobj.stats.checkpoints = dbobj.stats.checkpoints + 1
  end
  attach_periodic_checkpoint(dbobj, false)

  function dbobj.close()
    dbobj._cfs = nil
    for k in pairs(cfs) do cfs[k] = nil end
  end

  return attach_high_level_helpers(dbobj)
end

-- Open a RocksDB database
--------------------------------------------------------------------------------
-- Durability model (write path).
--
-- DEFAULT ("memtable-checkpoint", Core-style):
--   * Every write goes to the memtables only -- the RocksDB WAL is disabled
--     (WriteOptions.disableWAL).  connect_block's per-block atomic WriteBatch
--     (UTXO delta + undo + block body + index entries + chain_tip LAST) is
--     applied to memory; nothing is written to a file and nothing is fsync'd
--     on the block-connect path.
--   * atomic_flush=true: whenever RocksDB flushes (a memtable filled, an
--     explicit checkpoint, shutdown), ALL column families are flushed together
--     at one sequence number and installed with a single MANIFEST record.  A
--     memtable switch only happens between write groups, so every durable
--     state is exactly the state after some complete WriteBatch -- chain_tip,
--     the UTXO set, undo data and block bodies always agree.  This is the
--     same property the old WAL + kPointInTimeRecovery path provided after a
--     power loss, and the same model Bitcoin Core uses for its coins cache:
--     mutations accumulate in memory and are committed in large atomic
--     batches (FlushStateToDisk), not per block.
--   * A crash (SIGKILL, OOM, power loss) rolls the chainstate back to the last
--     flush; the node re-downloads and reconnects from there.  Bounded by the
--     memtable size (~256 MB of writes) and by maybe_periodic_checkpoint()
--     (time/block triggered), called from the P2P connect loop AND from
--     submitblock — a miner-style node has no P2P connect loop.
--   * Callers that ask for durability (put/delete/batch.write with sync=true:
--     reorg commit, snapshot activation, header-tip anchors) get a blocking
--     atomic flush after the write, so "returned => durable" still holds.
--   * dbobj.close() flushes (waits) before closing.
--
-- LEGACY (LUNARBLOCK_DB_WAL=1): the previous behaviour -- every write appended
-- to the WAL, sync=true => WAL fdatasync.  Kept as an operator escape hatch
-- and as the A/B control; same on-disk format, switchable between restarts
-- in either direction (a WAL left by legacy mode is replayed on open).
--
-- Why: MEASURED on the 725000 range slice (main thread sampled from /proc,
-- 2026-09-27): ~35% of the connect loop's wall time was the main thread
-- blocked in the kernel on WAL write() (ext4 journal waits) and WAL/dir
-- fdatasync (jbd2 commit waits), because on this box's ext4 every append that
-- touches inode metadata and every fsync waits for a journal commit that is
-- itself stuck behind the whole machine's dirty data.  Removing the WAL takes
-- those syscalls off the block-connect path entirely and also stops writing
-- every byte twice (WAL + SST).
--------------------------------------------------------------------------------
M.wal_enabled_default = (os.getenv("LUNARBLOCK_DB_WAL") == "1")

-- open_opts (optional table):
--   prune = bool  -- enable blob GC on the blocks CF so pruned bodies are
--                    reclaimed (off otherwise: no rewrite of live bodies).
--   wal   = bool  -- override the durability model (default: env / no WAL).
function M.open(path, cache_size_mb, open_opts)
  cache_size_mb = cache_size_mb or 2048
  open_opts = open_opts or {}
  local wal_enabled = M.wal_enabled_default
  if open_opts.wal ~= nil then wal_enabled = open_opts.wal and true or false end
  local errptr = ffi.new("char*[1]")

  -- Every CF gets the same engine options; the blocks CF additionally stores
  -- its values in blob files (see blocks_options below).  Built by a
  -- function so the blocks CF can get its own options object.
  local function new_base_options()
    local options = librocksdb.rocksdb_options_create()
    librocksdb.rocksdb_options_set_create_if_missing(options, 1)
    librocksdb.rocksdb_options_set_create_missing_column_families(options, 1)
    librocksdb.rocksdb_options_set_max_open_files(options, 1000)
    librocksdb.rocksdb_options_set_write_buffer_size(options, 256 * 1024 * 1024)  -- 256MB
    librocksdb.rocksdb_options_set_max_write_buffer_number(options, 4)
    -- Snappy compression (RocksDB type 1).
    --
    -- The old comment "(LZ4 not linked)" was stale: the librocksdb.so on this
    -- platform links snappy, lz4, zlib AND zstd (verified via `ldd librocksdb.so`
    -- + `nm -D`).  Running uncompressed was the dominant cause of the AssumeUTXO
    -- snapshot-import throughput collapse: the chainstate grew to ~45GB (≈4× Core's
    -- ~11GB LevelDB chainstate for the same ~190M-coin set) and the resulting
    -- write-amplification overwhelmed RocksDB's leveled compaction, eventually
    -- backing L0 up to the stop-writes trigger so `rocksdb_write` stalled and the
    -- loader rate collapsed to ~0 around the 45GB mark.
    --
    -- A bounded repro on UTXO-shaped data measured ~5.8× smaller SSTs with Snappy
    -- (58.0 → 10.0 bytes/coin post-compaction; zstd reaches 6.9 but costs more
    -- CPU).  On-disk SST size is a direct proxy for bytes-rewritten-per-compaction,
    -- so this cuts compaction write volume by the same factor and relieves the
    -- stall.  Compression is per-SST (codec recorded in the SST footer), so this
    -- is backward-compatible: existing uncompressed SSTs stay readable; only new
    -- writes/compactions use Snappy.  No consensus surface — the serialized bytes
    -- handed to RocksDB are byte-identical; compression is fully transparent below
    -- the get/put boundary.
    --
    -- Snappy chosen over lz4/zstd for the lowest CPU overhead (GB/s) so it cannot
    -- reintroduce a CPU ceiling on the per-coin import loop that commit 72af3ce
    -- just removed.
    librocksdb.rocksdb_options_set_compression(options, 1)  -- 1 = Snappy

    -- Leveled-compaction tuning for the bulk AssumeUTXO snapshot import.
    --
    -- Snappy (above) cut SST size ~4-6x, but the default LSM shape still drives
    -- avoidable write-amplification during a ~190M-coin bulk load:
    --
    --  * max_bytes_for_level_base defaults to 256MB == write_buffer_size, so L1's
    --    size target equals a SINGLE memtable. With L0 holding 256MB-worth of
    --    files before compaction, that forces near-constant L0->L1 churn and a
    --    deep level cascade. Raising the L1 target to 1GB lets each level hold
    --    more before cascading, so a given coin is rewritten through fewer
    --    levels (lower write-amp). (default multiplier 10 keeps the per-level
    --    growth, so total levels for the final ~10-15GB set stay small.)
    --
    --  * level0_slowdown/stop default to 20/36 in modern RocksDB, but were the
    --    historical 8/12 — we pin the higher values explicitly so a transient
    --    compaction backlog during the import does NOT trip the stop-writes
    --    trigger and stall rocksdb_write (the original ~45GB rate-collapse
    --    symptom). 20/36 is RocksDB's own current default; we just make it
    --    non-version-dependent.
    --
    --  * max_background_jobs raised to 6 so flushes + compactions run in
    --    parallel on this 16C/32T box and keep up with the single writer thread,
    --    instead of serializing behind it.
    --
    -- All of these are storage-engine knobs only: they change how SSTs are laid
    -- out and compacted, never the bytes stored. No consensus surface.
    librocksdb.rocksdb_options_set_max_bytes_for_level_base(options, 1024 * 1024 * 1024)  -- 1GB L1 target
    librocksdb.rocksdb_options_set_level0_slowdown_writes_trigger(options, 20)
    librocksdb.rocksdb_options_set_level0_stop_writes_trigger(options, 36)
    librocksdb.rocksdb_options_set_max_background_jobs(options, 6)
    -- Atomic flush: see "Durability model" above.  Required for crash
    -- consistency across column families once the WAL is off; harmless (and
    -- still consistent) in legacy WAL mode.
    librocksdb.rocksdb_options_set_atomic_flush(options, 1)
    -- Incremental background writeback of SST/blob files as they are written
    -- (sync_file_range every 1 MB, RocksDB tuning-guide default) instead of
    -- leaving hundreds of MB dirty for one large fsync at file close.  Runs on
    -- flush/compaction threads only.
    librocksdb.rocksdb_options_set_bytes_per_sync(options, 1024 * 1024)
    return options
  end
  local options = new_base_options()

  -- Block bodies (CF.BLOCKS) are large (~1-2 MB), written once and never
  -- modified.  In an LSM they were nevertheless rewritten by every compaction
  -- they passed through: MEASURED on the 725000 range slice's RocksDB LOG,
  -- the blocks CF had ingested 21.1 GB but compaction had written 118.6 GB
  -- (and read 97.5 GB) -- ~75% of all chainstate write traffic.  Integrated
  -- BlobDB stores each value >= min_blob_size in an append-only blob file at
  -- flush time; the LSM then holds only the key -> blob-reference, so
  -- compactions move ~50-byte references instead of megabyte bodies.  This is
  -- Core's layout in spirit (bodies appended once to blk*.dat, the index in
  -- a small KV store).  Reads are transparent (same Get / iterator API, same
  -- bytes).  Blob GC stays off unless pruning (GC would rewrite live bodies);
  -- with --prune it is on so deleted bodies are reclaimed.  Existing SST-
  -- resident bodies stay readable; only new flushes produce blobs.
  local blocks_options = new_base_options()
  librocksdb.rocksdb_options_set_enable_blob_files(blocks_options, 1)
  librocksdb.rocksdb_options_set_min_blob_size(blocks_options, 4096)
  librocksdb.rocksdb_options_set_blob_file_size(blocks_options, 256 * 1024 * 1024)
  librocksdb.rocksdb_options_set_blob_compression_type(blocks_options, 1)  -- Snappy
  librocksdb.rocksdb_options_set_enable_blob_gc(blocks_options, open_opts.prune and 1 or 0)
  local function cf_opts(cf_name)
    if cf_name == M.CF.BLOCKS then return blocks_options end
    return options
  end

  -- Create LRU block cache
  local cache_size = cache_size_mb * 1024 * 1024
  local cache = librocksdb.rocksdb_cache_create_lru(cache_size)

  -- Create block-based table options
  local table_options = librocksdb.rocksdb_block_based_options_create()
  librocksdb.rocksdb_block_based_options_set_block_cache(table_options, cache)
  librocksdb.rocksdb_block_based_options_set_block_size(table_options, 16 * 1024)  -- 16KB
  -- Full bloom filters, 10 bits/key (~1% false positives).  Without a filter
  -- policy (filter_policy=nullptr, observed in the OPTIONS file of the live
  -- 650000->675000 range slice) a Get for a key that is NOT in an SST must
  -- read and search a data block in every level it could live in.
  -- connect_block does one such negative lookup per created output (the BIP30
  -- HaveCoin probe and CoinView:add's FRESH probe); MEASURED with [CB-PROF]
  -- at 650000-650300 on a 67M-coin chainstate: 0.28-0.64 ms per negative
  -- probe, 1.4-3.2 s per block.  Filters are per-SST and recorded in the SST, so this
  -- only affects files written from now on (flushes/compactions/imports);
  -- existing SSTs stay readable.  Storage-engine knob only: the bytes stored
  -- and every Get result are unchanged.  (Core's LevelDB coins DB sets the
  -- same thing: dbwrapper.cpp GetOptions, NewBloomFilterPolicy(10).)
  librocksdb.rocksdb_block_based_options_set_filter_policy(
    table_options, librocksdb.rocksdb_filterpolicy_create_bloom_full(10))
  librocksdb.rocksdb_options_set_block_based_table_factory(options, table_options)
  librocksdb.rocksdb_options_set_block_based_table_factory(blocks_options, table_options)

  -- Check if the database already exists by looking for CURRENT file
  local db_exists = false
  local f = io.open(path .. "/CURRENT", "r")
  if f then
    f:close()
    db_exists = true
  end

  local db, handles

  if not db_exists then
    -- New database: use simple open first, then create column families
    db = librocksdb.rocksdb_open(options, path, errptr)
    check_error(errptr)

    handles = {}
    -- "default" CF is implicitly created by rocksdb_open
    -- Create all other column families
    for _, cf_name in ipairs(CF_LIST) do
      if cf_name ~= M.CF.DEFAULT then
        local handle = librocksdb.rocksdb_create_column_family(db, cf_opts(cf_name), cf_name, errptr)
        check_error(errptr)
        handles[cf_name] = handle
      end
    end

    -- Destroy column family handles before closing
    for _, handle in pairs(handles) do
      librocksdb.rocksdb_column_family_handle_destroy(handle)
    end
    -- Close and reopen with all column families so we get proper handles
    librocksdb.rocksdb_close(db)
    db = nil
    db_exists = true  -- now it exists
  end

  -- Open (or reopen) with column families
  if not db then
    -- List existing column families
    local existing_cfs = {}
    local lencf = ffi.new("size_t[1]")
    local cf_list_ptr = librocksdb.rocksdb_list_column_families(options, path, lencf, errptr)
    if cf_list_ptr ~= nil then
      for i = 0, tonumber(lencf[0]) - 1 do
        existing_cfs[ffi.string(cf_list_ptr[i])] = true
      end
      librocksdb.rocksdb_list_column_families_destroy(cf_list_ptr, lencf[0])
    else
      if errptr[0] ~= nil then
        librocksdb.rocksdb_free(errptr[0])
        errptr[0] = nil
      end
    end

    -- Determine which column families to open with
    local cfs_to_open = {}
    for cf_name, _ in pairs(existing_cfs) do
      cfs_to_open[#cfs_to_open + 1] = cf_name
    end
    if #cfs_to_open == 0 then
      cfs_to_open = { M.CF.DEFAULT }
    end

    -- Create arrays for column family names and options
    local num_cfs = #cfs_to_open
    local cf_names = ffi.new("const char*[?]", num_cfs)
    local cf_options = ffi.new("const rocksdb_options_t*[?]", num_cfs)
    local cf_handles = ffi.new("rocksdb_column_family_handle_t*[?]", num_cfs)

    for i, cf_name in ipairs(cfs_to_open) do
      cf_names[i - 1] = cf_name
      cf_options[i - 1] = cf_opts(cf_name)
    end

    -- Open database with column families
    db = librocksdb.rocksdb_open_column_families(
      options, path, num_cfs, cf_names, cf_options, cf_handles, errptr
    )
    check_error(errptr)

    -- Store handles in a map
    handles = {}
    for i, cf_name in ipairs(cfs_to_open) do
      handles[cf_name] = cf_handles[i - 1]
    end

    -- Create any missing column families
    for _, cf_name in ipairs(CF_LIST) do
      if not handles[cf_name] then
        local handle = librocksdb.rocksdb_create_column_family(db, cf_opts(cf_name), cf_name, errptr)
        check_error(errptr)
        handles[cf_name] = handle
      end
    end
  end

  -- Create read/write options
  local read_opts = librocksdb.rocksdb_readoptions_create()
  local write_opts = librocksdb.rocksdb_writeoptions_create()
  local write_opts_sync = librocksdb.rocksdb_writeoptions_create()
  if wal_enabled then
    librocksdb.rocksdb_writeoptions_set_sync(write_opts_sync, 1)
  else
    -- Memtable-only writes; sync=true callers get a blocking atomic flush
    -- after the write instead (after_sync_write).  RocksDB rejects
    -- sync=true together with disableWAL, so write_opts_sync is identical to
    -- write_opts in this mode.
    librocksdb.rocksdb_writeoptions_disable_WAL(write_opts, 1)
    librocksdb.rocksdb_writeoptions_disable_WAL(write_opts_sync, 1)
  end
  local flush_opts_wait = librocksdb.rocksdb_flushoptions_create()
  librocksdb.rocksdb_flushoptions_set_wait(flush_opts_wait, 1)
  local flush_opts_nowait = librocksdb.rocksdb_flushoptions_create()
  librocksdb.rocksdb_flushoptions_set_wait(flush_opts_nowait, 0)
  -- The non-blocking checkpoint must also not wait for stall conditions.
  -- With FlushOptions.allow_write_stall=false (the default) RocksDB's
  -- Flush() first blocks the CALLER in WaitUntilFlushWouldNotStallWrites
  -- until compaction has drained L0 / the immutable memtables -- even with
  -- wait=false.  MEASURED 2026-09-28 (arm C2, 651100->652000): one periodic
  -- checkpoint blocked the connect loop for 428 s ("[utxo]
  -- WaitUntilFlushWouldNotStallWrites waiting on stall conditions to clear"
  -- in the RocksDB LOG).  allow_write_stall=true schedules the flush at once;
  -- any resulting backpressure is RocksDB's normal delayed-write rate, the
  -- same as for an automatic memtable-full flush.  The C API has no setter,
  -- so set the field directly (c.cc: struct rocksdb_flushoptions_t
  -- { FlushOptions rep; }, FlushOptions = { bool wait; bool
  -- allow_write_stall; }) -- but only after probing that byte 0 tracks
  -- set_wait and byte 1 holds the documented default (false).  If the probe
  -- fails the field is left alone and checkpoint() falls back to skipping
  -- when a flush is already running (below).
  local nowait_allows_stall = false
  do
    local b = ffi.cast("unsigned char*", flush_opts_nowait)
    librocksdb.rocksdb_flushoptions_set_wait(flush_opts_nowait, 1)
    local w1 = b[0]
    librocksdb.rocksdb_flushoptions_set_wait(flush_opts_nowait, 0)
    local w0 = b[0]
    if w1 == 1 and w0 == 0 and b[1] == 0 then
      b[1] = 1
      nowait_allows_stall = true
    end
  end

  -- Build the database object
  local dbobj = {
    _db = db,
    _options = options,
    _table_options = table_options,
    _cache = cache,
    -- Configured RocksDB LRU block-cache size in bytes. This is the
    -- chainstate coins-DB cache budget (Core's
    -- Chainstate::m_coinsdb_cache_size_bytes), surfaced by getchainstates.
    _block_cache_bytes = cache_size,
    _read_opts = read_opts,
    _write_opts = write_opts,
    _write_opts_sync = write_opts_sync,
    _flush_opts_wait = flush_opts_wait,
    _flush_opts_nowait = flush_opts_nowait,
    _nowait_allows_stall = nowait_allows_stall,
    _blocks_options = blocks_options,
    _handles = handles,
    -- true: legacy WAL durability; false: memtable-checkpoint model (default).
    wal_enabled = wal_enabled,
    -- Counters for instrumentation ([CB-PROF] / tests).
    stats = { checkpoints = 0, durable_flushes = 0 },
    CF = M.CF,
  }

  -- Atomic flush of every column family (one MANIFEST commit).  wait=true
  -- blocks until the SSTs/blobs are durable; wait=false only schedules it.
  local function flush_all(wait)
    local n = 0
    for _ in pairs(dbobj._handles) do n = n + 1 end
    local arr = ffi.new("rocksdb_column_family_handle_t*[?]", n)
    local i = 0
    for _, h in pairs(dbobj._handles) do arr[i] = h; i = i + 1 end
    librocksdb.rocksdb_flush_cfs(dbobj._db,
      wait and dbobj._flush_opts_wait or dbobj._flush_opts_nowait, arr, n, errptr)
    check_error(errptr)
  end

  -- Called after every write that asked for sync=true.  Legacy WAL mode: the
  -- write itself was a synced WAL append, nothing to do.  Checkpoint mode:
  -- make everything written so far durable before returning.
  local function after_sync_write()
    if not dbobj.wal_enabled then
      flush_all(true)
      dbobj.stats.durable_flushes = dbobj.stats.durable_flushes + 1
    end
  end

  -- Periodic durability point for the IBD / block-connect loop (sync.lua).
  -- Replaces the old "rewrite chain_tip with sync=true" WAL fdatasync.
  --   checkpoint mode: request an atomic flush of all memtables; with
  --     wait=false this returns immediately and the flush runs on a RocksDB
  --     background thread -- the main thread never blocks on file IO.
  --   legacy WAL mode: fdatasync the WAL (what the sync=true write did).
  --   A non-blocking checkpoint is skipped (returns false) while a flush is
  --   already running: that flush is itself making the state durable, and
  --   stacking more small memtables behind it only adds L0 files.
  -- A failed durability point is fatal (Core FlushStateToDisk ->
  -- FatalError -> AbortNode): RocksDB is left in background-error state and
  -- every later write fails; carrying on would only turn the failure into
  -- something a classifier might read as a verdict.  Latch, then raise.
  local function checkpoint_failed(err)
    fault.latch("chainstate checkpoint (flush) failed: " .. tostring(err))
    error(err, 0)
  end

  function dbobj.checkpoint(wait)
    if fault.hooks then
      local inj = fault.hook("db_checkpoint", wait)
      if inj then
        local ok_i, err_i = pcall(raise_db_error, inj)
        if not ok_i then checkpoint_failed(err_i) end
      end
    end
    if dbobj.wal_enabled then
      librocksdb.rocksdb_flush_wal(dbobj._db, 1, errptr)
      local ok_c, err_c = pcall(check_error, errptr)
      if not ok_c then checkpoint_failed(err_c) end
    else
      if not wait then
        local running = dbobj.property("rocksdb.num-running-flushes")
        if running and running ~= "0" then
          dbobj.stats.checkpoints_skipped = (dbobj.stats.checkpoints_skipped or 0) + 1
          return false
        end
      end
      local ok_f, err_f = pcall(flush_all, wait and true or false)
      if not ok_f then checkpoint_failed(err_f) end
    end
    dbobj.stats.checkpoints = dbobj.stats.checkpoints + 1
    return true
  end
  attach_periodic_checkpoint(dbobj, wal_enabled)

  -- Explicit atomic flush of every memtable, regardless of mode (tests,
  -- maintenance).  wait=true blocks until durable.
  function dbobj.flush(wait)
    flush_all(wait and true or false)
  end

  -- Integer DB property (e.g. "rocksdb.num-running-flushes"); nil if absent.
  function dbobj.property(name)
    local v = librocksdb.rocksdb_property_value(dbobj._db, name)
    if v == nil then return nil end
    local r = ffi.string(v)
    librocksdb.rocksdb_free(v)
    return r
  end

  -- Get a value from a column family
  function dbobj.get(cf, key)
    local handle = dbobj._handles[cf]
    if not handle then
      error("Unknown column family: " .. tostring(cf))
    end
    if fault.hooks then
      local inj = fault.hook("db_get", cf, key)
      if inj then raise_db_error(inj) end
    end
    local vallen = ffi.new("size_t[1]")
    local val = librocksdb.rocksdb_get_cf(
      dbobj._db, dbobj._read_opts, handle, key, #key, vallen, errptr
    )
    check_error(errptr)
    if val == nil then
      return nil
    end
    local result = ffi.string(val, vallen[0])
    librocksdb.rocksdb_free(val)
    return result
  end

  -- Parallel point reads (csrc/coin_prefetch.c).  keys: array of strings,
  -- all exactly keylen bytes.  Returns an array aligned with keys whose
  -- entries are the value string (present), false (absent) or nil (RocksDB
  -- error for that key — the caller must not treat it as absent).  Returns
  -- nil when the helper library is not built.  Pure read: nothing is written.
  local pg_cap = 0
  local pg_keybuf, pg_vals, pg_lens
  function dbobj.parallel_get(cf, keys, keylen, nthreads)
    if not prefetch_lib then return nil end
    local handle = dbobj._handles[cf]
    if not handle then
      error("Unknown column family: " .. tostring(cf))
    end
    local n = #keys
    local out = {}
    if n == 0 then return out end
    if n > pg_cap then
      pg_cap = math.max(n, 2 * pg_cap, 1024)
      pg_keybuf = ffi.new("char[?]", pg_cap * keylen)
      pg_vals = ffi.new("char*[?]", pg_cap)
      pg_lens = ffi.new("size_t[?]", pg_cap)
    end
    for i = 1, n do
      local k = keys[i]
      if #k ~= keylen then
        error("parallel_get: key " .. i .. " has length " .. #k)
      end
      ffi.copy(pg_keybuf + (i - 1) * keylen, k, keylen)
    end
    prefetch_lib.coin_prefetch_get(dbobj._db, dbobj._read_opts, handle,
      pg_keybuf, keylen, n, pg_vals, pg_lens, nthreads or 16)
    for i = 0, n - 1 do
      local v = pg_vals[i]
      -- Test-only: an injected read error for this key reads as the C
      -- helper's per-key error (unknown, not absent).
      local inj = fault.hooks and fault.hook("db_get", cf, keys[i + 1])
      if inj then
        if v ~= nil then librocksdb.rocksdb_free(v) end
        out[i + 1] = nil
      elseif v ~= nil then
        out[i + 1] = ffi.string(v, pg_lens[i])
        librocksdb.rocksdb_free(v)
      elseif pg_lens[i] == SIZE_MAX_CDATA then
        out[i + 1] = nil  -- error: unknown, not absent
      else
        out[i + 1] = false
      end
    end
    return out
  end

  -- Put a value into a column family
  function dbobj.put(cf, key, value, sync)
    local handle = dbobj._handles[cf]
    if not handle then
      error("Unknown column family: " .. tostring(cf))
    end
    local opts = sync and dbobj._write_opts_sync or dbobj._write_opts
    librocksdb.rocksdb_put_cf(
      dbobj._db, opts, handle, key, #key, value, #value, errptr
    )
    check_error(errptr)
    if sync then after_sync_write() end
  end

  -- Delete a key from a column family
  function dbobj.delete(cf, key, sync)
    local handle = dbobj._handles[cf]
    if not handle then
      error("Unknown column family: " .. tostring(cf))
    end
    local opts = sync and dbobj._write_opts_sync or dbobj._write_opts
    librocksdb.rocksdb_delete_cf(dbobj._db, opts, handle, key, #key, errptr)
    check_error(errptr)
    if sync then after_sync_write() end
  end

  -- Create a write batch
  function dbobj.batch()
    local wb = librocksdb.rocksdb_writebatch_create()
    local batch = { _wb = wb }

    function batch.put(cf, key, value)
      local handle = dbobj._handles[cf]
      if not handle then
        error("Unknown column family: " .. tostring(cf))
      end
      librocksdb.rocksdb_writebatch_put_cf(batch._wb, handle, key, #key, value, #value)
    end

    function batch.delete(cf, key)
      local handle = dbobj._handles[cf]
      if not handle then
        error("Unknown column family: " .. tostring(cf))
      end
      librocksdb.rocksdb_writebatch_delete_cf(batch._wb, handle, key, #key)
    end

    function batch.write(sync)
      -- Test-only injection (fault.hooks is nil in production): a hook
      -- returning a message fails this write exactly as RocksDB would.
      if fault.hooks then
        local inj = fault.hook("db_write", sync)
        if inj then raise_db_error(inj) end
      end
      local opts = sync and dbobj._write_opts_sync or dbobj._write_opts
      librocksdb.rocksdb_write(dbobj._db, opts, batch._wb, errptr)
      check_error(errptr)
      if sync then after_sync_write() end
    end

    function batch.clear()
      librocksdb.rocksdb_writebatch_clear(batch._wb)
    end

    function batch.destroy()
      if batch._wb ~= nil then
        librocksdb.rocksdb_writebatch_destroy(batch._wb)
        batch._wb = nil
      end
    end

    return batch
  end

  -- Create an iterator for a column family
  function dbobj.iterator(cf)
    local handle = dbobj._handles[cf]
    if not handle then
      error("Unknown column family: " .. tostring(cf))
    end
    local it = librocksdb.rocksdb_create_iterator_cf(dbobj._db, dbobj._read_opts, handle)
    local iter = { _it = it }

    function iter.seek(key)
      librocksdb.rocksdb_iter_seek(iter._it, key, #key)
    end

    function iter.seek_to_first()
      librocksdb.rocksdb_iter_seek_to_first(iter._it)
    end

    function iter.seek_to_last()
      librocksdb.rocksdb_iter_seek_to_last(iter._it)
    end

    function iter.valid()
      return librocksdb.rocksdb_iter_valid(iter._it) ~= 0
    end

    function iter.next()
      librocksdb.rocksdb_iter_next(iter._it)
    end

    function iter.prev()
      librocksdb.rocksdb_iter_prev(iter._it)
    end

    function iter.key()
      local klen = ffi.new("size_t[1]")
      local k = librocksdb.rocksdb_iter_key(iter._it, klen)
      if k == nil then return nil end
      return ffi.string(k, klen[0])
    end

    function iter.value()
      local vlen = ffi.new("size_t[1]")
      local v = librocksdb.rocksdb_iter_value(iter._it, vlen)
      if v == nil then return nil end
      return ffi.string(v, vlen[0])
    end

    function iter.destroy()
      if iter._it ~= nil then
        librocksdb.rocksdb_iter_destroy(iter._it)
        iter._it = nil
      end
    end

    return iter
  end

  -- High-level helpers (chain tip / chaintx count / headers / blocks / height
  -- index / undo) are shared with the in-memory backend; see
  -- attach_high_level_helpers above.  They are defined purely in terms of the
  -- low-level dbobj.get/put/delete primitives installed just above.
  attach_high_level_helpers(dbobj)

  -- Close the database
  function dbobj.close()
    -- Checkpoint mode: memtables hold everything since the last flush; make
    -- it durable before closing (RocksDB would also flush unpersisted data on
    -- close, but do it explicitly and surface errors).
    if not dbobj.wal_enabled and dbobj._db ~= nil then
      local ok, err = pcall(flush_all, true)
      if not ok then
        io.stderr:write("storage.close: final flush failed: " .. tostring(err) .. "\n")
        -- The chainstate since the last checkpoint is lost (the on-disk
        -- state is still a consistent earlier one).  Core: a failed final
        -- FlushStateToDisk is a fatal error -> non-zero exit.
        fault.latch("final chainstate flush failed at shutdown: " .. tostring(err))
      end
    end
    -- Destroy column family handles
    for _, handle in pairs(dbobj._handles) do
      librocksdb.rocksdb_column_family_handle_destroy(handle)
    end
    dbobj._handles = {}

    -- Destroy read/write options
    librocksdb.rocksdb_readoptions_destroy(dbobj._read_opts)
    librocksdb.rocksdb_writeoptions_destroy(dbobj._write_opts)
    librocksdb.rocksdb_writeoptions_destroy(dbobj._write_opts_sync)
    librocksdb.rocksdb_flushoptions_destroy(dbobj._flush_opts_wait)
    librocksdb.rocksdb_flushoptions_destroy(dbobj._flush_opts_nowait)

    -- Destroy table options and cache
    librocksdb.rocksdb_block_based_options_destroy(dbobj._table_options)
    librocksdb.rocksdb_cache_destroy(dbobj._cache)

    -- Destroy main options
    librocksdb.rocksdb_options_destroy(dbobj._options)
    librocksdb.rocksdb_options_destroy(dbobj._blocks_options)

    -- Close the database
    librocksdb.rocksdb_close(dbobj._db)
    dbobj._db = nil
  end

  return dbobj
end

return M
