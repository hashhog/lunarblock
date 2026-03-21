local ffi = require("ffi")
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
]]

local librocksdb = ffi.load("rocksdb")

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
}

-- Helper: check error and throw if set
local function check_error(errptr)
  if errptr[0] ~= nil then
    local msg = ffi.string(errptr[0])
    librocksdb.rocksdb_free(errptr[0])
    error("RocksDB error: " .. msg)
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

-- Open a RocksDB database
function M.open(path, cache_size_mb)
  cache_size_mb = cache_size_mb or 450
  local errptr = ffi.new("char*[1]")

  -- Create main options
  local options = librocksdb.rocksdb_options_create()
  librocksdb.rocksdb_options_set_create_if_missing(options, 1)
  librocksdb.rocksdb_options_set_create_missing_column_families(options, 1)
  librocksdb.rocksdb_options_set_max_open_files(options, 1000)
  librocksdb.rocksdb_options_set_write_buffer_size(options, 64 * 1024 * 1024)  -- 64MB
  librocksdb.rocksdb_options_set_max_write_buffer_number(options, 3)
  librocksdb.rocksdb_options_set_compression(options, 0)  -- No compression

  -- Create LRU block cache
  local cache_size = cache_size_mb * 1024 * 1024
  local cache = librocksdb.rocksdb_cache_create_lru(cache_size)

  -- Create block-based table options
  local table_options = librocksdb.rocksdb_block_based_options_create()
  librocksdb.rocksdb_block_based_options_set_block_cache(table_options, cache)
  librocksdb.rocksdb_block_based_options_set_block_size(table_options, 16 * 1024)  -- 16KB
  librocksdb.rocksdb_options_set_block_based_table_factory(options, table_options)

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
        local handle = librocksdb.rocksdb_create_column_family(db, options, cf_name, errptr)
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
      cf_options[i - 1] = options
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
        local handle = librocksdb.rocksdb_create_column_family(db, options, cf_name, errptr)
        check_error(errptr)
        handles[cf_name] = handle
      end
    end
  end

  -- Create read/write options
  local read_opts = librocksdb.rocksdb_readoptions_create()
  local write_opts = librocksdb.rocksdb_writeoptions_create()
  local write_opts_sync = librocksdb.rocksdb_writeoptions_create()
  librocksdb.rocksdb_writeoptions_set_sync(write_opts_sync, 1)

  -- Build the database object
  local dbobj = {
    _db = db,
    _options = options,
    _table_options = table_options,
    _cache = cache,
    _read_opts = read_opts,
    _write_opts = write_opts,
    _write_opts_sync = write_opts_sync,
    _handles = handles,
    CF = M.CF,
  }

  -- Get a value from a column family
  function dbobj.get(cf, key)
    local handle = dbobj._handles[cf]
    if not handle then
      error("Unknown column family: " .. tostring(cf))
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
      local opts = sync and dbobj._write_opts_sync or dbobj._write_opts
      librocksdb.rocksdb_write(dbobj._db, opts, batch._wb, errptr)
      check_error(errptr)
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

  -- Close the database
  function dbobj.close()
    -- Destroy column family handles
    for _, handle in pairs(dbobj._handles) do
      librocksdb.rocksdb_column_family_handle_destroy(handle)
    end
    dbobj._handles = {}

    -- Destroy read/write options
    librocksdb.rocksdb_readoptions_destroy(dbobj._read_opts)
    librocksdb.rocksdb_writeoptions_destroy(dbobj._write_opts)
    librocksdb.rocksdb_writeoptions_destroy(dbobj._write_opts_sync)

    -- Destroy table options and cache
    librocksdb.rocksdb_block_based_options_destroy(dbobj._table_options)
    librocksdb.rocksdb_cache_destroy(dbobj._cache)

    -- Destroy main options
    librocksdb.rocksdb_options_destroy(dbobj._options)

    -- Close the database
    librocksdb.rocksdb_close(dbobj._db)
    dbobj._db = nil
  end

  return dbobj
end

return M
