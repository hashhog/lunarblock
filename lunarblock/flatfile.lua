-- Flat-file block storage for lunarblock
-- Implements Bitcoin Core's blk*.dat and rev*.dat file format
--
-- File format:
--   Each block is stored as: [4-byte magic] [4-byte size LE] [block data]
--   Files are named blk00000.dat, blk00001.dat, etc.
--   Undo files are named rev00000.dat, rev00001.dat, etc.
--   Max file size: 128 MB (then roll to next file)
--
-- Block index maps: hash -> {file_num, data_pos, undo_pos, height}

local ffi = require("ffi")
local serialize = require("lunarblock.serialize")
local types = require("lunarblock.types")
local validation = require("lunarblock.validation")

local M = {}

-- Constants matching Bitcoin Core
M.MAX_BLOCKFILE_SIZE = 0x8000000  -- 128 MiB
M.STORAGE_HEADER_BYTES = 8        -- 4-byte magic + 4-byte size

-- FFI for efficient file I/O
ffi.cdef[[
  typedef struct FILE FILE;
  FILE* fopen(const char* path, const char* mode);
  int fclose(FILE* stream);
  size_t fread(void* ptr, size_t size, size_t count, FILE* stream);
  size_t fwrite(const void* ptr, size_t size, size_t count, FILE* stream);
  int fseek(FILE* stream, long offset, int origin);
  long ftell(FILE* stream);
  int fflush(FILE* stream);
  int mkdir(const char* path, int mode);
]]

local SEEK_SET = 0
local SEEK_END = 2

-- Helper: format file number as 5-digit string
local function format_file_num(n)
  return string.format("%05d", n)
end

-- Helper: encode uint32 as little-endian bytes
local function encode_u32le(val)
  return string.char(
    val % 256,
    math.floor(val / 256) % 256,
    math.floor(val / 65536) % 256,
    math.floor(val / 16777216) % 256
  )
end

-- Helper: decode little-endian uint32 from bytes
local function decode_u32le(data, offset)
  offset = offset or 1
  local b1, b2, b3, b4 = data:byte(offset, offset + 3)
  return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
end

-- Block file info tracking (matches Bitcoin Core's CBlockFileInfo)
local function new_blockfile_info()
  return {
    nBlocks = 0,       -- number of blocks stored in file
    nSize = 0,         -- number of used bytes of block file
    nUndoSize = 0,     -- number of used bytes in the undo file
    nHeightFirst = nil,  -- lowest height of block in file
    nHeightLast = nil,   -- highest height of block in file
    nTimeFirst = nil,    -- earliest time of block in file
    nTimeLast = nil,     -- latest time of block in file
  }
end

-- Update block file info when adding a block
local function update_file_info(info, height, timestamp)
  if info.nBlocks == 0 or (info.nHeightFirst and height < info.nHeightFirst) then
    info.nHeightFirst = height
  end
  if info.nBlocks == 0 or (info.nTimeFirst and timestamp < info.nTimeFirst) then
    info.nTimeFirst = timestamp
  end
  info.nBlocks = info.nBlocks + 1
  if not info.nHeightLast or height > info.nHeightLast then
    info.nHeightLast = height
  end
  if not info.nTimeLast or timestamp > info.nTimeLast then
    info.nTimeLast = timestamp
  end
end

-- Serialize block file info for storage
local function serialize_blockfile_info(info)
  local w = serialize.buffer_writer()
  w.write_varint(info.nBlocks)
  w.write_varint(info.nSize)
  w.write_varint(info.nUndoSize)
  w.write_varint(info.nHeightFirst or 0)
  w.write_varint(info.nHeightLast or 0)
  w.write_varint(info.nTimeFirst or 0)
  w.write_varint(info.nTimeLast or 0)
  return w.result()
end

-- Deserialize block file info
local function deserialize_blockfile_info(data)
  local r = serialize.buffer_reader(data)
  local info = new_blockfile_info()
  info.nBlocks = r.read_varint()
  info.nSize = r.read_varint()
  info.nUndoSize = r.read_varint()
  info.nHeightFirst = r.read_varint()
  info.nHeightLast = r.read_varint()
  info.nTimeFirst = r.read_varint()
  info.nTimeLast = r.read_varint()
  return info
end

-- Block index entry
local function new_block_index_entry(file_num, data_pos, undo_pos, height)
  return {
    file_num = file_num,   -- which blk*.dat file
    data_pos = data_pos,   -- byte offset in block file (after header)
    undo_pos = undo_pos,   -- byte offset in undo file (0 if none)
    height = height,       -- block height
  }
end

-- Serialize block index entry
local function serialize_index_entry(entry)
  local w = serialize.buffer_writer()
  w.write_varint(entry.file_num)
  w.write_varint(entry.data_pos)
  w.write_varint(entry.undo_pos or 0)
  w.write_varint(entry.height)
  return w.result()
end

-- Deserialize block index entry
local function deserialize_index_entry(data)
  local r = serialize.buffer_reader(data)
  return new_block_index_entry(
    r.read_varint(),  -- file_num
    r.read_varint(),  -- data_pos
    r.read_varint(),  -- undo_pos
    r.read_varint()   -- height
  )
end

--- Open or create a flat file storage instance
-- @param blocks_dir string: path to blocks directory
-- @param magic_bytes string: 4-byte network magic
-- @return table: flat file storage object
function M.open(blocks_dir, magic_bytes)
  assert(#magic_bytes == 4, "magic_bytes must be exactly 4 bytes")

  -- Create directory if it doesn't exist
  ffi.C.mkdir(blocks_dir, tonumber("755", 8))

  local store = {
    _dir = blocks_dir,
    _magic = magic_bytes,
    _block_index = {},      -- hash_hex -> index_entry
    _file_info = {},        -- file_num -> blockfile_info
    _current_file = 0,      -- current block file number
    _current_undo_file = 0, -- current undo file number
  }

  -- Get path for a block file
  function store.blk_path(file_num)
    return store._dir .. "/blk" .. format_file_num(file_num) .. ".dat"
  end

  -- Get path for an undo file
  function store.rev_path(file_num)
    return store._dir .. "/rev" .. format_file_num(file_num) .. ".dat"
  end

  -- Get or create file info for a file number
  function store.get_file_info(file_num)
    if not store._file_info[file_num] then
      store._file_info[file_num] = new_blockfile_info()
    end
    return store._file_info[file_num]
  end

  -- Find the next position to write a block
  -- Returns: file_num, position (after header)
  function store.find_next_block_pos(block_size)
    local total_size = block_size + M.STORAGE_HEADER_BYTES

    -- Check if current file has enough space
    local info = store.get_file_info(store._current_file)
    if info.nSize + total_size > M.MAX_BLOCKFILE_SIZE then
      -- Roll to next file
      store._current_file = store._current_file + 1
      info = store.get_file_info(store._current_file)
    end

    local pos = info.nSize
    return store._current_file, pos + M.STORAGE_HEADER_BYTES
  end

  -- Find the next position to write undo data
  function store.find_next_undo_pos(file_num, undo_size)
    local info = store.get_file_info(file_num)
    local pos = info.nUndoSize
    return pos + M.STORAGE_HEADER_BYTES
  end

  --- Write a block to flat file storage
  -- @param block table: block object with header and transactions
  -- @param height number: block height
  -- @return string|nil, string|nil: hash hex string on success, or nil and error
  function store.write_block(block, height)
    -- Serialize the block
    local block_data = serialize.serialize_block(block)
    local block_size = #block_data

    -- Find position
    local file_num, data_pos = store.find_next_block_pos(block_size)
    local path = store.blk_path(file_num)

    -- Open file for append/write
    local file = ffi.C.fopen(path, "ab")
    if file == nil then
      -- Try creating new file
      file = ffi.C.fopen(path, "wb")
      if file == nil then
        return nil, "failed to open block file: " .. path
      end
    end

    -- Seek to end to get actual position
    ffi.C.fseek(file, 0, SEEK_END)
    local file_pos = tonumber(ffi.C.ftell(file))

    -- Write header: magic + size
    local header = store._magic .. encode_u32le(block_size)
    local header_buf = ffi.new("uint8_t[?]", #header)
    ffi.copy(header_buf, header, #header)
    ffi.C.fwrite(header_buf, 1, #header, file)

    -- Write block data
    local block_buf = ffi.new("uint8_t[?]", block_size)
    ffi.copy(block_buf, block_data, block_size)
    ffi.C.fwrite(block_buf, 1, block_size, file)

    ffi.C.fflush(file)
    ffi.C.fclose(file)

    -- Update file info
    local info = store.get_file_info(file_num)
    local timestamp = block.header.timestamp
    update_file_info(info, height, timestamp)
    info.nSize = file_pos + M.STORAGE_HEADER_BYTES + block_size

    -- Compute block hash and add to index
    local block_hash = validation.compute_block_hash(block.header)
    local hash_hex = types.hash256_hex(block_hash)

    store._block_index[hash_hex] = new_block_index_entry(
      file_num,
      file_pos + M.STORAGE_HEADER_BYTES,  -- position after header
      0,  -- no undo data yet
      height
    )

    return hash_hex
  end

  --- Read a block from flat file storage
  -- @param hash hash256 or hex string: block hash
  -- @return table|nil, string|nil: block object on success, or nil and error
  function store.read_block(hash)
    local hash_hex
    if type(hash) == "string" and #hash == 64 then
      hash_hex = hash
    elseif type(hash) == "table" and hash.bytes then
      hash_hex = types.hash256_hex(hash)
    else
      return nil, "invalid hash format"
    end

    -- Look up in index
    local entry = store._block_index[hash_hex]
    if not entry then
      return nil, "block not found in index"
    end

    local path = store.blk_path(entry.file_num)
    local file = ffi.C.fopen(path, "rb")
    if file == nil then
      return nil, "failed to open block file: " .. path
    end

    -- Seek to position before header
    local header_pos = entry.data_pos - M.STORAGE_HEADER_BYTES
    ffi.C.fseek(file, header_pos, SEEK_SET)

    -- Read header
    local header_buf = ffi.new("uint8_t[8]")
    local read = ffi.C.fread(header_buf, 1, 8, file)
    if read ~= 8 then
      ffi.C.fclose(file)
      return nil, "failed to read block header"
    end

    local header_data = ffi.string(header_buf, 8)
    local magic = header_data:sub(1, 4)
    local size = decode_u32le(header_data, 5)

    -- Verify magic
    if magic ~= store._magic then
      ffi.C.fclose(file)
      return nil, "block magic mismatch"
    end

    -- Read block data
    local block_buf = ffi.new("uint8_t[?]", size)
    read = ffi.C.fread(block_buf, 1, size, file)
    ffi.C.fclose(file)

    if read ~= size then
      return nil, "failed to read block data"
    end

    local block_data = ffi.string(block_buf, size)
    local block = serialize.deserialize_block(block_data)

    return block
  end

  --- Write undo data for a block
  -- @param hash hash256 or hex string: block hash
  -- @param undo_data string: serialized undo data
  -- @return boolean, string|nil: success, or false and error
  function store.write_undo(hash, undo_data)
    local hash_hex
    if type(hash) == "string" and #hash == 64 then
      hash_hex = hash
    elseif type(hash) == "table" and hash.bytes then
      hash_hex = types.hash256_hex(hash)
    else
      return false, "invalid hash format"
    end

    -- Look up block in index to get file number
    local entry = store._block_index[hash_hex]
    if not entry then
      return false, "block not found in index"
    end

    local file_num = entry.file_num
    local undo_size = #undo_data
    local path = store.rev_path(file_num)

    -- Open file for append/write
    local file = ffi.C.fopen(path, "ab")
    if file == nil then
      file = ffi.C.fopen(path, "wb")
      if file == nil then
        return false, "failed to open undo file: " .. path
      end
    end

    -- Seek to end to get actual position
    ffi.C.fseek(file, 0, SEEK_END)
    local file_pos = tonumber(ffi.C.ftell(file))

    -- Write header: magic + size
    local header = store._magic .. encode_u32le(undo_size)
    local header_buf = ffi.new("uint8_t[?]", #header)
    ffi.copy(header_buf, header, #header)
    ffi.C.fwrite(header_buf, 1, #header, file)

    -- Write undo data
    local undo_buf = ffi.new("uint8_t[?]", undo_size)
    ffi.copy(undo_buf, undo_data, undo_size)
    ffi.C.fwrite(undo_buf, 1, undo_size, file)

    ffi.C.fflush(file)
    ffi.C.fclose(file)

    -- Update file info
    local info = store.get_file_info(file_num)
    info.nUndoSize = file_pos + M.STORAGE_HEADER_BYTES + undo_size

    -- Update index entry with undo position
    entry.undo_pos = file_pos + M.STORAGE_HEADER_BYTES

    return true
  end

  --- Read undo data for a block
  -- @param hash hash256 or hex string: block hash
  -- @return string|nil, string|nil: undo data on success, or nil and error
  function store.read_undo(hash)
    local hash_hex
    if type(hash) == "string" and #hash == 64 then
      hash_hex = hash
    elseif type(hash) == "table" and hash.bytes then
      hash_hex = types.hash256_hex(hash)
    else
      return nil, "invalid hash format"
    end

    -- Look up in index
    local entry = store._block_index[hash_hex]
    if not entry then
      return nil, "block not found in index"
    end

    if entry.undo_pos == 0 then
      return nil, "no undo data for block"
    end

    local path = store.rev_path(entry.file_num)
    local file = ffi.C.fopen(path, "rb")
    if file == nil then
      return nil, "failed to open undo file: " .. path
    end

    -- Seek to position before header
    local header_pos = entry.undo_pos - M.STORAGE_HEADER_BYTES
    ffi.C.fseek(file, header_pos, SEEK_SET)

    -- Read header
    local header_buf = ffi.new("uint8_t[8]")
    local read = ffi.C.fread(header_buf, 1, 8, file)
    if read ~= 8 then
      ffi.C.fclose(file)
      return nil, "failed to read undo header"
    end

    local header_data = ffi.string(header_buf, 8)
    local magic = header_data:sub(1, 4)
    local size = decode_u32le(header_data, 5)

    -- Verify magic
    if magic ~= store._magic then
      ffi.C.fclose(file)
      return nil, "undo magic mismatch"
    end

    -- Read undo data
    local undo_buf = ffi.new("uint8_t[?]", size)
    read = ffi.C.fread(undo_buf, 1, size, file)
    ffi.C.fclose(file)

    if read ~= size then
      return nil, "failed to read undo data"
    end

    return ffi.string(undo_buf, size)
  end

  --- Get block index entry
  -- @param hash hash256 or hex string: block hash
  -- @return table|nil: index entry or nil
  function store.get_index(hash)
    local hash_hex
    if type(hash) == "string" and #hash == 64 then
      hash_hex = hash
    elseif type(hash) == "table" and hash.bytes then
      hash_hex = types.hash256_hex(hash)
    else
      return nil
    end
    return store._block_index[hash_hex]
  end

  --- Check if block exists in index
  -- @param hash hash256 or hex string: block hash
  -- @return boolean: true if block exists
  function store.has_block(hash)
    return store.get_index(hash) ~= nil
  end

  --- Get block height from index
  -- @param hash hash256 or hex string: block hash
  -- @return number|nil: block height or nil
  function store.get_height(hash)
    local entry = store.get_index(hash)
    return entry and entry.height
  end

  --- Serialize the entire block index for persistence
  -- @return string: serialized index data
  function store.serialize_index()
    local w = serialize.buffer_writer()

    -- Count entries
    local count = 0
    for _ in pairs(store._block_index) do
      count = count + 1
    end
    w.write_varint(count)

    -- Write each entry: hash (32 bytes) + entry data
    for hash_hex, entry in pairs(store._block_index) do
      -- Convert hex to bytes
      local hash_bytes = ""
      for i = 1, 64, 2 do
        local byte = tonumber(hash_hex:sub(i, i + 1), 16)
        hash_bytes = hash_bytes .. string.char(byte)
      end
      w.write_bytes(hash_bytes)
      w.write_bytes(serialize_index_entry(entry))
    end

    -- Write file info
    local max_file = store._current_file
    w.write_varint(max_file + 1)
    for i = 0, max_file do
      local info = store._file_info[i]
      if info then
        w.write_bytes(serialize_blockfile_info(info))
      else
        w.write_bytes(serialize_blockfile_info(new_blockfile_info()))
      end
    end

    -- Write current file numbers
    w.write_varint(store._current_file)
    w.write_varint(store._current_undo_file)

    return w.result()
  end

  --- Deserialize and load block index from data
  -- @param data string: serialized index data
  -- @return boolean, string|nil: success, or false and error
  function store.load_index(data)
    local r = serialize.buffer_reader(data)

    -- Read entries
    local count = r.read_varint()
    store._block_index = {}

    for _ = 1, count do
      -- Read 32-byte hash and convert to hex
      local hash_bytes = r.read_bytes(32)
      local hash_hex = ""
      for i = 1, 32 do
        hash_hex = hash_hex .. string.format("%02x", hash_bytes:byte(i))
      end

      -- Read entry data (need to read varint-encoded values)
      local entry = new_block_index_entry(
        r.read_varint(),  -- file_num
        r.read_varint(),  -- data_pos
        r.read_varint(),  -- undo_pos
        r.read_varint()   -- height
      )

      store._block_index[hash_hex] = entry
    end

    -- Read file info
    local file_count = r.read_varint()
    store._file_info = {}
    for i = 0, file_count - 1 do
      local info = new_blockfile_info()
      info.nBlocks = r.read_varint()
      info.nSize = r.read_varint()
      info.nUndoSize = r.read_varint()
      info.nHeightFirst = r.read_varint()
      info.nHeightLast = r.read_varint()
      info.nTimeFirst = r.read_varint()
      info.nTimeLast = r.read_varint()
      store._file_info[i] = info
    end

    -- Read current file numbers
    store._current_file = r.read_varint()
    store._current_undo_file = r.read_varint()

    return true
  end

  --- Save index to a file
  -- @param path string: path to index file
  -- @return boolean, string|nil: success, or false and error
  function store.save_index(path)
    local data = store.serialize_index()
    local file = io.open(path, "wb")
    if not file then
      return false, "failed to open index file for writing"
    end
    file:write(data)
    file:close()
    return true
  end

  --- Load index from a file
  -- @param path string: path to index file
  -- @return boolean, string|nil: success, or false and error
  function store.load_index_file(path)
    local file = io.open(path, "rb")
    if not file then
      return false, "index file not found"
    end
    local data = file:read("*a")
    file:close()
    return store.load_index(data)
  end

  --- Get current block file number
  -- @return number: current file number
  function store.get_current_file()
    return store._current_file
  end

  --- Get number of blocks in index
  -- @return number: count of blocks
  function store.get_block_count()
    local count = 0
    for _ in pairs(store._block_index) do
      count = count + 1
    end
    return count
  end

  --- Iterate over all blocks in index
  -- @return function: iterator yielding (hash_hex, entry)
  function store.iter_blocks()
    return pairs(store._block_index)
  end

  return store
end

-- Export helper functions for testing
M.new_blockfile_info = new_blockfile_info
M.serialize_blockfile_info = serialize_blockfile_info
M.deserialize_blockfile_info = deserialize_blockfile_info
M.new_block_index_entry = new_block_index_entry
M.serialize_index_entry = serialize_index_entry
M.deserialize_index_entry = deserialize_index_entry

return M
