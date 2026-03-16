describe("flatfile", function()
  local flatfile, types, serialize, validation, consensus

  -- Helper to create a unique temp directory
  local function make_temp_dir()
    local tmpname = os.tmpname()
    os.remove(tmpname)
    os.execute("mkdir -p " .. tmpname)
    return tmpname
  end

  -- Helper to remove a directory recursively
  local function remove_dir(path)
    os.execute("rm -rf " .. path)
  end

  setup(function()
    flatfile = require("lunarblock.flatfile")
    types = require("lunarblock.types")
    serialize = require("lunarblock.serialize")
    validation = require("lunarblock.validation")
    consensus = require("lunarblock.consensus")
  end)

  describe("constants", function()
    it("has correct max blockfile size", function()
      assert.equal(0x8000000, flatfile.MAX_BLOCKFILE_SIZE)
    end)

    it("has correct storage header size", function()
      assert.equal(8, flatfile.STORAGE_HEADER_BYTES)
    end)
  end)

  describe("blockfile_info", function()
    it("creates new blockfile info with defaults", function()
      local info = flatfile.new_blockfile_info()
      assert.equal(0, info.nBlocks)
      assert.equal(0, info.nSize)
      assert.equal(0, info.nUndoSize)
      assert.is_nil(info.nHeightFirst)
      assert.is_nil(info.nHeightLast)
    end)

    it("serializes and deserializes blockfile info", function()
      local info = flatfile.new_blockfile_info()
      info.nBlocks = 100
      info.nSize = 12345678
      info.nUndoSize = 987654
      info.nHeightFirst = 50000
      info.nHeightLast = 50100
      info.nTimeFirst = 1600000000
      info.nTimeLast = 1600100000

      local data = flatfile.serialize_blockfile_info(info)
      local restored = flatfile.deserialize_blockfile_info(data)

      assert.equal(info.nBlocks, restored.nBlocks)
      assert.equal(info.nSize, restored.nSize)
      assert.equal(info.nUndoSize, restored.nUndoSize)
      assert.equal(info.nHeightFirst, restored.nHeightFirst)
      assert.equal(info.nHeightLast, restored.nHeightLast)
      assert.equal(info.nTimeFirst, restored.nTimeFirst)
      assert.equal(info.nTimeLast, restored.nTimeLast)
    end)
  end)

  describe("block_index_entry", function()
    it("creates new block index entry", function()
      local entry = flatfile.new_block_index_entry(5, 12345, 6789, 100000)
      assert.equal(5, entry.file_num)
      assert.equal(12345, entry.data_pos)
      assert.equal(6789, entry.undo_pos)
      assert.equal(100000, entry.height)
    end)

    it("serializes and deserializes block index entry", function()
      local entry = flatfile.new_block_index_entry(10, 98765, 43210, 500000)
      local data = flatfile.serialize_index_entry(entry)
      local restored = flatfile.deserialize_index_entry(data)

      assert.equal(entry.file_num, restored.file_num)
      assert.equal(entry.data_pos, restored.data_pos)
      assert.equal(entry.undo_pos, restored.undo_pos)
      assert.equal(entry.height, restored.height)
    end)
  end)

  describe("open", function()
    it("creates a store with mainnet magic", function()
      local path = make_temp_dir()
      local magic = consensus.networks.mainnet.magic_bytes
      local store = flatfile.open(path, magic)

      assert.is_not_nil(store)
      assert.equal(0, store.get_current_file())
      assert.equal(0, store.get_block_count())

      remove_dir(path)
    end)

    it("creates a store with testnet magic", function()
      local path = make_temp_dir()
      local magic = consensus.networks.testnet3.magic_bytes
      local store = flatfile.open(path, magic)

      assert.is_not_nil(store)
      remove_dir(path)
    end)
  end)

  -- Helper to create a simple test block
  local function make_test_block(height, prev_hash)
    prev_hash = prev_hash or types.hash256_zero()
    local merkle = types.hash256(string.rep("\x01", 32))

    local header = types.block_header(
      1,                -- version
      prev_hash,
      merkle,
      1231006505 + height * 600,  -- timestamp
      0x1d00ffff,       -- bits
      height * 1000     -- nonce
    )

    -- Create a simple coinbase transaction
    local coinbase_input = types.txin(
      types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
      string.char(height % 256),  -- Simple script with height
      0xFFFFFFFF
    )
    local coinbase_output = types.txout(
      5000000000,  -- 50 BTC
      "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"  -- P2PKH
    )
    local coinbase_tx = types.transaction(1, {coinbase_input}, {coinbase_output}, 0)

    return types.block(header, {coinbase_tx})
  end

  describe("write_block", function()
    local store, path

    before_each(function()
      path = make_temp_dir()
      store = flatfile.open(path, consensus.networks.mainnet.magic_bytes)
    end)

    after_each(function()
      remove_dir(path)
    end)

    it("writes a single block", function()
      local block = make_test_block(0)
      local hash_hex, err = store.write_block(block, 0)

      assert.is_not_nil(hash_hex)
      assert.is_nil(err)
      assert.equal(64, #hash_hex)  -- hex string
      assert.equal(1, store.get_block_count())
    end)

    it("writes multiple blocks", function()
      local prev_hash = types.hash256_zero()
      for i = 0, 9 do
        local block = make_test_block(i, prev_hash)
        local hash_hex = store.write_block(block, i)
        assert.is_not_nil(hash_hex)
        prev_hash = types.hash256_from_hex(hash_hex)
      end

      assert.equal(10, store.get_block_count())
    end)

    it("creates block file on disk", function()
      local block = make_test_block(0)
      store.write_block(block, 0)

      local blk_path = store.blk_path(0)
      local file = io.open(blk_path, "rb")
      assert.is_not_nil(file)
      local size = file:seek("end")
      assert.is_true(size > 0)
      file:close()
    end)
  end)

  describe("read_block", function()
    local store, path

    before_each(function()
      path = make_temp_dir()
      store = flatfile.open(path, consensus.networks.mainnet.magic_bytes)
    end)

    after_each(function()
      remove_dir(path)
    end)

    it("reads a written block by hash hex", function()
      local block = make_test_block(0)
      local hash_hex = store.write_block(block, 0)

      local read_block, err = store.read_block(hash_hex)
      assert.is_not_nil(read_block)
      assert.is_nil(err)
      assert.equal(block.header.version, read_block.header.version)
      assert.equal(block.header.timestamp, read_block.header.timestamp)
      assert.equal(block.header.nonce, read_block.header.nonce)
      assert.equal(#block.transactions, #read_block.transactions)
    end)

    it("reads a written block by hash256 object", function()
      local block = make_test_block(0)
      local hash_hex = store.write_block(block, 0)
      local hash = types.hash256_from_hex(hash_hex)

      local read_block = store.read_block(hash)
      assert.is_not_nil(read_block)
      assert.equal(block.header.timestamp, read_block.header.timestamp)
    end)

    it("returns error for non-existent block", function()
      local hash = types.hash256(string.rep("\x99", 32))
      local block, err = store.read_block(hash)
      assert.is_nil(block)
      assert.equal("block not found in index", err)
    end)

    it("reads multiple blocks correctly", function()
      local prev_hash = types.hash256_zero()
      local hashes = {}

      for i = 0, 4 do
        local block = make_test_block(i, prev_hash)
        local hash_hex = store.write_block(block, i)
        hashes[i] = hash_hex
        prev_hash = types.hash256_from_hex(hash_hex)
      end

      for i = 0, 4 do
        local block = store.read_block(hashes[i])
        assert.is_not_nil(block)
        assert.equal(1231006505 + i * 600, block.header.timestamp)
      end
    end)
  end)

  describe("write_undo and read_undo", function()
    local store, path

    before_each(function()
      path = make_temp_dir()
      store = flatfile.open(path, consensus.networks.mainnet.magic_bytes)
    end)

    after_each(function()
      remove_dir(path)
    end)

    it("writes and reads undo data", function()
      local block = make_test_block(100)
      local hash_hex = store.write_block(block, 100)

      local undo_data = "test undo data with binary \x00\x01\x02\xff"
      local ok, err = store.write_undo(hash_hex, undo_data)
      assert.is_true(ok)
      assert.is_nil(err)

      local read_undo, err2 = store.read_undo(hash_hex)
      assert.is_not_nil(read_undo)
      assert.is_nil(err2)
      assert.equal(undo_data, read_undo)
    end)

    it("writes undo using hash256 object", function()
      local block = make_test_block(100)
      local hash_hex = store.write_block(block, 100)
      local hash = types.hash256_from_hex(hash_hex)

      local undo_data = "undo data"
      local ok = store.write_undo(hash, undo_data)
      assert.is_true(ok)

      local read_undo = store.read_undo(hash)
      assert.equal(undo_data, read_undo)
    end)

    it("creates undo file on disk", function()
      local block = make_test_block(100)
      local hash_hex = store.write_block(block, 100)
      store.write_undo(hash_hex, "undo data")

      local rev_path = store.rev_path(0)
      local file = io.open(rev_path, "rb")
      assert.is_not_nil(file)
      local size = file:seek("end")
      assert.is_true(size > 0)
      file:close()
    end)

    it("returns error when reading undo for non-existent block", function()
      local hash = types.hash256(string.rep("\xaa", 32))
      local undo, err = store.read_undo(hash)
      assert.is_nil(undo)
      assert.equal("block not found in index", err)
    end)

    it("returns error when reading undo before it is written", function()
      local block = make_test_block(100)
      local hash_hex = store.write_block(block, 100)

      local undo, err = store.read_undo(hash_hex)
      assert.is_nil(undo)
      assert.equal("no undo data for block", err)
    end)
  end)

  describe("block index", function()
    local store, path

    before_each(function()
      path = make_temp_dir()
      store = flatfile.open(path, consensus.networks.mainnet.magic_bytes)
    end)

    after_each(function()
      remove_dir(path)
    end)

    it("returns index entry for written block", function()
      local block = make_test_block(12345)
      local hash_hex = store.write_block(block, 12345)

      local entry = store.get_index(hash_hex)
      assert.is_not_nil(entry)
      assert.equal(0, entry.file_num)
      assert.is_true(entry.data_pos >= 8)  -- after header
      assert.equal(12345, entry.height)
    end)

    it("has_block returns true for existing block", function()
      local block = make_test_block(0)
      local hash_hex = store.write_block(block, 0)

      assert.is_true(store.has_block(hash_hex))
    end)

    it("has_block returns false for non-existent block", function()
      local hash = types.hash256(string.rep("\xbb", 32))
      assert.is_false(store.has_block(hash))
    end)

    it("get_height returns correct height", function()
      local block = make_test_block(54321)
      local hash_hex = store.write_block(block, 54321)

      assert.equal(54321, store.get_height(hash_hex))
    end)
  end)

  describe("index serialization", function()
    it("serializes and deserializes empty index", function()
      local path = make_temp_dir()
      local store = flatfile.open(path, consensus.networks.mainnet.magic_bytes)

      local data = store.serialize_index()
      assert.is_true(#data > 0)

      local store2 = flatfile.open(path .. "_2", consensus.networks.mainnet.magic_bytes)
      local ok = store2.load_index(data)
      assert.is_true(ok)
      assert.equal(0, store2.get_block_count())

      remove_dir(path)
      remove_dir(path .. "_2")
    end)

    it("serializes and deserializes index with blocks", function()
      local path = make_temp_dir()
      local store = flatfile.open(path, consensus.networks.mainnet.magic_bytes)

      -- Write some blocks
      local prev_hash = types.hash256_zero()
      local hashes = {}
      for i = 0, 4 do
        local block = make_test_block(i, prev_hash)
        local hash_hex = store.write_block(block, i)
        hashes[i] = hash_hex
        prev_hash = types.hash256_from_hex(hash_hex)
      end

      -- Serialize and reload
      local data = store.serialize_index()

      local store2 = flatfile.open(path .. "_2", consensus.networks.mainnet.magic_bytes)
      local ok = store2.load_index(data)
      assert.is_true(ok)
      assert.equal(5, store2.get_block_count())

      -- Verify entries
      for i = 0, 4 do
        local entry = store2.get_index(hashes[i])
        assert.is_not_nil(entry)
        assert.equal(i, entry.height)
      end

      remove_dir(path)
      remove_dir(path .. "_2")
    end)

    it("saves and loads index from file", function()
      local path = make_temp_dir()
      local store = flatfile.open(path, consensus.networks.mainnet.magic_bytes)

      -- Write blocks
      for i = 0, 2 do
        local block = make_test_block(i)
        store.write_block(block, i)
      end

      -- Save to file
      local index_path = path .. "/block_index.dat"
      local ok, err = store.save_index(index_path)
      assert.is_true(ok)
      assert.is_nil(err)

      -- Reload from file
      local store2 = flatfile.open(path, consensus.networks.mainnet.magic_bytes)
      ok, err = store2.load_index_file(index_path)
      assert.is_true(ok)
      assert.equal(3, store2.get_block_count())

      remove_dir(path)
    end)
  end)

  describe("file rolling", function()
    it("uses current file number correctly", function()
      local path = make_temp_dir()
      local store = flatfile.open(path, consensus.networks.mainnet.magic_bytes)

      assert.equal(0, store.get_current_file())

      local block = make_test_block(0)
      store.write_block(block, 0)

      assert.equal(0, store.get_current_file())

      remove_dir(path)
    end)

    it("generates correct file paths", function()
      local path = make_temp_dir()
      local store = flatfile.open(path, consensus.networks.mainnet.magic_bytes)

      assert.equal(path .. "/blk00000.dat", store.blk_path(0))
      assert.equal(path .. "/blk00001.dat", store.blk_path(1))
      assert.equal(path .. "/blk00123.dat", store.blk_path(123))
      assert.equal(path .. "/rev00000.dat", store.rev_path(0))
      assert.equal(path .. "/rev00456.dat", store.rev_path(456))

      remove_dir(path)
    end)
  end)

  describe("iter_blocks", function()
    it("iterates over all blocks in index", function()
      local path = make_temp_dir()
      local store = flatfile.open(path, consensus.networks.mainnet.magic_bytes)

      local prev_hash = types.hash256_zero()
      local expected_hashes = {}
      for i = 0, 4 do
        local block = make_test_block(i, prev_hash)
        local hash_hex = store.write_block(block, i)
        expected_hashes[hash_hex] = i
        prev_hash = types.hash256_from_hex(hash_hex)
      end

      local count = 0
      for hash_hex, entry in store.iter_blocks() do
        assert.equal(expected_hashes[hash_hex], entry.height)
        count = count + 1
      end

      assert.equal(5, count)
      remove_dir(path)
    end)
  end)
end)
