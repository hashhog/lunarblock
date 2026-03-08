describe("storage", function()
  local storage, types, serialize
  local test_db_path

  -- Helper to create a unique temp directory
  local function make_temp_dir()
    local tmpname = os.tmpname()
    os.remove(tmpname)  -- Remove the file so we can create a directory
    os.execute("mkdir -p " .. tmpname)
    return tmpname
  end

  -- Helper to remove a directory recursively
  local function remove_dir(path)
    os.execute("rm -rf " .. path)
  end

  setup(function()
    storage = require("lunarblock.storage")
    types = require("lunarblock.types")
    serialize = require("lunarblock.serialize")
  end)

  describe("open and close", function()
    it("opens and closes database without errors", function()
      local path = make_temp_dir()
      local db = storage.open(path, 16)  -- 16 MB cache for tests
      assert.is_not_nil(db)
      assert.is_not_nil(db._db)
      db.close()
      remove_dir(path)
    end)
  end)

  describe("get/put/delete", function()
    local db, path

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("puts and gets values in default column family", function()
      db.put(storage.CF.DEFAULT, "key1", "value1")
      local val = db.get(storage.CF.DEFAULT, "key1")
      assert.equal("value1", val)
    end)

    it("puts and gets values in headers column family", function()
      local key = string.rep("\x01", 32)
      local value = string.rep("\x02", 80)
      db.put(storage.CF.HEADERS, key, value)
      local val = db.get(storage.CF.HEADERS, key)
      assert.equal(value, val)
    end)

    it("puts and gets values in blocks column family", function()
      local key = string.rep("\xab", 32)
      local value = "block data here"
      db.put(storage.CF.BLOCKS, key, value)
      local val = db.get(storage.CF.BLOCKS, key)
      assert.equal(value, val)
    end)

    it("puts and gets values in utxo column family", function()
      local key = string.rep("\xcd", 36)  -- txid + vout
      local value = "utxo entry"
      db.put(storage.CF.UTXO, key, value)
      local val = db.get(storage.CF.UTXO, key)
      assert.equal(value, val)
    end)

    it("puts and gets values in tx_index column family", function()
      local key = string.rep("\xef", 32)
      local value = string.rep("\x12", 36)
      db.put(storage.CF.TX_INDEX, key, value)
      local val = db.get(storage.CF.TX_INDEX, key)
      assert.equal(value, val)
    end)

    it("puts and gets values in height_index column family", function()
      local key = "\x00\x00\x01\x00"  -- height 256
      local value = string.rep("\x34", 32)
      db.put(storage.CF.HEIGHT_INDEX, key, value)
      local val = db.get(storage.CF.HEIGHT_INDEX, key)
      assert.equal(value, val)
    end)

    it("puts and gets values in meta column family", function()
      db.put(storage.CF.META, "chain_tip", "some_data")
      local val = db.get(storage.CF.META, "chain_tip")
      assert.equal("some_data", val)
    end)

    it("returns nil for non-existent key", function()
      local val = db.get(storage.CF.DEFAULT, "nonexistent")
      assert.is_nil(val)
    end)

    it("deletes values and confirms nil return", function()
      db.put(storage.CF.DEFAULT, "to_delete", "value")
      assert.equal("value", db.get(storage.CF.DEFAULT, "to_delete"))

      db.delete(storage.CF.DEFAULT, "to_delete")
      assert.is_nil(db.get(storage.CF.DEFAULT, "to_delete"))
    end)

    it("handles binary keys and values", function()
      local binary_key = "\x00\x01\x02\x03\x04"
      local binary_value = "\xff\xfe\xfd\xfc\x00\x01\x02"
      db.put(storage.CF.DEFAULT, binary_key, binary_value)
      local val = db.get(storage.CF.DEFAULT, binary_key)
      assert.equal(binary_value, val)
    end)
  end)

  describe("batch writes", function()
    local db, path

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("writes multiple key-value pairs atomically", function()
      local batch = db.batch()
      batch.put(storage.CF.DEFAULT, "batch1", "val1")
      batch.put(storage.CF.DEFAULT, "batch2", "val2")
      batch.put(storage.CF.DEFAULT, "batch3", "val3")
      batch.write()
      batch.destroy()

      assert.equal("val1", db.get(storage.CF.DEFAULT, "batch1"))
      assert.equal("val2", db.get(storage.CF.DEFAULT, "batch2"))
      assert.equal("val3", db.get(storage.CF.DEFAULT, "batch3"))
    end)

    it("writes to multiple column families in one batch", function()
      local batch = db.batch()
      batch.put(storage.CF.DEFAULT, "key1", "val1")
      batch.put(storage.CF.META, "key2", "val2")
      batch.put(storage.CF.HEADERS, string.rep("\x00", 32), "header_data")
      batch.write()
      batch.destroy()

      assert.equal("val1", db.get(storage.CF.DEFAULT, "key1"))
      assert.equal("val2", db.get(storage.CF.META, "key2"))
      assert.equal("header_data", db.get(storage.CF.HEADERS, string.rep("\x00", 32)))
    end)

    it("supports delete operations in batch", function()
      db.put(storage.CF.DEFAULT, "to_batch_delete", "value")
      assert.equal("value", db.get(storage.CF.DEFAULT, "to_batch_delete"))

      local batch = db.batch()
      batch.delete(storage.CF.DEFAULT, "to_batch_delete")
      batch.put(storage.CF.DEFAULT, "new_key", "new_value")
      batch.write()
      batch.destroy()

      assert.is_nil(db.get(storage.CF.DEFAULT, "to_batch_delete"))
      assert.equal("new_value", db.get(storage.CF.DEFAULT, "new_key"))
    end)

    it("clears batch and allows reuse", function()
      local batch = db.batch()
      batch.put(storage.CF.DEFAULT, "cleared", "should_not_exist")
      batch.clear()
      batch.put(storage.CF.DEFAULT, "after_clear", "exists")
      batch.write()
      batch.destroy()

      assert.is_nil(db.get(storage.CF.DEFAULT, "cleared"))
      assert.equal("exists", db.get(storage.CF.DEFAULT, "after_clear"))
    end)
  end)

  describe("iterator", function()
    local db, path

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)

      -- Insert some ordered data
      db.put(storage.CF.DEFAULT, "aaa", "val_aaa")
      db.put(storage.CF.DEFAULT, "bbb", "val_bbb")
      db.put(storage.CF.DEFAULT, "ccc", "val_ccc")
      db.put(storage.CF.DEFAULT, "ddd", "val_ddd")
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("iterates from first to last", function()
      local iter = db.iterator(storage.CF.DEFAULT)
      local keys = {}

      iter.seek_to_first()
      while iter.valid() do
        keys[#keys + 1] = iter.key()
        iter.next()
      end
      iter.destroy()

      assert.equal(4, #keys)
      assert.equal("aaa", keys[1])
      assert.equal("bbb", keys[2])
      assert.equal("ccc", keys[3])
      assert.equal("ddd", keys[4])
    end)

    it("iterates from last to first", function()
      local iter = db.iterator(storage.CF.DEFAULT)
      local keys = {}

      iter.seek_to_last()
      while iter.valid() do
        keys[#keys + 1] = iter.key()
        iter.prev()
      end
      iter.destroy()

      assert.equal(4, #keys)
      assert.equal("ddd", keys[1])
      assert.equal("ccc", keys[2])
      assert.equal("bbb", keys[3])
      assert.equal("aaa", keys[4])
    end)

    it("seeks to specific key", function()
      local iter = db.iterator(storage.CF.DEFAULT)
      iter.seek("bbb")
      assert.is_true(iter.valid())
      assert.equal("bbb", iter.key())
      assert.equal("val_bbb", iter.value())
      iter.destroy()
    end)

    it("seeks to key greater than or equal to target", function()
      local iter = db.iterator(storage.CF.DEFAULT)
      iter.seek("bb")  -- Should land on "bbb"
      assert.is_true(iter.valid())
      assert.equal("bbb", iter.key())
      iter.destroy()
    end)

    it("returns invalid when seeking past end", function()
      local iter = db.iterator(storage.CF.DEFAULT)
      iter.seek("zzz")
      assert.is_false(iter.valid())
      iter.destroy()
    end)

    it("retrieves key and value correctly", function()
      local iter = db.iterator(storage.CF.DEFAULT)
      iter.seek("ccc")
      assert.is_true(iter.valid())
      assert.equal("ccc", iter.key())
      assert.equal("val_ccc", iter.value())
      iter.destroy()
    end)
  end)

  describe("chain tip", function()
    local db, path

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("returns nil for unset chain tip", function()
      local hash, height = db.get_chain_tip()
      assert.is_nil(hash)
      assert.is_nil(height)
    end)

    it("sets and gets chain tip round-trip", function()
      local test_hash = types.hash256(string.rep("\xab", 32))
      local test_height = 12345

      db.set_chain_tip(test_hash, test_height)

      local hash, height = db.get_chain_tip()
      assert.is_not_nil(hash)
      assert.is_true(types.hash256_eq(test_hash, hash))
      assert.equal(test_height, height)
    end)

    it("handles height zero", function()
      local genesis_hash = types.hash256(string.rep("\x00", 32))
      db.set_chain_tip(genesis_hash, 0)

      local hash, height = db.get_chain_tip()
      assert.is_true(types.hash256_eq(genesis_hash, hash))
      assert.equal(0, height)
    end)

    it("handles large height values", function()
      local test_hash = types.hash256(string.rep("\xff", 32))
      local large_height = 850000

      db.set_chain_tip(test_hash, large_height)

      local hash, height = db.get_chain_tip()
      assert.is_true(types.hash256_eq(test_hash, hash))
      assert.equal(large_height, height)
    end)
  end)

  describe("header storage", function()
    local db, path

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("returns nil for non-existent header", function()
      local hash = types.hash256(string.rep("\x99", 32))
      local header = db.get_header(hash)
      assert.is_nil(header)
    end)

    it("puts and gets header round-trip", function()
      local prev = types.hash256(string.rep("\x01", 32))
      local merkle = types.hash256(string.rep("\x02", 32))
      local header = types.block_header(1, prev, merkle, 1231006505, 0x1d00ffff, 2083236893)

      local block_hash = types.hash256(string.rep("\xab", 32))
      db.put_header(block_hash, header)

      local retrieved = db.get_header(block_hash)
      assert.is_not_nil(retrieved)
      assert.equal(header.version, retrieved.version)
      assert.is_true(types.hash256_eq(header.prev_hash, retrieved.prev_hash))
      assert.is_true(types.hash256_eq(header.merkle_root, retrieved.merkle_root))
      assert.equal(header.timestamp, retrieved.timestamp)
      assert.equal(header.bits, retrieved.bits)
      assert.equal(header.nonce, retrieved.nonce)
    end)

    it("handles genesis block header", function()
      local prev = types.hash256_zero()
      local merkle = types.hash256_from_hex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
      local genesis_header = types.block_header(1, prev, merkle, 1231006505, 0x1d00ffff, 2083236893)

      local genesis_hash = types.hash256_from_hex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
      db.put_header(genesis_hash, genesis_header)

      local retrieved = db.get_header(genesis_hash)
      assert.is_not_nil(retrieved)
      assert.equal(1, retrieved.version)
      assert.is_true(types.hash256_eq(types.hash256_zero(), retrieved.prev_hash))
    end)
  end)

  describe("height index", function()
    local db, path

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("returns nil for non-existent height", function()
      local hash = db.get_hash_by_height(999999)
      assert.is_nil(hash)
    end)

    it("puts and gets height index round-trip", function()
      local test_hash = types.hash256(string.rep("\xcd", 32))
      db.put_height_index(12345, test_hash)

      local retrieved = db.get_hash_by_height(12345)
      assert.is_not_nil(retrieved)
      assert.is_true(types.hash256_eq(test_hash, retrieved))
    end)

    it("handles height zero", function()
      local genesis_hash = types.hash256(string.rep("\x00", 32))
      db.put_height_index(0, genesis_hash)

      local retrieved = db.get_hash_by_height(0)
      assert.is_true(types.hash256_eq(genesis_hash, retrieved))
    end)

    it("maintains ordering with big-endian encoding", function()
      -- Insert heights out of order
      local hash1 = types.hash256(string.rep("\x01", 32))
      local hash2 = types.hash256(string.rep("\x02", 32))
      local hash3 = types.hash256(string.rep("\x03", 32))

      db.put_height_index(1000, hash2)
      db.put_height_index(100, hash1)
      db.put_height_index(10000, hash3)

      -- Use iterator to verify ordering
      local iter = db.iterator(storage.CF.HEIGHT_INDEX)
      local heights = {}

      iter.seek_to_first()
      while iter.valid() do
        local key = iter.key()
        local b1, b2, b3, b4 = key:byte(1, 4)
        local height = b1 * 16777216 + b2 * 65536 + b3 * 256 + b4
        heights[#heights + 1] = height
        iter.next()
      end
      iter.destroy()

      assert.equal(3, #heights)
      assert.equal(100, heights[1])
      assert.equal(1000, heights[2])
      assert.equal(10000, heights[3])
    end)
  end)

  describe("persistence", function()
    it("reopens existing database and verifies data persists", function()
      local path = make_temp_dir()

      -- Open, write data, close
      local db = storage.open(path, 16)
      db.put(storage.CF.DEFAULT, "persist_key", "persist_value")

      local test_hash = types.hash256(string.rep("\xef", 32))
      db.set_chain_tip(test_hash, 54321)

      local prev = types.hash256(string.rep("\x11", 32))
      local merkle = types.hash256(string.rep("\x22", 32))
      local header = types.block_header(2, prev, merkle, 1600000000, 0x1a00ffff, 99999)
      local header_hash = types.hash256(string.rep("\x33", 32))
      db.put_header(header_hash, header)

      db.put_height_index(100, header_hash)

      db.close()

      -- Reopen and verify
      local db2 = storage.open(path, 16)

      -- Verify default cf data
      assert.equal("persist_value", db2.get(storage.CF.DEFAULT, "persist_key"))

      -- Verify chain tip
      local hash, height = db2.get_chain_tip()
      assert.is_true(types.hash256_eq(test_hash, hash))
      assert.equal(54321, height)

      -- Verify header
      local retrieved_header = db2.get_header(header_hash)
      assert.is_not_nil(retrieved_header)
      assert.equal(2, retrieved_header.version)
      assert.equal(1600000000, retrieved_header.timestamp)

      -- Verify height index
      local retrieved_hash = db2.get_hash_by_height(100)
      assert.is_true(types.hash256_eq(header_hash, retrieved_hash))

      db2.close()
      remove_dir(path)
    end)
  end)
end)
