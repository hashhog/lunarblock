describe("txindex", function()
  local txindex, storage, types, serialize, validation

  -- Helper to create a unique temp directory
  local function make_temp_dir()
    local tmpname = os.tmpname()
    os.remove(tmpname)
    os.execute("mkdir -p " .. tmpname)
    return tmpname
  end

  local function remove_dir(path)
    os.execute("rm -rf " .. path)
  end

  setup(function()
    txindex = require("lunarblock.txindex")
    storage = require("lunarblock.storage")
    types = require("lunarblock.types")
    serialize = require("lunarblock.serialize")
    validation = require("lunarblock.validation")
  end)

  describe("serialize_tx_pos", function()
    it("serializes and deserializes tx position round-trip", function()
      local data = txindex.serialize_tx_pos(5, 12345, 999)
      assert.equal(12, #data)

      local pos = txindex.deserialize_tx_pos(data)
      assert.equal(5, pos.file_num)
      assert.equal(12345, pos.block_pos)
      assert.equal(999, pos.tx_offset)
    end)

    it("handles zero values", function()
      local data = txindex.serialize_tx_pos(0, 0, 0)
      local pos = txindex.deserialize_tx_pos(data)
      assert.equal(0, pos.file_num)
      assert.equal(0, pos.block_pos)
      assert.equal(0, pos.tx_offset)
    end)

    it("handles large values", function()
      local data = txindex.serialize_tx_pos(999, 0xFFFFFFFF, 0x7FFFFFFF)
      local pos = txindex.deserialize_tx_pos(data)
      assert.equal(999, pos.file_num)
      assert.equal(0xFFFFFFFF, pos.block_pos)
      assert.equal(0x7FFFFFFF, pos.tx_offset)
    end)

    it("returns nil for invalid data", function()
      assert.is_nil(txindex.deserialize_tx_pos(nil))
      assert.is_nil(txindex.deserialize_tx_pos("short"))
    end)
  end)

  describe("txindex instance", function()
    local db, path, idx

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
      idx = txindex.new(db, true)  -- enabled
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("reports enabled state correctly", function()
      assert.is_true(idx.is_enabled())
      idx.set_enabled(false)
      assert.is_false(idx.is_enabled())
    end)

    it("starts with no indexed height", function()
      assert.equal(-1, idx.get_best_height())
    end)

    it("stores and retrieves best height", function()
      idx.set_best_height(12345)
      assert.equal(12345, idx.get_best_height())
    end)

    it("puts and looks up transactions", function()
      local txid = types.hash256(string.rep("\xab", 32))
      idx.put_tx(txid, 3, 50000, 280)

      local pos = idx.lookup_tx(txid)
      assert.is_not_nil(pos)
      assert.equal(3, pos.file_num)
      assert.equal(50000, pos.block_pos)
      assert.equal(280, pos.tx_offset)
    end)

    it("returns nil for non-existent tx", function()
      local txid = types.hash256(string.rep("\xcd", 32))
      local pos = idx.lookup_tx(txid)
      assert.is_nil(pos)
    end)

    it("deletes transactions", function()
      local txid = types.hash256(string.rep("\xef", 32))
      idx.put_tx(txid, 1, 1000, 80)
      assert.is_not_nil(idx.lookup_tx(txid))

      idx.delete_tx(txid)
      assert.is_nil(idx.lookup_tx(txid))
    end)

    it("does nothing when disabled", function()
      idx.set_enabled(false)
      local txid = types.hash256(string.rep("\x11", 32))
      idx.put_tx(txid, 1, 1000, 80)

      local pos, err = idx.lookup_tx(txid)
      assert.is_nil(pos)
      assert.equal("txindex not enabled", err)
    end)
  end)

  describe("connect_block", function()
    local db, path, idx

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
      idx = txindex.new(db, true)
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("skips genesis block (height 0)", function()
      -- Create a mock genesis block
      local prev = types.hash256_zero()
      local merkle = types.hash256(string.rep("\x01", 32))
      local header = types.block_header(1, prev, merkle, 1231006505, 0x1d00ffff, 2083236893)

      local coinbase = types.transaction(1, {
        types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), "\x04\xff\xff\x00\x1d\x01\x04", 0xFFFFFFFF)
      }, {
        types.txout(5000000000, string.rep("\x00", 25))
      }, 0)

      local block = types.block(header, {coinbase})

      idx.connect_block(block, 0, 0, 8)
      assert.equal(0, idx.get_best_height())

      -- Genesis coinbase should not be indexed
      local txid = validation.compute_txid(coinbase)
      assert.is_nil(idx.lookup_tx(txid))
    end)

    it("indexes block transactions", function()
      -- Create a simple block at height 1
      local prev = types.hash256(string.rep("\x01", 32))
      local merkle = types.hash256(string.rep("\x02", 32))
      local header = types.block_header(1, prev, merkle, 1600000000, 0x1d00ffff, 12345)

      local tx1 = types.transaction(1, {
        types.txin(types.outpoint(types.hash256(string.rep("\xaa", 32)), 0), "\x00", 0xFFFFFFFF)
      }, {
        types.txout(100000000, "\x76\xa9" .. string.rep("\x00", 20) .. "\x88\xac")
      }, 0)

      local tx2 = types.transaction(1, {
        types.txin(types.outpoint(types.hash256(string.rep("\xbb", 32)), 1), "\x00", 0xFFFFFFFF)
      }, {
        types.txout(50000000, "\x76\xa9" .. string.rep("\x11", 20) .. "\x88\xac")
      }, 0)

      local block = types.block(header, {tx1, tx2})

      idx.connect_block(block, 1, 0, 100)

      -- Check height was updated
      assert.equal(1, idx.get_best_height())

      -- Check transactions are indexed
      local txid1 = validation.compute_txid(tx1)
      local txid2 = validation.compute_txid(tx2)

      local pos1 = idx.lookup_tx(txid1)
      local pos2 = idx.lookup_tx(txid2)

      assert.is_not_nil(pos1)
      assert.is_not_nil(pos2)
      assert.equal(0, pos1.file_num)
      assert.equal(100, pos1.block_pos)
      -- tx_offset should be > 0 (after header and tx count)
      assert.is_true(pos1.tx_offset > 80)
    end)
  end)

  describe("disconnect_block", function()
    local db, path, idx

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
      idx = txindex.new(db, true)
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("removes transactions and updates height", function()
      -- Create and connect a block
      local prev = types.hash256(string.rep("\x01", 32))
      local merkle = types.hash256(string.rep("\x02", 32))
      local header = types.block_header(1, prev, merkle, 1600000000, 0x1d00ffff, 12345)

      local tx1 = types.transaction(1, {
        types.txin(types.outpoint(types.hash256(string.rep("\xcc", 32)), 0), "\x00", 0xFFFFFFFF)
      }, {
        types.txout(100000000, "\x76\xa9" .. string.rep("\x00", 20) .. "\x88\xac")
      }, 0)

      local block = types.block(header, {tx1})
      idx.connect_block(block, 5, 0, 200)

      local txid = validation.compute_txid(tx1)
      assert.is_not_nil(idx.lookup_tx(txid))
      assert.equal(5, idx.get_best_height())

      -- Disconnect the block
      idx.disconnect_block(block, 5)

      -- Check tx is removed
      assert.is_nil(idx.lookup_tx(txid))
      -- Check height is decremented
      assert.equal(4, idx.get_best_height())
    end)
  end)

  describe("get_stats", function()
    local db, path, idx

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
      idx = txindex.new(db, true)
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("returns correct stats", function()
      idx.set_best_height(100)

      local stats = idx.get_stats()
      assert.is_true(stats.enabled)
      assert.is_false(stats.synced)
      assert.equal(100, stats.best_height)
    end)
  end)

  describe("build_async", function()
    local db, path, idx

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
      idx = txindex.new(db, true)
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("builds index using coroutines with progress", function()
      -- Create a mock block getter that returns simple blocks
      local blocks = {}
      for h = 1, 5 do
        local prev = types.hash256(string.rep(string.char(h), 32))
        local merkle = types.hash256(string.rep(string.char(h + 1), 32))
        local header = types.block_header(1, prev, merkle, 1600000000 + h, 0x1d00ffff, h)
        local tx = types.transaction(1, {
          types.txin(types.outpoint(types.hash256(string.rep(string.char(h + 10), 32)), 0), "\x00", 0xFFFFFFFF)
        }, {
          types.txout(100000000, "\x76\xa9" .. string.rep(string.char(h), 20) .. "\x88\xac")
        }, 0)
        blocks[h] = {types.block(header, {tx}), 0, h * 1000}
      end

      local function get_block(height)
        if blocks[height] then
          return blocks[height][1], blocks[height][2], blocks[height][3]
        end
        return nil
      end

      -- Build with yield every 2 blocks
      local coro = idx.build_async(get_block, 5, 2)

      local results = {}
      while coroutine.status(coro) ~= "dead" do
        local ok, result = coroutine.resume(coro)
        if ok and result then
          results[#results + 1] = result
        end
      end

      -- Should have progress at heights 2, 4 and complete
      assert.is_true(#results >= 1)
      assert.equal("complete", results[#results].type)
      assert.equal(5, results[#results].indexed_height)

      -- Verify index state
      assert.equal(5, idx.get_best_height())
      assert.is_true(idx.is_synced())
    end)
  end)
end)
