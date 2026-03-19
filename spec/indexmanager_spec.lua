describe("indexmanager", function()
  local indexmanager, storage, types

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
    indexmanager = require("lunarblock.indexmanager")
    storage = require("lunarblock.storage")
    types = require("lunarblock.types")
  end)

  describe("new", function()
    local db, path

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("creates manager with default disabled indexes", function()
      local manager = indexmanager.new(db, {})

      local txidx = manager.get_txindex()
      local filteridx = manager.get_filterindex()

      assert.is_false(txidx.is_enabled())
      assert.is_false(filteridx.is_enabled())
    end)

    it("creates manager with enabled indexes", function()
      local manager = indexmanager.new(db, {txindex = true, blockfilterindex = true})

      assert.is_true(manager.get_txindex().is_enabled())
      assert.is_true(manager.get_filterindex().is_enabled())
    end)

    it("can toggle index states", function()
      local manager = indexmanager.new(db, {txindex = false})

      manager.set_txindex_enabled(true)
      assert.is_true(manager.get_txindex().is_enabled())

      manager.set_txindex_enabled(false)
      assert.is_false(manager.get_txindex().is_enabled())
    end)
  end)

  describe("connect_block and disconnect_block", function()
    local db, path, manager

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
      manager = indexmanager.new(db, {txindex = true, blockfilterindex = true})
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("connects block to both indexes", function()
      local prev = types.hash256_zero()
      local merkle = types.hash256(string.rep("\x01", 32))
      local header = types.block_header(1, prev, merkle, 1600000000, 0x1d00ffff, 0)

      local script = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"
      local tx = types.transaction(1, {
        types.txin(types.outpoint(types.hash256(string.rep("\xaa", 32)), 0), "\x00", 0xFFFFFFFF)
      }, {
        types.txout(100000000, script),
      }, 0)

      local block = types.block(header, {tx})
      local block_hash = types.hash256(string.rep("\xab", 32))

      manager.connect_block(block, block_hash, 1, 0, 100, nil)

      -- Check txindex
      assert.equal(1, manager.get_txindex().get_best_height())

      -- Check filter index
      assert.equal(1, manager.get_filterindex().get_best_height())
      assert.is_not_nil(manager.get_filter(block_hash))
    end)

    it("disconnects block from both indexes", function()
      local prev = types.hash256_zero()
      local merkle = types.hash256(string.rep("\x01", 32))
      local header = types.block_header(1, prev, merkle, 1600000000, 0x1d00ffff, 0)

      local script = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"
      local tx = types.transaction(1, {
        types.txin(types.outpoint(types.hash256(string.rep("\xaa", 32)), 0), "\x00", 0xFFFFFFFF)
      }, {
        types.txout(100000000, script),
      }, 0)

      local block = types.block(header, {tx})
      local block_hash = types.hash256(string.rep("\xab", 32))

      manager.connect_block(block, block_hash, 1, 0, 100, nil)
      manager.disconnect_block(block, block_hash, 1)

      assert.equal(0, manager.get_txindex().get_best_height())
      assert.equal(0, manager.get_filterindex().get_best_height())
    end)
  end)

  describe("is_building and tick", function()
    local db, path, manager

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
      manager = indexmanager.new(db, {txindex = true})
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("reports not building initially", function()
      assert.is_false(manager.is_building())
    end)

    it("builds indexes using tick", function()
      -- Create mock blocks
      local blocks = {}
      for h = 1, 3 do
        local prev = types.hash256(string.rep(string.char(h), 32))
        local merkle = types.hash256(string.rep(string.char(h + 1), 32))
        local header = types.block_header(1, prev, merkle, 1600000000, 0x1d00ffff, 0)
        local tx = types.transaction(1, {
          types.txin(types.outpoint(types.hash256(string.rep(string.char(h + 10), 32)), 0), "\x00", 0xFFFFFFFF)
        }, {
          types.txout(100000000, "\x76\xa9\x14" .. string.rep(string.char(h), 20) .. "\x88\xac"),
        }, 0)
        blocks[h] = types.block(header, {tx})
      end

      local function get_block(height)
        return blocks[height], 0, height * 1000
      end

      manager.start_building(get_block, 3, 1)
      assert.is_true(manager.is_building())

      -- Tick until complete
      local iterations = 0
      while manager.is_building() and iterations < 100 do
        manager.tick()
        iterations = iterations + 1
      end

      assert.is_false(manager.is_building())
      assert.equal(3, manager.get_txindex().get_best_height())
    end)
  end)

  describe("get_stats", function()
    local db, path

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("returns comprehensive stats", function()
      local manager = indexmanager.new(db, {txindex = true, blockfilterindex = true})

      local stats = manager.get_stats()

      assert.is_not_nil(stats.txindex)
      assert.is_not_nil(stats.filterindex)
      assert.is_true(stats.txindex.enabled)
      assert.is_true(stats.filterindex.enabled)
      assert.is_false(stats.building)
    end)
  end)

  describe("lookup functions", function()
    local db, path, manager

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
      manager = indexmanager.new(db, {txindex = true, blockfilterindex = true})
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("looks up transaction by txid", function()
      -- Add a transaction to the index directly
      local txidx = manager.get_txindex()
      local txid = types.hash256(string.rep("\xab", 32))
      txidx.put_tx(txid, 3, 50000, 280)

      local pos = manager.lookup_tx(txid)
      assert.is_not_nil(pos)
      assert.equal(3, pos.file_num)
    end)

    it("gets filter by hash", function()
      -- Add a filter directly
      local filteridx = manager.get_filterindex()
      local block_hash = types.hash256(string.rep("\xcd", 32))
      local filter_data = "\x01\x00"
      local filter_hash = types.hash256(string.rep("\xef", 32))
      local filter_header = types.hash256(string.rep("\x11", 32))

      filteridx.put_filter(block_hash, 100, filter_data, filter_hash, filter_header)

      local result = manager.get_filter(block_hash)
      assert.is_not_nil(result)
      assert.equal(filter_data, result.filter)
    end)

    it("gets filter by height", function()
      local filteridx = manager.get_filterindex()
      local block_hash = types.hash256(string.rep("\x22", 32))
      local filter_data = "\x02\x12\x34"
      local filter_hash = types.hash256(string.rep("\x33", 32))
      local filter_header = types.hash256(string.rep("\x44", 32))

      filteridx.put_filter(block_hash, 500, filter_data, filter_hash, filter_header)

      local result = manager.get_filter_by_height(500)
      assert.is_not_nil(result)
      assert.equal(filter_data, result.filter)
    end)
  end)
end)
