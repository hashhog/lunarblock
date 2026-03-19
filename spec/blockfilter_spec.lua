describe("blockfilter", function()
  local blockfilter, storage, types, crypto

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
    blockfilter = require("lunarblock.blockfilter")
    storage = require("lunarblock.storage")
    types = require("lunarblock.types")
    crypto = require("lunarblock.crypto")
  end)

  describe("bit_stream_writer and reader", function()
    it("writes and reads bits correctly", function()
      local writer = blockfilter.bit_stream_writer()
      writer.write(1, 1)      -- 1
      writer.write(0, 1)      -- 0
      writer.write(5, 3)      -- 101
      writer.write(15, 4)     -- 1111
      writer.flush()

      local data = writer.result()
      local reader = blockfilter.bit_stream_reader(data)

      assert.equal(1, reader.read(1))
      assert.equal(0, reader.read(1))
      assert.equal(5, reader.read(3))
      assert.equal(15, reader.read(4))
    end)

    it("handles byte boundaries", function()
      local writer = blockfilter.bit_stream_writer()
      writer.write(0xFF, 8)  -- full byte
      writer.write(0xAB, 8)  -- another byte
      writer.flush()

      local data = writer.result()
      assert.equal(2, #data)

      local reader = blockfilter.bit_stream_reader(data)
      assert.equal(0xFF, reader.read(8))
      assert.equal(0xAB, reader.read(8))
    end)

    it("handles partial bytes at end", function()
      local writer = blockfilter.bit_stream_writer()
      writer.write(1, 1)
      writer.write(1, 1)
      writer.write(1, 1)  -- 111 = 0xE0 when padded
      writer.flush()

      local data = writer.result()
      assert.equal(1, #data)
      assert.equal(0xE0, data:byte(1))
    end)
  end)

  describe("golomb_rice_encode and decode", function()
    it("encodes and decodes single values", function()
      local P = 19  -- BIP158 parameter

      -- Test several values
      local test_values = {0, 1, 10, 100, 1000, 10000, 100000, 524287}

      for _, val in ipairs(test_values) do
        local writer = blockfilter.bit_stream_writer()
        blockfilter.golomb_rice_encode(writer, P, val)
        writer.flush()

        local reader = blockfilter.bit_stream_reader(writer.result())
        local decoded = blockfilter.golomb_rice_decode(reader, P)
        assert.equal(val, decoded, "Failed for value " .. val)
      end
    end)

    it("encodes deltas in sequence", function()
      local P = 19
      local values = {100, 500, 1000, 50000}

      local writer = blockfilter.bit_stream_writer()
      local last = 0
      for _, val in ipairs(values) do
        blockfilter.golomb_rice_encode(writer, P, val - last)
        last = val
      end
      writer.flush()

      local reader = blockfilter.bit_stream_reader(writer.result())
      local decoded = {}
      last = 0
      for i = 1, #values do
        local delta = blockfilter.golomb_rice_decode(reader, P)
        last = last + delta
        decoded[i] = last
      end

      for i, val in ipairs(values) do
        assert.equal(val, decoded[i])
      end
    end)
  end)

  describe("build_gcs_filter", function()
    it("builds empty filter for no elements", function()
      local block_hash = types.hash256(string.rep("\xab", 32))
      local filter = blockfilter.build_gcs_filter({}, block_hash)

      assert.equal(1, #filter)  -- just the varint count (0)
      assert.equal(0, filter:byte(1))
    end)

    it("builds filter with single element", function()
      local block_hash = types.hash256(string.rep("\xcd", 32))
      local elements = {"test_script"}
      local filter = blockfilter.build_gcs_filter(elements, block_hash)

      assert.is_true(#filter > 1)
      -- First byte is count (1)
      assert.equal(1, filter:byte(1))
    end)

    it("builds filter with multiple elements", function()
      local block_hash = types.hash256(string.rep("\xef", 32))
      local elements = {
        "\x76\xa9" .. string.rep("\x00", 20) .. "\x88\xac",
        "\xa9\x14" .. string.rep("\x11", 20) .. "\x87",
        "\x00\x14" .. string.rep("\x22", 20),
      }
      local filter = blockfilter.build_gcs_filter(elements, block_hash)

      assert.is_true(#filter > 1)
      assert.equal(3, filter:byte(1))  -- count
    end)
  end)

  describe("match_gcs_filter", function()
    it("matches existing element", function()
      local block_hash = types.hash256(string.rep("\x12", 32))
      local elements = {
        "element_one",
        "element_two",
        "element_three",
      }
      local filter = blockfilter.build_gcs_filter(elements, block_hash)

      assert.is_true(blockfilter.match_gcs_filter(filter, "element_two", block_hash))
    end)

    it("does not match non-existing element", function()
      local block_hash = types.hash256(string.rep("\x34", 32))
      local elements = {"alpha", "beta", "gamma"}
      local filter = blockfilter.build_gcs_filter(elements, block_hash)

      -- Note: false positives are possible, but should be rare
      -- We test that at least one clearly different element doesn't match
      local matched = false
      for i = 1, 100 do
        local test = "definitely_not_in_filter_" .. i
        if blockfilter.match_gcs_filter(filter, test, block_hash) then
          matched = true
          break
        end
      end
      -- With M=784931, false positive rate is ~1/784931, so 100 tests should not match
      assert.is_false(matched)
    end)

    it("returns false for empty filter", function()
      local block_hash = types.hash256(string.rep("\x56", 32))
      local filter = blockfilter.build_gcs_filter({}, block_hash)

      assert.is_false(blockfilter.match_gcs_filter(filter, "anything", block_hash))
    end)
  end)

  describe("match_any_gcs_filter", function()
    it("matches when any element exists", function()
      local block_hash = types.hash256(string.rep("\x78", 32))
      local elements = {"one", "two", "three"}
      local filter = blockfilter.build_gcs_filter(elements, block_hash)

      assert.is_true(blockfilter.match_any_gcs_filter(filter, {"zero", "two", "four"}, block_hash))
    end)

    it("returns false when no elements match", function()
      local block_hash = types.hash256(string.rep("\x9a", 32))
      local elements = {"alpha", "beta"}
      local filter = blockfilter.build_gcs_filter(elements, block_hash)

      assert.is_false(blockfilter.match_any_gcs_filter(filter, {"gamma", "delta"}, block_hash))
    end)
  end)

  describe("filter hash and header", function()
    it("computes filter hash", function()
      local filter_data = "\x01\x00"  -- simple filter
      local hash = blockfilter.compute_filter_hash(filter_data)

      assert.is_not_nil(hash)
      assert.equal(32, #hash.bytes)
    end)

    it("computes filter header chain", function()
      local filter1 = blockfilter.build_gcs_filter({"a"}, types.hash256(string.rep("\x01", 32)))
      local filter2 = blockfilter.build_gcs_filter({"b"}, types.hash256(string.rep("\x02", 32)))

      local hash1 = blockfilter.compute_filter_hash(filter1)
      local hash2 = blockfilter.compute_filter_hash(filter2)

      -- Genesis filter header
      local header0 = types.hash256_zero()
      local header1 = blockfilter.compute_filter_header(hash1, header0)
      local header2 = blockfilter.compute_filter_header(hash2, header1)

      -- Headers should be different
      assert.is_false(types.hash256_eq(header1, header0))
      assert.is_false(types.hash256_eq(header2, header1))

      -- Headers should be deterministic
      local header1_again = blockfilter.compute_filter_header(hash1, header0)
      assert.is_true(types.hash256_eq(header1, header1_again))
    end)
  end)

  describe("extract_basic_filter_elements", function()
    it("extracts output scripts", function()
      local prev = types.hash256_zero()
      local merkle = types.hash256(string.rep("\x01", 32))
      local header = types.block_header(1, prev, merkle, 1600000000, 0x1d00ffff, 0)

      -- P2PKH script
      local script1 = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"
      -- P2SH script
      local script2 = "\xa9\x14" .. string.rep("\x11", 20) .. "\x87"

      local tx = types.transaction(1, {
        types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), "\x00", 0xFFFFFFFF)
      }, {
        types.txout(100000000, script1),
        types.txout(50000000, script2),
      }, 0)

      local block = types.block(header, {tx})
      local elements = blockfilter.extract_basic_filter_elements(block, nil)

      assert.equal(2, #elements)
      assert.equal(script1, elements[1])
      assert.equal(script2, elements[2])
    end)

    it("excludes OP_RETURN outputs", function()
      local prev = types.hash256_zero()
      local merkle = types.hash256(string.rep("\x02", 32))
      local header = types.block_header(1, prev, merkle, 1600000000, 0x1d00ffff, 0)

      local script_normal = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"
      local script_op_return = "\x6a\x14" .. string.rep("\xab", 20)  -- OP_RETURN

      local tx = types.transaction(1, {
        types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), "\x00", 0xFFFFFFFF)
      }, {
        types.txout(100000000, script_normal),
        types.txout(0, script_op_return),
      }, 0)

      local block = types.block(header, {tx})
      local elements = blockfilter.extract_basic_filter_elements(block, nil)

      assert.equal(1, #elements)
      assert.equal(script_normal, elements[1])
    end)

    it("includes spent scripts from undo data", function()
      local prev = types.hash256_zero()
      local merkle = types.hash256(string.rep("\x03", 32))
      local header = types.block_header(1, prev, merkle, 1600000000, 0x1d00ffff, 0)

      local output_script = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"
      local spent_script = "\x00\x14" .. string.rep("\x22", 20)

      local tx = types.transaction(1, {
        types.txin(types.outpoint(types.hash256(string.rep("\xaa", 32)), 0), "\x00", 0xFFFFFFFF)
      }, {
        types.txout(100000000, output_script),
      }, 0)

      local block = types.block(header, {tx})
      local undo_data = {{script_pubkey = spent_script}}

      local elements = blockfilter.extract_basic_filter_elements(block, undo_data)

      -- Should have both output and spent scripts
      assert.equal(2, #elements)
    end)

    it("deduplicates identical scripts", function()
      local prev = types.hash256_zero()
      local merkle = types.hash256(string.rep("\x04", 32))
      local header = types.block_header(1, prev, merkle, 1600000000, 0x1d00ffff, 0)

      local script = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"

      local tx = types.transaction(1, {
        types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), "\x00", 0xFFFFFFFF)
      }, {
        types.txout(100000000, script),
        types.txout(50000000, script),  -- same script
      }, 0)

      local block = types.block(header, {tx})
      local elements = blockfilter.extract_basic_filter_elements(block, nil)

      assert.equal(1, #elements)  -- deduplicated
    end)
  end)

  describe("block filter index", function()
    local db, path, idx

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
      idx = blockfilter.new_index(db, true)
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("reports enabled state", function()
      assert.is_true(idx.is_enabled())
      idx.set_enabled(false)
      assert.is_false(idx.is_enabled())
    end)

    it("starts with no indexed height", function()
      assert.equal(-1, idx.get_best_height())
    end)

    it("stores and retrieves best height", function()
      idx.set_best_height(54321)
      assert.equal(54321, idx.get_best_height())
    end)

    it("starts with zero last header", function()
      local header = idx.get_last_header()
      assert.is_true(types.hash256_eq(types.hash256_zero(), header))
    end)

    it("stores and retrieves filter", function()
      local block_hash = types.hash256(string.rep("\xab", 32))
      local filter_data = "\x02\x12\x34"
      local filter_hash = types.hash256(string.rep("\xcd", 32))
      local filter_header = types.hash256(string.rep("\xef", 32))

      idx.put_filter(block_hash, 100, filter_data, filter_hash, filter_header)

      local result = idx.get_filter(block_hash)
      assert.is_not_nil(result)
      assert.equal(filter_data, result.filter)
      assert.is_true(types.hash256_eq(filter_hash, result.filter_hash))
      assert.is_true(types.hash256_eq(filter_header, result.filter_header))
    end)

    it("retrieves filter by height", function()
      local block_hash = types.hash256(string.rep("\x11", 32))
      local filter_data = "\x01\x00"
      local filter_hash = types.hash256(string.rep("\x22", 32))
      local filter_header = types.hash256(string.rep("\x33", 32))

      idx.put_filter(block_hash, 500, filter_data, filter_hash, filter_header)

      local result = idx.get_filter_by_height(500)
      assert.is_not_nil(result)
      assert.equal(filter_data, result.filter)
    end)

    it("returns nil for non-existent filter", function()
      local block_hash = types.hash256(string.rep("\x99", 32))
      local result = idx.get_filter(block_hash)
      assert.is_nil(result)
    end)

    it("deletes filter", function()
      local block_hash = types.hash256(string.rep("\x44", 32))
      local filter_data = "\x01\x00"
      local filter_hash = types.hash256(string.rep("\x55", 32))
      local filter_header = types.hash256(string.rep("\x66", 32))

      idx.put_filter(block_hash, 200, filter_data, filter_hash, filter_header)
      assert.is_not_nil(idx.get_filter(block_hash))

      idx.delete_filter(block_hash, 200)
      assert.is_nil(idx.get_filter(block_hash))
      assert.is_nil(idx.get_filter_by_height(200))
    end)
  end)

  describe("connect_block and disconnect_block", function()
    local db, path, idx

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
      idx = blockfilter.new_index(db, true)
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("connects block and builds filter", function()
      local prev = types.hash256_zero()
      local merkle = types.hash256(string.rep("\x01", 32))
      local header = types.block_header(1, prev, merkle, 1600000000, 0x1d00ffff, 0)

      local script = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"
      local tx = types.transaction(1, {
        types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), "\x00", 0xFFFFFFFF)
      }, {
        types.txout(100000000, script),
      }, 0)

      local block = types.block(header, {tx})
      local block_hash = types.hash256(string.rep("\xab", 32))

      idx.connect_block(block, block_hash, 1, nil)

      -- Check filter was stored
      local result = idx.get_filter(block_hash)
      assert.is_not_nil(result)
      assert.is_not_nil(result.filter)
      assert.is_not_nil(result.filter_hash)
      assert.is_not_nil(result.filter_header)

      -- Check height was updated
      assert.equal(1, idx.get_best_height())

      -- Check last header was updated
      local last_header = idx.get_last_header()
      assert.is_false(types.hash256_eq(types.hash256_zero(), last_header))
    end)

    it("disconnects block and removes filter", function()
      -- Connect two blocks
      local script = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"

      for height = 1, 2 do
        local prev = types.hash256(string.rep(string.char(height), 32))
        local merkle = types.hash256(string.rep(string.char(height + 1), 32))
        local header = types.block_header(1, prev, merkle, 1600000000, 0x1d00ffff, 0)
        local tx = types.transaction(1, {
          types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), "\x00", 0xFFFFFFFF)
        }, {
          types.txout(100000000, script),
        }, 0)
        local block = types.block(header, {tx})
        local block_hash = types.hash256(string.rep(string.char(height + 10), 32))
        idx.connect_block(block, block_hash, height, nil)
      end

      assert.equal(2, idx.get_best_height())

      -- Disconnect block 2
      local block_hash_2 = types.hash256(string.rep(string.char(12), 32))
      idx.disconnect_block(block_hash_2, 2)

      assert.equal(1, idx.get_best_height())
      assert.is_nil(idx.get_filter(block_hash_2))
    end)
  end)

  describe("get_stats", function()
    local db, path, idx

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
      idx = blockfilter.new_index(db, true)
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("returns correct stats", function()
      idx.set_best_height(1000)

      local stats = idx.get_stats()
      assert.is_true(stats.enabled)
      assert.is_false(stats.synced)
      assert.equal(1000, stats.best_height)
    end)
  end)
end)
