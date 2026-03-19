describe("sig_cache", function()
  local sig_cache

  setup(function()
    package.path = "src/?.lua;" .. package.path
    sig_cache = require("sig_cache")
  end)

  describe("new", function()
    it("creates a cache with default max entries", function()
      local cache = sig_cache.new()
      assert.equal(50000, cache.max_entries)
      assert.equal(0, cache.count)
    end)

    it("creates a cache with custom max entries", function()
      local cache = sig_cache.new(1000)
      assert.equal(1000, cache.max_entries)
    end)
  end)

  describe("make_key", function()
    it("creates deterministic keys from txid, input_index, and flags", function()
      local cache = sig_cache.new()
      local txid = string.rep("\x01", 32)
      local key1 = cache:make_key(txid, 0, 31)
      local key2 = cache:make_key(txid, 0, 31)
      local key3 = cache:make_key(txid, 1, 31)

      assert.equal(key1, key2)
      assert.are_not.equal(key1, key3)
    end)

    it("includes flags in key", function()
      local cache = sig_cache.new()
      local txid = string.rep("\x02", 32)
      local key1 = cache:make_key(txid, 0, 16)
      local key2 = cache:make_key(txid, 0, 31)

      assert.are_not.equal(key1, key2)
    end)
  end)

  describe("insert and lookup", function()
    it("returns false for uncached entry", function()
      local cache = sig_cache.new()
      local txid = string.rep("\xab", 32)

      assert.is_false(cache:lookup(txid, 0, 31))
    end)

    it("returns true after insert", function()
      local cache = sig_cache.new()
      local txid = string.rep("\xcd", 32)

      cache:insert(txid, 0, 31)
      assert.is_true(cache:lookup(txid, 0, 31))
    end)

    it("distinguishes different inputs", function()
      local cache = sig_cache.new()
      local txid = string.rep("\xef", 32)

      cache:insert(txid, 0, 31)
      assert.is_true(cache:lookup(txid, 0, 31))
      assert.is_false(cache:lookup(txid, 1, 31))
      assert.is_false(cache:lookup(txid, 0, 16))
    end)

    it("tracks count correctly", function()
      local cache = sig_cache.new()
      local txid1 = string.rep("\x11", 32)
      local txid2 = string.rep("\x22", 32)

      assert.equal(0, cache:size())

      cache:insert(txid1, 0, 31)
      assert.equal(1, cache:size())

      cache:insert(txid2, 0, 31)
      assert.equal(2, cache:size())

      -- Duplicate insert should not increase count
      cache:insert(txid1, 0, 31)
      assert.equal(2, cache:size())
    end)
  end)

  describe("eviction", function()
    it("evicts old entries when at capacity", function()
      local cache = sig_cache.new(3)

      for i = 1, 5 do
        local txid = string.rep(string.char(i), 32)
        cache:insert(txid, 0, 31)
      end

      -- Should have evicted 2 entries to make room
      assert.equal(3, cache:size())
    end)

    it("maintains capacity limit", function()
      local cache = sig_cache.new(10)

      for i = 1, 100 do
        local txid = string.rep(string.char(i % 256), 32) .. string.char(math.floor(i / 256))
        -- Make keys unique by including index in txid
        local unique_txid = string.format("%032d", i)
        cache:insert(unique_txid, 0, 31)
      end

      assert.is_true(cache:size() <= 10)
    end)
  end)

  describe("clear", function()
    it("removes all entries", function()
      local cache = sig_cache.new()
      local txid1 = string.rep("\xaa", 32)
      local txid2 = string.rep("\xbb", 32)

      cache:insert(txid1, 0, 31)
      cache:insert(txid2, 0, 31)
      assert.equal(2, cache:size())

      cache:clear()
      assert.equal(0, cache:size())
      assert.is_false(cache:lookup(txid1, 0, 31))
      assert.is_false(cache:lookup(txid2, 0, 31))
    end)
  end)
end)
