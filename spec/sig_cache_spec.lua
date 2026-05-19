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

  describe("W160 BUG-9: wtxid-vs-txid key separation", function()
    -- SegWit malleability defense: two transactions that share the same
    -- non-witness txid but differ in their witness (and therefore their
    -- wtxid) MUST produce distinct cache keys. If they collided, a
    -- cache HIT on a malleated witness would skip verification and
    -- admit an invalid signature. Mirrors Core's SignatureCacheHasher
    -- (sigcache.cpp:39-50) which keys on wtxid.
    it("two SegWit txs sharing txid but distinct wtxids produce distinct keys", function()
      local cache = sig_cache.new()
      -- Same 32-byte txid, but different wtxids (e.g. a malleated witness
      -- gives the same txid but a different witness commitment).
      local wtxid_canonical = string.rep("\xaa", 32)
      local wtxid_malleated = string.rep("\xab", 32)
      -- Same input_index and flags — only the key bytes differ.
      local key_canonical = cache:make_key(wtxid_canonical, 0, 0xFFFF)
      local key_malleated = cache:make_key(wtxid_malleated, 0, 0xFFFF)
      assert.are_not.equal(key_canonical, key_malleated)
      -- Insert canonical; malleated must NOT cache-hit.
      cache:insert(wtxid_canonical, 0, 0xFFFF)
      assert.is_true(cache:lookup(wtxid_canonical, 0, 0xFFFF))
      assert.is_false(cache:lookup(wtxid_malleated, 0, 0xFFFF))
    end)

    -- Cache-flags width: two distinct script-verify flag sets must produce
    -- distinct cache keys. A high-S signature accepted under flags-without-
    -- LOW_S must NOT cache-hit a later lookup with LOW_S enforced.
    it("differing flag bits (low_s on/off) produce distinct keys", function()
      local cache = sig_cache.new()
      local wtxid = string.rep("\xcd", 32)
      -- flags=0xFF (mandatory bits set) vs 0xFF + LOW_S bit (128)
      local key_lax    = cache:make_key(wtxid, 0, 0xFF)
      local key_strict = cache:make_key(wtxid, 0, 0xFF + 128)
      assert.are_not.equal(key_lax, key_strict)
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
