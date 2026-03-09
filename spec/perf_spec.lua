-- Performance utilities tests
local perf = require("lunarblock.perf")
local ffi = require("ffi")

describe("perf", function()
  describe("buffer pool", function()
    it("acquire and release cycle returns same buffer", function()
      -- Acquire a buffer
      local buf1 = perf.acquire_buffer()
      assert.is_not_nil(buf1)
      assert.is_not_nil(buf1.buf)
      assert.equals(4096, buf1.size)
      assert.is_true(buf1.in_use)

      -- Release it
      perf.release_buffer(buf1)
      assert.is_false(buf1.in_use)

      -- Acquire again should return the same buffer
      local buf2 = perf.acquire_buffer()
      assert.equals(buf1, buf2)

      -- Cleanup
      perf.release_buffer(buf2)
    end)

    it("exhaustion falls back to ephemeral allocation", function()
      -- Acquire all pooled buffers
      local buffers = {}
      local stats = perf.pool_stats()
      for i = 1, stats.total do
        buffers[i] = perf.acquire_buffer()
        assert.is_true(buffers[i].in_use)
      end

      -- Next allocation should be ephemeral
      local ephemeral = perf.acquire_buffer()
      assert.is_not_nil(ephemeral)
      assert.is_true(ephemeral.ephemeral)
      assert.is_true(ephemeral.in_use)

      -- Release ephemeral - should not affect in_use since it's ephemeral
      perf.release_buffer(ephemeral)
      assert.is_true(ephemeral.in_use)  -- ephemeral buffers stay marked in_use

      -- Release pooled buffers
      for i = 1, #buffers do
        perf.release_buffer(buffers[i])
      end
    end)

    it("respects min_size parameter", function()
      local buf = perf.acquire_buffer(8192)
      assert.is_not_nil(buf)
      assert.is_true(buf.size >= 8192)
      perf.release_buffer(buf)
    end)

    it("pool_stats returns correct counts", function()
      local stats1 = perf.pool_stats()
      assert.equals(16, stats1.total)
      local initial_available = stats1.available

      local buf = perf.acquire_buffer()
      local stats2 = perf.pool_stats()
      assert.equals(initial_available - 1, stats2.available)
      assert.equals(stats1.in_use + 1, stats2.in_use)

      perf.release_buffer(buf)
    end)
  end)

  describe("table pre-allocation", function()
    it("new_tx_list creates table", function()
      local t = perf.new_tx_list(100)
      assert.is_table(t)
      -- Can add elements
      for i = 1, 100 do
        t[i] = i
      end
      assert.equals(100, #t)
    end)

    it("new_hash_map creates table", function()
      local t = perf.new_hash_map(100)
      assert.is_table(t)
      -- Can add elements
      for i = 1, 100 do
        t["key" .. i] = i
      end
      -- Hash maps don't have length, just verify we can iterate
      local count = 0
      for _ in pairs(t) do count = count + 1 end
      assert.equals(100, count)
    end)

    it("new_table creates table with both parts", function()
      local t = perf.new_table(50, 50)
      assert.is_table(t)
      -- Add array elements
      for i = 1, 50 do
        t[i] = i
      end
      -- Add hash elements
      for i = 1, 50 do
        t["key" .. i] = i
      end
      assert.equals(50, #t)
    end)
  end)

  describe("serialize buffer", function()
    it("put_u32_le encodes correctly", function()
      local buf = perf.new_serialize_buffer()

      -- Test value 0x12345678
      perf.put_u32_le(buf, 0x12345678)
      local result = buf:get()

      assert.equals(4, #result)
      assert.equals(0x78, result:byte(1))
      assert.equals(0x56, result:byte(2))
      assert.equals(0x34, result:byte(3))
      assert.equals(0x12, result:byte(4))
    end)

    it("put_u32_le handles zero", function()
      local buf = perf.new_serialize_buffer()
      perf.put_u32_le(buf, 0)
      local result = buf:get()
      assert.equals(4, #result)
      assert.equals(0, result:byte(1))
      assert.equals(0, result:byte(2))
      assert.equals(0, result:byte(3))
      assert.equals(0, result:byte(4))
    end)

    it("put_u32_le handles max value", function()
      local buf = perf.new_serialize_buffer()
      perf.put_u32_le(buf, 0xFFFFFFFF)
      local result = buf:get()
      assert.equals(4, #result)
      assert.equals(0xFF, result:byte(1))
      assert.equals(0xFF, result:byte(2))
      assert.equals(0xFF, result:byte(3))
      assert.equals(0xFF, result:byte(4))
    end)

    it("put_u64_le encodes correctly", function()
      local buf = perf.new_serialize_buffer()

      -- Test value 0x123456789ABCDEF0
      -- This is within double precision range (< 2^53)
      local val = 0x123456789ABCDEF0ULL
      perf.put_u64_le(buf, tonumber(val))
      local result = buf:get()

      assert.equals(8, #result)
      -- Low bytes first (little endian)
      assert.equals(0xF0, result:byte(1))
      assert.equals(0xDE, result:byte(2))
      assert.equals(0xBC, result:byte(3))
      assert.equals(0x9A, result:byte(4))
      assert.equals(0x78, result:byte(5))
      assert.equals(0x56, result:byte(6))
      assert.equals(0x34, result:byte(7))
      assert.equals(0x12, result:byte(8))
    end)

    it("put_u64_le handles small values", function()
      local buf = perf.new_serialize_buffer()
      perf.put_u64_le(buf, 1000000)
      local result = buf:get()
      assert.equals(8, #result)
      -- 1000000 = 0x000F4240
      assert.equals(0x40, result:byte(1))
      assert.equals(0x42, result:byte(2))
      assert.equals(0x0F, result:byte(3))
      assert.equals(0x00, result:byte(4))
      assert.equals(0x00, result:byte(5))
      assert.equals(0x00, result:byte(6))
      assert.equals(0x00, result:byte(7))
      assert.equals(0x00, result:byte(8))
    end)

    it("put_varint encodes single byte", function()
      local buf = perf.new_serialize_buffer()
      perf.put_varint(buf, 100)
      local result = buf:get()
      assert.equals(1, #result)
      assert.equals(100, result:byte(1))
    end)

    it("put_varint encodes two bytes", function()
      local buf = perf.new_serialize_buffer()
      perf.put_varint(buf, 0x1234)
      local result = buf:get()
      assert.equals(3, #result)
      assert.equals(0xFD, result:byte(1))
      assert.equals(0x34, result:byte(2))
      assert.equals(0x12, result:byte(3))
    end)

    it("buffer reset works", function()
      local buf = perf.new_serialize_buffer()
      buf:put("hello")
      assert.equals("hello", buf:get())
      buf:reset()
      buf:put("world")
      assert.equals("world", buf:get())
    end)
  end)

  describe("FFI copy utilities", function()
    it("copy_to_ffi copies string to buffer", function()
      local buf = ffi.new("uint8_t[10]")
      perf.copy_to_ffi(buf, "hello", 5)
      assert.equals(string.byte("h"), buf[0])
      assert.equals(string.byte("e"), buf[1])
      assert.equals(string.byte("l"), buf[2])
      assert.equals(string.byte("l"), buf[3])
      assert.equals(string.byte("o"), buf[4])
    end)

    it("copy_from_ffi copies buffer to string", function()
      local buf = ffi.new("uint8_t[5]")
      buf[0] = string.byte("h")
      buf[1] = string.byte("i")
      local result = perf.copy_from_ffi(buf, 2)
      assert.equals("hi", result)
    end)

    it("fill_ffi fills buffer with value", function()
      local buf = ffi.new("uint8_t[5]")
      perf.fill_ffi(buf, 5, 0xAB)
      for i = 0, 4 do
        assert.equals(0xAB, buf[i])
      end
    end)
  end)
end)

describe("LRU cache", function()
  it("hit rate tracking works", function()
    local cache = perf.new_lru_cache(100)

    -- Initial state
    local stats = cache:stats()
    assert.equals(0, stats.hits)
    assert.equals(0, stats.misses)

    -- Miss
    cache:get("key1")
    stats = cache:stats()
    assert.equals(0, stats.hits)
    assert.equals(1, stats.misses)

    -- Put and then hit
    cache:put("key1", "value1")
    cache:get("key1")
    stats = cache:stats()
    assert.equals(1, stats.hits)
    assert.equals(1, stats.misses)
    assert.equals(0.5, stats.hit_rate)
  end)

  it("LRU eviction removes oldest entry", function()
    local cache = perf.new_lru_cache(3)

    -- Fill cache
    cache:put("a", 1)
    cache:put("b", 2)
    cache:put("c", 3)

    assert.equals(3, cache:stats().count)
    assert.equals(1, cache:get("a"))
    assert.equals(2, cache:get("b"))
    assert.equals(3, cache:get("c"))

    -- Access 'a' to make it most recently used
    cache:get("a")

    -- Add new entry, should evict 'b' (oldest after 'a' was accessed)
    cache:put("d", 4)

    assert.equals(3, cache:stats().count)
    assert.equals(1, cache:get("a"))  -- still present
    assert.is_nil(cache:get("b"))     -- evicted
    assert.equals(3, cache:get("c"))  -- still present
    assert.equals(4, cache:get("d"))  -- new entry
  end)

  it("update existing key moves to head", function()
    local cache = perf.new_lru_cache(3)

    cache:put("a", 1)
    cache:put("b", 2)
    cache:put("c", 3)

    -- Update 'a' (should move to head)
    cache:put("a", 10)

    -- Add new entry, should evict 'b' (oldest)
    cache:put("d", 4)

    assert.equals(10, cache:get("a"))  -- updated value, still present
    assert.is_nil(cache:get("b"))      -- evicted
  end)

  it("remove works correctly", function()
    local cache = perf.new_lru_cache(10)

    cache:put("a", 1)
    cache:put("b", 2)
    cache:put("c", 3)

    assert.equals(3, cache:stats().count)

    local removed = cache:remove("b")
    assert.equals(2, removed)
    assert.equals(2, cache:stats().count)
    assert.is_nil(cache:get("b"))

    -- Other entries still present
    assert.equals(1, cache:get("a"))
    assert.equals(3, cache:get("c"))
  end)

  it("clear resets cache", function()
    local cache = perf.new_lru_cache(10)

    cache:put("a", 1)
    cache:put("b", 2)
    cache:get("a")  -- hit

    local stats = cache:stats()
    assert.equals(2, stats.count)
    assert.equals(1, stats.hits)

    cache:clear()

    stats = cache:stats()
    assert.equals(0, stats.count)
    -- Stats are preserved through clear
    assert.equals(1, stats.hits)
    assert.is_nil(cache:get("a"))
    assert.is_nil(cache:get("b"))
  end)
end)
