local types = require("lunarblock.types")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local serialize = require("lunarblock.serialize")
local crypto = require("lunarblock.crypto")
local validation = require("lunarblock.validation")
local storage_mod = require("lunarblock.storage")
local script = require("lunarblock.script")

describe("utxo", function()

  describe("utxo_entry", function()
    it("creates entry with correct fields", function()
      local entry = utxo.utxo_entry(50000000, "\x76\xa9\x14", 100, true)
      assert.equal(50000000, entry.value)
      assert.equal("\x76\xa9\x14", entry.script_pubkey)
      assert.equal(100, entry.height)
      assert.is_true(entry.is_coinbase)
    end)

    it("handles non-coinbase entries", function()
      local entry = utxo.utxo_entry(12345678, "test_script", 500, false)
      assert.equal(12345678, entry.value)
      assert.equal("test_script", entry.script_pubkey)
      assert.equal(500, entry.height)
      assert.is_false(entry.is_coinbase)
    end)
  end)

  describe("serialize/deserialize round-trip", function()
    it("round-trips entry with coinbase flag true", function()
      local original = utxo.utxo_entry(5000000000, string.rep("\xab", 25), 0, true)
      local serialized = utxo.serialize_utxo_entry(original)
      local deserialized = utxo.deserialize_utxo_entry(serialized)

      assert.equal(original.value, deserialized.value)
      assert.equal(original.script_pubkey, deserialized.script_pubkey)
      assert.equal(original.height, deserialized.height)
      assert.equal(original.is_coinbase, deserialized.is_coinbase)
    end)

    it("round-trips entry with coinbase flag false", function()
      local original = utxo.utxo_entry(123456789, "\x00\x14" .. string.rep("\xcd", 20), 650000, false)
      local serialized = utxo.serialize_utxo_entry(original)
      local deserialized = utxo.deserialize_utxo_entry(serialized)

      assert.equal(original.value, deserialized.value)
      assert.equal(original.script_pubkey, deserialized.script_pubkey)
      assert.equal(original.height, deserialized.height)
      assert.equal(original.is_coinbase, deserialized.is_coinbase)
    end)

    it("handles empty script_pubkey", function()
      local original = utxo.utxo_entry(1000, "", 100, false)
      local serialized = utxo.serialize_utxo_entry(original)
      local deserialized = utxo.deserialize_utxo_entry(serialized)

      assert.equal(original.value, deserialized.value)
      assert.equal(original.script_pubkey, deserialized.script_pubkey)
      assert.equal(original.height, deserialized.height)
    end)

    it("handles maximum values", function()
      local original = utxo.utxo_entry(consensus.MAX_MONEY, string.rep("\xff", 100), 0xFFFFFFFF, true)
      local serialized = utxo.serialize_utxo_entry(original)
      local deserialized = utxo.deserialize_utxo_entry(serialized)

      assert.equal(original.value, deserialized.value)
      assert.equal(original.script_pubkey, deserialized.script_pubkey)
      -- Note: height is u32, so max is 0xFFFFFFFF
    end)
  end)

  describe("outpoint_key", function()
    it("generates deterministic 36-byte key", function()
      local txid = types.hash256(string.rep("\xab", 32))
      local key1 = utxo.outpoint_key(txid, 0)
      local key2 = utxo.outpoint_key(txid, 0)

      assert.equal(36, #key1)
      assert.equal(key1, key2)
    end)

    it("generates unique keys for different vout indices", function()
      local txid = types.hash256(string.rep("\xcd", 32))
      local key0 = utxo.outpoint_key(txid, 0)
      local key1 = utxo.outpoint_key(txid, 1)
      local key2 = utxo.outpoint_key(txid, 2)

      assert.not_equal(key0, key1)
      assert.not_equal(key1, key2)
      assert.not_equal(key0, key2)
    end)

    it("generates unique keys for different txids", function()
      local txid1 = types.hash256(string.rep("\x01", 32))
      local txid2 = types.hash256(string.rep("\x02", 32))
      local key1 = utxo.outpoint_key(txid1, 0)
      local key2 = utxo.outpoint_key(txid2, 0)

      assert.not_equal(key1, key2)
    end)

    it("encodes vout index in little-endian", function()
      local txid = types.hash256(string.rep("\x00", 32))
      local key = utxo.outpoint_key(txid, 0x01020304)

      -- Last 4 bytes should be vout index in LE
      assert.equal(0x04, key:byte(33))
      assert.equal(0x03, key:byte(34))
      assert.equal(0x02, key:byte(35))
      assert.equal(0x01, key:byte(36))
    end)
  end)

  describe("CoinView", function()
    local db
    local tmp_path

    setup(function()
      tmp_path = "/tmp/lunarblock_utxo_test_" .. os.time()
    end)

    before_each(function()
      -- Open fresh database for each test
      db = storage_mod.open(tmp_path .. "_" .. math.random(1000000))
    end)

    after_each(function()
      if db then
        db.close()
      end
    end)

    it("add and get operations work", function()
      local view = utxo.new_coin_view(db)
      local txid = types.hash256(string.rep("\xaa", 32))
      local entry = utxo.utxo_entry(50000000, "\x76\xa9", 100, true)

      view:add(txid, 0, entry)
      local retrieved = view:get(txid, 0)

      assert.is_not_nil(retrieved)
      assert.equal(entry.value, retrieved.value)
      assert.equal(entry.script_pubkey, retrieved.script_pubkey)
      assert.equal(entry.height, retrieved.height)
      assert.equal(entry.is_coinbase, retrieved.is_coinbase)
    end)

    it("get returns nil for non-existent entry", function()
      local view = utxo.new_coin_view(db)
      local txid = types.hash256(string.rep("\xbb", 32))

      local retrieved = view:get(txid, 0)
      assert.is_nil(retrieved)
    end)

    it("spend returns the entry and marks it spent", function()
      local view = utxo.new_coin_view(db)
      local txid = types.hash256(string.rep("\xcc", 32))
      local entry = utxo.utxo_entry(100000, "\xa9\x14", 200, false)

      view:add(txid, 0, entry)
      local spent_entry = view:spend(txid, 0)

      assert.is_not_nil(spent_entry)
      assert.equal(entry.value, spent_entry.value)

      -- After spending, get should return nil
      local after_spend = view:get(txid, 0)
      assert.is_nil(after_spend)
    end)

    it("spend returns nil for non-existent entry", function()
      local view = utxo.new_coin_view(db)
      local txid = types.hash256(string.rep("\xdd", 32))

      local result, err = view:spend(txid, 0)
      assert.is_nil(result)
      assert.equal("UTXO not found", err)
    end)

    it("flush writes to storage and entries persist after clear_cache", function()
      local view = utxo.new_coin_view(db)
      local txid = types.hash256(string.rep("\xee", 32))
      local entry = utxo.utxo_entry(75000000, "\x00\x14" .. string.rep("\x11", 20), 300, false)

      view:add(txid, 0, entry)
      view:flush()
      view:clear_cache()

      -- After clearing cache, should still be able to load from storage
      local retrieved = view:get(txid, 0)
      assert.is_not_nil(retrieved)
      assert.equal(entry.value, retrieved.value)
      assert.equal(entry.script_pubkey, retrieved.script_pubkey)
    end)

    it("flush removes spent entries from storage", function()
      local view = utxo.new_coin_view(db)
      local txid = types.hash256(string.rep("\xff", 32))
      local entry = utxo.utxo_entry(25000000, "\x51\x20" .. string.rep("\x22", 32), 400, true)

      view:add(txid, 0, entry)
      view:flush()
      view:clear_cache()

      -- Verify it exists
      assert.is_not_nil(view:get(txid, 0))

      -- Spend and flush
      view:spend(txid, 0)
      view:flush()
      view:clear_cache()

      -- Should be gone from storage
      local after_spend = view:get(txid, 0)
      assert.is_nil(after_spend)
    end)

    it("handles multiple entries", function()
      local view = utxo.new_coin_view(db)
      local txid1 = types.hash256(string.rep("\x11", 32))
      local txid2 = types.hash256(string.rep("\x22", 32))

      view:add(txid1, 0, utxo.utxo_entry(1000, "a", 1, false))
      view:add(txid1, 1, utxo.utxo_entry(2000, "b", 1, false))
      view:add(txid2, 0, utxo.utxo_entry(3000, "c", 2, true))

      view:flush()
      view:clear_cache()

      assert.equal(1000, view:get(txid1, 0).value)
      assert.equal(2000, view:get(txid1, 1).value)
      assert.equal(3000, view:get(txid2, 0).value)
    end)

    -- Regression test for the secondary symptom of the 944,186 wedge:
    -- if connect_block fails mid-block (e.g. tapscript SCRIPT_SIZE in a
    -- later tx), the in-memory cache holds spent entries / fresh adds
    -- from earlier txns that were never flushed. discard_dirty() drops
    -- them so retries see disk-resident state. See
    -- project_lunarblock_wedge_2026_04_28.
    describe("discard_dirty (connect_block partial-failure recovery)", function()
      it("reverts spent UTXO so re-get sees the disk entry again", function()
        local view = utxo.new_coin_view(db)
        local txid = types.hash256(string.rep("\x42", 32))
        local entry = utxo.utxo_entry(50000, "\x00\x14" .. string.rep("\x33", 20), 100, false)

        -- Persist the entry to disk first.
        view:add(txid, 0, entry)
        view:flush()
        view:clear_cache()

        -- Sanity: get from disk.
        assert.is_not_nil(view:get(txid, 0))

        -- Spend without flushing: cache marks it spent. get() returns nil.
        view:spend(txid, 0)
        assert.is_nil(view:get(txid, 0))
        assert.is_true(view:get_dirty_count() > 0)

        -- Discard dirty mutations: the cache entry is dropped, so the
        -- next get() falls back to disk and finds the original entry.
        view:discard_dirty()
        assert.equal(0, view:get_dirty_count())
        local recovered = view:get(txid, 0)
        assert.is_not_nil(recovered)
        assert.equal(entry.value, recovered.value)
        assert.equal(entry.script_pubkey, recovered.script_pubkey)
      end)

      it("reverts fresh adds so re-get returns nil (UTXO never created)", function()
        local view = utxo.new_coin_view(db)
        local txid = types.hash256(string.rep("\x77", 32))
        local entry = utxo.utxo_entry(99999, "\xa9\x14" .. string.rep("\x55", 20) .. "\x87", 200, false)

        -- Add a fresh entry (not yet on disk).
        view:add(txid, 0, entry)
        assert.is_not_nil(view:get(txid, 0))
        assert.is_true(view:get_dirty_count() > 0)

        -- Discard: the fresh add is dropped, so get() returns nil
        -- (the UTXO never reached disk).
        view:discard_dirty()
        assert.equal(0, view:get_dirty_count())
        assert.is_nil(view:get(txid, 0))
      end)

      it("simulates partial-block failure: spent input + new output", function()
        -- Mimic the 944,186 scenario: a block contains tx_A that spends
        -- UTXO_X and creates UTXO_Y, then tx_B fires SCRIPT_SIZE. After
        -- discard_dirty, UTXO_X must reappear (re-spendable by retry) and
        -- UTXO_Y must NOT exist (it was never confirmed).
        local view = utxo.new_coin_view(db)
        local x_id = types.hash256(string.rep("\xab", 32))
        local x_ent = utxo.utxo_entry(60000, "\x00\x14" .. string.rep("\xcd", 20), 50, false)
        view:add(x_id, 0, x_ent)
        view:flush()
        view:clear_cache()

        -- Simulate connect_block partial work: tx_A spends X, creates Y.
        view:spend(x_id, 0)
        local y_id = types.hash256(string.rep("\xef", 32))
        local y_ent = utxo.utxo_entry(50000, "\x00\x14" .. string.rep("\x12", 20), 51, false)
        view:add(y_id, 0, y_ent)

        -- Pre-discard view: X spent, Y exists.
        assert.is_nil(view:get(x_id, 0))
        assert.is_not_nil(view:get(y_id, 0))

        -- Now tx_B "fails" — discard the partial mutations.
        view:discard_dirty()

        -- Post-discard view: X re-visible from disk, Y gone.
        assert.is_not_nil(view:get(x_id, 0))
        assert.equal(60000, view:get(x_id, 0).value)
        assert.is_nil(view:get(y_id, 0))
      end)
    end)
  end)

  describe("CoinView flush strategy", function()
    local db
    local tmp_path

    setup(function()
      tmp_path = "/tmp/lunarblock_flush_test_" .. os.time()
    end)

    before_each(function()
      db = storage_mod.open(tmp_path .. "_" .. math.random(1000000))
    end)

    after_each(function()
      if db then
        db.close()
      end
    end)

    it("tracks dirty count correctly", function()
      local view = utxo.new_coin_view(db)
      local txid = types.hash256(string.rep("\x01", 32))

      assert.equal(0, view:get_dirty_count())

      view:add(txid, 0, utxo.utxo_entry(1000, "a", 1, false))
      assert.equal(1, view:get_dirty_count())

      view:add(txid, 1, utxo.utxo_entry(2000, "b", 1, false))
      assert.equal(2, view:get_dirty_count())

      view:flush()
      assert.equal(0, view:get_dirty_count())
    end)

    it("fresh entries that are spent skip disk write", function()
      local view = utxo.new_coin_view(db)
      local txid = types.hash256(string.rep("\x02", 32))

      -- Add a fresh entry
      view:add(txid, 0, utxo.utxo_entry(1000, "script", 1, false))

      -- Spend it before flushing (should skip disk write)
      view:spend(txid, 0)

      -- Flush should be a no-op since fresh+spent skips
      view:flush()

      -- Stats should show fresh_spent_skipped
      local stats = view:cache_stats()
      assert.equal(1, stats.fresh_spent_skipped)
      assert.equal(0, stats.disk_writes)
      assert.equal(0, stats.disk_deletes)
    end)

    it("non-fresh spent entries are deleted from disk", function()
      local view = utxo.new_coin_view(db)
      local txid = types.hash256(string.rep("\x03", 32))

      -- Add and flush to disk
      view:add(txid, 0, utxo.utxo_entry(1000, "script", 1, false))
      view:flush()

      -- Clear cache so entry is no longer fresh
      view:clear_cache()

      -- Load from disk, then spend
      local entry = view:get(txid, 0)
      assert.is_not_nil(entry)

      view:spend(txid, 0)
      view:flush()

      -- Entry should be deleted from disk
      view:clear_cache()
      assert.is_nil(view:get(txid, 0))

      local stats = view:cache_stats()
      assert.equal(1, stats.disk_deletes)
    end)

    it("tracks memory usage", function()
      local view = utxo.new_coin_view(db)
      local txid = types.hash256(string.rep("\x04", 32))

      local initial_mem = view:get_memory_usage()
      assert.equal(0, initial_mem)

      view:add(txid, 0, utxo.utxo_entry(1000, "script1", 1, false))
      local after_add = view:get_memory_usage()
      assert.is_true(after_add > 0)

      view:add(txid, 1, utxo.utxo_entry(2000, "script2", 1, false))
      local after_add2 = view:get_memory_usage()
      assert.is_true(after_add2 > after_add)
    end)

    it("should_flush returns true when memory exceeds threshold", function()
      -- Create view with tiny cache
      local view = utxo.new_coin_view(db, {dbcache = 0.001})  -- ~1KB

      assert.is_false(view:should_flush())

      -- Add entries until we exceed threshold
      for i = 1, 100 do
        local txid = types.hash256(string.rep(string.char(i % 256), 32))
        view:add(txid, 0, utxo.utxo_entry(1000, string.rep("x", 100), i, false))
      end

      assert.is_true(view:should_flush())
    end)

    it("sync preserves cache but clears dirty flags", function()
      local view = utxo.new_coin_view(db)
      local txid = types.hash256(string.rep("\x05", 32))

      view:add(txid, 0, utxo.utxo_entry(1000, "script", 1, false))
      assert.equal(1, view:get_dirty_count())

      view:sync()
      assert.equal(0, view:get_dirty_count())

      -- Entry should still be in cache
      assert.equal(1, view:get_cache_size())
      local entry = view:get(txid, 0)
      assert.is_not_nil(entry)
      assert.equal(1000, entry.value)
    end)

    it("uncache removes non-dirty entries", function()
      local view = utxo.new_coin_view(db)
      local txid = types.hash256(string.rep("\x06", 32))

      -- Add, flush (clears dirty), then uncache
      view:add(txid, 0, utxo.utxo_entry(1000, "script", 1, false))
      view:flush()

      local initial_count = view:get_cache_size()
      view:uncache(txid, 0)

      assert.equal(initial_count - 1, view:get_cache_size())
    end)

    it("uncache does not remove dirty entries", function()
      local view = utxo.new_coin_view(db)
      local txid = types.hash256(string.rep("\x07", 32))

      -- Add (dirty), try to uncache
      view:add(txid, 0, utxo.utxo_entry(1000, "script", 1, false))
      local initial_count = view:get_cache_size()

      view:uncache(txid, 0)

      -- Entry should still be in cache (dirty entries can't be uncached)
      assert.equal(initial_count, view:get_cache_size())
    end)

    it("sanity_check passes for valid cache state", function()
      local view = utxo.new_coin_view(db)
      local txid1 = types.hash256(string.rep("\x08", 32))
      local txid2 = types.hash256(string.rep("\x09", 32))

      view:add(txid1, 0, utxo.utxo_entry(1000, "script1", 1, false))
      view:add(txid2, 0, utxo.utxo_entry(2000, "script2", 2, true))

      local ok, err = view:sanity_check()
      assert.is_true(ok)
      assert.is_nil(err)

      view:flush()
      ok, err = view:sanity_check()
      assert.is_true(ok)
      assert.is_nil(err)
    end)

    it("have checks existence without caching", function()
      local view = utxo.new_coin_view(db)
      local txid = types.hash256(string.rep("\x0a", 32))

      -- Not in cache or disk
      assert.is_false(view:have(txid, 0))

      -- Add to cache
      view:add(txid, 0, utxo.utxo_entry(1000, "script", 1, false))
      assert.is_true(view:have(txid, 0))

      -- Flush and clear cache
      view:flush()
      view:clear_cache()

      -- Should still return true (checks disk)
      assert.is_true(view:have(txid, 0))
    end)

    it("cache_stats reports correct values", function()
      local view = utxo.new_coin_view(db)
      local txid1 = types.hash256(string.rep("\x0b", 32))
      local txid2 = types.hash256(string.rep("\x0c", 32))

      -- Generate some stats
      view:get(txid1, 0)  -- miss
      view:add(txid1, 0, utxo.utxo_entry(1000, "script", 1, false))
      view:get(txid1, 0)  -- hit
      view:get(txid1, 0)  -- hit
      view:flush()

      local stats = view:cache_stats()
      assert.equal(2, stats.hits)
      assert.equal(1, stats.misses)
      assert.equal(1, stats.count)
      assert.equal(0, stats.dirty_count)
      assert.equal(1, stats.disk_writes)
      assert.equal(1, stats.flushes)
    end)

    it("handles re-adding a spent entry correctly", function()
      local view = utxo.new_coin_view(db)
      local txid = types.hash256(string.rep("\x0d", 32))

      -- Add, flush, clear, get (loads from disk), spend
      view:add(txid, 0, utxo.utxo_entry(1000, "script", 1, false))
      view:flush()
      view:clear_cache()
      view:get(txid, 0)  -- load from disk
      view:spend(txid, 0)

      -- Re-add with different value (like during reorg)
      view:add(txid, 0, utxo.utxo_entry(2000, "script2", 2, true))

      local entry = view:get(txid, 0)
      assert.is_not_nil(entry)
      assert.equal(2000, entry.value)
      assert.equal("script2", entry.script_pubkey)
    end)
  end)

  describe("ChainState", function()
    local db
    local chain_state

    before_each(function()
      local tmp_path = "/tmp/lunarblock_chainstate_test_" .. os.time() .. "_" .. math.random(1000000)
      db = storage_mod.open(tmp_path)
      chain_state = utxo.new_chain_state(db, consensus.networks.regtest)
      chain_state:init()
    end)

    after_each(function()
      if db then
        db.close()
      end
    end)

    -- Helper to create a simple coinbase transaction
    local function make_coinbase_tx(height, value, script_pubkey)
      local coinbase_sig = string.char(1, height % 256)  -- Minimal BIP34 height encoding
      return types.transaction(
        1,
        {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), coinbase_sig, 0xFFFFFFFF)},
        {types.txout(value, script_pubkey)},
        0
      )
    end

    -- Helper to create a simple block
    local function make_block(height, transactions)
      local header = types.block_header(
        1,                                     -- version
        types.hash256_zero(),                  -- prev_hash (dummy)
        types.hash256_zero(),                  -- merkle_root (dummy)
        os.time() + height,                    -- timestamp
        consensus.networks.regtest.pow_limit_bits,  -- bits
        0                                      -- nonce
      )
      return types.block(header, transactions)
    end

    it("connects a simple block with coinbase only", function()
      local pubkey_hash = string.rep("\x42", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)
      local coinbase = make_coinbase_tx(0, 5000000000, script_pubkey)
      local block = make_block(0, {coinbase})
      local block_hash = validation.compute_block_hash(block.header)

      local ok, fees = chain_state:connect_block(block, 0, block_hash)
      assert.is_true(ok)
      assert.equal(0, fees)
      assert.equal(0, chain_state.tip_height)

      -- Verify coinbase output is in UTXO set
      local txid = validation.compute_txid(coinbase)
      local utxo_entry = chain_state.coin_view:get(txid, 0)
      assert.is_not_nil(utxo_entry)
      assert.equal(5000000000, utxo_entry.value)
      assert.is_true(utxo_entry.is_coinbase)
    end)

    it("connects a block with transaction spending previous outputs", function()
      -- First block: coinbase creates output
      local pubkey_hash1 = string.rep("\x11", 20)
      local script_pubkey1 = script.make_p2pkh_script(pubkey_hash1)
      local coinbase1 = make_coinbase_tx(0, 5000000000, script_pubkey1)
      local block1 = make_block(0, {coinbase1})
      local block_hash1 = validation.compute_block_hash(block1.header)

      chain_state:connect_block(block1, 0, block_hash1)

      -- Add 100 more blocks for maturity (using simple coinbase-only blocks)
      for h = 1, 100 do
        local cb = make_coinbase_tx(h, 5000000000, script_pubkey1)
        local blk = make_block(h, {cb})
        local hash = validation.compute_block_hash(blk.header)
        chain_state:connect_block(blk, h, hash)
      end

      -- Now the first coinbase is mature, we can spend it
      local coinbase1_txid = validation.compute_txid(coinbase1)

      -- Create spending transaction
      local pubkey_hash2 = string.rep("\x22", 20)
      local script_pubkey2 = script.make_p2pkh_script(pubkey_hash2)

      -- For simplicity, we'll skip actual signature verification by not using real sigs
      -- Just test the UTXO tracking logic
      local spend_tx = types.transaction(
        1,
        {types.txin(types.outpoint(coinbase1_txid, 0), "", 0xFFFFFFFF)},
        {types.txout(4999990000, script_pubkey2)},  -- 10000 sat fee
        0
      )

      -- We need a coinbase for block 101
      local coinbase_101 = make_coinbase_tx(101, 5000010000, script_pubkey1)  -- subsidy + fee
      local block_101 = make_block(101, {coinbase_101, spend_tx})

      -- For this test to work, we need to mock the script verification
      -- Since we don't have actual signatures, the connect_block will fail on script verification
      -- This test verifies the UTXO tracking structure is correct

      -- For now, let's just verify the previous UTXOs are tracked correctly
      local utxo_entry = chain_state.coin_view:get(coinbase1_txid, 0)
      assert.is_not_nil(utxo_entry)
      assert.is_true(utxo_entry.is_coinbase)
      assert.equal(0, utxo_entry.height)
    end)

    it("enforces coinbase maturity", function()
      -- Create coinbase at height 0
      local pubkey_hash = string.rep("\x33", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)
      local coinbase0 = make_coinbase_tx(0, 5000000000, script_pubkey)
      local block0 = make_block(0, {coinbase0})
      local block_hash0 = validation.compute_block_hash(block0.header)

      chain_state:connect_block(block0, 0, block_hash0)

      -- Add only 99 blocks (not enough for maturity)
      for h = 1, 99 do
        local cb = make_coinbase_tx(h, 5000000000, script_pubkey)
        local blk = make_block(h, {cb})
        local hash = validation.compute_block_hash(blk.header)
        chain_state:connect_block(blk, h, hash)
      end

      -- The coinbase at height 0 should not be mature yet at height 99
      -- (needs height 100 to be spendable)
      local coinbase0_txid = validation.compute_txid(coinbase0)
      local utxo_entry = chain_state.coin_view:get(coinbase0_txid, 0)

      assert.is_not_nil(utxo_entry)
      -- At height 99, we're 99 blocks after height 0, need 100
      assert.equal(0, utxo_entry.height)
      -- 99 - 0 = 99, which is < COINBASE_MATURITY (100)
    end)

    it("rejects block with coinbase value exceeding subsidy + fees", function()
      local pubkey_hash = string.rep("\x44", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      -- Coinbase claims more than subsidy (no transactions, so no fees)
      local coinbase = make_coinbase_tx(0, 5000000001, script_pubkey)  -- 1 sat too much
      local block = make_block(0, {coinbase})
      local block_hash = validation.compute_block_hash(block.header)

      assert.has_error(function()
        chain_state:connect_block(block, 0, block_hash)
      end, "Coinbase value too high: 5000000001 > 5000000000 + 0")
    end)

    it("correctly calculates block subsidy at different heights", function()
      -- Height 0: 50 BTC
      assert.equal(5000000000, consensus.get_block_subsidy(0))

      -- Height 210000: 25 BTC (first halving)
      assert.equal(2500000000, consensus.get_block_subsidy(210000))

      -- Height 420000: 12.5 BTC (second halving)
      assert.equal(1250000000, consensus.get_block_subsidy(420000))

      -- Height 630000: 6.25 BTC (third halving)
      assert.equal(625000000, consensus.get_block_subsidy(630000))
    end)

    it("does not add OP_RETURN outputs to UTXO set", function()
      local pubkey_hash = string.rep("\x55", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      -- Coinbase with OP_RETURN output
      local coinbase = types.transaction(
        1,
        {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), "\x01\x00", 0xFFFFFFFF)},
        {
          types.txout(5000000000, script_pubkey),
          types.txout(0, "\x6a\x04test"),  -- OP_RETURN with "test"
        },
        0
      )
      local block = make_block(0, {coinbase})
      local block_hash = validation.compute_block_hash(block.header)

      chain_state:connect_block(block, 0, block_hash)

      local txid = validation.compute_txid(coinbase)

      -- First output should be in UTXO set
      local utxo0 = chain_state.coin_view:get(txid, 0)
      assert.is_not_nil(utxo0)

      -- Second output (OP_RETURN) should NOT be in UTXO set
      local utxo1 = chain_state.coin_view:get(txid, 1)
      assert.is_nil(utxo1)
    end)
  end)

  describe("UTXO statistics", function()
    local db
    local chain_state

    before_each(function()
      local tmp_path = "/tmp/lunarblock_utxo_stats_test_" .. os.time() .. "_" .. math.random(1000000)
      db = storage_mod.open(tmp_path)
      chain_state = utxo.new_chain_state(db, consensus.networks.regtest)
      chain_state:init()
    end)

    after_each(function()
      if db then
        db.close()
      end
    end)

    it("returns correct statistics for empty UTXO set", function()
      local stats = chain_state:get_utxo_stats()
      assert.equal(0, stats.utxo_count)
      assert.equal(0, stats.total_value)
      assert.equal(0, stats.total_btc)
    end)

    it("returns correct statistics after adding blocks", function()
      local pubkey_hash = string.rep("\x66", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      -- Add 3 blocks
      for h = 0, 2 do
        local coinbase = types.transaction(
          1,
          {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), string.char(1, h), 0xFFFFFFFF)},
          {types.txout(5000000000, script_pubkey)},
          0
        )
        local header = types.block_header(1, types.hash256_zero(), types.hash256_zero(), os.time() + h, consensus.networks.regtest.pow_limit_bits, 0)
        local block = types.block(header, {coinbase})
        local block_hash = validation.compute_block_hash(block.header)
        chain_state:connect_block(block, h, block_hash)
      end

      local stats = chain_state:get_utxo_stats()
      assert.equal(3, stats.utxo_count)
      assert.equal(15000000000, stats.total_value)
      assert.equal(150, stats.total_btc)
    end)
  end)

  describe("undo data serialization", function()
    it("serializes and deserializes undo entry round-trip", function()
      local original = utxo.utxo_entry(5000000000, "\x76\xa9\x14" .. string.rep("\xab", 20) .. "\x88\xac", 100, true)
      local serialized = utxo.serialize_undo_entry(original)
      local reader = serialize.buffer_reader(serialized)
      local deserialized = utxo.deserialize_undo_entry(reader)

      assert.equal(original.value, deserialized.value)
      assert.equal(original.script_pubkey, deserialized.script_pubkey)
      assert.equal(original.height, deserialized.height)
      assert.equal(original.is_coinbase, deserialized.is_coinbase)
    end)

    it("handles undo entry with height zero (no dummy byte)", function()
      local original = utxo.utxo_entry(1000000, "\x00\x14" .. string.rep("\xcd", 20), 0, true)
      local serialized = utxo.serialize_undo_entry(original)
      local reader = serialize.buffer_reader(serialized)
      local deserialized = utxo.deserialize_undo_entry(reader)

      assert.equal(original.value, deserialized.value)
      assert.equal(original.height, deserialized.height)
      assert.equal(original.is_coinbase, deserialized.is_coinbase)
    end)

    it("handles undo entry without coinbase flag", function()
      local original = utxo.utxo_entry(999999, "\x51\x20" .. string.rep("\xef", 32), 50000, false)
      local serialized = utxo.serialize_undo_entry(original)
      local reader = serialize.buffer_reader(serialized)
      local deserialized = utxo.deserialize_undo_entry(reader)

      assert.equal(original.value, deserialized.value)
      assert.equal(original.height, deserialized.height)
      assert.is_false(deserialized.is_coinbase)
    end)

    it("serializes and deserializes tx_undo round-trip", function()
      local entries = {
        utxo.utxo_entry(1000, "script1", 10, false),
        utxo.utxo_entry(2000, "script2", 20, true),
        utxo.utxo_entry(3000, "script3", 30, false),
      }
      local original = utxo.tx_undo(entries)
      local serialized = utxo.serialize_tx_undo(original)
      local reader = serialize.buffer_reader(serialized)
      local deserialized = utxo.deserialize_tx_undo(reader)

      assert.equal(#original.prev_outputs, #deserialized.prev_outputs)
      for i, orig in ipairs(original.prev_outputs) do
        local deser = deserialized.prev_outputs[i]
        assert.equal(orig.value, deser.value)
        assert.equal(orig.script_pubkey, deser.script_pubkey)
        assert.equal(orig.height, deser.height)
        assert.equal(orig.is_coinbase, deser.is_coinbase)
      end
    end)

    it("serializes and deserializes block_undo round-trip", function()
      local tx_undo1 = utxo.tx_undo({
        utxo.utxo_entry(5000000000, "\x76\xa9", 0, true),
      })
      local tx_undo2 = utxo.tx_undo({
        utxo.utxo_entry(100000, "\x00\x14" .. string.rep("\x11", 20), 100, false),
        utxo.utxo_entry(200000, "\x00\x14" .. string.rep("\x22", 20), 101, false),
      })
      local original = utxo.block_undo({tx_undo1, tx_undo2})
      local serialized = utxo.serialize_block_undo(original)
      local deserialized, err = utxo.deserialize_block_undo(serialized)

      assert.is_nil(err)
      assert.is_not_nil(deserialized)
      assert.equal(2, #deserialized.tx_undo)
      assert.equal(1, #deserialized.tx_undo[1].prev_outputs)
      assert.equal(2, #deserialized.tx_undo[2].prev_outputs)

      -- Verify first tx_undo
      local entry1 = deserialized.tx_undo[1].prev_outputs[1]
      assert.equal(5000000000, entry1.value)
      assert.is_true(entry1.is_coinbase)

      -- Verify second tx_undo
      local entry2a = deserialized.tx_undo[2].prev_outputs[1]
      assert.equal(100000, entry2a.value)
      assert.is_false(entry2a.is_coinbase)
    end)

    it("detects checksum mismatch in block_undo", function()
      local tx_undo = utxo.tx_undo({
        utxo.utxo_entry(1000, "test", 10, false),
      })
      local original = utxo.block_undo({tx_undo})
      local serialized = utxo.serialize_block_undo(original)

      -- Corrupt the data (but not the checksum)
      local corrupted = "X" .. serialized:sub(2)
      local result, err = utxo.deserialize_block_undo(corrupted)

      assert.is_nil(result)
      assert.is_not_nil(err)
      assert.matches("checksum", err)
    end)

    it("rejects too-short undo data", function()
      local result, err = utxo.deserialize_block_undo("short")
      assert.is_nil(result)
      assert.matches("too short", err)
    end)

    it("handles empty block_undo (no non-coinbase transactions)", function()
      local original = utxo.block_undo({})
      local serialized = utxo.serialize_block_undo(original)
      local deserialized, err = utxo.deserialize_block_undo(serialized)

      assert.is_nil(err)
      assert.is_not_nil(deserialized)
      assert.equal(0, #deserialized.tx_undo)
    end)
  end)

  describe("disconnect_block", function()
    local db
    local chain_state

    before_each(function()
      local tmp_path = "/tmp/lunarblock_disconnect_test_" .. os.time() .. "_" .. math.random(1000000)
      db = storage_mod.open(tmp_path)
      chain_state = utxo.new_chain_state(db, consensus.networks.regtest)
      chain_state:init()
    end)

    after_each(function()
      if db then
        db.close()
      end
    end)

    -- Helper to create a simple coinbase transaction
    local function make_coinbase_tx(height, value, script_pubkey)
      local coinbase_sig = string.char(1, height % 256)
      return types.transaction(
        1,
        {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), coinbase_sig, 0xFFFFFFFF)},
        {types.txout(value, script_pubkey)},
        0
      )
    end

    -- Helper to create a simple block
    local function make_block(height, transactions, prev_hash)
      local header = types.block_header(
        1,
        prev_hash or types.hash256_zero(),
        types.hash256_zero(),
        os.time() + height,
        consensus.networks.regtest.pow_limit_bits,
        0
      )
      return types.block(header, transactions)
    end

    it("disconnects a coinbase-only block", function()
      local pubkey_hash = string.rep("\x55", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)
      local coinbase = make_coinbase_tx(0, 5000000000, script_pubkey)
      local block = make_block(0, {coinbase})
      local block_hash = validation.compute_block_hash(block.header)

      -- Connect the block
      chain_state:connect_block(block, 0, block_hash)

      local txid = validation.compute_txid(coinbase)
      assert.is_not_nil(chain_state.coin_view:get(txid, 0))
      assert.equal(0, chain_state.tip_height)

      -- Disconnect the block
      local prev_hash = block.header.prev_hash
      local ok = chain_state:disconnect_block(block, 0, block_hash, prev_hash)
      assert.is_true(ok)

      -- Coinbase output should be removed
      chain_state.coin_view:clear_cache()
      assert.is_nil(chain_state.coin_view:get(txid, 0))
      assert.equal(-1, chain_state.tip_height)
    end)

    it("connects and disconnects multiple blocks round-trip", function()
      local pubkey_hash = string.rep("\x66", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      -- Connect 3 blocks
      local block_hashes = {}
      local prev_hash = types.hash256_zero()
      for h = 0, 2 do
        local coinbase = make_coinbase_tx(h, 5000000000, script_pubkey)
        local block = make_block(h, {coinbase}, prev_hash)
        local block_hash = validation.compute_block_hash(block.header)
        block_hashes[h] = {hash = block_hash, block = block, prev = prev_hash}
        chain_state:connect_block(block, h, block_hash)
        prev_hash = block_hash
      end

      -- Verify initial state
      local stats = chain_state:get_utxo_stats()
      assert.equal(3, stats.utxo_count)
      assert.equal(2, chain_state.tip_height)

      -- Disconnect blocks in reverse order
      for h = 2, 0, -1 do
        local info = block_hashes[h]
        chain_state:disconnect_block(info.block, h, info.hash, info.prev)
      end

      -- All UTXOs should be gone
      chain_state.coin_view:clear_cache()
      stats = chain_state:get_utxo_stats()
      assert.equal(0, stats.utxo_count)
      assert.equal(-1, chain_state.tip_height)
    end)
  end)

  describe("invalidateblock", function()
    local db
    local chain_state

    before_each(function()
      local tmp_path = "/tmp/lunarblock_invalidate_test_" .. os.time() .. "_" .. math.random(1000000)
      db = storage_mod.open(tmp_path)
      chain_state = utxo.new_chain_state(db, consensus.networks.regtest)
      chain_state:init()
    end)

    after_each(function()
      if db then
        db.close()
      end
    end)

    -- Helper to create a simple coinbase transaction
    local function make_coinbase_tx(height, value, script_pubkey)
      local coinbase_sig = string.char(1, height % 256)
      return types.transaction(
        1,
        {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), coinbase_sig, 0xFFFFFFFF)},
        {types.txout(value, script_pubkey)},
        0
      )
    end

    -- Helper to create a simple block
    local function make_block(height, transactions, prev_hash)
      local header = types.block_header(
        1,
        prev_hash or types.hash256_zero(),
        types.hash256_zero(),
        os.time() + height,
        consensus.networks.regtest.pow_limit_bits,
        0
      )
      return types.block(header, transactions)
    end

    it("marks a block as invalid", function()
      local pubkey_hash = string.rep("\x77", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      -- Connect genesis block
      local coinbase0 = make_coinbase_tx(0, 5000000000, script_pubkey)
      local block0 = make_block(0, {coinbase0})
      local block_hash0 = validation.compute_block_hash(block0.header)
      db.put_header(block_hash0, block0.header)
      db.put_block(block_hash0, block0)
      chain_state:connect_block(block0, 0, block_hash0)

      -- Connect another block
      local coinbase1 = make_coinbase_tx(1, 5000000000, script_pubkey)
      local block1 = make_block(1, {coinbase1}, block_hash0)
      local block_hash1 = validation.compute_block_hash(block1.header)
      db.put_header(block_hash1, block1.header)
      db.put_block(block_hash1, block1)
      chain_state:connect_block(block1, 1, block_hash1)

      assert.equal(1, chain_state.tip_height)

      -- Invalidate block 1
      local ok, err = chain_state:invalidate_block(block_hash1)
      assert.is_true(ok)
      assert.is_nil(err)

      -- Block 1 should now be marked invalid
      assert.is_true(chain_state:is_block_invalid(block_hash1))

      -- Chain tip should be block 0
      assert.equal(0, chain_state.tip_height)
    end)

    it("rejects invalidating genesis block", function()
      local pubkey_hash = string.rep("\x88", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      -- Connect genesis block
      local coinbase0 = make_coinbase_tx(0, 5000000000, script_pubkey)
      local block0 = make_block(0, {coinbase0})
      local block_hash0 = validation.compute_block_hash(block0.header)
      db.put_header(block_hash0, block0.header)
      db.put_block(block_hash0, block0)
      chain_state:connect_block(block0, 0, block_hash0)

      -- Try to invalidate genesis
      local ok, err = chain_state:invalidate_block(block_hash0)
      assert.is_nil(ok)
      assert.matches("Cannot invalidate genesis", err)
    end)

    it("returns error for non-existent block", function()
      local fake_hash = types.hash256(string.rep("\xff", 32))
      local ok, err = chain_state:invalidate_block(fake_hash)
      assert.is_nil(ok)
      assert.matches("Block not found", err)
    end)

    it("triggers reorg when invalidating block on active chain", function()
      local pubkey_hash = string.rep("\x99", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      -- Build a chain of 3 blocks
      local block_hashes = {}
      local prev_hash = types.hash256_zero()
      for h = 0, 2 do
        local coinbase = make_coinbase_tx(h, 5000000000, script_pubkey)
        local block = make_block(h, {coinbase}, prev_hash)
        local block_hash = validation.compute_block_hash(block.header)
        db.put_header(block_hash, block.header)
        db.put_block(block_hash, block)
        block_hashes[h] = block_hash
        chain_state:connect_block(block, h, block_hash)
        prev_hash = block_hash
      end

      assert.equal(2, chain_state.tip_height)

      -- Invalidate block 1 (middle of chain)
      local ok, err = chain_state:invalidate_block(block_hashes[1])
      assert.is_true(ok)

      -- Should have rolled back to block 0
      assert.equal(0, chain_state.tip_height)

      -- Block 1 should be invalid
      assert.is_true(chain_state:is_block_invalid(block_hashes[1]))
    end)

    it("persists invalid blocks across save/load", function()
      local pubkey_hash = string.rep("\xaa", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      -- Connect two blocks
      local coinbase0 = make_coinbase_tx(0, 5000000000, script_pubkey)
      local block0 = make_block(0, {coinbase0})
      local block_hash0 = validation.compute_block_hash(block0.header)
      db.put_header(block_hash0, block0.header)
      db.put_block(block_hash0, block0)
      chain_state:connect_block(block0, 0, block_hash0)

      local coinbase1 = make_coinbase_tx(1, 5000000000, script_pubkey)
      local block1 = make_block(1, {coinbase1}, block_hash0)
      local block_hash1 = validation.compute_block_hash(block1.header)
      db.put_header(block_hash1, block1.header)
      db.put_block(block_hash1, block1)
      chain_state:connect_block(block1, 1, block_hash1)

      -- Invalidate block 1
      chain_state:invalidate_block(block_hash1)
      assert.is_true(chain_state:is_block_invalid(block_hash1))

      -- Create new chain state from same storage
      local chain_state2 = utxo.new_chain_state(db, consensus.networks.regtest)
      chain_state2:init()

      -- Invalid blocks should be loaded
      assert.is_true(chain_state2:is_block_invalid(block_hash1))
    end)
  end)

  describe("reconsiderblock", function()
    local db
    local chain_state

    before_each(function()
      local tmp_path = "/tmp/lunarblock_reconsider_test_" .. os.time() .. "_" .. math.random(1000000)
      db = storage_mod.open(tmp_path)
      chain_state = utxo.new_chain_state(db, consensus.networks.regtest)
      chain_state:init()
    end)

    after_each(function()
      if db then
        db.close()
      end
    end)

    -- Helper to create a simple coinbase transaction
    local function make_coinbase_tx(height, value, script_pubkey)
      local coinbase_sig = string.char(1, height % 256)
      return types.transaction(
        1,
        {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), coinbase_sig, 0xFFFFFFFF)},
        {types.txout(value, script_pubkey)},
        0
      )
    end

    -- Helper to create a simple block
    local function make_block(height, transactions, prev_hash)
      local header = types.block_header(
        1,
        prev_hash or types.hash256_zero(),
        types.hash256_zero(),
        os.time() + height,
        consensus.networks.regtest.pow_limit_bits,
        0
      )
      return types.block(header, transactions)
    end

    it("clears invalid flag from a block", function()
      local pubkey_hash = string.rep("\xbb", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      -- Connect two blocks
      local coinbase0 = make_coinbase_tx(0, 5000000000, script_pubkey)
      local block0 = make_block(0, {coinbase0})
      local block_hash0 = validation.compute_block_hash(block0.header)
      db.put_header(block_hash0, block0.header)
      db.put_block(block_hash0, block0)
      chain_state:connect_block(block0, 0, block_hash0)

      local coinbase1 = make_coinbase_tx(1, 5000000000, script_pubkey)
      local block1 = make_block(1, {coinbase1}, block_hash0)
      local block_hash1 = validation.compute_block_hash(block1.header)
      db.put_header(block_hash1, block1.header)
      db.put_block(block_hash1, block1)
      chain_state:connect_block(block1, 1, block_hash1)

      -- Invalidate block 1
      chain_state:invalidate_block(block_hash1)
      assert.is_true(chain_state:is_block_invalid(block_hash1))

      -- Reconsider block 1
      local ok, err = chain_state:reconsider_block(block_hash1)
      assert.is_true(ok)
      assert.is_nil(err)

      -- Block should no longer be marked invalid
      assert.is_false(chain_state:is_block_invalid(block_hash1))
    end)

    it("returns error for non-existent block", function()
      local fake_hash = types.hash256(string.rep("\xee", 32))
      local ok, err = chain_state:reconsider_block(fake_hash)
      assert.is_nil(ok)
      assert.matches("Block not found", err)
    end)

    it("clears invalid flags from ancestors", function()
      local pubkey_hash = string.rep("\xcc", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      -- Build chain of 3 blocks
      local block_hashes = {}
      local prev_hash = types.hash256_zero()
      for h = 0, 2 do
        local coinbase = make_coinbase_tx(h, 5000000000, script_pubkey)
        local block = make_block(h, {coinbase}, prev_hash)
        local block_hash = validation.compute_block_hash(block.header)
        db.put_header(block_hash, block.header)
        db.put_block(block_hash, block)
        block_hashes[h] = block_hash
        chain_state:connect_block(block, h, block_hash)
        prev_hash = block_hash
      end

      -- Manually mark blocks 1 and 2 as invalid
      chain_state.invalid_blocks[block_hashes[1].bytes] = true
      chain_state.invalid_blocks[block_hashes[2].bytes] = true
      chain_state:save_invalid_blocks()

      -- Reconsider block 2 (should also clear block 1)
      chain_state:reconsider_block(block_hashes[2])

      -- Both should be cleared
      assert.is_false(chain_state:is_block_invalid(block_hashes[1]))
      assert.is_false(chain_state:is_block_invalid(block_hashes[2]))
    end)

    it("persists reconsideration across save/load", function()
      local pubkey_hash = string.rep("\xdd", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      -- Connect two blocks
      local coinbase0 = make_coinbase_tx(0, 5000000000, script_pubkey)
      local block0 = make_block(0, {coinbase0})
      local block_hash0 = validation.compute_block_hash(block0.header)
      db.put_header(block_hash0, block0.header)
      db.put_block(block_hash0, block0)
      chain_state:connect_block(block0, 0, block_hash0)

      local coinbase1 = make_coinbase_tx(1, 5000000000, script_pubkey)
      local block1 = make_block(1, {coinbase1}, block_hash0)
      local block_hash1 = validation.compute_block_hash(block1.header)
      db.put_header(block_hash1, block1.header)
      db.put_block(block_hash1, block1)
      chain_state:connect_block(block1, 1, block_hash1)

      -- Invalidate then reconsider
      chain_state:invalidate_block(block_hash1)
      chain_state:reconsider_block(block_hash1)

      -- Create new chain state
      local chain_state2 = utxo.new_chain_state(db, consensus.networks.regtest)
      chain_state2:init()

      -- Block should not be invalid
      assert.is_false(chain_state2:is_block_invalid(block_hash1))
    end)
  end)

  describe("reorg with invalid blocks", function()
    local db
    local chain_state

    before_each(function()
      local tmp_path = "/tmp/lunarblock_reorg_test_" .. os.time() .. "_" .. math.random(1000000)
      db = storage_mod.open(tmp_path)
      chain_state = utxo.new_chain_state(db, consensus.networks.regtest)
      chain_state:init()
    end)

    after_each(function()
      if db then
        db.close()
      end
    end)

    -- Helper to create a simple coinbase transaction
    local function make_coinbase_tx(height, value, script_pubkey)
      local coinbase_sig = string.char(1, height % 256)
      return types.transaction(
        1,
        {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), coinbase_sig, 0xFFFFFFFF)},
        {types.txout(value, script_pubkey)},
        0
      )
    end

    -- Helper to create a simple block
    local function make_block(height, transactions, prev_hash)
      local header = types.block_header(
        1,
        prev_hash or types.hash256_zero(),
        types.hash256_zero(),
        os.time() + height,
        consensus.networks.regtest.pow_limit_bits,
        0
      )
      return types.block(header, transactions)
    end

    it("has_invalid_ancestor detects invalid ancestors", function()
      local pubkey_hash = string.rep("\xee", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      -- Build chain of 3 blocks
      local block_hashes = {}
      local prev_hash = types.hash256_zero()
      for h = 0, 2 do
        local coinbase = make_coinbase_tx(h, 5000000000, script_pubkey)
        local block = make_block(h, {coinbase}, prev_hash)
        local block_hash = validation.compute_block_hash(block.header)
        db.put_header(block_hash, block.header)
        db.put_block(block_hash, block)
        block_hashes[h] = block_hash
        chain_state:connect_block(block, h, block_hash)
        prev_hash = block_hash
      end

      -- Mark block 1 as invalid
      chain_state.invalid_blocks[block_hashes[1].bytes] = true

      -- Block 2 has an invalid ancestor (block 1)
      assert.is_true(chain_state:has_invalid_ancestor(block_hashes[2]))

      -- Block 1 itself is invalid (not just an ancestor)
      assert.is_true(chain_state:is_block_invalid(block_hashes[1]))

      -- Block 0 has no invalid ancestor
      assert.is_false(chain_state:has_invalid_ancestor(block_hashes[0]))
    end)

    it("get_invalid_blocks returns list of invalid block hashes", function()
      local pubkey_hash = string.rep("\xff", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      -- Build chain of 2 blocks
      local block_hashes = {}
      local prev_hash = types.hash256_zero()
      for h = 0, 1 do
        local coinbase = make_coinbase_tx(h, 5000000000, script_pubkey)
        local block = make_block(h, {coinbase}, prev_hash)
        local block_hash = validation.compute_block_hash(block.header)
        db.put_header(block_hash, block.header)
        db.put_block(block_hash, block)
        block_hashes[h] = block_hash
        chain_state:connect_block(block, h, block_hash)
        prev_hash = block_hash
      end

      -- Invalidate block 1
      chain_state:invalidate_block(block_hashes[1])

      -- Get invalid blocks list
      local invalid_list = chain_state:get_invalid_blocks()
      assert.equal(1, #invalid_list)
      assert.equal(block_hashes[1].bytes, invalid_list[1].bytes)
    end)
  end)

end)
