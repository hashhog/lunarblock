-- Tests for src/prune.lua: pruner state machine + RocksDB sweep
-- behavior. Uses a tiny on-disk RocksDB so we exercise the actual
-- delete path, not a mock.

describe("prune", function()
  local prune, storage, types
  local cjson = require("cjson")

  -- Helpers reused from spec/storage_spec.lua to make a temp datadir.
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
    prune = require("lunarblock.prune")
    storage = require("lunarblock.storage")
    types = require("lunarblock.types")
  end)

  describe("constants", function()
    it("MIN_BLOCKS_TO_KEEP matches Bitcoin Core (validation.h:76)", function()
      assert.equal(288, prune.MIN_BLOCKS_TO_KEEP)
    end)
  end)

  describe("constructor", function()
    it("target_mb=0 disables pruning entirely", function()
      local p = prune.new({ target_mb = 0 })
      assert.is_false(p.enabled)
      assert.is_false(p.automatic)
      assert.is_false(p.manual_only)
    end)

    it("target_mb=1 enables manual-only mode", function()
      local p = prune.new({ target_mb = 1 })
      assert.is_true(p.enabled)
      assert.is_true(p.manual_only)
      assert.is_false(p.automatic)
    end)

    it("target_mb=550 enables automatic mode", function()
      local p = prune.new({ target_mb = 550 })
      assert.is_true(p.enabled)
      assert.is_false(p.manual_only)
      assert.is_true(p.automatic)
    end)

    it("starts with prune_height=0", function()
      local p = prune.new({ target_mb = 550 })
      assert.equal(0, p.prune_height)
    end)

    it("clamps negative target_mb to 0 (defensive)", function()
      local p = prune.new({ target_mb = -50 })
      assert.is_false(p.enabled)
    end)
  end)

  describe("target_blocks_to_keep", function()
    it("returns infinity for manual-only mode", function()
      local p = prune.new({ target_mb = 1 })
      assert.equal(math.huge, p:target_blocks_to_keep())
    end)

    it("respects MIN_BLOCKS_TO_KEEP floor at 550 MB", function()
      -- 550 * 1024 * 1024 / 1.5 MB ~= 384 blocks -> above floor
      local p = prune.new({ target_mb = 550 })
      local kept = p:target_blocks_to_keep()
      assert.is_true(kept >= prune.MIN_BLOCKS_TO_KEEP)
    end)

    it("scales with target_mb", function()
      local p_small = prune.new({ target_mb = 550 })
      local p_large = prune.new({ target_mb = 5500 })
      assert.is_true(p_large:target_blocks_to_keep()
                     > p_small:target_blocks_to_keep())
    end)
  end)

  describe("compute_prune_target", function()
    it("returns nil when disabled", function()
      local p = prune.new({ target_mb = 0 })
      assert.is_nil(p:compute_prune_target(1000000))
    end)

    it("returns nil when tip below MIN_BLOCKS_TO_KEEP", function()
      local p = prune.new({ target_mb = 550 })
      assert.is_nil(p:compute_prune_target(100))
      assert.is_nil(p:compute_prune_target(prune.MIN_BLOCKS_TO_KEEP - 1))
    end)

    it("never returns within MIN_BLOCKS_TO_KEEP of tip", function()
      local p = prune.new({ target_mb = 550 })
      local tip = 1000000
      local target = p:compute_prune_target(tip)
      assert.is_truthy(target)
      assert.is_true(tip - target >= prune.MIN_BLOCKS_TO_KEEP)
    end)

    it("returns nil when no progress past current prune_height", function()
      local p = prune.new({ target_mb = 550 })
      -- For tip=1000, target = tip - target_blocks_to_keep, capped by
      -- tip - MIN_BLOCKS_TO_KEEP. At target_mb=550 that's around
      -- 550MB/1.5MB=~384 → tip - 384 = 616. So if we set prune_height
      -- already past that point, the function should not propose more.
      p.prune_height = 999  -- already pruned everything we could
      assert.is_nil(p:compute_prune_target(1000))
    end)
  end)

  describe("is_pruned", function()
    it("returns false when disabled", function()
      local p = prune.new({ target_mb = 0 })
      p.prune_height = 100
      assert.is_false(p:is_pruned(50))
    end)

    it("returns true at or below prune_height", function()
      local p = prune.new({ target_mb = 550 })
      p.prune_height = 100
      assert.is_true(p:is_pruned(50))
      assert.is_true(p:is_pruned(100))
    end)

    it("returns false above prune_height", function()
      local p = prune.new({ target_mb = 550 })
      p.prune_height = 100
      assert.is_false(p:is_pruned(101))
      assert.is_false(p:is_pruned(1000))
    end)

    it("handles nil height", function()
      local p = prune.new({ target_mb = 550 })
      assert.is_false(p:is_pruned(nil))
    end)
  end)

  describe("force_prune (real RocksDB)", function()
    local db, path, p

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)  -- 16 MB cache
      p = prune.new({ target_mb = 550, storage = db })
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("deletes block + undo entries for pruned heights", function()
      -- Write 10 fake blocks at heights 1..10.
      local hashes = {}
      for h = 1, 10 do
        local hash = types.hash256(string.rep(string.char(h), 32))
        hashes[h] = hash
        db.put(storage.CF.BLOCKS, hash.bytes, "block-body-" .. h)
        db.put(storage.CF.UNDO, hash.bytes, "undo-" .. h)
        db.put_height_index(h, hash)
      end

      -- Force-prune up to height 5.
      local deleted = p:force_prune(10000, 5)
      -- 5 - 0 = 5, but force_prune respects MIN_BLOCKS_TO_KEEP from
      -- a tip of 10000. up_to=5 is well below tip-288 so all 5 go.
      assert.equal(5, deleted)
      assert.equal(5, p.prune_height)

      -- Heights 1..5 should be gone from BLOCKS+UNDO.
      for h = 1, 5 do
        assert.is_nil(db.get(storage.CF.BLOCKS, hashes[h].bytes))
        assert.is_nil(db.get(storage.CF.UNDO, hashes[h].bytes))
      end
      -- Heights 6..10 still present.
      for h = 6, 10 do
        assert.is_not_nil(db.get(storage.CF.BLOCKS, hashes[h].bytes))
        assert.is_not_nil(db.get(storage.CF.UNDO, hashes[h].bytes))
      end
      -- Height index (CF.HEIGHT_INDEX) is intentionally NOT deleted —
      -- it matches Bitcoin Core which keeps CBlockIndex for pruned
      -- blocks so reorg detection still works.
      for h = 1, 10 do
        local hash_back = db.get_hash_by_height(h)
        assert.is_not_nil(hash_back)
      end
    end)

    it("respects MIN_BLOCKS_TO_KEEP cap from tip", function()
      -- Try to prune within the safety window — should not actually
      -- delete anything past tip - 288.
      local hash = types.hash256(string.rep("\x42", 32))
      db.put(storage.CF.BLOCKS, hash.bytes, "body")
      db.put_height_index(500, hash)

      -- tip=500, up_to=499 → last_can_prune = 500 - 288 = 212; 499 > 212
      -- so target gets clamped to 212. height 500 must remain.
      p:force_prune(500, 499)
      assert.is_not_nil(db.get(storage.CF.BLOCKS, hash.bytes))
    end)

    it("is a no-op when disabled", function()
      local p_off = prune.new({ target_mb = 0, storage = db })
      local hash = types.hash256(string.rep("\x55", 32))
      db.put(storage.CF.BLOCKS, hash.bytes, "body")
      db.put_height_index(1, hash)

      assert.equal(0, p_off:force_prune(10000, 5))
      assert.equal(0, p_off.prune_height)
      assert.is_not_nil(db.get(storage.CF.BLOCKS, hash.bytes))
    end)
  end)

  describe("maybe_prune throttling", function()
    it("does nothing on first call below MIN_BLOCKS_TO_KEEP", function()
      local p = prune.new({ target_mb = 550 })
      assert.equal(0, p:maybe_prune(100))
      assert.equal(0, p.prune_height)
    end)

    it("does not run before PRUNE_INTERVAL_BLOCKS elapsed since last sweep", function()
      local p = prune.new({ target_mb = 550 })
      -- Pretend we already swept at tip=1000.
      p.last_sweep_tip = 1000
      -- Tip has moved by < PRUNE_INTERVAL_BLOCKS — still throttled.
      assert.equal(0, p:maybe_prune(1000 + prune.PRUNE_INTERVAL_BLOCKS - 1))
    end)
  end)
end)
