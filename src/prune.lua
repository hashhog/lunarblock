--- Block pruning for lunarblock.
--
-- Implements a height-based prune sweep over RocksDB CF.BLOCKS + CF.UNDO,
-- modeled on Bitcoin Core's BlockManager::FindFilesToPrune logic
-- (see bitcoin-core/src/node/blockstorage.cpp). Lunarblock stores block
-- bodies in a RocksDB column family (not blk*.dat files), so "pruning a
-- file" reduces to "DELETE every (height, block_hash) pair below
-- prune_height".
--
-- Strategy: HEIGHT-BASED. We do not measure on-disk size of CF.BLOCKS at
-- runtime — RocksDB's GetApproximateSizes API isn't currently exposed via
-- our FFI surface, and walking every key to sum sizes would block the
-- single-threaded event loop on a multi-million-key column family. We
-- instead translate the user's --prune=N (target MB) into a target block
-- count using a fleet-empirical average block body size, then keep the
-- newest `target_blocks_to_keep` blocks (clamped to MIN_BLOCKS_TO_KEEP=288
-- per Bitcoin Core's `validation.h`).
--
-- TODO(prune-size): Replace the block-count translation with a real
-- size-driven sweep once storage.lua exposes
-- rocksdb_approximate_sizes_cf or a periodic CalculateCurrentUsage.
-- Rationale + math: see comment on `target_blocks_to_keep` below.
--
-- Reference: bitcoin-core/src/validation.h:76 MIN_BLOCKS_TO_KEEP = 288.

local types = require("lunarblock.types")
local storage_mod = require("lunarblock.storage")

local M = {}

-- Bitcoin Core's hard floor: never prune within 288 blocks of tip.  This
-- keeps reorgs (which Bitcoin Core caps at ~MIN_BLOCKS_TO_KEEP depth)
-- safe against undo data being missing.
M.MIN_BLOCKS_TO_KEEP = 288

-- Empirical average block body size (bytes). Used only to translate a
-- user-supplied size target (MB) into a block-count window. As of
-- 2026-04-29, mainnet's serialized block average is ~1.4 MB. We round up
-- so we err on the side of keeping more blocks than the target requests
-- (i.e., honor `--prune=N` as an upper bound on observable disk usage).
M.AVG_BLOCK_SIZE = 1500000  -- 1.5 MB

-- How often (in blocks connected) to attempt a prune sweep when running
-- in automatic mode. Matches Bitcoin Core's "check on flush" cadence at
-- a higher granularity; we deliberately keep this cheap so the IBD loop
-- can still call us on every block without measurable overhead.
M.PRUNE_INTERVAL_BLOCKS = 100

-- Maximum number of blocks deleted in a single sweep. Bounds the worst
-- case wall time we spend off the event loop. With ~1.5 MB blocks at
-- 100 deletes per sweep, a single call walks ~150 MB of RocksDB keys —
-- well within the per-tick budget on a modern NVMe.
M.MAX_DELETES_PER_SWEEP = 100

--- Create a new pruner.
-- @param opts table:
--   - target_mb (number): --prune value. 0=disabled, 1=manual-only,
--                         >=550=automatic with this MB target.
--   - storage  (table):   the storage handle from storage_mod.open.
-- @return table: pruner object
function M.new(opts)
  opts = opts or {}
  local target_mb = opts.target_mb or 0
  if target_mb < 0 then target_mb = 0 end

  local self = {
    -- Mode flags. 0 = off, 1 = manual-only (RPC/pruneblockchain), >=550 = auto.
    target_mb = target_mb,
    enabled = target_mb > 0,
    manual_only = target_mb == 1,
    automatic = target_mb >= 550,
    storage = opts.storage,

    -- Highest height that has been pruned (i.e. blocks at heights
    -- 1..prune_height have had their CF.BLOCKS / CF.UNDO entries
    -- removed).  Mirrors Bitcoin Core's prune_height derived from
    -- m_blockfile_info.  0 means nothing has been pruned yet.
    prune_height = 0,

    -- Last tip height at which we ran a sweep, to throttle calls.
    last_sweep_tip = -1,
  }

  --- Compute how many of the newest blocks we want to keep on disk to
  -- approximately satisfy the target_mb size budget. Always at least
  -- MIN_BLOCKS_TO_KEEP, never above the current tip.
  -- @return number: target blocks to keep
  function self:target_blocks_to_keep()
    if not self.automatic then
      -- manual_only: nothing to do here; pruneblockchain RPC drives it.
      return math.huge
    end
    local bytes = self.target_mb * 1024 * 1024
    local count = math.floor(bytes / M.AVG_BLOCK_SIZE)
    if count < M.MIN_BLOCKS_TO_KEEP then
      count = M.MIN_BLOCKS_TO_KEEP
    end
    return count
  end

  --- Determine the highest height that is safe to prune given the
  -- current tip. Returns nil if pruning is disabled or if there are
  -- not yet enough blocks to prune anything.
  -- @param tip_height number: current chain tip height
  -- @return number|nil: highest height to prune (inclusive) or nil
  function self:compute_prune_target(tip_height)
    if not self.automatic then return nil end
    if not tip_height or tip_height < M.MIN_BLOCKS_TO_KEEP then
      return nil
    end
    local keep = self:target_blocks_to_keep()
    -- Last block we are allowed to prune is tip - MIN_BLOCKS_TO_KEEP
    -- (see bitcoin-core/src/validation.cpp::GetPruneRange).
    local last_can_prune = tip_height - M.MIN_BLOCKS_TO_KEEP
    -- We additionally bound by `keep` so that we retain at least
    -- `keep` of the newest blocks.
    local target = tip_height - keep
    if target > last_can_prune then target = last_can_prune end
    if target <= self.prune_height then return nil end
    if target < 1 then return nil end
    return target
  end

  --- Delete CF.BLOCKS + CF.UNDO entries for height `h`. Uses the
  -- height index to look up the block hash, then deletes by hash.
  -- The height index entry is intentionally left in place: it's
  -- only 32 bytes per height (~30 MB at mainnet tip) and matches
  -- Bitcoin Core's BlockManager, which preserves CBlockIndex
  -- entries for pruned blocks so reorg detection / getblockheader
  -- continue to work.
  -- @return boolean: true if a block was actually deleted at this height
  function self:_delete_block_at_height(h)
    if not self.storage then return false end
    local hash = self.storage.get_hash_by_height(h)
    if not hash then return false end
    -- Best-effort: ignore RocksDB errors so a partially missing entry
    -- does not poison the sweep. Pruning is a disk-reclamation step,
    -- not a consensus-critical operation.
    local ok, err = pcall(function()
      self.storage.delete(storage_mod.CF.BLOCKS, hash.bytes, false)
      self.storage.delete(storage_mod.CF.UNDO, hash.bytes, false)
    end)
    if not ok then
      io.stderr:write(string.format(
        "[prune] WARN: delete failed at h=%d: %s\n", h, tostring(err)))
      return false
    end
    return true
  end

  --- Run one sweep up to (or partially up to) target prune height.
  -- Returns immediately if pruning is disabled / not yet useful.
  -- Bounded by MAX_DELETES_PER_SWEEP to avoid hogging the event loop;
  -- the sync.lua tick will call us again on the next batch of blocks.
  -- @param tip_height number: current chain tip
  -- @return number: number of heights pruned this call (0 = nothing to do)
  function self:maybe_prune(tip_height)
    if not self.automatic then return 0 end
    -- Throttle: only sweep every PRUNE_INTERVAL_BLOCKS unless we have
    -- never run before.
    if self.last_sweep_tip >= 0 and
       tip_height - self.last_sweep_tip < M.PRUNE_INTERVAL_BLOCKS then
      return 0
    end
    local target = self:compute_prune_target(tip_height)
    if not target then return 0 end

    local deleted = 0
    local start_h = self.prune_height + 1
    local end_h = target
    if end_h - start_h + 1 > M.MAX_DELETES_PER_SWEEP then
      end_h = start_h + M.MAX_DELETES_PER_SWEEP - 1
    end
    for h = start_h, end_h do
      self:_delete_block_at_height(h)
      self.prune_height = h
      deleted = deleted + 1
    end
    self.last_sweep_tip = tip_height
    if deleted > 0 then
      print(string.format(
        "[prune] swept heights %d..%d (target=%d, prune_height=%d, tip=%d)",
        start_h, end_h, target, self.prune_height, tip_height))
    end
    return deleted
  end

  --- Force a full prune sweep up to target. Used by --prune=1 manual
  -- mode via a future pruneblockchain RPC, and by tests. Unlike
  -- maybe_prune this ignores the throttle and the per-sweep cap.
  -- @param tip_height number: current chain tip
  -- @param up_to number|nil: highest height to prune (inclusive); if nil,
  --                          uses compute_prune_target(tip_height)
  -- @return number: number of heights pruned
  function self:force_prune(tip_height, up_to)
    if not self.enabled then return 0 end
    local target
    if up_to then
      -- Caller-specified target: still enforce the MIN_BLOCKS_TO_KEEP
      -- floor so we never delete blocks within reorg depth of tip.
      local last_can_prune = (tip_height or 0) - M.MIN_BLOCKS_TO_KEEP
      target = math.min(up_to, last_can_prune)
    else
      target = self:compute_prune_target(tip_height)
    end
    if not target or target <= self.prune_height then return 0 end

    local deleted = 0
    for h = self.prune_height + 1, target do
      self:_delete_block_at_height(h)
      self.prune_height = h
      deleted = deleted + 1
    end
    self.last_sweep_tip = tip_height or self.last_sweep_tip
    return deleted
  end

  --- True if the given height has been pruned and CF.BLOCKS no longer
  -- holds the body. RPC handlers consult this to return the right
  -- "block not available (pruned)" error per Bitcoin Core's
  -- rpc/blockchain.cpp:677.
  function self:is_pruned(height)
    if not self.enabled then return false end
    if not height then return false end
    return height <= self.prune_height
  end

  return self
end

return M
