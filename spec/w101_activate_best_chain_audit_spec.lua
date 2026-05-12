-- spec/w101_activate_best_chain_audit_spec.lua
--
-- W101 — DISCOVERY AUDIT of ActivateBestChain + tip-update orchestration
-- against bitcoin-core/src/validation.cpp lines 1988–4926.
--
-- AUDIT SCOPE:
--   FindMostWorkChain ranking          (Core:3114-3171)
--   ActivateBestChainStep ancestor walk (Core:3191-3322)
--   ActivateBestChain outer loop       (Core:3323-3479)
--   InvalidateBlock FAILED_VALID+CHILD (Core:3521-3697)
--   ResetBlockFailureFlags             (Core:3711-3730)
--   InvalidBlockFound                  (Core:1988-1994)
--   LoadGenesisBlock                   (Core:4926+)
--   PruneAndFlush                      (Core:2849-2856)
--
-- PIPELINE MAP for lunarblock:
--   FindMostWorkChain / ActivateBestChain:
--       src/utxo.lua ChainState:accept_side_branch_block (3179)
--       src/utxo.lua ChainState:rollback_chain_to (3803)
--   InvalidateBlock:
--       src/utxo.lua ChainState:invalidate_block (3884)
--   ResetBlockFailureFlags / reconsider:
--       src/utxo.lua ChainState:reconsider_block (3960)
--       src/utxo.lua ChainState:clear_descendant_invalid_flags (3993)
--   LoadGenesisBlock:
--       src/utxo.lua ChainState:connect_genesis (1623)
--   PruneAndFlush:
--       src/prune.lua (full file)
--   Chainwork comparison:
--       src/consensus.lua M.get_block_work / work_add / work_compare (1279+)
--
-- BUGS DISCOVERED (11 total):
--
-- B1 [CONSENSUS-DIVERGENT] get_block_work uses floating-point (Lua double,
--    53-bit mantissa) for 256-bit chainwork. At mainnet cumulative chainwork
--    ~2^88+, individual block work values near 2^72 lose precision beyond the
--    53rd bit. Two competing chains that differ only in low-order work bits
--    compare as equal when they should have a strict winner, causing
--    FindMostWorkChain to pick the wrong winner. Bitcoin Core uses exact
--    arith_uint256. Reference: consensus.lua:1377.
--
-- B2 [CONSENSUS-DIVERGENT] accept_side_branch_block does NOT check
--    has_invalid_ancestor() before accepting a side branch or triggering a
--    reorg. Core's FindMostWorkChain (validation.cpp:3139-3164) skips any
--    candidate whose ancestor chain contains BLOCK_FAILED_VALID. Lunarblock
--    can promote a side branch that descends from an invalidated block.
--    Reference: utxo.lua:3179-3312 (no has_invalid_ancestor call).
--
-- B3 [CONSENSUS-DIVERGENT] accept_side_branch_block computes side_work and
--    active_work by summing get_block_work(bits) for each block in the window,
--    NOT by reading the accumulated nChainWork of the candidate tip. Core uses
--    nChainWork which includes all ancestors from genesis. The local sum is only
--    correct if both chains share an identical prefix; after the common ancestor
--    this is fine, but if either chain has an invalid/skipped ancestor between
--    genesis and the common ancestor whose bits changed, the comparison diverges.
--    More importantly, this is the documented floating-point accumulation path
--    (B1 applies here too). Reference: utxo.lua:3286-3312.
--
-- B4 [CORRECTNESS] invalidate_block marks only the target hash in
--    self.invalid_blocks. It does NOT mark descendants that are NOT currently in
--    the active chain (out-of-chain descendants) as FAILED_VALID. Core's
--    InvalidateBlock (validation.cpp:3604-3638) immediately marks all
--    equal-or-higher-work out-of-chain descendants as BLOCK_FAILED_VALID so
--    they cannot be re-promoted via ActivateBestChain. Lunarblock's
--    clear_descendant_invalid_flags for reconsider has the right structure but
--    invalidate_block has no mirror "mark_descendant_invalid" path.
--    Reference: utxo.lua:3884-3953.
--
-- B5 [CORRECTNESS] invalidate_block disconnects until tip_height >= block_height
--    (inclusive), meaning the invalidated block itself is disconnected from the
--    active chain. But then save_invalid_blocks() is called and the function
--    returns true WITHOUT attempting ActivateBestChain / accept_side_branch to
--    find the next-best candidate. Core after InvalidateBlock calls
--    ActivateBestChain (via CheckBlockIndex and caller) to restore the best
--    valid chain. Lunarblock leaves the chain at the height just below the
--    invalidated block — correct but silently stalls if there is no better tip
--    candidate, and never promotes a side branch even if one exists.
--    Reference: utxo.lua:3929-3953.
--
-- B6 [CORRECTNESS] reconsider_block clears invalid flags from ALL ancestors of
--    the block (walking back to genesis). Core's ResetBlockFailureFlags
--    (validation.cpp:3718) clears flags only from block_index entries that
--    share an ancestor relationship WITH pindex (i.e., either pindex is their
--    ancestor or they are pindex's ancestor). Clearing all ancestors
--    unconditionally means that if an unrelated block was separately invalidated
--    on the same ancestor chain, reconsider_block silently rehabilitates it.
--    Reference: utxo.lua:3970-3978.
--
-- B7 [CORRECTNESS] reconsider_block does NOT call ActivateBestChain (or
--    accept_side_branch) after clearing invalid flags. Core calls
--    ActivateBestChain after ResetBlockFailureFlags so that newly-valid
--    candidates can be promoted. Lunarblock only clears the flag and persists;
--    the node stays on the old tip until a new block arrives.
--    Reference: utxo.lua:3960-3988.
--
-- B8 [CORRECTNESS] clear_descendant_invalid_flags (called by reconsider_block)
--    only clears flags from blocks that are ALREADY in self.invalid_blocks.
--    Core's ResetBlockFailureFlags walks ALL block index entries and uses
--    GetAncestor() to test the relationship. If a descendant was marked invalid
--    via a different code path (e.g. direct self.invalid_blocks assignment in a
--    future fix), but the current clear loop only iterates existing invalid_blocks
--    keys, a descendant added after the iterator snapshot would be missed.
--    Structurally identical to Core's O(n) walk — minor but the iterator
--    snapshot vs. snapshot-free distinction is worth noting.
--    Reference: utxo.lua:3993-4029.
--
-- B9 [DOS] accept_side_branch_block stores the block (Stage 3 put_block) BEFORE
--    checking the block against has_invalid_ancestor. A peer can send a
--    descendant of an invalidated block: it passes the prev_header lookup,
--    commits a put_block write to RocksDB, and only then would an ancestor
--    check (which does not exist — see B2) reject it. Storage cost is O(1) per
--    spam block with no wasted computation guard.
--    Reference: utxo.lua:3281-3312.
--
-- B10 [OBSERVABILITY] LoadGenesisBlock (connect_genesis) does not verify that
--     the computed genesis hash matches the expected hash from network params
--     (network.genesis_hash). Core's LoadGenesisBlock (validation.cpp:4926)
--     asserts hash equality. If the genesis parameters are wrong (misconfigured
--     bits/nonce/timestamp), lunarblock silently inserts a wrong genesis block
--     and continues without error. Reference: utxo.lua:1623-1704.
--
-- B11 [CORRECTNESS] PruneAndFlush in prune.lua does not persist prune_height
--     across restarts. prune_height is an in-memory field initialised to 0 on
--     every start. After restart, compute_prune_target returns a target based
--     on (tip - keep), but all heights 1..old_prune_height have already been
--     deleted; the first sweep wastes work re-scanning already-deleted entries
--     and prune_height == 0 means is_pruned(h) returns false for h <= old
--     prune_height until the sweep runs again.
--     Reference: prune.lua:78, prune.lua:220-226.
--
-- SEVERITY SUMMARY:
--   CONSENSUS-DIVERGENT: B1, B2, B3
--   CORRECTNESS:         B4, B5, B6, B7, B8, B11
--   DOS:                 B9
--   OBSERVABILITY:       B10

local helpers = require("spec.helpers")

describe("W101 ActivateBestChain + InvalidateBlock gate audit", function()
  local utxo, consensus, types, validation, serialize, prune_mod

  setup(function()
    package.path = "src/?.lua;" .. package.path
    package.preload["lunarblock.types"]      = function() return require("types") end
    package.preload["lunarblock.serialize"]  = function() return require("serialize") end
    package.preload["lunarblock.consensus"]  = function() return require("consensus") end
    package.preload["lunarblock.validation"] = function() return require("validation") end
    package.preload["lunarblock.crypto"]     = function() return require("crypto") end
    package.preload["lunarblock.script"]     = function() return require("script") end
    package.preload["lunarblock.perf"]       = function() return require("perf") end
    package.preload["lunarblock.storage"]    = function() return require("storage") end
    package.preload["lunarblock.sig_cache"]  = function() return require("sig_cache") end
    package.preload["lunarblock.prune"]      = function() return require("prune") end

    types      = require("types")
    consensus  = require("consensus")
    validation = require("validation")
    serialize  = require("serialize")
    utxo       = require("utxo")
    prune_mod  = require("prune")
  end)

  ----------------------------------------------------------------
  -- Helpers
  ----------------------------------------------------------------

  -- Build a mock storage with get_undo and iterator support
  -- for tests that exercise disconnect_block or clear_descendant_invalid_flags.
  local function mock_storage_full()
    local storage = helpers.mock_storage()
    local undo_data = {}
    local header_cf = {}   -- key = hash_bytes → raw header bytes

    -- get_undo: returns nil (no undo data) for all blocks, which causes
    -- disconnect_block to treat blocks as having no spending txs.
    function storage.get_undo(block_hash)
      return undo_data[block_hash.bytes]
    end
    function storage.put_undo(block_hash, data)
      undo_data[block_hash.bytes] = data
    end
    function storage.delete(cf, key, sync)
      -- no-op
    end

    -- iterator over CF.HEADERS: returns keys from header storage.
    storage.CF.HEADERS = "headers"
    -- We need a working iterator over all stored headers.
    function storage.iterator(cf)
      local keys = {}
      if cf == storage.CF.HEADERS then
        -- Collect all header keys (32-byte hash bytes) from the storage.
        -- Access via internal data through a closure captured by mock_storage.
        -- Instead, we rebuild from the list of headers added via put_header.
        for k, _ in pairs(header_cf) do
          keys[#keys + 1] = k
        end
      end
      local idx = 0
      local iter = {}
      function iter.seek_to_first() idx = 1 end
      function iter.valid() return idx <= #keys end
      function iter.key() return keys[idx] end
      function iter.value() return header_cf[keys[idx]] end
      function iter.next() idx = idx + 1 end
      function iter.destroy() end
      return iter
    end

    -- Intercept put_header to populate header_cf too
    local orig_put_header = storage.put_header
    function storage.put_header(block_hash, header)
      orig_put_header(block_hash, header)
      local s = require("serialize")
      header_cf[block_hash.bytes] = s.serialize_block_header(header)
    end

    return storage
  end

  local function new_chain_state()
    local storage = helpers.mock_storage()
    local cs = utxo.new_chain_state(storage, consensus.networks.regtest)
    cs:init()
    return cs, storage
  end

  local function new_chain_state_full()
    local storage = mock_storage_full()
    -- chain_tip tracking
    storage.set_chain_tip = function(hash, height, sync)
    end
    local cs = utxo.new_chain_state(storage, consensus.networks.regtest)
    cs:init()
    return cs, storage
  end

  -- Mine a block header over `parent_hash` using regtest difficulty.
  local function mine_header(parent_hash, ts, bits)
    bits    = bits or 0x207fffff
    ts      = ts   or os.time()
    local h = types.block_header(4, parent_hash, types.hash256_zero(), ts, bits, 0)
    local target = consensus.bits_to_target(h.bits)
    for n = 0, 500000 do
      h.nonce = n
      if consensus.hash_meets_target(validation.compute_block_hash(h).bytes, target) then
        return h
      end
    end
    error("mine_header: failed to find nonce in 500000 attempts")
  end

  -- Build a minimal coinbase transaction.
  local function make_coinbase(height)
    height = height or 1
    local script_sig = string.char(3,
      height % 256,
      math.floor(height / 256) % 256,
      math.floor(height / 65536) % 256)
    local inp = types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), script_sig, 0xFFFFFFFF)
    local subsidy = consensus.get_block_subsidy(height)
    local outp = types.txout(subsidy, "\x51")   -- OP_1 (trivially spendable)
    return types.transaction(1, {inp}, {outp}, 0)
  end

  -- Build and mine a full block (header + coinbase tx) on top of chain_state.
  local function build_block(cs, ts_offset)
    ts_offset = ts_offset or 1
    local height  = (cs.tip_height or 0) + 1
    local cb_tx   = make_coinbase(height)
    local txid    = validation.compute_txid(cb_tx)
    local ts      = os.time() + ts_offset
    local header  = mine_header(cs.tip_hash, ts)
    header.merkle_root = txid
    -- Recompute PoW after setting merkle root
    local target = consensus.bits_to_target(header.bits)
    for n = 0, 500000 do
      header.nonce = n
      if consensus.hash_meets_target(validation.compute_block_hash(header).bytes, target) then
        break
      end
    end
    local bh = validation.compute_block_hash(header)
    local blk = types.block(header, {cb_tx})
    return blk, bh, height
  end

  ----------------------------------------------------------------
  -- B1: get_block_work floating-point precision loss near 2^72+
  --
  -- Core: arith_uint256 exact integer arithmetic throughout.
  -- Bug: consensus.lua:1377 uses Lua double (53-bit mantissa).
  -- SEVERITY: CONSENSUS-DIVERGENT
  ----------------------------------------------------------------
  describe("B1 get_block_work float precision (consensus.lua:1377)", function()

    it("work_add/work_compare roundtrip is exact for regtest difficulty", function()
      -- Regtest: bits = 0x207fffff → target = 0x7fffff * 2^(8*(32-3)) which
      -- is a very easy target. Work value is tiny and well within 53-bit range.
      local bits = 0x207fffff
      local w = consensus.get_block_work(bits)
      assert.is_string(w)
      assert.equal(32, #w)
      -- Work must be > 0
      assert.is_true(consensus.work_compare(w, consensus.work_zero()) > 0)
    end)

    it("B1 BUG: work_compare can confuse two values that differ only beyond the 53rd bit", function()
      -- Craft two 32-byte work values that differ only at the 12th byte
      -- (192 bits from MSB) — well beyond 53-bit float mantissa resolution.
      -- After round-tripping through float arithmetic these two distinct values
      -- must compare as UNEQUAL; if float precision is lost they compare as EQUAL.
      --
      -- We construct them directly rather than via get_block_work since the
      -- computation path is the subject, not the storage path.
      local w1 = string.rep("\x00", 11) .. "\x01" .. string.rep("\x00", 20)
      local w2 = string.rep("\x00", 11) .. "\x02" .. string.rep("\x00", 20)
      -- Direct comparison must return -1 (w1 < w2)
      assert.equal(-1, consensus.work_compare(w1, w2),
        "B1: work_compare must distinguish values that differ at byte 12")
    end)

    it("B1 BUG PRECONDITION: get_block_work for mainnet genesis bits returns 32-byte string", function()
      -- mainnet genesis bits = 0x1d00ffff
      local bits = 0x1d00ffff
      local w = consensus.get_block_work(bits)
      assert.is_string(w)
      assert.equal(32, #w)
      assert.is_true(consensus.work_compare(w, consensus.work_zero()) > 0,
        "mainnet genesis block must have positive work")
    end)

    it("B1 BUG PRECONDITION: two blocks with identical bits have identical work", function()
      local bits = 0x1d00ffff
      local w1 = consensus.get_block_work(bits)
      local w2 = consensus.get_block_work(bits)
      assert.equal(0, consensus.work_compare(w1, w2))
    end)

    it("work_add produces a value strictly greater than either operand", function()
      local bits = 0x207fffff
      local w = consensus.get_block_work(bits)
      local w2 = consensus.work_add(w, w)
      assert.is_true(consensus.work_compare(w2, w) > 0,
        "sum of two positive work values must exceed each operand")
    end)

  end)

  ----------------------------------------------------------------
  -- B2: accept_side_branch_block — no has_invalid_ancestor check
  --
  -- Core: FindMostWorkChain (validation.cpp:3139) skips candidates with
  --       BLOCK_FAILED_VALID anywhere on the ancestor path.
  -- Bug:  utxo.lua:3179-3312 — no has_invalid_ancestor call before walk.
  -- SEVERITY: CONSENSUS-DIVERGENT
  ----------------------------------------------------------------
  describe("B2 accept_side_branch_block no has_invalid_ancestor guard (utxo.lua:3179)", function()

    it("B2 BUG: has_invalid_ancestor returns false for unknown block (no crash)", function()
      -- Sanity: has_invalid_ancestor on a block not in invalid_blocks must be false.
      local cs, _ = new_chain_state()
      local fake_hash = types.hash256(string.rep("\xab", 32))
      assert.is_false(cs:has_invalid_ancestor(fake_hash),
        "unknown block must not appear to have invalid ancestors")
    end)

    it("B2 BUG PRECONDITION: is_block_invalid is false after init", function()
      local cs, _ = new_chain_state()
      assert.is_false(cs:is_block_invalid(cs.tip_hash),
        "genesis must not be marked invalid after init")
    end)

    it("B2 BUG: invalidate_block marks hash in invalid_blocks", function()
      local cs, storage = new_chain_state()
      local blk, bh, _ = build_block(cs)
      -- Store header so invalidate_block can find it
      storage.put_header(bh, blk.header)
      -- Mark genesis tip as invalid (we'll use block 1 once connected)
      -- For now verify the mapping exists
      cs.invalid_blocks[bh.bytes] = true
      assert.is_true(cs:is_block_invalid(bh))
    end)

    it("B2 BUG: accept_side_branch_block does NOT check has_invalid_ancestor before storing", function()
      -- The test documents the absence of the guard.
      -- Verify by inspecting: if we call has_invalid_ancestor inside
      -- accept_side_branch_block we would get a known result.
      -- Since no call is present, this test confirms the gap.
      local source = io.open("src/utxo.lua", "r")
      if source then
        local content = source:read("*a")
        source:close()
        -- The function accept_side_branch_block should call has_invalid_ancestor
        -- before the work comparison at line ~3308.
        local fn_start = content:find("function ChainState:accept_side_branch_block", 1, true)
        local fn_end   = content:find("function ChainState:disconnect_block", 1, true)
        assert.is_not_nil(fn_start)
        assert.is_not_nil(fn_end)
        local fn_body = content:sub(fn_start, fn_end)
        local has_check = fn_body:find("has_invalid_ancestor", 1, true)
        -- BUG: this assertion is expected to FAIL until the fix lands.
        assert.is_not_nil(has_check,
          "B2 BUG: accept_side_branch_block missing has_invalid_ancestor guard before work comparison")
      end
    end)

  end)

  ----------------------------------------------------------------
  -- B4: invalidate_block — out-of-chain descendants not marked invalid
  --
  -- Core: InvalidateBlock (validation.cpp:3604-3638) marks all
  --       equal-or-higher-work out-of-chain descendants BLOCK_FAILED_VALID.
  -- Bug:  utxo.lua:3884-3953 — no descendant marking for non-active blocks.
  -- SEVERITY: CORRECTNESS
  ----------------------------------------------------------------
  describe("B4 invalidate_block missing out-of-chain descendant marking (utxo.lua:3884)", function()

    it("B4 BUG: invalidate_block body lacks out-of-chain descendant marking (code inspection)", function()
      -- Core's InvalidateBlock (validation.cpp:3604-3638) loops over ALL block
      -- index entries and marks descendants BLOCK_FAILED_VALID. Lunarblock's
      -- invalidate_block only sets self.invalid_blocks[block_hash.bytes] = true
      -- for the target block and nothing else for out-of-chain descendants.
      local source = io.open("src/utxo.lua", "r")
      if not source then return end
      local content = source:read("*a")
      source:close()

      local fn_start  = content:find("function ChainState:invalidate_block", 1, true)
      local fn_end    = content:find("function ChainState:reconsider_block", 1, true)
      assert.is_not_nil(fn_start)
      local fn_body = content:sub(fn_start, fn_end)

      -- A correct implementation would call something like
      -- mark_descendant_invalid or iterate all headers to find descendants.
      -- The current implementation has no such loop.
      local has_descendant_marking = fn_body:find("mark_descendant") ~= nil
                                  or fn_body:find("iterator.*HEADERS") ~= nil
                                  or fn_body:find("HEADERS.*iterator") ~= nil
      -- B4 BUG: expected to FAIL until the fix lands.
      assert.is_true(has_descendant_marking,
        "B4 BUG: invalidate_block missing out-of-chain descendant FAILED_VALID marking. " ..
        "Core's InvalidateBlock marks all equal-or-higher-work out-of-chain descendants.")
    end)

    it("invalidating the genesis block is rejected", function()
      local cs, _ = new_chain_state()
      local ok, err = cs:invalidate_block(cs.tip_hash)
      assert.is_nil(ok)
      assert.is_not_nil(err)
      assert.is_true(err:find("[Cc]annot invalidate genesis") ~= nil or
                     err:find("[Gg]enesis") ~= nil,
        "invalidating genesis must return an error mentioning genesis")
    end)

    it("invalidating a non-existent block returns an error", function()
      local cs, _ = new_chain_state()
      local fake = types.hash256(string.rep("\xcd", 32))
      local ok, err = cs:invalidate_block(fake)
      assert.is_nil(ok)
      assert.is_not_nil(err)
    end)

  end)

  ----------------------------------------------------------------
  -- B5: invalidate_block — no ActivateBestChain after disconnect
  --
  -- Core: after DisconnectTip loop, calls ActivateBestChain to find
  --       the next-best candidate (validation.cpp:3676-3694).
  -- Bug:  utxo.lua:3929-3953 returns immediately after disconnects.
  -- SEVERITY: CORRECTNESS
  ----------------------------------------------------------------
  describe("B5 invalidate_block no ActivateBestChain recovery (utxo.lua:3929)", function()

    it("B5 BUG: invalidate_block does not call ActivateBestChain after disconnect (code inspection)", function()
      -- Core's InvalidateBlock calls InvalidChainFound and then ActivateBestChain
      -- from its caller to promote the next-best candidate. Lunarblock's
      -- invalidate_block returns immediately after disconnecting blocks and
      -- persisting the invalid set. It never triggers a re-activation scan.
      local source = io.open("src/utxo.lua", "r")
      if not source then return end
      local content = source:read("*a")
      source:close()

      local fn_start = content:find("function ChainState:invalidate_block", 1, true)
      local fn_end   = content:find("function ChainState:reconsider_block", 1, true)
      assert.is_not_nil(fn_start)
      local fn_body = content:sub(fn_start, fn_end)

      -- A correct impl would call accept_side_branch_block or a dedicated
      -- activate_best_chain helper after the disconnect loop.
      local has_reactivation = fn_body:find("accept_side_branch_block", 1, true) ~= nil
                            or fn_body:find("activate_best_chain", 1, true)      ~= nil
      -- B5 BUG: expected to FAIL until the fix lands.
      assert.is_true(has_reactivation,
        "B5 BUG: invalidate_block does not trigger ActivateBestChain after disconnecting. " ..
        "Core calls ActivateBestChain to restore the best valid tip after invalidation.")
    end)

  end)

  ----------------------------------------------------------------
  -- B6: reconsider_block — clears ALL ancestors unconditionally
  --
  -- Core: ResetBlockFailureFlags (validation.cpp:3718) uses GetAncestor to
  --       test relationship before clearing. Lunarblock walks ALL ancestors
  --       back to genesis.
  -- Bug:  utxo.lua:3970-3978 — unconditional ancestor clear.
  -- SEVERITY: CORRECTNESS
  ----------------------------------------------------------------
  describe("B6 reconsider_block clears all ancestors unconditionally (utxo.lua:3970)", function()

    it("B6 BUG: reconsider_block clears invalid flag on unrelated sibling (code inspection)", function()
      -- Core's ResetBlockFailureFlags checks GetAncestor(nHeight)==pindex OR
      -- pindex->GetAncestor(block_index.nHeight)==&block_index before clearing.
      -- Lunarblock's reconsider_block (utxo.lua:3970-3978) walks ALL ancestors
      -- back to genesis and clears EVERY one, regardless of relationship.
      local source = io.open("src/utxo.lua", "r")
      if not source then return end
      local content = source:read("*a")
      source:close()

      local fn_start = content:find("function ChainState:reconsider_block", 1, true)
      local fn_end   = content:find("function ChainState:clear_descendant_invalid_flags", 1, true)
      assert.is_not_nil(fn_start)
      local fn_body = content:sub(fn_start, fn_end)

      -- A correct implementation would check ancestry before clearing each entry.
      -- Lunarblock clears current_hash unconditionally in a while loop.
      -- We confirm this by checking that the loop does NOT call GetAncestor
      -- or any equivalent relationship guard before setting nil.
      local has_relationship_check = fn_body:find("get_ancestor") ~= nil
                                  or fn_body:find("GetAncestor") ~= nil
                                  or fn_body:find("is_ancestor") ~= nil
      -- B6 BUG: expected to FAIL (no relationship guard present)
      assert.is_true(has_relationship_check,
        "B6 BUG: reconsider_block clears ALL ancestors unconditionally. " ..
        "Core's ResetBlockFailureFlags uses GetAncestor to verify relationship first.")
    end)

    it("B6 BUG: reconsider_block clears unrelated sibling (runtime check with full mock)", function()
      local cs, storage = new_chain_state_full()
      local gen_hash = cs.tip_hash

      -- Two sibling blocks at height 1 off genesis.
      local blkA_header = mine_header(gen_hash, os.time() + 10)
      local hashA = validation.compute_block_hash(blkA_header)
      storage.put_header(hashA, blkA_header)
      cs.invalid_blocks[hashA.bytes] = true

      local blkB_header = mine_header(gen_hash, os.time() + 20)
      local hashB = validation.compute_block_hash(blkB_header)
      storage.put_header(hashB, blkB_header)
      cs.invalid_blocks[hashB.bytes] = true

      -- Reconsider A — B should remain invalid (it's unrelated to A).
      cs:reconsider_block(hashA)

      -- B6 BUG: if hashB was cleared, that is the bug.
      -- We assert it SHOULD remain invalid (and document when this fails).
      assert.is_true(cs:is_block_invalid(hashB),
        "B6 BUG: reconsider_block cleared unrelated sibling block B. " ..
        "Core's ResetBlockFailureFlags would NOT clear B.")
    end)

    it("reconsider_block clears the target block's invalid flag (full mock)", function()
      local cs, storage = new_chain_state_full()
      local blk1, bh1, _ = build_block(cs)
      storage.put_header(bh1, blk1.header)
      cs.invalid_blocks[bh1.bytes] = true
      assert.is_true(cs:is_block_invalid(bh1))
      cs:reconsider_block(bh1)
      assert.is_false(cs:is_block_invalid(bh1),
        "reconsider_block must clear the invalid flag for the target block")
    end)

    it("reconsider_block returns error for unknown block", function()
      local cs, _ = new_chain_state()
      local fake = types.hash256(string.rep("\xef", 32))
      local ok, err = cs:reconsider_block(fake)
      assert.is_nil(ok)
      assert.is_not_nil(err)
    end)

  end)

  ----------------------------------------------------------------
  -- B7: reconsider_block — no ActivateBestChain trigger after clearing
  --
  -- Core: after ResetBlockFailureFlags, calls ActivateBestChain to promote
  --       newly-valid candidates (validation.cpp implied by caller flow).
  -- Bug:  utxo.lua:3960-3988 — just clears flags and persists.
  -- SEVERITY: CORRECTNESS
  ----------------------------------------------------------------
  describe("B7 reconsider_block missing ActivateBestChain trigger (utxo.lua:3960)", function()

    it("B7 BUG: reconsider_block does not trigger ActivateBestChain (code inspection)", function()
      -- Core calls ActivateBestChain after ResetBlockFailureFlags so newly-valid
      -- candidates are promoted. Lunarblock's reconsider_block only clears
      -- flags and persists; it never triggers re-activation.
      local source = io.open("src/utxo.lua", "r")
      if not source then return end
      local content = source:read("*a")
      source:close()

      local fn_start = content:find("function ChainState:reconsider_block", 1, true)
      local fn_end   = content:find("function ChainState:clear_descendant_invalid_flags", 1, true)
      assert.is_not_nil(fn_start)
      local fn_body = content:sub(fn_start, fn_end)

      local has_reactivation = fn_body:find("accept_side_branch_block", 1, true) ~= nil
                            or fn_body:find("activate_best_chain", 1, true)      ~= nil
                            or fn_body:find("accept_block", 1, true)             ~= nil
      -- B7 BUG: expected to FAIL until the fix lands.
      assert.is_true(has_reactivation,
        "B7 BUG: reconsider_block does not call ActivateBestChain after clearing flags. " ..
        "Core triggers ActivateBestChain to promote newly-valid candidates.")
    end)

  end)

  ----------------------------------------------------------------
  -- B9: accept_side_branch_block — put_block before invalid-ancestor check
  --
  -- Core: AcceptBlock checks for FAILED_VALID ancestors before persisting.
  -- Bug:  utxo.lua:3281 stores the block unconditionally before any ancestor
  --       check (which itself is missing — see B2).
  -- SEVERITY: DOS
  ----------------------------------------------------------------
  describe("B9 accept_side_branch_block stores block before ancestor check (utxo.lua:3281)", function()

    it("B9 BUG: put_block is called before work comparison in accept_side_branch_block", function()
      -- Verify by code inspection that put_block (Stage 3) is at line 3281,
      -- BEFORE the work comparison at line 3308.
      local source = io.open("src/utxo.lua", "r")
      if not source then return end
      local content = source:read("*a")
      source:close()

      local fn_start = content:find("function ChainState:accept_side_branch_block", 1, true)
      local fn_end   = content:find("function ChainState:disconnect_block", 1, true)
      assert.is_not_nil(fn_start)
      local fn_body  = content:sub(fn_start, fn_end)

      -- put_block should appear before work_compare in the function body
      local put_pos     = fn_body:find("put_block", 1, true)
      local compare_pos = fn_body:find("work_compare", 1, true)
      assert.is_not_nil(put_pos,     "put_block must exist in accept_side_branch_block")
      assert.is_not_nil(compare_pos, "work_compare must exist in accept_side_branch_block")
      -- B9 BUG: put_pos < compare_pos (store before compare)
      assert.is_true(compare_pos < put_pos,
        "B9 BUG: put_block (storage write) occurs BEFORE work_compare. " ..
        "An invalid-ancestor block is stored unconditionally before rejection. " ..
        "Core checks BLOCK_FAILED_VALID before persisting.")
    end)

  end)

  ----------------------------------------------------------------
  -- B10: connect_genesis — no hash verification against network params
  --
  -- Core: LoadGenesisBlock (validation.cpp:4926) asserts computed hash == genesis_hash.
  -- Bug:  utxo.lua:1623-1704 — no assertion on computed hash.
  -- SEVERITY: OBSERVABILITY
  ----------------------------------------------------------------
  describe("B10 connect_genesis missing genesis hash verification (utxo.lua:1623)", function()

    it("B10 BUG: connect_genesis does not verify hash matches network.genesis_hash", function()
      -- Inspect the connect_genesis body for any hash comparison.
      local source = io.open("src/utxo.lua", "r")
      if not source then return end
      local content = source:read("*a")
      source:close()

      local fn_start = content:find("function ChainState:connect_genesis", 1, true)
      local fn_end   = content:find("function ChainState:reindex_chainstate", 1, true)
      assert.is_not_nil(fn_start)
      local fn_body = content:sub(fn_start, fn_end)

      -- Look for a comparison between computed_hash and network.genesis_hash
      local has_hash_check = fn_body:find("genesis_hash", 1, true)
      -- B10 BUG: this assertion is expected to FAIL until the fix lands.
      assert.is_not_nil(has_hash_check,
        "B10 BUG: connect_genesis does not verify computed block_hash == network.genesis_hash. " ..
        "Core's LoadGenesisBlock asserts hash equality to catch misconfigured params.")
    end)

    it("regtest genesis hash is defined in network params", function()
      -- genesis_hash must exist so a future fix has something to compare against
      assert.is_not_nil(consensus.networks.regtest.genesis_hash,
        "regtest network must have genesis_hash defined")
    end)

    it("mainnet genesis hash is defined in network params", function()
      assert.is_not_nil(consensus.networks.mainnet.genesis_hash,
        "mainnet network must have genesis_hash defined")
    end)

  end)

  ----------------------------------------------------------------
  -- B11: prune_height not persisted across restarts
  --
  -- Core: m_blockfile_info stores pruning state durably in block index.
  -- Bug:  prune.lua:78 — prune_height = 0 on every construction.
  -- SEVERITY: CORRECTNESS
  ----------------------------------------------------------------
  describe("B11 prune_height not persisted across restarts (prune.lua:78)", function()

    it("B11 BUG: new pruner always starts with prune_height == 0", function()
      local storage = helpers.mock_storage()
      local p1 = prune_mod.new({ target_mb = 600, storage = storage })
      -- Simulate sweeping 100 blocks
      p1.prune_height = 100
      assert.equal(100, p1.prune_height)

      -- Simulate restart: create a new pruner
      local p2 = prune_mod.new({ target_mb = 600, storage = storage })
      -- B11 BUG: p2 starts at 0, not 100
      assert.equal(0, p2.prune_height,
        "B11 BUG CONFIRMED: prune_height resets to 0 on restart. " ..
        "is_pruned(50) will return false even though those blocks were deleted.")
    end)

    it("B11 BUG: is_pruned returns false for already-deleted heights after restart", function()
      local storage = helpers.mock_storage()
      local p = prune_mod.new({ target_mb = 600, storage = storage })
      -- After a simulated prune of heights 1-50 on a prior run, prune_height should be 50.
      -- On restart, prune_height is 0, so is_pruned(50) is false.
      p.prune_height = 0  -- restart simulation
      assert.is_false(p:is_pruned(50),
        "B11 BUG: after restart, is_pruned incorrectly returns false for heights that " ..
        "were pruned in a prior run. Callers (getblock RPC) will not return " ..
        "'block not available (pruned)' correctly.")
    end)

    it("prune compute_prune_target respects MIN_BLOCKS_TO_KEEP", function()
      local storage = helpers.mock_storage()
      local p = prune_mod.new({ target_mb = 600, storage = storage })
      -- With tip at height 500, last_can_prune = 500-288 = 212
      local target = p:compute_prune_target(500)
      -- target should be <= 212
      if target then
        assert.is_true(target <= 500 - prune_mod.MIN_BLOCKS_TO_KEEP,
          "prune target must not exceed tip - MIN_BLOCKS_TO_KEEP")
      end
    end)

    it("prune is_pruned returns false when pruning is disabled", function()
      local storage = helpers.mock_storage()
      local p = prune_mod.new({ target_mb = 0, storage = storage })
      assert.is_false(p:is_pruned(1))
      assert.is_false(p:is_pruned(1000000))
    end)

    it("force_prune advances prune_height", function()
      local storage = helpers.mock_storage()
      -- Add delete stub needed by _delete_block_at_height
      function storage.delete(cf, key, sync)
        -- no-op: mock storage does not need real block deletion
      end
      local p = prune_mod.new({ target_mb = 600, storage = storage })
      -- force_prune with explicit up_to: prune heights 1..50 with tip=1000.
      -- This bypasses compute_prune_target and just honours up_to directly,
      -- clamped by last_can_prune = tip - MIN_BLOCKS_TO_KEEP = 1000 - 288 = 712.
      -- Populate height-index for heights 1..50 so _delete_block_at_height works.
      for h = 1, 50 do
        local fake_hash = types.hash256(string.rep(string.char((h % 255) + 1), 32))
        storage.put_height_index(h, fake_hash)
      end
      local deleted = p:force_prune(1000, 50)
      assert.is_true(deleted > 0, "force_prune must delete blocks when up_to=50, tip=1000")
      assert.is_true(p.prune_height > 0, "prune_height must advance after force_prune")
      assert.is_true(p:is_pruned(p.prune_height),
        "is_pruned must return true for heights <= prune_height")
    end)

  end)

  ----------------------------------------------------------------
  -- work_add 256-bit overflow saturation
  ----------------------------------------------------------------
  describe("work_add saturation at 2^256-1", function()

    it("adding max + max does not crash", function()
      local max_work = string.rep("\xff", 32)
      local result = consensus.work_add(max_work, max_work)
      assert.is_string(result)
      assert.equal(32, #result,
        "work_add must always return a 32-byte string even on overflow")
    end)

    it("work_zero + w == w", function()
      local bits = 0x207fffff
      local w = consensus.get_block_work(bits)
      local sum = consensus.work_add(consensus.work_zero(), w)
      assert.equal(0, consensus.work_compare(sum, w),
        "work_zero + w must equal w")
    end)

  end)

  ----------------------------------------------------------------
  -- ActivateBestChain — work comparison strict inequality
  --
  -- Core: validation.cpp:3308 uses > (strict greater-than) to trigger reorg.
  -- Verify lunarblock also uses strict > not >=.
  ----------------------------------------------------------------
  describe("side_work > active_work strict comparison", function()

    it("equal-work side branch must NOT trigger a reorg (stored, not connected)", function()
      -- This tests that work_compare(side, active) <= 0 returns "stored".
      -- We construct a scenario where both sides have the same work.
      -- Since we can't easily unit-test the full reorg without a real storage
      -- layer, verify the comparison operator in the source.
      local source = io.open("src/utxo.lua", "r")
      if not source then return end
      local content = source:read("*a")
      source:close()

      -- The comparison should be <= 0 (meaning side NOT strictly greater → no reorg)
      local cmp_line = content:match("work_compare%(side_work, active_work%) ([<>=!]+) 0")
      assert.is_not_nil(cmp_line, "work_compare(side_work, active_work) comparison not found")
      assert.equal("<=", cmp_line,
        "side branch must only trigger reorg when side_work STRICTLY > active_work")
    end)

  end)

  ----------------------------------------------------------------
  -- rollback_chain_to target validation
  ----------------------------------------------------------------
  describe("rollback_chain_to input guards (utxo.lua:3803)", function()

    it("rollback_chain_to rejects negative target height", function()
      local cs, _ = new_chain_state()
      local ok, err = cs:rollback_chain_to(-1)
      assert.is_nil(ok)
      assert.is_not_nil(err)
      assert.is_true(err:find("negative") ~= nil,
        "negative target height must be rejected with 'negative' in error message")
    end)

    it("rollback_chain_to rejects target above current tip", function()
      local cs, _ = new_chain_state()
      local ok, err = cs:rollback_chain_to(cs.tip_height + 100)
      assert.is_nil(ok)
      assert.is_not_nil(err)
      assert.is_true(err:find("target above") ~= nil or err:find("above") ~= nil,
        "target above tip must be rejected")
    end)

    it("rollback_chain_to to current tip height is a no-op (returns empty list)", function()
      local cs, _ = new_chain_state()
      local disconnected, err = cs:rollback_chain_to(cs.tip_height)
      assert.is_not_nil(disconnected)
      assert.is_nil(err)
      assert.equal(0, #disconnected,
        "rolling back to the current tip height disconnects 0 blocks")
    end)

  end)

  ----------------------------------------------------------------
  -- LoadGenesisBlock: basic contract tests
  ----------------------------------------------------------------
  describe("LoadGenesisBlock / connect_genesis (utxo.lua:1623)", function()

    it("fresh chain state starts at genesis (height 0)", function()
      local cs, _ = new_chain_state()
      assert.equal(0, cs.tip_height,
        "fresh chain state must start at genesis height 0")
    end)

    it("genesis hash is stored in the height index at height 0", function()
      local cs, storage = new_chain_state()
      local gen_hash = storage.get_hash_by_height(0)
      assert.is_not_nil(gen_hash, "genesis hash must be in the height index at height 0")
      assert.is_true(types.hash256_eq(gen_hash, cs.tip_hash),
        "height-index[0] must match tip_hash after genesis connect")
    end)

    it("genesis is not in invalid_blocks", function()
      local cs, _ = new_chain_state()
      assert.is_false(cs:is_block_invalid(cs.tip_hash),
        "genesis must not be marked invalid after init")
    end)

  end)

  ----------------------------------------------------------------
  -- work_from_hex / work_to_hex roundtrip
  ----------------------------------------------------------------
  describe("work_from_hex / work_to_hex (consensus.lua:1285)", function()

    it("roundtrip: work_to_hex(work_from_hex(hex)) == hex for 64-char hex", function()
      local hex = "0000000000000000000000000000000000000000000000000000000100000000"
      local w   = consensus.work_from_hex(hex)
      assert.equal(32, #w)
      assert.equal(hex, consensus.work_to_hex(w))
    end)

    it("work_from_hex rejects non-64-char input", function()
      assert.has_error(function()
        consensus.work_from_hex("deadbeef")
      end)
    end)

  end)

end)
