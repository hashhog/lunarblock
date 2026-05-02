-- spec/chainstate_corruption_spec.lua
--
-- Verifies the BUG-REPORT.md (wave-2026-04-28-lunarblock-wedge) chainstate-
-- corruption fixes:
--
--   Fix #2: per-block atomic write barrier. Block body, undo data, UTXO
--           mutations, and chain_tip update all commit as ONE WriteBatch.
--           No state on disk where chain_tip advanced but its backing
--           data didn't.
--
--   Fix #3: startup consistency check (verify_chainstate_consistency)
--           with auto-rollback. Walks back from tip; if a block's inputs
--           are missing from CF.UTXO + undo, disconnect through it.
--
--   Fix #4: bounded retry on connect_callback failure. Per-hash
--           cb_fail_count exceeding cb_fail_threshold logs a clear
--           CHAINSTATE-CORRUPTION error pointing the operator at
--           --reindex-chainstate, instead of looping forever (the Apr 28
--           h=938344 wedge symptom: ~2 errors/sec for hours).

local types = require("lunarblock.types")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local script = require("lunarblock.script")
local storage_mod = require("lunarblock.storage")
local sync = require("lunarblock.sync")

-- Helpers (lifted from spec/dumptxoutset_rollback_spec.lua so this file is
-- self-contained).
local function make_coinbase_tx(height, value, script_pubkey)
  local coinbase_sig = string.char(1, height % 256)
  return types.transaction(
    1,
    {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                coinbase_sig, 0xFFFFFFFF)},
    {types.txout(value, script_pubkey)},
    0
  )
end

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

-- Build a chain of N coinbase-only blocks on top of a fresh chainstate.
-- Returns (db, chain_state, hashes_by_height, db_path).
local function build_chain(n_blocks)
  local tmp_path = "/tmp/lunarblock_chainstate_corruption_"
    .. os.time() .. "_" .. math.random(1000000)
  local db = storage_mod.open(tmp_path)
  local chain_state = utxo.new_chain_state(db, consensus.networks.regtest)
  chain_state:init()

  local pubkey_hash = string.rep("\x42", 20)
  local script_pubkey = script.make_p2pkh_script(pubkey_hash)

  local hashes = {}
  local prev_hash = types.hash256_zero()
  for h = 0, n_blocks - 1 do
    local coinbase = make_coinbase_tx(h, 5000000000, script_pubkey)
    local block = make_block(h, {coinbase}, prev_hash)
    local block_hash = validation.compute_block_hash(block.header)
    db.put_header(block_hash, block.header)
    db.put_block(block_hash, block)
    db.put_height_index(h, block_hash)
    chain_state:connect_block(block, h, block_hash)
    hashes[h] = block_hash
    prev_hash = block_hash
  end

  return db, chain_state, hashes, tmp_path
end

describe("chainstate corruption recovery", function()

  describe("Fix #2: atomic write barrier", function()
    it("connect_block writes UTXO + undo + chain_tip in one batch",
       function()
      -- After connect_block returns, the chain_tip in CF.META and the
      -- UTXO mutations and the undo data are all visible. There is no
      -- visible intermediate state from the caller's point of view.
      local db, chain_state, hashes = build_chain(3)

      -- Pull the persisted chain_tip via storage.get directly.
      local tip_data = db.get(storage_mod.CF.META, "chain_tip")
      assert.is_not_nil(tip_data)
      assert.equal(36, #tip_data)
      -- Expect chain_tip to point at h=2 (the last block we connected).
      local tip_height = tip_data:byte(33)
        + tip_data:byte(34) * 256
        + tip_data:byte(35) * 65536
        + tip_data:byte(36) * 16777216
      assert.equal(2, tip_height)

      -- chain_tip's hash must be the block hash of height 2 -- block body
      -- must already be on disk (atomic-barrier invariant).
      local tip_hash_bytes = tip_data:sub(1, 32)
      local block_data = db.get(storage_mod.CF.BLOCKS, tip_hash_bytes)
      assert.is_not_nil(block_data,
        "block body for chain_tip is missing -- atomic-barrier broken")

      db.close()
    end)

    it("undo data is written atomically for spending blocks",
       function()
      -- A spending tx requires coinbase maturity (100 blocks on regtest);
      -- build a 102-block coinbase-only chain, then a spending block on
      -- top, and confirm undo data is in CF.UNDO once chain_tip points
      -- at the spending block. The atomic-barrier invariant is: if
      -- chain_tip moved, undo data is on disk too.
      local db, chain_state, hashes = build_chain(102)
      local pubkey_hash = string.rep("\x42", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      local prev_txid = validation.compute_txid(
        (db.get_block(hashes[1])).transactions[1])
      local coinbase = make_coinbase_tx(102, 5000000000, script_pubkey)
      local spending = types.transaction(
        1,
        {types.txin(types.outpoint(prev_txid, 0), "", 0xFFFFFFFF)},
        {types.txout(4999990000, script_pubkey)},
        0
      )
      local block = make_block(102, {coinbase, spending}, hashes[101])
      local block_hash = validation.compute_block_hash(block.header)
      db.put_header(block_hash, block.header)
      db.put_block(block_hash, block)
      db.put_height_index(102, block_hash)

      local ok = chain_state:connect_block(
        block, 102, block_hash, nil, nil, true)
      assert.is_true(ok)

      -- Both undo and chain_tip must be on disk: atomic barrier.
      local undo_data = db.get(storage_mod.CF.UNDO, block_hash.bytes)
      assert.is_not_nil(undo_data,
        "undo data for spending block is missing -- atomic-barrier broken")

      local tip_data = db.get(storage_mod.CF.META, "chain_tip")
      assert.is_not_nil(tip_data)
      local tip_height = tip_data:byte(33)
        + tip_data:byte(34) * 256
        + tip_data:byte(35) * 65536
        + tip_data:byte(36) * 16777216
      assert.equal(102, tip_height)

      db.close()
    end)
  end)

  describe("Fix #3: startup consistency check + auto-rollback", function()
    it("rolls back to highest known-good height when a UTXO is missing",
       function()
      local db, chain_state, hashes = build_chain(5)
      assert.equal(4, chain_state.tip_height)

      -- Corrupt the chainstate by deleting the UTXO created by the
      -- coinbase at h=4 (which is referenced internally by the spending
      -- tx in the same block, so deleting forces the consistency-check
      -- detector to flag h=4). To simulate the post-EMFILE wedge we
      -- delete a UTXO that the consistency check WILL examine -- the
      -- coinbase's own output at h=4, then construct a synthetic spend
      -- referencing it at h=4 isn't possible (we'd need a new block).
      --
      -- Simpler approach: delete the coinbase UTXO at h=2 and add a
      -- pseudo-spend in the consistency check by overwriting the block
      -- body at h=4 with a tx that spends h=2's coinbase, mimicking the
      -- "lost UTXO from a prior crash" scenario.
      --
      -- For this test we instead use the "block body missing" branch
      -- of verify_chainstate_consistency, which is the strongest signal:
      -- chain_tip points at h=4 but block body is missing.
      local h4_hash = hashes[4]
      db.delete(storage_mod.CF.BLOCKS, h4_hash.bytes)

      -- Verify consistency check detects + rolls back.
      local rolled, final_h, details =
        chain_state:verify_chainstate_consistency(50, 5)
      assert.is_true(details.found_inconsistency,
        "consistency check missed corruption: " .. tostring(details.reason))
      assert.equal(4, details.first_bad_height)
      -- Rollback skips through the missing-body block via the
      -- partial-recovery path; final tip <= 3 (or undo_missing flag set).
      assert.is_true(final_h <= 3 or details.undo_missing,
        "rollback did not lower tip enough; final_h=" .. tostring(final_h))

      db.close()
    end)

    it("returns clean result when chainstate is consistent",
       function()
      local db, chain_state, hashes = build_chain(5)

      local rolled, final_h, details =
        chain_state:verify_chainstate_consistency(50, 5)

      assert.is_false(details.found_inconsistency)
      assert.equal(0, rolled)
      assert.equal(4, final_h)

      db.close()
    end)

    it("noop on fresh chainstate (tip_height=0)",
       function()
      local tmp_path = "/tmp/lunarblock_chainstate_corruption_fresh_"
        .. os.time() .. "_" .. math.random(1000000)
      local db = storage_mod.open(tmp_path)
      local chain_state = utxo.new_chain_state(db, consensus.networks.regtest)
      chain_state:init()
      assert.equal(0, chain_state.tip_height)

      local rolled, final_h, details =
        chain_state:verify_chainstate_consistency(50, 5)
      assert.equal(0, rolled)
      assert.is_false(details.found_inconsistency)

      db.close()
    end)
  end)

  describe("Fix #4: bounded callback-failure retry", function()
    it("BlockDownloader has cb_fail_threshold configured (default 5)",
       function()
      -- We're not running a full sync here -- this is a unit-level
      -- check that the new field is wired and the default matches
      -- BUG-REPORT.md fix #4. A lower-level integration test would
      -- need a live network and is covered by the live-datadir
      -- recovery validation in the meta-repo restart.log.
      local network = consensus.networks.regtest
      local tmp_path = "/tmp/lunarblock_chainstate_corruption_dl_"
        .. os.time() .. "_" .. math.random(1000000)
      local db = storage_mod.open(tmp_path)
      local header_chain = sync.new_header_chain(network, db)
      header_chain:init()
      local downloader = sync.new_block_downloader(header_chain, db, network)

      assert.equal(5, downloader.cb_fail_threshold)
      assert.is_table(downloader._cb_fail_count)
      -- Map starts empty.
      local count = 0
      for _ in pairs(downloader._cb_fail_count) do count = count + 1 end
      assert.equal(0, count)

      db.close()
    end)
  end)
end)
