-- test_reorg_atomicity.lua
-- Pattern D verification (multi-block reorg atomicity, 2026-05-05).
--
-- Audit reference:
--   CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md
--
-- This test exercises the new SHARED-batch path in
-- ChainState:accept_side_branch_block: when a side-branch becomes
-- strictly heavier than the active chain and the reorg fires, the
-- entire disconnect+connect sequence MUST commit as a single
-- RocksDB WriteBatch.  Crash mid-reorg → either pre or post state,
-- never partial.
--
-- Test cases:
--
--   1. SINGLE-BATCH:
--        Build A1, A2, A3 on the active chain and B1..B4 on a side
--        branch.  Submit B4 → reorg disconnects A1..A3 and connects
--        B1..B4 (3 disconnects + 4 connects = 7 per-block flushes
--        in the OLD design).  Verify that exactly ONE batch.write()
--        fires during the reorg (the shared-batch commit), NOT 7.
--
--   2. CRASH-PRE-COMMIT:
--        Inject a connect_block failure at the LAST side-branch
--        block (B4) by making its body unreadable from storage.
--        Verify that the abort path leaves on-disk chain_tip at the
--        ORIGINAL A3 tip (not at the partial common-ancestor or
--        partial side-branch position) and that re-querying the
--        UTXO state matches the pre-reorg snapshot.
--
--   3. MEMORY-CAP:
--        Build a side-branch deeper than MAX_REORG_DEPTH (100) and
--        verify accept_side_branch_block rejects with
--        "reorg-depth-exceeded" rather than allocating an unbounded
--        batch.
--
-- Reference (Bitcoin Core): src/validation.cpp Chainstate::DisconnectTip
-- + Chainstate::ConnectTip use a CCoinsViewCache layer over the disk
-- chainstate; partial mutations stay in memory until ActivateBestChain
-- flushes once at the end via FlushStateToDisk.

package.path = "./src/?.lua;" .. package.path
package.cpath = "./lib/?.so;" .. package.cpath

local utxo_mod    = require("lunarblock.utxo")
local validation  = require("lunarblock.validation")
local consensus   = require("lunarblock.consensus")
local types       = require("lunarblock.types")
local crypto      = require("lunarblock.crypto")
local serialize   = require("lunarblock.serialize")
local storage_mod = require("lunarblock.storage")

local pass, fail = 0, 0
local function check(name, cond, detail)
  if cond then
    io.write("PASS: " .. name .. "\n")
    pass = pass + 1
  else
    io.write("FAIL: " .. name .. (detail and (" -- " .. tostring(detail)) or "") .. "\n")
    fail = fail + 1
  end
end

local REGTEST = consensus.networks.regtest

local function tmpdir()
  local path = os.tmpname() .. "_reorg_atomicity"
  os.execute("mkdir -p " .. path)
  return path
end

local function make_coinbase(height, padding_byte)
  local height_enc = validation.encode_bip34_height(height)
  local pad_byte   = padding_byte or 0
  local padding    = string.rep(string.char(pad_byte), 20)
  return {
    version = 1, locktime = 0,
    inputs = {{
      prev_out   = { hash = types.hash256(string.rep("\0",32)), index = 0xFFFFFFFF },
      script_sig = height_enc .. "/LunarBlock/" .. padding,
      sequence   = 0xFFFFFFFF,
      witness    = {},
    }},
    outputs = {{ value = 5000000000, script_pubkey = "\x51" }},
  }
end

local function make_block(prev_hash, height, timestamp, padding_byte)
  local cb = make_coinbase(height, padding_byte)
  local base  = serialize.serialize_transaction(cb, false)
  local total = serialize.serialize_transaction(cb, true)
  cb._cached_base_data    = base
  cb._cached_witness_data = total
  cb._cached_txid         = crypto.hash256_type(base)
  cb._cached_wtxid        = crypto.hash256_type(total)

  local merkle = crypto.compute_merkle_root({cb._cached_txid})
  local header = {
    version = 0x20000000, prev_hash = prev_hash,
    merkle_root = merkle, timestamp = timestamp,
    bits = REGTEST.pow_limit_bits, nonce = 0,
  }
  for n = 0, 0xFFFFFF do
    header.nonce = n
    local h = validation.compute_block_hash(header)
    if string.byte(h.bytes, 32) < 0x80 then break end
  end
  return { header = header, transactions = {cb} }, validation.compute_block_hash(header)
end

local function submit_extending_block(cs, stor, blk, height)
  local bh = validation.compute_block_hash(blk.header)
  local block_data    = serialize.serialize_block(blk)
  local header_data   = serialize.serialize_block_header(blk.header)
  local height_key    = string.char(
    math.floor(height / 16777216) % 256,
    math.floor(height / 65536) % 256,
    math.floor(height / 256) % 256,
    height % 256
  )
  local store_batch_fn = function(batch)
    batch.put(storage_mod.CF.BLOCKS, bh.bytes, block_data)
    batch.put(storage_mod.CF.HEADERS, bh.bytes, header_data)
    batch.put(storage_mod.CF.HEIGHT_INDEX, height_key, bh.bytes)
  end
  local ok, err = cs:accept_block(blk, height, bh, {
    skip_scripts = true,
    nosync = true,
    caller_batch_fn = store_batch_fn,
  })
  return ok, err, bh
end

-- Persist a side-branch block body + header so accept_side_branch_block
-- can find them when walking the side chain backwards.  Mirrors what
-- the original Pattern Z submitblock branch does for B1, B2, B3 before
-- the heaviest sibling triggers the reorg.
local function store_side_branch_block(stor, blk, hash)
  -- Same primitives accept_side_branch_block uses for storage of new
  -- side-branch entries: put_block + put_header.
  stor.put_block(hash, blk)
  stor.put_header(hash, blk.header)
end

-- Wrap storage.batch() so we can count how many batches are created /
-- committed during a single reorg.  We patch only the dbobj returned
-- by storage_mod.open.  Returns a "monitor" table the test can read.
local function install_batch_monitor(stor)
  local monitor = { creates = 0, writes = 0, destroys = 0, last_batch = nil }
  local original_batch = stor.batch
  stor.batch = function(...)
    monitor.creates = monitor.creates + 1
    local b = original_batch(...)
    local original_write = b.write
    local original_destroy = b.destroy
    b.write = function(sync)
      monitor.writes = monitor.writes + 1
      monitor.last_batch = b
      return original_write(sync)
    end
    b.destroy = function()
      monitor.destroys = monitor.destroys + 1
      return original_destroy()
    end
    return b
  end
  return monitor
end

--------------------------------------------------------------------------------
-- Test 1: SINGLE-BATCH
--   Build  A1 → A2 → A3  on active chain, B1 → B2 → B3 → B4 on side branch.
--   Each side block is "submitted" first (stored, no reorg).  Submitting
--   B4 → strictly heavier → triggers the multi-block reorg.
--
--   Pre-fix (per-block batches): 3 disconnect + 4 connect = 7 batch.write
--     calls during the reorg, with a 7-step on-disk window where chain_tip
--     could be at any of {A2, A1, common-ancestor=genesis, B1, B2, B3, B4}.
--   Post-fix (shared batch): exactly 1 batch.write call during the reorg;
--     on-disk chain_tip atomically jumps from A3 to B4.
--------------------------------------------------------------------------------
do
  io.write("\n--- Test 1: SINGLE-BATCH (3-deep disconnect + 4-deep connect) ---\n")
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:connect_genesis()
  local genesis_hash = cs.tip_hash

  -- Active chain: A1, A2, A3.
  local blk_a1, hash_a1 = make_block(genesis_hash, 1, 1500000001, 0xA1)
  assert(submit_extending_block(cs, stor, blk_a1, 1))
  local blk_a2, hash_a2 = make_block(hash_a1, 2, 1500000002, 0xA2)
  assert(submit_extending_block(cs, stor, blk_a2, 2))
  local blk_a3, hash_a3 = make_block(hash_a2, 3, 1500000003, 0xA3)
  assert(submit_extending_block(cs, stor, blk_a3, 3))
  check("test1 setup: tip_height = 3", cs.tip_height == 3)
  check("test1 setup: tip_hash = A3", types.hash256_eq(cs.tip_hash, hash_a3))

  -- Side branch: B1, B2, B3 stored as side-branch (work ≤ active).
  local blk_b1, hash_b1 = make_block(genesis_hash, 1, 1500000010, 0xB1)
  local r1 = cs:accept_side_branch_block(blk_b1, hash_b1, {skip_scripts=true, nosync=true})
  check("test1 setup: B1 stored", r1 == "stored")
  local blk_b2, hash_b2 = make_block(hash_b1, 2, 1500000011, 0xB2)
  local r2 = cs:accept_side_branch_block(blk_b2, hash_b2, {skip_scripts=true, nosync=true})
  check("test1 setup: B2 stored (work tied with A2)", r2 == "stored")
  local blk_b3, hash_b3 = make_block(hash_b2, 3, 1500000012, 0xB3)
  local r3 = cs:accept_side_branch_block(blk_b3, hash_b3, {skip_scripts=true, nosync=true})
  check("test1 setup: B3 stored (work tied with A3)", r3 == "stored")
  check("test1 setup: tip still at A3 before reorg",
    types.hash256_eq(cs.tip_hash, hash_a3))

  -- Install batch monitor BEFORE the reorg-triggering submit.
  local mon = install_batch_monitor(stor)

  -- Submit B4: strictly heavier (4 vs 3) → reorg fires.
  local blk_b4, hash_b4 = make_block(hash_b3, 4, 1500000013, 0xB4)
  local r4, err4 = cs:accept_side_branch_block(blk_b4, hash_b4,
    {skip_scripts=true, nosync=true})
  check("test1: reorg fired (B4 returns 'connected')", r4 == "connected", err4)
  check("test1: tip_height advanced to 4", cs.tip_height == 4)
  check("test1: tip_hash flipped to B4", types.hash256_eq(cs.tip_hash, hash_b4))

  -- THE atomicity assertion: across 3 disconnects + 4 connects we expect
  -- ONE shared-batch commit, not 7.  (One batch.create + one batch.write
  -- + one batch.destroy = the lifecycle of the single shared reorg batch.)
  check("test1 atomicity: exactly 1 batch.write during reorg (got "
    .. tostring(mon.writes) .. ")", mon.writes == 1)
  check("test1 atomicity: exactly 1 batch.create during reorg (got "
    .. tostring(mon.creates) .. ")", mon.creates == 1)
  check("test1 atomicity: shared batch destroyed after commit (got "
    .. tostring(mon.destroys) .. ")", mon.destroys == 1)

  -- And the resulting state must be correct (height-index points at B chain).
  local h1_after = stor.get_hash_by_height(1)
  local h2_after = stor.get_hash_by_height(2)
  local h3_after = stor.get_hash_by_height(3)
  local h4_after = stor.get_hash_by_height(4)
  check("test1 result: height_index[1] = B1",
    h1_after and types.hash256_eq(h1_after, hash_b1))
  check("test1 result: height_index[2] = B2",
    h2_after and types.hash256_eq(h2_after, hash_b2))
  check("test1 result: height_index[3] = B3",
    h3_after and types.hash256_eq(h3_after, hash_b3))
  check("test1 result: height_index[4] = B4",
    h4_after and types.hash256_eq(h4_after, hash_b4))

  -- chain_tip on disk = B4 at height 4.
  local disk_tip_hash, disk_tip_height = stor.get_chain_tip()
  check("test1 result: on-disk chain_tip hash = B4",
    disk_tip_hash and types.hash256_eq(disk_tip_hash, hash_b4))
  check("test1 result: on-disk chain_tip height = 4",
    disk_tip_height == 4)

  stor.close()
  os.execute("rm -rf " .. dir)
end

--------------------------------------------------------------------------------
-- Test 2: CRASH-PRE-COMMIT
--   Build active chain A1, A2, A3.  Persist side-branch B1, B2, B3 as
--   side-branch entries.  Now hide B4 from storage so connect_block on
--   the deepest side-branch entry will fail mid-reorg.
--
--   Wait — this is fiddly because B4 is the block currently being
--   submitted; accept_side_branch_block uses the in-memory `block` arg
--   directly for entry.hash == block_hash.  Instead, hide B1: when the
--   reconnect loop starts at the OLDEST side-branch entry (B1), it
--   storage.get_block(B1) and that returns nil → abort.
--
--   Verify that after abort: on-disk chain_tip == A3 (pre-reorg state),
--   in-memory tip restored to A3 too, and cache.dirty_count == 0 so a
--   subsequent submit doesn't see ghost mutations.
--------------------------------------------------------------------------------
do
  io.write("\n--- Test 2: CRASH-PRE-COMMIT (abort during connect loop) ---\n")
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:connect_genesis()
  local genesis_hash = cs.tip_hash

  local blk_a1, hash_a1 = make_block(genesis_hash, 1, 1500001001, 0xA1)
  assert(submit_extending_block(cs, stor, blk_a1, 1))
  local blk_a2, hash_a2 = make_block(hash_a1, 2, 1500001002, 0xA2)
  assert(submit_extending_block(cs, stor, blk_a2, 2))
  local blk_a3, hash_a3 = make_block(hash_a2, 3, 1500001003, 0xA3)
  assert(submit_extending_block(cs, stor, blk_a3, 3))

  -- B1, B2, B3 stored as side-branch.
  local blk_b1, hash_b1 = make_block(genesis_hash, 1, 1500001010, 0xB1)
  cs:accept_side_branch_block(blk_b1, hash_b1, {skip_scripts=true, nosync=true})
  local blk_b2, hash_b2 = make_block(hash_b1, 2, 1500001011, 0xB2)
  cs:accept_side_branch_block(blk_b2, hash_b2, {skip_scripts=true, nosync=true})
  local blk_b3, hash_b3 = make_block(hash_b2, 3, 1500001012, 0xB3)
  cs:accept_side_branch_block(blk_b3, hash_b3, {skip_scripts=true, nosync=true})
  check("test2 setup: tip still at A3 after side-branch tied",
    types.hash256_eq(cs.tip_hash, hash_a3))

  -- Inject the failure: monkey-patch storage.get_block to return nil
  -- for B1 specifically.  When B4 triggers the reorg and the connect
  -- loop reaches the oldest side-branch entry (B1, since side_chain is
  -- newest-first and the loop iterates side_len → 1), the in-memory
  -- block load goes through self.storage.get_block(entry.hash) for
  -- every entry where entry.hash != block_hash (the new block).  For
  -- B1 != B4 this reads from disk and we make it fail.
  local original_get_block = stor.get_block
  stor.get_block = function(hash)
    if types.hash256_eq(hash, hash_b1) then
      return nil  -- simulate disk read failure mid-reorg
    end
    return original_get_block(hash)
  end

  -- Capture pre-abort UTXO snapshot for state-consistency check.
  local pre_chain_tip_hash, pre_chain_tip_height = stor.get_chain_tip()

  local blk_b4, hash_b4 = make_block(hash_b3, 4, 1500001013, 0xB4)
  local r, err = cs:accept_side_branch_block(blk_b4, hash_b4,
    {skip_scripts=true, nosync=true})

  check("test2: reorg aborted (returns nil)", r == nil)
  check("test2: error mentions reorg-connect-failed",
    err and string.find(err, "reorg-connect-failed", 1, true) ~= nil,
    "got: " .. tostring(err))

  -- Restore the patched function so we can read state cleanly.
  stor.get_block = original_get_block

  -- After abort: in-memory tip restored to A3 (the pre-reorg active tip).
  check("test2 atomicity: in-memory tip_height restored to 3",
    cs.tip_height == 3)
  check("test2 atomicity: in-memory tip_hash restored to A3",
    types.hash256_eq(cs.tip_hash, hash_a3))

  -- On-disk chain_tip MUST NOT have moved (no partial commit).
  local post_chain_tip_hash, post_chain_tip_height = stor.get_chain_tip()
  check("test2 atomicity: on-disk chain_tip unchanged (height = 3)",
    post_chain_tip_height == pre_chain_tip_height)
  check("test2 atomicity: on-disk chain_tip unchanged (hash = A3)",
    post_chain_tip_hash and pre_chain_tip_hash
      and types.hash256_eq(post_chain_tip_hash, pre_chain_tip_hash))

  -- Cache must have no leftover dirty entries from the aborted reorg.
  -- Otherwise a follow-up flush would write phantom UTXO mutations.
  check("test2 atomicity: coin_view.dirty_count == 0 after abort",
    cs.coin_view.dirty_count == 0,
    "got: " .. tostring(cs.coin_view.dirty_count))

  stor.close()
  os.execute("rm -rf " .. dir)
end

--------------------------------------------------------------------------------
-- Test 3: MEMORY-CAP (MAX_REORG_DEPTH = 100)
--   Walking the side chain back > MAX_REORG_DEPTH heights without hitting
--   the active chain returns "reorg-depth-exceeded" rather than
--   accumulating an unbounded WriteBatch in memory.
--
--   We simulate this CHEAPLY without actually building 100+ valid blocks:
--   we exploit the fact that accept_side_branch_block walks back via
--   `cursor_header.prev_hash` looking for a hash on the active chain.
--   If we feed it a header chain that loops/extends past 100 steps
--   without ever matching the active chain, the depth-exceeded branch
--   fires and we never enter the disconnect/connect loop.
--
--   A simple way to trip this: set up an active tip at a low height,
--   then submit a block whose ancestor chain (via header storage) is
--   longer than MAX_REORG_DEPTH.  We don't need the chain to be valid;
--   we just need 101 stored headers in a chain that doesn't intersect
--   the active chain.
--------------------------------------------------------------------------------
do
  io.write("\n--- Test 3: MEMORY-CAP (MAX_REORG_DEPTH=100) ---\n")
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:connect_genesis()
  local genesis_hash = cs.tip_hash

  -- Active chain: just A1.
  local blk_a1, hash_a1 = make_block(genesis_hash, 1, 1500002001, 0xA1)
  assert(submit_extending_block(cs, stor, blk_a1, 1))

  -- Build a synthetic side-branch header chain of length 102 that
  -- doesn't intersect the active chain.  We DON'T mine real PoW here
  -- (too slow); we just craft headers and put_header them into storage
  -- so accept_side_branch_block's storage.get_header walk succeeds.
  -- The test only exercises the depth-walk; we abort before any
  -- consensus check on the header chain.
  --
  -- Each header's prev_hash points back to the previous synthetic
  -- header.  The deepest synthetic header's prev_hash is a random
  -- 32-byte value NOT in storage and NOT genesis — so if MAX_REORG_DEPTH
  -- weren't enforced the walk would terminate with "side-branch-header-gap"
  -- when it tried to load that nonexistent header.  We want the depth
  -- guard to fire FIRST, which means we need exactly > MAX_REORG_DEPTH
  -- headers in the synthetic chain.

  local chain_len = 102  -- > MAX_REORG_DEPTH (100)
  local headers = {}
  local hashes = {}
  -- Deepest synthetic header points to a non-genesis "off-chain" hash
  -- (so the walk can't terminate via active-chain match either).
  local off_chain = types.hash256(string.rep("\xCD", 32))
  local prev = off_chain
  for i = 1, chain_len do
    -- Cheap header: all-zero merkle / nonce.  Stored only so
    -- get_header() returns non-nil during the walk.  The depth guard
    -- never reads consensus fields.
    local header = {
      version = 0x20000000,
      prev_hash = prev,
      merkle_root = types.hash256(string.rep("\0", 32)),
      timestamp = 1500003000 + i,
      bits = REGTEST.pow_limit_bits,
      nonce = i,
    }
    local h = validation.compute_block_hash(header)
    stor.put_header(h, header)
    headers[i] = header
    hashes[i] = h
    prev = h
  end

  -- The newest synthetic header is hashes[chain_len].  Submit a block
  -- whose prev_hash IS the newest synthetic.  accept_side_branch_block
  -- walks back: 1 step (newest synthetic) → 2 steps (one below) → … →
  -- 102 steps.  The MAX_REORG_DEPTH guard caps the walk at 100 and
  -- returns "reorg-depth-exceeded".
  local top_header = headers[chain_len]
  local top_hash = hashes[chain_len]
  -- Build an actual block (with coinbase) whose prev = top_hash so the
  -- function signature matches; the body is never validated because
  -- the walk fails first.
  local blk_deep, hash_deep = make_block(top_hash, chain_len + 1,
    1500004000, 0xDD)
  local r, err = cs:accept_side_branch_block(blk_deep, hash_deep,
    {skip_scripts=true, nosync=true})

  check("test3 cap: deep side-branch rejected", r == nil)
  check("test3 cap: error == 'reorg-depth-exceeded'",
    err == "reorg-depth-exceeded",
    "got: " .. tostring(err))

  -- And the on-disk chain_tip MUST still be A1 (no partial mutation).
  local disk_hash, disk_height = stor.get_chain_tip()
  check("test3 cap: on-disk chain_tip still at A1 (height=1)",
    disk_height == 1 and disk_hash and types.hash256_eq(disk_hash, hash_a1))

  stor.close()
  os.execute("rm -rf " .. dir)
end

io.write(string.format("\n=== %d passed, %d failed ===\n", pass, fail))
os.exit(fail > 0 and 1 or 0)
