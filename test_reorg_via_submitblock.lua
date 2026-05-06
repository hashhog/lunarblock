-- test_reorg_via_submitblock.lua
-- Pattern Z fix verification (2026-05-06).  See
--   CORE-PARITY-AUDIT/_reorg-via-submitblock-fleet-result-2026-05-05.md
-- for the cross-impl context.  This test exercises the NEW
-- ChainState:accept_side_branch_block path added today:
--
--   1. A block whose parent IS the active tip → normal connect_block,
--      no side-branch entry into the new path.
--   2. A block whose parent is NOT the active tip but IS in storage and
--      whose CHAIN IS NOT YET HEAVIER → stored as side-branch, tip
--      unchanged.
--   3. A block that EXTENDS that side-branch and pushes its cumulative
--      work strictly above the active chain → REORG: rollback to common
--      ancestor + connect side-branch oldest-first.  Active tip flips
--      to the side-branch tip.
--
-- This is the lunarblock unit-test analog of
--   tools/diff-test-corpus/regression/reorg-via-submitblock
-- which builds 2 vs 3 blocks.  Here we build 1 vs 2 so the test stays
-- self-contained (genesis + one mined fork-block on each side, then a
-- second B-side block to trigger the flip).
--
-- Reference (Bitcoin Core): src/validation.cpp ActivateBestChain.

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
  local path = os.tmpname() .. "_reorg_via_submitblock"
  os.execute("mkdir -p " .. path)
  return path
end

-- Build a valid coinbase tx for the given height.  Padding ensures the
-- serialized tx clears the MIN_TX_SIZE=60 floor (Core consensus rule).
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

-- Build and PoW-mine a regtest block; padding_byte differentiates side
-- branches at the same height (different coinbase scriptSig → different
-- merkle root → different block hash).
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

-- Mirror what submitblock does for a tip-extending block: validate +
-- accept_block + persist header / block / height-index in the connect's
-- atomic batch.
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
    skip_scripts = true,  -- regtest scaffolding: scripts irrelevant for this path
    nosync = true,
    caller_batch_fn = store_batch_fn,
  })
  return ok, err, bh
end

--------------------------------------------------------------------------------
-- Test scenario
--   genesis  ──►  A1 (h=1, ts=T1)
--      │
--      └──►  B1 (h=1, ts=T1+1)  ──►  B2 (h=2, ts=T1+2)
--
-- Step 1: connect A1 normally (becomes active tip).
-- Step 2: side-branch B1 — submitted with prev = genesis (NOT active tip).
--         Pre-fix: rejected as "inconclusive", never stored.
--         Post-fix: stored as side-branch; chain B work == chain A work
--         (one block each), so no reorg fires; tip stays at A1.
-- Step 3: side-branch B2 — submitted with prev = B1.  Now chain B has 2
--         blocks vs chain A's 1 → strictly heavier → REORG fires.
--         Active tip flips from A1 to B2.
--------------------------------------------------------------------------------
do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:connect_genesis()
  local genesis_hash = cs.tip_hash
  check("setup: genesis connected at h=0", cs.tip_height == 0)

  -- Step 1: A1 extends genesis → normal best-chain accept.
  local blk_a1, hash_a1 = make_block(genesis_hash, 1, 1296688700, 0xA1)
  local ok_a1, err_a1 = submit_extending_block(cs, stor, blk_a1, 1)
  check("step 1: A1 connected as best chain", ok_a1 == true, err_a1)
  check("step 1: tip_height = 1", cs.tip_height == 1)
  check("step 1: tip_hash = A1", types.hash256_eq(cs.tip_hash, hash_a1))

  -- Step 2: B1 — same height as A1 but different padding → different
  -- coinbase → different hash.  Submitted via the side-branch path.
  local blk_b1, hash_b1 = make_block(genesis_hash, 1, 1296688701, 0xB1)
  -- Sanity: B1 ≠ A1 (different timestamp + padding ensures unique merkle).
  check("step 2: B1 hash differs from A1", not types.hash256_eq(hash_b1, hash_a1))

  -- Pre-fix this branch returned "inconclusive" without storing the block.
  -- Post-fix accept_side_branch_block stores it and returns "stored"
  -- because total work A == total work B (one block at the same difficulty).
  local sb_result, sb_err = cs:accept_side_branch_block(blk_b1, hash_b1, {
    skip_scripts = true, nosync = true,
  })
  check("step 2: B1 accepted as side-branch (work tied → not flipped)",
    sb_result == "stored", sb_err)
  check("step 2: tip still at A1 after B1",
    types.hash256_eq(cs.tip_hash, hash_a1))
  -- B1 must be persisted in storage even when it's not the active chain.
  local stored_b1 = stor.get(storage_mod.CF.BLOCKS, hash_b1.bytes)
  check("step 2: B1 block body persisted under BLOCKS CF",
    stored_b1 ~= nil and #stored_b1 > 0)
  local stored_b1_hdr = stor.get(storage_mod.CF.HEADERS, hash_b1.bytes)
  check("step 2: B1 header persisted under HEADERS CF",
    stored_b1_hdr ~= nil and #stored_b1_hdr == 80)

  -- Step 3: B2 extends B1 → side-branch is now strictly heavier (2 > 1).
  -- accept_side_branch_block must fire the reorg and flip tip to B2.
  local blk_b2, hash_b2 = make_block(hash_b1, 2, 1296688702, 0xB2)
  local sb_result2, sb_err2 = cs:accept_side_branch_block(blk_b2, hash_b2, {
    skip_scripts = true, nosync = true,
  })
  check("step 3: B2 triggers reorg (returns 'connected')",
    sb_result2 == "connected", sb_err2)
  check("step 3: tip_height advanced to 2", cs.tip_height == 2)
  check("step 3: tip_hash flipped to B2",
    types.hash256_eq(cs.tip_hash, hash_b2))
  -- Height-index must now point to B-chain hashes at heights 1 and 2.
  local h1_after = stor.get_hash_by_height(1)
  check("step 3: height_index[1] = B1 (rewritten by reorg)",
    h1_after and types.hash256_eq(h1_after, hash_b1))
  local h2_after = stor.get_hash_by_height(2)
  check("step 3: height_index[2] = B2",
    h2_after and types.hash256_eq(h2_after, hash_b2))

  stor.close()
  os.execute("rm -rf " .. dir)
end

--------------------------------------------------------------------------------
-- Test scenario: true orphan (parent header absent from storage).
-- Should return ("nil", "unknown-parent") so submitblock surfaces
-- "inconclusive" per BIP-22.
--------------------------------------------------------------------------------
do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:connect_genesis()

  -- Build a block whose parent is a random hash (NOT in storage).
  local fake_parent = types.hash256(string.rep("\xde", 32))
  local blk_orphan, hash_orphan = make_block(fake_parent, 1, 1296688705, 0xFA)
  local sb_result, sb_err = cs:accept_side_branch_block(blk_orphan, hash_orphan, {
    skip_scripts = true, nosync = true,
  })
  check("orphan: returns nil result", sb_result == nil)
  check("orphan: error == 'unknown-parent'", sb_err == "unknown-parent",
    "got: " .. tostring(sb_err))

  stor.close()
  os.execute("rm -rf " .. dir)
end

io.write(string.format("\n=== %d passed, %d failed ===\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
