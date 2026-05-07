-- test_filterindex_revert_on_reorg.lua
-- BIP-157 Phase 2 verification (2026-05-07).  See
--   bitcoin-core/src/index/blockfilterindex.cpp::CustomRemove
-- for the reference behavior.  Pre-fix, lunarblock's blockfilter
-- module had a stand-alone disconnect_block that issued its OWN
-- self.storage.batch() — never plumbed into ChainState's reorg path,
-- and not atomic with chain_tip.  673dec7 wired the index for REST
-- reads; this wave wires the reorg-aware rollback so a multi-block
-- reorg disconnects + connects all filter entries inside the same
-- shared RocksDB batch as the UTXO/undo/chain_tip ops (Pattern D
-- atomicity, per 4e4cdeda).
--
-- Sibling to test_txindex_revert_on_reorg.lua (Pattern C0).
--
-- Reference (Bitcoin Core): src/index/blockfilterindex.cpp's
--   CustomAppend / CustomRemove via BaseIndex::BlockConnected /
--   BlockDisconnected.
--   m_last_header rewinds to ReadFilterHeader(height-1, prev_hash).

package.path = "./src/?.lua;" .. package.path
package.cpath = "./lib/?.so;" .. package.cpath

local utxo_mod    = require("lunarblock.utxo")
local validation  = require("lunarblock.validation")
local consensus   = require("lunarblock.consensus")
local types       = require("lunarblock.types")
local crypto      = require("lunarblock.crypto")
local serialize   = require("lunarblock.serialize")
local storage_mod = require("lunarblock.storage")
local blockfilter = require("lunarblock.blockfilter")

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
  local path = os.tmpname() .. "_filter_revert"
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

local function encode_height_be(h)
  return string.char(
    math.floor(h / 16777216) % 256,
    math.floor(h / 65536) % 256,
    math.floor(h / 256) % 256,
    h % 256
  )
end

local function decode_filter_blob(blob)
  if not blob or #blob < 64 then return nil end
  return {
    filter_hash   = blob:sub(1, 32),
    filter_header = blob:sub(33, 64),
  }
end

local function read_last_header(stor)
  return stor.get(storage_mod.CF.META, "filterindex_last_header")
end

local function read_best_height(stor)
  local raw = stor.get(storage_mod.CF.META, "filterindex_height")
  if not raw or #raw ~= 4 then return nil end
  return raw:byte(1) + raw:byte(2) * 256 +
         raw:byte(3) * 65536 + raw:byte(4) * 16777216
end

--------------------------------------------------------------------------------
-- Test 1: filter index disabled (default) — connect_block must NOT touch
-- CF.BLOCK_FILTER, CF.BLOCK_FILTER_HEIGHT, or filterindex_* META keys.
-- This is the live-mainnet path; we don't want any behavior change for
-- a node started without --blockfilterindex.
--------------------------------------------------------------------------------
do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  -- filterindex_enabled stays false (default)
  cs:connect_genesis()
  local genesis_hash = cs.tip_hash

  local blk_a1, hash_a1 = make_block(genesis_hash, 1, 1296688700, 0xA1)
  local ok_a1, err_a1 = submit_extending_block(cs, stor, blk_a1, 1)
  check("disabled: A1 connected", ok_a1 == true, err_a1)

  local filter_blob = stor.get(storage_mod.CF.BLOCK_FILTER, hash_a1.bytes)
  check("disabled: A1 filter NOT written", filter_blob == nil)
  local height_idx = stor.get(storage_mod.CF.BLOCK_FILTER_HEIGHT,
    encode_height_be(1))
  check("disabled: A1 height index NOT written", height_idx == nil)
  check("disabled: filterindex_last_header NOT written",
    read_last_header(stor) == nil)
  check("disabled: filterindex_height NOT written",
    read_best_height(stor) == nil)

  stor.close()
  os.execute("rm -rf " .. dir)
end

--------------------------------------------------------------------------------
-- Test 2: filter index enabled — happy path on the best chain.
--   genesis ──► A1 (h=1) ──► A2 (h=2)
-- After connect, both blocks must have filter entries with the correct
-- chained header: header[i] = hash256(filter_hash[i] || header[i-1]),
-- header[0_seed] = 32 zero bytes.
--------------------------------------------------------------------------------
do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:set_filterindex_enabled(true)
  check("enabled: filterindex_enabled flag is true",
    cs.filterindex_enabled == true)
  cs:connect_genesis()
  local genesis_hash = cs.tip_hash

  local blk_a1, hash_a1 = make_block(genesis_hash, 1, 1296688700, 0xA1)
  local ok_a1, err_a1 = submit_extending_block(cs, stor, blk_a1, 1)
  check("enabled: A1 connected", ok_a1 == true, err_a1)

  local blob_a1 = stor.get(storage_mod.CF.BLOCK_FILTER, hash_a1.bytes)
  check("enabled: A1 filter blob present", blob_a1 ~= nil)
  local hi_a1 = stor.get(storage_mod.CF.BLOCK_FILTER_HEIGHT,
    encode_height_be(1))
  check("enabled: A1 height index → A1 hash",
    hi_a1 ~= nil and hi_a1 == hash_a1.bytes)

  local parsed_a1 = decode_filter_blob(blob_a1)
  check("enabled: A1 filter blob >= 64 bytes (filter_hash || filter_header)",
    parsed_a1 ~= nil)

  -- Recompute expected filter header from filter_hash and zero seed.
  local zero_header = types.hash256_zero()
  local expect_a1_header = blockfilter.compute_filter_header(
    types.hash256(parsed_a1.filter_hash), zero_header)
  check("enabled: A1 filter_header chained from zero seed",
    parsed_a1.filter_header == expect_a1_header.bytes)
  check("enabled: filterindex_last_header == A1 filter_header",
    read_last_header(stor) == parsed_a1.filter_header)
  check("enabled: filterindex_height == 1",
    read_best_height(stor) == 1)

  -- Extend with A2.  Header chains onto A1's header.
  local blk_a2, hash_a2 = make_block(hash_a1, 2, 1296688701, 0xA2)
  local ok_a2, err_a2 = submit_extending_block(cs, stor, blk_a2, 2)
  check("enabled: A2 connected", ok_a2 == true, err_a2)

  local blob_a2 = stor.get(storage_mod.CF.BLOCK_FILTER, hash_a2.bytes)
  local parsed_a2 = decode_filter_blob(blob_a2)
  check("enabled: A2 filter blob present", parsed_a2 ~= nil)
  local expect_a2_header = blockfilter.compute_filter_header(
    types.hash256(parsed_a2.filter_hash),
    types.hash256(parsed_a1.filter_header))
  check("enabled: A2 filter_header chained from A1 filter_header",
    parsed_a2.filter_header == expect_a2_header.bytes)
  check("enabled: filterindex_last_header advanced to A2 filter_header",
    read_last_header(stor) == parsed_a2.filter_header)
  check("enabled: filterindex_height advanced to 2",
    read_best_height(stor) == 2)

  stor.close()
  os.execute("rm -rf " .. dir)
end

--------------------------------------------------------------------------------
-- Test 3: BIP-157 Phase 2 — filter rewind on reorg.
--   genesis  ──►  A1 (h=1)
--      │
--      └──►  B1 (h=1)  ──►  B2 (h=2)
--
-- After A1 connects, A1's filter is indexed.  After B2 triggers a
-- reorg, A1 disconnects (filter entries deleted, last_header rewound to
-- zero seed), then B1+B2 connect and their filters land with header
-- chained from the rewound seed.  Critically, this MUST happen inside
-- the same Pattern D atomic batch — not a sequence of independent
-- batch.write() calls — so a crash mid-reorg can't surface a chainstate
-- where chain_tip has flipped to B2 but the filter index still claims
-- A1 was the last indexed block.
--------------------------------------------------------------------------------
do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:set_filterindex_enabled(true)
  cs:connect_genesis()
  local genesis_hash = cs.tip_hash

  -- Step 1: A1 extends genesis.  Filter indexed.
  local blk_a1, hash_a1 = make_block(genesis_hash, 1, 1296688700, 0xA1)
  local ok_a1 = submit_extending_block(cs, stor, blk_a1, 1)
  check("revert: A1 connected", ok_a1 == true)

  local blob_a1_pre = stor.get(storage_mod.CF.BLOCK_FILTER, hash_a1.bytes)
  check("revert: A1 filter indexed pre-reorg", blob_a1_pre ~= nil)
  local last_header_pre = read_last_header(stor)
  check("revert: filterindex_last_header points at A1 pre-reorg",
    last_header_pre == decode_filter_blob(blob_a1_pre).filter_header)
  check("revert: filterindex_height == 1 pre-reorg",
    read_best_height(stor) == 1)

  -- Step 2: B1 stored as side-branch (work tied → no reorg yet).
  local blk_b1, hash_b1 = make_block(genesis_hash, 1, 1296688701, 0xB1)
  local sb1, sb1_err = cs:accept_side_branch_block(blk_b1, hash_b1, {
    skip_scripts = true, nosync = true,
  })
  check("revert: B1 stored as side-branch", sb1 == "stored", sb1_err)
  -- B1 is NOT on the active chain — filter must NOT be indexed.
  local b1_blob_before = stor.get(storage_mod.CF.BLOCK_FILTER, hash_b1.bytes)
  check("revert: B1 filter NOT yet indexed (B1 is side-branch)",
    b1_blob_before == nil)

  -- Step 3: B2 extends B1 → reorg fires.  A1 disconnects, B1+B2 connect.
  local blk_b2, hash_b2 = make_block(hash_b1, 2, 1296688702, 0xB2)
  local sb2, sb2_err = cs:accept_side_branch_block(blk_b2, hash_b2, {
    skip_scripts = true, nosync = true,
  })
  check("revert: B2 triggers reorg", sb2 == "connected", sb2_err)
  check("revert: tip flipped to B2", types.hash256_eq(cs.tip_hash, hash_b2))

  -- Phase 2 invariant #1: A1's filter entries must be DELETED.
  local blob_a1_post = stor.get(storage_mod.CF.BLOCK_FILTER, hash_a1.bytes)
  check("revert: A1 filter blob DELETED post-reorg",
    blob_a1_post == nil,
    "leaked blob size: " .. tostring(blob_a1_post and #blob_a1_post))

  -- Phase 2 invariant #2: B1+B2 filters ARE indexed.
  local blob_b1 = stor.get(storage_mod.CF.BLOCK_FILTER, hash_b1.bytes)
  check("revert: B1 filter indexed after reorg-connect", blob_b1 ~= nil)
  local blob_b2 = stor.get(storage_mod.CF.BLOCK_FILTER, hash_b2.bytes)
  check("revert: B2 filter indexed after reorg-connect", blob_b2 ~= nil)

  -- Phase 2 invariant #3: height index now points at B1 / B2.
  local hi1 = stor.get(storage_mod.CF.BLOCK_FILTER_HEIGHT,
    encode_height_be(1))
  check("revert: filter height index at h=1 → B1 (NOT A1)",
    hi1 ~= nil and hi1 == hash_b1.bytes,
    "got " .. tostring(hi1 and #hi1))
  local hi2 = stor.get(storage_mod.CF.BLOCK_FILTER_HEIGHT,
    encode_height_be(2))
  check("revert: filter height index at h=2 → B2",
    hi2 ~= nil and hi2 == hash_b2.bytes)

  -- Phase 2 invariant #4: filterindex_last_header points at B2's
  -- filter_header — meaning the rewind to zero seed (after A1
  -- disconnect) and the re-chain through B1, B2 all happened.
  local parsed_b1 = decode_filter_blob(blob_b1)
  local parsed_b2 = decode_filter_blob(blob_b2)
  -- B1 chains from zero (rewound from A1 disconnect → zero seed at h=0).
  local zero_header = types.hash256_zero()
  local expect_b1_header = blockfilter.compute_filter_header(
    types.hash256(parsed_b1.filter_hash), zero_header)
  check("revert: B1 filter_header chained from rewound zero seed",
    parsed_b1.filter_header == expect_b1_header.bytes)
  -- B2 chains from B1's filter_header.
  local expect_b2_header = blockfilter.compute_filter_header(
    types.hash256(parsed_b2.filter_hash),
    types.hash256(parsed_b1.filter_header))
  check("revert: B2 filter_header chained from B1 filter_header",
    parsed_b2.filter_header == expect_b2_header.bytes)
  check("revert: filterindex_last_header == B2 filter_header",
    read_last_header(stor) == parsed_b2.filter_header)
  check("revert: filterindex_height == 2 post-reorg",
    read_best_height(stor) == 2)

  stor.close()
  os.execute("rm -rf " .. dir)
end

--------------------------------------------------------------------------------
-- Test 4: Toggling filterindex_enabled at runtime takes effect immediately.
-- Defense against a regression that silently caches the flag at
-- constructor time (mirrors test_txindex_revert_on_reorg.lua test 4).
--------------------------------------------------------------------------------
do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:connect_genesis()
  local genesis_hash = cs.tip_hash

  -- Block 1 connects with filter index OFF.
  local blk1, hash1 = make_block(genesis_hash, 1, 1296688710, 0x10)
  submit_extending_block(cs, stor, blk1, 1)
  check("toggle: blk1 (off) NOT indexed",
    stor.get(storage_mod.CF.BLOCK_FILTER, hash1.bytes) == nil)
  check("toggle: filterindex_height NOT written",
    read_best_height(stor) == nil)

  -- Toggle ON; block 2 must be indexed.
  cs:set_filterindex_enabled(true)
  local blk2, hash2 = make_block(hash1, 2, 1296688711, 0x20)
  submit_extending_block(cs, stor, blk2, 2)
  check("toggle: blk2 (on) IS indexed",
    stor.get(storage_mod.CF.BLOCK_FILTER, hash2.bytes) ~= nil)
  -- And blk1 stays unindexed; toggling does not retroactively populate.
  check("toggle: blk1 still NOT indexed after toggle",
    stor.get(storage_mod.CF.BLOCK_FILTER, hash1.bytes) == nil)
  check("toggle: filterindex_height now == 2",
    read_best_height(stor) == 2)

  -- Toggle OFF; block 3 must NOT be indexed.
  cs:set_filterindex_enabled(false)
  local blk3, hash3 = make_block(hash2, 3, 1296688712, 0x30)
  submit_extending_block(cs, stor, blk3, 3)
  check("toggle: blk3 (off again) NOT indexed",
    stor.get(storage_mod.CF.BLOCK_FILTER, hash3.bytes) == nil)
  -- blk2 entry is preserved across the toggle.
  check("toggle: blk2 entry preserved across toggle",
    stor.get(storage_mod.CF.BLOCK_FILTER, hash2.bytes) ~= nil)

  stor.close()
  os.execute("rm -rf " .. dir)
end

--------------------------------------------------------------------------------
-- Test 5: Pattern D atomic envelope — filter ops appended to the SAME
-- shared reorg_batch as UTXO/undo/chain_tip.  We can't easily inspect
-- the batch internals from a unit test, but we CAN verify the post-
-- commit invariants that only hold if the writes were atomic with
-- chain_tip:
--   * After accept_side_branch_block returns "connected", filter
--     state is fully consistent with the new tip (chain_tip == B2 AND
--     filter_height == 2 AND height_index[1] == B1).
--   * No half-rewound state — A1's filter is gone AND B1's filter is
--     present.  (If filter writes were issued OUTSIDE the shared
--     batch, an aborted reorg would leave A1 filter still present
--     after the rollback restore.)
--------------------------------------------------------------------------------
do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:set_filterindex_enabled(true)
  cs:connect_genesis()
  local g = cs.tip_hash

  -- Build a 2-deep best chain A1→A2.
  local blk_a1, hash_a1 = make_block(g, 1, 1296688800, 0xA1)
  submit_extending_block(cs, stor, blk_a1, 1)
  local blk_a2, hash_a2 = make_block(hash_a1, 2, 1296688801, 0xA2)
  submit_extending_block(cs, stor, blk_a2, 2)

  -- Stage a 3-deep side-branch B1→B2→B3.
  local blk_b1, hash_b1 = make_block(g, 1, 1296688802, 0xB1)
  cs:accept_side_branch_block(blk_b1, hash_b1, { skip_scripts = true, nosync = true })
  local blk_b2, hash_b2 = make_block(hash_b1, 2, 1296688803, 0xB2)
  cs:accept_side_branch_block(blk_b2, hash_b2, { skip_scripts = true, nosync = true })
  local blk_b3, hash_b3 = make_block(hash_b2, 3, 1296688804, 0xB3)
  local r3, r3_err = cs:accept_side_branch_block(blk_b3, hash_b3,
    { skip_scripts = true, nosync = true })
  check("atomic: deep reorg fires (B3 connected)", r3 == "connected", r3_err)
  check("atomic: tip flipped to B3", types.hash256_eq(cs.tip_hash, hash_b3))

  -- A1 + A2 filters DELETED (Pattern D atomic rewind across multiple blocks).
  check("atomic: A1 filter deleted (multi-block reorg)",
    stor.get(storage_mod.CF.BLOCK_FILTER, hash_a1.bytes) == nil)
  check("atomic: A2 filter deleted (multi-block reorg)",
    stor.get(storage_mod.CF.BLOCK_FILTER, hash_a2.bytes) == nil)
  -- B1 + B2 + B3 filters PRESENT.
  check("atomic: B1 filter present", stor.get(storage_mod.CF.BLOCK_FILTER, hash_b1.bytes) ~= nil)
  check("atomic: B2 filter present", stor.get(storage_mod.CF.BLOCK_FILTER, hash_b2.bytes) ~= nil)
  check("atomic: B3 filter present", stor.get(storage_mod.CF.BLOCK_FILTER, hash_b3.bytes) ~= nil)
  -- height index points at the B-chain.
  check("atomic: height[1] → B1",
    stor.get(storage_mod.CF.BLOCK_FILTER_HEIGHT, encode_height_be(1))
      == hash_b1.bytes)
  check("atomic: height[2] → B2",
    stor.get(storage_mod.CF.BLOCK_FILTER_HEIGHT, encode_height_be(2))
      == hash_b2.bytes)
  check("atomic: height[3] → B3",
    stor.get(storage_mod.CF.BLOCK_FILTER_HEIGHT, encode_height_be(3))
      == hash_b3.bytes)
  check("atomic: filterindex_height == 3 (best B-chain)",
    read_best_height(stor) == 3)
  -- last_header chained through B1→B2→B3 from zero seed (genesis-rewound).
  local parsed_b1 = decode_filter_blob(stor.get(storage_mod.CF.BLOCK_FILTER, hash_b1.bytes))
  local parsed_b2 = decode_filter_blob(stor.get(storage_mod.CF.BLOCK_FILTER, hash_b2.bytes))
  local parsed_b3 = decode_filter_blob(stor.get(storage_mod.CF.BLOCK_FILTER, hash_b3.bytes))
  local h_b1 = blockfilter.compute_filter_header(
    types.hash256(parsed_b1.filter_hash), types.hash256_zero())
  local h_b2 = blockfilter.compute_filter_header(
    types.hash256(parsed_b2.filter_hash), h_b1)
  local h_b3 = blockfilter.compute_filter_header(
    types.hash256(parsed_b3.filter_hash), h_b2)
  check("atomic: B1 filter_header == hash256(filter_hash || zero)",
    parsed_b1.filter_header == h_b1.bytes)
  check("atomic: B2 filter_header chains onto B1",
    parsed_b2.filter_header == h_b2.bytes)
  check("atomic: B3 filter_header chains onto B2",
    parsed_b3.filter_header == h_b3.bytes)
  check("atomic: filterindex_last_header == B3 filter_header",
    read_last_header(stor) == parsed_b3.filter_header)

  stor.close()
  os.execute("rm -rf " .. dir)
end

io.write(string.format("\n=== %d passed, %d failed ===\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
