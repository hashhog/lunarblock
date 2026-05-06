-- test_txindex_revert_on_reorg.lua
-- Pattern C0 fix verification (2026-05-06).  See
--   CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-2026-05-05.md
-- and the cross-impl audit
--   CORE-PARITY-AUDIT/_reorg-correctness-cross-impl-2026-05-05.md
-- for context.  Pre-fix, lunarblock surfaced as "C0 / PASS-vacuous" in
-- the fleet table because connect_block never wrote into CF.TX_INDEX —
-- so getrawtransaction returned tx-err pre AND post reorg.  Post-fix,
-- when --txindex is enabled, connect_block writes (txid → blockhash ||
-- height_le) into CF.TX_INDEX inside the per-block atomic batch, and
-- disconnect_block deletes those keys symmetrically.  Result: pre-reorg
-- lookup hits, post-reorg lookup misses (matches nimrod's correct-PASS
-- shape).
--
-- This test is the lunarblock unit-test analog of the
--   tools/diff-test-corpus/regression/txindex-revert-on-reorg
-- corpus entry.  Sibling to test_reorg_via_submitblock.lua (Pattern Z).
--
-- Reference (Bitcoin Core): src/index/txindex.cpp CustomAppend /
-- CustomRemove via BaseIndex::BlockConnected / BlockDisconnected.

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
  local path = os.tmpname() .. "_txindex_revert"
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

--------------------------------------------------------------------------------
-- Test 1: txindex disabled (default) — connect_block must NOT write to
-- CF.TX_INDEX.  This is the live-mainnet path; we don't want any
-- behavior change for a node started without --txindex.
--------------------------------------------------------------------------------
do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  -- txindex_enabled stays false (default)
  cs:connect_genesis()
  local genesis_hash = cs.tip_hash

  local blk_a1, hash_a1 = make_block(genesis_hash, 1, 1296688700, 0xA1)
  local ok_a1, err_a1 = submit_extending_block(cs, stor, blk_a1, 1)
  check("disabled: A1 connected", ok_a1 == true, err_a1)

  local cb_txid = blk_a1.transactions[1]._cached_txid
  local indexed = stor.get(storage_mod.CF.TX_INDEX, cb_txid.bytes)
  check("disabled: A1.coinbase NOT indexed (default behavior preserved)",
    indexed == nil, "found unexpected entry: " .. tostring(indexed and #indexed))

  stor.close()
  os.execute("rm -rf " .. dir)
end

--------------------------------------------------------------------------------
-- Test 2: txindex enabled — happy path on the best chain.
--   genesis ──► A1 (h=1) ──► A2 (h=2)
-- After connect, both coinbases must be indexed.  Lookup by txid must
-- return CF.TX_INDEX value with bytes 1..32 == block_hash, bytes 33..36
-- == block_height (LE).
--------------------------------------------------------------------------------
do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:set_txindex_enabled(true)
  check("enabled: txindex_enabled flag is true", cs.txindex_enabled == true)
  cs:connect_genesis()
  local genesis_hash = cs.tip_hash

  local blk_a1, hash_a1 = make_block(genesis_hash, 1, 1296688700, 0xA1)
  local ok_a1, err_a1 = submit_extending_block(cs, stor, blk_a1, 1)
  check("enabled: A1 connected", ok_a1 == true, err_a1)

  local cb_a1_txid = blk_a1.transactions[1]._cached_txid
  local idx_a1 = stor.get(storage_mod.CF.TX_INDEX, cb_a1_txid.bytes)
  check("enabled: A1.coinbase indexed", idx_a1 ~= nil)
  check("enabled: A1 entry size == 36 (hash || height_le)",
    idx_a1 and #idx_a1 == 36, idx_a1 and ("got " .. #idx_a1) or "nil")
  check("enabled: A1 entry bytes 1..32 == hash_a1",
    idx_a1 and idx_a1:sub(1, 32) == hash_a1.bytes)
  -- Decode height from bytes 33..36 (LE)
  if idx_a1 and #idx_a1 == 36 then
    local h = idx_a1:byte(33) + idx_a1:byte(34) * 256
            + idx_a1:byte(35) * 65536 + idx_a1:byte(36) * 16777216
    check("enabled: A1 entry bytes 33..36 == height (LE) == 1", h == 1,
      "got " .. tostring(h))
  else
    check("enabled: A1 entry bytes 33..36 == height (LE) == 1", false,
      "entry missing or wrong size")
  end

  local blk_a2, hash_a2 = make_block(hash_a1, 2, 1296688701, 0xA2)
  local ok_a2, err_a2 = submit_extending_block(cs, stor, blk_a2, 2)
  check("enabled: A2 connected", ok_a2 == true, err_a2)

  local cb_a2_txid = blk_a2.transactions[1]._cached_txid
  local idx_a2 = stor.get(storage_mod.CF.TX_INDEX, cb_a2_txid.bytes)
  check("enabled: A2.coinbase indexed", idx_a2 ~= nil)
  check("enabled: A2 entry bytes 1..32 == hash_a2",
    idx_a2 and idx_a2:sub(1, 32) == hash_a2.bytes)

  stor.close()
  os.execute("rm -rf " .. dir)
end

--------------------------------------------------------------------------------
-- Test 3: Pattern C0 — txindex revert on reorg.
--   genesis  ──►  A1[A1cb] (h=1)
--      │
--      └──►  B1 (h=1)  ──►  B2 (h=2)
--
-- After A1 connects, A1cb is indexed.  After B2 triggers a reorg
-- (heavier B-chain), A1 disconnects.  CF.TX_INDEX[A1cb_txid] must be
-- DELETED — symmetric with the connect-time write.  This matches
-- bitcoin-core's BaseIndex::BlockDisconnected → CTxIndex::CustomRemove.
--
-- Critically: post-reorg, the diff-test corpus probe
-- getrawtransaction(A1cb_txid, true) must NOT return a positive
-- confirmations field.  Deleting the txindex entry causes the rpc
-- handler to return "no such tx" (Pattern C0 PASS shape — same as
-- nimrod, the only fleet impl besides bitcoin-core that gets this
-- right today).
--------------------------------------------------------------------------------
do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:set_txindex_enabled(true)
  cs:connect_genesis()
  local genesis_hash = cs.tip_hash

  -- Step 1: A1 extends genesis on the best chain.  Indexed normally.
  local blk_a1, hash_a1 = make_block(genesis_hash, 1, 1296688700, 0xA1)
  local ok_a1 = submit_extending_block(cs, stor, blk_a1, 1)
  check("revert: A1 connected", ok_a1 == true)
  local cb_a1_txid = blk_a1.transactions[1]._cached_txid

  local idx_pre = stor.get(storage_mod.CF.TX_INDEX, cb_a1_txid.bytes)
  check("revert: A1.coinbase indexed pre-reorg", idx_pre ~= nil)

  -- Step 2: B1 stored as side-branch (work tied → no reorg yet).
  local blk_b1, hash_b1 = make_block(genesis_hash, 1, 1296688701, 0xB1)
  local sb1, sb1_err = cs:accept_side_branch_block(blk_b1, hash_b1, {
    skip_scripts = true, nosync = true,
  })
  check("revert: B1 stored as side-branch", sb1 == "stored", sb1_err)
  -- B1 is NOT on the active chain — its coinbase must NOT be in txindex.
  local cb_b1_txid = blk_b1.transactions[1]._cached_txid
  local idx_b1_pre = stor.get(storage_mod.CF.TX_INDEX, cb_b1_txid.bytes)
  check("revert: B1.coinbase NOT yet indexed (B1 is side-branch)",
    idx_b1_pre == nil)

  -- Step 3: B2 extends B1 → reorg fires.  A1 disconnects, B1+B2 connect.
  local blk_b2, hash_b2 = make_block(hash_b1, 2, 1296688702, 0xB2)
  local sb2, sb2_err = cs:accept_side_branch_block(blk_b2, hash_b2, {
    skip_scripts = true, nosync = true,
  })
  check("revert: B2 triggers reorg", sb2 == "connected", sb2_err)
  check("revert: tip flipped to B2", types.hash256_eq(cs.tip_hash, hash_b2))

  -- Pattern C0 invariant: A1's coinbase must no longer be in CF.TX_INDEX.
  local idx_post = stor.get(storage_mod.CF.TX_INDEX, cb_a1_txid.bytes)
  check("revert: A1.coinbase txindex entry DELETED post-reorg",
    idx_post == nil, "leaked entry size: " .. tostring(idx_post and #idx_post))

  -- And B1+B2's coinbases ARE indexed (they connected during the reorg).
  local cb_b1_post = stor.get(storage_mod.CF.TX_INDEX, cb_b1_txid.bytes)
  check("revert: B1.coinbase indexed after reorg-connect",
    cb_b1_post ~= nil)
  check("revert: B1 entry points at hash_b1",
    cb_b1_post and cb_b1_post:sub(1, 32) == hash_b1.bytes)

  local cb_b2_txid = blk_b2.transactions[1]._cached_txid
  local cb_b2_post = stor.get(storage_mod.CF.TX_INDEX, cb_b2_txid.bytes)
  check("revert: B2.coinbase indexed after reorg-connect",
    cb_b2_post ~= nil)

  stor.close()
  os.execute("rm -rf " .. dir)
end

--------------------------------------------------------------------------------
-- Test 4: Toggling txindex_enabled at runtime takes effect immediately.
-- Useful both as a unit test and as defense against a regression that
-- silently caches the flag at constructor time.
--------------------------------------------------------------------------------
do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:connect_genesis()
  local genesis_hash = cs.tip_hash

  -- Block 1 connects with txindex OFF.
  local blk1, hash1 = make_block(genesis_hash, 1, 1296688710, 0x10)
  submit_extending_block(cs, stor, blk1, 1)
  local cb1_txid = blk1.transactions[1]._cached_txid
  check("toggle: blk1 (off) NOT indexed",
    stor.get(storage_mod.CF.TX_INDEX, cb1_txid.bytes) == nil)

  -- Toggle ON; block 2 must be indexed.
  cs:set_txindex_enabled(true)
  local blk2, hash2 = make_block(hash1, 2, 1296688711, 0x20)
  submit_extending_block(cs, stor, blk2, 2)
  local cb2_txid = blk2.transactions[1]._cached_txid
  check("toggle: blk2 (on) IS indexed",
    stor.get(storage_mod.CF.TX_INDEX, cb2_txid.bytes) ~= nil)
  -- And blk1 stays unindexed; toggling does not retroactively populate.
  check("toggle: blk1 still NOT indexed after toggle",
    stor.get(storage_mod.CF.TX_INDEX, cb1_txid.bytes) == nil)

  -- Toggle OFF; block 3 must NOT be indexed.
  cs:set_txindex_enabled(false)
  local blk3, hash3 = make_block(hash2, 3, 1296688712, 0x30)
  submit_extending_block(cs, stor, blk3, 3)
  local cb3_txid = blk3.transactions[1]._cached_txid
  check("toggle: blk3 (off again) NOT indexed",
    stor.get(storage_mod.CF.TX_INDEX, cb3_txid.bytes) == nil)
  -- blk2 entry stays — unrelated to runtime flag flip.
  check("toggle: blk2 entry preserved across toggle",
    stor.get(storage_mod.CF.TX_INDEX, cb2_txid.bytes) ~= nil)

  stor.close()
  os.execute("rm -rf " .. dir)
end

io.write(string.format("\n=== %d passed, %d failed ===\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
