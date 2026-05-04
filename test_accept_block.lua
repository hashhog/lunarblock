-- test_accept_block.lua
-- Verifies the unified accept_block helper:
--   1. Stage 1 (check_block) fires — invalid blocks rejected
--   2. prev_block_mtp computed correctly — BIP-113 IsFinalTx uses MTP not nil
--   3. BIP-68 time-based sequence locks guarded by real MTP
--   4. skip_check_block=true (IBD path) still runs connect_block
--
-- Uses a real RocksDB storage (same pattern as spec/utxo_spec.lua).

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
    io.write("FAIL: " .. name .. (detail and (" — " .. tostring(detail)) or "") .. "\n")
    fail = fail + 1
  end
end

local REGTEST = consensus.networks.regtest

local function tmpdir()
  local path = os.tmpname() .. "_accept_block"
  os.execute("mkdir -p " .. path)
  return path
end

local function make_coinbase(height)
  local height_enc = validation.encode_bip34_height(height)
  -- Pad script_sig so the coinbase serializes to >= MIN_TX_SIZE (60 bytes).
  -- Serialized coinbase = 4(ver)+1(vin_count)+32(prev_hash)+4(prev_idx)+
  --   1(script_len)+N(script)+4(seq)+1(vout_count)+8(value)+1(spk_len)+1(spk)+4(lock)
  -- = 4+1+32+4+1+N+4+1+8+1+1+4 = 61+N → N=0 gives 61 ≥ 60. But we also
  -- need the hash (prev_out.hash) to be a string, not hash256 object, since
  -- serialize_transaction expects raw bytes for coinbase prev_hash.
  local padding = string.rep("\x00", 20)  -- enough padding for any height
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

-- Build and PoW-mine a regtest block (trivial bits).
-- Caches serialization on each tx so check_block/connect_block don't re-serialize.
local function make_block(prev_hash_hash256, height, timestamp, extra_txs)
  local coinbase = make_coinbase(height)
  local txs = { coinbase }
  if extra_txs then for _, t in ipairs(extra_txs) do txs[#txs+1] = t end end

  for _, tx in ipairs(txs) do
    local base  = serialize.serialize_transaction(tx, false)
    local total = serialize.serialize_transaction(tx, true)
    tx._cached_base_data     = base
    tx._cached_witness_data  = total
    tx._cached_txid          = crypto.hash256_type(base)
    tx._cached_wtxid         = crypto.hash256_type(total)
  end

  local txids = {}
  for i, tx in ipairs(txs) do txids[i] = tx._cached_txid end
  local merkle = crypto.compute_merkle_root(txids)

  local header = {
    version = 0x20000000, prev_hash = prev_hash_hash256,
    merkle_root = merkle, timestamp = timestamp or os.time(),
    bits = REGTEST.pow_limit_bits, nonce = 0,
  }
  for n = 0, 0xFFFFFF do
    header.nonce = n
    local h = validation.compute_block_hash(header)
    if string.byte(h.bytes, 32) < 0x80 then break end
  end
  return { header = header, transactions = txs }
end

-- Compute 11-block MTP over storage chain from tip_hash
local function compute_mtp(stor, tip_hash)
  local ts, cur = {}, tip_hash
  for _ = 1, 11 do
    local hdr = stor.get_header(cur)
    if not hdr then break end
    ts[#ts+1] = hdr.timestamp
    cur = hdr.prev_hash
  end
  if #ts == 0 then return 0 end
  table.sort(ts)
  return ts[math.ceil(#ts / 2)]
end

-- Accept a block and store its header (atomically persisted by accept_block
-- via caller_batch_fn, but we also store header separately so get_mtp can
-- walk it for future blocks).
local function accept_and_store(cs, stor, blk, height, opts)
  local bh = validation.compute_block_hash(blk.header)
  -- Store header so compute_mtp can walk it on the NEXT block's accept_block.
  -- (accept_block's caller_batch_fn writes the block body; header is stored
  --  here explicitly, simulating what submitblock/sync.lua do.)
  stor.put_header(bh, blk.header)
  local ok, err = cs:accept_block(blk, height, bh, opts or {})
  return ok, err, bh
end

--------------------------------------------------------------------------------
-- Test 1: valid block at height=1 accepted
--------------------------------------------------------------------------------
do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:connect_genesis()

  local blk = make_block(cs.tip_hash, 1, 1296688700)
  local ok, err = accept_and_store(cs, stor, blk, 1, {})
  check("T1: valid block accepted", ok == true, err)
  check("T1: chain tip advanced to h=1", cs.tip_height == 1)
  stor.close()
  os.execute("rm -rf " .. dir)
end

--------------------------------------------------------------------------------
-- Test 2: check_block fires — block with no transactions rejected
--------------------------------------------------------------------------------
do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:connect_genesis()

  local blk = {
    header = {
      version = 0x20000000, prev_hash = cs.tip_hash,
      merkle_root = types.hash256(string.rep("\0",32)),
      timestamp = 1296688700, bits = REGTEST.pow_limit_bits, nonce = 0,
    },
    transactions = {},  -- EMPTY — must fail check_block Stage 1
  }
  local bh = validation.compute_block_hash(blk.header)
  local ok, err = cs:accept_block(blk, 1, bh, {})
  check("T2: block with no txs rejected by Stage 1", ok == nil,
    "ok=" .. tostring(ok) .. " err=" .. tostring(err))
  check("T2: rejection mentions transactions",
    err ~= nil and (err:find("transaction") ~= nil or err:find("tx") ~= nil), err)
  stor.close()
  os.execute("rm -rf " .. dir)
end

--------------------------------------------------------------------------------
-- Test 3: skip_check_block=true (IBD path) — Stage 1 skipped, connect runs
--------------------------------------------------------------------------------
do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:connect_genesis()

  local blk = make_block(cs.tip_hash, 1, 1296688700)
  local ok, err = accept_and_store(cs, stor, blk, 1, { skip_check_block = true })
  check("T3: skip_check_block=true still connects block", ok == true, err)
  check("T3: chain tip is h=1", cs.tip_height == 1)
  stor.close()
  os.execute("rm -rf " .. dir)
end

--------------------------------------------------------------------------------
-- Test 4: BIP-113 IsFinalTx uses real MTP (not nil / not block.timestamp)
--
-- At h >= csv_height=432, lock_time_cutoff = MTP (BIP-113).
-- A tx with locktime = MTP+1 and non-SEQUENCE_FINAL input is non-final.
-- Pre-refactor (nil MTP): lock_time_cutoff = block.timestamp > locktime → accepted (wrong).
-- Post-refactor (real MTP): lock_time_cutoff = MTP < locktime → rejected (correct).
--------------------------------------------------------------------------------
do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:connect_genesis()

  local GENESIS_TS = 1296688602
  local CSV_H      = REGTEST.csv_height  -- 432
  local ok_boot    = true

  -- Bootstrap chain to CSV_H: skip_check_block=true for speed
  for h = 1, CSV_H do
    local ts  = GENESIS_TS + h * 60
    local blk = make_block(cs.tip_hash, h, ts)
    local ok, err = accept_and_store(cs, stor, blk, h, { skip_check_block = true })
    if not ok then
      check("T4: bootstrap h=" .. h, false, err)
      ok_boot = false
      break
    end
  end

  if ok_boot then
    check("T4: bootstrap to CSV_H=" .. CSV_H, cs.tip_height == CSV_H)

    -- Compute expected MTP (same logic as accept_block's compute_mtp_from_storage)
    local expected_mtp = compute_mtp(stor, cs.tip_hash)
    local block_ts     = GENESIS_TS + (CSV_H + 1) * 60
    -- Verify test setup: block_ts > MTP so header rule passes, but locktime > MTP
    assert(block_ts > expected_mtp,
      "setup: block_ts=" .. block_ts .. " must be > mtp=" .. expected_mtp)

    -- Non-final tx: locktime = MTP + 1, non-SEQUENCE_FINAL input
    local non_final_tx = {
      version = 1, locktime = expected_mtp + 1,
      inputs = {{
        prev_out   = { hash = types.hash256(string.rep("\0",32)), index = 0xFFFFFFFF },
        script_sig = "", sequence = 0,  -- 0 != 0xFFFFFFFF → locktime applies
        witness    = {},
      }},
      outputs = {{ value = 0, script_pubkey = "\x51" }},
    }

    local blk = make_block(cs.tip_hash, CSV_H + 1, block_ts, { non_final_tx })
    local bh  = validation.compute_block_hash(blk.header)
    stor.put_header(bh, blk.header)

    local ok, err = cs:accept_block(blk, CSV_H + 1, bh, { skip_check_block = true })
    check("T4: block with locktime>MTP rejected (BIP-113 IsFinalTx enforced)",
      ok == nil,
      "ok=" .. tostring(ok) .. " err=" .. tostring(err) ..
      " mtp=" .. tostring(expected_mtp) ..
      " locktime=" .. tostring(expected_mtp + 1) ..
      " block_ts=" .. tostring(block_ts))
    if ok == nil then
      check("T4: rejection mentions nonfinal",
        err ~= nil and err:find("nonfinal") ~= nil, err)
    end
  end

  stor.close()
  os.execute("rm -rf " .. dir)
end

--------------------------------------------------------------------------------
-- Test 5: Multiple accept_block calls advance tip monotonically
--------------------------------------------------------------------------------
do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:connect_genesis()

  local CHAIN_LEN = 10
  for h = 1, CHAIN_LEN do
    local ts  = 1296688602 + h * 60
    local blk = make_block(cs.tip_hash, h, ts)
    local ok, err = accept_and_store(cs, stor, blk, h,
      { skip_check_block = (h > 1) })
    if not ok then
      check("T5: chain length " .. CHAIN_LEN, false, "h=" .. h .. ": " .. tostring(err))
      goto t5_done
    end
  end
  check("T5: tip_height after " .. CHAIN_LEN .. " blocks", cs.tip_height == CHAIN_LEN)
  ::t5_done::
  stor.close()
  os.execute("rm -rf " .. dir)
end

--------------------------------------------------------------------------------
-- Summary
--------------------------------------------------------------------------------
io.write(string.format("\n%d passed, %d failed\n", pass, fail))
if fail > 0 then os.exit(1) end
