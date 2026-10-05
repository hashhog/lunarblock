-- spec/f0_reorg_tombstone_eviction_spec.lua
--
-- F0 coin-cache resurrection, lunarblock variant (2026-10-05).
--
-- A multi-block reorg (ChainState:accept_side_branch_block) threads ONE shared
-- RocksDB batch through every disconnect and connect; nothing reaches disk
-- until the final commit.  CoinView:flush(.., reorg_batch) therefore keeps
-- each spent entry in the cache as a CLEAN tombstone: the cache, not the disk,
-- is the only record that the coin is gone.  The over-budget rebuild at the
-- end of the same flush kept only dirty entries and unspent clean ones, so it
-- DROPPED those tombstones (and the re-added / created coins whose puts were
-- also only in the batch).  The next CoinView:get in the same reorg missed
-- the cache and read the PRE-reorg disk record:
--
--   * accept-invalid: a coin spent by side block S1 is spent AGAIN by S2 of
--     the same branch -> the double-spending branch is CONNECTED;
--   * reject-valid:   a coin spent on the active chain and restored by the
--     disconnect is evicted, the disk still says "deleted" -> a valid heavier
--     branch that spends it is refused (node stays on the lighter chain).
--
-- Core: the CCoinsViewCache never forgets a modification before it is
-- written to the parent (coins.cpp SpendCoin keeps a DIRTY spent entry;
-- FetchCoin never re-reads an outpoint the cache holds; Flush/BatchWrite
-- erase only after the write).  Eviction (Uncache) only drops entries that
-- are neither DIRTY nor FRESH, i.e. whose state equals the parent's.
--
-- The eviction is forced deterministically by setting the CoinView byte
-- budget to 0 just before the reorg, so every per-block flush inside the
-- reorg takes the over-budget rebuild branch.  With the production budget
-- (450 MB) the same branch fires whenever the cache is near its budget at
-- the moment a reorg runs.

local types = require("lunarblock.types")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local script = require("lunarblock.script")
local storage_mod = require("lunarblock.storage")

local function subsidy(height)
  return math.floor(5000000000 / (2 ^ math.floor(height / 150)))
end

-- tag distinguishes coinbases of an active and a side block at one height
-- (otherwise both share a txid and BIP30 noise would mask the test).
local function make_coinbase_tx(height, value, spk, tag)
  local sig = string.char(2, height % 256, math.floor(height / 256) % 256, tag or 0)
  return types.transaction(1,
    {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), sig, 0xFFFFFFFF)},
    {types.txout(value, spk)}, 0)
end

local function make_block(height, txs, prev_hash, nonce)
  local header = types.block_header(1, prev_hash or types.hash256_zero(),
    types.hash256_zero(), 1700000000 + height * 600 + (nonce or 0),
    consensus.networks.regtest.pow_limit_bits, nonce or 0)
  return types.block(header, txs)
end

local PKH = string.rep("\x42", 20)
local SPK = script.make_p2pkh_script(PKH)

local function spend_tx(prev_txid, vout, value)
  return types.transaction(1,
    {types.txin(types.outpoint(prev_txid, vout), "", 0xFFFFFFFE)},
    {types.txout(value, SPK)}, 0)
end

local FORK_H = 102   -- coinbase of height 1 is mature from height 101

-- Builds genesis..FORK_H on the active chain.  Returns ctx.
local function build_prefix()
  local path = (os.getenv("LB_F0_TMP") or "/tmp") .. "/lunarblock_f0_"
    .. os.time() .. "_" .. math.random(1e9)
  local db = storage_mod.open(path)
  local cs = utxo.new_chain_state(db, consensus.networks.regtest)
  cs:init()
  local ctx = { path = path, db = db, cs = cs }
  local prev = types.hash256_zero()
  for h = 0, FORK_H do
    local cb = make_coinbase_tx(h, subsidy(h), SPK, 0)
    local blk = make_block(h, {cb}, prev, 0)
    local bh = validation.compute_block_hash(blk.header)
    db.put_header(bh, blk.header); db.put_block(bh, blk); db.put_height_index(h, bh)
    local ok, err = cs:connect_block(blk, h, bh, nil, nil, true, false, true)
    assert(ok, "prefix connect failed at " .. h .. ": " .. tostring(err))
    if h == 1 then ctx.x_txid = validation.compute_txid(cb) end
    prev = bh
  end
  ctx.fork_hash = prev
  return ctx
end

local function connect_active(ctx, h, txs, prev)
  local blk = make_block(h, txs, prev, 0)
  local bh = validation.compute_block_hash(blk.header)
  ctx.db.put_header(bh, blk.header); ctx.db.put_block(bh, blk)
  ctx.db.put_height_index(h, bh)
  local ok, err = ctx.cs:connect_block(blk, h, bh, nil, nil, true, false, true)
  assert(ok, "active connect failed at " .. h .. ": " .. tostring(err))
  return bh
end

local function store_side(ctx, h, txs, prev)
  local blk = make_block(h, txs, prev, 7)
  local bh = validation.compute_block_hash(blk.header)
  ctx.db.put_header(bh, blk.header); ctx.db.put_block(bh, blk)
  return bh, blk
end

local function teardown(ctx)
  pcall(ctx.db.close)
  os.execute("rm -rf '" .. ctx.path .. "'")
end

local X_VALUE = subsidy(1)

-- Active: F+1, F+2 (coinbase only).  Side: S1 spends X, S2 spends X AGAIN, S3.
-- Core: S2 has a missing input -> branch invalid, tip stays on the active chain.
local function run_double_spend_branch(force_eviction)
  local ctx = build_prefix()
  local prev = ctx.fork_hash
  local a1 = connect_active(ctx, FORK_H + 1, {make_coinbase_tx(FORK_H + 1, subsidy(FORK_H + 1), SPK, 1)}, prev)
  local a2 = connect_active(ctx, FORK_H + 2, {make_coinbase_tx(FORK_H + 2, subsidy(FORK_H + 2), SPK, 1)}, a1)
  local tx1 = spend_tx(ctx.x_txid, 0, X_VALUE - 1000)
  local tx2 = spend_tx(ctx.x_txid, 0, X_VALUE - 2000)   -- same prevout, other txid
  local s1 = store_side(ctx, FORK_H + 1, {make_coinbase_tx(FORK_H + 1, subsidy(FORK_H + 1), SPK, 2), tx1}, ctx.fork_hash)
  local s2 = store_side(ctx, FORK_H + 2, {make_coinbase_tx(FORK_H + 2, subsidy(FORK_H + 2), SPK, 2), tx2}, s1)
  local s3, s3blk = store_side(ctx, FORK_H + 3, {make_coinbase_tx(FORK_H + 3, subsidy(FORK_H + 3), SPK, 2)}, s2)
  if force_eviction then ctx.cs.coin_view.max_cache_bytes = 0 end
  local ok, res, err = pcall(ctx.cs.accept_side_branch_block, ctx.cs, s3blk, s3,
    { skip_scripts = true })
  local out = {
    pcall_ok = ok, res = res, err = err,
    tip_height = ctx.cs.tip_height,
    tip_is_active = types.hash256_hex(ctx.cs.tip_hash) == types.hash256_hex(a2),
  }
  local disk_tip_hash, disk_tip_h = ctx.db.get_chain_tip()
  out.disk_tip_is_active = disk_tip_hash and types.hash256_hex(disk_tip_hash) == types.hash256_hex(a2)
  out.disk_tip_h = disk_tip_h
  teardown(ctx)
  return out
end

-- Active: F+1 spends X.  Side: S1 spends X (valid: F+1 is disconnected), S2.
-- Core: the heavier side branch is valid and becomes the tip.
local function run_valid_respend_branch(force_eviction)
  local ctx = build_prefix()
  local a1 = connect_active(ctx, FORK_H + 1, {make_coinbase_tx(FORK_H + 1, subsidy(FORK_H + 1), SPK, 1),
    spend_tx(ctx.x_txid, 0, X_VALUE - 1000)}, ctx.fork_hash)
  local s1 = store_side(ctx, FORK_H + 1, {make_coinbase_tx(FORK_H + 1, subsidy(FORK_H + 1), SPK, 2),
    spend_tx(ctx.x_txid, 0, X_VALUE - 3000)}, ctx.fork_hash)
  local s2, s2blk = store_side(ctx, FORK_H + 2, {make_coinbase_tx(FORK_H + 2, subsidy(FORK_H + 2), SPK, 2)}, s1)
  if force_eviction then ctx.cs.coin_view.max_cache_bytes = 0 end
  local ok, res, err = pcall(ctx.cs.accept_side_branch_block, ctx.cs, s2blk, s2,
    { skip_scripts = true })
  local out = { pcall_ok = ok, res = res, err = err, tip_height = ctx.cs.tip_height,
    tip_is_side = ctx.cs.tip_hash and types.hash256_hex(ctx.cs.tip_hash) == types.hash256_hex(s2) }
  teardown(ctx)
  return out
end

describe("F0: reorg-mode CoinView eviction must not forget batch-only state", function()
  it("control (production budget): a branch that double-spends X is refused", function()
    local o = run_double_spend_branch(false)
    assert.is_true(o.pcall_ok, tostring(o.res))
    assert.are_not.equal("connected", o.res)
    assert.is_true(o.tip_is_active, "tip left the active chain")
    assert.is_true(o.disk_tip_is_active, "disk tip left the active chain")
  end)

  it("over-budget eviction mid-reorg: a branch that double-spends X is STILL refused", function()
    local o = run_double_spend_branch(true)
    print(string.format("[F0-LB] double-spend branch, eviction forced: res=%s err=%s tip_h=%s tip_is_active=%s disk_tip_h=%s",
      tostring(o.res), tostring(o.err), tostring(o.tip_height), tostring(o.tip_is_active), tostring(o.disk_tip_h)))
    assert.is_true(o.pcall_ok, tostring(o.res))
    assert.are_not.equal("connected", o.res,
      "double-spending side branch was CONNECTED (tombstone evicted, stale disk coin read)")
    assert.is_true(o.tip_is_active, "tip moved onto the double-spending branch")
    assert.is_true(o.disk_tip_is_active, "double-spending branch was COMMITTED to disk")
  end)

  it("control (production budget): a valid branch re-spending a restored coin connects", function()
    local o = run_valid_respend_branch(false)
    assert.is_true(o.pcall_ok, tostring(o.res))
    assert.equal("connected", o.res, tostring(o.err))
    assert.is_true(o.tip_is_side)
  end)

  it("over-budget eviction mid-reorg: a valid branch re-spending a restored coin STILL connects", function()
    local o = run_valid_respend_branch(true)
    print(string.format("[F0-LB] valid re-spend branch, eviction forced: res=%s err=%s tip_h=%s",
      tostring(o.res), tostring(o.err), tostring(o.tip_height)))
    assert.is_true(o.pcall_ok, tostring(o.res))
    assert.equal("connected", o.res,
      "valid heavier branch REFUSED (restored coin evicted, disk still says deleted): " .. tostring(o.err))
    assert.is_true(o.tip_is_side)
  end)
end)
