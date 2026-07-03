-- spec/deep_reorg_unbounded_spec.lua
--
-- Core-parity proof for the UNBOUNDED archive reorg fix (2026-07-02).
--
-- Bitcoin Core has NO reorg-depth cap: ActivateBestChainStep (validation.cpp)
-- walks unbounded to the fork point and follows the most-work VALID chain to
-- ANY depth.  The 288 constant (MIN_BLOCKS_TO_KEEP) is a PRUNING artifact — the
-- retained undo-block window — NOT a consensus rule.  lunarblock previously
-- enforced a flat 288 cap in ChainState:accept_side_branch_block, so on an
-- ARCHIVE node (pruning disabled = the default; all undo present) a >288-deep
-- higher-work fork was gratuitously REFUSED and the node stayed on the lighter
-- minority chain — a Class-A consensus split.
--
-- This builds an archive chainstate, an active branch, and a COMPETING branch
-- that forks >288 blocks back AND carries more total work, then submits the
-- competing tip through the SAME reorg orchestrator the submitblock RPC uses.
--
-- PRE-fix : accept_side_branch_block -> nil,"reorg-depth-exceeded"; tip unchanged
--           (the node strands itself on the lighter minority chain).
-- POST-fix: accept_side_branch_block -> "connected"; tip == the deep fork tip
--           (follows the most-work chain to any depth, exactly like Core).

local types = require("lunarblock.types")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local script = require("lunarblock.script")
local storage_mod = require("lunarblock.storage")

-- Regtest halves the block subsidy every 150 blocks; a coinbase paying more
-- than the height-appropriate subsidy is rejected (bad-cb-amount).
local function subsidy(height)
  return math.floor(5000000000 / (2 ^ math.floor(height / 150)))
end

local function make_coinbase_tx(height, value, script_pubkey)
  local coinbase_sig = string.char(1, height % 256)
  return types.transaction(
    1,
    {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                coinbase_sig, 0xFFFFFFFF)},
    {types.txout(value, script_pubkey)},
    0)
end

-- nonce lets an active block and a side block at the same height differ.
local function make_block(height, transactions, prev_hash, nonce)
  local header = types.block_header(
    1,
    prev_hash or types.hash256_zero(),
    types.hash256_zero(),
    os.time() + height + (nonce or 0) * 1000000,
    consensus.networks.regtest.pow_limit_bits,
    nonce or 0)
  return types.block(header, transactions)
end

-- Store + connect a tip-extending block (skip script validation for speed).
local function connect(cs, db, height, txs, prev_hash, nonce)
  local block = make_block(height, txs, prev_hash, nonce)
  local block_hash = validation.compute_block_hash(block.header)
  db.put_header(block_hash, block.header)
  db.put_block(block_hash, block)
  db.put_height_index(height, block_hash)
  local ok, err = cs:connect_block(block, height, block_hash, nil, nil, true)
  assert(ok, "connect_block failed at h=" .. height .. ": " .. tostring(err))
  return block_hash, block
end

-- Store a side-branch block (header + body only, NO height index) so
-- accept_side_branch_block can reorg onto it.
local function store_side(db, height, txs, prev_hash, nonce)
  local block = make_block(height, txs, prev_hash, nonce)
  local block_hash = validation.compute_block_hash(block.header)
  db.put_header(block_hash, block.header)
  db.put_block(block_hash, block)
  return block_hash, block
end

local PKH = string.rep("\x42", 20)
local SPK = script.make_p2pkh_script(PKH)

-- The pre-fix hard cap lived at exactly 288.  We fork FORK_BACK blocks behind
-- the active tip so the reorg is unambiguously deeper than that cap.
local ACTIVE_TIP = 290   -- active branch tip height (289 blocks above fork h=1)
local SIDE_TIP   = 291   -- side branch tip height (290 blocks above fork h=1)
local FORK_H     = 1     -- shared fork block height (a REAL block, not genesis:
                         -- the walk cannot use genesis as a common ancestor)

describe("unbounded archive reorg (Core parity, >288 deep)", function()
  local db, cs, path, fork_hash, side_tip_hash

  before_each(function()
    path = "/tmp/lunarblock_deepreorg_" .. os.time() .. "_" .. math.random(1e9)
    db = storage_mod.open(path)
    cs = utxo.new_chain_state(db, consensus.networks.regtest)
    cs:init()

    -- Shared prefix: genesis (h0) + fork block (h1).  Both chains descend from
    -- the fork block, so the reorg's common ancestor is h1 — >288 below both
    -- tips.
    local prev = types.hash256_zero()
    for h = 0, FORK_H do
      local bh = connect(cs, db, h, {make_coinbase_tx(h, subsidy(h), SPK)}, prev)
      if h == FORK_H then fork_hash = bh end
      prev = bh
    end

    -- Active branch: h=2 .. ACTIVE_TIP, extending the fork block.
    prev = fork_hash
    for h = FORK_H + 1, ACTIVE_TIP do
      prev = connect(cs, db, h, {make_coinbase_tx(h, subsidy(h), SPK)}, prev)
    end
    assert.equal(ACTIVE_TIP, cs.tip_height)

    -- Competing branch: h=2 .. SIDE_TIP, ALSO from the fork block, nonce=7 so
    -- every side block differs from its active same-height sibling.  One extra
    -- block of (equal-difficulty) work makes it strictly heavier than the
    -- active branch, so Core would reorg onto it.
    prev = fork_hash
    local last_side_block
    for h = FORK_H + 1, SIDE_TIP do
      side_tip_hash, last_side_block =
        store_side(db, h, {make_coinbase_tx(h, subsidy(h), SPK)}, prev, 7)
      prev = side_tip_hash
    end
    -- stash the deserialized tip body for accept_side_branch_block
    cs._deep_reorg_tip_block = last_side_block
  end)

  after_each(function()
    if db then db.close() end
  end)

  it("archive node (pruning OFF) reorgs onto the deeper higher-work chain", function()
    -- default chainstate: no pruner wired -> archive.
    assert.is_nil(cs.pruner)

    local depth = SIDE_TIP - FORK_H
    assert.is_true(depth > 288,
      "test must exceed the pre-fix 288 cap; depth=" .. depth)

    local res, err = cs:accept_side_branch_block(
      cs._deep_reorg_tip_block, side_tip_hash)

    -- POST-fix (Core parity): the reorg fires to any depth.
    assert.equal("connected", res,
      "archive node must follow the most-work chain to any depth; got " ..
      tostring(res) .. " / " .. tostring(err))
    assert.equal(SIDE_TIP, cs.tip_height,
      "tip must be the deep fork's tip after the reorg")
    assert.equal(types.hash256_hex(side_tip_hash),
      types.hash256_hex(cs.tip_hash),
      "tip hash must equal the competing chain's tip")
    -- (PRE-fix this returned nil,"reorg-depth-exceeded" and left tip at
    --  ACTIVE_TIP — the Class-A minority-chain stall this fix closes.)
  end)
end)
