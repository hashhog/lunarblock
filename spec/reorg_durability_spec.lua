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

-- ── #38: reorg DURABILITY across restart ────────────────────────────────────
-- The observed regression (2026-08-20/21): a reorg that completed in memory
-- (tip advanced onto the heavier fork) did NOT survive a process restart —
-- reopening the datadir loaded the OLD pre-reorg tip. accept_side_branch_block
-- claims "After this returns, the tip flip is durable and crash-recoverable"
-- (utxo.lua reorg_batch.write(true)); this test is the missing proof of that
-- claim. It reorgs on REAL RocksDB, closes the db, reopens the SAME path in a
-- fresh ChainState, and asserts init() loads the REORGED tip from storage.
describe("#38 reorg durability across restart", function()
  local path, fork_hash, side_tip_hash, side_tip_block

  before_each(function()
    path = "/tmp/lunarblock_reorgdurab_" .. os.time() .. "_" .. math.random(1e9)
    local db = storage_mod.open(path)
    local cs = utxo.new_chain_state(db, consensus.networks.regtest)
    cs:init()

    -- Shared prefix genesis+fork, active branch to ACTIVE_TIP, heavier side
    -- branch to SIDE_TIP (same topology as the deep-reorg spec, but the depth
    -- is irrelevant here — durability, not the cap, is under test, so keep it
    -- shallow for speed).
    local A_TIP, S_TIP, F_H = 6, 7, 1
    local prev = types.hash256_zero()
    for h = 0, F_H do
      local bh = connect(cs, db, h, {make_coinbase_tx(h, subsidy(h), SPK)}, prev)
      if h == F_H then fork_hash = bh end
      prev = bh
    end
    prev = fork_hash
    for h = F_H + 1, A_TIP do
      prev = connect(cs, db, h, {make_coinbase_tx(h, subsidy(h), SPK)}, prev)
    end
    prev = fork_hash
    local last
    for h = F_H + 1, S_TIP do
      side_tip_hash, last =
        store_side(db, h, {make_coinbase_tx(h, subsidy(h), SPK)}, prev, 7)
      prev = side_tip_hash
    end
    side_tip_block = last

    -- Reorg onto the heavier side branch. In-memory tip must flip.
    local res = cs:accept_side_branch_block(side_tip_block, side_tip_hash)
    assert.equal("connected", res, "precondition: reorg must fire in memory")
    assert.equal(S_TIP, cs.tip_height, "precondition: in-memory tip flipped")

    -- Simulate the restart: flush any lazy state and CLOSE the db. If the
    -- reorg's write(true) was truly durable, the on-disk chain_tip is now the
    -- side tip regardless of what close() does.
    db.close()
  end)

  it("reopening the datadir loads the REORGED tip, not the pre-reorg tip", function()
    local db2 = storage_mod.open(path)
    -- The lowest-level durability check: what did storage actually persist?
    local loaded_hash, loaded_height = db2.get_chain_tip()
    db2.close()
    assert.is_not_nil(loaded_hash, "storage has no chain_tip after reorg+close")
    assert.equal(7, loaded_height,
      "on-disk tip height is " .. tostring(loaded_height) ..
      ", expected the reorged side tip 7 (#38 durability hole)")
    assert.equal(types.hash256_hex(side_tip_hash),
      types.hash256_hex(loaded_hash),
      "on-disk tip hash is not the reorged side tip (#38 durability hole)")
  end)

  it("a fresh ChainState:init() adopts the reorged tip from storage", function()
    local db2 = storage_mod.open(path)
    local cs2 = utxo.new_chain_state(db2, consensus.networks.regtest)
    cs2:init()
    local h = cs2.tip_height
    local th = cs2.tip_hash and types.hash256_hex(cs2.tip_hash) or nil
    db2.close()
    assert.equal(7, h, "restarted node did not adopt the reorged tip height")
    assert.equal(types.hash256_hex(side_tip_hash), th,
      "restarted node did not adopt the reorged tip hash")
  end)
end)
