-- spec/diffbits_submitblock_spec.lua
--
-- Core-parity proof for the submitblock/accept_block bad-diffbits fix
-- (2026-07-03).
--
-- Bitcoin Core ContextualCheckBlockHeader (validation.cpp:4088-4089 + pow.cpp)
-- requires a block's declared nBits to EQUAL GetNextWorkRequired(pindexPrev),
-- else the block is rejected "bad-diffbits". On a regtest fPowNoRetargeting
-- chain the required bits are simply the parent's bits (genesis 0x207fffff).
--
-- lunarblock enforced this ONLY on the header-first / P2P path
-- (sync.lua:1243-1254). The submitblock RPC + mining paths route through
-- ChainState:accept_block (tip-extend) and ChainState:accept_side_branch_block
-- (side-branch), neither of which compared header.bits to the required work.
-- A block with valid PoW but the WRONG nBits (0x207ffffe when 0x207fffff is
-- required) was therefore ACCEPTED while Core rejects it — a consensus fork.
--
-- PRE-fix : accept_block / accept_side_branch_block ACCEPT the wrong-nBits
--           block (no bad-diffbits gate) — diverges from Core.
-- POST-fix: both reject with "bad-diffbits: ..."; a correct-nBits block still
--           accepts — matches Core.

local types = require("lunarblock.types")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local script = require("lunarblock.script")
local crypto = require("lunarblock.crypto")
local mining = require("lunarblock.mining")
local storage_mod = require("lunarblock.storage")

local REGTEST = consensus.networks.regtest
local REQUIRED_BITS = REGTEST.pow_limit_bits  -- 0x207fffff
local WRONG_BITS    = 0x207ffffe              -- valid PoW target, wrong diffbits
local BLOCK_VERSION = 0x20000000              -- >= 4 (regtest bip65_height = 0)
local SPK = script.make_p2pkh_script(string.rep("\x42", 20))

local function subsidy(height)
  return math.floor(5000000000 / (2 ^ math.floor(height / 150)))
end

-- Simple coinbase (no BIP34/witness) for the prefix chain, which is connected
-- via connect_block directly (skips check_block).
local function simple_coinbase(height, value)
  local coinbase_sig = string.char(1, height % 256)
  return types.transaction(
    1,
    {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                coinbase_sig, 0xFFFFFFFF)},
    {types.txout(value, SPK)},
    0)
end

local function make_simple_block(height, prev_hash, bits, nonce)
  local header = types.block_header(
    1, prev_hash or types.hash256_zero(), types.hash256_zero(),
    os.time() + height + (nonce or 0) * 1000000, bits, nonce or 0)
  return types.block(header, {simple_coinbase(height, subsidy(height))})
end

-- Store + connect a prefix tip block directly (bypasses accept_block).
local function connect_prefix(cs, db, height, prev_hash)
  local block = make_simple_block(height, prev_hash, REQUIRED_BITS, 0)
  local block_hash = validation.compute_block_hash(block.header)
  db.put_header(block_hash, block.header)
  db.put_block(block_hash, block)
  db.put_height_index(height, block_hash)
  local ok, err = cs:connect_block(block, height, block_hash, nil, nil, true)
  assert(ok, "prefix connect failed at h=" .. height .. ": " .. tostring(err))
  return block_hash
end

-- Build a FULLY VALID (mined, correct merkle + witness commitment + BIP34)
-- coinbase-only block at `height` on `prev_hash` declaring `bits`.  It passes
-- the entire check_block gauntlet, so accept_block reaches the diffbits gate.
local function build_valid_block(height, prev_hash, bits)
  -- Witness commitment over just the coinbase (wtxid placeholder = 0).
  local witness_root = crypto.compute_merkle_root({types.hash256_zero()})
  local witness_commitment = crypto.hash256(witness_root.bytes .. string.rep("\0", 32))
  local coinbase = mining.create_coinbase_tx(
    height, subsidy(height), "/diffbits-test/", witness_commitment, SPK)
  local merkle_root = crypto.compute_merkle_root({validation.compute_txid(coinbase)})
  local header = types.block_header(
    BLOCK_VERSION, prev_hash, merkle_root, os.time() + height, bits, 0)
  local block = types.block(header, {coinbase})
  local mined = mining.mine_block(block, 0x7FFFFFFF)
  assert(mined, "could not mine regtest block")
  return block, validation.compute_block_hash(block.header)
end

describe("submitblock/accept_block bad-diffbits gate (Core parity)", function()
  local db, cs, path, tip_hash, fork_hash

  before_each(function()
    path = "/tmp/lunarblock_diffbits_" .. os.time() .. "_" .. math.random(1e9)
    db = storage_mod.open(path)
    cs = utxo.new_chain_state(db, REGTEST)
    cs:init()
    -- genesis (h0) .. h3, all at the required bits.
    local prev = types.hash256_zero()
    for h = 0, 3 do
      prev = connect_prefix(cs, db, h, prev)
      if h == 2 then fork_hash = prev end  -- a real block to fork a side branch from
    end
    tip_hash = prev
    assert.equal(3, cs.tip_height)
  end)

  after_each(function()
    if db then db.close() end
  end)

  -- ── tip-extend arm (accept_block) ─────────────────────────────────────────

  it("tip-extend: REJECTS a wrong-nBits block (bad-diffbits)", function()
    local new_h = 4
    local blk, block_hash = build_valid_block(new_h, tip_hash, WRONG_BITS)
    local ok, err = cs:accept_block(blk, new_h, block_hash, {skip_scripts = true})
    assert.is_falsy(ok)                                  -- Core rejects; PRE-fix accepted
    assert.truthy(err and err:find("^bad%-diffbits"),
      "expected bad-diffbits, got " .. tostring(err))
    assert.equal(3, cs.tip_height)                       -- tip unchanged
  end)

  it("tip-extend: ACCEPTS a correct-nBits block", function()
    local new_h = 4
    local blk, block_hash = build_valid_block(new_h, tip_hash, REQUIRED_BITS)
    local ok, err = cs:accept_block(blk, new_h, block_hash, {skip_scripts = true})
    assert.truthy(ok, "correct-nBits block must accept; got " .. tostring(err))
    assert.equal(4, cs.tip_height)
  end)

  -- ── side-branch arm (accept_side_branch_block) ────────────────────────────
  -- accept_side_branch_block does no PoW/merkle check itself (Stage 1 runs at
  -- the RPC call site), so these blocks need not be mined — the diffbits gate
  -- is what's under test and it runs before any storage write.

  it("side-branch: REJECTS a wrong-nBits block (bad-diffbits)", function()
    local sb = make_simple_block(3, fork_hash, WRONG_BITS, 7)
    local sb_hash = validation.compute_block_hash(sb.header)
    local res, err = cs:accept_side_branch_block(sb, sb_hash, {check_diffbits = true})
    assert.is_falsy(res)                                 -- Core rejects; PRE-fix stored/inconclusive
    assert.truthy(err and err:find("^bad%-diffbits"),
      "expected bad-diffbits, got " .. tostring(err))
  end)

  it("side-branch: correct-nBits block is NOT rejected bad-diffbits", function()
    -- Equal-work single block off h2: stored as an inconclusive side branch.
    -- The point: the diffbits gate must NOT fire on correct bits.
    local sb = make_simple_block(3, fork_hash, REQUIRED_BITS, 7)
    local sb_hash = validation.compute_block_hash(sb.header)
    local res, err = cs:accept_side_branch_block(sb, sb_hash, {check_diffbits = true})
    assert.is_falsy(err and tostring(err):find("bad%-diffbits"),
      "correct-nBits side block must not be rejected bad-diffbits; got " ..
      tostring(res) .. " / " .. tostring(err))
    assert.equal("stored", res)
  end)
end)
