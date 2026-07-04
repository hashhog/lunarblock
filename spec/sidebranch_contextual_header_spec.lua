-- spec/sidebranch_contextual_header_spec.lua
--
-- Core-parity proof for the side-branch FULL ContextualCheckBlockHeader fix
-- (2026-07-03).
--
-- Bitcoin Core runs ContextualCheckBlockHeader (validation.cpp:4088-4118) inside
-- AcceptBlockHeader for EVERY header BEFORE it can enter the block index:
--   * bad-diffbits   (4088-4089) — nBits == GetNextWorkRequired(pindexPrev)
--   * time-too-old   (4092-4093) — timestamp > parent MedianTimePast
--   * time-too-new   (4108-4110) — timestamp <= now + MAX_FUTURE_BLOCK_TIME
--   * bad-version    (4113-4118) — nVersion floor per BIP34/66/65 at the height
-- An invalid header is refused here, so it never enters the index and no reorg
-- can ever activate onto it.
--
-- lunarblock's submitblock side-branch path ran STAGE-1 check_block with a NIL
-- height (context-free: no version floor, no MTP), then accept_side_branch_block
-- re-derived the real heights but — before this fix — only re-checked diffbits
-- (158b9c6).  So a side-branch D1 whose timestamp was <= parent MTP, or whose
-- nVersion was below the soft-fork floor, was STORED, and a heavier child D2
-- could then REORG the active tip onto that invalid block: a Class-A consensus
-- SPLIT vs Core.
--
-- PRE-fix : accept_side_branch_block STORES the invalid side block (only diffbits
--           was gated) -> a heavier child reorgs onto it -> diverges from Core.
-- POST-fix: accept_side_branch_block REJECTS time-too-old / bad-version /
--           time-too-new / bad-diffbits at the REAL height, BEFORE any store; a
--           VALID heavier side branch still reorgs (no over-reject); the prior
--           diffbits fix still holds.
--
-- The gates are gated behind opts.check_diffbits (the submitblock RPC arm only);
-- the P2P reorg reuse path (main.lua accept_side_branch_block, no check_diffbits)
-- already ran the identical gates on the header via sync.lua and is unchanged.

local types = require("lunarblock.types")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local script = require("lunarblock.script")
local storage_mod = require("lunarblock.storage")

local REGTEST       = consensus.networks.regtest
local REQUIRED_BITS = REGTEST.pow_limit_bits   -- 0x207fffff
local WRONG_BITS    = 0x207ffffe               -- valid PoW target, wrong diffbits
local BLOCK_VERSION = 0x20000000               -- >= 4 (clears the BIP65 floor)
local SPK           = script.make_p2pkh_script(string.rep("\x42", 20))

-- Fixed timestamp base so median-time-past is deterministic across runs.  BASE
-- is well in the past, so no honest block is ever "time-too-new" by wall clock.
local BASE    = 1700000000
local SPACING = 100

local function subsidy(height)
  return math.floor(5000000000 / (2 ^ math.floor(height / 150)))
end

local function make_coinbase_tx(height, value)
  local coinbase_sig = string.char(1, height % 256)
  return types.transaction(
    1,
    {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                coinbase_sig, 0xFFFFFFFF)},
    {types.txout(value, SPK)},
    0)
end

-- version/timestamp/bits are all explicit so each vector can isolate one gate.
local function make_block(height, prev_hash, version, timestamp, bits, nonce)
  local header = types.block_header(
    version, prev_hash or types.hash256_zero(), types.hash256_zero(),
    timestamp, bits, nonce or 0)
  return types.block(header, {make_coinbase_tx(height, subsidy(height))})
end

-- Store + connect a prefix tip block directly (bypasses check_block, so the v1
-- active prefix is fine — connect_block does not enforce the nVersion floor).
local function connect_prefix(cs, db, height, prev_hash, ts)
  local block = make_block(height, prev_hash, 1, ts, REQUIRED_BITS, 0)
  local block_hash = validation.compute_block_hash(block.header)
  db.put_header(block_hash, block.header)
  db.put_block(block_hash, block)
  db.put_height_index(height, block_hash)
  local ok, err = cs:connect_block(block, height, block_hash, nil, nil, true)
  assert(ok, "prefix connect failed at h=" .. height .. ": " .. tostring(err))
  return block_hash, block
end

describe("side-branch ContextualCheckBlockHeader gate (Core parity)", function()
  local db, cs, path, fork_hash, mtp_h2

  before_each(function()
    path = "/tmp/lunarblock_sbctx_" .. os.time() .. "_" .. math.random(1e9)
    db = storage_mod.open(path)
    cs = utxo.new_chain_state(db, REGTEST)
    cs:init()
    -- genesis (h0) .. h3, timestamps BASE + h*SPACING, all at required bits.
    local prev = types.hash256_zero()
    for h = 0, 3 do
      prev = connect_prefix(cs, db, h, prev, BASE + h * SPACING)
      if h == 2 then fork_hash = prev end  -- side branches fork off this real block
    end
    assert.equal(3, cs.tip_height)
    -- MedianTimePast of the chain ending at h2 = median(BASE, +100, +200).
    mtp_h2 = BASE + SPACING
  end)

  after_each(function()
    if db then db.close() end
  end)

  -- (a) time-too-old: side-branch D1 timestamped == parent MTP must be REFUSED
  --     at store time (Core validation.cpp:4092). PRE-fix: stored, then a heavier
  --     child reorged onto it.
  it("REJECTS a time-too-old side block (timestamp <= parent MTP)", function()
    local d1 = make_block(3, fork_hash, BLOCK_VERSION, mtp_h2, REQUIRED_BITS, 7)
    local d1_hash = validation.compute_block_hash(d1.header)
    local res, err = cs:accept_side_branch_block(d1, d1_hash, {check_diffbits = true})
    assert.is_falsy(res)
    assert.truthy(err and err:find("^time%-too%-old"),
      "expected time-too-old, got " .. tostring(err))
    assert.equal(3, cs.tip_height)                       -- tip unchanged
    assert.is_nil(db.get_block(d1_hash))                 -- never persisted
  end)

  -- (b) bad-version: v1 side block below the BIP34/66/65 floor must be REFUSED
  --     at its real height (Core validation.cpp:4113-4118). PRE-fix: the nil-height
  --     stage-1 disabled the floor, so it was stored.
  it("REJECTS a below-floor nVersion side block (bad-version)", function()
    local d1 = make_block(3, fork_hash, 1, BASE + 1000, REQUIRED_BITS, 7)
    local d1_hash = validation.compute_block_hash(d1.header)
    local res, err = cs:accept_side_branch_block(d1, d1_hash, {check_diffbits = true})
    assert.is_falsy(res)
    assert.truthy(err and err:find("^bad%-version"),
      "expected bad-version, got " .. tostring(err))
    assert.equal(3, cs.tip_height)
    assert.is_nil(db.get_block(d1_hash))
  end)

  -- (c) time-too-new: side block more than MAX_FUTURE_BLOCK_TIME ahead of the
  --     (injected) clock must be REFUSED (Core validation.cpp:4108).
  it("REJECTS a time-too-new side block (timestamp > now + 2h)", function()
    local clock = BASE + 5000
    local d1 = make_block(3, fork_hash, BLOCK_VERSION,
      clock + consensus.MAX_FUTURE_BLOCK_TIME + 1, REQUIRED_BITS, 7)
    local d1_hash = validation.compute_block_hash(d1.header)
    local res, err = cs:accept_side_branch_block(
      d1, d1_hash, {check_diffbits = true, current_time = clock})
    assert.is_falsy(res)
    assert.truthy(err and err:find("^time%-too%-new"),
      "expected time-too-new, got " .. tostring(err))
    assert.equal(3, cs.tip_height)
  end)

  -- (d) regression: the prior diffbits side-branch fix (158b9c6) still holds.
  it("REJECTS a wrong-nBits side block (bad-diffbits still enforced)", function()
    local d1 = make_block(3, fork_hash, BLOCK_VERSION, BASE + 1000, WRONG_BITS, 7)
    local d1_hash = validation.compute_block_hash(d1.header)
    local res, err = cs:accept_side_branch_block(d1, d1_hash, {check_diffbits = true})
    assert.is_falsy(res)
    assert.truthy(err and err:find("^bad%-diffbits"),
      "expected bad-diffbits, got " .. tostring(err))
    assert.equal(3, cs.tip_height)
  end)

  -- (e) no over-reject: a fully valid EQUAL-work side block is still STORED
  --     (inconclusive), exactly as before the fix.
  it("STORES a fully valid equal-work side block (no over-reject)", function()
    local d1 = make_block(3, fork_hash, BLOCK_VERSION, BASE + 1000, REQUIRED_BITS, 7)
    local d1_hash = validation.compute_block_hash(d1.header)
    local res, err = cs:accept_side_branch_block(d1, d1_hash, {check_diffbits = true})
    assert.equal("stored", res, "valid side block must store; got "
      .. tostring(res) .. " / " .. tostring(err))
    assert.equal(3, cs.tip_height)
    assert.truthy(db.get_block(d1_hash))                 -- persisted for a later reorg
  end)

  -- (f) no over-reject: a fully valid HEAVIER side branch (D1@h3 + D2@h4) still
  --     REORGS the active tip onto it, exactly like Core FindMostWorkChain.
  it("REORGS onto a valid heavier side branch (D1@h3 + D2@h4)", function()
    local d1 = make_block(3, fork_hash, BLOCK_VERSION, BASE + 1000, REQUIRED_BITS, 7)
    local d1_hash = validation.compute_block_hash(d1.header)
    local r1 = cs:accept_side_branch_block(d1, d1_hash, {check_diffbits = true})
    assert.equal("stored", r1)                           -- equal work -> stored
    assert.equal(3, cs.tip_height)

    local d2 = make_block(4, d1_hash, BLOCK_VERSION, BASE + 1100, REQUIRED_BITS, 7)
    local d2_hash = validation.compute_block_hash(d2.header)
    local r2, err2 = cs:accept_side_branch_block(d2, d2_hash, {check_diffbits = true})
    assert.equal("connected", r2, "heavier valid side branch must reorg; got "
      .. tostring(r2) .. " / " .. tostring(err2))
    assert.equal(4, cs.tip_height)
    assert.equal(types.hash256_hex(d2_hash), types.hash256_hex(cs.tip_hash))
  end)
end)
