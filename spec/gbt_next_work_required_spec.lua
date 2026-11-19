-- getblocktemplate / create_block_template: nBits and time follow Core's
-- BlockAssembler::CreateNewBlock (bitcoin-core/src/node/miner.cpp):
--   UpdateTime(pblock)                 -- time = max(GetMinimumTime, now)
--   pblock->nBits = GetNextWorkRequired(pindexPrev, pblock)   -- miner.cpp:220
--   TestBlockValidity(...)             -- miner.cpp:225, throws on failure
-- GetMinimumTime (miner.cpp:36) = MTP+1, raised to prev.time - MAX_TIMEWARP
-- on a retarget boundary (all networks).
--
-- Pre-fix mining.lua copied the PREVIOUS header's bits into every template,
-- so a template built on a tip at height 2015 (next block is a retarget)
-- carried the old difficulty and was rejected bad-diffbits by the node's own
-- check_diffbits; the same happened on min-difficulty testnets.
local types = require("lunarblock.types")
local mining = require("lunarblock.mining")
local consensus = require("lunarblock.consensus")
local utxo = require("lunarblock.utxo")

local MAINNET = consensus.networks.mainnet
local INTERVAL = consensus.DIFFICULTY_ADJUSTMENT_INTERVAL
local PAYOUT = "\x51"

local function empty_mempool()
  return { get_sorted_entries = function() return {} end, has = function() return false end }
end

-- Build `n+1` headers (heights 0..n) with the given per-height timestamp and
-- bits functions; returns the header map, the tip hash, and a by-height list.
local function build_chain(n, ts_of, bits_of, tag)
  local headers, by_height, hash_at = {}, {}, {}
  local prev = types.hash256_zero()
  local tip
  for h = 0, n do
    local hash = types.hash256(string.format("%-4s%028d", tag or "nwr", h))
    headers[hash.bytes] = { version = 0x20000000, prev_hash = prev,
      merkle_root = types.hash256_zero(), timestamp = ts_of(h), bits = bits_of(h), nonce = 0 }
    by_height[h] = headers[hash.bytes]
    hash_at[h] = hash
    prev = hash
    tip = hash
  end
  return headers, tip, by_height, hash_at
end

local function mock_cs(headers, tip, tip_height)
  return { tip_height = tip_height, tip_hash = tip,
           storage = { get_header = function(hash) return headers[hash.bytes] end } }
end

local function expected_bits(by_height, height, timestamp, network)
  return (consensus.get_next_work_required(height, timestamp, network,
    function(h) local hd = by_height[h]; return hd and { header = hd } or nil end))
end

describe("block template nBits = GetNextWorkRequired (Core miner.cpp:220)", function()
  -- Mainnet-params chain, tip at 2015, period spanning ONE week (half of the
  -- two-week target) -> difficulty must double at height 2016.
  local T0 = 1700000000
  local START_BITS = 0x1d00ffff
  local SPACING = 300
  local headers, tip, by_height, hash_at = build_chain(INTERVAL - 1,
    function(h) return T0 + SPACING * h end, function() return START_BITS end)

  it("tip at 2015, non-two-week timespan: template.bits == get_next_work_required", function()
    local tmpl, block = mining.create_block_template(empty_mempool(),
      mock_cs(headers, tip, INTERVAL - 1), MAINNET, PAYOUT)
    local want = expected_bits(by_height, INTERVAL, block.header.timestamp, MAINNET)
    assert.is_not_nil(want)
    assert.are_not.equal(START_BITS, want)   -- the retarget really changes difficulty
    assert.equal(string.format("%08x", want), tmpl.bits)
    assert.equal(want, block.header.bits)
    assert.equal(mining.hex_encode(consensus.bits_to_target(want)), tmpl.target)
  end)

  it("uses ChainState:next_work_required when the chain state provides it", function()
    local cs = utxo.new_chain_state(
      { get_header = function(hash) return headers[hash.bytes] end,
        batch = function() return {} end }, MAINNET)
    cs._snapshot_base_height = false
    cs.tip_height = INTERVAL - 1
    cs.tip_hash = tip
    local tmpl, block = mining.create_block_template(empty_mempool(), cs, MAINNET, PAYOUT)
    local want = expected_bits(by_height, INTERVAL, block.header.timestamp, MAINNET)
    assert.equal(want, block.header.bits)
    assert.equal(string.format("%08x", want), tmpl.bits)
    -- and the node's own connect-time gate accepts the template header
    assert.is_true(cs:check_diffbits(block.header, INTERVAL))
    -- check_diffbits now goes through next_work_required: it must still
    -- reject the stale parent bits the old template carried, and a
    -- non-retarget height must still require the parent's bits.
    local stale = {}
    for k, v in pairs(block.header) do stale[k] = v end
    stale.bits = START_BITS
    local ok, why = cs:check_diffbits(stale, INTERVAL)
    assert.is_false(ok)
    assert.matches("^bad%-diffbits", why)
    local mid = { prev_hash = hash_at[99] }
    assert.is_not_nil(mid.prev_hash)
    mid.timestamp = by_height[99].timestamp + 600
    mid.bits = START_BITS
    assert.is_true(cs:check_diffbits(mid, 100))
    mid.bits = want
    assert.is_false((cs:check_diffbits(mid, 100)))
  end)

  it("testnet min-difficulty: a template >20 min after the tip uses pow_limit bits", function()
    local TESTNET = consensus.networks.testnet
    local hard = 0x1c0fffff
    -- old chain (timestamps far in the past) at height 100, real difficulty
    local th, ttip, tby = build_chain(100,
      function(h) return T0 + 600 * h end, function() return hard end, "tn")
    local tmpl, block = mining.create_block_template(empty_mempool(),
      mock_cs(th, ttip, 100), TESTNET, PAYOUT)
    local want = expected_bits(tby, 101, block.header.timestamp, TESTNET)
    assert.equal(TESTNET.pow_limit_bits, want)
    assert.equal(want, block.header.bits)
    assert.equal(string.format("%08x", want), tmpl.bits)
  end)

  it("testnet: a template within 20 min of the tip keeps the walked-back real bits", function()
    local TESTNET = consensus.networks.testnet
    local hard = 0x1c0fffff
    local future = os.time() + 1000000   -- tip far ahead of the wall clock
    local th, ttip, tby = build_chain(100,
      function(h) return future + h end, function() return hard end, "tf")
    local _, block = mining.create_block_template(empty_mempool(),
      mock_cs(th, ttip, 100), TESTNET, PAYOUT)
    assert.equal(expected_bits(tby, 101, block.header.timestamp, TESTNET), block.header.bits)
    assert.equal(hard, block.header.bits)
  end)
end)

describe("block template time floor (Core GetMinimumTime, miner.cpp:36)", function()
  it("at a retarget boundary mintime/curtime >= prev.time - MAX_TIMEWARP (BIP94 floor)", function()
    -- Tip at 2015 whose timestamp is far ahead of both the wall clock and the
    -- MTP (MTP sits ~1e6 s earlier): the floor prev.time - 600 dominates.
    local future = os.time() + 2000000
    local n = INTERVAL - 1
    local headers, tip = build_chain(n, function(h)
      if h == n then return future end
      return future - 1000000 + h
    end, function() return MAINNET.pow_limit_bits end, "tw")
    local tmpl, block = mining.create_block_template(empty_mempool(),
      mock_cs(headers, tip, n), MAINNET, PAYOUT)
    local floor = future - consensus.MAX_TIMEWARP
    assert.equal(floor, tmpl.mintime)
    assert.equal(floor, tmpl.curtime)
    assert.equal(floor, block.header.timestamp)
  end)

  it("off a retarget boundary the floor is MTP+1 only", function()
    local future = os.time() + 2000000
    local n = 100
    local headers, tip = build_chain(n, function(h)
      if h == n then return future end
      return future - 1000000 + h
    end, function() return MAINNET.pow_limit_bits end, "nb")
    local tmpl = mining.create_block_template(empty_mempool(),
      mock_cs(headers, tip, n), MAINNET, PAYOUT)
    -- MTP of heights 90..100 = timestamp at height 95
    assert.equal(future - 1000000 + 95 + 1, tmpl.mintime)
  end)
end)

describe("block template dry-run validity check (Core TestBlockValidity, miner.cpp:225)", function()
  it("refuses to return a template whose header bits fail the contextual check", function()
    local T0 = 1700000000
    local headers, tip = build_chain(INTERVAL - 1,
      function(h) return T0 + 300 * h end, function() return 0x1d00ffff end, "tv")
    local cs = mock_cs(headers, tip, INTERVAL - 1)
    -- A chain-state hook that reports a WRONG next-work value: the template
    -- would carry it, and the independent dry-run must catch it.
    cs.next_work_required = function() return 0x1d00ffff end
    local ok, err = pcall(mining.create_block_template, empty_mempool(), cs, MAINNET, PAYOUT)
    assert.is_false(ok)
    assert.matches("TestBlockValidity failed: bad%-diffbits", tostring(err))
  end)

  it("refuses to build a template when the next work cannot be resolved", function()
    -- The period-first ancestor (height 0) is missing: fail closed, never guess.
    local T0 = 1700000000
    local headers, tip, by_height = build_chain(INTERVAL - 1,
      function(h) return T0 + 300 * h end, function() return 0x1d00ffff end, "tu")
    for hash, hd in pairs(headers) do
      if hd == by_height[0] then headers[hash] = nil end
    end
    local ok, err = pcall(mining.create_block_template, empty_mempool(),
      mock_cs(headers, tip, INTERVAL - 1), MAINNET, PAYOUT)
    assert.is_false(ok)
    assert.matches("next work required is not computable", tostring(err))
  end)
end)
