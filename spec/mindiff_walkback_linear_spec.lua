-- spec/mindiff_walkback_linear_spec.lua
--
-- The testnet min-difficulty walk-back must cost O(n) parent hops, not O(n^2).
--
-- consensus.get_next_work_required walks back over a run of powLimit headers
-- by asking the ancestor oracle for height-1, height-2, ... (Core pow.cpp:32-35
-- steps `pindex = pindex->pprev`, one hop per step).  HeaderChain's oracle
-- (make_work_ancestor_fn) used to answer every one of those calls by walking
-- from the candidate's PARENT down to the requested height again, so a run of
-- n powLimit headers cost ~n^2/2 prev_hash hops (~2 million for n=2014) on the
-- event loop, before bad-diffbits was even decided.  A peer can feed such
-- runs for free on testnet4 (powLimit headers are difficulty 1).
--
-- The hop count is measured through the HeaderChain.headers map: every hop of
-- the parent walk is exactly one `headers[prev_hex]` lookup, so wrapping the
-- map in a counting proxy counts hops without reaching into sync.lua's locals.

local types = require("lunarblock.types")
local sync = require("lunarblock.sync")
local consensus = require("lunarblock.consensus")
local helpers = require("spec.helpers")

local TESTNET4 = consensus.networks.testnet4
local INTERVAL = consensus.DIFFICULTY_ADJUSTMENT_INTERVAL
local POW_LIMIT = TESTNET4.pow_limit_bits
local REAL_BITS = 0x1c00ffff            -- a non-powLimit difficulty
local T0 = 1714777860                   -- arbitrary testnet4-era timestamp

local function fake_hash(height, tag)
  -- 32 distinct bytes per (height, tag): enough to key and link the fixture.
  local s = string.format("%-8s%024d", tag or "m", height)
  return types.hash256(s)
end

--- Build a HeaderChain holding a linked chain from `anchor_height` (bits =
--- REAL_BITS) followed by `n_min` powLimit headers, all 10 minutes apart.
--- Returns chain, the tip entry, and the counting state.
local function build_chain(anchor_height, n_min, opts)
  opts = opts or {}
  local chain = sync.new_header_chain(TESTNET4, helpers.mock_storage())
  local store = {}
  local counter = { lookups = 0 }
  chain.headers = setmetatable({}, {
    __index = function(_, k)
      counter.lookups = counter.lookups + 1
      return store[k]
    end,
    __newindex = function(_, k, v) store[k] = v end,
  })

  local prev_hash = fake_hash(anchor_height - 1, "pre")
  local tip
  for i = 0, n_min do
    local h = anchor_height + i
    local bits = (i == 0) and REAL_BITS or POW_LIMIT
    if opts.bits_at and opts.bits_at[h] then bits = opts.bits_at[h] end
    local hash = fake_hash(h)
    local entry = {
      header = { prev_hash = prev_hash, bits = bits, timestamp = T0 + 600 * i },
      height = h,
    }
    store[types.hash256_hex(hash)] = entry
    prev_hash = hash
    tip = entry
  end
  return chain, tip, counter
end

describe("min-difficulty walk-back through the HeaderChain oracle", function()
  it("costs at most 2 hops per walked header over 2015 linked powLimit headers", function()
    -- Anchor at 2016 (a retarget height, real bits), then 2014 powLimit
    -- headers 2017..4030: 2015 linked headers.  The candidate at 4031 is
    -- inside the period and on time, so the walk descends all 2014 powLimit
    -- headers to the anchor -- the longest walk a single period allows.
    local anchor = INTERVAL
    local chain, parent, counter = build_chain(anchor, INTERVAL - 2)
    assert.are.equal(anchor + INTERVAL - 2, parent.height)

    local candidate_height = parent.height + 1
    local candidate_ts = parent.header.timestamp + 600   -- not a 20-min gap

    counter.lookups = 0
    local bits, why = consensus.get_next_work_required(
      candidate_height, candidate_ts, TESTNET4, chain:make_work_ancestor_fn(parent))

    assert.is_nil(why)
    assert.are.equal(REAL_BITS, bits)          -- walked all the way to the anchor
    assert.is_true(counter.lookups <= 2 * (INTERVAL - 1),
      string.format("walk-back took %d get_ancestor_entry hops for %d headers (limit %d)",
        counter.lookups, INTERVAL - 1, 2 * (INTERVAL - 1)))
  end)

  it("still stops at the first non-powLimit header mid-run", function()
    local anchor = INTERVAL
    local stop_h = anchor + 1000
    local chain, parent = build_chain(anchor, INTERVAL - 2, { bits_at = { [stop_h] = 0x1c7fffff } })
    local bits = consensus.get_next_work_required(
      parent.height + 1, parent.header.timestamp + 600, TESTNET4,
      chain:make_work_ancestor_fn(parent))
    assert.are.equal(0x1c7fffff, bits)
  end)

  it("still fails closed when the run descends past a missing ancestor", function()
    -- Anchor at 2017 is powLimit too and its parent (2016) is not held, so the
    -- walk must report missing-ancestor rather than guess.
    local chain, parent = build_chain(INTERVAL + 1, 100,
      { bits_at = { [INTERVAL + 1] = POW_LIMIT } })
    local bits, why = consensus.get_next_work_required(
      parent.height + 1, parent.header.timestamp + 600, TESTNET4,
      chain:make_work_ancestor_fn(parent))
    assert.is_nil(bits)
    assert.are.equal("missing-ancestor:" .. INTERVAL, why)
  end)

  it("returns the same oracle answers for out-of-order lookups", function()
    -- The oracle is shared by every caller of get_next_work_required; a
    -- request ABOVE the last answer must still resolve from the parent.
    local chain, parent = build_chain(INTERVAL, 200)
    local get = chain:make_work_ancestor_fn(parent)
    assert.are.equal(INTERVAL + 50, get(INTERVAL + 50).height)
    assert.are.equal(INTERVAL + 10, get(INTERVAL + 10).height)
    assert.are.equal(INTERVAL + 150, get(INTERVAL + 150).height)
    assert.are.equal(INTERVAL + 150, get(INTERVAL + 150).height)
    assert.are.equal(INTERVAL, get(INTERVAL).height)
    assert.is_nil(get(INTERVAL - 1))
    assert.is_nil(get(parent.height + 1))
    assert.are.equal(parent.height, get(parent.height).height)
  end)
end)
