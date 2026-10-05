-- Block-template lock-time cutoff = MTP of the tip the template builds on
-- (Core node/miner.cpp CreateNewBlock: m_lock_time_cutoff =
-- pindexPrev->GetMedianTimePast(); mintime = GetMinimumTime = MTP+1;
-- curtime = block time = max(MTP+1, now)).
-- Pre-fix (4ab752a) mining.lua used `chain_state.mtp or (os.time() - 3600)` and
-- production never assigned chain_state.mtp -> wall clock - 1h.
local types = require("lunarblock.types")
local mining = require("lunarblock.mining")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")

describe("block template MTP (getblocktemplate mintime/curtime, lock-time cutoff)", function()
  local TIP = 50

  local function make_cs(T0, step, drop)
    local headers = {}
    local prev = types.hash256_zero()
    local tip_hash
    for h = 0, TIP do
      local hash = types.hash256(string.format("tmpl%028d", h))
      headers[hash.bytes] = { version = 4, prev_hash = prev, merkle_root = types.hash256_zero(),
        timestamp = T0 + step * h, bits = consensus.networks.regtest.pow_limit_bits, nonce = 0 }
      prev = hash
      tip_hash = hash
    end
    if drop then
      -- drop the header at height TIP-3 (inside the tip's MTP window)
      local cur = tip_hash
      for _ = 1, 3 do cur = headers[cur.bytes].prev_hash end
      headers[cur.bytes] = nil
    end
    return {
      tip_height = TIP,
      tip_hash = tip_hash,
      storage = { get_header = function(hash) return headers[hash.bytes] end },
    }
  end

  local function entry_for(tx)
    local weight = validation.get_tx_weight(tx)
    local vsize = math.ceil(weight / 4)
    return { tx = tx, txid = validation.compute_txid(tx), wtxid = validation.compute_wtxid(tx),
      fee = 1000, vsize = vsize, weight = weight, fee_rate = 1000 / vsize, height = TIP,
      time = os.time(), ancestors = {}, descendants = {}, ancestor_count = 0,
      descendant_count = 0, ancestor_size = 0, descendant_size = 0, ancestor_fees = 0,
      descendant_fees = 0 }
  end

  local function mock_mempool(entries)
    local map = {}
    for _, e in ipairs(entries) do map[types.hash256_hex(e.txid)] = e end
    return { get_sorted_entries = function() return entries end,
             has = function(_, h) return map[h] ~= nil end }
  end

  local function locked_tx(tag, locktime)
    return types.transaction(2,
      { types.txin(types.outpoint(types.hash256(string.format("in%-30s", tag)), 0), "", 0xFFFFFFFE) },
      { types.txout(9000, "\x51") }, locktime)
  end

  local PAYOUT = "\x51"
  local REGTEST = consensus.networks.regtest

  -- tip MTP of a strictly increasing chain = timestamp at TIP-5
  local T0, STEP = 1500000000, 600
  local TIP_MTP = T0 + STEP * (TIP - 5)

  it("mintime = tip MTP + 1 and curtime >= mintime (old chain: MTP years in the past)", function()
    local tmpl = mining.create_block_template(mock_mempool({}), make_cs(T0, STEP), REGTEST, PAYOUT)
    assert.equal(TIP_MTP + 1, tmpl.mintime)
    assert.is_true(tmpl.curtime >= tmpl.mintime)
  end)

  it("curtime = MTP + 1 when the tip MTP is AHEAD of the wall clock (never below mintime)", function()
    local future = os.time() + 100000
    local cs = make_cs(future, 1)
    local mtp = future + (TIP - 5)
    local tmpl, block = mining.create_block_template(mock_mempool({}), cs, REGTEST, PAYOUT)
    assert.equal(mtp + 1, tmpl.mintime)
    assert.equal(mtp + 1, tmpl.curtime)
    assert.equal(mtp + 1, block.header.timestamp)
  end)

  it("includes nLockTime = tip MTP - 1, EXCLUDES nLockTime = tip MTP (BIP-113 cutoff)", function()
    local ok_tx = locked_tx("ok", TIP_MTP - 1)
    local bad_tx = locked_tx("bad", TIP_MTP)
    local tmpl, block = mining.create_block_template(
      mock_mempool({ entry_for(bad_tx), entry_for(ok_tx) }), make_cs(T0, STEP), REGTEST, PAYOUT)
    assert.equal(2, #block.transactions)
    assert.equal(1, #tmpl.transactions)
    assert.equal(types.hash256_hex(validation.compute_txid(ok_tx)),
      types.hash256_hex(validation.compute_txid(block.transactions[2])))
  end)

  it("EXCLUDES a tx locked to a time between the tip MTP and wall clock - 1h", function()
    -- The pre-fix cutoff (now - 3600) would have included this non-final tx.
    local tx = locked_tx("mid", TIP_MTP + 1000)
    local _, block = mining.create_block_template(
      mock_mempool({ entry_for(tx) }), make_cs(T0, STEP), REGTEST, PAYOUT)
    assert.equal(1, #block.transactions)
  end)

  it("refuses to build a template when the tip MTP window is not held (fail closed)", function()
    assert.has_error(function()
      mining.create_block_template(mock_mempool({}), make_cs(T0, STEP, true), REGTEST, PAYOUT)
    end)
  end)
end)
