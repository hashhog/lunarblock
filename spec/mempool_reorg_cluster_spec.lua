-- Reorg refill must not leave a cluster over Core's limits.
--
-- Bitcoin Core v31.1 MaybeUpdateMempoolForReorg (validation.cpp) re-admits
-- disconnected txs with AcceptToMemoryPool, then
-- CTxMemPool::UpdateTransactionsFromBlock (txmempool.cpp) AddDependency's
-- each re-added parent to its in-mempool children and calls
-- TxGraphImpl::Trim (txgraph.cpp). Trim keeps the highest-chunk-feerate
-- prefix that respects dependencies and drops the rest (with descendants)
-- so the cluster is back within cluster_count (64) and cluster size
-- (404000 weight). A parent that was confirmed, plus N children that were
-- each their own cluster while it was confirmed, is the case AcceptToMemoryPool
-- cannot see: the cluster check there only unions in-mempool input-parents.

local types = require("lunarblock.types")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local script = require("lunarblock.script")
local crypto = require("lunarblock.crypto")
local storage_mod = require("lunarblock.storage")
local mempool_mod = require("lunarblock.mempool")

local OP_TRUE = "\x51"
local SPK = script.make_p2sh_script(crypto.hash160(OP_TRUE))
local SIG = "\x01" .. OP_TRUE

local function subsidy(height)
  return math.floor(5000000000 / (2 ^ math.floor(height / 150)))
end

local function coinbase(height, tag)
  return types.transaction(1,
    {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                string.char(2, height % 256, math.floor(height / 256)) .. (tag or ""),
                0xFFFFFFFF)},
    {types.txout(subsidy(height), SPK)}, 0)
end

local function hx(tx) return types.hash256_hex(validation.compute_txid(tx)) end

local T0 = os.time() - 200 * 600
local function make_block(height, txs, prev_hash)
  local header = types.block_header(4, prev_hash, types.hash256_zero(),
    T0 + height * 600, consensus.networks.regtest.pow_limit_bits, 0)
  return types.block(header, txs)
end

-- Parent spending prev's vout 0 into `n` equal P2SH outputs.
local function fan_parent(prev, n, fee)
  local input = prev.outputs[1].value
  local each = math.floor((input - fee) / n)
  local rem = (input - fee) - each * n
  local outputs = {}
  for i = 1, n do
    outputs[i] = types.txout(each + (i == 1 and rem or 0), SPK)
  end
  return types.transaction(2,
    {types.txin(types.outpoint(validation.compute_txid(prev), 0), SIG, 0xFFFFFFFE)},
    outputs, 0)
end

local function child_of(parent, vout, fee, opreturn)
  local outputs = {types.txout(parent.outputs[vout + 1].value - fee, SPK)}
  if opreturn then outputs[2] = types.txout(0, opreturn) end
  return types.transaction(2,
    {types.txin(types.outpoint(validation.compute_txid(parent), vout), SIG, 0xFFFFFFFE)},
    outputs, 0)
end

-- OP_RETURN <pushdata2 data>. Script stays under MAX_OP_RETURN_RELAY.
local function nulldata(nbytes)
  return "\x6a\x4d" .. string.char(nbytes % 256, math.floor(nbytes / 256))
    .. string.rep("\0", nbytes)
end

describe("reorg refill cluster limits (TxGraphImpl::Trim)", function()
  local path, db, cs, mp

  local function fresh()
    path = "/tmp/lunarblock_mpcluster_" .. os.time() .. "_" .. math.random(1e9)
    db = storage_mod.open(path)
    cs = utxo.new_chain_state(db, consensus.networks.regtest)
    cs:init()
    mp = mempool_mod.new(cs, {})
    cs.callbacks.on_block_connected = function(_, block)
      mp:on_block_connected(block)
    end
  end

  local function connect(height, txs, prev)
    local block = make_block(height, txs, prev)
    local bh = validation.compute_block_hash(block.header)
    db.put_header(bh, block.header)
    db.put_block(bh, block)
    db.put_height_index(height, bh)
    local ok, err = cs:connect_block(block, height, bh, nil, nil, true)
    assert(ok, "connect_block h=" .. height .. ": " .. tostring(err))
    return bh
  end

  -- Mature coinbases, then `parent` confirmed in the tip block.
  local function chain_with_parent(parent_tx)
    local prev = types.hash256_zero()
    local tip
    tip = connect(0, {coinbase(0)}, prev)
    prev = tip
    local cbs = {}
    for h = 1, 110 do
      cbs[h] = coinbase(h)
      prev = connect(h, {cbs[h]}, prev)
    end
    local ph = connect(111, {coinbase(111), parent_tx}, prev)
    return ph, cbs
  end

  local function cluster_count(txid_hex)
    local root = mempool_mod.uf_find(txid_hex)
    return mempool_mod.get_cluster_stats(root, mp.entries)
  end

  local function cluster_weight(txid_hex)
    local root = mempool_mod.uf_find(txid_hex)
    local _, w = mempool_mod.get_cluster_stats(root, mp.entries)
    return w
  end

  after_each(function()
    if db then pcall(db.close) end
    if path then os.execute("rm -rf '" .. path .. "'") end
    db, path = nil, nil
  end)

  it("parent plus 64 in-pool children is trimmed to 64 on invalidateblock", function()
    fresh()
    -- chain_with_parent confirms coinbase(1); the parent spends that coinbase.
    local spend_cb = coinbase(1)
    local parent = fan_parent(spend_cb, 64, 10000)
    local tip = chain_with_parent(parent)
    local children = {}
    for i = 1, 64 do
      -- i == 1 is the lowest fee. Identical shapes, so fee order is feerate order.
      children[i] = child_of(parent, i - 1, i * 1000)
      local ok, why = mp:accept_transaction(children[i])
      assert(ok, "child " .. i .. " admitted: " .. tostring(why))
      assert.equal(1, cluster_count(hx(children[i])))
    end

    local ok, err = cs:invalidate_block(tip, mp)
    assert.truthy(ok, tostring(err))
    assert.equal(110, cs.tip_height)

    -- Core Trim: the parent stays (children depend on it), then the 63
    -- highest-feerate children. The lowest-feerate child is removed.
    -- 64 is not over the limit; 65 is.
    assert.is_not_nil(mp.entries[hx(parent)], "re-added parent must stay")
    local n = cluster_count(hx(parent))
    assert.equal(64, n, "cluster count after refill is " .. tostring(n)
      .. " (limit 64); lowest-fee child still present: "
      .. tostring(mp.entries[hx(children[1])] ~= nil))
    assert.is_nil(mp.entries[hx(children[1])], "lowest-feerate child dropped")
    for i = 2, 64 do
      local e = mp.entries[hx(children[i])]
      assert.is_not_nil(e, "higher-feerate child " .. i .. " kept")
      assert.is_true(e.ancestors[hx(parent)] == true)
    end
    assert.is_true(mp.entries[hx(parent)].descendants[hx(children[64])] == true)
    assert.is_nil(mp.entries[hx(parent)].descendants[hx(children[1])])
  end)

  it("parent plus 63 in-pool children stays a 64-tx cluster", function()
    fresh()
    local parent = fan_parent(coinbase(1), 63, 10000)
    local tip = chain_with_parent(parent)
    local children = {}
    for i = 1, 63 do
      children[i] = child_of(parent, i - 1, i * 1000)
      local ok, why = mp:accept_transaction(children[i])
      assert(ok, "child " .. i .. ": " .. tostring(why))
    end
    assert.truthy(cs:invalidate_block(tip, mp))
    assert.is_not_nil(mp.entries[hx(parent)])
    assert.equal(64, cluster_count(hx(parent)))
    for i = 1, 63 do
      local e = mp.entries[hx(children[i])]
      assert.is_not_nil(e, "child " .. i)
      assert.is_true(e.ancestors[hx(parent)] == true)
    end
  end)

  it("parent plus two heavy children keeps the higher-feerate one", function()
    fresh()
    local parent = fan_parent(coinbase(1), 2, 10000)
    -- Pad until one child is heavy, two of them plus the parent exceed
    -- 404000 weight, and either child alone still fits with the parent.
    local pad, sample = 50000, nil
    for _ = 1, 8 do
      sample = child_of(parent, 0, 200000, nulldata(pad))
      local w = validation.get_tx_weight(sample)
      if w > 201000 and w < 250000 then break end
      pad = pad + math.floor((210000 - w) / 4)
      if pad < 1000 then pad = 1000 end
      if pad > 80000 then pad = 80000 end
    end
    local hi = child_of(parent, 0, 5000000, nulldata(pad))
    local lo = child_of(parent, 1, 200000, nulldata(pad))
    local tip = chain_with_parent(parent)
    local ok_hi, why_hi = mp:accept_transaction(hi)
    local ok_lo, why_lo = mp:accept_transaction(lo)
    assert(ok_hi, tostring(why_hi))
    assert(ok_lo, tostring(why_lo))
    local wh = mp.entries[hx(hi)].adjusted_weight
    local wl = mp.entries[hx(lo)].adjusted_weight
    local wp = validation.get_tx_weight(parent)
    assert.is_true(wh + wl + wp > mempool_mod.MAX_CLUSTER_WEIGHT,
      string.format("setup weight %d+%d+%d", wh, wl, wp))
    assert.is_true(wh + wp <= mempool_mod.MAX_CLUSTER_WEIGHT)
    assert.is_true(wl + wp <= mempool_mod.MAX_CLUSTER_WEIGHT)
    assert.is_true(wh == wl, "same shape, fee decides feerate")

    assert.truthy(cs:invalidate_block(tip, mp))
    assert.is_not_nil(mp.entries[hx(parent)], "parent stays")
    assert.is_not_nil(mp.entries[hx(hi)], "higher-feerate child stays")
    assert.is_nil(mp.entries[hx(lo)], "lower-feerate child dropped")
    local n, w = mempool_mod.get_cluster_stats(
      mempool_mod.uf_find(hx(parent)), mp.entries)
    assert.is_true(n <= mempool_mod.MAX_CLUSTER_COUNT, "count " .. tostring(n))
    assert.is_true(w <= mempool_mod.MAX_CLUSTER_WEIGHT,
      "cluster weight " .. tostring(w))
    assert.is_true(mp.entries[hx(hi)].ancestors[hx(parent)] == true)
    assert.equal(w, cluster_weight(hx(parent)))
  end)
end)
