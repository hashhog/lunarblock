-- spec/mempool_accept_memory_spec.lua
--
-- Accepting one transaction must cost memory in proportion to its cluster, not
-- to the whole mempool.
--
-- The mainnet node was OOM-killed at its 20G cgroup cap (2026-11-17 00:39Z)
-- with a ~70k-tx mempool.  Its own [DIAG] lines show the Lua heap climbing
-- ~500 MB a minute between collections and jumping by gigabytes during tx
-- bursts.  The cause: the cluster-limit gate in accept_transaction called
-- get_cluster_stats(), which copied EVERY union-find key (the whole mempool,
-- plus removed txids the re-root path brings back) into a fresh array and ran
-- uf_find on each of them, once per accepted transaction.  At 70k entries that
-- is about 1 MB of garbage per tx; a few thousand txs arriving together is
-- gigabytes, faster than the incremental GC returns it.
--
-- Core sizes the cluster from TxGraph, whose work is bounded by the cluster
-- (txgraph.cpp, IsOversized after AddTransaction/AddDependency), and the
-- cluster is the connected component of the live dependency graph: a removed
-- transaction no longer joins the two halves it used to link (TxGraph splits
-- the cluster on removal).

local types      = require("lunarblock.types")
local mempool    = require("lunarblock.mempool")
local validation = require("lunarblock.validation")

describe("mempool accept memory is bounded by the cluster", function()
  local P2PKH = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"

  local counter = 0
  local function fresh_txid()
    counter = counter + 1
    return types.hash256(string.format("accept-memory-spec-%013d", counter))
  end

  local function make_chain()
    local cv = {
      utxos = {},
      get = function(self, txid_hash, vout)
        return self.utxos[types.hash256_hex(txid_hash) .. ":" .. vout]
      end,
    }
    return { coin_view = cv, tip_height = 700000 }
  end

  local function add_utxo(cs, txid_hash, vout, value)
    cs.coin_view.utxos[types.hash256_hex(txid_hash) .. ":" .. vout] = {
      value = value or 100000, script_pubkey = P2PKH,
      height = 699990, is_coinbase = false,
    }
  end

  -- A one-in one-out tx spending a fresh confirmed coin: its own cluster.
  local function singleton(cs)
    local coin = fresh_txid()
    add_utxo(cs, coin, 0, 1000000)
    return types.transaction(1,
      { types.txin(types.outpoint(coin, 0), "", 0xFFFFFFFE) },
      { types.txout(900000, P2PKH) }, 0)
  end

  local function fill(mp, cs, n)
    for _ = 1, n do
      local ok, err = mp:accept_transaction(singleton(cs))
      assert.is_true(ok, tostring(err))
    end
  end

  -- Average Lua-heap allocation (KB) of accepting `k` singletons, with the
  -- collector stopped so freed garbage still counts.
  local function avg_accept_kb(mp, cs, k)
    local txs = {}
    for i = 1, k do
      local tx = singleton(cs)
      validation.compute_txid(tx)   -- warm the txid cache outside the window
      txs[i] = tx
    end
    collectgarbage("collect")
    collectgarbage("stop")
    local before = collectgarbage("count")
    for i = 1, k do
      local ok, err = mp:accept_transaction(txs[i])
      assert.is_true(ok, tostring(err))
    end
    local used = collectgarbage("count") - before
    collectgarbage("restart")
    return used / k
  end

  it("does not grow with the size of the pool", function()
    local cs = make_chain()
    local mp = mempool.new(cs)
    fill(mp, cs, 500)
    local small = avg_accept_kb(mp, cs, 40)
    fill(mp, cs, 12000)
    local large = avg_accept_kb(mp, cs, 40)
    -- 25x more entries.  The old gate allocated ~16 bytes per union-find key
    -- per accept (the key array plus its doublings), so `large` was hundreds
    -- of KB above `small`.  Allow 32 KB of noise for the tables' own growth.
    assert.is_true(large - small < 32,
      string.format("accept allocates %.1f KB at %d txs vs %.1f KB at 500: "
        .. "per-tx cost scales with the pool", large, mp.tx_count, small))
  end)

  it("sizes the cluster by live links, so a removed linking tx splits it", function()
    -- Core: TxGraph removes the tx and splits the cluster; the gate then sees
    -- only the live component.  The union-find never split, so the two
    -- halves stayed one cluster and a later tx was refused as
    -- too-large-cluster although its real cluster held 41 transactions.
    local cs = make_chain()
    local mp = mempool.new(cs)

    local function chain_of(n)
      local coin = fresh_txid()
      add_utxo(cs, coin, 0, 50000000)
      local prev, value = coin, 50000000
      for _ = 1, n do
        value = value - 10000
        local tx = types.transaction(1,
          { types.txin(types.outpoint(prev, 0), "", 0xFFFFFFFE) },
          { types.txout(value, P2PKH), types.txout(10000 - 5000, P2PKH) }, 0)
        local ok, err = mp:accept_transaction(tx)
        assert.is_true(ok, tostring(err))
        prev = validation.compute_txid(tx)
      end
      return prev, value
    end

    local a_tip, a_value = chain_of(30)
    local b_tip = chain_of(30)

    -- X joins the two chains through their change outputs: 61 txs, allowed.
    local x = types.transaction(1,
      { types.txin(types.outpoint(a_tip, 1), "", 0xFFFFFFFE),
        types.txin(types.outpoint(b_tip, 1), "", 0xFFFFFFFE) },
      { types.txout(9000, P2PKH) }, 0)
    local ok, x_hex = mp:accept_transaction(x)
    assert.is_true(ok, tostring(x_hex))
    assert.are_equal(61, mp.tx_count)

    -- X leaves the pool (it has no descendants, so nothing else goes).
    mp:remove_transaction(x_hex, "test")
    assert.are_equal(60, mp.tx_count)

    -- Extend chain A by 11: its live cluster is 41, far under 64.
    local prev, value = a_tip, a_value
    for i = 1, 11 do
      value = value - 10000
      local tx = types.transaction(1,
        { types.txin(types.outpoint(prev, 0), "", 0xFFFFFFFE) },
        { types.txout(value, P2PKH) }, 0)
      local accepted, err = mp:accept_transaction(tx)
      assert.is_true(accepted, string.format(
        "extension %d of chain A (live cluster %d) refused: %s",
        i, 30 + i, tostring(err)))
      prev = validation.compute_txid(tx)
    end
    assert.are_equal(71, mp.tx_count)
  end)

  it("still refuses the 65th transaction of a live cluster", function()
    local cs = make_chain()
    local mp = mempool.new(cs)
    local coin = fresh_txid()
    add_utxo(cs, coin, 0, 50000000)
    local prev, value = coin, 50000000
    for i = 1, 65 do
      value = value - 10000
      local tx = types.transaction(1,
        { types.txin(types.outpoint(prev, 0), "", 0xFFFFFFFE) },
        { types.txout(value, P2PKH) }, 0)
      local ok, err = mp:accept_transaction(tx)
      if i <= 64 then
        assert.is_true(ok, "tx " .. i .. ": " .. tostring(err))
      else
        assert.is_false(ok)
        assert.are_equal("too-large-cluster", err)
      end
      prev = validation.compute_txid(tx)
    end
    assert.are_equal(64, mp.tx_count)
  end)

  it("refuses a tx whose parents' clusters together pass 64", function()
    -- Two live chains of 32 and a child of both: 65 in one component.
    local cs = make_chain()
    local mp = mempool.new(cs)
    local tips = {}
    for c = 1, 2 do
      local coin = fresh_txid()
      add_utxo(cs, coin, 0, 50000000)
      local prev, value = coin, 50000000
      for _ = 1, 32 do
        value = value - 10000
        local tx = types.transaction(1,
          { types.txin(types.outpoint(prev, 0), "", 0xFFFFFFFE) },
          { types.txout(value, P2PKH), types.txout(5000, P2PKH) }, 0)
        local ok, err = mp:accept_transaction(tx)
        assert.is_true(ok, tostring(err))
        prev = validation.compute_txid(tx)
      end
      tips[c] = prev
    end
    local child = types.transaction(1,
      { types.txin(types.outpoint(tips[1], 1), "", 0xFFFFFFFE),
        types.txin(types.outpoint(tips[2], 1), "", 0xFFFFFFFE) },
      { types.txout(9000, P2PKH) }, 0)
    local ok, err = mp:accept_transaction(child)
    assert.is_false(ok)
    assert.are_equal("too-large-cluster", err)
    assert.are_equal(64, mp.tx_count)
  end)
end)

-- During a reorg refill, the gate must not see the links that
-- link_mempool_children deferred.  Core re-admits each disconnected tx with
-- AcceptToMemoryPool BEFORE UpdateTransactionsFromBlock adds the re-added
-- parents' dependencies on their in-pool children, then Trims once
-- (validation.cpp MaybeUpdateMempoolForReorg, txmempool.cpp).  A second tx of
-- the disconnected block that spends the first therefore sees a 2-tx cluster,
-- however many in-pool children the first already has.
describe("reorg refill: the accept gate ignores deferred links", function()
  local utxo        = require("lunarblock.utxo")
  local consensus   = require("lunarblock.consensus")
  local script      = require("lunarblock.script")
  local crypto      = require("lunarblock.crypto")
  local storage_mod = require("lunarblock.storage")

  local OP_TRUE = "\x51"
  local SPK = script.make_p2sh_script(crypto.hash160(OP_TRUE))
  local SIG = "\x01" .. OP_TRUE
  local T0 = os.time() - 200 * 600

  local function hx(tx) return types.hash256_hex(validation.compute_txid(tx)) end

  local function coinbase(height)
    local subsidy = math.floor(5000000000 / (2 ^ math.floor(height / 150)))
    return types.transaction(1,
      {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                  string.char(2, height % 256, math.floor(height / 256)),
                  0xFFFFFFFF)},
      {types.txout(subsidy, SPK)}, 0)
  end

  local function spend(prev_tx, vout, outputs)
    return types.transaction(2,
      {types.txin(types.outpoint(validation.compute_txid(prev_tx), vout), SIG, 0xFFFFFFFE)},
      outputs, 0)
  end

  local path, db
  after_each(function()
    if db then pcall(db.close) end
    if path then os.execute("rm -rf '" .. path .. "'") end
    db, path = nil, nil
  end)

  it("re-admits the block's second tx although the first has 63 in-pool children", function()
    path = "/tmp/lunarblock_acceptmem_reorg_" .. os.time() .. "_" .. math.random(1e9)
    db = storage_mod.open(path)
    local cs = utxo.new_chain_state(db, consensus.networks.regtest)
    cs:init()
    local mp = mempool.new(cs, {})
    cs.callbacks.on_block_connected = function(_, block) mp:on_block_connected(block) end

    local prev = types.hash256_zero()
    local function connect(height, txs)
      local header = types.block_header(4, prev, types.hash256_zero(),
        T0 + height * 600, consensus.networks.regtest.pow_limit_bits, 0)
      local block = types.block(header, txs)
      local bh = validation.compute_block_hash(header)
      db.put_header(bh, header); db.put_block(bh, block); db.put_height_index(height, bh)
      local ok, err = cs:connect_block(block, height, bh, nil, nil, true)
      assert(ok, "connect_block h=" .. height .. ": " .. tostring(err))
      prev = bh
      return bh
    end
    connect(0, {coinbase(0)})
    local cb1
    for h = 1, 110 do
      local cb = coinbase(h)
      if h == 1 then cb1 = cb end
      connect(h, {cb})
    end

    -- P fans coinbase(1) out to 64 outputs; T2 (same block) spends output 63
    -- with a high fee; 63 in-pool children spend outputs 0..62.
    local input = cb1.outputs[1].value
    local each = math.floor((input - 10000) / 64)
    local outs = {}
    for i = 1, 64 do outs[i] = types.txout(each, SPK) end
    local P = spend(cb1, 0, outs)
    local T2 = spend(P, 63, {types.txout(each - 500000, SPK)})
    local tip = connect(111, {coinbase(111), P, T2})

    local children = {}
    for i = 1, 63 do
      children[i] = spend(P, i - 1, {types.txout(each - i * 1000, SPK)})
      local ok, why = mp:accept_transaction(children[i])
      assert(ok, "child " .. i .. ": " .. tostring(why))
    end

    assert.truthy(cs:invalidate_block(tip, mp))

    -- Core: P and T2 are re-admitted ({P}, then {P, T2}); the deferred links
    -- then make a 65-tx cluster and Trim drops the lowest-feerate child.
    assert.is_not_nil(mp.entries[hx(P)], "re-added P stays")
    assert.is_not_nil(mp.entries[hx(T2)],
      "T2 must be re-admitted: its cluster at accept time is {P, T2}")
    assert.is_nil(mp.entries[hx(children[1])], "lowest-feerate child trimmed")
    for i = 2, 63 do
      assert.is_not_nil(mp.entries[hx(children[i])], "child " .. i .. " kept")
    end
    -- P + T2 + 62 children: one 64-tx cluster, the whole pool.
    assert.are_equal(64, mp.tx_count)
  end)
end)
