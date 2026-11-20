-- spec/mempool_cluster_unionfind_leak_spec.lua
--
-- No union-find key may outlive its mempool entry.
--
-- The cluster union-find (uf_parent / uf_rank in src/mempool.lua) is the
-- mempool's record of which transactions share a cluster.  On master,
-- remove_transaction deleted only the removed txid's own key, and uf_find
-- re-inserted a missing parent as a fresh root whenever a surviving
-- transaction still pointed at it.  So a removed txid that another node
-- pointed at came back as a key with no entry, and nothing ever deleted it
-- again (remove_transaction returns early for a txid with no entry).  The
-- union-find then grew with uptime, and every walk over it (the cluster
-- reporting helpers, the reorg cluster-link pass) got slower with it.
--
-- Core: TxGraph::RemoveTransaction drops the transaction's node completely
-- and the cluster splits along the remaining dependencies (txgraph.cpp
-- ApplyRemovals / Split), so the graph holds exactly the mempool's
-- transactions and per-transaction work is bounded by the cluster.

local types      = require("lunarblock.types")
local mempool    = require("lunarblock.mempool")
local validation = require("lunarblock.validation")

describe("mempool cluster union-find holds only live transactions", function()
  local P2PKH = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"

  local counter = 0
  local function fresh_txid()
    counter = counter + 1
    return types.hash256(string.format("uf-leak-spec-%019d", counter))
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
      value = value, script_pubkey = P2PKH,
      height = 699990, is_coinbase = false,
    }
  end

  local function spend(prevs, outs)
    local ins = {}
    for i, p in ipairs(prevs) do
      ins[i] = types.txin(types.outpoint(p[1], p[2]), "", 0xFFFFFFFD)
    end
    local o = {}
    for i, v in ipairs(outs) do o[i] = types.txout(v, P2PKH) end
    return types.transaction(2, ins, o, 0)
  end

  local function accept(mp, tx)
    local ok, res = mp:accept_transaction(tx)
    assert.is_true(ok, tostring(res))
    return validation.compute_txid(tx), types.hash256_hex(validation.compute_txid(tx))
  end

  -- Keys present before the test: the union-find is module-level, so other
  -- mempools built in this process may own keys of their own.
  local function key_set()
    local s = {}
    for k in pairs(mempool.uf_parent) do s[k] = true end
    return s
  end

  -- Keys this test added that have no entry in `mp`, and how many it added.
  local function new_keys(before, mp)
    local leaked, n = {}, 0
    for k in pairs(mempool.uf_parent) do
      if not before[k] then
        n = n + 1
        if not mp.entries[k] then leaked[#leaked + 1] = k end
      end
    end
    return leaked, n
  end

  -- One round of the finding's scenario.  P has two outputs.  C spends P:0,
  -- so P joins C's set and points at C.  C2 RBF-replaces C (same input,
  -- higher fee), which removes C.  D then spends P:1 and U is unrelated.
  -- Returns the hex txids so the caller can check them.
  local function rbf_round(mp, cs)
    local coin = fresh_txid()
    add_utxo(cs, coin, 0, 1000000)
    local p, p_hex = accept(mp, spend({ { coin, 0 } }, { 400000, 400000 }))
    local _, c_hex = accept(mp, spend({ { p, 0 } }, { 399000 }))
    local _, c2_hex = accept(mp, spend({ { p, 0 } }, { 390000 }))
    assert.is_nil(mp.entries[c_hex], "C must be replaced by C2")
    local _, d_hex = accept(mp, spend({ { p, 1 } }, { 399000 }))
    local u_coin = fresh_txid()
    add_utxo(cs, u_coin, 0, 1000000)
    local _, u_hex = accept(mp, spend({ { u_coin, 0 } }, { 990000 }))
    return { p = p_hex, c = c_hex, c2 = c2_hex, d = d_hex, u = u_hex }
  end

  it("an RBF-replaced child leaves no union-find key behind", function()
    local cs = make_chain()
    local mp = mempool.new(cs)
    local before = key_set()

    local r = rbf_round(mp, cs)

    assert.is_nil(mempool.uf_parent[r.c],
      "replaced tx C still has a union-find key (resurrected by uf_find)")
    local leaked = new_keys(before, mp)
    assert.are_same({}, leaked)
  end)

  it("1000 RBF rounds leave exactly tx_count union-find keys", function()
    local cs = make_chain()
    local mp = mempool.new(cs)
    local before = key_set()

    for _ = 1, 1000 do rbf_round(mp, cs) end

    local leaked, n = new_keys(before, mp)
    assert.are_equal(0, #leaked,
      #leaked .. " union-find keys have no mempool entry")
    assert.are_equal(mp.tx_count, n)
  end)

  it("removing a confirmed parent splits its cluster and drops its key", function()
    -- P has two children C1 and C2.  When a block confirms P, Core's TxGraph
    -- removes P and C1, C2 become two clusters.  The union-find kept them in
    -- one set rooted at a surviving child, so the cluster reporting helpers
    -- counted the other child in it.
    local cs = make_chain()
    local mp = mempool.new(cs)
    local before = key_set()

    local coin = fresh_txid()
    add_utxo(cs, coin, 0, 1000000)
    local p, p_hex = accept(mp, spend({ { coin, 0 } }, { 400000, 400000 }))
    local _, c1_hex = accept(mp, spend({ { p, 0 } }, { 399000 }))
    local _, c2_hex = accept(mp, spend({ { p, 1 } }, { 399000 }))
    assert.are_equal(3, mempool.get_cluster_size(mempool.uf_find(c1_hex)))

    mp:remove_confirmed(p_hex)
    assert.are_equal(2, mp.tx_count)

    assert.is_nil(mempool.uf_parent[p_hex], "confirmed P keeps a union-find key")
    assert.are_same({ c1_hex }, mempool.get_cluster_txids(mempool.uf_find(c1_hex)))
    assert.are_same({ c2_hex }, mempool.get_cluster_txids(mempool.uf_find(c2_hex)))
    assert.are_equal(1, mempool.get_cluster_size(mempool.uf_find(c2_hex)))
    assert.are_same({}, (new_keys(before, mp)))
  end)

  it("a removal keeps the transactions that are still linked in one cluster", function()
    -- Control: removing a leaf must not split what is still connected.
    -- A <- B <- C plus A <- D; removing C leaves {A, B, D} one cluster.
    local cs = make_chain()
    local mp = mempool.new(cs)
    local coin = fresh_txid()
    add_utxo(cs, coin, 0, 1000000)
    local a, a_hex = accept(mp, spend({ { coin, 0 } }, { 400000, 400000 }))
    local b, b_hex = accept(mp, spend({ { a, 0 } }, { 399000 }))
    local _, c_hex = accept(mp, spend({ { b, 0 } }, { 398000 }))
    local _, d_hex = accept(mp, spend({ { a, 1 } }, { 399000 }))

    mp:remove_transaction(c_hex, "test")
    assert.is_nil(mempool.uf_parent[c_hex])
    local txids = mempool.get_cluster_txids(mempool.uf_find(d_hex))
    table.sort(txids)
    local want = { a_hex, b_hex, d_hex }
    table.sort(want)
    assert.are_same(want, txids)
    assert.are_equal(mempool.uf_find(a_hex), mempool.uf_find(b_hex))
    assert.are_equal(mempool.uf_find(a_hex), mempool.uf_find(d_hex))
  end)
end)
