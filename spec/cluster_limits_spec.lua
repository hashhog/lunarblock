-- spec/cluster_limits_spec.lua
--
-- Bitcoin Core v31 cluster mempool limits — boundary pins.
--
-- Ground truth (read directly from bitcoin-core/):
--   policy/policy.h:50          DEFAULT_BYTES_PER_SIGOP        = 20
--   policy/policy.h:72          DEFAULT_CLUSTER_LIMIT          = 64
--   policy/policy.h:74          DEFAULT_CLUSTER_SIZE_LIMIT_KVB = 101
--   kernel/mempool_limits.h:20  cluster_count       = DEFAULT_CLUSTER_LIMIT
--   kernel/mempool_limits.h:21  cluster_size_vbytes = 101 * 1000 = 101,000 vB
--   txmempool.cpp:181           max_cluster_size    = cluster_size_vbytes
--                                                     * WITNESS_SCALE_FACTOR
--                                                   = 404,000 weight units
--   policy/policy.cpp:390       GetSigOpsAdjustedWeight(weight, sigops, bps)
--                                 = max(weight, sigops * bps)
--   txmempool.cpp:1017          FeePerWeight(fee, GetSigOpsAdjustedWeight(...))
--                                 -> TxGraph::AddTransaction
--   txgraph.cpp:2059            total_count > m_max_cluster_count ||
--                               total_size  > m_max_cluster_size
--   validation.cpp:1024,:1116,:1343,:1521
--                               Invalid(..., "too-large-cluster", "")
--
-- So, in WEIGHT UNITS throughout:
--   per-tx contribution := max(tx_weight, tx_sigops_cost * 20)
--   cluster_size        := Σ (per-tx contribution)   -- no per-tx division/rounding
--   reject if cluster_size  > 404000
--   reject if cluster_count > 64
--
-- Both comparisons are strictly-greater, so 64 ACCEPTS and 65 REJECTS.
--
-- This is mempool POLICY, not consensus: none of it may affect block validation.

local types      = require("lunarblock.types")
local mempool    = require("lunarblock.mempool")
local validation = require("lunarblock.validation")

describe("cluster mempool limits (Core v31)", function()

  -- Standard P2PKH script (accepted by IsStandardTx)
  local P2PKH = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"

  local function random_txid()
    local b = ""
    for _ = 1, 32 do b = b .. string.char(math.random(0, 255)) end
    return types.hash256(b)
  end

  local function make_input(txid_hash, vout, seq)
    return types.txin(types.outpoint(txid_hash, vout), "", seq or 0xFFFFFFFE)
  end

  local function make_output(value, spk)
    return types.txout(value, spk or P2PKH)
  end

  local function make_chain(height)
    local cv = {
      utxos = {},
      get = function(self, txid_hash, vout)
        return self.utxos[types.hash256_hex(txid_hash) .. ":" .. vout]
      end
    }
    return { coin_view = cv, tip_height = height or 700000 }
  end

  local function add_utxo(cs, txid_hash, vout, value)
    cs.coin_view.utxos[types.hash256_hex(txid_hash) .. ":" .. vout] = {
      value         = value or 100000,
      script_pubkey = P2PKH,
      height        = 699990,
      is_coinbase   = false,
    }
  end

  -----------------------------------------------------------------------------
  -- Constants and units
  -----------------------------------------------------------------------------
  describe("constants", function()
    it("cluster count limit is 64 (DEFAULT_CLUSTER_LIMIT)", function()
      assert.are_equal(64, mempool.MAX_CLUSTER_COUNT)
    end)

    it("cluster size limit is 404000 WEIGHT units, not 101000 vbytes", function()
      assert.are_equal(404000, mempool.MAX_CLUSTER_WEIGHT)
      assert.are_equal(101000, mempool.MAX_CLUSTER_VSIZE)
      assert.are_equal(mempool.MAX_CLUSTER_VSIZE * 4, mempool.MAX_CLUSTER_WEIGHT)
    end)

    it("bytes-per-sigop is 20 (DEFAULT_BYTES_PER_SIGOP)", function()
      assert.are_equal(20, mempool.DEFAULT_BYTES_PER_SIGOP)
    end)

    it("MAX_PACKAGE_COUNT stays 25 — a different limit from the cluster count",
      function()
        -- policy/packages.h:19 MAX_PACKAGE_COUNT{25}; :29 static_asserts only
        -- that DEFAULT_CLUSTER_LIMIT >= MAX_PACKAGE_COUNT.  They are not the
        -- same limit and the package one must NOT be raised to 64.
        assert.are_equal(25, mempool.MAX_PACKAGE_COUNT)
      end)

    it("TRUC 2/2 limits are untouched", function()
      assert.are_equal(2, mempool.TRUC_ANCESTOR_LIMIT)
      assert.are_equal(2, mempool.TRUC_DESCENDANT_LIMIT)
    end)
  end)

  -----------------------------------------------------------------------------
  -- The arithmetic: max(weight, sigops*20), summed, no per-tx rounding
  -----------------------------------------------------------------------------
  describe("per-transaction contribution = max(weight, sigops*20)", function()
    it("returns the weight when weight dominates", function()
      assert.are_equal(1000, mempool.sigops_adjusted_weight(1000, 0))
      assert.are_equal(1000, mempool.sigops_adjusted_weight(1000, 49))  -- 980
      assert.are_equal(1000, mempool.sigops_adjusted_weight(1000, 50))  -- 1000, tie
    end)

    it("returns sigops*20 when the sigop cost dominates", function()
      assert.are_equal(1020, mempool.sigops_adjusted_weight(1000, 51))
      assert.are_equal(32000, mempool.sigops_adjusted_weight(400, 1600))
    end)

    it("an entry contributes its raw adjusted weight, never ceil(w/4)", function()
      -- 1001 wu would become 251 vB under a ceilinged-vsize formulation; the
      -- cluster accounting must see 1001, with no division and no rounding.
      local e = { adjusted_weight = 1001, weight = 1001, vsize = 251 }
      assert.are_equal(1001, mempool.entry_cluster_weight(e))
    end)

    it("summing ceilinged vsizes would be strictly stricter than Core", function()
      -- Σ⌈wᵢ/4⌉ ≥ (Σwᵢ)/4, and for wᵢ ≡ 1 (mod 4) the gap is 3 vB per tx.
      local per_tx_weight = 4001
      local n = 64
      local core_total = per_tx_weight * n                     -- 256,064 wu
      local vbyte_total = math.ceil(per_tx_weight / 4) * n     -- 1001 * 64 vB
      assert.are_equal(256064, core_total)
      assert.are_equal(64064, vbyte_total)
      -- 64064 vB * 4 = 256,256 wu — 192 wu more than Core counts.
      assert.is_true(vbyte_total * 4 > core_total)
    end)
  end)

  -----------------------------------------------------------------------------
  -- Cluster COUNT boundary: 64 accepts, 65 rejects
  -----------------------------------------------------------------------------
  describe("cluster count boundary", function()
    -- Mirrors diff-test corpus entries `cluster-linear-64` (all accept) and
    -- `cluster-linear-65` (tx index 64 rejects).  Each tx here is ~192 bytes,
    -- so a 65-tx chain is ~50,000 wu — well under 404,000.  Only COUNT can fire.
    local function build_chain(mp, coin, n)
      local prev = coin
      local last_err = nil
      local accepted = 0
      for i = 1, n do
        local tx = types.transaction(1,
          { make_input(prev, 0) },
          { make_output(50000000 - i * 100000) }, 0)
        local ok, err = mp:accept_transaction(tx)
        if not ok then
          last_err = err
          break
        end
        accepted = accepted + 1
        prev = validation.compute_txid(tx)
      end
      return accepted, last_err
    end

    it("accepts a 64-transaction cluster (64 is not > 64)", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 50000000)
      local mp = mempool.new(cs)

      local accepted, err = build_chain(mp, coin, 64)
      assert.are_equal(64, accepted, "64-tx cluster must be accepted: " .. tostring(err))
      assert.are_equal(64, mp.tx_count)
    end)

    it("rejects the 65th transaction with exactly 'too-large-cluster'", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 50000000)
      local mp = mempool.new(cs)

      local accepted, err = build_chain(mp, coin, 65)
      assert.are_equal(64, accepted, "exactly 64 must get in")
      -- Core's reject reason, with an EMPTY debug string (validation.cpp:1343).
      -- Nothing may be appended — no counts, no limit values.
      assert.are_equal("too-large-cluster", err)
      -- The rejected transaction must not have been left in the mempool.
      assert.are_equal(64, mp.tx_count)
    end)

    it("counts the whole connected component, not the ancestor set", function()
      -- 1 parent + 63 children = a 64-tx cluster in which every child has just
      -- TWO ancestors.  An ancestor-scoped count would happily accept a 65th,
      -- 100th, ... child.  Mirrors corpus entry `cluster-sibling-72`.
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 100000000)
      local mp = mempool.new(cs)

      local parent_outs = {}
      for _ = 1, 70 do parent_outs[#parent_outs + 1] = make_output(1000000) end
      local parent = types.transaction(1, { make_input(coin, 0) }, parent_outs, 0)
      local ok_p, parent_hex = mp:accept_transaction(parent)
      assert.is_true(ok_p, "parent must be accepted: " .. tostring(parent_hex))
      local parent_txid = validation.compute_txid(parent)

      -- 63 children -> cluster of 64.
      for i = 0, 62 do
        local child = types.transaction(1,
          { make_input(parent_txid, i) },
          { make_output(900000) }, 0)
        local ok, err = mp:accept_transaction(child)
        assert.is_true(ok, "child " .. i .. " must be accepted: " .. tostring(err))
      end
      assert.are_equal(64, mp.tx_count)

      -- The 64th child would make a 65-transaction cluster.
      local child64 = types.transaction(1,
        { make_input(parent_txid, 63) },
        { make_output(900000) }, 0)
      local ok64, err64 = mp:accept_transaction(child64)
      assert.is_false(ok64, "65-tx cluster must be rejected")
      assert.are_equal("too-large-cluster", err64)
      assert.are_equal(64, mp.tx_count)
    end)
  end)

  -----------------------------------------------------------------------------
  -- Cluster SIZE boundary, including the sigop-bound case
  -----------------------------------------------------------------------------
  describe("cluster size boundary (weight units)", function()
    -- Register synthetic entries in the module-level union-find and read the
    -- production accounting function (get_cluster_stats) — the exact function
    -- the acceptance gate calls.  This is how the sigop-dominated case is
    -- reachable: a *standard* transaction whose sigops*20 exceeds its weight is
    -- not constructible through the relay gates (bare multisig and raw CHECKSIG
    -- scriptPubKeys are non-standard), but the accounting must still be right,
    -- because -bytespersigop and non-standard-relay configurations reach it.
    local function link(entries, txid_hex, entry, parent_hex)
      entries[txid_hex] = entry
      mempool.uf_parent[txid_hex] = txid_hex
      mempool.uf_rank[txid_hex] = 0
      if parent_hex then mempool.uf_union(txid_hex, parent_hex) end
    end

    local function synth(weight, sigops)
      return {
        weight = weight,
        adjusted_weight = mempool.sigops_adjusted_weight(weight, sigops),
        vsize = math.ceil(mempool.sigops_adjusted_weight(weight, sigops) / 4),
        fee = 100000,
      }
    end

    it("sums raw adjusted weights across the cluster", function()
      local entries = {}
      local prefix = "c1" .. string.rep("0", 8)
      local prev = nil
      for i = 1, 4 do
        local hex = prefix .. string.format("%054d", i)
        link(entries, hex, synth(4001, 0), prev)
        prev = hex
      end
      local root = mempool.uf_find(prefix .. string.format("%054d", 1))
      local count, weight = mempool.get_cluster_stats(root, entries)
      assert.are_equal(4, count)
      -- 4 * 4001 = 16,004 wu.  Σ⌈4001/4⌉ * 4 would be 4 * 1001 * 4 = 16,016.
      assert.are_equal(16004, weight)
    end)

    it("SIGOP-BOUND: max(weight, sigops*20) is what trips the limit", function()
      -- 20 transactions of 4,000 wu each = 80,000 wu by raw weight — nowhere
      -- near 404,000.  Give each 1,600 sigops: 1,600 * 20 = 32,000 wu each, so
      -- the cluster is 20 * 32,000 = 640,000 wu and MUST be over the limit.
      -- If the implementation summed raw weight (or vsize without the sigop
      -- adjustment) it would compute 80,000 and wrongly accept.
      local entries = {}
      local prefix = "c2" .. string.rep("0", 8)
      local prev = nil
      for i = 1, 20 do
        local hex = prefix .. string.format("%054d", i)
        link(entries, hex, synth(4000, 1600), prev)
        prev = hex
      end
      local root = mempool.uf_find(prefix .. string.format("%054d", 1))
      local count, weight = mempool.get_cluster_stats(root, entries)

      assert.are_equal(20, count)
      assert.are_equal(640000, weight, "must use sigops*20, not the 4000 wu weight")
      assert.is_true(count <= mempool.MAX_CLUSTER_COUNT,
        "count must NOT be what fires here")
      assert.is_true(weight > mempool.MAX_CLUSTER_WEIGHT,
        "sigop-adjusted weight must exceed 404000")

      -- And the raw-weight sum a naive implementation would compute is under
      -- the limit, so this case genuinely discriminates the two formulations.
      local naive = 0
      for _, e in pairs(entries) do naive = naive + e.weight end
      assert.are_equal(80000, naive)
      assert.is_true(naive <= mempool.MAX_CLUSTER_WEIGHT)
    end)

    it("404000 is inside the limit and 404001 is outside (strict >)", function()
      local entries = {}
      local prefix = "c3" .. string.rep("0", 8)
      local a = prefix .. string.format("%054d", 1)
      local b = prefix .. string.format("%054d", 2)

      link(entries, a, synth(404000, 0), nil)
      local root = mempool.uf_find(a)
      local _, w_at = mempool.get_cluster_stats(root, entries)
      assert.are_equal(404000, w_at)
      assert.is_false(w_at > mempool.MAX_CLUSTER_WEIGHT, "404000 must ACCEPT")

      link(entries, b, synth(1, 0), a)
      root = mempool.uf_find(a)
      local _, w_over = mempool.get_cluster_stats(root, entries)
      assert.are_equal(404001, w_over)
      assert.is_true(w_over > mempool.MAX_CLUSTER_WEIGHT, "404001 must REJECT")
    end)
  end)

  -----------------------------------------------------------------------------
  -- Regression: union-find mutation during traversal (latent LuaJIT UB)
  -----------------------------------------------------------------------------
  describe("union-find traversal safety", function()
    -- uf_find() writes `uf_parent[x] = x` when it walks onto a node whose
    -- parent entry was nil'd by remove_transaction.  Iterating pairs(uf_parent)
    -- while that insert can happen is undefined in Lua 5.1/LuaJIT.  The cluster
    -- walks must snapshot the key set first.
    it("cluster walks survive an orphan re-root mid-traversal", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 50000000)
      local mp = mempool.new(cs)

      local hexes = {}
      local prev = coin
      for i = 1, 12 do
        local tx = types.transaction(1,
          { make_input(prev, 0) },
          { make_output(50000000 - i * 100000) }, 0)
        local ok, hex = mp:accept_transaction(tx)
        assert.is_true(ok, "tx " .. i .. ": " .. tostring(hex))
        hexes[i] = hex
        prev = validation.compute_txid(tx)
      end

      -- Drop a middle transaction directly from the union-find, exactly the
      -- state remove_transaction leaves behind: its children still point at a
      -- txid that is no longer a key, so the next uf_find INSERTS it back.
      local orphaned = hexes[6]
      mempool.uf_parent[orphaned] = nil
      mempool.uf_rank[orphaned] = nil
      mp.entries[orphaned] = nil

      -- Each of these iterates the union-find while uf_find may re-root.
      local root = mempool.uf_find(hexes[12])
      assert.has_no.errors(function() mempool.get_cluster_size(root) end)
      assert.has_no.errors(function() mempool.get_cluster_txids(root) end)
      assert.has_no.errors(function() mempool.get_cluster_vsize(root, mp.entries) end)
      assert.has_no.errors(function() mempool.get_cluster_stats(root, mp.entries) end)

      -- And the resurrected orphan must not be charged to the cluster: the
      -- count is scoped to transactions actually resident in `entries`.
      local count = select(1, mempool.get_cluster_stats(root, mp.entries))
      for _, hex in ipairs(hexes) do
        if mp.entries[hex] then
          assert.is_truthy(hex)
        end
      end
      assert.is_true(count <= 11,
        "removed tx must not be counted (got " .. count .. ")")
    end)

    it("accepting after a removal still bounds the cluster correctly", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 50000000)
      local mp = mempool.new(cs)

      local prev = coin
      local hexes, txids = {}, {}
      for i = 1, 10 do
        local tx = types.transaction(1,
          { make_input(prev, 0) },
          { make_output(50000000 - i * 100000) }, 0)
        local ok, hex = mp:accept_transaction(tx)
        assert.is_true(ok, "tx " .. i .. ": " .. tostring(hex))
        hexes[i] = hex
        prev = validation.compute_txid(tx)
        txids[i] = prev
      end
      assert.are_equal(10, mp.tx_count)

      -- Remove a mid-chain entry through the normal path.  This cascades to its
      -- descendants and leaves union-find nodes whose parent pointers name
      -- txids that are no longer keys — the orphan re-root state.
      mp:remove_transaction(hexes[5], "test")
      assert.are_equal(4, mp.tx_count, "removal must cascade to descendants")

      -- tx4's output is unspent again; keep extending from there.  Every accept
      -- runs the cluster walk over a union-find containing those orphan nodes.
      prev = txids[4]
      for i = 5, 40 do
        local tx = types.transaction(1,
          { make_input(prev, 0) },
          { make_output(50000000 - i * 100000) }, 0)
        local ok, err = mp:accept_transaction(tx)
        assert.is_true(ok, "post-removal tx " .. i .. " must be accepted: "
          .. tostring(err))
        prev = validation.compute_txid(tx)
      end

      -- 4 survivors + 36 new = 40 live transactions in one cluster.  A count
      -- that charged the cluster for the 6 removed transactions would have
      -- reported 46 and still fit, so also assert the accounting directly.
      assert.are_equal(40, mp.tx_count)
      local root = mempool.uf_find(prev and types.hash256_hex(prev))
      local count = select(1, mempool.get_cluster_stats(root, mp.entries))
      assert.are_equal(40, count, "removed transactions must not be counted")
    end)
  end)

  -----------------------------------------------------------------------------
  -- Removed gates: the legacy ancestor/descendant limits are NOT enforced
  -----------------------------------------------------------------------------
  describe("legacy ancestor/descendant gates are gone", function()
    it("accepts a 26-long chain (corpus: cluster-linear-26)", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 50000000)
      local mp = mempool.new(cs)

      local prev = coin
      for i = 1, 26 do
        local tx = types.transaction(1,
          { make_input(prev, 0) },
          { make_output(50000000 - i * 100000) }, 0)
        local ok, err = mp:accept_transaction(tx)
        assert.is_true(ok, "tx " .. i .. " must be accepted: " .. tostring(err))
        prev = validation.compute_txid(tx)
      end
      assert.are_equal(26, mp.tx_count)
    end)

    it("accepts a 1-parent/26-child fan-out (corpus: cluster-fan-26)", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 100000000)
      local mp = mempool.new(cs)

      local outs = {}
      for _ = 1, 30 do outs[#outs + 1] = make_output(1000000) end
      local parent = types.transaction(1, { make_input(coin, 0) }, outs, 0)
      local ok_p, perr = mp:accept_transaction(parent)
      assert.is_true(ok_p, "parent: " .. tostring(perr))
      local parent_txid = validation.compute_txid(parent)

      for i = 0, 25 do
        local child = types.transaction(1,
          { make_input(parent_txid, i) },
          { make_output(900000) }, 0)
        local ok, err = mp:accept_transaction(child)
        assert.is_true(ok, "child " .. i .. " must be accepted: " .. tostring(err))
      end
      assert.are_equal(27, mp.tx_count)
    end)
  end)
end)
