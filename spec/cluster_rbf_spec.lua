-- Core 31 cluster-mempool replacement rules (policy/rbf.cpp, validation.cpp
-- ReplacementChecks / PackageRBFChecks / AcceptPackage) in place of the
-- BIP125 eviction limits.
local types = require("lunarblock.types")
local mempool = require("lunarblock.mempool")
local validation = require("lunarblock.validation")

describe("cluster-mempool RBF", function()
  local P2PKH = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"
  -- Bare 1-of-1 multisig (secp256k1 generator): 20 legacy sigops, cost 80,
  -- so its sigop-adjusted weight (1600) dwarfs its raw weight.
  local G = "\x02\x79\xbe\x66\x7e\xf9\xdc\xbb\xac\x55\xa0\x62\x95\xce\x87\x0b\x07" ..
            "\x02\x9b\xfc\xdb\x2d\xce\x28\xd9\x59\xf2\x81\x5b\x16\xf8\x17\x98"
  local MULTISIG = "\x51\x21" .. G .. "\x51\xae"
  local next_coin = 0

  local function chain_state()
    return {
      coin_view = {
        utxos = {},
        get = function(self, txid, vout)
          return self.utxos[types.hash256_hex(txid) .. ":" .. vout]
        end,
      },
      tip_height = 700000,
    }
  end

  -- A fresh confirmed coin; returns its txid hash.
  local function coin(cs, value)
    next_coin = next_coin + 1
    local h = types.hash256(string.format("%064x", next_coin):gsub("..", function(b)
      return string.char(tonumber(b, 16))
    end))
    cs.coin_view.utxos[types.hash256_hex(h) .. ":0"] = {
      value = value, script_pubkey = P2PKH, height = 500000, is_coinbase = false,
    }
    return h
  end

  -- outputs: values, or {value, script} pairs.
  local function tx_of(inputs, outputs)
    local ins, outs = {}, {}
    for i, inp in ipairs(inputs) do
      ins[i] = types.txin(types.outpoint(inp[1], inp[2] or 0), "", 0xFFFFFFFD)
    end
    for i, v in ipairs(outputs) do
      if type(v) == "table" then
        outs[i] = types.txout(v[1], v[2])
      else
        outs[i] = types.txout(v, P2PKH)
      end
    end
    return types.transaction(1, ins, outs, 0)
  end

  local function txid_hex(tx) return types.hash256_hex(validation.compute_txid(tx)) end
  local function wtxid_hex(tx) return types.hash256_hex(validation.compute_wtxid(tx)) end

  local function rep(v, n)
    local t = {}
    for i = 1, n do t[i] = v end
    return t
  end

  describe("Rule 5", function()
    it("counts conflicting clusters, not evicted transactions", function()
      local cs = chain_state()
      local mp = mempool.new(cs)
      local roots = {}
      -- Two clusters of 1 root + 60 children: 122 evictions, 2 clusters.
      for c = 1, 2 do
        local base = coin(cs, 100000000)
        local root = tx_of({ { base } }, rep(1666000, 60))  -- fee 40000
        assert.is_true((mp:accept_transaction(root)))
        for k = 0, 59 do
          local child = tx_of({ { validation.compute_txid(root), k } }, { 1665000 })
          assert.is_true((mp:accept_transaction(child)))
        end
        roots[c] = base
      end
      assert.equal(122, mp.tx_count)
      local sweep = tx_of({ { roots[1] }, { roots[2] } }, { 200000000 - 400000 })
      local ok, err = mp:accept_transaction(sweep)
      assert.is_true(ok, tostring(err))
      assert.equal(1, mp.tx_count)
    end)

    it("refuses more than 100 conflicting clusters with Core's reject", function()
      local cs = chain_state()
      local mp = mempool.new(cs)
      local inputs = {}
      for i = 1, 101 do
        local base = coin(cs, 100000)
        assert.is_true((mp:accept_transaction(tx_of({ { base } }, { 99000 }))))
        inputs[i] = { base }
      end
      local sweep = tx_of(inputs, { 101 * 100000 - 1000000 })
      local ok, reason, details = mp:accept_transaction(sweep)
      assert.is_false(ok)
      assert.equal("too many potential replacements", reason)
      assert.equal("rejecting replacement " .. txid_hex(sweep) ..
        "; too many conflicting clusters (101 > 100)", details)
    end)
  end)

  describe("feerate diagram", function()
    -- rbf/diagram: PaysForRBF passes (5200 >= 5000 + relay), the feerate
    -- drops, so the staged diagram is worse in its first chunk.
    local function diagram_case()
      local cs = chain_state()
      local mp = mempool.new(cs)
      local base = coin(cs, 5000000000)
      local orig = tx_of({ { base } }, { 5000000000 - 5000 })
      assert.is_true((mp:accept_transaction(orig)))
      local each = math.floor((5000000000 - 5200) / 40)
      local outs = rep(each, 40)
      outs[1] = each + (5000000000 - 5200 - each * 40)
      return mp, orig, tx_of({ { base } }, outs)
    end

    it("refuses a replacement that worsens the diagram with replacement-failed", function()
      local mp, orig, wide = diagram_case()
      local ok, reason, details = mp:accept_transaction(wide)
      assert.is_false(ok)
      assert.equal("replacement-failed", reason)
      assert.equal("insufficient feerate: does not improve feerate diagram", details)
      assert.is_not_nil(mp:get_entry(txid_hex(orig)))
    end)

    it("reports reject-reason and reject-details separately for testmempoolaccept", function()
      local mp, _, wide = diagram_case()
      local res = mp:accept_to_memory_pool(wide, true)
      assert.is_false(res.accepted)
      assert.equal("replacement-failed", res.reject_reason)
      assert.equal("replacement-failed, insufficient feerate: does not improve feerate diagram",
        res.reject_details)
    end)

    it("compare_chunks orders diagrams like Core's CompareChunks", function()
      local cc = mempool.compare_chunks
      assert.equal(0, cc({ { fee = 10, size = 10 } }, { { fee = 10, size = 10 } }))
      assert.equal(1, cc({ { fee = 20, size = 10 } }, { { fee = 10, size = 10 } }))
      assert.equal(-1, cc({ { fee = 10, size = 10 } }, { { fee = 10, size = 5 } }))
      -- Higher first chunk, lower total: incomparable.
      assert.is_nil(cc({ { fee = 10, size = 5 } },
        { { fee = 8, size = 5 }, { fee = 8, size = 5 } }))
    end)
  end)

  describe("eviction happens only after every check", function()
    it("test_accept of a valid replacement leaves its conflict in the pool", function()
      local cs = chain_state()
      local mp = mempool.new(cs)
      local base = coin(cs, 100000)
      local orig = tx_of({ { base } }, { 90000 })
      assert.is_true((mp:accept_transaction(orig)))
      local res = mp:accept_to_memory_pool(tx_of({ { base } }, { 80000 }), true)
      assert.is_true(res.accepted)
      assert.is_true(res.vsize > 0)
      assert.is_not_nil(mp:get_entry(txid_hex(orig)))
      assert.equal(1, mp.tx_count)
    end)

    it("a replacement refused after the RBF checks keeps its conflict", function()
      local cs = chain_state()
      local mp = mempool.new(cs)
      local base = coin(cs, 100000)
      local orig = tx_of({ { base } }, { 90000 })
      assert.is_true((mp:accept_transaction(orig)))
      -- Passes every replacement rule, then trips the client max-feerate gate.
      mp.client_max_feerate_kvb = 1000
      local ok = mp:accept_transaction(tx_of({ { base } }, { 80000 }))
      assert.is_false(ok)
      assert.is_not_nil(mp:get_entry(txid_hex(orig)))
    end)

    it("rejects with Core's reason Rule 3 (less fees than conflicting txs)", function()
      local cs = chain_state()
      local mp = mempool.new(cs)
      local base = coin(cs, 100000)
      assert.is_true((mp:accept_transaction(tx_of({ { base } }, { 79000 }))))
      local low = tx_of({ { base } }, { 94000 })
      local ok, reason, details = mp:accept_transaction(low)
      assert.is_false(ok)
      assert.equal("insufficient fee", reason)
      assert.equal("rejecting replacement " .. txid_hex(low) ..
        ", less fees than conflicting txs; 0.00006 < 0.00021", details)
    end)
  end)

  describe("package RBF (submitpackage)", function()
    -- package_rbf: O (wide, cheap) + its child D in the pool; P double-spends
    -- O's input and pays less than O+D, its child C pays for both.
    local function package_case(p_outputs, c_outputs, script)
      local cs = chain_state()
      local mp = mempool.new(cs)
      local value = 5000000000
      local base = coin(cs, value)
      local o_change = value - 20000 - 600 * 1000
      local o_outs = rep(1000, 600)
      table.insert(o_outs, 1, o_change)
      local o = tx_of({ { base } }, o_outs)
      assert.is_true((mp:accept_transaction(o)))
      local d = tx_of({ { validation.compute_txid(o), 0 } }, { o_change - 1000 })
      assert.is_true((mp:accept_transaction(d)))
      local p_change = value - 6000 - p_outputs * 1000
      local p_outs = rep(script and { 1000, script } or 1000, p_outputs)
      table.insert(p_outs, 1, p_change)
      local p = tx_of({ { base } }, p_outs)
      local c_outs = rep(script and { 1000, script } or 1000, c_outputs)
      table.insert(c_outs, 1, p_change - 200000 - c_outputs * 1000)
      local c = tx_of({ { validation.compute_txid(p), 0 } }, c_outs)
      return mp, o, d, p, c
    end

    it("replaces the conflict and its descendant with a 1-parent-1-child package", function()
      local mp, o, d, p, c = package_case(100, 100)
      local state, results, replaced = mp:process_new_package({ p, c }, false)
      assert.is_nil(state, state and mempool.validation_state_string(state.reason, state.details))
      assert.is_nil(mp:get_entry(txid_hex(o)))
      assert.is_nil(mp:get_entry(txid_hex(d)))
      assert.is_not_nil(mp:get_entry(txid_hex(p)))
      assert.is_not_nil(mp:get_entry(txid_hex(c)))
      assert.equal(2, #replaced)
      local rp, rc = results[wtxid_hex(p)], results[wtxid_hex(c)]
      assert.equal("valid", rp.kind)
      assert.same({ wtxid_hex(p), wtxid_hex(c) }, rp.effective_includes)
      assert.equal(rp.effective_feerate, rc.effective_feerate)
      assert.equal(math.floor(206000 * 1000 / (rp.vsize + rc.vsize)), rp.effective_feerate)
    end)

    it("refuses a package whose cluster is too large and keeps the conflicts", function()
      -- package_rbf/over: 127 + 126 bare multisig outputs, 404800
      -- sigop-adjusted weight (raw ~47000) against the 404000 limit.
      local saved = mempool.PERMIT_BARE_MULTISIG
      mempool.PERMIT_BARE_MULTISIG = true
      local mp, o, d, p, c = package_case(127, 126, MULTISIG)
      local state, results, replaced = mp:process_new_package({ p, c }, false)
      mempool.PERMIT_BARE_MULTISIG = saved
      assert.is_not_nil(state)
      assert.equal("too-large-cluster", mempool.validation_state_string(state.reason, state.details))
      assert.is_not_nil(mp:get_entry(txid_hex(o)))
      assert.is_not_nil(mp:get_entry(txid_hex(d)))
      assert.is_nil(mp:get_entry(txid_hex(p)))
      assert.equal(0, #replaced)
      -- Each transaction carries its individual (first-pass) result.
      local rp = results[wtxid_hex(p)]
      assert.equal("insufficient fee", rp.reason)
      assert.truthy(rp.details:match(
        "^rejecting replacement %x+, less fees than conflicting txs; 0%.00006 < 0%.00021$"))
      assert.equal(mempool.REJECT_MISSING_INPUTS, results[wtxid_hex(c)].reason)
    end)

    it("refuses a package that cannot pay for what it replaces", function()
      local mp, o, _, p = package_case(100, 100)
      -- A child paying nothing: 6000 in package fees against 21000 replaced.
      local c0 = tx_of({ { validation.compute_txid(p), 0 } }, { p.outputs[1].value })
      local state = mp:process_new_package({ p, c0 }, false)
      assert.is_not_nil(state)
      assert.equal("package RBF failed: insufficient anti-DoS fees, rejecting replacement " ..
        txid_hex(c0) .. ", less fees than conflicting txs; 0.00006 < 0.00021",
        mempool.validation_state_string(state.reason, state.details))
      assert.is_not_nil(mp:get_entry(txid_hex(o)))
    end)
  end)

  it("format_money matches Core FormatMoney", function()
    assert.equal("0.00006", mempool.format_money(6000))
    assert.equal("1.00", mempool.format_money(100000000))
    assert.equal("0.00", mempool.format_money(0))
    assert.equal("0.00000001", mempool.format_money(1))
  end)
end)
