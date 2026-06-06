-- spec/w106_mempool_spec.lua
--
-- W106 — DISCOVERY AUDIT: CTxMemPool descendant/ancestor tracking,
-- RBF, TRUC, and package mempool for lunarblock vs Bitcoin Core.
--
-- Reference: bitcoin-core/src/txmempool.h/cpp, policy/rbf.h/cpp,
--            policy/truc_policy.h/cpp, policy/packages.h/cpp.
--
-- 30 gates:
--   G1  - G10  ancestor/descendant tracking
--   G11 - G20  RBF (BIP-125)
--   G21 - G25  TRUC (BIP-431, v3 policy)
--   G26 - G30  package / misc

local types      = require("lunarblock.types")
local mempool    = require("lunarblock.mempool")
local validation = require("lunarblock.validation")

describe("W106 CTxMemPool descendant/ancestor + RBF + TRUC + package audit", function()

  ---------------------------------------------------------------------------
  -- Shared test helpers
  ---------------------------------------------------------------------------

  -- Standard P2PKH script (accepted by IsStandardTx)
  local P2PKH = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"

  -- Returns a hash256 object with random bytes
  local function random_txid()
    local b = ""
    for _ = 1, 32 do b = b .. string.char(math.random(0, 255)) end
    return types.hash256(b)
  end

  -- txid_hash is a hash256 object
  local function make_input(txid_hash, vout, seq)
    return types.txin(types.outpoint(txid_hash, vout), "", seq or 0xFFFFFFFE)
  end

  local function make_output(value, spk)
    return types.txout(value, spk or P2PKH)
  end

  -- Build a chain_state with UTXO coin_view
  local function make_chain(utxos, height)
    utxos = utxos or {}
    local cv = {
      utxos = utxos,
      get = function(self, txid_hash, vout)
        local key = types.hash256_hex(txid_hash) .. ":" .. vout
        return self.utxos[key]
      end
    }
    return { coin_view = cv, tip_height = height or 700000 }
  end

  -- Register a coin in the chain state (txid_hash is a hash256 object)
  local function add_utxo(cs, txid_hash, vout, value, spk, height)
    local key = types.hash256_hex(txid_hash) .. ":" .. vout
    cs.coin_view.utxos[key] = {
      value         = value or 100000,
      script_pubkey = spk or P2PKH,
      height        = height or 699990,
      is_coinbase   = false,
    }
  end

  -- Accept a tx into a mempool; returns ok, txid_hex_or_err, fee
  local function accept(mp, tx, allow_rbf)
    return mp:accept_transaction(tx, allow_rbf)
  end

  ---------------------------------------------------------------------------
  -- G1: ancestor_count updated correctly on add
  ---------------------------------------------------------------------------
  describe("G1: ancestor_count correct on add", function()
    it("child entry has ancestor_count = 1 (one parent)", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 200000)

      local mp = mempool.new(cs)
      local parent = types.transaction(1,
        { make_input(coin, 0) },
        { make_output(100000) }, 0)
      local ok1, par_hex = accept(mp, parent)
      assert.is_true(ok1, "parent accept: " .. tostring(par_hex))

      local par_txid = validation.compute_txid(parent)
      local child = types.transaction(1,
        { make_input(par_txid, 0) },
        { make_output(50000) }, 0)
      local ok2, child_hex = accept(mp, child)
      assert.is_true(ok2, "child accept: " .. tostring(child_hex))

      local child_entry = mp.entries[child_hex]
      assert.is_not_nil(child_entry)
      -- ancestor_count excludes self per Core convention: 1 in-mempool ancestor
      assert.are_equal(1, child_entry.ancestor_count)
    end)
  end)

  ---------------------------------------------------------------------------
  -- G2: ancestor set contains all transitive ancestors
  ---------------------------------------------------------------------------
  describe("G2: ancestor set contains transitive ancestors", function()
    it("grandchild.ancestors includes both parent and grandparent txids", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 300000)

      local mp = mempool.new(cs)

      local gp = types.transaction(1, { make_input(coin, 0) },
        { make_output(200000) }, 0)
      local ok1, gp_hex = accept(mp, gp)
      assert.is_true(ok1)

      local gp_txid = validation.compute_txid(gp)
      local par = types.transaction(1, { make_input(gp_txid, 0) },
        { make_output(100000) }, 0)
      local ok2, par_hex = accept(mp, par)
      assert.is_true(ok2)

      local par_txid = validation.compute_txid(par)
      local gc = types.transaction(1, { make_input(par_txid, 0) },
        { make_output(50000) }, 0)
      local ok3, gc_hex = accept(mp, gc)
      assert.is_true(ok3)

      local gc_entry = mp.entries[gc_hex]
      assert.is_not_nil(gc_entry)
      assert.is_not_nil(gc_entry.ancestors[gp_hex], "grandparent must be in gc.ancestors")
      assert.is_not_nil(gc_entry.ancestors[par_hex], "parent must be in gc.ancestors")
      assert.are_equal(2, gc_entry.ancestor_count)
    end)
  end)

  ---------------------------------------------------------------------------
  -- G3: descendant_count updated when child is added
  ---------------------------------------------------------------------------
  describe("G3: descendant_count updated on child add", function()
    it("parent.descendant_count increments after child is accepted", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 200000)

      local mp = mempool.new(cs)
      local par = types.transaction(1, { make_input(coin, 0) },
        { make_output(100000) }, 0)
      local ok1, par_hex = accept(mp, par)
      assert.is_true(ok1)
      local par_entry = mp.entries[par_hex]
      assert.are_equal(0, par_entry.descendant_count, "no descendants yet")

      local par_txid = validation.compute_txid(par)
      local child = types.transaction(1, { make_input(par_txid, 0) },
        { make_output(50000) }, 0)
      local ok2 = accept(mp, child)
      assert.is_true(ok2)
      assert.are_equal(1, par_entry.descendant_count)
    end)
  end)

  ---------------------------------------------------------------------------
  -- G4: descendant set populated on child add
  ---------------------------------------------------------------------------
  describe("G4: descendant set populated on child add", function()
    it("parent.descendants contains child txid after acceptance", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 200000)

      local mp = mempool.new(cs)
      local par = types.transaction(1, { make_input(coin, 0) },
        { make_output(100000) }, 0)
      local _, par_hex = accept(mp, par)

      local par_txid = validation.compute_txid(par)
      local child = types.transaction(1, { make_input(par_txid, 0) },
        { make_output(50000) }, 0)
      local ok2, child_hex = accept(mp, child)
      assert.is_true(ok2)

      local par_entry = mp.entries[par_hex]
      assert.is_not_nil(par_entry.descendants[child_hex])
    end)
  end)

  ---------------------------------------------------------------------------
  -- G5: ancestor_size tracks aggregate ancestor vsize
  ---------------------------------------------------------------------------
  describe("G5: ancestor_size tracks in-mempool ancestor vsize", function()
    it("child.ancestor_size equals parent.vsize", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 200000)

      local mp = mempool.new(cs)
      local par = types.transaction(1, { make_input(coin, 0) },
        { make_output(100000) }, 0)
      local ok1, par_hex = accept(mp, par)
      assert.is_true(ok1)
      local par_entry = mp.entries[par_hex]

      local par_txid = validation.compute_txid(par)
      local child = types.transaction(1, { make_input(par_txid, 0) },
        { make_output(50000) }, 0)
      local ok2, child_hex = accept(mp, child)
      assert.is_true(ok2)

      local child_entry = mp.entries[child_hex]
      -- ancestor_size excludes self; should equal parent.vsize
      assert.are_equal(par_entry.vsize, child_entry.ancestor_size)
    end)
  end)

  ---------------------------------------------------------------------------
  -- G6: ancestor limit MAX_ANCESTORS = 25 enforced
  ---------------------------------------------------------------------------
  describe("G6: ancestor limit MAX_ANCESTORS = 25 enforced", function()
    it("rejects a tx that would exceed 25 in-mempool ancestors", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 10000000)

      local mp = mempool.new(cs)

      local prev_txid = coin
      local prev_vout = 0

      for i = 1, 25 do
        local tx = types.transaction(1,
          { make_input(prev_txid, prev_vout) },
          { make_output(10000000 - i * 300000) }, 0)
        local ok, txhex = accept(mp, tx)
        assert.is_true(ok, "tx " .. i .. " should be accepted: " .. tostring(txhex))
        prev_txid = validation.compute_txid(tx)
        prev_vout = 0
      end

      -- 26th tx would have 25 in-mempool ancestors: exceeds MAX_ANCESTORS
      local tx26 = types.transaction(1,
        { make_input(prev_txid, 0) },
        { make_output(100000) }, 0)
      local ok26, err26 = accept(mp, tx26)
      assert.is_false(ok26, "26th tx must be rejected (too many ancestors)")
      assert.is_string(err26)
      assert.is_truthy(err26:find("ancestor"))
    end)
  end)

  ---------------------------------------------------------------------------
  -- G7: ancestor_size limit constant correct
  ---------------------------------------------------------------------------
  describe("G7: MAX_ANCESTOR_SIZE constant = 101000 vbytes", function()
    it("MAX_ANCESTOR_SIZE is 101000 vbytes (101 kvB)", function()
      assert.are_equal(101000, mempool.MAX_ANCESTOR_SIZE)
    end)
  end)

  ---------------------------------------------------------------------------
  -- G8: descendant count checked for ALL ancestors (not just direct parent)
  ---------------------------------------------------------------------------
  describe("G8: descendant_count updated for all in-mempool ancestors", function()
    it("grandparent.descendant_count = 2 after grandchild is accepted", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 300000)

      local mp = mempool.new(cs)
      local gp = types.transaction(1, { make_input(coin, 0) },
        { make_output(200000) }, 0)
      local _, gp_hex = accept(mp, gp)

      local gp_txid = validation.compute_txid(gp)
      local par = types.transaction(1, { make_input(gp_txid, 0) },
        { make_output(100000) }, 0)
      accept(mp, par)

      local par_txid = validation.compute_txid(par)
      local gc = types.transaction(1, { make_input(par_txid, 0) },
        { make_output(50000) }, 0)
      local ok3 = accept(mp, gc)
      assert.is_true(ok3)

      local gp_entry = mp.entries[gp_hex]
      -- grandparent must have 2 descendants (par + gc)
      assert.are_equal(2, gp_entry.descendant_count,
        "BUG if 1: grandparent must track 2 descendants after grandchild added")
    end)
  end)

  ---------------------------------------------------------------------------
  -- G9: descendant_count decremented on remove
  ---------------------------------------------------------------------------
  describe("G9: descendant_count decremented on remove", function()
    it("parent.descendant_count returns to 0 after child removed", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 200000)

      local mp = mempool.new(cs)
      local par = types.transaction(1, { make_input(coin, 0) },
        { make_output(100000) }, 0)
      local _, par_hex = accept(mp, par)
      local par_entry = mp.entries[par_hex]

      local par_txid = validation.compute_txid(par)
      local child = types.transaction(1, { make_input(par_txid, 0) },
        { make_output(50000) }, 0)
      local _, child_hex = accept(mp, child)
      assert.are_equal(1, par_entry.descendant_count)

      mp:remove_transaction(child_hex, "test")
      assert.are_equal(0, par_entry.descendant_count,
        "descendant_count must decrement to 0 after child removed")
    end)
  end)

  ---------------------------------------------------------------------------
  -- G10 BUG: union-find cluster state is MODULE-LEVEL (shared across instances)
  --
  -- Core's TxGraph is allocated per CTxMemPool instance.
  -- lunarblock declares uf_parent/uf_rank as module-level `local` tables,
  -- so every Mempool instance shares the same union-find state.
  -- This causes cross-instance cluster accounting corruption.
  ---------------------------------------------------------------------------
  describe("G10 BUG: cluster union-find state is module-global (should be per-instance)", function()
    it("DOCUMENTS: txid registered in mp1 appears in module-level uf_parent export", function()
      local cs1 = make_chain()
      local coin1 = random_txid()
      add_utxo(cs1, coin1, 0, 200000)

      local mp1 = mempool.new(cs1)
      local tx1 = types.transaction(1,
        { make_input(coin1, 0) },
        { make_output(100000) }, 0)
      local _, txhex1 = accept(mp1, tx1)
      assert.is_not_nil(txhex1)

      -- The module exports uf_parent; it must contain the txid (proves global scope)
      assert.is_not_nil(mempool.uf_parent[txhex1],
        "BUG-G10: uf_parent is module-global — txid from mp1 visible in module export " ..
        "(should be per-instance like Core TxGraph)")
    end)
  end)

  ---------------------------------------------------------------------------
  -- G11: RBF Rule #1 — conflicting tx must signal RBF
  ---------------------------------------------------------------------------
  describe("G11: RBF Rule #1 - conflicting tx must signal RBF", function()
    it("rejects replacement if conflicting tx has sequence=0xFFFFFFFF (FINAL)", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 200000)

      local mp = mempool.new(cs)
      -- Non-RBF tx: nSequence = 0xFFFFFFFF = SEQUENCE_FINAL
      local orig = types.transaction(1,
        { make_input(coin, 0, 0xFFFFFFFF) },
        { make_output(100000) }, 0)
      local ok1 = accept(mp, orig)
      assert.is_true(ok1)

      -- Attempt replacement (double-spend same coin with higher fee)
      local coin2 = random_txid()
      add_utxo(cs, coin2, 0, 500000)
      local repl = types.transaction(1,
        { make_input(coin, 0, 0xFFFFFFFD),
          make_input(coin2, 0) },
        { make_output(200000) }, 0)
      local ok2, err2 = accept(mp, repl)
      assert.is_false(ok2, "replacement should fail: original does not signal RBF")
      assert.is_string(err2)
    end)
  end)

  ---------------------------------------------------------------------------
  -- G12: RBF Rule #2 — no new unconfirmed inputs
  ---------------------------------------------------------------------------
  describe("G12: RBF Rule #2 - replacement may not add new unconfirmed inputs", function()
    it("rejects replacement adding a new in-mempool input not in original", function()
      local cs = make_chain()
      local coin_a = random_txid()
      add_utxo(cs, coin_a, 0, 300000)
      local coin_b = random_txid()
      add_utxo(cs, coin_b, 0, 300000)

      local mp = mempool.new(cs)

      -- Accept a parent tx (creates unconfirmed output)
      local parent_tx = types.transaction(1,
        { make_input(coin_b, 0) },
        { make_output(200000) }, 0)
      local ok_p = accept(mp, parent_tx)
      assert.is_true(ok_p)
      local parent_txid = validation.compute_txid(parent_tx)

      -- Original RBF-signaling tx (only spends confirmed coin_a)
      local orig = types.transaction(1,
        { make_input(coin_a, 0, 0xFFFFFFFD) },
        { make_output(200000) }, 0)
      local ok1 = accept(mp, orig)
      assert.is_true(ok1)

      -- Replacement adds parent_tx:0 (a NEW unconfirmed input — Rule #2 violation)
      local repl = types.transaction(2,
        { make_input(coin_a, 0, 0xFFFFFFFD),
          make_input(parent_txid, 0) },
        { make_output(300000) }, 0)
      local ok2, err2 = accept(mp, repl)
      assert.is_false(ok2,
        "replacement adding new unconfirmed input must be rejected (BIP-125 Rule #2)")
      assert.is_string(err2)
    end)
  end)

  ---------------------------------------------------------------------------
  -- G13: RBF Rule #3 — replacement fee >= sum of conflicting fees
  ---------------------------------------------------------------------------
  describe("G13: RBF Rule #3 - replacement fee >= original fees", function()
    it("rejects replacement whose fee < conflicting tx fee", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 200000)

      local mp = mempool.new(cs)
      -- orig fee = 200000 - 100000 = 100000
      local orig = types.transaction(1,
        { make_input(coin, 0, 0xFFFFFFFD) },
        { make_output(100000) }, 0)
      local ok1 = accept(mp, orig)
      assert.is_true(ok1)

      local coin2 = random_txid()
      add_utxo(cs, coin2, 0, 200000)
      -- replacement fee = (200000+200000) - 350000 = 50000 < 100000 (original)
      local repl = types.transaction(2,
        { make_input(coin, 0, 0xFFFFFFFD),
          make_input(coin2, 0) },
        { make_output(350000) }, 0)
      local ok2, err2 = accept(mp, repl)
      assert.is_false(ok2, "replacement with fee < original must be rejected (Rule #3)")
    end)
  end)

  ---------------------------------------------------------------------------
  -- G14: RBF Rule #4 — INCREMENTAL_RELAY_FEE = 100 sat/kvB
  ---------------------------------------------------------------------------
  describe("G14: RBF Rule #4 - INCREMENTAL_RELAY_FEE = 100 sat/kvB", function()
    it("INCREMENTAL_RELAY_FEE is 100 sat/kvB (not 1000)", function()
      -- This was previously wrong (1000 sat/kvB = 10× too high).
      assert.are_equal(100, mempool.INCREMENTAL_RELAY_FEE,
        "INCREMENTAL_RELAY_FEE must be 100 sat/kvB (Core policy/policy.h:48)")
    end)

    it("rejects replacement whose additional fee is insufficient for bandwidth", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 100000)

      local mp = mempool.new(cs)
      -- orig fee = 1000
      local orig = types.transaction(1,
        { make_input(coin, 0, 0xFFFFFFFD) },
        { make_output(99000) }, 0)
      local ok1 = accept(mp, orig)
      assert.is_true(ok1)

      local coin2 = random_txid()
      add_utxo(cs, coin2, 0, 100000)
      -- repl fee = 100000+100000-198999 = 1001; additional = 1001-1000 = 1 sat
      -- For typical tx ~150 vbytes: required = ceil(100 * 150 / 1000) = 15 sat; 1 < 15
      local repl = types.transaction(2,
        { make_input(coin, 0, 0xFFFFFFFD),
          make_input(coin2, 0) },
        { make_output(198999) }, 0)
      local ok2, err2 = accept(mp, repl)
      assert.is_false(ok2,
        "replacement with 1 sat additional fee should fail Rule #4 bandwidth check " ..
        "(required ~15 sat for ~150-vbyte tx at 100 sat/kvB)")
    end)
  end)

  ---------------------------------------------------------------------------
  -- G15: RBF Rule #5 — MAX_REPLACEMENT_CANDIDATES = 100
  ---------------------------------------------------------------------------
  describe("G15: RBF Rule #5 - MAX_REPLACEMENT_CANDIDATES = 100", function()
    it("MAX_REPLACEMENT_CANDIDATES constant is 100", function()
      assert.are_equal(100, mempool.MAX_REPLACEMENT_CANDIDATES)
    end)
  end)

  ---------------------------------------------------------------------------
  -- G16: EntriesAndTxidsDisjoint — replacement cannot be a descendant of conflict
  ---------------------------------------------------------------------------
  describe("G16: EntriesAndTxidsDisjoint - replacement cannot descend from conflict", function()
    it("rejects replacement that is a descendant of the tx it conflicts with", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 500000)

      local mp = mempool.new(cs)

      -- A: spends coin (RBF-signaling)
      local tx_a = types.transaction(1,
        { make_input(coin, 0, 0xFFFFFFFD) },
        { make_output(300000) }, 0)
      local ok_a, a_hex = accept(mp, tx_a)
      assert.is_true(ok_a)
      local a_txid = validation.compute_txid(tx_a)

      -- B: child of A
      local tx_b = types.transaction(1,
        { make_input(a_txid, 0, 0xFFFFFFFD) },
        { make_output(200000) }, 0)
      accept(mp, tx_b)

      -- C: conflicts with A on `coin` (double-spend) AND is a descendant of A
      -- (spends A's output A:0, making C a descendant of A)
      -- → C's ancestor set contains A, but A is also a direct conflict
      -- → EntriesAndTxidsDisjoint must reject this
      local tx_c = types.transaction(2,
        { make_input(coin, 0, 0xFFFFFFFD),   -- conflicts with A on coin
          make_input(a_txid, 0) },            -- C descends from A
        { make_output(400000) }, 0)
      local ok_c, err_c = accept(mp, tx_c)
      assert.is_false(ok_c,
        "replacement that descends from its own conflict must be rejected (cyclic)")
    end)
  end)

  ---------------------------------------------------------------------------
  -- G17: is_replaceable checks ancestor RBF signaling
  ---------------------------------------------------------------------------
  describe("G17: is_replaceable checks ancestor signaling (BIP-125 Rule #1)", function()
    it("tx with FINAL sequence is replaceable when ancestor signals RBF", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 300000)

      local mp = mempool.new(cs)

      -- Parent: signals RBF
      local par = types.transaction(1,
        { make_input(coin, 0, 0xFFFFFFFD) },
        { make_output(200000) }, 0)
      local ok1, par_hex = accept(mp, par)
      assert.is_true(ok1)

      -- Child: FINAL nSequence (no direct signal)
      local par_txid = validation.compute_txid(par)
      local child = types.transaction(1,
        { make_input(par_txid, 0, 0xFFFFFFFF) },
        { make_output(100000) }, 0)
      local ok2, child_hex = accept(mp, child)
      assert.is_true(ok2)

      -- Child is replaceable because ancestor signals RBF (Core rbf.cpp:44-46)
      assert.is_true(mp:is_replaceable(child_hex),
        "child with FINAL sequence must be replaceable when ancestor signals RBF")
    end)
  end)

  ---------------------------------------------------------------------------
  -- G18 BUG: No PrioritiseTransaction / mapDeltas — modified fee unavailable
  --
  -- Core uses GetModifiedFee() (fee + mapDeltas delta) for RBF Rules 3 and 4.
  -- lunarblock has no mapDeltas or prioritise_transaction, so modified fees
  -- are impossible to apply; RBF comparisons use raw base fees only.
  ---------------------------------------------------------------------------
  describe("G18 BUG: no PrioritiseTransaction/mapDeltas — modified fee unavailable", function()
    it("DOCUMENTS: Mempool has no prioritise_transaction method", function()
      local cs = make_chain()
      local mp = mempool.new(cs)
      -- Core: CTxMemPool::PrioritiseTransaction updates mapDeltas and
      -- calls m_txgraph->SetTransactionFee.  lunarblock has no equivalent.
      assert.is_nil(mp.prioritise_transaction,
        "BUG-G18: no prioritise_transaction method — Core mapDeltas gap")
    end)
  end)

  ---------------------------------------------------------------------------
  -- G19 FIXED: ImprovesFeerateDiagram wired into RBF accept path
  --
  -- After Rules 3/4, accept_transaction now builds old/new feerate diagrams
  -- for the affected clusters and calls compare_diagrams(old, new).
  -- A replacement that passes Rules 3/4 but does not improve the diagram
  -- must be rejected with "does not improve feerate diagram".
  -- Reference: Core rbf.cpp:127-140 ImprovesFeerateDiagram.
  ---------------------------------------------------------------------------
  describe("G19 FIXED: ImprovesFeerateDiagram wired into RBF accept path", function()
    it("compare_diagrams and build_feerate_diagram are exported", function()
      assert.is_function(mempool.compare_diagrams,
        "compare_diagrams must be exported from module")
      assert.is_function(mempool.build_feerate_diagram,
        "build_feerate_diagram must be exported from module")
    end)

    it("accepts RBF replacement that strictly improves the feerate diagram", function()
      -- A replacement whose feerate is clearly higher than the original must be
      -- accepted: the diagram gate is live and compare_diagrams returns true.
      -- Original: 1 input 500 000 sat → output 490 000 sat; fee = 10 000
      -- Replacement: double-spends same coin + 1 extra coin; total in = 1 000 000 sat
      --   output = 975 000 sat; fee = 25 000
      --   additional = 25 000 - 10 000 = 15 000
      --   required   = ceil(100 * vsize_repl / 1000) ≈ ceil(100 * ~200 / 1000) = 20
      --   Rule #4 passes.  Replacement feerate ≈ 25000/200 = 125 sat/vB vs
      --   original feerate ≈ 10000/100 = 100 sat/vB → diagram strictly improves.
      local cs = make_chain()
      local coin_a = random_txid()
      add_utxo(cs, coin_a, 0, 500000)
      local mp = mempool.new(cs)

      local orig = types.transaction(1,
        { make_input(coin_a, 0, 0xFFFFFFFD) },
        { make_output(490000) }, 0)   -- fee = 10 000
      local ok1, orig_hex = accept(mp, orig)
      assert.is_true(ok1, "original must be accepted: " .. tostring(orig_hex))

      local coin_b = random_txid()
      add_utxo(cs, coin_b, 0, 500000)
      local repl = types.transaction(2,
        { make_input(coin_a, 0, 0xFFFFFFFD),
          make_input(coin_b, 0) },
        { make_output(975000) }, 0)   -- fee = 25 000 > 10 000; diagram improves
      local ok2, err2 = accept(mp, repl)
      assert.is_true(ok2,
        "FIXED G19: high-feerate replacement must be accepted — " ..
        "ImprovesFeerateDiagram gate is live and correctly passes a better diagram " ..
        "(was silently absent before this fix); err=" .. tostring(err2))
    end)

    it("rejects RBF replacement that passes Rules 3+4 but degrades feerate diagram", function()
      -- Setup a replacement that clearly degrades the feerate diagram:
      --   original: very high feerate (fee/vsize large)
      --   replacement: just barely passes Rules 3+4 (additional fee > required),
      --     but feerate is much lower (large vsize, small fee increment).
      --
      -- Original: coin_a(1 000 000) → output(500 000); fee = 500 000; vsize ≈ 100 vB
      --   feerate ≈ 5000 sat/vB
      --
      -- Build a bloated replacement with 30 confirmed inputs each of tiny value:
      --   30 × coin_tiny = 30 × 20 001 sat = 600 030 sat total tiny
      --   coin_a input = 1 000 000 sat
      --   total_in = 1 600 030 sat
      --   fee_required_r3 = 500 001 (just above original fee)
      --   additional_required_r4 = ceil(100 * vsize_repl / 1000)
      --     vsize_repl ≈ 100 + 30 * 41 = 1330 vB → required ≈ 133 sat
      --   target fee = 500 001 + 133 + 1 = 500 135
      --   output = 1 600 030 - 500 135 = 1 099 895 sat
      --   replacement feerate ≈ 500 135 / 1330 ≈ 376 sat/vB << 5000 sat/vB of original
      --   → compare_diagrams(old, new) must return false → reject with diagram error.
      local cs = make_chain()
      local coin_a = random_txid()
      add_utxo(cs, coin_a, 0, 1000000)

      local tiny_coins = {}
      local total_tiny = 0
      for _ = 1, 30 do
        local c = random_txid()
        add_utxo(cs, c, 0, 20001)
        tiny_coins[#tiny_coins + 1] = c
        total_tiny = total_tiny + 20001
      end

      local mp = mempool.new(cs)

      -- Accept original (ultra-high feerate)
      local orig = types.transaction(1,
        { make_input(coin_a, 0, 0xFFFFFFFD) },
        { make_output(500000) }, 0)   -- fee = 500 000
      local ok1, orig_hex = accept(mp, orig)
      assert.is_true(ok1, "original must be accepted: " .. tostring(orig_hex))

      -- Build replacement inputs: coin_a (double-spend) + all 30 tiny coins
      local repl_inputs = { make_input(coin_a, 0, 0xFFFFFFFD) }
      for _, c in ipairs(tiny_coins) do
        repl_inputs[#repl_inputs + 1] = make_input(c, 0)
      end

      -- total_in = 1 000 000 + total_tiny; output chosen so fee passes R3+R4
      -- but feerate is much lower than original
      local total_in = 1000000 + total_tiny
      local repl_fee = 500500   -- passes Rule #3 (500500 > 500000); large but tiny feerate
      local repl_output = total_in - repl_fee

      local repl = types.transaction(2, repl_inputs, { make_output(repl_output) }, 0)
      local ok2, err2 = accept(mp, repl)

      -- The diagram check must fire and reject the replacement.
      assert.is_false(ok2,
        "FIXED G19: low-feerate replacement must be rejected by ImprovesFeerateDiagram " ..
        "(was silently accepted before this fix; Core rbf.cpp:127-140)")
      assert.is_string(err2)
      assert.is_truthy(err2:find("feerate diagram"),
        "rejection reason must mention 'feerate diagram', got: " .. tostring(err2))
    end)
  end)

  ---------------------------------------------------------------------------
  -- G20: RBF eviction collects all descendants of conflicting txs
  ---------------------------------------------------------------------------
  describe("G20: RBF evicts conflicting tx and all its descendants", function()
    it("replacing A evicts both A and its child B", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 500000)

      local mp = mempool.new(cs)
      -- A (RBF-signaling, fee = 200000)
      local tx_a = types.transaction(1,
        { make_input(coin, 0, 0xFFFFFFFD) },
        { make_output(300000) }, 0)
      local _, a_hex = accept(mp, tx_a)
      local a_txid = validation.compute_txid(tx_a)

      -- B: child of A
      local tx_b = types.transaction(1,
        { make_input(a_txid, 0) },
        { make_output(200000) }, 0)
      local _, b_hex = accept(mp, tx_b)

      -- Replacement: double-spends coin, fee = 500000+500000-600000 = 400000
      -- All conflicting fees: tx_a=200000, tx_b=100000 → total=300000.
      -- additional = 400000 - 300000 = 100000, well above relay cost.
      local coin2 = random_txid()
      add_utxo(cs, coin2, 0, 500000)
      local repl = types.transaction(2,
        { make_input(coin, 0, 0xFFFFFFFD),
          make_input(coin2, 0) },
        { make_output(600000) }, 0)
      local ok_r, err_r = accept(mp, repl, true)   -- allow_rbf=true
      assert.is_true(ok_r, "replacement must be accepted: " .. tostring(err_r))

      -- Both A and B must have been evicted
      assert.is_nil(mp.entries[a_hex], "conflicting tx A must be evicted")
      assert.is_nil(mp.entries[b_hex],
        "descendant B must be evicted with A (all_conflicts collection)")
    end)
  end)

  ---------------------------------------------------------------------------
  -- G21: TRUC Gate 1 — non-TRUC cannot spend TRUC parent
  ---------------------------------------------------------------------------
  describe("G21: TRUC Gate 1 - non-v3 tx cannot spend v3 parent", function()
    it("rejects version=1 tx that spends a version=3 in-mempool parent", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 200000)

      local mp = mempool.new(cs)
      -- TRUC parent (version=3)
      local truc_par = types.transaction(3,
        { make_input(coin, 0) },
        { make_output(100000) }, 0)
      local ok1, p_hex = accept(mp, truc_par)
      assert.is_true(ok1, "TRUC parent accepted: " .. tostring(p_hex))

      -- Non-TRUC child (version=1) spending TRUC parent → Gate 1 violation
      local p_txid = validation.compute_txid(truc_par)
      local non_truc_child = types.transaction(1,
        { make_input(p_txid, 0) },
        { make_output(50000) }, 0)
      local ok2, err2 = accept(mp, non_truc_child)
      assert.is_false(ok2, "non-TRUC child of TRUC parent must be rejected")
      assert.is_string(err2)
    end)
  end)

  ---------------------------------------------------------------------------
  -- G22: TRUC Gate 2 — TRUC cannot spend non-TRUC parent
  ---------------------------------------------------------------------------
  describe("G22: TRUC Gate 2 - v3 tx cannot spend non-v3 parent", function()
    it("rejects version=3 tx that spends a version=1 in-mempool parent", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 200000)

      local mp = mempool.new(cs)
      -- Non-TRUC parent (version=1)
      local non_truc_par = types.transaction(1,
        { make_input(coin, 0) },
        { make_output(100000) }, 0)
      local ok1, p_hex = accept(mp, non_truc_par)
      assert.is_true(ok1)

      -- TRUC child (version=3) spending non-TRUC parent → Gate 2 violation
      local p_txid = validation.compute_txid(non_truc_par)
      local truc_child = types.transaction(3,
        { make_input(p_txid, 0) },
        { make_output(50000) }, 0)
      local ok2, err2 = accept(mp, truc_child)
      assert.is_false(ok2, "TRUC child of non-TRUC parent must be rejected")
      assert.is_string(err2)
    end)
  end)

  ---------------------------------------------------------------------------
  -- G23: TRUC Gate 3/5 constants correct
  ---------------------------------------------------------------------------
  describe("G23: TRUC_MAX_VSIZE = 10000 and TRUC_CHILD_MAX_VSIZE = 1000", function()
    it("TRUC_MAX_VSIZE is 10000 vbytes", function()
      assert.are_equal(10000, mempool.TRUC_MAX_VSIZE,
        "Core truc_policy.h:30 TRUC_MAX_VSIZE = 10000")
    end)

    it("TRUC_CHILD_MAX_VSIZE is 1000 vbytes", function()
      assert.are_equal(1000, mempool.TRUC_CHILD_MAX_VSIZE,
        "Core truc_policy.h:33 TRUC_CHILD_MAX_VSIZE = 1000")
    end)
  end)

  ---------------------------------------------------------------------------
  -- G24 BUG: accept_package does NOT call TRUC checks (PackageTRUCChecks)
  --
  -- Core calls PackageTRUCChecks (and SingleTRUCChecks) for each tx in a
  -- package.  lunarblock's accept_package runs only check_transaction +
  -- weight cap, never single_truc_checks.
  ---------------------------------------------------------------------------
  -- G24 (FIXED, audit w14z8m3zc): accept_package now routes every member
  -- through accept_transaction, which runs single_truc_checks.  A non-TRUC
  -- (v1) child of a TRUC (v3) parent violates TRUC Gate 1 and MUST be rejected.
  describe("G24: accept_package enforces TRUC inheritance checks", function()
    it("rejects a non-TRUC child of a TRUC parent via accept_package (Gate 1)", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 300000)

      local mp = mempool.new(cs)

      -- TRUC parent + non-TRUC child (Gate 1 violation)
      local truc_par = types.transaction(3,
        { make_input(coin, 0) },
        { make_output(200000) }, 0)
      local p_txid = validation.compute_txid(truc_par)
      local non_truc_child = types.transaction(1,
        { make_input(p_txid, 0) },
        { make_output(100000) }, 0)

      local ok = mp:accept_package({ truc_par, non_truc_child })
      assert.is_false(ok,
        "TRUC Gate-1 violation (v1 child of v3 parent) MUST be rejected by " ..
        "accept_package now that members run single_truc_checks")
      -- Atomic: neither member may linger.
      assert.are_equal(0, mp.tx_count,
        "rejected package must leave the mempool empty (atomic rollback)")
    end)
  end)

  ---------------------------------------------------------------------------
  -- G25: TRUC sibling eviction (Gate 6)
  ---------------------------------------------------------------------------
  describe("G25: TRUC sibling eviction when parent already has one child", function()
    it("second TRUC child evicts or replaces first TRUC child of same parent", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 500000)

      local mp = mempool.new(cs)

      -- TRUC parent
      local truc_par = types.transaction(3,
        { make_input(coin, 0) },
        { make_output(400000) }, 0)
      local ok1, par_hex = accept(mp, truc_par)
      assert.is_true(ok1)
      local par_txid = validation.compute_txid(truc_par)

      -- First TRUC child
      local truc_c1 = types.transaction(3,
        { make_input(par_txid, 0) },
        { make_output(300000) }, 0)
      local ok2, c1_hex = accept(mp, truc_c1)
      assert.is_true(ok2, "first TRUC child accepted")

      -- Second TRUC child (same parent → triggers Gate 6 / sibling eviction)
      local truc_c2 = types.transaction(3,
        { make_input(par_txid, 0) },
        { make_output(290000) }, 0)
      local ok3, c2_result = accept(mp, truc_c2)
      if ok3 then
        -- Sibling eviction path: c1 should be gone
        assert.is_nil(mp.entries[c1_hex],
          "TRUC sibling c1 evicted when c2 accepted (Gate 6 sibling eviction)")
      else
        -- May fail Rule #2/3/4 (no new unconfirmed inputs via RBF path)
        assert.is_string(c2_result)
      end
    end)
  end)

  ---------------------------------------------------------------------------
  -- G26: is_well_formed_package — MAX_PACKAGE_COUNT = 25
  ---------------------------------------------------------------------------
  describe("G26: is_well_formed_package - MAX_PACKAGE_COUNT = 25 enforced", function()
    it("rejects package with 26 transactions", function()
      local txns = {}
      for _ = 1, 26 do
        local coin = random_txid()
        txns[#txns + 1] = types.transaction(1,
          { make_input(coin, 0) },
          { make_output(50000) }, 0)
      end
      local ok, err = mempool.is_well_formed_package(txns)
      assert.is_false(ok, "26-tx package must be rejected")
      assert.is_string(err)
    end)
  end)

  ---------------------------------------------------------------------------
  -- G27: MAX_PACKAGE_WEIGHT constant
  ---------------------------------------------------------------------------
  describe("G27: MAX_PACKAGE_WEIGHT = 404000 wu", function()
    it("MAX_PACKAGE_WEIGHT is 404000 weight units", function()
      assert.are_equal(404000, mempool.MAX_PACKAGE_WEIGHT,
        "Core packages.h:24 MAX_PACKAGE_WEIGHT = 404000 wu (101 kvB * 4)")
    end)
  end)

  ---------------------------------------------------------------------------
  -- G28: Package topological order enforced
  ---------------------------------------------------------------------------
  describe("G28: is_topo_sorted_package - parent must precede child", function()
    it("rejects package where child appears before parent", function()
      local coin = random_txid()
      local parent_tx = types.transaction(1,
        { make_input(coin, 0) },
        { make_output(50000) }, 0)
      local par_txid = validation.compute_txid(parent_tx)
      local child_tx = types.transaction(1,
        { make_input(par_txid, 0) },
        { make_output(30000) }, 0)

      -- Wrong order: child before parent
      local ok, _ = mempool.is_topo_sorted_package({ child_tx, parent_tx })
      assert.is_false(ok, "out-of-order package must be rejected")
    end)

    it("accepts package with correct topological order", function()
      local coin = random_txid()
      local parent_tx = types.transaction(1,
        { make_input(coin, 0) },
        { make_output(50000) }, 0)
      local par_txid = validation.compute_txid(parent_tx)
      local child_tx = types.transaction(1,
        { make_input(par_txid, 0) },
        { make_output(30000) }, 0)

      local ok, _ = mempool.is_topo_sorted_package({ parent_tx, child_tx })
      assert.is_true(ok)
    end)
  end)

  ---------------------------------------------------------------------------
  -- G29: is_consistent_package — no conflicting inputs within a package
  ---------------------------------------------------------------------------
  describe("G29: is_consistent_package - no double-spend within package", function()
    it("rejects package where two txs spend the same outpoint", function()
      local coin = random_txid()
      local tx1 = types.transaction(1,
        { make_input(coin, 0) },
        { make_output(50000) }, 0)
      -- tx2 spends the same outpoint as tx1
      local tx2 = types.transaction(1,
        { make_input(coin, 0) },
        { make_output(40000) }, 0)

      local ok, _ = mempool.is_consistent_package({ tx1, tx2 })
      assert.is_false(ok, "package with internal double-spend must be rejected")
    end)
  end)

  ---------------------------------------------------------------------------
  -- G30 BUG: accept_package skips per-tx standardness (version, dust, etc.)
  --
  -- Core runs IsStandardTx, IsFinalTx, SequenceLocks, ValidateInputsStandardness,
  -- IsWitnessStandard, and TRUC checks for each tx in a package.
  -- lunarblock's accept_package only runs check_transaction + weight cap,
  -- silently admitting non-standard txs (wrong version, dust outputs, etc.).
  ---------------------------------------------------------------------------
  -- G30 (FIXED, audit w14z8m3zc): accept_package now applies the SAME per-tx
  -- standardness gates single-tx admission applies, because every member is
  -- routed through accept_transaction.
  describe("G30: accept_package enforces per-tx standardness gates", function()
    it("rejects a version=0 (non-standard) tx via accept_package", function()
      local cs = make_chain()
      local coin_single = random_txid()
      add_utxo(cs, coin_single, 0, 200000)

      local mp = mempool.new(cs)

      -- version=0 is rejected by accept_transaction (IsStandardTx).
      local tx_v0 = types.transaction(0,
        { make_input(coin_single, 0) },
        { make_output(100000) }, 0)
      local ok_single, err_single = mp:accept_transaction(tx_v0)
      assert.is_false(ok_single,
        "version=0 correctly rejected by accept_transaction (IsStandardTx)")
      assert.is_truthy(string.find(tostring(err_single), "version"))

      -- The SAME tx via accept_package must now also be rejected.
      local coin2 = random_txid()
      add_utxo(cs, coin2, 0, 200000)
      local tx_v0b = types.transaction(0,
        { make_input(coin2, 0) },
        { make_output(100000) }, 0)
      local ok_pkg, pkg_err = mp:accept_package({ tx_v0b })
      assert.is_false(ok_pkg,
        "version=0 non-standard tx MUST be rejected via accept_package now " ..
        "that members run IsStandardTx")
      assert.is_truthy(string.find(tostring(pkg_err), "version"),
        "reject reason must reference the version gate, got: " .. tostring(pkg_err))
      assert.are_equal(0, mp.tx_count)
    end)
  end)

end)
