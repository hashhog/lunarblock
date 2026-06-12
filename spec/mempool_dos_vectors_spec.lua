-- spec/mempool_dos_vectors_spec.lua
--
-- DoS-vector regression suite (audit w14z8m3zc).  Each test below is a
-- "proven-teeth" busted test: it FAILS if the corresponding DoS gap regresses.
--
-- Gap 1 — Relay-time PolicyScriptChecks were disabled in production: the live
--         P2P/RPC mempool-admission path (accept_transaction) skipped input-
--         script verification, so invalid-script txs were admitted AND relayed.
--         Fix: main.lua now builds the production mempool with
--         verify_input_scripts=true (Core validation.cpp:1382 PolicyScriptChecks).
--
-- Gap 2 — Package validation (submitpackage / 1p1c) bypassed PreChecks: the
--         old accept_package inserted entries after only check_transaction +
--         a weight cap, skipping IsStandardTx (version/dust/scriptSig/
--         scriptPubKey), ValidateInputsStandardness, sigop cap, TRUC, and
--         PolicyScriptChecks that single-tx admission applies.  Fix:
--         accept_package now routes every member through accept_transaction
--         (Core validation.cpp AcceptMultipleTransactionsInternal:1447-1449
--         runs PreChecks per member; PolicyScriptChecks at :1538).
--
-- Gap 3 — Orphan-pool EraseForPeer was not wired to peer disconnect: orphans
--         from a departed peer lingered until the 5-min expiry, letting a
--         malicious peer flood-then-disconnect-then-reconnect to pin memory and
--         starve the global orphan cap.  Fix: main.lua's on_peer_disconnected
--         callback now calls orphan_pool:remove_for_peer(pid) (Core
--         net_processing.cpp:1710 FinalizeNode -> DisconnectedPeer ->
--         TxOrphanage::EraseForPeer).

local types      = require("lunarblock.types")
local mempool    = require("lunarblock.mempool")
local validation = require("lunarblock.validation")

describe("mempool DoS-vector gaps (audit w14z8m3zc)", function()

  -- Standard P2PKH scriptPubKey (passes IsStandardTx classify_script).
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
      end,
    }
    return { coin_view = cv, tip_height = height or 700000 }
  end

  local function add_utxo(cs, txid_hash, vout, value, spk)
    cs.coin_view.utxos[types.hash256_hex(txid_hash) .. ":" .. vout] = {
      value         = value or 100000,
      script_pubkey = spk or P2PKH,
      height        = 699000,
      is_coinbase   = false,
    }
  end

  -- A non-witness P2PKH-spending tx whose scriptSig pushes garbage (a 72-byte
  -- "signature" + a 33-byte "pubkey" that hash160s to something other than the
  -- 20 zero bytes in the prev P2PKH).  It is push-only (standard scriptSig) and
  -- spends a standard scriptPubKey, so it clears every gate EXCEPT script
  -- verification: OP_EQUALVERIFY (or OP_CHECKSIG) fails.
  local function make_bad_script_tx(coin)
    local fake_sig = string.char(0x48) .. string.rep("\x01", 72)
    local fake_pk  = string.char(0x21) .. string.rep("\x02", 33)
    local scriptsig = fake_sig .. fake_pk
    return types.transaction(1,
      { types.txin(types.outpoint(coin, 0), scriptsig, 0xFFFFFFFE) },
      { make_output(90000) }, 0)
  end

  -----------------------------------------------------------------------------
  -- Gap 1: Relay-time PolicyScriptChecks
  -----------------------------------------------------------------------------
  describe("Gap 1: PolicyScriptChecks run at relay time on the production path", function()

    it("rejects a tx with an invalid input script when verify_input_scripts is on", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 200000)

      -- The production mempool (main.lua) is constructed with this flag.
      local mp = mempool.new(cs, { verify_input_scripts = true })
      local tx = make_bad_script_tx(coin)

      local ok, err = mp:accept_transaction(tx)
      assert.is_false(ok,
        "invalid-script tx MUST be rejected at relay when PolicyScriptChecks " ..
        "are enabled (production path)")
      assert.is_truthy(string.find(tostring(err), "script%-verify%-flag%-failed"),
        "reject reason must be a script-verify failure, got: " .. tostring(err))
      assert.is_nil(mp.entries[types.hash256_hex(validation.compute_txid(tx))],
        "the bad tx must NOT be in the mempool (and therefore never relayed)")
    end)

    it("DEMONSTRATES the gap: with the flag off the same bad tx is admitted", function()
      -- This pins the failure mode the fix closes: without PolicyScriptChecks
      -- the invalid-script tx is accepted and would be re-announced to peers.
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 200000)

      local mp = mempool.new(cs, { verify_input_scripts = false })
      local tx = make_bad_script_tx(coin)
      local ok = mp:accept_transaction(tx)
      assert.is_true(ok,
        "control: flag off admits the bad tx (this is exactly the DoS the " ..
        "production verify_input_scripts=true flag closes)")
    end)

    it("production mempool in main.lua sets verify_input_scripts=true", function()
      -- Guard the wiring itself: if a future edit drops the production flag the
      -- relay-time script gate silently turns off again.
      local f = assert(io.open("src/main.lua", "r"))
      local src = f:read("*a"); f:close()
      assert.is_truthy(src:find("verify_input_scripts%s*=%s*true"),
        "main.lua production mempool must construct with verify_input_scripts=true")
    end)
  end)

  -----------------------------------------------------------------------------
  -- Gap 2: package members go through the single-tx PreChecks
  -----------------------------------------------------------------------------
  describe("Gap 2: accept_package routes members through PreChecks", function()

    it("rejects a non-standard (version=0) package member (was G30 bug)", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 200000)
      local mp = mempool.new(cs)

      local v0 = types.transaction(0,
        { make_input(coin, 0) }, { make_output(190000) }, 0)
      local ok, err = mp:accept_package({ v0 })
      assert.is_false(ok,
        "version=0 (non-standard) member MUST be rejected by accept_package")
      assert.is_truthy(string.find(tostring(err), "version"),
        "reject reason must reference the version gate, got: " .. tostring(err))
      assert.are_equal(0, mp.tx_count, "nothing must have been admitted")
    end)

    it("rejects a fee-paying-dust package member", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 200000)
      local mp = mempool.new(cs)

      -- 100-sat dust output + a fee-paying change output => PreCheckEphemeralTx
      -- requires a dust-carrying tx to be 0-fee.  Single-tx admission rejects
      -- this; the package path must too.
      local dusttx = types.transaction(1,
        { make_input(coin, 0) },
        { make_output(100), make_output(150000) }, 0)
      local ok, err = mp:accept_package({ dusttx })
      assert.is_false(ok, "fee-paying dust member MUST be rejected by accept_package")
      assert.is_truthy(string.find(tostring(err), "dust"),
        "reject reason must reference dust, got: " .. tostring(err))
      assert.are_equal(0, mp.tx_count)
    end)

    it("rejects an invalid-input-script package member (PolicyScriptChecks)", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 200000)
      -- Package members are routed through accept_transaction, which runs
      -- PolicyScriptChecks IFF the mempool has verify_input_scripts on (as the
      -- production mempool does).
      local mp = mempool.new(cs, { verify_input_scripts = true })

      local bad = make_bad_script_tx(coin)
      local ok, err = mp:accept_package({ bad })
      assert.is_false(ok,
        "invalid-script member MUST be rejected by accept_package when relay " ..
        "script checks are on")
      assert.is_truthy(string.find(tostring(err), "script%-verify%-flag%-failed"),
        "reject reason must be a script-verify failure, got: " .. tostring(err))
      assert.are_equal(0, mp.tx_count)
    end)

    it("a mid-package member rejection rolls the whole package back (atomic)", function()
      local cs = make_chain()
      -- parent valid + standard, child non-standard (version=0).
      local coin = random_txid()
      add_utxo(cs, coin, 0, 300000)
      local mp = mempool.new(cs)

      local parent = types.transaction(1,
        { make_input(coin, 0) }, { make_output(200000) }, 0)
      local p_txid = validation.compute_txid(parent)
      local bad_child = types.transaction(0,  -- version 0 -> non-standard
        { make_input(p_txid, 0) }, { make_output(100000) }, 0)

      local ok = mp:accept_package({ parent, bad_child })
      assert.is_false(ok, "package with a bad child must fail")
      assert.are_equal(0, mp.tx_count,
        "the already-admitted parent must be rolled back (no partial package)")
      assert.is_nil(mp.entries[types.hash256_hex(p_txid)],
        "parent must not linger after the package was rejected")
    end)

    it("still accepts a legitimate CPFP package (low-fee parent + high-fee child)", function()
      -- Teeth in the other direction: the fix must NOT break valid CPFP, i.e.
      -- the per-tx fee floor is bypassed for package members but every other
      -- gate still runs.
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 100000000)
      -- CPFP-LOGIC test: pin min_relay_fee to 1000 sat/kvB so the 20-sat parent
      -- is below the floor independent of the (Core-correct 100 sat/kvB)
      -- default, keeping the "parent rejected alone, package accepted" scenario.
      local mp = mempool.new(cs, { min_relay_fee = 1000 })

      local parent = types.transaction(1,
        { make_input(coin, 0) }, { make_output(99999980) }, 0)  -- 20-sat fee, below floor
      local p_txid = validation.compute_txid(parent)
      local child = types.transaction(1,
        { make_input(p_txid, 0) }, { make_output(99899980) }, 0)  -- 100k-sat fee

      -- Parent alone is below the relay floor.
      local ok_parent = mp:accept_transaction(parent)
      assert.is_false(ok_parent, "low-fee parent rejected on its own")

      local ok_pkg, res = mp:accept_package({ parent, child })
      assert.is_true(ok_pkg, "CPFP package must be accepted")
      assert.are_equal(2, #res.txids)
      assert.are_equal(2, mp.tx_count)
    end)

    it("test_accept package leaves the mempool unchanged but reports per-tx fees", function()
      local cs = make_chain()
      local coin = random_txid()
      add_utxo(cs, coin, 0, 100000000)
      local mp = mempool.new(cs)

      local parent = types.transaction(1,
        { make_input(coin, 0) }, { make_output(99990000) }, 0)
      local p_txid = validation.compute_txid(parent)
      local child = types.transaction(1,
        { make_input(p_txid, 0) }, { make_output(99980000) }, 0)

      local ok, res = mp:accept_package({ parent, child }, true)  -- test_accept
      assert.is_true(ok)
      assert.are_equal(0, mp.tx_count, "dry-run must not mutate the mempool")
      assert.is_table(res.fees, "test_accept must surface per-tx fees for RPC")
      assert.are_equal(2, #res.txids)
    end)
  end)

  -----------------------------------------------------------------------------
  -- Gap 3: orphan EraseForPeer on disconnect
  -----------------------------------------------------------------------------
  describe("Gap 3: orphan pool EraseForPeer wired to peer disconnect", function()

    local function make_orphan()
      local parent = random_txid()
      local tx = types.transaction(1,
        { make_input(parent, 0) }, { make_output(50000) }, 0)
      local wtxid = validation.compute_wtxid(tx)
      return tx, types.hash256_hex(wtxid)
    end

    it("remove_for_peer erases only the departed peer's orphans", function()
      local pool = mempool.new_orphan_pool()
      -- pid format must match the tx handler: peer.ip .. ":" .. peer.port.
      local peerA = "1.2.3.4:8333"
      local peerB = "5.6.7.8:8333"
      for _ = 1, 3 do local tx, w = make_orphan(); assert.is_true(pool:add(tx, w, peerA, {})) end
      for _ = 1, 2 do local tx, w = make_orphan(); assert.is_true(pool:add(tx, w, peerB, {})) end
      assert.are_equal(5, pool:size())

      local removed = pool:remove_for_peer(peerA)
      assert.are_equal(3, removed, "exactly peerA's 3 orphans erased")
      assert.are_equal(2, pool:size(), "peerB's orphans survive")
      assert.is_nil(pool.by_peer[peerA], "peerA fully cleared from per-peer counts")
      assert.are_equal(2, pool.by_peer[peerB], "peerB count intact")
    end)

    it("simulating the disconnect callback erases the flooding peer's orphans", function()
      -- Replicate the wiring in main.lua's on_peer_disconnected: given the peer
      -- object, derive the same pid the tx handler used and call remove_for_peer.
      local pool = mempool.new_orphan_pool()
      local attacker = { ip = "9.9.9.9", port = 8333 }
      local honest   = { ip = "1.1.1.1", port = 8333 }
      local function pid_of(p) return p.ip .. ":" .. p.port end

      for _ = 1, 4 do local tx, w = make_orphan(); assert.is_true(pool:add(tx, w, pid_of(attacker), {})) end
      for _ = 1, 1 do local tx, w = make_orphan(); assert.is_true(pool:add(tx, w, pid_of(honest), {})) end
      assert.are_equal(5, pool:size())

      -- == on_peer_disconnected(attacker) ==
      local removed = pool:remove_for_peer(pid_of(attacker))

      assert.are_equal(4, removed)
      assert.are_equal(1, pool:size(),
        "after the attacker disconnects, only the honest peer's orphan remains")
    end)

    it("main.lua's disconnect handler calls remove_for_peer (wiring guard)", function()
      -- Pure-behavior teeth can't reach main.lua's startup wiring; guard the
      -- source so deleting the EraseForPeer call fails this test.
      local f = assert(io.open("src/main.lua", "r"))
      local src = f:read("*a"); f:close()
      local cb_start = src:find("on_peer_disconnected%s*=%s*function")
      assert.is_truthy(cb_start, "on_peer_disconnected callback must exist")
      -- The remove_for_peer call must appear inside the disconnect callback,
      -- after its definition.
      local has_erase = src:find("orphan_pool:remove_for_peer", cb_start, true)
      assert.is_truthy(has_erase,
        "on_peer_disconnected must call orphan_pool:remove_for_peer(pid)")
    end)
  end)
end)
