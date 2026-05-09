-- W41: PSBT consistency + finalizepsbt P2SH-P2WSH crash regression tests.
--
-- This wave covers three tightly-related defenses on the PSBT signer/
-- finalizer:
--
--   Fix 1.  finalizepsbt no longer crashes (or silently mis-assembles) on
--           a P2SH-P2WSH-multisig input.  Before W41 the finalize_input
--           "p2sh" branch handled redeem_type == "p2wpkh" and fell through
--           to a pure-P2SH "<sig> <pubkey> <redeem_script>" template for
--           every other shape — which is wrong for both legacy P2SH-
--           multisig (needs OP_0 + N sigs + redeem_script) AND P2SH-P2WSH
--           (needs witness stack + scriptSig=<push redeem>).  The W40-C
--           harness flagged this as a stability P0 because the running
--           daemon hit `attempt to call field 'verify_p2sh_commitment'`
--           on a stale luajit-cached copy of psbt.lua; the on-disk fix is
--           to simply assemble the right wire bytes.
--
--   Fix 2.  PSBT_IN_NON_WITNESS_UTXO must hash to the spent outpoint
--           (BIP-174 / bitcoin-core/src/psbt.cpp PSBTInput::IsSane).
--           Without this check, an attacker-supplied non_witness_utxo
--           steers a downstream signer's value/scriptPubKey/scriptCode
--           lookups against an arbitrary fake transaction.  Wired at
--           BOTH the deserialize site AND the sign-time path.
--
--   Fix 3.  CVE-2020-14199: when both witness_utxo and non_witness_utxo
--           are present they MUST agree on (value, scriptPubKey).  An
--           inflated witness_utxo.value over a truthful non_witness_utxo
--           lets the attacker trick a hardware-wallet-style signer into
--           binding a BIP-143 segwit-v0 sighash to a fee the user never
--           approved.

local function setup_loader()
  local loaders = package.loaders or package.searchers
  table.insert(loaders, 2, function(module)
    local name = module:match("^lunarblock%.(.+)")
    if name then
      local filename = "src/" .. name .. ".lua"
      local f = io.open(filename)
      if f then
        f:close()
        return function() return dofile(filename) end
      end
    end
    return nil, "not found"
  end)
end

local function read_file(path)
  local f = assert(io.open(path, "r"))
  local d = f:read("*a")
  f:close()
  return d
end

local function bytes_to_hex(bytes)
  local out = {}
  for i = 1, #bytes do out[i] = string.format("%02x", bytes:byte(i)) end
  return table.concat(out)
end

describe("PSBT W41 — finalizepsbt + NON_WITNESS_UTXO consistency", function()
  local crypto, script_mod, types, psbt_mod, serialize, validation

  setup(function()
    setup_loader()
    crypto = require("lunarblock.crypto")
    script_mod = require("lunarblock.script")
    types = require("lunarblock.types")
    psbt_mod = require("lunarblock.psbt")
    serialize = require("lunarblock.serialize")
    validation = require("lunarblock.validation")
  end)

  --------------------------------------------------------------------------
  -- Fix 1: finalizepsbt no longer crashes on P2SH-P2WSH-multisig.
  -- Use the canonical W40-C multi-input fixture (Core 31.99 round-trip
  -- verified) — input 1 is exactly the asymmetric P2SH-P2WSH-multisig
  -- shape that triggered the crash.  After W41 the extracted hex must
  -- match Bitcoin Core byte-for-byte.
  --------------------------------------------------------------------------

  describe("finalizepsbt on multi-input asymmetric (P2SH-multisig + P2SH-P2WSH-multisig)", function()
    it("matches Core's extracted hex byte-for-byte (W40-C fixture)", function()
      local fixture_path = "../tools/psbt-multi-input-fixture.json"
      -- Tests run with cwd = lunarblock/, so the fixture is one level up.
      local f = io.open(fixture_path, "r")
      if not f then
        -- Fall back to absolute path; meta-repo layout on maxbox.
        f = io.open("/home/work/hashhog/tools/psbt-multi-input-fixture.json", "r")
      end
      assert.is_not_nil(f, "W40-C fixture must be reachable")
      local fixture = f:read("*a")
      f:close()

      local psbt_signed = fixture:match('"psbt_signed":%s*"([^"]+)"')
      local extracted_expected = fixture:match('"extracted_tx_hex":%s*"([^"]+)"')
      assert.is_string(psbt_signed)
      assert.is_string(extracted_expected)

      local p = psbt_mod.from_base64(psbt_signed)
      assert.equals(2, #p.inputs)
      -- Input 1 is the asymmetric P2SH-P2WSH-multisig that pre-W41 crashed.
      assert.is_not_nil(p.inputs[2].witness_utxo)
      assert.is_not_nil(p.inputs[2].redeem_script)
      assert.is_not_nil(p.inputs[2].witness_script)

      -- finalize must succeed end-to-end (no crash, no DIVERGE).
      local complete = psbt_mod.finalize(p)
      assert.is_true(complete)

      local tx = psbt_mod.extract(p)
      local got_hex = bytes_to_hex(serialize.serialize_transaction(tx, true))
      assert.equals(extracted_expected, got_hex)
    end)

    it("rejects forged witness_script under P2SH-P2WSH (W41 regression)", function()
      -- Build a 2-of-2 multisig witness_script.  Honest path: redeem_script
      -- = `0020 sha256(witness_script)`.  Attacker swaps witness_script in
      -- after the producer set the redeem.  finalize MUST refuse.
      local pk_a = crypto.pubkey_from_privkey(
        crypto.sha256("lunarblock-w41-p2shp2wsh-honest-a"), true)
      local pk_b = crypto.pubkey_from_privkey(
        crypto.sha256("lunarblock-w41-p2shp2wsh-honest-b"), true)
      local pk_evil = crypto.pubkey_from_privkey(
        crypto.sha256("lunarblock-w41-p2shp2wsh-attacker"), true)

      local function multisig_2of2(p1, p2)
        return "\x52" .. "\x21" .. p1 .. "\x21" .. p2 .. "\x52" .. "\xae"
      end
      local ws_honest = multisig_2of2(pk_a, pk_b)
      local ws_forged = multisig_2of2(pk_a, pk_evil)
      local redeem = script_mod.make_p2wsh_script(crypto.sha256(ws_honest))
      local spk = script_mod.make_p2sh_script(crypto.hash160(redeem))

      local fake_prev = types.hash256(string.rep("\x77", 32))
      local tx = types.transaction(2,
        { types.txin(types.outpoint(fake_prev, 0), "", 0xfffffffd) },
        { types.txout(99000000, script_mod.make_p2wpkh_script(crypto.hash160(pk_a))) },
        0)
      local p = psbt_mod.new(tx)
      p.inputs[1].witness_utxo = {value = 100000000, script_pubkey = spk}
      p.inputs[1].redeem_script = redeem
      p.inputs[1].witness_script = ws_forged  -- attacker swap
      -- Stub a single partial sig so finalize doesn't bail on "no sigs".
      p.inputs[1].partial_sigs[bytes_to_hex(pk_a)] = string.rep("\x42", 71) .. "\x01"

      local ok, err = pcall(psbt_mod.finalize_input, p, 0)
      assert.is_false(ok)
      assert.is_truthy(tostring(err):find("does not commit")
                    or tostring(err):find("sha256 mismatch"))
    end)
  end)

  --------------------------------------------------------------------------
  -- Fix 2: NON_WITNESS_UTXO txid commitment (BIP-174 IsSane).
  --------------------------------------------------------------------------

  describe("NON_WITNESS_UTXO txid commitment", function()
    it("crypto.verify_non_witness_utxo_txid round-trips honestly", function()
      -- Build a real prev-tx, serialize without witness, hash it, and check.
      local prev_tx = types.transaction(2,
        { types.txin(types.outpoint(types.hash256(string.rep("\x33", 32)), 0),
                     "", 0xffffffff) },
        { types.txout(5000000000,
                      script_mod.make_p2pkh_script(string.rep("\x44", 20))) },
        0)
      local prev_bytes = serialize.serialize_transaction(prev_tx, false)
      local txid = validation.compute_txid(prev_tx).bytes

      assert.is_true(crypto.verify_non_witness_utxo_txid(prev_bytes, txid))
      -- Flip a byte in the serialized tx → mismatch.
      local mutated = prev_bytes:sub(1, 10) .. string.char((prev_bytes:byte(11) + 1) % 256) .. prev_bytes:sub(12)
      assert.is_false(crypto.verify_non_witness_utxo_txid(mutated, txid))
      -- Non-32-byte txid → false (defensive).
      assert.is_false(crypto.verify_non_witness_utxo_txid(prev_bytes, "tooshort"))
    end)

    -- W46 regression: the deserialize-path txid check used to hash the
    -- raw `entry.value` bytes from the PSBT.  When the embedded prev-tx
    -- carries a segwit marker+flag+witness, those bytes hash to wtxid,
    -- not txid — so honest PSBTs failed decode with "txid mismatch".  The
    -- fix routes through deserialize → re-serialize(include_witness=false)
    -- before hashing.  This mirrors bitcoin-core PSBTInput::IsSane which
    -- calls non_witness_utxo->GetHash() (the no-witness serializer).
    --
    -- See tools/psbt-byte-identity-corpus.json entries 2 and 3 for the
    -- exact upstream fixture (rpc_psbt.json valid[0] full + valid[2]).
    it("deserializer accepts a non_witness_utxo with embedded segwit witness (W46)", function()
      -- Build a segwit prev-tx (marker+flag+witness items present).  Its
      -- bytes-with-witness hash != txid, so a naive hash256(raw) would fail.
      local prev_segwit = types.transaction(1,
        { types.txin(types.outpoint(types.hash256(string.rep("\x77", 32)), 0),
                     "", 0xffffffff) },
        { types.txout(50000000,
                      script_mod.make_p2pkh_script(string.rep("\x21", 20))) },
        0)
      prev_segwit.segwit = true
      prev_segwit.inputs[1].witness = {
        string.rep("\x33", 71),  -- pretend signature
        string.rep("\x44", 33),  -- pretend pubkey
      }
      -- Sanity: the with-witness bytes really do differ from no-witness.
      local with_w = serialize.serialize_transaction(prev_segwit, true)
      local no_w   = serialize.serialize_transaction(prev_segwit, false)
      assert.is_true(#with_w > #no_w)
      assert.is_not.equal(crypto.hash256(with_w), crypto.hash256(no_w))

      local prev_txid = validation.compute_txid(prev_segwit)
      local outer = types.transaction(2,
        { types.txin(types.outpoint(prev_txid, 0), "", 0xfffffffd) },
        { types.txout(40000000,
                      script_mod.make_p2pkh_script(string.rep("\x55", 20))) },
        0)
      local p = psbt_mod.new(outer)
      p.inputs[1].non_witness_utxo = prev_segwit

      -- Round-trip via PSBT.  lunarblock's PSBT serializer follows Core
      -- (psbt.h:306 TX_NO_WITNESS) — it strips witness on the wire.  So
      -- the round-tripped non_witness_utxo will not carry segwit data;
      -- what we're testing is that decode SUCCEEDS in the first place.
      -- Pre-W46, the to_base64 step was fine (it wrote no-witness bytes),
      -- but then on re-decode the txid check still failed because *some*
      -- producers (Core in particular: psbt.h:513 TX_WITH_WITNESS) emit
      -- segwit-bearing non_witness_utxo blobs.  Simulate that case by
      -- byte-injecting a with-witness blob into a hand-crafted PSBT.
      local outer_bytes = serialize.serialize_transaction(outer, false)
      local function vi(n)
        if n < 0xfd then return string.char(n) end
        if n < 0x10000 then return "\xfd" .. string.char(n % 256) .. string.char(math.floor(n/256)) end
        error("varint too large for test")
      end
      local nw_bytes_with_witness = with_w  -- with marker+flag+witness
      local hand_psbt =
        "psbt\xff" ..
        -- global map: PSBT_GLOBAL_UNSIGNED_TX (key=0x00) → outer_bytes
        vi(1) .. "\x00" .. vi(#outer_bytes) .. outer_bytes ..
        -- end of global map
        "\x00" ..
        -- input 0 map: PSBT_IN_NON_WITNESS_UTXO (key=0x00) → with-witness blob
        vi(1) .. "\x00" .. vi(#nw_bytes_with_witness) .. nw_bytes_with_witness ..
        "\x00" ..
        -- output 0 map: empty
        "\x00"
      -- Sanity: len mod 3 → padded base64.
      local hand_b64 = psbt_mod.base64_encode(hand_psbt)

      local p_back
      assert.has_no.errors(function() p_back = psbt_mod.from_base64(hand_b64) end)
      assert.is_not_nil(p_back.inputs[1].non_witness_utxo)
      -- The witness data round-trips at deserialize because Core (and
      -- lunarblock post-W46) parses with TX_WITH_WITNESS on the wire.
      assert.is_true(p_back.inputs[1].non_witness_utxo.segwit)
      assert.equals(2, #p_back.inputs[1].non_witness_utxo.inputs[1].witness)
    end)

    it("deserializer still rejects a genuinely forged non_witness_utxo after W46", function()
      -- Defenders-in-depth: prove the W46 round-trip fix did NOT
      -- accidentally disable the IsSane check itself.  Same shape as the
      -- forged-utxo test below, but specifically guards against a
      -- "fix-deletes-the-check" regression.
      local pkh = string.rep("\x66", 20)
      local prev_real = types.transaction(2,
        { types.txin(types.outpoint(types.hash256(string.rep("\xaa", 32)), 0),
                     "", 0xffffffff) },
        { types.txout(40000000, script_mod.make_p2pkh_script(pkh)) },
        0)
      local prev_real_txid = validation.compute_txid(prev_real)
      local outer = types.transaction(2,
        { types.txin(types.outpoint(prev_real_txid, 0), "", 0xfffffffd) },
        { types.txout(35000000, script_mod.make_p2pkh_script(pkh)) },
        0)
      local prev_fake = types.transaction(2,
        { types.txin(types.outpoint(types.hash256(string.rep("\xbb", 32)), 0),
                     "", 0xffffffff) },
        { types.txout(99999999, script_mod.make_p2pkh_script(pkh)) },
        0)
      local p_bad = psbt_mod.new(outer)
      p_bad.inputs[1].non_witness_utxo = prev_fake
      local bad_b64 = psbt_mod.to_base64(p_bad)
      local ok, err = pcall(psbt_mod.from_base64, bad_b64)
      assert.is_false(ok)
      assert.is_truthy(tostring(err):find("non_witness_utxo txid mismatch"))
    end)

    it("psbt deserializer rejects a forged non_witness_utxo (CVE-2020-14199 family)", function()
      -- Construct a valid PSBT, then mutate the embedded non_witness_utxo
      -- so its hash no longer matches prev_out.hash.  Re-serialize and
      -- expect from_base64 to reject the result.
      local pkh = string.rep("\x55", 20)
      local prev_real = types.transaction(2,
        { types.txin(types.outpoint(types.hash256(string.rep("\x99", 32)), 0),
                     "", 0xffffffff) },
        { types.txout(75000000, script_mod.make_p2pkh_script(pkh)) },
        0)
      local prev_real_txid = validation.compute_txid(prev_real)

      -- Outer tx spends prev_real:0.
      local outer = types.transaction(2,
        { types.txin(types.outpoint(prev_real_txid, 0), "", 0xfffffffd) },
        { types.txout(70000000, script_mod.make_p2pkh_script(pkh)) },
        0)
      local p = psbt_mod.new(outer)
      p.inputs[1].non_witness_utxo = prev_real
      local good_b64 = psbt_mod.to_base64(p)
      -- Sanity: honest PSBT round-trips.
      assert.has_no.errors(function() psbt_mod.from_base64(good_b64) end)

      -- Now lie about non_witness_utxo: substitute a different prev tx
      -- whose hash != prev_real_txid.  Re-build the PSBT object directly
      -- so we don't have to byte-edit the serialized form.
      local prev_fake = types.transaction(2,
        { types.txin(types.outpoint(types.hash256(string.rep("\x88", 32)), 0),
                     "", 0xffffffff) },
        { types.txout(7500000000,  -- inflated, but matters not
                      script_mod.make_p2pkh_script(pkh)) },
        0)
      local p_bad = psbt_mod.new(outer)
      p_bad.inputs[1].non_witness_utxo = prev_fake
      local bad_b64 = psbt_mod.to_base64(p_bad)

      local ok, err = pcall(psbt_mod.from_base64, bad_b64)
      assert.is_false(ok)
      assert.is_truthy(tostring(err):find("non_witness_utxo txid mismatch"))
    end)
  end)

  --------------------------------------------------------------------------
  -- Fix 3: CVE-2020-14199 — witness_utxo / non_witness_utxo amount oracle.
  --------------------------------------------------------------------------

  describe("witness_utxo vs non_witness_utxo cross-check (CVE-2020-14199)", function()
    it("sign_input rejects when witness_utxo.value differs from non_witness_utxo", function()
      local privkey = crypto.sha256("lunarblock-w41-cve-2020-14199-key")
      local pubkey = crypto.pubkey_from_privkey(privkey, true)
      local pkh = crypto.hash160(pubkey)
      local spk = script_mod.make_p2wpkh_script(pkh)

      -- Honest prev tx: 100000000 to spk at vout 0.
      local prev_tx = types.transaction(2,
        { types.txin(types.outpoint(types.hash256(string.rep("\x11", 32)), 0),
                     "", 0xffffffff) },
        { types.txout(100000000, spk) },
        0)
      local prev_txid = validation.compute_txid(prev_tx)

      local outer = types.transaction(2,
        { types.txin(types.outpoint(prev_txid, 0), "", 0xfffffffd) },
        { types.txout(99000000, spk) },
        0)
      local p = psbt_mod.new(outer)
      p.inputs[1].non_witness_utxo = prev_tx
      -- Attacker inflates witness_utxo.value (the BIP-143 oracle).
      p.inputs[1].witness_utxo = {value = 100000000000, script_pubkey = spk}

      local ok, err = pcall(psbt_mod.sign_input, p, 0, privkey, pubkey)
      assert.is_false(ok)
      assert.is_truthy(tostring(err):find("CVE-2020-14199")
                    or tostring(err):find("witness_utxo disagrees"))
      -- And no partial signature has leaked.
      assert.is_nil(next(p.inputs[1].partial_sigs))
    end)

    it("sign_input rejects when witness_utxo.script_pubkey differs", function()
      local privkey = crypto.sha256("lunarblock-w41-cve-spk-mismatch")
      local pubkey = crypto.pubkey_from_privkey(privkey, true)
      local pkh = crypto.hash160(pubkey)
      local honest_spk = script_mod.make_p2wpkh_script(pkh)
      local forged_spk = script_mod.make_p2wpkh_script(string.rep("\x99", 20))

      local prev_tx = types.transaction(2,
        { types.txin(types.outpoint(types.hash256(string.rep("\x12", 32)), 0),
                     "", 0xffffffff) },
        { types.txout(100000000, honest_spk) },
        0)
      local prev_txid = validation.compute_txid(prev_tx)
      local outer = types.transaction(2,
        { types.txin(types.outpoint(prev_txid, 0), "", 0xfffffffd) },
        { types.txout(99000000, honest_spk) },
        0)
      local p = psbt_mod.new(outer)
      p.inputs[1].non_witness_utxo = prev_tx
      -- Same value, different scriptPubKey.
      p.inputs[1].witness_utxo = {value = 100000000, script_pubkey = forged_spk}

      local ok, err = pcall(psbt_mod.sign_input, p, 0, privkey, pubkey)
      assert.is_false(ok)
      assert.is_truthy(tostring(err):find("CVE-2020-14199")
                    or tostring(err):find("witness_utxo disagrees"))
    end)

    it("sign_input still accepts honest agreement between both UTXO views", function()
      local privkey = crypto.sha256("lunarblock-w41-cve-honest-key")
      local pubkey = crypto.pubkey_from_privkey(privkey, true)
      local pkh = crypto.hash160(pubkey)
      local spk = script_mod.make_p2wpkh_script(pkh)

      local prev_tx = types.transaction(2,
        { types.txin(types.outpoint(types.hash256(string.rep("\x13", 32)), 0),
                     "", 0xffffffff) },
        { types.txout(100000000, spk) },
        0)
      local prev_txid = validation.compute_txid(prev_tx)
      local outer = types.transaction(2,
        { types.txin(types.outpoint(prev_txid, 0), "", 0xfffffffd) },
        { types.txout(99000000, spk) },
        0)
      local p = psbt_mod.new(outer)
      p.inputs[1].non_witness_utxo = prev_tx
      p.inputs[1].witness_utxo = {value = 100000000, script_pubkey = spk}

      local ok = psbt_mod.sign_input(p, 0, privkey, pubkey)
      assert.is_true(ok)
      assert.is_not_nil(next(p.inputs[1].partial_sigs))
    end)
  end)
end)
