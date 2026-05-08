-- W38: P2WSH commitment-check tests.
--
-- BIP-141 says scriptPubKey "OP_0 <h32>" is satisfied iff
-- sha256(witnessScript) == h32 (single sha256, NOT hash256).  Prior to W38,
-- lunarblock's PSBT signer + finalizer would happily sign or finalize against
-- a witness_script that didn't commit to the spk — Core then rejects the
-- transaction on the P2WSH hash-mismatch path of EvalScript but the partial
-- signature has already escaped, bound to whatever script the upstream
-- producer chose.  Same bug class as W31's P2SH gap; this completes the
-- segwit-v0 side.
--
-- Reference: bitcoin-core/src/script/sign.cpp ProduceSignature +
-- bitcoin-core/src/script/interpreter.cpp ExecuteWitnessProgram (P2WSH
-- branch).  The companion consensus call site in lunarblock is
-- src/script.lua:1785 (`crypto.sha256(witness_script)`).

-- Loader shim so spec can `require("lunarblock.X")` against src/X.lua,
-- mirroring spec/p2sh_commitment_spec.lua.
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

describe("P2WSH commitment check (BIP-141, W38)", function()
  local crypto, script_mod, types, psbt_mod

  setup(function()
    setup_loader()
    crypto = require("lunarblock.crypto")
    script_mod = require("lunarblock.script")
    types = require("lunarblock.types")
    psbt_mod = require("lunarblock.psbt")
  end)

  --------------------------------------------------------------------------
  -- crypto.verify_p2wsh_commitment helper
  --------------------------------------------------------------------------

  describe("crypto.verify_p2wsh_commitment", function()
    it("accepts a witness_script whose sha256 matches the spk hash", function()
      -- Build a single-key witnessScript: <pk> OP_CHECKSIG.  Asymmetric
      -- pubkey content (not all 0x02 / not 0x11-padded) so a palindromic
      -- spk byte order can't accidentally pass.
      local pk = crypto.pubkey_from_privkey(
        crypto.sha256("lunarblock-w38-helper-pk-honest"), true)
      assert.equals(33, #pk)
      local witness_script = "\x21" .. pk .. "\xac"
      assert.equals(35, #witness_script)
      local script_hash = crypto.sha256(witness_script)
      assert.equals(32, #script_hash)
      local spk = script_mod.make_p2wsh_script(script_hash)

      assert.is_true(crypto.verify_p2wsh_commitment(witness_script, spk))
    end)

    it("rejects a forged single-key witness_script", function()
      -- Honest commitment is to ws_a; attacker swaps in ws_b.  Asymmetric
      -- pubkeys, no palindromic 0x11/0x22 fixtures.
      local pk_a = crypto.pubkey_from_privkey(
        crypto.sha256("lunarblock-w38-helper-honest"), true)
      local pk_b = crypto.pubkey_from_privkey(
        crypto.sha256("lunarblock-w38-helper-forged"), true)
      assert.are_not.equal(pk_a, pk_b)
      local ws_a = "\x21" .. pk_a .. "\xac"
      local ws_b = "\x21" .. pk_b .. "\xac"
      local spk = script_mod.make_p2wsh_script(crypto.sha256(ws_a))

      assert.is_true(crypto.verify_p2wsh_commitment(ws_a, spk))
      assert.is_false(crypto.verify_p2wsh_commitment(ws_b, spk))
    end)

    it("rejects malformed scriptPubKey shapes", function()
      local pk = crypto.pubkey_from_privkey(
        crypto.sha256("lunarblock-w38-helper-shape"), true)
      local ws = "\x21" .. pk .. "\xac"
      local valid_spk = script_mod.make_p2wsh_script(crypto.sha256(ws))

      -- Sanity: the well-formed spk passes.
      assert.is_true(crypto.verify_p2wsh_commitment(ws, valid_spk))
      -- Too short.
      assert.is_false(crypto.verify_p2wsh_commitment(ws, "\x00\x20"))
      -- Right length, wrong opcodes (P2SH-shaped: a9 14 <20> 87 + padding
      -- to 34 bytes — clearly not a P2WSH spk).
      local p2sh_like = "\xa9\x14" .. string.rep("\x42", 20) .. "\x87"
                     .. string.rep("\x00", 34 - 23)
      assert.equals(34, #p2sh_like)
      assert.is_false(crypto.verify_p2wsh_commitment(ws, p2sh_like))
      -- Right length, wrong leading opcode (OP_1 = P2TR, not P2WSH).
      local p2tr_like = "\x51\x20" .. string.rep("\x42", 32)
      assert.is_false(crypto.verify_p2wsh_commitment(ws, p2tr_like))
      -- Right length, wrong push length byte (0x21 instead of 0x20).
      local bad_push = "\x00\x21" .. string.rep("\x42", 32)
      assert.is_false(crypto.verify_p2wsh_commitment(ws, bad_push))
      -- Right shape, but spk hash bytes differ from sha256(ws).
      local wrong_hash_spk = "\x00\x20" .. string.rep("\x42", 32)
      assert.is_false(crypto.verify_p2wsh_commitment(ws, wrong_hash_spk))
    end)

    it("rejects non-string args", function()
      local valid_spk = "\x00\x20" .. string.rep("\x42", 32)
      assert.is_false(crypto.verify_p2wsh_commitment(nil, valid_spk))
      assert.is_false(crypto.verify_p2wsh_commitment("\x51", nil))
      assert.is_false(crypto.verify_p2wsh_commitment(42, valid_spk))
    end)
  end)

  --------------------------------------------------------------------------
  -- psbt.sign_input — refuses to sign with a forged P2WSH witness_script
  --------------------------------------------------------------------------

  describe("psbt.sign_input rejects forged P2WSH witness_script", function()
    it("errors when sha256(witness_script) != spk[2:34]", function()
      local privkey = crypto.sha256("lunarblock-w38-psbt-sign-key")
      local pubkey = crypto.pubkey_from_privkey(privkey, true)

      -- Honest witnessScript: <pubkey> OP_CHECKSIG (single-key).  Bind spk
      -- to that, then attacker supplies a different witnessScript built
      -- around a foreign pubkey.
      local witness_script_honest = "\x21" .. pubkey .. "\xac"
      local spk = script_mod.make_p2wsh_script(
        crypto.sha256(witness_script_honest))

      local foreign_pk = crypto.pubkey_from_privkey(
        crypto.sha256("attacker-controlled-w38-key"), true)
      local witness_script_forged = "\x21" .. foreign_pk .. "\xac"

      -- Build a 1-in 1-out PSBT spending a fake outpoint.  Asymmetric prev
      -- bytes (not 0x11/0x22 fill).
      local fake_prev = types.hash256(
        "\x9c\x1d\x4f\xa3\x67\xb2\x58\x91"
       .."\x0e\x5a\xc4\x83\xd6\x71\x29\xee"
       .."\x42\x18\x6b\xf7\x05\xa9\xc2\x3d"
       .."\x84\x57\x60\x2b\x91\xfe\x0c\x37")
      local out_pkh = crypto.hash160(pubkey)
      local tx = types.transaction(2,
        { types.txin(types.outpoint(fake_prev, 0), "", 0xfffffffd) },
        { types.txout(99000000, script_mod.make_p2wpkh_script(out_pkh)) },
        0)
      local psbt = psbt_mod.new(tx)
      psbt.inputs[1].witness_utxo = {value = 100000000, script_pubkey = spk}
      psbt.inputs[1].witness_script = witness_script_forged

      local ok, err = pcall(psbt_mod.sign_input, psbt, 0, privkey, pubkey)
      assert.is_false(ok)
      assert.is_string(err or "")
      assert.is_truthy(tostring(err):find("sha256 mismatch")
                    or tostring(err):find("does not commit"))
      -- And no partial signature should have leaked.
      assert.is_nil(next(psbt.inputs[1].partial_sigs))
    end)

    it("still signs successfully when witness_script commits correctly",
    function()
      local privkey = crypto.sha256("lunarblock-w38-psbt-sign-key-good")
      local pubkey = crypto.pubkey_from_privkey(privkey, true)
      local witness_script = "\x21" .. pubkey .. "\xac"
      local spk = script_mod.make_p2wsh_script(crypto.sha256(witness_script))

      local fake_prev = types.hash256(
        "\x37\x0c\xfe\x91\x2b\x60\x57\x84"
       .."\x3d\xc2\xa9\x05\xf7\x6b\x18\x42"
       .."\xee\x29\x71\xd6\x83\xc4\x5a\x0e"
       .."\x91\x58\xb2\x67\xa3\x4f\x1d\x9c")
      local out_pkh = crypto.hash160(pubkey)
      local tx = types.transaction(2,
        { types.txin(types.outpoint(fake_prev, 0), "", 0xfffffffd) },
        { types.txout(99000000, script_mod.make_p2wpkh_script(out_pkh)) },
        0)
      local psbt = psbt_mod.new(tx)
      psbt.inputs[1].witness_utxo = {value = 100000000, script_pubkey = spk}
      psbt.inputs[1].witness_script = witness_script

      local ok = psbt_mod.sign_input(psbt, 0, privkey, pubkey)
      assert.is_true(ok)
      assert.is_not_nil(next(psbt.inputs[1].partial_sigs))
    end)
  end)

  --------------------------------------------------------------------------
  -- psbt.finalize_input — refuses to finalize with a forged witness_script
  --------------------------------------------------------------------------

  describe("psbt.finalize_input rejects forged P2WSH witness_script", function()
    it("errors when sha256(witness_script) != spk[2:34]", function()
      -- Honest: witnessScript = <pk_good> CHECKSIG; spk binds to it.
      -- Attacker swaps in <pk_bad> CHECKSIG (same shape, different pubkey).
      local pubkey_good = crypto.pubkey_from_privkey(
        crypto.sha256("lunarblock-w38-finalize-good"), true)
      local pubkey_bad = crypto.pubkey_from_privkey(
        crypto.sha256("lunarblock-w38-finalize-bad"), true)
      assert.are_not.equal(pubkey_good, pubkey_bad)

      local ws_honest = "\x21" .. pubkey_good .. "\xac"
      local ws_forged = "\x21" .. pubkey_bad  .. "\xac"
      local spk = script_mod.make_p2wsh_script(crypto.sha256(ws_honest))

      local fake_prev = types.hash256(
        "\x42\x18\x6b\xf7\x05\xa9\xc2\x3d"
       .."\x84\x57\x60\x2b\x91\xfe\x0c\x37"
       .."\x9c\x1d\x4f\xa3\x67\xb2\x58\x91"
       .."\x0e\x5a\xc4\x83\xd6\x71\x29\xee")
      local out_spk = "\x00\x14" .. crypto.hash160(pubkey_good)
      local tx = types.transaction(2,
        { types.txin(types.outpoint(fake_prev, 0), "", 0xfffffffd) },
        { types.txout(99000000, out_spk) },
        0)
      local psbt = psbt_mod.new(tx)
      psbt.inputs[1].witness_utxo = {value = 100000000, script_pubkey = spk}
      psbt.inputs[1].witness_script = ws_forged
      -- Inject a syntactically-valid partial sig so finalize reaches the
      -- P2WSH branch (the early "no signatures" return must not preempt).
      psbt.inputs[1].partial_sigs[
        (pubkey_bad:gsub(".", function(c)
          return string.format("%02x", c:byte()) end))
      ] = string.rep("\x30", 71) .. "\x01"

      local ok, err = pcall(psbt_mod.finalize_input, psbt, 0)
      assert.is_false(ok)
      assert.is_truthy(tostring(err):find("sha256 mismatch")
                    or tostring(err):find("does not commit"))
      assert.is_nil(psbt.inputs[1].final_script_sig)
      assert.is_nil(psbt.inputs[1].final_script_witness)
    end)
  end)
end)
