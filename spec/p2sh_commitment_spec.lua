-- W31: P2SH commitment-check tests.
--
-- BIP-16 says scriptPubKey "OP_HASH160 <h20> OP_EQUAL" is satisfied iff
-- hash160(redeemScript) == h20.  Prior to W31, lunarblock's PSBT signer +
-- finalizer + the wallet/key signrawtransactionwithkey path would happily
-- sign or finalize against a redeem_script that didn't commit to the spk
-- — Core then rejects the transaction at script-eval time but the partial
-- signature has already escaped, bound to whatever script the upstream
-- producer chose.
--
-- Reference: bitcoin-core/src/script/sign.cpp ProduceSignature +
-- bitcoin-core/src/script/interpreter.cpp EvalScript (P2SH branch).

local function hex_to_bin(hex)
  return (hex:gsub('..', function(cc) return string.char(tonumber(cc, 16)) end))
end

-- Loader shim so spec can `require("lunarblock.X")` against src/X.lua,
-- mirroring spec/wallet_signing_rpc_spec.lua.
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

describe("P2SH commitment check (BIP-16, W31)", function()
  local crypto, script_mod, types, psbt_mod

  setup(function()
    setup_loader()
    crypto = require("lunarblock.crypto")
    script_mod = require("lunarblock.script")
    types = require("lunarblock.types")
    psbt_mod = require("lunarblock.psbt")
  end)

  --------------------------------------------------------------------------
  -- crypto.verify_p2sh_commitment helper
  --------------------------------------------------------------------------

  describe("crypto.verify_p2sh_commitment", function()
    it("accepts a redeem_script whose hash160 matches the spk hash", function()
      -- Build a P2SH-P2WPKH redeem script for an arbitrary 20-byte pkh.
      local pkh = crypto.hash160("lunarblock-w31-key-positive")  -- 20 bytes
      assert.equals(20, #pkh)
      local redeem = script_mod.make_p2wpkh_script(pkh)
      local script_hash = crypto.hash160(redeem)
      local spk = script_mod.make_p2sh_script(script_hash)

      assert.is_true(crypto.verify_p2sh_commitment(redeem, spk))
    end)

    it("rejects a forged P2SH-P2WPKH redeem_script", function()
      -- Honest commitment is to redeem_a; attacker swaps in redeem_b.
      local pkh_a = crypto.hash160("lunarblock-w31-honest-key")
      local pkh_b = crypto.hash160("lunarblock-w31-forged-key")
      local redeem_a = script_mod.make_p2wpkh_script(pkh_a)
      local redeem_b = script_mod.make_p2wpkh_script(pkh_b)
      local spk = script_mod.make_p2sh_script(crypto.hash160(redeem_a))

      assert.is_true(crypto.verify_p2sh_commitment(redeem_a, spk))
      assert.is_false(crypto.verify_p2sh_commitment(redeem_b, spk))
    end)

    it("rejects a forged pure-P2SH redeem_script", function()
      -- Honest pure-P2SH redeem (e.g. <pk> OP_CHECKSIG).  Attacker proposes
      -- a different one.
      local honest = "\x21" .. string.rep("\x02", 33) .. "\xac"  -- 35 bytes
      local forged = "\x21" .. string.rep("\x03", 33) .. "\xac"
      local spk = script_mod.make_p2sh_script(crypto.hash160(honest))

      assert.is_true(crypto.verify_p2sh_commitment(honest, spk))
      assert.is_false(crypto.verify_p2sh_commitment(forged, spk))
    end)

    it("rejects malformed scriptPubKey shapes", function()
      local redeem = "\x51"  -- OP_TRUE
      -- Too short.
      assert.is_false(crypto.verify_p2sh_commitment(redeem, "\xa9\x14"))
      -- Right length, wrong opcodes (P2WSH-shaped: 00 20 <32>).
      local p2wsh_like = "\x00\x20" .. string.rep("\x00", 32)
      assert.is_false(crypto.verify_p2sh_commitment(redeem, p2wsh_like))
      -- Right length, missing trailing OP_EQUAL (0x87).
      local bad_tail = "\xa9\x14" .. string.rep("\x00", 20) .. "\x88"
      assert.is_false(crypto.verify_p2sh_commitment(redeem, bad_tail))
    end)
  end)

  --------------------------------------------------------------------------
  -- psbt.sign_input — refuses to sign with a forged P2SH-P2WPKH redeem
  --------------------------------------------------------------------------

  describe("psbt.sign_input rejects forged P2SH-P2WPKH redeem", function()
    it("errors when hash160(redeem) != spk[2:22]", function()
      local privkey = crypto.sha256("lunarblock-w31-psbt-sign-key")
      local pubkey = crypto.pubkey_from_privkey(privkey, true)
      local pkh = crypto.hash160(pubkey)

      -- Honest commitment: spk binds to redeem_honest.
      local redeem_honest = script_mod.make_p2wpkh_script(pkh)
      local spk = script_mod.make_p2sh_script(crypto.hash160(redeem_honest))

      -- Attacker-supplied redeem_script: same shape, wrong pkh.
      local forged_pkh = crypto.hash160("attacker-controlled-key")
      local redeem_forged = script_mod.make_p2wpkh_script(forged_pkh)

      -- Build a 1-in 1-out PSBT spending a fake outpoint.
      local fake_prev = types.hash256(string.rep("\x77", 32))
      local tx = types.transaction(2,
        { types.txin(types.outpoint(fake_prev, 0), "", 0xfffffffd) },
        { types.txout(99000000, script_mod.make_p2wpkh_script(pkh)) },
        0)
      local psbt = psbt_mod.new(tx)
      psbt.inputs[1].witness_utxo = {value = 100000000, script_pubkey = spk}
      psbt.inputs[1].redeem_script = redeem_forged

      local ok, err = pcall(psbt_mod.sign_input, psbt, 0, privkey, pubkey)
      assert.is_false(ok)
      assert.is_string(err or "")
      assert.is_truthy(tostring(err):find("hash160 mismatch")
                    or tostring(err):find("does not commit"))
      -- And no partial signature should have leaked.
      assert.is_nil(next(psbt.inputs[1].partial_sigs))
    end)

    it("still signs successfully when redeem commits correctly", function()
      local privkey = crypto.sha256("lunarblock-w31-psbt-sign-key-good")
      local pubkey = crypto.pubkey_from_privkey(privkey, true)
      local pkh = crypto.hash160(pubkey)
      local redeem = script_mod.make_p2wpkh_script(pkh)
      local spk = script_mod.make_p2sh_script(crypto.hash160(redeem))

      local fake_prev = types.hash256(string.rep("\x77", 32))
      local tx = types.transaction(2,
        { types.txin(types.outpoint(fake_prev, 0), "", 0xfffffffd) },
        { types.txout(99000000, script_mod.make_p2wpkh_script(pkh)) },
        0)
      local psbt = psbt_mod.new(tx)
      psbt.inputs[1].witness_utxo = {value = 100000000, script_pubkey = spk}
      psbt.inputs[1].redeem_script = redeem

      local ok = psbt_mod.sign_input(psbt, 0, privkey, pubkey)
      assert.is_true(ok)
      assert.is_not_nil(next(psbt.inputs[1].partial_sigs))
    end)
  end)

  --------------------------------------------------------------------------
  -- psbt.finalize_input — refuses to finalize a pure-P2SH with forged redeem
  --------------------------------------------------------------------------

  describe("psbt.finalize_input rejects forged pure-P2SH redeem", function()
    it("errors when hash160(redeem) != spk[2:22] for pure P2SH", function()
      -- Honest: redeem is a 1-of-1 <pk> CHECKSIG; the P2SH spk binds to it.
      -- Attacker swaps in a different <pk'> CHECKSIG with the same shape.
      local pubkey_good = crypto.pubkey_from_privkey(
        crypto.sha256("lunarblock-w31-finalize-good"), true)
      local pubkey_bad = crypto.pubkey_from_privkey(
        crypto.sha256("lunarblock-w31-finalize-bad"), true)

      local redeem_honest = "\x21" .. pubkey_good .. "\xac"  -- <pk> CHECKSIG
      local redeem_forged = "\x21" .. pubkey_bad  .. "\xac"
      local spk = script_mod.make_p2sh_script(crypto.hash160(redeem_honest))

      local fake_prev = types.hash256(string.rep("\x88", 32))
      local tx = types.transaction(2,
        { types.txin(types.outpoint(fake_prev, 0), "", 0xfffffffd) },
        { types.txout(99000000, "\x00\x14" .. string.rep("\x02", 20)) },
        0)
      local psbt = psbt_mod.new(tx)
      psbt.inputs[1].witness_utxo = {value = 100000000, script_pubkey = spk}
      psbt.inputs[1].redeem_script = redeem_forged
      -- Inject a syntactically-valid partial sig so finalize reaches the
      -- P2SH branch (the early "no signatures" return must not preempt).
      psbt.inputs[1].partial_sigs[
        (pubkey_bad:gsub(".", function(c)
          return string.format("%02x", c:byte()) end))
      ] = string.rep("\x30", 71) .. "\x01"

      local ok, err = pcall(psbt_mod.finalize_input, psbt, 0)
      assert.is_false(ok)
      assert.is_truthy(tostring(err):find("hash160 mismatch")
                    or tostring(err):find("does not commit"))
      assert.is_nil(psbt.inputs[1].final_script_sig)
      assert.is_nil(psbt.inputs[1].final_script_witness)
    end)
  end)
end)
