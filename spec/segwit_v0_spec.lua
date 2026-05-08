-- spec/segwit_v0_spec.lua
--
-- Phase-2 segwit-v0 P2WSH wallet+PSBT signing tests (W28).
--
-- Covers:
--   1. PSBT P2WSH single-sig finalizer (preserves W19 behaviour).
--   2. PSBT P2WSH 2-of-3 multisig finalizer — witness stack shape is
--      [OP_0_dummy, sig1, sig2, witnessScript] with sigs ordered by canonical
--      witnessScript pubkey order (BIP-143 + Core ProduceSignature).
--   3. Raw-tx wallet.sign_input_p2wsh — same shape, plus pre-existing
--      single-key witnessScript path.
--   4. PSBT round-trip vs raw-tx signer: identical witness bytes.
--   5. signrawtransactionwithkey RPC produces a P2WSH 2-of-2 spend.
--
-- Reference:
--   bitcoin-core/src/script/sign.cpp::ProduceSignature
--   BIP-143 (segwit v0 sighash + P2WSH witness layout)

local function hex_to_bin(hex)
  return (hex:gsub('..', function(cc) return string.char(tonumber(cc, 16)) end))
end

local function bin_to_hex(bin)
  local hex = {}
  for i = 1, #bin do hex[i] = string.format("%02x", bin:byte(i)) end
  return table.concat(hex)
end

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

describe("segwit-v0 P2WSH signing (W28)", function()
  local crypto, script_mod, validation, types, consensus, serialize
  local wallet_mod, psbt_mod, rpc_mod, address_mod

  setup(function()
    setup_loader()
    crypto = require("lunarblock.crypto")
    script_mod = require("lunarblock.script")
    validation = require("lunarblock.validation")
    types = require("lunarblock.types")
    consensus = require("lunarblock.consensus")
    serialize = require("lunarblock.serialize")
    wallet_mod = require("lunarblock.wallet")
    psbt_mod = require("lunarblock.psbt")
    rpc_mod = require("lunarblock.rpc")
    address_mod = require("lunarblock.address")
  end)

  ----------------------------------------------------------------------------
  -- Helpers shared by the test cases below.
  ----------------------------------------------------------------------------

  -- Build an M-of-N CHECKMULTISIG witnessScript, byte-for-byte:
  --   OP_M <pk1> <pk2> ... <pkN> OP_N OP_CHECKMULTISIG
  local function build_multisig_script(m, pubkeys)
    local parts = {string.char(0x50 + m)}
    for _, pk in ipairs(pubkeys) do
      parts[#parts + 1] = string.char(#pk)  -- direct push (33 or 65)
      parts[#parts + 1] = pk
    end
    parts[#parts + 1] = string.char(0x50 + #pubkeys)
    parts[#parts + 1] = string.char(0xae)  -- OP_CHECKMULTISIG
    return table.concat(parts)
  end

  -- Build an unsigned tx with one input (spending `prev_txid:0`) and one
  -- P2WPKH-style output. Returns the tx object.
  local function build_unsigned_tx(prev_txid)
    return types.transaction(2,
      {types.txin(types.outpoint(prev_txid, 0), "", 0xFFFFFFFD)},
      {types.txout(99000000, "\x00\x14" .. string.rep("\xab", 20))},
      0)
  end

  ----------------------------------------------------------------------------
  -- 1. parse_multisig_script
  ----------------------------------------------------------------------------

  describe("script.parse_multisig_script", function()
    it("recognises a 2-of-3 CHECKMULTISIG witnessScript", function()
      local pks = {
        crypto.pubkey_from_privkey(crypto.sha256("k1"), true),
        crypto.pubkey_from_privkey(crypto.sha256("k2"), true),
        crypto.pubkey_from_privkey(crypto.sha256("k3"), true),
      }
      local ws = build_multisig_script(2, pks)
      local m, n, pubkeys = script_mod.parse_multisig_script(ws)
      assert.equals(2, m)
      assert.equals(3, n)
      assert.equals(3, #pubkeys)
      for i = 1, 3 do
        assert.equals(pks[i], pubkeys[i])
      end
    end)

    it("rejects a non-multisig witness script (single CHECKSIG)", function()
      local pk = crypto.pubkey_from_privkey(crypto.sha256("k"), true)
      -- `<pk> OP_CHECKSIG` (the bare single-key witnessScript shape)
      local ws = string.char(#pk) .. pk .. string.char(0xac)
      local m, n, pubkeys = script_mod.parse_multisig_script(ws)
      assert.is_nil(m)
      assert.is_nil(n)
      assert.is_nil(pubkeys)
    end)

    it("rejects a script with mismatched N", function()
      local pk = crypto.pubkey_from_privkey(crypto.sha256("k"), true)
      -- claims OP_2 ... OP_3 CHECKMULTISIG but only 1 pubkey: malformed
      local ws = string.char(0x52)              -- OP_2
        .. string.char(#pk) .. pk
        .. string.char(0x53)                    -- OP_3
        .. string.char(0xae)                    -- OP_CHECKMULTISIG
      local m = script_mod.parse_multisig_script(ws)
      assert.is_nil(m)
    end)
  end)

  ----------------------------------------------------------------------------
  -- 2. wallet.sign_input_p2wsh — shape tests
  ----------------------------------------------------------------------------

  describe("wallet.sign_input_p2wsh", function()
    it("single-key witness script: stack = [sig, witnessScript]", function()
      local priv = crypto.sha256("p2wsh-single-key-1")
      local pub = crypto.pubkey_from_privkey(priv, true)
      -- bare `<pubkey> OP_CHECKSIG`
      local ws = string.char(#pub) .. pub .. string.char(0xac)

      local prev_txid = types.hash256(string.rep("\x11", 32))
      local tx = build_unsigned_tx(prev_txid)

      local stack = wallet_mod.sign_input_p2wsh(
        tx, 0, ws, 100000000,
        {{privkey = priv, pubkey = pub}},
        consensus.SIGHASH.ALL)

      assert.is_table(stack)
      assert.equals(2, #stack)
      -- stack[1] = DER sig + sighash byte; verify it parses
      assert.is_true(#stack[1] > 8)
      assert.equals(consensus.SIGHASH.ALL, stack[1]:byte(#stack[1]))
      -- Verify against witnessScript-as-scriptCode sighash.
      local sighash = validation.signature_hash_segwit_v0(
        tx, 0, ws, 100000000, consensus.SIGHASH.ALL)
      local sig_der = stack[1]:sub(1, -2)
      assert.is_true(crypto.ecdsa_verify(pub, sig_der, sighash))
      -- stack[2] = witnessScript verbatim
      assert.equals(ws, stack[2])
    end)

    it("2-of-3 multisig: stack = [OP_0, sig1, sig2, witnessScript]", function()
      local priv1 = crypto.sha256("p2wsh-multi-key-1")
      local priv2 = crypto.sha256("p2wsh-multi-key-2")
      local priv3 = crypto.sha256("p2wsh-multi-key-3")
      local pub1 = crypto.pubkey_from_privkey(priv1, true)
      local pub2 = crypto.pubkey_from_privkey(priv2, true)
      local pub3 = crypto.pubkey_from_privkey(priv3, true)
      local ws = build_multisig_script(2, {pub1, pub2, pub3})

      local prev_txid = types.hash256(string.rep("\x22", 32))
      local tx = build_unsigned_tx(prev_txid)

      -- Sign with k1 + k2 (skip k3) — finalizer must produce sigs in
      -- canonical pubkey-list order, NOT in signKeys-arg order.
      local stack = wallet_mod.sign_input_p2wsh(
        tx, 0, ws, 100000000,
        {
          {privkey = priv1, pubkey = pub1},
          {privkey = priv2, pubkey = pub2},
        },
        consensus.SIGHASH.ALL)

      assert.is_table(stack)
      assert.equals(4, #stack)               -- dummy + 2 sigs + script
      assert.equals("", stack[1])            -- CHECKMULTISIG dummy
      assert.equals(ws, stack[4])

      local sighash = validation.signature_hash_segwit_v0(
        tx, 0, ws, 100000000, consensus.SIGHASH.ALL)

      -- sig at stack[2] verifies under pub1, sig at stack[3] under pub2.
      local sig1 = stack[2]:sub(1, -2)
      local sig2 = stack[3]:sub(1, -2)
      assert.equals(consensus.SIGHASH.ALL, stack[2]:byte(#stack[2]))
      assert.equals(consensus.SIGHASH.ALL, stack[3]:byte(#stack[3]))
      assert.is_true(crypto.ecdsa_verify(pub1, sig1, sighash))
      assert.is_true(crypto.ecdsa_verify(pub2, sig2, sighash))
    end)

    it("2-of-3 multisig: signKeys order does not affect canonical layout",
       function()
      -- Same script, but supply signers in (k3, k1) order. Result must put
      -- sig1 (the k1 sig) BEFORE sig3, since pubkeys are sorted in script.
      local priv1 = crypto.sha256("p2wsh-perm-key-1")
      local priv3 = crypto.sha256("p2wsh-perm-key-3")
      local pub1 = crypto.pubkey_from_privkey(priv1, true)
      local pub2 = crypto.pubkey_from_privkey(crypto.sha256("p2wsh-perm-key-2"), true)
      local pub3 = crypto.pubkey_from_privkey(priv3, true)
      local ws = build_multisig_script(2, {pub1, pub2, pub3})

      local prev_txid = types.hash256(string.rep("\x33", 32))
      local tx = build_unsigned_tx(prev_txid)

      local stack = wallet_mod.sign_input_p2wsh(
        tx, 0, ws, 100000000,
        {
          {privkey = priv3, pubkey = pub3},  -- supplied first
          {privkey = priv1, pubkey = pub1},  -- supplied second
        },
        consensus.SIGHASH.ALL)

      assert.is_table(stack)
      assert.equals(4, #stack)

      local sighash = validation.signature_hash_segwit_v0(
        tx, 0, ws, 100000000, consensus.SIGHASH.ALL)

      -- stack[2] must verify under pub1 (canonical order), not pub3.
      local sig_first = stack[2]:sub(1, -2)
      assert.is_true(crypto.ecdsa_verify(pub1, sig_first, sighash))
      assert.is_false(crypto.ecdsa_verify(pub3, sig_first, sighash))
      -- stack[3] must verify under pub3 (the only other signer we provided).
      local sig_second = stack[3]:sub(1, -2)
      assert.is_true(crypto.ecdsa_verify(pub3, sig_second, sighash))
    end)

    it("returns nil + error when fewer than M sigs are provided", function()
      local priv1 = crypto.sha256("p2wsh-short-1")
      local priv2 = crypto.sha256("p2wsh-short-2")
      local pub1 = crypto.pubkey_from_privkey(priv1, true)
      local pub2 = crypto.pubkey_from_privkey(priv2, true)
      local pub3 = crypto.pubkey_from_privkey(crypto.sha256("p2wsh-short-3"), true)
      local ws = build_multisig_script(2, {pub1, pub2, pub3})

      local prev_txid = types.hash256(string.rep("\x44", 32))
      local tx = build_unsigned_tx(prev_txid)

      -- Only one signing key for a 2-of-3.
      local stack, err = wallet_mod.sign_input_p2wsh(
        tx, 0, ws, 100000000,
        {{privkey = priv1, pubkey = pub1}},
        consensus.SIGHASH.ALL)
      assert.is_nil(stack)
      assert.is_string(err)
      assert.is_truthy(err:find("multisig"))
    end)
  end)

  ----------------------------------------------------------------------------
  -- 3. PSBT finalizer parity (multisig + single-sig)
  ----------------------------------------------------------------------------

  describe("psbt.finalize_input P2WSH", function()
    it("finalizes a 2-of-3 multisig with [OP_0, sig1, sig2, witnessScript]",
       function()
      local priv1 = crypto.sha256("psbt-multi-1")
      local priv2 = crypto.sha256("psbt-multi-2")
      local priv3 = crypto.sha256("psbt-multi-3")
      local pub1 = crypto.pubkey_from_privkey(priv1, true)
      local pub2 = crypto.pubkey_from_privkey(priv2, true)
      local pub3 = crypto.pubkey_from_privkey(priv3, true)
      local ws = build_multisig_script(2, {pub1, pub2, pub3})
      local ws_hash = crypto.sha256(ws)
      local p2wsh_spk = "\x00\x20" .. ws_hash

      local prev_txid = types.hash256(string.rep("\x55", 32))
      local tx = build_unsigned_tx(prev_txid)

      -- Build a PSBT with witness_utxo + witness_script populated for input 0.
      local p = psbt_mod.new(tx)
      p.inputs[1].witness_utxo = {value = 100000000, script_pubkey = p2wsh_spk}
      p.inputs[1].witness_script = ws

      -- Sign with k1 and k2 (skip k3).
      assert.is_true(psbt_mod.sign_input(p, 0, priv1, pub1))
      assert.is_true(psbt_mod.sign_input(p, 0, priv2, pub2))

      assert.is_true(psbt_mod.finalize_input(p, 0))
      local stack = p.inputs[1].final_script_witness
      assert.is_table(stack)
      assert.equals(4, #stack)
      assert.equals("", stack[1])              -- OP_0 dummy
      assert.equals(ws, stack[4])              -- witnessScript

      local sighash = validation.signature_hash_segwit_v0(
        tx, 0, ws, 100000000, consensus.SIGHASH.ALL)
      assert.is_true(crypto.ecdsa_verify(pub1, stack[2]:sub(1, -2), sighash))
      assert.is_true(crypto.ecdsa_verify(pub2, stack[3]:sub(1, -2), sighash))
    end)

    it("finalizes a single-key witness script with legacy [sig, pk, ws] shape",
       function()
      local priv = crypto.sha256("psbt-single-1")
      local pub = crypto.pubkey_from_privkey(priv, true)
      local ws = string.char(#pub) .. pub .. string.char(0xac)
      local ws_hash = crypto.sha256(ws)
      local p2wsh_spk = "\x00\x20" .. ws_hash

      local prev_txid = types.hash256(string.rep("\x66", 32))
      local tx = build_unsigned_tx(prev_txid)

      local p = psbt_mod.new(tx)
      p.inputs[1].witness_utxo = {value = 100000000, script_pubkey = p2wsh_spk}
      p.inputs[1].witness_script = ws

      assert.is_true(psbt_mod.sign_input(p, 0, priv, pub))
      assert.is_true(psbt_mod.finalize_input(p, 0))

      local stack = p.inputs[1].final_script_witness
      assert.is_table(stack)
      -- W19 single-sig template: [sig, pubkey, witnessScript]
      assert.equals(3, #stack)
      assert.equals(pub, stack[2])
      assert.equals(ws, stack[3])
    end)

    it("PSBT round-trip = raw-tx signer for 2-of-2 multisig", function()
      local priv1 = crypto.sha256("rt-multi-1")
      local priv2 = crypto.sha256("rt-multi-2")
      local pub1 = crypto.pubkey_from_privkey(priv1, true)
      local pub2 = crypto.pubkey_from_privkey(priv2, true)
      local ws = build_multisig_script(2, {pub1, pub2})
      local ws_hash = crypto.sha256(ws)
      local p2wsh_spk = "\x00\x20" .. ws_hash

      local prev_txid = types.hash256(string.rep("\x77", 32))
      local tx_a = build_unsigned_tx(prev_txid)
      local tx_b = build_unsigned_tx(prev_txid)

      -- (a) PSBT path
      local p = psbt_mod.new(tx_a)
      p.inputs[1].witness_utxo = {value = 100000000, script_pubkey = p2wsh_spk}
      p.inputs[1].witness_script = ws
      assert.is_true(psbt_mod.sign_input(p, 0, priv1, pub1))
      assert.is_true(psbt_mod.sign_input(p, 0, priv2, pub2))
      assert.is_true(psbt_mod.finalize_input(p, 0))
      local psbt_stack = p.inputs[1].final_script_witness

      -- (b) Raw-tx path
      local raw_stack = wallet_mod.sign_input_p2wsh(
        tx_b, 0, ws, 100000000,
        {
          {privkey = priv1, pubkey = pub1},
          {privkey = priv2, pubkey = pub2},
        },
        consensus.SIGHASH.ALL)

      -- Witness stacks must be byte-identical: same dummy element, same
      -- canonical sig order, same witnessScript.
      assert.equals(#psbt_stack, #raw_stack)
      for i = 1, #psbt_stack do
        assert.equals(psbt_stack[i], raw_stack[i],
          "stack[" .. i .. "] differs between PSBT and raw-tx paths")
      end
    end)
  end)

  ----------------------------------------------------------------------------
  -- 4. signrawtransactionwithkey RPC end-to-end
  ----------------------------------------------------------------------------

  describe("signrawtransactionwithkey P2WSH multisig dispatch", function()
    it("signs a 2-of-2 P2WSH input given matching keys + prevtxs", function()
      local server = rpc_mod.new({network = consensus.networks.regtest})

      local priv1 = crypto.sha256("rpc-p2wsh-1")
      local priv2 = crypto.sha256("rpc-p2wsh-2")
      local pub1 = crypto.pubkey_from_privkey(priv1, true)
      local pub2 = crypto.pubkey_from_privkey(priv2, true)
      local ws = build_multisig_script(2, {pub1, pub2})
      local ws_hash = crypto.sha256(ws)
      local p2wsh_spk = "\x00\x20" .. ws_hash

      local prev_txid = types.hash256(string.rep("\x88", 32))
      local tx = build_unsigned_tx(prev_txid)
      local hex_tx = bin_to_hex(serialize.serialize_transaction(tx, false))

      -- WIF-encode both privkeys for the regtest network.
      local function to_wif(priv)
        return address_mod.base58check_encode(
          consensus.networks.regtest.wif_prefix, priv .. "\x01")
      end

      local prevtxs = {{
        txid = types.hash256_hex(prev_txid),
        vout = 0,
        scriptPubKey = bin_to_hex(p2wsh_spk),
        witnessScript = bin_to_hex(ws),
        amount = 1.0,
      }}

      local result = server.methods["signrawtransactionwithkey"](
        server, {hex_tx, {to_wif(priv1), to_wif(priv2)}, prevtxs})

      assert.is_table(result)
      assert.is_true(result.complete,
        "expected complete=true; errors=" .. require("cjson").encode(result.errors or {}))
      assert.is_string(result.hex)
      assert.is_not.equals(hex_tx, result.hex)

      -- Decode the signed tx and inspect the witness stack on input 0.
      local signed_raw = hex_to_bin(result.hex)
      local signed_tx = serialize.deserialize_transaction(signed_raw)
      local witness = signed_tx.inputs[1].witness
      assert.is_table(witness)
      assert.equals(4, #witness)              -- [OP_0, sig1, sig2, ws]
      assert.equals("", witness[1])
      assert.equals(ws, witness[4])

      local sighash = validation.signature_hash_segwit_v0(
        tx, 0, ws, 100000000, consensus.SIGHASH.ALL)
      assert.is_true(crypto.ecdsa_verify(pub1, witness[2]:sub(1, -2), sighash))
      assert.is_true(crypto.ecdsa_verify(pub2, witness[3]:sub(1, -2), sighash))
    end)
  end)
end)
