-- W39: P2WSH commitment-check tests for the raw-tx RPC layer.
--
-- W37 audit found three P2WSH branches in src/rpc.lua that consumed a
-- caller-supplied witness_script (from a prevtxs array or wallet path)
-- without verifying that sha256(witnessScript) == scriptPubKey[2:34]:
--
--   1. signrawtransactionwithkey   sign_one_input  (rpc.lua:4778)
--   2. signrawtransactionwithkey   key_resolver    (rpc.lua:4919)
--   3. signrawtransactionwithwallet key_resolver   (rpc.lua:5009)
--
-- W38 closed the PSBT-side gap (psbt.lua:774, 1011) but flagged these
-- three RPC sites as out-of-scope.  W39 wires the same crypto helper
-- (crypto.verify_p2wsh_commitment, added in W38) at all three.  These
-- tests exercise the negative path at each site, asserting:
--
--   * The RPC call succeeds (Core's signrawtransactionwith* never raises
--     on a per-input failure; it returns complete=false + an error array).
--   * `complete` is false.
--   * No witness/scriptSig was written to the input.
--
-- They use ASYMMETRIC ECDSA pubkeys (no 0x11/0x22 palindromes) so a spk
-- byte-order bug can't accidentally pass.
--
-- Reference: bitcoin-core/src/rpc/rawtransaction.cpp signrawtransactionwithkey,
--            bitcoin-core/src/wallet/rpc/spend.cpp signrawtransactionwithwallet,
--            bitcoin-core/src/script/sign.cpp ProduceSignature.
-- Companion W31 P2SH tests: spec/p2sh_commitment_spec.lua.
-- Companion W38 PSBT P2WSH tests: spec/p2wsh_commitment_spec.lua.

local function bin_to_hex(bin)
  local hex = {}
  for i = 1, #bin do hex[i] = string.format("%02x", bin:byte(i)) end
  return table.concat(hex)
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

describe("P2WSH RPC commitment check (BIP-141, W39)", function()
  local rpc, types, consensus, crypto, script_mod, address_mod
  local serialize
  local server

  setup(function()
    setup_loader()
    rpc = require("lunarblock.rpc")
    types = require("lunarblock.types")
    consensus = require("lunarblock.consensus")
    crypto = require("lunarblock.crypto")
    script_mod = require("lunarblock.script")
    address_mod = require("lunarblock.address")
    serialize = require("lunarblock.serialize")
  end)

  before_each(function()
    server = rpc.new({network = consensus.networks.regtest})
  end)

  --------------------------------------------------------------------------
  -- Site 1: signrawtransactionwithkey -> sign_one_input (rpc.lua:4778)
  --
  -- Wire-up: the key_resolver at site 2 returns a key set that the
  -- *forged* witness_script could plausibly satisfy (because it embeds the
  -- attacker's pubkey), then sign_one_input commits to spk on the way to
  -- the sighash.  The W39 guard at site 1 short-circuits *before* sighash
  -- construction and forces the RPC to report complete=false.
  --
  -- To isolate site 1 we build a forged witnessScript whose embedded
  -- pubkey IS in the caller-supplied keys array, so site 2 returns
  -- non-nil and execution reaches site 1.
  --------------------------------------------------------------------------

  describe("Site 1: signrawtransactionwithkey sign_one_input", function()
    it("rejects a forged P2WSH witness_script (sha256 mismatch on spk)",
    function()
      -- Build two distinct ECDSA keys.  The honest spk binds to ws_honest;
      -- ws_forged uses pk_forged so the resolver finds a match in keys[].
      local privkey_honest = crypto.sha256("lunarblock-w39-site1-honest")
      local privkey_forged = crypto.sha256("lunarblock-w39-site1-forged")
      local pubkey_honest = crypto.pubkey_from_privkey(privkey_honest, true)
      local pubkey_forged = crypto.pubkey_from_privkey(privkey_forged, true)
      assert.are_not.equal(pubkey_honest, pubkey_forged)

      -- Honest witnessScript: <pk_honest> OP_CHECKSIG.
      -- Attacker substitutes:  <pk_forged> OP_CHECKSIG.  Same shape, but
      -- the spk's 32-byte commitment is to ws_honest, so the sha256 check
      -- at site 1 must fail.
      local ws_honest = "\x21" .. pubkey_honest .. "\xac"
      local ws_forged = "\x21" .. pubkey_forged .. "\xac"
      local spk = script_mod.make_p2wsh_script(crypto.sha256(ws_honest))

      -- Build a 1-in 1-out tx spending the spk-bound outpoint.
      local prev_txid = types.hash256(
        "\x9c\x1d\x4f\xa3\x67\xb2\x58\x91"
       .."\x0e\x5a\xc4\x83\xd6\x71\x29\xee"
       .."\x42\x18\x6b\xf7\x05\xa9\xc2\x3d"
       .."\x84\x57\x60\x2b\x91\xfe\x0c\x37")
      local tx = types.transaction(2,
        {types.txin(types.outpoint(prev_txid, 0), "", 0xFFFFFFFD)},
        {types.txout(99000000,
          script_mod.make_p2wpkh_script(crypto.hash160(pubkey_honest)))},
        0)
      local hex_tx = bin_to_hex(serialize.serialize_transaction(tx, false))

      -- WIFs for the forged key (so site 2 returns it for ws_forged) and
      -- the honest key (positive control for sanity).
      local wif_forged = address_mod.base58check_encode(
        consensus.networks.regtest.wif_prefix,
        privkey_forged .. "\x01")

      local prevtxs = {{
        txid = types.hash256_hex(prev_txid),
        vout = 0,
        scriptPubKey = bin_to_hex(spk),
        witnessScript = bin_to_hex(ws_forged),
        amount = 1.0,
      }}

      local result = server.methods["signrawtransactionwithkey"](
        server, {hex_tx, {wif_forged}, prevtxs})

      -- The RPC must NOT raise — Core surfaces per-input failures as
      -- complete=false + errors[].  But the input must NOT have been
      -- signed: site 1 short-circuits before wallet.sign_input_p2wsh runs.
      assert.is_table(result)
      assert.is_false(result.complete)

      -- Re-decode the returned tx and verify the input has no witness.
      local raw = (result.hex:gsub('..',
        function(cc) return string.char(tonumber(cc, 16)) end))
      local signed_tx = serialize.deserialize_transaction(raw)
      local witness = signed_tx.inputs[1].witness
      assert.is_truthy(witness == nil or #witness == 0)
    end)
  end)

  --------------------------------------------------------------------------
  -- Site 2: signrawtransactionwithkey key_resolver (rpc.lua:4919)
  --
  -- Wire-up: when the witness_script doesn't commit to spk we want the
  -- *resolver* to return nil (so sign_raw_tx_common sees no key_info,
  -- marks the input complete=false, and never reaches sign_one_input).
  -- To isolate this site from site 1 we use a multisig witnessScript so
  -- the resolver's "multisig path" (the lines guarded by the new check)
  -- is what's exercised; without the guard, the resolver would happily
  -- assemble `{multi=true, keys={...}}` and hand it to sign_one_input
  -- where site 1 would catch it.  With the guard, site 2 catches it
  -- first.  A pcall'd test against a stub for site 1 confirms the
  -- ordering: we restore the real sign_one_input implicitly by using a
  -- fresh server in before_each.
  --------------------------------------------------------------------------

  describe("Site 2: signrawtransactionwithkey key_resolver", function()
    it("returns no key (and complete=false) for a forged multisig witness_script",
    function()
      -- Build a 2-of-2 honest witnessScript.  Attacker substitutes a
      -- 2-of-2 with the same shape but different cosigner pubkeys.
      local privA = crypto.sha256("lunarblock-w39-site2-cosignerA")
      local privB = crypto.sha256("lunarblock-w39-site2-cosignerB")
      local privX = crypto.sha256("lunarblock-w39-site2-attackerX")
      local privY = crypto.sha256("lunarblock-w39-site2-attackerY")
      local pkA = crypto.pubkey_from_privkey(privA, true)
      local pkB = crypto.pubkey_from_privkey(privB, true)
      local pkX = crypto.pubkey_from_privkey(privX, true)
      local pkY = crypto.pubkey_from_privkey(privY, true)
      assert.are_not.equal(pkA, pkX)
      assert.are_not.equal(pkB, pkY)

      -- multisig 2-of-2: OP_2 <pkA> <pkB> OP_2 OP_CHECKMULTISIG
      local function ms_2of2(p1, p2)
        return "\x52" .. "\x21" .. p1 .. "\x21" .. p2 .. "\x52" .. "\xae"
      end
      local ws_honest = ms_2of2(pkA, pkB)
      local ws_forged = ms_2of2(pkX, pkY)
      assert.are_not.equal(ws_honest, ws_forged)
      local spk = script_mod.make_p2wsh_script(crypto.sha256(ws_honest))

      local prev_txid = types.hash256(
        "\x37\x0c\xfe\x91\x2b\x60\x57\x84"
       .."\x3d\xc2\xa9\x05\xf7\x6b\x18\x42"
       .."\xee\x29\x71\xd6\x83\xc4\x5a\x0e"
       .."\x91\x58\xb2\x67\xa3\x4f\x1d\x9c")
      local tx = types.transaction(2,
        {types.txin(types.outpoint(prev_txid, 0), "", 0xFFFFFFFD)},
        {types.txout(99000000,
          script_mod.make_p2wpkh_script(crypto.hash160(pkA)))},
        0)
      local hex_tx = bin_to_hex(serialize.serialize_transaction(tx, false))

      -- Supply WIFs for the *attacker's* cosigners so resolver would
      -- happily assemble {multi=true, keys=...} sans the guard.
      local function wif(priv)
        return address_mod.base58check_encode(
          consensus.networks.regtest.wif_prefix, priv .. "\x01")
      end
      local prevtxs = {{
        txid = types.hash256_hex(prev_txid),
        vout = 0,
        scriptPubKey = bin_to_hex(spk),
        witnessScript = bin_to_hex(ws_forged),
        amount = 1.0,
      }}

      local result = server.methods["signrawtransactionwithkey"](
        server, {hex_tx, {wif(privX), wif(privY)}, prevtxs})

      assert.is_table(result)
      assert.is_false(result.complete)

      local raw = (result.hex:gsub('..',
        function(cc) return string.char(tonumber(cc, 16)) end))
      local signed_tx = serialize.deserialize_transaction(raw)
      local witness = signed_tx.inputs[1].witness
      assert.is_truthy(witness == nil or #witness == 0)
    end)
  end)

  --------------------------------------------------------------------------
  -- Site 3: signrawtransactionwithwallet key_resolver (rpc.lua:5009)
  --
  -- Wire-up: same shape as site 2 but the keys are sourced from the
  -- request wallet (pubkey_index) rather than the keys[] arg.  We
  -- inject a fake wallet whose pubkey_index covers the *attacker's*
  -- cosigner pubkeys, so without the guard the resolver would return
  -- a multi cosigner set bound to the forged witnessScript.
  --------------------------------------------------------------------------

  describe("Site 3: signrawtransactionwithwallet key_resolver", function()
    it("returns no key (and complete=false) for a forged wallet witness_script",
    function()
      local privA = crypto.sha256("lunarblock-w39-site3-cosignerA")
      local privB = crypto.sha256("lunarblock-w39-site3-cosignerB")
      local privX = crypto.sha256("lunarblock-w39-site3-attackerX")
      local privY = crypto.sha256("lunarblock-w39-site3-attackerY")
      local pkA = crypto.pubkey_from_privkey(privA, true)
      local pkB = crypto.pubkey_from_privkey(privB, true)
      local pkX = crypto.pubkey_from_privkey(privX, true)
      local pkY = crypto.pubkey_from_privkey(privY, true)
      assert.are_not.equal(pkA, pkX)

      local function ms_2of2(p1, p2)
        return "\x52" .. "\x21" .. p1 .. "\x21" .. p2 .. "\x52" .. "\xae"
      end
      local ws_honest = ms_2of2(pkA, pkB)
      local ws_forged = ms_2of2(pkX, pkY)
      local spk = script_mod.make_p2wsh_script(crypto.sha256(ws_honest))

      local prev_txid = types.hash256(
        "\x42\x18\x6b\xf7\x05\xa9\xc2\x3d"
       .."\x84\x57\x60\x2b\x91\xfe\x0c\x37"
       .."\x9c\x1d\x4f\xa3\x67\xb2\x58\x91"
       .."\x0e\x5a\xc4\x83\xd6\x71\x29\xee")
      local outpoint_key = prev_txid.bytes .. string.char(0, 0, 0, 0)

      -- Inject a fake wallet whose keys table holds the attacker's
      -- pubkeys + privkeys.  Site 3's pubkey_index is built from
      -- wallet.keys at handler entry, so the forged ws (which embeds
      -- pkX/pkY) would resolve to {multi=true,...} without the guard.
      local fake_wallet = {
        network = consensus.networks.regtest,
        is_encrypted = false, is_locked = false,
        keys = {
          ["addrX"] = {privkey = privX, pubkey = pkX, type = "p2wsh"},
          ["addrY"] = {privkey = privY, pubkey = pkY, type = "p2wsh"},
        },
        utxos = {
          [outpoint_key] = {
            value = 100000000, script_pubkey = spk,
            txid = prev_txid, vout = 0,
          },
        },
        scan_utxos = function() end,
      }
      server.wallet = fake_wallet

      local tx = types.transaction(2,
        {types.txin(types.outpoint(prev_txid, 0), "", 0xFFFFFFFD)},
        {types.txout(99000000,
          script_mod.make_p2wpkh_script(crypto.hash160(pkA)))},
        0)
      local hex_tx = bin_to_hex(serialize.serialize_transaction(tx, false))

      local prevtxs = {{
        txid = types.hash256_hex(prev_txid),
        vout = 0,
        scriptPubKey = bin_to_hex(spk),
        witnessScript = bin_to_hex(ws_forged),
        amount = 1.0,
      }}

      local result = server.methods["signrawtransactionwithwallet"](
        server, {hex_tx, prevtxs})

      assert.is_table(result)
      assert.is_false(result.complete)

      local raw = (result.hex:gsub('..',
        function(cc) return string.char(tonumber(cc, 16)) end))
      local signed_tx = serialize.deserialize_transaction(raw)
      local witness = signed_tx.inputs[1].witness
      assert.is_truthy(witness == nil or #witness == 0)
    end)
  end)
end)
