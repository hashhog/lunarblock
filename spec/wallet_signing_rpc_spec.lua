-- Wallet wave: signrawtransactionwithwallet, signrawtransactionwithkey,
-- and walletcreatefundedpsbt RPC handler tests.
--
-- The handlers under test were added in the wallet wave; previously
-- lunarblock shipped psbt.sign_input + HD-derive primitives but no RPC
-- registration for the three Core-mainstream entry points.
--
-- Reference: bitcoin-core/src/rpc/rawtransaction.cpp signrawtransactionwithkey,
--            bitcoin-core/src/wallet/rpc/spend.cpp  signrawtransactionwithwallet,
--                                                 walletcreatefundedpsbt.

local function hex_to_bin(hex)
  return (hex:gsub('..', function(cc) return string.char(tonumber(cc, 16)) end))
end

local function bin_to_hex(bin)
  local hex = {}
  for i = 1, #bin do hex[i] = string.format("%02x", bin:byte(i)) end
  return table.concat(hex)
end

-- Allow `require("lunarblock.X")` to resolve src/X.lua.  Mirrors the loader
-- shim used in spec/wallet_spec.lua.
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

describe("wallet signing RPCs", function()
  local rpc, types, consensus, crypto, script_mod, address_mod
  local wallet_mod, serialize, psbt_mod
  local server

  setup(function()
    setup_loader()
    rpc = require("lunarblock.rpc")
    types = require("lunarblock.types")
    consensus = require("lunarblock.consensus")
    crypto = require("lunarblock.crypto")
    script_mod = require("lunarblock.script")
    address_mod = require("lunarblock.address")
    wallet_mod = require("lunarblock.wallet")
    serialize = require("lunarblock.serialize")
    psbt_mod = require("lunarblock.psbt")
  end)

  before_each(function()
    server = rpc.new({network = consensus.networks.regtest})
  end)

  describe("registration", function()
    it("registers signrawtransactionwithwallet", function()
      assert.is_function(server.methods["signrawtransactionwithwallet"])
    end)

    it("registers signrawtransactionwithkey", function()
      assert.is_function(server.methods["signrawtransactionwithkey"])
    end)

    it("registers walletcreatefundedpsbt", function()
      assert.is_function(server.methods["walletcreatefundedpsbt"])
    end)
  end)

  describe("signrawtransactionwithkey", function()
    it("rejects malformed params", function()
      local ok, err = pcall(server.methods["signrawtransactionwithkey"],
        server, {})
      assert.is_false(ok)
      assert.is_table(err)
      assert.equals(rpc.ERROR.INVALID_PARAMS, err.code)
    end)

    it("rejects when keys arg is not an array", function()
      local ok, err = pcall(server.methods["signrawtransactionwithkey"],
        server, {"deadbeef", "not-an-array"})
      assert.is_false(ok)
      assert.is_table(err)
      assert.equals(rpc.ERROR.INVALID_PARAMS, err.code)
    end)

    it("signs a P2WPKH input given matching key + prevtx", function()
      -- Generate a key, derive its P2WPKH SPK + address.
      local privkey = crypto.sha256("lunarblock-wallet-wave-test-key-1")
      local pubkey = crypto.pubkey_from_privkey(privkey, true)
      local pkh = crypto.hash160(pubkey)
      local spk = script_mod.make_p2wpkh_script(pkh)

      -- Build an unsigned tx spending a fake outpoint (1 BTC -> 0.999 BTC).
      local prev_txid = types.hash256(string.rep("\x42", 32))
      local tx = types.transaction(2,
        {types.txin(types.outpoint(prev_txid, 0), "", 0xFFFFFFFD)},
        {types.txout(99900000, "\x00\x14" .. string.rep("\x33", 20))},
        0)

      local hex_tx = bin_to_hex(serialize.serialize_transaction(tx, false))

      -- Encode privkey as WIF for the regtest network.
      local wif = address_mod.base58check_encode(
        consensus.networks.regtest.wif_prefix,
        privkey .. "\x01")

      local prevtxs = {{
        txid = types.hash256_hex(prev_txid),
        vout = 0,
        scriptPubKey = bin_to_hex(spk),
        amount = 1.0,
      }}

      local result = server.methods["signrawtransactionwithkey"](
        server, {hex_tx, {wif}, prevtxs})

      assert.is_table(result)
      assert.is_string(result.hex)
      assert.is_true(result.complete)
      -- Hex should differ from input now that we wrote a witness.
      assert.is_not.equals(hex_tx, result.hex)
    end)
  end)

  describe("signrawtransactionwithwallet", function()
    it("errors when no wallet is loaded", function()
      local ok, err = pcall(server.methods["signrawtransactionwithwallet"],
        server, {"deadbeef"})
      assert.is_false(ok)
      assert.is_table(err)
      assert.equals(rpc.ERROR.WALLET_ERROR, err.code)
    end)

    it("signs using a wallet-bound key matching the prevout SPK", function()
      -- Build a minimal wallet with one key and one UTXO.
      local privkey = crypto.sha256("lunarblock-wallet-wave-test-key-2")
      local pubkey = crypto.pubkey_from_privkey(privkey, true)
      local pkh = crypto.hash160(pubkey)
      local spk = script_mod.make_p2wpkh_script(pkh)
      local addr = address_mod.pubkey_to_p2wpkh(pubkey, "regtest")

      local fake_wallet = {
        network = consensus.networks.regtest,
        is_encrypted = false,
        is_locked = false,
        keys = {[addr] = {privkey = privkey, pubkey = pubkey, type = "p2wpkh"}},
        utxos = {},
        scan_utxos = function() end,  -- no-op when chain_state==nil
      }

      -- Inject the UTXO so resolve_prevout finds it.
      local prev_txid = types.hash256(string.rep("\x55", 32))
      local outpoint_key = prev_txid.bytes .. string.char(0, 0, 0, 0)
      fake_wallet.utxos[outpoint_key] = {
        value = 50000000, script_pubkey = spk, address = addr,
        txid = prev_txid, vout = 0,
      }

      server.wallet = fake_wallet  -- legacy single-wallet field

      local tx = types.transaction(2,
        {types.txin(types.outpoint(prev_txid, 0), "", 0xFFFFFFFD)},
        {types.txout(49900000, "\x00\x14" .. string.rep("\x44", 20))},
        0)
      local hex_tx = bin_to_hex(serialize.serialize_transaction(tx, false))

      local result = server.methods["signrawtransactionwithwallet"](
        server, {hex_tx})

      assert.is_table(result)
      assert.is_true(result.complete)
      assert.is_string(result.hex)
    end)
  end)

  describe("walletcreatefundedpsbt", function()
    it("errors when no wallet is loaded", function()
      local ok, err = pcall(server.methods["walletcreatefundedpsbt"],
        server, {{}, {{["bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3xueyj"] = 0.001}}})
      assert.is_false(ok)
      assert.is_table(err)
      assert.equals(rpc.ERROR.WALLET_ERROR, err.code)
    end)

    it("rejects invalid outputs arg", function()
      server.wallet = {
        network = consensus.networks.regtest,
        utxos = {}, keys = {},
        scan_utxos = function() end,
        estimate_fee_rate = function() return 1 end,
      }
      local ok, err = pcall(server.methods["walletcreatefundedpsbt"],
        server, {{}, "not-an-array"})
      assert.is_false(ok)
      assert.is_table(err)
      assert.equals(rpc.ERROR.INVALID_PARAMS, err.code)
    end)

    it("builds a funded PSBT when wallet has a UTXO covering the output", function()
      -- Stand up a fake wallet with one P2WPKH UTXO worth 1 BTC.
      local privkey = crypto.sha256("lunarblock-wallet-wave-test-key-3")
      local pubkey = crypto.pubkey_from_privkey(privkey, true)
      local pkh = crypto.hash160(pubkey)
      local spk = script_mod.make_p2wpkh_script(pkh)
      local addr = address_mod.pubkey_to_p2wpkh(pubkey, "regtest")

      local prev_txid = types.hash256(string.rep("\x66", 32))
      local outpoint_key = prev_txid.bytes .. string.char(0, 0, 0, 0)

      local fake_wallet = {
        network = consensus.networks.regtest,
        is_encrypted = false, is_locked = false,
        keys = {[addr] = {privkey = privkey, pubkey = pubkey, type = "p2wpkh"}},
        utxos = {
          [outpoint_key] = {
            value = 100000000, script_pubkey = spk, address = addr,
            txid = prev_txid, vout = 0, confirmations = 100,
          },
        },
        scan_utxos = function() end,
        estimate_fee_rate = function() return 1 end,
        get_change_address = function() return addr end,
      }
      server.wallet = fake_wallet

      -- Send 0.5 BTC out; coin selection will pick the 1 BTC UTXO + change.
      local outputs = {{["bcrt1q" .. string.rep("q", 38) .. "3xueyj"] = 0.5}}
      -- Use a regtest-encoded recipient address derived from a fresh key
      -- (the literal above was a placeholder; build a real regtest p2wpkh
      -- address so address_mod.decode_address accepts it).
      local recip_priv = crypto.sha256("lunarblock-wallet-wave-recipient")
      local recip_pub = crypto.pubkey_from_privkey(recip_priv, true)
      local recip_addr = address_mod.pubkey_to_p2wpkh(recip_pub, "regtest")
      outputs = {{[recip_addr] = 0.5}}

      local result = server.methods["walletcreatefundedpsbt"](
        server, {{}, outputs, 0, {feeRate = 1}})

      assert.is_table(result)
      assert.is_string(result.psbt)
      assert.is_number(result.fee)
      assert.is_number(result.changepos)

      -- PSBT round-trips and contains 1 input + 2 outputs (recip + change).
      local psbt = psbt_mod.from_base64(result.psbt)
      assert.equals(1, #psbt.tx.inputs)
      assert.equals(2, #psbt.tx.outputs)
      -- The single input should have witness_utxo populated.
      assert.is_not_nil(psbt.inputs[1].witness_utxo)
      assert.equals(100000000, psbt.inputs[1].witness_utxo.value)
    end)
  end)
end)
