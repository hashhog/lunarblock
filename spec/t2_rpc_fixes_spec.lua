-- R5 T2 probe misses: combinerawtransaction / createmultisig / descriptorprocesspsbt
--
-- combinerawtransaction
--   The -25 "Input not found or already spent" check called `cv.get(txid, n)`
--   on a CoinView, whose `get` is a METHOD.  `self` was the txid, so the first
--   field access raised a Lua error (utxo.lua) and the client saw -32603
--   instead of Core's -25 (rawtransaction.cpp combinerawtransaction).
-- createmultisig
--   Addresses were encoded with a hard-coded "mainnet", so regtest/testnet
--   nodes returned 3.../bc1... where Core (Params()) returns 2.../bcrt1....
-- descriptorprocesspsbt
--   Was a stub: only validated descriptors, never updated the PSBT.  Core adds
--   the output BIP32 derivation for a descriptor-owned scriptPubKey, fills
--   prevouts, signs and finalizes.  Descriptor keys were also decoded as
--   mainnet only, so a regtest/testnet WIF was rejected.
--   Expected PSBT below was produced by Bitcoin Core v31.1 (regtest) for the
--   same PSBT + descriptor and is compared byte-for-byte.

local rpc = require("lunarblock.rpc")
local consensus = require("lunarblock.consensus")
local address = require("lunarblock.address")
local psbt_mod = require("lunarblock.psbt")
local serialize = require("lunarblock.serialize")
local types = require("lunarblock.types")
local cjson = require("cjson")

-- A CoinView stand-in whose `get` is a real method (uses `self`).
local function fake_coin_view(coins)
  local cv = {coins = coins or {}}
  function cv:get(txid, vout)
    return self.coins[txid.bytes .. ":" .. vout]
  end
  return cv
end

local function make_server(net, coins)
  local server = rpc.new({network = net})
  server.chain_state = {coin_view = fake_coin_view(coins)}
  return server
end

local function call(server, method, params)
  local body = cjson.encode({method = method, params = params, id = 1})
  return cjson.decode((server:handle_request(body)))
end

local function is_err(r) return type(r.error) == "table" end

local MAINNET_WIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
local PSBT_B64 = "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA"
-- Core v31.1 output for PSBT_B64 + wpkh(<that key>): output 0 gains the
-- BIP32 derivation (fingerprint = hash160(pubkey)[0:4], empty path).
local CORE_UPDATED = "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAiAgJ5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmAR1HnboAA=="

local function regtest_wif()
  local _, payload = address.base58check_decode(MAINNET_WIF)
  return address.base58check_encode(0xEF, payload)
end

describe("combinerawtransaction -25 on unknown input", function()
  local UNKNOWN_TX = "0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000fdffffff01a086010000000000160014751e76e8199196d454941c45d1b3a323f1433bd600000000"

  it("returns -25 (not a Lua error / -32603) when the prevout is missing", function()
    local r = call(make_server(consensus.networks.regtest), "combinerawtransaction",
      {{UNKNOWN_TX, UNKNOWN_TX}})
    assert.is_true(is_err(r), "expected an error")
    assert.equals(-25, r.error.code, tostring(r.error.message))
    assert.equals("Input not found or already spent", r.error.message)
  end)

  it("CONTROL: succeeds and returns the tx when the prevout exists", function()
    local tx = serialize.deserialize_transaction(rpc.hex_decode(UNKNOWN_TX))
    local inp = tx.inputs[1].prev_out
    local coins = {[inp.hash.bytes .. ":" .. inp.index] =
      {value = 100000, script_pubkey = "\0\20" .. string.rep("\1", 20)}}
    local r = call(make_server(consensus.networks.regtest, coins),
      "combinerawtransaction", {{UNKNOWN_TX, UNKNOWN_TX}})
    assert.is_false(is_err(r), is_err(r) and r.error.message or "")
    assert.equals(UNKNOWN_TX, r.result)
  end)
end)

describe("createmultisig uses the node's network", function()
  local K = {"03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd",
             "03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626"}

  it("regtest legacy == Core's 2NGRTbZB... (was 3QsFXpFJ... mainnet)", function()
    local r = call(make_server(consensus.networks.regtest), "createmultisig", {2, K})
    assert.is_false(is_err(r))
    assert.equals("2NGRTbZBLGV4tJ3y4Avz7sa2Dea9o93UaPH", r.result.address)
  end)

  it("regtest bech32 starts bcrt1q (was bc1q)", function()
    local r = call(make_server(consensus.networks.regtest), "createmultisig", {2, K, "bech32"})
    assert.is_false(is_err(r))
    assert.equals("bcrt1q0jnggjwnn22a4ywxc2pcw86c0d6tghqkgk3hlryrxl7", r.result.address:sub(1, 49))
  end)

  it("CONTROL: mainnet still yields 3QsFXpFJ...", function()
    local r = call(make_server(consensus.networks.mainnet), "createmultisig", {2, K})
    assert.equals("3QsFXpFJf2ZY6GLWVoNFFd2xSDwdS713qX", r.result.address)
  end)
end)

describe("descriptorprocesspsbt", function()
  it("regtest: accepts a regtest WIF and adds the output derivation == Core", function()
    local r = call(make_server(consensus.networks.regtest), "descriptorprocesspsbt",
      {PSBT_B64, {"wpkh(" .. regtest_wif() .. ")"}})
    assert.is_false(is_err(r), is_err(r) and r.error.message or "")
    assert.equals(CORE_UPDATED, r.result.psbt)
    assert.is_false(r.result.complete)
  end)

  it("mainnet: the mainnet WIF gives the same Core-identical PSBT", function()
    local r = call(make_server(consensus.networks.mainnet), "descriptorprocesspsbt",
      {PSBT_B64, {"wpkh(" .. MAINNET_WIF .. ")"}})
    assert.is_false(is_err(r), is_err(r) and r.error.message or "")
    assert.equals(CORE_UPDATED, r.result.psbt)
  end)

  it("regtest rejects a mainnet WIF with -5 (as Core does)", function()
    local r = call(make_server(consensus.networks.regtest), "descriptorprocesspsbt",
      {PSBT_B64, {"wpkh(" .. MAINNET_WIF .. ")"}})
    assert.is_true(is_err(r))
    assert.equals(-5, r.error.code)
  end)

  it("bip32derivs=false leaves the PSBT unchanged", function()
    local r = call(make_server(consensus.networks.regtest), "descriptorprocesspsbt",
      {PSBT_B64, {"wpkh(" .. regtest_wif() .. ")"}, {bip32derivs = false}})
    assert.equals(PSBT_B64, r.result.psbt)
  end)

  it("signs and finalizes an owned p2wpkh input from the chainstate", function()
    local _, payload = address.base58check_decode(MAINNET_WIF)
    local crypto = require("lunarblock.crypto")
    local priv = payload:sub(1, 32)
    local pub = crypto.pubkey_from_privkey(priv, true)
    local spk = "\0\20" .. crypto.hash160(pub)
    local prev = types.hash256(string.rep("\171", 32))
    local tx = types.transaction(2, {
      types.txin(types.outpoint(prev, 0), "", 0xfffffffd)},
      {types.txout(90000, spk)}, 0)
    local psbt = psbt_mod.new(tx)
    local coins = {[prev.bytes .. ":0"] = {value = 100000, script_pubkey = spk}}
    local r = call(make_server(consensus.networks.regtest, coins), "descriptorprocesspsbt",
      {psbt_mod.to_base64(psbt), {"wpkh(" .. regtest_wif() .. ")"}})
    assert.is_false(is_err(r), is_err(r) and r.error.message or "")
    assert.is_true(r.result.complete)
    local out = serialize.deserialize_transaction(rpc.hex_decode(r.result.hex))
    assert.equals(2, #out.inputs[1].witness)
    assert.equals(pub, out.inputs[1].witness[2])
  end)

  it("CONTROL: unknown prevout stays unsigned (complete=false)", function()
    local r = call(make_server(consensus.networks.regtest), "descriptorprocesspsbt",
      {PSBT_B64, {"wpkh(" .. regtest_wif() .. ")"}})
    assert.is_false(r.result.complete)
    assert.is_nil(r.result.hex)
  end)
end)
