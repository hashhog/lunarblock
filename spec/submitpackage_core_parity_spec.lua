-- submitpackage / package testmempoolaccept: acceptance and per-tx results
-- follow Bitcoin Core v31.
--
-- Reference: bitcoin-core/src/validation.cpp
--   MemPoolAccept::AcceptPackage                (submitpackage)
--   MemPoolAccept::AcceptMultipleTransactions   (package testmempoolaccept,
--                                                m_package_feerates=false)
--   MemPoolAccept::PolicyScriptChecks -> CheckInputScripts
-- and bitcoin-core/src/rpc/mempool.cpp testmempoolaccept / submitpackage.
--
-- The headline case: a P2WPKH child whose ECDSA signature is non-empty but
-- wrong.  Core refuses it with mempool-script-verify-flag-failed (NULLFAIL);
-- lunarblock used to admit it because the relay-time script check skipped
-- every witness input.

local cjson      = require("cjson")
local types      = require("lunarblock.types")
local crypto     = require("lunarblock.crypto")
local script     = require("lunarblock.script")
local validation = require("lunarblock.validation")
local serialize  = require("lunarblock.serialize")
local consensus  = require("lunarblock.consensus")
local mempool    = require("lunarblock.mempool")
local rpc        = require("lunarblock.rpc")

local PRIV = string.rep("\x01", 31) .. "\x2a"
local PUB  = crypto.pubkey_from_privkey(PRIV, true)
local PKH  = crypto.hash160(PUB)
local SPK  = script.make_p2wpkh_script(PKH)
local COIN_VALUE = 5000000000

local NULLFAIL_REASON =
  "mempool-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)"

local function hex(h) return types.hash256_hex(h) end
local function txid_hex(tx) return hex(validation.compute_txid(tx)) end
local function wtxid_hex(tx) return hex(validation.compute_wtxid(tx)) end

local function make_chain()
  local utxos = {}
  local cv = {
    get = function(_, txid, vout)
      return utxos[hex(txid) .. ":" .. vout]
    end,
  }
  return { coin_view = cv, tip_height = 200, network = consensus.networks.regtest }, utxos
end

local function fund(utxos, tag)
  local txid = types.hash256(crypto.hash256("submitpackage-parity-" .. tag))
  utxos[hex(txid) .. ":0"] = {
    value = COIN_VALUE, script_pubkey = SPK, height = 1, is_coinbase = false,
  }
  return txid
end

-- One-in one-out P2WPKH spend of prev_txid:0 paying `fee`, signed with PRIV.
local function spend(prev_txid, prev_value, fee)
  local tx = types.transaction(2,
    { types.txin(types.outpoint(prev_txid, 0), "", 0xFFFFFFFD) },
    { types.txout(prev_value - fee, SPK) }, 0)
  local sighash = validation.signature_hash_segwit_v0(
    tx, 0, script.make_p2pkh_script(PKH), prev_value, 1)
  local der = assert(crypto.ecdsa_sign(PRIV, sighash))
  tx.inputs[1].witness = { der .. "\x01", PUB }
  tx.segwit = true
  return tx
end

-- Flip the low bit of DER r (what the core-regtest harness does): still
-- strict DER, so CHECKSIG fails and NULLFAIL fires.
local function corrupt(tx)
  local sig = tx.inputs[1].witness[1]
  local last = 4 + sig:byte(4)
  local flipped = sig:sub(1, last - 1) .. string.char(bit.bxor(sig:byte(last), 1)) .. sig:sub(last + 1)
  local bad = types.transaction(tx.version, {
    types.txin(tx.inputs[1].prev_out, "", tx.inputs[1].sequence),
  }, tx.outputs, tx.locktime)
  bad.inputs[1].witness = { flipped, tx.inputs[1].witness[2] }
  bad.segwit = true
  return bad
end

local function details_for(tx)
  return string.format("input 0 of %s (wtxid %s), spending %s:0",
    txid_hex(tx), wtxid_hex(tx), hex(tx.inputs[1].prev_out.hash))
end

local function raw(tx)
  return rpc.hex_encode(serialize.serialize_transaction(tx, true))
end

local function new_env()
  local cs, utxos = make_chain()
  local mp = mempool.new(cs, { verify_input_scripts = true })
  local server = rpc.new({ network = consensus.networks.regtest, mempool = mp })
  local function call(method, params)
    local body = server:handle_request(cjson.encode({ method = method, params = params, id = 1 }))
    return cjson.decode(body), body
  end
  return { mp = mp, utxos = utxos, call = call }
end

-- Core: CFeeRate(fee, vsize).GetFeePerK() is truncated sat/kvB, printed as BTC.
local function feerate(fee, vsize)
  return math.floor(fee * 1000 / vsize) / 1e8
end

describe("submitpackage / package testmempoolaccept follow Core", function()

  describe("relay-time script checks cover witness inputs", function()
    it("CONTROL: a correctly signed P2WPKH spend is admitted", function()
      local env = new_env()
      local tx = spend(fund(env.utxos, "ctl"), COIN_VALUE, 10000)
      local ok, err = env.mp:accept_transaction(tx)
      assert.is_true(ok, tostring(err))
    end)

    it("refuses a P2WPKH spend with an invalid signature (NULLFAIL), with Core's reason and details", function()
      local env = new_env()
      local bad = corrupt(spend(fund(env.utxos, "bad"), COIN_VALUE, 10000))
      local ok, reason, details = env.mp:accept_transaction(bad)
      assert.is_false(ok)
      assert.equals(NULLFAIL_REASON, reason)
      assert.equals(details_for(bad), details)
      assert.is_nil(env.mp.entries[txid_hex(bad)])
    end)
  end)

  describe("submitpackage", function()
    it("invalid-signature child: parent accepted alone, child refused, package_msg 'transaction failed'", function()
      local env = new_env()
      local parent = spend(fund(env.utxos, "isc"), COIN_VALUE, 10000)
      local child = corrupt(spend(validation.compute_txid(parent), COIN_VALUE - 10000, 10000))
      local resp = env.call("submitpackage", { { raw(parent), raw(child) } })
      assert.equals(cjson.null, resp.error)
      local r = resp.result
      assert.equals("transaction failed", r.package_msg)
      local pr = r["tx-results"][wtxid_hex(parent)]
      assert.equals(txid_hex(parent), pr.txid)
      assert.equals(110, pr.vsize)
      assert.equals(0.0001, pr.fees.base)
      assert.equals(feerate(10000, 110), pr.fees["effective-feerate"])
      assert.same({ wtxid_hex(parent) }, pr.fees["effective-includes"])
      local cr = r["tx-results"][wtxid_hex(child)]
      assert.same({ txid = txid_hex(child),
                    error = NULLFAIL_REASON .. ", " .. details_for(child) }, cr)
      assert.is_not_nil(env.mp.entries[txid_hex(parent)])
      assert.is_nil(env.mp.entries[txid_hex(child)],
        "the invalid-signature child must not enter the mempool")
    end)

    it("invalid-signature parent: parent refused, child missing inputs, nothing admitted", function()
      local env = new_env()
      local good_parent = spend(fund(env.utxos, "isp"), COIN_VALUE, 10000)
      local parent = corrupt(good_parent)
      local child = spend(validation.compute_txid(parent), COIN_VALUE - 10000, 10000)
      local resp = env.call("submitpackage", { { raw(parent), raw(child) } })
      local r = resp.result
      assert.equals("transaction failed", r.package_msg)
      assert.same({ txid = txid_hex(parent), error = NULLFAIL_REASON .. ", " .. details_for(parent) },
        r["tx-results"][wtxid_hex(parent)])
      assert.same({ txid = txid_hex(child), error = "bad-txns-inputs-missingorspent" },
        r["tx-results"][wtxid_hex(child)])
      assert.is_nil(env.mp.entries[txid_hex(parent)])
      assert.is_nil(env.mp.entries[txid_hex(child)])
    end)

    it("CPFP below min relay: success, both members report the package feerate and both wtxids", function()
      local env = new_env()
      local low = spend(fund(env.utxos, "cpfp"), COIN_VALUE, 1)
      local high = spend(validation.compute_txid(low), COIN_VALUE - 1, 20000)
      local resp, body = env.call("submitpackage", { { raw(low), raw(high) } })
      local r = resp.result
      assert.equals("success", r.package_msg)
      local includes = { wtxid_hex(low), wtxid_hex(high) }
      for _, tx in ipairs({ low, high }) do
        local tr = r["tx-results"][wtxid_hex(tx)]
        assert.equals(feerate(20001, 220), tr.fees["effective-feerate"])
        assert.same(includes, tr.fees["effective-includes"])
      end
      assert.truthy(body:find('"replaced%-transactions":%[%]'),
        "replaced-transactions must encode as a JSON array: " .. body)
    end)

    it("missing input: valid parent stays in the mempool, child reports bad-txns-inputs-missingorspent", function()
      local env = new_env()
      local base = spend(fund(env.utxos, "mi"), COIN_VALUE, 10000)
      local child = spend(validation.compute_txid(base), COIN_VALUE - 10000, 10000)
      child.inputs[2] = types.txin(types.outpoint(types.hash256(string.rep("\x22", 32)), 1), "", 0xFFFFFFFD)
      child.inputs[2].witness = {}
      local resp = env.call("submitpackage", { { raw(base), raw(child) } })
      local r = resp.result
      assert.equals("transaction failed", r.package_msg)
      local br = r["tx-results"][wtxid_hex(base)]
      assert.same({ wtxid_hex(base) }, br.fees["effective-includes"])
      assert.same({ txid = txid_hex(child), error = "bad-txns-inputs-missingorspent" },
        r["tx-results"][wtxid_hex(child)])
      assert.is_not_nil(env.mp.entries[txid_hex(base)])
    end)
  end)

  describe("package testmempoolaccept (per-tx feerates, Core m_package_feerates=false)", function()
    it("invalid-signature child: [0] allowed with its own wtxid, [1] refused with reason and details", function()
      local env = new_env()
      local parent = spend(fund(env.utxos, "tisc"), COIN_VALUE, 10000)
      local child = corrupt(spend(validation.compute_txid(parent), COIN_VALUE - 10000, 10000))
      local r = env.call("testmempoolaccept", { { raw(parent), raw(child) } }).result
      assert.is_true(r[1].allowed)
      assert.same({ wtxid_hex(parent) }, r[1].fees["effective-includes"])
      assert.equals(feerate(10000, 110), r[1].fees["effective-feerate"])
      assert.is_false(r[2].allowed)
      assert.equals(NULLFAIL_REASON, r[2]["reject-reason"])
      assert.equals(NULLFAIL_REASON .. ", " .. details_for(child), r[2]["reject-details"])
      assert.is_nil(r[2].vsize)
      assert.is_nil(env.mp.entries[txid_hex(parent)], "test accept leaves the mempool alone")
    end)

    it("invalid-signature parent: [0] refused, [1] unfinished (txid and wtxid only)", function()
      local env = new_env()
      local parent = corrupt(spend(fund(env.utxos, "tisp"), COIN_VALUE, 10000))
      local child = spend(validation.compute_txid(parent), COIN_VALUE - 10000, 10000)
      local r = env.call("testmempoolaccept", { { raw(parent), raw(child) } }).result
      assert.is_false(r[1].allowed)
      assert.equals(NULLFAIL_REASON, r[1]["reject-reason"])
      assert.same({ txid = txid_hex(child), wtxid = wtxid_hex(child) }, r[2])
    end)

    it("CPFP below min relay: [0] 'min relay fee not met' with '1 < 11', [1] unfinished", function()
      local env = new_env()
      local low = spend(fund(env.utxos, "tcpfp"), COIN_VALUE, 1)
      local high = spend(validation.compute_txid(low), COIN_VALUE - 1, 20000)
      local r = env.call("testmempoolaccept", { { raw(low), raw(high) } }).result
      assert.is_false(r[1].allowed)
      assert.equals("min relay fee not met", r[1]["reject-reason"])
      assert.equals("min relay fee not met, 1 < 11", r[1]["reject-details"])
      assert.is_nil(r[1].fees)
      assert.same({ txid = txid_hex(high), wtxid = wtxid_hex(high) }, r[2])
    end)

    it("parent-child both paying their own way: each lists only its own wtxid", function()
      local env = new_env()
      local parent = spend(fund(env.utxos, "tpc"), COIN_VALUE, 10000)
      local child = spend(validation.compute_txid(parent), COIN_VALUE - 10000, 10000)
      local r = env.call("testmempoolaccept", { { raw(parent), raw(child) } }).result
      assert.is_true(r[1].allowed)
      assert.is_true(r[2].allowed)
      assert.same({ wtxid_hex(parent) }, r[1].fees["effective-includes"])
      assert.same({ wtxid_hex(child) }, r[2].fees["effective-includes"])
    end)
  end)

  describe("single-tx testmempoolaccept fee fields", function()
    it("effective-includes is the wtxid and effective-feerate is truncated sat/kvB", function()
      local env = new_env()
      local tx = spend(fund(env.utxos, "single"), COIN_VALUE, 10000)
      assert.are_not.equal(txid_hex(tx), wtxid_hex(tx))
      local r = env.call("testmempoolaccept", { { raw(tx) } }).result
      assert.is_true(r[1].allowed)
      assert.same({ wtxid_hex(tx) }, r[1].fees["effective-includes"])
      assert.equals(feerate(10000, 110), r[1].fees["effective-feerate"])
    end)
  end)
end)

-- Negative-space controls for widening relay-time script checks to witness
-- inputs: the risk of the change is refusing a VALID spend (a false reject
-- strands a wallet's tx and its children), so every standard output type the
-- verifier now runs on is pinned as accepted when correctly signed, and as
-- refused when the signature is broken.
describe("relay-time script checks: valid spends of every witness type are admitted", function()
  local function fund_spk(utxos, tag, spk, value)
    local txid = types.hash256(crypto.hash256("submitpackage-parity-ctl-" .. tag))
    utxos[hex(txid) .. ":0"] = {
      value = value, script_pubkey = spk, height = 1, is_coinbase = false,
    }
    return txid
  end
  local function unsigned(prev_txid, value)
    return types.transaction(2,
      { types.txin(types.outpoint(prev_txid, 0), "", 0xFFFFFFFD) },
      { types.txout(value - 10000, SPK) }, 0)
  end
  local function admit(env, tx)
    tx.segwit = true
    return env.mp:accept_transaction(tx)
  end

  it("P2WSH <pub> OP_CHECKSIG: valid admitted, broken signature refused", function()
    local env = new_env()
    local ws = string.char(#PUB) .. PUB .. "\xac"
    local spk = script.make_p2wsh_script(crypto.sha256(ws))
    local prev = fund_spk(env.utxos, "p2wsh", spk, 100000)
    local tx = unsigned(prev, 100000)
    local sighash = validation.signature_hash_segwit_v0(tx, 0, ws, 100000, 1)
    local sig = assert(crypto.ecdsa_sign(PRIV, sighash)) .. "\x01"
    tx.inputs[1].witness = { sig, ws }
    local ok, err = admit(env, tx)
    assert.is_true(ok, tostring(err))

    local env2 = new_env()
    fund_spk(env2.utxos, "p2wsh", spk, 100000)
    local bad = unsigned(prev, 100000)
    local last = 4 + sig:byte(4)
    bad.inputs[1].witness = {
      sig:sub(1, last - 1) .. string.char(bit.bxor(sig:byte(last), 1)) .. sig:sub(last + 1), ws }
    local ok2, reason = admit(env2, bad)
    assert.is_false(ok2)
    assert.equals(NULLFAIL_REASON, reason)
  end)

  it("P2SH-P2WPKH: valid admitted", function()
    local env = new_env()
    local redeem = script.make_p2wpkh_script(PKH)
    local spk = script.make_p2sh_script(crypto.hash160(redeem))
    local prev = fund_spk(env.utxos, "p2sh-p2wpkh", spk, 100000)
    local tx = unsigned(prev, 100000)
    tx.inputs[1].script_sig = string.char(#redeem) .. redeem
    local sighash = validation.signature_hash_segwit_v0(
      tx, 0, script.make_p2pkh_script(PKH), 100000, 1)
    tx.inputs[1].witness = { assert(crypto.ecdsa_sign(PRIV, sighash)) .. "\x01", PUB }
    local ok, err = admit(env, tx)
    assert.is_true(ok, tostring(err))
  end)

  it("P2TR key path: valid admitted, wrong-key signature refused", function()
    local env = new_env()
    local xonly = PUB:sub(2, 33)
    local tweak = crypto.tagged_hash("TapTweak", xonly)
    local out_key = assert(crypto.tweak_pubkey(xonly, tweak))
    local spk = script.make_p2tr_script(out_key)
    local prev = fund_spk(env.utxos, "p2tr", spk, 100000)
    local tx = unsigned(prev, 100000)
    local prevouts = { { value = 100000, script_pubkey = spk } }
    local sighash = assert(validation.signature_hash_taproot(tx, 0, 0x00, prevouts, 0))
    local seckey = assert(crypto.taproot_tweak_seckey(PRIV, tweak))
    tx.inputs[1].witness = { assert(crypto.schnorr_sign(seckey, sighash, string.rep("\0", 32))) }
    local ok, err = admit(env, tx)
    assert.is_true(ok, tostring(err))

    local env2 = new_env()
    fund_spk(env2.utxos, "p2tr", spk, 100000)
    local bad = unsigned(prev, 100000)
    -- Signed with the UNTWEAKED key: a well-formed Schnorr signature that
    -- does not verify against the output key.
    bad.inputs[1].witness = { assert(crypto.schnorr_sign(PRIV, sighash, string.rep("\0", 32))) }
    local ok2, reason = admit(env2, bad)
    assert.is_false(ok2)
    assert.truthy(reason:match("^mempool%-script%-verify%-flag%-failed %("), reason)
  end)

  it("P2A anchor spend with an empty witness: admitted (anyone-can-spend v1 program)", function()
    local env = new_env()
    local prev = fund_spk(env.utxos, "p2a", "\x51\x02\x4e\x73", 100000)
    local tx = unsigned(prev, 100000)
    tx.inputs[1].witness = {}
    local ok, err = env.mp:accept_transaction(tx)
    assert.is_true(ok, tostring(err))
  end)

  it("legacy P2PKH: valid admitted, broken signature refused with Core's reason", function()
    local env = new_env()
    local spk = script.make_p2pkh_script(PKH)
    local prev = fund_spk(env.utxos, "p2pkh", spk, 100000)
    local tx = unsigned(prev, 100000)
    local sighash = validation.signature_hash_legacy(tx, 0, spk, 1)
    local sig = assert(crypto.ecdsa_sign(PRIV, sighash)) .. "\x01"
    tx.inputs[1].script_sig = string.char(#sig) .. sig .. string.char(#PUB) .. PUB
    local ok, err = env.mp:accept_transaction(tx)
    assert.is_true(ok, tostring(err))

    local env2 = new_env()
    fund_spk(env2.utxos, "p2pkh", spk, 100000)
    local bad = unsigned(prev, 100000)
    local last = 4 + sig:byte(4)
    local bsig = sig:sub(1, last - 1) .. string.char(bit.bxor(sig:byte(last), 1)) .. sig:sub(last + 1)
    bad.inputs[1].script_sig = string.char(#bsig) .. bsig .. string.char(#PUB) .. PUB
    local ok2, reason, details = env2.mp:accept_transaction(bad)
    assert.is_false(ok2)
    assert.equals(NULLFAIL_REASON, reason)
    assert.equals(details_for(bad), details)
  end)
end)
