-- BIP-431 TRUC sibling eviction is a STAGED replacement, not an eviction
-- performed inside the TRUC gate.
--
-- Reference: bitcoin-core/src/validation.cpp
--   MemPoolAccept::PreChecks (958-969): with m_allow_sibling_eviction set, the
--     sibling returned by SingleTRUCChecks is inserted into ws.m_conflicts, so
--     ReplacementChecks (Rule 5, PaysForRBF, cluster limit, feerate diagram)
--     judges it like any other replaced tx.
--   MemPoolAccept::FinalizeSubpackage: the only place the staged removals are
--     applied -- after PolicyScriptChecks, and never for m_test_accept.
--   ATMPArgs::PackageTestAccept / PackageChildWithParents: allow_sibling_eviction
--     is false, so a multi-transaction package never evicts a sibling.
--
-- lunarblock used to call remove_transaction on the sibling inside the TRUC
-- gate, before the max-feerate gate, the script checks and the test-accept
-- return, and never restored it: a peer could evict an honest TRUC child with
-- an invalid-signature, min-fee sibling for free, and testmempoolaccept or a
-- package dry run evicted it for good.

local cjson      = require("cjson")
local types      = require("lunarblock.types")
local crypto     = require("lunarblock.crypto")
local script     = require("lunarblock.script")
local validation = require("lunarblock.validation")
local serialize  = require("lunarblock.serialize")
local consensus  = require("lunarblock.consensus")
local mempool    = require("lunarblock.mempool")
local rpc        = require("lunarblock.rpc")

local PRIV = string.rep("\x02", 31) .. "\x3b"
local PUB  = crypto.pubkey_from_privkey(PRIV, true)
local PKH  = crypto.hash160(PUB)
local SPK  = script.make_p2wpkh_script(PKH)
local COIN_VALUE = 5000000000
local PARENT_FEE = 10000
local HALF = (COIN_VALUE - PARENT_FEE) / 2

local NULLFAIL_REASON =
  "mempool-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)"

local function hex(h) return types.hash256_hex(h) end
local function txid_hex(tx) return hex(validation.compute_txid(tx)) end

-- Sign input 1 (P2WPKH, PRIV) of a one-input tx spending a coin of `value`.
local function sign(tx, value)
  local sighash = validation.signature_hash_segwit_v0(
    tx, 0, script.make_p2pkh_script(PKH), value, 1)
  tx.inputs[1].witness = { assert(crypto.ecdsa_sign(PRIV, sighash)) .. "\x01", PUB }
  tx.segwit = true
  return tx
end

-- v3 one-in spend of prev_txid:vout (worth `value`) paying `fee`.
local function v3_spend(prev_txid, vout, value, fee)
  local tx = types.transaction(3,
    { types.txin(types.outpoint(prev_txid, vout), "", 0xFFFFFFFD) },
    { types.txout(value - fee, SPK) }, 0)
  return sign(tx, value)
end

-- Flip the low bit of DER r: still strict DER, so CHECKSIG fails (NULLFAIL).
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

local function raw(tx)
  return rpc.hex_encode(serialize.serialize_transaction(tx, true))
end

-- Mempool holding v3 parent P (two outputs) and the honest v3 child C on P:0
-- paying `child_fee`.
local function setup(tag, child_fee)
  local utxos = {}
  local cs = {
    coin_view = { get = function(_, txid, vout) return utxos[hex(txid) .. ":" .. vout] end },
    tip_height = 200, network = consensus.networks.regtest,
  }
  local mp = mempool.new(cs, { verify_input_scripts = true })
  local server = rpc.new({ network = consensus.networks.regtest, mempool = mp })
  local function call(method, params)
    local body = server:handle_request(cjson.encode({ method = method, params = params, id = 1 }))
    return cjson.decode(body), body
  end
  local function fund(t)
    local txid = types.hash256(crypto.hash256("truc-sibling-staging-" .. tag .. t))
    utxos[hex(txid) .. ":0"] = { value = COIN_VALUE, script_pubkey = SPK, height = 1, is_coinbase = false }
    return txid
  end

  local p = types.transaction(3,
    { types.txin(types.outpoint(fund("p"), 0), "", 0xFFFFFFFD) },
    { types.txout(HALF, SPK), types.txout(HALF, SPK) }, 0)
  sign(p, COIN_VALUE)
  local ok_p, err_p = mp:accept_transaction(p)
  assert(ok_p, "parent: " .. tostring(err_p))
  local p_txid = validation.compute_txid(p)

  local c = v3_spend(p_txid, 0, HALF, child_fee or 50000)
  local ok_c, err_c = mp:accept_transaction(c)
  assert(ok_c, "honest child: " .. tostring(err_c))

  return { mp = mp, call = call, fund = fund, p = p, p_txid = p_txid, c = c,
           c_hex = txid_hex(c) }
end

local function assert_child_kept(env, what)
  assert.is_not_nil(env.mp.entries[env.c_hex],
    what .. ": the honest TRUC child must still be in the mempool")
  assert.is_not_nil(env.mp.entries[txid_hex(env.p)], what .. ": the parent must stay")
end

describe("TRUC sibling eviction is staged as an RBF conflict (Core PreChecks/FinalizeSubpackage)", function()

  describe("accept_transaction / sendrawtransaction", function()
    it("an invalid-signature, min-fee sibling does not evict the honest child", function()
      local env = setup("inv-min")
      local bad = corrupt(v3_spend(env.p_txid, 1, HALF, 110))
      local ok, reason = env.mp:accept_transaction(bad)
      assert.is_false(ok)
      assert.is_nil(env.mp.entries[txid_hex(bad)])
      assert_child_kept(env, "invalid-sig min-fee sibling")
      -- PaysForRBF now covers the sibling: 110 < 50000.
      assert.equals("insufficient fee (including sibling eviction)", reason)
    end)

    it("an invalid-signature sibling paying enough for RBF fails the script check and evicts nothing", function()
      local env = setup("inv-high")
      local bad = corrupt(v3_spend(env.p_txid, 1, HALF, 100000))
      local ok, reason = env.mp:accept_transaction(bad)
      assert.is_false(ok)
      assert.equals(NULLFAIL_REASON, reason)
      assert.is_nil(env.mp.entries[txid_hex(bad)])
      assert_child_kept(env, "invalid-sig high-fee sibling")
    end)

    it("sendrawtransaction of an invalid-signature min-fee sibling leaves the child", function()
      local env = setup("inv-srt")
      local bad = corrupt(v3_spend(env.p_txid, 1, HALF, 110))
      local resp = env.call("sendrawtransaction", { raw(bad) })
      assert.is_not_nil(resp.error)
      assert.is_true(resp.error ~= cjson.null)
      assert_child_kept(env, "sendrawtransaction")
    end)

    it("a valid sibling that does not pay for the evicted child is refused (Rule 3)", function()
      local env = setup("val-min")
      local low = v3_spend(env.p_txid, 1, HALF, 110)
      local ok, reason, details = env.mp:accept_transaction(low)
      assert.is_false(ok)
      assert.equals("insufficient fee (including sibling eviction)", reason)
      assert.truthy(tostring(details):find("less fees than conflicting txs", 1, true), tostring(details))
      assert_child_kept(env, "valid min-fee sibling")
    end)

    it("a valid sibling over the max-feerate cap evicts nothing", function()
      local env = setup("val-cap")
      local hi = v3_spend(env.p_txid, 1, HALF, 100000)
      -- 100000 sat on ~110 vB is ~909 sat/vB; cap at 500 sat/vB.
      local ok, reason = env.mp:accept_transaction(hi, nil, { max_fee_per_kvb = 500000 })
      assert.is_false(ok)
      assert.equals(mempool.MAX_FEE_EXCEEDED, reason)
      assert_child_kept(env, "max-feerate cap")
    end)

    it("CONTROL: a valid sibling paying for the eviction replaces the child and reports it as replaced", function()
      local env = setup("val-high")
      local good = v3_spend(env.p_txid, 1, HALF, 100000)
      local ok, txid, _, replaced = env.mp:accept_transaction(good)
      assert.is_true(ok, tostring(txid))
      assert.is_nil(env.mp.entries[env.c_hex], "the sibling is evicted once every check passed")
      assert.is_not_nil(env.mp.entries[txid_hex(good)])
      assert.same({ env.c_hex }, replaced)
    end)
  end)

  describe("testmempoolaccept never evicts", function()
    it("a valid, sufficiently paying sibling is allowed but the child stays", function()
      local env = setup("tma-high")
      local good = v3_spend(env.p_txid, 1, HALF, 100000)
      local r = env.call("testmempoolaccept", { { raw(good) } }).result
      assert.is_true(r[1].allowed, cjson.encode(r[1]))
      assert.is_nil(env.mp.entries[txid_hex(good)])
      assert_child_kept(env, "testmempoolaccept (single)")
    end)

    it("a valid min-fee sibling is refused and the child stays", function()
      local env = setup("tma-min")
      local low = v3_spend(env.p_txid, 1, HALF, 110)
      local r = env.call("testmempoolaccept", { { raw(low) } }).result
      assert.is_false(r[1].allowed)
      assert.equals("insufficient fee (including sibling eviction)", r[1]["reject-reason"])
      assert_child_kept(env, "testmempoolaccept (single, min fee)")
    end)

    it("package testmempoolaccept (no sibling eviction in PackageTestAccept) leaves the child", function()
      local env = setup("tma-pkg")
      local good = v3_spend(env.p_txid, 1, HALF, 100000)
      -- An unrelated, valid v2 tx makes this a two-transaction package.
      local other = types.transaction(2,
        { types.txin(types.outpoint(env.fund("other"), 0), "", 0xFFFFFFFD) },
        { types.txout(COIN_VALUE - 10000, SPK) }, 0)
      sign(other, COIN_VALUE)
      local r = env.call("testmempoolaccept", { { raw(other), raw(good) } }).result
      assert.is_not_nil(r[2])
      assert.is_true(r[2].allowed ~= true, "a package never evicts a sibling: " .. cjson.encode(r[2]))
      assert.is_nil(env.mp.entries[txid_hex(good)])
      assert.is_nil(env.mp.entries[txid_hex(other)], "test accept leaves the mempool alone")
      assert_child_kept(env, "package testmempoolaccept")
    end)
  end)

  describe("submitpackage", function()
    it("an invalid-signature min-fee sibling leaves the child", function()
      local env = setup("sp-inv")
      local bad = corrupt(v3_spend(env.p_txid, 1, HALF, 110))
      local resp = env.call("submitpackage", { { raw(bad) } })
      assert.equals(cjson.null, resp.error)
      assert.equals("transaction failed", resp.result.package_msg)
      assert.is_nil(env.mp.entries[txid_hex(bad)])
      assert_child_kept(env, "submitpackage invalid-sig")
    end)

    it("an invalid-signature sibling paying enough for RBF leaves the child", function()
      local env = setup("sp-inv-high")
      local bad = corrupt(v3_spend(env.p_txid, 1, HALF, 100000))
      local resp = env.call("submitpackage", { { raw(bad) } })
      assert.equals("transaction failed", resp.result.package_msg)
      assert.is_nil(env.mp.entries[txid_hex(bad)])
      assert_child_kept(env, "submitpackage invalid-sig high fee")
    end)

    it("a valid min-fee sibling leaves the child", function()
      local env = setup("sp-min")
      local low = v3_spend(env.p_txid, 1, HALF, 110)
      local resp = env.call("submitpackage", { { raw(low) } })
      assert.equals("transaction failed", resp.result.package_msg)
      assert.is_nil(env.mp.entries[txid_hex(low)])
      assert_child_kept(env, "submitpackage valid min fee")
    end)
  end)
end)
