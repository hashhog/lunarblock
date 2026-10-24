-- RPC argument checks Bitcoin Core makes and lunarblock did not:
--   getblockheader   verbose must be a bool (RPCHelpMan type check, -3)
--   sendrawtransaction  maxfeerate parsed by AmountFromValue/ParseFeeRate and
--                       enforced (default 0.10 BTC/kvB; 0 = no cap; -25 over)
--   testmempoolaccept   rawtxs must be an array (-3) of 1..25 txs (-8);
--                       maxfeerate 0 = no cap, parsed like sendrawtransaction
--
-- Reference: bitcoin-core/src/rpc/util.cpp (RPCHelpMan::HandleRequest,
-- AmountFromValue, ParseFeeRate), src/rpc/mempool.cpp (sendrawtransaction,
-- testmempoolaccept), src/node/transaction.cpp (BroadcastTransaction),
-- src/common/messages.cpp (MAX_FEE_EXCEEDED text).

local cjson = require("cjson")
local rpc = require("lunarblock.rpc")
local consensus = require("lunarblock.consensus")
local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local validation = require("lunarblock.validation")

local function tx_hex()
  local prev = types.outpoint(types.hash256(string.rep("\1", 32)), 0)
  local tx = types.transaction(2,
    {types.txin(prev, "", 0xfffffffd)},
    {types.txout(50000, "\0\20" .. string.rep("\2", 20))}, 0)
  return rpc.hex_encode(serialize.serialize_transaction(tx, true)), tx
end

-- A mempool stub: every tx validates, paying `fee` sat at `vsize` vbytes.
-- It refuses over the caller's cap the way Mempool:accept_transaction does
-- (before adding anything); the real mempool is exercised further down.
local function stub_mempool(fee, vsize)
  local mempool = require("lunarblock.mempool")
  local m = {entries = {}, accepted = 0}
  -- testmempoolaccept's single-tx path.
  function m:accept_to_memory_pool(tx, test_accept)
    return {accepted = true, fee = fee, vsize = vsize}
  end
  function m:accept_transaction(tx, allow_rbf, opts)
    local cap = opts and opts.max_fee_per_kvb
    if cap and cap > 0 and fee > mempool.fee_for_rate(cap, vsize) then
      return false, mempool.MAX_FEE_EXCEEDED
    end
    self.accepted = self.accepted + 1
    return true, types.hash256_hex(validation.compute_txid(tx)), fee
  end
  -- sendrawtransaction records every accepted txid in the unbroadcast set
  -- before relaying it; these tests only check the RPC result.
  function m:add_unbroadcast(txid_hex) end
  return m
end

local function server(mempool)
  return rpc.new({network = consensus.networks.regtest, mempool = mempool})
end

local function call(srv, method, params)
  local body = srv:handle_request(cjson.encode({
    method = method, params = params, id = 1,
  }))
  return cjson.decode(body)
end

local function is_err(resp, code, message)
  assert.is_truthy(resp.error and resp.error ~= cjson.null)
  assert.equal(code, resp.error.code)
  if message then assert.equal(message, resp.error.message) end
end

local function wrong_type(position_name, got, want)
  return string.format(
    'Wrong type passed:\n{\n    "%s": "JSON value of type %s is not of expected type %s"\n}',
    position_name, got, want)
end

describe("getblockheader verbose type check", function()
  it("refuses a string verbose with -3 before looking at the hash", function()
    local resp = call(server(), "getblockheader", {string.rep("0", 64), "x"})
    is_err(resp, -3, wrong_type("Position 2 (verbose)", "string", "bool"))
  end)
  it("refuses a numeric verbose", function()
    local resp = call(server(), "getblockheader", {string.rep("0", 64), 1})
    is_err(resp, -3, wrong_type("Position 2 (verbose)", "number", "bool"))
  end)
  it("still accepts null and bool verbose (reaches the lookup, not -3)", function()
    for _, v in ipairs({cjson.null, false, true}) do
      local r = call(server(), "getblockheader", {string.rep("0", 64), v})
      assert.is_truthy(r.error and r.error ~= cjson.null)
      assert.is_not.equal(-3, r.error.code)
    end
  end)
end)

describe("sendrawtransaction maxfeerate", function()
  it("refuses a non-amount maxfeerate with -3 Invalid amount", function()
    local hex = tx_hex()
    is_err(call(server(stub_mempool(1000, 100)), "sendrawtransaction", {hex, "x"}),
           -3, "Invalid amount")
  end)
  it("refuses a bool maxfeerate with -3", function()
    local hex = tx_hex()
    is_err(call(server(stub_mempool(1000, 100)), "sendrawtransaction", {hex, true}),
           -3, "Amount is not a number or string")
  end)
  it("refuses maxfeerate >= 1 BTC/kvB with -8", function()
    local hex = tx_hex()
    is_err(call(server(stub_mempool(1000, 100)), "sendrawtransaction", {hex, 1}),
           -8, "Fee rates larger than or equal to 1BTC/kvB are not accepted")
  end)
  it("enforces the default 0.10 BTC/kvB cap with -25 and does not add the tx", function()
    local hex = tx_hex()
    -- 1 BTC fee at 100 vB = 10 BTC/kvB
    local mp = stub_mempool(100000000, 100)
    is_err(call(server(mp), "sendrawtransaction", {hex}), -25,
           "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)")
    assert.equal(0, mp.accepted)
  end)
  it("accepts a fee under the default cap", function()
    local hex = tx_hex()
    local mp = stub_mempool(1000, 100) -- 0.0001 BTC/kvB... 10 sat/vB = 0.0001
    local r = call(server(mp), "sendrawtransaction", {hex})
    assert.is_truthy(r.result and r.result ~= cjson.null)
    assert.equal(1, mp.accepted)
  end)
  it("maxfeerate 0 means no cap", function()
    local hex = tx_hex()
    local mp = stub_mempool(100000000, 100)
    local r = call(server(mp), "sendrawtransaction", {hex, 0})
    assert.is_truthy(r.result and r.result ~= cjson.null)
    assert.equal(1, mp.accepted)
  end)
  it("an explicit maxfeerate below the tx rate refuses with -25", function()
    local hex = tx_hex()
    -- 10 sat/vB = 0.0001 BTC/kvB; cap at 0.00005
    is_err(call(server(stub_mempool(1000, 100)), "sendrawtransaction", {hex, 0.00005}), -25)
  end)
  it("accepts a string maxfeerate", function()
    local hex = tx_hex()
    local r = call(server(stub_mempool(1000, 100)), "sendrawtransaction", {hex, "0.001"})
    assert.is_truthy(r.result and r.result ~= cjson.null)
  end)
end)

describe("testmempoolaccept rawtxs and maxfeerate", function()
  it("refuses an empty array with -8", function()
    is_err(call(server(stub_mempool(1000, 100)), "testmempoolaccept", {{}}),
           -8, "Array must contain between 1 and 25 transactions.")
  end)
  it("refuses more than 25 transactions with -8", function()
    local hex = tx_hex()
    local arr = {}
    for i = 1, 26 do arr[i] = hex end
    is_err(call(server(stub_mempool(1000, 100)), "testmempoolaccept", {arr}),
           -8, "Array must contain between 1 and 25 transactions.")
  end)
  it("refuses a string rawtxs with -3 Wrong type passed", function()
    local hex = tx_hex()
    is_err(call(server(stub_mempool(1000, 100)), "testmempoolaccept", {hex}),
           -3, wrong_type("Position 1 (rawtxs)", "string", "array"))
  end)
  it("maxfeerate 0 means no cap: allowed true with vsize and fees", function()
    local hex = tx_hex()
    local r = call(server(stub_mempool(100000000, 100)), "testmempoolaccept", {{hex}, 0})
    assert.is_true(r.result[1].allowed)
    assert.equal(100, r.result[1].vsize)
    assert.is_truthy(r.result[1].fees)
    assert.is_nil(r.result[1]["reject-reason"])
  end)
  it("fees carry Core's 8-decimal effective-feerate and the wtxid in effective-includes", function()
    local hex, tx = tx_hex()
    -- 10000 sat at 110 vB: CFeeRate = 10000 * 1000 / 110 = 90909 sat/kvB
    local r = call(server(stub_mempool(10000, 110)), "testmempoolaccept", {{hex}, 0})
    local fees = r.result[1].fees
    assert.equal(0.00090909, fees["effective-feerate"])
    assert.equal(0.0001, fees.base)
    assert.same({r.result[1].wtxid}, fees["effective-includes"])
    assert.equal(types.hash256_hex(validation.compute_wtxid(tx)), fees["effective-includes"][1])
  end)
  it("default cap still reports max-fee-exceeded", function()
    local hex = tx_hex()
    local r = call(server(stub_mempool(100000000, 100)), "testmempoolaccept", {{hex}})
    assert.is_false(r.result[1].allowed)
    assert.equal("max-fee-exceeded", r.result[1]["reject-reason"])
  end)
  it("refuses a non-amount maxfeerate with -3 Invalid amount", function()
    local hex = tx_hex()
    is_err(call(server(stub_mempool(1000, 100)), "testmempoolaccept", {{hex}, "x"}),
           -3, "Invalid amount")
  end)
end)

-- testmempoolaccept on two or more txs goes through process_new_package.
-- Stub: every member validates at its own fee and vsize.
local function stub_package_mempool(members)
  local m = {entries = {}}
  function m:process_new_package(txs, test_accept)
    local results = {}
    for i, tx in ipairs(txs) do
      local wtxid = types.hash256_hex(validation.compute_wtxid(tx))
      local f = members[i]
      results[wtxid] = {
        kind = "valid", fee = f.fee, vsize = f.vsize,
        effective_feerate = math.floor(f.fee * 1000 / f.vsize),
        effective_includes = {wtxid},
      }
    end
    return nil, results
  end
  return m
end

-- Two distinct txs; the stub does not look at what they spend.
local function pair_hex()
  local a = tx_hex()
  local prev = types.outpoint(types.hash256(string.rep("\3", 32)), 0)
  local tx = types.transaction(2,
    {types.txin(prev, "", 0xfffffffd)},
    {types.txout(40000, "\0\20" .. string.rep("\4", 20))}, 0)
  return a, rpc.hex_encode(serialize.serialize_transaction(tx, true))
end

describe("testmempoolaccept maxfeerate on a package", function()
  -- Parent pays 0.9 BTC at 200 vB (450 BTC/kvB); the child pays 1,000 sat.
  local members = {{fee = 90000000, vsize = 200}, {fee = 1000, vsize = 100}}

  it("maxfeerate 0 means no cap: both members allowed", function()
    local parent, child = pair_hex()
    local r = call(server(stub_package_mempool(members)), "testmempoolaccept",
                   {{parent, child}, 0})
    assert.is_true(r.result[1].allowed)
    assert.is_nil(r.result[1]["reject-reason"])
    assert.equal(200, r.result[1].vsize)
    assert.is_true(r.result[2].allowed)
  end)

  it("control: omitting maxfeerate applies 0.10 BTC/kvB to the parent", function()
    local parent, child = pair_hex()
    local r = call(server(stub_package_mempool(members)), "testmempoolaccept",
                   {{parent, child}})
    assert.is_false(r.result[1].allowed)
    assert.equal("max-fee-exceeded", r.result[1]["reject-reason"])
    -- Core stops at the first max-fee-exceeded: the child gets no verdict.
    assert.is_nil(r.result[2].allowed)
  end)

  -- Core v31.1 measured on regtest (staged-patches/core-getfee/probe.sh):
  -- fee 3001 at vsize 110 is allowed at 0.00027281 BTC/kvB (27281 * 110 /
  -- 1000 = 3000.91, GetFee rounds UP to 3001) and refused at 0.00027272
  -- (2999.92 -> 3000).
  it("the cap is GetFee(vsize) rounded up, as Core v31.1 answers", function()
    local parent, child = pair_hex()
    local m = {{fee = 3001, vsize = 110}, {fee = 1000, vsize = 100}}
    local r = call(server(stub_package_mempool(m)), "testmempoolaccept",
                   {{parent, child}, 0.00027281})
    assert.is_true(r.result[1].allowed)
    assert.is_true(r.result[2].allowed)
    r = call(server(stub_package_mempool(m)), "testmempoolaccept",
             {{parent, child}, 0.00027272})
    assert.is_false(r.result[1].allowed)
    assert.equal("max-fee-exceeded", r.result[1]["reject-reason"])
  end)
end)

describe("testmempoolaccept maxfeerate on one tx", function()
  it("the cap is GetFee(vsize) rounded up, as Core v31.1 answers", function()
    local hex = tx_hex()
    local r = call(server(stub_mempool(3001, 110)), "testmempoolaccept", {{hex}, 0.00027281})
    assert.is_true(r.result[1].allowed)
    assert.equal(110, r.result[1].vsize)
    r = call(server(stub_mempool(3001, 110)), "testmempoolaccept", {{hex}, 0.00027272})
    assert.is_false(r.result[1].allowed)
    assert.equal("max-fee-exceeded", r.result[1]["reject-reason"])
    assert.is_nil(r.result[1].vsize)
  end)
end)

describe("CFeeRate::GetFee", function()
  local mempool = require("lunarblock.mempool")
  it("rounds up, matching Core v31.1 (EvaluateFeeUp)", function()
    assert.equal(3001, mempool.fee_for_rate(27281, 110))
    assert.equal(3001, mempool.fee_for_rate(27280, 110))
    assert.equal(3000, mempool.fee_for_rate(27272, 110))
    assert.equal(3001, mempool.fee_for_rate(27273, 110))  -- 3000.03
    assert.equal(1, mempool.fee_for_rate(1, 1))
    assert.equal(0, mempool.fee_for_rate(0, 110))
    assert.equal(0, mempool.fee_for_rate(27281, 0))
  end)
end)

-- The cap on a REAL mempool.  Core's BroadcastTransaction test-accept never
-- commits, so a tx refused for its fee leaves the pool exactly as it was.
-- lunarblock's test-accept removes BIP125 conflicts (and trims) before the
-- new tx is dropped again, so the cap must be checked before any eviction.
describe("sendrawtransaction maxfeerate on a real mempool", function()
  local mempool = require("lunarblock.mempool")
  local P2PKH = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"
  local prev = types.hash256(string.rep("\x07", 32))

  local function real_mempool()
    local utxos = {
      [types.hash256_hex(prev) .. ":0"] = {
        value = 10000000, script_pubkey = P2PKH, height = 500000, is_coinbase = false,
      },
    }
    local chain_state = {
      coin_view = {
        get = function(_, txid, vout) return utxos[types.hash256_hex(txid) .. ":" .. vout] end,
      },
      tip_height = 700000,
    }
    return mempool.new(chain_state)
  end

  -- Spends prev:0, RBF-signaling, paying 10,000,000 - out_value sat.
  local function spend(out_value)
    local tx = types.transaction(1,
      {types.txin(types.outpoint(prev, 0), "", 0xfffffffd)},
      {types.txout(out_value, P2PKH)}, 0)
    return tx, rpc.hex_encode(serialize.serialize_transaction(tx, false)),
           types.hash256_hex(validation.compute_txid(tx))
  end

  it("a refused high-fee replacement leaves the original in the pool", function()
    local mp = real_mempool()
    local orig = spend(9995000)                    -- 5,000 sat fee
    local ok, orig_txid = mp:accept_transaction(orig)
    assert.is_true(ok, tostring(orig_txid))

    -- 2,000,000 sat at well under 1,000 vB: far over 0.10 BTC/kvB.
    local _, repl_hex, repl_txid = spend(8000000)
    is_err(call(server(mp), "sendrawtransaction", {repl_hex}), -25,
           "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)")
    assert.is_not_nil(mp.entries[orig_txid])
    assert.is_nil(mp.entries[repl_txid])
    assert.equal(1, mp.tx_count)
  end)

  it("a replacement under the cap still replaces the original", function()
    local mp = real_mempool()
    local orig = spend(9995000)
    local ok, orig_txid = mp:accept_transaction(orig)
    assert.is_true(ok, tostring(orig_txid))

    local _, repl_hex, repl_txid = spend(9990000)  -- 10,000 sat fee
    local r = call(server(mp), "sendrawtransaction", {repl_hex})
    assert.equal(repl_txid, r.result)
    assert.is_nil(mp.entries[orig_txid])
    assert.is_not_nil(mp.entries[repl_txid])
  end)

  it("maxfeerate 0 lets the high-fee replacement through", function()
    local mp = real_mempool()
    local orig = spend(9995000)
    local ok, orig_txid = mp:accept_transaction(orig)
    assert.is_true(ok, tostring(orig_txid))

    local _, repl_hex, repl_txid = spend(8000000)
    local r = call(server(mp), "sendrawtransaction", {repl_hex, 0})
    assert.equal(repl_txid, r.result)
    assert.is_nil(mp.entries[orig_txid])
  end)

  -- BroadcastTransaction answers a tx already in the pool at step 1, before
  -- the fee cap: the txid comes back even when the tx's fee is over the cap,
  -- and the resubmit does not put it in the unbroadcast set.
  it("a tx already in the pool is answered before the cap", function()
    local mp = real_mempool()
    local tx, hex, txid = spend(8000000)           -- 2,000,000 sat: over 0.10 BTC/kvB
    local ok, err = mp:accept_transaction(tx)
    assert.is_true(ok, tostring(err))
    local r = call(server(mp), "sendrawtransaction", {hex})
    assert.is_truthy(r.error == nil or r.error == cjson.null)
    assert.equal(txid, r.result)
    assert.is_nil(mp.unbroadcast[txid])
    assert.equal(1, mp.tx_count)
  end)

  it("the mempool's cap is GetFee(vsize): equal passes, one sat over refuses", function()
    -- Directly on accept_transaction, against the sigop-adjusted vsize.
    local mp = real_mempool()
    local probe = spend(9995000)
    local vsize = validation.get_virtual_tx_size(validation.get_tx_weight(probe), 0,
                                                 mempool.DEFAULT_BYTES_PER_SIGOP)
    -- 5,000 sat fee; a cap whose GetFee(vsize) is exactly 5,000 passes...
    local per_kvb = math.ceil(5000 * 1000 / vsize)
    while mempool.fee_for_rate(per_kvb, vsize) > 5000 do per_kvb = per_kvb - 1 end
    assert.equal(5000, mempool.fee_for_rate(per_kvb, vsize))
    local ok, err = mp:accept_transaction(probe, nil, {max_fee_per_kvb = per_kvb})
    assert.is_true(ok, tostring(err))
    -- ...and a cap one sat/kvB lower (GetFee < 5,000) refuses a fresh pool.
    local mp2 = real_mempool()
    local lower = per_kvb
    while mempool.fee_for_rate(lower, vsize) >= 5000 do lower = lower - 1 end
    local ok2, err2 = mp2:accept_transaction(probe, nil, {max_fee_per_kvb = lower})
    assert.is_false(ok2)
    assert.equal(mempool.MAX_FEE_EXCEEDED, err2)
    assert.equal(0, mp2.tx_count)
  end)
end)
