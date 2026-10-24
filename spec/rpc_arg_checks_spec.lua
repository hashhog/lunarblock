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
local function stub_mempool(fee, vsize)
  local m = {entries = {}, accepted = 0}
  function m:accept_to_memory_pool(tx, test_accept)
    return {accepted = true, fee = fee, vsize = vsize}
  end
  function m:accept_transaction(tx)
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
