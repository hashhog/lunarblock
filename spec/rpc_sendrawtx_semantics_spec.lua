local rpc = require("lunarblock.rpc")
local types = require("lunarblock.types")
local consensus = require("lunarblock.consensus")
local serialize = require("lunarblock.serialize")
local validation = require("lunarblock.validation")
local cjson = require("cjson")

-- sendrawtransaction error mapping vs Core v31.1 BroadcastTransaction
-- (node/transaction.cpp) and sendrawtransaction (rpc/rawtransaction.cpp).
describe("sendrawtransaction result mapping", function()
  local tx = {
    version = 2,
    inputs = {{
      prev_out = {hash = types.hash256(string.rep("\x01", 32)), index = 0},
      script_sig = "\x00", sequence = 0xFFFFFFFE, witness = {},
    }},
    outputs = {{
      value = 50000,
      script_pubkey = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac",
    }},
    locktime = 0,
    segwit = false,
  }
  local txid_hex = types.hash256_hex(validation.compute_txid(tx))
  local hex = rpc.hex_encode(serialize.serialize_transaction(tx, false))

  -- reject == nil means the mempool accepts the tx.  Returns the decoded
  -- response, the txids passed to add_unbroadcast, and the relayed messages.
  local function send_with(reject)
    local unbroadcast, relayed = {}, {}
    local mempool = {
      entries = {},
      has = function() return false end,
      accept_transaction = function()
        if reject == nil then return true, txid_hex end
        return false, reject
      end,
      remove_transaction = function() end,
      add_unbroadcast = function(_, id) unbroadcast[#unbroadcast + 1] = id end,
    }
    local peer_manager = {
      broadcast = function(_, cmd) relayed[#relayed + 1] = cmd end,
    }
    local server = rpc.new({network = consensus.networks.mainnet,
      mempool = mempool, peer_manager = peer_manager})
    local response = server:handle_request(
      '{"method":"sendrawtransaction","params":["' .. hex .. '"],"id":1}')
    return cjson.decode(response), unbroadcast, relayed
  end

  it("a newly accepted tx is marked unbroadcast and relayed", function()
    local d, unbroadcast, relayed = send_with(nil)
    assert.truthy(d.error == nil or d.error == cjson.null)
    assert.equal(txid_hex, d.result)
    assert.same({txid_hex}, unbroadcast)
    assert.same({"inv"}, relayed)
  end)

  -- Core BroadcastTransaction only calls AddUnbroadcastTx on the branch that
  -- just inserted the tx; the already-in-mempool branch only reannounces.
  it("resubmitting a tx already in the mempool returns its txid", function()
    local d, unbroadcast, relayed = send_with("txn-already-in-mempool")
    assert.truthy(d.error == nil or d.error == cjson.null)
    assert.equal(txid_hex, d.result)
    assert.same({}, unbroadcast)
    assert.same({"inv"}, relayed)
  end)

  it("resubmitting a same-txid tx already in the mempool returns its txid", function()
    local d, unbroadcast, relayed = send_with("txn-same-nonwitness-data-in-mempool")
    assert.truthy(d.error == nil or d.error == cjson.null)
    assert.equal(txid_hex, d.result)
    assert.same({}, unbroadcast)
    assert.same({"inv"}, relayed)
  end)

  it("a confirmed tx is refused with -27 'Transaction outputs already in utxo set'", function()
    local d = send_with("txn-already-known")
    assert.is_not_nil(d.error)
    assert.equal(-27, d.error.code)
    assert.equal("Transaction outputs already in utxo set", d.error.message)
  end)

  it("missing inputs is refused with -25 and the reject token", function()
    local d = send_with("bad-txns-inputs-missingorspent")
    assert.is_not_nil(d.error)
    assert.equal(-25, d.error.code)
    assert.equal("bad-txns-inputs-missingorspent", d.error.message)
  end)

  it("other policy rejects stay -26", function()
    local d = send_with("min relay fee not met")
    assert.is_not_nil(d.error)
    assert.equal(-26, d.error.code)
  end)
end)
