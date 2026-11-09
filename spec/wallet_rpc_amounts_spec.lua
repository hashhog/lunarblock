-- Wallet RPC amounts are ValueFromAmount numbers in Core (core_io.cpp:
-- "%s%d.%08d"), used by getbalance, getbalances, listunspent and
-- gettransaction (wallet/rpc/coins.cpp, wallet/rpc/transactions.cpp). So a
-- whole 50 BTC goes out as 50.00000000, a JSON real. lunarblock returned
-- sats / 1e8 as a Lua number, which cjson writes as the JSON integer 50; the
-- Core regtest wallet group compares types and reported every such field.
-- These specs read the bytes on the wire, not the Lua table.

local function hex_to_bin(hex)
  return (hex:gsub('..', function(cc) return string.char(tonumber(cc, 16)) end))
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

describe("wallet RPC amounts are Core fixed-8 reals", function()
  local wallet, consensus, types, crypto, rpc, cjson
  local w, server

  setup(function()
    setup_loader()
    wallet = require("lunarblock.wallet")
    consensus = require("lunarblock.consensus")
    types = require("lunarblock.types")
    crypto = require("lunarblock.crypto")
    rpc = require("lunarblock.rpc")
    cjson = require("cjson")
  end)

  local function add_coin(byte, value, confirmations, is_coinbase)
    local addr = w.addresses[1]
    local txid = types.hash256(string.rep(string.char(byte), 32))
    w.utxos[txid.bytes .. "\x00\x00\x00\x00"] = {
      value = value,
      script_pubkey = "\x00\x14" .. crypto.hash160(w.keys[addr].pubkey),
      address = addr, txid = txid, vout = 0,
      height = 1, confirmations = confirmations, is_coinbase = is_coinbase,
    }
  end

  before_each(function()
    local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    w = wallet.from_seed(seed, consensus.networks.regtest, nil)
    add_coin(1, 5000000000, 101, true)   -- one mature 50 BTC coinbase
    add_coin(2, 100000000, 3, false)     -- 1 BTC
    w.spendable_balance = 5100000000
    w.confirmed_balance = 5100000000
    w.unconfirmed_balance = 0
    server = rpc.new({ network = consensus.networks.regtest, wallet = w })
  end)

  local function call(method, params)
    local body = cjson.encode({ jsonrpc = "1.0", id = 1, method = method, params = params or {} })
    return server:handle_request(body)
  end

  it("getbalance writes 51.00000000, not 51", function()
    local resp = call("getbalance")
    assert.is_truthy(resp:find('"result":51.00000000', 1, true), resp)
  end)

  it("getbalances writes every mine amount fixed-8", function()
    local resp = call("getbalances")
    assert.is_truthy(resp:find('"trusted":51.00000000', 1, true), resp)
    assert.is_truthy(resp:find('"untrusted_pending":0.00000000', 1, true), resp)
    assert.is_truthy(resp:find('"immature":0.00000000', 1, true), resp)
    local decoded = cjson.decode(resp)
    assert.is_table(decoded.result.lastprocessedblock)
  end)

  it("listunspent writes each amount fixed-8", function()
    local resp = call("listunspent")
    assert.is_truthy(resp:find('"amount":50.00000000', 1, true), resp)
    assert.is_truthy(resp:find('"amount":1.00000000', 1, true), resp)
    assert.is_nil(resp:find('"amount":50[,}]'), resp)
    assert.equals(2, #cjson.decode(resp).result)
  end)

  it("gettransaction writes amount, fee and details amounts fixed-8", function()
    local txid = string.rep("ab", 32)
    w.get_transaction_detail = function(_, id)
      if id ~= txid then return nil end
      return {
        amount = 1, fee = -0.0000141, confirmations = 1, txid = txid,
        details = {
          { category = "send", amount = -1, fee = -0.0000141, vout = 0 },
          { category = "receive", amount = 1, vout = 0 },
        },
      }
    end
    local resp = call("gettransaction", { txid })
    local decoded = cjson.decode(resp)
    assert.is_table(decoded.result, resp)
    assert.is_truthy(resp:find('"amount":1.00000000', 1, true), resp)
    assert.is_truthy(resp:find('"amount":-1.00000000', 1, true), resp)
    assert.is_truthy(resp:find('"fee":-0.00001410', 1, true), resp)
    assert.equals(2, #decoded.result.details)
  end)
end)
