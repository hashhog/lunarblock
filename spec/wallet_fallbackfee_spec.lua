-- Core-style -fallbackfee for the wallet (bitcoin-core/src/wallet/fees.cpp
-- GetMinimumFeeRate; spend.cpp maps a failed CreateTransaction to -6).
-- Before: create_transaction/sendtoaddress silently used a hardcoded 1 sat/vB
-- whenever the estimator had no data.

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

describe("wallet -fallbackfee", function()
  local wallet, consensus, types, crypto, rpc
  local w

  setup(function()
    setup_loader()
    wallet = require("lunarblock.wallet")
    consensus = require("lunarblock.consensus")
    types = require("lunarblock.types")
    crypto = require("lunarblock.crypto")
    rpc = require("lunarblock.rpc")
  end)

  before_each(function()
    wallet.fallback_fee_rate = nil
    wallet.fee_estimator = nil
    local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    w = wallet.from_seed(seed, consensus.networks.regtest, nil)
    local addr = w.addresses[1]
    local fake_txid = types.hash256(string.rep("\x01", 32))
    w.utxos[fake_txid.bytes .. "\x00\x00\x00\x00"] = {
      value = 100000,
      script_pubkey = "\x00\x14" .. crypto.hash160(w.keys[addr].pubkey),
      address = addr, txid = fake_txid, vout = 0,
      height = 100, confirmations = 100, is_coinbase = false,
    }
    w.balance = 100000
  end)

  after_each(function()
    wallet.fallback_fee_rate = nil
    wallet.fee_estimator = nil
  end)

  it("create_transaction fails like Core with no estimate and no fallbackfee", function()
    local tx, err = w:create_transaction({{address = w:get_new_address(), amount = 50000}})
    assert.is_nil(tx)
    assert.equals("Fee estimation failed. Fallbackfee is disabled. " ..
                  "Wait a few blocks or enable -fallbackfee.", err)
  end)

  it("an explicit fee_rate needs neither estimator nor fallbackfee", function()
    local tx = w:create_transaction({{address = w:get_new_address(), amount = 50000}},
                                    {fee_rate = 2})
    assert.is_not_nil(tx)
  end)

  it("with fallbackfee the fee is vsize * fallback rate, not 1 sat/vB", function()
    wallet.fallback_fee_rate = 20  -- --fallbackfee=0.0002 BTC/kvB
    local tx, fee = w:create_transaction({{address = w:get_new_address(), amount = 50000}})
    assert.is_not_nil(tx)
    -- ~110 vB at 20 sat/vB; a 1 sat/vB fee would be < 200.
    assert.is_true(fee >= 1500)
  end)

  it("sendtoaddress returns -6 when estimation fails and no fallbackfee", function()
    local server = rpc.new({network = consensus.networks.regtest, wallet = w})
    local addr = w:get_new_address()
    local ok, err = pcall(server.methods["sendtoaddress"], server, {addr, 0.0005})
    assert.is_false(ok)
    assert.equals(-6, err.code)
    assert.truthy(err.message:find("Fee estimation failed. Fallbackfee is disabled", 1, true))
  end)

  it("sendtoaddress gets past fee selection with fallbackfee set", function()
    wallet.fallback_fee_rate = 20
    local server = rpc.new({network = consensus.networks.regtest, wallet = w})
    local addr = w:get_new_address()
    local ok, err = pcall(server.methods["sendtoaddress"], server, {addr, 0.0005})
    if not ok then
      -- Without a mempool the broadcast step may fail; it must not be the fee error.
      assert.is_nil(tostring(type(err) == "table" and err.message or err):find("Fee estimation failed", 1, true))
    end
  end)
end)
