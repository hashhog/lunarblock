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

describe("getbalances key set matches Core", function()
  local wallet, consensus, rpc, cjson

  setup(function()
    setup_loader()
    wallet = require("lunarblock.wallet")
    consensus = require("lunarblock.consensus")
    rpc = require("lunarblock.rpc")
    cjson = require("cjson")
  end)

  -- Core wallet/rpc/coins.cpp getbalances emits only "mine" and
  -- "lastprocessedblock"; the old "watchonly" object was removed (watch-only
  -- funds count under mine). The Core regtest wallet group saw an extra third
  -- key (wallet/receive/getbalances:keys[2] = watchonly).
  it("returns only mine and lastprocessedblock", function()
    local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    local w = wallet.from_seed(seed, consensus.networks.regtest, nil)
    local server = rpc.new({ network = consensus.networks.regtest, wallet = w })
    local resp = server:handle_request(cjson.encode(
      { jsonrpc = "1.0", id = 1, method = "getbalances", params = {} }))
    local result = cjson.decode(resp).result
    assert.is_table(result, resp)
    local keys = {}
    for k in pairs(result) do keys[#keys + 1] = k end
    table.sort(keys)
    assert.same({ "lastprocessedblock", "mine" }, keys)
    assert.is_nil(result.watchonly)
  end)
end)
