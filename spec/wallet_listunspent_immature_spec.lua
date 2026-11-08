-- listunspent leaves immature coinbase outputs out, as Core does:
--   if (wallet.IsTxImmatureCoinBase(wtx) && !params.include_immature_coinbase)
--       continue;
-- (bitcoin-core/src/wallet/spend.cpp AvailableCoins; listunspent's
-- include_immature_coinbase query option defaults to false,
-- wallet/rpc/coins.cpp). lunarblock listed every immature coinbase with
-- spendable=false, so a regtest wallet that mined 101 blocks showed 101 coins
-- where Core shows 1, and the minimum confirmation count was 1, not 101.

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

describe("listunspent and immature coinbase", function()
  local wallet, consensus, types, crypto, rpc, cjson
  local w

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
    add_coin(1, 5000000000, 101, true)  -- mature: COINBASE_MATURITY + 1 confirmations
    add_coin(2, 5000000000, 100, true)  -- immature: one block short
    add_coin(3, 5000000000, 1, true)    -- immature: just mined
    add_coin(4, 100000000, 1, false)    -- a 1-conf non-coinbase coin is listed
  end)

  it("Wallet:list_unspent drops immature coinbases by default", function()
    local rows = w:list_unspent(false)
    assert.equals(2, #rows)
    local confs = {}
    for _, r in ipairs(rows) do confs[#confs + 1] = r.confirmations end
    table.sort(confs)
    assert.same({1, 101}, confs)
    for _, r in ipairs(rows) do assert.is_true(r.spendable) end
  end)

  it("include_immature_coinbase lists them again, spendable as Core reports", function()
    -- Core listunspent: "Any coins we list are always spendable".
    local rows = w:list_unspent(false, true)
    assert.equals(4, #rows)
    for _, r in ipairs(rows) do assert.is_true(r.spendable) end
  end)

  it("listunspent RPC returns only the mature coinbase and the 1-conf coin", function()
    local server = rpc.new({ network = consensus.networks.regtest, wallet = w })
    local body = cjson.encode({ jsonrpc = "1.0", id = 1, method = "listunspent", params = {} })
    local resp = server:handle_request(body)
    local decoded = cjson.decode(resp)
    assert.is_table(decoded.result)
    assert.equals(2, #decoded.result)
    for _, e in ipairs(decoded.result) do
      assert.is_true(e.spendable)
      assert.is_true(e.confirmations == 1 or e.confirmations == 101)
    end
  end)
end)
