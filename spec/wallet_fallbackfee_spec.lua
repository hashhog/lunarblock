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

-- Warden review of lunarblock#27: send's error code, -fallbackfee parsing
-- (Core ParseMoney), the GetMinimumFeeRate floor, and CFeeRate::GetFee
-- round-up.
describe("wallet -fallbackfee (Core parity)", function()
  local wallet, consensus, types, crypto, rpc, ops, main
  local w

  local function fund(wl, values)
    local addr = wl.addresses[1]
    local total = 0
    for i, v in ipairs(values) do
      local txid = types.hash256(string.rep(string.char(i), 32))
      wl.utxos[txid.bytes .. "\x00\x00\x00\x00"] = {
        value = v,
        script_pubkey = "\x00\x14" .. crypto.hash160(wl.keys[addr].pubkey),
        address = addr, txid = txid, vout = 0,
        height = 100, confirmations = 100, is_coinbase = false,
      }
      total = total + v
    end
    wl.balance = total
  end

  local function fake_mempool(min_fee_kvb, relay_kvb)
    return {
      min_relay_fee = relay_kvb or 100,
      get_min_fee = function() return min_fee_kvb end,
    }
  end

  setup(function()
    setup_loader()
    wallet = require("lunarblock.wallet")
    consensus = require("lunarblock.consensus")
    types = require("lunarblock.types")
    crypto = require("lunarblock.crypto")
    rpc = require("lunarblock.rpc")
    ops = require("lunarblock.ops")
    main = require("lunarblock.main")
  end)

  before_each(function()
    wallet.fallback_fee_rate = nil
    wallet.fee_estimator = nil
    wallet.mempool = nil
    local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    w = wallet.from_seed(seed, consensus.networks.regtest, nil)
  end)

  after_each(function()
    wallet.fallback_fee_rate = nil
    wallet.fee_estimator = nil
    wallet.mempool = nil
  end)

  -- 1. Core `send` goes through FundTransaction -> RPC_WALLET_ERROR (-4);
  -- only sendtoaddress/sendmany (SendMoney) use -6.
  it("send returns -4 when estimation fails and no fallbackfee", function()
    fund(w, {100000})
    local server = rpc.new({network = consensus.networks.regtest, wallet = w})
    local addr = w:get_new_address()
    local ok, err = pcall(server.methods["send"], server, {{[addr] = 0.0005}})
    assert.is_false(ok)
    assert.equals(-4, err.code)
    assert.equals(wallet.FEE_ESTIMATION_FAILED, err.message)
  end)

  -- 3. GetMinimumFeeRate: fallback (or estimate) raised to the mempool
  -- minimum fee, then to the required fee max(-mintxfee, relay minimum).
  it("raises the fallback fee to the mempool minimum fee", function()
    wallet.fallback_fee_rate = 2           -- 2000 sat/kvB
    wallet.mempool = fake_mempool(5000)    -- mempool min 5000 sat/kvB
    assert.equals(5, w:estimate_fee_rate(6))
  end)

  it("raises the fallback fee to the relay minimum when that is above -mintxfee", function()
    wallet.fallback_fee_rate = 2
    wallet.mempool = fake_mempool(0, 3000)
    assert.equals(3, w:estimate_fee_rate(6))
  end)

  it("raises the fallback fee to Core's default -mintxfee (1000 sat/kvB)", function()
    wallet.fallback_fee_rate = 0.5
    wallet.mempool = fake_mempool(0, 100)
    assert.equals(1, w:estimate_fee_rate(6))
  end)

  it("a disabled fallback still fails even when the mempool minimum is set", function()
    wallet.mempool = fake_mempool(5000)
    local rate, err = w:estimate_fee_rate(6)
    assert.is_nil(rate)
    assert.equals(wallet.FEE_ESTIMATION_FAILED, err)
  end)

  it("an explicit fee_rate is not raised to the mempool minimum", function()
    fund(w, {100000})
    wallet.mempool = fake_mempool(5000)
    local tx, fee = w:create_transaction({{address = w:get_new_address(), amount = 50000}},
                                         {fee_rate = 2})
    assert.is_not_nil(tx)
    assert.equals(141 * 2, fee)  -- 11 + 68 + 2*31 vB at 2 sat/vB, not 5
  end)

  -- CFeeRate::GetFee: ceil(fee_per_kvb * vsize / 1000) in integers. 2.075
  -- sat/vB * 240 vB is 498 exactly; the float product rounds up to 499.
  it("rounds the fee up like CFeeRate::GetFee, without float overshoot", function()
    fund(w, {40000, 40000})
    local tx, fee = w:create_transaction({
      {address = w:get_new_address(), amount = 30000},
      {address = w:get_new_address(), amount = 30000},
    }, {fee_rate = 2.075})
    assert.is_not_nil(tx)
    assert.equals(2, #tx.inputs)
    assert.equals(498, fee)
  end)

  -- 2. -fallbackfee parsing: Core ParseMoney, from the CLI and the config file.
  describe("ParseMoney", function()
    local cases = {
      {"0.0002", 20000}, {" 0.0002 ", 20000}, {"\t1\n", 100000000},
      {"0", 0}, {"1.", 100000000}, {".5", 50000000},
      {"0.00000001", 1}, {"21000000", 2100000000000000},
      {"1e2", nil}, {"0.000000001", nil}, {"12345678901", nil},
      {"21000000.00000001", nil}, {"0.0002\0", nil}, {"-1", nil},
      {"", nil}, {"   ", nil}, {"abc", nil}, {"1 0", nil}, {"+1", nil},
      {"0x10", nil}, {"1,5", nil},
    }
    for _, c in ipairs(cases) do
      it(string.format("%q -> %s", c[1], tostring(c[2])), function()
        assert.equals(c[2], ops.parse_money(c[1]))
      end)
    end
  end)

  describe("startup", function()
    local real_exit, real_stderr, stderr_buf

    before_each(function()
      real_exit, real_stderr = os.exit, io.stderr
      stderr_buf = {}
      os.exit = function(code) error({exit_code = code}, 0) end
      io.stderr = { write = function(_, ...)
        for _, s in ipairs({...}) do stderr_buf[#stderr_buf + 1] = tostring(s) end
      end }
    end)

    after_each(function()
      os.exit, io.stderr = real_exit, real_stderr
    end)

    local function refused(argv, value)
      local ok, err = pcall(main.parse_args, argv)
      assert.is_false(ok)
      assert.equals(1, type(err) == "table" and err.exit_code or err)
      assert.truthy(table.concat(stderr_buf):find(
        "Invalid amount for -fallbackfee=<amount>: '" .. value .. "'", 1, true))
    end

    for _, v in ipairs({"1e2", "0.000000001", "12345678901", "21000001", "abc", "-1", ""}) do
      it("refuses --fallbackfee=" .. v .. " on the command line", function()
        refused({"--regtest", "--fallbackfee=" .. v}, v)
      end)
    end

    it("refuses a bad fallbackfee= in the config file", function()
      local path = os.tmpname()
      local f = assert(io.open(path, "w"))
      f:write("fallbackfee=1e2\n")
      f:close()
      local ok_r, e = pcall(refused, {"--regtest", "--conf=" .. path}, "1e2")
      os.remove(path)
      assert(ok_r, e)
    end)

    it("takes a valid fallbackfee= from the config file", function()
      local path = os.tmpname()
      local f = assert(io.open(path, "w"))
      f:write("fallbackfee=0.0002\n")
      f:close()
      local ok_p, args = pcall(main.parse_args, {"--regtest", "--conf=" .. path})
      os.remove(path)
      assert(ok_p, args)
      assert.equals(20000, args.fallbackfee_kvb)
    end)

    it("trims the CLI value like ParseMoney", function()
      local args = main.parse_args({"--regtest", "--fallbackfee= 0.0002 "})
      assert.equals(20000, args.fallbackfee_kvb)
      assert.equals("", table.concat(stderr_buf))
    end)

    it("starts with a warning above HIGH_TX_FEE_PER_KB", function()
      local args = main.parse_args({"--regtest", "--fallbackfee=0.02"})
      assert.equals(2000000, args.fallbackfee_kvb)
      assert.truthy(table.concat(stderr_buf):find(
        "-fallbackfee is set very high! This is the transaction fee you may " ..
        "pay when fee estimates are not available.", 1, true))
    end)

    it("does not warn at exactly HIGH_TX_FEE_PER_KB", function()
      local args = main.parse_args({"--regtest", "--fallbackfee=0.01"})
      assert.equals(1000000, args.fallbackfee_kvb)
      assert.is_nil(table.concat(stderr_buf):find("set very high", 1, true))
    end)
  end)
end)
