-- RPC integer-argument bounds: Core's getInt<T> parity.
--
-- Core reads numeric RPC arguments with UniValue::getInt<T>() (univalue.h),
-- which parses the JSON token with std::from_chars INTO THE DESTINATION WIDTH.
-- The width check therefore lives inside the conversion and fires BEFORE the
-- handler's own domain test:
--
--   out of the destination type, or fractional  -> std::runtime_error
--                                                  "JSON integer out of range"
--                                               -> RPC_MISC_ERROR (-1)
--   converts, but violates the handler's range  -> RPC_INVALID_PARAMETER (-8)
--
-- Before this pin, lunarblock accepted 24 out-of-int32 arguments across these
-- methods: the value was floored (or silently clamped) and the call SUCCEEDED,
-- answering a question the caller never asked.
--
-- Reference: bitcoin-core/src/univalue/include/univalue.h (getInt),
--            src/rpc/server.cpp (std::exception -> RPC_MISC_ERROR),
--            src/rpc/util.cpp (ParseConfirmTarget),
--            src/rpc/blockchain.cpp (gettxout n is getInt<uint32_t>),
--            src/rpc/net.cpp (getnodeaddresses count is getInt<int>).

local cjson = require("cjson")
local rpc = require("lunarblock.rpc")
local consensus = require("lunarblock.consensus")

local OUT_OF_INT32 = {2147483648, -2147483649, 4294967296, -4294967297}

local function server()
  return rpc.new({network = consensus.networks.mainnet})
end

-- handle_request returns TWO values (body, status_override); the extra one
-- would reach cjson.decode as a second argument, so bind the body first.
local function rpc_call(srv, method, params)
  local body = srv:handle_request(cjson.encode({
    method = method, params = params, id = 1,
  }))
  return cjson.decode(body)
end

-- NOTE: luassert's asserts take exactly one value -- a second positional arg
-- is an arity error, not a message -- so context lives in the test names.
local function assert_out_of_range(resp)
  assert.is_truthy(resp.error and resp.error ~= cjson.null)
  assert.equal(rpc.ERROR.MISC_ERROR, resp.error.code)
  assert.equal("JSON integer out of range", resp.error.message)
end

describe("RPC integer-argument bounds (Core getInt<T> parity)", function()

  describe("wait family timeout (getInt<int>)", function()
    it("rejects an out-of-int32 timeout on waitfornewblock", function()
      for _, v in ipairs(OUT_OF_INT32) do
        assert_out_of_range(rpc_call(server(), "waitfornewblock", {v}))
      end
    end)

    it("rejects an out-of-int32 timeout on waitforblock", function()
      local h = string.rep("a", 64)
      for _, v in ipairs(OUT_OF_INT32) do
        assert_out_of_range(rpc_call(server(), "waitforblock", {h, v}))
      end
    end)

    it("rejects a fractional timeout before the negative-timeout test", function()
      assert_out_of_range(rpc_call(server(), "waitfornewblock", {1.5}))
    end)

    it("still rejects an in-range negative timeout with Core's own message", function()
      local resp = rpc_call(server(), "waitfornewblock", {-1})
      assert.is_truthy(resp.error and resp.error ~= cjson.null)
      assert.equal(rpc.ERROR.MISC_ERROR, resp.error.code)
      assert.equal("Negative timeout", resp.error.message)
    end)
  end)

  describe("waitforblockheight height (getInt<int>)", function()
    it("rejects an out-of-int32 height", function()
      for _, v in ipairs(OUT_OF_INT32) do
        assert_out_of_range(rpc_call(server(), "waitforblockheight", {v}))
      end
    end)

    it("rejects an out-of-int32 timeout", function()
      for _, v in ipairs(OUT_OF_INT32) do
        assert_out_of_range(rpc_call(server(), "waitforblockheight", {1, v}))
      end
    end)
  end)

  describe("getnetworkhashps (Arg<int> nblocks/height)", function()
    it("rejects an out-of-int32 nblocks", function()
      for _, v in ipairs(OUT_OF_INT32) do
        assert_out_of_range(rpc_call(server(), "getnetworkhashps", {v}))
      end
    end)

    it("rejects an out-of-int32 height", function()
      for _, v in ipairs(OUT_OF_INT32) do
        assert_out_of_range(rpc_call(server(), "getnetworkhashps", {1, v}))
      end
    end)

    it("rejects nblocks == 0 and nblocks < -1 instead of clamping", function()
      for _, v in ipairs({0, -2, -1000}) do
        local resp = rpc_call(server(), "getnetworkhashps", {v})
        assert.is_truthy(resp.error and resp.error ~= cjson.null)
        assert.equal(rpc.ERROR.INVALID_PARAMETER, resp.error.code)
        assert.equal("Invalid nblocks. Must be a positive number or -1.", resp.error.message)
      end
    end)

    it("rejects a height above the tip instead of silently using the tip", function()
      local srv = rpc.new({
        network = consensus.networks.mainnet,
        chain_state = {tip_height = 5},
        storage = {get_hash_by_height = function() return nil end,
                   get_header = function() return nil end},
      })
      for _, v in ipairs({6, 99999999}) do
        local resp = rpc_call(srv, "getnetworkhashps", {120, v})
        assert.is_truthy(resp.error and resp.error ~= cjson.null)
        assert.equal(rpc.ERROR.INVALID_PARAMETER, resp.error.code)
        assert.equal("Block does not exist at specified height", resp.error.message)
      end
    end)

    it("accepts nblocks == -1 (since the last difficulty change)", function()
      local srv = rpc.new({
        network = consensus.networks.mainnet,
        chain_state = {tip_height = 5},
        storage = {get_hash_by_height = function() return nil end,
                   get_header = function() return nil end},
      })
      local resp = rpc_call(srv, "getnetworkhashps", {-1})
      assert.equal(cjson.null, resp.error)
    end)

    it("type-errors a non-number instead of falling back to the default", function()
      local resp = rpc_call(server(), "getnetworkhashps", {"120"})
      assert.is_truthy(resp.error and resp.error ~= cjson.null)
      assert.equal(rpc.ERROR.TYPE_ERROR, resp.error.code)
    end)
  end)

  describe("getnodeaddresses count (getInt<int>, then -8)", function()
    it("rejects an out-of-int32 count with the CONVERSION error", function()
      for _, v in ipairs(OUT_OF_INT32) do
        assert_out_of_range(rpc_call(server(), "getnodeaddresses", {v}))
      end
    end)

    it("keeps -8 for a negative count that converts fine", function()
      local resp = rpc_call(server(), "getnodeaddresses", {-1})
      assert.is_truthy(resp.error and resp.error ~= cjson.null)
      assert.equal(rpc.ERROR.INVALID_PARAMETER, resp.error.code)
      assert.equal("Address count out of range", resp.error.message)
    end)
  end)

  describe("estimatesmartfee / estimaterawfee conf_target (ParseConfirmTarget)", function()
    it("rejects an out-of-int32 conf_target before the domain test", function()
      for _, m in ipairs({"estimatesmartfee", "estimaterawfee"}) do
        for _, v in ipairs(OUT_OF_INT32) do
          assert_out_of_range(rpc_call(server(), m, {v}), m .. " conf_target " .. v)
        end
      end
    end)

    it("rejects an in-range conf_target above the highest tracked target", function()
      for _, m in ipairs({"estimatesmartfee", "estimaterawfee"}) do
        local resp = rpc_call(server(), m, {99999})
        assert.is_truthy(resp.error and resp.error ~= cjson.null)
        assert.equal(rpc.ERROR.INVALID_PARAMETER, resp.error.code)
        assert.equal("Invalid conf_target, must be between 1 and 1008", resp.error.message)
      end
    end)

    it("rejects conf_target below 1", function()
      for _, m in ipairs({"estimatesmartfee", "estimaterawfee"}) do
        local resp = rpc_call(server(), m, {0})
        assert.is_truthy(resp.error and resp.error ~= cjson.null)
        assert.equal(rpc.ERROR.INVALID_PARAMETER, resp.error.code)
      end
    end)

    -- Core validates estimate_mode with FeeModeFromString; lunarblock ignored
    -- the argument, so "" (and anything else) returned an estimate as though
    -- the default mode had been asked for.
    it("rejects an unknown estimate_mode instead of ignoring it", function()
      for _, m in ipairs({"", "garbage", "ECONOMICALLY"}) do
        local resp = rpc_call(server(), "estimatesmartfee", {1, m})
        assert.is_truthy(resp.error and resp.error ~= cjson.null)
        assert.equal(rpc.ERROR.INVALID_PARAMETER, resp.error.code)
        assert.equal('Invalid estimate_mode parameter, must be one of: "unset", "economical", "conservative"',
                     resp.error.message)
      end
    end)

    it("accepts the three fee modes case-insensitively", function()
      for _, m in ipairs({"unset", "economical", "CONSERVATIVE", "Economical"}) do
        local resp = rpc_call(server(), "estimatesmartfee", {1, m})
        assert.equal(cjson.null, resp.error)
      end
    end)

    it("still answers a valid conf_target", function()
      local resp = rpc_call(server(), "estimatesmartfee", {6})
      assert.equal(cjson.null, resp.error)
      assert.equal(6, resp.result.blocks)
    end)
  end)
end)
