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

    -- Regression: total_work is a 32-byte big-endian string on a real chain
    -- (consensus.work_zero/work_add), not the float that work_for_bits
    -- produces, so `work_top - work_bot` raised a Lua arithmetic error and
    -- getnetworkhashps answered -32603 with a source path for EVERY mainnet
    -- call.  Proven live on 2026-08-29 against the deployed node.
    it("computes a hashrate when total_work is the 32-byte binary form", function()
      local types = require("lunarblock.types")
      -- storage returns wrapped hash256 values (types.hash256), which is what
      -- the handler hands to types.hash256_hex.
      local h_top = types.hash256(string.rep("\1", 32))
      local h_bot = types.hash256(string.rep("\2", 32))
      local top_work = consensus.work_from_hex(string.rep("0", 48) .. "0000000000010000")
      local bot_work = consensus.work_from_hex(string.rep("0", 64))
      local srv = rpc.new({
        network = consensus.networks.mainnet,
        chain_state = {tip_height = 200},
        storage = {
          get_hash_by_height = function(h) return (h == 200) and h_top or h_bot end,
          get_header = function(hh)
            return {timestamp = (hh == h_top) and 2000 or 1000, bits = 0x1d00ffff}
          end,
        },
        header_chain = {headers = {
          [types.hash256_hex(h_top)] = {total_work = top_work},
          [types.hash256_hex(h_bot)] = {total_work = bot_work},
        }},
      })
      local resp = rpc_call(srv, "getnetworkhashps", {120})
      assert.equal(cjson.null, resp.error)
      assert.equal(65, resp.result)  -- floor(0x10000 / (2000-1000))
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

-- ==========================================================================
-- #41 round: the SAME width rule on the methods that already rejected, but
-- with their own later error instead of Core's conversion error.
--
-- Core's getInt<T> fails in the CONVERSION, so an out-of-int32 argument never
-- reaches the lookup or the domain test. These five answered -5 "Block not
-- found" / -8 "Block height out of range" / -32602 instead of -1.
-- ==========================================================================

describe("#41 conversion beats the later error", function()
  local function range_err(method, params)
    local resp = rpc_call(server(), method, params)
    assert.is_truthy(resp.error and resp.error ~= cjson.null)
    assert.equal(rpc.ERROR.MISC_ERROR, resp.error.code)
    assert.equal("JSON integer out of range", resp.error.message)
  end

  it("getblockhash height converts before the -8 range test", function()
    for _, v in ipairs(OUT_OF_INT32) do range_err("getblockhash", {v}) end
  end)

  it("getblock verbosity converts before the block lookup", function()
    for _, v in ipairs(OUT_OF_INT32) do
      range_err("getblock", {string.rep("a", 64), v})
    end
  end)

  it("getrawtransaction verbosity converts before the tx lookup", function()
    for _, v in ipairs(OUT_OF_INT32) do
      range_err("getrawtransaction", {string.rep("a", 64), v})
    end
  end)

  it("getchaintxstats nblocks converts before the -8 domain test", function()
    -- Needs a storage/chain_state stub: this handler checks "Storage not
    -- available" before it reads nblocks, so a bare server never reaches the
    -- conversion. (Core does the conversion in RPCHelpMan, i.e. before the
    -- handler body runs at all — a nuance no measurement here covers, so the
    -- handler order is left as the codebase has it.)
    local srv = rpc.new({
      network = consensus.networks.mainnet,
      chain_state = {tip_height = 10, tip_hash = string.rep("\0", 32)},
      storage = {get_hash_by_height = function() return nil end,
                 get_header = function() return nil end},
    })
    for _, v in ipairs(OUT_OF_INT32) do
      local resp = rpc_call(srv, "getchaintxstats", {v})
      assert.is_truthy(resp.error and resp.error ~= cjson.null)
      assert.equal(rpc.ERROR.MISC_ERROR, resp.error.code)
      assert.equal("JSON integer out of range", resp.error.message)
    end
  end)

  it("createmultisig nrequired converts before the keys array is read", function()
    -- Core answers -1 even though keys is ALSO empty: the conversion runs
    -- first. This previously reported the empty-keys error.
    for _, v in ipairs(OUT_OF_INT32) do range_err("createmultisig", {v, {}}) end
  end)

  -- CONTROL: in-range values must still get PAST the conversion and reach the
  -- handler. This suite builds a bare server with no chainstate, so what the
  -- handler then says varies ("Chain state not available") — the assertion
  -- that carries meaning is that it is NOT the conversion error. Without this,
  -- a handler that answered -1 for every value would satisfy all five cases
  -- above.
  it("CONTROL an in-range height gets past the conversion", function()
    local resp = rpc_call(server(), "getblockhash", {999999999})
    assert.is_truthy(resp.error and resp.error ~= cjson.null)
    assert.are_not.equal("JSON integer out of range", resp.error.message)
  end)

  it("CONTROL int32 boundary values are accepted by the conversion", function()
    for _, v in ipairs({2147483647, -2147483648}) do
      local resp = rpc_call(server(), "getblockhash", {v})
      assert.are_not.equal("JSON integer out of range", resp.error.message)
    end
  end)

  it("CONTROL an in-range verbosity still reaches the block lookup", function()
    local resp = rpc_call(server(), "getblock", {string.rep("a", 64), 1})
    assert.is_truthy(resp.error and resp.error ~= cjson.null)
    assert.are_not.equal("JSON integer out of range", resp.error.message)
  end)
end)

-- ==========================================================================
-- setban: two defects the differential's CONTROLS found, not its hostile cases.
-- ==========================================================================

describe("#41 setban parity", function()
  local function srv_with_peers()
    local pm = {
      bans = {},
      is_banned = function(self, k) return self.bans[k] == true end,
      ban_peer = function(self, k, _d) self.bans[k] = true end,
    }
    return rpc.new({network = consensus.networks.mainnet, peer_manager = pm})
  end

  it("an absolute bantime in the past is REJECTED, not clamped to 1s", function()
    -- The code carried a comment asserting Core "treats absolute-in-the-past
    -- as a no-op insert". Core actually answers -8 here.
    local resp = rpc_call(srv_with_peers(), "setban", {"1.2.3.4", "add", 1, true})
    assert.is_truthy(resp.error and resp.error ~= cjson.null)
    assert.equal(rpc.ERROR.INVALID_PARAMETER, resp.error.code)
    assert.equal("Error: Absolute timestamp is in the past", resp.error.message)
  end)

  it("re-banning answers Core's -23, not the generic -1", function()
    local s = srv_with_peers()
    local first = rpc_call(s, "setban", {"1.2.3.4", "add", 3600})
    assert.equal(cjson.null, first.error)
    local again = rpc_call(s, "setban", {"1.2.3.4", "add", 3600})
    assert.is_truthy(again.error and again.error ~= cjson.null)
    assert.equal(rpc.ERROR.CLIENT_NODE_ALREADY_ADDED, again.error.code)
    assert.equal("Error: IP/Subnet already banned", again.error.message)
  end)

  it("CONTROL a future absolute bantime is still accepted", function()
    local future = os.time() + 86400
    local resp = rpc_call(srv_with_peers(), "setban", {"1.2.3.4", "add", future, true})
    assert.equal(cjson.null, resp.error)
  end)
end)
