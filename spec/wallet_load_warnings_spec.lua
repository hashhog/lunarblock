-- createwallet / loadwallet / unloadwallet / restorewallet put "warnings" in
-- the result only when there is at least one, like Core (rpc/util.cpp
-- PushWarnings: `if (warnings.empty()) return;`; wallet/rpc/wallet.cpp
-- createwallet/loadwallet/unloadwallet, wallet/rpc/backup.cpp restorewallet).
-- lunarblock always sent `warnings = {}`, which the system lua-cjson 2.1.0
-- also encoded as an object (core-regtest row wallet/create/wallet:warnings,
-- core <missing> vs node {}). The spec removes cjson's empty_array_mt /
-- array_mt to reproduce that cjson and checks the bytes on the wire.

local rpc = require("lunarblock.rpc")
local consensus = require("lunarblock.consensus")
local cjson = require("cjson")

describe("wallet-load RPCs omit empty warnings (Core PushWarnings)", function()
  local saved_array_mt, saved_empty_array_mt
  local scratch

  setup(function()
    scratch = os.tmpname()
    os.remove(scratch)
    assert(os.execute("mkdir -p '" .. scratch .. "'"))
  end)
  teardown(function()
    if scratch and scratch:match("^/tmp/lua_") then
      os.execute("rm -rf '" .. scratch .. "'")
    end
  end)

  before_each(function()
    saved_array_mt, saved_empty_array_mt = cjson.array_mt, cjson.empty_array_mt
    cjson.array_mt, cjson.empty_array_mt = nil, nil
  end)
  after_each(function()
    cjson.array_mt, cjson.empty_array_mt = saved_array_mt, saved_empty_array_mt
  end)

  local function fake_wallet()
    return { mark_dirty = function() end, save_if_dirty = function() end }
  end

  local function server()
    local manager = {
      wallets = {},
      create_wallet = function() return fake_wallet() end,
      load_wallet = function() return fake_wallet() end,
      unload_wallet = function() return true end,
      get_wallet = function() return nil end,
      get_default_wallet = function() return nil, "" end,
      get_wallet_dir = function(_, n) return scratch .. "/" .. n end,
      get_wallet_path = function(_, n) return scratch .. "/" .. n .. "/wallet.json" end,
    }
    return rpc.new({ network = consensus.networks.regtest, wallet_manager = manager })
  end

  local function call(method, params)
    local body = cjson.encode({ jsonrpc = "1.0", id = 1, method = method, params = params })
    local resp = server():handle_request(body)
    local decoded = cjson.decode(resp)
    assert.is_true(decoded.error == cjson.null, resp)
    return resp, decoded.result
  end

  it("createwallet has no warnings key when there are none", function()
    local resp, result = call("createwallet", { "w1" })
    assert.equals("w1", result.name)
    assert.is_nil(resp:find('"warnings"', 1, true), resp)
  end)

  it("createwallet keeps a real warning as a JSON array", function()
    local resp = call("createwallet", { "w2", false, false, "" })
    assert.is_truthy(resp:find(
      '"warnings":["Empty string given as passphrase, wallet will not be encrypted."]',
      1, true), resp)
  end)

  it("loadwallet has no warnings key when there are none", function()
    local resp, result = call("loadwallet", { "w1" })
    assert.equals("w1", result.name)
    assert.is_nil(resp:find('"warnings"', 1, true), resp)
  end)

  it("unloadwallet returns {} with no warnings key", function()
    local resp = call("unloadwallet", { "w1" })
    assert.is_truthy(resp:find('"result":{}', 1, true), resp)
  end)

  it("restorewallet has no warnings key when there are none", function()
    local backup = scratch .. "/backup.json"
    local f = assert(io.open(backup, "wb")); f:write("{}"); f:close()
    local resp, result = call("restorewallet", { "restored", backup })
    assert.equals("restored", result.name)
    assert.is_nil(resp:find('"warnings"', 1, true), resp)
  end)
end)
