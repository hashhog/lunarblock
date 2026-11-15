-- getrawmempool on an empty pool is a JSON array in Core (rpc/mempool.cpp
-- MempoolToJSON: UniValue::VARR for verbose=false, VOBJ for verbose=true).
-- The node tagged the empty table with cjson.empty_array_mt, but the lua-cjson
-- 2.1.0 on the production LUA_CPATH (/usr/lib/x86_64-linux-gnu/lua/5.1) has no
-- empty_array_mt, so the table went out as `{}` (core-regtest rows
-- warden_c/c-reconsider/txids:$ and warden_f/f-conflict/txids:$, core [] vs
-- node {}). This spec removes empty_array_mt/array_mt to reproduce that cjson
-- and checks the bytes on the wire, not the decoded Lua table (which cannot
-- tell [] from {}).

local rpc = require("lunarblock.rpc")
local consensus = require("lunarblock.consensus")
local cjson = require("cjson")

describe("getrawmempool empty pool encoding", function()
  local saved_array_mt, saved_empty_array_mt
  before_each(function()
    saved_array_mt, saved_empty_array_mt = cjson.array_mt, cjson.empty_array_mt
    cjson.array_mt, cjson.empty_array_mt = nil, nil
  end)
  after_each(function()
    cjson.array_mt, cjson.empty_array_mt = saved_array_mt, saved_empty_array_mt
  end)

  local function call(server, params)
    local body = cjson.encode({ jsonrpc = "1.0", id = 1, method = "getrawmempool",
                                params = params })
    return server:handle_request(body)
  end

  local function empty_pool_server()
    return rpc.new({
      network = consensus.networks.regtest,
      mempool = {
        entries = {},
        get_raw_mempool = function() return {} end,
        chunk_feerates = function() return {} end,
      },
    })
  end

  it("emits [] for an empty mempool (non-verbose)", function()
    local resp = call(empty_pool_server(), {})
    assert.is_truthy(resp:find('"result":[]', 1, true), resp)
    assert.is_nil(resp:find('"result":{}', 1, true), resp)
  end)

  it("emits [] when the node has no mempool object (non-verbose)", function()
    local resp = call(rpc.new({ network = consensus.networks.regtest }), {})
    assert.is_truthy(resp:find('"result":[]', 1, true), resp)
  end)

  it("keeps {} for an empty mempool when verbose", function()
    local resp = call(empty_pool_server(), { true })
    assert.is_truthy(resp:find('"result":{}', 1, true), resp)
    resp = call(rpc.new({ network = consensus.networks.regtest }), { true })
    assert.is_truthy(resp:find('"result":{}', 1, true), resp)
  end)

  it("still lists txids for a non-empty pool", function()
    local server = rpc.new({
      network = consensus.networks.regtest,
      mempool = {
        entries = {},
        get_raw_mempool = function() return { "aa", "bb" } end,
      },
    })
    local resp = call(server, {})
    local decoded = cjson.decode(resp)
    assert.same({ "aa", "bb" }, decoded.result)
  end)
end)
