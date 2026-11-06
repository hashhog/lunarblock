-- getpeerinfo `inflight` and `permissions` are JSON arrays in Core
-- (src/rpc/net.cpp: UniValue::VARR).  The node tagged an empty Lua table with
-- cjson.array_mt, but the lua-cjson 2.1.0 on the production LUA_CPATH
-- (/usr/lib/x86_64-linux-gnu/lua/5.1) has no array_mt, so the empty table went
-- out as `{}`.  This spec removes array_mt to reproduce that cjson and checks
-- the bytes on the wire, not the Lua table.

local rpc = require("lunarblock.rpc")
local consensus = require("lunarblock.consensus")
local cjson = require("cjson")

describe("getpeerinfo empty arrays", function()
  local saved_array_mt, saved_empty_array_mt
  before_each(function()
    saved_array_mt, saved_empty_array_mt = cjson.array_mt, cjson.empty_array_mt
    cjson.array_mt, cjson.empty_array_mt = nil, nil
  end)
  after_each(function()
    cjson.array_mt, cjson.empty_array_mt = saved_array_mt, saved_empty_array_mt
  end)

  local function call(peers)
    local server = rpc.new({
      network = consensus.networks.regtest,
      peer_manager = { peer_list = peers },
    })
    local body = cjson.encode({ jsonrpc = "1.0", id = 1, method = "getpeerinfo", params = {} })
    local resp = server:handle_request(body)
    return resp
  end

  it("emits inflight and permissions as [] for a connected peer", function()
    local resp = call({ { ip = "10.1.2.3", port = 18444, services = 9,
                          inbound = false, latency_ms = 5 } })
    assert.is_truthy(resp:find('"inflight":%[%]'), resp)
    assert.is_truthy(resp:find('"permissions":%[%]'), resp)
    assert.is_nil(resp:find('"inflight":{}', 1, true), resp)
    assert.is_nil(resp:find('"permissions":{}', 1, true), resp)
  end)

  it("keeps the empty per-message maps as objects", function()
    local resp = call({ { ip = "10.1.2.3", port = 18444, services = 9,
                          inbound = true, latency_ms = 5 } })
    assert.is_truthy(resp:find('"bytessent_per_msg":{}', 1, true), resp)
    assert.is_truthy(resp:find('"bytesrecv_per_msg":{}', 1, true), resp)
  end)

  it("passes a '%' in a peer string through unchanged", function()
    local resp = call({ { ip = "10.1.2.3", port = 18444, services = 9,
                          inbound = false, latency_ms = 5,
                          user_agent = "/x%d%1/" } })
    assert.is_truthy(resp:find("x%d%1", 1, true), resp)
    assert.is_truthy(resp:find('"inflight":%[%]'), resp)
  end)

  it("returns [] with no peers", function()
    local resp = call({})
    assert.is_truthy(resp:find('"result":%[%]'), resp)
  end)
end)
