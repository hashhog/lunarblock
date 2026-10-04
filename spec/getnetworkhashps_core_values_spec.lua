-- getnetworkhashps VALUE parity with Bitcoin Core (rpc/mining.cpp
-- GetNetworkHashPS, :65-104).
--
-- Chain: a deterministic 110-block regtest chain.  Block h has
--   time = 1296688602 + 600*h + (h*7919 mod 300)
-- and every block (genesis included) has bits 0x207fffff, so
-- chainwork(h) = 2*(h+1).  The expected values were read from a scratch
-- regtest Core v31.99 that mined exactly this chain under setmocktime
-- (2026-10-04).
--
-- Before the fix every row returned 0: the handler math.floor()ed a ~3.3e-3
-- H/s rate, used only the two endpoint timestamps instead of Core's min/max
-- over the window, and subtracted float chainworks.

local cjson = require("cjson")
local rpc = require("lunarblock.rpc")
local consensus = require("lunarblock.consensus")
local types = require("lunarblock.types")

local TIP = 110
local function time_at(h) return 1296688602 + 600 * h + (h * 7919) % 300 end
local function hash_at(h) return types.hash256(string.char(h % 256) .. string.rep("\165", 31)) end
local function work_be(n)
  return consensus.work_from_hex(string.format("%064x", n))
end

local function make_server(with_header_chain)
  local by_hex, headers = {}, {}
  for h = 0, TIP do
    local hh = hash_at(h)
    by_hex[types.hash256_hex(hh)] = h
    headers[types.hash256_hex(hh)] = {total_work = work_be(2 * (h + 1))}
  end
  return rpc.new({
    network = consensus.networks.regtest,
    chain_state = {tip_height = TIP},
    storage = {
      get_hash_by_height = function(h)
        if h >= 0 and h <= TIP then return hash_at(h) end
      end,
      get_header = function(hh)
        local h = by_hex[types.hash256_hex(hh)]
        if h then return {timestamp = time_at(h), bits = 0x207fffff} end
      end,
    },
    header_chain = with_header_chain and {headers = headers} or nil,
  })
end

local function rpc_call(srv, method, params)
  local body = srv:handle_request(cjson.encode({
    method = method, params = params, id = 1,
  }))
  return cjson.decode(body)
end

-- {nblocks, height, Core's answer}
local CORE = {
  {120, -1, 0.00332376491917208},   -- lookup clamps to 110: walks to genesis
  {120, 50, 0.003305785123966942},  -- the R5 probe shape: nblocks >= height
  {50, 50, 0.003305785123966942},
  {49, 50, 0.003318546612034811},
  {10, 50, 0.00333889816360601},
  {1, 1, 0.002781641168289291},
  {-1, -1, 0.00332376491917208},
  {-1, 30, 0.003284072249589491},
  {1000, 110, 0.00332376491917208},
  {110, 110, 0.00332376491917208},
  {109, 110, 0.003329718501321196},
  {3, 100, 0.003231017770597738},
}

for _, mode in ipairs({
  {name = "chainwork from the header chain", hc = true},
  {name = "chainwork from the window's bits", hc = false},
}) do
  describe("getnetworkhashps == Core on a regtest chain (" .. mode.name .. ")", function()
    local srv = make_server(mode.hc)
    for _, v in ipairs(CORE) do
      local nb, ht, want = v[1], v[2], v[3]
      it(string.format("getnetworkhashps %d %d == %.16g", nb, ht, want), function()
        local resp = rpc_call(srv, "getnetworkhashps", {nb, ht})
        assert.equal(cjson.null, resp.error)
        assert.equal("number", type(resp.result))
        -- cjson encodes 14 significant digits, so compare the wire value
        -- to Core's at that precision.
        assert.is_true(math.abs(resp.result - want) <= 1e-13 * want)
      end)
    end
    it("height 0 returns 0 (Core: !pb->nHeight)", function()
      assert.equal(0, rpc_call(srv, "getnetworkhashps", {120, 0}).result)
    end)
  end)
end
