-- Mempool entry accounting as Core v31.1 reports it (rpc/mempool.cpp
-- entryToJSON): ancestor/descendant count, size and fees INCLUDE the entry
-- itself and sum MODIFIED fees (txmempool.cpp CalculateAncestorData /
-- CalculateDescendantData); depends is the
-- sorted set of in-pool parents; spentby the in-pool children, sorted by txid
-- byte order (txmempool.cpp GetChildren, CompareIteratorByHash).

local types = require("lunarblock.types")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local mempool = require("lunarblock.mempool")
local rpc = require("lunarblock.rpc")
local cjson = require("cjson")

local SCRIPT = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"  -- P2PKH: IsStandard
local COIN = consensus.COIN

local function fund(value)
  local prev_txid = types.hash256(string.rep("\xab", 32))
  local prev_hex = types.hash256_hex(prev_txid)
  local view = {
    utxos = {
      [prev_hex .. ":0"] = {
        value = value, script_pubkey = SCRIPT, height = 500000, is_coinbase = false,
      },
    },
    get = function(self, txid, vout)
      return self.utxos[types.hash256_hex(txid) .. ":" .. vout]
    end,
  }
  local mp = mempool.new({ coin_view = view, tip_height = 700000 })
  return mp, prev_txid
end

local function spend(prev_txid, vout, outputs)
  local outs = {}
  for i, v in ipairs(outputs) do outs[i] = types.txout(v, SCRIPT) end
  return types.transaction(1,
    { types.txin(types.outpoint(prev_txid, vout), "", 0xFFFFFFFE) }, outs, 0)
end

local function txid_of(tx) return validation.compute_txid(tx) end
local function hex_of(tx) return types.hash256_hex(txid_of(tx)) end

local function call(server, method, params)
  local body = server:handle_request(cjson.encode({ method = method, params = params, id = 1 }))
  local resp = cjson.decode(body)
  assert.equal(cjson.null, resp.error)
  return resp.result, body
end

-- uint256 operator< is a memcmp of the stored (little-endian) bytes, so
-- display hex sorts by its byte-reversed form.
local function byte_order_key(h)
  local t = {}
  for i = #h - 1, 1, -2 do t[#t + 1] = h:sub(i, i + 1) end
  return table.concat(t)
end

local function close(a, b) return math.abs(a - b) < 1e-12 end

describe("mempool entry accounting (Core v31.1 entryToJSON)", function()
  describe("CPFP pair", function()
    local mp, server, p_hex, c_hex, pe, ce

    before_each(function()
      local prev
      mp, prev = fund(100000)
      local parent = spend(prev, 0, { 100000 - 200 })
      assert(mp:accept_transaction(parent))
      local child = spend(txid_of(parent), 0, { 100000 - 200 - 20000 })
      assert(mp:accept_transaction(child))
      p_hex, c_hex = hex_of(parent), hex_of(child)
      pe, ce = mp.entries[p_hex], mp.entries[c_hex]
      server = rpc.new({ network = consensus.networks.mainnet, mempool = mp })
    end)

    it("parent counts itself in ancestors and the child in descendants", function()
      local r = call(server, "getmempoolentry", { p_hex })
      assert.equal(1, r.ancestorcount)
      assert.equal(pe.vsize, r.ancestorsize)
      assert.is_true(close(200 / COIN, r.fees.ancestor))
      assert.equal(2, r.descendantcount)
      assert.equal(pe.vsize + ce.vsize, r.descendantsize)
      assert.is_true(close(20200 / COIN, r.fees.descendant))
    end)

    it("child counts the parent and itself", function()
      local r = call(server, "getmempoolentry", { c_hex })
      assert.equal(2, r.ancestorcount)
      assert.equal(pe.vsize + ce.vsize, r.ancestorsize)
      assert.is_true(close(20200 / COIN, r.fees.ancestor))
      assert.equal(1, r.descendantcount)
      assert.equal(ce.vsize, r.descendantsize)
      assert.is_true(close(20000 / COIN, r.fees.descendant))
    end)

    it("depends and spentby name the edge, and empty ones are JSON arrays", function()
      local rp, body_p = call(server, "getmempoolentry", { p_hex })
      local rc, body_c = call(server, "getmempoolentry", { c_hex })
      assert.same({ c_hex }, rp.spentby)
      assert.same({ p_hex }, rc.depends)
      assert.truthy(body_p:find('"depends":[]', 1, true))
      assert.truthy(body_c:find('"spentby":[]', 1, true))
    end)

    it("empty depends/spentby are [] even under a cjson without empty_array_mt", function()
      -- The node loads the system lua-cjson 2.1.0, which has no
      -- empty_array_mt: an empty Lua table there encodes as {}.
      local saved = cjson.empty_array_mt
      cjson.empty_array_mt = nil
      local ok, body_p = pcall(function() return select(2, call(server, "getmempoolentry", { p_hex })) end)
      local ok2, body_all = pcall(function() return select(2, call(server, "getrawmempool", { true })) end)
      cjson.empty_array_mt = saved
      assert.is_true(ok, body_p)
      assert.is_true(ok2, body_all)
      assert.truthy(body_p:find('"depends":[]', 1, true))
      assert.falsy(body_p:find('"depends":{}', 1, true))
      assert.falsy(body_all:find('"depends":{}', 1, true))
      assert.falsy(body_all:find('"spentby":{}', 1, true))
    end)

    it("ancestor/descendant fees use the modified fee", function()
      mp:prioritise_transaction(p_hex, 1000)
      local r = call(server, "getmempoolentry", { c_hex })
      assert.is_true(close(21200 / COIN, r.fees.ancestor))
      local rp = call(server, "getmempoolentry", { p_hex })
      assert.is_true(close(1200 / COIN, rp.fees.ancestor))
      assert.is_true(close(21200 / COIN, rp.fees.descendant))
    end)

    it("getrawmempool verbose reports the same entries", function()
      local all = call(server, "getrawmempool", { true })
      for _, h in ipairs({ p_hex, c_hex }) do
        local one = call(server, "getmempoolentry", { h })
        assert.same(one, all[h])
      end
    end)

    it("a connected block confirming the parent leaves the child alone", function()
      local parent_tx = mp.entries[p_hex].tx
      mp:on_block_connected({ transactions = { parent_tx } })
      local r = call(server, "getmempoolentry", { c_hex })
      assert.equal(1, r.ancestorcount)
      assert.equal(ce.vsize, r.ancestorsize)
      assert.same({}, r.depends)
    end)
  end)

  describe("parent with 63 in-pool children (warden_e shape)", function()
    local CHILDREN = 63
    local PARENT_FEE = 10000
    local mp, server, p_hex, kids

    before_each(function()
      local prev
      mp, prev = fund(64 * 100000 + PARENT_FEE)
      local outs = {}
      for i = 1, 64 do outs[i] = 100000 end
      local parent = spend(prev, 0, outs)
      assert(mp:accept_transaction(parent))
      p_hex = hex_of(parent)
      kids = {}
      for i = 1, CHILDREN do
        local fee = (i + 1) * 1000
        local child = spend(txid_of(parent), i, { 100000 - fee })
        assert(mp:accept_transaction(child))
        kids[i] = { hex = hex_of(child), fee = fee }
      end
      server = rpc.new({ network = consensus.networks.mainnet, mempool = mp })
    end)

    it("parent: 64 descendants including itself, spentby in byte order", function()
      local r = call(server, "getmempoolentry", { p_hex })
      local pe = mp.entries[p_hex]
      local size, fees = pe.vsize, PARENT_FEE
      local expect = {}
      for i = 1, CHILDREN do
        size = size + mp.entries[kids[i].hex].vsize
        fees = fees + kids[i].fee
        expect[i] = kids[i].hex
      end
      table.sort(expect, function(a, b) return byte_order_key(a) < byte_order_key(b) end)
      assert.equal(1, r.ancestorcount)
      assert.equal(CHILDREN + 1, r.descendantcount)
      assert.equal(size, r.descendantsize)
      assert.is_true(close(fees / COIN, r.fees.descendant))
      assert.same(expect, r.spentby)
    end)
  end)
end)
