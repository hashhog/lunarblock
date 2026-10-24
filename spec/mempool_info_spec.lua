-- getmempoolinfo / GET /rest/mempool/info.json against Core v31.1's
-- MempoolInfoToJSON (bitcoin-core/src/rpc/mempool.cpp:1043) and
-- CTxMemPool::DynamicMemoryUsage (txmempool.cpp:778).
--
-- The usage figures below were MEASURED on a Core v31.1 regtest node
-- (wallet-built P2WPKH 1-in-1-out txs, 72-byte signature) with
-- tools/core-regtest's pinned bitcoind: one tx 1176, two independent 2320,
-- three 3512, five 5896; a parent/child pair 2456 when the child pays a lower
-- feerate (two chunks) and 2392 when it pays more (one chunk); an emptied pool
-- 64 because txns_randomized keeps its capacity; a six-tx descending chain 7016.
local types = require("lunarblock.types")
local mempool = require("lunarblock.mempool")
local validation = require("lunarblock.validation")
local rpc = require("lunarblock.rpc")
local rest = require("lunarblock.rest")
local consensus = require("lunarblock.consensus")
local cjson = require("cjson")

describe("getmempoolinfo", function()
  local P2WPKH = "\x00\x14" .. string.rep("\x11", 20)

  local function make_chain_state()
    return {
      tip_height = 700000,
      coin_view = {
        utxos = {},
        get = function(self, txid, vout)
          return self.utxos[types.hash256_hex(txid) .. ":" .. vout]
        end,
      },
    }
  end

  local function fund(cs, tag, value)
    local txid = types.hash256(string.rep(string.char(tag), 32))
    cs.coin_view.utxos[types.hash256_hex(txid) .. ":0"] = {
      value = value, script_pubkey = P2WPKH, height = 500000, is_coinbase = false,
    }
    return txid
  end

  -- 1-in-1-out P2WPKH spend with a 72-byte signature and 33-byte pubkey.
  local function p2wpkh_spend(prev_txid, prev_vout, out_value)
    local tx = types.transaction(2, {}, {}, 0)
    tx.inputs[1] = types.txin(types.outpoint(prev_txid, prev_vout), "", 0xFFFFFFFD)
    tx.inputs[1].witness = { string.rep("\x30", 72), "\x02" .. string.rep("\x22", 32) }
    tx.outputs[1] = types.txout(out_value, P2WPKH)
    tx.segwit = true
    return tx
  end

  local function accept(mp, tx)
    local ok, res = mp:accept_transaction(tx)
    assert.is_true(ok, tostring(res))
    return res
  end

  it("counts bytes as the sum of virtual sizes, not serialized bytes", function()
    local cs = make_chain_state()
    local mp = mempool.new(cs)
    accept(mp, p2wpkh_spend(fund(cs, 1, 100000), 0, 90000))
    local info = mp:get_info()
    local entry = next(mp.entries) and mp.entries[next(mp.entries)]
    assert.equal(entry.vsize, info.bytes)
    assert.is_true(entry.size > entry.vsize)
  end)

  it("reports Core's memory-usage estimate for one transaction", function()
    local cs = make_chain_state()
    local mp = mempool.new(cs)
    accept(mp, p2wpkh_spend(fund(cs, 1, 100000), 0, 90000))
    assert.equal(1176, mp:get_info().usage)
  end)

  it("counts a long scriptSig but not a long scriptPubKey, as Core does", function()
    -- Measured on Core v31.1: a 1-in P2PKH spend (106-byte scriptSig, no
    -- witness) is 1080; a P2WSH / P2TR output (34 bytes) costs nothing extra.
    local cs = make_chain_state()
    local mp = mempool.new(cs)
    local txid = types.hash256(string.rep("\x05", 32))
    cs.coin_view.utxos[types.hash256_hex(txid) .. ":0"] = {
      value = 100000, script_pubkey = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac",
      height = 500000, is_coinbase = false,
    }
    local tx = types.transaction(2, {}, {}, 0)
    tx.inputs[1] = types.txin(types.outpoint(txid, 0), "\x4c\x68" .. string.rep("\x30", 104), 0xFFFFFFFD)
    tx.outputs[1] = types.txout(90000, "\x00\x20" .. string.rep("\x11", 32))
    accept(mp, tx)
    assert.equal(1080, mp:get_info().usage)
  end)

  it("tracks txns_randomized capacity across independent transactions", function()
    local cs = make_chain_state()
    local mp = mempool.new(cs)
    local want = { 1176, 2320, 3512, 4624, 5896 }
    for i = 1, 5 do
      accept(mp, p2wpkh_spend(fund(cs, i, 100000), 0, 90000))
      assert.equal(want[i], mp:get_info().usage)
    end
    -- Core shrinks the vector while under half full and clear()s the last
    -- element without releasing capacity: an emptied pool still costs 64.
    for hex in pairs(mp.entries) do mp:remove_transaction(hex, "test") end
    assert.equal(0, mp.tx_count)
    assert.equal(64, mp:get_info().usage)
  end)

  it("costs a parent/child cluster by size and chunk count", function()
    local function chain(parent_out, child_out)
      local cs = make_chain_state()
      local mp = mempool.new(cs)
      local parent = p2wpkh_spend(fund(cs, 1, 100000), 0, parent_out)
      accept(mp, parent)
      accept(mp, p2wpkh_spend(validation.compute_txid(parent), 0, child_out))
      return mp
    end
    -- child pays less than the parent: two chunks
    assert.equal(2456, chain(90000, 85000):get_info().usage)
    -- child pays more than the parent: CPFP merges them into one chunk
    assert.equal(2392, chain(95000, 70000):get_info().usage)
  end)

  it("counts locally submitted txs as unbroadcast until a peer asks", function()
    local cs = make_chain_state()
    local mp = mempool.new(cs)
    local a = accept(mp, p2wpkh_spend(fund(cs, 1, 100000), 0, 90000))
    local b = accept(mp, p2wpkh_spend(fund(cs, 2, 100000), 0, 90000))
    assert.equal(0, mp:get_info().unbroadcastcount)
    mp:add_unbroadcast(a)
    mp:add_unbroadcast(a)
    mp:add_unbroadcast(b)
    assert.equal(2, mp:get_info().unbroadcastcount)
    mp:remove_unbroadcast(a)
    assert.equal(1, mp:get_info().unbroadcastcount)
    mp:remove_transaction(b, "test")   -- leaving the pool clears it too
    assert.equal(0, mp:get_info().unbroadcastcount)
    mp:add_unbroadcast("ff")           -- not in the pool: ignored
    assert.equal(0, mp:get_info().unbroadcastcount)
  end)

  it("decays mempoolminfee against the (mockable) mempool clock", function()
    local cs = make_chain_state()
    local mp = mempool.new(cs)
    mempool.set_mock_time(1700000000)
    mp.rolling_minimum_fee_rate = 10000
    mp.last_rolling_fee_update = 1700000000
    mp.block_since_last_rolling_fee_bump = true
    assert.equal(10000, mp:get_min_fee())
    -- pool is empty (< 1/4 full): half-life is 12h / 4 = 3h
    mempool.set_mock_time(1700000000 + 3 * 3600)
    local decayed = mp:get_min_fee()
    mempool.set_mock_time(0)
    assert.is_true(math.abs(decayed - 5000) < 1)
  end)

  describe("JSON body", function()
    local FIELDS = {
      "loaded", "size", "bytes", "usage", "total_fee", "maxmempool",
      "mempoolminfee", "minrelaytxfee", "incrementalrelayfee",
      "unbroadcastcount", "fullrbf", "permitbaremultisig", "maxdatacarriersize",
      "limitclustercount", "limitclustersize", "optimal",
    }

    local function pool_with_one_tx()
      local cs = make_chain_state()
      local mp = mempool.new(cs)
      local txid = accept(mp, p2wpkh_spend(fund(cs, 1, 100000), 0, 90000))
      mp:add_unbroadcast(txid)
      return mp
    end

    it("REST carries every Core field with the RPC's values", function()
      local mp = pool_with_one_tx()
      local server = rpc.new({ network = consensus.networks.regtest, mempool = mp })
      local response = server:handle_request('{"method":"getmempoolinfo","params":[],"id":1}')
      local rpc_body = cjson.decode(response).result
      local raw = rest.new({ mempool = mp }):route("GET", "/rest/mempool/info.json")
      local rest_body = cjson.decode(raw:sub(raw:find("\r\n\r\n") + 4))
      for _, f in ipairs(FIELDS) do
        assert.is_not_nil(rest_body[f], "REST is missing " .. f)
        assert.is_not_nil(rpc_body[f], "RPC is missing " .. f)
        assert.same(rpc_body[f], rest_body[f], f)
      end
      assert.equal(1, rest_body.unbroadcastcount)
      assert.equal(1176, rest_body.usage)
    end)
  end)
end)
