-- getblocktemplate parity with Core 31.1 (rpc/mining.cpp getblocktemplate,
-- node/miner.cpp BlockAssembler).
--
--   * per-tx `sigops` is the mempool entry's GetSigOpCost(): prevout-aware
--     (legacy x4 + P2SH x4 + witness).  lunarblock hard-coded 0.
--   * the assembler's sigop budget starts at 400
--     (DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS) and counts that cost.
--   * a bare 1-of-1 multisig output is relayed under Core's default
--     -permitbaremultisig=1; lunarblock refused it ("bare-multisig"), so the
--     tx never reached the template (coinbasevalue 2000 sat short).
--   * no `coinbasetxn` (Core emits only coinbasevalue), `coinbaseaux` is an
--     empty object, and an empty `depends` is the JSON array [].
local types = require("lunarblock.types")
local mining = require("lunarblock.mining")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local mempool_mod = require("lunarblock.mempool")
local rpc = require("lunarblock.rpc")
local cjson = require("cjson")

local P2WPKH = "\x00\x14" .. string.rep("\x07", 20)
local P2PKH = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"
local BARE_1OF1 = "\x51\x21" .. string.rep("\x02", 33) .. "\x51\xae"

-- One chain state serving both the mempool (coin_view) and the template
-- builder (tip + storage.get_header for the MTP window).
local function make_chain_state()
  local cs = {
    tip_height = 200,
    tip_hash = types.hash256(string.rep("\xab", 32)),
    coin_view = { utxos = {} },
    storage = {
      get_header = function()
        return {
          version = 0x20000000,
          prev_hash = types.hash256_zero(),
          merkle_root = types.hash256_zero(),
          timestamp = 1700000000,
          bits = consensus.networks.regtest.pow_limit_bits,
          nonce = 0,
        }
      end,
    },
  }
  function cs.coin_view:get(txid, vout)
    return self.utxos[types.hash256_hex(txid) .. ":" .. vout]
  end
  return cs
end

local function add_utxo(cs, byte, value, spk)
  local txid = types.hash256(string.rep(byte, 32))
  cs.coin_view.utxos[types.hash256_hex(txid) .. ":0"] = {
    value = value, script_pubkey = spk, height = 100, is_coinbase = false,
  }
  return txid
end

local function spend(prev_txid, value, spk)
  return types.transaction(2,
    { types.txin(types.outpoint(prev_txid, 0), "", 0xFFFFFFFD) },
    { types.txout(value, spk) }, 0)
end

local function mock_entry(tx, fee, sigop_cost)
  local weight = validation.get_tx_weight(tx)
  return {
    tx = tx, txid = validation.compute_txid(tx), wtxid = validation.compute_wtxid(tx),
    fee = fee, weight = weight, vsize = math.ceil(weight / 4),
    sigop_cost = sigop_cost, ancestors = {}, ancestor_count = 0,
  }
end

local function mock_mempool(entries)
  local mp = { list = entries, map = {} }
  for _, e in ipairs(entries) do mp.map[types.hash256_hex(e.txid)] = e end
  function mp:get_sorted_entries() return self.list end
  function mp:has(h) return self.map[h] ~= nil end
  function mp:get_entry(h) return self.map[h] end
  return mp
end

describe("getblocktemplate Core parity", function()
  it("accepts a bare 1-of-1 multisig output under the default -permitbaremultisig", function()
    local cs = make_chain_state()
    local prev = add_utxo(cs, "\x31", 100000, P2PKH)
    local mp = mempool_mod.new(cs)
    local ok, err = mp:accept_transaction(spend(prev, 98000, BARE_1OF1))
    assert.is_true(ok, tostring(err))
  end)

  it("records the prevout-aware sigop cost on the mempool entry", function()
    local cs = make_chain_state()
    local prev = add_utxo(cs, "\x32", 100000, P2WPKH)
    local mp = mempool_mod.new(cs)
    local ok, txid_hex = mp:accept_transaction(spend(prev, 98000, P2WPKH))
    assert.is_true(ok, tostring(txid_hex))
    -- P2WPKH spend: no legacy sigops, one witness sigop (Core CountWitnessSigOps).
    assert.equal(1, mp:get_entry(txid_hex).sigop_cost)
  end)

  it("reports each template transaction's sigop cost, not 0", function()
    local cs = make_chain_state()
    local p1 = add_utxo(cs, "\x33", 100000, P2WPKH)
    local p2 = add_utxo(cs, "\x34", 100000, P2PKH)
    local mp = mempool_mod.new(cs)
    local ok1, h1 = mp:accept_transaction(spend(p1, 98000, P2WPKH))
    local ok2, h2 = mp:accept_transaction(spend(p2, 97000, P2PKH))
    assert.is_true(ok1, tostring(h1)); assert.is_true(ok2, tostring(h2))
    local t = mining.create_block_template(mp, cs, consensus.networks.regtest, "\x51")
    local by_txid = {}
    for _, e in ipairs(t.transactions) do by_txid[e.txid] = e end
    assert.equal(1, by_txid[h1].sigops)  -- witness sigop
    assert.equal(4, by_txid[h2].sigops)  -- legacy OP_CHECKSIG output x4
  end)

  it("budgets selection on the entry sigop cost with 400 reserved for the coinbase", function()
    local cs = make_chain_state()
    local net = consensus.networks.regtest
    local limit = consensus.MAX_BLOCK_SIGOPS_COST
    local tx = spend(types.hash256(string.rep("\x35", 32)), 9000, P2WPKH)
    -- 400 + cost >= limit is refused (Core TestChunkBlockLimits).
    local t1 = mining.create_block_template(
      mock_mempool({ mock_entry(tx, 1000, limit - 400) }), cs, net, "\x51")
    assert.equal(0, #t1.transactions)
    local t2 = mining.create_block_template(
      mock_mempool({ mock_entry(tx, 1000, limit - 401) }), cs, net, "\x51")
    assert.equal(1, #t2.transactions)
    assert.equal(limit - 401, t2.transactions[1].sigops)
  end)

  it("getblocktemplate JSON: no coinbasetxn, empty coinbaseaux object, depends []", function()
    local cs = make_chain_state()
    local tx = spend(types.hash256(string.rep("\x36", 32)), 9000, P2WPKH)
    local server = rpc.new({
      chain_state = cs, network = consensus.networks.regtest,
      mempool = mock_mempool({ mock_entry(tx, 1000, 1) }), mining = mining,
    })
    local body = server:handle_request(
      '{"method":"getblocktemplate","params":[{"rules":["segwit"]}],"id":1}')
    local res = cjson.decode(body).result
    assert.is_table(res, body)
    assert.is_nil(res.coinbasetxn)
    assert.is_nil(res.coinbaseaux.flags)
    assert.truthy(body:find('"coinbaseaux":{}', 1, true), body)
    assert.truthy(body:find('"depends":[]', 1, true), body)
    assert.equal(1, res.transactions[1].sigops)
    -- Core's pushKV order for the leading keys.
    local i_cap = body:find('"capabilities"', 1, true)
    local i_ver = body:find('"version"', 1, true)
    local i_txs = body:find('"transactions"', 1, true)
    local i_val = body:find('"coinbasevalue"', 1, true)
    local i_h = body:find('"height"', 1, true)
    assert.is_true(i_cap < i_ver and i_ver < i_txs and i_txs < i_val and i_val < i_h)
  end)
end)
