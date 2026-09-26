-- getdata serving decision, Core parity
-- (bitcoin-core/src/net_processing.cpp ProcessGetData / FindTxForGetData).
--
--   MSG_WTX (5)                 lookup by WTXID, serialize WITH witness
--   MSG_WITNESS_TX (0x40000001) lookup by txid,  serialize WITH witness
--   MSG_TX (1)                  lookup by txid,  serialize WITHOUT witness
--   MSG_BLOCK (2)               serialize WITHOUT witness
--   MSG_WITNESS_BLOCK           serialize WITH witness
--   unserveable tx/block items  -> notfound batch
--
-- lunarblock announces mempool txs to wtxidrelay peers (every modern Core) as
-- MSG_WTX + wtxid.  Before this fix the getdata handler had no MSG_WTX branch,
-- so Core's getdata was silently dropped and no tx relayed from lunarblock to
-- Core over the trickle path.

local types = require("lunarblock.types")
local mempool_mod = require("lunarblock.mempool")
local validation = require("lunarblock.validation")
local serialize = require("lunarblock.serialize")
local p2p = require("lunarblock.p2p")
local peerman = require("lunarblock.peerman")

local T = p2p.INV_TYPE

local function mock_chain_state()
  local utxos = {}
  return {
    coin_view = {
      utxos = utxos,
      get = function(self, txid, vout)
        return self.utxos[types.hash256_hex(txid) .. ":" .. vout]
      end,
    },
    tip_height = 700000,
  }, utxos
end

local P2WPKH_A = "\x00\x14" .. string.rep("\x11", 20)
local P2WPKH_B = "\x00\x14" .. string.rep("\x22", 20)
local P2PKH = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"

-- A segwit tx (txid ~= wtxid) and a legacy tx (txid == wtxid), both accepted
-- into a real Mempool through accept_transaction (the production insert path).
local function setup()
  local cs, utxos = mock_chain_state()
  local prev1 = types.hash256(string.rep("\x01", 32))
  local prev2 = types.hash256(string.rep("\x02", 32))
  utxos[types.hash256_hex(prev1) .. ":0"] =
    { value = 100000, script_pubkey = P2WPKH_A, height = 500000, is_coinbase = false }
  utxos[types.hash256_hex(prev2) .. ":0"] =
    { value = 100000, script_pubkey = P2PKH, height = 500000, is_coinbase = false }
  local mp = mempool_mod.new(cs)

  local sw = types.transaction(2,
    { types.txin(types.outpoint(prev1, 0), "", 0xFFFFFFFD) },
    { types.txout(90000, P2WPKH_B) }, 0)
  sw.inputs[1].witness = { string.rep("\x30", 71), "\x02" .. string.rep("\x33", 32) }
  sw.segwit = true
  assert.is_true((mp:accept_transaction(sw)))

  local legacy = types.transaction(1,
    { types.txin(types.outpoint(prev2, 0), "", 0xFFFFFFFE) },
    { types.txout(90000, P2PKH) }, 0)
  assert.is_true((mp:accept_transaction(legacy)))

  return mp, sw, legacy
end

local function hex(h) return types.hash256_hex(h) end

describe("getdata serving decision (Core ProcessGetData parity)", function()
  local mp, sw, legacy, sw_txid, sw_wtxid
  before_each(function()
    mp, sw, legacy = setup()
    sw_txid = validation.compute_txid(sw)
    sw_wtxid = validation.compute_wtxid(sw)
    assert.not_equal(hex(sw_txid), hex(sw_wtxid))
  end)

  local function ask(type_, hash, get_block)
    return peerman.getdata_response({ type = type_, hash = hash },
      { mempool = mp, get_block = get_block })
  end

  it("MSG_WTX: looks the tx up by WTXID and serves it WITH witness", function()
    local cmd, data, status = ask(T.MSG_WTX, sw_wtxid)
    assert.equal("served", status)
    assert.equal("tx", cmd)
    assert.equal(serialize.serialize_transaction(sw, true), data)
    assert.not_equal(serialize.serialize_transaction(sw, false), data)
  end)

  it("MSG_WTX: a segwit TXID is not a wtxid -> notfound", function()
    local _, _, status = ask(T.MSG_WTX, sw_txid)
    assert.equal("notfound", status)
  end)

  it("MSG_WTX: non-segwit tx is found under wtxid == txid", function()
    local cmd, data, status = ask(T.MSG_WTX, validation.compute_wtxid(legacy))
    assert.equal("served", status)
    assert.equal("tx", cmd)
    assert.equal(serialize.serialize_transaction(legacy, false), data)
  end)

  it("MSG_WTX: unknown wtxid -> notfound", function()
    local _, _, status = ask(T.MSG_WTX, types.hash256(string.rep("\x99", 32)))
    assert.equal("notfound", status)
  end)

  it("MSG_WITNESS_TX: by txid, WITH witness", function()
    local cmd, data, status = ask(T.MSG_WITNESS_TX, sw_txid)
    assert.equal("served", status)
    assert.equal("tx", cmd)
    assert.equal(serialize.serialize_transaction(sw, true), data)
  end)

  it("MSG_TX: by txid, WITHOUT witness", function()
    local cmd, data, status = ask(T.MSG_TX, sw_txid)
    assert.equal("served", status)
    assert.equal("tx", cmd)
    assert.equal(serialize.serialize_transaction(sw, false), data)
  end)

  it("MSG_TX: unknown txid -> notfound", function()
    local _, _, status = ask(T.MSG_TX, types.hash256(string.rep("\x98", 32)))
    assert.equal("notfound", status)
  end)

  it("wtxid lookup stops serving once the tx leaves the mempool", function()
    mp:remove_transaction(hex(sw_txid), "test")
    local _, _, status = ask(T.MSG_WTX, sw_wtxid)
    assert.equal("notfound", status)
    assert.is_nil(mp.wtxid_index[hex(sw_wtxid)])
  end)

  describe("blocks", function()
    local blk, bhash
    before_each(function()
      blk = types.block(types.block_header(0x20000000), { legacy, sw })
      bhash = types.hash256(string.rep("\x77", 32))
    end)
    local function get_block(h)
      if hex(h) == hex(bhash) then return blk end
      return nil
    end

    it("MSG_BLOCK: served WITHOUT witness", function()
      local cmd, data, status = ask(T.MSG_BLOCK, bhash, get_block)
      assert.equal("served", status)
      assert.equal("block", cmd)
      assert.equal(serialize.serialize_block_without_witness(blk), data)
      assert.not_equal(serialize.serialize_block(blk), data)
    end)

    it("MSG_WITNESS_BLOCK: served WITH witness", function()
      local cmd, data, status = ask(T.MSG_WITNESS_BLOCK, bhash, get_block)
      assert.equal("served", status)
      assert.equal("block", cmd)
      assert.equal(serialize.serialize_block(blk), data)
    end)

    it("unknown block -> notfound", function()
      local _, _, status = ask(T.MSG_BLOCK, types.hash256(string.rep("\x55", 32)), get_block)
      assert.equal("notfound", status)
    end)
  end)

  it("MSG_FILTERED_BLOCK is left to the caller (bloom path)", function()
    local _, _, status = ask(T.MSG_FILTERED_BLOCK, types.hash256(string.rep("\x55", 32)))
    assert.equal("unhandled", status)
  end)
end)
