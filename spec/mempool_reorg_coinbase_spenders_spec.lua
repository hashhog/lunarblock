-- Reorg: spenders of a disconnected coinbase must leave the mempool.
--
-- Core MaybeUpdateMempoolForReorg (validation.cpp) walks EVERY tx of the
-- disconnect pool, coinbase included: a coinbase never re-enters the pool
-- ((*it)->IsCoinBase() short-circuits AcceptToMemoryPool), so it is
-- removeRecursive'd and every in-pool spender of its outputs goes with it.
-- Its removeForReorg filter then drops any entry whose lock points cannot be
-- computed (CalculateLockPointsAtTip returns nullopt when an input's coin is
-- in neither the UTXO view nor the pool).
--
-- Pre-fix lunarblock started update_for_reorg at transactions[2] (skipping the
-- coinbase) and remove_for_reorg returned "not ours to judge" for an input
-- that resolved to neither a coin nor a pool parent, so after a 100+ block
-- reorg a spender of a now-nonexistent coinbase stayed in the pool and went
-- into getblocktemplate -> an invalid block (bad-txns-inputs-missingorspent).
local types = require("lunarblock.types")
local mempool = require("lunarblock.mempool")
local validation = require("lunarblock.validation")

describe("mempool reorg: spenders of a disconnected coinbase", function()
  local T0 = 1600000000
  local STEP = 600
  local TIP = 300

  local P2PKH = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"

  local function hhash(tag, h)
    return types.hash256(string.format("%-8s%024d", tag, h))
  end

  local function make_cs()
    local headers, index = {}, {}
    local prev = types.hash256_zero()
    for h = 0, TIP do
      local hash = hhash("active", h)
      headers[hash.bytes] = { prev_hash = prev, timestamp = T0 + STEP * h,
        bits = 0x207fffff, version = 4 }
      index[h] = hash
      prev = hash
    end
    return {
      tip_height = TIP,
      tip_hash = index[TIP],
      storage = {
        get_header = function(hash) return headers[hash.bytes] end,
        get_hash_by_height = function(h) return index[h] end,
      },
      network = { csv_height = 1 },
      coin_view = {
        utxos = {},
        get = function(self, txid, vout)
          return self.utxos[types.hash256_hex(txid) .. ":" .. vout]
        end,
      },
    }, index
  end

  local function txid_hex(tx) return types.hash256_hex(validation.compute_txid(tx)) end

  local function put_coin(cs, txid, vout, height, is_coinbase)
    cs.coin_view.utxos[types.hash256_hex(txid) .. ":" .. vout] =
      { value = 5000000000, script_pubkey = P2PKH, height = height,
        is_coinbase = is_coinbase }
  end

  local function drop_coin(cs, txid, vout)
    cs.coin_view.utxos[types.hash256_hex(txid) .. ":" .. vout] = nil
  end

  local function coinbase_at(height)
    local script_sig = string.char(2, height % 256, math.floor(height / 256)) .. "lb"
    return types.transaction(1,
      { types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), script_sig, 0xFFFFFFFF) },
      { types.txout(5000000000, P2PKH) }, 0)
  end

  local function spend(txid, vout, value)
    return types.transaction(2,
      { types.txin(types.outpoint(txid, vout), "", 0xFFFFFFFE) },
      { types.txout(value, P2PKH) }, 0)
  end

  local function plain_coin(cs, tag, height)
    local txid = types.hash256(string.format("coin%-28s", tag))
    put_coin(cs, txid, 0, height, false)
    return txid
  end

  -- A block at `height` that holds only the coinbase.  A 100+ block reorg
  -- disconnects it: its coinbase output is gone from the coin view.
  local function setup_coinbase_spender()
    local cs, index = make_cs()
    local mp = mempool.new(cs)
    local CB_H = 150                         -- mature at tip 300
    local cb = coinbase_at(CB_H)
    local cb_txid = validation.compute_txid(cb)
    put_coin(cs, cb_txid, 0, CB_H, true)
    local spender = spend(cb_txid, 0, 4999990000)
    assert.is_true((mp:accept_transaction(spender)))
    local child = spend(validation.compute_txid(spender), 0, 4999980000)
    assert.is_true((mp:accept_transaction(child)))
    -- Control: a pool entry spending an unrelated confirmed coin.
    local other = spend(plain_coin(cs, "keep", 120), 0, 90000)
    assert.is_true((mp:accept_transaction(other)))
    assert.equal(3, mp.tx_count)
    local block = { header = { prev_hash = index[CB_H - 1] }, transactions = { cb } }
    return cs, mp, cb, cb_txid, block, spender, child, other
  end

  it("update_for_reorg removes in-pool spenders (and their children) of a disconnected coinbase", function()
    local cs, mp, _, cb_txid, block, spender, child, other = setup_coinbase_spender()
    -- The reorg disconnected the coinbase's block: its coin is gone, and the
    -- new tip is far enough below that nothing else changes.
    drop_coin(cs, cb_txid, 0)
    mp:update_for_reorg({ block }, {})
    assert.is_nil(mp.entries[txid_hex(spender)], "spender of the disconnected coinbase stayed")
    assert.is_nil(mp.entries[txid_hex(child)], "child of the coinbase spender stayed")
    assert.is_not_nil(mp.entries[txid_hex(other)], "unrelated entry was removed")
    assert.equal(1, mp.tx_count)
  end)

  it("a disconnected coinbase never enters the mempool", function()
    local cs, mp, cb, cb_txid, block = setup_coinbase_spender()
    drop_coin(cs, cb_txid, 0)
    mp:update_for_reorg({ block }, {})
    assert.is_nil(mp.entries[txid_hex(cb)])
  end)

  it("remove_for_reorg removes an entry whose input resolves to neither a coin nor a pool parent", function()
    local cs = make_cs()
    local mp = mempool.new(cs)
    local gone = plain_coin(cs, "gone", 120)
    local orphaned = spend(gone, 0, 90000)
    assert.is_true((mp:accept_transaction(orphaned)))
    local child = spend(validation.compute_txid(orphaned), 0, 80000)
    assert.is_true((mp:accept_transaction(child)))
    local other = spend(plain_coin(cs, "stay", 120), 0, 90000)
    assert.is_true((mp:accept_transaction(other)))
    drop_coin(cs, gone, 0)
    local n = mp:remove_for_reorg()
    assert.equal(2, n)
    assert.is_nil(mp.entries[txid_hex(orphaned)])
    assert.is_nil(mp.entries[txid_hex(child)])
    assert.is_not_nil(mp.entries[txid_hex(other)])
  end)

  it("control: a spender of a coinbase that stays confirmed and mature is kept", function()
    local _, mp, _, _, _, spender, child, other = setup_coinbase_spender()
    -- No block disconnected; the coin is still there.
    mp:update_for_reorg({}, {})
    assert.is_not_nil(mp.entries[txid_hex(spender)])
    assert.is_not_nil(mp.entries[txid_hex(child)])
    assert.is_not_nil(mp.entries[txid_hex(other)])
    assert.equal(3, mp.tx_count)
  end)

  it("control: a disconnected non-coinbase tx is re-admitted and its in-pool child kept", function()
    local cs, index = make_cs()
    local mp = mempool.new(cs)
    local cb = coinbase_at(250)
    local funding_coin = plain_coin(cs, "fund", 100)
    local parent = spend(funding_coin, 0, 95000)
    local parent_txid = validation.compute_txid(parent)
    -- The parent was confirmed at 250; its child is in the pool.
    put_coin(cs, parent_txid, 0, 250, false)
    local child = spend(parent_txid, 0, 90000)
    assert.is_true((mp:accept_transaction(child)))
    -- Disconnect block 250: the parent's output goes, its input returns.
    drop_coin(cs, parent_txid, 0)
    cs.tip_height, cs.tip_hash = 249, index[249]
    local block = { header = { prev_hash = index[249] }, transactions = { cb, parent } }
    mp:update_for_reorg({ block }, {})
    assert.is_not_nil(mp.entries[txid_hex(parent)], "disconnected parent not re-admitted")
    assert.is_not_nil(mp.entries[txid_hex(child)], "child of a re-admitted parent was dropped")
    assert.is_nil(mp.entries[txid_hex(cb)])
  end)
end)
