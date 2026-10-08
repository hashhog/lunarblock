-- Mempool consistent with the chain across a reorg / invalidateblock (LB-7).
--
-- Core (validation.cpp): DisconnectTip puts each disconnected block's txs in a
-- DisconnectedBlockTransactions pool; ConnectTip -> removeForBlock drops the
-- confirmed txs and their conflicts; only once the whole ActivateBestChainStep
-- has succeeded does MaybeUpdateMempoolForReorg re-admit the pool EARLIEST
-- FIRST at the new tip (a tx that fails takes its in-pool children with it --
-- removeRecursive; a re-added tx keeps its in-pool children --
-- UpdateTransactionsFromBlock), then removeForReorg.  InvalidateBlock runs
-- MaybeUpdateMempoolForReorg after EACH disconnected block.
--
-- Pre-fix (abb1130) lunarblock refilled the mempool at the FORK POINT, before
-- the connect loop, and never undid it when the reorg aborted:
--   * reorg:   C (spends P, re-confirmed on the new branch) and LT (final only
--              above the fork) were lost; M2 (child of A1, which the new branch
--              conflicts) stayed -> an invalid getblocktemplate.
--   * abort:   the mempool and every block-connect observer reflected a branch
--              that was rolled back.
--   * invalidateblock: nothing was re-added at all.
--
-- Chain (regtest, P2SH(OP_TRUE) coinbases):
--   1..110 coinbase only
--   111  [A1 <- cb1, P <- cb2]
--   112  [A2 <- cb3, C <- P:0, LT <- cb4 (nLockTime 111)]
--   mempool: M1 <- A2:0, M2 <- A1:0
--   branch off 110: 111b [X <- cb1 (conflicts A1)], 112b [P], 113b [] (or an
--   invalid 113b whose coinbase overpays).

local types = require("lunarblock.types")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local script = require("lunarblock.script")
local crypto = require("lunarblock.crypto")
local storage_mod = require("lunarblock.storage")
local mempool_mod = require("lunarblock.mempool")
local mining = require("lunarblock.mining")

local OP_TRUE = "\x51"
local SPK = script.make_p2sh_script(crypto.hash160(OP_TRUE))
local SIG = "\x01" .. OP_TRUE   -- push the redeem script
local FEE = 10000

local function subsidy(height)
  return math.floor(5000000000 / (2 ^ math.floor(height / 150)))
end

local function coinbase(height, tag, extra)
  return types.transaction(1,
    {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                string.char(2, height % 256, math.floor(height / 256)) .. (tag or ""),
                0xFFFFFFFF)},
    {types.txout(subsidy(height) + (extra or 0), SPK)}, 0)
end

local function spend(prev, vout, locktime)
  return types.transaction(2,
    {types.txin(types.outpoint(validation.compute_txid(prev), vout), SIG, 0xFFFFFFFE)},
    {types.txout(prev.outputs[vout + 1].value - FEE, SPK)}, locktime or 0)
end

local T0 = os.time() - 200 * 600
local function make_block(height, txs, prev_hash, nonce)
  local header = types.block_header(4, prev_hash, types.hash256_zero(),
    T0 + height * 600 + (nonce or 0), consensus.networks.regtest.pow_limit_bits, nonce or 0)
  return types.block(header, txs)
end

local function hx(tx) return types.hash256_hex(validation.compute_txid(tx)) end

describe("mempool vs chain on reorg / invalidateblock (MaybeUpdateMempoolForReorg, LB-7)", function()
  local path, db, cs, mp, tx, names, hashes, events, side

  local function connect(height, txs, prev)
    local block = make_block(height, txs, prev)
    local bh = validation.compute_block_hash(block.header)
    db.put_header(bh, block.header)
    db.put_block(bh, block)
    db.put_height_index(height, bh)
    local ok, err = cs:connect_block(block, height, bh, nil, nil, true)
    assert(ok, "connect_block h=" .. height .. ": " .. tostring(err))
    return bh, block
  end

  local function store_side(height, txs, prev)
    local block = make_block(height, txs, prev, 7)
    local bh = validation.compute_block_hash(block.header)
    db.put_header(bh, block.header)
    db.put_block(bh, block)
    return bh, block
  end

  local function pool()
    local out = {}
    for txid_hex in pairs(mp.entries) do out[#out + 1] = names[txid_hex] or txid_hex end
    table.sort(out)
    return table.concat(out, ",")
  end

  -- Build the side branch; `bad_tip` makes 113b's coinbase overpay.
  local function build_side(bad_tip)
    local prev = hashes[110]
    local b111, b112, b113
    prev, b111 = store_side(111, {coinbase(111, "b"), tx.X}, prev)
    prev, b112 = store_side(112, {coinbase(112, "b"), tx.P}, prev)
    local h113
    h113, b113 = store_side(113, {coinbase(113, "b", bad_tip and 1 or 0)}, prev)
    return h113, b113
  end

  before_each(function()
    path = "/tmp/lunarblock_mpreorg_" .. os.time() .. "_" .. math.random(1e9)
    db = storage_mod.open(path)
    cs = utxo.new_chain_state(db, consensus.networks.regtest)
    cs:init()
    mp = mempool_mod.new(cs, {})
    events = {}
    -- main.lua wiring: removeForBlock on every connected block, plus an
    -- observer that records what peers / ZMQ / the wallet would see.
    cs.callbacks.on_block_connected = function(bh, block)
      events[#events + 1] = "+" .. types.hash256_hex(bh)
      mp:on_block_connected(block)
    end
    cs.callbacks.on_block_disconnected = function(bh)
      events[#events + 1] = "-" .. types.hash256_hex(bh)
    end

    tx, names, hashes = {}, {}, {}
    local cbs = {}
    local prev = types.hash256_zero()
    hashes[0] = connect(0, {coinbase(0)}, prev)
    prev = hashes[0]
    for h = 1, 110 do
      cbs[h] = coinbase(h)
      prev = connect(h, {cbs[h]}, prev)
      hashes[h] = prev
    end
    tx.A1 = spend(cbs[1], 0)
    tx.P = spend(cbs[2], 0)
    tx.A2 = spend(cbs[3], 0)
    tx.C = spend(tx.P, 0)
    tx.LT = spend(cbs[4], 0, 111)
    tx.X = spend(cbs[1], 0)
    tx.X.outputs[1].value = tx.X.outputs[1].value - 1  -- differ from A1
    hashes[111] = connect(111, {coinbase(111), tx.A1, tx.P}, hashes[110])
    hashes[112] = connect(112, {coinbase(112), tx.A2, tx.C, tx.LT}, hashes[111])
    tx.M1 = spend(tx.A2, 0)
    tx.M2 = spend(tx.A1, 0)
    for k, t in pairs(tx) do names[hx(t)] = k end
    for _, k in ipairs({"M1", "M2"}) do
      local ok, why = mp:accept_transaction(tx[k])
      assert(ok, "precondition: " .. k .. " admitted: " .. tostring(why))
    end
    assert.equal("M1,M2", pool())
    events = {}
  end)

  after_each(function()
    pcall(db.close)
    os.execute("rm -rf '" .. path .. "'")
  end)

  it("P2P reorg: disconnected txs re-admitted at the NEW tip, conflicts and their children dropped", function()
    local h113, b113 = build_side(false)
    local res, err = cs:accept_side_branch_block(b113, h113, {mempool = mp, skip_scripts = true})
    assert.equal("connected", res, tostring(err))
    assert.equal(113, cs.tip_height)
    -- Core: {A2, C, LT, M1}.  A1 conflicts X, M2 is A1's child, P is confirmed
    -- again in 112b; C (spends P) and LT (final at 114) come back.
    assert.equal("A2,C,LT,M1", pool())
    -- A2 re-added under its in-pool child M1 (UpdateTransactionsFromBlock).
    assert.is_true(mp.entries[hx(tx.M1)].ancestors[hx(tx.A2)] == true)
    assert.is_true(mp.entries[hx(tx.A2)].descendants[hx(tx.M1)] == true)
    -- every connected block was published, after the 2 disconnects
    assert.equal(5, #events)
  end)

  it("aborted reorg (invalid last block): mempool and observers match the RESTORED chain", function()
    local h113, b113 = build_side(true)
    local res, err = cs:accept_side_branch_block(b113, h113, {mempool = mp, skip_scripts = true})
    assert.is_nil(res)
    assert.truthy(tostring(err):find("reorg-connect-failed", 1, true), tostring(err))
    assert.equal(112, cs.tip_height)
    assert.equal(types.hash256_hex(hashes[112]), types.hash256_hex(cs.tip_hash))
    -- The old chain is back, so the pool must be exactly the pre-reorg pool.
    assert.equal("M1,M2", pool())
    -- No observer saw the rolled-back branch (ZMQ / peers / wallet / notifier).
    assert.equal(0, #events, table.concat(events, " "))
  end)

  it("invalidateblock: each disconnected block's txs return (Core per-block MaybeUpdateMempoolForReorg)", function()
    local ok, err = cs:invalidate_block(hashes[111], mp)
    assert.truthy(ok, tostring(err))
    assert.equal(110, cs.tip_height)
    -- LT is non-final at 111 (removeForReorg); everything else is back.
    assert.equal("A1,A2,C,M1,M2,P", pool())
    assert.is_true(mp.entries[hx(tx.M2)].ancestors[hx(tx.A1)] == true)
    assert.is_true(mp.entries[hx(tx.C)].ancestors[hx(tx.P)] == true)
    assert.is_true(mp.entries[hx(tx.P)].descendants[hx(tx.C)] == true)
  end)

  it("getblocktemplate after invalidateblock: every re-added parent+child pair, parents first", function()
    assert.truthy(cs:invalidate_block(hashes[111], mp))
    local tmpl = mining.create_block_template(mp, cs, consensus.networks.regtest, SPK)
    local order, pos = {}, {}
    for _, t in ipairs(tmpl.transactions) do
      local n = names[t.txid] or t.txid
      order[#order + 1] = n
      pos[n] = #order
    end
    local got = {}
    for _, n in ipairs(order) do got[#got + 1] = n end
    table.sort(got)
    assert.equal("A1,A2,C,M1,M2,P", table.concat(got, ","))
    assert.is_true(pos.P < pos.C and pos.A1 < pos.M2 and pos.A2 < pos.M1, table.concat(order, ","))
  end)

  it("a block confirming a parent keeps its in-mempool child (Core removeForBlock)", function()
    assert.truthy(cs:invalidate_block(hashes[111], mp))
    assert.truthy(cs:reconsider_block(hashes[111]))
    local b111 = db.get_block(hashes[111])
    local ok, err = cs:connect_block(b111, 111, hashes[111], nil, nil, true)
    assert(ok, tostring(err))
    -- A1, P confirmed; their children M2, C stay (Core keeps descendants).
    assert.equal("A2,C,M1,M2", pool())
    assert.is_nil(mp.entries[hx(tx.M2)].ancestors[hx(tx.A1)])
    assert.equal(0, mp.entries[hx(tx.M2)].ancestor_count)
  end)
end)
