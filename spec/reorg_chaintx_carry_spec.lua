-- spec/reorg_chaintx_carry_spec.lua
--
-- Cumulative tx count (m_chain_tx_count) across a multi-block reorg.
--
-- Core sets CBlockIndex::m_chain_tx_count from pprev->m_chain_tx_count when a
-- block is accepted (validation.cpp ReceivedBlockTransactions), so a block's
-- count never depends on what is or is not flushed to disk.  lunarblock keys
-- the count by height and computes it in connect_block as
-- chaintx(height-1) + #block.transactions.  Inside a multi-block reorg every
-- per-block write goes to ONE uncommitted shared batch, so for the second and
-- later side-branch blocks chaintx(height-1) read from disk is still the
-- REPLACED block's count.  The persisted counts (getchaintxstats txcount,
-- dumptxoutset nchaintx) then carry the old branch's per-block tx counts.
--
-- Here the active branch's replaced blocks and the side branch's blocks carry
-- different numbers of transactions, so the stale read is visible:
--   PRE-fix : txcount at the new tip = old-branch count + 1 (108, not 106)
--   POST-fix: txcount at every new-chain height = sum of #txs along the chain

local cjson = require("cjson")
local types = require("lunarblock.types")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local storage_mod = require("lunarblock.storage")
local rpc = require("lunarblock.rpc")

local function subsidy(height)
  return math.floor(5000000000 / (2 ^ math.floor(height / 150)))
end

-- OP_TRUE outputs: spendable with an empty scriptSig, so the test needs no keys.
local SPK = "\x51"

local function make_coinbase_tx(height, value)
  return types.transaction(
    1,
    {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                string.char(1, height % 256), 0xFFFFFFFF)},
    {types.txout(value, SPK)},
    0)
end

local function make_spend_tx(prev_txid, value)
  return types.transaction(
    1,
    {types.txin(types.outpoint(prev_txid, 0), "", 0xFFFFFFFF)},
    {types.txout(value, SPK)},
    0)
end

local function make_block(height, transactions, prev_hash, nonce)
  local header = types.block_header(
    1,
    prev_hash or types.hash256_zero(),
    types.hash256_zero(),
    os.time() + height + (nonce or 0) * 1000000,
    consensus.networks.regtest.pow_limit_bits,
    nonce or 0)
  return types.block(header, transactions)
end

local function connect(cs, db, height, txs, prev_hash)
  local block = make_block(height, txs, prev_hash, 0)
  local block_hash = validation.compute_block_hash(block.header)
  db.put_header(block_hash, block.header)
  db.put_block(block_hash, block)
  db.put_height_index(height, block_hash)
  local ok, err = cs:connect_block(block, height, block_hash, nil, nil, true)
  assert(ok, "connect_block failed at h=" .. height .. ": " .. tostring(err))
  return block_hash, block
end

local function store_side(db, height, txs, prev_hash)
  local block = make_block(height, txs, prev_hash, 7)
  local block_hash = validation.compute_block_hash(block.header)
  db.put_header(block_hash, block.header)
  db.put_block(block_hash, block)
  return block_hash, block
end

local FORK_H = 101   -- coinbase at h=k is spendable from h=k+100

describe("reorg carries the cumulative tx count across the side branch", function()
  local db, cs, path, side_tip_hash, side_tip_block
  local cb_txid = {}
  local expected = {}   -- height -> cumulative tx count along the NEW chain

  before_each(function()
    path = "/tmp/lunarblock_chaintx_carry_" .. os.time() .. "_" .. math.random(1e9)
    db = storage_mod.open(path)
    cs = utxo.new_chain_state(db, consensus.networks.regtest)
    cs:init()

    -- Shared prefix h=0..FORK_H, one coinbase each.
    local prev = types.hash256_zero()
    local fork_hash
    local running = 0
    for h = 0, FORK_H do
      local cb = make_coinbase_tx(h, subsidy(h))
      cb_txid[h] = validation.compute_txid(cb)
      prev = connect(cs, db, h, {cb}, prev)
      running = running + 1
      expected[h] = running
    end
    fork_hash = prev

    -- Active branch (to be replaced): h=102 has 2 txs, h=103 has 3 txs.
    prev = fork_hash
    prev = connect(cs, db, 102, {make_coinbase_tx(102, subsidy(102)),
      make_spend_tx(cb_txid[1], subsidy(1))}, prev)
    prev = connect(cs, db, 103, {make_coinbase_tx(103, subsidy(103)),
      make_spend_tx(cb_txid[2], subsidy(2)),
      make_spend_tx(cb_txid[3], subsidy(3))}, prev)
    assert.equal(103, cs.tip_height)

    -- Side branch from the fork: h=102 1 tx, h=103 2 txs, h=104 1 tx.
    local side_txs = {
      [102] = {make_coinbase_tx(102, subsidy(102))},
      [103] = {make_coinbase_tx(103, subsidy(103)),
               make_spend_tx(cb_txid[3], subsidy(3))},
      [104] = {make_coinbase_tx(104, subsidy(104))},
    }
    prev = fork_hash
    for h = 102, 104 do
      side_tip_hash, side_tip_block = store_side(db, h, side_txs[h], prev)
      prev = side_tip_hash
      running = running + #side_txs[h]
      expected[h] = running
    end
  end)

  after_each(function()
    if db then db.close() end
    if path then os.execute("rm -rf -- '" .. path .. "'") end
  end)

  it("CONTROL the pre-reorg active tip's count is the sum along the old chain", function()
    -- 102 single-tx blocks + 2 + 3: the counter itself works on tip extension.
    assert.equal(107, db.get_chaintx_at_height(103))
  end)

  it("stores the new chain's cumulative count at every reorged height", function()
    local res, err = cs:accept_side_branch_block(side_tip_block, side_tip_hash)
    assert.equal("connected", res, tostring(err))
    assert.equal(104, cs.tip_height)
    -- The first side block reads the fork point, which is on disk: correct
    -- on master too.  103 and 104 are where the stale read showed.
    assert.equal(expected[FORK_H], db.get_chaintx_at_height(FORK_H))
    assert.equal(expected[102], db.get_chaintx_at_height(102))
    assert.equal(expected[103], db.get_chaintx_at_height(103))
    assert.equal(expected[104], db.get_chaintx_at_height(104))
  end)

  it("getchaintxstats txcount at the new tip equals the sum along the new chain", function()
    local res, err = cs:accept_side_branch_block(side_tip_block, side_tip_hash)
    assert.equal("connected", res, tostring(err))
    local srv = rpc.new({network = consensus.networks.regtest,
                         chain_state = cs, storage = db})
    local body = srv:handle_request(cjson.encode({
      method = "getchaintxstats", params = {}, id = 1}))
    local resp = cjson.decode(body)
    assert.is_truthy(resp.error == nil or resp.error == cjson.null)
    assert.equal(106, expected[104])
    assert.equal(106, resp.result.txcount)
    assert.equal(types.hash256_hex(side_tip_hash), resp.result.window_final_block_hash)
  end)

  it("an aborted reorg leaves the old chain's counts and a later reorg is still correct", function()
    -- Make the side tip invalid (coinbase overpays), so the reorg aborts
    -- after the first two side blocks were connected into the batch.
    local bad_tx = {make_coinbase_tx(104, subsidy(104) + 1)}
    local bad_hash, bad_block = store_side(db, 104, bad_tx,
      side_tip_block.header.prev_hash)
    local res = cs:accept_side_branch_block(bad_block, bad_hash)
    assert.are_not.equal("connected", res)
    assert.equal(103, cs.tip_height)
    assert.equal(104, db.get_chaintx_at_height(102))
    assert.equal(107, db.get_chaintx_at_height(103))
    -- The good side tip still reorgs with the right counts: nothing from the
    -- aborted attempt leaks into the next one.
    local res2, err2 = cs:accept_side_branch_block(side_tip_block, side_tip_hash)
    assert.equal("connected", res2, tostring(err2))
    assert.equal(expected[103], db.get_chaintx_at_height(103))
    assert.equal(expected[104], db.get_chaintx_at_height(104))
  end)
end)
