-- spec/chain_reactivation_spec.lua
--
-- invalidateblock / reconsiderblock must activate the best chain the way
-- Core does (fix-lunarblock-chain-reactivation-after-25, Core regtest group
-- failed_reorg steps b, c and e).
--
-- Core rpc/blockchain.cpp invalidateblock -> Chainstate::InvalidateBlock, then
-- ActivateBestChain; reconsiderblock -> ResetBlockFailureFlags, then
-- ActivateBestChain.  ActivateBestChain takes the most-work candidate in
-- setBlockIndexCandidates (every block with all its data, not failed, with at
-- least the tip's work).  Equal work goes to the lower nSequenceId: the order
-- the bodies were received in, except that a restart gives the active chain
-- loaded from disk 0 and every other block 1 (SEQ_ID_BEST_CHAIN_FROM_DISK /
-- SEQ_ID_INIT_FROM_DISK, chain.h).  A candidate that fails ConnectBlock is
-- marked failed and the next one is tried (InvalidChainFound).
--
-- lunarblock bugs (master 0a3f6e8):
--   * invalidateblock only disconnected: a stored heavier side branch was
--     never connected, so the node sat on the invalidated block's parent;
--   * the next reconsiderblock then reconnected the reconsidered block over
--     a side branch Core had already moved to and kept (equal work, lower
--     sequence id after a restart).
--
-- Driven through the RPC handlers on a real ChainState (regtest, fresh
-- RocksDB under /tmp), as getchaintips_fleet_spec does.  "Restart" closes the
-- database and builds a new ChainState and RPC server on the same directory.

local types = require("lunarblock.types")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local script = require("lunarblock.script")
local crypto = require("lunarblock.crypto")
local mining = require("lunarblock.mining")
local serialize = require("lunarblock.serialize")
local storage_mod = require("lunarblock.storage")
local rpc_mod = require("lunarblock.rpc")
local cjson = require("cjson")

local REGTEST = consensus.networks.regtest
local BITS = REGTEST.pow_limit_bits
local SPK = script.make_p2pkh_script(string.rep("\x43", 20))
local T0 = os.time() - 100000

local function subsidy(height)
  return math.floor(5000000000 / (2 ^ math.floor(height / 150)))
end

local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function hx(h) return types.hash256_hex(h) end

local function simple_block(height, prev_hash)
  local cb = types.transaction(1,
    {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                string.char(1, height % 256), 0xFFFFFFFF)},
    {types.txout(subsidy(height), SPK)}, 0)
  local header = types.block_header(1, prev_hash, types.hash256_zero(),
    T0 + height, BITS, 0)
  local block = types.block(header, {cb})
  block.header.merkle_root = crypto.compute_merkle_root({validation.compute_txid(cb)})
  return block, validation.compute_block_hash(block.header)
end

-- A block that passes ConnectBlock on submitblock; overpay > 0 makes its
-- coinbase claim more than the subsidy (bad-cb-amount at connect time).
local function valid_block(height, prev_hash, tag, overpay)
  local witness_root = crypto.compute_merkle_root({types.hash256_zero()})
  local commitment = crypto.hash256(witness_root.bytes .. string.rep("\0", 32))
  local cb = mining.create_coinbase_tx(height, subsidy(height) + (overpay or 0),
    "/" .. tag .. "/", commitment, SPK)
  local header = types.block_header(0x20000000, prev_hash,
    crypto.compute_merkle_root({validation.compute_txid(cb)}), T0 + height + 1, BITS, 0)
  local block = types.block(header, {cb})
  assert(mining.mine_block(block, 0x7FFFFFFF), "could not mine regtest block")
  return block, validation.compute_block_hash(block.header)
end

describe("invalidateblock / reconsiderblock activate the best chain (Core ActivateBestChain)", function()
  local path, db, cs, r, hashes

  local function call(method, ...)
    return r.methods[method](r, {...})
  end

  local function submit(block)
    return call("submitblock", hex(serialize.serialize_block(block)))
  end

  local function open()
    db = storage_mod.open(path)
    cs = utxo.new_chain_state(db, REGTEST)
    cs:init()
    r = rpc_mod.new({ rpcport = 0, network = REGTEST })
    r.chain_state = cs
    r.storage = db
  end

  local function restart()
    db.close()
    open()
  end

  local function tips()
    local arr = cjson.decode(call("getchaintips")._raw_json)
    local out = {}
    for _, t in ipairs(arr) do
      out[t.hash] = string.format("%d/%d/%s", t.height, t.branchlen, t.status)
    end
    return out
  end

  -- Active chain 0..10; side blocks are built off `fork` with valid_block.
  before_each(function()
    path = "/tmp/lunarblock_reactivation_" .. os.time() .. "_" .. math.random(1e9)
    open()
    hashes = {}
    local prev = types.hash256_zero()
    for h = 0, 10 do
      local block, bh = simple_block(h, prev)
      db.put_header(bh, block.header)
      db.put_block(bh, block)
      db.put_height_index(h, bh)
      local ok, err = cs:connect_block(block, h, bh, nil, nil, true)
      assert(ok, "prefix connect h=" .. h .. ": " .. tostring(err))
      hashes[h] = bh
      prev = bh
    end
  end)

  after_each(function()
    pcall(db.close)
    os.execute("rm -rf '" .. path .. "'")
  end)

  -- 0..8-9-10 active, 8-s9-s10 submitted afterwards (equal work, stored).
  local function equal_work_side()
    local s9, s9h = valid_block(9, hashes[8], "s9")
    local s10, s10h = valid_block(10, s9h, "s10")
    assert.equal("inconclusive", submit(s9))
    assert.equal("inconclusive", submit(s10))
    assert.equal(hx(hashes[10]), hx(cs.tip_hash))
    return s9h, s10h
  end

  -- failed_reorg c-invalidate / e-invalidate.
  it("invalidateblock moves to a stored side branch with more work than the parent", function()
    local _, s10h = equal_work_side()
    assert.equal(cjson.null, call("invalidateblock", hx(hashes[10])))
    assert.equal(hx(s10h), hx(cs.tip_hash))
    assert.equal(10, cs.tip_height)
    assert.same({
      [hx(s10h)]       = "10/0/active",
      [hx(hashes[10])] = "10/2/invalid",
    }, tips())
  end)

  -- failed_reorg c-reconsider: no restart, the reconsidered block was received
  -- first, so it wins the equal-work tie and the side branch is displaced.
  it("reconsiderblock returns to an equal-work block received before the side branch", function()
    local _, s10h = equal_work_side()
    call("invalidateblock", hx(hashes[10]))
    assert.equal(hx(s10h), hx(cs.tip_hash))
    assert.equal(cjson.null, call("reconsiderblock", hx(hashes[10])))
    assert.equal(hx(hashes[10]), hx(cs.tip_hash))
    assert.same({
      [hx(hashes[10])] = "10/0/active",
      [hx(s10h)]       = "10/2/valid-fork",
    }, tips())
  end)

  -- failed_reorg e-reconsider / e-restart (the four rows of the item): a
  -- restart between the two calls gives the active side branch sequence id 0
  -- and the reconsidered block 1, so Core stays on the side branch.
  it("after a restart, reconsiderblock leaves the equal-work active chain in place", function()
    local _, s10h = equal_work_side()
    call("invalidateblock", hx(hashes[10]))
    assert.equal(hx(s10h), hx(cs.tip_hash))
    restart()
    assert.equal(hx(s10h), hx(cs.tip_hash))
    assert.equal(cjson.null, call("reconsiderblock", hx(hashes[10])))
    assert.equal(hx(s10h), hx(cs.tip_hash))
    local want = {
      [hx(s10h)]       = "10/0/active",
      [hx(hashes[10])] = "10/2/valid-fork",
    }
    assert.same(want, tips())
    restart()
    assert.equal(hx(s10h), hx(cs.tip_hash))
    assert.same(want, tips())
  end)

  -- failed_reorg b-invalidate / b-restart: the most-work candidate's last
  -- block fails ConnectBlock.  Core marks it failed and settles on the valid
  -- prefix, which still has more work than the invalidated block's parent.
  it("a candidate that fails to connect is marked invalid and its valid prefix activated", function()
    local s8, s8h = valid_block(8, hashes[7], "s8")
    local s9, s9h = valid_block(9, s8h, "s9")
    local s10, s10h = valid_block(10, s9h, "s10bad", 1)
    assert.equal("inconclusive", submit(s8))
    assert.equal("inconclusive", submit(s9))
    assert.equal("inconclusive", submit(s10))
    assert.equal(cjson.null, call("invalidateblock", hx(hashes[9])))
    assert.equal(hx(s9h), hx(cs.tip_hash))
    assert.equal(9, cs.tip_height)
    assert.is_true(cs:is_block_invalid(s10h))
    assert.is_false(cs:is_block_invalid(s9h))
    local want = {
      [hx(s9h)]        = "9/0/active",
      [hx(s10h)]       = "10/1/invalid",
      [hx(hashes[10])] = "10/3/invalid",
    }
    assert.same(want, tips())
    restart()
    assert.equal(hx(s9h), hx(cs.tip_hash))
    assert.same(want, tips())
  end)

  -- Controls: nothing heavier than the parent, or only a lighter side branch,
  -- leaves invalidateblock where it was before this change.
  it("control: invalidateblock with no side branch stays on the parent", function()
    call("invalidateblock", hx(hashes[10]))
    assert.equal(hx(hashes[9]), hx(cs.tip_hash))
  end)

  it("control: a heavier main chain wins back on reconsider; a side branch under an invalidated block is not activated", function()
    local s9, s9h = valid_block(9, hashes[8], "s9")
    assert.equal("inconclusive", submit(s9))
    call("invalidateblock", hx(hashes[9]))
    -- s9 has more work than 8 (the parent of 9): Core moves to it.
    assert.equal(hx(s9h), hx(cs.tip_hash))
    call("reconsiderblock", hx(hashes[9]))
    -- 9-10 outweighs s9: back to 10.
    assert.equal(hx(hashes[10]), hx(cs.tip_hash))
    call("invalidateblock", hx(hashes[8]))
    -- s9 descends from 8 too: invalid, so the tip is 7.
    assert.equal(hx(hashes[7]), hx(cs.tip_hash))
  end)
end)
