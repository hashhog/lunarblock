-- spec/submitblock_failed_sidebranch_invalid_spec.lua
--
-- A side-branch block submitted through submitblock that outweighs the
-- active tip and then fails ConnectBlock during the reorg is marked failed,
-- and getchaintips lists it "invalid" (item
-- refill-20261102-lunarblock-consensus).
--
-- Core: ActivateBestChainStep connects the heavier branch block by block; a
-- ConnectTip failure with a consensus verdict reaches
-- Chainstate::InvalidBlockFound, which sets BLOCK_FAILED_VALID on that block
-- (validation.cpp), and the node returns to the best valid chain.
-- rpc/blockchain.cpp getchaintips reports the entry "invalid".
--
-- lunarblock bug (master 6cf2207): accept_side_branch_block's abort_reorg
-- rolled the reorg back but recorded no verdict on the submitblock path
-- (activate_best_chain and the P2P path each record their own).  The failed
-- block stayed unmarked: getchaintips left it out while its branch had more
-- work than the tip, and listed it "valid-headers" once the active chain
-- caught up (core-regtest failed_reorg 00e14e8a.., warden_invalidated_submit
-- 0a5602e9.., seed_invalidated_submit 6fb2e7ca.. rows).

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
local fault = require("lunarblock.fault")
local cjson = require("cjson")

local REGTEST = consensus.networks.regtest
local BITS = REGTEST.pow_limit_bits
local SPK = script.make_p2pkh_script(string.rep("\x44", 20))
local T0 = os.time()

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

-- A mined block at `height` on `prev_hash`; `overpay` satoshis above the
-- subsidy make it fail ConnectBlock with bad-cb-amount.  `bad_merkle` breaks
-- the merkle root (a mutated body: CheckBlock bad-txnmrklroot).
local function mined_block(height, prev_hash, tag, overpay, bad_merkle)
  local witness_root = crypto.compute_merkle_root({types.hash256_zero()})
  local commitment = crypto.hash256(witness_root.bytes .. string.rep("\0", 32))
  local cb = mining.create_coinbase_tx(height, subsidy(height) + (overpay or 0),
    "/" .. tag .. "/", commitment, SPK)
  local root = crypto.compute_merkle_root({validation.compute_txid(cb)})
  if bad_merkle then root = types.hash256(string.rep("\x5a", 32)) end
  local header = types.block_header(0x20000000, prev_hash, root,
    T0 + height + 1, BITS, 0)
  local block = types.block(header, {cb})
  assert(mining.mine_block(block, 0x7FFFFFFF), "could not mine regtest block")
  return block, validation.compute_block_hash(block.header)
end

describe("submitblock: a side-branch block that fails ConnectBlock in the reorg is an invalid tip", function()
  local path, db, cs, r, hashes

  local function call(method, ...)
    return r.methods[method](r, {...})
  end

  local function submit(block)
    return call("submitblock", hex(serialize.serialize_block(block)))
  end

  local function tips()
    local arr = cjson.decode(call("getchaintips")._raw_json)
    local out = {}
    for _, t in ipairs(arr) do
      out[t.hash] = string.format("%d/%d/%s", t.height, t.branchlen, t.status)
    end
    return out
  end

  local function new_rpc(chain_state)
    local rr = rpc_mod.new({ rpcport = 0, network = REGTEST })
    rr.chain_state = chain_state
    rr.storage = db
    return rr
  end

  before_each(function()
    path = (os.getenv("TMPDIR") or "/tmp") .. "/lunarblock_failed_side_"
      .. os.time() .. "_" .. math.random(1e9)
    db = storage_mod.open(path)
    cs = utxo.new_chain_state(db, REGTEST)
    cs:init()
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
    r = new_rpc(cs)
  end)

  after_each(function()
    fault._reset_for_tests()
    pcall(db.close)
    os.execute("rm -rf '" .. path .. "'")
  end)

  -- The failed_reorg scenario A / *_invalidated_submit failed-connect shape:
  -- an equal-work sibling of the tip, then a bad-cb-amount child on it.
  local function failed_side_branch()
    local sib, sib_h = mined_block(10, hashes[9], "sib10")
    assert.equal("inconclusive", submit(sib))
    local bad, bad_h = mined_block(11, sib_h, "bad11", 1)
    local res = submit(bad)
    assert.is_true(type(res) == "string" and res ~= "inconclusive", tostring(res))
    return sib, sib_h, bad, bad_h
  end

  it("bad-cb-amount on a heavier side branch: tip kept, block listed invalid at branchlen 2", function()
    local _, sib_h, _, bad_h = failed_side_branch()
    assert.equal(hx(hashes[10]), hx(cs.tip_hash))
    assert.is_true(cs:is_block_invalid(bad_h))
    assert.is_false(cs:is_block_invalid(sib_h))
    assert.same({
      [hx(hashes[10])] = "10/0/active",
      [hx(bad_h)]      = "11/2/invalid",
    }, tips())
  end)

  it("the failed side-branch block stays invalid after the active chain outgrows it", function()
    local _, _, _, bad_h = failed_side_branch()
    local c11, c11_h = mined_block(11, hashes[10], "c11")
    assert.equal(cjson.null, submit(c11))
    local c12, c12_h = mined_block(12, c11_h, "c12")
    assert.equal(cjson.null, submit(c12))
    assert.equal(hx(c12_h), hx(cs.tip_hash))
    assert.same({
      [hx(c12_h)] = "12/0/active",
      [hx(bad_h)] = "11/2/invalid",
    }, tips())
  end)

  it("the invalid mark on the failed side-branch block survives a restart", function()
    local _, _, _, bad_h = failed_side_branch()
    local cs2 = utxo.new_chain_state(db, REGTEST)
    cs2:init()
    r = new_rpc(cs2)
    assert.is_true(cs2:is_block_invalid(bad_h))
    assert.equal(hx(hashes[10]), hx(cs2.tip_hash))
    assert.same({
      [hx(hashes[10])] = "10/0/active",
      [hx(bad_h)]      = "11/2/invalid",
    }, tips())
  end)

  -- Consensus guards: the mark lands on the failed block only.
  it("a child of the failed side-branch block is refused and never connected", function()
    local _, _, _, bad_h = failed_side_branch()
    local kid, kid_h = mined_block(12, bad_h, "kid12")
    assert.equal("bad-prevblk", submit(kid))
    assert.equal(hx(hashes[10]), hx(cs.tip_hash))
    assert.is_nil(db.get(storage_mod.CF.BLOCKS, kid_h.bytes))
  end)

  it("the failed block's valid parent is not marked: a valid sibling of the failed block still reorgs", function()
    local _, sib_h, _, bad_h = failed_side_branch()
    local alt, alt_h = mined_block(11, sib_h, "alt11")
    assert.equal(cjson.null, submit(alt))
    assert.equal(hx(alt_h), hx(cs.tip_hash))
    assert.same({
      [hx(alt_h)]      = "11/0/active",
      [hx(hashes[10])] = "10/1/valid-fork",
      [hx(bad_h)]      = "11/1/invalid",
    }, tips())
  end)

  -- Negative controls: no verdict, no mark.
  it("a valid lighter side-branch block is listed valid-headers, not invalid", function()
    local sib, sib_h = mined_block(10, hashes[9], "sib10")
    assert.equal("inconclusive", submit(sib))
    assert.is_false(cs:is_block_invalid(sib_h))
    assert.same({
      [hx(hashes[10])] = "10/0/active",
      [hx(sib_h)]      = "10/1/valid-headers",
    }, tips())
  end)

  it("a system fault during the side-branch connect is not a verdict: nothing marked", function()
    local sib, sib_h = mined_block(10, hashes[9], "sib10")
    submit(sib)
    local blk, blk_h = mined_block(11, sib_h, "fault11")
    local real = cs.connect_block
    cs.connect_block = function() fault.raise("injected db read error") end
    pcall(submit, blk)
    cs.connect_block = real
    assert.is_false(cs:is_block_invalid(blk_h))
    assert.is_false(cs:is_block_invalid(sib_h))
    assert.equal(hx(hashes[10]), hx(cs.tip_hash))
  end)
end)
