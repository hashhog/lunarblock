-- spec/submitblock_failed_tip_invalid_spec.lua
--
-- A block submitted on top of the active tip that fails validation stays in
-- the block index as a failed block, and getchaintips lists it "invalid"
-- (item batch5-lunarblock-consensus).
--
-- Core: ProcessNewBlock -> AcceptBlock adds the header to the block index and
-- writes the block to disk before ContextualCheckBlock / ConnectBlock; a
-- verdict there reaches Chainstate::InvalidBlockFound, which sets
-- BLOCK_FAILED_VALID (not for BLOCK_MUTATED).  getchaintips then reports the
-- entry with status "invalid" (rpc/blockchain.cpp getchaintips).  A body that
-- fails the context-free CheckBlock is never indexed: ProcessNewBlock runs
-- CheckBlock before AcceptBlock.
--
-- lunarblock bug (master 03932fb): the submitblock tip path wrote header and
-- body only inside the connect batch, so a rejected block left no trace and
-- getchaintips omitted it (the core-regtest seed_invalidated_submit and
-- warden_invalidated_submit rows for the premature-coinbase-spend block).

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

describe("submitblock: a tip-extending block that fails validation is an invalid tip", function()
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
    path = (os.getenv("TMPDIR") or "/tmp") .. "/lunarblock_failed_tip_"
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

  it("bad-cb-amount on the tip: rejected, then listed invalid at branchlen 1", function()
    local bad, bad_h = mined_block(11, hashes[10], "bad11", 1)
    assert.equal("bad-cb-amount", submit(bad))
    assert.equal(hx(hashes[10]), hx(cs.tip_hash))
    assert.is_true(cs:is_block_invalid(bad_h))
    assert.same({
      [hx(hashes[10])] = "10/0/active",
      [hx(bad_h)]      = "11/1/invalid",
    }, tips())
  end)

  -- The seed_invalidated_submit shape: the failed block's valid sibling
  -- connects afterwards; the failed one stays an invalid tip beside it.
  it("the failed block stays invalid after its valid sibling connects", function()
    local bad, bad_h = mined_block(11, hashes[10], "bad11", 1)
    submit(bad)
    local good, good_h = mined_block(11, hashes[10], "good11")
    assert.equal(cjson.null, submit(good))
    assert.equal(hx(good_h), hx(cs.tip_hash))
    assert.same({
      [hx(good_h)] = "11/0/active",
      [hx(bad_h)]  = "11/1/invalid",
    }, tips())
  end)

  -- Consensus guard: the indexed failed body must never be connected.  With
  -- the valid sibling invalidated, the failed block is the only block above
  -- the fork that has data; activate_best_chain must not pick it.
  it("an indexed failed block is never connected, even as the only candidate", function()
    local bad, bad_h = mined_block(11, hashes[10], "bad11", 1)
    submit(bad)
    local good, good_h = mined_block(11, hashes[10], "good11")
    submit(good)
    call("invalidateblock", hx(good_h))
    assert.equal(hx(hashes[10]), hx(cs.tip_hash))
    assert.same({
      [hx(hashes[10])] = "10/0/active",
      [hx(good_h)]     = "11/1/invalid",
      [hx(bad_h)]      = "11/1/invalid",
    }, tips())
    -- resubmitting it on the tip is refused, not connected
    assert.is_true(type(submit(bad)) == "string")
    assert.equal(hx(hashes[10]), hx(cs.tip_hash))
  end)

  it("the invalid mark and the index entry survive a restart", function()
    local bad, bad_h = mined_block(11, hashes[10], "bad11", 1)
    submit(bad)
    local cs2 = utxo.new_chain_state(db, REGTEST)
    cs2:init()
    r = new_rpc(cs2)
    assert.is_true(cs2:is_block_invalid(bad_h))
    assert.same({
      [hx(hashes[10])] = "10/0/active",
      [hx(bad_h)]      = "11/1/invalid",
    }, tips())
  end)

  -- Negative controls: what Core never indexes stays out.
  it("a mutated body (bad merkle root, CheckBlock) is not indexed or marked", function()
    local mut, mut_h = mined_block(11, hashes[10], "mut11", 0, true)
    local res = submit(mut)
    assert.is_true(type(res) == "string", tostring(res))
    assert.is_false(cs:is_block_invalid(mut_h))
    assert.is_nil(db.get(storage_mod.CF.HEADERS, mut_h.bytes))
    assert.same({ [hx(hashes[10])] = "10/0/active" }, tips())
  end)

  it("a system fault during connect is not a verdict: nothing indexed or marked", function()
    local blk, blk_h = mined_block(11, hashes[10], "fault11")
    local real = cs.connect_block
    cs.connect_block = function() fault.raise("injected db read error") end
    local ok = pcall(submit, blk)
    cs.connect_block = real
    assert.is_false(ok)  -- surfaced as an RPC error, not a reject token
    assert.is_false(cs:is_block_invalid(blk_h))
    assert.is_nil(db.get(storage_mod.CF.HEADERS, blk_h.bytes))
    -- and the same block connects once the fault is gone
    fault._reset_for_tests()
    assert.equal(cjson.null, submit(blk))
    assert.equal(hx(blk_h), hx(cs.tip_hash))
  end)
end)
