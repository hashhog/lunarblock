-- spec/submitblock_bip22_tokens_spec.lua
--
-- submitblock's BIP22 result token on the paths that do not extend the active
-- tip, against Bitcoin Core v31.1:
--
--   * unknown parent: Core AcceptBlockHeader (validation.cpp) returns
--     BLOCK_MISSING_PREV "prev-blk-not-found"; ProcessNewBlock reports it via
--     BlockChecked, so submitblock answers that token (rpc/mining.cpp
--     BIP22ValidationResult).  lunarblock answered "inconclusive".
--   * a stored descendant of an invalidated block: Core AcceptBlockHeader
--     finds the index entry BLOCK_FAILED_VALID and returns
--     BLOCK_CACHED_INVALID "duplicate-invalid".  lunarblock answered
--     "duplicate".
--   * a side-branch block that becomes the heavier tip and itself fails
--     ConnectBlock: Core's submitblock_StateCatcher sees BlockChecked for the
--     submitted block and answers its reason ("bad-cb-amount").  lunarblock
--     wrapped the reason as "reorg-connect-failed at height H: ..." and the
--     token map turned it into "rejected".  When an ANCESTOR on the branch is
--     the block that fails, the catcher never fires and Core answers
--     "inconclusive".
--
-- Core regtest rows: chain/submit/prev-not-found,
-- {seed,warden}_invalidated_submit/submit/duplicate-invalid-descendant,
-- seed_invalidated_submit/submit/bad-cb-amount,
-- warden_invalidated_submit/submit/failed-connect-bad-cb-amount,
-- failed_reorg/a/bad-4s.

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
local SPK = script.make_p2pkh_script(string.rep("\x42", 20))
local T0 = os.time()

local function subsidy(height)
  return math.floor(5000000000 / (2 ^ math.floor(height / 150)))
end

local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function hx(h) return types.hash256_hex(h) end

-- Prefix block, connected with connect_block directly.
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

-- A mined, BIP34, witness-committed coinbase-only block that passes
-- check_block.  `overpay` adds satoshis to the coinbase, which only
-- ConnectBlock rejects (bad-cb-amount).
local function valid_block(height, prev_hash, tag, overpay)
  local witness_root = crypto.compute_merkle_root({types.hash256_zero()})
  local commitment = crypto.hash256(witness_root.bytes .. string.rep("\0", 32))
  local cb = mining.create_coinbase_tx(height, subsidy(height) + (overpay or 0),
    "/" .. (tag or "lb") .. "/", commitment, SPK)
  local header = types.block_header(0x20000000, prev_hash,
    crypto.compute_merkle_root({validation.compute_txid(cb)}), T0 + height + 1, BITS, 0)
  local block = types.block(header, {cb})
  assert(mining.mine_block(block, 0x7FFFFFFF), "could not mine regtest block")
  return block, validation.compute_block_hash(block.header)
end

describe("submitblock BIP22 tokens off the active tip (Core v31.1)", function()
  local path, db, cs, r, hashes

  local function call(method, ...)
    return r.methods[method](r, {...})
  end

  local function submit(block)
    return call("submitblock", hex(serialize.serialize_block(block)))
  end

  local function tip_is(height, hash)
    assert.equal(height, cs.tip_height)
    assert.equal(hx(hash), hx(cs.tip_hash))
  end

  before_each(function()
    path = "/tmp/lunarblock_sbtok_" .. os.time() .. "_" .. math.random(1e9)
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
    r = rpc_mod.new({ rpcport = 0, network = REGTEST })
    r.chain_state = cs
    r.storage = db
    tip_is(10, hashes[10])
  end)

  after_each(function()
    pcall(db.close)
    os.execute("rm -rf '" .. path .. "'")
  end)

  it("prev-not-found: a block with an unknown parent is prev-blk-not-found", function()
    local orphan = valid_block(1, types.hash256(string.rep("\x11", 32)), "orphan")
    assert.equal("prev-blk-not-found", submit(orphan))
    tip_is(10, hashes[10])
  end)

  it("duplicate-invalid-descendant: a stored descendant of an invalidated block", function()
    call("invalidateblock", hx(hashes[9]))
    tip_is(8, hashes[8])
    assert.equal("duplicate-invalid", submit((simple_block(10, hashes[9]))))
    tip_is(8, hashes[8])
  end)

  it("control: a stored block with no failed ancestor is still duplicate", function()
    -- block 5 is on the active chain; its parent is not the tip.
    assert.equal("duplicate", submit((simple_block(5, hashes[4]))))
    -- a stored, valid side-branch block (equal work, not connected).
    local s10 = valid_block(10, hashes[9], "s10dup")
    assert.equal("inconclusive", submit(s10))
    tip_is(10, hashes[10])
    assert.equal("duplicate", submit(s10))
  end)

  it("failed-connect-bad-cb-amount: the submitted side-branch tip fails ConnectBlock", function()
    local s10, s10h = valid_block(10, hashes[9], "s10")
    assert.equal("inconclusive", submit(s10))
    tip_is(10, hashes[10])
    local bad = valid_block(11, s10h, "bad11", 100000000)
    assert.equal("bad-cb-amount", submit(bad))
    tip_is(10, hashes[10])
  end)

  it("an ancestor on the branch fails ConnectBlock: inconclusive", function()
    -- s10 overpays; equal work, so it is only stored.
    local s10, s10h = valid_block(10, hashes[9], "s10bad", 100000000)
    assert.equal("inconclusive", submit(s10))
    tip_is(10, hashes[10])
    -- s11 is valid itself; the reorg fails on s10, which Core reports
    -- through BlockChecked(s10), not for s11.
    local s11 = valid_block(11, s10h, "s11")
    local res = submit(s11)
    assert.equal("inconclusive", res)
    tip_is(10, hashes[10])
    assert.is_true(cs:is_block_invalid(s10h))
  end)

  it("control: a heavier valid side branch still reorgs (null)", function()
    local s10, s10h = valid_block(10, hashes[9], "ok10")
    assert.equal("inconclusive", submit(s10))
    local s11, s11h = valid_block(11, s10h, "ok11")
    local res = submit(s11)
    assert.is_true(res == nil or res == cjson.null, tostring(res))
    tip_is(11, s11h)
  end)
end)
