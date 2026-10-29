-- spec/getchaintips_fleet_spec.lua
--
-- getchaintips must list every block-index leaf, not only the active tip
-- (fleet item done-fleet-regtest-getchaintips).
--
-- Core rpc/blockchain.cpp getchaintips: tips = every block-index entry not on
-- the active chain that is not the parent of another such entry, plus the
-- active tip; branchlen = height - FindFork(active).height; status active /
-- invalid (BLOCK_FAILED_VALID, descendants included) / headers-only
-- (!HaveNumChainTxs) / valid-fork (IsValid(BLOCK_VALID_SCRIPTS)) /
-- valid-headers (IsValid(BLOCK_VALID_TREE)).
--
-- lunarblock bug (master f7fa098): the handler returned the active tip alone,
-- although CF.HEADERS (the block index) holds invalidated blocks, submitted
-- side branches, blocks a reorg disconnected and headers above the tip.
--
-- Driven through the RPC handlers on a real ChainState (regtest, fresh
-- RocksDB under /tmp), the same way as invalid_ancestor_chain_selection_spec.

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

local function valid_block(height, prev_hash, tag, overpay)
  local witness_root = crypto.compute_merkle_root({types.hash256_zero()})
  local commitment = crypto.hash256(witness_root.bytes .. string.rep("\0", 32))
  local cb = mining.create_coinbase_tx(height, subsidy(height) + (overpay or 0),
    "/" .. (tag or "gct") .. "/", commitment, SPK)
  local header = types.block_header(0x20000000, prev_hash,
    crypto.compute_merkle_root({validation.compute_txid(cb)}), T0 + height + 1, BITS, 0)
  local block = types.block(header, {cb})
  assert(mining.mine_block(block, 0x7FFFFFFF), "could not mine regtest block")
  return block, validation.compute_block_hash(block.header)
end

describe("getchaintips lists every block-index leaf (Core statuses)", function()
  local path, db, cs, r, hashes

  local function call(method, ...)
    return r.methods[method](r, {...})
  end

  local function submit(block)
    return call("submitblock", hex(serialize.serialize_block(block)))
  end

  -- getchaintips as a { [hash] = "height/branchlen/status" } map.
  local function tips()
    local res = call("getchaintips")
    local arr = cjson.decode(res._raw_json)
    local out = {}
    for _, t in ipairs(arr) do
      out[t.hash] = string.format("%d/%d/%s", t.height, t.branchlen, t.status)
    end
    return out
  end

  before_each(function()
    path = "/tmp/lunarblock_gct_fleet_" .. os.time() .. "_" .. math.random(1e9)
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
  end)

  after_each(function()
    pcall(db.close)
    os.execute("rm -rf '" .. path .. "'")
  end)

  it("control: no fork -> the active tip alone", function()
    assert.same({ [hx(hashes[10])] = "10/0/active" }, tips())
  end)

  it("an invalidated branch is an invalid tip", function()
    call("invalidateblock", hx(hashes[8]))
    assert.same({
      [hx(hashes[7])]  = "7/0/active",
      [hx(hashes[10])] = "10/3/invalid",
    }, tips())
  end)

  it("a submitted side block that never connected is valid-headers", function()
    local side, side_h = valid_block(1, hashes[0], "side")
    assert.equal("inconclusive", submit(side))
    assert.same({
      [hx(hashes[10])] = "10/0/active",
      [hx(side_h)]     = "1/1/valid-headers",
    }, tips())
  end)

  it("a once-connected branch left behind by a heavier chain is valid-fork", function()
    call("invalidateblock", hx(hashes[10]))
    local a10, a10h = valid_block(10, hashes[9], "a10")
    local a11, a11h = valid_block(11, a10h, "a11")
    submit(a10)
    submit(a11)
    call("reconsiderblock", hx(hashes[10]))
    assert.equal(hx(a11h), hx(cs.tip_hash))
    assert.same({
      [hx(a11h)]       = "11/0/active",
      [hx(hashes[10])] = "10/1/valid-fork",
    }, tips())
  end)

  it("headers without bodies are headers-only, measured to the fork", function()
    local h11, h11h = simple_block(11, hashes[10])
    local h12, h12h = simple_block(12, h11h)
    db.put_header(h11h, h11.header)
    db.put_header(h12h, h12.header)
    -- and a header on top of a side block that has its body
    local side, side_h = valid_block(9, hashes[8], "side9")
    assert.equal("inconclusive", submit(side))
    local s10, s10h = simple_block(10, side_h)
    db.put_header(s10h, s10.header)
    assert.same({
      [hx(hashes[10])] = "10/0/active",
      [hx(h12h)]       = "12/2/headers-only",
      [hx(s10h)]       = "10/2/headers-only",
    }, tips())
  end)

  it("reconsider of the invalidated tip leaves the active tip alone", function()
    call("invalidateblock", hx(hashes[9]))
    call("reconsiderblock", hx(hashes[9]))
    assert.same({ [hx(hashes[10])] = "10/0/active" }, tips())
  end)

  -- A heavier side branch whose connect failed (s11 overpays its coinbase):
  -- Core marks s11 failed and lists it "invalid".  lunarblock aborts the
  -- reorg without recording a verdict, so s11 is a "valid" leaf with data and
  -- more work than the active chain -- a state Core cannot be in.  Its status
  -- is unknown here, so it is left out instead of reported valid-headers.
  it("a heavier branch whose connect failed is left out, not called valid", function()
    local s10, s10h = valid_block(10, hashes[9], "s10")
    local s11, s11h = valid_block(11, s10h, "s11", 1)
    assert.equal("inconclusive", submit(s10))
    local res = submit(s11)
    assert.is_true(type(res) == "string", tostring(res))  -- rejected, not null
    assert.equal(hx(hashes[10]), hx(cs.tip_hash))
    assert.is_not_nil(db.get(storage_mod.CF.BLOCKS, s11h.bytes))  -- s11 is indexed with data
    assert.is_false(cs:is_block_invalid(s11h))                    -- and no verdict recorded
    assert.same({ [hx(hashes[10])] = "10/0/active" }, tips())
  end)

  -- Index bookkeeping this item adds: disconnect_block records that the block
  -- was connected once; nothing else writes or reads the marker.
  it("disconnect records the was-connected marker; a never-connected block has none", function()
    local chaintips = require("lunarblock.chaintips")
    local key = function(h) return chaintips.WAS_CONNECTED_PREFIX .. h.bytes end
    assert.is_nil(db.get(storage_mod.CF.META, key(hashes[10])))
    call("invalidateblock", hx(hashes[10]))
    assert.is_not_nil(db.get(storage_mod.CF.META, key(hashes[10])))
    local side, side_h = valid_block(1, hashes[0], "never")
    submit(side)
    assert.is_nil(db.get(storage_mod.CF.META, key(side_h)))
  end)
end)
