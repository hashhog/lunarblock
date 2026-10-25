-- spec/invalid_ancestor_chain_selection_spec.lua
--
-- Two chain-selection paths around invalidateblock / reconsiderblock, driven
-- through the submitblock / invalidateblock / reconsiderblock RPC handlers on
-- a real ChainState (regtest, fresh RocksDB under /tmp).
--
-- (a) Core AcceptBlockHeader (validation.cpp): a block whose parent carries
--     BLOCK_FAILED_VALID is refused "bad-prevblk" and never stored or
--     connected; InvalidateBlock marks every descendant failed, so the same
--     holds below an invalidated ancestor.  lunarblock's guard walked from the
--     NEW block's own hash, which a submitblock-only block has in neither the
--     header index nor CF.HEADERS, so the walk ended at once: the child was
--     connected and the invalidated parent reconnected with it.
--
-- (b) Core ReconsiderBlock (rpc/blockchain.cpp): ResetBlockFailureFlags, then
--     ActivateBestChain.  lunarblock only cleared the flags, so the node stayed
--     on the chain it fell back to at invalidateblock.

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

-- Prefix block, connected with connect_block directly (no check_block).
-- `extra` overpays the coinbase (consensus-invalid: bad-cb-amount).
local function simple_block(height, prev_hash, tag, extra)
  local cb = types.transaction(1,
    {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                string.char(1, height % 256) .. (tag or ""), 0xFFFFFFFF)},
    {types.txout(subsidy(height) + (extra or 0), SPK)}, 0)
  local header = types.block_header(1, prev_hash, types.hash256_zero(),
    T0 + height, BITS, 0)
  local block = types.block(header, {cb})
  block.header.merkle_root = crypto.compute_merkle_root({validation.compute_txid(cb)})
  return block, validation.compute_block_hash(block.header)
end

-- A fully valid (mined, BIP34, witness commitment) coinbase-only block, so
-- submitblock's check_block passes and only chain selection decides.
local function valid_block(height, prev_hash, tag)
  local witness_root = crypto.compute_merkle_root({types.hash256_zero()})
  local commitment = crypto.hash256(witness_root.bytes .. string.rep("\0", 32))
  local cb = mining.create_coinbase_tx(height, subsidy(height),
    "/" .. (tag or "lb") .. "/", commitment, SPK)
  local header = types.block_header(0x20000000, prev_hash,
    crypto.compute_merkle_root({validation.compute_txid(cb)}), T0 + height + 1, BITS, 0)
  local block = types.block(header, {cb})
  assert(mining.mine_block(block, 0x7FFFFFFF), "could not mine regtest block")
  return block, validation.compute_block_hash(block.header)
end

local function block_hex(block)
  return hex(serialize.serialize_block(block))
end

describe("invalid-ancestor refusal and reconsiderblock chain activation", function()
  local path, db, cs, r, hashes

  local function call(method, ...)
    return r.methods[method](r, {...})
  end

  local function submit(block)
    return call("submitblock", block_hex(block))
  end

  local function tip_is(height, hash)
    assert.equal(height, cs.tip_height)
    assert.equal(hx(hash), hx(cs.tip_hash))
  end

  before_each(function()
    path = "/tmp/lunarblock_invanc_" .. os.time() .. "_" .. math.random(1e9)
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

  describe("(a) a block building on a failed block", function()
    it("child of an invalidated block: bad-prevblk, not stored, tip unchanged", function()
      call("invalidateblock", hx(hashes[10]))
      tip_is(9, hashes[9])
      local child, child_hash = valid_block(11, hashes[10], "child")
      assert.equal("bad-prevblk", submit(child))
      tip_is(9, hashes[9])
      assert.is_nil(db.get_block(child_hash))
      assert.is_true(cs:is_block_invalid(hashes[10]))
    end)

    it("child of a descendant of an invalidated block: bad-prevblk, tip unchanged", function()
      call("invalidateblock", hx(hashes[9]))
      tip_is(8, hashes[8])
      local child = valid_block(11, hashes[10], "grandchild")
      assert.equal("bad-prevblk", submit(child))
      tip_is(8, hashes[8])
    end)

    it("control: a heavier fork that does not touch the failed block still reorgs", function()
      call("invalidateblock", hx(hashes[10]))
      tip_is(9, hashes[9])
      -- fork off 8: 9f has the same work as 9 (stored), 10f is heavier.
      local f9, f9h = valid_block(9, hashes[8], "f9")
      assert.equal("inconclusive", submit(f9))
      tip_is(9, hashes[9])
      local f10, f10h = valid_block(10, f9h, "f10")
      local res = submit(f10)
      assert.is_true(res == nil or res == require("cjson").null, tostring(res))
      tip_is(10, f10h)
    end)
  end)

  describe("(b) reconsiderblock activates the best chain", function()
    it("reconsider of the invalidated tip reconnects it", function()
      call("invalidateblock", hx(hashes[10]))
      tip_is(9, hashes[9])
      call("reconsiderblock", hx(hashes[10]))
      tip_is(10, hashes[10])
      -- and its child is accepted again (the refusal was the failed flag only)
      local child, child_hash = valid_block(11, hashes[10], "child")
      local res = submit(child)
      assert.is_true(res == nil or res == require("cjson").null, tostring(res))
      tip_is(11, child_hash)
    end)

    it("reconsider of an invalidated ancestor reconnects its descendants", function()
      call("invalidateblock", hx(hashes[9]))
      tip_is(8, hashes[8])
      call("reconsiderblock", hx(hashes[9]))
      tip_is(10, hashes[10])
    end)

    it("control: reconsider does not leave a heavier valid chain", function()
      call("invalidateblock", hx(hashes[10]))
      local a10, a10h = valid_block(10, hashes[9], "a10")
      local a11, a11h = valid_block(11, a10h, "a11")
      submit(a10)
      submit(a11)
      tip_is(11, a11h)
      call("reconsiderblock", hx(hashes[10]))
      tip_is(11, a11h)
    end)

    it("a consensus-invalid descendant is not connected; the valid part of the branch is", function()
      -- 11x overpays its coinbase (bad-cb-amount); stored as a side block.
      local bad, bad_h = simple_block(11, hashes[10], "bad", 1)
      db.put_header(bad_h, bad.header)
      db.put_block(bad_h, bad)
      call("invalidateblock", hx(hashes[10]))
      tip_is(9, hashes[9])
      assert.is_true(cs:is_block_invalid(bad_h))
      call("reconsiderblock", hx(hashes[10]))
      -- Core: ConnectTip(11x) fails, InvalidBlockFound, next candidate (10).
      tip_is(10, hashes[10])
    end)
  end)
end)
