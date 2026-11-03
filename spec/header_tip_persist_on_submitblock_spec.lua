-- spec/header_tip_persist_on_submitblock_spec.lua
--
-- Core regtest ratchet (warden_invalidated_submit/p2p-header/valid, a
-- node_error row): after a restart a header pushed over P2P on top of the
-- active tip was dropped as "unknown parent", because the persisted
-- `header_tip` META record was stale (height 102 while the chain was at 208).
-- HeaderChain:add_mined_tip (generatetoaddress / submitblock) moved the
-- in-memory header tip but never wrote the META record, so the next boot
-- loaded only the headers below the last P2P/RPC header acceptance.
-- Core keeps the whole block index across restarts.

local types = require("lunarblock.types")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local script = require("lunarblock.script")
local storage_mod = require("lunarblock.storage")
local sync = require("lunarblock.sync")
local mining = require("lunarblock.mining")
local rpc_mod = require("lunarblock.rpc")
local cjson = require("cjson")

local REGTEST = consensus.networks.regtest
local BITS = REGTEST.pow_limit_bits
local SPK = script.make_p2pkh_script(string.rep("\x42", 20))

local function simple_block(height, prev_hash)
  local cb = types.transaction(1,
    {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                string.char(1, height % 256), 0xFFFFFFFF)},
    {types.txout(5000000000, SPK)}, 0)
  local header = types.block_header(1, prev_hash or types.hash256_zero(),
    types.hash256_zero(), os.time() + height, BITS, 0)
  return types.block(header, {cb})
end

describe("add_mined_tip persists the header tip", function()
  local path, db

  before_each(function()
    path = os.tmpname()
    os.remove(path)
    os.execute("mkdir -p " .. path)
    db = storage_mod.open(path)
  end)

  after_each(function()
    if db then db.close() end
    os.execute("rm -rf " .. path)
  end)

  it("a restarted header chain still knows the block added by add_mined_tip", function()
    local cs = utxo.new_chain_state(db, REGTEST)
    cs:init()
    local hashes, prev = {}, types.hash256_zero()
    for h = 0, 3 do
      local b = simple_block(h, prev)
      local bh = validation.compute_block_hash(b.header)
      db.put_header(bh, b.header)
      db.put_block(bh, b)
      db.put_height_index(h, bh)
      assert(cs:connect_block(b, h, bh, nil, nil, true))
      hashes[h] = bh
      prev = bh
    end
    local hc = sync.new_header_chain(REGTEST, db)
    hc:init()
    for h = 1, 3 do
      assert(hc:add_mined_tip(db.get_header(hashes[h]), h, {memory_only = true}))
    end
    assert.equal(3, hc.header_tip_height)

    -- "Restart": a fresh header chain over the same storage.
    local hc2 = sync.new_header_chain(REGTEST, db)
    hc2:init()
    assert.equal(3, hc2.header_tip_height)
    assert.truthy(hc2.headers[types.hash256_hex(hashes[3])])
  end)

  -- Same row, the field-level rows it exposes once the header is stored: a
  -- header-only block above the active tip is NOT on the active chain
  -- (Core: confirmations -1, nTx 0, no nextblockhash).  The persisted height
  -- index also holds the best-HEADER chain, so a header accepted over P2P sits
  -- at tip+1 in it; getblockheader must not read that as active membership.
  it("getblockheader reports a header-only block above the tip as off-chain", function()
    local cs = utxo.new_chain_state(db, REGTEST)
    cs:init()
    local hashes, prev = {}, types.hash256_zero()
    for h = 0, 3 do
      local b = simple_block(h, prev)
      local bh = validation.compute_block_hash(b.header)
      db.put_header(bh, b.header)
      db.put_block(bh, b)
      db.put_height_index(h, bh)
      assert(cs:connect_block(b, h, bh, nil, nil, true))
      hashes[h] = bh
      prev = bh
    end
    -- This spec's chain is not the regtest genesis chain: drop the checkpoints.
    local NET = setmetatable({checkpoints = {}}, {__index = REGTEST})
    local hc = sync.new_header_chain(NET, db)
    hc:init()
    for h = 0, 3 do
      assert(hc:add_mined_tip(db.get_header(hashes[h]), h, {memory_only = true}))
    end
    local header = types.block_header(0x20000000, hashes[3], types.hash256_zero(),
      os.time() + 4, BITS, 0)
    local blk = types.block(header, {})
    assert(mining.mine_block(blk, 0x7FFFFFFF), "could not mine regtest header")
    local hh = validation.compute_block_hash(blk.header)
    assert(hc:accept_header(blk.header))
    assert.equal(4, hc.header_tip_height)
    assert.equal(3, cs.tip_height)

    local rpc = rpc_mod.new({rpcport = 0, network = REGTEST, chain_state = cs,
                             storage = db, header_chain = hc})
    local res = rpc.methods["getblockheader"](rpc, {types.hash256_hex(hh)})
    local j = cjson.decode(res._raw_json)
    assert.equal(-1, j.confirmations)
    assert.equal(0, j.nTx)
    assert.is_nil(j.nextblockhash)
    assert.equal(4, j.height)
  end)
end)
