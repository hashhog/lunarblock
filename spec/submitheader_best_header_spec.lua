-- spec/submitheader_best_header_spec.lua
--
-- Core regtest ratchet, warden_invalidated_submit/{headers-only,restart,
-- p2p-header}/info:headers: after two submitheader calls on top of the tip
-- (208), Core's getblockchaininfo reports headers=210 and keeps it across a
-- restart; lunarblock reported 208 (and 209 once a P2P header arrived).
--
-- Core: getblockchaininfo "headers" is chainman.m_best_header->nHeight
-- (src/rpc/blockchain.cpp:1423).  submitheader -> ProcessNewBlockHeaders ->
-- AcceptBlockHeader -> BlockManager::AddToBlockIndex(block, m_best_header)
-- (src/validation.cpp:4233) moves m_best_header on more work
-- (src/node/blockstorage.cpp:249-250), and the block index (header included)
-- is persisted; LoadBlockIndex rebuilds m_best_header from it at boot
-- (src/validation.cpp:4919-4920), so the best header survives a restart.
--
-- Two lunarblock defects behind the one symptom:
--   * getblockchaininfo read chain_state.header_tip_height, which is copied
--     from the header chain only on the P2P headers path (main.lua), so a
--     submitheader-accepted header never reached it (nor a boot: it fell back
--     to the block tip);
--   * submitheader called HeaderChain:accept_header directly and never wrote
--     the header_tip META record (process_headers does), so a restart loaded
--     the header chain only up to the last mined/P2P tip.

local types = require("lunarblock.types")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local script = require("lunarblock.script")
local storage_mod = require("lunarblock.storage")
local sync = require("lunarblock.sync")
local mining = require("lunarblock.mining")
local rpc_mod = require("lunarblock.rpc")
local serialize = require("lunarblock.serialize")
local cjson = require("cjson")

local REGTEST = consensus.networks.regtest
local BITS = REGTEST.pow_limit_bits
local SPK = script.make_p2pkh_script(string.rep("\x42", 20))
-- This spec's chain is not the regtest genesis chain: drop the checkpoints.
local NET = setmetatable({checkpoints = {}}, {__index = REGTEST})

local function simple_block(height, prev_hash)
  local cb = types.transaction(1,
    {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                string.char(1, height % 256), 0xFFFFFFFF)},
    {types.txout(5000000000, SPK)}, 0)
  local header = types.block_header(1, prev_hash or types.hash256_zero(),
    types.hash256_zero(), os.time() + height, BITS, 0)
  return types.block(header, {cb})
end

local function to_hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function mined_header_hex(prev_hash, t)
  local blk = types.block(types.block_header(0x20000000, prev_hash,
    types.hash256_zero(), t, BITS, 0), {})
  assert(mining.mine_block(blk, 0x7FFFFFFF), "could not mine regtest header")
  return to_hex(serialize.serialize_block_header(blk.header)),
         validation.compute_block_hash(blk.header)
end

local function headers_of(rpc)
  local res = rpc.methods["getblockchaininfo"](rpc, {})
  local j = res._raw_json and cjson.decode(res._raw_json) or res
  return j.headers, j.blocks
end

describe("submitheader moves getblockchaininfo.headers (Core m_best_header)", function()
  local path, db, cs, tip3

  local function build_chain()
    cs = utxo.new_chain_state(db, REGTEST)
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
    tip3 = prev
    local hc = sync.new_header_chain(NET, db)
    hc:init()
    for h = 0, 3 do
      assert(hc:add_mined_tip(db.get_header(hashes[h]), h))
    end
    assert.equal(3, hc.header_tip_height)
    return hc
  end

  local function submit_two(rpc)
    local t = os.time() + 10
    local h4hex, h4 = mined_header_hex(tip3, t)
    local h5hex = mined_header_hex(h4, t + 1)
    assert.equal(cjson.null, rpc.methods["submitheader"](rpc, {h4hex}))
    assert.equal(cjson.null, rpc.methods["submitheader"](rpc, {h5hex}))
  end

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

  it("headers-only: getblockchaininfo.headers counts headers accepted by submitheader", function()
    local hc = build_chain()
    local rpc = rpc_mod.new({rpcport = 0, network = REGTEST, chain_state = cs,
                             storage = db, header_chain = hc})
    submit_two(rpc)
    assert.equal(5, hc.header_tip_height)
    local headers, blocks = headers_of(rpc)
    assert.equal(3, blocks)
    assert.equal(5, headers)
  end)

  it("restart: a header accepted by submitheader is still the best header after a restart", function()
    local hc = build_chain()
    local rpc = rpc_mod.new({rpcport = 0, network = REGTEST, chain_state = cs,
                             storage = db, header_chain = hc})
    submit_two(rpc)

    -- "Restart": fresh chain state and header chain over the same storage.
    local cs2 = utxo.new_chain_state(db, REGTEST)
    cs2:init()
    local hc2 = sync.new_header_chain(NET, db)
    hc2:init()
    assert.equal(5, hc2.header_tip_height)
    local rpc2 = rpc_mod.new({rpcport = 0, network = REGTEST, chain_state = cs2,
                              storage = db, header_chain = hc2})
    local headers, blocks = headers_of(rpc2)
    assert.equal(3, blocks)
    assert.equal(5, headers)
  end)

  -- Control: with no header beyond the tip, headers == blocks (the fix must
  -- not invent headers).
  it("control: no submitted header leaves headers equal to blocks", function()
    local hc = build_chain()
    local rpc = rpc_mod.new({rpcport = 0, network = REGTEST, chain_state = cs,
                             storage = db, header_chain = hc})
    local headers, blocks = headers_of(rpc)
    assert.equal(3, blocks)
    assert.equal(3, headers)
  end)
end)
