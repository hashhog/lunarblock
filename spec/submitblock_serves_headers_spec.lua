-- spec/submitblock_serves_headers_spec.lua
--
-- SERVE scenario finding (tools/conformance-scenarios.py --scenario SERVE,
-- item done-lunarblock-serve-proof).  A block connected through the
-- submitblock RPC never reached the in-memory HeaderChain, so
-- header_tip_height stayed behind chain_state.tip_height and
-- peerman.getheaders_response (which serves min(header tip, active tip))
-- answered a peer's getheaders with an EMPTY `headers`.  A Core peer dialing
-- in could never sync a chain that had been fed by submitblock.
-- (generatetoaddress already calls HeaderChain:add_mined_tip; submitblock did not.)

local types = require("lunarblock.types")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local script = require("lunarblock.script")
local crypto = require("lunarblock.crypto")
local mining = require("lunarblock.mining")
local storage_mod = require("lunarblock.storage")
local sync = require("lunarblock.sync")
local serialize = require("lunarblock.serialize")
local rpc_mod = require("lunarblock.rpc")
local peerman = require("lunarblock.peerman")
local p2p = require("lunarblock.p2p")

local REGTEST = consensus.networks.regtest
local BITS = REGTEST.pow_limit_bits
local BLOCK_VERSION = 0x20000000
local SPK = script.make_p2pkh_script(string.rep("\x42", 20))

local function subsidy(height)
  return math.floor(5000000000 / (2 ^ math.floor(height / 150)))
end

local function simple_block(height, prev_hash)
  local cb = types.transaction(1,
    {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                string.char(1, height % 256), 0xFFFFFFFF)},
    {types.txout(subsidy(height), SPK)}, 0)
  local header = types.block_header(1, prev_hash or types.hash256_zero(),
    types.hash256_zero(), os.time() + height, BITS, 0)
  return types.block(header, {cb})
end

local function valid_block(height, prev_hash)
  local witness_root = crypto.compute_merkle_root({types.hash256_zero()})
  local commitment = crypto.hash256(witness_root.bytes .. string.rep("\0", 32))
  local coinbase = mining.create_coinbase_tx(height, subsidy(height),
    "/serve-test/", commitment, SPK)
  local merkle = crypto.compute_merkle_root({validation.compute_txid(coinbase)})
  local header = types.block_header(BLOCK_VERSION, prev_hash, merkle,
    os.time() + height, BITS, 0)
  local block = types.block(header, {coinbase})
  assert(mining.mine_block(block, 0x7FFFFFFF), "could not mine regtest block")
  return block, validation.compute_block_hash(block.header)
end

local function make_temp_dir()
  local tmpname = os.tmpname()
  os.remove(tmpname)
  os.execute("mkdir -p " .. tmpname)
  return tmpname
end

describe("submitblock advances the header chain (getheaders serving)", function()
  local db, cs, hc, rpc, path, hashes

  before_each(function()
    path = make_temp_dir()
    db = storage_mod.open(path)
    cs = utxo.new_chain_state(db, REGTEST)
    cs:init()
    hashes = {}
    local prev = types.hash256_zero()
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
    hc = sync.new_header_chain(REGTEST, db)
    hc:init()
    -- The prefix was connected directly (as a restart would load it): give the
    -- header chain the same blocks so the locator below is known to it.
    for h = 1, 3 do
      local hdr = db.get_header(hashes[h])
      assert(hc:add_mined_tip(hdr, h))
    end
    assert.equal(3, hc.header_tip_height)
    rpc = rpc_mod.new({rpcport = 0, network = REGTEST, chain_state = cs,
                       storage = db, header_chain = hc})
  end)

  after_each(function()
    if db then db.close() end
    os.execute("rm -rf " .. path)
  end)

  it("serves the submitted block in answer to getheaders", function()
    local blk, bh = valid_block(4, hashes[3])
    local res = rpc.methods["submitblock"](rpc, {
      mining.hex_encode(serialize.serialize_block(blk))})
    assert.is_nil(res ~= require("cjson").null and res or nil)
    assert.equal(4, cs.tip_height)
    assert.equal(4, hc.header_tip_height)
    local payload = peerman.getheaders_response(
      {block_locator_hashes = {hashes[3]},
       hash_stop = types.hash256(string.rep("\0", 32))},
      hc, cs.tip_height)
    local headers = p2p.deserialize_headers(payload)
    assert.equal(1, #headers)
    assert.truthy(types.hash256_eq(validation.compute_block_hash(headers[1]), bh))
  end)

  -- hashhog/lunarblock#26 review: the persisted height index belongs to the
  -- chainstate activation path (submitblock's accept_block batch).  The
  -- header-chain bump must stay in memory, so a header that merely wins the
  -- header-work compare cannot repoint heights the active chain still owns
  -- (it moved getchaintips in the core-regtest failed_reorg scenarios).
  it("does not write the persisted height index from the header chain", function()
    local blk, bh = valid_block(4, hashes[3])
    local writes = {}
    local real_put = db.put_height_index
    db.put_height_index = function(h, hash)
      writes[#writes + 1] = h
      return real_put(h, hash)
    end
    local res = rpc.methods["submitblock"](rpc, {
      mining.hex_encode(serialize.serialize_block(blk))})
    db.put_height_index = real_put
    assert.is_nil(res ~= require("cjson").null and res or nil)
    assert.equal(4, hc.header_tip_height)
    assert.equal(types.hash256_hex(bh), hc.height_to_hash[4])
    assert.same({}, writes)
    -- The activation batch still recorded the block at its height.
    assert.truthy(types.hash256_eq(db.get_hash_by_height(4), bh))
  end)

  -- hashhog/lunarblock#26 review: after a restart the in-memory map can hold
  -- only genesis (core-regtest failed_reorg a-restart-child).  The header tip
  -- then jumped to the submitted block with heights 1..3 missing from
  -- height_to_hash, and getchaintips reported the active block below the new
  -- tip as an extra valid-headers tip of branchlen 4.
  it("leaves no height_to_hash hole when the map is partial after a restart", function()
    local fresh = sync.new_header_chain(REGTEST, db)
    fresh:init()
    -- This spec's chain starts from its own height-0 block, not the regtest
    -- genesis; make it resident the way init makes the real genesis resident.
    local g = db.get_header(hashes[0])
    fresh.headers[types.hash256_hex(hashes[0])] =
      {header = g, height = 0, total_work = fresh:work_for_bits(g.bits)}
    fresh.height_to_hash[0] = types.hash256_hex(hashes[0])
    assert.is_nil(fresh.headers[types.hash256_hex(hashes[3])])
    local r = rpc_mod.new({rpcport = 0, network = REGTEST, chain_state = cs,
                           storage = db, header_chain = fresh})
    local blk, bh = valid_block(4, hashes[3])
    local res = r.methods["submitblock"](r, {
      mining.hex_encode(serialize.serialize_block(blk))})
    assert.is_nil(res ~= require("cjson").null and res or nil)
    assert.equal(4, fresh.header_tip_height)
    for h = 1, 3 do
      assert.equal(types.hash256_hex(hashes[h]), fresh.height_to_hash[h])
    end
    local tips = require("lunarblock.chaintips").tips(
      {storage = db, chain_state = cs, header_chain = fresh})
    assert.equal(1, #tips)
    assert.equal(types.hash256_hex(bh), tips[1].hash)
    assert.equal("active", tips[1].status)
  end)
end)
