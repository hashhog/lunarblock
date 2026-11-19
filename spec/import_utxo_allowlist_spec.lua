-- spec/import_utxo_allowlist_spec.lua
--
-- --import-utxo must refuse a snapshot whose base block has no assumeutxo
-- entry, exactly as loadtxoutset does, unless HASHHOG_UNSAFE_SNAPSHOT_HEIGHT
-- is set.
--
-- Before the fix run_import_utxo (src/main.lua) only WARNED when the base was
-- not allowlisted and then called cs:load_snapshot(file, nil, nil).  With
-- expected_hash nil the HASH_SERIALIZED gate was skipped and the per-coin
-- height bound fell back to the CURRENT TIP, so on a datadir already past the
-- snapshot's base height any well-formed Core-format file replaced the live
-- UTXO set and the run exited 0 ("NOT VERIFIED").
--
-- Core: ChainstateManager::ActivateSnapshot (validation.cpp) refuses a base
-- blockhash with no m_assumeutxo_data entry before reading a coin
-- ("assumeutxo block hash in snapshot metadata not recognized").
--
-- The second half pins the library gate: ChainState:load_snapshot with no
-- expected_hash refuses unless the caller passes an explicit reason
-- (opts.unsafe_unverified / opts.hash_gated_by_caller), and
-- activate_snapshot_with_background with no commitment refuses unless
-- opts.unsafe_unverified.

local types       = require("lunarblock.types")
local utxo        = require("lunarblock.utxo")
local consensus   = require("lunarblock.consensus")
local validation  = require("lunarblock.validation")
local storage_mod = require("lunarblock.storage")
local script      = require("lunarblock.script")
local rpc         = require("lunarblock.rpc")
local cjson       = require("cjson")

local REGTEST = consensus.networks.regtest

local scratch = {}

local function new_dir(tag)
  local p = string.format("/tmp/lb_import_utxo_allowlist_%s_%d_%d",
    tag, os.time(), math.random(1000000000))
  scratch[#scratch + 1] = p
  return p
end

local function make_coinbase_tx(height, value, script_pubkey, salt)
  return types.transaction(
    1,
    {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                string.char(1, height % 256, salt), 0xFFFFFFFF)},
    {types.txout(value, script_pubkey)},
    0)
end

-- Connect blocks 1..n-1 on top of regtest genesis (coinbase-only; `salt`
-- makes chains distinct).  Returns db, chain_state.
local function build_chain(path, n_blocks, salt)
  local db = storage_mod.open(path)
  local cs = utxo.new_chain_state(db, REGTEST)
  cs:init()
  local spk = script.make_p2pkh_script(string.rep(string.char(salt), 20))
  local prev = cs.tip_hash
  for h = 1, n_blocks - 1 do
    local header = types.block_header(1, prev, types.hash256_zero(),
      1700000000 + h, REGTEST.pow_limit_bits, 0)
    local blk = types.block(header, {make_coinbase_tx(h, 5000000000, spk, salt)})
    local bh = validation.compute_block_hash(blk.header)
    cs:connect_block(blk, h, bh)
    db.put_block(bh, blk)
    db.put_height_index(h, bh)
    prev = bh
  end
  return db, cs
end

local function call(server, method, params)
  local raw = server:handle_request(cjson.encode(
    {jsonrpc = "1.0", id = 1, method = method, params = params or {}}))
  local resp = cjson.decode(raw)
  if resp.error ~= nil and resp.error ~= cjson.null then
    return nil, resp.error
  end
  return resp.result
end

local function observe(server)
  local info, ierr = call(server, "gettxoutsetinfo")
  assert(info, "gettxoutsetinfo failed: " .. cjson.encode(ierr or {}))
  return {
    height = info.height,
    bestblock = info.bestblock,
    txouts = info.txouts,
    total_amount = tostring(info.total_amount),
    hash_serialized_3 = info.hash_serialized_3,
    blockcount = call(server, "getblockcount"),
    bestblockhash = call(server, "getbestblockhash"),
  }
end

local function reopen(path)
  local db = storage_mod.open(path)
  local cs = utxo.new_chain_state(db, REGTEST)
  cs:init()
  return db, cs, rpc.new({chain_state = cs, storage = db, network = REGTEST})
end

describe("--import-utxo / load_snapshot refuse a snapshot with no assumeutxo commitment", function()

  -- Source chain (salt 0x61): five blocks, snapshot dumped at its tip (h=4).
  -- Its base is NOT in regtest's assumeutxo table.
  local snap, base_hex
  local cleanup = {}

  before_each(function()
    local src_dir = new_dir("src")
    local sdb, scs = build_chain(src_dir, 5, 0x61)
    snap = src_dir .. ".snap"
    cleanup[#cleanup + 1] = snap
    assert.is_truthy(scs:dump_snapshot(snap))
    base_hex = types.hash256_hex(scs.tip_hash)
    sdb.close()
    local au = consensus.assumeutxo_for_blockhash(REGTEST, base_hex)
    assert.is_nil(au, "fixture base must not be allowlisted")
  end)

  after_each(function()
    for _, p in ipairs(cleanup) do os.remove(p) end
    cleanup = {}
    for _, p in ipairs(scratch) do os.execute("rm -rf '" .. p .. "'") end
    scratch = {}
  end)

  -- A live regtest datadir at height 5 (past the snapshot base, so the tip
  -- height bound master fell back to does not stop the coins), on a different
  -- chain.  Runs the real CLI in a child process with the given env prefix.
  local function run_import(env_prefix)
    local root = new_dir("imp")
    local cs_dir = root .. "/regtest/chainstate"
    os.execute("mkdir -p '" .. root .. "/regtest'")
    local db = build_chain(cs_dir, 6, 0x62)
    db.close()
    local bdb, _, bserver = reopen(cs_dir)
    local before = observe(bserver)
    bdb.close()
    assert.are.equal(5, before.blockcount)

    local out = root .. ".out"
    cleanup[#cleanup + 1] = out
    local cmd = string.format(
      "env -u HASHHOG_CAMPAIGN_ASSUMEUTXO -u HASHHOG_UNSAFE_SNAPSHOT_HEIGHT %s "
      .. "luajit src/main.lua --regtest --datadir '%s' --import-utxo '%s' > '%s' 2>&1",
      env_prefix or "", root, snap, out)
    local r1, _, r3 = os.execute(cmd)
    local code = (type(r1) == "number") and r1 or r3
    local of = assert(io.open(out, "rb")); local text = of:read("*a"); of:close()
    local adb, _, aserver = reopen(cs_dir)
    local after = observe(aserver)
    local record = utxo.read_snapshot_record(adb)
    adb.close()
    return before, after, code, text, record
  end

  it("--import-utxo refuses a non-allowlisted base and leaves the UTXO set and tip unchanged", function()
    local before, after, code, text, record = run_import(nil)
    assert.are_not.equal(0, code, "non-allowlisted import exited 0: " .. text)
    assert.matches("import%-utxo FAILED: Assumeutxo height in snapshot metadata "
      .. "not recognized %([%d%?]+%) %- refusing to load snapshot", text)
    assert.are.same(before, after,
      "--import-utxo replaced the live set with a non-allowlisted snapshot")
    assert.is_nil(record, "a refused import recorded a snapshot start")
  end)

  it("--import-utxo message matches loadtxoutset's for the same file", function()
    local dir = new_dir("rpc")
    local db, cs = build_chain(dir, 6, 0x63)
    local server = rpc.new({chain_state = cs, storage = db, network = REGTEST})
    local res, err = call(server, "loadtxoutset", {snap})
    db.close()
    assert.is_nil(res)
    local _, _, code, text = run_import(nil)
    assert.are_not.equal(0, code)
    assert.is_truthy(text:find("import-utxo FAILED: " .. err.message, 1, true),
      "CLI text " .. text .. " does not carry RPC message " .. err.message)
  end)

  it("control: HASHHOG_UNSAFE_SNAPSHOT_HEIGHT still lets --import-utxo load", function()
    local before, after, code, text = run_import("HASHHOG_UNSAFE_SNAPSHOT_HEIGHT=4")
    assert.are.equal(0, code, "unsafe-override import failed: " .. text)
    assert.matches("UNVERIFIED SNAPSHOT ACCEPTED", text)
    assert.matches("NOT VERIFIED", text)
    assert.are_not.same(before, after)
    assert.are.equal(4, after.blockcount)
    assert.are.equal(base_hex, after.bestblockhash)
  end)

  it("load_snapshot with no expected_hash and no unsafe flag refuses and writes nothing", function()
    local dir = new_dir("lib")
    local db, cs = build_chain(dir, 6, 0x64)
    local server = rpc.new({chain_state = cs, storage = db, network = REGTEST})
    local before = observe(server)
    local ok, err = cs:load_snapshot(snap)
    assert.is_false(ok)
    assert.matches("no assumeutxo hash_serialized", tostring(err))
    assert.are.same(before, observe(server))
    db.close()
    local db2, _, server2 = reopen(dir)
    assert.are.same(before, observe(server2))
    db2.close()
  end)

  it("control: load_snapshot with opts.unsafe_unverified loads without a hash", function()
    local dir = new_dir("libok")
    local db, cs = build_chain(dir, 6, 0x65)
    local ok, err = cs:load_snapshot(snap, nil, 4, nil, nil, nil, nil,
      {unsafe_unverified = true})
    assert.is_true(ok, tostring(err))
    db.close()
  end)

  it("activate_snapshot_with_background with no commitment refuses unless opts.unsafe_unverified", function()
    local get_block = function() return nil end
    local au_nohash = {height = 4, blockhash = base_hex}

    local dir = new_dir("act")
    local db, cs = build_chain(dir, 6, 0x66)
    local server = rpc.new({chain_state = cs, storage = db, network = REGTEST})
    local before = observe(server)
    local act, aerr = utxo.activate_snapshot_with_background(
      cs, snap, au_nohash, 4, get_block, {})
    assert.is_nil(act, "activation with no commitment and no unsafe flag succeeded")
    assert.matches("no assumeutxo hash_serialized", tostring(aerr))
    assert.are.same(before, observe(server))
    db.close()

    local dir2 = new_dir("act2")
    local db2, cs2 = build_chain(dir2, 6, 0x67)
    local act2, aerr2 = utxo.activate_snapshot_with_background(
      cs2, snap, au_nohash, 4, get_block, {unsafe_unverified = true})
    assert.is_not_nil(act2, tostring(aerr2))
    db2.close()
  end)
end)
