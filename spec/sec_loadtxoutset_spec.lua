-- spec/sec_loadtxoutset_spec.lua
--
-- Security audit 2026-11-04, finding H2: a loadtxoutset that FAILS must leave
-- the live chainstate exactly as it was.
--
-- Before the fix, ChainState:load_snapshot wrote every snapshot coin into the
-- live CF.UTXO (periodic flush + final flush) BEFORE any hash gate ran, and
-- with no in-progress marker.  A load that then returned an error (content
-- hash mismatch, background re-validation mismatch, a bad coin late in the
-- file) left old + snapshot coins live, and the tip moved to the snapshot
-- base -- across a restart too.  The audit's regtest repro: total_amount 5550
-- instead of 5500 and a coin spent at height 102 unspent again.
--
-- Core (validation.cpp ActivateSnapshot / PopulateAndValidateSnapshot) loads
-- the coins into a SEPARATE snapshot chainstate and only activates it after
-- the content hash matched m_assumeutxo_data; on any failure the snapshot
-- chainstate is discarded and the original chainstate is untouched.
--
-- Every case below snapshots gettxoutsetinfo, getblockcount and
-- getbestblockhash through the RPC server, attempts the load, and compares
-- them again -- in-process and after closing and reopening the RocksDB
-- datadir.

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
  local p = string.format("/tmp/lb_sec_loadtxoutset_%s_%d_%d",
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

local function make_block(height, txs, prev_hash)
  local header = types.block_header(1, prev_hash, types.hash256_zero(),
    1700000000 + height, REGTEST.pow_limit_bits, 0)
  return types.block(header, txs)
end

-- Connect blocks 1..n-1 on top of regtest genesis (coinbase-only, `salt`
-- makes the chains distinct).  Every block is stored with its height-index
-- row so a background pass can read it back.
-- Returns db, chain_state, {blocks}, {hashes}.
local function build_chain(path, n_blocks, salt)
  local db = storage_mod.open(path)
  local cs = utxo.new_chain_state(db, REGTEST)
  cs:init()
  local spk = script.make_p2pkh_script(string.rep(string.char(salt), 20))
  local prev = cs.tip_hash
  local blocks, hashes = {}, {}
  hashes[0] = prev
  for h = 1, n_blocks - 1 do
    local blk = make_block(h, {make_coinbase_tx(h, 5000000000, spk, salt)}, prev)
    local bh = validation.compute_block_hash(blk.header)
    cs:connect_block(blk, h, bh)
    db.put_block(bh, blk)
    db.put_height_index(h, bh)
    blocks[h], hashes[h] = blk, bh
    prev = bh
  end
  return db, cs, blocks, hashes
end

local function network_with(height, blockhash_hex, hash_serialized_hex)
  local net = {}
  for k, v in pairs(REGTEST) do net[k] = v end
  net.assumeutxo = {
    [height] = {
      hash_serialized = hash_serialized_hex,
      m_chain_tx_count = height + 1,
      blockhash = blockhash_hex,
    },
  }
  return net
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

-- The observable live state: what an operator (or a peer-facing path) sees.
local function observe(server)
  local info, ierr = call(server, "gettxoutsetinfo")
  assert(info, "gettxoutsetinfo failed: " .. cjson.encode(ierr or {}))
  local count = call(server, "getblockcount")
  local best = call(server, "getbestblockhash")
  return {
    height = info.height,
    bestblock = info.bestblock,
    txouts = info.txouts,
    total_amount = tostring(info.total_amount),
    hash_serialized_3 = info.hash_serialized_3,
    blockcount = count,
    bestblockhash = best,
  }
end

local function reopen(path, net)
  local db = storage_mod.open(path)
  local cs = utxo.new_chain_state(db, net)
  cs:init()
  return db, cs, rpc.new({chain_state = cs, storage = db, network = net})
end

local function hex_display(raw32)
  return types.hash256_hex(types.hash256(raw32))
end

-- Rewrite a valid snapshot with its LAST coin replaced by mutate(entry):
-- every earlier coin parses and passes its gates first.
local function rewrite_last_coin(src_path, dst_path, mutate)
  local src = assert(io.open(src_path, "rb"))
  local data = src:read("*a")
  src:close()
  -- Parse the snapshot ourselves to find the last coin's byte range.
  local meta = utxo.deserialize_snapshot_metadata(data:sub(1, 51))
  local serialize = require("lunarblock.serialize")
  local r = serialize.buffer_reader(data:sub(52))
  local last_start, last_entry
  local left = tonumber(meta.coins_count)
  while left > 0 do
    r.read_bytes(32)
    local n = r.read_varint()
    for _ = 1, n do
      r.read_varint()
      last_start = r.position()
      last_entry = utxo.deserialize_snapshot_coin(r)
      left = left - 1
    end
  end
  local body = data:sub(52)
  local before = body:sub(1, last_start - 1)
  local out = data:sub(1, 51) .. before
    .. utxo.serialize_snapshot_coin(mutate(last_entry))
  local dst = assert(io.open(dst_path, "wb"))
  dst:write(out)
  dst:close()
end

-- The last coin's height above the base: the load fails only after it has
-- handled every other coin.
local function rewrite_last_coin_bad_height(src_path, dst_path, base_height)
  rewrite_last_coin(src_path, dst_path, function(e)
    return utxo.utxo_entry(e.value, e.script_pubkey, base_height + 1, e.is_coinbase)
  end)
end

-- Hand-build a snapshot of ONE txid whose coins are written in the given vout
-- order (Core writes a txid's coins in its VARINT key order, not numeric).
local function write_group_snapshot(path, base_hash, txid_bytes, vouts, height)
  local serialize = require("lunarblock.serialize")
  local w = serialize.buffer_writer()
  w.write_bytes(utxo.serialize_snapshot_metadata(
    utxo.snapshot_metadata(REGTEST.magic_bytes, base_hash, #vouts)))
  w.write_bytes(txid_bytes)
  w.write_varint(#vouts)
  for i, vout in ipairs(vouts) do
    w.write_varint(vout)
    w.write_bytes(utxo.serialize_snapshot_coin(utxo.utxo_entry(
      1000 + i, script.make_p2pkh_script(string.rep("\x77", 20)), height, false)))
  end
  local f = assert(io.open(path, "wb"))
  f:write(w.result())
  f:close()
end

-- HASH_SERIALIZED of a coin set as compute_utxo_stats computes it from a
-- chainstate DB (the walk gettxoutsetinfo and Core's ComputeUTXOStats use).
local function db_hash_of(coins)
  local cs = utxo.new_chain_state(storage_mod.new_memory_storage(), REGTEST)
  cs:init()
  for _, c in ipairs(coins) do cs.coin_view:add(c.txid, c.vout, c.entry) end
  return (cs:compute_utxo_hash())
end

-- Reads the in-progress marker; absent on a tree that has none.
local function read_marker(db)
  if not utxo.read_snapshot_load_marker then return nil end
  return utxo.read_snapshot_load_marker(db)
end

describe("H2: a failed loadtxoutset leaves the live UTXO set and tip untouched", function()

  -- Source chain (salt 0x51): five blocks, snapshot dumped at its tip (h=4).
  -- Live chain (salt 0x52): three blocks, tip h=2 < base, different coins.
  local src_dir, snap, snap_hash_raw, base_hex
  local cleanup = {}

  before_each(function()
    src_dir = new_dir("src")
    local sdb, scs = build_chain(src_dir, 5, 0x51)
    snap = src_dir .. ".snap"
    local res = assert(scs:dump_snapshot(snap))
    assert.is_truthy(res)
    snap_hash_raw = scs:compute_utxo_hash()
    base_hex = types.hash256_hex(scs.tip_hash)
    sdb.close()
    cleanup[#cleanup + 1] = snap
  end)

  after_each(function()
    for _, p in ipairs(cleanup) do os.remove(p) end
    cleanup = {}
    for _, p in ipairs(scratch) do os.execute("rm -rf '" .. p .. "'") end
    scratch = {}
  end)

  -- Live node at height 2 on a different chain; returns db path + server.
  local function live_node(net)
    local dir = new_dir("live")
    local db, cs = build_chain(dir, 3, 0x52)
    local server = rpc.new({chain_state = cs, storage = db, network = net})
    return dir, db, cs, server
  end

  local function assert_untouched(dir, db, server, net, before, label)
    assert.are.same(before, observe(server),
      label .. ": live state changed in-process after the refused load")
    db.close()
    local db2, _, server2 = reopen(dir, net)
    assert.are.same(before, observe(server2),
      label .. ": live state changed on disk after the refused load")
    db2.close()
  end

  it("content hash mismatch: refused, gettxoutsetinfo and tip identical, also after reopen", function()
    local net = network_with(4, base_hex, string.rep("ab", 32))
    local dir, db, _, server = live_node(net)
    local before = observe(server)
    assert.are.equal(2, before.blockcount)

    local res, err = call(server, "loadtxoutset", {snap})
    assert.is_nil(res)
    assert.is_truthy(err)
    assert.matches("Bad snapshot content hash", err.message)

    assert_untouched(dir, db, server, net, before, "hash mismatch")
  end)

  it("bad coin after every other coin was read: refused, live state untouched, also after reopen", function()
    local bad = snap .. ".badlast"
    cleanup[#cleanup + 1] = bad
    rewrite_last_coin_bad_height(snap, bad, 4)
    local net = network_with(4, base_hex, hex_display(snap_hash_raw))
    local dir, db, _, server = live_node(net)
    local before = observe(server)

    local res, err = call(server, "loadtxoutset", {bad})
    assert.is_nil(res)
    assert.matches("Bad snapshot data", err.message)

    assert_untouched(dir, db, server, net, before, "bad last coin")
  end)

  it("background re-validation mismatch: refused before any live write, also after reopen", function()
    -- The live node holds blocks 0..4 of ITS OWN chain (salt 0x53) but its
    -- tip was rolled back to 2.  A snapshot claiming that chain's block 4 as
    -- base carries the SOURCE chain's coins; the whitelist entry commits to
    -- that forged set, so only the background genesis->base replay of the
    -- live node's own blocks can catch it -- and it must do so before the
    -- live set is touched.
    local dir = new_dir("bgmm")
    local db, cs, blocks, hashes = build_chain(dir, 5, 0x53)
    for h = 4, 3, -1 do
      assert.is_truthy(cs:disconnect_block(blocks[h], h, hashes[h], hashes[h - 1]))
    end
    cs.tip_hash, cs.tip_height = hashes[2], 2
    db.set_chain_tip(hashes[2], 2, true)
    for h = 3, 4 do db.put_height_index(h, hashes[h]) end

    -- Forge: source coins, live chain's block-4 hash as base.
    local forged = snap .. ".forged"
    cleanup[#cleanup + 1] = forged
    do
      local f = assert(io.open(snap, "rb")); local data = f:read("*a"); f:close()
      local meta = utxo.deserialize_snapshot_metadata(data:sub(1, 51))
      local m2 = utxo.snapshot_metadata(REGTEST.magic_bytes, hashes[4], meta.coins_count)
      local o = assert(io.open(forged, "wb"))
      o:write(utxo.serialize_snapshot_metadata(m2) .. data:sub(52)); o:close()
    end
    local net = network_with(4, types.hash256_hex(hashes[4]), hex_display(snap_hash_raw))
    local server = rpc.new({chain_state = cs, storage = db, network = net})
    local before = observe(server)
    assert.are.equal(2, before.blockcount)

    local res, err = call(server, "loadtxoutset", {forged})
    assert.is_nil(res)
    assert.is_truthy(err)
    assert_untouched(dir, db, server, net, before, "background mismatch")
    -- The refusal came from the independent replay, not the content gate.
    assert.matches("background re%-validation", err.message)
  end)

  it("control: a good snapshot onto a lower live chain loads to exactly the snapshot's set", function()
    local net = network_with(4, base_hex, hex_display(snap_hash_raw))
    local dir, db, _, server = live_node(net)

    local res, err = call(server, "loadtxoutset", {snap})
    assert.is_truthy(res, "good snapshot refused: " .. cjson.encode(err or {}))
    assert.are.equal(4, res.base_height)

    local after = observe(server)
    assert.are.equal(4, after.blockcount)
    assert.are.equal(base_hex, after.bestblockhash)
    assert.are.equal(hex_display(snap_hash_raw), after.hash_serialized_3)
    assert.are.equal(4, after.txouts)
    db.close()

    local db2, _, server2 = reopen(dir, net)
    assert.are.same(after, observe(server2))
    db2.close()
  end)

  it("a write failure while committing leaves the marker, and a restart refuses the partial set", function()
    local fault = require("lunarblock.fault")
    local net = network_with(4, base_hex, hex_display(snap_hash_raw))
    local dir, db, cs, server = live_node(net)

    -- Fail the first batched write: on head that is the commit's wipe of the
    -- old coins, after the marker was made durable.
    local fired = false
    fault.hooks = { db_write = function()
      if fired then return nil end
      fired = true
      return "injected: disk full"
    end }
    local res, err = call(server, "loadtxoutset", {snap})
    fault.hooks = nil

    assert.is_nil(res)
    assert.is_truthy(err)
    assert.matches("incomplete", err.message)
    assert.is_truthy(cs.snapshot_commit_failed)
    -- The running node must not keep using the partial set: the AbortNode
    -- latch is set, so connect / submitblock / mempool entry points refuse.
    local latched = fault.is_latched()
    local ok_connect = pcall(fault.check_latch, "block connect")
    fault._reset_for_tests()
    assert.is_true(latched, "a failed commit left the node running on a partial set")
    assert.is_false(ok_connect)
    assert.are.equal(types.hash256_from_hex(base_hex).bytes, read_marker(db))
    db.close()

    -- A plain restart must refuse the half-written set.
    local db2 = storage_mod.open(dir)
    local cs2 = utxo.new_chain_state(db2, net)
    local ok_init, init_err = pcall(function() cs2:init() end)
    assert.is_false(ok_init, "restart accepted a half-written UTXO set")
    assert.matches("interrupted", tostring(init_err))

    -- --import-utxo finishes it: the whole set is rewritten, marker cleared.
    local cs3 = utxo.new_chain_state(db2, net)
    cs3.resume_interrupted_snapshot_load = true
    cs3:init()
    local ok_load, lerr = cs3:load_snapshot(snap, snap_hash_raw, 4)
    assert.is_true(ok_load, tostring(lerr))
    assert.is_nil(read_marker(db2))
    db2.close()

    local db4, _, server4 = reopen(dir, net)
    local after = observe(server4)
    assert.are.equal(4, after.blockcount)
    assert.are.equal(hex_display(snap_hash_raw), after.hash_serialized_3)
    db4.close()
  end)

  it("a snapshot file that changes between verify and commit is not activated", function()
    local net = network_with(4, base_hex, hex_display(snap_hash_raw))
    local dir, db, cs = live_node(net)
    local before_tip = cs.tip_hash

    local swapped = false
    local ok, err = cs:load_snapshot(snap, snap_hash_raw, 4, nil, nil, nil, nil,
      { pre_commit = function()
          -- Same count, every gate passes, one value differs.
          rewrite_last_coin(snap, snap, function(e)
            return utxo.utxo_entry(e.value - 1, e.script_pubkey, e.height, e.is_coinbase)
          end)
          swapped = true
          return true
        end })
    local fault = require("lunarblock.fault")
    local latched = fault.is_latched()
    fault._reset_for_tests()
    assert.is_true(swapped, "the verify pass never handed over to the commit")
    assert.is_false(ok)
    assert.is_true(latched, "a failed commit left the node running on a partial set")
    assert.matches("changed while it was being loaded", tostring(err))
    assert.are.equal(before_tip, cs.tip_hash)
    assert.is_truthy(read_marker(db))
    db.close()

    local db2 = storage_mod.open(dir)
    local cs2 = utxo.new_chain_state(db2, net)
    assert.is_false(pcall(function() cs2:init() end))
    db2.close()
  end)

  it("control: a Core-ordered txid group across the VARINT boundary loads to Core's hash", function()
    -- Core's cursor order for outputs 255, 16512, 256 (keys ..80 7f, ..80 80
    -- 00, ..81 00); its ComputeUTXOStats hashes them numerically.
    local txid_bytes = string.rep("\x5a", 32)
    local f = snap .. ".varint"
    cleanup[#cleanup + 1] = f
    write_group_snapshot(f, types.hash256_from_hex(base_hex), txid_bytes, {255, 16512, 256}, 1)
    local txid = types.hash256(txid_bytes)
    local spk = script.make_p2pkh_script(string.rep("\x77", 20))
    local want = db_hash_of({
      {txid = txid, vout = 255,   entry = utxo.utxo_entry(1001, spk, 1, false)},
      {txid = txid, vout = 16512, entry = utxo.utxo_entry(1002, spk, 1, false)},
      {txid = txid, vout = 256,   entry = utxo.utxo_entry(1003, spk, 1, false)},
    })

    local dir = new_dir("varint")
    local db = storage_mod.open(dir)
    local cs = utxo.new_chain_state(db, REGTEST)
    cs:init()
    local ok, err = cs:load_snapshot(f, want, 4)
    assert.is_true(ok, tostring(err))
    local got, n = cs:compute_utxo_hash()
    assert.are.equal(3, n)
    assert.are.equal(hex_display(want), hex_display(got))
    db.close()
  end)

  it("duplicate coin in a txid group keeps the first copy, as Core's loader does", function()
    -- Core: EmplaceCoinInternalDANGER is a try_emplace, so the first copy of a
    -- repeated outpoint wins and the content hash is of the collapsed set.
    local txid_bytes = string.rep("\x5b", 32)
    local txid = types.hash256(txid_bytes)
    local spk = script.make_p2pkh_script(string.rep("\x77", 20))
    local f = snap .. ".dup"
    cleanup[#cleanup + 1] = f
    write_group_snapshot(f, types.hash256_from_hex(base_hex), txid_bytes, {1, 1}, 1)
    local first = db_hash_of({
      {txid = txid, vout = 1, entry = utxo.utxo_entry(1001, spk, 1, false)}})
    local second = db_hash_of({
      {txid = txid, vout = 1, entry = utxo.utxo_entry(1002, spk, 1, false)}})

    -- Committed to the SECOND copy: refused, live state untouched.
    local net_b = network_with(4, base_hex, hex_display(second))
    local dir_b, db_b, _, server_b = live_node(net_b)
    local before = observe(server_b)
    local res_b, err_b = call(server_b, "loadtxoutset", {f})
    assert.is_nil(res_b)
    assert.is_truthy(err_b)
    assert_untouched(dir_b, db_b, server_b, net_b, before, "duplicate coin")
    assert.matches("Bad snapshot content hash", err_b.message)

    -- Committed to the FIRST copy: loads, and the live coin is the first one.
    local net_a = network_with(4, base_hex, hex_display(first))
    local dir_a, db_a, _, server_a = live_node(net_a)
    local res_a, err_a = call(server_a, "loadtxoutset", {f})
    assert.is_truthy(res_a, cjson.encode(err_a or {}))
    local after = observe(server_a)
    assert.are.equal(1, after.txouts)
    assert.are.equal(hex_display(first), after.hash_serialized_3)
    db_a.close()
    local _ = dir_a
  end)

  it("load_snapshot without a base height leaves the stored tip to the caller", function()
    -- An explicitly unsafe load with no base height (base_height = nil); the
    -- commit must not pair the base hash with a guessed height on disk.
    local net = network_with(4, base_hex, string.rep("00", 32))
    local _, db, cs = live_node(net)
    local old_hash, old_height = db.get_chain_tip()
    local f = snap .. ".nobase"
    cleanup[#cleanup + 1] = f
    write_group_snapshot(f, types.hash256_from_hex(base_hex), string.rep("\x5c", 32), {0}, 1)
    local ok, err = cs:load_snapshot(f, nil, nil, nil, nil, nil, nil, {unsafe_unverified = true})
    assert.is_true(ok, tostring(err))
    local hash, height = db.get_chain_tip()
    assert.are.equal(old_hash.bytes, hash.bytes)
    assert.are.equal(old_height, height)
    assert.is_nil(read_marker(db))
    db.close()
  end)

  -- --import-utxo (main.lua run_import_utxo) against a datadir that already
  -- holds a chain.  Runs the real CLI in a child process, exactly as an
  -- operator would, with the snapshot's base allowlisted through
  -- HASHHOG_CAMPAIGN_ASSUMEUTXO under `hash_serialized_hex`.
  local function run_import(hash_serialized_hex)
    local root = new_dir("imp")
    local cs_dir = root .. "/regtest/chainstate"
    os.execute("mkdir -p '" .. root .. "/regtest'")
    local db = build_chain(cs_dir, 3, 0x52)
    db.close()
    local before_db, _, before_server = reopen(cs_dir, REGTEST)
    local before = observe(before_server)
    before_db.close()
    assert.are.equal(2, before.blockcount)

    local campaign = root .. ".campaign.json"
    cleanup[#cleanup + 1] = campaign
    local cf = assert(io.open(campaign, "wb"))
    cf:write(cjson.encode({{height = 4, blockhash = base_hex,
      hash_serialized = hash_serialized_hex, m_chain_tx_count = 5}}))
    cf:close()
    local out = root .. ".out"
    cleanup[#cleanup + 1] = out
    local cmd = string.format(
      "HASHHOG_CAMPAIGN_ASSUMEUTXO='%s' luajit src/main.lua --regtest "
      .. "--datadir '%s' --import-utxo '%s' > '%s' 2>&1",
      campaign, root, snap, out)
    local r1, _, r3 = os.execute(cmd)
    local code = (type(r1) == "number") and r1 or r3
    local of = assert(io.open(out, "rb")); local text = of:read("*a"); of:close()
    return cs_dir, before, code, text
  end

  it("--import-utxo with a mismatched assumeutxo hash leaves the on-disk tip and UTXO set unchanged", function()
    local cs_dir, before, code, text = run_import(string.rep("ab", 32))
    assert.are_not.equal(0, code, "import of a mismatched snapshot exited 0: " .. text)

    local db, _, server = reopen(cs_dir, REGTEST)
    local after = observe(server)
    local marker = read_marker(db)
    local record = utxo.read_snapshot_record(db)
    db.close()
    assert.are.same(before, after,
      "--import-utxo replaced the live set with a snapshot that failed its commitment")
    assert.is_nil(marker, "--import-utxo left the in-progress marker set")
    assert.is_nil(record, "--import-utxo recorded a snapshot start for a refused snapshot")
    -- Refused by load_snapshot's pre-write gate, not by the post-load check.
    assert.matches("import%-utxo FAILED: snapshot hash mismatch %(hash_serialized%)", text)
  end)

  it("control: --import-utxo with the matching assumeutxo hash loads the snapshot", function()
    local cs_dir, before, code, text = run_import(hex_display(snap_hash_raw))
    assert.are.equal(0, code, "good snapshot import failed: " .. text)
    assert.matches("MATCHES assumeutxo", text)

    local db, _, server = reopen(cs_dir, REGTEST)
    local after = observe(server)
    assert.are_not.same(before, after)
    assert.are.equal(4, after.blockcount)
    assert.are.equal(base_hex, after.bestblockhash)
    assert.are.equal(hex_display(snap_hash_raw), after.hash_serialized_3)
    assert.is_nil(read_marker(db))
    assert.is_truthy(utxo.read_snapshot_record(db))
    db.close()
  end)

  it("txid groups out of order: refused before any write, live state untouched", function()
    -- Two one-coin groups, the larger txid first.
    local serialize = require("lunarblock.serialize")
    local w = serialize.buffer_writer()
    w.write_bytes(utxo.serialize_snapshot_metadata(
      utxo.snapshot_metadata(REGTEST.magic_bytes, types.hash256_from_hex(base_hex), 2)))
    for _, b in ipairs({"\x6b", "\x6a"}) do
      w.write_bytes(string.rep(b, 32))
      w.write_varint(1)
      w.write_varint(0)
      w.write_bytes(utxo.serialize_snapshot_coin(utxo.utxo_entry(
        1000, script.make_p2pkh_script(string.rep("\x77", 20)), 1, false)))
    end
    local f = snap .. ".order"
    cleanup[#cleanup + 1] = f
    local fh = assert(io.open(f, "wb")); fh:write(w.result()); fh:close()

    local net = network_with(4, base_hex, string.rep("ef", 32))
    local dir, db, _, server = live_node(net)
    local before = observe(server)
    local res, err = call(server, "loadtxoutset", {f})
    assert.is_nil(res)
    assert.is_truthy(err)
    assert_untouched(dir, db, server, net, before, "txid order")
    assert.matches("coins out of order", err.message)
  end)
end)
