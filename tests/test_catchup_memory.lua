#!/usr/bin/env luajit
-- Catch-up working set is bounded by --dbcache, not by how far behind we are.
--
-- Live 2026-09-18T01:35-01:55Z: an 8-day resume (~1,130 blocks behind)
-- filled the 12 G cgroup, then the raised 20 G cgroup, and pinned there
-- while connecting. Raising the ceiling raised the plateau — the signature
-- of a working set that scales with the backlog. Root cause: handle_block
-- kept up to download_window (1024) fully decoded Lua block objects in
-- pending_blocks. A recent mainnet block is ~2 MB on the wire and tens of
-- MB as Lua tables; 1024 of those is the 12–20 G RSS. Bitcoin Core writes
-- the body to disk on receipt and does not keep a decoded CBlock per
-- in-flight height.
--
-- Operator contract: a node 1,000 blocks behind must not need more RAM
-- than one 10 blocks behind. Bound = configured dbcache, not the gap.
--
-- ASK (2) 15.3 s connect_callback: that banner fires at the 10 s threshold
-- while the heap is at the cgroup ceiling. LuaJIT GC on a 20 G live set of
-- decoded pending blocks runs inside connect_block. After this bound the
-- decoded live set is one block; remaining connect cost is script
-- verification (R4), not the catch-up working set.
-- ASK (3) the 20 G MemoryMax is a runtime systemd property and is lost on
-- restart — that is the tools/operator item, not this node.
--
-- Control: luajit tests/test_catchup_memory.lua

package.path = "src/?.lua;src/?/init.lua;" .. package.path

local sync       = require("lunarblock.sync")
local types      = require("lunarblock.types")
local serialize  = require("lunarblock.serialize")
local consensus  = require("lunarblock.consensus")
local validation = require("lunarblock.validation")

local NET = consensus.networks.regtest
local PASS, FAIL = 0, 0

local function pass(name)
  io.write(string.format("  PASS  %s\n", name)); PASS = PASS + 1
end
local function fail(name, msg)
  io.write(string.format("  FAIL  %s -- %s\n", name, msg)); FAIL = FAIL + 1
end
local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end
local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a)
      .. ", expected " .. tostring(b), 2)
  end
end
local function expect_true(v, msg)
  if not v then error((msg or "expected true") .. ": got " .. tostring(v), 2) end
end
local function expect_false(v, msg)
  if v then error((msg or "expected false") .. ": got " .. tostring(v), 2) end
end
local function expect_lt(a, b, msg)
  if not (a < b) then
    error((msg or "expected a < b") .. ": " .. tostring(a) .. " < " .. tostring(b), 2)
  end
end
local function expect_le(a, b, msg)
  if not (a <= b) then
    error((msg or "expected a <= b") .. ": " .. tostring(a) .. " <= " .. tostring(b), 2)
  end
end

--------------------------------------------------------------------------------
-- Minimal in-memory storage (same shape as spec/sync_spec.lua).
--------------------------------------------------------------------------------
local function create_storage()
  local data = { headers = {}, height_index = {}, meta = {}, blocks = {} }
  local storage = {
    CF = { META = "meta", HEADERS = "headers", HEIGHT_INDEX = "height", BLOCKS = "blocks" },
  }
  function storage.get(cf, key)
    if cf == "meta" then return data.meta[key] end
    if cf == "headers" then return data.headers[key] end
    if cf == "height" then return data.height_index[key] end
    if cf == "blocks" then return data.blocks[key] end
    return nil
  end
  function storage.put(cf, key, value)
    if cf == "meta" then data.meta[key] = value
    elseif cf == "headers" then data.headers[key] = value
    elseif cf == "height" then data.height_index[key] = value
    elseif cf == "blocks" then data.blocks[key] = value end
  end
  function storage.get_header(block_hash)
    local header_data = data.headers[block_hash.bytes]
    if not header_data then return nil end
    return serialize.deserialize_block_header(header_data)
  end
  function storage.put_header(block_hash, header)
    data.headers[block_hash.bytes] = serialize.serialize_block_header(header)
  end
  function storage.get_hash_by_height(height)
    local key = string.char(
      math.floor(height / 16777216) % 256,
      math.floor(height / 65536) % 256,
      math.floor(height / 256) % 256,
      height % 256)
    local hash_bytes = data.height_index[key]
    if not hash_bytes or #hash_bytes ~= 32 then return nil end
    return types.hash256(hash_bytes)
  end
  function storage.put_height_index(height, block_hash)
    local key = string.char(
      math.floor(height / 16777216) % 256,
      math.floor(height / 65536) % 256,
      math.floor(height / 256) % 256,
      height % 256)
    data.height_index[key] = block_hash.bytes
  end
  function storage.get_chain_tip() return nil, nil end
  function storage.set_chain_tip() end
  function storage.put_block(block_hash, blk)
    data.blocks[block_hash.bytes] = serialize.serialize_block(blk)
  end
  function storage.get_block(block_hash)
    local d = data.blocks[block_hash.bytes]
    if not d then return nil end
    return serialize.deserialize_block(d)
  end
  return storage
end

local function find_valid_nonce(header)
  local target = consensus.bits_to_target(header.bits)
  for nonce = 0, 1000000 do
    header.nonce = nonce
    local hash = validation.compute_block_hash(header)
    if consensus.hash_meets_target(hash.bytes, target) then return true end
  end
  return false
end

local function accept_headers(chain, n)
  local parent = chain:get_tip_hash()
  local ts = NET.genesis.timestamp
  for i = 1, n do
    ts = ts + 600
    local header = types.block_header(4, parent, types.hash256_zero(), ts, 0x207fffff, 0)
    assert(find_valid_nonce(header), "nonce grind failed at height " .. i)
    assert(chain:accept_header(header), "accept_header failed at height " .. i)
    parent = validation.compute_block_hash(header)
  end
end

-- Many small outputs → Lua tables explode vs compact wire bytes, which is
-- the live mainnet shape (thousands of txins/txouts per block).
local function fat_block_for_header(header, n_outs)
  n_outs = n_outs or 800
  local outs = {}
  local spk = string.rep("\x00", 25)
  for i = 1, n_outs do
    outs[i] = types.txout(1, spk)
  end
  local coinbase = types.transaction(1, {
    types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), "\x01", 0xFFFFFFFF),
  }, outs, 0)
  return types.block(header, { coinbase })
end

local function mock_peer()
  return {
    send_message = function() return true end,
    addr = "127.0.0.1:1",
    address = "127.0.0.1",
    start_height = 100000,
    services = 9,  -- NODE_NETWORK|NODE_WITNESS (block download requires witness)
  }
end

-- Feed blocks at heights [from_h, to_h] so they sit in pending (caller
-- leaves a gap at next_connect_height so connect_pending_blocks stalls).
local function feed_pending(downloader, chain, from_h, to_h, n_outs)
  local peer = mock_peer()
  local sizes = {}
  for h = from_h, to_h do
    local entry = chain:get_header_at_height(h)
    assert(entry, "missing header at " .. h)
    local blk = fat_block_for_header(entry.header, n_outs)
    local block_data = serialize.serialize_block(blk)
    sizes[#sizes + 1] = #block_data
    local hash_hex = chain.height_to_hash[h]
    downloader.inflight[hash_hex] = { peer = peer, request_time = 0, timeout = 60 }
    downloader.peer_inflight[peer] = (downloader.peer_inflight[peer] or 0) + 1
    local ok, err = downloader:handle_block(peer, block_data)
    expect_true(ok ~= false, "handle_block failed at " .. h .. ": " .. tostring(err))
  end
  return sizes
end

local function lua_kb()
  collectgarbage("collect")
  collectgarbage("collect")
  return collectgarbage("count")
end

--------------------------------------------------------------------------------
io.write("test_catchup_memory.lua\n")

test("new_block_downloader exposes a dbcache-derived pending byte cap", function()
  local storage = create_storage()
  local chain = sync.new_header_chain(NET, storage)
  chain:init()
  local dl = sync.new_block_downloader(chain, storage, NET, { dbcache = 4 })
  expect_true(type(dl.pending_bytes_cap) == "number", "pending_bytes_cap missing")
  expect_eq(dl.pending_bytes_cap, 4 * 1024 * 1024, "cap should be dbcache in bytes")
  expect_eq(dl.pending_bytes or 0, 0, "pending_bytes starts at 0")
  expect_true(type(dl.get_pending_bytes) == "function", "get_pending_bytes missing")
  expect_eq(dl:get_pending_bytes(), 0)
end)

test("handle_block does not retain a decoded Lua block in pending", function()
  local storage = create_storage()
  local chain = sync.new_header_chain(NET, storage)
  chain:init()
  accept_headers(chain, 3)
  local dl = sync.new_block_downloader(chain, storage, NET, { dbcache = 32 })
  dl.next_connect_height = 1
  -- Leave height 1 missing so 2 and 3 stay pending.
  feed_pending(dl, chain, 2, 3, 200)
  expect_eq(dl:get_pending_count(), 2, "both far-ahead blocks should be pending")
  for h = 2, 3 do
    local hex = chain.height_to_hash[h]
    local p = dl.pending_blocks[hex]
    expect_true(p ~= nil, "pending missing at height " .. h)
    expect_true(p.block == nil,
      "pending.block must be dropped after receipt (decoded Lua object retained at h="
        .. h .. ")")
    expect_true(type(p.block_data) == "string" and #p.block_data > 80,
      "pending must keep serialized block_data, not the decoded table")
  end
end)

test("pending serialized bytes never exceed the dbcache cap (200-block backlog)", function()
  local storage = create_storage()
  local chain = sync.new_header_chain(NET, storage)
  chain:init()
  local n = 40
  accept_headers(chain, n)
  -- ~40 fat blocks, cap small enough that they cannot all fit.
  local cap = 256 * 1024
  local dl = sync.new_block_downloader(chain, storage, NET, {
    dbcache = 1,
    pending_bytes_cap = cap,
  })
  dl.next_connect_height = 1
  dl.download_window = 1024
  feed_pending(dl, chain, 2, n, 800)
  local bytes = dl:get_pending_bytes()
  expect_true(bytes > 0, "pending_bytes should track serialized payload")
  expect_le(bytes, cap, "pending_bytes " .. bytes .. " exceeded cap " .. cap)
  expect_true(dl:get_pending_count() < (n - 1),
    "byte cap must evict; held " .. dl:get_pending_count() .. " of " .. (n - 1))
end)

test("a 40-block backlog and a 10-block backlog share the same pending cap", function()
  local function run(n, cap)
    local storage = create_storage()
    local chain = sync.new_header_chain(NET, storage)
    chain:init()
    accept_headers(chain, n)
    local dl = sync.new_block_downloader(chain, storage, NET, {
      dbcache = 1,
      pending_bytes_cap = cap,
    })
    dl.next_connect_height = 1
    feed_pending(dl, chain, 2, n, 800)
    return dl:get_pending_bytes(), dl:get_pending_count()
  end
  local cap = 200 * 1024
  local b_big, n_big = run(40, cap)
  local b_small, n_small = run(12, cap)
  expect_le(b_big, cap, "40-block backlog bytes")
  expect_le(b_small, cap, "12-block backlog bytes")
  -- The 40-block run must not be allowed to hold a working set proportional
  -- to the extra 28 blocks. Both sit at (or under) the same cap.
  expect_true(n_big <= n_small + 2,
    "40-block backlog held " .. n_big .. " pending vs " .. n_small
      .. " for the 12-block run — working set scaled with the gap")
end)

test("Lua heap after a fat backlog stays on the order of the cap, not the gap", function()
  local cap = 256 * 1024
  local function heap_after(n)
    collectgarbage("collect")
    local storage = create_storage()
    local chain = sync.new_header_chain(NET, storage)
    chain:init()
    accept_headers(chain, n)
    local dl = sync.new_block_downloader(chain, storage, NET, {
      dbcache = 1,
      pending_bytes_cap = cap,
    })
    dl.next_connect_height = 1
    feed_pending(dl, chain, 2, n, 800)
    local kb = lua_kb()
    -- Keep a live ref so the downloader is not collected before the read.
    return kb, dl:get_pending_bytes(), dl
  end
  local kb10, bytes10, hold10 = heap_after(12)
  local kb40, bytes40, hold40 = heap_after(40)
  expect_le(bytes10, cap)
  expect_le(bytes40, cap)
  -- Decoded 800-output blocks are far larger than their wire size. If the
  -- downloader retained them, 40 pending would dwarf 12. After the bound
  -- both heaps are dominated by the same serialized cap.
  local ratio = kb40 / math.max(kb10, 1)
  expect_lt(ratio, 2.5,
    "Lua heap scaled with backlog: 12-block " .. string.format("%.0f", kb10)
      .. " KB vs 40-block " .. string.format("%.0f", kb40)
      .. " KB (ratio " .. string.format("%.2f", ratio) .. ")")
  hold10, hold40 = hold10, hold40  -- silence unused
end)

test("connect_pending_blocks materializes from block_data (no pending.block)", function()
  local storage = create_storage()
  local chain = sync.new_header_chain(NET, storage)
  chain:init()
  accept_headers(chain, 2)
  local dl = sync.new_block_downloader(chain, storage, NET, { dbcache = 32 })
  dl.next_connect_height = 2
  local entry = chain:get_header_at_height(2)
  local blk = fat_block_for_header(entry.header, 50)
  local block_data = serialize.serialize_block(blk)
  local hex = chain.height_to_hash[2]
  local hash = validation.compute_block_hash(entry.header)
  dl.pending_blocks[hex] = {
    height = 2,
    hash = hash,
    block_data = block_data,
  }
  dl.pending_bytes = #block_data
  -- No connect_callback: the no-callback branch persists the body. The
  -- important part is it must not throw on pending.block == nil.
  local ok, err = dl:connect_pending_blocks()
  expect_true(ok ~= false, "connect_pending_blocks threw/failed: " .. tostring(err))
end)

test("schedule_downloads stops prefetching once pending_bytes is at the cap", function()
  local storage = create_storage()
  local chain = sync.new_header_chain(NET, storage)
  chain:init()
  accept_headers(chain, 20)
  local dl = sync.new_block_downloader(chain, storage, NET, {
    dbcache = 1,
    pending_bytes_cap = 64 * 1024,
  })
  dl.next_connect_height = 1
  dl.next_download_height = 1
  -- Saturate the byte cap with fake pending (no decoded objects).
  local dummy = string.rep("x", 70 * 1024)
  local hex2 = chain.height_to_hash[2]
  dl.pending_blocks[hex2] = {
    height = 2,
    hash = validation.compute_block_hash(chain:get_header_at_height(2).header),
    block_data = dummy,
  }
  dl.pending_bytes = #dummy
  local peer = mock_peer()
  peer.messages_sent = {}
  function peer:send_message(cmd, payload)
    self.messages_sent[#self.messages_sent + 1] = { command = cmd, payload = payload }
    return true
  end
  dl:schedule_downloads({ peer })
  -- Cursor-priority W46 may still request height 1. Prefetch of heights
  -- well ahead of the cursor must not.
  local n_getdata = 0
  for _, m in ipairs(peer.messages_sent) do
    if m.command == "getdata" then n_getdata = n_getdata + 1 end
  end
  local inflight = dl:get_inflight_count()
  expect_true(inflight <= 1,
    "prefetch continued at the byte cap: inflight=" .. inflight
      .. " getdata_msgs=" .. n_getdata)
end)

test("connect reuses stored block_data rather than re-serializing", function()
  -- Structural pin: the connect path must prefer pending.block_data so a
  -- 2 MB mainnet body is not serialized a second time inside the 10 s+
  -- connect_callback window.
  local src = io.open("src/sync.lua", "r")
  assert(src, "src/sync.lua")
  local body = src:read("*a")
  src:close()
  expect_true(body:find("pending%.block_data", 1, false) ~= nil,
    "connect/handle path never mentions pending.block_data")
  expect_true(body:find("pending_block_bytes = pending.block_data", 1, true) ~= nil
      or body:find("pending_block_bytes = pending%.block_data", 1, false) ~= nil,
    "connect must use pending.block_data for the atomic body write")
end)

io.write(string.format("\n%d PASS / %d FAIL\n", PASS, FAIL))
os.exit(FAIL == 0 and 0 or 1)
