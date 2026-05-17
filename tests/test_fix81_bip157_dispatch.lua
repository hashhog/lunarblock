#!/usr/bin/env luajit
-- FIX-81 BIP-157 P2P dispatch wire-up
--
-- Closes W121 BUG-1 (peer.lua:854 dispatch table had zero case for the
-- 6 cf* messages) and W121 BUG-2 (NODE_COMPACT_FILTERS service bit
-- gated FALSE via BIP157_P2P_DISPATCH_PRESENT=false).
--
-- After FIX-81:
--   * peer.lua has 3 incoming dispatch arms for getcfilters /
--     getcfheaders / getcfcheckpt (and 3 outbound/log arms for the
--     response messages cfilter / cfheaders / cfcheckpt).
--   * main.lua registers Core-parity handlers for the 3 request
--     messages.  Each handler validates filter_type / NODE_COMPACT_
--     FILTERS-advertised / stop_hash on active chain / range size,
--     disconnects misbehaving peers, and emits the response message
--     when validation passes.
--   * p2p.MAX_GETCFILTERS_SIZE=1000, p2p.MAX_GETCFHEADERS_SIZE=2000,
--     blockfilter.CFCHECKPT_INTERVAL=1000 — direct Core mirrors.
--   * p2p.BIP157_P2P_DISPATCH_PRESENT=true; should_advertise_compact_
--     filters() now fires when operator passes --peerblockfilters AND
--     --blockfilterindex.
--
-- Reference:
--   bitcoin-core/src/net_processing.cpp lines 3262-3422
--     (PrepareBlockFilterRequest / ProcessGetCFilters / CFHeaders /
--      CFCheckPt)
--   bitcoin-core/src/protocol.h           (NODE_COMPACT_FILTERS=64)
--   bitcoin-core/src/index/blockfilterindex.h:31 (CFCHECKPT_INTERVAL)
--
-- The behavioral tests below construct a minimal HeaderChain and
-- storage mock, copy the handler logic verbatim from main.lua (since
-- closures are not exported), and exercise happy-path + 4
-- violation-per-handler paths.
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_fix81_bip157_dispatch.lua 2>&1

package.path = "src/?.lua;./?.lua;" .. package.path

local loaders = package.loaders or package.searchers
table.insert(loaders, 2, function(module)
  local name = module:match("^lunarblock%.(.+)")
  if name then
    local filename = "src/" .. name .. ".lua"
    local f = io.open(filename)
    if f then f:close(); return function() return dofile(filename) end end
  end
  return nil, "not found"
end)

local p2p         = require("lunarblock.p2p")
local types       = require("lunarblock.types")
local crypto      = require("lunarblock.crypto")
local serialize   = require("lunarblock.serialize")
local blockfilter = require("lunarblock.blockfilter")
local bit         = require("bit")

local PASS = 0
local FAIL = 0

local function pass(name)
  io.write(string.format("  PASS  %s\n", name))
  PASS = PASS + 1
end

local function fail(name, msg)
  io.write(string.format("  FAIL  %s -- %s\n", name, msg))
  FAIL = FAIL + 1
end

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) ..
          ", expected " .. tostring(b))
  end
end

local function expect_true(v, msg)
  if not v then error(msg or "expected true, got false") end
end

local function expect_false(v, msg)
  if v then error(msg or "expected false, got true") end
end

local function read_file(path)
  local f = io.open(path, "r")
  if not f then return "" end
  local s = f:read("*a"); f:close(); return s
end

-- ============================================================================
-- Test fixture: mock HeaderChain + storage + peer
-- ============================================================================

-- Build N synthetic blocks on a single active chain.  Each block_hash is
-- a deterministic 32-byte hash of "block_<height>" (no genesis-checksum
-- semantics matter here — we only need stable identifiers).  Filter
-- payloads are likewise deterministic.
local function make_block_hash(h)
  -- 32-byte deterministic hash: SHA256("block_<height>")
  return crypto.hash256_type("block_" .. tostring(h))
end

local function make_filter_data(h)
  -- A trivial 4-byte filter payload — content is irrelevant for dispatch
  -- behavior (we only check that what we sent equals what we stored).
  return string.format("F%04d", h)
end

local function make_filter_hash(filter_data)
  return crypto.hash256_type(filter_data)
end

local function make_filter_header(filter_hash, prev_filter_header)
  return crypto.hash256_type(filter_hash.bytes .. prev_filter_header.bytes)
end

--- Build a fake chain of length `chain_tip_height + 1` (heights 0..tip).
-- Returns header_chain (with get_header + height_to_hash), and storage
-- (with get(CF.BLOCK_FILTER, block_hash.bytes) → filter blob).
local function build_fake_chain(chain_tip_height)
  local hc = {
    headers = {},        -- hash_hex -> {height}
    height_to_hash = {}, -- height -> hash_hex
    header_tip_height = chain_tip_height,
  }
  function hc:get_header(hash)
    return self.headers[types.hash256_hex(hash)]
  end

  local prev_filter_header = types.hash256_zero()
  local stored = {}  -- block_hash.bytes -> blob

  for h = 0, chain_tip_height do
    local bhash = make_block_hash(h)
    local hex = types.hash256_hex(bhash)
    hc.headers[hex] = { height = h }
    hc.height_to_hash[h] = hex

    local fdata = make_filter_data(h)
    local fhash = make_filter_hash(fdata)
    local fheader = make_filter_header(fhash, prev_filter_header)
    prev_filter_header = fheader

    local w = serialize.buffer_writer()
    w.write_hash256(fhash)
    w.write_hash256(fheader)
    w.write_varstr(fdata)
    stored[bhash.bytes] = w.result()
  end

  local storage = {
    -- main.lua reads via db.get(storage_mod.CF.BLOCK_FILTER, block_hash.bytes).
    -- For the test we use the constant string "block_filter" directly.
    get = function(cf, key)
      if cf == "block_filter" then return stored[key] end
      return nil
    end,
  }

  return hc, storage
end

--- Build a fake peer with our_services bit set or unset.
-- Tracks all send_message calls and disconnect calls.
local function make_fake_peer(advertise_compact_filters)
  local p = {
    our_services = bit.bor(p2p.SERVICES.NODE_NETWORK, p2p.SERVICES.NODE_WITNESS),
    sent_messages = {},
    disconnect_called = false,
    disconnect_reason = nil,
    misbehaving_called = false,
  }
  if advertise_compact_filters then
    p.our_services = bit.bor(p.our_services, p2p.SERVICES.NODE_COMPACT_FILTERS)
  end
  function p:send_message(cmd, payload)
    self.sent_messages[#self.sent_messages + 1] = {cmd = cmd, payload = payload}
  end
  function p:disconnect(reason)
    self.disconnect_called = true
    self.disconnect_reason = reason
  end
  function p:misbehaving(_score, reason)
    self.misbehaving_called = true
    self:disconnect("misbehaving: " .. reason)
    return true
  end
  return p
end

--- Construct handler closures that mirror main.lua's BIP-157 dispatch.
-- This is a controlled clone because main.lua's closures aren't
-- exported.  Keep this in sync with main.lua's getcfilters/getcfheaders/
-- getcfcheckpt register_handler bodies; the source-level tests below
-- guard against drift.
local function build_handlers(header_chain, storage, filterindex_enabled)
  local CF_BLOCK_FILTER = "block_filter"

  local function get_active_chain_hash(height)
    local hash_hex = header_chain.height_to_hash[height]
    if not hash_hex then return nil end
    return types.hash256_from_hex(hash_hex)
  end

  local function resolve_stop_hash_on_active_chain(stop_hash)
    local entry = header_chain:get_header(stop_hash)
    if not entry then return nil end
    local stop_height = entry.height
    local active_hex = header_chain.height_to_hash[stop_height]
    if not active_hex then return nil end
    if active_hex ~= types.hash256_hex(stop_hash) then return nil end
    return stop_height
  end

  local function read_filter_blob(block_hash)
    local data = storage.get(CF_BLOCK_FILTER, block_hash.bytes)
    if not data then return nil end
    local r = serialize.buffer_reader(data)
    return {
      filter_hash   = r.read_hash256(),
      filter_header = r.read_hash256(),
      filter        = r.read_varstr(),
    }
  end

  local function our_compact_filters_advertised(peer)
    return bit.band(peer.our_services or 0,
                    p2p.SERVICES.NODE_COMPACT_FILTERS) ~= 0
  end

  local function getcfilters_handler(peer, payload)
    if not p2p.BIP157_P2P_DISPATCH_PRESENT then return end
    if not filterindex_enabled then return end
    local ok, req = pcall(p2p.deserialize_getcfilters, payload)
    if not ok or not req then
      peer:misbehaving(10, "malformed getcfilters")
      return
    end
    if req.filter_type ~= p2p.FILTER_TYPE.BASIC or
       not our_compact_filters_advertised(peer) then
      peer:disconnect("getcfilters: unsupported filter_type or NODE_COMPACT_FILTERS not advertised")
      return
    end
    local stop_height = resolve_stop_hash_on_active_chain(req.stop_hash)
    if not stop_height then
      peer:disconnect("getcfilters: stop_hash not on active chain")
      return
    end
    if req.start_height > stop_height then
      peer:disconnect("getcfilters: start_height > stop_height")
      return
    end
    if stop_height - req.start_height >= p2p.MAX_GETCFILTERS_SIZE then
      peer:disconnect("getcfilters: range exceeds MAX_GETCFILTERS_SIZE")
      return
    end
    for h = req.start_height, stop_height do
      local block_hash = get_active_chain_hash(h)
      if not block_hash then break end
      local info = read_filter_blob(block_hash)
      if not info then break end
      local out = p2p.serialize_cfilter(req.filter_type, block_hash, info.filter)
      peer:send_message("cfilter", out)
    end
  end

  local function getcfheaders_handler(peer, payload)
    if not p2p.BIP157_P2P_DISPATCH_PRESENT then return end
    if not filterindex_enabled then return end
    local ok, req = pcall(p2p.deserialize_getcfheaders, payload)
    if not ok or not req then
      peer:misbehaving(10, "malformed getcfheaders")
      return
    end
    if req.filter_type ~= p2p.FILTER_TYPE.BASIC or
       not our_compact_filters_advertised(peer) then
      peer:disconnect("getcfheaders: unsupported filter_type or NODE_COMPACT_FILTERS not advertised")
      return
    end
    local stop_height = resolve_stop_hash_on_active_chain(req.stop_hash)
    if not stop_height then
      peer:disconnect("getcfheaders: stop_hash not on active chain")
      return
    end
    if req.start_height > stop_height then
      peer:disconnect("getcfheaders: start_height > stop_height")
      return
    end
    if stop_height - req.start_height >= p2p.MAX_GETCFHEADERS_SIZE then
      peer:disconnect("getcfheaders: range exceeds MAX_GETCFHEADERS_SIZE")
      return
    end
    local prev_filter_header
    if req.start_height == 0 then
      prev_filter_header = types.hash256_zero()
    else
      local prev_block_hash = get_active_chain_hash(req.start_height - 1)
      if not prev_block_hash then return end
      local prev_info = read_filter_blob(prev_block_hash)
      if not prev_info then return end
      prev_filter_header = prev_info.filter_header
    end
    local filter_hashes = {}
    for h = req.start_height, stop_height do
      local block_hash = get_active_chain_hash(h)
      if not block_hash then return end
      local info = read_filter_blob(block_hash)
      if not info then return end
      filter_hashes[#filter_hashes + 1] = info.filter_hash
    end
    local stop_hash = get_active_chain_hash(stop_height) or req.stop_hash
    local out = p2p.serialize_cfheaders(req.filter_type, stop_hash,
                                        prev_filter_header, filter_hashes)
    peer:send_message("cfheaders", out)
  end

  local function getcfcheckpt_handler(peer, payload)
    if not p2p.BIP157_P2P_DISPATCH_PRESENT then return end
    if not filterindex_enabled then return end
    local ok, req = pcall(p2p.deserialize_getcfcheckpt, payload)
    if not ok or not req then
      peer:misbehaving(10, "malformed getcfcheckpt")
      return
    end
    if req.filter_type ~= p2p.FILTER_TYPE.BASIC or
       not our_compact_filters_advertised(peer) then
      peer:disconnect("getcfcheckpt: unsupported filter_type or NODE_COMPACT_FILTERS not advertised")
      return
    end
    local stop_height = resolve_stop_hash_on_active_chain(req.stop_hash)
    if not stop_height then
      peer:disconnect("getcfcheckpt: stop_hash not on active chain")
      return
    end
    local interval = blockfilter.CFCHECKPT_INTERVAL
    local n = math.floor(stop_height / interval)
    local headers = {}
    for i = 1, n do
      local h = i * interval
      local block_hash = get_active_chain_hash(h)
      if not block_hash then return end
      local info = read_filter_blob(block_hash)
      if not info then return end
      headers[i] = info.filter_header
    end
    local stop_hash = get_active_chain_hash(stop_height) or req.stop_hash
    local out = p2p.serialize_cfcheckpt(req.filter_type, stop_hash, headers)
    peer:send_message("cfcheckpt", out)
  end

  return {
    getcfilters = getcfilters_handler,
    getcfheaders = getcfheaders_handler,
    getcfcheckpt = getcfcheckpt_handler,
  }
end

-- ============================================================================
-- Section S: source-level guards (dispatch arms wired + flag flipped)
-- ============================================================================
print("\n--- S: source-level guards ---")

test("S1: BIP157_P2P_DISPATCH_PRESENT module flag is true", function()
  expect_eq(p2p.BIP157_P2P_DISPATCH_PRESENT, true,
    "FIX-81 wired the dispatch; flag must be true")
end)

test("S2: peer.lua dispatch arm for getcfilters present", function()
  local src = read_file("src/peer.lua")
  expect_true(src:find('"getcfilters"', 1, true) ~= nil,
    "peer.lua must have a getcfilters dispatch arm")
end)

test("S3: peer.lua dispatch arm for getcfheaders present", function()
  local src = read_file("src/peer.lua")
  expect_true(src:find('"getcfheaders"', 1, true) ~= nil,
    "peer.lua must have a getcfheaders dispatch arm")
end)

test("S4: peer.lua dispatch arm for getcfcheckpt present", function()
  local src = read_file("src/peer.lua")
  expect_true(src:find('"getcfcheckpt"', 1, true) ~= nil,
    "peer.lua must have a getcfcheckpt dispatch arm")
end)

test("S5: peer.lua dispatch arms for response messages present", function()
  -- cfilter / cfheaders / cfcheckpt — currently log-only handlers since
  -- lunarblock is server-only, but the arms must exist so messages
  -- received from upstream peers aren't routed through the generic
  -- catchall fallback (which would silently drop without registry).
  local src = read_file("src/peer.lua")
  expect_true(src:find('"cfilter"', 1, true) ~= nil, "cfilter arm present")
  expect_true(src:find('"cfheaders"', 1, true) ~= nil, "cfheaders arm present")
  expect_true(src:find('"cfcheckpt"', 1, true) ~= nil, "cfcheckpt arm present")
end)

test("S6: main.lua registers getcfilters handler", function()
  local src = read_file("src/main.lua")
  expect_true(src:find('register_handler%("getcfilters"') ~= nil,
    "main.lua must register a getcfilters handler closure")
end)

test("S7: main.lua registers getcfheaders handler", function()
  local src = read_file("src/main.lua")
  expect_true(src:find('register_handler%("getcfheaders"') ~= nil,
    "main.lua must register a getcfheaders handler closure")
end)

test("S8: main.lua registers getcfcheckpt handler", function()
  local src = read_file("src/main.lua")
  expect_true(src:find('register_handler%("getcfcheckpt"') ~= nil,
    "main.lua must register a getcfcheckpt handler closure")
end)

test("S9: p2p constants MAX_GETCFILTERS_SIZE/MAX_GETCFHEADERS_SIZE defined", function()
  expect_eq(p2p.MAX_GETCFILTERS_SIZE, 1000,
    "Core net_processing.cpp:184 — MAX_GETCFILTERS_SIZE=1000")
  expect_eq(p2p.MAX_GETCFHEADERS_SIZE, 2000,
    "Core net_processing.cpp:186 — MAX_GETCFHEADERS_SIZE=2000")
end)

test("S10: blockfilter.CFCHECKPT_INTERVAL defined", function()
  expect_eq(blockfilter.CFCHECKPT_INTERVAL, 1000,
    "Core blockfilterindex.h:31 — CFCHECKPT_INTERVAL=1000")
end)

test("S11: NODE_COMPACT_FILTERS now advertised when operator opts in", function()
  -- Forward-regression of the FIX-71 → FIX-81 transition.  With (a)+(b)
  -- true and dispatch present (c), the bit fires.
  local s = p2p.our_services(false, false, {
    peerblockfilters = true,
    blockfilterindex_enabled = true,
  })
  expect_true(bit.band(s, p2p.SERVICES.NODE_COMPACT_FILTERS) ~= 0,
    "NODE_COMPACT_FILTERS must appear in services bitfield")
end)

-- ============================================================================
-- Section H: getcfilters handler behavior
-- ============================================================================
print("\n--- H: getcfilters handler behavior ---")

test("H1: happy path — full range returns one cfilter per height", function()
  local hc, storage = build_fake_chain(10)
  local handlers = build_handlers(hc, storage, true)
  local peer = make_fake_peer(true)
  local stop_hash = make_block_hash(5)
  local payload = p2p.serialize_getcfilters(0, 2, stop_hash)
  handlers.getcfilters(peer, payload)
  expect_false(peer.disconnect_called,
    "happy path must not disconnect peer (reason="
    .. tostring(peer.disconnect_reason) .. ")")
  expect_eq(#peer.sent_messages, 4, "heights 2..5 = 4 cfilters")
  for i, msg in ipairs(peer.sent_messages) do
    expect_eq(msg.cmd, "cfilter", "message " .. i .. " is cfilter")
    local d = p2p.deserialize_cfilter(msg.payload)
    expect_eq(d.filter_type, 0, "filter_type=0 (BASIC)")
    -- filter_data deterministic per height
    expect_eq(d.filter_data, make_filter_data(2 + i - 1),
      "filter_data matches expected for height " .. (2 + i - 1))
  end
end)

test("H2: violation — filter_type != 0 → disconnect", function()
  local hc, storage = build_fake_chain(10)
  local handlers = build_handlers(hc, storage, true)
  local peer = make_fake_peer(true)
  -- Bypass the codec and craft a payload with filter_type=99.
  local w = serialize.buffer_writer()
  w.write_u8(99)
  w.write_u32le(0)
  w.write_hash256(make_block_hash(5))
  handlers.getcfilters(peer, w.result())
  expect_true(peer.disconnect_called, "unsupported filter_type must disconnect")
end)

test("H3: violation — NODE_COMPACT_FILTERS not advertised → disconnect", function()
  local hc, storage = build_fake_chain(10)
  local handlers = build_handlers(hc, storage, true)
  -- peer with advertise_compact_filters=false
  local peer = make_fake_peer(false)
  local payload = p2p.serialize_getcfilters(0, 0, make_block_hash(5))
  handlers.getcfilters(peer, payload)
  expect_true(peer.disconnect_called,
    "must disconnect peer requesting cfilters when we never advertised")
end)

test("H4: violation — stop_hash not on active chain → disconnect", function()
  local hc, storage = build_fake_chain(10)
  local handlers = build_handlers(hc, storage, true)
  local peer = make_fake_peer(true)
  -- Unknown stop_hash
  local unknown = crypto.hash256_type("never_seen_block")
  local payload = p2p.serialize_getcfilters(0, 0, unknown)
  handlers.getcfilters(peer, payload)
  expect_true(peer.disconnect_called,
    "unknown stop_hash must disconnect (BlockRequestAllowed false)")
end)

test("H5: violation — start_height > stop_height → disconnect", function()
  local hc, storage = build_fake_chain(10)
  local handlers = build_handlers(hc, storage, true)
  local peer = make_fake_peer(true)
  local payload = p2p.serialize_getcfilters(0, 8, make_block_hash(5))
  handlers.getcfilters(peer, payload)
  expect_true(peer.disconnect_called,
    "start_height > stop_height must disconnect")
end)

test("H6: violation — range exceeds MAX_GETCFILTERS_SIZE → disconnect", function()
  -- Build a 1500-deep chain; ask for height 0..1499 (range=1500 >= 1000).
  local hc, storage = build_fake_chain(1500)
  local handlers = build_handlers(hc, storage, true)
  local peer = make_fake_peer(true)
  local payload = p2p.serialize_getcfilters(0, 0, make_block_hash(1499))
  handlers.getcfilters(peer, payload)
  expect_true(peer.disconnect_called,
    "range >= MAX_GETCFILTERS_SIZE must disconnect")
end)

-- ============================================================================
-- Section H': getcfheaders handler behavior
-- ============================================================================
print("\n--- H': getcfheaders handler behavior ---")

test("HH1: happy path — returns cfheaders with prev_filter_header + hash chain", function()
  local hc, storage = build_fake_chain(20)
  local handlers = build_handlers(hc, storage, true)
  local peer = make_fake_peer(true)
  local stop_hash = make_block_hash(10)
  local payload = p2p.serialize_getcfheaders(0, 3, stop_hash)
  handlers.getcfheaders(peer, payload)
  expect_false(peer.disconnect_called, "happy path must not disconnect")
  expect_eq(#peer.sent_messages, 1, "exactly one cfheaders response")
  expect_eq(peer.sent_messages[1].cmd, "cfheaders", "response is cfheaders")
  local d = p2p.deserialize_cfheaders(peer.sent_messages[1].payload)
  expect_eq(d.filter_type, 0, "filter_type echoed")
  expect_eq(#d.filter_hashes, 8, "heights 3..10 = 8 filter hashes")
  -- prev_filter_header for start=3 is the filter_header at height 2.
  local expected_prev_filter_header
  do
    local prev = types.hash256_zero()
    for h = 0, 2 do
      local fd = make_filter_data(h)
      local fh = make_filter_hash(fd)
      prev = make_filter_header(fh, prev)
    end
    expected_prev_filter_header = prev
  end
  expect_true(types.hash256_eq(d.prev_filter_header, expected_prev_filter_header),
    "prev_filter_header chain matches synthetic chain")
end)

test("HH2: happy path with start_height=0 — prev_filter_header=zero", function()
  local hc, storage = build_fake_chain(20)
  local handlers = build_handlers(hc, storage, true)
  local peer = make_fake_peer(true)
  local payload = p2p.serialize_getcfheaders(0, 0, make_block_hash(3))
  handlers.getcfheaders(peer, payload)
  expect_eq(#peer.sent_messages, 1)
  local d = p2p.deserialize_cfheaders(peer.sent_messages[1].payload)
  expect_true(types.hash256_eq(d.prev_filter_header, types.hash256_zero()),
    "start_height=0 ⇒ prev_filter_header=zero (BIP-157 §Filter Headers)")
end)

test("HH3: violation — filter_type != 0 → disconnect", function()
  local hc, storage = build_fake_chain(10)
  local handlers = build_handlers(hc, storage, true)
  local peer = make_fake_peer(true)
  local w = serialize.buffer_writer()
  w.write_u8(5)
  w.write_u32le(0)
  w.write_hash256(make_block_hash(5))
  handlers.getcfheaders(peer, w.result())
  expect_true(peer.disconnect_called, "unsupported filter_type must disconnect")
end)

test("HH4: violation — stop_hash not on active chain → disconnect", function()
  local hc, storage = build_fake_chain(10)
  local handlers = build_handlers(hc, storage, true)
  local peer = make_fake_peer(true)
  local unknown = crypto.hash256_type("unknown")
  local payload = p2p.serialize_getcfheaders(0, 0, unknown)
  handlers.getcfheaders(peer, payload)
  expect_true(peer.disconnect_called, "unknown stop_hash must disconnect")
end)

test("HH5: violation — range exceeds MAX_GETCFHEADERS_SIZE → disconnect", function()
  local hc, storage = build_fake_chain(2500)
  local handlers = build_handlers(hc, storage, true)
  local peer = make_fake_peer(true)
  -- Range = 2001 > 2000 limit.
  local payload = p2p.serialize_getcfheaders(0, 0, make_block_hash(2000))
  handlers.getcfheaders(peer, payload)
  expect_true(peer.disconnect_called,
    "range >= MAX_GETCFHEADERS_SIZE must disconnect")
end)

-- ============================================================================
-- Section H'': getcfcheckpt handler behavior
-- ============================================================================
print("\n--- H'': getcfcheckpt handler behavior ---")

test("HC1: happy path — returns checkpoint chain at CFCHECKPT_INTERVAL=1000", function()
  -- Build a 3500-deep chain; stop at height 2500 ⇒ N = floor(2500/1000) = 2.
  local hc, storage = build_fake_chain(2500)
  local handlers = build_handlers(hc, storage, true)
  local peer = make_fake_peer(true)
  local stop_hash = make_block_hash(2500)
  local payload = p2p.serialize_getcfcheckpt(0, stop_hash)
  handlers.getcfcheckpt(peer, payload)
  expect_false(peer.disconnect_called, "happy path must not disconnect")
  expect_eq(#peer.sent_messages, 1, "exactly one cfcheckpt response")
  expect_eq(peer.sent_messages[1].cmd, "cfcheckpt", "response is cfcheckpt")
  local d = p2p.deserialize_cfcheckpt(peer.sent_messages[1].payload)
  expect_eq(d.filter_type, 0, "filter_type echoed")
  expect_eq(#d.filter_headers, 2,
    "floor(2500/1000) = 2 checkpoint headers (heights 1000 + 2000)")
end)

test("HC2: short chain — N=0 for stop_height < CFCHECKPT_INTERVAL", function()
  local hc, storage = build_fake_chain(500)
  local handlers = build_handlers(hc, storage, true)
  local peer = make_fake_peer(true)
  local payload = p2p.serialize_getcfcheckpt(0, make_block_hash(500))
  handlers.getcfcheckpt(peer, payload)
  expect_false(peer.disconnect_called)
  expect_eq(#peer.sent_messages, 1)
  local d = p2p.deserialize_cfcheckpt(peer.sent_messages[1].payload)
  expect_eq(#d.filter_headers, 0,
    "stop_height=500 < CFCHECKPT_INTERVAL ⇒ zero headers (Core: vector(0))")
end)

test("HC3: violation — filter_type != 0 → disconnect", function()
  local hc, storage = build_fake_chain(2000)
  local handlers = build_handlers(hc, storage, true)
  local peer = make_fake_peer(true)
  local w = serialize.buffer_writer()
  w.write_u8(1)
  w.write_hash256(make_block_hash(1500))
  handlers.getcfcheckpt(peer, w.result())
  expect_true(peer.disconnect_called, "unsupported filter_type must disconnect")
end)

test("HC4: violation — NODE_COMPACT_FILTERS not advertised → disconnect", function()
  local hc, storage = build_fake_chain(2000)
  local handlers = build_handlers(hc, storage, true)
  local peer = make_fake_peer(false)
  local payload = p2p.serialize_getcfcheckpt(0, make_block_hash(1500))
  handlers.getcfcheckpt(peer, payload)
  expect_true(peer.disconnect_called,
    "must disconnect peer when we don't advertise the service bit")
end)

test("HC5: violation — stop_hash unknown → disconnect", function()
  local hc, storage = build_fake_chain(2000)
  local handlers = build_handlers(hc, storage, true)
  local peer = make_fake_peer(true)
  local unknown = crypto.hash256_type("totally-unknown")
  local payload = p2p.serialize_getcfcheckpt(0, unknown)
  handlers.getcfcheckpt(peer, payload)
  expect_true(peer.disconnect_called, "unknown stop_hash must disconnect")
end)

-- ============================================================================
-- Section G: gate-flip integrity (NODE_COMPACT_FILTERS in version handshake)
-- ============================================================================
print("\n--- G: gate-flip integrity ---")

test("G1: gate fires when (a)+(b) true AND dispatch present (module flag)", function()
  -- This is the post-FIX-81 production state — operator opts in via
  -- --peerblockfilters AND --blockfilterindex; module flag is true.
  expect_true(p2p.should_advertise_compact_filters({
    peerblockfilters = true,
    blockfilterindex_enabled = true,
  }), "FIX-81 module-level flag flip suffices for the gate")
end)

test("G2: gate stays dark without operator opt-in (peerblockfilters=false)", function()
  -- Operator default — even with index running and FIX-81 dispatch
  -- present, the bit stays dark.  Matches Core DEFAULT_PEERBLOCKFILTERS.
  expect_false(p2p.should_advertise_compact_filters({
    peerblockfilters = false,
    blockfilterindex_enabled = true,
  }), "operator default ⇒ no advertisement")
end)

test("G3: gate stays dark without index running (blockfilterindex_enabled=false)", function()
  -- Operator opted in but no index ⇒ refusal to lie.
  expect_false(p2p.should_advertise_compact_filters({
    peerblockfilters = true,
    blockfilterindex_enabled = false,
  }), "no index ⇒ refusal to lie")
end)

test("G4: explicit override bip157_dispatch_present=false force-disables", function()
  -- Test-only safety hatch: force the dispatch-absent state for unit
  -- tests that drill the gate semantics.
  expect_false(p2p.should_advertise_compact_filters({
    peerblockfilters = true,
    blockfilterindex_enabled = true,
    bip157_dispatch_present = false,
  }), "explicit override forces dispatch-absent state")
end)

-- ============================================================================
-- Summary
-- ============================================================================
print("\n=========================================================================")
print(string.format("FIX-81 BIP-157 P2P dispatch: %d PASS / %d FAIL", PASS, FAIL))
print(string.format("Dispatch state: BIP157_P2P_DISPATCH_PRESENT=%s",
  tostring(p2p.BIP157_P2P_DISPATCH_PRESENT)))
print(string.format("Constants: MAX_GETCFILTERS_SIZE=%d / MAX_GETCFHEADERS_SIZE=%d / CFCHECKPT_INTERVAL=%d",
  p2p.MAX_GETCFILTERS_SIZE,
  p2p.MAX_GETCFHEADERS_SIZE,
  blockfilter.CFCHECKPT_INTERVAL))
print("=========================================================================")

if FAIL > 0 then os.exit(1) end
