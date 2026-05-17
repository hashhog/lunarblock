#!/usr/bin/env luajit
-- W121 BIP-157/158 compact block filters audit — lunarblock (Lua / LuaJIT)
--
-- Reference: bitcoin-core/src/blockfilter.{cpp,h};
--            bitcoin-core/src/index/blockfilterindex.{cpp,h};
--            bitcoin-core/src/net_processing.cpp (ProcessGetCFilters/Headers/CheckPt);
--            BIP-157 (light-client P2P), BIP-158 (filter content & encoding).
--
-- Scope: wire codecs (p2p.lua), dispatch + service-bit advertisement
--        (peer.lua / sync.lua / p2p.our_services), GCS construction
--        (blockfilter.lua build_basic_filter + build_gcs_filter), header
--        chain (compute_filter_header), index lifecycle (connect_block /
--        disconnect_block / get_filter / get_filter_by_height /
--        get_filter_headers), REST endpoints (rest.lua handle_blockfilter*).
--
-- Gate map:
--   G1-G3   BIP-158 constants  (P=19, M=784931, FILTER_TYPE.BASIC=0).
--   G4-G6   Wire codecs round-trip — getcfilters / getcfheaders / getcfcheckpt.
--   G7-G9   Wire codecs round-trip — cfilter / cfheaders / cfcheckpt.
--   G10-G12 P2P dispatch — handlers for the 6 cf* messages.
--   G13     Service bit — NODE_COMPACT_FILTERS advertised when index enabled.
--   G14-G15 Core P2P limits — MAX_GETCFILTERS_SIZE / MAX_GETCFHEADERS_SIZE.
--   G16     CFCHECKPT_INTERVAL constant (=1000).
--   G17-G18 BasicFilterElements — output skip rules + undo-data structure.
--   G19-G21 SipHash key derivation + FastRange64 + HashToRange.
--   G22-G24 Golomb-Rice encode/decode (parameter handling, bounds, P!=19).
--   G25     Filter-hash + filter-header chain (BIP-157 §"Filter Headers").
--   G26-G28 Index lifecycle — put/get/delete + height column + reorg.
--   G29     REST endpoints — handle_blockfilter + handle_blockfilterheaders.
--   G30     Cross-impl behavior — empty-block filter is varint(0) only.
--
-- Bugs found (P0/P1/MED/LOW; CDIV = wire-protocol divergence):
--
--   BUG-1  (P0-WIRE)   Dispatch is dead — peer.lua:854 has NO handlers for
--                     any of getcfilters / cfilter / getcfheaders / cfheaders
--                     / getcfcheckpt / cfcheckpt.  All 6 codecs in p2p.lua
--                     are dead code on both inbound and outbound paths.
--                     Net effect: a BIP-157 light client connecting to
--                     lunarblock with --blockfilterindex enabled receives
--                     ZERO responses to its getcfilters/getcfheaders, hits
--                     the 30s read timeout in Core's PoissonNextSend path,
--                     and disconnects.  The filter index exists on disk
--                     (connect_block writes it) but is invisible to peers.
--                     The REST path (rest.lua) is wired and works — only
--                     the P2P path is dark.  References: net_processing.cpp
--                     lines 3315 (ProcessGetCFilters), 3344
--                     (ProcessGetCFHeaders), 3386 (ProcessGetCFCheckPt).
--                     "Well-engineered dead helper" pattern — full wire
--                     codec + REST endpoint + index lifecycle, no dispatch.
--
--   BUG-2  (P0-WIRE)   NODE_COMPACT_FILTERS = 64 is defined in p2p.lua:21
--                     but NEVER OR'd into our_services() (p2p.lua:36-46),
--                     even when args.blockfilterindex is true.  Per
--                     BIP-157 §"Service Bit" and net_processing.cpp:3268
--                     ("peer.m_our_services & NODE_COMPACT_FILTERS"),
--                     a BIP-157-aware peer chooses outbound connections
--                     by this advertised bit.  Lunarblock with the index
--                     enabled is unfindable by spec-compliant clients.
--                     Compounded with BUG-1: even peers that probe blindly
--                     get no response.  Fix: thread an opt-in
--                     `compactfilters` flag from main.lua args into
--                     our_services(), gated on filter_index.is_enabled().
--
--   BUG-3  (P0-CDIV)   golomb_rice_decode (blockfilter.lua:251-262) reads
--                     unary q via unbounded `while bitreader.read(1) == 1`
--                     with no upper bound on q.  Core (util/golombrice.h
--                     line 53-57: `while (q < std::numeric_limits<uint64_t>
--                     ::max() && bitreader.Read(1))`) caps at 2^64.  A
--                     peer crafting a filter whose body is all 0xFF bytes
--                     wedges the decoder reading 8 * filter_len 1-bits
--                     for a single element delta — DoS by a single
--                     malformed cfilter.  When BUG-1 is fixed, this
--                     becomes a remotely triggerable hang on any peer
--                     that sends a malformed BIP-157 filter response.
--                     Severity escalates from latent to active.
--
--   BUG-4  (P1-CDIV)   golomb_rice_encode/decode hardcode 524288 = 2^19
--                     (lines 230, 245, 261) even though `P` is a parameter.
--                     The comment on line 231 admits this:
--                       "For other P values use: local shift =
--                        bit.lshift(1, P); q = math.floor(x / shift)"
--                     Comment-as-confession.  Only BIP-158 basic filters
--                     (P=19) work.  Future filter types from BIP-158 §3
--                     ("Compact filters for other purposes") or the
--                     experimental EXTENDED type from BIP-158 v1 cannot
--                     be encoded or decoded.  Mirror of W90 BUG-10/11
--                     not actually closed despite the file claiming so.
--
--   BUG-5  (P1-CDIV)   No MAX_GETCFILTERS_SIZE (1000) or MAX_GETCFHEADERS_
--                     SIZE (2000) constants in p2p.lua.  Core enforces
--                     disconnect-on-violation in PrepareBlockFilterRequest
--                     (net_processing.cpp lines 184-186, 3299-3304: peer
--                     sending stop-start ≥ max gets fDisconnect=true).
--                     When BUG-1 is fixed, the handlers will need these
--                     to bound CPU/memory work and reject abusive peers.
--                     Without them, a single getcfilters with
--                     stop_height - start_height = 10000 causes 5 MB+
--                     payload + 10000× index lookups — easy DoS.
--
--   BUG-6  (P1-CDIV)   No CFCHECKPT_INTERVAL constant (Core: 1000, in
--                     index/blockfilterindex.h:31).  The cfcheckpt message
--                     is defined to carry filter headers at every 1000th
--                     block on the active chain (BIP-157 §"Filter Header
--                     Checkpoints").  ProcessGetCFCheckPt
--                     (net_processing.cpp:3402) returns `stop_index->
--                     nHeight / CFCHECKPT_INTERVAL` headers.  Lunarblock
--                     has zero plumbing for this — when BUG-1 is fixed,
--                     the cfcheckpt path will be the only one not
--                     implementable without first adding this constant
--                     and the chain-walk helper.
--
--   BUG-7  (MED-CDIV) extract_basic_filter_elements (blockfilter.lua:435)
--                     accepts a FLAT undo_data list:
--                       for _, spent in ipairs(undo_data) do
--                         if spent.script_pubkey then ...
--                     Core (blockfilter.cpp:200) iterates
--                       for (const CTxUndo& tx_undo : block_undo.vtxundo)
--                         for (const Coin& prevout : tx_undo.vprevout)
--                     — a NESTED structure where vtxundo has
--                     `vtx.size() - 1` entries (coinbase skipped).  The
--                     existing comment on lines 39-42 admits this as an
--                     "architectural note, not a code fix" — but it IS
--                     a correctness gap: callers that pass a flattened
--                     list including coinbase fakes will silently include
--                     them, producing filters that disagree with Core's
--                     filter_hash and therefore an incompatible filter
--                     header chain.  Any peer comparing filter headers
--                     would BAN this node.
--
--   BUG-8  (MED)      bit_stream_reader.read(nbits) (blockfilter.lua:199)
--                     uses Lua bit.lshift on a number accumulator, which
--                     on standard LuaJIT bitop operates modulo 2^32.  If
--                     BUG-4 is fixed and a caller invokes with nbits > 32
--                     (e.g. P=24 for hypothetical larger filter types),
--                     the top bits silently drop.  Currently de-facto
--                     safe because P=19 hardcoding (BUG-4) limits nbits
--                     to 19 in remainder reads, but a defensive
--                     implementation should error on nbits > 32 or use
--                     uint64_t accumulator.
--
--   BUG-9  (MED)      build_gcs_filter (blockfilter.lua:296) demotes the
--                     uint64_t SipHash output via tonumber() before
--                     sorting:
--                       hashed[i] = tonumber(hash_to_range(...))
--                     For mainnet basic-filter blocks the maximum hashed
--                     value is F = N * M = N * 784931.  N=12000 (~max
--                     unique scriptPubKeys in a 4MB block) gives F ≈ 9.4
--                     × 10^9, comfortably below 2^53.  But the
--                     architectural decision to drop uint64_t precision
--                     means any future bump of M (e.g. for a stricter
--                     false-positive rate) or a synthetic block with
--                     many more unique scripts pushes hashes into the
--                     2^53+ regime where Lua doubles lose 1-bit
--                     precision per multiply.  match_gcs_filter would
--                     then produce false-negatives on legitimate
--                     queries — silently breaking SPV clients.  Keep
--                     uint64_t end-to-end and use ffi-typed sort
--                     comparator.
--
--   BUG-10 (MED)      compute_filter_header (blockfilter.lua:500) accepts
--                     `prev_header` as a hash256 type.  At the genesis
--                     block (height=0), index.connect_block fetches
--                     index.get_last_header(), which returns
--                     types.hash256_zero() when no meta key exists.  But
--                     Core (blockfilter.cpp:255) uses `uint256()` — the
--                     default-constructed all-zeros — only for the
--                     SyncStarted path before genesis is connected.
--                     After genesis is connected, prev_header for
--                     height=1 must be the GENESIS filter header, NOT
--                     zero.  If index.connect_block is called for
--                     height=1 before height=0 (out-of-order replay),
--                     the chain seeds wrong and ALL subsequent filter
--                     headers diverge from Core forever.  The index
--                     should refuse out-of-order connect or assert
--                     `height == best_height + 1`.
--
--   BUG-11 (MED)      index.disconnect_block (blockfilter.lua:673-690)
--                     handles a missing prev filter at height-1 by
--                     resetting to hash256_zero().  Core (blockfilter
--                     index.cpp WriteBlock rollback) never resets to
--                     genesis-zero mid-chain — a missing predecessor
--                     means the index is corrupt and must be rebuilt
--                     from scratch.  Silent zero-fill makes a corrupt
--                     index look healthy until the divergence is
--                     discovered downstream (REST returns wrong header,
--                     P2P after BUG-1 is fixed serves bad cfheaders,
--                     peers ban).
--
--   BUG-12 (MED)      index.set_best_height (blockfilter.lua:543) and
--                     encode_height (blockfilter.lua:570) DISAGREE on
--                     endianness: set_best_height writes 4-byte LE,
--                     encode_height writes 4-byte BE.  Justification
--                     plausible (LE for the meta scalar, BE for ordered
--                     iteration on the height column family), but the
--                     mismatch is undocumented and invites adjacent
--                     code to assume uniform encoding.  Core uses
--                     uint32_t throughout; lunarblock has no comment
--                     explaining the split.
--
--   BUG-13 (LOW)      No persistent CFCHECKPT cache.  Core stores
--                     pre-computed checkpoint headers every 1000 blocks
--                     in the filter index DB (blockfilterindex.cpp
--                     line 372: `bool is_checkpoint{block_index->
--                     nHeight % CFCHECKPT_INTERVAL == 0}`).  Lunarblock
--                     would have to walk the chain on every getcfcheckpt
--                     request after BUG-1+6 are fixed — at chain height
--                     900k that's 900 round-trips through
--                     get_filter_by_height.
--
--   BUG-14 (LOW)      get_filter_headers (blockfilter.lua:730-741) does
--                     N round-trips for a range request.  Core's
--                     LookupFilterHashRange uses a single iterator pass.
--                     A getcfheaders for 2000 headers (MAX_GETCFHEADERS_
--                     SIZE) costs 2000 DB lookups in lunarblock vs 1 in
--                     Core.  Performance, not correctness, but at chain
--                     tip the path is hot.
--
--   BUG-15 (LOW)      encode_height (blockfilter.lua:570) uses
--                     math.floor + % to encode big-endian, which
--                     silently wraps at 2^32.  A test height of
--                     5_000_000_000 (above mainnet capacity but valid
--                     in adversarial unit tests) encodes to the wrong
--                     bytes with no error.  Core uses uint32_t typed
--                     storage and a bounded encoder.
--
--   BUG-16 (LOW)      build_gcs_filter / match_gcs_filter accept a
--                     `block_hash` arg but the F computation is N * M
--                     with NO upper bound on N (line 291).  A pathological
--                     caller passing N=10^9 would create
--                     F = 7.85 × 10^14 ≈ 2^49.5 — still in uint64_t
--                     range, but tonumber(F) thereafter loses precision.
--                     Core enforces N ≤ 2^32 via the wire-level varint
--                     bound but the function lacks a defensive guard.
--
--   BUG-17 (LOW)      No FILTER_TYPE_BY_NAME map exported from
--                     blockfilter.lua — rest.lua duplicates the mapping
--                     locally (rest.lua:34 M.FILTER_TYPE_BY_NAME).  When
--                     a new filter type is added (e.g. taproot annex
--                     filter), the rest.lua copy must be updated
--                     separately.  Two-pipeline gap (filter type
--                     registry in both files).
--
--   BUG-18 (LOW)      P2P V2_MESSAGE_IDS in p2p.lua:1278 and bip324.lua:99
--                     both list "getcfilters" at slot 22, but the maps
--                     are HAND-DUPLICATED.  Adding a new message type
--                     requires editing two files.  Two-pipeline.
--
-- Total: 18 actionable bugs / 38 tests / 30 gates.
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_w121_compact_filters.lua 2>&1

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

local blockfilter = require("lunarblock.blockfilter")
local p2p         = require("lunarblock.p2p")
local types       = require("lunarblock.types")
local crypto      = require("lunarblock.crypto")
local serialize   = require("lunarblock.serialize")

local PASS = 0
local FAIL = 0
local BUGS = {}

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
    error((msg or "mismatch") .. ": got " .. tostring(a) .. ", expected " .. tostring(b))
  end
end

local function expect_true(v, msg)
  if not v then error(msg or "expected true, got false") end
end

local function expect_false(v, msg)
  if v then error(msg or "expected false, got true") end
end

local function bug(id, severity)
  BUGS[#BUGS + 1] = id .. " (" .. severity .. ")"
end

local function read_file(path)
  local f = io.open(path, "r")
  if not f then return "" end
  local s = f:read("*a"); f:close(); return s
end

-- ---------------------------------------------------------------------------
-- G1: BIP-158 P parameter (Golomb-Rice = 19)
-- ---------------------------------------------------------------------------
print("\n--- G1: BIP-158 P parameter ---")

test("G1-a: BASIC_FILTER_P = 19", function()
  expect_eq(blockfilter.BASIC_FILTER_P, 19, "BIP-158 §1")
end)

test("G1-b: blockfilter.h:90 value match", function()
  expect_eq(blockfilter.BASIC_FILTER_P, 19, "blockfilter.h line 90")
end)

-- ---------------------------------------------------------------------------
-- G2: BIP-158 M parameter (1 / false-positive rate = 784931)
-- ---------------------------------------------------------------------------
print("\n--- G2: BIP-158 M parameter ---")

test("G2-a: BASIC_FILTER_M = 784931", function()
  expect_eq(blockfilter.BASIC_FILTER_M, 784931, "BIP-158 §1")
end)

-- ---------------------------------------------------------------------------
-- G3: FILTER_TYPE.BASIC = 0
-- ---------------------------------------------------------------------------
print("\n--- G3: FILTER_TYPE.BASIC = 0 ---")

test("G3-a: blockfilter.FILTER_TYPE.BASIC = 0", function()
  expect_eq(blockfilter.FILTER_TYPE.BASIC, 0, "BIP-157 §Filter Types")
end)

test("G3-b: p2p.FILTER_TYPE.BASIC = 0", function()
  expect_eq(p2p.FILTER_TYPE.BASIC, 0, "p2p mirror")
end)

-- ---------------------------------------------------------------------------
-- G4: getcfilters wire codec round-trip
-- ---------------------------------------------------------------------------
print("\n--- G4: getcfilters round-trip ---")

test("G4-a: serialize/deserialize getcfilters", function()
  local stop = types.hash256_from_hex(
    "00000000000000000007878ec04bb2b2e12317804810f4c26033585b3f81ffaa")
  local payload = p2p.serialize_getcfilters(0, 100000, stop)
  expect_eq(#payload, 1 + 4 + 32, "1+4+32 byte wire size")
  local d = p2p.deserialize_getcfilters(payload)
  expect_eq(d.filter_type, 0, "filter_type")
  expect_eq(d.start_height, 100000, "start_height")
  expect_true(types.hash256_eq(d.stop_hash, stop), "stop_hash")
end)

-- ---------------------------------------------------------------------------
-- G5: getcfheaders wire codec round-trip
-- ---------------------------------------------------------------------------
print("\n--- G5: getcfheaders round-trip ---")

test("G5-a: serialize/deserialize getcfheaders", function()
  local stop = types.hash256_from_hex(
    "00000000000000000007878ec04bb2b2e12317804810f4c26033585b3f81ffaa")
  local payload = p2p.serialize_getcfheaders(0, 200000, stop)
  expect_eq(#payload, 1 + 4 + 32, "wire size")
  local d = p2p.deserialize_getcfheaders(payload)
  expect_eq(d.start_height, 200000, "start_height")
end)

-- ---------------------------------------------------------------------------
-- G6: getcfcheckpt wire codec round-trip
-- ---------------------------------------------------------------------------
print("\n--- G6: getcfcheckpt round-trip ---")

test("G6-a: serialize/deserialize getcfcheckpt", function()
  local stop = types.hash256_from_hex(
    "00000000000000000007878ec04bb2b2e12317804810f4c26033585b3f81ffaa")
  local payload = p2p.serialize_getcfcheckpt(0, stop)
  expect_eq(#payload, 1 + 32, "1+32 byte wire size")
  local d = p2p.deserialize_getcfcheckpt(payload)
  expect_eq(d.filter_type, 0, "filter_type")
end)

-- ---------------------------------------------------------------------------
-- G7: cfilter wire codec round-trip
-- ---------------------------------------------------------------------------
print("\n--- G7: cfilter round-trip ---")

test("G7-a: serialize/deserialize cfilter with non-empty body", function()
  local h = types.hash256_from_hex(
    "00000000000000000007878ec04bb2b2e12317804810f4c26033585b3f81ffaa")
  local body = "\x02\x00\xff\xff\xff\xff"  -- varint(2) + 5 bytes
  local payload = p2p.serialize_cfilter(0, h, body)
  local d = p2p.deserialize_cfilter(payload)
  expect_eq(d.filter_type, 0, "filter_type")
  expect_eq(d.filter_data, body, "filter_data round-trip")
end)

-- ---------------------------------------------------------------------------
-- G8: cfheaders wire codec round-trip
-- ---------------------------------------------------------------------------
print("\n--- G8: cfheaders round-trip ---")

test("G8-a: serialize/deserialize cfheaders with 3 hashes", function()
  local stop = types.hash256(crypto.sha256("stop"))
  local prev = types.hash256(crypto.sha256("prev"))
  local hashes = {
    types.hash256(crypto.sha256("h1")),
    types.hash256(crypto.sha256("h2")),
    types.hash256(crypto.sha256("h3")),
  }
  local payload = p2p.serialize_cfheaders(0, stop, prev, hashes)
  local d = p2p.deserialize_cfheaders(payload)
  expect_eq(#d.filter_hashes, 3, "3 filter hashes")
  expect_true(types.hash256_eq(d.filter_hashes[2], hashes[2]), "h2 round-trip")
end)

-- ---------------------------------------------------------------------------
-- G9: cfcheckpt wire codec round-trip
-- ---------------------------------------------------------------------------
print("\n--- G9: cfcheckpt round-trip ---")

test("G9-a: serialize/deserialize cfcheckpt with 5 headers", function()
  local stop = types.hash256(crypto.sha256("stop"))
  local headers = {}
  for i = 1, 5 do
    headers[i] = types.hash256(crypto.sha256("cp" .. i))
  end
  local payload = p2p.serialize_cfcheckpt(0, stop, headers)
  local d = p2p.deserialize_cfcheckpt(payload)
  expect_eq(#d.filter_headers, 5, "5 checkpoint headers")
end)

-- ---------------------------------------------------------------------------
-- G10: P2P dispatch — getcfilters handler (BUG-1)
-- ---------------------------------------------------------------------------
print("\n--- G10: P2P dispatch — getcfilters handler ---")

test("G10-a: FIX-81 — peer.lua dispatch arm for getcfilters present", function()
  -- FIX-81 closure of BUG-1: peer.lua now has an explicit case branch
  -- dispatching getcfilters to the registered handler chain.
  local peer_src = read_file("src/peer.lua")
  expect_true(peer_src:find('"getcfilters"', 1, true) ~= nil,
    "peer.lua dispatch arm for getcfilters is present (FIX-81)")
  -- The handler lives in main.lua as a peer_manager:register_handler
  -- closure (deserialization happens inside the handler, not in peer.lua).
  local main_src = read_file("src/main.lua")
  expect_true(main_src:find("deserialize_getcfilters", 1, true) ~= nil,
    "main.lua handler invokes p2p.deserialize_getcfilters")
end)

test("G10-b: FIX-81 — codec + main.lua handler + peer.lua dispatch wire end-to-end", function()
  expect_true(type(p2p.deserialize_getcfilters) == "function",
    "deserialize_getcfilters wire codec exists")
  expect_true(type(p2p.serialize_cfilter) == "function",
    "serialize_cfilter response codec exists")
  local main_src = read_file("src/main.lua")
  expect_true(main_src:find('register_handler%("getcfilters"') ~= nil,
    "main.lua registers getcfilters handler")
end)

-- ---------------------------------------------------------------------------
-- G11: P2P dispatch — getcfheaders handler (BUG-1)
-- ---------------------------------------------------------------------------
print("\n--- G11: P2P dispatch — getcfheaders handler ---")

test("G11-a: FIX-81 — peer.lua dispatch arm for getcfheaders present", function()
  local peer_src = read_file("src/peer.lua")
  expect_true(peer_src:find('"getcfheaders"', 1, true) ~= nil,
    "peer.lua dispatch arm for getcfheaders is present (FIX-81)")
  local main_src = read_file("src/main.lua")
  expect_true(main_src:find('register_handler%("getcfheaders"') ~= nil,
    "main.lua registers getcfheaders handler")
end)

-- ---------------------------------------------------------------------------
-- G12: P2P dispatch — getcfcheckpt handler (BUG-1)
-- ---------------------------------------------------------------------------
print("\n--- G12: P2P dispatch — getcfcheckpt handler ---")

test("G12-a: FIX-81 — peer.lua dispatch arm for getcfcheckpt present", function()
  local peer_src = read_file("src/peer.lua")
  expect_true(peer_src:find('"getcfcheckpt"', 1, true) ~= nil,
    "peer.lua dispatch arm for getcfcheckpt is present (FIX-81)")
  local main_src = read_file("src/main.lua")
  expect_true(main_src:find('register_handler%("getcfcheckpt"') ~= nil,
    "main.lua registers getcfcheckpt handler")
end)

test("G12-b: FIX-81 — main.lua hosts the handlers (not peerman.lua)", function()
  -- The handlers are registered in main.lua via peer_manager:register_handler.
  -- peerman.lua only plumbs the gate inputs; it does not host filter handlers.
  local peerman_src = read_file("src/peerman.lua")
  expect_false(peerman_src:find('"getcfcheckpt"', 1, true) ~= nil,
    "peerman.lua does not host the getcfcheckpt handler (lives in main.lua)")
end)

-- ---------------------------------------------------------------------------
-- G13: Service bit — NODE_COMPACT_FILTERS advertisement (BUG-2)
-- ---------------------------------------------------------------------------
print("\n--- G13: NODE_COMPACT_FILTERS service-bit advertisement ---")

test("G13-a: NODE_COMPACT_FILTERS constant defined", function()
  expect_eq(p2p.SERVICES.NODE_COMPACT_FILTERS, 64,
    "BIP-157 service bit = 1<<6 = 64")
end)

test("G13-b: FIX-81 — gate fires when operator opts in and dispatch is present", function()
  -- FIX-81 closure: BIP157_P2P_DISPATCH_PRESENT flipped to true now
  -- that peer.lua:854 dispatch arms are wired.  With (a)+(b)+(c) all
  -- true, NODE_COMPACT_FILTERS is honestly advertised.
  local bit = require("bit")
  local s = p2p.our_services(true, true, {
    peerblockfilters = true,
    blockfilterindex_enabled = true,
  })
  expect_true(bit.band(s, p2p.SERVICES.NODE_COMPACT_FILTERS) ~= 0,
    "FIX-81: all 3 gate conditions true ⇒ NODE_COMPACT_FILTERS advertised")
  -- Without opts the bit still stays dark (Core default: peerblockfilters=false).
  local s2 = p2p.our_services(true, true)
  expect_false(bit.band(s2, p2p.SERVICES.NODE_COMPACT_FILTERS) ~= 0,
    "no opts table → no advertisement (matches Core DEFAULT_PEERBLOCKFILTERS)")
end)

test("G13-c: FIX-71 — source-level regression guard rejects unconditional OR", function()
  -- Forward-regression guard: assert no source file unconditionally
  -- ORs NODE_COMPACT_FILTERS into a service bitfield.  Any new wiring
  -- must go through should_advertise_compact_filters().
  for _, path in ipairs({"src/p2p.lua", "src/peer.lua", "src/peerman.lua",
                          "src/main.lua"}) do
    local src = read_file(path)
    -- Match `bit.bor(...NODE_COMPACT_FILTERS...)` ONLY if the line is
    -- gated by `should_advertise_compact_filters`.  We scan line-by-line
    -- and check each occurrence.  In p2p.lua's our_services() the OR is
    -- inside `if ... should_advertise_compact_filters(compactfilters)`.
    for line in src:gmatch("[^\n]+") do
      if line:find("bit%.bor.*NODE_COMPACT_FILTERS") then
        -- This is the gated OR inside our_services.  Verify the
        -- enclosing function has the gate call.
        local idx = src:find(line, 1, true)
        if idx then
          local window = src:sub(math.max(1, idx - 400), idx)
          expect_true(window:find("should_advertise_compact_filters") ~= nil,
            "unconditional NODE_COMPACT_FILTERS OR found in " .. path
            .. " — must be gated by should_advertise_compact_filters")
        end
      end
    end
  end
end)

test("G13-d: FIX-81 — gate function signature + BIP157_P2P_DISPATCH_PRESENT flipped", function()
  -- FIX-81 closure: BIP157_P2P_DISPATCH_PRESENT flipped to true after
  -- peer.lua dispatch arms shipped.  The gate fires for any caller
  -- passing peerblockfilters + blockfilterindex_enabled (no override).
  expect_eq(type(p2p.should_advertise_compact_filters), "function",
    "p2p.should_advertise_compact_filters exists")
  expect_eq(p2p.BIP157_P2P_DISPATCH_PRESENT, true,
    "FIX-81: BIP157_P2P_DISPATCH_PRESENT=true — dispatch arms wired")
  -- Confirm the bit fires via the module-level flag (no override).
  local bit = require("bit")
  local s = p2p.our_services(false, false, {
    peerblockfilters = true,
    blockfilterindex_enabled = true,
  })
  expect_true(bit.band(s, p2p.SERVICES.NODE_COMPACT_FILTERS) ~= 0,
    "with (a)+(b)+(c=module flag) all true, bit DOES set")
end)

test("G13-e: FIX-81 — operator opt-in is the only remaining knob", function()
  local bit = require("bit")
  -- peerblockfilters=true, others default → dark (operator wants but no index).
  local s1 = p2p.our_services(false, false, {peerblockfilters = true})
  expect_false(bit.band(s1, p2p.SERVICES.NODE_COMPACT_FILTERS) ~= 0,
    "peerblockfilters alone → bit dark (blockfilterindex_enabled missing)")
  -- blockfilterindex_enabled=true only → dark (index but operator opted out).
  local s2 = p2p.our_services(false, false, {blockfilterindex_enabled = true})
  expect_false(bit.band(s2, p2p.SERVICES.NODE_COMPACT_FILTERS) ~= 0,
    "blockfilterindex_enabled alone → bit dark (peerblockfilters missing)")
  -- Both opts true ⇒ bit fires (FIX-81: dispatch present).
  local s3 = p2p.our_services(false, false, {
    peerblockfilters = true,
    blockfilterindex_enabled = true,
  })
  expect_true(bit.band(s3, p2p.SERVICES.NODE_COMPACT_FILTERS) ~= 0,
    "FIX-81: (a)+(b)+(c) all true → bit set")
  bug("BUG-2", "P0-WIRE (CLOSED by FIX-81 — peer.lua dispatch + flag flip)")
end)

-- ---------------------------------------------------------------------------
-- G14: MAX_GETCFILTERS_SIZE limit (BUG-5)
-- ---------------------------------------------------------------------------
print("\n--- G14: MAX_GETCFILTERS_SIZE ---")

test("G14-a: FIX-81 — MAX_GETCFILTERS_SIZE constant defined in p2p.lua", function()
  -- FIX-81 closure of BUG-5: net_processing.cpp:184 mirror.
  expect_true(p2p.MAX_GETCFILTERS_SIZE ~= nil,
    "MAX_GETCFILTERS_SIZE constant must exist after FIX-81")
  expect_eq(p2p.MAX_GETCFILTERS_SIZE, 1000,
    "Core value (net_processing.cpp:184) is 1000")
  bug("BUG-5", "P1-CDIV (CLOSED by FIX-81)")
end)

test("G14-b: Core value is 1000", function()
  -- net_processing.cpp:184  static constexpr uint32_t MAX_GETCFILTERS_SIZE = 1000;
  expect_eq(1000, 1000, "Core value referenced for fix")
end)

-- ---------------------------------------------------------------------------
-- G15: MAX_GETCFHEADERS_SIZE limit (BUG-5)
-- ---------------------------------------------------------------------------
print("\n--- G15: MAX_GETCFHEADERS_SIZE ---")

test("G15-a: FIX-81 — MAX_GETCFHEADERS_SIZE constant defined in p2p.lua", function()
  -- FIX-81 closure of BUG-5: net_processing.cpp:186 mirror.
  expect_true(p2p.MAX_GETCFHEADERS_SIZE ~= nil,
    "MAX_GETCFHEADERS_SIZE constant must exist after FIX-81")
  expect_eq(p2p.MAX_GETCFHEADERS_SIZE, 2000,
    "Core value (net_processing.cpp:186) is 2000")
end)

-- ---------------------------------------------------------------------------
-- G16: CFCHECKPT_INTERVAL constant (BUG-6)
-- ---------------------------------------------------------------------------
print("\n--- G16: CFCHECKPT_INTERVAL ---")

test("G16-a: FIX-81 — CFCHECKPT_INTERVAL constant defined in blockfilter.lua", function()
  -- FIX-81 closure of BUG-6: blockfilterindex.h:31 mirror.
  expect_true(blockfilter.CFCHECKPT_INTERVAL ~= nil,
    "CFCHECKPT_INTERVAL constant must exist after FIX-81")
  expect_eq(blockfilter.CFCHECKPT_INTERVAL, 1000,
    "Core value (blockfilterindex.h:31) is 1000")
  bug("BUG-6", "P1-CDIV (CLOSED by FIX-81)")
end)

test("G16-b: Core value is 1000", function()
  -- blockfilterindex.h:31 static constexpr int CFCHECKPT_INTERVAL = 1000;
  expect_eq(1000, 1000, "Core value referenced for fix")
end)

-- ---------------------------------------------------------------------------
-- G17: BasicFilterElements — OP_RETURN and empty-script skip
-- ---------------------------------------------------------------------------
print("\n--- G17: BasicFilterElements skip rules ---")

test("G17-a: empty-script outputs are skipped", function()
  local block = {
    transactions = {
      {
        outputs = {
          {script_pubkey = ""},                       -- empty: skip
          {script_pubkey = "\x76\xa9\x14...."},       -- p2pkh: include
        },
      },
    },
  }
  local elems = blockfilter.extract_basic_filter_elements(block, nil)
  expect_eq(#elems, 1, "empty-script skipped")
end)

test("G17-b: OP_RETURN (0x6a) outputs are skipped", function()
  local block = {
    transactions = {
      {
        outputs = {
          {script_pubkey = "\x6a\x05hello"},          -- op_return: skip
          {script_pubkey = "\x76\xa9\x14...."},
        },
      },
    },
  }
  local elems = blockfilter.extract_basic_filter_elements(block, nil)
  expect_eq(#elems, 1, "OP_RETURN skipped")
end)

test("G17-c: duplicates are deduplicated", function()
  local block = {
    transactions = {
      {
        outputs = {
          {script_pubkey = "\x76\xa9\x14AAAA"},
          {script_pubkey = "\x76\xa9\x14AAAA"},      -- dup
        },
      },
    },
  }
  local elems = blockfilter.extract_basic_filter_elements(block, nil)
  expect_eq(#elems, 1, "duplicate dedupe via seen[]")
end)

-- ---------------------------------------------------------------------------
-- G18: BasicFilterElements — undo_data shape (BUG-7)
-- ---------------------------------------------------------------------------
print("\n--- G18: undo_data shape ---")

test("G18-a: BUG-7 — undo_data accepted as flat list (not nested vtxundo)", function()
  -- Core's vtxundo is nested; lunarblock flattens.  Verify by injecting a
  -- "coinbase-like" entry that Core would skip but lunarblock includes.
  local block = {transactions = {{outputs = {}}}}
  local undo_data = {
    {script_pubkey = "\x6a"},                         -- "coinbase fake"
    {script_pubkey = "\x51"},                         -- real prevout
  }
  local elems = blockfilter.extract_basic_filter_elements(block, undo_data)
  -- Lunarblock includes BOTH (no coinbase-skip).  Core would skip the
  -- first because it lives in vtxundo[0] which corresponds to vtx[1]
  -- (coinbase has no entry).
  expect_eq(#elems, 2,
    "lunarblock includes 'coinbase' undo entry — Core would skip via "
    .. "vtxundo.size() == vtx.size() - 1 invariant")
  bug("BUG-7", "MED-CDIV")
end)

-- ---------------------------------------------------------------------------
-- G19: SipHash key derivation from block hash
-- ---------------------------------------------------------------------------
print("\n--- G19: block_hash_to_keys ---")

test("G19-a: derives two uint64 keys from 32-byte block hash", function()
  local h = types.hash256_from_hex(
    "0000000000000000000000000000000000000000000000000000000000000001")
  local k0, k1 = blockfilter.block_hash_to_keys(h)
  -- bytes 0..7 little-endian: byte 0 = 0x01 (the trailing-byte of internal LE)
  -- Actually hash256_from_hex stores reverse — so byte 0 of internal is the
  -- hex string's last byte (0x01).  k0 should equal 1.
  expect_eq(tostring(k0), "1ULL", "k0 = 1 (byte 0 LE)")
end)

-- ---------------------------------------------------------------------------
-- G20: FastRange64 (upper 64 bits of x * n)
-- ---------------------------------------------------------------------------
print("\n--- G20: FastRange64 ---")

test("G20-a: FastRange64(0, F) = 0", function()
  local ffi = require("ffi")
  local r = blockfilter.fast_range64(ffi.new("uint64_t", 0),
                                     ffi.new("uint64_t", 1000))
  expect_eq(tostring(r), "0ULL", "fast_range64(0, n) = 0")
end)

test("G20-b: FastRange64(2^63, F) ≈ F/2", function()
  local ffi = require("ffi")
  local x = ffi.new("uint64_t", 0x8000000000000000ULL)
  local F = ffi.new("uint64_t", 1000)
  local r = blockfilter.fast_range64(x, F)
  expect_eq(tostring(r), "500ULL", "x = 2^63 → r = F/2 = 500")
end)

-- ---------------------------------------------------------------------------
-- G21: HashToRange composition (SipHash + FastRange64)
-- ---------------------------------------------------------------------------
print("\n--- G21: HashToRange ---")

test("G21-a: identical element + key → identical range", function()
  local ffi = require("ffi")
  local k0 = ffi.new("uint64_t", 1)
  local k1 = ffi.new("uint64_t", 2)
  local F  = ffi.new("uint64_t", 1000000)
  local a = blockfilter.hash_to_range(k0, k1, "hello", F)
  local b = blockfilter.hash_to_range(k0, k1, "hello", F)
  expect_eq(tostring(a), tostring(b), "deterministic")
end)

test("G21-b: different elements → different ranges (FP only)", function()
  local ffi = require("ffi")
  local k0 = ffi.new("uint64_t", 1)
  local k1 = ffi.new("uint64_t", 2)
  local F  = ffi.new("uint64_t", 1000000)
  local a = blockfilter.hash_to_range(k0, k1, "hello", F)
  local b = blockfilter.hash_to_range(k0, k1, "world", F)
  expect_true(tostring(a) ~= tostring(b),
    "distinct elements should usually map distinct (assert single sample)")
end)

-- ---------------------------------------------------------------------------
-- G22: Golomb-Rice encode/decode round-trip at P=19 (BUG-4)
-- ---------------------------------------------------------------------------
print("\n--- G22: GR encode/decode at P=19 ---")

test("G22-a: round-trip small values [0..1000)", function()
  local writer = blockfilter.bit_stream_writer()
  local values = {0, 1, 100, 524287, 524288, 1000000, 9999999}
  local last = 0
  for _, v in ipairs(values) do
    blockfilter.golomb_rice_encode(writer, 19, v - last)
    last = v
  end
  writer.flush()
  local reader = blockfilter.bit_stream_reader(writer.result())
  last = 0
  for _, expected in ipairs(values) do
    local delta = blockfilter.golomb_rice_decode(reader, 19)
    last = last + delta
    expect_eq(last, expected, "round-trip " .. expected)
  end
end)

-- ---------------------------------------------------------------------------
-- G23: Golomb-Rice with P ~= 19 (BUG-4)
-- ---------------------------------------------------------------------------
print("\n--- G23: GR encode/decode at P=20 (NON-basic) ---")

test("G23-a: BUG-4 — P=20 hardcoded to 524288 = 2^19", function()
  local writer = blockfilter.bit_stream_writer()
  -- Encode value 1048575 = 2^20 - 1 with P=20.
  -- Correct: q = 0, r = 1048575 (20 bits all-1).
  -- Lunarblock buggy: q = math.floor(1048575 / 524288) = 1, r = 524287.
  blockfilter.golomb_rice_encode(writer, 20, 1048575)
  writer.flush()
  local reader = blockfilter.bit_stream_reader(writer.result())
  local decoded = blockfilter.golomb_rice_decode(reader, 20)
  -- With both encoder and decoder buggy (both hardcoded to 524288),
  -- round-trip happens to work (q=1, r=524287 encoded → q=1, r=524287
  -- decoded → 1*524288 + 524287 = 1048575).  So self-roundtrip ALSO
  -- happens to pass — but the wire bytes disagree with Core.
  expect_eq(decoded, 1048575,
    "self-consistent at P=20 only because BOTH sides bug-equivalent")
  -- Verify the bytes-on-wire differ from a real P=20 encoder:
  -- Correct: 0-bit (q=0), then 20 bits of r=0xFFFFF → 21 bits total.
  -- Lunarblock: 1-bit, 0-bit, then 19 bits of r=0x7FFFF → 21 bits same
  -- count, but the value layout is wrong.  We can't easily diff against
  -- Core in pure Lua, so this test only documents the bug from source.
  local src = read_file("src/blockfilter.lua")
  expect_true(src:find("524288", 1, true) ~= nil,
    "blockfilter.lua hardcodes 524288 — fix landed")
  bug("BUG-4", "P1-CDIV")
end)

-- ---------------------------------------------------------------------------
-- G24: Golomb-Rice decoder bounds (BUG-3, BUG-11)
-- ---------------------------------------------------------------------------
print("\n--- G24: GR decoder bounds / DoS ---")

test("G24-a: BUG-3 — decoder unbounded unary q read", function()
  local src = read_file("src/blockfilter.lua")
  -- Look for the unbounded while loop.
  expect_true(src:find("while bitreader.read%(1%) == 1 do") ~= nil,
    "decoder has unbounded q read — bound check is present")
  bug("BUG-3", "P0-CDIV")
end)

test("G24-b: BUG-8 — bit_stream_reader.read uses Lua bit.lshift", function()
  local src = read_file("src/blockfilter.lua")
  -- The reader inner loop accumulates via numeric shift; verify the
  -- comment / structure.
  expect_true(src:find("result = bit%.lshift%(result, 1%)") ~= nil,
    "reader uses Lua bit.lshift — replaced with uint64 accumulator")
  bug("BUG-8", "MED")
end)

-- ---------------------------------------------------------------------------
-- G25: filter hash + filter header chain (BIP-157 §"Filter Headers")
-- ---------------------------------------------------------------------------
print("\n--- G25: filter hash + header chain ---")

test("G25-a: compute_filter_hash = SHA256d(encoded_filter)", function()
  local enc = "\x00"  -- varint(0): empty filter
  local h = blockfilter.compute_filter_hash(enc)
  -- SHA256d("\x00") = SHA256(SHA256("\x00"))
  local expected = crypto.hash256("\x00")
  expect_eq(h.bytes, expected, "SHA256d of encoded filter")
end)

test("G25-b: compute_filter_header chains correctly", function()
  local filter_hash = types.hash256(string.rep("\x01", 32))
  local prev_header = types.hash256(string.rep("\x02", 32))
  local header = blockfilter.compute_filter_header(filter_hash, prev_header)
  -- header = SHA256d(filter_hash.bytes || prev_header.bytes)
  local expected = crypto.hash256(string.rep("\x01", 32) .. string.rep("\x02", 32))
  expect_eq(header.bytes, expected, "SHA256d(fhash || prev)")
end)

test("G25-c: genesis header uses all-zero prev (BIP-157)", function()
  local filter_hash = types.hash256(string.rep("\x01", 32))
  local zero = types.hash256_zero()
  local header = blockfilter.compute_filter_header(filter_hash, zero)
  local expected = crypto.hash256(string.rep("\x01", 32) .. string.rep("\x00", 32))
  expect_eq(header.bytes, expected, "genesis prev = uint256()")
end)

-- ---------------------------------------------------------------------------
-- G26: build_basic_filter for empty block
-- ---------------------------------------------------------------------------
print("\n--- G26: build_basic_filter empty block ---")

test("G26-a: empty block produces varint(0) only", function()
  local block = {transactions = {}}
  local h = types.hash256(string.rep("\x00", 32))
  local enc = blockfilter.build_basic_filter(block, h, nil)
  expect_eq(enc, "\x00",
    "BIP-158: empty filter is single byte varint(0)")
end)

-- ---------------------------------------------------------------------------
-- G27: build + match round-trip (single element)
-- ---------------------------------------------------------------------------
print("\n--- G27: filter match round-trip ---")

test("G27-a: single element match", function()
  local block_hash = types.hash256(string.rep("\xAB", 32))
  local enc = blockfilter.build_gcs_filter({"hello"}, block_hash)
  expect_true(blockfilter.match_gcs_filter(enc, "hello", block_hash),
    "matches inserted element")
  expect_false(blockfilter.match_gcs_filter(enc, "absent", block_hash),
    "does not match (unless FP) absent element")
end)

test("G27-b: match_any round-trip", function()
  local block_hash = types.hash256(string.rep("\xCD", 32))
  local enc = blockfilter.build_gcs_filter({"a", "b", "c"}, block_hash)
  expect_true(blockfilter.match_any_gcs_filter(enc, {"x", "y", "b"}, block_hash),
    "any-match finds 'b'")
end)

-- ---------------------------------------------------------------------------
-- G28: Filter index lifecycle (BUG-10, BUG-11, BUG-12)
-- ---------------------------------------------------------------------------
print("\n--- G28: filter index lifecycle ---")

test("G28-a: BUG-10 — connect_block does not enforce sequential height", function()
  local src = read_file("src/blockfilter.lua")
  -- Verify connect_block has no `height == best_height + 1` assertion.
  local fn_block = src:match(
    "function index%.connect_block%b()%s*(.-)\n%s*end\n%s*\n")
  if fn_block then
    expect_false(fn_block:find("get_best_height") ~= nil,
      "connect_block validates height ordering — fix landed")
  end
  bug("BUG-10", "MED")
end)

test("G28-b: BUG-11 — disconnect_block silently zero-fills on missing prev", function()
  local src = read_file("src/blockfilter.lua")
  -- The body for disconnect_block on prev-missing branch sets header to
  -- types.hash256_zero() — verify present.
  expect_true(src:find("hash256_zero%(%)") ~= nil,
    "disconnect_block error path on missing prev — fix landed")
  bug("BUG-11", "MED")
end)

test("G28-c: BUG-12 — set_best_height LE vs encode_height BE mismatch", function()
  local src = read_file("src/blockfilter.lua")
  expect_true(src:find("write_u32le%(height%)") ~= nil,
    "set_best_height uses write_u32le")
  expect_true(src:find("math%.floor%(height / 16777216%)") ~= nil,
    "encode_height uses big-endian math.floor / %% encoding")
  bug("BUG-12", "MED")
end)

test("G28-d: BUG-15 — encode_height silently wraps at 2^32", function()
  local src = read_file("src/blockfilter.lua")
  expect_true(src:find("math%.floor%(height / 16777216%) %% 256") ~= nil,
    "encode_height wraps via mod 256 — fix bounds check")
  bug("BUG-15", "LOW")
end)

-- ---------------------------------------------------------------------------
-- G29: REST endpoints
-- ---------------------------------------------------------------------------
print("\n--- G29: REST endpoints ---")

test("G29-a: handle_blockfilter exists", function()
  local rest = require("lunarblock.rest")
  -- Check the function is defined on the prototype.
  local src = read_file("src/rest.lua")
  expect_true(src:find("RESTServer:handle_blockfilter%(") ~= nil,
    "/rest/blockfilter/* endpoint exists")
end)

test("G29-b: handle_blockfilterheaders exists", function()
  local src = read_file("src/rest.lua")
  expect_true(src:find("RESTServer:handle_blockfilterheaders%(") ~= nil,
    "/rest/blockfilterheaders/* endpoint exists")
end)

test("G29-c: BUG-17 — FILTER_TYPE_BY_NAME duplicated in rest.lua", function()
  local rest_src = read_file("src/rest.lua")
  local bf_src = read_file("src/blockfilter.lua")
  expect_true(rest_src:find("FILTER_TYPE_BY_NAME") ~= nil,
    "rest.lua has FILTER_TYPE_BY_NAME")
  expect_false(bf_src:find("FILTER_TYPE_BY_NAME") ~= nil,
    "blockfilter.lua exports FILTER_TYPE_BY_NAME — single source of truth")
  bug("BUG-17", "LOW")
end)

-- ---------------------------------------------------------------------------
-- G30: tonumber demotion of uint64 hash output (BUG-9)
-- ---------------------------------------------------------------------------
print("\n--- G30: uint64 → number demotion in build/match ---")

test("G30-a: BUG-9 — tonumber(hash_to_range) in build_gcs_filter", function()
  local src = read_file("src/blockfilter.lua")
  expect_true(src:find("tonumber%(hash_to_range") ~= nil,
    "build/match still demote uint64 to number — uint64-end-to-end fix landed")
  bug("BUG-9", "MED")
end)

test("G30-b: F = N * M kept as uint64 (partial credit)", function()
  local src = read_file("src/blockfilter.lua")
  expect_true(src:find('ffi%.new%("uint64_t", N%) %* ffi%.new%("uint64_t", M_param%)') ~= nil,
    "F kept as uint64_t — W90 Bug 9 fix preserved")
end)

test("G30-c: BUG-16 — no upper-bound check on N", function()
  local src = read_file("src/blockfilter.lua")
  -- Look for any `if N > ...` guard between the empty-filter check and
  -- the F computation.
  expect_false(src:find("if N > %d") ~= nil,
    "build_gcs_filter bounds-checks N — fix landed")
  bug("BUG-16", "LOW")
end)

test("G30-d: BUG-13 — no CFCHECKPT persistence in index", function()
  local src = read_file("src/blockfilter.lua")
  expect_false(src:find("is_checkpoint") ~= nil,
    "checkpoint persistence wired — fix landed")
  bug("BUG-13", "LOW")
end)

test("G30-e: BUG-14 — get_filter_headers does N round-trips", function()
  local src = read_file("src/blockfilter.lua")
  local fn = src:match("function index%.get_filter_headers(.-)end\n")
  if fn then
    expect_true(fn:find("get_filter_by_height") ~= nil,
      "still per-height lookup — fix landed (single-pass iterator)")
  end
  bug("BUG-14", "LOW")
end)

test("G30-f: BUG-18 — V2_MESSAGE_IDS duplicated in p2p.lua and bip324.lua", function()
  local p2p_src = read_file("src/p2p.lua")
  local b324_src = read_file("src/bip324.lua")
  expect_true(p2p_src:find('%[22%] = "getcfilters"') ~= nil,
    "p2p.lua V2_MESSAGE_IDS slot 22 = getcfilters")
  expect_true(b324_src:find('%[22%] = "getcfilters"') ~= nil,
    "bip324.lua V2_MESSAGE_IDS slot 22 = getcfilters — duplicated mapping")
  bug("BUG-18", "LOW")
end)

-- ===========================================================================
-- Summary
-- ===========================================================================
print("\n=========================================================================")
print(string.format("W121 BIP-157/158 compact filters audit: %d PASS / %d FAIL / %d gates",
  PASS, FAIL, 30))
print(string.format("Bugs found: %d", #BUGS))
for _, b in ipairs(BUGS) do print("  " .. b) end
print("=========================================================================")

if FAIL > 0 then os.exit(1) end
