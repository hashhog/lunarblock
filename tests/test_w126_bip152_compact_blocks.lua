#!/usr/bin/env luajit
-- W126 BIP-152 Compact Blocks audit — lunarblock (Lua / LuaJIT)
--
-- Reference: bitcoin-core/src/blockencodings.cpp + blockencodings.h
--            bitcoin-core/src/net_processing.cpp (SENDCMPCT / CMPCTBLOCK /
--              GETBLOCKTXN / BLOCKTXN handlers, MaybeSetPeerAsAnnouncing
--              HeaderAndIDs, NewPoWValidBlock fast-announce)
--            bitcoin-core/src/net_processing.h (MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK)
--            BIP-152
--
-- Scope: verify lunarblock's compact-block path matches Core's behavior on
--        the 30 gates enumerated in audit/w126_bip152_compact_blocks.md.
--        Tests that exercise existing PRESENT plumbing use plain test();
--        tests that exercise MISSING/PARTIAL plumbing use test_xfail_pre_fix
--        so the suite stays green pre-fix and flips naturally when fixes
--        land (lunarblock W121 / W122 / W125 convention).
--
-- Gate summary (audit/w126_bip152_compact_blocks.md):
--   G1   CMPCTBLOCKS_VERSION == 2                                  PRESENT
--   G2   MAX_CMPCTBLOCK_DEPTH == 5                                 PRESENT
--   G3   SHORTTXIDS_LENGTH == 6                                    PRESENT
--   G4   MAX_CMPCTBLOCK_TX_COUNT == 100000                         PRESENT
--   G5   MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK == 3 (constant only)   BUG-1 (P1)
--   G6   MAX_BLOCKTXN_DEPTH == 10                                  BUG-2 (P1)
--   G7   sendcmpct version==2 gating (W112 BUG-8 fix)              PRESENT
--   G8   SipHash-2-4 test-vector parity                            PRESENT
--   G9   siphash_key_from_header SHA256(header‖nonce) split        PRESENT
--   G10  short-id is lower 48 bits                                 PRESENT
--   G11  cmpctblock differential prefilled-index decoding          PRESENT
--   G12  getblocktxn differential index round-trip                 PRESENT
--   G13  InitData 9-gate validation                                PRESENT
--   G14  cmpctblock header PoW + chain-connect                     BUG-3 (P0-CDIV)
--   G15  cmpctblock anti-DoS work threshold (low-work filter)      BUG-4 (P1)
--   G16  cmpctblock LoadingBlocks/IBD guard                        BUG-5 (P2)
--   G17  cmpctblock Misbehaving on INVALID InitData                BUG-6 (P1)
--   G18  cmpctblock inflight tracking + first-in-flight branch     BUG-7 (P2)
--   G19  cmpctblock optimistic reconstruction path                 BUG-8 (P2)
--   G20  reconstruct() IsBlockMutated hook (segwit_active)         BUG-9 (P1)
--   G21  init() extra_txn (vExtraTxnForCompact) plumbing           BUG-10 (P2)
--   G22  getblocktxn Misbehaving on out-of-bounds tx index         BUG-11 (P1)
--   G23  getblocktxn MAX_BLOCKTXN_DEPTH + full-block fallback      (BUG-2)
--   G24  getdata MSG_CMPCT_BLOCK response                          BUG-12 (P2)
--   G25  sendcmpct gated on CommonVersion >= SHORT_IDS_BLOCKS_V    BUG-13 (P3)
--   G26  distinct m_bip152_highbandwidth_to vs _from               BUG-13b (P2)
--   G27  MaybeSetPeerAsAnnouncingHeaderAndIDs outbound HB promo    BUG-13c (P2)
--   G28  HB peer cap == 3 enforced at HB selection time            PARTIAL
--   G29  m_most_recent_compact_block cache                         BUG-14 (P3)
--   G30  explicit cmpctblock/getblocktxn/blocktxn dispatch arms    PARTIAL
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_w126_bip152_compact_blocks.lua 2>&1
--

package.path = "src/?.lua;src/?/init.lua;./?.lua;" .. package.path

local ffi    = require("ffi")
local crypto = require("lunarblock.crypto")
local p2p    = require("lunarblock.p2p")
local cb_mod = require("lunarblock.compact_block")
local types  = require("lunarblock.types")
local serial = require("lunarblock.serialize")

-- ---------------------------------------------------------------------------
-- Test scaffolding (W121/W122/W125 lunarblock convention)
-- ---------------------------------------------------------------------------

local PASS = 0
local FAIL = 0
local XFAIL_PRE_FIX = 0
local BUGS = {}

local function pass(name)
  io.write(string.format("  PASS  %s\n", name))
  PASS = PASS + 1
end

local function fail(name, msg)
  io.write(string.format("  FAIL  %s -- %s\n", name, msg))
  FAIL = FAIL + 1
end

local function xfail_pre_fix(name, msg)
  io.write(string.format("  XFAIL %s -- %s\n", name, msg))
  XFAIL_PRE_FIX = XFAIL_PRE_FIX + 1
end

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end

-- Wraps a test that is expected to FAIL pre-fix.  When the fix lands,
-- flip to plain test() — or just let it auto-flip via the
-- "[now PASSing — ...]" branch below.
local function test_xfail_pre_fix(name, bug_id, fn)
  local ok, err = pcall(fn)
  if ok then
    pass(name .. " [now PASSing — " .. bug_id .. " fix likely landed]")
  else
    xfail_pre_fix(name .. " (" .. bug_id .. ")", tostring(err))
  end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) ..
          ", expected " .. tostring(b), 2)
  end
end

local function expect_ok(v, msg)
  if not v then error((msg or "expected truthy") .. ": got " .. tostring(v), 2) end
end

local function expect_not_ok(v, msg)
  if v then error((msg or "expected falsy") .. ": got " .. tostring(v), 2) end
end

local function bug(id, severity)
  BUGS[#BUGS + 1] = id .. " (" .. severity .. ")"
end

local function file_contains(path, needle)
  local f = io.open(path, "r")
  if not f then return false end
  local body = f:read("*a")
  f:close()
  return body:find(needle, 1, true) ~= nil
end

local function file_does_not_contain(path, needle)
  return not file_contains(path, needle)
end

local function make_fake_hdr()
  return {
    version    = 1,
    prev_hash  = types.hash256_zero(),
    merkle_root= types.hash256_zero(),
    timestamp  = 0,
    bits       = 0x1d00ffff,
    nonce      = 0,
  }
end

-- ---------------------------------------------------------------------------
-- Banner
-- ---------------------------------------------------------------------------

print("\n=========================================================================")
print("W126 BIP-152 Compact Blocks audit — lunarblock")
print("Source: src/compact_block.lua, src/p2p.lua, src/crypto.lua,")
print("        src/peer.lua, src/peerman.lua, src/main.lua")
print("Reference: bitcoin-core/src/blockencodings.{cpp,h}, net_processing.cpp")
print("=========================================================================")

-- ---------------------------------------------------------------------------
-- G1: CMPCTBLOCKS_VERSION == 2 (BIP-152 v2, wtxid-based)
-- Expectation: PRESENT.  compact_block.lua:16.
-- ---------------------------------------------------------------------------
print("\n--- G1: CMPCTBLOCKS_VERSION == 2 ---")
test("G1-a: CMPCTBLOCKS_VERSION constant == 2",
  function() expect_eq(cb_mod.CMPCTBLOCKS_VERSION, 2, "CMPCTBLOCKS_VERSION") end)

-- ---------------------------------------------------------------------------
-- G2: MAX_CMPCTBLOCK_DEPTH == 5 (Core net_processing.cpp:138)
-- Expectation: PRESENT.  compact_block.lua:19.
-- ---------------------------------------------------------------------------
print("\n--- G2: MAX_CMPCTBLOCK_DEPTH == 5 ---")
test("G2-a: MAX_CMPCTBLOCK_DEPTH constant == 5",
  function() expect_eq(cb_mod.MAX_CMPCTBLOCK_DEPTH, 5, "MAX_CMPCTBLOCK_DEPTH") end)

-- ---------------------------------------------------------------------------
-- G3: SHORTTXIDS_LENGTH == 6 (BIP-152 §3.3)
-- Expectation: PRESENT.  p2p.lua:966.
-- ---------------------------------------------------------------------------
print("\n--- G3: SHORTTXIDS_LENGTH == 6 ---")
test("G3-a: SHORTTXIDS_LENGTH constant == 6",
  function() expect_eq(p2p.SHORTTXIDS_LENGTH, 6, "SHORTTXIDS_LENGTH") end)

-- ---------------------------------------------------------------------------
-- G4: MAX_CMPCTBLOCK_TX_COUNT == 100000 (Core blockencodings.cpp:64)
-- Expectation: PRESENT.  compact_block.lua:30.
-- ---------------------------------------------------------------------------
print("\n--- G4: MAX_CMPCTBLOCK_TX_COUNT == 100000 ---")
test("G4-a: MAX_CMPCTBLOCK_TX_COUNT == 100000",
  function() expect_eq(cb_mod.MAX_CMPCTBLOCK_TX_COUNT, 100000, "MAX_CMPCTBLOCK_TX_COUNT") end)
test("G4-b: above-limit short_ids+prefilled rejected by InitData",
  function()
    local big_ids = {}
    for i = 1, 100001 do big_ids[i] = i end
    local pdb = cb_mod.new_partial_block()
    local err = pdb:init({header = make_fake_hdr(),
                          short_ids = big_ids, prefilled_txns = {}, nonce = 0})
    expect_ok(err, "InitData returned an error for 100001-tx cmpctblock")
  end)

-- ---------------------------------------------------------------------------
-- G5: MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK == 3 (Core net_processing.h:47)
-- Expectation: constant present, ENFORCEMENT MISSING.  BUG-1 P1.
-- ---------------------------------------------------------------------------
print("\n--- G5: MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK ENFORCEMENT (BUG-1 P1) ---")
bug("BUG-1", "P1")
test("G5-a: MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK constant == 3",
  function() expect_eq(cb_mod.MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK, 3,
    "MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK") end)
test_xfail_pre_fix(
  "G5-b: cmpctblock handler enforces MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK",
  "BUG-1", function()
    -- The constant is defined but not referenced anywhere in main.lua.
    -- Once enforced, main.lua will grep for it.
    expect_ok(file_contains("src/main.lua", "MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK"),
      "main.lua should reference MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK for enforcement")
  end)

-- ---------------------------------------------------------------------------
-- G6: MAX_BLOCKTXN_DEPTH == 10 (Core net_processing.cpp:140)
-- Expectation: MISSING.  BUG-2 P1.
-- ---------------------------------------------------------------------------
print("\n--- G6: MAX_BLOCKTXN_DEPTH == 10 (BUG-2 P1) ---")
bug("BUG-2", "P1")
test_xfail_pre_fix(
  "G6-a: MAX_BLOCKTXN_DEPTH constant defined",
  "BUG-2", function()
    expect_ok(cb_mod.MAX_BLOCKTXN_DEPTH ~= nil,
      "compact_block.lua should export MAX_BLOCKTXN_DEPTH")
    expect_eq(cb_mod.MAX_BLOCKTXN_DEPTH, 10, "MAX_BLOCKTXN_DEPTH should be 10")
  end)
test_xfail_pre_fix(
  "G6-b: getblocktxn handler enforces MAX_BLOCKTXN_DEPTH",
  "BUG-2", function()
    -- Search src/main.lua for the constant reference inside the getblocktxn handler.
    expect_ok(file_contains("src/main.lua", "MAX_BLOCKTXN_DEPTH"),
      "main.lua getblocktxn handler should reference MAX_BLOCKTXN_DEPTH")
  end)

-- ---------------------------------------------------------------------------
-- G7: sendcmpct only enables compact mode when version == 2 (W112 BUG-8 fix)
-- Expectation: PRESENT.  peer.lua:892-902 (the version == 2 guard).
-- ---------------------------------------------------------------------------
print("\n--- G7: sendcmpct version==2 gating ---")
test("G7-a: sendcmpct round-trips version=2",
  function()
    local sc = p2p.deserialize_sendcmpct(p2p.serialize_sendcmpct(true, 2))
    expect_eq(sc.version, 2, "version round-trips")
    expect_eq(sc.announce, true, "announce round-trips")
  end)
test("G7-b: source-level — sendcmpct guard requires version == 2",
  function()
    expect_ok(file_contains("src/peer.lua", "sc.version == 2"),
      "peer.lua sendcmpct handler should require sc.version == 2")
  end)

-- ---------------------------------------------------------------------------
-- G8: SipHash-2-4 test vector parity (Core/RFC standard vector)
-- Expectation: PRESENT.  crypto.lua:1198.
-- ---------------------------------------------------------------------------
print("\n--- G8: SipHash-2-4 test vector ---")
test("G8-a: SipHash-2-4 standard test vector matches",
  function()
    -- Standard SipHash-2-4 vector:
    -- key = 000102030405060708090a0b0c0d0e0f → k0=0706050403020100, k1=0f0e0d0c0b0a0908
    -- msg = 000102030405060708090a0b0c0d0e (15 bytes)
    -- expected = 0xa129ca6149be45e5
    local k0 = ffi.new("uint64_t", 0x0706050403020100ULL)
    local k1 = ffi.new("uint64_t", 0x0f0e0d0c0b0a0908ULL)
    local msg = ""
    for i = 0, 14 do msg = msg .. string.char(i) end
    local got = crypto.siphash24(k0, k1, msg)
    local expected = ffi.new("uint64_t", 0xa129ca6149be45e5ULL)
    expect_ok(got == expected, "SipHash-2-4 vector matches: got " .. tostring(got))
  end)

-- ---------------------------------------------------------------------------
-- G9: siphash_key_from_header = SHA256(header‖nonce) split into k0/k1
-- Expectation: PRESENT.  crypto.lua:1254.
-- ---------------------------------------------------------------------------
print("\n--- G9: siphash_key_from_header ---")
test("G9-a: deterministic key derivation",
  function()
    local hdr = string.rep("\x00", 80)
    local k0a, k1a = crypto.siphash_key_from_header(hdr, 0)
    local k0b, k1b = crypto.siphash_key_from_header(hdr, 0)
    expect_ok(k0a == k0b and k1a == k1b, "same input → same keys")
  end)
test("G9-b: nonce diversification produces distinct keys",
  function()
    local hdr = string.rep("\x00", 80)
    local k0a, k1a = crypto.siphash_key_from_header(hdr, 0)
    local k0b, k1b = crypto.siphash_key_from_header(hdr, 1)
    expect_ok(k0a ~= k0b or k1a ~= k1b, "different nonces should diversify keys")
  end)

-- ---------------------------------------------------------------------------
-- G10: short_id = SipHash result & 0xffffffffffff (lower 48 bits)
-- Expectation: PRESENT.  crypto.lua:1278.
-- ---------------------------------------------------------------------------
print("\n--- G10: short_id is lower 48 bits ---")
test("G10-a: compact_block_short_id returns Lua number in [0, 2^48)",
  function()
    local k0 = ffi.new("uint64_t", 0x0102030405060708ULL)
    local k1 = ffi.new("uint64_t", 0x090a0b0c0d0e0f10ULL)
    local wtxid = string.rep("\x42", 32)
    local sid = crypto.compact_block_short_id(k0, k1, wtxid)
    expect_eq(type(sid), "number", "short_id is Lua number")
    expect_ok(sid >= 0 and sid < 2^48, "short_id in [0, 2^48)")
  end)

-- ---------------------------------------------------------------------------
-- G11: cmpctblock differential prefilled-index decoding
-- Expectation: PRESENT.  p2p.lua:1046-1053.
-- ---------------------------------------------------------------------------
print("\n--- G11: cmpctblock differential prefilled decoding ---")
test("G11-a: 6-byte short_id wire round-trip",
  function()
    -- Build a minimal cmpctblock with one max-value short_id, no prefilled.
    local hdr_bytes = string.rep("\x00", 80)
    local w = serial.buffer_writer()
    w.write_bytes(hdr_bytes)
    w.write_u64le(0)         -- nonce
    w.write_varint(1)        -- 1 short_id
    local max_sid = 0xffffffffffff
    for i = 0, 5 do
      local byte = math.floor(max_sid / (256^i)) % 256
      w.write_u8(byte)
    end
    w.write_varint(0)        -- 0 prefilled
    local parsed = p2p.deserialize_cmpctblock(w.result())
    expect_eq(#parsed.short_ids, 1, "one short_id deserialized")
    expect_eq(parsed.short_ids[1], max_sid, "max 6-byte short_id round-trips")
  end)

-- ---------------------------------------------------------------------------
-- G12: getblocktxn differential index encode/decode round-trip
-- Expectation: PRESENT.  p2p.lua:1079-1117.
-- ---------------------------------------------------------------------------
print("\n--- G12: getblocktxn differential index round-trip ---")
test("G12-a: indexes round-trip through diff encoding",
  function()
    local block_hash = types.hash256(string.rep("\xab", 32))
    local indexes = {0, 1, 5, 10, 11}  -- diffs: 0, 0, 3, 4, 0
    local payload = p2p.serialize_getblocktxn(block_hash, indexes)
    local parsed = p2p.deserialize_getblocktxn(payload)
    expect_eq(#parsed.indexes, #indexes, "index count round-trips")
    for i, idx in ipairs(indexes) do
      expect_eq(parsed.indexes[i], idx,
        string.format("index %d (pos %d) round-trips", idx, i))
    end
  end)

-- ---------------------------------------------------------------------------
-- G13: PartiallyDownloadedBlock InitData validation
-- Expectation: PRESENT.  compact_block.lua:134-323 (W112 G1-G9).
-- ---------------------------------------------------------------------------
print("\n--- G13: PartiallyDownloadedBlock InitData validation ---")
test("G13-a: missing header → INVALID",
  function()
    local pdb = cb_mod.new_partial_block()
    local err = pdb:init({header = nil, short_ids = {1}, prefilled_txns = {}})
    expect_ok(err ~= nil, "missing header returns error")
  end)
test("G13-b: both-lists-empty → INVALID",
  function()
    local pdb = cb_mod.new_partial_block()
    local err = pdb:init({header = make_fake_hdr(), short_ids = {}, prefilled_txns = {}})
    expect_ok(err ~= nil, "empty short_ids and prefilled_txns → error")
  end)
test("G13-c: re-init guard",
  function()
    local pdb = cb_mod.new_partial_block()
    local err1 = pdb:init({header = make_fake_hdr(),
                           short_ids = {1, 2}, prefilled_txns = {}, nonce = 0})
    if err1 == nil then
      local err2 = pdb:init({header = make_fake_hdr(),
                             short_ids = {3}, prefilled_txns = {}, nonce = 0})
      expect_ok(err2 ~= nil, "second init must error")
    end
  end)

-- ---------------------------------------------------------------------------
-- G14: cmpctblock header PoW + chain-connect validation
-- Expectation: MISSING.  BUG-3 P0-CDIV.
-- Core: net_processing.cpp:4483-4508 (LookupBlockIndex + ProcessNewBlockHeaders).
-- ---------------------------------------------------------------------------
print("\n--- G14: cmpctblock header PoW + chain-connect (BUG-3 P0-CDIV) ---")
bug("BUG-3", "P0-CDIV")
test_xfail_pre_fix(
  "G14-a: cmpctblock handler calls check_block_header / ProcessNewBlockHeaders",
  "BUG-3", function()
    -- Source-level: main.lua cmpctblock handler must reference header
    -- validation.  Either via `validation.check_block_header(...)` or
    -- via the existing `accept_block` plumbing called BEFORE
    -- partial:init.
    local main_lua = io.open("src/main.lua", "r")
    expect_ok(main_lua, "open main.lua")
    local body = main_lua:read("*a")
    main_lua:close()
    -- Locate the cmpctblock handler.  We bound it loosely between its
    -- registration line and the next `peer_manager:register_handler(`.
    local handler_start = body:find('register_handler%("cmpctblock"', 1, false)
    expect_ok(handler_start, "cmpctblock handler should be registered")
    local handler_end = body:find('register_handler%(', handler_start + 1, false)
                       or #body
    local handler_body = body:sub(handler_start, handler_end)
    -- Look for either check_block_header (direct validation) or
    -- LookupBlockIndex / prev_block existence check.
    local has_header_check = handler_body:find("check_block_header", 1, true)
                          or handler_body:find("check_pow", 1, true)
                          or handler_body:find("prev_block", 1, true)
    expect_ok(has_header_check,
      "cmpctblock handler must validate header PoW + prev_block")
  end)

-- ---------------------------------------------------------------------------
-- G15: cmpctblock anti-DoS work threshold (low-work filter)
-- Expectation: MISSING.  BUG-4 P1.
-- Core: net_processing.cpp:4490-4494.
-- ---------------------------------------------------------------------------
print("\n--- G15: cmpctblock anti-DoS work threshold (BUG-4 P1) ---")
bug("BUG-4", "P1")
test_xfail_pre_fix(
  "G15-a: cmpctblock handler references anti-DoS work threshold",
  "BUG-4", function()
    expect_ok(file_contains("src/main.lua", "GetAntiDoSWorkThreshold")
           or file_contains("src/main.lua", "anti_dos_work_threshold")
           or file_contains("src/main.lua", "anti_dos_work"),
      "cmpctblock handler should call anti-DoS work threshold check")
  end)

-- ---------------------------------------------------------------------------
-- G16: cmpctblock LoadingBlocks/IBD guard
-- Expectation: MISSING.  BUG-5 P2.
-- Core: net_processing.cpp:4468-4472.
-- ---------------------------------------------------------------------------
print("\n--- G16: cmpctblock LoadingBlocks/IBD guard (BUG-5 P2) ---")
bug("BUG-5", "P2")
test_xfail_pre_fix(
  "G16-a: cmpctblock handler early-returns when not ibd_complete",
  "BUG-5", function()
    local body = io.open("src/main.lua"):read("*a")
    local h = body:find('register_handler%("cmpctblock"', 1, false)
    local e = body:find('register_handler%(', h + 1, false) or #body
    local seg = body:sub(h, e)
    expect_ok(seg:find("ibd_complete", 1, true)
           or seg:find("LoadingBlocks", 1, true),
      "cmpctblock handler should gate on ibd_complete / LoadingBlocks")
  end)

-- ---------------------------------------------------------------------------
-- G17: cmpctblock Misbehaving on INVALID InitData
-- Expectation: MISSING.  BUG-6 P1.
-- Core: net_processing.cpp:4592-4595.
-- ---------------------------------------------------------------------------
print("\n--- G17: cmpctblock Misbehaving on INVALID InitData (BUG-6 P1) ---")
bug("BUG-6", "P1")
test_xfail_pre_fix(
  "G17-a: cmpctblock handler calls peer:misbehaving on INVALID InitData",
  "BUG-6", function()
    local body = io.open("src/main.lua"):read("*a")
    local h = body:find('register_handler%("cmpctblock"', 1, false)
    local e = body:find('register_handler%(', h + 1, false) or #body
    local seg = body:sub(h, e)
    expect_ok(seg:find("misbehaving", 1, true)
           or seg:find("Misbehaving", 1, true),
      "cmpctblock handler should call peer:misbehaving on INVALID")
  end)

-- ---------------------------------------------------------------------------
-- G18: cmpctblock inflight tracking + first-in-flight branch
-- Expectation: MISSING.  BUG-7 P2.
-- Core: net_processing.cpp:4543-4634.
-- ---------------------------------------------------------------------------
print("\n--- G18: cmpctblock inflight tracking (BUG-7 P2) ---")
bug("BUG-7", "P2")
test_xfail_pre_fix(
  "G18-a: cmpctblock handler tracks per-block in-flight count",
  "BUG-7", function()
    expect_ok(file_contains("src/main.lua", "first_in_flight")
           or file_contains("src/main.lua", "already_in_flight")
           or file_contains("src/main.lua", "in_flight"),
      "cmpctblock handler should track per-block in-flight count")
  end)

-- ---------------------------------------------------------------------------
-- G19: cmpctblock optimistic reconstruction path
-- Expectation: MISSING.  BUG-8 P2.
-- Core: net_processing.cpp:4640-4654.
-- ---------------------------------------------------------------------------
print("\n--- G19: cmpctblock optimistic reconstruction (BUG-8 P2) ---")
bug("BUG-8", "P2")
test_xfail_pre_fix(
  "G19-a: cmpctblock handler attempts optimistic reconstruct when block already in flight",
  "BUG-8", function()
    expect_ok(file_contains("src/main.lua", "optimistic")
           or file_contains("src/main.lua", "tempBlock")
           or file_contains("src/main.lua", "fBlockReconstructed"),
      "cmpctblock handler should attempt optimistic reconstruction")
  end)

-- ---------------------------------------------------------------------------
-- G20: reconstruct() IsBlockMutated hook (segwit_active)
-- Expectation: PARTIAL — hook exists in compact_block.lua but main.lua
--   never passes it.  BUG-9 P1.
-- Core: blockencodings.cpp:219-221.
-- ---------------------------------------------------------------------------
print("\n--- G20: reconstruct() IsBlockMutated hook (BUG-9 P1) ---")
bug("BUG-9", "P1")
test("G20-a: PartiallyDownloadedBlock:reconstruct accepts check_mutated argument",
  function()
    -- Verify the hook exists in compact_block.lua source.
    expect_ok(file_contains("src/compact_block.lua", "check_mutated"),
      "compact_block.lua should accept check_mutated hook")
  end)
test_xfail_pre_fix(
  "G20-b: main.lua cmpctblock handler passes check_mutated to reconstruct()",
  "BUG-9", function()
    local body = io.open("src/main.lua"):read("*a")
    -- Find every partial:reconstruct(...) call and check the arg list.
    -- Expect a non-empty argument (function reference).
    local found_with_arg = false
    for arg in body:gmatch("partial:reconstruct%(([^)]*)%)") do
      if #arg:gsub("%s", "") > 0 then found_with_arg = true; break end
    end
    expect_ok(found_with_arg,
      "main.lua should pass a check_mutated callback to partial:reconstruct(...)")
  end)

-- ---------------------------------------------------------------------------
-- G21: init() extra_txn (vExtraTxnForCompact) plumbing
-- Expectation: PARTIAL — param exists but main.lua never passes it.
-- BUG-10 P2.
-- Core: net_processing.cpp:4591,4642.
-- ---------------------------------------------------------------------------
print("\n--- G21: init() extra_txn plumbing (BUG-10 P2) ---")
bug("BUG-10", "P2")
test("G21-a: PartiallyDownloadedBlock:init accepts extra_txn parameter",
  function()
    expect_ok(file_contains("src/compact_block.lua", "extra_txn"),
      "compact_block.lua init should accept extra_txn")
  end)
test_xfail_pre_fix(
  "G21-b: main.lua cmpctblock handler passes extra_txn (orphan/evicted)",
  "BUG-10", function()
    local body = io.open("src/main.lua"):read("*a")
    -- Find every partial:init(...) call and check it has a 3rd argument.
    local found_with_extra = false
    for args in body:gmatch("partial:init%(([^)]*)%)") do
      -- Count commas; 2 commas means 3 args (cmpctblock, mempool, extra_txn).
      local _, ncommas = args:gsub(",", "")
      if ncommas >= 2 then found_with_extra = true; break end
    end
    expect_ok(found_with_extra,
      "main.lua should call partial:init(cmpctblock, mempool, extra_txn)")
  end)

-- ---------------------------------------------------------------------------
-- G22: getblocktxn Misbehaving on out-of-bounds tx index
-- Expectation: MISSING.  BUG-11 P1.
-- Core: net_processing.cpp:2602-2604.
-- ---------------------------------------------------------------------------
print("\n--- G22: getblocktxn out-of-bounds Misbehaving (BUG-11 P1) ---")
bug("BUG-11", "P1")
test_xfail_pre_fix(
  "G22-a: getblocktxn handler misbehaves on out-of-bounds tx index",
  "BUG-11", function()
    local body = io.open("src/main.lua"):read("*a")
    local h = body:find('register_handler%("getblocktxn"', 1, false)
    expect_ok(h, "getblocktxn handler should be registered")
    local e = body:find('register_handler%(', h + 1, false) or #body
    local seg = body:sub(h, e)
    expect_ok(seg:find("misbehaving", 1, true)
           or seg:find("out%-of%-bounds")
           or seg:find("out of bounds"),
      "getblocktxn handler should misbehave on out-of-bounds indexes")
  end)

-- ---------------------------------------------------------------------------
-- G23: getblocktxn MAX_BLOCKTXN_DEPTH + full-block fallback
-- Expectation: MISSING.  Subsumed by BUG-2.
-- Core: net_processing.cpp:4276-4302.
-- ---------------------------------------------------------------------------
print("\n--- G23: getblocktxn MAX_BLOCKTXN_DEPTH fallback (BUG-2 P1) ---")
test_xfail_pre_fix(
  "G23-a: getblocktxn handler falls back to full block when too deep",
  "BUG-2", function()
    local body = io.open("src/main.lua"):read("*a")
    local h = body:find('register_handler%("getblocktxn"', 1, false)
    local e = body:find('register_handler%(', h + 1, false) or #body
    local seg = body:sub(h, e)
    expect_ok(seg:find("MAX_BLOCKTXN_DEPTH", 1, true)
           or seg:find("MSG_WITNESS_BLOCK", 1, true),
      "getblocktxn handler should fall back to full block for too-deep requests")
  end)

-- ---------------------------------------------------------------------------
-- G24: getdata MSG_CMPCT_BLOCK response
-- Expectation: MISSING.  BUG-12 P2.
-- Core: net_processing.cpp:2461-2476.
-- ---------------------------------------------------------------------------
print("\n--- G24: getdata MSG_CMPCT_BLOCK response (BUG-12 P2) ---")
bug("BUG-12", "P2")
test("G24-a: INV_TYPE.MSG_CMPCT_BLOCK constant == 4",
  function() expect_eq(p2p.INV_TYPE.MSG_CMPCT_BLOCK, 4, "MSG_CMPCT_BLOCK") end)
test_xfail_pre_fix(
  "G24-b: getdata handler matches MSG_CMPCT_BLOCK",
  "BUG-12", function()
    local body = io.open("src/main.lua"):read("*a")
    local h = body:find('register_handler%("getdata"', 1, false)
    expect_ok(h, "getdata handler should be registered")
    local e = body:find('register_handler%(', h + 1, false) or #body
    local seg = body:sub(h, e)
    expect_ok(seg:find("MSG_CMPCT_BLOCK", 1, true),
      "getdata handler should branch on MSG_CMPCT_BLOCK")
  end)

-- ---------------------------------------------------------------------------
-- G25: sendcmpct gated on CommonVersion >= SHORT_IDS_BLOCKS_VERSION (70014)
-- Expectation: MISSING.  BUG-13 P3.
-- Core: net_processing.cpp:3864-3871.
-- ---------------------------------------------------------------------------
print("\n--- G25: sendcmpct version gating (BUG-13 P3) ---")
bug("BUG-13", "P3")
test_xfail_pre_fix(
  "G25-a: sendcmpct send gated on remote version >= SHORT_IDS_BLOCKS_VERSION",
  "BUG-13", function()
    expect_ok(file_contains("src/peer.lua", "SHORT_IDS_BLOCKS_VERSION")
           or file_contains("src/peer.lua", "70014"),
      "peer.lua should gate sendcmpct on remote version >= 70014")
  end)

-- ---------------------------------------------------------------------------
-- G26: distinct m_bip152_highbandwidth_to vs _from (Core CNode state)
-- Expectation: MISSING.  Lunarblock collapses to single 'high_bandwidth' flag.
-- BUG-13b P2.
-- ---------------------------------------------------------------------------
print("\n--- G26: distinct highbandwidth_to vs _from (BUG-13b P2) ---")
bug("BUG-13b", "P2")
test_xfail_pre_fix(
  "G26-a: Peer object has separate _to and _from HB flags",
  "BUG-13b", function()
    expect_ok(file_contains("src/peer.lua", "highbandwidth_to")
           or file_contains("src/peer.lua", "high_bandwidth_to")
           or file_contains("src/peer.lua", "bip152_highbandwidth_to"),
      "peer.lua should declare distinct _to and _from HB state flags")
  end)

-- ---------------------------------------------------------------------------
-- G27: MaybeSetPeerAsAnnouncingHeaderAndIDs (outbound HB promotion)
-- Expectation: MISSING.  BUG-13c P2.
-- Core: net_processing.cpp:1272-1329 + BlockChecked:2196-2225.
-- ---------------------------------------------------------------------------
print("\n--- G27: outbound HB promotion via BlockChecked (BUG-13c P2) ---")
bug("BUG-13c", "P2")
test_xfail_pre_fix(
  "G27-a: peerman has MaybeSetPeerAsAnnouncingHeaderAndIDs-equivalent",
  "BUG-13c", function()
    expect_ok(file_contains("src/peerman.lua", "MaybeSetPeerAsAnnouncing")
           or file_contains("src/peerman.lua", "set_peer_as_announcing")
           or file_contains("src/peerman.lua", "promote_hb_peer")
           or file_contains("src/peerman.lua", "announce_header_and_ids"),
      "peerman.lua should promote up-to-3 peers to outbound HB role")
  end)
test_xfail_pre_fix(
  "G27-b: lunarblock sends sendcmpct(true, 2) outbound after a block",
  "BUG-13c", function()
    expect_ok(file_contains("src/peerman.lua", "serialize_sendcmpct(true")
           or file_contains("src/main.lua", "serialize_sendcmpct(true")
           or file_contains("src/peer.lua", "serialize_sendcmpct(true"),
      "we should send sendcmpct(true, 2) to chosen outbound HB peers")
  end)

-- ---------------------------------------------------------------------------
-- G28: HB peer cap == 3 enforced at HB selection
-- Expectation: PARTIAL — MAX_HIGH_BANDWIDTH_PEERS constant exists in
-- compact_block.lua but select_high_bandwidth_peers is never called.
-- Subsumed by BUG-13c.
-- ---------------------------------------------------------------------------
print("\n--- G28: HB peer cap == 3 enforced ---")
test("G28-a: MAX_HIGH_BANDWIDTH_PEERS constant == 3",
  function() expect_eq(cb_mod.MAX_HIGH_BANDWIDTH_PEERS, 3, "MAX_HIGH_BANDWIDTH_PEERS") end)
test_xfail_pre_fix(
  "G28-b: select_high_bandwidth_peers is wired (called from main / peerman)",
  "BUG-13c", function()
    expect_ok(file_contains("src/main.lua", "select_high_bandwidth_peers")
           or file_contains("src/peerman.lua", "select_high_bandwidth_peers"),
      "select_high_bandwidth_peers should be called somewhere")
  end)

-- ---------------------------------------------------------------------------
-- G29: m_most_recent_compact_block cache
-- Expectation: MISSING — announce_block rebuilds every time. BUG-14 P3.
-- Core: net_processing.cpp:2126-2131.
-- ---------------------------------------------------------------------------
print("\n--- G29: most_recent_compact_block cache (BUG-14 P3) ---")
bug("BUG-14", "P3")
test_xfail_pre_fix(
  "G29-a: most-recent compact block cached for reuse",
  "BUG-14", function()
    expect_ok(file_contains("src/peerman.lua", "most_recent_compact_block")
           or file_contains("src/main.lua", "most_recent_compact_block")
           or file_contains("src/peerman.lua", "recent_compact_block"),
      "the most-recent cmpctblock should be cached for getdata reuse")
  end)

-- ---------------------------------------------------------------------------
-- G30: explicit cmpctblock/getblocktxn/blocktxn dispatch arms in peer.lua
-- Expectation: PARTIAL — currently falls through to catch-all
-- message_handlers[msg.command].  Functional but inconsistent with cfilter
-- pattern that has explicit elif arms.
-- ---------------------------------------------------------------------------
print("\n--- G30: explicit BIP-152 dispatch arms in peer.lua ---")
test("G30-a: cmpctblock/getblocktxn/blocktxn reach registered handlers",
  function()
    -- Smoke: process_messages dispatch flow can be verified by checking
    -- that the catch-all `else` branch exists in peer.lua.
    expect_ok(file_contains("src/peer.lua", "message_handlers[msg.command]"),
      "peer.lua should have a catch-all message_handlers dispatch")
  end)
test_xfail_pre_fix(
  "G30-b: explicit BIP-152 elif arms (cmpctblock/getblocktxn/blocktxn)",
  "G30-cosmetic", function()
    expect_ok(file_contains("src/peer.lua", 'msg.command == "cmpctblock"')
           or file_contains("src/peer.lua", 'msg.command == "getblocktxn"')
           or file_contains("src/peer.lua", 'msg.command == "blocktxn"'),
      "peer.lua should explicitly dispatch BIP-152 messages (cosmetic, " ..
      "matches cfilter pattern)")
  end)

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
print("\n=========================================================================")
print(string.format("W126 Results:  PASS=%d   XFAIL_PRE_FIX=%d   FAIL=%d",
  PASS, XFAIL_PRE_FIX, FAIL))
print(string.format("Total tests: %d", PASS + XFAIL_PRE_FIX + FAIL))

-- Deduplicate BUGS list and print rollup.
local seen = {}
local unique_bugs = {}
for _, bug_id in ipairs(BUGS) do
  if not seen[bug_id] then
    seen[bug_id] = true
    unique_bugs[#unique_bugs + 1] = bug_id
  end
end
print(string.format("\nBUGs catalogued: %d (1 P0-CDIV / 6 P1 / 7 P2 / 2 P3)",
  #unique_bugs))
for _, bug_id in ipairs(unique_bugs) do
  io.write("  " .. bug_id .. "\n")
end
print("\nSee audit/w126_bip152_compact_blocks.md for full bug detail.")
print("=========================================================================\n")

if FAIL > 0 then os.exit(1) end
os.exit(0)
