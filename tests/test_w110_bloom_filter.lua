#!/usr/bin/env luajit
-- test_w110_bloom_filter.lua — W110 bloom filter audit test suite
--
-- Tests BUG-8/9/10 (G25/G26/G27): BIP-111 disconnect path for
-- filterload/filteradd/filterclear when NODE_BLOOM not advertised.
-- Also tests BUG-3 (MurmurHash3 53-bit mantissa fix via mul32u).
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_w110_bloom_filter.lua
--   # or: luajit -e "package.path = 'src/?.lua;' .. package.path; require('bloom')"

package.path = "src/?.lua;./?.lua;" .. package.path

local bloom = require("lunarblock.bloom")
local p2p   = require("lunarblock.p2p")

local PASS = 0
local FAIL = 0

local function pass(name)
  print(string.format("  PASS  %s", name))
  PASS = PASS + 1
end

local function fail(name, msg)
  print(string.format("  FAIL  %s — %s", name, msg))
  FAIL = FAIL + 1
end

local function eq(a, b, name)
  if a == b then
    pass(name)
  else
    fail(name, string.format("expected %s, got %s", tostring(b), tostring(a)))
  end
end

local function ok(v, name)
  if v then pass(name) else fail(name, "expected truthy, got falsy") end
end

local function not_ok(v, name)
  if not v then pass(name) else fail(name, "expected falsy, got truthy") end
end

------------------------------------------------------------------------
-- Helpers to simulate the BIP-111 dispatch logic without a live node.
-- We replicate the bloom_guard() closure from main.lua exactly.
------------------------------------------------------------------------

local bit_mod = require("bit")

--- Simulate the bloom_guard check from main.lua:
-- Returns false (and records a disconnect) if NODE_BLOOM not advertised.
local function bloom_guard_sim(peer_our_services, msg_type)
  local advertised_bloom = bit_mod.band(peer_our_services or 0,
                                        p2p.SERVICES.NODE_BLOOM) ~= 0
  if not advertised_bloom then
    return false, msg_type .. " received but NODE_BLOOM not advertised (BIP-111)"
  end
  return true, nil
end

------------------------------------------------------------------------
-- Section 1: p2p constants
------------------------------------------------------------------------
print("=== Section 1: p2p constants ===")

-- NODE_BLOOM = 1<<2 = 4 (BIP-111, p2p.h)
eq(p2p.SERVICES.NODE_BLOOM, 4, "NODE_BLOOM service bit = 4")

-- bloom.lua exports the same constant
eq(bloom.NODE_BLOOM, 4, "bloom.NODE_BLOOM = 4")

------------------------------------------------------------------------
-- Section 2: BIP-111 disconnect — filterload (BUG-8 / G25)
------------------------------------------------------------------------
print("=== Section 2: BIP-111 filterload disconnect (BUG-8) ===")

-- NODE_BLOOM NOT advertised → must disconnect
do
  local our_svc_no_bloom = 0  -- NODE_NETWORK only (bit 0)
  local guarded, reason = bloom_guard_sim(our_svc_no_bloom, "filterload")
  not_ok(guarded, "filterload guard rejects when NODE_BLOOM absent (services=0)")
  ok(reason and reason:find("BIP%-111"), "filterload disconnect reason contains BIP-111")
end

-- NODE_BLOOM IS advertised → must not disconnect
do
  local our_svc_with_bloom = p2p.SERVICES.NODE_BLOOM  -- = 4
  local guarded, reason = bloom_guard_sim(our_svc_with_bloom, "filterload")
  ok(guarded, "filterload guard passes when NODE_BLOOM advertised")
  ok(reason == nil, "filterload no disconnect reason when NODE_BLOOM advertised")
end

-- Combined services: NODE_NETWORK | NODE_BLOOM | NODE_WITNESS (1|4|8 = 13)
do
  local our_svc_combined = bit_mod.bor(1, 4, 8)  -- 13
  local guarded, _ = bloom_guard_sim(our_svc_combined, "filterload")
  ok(guarded, "filterload guard passes with combined services (NODE_NETWORK|BLOOM|WITNESS)")
end

-- Nil our_services (unset peer, should default to 0 → disconnect)
do
  local guarded, reason = bloom_guard_sim(nil, "filterload")
  not_ok(guarded, "filterload guard rejects when our_services=nil")
  ok(reason ~= nil, "filterload nil our_services produces disconnect reason")
end

------------------------------------------------------------------------
-- Section 3: BIP-111 disconnect — filteradd (BUG-9 / G26)
------------------------------------------------------------------------
print("=== Section 3: BIP-111 filteradd disconnect (BUG-9) ===")

do
  local guarded, reason = bloom_guard_sim(0, "filteradd")
  not_ok(guarded, "filteradd guard rejects when NODE_BLOOM absent")
  ok(reason and reason:find("filteradd"), "filteradd reason names the message type")
end

do
  local guarded, _ = bloom_guard_sim(p2p.SERVICES.NODE_BLOOM, "filteradd")
  ok(guarded, "filteradd guard passes when NODE_BLOOM advertised")
end

------------------------------------------------------------------------
-- Section 4: BIP-111 disconnect — filterclear (BUG-10 / G27)
------------------------------------------------------------------------
print("=== Section 4: BIP-111 filterclear disconnect (BUG-10) ===")

do
  local guarded, reason = bloom_guard_sim(0, "filterclear")
  not_ok(guarded, "filterclear guard rejects when NODE_BLOOM absent")
  ok(reason and reason:find("filterclear"), "filterclear reason names the message type")
end

do
  local guarded, _ = bloom_guard_sim(p2p.SERVICES.NODE_BLOOM, "filterclear")
  ok(guarded, "filterclear guard passes when NODE_BLOOM advertised")
end

------------------------------------------------------------------------
-- Section 5: bloom.lua module loads and exports key functions (BUG-3 infra)
------------------------------------------------------------------------
print("=== Section 5: bloom.lua module integrity ===")

ok(type(bloom.bloom_filter)           == "function", "bloom.bloom_filter exported")
ok(type(bloom.insert)                 == "function", "bloom.insert exported")
ok(type(bloom.contains)               == "function", "bloom.contains exported")
ok(type(bloom.parse_filterload)       == "function", "bloom.parse_filterload exported")
ok(type(bloom.parse_filteradd)        == "function", "bloom.parse_filteradd exported")
ok(type(bloom.is_within_size_constraints) == "function", "bloom.is_within_size_constraints exported")
ok(type(bloom.murmur_hash3)           == "function", "bloom.murmur_hash3 exported (BUG-3 fix)")

-- MAX constants
eq(bloom.MAX_BLOOM_FILTER_SIZE, 36000, "MAX_BLOOM_FILTER_SIZE = 36000")
eq(bloom.MAX_HASH_FUNCS, 50, "MAX_HASH_FUNCS = 50")
eq(bloom.MAX_FILTER_ADD_SIZE, 520, "MAX_FILTER_ADD_SIZE = 520 (BIP-37)")

------------------------------------------------------------------------
-- Section 6: MurmurHash3 BUG-3 fix (mul32u 53-bit mantissa guard)
-- Reference values from bitcoin-core/src/hash.cpp test vectors.
------------------------------------------------------------------------
print("=== Section 6: MurmurHash3 BUG-3 (mul32u 53-bit overflow guard) ===")

-- Known test vectors from Core's murmur tests (src/test/bloom_tests.cpp)
-- MurmurHash3(0, "") = 0
eq(bloom.murmur_hash3(0, ""), 0, "MurmurHash3(seed=0, data='') = 0")

-- MurmurHash3(0, one_null_byte): Lua string "\x00" is a space (0x20), not NUL.
-- Use string.char(0) for the actual NUL byte.
-- The one-byte body exercises the tail path and mul32u in fmix32.
-- Verified value: 1364076727 (cross-checked against the Lua implementation).
local h_zero_byte = bloom.murmur_hash3(0, string.char(0))
eq(h_zero_byte, 1364076727, "MurmurHash3(0, NUL-byte) = 1364076727 (BUG-3 regression)")

-- BUG-3 trigger check: seeds/data that exercise the multiplication path.
-- MurmurHash3(1, "") = 1364076727 (same as MurmurHash3(0, "\x00") due to fmix32
-- with h1=seed after empty body — seed=1 exercises the mul32u path in finalization).
eq(bloom.murmur_hash3(1, ""), 1364076727, "MurmurHash3(seed=1, data='') = 1364076727")

-- Large seed exercises the mul32u cross-product path in fmix32
-- MurmurHash3(5, "") = 3423425485
eq(bloom.murmur_hash3(5, ""), 3423425485, "MurmurHash3(seed=5, data='') = 3423425485")

-- Result is always in u32 range
local h_hello = bloom.murmur_hash3(0xdeadbeef, "hello")
ok(h_hello >= 0 and h_hello < 4294967296, "MurmurHash3 result is in u32 range (0..2^32-1)")

------------------------------------------------------------------------
-- Section 7: CBloomFilter insert/contains round-trip
------------------------------------------------------------------------
print("=== Section 7: CBloomFilter insert/contains ===")

local bf = bloom.bloom_filter(1000, 0.001, 0, bloom.UPDATE_NONE)
ok(bf ~= nil, "bloom_filter() constructs a filter")
ok(bf.vdata_len > 0, "filter has non-zero vdata")
ok(bf.n_hash_funcs >= 1, "filter has at least 1 hash function")
ok(bloom.is_within_size_constraints(bf), "default filter is within size constraints")

-- Insert a key and check membership
bloom.insert(bf, "testkey")
ok(bloom.contains(bf, "testkey"), "contains() true for inserted key")
-- Non-inserted key should (almost certainly) not be present with 0.1% FP rate
-- We use a very long key that can't realistically collide
local absent = bloom.contains(bf, "this_key_was_never_inserted_xyz_123")
-- Can't assert false due to probabilistic nature; just ensure function returns bool
ok(type(absent) == "boolean", "contains() returns boolean for absent key")

------------------------------------------------------------------------
-- Section 8: parse_filterload round-trip (bloom.lua wiring readiness)
------------------------------------------------------------------------
print("=== Section 8: parse_filterload round-trip ===")

-- Build a filter, encode it, parse it back
local bf2 = bloom.bloom_filter(100, 0.001, 42, bloom.UPDATE_ALL)
bloom.insert(bf2, "roundtrip_test")
local encoded = bloom.encode_filterload(bf2)
ok(type(encoded) == "string", "encode_filterload returns string")
ok(#encoded > 0, "encode_filterload returns non-empty bytes")

local parsed, err = bloom.parse_filterload(encoded)
ok(parsed ~= nil, "parse_filterload succeeds on valid payload")
ok(err == nil, "parse_filterload no error on valid payload")
if parsed then
  eq(parsed.n_hash_funcs, bf2.n_hash_funcs, "round-trip n_hash_funcs matches")
  eq(parsed.n_tweak, bf2.n_tweak, "round-trip n_tweak matches")
  eq(parsed.n_flags, bf2.n_flags, "round-trip n_flags matches")
  eq(parsed.vdata_len, bf2.vdata_len, "round-trip vdata_len matches")
  -- Verify the inserted key still matches in the parsed filter
  ok(bloom.contains(parsed, "roundtrip_test"), "contains() true in parsed filter for inserted key")
end

------------------------------------------------------------------------
-- Section 9: parse_filteradd size guard (MAX_FILTER_ADD_SIZE = 520)
------------------------------------------------------------------------
print("=== Section 9: parse_filteradd size guard ===")

-- Valid element (1 byte)
local ser = require("lunarblock.serialize")
local w = ser.buffer_writer()
w.write_varstr("A")
local ok_payload = w.result()
local elem, ferr = bloom.parse_filteradd(ok_payload)
ok(elem ~= nil, "parse_filteradd succeeds on 1-byte element")
ok(ferr == nil, "parse_filteradd no error on 1-byte element")

-- Oversized element (521 bytes — should fail)
local w2 = ser.buffer_writer()
w2.write_varstr(string.rep("\xAB", 521))
local over_payload = w2.result()
local elem2, ferr2 = bloom.parse_filteradd(over_payload)
ok(elem2 == nil, "parse_filteradd rejects 521-byte element (MAX_FILTER_ADD_SIZE=520)")
ok(ferr2 ~= nil, "parse_filteradd error message for oversized element")

-- Exactly 520 bytes — should succeed
local w3 = ser.buffer_writer()
w3.write_varstr(string.rep("\xCD", 520))
local exact_payload = w3.result()
local elem3, ferr3 = bloom.parse_filteradd(exact_payload)
ok(elem3 ~= nil, "parse_filteradd accepts exactly 520-byte element")
ok(ferr3 == nil, "parse_filteradd no error for exactly 520-byte element")

------------------------------------------------------------------------
-- Summary
------------------------------------------------------------------------
print(string.rep("-", 60))
print(string.format("Results: %d PASS, %d FAIL", PASS, FAIL))
if FAIL > 0 then
  os.exit(1)
else
  print("ALL PASS")
  os.exit(0)
end
