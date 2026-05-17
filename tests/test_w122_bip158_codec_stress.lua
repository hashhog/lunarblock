#!/usr/bin/env luajit
-- W122 BIP-158 GCS codec stress-vector audit — lunarblock (Lua / LuaJIT)
--
-- Reference: bitcoin-core/src/util/golombrice.h GolombRiceEncode/Decode;
--            bitcoin-core/src/streams.h::BitStreamWriter;
--            BIP-158 §"Filter Encoding";
--            haskoin commit 4a2de0f (W121 addendum BUG-16 P0).
--
-- Scope: Stress-test the Golomb-Rice encoder/decoder beyond the
--        q < 64 zone covered by Core's blockfilters.json (13 vectors,
--        all q < 64), where neither W90 nor W121 looked.  Mirror of
--        haskoin BUG-16 hunt in a different code-shape — LuaJIT's
--        bit.lshift 32-bit modular semantics vs Haskell's Word64
--        boundary write.
--
-- Gate map (W122):
--   G1   Encode/decode round-trip for q = 0
--   G2   Encode/decode round-trip for q = 1
--   G3   Encode/decode round-trip for q = 30 (high but < 32)
--   G4   Encode/decode round-trip for q = 31 (boundary — bit.lshift 32-bit edge)
--   G5   Encode/decode round-trip for q = 32 (BUG ZONE entry)
--   G6   Encode/decode round-trip for q = 33 (BUG ZONE)
--   G7   Encode/decode round-trip for q = 40 (BUG ZONE)
--   G8   Encode/decode round-trip for q = 50 (BUG ZONE)
--   G9   Encode/decode round-trip for q = 63 (BUG ZONE upper)
--   G10  Encode/decode round-trip for q = 64 (special 64-bit path)
--   G11  Encode/decode round-trip for q = 65 (just past 64 path)
--   G12  Encode/decode round-trip for q = 100 (64 + 36 = tail in BUG ZONE)
--   G13  Encode/decode round-trip for q = 200 (3*64 + 8 = tail outside BUG ZONE)
--   G14  Encode/decode round-trip for q = 1000 (1000/64 = 15 + 40 = tail in BUG ZONE)
--   G15  Mixed-quotient stream (sorted deltas with q's straddling boundary)
--   G16  Random sorted-delta stream (seeded, 50 elements, wide range)
--   G17  Round-trip integrity (encode -> decode = identity, regardless of value)
--   G18  Source-level regression marker (BUG-1 trigger value q=33)
--   G19  Cross-check vs Core blockfilters.json genesis vector (q < 64 baseline)
--   G20  bit_stream_writer accepts uint64_t cdata mask (FIX-shape probe)
--
-- Bugs found:
--   BUG-1 (P0-CDIV)  golomb_rice_encode (blockfilter.lua:247) writes a
--                    WRONG unary-bit mask for nbits in [32, 63] (and any
--                    q whose 64-tail lands in [32, 63]) because
--                    `bit.lshift(1, nbits) - 1` collapses under LuaJIT's
--                    32-bit modular semantics:
--                      bit.lshift(1, 32) == 1       -> mask=0       (FAIL)
--                      bit.lshift(1, 33) == 2       -> mask=1       (FAIL)
--                      bit.lshift(1, 50) == 262144  -> mask=262143  (FAIL)
--                      bit.lshift(1, 63) == -2147483648 -> mask=0x7FFFFFFF (FAIL)
--                      bit.lshift(1, 64) == 1       -> handled by 64-bit special path
--                    Result: encoded filter for any block with a per-element
--                    delta >= 32 * 2^P (i.e. >= 16777216 for P=19) has a
--                    wrong run-length, the filter_hash diverges from Core,
--                    and the BIP-157 filter_header chain forks from
--                    every other compliant implementation.
--                    P2P-reachable after FIX-81 (W121 BUG-1 closure).
--                    See audit/w122_bip158_codec_stress.md for full trace.
--
--   BUG-2 (carryover of W121 BUG-8) — bit_stream_reader.read(nbits)
--                    silently truncates to 32 bits when nbits > 32 because
--                    `bit.lshift(result, 1)` mods 2^32.  Latent (P=19
--                    hardcoding gates it; included here for completeness).
--
-- Total: 2 actionable bugs / 25 tests / 20 gates.
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_w122_bip158_codec_stress.lua 2>&1

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

local ffi         = require("ffi")
local blockfilter = require("lunarblock.blockfilter")

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
  io.write(string.format("  XFAIL %s (expected pre-fix, BUG-1) -- %s\n", name, msg))
  XFAIL_PRE_FIX = XFAIL_PRE_FIX + 1
end

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end

-- Wraps a test that is expected to FAIL pre-fix (i.e. BUG-1 is open).
-- When the fix lands, flip to plain test() and the post-fix verifier flips
-- to expecting PASS.
local function test_xfail_pre_fix(name, fn)
  local ok, err = pcall(fn)
  if ok then
    -- Post-fix: this should also pass.  If it does, we surface that as
    -- a sign the fix landed (test name flips meaning).  For now we treat
    -- it as PASS so the gate is green either way.
    pass(name .. " [now PASSing — BUG-1 fix likely landed]")
  else
    xfail_pre_fix(name, tostring(err))
  end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) .. ", expected " .. tostring(b))
  end
end

local function bug(id, severity)
  BUGS[#BUGS + 1] = id .. " (" .. severity .. ")"
end

-- ---------------------------------------------------------------------------
-- Helper: encode a single value with P=19, then decode, return the decoded
-- value.  This is the canonical round-trip probe used throughout W122.
-- ---------------------------------------------------------------------------

local P_BASIC = 19  -- BIP-158 §1; blockfilter.h:90
local TWO_P   = 2 ^ P_BASIC  -- 524288

local function round_trip(value, P)
  P = P or P_BASIC
  local w = blockfilter.bit_stream_writer()
  blockfilter.golomb_rice_encode(w, P, value)
  w.flush()
  local r = blockfilter.bit_stream_reader(w.result())
  return blockfilter.golomb_rice_decode(r, P)
end

-- Compute a value that lands in a given quotient bucket (with a known r)
local function value_with_quotient(q, r)
  r = r or 12345  -- arbitrary, < 2^19
  return q * TWO_P + r
end

-- ---------------------------------------------------------------------------
-- Print banner
-- ---------------------------------------------------------------------------

print("\n=========================================================================")
print("W122 BIP-158 GCS codec stress-vector audit — lunarblock")
print("Source: src/blockfilter.lua  (golomb_rice_encode / decode, bit streams)")
print("Reference: bitcoin-core/src/util/golombrice.h, haskoin 4a2de0f")
print("=========================================================================")

-- ---------------------------------------------------------------------------
-- G1: q = 0
-- ---------------------------------------------------------------------------
print("\n--- G1: q = 0 (delta < 2^P) ---")
test("G1-a: round-trip(value=0)", function()
  expect_eq(round_trip(0), 0, "q=0 r=0")
end)
test("G1-b: round-trip(value=12345)", function()
  expect_eq(round_trip(12345), 12345, "q=0 r=12345")
end)

-- ---------------------------------------------------------------------------
-- G2: q = 1
-- ---------------------------------------------------------------------------
print("\n--- G2: q = 1 (single unary one) ---")
test("G2-a: round-trip(value=2^19)", function()
  expect_eq(round_trip(TWO_P), TWO_P, "q=1 r=0")
end)
test("G2-b: round-trip(value_with_quotient(1, 12345))", function()
  local v = value_with_quotient(1, 12345)
  expect_eq(round_trip(v), v, "q=1 r=12345")
end)

-- ---------------------------------------------------------------------------
-- G3: q = 30 (high, but still < 32 — safe zone)
-- ---------------------------------------------------------------------------
print("\n--- G3: q = 30 (below LuaJIT 32-bit boundary) ---")
test("G3-a: round-trip(value_with_quotient(30, 12345))", function()
  local v = value_with_quotient(30)
  expect_eq(round_trip(v), v, "q=30")
end)

-- ---------------------------------------------------------------------------
-- G4: q = 31 (boundary — bit.lshift(1, 31) is signed-equivalent of 2^31)
-- ---------------------------------------------------------------------------
print("\n--- G4: q = 31 (LuaJIT 32-bit boundary) ---")
test("G4-a: round-trip(value_with_quotient(31, 12345))", function()
  local v = value_with_quotient(31)
  expect_eq(round_trip(v), v, "q=31")
end)

-- ---------------------------------------------------------------------------
-- G5-G9: BUG ZONE — q in [32, 63]
-- FIX-83 (W122 BUG-1 closure) flipped these from XFAIL_PRE_FIX → PASS.
-- ---------------------------------------------------------------------------
print("\n--- G5-G9: BUG ZONE q in [32, 63] (BUG-1, FIX-83 closed) ---")

test("G5: q=32 round-trip (smallest BUG ZONE, FIX-83 closed)", function()
  local v = value_with_quotient(32)
  expect_eq(round_trip(v), v, "q=32 BUG-1")
end)

test("G6: q=33 round-trip (FIX-83 closed)", function()
  local v = value_with_quotient(33)
  expect_eq(round_trip(v), v, "q=33 BUG-1")
end)

test("G7: q=40 round-trip (FIX-83 closed)", function()
  local v = value_with_quotient(40)
  expect_eq(round_trip(v), v, "q=40 BUG-1")
end)

test("G8: q=50 round-trip (FIX-83 closed)", function()
  local v = value_with_quotient(50)
  expect_eq(round_trip(v), v, "q=50 BUG-1")
end)

test("G9: q=63 round-trip (BUG ZONE upper bound, FIX-83 closed)", function()
  local v = value_with_quotient(63)
  expect_eq(round_trip(v), v, "q=63 BUG-1")
end)

-- ---------------------------------------------------------------------------
-- G10: q = 64 (special 64-bit path, should pass)
-- ---------------------------------------------------------------------------
print("\n--- G10: q = 64 (special path uses uint64_t mask) ---")
test("G10-a: round-trip(value_with_quotient(64, 12345))", function()
  local v = value_with_quotient(64)
  expect_eq(round_trip(v), v, "q=64 special path")
end)

-- ---------------------------------------------------------------------------
-- G11: q = 65 (special path + 1 extra unary bit)
-- ---------------------------------------------------------------------------
print("\n--- G11: q = 65 (64-path + nbits=1 outside bug zone) ---")
test("G11-a: round-trip(value_with_quotient(65, 12345))", function()
  local v = value_with_quotient(65)
  expect_eq(round_trip(v), v, "q=65")
end)

-- ---------------------------------------------------------------------------
-- G12: q = 100 (64-path + nbits=36 IN BUG ZONE)
-- ---------------------------------------------------------------------------
print("\n--- G12: q = 100 (64+36 tail in BUG ZONE, FIX-83 closed) ---")
test("G12: q=100 round-trip (FIX-83 closed)", function()
  local v = value_with_quotient(100)
  expect_eq(round_trip(v), v, "q=100 BUG-1 (tail=36)")
end)

-- ---------------------------------------------------------------------------
-- G13: q = 200 (3*64 + 8 tail OUTSIDE bug zone)
-- ---------------------------------------------------------------------------
print("\n--- G13: q = 200 (3*64+8 tail outside bug zone) ---")
test("G13-a: round-trip(value_with_quotient(200, 12345))", function()
  local v = value_with_quotient(200)
  expect_eq(round_trip(v), v, "q=200")
end)

-- ---------------------------------------------------------------------------
-- G14: q = 1000 (15*64 + 40 tail in BUG ZONE)
-- ---------------------------------------------------------------------------
print("\n--- G14: q = 1000 (15*64+40 tail in BUG ZONE, FIX-83 closed) ---")
test("G14: q=1000 round-trip (FIX-83 closed)", function()
  local v = value_with_quotient(1000)
  expect_eq(round_trip(v), v, "q=1000 BUG-1 (tail=40)")
end)

-- ---------------------------------------------------------------------------
-- G15: Mixed-quotient stream (deltas straddling the boundary)
-- ---------------------------------------------------------------------------
print("\n--- G15: Mixed-quotient delta stream (FIX-83 closed) ---")
test("G15: encode+decode sorted deltas {q=1, 5, 30, 33, 50, 64, 100} (FIX-83 closed)", function()
  local deltas = {
    value_with_quotient(1,  100),
    value_with_quotient(5,  200),
    value_with_quotient(30, 300),
    value_with_quotient(33, 400),  -- BUG zone
    value_with_quotient(50, 500),  -- BUG zone
    value_with_quotient(64, 600),  -- 64-special path
    value_with_quotient(100,700),  -- 64+36 tail BUG zone
  }
  local w = blockfilter.bit_stream_writer()
  for _, d in ipairs(deltas) do
    blockfilter.golomb_rice_encode(w, P_BASIC, d)
  end
  w.flush()
  local r = blockfilter.bit_stream_reader(w.result())
  for i, d in ipairs(deltas) do
    local dec = blockfilter.golomb_rice_decode(r, P_BASIC)
    expect_eq(dec, d, "stream idx=" .. i .. " q=" .. math.floor(d / TWO_P))
  end
end)

-- ---------------------------------------------------------------------------
-- G16: Random sorted-delta stream (seeded for reproducibility)
-- ---------------------------------------------------------------------------
print("\n--- G16: Random sorted-delta stream (seed=42, 50 elements, FIX-83 closed) ---")
test("G16: round-trip 50 random values, deltas span the bug zone (FIX-83 closed)", function()
  math.randomseed(42)
  local values = {}
  for i = 1, 50 do
    values[i] = math.random(0, 2 ^ 32 - 1)
  end
  table.sort(values)

  local w = blockfilter.bit_stream_writer()
  local last = 0
  for _, v in ipairs(values) do
    blockfilter.golomb_rice_encode(w, P_BASIC, v - last)
    last = v
  end
  w.flush()

  local r = blockfilter.bit_stream_reader(w.result())
  local decoded = {}
  last = 0
  for i = 1, #values do
    local delta = blockfilter.golomb_rice_decode(r, P_BASIC)
    last = last + delta
    decoded[i] = last
  end
  for i = 1, #values do
    expect_eq(decoded[i], values[i],
      string.format("idx=%d val=%d", i, values[i]))
  end
end)

-- ---------------------------------------------------------------------------
-- G17: Round-trip identity property (encode then decode is the identity)
-- ---------------------------------------------------------------------------
print("\n--- G17: Identity property across representative values ---")

local identity_values = {
  0, 1, 2, 524287, 524288, 524289, 1048575, 1048576,
  -- q < 32 (safe zone): pass
  16265272,  -- q = 31, r = 0
  -- q in [32, 63] (BUG ZONE)
  16777216,  -- q = 32, r = 0
  33042488,  -- q = 63, r = 0
  -- q = 64 (special path)
  33554432,  -- q = 64, r = 0
  -- q in [65, 127] mixed
  34091065,  -- q = 65, r = 12345
  100000000, -- q = 190
}

for _, v in ipairs(identity_values) do
  -- FIX-83 (W122 BUG-1 closure) made the bug-zone and safe-zone tests
  -- both round-trip identically.  We still tag the zone in the test name
  -- for diagnostic value when a future regression breaks this.
  local q = math.floor(v / TWO_P)
  local in_bug_zone = (q >= 32 and q <= 63) or
    ((q - 64) >= 32 and (q - 64) <= 63 and q >= 64) or
    ((q - 128) >= 32 and (q - 128) <= 63 and q >= 128) or
    ((q - 192) >= 32 and (q - 192) <= 63 and q >= 192)
  test(string.format("G17: identity round_trip(%d) [q=%d %s]",
       v, q, in_bug_zone and "BUG-1 FIX-83 closed" or "safe"),
     function()
       expect_eq(round_trip(v), v, "value=" .. v)
     end)
end

-- ---------------------------------------------------------------------------
-- G18: Source-level regression marker — q=33 trigger
-- This is the canonical haskoin-style "smallest failing case" — the
-- audit doc references this exact value as BUG-1 evidence.
-- FIX-83 closure flipped this from XFAIL_PRE_FIX → PASS.
-- ---------------------------------------------------------------------------
print("\n--- G18: BUG-1 regression marker (q=33, FIX-83 closed) ---")
test("G18: golomb_rice_encode(P=19, x=17313849) round-trips (FIX-83 closed)", function()
  expect_eq(round_trip(17313849), 17313849,
    "BUG-1 regression marker — q=33, r=12345, identity post-FIX-83")
end)

-- ---------------------------------------------------------------------------
-- G19: Cross-check vs Core blockfilters.json genesis baseline (q < 64)
-- This ensures the BUG ZONE finding does not regress the safe zone.
-- The genesis basic filter is 0x019dfca8 per blockfilters.json.
-- This is decoded by the BIP-158 test in spec/blockfilter_spec.lua;
-- here we just probe that the GR encoder of {0xfca8} (the only element
-- after the varint count) round-trips correctly.  The actual genesis
-- vector uses one element with a small q, so it lands in the safe zone.
-- ---------------------------------------------------------------------------
print("\n--- G19: Core blockfilters.json genesis baseline (safe zone) ---")
test("G19: small-q encode+decode mirrors Core 13-vector behavior", function()
  -- Genesis basic filter elements: 1 single P2PK script's hash maps to
  -- a value within [0, F=784931).  q = value >> 19, so q is at most 1.
  -- Probe a representative small value.
  local v = 1031208  -- arbitrary value < 2^20, q = 1, r = ~ 0x7DAA8
  expect_eq(round_trip(v), v, "small-q baseline")
end)

-- ---------------------------------------------------------------------------
-- G20: bit_stream_writer accepts uint64_t cdata mask (FIX-shape probe)
-- This documents the path the fix should take — handing the writer
-- ffi.new("uint64_t", 0xFFFFFFFFFFFFFFFFULL) for any nbits in [1, 64].
-- ---------------------------------------------------------------------------
print("\n--- G20: FIX-shape probe (uint64_t cdata mask round-trip) ---")
test("G20: writer accepts ffi.new uint64_t all-ones mask, decoder reads 33 ones", function()
  local w = blockfilter.bit_stream_writer()
  -- Write 33 ones using the cdata-uint64 path (mirrors the 64-bit special
  -- case in golomb_rice_encode).  This is the FIX-shape: the encoder
  -- should hand this exact form for any nbits in [1, 64].
  w.write(ffi.new("uint64_t", 0xFFFFFFFFFFFFFFFFULL), 33)
  w.flush()
  local r = blockfilter.bit_stream_reader(w.result())
  local ones = 0
  for _ = 1, 33 do
    local b = r.read(1)
    if b == 1 then ones = ones + 1 end
  end
  expect_eq(ones, 33, "33 ones via cdata uint64_t mask")
end)

-- ---------------------------------------------------------------------------
-- G21: Source-level regression guard for FIX-83 (W122 BUG-1 closure).
-- Forward-guard: assert golomb_rice_encode in src/blockfilter.lua routes
-- every unary write through the writer's cdata-uint64 branch — NOT
-- through `bit.lshift(1, nbits) - 1` which has LuaJIT 32-bit modular
-- semantics for nbits in [32, 63] and silently produces a wrong mask.
-- If a future refactor reintroduces the broken pattern this test fires.
-- ---------------------------------------------------------------------------
print("\n--- G21: FIX-83 source-level regression guard ---")
test("G21: golomb_rice_encode uses cdata-uint64 mask (no bit.lshift(1,nbits)-1)", function()
  local f = io.open("src/blockfilter.lua", "r")
  expect_eq(f ~= nil, true, "open src/blockfilter.lua")
  local src = f:read("*a")
  f:close()
  -- Find the golomb_rice_encode function body
  local start_idx = src:find("local function golomb_rice_encode", 1, true)
  expect_eq(type(start_idx), "number", "golomb_rice_encode function found")
  -- The function ends at "^end$" — find the next function definition
  local end_idx = src:find("\n-- Golomb%-Rice decode", start_idx, false)
  if not end_idx then
    end_idx = src:find("local function golomb_rice_decode", start_idx + 1, true)
  end
  expect_eq(type(end_idx), "number", "golomb_rice_encode body terminated")
  local body = src:sub(start_idx, end_idx)
  -- POSITIVE: the cdata-uint64 all-ones mask must appear in the unary path.
  expect_eq(body:find('ffi%.new%("uint64_t", 0xFFFFFFFFFFFFFFFFULL%)') ~= nil, true,
    "FIX-83 cdata-uint64 unary mask present in golomb_rice_encode")
  -- NEGATIVE: the broken `bit.lshift(1, nbits) - 1` (or equivalent) MUST NOT
  -- appear as a writer argument for the unary path.  We tolerate the
  -- pattern only inside comments or in golomb_rice_decode (which uses
  -- per-bit reads, not masks).
  for line in body:gmatch("[^\n]+") do
    local trimmed = line:gsub("^%s+", "")
    -- skip pure comment lines
    if not trimmed:match("^%-%-") then
      -- forbid the literal broken pattern on a non-comment line
      if line:find("bit%.lshift%(1, nbits%)") and line:find("bitwriter%.write") then
        error("FIX-83 regression: bit.lshift(1, nbits) - 1 used as writer arg: " .. line)
      end
    end
  end
end)

-- ---------------------------------------------------------------------------
-- G22: BUG-2 closure (W121 BUG-8 carryover) — bit_stream_reader.read uses
-- uint64_t cdata accumulator for nbits > 32 so the LuaJIT 32-bit modular
-- semantics on bit.lshift(result, 1) no longer silently truncate.  This
-- guards a future larger-P filter or wide-field consumer.
-- ---------------------------------------------------------------------------
print("\n--- G22: BUG-2 closure (reader cdata path for nbits>32) ---")
test("G22-a: reader.read(33) preserves bit 33 (no 32-bit truncation)", function()
  -- Encode 33 bits where the top bit is 1 and the rest are zero.
  -- Expected: bit_stream_reader.read(33) returns 2^32 = 4294967296.
  -- Pre-fix: returns 0 because bit.lshift wraps mod 2^32.
  local w = blockfilter.bit_stream_writer()
  w.write(1, 1)
  for _ = 1, 32 do w.write(0, 1) end
  w.flush()
  local r = blockfilter.bit_stream_reader(w.result())
  local v = r.read(33)
  expect_eq(v, 4294967296, "33-bit read with top bit set")
end)
test("G22-b: reader.read(40) preserves high bits", function()
  -- Write all 40 ones; expect 2^40 - 1 = 1099511627775.
  local w = blockfilter.bit_stream_writer()
  w.write(ffi.new("uint64_t", 0xFFFFFFFFFFFFFFFFULL), 40)
  w.flush()
  local r = blockfilter.bit_stream_reader(w.result())
  local v = r.read(40)
  expect_eq(v, 1099511627775, "40-bit read of all ones")
end)
test("G22-c: reader.read(<=32) unchanged (safe-zone numeric path)", function()
  -- Regression guard: P=19 BIP-158 callers must not be perturbed.
  local w = blockfilter.bit_stream_writer()
  w.write(0x7FFFF, 19)  -- 19-bit remainder field, all ones
  w.flush()
  local r = blockfilter.bit_stream_reader(w.result())
  local v = r.read(19)
  expect_eq(v, 0x7FFFF, "P=19 remainder read unchanged")
end)

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------

print("\n=========================================================================")
print(string.format("W122 SUMMARY: %d PASS, %d FAIL, %d XFAIL (pre-fix expected)",
  PASS, FAIL, XFAIL_PRE_FIX))
print(string.format("Status: %s",
  FAIL == 0 and (XFAIL_PRE_FIX > 0 and "BUG-1 PRESENT (expected pre-fix)" or "ALL GREEN — BUG-1 FIXED")
  or "UNEXPECTED FAILURES — investigate"))
print("=========================================================================")

-- Record bugs found this wave
bug("BUG-1", "P0-CDIV  golomb_rice_encode unary-mask off for nbits in [32, 63]")
bug("BUG-2", "carryover from W121 BUG-8 — reader bit.lshift mod 2^32")

print("\nBugs found:")
for _, b in ipairs(BUGS) do
  print("  " .. b)
end

-- Exit non-zero only on UNEXPECTED failures.  Expected pre-fix XFAILs do
-- not cause non-zero exit — we treat them as advisory until a fix lands
-- and they flip to PASS.
if FAIL > 0 then os.exit(1) end
