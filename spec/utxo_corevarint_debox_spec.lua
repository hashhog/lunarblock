-- spec/utxo_corevarint_debox_spec.lua
--
-- CONSENSUS GATE for the AssumeUTXO snapshot-loader perf fix
-- (_lunarblock-loader-perf-2026-06-02.md, Fix B: "de-box the varint / amount
-- decoders"). The fix rewrites the hot snapshot-decode path
--   M.read_corevarint  (Core ReadVarInt, MSB base-128)
--   M.decompress_amount (compressor.cpp DecompressAmount)
-- from boxed-uint64 (LuaJIT FFI cdata) arithmetic to plain-Lua-number
-- arithmetic, which is bit-for-bit exact for every value < 2^53 — i.e. ALL
-- legitimate snapshot fields (heights, vouts, compressed amounts <= MAX_MONEY
-- = 2.1e15 < 2^53). Out-of-domain (> 2^53) inputs fall back to an exact cdata
-- tail so NOTHING about the decoded value or the overflow-guard accept/reject
-- decision can drift.
--
-- This spec PROVES the rewrite is decision- and byte-IDENTICAL to the prior
-- all-cdata implementation. The "expected" values below were captured by
-- running the ORIGINAL boxed-uint64 decoders verbatim (pre-fix HEAD) over the
-- same byte vectors; they are hard-coded here so the gate stands on its own
-- without needing the pre-fix source checked out.
--
-- Reference:
--   bitcoin-core/src/serialize.h     (ReadVarInt, "size too large" guard:
--                                     n > (numeric_limits<I>::max() >> 7))
--   bitcoin-core/src/compressor.h    (DecompressAmount)
--
-- Two properties asserted:
--   (1) BYTE-IDENTICAL VALUE: every (bytes -> value) pair decodes to exactly
--       the value the old cdata path produced, across small / mid / near-2^53
--       / and out-of-domain (> 2^53, exact-tail) ranges.
--   (2) GUARD DECISION PRESERVED: every malformed / overflow byte stream that
--       the old path REJECTED ("size too large" / over-long / truncated /
--       empty) is still rejected, and every stream it ACCEPTED is still
--       accepted. No accept<->reject flip.

local serialize = require("lunarblock.serialize")
local utxo      = require("lunarblock.utxo")
local ffi       = require("ffi")

-- Decode a Core VARINT from a raw byte string. read_corevarint returns a Lua
-- number on the in-domain fast path (value < 2^53, where %.0f is exact); we
-- normalize via tonumber() for those rows. For the out-of-domain exact-tail
-- rows (value > 2^53) we compare the RAW return (a uint64_t cdata) via
-- tostring(), which is bit-exact — tonumber() would lose the low bits and so
-- could not prove byte-identity at that magnitude.
local function rv_num(bytes)
  local r = serialize.buffer_reader(bytes)
  return tonumber(utxo.read_corevarint(r))
end

-- Exact (lossless) decimal rendering of the raw return value, whether it is a
-- Lua number (< 2^53) or a uint64_t cdata (exact tail). For cdata, tostring()
-- yields the precise integer with a "ULL" suffix we strip; for a number,
-- %.0f is exact below 2^53.
local function rv_exact(bytes)
  local r = serialize.buffer_reader(bytes)
  local v = utxo.read_corevarint(r)
  if type(v) == "cdata" then
    return (tostring(v):gsub("ULL$", ""))
  end
  return string.format("%.0f", v)
end

-- Format an in-domain number with no exponent / fractional part.
local function fmt(v)
  return string.format("%.0f", v)
end

local function bytes_of(...)
  local t = { ... }
  local o = {}
  for i = 1, #t do o[i] = string.char(t[i]) end
  return table.concat(o)
end

describe("AssumeUTXO decoder de-box — byte-identical to old cdata path", function()

  -----------------------------------------------------------------------------
  -- (1) read_corevarint: byte-identical VALUE across the full range.
  --     Each row is { hex-byte-string, expected-decoded-value-as-%.0f-string }.
  --     Expected values captured from the ORIGINAL boxed-uint64 decoder.
  -----------------------------------------------------------------------------
  describe("read_corevarint value parity (captured from old cdata path)", function()
    -- in-domain (< 2^53): legitimate snapshot fields
    local in_domain = {
      { bytes_of(0x00),                                           "0" },
      { bytes_of(0x01),                                           "1" },
      { bytes_of(0x02),                                           "2" },
      { bytes_of(0x7F),                                           "127" },
      { bytes_of(0x80, 0x00),                                     "128" },
      { bytes_of(0x80, 0x01),                                     "129" },
      { bytes_of(0x80, 0x7F),                                     "255" },
      { bytes_of(0x81, 0x00),                                     "256" },
      { bytes_of(0xFE, 0x7F),                                     "16383" },
      { bytes_of(0xFF, 0x00),                                     "16384" },
      { bytes_of(0x82, 0xFE, 0x7F),                               "65535" },
      { bytes_of(0x82, 0xFF, 0x00),                               "65536" },
      { bytes_of(0xBC, 0x83, 0x40),                               "1000000" },
      -- ~MAX_MONEY (2,099,999,997,690,000) — the largest legit amount field
      { bytes_of(0x82, 0xDC, 0xBD, 0x84, 0xCE, 0x8F, 0x80, 0x10), "2099999997690000" },
      -- 2^52 - 1
      { bytes_of(0x86, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0x7F), "4503599627370495" },
      -- 2^52
      { bytes_of(0x86, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFF, 0x00), "4503599627370496" },
      -- 2^53 - 1  (largest exact double; upper edge of the in-domain range)
      { bytes_of(0x8E, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0x7F), "9007199254740991" },
    }
    for _, row in ipairs(in_domain) do
      local hex = row[1]:gsub(".", function(c) return string.format("%02x", c:byte()) end)
      it("decodes " .. hex .. " -> " .. row[2], function()
        assert.equal(row[2], fmt(rv_num(row[1])))
      end)
    end

    -- out-of-domain (> 2^53): exercises the exact cdata tail. These values are
    -- impossible for any real snapshot field and are rejected downstream by the
    -- per-coin height / MoneyRange / script-size guards; we assert them only to
    -- prove the decoder itself stays byte-identical with the old cdata path
    -- (so the exact tail can never silently change a value the old code saw).
    -- Expected values captured BIT-EXACT from the original all-cdata decoder
    -- via tostring() (NOT tonumber(), which is lossy at this magnitude).
    local out_of_domain = {
      -- ffffffffffffffff7f -> 9295997013522923647 (exact uint64; note tonumber
      -- of this cdata rounds to ...520, hence we compare exact strings)
      { bytes_of(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F), "9295997013522923647" },
      -- 80fefefefefefefe7f -> 2^57 - 1 = 144115188075855871 (a NAIVE double
      -- would give ...872; the exact cdata tail reproduces ...871 exactly)
      { bytes_of(0x80, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0x7F), "144115188075855871" },
      -- 80fefefefefefeff00 -> 2^57 = 144115188075855872
      { bytes_of(0x80, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFF, 0x00), "144115188075855872" },
      -- 80fefefefefefefefe7f -> 2^64 - 1 = 18446744073709551615 (max uint64;
      -- a naive double would give ...616 — the exact tail keeps ...615)
      { bytes_of(0x80, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0x7F), "18446744073709551615" },
    }
    for _, row in ipairs(out_of_domain) do
      local hex = row[1]:gsub(".", function(c) return string.format("%02x", c:byte()) end)
      it("exact-tail decodes " .. hex .. " -> " .. row[2], function()
        assert.equal(row[2], rv_exact(row[1]))
      end)
    end
  end)

  -----------------------------------------------------------------------------
  -- (2) read_corevarint: overflow / malformed guard DECISION preserved.
  --     The old cdata path's accept/reject for each stream is hard-coded.
  -----------------------------------------------------------------------------
  describe("read_corevarint guard decision parity (captured from old cdata path)", function()
    -- ACCEPTED by the old path (decode succeeds):
    local accepted = {
      { name = "9 bytes terminating below guard (8xFF+7F)",
        bytes = bytes_of(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F) },
      { name = "2^57-1 encoding (80fe..7f)",
        bytes = bytes_of(0x80, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0x7F) },
      { name = "2^64-1 encoding (80fe..fe7f)",
        bytes = bytes_of(0x80, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0x7F) },
    }
    for _, c in ipairs(accepted) do
      it("ACCEPTS " .. c.name, function()
        assert.has_no.errors(function() rv_num(c.bytes) end)
      end)
    end

    -- REJECTED by the old path (decode errors). All three failure modes:
    --   "size too large"   (accumulator exceeds UINT64_MAX >> 7)
    --   "encoded length exceeds uint64 range" (guard > 18 iterations)
    --   EOF / truncated     (stream ends mid-varint)
    local rejected = {
      { name = "9xFF + 0x00 (size too large at guard check)",
        bytes = bytes_of(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00) },
      { name = "10xFF + 0x00 (size too large)",
        bytes = bytes_of(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00) },
      { name = "9xFF + 0x7F (size too large)",
        bytes = bytes_of(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F) },
      -- the precision-trap streams: an exact uint64 accumulator crosses the
      -- 2^57-1 guard, but a NAIVE double would under-count and wrongly accept.
      -- The exact tail must REJECT these, matching the old cdata path.
      { name = "80fe..feff00 precision-trap (must stay rejected)",
        bytes = bytes_of(0x80, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFF, 0x00) },
      { name = "80fe..feff7f precision-trap (must stay rejected)",
        bytes = bytes_of(0x80, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFF, 0x7F) },
      { name = "19x0x80 over-long (guard > 18)",
        bytes = string.rep(string.char(0x80), 19) },
      { name = "18xFF + 0x00 over-long (guard > 18)",
        bytes = string.rep(string.char(0xFF), 18) .. string.char(0x00) },
      { name = "truncated 0x80 0x80 (EOF)",
        bytes = bytes_of(0x80, 0x80) },
      { name = "empty stream (EOF)",
        bytes = "" },
    }
    for _, c in ipairs(rejected) do
      it("REJECTS " .. c.name, function()
        assert.has_error(function() rv_num(c.bytes) end)
      end)
    end
  end)

  -----------------------------------------------------------------------------
  -- (3) decompress_amount: byte-identical to the old cdata path.
  --     Direct (compressed -> satoshi) vectors captured from the old decoder.
  -----------------------------------------------------------------------------
  describe("decompress_amount value parity (captured from old cdata path)", function()
    -- { compressed-input, expected-satoshi-as-%.0f }
    local vectors = {
      { 0,          "0" },
      { 1,          "1" },
      { 2,          "10" },
      { 3,          "100" },
      { 9,          "100000000" },
      { 10,         "1000000000" },
      { 11,         "2" },
      { 100,        "10000000000" },
      { 1000,       "100000000000" },
      { 1000000000, "100000000000000000" },
    }
    for _, row in ipairs(vectors) do
      it("decompress_amount(" .. row[1] .. ") -> " .. row[2], function()
        assert.equal(row[2], fmt(utxo.decompress_amount(row[1])))
      end)
    end

    -- accepts a uint64_t cdata input too (the read_corevarint exact tail) and
    -- still matches the old cdata path byte-for-byte.
    it("decompress_amount(cdata 1889999997925) -> 2099999997690000", function()
      local cd = ffi.cast("uint64_t", 1889999997925LL)
      assert.equal("2099999997690000", fmt(utxo.decompress_amount(cd)))
    end)
  end)

  -----------------------------------------------------------------------------
  -- (4) End-to-end round trip: compress_amount(a) -> decompress_amount == a,
  --     across every amount class (dust, subsidy, MAX_MONEY).
  -----------------------------------------------------------------------------
  describe("compress->decompress amount round trip", function()
    local amounts = { 0, 1, 2, 3, 546, 1000, 100000000, 5000000000, 2099999997690000 }
    for _, a in ipairs(amounts) do
      it("round-trips " .. fmt(a) .. " satoshis", function()
        local c = utxo.compress_amount(a)
        assert.equal(fmt(a), fmt(utxo.decompress_amount(c)))
      end)
    end
  end)

  -----------------------------------------------------------------------------
  -- (5) Full snapshot-coin round trip through the rewritten decode path:
  --     serialize_snapshot_coin -> deserialize_snapshot_coin recovers the coin.
  --     Exercises read_corevarint + decompress_amount on the actual hot path.
  -----------------------------------------------------------------------------
  describe("snapshot coin round trip (decode hot path)", function()
    local coins = {
      { value = 5000000000,       height = 1,       coinbase = true },
      { value = 546,              height = 200000,  coinbase = false },
      { value = 2099999997690000, height = 840000,  coinbase = false },
      { value = 1,                height = 0,        coinbase = false },
    }
    for i, c in ipairs(coins) do
      it("round-trips coin #" .. i, function()
        -- P2PKH-ish 25-byte scriptPubKey
        local spk = string.char(0x76, 0xA9, 0x14) .. string.rep("\x11", 20)
                    .. string.char(0x88, 0xAC)
        local entry = utxo.utxo_entry(c.value, spk, c.height, c.coinbase)
        local enc = utxo.serialize_snapshot_coin(entry)
        local r = serialize.buffer_reader(enc)
        local back = utxo.deserialize_snapshot_coin(r)
        assert.equal(fmt(c.value), fmt(back.value))
        assert.equal(c.height, back.height)
        assert.equal(c.coinbase, back.is_coinbase)
        assert.equal(spk, back.script_pubkey)
      end)
    end
  end)
end)
