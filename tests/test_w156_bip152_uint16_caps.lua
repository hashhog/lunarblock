#!/usr/bin/env luajit
-- test_w156_bip152_uint16_caps.lua — Phase 3 audit-track closure for
-- W156 BUG-3 (P0-DoS) + BUG-4 (P1) + BUG-10 (P1).
--
-- Reference:
--   CORE-PARITY-AUDIT/_lunarblock-unfreeze-plan-2026-05-26.md  (Phase 3)
--   CORE-PARITY-AUDIT/lunarblock/CORE-PARITY-AUDIT/w156-bip152-cmpctblock-blocktxn.md
--   bitcoin-core/src/blockencodings.h:36-42   (DifferenceFormatter::Unser
--                                              throws on UINT16 overflow)
--   bitcoin-core/src/blockencodings.h:121-130 (CBlockHeaderAndShortTxIDs
--                                              throws on BlockTxCount > 65535)
--
-- W156 BUG-3 (P0-DoS): `deserialize_cmpctblock` had no UINT16 cap on
-- short_id_count or BlockTxCount.  A single 50-byte malicious packet
-- could allocate ~5.6M Lua-table entries (~80–200 MiB transient heap +
-- multi-second CPU) before the post-stream
-- `MAX_CMPCTBLOCK_TX_COUNT=100000` check in compact_block.lua:148 fired.
--
-- W156 BUG-4 (P1): differential prefilled-index decode had no
-- running-sum overflow check; over-large indexes propagated until the
-- post-loop check at compact_block.lua:183 fired AFTER each oversized
-- tx body had been deserialized.
--
-- W156 BUG-10 (P1): same pattern in `deserialize_getblocktxn`; silent
-- over-large indexes caused `blk.transactions[huge + 1]` nil lookups
-- per-index (wasted CPU + no misbehaving).
--
-- This file validates the fix by:
--   (1) Confirming both deserializers error mid-stream on
--       short_id_count > 65535 / count > 65535.
--   (2) Confirming both deserializers error on a combined
--       short_id_count + prefilled_count > 65535.
--   (3) Confirming the differential decoder fires
--       "differential value overflow" the first time the running
--       last_index passes UINT16_MAX, BEFORE deserializing the next tx.
--   (4) Confirming the happy-path round-trip at exact 65535 boundary
--       still works (we haven't broken legitimate cmpctblock relay).
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_w156_bip152_uint16_caps.lua

package.path = "src/?.lua;src/?/init.lua;./?.lua;" .. package.path

local p2p       = require("lunarblock.p2p")
local serialize = require("lunarblock.serialize")
local types     = require("lunarblock.types")

-- A minimum-shape NON-SEGWIT tx (61 bytes) that survives
-- deserialize_transaction.  Used to fill out cmpctblock prefilled-txn
-- bodies in cases where we want the bug-3 cap check to fire BEFORE the
-- next tx body would be deserialized.
local function min_tx_bytes()
  local tx = {
    version = 1,
    inputs = {types.txin(types.outpoint(types.hash256_zero(), 0xffffffff),
                         "\x00", 0xffffffff)},
    outputs = {types.txout(0, "")},
    locktime = 0,
  }
  return serialize.serialize_transaction(tx, false)
end

-- Tiny harness ----------------------------------------------------------
local PASS, FAIL = 0, 0
local function pass(name) io.write(string.format("  PASS  %s\n", name)); PASS = PASS + 1 end
local function fail(name, msg) io.write(string.format("  FAIL  %s -- %s\n", name, msg)); FAIL = FAIL + 1 end
local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end
local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) ..
          ", expected " .. tostring(b), 2)
  end
end
local function expect_error(fn, pat, msg)
  local ok, err = pcall(fn)
  if ok then error((msg or "expected error") .. " (got success)", 2) end
  if pat and not tostring(err):find(pat) then
    error((msg or "wrong error") ..
          " — wanted /" .. pat .. "/, got: " .. tostring(err), 2)
  end
end

-- Wire helpers ----------------------------------------------------------

-- A canonical 80-byte zero block header bytes.
local function zero_header_bytes()
  return string.rep("\x00", 80)
end

-- Encode a varint exactly the way Core ReadCompactSize parses
-- (matches src/serialize.lua read_varint).
local function write_varint(w, n)
  w.write_varint(n)
end

local function build_cmpctblock_bytes(short_id_count, prefilled_count, prefilled_indexes)
  -- Produces a wire payload whose declared counts are as specified but
  -- without actually writing the (potentially huge) bodies.  Used to
  -- exercise the cap check BEFORE allocation.
  --
  -- For honest happy-path cases, callers pass small counts and full
  -- short_id bytes plus prefilled tx bodies.
  local w = serialize.buffer_writer()
  w.write_bytes(zero_header_bytes())
  w.write_u64le(0)
  write_varint(w, short_id_count)
  -- write `short_id_count` 6-byte zero short_ids
  local six_zeros = string.rep("\x00", 6)
  for _ = 1, short_id_count do
    w.write_bytes(six_zeros)
  end
  write_varint(w, prefilled_count)
  if prefilled_indexes then
    -- Encode each prefilled diff index; this caller knows what they want
    -- to encode (used only by overflow tests, never with real tx bodies).
    for _, diff in ipairs(prefilled_indexes) do
      write_varint(w, diff)
      -- Write a minimum-size tx body that deserialize_transaction
      -- accepts so we can probe what happens AFTER the index check.
      -- We never actually want to *reach* here in the overflow tests,
      -- so use a deliberately-invalid stub byte (which would error
      -- *if reached*).
      w.write_bytes("\x00")
    end
  end
  return w.result()
end

-- A header-only cmpctblock declaring a huge short_id_count without
-- following through with the (impossible) body.  read_varint itself
-- gates at MAX_SIZE = 0x02000000 so the largest declarable value is
-- 33554432.  Used to confirm the cap check fires BEFORE the read loop
-- runs (so the test runs in O(1) time, not O(N)).
local function declare_huge_short_id_count(n)
  local w = serialize.buffer_writer()
  w.write_bytes(zero_header_bytes())
  w.write_u64le(0)
  w.write_varint(n)
  return w.result()
end

local function declare_combined_count(short_id_count, prefilled_count)
  local w = serialize.buffer_writer()
  w.write_bytes(zero_header_bytes())
  w.write_u64le(0)
  w.write_varint(short_id_count)
  -- Provide the short_id bytes so we get past the inner loop and
  -- actually reach the prefilled_count read.
  local six_zeros = string.rep("\x00", 6)
  for _ = 1, short_id_count do w.write_bytes(six_zeros) end
  w.write_varint(prefilled_count)
  return w.result()
end

print("\n=========================================================================")
print("W156 BIP-152 uint16 cap regression — lunarblock")
print("Source: src/p2p.lua  deserialize_cmpctblock / deserialize_getblocktxn")
print("Reference: bitcoin-core/src/blockencodings.h:36-42, 121-130")
print("=========================================================================")

-- --- cmpctblock: cap (1) short_id_count alone ---
print("\n--- cmpctblock cap (1): short_id_count > 65535 ---")

test("cmpctblock rejects short_id_count = 65536 (UINT16_MAX + 1)",
  function()
    local data = declare_huge_short_id_count(65536)
    expect_error(function() p2p.deserialize_cmpctblock(data) end,
                 "indexes overflowed 16 bits",
                 "expected throw at short_id_count = 65536")
  end)

test("cmpctblock rejects short_id_count = MAX_SIZE",
  function()
    -- MAX_SIZE = 0x02000000 = 33554432
    local data = declare_huge_short_id_count(0x02000000)
    expect_error(function() p2p.deserialize_cmpctblock(data) end,
                 "indexes overflowed 16 bits",
                 "expected throw at short_id_count = MAX_SIZE")
  end)

-- --- cmpctblock: cap (2) combined sum > 65535 ---
print("\n--- cmpctblock cap (2): short_id_count + prefilled_count > 65535 ---")

test("cmpctblock rejects short_ids=65535 + prefilled=1 = 65536",
  function()
    -- This test ACTUALLY writes 65535 short_ids bytes (393210 bytes) to
    -- exercise that the cap fires AFTER the short_ids read but BEFORE
    -- the prefilled differential decode would allocate any tx body.
    local data = declare_combined_count(65535, 1)
    expect_error(function() p2p.deserialize_cmpctblock(data) end,
                 "indexes overflowed 16 bits",
                 "expected throw at combined = 65536")
  end)

test("cmpctblock rejects short_ids=40000 + prefilled=40000",
  function()
    local data = declare_combined_count(40000, 40000)
    expect_error(function() p2p.deserialize_cmpctblock(data) end,
                 "indexes overflowed 16 bits",
                 "expected throw at combined = 80000")
  end)

-- --- cmpctblock: cap (3) running differential overflow ---
print("\n--- cmpctblock cap (3): differential overflow in prefilled loop ---")

test("cmpctblock rejects prefilled diff that pushes index above 65535",
  function()
    -- Two prefilled txns: first with diff=65530 → index=65530, second
    -- with diff=10 → index=65541 (>65535). Should fail BEFORE the
    -- 2nd tx body is deserialized.  Note we don't bother writing tx
    -- bodies — the differential overflow check fires first.
    local w = serialize.buffer_writer()
    w.write_bytes(zero_header_bytes())
    w.write_u64le(0)
    w.write_varint(0)            -- 0 short_ids
    w.write_varint(2)            -- 2 prefilled
    w.write_varint(65530)        -- diff=65530 → index=65530 (OK)
    -- Emit a real minimum-shape tx so the first iteration completes;
    -- the second iteration's overflow check then fires BEFORE we
    -- spend cycles deserializing the (absent) next body.
    w.write_bytes(min_tx_bytes())
    w.write_varint(10)           -- diff=10 → index=65541 (OVERFLOW)
    -- No need for a 2nd tx body — the overflow check fires first.
    local data = w.result()
    expect_error(function() p2p.deserialize_cmpctblock(data) end,
                 "differential value overflow",
                 "expected differential-overflow throw")
  end)

test("cmpctblock rejects diff that immediately overflows 65535",
  function()
    -- Single prefilled with diff=65536 → index=65536 (just over UINT16).
    local w = serialize.buffer_writer()
    w.write_bytes(zero_header_bytes())
    w.write_u64le(0)
    w.write_varint(0)
    w.write_varint(1)
    w.write_varint(65536)        -- diff alone exceeds the limit
    local data = w.result()
    expect_error(function() p2p.deserialize_cmpctblock(data) end,
                 "differential value overflow",
                 "expected differential-overflow throw")
  end)

-- --- cmpctblock: happy-path boundary ---
print("\n--- cmpctblock boundary: exact 65535 still accepted ---")

test("cmpctblock accepts short_ids=65535 + prefilled=0 = 65535",
  function()
    -- This exercises 65535 * 6 = 393_210 bytes of short_id payload —
    -- well within Lua heap budget.  Should succeed.
    local data = declare_combined_count(65535, 0)
    local cb = p2p.deserialize_cmpctblock(data)
    expect_eq(#cb.short_ids, 65535, "65535 short_ids deserialized")
    expect_eq(#cb.prefilled_txns, 0, "0 prefilled_txns deserialized")
  end)

test("cmpctblock accepts single prefilled at exactly index 65535",
  function()
    local w = serialize.buffer_writer()
    w.write_bytes(zero_header_bytes())
    w.write_u64le(0)
    w.write_varint(0)
    w.write_varint(1)
    w.write_varint(65535)        -- diff=65535 → index=65535 (boundary)
    w.write_bytes(min_tx_bytes()) -- min-shape tx body
    local data = w.result()
    local cb = p2p.deserialize_cmpctblock(data)
    expect_eq(#cb.prefilled_txns, 1, "1 prefilled_txn deserialized")
    expect_eq(cb.prefilled_txns[1].index, 65535, "index at boundary")
  end)

-- --- getblocktxn: count cap ---
print("\n--- getblocktxn cap: count > 65535 ---")

test("getblocktxn rejects count = 65536",
  function()
    local w = serialize.buffer_writer()
    w.write_hash256(types.hash256_zero())
    w.write_varint(65536)
    local data = w.result()
    expect_error(function() p2p.deserialize_getblocktxn(data) end,
                 "indexes overflowed 16 bits",
                 "expected throw at count = 65536")
  end)

test("getblocktxn rejects count = MAX_SIZE",
  function()
    local w = serialize.buffer_writer()
    w.write_hash256(types.hash256_zero())
    w.write_varint(0x02000000)
    local data = w.result()
    expect_error(function() p2p.deserialize_getblocktxn(data) end,
                 "indexes overflowed 16 bits",
                 "expected throw at count = MAX_SIZE")
  end)

-- --- getblocktxn: differential overflow ---
print("\n--- getblocktxn differential overflow ---")

test("getblocktxn rejects diff pushing index above 65535",
  function()
    local w = serialize.buffer_writer()
    w.write_hash256(types.hash256_zero())
    w.write_varint(2)
    w.write_varint(65530)        -- diff=65530 → index=65530 (OK)
    w.write_varint(10)           -- diff=10   → index=65541 (OVERFLOW)
    local data = w.result()
    expect_error(function() p2p.deserialize_getblocktxn(data) end,
                 "differential value overflow",
                 "expected differential-overflow throw")
  end)

test("getblocktxn rejects single diff > 65535",
  function()
    local w = serialize.buffer_writer()
    w.write_hash256(types.hash256_zero())
    w.write_varint(1)
    w.write_varint(65536)
    local data = w.result()
    expect_error(function() p2p.deserialize_getblocktxn(data) end,
                 "differential value overflow",
                 "expected differential-overflow throw")
  end)

-- --- getblocktxn happy path ---
print("\n--- getblocktxn boundary: exact 65535 still accepted ---")

test("getblocktxn accepts single index = 65535",
  function()
    local w = serialize.buffer_writer()
    w.write_hash256(types.hash256_zero())
    w.write_varint(1)
    w.write_varint(65535)
    local data = w.result()
    local req = p2p.deserialize_getblocktxn(data)
    expect_eq(#req.indexes, 1, "1 index deserialized")
    expect_eq(req.indexes[1], 65535, "boundary index")
  end)

test("getblocktxn round-trips a typical request",
  function()
    local indexes = {0, 1, 5, 10, 11}
    local payload = p2p.serialize_getblocktxn(types.hash256_zero(), indexes)
    local parsed = p2p.deserialize_getblocktxn(payload)
    expect_eq(#parsed.indexes, #indexes, "index count")
    for i, idx in ipairs(indexes) do
      expect_eq(parsed.indexes[i], idx, "index " .. i)
    end
  end)

-- --- Constant exposed ---
print("\n--- exported constant ---")

test("CMPCTBLOCK_MAX_TX_COUNT == 0xFFFF",
  function()
    expect_eq(p2p.CMPCTBLOCK_MAX_TX_COUNT, 0xFFFF, "uint16 cap constant")
  end)

-- ---------------------------------------------------------------------------

print("\n=========================================================================")
print(string.format("W156 BIP-152 uint16 cap regression: %d PASS / %d FAIL", PASS, FAIL))
print("=========================================================================")

os.exit(FAIL == 0 and 0 or 1)
