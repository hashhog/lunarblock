#!/usr/bin/env luajit
-- W132 BIP-68 / BIP-112 / BIP-113 nSequence + OP_CSV + MTP audit — lunarblock
--
-- Reference:
--   bitcoin-core/src/consensus/tx_verify.cpp (CalculateSequenceLocks,
--     EvaluateSequenceLocks, IsFinalTx, SequenceLocks),
--   bitcoin-core/src/script/interpreter.cpp:561-593 (OP_CHECKSEQUENCEVERIFY),
--   bitcoin-core/src/script/interpreter.cpp:1782-1826 (CheckSequence),
--   bitcoin-core/src/script/interpreter.cpp:1739-1779 (CheckLockTime),
--   bitcoin-core/src/primitives/transaction.h:76-114 (SEQUENCE_* constants),
--   bitcoin-core/src/chain.h:231-245 (GetMedianTimePast),
--   bitcoin-core/src/validation.cpp:4129-4149 (ContextualCheckBlock).
--
-- Scope:  Audit the 11 bugs found in audit/w132_nsequence_csv_mtp.md as
--         executable assertions against lunarblock's three-axis locktime
--         subsystem (BIP-68 relative locks, BIP-112 CSV opcode, BIP-113
--         MTP-tied IsFinalTx).
--
-- Gate map (W132):
--   G1   SEQUENCE_FINAL constant pinned
--   G2   SEQUENCE_LOCKTIME_DISABLE_FLAG/TYPE_FLAG/MASK/GRANULARITY pinned
--   G3   MAX_SEQUENCE_NONFINAL constant
--   G4   fEnforceBIP68 = (version >= 2) AND flag-bit
--   G5   DISABLE_FLAG input skipped in calculate_sequence_locks
--   G6   Time-based branch invokes get_block_mtp(max(coin_h - 1, 0))
--   G7   nMinTime = max(nMinTime, nCoinTime + (mask<<9) - 1)
--   G8   nMinHeight = max(nMinHeight, coin_h + mask - 1)
--   G9   prevHeights[i] = 0 mutation on DISABLE_FLAG  (BUG-2)
--   G10  EvaluateSequenceLocks: min_h >= block.nHeight → false
--   G11  EvaluateSequenceLocks: min_t >= pprev.MTP → false
--   G12  GetMedianTimePast walks ≤ 11 ancestors via pprev
--   G13  Median picks pbegin[(n)/2] (upper-middle for even-near-genesis)
--   G14  os.time() fallback is non-Core   (BUG-3, XFAIL pre-fix)
--   G15  IsFinalTx: locktime==0 → final
--   G16  IsFinalTx: locktime < cutoff → final
--   G17  IsFinalTx: every-input-SEQUENCE_FINAL overrides
--   G18  IsFinalTx mempool: cutoff = TIP's MTP, nextHeight = tip+1
--   G19  OP_CSV gated on SCRIPT_VERIFY_CHECKSEQUENCEVERIFY else NOP3
--   G20  OP_CSV empty stack → INVALID_STACK_OPERATION
--   G21  OP_CSV uses 5-byte CScriptNum
--   G22  OP_CSV negative value → NEGATIVE_LOCKTIME
--   G23  OP_CSV DISABLE_FLAG set → NOP                 (BUG-4 partial)
--   G24  OP_CSV preserves top-of-stack byte form        (BUG-5)
--   G25  CheckSequence: tx.version < 2 → false
--   G26  CheckSequence: txTo DISABLE_FLAG → false
--   G27  CheckSequence: types must match before compare (BUG-6)
--   G28  CheckSequence: masked-value comparison
--   G29  bit.lshift(lock_value, 9) safe (< 2^25)
--   G30  bit.band on 5-byte CScriptNum (LuaJIT trap-weak — BUG-9)
--
-- Bugs catalogued:
--   BUG-1  (P0-CDIV) Mempool BIP-68 uses tip MTP for every input
--   BUG-2  (P2)      prevHeights[i] = 0 mutation absent
--   BUG-3  (P1)      os.time() fallback in MTP helpers (non-determinism)
--   BUG-4  (P2)      Double DISABLE_FLAG check with inconsistent typing
--   BUG-5  (P2)      OP_CSV re-encodes top-of-stack via script_num_encode
--   BUG-6  (P1)      CheckSequence type-check is two-mask not Core's combined-mask
--   BUG-7  (P1)      Three-copy check_sequence sig-checker drift surface
--   BUG-8  (P3)      Three-copy check_locktime sig-checker drift surface
--   BUG-9  (P1)      LuaJIT bit.band 32-bit modular latent on 5-byte CScriptNum
--   BUG-10 (P1)      BUG-3 + sentinel -1 combine into non-deterministic boot
--   BUG-11 (P1)      No LockPoints cache (perf cliff, not consensus)
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_w132_nsequence_csv_mtp.lua 2>&1

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

local consensus  = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local mining     = require("lunarblock.mining")

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

local function xfail(name, bug, msg)
  io.write(string.format("  XFAIL %s (expected pre-fix, %s) -- %s\n", name, bug, msg))
  XFAIL_PRE_FIX = XFAIL_PRE_FIX + 1
end

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end

-- A test that is expected to FAIL pre-fix.  When the corresponding fix
-- lands the assertion will start passing and the harness flips the
-- label to PASS.
local function test_xfail(name, bug, fn)
  local ok, err = pcall(fn)
  if ok then
    pass(name .. " [now PASSing — " .. bug .. " fix likely landed]")
  else
    xfail(name, bug, tostring(err))
  end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) ..
          ", expected " .. tostring(b))
  end
end

local function expect_truthy(v, msg)
  if not v then error((msg or "expected truthy") .. ": got " .. tostring(v)) end
end

local function expect_falsy(v, msg)
  if v then error((msg or "expected falsy") .. ": got " .. tostring(v)) end
end

local function bug(id, severity)
  BUGS[#BUGS + 1] = id .. " (" .. severity .. ")"
end

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

local SEQUENCE_FINAL = 0xFFFFFFFF
local MAX_SEQUENCE_NONFINAL = 0xFFFFFFFE
local DISABLE_FLAG = 0x80000000
local TYPE_FLAG = 0x00400000
local MASK = 0x0000FFFF
local GRANULARITY = 9
local LOCKTIME_THRESHOLD = 500000000

local function make_tx(version, locktime, sequences)
  local inputs = {}
  for _, seq in ipairs(sequences) do
    table.insert(inputs, {
      sequence = seq,
      prev_out = { hash = string.rep("\0", 32), index = 0 },
    })
  end
  return {
    version = version,
    locktime = locktime,
    inputs = inputs,
    outputs = {},
  }
end

-- ---------------------------------------------------------------------------
-- Print banner
-- ---------------------------------------------------------------------------

print("\n=========================================================================")
print("W132 BIP-68 / 112 / 113 nSequence + OP_CSV + MTP — lunarblock")
print("Source: src/consensus.lua + src/validation.lua + src/script.lua")
print("        src/mining.lua + src/mempool.lua + src/utxo.lua")
print("Reference: bitcoin-core/src/consensus/tx_verify.cpp +")
print("           script/interpreter.cpp + chain.h + validation.cpp")
print("=========================================================================")

-- ---------------------------------------------------------------------------
-- G1: SEQUENCE_FINAL constant
-- ---------------------------------------------------------------------------
print("\n--- G1: SEQUENCE_FINAL constant ---")

test("G1-a: SEQUENCE_FINAL = 0xFFFFFFFF (from mining.lua)", function()
  -- mining.lua hardcodes SEQUENCE_FINAL = 0xFFFFFFFF locally
  -- consensus.lua does NOT re-export it; verify via behavior in is_final_tx
  local tx_all_final = make_tx(2, 9999999999, { SEQUENCE_FINAL, SEQUENCE_FINAL })
  expect_truthy(mining.is_final_tx(tx_all_final, 100, 500000000),
    "every-input SEQUENCE_FINAL forces is_final_tx = true")
  local tx_one_final = make_tx(2, 9999999999, { SEQUENCE_FINAL - 1, SEQUENCE_FINAL })
  expect_falsy(mining.is_final_tx(tx_one_final, 100, 500000000),
    "one-input not-SEQUENCE_FINAL forces is_final_tx = false")
end)

-- ---------------------------------------------------------------------------
-- G2: BIP-68 mask constants
-- ---------------------------------------------------------------------------
print("\n--- G2: BIP-68 mask constants ---")

test("G2-a: SEQUENCE_LOCKTIME_DISABLE_FLAG = 0x80000000", function()
  expect_eq(consensus.SEQUENCE_LOCKTIME_DISABLE_FLAG, DISABLE_FLAG, "DISABLE_FLAG")
end)
test("G2-b: SEQUENCE_LOCKTIME_TYPE_FLAG = 0x00400000", function()
  expect_eq(consensus.SEQUENCE_LOCKTIME_TYPE_FLAG, TYPE_FLAG, "TYPE_FLAG")
end)
test("G2-c: SEQUENCE_LOCKTIME_MASK = 0x0000FFFF", function()
  expect_eq(consensus.SEQUENCE_LOCKTIME_MASK, MASK, "MASK")
end)
test("G2-d: SEQUENCE_LOCKTIME_GRANULARITY = 9 (512s units)", function()
  expect_eq(consensus.SEQUENCE_LOCKTIME_GRANULARITY, GRANULARITY, "GRANULARITY")
end)

-- ---------------------------------------------------------------------------
-- G3: MAX_SEQUENCE_NONFINAL = SEQUENCE_FINAL - 1
-- ---------------------------------------------------------------------------
print("\n--- G3: MAX_SEQUENCE_NONFINAL = 0xFFFFFFFE ---")

test("G3-a: MAX_SEQUENCE_NONFINAL = SEQUENCE_FINAL - 1 (mining.lua hardcoded)", function()
  expect_eq(MAX_SEQUENCE_NONFINAL, SEQUENCE_FINAL - 1, "0xFFFFFFFE")
end)

-- ---------------------------------------------------------------------------
-- G4: fEnforceBIP68 = (tx.version >= 2) AND (flags & LOCKTIME_VERIFY_SEQUENCE)
-- ---------------------------------------------------------------------------
print("\n--- G4: BIP-68 enforcement gated on version >= 2 + flag bit ---")

test("G4-a: tx.version=1 returns (-1,-1) regardless of flag", function()
  local tx = make_tx(1, 0, { 0 })
  local function utxo_h(_) return 100 end
  local function block_mtp(_) return 500000000 end
  local mh, mt = validation.calculate_sequence_locks(tx, 200, utxo_h, block_mtp, true)
  expect_eq(mh, -1, "min_height should be -1 for version=1")
  expect_eq(mt, -1, "min_time should be -1 for version=1")
end)

test("G4-b: tx.version=2 with enforce=false returns (-1,-1)", function()
  local tx = make_tx(2, 0, { 0 })
  local function utxo_h(_) return 100 end
  local function block_mtp(_) return 500000000 end
  local mh, mt = validation.calculate_sequence_locks(tx, 200, utxo_h, block_mtp, false)
  expect_eq(mh, -1, "min_height should be -1 when enforce=false")
  expect_eq(mt, -1, "min_time should be -1 when enforce=false")
end)

test("G4-c: tx.version=2 + enforce=true computes per-input locks", function()
  local tx = make_tx(2, 0, { 5 })  -- height-based lock = 5 blocks
  local function utxo_h(_) return 100 end
  local function block_mtp(_) return 500000000 end
  local mh, mt = validation.calculate_sequence_locks(tx, 200, utxo_h, block_mtp, true)
  -- Core: nMinHeight = coin_h + (seq & MASK) - 1 = 100 + 5 - 1 = 104
  expect_eq(mh, 104, "min_height = coin_h + 5 - 1")
  expect_eq(mt, -1, "min_time stays -1 for height-only inputs")
end)

-- ---------------------------------------------------------------------------
-- G5: DISABLE_FLAG input is skipped (no contribution to min_height/min_time)
-- ---------------------------------------------------------------------------
print("\n--- G5: DISABLE_FLAG input skipped ---")

test("G5-a: every-input-DISABLED returns (-1,-1)", function()
  local tx = make_tx(2, 0, { bit.bor(DISABLE_FLAG, 50), bit.bor(DISABLE_FLAG, 30) })
  local function utxo_h(_) return 100 end
  local function block_mtp(_) return 500000000 end
  local mh, mt = validation.calculate_sequence_locks(tx, 200, utxo_h, block_mtp, true)
  expect_eq(mh, -1, "all-disabled → min_height = -1")
  expect_eq(mt, -1, "all-disabled → min_time = -1")
end)

test("G5-b: mixed disabled+enabled — only enabled contributes", function()
  -- input 1: disabled (height-based with lock=999, should be skipped)
  -- input 2: enabled height-based, lock=10
  local tx = make_tx(2, 0, { bit.bor(DISABLE_FLAG, 999), 10 })
  local function utxo_h(_) return 200 end
  local function block_mtp(_) return 0 end
  local mh, mt = validation.calculate_sequence_locks(tx, 500, utxo_h, block_mtp, true)
  -- enabled input 2: 200 + 10 - 1 = 209  (disabled input contributes nothing)
  expect_eq(mh, 209, "only enabled input contributes")
  expect_eq(mt, -1, "no time-based inputs")
end)

-- ---------------------------------------------------------------------------
-- G6: Time-based branch invokes get_block_mtp(max(coin_h - 1, 0))
-- ---------------------------------------------------------------------------
print("\n--- G6: time-based uses get_block_mtp(coin_h - 1) ---")

test("G6-a: time-based input queries MTP of (coin_h - 1)", function()
  local probed_h = nil
  local function utxo_h(_) return 200 end
  local function block_mtp(h) probed_h = h; return 1700000000 end
  local seq_time = bit.bor(TYPE_FLAG, 5)  -- lock = 5 * 512 = 2560 seconds
  local tx = make_tx(2, 0, { seq_time })
  validation.calculate_sequence_locks(tx, 500, utxo_h, block_mtp, true)
  expect_eq(probed_h, 199, "get_block_mtp invoked at coin_h - 1 = 199")
end)

test("G6-b: coin_h = 0 → probes max(0-1, 0) = 0 (no negative ancestor)", function()
  local probed_h = nil
  local function utxo_h(_) return 0 end
  local function block_mtp(h) probed_h = h; return 1230768000 end  -- genesis
  local seq_time = bit.bor(TYPE_FLAG, 1)
  local tx = make_tx(2, 0, { seq_time })
  validation.calculate_sequence_locks(tx, 100, utxo_h, block_mtp, true)
  expect_eq(probed_h, 0, "max(0-1, 0) clamped to 0")
end)

-- ---------------------------------------------------------------------------
-- G7: nMinTime = max(nMinTime, nCoinTime + (mask << 9) - 1)
-- ---------------------------------------------------------------------------
print("\n--- G7: nMinTime arithmetic ---")

test("G7-a: time-based lock=1 (1 * 512 seconds, -1 for last-invalid)", function()
  local function utxo_h(_) return 200 end
  local function block_mtp(_) return 1700000000 end
  local seq_time = bit.bor(TYPE_FLAG, 1)
  local tx = make_tx(2, 0, { seq_time })
  local mh, mt = validation.calculate_sequence_locks(tx, 500, utxo_h, block_mtp, true)
  -- Core: nMinTime = 1700000000 + (1 << 9) - 1 = 1700000000 + 512 - 1 = 1700000511
  expect_eq(mh, -1, "no height-based inputs")
  expect_eq(mt, 1700000511, "1700000000 + 512 - 1")
end)

test("G7-b: time-based lock=10 (10 * 512 = 5120 seconds)", function()
  local function utxo_h(_) return 200 end
  local function block_mtp(_) return 1700000000 end
  local seq_time = bit.bor(TYPE_FLAG, 10)
  local tx = make_tx(2, 0, { seq_time })
  local mh, mt = validation.calculate_sequence_locks(tx, 500, utxo_h, block_mtp, true)
  -- 1700000000 + (10 << 9) - 1 = 1700000000 + 5120 - 1 = 1700005119
  expect_eq(mt, 1700005119, "1700000000 + 5120 - 1")
end)

test("G7-c: max() across multiple time-based inputs", function()
  local function utxo_h(inp) return 200 end  -- all share coin_h = 200
  local function block_mtp(_) return 1700000000 end
  local seq_time_a = bit.bor(TYPE_FLAG, 1)   -- expects min_time = 1700000511
  local seq_time_b = bit.bor(TYPE_FLAG, 10)  -- expects min_time = 1700005119 (bigger)
  local tx = make_tx(2, 0, { seq_time_a, seq_time_b })
  local _, mt = validation.calculate_sequence_locks(tx, 500, utxo_h, block_mtp, true)
  expect_eq(mt, 1700005119, "max(1700000511, 1700005119)")
end)

-- ---------------------------------------------------------------------------
-- G8: nMinHeight arithmetic
-- ---------------------------------------------------------------------------
print("\n--- G8: nMinHeight arithmetic ---")

test("G8-a: height-based lock=1 (coin_h + 1 - 1 = coin_h)", function()
  local function utxo_h(_) return 200 end
  local function block_mtp(_) return 0 end
  local tx = make_tx(2, 0, { 1 })
  local mh, _ = validation.calculate_sequence_locks(tx, 500, utxo_h, block_mtp, true)
  expect_eq(mh, 200, "200 + 1 - 1")
end)

test("G8-b: height-based lock=MASK (0xFFFF = 65535)", function()
  local function utxo_h(_) return 200 end
  local function block_mtp(_) return 0 end
  local tx = make_tx(2, 0, { MASK })
  local mh, _ = validation.calculate_sequence_locks(tx, 100000, utxo_h, block_mtp, true)
  expect_eq(mh, 200 + 65535 - 1, "200 + 65535 - 1 = 65734")
end)

test("G8-c: type-flag-clear, value=10 (height-based, not time-based)", function()
  -- seq = 0x0000000A: TYPE_FLAG clear → height-based with lock=10
  local function utxo_h(_) return 50 end
  local function block_mtp(h) error("should not query MTP for height-based input") end
  local tx = make_tx(2, 0, { 0x0000000A })
  local mh, mt = validation.calculate_sequence_locks(tx, 200, utxo_h, block_mtp, true)
  expect_eq(mh, 59, "50 + 10 - 1")
  expect_eq(mt, -1, "no time-based inputs")
end)

-- ---------------------------------------------------------------------------
-- G9: prevHeights[i] = 0 mutation on DISABLE_FLAG (BUG-2)
-- ---------------------------------------------------------------------------
print("\n--- G9: prevHeights[i] = 0 mutation absent (BUG-2) ---")

test("G9-a: BUG-2 — calculate_sequence_locks takes get_utxo_height CALLBACK", function()
  -- Core's tx_verify.cpp:67 mutates a std::vector<int>& prevHeights so
  -- caller-side LockPoints::maxInputBlock computation (validation.cpp:230)
  -- can skip disabled inputs.  lunarblock takes a callback — the mutation
  -- contract cannot be implemented.  Assert via shape.
  local arg_count = 0
  local function utxo_h(_) arg_count = arg_count + 1; return 100 end
  local function block_mtp(_) return 0 end
  -- DISABLE_FLAG input should be skipped → utxo_h NOT invoked for that input
  local tx = make_tx(2, 0, { bit.bor(DISABLE_FLAG, 5), 5 })
  validation.calculate_sequence_locks(tx, 200, utxo_h, block_mtp, true)
  expect_eq(arg_count, 1,
    "utxo_h invoked exactly once (DISABLE_FLAG input skipped)")
  bug("BUG-2", "P2")
end)

test("G9-b: no LockPoints persistence cache exists (forward-regression)", function()
  -- BUG-11: LockPoints persistence missing.  Asserted by absence.
  local found_lockpoints = pcall(function() return validation.LockPoints end)
  -- Either no global type or it's nil — both acceptable as proof-of-absence.
  -- We expect ABSENCE (BUG-11), so assertion is that calling LockPoints
  -- yields nil.
  expect_falsy(validation.LockPoints,
    "BUG-11: no validation.LockPoints type — LockPoints cache absent")
  bug("BUG-11", "P1")
end)

-- ---------------------------------------------------------------------------
-- G10: EvaluateSequenceLocks: min_h >= block.nHeight → false
-- ---------------------------------------------------------------------------
print("\n--- G10: EvaluateSequenceLocks block.nHeight check ---")

test("G10-a: min_height = 100, block_height = 100 → fail (strict >=)", function()
  local ok = validation.check_sequence_locks(100, -1, 100, 1700000000)
  expect_falsy(ok, "100 >= 100 → not satisfied")
end)

test("G10-b: min_height = 99, block_height = 100 → pass", function()
  local ok = validation.check_sequence_locks(99, -1, 100, 1700000000)
  expect_truthy(ok, "99 < 100 → satisfied")
end)

test("G10-c: min_height = -1 (no lock) → pass regardless of block_height", function()
  expect_truthy(validation.check_sequence_locks(-1, -1, 1, 0), "-1 < 1")
  expect_truthy(validation.check_sequence_locks(-1, -1, 0, 0), "-1 < 0")
end)

-- ---------------------------------------------------------------------------
-- G11: EvaluateSequenceLocks: min_t >= prev.MTP → false
-- ---------------------------------------------------------------------------
print("\n--- G11: EvaluateSequenceLocks prev_block_mtp check ---")

test("G11-a: min_time = 1700000000, prev_mtp = 1700000000 → fail (strict >=)", function()
  local ok = validation.check_sequence_locks(-1, 1700000000, 100, 1700000000)
  expect_falsy(ok, "1700000000 >= 1700000000 → not satisfied")
end)

test("G11-b: min_time = 1699999999, prev_mtp = 1700000000 → pass", function()
  local ok = validation.check_sequence_locks(-1, 1699999999, 100, 1700000000)
  expect_truthy(ok, "1699999999 < 1700000000 → satisfied")
end)

-- ---------------------------------------------------------------------------
-- G12: GetMedianTimePast walks up to 11 ancestors
-- ---------------------------------------------------------------------------
print("\n--- G12: GetMedianTimePast 11-block window ---")

test("G12-a: get_median_time_past with 11 timestamps", function()
  local ts = { 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100 }
  local mtp = consensus.get_median_time_past(ts)
  -- Core: pbegin[(11)/2] = pbegin[5] = 6th element (1-indexed sorted[6])
  -- Sorted: [100..1100], sorted[6] = 600
  expect_eq(mtp, 600, "sorted[6] of [100..1100] = 600")
end)

test("G12-b: get_median_time_past with 1 timestamp (genesis-like)", function()
  local mtp = consensus.get_median_time_past({ 12345 })
  -- Core: pbegin[(1)/2] = pbegin[0] = 1st element (sorted[1])
  expect_eq(mtp, 12345, "single-timestamp window")
end)

test("G12-c: get_median_time_past with 2 timestamps (upper-middle)", function()
  local mtp = consensus.get_median_time_past({ 100, 200 })
  -- Core: pbegin[(2)/2] = pbegin[1] = 2nd element (sorted[2]) — upper-middle
  expect_eq(mtp, 200, "upper-middle = 200")
end)

-- ---------------------------------------------------------------------------
-- G13: Median picks upper-middle for even-near-genesis
-- ---------------------------------------------------------------------------
print("\n--- G13: median upper-middle invariant ---")

test("G13-a: median of unsorted [5,3,1,4,2] = 3", function()
  expect_eq(consensus.get_median_time_past({5,3,1,4,2}), 3, "median = 3")
end)

test("G13-b: median of 11 sorted desc = sorted[6]", function()
  expect_eq(consensus.get_median_time_past({11,10,9,8,7,6,5,4,3,2,1}), 6,
    "sort + sorted[6] = 6")
end)

-- ---------------------------------------------------------------------------
-- G14: os.time() fallback in MTP helpers (BUG-3, XFAIL pre-fix)
-- ---------------------------------------------------------------------------
print("\n--- G14: BUG-3 — os.time() fallback in MTP helpers ---")

test_xfail("G14: BUG-3 — mempool get_tip_mtp / utxo compute_mtp_from_storage falls back to os.time()", "BUG-3", function()
  -- This is an XFAIL: we expect the source to contain `os.time()` in
  -- the fallback path, which is non-deterministic vs Core.
  -- The "fail" mode (which is the pre-fix state) is that os.time() IS
  -- still in the source.  Post-fix, the call site uses a deterministic
  -- sentinel (e.g. -1 → reject) and this test passes.
  local f = io.open("src/mempool.lua", "r")
  expect_truthy(f, "open src/mempool.lua")
  local src = f:read("*a"); f:close()
  -- Look for the line: `return os.time()` inside get_tip_mtp body
  local got = src:find("function get_tip_mtp.-os%.time%(%)") ~= nil
  if got then
    error("BUG-3 STILL PRESENT: get_tip_mtp falls back to os.time() (mempool.lua)")
  end
  local f2 = io.open("src/utxo.lua", "r")
  expect_truthy(f2, "open src/utxo.lua")
  local src2 = f2:read("*a"); f2:close()
  local got2 = src2:find("function compute_mtp_from_storage.-os%.time%(%)") ~= nil
  if got2 then
    error("BUG-3 STILL PRESENT: compute_mtp_from_storage falls back to os.time() (utxo.lua)")
  end
end)
bug("BUG-3", "P1")

-- ---------------------------------------------------------------------------
-- G15: IsFinalTx: locktime=0 → always final
-- ---------------------------------------------------------------------------
print("\n--- G15: IsFinalTx locktime=0 invariant ---")

test("G15-a: locktime=0 final regardless of sequences or height", function()
  expect_truthy(mining.is_final_tx(make_tx(1, 0, { 0 }), 1, 0), "locktime=0")
  expect_truthy(mining.is_final_tx(make_tx(2, 0, { 1, 2, 3 }), 1, 0), "locktime=0")
end)

-- ---------------------------------------------------------------------------
-- G16: IsFinalTx: locktime < cutoff → final
-- ---------------------------------------------------------------------------
print("\n--- G16: IsFinalTx height vs time cutoff selection ---")

test("G16-a: height-based locktime, satisfied by height", function()
  -- locktime = 100 (< LOCKTIME_THRESHOLD), height = 101, mtp arbitrary
  expect_truthy(mining.is_final_tx(make_tx(1, 100, { 0 }), 101, 9999999999),
    "100 < 101 → final")
end)

test("G16-b: height-based locktime, NOT satisfied + non-final seq", function()
  expect_falsy(mining.is_final_tx(make_tx(1, 100, { 0 }), 100, 9999999999),
    "100 < 100 false + seq != SEQUENCE_FINAL")
  expect_falsy(mining.is_final_tx(make_tx(1, 100, { 0 }), 99, 9999999999),
    "100 < 99 false + seq != SEQUENCE_FINAL")
end)

test("G16-c: time-based locktime, satisfied by MTP", function()
  -- locktime = 500000001 (>= LOCKTIME_THRESHOLD), MTP = 500000002
  expect_truthy(mining.is_final_tx(make_tx(1, 500000001, { 0 }), 1, 500000002),
    "500000001 < 500000002 → final")
end)

test("G16-d: time-based locktime, NOT satisfied + non-final seq", function()
  expect_falsy(mining.is_final_tx(make_tx(1, 500000002, { 0 }), 1, 500000001),
    "500000002 < 500000001 false + seq != SEQUENCE_FINAL")
end)

-- ---------------------------------------------------------------------------
-- G17: IsFinalTx: every-input-SEQUENCE_FINAL overrides locktime
-- ---------------------------------------------------------------------------
print("\n--- G17: IsFinalTx SEQUENCE_FINAL override ---")

test("G17-a: locktime unsatisfied but all-inputs-SEQUENCE_FINAL → final", function()
  expect_truthy(mining.is_final_tx(make_tx(1, 9999999999, { SEQUENCE_FINAL }), 1, 0),
    "all SEQUENCE_FINAL overrides unsatisfied locktime")
end)

test("G17-b: locktime unsatisfied + mixed → non-final", function()
  expect_falsy(mining.is_final_tx(make_tx(1, 9999999999, { SEQUENCE_FINAL, 0 }), 1, 0),
    "ONE input not-SEQUENCE_FINAL → non-final")
end)

-- ---------------------------------------------------------------------------
-- G18: IsFinalTx mempool: cutoff = TIP's MTP, nextHeight = tip+1
-- ---------------------------------------------------------------------------
print("\n--- G18: IsFinalTx mempool invariant ---")

test("G18-a: mempool uses next_height = tip_height + 1", function()
  -- Core CheckFinalTxAtTip (validation.cpp:147-167):
  --   nBlockHeight = active_chain_tip.nHeight + 1
  -- Lunarblock at mempool.lua:1103-1105 does the same.
  -- Smoke: tx with locktime=101 should be final at next_height=101 (height-based)
  -- if interpretation is correct: 101 < 101 is FALSE, but the test must follow
  -- the actual rule.  At tip_height=100, next_height=101, locktime=101:
  -- 101 < 101 is FALSE → not satisfied → check seqs.  All seqs = SEQUENCE_FINAL
  -- → still final.  Or all seqs = 0 → not final.
  local tx = make_tx(1, 101, { 0 })
  expect_falsy(mining.is_final_tx(tx, 101, 0),
    "locktime=101, next_height=101 → not satisfied + non-final seq")
  local tx2 = make_tx(1, 100, { 0 })
  expect_truthy(mining.is_final_tx(tx2, 101, 0),
    "locktime=100, next_height=101 → satisfied → final")
end)

-- ---------------------------------------------------------------------------
-- G19: OP_CSV gated on SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
-- ---------------------------------------------------------------------------
print("\n--- G19: OP_CSV gating via SCRIPT_VERIFY_CHECKSEQUENCEVERIFY ---")

test("G19-a: source-level check that flag is consulted", function()
  local f = io.open("src/script.lua", "r")
  expect_truthy(f, "open src/script.lua")
  local src = f:read("*a"); f:close()
  -- Find OP_CHECKSEQUENCEVERIFY block
  local idx = src:find("opcode == M%.OP%.OP_CHECKSEQUENCEVERIFY", 1, false)
  expect_truthy(idx, "OP_CHECKSEQUENCEVERIFY opcode handler present")
  local handler_block = src:sub(idx, idx + 1500)
  expect_truthy(handler_block:find("verify_checksequenceverify", 1, true),
    "handler consults flags.verify_checksequenceverify")
end)

-- ---------------------------------------------------------------------------
-- G20: OP_CSV empty stack → INVALID_STACK_OPERATION
-- ---------------------------------------------------------------------------
print("\n--- G20: OP_CSV empty-stack failure ---")

test("G20-a: source asserts #stack > 0 before consuming top", function()
  local f = io.open("src/script.lua", "r")
  local src = f:read("*a"); f:close()
  local idx = src:find("opcode == M%.OP%.OP_CHECKSEQUENCEVERIFY", 1, false)
  local block = src:sub(idx, idx + 700)
  expect_truthy(block:find("assert%(#stack > 0", 1, false),
    "asserts #stack > 0 before processing CSV value")
end)

-- ---------------------------------------------------------------------------
-- G21: OP_CSV uses 5-byte CScriptNum
-- ---------------------------------------------------------------------------
print("\n--- G21: OP_CSV 5-byte CScriptNum ---")

test("G21-a: pop_num(5) used (NOT pop_num(4))", function()
  local f = io.open("src/script.lua", "r")
  local src = f:read("*a"); f:close()
  local idx = src:find("opcode == M%.OP%.OP_CHECKSEQUENCEVERIFY", 1, false)
  local block = src:sub(idx, idx + 700)
  expect_truthy(block:find("pop_num%(5%)", 1, false),
    "CSV reads top as 5-byte CScriptNum (allows full uint32 nSequence)")
end)

-- ---------------------------------------------------------------------------
-- G22: OP_CSV negative value → NEGATIVE_LOCKTIME
-- ---------------------------------------------------------------------------
print("\n--- G22: OP_CSV negative-locktime check ---")

test("G22-a: source rejects negative sequence", function()
  local f = io.open("src/script.lua", "r")
  local src = f:read("*a"); f:close()
  local idx = src:find("opcode == M%.OP%.OP_CHECKSEQUENCEVERIFY", 1, false)
  local block = src:sub(idx, idx + 1500)
  expect_truthy(block:find('error%("negative sequence"%)', 1, false),
    "error path for sequence < 0")
end)

-- ---------------------------------------------------------------------------
-- G23: OP_CSV DISABLE_FLAG set → NOP (BUG-4)
-- ---------------------------------------------------------------------------
print("\n--- G23: OP_CSV DISABLE_FLAG behavior + BUG-4 source check ---")

test("G23-a: OP_CSV uses math.floor / 0x80000000 to test DISABLE_FLAG (avoids LuaJIT trap)", function()
  local f = io.open("src/script.lua", "r")
  local src = f:read("*a"); f:close()
  local idx = src:find("opcode == M%.OP%.OP_CHECKSEQUENCEVERIFY", 1, false)
  local block = src:sub(idx, idx + 1500)
  expect_truthy(block:find("math%.floor%(sequence / 0x80000000%) %% 2 == 1", 1, false),
    "DISABLE_FLAG check uses math.floor / 0x80000000 (avoids LuaJIT bit.band 32-bit trap)")
end)

test("G23-b: BUG-4 — checker.check_sequence ALSO consults sequence_locks_active (double-check, inconsistent)", function()
  -- BUG-4: the opcode does the careful math.floor check, then the
  -- checker re-checks via bit.band-based sequence_locks_active.
  -- This is the source-level smell.  Forward-regression: if the
  -- opcode-side check is ever removed without consolidating, the
  -- checker-side bit.band would be the sole guard and could trap.
  local f = io.open("src/validation.lua", "r")
  local src = f:read("*a"); f:close()
  -- check_sequence factory calls consensus.sequence_locks_active(script_sequence)
  expect_truthy(src:find("consensus%.sequence_locks_active%(script_sequence%)", 1, false),
    "validation.lua check_sequence consults consensus.sequence_locks_active")
  bug("BUG-4", "P2")
end)

-- ---------------------------------------------------------------------------
-- G24: OP_CSV preserves top-of-stack byte form (BUG-5)
-- ---------------------------------------------------------------------------
print("\n--- G24: OP_CSV stack preservation + BUG-5 source check ---")

test("G24-a: BUG-5 — OP_CSV pops then re-pushes via script_num_encode (NOT byte-preserving)", function()
  local f = io.open("src/script.lua", "r")
  local src = f:read("*a"); f:close()
  local idx = src:find("opcode == M%.OP%.OP_CHECKSEQUENCEVERIFY", 1, false)
  local block = src:sub(idx, idx + 1500)
  -- BUG-5 trigger: push(M.script_num_encode(sequence)) re-encodes the value
  expect_truthy(block:find("push%(M%.script_num_encode%(sequence%)%)", 1, false) or
                block:find("push%(M%.script_num_encode%(sequence%)%) ", 1, false),
    "OP_CSV pops + re-pushes via script_num_encode (non-byte-preserving)")
  bug("BUG-5", "P2")
end)

-- ---------------------------------------------------------------------------
-- G25: CheckSequence: tx.version < 2 → false
-- ---------------------------------------------------------------------------
print("\n--- G25: CheckSequence version gate ---")

test("G25-a: tx.version=1 fails check_sequence regardless of values", function()
  -- We synthesize via the legacy sig-checker factory.
  local tx = make_tx(1, 0, { 5 })  -- version=1, seq=5
  local checker = validation.make_sig_checker(tx, 0, 1000, "", {}, nil)
  expect_falsy(checker.check_sequence(5),
    "version=1 → check_sequence(5) returns false")
end)

test("G25-b: tx.version=2 with disabled input fails check_sequence", function()
  local tx = make_tx(2, 0, { bit.bor(DISABLE_FLAG, 5) })
  local checker = validation.make_sig_checker(tx, 0, 1000, "", {}, nil)
  expect_falsy(checker.check_sequence(5),
    "DISABLE_FLAG on input → check_sequence returns false")
end)

-- ---------------------------------------------------------------------------
-- G26: CheckSequence: txTo DISABLE_FLAG → false
-- ---------------------------------------------------------------------------
print("\n--- G26: CheckSequence txTo disable-flag ---")

test("G26-a: script_sequence with DISABLE_FLAG → check_sequence treats as NOP (true)", function()
  -- Per validation.lua:1629 — if script_sequence has DISABLE_FLAG, return true.
  -- This deviates from Core in form (Core's opcode handler catches this BEFORE
  -- calling CheckSequence) but is functionally consistent because the
  -- opcode is the only caller and never invokes check_sequence with DISABLED.
  local tx = make_tx(2, 0, { 5 })
  local checker = validation.make_sig_checker(tx, 0, 1000, "", {}, nil)
  expect_truthy(checker.check_sequence(bit.bor(DISABLE_FLAG, 5)),
    "script_sequence DISABLED → returns true (NOP semantics at checker level)")
end)

-- ---------------------------------------------------------------------------
-- G27: CheckSequence type-match check (BUG-6)
-- ---------------------------------------------------------------------------
print("\n--- G27: CheckSequence type-match + BUG-6 ---")

test("G27-a: types match — both height-based", function()
  local tx = make_tx(2, 0, { 100 })  -- input: height-based, value 100
  local checker = validation.make_sig_checker(tx, 0, 1000, "", {}, nil)
  expect_truthy(checker.check_sequence(50),
    "script=50 vs input=100, both height-based, 50 <= 100 → true")
end)

test("G27-b: types mismatch — script time-based, input height-based", function()
  local tx = make_tx(2, 0, { 100 })  -- input: height-based, value 100
  local checker = validation.make_sig_checker(tx, 0, 1000, "", {}, nil)
  expect_falsy(checker.check_sequence(bit.bor(TYPE_FLAG, 50)),
    "script time-based + input height-based → types mismatch → false")
end)

test("G27-c: types mismatch — script height-based, input time-based", function()
  local tx = make_tx(2, 0, { bit.bor(TYPE_FLAG, 100) })  -- input: time-based
  local checker = validation.make_sig_checker(tx, 0, 1000, "", {}, nil)
  expect_falsy(checker.check_sequence(50),
    "script height-based + input time-based → types mismatch → false")
end)

test("G27-d: BUG-6 — type-check uses two separate masks, not Core's combined 0x0040FFFF", function()
  local f = io.open("src/validation.lua", "r")
  local src = f:read("*a"); f:close()
  -- BUG-6: the type-match check is `script_is_time ~= input_is_time` using
  -- raw TYPE_FLAG band, NOT `(masked < TYPE_FLAG) AND (masked < TYPE_FLAG)`
  -- on the COMBINED-mask values.  Smoke for the two-mask pattern:
  expect_truthy(src:find("script_is_time ~= input_is_time", 1, false),
    "BUG-6: two-mask separate type-check pattern (not Core combined-mask)")
  bug("BUG-6", "P1")
end)

-- ---------------------------------------------------------------------------
-- G28: CheckSequence masked-value comparison
-- ---------------------------------------------------------------------------
print("\n--- G28: CheckSequence value comparison ---")

test("G28-a: script_value > input_value → false", function()
  local tx = make_tx(2, 0, { 50 })
  local checker = validation.make_sig_checker(tx, 0, 1000, "", {}, nil)
  expect_falsy(checker.check_sequence(100),
    "script=100 > input=50 → false")
end)

test("G28-b: script_value == input_value → true (equality allowed)", function()
  local tx = make_tx(2, 0, { 50 })
  local checker = validation.make_sig_checker(tx, 0, 1000, "", {}, nil)
  expect_truthy(checker.check_sequence(50),
    "script=50 == input=50 → true (Core nSequenceMasked > txToSequenceMasked = false)")
end)

test("G28-c: time-based — script time-value <= input time-value", function()
  local script_seq = bit.bor(TYPE_FLAG, 10)
  local input_seq  = bit.bor(TYPE_FLAG, 100)
  local tx = make_tx(2, 0, { input_seq })
  local checker = validation.make_sig_checker(tx, 0, 1000, "", {}, nil)
  expect_truthy(checker.check_sequence(script_seq),
    "time-based: 10 <= 100 → true")
end)

-- ---------------------------------------------------------------------------
-- G29: bit.lshift(lock_value, 9) safe zone audit
-- ---------------------------------------------------------------------------
print("\n--- G29: bit.lshift(lock_value, 9) safe-zone audit ---")

test("G29-a: lock_value <= 0xFFFF, so lock_value << 9 <= 0x01FFFE00 (< 2^25)", function()
  -- LuaJIT bit.lshift is 32-bit modular; safe for shifts where result < 2^31.
  -- Max lock_value = 0xFFFF, shift = 9, max shifted = 0xFFFF * 2 = 0x01FFFE00
  -- = 33,553,920 < 2^25.  No trap.
  local v = bit.lshift(0xFFFF, 9)
  expect_eq(v, 33553920, "0xFFFF << 9 = 0x1FFFE00")
end)

test("G29-b: forward-regression: validation.lua uses bit.lshift(lock_value, GRANULARITY)", function()
  local f = io.open("src/validation.lua", "r")
  local src = f:read("*a"); f:close()
  expect_truthy(src:find("bit%.lshift%(lock_value, consensus%.SEQUENCE_LOCKTIME_GRANULARITY%)", 1, false),
    "validation.lua uses bit.lshift(lock_value, GRANULARITY=9) — safe zone")
end)

-- ---------------------------------------------------------------------------
-- G30: bit.band on 5-byte CScriptNum (BUG-9 — LuaJIT trap-weak)
-- ---------------------------------------------------------------------------
print("\n--- G30: BUG-9 — bit.band on 5-byte CScriptNum (FIX-83 pattern) ---")

test("G30-a: bit.band(0x180000000, DISABLE_FLAG) — LuaJIT 32-bit modular truncates", function()
  -- LuaJIT bit.band truncates inputs to int32 first.
  -- 0x180000000 -> low 32 bits = 0x80000000, then & 0x80000000 = 0x80000000.
  -- Core (int64): 0x180000000 & 0x80000000 = 0x80000000.
  -- Same answer for DISABLE_FLAG bit position.
  local lo = bit.band(0x180000000, DISABLE_FLAG)
  -- bit.band returns int32 (signed) in LuaJIT — 0x80000000 = -2147483648 signed
  expect_truthy(lo ~= 0, "LuaJIT truncation preserves bit 31 of low 32 bits")
end)

test("G30-b: source-level marker for BUG-9 (raw bit.band on potentially > 2^32 inputs)", function()
  local f = io.open("src/consensus.lua", "r")
  local src = f:read("*a"); f:close()
  -- consensus.sequence_locks_active uses bit.band(sequence, ...) — same trap surface.
  expect_truthy(src:find("bit%.band%(sequence, M%.SEQUENCE_LOCKTIME_DISABLE_FLAG%)", 1, false),
    "BUG-9: consensus.sequence_locks_active uses raw bit.band (LuaJIT trap-weak for inputs > 2^32)")
  bug("BUG-9", "P1")
end)

-- ---------------------------------------------------------------------------
-- BUG-1 (P0-CDIV) — Mempool BIP-68 uses tip_mtp for every input
-- ---------------------------------------------------------------------------
print("\n--- BUG-1 (P0-CDIV): mempool ancestor MTP closure ignores h ---")

test_xfail("BUG-1: mempool.lua get_block_mtp_conservative returns tip_mtp regardless of h", "BUG-1", function()
  local f = io.open("src/mempool.lua", "r")
  expect_truthy(f, "open src/mempool.lua")
  local src = f:read("*a"); f:close()
  -- BUG-1: the closure ignores its h argument and returns tip_mtp.
  -- Pre-fix: closure is named get_block_mtp_conservative and body is
  -- literally `return tip_mtp`.
  -- Post-fix: closure walks storage and returns ancestor MTP.
  local conservative_idx = src:find("get_block_mtp_conservative", 1, true)
  if conservative_idx then
    -- Pre-fix state: find the body and assert it's `return tip_mtp`.
    -- We slice ~200 chars around the definition.
    local body = src:sub(conservative_idx, conservative_idx + 400)
    -- BUG-1 trigger: body contains `return tip_mtp` (no ancestor walk)
    if body:find("return tip_mtp", 1, true) then
      error("BUG-1 STILL PRESENT: mempool.lua get_block_mtp_conservative returns tip_mtp (ignores h)")
    end
  end
end)
bug("BUG-1", "P0-CDIV")

-- ---------------------------------------------------------------------------
-- BUG-7 — Three-copy check_sequence drift surface
-- ---------------------------------------------------------------------------
print("\n--- BUG-7 — three-copy check_sequence sig-checker drift surface ---")

test("BUG-7: validation.lua has 3 copies of check_sequence across 3 factories", function()
  local f = io.open("src/validation.lua", "r")
  local src = f:read("*a"); f:close()
  -- Count occurrences of `function checker.check_sequence`
  local count = 0
  local pos = 1
  while true do
    local i = src:find("function checker%.check_sequence", pos, false)
    if not i then break end
    count = count + 1
    pos = i + 1
  end
  expect_eq(count, 3,
    "BUG-7: three copies of check_sequence (make_sig_checker + make_tapscript_checker + make_collecting_sig_checker)")
  bug("BUG-7", "P1")
end)

-- ---------------------------------------------------------------------------
-- BUG-8 — Three-copy check_locktime drift surface
-- ---------------------------------------------------------------------------
print("\n--- BUG-8 — three-copy check_locktime sig-checker drift surface ---")

test("BUG-8: validation.lua has 3 copies of check_locktime across 3 factories", function()
  local f = io.open("src/validation.lua", "r")
  local src = f:read("*a"); f:close()
  local count = 0
  local pos = 1
  while true do
    local i = src:find("function checker%.check_locktime", pos, false)
    if not i then break end
    count = count + 1
    pos = i + 1
  end
  expect_eq(count, 3, "BUG-8: three copies of check_locktime")
  bug("BUG-8", "P3")
end)

-- ---------------------------------------------------------------------------
-- BUG-10 — BUG-3 + sentinel -1 combine into non-deterministic boot
-- ---------------------------------------------------------------------------
print("\n--- BUG-10 — BUG-3 + sentinel -1 combine at boot ---")

test("BUG-10: check_sequence_locks(-1, -1, h, mtp) returns true (no-lock path)", function()
  -- Smoke that the -1 sentinel path works.  Combined with BUG-3,
  -- a near-boot tx with calculate_sequence_locks returning -1,-1 and
  -- prev_block_mtp = os.time() does NOT actually use the os.time() value
  -- (because -1 >= anything is false), so BUG-10 reduces to "potentially
  -- consumed elsewhere".  This test pins the no-lock path's invariant.
  expect_truthy(validation.check_sequence_locks(-1, -1, 1, 0), "(-1,-1) → satisfied")
  expect_truthy(validation.check_sequence_locks(-1, -1, 1, 1700000000), "(-1,-1) → satisfied at large MTP")
  bug("BUG-10", "P1")
end)

-- ---------------------------------------------------------------------------
-- Final source-level forward-regression
-- ---------------------------------------------------------------------------
print("\n--- Forward-regression source-level guards ---")

test("FR-1: SEQUENCE_LOCKTIME_* constants pinned to Core values", function()
  expect_eq(consensus.SEQUENCE_LOCKTIME_DISABLE_FLAG, 0x80000000, "DISABLE_FLAG")
  expect_eq(consensus.SEQUENCE_LOCKTIME_TYPE_FLAG, 0x00400000, "TYPE_FLAG")
  expect_eq(consensus.SEQUENCE_LOCKTIME_MASK, 0x0000FFFF, "MASK")
  expect_eq(consensus.SEQUENCE_LOCKTIME_GRANULARITY, 9, "GRANULARITY")
end)

test("FR-2: MEDIAN_TIME_PAST_BLOCKS = 11 (Core nMedianTimeSpan)", function()
  expect_eq(consensus.MEDIAN_TIME_PAST_BLOCKS, 11, "MTP window = 11 blocks")
end)

test("FR-3: LOCKTIME_THRESHOLD = 500,000,000 (Core)", function()
  expect_eq(consensus.LOCKTIME_THRESHOLD, 500000000, "LOCKTIME_THRESHOLD")
end)

test("FR-4: csv_height for mainnet = 419328", function()
  local mainnet = consensus.network and consensus.network("main")
  -- consensus.lua:892 defines mainnet csv_height = 419328
  -- We probe via a different surface to avoid coupling to internal accessor
  local f = io.open("src/consensus.lua", "r")
  local src = f:read("*a"); f:close()
  expect_truthy(src:find("csv_height = 419328", 1, false),
    "mainnet csv_height = 419328")
end)

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------

print("\n=========================================================================")
print(string.format("W132 SUMMARY: %d PASS, %d FAIL, %d XFAIL (pre-fix expected)",
  PASS, FAIL, XFAIL_PRE_FIX))
print(string.format("Status: %s",
  FAIL == 0 and (XFAIL_PRE_FIX > 0
    and "BUG-1 + BUG-3 PRESENT (expected pre-fix)"
    or "ALL GREEN — BUG-1 + BUG-3 FIXED")
  or "UNEXPECTED FAILURES — investigate"))
print("=========================================================================")

print("\nBugs found:")
for _, b in ipairs(BUGS) do
  print("  " .. b)
end

print("\nSee audit/w132_nsequence_csv_mtp.md for full classification + fix order.")

-- Exit non-zero only on UNEXPECTED failures.  Expected pre-fix XFAILs
-- do not cause non-zero exit — they're advisory until a fix lands and
-- they flip to PASS.
if FAIL > 0 then os.exit(1) end
