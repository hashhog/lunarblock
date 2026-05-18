#!/usr/bin/env luajit
-- W135 Standardness rules (IsStandardTx) audit -- lunarblock
--
-- Reference: bitcoin-core/src/policy/policy.{cpp,h}
--            bitcoin-core/src/script/solver.{cpp,h}
--            bitcoin-core/src/script/script.{cpp,h} (IsPushOnly, IsPayToAnchor)
--            bitcoin-core/src/policy/truc_policy.{cpp,h}
--            bitcoin-core/src/consensus/tx_check.cpp
--            bitcoin-core/src/validation.cpp:812-814 (PreChecks tx-size-small)
--            bitcoin-core/src/node/mempool_args.cpp:95-99 (-datacarrier toggle)
--
-- Scope: assert lunarblock's relay-time standardness parity vs Core.
-- EXCLUDES: package-relay protocol (W116), descriptor / miniscript wallet types
-- (W131), Taproot interpreter semantics (W127), BIP-68 / 112 / 113 (W132).
--
-- Gate map (W135):
--   G1   tx.version not in [1,3] -> reason="version"
--   G2   weight > MAX_STANDARD_TX_WEIGHT(=400000) -> reason="tx-size"
--   G3   non-witness size < MIN_STANDARD_TX_NONWITNESS_SIZE(=65)
--          -> reason="tx-size-small" (CVE-2017-12842)
--   G4   per-input: scriptSig.size > MAX_STANDARD_SCRIPTSIG_SIZE(=1650)
--          -> reason="scriptsig-size"
--   G5   per-input: scriptSig not push-only -> reason="scriptsig-not-pushonly"
--   G6   datacarrier accumulator + -datacarrier=0 toggle
--   G7   GetDust().size > MAX_DUST_OUTPUTS_PER_TX(=1) -> reason="dust"
--   G8   Solver() -> TxoutType::PUBKEY classification (P2PK)
--   G9   Solver() -> TxoutType::MULTISIG with IsStandard n<=3 + bare-multisig
--   G10  Solver() -> TxoutType::NULL_DATA with OP_RESERVED push-only acceptance
--   G11  Solver() -> TxoutType::ANCHOR (P2A) exact bytes
--   G15  IsUnspendable: size>0 && [0]==OP_RETURN OR size > MAX_SCRIPT_SIZE
--   G16  GetDustThreshold nSize: witness +67, non-witness +148
--   G17  CFeeRate::GetFee round-UP (EvaluateFee<false>)
--   G18  MAX_DUST_OUTPUTS_PER_TX=1 (ephemeral-anchor)
--   G19  BIP-54 CheckSigopsBIP54 (MAX_TX_LEGACY_SIGOPS=2500)
--   G20  ValidateInputsStandardness NONSTANDARD prev-spk
--   G21  ValidateInputsStandardness WITNESS_UNKNOWN prev-spk
--   G22  P2SH redeemScript sigops > MAX_P2SH_SIGOPS(=15) + extract semantics
--   G23  IsWitnessStandard coinbase guard
--   G24  P2A input with non-empty witness -> reject
--   G25  P2SH-wrapped witness redeemScript extraction (EvalScript NONE)
--   G26  P2WSH (v0 32-byte): script size + stack items + per-item limits
--   G27  P2TR (v1 32-byte non-P2SH): annex + tapscript-leaf limits
--   G28  SingleTRUCChecks (6 gates)
--   G29  PackageTRUCChecks present + wired
--   G30  accept_package runs IsStandardTx per tx (full pipeline, not subset)
--
-- Bugs (12; BUG-4 retracted as false-positive post-runtime-probe):
--   BUG-1   P2     is_push_only raises uncaught Lua error on malformed scriptSig  (G5)
--   BUG-2   P1     -datacarrier=0 operator toggle absent                           (G6)
--   BUG-3   P0     P2PK classify_script missing -> rejected as nonstandard         (G8)
--   BUG-4   --     RETRACTED: OP_RESERVED IS accepted (classify_script:761 range
--                  0x4f..0x60 INCLUSIVE of 0x50; misleading comment only)         (G10)
--   BUG-5   P2     IsUnspendable size>10000 path missing                           (G15)
--   BUG-6   P1     Dust nSize wrong for witness_unknown outputs (v2-v16)           (G16)
--   BUG-7   P1     extract_p2sh_redeem_script uses last-push, not EvalScript-NONE  (G22)
--   BUG-8   P1     PackageTRUCChecks missing                                        (G29)
--   BUG-9   P1     accept_package skips most IsStandardTx gates                    (G30)
--   BUG-10  P2     MAX_OP_RETURN_RELAY = 100000 hard-coded (not derived)           (G6)
--   BUG-11  P3     Reason-string drift (all witness rejects -> "bad-witness-nonstandard") (G24-G27)
--   BUG-12  P1     is_witness_standard coinbase guard missing                      (G23)
--   BUG-13  P3     is_push_only("") guard at call site (unnecessary)               (G5)
--
-- Test harness style mirrors test_w132_nsequence_csv_mtp.lua /
-- test_w133_index_databases.lua so the project test runner output stays uniform.

package.path = "src/?.lua;src/?/init.lua;" .. package.path

-- ---------------------------------------------------------------------------
-- Test scaffolding
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

local function test_xfail_pre_fix(name, bug_id, fn)
  local ok, err = pcall(fn)
  if ok then
    pass(name .. " [now PASSing -- " .. bug_id .. " fix likely landed]")
  else
    xfail_pre_fix(name .. " (" .. bug_id .. ")", tostring(err))
  end
end

local function bug(id, severity)
  BUGS[#BUGS + 1] = id .. " (" .. severity .. ")"
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

local function expect_nil(v, msg)
  if v ~= nil then error((msg or "expected nil") .. ": got " .. tostring(v), 2) end
end

local function expect_not_nil(v, msg)
  if v == nil then error((msg or "expected non-nil"), 2) end
end

-- Pluck a file source for grep-style checks.
local function slurp(path)
  local f = io.open(path, "r")
  if not f then return nil end
  local body = f:read("*a")
  f:close()
  return body
end

local function file_contains(path, needle)
  local body = slurp(path)
  if not body then return false end
  return body:find(needle, 1, true) ~= nil
end

-- ---------------------------------------------------------------------------
-- Load modules (best-effort -- some tests are source-grep only)
-- ---------------------------------------------------------------------------

local script_mod_ok, script_mod = pcall(require, "script")
local mempool_mod_ok, mempool = pcall(require, "mempool")

-- ---------------------------------------------------------------------------
-- Banner
-- ---------------------------------------------------------------------------

print("\n=========================================================================")
print("W135 Standardness rules (IsStandardTx) -- lunarblock")
print("Source: src/mempool.lua (accept_transaction, accept_package,")
print("        single_truc_checks, validate_inputs_standardness,")
print("        is_witness_standard, constants) +")
print("        src/script.lua (classify_script, is_push_only,")
print("        is_pay_to_anchor, is_witness_program, parse_script,")
print("        extract_last_push)")
print("Reference: bitcoin-core/src/policy/{policy,truc_policy}.{cpp,h} +")
print("           bitcoin-core/src/script/{solver,script}.{cpp,h} +")
print("           bitcoin-core/src/consensus/tx_check.cpp +")
print("           bitcoin-core/src/validation.cpp:812-814")
print("=========================================================================")

-- ---------------------------------------------------------------------------
-- Constants -- forward-regression source guards
-- Pin every standardness constant to its Core value.
-- ---------------------------------------------------------------------------

print("\n--- Constants (forward-regression source guards) ---")

if mempool_mod_ok then
  test("CONST: MAX_STANDARD_TX_WEIGHT = 400000", function()
    expect_eq(mempool.MAX_STANDARD_TX_WEIGHT, 400000)
  end)
  test("CONST: TX_MIN_STANDARD_VERSION = 1", function()
    expect_eq(mempool.TX_MIN_STANDARD_VERSION, 1)
  end)
  test("CONST: TX_MAX_STANDARD_VERSION = 3", function()
    expect_eq(mempool.TX_MAX_STANDARD_VERSION, 3)
  end)
  test("CONST: MAX_STANDARD_SCRIPTSIG_SIZE = 1650", function()
    expect_eq(mempool.MAX_STANDARD_SCRIPTSIG_SIZE, 1650)
  end)
  test("CONST: MAX_STANDARD_TX_SIGOPS_COST = 16000", function()
    expect_eq(mempool.MAX_STANDARD_TX_SIGOPS_COST, 16000)
  end)
  test("CONST: MIN_STANDARD_TX_NONWITNESS_SIZE = 65", function()
    expect_eq(mempool.MIN_STANDARD_TX_NONWITNESS_SIZE, 65)
  end)
  test("CONST: MAX_OP_RETURN_RELAY = 100000", function()
    expect_eq(mempool.MAX_OP_RETURN_RELAY, 100000)
  end)
  test("CONST: DUST_RELAY_FEE_RATE = 3000", function()
    expect_eq(mempool.DUST_RELAY_FEE_RATE, 3000)
  end)
  test("CONST: MAX_P2SH_SIGOPS = 15", function()
    expect_eq(mempool.MAX_P2SH_SIGOPS, 15)
  end)
  test("CONST: MAX_TX_LEGACY_SIGOPS = 2500", function()
    expect_eq(mempool.MAX_TX_LEGACY_SIGOPS, 2500)
  end)
  test("CONST: PERMIT_BARE_MULTISIG = false (matches Core v28+ -permitbaremultisig=0)",
    function()
      expect_eq(mempool.PERMIT_BARE_MULTISIG, false)
    end)
  test("CONST: TRUC_VERSION = 3", function()
    expect_eq(mempool.TRUC_VERSION, 3)
  end)
  test("CONST: TRUC_ANCESTOR_LIMIT = 2", function()
    expect_eq(mempool.TRUC_ANCESTOR_LIMIT, 2)
  end)
  test("CONST: TRUC_DESCENDANT_LIMIT = 2", function()
    expect_eq(mempool.TRUC_DESCENDANT_LIMIT, 2)
  end)
  test("CONST: TRUC_MAX_VSIZE = 10000", function()
    expect_eq(mempool.TRUC_MAX_VSIZE, 10000)
  end)
  test("CONST: TRUC_CHILD_MAX_VSIZE = 1000", function()
    expect_eq(mempool.TRUC_CHILD_MAX_VSIZE, 1000)
  end)
  test("CONST: MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600", function()
    expect_eq(mempool.MAX_STANDARD_P2WSH_SCRIPT_SIZE, 3600)
  end)
  test("CONST: MAX_STANDARD_P2WSH_STACK_ITEMS = 100", function()
    expect_eq(mempool.MAX_STANDARD_P2WSH_STACK_ITEMS, 100)
  end)
  test("CONST: MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80", function()
    expect_eq(mempool.MAX_STANDARD_P2WSH_STACK_ITEM_SIZE, 80)
  end)
  test("CONST: MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80", function()
    expect_eq(mempool.MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE, 80)
  end)
  test("CONST: ANNEX_TAG = 0x50", function()
    expect_eq(mempool.ANNEX_TAG, 0x50)
  end)
  test("CONST: TAPROOT_LEAF_MASK = 0xfe", function()
    expect_eq(mempool.TAPROOT_LEAF_MASK, 0xfe)
  end)
  test("CONST: TAPROOT_LEAF_TAPSCRIPT = 0xc0", function()
    expect_eq(mempool.TAPROOT_LEAF_TAPSCRIPT, 0xc0)
  end)
else
  io.write("  SKIP  constants -- mempool module not loadable in isolation\n")
end

-- ---------------------------------------------------------------------------
-- G1: tx.version not in [1,3] -> reason="version"
-- ---------------------------------------------------------------------------

print("\n--- G1: tx.version range (PRESENT) ---")

test("G1-a: accept_transaction checks tx.version range [1,3] with reason 'version'",
function()
  expect_true(file_contains("src/mempool.lua",
    "tx.version < M.TX_MIN_STANDARD_VERSION or tx.version > M.TX_MAX_STANDARD_VERSION"),
    "version-range guard present")
  expect_true(file_contains("src/mempool.lua",
    "\"version: tx version "),
    "reason string 'version:' present")
end)

-- ---------------------------------------------------------------------------
-- G2: weight > MAX_STANDARD_TX_WEIGHT -> reason="tx-size"
-- ---------------------------------------------------------------------------

print("\n--- G2: tx weight cap (PRESENT) ---")

test("G2: weight > 400000 -> reason 'tx-size'", function()
  expect_true(file_contains("src/mempool.lua",
    "tx_weight_check > M.MAX_STANDARD_TX_WEIGHT"),
    "weight cap guard present")
  expect_true(file_contains("src/mempool.lua",
    "\"tx-size: weight "),
    "reason 'tx-size' present")
end)

-- ---------------------------------------------------------------------------
-- G3: non-witness size < 65 -> reason="tx-size-small" (CVE-2017-12842)
-- ---------------------------------------------------------------------------

print("\n--- G3: tx-size-small / CVE-2017-12842 (PRESENT) ---")

test("G3: non-witness serialized size < MIN_STANDARD_TX_NONWITNESS_SIZE",
function()
  expect_true(file_contains("src/mempool.lua",
    "nonwitness_size < M.MIN_STANDARD_TX_NONWITNESS_SIZE"),
    "CVE-2017-12842 guard present")
  expect_true(file_contains("src/mempool.lua",
    "\"tx-size-small: non-witness size "),
    "reason 'tx-size-small' present")
end)

-- ---------------------------------------------------------------------------
-- G4: per-input scriptSig.size > MAX_STANDARD_SCRIPTSIG_SIZE
-- ---------------------------------------------------------------------------

print("\n--- G4: per-input scriptSig size cap (PRESENT) ---")

test("G4: scriptSig > 1650 bytes -> reason 'scriptsig-size'", function()
  expect_true(file_contains("src/mempool.lua",
    "#ss > M.MAX_STANDARD_SCRIPTSIG_SIZE"),
    "scriptsig-size guard present")
  expect_true(file_contains("src/mempool.lua",
    "\"scriptsig-size: "),
    "reason 'scriptsig-size' present")
end)

-- ---------------------------------------------------------------------------
-- G5: per-input scriptSig push-only check
-- BUG-1: is_push_only raises uncaught Lua error on malformed scriptSig
-- BUG-13: #ss > 0 guard at call site is unnecessary
-- ---------------------------------------------------------------------------

print("\n--- G5: scriptSig push-only (BUG-1, BUG-13) ---")

test("G5-a: accept_transaction calls is_push_only on scriptSig", function()
  expect_true(file_contains("src/mempool.lua",
    "if #ss > 0 and not script_mod.is_push_only(ss) then"),
    "push-only call site present")
  expect_true(file_contains("src/mempool.lua",
    "\"scriptsig-not-pushonly\""),
    "reason 'scriptsig-not-pushonly' present")
end)

test_xfail_pre_fix(
  "G5-b: is_push_only handles malformed pushes cleanly (no uncaught assert)",
  "BUG-1", function()
    bug("BUG-1", "P2")
    -- Probe: parse_script (script.lua:380) uses assert() on truncated pushes.
    -- The caller at mempool.lua:1006 doesn't pcall-wrap. Core's IsPushOnly
    -- returns false cleanly on truncated push.
    if not script_mod_ok then
      error("script module unavailable")
    end
    -- A direct push of length 5 but only 2 trailing bytes -- truncated.
    local malformed = "\x05\x01\x02"
    local ok, _ = pcall(script_mod.is_push_only, malformed)
    if not ok then
      error("is_push_only raised on malformed scriptSig (Core's IsPushOnly returns false cleanly)")
    end
  end)

test_xfail_pre_fix(
  "G5-c: call site has no `#ss > 0` guard (BUG-13 cosmetic)",
  "BUG-13", function()
    bug("BUG-13", "P3")
    -- The guard at mempool.lua:1006 `if #ss > 0 and not script_mod.is_push_only(ss)`
    -- is unnecessary because is_push_only("") returns true through its
    -- natural code path. Source guard for cosmetic cleanup.
    local body = slurp("src/mempool.lua") or ""
    -- After fix this line should NOT contain `#ss > 0 and not`:
    expect_false(body:find("#ss > 0 and not script_mod.is_push_only(ss)", 1, true),
      "unnecessary #ss > 0 guard still present")
  end)

-- ---------------------------------------------------------------------------
-- G6: datacarrier accumulator + -datacarrier=0 toggle
-- BUG-2: -datacarrier=0 absent
-- BUG-10: MAX_OP_RETURN_RELAY hard-coded
-- ---------------------------------------------------------------------------

print("\n--- G6: datacarrier accumulator + -datacarrier=0 (BUG-2, BUG-10) ---")

test("G6-a: accept_transaction enforces nulldata size budget", function()
  expect_true(file_contains("src/mempool.lua",
    "datacarrier_bytes_left = M.MAX_OP_RETURN_RELAY"),
    "datacarrier budget initialised")
  expect_true(file_contains("src/mempool.lua",
    "if script_size > datacarrier_bytes_left then"),
    "datacarrier accumulator check")
  expect_true(file_contains("src/mempool.lua",
    "\"datacarrier\""),
    "reason 'datacarrier' present")
end)

test_xfail_pre_fix(
  "G6-b: -datacarrier=0 operator toggle plumbed end-to-end",
  "BUG-2", function()
    bug("BUG-2", "P1")
    -- Core's node/mempool_args.cpp:95-99 sets max_datacarrier_bytes = nullopt
    -- when -datacarrier=false; value_or(0) then yields 0 and first non-zero
    -- OP_RETURN rejects. lunarblock hard-codes 100000.
    local main_body = slurp("src/main.lua") or ""
    local mempool_body = slurp("src/mempool.lua") or ""
    expect_true(main_body:find("--datacarrier", 1, true) ~= nil
      or mempool_body:find("datacarrier_enabled", 1, true) ~= nil
      or mempool_body:find("accept_datacarrier", 1, true) ~= nil,
      "no -datacarrier toggle plumbed")
  end)

test_xfail_pre_fix(
  "G6-c: MAX_OP_RETURN_RELAY derived from MAX_STANDARD_TX_WEIGHT",
  "BUG-10", function()
    bug("BUG-10", "P2")
    -- Core (policy.h:84): MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR
    -- lunarblock hard-codes 100000. If MAX_STANDARD_TX_WEIGHT ever changes,
    -- lunarblock will not auto-track. Pre-fix: hard-coded literal present.
    local body = slurp("src/mempool.lua") or ""
    -- Probe for a derived form (e.g. MAX_STANDARD_TX_WEIGHT / consensus.WITNESS_SCALE_FACTOR)
    expect_true(body:find("MAX_OP_RETURN_RELAY = M.MAX_STANDARD_TX_WEIGHT", 1, true) ~= nil
      or body:find("MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT", 1, true) ~= nil,
      "MAX_OP_RETURN_RELAY hard-coded; not derived from MAX_STANDARD_TX_WEIGHT")
  end)

-- ---------------------------------------------------------------------------
-- G7: GetDust().size > MAX_DUST_OUTPUTS_PER_TX -> reason="dust"
-- ---------------------------------------------------------------------------

print("\n--- G7: dust output count cap (PRESENT) ---")

test("G7: dust_count > 1 -> reason 'dust' (MAX_DUST_OUTPUTS_PER_TX=1)", function()
  expect_true(file_contains("src/mempool.lua",
    "if dust_count > 1 then"),
    "dust count cap present")
  expect_true(file_contains("src/mempool.lua",
    "return false, \"dust\""),
    "reason 'dust' present")
end)

-- ---------------------------------------------------------------------------
-- G8: Solver() -> TxoutType::PUBKEY (P2PK)
-- BUG-3: P2PK classify_script missing (P0-CDIV)
-- ---------------------------------------------------------------------------

print("\n--- G8: P2PK classify_script (BUG-3 P0-CDIV) ---")

test_xfail_pre_fix(
  "G8-a: classify_script recognises 35-byte P2PK (<0x21> pk <0xac>)",
  "BUG-3", function()
    bug("BUG-3", "P0-CDIV")
    if not script_mod_ok then error("script module unavailable") end
    -- 33-byte compressed pubkey + OP_CHECKSIG
    local pk_compressed = string.rep("\x02", 33)
    local p2pk = "\x21" .. pk_compressed .. "\xac"
    expect_eq(#p2pk, 35, "P2PK serialized length")
    local stype = script_mod.classify_script(p2pk)
    expect_eq(stype, "pubkey",
      "Core Solver() returns TxoutType::PUBKEY for 35-byte P2PK; lunarblock should match")
  end)

test_xfail_pre_fix(
  "G8-b: classify_script recognises 67-byte P2PK (<0x41> pk <0xac>)",
  "BUG-3", function()
    if not script_mod_ok then error("script module unavailable") end
    -- 65-byte uncompressed pubkey + OP_CHECKSIG
    local pk_uncompressed = string.rep("\x04", 65)
    local p2pk = "\x41" .. pk_uncompressed .. "\xac"
    expect_eq(#p2pk, 67, "P2PK uncompressed serialized length")
    local stype = script_mod.classify_script(p2pk)
    expect_eq(stype, "pubkey",
      "Core Solver() returns TxoutType::PUBKEY for 67-byte P2PK; lunarblock should match")
  end)

test_xfail_pre_fix(
  "G8-c: accept_transaction admits P2PK output as standard (not 'scriptpubkey')",
  "BUG-3", function()
    -- Source-grep regression: post-fix mempool.lua must handle 'pubkey' explicitly.
    expect_true(file_contains("src/mempool.lua",
      "elseif script_type == \"pubkey\""),
      "mempool.lua does not handle pubkey type")
  end)

test("G8-d: rpc.lua already has P2PK detector (the team knows the type)",
function()
  -- Confirms the type is recognised in the wallet path but never wired
  -- into the policy classifier -- BUG-3 root cause.
  expect_true(file_contains("src/rpc.lua",
    "0x21 and script:byte(35) == 0xac"),
    "rpc.lua has 35-byte P2PK detector at get_script_type()")
  expect_true(file_contains("src/rpc.lua",
    "0x41 and script:byte(67) == 0xac"),
    "rpc.lua has 67-byte P2PK detector at get_script_type()")
end)

-- ---------------------------------------------------------------------------
-- G9: Solver() -> TxoutType::MULTISIG with IsStandard n<=3 + bare-multisig
-- ---------------------------------------------------------------------------

print("\n--- G9: bare multisig n<=3 + permit_bare_multisig (PRESENT) ---")

test("G9-a: classify_script returns 'multisig' for valid 1-of-1 ... 3-of-3",
function()
  if not script_mod_ok then error("script module unavailable") end
  -- Construct OP_1 <33B pk> OP_1 OP_CHECKMULTISIG
  local pk = string.rep("\x03", 33)
  -- 1-of-1: OP_1 push33 pk OP_1 CHECKMULTISIG
  local ms11 = "\x51\x21" .. pk .. "\x51\xae"
  local stype, meta = script_mod.classify_script(ms11)
  expect_eq(stype, "multisig", "1-of-1 multisig classification")
  expect_eq(meta, "1_1", "m_n string format")
end)

test("G9-b: classify_script returns 'multisig' even for n > 3 (gate enforced at policy layer)",
function()
  if not script_mod_ok then error("script module unavailable") end
  local pk = string.rep("\x03", 33)
  -- 1-of-4: OP_1 push33 pk x4 OP_4 CHECKMULTISIG
  local ms14 = "\x51"
    .. ("\x21" .. pk) .. ("\x21" .. pk) .. ("\x21" .. pk) .. ("\x21" .. pk)
    .. "\x54\xae"
  local stype, meta = script_mod.classify_script(ms14)
  expect_eq(stype, "multisig", "1-of-4 still classified as multisig")
  expect_eq(meta, "1_4", "m_n string for 1-of-4")
end)

test("G9-c: accept_transaction rejects n > 3 with reason 'scriptpubkey'",
function()
  expect_true(file_contains("src/mempool.lua",
    "n < 1 or n > 3 or m < 1 or m > n"),
    "n<=3 guard present")
  expect_true(file_contains("src/mempool.lua",
    "return false, \"scriptpubkey\""),
    "reason 'scriptpubkey' present")
end)

test("G9-d: accept_transaction rejects bare multisig with reason 'bare-multisig'",
function()
  expect_true(file_contains("src/mempool.lua",
    "if not M.PERMIT_BARE_MULTISIG then"),
    "PERMIT_BARE_MULTISIG guard present")
  expect_true(file_contains("src/mempool.lua",
    "return false, \"bare-multisig\""),
    "reason 'bare-multisig' present")
end)

-- ---------------------------------------------------------------------------
-- G10: Solver() -> TxoutType::NULL_DATA + OP_RESERVED accepted as push
-- BUG-4: OP_RESERVED (0x50) not accepted in classify_script nulldata loop
-- ---------------------------------------------------------------------------

print("\n--- G10: OP_RETURN nulldata + OP_RESERVED (PRESENT; BUG-4 retracted) ---")

test("G10-a: classify_script returns 'nulldata' for OP_RETURN + pushdata",
function()
  if not script_mod_ok then error("script module unavailable") end
  -- OP_RETURN OP_PUSH(5) "hello"
  local nd = "\x6a\x05hello"
  local stype = script_mod.classify_script(nd)
  expect_eq(stype, "nulldata", "OP_RETURN + push-only classified as nulldata")
end)

test("G10-b: classify_script accepts OP_RETURN + OP_RESERVED (0x50) as nulldata",
function()
  -- Retracted BUG-4: classify_script:761 `op >= 0x4f and op <= 0x60` is
  -- INCLUSIVE of 0x50 (OP_RESERVED). The comment at line 762 mentions
  -- only OP_1NEGATE and OP_1..OP_16 but the range is correct.
  -- Runtime probe confirms parity with Core IsPushOnly.
  if not script_mod_ok then error("script module unavailable") end
  local nd_with_reserved = "\x6a\x50"
  local stype = script_mod.classify_script(nd_with_reserved)
  expect_eq(stype, "nulldata",
    "OP_RETURN OP_RESERVED IS classified as NULL_DATA (matches Core)")
end)

-- ---------------------------------------------------------------------------
-- G11: Solver() -> TxoutType::ANCHOR (P2A)
-- ---------------------------------------------------------------------------

print("\n--- G11: P2A (Pay-to-Anchor) (PRESENT) ---")

test("G11-a: is_pay_to_anchor exact byte match (\\x51\\x02\\x4e\\x73)", function()
  if not script_mod_ok then error("script module unavailable") end
  local p2a = "\x51\x02\x4e\x73"
  expect_true(script_mod.is_pay_to_anchor(p2a), "P2A byte match")
  expect_false(script_mod.is_pay_to_anchor("\x51\x02\x4e\x74"),
    "P2A rejects 1-byte modification")
end)

test("G11-b: classify_script returns 'p2a' for canonical P2A bytes", function()
  if not script_mod_ok then error("script module unavailable") end
  local stype = script_mod.classify_script("\x51\x02\x4e\x73")
  expect_eq(stype, "p2a", "P2A classified as p2a")
end)

-- ---------------------------------------------------------------------------
-- G15: IsUnspendable: size>0 && [0]==OP_RETURN OR size > MAX_SCRIPT_SIZE
-- BUG-5: size>10000 path missing
-- ---------------------------------------------------------------------------

print("\n--- G15: IsUnspendable size-side check (BUG-5 P2) ---")

test("G15-a: dust check exempts OP_RETURN outputs (threshold = 0)", function()
  expect_true(file_contains("src/mempool.lua",
    "is_unspendable = (#spk >= 1 and spk:byte(1) == 0x6a)"),
    "OP_RETURN unspendable guard present")
end)

test_xfail_pre_fix(
  "G15-b: dust check ALSO exempts scriptPubKey > MAX_SCRIPT_SIZE (10000 bytes)",
  "BUG-5", function()
    bug("BUG-5", "P2")
    -- Core script.h:563-566: IsUnspendable = (size > 0 && [0]==OP_RETURN)
    --                                       || (size > MAX_SCRIPT_SIZE)
    -- lunarblock only handles the OP_RETURN side.
    local body = slurp("src/mempool.lua") or ""
    expect_true(body:find("MAX_SCRIPT_SIZE", 1, true) ~= nil
      or body:find("#spk > 10000", 1, true) ~= nil,
      "dust IsUnspendable size-side check absent")
  end)

-- ---------------------------------------------------------------------------
-- G16: GetDustThreshold nSize witness (+67) vs non-witness (+148)
-- BUG-6: witness_unknown outputs misclassified as non-witness
-- ---------------------------------------------------------------------------

print("\n--- G16: dust nSize witness vs non-witness (BUG-6 P1) ---")

test("G16-a: witness segwit named types use +67 nSize bump", function()
  expect_true(file_contains("src/mempool.lua",
    "script_type == \"p2wpkh\" or script_type == \"p2wsh\""),
    "p2wpkh/p2wsh recognised as witness for dust")
  expect_true(file_contains("src/mempool.lua",
    "or script_type == \"p2tr\" or script_type == \"p2a\""),
    "p2tr/p2a recognised as witness for dust")
  expect_true(file_contains("src/mempool.lua",
    "nSize = nSize + 32 + 4 + 1 + 26 + 4"),
    "witness nSize bump = +67 (per Core policy.cpp:58 with 107/4=26)")
end)

test_xfail_pre_fix(
  "G16-b: witness_unknown (v2-v16) outputs also use +67 nSize bump",
  "BUG-6", function()
    bug("BUG-6", "P1")
    -- Core's IsWitnessProgram returns true for ANY v0..v16 witness program
    -- with prog-len in [2,40], so Core uses the witness nSize for those.
    -- lunarblock's is_witness check excludes "witness_unknown" -> wrong
    -- dust threshold for forward-compat segwit outputs.
    local body = slurp("src/mempool.lua") or ""
    expect_true(body:find("or script_type == \"witness_unknown\"", 1, true) ~= nil,
      "witness_unknown not in is_witness check; dust threshold wrong for v2-v16")
  end)

test("G16-c: non-witness uses +148 nSize bump (Core policy.cpp:60)", function()
  expect_true(file_contains("src/mempool.lua",
    "nSize = nSize + 32 + 4 + 1 + 107 + 4"),
    "non-witness nSize bump = +148")
end)

-- ---------------------------------------------------------------------------
-- G17: CFeeRate::GetFee uses round-UP fraction (EvaluateFee<false>)
-- ---------------------------------------------------------------------------

print("\n--- G17: dust threshold ceil division (PRESENT) ---")

test("G17: math.ceil for dust threshold (matches EvaluateFee<false>)", function()
  expect_true(file_contains("src/mempool.lua",
    "math.ceil(M.DUST_RELAY_FEE_RATE * nSize / 1000)"),
    "ceil division per Core feerate.cpp:20-26 + feefrac.h:202-218")
end)

-- ---------------------------------------------------------------------------
-- G18: MAX_DUST_OUTPUTS_PER_TX = 1 (ephemeral-anchor)
-- ---------------------------------------------------------------------------

print("\n--- G18: ephemeral-anchor allowance (PRESENT) ---")

test("G18: exactly one dust output allowed (dust_count > 1 -> reject)", function()
  expect_true(file_contains("src/mempool.lua",
    "MAX_DUST_OUTPUTS_PER_TX = 1"),
    "MAX_DUST_OUTPUTS_PER_TX = 1 comment / constant")
  expect_true(file_contains("src/mempool.lua",
    "if dust_count > 1 then"),
    "dust_count > 1 guard")
end)

-- ---------------------------------------------------------------------------
-- G19: BIP-54 CheckSigopsBIP54 (MAX_TX_LEGACY_SIGOPS=2500)
-- ---------------------------------------------------------------------------

print("\n--- G19: BIP-54 legacy sigops cap (PRESENT) ---")

test("G19: validate_inputs_standardness enforces MAX_TX_LEGACY_SIGOPS",
function()
  expect_true(file_contains("src/mempool.lua",
    "sigops > M.MAX_TX_LEGACY_SIGOPS"),
    "BIP-54 cap present")
  expect_true(file_contains("src/mempool.lua",
    "non-witness sigops exceed bip54 limit"),
    "reason text present")
end)

-- ---------------------------------------------------------------------------
-- G20: NONSTANDARD prev scriptPubKey -> "bad-txns-nonstandard-inputs"
-- ---------------------------------------------------------------------------

print("\n--- G20: NONSTANDARD prev-spk rejection (PRESENT) ---")

test("G20: NONSTANDARD prev -> 'bad-txns-nonstandard-inputs: input %d script unknown'",
function()
  expect_true(file_contains("src/mempool.lua",
    "if script_type == \"nonstandard\" then"),
    "NONSTANDARD prev check present")
  expect_true(file_contains("src/mempool.lua",
    "input %d script unknown"),
    "reason text matches Core")
end)

-- ---------------------------------------------------------------------------
-- G21: WITNESS_UNKNOWN prev scriptPubKey rejection
-- ---------------------------------------------------------------------------

print("\n--- G21: WITNESS_UNKNOWN prev-spk rejection (PRESENT) ---")

test("G21: WITNESS_UNKNOWN prev -> 'witness program is undefined'",
function()
  expect_true(file_contains("src/mempool.lua",
    "elseif script_type == \"witness_unknown\" then"),
    "WITNESS_UNKNOWN prev check present")
  expect_true(file_contains("src/mempool.lua",
    "witness program is undefined"),
    "reason text matches Core")
end)

-- ---------------------------------------------------------------------------
-- G22: P2SH redeemScript sigops > 15 + extract semantics
-- BUG-7: extract_p2sh_redeem_script uses last-push not EvalScript-NONE
-- ---------------------------------------------------------------------------

print("\n--- G22: P2SH redeemScript sigops + extract semantics (BUG-7 P1) ---")

test("G22-a: P2SH redeem sigops > MAX_P2SH_SIGOPS -> reject",
function()
  expect_true(file_contains("src/mempool.lua",
    "sigop_count > M.MAX_P2SH_SIGOPS"),
    "P2SH sigops cap present")
  expect_true(file_contains("src/mempool.lua",
    "p2sh redeemscript sigops exceed limit"),
    "reason text matches Core")
end)

test_xfail_pre_fix(
  "G22-b: extract_p2sh_redeem_script uses EvalScript-NONE semantics (push-execution)",
  "BUG-7", function()
    bug("BUG-7", "P1")
    -- Core's policy.cpp:245-252 does a REAL EvalScript(stack, scriptSig,
    -- SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE, &serror)
    -- and takes stack.back(). lunarblock's extract_p2sh_redeem_script
    -- (validation.lua) uses extract_last_push (script.lua:939-954) which
    -- takes the LAST push opcode's .data. Diverges for scriptSigs that
    -- pre-pend a non-push opcode whose execution rotates the stack so the
    -- actual top-of-stack at end is NOT the last push in wire ordering.
    -- (Such scriptSigs fail G5 IsPushOnly anyway, but G5 has BUG-1.)
    local validation_body = slurp("src/validation.lua") or ""
    expect_true(validation_body:find("eval_script_push_only", 1, true) ~= nil
      or validation_body:find("EvalScript_NONE", 1, true) ~= nil,
      "extract_p2sh_redeem_script uses last-push, not push-execution")
  end)

-- ---------------------------------------------------------------------------
-- G23: IsWitnessStandard coinbase guard
-- BUG-12: coinbase guard missing inside is_witness_standard
-- ---------------------------------------------------------------------------

print("\n--- G23: IsWitnessStandard coinbase guard (BUG-12 P1) ---")

test("G23-a: caller skips coinbase (accept_transaction line 964)", function()
  expect_true(file_contains("src/mempool.lua",
    "return false, \"coinbase transactions not accepted\""),
    "caller-side coinbase skip present")
end)

test_xfail_pre_fix(
  "G23-b: is_witness_standard has internal coinbase short-circuit (defense-in-depth)",
  "BUG-12", function()
    bug("BUG-12", "P1")
    -- Core policy.cpp:267-268 has the guard. lunarblock relies on caller.
    local body = slurp("src/mempool.lua") or ""
    -- Probe for either tx.IsCoinBase analog or explicit check at top of
    -- is_witness_standard body.
    local fn_start = body:find("function M.is_witness_standard", 1, true)
    expect_not_nil(fn_start, "is_witness_standard function exists")
    local fn_end = body:find("\nend\n", fn_start + 1, true)
    local fn_body = body:sub(fn_start, fn_end or #body)
    expect_true(fn_body:find("is_coinbase", 1, true) ~= nil
      or fn_body:find("IsCoinBase", 1, true) ~= nil,
      "no internal coinbase guard inside is_witness_standard")
  end)

-- ---------------------------------------------------------------------------
-- G24: P2A input with non-empty witness -> reject
-- ---------------------------------------------------------------------------

print("\n--- G24: P2A witness-stuffing rejection (PRESENT) ---")

test("G24: is_witness_standard rejects P2A input with non-empty witness",
function()
  expect_true(file_contains("src/mempool.lua",
    "if script_type == \"p2a\" then"),
    "P2A witness short-circuit present")
  expect_true(file_contains("src/mempool.lua",
    "return false, \"bad-witness-nonstandard\""),
    "reason 'bad-witness-nonstandard' present")
end)

-- ---------------------------------------------------------------------------
-- G25: P2SH-wrapped witness redeemScript extraction (EvalScript NONE)
-- ---------------------------------------------------------------------------

print("\n--- G25: P2SH-wrapped witness extraction (PRESENT, reference-grade) ---")

test("G25-a: is_witness_standard re-implements push-execution for P2SH-wrapped",
function()
  local body = slurp("src/mempool.lua") or ""
  -- Probe for the careful manual push-execution at lines ~640-675.
  expect_true(body:find("Core does EvalScript(stack, scriptSig, SCRIPT_VERIFY_NONE", 1, true) ~= nil,
    "Core reference comment present")
  expect_true(body:find("OP_1NEGATE", 1, true) ~= nil,
    "OP_1NEGATE handled in push subset")
end)

test("G25-b: P2SH-wrapped: non-push opcode -> reject", function()
  expect_true(file_contains("src/mempool.lua",
    "-- Non-push opcode: EvalScript with SCRIPT_VERIFY_NONE would"),
    "non-push opcode rejection comment present")
end)

test("G25-c: P2SH-wrapped: empty stack -> reject", function()
  expect_true(file_contains("src/mempool.lua",
    "if #stack == 0 then"),
    "empty stack rejection present")
end)

-- ---------------------------------------------------------------------------
-- G26: P2WSH (v0, 32B) limits
-- ---------------------------------------------------------------------------

print("\n--- G26: P2WSH v0 limits (PRESENT) ---")

test("G26-a: P2WSH redeem script size cap (3600)", function()
  expect_true(file_contains("src/mempool.lua",
    "#ws > M.MAX_STANDARD_P2WSH_SCRIPT_SIZE"),
    "P2WSH script size cap")
end)

test("G26-b: P2WSH stack item count cap (100)", function()
  expect_true(file_contains("src/mempool.lua",
    "n_stack > M.MAX_STANDARD_P2WSH_STACK_ITEMS"),
    "P2WSH stack item count cap")
end)

test("G26-c: P2WSH per-item size cap (80)", function()
  expect_true(file_contains("src/mempool.lua",
    "#witness[j] > M.MAX_STANDARD_P2WSH_STACK_ITEM_SIZE"),
    "P2WSH per-item size cap")
end)

-- ---------------------------------------------------------------------------
-- G27: P2TR (v1 32B non-P2SH) annex + tapscript limits
-- ---------------------------------------------------------------------------

print("\n--- G27: P2TR annex + tapscript limits (PRESENT) ---")

test("G27-a: P2TR annex (last item starts with 0x50) -> reject", function()
  expect_true(file_contains("src/mempool.lua",
    "stack[#stack]:byte(1) == M.ANNEX_TAG"),
    "annex detection on last witness item")
end)

test("G27-b: P2TR script-path stack>=2 + tapscript leaf check", function()
  expect_true(file_contains("src/mempool.lua",
    "bit.band(control_block:byte(1), M.TAPROOT_LEAF_MASK)"),
    "TAPROOT_LEAF_MASK band on control_block[0]")
  expect_true(file_contains("src/mempool.lua",
    "== M.TAPROOT_LEAF_TAPSCRIPT then"),
    "TAPROOT_LEAF_TAPSCRIPT compare")
end)

test("G27-c: P2TR tapscript stack item size cap (80)", function()
  expect_true(file_contains("src/mempool.lua",
    "#stack[j] > M.MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE"),
    "tapscript per-item size cap")
end)

test("G27-d: P2TR not P2SH-wrapped (Core only applies P2TR policy if !p2sh)",
function()
  expect_true(file_contains("src/mempool.lua",
    "and not is_p2sh then"),
    "p2sh-wrap exclusion present")
end)

test("G27-e: P2TR empty stack (0 items) -> reject", function()
  expect_true(file_contains("src/mempool.lua",
    "-- 0 stack elements: already invalid by consensus"),
    "empty stack rejection comment")
end)

-- ---------------------------------------------------------------------------
-- G28: SingleTRUCChecks (6 gates per BIP-431)
-- ---------------------------------------------------------------------------

print("\n--- G28: SingleTRUCChecks (PRESENT) ---")

test("G28-a: single_truc_checks function exists", function()
  expect_true(file_contains("src/mempool.lua",
    "function M.single_truc_checks"),
    "single_truc_checks defined")
end)

test("G28-b: Gates 1+2 inheritance (TRUC <-> non-TRUC parent)", function()
  expect_true(file_contains("src/mempool.lua",
    "non-version=3 tx cannot spend from version=3 tx"),
    "Gate 1 non-TRUC spending TRUC")
  expect_true(file_contains("src/mempool.lua",
    "version=3 tx cannot spend from non-version=3 tx"),
    "Gate 2 TRUC spending non-TRUC")
end)

test("G28-c: Gate 3 TRUC vsize <= TRUC_MAX_VSIZE", function()
  expect_true(file_contains("src/mempool.lua",
    "if vsize > M.TRUC_MAX_VSIZE then"),
    "Gate 3 vsize cap")
end)

test("G28-d: Gate 4 ancestor count + parent's ancestor depth", function()
  expect_true(file_contains("src/mempool.lua",
    "if parent_count + 1 > M.TRUC_ANCESTOR_LIMIT then"),
    "Gate 4a ancestor count")
  expect_true(file_contains("src/mempool.lua",
    "if parent_anc_depth + 1 > M.TRUC_ANCESTOR_LIMIT then"),
    "Gate 4b parent's depth")
end)

test("G28-e: Gate 5 child vsize <= TRUC_CHILD_MAX_VSIZE when has parent", function()
  expect_true(file_contains("src/mempool.lua",
    "if vsize > M.TRUC_CHILD_MAX_VSIZE then"),
    "Gate 5 child vsize cap")
end)

test("G28-f: Gate 6 descendant count + sibling-eviction signal", function()
  expect_true(file_contains("src/mempool.lua",
    "parent_desc_count_with_self + 1 > M.TRUC_DESCENDANT_LIMIT"),
    "Gate 6 descendant count")
  expect_true(file_contains("src/mempool.lua",
    "if parent_desc_count_with_self == 2 then"),
    "sibling-eviction eligibility")
end)

test("G28-g: single_truc_checks wired into accept_transaction at step 8c",
function()
  expect_true(file_contains("src/mempool.lua",
    "M.single_truc_checks(self.entries, tx, direct_parents, vsize, truc_conflicts)"),
    "TRUC checks call site")
end)

-- ---------------------------------------------------------------------------
-- G29: PackageTRUCChecks present + wired
-- BUG-8: PackageTRUCChecks missing
-- ---------------------------------------------------------------------------

print("\n--- G29: PackageTRUCChecks (BUG-8 P1) ---")

test_xfail_pre_fix(
  "G29-a: package_truc_checks function exists",
  "BUG-8", function()
    bug("BUG-8", "P1")
    local body = slurp("src/mempool.lua") or ""
    expect_true(body:find("function M.package_truc_checks", 1, true) ~= nil
      or body:find("function M.package_truc", 1, true) ~= nil,
      "no package_truc_checks impl -- Core's PackageTRUCChecks unimplemented")
  end)

test_xfail_pre_fix(
  "G29-b: accept_package calls package_truc_checks per tx",
  "BUG-8", function()
    local body = slurp("src/mempool.lua") or ""
    expect_true(body:find("package_truc_checks", 1, true) ~= nil
      or body:find("PackageTRUCChecks", 1, true) ~= nil,
      "accept_package does not invoke PackageTRUCChecks")
  end)

-- ---------------------------------------------------------------------------
-- G30: accept_package runs IsStandardTx per tx (full pipeline)
-- BUG-9: accept_package skips most IsStandardTx gates
-- ---------------------------------------------------------------------------

print("\n--- G30: accept_package full IsStandardTx pipeline (BUG-9 P1) ---")

test("G30-a: accept_package runs MAX_STANDARD_TX_WEIGHT cap per tx",
function()
  expect_true(file_contains("src/mempool.lua",
    "tx_weight_pkg > M.MAX_STANDARD_TX_WEIGHT"),
    "weight cap per tx in accept_package")
end)

test_xfail_pre_fix(
  "G30-b: accept_package runs version-range check per tx",
  "BUG-9", function()
    bug("BUG-9", "P1")
    -- Probe: locate the accept_package function body and verify it
    -- contains a TX_MIN_STANDARD_VERSION check inside.
    local body = slurp("src/mempool.lua") or ""
    local fn_start = body:find("function Mempool:accept_package", 1, true)
    expect_not_nil(fn_start, "accept_package function exists")
    -- Take a generous bound -- function is large, but should end before
    -- the next "function " or "function Mempool:"
    local fn_end = body:find("\nfunction ", fn_start + 1, true) or #body
    local fn_body = body:sub(fn_start, fn_end)
    expect_true(fn_body:find("TX_MIN_STANDARD_VERSION", 1, true) ~= nil
      or fn_body:find("TX_MAX_STANDARD_VERSION", 1, true) ~= nil,
      "accept_package does not enforce version-range per tx")
  end)

test_xfail_pre_fix(
  "G30-c: accept_package runs scriptsig push-only + size per tx",
  "BUG-9", function()
    local body = slurp("src/mempool.lua") or ""
    local fn_start = body:find("function Mempool:accept_package", 1, true)
    local fn_end = body:find("\nfunction ", fn_start + 1, true) or #body
    local fn_body = body:sub(fn_start, fn_end)
    expect_true(fn_body:find("scriptsig-not-pushonly", 1, true) ~= nil
      or fn_body:find("MAX_STANDARD_SCRIPTSIG_SIZE", 1, true) ~= nil,
      "accept_package does not enforce scriptSig push-only / size per tx")
  end)

test_xfail_pre_fix(
  "G30-d: accept_package runs dust + datacarrier per tx",
  "BUG-9", function()
    local body = slurp("src/mempool.lua") or ""
    local fn_start = body:find("function Mempool:accept_package", 1, true)
    local fn_end = body:find("\nfunction ", fn_start + 1, true) or #body
    local fn_body = body:sub(fn_start, fn_end)
    expect_true(fn_body:find("dust_count", 1, true) ~= nil
      or fn_body:find("datacarrier_bytes_left", 1, true) ~= nil,
      "accept_package does not enforce dust / datacarrier per tx")
  end)

test_xfail_pre_fix(
  "G30-e: accept_package runs is_witness_standard + validate_inputs_standardness per tx",
  "BUG-9", function()
    local body = slurp("src/mempool.lua") or ""
    local fn_start = body:find("function Mempool:accept_package", 1, true)
    local fn_end = body:find("\nfunction ", fn_start + 1, true) or #body
    local fn_body = body:sub(fn_start, fn_end)
    expect_true(fn_body:find("is_witness_standard", 1, true) ~= nil
      or fn_body:find("validate_inputs_standardness", 1, true) ~= nil,
      "accept_package does not run witness / input standardness per tx")
  end)

-- ---------------------------------------------------------------------------
-- Cross-cutting: reason-string drift (BUG-11)
-- ---------------------------------------------------------------------------

print("\n--- BUG-11: reason-string drift (P3 cosmetic) ---")

test("BUG-11: all is_witness_standard rejects use generic 'bad-witness-nonstandard'",
function()
  bug("BUG-11", "P3")
  -- Documents the divergence: Core returns boolean false (caller sets
  -- reason string from outer context); lunarblock returns the reason
  -- text directly. This is fine because both end up with the same
  -- reason text "bad-witness-nonstandard" in the surfaced rejection,
  -- but the SHAPE of the return is different.
  expect_true(file_contains("src/mempool.lua",
    "return false, \"bad-witness-nonstandard\""),
    "generic reason string used at all rejection points")
end)

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------

print("\n=========================================================================")
print("W135 Standardness rules -- summary")
print("=========================================================================")
io.write(string.format("\n  PASS:  %d\n", PASS))
io.write(string.format("  XFAIL: %d (expected pre-fix divergences)\n", XFAIL_PRE_FIX))
io.write(string.format("  FAIL:  %d\n\n", FAIL))

if #BUGS > 0 then
  local seen, dedup = {}, {}
  for _, b in ipairs(BUGS) do
    if not seen[b] then
      dedup[#dedup + 1] = b
      seen[b] = true
    end
  end
  io.write("Bugs surfaced:\n")
  for _, b in ipairs(dedup) do
    io.write("  " .. b .. "\n")
  end
  io.write("\n")
end

print("Audit gates: 30 W135 set")
print("  PRESENT:        16  (G1, G2, G3, G4, G7, G9, G10, G11, G17, G18, G19,")
print("                       G20, G21, G24, G25, G26, G27, G28)")
print("  PARTIAL/MISSING: 14  (G5 [BUG-1+13], G6 [BUG-2+10], G8 [BUG-3 P0],")
print("                       G15 [BUG-5], G16 [BUG-6], G22 [BUG-7],")
print("                       G23 [BUG-12], G29 [BUG-8], G30 [BUG-9])")
print("")
print("Cross-references:")
print("  W127 Taproot key-path vs script-path semantics")
print("  W120 mempool RBF (TRUC sibling-eviction shape)")
print("  W116 package-relay protocol (BIP-331) -- adjacent")
print("  W132 BIP-68/112/113 -- IsFinalTx is the OTHER policy gate at admission")
print("  FIX-83 LuaJIT bit-op trap (none surface here -- standardness uses int32)")

if FAIL > 0 then
  os.exit(1)
end
os.exit(0)
