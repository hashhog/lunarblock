#!/usr/bin/env luajit
-- W130 BIP-125 RBF feebumper Rule 3 audit — lunarblock (Lua / LuaJIT)
--
-- Discovery-only. Tests assert lunarblock's wallet-side bump-fee state and
-- document the divergence from Bitcoin Core's wallet/feebumper.cpp
-- (CheckFeeRate, EstimateFeeRate, CreateRateBumpTransaction) and the
-- policy/rbf.cpp::PaysForRBF Rule 3/4 invariant.
--
-- 30 gates (G1-G30) covering:
--   G1-G7   Rule 3 invariant decomposition (new_total_fee, combined_bump_fee,
--           minTotalFee, maxTxSize, strict-equal, incrementalRelayFee = max(
--           node, wallet) = 5 sat/vB)
--   G8-G10  Rule 4 invariant decomposition (additional_fees ≥ relay_fee *
--           replacement_vsize)
--   G11-G15 EstimateFeeRate floor-stack (orig+1, max(incremental), min floor,
--           mempool min when user-provided)
--   G16-G22 CreateRateBumpTransaction preconditions + plumbing
--           (HasWalletSpend, hasDescendantsInMempool, height>0, replaced_by,
--           require_mine, m_min_depth=1)
--   G23-G27 Replacement bookkeeping + commit-time semantics
--           (m_allow_other_inputs, mapValue[replaces_txid], MarkReplaced)
--   G28-G30 Recyclable change + outputs override
--
-- W129 BUG-24 re-verification: still PRESENT (re-classified W130 BUG-1).
--
-- See audit/w130_bip125_feebumper_rule3.md for full discussion.

package.path = "src/?.lua;" .. package.path

-- Custom loader for lunarblock modules
local loaders = package.loaders or package.searchers
table.insert(loaders, 2, function(module)
  local name = module:match("^lunarblock%.(.+)")
  if name then
    local filename = "src/" .. name .. ".lua"
    local f = io.open(filename)
    if f then
      f:close()
      return function() return dofile(filename) end
    end
  end
  return nil, "not found"
end)

local wallet = require("lunarblock.wallet")
local mempool_mod = require("lunarblock.mempool")

-- Test infrastructure -------------------------------------------------------
local tests_passed = 0
local tests_failed = 0
local bugs = {}

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then
    print("PASS: " .. name)
    tests_passed = tests_passed + 1
  else
    print("FAIL: " .. name)
    print("      " .. tostring(err))
    tests_failed = tests_failed + 1
  end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a)
      .. ", expected " .. tostring(b))
  end
end

local function expect_true(v, msg)
  if not v then error(msg or "expected true") end
end

local function expect_false(v, msg)
  if v then error(msg or "expected false") end
end

local function expect_ne(a, b, msg)
  if a == b then
    error((msg or "expected not equal") .. ": both are " .. tostring(a))
  end
end

local function log_bug(id, priority, desc)
  bugs[#bugs + 1] = {id = id, priority = priority, desc = desc}
end

-- Helper: read a file, return contents as string (for source-grep checks)
local function read_file(path)
  local f = io.open(path, "rb")
  if not f then return nil end
  local s = f:read("*a")
  f:close()
  return s
end

local WALLET_SRC = read_file("src/wallet.lua")
local MEMPOOL_SRC = read_file("src/mempool.lua")
assert(WALLET_SRC, "could not read src/wallet.lua")
assert(MEMPOOL_SRC, "could not read src/mempool.lua")

-- Core constants (from bitcoin-core; expected values)
local CORE_WALLET_INCREMENTAL_RELAY_FEE = 5000        -- sat/kvB (wallet.h:124)
local CORE_DEFAULT_INCREMENTAL_RELAY_FEE = 100         -- sat/kvB (policy/policy.h:48)
local CORE_DEFAULT_TRANSACTION_MAXFEE = 10000000       -- 0.1 BTC (COIN/10, wallet.h:137)

print("=== W130 lunarblock BIP-125 RBF feebumper Rule 3 audit ===\n")

--------------------------------------------------------------------------------
-- Rule 3 invariant decomposition (G1-G7)
--------------------------------------------------------------------------------

print("--- G1-G7: Rule 3 invariant decomposition ---")

test("G1: new_total_fee = newFeerate.GetFee(maxTxSize) + combined_bump_fee",
function()
  log_bug("BUG-1", "P0",
    "wallet.lua:1876: new_fee = old_fee + ceil(orig_vsize * 1). "
    .. "Core's new_total_fee = newFeerate.GetFee(maxTxSize) + "
    .. "combined_bump_fee.value() (feebumper.cpp:88). "
    .. "Replacement of tx-B (child of unconfirmed tx-A) must outpay "
    .. "tx-A's cluster deficit at the new feerate. lunarblock builds "
    .. "a replacement Core's mempool will reject under Rule 4 once "
    .. "MiniMiner is consulted. W129 BUG-24 RE-VERIFIED: STILL PRESENT.")
  -- Source-level: find the exact buggy line
  expect_true(
    WALLET_SRC:find("new_fee%s*=%s*old_fee%s*%+%s*math%.ceil%(orig_vsize%s*%*%s*1%)", 1, false)
      ~= nil,
    "wallet.lua:~1876 hardcodes +1 sat/vB increment (W129 BUG-24 line)")
  -- Verify no combined_bump_fee reference exists
  expect_false(WALLET_SRC:find("combined_bump_fee", 1, true) ~= nil,
    "combined_bump_fee NOT referenced in wallet.lua (BUG-1)")
end)

test("G2: MiniMiner / CalculateTotalBumpFees ABSENT", function()
  log_bug("BUG-2", "P0",
    "calculateCombinedBumpFee (interfaces.cpp:702) / "
    .. "MiniMiner::CalculateTotalBumpFees (mini_miner.cpp) walks the "
    .. "unconfirmed-ancestor cluster and returns the sum of additional "
    .. "fees required to make the cluster mine at target_feerate. "
    .. "lunarblock has no equivalent. Without this primitive BUG-1 "
    .. "cannot be fixed.")
  expect_false(WALLET_SRC:find("MiniMiner", 1, true) ~= nil,
    "MiniMiner symbol absent")
  expect_false(WALLET_SRC:find("calculate_combined_bump_fee", 1, true)
      ~= nil,
    "calculate_combined_bump_fee helper absent")
  expect_false(MEMPOOL_SRC:find("CalculateTotalBumpFees", 1, true)
      ~= nil,
    "CalculateTotalBumpFees absent in mempool")
end)

test("G3: minTotalFee = old_fee + incrementalRelayFee.GetFee(maxTxSize)",
function()
  log_bug("BUG-3", "P0",
    "lunarblock's de-facto minTotalFee is old_fee + ceil(orig_vsize "
    .. "* 1). Core: minTotalFee = old_fee + "
    .. "incrementalRelayFee.GetFee(maxTxSize) where (a) maxTxSize is "
    .. "the worst-case REPLACEMENT vsize (not orig) and (b) "
    .. "incrementalRelayFee = max(node, wallet=5 sat/vB). Product of "
    .. "(1×5 sat/vB) × (orig/replacement vsize) makes lunarblock's "
    .. "minTotalFee anywhere from 1× to 25× below Core's at the "
    .. "wallet boundary.")
  -- The Core invariant requires the constant 5 (sat/vB from WALLET_*).
  -- lunarblock multiplies by 1. Show the deviation numerically:
  local orig_vsize = 200
  local lunarblock_increment = math.ceil(orig_vsize * 1)
  local core_increment = math.ceil(orig_vsize * 5)   -- using wallet incremental
  expect_eq(lunarblock_increment, 200,
    "lunarblock: 200 vbyte * 1 sat/vB = 200 sat")
  expect_eq(core_increment, 1000,
    "Core: 200 vbyte * 5 sat/vB = 1000 sat (5× higher)")
end)

test("G4: maxTxSize derived from CalculateMaximumSignedTxSize ABSENT",
function()
  log_bug("BUG-4", "P1",
    "wallet.lua:1868 uses _compute_vsize(orig) — the ORIGINAL signed "
    .. "vsize. Core (feebumper.cpp:289) uses "
    .. "CalculateMaximumSignedTxSize(tx, wallet, coin_control).vsize, "
    .. "the WORST-CASE replacement signed vsize (with dummy "
    .. "max-size signatures and any added inputs). When "
    .. "m_allow_other_inputs becomes wired (BUG-15) maxTxSize must "
    .. "equal the worst-case replacement size, not the original.")
  expect_false(
    WALLET_SRC:find("calculate_maximum_signed_tx_size", 1, true)
      ~= nil,
    "calculate_maximum_signed_tx_size helper absent")
  expect_false(WALLET_SRC:find("max_signed_tx_size", 1, true) ~= nil,
    "max_signed_tx_size symbol absent")
end)

test("G5: Wallet-side Rule 3 check 'new_fee > old_fee' is wrong invariant",
function()
  log_bug("BUG-5", "P2",
    "wallet.lua:1880 'if new_fee <= old_fee then error'. Rule 3 is "
    .. "replacement_fees < original_fees at MEMPOOL (rbf.cpp:109) "
    .. "where original_fees = sum of ALL evicted txs. Wallet has no "
    .. "view of evicted-descendant fees so it cannot enforce Rule 3 "
    .. "here; the current check is a weak proxy strictly weaker than "
    .. "Core's CheckFeeRate 'new_total_fee < minTotalFee'.")
  expect_true(
    WALLET_SRC:find("if new_fee <= old_fee then", 1, true) ~= nil,
    "wrong-invariant proxy at wallet.lua:1880")
end)

test("G6: incrementalRelayFee = max(node, wallet) — lunarblock hardcodes 1 sat/vB",
function()
  log_bug("BUG-6", "P0",
    "wallet.lua:1876 hardcodes 1 sat/vB. Core: max("
    .. "node_relayIncrementalFee=0.1 sat/vB, "
    .. "WALLET_INCREMENTAL_RELAY_FEE=5 sat/vB) = 5 sat/vB. lunarblock "
    .. "5× too low → bumps fail Core's PaysForRBF Rule 4 at any "
    .. "tx ≥200 vbyte (200 × (5-1) = 800 sat shortfall). Funds at "
    .. "risk: user pays original fee + small bump but tx never "
    .. "enters Core's mempool.")
  -- WALLET_INCREMENTAL_RELAY_FEE constant should be 5000 (sat/kvB)
  expect_false(wallet.WALLET_INCREMENTAL_RELAY_FEE ~= nil,
    "WALLET_INCREMENTAL_RELAY_FEE constant absent on wallet module")
  -- And mempool.lua has INCREMENTAL_RELAY_FEE = 100 sat/kvB (correct
  -- policy default), but no WALLET-side variant.
  expect_eq(mempool_mod.INCREMENTAL_RELAY_FEE, 100,
    "mempool.INCREMENTAL_RELAY_FEE = 100 sat/kvB (policy.h:48)")
end)

test("G7: WALLET_INCREMENTAL_RELAY_FEE = 5000 sat/kvB constant defined",
function()
  -- Same bug class as G6; this test pins the missing constant.
  -- Note: the literal string 'WALLET_INCREMENTAL_RELAY_FEE' DOES
  -- appear in a comment at wallet.lua:1874 acknowledging the Core
  -- constant name — but no actual constant is exported on the wallet
  -- module, and the source value is wrong (says '1 sat/vB' in the
  -- comment).
  expect_false(wallet.WALLET_INCREMENTAL_RELAY_FEE ~= nil,
    "WALLET_INCREMENTAL_RELAY_FEE (= 5000 sat/kvB) constant not "
    .. "exported on wallet module")
  -- No assignment form 'WALLET_INCREMENTAL_RELAY_FEE = …':
  expect_false(
    WALLET_SRC:find("WALLET_INCREMENTAL_RELAY_FEE%s*=%s*5000",
      1, false) ~= nil,
    "no '= 5000' literal assignment")
  expect_false(
    WALLET_SRC:find("M%.WALLET_INCREMENTAL_RELAY_FEE", 1, false)
      ~= nil,
    "no M.WALLET_INCREMENTAL_RELAY_FEE constant assignment")
end)

--------------------------------------------------------------------------------
-- Rule 4 invariant decomposition (G8-G10)
--------------------------------------------------------------------------------

print("\n--- G8-G10: Rule 4 invariant decomposition ---")

test("G8: additional_fees >= relay_fee * replacement_vsize enforced wallet-side",
function()
  log_bug("BUG-7", "P1",
    "Wallet's bump_fee doesn't enforce Rule 4 itself; it relies on "
    .. "Mempool:accept_transaction (mempool.lua:1402-1409). That "
    .. "check is correct for direct-conflicts-without-ancestors, but "
    .. "the wallet shouldn't BUILD a replacement that fails Rule 4. "
    .. "Core's CheckFeeRate (feebumper.cpp:60-117) is the wallet-side "
    .. "gate; lunarblock has no equivalent.")
  -- Mempool-side IS present:
  expect_true(
    MEMPOOL_SRC:find(
      "additional_fee%s*=%s*fee%s*%-%s*conflicting_fees", 1, false)
      ~= nil,
    "mempool.lua:1404 'additional_fee = fee - conflicting_fees' "
    .. "present")
  -- Wallet-side is NOT:
  expect_false(WALLET_SRC:find("additional_fee", 1, true) ~= nil,
    "additional_fee symbol absent in wallet.lua")
  expect_false(WALLET_SRC:find("CheckFeeRate", 1, true) ~= nil,
    "CheckFeeRate equivalent absent in wallet.lua")
end)

test("G9: DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB (mempool) AND " ..
    "WALLET = 5000 sat/kvB",
function()
  -- Mempool default matches Core policy:
  expect_eq(mempool_mod.INCREMENTAL_RELAY_FEE, 100,
    "mempool default = 100 sat/kvB matches policy.h:48")
  -- Wallet-side wrapper missing:
  expect_false(wallet.WALLET_INCREMENTAL_RELAY_FEE ~= nil,
    "wallet-side 5000 sat/kvB missing (counts as BUG-6 follow-on)")
end)

test("G10: Rule 4 multiplied against REPLACEMENT vsize, not ORIGINAL vsize",
function()
  log_bug("BUG-8", "P1",
    "wallet.lua:1876 uses orig_vsize (ORIGINAL). Core's "
    .. "incrementalRelayFee.GetFee(maxTxSize) uses worst-case "
    .. "REPLACEMENT vsize. For a replacement that adds inputs "
    .. "(Core path with m_allow_other_inputs=true), maxTxSize > "
    .. "orig_vsize → Core requires more increment than lunarblock. "
    .. "Even without added inputs, segwit signature worst-case can "
    .. "shift vsize by 1-2 vbytes vs the original.")
  expect_true(
    WALLET_SRC:find("orig_vsize%s*%*%s*1", 1, false) ~= nil,
    "wallet.lua:1876 multiplies orig_vsize, not replacement vsize")
end)

--------------------------------------------------------------------------------
-- EstimateFeeRate floor-stack (G11-G15)
--------------------------------------------------------------------------------

print("\n--- G11-G15: EstimateFeeRate floor-stack ---")

test("G11: Original feerate += CFeeRate(1) (1 sat/kvB) ABSENT",
function()
  log_bug("BUG-9", "P2",
    "Core (feebumper.cpp:124-126): feerate(old_fee, txSize) + "
    .. "CFeeRate(1) — i.e. add 1 sat/kvB to defeat the integer-"
    .. "division truncation in (old_fee / txSize). lunarblock never "
    .. "computes 'original feerate' — works in absolute satoshis — "
    .. "so the rounding is unobservable, but the purpose (don't be "
    .. "off-by-one from original feerate) is also unfulfilled.")
  -- Note: the string 'EstimateFeeRate' appears in a comment at
  -- wallet.lua:1873 referencing the Core helper, but there is no
  -- equivalent function. Look for a real function/method.
  expect_false(
    WALLET_SRC:find("function%s+[%w._]*EstimateFeeRate", 1, false)
      ~= nil,
    "no EstimateFeeRate function defined")
  expect_false(
    WALLET_SRC:find("function%s+[%w._]*estimate_feebump_rate",
      1, false) ~= nil,
    "no estimate_feebump_rate function")
end)

test("G12: Feerate += max(node_incremental, wallet_incremental) ABSENT",
function()
  -- This is BUG-6 follow-on; same source symptom.
  expect_true(
    WALLET_SRC:find("math%.ceil%(orig_vsize%s*%*%s*1%)", 1, false)
      ~= nil,
    "lunarblock uses absolute add, no max(node, wallet) feerate calc")
end)

test("G13: Feerate clamped from below by GetMinimumFeeRate ABSENT",
function()
  log_bug("BUG-10", "P1",
    "Core (feebumper.cpp:140 + fees.cpp:29-76): chosen feerate "
    .. "clamped ≥ GetMinimumFeeRate(wallet, coin_control) = max("
    .. "m_min_fee, relayMinFee, mempoolMinFee, m_fallback_fee). "
    .. "lunarblock's default bump has no floor → in 'fallback-fee "
    .. "disabled + smart-fee unavailable' the bump can produce a "
    .. "sub-relay-fee replacement.")
  expect_false(
    WALLET_SRC:find("get_minimum_fee_rate", 1, true) ~= nil,
    "get_minimum_fee_rate helper absent")
  expect_false(
    WALLET_SRC:find("GetMinimumFeeRate", 1, true) ~= nil,
    "GetMinimumFeeRate symbol absent")
end)

test("G14: User-provided fee_rate STILL checked against mempool_min_fee ABSENT",
function()
  log_bug("BUG-11", "P1",
    "When caller provides options.fee_rate, lunarblock builds the "
    .. "replacement without checking newFeerate ≥ mempool min fee "
    .. "(Core CheckFeeRate:69 enforces 'newFeerate.GetFeePerK() < "
    .. "minMempoolFeeRate.GetFeePerK()' → error). lunarblock will "
    .. "build a sub-mempool-min replacement and only the mempool's "
    .. "accept_transaction will reject it with a different error.")
  -- The branch at wallet.lua:1870 takes options.fee_rate verbatim:
  expect_true(
    WALLET_SRC:find(
      "if options%.fee_rate and options%.fee_rate > 0 then", 1, false)
      ~= nil,
    "wallet.lua:1870 takes options.fee_rate without mempool-min check")
  expect_false(
    WALLET_SRC:find("min_relay_fee", 1, true) ~= nil
      or WALLET_SRC:find("mempool_min_fee", 1, true) ~= nil,
    "no min_relay_fee / mempool_min_fee guards on the user path")
end)

test("G15: EstimateFeeRate 4-step computation (orig+1 / max(incr) / floor / RBF)",
function()
  log_bug("BUG-12", "P1",
    "Core EstimateFeeRate: (1) old_fee/orig_size + 1 sat/kvB, "
    .. "(2) + max(node_incremental, wallet_incremental), "
    .. "(3) clamp ≥ GetMinimumFeeRate, (4) return CFeeRate. "
    .. "lunarblock collapses (1)+(2) into 'old_fee + orig_vsize * 1 "
    .. "sat/vB' and skips (3). Shape is 'absolute add' not 'feerate "
    .. "compute'.")
  -- Look for an actual function definition (not the comment ref):
  expect_false(
    WALLET_SRC:find("function%s+[%w._]*EstimateFeeRate", 1, false)
      ~= nil,
    "no EstimateFeeRate function defined")
  -- The default branch at wallet.lua:1872-1877 is an absolute add,
  -- not a feerate compute:
  expect_true(
    WALLET_SRC:find(
      "new_fee%s*=%s*old_fee%s*%+%s*math%.ceil%(orig_vsize%s*%*%s*1%)",
      1, false) ~= nil,
    "default branch is 'absolute add' not 'feerate compute'")
end)

--------------------------------------------------------------------------------
-- CreateRateBumpTransaction preconditions + plumbing (G16-G22)
--------------------------------------------------------------------------------

print("\n--- G16-G22: CreateRateBumpTransaction preconditions + plumbing ---")

test("G16: HasWalletSpend (no wallet-descendants) check ABSENT",
function()
  log_bug("BUG-13", "P1",
    "Core feebumper.cpp:25: if (wallet.HasWalletSpend(wtx.tx)) → "
    .. "'Transaction has descendants in the wallet'. lunarblock's "
    .. "PreconditionChecks (wallet.lua:1765-1775) doesn't have this. "
    .. "Without it: user bumps tx-A while tx-B is in the wallet "
    .. "spending tx-A → tx-B orphaned on replace.")
  expect_false(WALLET_SRC:find("HasWalletSpend", 1, true) ~= nil,
    "HasWalletSpend symbol absent")
  expect_false(WALLET_SRC:find("has_wallet_spend", 1, true) ~= nil,
    "has_wallet_spend helper absent")
  expect_false(WALLET_SRC:find("descendants in the wallet", 1, true)
      ~= nil,
    "error string absent")
end)

test("G17: hasDescendantsInMempool check ABSENT (BUG-13 follow-on)",
function()
  -- Same bug class; pin the second check.
  expect_false(
    WALLET_SRC:find("hasDescendantsInMempool", 1, true) ~= nil,
    "hasDescendantsInMempool symbol absent")
  expect_false(
    WALLET_SRC:find("has_descendants_in_mempool", 1, true) ~= nil,
    "has_descendants_in_mempool helper absent")
  expect_false(
    WALLET_SRC:find("descendants in the mempool", 1, true) ~= nil,
    "error string absent")
end)

test("G18: GetTxDepthInMainChain != 0 ('Transaction has been mined') PRESENT",
function()
  expect_true(
    WALLET_SRC:find(
      "entry%.height and entry%.height > 0", 1, false) ~= nil,
    "wallet.lua:1766 height > 0 guard present")
  expect_true(
    WALLET_SRC:find("has been mined", 1, true) ~= nil,
    "error string present")
end)

test("G19: replaced_by_txid check ('Cannot bump … already bumped') PRESENT",
function()
  expect_true(
    WALLET_SRC:find("entry%.replaced_by", 1, false) ~= nil,
    "wallet.lua:1770 entry.replaced_by guard present")
  expect_true(
    WALLET_SRC:find("Cannot bump transaction", 1, true) ~= nil,
    "error string present")
end)

test("G20: require_mine / AllInputsMine enforcement PRESENT", function()
  -- The per-input value reconstruction at wallet.lua:1785-1835
  -- effectively enforces require_mine: an input not in our utxos /
  -- pending_utxos / entry.input_values returns "Transaction contains
  -- inputs that don't belong to this wallet".
  expect_true(
    WALLET_SRC:find(
      "Transaction contains inputs that don't belong to this wallet",
      1, true) ~= nil,
    "wallet.lua:1813,1831 require_mine error present")
end)

test("G21: Sequence numbers preserved (≤0xFFFFFFFD) — replacement still " ..
    "signals RBF",
function()
  expect_true(
    WALLET_SRC:find("inp%.sequence", 1, false) ~= nil,
    "wallet.lua:1903 reuses inp.sequence in replacement")
  -- After bump, signals_rbf(new_tx) must still be true; tested via
  -- existing test_fix61 path.
end)

test("G22: new_coin_control.m_min_depth = 1 (Rule 2 wallet-side gate) ABSENT",
function()
  log_bug("BUG-14", "P1",
    "Core feebumper.cpp:312: new_coin_control.m_min_depth = 1 "
    .. "(BIP-125 Rule 2: replacement may not source new UNCONFIRMED "
    .. "inputs). lunarblock has no m_min_depth setting. If BUG-15 is "
    .. "fixed (without setting min_depth), wallet will pull "
    .. "unconfirmed UTXOs into the replacement → mempool rejects "
    .. "for Rule 2.")
  expect_false(WALLET_SRC:find("m_min_depth", 1, true) ~= nil,
    "m_min_depth symbol absent")
  expect_false(WALLET_SRC:find("min_depth", 1, true) ~= nil,
    "min_depth concept absent")
end)

--------------------------------------------------------------------------------
-- Replacement bookkeeping + commit-time semantics (G23-G27)
--------------------------------------------------------------------------------

print("\n--- G23-G27: Replacement bookkeeping + commit-time semantics ---")

test("G23: m_allow_other_inputs = true (wallet may add inputs) ABSENT",
function()
  log_bug("BUG-15", "P2",
    "Core feebumper.cpp:309: new_coin_control.m_allow_other_inputs "
    .. "= true. Wallet can ADD inputs to fund the bump when shrinking "
    .. "change isn't enough. lunarblock only shrinks the existing "
    .. "change output → high-feerate bump on a tx with small change "
    .. "fails with 'change after fee bump would be dust' where Core "
    .. "would have succeeded by pulling in more inputs.")
  expect_false(WALLET_SRC:find("m_allow_other_inputs", 1, true) ~= nil,
    "m_allow_other_inputs symbol absent")
  expect_false(WALLET_SRC:find("allow_other_inputs", 1, true) ~= nil,
    "allow_other_inputs helper absent")
  -- The bump path never calls select_coins:
  -- (look for 'select_coins(' inside the bump_fee body roughly
  -- between lines 1748 and 1929 — we slice between function header
  -- and the next top-level section divider.)
  local bump_start = WALLET_SRC:find("function Wallet:bump_fee", 1, true)
  local bump_end = WALLET_SRC:find("Wallet Info Queries", bump_start or 1, true)
    or #WALLET_SRC
  local bump_block = WALLET_SRC:sub(bump_start, bump_end)
  expect_false(bump_block:find("select_coins", 1, true) ~= nil,
    "bump_fee block doesn't call select_coins (no input-add path)")
end)

test("G24: mapValue['replaces_txid'] annotation ABSENT", function()
  log_bug("BUG-16", "P2",
    "Core feebumper.cpp:372: mapValue['replaces_txid'] = "
    .. "oldWtx.GetHash().ToString(). lunarblock's bump_fee returns "
    .. "(new_tx, old_fee, new_fee, input_utxos); relies on caller "
    .. "of submit_transaction to pass meta.replaces. If caller "
    .. "forgets, entry.replaced_by is never set → a second bumpfee "
    .. "on the same original tx is accepted (BUG-class double-pay).")
  expect_false(WALLET_SRC:find("replaces_txid", 1, true) ~= nil,
    "replaces_txid mapValue absent")
end)

test("G25: MarkReplaced wired through bump_fee return path", function()
  -- Partial: replaced_by IS set, but only by submit_transaction when
  -- it receives meta.replaces; bump_fee itself doesn't auto-populate.
  expect_true(
    WALLET_SRC:find("old%.replaced_by%s*=%s*txid_hex", 1, false)
      ~= nil,
    "wallet.lua:1588 replaced_by set ONLY by submit_transaction (no "
    .. "automatic wire-up from bump_fee)")
  -- bump_fee itself doesn't call MarkReplaced equivalent:
  local bump_start = WALLET_SRC:find("function Wallet:bump_fee", 1, true)
  local bump_end = WALLET_SRC:find("Wallet Info Queries", bump_start or 1, true)
    or #WALLET_SRC
  local bump_block = WALLET_SRC:sub(bump_start, bump_end)
  -- Note: the function body checks 'entry.replaced_by' as a precondition
  -- (BUG-19 PRESENT) but never SETS replaced_by itself.  We test for
  -- the assignment form 'replaced_by =' specifically.
  expect_false(bump_block:find("replaced_by%s*=", 1, false) ~= nil,
    "bump_fee block has no 'replaced_by =' assignment "
    .. "(side-effect lives in submit_transaction)")
end)

test("G26: CommitTransaction with mapValue.replaces_txid semantics ABSENT",
function()
  -- BUG-16 follow-on; same source observation.
  expect_false(WALLET_SRC:find("replaces_txid", 1, true) ~= nil,
    "mapValue['replaces_txid'] absent at commit time")
end)

test("G27: MarkReplaced failure path ABSENT", function()
  log_bug("BUG-17", "P2",
    "Core feebumper.cpp:378-380: if wallet.MarkReplaced(oldHash, "
    .. "bumped_txid) returns false → append 'Created new bumpfee "
    .. "transaction but could not mark the original transaction as "
    .. "replaced' to errors but commit. Edge case — lunarblock has "
    .. "no failure path because replaced_by assignment is "
    .. "unconditional when meta.replaces is passed.")
  expect_false(
    WALLET_SRC:find("could not mark the original", 1, true) ~= nil,
    "MarkReplaced failure error string absent")
end)

--------------------------------------------------------------------------------
-- Recyclable change + outputs override (G28-G30)
--------------------------------------------------------------------------------

print("\n--- G28-G30: Recyclable change + outputs override ---")

test("G28: options.outputs (override recipient set) ABSENT", function()
  -- We don't log a separate bug here; G28-G30 collectively fall under
  -- BUG-15 / BUG-16's missing-bumpfee-API note. Test pins the gap.
  expect_false(WALLET_SRC:find("options%.outputs", 1, false) ~= nil,
    "options.outputs not handled in bump_fee")
end)

test("G29: options.original_change_index (recycle specific output) ABSENT",
function()
  -- The string 'original_change_index' DOES occur in a comment
  -- (wallet.lua:1839) acknowledging the Core API gap, but there is no
  -- functional handling of an options.original_change_index field
  -- in the bump_fee body.
  expect_false(
    WALLET_SRC:find("options%.original_change_index", 1, false) ~= nil,
    "options.original_change_index field not handled in body")
  expect_false(
    WALLET_SRC:find("original_change_index%s*=", 1, false) ~= nil,
    "no assignment to original_change_index anywhere")
  -- lunarblock auto-detects change: first wallet-owned output.
  expect_true(
    WALLET_SRC:find(
      "Core's CreateRateBumpTransaction accepts an explicit",
      1, true) ~= nil,
    "lunarblock's source-comment acknowledges the gap "
    .. "(wallet.lua:1839)")
end)

test("G30: Mutually-exclusive outputs + original_change_index check ABSENT",
function()
  expect_false(
    WALLET_SRC:find(
      "options and 'original_change_index' are incompatible",
      1, true) ~= nil,
    "mutual-exclusion check absent")
end)

--------------------------------------------------------------------------------
-- W129 BUG-24 re-verification
--------------------------------------------------------------------------------

print("\n--- W129 BUG-24 re-verification ---")

test("W129 BUG-24 STILL PRESENT (re-classified W130 BUG-1)", function()
  -- The exact buggy line is unchanged since W129 (commit 0889c56).
  expect_true(
    WALLET_SRC:find(
      "new_fee%s*=%s*old_fee%s*%+%s*math%.ceil%(orig_vsize%s*%*%s*1%)",
      1, false) ~= nil,
    "wallet.lua:1876 STILL hardcoded '1 sat/vB' increment as of W130 "
    .. "audit. W129 0889c56 → W130 (no FIX between waves).")
end)

--------------------------------------------------------------------------------
-- Cross-reference: mempool-side Rule 4 is correctly enforced (W120)
--------------------------------------------------------------------------------

print("\n--- Cross-ref: mempool-side Rule 4 enforcement ---")

test("Mempool-side Rule 4 (additional_fee >= INCREMENTAL_RELAY_FEE * " ..
    "vsize) PRESENT",
function()
  expect_true(
    MEMPOOL_SRC:find(
      "required_additional%s*=%s*math%.ceil%(M%.INCREMENTAL_RELAY_FEE%s*%*%s*vsize%s*/%s*1000%)",
      1, false) ~= nil,
    "mempool.lua:1405 mempool-side Rule 4 enforced (W120 G19-G21)")
  expect_eq(mempool_mod.INCREMENTAL_RELAY_FEE, 100,
    "policy.h:48 default = 100 sat/kvB matches")
end)

test("Mempool-side Rule 3 (fee < conflicting_fees) PRESENT", function()
  expect_true(
    MEMPOOL_SRC:find(
      "if fee < conflicting_fees then", 1, true) ~= nil,
    "mempool.lua:1397 mempool-side Rule 3 enforced (W120 G16)")
end)

--------------------------------------------------------------------------------
-- LuaJIT bit-ops trap check (per FIX-83)
--------------------------------------------------------------------------------

print("\n--- FIX-83 bit-ops trap check (fee arithmetic) ---")

test("bump_fee fee arithmetic uses no LuaJIT bit.lshift / bit.band " ..
    "(no FIX-83 trap)",
function()
  local bump_start = WALLET_SRC:find("function Wallet:bump_fee", 1, true)
  local bump_end = WALLET_SRC:find("Wallet Info Queries", bump_start or 1, true)
    or #WALLET_SRC
  local bump_block = WALLET_SRC:sub(bump_start, bump_end)
  -- bit.band/bit.rshift ARE used at wallet.lua:1787-1791 for outpoint
  -- INDEX serialization (32-bit by spec; no trap), but no bit.lshift
  -- on fee amounts.
  expect_false(bump_block:find("bit%.lshift", 1, false) ~= nil,
    "no bit.lshift in bump_fee fee arithmetic")
  -- Fee math is plain Lua doubles via math.ceil + arithmetic ops.
  expect_true(
    bump_block:find("math%.ceil%(orig_vsize", 1, false) ~= nil,
    "fee math uses math.ceil + plain arithmetic (no FIX-83 trap)")
end)

--------------------------------------------------------------------------------
-- Summary
--------------------------------------------------------------------------------

print("\n=== W130 Summary ===")
print(string.format("Tests passed: %d / Tests failed: %d",
  tests_passed, tests_failed))
print(string.format("Bugs documented: %d", #bugs))
print("")

-- Count by priority
local by_prio = {P0 = 0, P1 = 0, P2 = 0, P3 = 0}
for _, b in ipairs(bugs) do
  by_prio[b.priority] = (by_prio[b.priority] or 0) + 1
end
print(string.format(
  "By priority: P0=%d  P1=%d  P2=%d  P3=%d",
  by_prio.P0, by_prio.P1, by_prio.P2, by_prio.P3))
print("")

if #bugs > 0 then
  print("Bug list:")
  for _, bug in ipairs(bugs) do
    local short = bug.desc:sub(1, 80)
    if bug.desc:len() > 80 then short = short .. "..." end
    print(string.format("  %s (%s): %s", bug.id, bug.priority, short))
  end
end

print("")
print("W129 BUG-24 re-verification: STILL PRESENT "
  .. "(re-classified as W130 BUG-1 + companions BUG-2/3/6/8).")
print("")

if tests_failed == 0 then
  print("All W130 tests passed (audit-presence assertions).")
else
  print("W130 audit harness encountered FAIL — see lines above.")
  os.exit(1)
end
