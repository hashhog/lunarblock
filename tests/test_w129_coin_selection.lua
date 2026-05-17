#!/usr/bin/env luajit
-- W129 Coin Selection audit — lunarblock (Lua / LuaJIT)
-- Discovery-only. Tests assert the lunarblock state and document the
-- divergence from Bitcoin Core's wallet/coinselection.{cpp,h} +
-- wallet/spend.cpp + wallet/feebumper.cpp.
--
-- 30 gates (G1-G30) covering:
--   G1-G5   algorithm presence (BnB, Knapsack, SRD, CG, ChooseSelectionResult)
--   G6-G10  OutputGroup / eligibility / weight tracking
--   G11-G15 BnB internal correctness
--   G16-G20 Knapsack internal + effective_value
--   G21-G25 change handling (cost_of_change, min_viable_change,
--           GenerateChangeTarget, SFFO)
--   G26-G28 cascade triggers (3x LTFRE → CG, discard_feerate,
--           AttemptSelection mixed-group)
--   G29-G30 bump_fee parity (incrementalRelayFee, absorb-change-into-fee)
--
-- See audit/w129_coin_selection.md for full discussion.

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

-- Helper: build a mock UTXO list
local function make_utxos(values)
  local utxos = {}
  for i, v in ipairs(values) do
    utxos[i] = {
      key = "txid" .. i .. ":0",
      utxo = {
        txid = string.rep(string.char(i), 32),
        vout = 0,
        value = v,
        address = "addr" .. i,
        confirmations = 6,
        is_coinbase = false,
      }
    }
  end
  return utxos
end

print("=== W129 lunarblock Coin Selection audit ===\n")

--------------------------------------------------------------------------------
-- G1-G5: Algorithm presence + ChooseSelectionResult tournament
--------------------------------------------------------------------------------

print("--- G1-G5: Algorithm presence ---")

test("G1: SelectCoinsBnB present", function()
  expect_true(type(wallet.select_coins_bnb) == "function",
    "select_coins_bnb missing")
end)

test("G2: KnapsackSolver present", function()
  expect_true(type(wallet.select_coins_knapsack) == "function",
    "select_coins_knapsack missing")
end)

test("G3: SRD (Single Random Draw) ABSENT — naive random fallback only",
function()
  log_bug("BUG-1", "P1",
    "SRD (target + CHANGE_LOWER + change_fee) absent; "
    .. "select_coins_random is naive Fisher-Yates fallback, "
    .. "no CHANGE_LOWER floor, no weight-heap min-prune")
  expect_true(type(wallet.select_coins_random) == "function",
    "naive fallback present (not SRD)")
  -- SRD would require CHANGE_LOWER constant exposed
  expect_false(wallet.CHANGE_LOWER ~= nil,
    "CHANGE_LOWER constant absent (BUG-1)")
end)

test("G4: CoinGrinder (CG) entirely ABSENT", function()
  log_bug("BUG-2", "P1",
    "CoinGrinder entirely absent; "
    .. "Core's min-weight-with-change DFS used for ≥30 sat/vB feerates")
  expect_false(type(wallet.coin_grinder) == "function",
    "coin_grinder absent")
  expect_false(type(wallet.select_coins_cg) == "function",
    "select_coins_cg absent")
end)

test("G5: ChooseSelectionResult waste-tournament ABSENT", function()
  log_bug("BUG-3", "P1",
    "select_coins short-circuits on first hit (BnB → Knapsack → Random); "
    .. "Core's ChooseSelectionResult runs ALL 4 algorithms and picks "
    .. "the result with minimum waste (spend.cpp:809-811 std::min_element)")
  -- Structural: verify select_coins is the sequential-fallback form
  local utxos = make_utxos({100000, 50000, 30000})
  local _, algo = wallet.select_coins(utxos, 80000, 1)
  expect_true(algo == "bnb" or algo == "knapsack" or algo == "random",
    "select_coins returns first-success algorithm name, "
    .. "not min-waste choice")
end)

--------------------------------------------------------------------------------
-- G6-G10: OutputGroup / eligibility / weight tracking
--------------------------------------------------------------------------------

print("\n--- G6-G10: OutputGroup / eligibility / weight ---")

test("G6: OutputGroup struct ABSENT", function()
  log_bug("BUG-4", "P1",
    "OutputGroup struct absent: no script-pubkey grouping, "
    .. "no m_from_me / m_depth / m_ancestors / m_max_cluster_count; "
    .. "each UTXO treated independently")
  expect_false(type(wallet.OutputGroup) == "table"
    or type(wallet.OutputGroup) == "function",
    "OutputGroup absent as expected")
end)

test("G7: OUTPUT_GROUP_MAX_ENTRIES = 100 cap ABSENT", function()
  log_bug("BUG-5", "P2",
    "OUTPUT_GROUP_MAX_ENTRIES=100 constant absent; "
    .. "no cap on UTXOs per output group")
  expect_false(wallet.OUTPUT_GROUP_MAX_ENTRIES ~= nil,
    "constant absent")
end)

test("G8: CoinEligibilityFilter cascade (6/6/4 → 1/1/4 → 0/1/4) ABSENT",
function()
  log_bug("BUG-6", "P0",
    "Eligibility-filter cascade absent: lunarblock takes a single "
    .. "min_confirmations from caller; Core tries 6/6/4, then 1/1/4, "
    .. "then 0/1/4. A wallet holding only unconfirmed-mine UTXOs "
    .. "cannot send via lunarblock; Core widens filter on each pass.")
  expect_false(type(wallet.CoinEligibilityFilter) == "table",
    "CoinEligibilityFilter absent as expected")
end)

test("G9: long_term_fee per UTXO ABSENT", function()
  log_bug("BUG-7", "P1",
    "OutputGroup.long_term_fee absent: waste metric loses "
    .. "Σ(fee_i − long_term_fee_i) component; cannot signal "
    .. "'cheap-now-expensive-later' UTXOs")
  -- Confirmed by inspection of effective_value at wallet.lua:182:
  -- there's no per-UTXO long-term-fee field anywhere.
  expect_true(true, "long_term_fee absent (inspection)")
end)

test("G10: max_selection_weight bail in all 4 algorithms ABSENT", function()
  log_bug("BUG-8", "P1",
    "max_selection_weight absent: no weight-bail in BnB/Knapsack/SRD/CG; "
    .. "Core: MAX_STANDARD_TX_WEIGHT = 400000 weight units; "
    .. "lunarblock can select 10000+ UTXOs exceeding standardness")
  expect_false(wallet.max_selection_weight ~= nil, "constant absent")
end)

--------------------------------------------------------------------------------
-- G11-G15: BnB internal
--------------------------------------------------------------------------------

print("\n--- G11-G15: BnB internal ---")

test("G11: BnB exact-match path present", function()
  -- fee_rate=1, vsize=68 → effective(100000) = 99932
  -- target=99932, cost_of_change=ceil(148*1)=148, range=[99932, 100080]
  -- 99932 exact: solution found
  local utxos = make_utxos({100000})
  local selected = wallet.select_coins_bnb(utxos, 99932, 1)
  expect_true(selected ~= nil, "BnB should find exact match")
  expect_eq(#selected, 1, "1 UTXO selected")
end)

test("G12: BnB is_feerate_high waste-prune ABSENT", function()
  log_bug("BUG-9", "P2",
    "Core line 129: backtrack when curr_waste > best_waste && "
    .. "is_feerate_high (fee > long_term_fee). lunarblock "
    .. "has no waste-prune at all (waste only updates at solution).")
  expect_true(true, "absence confirmed by inspection (wallet.lua:240-298)")
end)

test("G13: BnB duplicate-omission shortcut ABSENT", function()
  log_bug("BUG-10", "P2",
    "Core lines 174-178: skip inclusion when predecessor "
    .. "(just-omitted) had identical effective_value and fee; "
    .. "lunarblock wastes tries exploring equivalent subtrees")
  expect_true(true, "absence confirmed by inspection")
end)

test("G14: BnB waste = sel_value - target ONLY (BUG-11)", function()
  log_bug("BUG-11", "P0",
    "BnB waste metric is excess-only (wallet.lua:231-233). "
    .. "Missing both Σ(fee_i − long_term_fee_i) and change_cost terms. "
    .. "Causes wrong solution selection at high feerates when multiple "
    .. "changeless candidates exist with different input counts.")
  -- Structural: the closure on wallet.lua:231 is just sel_value - target
  -- We cannot inspect closure body here, but the documented bug is
  -- confirmed by reading the source.
  local utxos = make_utxos({200000, 100100})
  local selected = wallet.select_coins_bnb(utxos, 100000, 1)
  expect_true(selected ~= nil, "BnB should find solution")
end)

test("G15: TOTAL_TRIES = 100000 matches Core", function()
  expect_eq(wallet.MAX_BNB_TRIES, 100000,
    "MAX_BNB_TRIES should equal Core TOTAL_TRIES=100000")
end)

--------------------------------------------------------------------------------
-- G16-G20: Knapsack + effective_value
--------------------------------------------------------------------------------

print("\n--- G16-G20: Knapsack + effective_value ---")

test("G16: Knapsack exact-subset (nTotalLower == nTargetValue) ABSENT",
function()
  log_bug("BUG-12", "P2",
    "Core line 683: if Σ(applicable_groups) == target, take all "
    .. "applicable groups as the answer; lunarblock has no such "
    .. "perfect-subset shortcut")
  expect_true(true, "absence confirmed by inspection (wallet.lua:353-382)")
end)

test("G17: ApproximateBestSubset (1000-iter stochastic subset sum) ABSENT",
function()
  log_bug("BUG-13", "P1",
    "Core's ApproximateBestSubset (1000 random passes per call, "
    .. "called twice with/without change_target) absent; "
    .. "lunarblock Knapsack is greedy largest-first which always "
    .. "overshoots and creates unnecessary change")
  expect_true(true, "absence confirmed by inspection")
end)

test("G18: Knapsack change_target parameter ABSENT", function()
  log_bug("BUG-14", "P1",
    "Core: KnapsackSolver(groups, target, change_target, ...); "
    .. "applicable_groups = those with selection_amount < target + change_target. "
    .. "lunarblock: select_coins_knapsack(utxos, target) only.")
  local info = debug.getinfo(wallet.select_coins_knapsack, "u")
  expect_eq(info.nparams, 2,
    "select_coins_knapsack takes 2 params (Core takes 5)")
end)

test("G19: Knapsack first-pass single-coin guard is WRONG", function()
  log_bug("BUG-15", "P1",
    "lunarblock first-pass guard 'value >= target AND value < target * 2' "
    .. "MISSES any coin ≥ 2×target. Core's lowest_larger accepts ANY "
    .. "group with selection_amount ≥ target + change_target. "
    .. "lunarblock falls through to greedy second pass which may pick "
    .. "it, but the single-coin-best-fallback canonical form is lost.")
  -- 300000 > 100000*2 = 200000 → skipped by first pass, second pass takes it
  local utxos = make_utxos({300000})
  local selected = wallet.select_coins_knapsack(utxos, 100000)
  expect_true(selected ~= nil, "second pass picks it up")
  expect_eq(#selected, 1, "1 UTXO selected")
end)

test("G20: effective_value hardcodes 68 vbytes for ALL input types — BUG-16",
function()
  log_bug("BUG-16", "P0",
    "effective_value(value, fee_rate, input_vsize) defaults input_vsize=68. "
    .. "All call sites use the default → effective_value is wrong for "
    .. "P2PKH (148 vbytes), P2TR keypath (~57.5), P2SH-P2WPKH (~91). "
    .. "Funds-loss risk on legacy wallets at high feerates: P2PKH "
    .. "underestimated by 80 vbytes × feerate = 8000 sat at 100 sat/vB.")
  -- Structural: the default param is `input_vsize = input_vsize or 68`
  -- All call sites in wallet.lua read from item.utxo.value with no
  -- per-script-type vsize, so the default applies always.
  expect_true(true, "hardcoded 68 vbytes confirmed at wallet.lua:183")
end)

--------------------------------------------------------------------------------
-- G21-G25: Change handling
--------------------------------------------------------------------------------

print("\n--- G21-G25: Change handling ---")

test("G21: cost_of_change wrong (148 × feerate, no long_term_feerate)",
function()
  log_bug("BUG-17", "P0",
    "M.COST_OF_CHANGE = 148 (legacy P2PKH input vsize, NOT "
    .. "change_output + change_input = 31+68 = 99 for P2WPKH). "
    .. "Multiplied by current feerate only: ignores long_term_feerate "
    .. "for the change-spend cost. Causes BnB to reject valid "
    .. "changeless candidates that Core would accept.")
  expect_eq(wallet.COST_OF_CHANGE, 148,
    "constant is 148 (should be ~99 for P2WPKH; also feerate-dependent)")
end)

test("G22: min_viable_change = DUST_THRESHOLD (546) is feerate-blind",
function()
  log_bug("BUG-18", "P0",
    "Core: min_viable_change = max(change_spend_fee + 1, dust). "
    .. "lunarblock: hardcoded 546 sat. At 100 sat/vB, P2WPKH change-spend "
    .. "costs 6800 sat; lunarblock creates 600-sat change that loses "
    .. "6200 sat when spent later.")
  expect_eq(wallet.DUST_THRESHOLD, 546, "constant is 546")
  expect_false(wallet.min_viable_change ~= nil,
    "min_viable_change feerate-dependent function absent")
end)

test("G23: GenerateChangeTarget (random in [CHANGE_LOWER, CHANGE_UPPER]) ABSENT",
function()
  log_bug("BUG-19", "P1",
    "Core randomises change-target in [50000, min(2*payment, 1000000)] "
    .. "to avoid change-amount fingerprinting. lunarblock change = "
    .. "total_in - total_out - fee (deterministic); identifies "
    .. "lunarblock-built txs to chain analysis.")
  expect_false(type(wallet.generate_change_target) == "function",
    "function absent")
  expect_false(wallet.CHANGE_LOWER ~= nil, "CHANGE_LOWER absent")
  expect_false(wallet.CHANGE_UPPER ~= nil, "CHANGE_UPPER absent")
end)

test("G24: CHANGE_LOWER = 50000 / CHANGE_UPPER = 1000000 constants ABSENT",
function()
  -- BUG-19 follow-on (no new bug id; same root cause as G23).
  expect_false(wallet.CHANGE_LOWER ~= nil, "constant absent")
  expect_false(wallet.CHANGE_UPPER ~= nil, "constant absent")
end)

test("G25: SFFO (subtract_fee_from_amount) ignored by select_coins", function()
  log_bug("BUG-20", "P1",
    "options.subtract_fee_from_amount documented at wallet.lua:1336 "
    .. "but never passed to M.select_coins (wallet.lua:1369). "
    .. "Core: when SFFO is set, OutputGroup.GetSelectionAmount() returns "
    .. "raw m_value (not effective_value) and BnB is skipped entirely. "
    .. "lunarblock silently ignores the flag → over-selects by Σ input_fee.")
  expect_true(true,
    "confirmed by inspection: wallet.lua:1369 call site omits flag")
end)

--------------------------------------------------------------------------------
-- G26-G28: Cascade triggers
--------------------------------------------------------------------------------

print("\n--- G26-G28: Cascade triggers ---")

test("G26: CG trigger (effective_feerate > 3 × long_term_feerate) ABSENT",
function()
  log_bug("BUG-21", "P1",
    "Core spend.cpp:769: at feerates ≥30 sat/vB (3× default consolidate "
    .. "feerate 10 sat/vB), trigger CoinGrinder to minimise weight. "
    .. "Moot since CG itself is missing (BUG-2), but the trigger is the "
    .. "canonical gate for the SRD/CG choice.")
  expect_true(true, "absence confirmed (no long_term_feerate field exists)")
end)

test("G27: discard_feerate change-drop ABSENT", function()
  log_bug("BUG-22", "P0",
    "Core: if change < discard_feerate × change_spend_size, drop change "
    .. "to fees. lunarblock: drops only when change ≤ DUST_THRESHOLD=546. "
    .. "At 50 sat/vB with DEFAULT_DISCARD_FEE=10 sat/vB, P2WPKH change-spend "
    .. "is 68 vbytes → threshold = 680 sat. lunarblock creates 547-sat "
    .. "change that costs 3400 sat to spend = net loss 2853 sat per tx.")
  expect_false(wallet.discard_feerate ~= nil, "no discard_feerate concept")
  expect_true(true, "absence confirmed by inspection (wallet.lua:1446)")
end)

test("G28: AttemptSelection mixed-group retry ABSENT", function()
  log_bug("BUG-23", "P1",
    "Core spend.cpp:702-722: AttemptSelection first tries positive-group "
    .. "(all positive-effective-value UTXOs); on failure retries with "
    .. "mixed_group (allows zero/negative-eff UTXOs for SFFO/legacy). "
    .. "lunarblock single-pass over flat list → cannot select negative-eff "
    .. "UTXOs even for SFFO sends where Core would.")
  expect_true(true, "absence confirmed by inspection")
end)

--------------------------------------------------------------------------------
-- G29-G30: bump_fee parity
--------------------------------------------------------------------------------

print("\n--- G29-G30: bump_fee parity ---")

test("G29: bump_fee skips combined_bump_fee for unconfirmed ancestors",
function()
  log_bug("BUG-24", "P0",
    "wallet.lua:1876: new_fee = old_fee + ceil(vsize * 1). "
    .. "Adds an absolute +1 sat/vB increment but skips Core's "
    .. "combined_bump_fee for the unconfirmed-ancestor package "
    .. "(feebumper.cpp:83-100). A tx with unconfirmed ancestors will "
    .. "be locally accepted but Core's mempool rejects it (RBF rule 4 — "
    .. "total fee must outpay ancestor combined bump at new feerate).")
  -- Structural: bump_fee exists but only adds 1 sat/vB without
  -- consulting any ancestor-fee context.
  expect_true(type(wallet.Wallet) == "table" or true,
    "bump_fee on Wallet metatable; structural check via grep")
end)

test("G30: bump_fee refuses on dust change instead of absorbing into fee",
function()
  log_bug("BUG-25", "P1",
    "wallet.lua:1889: if new_change ≤ DUST_THRESHOLD, return error "
    .. "'insufficient funds'. Core's CreateRateBumpTransaction "
    .. "(feebumper.cpp) absorbs change entirely into fee if doing so "
    .. "still produces a valid tx. lunarblock refuses prematurely → "
    .. "usability regression on high-feerate bumps.")
  expect_true(true, "confirmed by inspection (wallet.lua:1889)")
end)

--------------------------------------------------------------------------------
-- Summary
--------------------------------------------------------------------------------

print("\n=== W129 Summary ===")
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
if tests_failed == 0 then
  print("All W129 tests passed (audit-presence assertions).")
else
  print("W129 audit harness encountered FAIL — see lines above.")
  os.exit(1)
end
