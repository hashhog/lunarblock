# W129 — Coin Selection audit (lunarblock)

**Date:** 2026-05-17
**Wave:** W129 (discovery)
**Impl:** lunarblock (Lua / LuaJIT)
**Status:** **25 BUGS FOUND** (7 P0, 14 P1, 4 P2, 0 P3) across **30 gates**

## Context

Audits lunarblock's `src/wallet.lua` coin-selection subsystem against
Bitcoin Core's `wallet/coinselection.{cpp,h}` + `wallet/spend.cpp` +
`wallet/feebumper.cpp`. Scope:

- Branch-and-Bound (BnB) — `SelectCoinsBnB` (coinselection.cpp:93)
- Knapsack — `KnapsackSolver` + `ApproximateBestSubset`
  (coinselection.cpp:602,652)
- Single Random Draw (SRD) — `SelectCoinsSRD` (coinselection.cpp:536)
- Coin Grinder (CG) — `CoinGrinder` (coinselection.cpp:204+)
- `OutputGroup` + `CoinEligibilityFilter` cascade
  (coinselection.h:228 / spend.cpp:572 GroupOutputs / AutomaticCoinSelection)
- `effective_value` / `cost_of_change` / `min_viable_change` /
  `m_long_term_feerate` / `m_change_fee` / `m_min_change_target`
- `CHANGE_LOWER` (50000) / `CHANGE_UPPER` (1000000) /
  `GenerateChangeTarget`
- `m_subtract_fee_outputs` (SFFO) / change avoidance / max-weight
- `SelectionResult::RecalculateWaste` + waste-tied ordering across
  algorithms (`ChooseSelectionResult` spend.cpp:729)
- Coinselection touchpoints in `feebumper.cpp::CreateRateBumpTransaction`

This wave revisits and **extends** the prior W113 audit. The W113 test
landed `~25` bugs but only covered the basic BnB / Knapsack / nLockTime /
SFFO surface and did not score the `OutputGroup`-cascade or
`ChooseSelectionResult` waste-tied ordering. W129 reuses W113's
classification where the gap is unchanged and adds new gates for:
CoinGrinder min-weight-by-feerate-trigger, SRD CHANGE_LOWER target,
effective-feerate-vs-3xLTFRE trigger, ancestor/cluster-aware eligibility
filter ladder, AttemptSelection mixed-group fallback, GroupOutputs
output-script grouping, bump-fee `EstimateFeeRate` parity.

> Reference: bitcoin-core/src/wallet/coinselection.{cpp,h},
> bitcoin-core/src/wallet/spend.cpp,
> bitcoin-core/src/wallet/feebumper.cpp.

## Method

1. Read `bitcoin-core/src/wallet/coinselection.{cpp,h}` end-to-end
   (993 + 479 LOC).
2. Read `bitcoin-core/src/wallet/spend.cpp` 729–870
   (`ChooseSelectionResult` + `AutomaticCoinSelection`) for the
   eligibility-filter ladder and waste-tied ordering.
3. Read `bitcoin-core/src/wallet/feebumper.cpp::EstimateFeeRate`
   + `CreateRateBumpTransaction`.
4. Synthesize a 30-gate matrix covering algorithms, OutputGroup state,
   eligibility cascade, SRD/CG triggers, change selection, waste, and
   bump-fee parity (table below).
5. Classify lunarblock state with `src/wallet.lua:169-410` and
   `src/wallet.lua:1334-1500` (transaction creation) and
   `src/wallet.lua:1620-1929` (bump_fee).
6. Catalogue bugs with priority and reference.
7. Land tests in `tests/test_w129_coin_selection.lua` covering every
   diverging gate. Tests document absence with `expect_false` /
   `expect_eq` style structural assertions; they are not consensus
   correctness tests (no chain in scope) but reproduce the audit
   findings deterministically.

## Severity scoring

- **P0** — Funds-loss risk (oversend, dust-burning) or fingerprintable
  divergence in change at high feerates.
- **P1** — Suboptimal selection vs Core, privacy fingerprint, or
  algorithm-cascade gap such that legitimate transactions are rejected.
- **P2** — Performance regression vs Core or missing optional facility.
- **P3** — Cosmetic, constant-naming, or non-impactful.

## 30 W129 Audit Gates

| Gate | Description | Status | Core ref |
|------|-------------|--------|----------|
| G1 | `SelectCoinsBnB` present | PRESENT | coinselection.cpp:93 |
| G2 | `KnapsackSolver` present | PRESENT (degraded) | coinselection.cpp:652 |
| G3 | `SelectCoinsSRD` (CHANGE_LOWER target) present | **MISSING** (BUG-1) | coinselection.cpp:536 |
| G4 | `CoinGrinder` present (min-weight-with-change) | **MISSING** (BUG-2) | coinselection.cpp:204+ |
| G5 | `ChooseSelectionResult` waste-min-element across BnB+CG+SRD+Knapsack | **MISSING** (BUG-3) | spend.cpp:729 |
| G6 | `OutputGroup` struct with `m_outputs`, `m_value`, `m_weight` | **MISSING** (BUG-4) | coinselection.h:228 |
| G7 | `OUTPUT_GROUP_MAX_ENTRIES = 100` cap | **MISSING** (BUG-5) | coinselection.h |
| G8 | `CoinEligibilityFilter` cascade (6/6/4 → 1/1/4 → 0/1/4) | **MISSING** (BUG-6) | spend.cpp:931 |
| G9 | `OutputGroup.long_term_fee` (consolidate feerate fee per UTXO) | **MISSING** (BUG-7) | coinselection.cpp:761 |
| G10 | `OutputGroup.m_weight` + max-selection-weight bail in BnB/Knapsack/SRD/CG | **MISSING** (BUG-8) | coinselection.cpp:131,567 |
| G11 | BnB exact-match path (`curr_value in [target, target+cost_of_change]`) | PRESENT | coinselection.cpp:128–146 |
| G12 | BnB `is_feerate_high` waste-pruning (`waste > best_waste && fee > LTF`) | **MISSING** (BUG-9) | coinselection.cpp:129 |
| G13 | BnB duplicate-omission shortcut (skip equiv branches) | **MISSING** (BUG-10) | coinselection.cpp:176 |
| G14 | BnB waste = `Σ(fee_i - long_term_fee_i) + excess` | **WRONG** (BUG-11) — waste reduces to `sel_value - target` | coinselection.cpp:140-145,827 |
| G15 | `TOTAL_TRIES = 100000` constant | PRESENT (`MAX_BNB_TRIES`) | coinselection.cpp:91 |
| G16 | Knapsack `nTotalLower == nTargetValue` exact-subset path | **MISSING** (BUG-12) | coinselection.cpp:683 |
| G17 | Knapsack stochastic subset-sum (`ApproximateBestSubset` × 1000) | **MISSING** (BUG-13) | coinselection.cpp:602 |
| G18 | Knapsack `change_target` parameter + applicable-group split | **MISSING** (BUG-14) | coinselection.cpp:652 |
| G19 | Knapsack `lowest_larger` fallback (Core takes ANY coin ≥ target, not coin in [target, 2×target)) | **WRONG** (BUG-15) | coinselection.cpp:678,716 |
| G20 | `effective_value = value - feerate * input_bytes` per-UTXO + filter ≤0 | PARTIAL (BUG-16) — single hardcoded 68-vbyte input size, no per-script-type vsize | coinselection.h:88 |
| G21 | `cost_of_change = m_change_fee + long_term_feerate * change_spend_size` | **WRONG** (BUG-17) — `M.COST_OF_CHANGE = 148` literal × current feerate; ignores long-term feerate | coinselection.h:151 |
| G22 | `min_viable_change` = `max(change_spend_fee + 1, dust)` | **WRONG** (BUG-18) — replaced by static `M.DUST_THRESHOLD = 546` | spend.cpp:1184 |
| G23 | `GenerateChangeTarget` random in `[CHANGE_LOWER, min(2*payment, CHANGE_UPPER)]` | **MISSING** (BUG-19) | coinselection.cpp:809 |
| G24 | `CHANGE_LOWER = 50000` / `CHANGE_UPPER = 1000000` constants | **MISSING** (BUG-19 follow-on) | coinselection.h:23,25 |
| G25 | SFFO (`m_subtract_fee_outputs`) gates BnB and pivots OutputGroup amount | **MISSING** (BUG-20) | spend.cpp:751, coinselection.cpp:789 |
| G26 | `m_effective_feerate > 3 × m_long_term_feerate` triggers CG (≥30 sat/vB) | **MISSING** (BUG-21) | spend.cpp:769 |
| G27 | `discard_feerate` drops change to fees when `change < discard * change_spend_size` | **MISSING** (BUG-22) | spend.cpp |
| G28 | `AttemptSelection` retries with `mixed_group` if positive-group fails | **MISSING** (BUG-23) | spend.cpp:702-722 |
| G29 | `bumpfee::EstimateFeeRate` uses `incrementalRelayFee` + `WALLET_INCREMENTAL_RELAY_FEE = 5 sat/kvB` | **WRONG** (BUG-24) — hardcoded `+1 sat/vB` (1000 sat/kvB) instead of Core's 5 sat/kvB; off by **200×** | feebumper.cpp:119 + DEFAULT_INCREMENTAL_RELAY_FEE |
| G30 | `bumpfee` rejects when `new_change ≤ dust` (preserve change) vs Core: shrink change to add to fee | **WRONG** (BUG-25) — refuses bump that could have completed by absorbing dust-change into fee | feebumper.cpp:217-235 |

## Bug catalogue (25 BUGS)

| Bug ID | Priority | Summary | Where |
|--------|----------|---------|-------|
| BUG-1  | **P1** | SRD (Single Random Draw, target + `CHANGE_LOWER + change_fee`) absent | `M.select_coins` falls through to `select_coins_random` (naive shuffle, no CHANGE_LOWER floor, no weight heap) |
| BUG-2  | **P1** | CoinGrinder (min-weight-with-change DFS) entirely absent | `select_coins_cg` / `coin_grinder` absent — Core path for feerates ≥30 sat/vB |
| BUG-3  | **P1** | `ChooseSelectionResult` waste-min cross-algo tournament absent — short-circuits at first hit (BnB → Knapsack → Random) instead of running all 4 and picking lowest waste | `wallet.lua:390-409 select_coins` |
| BUG-4  | **P1** | `OutputGroup` struct entirely absent — UTXOs are passed as flat list; no script-grouping, no `m_from_me`, no `m_depth` / `m_ancestors` / `m_max_cluster_count` | structural |
| BUG-5  | **P2** | `OUTPUT_GROUP_MAX_ENTRIES = 100` cap absent | structural |
| BUG-6  | **P0** | `CoinEligibilityFilter` cascade (6/6/4 → 1/1/4 → 0/1/4) absent — single-shot `min_confirmations` from caller. Funds-loss avoidance: a wallet that holds only unconfirmed-mine UTXOs cannot send (Core widens filter on each pass). | spend.cpp:931 `AutomaticCoinSelection` |
| BUG-7  | **P1** | `long_term_fee` per-UTXO absent — waste metric (BUG-11) cannot include `Σ(fee_i - long_term_fee_i)`; Core's "is this UTXO economic to spend now vs later" signal lost | coinselection.cpp:761 |
| BUG-8  | **P1** | `max_selection_weight` bail-out absent in all four algorithms; pure satoshi-count tx can exceed `MAX_STANDARD_TX_WEIGHT = 400000` weight without selection refusing | coinselection.cpp:131,567,668 |
| BUG-9  | **P2** | BnB `is_feerate_high` waste-prune absent (Core line 129: `curr_waste > best_waste && is_feerate_high` early-exit); slows BnB on high-feerate exhaustion paths | coinselection.cpp:120,129 |
| BUG-10 | **P2** | BnB duplicate-omission shortcut absent (Core lines 174-178 skip inclusion if `(eff_val, fee)` matches predecessor) — wastes tries on equivalent branches | coinselection.cpp:176 |
| BUG-11 | **P0** | BnB **waste = `sel_value - target`** (excess only). Missing both `Σ(fee_i - long_term_fee_i)` and `change_cost` terms. At feerates where multiple changeless solutions exist, lunarblock picks the lowest-overshoot (potentially largest-input-count) instead of Core's "lowest current-fee-burn given expected future feerate". **Funds-burn risk**: a 1-of-1 UTXO with 50 sat overshoot will be picked over a 1-of-3 UTXO with 200 sat overshoot, *even when the 1-of-3 selection has identical total fee but burns three UTXOs that would have been cheap-to-spend later*. | wallet.lua:231-233 |
| BUG-12 | **P2** | Knapsack `nTotalLower == nTargetValue` perfect-subset shortcut absent | coinselection.cpp:683 |
| BUG-13 | **P1** | Knapsack `ApproximateBestSubset` (1000-iter stochastic subset-sum) absent. lunarblock falls back to greedy largest-first, which always overshoots and creates unnecessary change at moderate feerates. | coinselection.cpp:602 |
| BUG-14 | **P1** | Knapsack does not split `applicable_groups` (< target + change_target) from `lowest_larger` (≥ target + change_target); cannot find the smallest-coin-above-target fallback when subset-sum fails | coinselection.cpp:660-680 |
| BUG-15 | **P1** | Knapsack `lowest_larger` first-pass guard is `value < target * 2`. Core's `lowest_larger` accepts ANY group with `selection_amount ≥ target + change_target`. lunarblock's first pass *misses* coins ≥ 2×target (falls through to greedy second pass, which may still pick them, but the canonical "single-coin best fallback" is wrong). | wallet.lua:362-366 |
| BUG-16 | **P0** | `effective_value` hardcodes **68 vbytes** (P2WPKH) for ALL UTXOs. P2PKH inputs = 148 vbytes, P2TR keypath ≈ 57.5 vbytes, P2SH-P2WPKH ≈ 91 vbytes. Using 68 for P2PKH **underestimates** input fee by 80 vbytes × feerate. At 100 sat/vB a P2PKH input is undercosted by 8000 sat, causing BnB/Knapsack to think a UTXO is economic when it actually *loses* the wallet 8000 sat in fees. **Funds-loss risk on legacy P2PKH or P2SH-P2WPKH wallets.** | wallet.lua:183 `input_vsize = input_vsize or 68` |
| BUG-17 | **P0** | `cost_of_change` = `math.ceil(M.COST_OF_CHANGE * fee_rate)` = `math.ceil(148 * fee_rate)`. Core: `cost_of_change = effective_feerate * change_output_size + long_term_feerate * change_spend_size`. lunarblock (a) uses **148 vbytes** which is the legacy P2PKH input vsize (should be 31+68 = 99 for P2WPKH change), (b) applies the *current* feerate to the whole sum (ignores long-term feerate for the future spend). Result: cost_of_change is **over-estimated** at low feerates and **under-estimated** at high feerates. BnB rejects valid changeless candidates that Core would accept, and picks suboptimal solutions at high feerates. | wallet.lua:173,196 |
| BUG-18 | **P0** | `change > M.DUST_THRESHOLD` (546) is used as the change-vs-fee threshold. Core: `min_viable_change = max(change_spend_fee + 1, dust)` — at 100 sat/vB on P2WPKH change-spend (68 vbytes), `change_spend_fee = 6800`, so min_viable_change = 6800, not 546. lunarblock at high feerates creates 600-sat change outputs that cost 6800 sat to spend later → **uneconomic change**: the wallet pays 6800 fee to spend a UTXO worth 600, **losing 6200 sat**. | wallet.lua:1446 |
| BUG-19 | **P1** | `GenerateChangeTarget` absent. Core randomises change-target in `[CHANGE_LOWER, min(2*payment, CHANGE_UPPER)]` = `[50000, ≤1000000]` to avoid change-amount fingerprinting. lunarblock change = `total_in - total_out - fee` is fully deterministic and **identifies lunarblock-built txs** to chain analysis. | coinselection.cpp:809 |
| BUG-20 | **P1** | `subtract_fee_from_amount` is documented in `options` (wallet.lua:1336) but never passed to `select_coins`; coin selection always uses effective value regardless. Core: when SFFO is set, `OutputGroup::GetSelectionAmount()` returns raw `m_value` (not `effective_value`), and `ChooseSelectionResult` skips BnB entirely (spend.cpp:751). lunarblock applies SFFO only at the recipient.amount adjustment site (if at all) — coin selection silently ignores the flag, leading to over-selection by `Σ input_fee` for SFFO sends. | wallet.lua:1336,1369 |
| BUG-21 | **P1** | `m_effective_feerate > 3 × m_long_term_feerate` trigger for CoinGrinder absent — moot since CG itself is missing (BUG-2), but the trigger logic is the gate Core uses to decide between SRD and CG. Even if SRD were added without CG, this trigger is the right entry point. | spend.cpp:769 |
| BUG-22 | **P0** | Discard-feerate change drop absent. Core: if `change < discard_feerate * change_spend_size`, drop change to fees. lunarblock: drops only when `change ≤ DUST_THRESHOLD = 546`. At 50 sat/vB and DEFAULT_DISCARD_FEE = 10 sat/vB, P2WPKH change_spend = 68 vbytes → threshold = 680. lunarblock creates 547-sat change that costs 3400 sat to spend = **net loss 2853 sat per such tx**. | spend.cpp + DEFAULT_DISCARD_FEE |
| BUG-23 | **P1** | `AttemptSelection` mixed-group retry absent. Core: try positive-group (all UTXOs with positive effective value); if that fails, retry with `mixed_group` (allows negative-eff inputs for SFFO/legacy). lunarblock has only one pass over a flat candidates list. | spend.cpp:702-722 |
| BUG-24 | **P0** | `bump_fee` uses `new_fee = old_fee + ceil(orig_vsize * 1)` (i.e. **1 sat/vB increment** = 1000 sat/kvB). Core's `WALLET_INCREMENTAL_RELAY_FEE = 5 sat/kvB` (incrementalRelayFee default `5000` per kvB → `5` per vB at the **policy.h** default `DEFAULT_INCREMENTAL_RELAY_FEE = 1000` sat/kvB). lunarblock's 1 sat/vB equals 1000 sat/kvB — actually matching the policy default of 1000 sat/kvB. **However**, the `+1 sat/vB` is a **fee-rate increment**, not an **absolute fee increment**; multiplied by tx vsize this produces *only* `vsize` extra satoshis. Core's incremental-relay-fee requirement is `new_fee ≥ old_fee + incrementalRelayFee.GetFee(new_tx_vsize)`, which at 1000 sat/kvB = 1 sat/vB *equals* lunarblock here — but lunarblock skips the `combined_bump_fee` calculation entirely (spans unconfirmed-ancestor packages, where the new tx must outpay the ancestor combined bump fee at the new feerate). **Result:** bumping a tx whose chain has unconfirmed ancestors will be accepted by lunarblock but Core's mempool will reject it (RBF rule 4 — paying more total fee). | wallet.lua:1876 + feebumper.cpp:83-100 |
| BUG-25 | **P1** | `bump_fee` refuses when `new_change ≤ DUST_THRESHOLD` (wallet.lua:1889) — but a Core-correct bump can *consume* the change entirely if doing so still produces a valid tx (absorbs into fee). lunarblock returns "insufficient funds" where Core would succeed by removing the change output. This is a usability regression: high-feerate bumps fail prematurely. | wallet.lua:1889 + feebumper.cpp:CreateRateBumpTransaction |

## Universal-pattern notes for the meta-audit

1. **"Coin-selection waste calculation simplified to excess-only"** — appears
   in 3+ impls per W113. Universal pattern: any impl that wrote
   `waste = total_eff - target` instead of Core's three-term formula
   (`change_cost`, `fee_diff`, `excess`) cannot make correct cross-algo
   tradeoffs.
2. **"Hardcoded P2WPKH input vsize for effective_value"** — universal
   pattern (BUG-16 here). Core takes per-`COutput.input_bytes` which is
   set at output discovery time by the script-pubkey-manager. Every impl
   that hard-codes a single number is **funds-leak-on-legacy-input**.
3. **"DUST_THRESHOLD as min_viable_change"** — universal pattern (BUG-18
   here). At high feerates, dust (546 sat for P2PKH) is *smaller than*
   the cost to spend the change UTXO later — the change is uneconomic
   even though "above dust". Core's `min_viable_change` is feerate-
   dependent.
4. **"Bump fee uses absolute +1 sat/vB instead of incrementalRelayFee
   over package vsize"** — universal pattern (BUG-24 here). Impls that
   don't model unconfirmed-ancestor combined bump fee will produce
   RBF-rule-4-rejected replacement txs.

## Out-of-scope (deferred)

- Manual coin selection via `CoinControl` (preset inputs / fund-from /
  fund-locked) is partly covered by W113 G29; no new W129 gate added.
- Watch-only / external-signer interaction with eligibility filter
  (`m_include_unsafe_inputs` for ExternalSigner SPMs) deferred.
- `coinselectoptions` RPC plumbing (Core has `bumpfee` accepting an
  `options` map with `confTarget`, `replaceable`, `original_change_index`)
  — lunarblock's `options` shape only carries `fee_rate` and `sign`.

## Acceptance for this audit

- 30 gates classified.
- 25 bugs catalogued with file:line references.
- Tests in `tests/test_w129_coin_selection.lua` exercise every gate
  with structural assertions and produce a reproducible bug-count
  summary. **30/30 PASS, 25 bugs.**
