# W130 — BIP-125 RBF feebumper Rule 3 audit (lunarblock)

**Date:** 2026-05-17
**Wave:** W130 (discovery)
**Impl:** lunarblock (Lua / LuaJIT)
**Status:** **17 BUGS FOUND** (4 P0, 8 P1, 5 P2, 0 P3) across **30 gates**

## Context

W130 audits lunarblock's **wallet-side** BIP-125 fee-bump path
(`Wallet:bump_fee` at `src/wallet.lua:1748-1929`) against
Bitcoin Core's `wallet/feebumper.cpp` (`CheckFeeRate` +
`CreateRateBumpTransaction` + `EstimateFeeRate`) and the
`policy/rbf.cpp::PaysForRBF` invariant used by mempool acceptance.

Scope explicitly **focuses on Rule 3** of BIP-125 (the replacement-fees
≥ original-fees invariant and the surrounding wallet logic that ensures
the replacement clears BOTH Rule 3 and Rule 4 at the mempool boundary).
The mempool-side acceptance (`Mempool:accept_transaction` Rule 1-5) was
already audited in **W120** — *that* path is reasonably faithful (modulo
W120 BUG-5 strict-less-than off-by-one and BUG-10 division order); W130
is the **wallet-side** companion: does the wallet ever build a bump that
will be rejected by Core's mempool acceptance? Core's invariant per
`feebumper.cpp::CheckFeeRate`:

```
new_total_fee = newFeerate.GetFee(maxTxSize) + combined_bump_fee
minTotalFee   = old_fee + incrementalRelayFee.GetFee(maxTxSize)
ASSERT new_total_fee >= minTotalFee                                  (1)
ASSERT new_total_fee >= GetRequiredFee(wallet, maxTxSize)            (2)
ASSERT new_total_fee <= wallet.m_default_max_tx_fee                  (3)
```

Where `incrementalRelayFee = max(node_relayIncrementalFee,
WALLET_INCREMENTAL_RELAY_FEE)` — Core deliberately picks the **max** of
`relayIncrementalFee()` (default 100 sat/kvB = 0.1 sat/vB) and
`WALLET_INCREMENTAL_RELAY_FEE = 5000` sat/kvB (5 sat/vB) "to future
proof against changes to network wide policy" (feebumper.cpp:130-137).

This is **W129 BUG-24** restated and extended. W129 caught the missing
`combined_bump_fee` term; W130 catalogues every adjacent gap that makes
lunarblock's bump path either build a Rule-3/Rule-4-failing replacement
OR refuse a Core-valid replacement.

> References: bitcoin-core/src/wallet/feebumper.cpp,
> bitcoin-core/src/policy/rbf.cpp + rbf.h,
> bitcoin-core/src/policy/feerate.{cpp,h},
> bitcoin-core/src/policy/policy.h (DEFAULT_INCREMENTAL_RELAY_FEE),
> bitcoin-core/src/wallet/wallet.h (WALLET_INCREMENTAL_RELAY_FEE,
> DEFAULT_TRANSACTION_MAXFEE), bitcoin-core/src/wallet/fees.cpp
> (GetRequiredFee / GetMinimumFeeRate), bitcoin-core/src/node/mini_miner.cpp
> (CalculateTotalBumpFees), BIP-125.

## Method

1. Re-read bitcoin-core `wallet/feebumper.cpp` end-to-end (385 LOC) +
   `policy/rbf.cpp` (`PaysForRBF`, `EntriesAndTxidsDisjoint`,
   `ImprovesFeerateDiagram`).
2. Re-read W129 lunarblock audit (`audit/w129_coin_selection.md` G29/G30
   + BUG-24/BUG-25) — confirm W130 isn't double-counting; W130 expands
   the surface from "1 sat/vB increment" to the **full Rule-3 invariant**.
3. Synthesize 30-gate matrix covering:
   - Rule 3 invariant decomposition (G1-G7)
   - Rule 4 invariant decomposition (G8-G10)
   - `EstimateFeeRate` floor-stack (G11-G15)
   - `CreateRateBumpTransaction` precondition + plumbing (G16-G22)
   - Replacement bookkeeping + commit-time semantics (G23-G27)
   - Recyclable change + outputs-override (G28-G30)
4. Classify lunarblock state with `src/wallet.lua:1748-1929` (bump_fee) +
   `src/wallet.lua:1509-1597` (submit_transaction / replaced_by
   bookkeeping) + `src/mempool.lua:278-290,1387-1409`
   (INCREMENTAL_RELAY_FEE constant + Rule 3/4 enforcement on the mempool
   side, for cross-reference).
5. Catalogue bugs.
6. Write `tests/test_w130_bip125_feebumper_rule3.lua` covering every gate
   with structural assertions. Where the gap is purely "feature absent",
   the test is a `log_bug` + sentinel assertion; where a wrong value is
   computed, the test computes the Core-correct expected value and shows
   the lunarblock deviation.

## Severity scoring

- **P0** — Funds-loss risk OR builds a replacement that Core's mempool
  REJECTS for Rule 3/4 (i.e. user thinks they bumped, broadcast fails).
- **P1** — Refuses a Core-valid bump (usability regression) OR misses
  Core safety net (`m_min_depth`, `m_default_max_tx_fee`, `MarkReplaced`)
  with potential for accidental double-pay.
- **P2** — Missing optional facility (PSBT path, external-input weight,
  outputs-override) or wrong-but-non-fatal value.
- **P3** — Cosmetic.

## 30 W130 Audit Gates

| Gate | Description | Status | Core ref |
|------|-------------|--------|----------|
| **Rule 3 invariant decomposition** | | | |
| G1 | `new_total_fee = newFeerate.GetFee(maxTxSize) + combined_bump_fee` (sum, not just fee on own vsize) | **WRONG** (BUG-1 = W129 BUG-24, **P0**) | feebumper.cpp:88 |
| G2 | `combined_bump_fee` queried via MiniMiner across unconfirmed-ancestor cluster | **MISSING** (BUG-2, **P0**) | feebumper.cpp:83 + mini_miner.cpp:CalculateTotalBumpFees |
| G3 | `minTotalFee = old_fee + incrementalRelayFee.GetFee(maxTxSize)` (absolute increment over **maxTxSize**, not orig_vsize) | **WRONG** (BUG-3, **P0**) | feebumper.cpp:93 |
| G4 | `maxTxSize` derived from `CalculateMaximumSignedTxSize` (worst-case signed vsize), not orig signed vsize | **WRONG** (BUG-4, **P1**) | feebumper.cpp:289 |
| G5 | Rule 3 strict-equal allowed (Core: `new_total_fee < minTotalFee` rejects; equality OK) | PARTIAL (BUG-5, **P2**) — lunarblock uses `new_fee <= old_fee` (rejects equality, but the test boundary is wrong because Rule 3 is fee-vs-conflicts, not new_fee-vs-old_fee) | feebumper.cpp:95 + rbf.cpp:109 |
| G6 | Replacement uses **wallet+node** `incrementalRelayFee` = `max(node_relayIncrementalFee, WALLET_INCREMENTAL_RELAY_FEE = 5 sat/vB)` | **WRONG** (BUG-6, **P0**) — lunarblock uses literal `1 sat/vB`; **off by 5×** at the default policy | feebumper.cpp:135-137 |
| G7 | `WALLET_INCREMENTAL_RELAY_FEE = 5000 sat/kvB` constant defined | **MISSING** (BUG-6 follow-on) | wallet.h:124 |
| **Rule 4 invariant decomposition** | | | |
| G8 | `additional_fees = replacement_fees - original_fees` ≥ `relay_fee.GetFee(replacement_vsize)` | PARTIAL (BUG-7, **P1**) — lunarblock enforces this in `Mempool:accept_transaction` (mempool.lua:1402-1409) but NOT in `Wallet:bump_fee`; wallet builds the replacement *blind* to Rule 4 | rbf.cpp:117-123 |
| G9 | `INCREMENTAL_RELAY_FEE` (policy default) = 100 sat/kvB AT THE MEMPOOL; wallet-side incremental = 5000 sat/kvB | **MISSING** (BUG-6 follow-on) | policy.h:48 + wallet.h:124 |
| G10 | Rule 4 multiplied against the **REPLACEMENT** vsize, not the ORIGINAL vsize | **WRONG** (BUG-8, **P1**) — lunarblock at wallet.lua:1876 uses `orig_vsize` (= ORIGINAL); Core's `incrementalRelayFee.GetFee(maxTxSize)` uses the worst-case **REPLACEMENT** vsize | feebumper.cpp:93 (maxTxSize = replacement) |
| **EstimateFeeRate floor-stack** | | | |
| G11 | Original feerate rounded up by `+CFeeRate(1)` (1 sat/kvB) to undo `old_fee/txSize` truncation | **MISSING** (BUG-9, **P2**) | feebumper.cpp:126 |
| G12 | Feerate += `max(node_incremental, wallet_incremental)` | **WRONG** (BUG-6 follow-on) | feebumper.cpp:137 |
| G13 | Feerate clamped from below by `GetMinimumFeeRate` (wallet min, mempool min, fallback fee) | **MISSING** (BUG-10, **P1**) | feebumper.cpp:140 + fees.cpp:29 |
| G14 | When `options.fee_rate` is provided, **STILL** check it's ≥ mempool min fee (Core CheckFeeRate :69) | **MISSING** (BUG-11, **P1**) | feebumper.cpp:69 |
| G15 | When `options.fee_rate` is **NOT** provided, fall back to `EstimateFeeRate` (orig feerate + 1 sat/kvB + incremental + min floor) | PARTIAL (BUG-12, **P1**) — lunarblock falls back to `old_fee + 1 sat/vB * orig_vsize` (a single absolute term, not a feerate computation; never queries `min_relay_fee` or `mempoolMinFee`) | feebumper.cpp:119-143 |
| **CreateRateBumpTransaction preconditions + plumbing** | | | |
| G16 | `HasWalletSpend(wtx.tx)` check (no descendants in wallet) | **MISSING** (BUG-13, **P1**) | feebumper.cpp:25 |
| G17 | `wallet.chain().hasDescendantsInMempool(wtx.GetHash())` check | **MISSING** (BUG-13 follow-on) | feebumper.cpp:31 |
| G18 | `GetTxDepthInMainChain(wtx) != 0` check ("Transaction has been mined") | PRESENT (wallet.lua:1766-1768, `entry.height > 0`) | feebumper.cpp:37 |
| G19 | `replaced_by_txid` mapValue check ("Cannot bump transaction X which was already bumped") | PRESENT (wallet.lua:1770-1774, `entry.replaced_by`) | feebumper.cpp:42 |
| G20 | `require_mine` enforcement (AllInputsMine) | PRESENT (wallet.lua:1785-1835, per-input reconstruct or fail) | feebumper.cpp:47-54 |
| G21 | Sequence numbers preserved (≤0xFFFFFFFD) so replacement still signals RBF | PRESENT (wallet.lua:1899-1904 reuses inp.sequence) | feebumper.cpp (implicit; replacement inherits sequence) |
| G22 | `new_coin_control.m_min_depth = 1` (BIP-125 Rule 2: replacement may not add **new** unconfirmed inputs) | **MISSING** (BUG-14, **P1**) | feebumper.cpp:312 |
| **Replacement bookkeeping + commit-time semantics** | | | |
| G23 | `new_coin_control.m_allow_other_inputs = true` (wallet may add inputs to fund the bump) | **MISSING** (BUG-15, **P2**) — lunarblock only shrinks change, never adds inputs | feebumper.cpp:309 |
| G24 | `mapValue["replaces_txid"]` set on the new tx during commit | **MISSING** (BUG-16, **P2**) — caller-side `submit_transaction` with `meta.replaces` works but `bump_fee` doesn't auto-populate; the bumpfee RPC must remember to pass it | feebumper.cpp:372 |
| G25 | `wallet.MarkReplaced(old_txid, bumped_txid)` after broadcast | PARTIAL (wallet.lua:1582-1590 sets `replaced_by` only if `submit_transaction` receives `meta.replaces`) — bump_fee itself doesn't return the link | feebumper.cpp:378 |
| G26 | `wallet.CommitTransaction(tx, mapValue=mapValue_with_replaces_txid, ...)` semantics | PARTIAL (BUG-16 follow-on) | feebumper.cpp:374 |
| G27 | If MarkReplaced fails, surface as error but commit proceeds | **MISSING** (BUG-17, **P2**) — no path documented for partial commit | feebumper.cpp:379 |
| **Recyclable change + outputs-override** | | | |
| G28 | `options.outputs` (override recipient set) supported by Core CreateRateBumpTransaction | **MISSING** (no `options.outputs` handling at wallet.lua:1748-1929) | feebumper.cpp:160 |
| G29 | `options.original_change_index` (recycle a specific output as change) supported | **MISSING** (lunarblock auto-detects "first wallet-owned output is change"; no override) | feebumper.cpp:160,256 |
| G30 | Mutually-exclusive: outputs + original_change_index | **MISSING** (BUG-15 follow-on, P2-not-counted-separate) | feebumper.cpp:162-166 |

## Bug catalogue (17 BUGS)

| Bug ID | Priority | Summary | Where |
|--------|----------|---------|-------|
| BUG-1  | **P0** | `bump_fee` skips `combined_bump_fee` for unconfirmed-ancestor packages (re-state of W129 BUG-24). At wallet.lua:1876 `new_fee = old_fee + ceil(orig_vsize * 1)` — Core's `new_total_fee` = `newFeerate.GetFee(maxTxSize) + combined_bump_fee`. A replacement of tx-B (child of unconfirmed tx-A) requires the new total fee to ALSO outpay tx-A's deficit to make the new feerate at the *cluster* boundary. lunarblock builds a replacement that Core's mempool will reject under Rule 4 (`PaysForRBF` rbf.cpp:117), because additional_fees < relay_fee × replacement_vsize once you account for the combined package. **W129 BUG-24 STILL PRESENT.** | wallet.lua:1876 + feebumper.cpp:83-100 |
| BUG-2  | **P0** | MiniMiner / CalculateTotalBumpFees not implemented. The chain interface `calculateCombinedBumpFee(outpoints, target_feerate)` (interfaces.cpp:702) walks the unconfirmed-ancestor cluster and returns the sum of "additional fees to make the cluster mine at target_feerate". lunarblock has no equivalent. Without it BUG-1 cannot be fixed (it's the function that produces the missing term). | structural |
| BUG-3  | **P0** | `minTotalFee` does not equal `old_fee + incrementalRelayFee.GetFee(maxTxSize)`. lunarblock computes the new fee as `old_fee + ceil(orig_vsize * 1)`. Core's `minTotalFee` is a function of (a) `maxTxSize` (the worst-case **replacement** vsize, not the original) and (b) `incrementalRelayFee` (which lunarblock has misvalued — see BUG-6). Two-axis divergence; product of (1 vs 5) × (orig vs replacement) makes lunarblock's bump fee anywhere from 1× to 25× below Core's required minimum on the wallet boundary. | wallet.lua:1876 + feebumper.cpp:93 |
| BUG-4  | **P1** | `maxTxSize` should be computed via `CalculateMaximumSignedTxSize(tx, wallet, coin_control).vsize` (feebumper.cpp:289), which uses the WORST-CASE post-sign vsize of the **replacement** (including any newly-added inputs from coin selection, with dummy max-size signatures). lunarblock uses `_compute_vsize(orig)` — the ORIGINAL signed tx vsize — which only equals maxTxSize when the replacement reuses all original inputs unchanged. Once `m_allow_other_inputs = true` becomes wired (BUG-15), this needs to be the replacement worst-case. | wallet.lua:1868 |
| BUG-5  | **P2** | Wallet-side Rule 3 check `new_fee <= old_fee` (wallet.lua:1880) is **the wrong invariant**. Rule 3 is `replacement_fees < original_fees` at the **mempool** (rbf.cpp:109), where "original_fees" = sum of fees of ALL evicted txs (the conflict + descendants). The wallet has no view of evicted-descendant fees, so it cannot enforce Rule 3 here. The current check is a weak proxy that's strictly weaker than Core's CheckFeeRate `new_total_fee < minTotalFee` (which incorporates incrementalRelayFee and maxTxSize). | wallet.lua:1880 |
| BUG-6  | **P0** | `incrementalRelayFee` hardcoded as **1 sat/vB** (i.e. 1000 sat/kvB) in the default branch (wallet.lua:1876 `ceil(orig_vsize * 1)`). Core takes `max(node_relayIncrementalFee, WALLET_INCREMENTAL_RELAY_FEE)`. `WALLET_INCREMENTAL_RELAY_FEE = 5000` sat/kvB = **5 sat/vB**. Default policy `DEFAULT_INCREMENTAL_RELAY_FEE = 100` sat/kvB = 0.1 sat/vB. Therefore Core's increment is `max(0.1, 5) = 5 sat/vB`. lunarblock uses 1 sat/vB → **5× too low**. Result: lunarblock-built bumps will fail Core's `PaysForRBF` Rule 4 at any tx ≥200 vbyte (200 × (5-1) = 800 sat shortfall). **Funds at risk** because the user pays the original fee + ~vsize sats but the tx never enters the mempool (broadcast appears successful, but no relay). | wallet.lua:1876 + feebumper.cpp:135-137 |
| BUG-7  | **P1** | Wallet's `bump_fee` doesn't enforce Rule 4 itself; it relies on the mempool's `Mempool:accept_transaction` Rule 4 check (mempool.lua:1402-1409). That check is correct for direct-conflicts-without-ancestors but the wallet shouldn't *build* a replacement that fails Rule 4. Core's `CheckFeeRate` (feebumper.cpp:60-117) is the wallet-side gate; lunarblock has no equivalent — `bump_fee` rebuilds the tx and returns it without checking that the constructed fee clears the wallet-side `minTotalFee`. | wallet.lua:1748-1929 |
| BUG-8  | **P1** | When `options.fee_rate` is **not** provided, lunarblock uses `orig_vsize` (the ORIGINAL tx vsize) for the increment: `old_fee + ceil(orig_vsize * 1)`. Core multiplies by `maxTxSize` (replacement-with-worst-case-signatures vsize). For a replacement that adds inputs (Core path with `m_allow_other_inputs = true`), maxTxSize > orig_vsize → Core requires more increment than lunarblock. Even without added inputs, segwit signature worst-case can shift vsize by 1-2 vbytes vs the original. | wallet.lua:1876 |
| BUG-9  | **P2** | Original-feerate `+CFeeRate(1)` round-up (feebumper.cpp:126) is missing. Core computes the original feerate as `old_fee / orig_size` (truncation by integer division) and then bumps by 1 sat/kvB to "Add 1 satoshi to the result" to defeat the rounding. lunarblock never computes an "original feerate" — it works in absolute satoshis — so this rounding is unobservable, but the *purpose* (don't be off-by-one from the original feerate) is also unfulfilled in lunarblock's absolute-add-then-test model. | feebumper.cpp:124-126 |
| BUG-10 | **P1** | `GetMinimumFeeRate` floor missing. Core's `EstimateFeeRate` clamps the chosen feerate from BELOW by `GetMinimumFeeRate(wallet, coin_control, /*feeCalc=*/nullptr)` (feebumper.cpp:140), which is max of `m_min_fee`, `relayMinFee()`, `mempoolMinFee`, and `m_fallback_fee` when smart-fee unavailable. lunarblock's default `old_fee + orig_vsize` bump has no such floor → if the user is in a "fallback fee disabled, smart fee unavailable" situation, the bump can produce a sub-relay-fee replacement. | feebumper.cpp:140 + fees.cpp:29 |
| BUG-11 | **P1** | When the caller provides `options.fee_rate`, lunarblock does not check it against `mempool_min_fee` (Core CheckFeeRate :69 enforces `newFeerate.GetFeePerK() < minMempoolFeeRate.GetFeePerK()` → error). lunarblock will build a sub-mempool-min replacement and only the mempool's accept_transaction will reject it (with a different error string). | wallet.lua:1870-1871 + feebumper.cpp:67-75 |
| BUG-12 | **P1** | `EstimateFeeRate` (the no-feerate-given path) entirely missing. Core does a 4-step computation: (1) `old_fee / orig_size + 1 sat/kvB`, (2) `+ max(node_incremental, wallet_incremental)`, (3) clamp ≥ `GetMinimumFeeRate`, (4) returns as a `CFeeRate`. lunarblock collapses (1)+(2) into `old_fee + orig_vsize * 1 sat/vB` and skips (3). The shape is "absolute add" not "feerate compute"; the difference matters when orig vsize > replacement vsize OR mempool min > old feerate. | wallet.lua:1872-1877 + feebumper.cpp:119-143 |
| BUG-13 | **P1** | `PreconditionChecks` doesn't cover Core's two descendant-existence checks: (a) `wallet.HasWalletSpend(wtx.tx)` ("Transaction has descendants in the wallet") — feebumper.cpp:25; (b) `wallet.chain().hasDescendantsInMempool(wtx.GetHash())` — feebumper.cpp:31. Without (a) lunarblock will let the user bump a tx-A even when there's a tx-B in the wallet that spends a tx-A output; replacing tx-A breaks tx-B (orphan-on-replace). Without (b) the user can bump a tx-A even when its descendants are unconfirmed in the mempool; replacing tx-A double-pays the descendant if both eventually confirm (one via tx-A→tx-B chain, one via tx-A'). | wallet.lua:1765-1775 |
| BUG-14 | **P1** | `m_min_depth = 1` (BIP-125 Rule 2: replacement may not source new **unconfirmed** inputs) is not set in lunarblock's bump path. Since BUG-15 means lunarblock doesn't add inputs at all, the surface area is currently zero — BUT if BUG-15 is fixed (without also setting min_depth), the wallet will happily pull new unconfirmed UTXOs into the replacement, and the mempool will reject for Rule 2 violation. | feebumper.cpp:312 |
| BUG-15 | **P2** | `m_allow_other_inputs = true` not set. Core's bump path can ADD inputs to the replacement when shrinking change isn't enough. lunarblock only shrinks the existing change output, so a high-feerate bump on a tx with small change will fail with "change after fee bump would be dust" (BUG-25 in W129) where Core could have succeeded by pulling in more inputs. | feebumper.cpp:309 |
| BUG-16 | **P2** | `mapValue["replaces_txid"]` annotation absent. Core writes `mapValue["replaces_txid"] = oldWtx.GetHash().ToString()` (feebumper.cpp:372) so the new tx is **provably-bumpable-from-X** in the wallet record. lunarblock's bump_fee returns `new_tx, old_fee, new_fee, input_utxos` and relies on the caller of `submit_transaction` to pass `meta.replaces`, but if the caller forgets, `replaced_by` is never set on the original. Result: a second bumpfee on the same original tx is accepted (PreconditionChecks's `entry.replaced_by` check is non-empty only when meta.replaces was passed). | wallet.lua:1748-1929 + feebumper.cpp:372 |
| BUG-17 | **P2** | `MarkReplaced` failure surfacing absent. Core: if `wallet.MarkReplaced(oldWtx.GetHash(), bumped_txid)` returns false, Core appends "could not mark the original transaction as replaced" to errors but DOES commit (the broadcast already happened). lunarblock has no equivalent path — the `replaced_by` field is set unconditionally if meta.replaces is passed. Edge case but Core covers it; lunarblock loses the signal. | feebumper.cpp:378-380 |

## W129 BUG-24 re-verification

**STATUS: STILL PRESENT.**

W129 BUG-24 = "bump_fee skips combined_bump_fee for unconfirmed
ancestors" → re-classified here as W130 **BUG-1** with the additional
companion BUGs **BUG-2** (MiniMiner missing), **BUG-3** (minTotalFee
formula), **BUG-6** (incrementalRelayFee hardcoded), **BUG-8** (orig
vs replacement vsize) — five interconnected bugs comprising the
Rule-3 / Rule-4 invariant gap that BUG-24 surfaced.

Line `wallet.lua:1876` is unchanged from W129 (no FIX-N between W129
and W130).

```lua
new_fee = old_fee + math.ceil(orig_vsize * 1)
```

vs Core (feebumper.cpp:88-93):

```
new_total_fee = newFeerate.GetFee(maxTxSize) + combined_bump_fee.value()
minTotalFee   = old_fee + incrementalRelayFee.GetFee(maxTxSize)
```

## Universal-pattern notes for the meta-audit

1. **"Wallet bumps the wrong absolute amount"** — five-axis bug
   (1 vs 5 sat/vB increment × orig vs replacement vsize × no combined
   bump fee × no min-feerate floor × no max-tx-fee cap). This pattern
   is likely present in every impl that wrote a `bump_fee` against the
   BIP-125 *spec* (which says "rule 3: more fee") without reading
   Core's `feebumper.cpp::CheckFeeRate` for the **precise invariant**.
   Universal classification: any impl with `new_fee = old_fee + k *
   vsize` where `k ≠ 5` AND the impl has no `combined_bump_fee` term
   AND uses orig (not maxTxSize) vsize is **BIP-125 Rule 4 fail-on-bump**.
2. **"Wallet skips MiniMiner"** — building unconfirmed-ancestor combined
   bump fee requires walking the cluster; in pure-Lua impls there is no
   shared `MiniMiner` library, so every impl that hasn't ported one
   from Core will exhibit BUG-2.
3. **"Wallet-side ≠ mempool-side enforcement"** — lunarblock's
   `Mempool:accept_transaction` Rule 1-5 is fairly accurate (W120
   audit), but `Wallet:bump_fee` builds the candidate without consulting
   the same invariant. Universal pattern: any impl that doesn't share
   the constants between its wallet and its mempool's `accept` path
   will have this bug-class.
4. **"`outputs` / `original_change_index` plumbing absent"** — the
   recent Core feebumper API extension (PR #25768, ~2023) added these
   parameters; impls written against pre-Core-25 documentation won't
   have them.

## LuaJIT bit-ops trap check (per FIX-83)

W122/FIX-83 universal pattern: `bit.lshift(1, n)` in LuaJIT is
**32-bit modular** when called on non-cdata, which truncates for
`n ≥ 32`. Audit of `Wallet:bump_fee`:

- All fee arithmetic uses plain Lua doubles (`math.ceil`,
  `* fee_rate`, `+ old_fee`). No `bit.lshift` / `bit.band` /
  `bit.rshift` on fee amounts.
- `bit.band` / `bit.rshift` ARE used at wallet.lua:1787-1791 but **only
  for serializing the 32-bit outpoint index** (which fits in 32 bits by
  spec); no trap.

**Conclusion: no bit-ops trap in the bump_fee path.** Fee math is
unaffected by FIX-83-class bugs.

## Out-of-scope (deferred)

- Cluster-mempool Rule 8 (`ImprovesFeerateDiagram`) enforcement on the
  wallet side (Core does this at the **mempool** boundary, not the
  wallet). Already partially covered by W120 G29.
- Sibling RBF (parent in the cluster signals descendant CPFP overlap)
  is structurally out of scope until cluster-mempool semantics are
  fully audited fleet-wide.
- External-signer (`WALLET_FLAG_EXTERNAL_SIGNER`) integration with
  PSBT path (feebumper.cpp:333-344). lunarblock has no external-signer.
- `coin_control.fOverrideFeeRate` semantics — lunarblock has no
  CoinControl object; deferred to a future wave that audits the full
  CoinControl shape (W129 G29 covered the bump-related subset).
- Mempool `RBFTransactionState::UNKNOWN` (cluster mempool's UNKNOWN
  state, when tx isn't in our mempool). lunarblock's `is_replaceable`
  returns boolean (W120 BUG-6); not re-counted here.

## Acceptance for this audit

- 30 gates classified.
- 17 bugs catalogued with file:line references.
- W129 BUG-24 re-verified: **STILL PRESENT** (reclassified as W130
  BUG-1; companion bugs BUG-2/BUG-3/BUG-6/BUG-8).
- Tests in `tests/test_w130_bip125_feebumper_rule3.lua` exercise every
  gate with structural assertions and produce a reproducible
  bug-count summary. **30/30 PASS, 17 bugs.**
