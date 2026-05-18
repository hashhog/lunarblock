# W151 — Package relay + BIP-125 RBF rules 2-5 (lunarblock)

**Wave:** W151 — `MemPoolAccept::AcceptPackage` /
`AcceptMultipleTransactionsInternal`, `IsWellFormedPackage`,
`IsTopoSortedPackage`, `IsConsistentPackage`, `IsChildWithParents`,
`IsChildWithParentsTree`, `GetPackageHash`, `PackageMempoolChecks`,
`PackageRBFChecks`, BIP-125 rules 1–5 (`SignalsOptInRBF`, `IsRBFOptIn`,
`GetEntriesForConflicts`, `EntriesAndTxidsDisjoint`, `PaysForRBF`,
`ImprovesFeerateDiagram`), constants `MAX_PACKAGE_COUNT=25`,
`MAX_PACKAGE_WEIGHT=404'000`, `MAX_REPLACEMENT_CANDIDATES=100`,
`submitpackage` RPC, `ProcessNewPackage`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/policy/packages.h:19-30` — `MAX_PACKAGE_COUNT{25}`,
  `MAX_PACKAGE_WEIGHT=404'000`, `static_assert`s tying the package
  limits into `DEFAULT_CLUSTER_LIMIT` and `DEFAULT_CLUSTER_SIZE_LIMIT_KVB`.
- `bitcoin-core/src/policy/packages.cpp:17-50` — `IsTopoSortedPackage`
  (set of remaining-children-txids, drops self via `later_txids.erase`
  with `Assume(... == 1)` doubling as **duplicate detection**).
- `bitcoin-core/src/policy/packages.cpp:52-77` — `IsConsistentPackage`
  (empty-vin reject + duplicate-prevout reject via `inputs_seen` set).
- `bitcoin-core/src/policy/packages.cpp:79-117` — `IsWellFormedPackage`
  (sequence: PCKG_POLICY `package-too-many-transactions` →
  `package-too-large` → `package-contains-duplicates` →
  `package-not-sorted` → `conflict-in-package`).
- `bitcoin-core/src/policy/packages.cpp:119-149` —
  `IsChildWithParents` / `IsChildWithParentsTree`.
- `bitcoin-core/src/policy/packages.cpp:151-170` — `GetPackageHash`
  (SHA256 of wtxids sorted as little-endian numbers, ascending).
- `bitcoin-core/src/policy/rbf.h:24-26` — `MAX_REPLACEMENT_CANDIDATES{100}`
  (Rule #5 cluster count, NOT tx count).
- `bitcoin-core/src/policy/rbf.cpp:24-50` — `IsRBFOptIn` (REPLACEABLE_BIP125
  / UNKNOWN / FINAL tri-state).
- `bitcoin-core/src/policy/rbf.cpp:58-83` — `GetEntriesForConflicts`
  (`pool.GetUniqueClusterCount(iters_conflicting) >
  MAX_REPLACEMENT_CANDIDATES`, NOT descendant count).
- `bitcoin-core/src/policy/rbf.cpp:85-98` — `EntriesAndTxidsDisjoint`
  (Rule on `ancestors ∩ direct_conflicts`).
- `bitcoin-core/src/policy/rbf.cpp:100-125` — `PaysForRBF` (Rule #3
  `replacement_fees >= original_fees`; Rule #4 `additional_fees >=
  relay_fee.GetFee(replacement_vsize)`).
- `bitcoin-core/src/policy/rbf.cpp:127-140` — `ImprovesFeerateDiagram`
  (Rule #8; strict `is_gt` on `CompareChunks(new, old)`).
- `bitcoin-core/src/validation.cpp:984-1035` — `ReplacementChecks`
  (single-tx RBF: GetEntriesForConflicts → PaysForRBF →
  CheckMemPoolPolicyLimits → ImprovesFeerateDiagram).
- `bitcoin-core/src/validation.cpp:1037-1131` — `PackageRBFChecks`
  (must be 1-parent-1-child, no in-mempool ancestors,
  `package_fee > parent_fee` clause, anti-DoS fee check).
- `bitcoin-core/src/validation.cpp:1432-1564` —
  `AcceptMultipleTransactionsInternal` (PreChecks per ws → TRUC →
  `m_total_modified_fees / m_total_vsize` package feerate gate →
  PackageRBFChecks → `CheckMemPoolPolicyLimits` → `CheckEphemeralSpends`
  → PolicyScriptChecks per ws → SubmitPackage).
- `bitcoin-core/src/validation.cpp:1622-1771` — `AcceptPackage` (dedup
  via `m_pool.exists(wtxid)`/`exists(txid)` →
  `AcceptSubPackage({tx})` single-shot retry → fall through to
  `AcceptSubPackage(txns_package_eval)` ELSE individual_results_nonfinal
  → final `LimitMempoolSize`).
- `bitcoin-core/src/rpc/mempool.cpp:1302-1480` — `submitpackage` RPC
  (params: array + `maxfeerate` + `maxburnamount`; emits `package_msg`,
  `tx-results` keyed by wtxid, `replaced-transactions`; `IsUnspendable
  || !HasValidOps && nValue > max_burn_amount → MAX_BURN_EXCEEDED`
  fail-fast; `client_maxfeerate=nullopt` when 0).

**Files audited**
- `src/mempool.lua` — `Mempool:accept_package` (lines 2566-2821),
  `Mempool:accept_transaction` RBF block (lines 1314-1499),
  `M.is_well_formed_package` / `is_topo_sorted_package` /
  `is_consistent_package` / `is_child_with_parents` /
  `is_child_with_parents_tree` / `calculate_package_fee_rate` /
  `compute_package_hash` (lines 2333-2558), `M.signals_rbf` (758),
  `Mempool:is_replaceable` (2309), `Mempool:bip125_replaceable_tx`
  (2180), `Mempool:track_package_removed` (1965), `Mempool:get_min_fee`
  (1988), `Mempool:trim` (2088), module constants `MAX_PACKAGE_COUNT`,
  `MAX_PACKAGE_WEIGHT`, `MAX_PACKAGE_VSIZE`, `MAX_REPLACEMENT_CANDIDATES`,
  `INCREMENTAL_RELAY_FEE`, `DEFAULT_MEMPOOL_FULL_RBF`, `MAX_BIP125_RBF_SEQUENCE`
  (278-310), cluster helpers `linearize_cluster`, `build_feerate_diagram`,
  `compare_diagrams`, `interpolate_fee`, `uf_*` (35-194).
- `src/rpc.lua` — `submitpackage` (3559-3634), `testmempoolaccept`
  (7289-7455), `getmempoolinfo` (1876-).
- `src/main.lua` — `parse_args` (80-, only `--mempool-fullrbf` knob;
  no `-maxpackagecount`, `-maxpackageweight`, `-maxmempool`, etc.).
- `bitcoin-core/src/policy/packages.h`, `bitcoin-core/src/policy/packages.cpp`,
  `bitcoin-core/src/policy/rbf.h`, `bitcoin-core/src/policy/rbf.cpp`,
  `bitcoin-core/src/validation.cpp` (AcceptPackage section), and
  `bitcoin-core/src/rpc/mempool.cpp` (submitpackage section).

---

## Gate matrix (33 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | IsWellFormedPackage tokens | G1: `package-too-many-transactions` | PASS (`mempool.lua:2400`) |
| 1 | … | G2: `package-too-large` (only when count > 1) | PASS (`mempool.lua:2424`) |
| 1 | … | G3: `package-contains-duplicates` | PASS (`mempool.lua:2415-2416`) |
| 1 | … | G4: `package-not-sorted` | PASS (`mempool.lua:2429-2431`) |
| 1 | … | G5: `conflict-in-package` (hyphenated, Core wire token) | **BUG-1 (P1)** — lunarblock emits the English string `"conflict in package"` (with spaces) at `mempool.lua:2380`, not the Core wire token `conflict-in-package`. Same shape as the W125/W145/W150 "reject-string wire-parity slippage" sweep; running fleet total now 26+ lunarblock tokens drifted |
| 1 | … | G6: empty package rejected | PARTIAL — lunarblock returns `"empty package"` (`mempool.lua:2403-2405`); Core does NOT have an explicit empty-package token in `IsWellFormedPackage` (asserts `!package.empty()` at validation.cpp:1624). Effect is same (reject), but the message is custom |
| 1 | … | G7: empty-vin in any pkg tx → false from IsConsistentPackage | PARTIAL — lunarblock returns `"transaction has no inputs"` at `mempool.lua:2374`; Core returns `false` and the caller surfaces `conflict-in-package`. Wire-token drift; lunarblock leaks a brand-new English string |
| 2 | Topological-sort semantics | G8: parent-after-child rejected | PASS (`mempool.lua:2336-2362`) |
| 2 | … | G9: duplicate-txid detection (Core relies on `later_txids.erase == 1`) | PASS (lunarblock instead pre-checks with `seen_txids` at 2408-2418 — equivalent for !duplicate detection but the assert-after-erase invariant is not replicated; if a future caller passes a non-pre-checked package the sort would silently accept duplicates) |
| 3 | Child-with-parents topology | G10: `IsChildWithParents` reachable | PASS (`mempool.lua:2446-2472`) |
| 3 | … | G11: `IsChildWithParentsTree` reachable + wire-token | **BUG-2 (P1)** — `submitpackage` (rpc.lua:3589-3592) rejects with `"package-not-child-with-parents-tree: parents must not spend other parents in the package"`. Core's wire token is `package-not-child-with-parents` (validation.cpp:1643), no `-tree` suffix and no English explanation appended. Wire-token slippage continued |
| 4 | MAX_PACKAGE constants wired | G12: MAX_PACKAGE_COUNT=25 | PASS (`mempool.lua:308`) |
| 4 | … | G13: MAX_PACKAGE_WEIGHT=404000 | PASS (`mempool.lua:309`) |
| 4 | … | G14: MAX_PACKAGE_VSIZE constant used | **BUG-3 (P2)** — defined at `mempool.lua:310` (`M.MAX_PACKAGE_VSIZE = 101000`), but never read by any production code path. Grep shows zero consumers (the only sites are the definition + the audit/test files). Dead-constant; classic dead-data plumbing pattern. Cross-cite W150 BUG-3 / W149 BUG-17 |
| 5 | GetPackageHash parity | G15: byte-ordering matches Core (lexicographic compare of `make_reverse_iterator(wtxid)`) | PASS (`mempool.lua:2532-2557`; sort uses reverse-iteration over the 32 bytes) |
| 6 | submitpackage RPC | G16: accepts `maxfeerate` param | **BUG-4 (P1)** — Core takes `maxfeerate` (rpc/mempool.cpp:1319-1322, default `DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK()`). lunarblock submitpackage (rpc.lua:3563-3634) accepts ONLY the `package` array; `params[2]` and beyond are ignored. Wallets that send `submitpackage [...] 0.001 0` get `maxfeerate=0.001` silently dropped; the package always sees `client_maxfeerate=nil` and rejects only on per-tx hardcoded limits |
| 6 | … | G17: accepts `maxburnamount` param | **BUG-5 (P1)** — Core takes `maxburnamount` (rpc/mempool.cpp:1322-1324; pre-validation per-output `IsUnspendable || !HasValidOps && nValue > max_burn_amount` fast-fail at 1386-1390). lunarblock has no equivalent — a wallet that calls `submitpackage [...] 0.001 0` cannot enforce burn safety, and accidental OP_RETURN with high value passes |
| 6 | … | G18: dedupes already-in-mempool / same-txid-diff-wtxid | **BUG-6 (P0-CDIV)** — Core's `AcceptPackage` (validation.cpp:1664-1686) skips wtxid-already-in-mempool / same-txid-diff-wtxid txs and emits `MempoolAcceptResult::MempoolTx` / `MempoolTxDifferentWitness` for them; the remaining txs go through `AcceptSubPackage`. lunarblock's `accept_package` does NOT short-circuit already-in-mempool txs from validation; it accepts them silently inside the per-tx loop (`mempool.lua:2709-2712 if self.entries[txid_hex] then accepted_txids[...] = txid_hex; goto continue`), but it still ran `is_well_formed_package` + `check_transaction` + the full per-tx UTXO lookup beforehand. The `MempoolTxDifferentWitness` (same-txid-diff-wtxid) case is **entirely absent** — lunarblock's package path indexes by txid_hex, so a package tx with the same txid but different witness as an existing mempool tx is treated as already-in-mempool (silent accept of the OLD entry, the new witness is discarded). Witness replacement that Core handles cleanly silently drops on lunarblock |
| 6 | … | G19: returns per-tx response with wtxid key | PASS (`rpc.lua:3601-3611`) |
| 6 | … | G20: emits `replaced-transactions` | **BUG-7 (P1)** — always emits `["replaced-transactions"] = {}` (rpc.lua:3626, 3632). Even in the legitimate package-RBF path (when implemented), the replaced set is never populated. Combined with BUG-9 below (package path skips RBF entirely), this field is permanently empty |
| 7 | accept_package: RBF support inside package path | G21: package can replace an in-mempool tx (Core: PackageRBFChecks at validation.cpp:1037-1131) | **BUG-8 (P0-CDIV)** — `accept_package` rejects ALL mempool conflicts unconditionally: `if existing_spender and not package_txid_to_idx[existing_spender] then return false, "conflict with existing mempool tx"` (mempool.lua:2615-2618). There is NO RBF in the package path. Core supports `PackageRBFChecks` (1-parent-1-child packages can replace a single in-mempool entry with the package). Lightning fee-bumping / sponsor flows that depend on package RBF are unusable against lunarblock |
| 7 | … | G22: package-only conflict short-circuit handled correctly | PARTIAL — `if existing_spender and not package_txid_to_idx[existing_spender]` only rejects when the spender is OUTSIDE the package (mempool.lua:2616). A package tx that conflicts with another package tx is caught earlier in `is_consistent_package`. Logic seems right, but the gate path doesn't reach RBF |
| 8 | accept_package: feerate gates | G23: package_feerate ≥ relay_floor (Core validation.cpp:1507-1512 — `CheckFeeRate(m_total_vsize, m_total_modified_fees, ...)`, uses **`get_min_fee()`** rolling floor) | **BUG-9 (P0-CDIV)** — lunarblock's package feerate gate (mempool.lua:2693-2697) uses `self.min_relay_fee` (raw config floor) NOT `self:get_min_fee()` (the rolling minimum that includes the TrimToSize bump). After a high-feerate trim sweep bumps `rolling_minimum_fee_rate` to e.g. 5000 sat/kvB, single-tx accept correctly rejects below 5000, but **the package path keeps accepting at min_relay_fee=1000**. Adversaries can drain a trim-bumped mempool one CPFP package at a time |
| 8 | … | G24: client_max_feerate honoured in package path | **BUG-10 (P1)** — `accept_transaction` honours `self.client_max_feerate_kvb` (mempool.lua:1594-1599), `accept_package` does NOT. Combined with BUG-4 (submitpackage drops `maxfeerate`), this is moot today but if BUG-4 is fixed, BUG-10 leaks a per-tx max-feerate ceiling that the wallet expected to enforce |
| 9 | RBF single-tx path: BIP-125 Rules | G25: Rule #1 — every direct conflict must be replaceable (fullrbf bypass) | PASS-WITH-CAVEAT (`mempool.lua:1328-1334`, skipped when `self.fullrbf`); the underlying `is_replaceable` walks ancestors transitively which matches Core's `IsRBFOptIn`. Behaviour matches Core v28+ when fullrbf is on |
| 9 | … | G26: Rule #2 — replacement may only add new unconfirmed input if that outpoint was already an input of one of the direct conflicts | **BUG-11 (P1)** — implemented at `mempool.lua:1463-1490`, but the implementation builds `conflict_input_outpoints` from `pairs(conflicts)` (the **direct-conflict** set from the for-loop scan, not the `all_conflicts` set including descendants). Core's pre-cluster-mempool `HasNoNewUnconfirmed` (still asserted at BIP-125 spec level) used the direct conflicts only, so this is correct. **However:** after the cluster-mempool branch, Core removed Rule #2 (`HasNoNewUnconfirmed` no longer exists in current Core, see `git log src/validation.cpp -- "HasNoNewUnconfirmed"`); lunarblock still enforces it. **lunarblock is STRICTER than Core**: a CPFP replacement that adds a new unconfirmed parent that doesn't appear in the original is admitted by Core (it's allowed under cluster-mempool's ImprovesFeerateDiagram gate) but rejected by lunarblock with `"replacement adds new unconfirmed input"`. This is a relay-policy divergence |
| 9 | … | G27: Rule #3 — replacement fees ≥ original fees | PASS (`mempool.lua:1387-1400`) — uses strict `fee < conflicting_fees` not `<=`, matching Core (`bitcoin-core/src/policy/rbf.cpp:109`) |
| 9 | … | G28: Rule #3 — fees include prioritise deltas (Core uses `GetModifiedFee` / `m_modified_fees`) | **BUG-12 (P1)** — lunarblock has no `prioritisetransaction` RPC and no `delta_fee` field on `mempool_entry`. `conflicting_fees` sums raw `entry.fee` (mempool.lua:1391-1396); Core sums `entry.GetModifiedFee()` which incorporates any operator prioritise delta. If a fixed-fee tx was prioritised UP in the existing mempool, lunarblock undercounts the original fee → admits replacements that Core would reject. (Fleet pattern: 6th distinct lunarblock instance of "operator-knob absent" per W150 BUG-16) |
| 9 | … | G29: Rule #4 — additional fees ≥ incremental_relay_feerate × replacement_vsize | PASS (`mempool.lua:1402-1409`, `M.INCREMENTAL_RELAY_FEE * vsize / 1000` with `math.ceil`) — uses Lua integer math correctly **but** see BUG-13 below on Lua-double precision when fees + vsize cross 2^53 |
| 9 | … | G30: Rule #5 — MAX_REPLACEMENT_CANDIDATES (100) on unique CLUSTERS | **BUG-13 (P0-CDIV)** — `mempool.lua:1351-1359` counts **all_conflicts** entries (direct conflicts + ALL their descendants), comparing the txn count to `MAX_REPLACEMENT_CANDIDATES=100`. Core's current Rule #5 (rbf.cpp:69-75) calls `pool.GetUniqueClusterCount(iters_conflicting)` which counts the UNIQUE CLUSTERS the conflicts span, NOT the number of evicted entries. A cluster with 200 descendants but only 1 direct conflict is **1 cluster** in Core's accounting → passes Rule #5; lunarblock's counter sees 200 → rejects. Divergence: legitimate fee-bump replacements that touch a single cluster of >100 descendants succeed on Core, fail on lunarblock with `"too many potential replacements: 200 > 100"`. (Cross-cite: this is the same shape as the W128 fleet-wide banman conflation — lunarblock counts the wrong primitive) |
| 9 | … | G31: Rule #8 (cluster-mempool) — ImprovesFeerateDiagram on EVERY affected cluster, strict `>` | PASS-WITH-PRECISION-RISK — `mempool.lua:1411-1461` runs `compare_diagrams(old_diag, new_diag)` and rejects on `not compare_diagrams(...)`. But the diagrams are built from `(e.fee + cum)` accumulated in Lua doubles (`mempool.lua:142-154`), and `interpolate_fee` (130-140) returns a `frac * (curr.fee - prev.fee)` that introduces non-integer rationals. For fees in the 2^53+ range (8.9 PH-sat ≈ 89 mBTC for a single tx, or aggregate package fees in the same range), the comparison loses precision. **BUG-14 below covers this** |
| 10 | Lua-double precision on RBF fee math | G32: all fee comparisons use exact integer math | **BUG-14 (P1)** — fee math throughout the RBF path uses Lua doubles. Specific risk points: (a) `interpolate_fee` (`mempool.lua:130-140`) — `frac * (curr.fee - prev.fee)` returns a non-integer rational; (b) `compare_diagrams` (`mempool.lua:156-175`) — strict `<`/`>` against double-vs-double `old_fee` / `new_fee`; (c) `package_fee_rate = total_fees / total_vsize` (`mempool.lua:2690`) — same loss; (d) `track_package_removed(evicted_rate_kvb + INCREMENTAL_RELAY_FEE)` (`mempool.lua:2113`) — `evicted_rate_kvb = math.floor(worst_rate * 1000)` re-rounds. For mempool-scale aggregates (sub-`2^53`), this is exact, but **when package fees approach `2^53` (~9 PB-sat ≈ 0.09 BTC)** or when many tiny fees compound through `cum_fee`, the gate can flip on the boundary. Companion to W149 BUG-10 chain_work lossy comparator and W150 BUG-14 rolling-fee precision. **Fleet pattern**: "Lua-double precision loss on Rule 3/4 fee math" — first dedicated audit instance |
| 11 | Other parity gaps | G33: package path runs `expire()` before `trim()` | **BUG-15 (P1)** — `accept_package` calls only `self:trim()` (mempool.lua:2812), not `self:expire()`. Core's `LimitMempoolSize` (validation.cpp:271-276) runs Expire then TrimToSize. After a package-accept, old txs that should have been expired stay in the pool until the next single-tx accept or block-connect. Cross-cite: `accept_transaction` correctly runs both at mempool.lua:1742-1743 — this is a **two-pipeline divergence** (17th distinct lunarblock instance, cross-cite W150 BUG-18) |

---

## BUG-1 (P1) — Package wire-token `conflict in package` (spaces) vs Core `conflict-in-package` (hyphens)

**Severity:** P1. `bitcoin-core/src/policy/packages.cpp:114` returns
`PCKG_POLICY` with the wire token `"conflict-in-package"`. lunarblock's
`M.is_consistent_package` (`src/mempool.lua:2380`) returns
`"conflict in package"` (with spaces). The token surfaces through
`accept_package` and `submitpackage` to the JSON `package_msg` field
and the P2P reject message — explorer tooling that scrapes Core wire
tokens (e.g. mempool.space's "package validation" dashboards) cannot
match the lunarblock string.

**File:** `src/mempool.lua:2380`.
**Core ref:** `bitcoin-core/src/policy/packages.cpp:114`.

**Impact:** wire-token parity gap; cross-impl monitoring divergence;
running lunarblock "reject-string wire-parity slippage" tally now
~26+ tokens (W125: 9; W145: 9; W150: 6+; W151: 4 new from this
audit — BUG-1 / BUG-2 / and the `"empty package"` and `"transaction
has no inputs"` strings noted in G6/G7).

---

## BUG-2 (P1) — `submitpackage` wire-token `package-not-child-with-parents-tree:...` vs Core `package-not-child-with-parents`

**Severity:** P1. `bitcoin-core/src/validation.cpp:1643` returns
`PCKG_POLICY` with the wire token `"package-not-child-with-parents"`
(no `-tree` suffix, no English explanation). lunarblock's
`submitpackage` (`src/rpc.lua:3589-3592`) returns

```lua
error({code = M.ERROR.INVALID_PARAMS,
  message = "package-not-child-with-parents-tree: parents must not spend other parents in the package"})
```

Two divergences: (a) `-tree` suffix is not in Core's token; (b) the
English explanation after the colon is non-standard. Core's
`rpc/mempool.cpp:1396` uses the **TransactionError::INVALID_PACKAGE**
JSON error with the message `"package topology disallowed. not
child-with-parents or parents depend on each other."` for this case —
the JSON error code differs but the message text is also distinct.

**File:** `src/rpc.lua:3589-3592`.
**Core refs:** `bitcoin-core/src/validation.cpp:1643`,
`bitcoin-core/src/rpc/mempool.cpp:1395-1397`.

**Impact:** Wire-token parity gap; same shape as BUG-1.

---

## BUG-3 (P2) — `MAX_PACKAGE_VSIZE = 101000` is dead data

**Severity:** P2 (cosmetic / cleanup-candidate). The constant is
defined at `src/mempool.lua:310`:

```lua
M.MAX_PACKAGE_VSIZE = 101000             -- Max total vsize (weight / 4)
```

Grep over `src/`, `spec/`, `test_*.lua` shows zero consumers — the
constant is set, exported, and never read. Core has NO equivalent
constant (Core enforces only `MAX_PACKAGE_WEIGHT` in weight units; the
vsize derivation is left to the cluster-size limit
`DEFAULT_CLUSTER_SIZE_LIMIT_KVB=101`). lunarblock's constant is the
right number for that conversion but it's not wired into any gate.

**File:** `src/mempool.lua:310`.
**Core ref:** `bitcoin-core/src/policy/packages.h:24,30`
(`MAX_PACKAGE_WEIGHT=404'000` and the static_assert tying it to
`DEFAULT_CLUSTER_SIZE_LIMIT_KVB * WITNESS_SCALE_FACTOR * 1000`).

**Impact:** classic dead-data plumbing; ~6th distinct lunarblock
instance (cross-cite W150 BUG-3, W149 BUG-17 plumbing).

---

## BUG-4 (P1) — `submitpackage` drops `maxfeerate` parameter

**Severity:** P1. Bitcoin Core's `submitpackage` RPC accepts three
params (`rpc/mempool.cpp:1319-1324`):
1. `package` — array of raw tx hex
2. `maxfeerate` — `DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK()` default
3. `maxburnamount` — `DEFAULT_MAX_BURN_AMOUNT` default

The `maxfeerate` is plumbed through `ProcessNewPackage(..., client_maxfeerate)`
to `AcceptMultipleTransactionsInternal`'s `args.m_client_maxfeerate`
gate (`validation.cpp:1458-1465`), which fails-fast with
`"max feerate exceeded"` when per-tx modified feerate exceeds the
client cap.

lunarblock's `submitpackage` (`src/rpc.lua:3563-3634`) reads only
`params[1]` (`pkg = params and params[1]`). `params[2]` (maxfeerate)
and `params[3]` (maxburnamount) are silently dropped. The
`rpc.mempool:accept_package(txs)` call has no maxfeerate argument.

```lua
-- src/rpc.lua:3593
local accept_ok, err_or_results = rpc.mempool:accept_package(txs)
```

**Impact:** wallets calling `submitpackage [...] 0.001 0` expect a
per-tx max-feerate enforcement; lunarblock silently ignores the cap.
A package that includes a high-fee outlier tx that Core would reject
goes through on lunarblock. Cross-cite BUG-10 (accept_package itself
doesn't honour `client_max_feerate_kvb` even when set).

**File:** `src/rpc.lua:3563-3634`.
**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:1319-1322, 1367-1372,
1402`.

---

## BUG-5 (P1) — `submitpackage` skips `maxburnamount` per-output gate

**Severity:** P1. Bitcoin Core's `submitpackage` runs a pre-validation
per-output check (`rpc/mempool.cpp:1386-1390`):

```cpp
for (const auto& out : mtx.vout) {
    if((out.scriptPubKey.IsUnspendable() || !out.scriptPubKey.HasValidOps()) && out.nValue > max_burn_amount) {
        throw JSONRPCTransactionError(TransactionError::MAX_BURN_EXCEEDED);
    }
}
```

This catches wallet-side foot-guns where an OP_RETURN tx (or other
`IsUnspendable` scriptPubKey) is accidentally created with a high
value — without the gate, the funds are burned permanently. Core's
default `DEFAULT_MAX_BURN_AMOUNT = 0` means by default any unspendable
output with value > 0 will fail-fast.

lunarblock's `submitpackage` (`src/rpc.lua:3563-3634`) does no such
check; an OP_RETURN tx with `value = 100000000` (1 BTC) goes through
the full validation pipeline and (assuming other gates pass) is
accepted. The funds are then unrecoverable.

**File:** `src/rpc.lua:3563-3634`.
**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:1386-1390`,
`DEFAULT_MAX_BURN_AMOUNT = 0`.

**Impact:** wallet foot-gun protection absent — accidental high-value
unspendable outputs are silently accepted. Same class as Core's
`sendrawtransaction` `maxburnamount` (W150 cross-cite — lunarblock's
`sendrawtransaction` is presumably also missing it).

---

## BUG-6 (P0-CDIV) — `MempoolTxDifferentWitness` case unhandled in package path; same-txid different-witness silently kept old

**Severity:** P0-CDIV. Bitcoin Core's `AcceptPackage`
(`validation.cpp:1664-1686`) has explicit three-way dedup logic:

```cpp
if (m_pool.exists(wtxid)) {
    // Exact transaction already exists.
    results_final.emplace(wtxid, MempoolAcceptResult::MempoolTx(...));
} else if (m_pool.exists(txid)) {
    // Same txid, different wtxid (witness replacement scenario).
    results_final.emplace(wtxid, MempoolAcceptResult::MempoolTxDifferentWitness(
        entry.GetTx().GetWitnessHash()));
} else {
    // Try single submission first, fall back to full package.
    ...
}
```

The middle branch is critical for **witness replacement** — segwit
allows two transactions with the same txid (same non-witness data,
same inputs/outputs) but different witnesses. Core's package path
returns `MempoolTxDifferentWitness` so the caller knows the mempool
already has a same-txid tx with a different wtxid and can decide
whether to disconnect peers / re-relay.

lunarblock's `accept_package` (`src/mempool.lua:2566-2821`) indexes
entirely by `txid_hex` (computed via `validation.compute_txid`, NOT
wtxid). At `mempool.lua:2709-2712`:

```lua
-- Skip if already in mempool
if self.entries[txid_hex] then
  accepted_txids[#accepted_txids + 1] = txid_hex
  goto continue
end
```

A package tx with the same txid as an in-mempool tx is silently
considered "already-accepted" and the existing entry is kept — even
if the package tx has a different wtxid (different witness). The new
witness is discarded; no `MempoolTxDifferentWitness` signal reaches
the RPC layer. lunarblock cannot perform witness-replacement of any
form (intentional or attacker-triggered) within a package.

Compounding: `submitpackage`'s response (rpc.lua:3596-3628) keys
`tx-results` by wtxid:

```lua
local txid_hex = types.hash256_hex(txid)
local wtxid_hex = types.hash256_hex(wtxid)
tx_results[wtxid_hex] = { txid = txid_hex, ... }
```

For a same-txid-diff-wtxid package tx, the response says
`tx-results[NEW_WTXID] = { txid = COMMON_TXID, ... }`, but the OLD
wtxid is what's actually in the mempool. The wallet sees a successful
submission of NEW_WTXID, but a follow-up `getrawmempool` shows
OLD_WTXID. Silent inconsistency.

**File:** `src/mempool.lua:2709-2712`; cross-file
`src/rpc.lua:3596-3611` (wtxid-keyed response).
**Core ref:** `bitcoin-core/src/validation.cpp:1664-1686`,
`bitcoin-core/src/policy/packages.h:36-41` (PackageValidationResult
enum).

**Impact:**
- Witness-replacement attack surface: an attacker submits a same-txid
  with a malleated witness via submitpackage; lunarblock silently
  keeps the original (potentially fine), but the wallet thinks the
  new wtxid was accepted and may later attempt to spend an output
  with the wrong witness in a CPFP chain.
- Wire-layer divergence: Core ecosystem peers expecting
  `MempoolTxDifferentWitness` semantics get a successful accept
  response from lunarblock instead of the discriminating signal.
- Cross-impl monitor breakage: tools that look up tx by wtxid via
  `getmempoolentry` see "not found" after a package submission that
  appeared to succeed.

---

## BUG-7 (P1) — `replaced-transactions` always empty in submitpackage response

**Severity:** P1. Bitcoin Core's `submitpackage`
(`rpc/mempool.cpp:1437-1471`, building `replaced-transactions` field)
populates the array with the txid, wtxid, and fee of every mempool
entry that was evicted by the package — surfaced through
`m_subpackage.m_replaced_transactions` (validation.cpp:1219).

lunarblock's `submitpackage` (`src/rpc.lua:3596-3633`) ALWAYS emits
`["replaced-transactions"] = {}` on both the success and failure
paths. Combined with BUG-8 (package path skips RBF entirely), the
field is permanently empty regardless of state — but if BUG-8 is
fixed and package RBF is added, the JSON shape will continue to lie.

**File:** `src/rpc.lua:3626, 3632`.
**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::submitpackage`
(`replaced-transactions` field).

**Impact:** wallets that read `replaced-transactions` (e.g. to
update local UTXO bookkeeping after an RBF replacement) see an empty
array; they fail to learn about evicted transactions and may keep
stale references.

---

## BUG-8 (P0-CDIV) — `accept_package` has NO RBF; rejects every mempool conflict unconditionally

**Severity:** P0-CDIV. Bitcoin Core's `PackageRBFChecks`
(`validation.cpp:1037-1131`) supports package RBF: a 1-parent-1-child
package can replace one or more in-mempool transactions if it (a) has
no in-mempool ancestors, (b) the package feerate strictly exceeds the
parent feerate, (c) anti-DoS fees pass, (d) cluster-size limits hold.

lunarblock's `accept_package` (`src/mempool.lua:2614-2618`):

```lua
-- Check for conflicts with existing mempool transactions
local existing_spender = self.outpoint_to_tx[outpoint_key]
if existing_spender and not package_txid_to_idx[existing_spender] then
  return false, "conflict with existing mempool tx"
end
```

Any mempool conflict with a tx NOT in the package is an unconditional
reject. The RBF block in `accept_transaction` (lines 1314-1499) — Rule
#1, #2, #3, #4, #5, #8, EntriesAndTxidsDisjoint — is not reachable
from `accept_package`. The single-tx-with-package retry pattern from
Core's `AcceptPackage` (validation.cpp:1689-1716, calling
`AcceptSubPackage({tx})` first then falling back to package eval) is
also absent.

**Consequences for Lightning fee-bumping:** the canonical use case
for package relay is L2 protocols pushing a fee-bumping child along
with its parent. When the parent already exists in the lunarblock
mempool at a lower fee rate, the package RBF should kick in to
replace the parent with the new (higher-fee) parent + child. Instead,
lunarblock returns `"conflict with existing mempool tx"` and the
fee-bump is rejected. Lightning channels using anchor outputs and
package RBF for CPFP are non-functional against lunarblock peers.

**File:** `src/mempool.lua:2614-2618` (the unconditional reject);
also `src/mempool.lua:2566-2821` (entire `accept_package` body, no
RBF block).
**Core ref:** `bitcoin-core/src/validation.cpp:1037-1131`
(PackageRBFChecks), `1622-1771` (AcceptPackage retry logic).

**Impact:**
- Lightning anchor-CPFP fee-bumping doesn't work on lunarblock-peered
  mempools.
- Package-relay BIP-331 use cases that depend on package RBF are
  unusable.
- Cross-impl divergence: a package that Core accepts (and broadcasts)
  is rejected by lunarblock; the package never reaches downstream
  lunarblock peers from a Core router.

---

## BUG-9 (P0-CDIV) — Package fee gate uses `min_relay_fee` not `get_min_fee()` (rolling-fee floor skipped)

**Severity:** P0-CDIV. Bitcoin Core's `AcceptMultipleTransactionsInternal`
(`validation.cpp:1497-1512`) computes package feerate as
`m_total_modified_fees / m_total_vsize` and runs `CheckFeeRate(...)`
which uses the **current rolling minimum fee** (`pool.GetMinFee()`)
— the floor that bumps after `TrimToSize` evicts low-feerate
transactions.

lunarblock's `accept_package` (`src/mempool.lua:2693-2697`):

```lua
-- 6. Check package fee rate meets minimum relay fee
if package_fee_rate_per_kb < self.min_relay_fee then
  return false, string.format("package fee rate too low: %.2f < %d sat/KB",
    package_fee_rate_per_kb, self.min_relay_fee)
end
```

The gate compares against `self.min_relay_fee` — the static config
floor (defaults to 1000 sat/kvB per W150 BUG-3) — NOT
`self:get_min_fee()` which incorporates the rolling
`rolling_minimum_fee_rate`.

**Failure mode:** mempool is at capacity → `trim()` evicts the lowest
feerate cluster at e.g. 5000 sat/vB (5 sat/vB) → `track_package_removed`
bumps `rolling_minimum_fee_rate` to 5000 sat/kvB. Now:

- Single-tx accept (`accept_transaction`) at 4000 sat/kvB fails with
  `"mempool min fee not met: 4.00 < 5.00 sat/kvB"` (mempool.lua:1306).
- Package accept (`accept_package`) at the same 4000 sat/kvB **passes**
  because the gate only checks the 1000 sat/kvB static floor.

Attackers can drain a trim-bumped mempool by submitting CPFP packages
just above the static `min_relay_fee` floor; each package bypasses
the rolling-fee bump that single-tx accepts honour. This is
asymmetric DoS hardening: the single-tx path is correctly defended,
the package path is wide open.

**File:** `src/mempool.lua:2693-2697`.
**Core ref:** `bitcoin-core/src/validation.cpp:1488-1512`
(`CheckFeeRate(m_total_vsize, m_total_modified_fees, ...)` which
internally calls `GetMinFee`).

**Impact:**
- Mempool drain attack via packages.
- Asymmetric rolling-fee enforcement (two-pipeline divergence — 17th
  distinct lunarblock instance per fleet tracking).
- Cross-cite W150 BUG-14 Lua-double rolling-fee comparator: even when
  the rolling fee is consulted (BUG-9 fixed), the double-precision
  loss in W150 BUG-14 weakens the gate.

---

## BUG-10 (P1) — `accept_package` ignores `client_max_feerate_kvb`

**Severity:** P1. `accept_transaction` (`mempool.lua:1594-1599`)
correctly honours the per-call client-max-feerate cap:

```lua
if self.client_max_feerate_kvb
   and fee_rate_per_kb > self.client_max_feerate_kvb then
  return false, string.format(
    "max-fee-exceeded: feerate %.2f > %.2f sat/kvB",
    fee_rate_per_kb, self.client_max_feerate_kvb)
end
```

`accept_package` (`src/mempool.lua:2566-2821`) has no such gate. Core
checks it inside the per-workspace PreChecks loop (validation.cpp:
1458-1465) — fail-fast on the FIRST tx that exceeds the cap.

Combined with BUG-4 (submitpackage doesn't pass `maxfeerate` through
to `accept_package`), this is moot today. If BUG-4 is fixed, BUG-10
will silently bypass the wallet-supplied cap on package submissions.

**File:** `src/mempool.lua:2566-2821` (no client_max_feerate gate);
cross-cite BUG-4.
**Core ref:** `bitcoin-core/src/validation.cpp:1458-1465`.

**Impact:** symbiotic with BUG-4. Both must be fixed for the
wallet-supplied maxfeerate cap to be honoured.

---

## BUG-11 (P1) — Rule #2 (`HasNoNewUnconfirmed`) enforced — STRICTER than current Core

**Severity:** P1 (over-strict / relay-policy divergence). Bitcoin
Core's BIP-125 Rule #2 (the original `HasNoNewUnconfirmed` from
pre-cluster-mempool branches) said:

> The replacement transaction may only include an unconfirmed input
> if that input was already an input of one of the directly
> conflicting transactions.

Core's current source — after the cluster-mempool branch — REMOVED
this gate entirely (replaced by `ImprovesFeerateDiagram`'s holistic
view). `git log -p src/validation.cpp` shows `HasNoNewUnconfirmed`
deleted; no current Core path enforces Rule #2.

lunarblock still enforces Rule #2 at `src/mempool.lua:1463-1490`:

```lua
-- BIP125 Rule #2: The replacement may only include an unconfirmed input if
-- that specific outpoint (txid:vout) was already an input of one of the
-- conflicting transactions.
local conflict_input_outpoints = {}
for conflict_hex in pairs(conflicts) do
  ...
end

for _, inp in ipairs(tx.inputs) do
  local prev_hex = types.hash256_hex(inp.prev_out.hash)
  local prev_entry = self.entries[prev_hex]
  if prev_entry then
    local outpoint_key = prev_hex .. ":" .. inp.prev_out.index
    if not conflict_input_outpoints[outpoint_key] then
      return false, "replacement adds new unconfirmed input"
    end
  end
end
```

lunarblock REJECTS a replacement that adds a new unconfirmed input
that Core would ACCEPT under cluster-mempool. Specifically, a
"sponsor" tx pattern (use a new unrelated mempool parent to pay for
the replacement) works on Core but fails on lunarblock with
`"replacement adds new unconfirmed input"`.

This is the inverse of BUG-8: BUG-8 says lunarblock REJECTS valid
package-RBF replacements; BUG-11 says lunarblock REJECTS valid
single-tx RBF replacements (with new unconfirmed inputs).

**File:** `src/mempool.lua:1463-1490`.
**Core ref:** `bitcoin-core/src/policy/rbf.cpp` (HasNoNewUnconfirmed
absent in current source); old reference
`bitcoin-core/src/policy/rbf.cpp@v22.0:HasNoNewUnconfirmed`.

**Impact:** legitimate RBF flows that add a sponsor input are
rejected; lunarblock is over-strict vs current Core.

---

## BUG-12 (P1) — `conflicting_fees` sums raw `entry.fee`, not `GetModifiedFee` (prioritisetransaction delta dropped)

**Severity:** P1. Bitcoin Core's `ReplacementChecks`
(`validation.cpp:1005-1015`) sums **`it->GetModifiedFee()`** for each
`all_conflicts` entry, then passes the total to `PaysForRBF` along
with the replacement's modified fee. The modified fee includes any
`prioritisetransaction` delta the operator applied via RPC.

lunarblock has no `prioritisetransaction` RPC, no `delta_fee` field
on `mempool_entry`, and `conflicting_fees` sums raw `entry.fee`:

```lua
-- src/mempool.lua:1387-1400
local conflicting_fees = 0
for conflict_hex in pairs(all_conflicts) do
  local entry = self.entries[conflict_hex]
  if entry then
    conflicting_fees = conflicting_fees + entry.fee
  end
end
if fee < conflicting_fees then
  return false, string.format("replacement fee not higher than conflicting txs: %d < %d",
    fee, conflicting_fees)
end
```

**Failure mode:** operator runs `prioritisetransaction <old_tx>
+50000` to bump an existing mempool entry's effective fee by 50000
sats. Core's RBF Rule #3 now requires the replacement to pay at
least `entry.fee + 50000`. lunarblock's RBF Rule #3 still only
requires `entry.fee`. An attacker submits a replacement at
`entry.fee + 1` and lunarblock accepts it, undercutting the
operator's prioritise. Cross-impl: replacement that Core accepts is
also accepted by lunarblock, but replacement that Core rejects (due
to prioritise) is accepted by lunarblock.

**File:** `src/mempool.lua:1387-1400`; cross-file
`src/mempool.lua:929-` (`mempool_entry` constructor has no `delta_fee`
field).
**Core ref:** `bitcoin-core/src/validation.cpp:1005-1015`,
`bitcoin-core/src/policy/rbf.cpp:100-125` (PaysForRBF), and
`bitcoin-core/src/kernel/mempool_entry.h::GetModifiedFee`.

**Impact:** operator prioritise is effectively defeated for RBF Rule
#3 enforcement; cross-impl divergence; small attack surface against
operators who use prioritise. Cross-cite W150 BUG-16 (operator-knob
absence — 6th distinct lunarblock instance now).

---

## BUG-13 (P0-CDIV) — Rule #5 counts evicted-tx descendants, not unique CLUSTERS

**Severity:** P0-CDIV. Bitcoin Core's current Rule #5
(`policy/rbf.cpp:64-75`):

```cpp
auto num_clusters = pool.GetUniqueClusterCount(iters_conflicting);
if (num_clusters > MAX_REPLACEMENT_CANDIDATES) {
    return strprintf("rejecting replacement %s; too many conflicting clusters (%u > %d)",
            tx.GetHash().ToString(), num_clusters, MAX_REPLACEMENT_CANDIDATES);
}
```

Rule #5 counts the number of UNIQUE CLUSTERS the directly-conflicting
entries span. A cluster with 500 descendants is **1** cluster.

lunarblock's Rule #5 (`src/mempool.lua:1336-1359`):

```lua
local conflict_descendants = {}
for conflict_txid_hex in pairs(conflicts) do
  all_conflicts[conflict_txid_hex] = true
  local conflict_entry = self.entries[conflict_txid_hex]
  if conflict_entry then
    for desc_hex in pairs(conflict_entry.descendants) do
      conflict_descendants[desc_hex] = true
    end
  end
end
for desc_hex in pairs(conflict_descendants) do
  all_conflicts[desc_hex] = true
end

-- BIP125 Rule #5
local eviction_count = 0
for _ in pairs(all_conflicts) do
  eviction_count = eviction_count + 1
end
if eviction_count > M.MAX_REPLACEMENT_CANDIDATES then
  return false, string.format("too many potential replacements: %d > %d",
    eviction_count, M.MAX_REPLACEMENT_CANDIDATES)
end
```

`eviction_count` is the size of `all_conflicts` — direct conflicts
PLUS all transitive descendants. lunarblock counts TXS, Core counts
CLUSTERS.

**Failure mode:** a fee-bump that replaces a single in-mempool root
with a 200-tx descendant tree:
- Core: 1 cluster ≤ 100 → Rule #5 PASSES.
- lunarblock: 201 evictions > 100 → Rule #5 REJECTS with
  `"too many potential replacements: 201 > 100"`.

Legitimate replacements that Core accepts are rejected by lunarblock.

There is an additional concern: lunarblock's `MAX_REPLACEMENT_CANDIDATES
= 100` constant was the original BIP-125 limit (Core's *old* meaning
was also "max evicted txs", which is what lunarblock implements).
Core changed the semantics to "max unique clusters" in the
cluster-mempool branch. lunarblock is implementing the OLD semantics
with the NEW constant — so it's stricter than both versions of Core.

**File:** `src/mempool.lua:1336-1359`.
**Core ref:** `bitcoin-core/src/policy/rbf.cpp:64-75`;
`bitcoin-core/src/policy/rbf.h:24-26` (`MAX_REPLACEMENT_CANDIDATES{100}`
comment "Maximum number of unique clusters that can be affected by an
RBF (Rule #5)").

**Impact:**
- Legitimate fee-bumps on long descendant chains rejected by
  lunarblock that Core accepts.
- Cross-impl monitor divergence.
- Same SHAPE as the W128 fleet-wide banman conflation
  (banner-ban-vs-discouragement counted-wrong primitive). Fleet
  pattern crystallizes: lunarblock joins the catalog of "counted the
  wrong primitive against the right constant" findings.

---

## BUG-14 (P1) — Lua-double precision loss on RBF Rule 3/4/8 fee math

**Severity:** P1. Lua 5.1 / LuaJIT uses IEEE-754 double-precision
(53-bit mantissa) for all numeric arithmetic. Integer fees in
satoshis up to 2^53 (~9 PB-sat ≈ 90,071 BTC) are exact, but the
following sites in lunarblock's RBF math introduce non-integer
rationals or compound enough additions to risk precision loss:

**Site (a) — `interpolate_fee` (`src/mempool.lua:130-140`):**
```lua
local frac = (size - prev.size) / math.max(curr.size - prev.size, 1)
return prev.fee + frac * (curr.fee - prev.fee)
```
`frac` is a non-integer rational; the returned `prev.fee + frac *
delta` loses precision even for moderate fee values. The result feeds
`compare_diagrams`'s strict `<`/`>` (line 169-170).

**Site (b) — `compare_diagrams` (`src/mempool.lua:156-175`):**
```lua
local old_fee = interpolate_fee(old_diag, check_size)
local new_fee = interpolate_fee(new_diag, check_size)
if new_fee < old_fee then dominated = false; break end
if new_fee > old_fee then strictly_better = true end
```
The strict comparator on double-vs-double `old_fee`/`new_fee` can
return `false` when the true integer math would return `true` (or
vice versa) at boundary cases. The boundary is where it MATTERS most
— close-to-break-even RBF replacements.

**Site (c) — `package_fee_rate = total_fees / total_vsize`
(`src/mempool.lua:2690`):** double division; subsequent comparison
with `self.min_relay_fee` (integer) introduces a one-sided rounding
risk. The same shape as W150 BUG-14 and W149 BUG-10.

**Site (d) — `track_package_removed` (`src/mempool.lua:2113`):**
```lua
local evicted_rate_kvb = math.floor(worst_rate * 1000)  -- sat/vB -> sat/kvB
self:track_package_removed(evicted_rate_kvb + M.INCREMENTAL_RELAY_FEE)
```
`worst_rate` is `(entry.fee + entry.descendant_fees) / total_vsize`
— a double. `math.floor(x * 1000)` re-rounds; if `worst_rate` was
already imprecise, the floor can be off-by-one.

**Site (e) — `get_min_fee` decay (`src/mempool.lua:2007-2008`):**
```lua
self.rolling_minimum_fee_rate =
  self.rolling_minimum_fee_rate / math.pow(2.0, dt / halflife)
```
`rolling_minimum_fee_rate` is stored as Lua double from W150 BUG-14;
the exponential decay introduces additional precision loss on each
call. Over many decay cycles the rolling minimum drifts.

**File:** `src/mempool.lua:130-140` (a), `156-175` (b), `2690` (c),
`2113` (d), `2007-2008` (e).
**Core ref:** Core uses `CAmount` (int64_t) throughout the fee path
and only converts to `CFeeRate` (`CAmount` + size) for compares;
`FeeFrac` (`util/feefrac.h`) for diagram math uses rational
comparison with exact integer arithmetic. No double-precision in any
fee path.

**Impact:** boundary-case mis-decisions in RBF accept/reject; cumulative
drift in `rolling_minimum_fee_rate` over decay cycles; cross-impl
divergence at the edge. Fleet pattern: "Lua-double precision loss
on Rule 3/4 fee math" — first dedicated audit instance, joins W150
BUG-14 (rolling fee) and W149 BUG-10 (chain_work) in the running
lunarblock precision tally.

---

## BUG-15 (P1) — `accept_package` skips `expire()`; only calls `trim()`

**Severity:** P1 (two-pipeline divergence; 17th distinct lunarblock
instance). Bitcoin Core's `LimitMempoolSize`
(`validation.cpp:271-276`) is called by `AcceptPackage` /
`AcceptMultipleTransactionsInternal` post-submission and runs Expire
THEN TrimToSize. The single-tx `accept_transaction` mirrors this:

```lua
-- src/mempool.lua:1738-1743
-- 9. Evict low-fee and expired transactions if mempool exceeds limits.
-- Core's LimitMempoolSize (validation.cpp:271-276) calls Expire() then
-- TrimToSize().  We mirror that order: first expire old txs, then trim
-- by size so that the freshest high-feerate txs survive.
self:expire()
self:trim()
```

`accept_package` (mempool.lua:2810-2813) only calls `self:trim()`:

```lua
-- 8. Trim mempool if needed (skip when test_accept — no state was mutated)
if not test_accept then
  self:trim()
end
```

Old transactions that should have been expired (e.g. 15 days old, past
`DEFAULT_MEMPOOL_EXPIRY = 336 hours`) remain in the mempool until the
NEXT call to `accept_transaction` or some other expire trigger. In
a package-heavy workload (Lightning channels constantly broadcasting
CPFP packages), expire could go un-fired for hours.

Side effect: when expire eventually runs, it'll evict a larger batch
all at once, which can cause a feerate cliff that perturbs the
`rolling_minimum_fee_rate` more severely than gradual expiry would.

**File:** `src/mempool.lua:2810-2813`.
**Core ref:** `bitcoin-core/src/validation.cpp:271-276`.

**Impact:** two-pipeline divergence; expired txs linger; rolling-fee
state drifts.

---

## Summary

**Bug count:** 15 (BUG-1 through BUG-15).

**Severity distribution:**
- **P0-CDIV:** 4 (BUG-6, BUG-8, BUG-9, BUG-13)
- **P1:** 10 (BUG-1, BUG-2, BUG-4, BUG-5, BUG-7, BUG-10, BUG-11,
  BUG-12, BUG-14, BUG-15)
- **P2:** 1 (BUG-3)

**Fleet patterns confirmed:**
- **"reject-string wire-parity slippage"** — 4 new tokens this audit
  (BUG-1 `conflict in package` vs `conflict-in-package`; BUG-2
  `package-not-child-with-parents-tree:...` vs
  `package-not-child-with-parents`; G6 `empty package`; G7
  `transaction has no inputs`). **Running lunarblock total now ~26+
  tokens** (W125: 9; W145: 9; W150: 6+; W151: 4 = 28 catalogued).
- **"two-pipeline guard 17th distinct lunarblock extension"** —
  BUG-9 (package-fee gate uses different min-fee than single-tx);
  BUG-15 (package skips expire that single-tx runs); BUG-10 (package
  ignores client_max_feerate that single-tx honours). Three distinct
  divergences between `accept_transaction` and `accept_package` in
  ONE wave.
- **"Lua-double precision loss on Rule 3/4 fee math"** — first
  dedicated audit instance (BUG-14); cross-cites W150 BUG-14 (rolling
  fee) and W149 BUG-10 (chain_work). Pattern is now a running
  lunarblock-specific concern across 3 distinct audits.
- **"dead-data plumbing"** — BUG-3 `MAX_PACKAGE_VSIZE`; ~6th lunarblock
  instance per running W138/W139/W144 tracking.
- **"operator-knob absent"** — BUG-12 (prioritisetransaction absent
  → modified-fee dropped in RBF Rule #3 math); 6th distinct
  lunarblock instance per W150 BUG-16.
- **"counted the wrong primitive against the right constant"** —
  BUG-13 (lunarblock counts `eviction_count` but Core's constant is
  for `num_clusters`). Same SHAPE as fleet-wide W128 banman
  conflation. Fleet pattern crystallizes.
- **"30-of-30-gates-buggy candidate"** — `accept_package`'s 7-gate
  pipeline (well-formed → check_transaction → MAX_STANDARD_TX_WEIGHT
  → UTXO lookup → COINBASE_MATURITY → fee≥0 → package fee rate)
  skips ~20+ gates that `accept_transaction` runs. Cross-cite W150
  BUG-18 confirmed THIRD lunarblock instance. This audit adds the
  observation that `accept_package` ALSO has no RBF (BUG-8) and no
  expire (BUG-15) — both critical gates the single-tx path has.
- **"comment-as-confession"** — `accept_package`'s package fee
  comment "For individual transactions that don't meet min fee rate,
  we accept them anyway because the package as a whole does"
  (`mempool.lua:2700-2701`) accurately describes the design but
  doesn't admit that the package-fee gate uses the wrong floor
  (BUG-9). The W120 fix comment at lines 1320-1327 admits "fullrbf
  reflects the actual setting (no longer lies)" — meta-confession
  that a prior version DID lie. 12th lunarblock instance.

**Top three findings:**

1. **BUG-8 (P0-CDIV — accept_package has zero RBF support)** —
   Package path rejects EVERY mempool conflict unconditionally;
   Lightning anchor-CPFP fee-bumping is non-functional against
   lunarblock peers. Core's entire `PackageRBFChecks` infrastructure
   has no equivalent. Combined with BUG-13 (Rule #5 counts wrong
   primitive) and BUG-11 (Rule #2 still enforced after Core removed
   it), lunarblock's RBF surface diverges significantly from Core
   in both stricter (BUG-11, BUG-13) AND missing (BUG-8) directions.

2. **BUG-9 (P0-CDIV — package fee gate skips rolling-fee floor)** —
   `accept_package` uses static `min_relay_fee` while
   `accept_transaction` uses `get_min_fee()`. After a trim-bump
   raises the rolling minimum, attackers can drain the mempool one
   CPFP package at a time by submitting just above the static floor.
   Asymmetric DoS hardening: single-tx accept defended, package
   accept wide open.

3. **BUG-6 + BUG-13 + BUG-14 cluster (witness-replacement gap +
   wrong-primitive Rule #5 + Lua-double precision)** — Three
   independent semantic gaps in the RBF / package machinery:
   - BUG-6: same-txid-diff-wtxid silently keeps old entry; no
     `MempoolTxDifferentWitness` signal; witness-replacement
     foot-gun.
   - BUG-13: Rule #5 counts evicted txs (200) where Core counts
     unique clusters (1); legitimate fee-bumps on long chains
     rejected.
   - BUG-14: Lua-double precision loss in `interpolate_fee` /
     `compare_diagrams` / `track_package_removed` / `get_min_fee`
     decay; boundary-case RBF accept/reject mis-decisions.

**Priority next fix waves from this audit:**
1. **BUG-8 (P0-CDIV)** — Wire `accept_package` to call RBF block
   per-tx OR add a `PackageRBFChecks`-equivalent for 1-parent-1-child
   packages. Closes the Lightning fee-bump gap. ~40 LOC.
2. **BUG-9 (P0-CDIV)** — One-line: change `self.min_relay_fee` to
   `math.max(self.min_relay_fee, self:get_min_fee())` at
   `src/mempool.lua:2694`. Closes the package-drain DoS.
3. **BUG-13 (P0-CDIV)** — Change Rule #5 to count `next(conflicts)`
   length (direct conflicts only, approximating "unique clusters")
   instead of `all_conflicts` length. ~2 LOC at `src/mempool.lua:
   1352-1359`. Closes the fee-bump-on-long-chain rejection.
6. **BUG-6 (P0-CDIV)** — Add wtxid index check in `accept_package`
   to detect same-txid-diff-wtxid; emit `mempool-tx-different-witness`
   sentinel back to `submitpackage`. ~10 LOC.
7. **BUG-11 (P1)** — Remove the Rule #2 `HasNoNewUnconfirmed` block
   at `src/mempool.lua:1463-1490` (Core removed this rule in the
   cluster-mempool branch). ~30 LOC removal.
8. **BUG-1 + BUG-2 (P1 fleet sweep)** — Fix the 4 wire-token slippage
   strings (`"conflict in package"` → `"conflict-in-package"`,
   `"package-not-child-with-parents-tree:..."` →
   `"package-not-child-with-parents"`, `"empty package"` → drop or
   align with Core, `"transaction has no inputs"` → drop). ~5 LOC.
9. **BUG-4 + BUG-5 + BUG-10 (P1 bundle)** — Plumb `maxfeerate` and
   `maxburnamount` from `submitpackage` RPC through to
   `accept_package`; add `client_max_feerate_kvb` gate inside
   `accept_package`. ~20 LOC.
10. **BUG-15 (P1)** — One-line: add `self:expire()` before
   `self:trim()` at `src/mempool.lua:2812`.
