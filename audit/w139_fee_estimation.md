# W139 — Fee estimation engine (CBlockPolicyEstimator) audit (lunarblock)

**Date:** 2026-05-18
**Wave:** W139 (discovery)
**Impl:** lunarblock (Lua / LuaJIT)
**Status:** **30 BUGS FOUND** (8 P0 / 14 P1 / 6 P2 / 2 P3) across **30 gates**
**Scope:** `CBlockPolicyEstimator` and its supporting types
(`TxConfirmStats`, `CFeeRate`, `FeeFilterRounder`, `FeeCalculation`).
The audit covers the bucket layout, three time-horizon architecture,
new-tx tracking, removal-as-failure accounting, the `EstimateMedianVal`
range-combining algorithm, `estimateSmartFee`'s three-sub-estimate
`max(half, full, double, [conservative])` composition, the
`fee_estimates.dat` binary file format (versioning, stale-file guard,
flush interval), the `CValidationInterface` reactor hooks
(`TransactionAddedToMempool` / `TransactionRemovedFromMempool` /
`MempoolTransactionsRemovedForBlock`), the `validForFeeEstimation`
gate (IBD + package + chained mempool parents), `MaxUsableEstimate`,
reorg/disconnect-tip semantics, `FeeFilterRounder` for the BIP-133
privacy quantizer, and the `estimatesmartfee`/`estimaterawfee` RPC
plumbing (clamp to `MinRelayFee`/`GetMinFee`, conservative mode,
horizon-skip on out-of-range targets, scale/decay/pass/fail bucket
emission).
**Excludes:** `getmempoolinfo` (W125), wallet-side `coin_selection`
fee bumping (W129), `feefilter` P2P wire format & broadcast timing
(W136), `BIP-125` feebumper rule-3 (W130).

This audit is a **follow-up to W114** ("fee estimation") at higher
algorithmic resolution. W114 catalogued 24 BUGs at the
constants/surface level (bucket count, decay constants, single-vs-
three-horizon, bucket-upper-bound vs median feerate); W139 dives
into the algorithm internals (range combining, periodTarget
rounding, oldUnconfTxs circular buffer, BlockSpan vs
HistoricalBlockSpan, file persistence schema, reorg semantics,
validation-interface contract) plus the wiring around the engine
(IBD gate, mempool-parent gate, RPC clamping to MinRelayFee/
GetMinFee, FeeFilterRounder, FeeCalculation reason emission). The
W114 catalogue is preserved; W139 adds 27 new BUG-N entries scoped
to the algorithm/wiring layer.

## Context

Audits lunarblock's fee estimation engine against Bitcoin Core:

- `bitcoin-core/src/policy/fees/block_policy_estimator.h` — public
  surface (FeeEstimateHorizon, FeeReason, EstimatorBucket,
  EstimationResult, FeeCalculation, CBlockPolicyEstimator class).
- `bitcoin-core/src/policy/fees/block_policy_estimator.cpp` (1119 LOC) —
  TxConfirmStats helper (private), EstimateMedianVal range-combining,
  estimateSmartFee max-of-three composition, Write/Read binary
  schema, ClearCurrent circular buffer, NewTx, processBlock,
  FlushUnconfirmed, FeeFilterRounder.
- `bitcoin-core/src/policy/fees/block_policy_estimator_args.{h,cpp}` —
  CLI flag wiring (DEFAULT_ACCEPT_STALE_FEE_ESTIMATES).
- `bitcoin-core/src/policy/feerate.{h,cpp}` — CFeeRate / FeePerVSize
  arithmetic (EvaluateFeeUp, EvaluateFeeDown, GetFee, GetFeePerK).
- `bitcoin-core/src/rpc/fees.cpp` — `estimatesmartfee` and
  `estimaterawfee` RPC.
- `bitcoin-core/src/kernel/mempool_entry.h` — RemovedMempoolTransactionInfo
  + NewMempoolTransactionInfo (m_chainstate_is_current,
  m_submitted_in_package, m_has_no_mempool_parents,
  m_mempool_limit_bypassed).
- `bitcoin-core/src/validationinterface.h` — TransactionAddedToMempool,
  TransactionRemovedFromMempool, MempoolTransactionsRemovedForBlock.

The lunarblock surface lives at:

- `src/fee.lua` — 302 LOC, the whole engine.
  - L5–25 bucket generation (FEE_BUCKETS, BUCKET_COUNT=40,
    FEE_SPACING=1.2, MIN=1, MAX=10000 sat/vB).
  - L30–37 `M.get_bucket_index(fee_rate)`.
  - L39 `FeeEstimator` class; `M.new(max_target)` at L45–74
    (single-horizon `self.confirmed[target][bucket]={count,total}`
    matrix + `self.failAvg[target][bucket]` matrix + decay=0.998).
  - L80–87 `FeeEstimator:track_tx(txid, fee_rate, height)`.
  - L92–116 `FeeEstimator:tx_confirmed(txid, conf_height)` —
    records success at all `t >= blocks_to_confirm` and "failure"
    (no, just total++) at `t < blocks_to_confirm`.
  - L127–161 `FeeEstimator:tx_removed(txid, reason)` — failAvg
    accounting on eviction (added in FIX-49).
  - L165–178 `FeeEstimator:on_block(height)` — sets best_height and
    decays everything.
  - L184–215 `FeeEstimator:estimate_fee(target, success_threshold)` —
    walks buckets high-to-low, returns first bucket meeting threshold.
  - L220–235 `FeeEstimator:estimate_smart_fee(target)` — serial
    fallback `(85% @ target) → (60% @ 2*target) → (1 sat/vB,
    max_target)`.
  - L239–266 `FeeEstimator:save(path)` — JSON v1 (atomic via
    `.tmp` + `os.rename`).
  - L271–300 `FeeEstimator:load(path)` — JSON v1.
- `src/main.lua:1126-1180` — fee_estimator init + wiring:
  - L1127 `fee_estimator = fee_mod.new(144)`.
  - L1128-1131 `fee_estimates.dat` load on startup.
  - L1138-1144 `on_tx_removed` callback wraps prior callback +
    calls `tx_removed(txid, reason)`.
  - L1148-1180 `on_block_connected` callback wraps prior +
    iterates block's transactions calling `tx_confirmed` + finally
    `on_block(height)`.
  - L1343 `track_tx` called UNCONDITIONALLY on every mempool
    accept (no IBD / no `m_has_no_mempool_parents` / no
    `m_submitted_in_package` gate).
  - L2273 `fee_estimator:save(fee_est_path)` on shutdown.
- `src/rpc.lua:959` — `self.fee_estimator = config.fee_estimator`
  on the RPCServer.
- `src/rpc.lua:2762-2779` — `estimatesmartfee` RPC (returns
  `{feerate=fr/100000, blocks=actual_target}` — no clamp to
  MinRelayFee/GetMinFee).
- `src/rpc.lua:2789-2828` — `estimaterawfee` RPC (always returns
  the same single-bucket entry under all 3 horizon keys; scale=1
  hard-coded; pass.startrange/endrange = `fee_rate` in sat/vB
  not BTC/kvB).

## Method

1. Read Core block_policy_estimator.{h,cpp} 1465 LOC end-to-end,
   feerate.{h,cpp}, rpc/fees.cpp.
2. Catalogue Core's algorithm into 30 distinct gates that go below
   the W114 surface (algorithm internals, persistence schema,
   reactor contract, wiring).
3. Read lunarblock `fee.lua` (302 LOC), the `main.lua` wiring
   (L1126–1180, L1343, L2273), and `rpc.lua` (L2762–2828).
4. Match Core gates to lunarblock surface and classify each as
   PRESENT / DIVERGENT / MISSING.
5. Catalogue divergences as BUG-N with file:line + Core ref.
6. Land xfail tests in `tests/test_w139_fee_estimation.lua` exercising
   each bug pre-fix.

## Severity scoring

- **P0** — Correctness divergence at the algorithm core: wrong fee
  estimate returned in normal operation, or stale/poisoned data
  consumed silently.
- **P1** — Missing primitive (three horizons, FeeFilterRounder,
  conservative mode, max-of-three composition) that meaningfully
  changes the recommended feerate vs Core.
- **P2** — Wiring/glue gaps (RPC unit mismatch, IBD gate, file
  persistence schema, validation interface decoupling) — visible
  to operators but doesn't return a wrong number in steady state.
- **P3** — Cosmetic / docs / fields hardcoded for future expansion.

## 30 W139 Audit Gates

| Gate | Description | Status | Core ref |
|------|-------------|--------|----------|
| G1 | `CURRENT_FEES_FILE_VERSION = 309900` and on-disk binary format with version negotiation | **DIVERGENT** (BUG-1 P2) — `src/fee.lua:243` saves `version=1` in JSON; binary 309900 layout absent | block_policy_estimator.cpp:37, :978–1062 |
| G2 | `MAX_FILE_AGE = 60h` stale-fee-file guard on read (refuse without `DEFAULT_ACCEPT_STALE_FEE_ESTIMATES`) | **MISSING** (BUG-2 P1) — `fee.lua:load` reads any age unconditionally | block_policy_estimator.h:32, .cpp:568–572 |
| G3 | `DEFAULT_ACCEPT_STALE_FEE_ESTIMATES = false` CLI override flag | **MISSING** (BUG-3 P3) — no `-acceptstalefeeestimates` argument | block_policy_estimator.h:35 |
| G4 | `FEE_FLUSH_INTERVAL = 1h` periodic flush of `fee_estimates.dat` while running (not only at shutdown) | **MISSING** (BUG-4 P2) — `main.lua:2273` only saves at shutdown; no in-flight flush task | block_policy_estimator.h:26 |
| G5 | `TxConfirmStats` separate class with explicit `(decay, scale, maxPeriods)` per horizon | **MISSING** (BUG-5 P1) — fee.lua has a single set of decay/target/matrices on the `FeeEstimator` instance, no TxConfirmStats helper | block_policy_estimator.cpp:78–176 |
| G6 | Three horizon scales: `SHORT_SCALE=1`, `MED_SCALE=2`, `LONG_SCALE=24` — `periodTarget = (confTarget + scale - 1) / scale` for ceiling rounding | **MISSING** (BUG-6 P1) — no scale param; tracks at raw 1-block granularity even at long horizons | block_policy_estimator.cpp:222, :254 |
| G7 | `ClearCurrent(nBlockHeight)` rolls the unconfirmed circular buffer at every block, flushing `unconfTxs[h % size]` into `oldUnconfTxs[bucket]` | **MISSING** (BUG-7 P1) — `fee.lua:on_block` only decays; no circular buffer; "in-mempool count for confTarget" calculation impossible | block_policy_estimator.cpp:207–214 |
| G8 | `oldUnconfTxs[bucket]` carryover counter for txs that aged past `GetMaxConfirms` | **MISSING** (BUG-8 P1) — no equivalent; effectively `extraNum` in EstimateMedianVal is always 0 | block_policy_estimator.cpp:115, :291–292 |
| G9 | `Record(blocksToConfirm, feerate)` increments `confAvg[i][bucket]` for ALL `i >= periodsToConfirm`, AND increments `txCtAvg[bucket]` and `m_feerate_avg[bucket]` (sum of feerates) | **DIVERGENT** (BUG-9 P0) — `tx_confirmed` (fee.lua:103) increments only `count` + `total` (no per-bucket sum-of-feerates), so median feerate within bucket cannot be computed; estimate returns `FEE_BUCKETS[best_bucket]` (the bucket UPPER bound) rather than `m_feerate_avg[j] / txCtAvg[j]` | block_policy_estimator.cpp:217–229, :345–365 |
| G10 | `txCtAvg[bucket]` decayed total-tx counter per bucket (independent of confirmation-period dimension) | **MISSING** (BUG-10 P1) — `fee.lua` only keeps the 2D `confirmed[t][b]={count,total}`; no separate 1D txCtAvg | block_policy_estimator.cpp:88, :226–228 |
| G11 | `EstimateMedianVal` range-combining: walks buckets high-to-low, accumulating `partialNum` until `partialNum >= sufficientTxVal / (1 - decay)` before testing curPct against threshold (so groups share consistent sample sizes across confirmation targets) | **DIVERGENT** (BUG-11 P0) — `fee.lua:194–206` tests every bucket independently against a flat `total >= 10`; no range merging, no decay-adjusted threshold; sub-buckets that fail the 10-sample test are silently skipped | block_policy_estimator.cpp:245–342 |
| G12 | `EstimateMedianVal` reports both `passBucket` (lowest passing range) AND `failBucket` (highest failing range) into `EstimationResult` | **MISSING** (BUG-12 P1) — `fee.lua:184–215` returns only `(fee_rate, reliable)`; failBucket absent; rpc.lua manufactures a synthetic single-bucket pass | block_policy_estimator.cpp:71–88, :310–340 |
| G13 | `failNum` counter and `failBucket.leftMempool` derived from `failAvg[periodTarget-1][bucket]` (txs that left mempool without confirming within target) | **DIVERGENT** (BUG-13 P1) — `failAvg` IS tracked in fee.lua:127–161 but never consumed by `estimate_fee`; the failure axis is dead-data (G7 of W114 noted absence; FIX-49 added accumulation but not consumption) | block_policy_estimator.cpp:289, :383 |
| G14 | `estimateSmartFee` returns `max(halfEst@target/2 60%, fullEst@target 85%, doubleEst@2*target 95%)`, then optionally `consEst@2*target` over LONG horizon when conservative=true | **DIVERGENT** (BUG-14 P0) — `fee.lua:220-235` falls back serially: first tries 85% @ target, then 60% @ 2*target, else returns 1 sat/vB. Never computes half/double/conservative, so estimate can be LOWER than Core (Core takes the max across thresholds, so a high 60%@target/2 estimate forces a higher overall fee) | block_policy_estimator.cpp:864–956 |
| G15 | `estimateSmartFee` clamps `confTarget == 1` UP to `confTarget = 2` ("not possible for target 1") | **DIVERGENT** (BUG-15 P1) — `fee.lua:186–187` allows target=1 through unchanged (also covered W114 G10) | block_policy_estimator.cpp:889–890 |
| G16 | `MaxUsableEstimate = min(longStats->GetMaxConfirms(), max(BlockSpan, HistoricalBlockSpan) / 2)` clamps `confTarget` so we don't extrapolate beyond observed history | **MISSING** (BUG-16 P1) — `fee.lua` does not track `firstRecordedHeight` / `historicalFirst` / `historicalBest`; `BlockSpan` / `HistoricalBlockSpan` / `MaxUsableEstimate` all absent; `estimate_smart_fee(1008)` works on a freshly-booted node | block_policy_estimator.cpp:798–802 |
| G17 | `FeeReason` enum + `FeeCalculation.reason` field emitted to caller (FeeCalculation::reason = HALF_ESTIMATE / FULL_ESTIMATE / DOUBLE_ESTIMATE / CONSERVATIVE / MEMPOOL_MIN / FALLBACK) | **MISSING** (BUG-17 P2) — `fee.lua:estimate_smart_fee` returns only `(fee_rate, actual_target)`; no reason; RPC cannot expose it | block_policy_estimator.h:59–68, :90–97 |
| G18 | `EstimatorBucket` fields { start, end, withinTarget, totalConfirmed, inMempool, leftMempool } emitted by `estimaterawfee` for each horizon | **DIVERGENT** (BUG-18 P0) — `rpc.lua:2811–2818` synthesizes a single bucket with `startrange=endrange=fee_rate` (sat/vB units, not BTC/kvB; W114 G14), `withintarget=totalconfirmed=reliable and 1 or 0` (boolean cast not real count), `inmempool=leftmempool=0` always | rpc/fees.cpp:181–193 |
| G19 | `estimaterawfee` per-horizon `pass.startrange/endrange` and `feerate` emitted in BTC/kvB (Core uses `ValueFromAmount(GetFeePerK())`) | **DIVERGENT** (BUG-19 P1) — `rpc.lua:2812–2813` emits `startrange=endrange=fee_rate` in sat/vB; only `feerate` is divided by 100000 (W114 G14 documented this; relisted as P1 because the unit mismatch in the same payload is operator-confusing) | rpc/fees.cpp:181–186 |
| G20 | `estimaterawfee` skips horizons where `conf_target > HighestTargetTracked(horizon)` (so e.g. conf_target=100 only emits `medium` + `long`, not `short`) | **MISSING** (BUG-20 P2) — `rpc.lua:2803` always emits all three horizons (W114 G13 documented) | rpc/fees.cpp:170–175 |
| G21 | `estimaterawfee` per-horizon `scale` is 1 / 2 / 24 (matches TxConfirmStats.scale) | **DIVERGENT** (BUG-21 P3) — `rpc.lua:2810` hardcodes `entry.scale = 1` (W114 G25) | rpc/fees.cpp:199 |
| G22 | `estimatesmartfee` clamps returned feerate via `std::max({feeRate, mempool.GetMinFee(), mempool.m_opts.min_relay_feerate})` before emit | **DIVERGENT** (BUG-22 P0) — `rpc.lua:2770–2776` returns the raw estimator output; no clamping to MinRelayFee (1000 sat/kvB) or rolling mempool minimum (`mempool.lua:get_min_fee`). An empty / cold node can return < min-relay fee that, if used, will be rejected by every relay-policy peer | rpc/fees.cpp:82–86 |
| G23 | `estimatesmartfee` accepts `estimate_mode` (ECONOMICAL / CONSERVATIVE / UNSET) and threads `conservative=(mode == CONSERVATIVE)` into `estimateSmartFee(confTarget, &feeCalc, conservative)` | **MISSING** (BUG-23 P0) — `rpc.lua:2763–2779` ignores `params[2]`; CONSERVATIVE mode always returns ECONOMICAL output (W114 G12 documented this; relisted P0 because Core 26.0 made `estimate_mode` mandatory-default-"economical" and many UIs default to CONSERVATIVE) | rpc/fees.cpp:32–94 |
| G24 | `CFeeRate::GetFee(virtual_bytes)` uses `EvaluateFeeUp` (ceiling division) so 1 sat/vB on a 251-byte tx returns 1 sat (not 0); `GetFeePerK` uses `EvaluateFeeDown` | **NOT-APPLICABLE-LUA-FLOATS** (BUG-24 P2) — `fee.lua` operates on `sat/vB` doubles throughout; `mempool.lua:1084` documents the W96 fix that uses `math.ceil` for the relay floor, but the estimator's `fee_rate` argument is whatever the caller computes (`mempool.lua:1289` does `fee * 1000 / vsize` with float division). When `entry.fee_rate` is passed to `track_tx`, it has been rounded by the caller; estimator-internal arithmetic can drift by ≤ 1 sat versus Core's int rounding | feerate.cpp:11–27, feerate.h:62 |
| G25 | `TransactionAddedToMempool` / `TransactionRemovedFromMempool` / `MempoolTransactionsRemovedForBlock` are the three CValidationInterface entry points; engine reacts to those, not raw "block connected" | **DIVERGENT** (BUG-25 P2) — `main.lua:1148–1180` ties into `on_block_connected` directly and `on_tx_removed` per-tx callback; there's no `MempoolTransactionsRemovedForBlock` batch with `RemovedMempoolTransactionInfo` carrying fee/vsize at removal time — `tx_confirmed` re-reads the tx and recomputes via `mempool.callbacks` indirection that has already evicted the entry | block_policy_estimator.h:267–273, .cpp:581–594 |
| G26 | `processTransaction` gates tracking on `validForFeeEstimation = !m_mempool_limit_bypassed && !m_submitted_in_package && m_chainstate_is_current && m_has_no_mempool_parents` | **MISSING** (BUG-26 P0) — `main.lua:1343` calls `fee_estimator:track_tx` UNCONDITIONALLY for any accepted mempool tx; during IBD, package-relay, or for any chained child the engine ingests data that Core would discard, biasing estimates LOWER (cheap chained children look like full-fee primary txs) | block_policy_estimator.cpp:614–626 |
| G27 | `processBlock` ignores blocks where `nBlockHeight <= nBestSeenHeight` (re-org safety: side-chain and 1-block re-org blocks don't double-count) | **DIVERGENT** (BUG-27 P0) — `main.lua:1149–1159` runs `tx_confirmed` for every tx in any block-connected callback; on a reorg with disconnect-then-reconnect-at-same-height, txs are double-counted; `chain_state.callbacks.on_block_disconnected` is wired (`main.lua:1112`) but the fee estimator gets nothing on disconnect, leaving stale `unconfirmed` entries and double-counting on re-application | block_policy_estimator.cpp:673–680 |
| G28 | `FlushUnconfirmed()` on shutdown calls `_removeTx(hash, inBlock=false)` for every tracked unconfirmed tx, so they all get counted as failures | **MISSING** (BUG-28 P1) — `main.lua:2273` calls `save(fee_est_path)` which JSON-serializes `confirmed` only; the `unconfirmed` map and the freshly-converted-to-failure entries are dropped on the floor (W114 G8 documented absence) | block_policy_estimator.cpp:1064–1076 |
| G29 | `FeeFilterRounder` quantizes the per-peer feefilter broadcast feerate using a 1.1-spaced fee set seeded from `min_incremental_fee` (MAX_FILTER_FEERATE=1e7) for BIP-133 privacy | **MISSING** (BUG-29 P1) — no FeeFilterRounder type in lunarblock; `peer.lua:758` hardcodes `feefilter = 100000 sat/kvB` (= 100 sat/vB) regardless of mempool state, and does NOT re-broadcast on rolling-min-fee change (W136 BUG covered the broadcast side; W139 covers the rounder primitive). When implemented, the rounder needs `feerate.GetFeePerK()` semantics and an `insecure_rand` source for privacy (Core uses 1-in-3 down-round on lower_bound hits) | block_policy_estimator.h:323–344, .cpp:1085–1119 |
| G30 | Mempool-loaded txs replay through `processTransaction` so persistent mempool seeds the estimator's `mapMemPoolTxs` view of currently-pending fee histograms | **DIVERGENT** (BUG-30 P1) — `mempool_persist.lua` (W122 lineage) reloads txs at startup, but `main.lua:1127` instantiates the fee estimator BEFORE the mempool is populated; the `track_tx` calls during `load_mempool` are missed because the `on_block_connected` callback chain only fires on real block delivery. As a result, restarting a node loses the in-flight unconfirmed view that Core preserves via the validation-interface reactor | block_policy_estimator.cpp:581–584, mempool_persist.cpp:99–132 |

## BUG catalogue

### BUG-1 (P2) — fee_estimates.dat uses JSON v1 not Core binary v309900

`src/fee.lua:241–266` serializes `{version=1, best_height,
max_target, decay, confirmed[][]}` as JSON. Core's binary layout
(`block_policy_estimator.cpp:978–999`) is

```
CURRENT_FEES_FILE_VERSION                 (i32)
nBestSeenHeight                           (u32)
firstRecordedHeight | historicalFirst     (u32)
nBestSeenHeight | historicalBest          (u32)
buckets                                   (VectorFormatter<EncodedDouble>)
feeStats.{decay, scale, m_feerate_avg, txCtAvg, confAvg, failAvg}
shortStats.…
longStats.…
```

with version-tolerant Read that throws on (a) `decay <= 0 || >= 1`,
(b) `scale == 0`, (c) bucket-count mismatch, (d) `maxConfirms > 6*24*7`
(=1008). lunarblock's load (`fee.lua:271–300`) only rejects on
version != 1; no semantic guards.

**Severity P2** — file is local-only, but the format makes
cross-tool interop and corruption diagnosis harder.

### BUG-2 (P1) — no MAX_FILE_AGE stale-fee-file guard

`fee.lua:271–300 (load)` reads the JSON unconditionally. Core
(`block_policy_estimator.cpp:568–572`) refuses to use a fee file
older than `MAX_FILE_AGE = 60h` unless `read_stale_estimates=true`
(set via the `-acceptstalefeeestimates` CLI flag, default false).
A node restarted after several days with a stale `fee_estimates.dat`
will resurrect a fee distribution from a different network state.

### BUG-3 (P3) — `-acceptstalefeeestimates` CLI flag absent

Tied to BUG-2. Core's `block_policy_estimator_args.{h,cpp}` exposes
the `DEFAULT_ACCEPT_STALE_FEE_ESTIMATES = false` toggle so the
operator can override the 60h refusal. No equivalent in
`src/main.lua` argparse.

### BUG-4 (P2) — no `FEE_FLUSH_INTERVAL = 1h` periodic flush

`main.lua:2273` calls `fee_estimator:save(fee_est_path)` only on
graceful shutdown. A SIGKILL / power loss loses all bucket data
acquired since startup. Core writes every 1h
(`block_policy_estimator.h:26` + scheduler call in `init.cpp`).

### BUG-5 (P1) — no TxConfirmStats class

Core encapsulates `(decay, scale, maxPeriods, buckets, bucketMap,
confAvg, failAvg, txCtAvg, m_feerate_avg, unconfTxs, oldUnconfTxs)`
in one helper that is instantiated three times (short/medium/long).
lunarblock inlines a SINGLE set of stats fields on `FeeEstimator`
itself with one decay and one max_target, so adding short/long
horizons is a substantial refactor not a parameter change.

### BUG-6 (P1) — no `(periodTarget = (confTarget + scale - 1) / scale)` ceiling rounding

Core (`block_policy_estimator.cpp:222`) maps `blocksToConfirm` to
"periods" via ceiling division by `scale`. With LONG_SCALE=24 a
tx confirmed in block 7 records as period 1 (i.e., target-up-to-24
blocks). lunarblock records at raw block granularity, so its
single-horizon data approximates only `feeStats` (scale=2) and
cannot represent the long horizon's coarser bucketing.

### BUG-7 (P1) — no `ClearCurrent(nBlockHeight)` circular-buffer roll

Core's `unconfTxs[GetMaxConfirms()][bucket]` ring buffer tracks
"how many txs entered the mempool N blocks ago in bucket X" so
`EstimateMedianVal` can add the still-pending `extraNum` to its
denominator. `fee.lua:on_block` only multiplies stats by decay;
the per-block-of-entry breakdown is lost.

### BUG-8 (P1) — no `oldUnconfTxs[bucket]` carryover

Core's `oldUnconfTxs[bucket]` collects txs that aged past
`GetMaxConfirms` (still unconfirmed). Without it
`EstimateMedianVal::extraNum` is always 0 in lunarblock, biasing
estimates because pending old txs are silently dropped.

### BUG-9 (P0) — `Record` doesn't accumulate per-bucket feerate sum (`m_feerate_avg`)

The single most consequential algorithmic divergence:

Core (block_policy_estimator.cpp:217–229):
```cpp
void TxConfirmStats::Record(int blocksToConfirm, double feerate) {
    int periodsToConfirm = (blocksToConfirm + scale - 1) / scale;
    unsigned int bucketindex = bucketMap.lower_bound(feerate)->second;
    for (size_t i = periodsToConfirm; i <= confAvg.size(); i++)
        confAvg[i - 1][bucketindex]++;
    txCtAvg[bucketindex]++;
    m_feerate_avg[bucketindex] += feerate;     // ← sum-of-feerates per bucket
}
```

then in `EstimateMedianVal` (block_policy_estimator.cpp:362):
```cpp
median = m_feerate_avg[j] / txCtAvg[j];
```

lunarblock (`fee.lua:103–113`) only increments `count` and `total`
per (target,bucket) cell; there's no per-bucket sum-of-feerates,
so the estimator can't compute the within-bucket median feerate.
It falls back to returning `FEE_BUCKETS[best_bucket]` (the
bucket's UPPER bound), which systematically overestimates by
up to `(FEE_SPACING - 1) * actual_median` (with FEE_SPACING=1.2
that's up to +20%; with Core's 1.05 it'd be +5%).

(W114 G9 noted the absence of `m_feerate_avg`; W139 promotes to
P0 because the result is a wrong number returned to RPC callers
in normal operation.)

### BUG-10 (P1) — no separate `txCtAvg[bucket]` total-tx counter

Decoupled from `confirmed[t][b]`, Core's `txCtAvg[bucket]` is a
single-dimensional sum-of-txs-per-bucket. lunarblock collapses
this into `confirmed[t][b].total`, which is per-target so the
range-merging walk can't read "total txs in bucket b across all
targets" without summing T cells.

### BUG-11 (P0) — `estimate_fee` doesn't range-combine; threshold isn't decay-adjusted

Core's `EstimateMedianVal` accumulates `partialNum = sum of
txCtAvg over the current curNear..curFar bucket range`, only
testing curPct against threshold when `partialNum >=
sufficientTxVal / (1 - decay)`. With MED decay=0.9952 and
SUFFICIENT_FEETXS=0.1 that's ~20.8 txs per range; lunarblock
hardcodes `total >= 10` flat. This means:

1. Buckets with < 10 confirmed are silently skipped (Core would
   merge them with adjacent buckets to hit the threshold).
2. The threshold isn't decay-adjusted, so SHORT-style fast-decay
   data needs more samples to qualify (Core: 0.5/(1-0.962)≈13.2)
   and LONG-style slow-decay data needs more samples
   (0.1/(1-0.99931)≈144.9).

Concretely, a sparse bucket pattern (e.g. 8 txs at 50 sat/vB,
12 at 100 sat/vB, 8 at 200 sat/vB) makes lunarblock skip the 50
and 200 buckets (8 < 10) and only consider 100; Core merges them
into a single 50–200 range, accepts as a passing sample, and
returns the in-range median (~100 weighted by m_feerate_avg).

### BUG-12 (P1) — no `failBucket` reported (only passBucket)

Core's `EstimationResult` carries both `pass` and `fail`
EstimatorBuckets so the RPC can show the operator the highest
range that JUST FAILED to meet threshold (very useful for "your
6-block target is just barely missing — go 1 bucket higher").
`fee.lua:estimate_fee` returns only `(fee_rate, reliable)`.

### BUG-13 (P1) — `failAvg` populated (FIX-49) but never consumed

`fee.lua:127–161` (tx_removed) populates `failAvg[t][b]` on
mempool eviction, BUT `estimate_fee`/`estimate_smart_fee`
(`fee.lua:184–235`) never read `failAvg`. Core's
`EstimateMedianVal` includes `failNum +=
failAvg[periodTarget-1][bucket]` in the denominator (line 289)
so the threshold check
`nConf / (totalNum + failNum + extraNum) >= successBreakPoint`
penalizes buckets where a lot of txs in that feerate range
failed to confirm. lunarblock omits `failNum` from its check,
inflating the success rate of bad buckets. Result: estimates
favor feerates that were historically evicted.

### BUG-14 (P0) — `estimate_smart_fee` doesn't compute `max(halfEst, fullEst, doubleEst)`

Core (`block_policy_estimator.cpp:919–940`):
```cpp
double halfEst   = estimateCombinedFee(confTarget/2,     HALF_SUCCESS_PCT,  ...);
double median = halfEst;
double actualEst = estimateCombinedFee(confTarget,        SUCCESS_PCT,       ...);
if (actualEst > median) median = actualEst;
double doubleEst = estimateCombinedFee(2 * confTarget,    DOUBLE_SUCCESS_PCT,...);
if (doubleEst > median) median = doubleEst;
```

lunarblock (`fee.lua:220–235`):
```lua
local fee, reliable = self:estimate_fee(target, 0.85)
if reliable then return fee, target end
fee, reliable = self:estimate_fee(target * 2, 0.60)
if reliable then return fee, target * 2 end
return 1, self.max_target
```

Core takes the MAX of three thresholds — so even if 85%@target
succeeds with a low fee, a high 60%@target/2 estimate forces the
overall fee higher. lunarblock takes the FIRST passing threshold,
which can return a LOWER fee than Core. (W114 G11 documented the
absence; W139 promotes to P0 because the recommended fee is the
public output of the engine and this is the canonical algorithm.)

### BUG-15 (P1) — `confTarget==1` not clamped to 2

`fee.lua:186 (target = math.max(target, 1))` lets target=1
through. Core `if (confTarget == 1) confTarget = 2;` because
"it's not possible to get reasonable estimates for confTarget of
1" (comment at block_policy_estimator.cpp:889). The W114 audit
documented this at LOW; W139 promotes to P1 because callers
asking for "next-block" reliably get garbage data from lunarblock.

### BUG-16 (P1) — no `MaxUsableEstimate` history-aware clamp

Core (`block_policy_estimator.cpp:798–802`):
```cpp
unsigned int MaxUsableEstimate() const {
    return std::min(longStats->GetMaxConfirms(),
                    std::max(BlockSpan(), HistoricalBlockSpan()) / 2);
}
```

clamps `confTarget` so we never extrapolate beyond half of the
observed block history. lunarblock has no `firstRecordedHeight` /
`historicalFirst` / `historicalBest`, so a freshly-booted node
returns optimistic estimates for `target=1008` despite having
seen zero blocks.

### BUG-17 (P2) — no `FeeReason` / `FeeCalculation.reason` emission

Core's `FeeCalculation` carries a `FeeReason` (one of
HALF_ESTIMATE, FULL_ESTIMATE, DOUBLE_ESTIMATE, CONSERVATIVE,
MEMPOOL_MIN, FALLBACK, REQUIRED) telling the caller which
sub-estimate produced the answer. lunarblock returns only
(fee_rate, target); the RPC layer can't tell the operator what
the engine actually computed.

### BUG-18 (P0) — `estimaterawfee` emits a fake single bucket

`rpc.lua:2810–2818` returns the same synthesized struct for
all three horizon keys:
```lua
entry.pass = {
  startrange = fee_rate, endrange = fee_rate,
  withintarget = reliable and 1 or 0,
  totalconfirmed = reliable and 1 or 0,
  inmempool = 0, leftmempool = 0,
}
```

Every bucket-statistic field is either echoed from the answer
(startrange==endrange==fee_rate) or a constant
(withintarget=0|1, inmempool=0, leftmempool=0). Core's response
is per-horizon, with `startrange = round(buckets[minBucket-1])`,
`endrange = round(buckets[maxBucket])` (sat/kvB ints) and real
`withinTarget`/`totalConfirmed`/`inMempool`/`leftMempool`
floats. This makes `estimaterawfee` effectively unusable for fee
forensics — its entire purpose is exposing those raw counts.

### BUG-19 (P1) — `pass.startrange/endrange` unit mismatch (sat/vB not sat/kvB)

Tied to BUG-18 and W114 G14. Core's
`passbucket.pushKV("startrange", round(buckets.pass.start))`
emits sat/kvB (integer). lunarblock `entry.pass.startrange =
fee_rate` is in sat/vB, off by a factor of 1000 (e.g. 5000 sat/vB
should be 5 in sat/kvB, but the JSON says 5000). The `feerate`
field IS divided by 100000 (sat/vB → BTC/kvB) so within the
same response object two fields use two different units.

### BUG-20 (P2) — `estimaterawfee` doesn't skip out-of-range horizons

`rpc.lua:2803-2826` iterates `{ short=12, medium=144, long=1008 }`
without checking `conf_target` against each horizon's max. Core
(rpc/fees.cpp:174–175):
```cpp
if (conf_target > fee_estimator.HighestTargetTracked(horizon)) continue;
```

skips entirely. Result: `estimaterawfee(1008)` from lunarblock
emits a `short` key even though SHORT only tracks up to
SHORT_BLOCK_PERIODS * SHORT_SCALE = 12 blocks.

### BUG-21 (P3) — `entry.scale = 1` hardcoded for all horizons

`rpc.lua:2810`: `entry.scale = 1`. Core: short=1, medium=2,
long=24. W114 G25 documented this; P3 because today there's no
multi-horizon engine to emit a different value, but the schema
field is wrong for any client doing math on it.

### BUG-22 (P0) — `estimatesmartfee` doesn't clamp to MinRelayFee/GetMinFee

Core (`rpc/fees.cpp:82–86`):
```cpp
CFeeRate min_mempool_feerate{mempool.GetMinFee()};
CFeeRate min_relay_feerate{mempool.m_opts.min_relay_feerate};
feeRate = std::max({feeRate, min_mempool_feerate, min_relay_feerate});
```

lunarblock (`rpc.lua:2770–2776`) returns the raw estimator
output. If the engine recommends < min-relay-fee (e.g. cold-start
with insufficient data), `estimatesmartfee` returns a feerate
that will be REJECTED by every peer with default policy
(min_relay_fee=1000 sat/kvB). Wallet applications then create
transactions stuck at the bottom of the mempool.

### BUG-23 (P0) — `estimate_mode` parameter not wired

`rpc.lua:2763-2779` reads `params[1]` (conf_target) only.
`params[2]` (estimate_mode in {"unset", "economical",
"conservative"}) is ignored. Core threads `conservative =
fee_mode == FeeEstimateMode::CONSERVATIVE` into `estimateSmartFee`,
which then runs `estimateConservativeFee(2*confTarget, …)` over
the LONG horizon. lunarblock returns the same value for any
mode, breaking CONSERVATIVE-defaulting clients (Bitcoin Knots,
many UIs).

### BUG-24 (P2) — `CFeeRate` ceiling-rounding not enforced for estimator input

The fee_rate passed to `fee_estimator:track_tx` is whatever the
mempool entry stores. `mempool.lua:1289 (fee_rate_per_kb = fee *
1000 / vsize)` is float division. Core's `CFeeRate(nFeePaid,
virtual_bytes)` uses `FeePerVSize(nFeePaid, virtual_bytes)`
which preserves the (fee, vsize) fraction and EvaluateFeeDown for
display via GetFeePerK. Drift is ≤ 1 sat/kvB per tx, but it
accumulates across `m_feerate_avg` summation. P2 because the
visible RPC output differs by ≤1 sat/kvB for typical values; not
zero.

### BUG-25 (P2) — engine not driven by CValidationInterface contract

Core invokes the estimator from three CValidationInterface hooks:
`TransactionAddedToMempool(NewMempoolTransactionInfo)`,
`TransactionRemovedFromMempool(CTransactionRef, reason, …)`,
`MempoolTransactionsRemovedForBlock(vector<RemovedMempoolTransactionInfo>, height)`.
The `RemovedMempoolTransactionInfo` carries `m_fee`,
`m_virtual_transaction_size`, `txHeight` SNAPSHOTTED at removal
time (so a 6-week-stuck tx still reports its original feerate).

`main.lua:1148–1180` instead reads transactions back from
`block.transactions`, recomputes the txid, and asks the estimator
to record "1 block to confirm". The original entry height and
the original feerate at admission must be looked up from the
mempool entry (likely already evicted). Today `tx_confirmed`
takes only `(txid_hex, confirmed_height)`; it pulls
`entry_height` from `self.unconfirmed[txid_hex]` — but if the
tx was never tracked (e.g. accepted before estimator init, or
during IBD where Core would skip per BUG-26), the call is a
silent no-op.

### BUG-26 (P0) — `validForFeeEstimation` gate missing

`main.lua:1343 (fee_estimator:track_tx(txid_hex, entry.fee_rate,
chain_state.tip_height))` is called for every accepted mempool
tx. Core (`block_policy_estimator.cpp:614–626`) gates this on:

```cpp
const bool validForFeeEstimation =
       !tx.m_mempool_limit_bypassed
    && !tx.m_submitted_in_package
    && tx.m_chainstate_is_current
    && tx.m_has_no_mempool_parents;
if (!validForFeeEstimation) { untrackedTxs++; return; }
```

Consequences:

- **IBD bias** — during initial sync, blocks arrive faster than
  real time, and confirmations within the just-replayed
  historical mempool happen "instantly". lunarblock records
  thousands of "0–1 block confirmations" at IBD rates,
  swamping the decayed moving average. (W114 G28 noted; W139
  promotes to P0 because this systematically poisons the
  estimator for HOURS after IBD ends.)
- **Package-relay bias** — package CPFP children with a
  zero-fee parent get tracked as "200 sat/vB tx confirmed in 1
  block" when really the FAMILY paid 200 sat/vB on 2 vsize
  units. Inflates the "high-fee bucket confirms fast" signal.
- **Chained-children bias** — a child of an in-mempool parent
  inherits the parent's confirm time but the child's feerate.
  Mempool descendants of a stuck parent record as
  "high-fee tx eventually confirmed" when really the bottleneck
  was the parent.

### BUG-27 (P0) — no reorg handling; double-count on disconnect-reconnect

`main.lua:1149–1159 (on_block_connected handler)` runs
`tx_confirmed` for every tx in any block-connected callback.
Core's `processBlock` (block_policy_estimator.cpp:673–680) early-returns
when `nBlockHeight <= nBestSeenHeight`, so on a reorg
(disconnect block H, reconnect new block H'), the txs in H' are
recorded — but the txs in old H were never UN-recorded.
lunarblock has the same `nBlockHeight <= nBestSeenHeight` issue
PLUS no equivalent of `on_block_disconnected` rolling back
`tx_confirmed` increments. On a deep reorg the
`confirmed[t][b]` matrices are corrupt with double-counted txs.

### BUG-28 (P1) — `FlushUnconfirmed` on shutdown absent

Core's shutdown path:
```cpp
void CBlockPolicyEstimator::FlushUnconfirmed() {
    LOCK(m_cs_fee_estimator);
    while (!mapMemPoolTxs.empty()) {
        _removeTx(mapMemPoolTxs.begin()->first, false);
    }
}
```

converts every tracked unconfirmed tx into a failure entry so the
`failAvg` matrix gets that "stuck txs" signal. `main.lua:2273`
calls `save(fee_est_path)` which JSON-serializes `confirmed` but
NOT `unconfirmed` or `failAvg` — they're discarded entirely.
W114 G8 noted absence; W139 keeps at P1 because (a) failAvg IS
in-memory tracked since FIX-49, but (b) it's neither flushed at
shutdown nor read by estimate_fee anyway.

### BUG-29 (P1) — FeeFilterRounder primitive missing

`peer.lua:758` blasts `feefilter = 100000 sat/kvB` (= 100 sat/vB)
at handshake end — hardcoded, no quantization, no MAX_MONEY
override during IBD (covered W136 BUG-15/16/17). Core's
`FeeFilterRounder::round(CAmount currentMinFee)`
(block_policy_estimator.cpp:1109) quantizes via a 1.1-spaced fee
set (`MakeFeeSet`) seeded from `min_incremental_fee`, with a
1-in-3 random down-round for privacy. The current rolling-min
also feeds back into the rounder. lunarblock cannot implement
the W136 broadcast loop correctly without this primitive.

### BUG-30 (P1) — mempool-load doesn't seed estimator

`main.lua:1127 (fee_estimator = fee_mod.new(144))` instantiates
the estimator BEFORE the persistent mempool is reloaded. The
`mempool_persist.lua` reload runs accept_transaction but
`fee_estimator:track_tx` is called from the P2P tx handler
(`main.lua:1343`), not from the mempool's load path. Result:
on a restart with a 5000-tx mempool, the estimator starts
with 0 unconfirmed; the first 5000 block-connected txs
generate `tx_confirmed` calls for txids the estimator never
saw (silent no-op early-return at `fee.lua:94`), so the
restart-and-warm-up window is effectively a fresh boot.

## Summary

- **8 P0** (BUG-9, -11, -14, -18, -22, -23, -26, -27) —
  algorithm core returns wrong fee or RPC payload returns wrong
  units; chain-state biases (IBD, reorg) actively poison the
  matrix.
- **14 P1** — missing primitives (TxConfirmStats, three horizons,
  scale-aware periodTarget, ClearCurrent circular buffer,
  oldUnconfTxs, txCtAvg, MaxUsableEstimate, FeeFilterRounder,
  FlushUnconfirmed, MAX_FILE_AGE stale guard), confTarget=1 clamp,
  consumer-side gaps (failAvg accumulated but unused, no
  failBucket emission, mempool-load doesn't seed),
  startrange/endrange unit conversion.
- **6 P2** — file format (JSON vs binary v309900, FEE_FLUSH_INTERVAL),
  CFeeRate ceiling-rounding drift, CValidationInterface wiring,
  IBD-protocol-state wiring divergences visible to operators,
  FeeReason emission, estimaterawfee horizon-skip.
- **2 P3** — cosmetic / forward-compat (CLI flag, hardcoded
  scale field per horizon).

The two algorithmic divergences (BUG-9, BUG-11, BUG-14) together
mean lunarblock's `estimatesmartfee` output is **systematically
biased** vs Core: high by `(FEE_SPACING-1)≈20%` on the bucket
upper-bound override (BUG-9), low by missing
max-of-three composition (BUG-14), and unstable in sparse-data
regimes by lack of range-merging (BUG-11). The chain-state
biases (BUG-26 IBD, BUG-27 reorg) compound these errors over
runtime.

The minimal fix to make `estimatesmartfee` actionable for
relay-policy peers is **BUG-22** (clamp to MinRelayFee) — one
line in `rpc.lua:2776`.

## Two-pipeline / cross-wave notes

- **W114 surface vs W139 algorithm** — W114 already catalogued
  24 BUGs at the bucket-constants and surface level. W139
  preserves the W114 entries for traceability (G15→G15, G10→G10,
  etc.) but adds new BUG entries at the algorithm-internals
  layer (range merging, m_feerate_avg, periodTarget rounding,
  oldUnconfTxs circular buffer, FlushUnconfirmed, IBD/reorg
  semantics, FeeFilterRounder).
- **W136 BIP-133 feefilter** — W136 documented the
  outbound/inbound feefilter message protocol; W139 documents
  the underlying FeeFilterRounder primitive that should drive
  the broadcast value.
- **W120 mempool RBF / W130 BIP-125 feebumper** — overlap
  zero; this wave is the estimator engine not RBF policy.
- **FIX-49** (already landed) wired `tx_removed → failAvg` but
  the consumer side (`estimate_fee` reading `failAvg`) was not
  finished; BUG-13 captures this dead-data state.

## Methodology citations

- Bitcoin Core 30.x branch (commit pinned in
  `bitcoin-core/` submodule).
- Cross-checked W114 (`tests/test_w114_fee_estimation.lua`)
  bug set; new bugs in W139 do not duplicate W114 bugs (W114
  bugs renumbered into the W139 gate table only where
  algorithmically distinct).

— end W139 audit (lunarblock) —
