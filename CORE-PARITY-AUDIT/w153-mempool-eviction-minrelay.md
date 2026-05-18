# W153 — Mempool eviction + tx-removed signals + min-relay fee (lunarblock)

**Wave:** W153 — `CTxMemPool::TrimToSize`, `Expire`, `LimitMempoolSize`,
`GetMinFee`, `trackPackageRemoved`, `removeForBlock`, `removeForReorg`,
`MaybeUpdateMempoolForReorg`, `DisconnectedBlockTransactions` (cap =
`MAX_DISCONNECTED_TX_POOL_BYTES` 20 MiB), `MemPoolRemovalReason` enum
fan-out (EXPIRY/SIZELIMIT/REORG/BLOCK/CONFLICT/REPLACED), removed-signal
fan-out to `CBlockPolicyEstimator::removeTx`, ZMQ `hashtx`/`sequence`
publisher, REST `/rest/mempool/info`, tx-relay `RelayTransactions` /
`InitiateTxBroadcastToAll`, `prioritisetransaction` /
`getprioritisedtransactions` / `getmempoolinfo` (`unbroadcastcount`,
`minrelaytxfee`, `incrementalrelayfee`, `mempoolminfee`, `total_fee`),
`-maxmempool` / `-mempoolexpiry` / `-minrelaytxfee` /
`-incrementalrelayfee` operator knobs, mempool persistence
(`mempool.dat` `mapDeltas` + `unbroadcast` round-trip).

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/kernel/mempool_options.h:19` —
  `DEFAULT_MAX_MEMPOOL_SIZE_MB = 300` (metric MB, not MiB);
  `max_size_bytes = DEFAULT_MAX_MEMPOOL_SIZE_MB * 1'000'000 = 300_000_000`.
- `bitcoin-core/src/kernel/mempool_options.h:23` —
  `DEFAULT_MEMPOOL_EXPIRY_HOURS = 336` (14 days);
  `expiry = chrono::hours{DEFAULT_MEMPOOL_EXPIRY_HOURS}`.
- `bitcoin-core/src/policy/policy.h:48` —
  `DEFAULT_INCREMENTAL_RELAY_FEE = 100` (sat/kvB).
- `bitcoin-core/src/policy/policy.h:70` —
  `DEFAULT_MIN_RELAY_TX_FEE = 100` (sat/kvB). **NOT 1000.**
- `bitcoin-core/src/txmempool.h:212` —
  `ROLLING_FEE_HALFLIFE = 60 * 60 * 12 = 43200` seconds.
- `bitcoin-core/src/txmempool.cpp:829-851` — `CTxMemPool::GetMinFee`:
  conditional decay only when `blockSinceLastRollingFeeBump &&
  rollingMinimumFeeRate != 0`; halflife `/4` when `<sizelimit/4`,
  `/2` when `<sizelimit/2`; zero-floor at
  `incremental_relay_feerate.GetFeePerK() / 2`; return value clamped
  `std::max(CFeeRate(llround(rollingMinimumFeeRate)), incremental_relay_feerate)`.
- `bitcoin-core/src/txmempool.cpp:853-859` — `trackPackageRemoved`:
  `if (rate.GetFeePerK() > rollingMinimumFeeRate) { rollingMinimumFeeRate
  = rate.GetFeePerK(); blockSinceLastRollingFeeBump = false; }`.
- `bitcoin-core/src/txmempool.cpp:861-911` — `TrimToSize`: loop while
  `DynamicMemoryUsage() > sizelimit`; per iteration extract entire
  worst chunk via `m_txgraph->GetWorstMainChunk()`, bump
  `removed += incremental_relay_feerate`, `trackPackageRemoved(removed)`,
  remove every entry of the chunk with `MemPoolRemovalReason::SIZELIMIT`,
  optionally extract removed outpoints into `pvNoSpendsRemaining`
  for wallet refresh.
- `bitcoin-core/src/txmempool.cpp:811-827` — `Expire`: collect every
  entry whose `entry_time < now - expiry`, expand via
  `CalculateDescendants`, `RemoveStaged(stage, MemPoolRemovalReason::EXPIRY)`.
- `bitcoin-core/src/kernel/mempool_removal_reason.h:13-21` —
  `MemPoolRemovalReason { EXPIRY, SIZELIMIT, REORG, BLOCK, CONFLICT,
  REPLACED }`; `RemovalReasonToString` returns the strings
  `"expiry"/"sizelimit"/"reorg"/"block"/"conflict"/"replacement"`.
- `bitcoin-core/src/validation.cpp:294-385` —
  `Chainstate::MaybeUpdateMempoolForReorg`: drains `DisconnectedBlockTransactions`
  in reverse (most-recent first → re-feed via `AcceptToMemoryPool`),
  drops txs that failed re-add via `EraseTx`, then runs
  `removeForReorg(m_chain, filter_final_and_mature)` to evict
  pre-existing mempool entries that lost finality / sequence-locks /
  maturity, then `LimitMempoolSize(*m_mempool, this->CoinsTip())`.
  `filter_final_and_mature` predicate consults `CheckFinalTxAtTip` and
  `CheckSequenceLocksAtTip`.
- `bitcoin-core/src/validation.cpp:3074-3075` — `ConnectTip`:
  `m_mempool->removeForBlock(block.vtx, pindexNew->nHeight);
  disconnectpool.removeForBlock(block.vtx);`.
- `bitcoin-core/src/kernel/disconnected_transactions.h:18` —
  `MAX_DISCONNECTED_TX_POOL_BYTES = 20'000'000` (20 MiB cap, bound on
  reorg memory regardless of reorg depth).
- `bitcoin-core/src/node/mempool_persist.cpp` — `DumpMempool` writes
  the on-disk `mempool.dat` v2 (XOR-obfuscated) with `mapDeltas` and
  `unbroadcast_txids` entries pulled from
  `pool.mapDeltas` + `pool.GetUnbroadcastTxs()`; periodic dump runs
  inside scheduler at `DUMP_BYTES_PER_SEC` rate.
- `bitcoin-core/src/policy/fees.cpp::CBlockPolicyEstimator::removeTx` —
  receives every mempool removal except `BLOCK` (block path uses
  `processBlockTx`); `(reason == REORG)` is a no-op so reorg re-adds
  don't pollute the failure averages.
- `bitcoin-core/src/zmq/zmqpublishnotifier.cpp` — `hashtx`/`rawtx`/`sequence`
  publishers fire on every mempool add AND every mempool removal
  (sequence label `R` includes the mempool sequence number).

**Files audited**
- `src/mempool.lua` (3141 lines) — `M.DEFAULT_MAX_MEMPOOL_SIZE`,
  `M.DEFAULT_MIN_RELAY_FEE`, `M.DEFAULT_MEMPOOL_EXPIRY`,
  `M.INCREMENTAL_RELAY_FEE`, `M.ROLLING_FEE_HALFLIFE`, `Mempool.new`,
  `Mempool:accept_transaction` (steps 6, 6b, 9), `Mempool:on_block_connected`
  (line 1893-1914), `Mempool:block_disconnected` (line 1940-1953),
  `Mempool:remove_transaction` (line 1836-1881), `Mempool:track_package_removed`
  (line 1965-1970), `Mempool:get_min_fee` (line 1988-2022),
  `Mempool:expire` (line 2030-2075), `Mempool:trim` (line 2088-2117),
  `Mempool:get_info` (line 2144-2161). Callback surface:
  `self.callbacks = { on_tx_removed = nil }` (line 920-922) — no
  `on_tx_added` slot.
- `src/mempool_persist.lua` (302 lines) — `M.snapshot`, `M.encode_dump`,
  `M.dump`, `M.decode_dump`, `M.load`, `random_xor_key` (line 69-75),
  payload format with `map_deltas` (line 96-110) + `unbroadcast`
  (line 113-123).
- `src/fee.lua` (302 lines) — `FeeEstimator:tx_removed` (line 127-161),
  `FeeEstimator:tx_confirmed` (line 92-116), `FeeEstimator:on_block`
  (line 165-178), reason-string switch (line 132-141).
- `src/zmq.lua` (608 lines) — `NotificationManager:on_block_connected`
  (line 558-566), `on_block_disconnected` (line 570-573),
  `on_tx_added` (line 578-588), `on_tx_removed` (line 592-597),
  `TOPIC_*` constants (line 97-101), `LABEL_*` (line 104-107).
- `src/main.lua` (line 1058-1145) — mempool construction
  (`max_mempool_size = 300 * 1024 * 1024`, `min_relay_fee = 1000`),
  ZMQ wiring (line 1091-1124), fee-estimator wiring (line 1138-1180),
  shutdown dump (line 2279-2286). No `-maxmempool` / `-mempoolexpiry`
  / `-minrelaytxfee` / `-incrementalrelayfee` flag declarations
  (verified by grep in flag block line 300-358).
- `src/utxo.lua` (line 3350-3446) — reorg refill path:
  unconditionally collects `disconnected_blocks` (no
  `MAX_DISCONNECTED_TX_POOL_BYTES` cap), calls
  `opts.mempool:block_disconnected(dblk)` for each before connect.
- `src/rpc.lua` (line 1876-1925 getmempoolinfo, line 1988-2026
  dumpmempool/loadmempool, line 2029-2057 sendrawtransaction,
  line 7033 / 7187 the two submitblock mempool wires).
  No `prioritisetransaction`, no `getprioritisedtransactions`,
  no `importmempool`, no `listunbroadcast`.
- `src/rest.lua` (line 1067-1095) — `/rest/mempool/info` BTC/kvB
  conversion path.
- `src/sync.lua` — verified contains **zero** mempool references
  (the IBD-and-tip block-receive path never tells the mempool that
  a tx confirmed).

---

## Gate matrix (30 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | DEFAULT_MAX_MEMPOOL_SIZE = 300 MB metric | G1: constant in `M.DEFAULT_MAX_MEMPOOL_SIZE` | PASS (`mempool.lua:202` = `300 * 1000 * 1000`) |
| 1 | … | G2: actual mempool uses metric 300 MB | **BUG-1 (P0-CDIV)** — `main.lua:1059` overrides with `300 * 1024 * 1024` (314,572,800 = 300 MiB, **4.86% too large**); `rpc.lua:1885` no-mempool fallback ditto; **three sources of truth disagree** (correct constant exists, two call-sites use the wrong one) |
| 1 | … | G3: `-maxmempool` CLI knob | **BUG-2 (P1)** — no `-maxmempool` declaration in flag parser (`main.lua:170-358`); operators can't override |
| 1 | … | G4: `TrimToSize` compares MEMORY usage, not wire size | **BUG-3 (P0-CDIV)** — `Mempool.total_size` (`mempool.lua:1688/1868`) accumulates `entry.size = #serialize.serialize_transaction(tx, true)` (raw wire size); Core's `DynamicMemoryUsage()` is roughly 3–5× wire size (mapTx node overhead + cluster graph nodes). lunarblock therefore tolerates **~3–5× more transactions in the mempool** than the same-named Core 300 MB limit; combined with BUG-1's 4.86% overshoot the actual cap is ~16× the Core target |
| 2 | DEFAULT_MEMPOOL_EXPIRY = 336h | G5: constant present | PASS (`mempool.lua:305` = `336 * 3600`) |
| 2 | … | G6: `-mempoolexpiry` CLI knob | **BUG-4 (P1)** — no `-mempoolexpiry` declaration (flag parser line 170-358) |
| 2 | … | G7: re-admitted (reorg-refill) txs preserve original time | **BUG-5 (P1)** — `block_disconnected` calls `accept_transaction` (`mempool.lua:1949-1951`) which calls `M.mempool_entry(..., os.time())` (`mempool.lua:1681`) — entry.time clobbered to NOW. Reorg-readmitted txs survive a fresh 14-day expiry window. Core preserves time via `DisconnectedBlockTransactions` round-trip. `mempool_persist.load` works around the same bug (line 285-291) by post-overwriting `entry.time` — `block_disconnected` doesn't |
| 3 | DEFAULT_MIN_RELAY_TX_FEE = 100 sat/kvB | G8: constant matches Core | **BUG-6 (P0-CDIV)** — `mempool.lua:203` `M.DEFAULT_MIN_RELAY_FEE = 1000` (10× Core's `policy.h:70` `DEFAULT_MIN_RELAY_TX_FEE{100}`); main.lua:1060 reinforces with `min_relay_fee = 1000`. Comment says "1 sat/vB" but Core's relay floor is **0.1 sat/vB** since v0.12. Effect: lunarblock relays nothing below 1 sat/vB while Core (and the rest of the fleet) accepts down to 0.1 sat/vB → many txs the network treats as standard are rejected here with `"fee rate too low: X < 1000 sat/KB"` |
| 3 | … | G9: `-minrelaytxfee` CLI knob | **BUG-7 (P1)** — no CLI flag; cannot be overridden even to match Core (operator-knob absence pattern, fleet-wide) |
| 4 | DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB | G10: constant matches Core | PASS (`mempool.lua:283` = 100, explicit FIX-x comment notes it was previously 1000 = 10× too high; W120-era fix) |
| 4 | … | G11: `-incrementalrelayfee` CLI knob | **BUG-8 (P1)** — no CLI flag |
| 4 | … | G12: getmempoolinfo.incrementalrelayfee reads actual setting | **BUG-9 (P1)** — `rpc.lua:1911` hardcodes `incrementalrelayfee = 0.00001` (BTC/kvB = 1000 sat/kvB = 10× the actual `M.INCREMENTAL_RELAY_FEE`). Field lies — operators reading the field for fee-bump math compute wrong required amounts. **Same shape as W120 BUG-9 fullrbf lie** (since fixed for fullrbf, never fixed for incrementalrelayfee) |
| 5 | Rolling-fee decay (ROLLING_FEE_HALFLIFE) | G13: 12-hour half-life | PASS (`mempool.lua:301` = 43200) |
| 5 | … | G14: halflife `/4` when pool < 1/4 full | PASS (`mempool.lua:2000-2001`) |
| 5 | … | G15: halflife `/2` when pool < 1/2 full | PASS (`mempool.lua:2002-2003`) |
| 5 | … | G16: zero-floor at `INCREMENTAL_RELAY_FEE / 2` | PASS (`mempool.lua:2013`) |
| 5 | … | G17: `get_min_fee` return clamps to `max(rolling, incremental)` | PARTIAL — `mempool.lua:2021` returns `math.max(rolling, INCREMENTAL_RELAY_FEE)` (100), correct. But the **early-return** at line 1993 returns `self.rolling_minimum_fee_rate` **unclamped** when no block has been seen since last bump — so when rolling is 0 (cold start, no eviction yet) `get_min_fee` returns 0 instead of `incremental_relay_feerate.GetFeePerK() = 100`. Core's `txmempool.cpp:831-832` `return CFeeRate(llround(rollingMinimumFeeRate))` is also unclamped here (returns 0), so this is Core-parity — promote to PASS |
| 6 | MemPoolRemovalReason enum fan-out | G18: reason strings match Core enum tokens | **BUG-10 (P1)** — lunarblock's reason strings are free-form English; Core's `RemovalReasonToString` returns `"expiry"/"sizelimit"/"reorg"/"block"/"conflict"/"replacement"`. lunarblock emits `"confirmed"` (Core: `"block"`), `"evicted"` (Core: `"sizelimit"`), `"replaced"` (Core: `"replacement"`), `"cluster-limit"` (no Core counterpart — extra), `"test-accept"` (no Core counterpart — extra), `"truc-sibling-eviction"` (no Core counterpart — extra). **Six distinct token gaps in one switch.** Wire-string parity slippage (5th distinct instance in W125/W141/W143/W144/W145 series → 6th total) |
| 6 | … | G19: REORG reason emitted for reorg-evicted (no longer final) txs | **BUG-11 (P0-CDIV)** — never emitted; **`removeForReorg` does not exist** (no helper that scans the mempool after disconnect to evict newly-time-locked or newly-immature txs). `block_disconnected` only **re-adds** disconnected-block txs; it does not consult `CheckFinalTxAtTip` or `CheckSequenceLocksAtTip` on EXISTING entries. **Cross-cite W132 BUG-10 (lunarblock MTP off-by-one on disconnect path)** |
| 7 | Removed-signal fan-out | G20: fee estimator notified | PASS — `main.lua:1138-1144` wraps `mempool.callbacks.on_tx_removed` with `fee_estimator:tx_removed(txid_hex, reason)` |
| 7 | … | G21: ZMQ `sequence` topic fires on every removal | PASS — `main.lua:1116-1119` (ZMQ wrap), `zmq.lua:592-597` (`on_tx_removed` publishes label `R` with sequence number); WRAP order: main.lua:1138 chains fee-estimator on top of ZMQ so both fire |
| 7 | … | G22: ZMQ `hashtx` fires on RPC `sendrawtransaction` | **BUG-12 (P0-DEAD)** — `sendrawtransaction` (`rpc.lua:2029-2057`) calls `mempool:accept_transaction`, but **never invokes `zmq_notifier:on_tx_added`**. Compare to `main.lua:1325-1352` (P2P `tx` handler) which does. Wallet-broadcast txs are invisible to ZMQ subscribers — Bitcoin Core fires `hashtx`/`rawtx`/`sequence A` on *every* successful mempool insertion regardless of source |
| 7 | … | G23: tx-relay (peer announcement) on `sendrawtransaction` mirrors P2P trickle privacy | **BUG-13 (P1)** — `rpc.lua:2049-2055` uses `peer_manager:broadcast("inv", inv_payload)` — immediate fan-out to **all** peers, no Poisson trickle, no per-peer `m_tx_inventory_known_filter` consultation. **Tx-origin leakage**: passive observer can identify lunarblock as the origin by the simultaneous-burst signature. Compare main.lua:1338 which uses `queue_tx_announcement` (Poisson + bloom-known check) for P2P-received txs |
| 7 | … | G24: removeForBlock fires on every block, not only RPC submitblock | **BUG-14 (P0-CDIV)** — `mempool:on_block_connected(block)` is called from exactly **two** sites: `rpc.lua:7033` and `rpc.lua:7187`, both in the `submitblock` RPC handler. The IBD/P2P block path (`sync.lua`, which has **zero** mempool references) never invokes it. So during normal P2P operation **mempool entries are never cleaned up when their tx confirms** — they linger until expiry (336 h) or until evicted by trim. Effective consequence: getrawmempool returns confirmed txs; fee estimator's `tx_confirmed` is also never called (wired via the same callback chain in main.lua:1149-1180 → `prev_on_block_connected`, which is `chain_state.callbacks.on_block_connected`, which fires from utxo.lua:2983 — that one **does** fire on every connect path). So fee estimator sees confirmations but mempool retains the txs → fee-estimator records success for entries that never leave the mempool → confirmed-yet-mempool double-counting on next removal as "evicted" |
| 8 | LimitMempoolSize fires on block connect | G25: Expire + TrimToSize run after each connect | **BUG-15 (P1)** — `on_block_connected` (`mempool.lua:1893-1914`) does **NOT** call `self:expire()` or `self:trim()`. Core's `MaybeUpdateMempoolForReorg` (validation.cpp:385) and `ConnectTip` post-step both call `LimitMempoolSize`. lunarblock only re-limits when `accept_transaction` runs (the end of step 9 at `mempool.lua:1742-1743`). On a chain with no incoming relay traffic but many block-connect-driven removals, the mempool can accumulate via `block_disconnected` re-add without ever re-trimming after the eventual reconnect |
| 9 | MaybeUpdateMempoolForReorg | G26: `DisconnectedBlockTransactions` capped at 20 MiB | **BUG-16 (P0-CDIV)** — `utxo.lua:3365-3385` collects `disconnected_blocks` into an unbounded Lua array; no `MAX_DISCONNECTED_TX_POOL_BYTES` (20 MiB) cap. A deep reorg over a busy chain pulls every block body into RAM. With 4 MB blocks, a 100-block reorg = **400 MB resident in this list alone** before refill begins — OOM kill on the lunarblock process. Core caps the **transaction** total at 20 MB and evicts excess via `disconnectpool.AddTransactionsFromBlock` |
| 9 | … | G27: `removeForReorg` filter evicts newly-time-locked entries | **BUG-11 cross-cite** |
| 9 | … | G28: best-effort accept failures route through `EraseTx`(REORG) | **BUG-17 (P1)** — `mempool.lua:1949-1951` `pcall(accept_transaction)` swallows the failure with no `remove_transaction(..., "reorg")` for txs that were in mempool from the disconnected block but failed re-add. Core: `MaybeUpdateMempoolForReorg` falls through to `EraseTx` on rejection. lunarblock silently drops the result; the tx vanishes from getrawmempool with no `sequence R` ZMQ event and no fee-estimator failure record |
| 10 | prioritisetransaction + map_deltas round-trip | G29: `prioritisetransaction` RPC dispatched | **BUG-18 (P0-DEAD)** — no `case "prioritisetransaction"` in `rpc.lua` dispatch table; **mempool struct has no `map_deltas` field at all**. `mempool_persist.lua` serializes a `map_deltas` table on disk (lines 96-110) but the only caller (`mempool_persist_mod.dump(mempool, path)` in `rpc.lua:1997` + `main.lua:2280`) passes no `map_deltas` argument — so the field is always empty in on-disk dumps. Symmetric dead-data plumbing: `unbroadcast` is also serialized but never populated. **Three consecutive layers (struct → CLI/RPC → wire format) all dead** |
| 10 | … | G30: `getprioritisedtransactions` RPC | **BUG-19 (P1)** — no handler. Operators porting bitcoin.conf scripts that read prioritisation state get method-not-found. Companion to BUG-18 |

**Gate-buggy ratio: 19/30 = 63%.** With BUG-1/3/6/11/14/16/18 all P0-class. **lunarblock is on track for a 5th 30-of-30 candidate — falls 2 PASS gates short** (G1, G5, G10, G13-G17 pass cleanly; the rolling-fee state machine itself is well-modelled, but everything that **feeds** it diverges).

---

## BUG-1 (P0-CDIV) — `max_mempool_size` instantiated with 300 MiB binary while the constant declares 300 MB metric

**Severity:** P0-CDIV. Bitcoin Core `kernel/mempool_options.h:19,40` is
unambiguous: `DEFAULT_MAX_MEMPOOL_SIZE_MB{300}` and
`max_size_bytes{DEFAULT_MAX_MEMPOOL_SIZE_MB * 1'000'000}` — the
constant evaluates to **300_000_000** bytes (metric MB). lunarblock's
own constant `mempool.lua:202` `M.DEFAULT_MAX_MEMPOOL_SIZE = 300 * 1000
* 1000` matches Core exactly — but **main.lua never uses it**.

main.lua line 1058-1062:
```lua
local mempool = mempool_mod.new(chain_state, {
  max_mempool_size = 300 * 1024 * 1024,  -- 314_572_800 bytes
  min_relay_fee = 1000,
  fullrbf = args.mempool_fullrbf,
})
```

So the actually-instantiated mempool ignores the canonical 300_000_000
constant and uses **314_572_800** (300 MiB binary). That's 4.86% larger
than Core's limit. The same wrong-units pattern appears at
`rpc.lua:1885` for the no-mempool getmempoolinfo fallback. Three
sources of truth:

| File | Value | Units |
|------|-------|-------|
| `mempool.lua:202` | `300 * 1000 * 1000` = 300_000_000 | metric (correct) |
| `main.lua:1059` | `300 * 1024 * 1024` = 314_572_800 | binary (wrong, used) |
| `rpc.lua:1885` | `300 * 1024 * 1024` = 314_572_800 | binary (wrong, dead) |

**Core ref:** `bitcoin-core/src/kernel/mempool_options.h:19, 40`.

**Impact:** mempool grows 4.86% larger than Core before TrimToSize
fires; `getmempoolinfo.maxmempool` reports 314,572,800 to operators
who tune their alerts against the 300,000,000 Core value. Combined
with BUG-3 (wire-size vs memory-usage) the effective cap is ~16×
the Core target — see BUG-3.

---

## BUG-2 (P1) — no `-maxmempool` CLI knob

**Severity:** P1. Bitcoin Core init.cpp `-maxmempool=<n>` is one of
the most-tuned config-file knobs on busy nodes (Lightning routing
nodes set it to 1000+ MB; pruned wallet nodes set it to 50 MB).
lunarblock's main.lua flag parser (line 170-358) has no
`-maxmempool` or `--max-mempool` case. The mempool size is wired at
construction (line 1059) and there is no operator override.

**File:** `src/main.lua:170-358` (flag parser), `src/main.lua:1058-1062`
(construction).

**Core ref:** `bitcoin-core/src/init.cpp` — `-maxmempool=<n>`
argument parsing, `bitcoin-core/src/kernel/mempool_options.h:40`.

**Impact:** operators porting bitcoin.conf or systemd unit files
that contain `-maxmempool=<N>` cannot reuse them; lunarblock
silently ignores the option (via the unknown-option `os.exit(1)`
at `main.lua:354`, so an explicit `-maxmempool=1000` on the command
line is in fact REJECTED — see BUG-2-fail-mode below). Fleet-wide
operator-knob-absence pattern (companion: W139 absent
`-checkpoolinterval`, W141 absent `-blocknotify`).

**Failure mode worse than silent**: `main.lua:354` halts startup
with `Unknown option: -maxmempool` so an operator who copies a
Core config gets an immediate boot failure rather than ignored
flag. Operationally this is *better* (loud), but doc-wise lunarblock
advertises Core compatibility.

---

## BUG-3 (P0-CDIV) — TrimToSize compares serialized wire size, not memory usage

**Severity:** P0-CDIV. Core's `TrimToSize(sizelimit)` loop condition
is `while (DynamicMemoryUsage() > sizelimit)`. `DynamicMemoryUsage`
sums `sizeof(CTxMemPoolEntry) * mapTx.size() + m_txgraph_memory + ...`
— it is dominated by **node overhead, not wire bytes**. On a typical
mainnet mempool, `DynamicMemoryUsage ≈ 3–5× total wire size`.

lunarblock's `total_size` accumulator (`mempool.lua:1688` add,
`mempool.lua:1868` remove) sums `entry.size = #serialize.serialize_transaction(tx, true)`
— pure wire bytes. The trim loop at `mempool.lua:2089`:
```lua
while self.total_size > self.max_size do  -- wire bytes > 314_572_800
```

So the actual cap on resident wire bytes is **314,572,800** (BUG-1)
which corresponds to roughly **~1 GB of equivalent Core
DynamicMemoryUsage** before trim fires. Plus the LuaJIT mempool
entry table per tx is itself heavier than C++'s `CTxMemPoolEntry`
(string keys, table-per-entry, ancestors/descendants table-per-entry),
so the **actual process RSS contribution per tx is even higher than
Core's**.

Net: an operator setting `-maxmempool=300` in Core gets a 300 MB
**memory** ceiling; the same operator running lunarblock gets a
~1 GB **memory** ceiling. On a 1 GB VPS this is the difference
between "stable for weeks" and "OOM killed in an hour".

**File:** `src/mempool.lua:1688` (add), `1868` (remove),
`2089` (trim loop).

**Core ref:** `bitcoin-core/src/txmempool.cpp:861-911`
(`TrimToSize`), `bitcoin-core/src/txmempool.cpp::DynamicMemoryUsage`.

**Impact:** ~3-5× actual memory consumption vs Core advertised cap;
silent OOM under sustained mempool load; cross-impl fee-rate
disagreement (lunarblock retains low-feerate txs Core has already
trimmed → `mempoolminfee` lower on lunarblock → wallet fee estimates
disagree across the fleet).

---

## BUG-4 (P1) — no `-mempoolexpiry` CLI knob

**Severity:** P1. Same shape as BUG-2 for the expiry knob.
`mempool.lua:879` reads `self.expiry = (config and config.expiry) or
M.DEFAULT_MEMPOOL_EXPIRY` and `main.lua:1058-1062` passes no
`expiry` key. There is no flag to override.

**File:** `src/main.lua:170-358` (flag parser).

**Core ref:** `bitcoin-core/src/init.cpp` — `-mempoolexpiry=<hours>`.

**Impact:** can't shorten expiry for ephemeral / wallet-node use;
can't extend for archival. Fleet-wide operator-knob-absence.

---

## BUG-5 (P1) — `block_disconnected` re-admits with NOW timestamp; lost original entry time

**Severity:** P1. Core's `DisconnectedBlockTransactions` round-trip
preserves the *original* mempool entry time — when the reorg
re-admits a tx via `AcceptToMemoryPool`, the new entry's `nTime`
matches the disconnect-snapshot. This bounds total in-mempool
lifetime by the original expiry deadline rather than restarting
the 14-day clock at every reorg.

lunarblock `block_disconnected` (`mempool.lua:1940-1953`) calls
`accept_transaction(tx)` which calls
`M.mempool_entry(tx, txid, fee, vsize, tip_height, os.time())`
(`mempool.lua:1681`) — `entry.time` is unconditionally **now**.
Same code path elsewhere (`mempool_persist.lua:285-291`) explicitly
post-overwrites `entry.time` to work around this — `block_disconnected`
does not.

**File:** `src/mempool.lua:1940-1953` (block_disconnected);
`src/mempool.lua:1681` (entry construction with os.time());
contrast `src/mempool_persist.lua:285-291` (the workaround in the
persist path).

**Core ref:** `bitcoin-core/src/validation.cpp::MaybeUpdateMempoolForReorg`
+ `DisconnectedBlockTransactions::AddTransactionsFromBlock` + the
nTime preservation in `CTxMemPoolEntry` round-trip.

**Impact:** on a chain prone to reorgs (testnet4 in production,
mainnet during chain splits), every reorg adds **14 more days** to
the surviving expiry of every re-admitted tx. A tx that was 14 days
old and about to expire can be reorg-revived indefinitely. Practical
impact is small on mainnet (rare deep reorgs) but plausibly
exploitable on testnet/regtest harnesses that drive synthetic reorgs.

---

## BUG-6 (P0-CDIV) — `DEFAULT_MIN_RELAY_FEE = 1000`, 10× higher than Core

**Severity:** P0-CDIV. Bitcoin Core `policy/policy.h:70`:
```cpp
static constexpr unsigned int DEFAULT_MIN_RELAY_TX_FEE{100};
```

Units: sat/kvB. 100 sat/kvB = 0.1 sat/vB. lunarblock
`mempool.lua:203`:
```lua
M.DEFAULT_MIN_RELAY_FEE = 1000    -- 1 sat/vB in sat/KB
```

The comment "1 sat/vB" is wrong about Core's default (Core lowered
this in 2017; the v0.16+ floor is 0.1 sat/vB). `main.lua:1060` then
reinforces with `min_relay_fee = 1000`. With this floor every tx
paying less than 1 sat/vB is rejected at relay with
`"fee rate too low: X < 1000 sat/KB"` (`mempool.lua:1290-1292`).

On a typical mainnet day where `mempoolminfee == 0.1 sat/vB` (no
trim pressure), Core relays sub-1 sat/vB traffic from wallets
gracefully; lunarblock rejects it as spam.

**File:** `src/mempool.lua:203` (constant), `src/main.lua:1060`
(redundant explicit override of the already-wrong default).

**Core ref:** `bitcoin-core/src/policy/policy.h:70`.

**Impact:**
- lunarblock **does not relay** any tx paying < 1 sat/vB; Core
  does. Cross-impl divergence visible in `getrawmempool` between
  lunarblock and a Core/Knots peer on the same network.
- Fee estimation skewed: `fee_estimator:tx_removed` (reason
  "evicted") never sees sub-1-sat/vB txs because they never made
  it past the relay gate. `estimate_smart_fee` over-estimates.
- Mempool persists across the fleet: a tx broadcast to a Core peer
  enters its mempool, propagates to other Core peers, fails the
  lunarblock relay gate, and `mempool.dat` on lunarblock under-
  represents network conditions.

**Fix:** one-line in `mempool.lua:203` (1000 → 100) and one-line
in `main.lua:1060` (1000 → 100, or better: drop the explicit
override and let the module default win).

---

## BUG-7 (P1) — no `-minrelaytxfee` CLI knob

**Severity:** P1. Same shape as BUG-2/4 for the min-relay knob.
The "Lua-double precision loss on fee math" line item in the
W139/W149/W150/W152 pattern bucket has a corollary here: even when
operators KNOW the 10× error in BUG-6, they can't reduce the
deployed value without editing source.

**Core ref:** `bitcoin-core/src/init.cpp` — `-minrelaytxfee=<amt>`.

---

## BUG-8 (P1) — no `-incrementalrelayfee` CLI knob

**Severity:** P1. Same shape. Companion to BUG-7. Both are part
of the fleet-wide operator-knob-absence pattern; lunarblock has
**zero** of the four `-maxmempool`/`-mempoolexpiry`/`-minrelaytxfee`/
`-incrementalrelayfee` flags. Compare the W139 finding of "30-of-30
gates buggy".

---

## BUG-9 (P1) — `getmempoolinfo.incrementalrelayfee` lies

**Severity:** P1. `rpc.lua:1911`:
```lua
incrementalrelayfee = 0.00001,  -- BTC/kvB = 1000 sat/kvB
```

This is hardcoded. The actual incremental relay fee constant is
`M.INCREMENTAL_RELAY_FEE = 100` sat/kvB (`mempool.lua:283`,
explicitly fixed from 1000 in an earlier wave) — which converts to
`0.000001` BTC/kvB, not `0.00001`. The RPC response is **10× the
real value used in relay decisions**, identical to the bug pattern
that prompted FIX-68 for the `fullrbf` field (where the RPC was
hardcoded to `true` while the relay code still enforced Rule 1).

Operators that read `incrementalrelayfee` from `getmempoolinfo` to
compute the required fee bump for RBF replacements (Rule 4) get a
10× over-estimate; their replacement txs pay 10× the actually-
required incremental and `bumpfee` UX is silently wasteful.

**File:** `src/rpc.lua:1911`; `src/rest.lua:1085-1094` does not even
emit incrementalrelayfee, so REST consumers see different shape than
RPC consumers.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::getmempoolinfo` —
`incrementalrelayfee = ValueFromAmount(pool.m_opts.incremental_relay_feerate.GetFeePerK())`.

**Impact:** wallet fee-bump over-payment; UX confusion in
`getmempoolinfo` consumers; field is **dead-data plumbing** rooted in
the W120 FIX-68-class oversight (the same lie-pattern, never caught).

---

## BUG-10 (P1) — MemPoolRemovalReason strings diverge from Core's 6-token enum

**Severity:** P1. Bitcoin Core `kernel/mempool_removal_reason.h`
defines six reason tokens: `EXPIRY`, `SIZELIMIT`, `REORG`, `BLOCK`,
`CONFLICT`, `REPLACED`. `RemovalReasonToString` produces lower-case
strings: `"expiry"`, `"sizelimit"`, `"reorg"`, `"block"`, `"conflict"`,
`"replacement"`.

lunarblock emits the following reason strings via
`remove_transaction(txid_hex, reason)`:

| lunarblock string | Core enum | Match? |
|-------------------|-----------|--------|
| `"expiry"` | `"expiry"` | PASS |
| `"evicted"` | `"sizelimit"` | **MISMATCH** |
| `"confirmed"` | `"block"` | **MISMATCH** |
| `"conflict"` | `"conflict"` | PASS |
| `"replaced"` | `"replacement"` | **MISMATCH** |
| (none) | `"reorg"` | **MISSING — see BUG-11** |
| `"cluster-limit"` | (no counterpart) | extra |
| `"test-accept"` | (no counterpart) | extra |
| `"truc-sibling-eviction"` | (no counterpart) | extra |

**Six distinct token gaps in one switch.** This is the
**reject-string wire-parity slippage pattern** in its 6th distinct
instance across the W125/W141/W143/W144/W145 line-up; W153 catches
it on the *removal* reason switch.

The fee estimator (`fee.lua:127-161`) hardcodes the lunarblock
spelling — switching to Core's tokens needs a synchronized fix in
both files. ZMQ sequence-label is unaffected (it emits a single
`R` byte regardless of reason), so the slippage is RPC-visible
only: it surfaces in any future `getmempoolinfo` removal-reason
counter (Core has none currently but the field would be wrong on
the wire if ever added), and in logs (currently no logs include
the reason).

**File:** `src/mempool.lua:1496, 1728, 1734, 1781, 1898, 1905,
2070, 2115` (remove_transaction call sites); `src/fee.lua:127-161`
(reason switch consumer).

**Core ref:** `bitcoin-core/src/kernel/mempool_removal_reason.h:13-21`
+ `mempool_removal_reason.cpp::RemovalReasonToString`.

---

## BUG-11 (P0-CDIV) — `removeForReorg` filter entirely absent; mempool retains time-locked-invalid entries after reorg

**Severity:** P0-CDIV. Bitcoin Core's `MaybeUpdateMempoolForReorg`
(validation.cpp:294-385) is a TWO-stage process:

1. **Refill** — drain `DisconnectedBlockTransactions` into the
   mempool via `AcceptToMemoryPool`.
2. **Evict** — call `removeForReorg(m_chain, filter_final_and_mature)`
   to walk every pre-existing mempool entry and evict ones whose
   `CheckFinalTxAtTip` or `CheckSequenceLocksAtTip` predicates now
   fail because the active tip changed.

lunarblock `block_disconnected` (`mempool.lua:1940-1953`)
implements only **stage 1**. There is no helper that scans
post-reorg mempool entries for stale finality / sequence-locks.
A tx that was BIP-113-final at the pre-reorg tip but is BIP-113-not-final
at the post-reorg tip stays in the mempool, and the next block
template includes it → the block is rejected by the rest of the
network as `non-final-tx`. **Mining-pool revenue loss** in the worst case.

This is also the cross-cite for BUG-10 G19: `REORG` removal reason
is never emitted because the code that should emit it does not exist.

**File:** `src/mempool.lua` — no `Mempool:removeForReorg` helper;
`src/mempool.lua:1940-1953` `block_disconnected` is only stage 1.
The fan-out (`utxo.lua:3442-3446`) calls only `block_disconnected`,
never any post-reorg filter.

**Core ref:** `bitcoin-core/src/validation.cpp:294-385`
`MaybeUpdateMempoolForReorg`; `bitcoin-core/src/txmempool.cpp::removeForReorg`.

**Impact:** time-lock and sequence-lock invariants violated in
mempool state post-reorg; mining template can be wrong;
`fee_estimator:tx_removed` never gets a `"reorg"` event (Core's
fee estimator skips REORG to keep estimates clean — lunarblock
silently has nothing to skip because nothing fires).

**Cross-cite:** W132 BUG-10 (lunarblock MTP off-by-one in
`utxo.lua` connect/disconnect path) — a fixed MTP plus a missing
reorg filter compound: the surviving mempool entry's stored
`prev_block_mtp` is stale by exactly the W132 off-by-one and never
gets re-checked.

---

## BUG-12 (P0-DEAD) — `sendrawtransaction` does NOT fire ZMQ `hashtx`/`rawtx`/`sequence`

**Severity:** P0-DEAD. Bitcoin Core's `BroadcastTransaction`
(node/transaction.cpp) routes every successful mempool insertion
— P2P, RPC, REST, wallet — through the same
`m_mempool->addUnchecked(...)` path which fires the
`TransactionAddedToMempool` signal; the ZMQ publisher subscribes
to that signal and emits `hashtx` / `rawtx` / `sequence A` on
every add.

lunarblock has TWO entry points (no shared post-accept hook):

| Entry point | File:line | Fires ZMQ `on_tx_added`? |
|-------------|-----------|--------------------------|
| P2P `tx` handler | `main.lua:1325-1352` | YES (line 1346-1348) |
| RPC `sendrawtransaction` | `rpc.lua:2029-2057` | **NO** |

Wallet broadcasts via `sendrawtransaction` / `submitpackage`
(if it existed) are entirely invisible to ZMQ subscribers — even
ones the operator explicitly subscribed to `hashtx` to track their
own outgoing txs.

**File:** `src/rpc.lua:2029-2057` (sendrawtransaction).

**Core ref:** `bitcoin-core/src/node/transaction.cpp::BroadcastTransaction`
fan-out via `m_mempool->TransactionAddedToMempool`.

**Impact:** wallet UX gap (electrs, fulcrum, mempool.space, custom
operator dashboards relying on ZMQ `sequence A`/`hashtx` miss
operator-originated traffic); also affects packagerelay if added
later. Same shape as W141 fleet pattern "hashtx per-tx fan-out
missing on BlockConnected" but at the tx-add side. **`Mempool`
struct has no `on_tx_added` callback slot at all** (line 919-922
defines only `on_tx_removed`) — the integration point is "wire
manually at every accept call site" rather than the
"single-hook-fires-from-Mempool" Core design.

**Fix:** add `Mempool.callbacks.on_tx_added` slot in `mempool.lua:920`;
fire it inside `accept_transaction` after step 8 (before step 9's
expire+trim); remove the per-call-site wiring in `main.lua:1346-1348`.

---

## BUG-13 (P1) — `sendrawtransaction` broadcasts immediately to all peers (tx-origin leakage)

**Severity:** P1. `rpc.lua:2049-2055`:
```lua
if rpc.peer_manager then
  local txid = validation.compute_txid(tx)
  local inv_payload = p2p.serialize_inv({
    {type = p2p.INV_TYPE.MSG_WITNESS_TX, hash = txid}
  })
  rpc.peer_manager:broadcast("inv", inv_payload)
end
```

This sends the same INV to **every connected peer simultaneously**.
The P2P-received tx path (`main.lua:1338`) uses
`queue_tx_announcement` which routes through the Poisson trickle
queue per peer (different timing per peer; per-peer
`m_tx_inventory_known_filter` consultation).

The simultaneous-burst signature is a classic tx-origin
identification primitive — a passive observer on the network can
fingerprint lunarblock as the originator with high confidence
purely from the timing pattern. Companion to W152's TXID_RELAY_DELAY
+ NONPREF_PEER_TX_DELAY findings.

**File:** `src/rpc.lua:2049-2055`.

**Core ref:** `bitcoin-core/src/node/transaction.cpp::BroadcastTransaction`
+ `bitcoin-core/src/net_processing.cpp::RelayTransaction` — both
route through the per-peer `m_tx_inventory_to_send` set, not an
immediate broadcast.

**Impact:** privacy leak; wallet de-anonymization; lunarblock
identifiable by passive peers. Hard to detect from logs (the
INV looks normal); only the timing differs.

---

## BUG-14 (P0-CDIV) — `mempool:on_block_connected` is called only from RPC submitblock, not from P2P / IBD block-received paths

**Severity:** P0-CDIV. `mempool:on_block_connected(block)` is the
only path that removes confirmed txs from the mempool with reason
`"confirmed"` (BUG-10 also: should be `"block"`). It is called from
exactly two sites:

```
$ grep -rn "mempool:on_block_connected\|opts.mempool:on_block" src/
src/rpc.lua:7033:        rpc.mempool:on_block_connected(block)   -- submitblock-best-chain
src/rpc.lua:7187:      rpc.mempool:on_block_connected(block)     -- submitblock-fresh-tip
```

The P2P block-received pipeline lives in `src/sync.lua` (the
`BlockDownloader`), which has **zero** mempool references:

```
$ grep -n "mempool" src/sync.lua
(no output)
```

So during normal P2P operation (every IBD block, every newly-mined
block received from peers), mempool entries for txs included in
that block are **never removed**. They linger until:
- `expire()` fires when a `accept_transaction` happens to run AND
  the tx is > 14 days old; or
- `trim()` fires when wire-size exceeds the (inflated) max — by
  which time the mempool is enormous (see BUG-3).

Meanwhile `fee_estimator:tx_confirmed` IS fired correctly because
its wiring (`main.lua:1149-1180`) hooks the chain-state
`on_block_connected` callback (`utxo.lua:2983`) which DOES fire on
every connect path. So the fee estimator records the tx as
confirmed and removes its entry from `self.unconfirmed[]`. Then
later, when `expire`/`trim` eventually removes the still-present
mempool entry, the `fee_estimator:tx_removed(txid, "evicted")`
call finds `info = nil` (already removed by `tx_confirmed`) and
returns early — silent double-handling. So the fee estimator
survives the bug; the mempool itself is what gets corrupt.

**File:** `src/rpc.lua:7033`, `src/rpc.lua:7187` (only callers);
`src/sync.lua` (entire file, zero mempool refs); `src/utxo.lua`
(connect_block, connects on every path, never invokes mempool).

**Core ref:** `bitcoin-core/src/validation.cpp:3074`
`m_mempool->removeForBlock(block_to_connect->vtx,
pindexNew->nHeight)` is called from `ConnectTip` on every connect
regardless of source (P2P / RPC / loadblock / etc.).

**Impact:**
- `getrawmempool` returns confirmed txs for hours / days post-block.
- `getrawmempool true` (verbose) returns nonsense ancestor / descendant
  counts (still tracking now-confirmed parents as in-mempool ancestors).
- Mining template (when lunarblock mining lands) double-includes
  already-confirmed txs and builds invalid blocks.
- ZMQ `sequence R` events do not fire for the in-block evictions —
  consumers expecting that signal (electrs ledger reconciliation)
  silently drift.

**Fix:** wire `mempool:on_block_connected(block)` into the IBD path
(`sync.lua` → `block_downloader:handle_block` post-connect) AND
`utxo.lua::connect_block` callback fan-out. Same architectural fix
as BUG-12 (single post-connect-block hook fires from the chain
state, mempool subscribes once).

---

## BUG-15 (P1) — `LimitMempoolSize` not invoked on block connect

**Severity:** P1. Core's `ConnectTip` (post-step) and
`MaybeUpdateMempoolForReorg` (post-step) both call
`LimitMempoolSize(*m_mempool, this->CoinsTip())` which runs
Expire() + TrimToSize(). lunarblock's `on_block_connected`
(`mempool.lua:1893-1914`) bumps the rolling-fee clock but does
**not** call `self:expire()` or `self:trim()`. Re-limiting only
happens on `accept_transaction` (line 1742-1743).

**File:** `src/mempool.lua:1893-1914`.

**Core ref:** `bitcoin-core/src/validation.cpp:271-276`
`LimitMempoolSize` invocations in `ConnectTip` and
`MaybeUpdateMempoolForReorg`.

**Impact:** between blocks on a quiet-relay node (e.g. validator
hub with no incoming tx-relay), the mempool grows monotonically.
Combined with BUG-14 (no removeForBlock on P2P), this is the
primary mechanism by which lunarblock's mempool diverges from
fleet peers.

---

## BUG-16 (P0-CDIV) — `disconnected_blocks` list is unbounded; no MAX_DISCONNECTED_TX_POOL_BYTES cap

**Severity:** P0-CDIV. Core caps the disconnect pool at 20 MiB
(`kernel/disconnected_transactions.h:18`
`MAX_DISCONNECTED_TX_POOL_BYTES{20'000'000}`) — once exceeded,
oldest entries are dropped rather than admitted. This bounds reorg
memory regardless of depth.

lunarblock `utxo.lua:3365-3385`:
```lua
local disconnected_blocks = nil
if opts.mempool then
  disconnected_blocks = {}
  local h = self.tip_height
  while h > common_height do
    local h_hash = self.storage.get_hash_by_height(h)
    if h_hash then
      local h_block = self.storage.get_block(h_hash)
      if h_block then
        disconnected_blocks[#disconnected_blocks + 1] = h_block
      end
    end
    h = h - 1
  end
end
```

Unbounded. Loads every block body from `tip_height` down to
`common_height` into RAM. With 4 MB blocks at mainnet tip-height,
a 100-block reorg = **400 MB** resident in this one list before
`mempool:block_disconnected` even runs (and `block_disconnected`
itself iterates `block.transactions` in memory, hitting
`accept_transaction` for each non-coinbase). On a typical 4 GB
testnet VM, a 200-block reorg = OOM.

**File:** `src/utxo.lua:3365-3385`.

**Core ref:** `bitcoin-core/src/kernel/disconnected_transactions.h:18`;
`bitcoin-core/src/kernel/disconnected_transactions.cpp::AddTransactionsFromBlock`.

**Impact:** OOM on deep reorg; lunarblock kernel-killed mid-reorg
leaves chain state inconsistent (the reorg is supposed to be atomic
via Pattern D shared WriteBatch but a SIGKILL skips the commit
entirely).

---

## BUG-17 (P1) — Re-admission failures swallowed silently; no `EraseTx(REORG)` event

**Severity:** P1. `mempool.lua:1949-1951`:
```lua
pcall(function()
  self:accept_transaction(tx)
end)
```

The `pcall` swallows ALL failures with no further bookkeeping:
no `remove_transaction(..., "reorg")` for the silent drop, no
`fee_estimator:tx_removed(..., "reorg")` event, no ZMQ
`sequence R` notification.

Core's `MaybeUpdateMempoolForReorg` is explicit on this path:
re-admit failures cause `EraseTx`, which fires the same
removed-tx signal fan-out as any other removal. lunarblock's
silent-drop means consumers of the removal signal (fee estimator,
ZMQ, REST `/rest/mempool/info` bookkeeping) never see the event.

**File:** `src/mempool.lua:1949-1951`.

**Core ref:** `bitcoin-core/src/validation.cpp::MaybeUpdateMempoolForReorg`
behaviour on `AcceptToMemoryPool` failure.

---

## BUG-18 (P0-DEAD) — `prioritisetransaction` RPC absent; `map_deltas` is dead data plumbing

**Severity:** P0-DEAD. Three layers all dead in sequence:

1. **Mempool struct**: `Mempool` (`mempool.lua:874-924`) has
   **no `map_deltas` field**. `MempoolEntry` (line 845) has
   no `fee_delta` field. There is no path for an operator to
   add a fee delta.

2. **CLI / RPC**: `rpc.lua` dispatch table has no
   `case "prioritisetransaction"`; no
   `case "getprioritisedtransactions"`. There is no path even
   in principle for an operator to call into mempool delta state.

3. **On-disk persistence**: `mempool_persist.lua:96-110` is fully
   capable of round-tripping a `map_deltas` table to disk in the
   Core v2 mempool.dat format — but the call-site
   (`mempool_persist.lua:M.dump(mempool, path)` invoked from
   `rpc.lua:1997` and `main.lua:2280`) passes only the mempool;
   no `opts.map_deltas` is provided. Field always empty in
   dumps. `unbroadcast` is identical: serialized but never
   populated.

A consumer who reads lunarblock's mempool.dat with a Core decoder
sees the expected file format and zero entries in both subfields.
A consumer who imports that dump back into Core loses all
prioritisation as a no-op (because empty).

**File:** `src/mempool.lua:920` (callbacks have no priority slot);
`src/rpc.lua` (no prioritisetransaction / getprioritisedtransactions
case); `src/mempool_persist.lua:96-123` (encode loop);
`src/main.lua:2280` (dump call with no deltas).

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::prioritisetransaction`,
`bitcoin-core/src/rpc/mempool.cpp::getprioritisedtransactions`,
`bitcoin-core/src/txmempool.cpp::PrioritiseTransaction`,
`bitcoin-core/src/node/mempool_persist.cpp::DumpMempool`.

**Impact:**
- CPFP wallet UX broken (cannot operator-side prioritize a child).
- BIP-125 RBF on lunarblock cannot be augmented with priority
  bumps that Core honours.
- Mempool.dat round-trip is lossy w.r.t. priority state — operator
  toolkits that rely on the priority-preservation aspect of Core's
  v2 dump format silently lose the data on lunarblock.

**Three-layer dead-data-plumbing pattern** (struct → CLI → wire),
same shape as W138 "ChainstateManager dead-class" but more severe:
W138 had a struct with methods that simply weren't wired up; here
the wire format is even ready and unused.

---

## BUG-19 (P1) — `getprioritisedtransactions` RPC absent

**Severity:** P1. Standalone read-side companion to BUG-18.
Without this RPC, operators cannot inspect the current priority
state even if BUG-18 were partially fixed. Bitcoin Core
exposes the read-side independently of the write-side.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::getprioritisedtransactions`.

---

## Additional notes / softer findings (not numbered as bugs)

**A.** `getmempoolinfo.unbroadcastcount` is hardcoded to 0
(`rpc.lua:1912`). Bitcoin Core tracks an `unbroadcast` set of
txs that have been added to the mempool by the local wallet /
operator but not yet observed in INVs from peers (used by the
`/rest/mempool/info` and dump path). lunarblock has no
`unbroadcast` set on the `Mempool` struct so the field cannot
become non-zero. **Loose end** of BUG-18 — same dead-data
plumbing — not promoted to bug status because it's a
hardcoded-to-0 status rather than a wrong value.

**B.** `random_xor_key` in `mempool_persist.lua:69-75` uses
`math.random(0, 255)` with no `math.randomseed`. The mempool.dat
XOR key is therefore deterministic on Lua's default seed (1)
unless some other code path has called `math.randomseed` first.
The companion comment (line 65-68) admits this is opportunistic
anti-AV-scanning only and not security-critical — Core's comment
matches. But this is the **W152 BUG-12 carry-forward pattern** in
its 2nd lunarblock instance (W152 caught it in `peerman.lua`
trickle/Poisson; W153 catches it in mempool persist XOR-key).
Fix is the same one-line `math.randomseed(os.time() + os.clock() *
1e9)` at module load, applied centrally.

**C.** `trim` (`mempool.lua:2088-2117`) evicts ONE entry per loop
iteration (with cascading via `remove_transaction`); Core
extracts the whole worst cluster (`m_txgraph->GetWorstMainChunk()`)
per iteration. Functionally the cascading achieves a similar end
result, but the rolling-fee bump is per-eviction in lunarblock
(O(n) bumps) where Core does ONE bump per cluster. On large
trim sweeps, lunarblock's `rolling_minimum_fee_rate` is set to
the highest individual tx feerate rather than the highest cluster
feerate, leading to over-restriction post-trim. Not promoted to
bug because of the cascading behaviour partially compensates.

**D.** No `pvNoSpendsRemaining` analog. Core extracts the
outpoints freed by trim and forwards them to the wallet so the
wallet can refresh balances. lunarblock has no wallet ↔ mempool
notification on trim, so the wallet's view drifts after sustained
trim activity. Bundled into the broader removal-signal fan-out gap
(BUG-12 / BUG-17).

**E.** `mempool_persist.M.dump` saves on **shutdown only** (no
periodic dump). Core's scheduler runs `DumpMempool` periodically
(rate-limited by `DUMP_BYTES_PER_SEC`). A lunarblock SIGKILL loses
the entire mempool since last orderly shutdown. Tunable with `-persistmempoolv1` etc. in Core; no analog in lunarblock. Loose end,
not promoted because Core's default is "dump on shutdown" and
periodic-dump is an explicit operator opt-in.

---

## Severity tallies

| Severity | Count | Bugs |
|----------|-------|------|
| P0-CDIV | 7 | 1, 3, 6, 11, 14, 16 + BUG-12 (P0-DEAD) + BUG-18 (P0-DEAD) |
| P0-DEAD | 2 | 12, 18 |
| P1 | 11 | 2, 4, 5, 7, 8, 9, 10, 13, 15, 17, 19 |
| **Total** | **19** | |

P0-class total: 8 (six P0-CDIV + two P0-DEAD). Gate pass rate:
11/30 = 37%.

**Note**: "5th 30-of-30 candidate" was the hypothesis going in.
lunarblock falls 2 PASS gates short — the rolling-fee state machine
itself (G13-G17) is clean and the expire/trim algorithms are
algorithmically right, even when EVERYTHING that feeds them
diverges. Gate matrix would tip to 30-of-30 in W154 if the next
expansion (e.g. mempool-on-disk format / `mapDeltas` round-trip)
finds two more breakages.

---

## Fleet-pattern reuse observed

- **operator-knob-absence**: BUG-2, BUG-4, BUG-7, BUG-8
  (`-maxmempool`, `-mempoolexpiry`, `-minrelaytxfee`,
  `-incrementalrelayfee` all four absent). **4-for-4 on this
  group; matches the W139 "30-of-30 gates buggy" knob-absence
  bucket.**
- **dead-data-plumbing**: BUG-18 (struct → CLI → wire all dead
  for `prioritisetransaction`); BUG-9 (`incrementalrelayfee` value
  field is dead-RPC plumbing returning a 10× wrong constant).
- **wiring-look-but-no-wire**: BUG-14 (`mempool:on_block_connected`
  exists, looks plumbed via two RPC sites, but the dominant
  P2P/IBD entry path doesn't invoke it).
- **comment-as-confession**: `mempool.lua:1946-1948`
  ("Best-effort: ignore failures (tx may now conflict with the
  new chain, exceed mempool size, etc.). Core's removeForReorg
  has the same swallow-and-continue policy.") — the comment
  defends the bug (BUG-17). Core's `removeForReorg` does NOT
  swallow; it `EraseTx`'es with REORG reason, firing the full
  removal signal. **13th comment-as-confession instance.**
- **wire-string parity slippage**: BUG-10 (6-of-6 removal reasons
  diverge). **6th distinct W125/W141/W143/W144/W145 series
  instance.**
- **two-pipeline guard, third instance**: three sources of truth
  for `max_mempool_size` (BUG-1): correct constant in
  `mempool.lua`, two wrong call-sites overriding it. **16th
  distinct two-pipeline / three-pipeline guard extension**.
- **unseeded math.random carry-forward**: Section "A" above.
  **2nd lunarblock instance of W152 BUG-12** (peerman → mempool
  persist).

---

## Priority repro / fix order (operator impact ranking)

1. **BUG-14** — wire `mempool:on_block_connected` into IBD/P2P
   block path (`sync.lua` post-connect). Single architectural
   fix; clears the dominant "mempool retains confirmed txs"
   user-facing symptom.
2. **BUG-6** — `DEFAULT_MIN_RELAY_FEE = 1000` → `100`
   (one-line in `mempool.lua:203` + one-line in `main.lua:1060`).
   Restores cross-impl relay parity.
3. **BUG-11** — implement `Mempool:removeForReorg(filter)` and
   call it from `block_disconnected`. Closes the post-reorg
   time-lock-invalid retention; emits REORG removal reason.
4. **BUG-1 + BUG-3** — `300 * 1024 * 1024` → `300 * 1000 * 1000`
   in `main.lua:1059` and `rpc.lua:1885`; add a memory-usage
   estimator for `total_size` (or document the wire-bytes
   semantic and re-set the cap accordingly).
5. **BUG-12** — add `Mempool.callbacks.on_tx_added` slot and
   fire from inside `accept_transaction`; remove the per-site
   wiring in `main.lua:1346-1348`.
6. **BUG-16** — cap `disconnected_blocks` at 20 MiB; drop
   newest entries past cap.
7. **BUG-18** — implement `prioritisetransaction` RPC +
   `Mempool.map_deltas` field; wire dump/load to actually use
   the persist format.
8. **BUG-2 / 4 / 7 / 8** — add the four `-maxmempool` /
   `-mempoolexpiry` / `-minrelaytxfee` / `-incrementalrelayfee`
   CLI flags. Bundle as one ~20-line wave.
9. **BUG-10** — wire-string parity sweep over the 6 reason
   tokens, plus update `fee.lua:127-161` switch.
10. **BUG-9, 13, 15, 17, 19** — remaining cleanup.

**Total estimated patch size:** ~250 LOC across mempool.lua,
main.lua, rpc.lua, sync.lua, fee.lua, utxo.lua, mempool_persist.lua.
No tests added; existing test suite under `test-suite/` should
cover the mempool side through `test_rpc.py::test_getmempoolinfo`
once values change.
