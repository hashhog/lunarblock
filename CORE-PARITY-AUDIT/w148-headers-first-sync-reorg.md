# W148 — Headers-first sync + chain selection + reorg audit (lunarblock)

**Wave:** W148 — `ProcessNewBlockHeaders`, `AcceptBlockHeader`,
`ActivateBestChain`, `ActivateBestChainStep`, `FindMostWorkChain`,
`ConnectTip`, `DisconnectTip`, `InvalidateBlock`, `MAX_REORG_DEPTH` /
`MIN_BLOCKS_TO_KEEP`, `CBlockIndex` `BLOCK_VALID_*` validity bitfield,
`m_chain_tx_count`, `nSequenceId`, `nTimeMax`, `m_best_header`,
`setBlockIndexCandidates`.

**Date:** 2026-05-18
**Impl:** lunarblock (Lua / LuaJIT)
**Status:** **24 BUGS FOUND** (2 P0-CONS / 6 P0-CDIV / 1 P0-SEC /
4 P0-DEAD / 5 P1 / 4 P2 / 2 P3) across 30 sub-gates / 8 behaviours
**Scope:** discovery only — zero production code changes.

## Why this matters

Headers-first sync + chain selection + reorg is the **outer control
loop** of every Bitcoin full node. Bugs at this layer drive:

1. **Silent chain split** — node accepts/rejects blocks Core would not.
2. **Wedge / livelock** — node refuses to switch to a heavier side branch
   it already has on disk (W101 G1-G5 pattern).
3. **DoS** — peer pushes a long invalid header chain; node stores all
   headers without bounding chain-work or commitment verification.
4. **Persistent corruption** — partial reorg leaves the on-disk UTXO
   inconsistent with the tip pointer; restart pulls a non-valid tip and
   silently advances.

Three failure modes recur in lunarblock and all three are fleet
patterns documented in MEMORY.md:

1. **No `ActivateBestChain` outer loop / no `setBlockIndexCandidates`.**
   Tip advance is driven by **two ad-hoc pipelines** —
   `BlockDownloader:connect_pending_blocks` (sync.lua:2151) and
   `accept_side_branch_block` (utxo.lua:3196). Neither maintains a
   sorted candidate set; the former extends the active tip one-block-
   at-a-time, the latter is RPC-only (`submitblock`). There is no
   single function that, after any state change, asks "what is the
   most-work valid candidate header right now and is it different
   from my tip?" — Core's `FindMostWorkChain` semantics.

2. **No `BLOCK_VALID_*` validity ladder.** lunarblock has **zero
   references** to `BLOCK_VALID_TREE / BLOCK_VALID_TRANSACTIONS /
   BLOCK_VALID_CHAIN / BLOCK_VALID_SCRIPTS / BLOCK_FAILED_VALID /
   BLOCK_FAILED_CHILD / BLOCK_HAVE_DATA / BLOCK_HAVE_UNDO` as enum
   values (only in comments). The header index in `sync.lua` stores
   `{header, height, total_work}` per hash — no `nStatus`, no
   `nSequenceId`, no `m_chain_tx_count`, no `nTimeMax`, no `pskip`.
   The only invalidity tracking is an in-memory boolean set
   `chain_state.invalid_blocks` (utxo.lua:2086) keyed by hash bytes;
   `BLOCK_FAILED_CHILD`-style descendant propagation runs only inside
   `mark_descendant_invalid` and is **O(n × depth) iteration over the
   full HEADERS column family**. No `IsValid(nUpTo) / RaiseValidity`
   semantics — and no way to query "was this block at least
   `VALID_TRANSACTIONS`?" before considering it for tip extension.

3. **LuaJIT `assert()` as validation gate (W142 BUG-24 reprise).**
   `connect_block` (utxo.lua:2134) raises `assert()` for ~25 distinct
   consensus rules; `check_block` (validation.lua:1305-1363) raises
   `assert()` for at least 12 more (no-tx, coinbase position,
   weight-cap, sigops-cap, merkle, witness malleation, signature
   validity). Production callers wrap these in `pcall`, but the
   reorg-connect loop at `utxo.lua:3490` calls `self:connect_block(...)`
   **without** pcall and **without** `check_block` (W143 BUG-3) —
   any assertion fires unwinding through `accept_side_branch_block`,
   which then leaks a half-applied `reorg_batch`. The
   `coin_view:discard_dirty()` cleanup is only on the IBD path in
   main.lua:1030, not on the reorg path.

## Source map

- `lunarblock/src/sync.lua:138-435` — `HeadersSyncState` (PRESYNC /
  REDOWNLOAD / FINAL) anti-DoS pipeline; `compute_commitment`,
  `process_presync`, `process_redownload`, `transition_to_redownload`.
- `lunarblock/src/sync.lua:563-601` — `HeadersSyncState:process_headers`
  dispatches presync vs redownload.
- `lunarblock/src/sync.lua:627-877` — `HeaderChain` constructor /
  `init` / `add_genesis` (header index = flat Lua table keyed by hash
  hex; `headers[hash_hex] = {header, height, total_work}`).
- `lunarblock/src/sync.lua:888-910` — `work_for_bits` (**Lua double**
  approximation; NOT 256-bit integer math — see BUG-7).
- `lunarblock/src/sync.lua:920-937` — `HeaderChain:process_headers`
  (header batch accept).
- `lunarblock/src/sync.lua:950-1134` — `HeaderChain:accept_header`
  (single-header validation: PoW + MTP + time-too-old / -new + BIP-94
  timewarp + difficulty target + checkpoint + min-pow-checked +
  total-work update).
- `lunarblock/src/sync.lua:1166-1195` — `get_block_locator`
  (exponential locator; matches Core).
- `lunarblock/src/sync.lua:1259-1291` — `is_low_work_chain` /
  `get_chain_work` (the chain-work-bytes conversion uses floating-point
  approximation — same BUG-7 hazard).
- `lunarblock/src/sync.lua:1295-1310` — `start_sync` (issue
  `getheaders`).
- `lunarblock/src/sync.lua:1318-1551` — `try_low_work_sync` /
  `handle_headers` (per-peer PRESYNC state machine + unconnecting-
  headers tracking, MAX_NUM_UNCONNECTING_HEADERS_MSGS=10).
- `lunarblock/src/sync.lua:1603-1979` — `BlockDownloader` (single
  active-tip extender; `download_window=1024`, `blocks_per_peer=16`,
  `base_stall_timeout=60s`, `connect_stall_timeout=90s`,
  `MAX_BLOCKS_PER_CONNECT=8`, `utxo_flush_interval=200`).
- `lunarblock/src/sync.lua:2011-2140` — `BlockDownloader:handle_block`
  (one P2P block arrival → pending buffer).
- `lunarblock/src/sync.lua:2151-2562` — `BlockDownloader:connect_pending_blocks`
  (the de-facto `ActivateBestChainStep` — tip-extend-only, no fork
  decision, no candidate re-evaluation).
- `lunarblock/src/utxo.lua:2086-2111` — `is_block_invalid` /
  `has_invalid_ancestor` (parent-chain walk via storage.get_header).
- `lunarblock/src/utxo.lua:2134-3022` — `ChainState:connect_block`
  (assertions as validation; `coin_view:flush` with optional
  `reorg_batch`).
- `lunarblock/src/utxo.lua:3025-3163` — `ChainState:accept_block`
  (unified entry-point helper; fTooFarAhead gate at line 3098).
- `lunarblock/src/utxo.lua:3196-3513` — `accept_side_branch_block`
  (the only path that triggers a reorg; `MAX_REORG_DEPTH=100` hardcoded
  at line 3224).
- `lunarblock/src/utxo.lua:3530-3833` — `disconnect_block` /
  `rollback_chain_to`.
- `lunarblock/src/utxo.lua:3911-4111` — `mark_descendant_invalid` /
  `invalidate_block` / `reconsider_block` /
  `clear_descendant_invalid_flags`.
- `lunarblock/src/main.lua:960-1041` — `block_downloader.connect_callback`
  wiring (the only place ChainState:accept_block is called from the
  IBD path).
- `lunarblock/src/prune.lua:34` — `MIN_BLOCKS_TO_KEEP=288`.

## Bitcoin Core references

- `bitcoin-core/src/validation.cpp:4242-4270` — `ProcessNewBlockHeaders`
  (header batch loop + NotifyHeaderTip + CheckBlockIndex).
- `bitcoin-core/src/validation.cpp:4183-4239` — `AcceptBlockHeader`
  (PoW + ctx + `bad-prevblk` invalid-ancestor check at line 4220-4223 +
  AddToBlockIndex + `m_best_header` update).
- `bitcoin-core/src/validation.cpp:3323-3488` — `ActivateBestChain`
  (outer do-while loop releasing `cs_main` between iterations,
  breaks when `pindexMostWork == m_chain.Tip()`).
- `bitcoin-core/src/validation.cpp:3191-3280` — `ActivateBestChainStep`
  (Disconnect-loop-to-fork → DisconnectedBlockTransactions →
  `vpindexToConnect` descending walk in chunks of 32 → ConnectTip loop
  → MaybeUpdateMempoolForReorg).
- `bitcoin-core/src/validation.cpp:3114-3171` — `FindMostWorkChain`
  (reverse iter on sorted `setBlockIndexCandidates`,
  `BLOCK_FAILED_VALID` / `BLOCK_HAVE_DATA` ancestor filter, candidate
  erase on failure).
- `bitcoin-core/src/validation.cpp:3005-3110` — `ConnectTip` (block
  read + ConnectBlock + chainstate write + UpdateTip).
- `bitcoin-core/src/validation.cpp:2929-2992` — `DisconnectTip` (read
  rev*.dat undo + DisconnectBlock + `DisconnectedBlockTransactions`
  capture + tip→pprev).
- `bitcoin-core/src/validation.cpp:3521-3697` — `InvalidateBlock`
  (descendant marking with `BLOCK_FAILED_VALID`).
- `bitcoin-core/src/validation.cpp:3711-3730` — `ResetBlockFailureFlags`
  (only clears `BLOCK_FAILED_VALID` from blocks that **are descendants
  of pindex OR ancestors of pindex**; does NOT touch unrelated
  failed blocks).
- `bitcoin-core/src/validation.cpp:4325 + 4339` — `fTooFarAhead` gate
  using `MIN_BLOCKS_TO_KEEP = 288`.
- `bitcoin-core/src/chain.h:42-86` — `BLOCK_VALID_*` (5-level ordered
  ladder UNKNOWN/RESERVED/TREE/TRANSACTIONS/CHAIN/SCRIPTS + HAVE_DATA
  / HAVE_UNDO / FAILED_VALID / FAILED_CHILD / OPT_WITNESS; ordinal
  mask = 7).
- `bitcoin-core/src/chain.h:254-258` — `CBlockIndex::IsValid(nUpTo)`
  uses `(nStatus & BLOCK_VALID_MASK) >= nUpTo`.
- `bitcoin-core/src/chain.h:265-271` — `CBlockIndex::RaiseValidity`
  (monotonic state transition; replaces ordinal).
- `bitcoin-core/src/chain.h:120-129,149,152` — `nTx`,
  `m_chain_tx_count`, `nSequenceId`, `nTimeMax`.
- `bitcoin-core/src/node/blockstorage.cpp` — `CBlockIndexWorkComparator`
  tiebreak: chainwork DESC → nSequenceId ASC → pointer ASC.
- `bitcoin-core/src/validation.h:75-76` — `MIN_BLOCKS_TO_KEEP=288`.

**BIPs / specs covered:** BIP-30 (duplicate coinbase, disconnect side),
BIP-34 (BIP-34 height activation tightens header acceptance), BIP-113
(MTP-as-locktime), BIP-130 (sendheaders), BIP-94 (testnet4 timewarp
gate at retarget boundaries).

## Gate matrix (30 sub-gates / 8 behaviours)

| # | Behaviour                                                                                          | Verdict |
|---|----------------------------------------------------------------------------------------------------|---------|
| G1  | `ActivateBestChain` exists as the outer control loop                                              | **BUG-1 (P0-CDIV)** missing — two ad-hoc pipelines |
| G2  | `setBlockIndexCandidates` sorted candidate set exists                                             | **BUG-2 (P0-DEAD)** missing — flat hash table only |
| G3  | `FindMostWorkChain` scans candidates skipping FAILED / missing-DATA ancestors                      | **BUG-2 cross-cite** — no candidate set, never re-evaluates |
| G4  | `ConnectTip` extracted as a discrete primitive                                                    | **BUG-3 (P1)** inlined into `connect_pending_blocks` + reorg loop |
| G5  | `DisconnectTip` extracted as a discrete primitive                                                 | PARTIAL (`disconnect_block`, but `rollback_chain_to` is the only caller — inlined into reorg path) |
| G6  | `MAX_REORG_DEPTH` matches Core (NO cap; only `MIN_BLOCKS_TO_KEEP=288` for prune-protection)        | **BUG-4 (P0-CDIV)** hardcoded 100; rejects deeper reorgs Core would accept |
| G7  | `BlockStatus::VALID_*` 5-level ordinal ladder in low 3 bits                                       | **BUG-5 (P0-DEAD)** absent entirely; only boolean `invalid_blocks` set |
| G8  | `IsValid(nUpTo)` uses `(nStatus & MASK) >= nUpTo`                                                 | **BUG-5 cross-cite** |
| G9  | `RaiseValidity(nUpTo)` is monotonic ordinal transition                                            | **BUG-5 cross-cite** |
| G10 | Chain candidates tie-broken by `nSequenceId` not block hash                                       | **BUG-6 (P1)** no candidate set, no sequence counter |
| G11 | `m_chain_tx_count` cumulative tx counter on header index                                          | **BUG-8 (P1)** absent (only mentioned in `assumeutxo_for_blockhash` data table) |
| G12 | `nTimeMax` (max timestamp self + ancestors)                                                       | **BUG-9 (P2)** absent |
| G13 | Header-acceptance checks parent `BLOCK_FAILED_VALID`                                              | **BUG-10 (P0-CDIV)** `accept_header` never consults `invalid_blocks` |
| G14 | `contextual_check_block_header` (full BIP-113 + version-bits)                                     | PARTIAL (inline in accept_header — version-bits OK, BIP-113 MTP OK; **no parent.nTimeMax check**) |
| G15 | Header persisted at HEADER-acceptance time (Core `AcceptBlockHeader`)                              | PASS (`put_header` + `put_height_index` at sync.lua:1116-1117) |
| G16 | `m_best_header` pointer distinct from chain tip, advanced on header arrival                       | PASS (`header_tip_hash` / `header_tip_height` advance independently — sync.lua:1129-1130) |
| G17 | `ProcessNewBlockHeaders` runs PoW + MTP **before** block download begins                          | PASS (sync.lua:967-1004 in `accept_header`) |
| G18 | Headers-first downloads release the main lock between iterations (Core cs_main chunking)          | PARTIAL — `max_blocks_per_connect=8` yields back to event loop (sync.lua:2157-2159) |
| G19 | `fInvalidFound` retry loop falls back to next-best chain on ConnectBlock failure                  | **BUG-11 (P0-CDIV)** no fallback; failed block → `next_connect_height++` (sync.lua:2243) skips it, never re-tries with side branch |
| G20 | `InvalidateBlock` marks descendants `BLOCK_FAILED_VALID` (not propagated through children)        | PARTIAL — `mark_descendant_invalid` walks ALL headers O(n × depth) — see BUG-13 |
| G21 | `setBlockIndexCandidates.erase(invalidated)` keeps candidate set consistent                       | **BUG-2 cross-cite** |
| G22 | `MaybeUpdateMempoolForReorg` runs post-reorg                                                      | PASS (utxo.lua:3442-3446 — `opts.mempool` plumbed; calls `block_disconnected`) |
| G23 | Block-connection signals fire AFTER `cs_main` released                                            | PARTIAL — `callbacks.on_block_connected` fires inline at connect-time (utxo.lua line ~2980), not after lock release; no ValidationInterface analog |
| G24 | `MAX_DISCONNECTED_TX_POOL_BYTES` cap on disconnect-pool RAM                                       | **BUG-14 (P2)** absent; `disconnected_blocks` array grows linearly |
| G25 | Reorg walk uses skip-pointer (`pskip`) for O(log n) ancestor traversal                            | **BUG-15 (P1)** linear `header.prev_hash` walk only |
| G26 | Headers-first PRESYNC writes nothing to disk                                                      | PASS (PRESYNC stores only commitments in `self.presync`) |
| G27 | After REDOWNLOAD the chain-work threshold is enforced via min_pow_checked                          | PASS (`accept_header` opts.min_pow_checked threading; sync.lua:1450) |
| G28 | `BLOCK_OPT_WITNESS=128` / `BLOCK_STATUS_RESERVED=256` flags present                               | **BUG-5 cross-cite** absent |
| G29 | Disconnect-tip block-data persisted (re-connect on reorg-back)                                    | PASS (storage retains block bodies; rollback_chain_to does not delete) |
| G30 | Reorg path is atomic-on-disk (single `WriteBatch` for the whole reorg)                            | PASS (`reorg_batch` shared batch at utxo.lua:3411, written sync=true at 3509) |

Additional findings outside the gate matrix:
- **256-bit chainwork is faked.** `work_for_bits` (sync.lua:888-910)
  returns a **Lua double** ≈ `1.157920892373162e+77 / target_num` —
  loses precision well before mainnet target ranges. Comparison
  rolls back to a fake 32-byte big-endian re-encoding of the double
  (sync.lua:1268-1289) — see BUG-7.
- **No `OPT_WITNESS` bit / no `BLOCK_STATUS_RESERVED` bit** — see BUG-5.
- **Testnet4 genesis hardcoded mismatch (Known Issue 2026-03-28)** is
  upstream of this audit — see BUG-22 cross-cite.

---

## BUGS

### BUG-1 (P0-CDIV) — No `ActivateBestChain` function; tip advancement is split across two ad-hoc pipelines, neither of which re-evaluates side branches after the tip changes

**Severity:** P0-CDIV.
**File:** `lunarblock/src/sync.lua:2151-2562` (`connect_pending_blocks` —
tip-extend-only); `lunarblock/src/utxo.lua:3196-3513`
(`accept_side_branch_block` — RPC submitblock-only).
**Core ref:** `bitcoin-core/src/validation.cpp:3323-3488` —
`ActivateBestChain` is a do-while loop that **after every tip mutation**
re-runs `FindMostWorkChain` and switches to the heaviest valid
candidate.

**Description:** Lunarblock has no function that fits the contract:
> "after any new block / header / invalidate, pick the
> most-work valid candidate and connect or disconnect to reach it."

Instead, two distinct pipelines drive the tip:

1. `BlockDownloader:connect_pending_blocks` (sync.lua:2151) extends
   the active tip **one block at a time, in header-index height order**.
   It cannot fork to a different branch — it walks
   `header_chain.height_to_hash[next_connect_height]`, which is the
   per-height **active chain pointer**, not a candidate set.
2. `ChainState:accept_side_branch_block` (utxo.lua:3196) is the only
   function that compares total work of a side branch against the
   active chain — and it is **called only from `submitblock` RPC**
   (rpc.lua:7018). The P2P IBD path never invokes it.

If during IBD a peer announces a heavier side-branch with the same
prefix headers, the headers will be accepted into `self.headers` —
but `height_to_hash` is overwritten only when the new branch has
strictly more total work (sync.lua:1128-1131). So `height_to_hash`
already does mostly-correct tip selection at the **header layer** —
but `connect_pending_blocks` doesn't know to roll back
`next_connect_height` when that happens. The IBD downloader keeps
extending from the now-stale `next_connect_height` on the old branch,
silently bypassing the heavier candidate at the **block** layer.

**Impact:** Mid-IBD reorg via P2P (e.g. an attacker pushes a slightly
heavier side branch after some headers were already accepted) is
silently ignored by the block downloader. The reorg only happens if
the operator manually calls `submitblock` with the side-branch tip.

---

### BUG-2 (P0-DEAD) — No `setBlockIndexCandidates` sorted candidate set; tip selection scans only the active `height_to_hash` map

**Severity:** P0-DEAD.
**File:** `lunarblock/src/sync.lua:631-784` (header index = flat Lua
table `headers[hash_hex] = {header, height, total_work}` + per-height
pointer `height_to_hash[height] = hash_hex`).
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp` —
`CBlockIndexWorkComparator`; `setBlockIndexCandidates` is a
`std::set<CBlockIndex*, CBlockIndexWorkComparator>` updated on every
`ReceivedBlockTransactions` / `RaiseValidity` event.

**Description:** lunarblock's only "candidate set" is `height_to_hash` —
keyed by height, **only one hash per height** (whichever total_work
last won the swap at sync.lua:1128). A side branch that arrives with
the same height but lower total_work is stored in `self.headers`
keyed by its hash, but it is **never enumerated**: there is no
"iterate all candidate tips" call site anywhere in the codebase.

Consequence: when the active chain is invalidated (via
`invalidate_block` RPC, BUG-13), there is no `FindMostWorkChain` to
walk back through the remaining candidates and pick the next-best
non-failed chain. The active chain just shrinks to the last
non-invalid tip and stops. If a heavier side branch already exists
on disk but is not the current `height_to_hash[h]` for any h, it
will never be promoted.

This is the lunarblock manifestation of the same defect rustoshi has
(W148 BUG-2) and which W101 G1-G5 documented on the active fleet.

**Cross-cite:** W101 G1-G5 (no candidate set), W101 G18 (no
`setBlockIndexCandidates.erase` on invalidate).

---

### BUG-3 (P1) — `ConnectTip` inlined into `connect_pending_blocks` + reorg loop; no shared primitive

**Severity:** P1.
**File:** `lunarblock/src/sync.lua:2229-2453` (IBD per-block connect);
`lunarblock/src/utxo.lua:3449-3502` (reorg-time per-block connect via
`accept_side_branch_block`).

**Description:** Core's `ConnectTip` (validation.cpp:3005-3110) is a
single named primitive that reads the block, calls `ConnectBlock`,
updates the chainstate, and emits `BlockConnected`. Lunarblock has
two implementations:

1. IBD path (sync.lua:2229): `check_block` → `connect_callback` →
   `chain_state:accept_block` → connect_block → `set_chain_tip`.
2. Reorg path (utxo.lua:3490): `connect_block` **directly** (bypassing
   accept_block + check_block — W143 BUG-3) with a `reorg_batch` shim.

The two paths diverge on: BIP-113 IsFinalTx enforcement (reorg passes
`prev_block_mtp=nil, get_block_mtp=nil` — see W143 BUG-3), check_block
re-run (reorg skips), atomicity (reorg uses a shared batch; IBD uses
per-block batches), and signal emission (`on_block_connected` fires
on the IBD path but not consistently on the reorg path — the
`callbacks` field is set up in main.lua:1108 and runs inside
connect_block via `self.callbacks.on_block_connected`, which is on
the active-chain reorg path BUT bypasses BIP-113 + check_block).

A single `connect_tip(block_index)` would route all callers through
the same validation gates and guarantee `m_chain_tx_count` /
`nSequenceId` / status-bit updates are consistent. Today the two
pipelines drift.

---

### BUG-4 (P0-CDIV) — `MAX_REORG_DEPTH = 100` hardcoded; diverges from Core (no max reorg depth, only `MIN_BLOCKS_TO_KEEP=288` prune protection)

**Severity:** P0-CDIV.
**File:** `lunarblock/src/utxo.lua:3224` — `local MAX_REORG_DEPTH = 100`.
**Core ref:** Core has no `MAX_REORG_DEPTH`. Reorgs of arbitrary depth
are accepted **if the new chain has more total work**;
`MIN_BLOCKS_TO_KEEP = 288` controls only how far back rev*.dat files
are retained for the active chain.

**Description:** `accept_side_branch_block` walks back from the
incoming side-branch tip to find a common ancestor with the active
chain (utxo.lua:3252-3274). The walk caps at 100 steps; deeper
side branches return `"reorg-depth-exceeded"` and the block is
dropped.

```lua
-- utxo.lua:3224
local MAX_REORG_DEPTH = 100
-- ...
while cursor_hash and steps < MAX_REORG_DEPTH do
  -- ...
  if maybe_active ~= nil then common_height = ...; break end
  steps = steps + 1
end
if common_height == nil then return nil, "reorg-depth-exceeded" end
```

The comment claims "Core also caps reorg depth in practice via the
headers-first work threshold" — this is false. Core has no
`MAX_REORG_DEPTH` constant; it relies on chainwork + invalidate/
reconsider + `MIN_BLOCKS_TO_KEEP=288` for prune-protection. A
175-block reorg (e.g. exchange double-spend recovery) that Core
would accept is silently rejected by lunarblock with `submitblock`.

**Impact:** divergence from Core on deep reorgs. Not a chain-split
risk in the normal IBD path (which is tip-extend-only), but RPC
submitblock cannot reach Core-accepted heavy reorgs > 100 blocks
deep.

---

### BUG-5 (P0-DEAD) — Zero references to `BLOCK_VALID_*` validity ladder; header index has no `nStatus` field

**Severity:** P0-DEAD.
**File:** lunarblock-wide (zero matches via `grep -c "BLOCK_VALID"
src/*.lua`; only `src/utxo.lua:3292,3914,3975` mention it in comments
**describing what Core does** but lunarblock does not).
**Core ref:** `bitcoin-core/src/chain.h:42-86`.

**Description:** Core's `CBlockIndex::nStatus` is a 32-bit bitfield:

- Low 3 bits (`BLOCK_VALID_MASK = 7`): ordinal validity 0..5 (UNKNOWN /
  RESERVED / TREE / TRANSACTIONS / CHAIN / SCRIPTS).
- High bits: HAVE_DATA=8, HAVE_UNDO=16, FAILED_VALID=32, FAILED_CHILD=64,
  OPT_WITNESS=128, STATUS_RESERVED=256.

`IsValid(nUpTo)` is `(nStatus & MASK) >= nUpTo`. `RaiseValidity` is
monotonic: `if new > old: nStatus = (nStatus & ~MASK) | new`.

lunarblock has **none** of this. Header index entry (sync.lua:1108-1112):

```lua
self.headers[hash_hex] = {
  header = header,
  height = height,
  total_work = work,    -- Lua double; see BUG-7
}
```

No `nStatus`. No `IsValid`. No `RaiseValidity`. The only
invalid-block tracking is a single in-memory hash set
`chain_state.invalid_blocks` (utxo.lua:2086) keyed by raw 32-byte hash.
There is no distinction between "header valid but body missing" /
"body present, undo not applied" / "fully connected" — all in-memory
header entries are treated identically.

Consequence: lunarblock cannot answer "does this block have its
body on disk?" without a separate `storage.get(BLOCKS, hash.bytes)`
RocksDB lookup. Cannot answer "is this block at least
`VALID_TRANSACTIONS`?" without the same. The candidate-set
comparator Core uses (chainwork DESC, but **only among candidates
with `m_chain_tx_count` populated**) is unimplementable.

This is the foundation that BUG-2, BUG-8, BUG-9, BUG-10, and
BUG-15 all build on. Fleet pattern: same shape as W148 BUG-7 for
rustoshi (uses status as bitflags not ordinal) and W148 BUG-9 for
blockbrew (6 disjoint bits instead of 5-level ladder), but
lunarblock is more severe — **no status field at all**.

**Cross-cite:** W109 G21, W109 G22, W148 (rustoshi G7/G8/G9 + blockbrew G22).

---

### BUG-6 (P1) — No `nSequenceId` insertion-order counter; tiebreak by `total_work` only

**Severity:** P1.
**File:** `lunarblock/src/sync.lua:920-937` (`process_headers`) —
the headers `{header, height, total_work}` record has no `seq` field.
**Core ref:** `bitcoin-core/src/chain.h:149` — `int32_t nSequenceId`;
`CBlockIndexWorkComparator` tiebreaks by sequence id ascending then
pointer-address ascending.

**Description:** Core assigns `nSequenceId` to each `CBlockIndex` in
**insertion order via `nBlockSequenceId++`** at `BlockManager::AddToBlockIndex`
(validation.cpp:4154). When two candidate chains have identical
chainwork, the **earlier-seen** chain wins, which gives deterministic
behaviour against grinding attacks.

lunarblock's only tiebreak is "whichever chain accumulated more
`total_work` wins" (sync.lua:1128). Two chains with equal floating-
point work (BUG-7 makes this surprisingly common) tiebreak on
"whichever was processed second" implicitly (the `>` is strict, so
ties keep the existing tip). That is the **opposite** of Core's
"earlier-seen wins" policy.

Adversarial: a peer that knows two distinct nonces yielding the same
PoW hash class can grind blocks with equal-work targets and grief
the node's tip selection. (Not a chain split, but unstable tip.)

---

### BUG-7 (P0-CDIV) — Chainwork stored as Lua double (floating-point), not 256-bit big-endian integer

**Severity:** P0-CDIV (silent divergence over long chains).
**File:** `lunarblock/src/sync.lua:888-910` (`work_for_bits`);
sync.lua:1083-1103 (candidate work compare during `accept_header`);
sync.lua:1268-1289 (`get_chain_work` — float-to-bytes conversion).
**Core ref:** `bitcoin-core/src/chain.h:24` — `arith_uint256
nChainWork`; full 256-bit integer arithmetic.

**Description:** lunarblock computes per-block work as a **Lua
double**:

```lua
-- sync.lua:907-909
-- Work = 2^256 / (target + 1)
-- We use 2^256 ≈ 1.157920892373162e+77
return 1.157920892373162e+77 / (target_num + 1)
```

`target_num` is itself a double summarised from the first 8 bytes of
the target (sync.lua:892-901). This loses precision in the low
bits of every per-block work value. Cumulative `total_work` is also
a double. The chain-work comparator at sync.lua:1083-1103 converts
the float back to 32 big-endian bytes for `work_compare`, but the
input has **already lost ~50 bits of precision** vs Core.

Consequence: two chains with `Δwork < 2^203`-ish (well below mainnet
adjustment scales but **possibly within an attacker's grinding
budget on testnet/regtest**) will compare equal in lunarblock when
Core sees them as distinct. Tiebreak then falls to BUG-6
("first-seen keeps tip" via the strict `>`).

Functionally: this is a chain-split candidate in regtest /
adversarial setups, and a soft chainwork desync on mainnet long-tail
(precision drift over hundreds of thousands of blocks).

**Cross-cite:** This is a recurring lunarblock pattern from W122
(work-arithmetic), but W148 is the first audit to surface it in the
chain-selection context.

---

### BUG-8 (P1) — `m_chain_tx_count` cumulative tx counter absent on header index

**Severity:** P1.
**File:** `lunarblock/src/sync.lua:1108-1112` — header entry has
`{header, height, total_work}` only.
**Core ref:** `bitcoin-core/src/chain.h:125-129`,
`bitcoin-core/src/validation.cpp:3765-3815` (`ReceivedBlockTransactions`
populates `nTx = block.vtx.size(); m_chain_tx_count = nTx +
pprev->m_chain_tx_count;` and walks descendants).

**Description:** Core uses `m_chain_tx_count` as the
"transactions-known-on-this-branch" counter that
`CBlockIndexWorkComparator` requires before promoting a candidate:
the comparator only considers candidates with a non-zero
`m_chain_tx_count`. lunarblock has no equivalent. The only
mention of the name in the codebase is in
`consensus.lua:938-980` — the hardcoded **assumeutxo data table**
(`m_chain_tx_count = 991032194, …`) for snapshots — none of which
populates a runtime field.

Without `m_chain_tx_count`, lunarblock cannot answer:
- "what is `getblockchaininfo.nchaintx`?" (rpc.lua:7770 returns
  `coins_count` and comments "caller can read m_chain_tx_count
  from chainparams" — confessed gap).
- "is this candidate eligible for FindMostWorkChain?"
- "what's the verification-progress estimate?" (Core uses
  `m_chain_tx_count` against `assumeutxo` reference).

**Cross-cite:** Fleet pattern across W109 G10 (rustoshi), W148
blockbrew BUG-11. lunarblock is the third confirmed.

---

### BUG-9 (P2) — `nTimeMax` (max timestamp over self + ancestors) absent

**Severity:** P2.
**File:** `lunarblock/src/sync.lua:1108-1112` — no `n_time_max` field.
**Core ref:** `bitcoin-core/src/chain.h:152` — `unsigned int nTimeMax`
populated at `AddToBlockIndex`.

**Description:** Core uses `nTimeMax` for two things:
- `getblockchaininfo.time` (returns the tip's `nTimeMax` so reorgs
  cannot make the chain "go backwards in time").
- Some pruning heuristics rely on it to keep
  "blocks within the last day" instead of "last 24h of block-time".

lunarblock has neither field nor either of those semantics. RPC
`getblockchaininfo` returns `header.timestamp` directly — which can
go backwards on reorg (BIP-94 testnet4 timewarp limit aside).

---

### BUG-10 (P0-CDIV) — `accept_header` never checks `parent.invalid_blocks` (no `bad-prevblk` rejection)

**Severity:** P0-CDIV.
**File:** `lunarblock/src/sync.lua:950-1134` (`HeaderChain:accept_header`).
**Core ref:** `bitcoin-core/src/validation.cpp:4220-4223`:
```cpp
if (pindexPrev->nStatus & BLOCK_FAILED_VALID) {
    return state.Invalid(BlockValidationResult::BLOCK_INVALID_PREV, "bad-prevblk");
}
```

**Description:** Core rejects any header whose parent is marked
`BLOCK_FAILED_VALID`. lunarblock's `accept_header` validates:

- parent exists (sync.lua:962-965)
- PoW (sync.lua:968-971)
- time-too-old / time-too-new / BIP-94 timewarp (sync.lua:977-1001)
- difficulty target (sync.lua:1006-1019)
- bad-version (sync.lua:1034-1049)
- checkpoint (sync.lua:1051-1055)
- anti-fork pre-checkpoint (sync.lua:1057-1074)
- min_pow_checked (sync.lua:1083-1104)

**But never:** parent's hash in `chain_state.invalid_blocks`. The
invalid-blocks set is held on `ChainState`, not on `HeaderChain`, and
`accept_header` lives on `HeaderChain` and has no reference to it.

Consequence: an attacker that learns a block hash that lunarblock
has explicitly invalidated (via RPC `invalidateblock` or via a
ConnectBlock failure) can extend a header chain from that
invalidated block, and every descendant header is silently grafted
into the header index. The peer is not banned (no
"bad-prevblk" rejection signal). The downloader will then request
those side-branch blocks. They will fail to connect (because
`has_invalid_ancestor` is checked in `accept_side_branch_block` —
utxo.lua:3295), but only after wasting download bandwidth and
disk-storage write traffic.

**Cross-cite:** rustoshi W148 BUG-13/BUG-14 + blockbrew BUG-1 are the
fleet siblings. lunarblock is the third confirmed; all three have
the same architectural gap (header layer doesn't know about block-layer
invalidation).

---

### BUG-11 (P0-CDIV) — Failed connect_block at height H sets `next_connect_height = H+1` and **never re-tries**; no `fInvalidFound` retry loop or candidate fall-back

**Severity:** P0-CDIV.
**File:** `lunarblock/src/sync.lua:2229-2249`.
**Core ref:** `bitcoin-core/src/validation.cpp:3270-3275` —
`ActivateBestChainStep` returns `fInvalidFound=true`,
`ActivateBestChain` then loops and `FindMostWorkChain` returns the
**next-best candidate** that bypasses the invalid block.

**Description:** When `pcall(validation.check_block, …)` fails or
the connect_callback raises, the IBD path:

```lua
-- sync.lua:2241-2248
self.pending_blocks[hash_hex] = nil
print(string.format("Skipping invalid block at height %d: %s", …))
self.next_connect_height = self.next_connect_height + 1
-- Reset stall-recovery timer
self.last_connect_advance = _sock.gettime()
goto continue_loop
```

`next_connect_height++` — so on the **next** iteration, lunarblock
tries to connect height H+1. But:
- Height H+1's block depends on height H (which we just declared
  invalid).
- Height H+1's `check_block` may not detect the dependency (the
  contextual gates assume the parent connected).
- Without a `FindMostWorkChain` fall-back, lunarblock has no way to
  switch to a different branch — `height_to_hash[H]` still points
  to the rejected block.

Result: the rejected block at H may have been a legitimate Core-
accepted block whose `check_block` raised due to a lunarblock bug
(W142+W143 confirm many such asserts). Lunarblock then permanently
skips it and tries to connect its descendants on top of nothing — a
self-induced cascade of "Missing UTXO" errors.

The classify_callback_error helper (sync.lua:40-100) at least names
the failure mode, but the recovery path is just "give up at this
hash for retry-count=5 then advise --reindex-chainstate." No
alternative-branch lookup.

**Cross-cite:** W101 G10 (rustoshi same shape).

---

### BUG-12 (P0-SEC) — Reorg connect loop calls `self:connect_block(...)` WITHOUT pcall and WITHOUT `check_block`; any LuaJIT assert leaks half-applied reorg_batch + dirty UTXO cache (W142 BUG-24 reprise + W143 BUG-3 amplifier)

**Severity:** P0-SEC.
**File:** `lunarblock/src/utxo.lua:3490-3501`.
**Core ref:** `bitcoin-core/src/validation.cpp:3046-3062` —
ConnectTip's `ConnectBlock` failure path calls `state.IsInvalid()` →
`InvalidBlockFound` → returns false; ActivateBestChain unwinds the
abandoned connect via `DisconnectTip` recovery.

**Description:** The reorg connect loop (utxo.lua:3449-3502):

```lua
for i = side_len, 1, -1 do
  local entry = side_chain[i]
  -- … load block, build store_batch_fn …
  local ok_conn, err_conn = self:connect_block(
    sb_block, entry.height, entry.hash,
    nil, nil,  -- prev_block_mtp / get_block_mtp nil (W143 BUG-3)
    opts.skip_scripts, false,
    opts.nosync, store_batch_fn,
    reorg_batch
  )
  if not ok_conn then
    return abort_reorg(string.format("reorg-connect-failed at height %d: %s", …))
  end
end
```

`connect_block` (utxo.lua:2134) raises `assert()` for ~25 distinct
consensus failures (utxo.lua:2327, 2370, 2390, 2400, 2402, 2519,
2526, 2547, 2552, 2580, 2585, 2587, 2624, 2632, 2639, 2652, 2656,
2667, 2668, 2669, 2700, 2702, 2733, 2741, 2766, 2772, 2794, …).
None of these returns `(nil, err)` — they `error()` and unwind the
Lua stack.

The reorg call site does **NOT** wrap this in `pcall`. Effect:
- LuaJIT propagates the error up to the next pcall, which is in
  `rpc.lua:6877` (submitblock outer wrapper).
- `reorg_batch` is **NOT** destroyed (the cleanup in
  `abort_reorg` only runs on the "ok_conn=false" path).
- `coin_view.dirty` entries from the partial disconnect+connect are
  **NOT** dropped (`discard_dirty()` is only called from `abort_reorg`).
- The pending `reorg_batch` may already have written disconnect ops
  for the entire active chain down to common_height.

Worst case: a peer crafts an invalid side-branch block whose
`connect_block` raises an assert at, e.g., utxo.lua:2547 (P2WPKH
script verification failed); submitblock pcalls catch it but the
chain_state is left with stale dirty-UTXO entries in memory and a
detached `reorg_batch` object (which gets GC'd, but in the meantime
the in-memory tip pointer may have already been mutated in
disconnect_block — utxo.lua:3530 starts by clearing sig_cache and
loading undo, then in the shared-batch path advances the tip
pointer mid-flight). Subsequent calls (mempool refill, RPC reads)
see inconsistent state until the next restart pulls the on-disk
truth.

**Cross-cite:** W142 BUG-24 ("LuaJIT assert-as-validation → wire-DoS"
pattern, same shape) + W143 BUG-3 ("reorg skips check_block")
compounded. lunarblock has **two** known assert-as-validation
re-entrance hazards in production — this one is the more serious
because the partial-write side effects extend to RocksDB.

---

### BUG-13 (P1) — `mark_descendant_invalid` is O(n × depth) iteration over full HEADERS column family per `invalidate_block` call

**Severity:** P1.
**File:** `lunarblock/src/utxo.lua:3917-3952`.
**Core ref:** `bitcoin-core/src/validation.cpp:3521-3697` —
InvalidateBlock walks `m_block_index` once (O(n)) and uses parent
pointers; descendant detection is O(n × log n) average with
skip-pointers.

**Description:** Lunarblock's `mark_descendant_invalid` walks every
header in the HEADERS column family, and for each candidate **walks
its entire ancestor chain (capped at 10000 steps)** checking if any
ancestor equals `block_hash`. This is O(n × depth) per call — at
mainnet height ~880k headers × ~880k average ancestor depth, the
worst case is on the order of 10^11 work. The 10,000-cap mitigates
runaway loops but also **silently misses** descendants whose
common ancestor is more than 10,000 blocks below the invalidated
block.

```lua
-- utxo.lua:3922-3950
iter.seek_to_first()
while iter.valid() do
  local candidate_bytes = iter.key()
  if candidate_bytes ~= block_hash.bytes and not self.invalid_blocks[candidate_bytes] then
    local cur = candidate_hash
    local limit = 10000  -- prevent infinite loop on malformed storage
    while cur and limit > 0 do
      limit = limit - 1
      -- … walk parent chain looking for block_hash …
    end
  end
  iter.next()
end
```

This is the symmetric counterpart to BUG-15 (linear ancestor walk
on the reorg path).

---

### BUG-14 (P2) — No `MAX_DISCONNECTED_TX_POOL_BYTES` cap on disconnect-pool RAM during reorg

**Severity:** P2.
**File:** `lunarblock/src/utxo.lua:3365-3385` — `disconnected_blocks`
array grows linearly with reorg depth, each entry holding a fully
deserialized block (~1 MB / mainnet block).
**Core ref:** `bitcoin-core/src/txmempool.h` —
`MAX_DISCONNECTED_TX_POOL_BYTES = 20 MB` controls the
`DisconnectedBlockTransactions` ring buffer.

**Description:** Lunarblock's reorg snapshot (utxo.lua:3367-3384)
captures the full block bodies of every disconnected block. At
MAX_REORG_DEPTH=100 and 1 MB per block, peak RAM is bounded at
~100 MB — modest, but on regtest with synthetic blocks (each
holding many txs) the peak is unbounded by tx count. Core caps the
combined size of all retained txs at 20 MB and forces eviction
beyond that.

---

### BUG-15 (P1) — Reorg ancestor walk in `accept_side_branch_block` is linear `header.prev_hash` (no skip-pointer)

**Severity:** P1.
**File:** `lunarblock/src/utxo.lua:3248-3274`.
**Core ref:** `bitcoin-core/src/chain.cpp` — `CBlockIndex::GetAncestor`
uses `pskip` (log-tree skip-pointer) for O(log n) ancestor traversal.

**Description:** lunarblock walks `cursor_header.prev_hash` one step
at a time. Each step is a storage.get_header RocksDB lookup. At
MAX_REORG_DEPTH=100 depth, that's 100 RocksDB GETs serially —
~10 ms of disk I/O under normal load, but uncapped under contention.
A skip-pointer would reduce this to ~log2(100) ≈ 7 lookups.

---

### BUG-16 (P0-DEAD) — `clear_descendant_invalid_flags` only iterates already-invalid blocks; can leave non-invalid descendants of a reconsidered block carrying `FAILED_CHILD` semantics (modulo absence of FAILED_CHILD, BUG-5)

**Severity:** P0-DEAD.
**File:** `lunarblock/src/utxo.lua:4075-4111`.
**Core ref:** `bitcoin-core/src/validation.cpp:3711-3730` —
`ResetBlockFailureFlags` filters by **ancestor-OR-descendant relation
AND `BLOCK_FAILED_VALID`** — does NOT touch unrelated failed blocks.

**Description:** Reconsider's helper walks ALL headers, but **only**
considers entries already in `self.invalid_blocks`. Descendants of
the reconsidered block that were never explicitly invalidated (Core
would have `FAILED_CHILD` from descendant propagation) are no-ops
here because lunarblock has no FAILED_CHILD bit (BUG-5).

```lua
-- utxo.lua:4081-4106
while iter.valid() do
  local hash_bytes = iter.key()
  if self.invalid_blocks[hash_bytes] then    -- ← gate
    -- walk ancestors looking for block_hash
    -- if descendant, mark for clearing
  end
  iter.next()
end
```

Coupled with BUG-13's invalidate-side fanout (which DOES mark
descendants explicitly), this is symmetric: invalidation marks
descendants, reconsider clears descendants — but only the explicitly-
marked ones. The 10,000-step ancestor cap (BUG-13) means deep
descendants may remain marked invalid after `reconsider_block` is
called on the original block.

The wider gap: Core's `ResetBlockFailureFlags` semantics ("filter by
relation, only clear FAILED_VALID") aren't replicated. Lunarblock's
helper walks **ancestors too** (utxo.lua:4053-4061) and unconditionally
clears them — which is **wrong** in Core: ancestors of a reconsidered
block could be marked invalid for independent reasons, and clearing
them here lets a previously-bad block re-enter the candidate set.

---

### BUG-17 (P1) — `is_complete` IBD-exit latch never re-derives from work + tip-age; relies on a one-shot boolean

**Severity:** P1.
**File:** `lunarblock/src/sync.lua:2562-2566` + comments at
sync.lua:2540-2545 acknowledging the gap.
**Core ref:** `bitcoin-core/src/validation.cpp:1940-1942,3283-3291` —
`IsInitialBlockDownload` returns a cached value, but the cache is
**latched only when `IsTipRecent(MinimumChainWork(), max_tip_age)`**
— a function of chain state, not a one-shot flag.

**Description:** lunarblock's `ibd_complete` is a sticky boolean that
flips true once when the three conditions
(next_connect_height > header_tip_height AND no pending AND no
inflight) all hold, plus a "defensive un-latch" at sync.lua:1698-1705
when header_tip races ahead. The defensive un-latch is admitted in
the comments to be "belt-and-braces against a premature-fire race"
— not a principled fix.

Core's design (work-threshold + tip-age) means IBD-exit is a function
of "have I caught up?" not "did my downloader empty its queues?".
The lunarblock latch will incorrectly fire when:
- A SIGTERM mid-IBD drains pending/inflight, then restart loads
  header_tip > best_block (the comment at sync.lua:2516 confirms
  this exact bug pattern was observed on mainnet).
- During a long mempool-driven RPC stall, the downloader stops
  scheduling new GETDATAs.

The latch is acknowledged by the lunarblock authors (`Bitcoin Core's
IsInitialBlockDownload() in validation.cpp is derived from chain
state (work + tip age), not latched by a one-shot flag. This local
fix preserves the latched-flag shape because flipping to derived
would touch every is_complete() caller`).

---

### BUG-18 (P1) — `MAX_NUM_UNCONNECTING_HEADERS_MSGS=10` constant disagrees with Core's `MAX_NUM_UNCONNECTING_HEADERS = 10` — same value but per-peer counter never expires

**Severity:** P1.
**File:** `lunarblock/src/sync.lua:662-694` (`note_unconnecting_headers`).
**Core ref:** `bitcoin-core/src/net_processing.cpp` —
`nUnconnectingHeaders++` reset to 0 on **any** successful header
batch (per-peer); after threshold, peer is **Misbehaving(20)** then
disconnected.

**Description:** Lunarblock's counter (sync.lua:662-694) accumulates
per-peer but the comment at sync.lua:1517 admits "Reset the counter
on the way out so a re-connect from the same peer starts fresh" —
i.e., the reset on the **escalation** path. The reset on the
**success** path is at sync.lua:1538 but only fires when
`accepted > 0`.

Scenario: peer sends 9 batches each with one unconnecting header (no
"unknown parent" trigger fires on the 10th because each batch
contains 9 connecting + 1 unconnecting — accepted > 0 path resets
counter). Peer can permanently keep 9 unconnecting headers in
lunarblock's gauge.

The decay is OK in steady state but the watchdog will not fire on a
slowly-drip attack.

---

### BUG-19 (P0-CDIV) — `fTooFarAhead = height > active_height + MIN_BLOCKS_TO_KEEP` uses **strict** `>` and counts from `active_height`; Core uses `pindex->nHeight > ActiveHeight() + MIN_BLOCKS_TO_KEEP` (also strict) but reads the **next-tip-after-this-block height**, not the current active height

**Severity:** P0-CDIV.
**File:** `lunarblock/src/utxo.lua:3098-3104`.
**Core ref:** `bitcoin-core/src/validation.cpp:4325` —
`fTooFarAhead = (pindex->nHeight > m_chain.Height() + int(MIN_BLOCKS_TO_KEEP))`.

**Description:** The arithmetic is correct **if** `height` is the
new tip's height and `active_height = self.tip_height` (current
tip). But the lunarblock `requested` exemption at utxo.lua:3098
exempts the block from the gate entirely when `opts.requested ==
true`. The IBD downloader (sync.lua:978 connect_callback) does NOT
pass `requested=true` — but `accept_block` is only called when the
block is already in the downloader's `pending_blocks` map, which
implies it WAS requested. Net effect: the gate is enforced when
it shouldn't be (for legitimately-requested IBD blocks, the
`fTooFarAhead` denial fires if header_tip races > 288 ahead of
chain_tip).

This is the inverse failure to BUG-17 — IBD-exit latch is
**too eager**, fTooFarAhead gate is **too strict** for the same
mid-IBD state.

In practice this rarely fires because the downloader's
`max_ahead = next_connect_height + 1024` (sync.lua:1897) keeps
downloads bounded. But on a recovery from chain_tip < header_tip-288
(e.g. after a crash mid-IBD), the next legitimately-arrived block
hits `too-far-ahead` and is dropped.

---

### BUG-20 (P2) — No `pindexBestForkTip` / `pindexBestForkBase` warning when a competing chain has work close to active

**Severity:** P2.
**File:** lunarblock-wide (no equivalent state).
**Core ref:** `bitcoin-core/src/validation.cpp:1820-1851` —
`CheckForkWarningConditions` sets `pindexBestForkTip` if a
non-active chain is within ~7 blocks of the tip; surfaces as
`getchaintips`, `-alertnotify`, and "WARNING: Found large fork"
log lines.

**Description:** Lunarblock's `getchaintips` (rpc.lua) returns
active + side-branch tips from `height_to_hash` but does not
maintain `pindexBestForkTip` / `pindexBestForkBase` and does not
emit a warning when a competing chain accumulates significant work.
Operators have no visibility into a near-miss tip race.

---

### BUG-21 (P3) — Reorg loop's `connect_block` call passes `prev_block_mtp=nil, get_block_mtp=nil` (W143 BUG-3 cross-cite)

**Severity:** P3 (cross-cite).
**File:** `lunarblock/src/utxo.lua:3492-3493`.
**Cross-cite:** W143 BUG-3 + W143 BUG-9.

This is documented in W143 (reorg connect loop bypasses BIP-113
IsFinalTx and BIP-68 time-based sequence locks). Carry-forward for
W148's chain-selection-context catalogue but full description and
fix lives in W143.

---

### BUG-22 (P3-LOG) — Testnet4 genesis hardcoded mismatch (Known Issue 2026-03-28) blocks IBD from a fresh start on testnet4

**Severity:** P3-LOG (cross-cite Known Issues; out-of-scope for
W148's primary scope but the headers-first IBD path is what
exhibits the symptom).
**File:** `lunarblock/src/sync.lua:819-877` (`add_genesis`).
**Cross-cite:** root `CLAUDE.md` Known Issues section.

**Description:** `add_genesis` (sync.lua:819) builds the genesis
block from `network.genesis` fields and computes the hash from
the constructed coinbase. If the testnet4 `coinbase_message` /
`pubkey` / `subsidy` / `bits` / `nonce` fields disagree with the
canonical testnet4 genesis hash, every peer sending real testnet4
headers is rejected with "unknown parent" because the first header
they advertise descends from the canonical genesis hash, not the
synthesized one. This is the documented Known Issue. W148 records
it because it lives **inside the headers-first sync code**
(HeaderChain:add_genesis is the entry point).

---

### BUG-23 (P2) — `process_redownload` per-batch validation does NOT include the BIP-113 / time-too-old / BIP-94 timewarp checks; only continuity + PoW + difficulty + commitment

**Severity:** P2.
**File:** `lunarblock/src/sync.lua:445-549` (`process_redownload`)
vs sync.lua:973-1001 (`accept_header`'s timestamp gates).
**Core ref:** `bitcoin-core/src/headerssync.cpp` —
`ValidateAndStoreRedownloadedHeader` calls
`CheckBlockHeader → ContextualCheckBlockHeader` which DOES include
the time-too-old / BIP-94 checks.

**Description:** `process_redownload` is the second pass of the
anti-DoS pipeline. Header validation here is intentionally light
because the first pass (`process_presync`) already accumulated work
and commitments. But Core re-runs ContextualCheckBlockHeader on
each REDOWNLOAD header — lunarblock skips that. The headers are
then routed to `accept_header` (sync.lua:1450) with
`min_pow_checked=true`, which **does** run the timestamp gates —
so the consensus-level checks ultimately fire. P2 because the
defense-in-depth is missing: a redownload pass that accepts a
time-warped header up to the accept_header gate has wasted CPU,
not committed bad state.

---

### BUG-24 (P3-LOG) — Header-tip persistence (`set_header_tip`) is sync=false on every header batch; ungraceful shutdown can lose up to 2000 headers of progress

**Severity:** P3-LOG.
**File:** `lunarblock/src/sync.lua:933` (set_header_tip called with
`false` for sync).
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp` —
Core flushes `m_block_index` periodically; the in-memory state is
authoritative.

**Description:** Each successful header batch calls
`set_header_tip(self.header_tip_hash, self.header_tip_height, false)`
(sync.lua:933) with `sync=false` — meaning the underlying
RocksDB put goes into the WAL but is not fsync'd. A power loss
between the last sync'd write and the SIGKILL/crash discards up to
the entire current 2000-header batch (~12 KB of header data).

The headers will be re-requested on next start (via the locator
exponential-from-tip), so this is a soft loss, not consensus risk.
But the start time grows when IBD is interrupted near the chain
tip — every restart re-syncs the last partially-written 2000-header
batch.

P3-LOG because there is a periodic durability sync elsewhere (the
chain-tip path uses sync=true at sync.lua:2448 for chainstate
flushes) but the **header-tip path** does not get a matched sync
cadence.

---

## Cross-impl pattern summary

- BUG-1 + BUG-2 + BUG-5 + BUG-6 + BUG-8 + BUG-10 + BUG-13 + BUG-15
  are all manifestations of "**no `setBlockIndexCandidates` + no
  `BLOCK_VALID_*` ordinal**" → lunarblock's outer chain-selection
  surface is structurally incompatible with Core's. Fix is a major
  refactor (introduce `BlockNode` with `nStatus`, `m_chain_tx_count`,
  `nSequenceId`, `nTimeMax`, `pskip`; introduce a
  `setBlockIndexCandidates` Lua sorted set keyed by
  `(chainwork DESC, nSequenceId ASC, hash ASC)`).
- BUG-3 + BUG-4 + BUG-11 + BUG-19 are "**ad-hoc tip-advance
  pipelines diverge from Core on the easy fixes**" (single-block
  step semantics, MAX_REORG_DEPTH, fInvalidFound retry, fTooFarAhead
  exemption). Each is a small fix.
- BUG-12 is the **same shape as W142 BUG-24** — `assert()` as
  validation gate, with an additional re-entrance hazard because
  the reorg loop's caller doesn't `pcall` and doesn't `discard_dirty`
  the cache.
- BUG-7 (Lua-double chainwork) is a recurring lunarblock
  hazard from W122 surfacing again in chain-selection context.
- BUG-17 + BUG-19 + BUG-22 + BUG-24 are operational / wire-parity
  niceties.

**Fleet pattern cross-cites:**
- W148 rustoshi: BUG-1/2 (no candidate set / no ABC), BUG-7
  (status-as-bitflags), BUG-10 (hash-tiebreak not nSequenceId),
  BUG-11 (no m_chain_tx_count), BUG-12 (no nTimeMax), BUG-13/14
  (dead-code header chainwork helpers).
- W148 blockbrew: BUG-1 (no parent.IsInvalid check at AddHeader),
  BUG-3 (no ActivateBestChain loop), BUG-5 (MaxReorgDepth=100),
  BUG-7 (no StatusInvalid mark on ConnectBlock fail), BUG-9
  (power-of-two flags not 5-level ladder), BUG-11 (no nChainTx
  field), BUG-13 (IBD-exit gate divergence).
- lunarblock confirms: BUG-1 (Core ActivateBestChain absent — 3rd
  impl), BUG-2 (no candidate set — 3rd impl), BUG-5 (no validity
  ladder — most severe instance; 0 references vs rustoshi's
  bitflag misuse), BUG-10 (no bad-prevblk at AddHeader — 3rd
  impl), BUG-11 (no fInvalidFound retry — 2nd impl after
  rustoshi), BUG-12 (assert-as-validation in reorg —
  lunarblock-specific shape, no fleet parallel yet), BUG-17
  (one-shot IBD-exit latch — 2nd impl after blockbrew).

## Suggested fix waves (not in scope of this audit)

1. **Architectural:** introduce `BlockNode` with full Core-parity
   fields (`nStatus`, `m_chain_tx_count`, `nSequenceId`, `nTimeMax`,
   `pskip`) and a sorted candidate set; refactor `connect_pending_blocks`
   + `accept_side_branch_block` into one `activate_best_chain`. This
   closes BUG-1/2/3/5/6/8/9/15.
2. **One-liner P0-CDIV:** add `parent.invalid_blocks[parent_hash.bytes]
   check` at the top of `accept_header` (BUG-10 — fleet-wide pattern).
3. **One-liner P0-CDIV:** remove hardcoded `MAX_REORG_DEPTH=100`
   (BUG-4) or raise to a Core-parity threshold gated by chainwork.
4. **P0-SEC:** wrap reorg-loop `connect_block` in pcall and call
   `coin_view:discard_dirty()` + `reorg_batch.destroy()` on error
   (BUG-12 — closes assert-as-validation re-entrance).
5. **P0-CDIV:** replace Lua-double chainwork with 256-bit big-endian
   arithmetic (BUG-7 — recurring lunarblock pattern; consensus.lua
   already has the helpers).

## End of audit
