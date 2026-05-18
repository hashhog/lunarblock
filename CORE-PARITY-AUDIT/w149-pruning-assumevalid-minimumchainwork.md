# W149 — Pruning + assumevalid + minimumchainwork (lunarblock)

**Wave:** W149 — `BlockManager::FindFilesToPrune`,
`FindFilesToPruneManual`, `UnlinkPrunedFiles`, `MIN_BLOCKS_TO_KEEP`,
`PruneAfterHeight`, `BLOCK_HAVE_DATA`/`BLOCK_HAVE_UNDO`,
`-prune=N` sentinel (0/1/>=550), `pruneblockchain` RPC,
`ConnectBlock` `fScriptChecks` skip gate, `defaultAssumeValid`,
`-assumevalid` operator override, `nMinimumChainWork`,
`MinimumConnectedChainWork`, `IsInitialBlockDownload`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/node/blockstorage.cpp:292-318` — `FindFilesToPruneManual`
  (clamps target to `tip - MIN_BLOCKS_TO_KEEP`, walks `m_blockfile_info`
  reverse, sets `m_have_pruned=true`).
- `bitcoin-core/src/node/blockstorage.cpp:321-410` — `FindFilesToPrune`
  (size-driven, MAX_BLOCK_FILE_SIZE step, `nPruneAfterHeight` floor,
  refuses to start until tip > PruneAfterHeight).
- `bitcoin-core/src/node/blockstorage.cpp:804-845` — `UnlinkPrunedFiles`
  (unlinks both blk*.dat AND rev*.dat by file number).
- `bitcoin-core/src/node/blockstorage.cpp:615-640` — `GetFirstBlock`/
  `GetFirstStoredBlock` (walks block_index for first surviving HAVE_DATA).
- `bitcoin-core/src/validation.h:75-87` — `MIN_BLOCKS_TO_KEEP = 288`,
  `MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 MiB` (the 550 in `-prune=550`).
- `bitcoin-core/src/init.cpp:1001-1009` — `-prune` × `-txindex` /
  `-reindex-chainstate` / `-txospenderindex` hard-incompat checks at
  init; node refuses to start.
- `bitcoin-core/src/init.cpp:863, 1947-1953` — `g_local_services`
  defaults to `NODE_NETWORK_LIMITED | NODE_WITNESS`; `NODE_NETWORK`
  is ADDED iff `HistoricalChainstate()==false` (i.e., we have full history).
- `bitcoin-core/src/init.cpp:522` — `-prune` help: "This mode is
  incompatible with -txindex" — operator-visible promise.
- `bitcoin-core/src/rpc/blockchain.cpp:908-965` — `pruneblockchain` RPC
  (dual-mode: height ≤ 1e9 = block height, height > 1e9 = unix time;
  refuses below `PruneAfterHeight`; clamps to `tip-MIN_BLOCKS_TO_KEEP`).
- `bitcoin-core/src/validation.cpp:2345-2383` — assumevalid 6-condition
  gate: (1) `AssumedValidBlock().IsNull()`, (2) hash in block_index,
  (3) `GetAncestor(height) == pindex`, (4) best-header descends from
  pindex, (5) `m_best_header->nChainWork >= MinimumChainWork()`,
  (6) `GetBlockProofEquivalentTime > TWO_WEEKS_IN_SECONDS`.
- `bitcoin-core/src/chain.h:42-86` — `BlockStatus` 5-level ladder +
  `BLOCK_HAVE_DATA`/`HAVE_UNDO` bits + `BLOCK_FAILED_VALID`/`FAILED_CHILD`
  + `BLOCK_STATUS_RESERVED` (was `BLOCK_ASSUMED_VALID`).
- `bitcoin-core/src/kernel/chainparams.cpp:109,232,332,423,557` —
  `nMinimumChainWork` per network (mainnet `…01128750f82f4c366153a3a030`
  ~v29; testnet3 `…17dde1c649f3708d14b6`; testnet4
  `…09a0fe15d0177d086304`; signet `…0b463ea0a4b8`; regtest empty).
- `bitcoin-core/src/kernel/chainparams.cpp:122,240,340,482,565` —
  `nPruneAfterHeight` per network (mainnet 100000; testnet/testnet4/
  signet 1000; regtest 1000 or 100 fastprune).
- `bitcoin-core/src/validation.cpp:1940-1942,3283-3291` —
  `IsInitialBlockDownload`/`UpdateIBDStatus` exit gate: latches false
  once `IsTipRecent(MinimumChainWork(), max_tip_age)` returns true.
- `bitcoin-core/src/net_processing.cpp:153-156,1533,1760-1762` —
  `NODE_NETWORK_LIMITED_MIN_BLOCKS=288`,
  `NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS=144`, peer-serve gating.

**Files audited**
- `src/prune.lua` — pruner module (`M.new`, `compute_prune_target`,
  `maybe_prune`, `force_prune`, `is_pruned`, `MIN_BLOCKS_TO_KEEP=288`,
  `AVG_BLOCK_SIZE=1.5MB`, `PRUNE_INTERVAL_BLOCKS=100`,
  `MAX_DELETES_PER_SWEEP=100`).
- `src/main.lua` — `--prune N` parser (line 274-289), pruner init
  (line 945-959), `connect_callback` prune sweep (line 1034-1041),
  service-flag wiring (line 1188-1191), reindex/reindex-chainstate
  path (line 906-942), assumevalid callback build (line 966-969).
- `src/consensus.lua` — per-network `min_chain_work`, `assumevalid`,
  `make_assumevalid_callbacks`, `should_skip_script_validation`
  (line 1543-1582), `work_compare`/`work_from_hex`/`work_add`.
- `src/sync.lua` — header sync min-work gates (line 1086-1101, 1260-1263,
  1336-1340), `HeaderChain:get_chain_work` float→bytes packing
  (line 1268-1291).
- `src/utxo.lua` — `accept_block` (line 3089-3163), `connect_block`
  `skip_script_validation` plumbing (line 2134, 2406), `reindex_chainstate`
  (line 1744-1856), `accept_side_branch_block`+`connect_block` reorg
  path (line 3196-3513), `MAX_REORG_DEPTH=100`, `MIN_BLOCKS_TO_KEEP`
  re-export (line 19).
- `src/rpc.lua` — `getblockchaininfo` prune fields (line 1323-1364),
  `getblock` pruned-data error (line 1413-1446), `submitblock` →
  assumevalid skip computation (line 7111-7123), `dumptxoutset`
  prune pre-check (line 7658-7678).
- `src/p2p.lua` — `our_services` `NODE_NETWORK_LIMITED` advertisement
  gate (line 136-153).
- `src/peer.lua` — version handshake services emission (line 192).
- `src/storage.lua` — CF map (HEADERS/BLOCKS/UNDO/UTXO/HEIGHT_INDEX/
  META/TX_INDEX). No per-block `nStatus` storage.

---

## Gate matrix (32 sub-gates / 9 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `-prune=N` arg semantics | G1: `0` = disabled | PASS (`main.lua:281-289`) |
| 1 | … | G2: `1` = manual-only (RPC-driven) | **BUG-1 (P0)** parsed + sets `manual_only=true`, but `pruneblockchain` RPC NEVER REGISTERED — value is dead-data plumbing. |
| 1 | … | G3: `>=550` = auto with target MiB | PARTIAL — accepts the value (`main.lua:285-289`) but pruning uses block-COUNT heuristic, not on-disk size (`prune.lua:84-99`, `AVG_BLOCK_SIZE=1.5MB`). |
| 1 | … | G4: `-prune` × `-txindex` mutual-exclusion | **BUG-2 (P0)** Core init.cpp:1003 hard-fails; lunarblock silently accepts both → CF.TX_INDEX is written for txs whose CF.BLOCKS body has been pruned. |
| 1 | … | G5: `-prune` × `-reindex-chainstate` mutual-exclusion | **BUG-3 (P0)** Core init.cpp:1006-1008 hard-fails; lunarblock runs reindex on line 915 *before* pruner init (line 949). Pruner is created with `prune_height=0` after reindex, so reindex sees blocks. BUT on next restart, if pruner already ran and prune_height was N, the second run resets it to 0 and silently no-ops — see BUG-4. |
| 2 | Prune state persistence | G6: `prune_height` survives restart (Core: `m_blockfile_info` on disk) | **BUG-4 (P0)** `pruner.prune_height` is in-memory only (`prune.lua:78`); never persisted to CF.META, never reloaded. After restart, `prune_height=0` regardless of what was deleted on the previous run. `is_pruned(h)` returns false for already-deleted heights → `getblock` returns "Block not found" instead of "Block not available (pruned data)"; `getblockchaininfo.pruneheight=0` lies. |
| 2 | … | G7: BLOCK_HAVE_DATA bit on the block index entry | **BUG-5 (P1)** No `nStatus` bitfield exists on lunarblock's block-index records — no `HAVE_DATA`/`HAVE_UNDO`/`FAILED_VALID`/`FAILED_CHILD`. RPC handlers that should consult HAVE_DATA fall through to "Block not found" (cross-cite W148 BUG-9). |
| 3 | `pruneblockchain` RPC | G8: handler registered | **BUG-6 (P0)** No `self.methods["pruneblockchain"]` — `rpc.lua` exposes zero pruning RPC. Operator literally CANNOT manually prune. |
| 3 | … | G9: dual-mode (height vs unix timestamp) parsing | **BUG-6 cross-cite** absent: there is no handler to dual-mode. |
| 3 | … | G10: `getblockfrompeer` available to re-fetch pruned blocks | NOT IMPLEMENTED (cross-cite: W148 doesn't mention it either). Once a block is deleted from CF.BLOCKS, no recovery path exists short of `--reindex` (which itself is broken — see BUG-15). |
| 4 | `MIN_BLOCKS_TO_KEEP=288` floor | G11: `compute_prune_target` clamps to `tip-288` | PASS (`prune.lua:114`) |
| 4 | … | G12: `tip < MIN_BLOCKS_TO_KEEP` early-return | PASS (`prune.lua:108-110`) |
| 4 | … | G13: Core's `nPruneAfterHeight` start-floor (mainnet 100,000; testnet/signet 1,000; regtest fastprune=100) | **BUG-7 (P1)** entirely absent — lunarblock starts pruning the moment `tip > 288`. On regtest a 300-block test triggers prune sweeps. Core: regtest doesn't prune until tip > 1000 (or 100 fastprune). Causes regtest interop divergence + spurious early sweeps in fleet smoke. |
| 4 | … | G14: `--prune=N` minimum-value gate matches Core's `MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 MiB` | PASS (`main.lua:285-288`) |
| 5 | Per-sweep behaviour | G15: deletes BOTH CF.BLOCKS and CF.UNDO at the height | PASS (`prune.lua:140-141`) |
| 5 | … | G16: preserves CF.HEADERS + CF.HEIGHT_INDEX (Core preserves CBlockIndex) | PASS by comment + impl (`prune.lua:126-130`) |
| 5 | … | G17: bounded per call to avoid event-loop stall | PASS (`MAX_DELETES_PER_SWEEP=100`, `prune.lua:53,171-173`) |
| 5 | … | G18: throttled across blocks (`PRUNE_INTERVAL_BLOCKS`) | PASS (`prune.lua:47,161-164`) |
| 5 | … | G19: pcall'd delete failure does not poison sweep | PASS (`prune.lua:139-148`) but **BUG-8 (P1)** when CF.BLOCKS delete fails but CF.UNDO succeeds (or vice-versa), `prune_height` is still advanced — orphan-row pattern persists across restarts with no way to detect (cross-cite W147 atomicity hygiene). |
| 6 | Service-flag advertisement | G20: `NODE_NETWORK_LIMITED` set when prune is on | PASS (`p2p.lua:142-144`, `peer.lua:192`) |
| 6 | … | G21: `NODE_NETWORK` REMOVED when prune is on (Core init.cpp:863, 1947-1950: only ADDED when HistoricalChainstate==false) | **BUG-9 (P0-SEC)** lunarblock keeps `NODE_NETWORK` set ALWAYS (`p2p.lua:138`) even when prune > 0; comment-as-confession at `p2p.lua:120-123` documents the divergence ("we keep NODE_NETWORK set as well"). Peers will request historical blocks we cannot serve → notfound storms + reputation damage. |
| 6 | … | G22: `NODE_NETWORK_LIMITED` advertised even with `--prune=1` (RPC-only mode that never deletes) | PASS but problematic — the gate at `main.lua:1191` flips on any `args.prune > 0`, including the manual-only mode whose RPC is missing → node falsely claims to be pruned-network when it has FULL data. |
| 7 | Assumevalid 6-condition gate | G23: condition 1 — assumevalid configured | PASS (`consensus.lua:1547-1550`) |
| 7 | … | G24: condition 2 — hash in header index | PASS (`consensus.lua:1553-1555`) |
| 7 | … | G25: condition 3 — block ancestor of assumevalid | PASS (`consensus.lua:1557-1560`) |
| 7 | … | G26: condition 4 — block ancestor of best header | PASS (`consensus.lua:1562-1565`) |
| 7 | … | G27: condition 5 — best header chainwork >= MinimumChainWork | **BUG-10 (P0-CDIV)** compare uses `HeaderChain:get_chain_work()` (`sync.lua:1268-1291`) which converts a Lua double → 32 bytes byte-by-byte. At mainnet scale (~9.4e29) a double's 53-bit mantissa loses ALL bytes below position 25. mainnet `min_chain_work=…88430067bc7f9c1f8cc40b55` — the lower 7 bytes `f9c1f8cc40b55` cannot be represented; comparison is lossy in both directions. **`get_chain_work()` comment literally says "Approximate conversion … sufficient for comparison with min_chain_work"** (comment-as-confession 6th instance, after W143 ouroboros). |
| 7 | … | G28: condition 6 — GetBlockProofEquivalentTime > TWO_WEEKS | **BUG-11 (P1)** approximated as `best_header_height - block_height >= 2016` blocks (`consensus.lua:1576-1579`). Core uses *equivalent-work-time* via `GetBlockProofEquivalentTime`, which accounts for the actual hash-rate at the block's difficulty. Height-based approximation diverges materially in steep difficulty drops (e.g. mainnet difficulty crashes after exchange collapses); on testnet4 with min-difficulty mode it diverges by orders of magnitude. |
| 8 | `-assumevalid` operator override | G29: `-assumevalid=<hash>` CLI override | **BUG-12 (P0)** no `--assumevalid` arg recognized in `main.lua` parser. The hardcoded hash in `consensus.lua:931` is the ONLY value. Operators cannot upgrade past a stale default without re-editing source + rebuild. Core: `args.GetArg("-assumevalid", ...)`. |
| 8 | … | G30: `-assumevalid=0` disable (Core: `AssumedValidBlock().IsNull()` then `script_check_reason = "assumevalid=0 (always verify)"`) | **BUG-12 cross-cite** — no way to disable assumevalid short of source patch. |
| 9 | MinimumChainWork | G31: per-network values match Core | **BUG-13 (P0-CDIV)** stale + missing-network: mainnet `…88430067bc7f9c1f8cc40b55` is v27-era (Core current: `…01128750f82f4c366153a3a030`); testnet3 `…000100010001` placeholder (Core: `…17dde1c649f3708d14b6`); testnet4 ZEROS (Core: `…09a0fe15d0177d086304`); regtest 0 (correct); **signet network entirely absent**. Effect: low-work-chain anti-DoS (BIP-30 spoof primitive) is materially weakened. |
| 9 | … | G32: `IsInitialBlockDownload` gate uses MinimumChainWork to latch-out IBD | **BUG-14 (P1)** lunarblock has no `IsInitialBlockDownload()` equivalent; `getblockchaininfo.initialblockdownload` is computed as `tip-header timestamp > 24h` (`rpc.lua:1301-1309`) — Core uses tip-recent AND chainwork >= MinimumChainWork AND tip-age < max_tip_age. Pure age-based check means a node with a 25-hour-stale tip but full chain is reported as IBD; a node that just synced with low-work cannot exit IBD via the age path. |

---

## BUG-1 (P0) — `--prune=1` sentinel parsed but `pruneblockchain` RPC absent (dead-data plumbing)

**Severity:** P0. `--prune=1` is the documented Bitcoin Core sentinel for
"RPC-driven manual pruning only — never prune automatically." lunarblock
parses it (`main.lua:281-289`), records `manual_only=true`
(`prune.lua:70`), advertises `NODE_NETWORK_LIMITED` to peers
(`main.lua:1191` → `p2p.lua:142-144`), and `force_prune` exists in
`prune.lua:195-216` — but there is **no `pruneblockchain` RPC handler**
in `rpc.lua`. Operator runs `lunarblock --prune=1`, the node tells
peers it serves a limited window, refuses to actually delete anything,
and exposes no API to trigger deletion. Pure dead-data plumbing.

**File:** `prune.lua:67,70,90`, `prune.lua:188-216` (`force_prune`),
`rpc.lua` (no `self.methods["pruneblockchain"]` definition).

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp:908-965`
(`pruneblockchain` RPC).

**Excerpt (lunarblock comment that admits the gap)**
```lua
-- Mode flags. 0 = off, 1 = manual-only (RPC/pruneblockchain), >=550 = auto.
manual_only = target_mb == 1,
-- ...
-- manual_only: nothing to do here; pruneblockchain RPC drives it.
```

**Impact:**
- `--prune=1` operator-facing claim is a lie. The node looks like a
  limited-archive peer but actually retains every byte; peers that
  prefer NODE_NETWORK_LIMITED partners for IBD bootstrap will avoid us.
- Closes the prune fleet pattern: 9 of 10 impls have `pruneblockchain`
  RPC; lunarblock is the outlier. (cross-cite W138 chainstateManager-
  defined-but-unwired pattern; this is the same archetype at the RPC
  surface.)

---

## BUG-2 (P0) — No `-prune` × `-txindex` incompatibility check

**Severity:** P0. Core (`init.cpp:1001-1003`) hard-fails at startup:
> `return InitError(_("Prune mode is incompatible with -txindex."));`

lunarblock parses both flags independently (`main.lua:242-252` for
`--txindex`, `main.lua:274-289` for `--prune`); the txindex
maintenance writes into `CF.TX_INDEX` *while* the pruner deletes
the matching `CF.BLOCKS` row at the same height. `getrawtransaction`
now returns the (txid → blockhash) pointer but the block body is gone.

**File:** `main.lua:242-289` (parser), `main.lua:819-826` +
`utxo.lua:set_txindex_enabled` (no validation).

**Core ref:** `bitcoin-core/src/init.cpp:1001-1009`.

**Impact:**
- `getrawtransaction <txid>` returns pointer to block N; `getblock N`
  returns "Block not found" → txindex looks like it works but every
  pre-prune-window lookup leaks corrupted state.
- W2P pattern: this is the same shape as the W141 `--prune` ×
  `--txospenderindex` check in Core (which lunarblock also lacks but
  has no txospenderindex feature anyway).

---

## BUG-3 (P0) — No `-prune` × `-reindex-chainstate` incompatibility check

**Severity:** P0. Core (`init.cpp:1006-1008`) hard-fails:
> `"Prune mode is incompatible with -reindex-chainstate. Use full -reindex instead."`

lunarblock's startup sequence at `main.lua:915-942` runs
`chain_state:reindex_chainstate(reindex_target)` (which iterates every
height 1 → tip and calls `self.storage.get_block(block_hash)` at
`utxo.lua:1826`) BEFORE the pruner is constructed at `main.lua:949`.
But if a *previous* run already pruned heights, `get_block` returns nil
and reindex fails at the first hole with `"reindex: missing block body
for h=N"` (`utxo.lua:1827-1829`) — no explanatory error linking it
back to prune. Operator sees a cryptic failure and the only fix
documented is `--reindex` (the full variant), which lunarblock
silently downgrades to `--reindex-chainstate` again at `main.lua:906-909`.

**File:** `main.lua:906-942` (reindex path), `main.lua:949-959`
(pruner constructed after).

**Core ref:** `bitcoin-core/src/init.cpp:1006-1008`.

**Impact:**
- Wedge loop: prune mode partially deletes → restart with `--reindex-
  chainstate` → fails at first deleted height → user tries `--reindex`
  (per lunarblock docs) → lunarblock turns it into `--reindex-chainstate`
  → same failure. Only escape is wipe datadir.

---

## BUG-4 (P0) — `prune_height` not persisted; pruner forgets across restart

**Severity:** P0. `pruner.prune_height` is a plain field on the in-memory
table (`prune.lua:78`). There is no `storage.get_meta("prune_height")`
load on construction, no `storage.put_meta` on update, no entry in
`CF.META`. On restart the value is reset to 0; the pruner forgets that
heights 1…N have already been deleted.

**Consequences:**
1. `pruner:is_pruned(h)` returns false for already-deleted heights →
   `getblock <hash>` falls through to `INVALID_ADDRESS` "Block not
   found" (`rpc.lua:1446`) instead of `MISC_ERROR` "Block not available
   (pruned data)" (Core's wire-string parity contract — RPC clients
   distinguish "wrong hash" from "pruned").
2. `getblockchaininfo.pruneheight = pruner.prune_height + 1 = 1`
   (`rpc.lua:1357-1358`) — claims height 1 is the first stored block
   after every restart; explorers/electrs reading this think we have
   full archive.
3. The pruner re-evaluates `compute_prune_target` based on `tip - keep`;
   `target > prune_height` is now `target > 0` so the first sweep
   tries to delete heights 1…target → calls `_delete_block_at_height`
   for already-deleted blocks. `storage.get_hash_by_height(h)` STILL
   returns the hash (height index preserved), so the
   `storage.delete(CF.BLOCKS, hash.bytes, false)` call runs against
   keys that no longer exist (RocksDB no-op on missing key) — silently
   walks the entire prune window again on every restart.
4. The MAX_DELETES_PER_SWEEP=100 throttle + PRUNE_INTERVAL_BLOCKS=100
   means it takes `(N/100)*100 = N` blocks of tip advancement to
   re-prune the same already-deleted N heights → never catches up.

**File:** `prune.lua:74-82` (declaration only — no load/save), absent
in `main.lua:949-959` (constructor) and `prune.lua:174-178`
(no persist on update).

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:516-545,571-606`
— `m_blockfile_info` is written to `m_block_tree_db` (LevelDB) on
every prune sweep + on graceful shutdown via `Flush()`.

---

## BUG-5 (P1) — No `BlockStatus`/`HAVE_DATA`/`HAVE_UNDO` bitfield on the block index

**Severity:** P1. Core's CBlockIndex carries an `nStatus` bitfield with
the 5-level validity ladder (`VALID_TREE` → `VALID_SCRIPTS`) plus
`HAVE_DATA`/`HAVE_UNDO`/`FAILED_VALID`/`FAILED_CHILD`/`OPT_WITNESS`.
lunarblock's "block index" is just three column families
(`CF.HEADERS`, `CF.BLOCKS`, `CF.HEIGHT_INDEX`) with no per-block
status row at all (see `storage.lua:176-185`). Consequences:

- No way to mark a header as "received but body pending" — the
  storage-vs-no-storage distinction is binary, lookup-driven, has to
  hit RocksDB on every check.
- After prune, headers stay but bodies are gone — `HAVE_DATA` should
  be cleared; without that bit `getchaintips` / `getblockchaininfo`
  cannot report the first-available-block height (see BUG-4 #2).
- `FAILED_VALID` propagation to descendants on `InvalidateBlock` is
  impossible to express (cross-cite W148 BUG-9 same shape at blockbrew).
- BIP-152 compact-block code in `compact_block.lua` checks for body
  presence via storage lookup, not a bit-test — every cmpctblock
  message touches RocksDB.

**File:** `storage.lua:176-185` (CF list), `prune.lua` (no status
update on delete).

**Core ref:** `bitcoin-core/src/chain.h:42-86,131`.

---

## BUG-6 (P0) — `pruneblockchain` RPC handler does not exist

**Severity:** P0. Searched `src/rpc.lua` for `pruneblockchain` —
only references are in `src/prune.lua` comments referring to a
"future" handler. The RPC is enumerated by Core as a critical
operational tool for pruned nodes (see Core's `-prune=1` docs:
"This mode … enables the pruneblockchain RPC to be called").

**File:** `rpc.lua` (no `self.methods["pruneblockchain"]`).

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp:908-965`.

**Impact:**
- `--prune=1` is unusable (see BUG-1).
- Even with `--prune=550`, an operator with a sudden disk-pressure
  event has no way to force-prune to a specific height.
- Wallet rescans + chain-rewinds that need to free disk first
  (Core RPC pattern: `pruneblockchain` then `rescanblockchain`) are
  blocked.

---

## BUG-7 (P1) — `nPruneAfterHeight` floor entirely absent (regtest interop)

**Severity:** P1. Core's per-network `nPruneAfterHeight`
(`chainparams.cpp:122,240,340,482,565`) gates the first prune sweep:
mainnet doesn't prune until `tip > 100,000`; testnet/signet/testnet4
not until `tip > 1,000`; regtest not until `tip > 1,000` (or 100
under `-fastprune`). lunarblock's only height gate is
`tip < MIN_BLOCKS_TO_KEEP (288)` (`prune.lua:108-110`) — the moment
the chain crosses 289 + keep blocks, the sweep fires.

**File:** `prune.lua:108`, `consensus.lua:880-984` (per-network blocks
— no `nPruneAfterHeight` field at all).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:122,240,340,482,565`.

**Impact:**
- Regtest tests that mine 300 blocks then run `getblockchaininfo` see
  `pruneheight=12` (or similar) on lunarblock; on Core they see
  `pruneheight=0` because the floor isn't crossed. Test-suite parity
  with Core breaks for any test that asserts on `pruneheight`.
- Mainnet from-genesis IBD with `--prune=550`: lunarblock starts
  deleting at h=289+288 = 577; Core waits until 100,000. The
  observable IBD-window log timing diverges by ~99k blocks.

---

## BUG-8 (P1) — Partial-delete (BLOCKS succeeds, UNDO fails) advances `prune_height` anyway

**Severity:** P1 (data integrity, orphan rows). `_delete_block_at_height`
(`prune.lua:132-149`) pcalls BOTH the BLOCKS and UNDO deletes inside
ONE pcall. If `CF.BLOCKS` delete succeeds but `CF.UNDO` delete throws,
the pcall catches the second failure, logs "delete failed at h=N",
but `prune_height` is still advanced one loop iteration later
(`prune.lua:175-178`). The orphan UNDO row at that height persists
forever (no GC sweep, no second-chance retry).

Worse: the inverse case (UNDO succeeds, BLOCKS fails) leaves a block
body whose undo data is gone — if a reorg later disconnects that
height, `disconnect_block` will fail with no undo, and the chain
wedges.

**File:** `prune.lua:139-148,170-178`.

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:804-845`
(`UnlinkPrunedFiles` — atomic at the file-system level via two
`fs::remove` calls; failure of one doesn't advance the prune cursor
for the other).

**Impact:**
- Eventual file-system litter; on-disk usage diverges from
  `pruner.prune_height`-reported space saving.
- Reorg-path wedge if BLOCKS delete fails on a depth that's later
  reorged through (small probability but unbounded fault-tolerance gap).

---

## BUG-9 (P0-SEC) — `NODE_NETWORK` still advertised when prune is enabled (peer-deception)

**Severity:** P0-SEC. Core's `g_local_services` defaults to
`NODE_NETWORK_LIMITED | NODE_WITNESS` (init.cpp:863); `NODE_NETWORK`
is ADDED iff `HistoricalChainstate() == false`, i.e., we have the
*full* chain. When prune is enabled, `HistoricalChainstate()` returns
true and `NODE_NETWORK` is never added. lunarblock's `our_services`
(`p2p.lua:136-153`) unconditionally `bit.bor`s `NODE_NETWORK`:

```lua
local s = bit.bor(M.SERVICES.NODE_NETWORK, M.SERVICES.NODE_WITNESS)
-- ...
if prune_mode then
  s = bit.bor(s, M.SERVICES.NODE_NETWORK_LIMITED)
end
```

Comment at `p2p.lua:120-123` literally documents the deviation:
> "Core advertises NODE_NETWORK alongside NODE_NETWORK_LIMITED in the
> auto-prune case (the node still has the recent-288 window), so we
> keep NODE_NETWORK set as well."

This claim is wrong. Core does NOT advertise NODE_NETWORK when prune
is on. **Comment-as-confession 7th instance** (cross-cite W143 lunarblock
BUG-12, W141 nimrod, W128 banman 8/10 fleet pattern).

**File:** `p2p.lua:136-153`, claim at `p2p.lua:120-123`.

**Core ref:** `bitcoin-core/src/init.cpp:863,1947-1953`.

**Impact:**
- A pruned lunarblock node tells peers it serves the FULL chain.
  Peers request historical blocks at random heights, get `notfound`
  for everything below the prune window → ban-score on us in Core
  peers (Core: `MaybePunishNodeForBlock` for repeated `notfound`).
- Peer selection bias: bootstrap peers prefer NODE_NETWORK; pruned
  lunarblock claims the bit, gets selected for IBD bootstrap by
  fresh-install peers, then fails to serve every request below 288.

---

## BUG-10 (P0-CDIV) — `HeaderChain:get_chain_work()` lossy float→bytes (assumevalid + IBD anti-DoS broken)

**Severity:** P0-CDIV. `HeaderChain:get_chain_work()` (`sync.lua:1268-1291`)
takes `entry.total_work` (a Lua double, 53-bit mantissa) and packs it
into 32 bytes via repeated `floor(remaining / 256)`. Mainnet chainwork
at h=938,343 is approximately `9.4 × 10^29`; a double cannot represent
values above ~9 × 10^15 with byte-level precision. The lower ~14 bytes
of the resulting 32-byte string are stuck at zero (or worse — drift).

The comment **literally says** "Approximate conversion (sufficient for
comparison with min_chain_work)" — this is FALSE for any non-trivial
chain. `consensus.should_skip_script_validation` (`consensus.lua:1568-1571`)
compares this lossy value against `network.min_chain_work` which
encodes precision down to byte 7. Comparison can flip in either
direction depending on rounding.

This is **comment-as-confession 7th distinct instance** (W76+ tracking;
previous: rustoshi W141, lunarblock W143 BUG-12, ouroboros W143, plus
3 prior).

**File:** `sync.lua:1268-1291` (impl), `consensus.lua:1568-1571`
(consumer), `consensus.lua:927` (mainnet `min_chain_work` with
byte-7 precision the float can't carry).

**Core ref:** `bitcoin-core/src/arith_uint256.h` — Core uses
`arith_uint256` (full 256-bit big-int) for `nChainWork`.

**Impact:**
- `should_skip_script_validation` condition 5 (best-header chainwork
  >= MinimumChainWork) can WRONGLY return false → script validation
  fires for blocks Core would skip → IBD throughput regression of
  the same magnitude as removing assumevalid altogether.
- Worse: it can WRONGLY return true → on a mid-IBD low-work attack
  (e.g. attacker feeds 100k low-difficulty headers from a fork point),
  the lossy comparator may declare best_header_work >= min_chain_work
  when it actually isn't → script-skip path activates on a chain that
  shouldn't be trusted.
- `sync.lua:1258-1263` (`is_below_min_chain_work`) and lines
  1336-1340 (`try_low_work_sync`) consume the same broken
  `get_chain_work()` → headers-first anti-DoS PRESYNC threshold
  triggers nondeterministically.

---

## BUG-11 (P1) — Assumevalid condition 6 uses height-gap approximation

**Severity:** P1. Core uses `GetBlockProofEquivalentTime` (an
equivalent-work-time conversion that accounts for the block's actual
difficulty vs the chain's current hash rate) and compares against
TWO_WEEKS_IN_SECONDS (`validation.cpp:2364`). lunarblock approximates:

```lua
local TWO_WEEKS_BLOCKS = 2016  -- ~2 weeks at 10 min/block
if best_header_height - block_height < TWO_WEEKS_BLOCKS then
  return false, "block too recent relative to best header"
end
```

The approximation diverges materially on:
- testnet4 with `pow_allow_min_difficulty=true`: a low-difficulty
  patch can fit 5x more blocks per 2-week wall time → block-count
  approximation OVER-counts elapsed time → unlocks skip too early.
- mainnet difficulty crashes (e.g. post-event hash-rate drops):
  2016 blocks may span 6 weeks of wall-clock → approximation
  UNDER-counts → keeps skip locked when Core would unlock.

**File:** `consensus.lua:1573-1579` (impl + docstring admitting
the divergence).

**Core ref:** `bitcoin-core/src/validation.cpp:2364`.

---

## BUG-12 (P0) — No `-assumevalid` CLI/RPC override

**Severity:** P0. Core supports `args.GetArg("-assumevalid", default_av)`:
operators can override the compiled-in default per-run, OR pass
`-assumevalid=0` to disable. lunarblock's `main.lua:14-78` `default_args()`
table has no `assumevalid` field; no parser arm at `main.lua:80-380`
recognizes `--assumevalid`. The hash in `consensus.lua:931` is the
only knob and requires a source patch + rebuild.

**File:** `main.lua:14-380` (parser), `consensus.lua:931` (hardcoded).

**Core ref:** `bitcoin-core/src/validation.cpp:2347` ("assumevalid=0
(always verify)" reason string), `bitcoin-core/src/init.cpp` arg parse.

**Impact:**
- Stale default at `consensus.lua:931` (h=938,343 from Core v28);
  current Core v29 default is much higher. Without override, lunarblock
  operators are stuck with v28-era skip range until the next lunarblock
  release.
- Reproducibility — security researchers cannot run a from-genesis
  full-script-verify IBD on lunarblock to validate consensus
  (Core: `-assumevalid=0`).

---

## BUG-13 (P0-CDIV) — `min_chain_work` stale on mainnet, placeholder on testnet3, ZERO on testnet4, no signet

**Severity:** P0-CDIV. Per-network `min_chain_work`
(`consensus.lua:927,1044,1116,1177`) vs Core
(`chainparams.cpp:109,232,332,423,557`):

| Network | lunarblock | Core (current) |
|---------|-----------|----------------|
| mainnet | `…88430067bc7f9c1f8cc40b55` (v27 era) | `…01128750f82f4c366153a3a030` (v29) |
| testnet3 | `…000100010001` (placeholder) | `…17dde1c649f3708d14b6` |
| testnet4 | `0000…0000` (entirely zero) | `…09a0fe15d0177d086304` |
| signet | (network absent) | `…0b463ea0a4b8` |
| regtest | `0000…0000` | `uint256{}` ✓ |

**File:** `consensus.lua:927,1044,1116,1177` (values), no signet
network entry.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:109,232,332,423,557`.

**Impact:**
- mainnet: a low-work-chain DoS bounded by Core's v29 threshold is
  bounded much higher by lunarblock's v27 threshold. Attacker can
  feed a much longer fake chain before headers-first PRESYNC trips
  the min-work gate.
- testnet3: `…000100010001` is approximately 2^32 — well below any
  realistic testnet3 chain — so the gate effectively never fires
  on testnet3. lunarblock is wide-open to header-spam on testnet3.
- testnet4: ZERO chainwork threshold → every header chain ≥ genesis
  passes the min-work gate → lunarblock testnet4 nodes accept any
  fake chain that exceeds 1 work unit. Severely undermines the
  testnet4 BIP-94 anti-DoS design.
- signet: lunarblock cannot even attempt signet — no chainparams
  entry. Fleet-wide signet coverage: not reportable.

---

## BUG-14 (P1) — `IsInitialBlockDownload` substituted by 24h-age heuristic only

**Severity:** P1. Core's `IsInitialBlockDownload` (validation.cpp:1940-1942)
latches false when `IsTipRecent(MinimumChainWork(), max_tip_age)`:
- `m_cached_is_ibd` once false stays false
- transitions require BOTH tip-recent (timestamp within `max_tip_age`)
  AND `nChainWork >= MinimumChainWork`

lunarblock's `getblockchaininfo` (`rpc.lua:1301-1309`) computes IBD as:
```lua
local age = os.time() - header.timestamp
initial_block_download = age > 24 * 60 * 60
```

No chainwork comparison, no latch, no max_tip_age (Core: 24h by default
but is a per-network param). The same 24h cutoff fires every time the
RPC is called, so a node can flip back to IBD if the tip ages out.

**File:** `rpc.lua:1301-1309`.

**Core ref:** `bitcoin-core/src/validation.cpp:1940-1942,3283-3291`.

**Impact:**
- Wallet rescans, getblocktemplate, peer-relay all gate on IBD; a
  flapping `initialblockdownload` flag in `getblockchaininfo` causes
  miners/wallets to misbehave (rescan loops, GBT stalls).
- A low-work chain can latch us OUT of IBD if it has a recent
  timestamp (no chainwork check).

---

## BUG-15 (P0) — `reindex_chainstate` hardcodes `skip_script_validation=true` and bypasses `check_block`

**Severity:** P0 (cross-cite W143 BUG-3 — same pattern, different
entry-point). `ChainState:reindex_chainstate` (`utxo.lua:1820-1849`)
loops `for height = 1, header_tip_height do` and calls
`self:connect_block(block, height, block_hash, nil, nil, true, nil, true, nil)`
directly — `true` at position 6 is `skip_script_validation`, hardcoded
ON regardless of `network.assumevalid` configuration.

Additionally:
- The call goes through `connect_block` (NOT `accept_block`) → skips
  Stage 1 `validation.check_block` → no merkle root recompute (CVE-2012-2459
  malleation guard), no witness commitment recompute, no block size cap,
  no first-coinbase / second-coinbase check, no per-tx
  `validation.check_transaction`, no BIP-34 byte-prefix check.
- `prev_block_mtp` and `get_block_mtp` are both nil → BIP-113 IsFinalTx
  uses block timestamp (correct only pre-CSV); BIP-68 time-based
  sequence locks are silently disabled (`utxo.lua:2189-2192` falls
  back to `block.header.timestamp` when MTP is nil).

This is the **third distinct production entry-point in lunarblock that
bypasses the unified consensus pipeline** (cross-cite W143 BUG-3 reorg
loop, plus the original `connect_block`-called-with-nil-MTP path that
fix wave 35 partially repaired). Now reindex is added: "three-pipeline
drift" pattern (cross-cite W143 ouroboros — first observed at ouroboros,
now repeated in lunarblock).

**File:** `utxo.lua:1835-1836`.

**Core ref:** `bitcoin-core/src/validation.cpp:5300+` — Core's reindex
path (`LoadExternalBlockFile` + `ActivateBestChain` + `ConnectBlock`)
runs the FULL validation pipeline (only skipping signature verification
under `-assumevalid`, NOT skipping `CheckBlock` / merkle / BIP-113 /
BIP-68).

**Impact:**
- A regtest reindex (where `network.assumevalid = nil`) silently skips
  script verification → a mutated/invalid-script block planted in
  CF.BLOCKS would be re-accepted as valid into the chainstate.
- CVE-2012-2459 mutated-merkle attack against a checkpointed but
  pre-prune-window block range is silently re-accepted on reindex.
- CSV/BIP-68 time-based locks on >h=419328 mainnet blocks are not
  re-evaluated during reindex → if the original IBD path had a bug
  in MTP computation, the reindex would not catch it.

---

## BUG-16 (P1) — Side-branch reorg `connect_block` bypass same shape as reindex

**Severity:** P1 (carry-forward verification of W143 BUG-3, with
additional context found in this audit). `accept_side_branch_block`
calls `self:connect_block(sb_block, entry.height, entry.hash, nil, nil,
opts.skip_scripts, false, opts.nosync, store_batch_fn, reorg_batch)`
(`utxo.lua:3490-3496`) — same pattern as BUG-15:

- No `check_block` (Stage 1 bypassed).
- `prev_block_mtp` and `get_block_mtp` both nil → BIP-113 + BIP-68
  silently disabled.
- Comment-as-confession at `utxo.lua:3486-3489`: "the original-acceptance
  path already validated these for B1/B2/B3, and CSV is not active in
  the regtest reorg corpus" — assumes future reorg-test corpora will
  not hit CSV blocks. Mainnet reorg at >h=419328 DOES hit CSV.

This is W143 BUG-3 still open. Documented here because the test corpus
"regtest reorg" justification rings hollow when the same code runs on
mainnet reorgs.

**File:** `utxo.lua:3486-3496`.

**Core ref:** `bitcoin-core/src/validation.cpp:2900-3000` —
`ConnectTip` always reads the block from disk and calls
`m_chainman.ConnectBlock(...)` with full MTP context.

---

## BUG-17 (P1) — Pruner ignores `pruner.enabled` in `force_prune` when `--prune=1`

**Severity:** P1. `force_prune` (`prune.lua:195-216`) gates on
`self.enabled` (`enabled = target_mb > 0`, so `--prune=1` qualifies).
But `target_blocks_to_keep` returns `math.huge` for `manual_only`
mode (`prune.lua:88-92`), and `compute_prune_target` returns nil
for `not self.automatic` (`prune.lua:107`). The `up_to` caller-
specified path proceeds, but the fallback `target = self:
compute_prune_target(tip_height)` returns nil → `if not target` →
early return → `force_prune` is a no-op when `up_to` is nil even
under `--prune=1`.

This is dead-code at function-defaults level. The intended
operator-facing behaviour ("call `force_prune(tip_height)` with no
target to mean 'prune as much as possible under manual_only mode'")
silently no-ops because `compute_prune_target` only honours
`automatic`.

**File:** `prune.lua:88-92,107,195-206`.

---

## BUG-18 (P1) — `get_block` pruned-data branch is O(prune_height) iterator walk

**Severity:** P1 (performance, observable). `getblock` (`rpc.lua:1418-1444`)
on a not-found body falls through to:
```lua
local iter = rpc.storage.iterator("height")
iter.seek_to_first()
while iter.valid() do
  local v = iter.value()
  if v and #v == 32 and v == hash.bytes then
    ...
  end
  iter.next()
end
```

For every "block not available (pruned data)" check, the handler
iterates the ENTIRE `CF.HEIGHT_INDEX` from genesis. On mainnet that's
~944k entries per call. An attacker can `getblock <random-fake-hash>`
in a loop to OOM/CPU-pin the node (the iterator allocates a snapshot,
holds it open while iterating ~944k times).

**File:** `rpc.lua:1421-1438`.

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp:677` — Core has
O(1) lookup via `pblockindex->nStatus & BLOCK_HAVE_DATA`.

**Impact:**
- Trivial RPC-DoS surface; one curl loop pins a node.
- Cross-cite W148 — same shape as a O(h) lookup ill-advised in the
  RPC fast path.

---

## BUG-19 (P1) — `getblockchaininfo.pruneheight` reports `prune_height+1` from in-memory state (lies after restart)

**Severity:** P1 (operator-visible wrong data). `getblockchaininfo`
(`rpc.lua:1356-1359`) returns:
```lua
result.pruneheight = pruner.prune_height > 0
  and (pruner.prune_height + 1) or 0
```

Combined with BUG-4 (no persistence), after a restart `prune_height=0`
unconditionally → `pruneheight=0` is reported even though blocks are
actually missing on disk. Explorers, wallets, the test-suite
`utxo_compare.py`, all consume this field. Cross-cite BUG-4.

**File:** `rpc.lua:1356-1359`.

---

## BUG-20 (P1) — `dumptxoutset` prune check uses same volatile `prune_height`

**Severity:** P1. `dumptxoutset` (`rpc.lua:7658-7678`) refuses to dump
below `prune_height`:
```lua
if target_height ~= nil and rpc.pruner and rpc.pruner.enabled
   and rpc.pruner.prune_height > 0
   and target_height <= rpc.pruner.prune_height then
  -- error: "Block height N not available (pruned data)..."
```

Same bug as BUG-19 — after restart, `prune_height=0` so the check
ALWAYS passes, and the dump proceeds reading deleted blocks. Then
mid-rewind, `rollback_chain_to` (`rpc.lua:7704`) fails when it tries
to read a block body that's actually gone — fatal mid-rewind, node
is left at an intermediate height with `block_submission_paused=true`
until the pcall finally clears it.

**File:** `rpc.lua:7658-7678,7700-7720`.

---

## BUG-21 (P1) — `MAX_REORG_DEPTH=100` floor is unusably low for cross-prune-boundary recovery

**Severity:** P1 (correctness in edge case). `accept_side_branch_block`
caps reorg depth at 100 (`utxo.lua:3224,3252,3277`). When pruning is
enabled and `target_blocks_to_keep` < 100 + MIN_BLOCKS_TO_KEEP, a
reorg deep enough to be valid (Core: no max-reorg cap; only
MIN_BLOCKS_TO_KEEP governs prune-protection) will fail with
"reorg-depth-exceeded" AND/OR fail with "side-branch-header-gap" if
the side-branch parent has been pruned.

Cross-cite W148 BUG-5 (blockbrew has the same `MaxReorgDepth=100`
constant divergence from Core; this is now a fleet-wide pattern of at
least 2 impls).

**File:** `utxo.lua:3224,3252-3274`.

**Core ref:** Core has no MAX_REORG_DEPTH; only the implicit prune
window protects.

---

## BUG-22 (P1) — Reject-string wire-parity: "Block not found" vs "Block not available (pruned data)"

**Severity:** P1 (RPC client distinction). `getblock` returns
`INVALID_ADDRESS` "Block not found" when CF.BLOCKS has no body. Core
distinguishes:
- `RPC_INVALID_ADDRESS_OR_KEY` "Block not found" — when the hash is
  unknown to the header index.
- `RPC_MISC_ERROR` "Block not available (pruned data)" — when the
  header is known but body was pruned.

lunarblock attempts the distinction (`rpc.lua:1413-1446`) but only
when `pruner.enabled` is true. Combined with BUG-4 (no persistence),
after restart `pruner.enabled=true` but `prune_height=0` so
`is_pruned(found_height)` returns false → falls through to
"Block not found" for a body that is actually pruned. RPC clients
(electrs, mempool.space, fulcrum) special-case the two strings —
returning the wrong one breaks the partial-archive cache eviction
logic.

Cross-cite W125 lunarblock reject-string sweep (was 9 tokens; this is
the 10th distinct gap).

**File:** `rpc.lua:1413-1446`.

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp:677`.

---

## BUG-23 (P1) — LuaJIT assert-as-validation pattern in `connect_block` script-check skip path

**Severity:** P1 (DoS surface). Same shape as W142 BUG-24
(LuaJIT `assert()` used for consensus validation aborts the entire
VM on failure rather than returning a wire-parity reject string).
`utxo.lua:2390-2403` uses `assert(...)` for COINBASE_MATURITY
check and per-input amount MoneyRange check INSIDE `connect_block`
— but these run UNCONDITIONALLY regardless of `skip_script_validation`.

An attacker who can submit a block (via submitblock RPC) with a coinbase
spend at depth < 100 or an out-of-range input value causes an `assert
failed` that propagates up via `error()` at `main.lua:1032` and is
caught by the outer pcall in `connect_pending_blocks`. BUT the
error message includes a Lua-style filename:line: header (the
`assert` failure path) — not the Core wire-string format. Same
shape as the W142 BUG-24 finding.

W145 BUG-7 (HALVING_INTERVAL=210000 fleet) also hits this — when
subsidy validation fails on regtest with a wrong-network halving,
the assert path leaks "validation.lua:220:" into the reject reason.

**File:** `utxo.lua:2390-2403`.

**Cross-cite:** W142 BUG-24, W145 BUG-12.

---

## BUG-24 (P2) — `compute_prune_target` does not consult disk usage; pure block-count heuristic

**Severity:** P2 (documented + acknowledged). The pruner's
`AVG_BLOCK_SIZE = 1.5MB` constant (`prune.lua:41`) is used to translate
`target_mb` → `target_blocks_to_keep`. Core uses
`GetApproximateSizes` on the actual blk*.dat files; pruning is
size-driven, not block-driven.

The TODO at `prune.lua:19-22` documents this:
> "TODO(prune-size): Replace the block-count translation with a real
> size-driven sweep once storage.lua exposes rocksdb_approximate_sizes_cf
> or a periodic CalculateCurrentUsage."

For an operator who sets `--prune=550` (the documented minimum):
- 550 MB / 1.5 MB = 366 blocks kept
- 366 blocks @ 1.5 MB *average* but the empty-2010 blocks were ~200B
  each, the modern blocks are ~2 MB each → actual disk usage drifts
  from advertised target by orders of magnitude depending on chain
  range.

Cross-cite the "comment-as-confession" pattern; this one is honest
about being a TODO and is P2.

**File:** `prune.lua:39-41,84-99`, TODO at `prune.lua:19-22`.

---

## BUG-25 (P1) — No `signet` network at all

**Severity:** P1 (coverage). `consensus.lua:880-1195` enumerates
mainnet/testnet3/testnet4/regtest. No `M.networks.signet`. Core
supports signet (BIP-325) as a first-class network with its own
genesis, magic, ports, challenge script, and chainparams. lunarblock
cannot run on signet at all — `--network signet` would return nil
from `M.get_network("signet")` (`consensus.lua:1198`).

**File:** `consensus.lua:880-1199`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:380-450`
(signet section).

**Impact:**
- Closes fleet signet coverage: most other impls audited support
  signet; lunarblock is the outlier.
- BIP-325 SIGNET_BLOCK_CHALLENGE handling (separate witness commitment
  scheme) is entirely absent.

---

## BUG-26 (P1) — Pruner sees no `nPruneAfterHeight` per-network override; same constants on all networks

**Severity:** P1. Even ignoring BUG-7's "absent floor," the per-network
constants in lunarblock's pruner are GLOBAL (module-level):
`MIN_BLOCKS_TO_KEEP=288`, `AVG_BLOCK_SIZE=1.5MB`,
`PRUNE_INTERVAL_BLOCKS=100`, `MAX_DELETES_PER_SWEEP=100`. Core
parameterizes the prune behaviour off `nPruneAfterHeight` per
chainparams entry. lunarblock cannot tune these per-network without
editing `prune.lua`.

**File:** `prune.lua:34-53`.

---

## Fleet patterns confirmed/extended in this audit

1. **Dead-data plumbing** — `--prune=1` sentinel + `manual_only` flag
   + `force_prune` impl, BUT `pruneblockchain` RPC missing (BUG-1, BUG-6).
   Cross-cite W138 (ChainstateManager defined-but-unwired in 9 of 10
   impls); W144 ouroboros (BIP9 plumbed but never set TAPROOT).
2. **Comment-as-confession** (7th-9th distinct instances this wave):
   - BUG-9: `p2p.lua:120-123` claims Core advertises NODE_NETWORK with
     prune; Core does not.
   - BUG-10: `sync.lua:1278` "Approximate conversion (sufficient for
     comparison with min_chain_work)" — the comparison is NOT sufficient.
   - BUG-16: `utxo.lua:3486-3489` "CSV is not active in the regtest
     reorg corpus" — true for the test corpus, false for mainnet
     reorgs >h=419328.
3. **Three-pipeline drift** (was first observed W143 ouroboros, now
   extended to lunarblock) — BUG-15 + BUG-16 + the original
   `accept_block` path = three production entry-points into the
   block-validation surface, two of which bypass `check_block`.
4. **Two-pipeline guard** (16th distinct extension) — `main.lua`
   reindex path vs `utxo.lua` reindex implementation diverge in
   bookkeeping (BUG-3 — reindex_chainstate runs BEFORE pruner init).
5. **Reject-string wire-parity slippage** (cross-cite W125 — 10th
   token; BUG-22). "Block not found" vs "Block not available (pruned
   data)" misrouted after restart.
6. **LuaJIT assert-as-validation** (W142 BUG-24 pattern, 4th distinct
   carrier in lunarblock) — BUG-23.
7. **Hardcoded constants that should be params-aware** —
   `nPruneAfterHeight` absent (BUG-7), `MAX_REORG_DEPTH` not params
   (BUG-21), prune tunables module-level (BUG-26).
8. **"30-of-30-gates-buggy" signal** — 32 sub-gates audited, 26 found
   buggy (P0-P2). The pruning + assumevalid + minimumchainwork
   subsystem is a subsystem-rewrite candidate, joining W138 clearbit /
   W139 lunarblock / W141 clearbit as the 4th instance fleet-wide.
   Particular suspect modules: `prune.lua` (no persistence, dead-data
   sentinel, no `pruneblockchain` RPC, no incompat checks at init),
   `consensus.should_skip_script_validation` (lossy float comparison
   in critical gate), per-network chainparams (stale + missing signet).

---

## Top 3 priority fixes

1. **BUG-10 (P0-CDIV)** — `HeaderChain:get_chain_work()` lossy float
   → bytes. Single-source-of-truth break for the assumevalid gate
   AND headers-first PRESYNC min-work gate. Fix: track chainwork as
   32-byte big-endian throughout (already present in `consensus.work_
   add` / `consensus.work_compare`); pipe through `HeaderChain` entry
   instead of `entry.total_work` float. ~30 LOC across sync.lua.
2. **BUG-4 (P0)** — `prune_height` persistence to `CF.META`.
   Single-row, single-line per save, single-line per load. Without it
   BUG-19, BUG-20, BUG-22 all leak. ~10 LOC across prune.lua + main.lua.
3. **BUG-13 (P0-CDIV)** — Refresh `min_chain_work` values to current
   Core; add signet network entry. ~5 minutes of typing; closes
   testnet4 wide-open + signet coverage gap.

(Honorable mentions: BUG-1 `pruneblockchain` RPC handler — ~40 LOC,
restores `--prune=1` operator promise; BUG-15 reindex_chainstate
route through `accept_block` — cross-cite W143 BUG-3.)
