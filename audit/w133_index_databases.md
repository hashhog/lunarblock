# W133 — Index databases (txindex + coinstatsindex) audit (lunarblock)

**Date:** 2026-05-17
**Wave:** W133 (discovery)
**Impl:** lunarblock (Lua / LuaJIT)
**Status:** **23 BUGS FOUND** (3 P0 / 11 P1 / 8 P2 / 1 P3) across **30 gates**
**Scope:** txindex (`-txindex`, getrawtransaction by txid),
coinstatsindex (`-coinstatsindex`, gettxoutsetinfo with `hash_type=muhash`),
BaseIndex sync infrastructure (CBlockLocator, BlockConnected/Disconnected
hooks, BlockUntilSyncedToCurrentChain, prune locks).
**Excludes:** blockfilterindex (W121).

## Context

Audits lunarblock's index subsystem against Bitcoin Core's
`src/index/base.{cpp,h}` + `src/index/txindex.{cpp,h}` +
`src/index/coinstatsindex.{cpp,h}` + `src/index/disktxpos.h` +
`src/index/db_key.h`. The lunarblock surface is split across:

- `src/utxo.lua` — Pattern C0 (2026-05-06) inline txindex maintenance
  inside `connect_block`/`disconnect_block` (the LIVE path).
- `src/txindex.lua` — a separate `M.new(db, enabled)` factory exposing
  `put_tx`/`lookup_tx`/`build_async` etc., with a different value
  layout (file_num/block_pos/tx_offset). **NEVER required by main.lua
  or any production code path; only by `spec/txindex_spec.lua` and
  `src/indexmanager.lua`.** Dead-code.
- `src/indexmanager.lua` — coordinator that would tick the
  txindex/blockfilter coroutines. **NEVER required by main.lua, sync.lua,
  or utxo.lua; only by `spec/indexmanager_spec.lua`.** Dead-code.
- `src/utxo.lua` — `ChainState:compute_utxo_hash()` full-iterator
  UTXO scan that powers `gettxoutsetinfo hash_serialized_3`. No
  coinstatsindex / no MuHash incremental state.

The crux of W133 is: the LIVE txindex (Pattern C0) is functionally
correct on the happy path (write on connect, delete on disconnect),
but its surrounding BaseIndex infrastructure — block-locator
persistence, sync-progress tracking, BlockUntilSyncedToCurrentChain,
prune-lock coordination, getindexinfo RPC, on-restart catch-up —
is entirely absent. Coinstatsindex is **completely absent**;
gettxoutsetinfo synthesises its `hash_serialized_3` from a full
iterator scan on every call. There is no MuHash incremental state,
no per-block DBVal record, no LookUpStats by block_index.

> References:
> - `bitcoin-core/src/index/base.{cpp,h}` — BaseIndex lifecycle,
>   Sync(), Commit(), Rewind(), BlockConnected hook,
>   ChainStateFlushed, BlockUntilSyncedToCurrentChain, SetBestBlockIndex
>   (prune locks).
> - `bitcoin-core/src/index/txindex.{cpp,h}` — CustomAppend writes
>   `(txid → CDiskTxPos)`; FindTx reads block via OpenBlockFile and
>   verifies header.GetHash().
> - `bitcoin-core/src/index/coinstatsindex.{cpp,h}` — CustomAppend
>   maintains MuHash3072 + per-block DBVal (output count, bogo size,
>   subsidy, prevout_spent, new_outputs, coinbase, unspendables×4);
>   CustomRemove rolls back via undo data; LookUpStats keyed by
>   (block_hash, height); CustomCommit writes DB_MUHASH atomically
>   with DB_BEST_BLOCK.
> - `bitcoin-core/src/index/disktxpos.h` — CDiskTxPos = FlatFilePos +
>   nTxOffset (VARINT, serialised inside the tx-position record).
> - `bitcoin-core/src/index/db_key.h` — DBHeightKey (big-endian, 'B' /
>   'H' prefixes), DBHashKey, CopyHeightIndexToHashIndex (preserves
>   stale-chain entries across reorgs), LookUpOne.

## Method

1. Read Core refs end-to-end (base 505 LOC, txindex 121 LOC,
   coinstatsindex 404 LOC, disktxpos 27 LOC, db_key 117 LOC).
2. Inventory lunarblock's index surface:
   - `src/utxo.lua:1554-1623` — `txindex_enabled` flag, set toggles.
   - `src/utxo.lua:2296-2308, 2860-2964` — connect_block Pattern C0
     write path.
   - `src/utxo.lua:3572-3747` — disconnect_block Pattern C0 delete
     path.
   - `src/utxo.lua:4180-4269` — `compute_utxo_hash` (gettxoutsetinfo
     backend).
   - `src/rpc.lua:2059-2380` — getrawtransaction txindex reader.
   - `src/rpc.lua:8024-8098` — gettxoutsetinfo handler.
   - `src/storage.lua:160-186` — CF.TX_INDEX column-family schema.
   - `src/main.lua:119-127, 240-256, 819-839` — CLI parsing for
     `--txindex` + `--blockfilterindex` (no `--coinstatsindex`).
   - `src/indexmanager.lua` and `src/txindex.lua` — dead code (the
     "official" factory that's never plumbed into main.lua).
3. Synthesize a 30-gate matrix.
4. Catalogue divergences as BUG-N with file:line + Core reference.
5. Land xfail tests in `tests/test_w133_index_databases.lua`
   exercising each bug pre-fix.

## Severity scoring

- **P0** — Correctness divergence visible at the RPC surface, or
  data loss on restart, or operator cannot enable / discover index
  state.
- **P1** — Missing operational primitive (getindexinfo, locator,
  BlockUntilSynced) that's required for safe production use of the
  index, or stale-chain reorg key not preserved.
- **P2** — Performance regression vs Core (full-iterator scan instead
  of cached per-block snapshot, missing async background sync).
- **P3** — Cosmetic / docs / dead-code stale comments.

## 30 W133 Audit Gates

| Gate | Description | Status | Core ref |
|------|-------------|--------|----------|
| G1   | `-txindex` CLI flag accepted; default off | PRESENT | txindex.h:19, main.lua:240-256 |
| G2   | `-coinstatsindex` CLI flag accepted; default off | **MISSING** (BUG-1 P0) | coinstatsindex.h:25 |
| G3   | txindex CustomAppend: write `(txid → CDiskTxPos)` for every non-genesis tx | **DIVERGENT** (BUG-2 P1) — value is `(block_hash 32B ‖ height 4B LE)` not CDiskTxPos | txindex.cpp:74-89 |
| G4   | txindex skips genesis block tx (height==0 returns true) | **MISSING** (BUG-3 P1) — connect_block short-circuits at `genesis_hash` BEFORE Pattern C0 writes; net effect: genesis-coinbase never indexed (OK), but `connect_genesis()` path also skips index entirely | txindex.cpp:77 |
| G5   | Atomic CustomAppend + WriteBatch (per-block) | PRESENT (utxo.lua:2930-2974 atomic batch) | txindex.cpp:60-66 |
| G6   | CustomRemove on disconnect (symmetrical with CustomAppend) | PRESENT (utxo.lua:3743-3747 atomic delete) | base.cpp:290-326 Rewind |
| G7   | BaseIndex DB_BEST_BLOCK locator written on every Commit | **MISSING** (BUG-4 P0) — Pattern C0 never writes a txindex-specific locator; only `CF.META["chain_tip"]` is shared with the chainstate | base.cpp:90-93, 270-288 |
| G8   | BaseIndex Init() reads locator and rewinds to fork point on restart | **MISSING** (BUG-5 P1) | base.cpp:104-148 |
| G9   | BaseIndex Sync() background-thread catch-up loop | **MISSING** (BUG-6 P2) — `indexmanager.lua:start_building` exists but is never called; production has no async sync, only inline-on-connect | base.cpp:201-268 |
| G10  | BaseIndex BlockUntilSyncedToCurrentChain (RPC dependency) | **MISSING** (BUG-7 P1) | base.cpp:424-446 |
| G11  | BaseIndex GetSummary (name, synced, best_block_height, best_block_hash) | **MISSING** (BUG-8 P1) — no per-index summary; no `getindexinfo` RPC | base.cpp:472-485 |
| G12  | `getindexinfo` RPC | **MISSING** (BUG-9 P1) | rpc/blockchain.cpp::getindexinfo |
| G13  | TxIndex::FindTx looks up via CDiskTxPos + OpenBlockFile + txid verify | **DIVERGENT** (BUG-10 P1) — `getrawtransaction` reads first 32B as block_hash, fetches whole block, linear-scans transactions for matching txid | txindex.cpp:93-120 |
| G14  | tx-index value carries enough info to skip block load (i.e., a block-internal offset like nTxOffset) | **MISSING** (BUG-11 P2) — value is `(block_hash, height)` not `(block_hash, nTxOffset)`; FindTx requires full-block deserialise + linear loop | disktxpos.h:13, txindex.cpp:107-109 |
| G15  | tx-index value INCLUDES height for confirmations calc without separate lookup | **PARTIALLY DIVERGENT** (BUG-12 P2) — Pattern C0 writes height_LE in bytes 33..36 but `getrawtransaction` IGNORES those bytes and falls back to O(N) iterator scan over height_index | rpc.lua:2354 inline comment ("This is expensive — in production, store height in tx_index") contradicts utxo.lua:2860-2863 which already does store height |
| G16  | Coinstatsindex MuHash3072 incremental state + persisted DB_MUHASH | **MISSING** (BUG-13 P0) — `compute_utxo_hash` does a full UTXO iterator scan on every gettxoutsetinfo call (O(UTXO_count)) instead of returning cached muhash from DB_MUHASH committed atomically with DB_BEST_BLOCK | coinstatsindex.cpp:42, 105-106, 264-313 |
| G17  | Coinstatsindex DBVal per-block snapshot (output_count, bogo_size, total_amount, total_subsidy, prevout_spent, new_outputs, coinbase, unspendables×4) | **MISSING** (BUG-14 P1) — no per-block DBVal; `gettxoutsetinfo` reports tip-only values | coinstatsindex.cpp:46-83 |
| G18  | Coinstatsindex LookUpStats(block_index) — historical snapshots | **MISSING** (BUG-15 P1) — `gettxoutsetinfo` has no `hash_type` / `height_or_hash` parameter; only the current tip is queryable | coinstatsindex.cpp:236-260 |
| G19  | Coinstatsindex unspendables tracking: genesis_block, bip30, scripts, unclaimed_rewards | **MISSING** (BUG-16 P2) — none of the 4 unspendables totals are maintained anywhere | coinstatsindex.cpp:39-46, 130-188 |
| G20  | Coinstatsindex height-key index AND hash-key index (with CopyHeightIndexToHashIndex on reorg) | **MISSING** (BUG-17 P1) — chain reorg of pre-coinstatsindex-era stale-chain entries is not preserved (because coinstatsindex doesn't exist) | db_key.h:71-93 |
| G21  | `gettxoutsetinfo hash_type=muhash` (Core's default in v23+) returns the running MuHash3072 | **MISSING** (BUG-18 P0) — RPC handler signature is `function(rpc, _params)`; `params` is discarded; only returns `hash_serialized_3` field | rpc/blockchain.cpp::gettxoutsetinfo; coinstatsindex.cpp |
| G22  | `gettxoutsetinfo hash_type=none` (count-only, no hash) supported | **MISSING** (BUG-19 P3) | rpc/blockchain.cpp |
| G23  | `gettxoutsetinfo use_index=false` forces full scan even when coinstatsindex present | **N/A** (no index means no toggle) | rpc/blockchain.cpp |
| G24  | DB_BLOCK_HEIGHT key is big-endian for sequential scan (txindex.cpp not strictly applicable; coinstatsindex MUST use BE) | **MISSING for coinstatsindex** (no index); CF.HEIGHT_INDEX in lunarblock uses BE 4B for block-hash lookups but no per-index analog | db_key.h:25, 40 |
| G25  | DBHashKey + DBHeightKey prefix bytes (`'s'` and `'t'`) distinct from BaseIndex DB_BEST_BLOCK `'B'` | **N/A** (no per-index DB layout) | db_key.h:29-30, base.cpp:47 |
| G26  | UpdatePruneLock when index is active so pruning cannot delete blocks the index hasn't covered yet | **MISSING** (BUG-20 P1) — no prune-lock coordination; if `--prune=…` is added later, txindex could see blocks deleted underneath it | base.cpp:487-504, blockstorage.cpp PruneLockInfo |
| G27  | ValidationInterface BlockConnected hook: ignore events when `role.validated == false` (avoids out-of-order indexing for background chainstate) | **MISSING** (BUG-21 P2) — single-chainstate model; no background chainstate ⇒ no role checking, but the abstraction is also absent so a future multi-chainstate model would silently corrupt indexes | base.cpp:328-378 |
| G28  | ChainStateFlushed periodic locator commit (every 30s SYNC_LOCATOR_WRITE_INTERVAL) | **MISSING** (BUG-22 P2) | base.cpp:50, 254-259, 380-422 |
| G29  | `scanblocks` RPC uses BlockFilterIndex + (for txindex hits) TxIndex to surface txs without rescanning every block | **N/A** (no scanblocks RPC) | rpc/blockchain.cpp::scanblocks |
| G30  | Dead-code modules (`src/txindex.lua`, `src/indexmanager.lua`) deleted or wired in | **DEAD-CODE** (BUG-23 P3) — modules expose `serialize_tx_pos(file_num, block_pos, tx_offset)`, `build_async`, `tick` coroutines, all referenced ONLY by `spec/txindex_spec.lua` and `spec/indexmanager_spec.lua`; production utxo.lua uses entirely different schema and never imports either | structural |

## Bugs (23)

### BUG-1 (G2, P0, OPS) — `-coinstatsindex` CLI flag absent

**File:** `src/main.lua:240-256` (CLI parser handles `--txindex` and
`--blockfilterindex` but not `--coinstatsindex`).
**Core:** `index/coinstatsindex.h:25` (`DEFAULT_COINSTATSINDEX = false`);
init.cpp adds `-coinstatsindex` option and wires
`g_coin_stats_index = std::make_unique<CoinStatsIndex>(...)` when set.

Operator cannot opt into the coinstatsindex even on a fresh node.
`gettxoutsetinfo` always does a full UTXO scan; no MuHash incremental
state exists; historical block lookup `gettxoutsetinfo <height>` is
unsupported.

### BUG-2 (G3, P1, CORRECTNESS) — tx-index value is `(block_hash, height_LE)` not CDiskTxPos

**File:** `src/utxo.lua:2853-2863`
```lua
local tip_buf = ffi.new("uint8_t[36]")
ffi.copy(tip_buf, tip_hash_capture.bytes, 32)
-- (height_LE in bytes 33..36)
local txindex_value = block_txid_bytes and tip_data or nil
```
**Core:** `index/disktxpos.h:11-22` — `CDiskTxPos{nFile, nPos, nTxOffset}`.
`index/txindex.cpp:80-87` advances `pos.nTxOffset` after each tx so
FindTx can seek directly to the tx bytes without deserialising the
whole block.

Lunarblock's value is functionally adequate for the
`getrawtransaction txid blockhash?` flow (FindTx ends up linearly
scanning the block anyway), but the divergence from Core's schema
means:
- A future operator who copies a lunarblock chainstate cannot
  reuse a Core txindex (and vice versa).
- The "intermediate offset" required to skip the block read is
  permanently unavailable until the schema is migrated.
- The "blk*.dat file number" — meaningless in lunarblock's RocksDB
  block store — is correctly absent, but the dead-code
  `src/txindex.lua:24` claims the format IS that 12-byte layout.

### BUG-3 (G4, P1, CORRECTNESS) — connect_block skips genesis BEFORE Pattern C0 write

**File:** `src/utxo.lua:2144-2151` (genesis short-circuit returns
early). `block_txid_bytes` is declared at line 2300, AFTER the genesis
short-circuit, so this isn't actually broken on the genesis path.
**Core:** `index/txindex.cpp:77` `if (block.height == 0) return true;`
is explicit and at the top of CustomAppend.

This is structurally divergent: lunarblock relies on a SIDE EFFECT
(connect_block returns early on `genesis_hash`) to skip indexing the
genesis coinbase. If a future refactor moves the txindex collection
above the genesis short-circuit, or if `connect_genesis()` ever
starts driving Pattern C0, the genesis coinbase will silently land
in CF.TX_INDEX. The comment in `src/utxo.lua:1554-1568` describes
"connect_block writes per-block tx_index entries inside the atomic
batch" without mentioning the genesis-skip contract; new readers
won't know to preserve it.

P1 rather than P0 because the current code path is correct.

### BUG-4 (G7, P0, OPS) — Pattern C0 never writes a txindex-specific block-locator

**File:** `src/utxo.lua` ChainState — no `txindex_height` /
`txindex_best_block` / `txindex_locator` meta key is ever written by
Pattern C0. The chainstate's `CF.META["chain_tip"]` is shared, so
the index has no independent persisted progress marker.
**Core:** `index/base.cpp:90-93` `WriteBestBlock(batch, locator)`
inside `Commit()`; `index/base.cpp:104-148` `Init()` reads the
locator and "if it is not part of the best chain, we will rewind to
the fork point during index sync".

Impact:
- After a hard-crash where `chain_tip` was committed but a previous
  txindex batch was missed (e.g. crash mid-IBD between connect_block
  batches across blocks), the locator-driven catch-up that Core
  performs on restart is impossible. lunarblock today doesn't
  detect or repair such a gap.
- If `--txindex` is FIRST enabled on a node with an existing
  chainstate at height N, there is no machinery to retro-index blocks
  0..N-1 (no `build_async` is wired to start). The flag silently
  becomes "index from this block forward" — Core builds the missing
  history asynchronously.
- `gettransaction` and `getrawtransaction` against any tx confirmed
  before `--txindex` was enabled will return "not found" forever.

### BUG-5 (G8, P1, OPS) — No locator-based rewind on restart

**File:** `src/utxo.lua:1625-1670` `ChainState:init()` — only reads
`get_chain_tip()`; no index-locator rewind step.
**Core:** `index/base.cpp:124-134` — locator points to a block in
the chain; if not on best chain, sync thread will rewind to fork
point.

After a crash where the chain reorganized below the indexed tip,
the txindex state on disk is stale (entries still pointing to
disconnected blocks). Pattern C0's `disconnect_block` path is only
invoked when the node itself performs a reorg via the live RPC/P2P
path. A crash-rewind on restart has no symmetric replay.

### BUG-6 (G9, P2, OPS) — No background-thread sync

**File:** `src/main.lua` does not start any txindex/coinstatsindex
background thread.
`src/indexmanager.lua:M.new(db, opts).start_building(...)` exists but
is **never called by production code** (only by
`spec/indexmanager_spec.lua`).
**Core:** `index/base.cpp:201-268` `BaseIndex::Sync()` runs in a
dedicated `m_thread_sync` thread, drives `NextSyncBlock`, commits
every 30s via `SYNC_LOCATOR_WRITE_INTERVAL`.

Without a Sync thread, "first-time enable" of `--txindex` on an
existing chainstate produces an index that only covers
post-enable blocks (BUG-4 follow-on). LuaJIT's coroutines could
fulfil the same role, but the `indexmanager.tick()` loop is dead.

### BUG-7 (G10, P1, OPS) — No `BlockUntilSyncedToCurrentChain` primitive

**File:** No analog exists in `src/utxo.lua`, `src/rpc.lua`, or
`src/indexmanager.lua`.
**Core:** `index/base.cpp:424-446` blocks the caller until the
index catches up to the current chain tip; widely called by RPC
methods that depend on a fully-synced index (e.g. `scanblocks`,
`gettxoutsetinfo` with `hash_type=muhash` when use_index=true).

In lunarblock today this is not a regression in user-visible
behavior because (a) the txindex is updated inline-on-connect
(BUG-6 means no async lag) and (b) coinstatsindex doesn't exist. But
the moment any of those gaps is closed, the primitive becomes
mandatory. Filed P1 as a known-gap blocker for BUG-13/18 fixes.

### BUG-8 (G11, P1, OPS) — No per-index `GetSummary`

**File:** No `txindex.get_summary()`, no `chain_state:index_summary()`.
**Core:** `index/base.cpp:472-485` returns
`{name, synced, best_block_height, best_block_hash}` for the
`getindexinfo` RPC (see BUG-9).

### BUG-9 (G12, P1, OPS) — `getindexinfo` RPC absent

**File:** `src/rpc.lua` exposes ~280 methods but
`grep getindexinfo rpc.lua` returns nothing.
**Core:** Operator-visible RPC that reports
`{ txindex: {synced, best_block_height}, coinstatsindex: {…}, basic block filter index: {…} }`.

Without it, operators cannot diagnose "is my txindex done building?"
or detect "is my coinstatsindex stuck?" or compare index-tip across
the fleet during a divergence drill.

### BUG-10 (G13, P1, PERF) — `getrawtransaction` does a full-block deserialise + linear tx scan

**File:** `src/rpc.lua:2143-2162`
```lua
local tx_index_data = rpc.storage.get and rpc.storage.get("tx_index", txid_bytes.bytes)
if tx_index_data then
  if #tx_index_data >= 32 then
    local index_block_hash = types.hash256(tx_index_data:sub(1, 32))
    found_blockhash = types.hash256_hex(index_block_hash)
    block = rpc.storage.get_block(index_block_hash)
    if block then
      -- Find tx in block
      for _, btx in ipairs(block.transactions) do
        local btx_txid = types.hash256_hex(validation.compute_txid(btx))
        ...
```
**Core:** `index/txindex.cpp:93-120` `FindTx` uses
`CDiskTxPos`. `file.seek(postx.nTxOffset, SEEK_CUR)` then
`file >> TX_WITH_WITNESS(tx)` reads ONLY that tx's bytes — O(1) in
block size.

Impact: `getrawtransaction` on a mainnet block with 3000+ txs does
~3000 `compute_txid` operations (each is a double-SHA256 over the
serialised tx) every time. Per-tx wall time scales with block
density, not with the tx itself.

### BUG-11 (G14, P2, SCHEMA) — No `nTxOffset` in the tx-index value

**File:** `src/utxo.lua:2853-2863` — value is 32B+4B = 36 bytes total.
**Core:** `index/disktxpos.h:13` — `nTxOffset` VARINT inside the
record.

Required to fix BUG-10. Schema migration needed.

### BUG-12 (G15, P2, PERF) — `getrawtransaction` ignores the height bytes already in the value

**File:** `src/rpc.lua:2354` inline comment:
```lua
-- This is expensive - in production, store height in tx_index
```
…contradicting `src/utxo.lua:2860-2863` which DOES store height_LE in
bytes 33..36. The rpc method `read_u32le(tx_index_data:sub(33,36))`
would give the height immediately; instead the RPC iterates the
height_index CF:
```lua
local iter = rpc.storage.iterator("height")
if iter then
  iter.seek_to_first()
  while iter.valid() do
    local v = iter.value()
    if v and #v == 32 and v == block_hash.bytes then
      block_height = k:byte(1) * 16777216 + ...
```
i.e. an O(chain_height) linear scan, **per `getrawtransaction` call**,
to recover information that's already in the value bytes.

`gettransaction txid verbose=1` on a node at height ~3M scans
~3M height_index entries to compute one confirmation count. P2
because it's perf-only (correctness unaffected).

### BUG-13 (G16, P0, PERF) — `compute_utxo_hash` does full UTXO scan per `gettxoutsetinfo`

**File:** `src/utxo.lua:4203-4269`
```lua
function ChainState:compute_utxo_hash()
  self.coin_view:flush()
  local hasher = crypto.sha256_init()
  local count = 0
  local iter = self.storage.iterator(storage_mod.CF.UTXO)
  iter.seek_to_first()
  while iter.valid() do ...
```
**Core:** `index/coinstatsindex.cpp:108-214` maintains an incremental
`MuHash3072` member (`m_muhash`) updated by `ApplyCoinHash`/
`RemoveCoinHash` per coin in `CustomAppend`/`RevertBlock`; the
`gettxoutsetinfo` RPC reads the cached value back via
`LookUpStats(block_index)` in O(1).

Severity P0: every `gettxoutsetinfo` call on a mainnet UTXO set
(~95M coins at h=900k) is a full RocksDB iterator pass that
materialises 95M `UtxoEntry` Lua tables and double-SHA256s each
serialised TxOutSer. Empirically observed wall time on lunarblock at
mainnet tip is in the multi-minute range. Core with `-coinstatsindex`
returns in ~50ms.

### BUG-14 (G17, P1, COMPLETENESS) — No per-block DBVal record

**File:** Not present anywhere.
**Core:** `index/coinstatsindex.cpp:46-83`
```
DBVal { muhash, transaction_output_count, bogo_size, total_amount,
        total_subsidy, total_prevout_spent_amount, total_new_outputs_ex_coinbase_amount,
        total_coinbase_amount, total_unspendables_genesis_block,
        total_unspendables_bip30, total_unspendables_scripts,
        total_unspendables_unclaimed_rewards }
```

Without this, lunarblock cannot expose Core's `gettxoutsetinfo` output
fields: `total_amount`, `total_unspendable_amount`,
`block_info.{unspendable, prevout_spent, new_outputs_ex_coinbase, coinbase, unspendables{…}}`.
The current handler returns `total_amount = total_sats / 1e8` but
the per-block subsidy / unspendable splits are entirely absent.

### BUG-15 (G18, P1, RPC) — `gettxoutsetinfo <height>` historical lookup unsupported

**File:** `src/rpc.lua:8024-8098` — handler discards `_params`.
**Core:** `index/coinstatsindex.cpp:236-260` `LookUpStats(CBlockIndex)`
uses dual-index (`DBHeightKey` + `DBHashKey`) so any historical block
on the active chain (and any disconnected stale-chain block whose
record was preserved via `CopyHeightIndexToHashIndex`) is queryable.

`gettxoutsetinfo 800000` is supported in Core ≥v23. lunarblock today
silently ignores the argument and returns tip-state.

### BUG-16 (G19, P2, COMPLETENESS) — No unspendables tracking

**File:** Not present.
**Core:** `index/coinstatsindex.cpp:43-46` 4 separate counters,
incremented per the relevant rule (genesis-block-coinbase,
BIP30-shadowed coinbase, OP_RETURN / unspendable scripts, unclaimed
subsidy via miner under-claim).

`gettxoutsetinfo` exposes these via the `block_info` sub-object;
external tooling (e.g. mempool.space's "issuance" view) depends on
them. Filed P2 because the data CAN be reconstructed from a full
chain replay; only the cached values are missing.

### BUG-17 (G20, P1, REORG) — No CopyHeightIndexToHashIndex on disconnect

**File:** lunarblock has no per-block-stats index at all; the per-tx
txindex `disconnect_block` simply DELETES the records (utxo.lua:3743-3747).
**Core:** `index/db_key.h:71-93`
`CopyHeightIndexToHashIndex<DBVal>` is called by
`CoinStatsIndex::CustomRemove` to preserve the disconnected block's
DBVal in the hash-keyed index so that `gettxoutsetinfo <stale-hash>`
keeps working post-reorg.

In lunarblock today, txindex entries for a disconnected block are
deleted; `getrawtransaction <txid-in-disconnected-block>` returns
"no such tx" (matches nimrod's correct-PASS shape per the
2026-05-05 cross-impl audit). Core's behavior is to ALSO support
`getrawtransaction <txid> <stale-block-hash>` via the index lookup
because the hash-keyed mirror persists. Symptom: lunarblock cannot
serve stale-chain queries; Core can.

### BUG-18 (G21, P0, RPC) — `gettxoutsetinfo hash_type=muhash` absent

**File:** `src/rpc.lua:8025` `function(rpc, _params)` discards params.
**Core:** Default `hash_type` in v23+ is `muhash`; `hash_serialized_3`
is opt-in. Many production wallets / explorers query with
`hash_type=muhash`.

lunarblock returns ONLY `hash_serialized_3`. A `--rpcclient` calling
`gettxoutsetinfo` with `hash_type=muhash` receives `nil` or "no such
field" depending on JSON-RPC client behavior. P0 because it's a
fleet-visible divergence: cross-impl audit would surface as
"lunarblock returns no muhash, all 9 other nodes return one."

### BUG-19 (G22, P3, RPC) — `hash_type=none` not supported

**File:** Same as BUG-18.
**Core:** Skips hashing entirely, returns count + total_amount only.
Useful for fast spot-checks. P3 because operationally optional.

### BUG-20 (G26, P1, SAFETY) — No prune-lock coordination

**File:** No `prune_lock` / `UpdatePruneLock` reference anywhere in
lunarblock.
**Core:** `index/base.cpp:487-504` `SetBestBlockIndex` updates
`m_chainstate->m_blockman.UpdatePruneLock(GetName(), prune_lock)` for
any AllowPrune-true index (coinstatsindex returns true; txindex
returns false). The pruner respects locks and refuses to delete
blocks the index hasn't yet processed.

Without this, enabling `--prune=550` plus `--txindex` on lunarblock
will succeed but the pruner (when implemented; see `src/prune.lua`)
could delete a block-body that the txindex still needs for a
historical query. Today `src/prune.lua` doesn't exist as a wired
production path, so this is latent.

### BUG-21 (G27, P2, FUTURE) — No ValidationInterface role check

**File:** lunarblock's connect_block is single-chainstate; no
`role.validated` parameter exists.
**Core:** `index/base.cpp:328-336` ignores BlockConnected events
where `role.validated == false` (i.e. background IBD chainstate
emitting events during an assumeutxo sync). Indexes only follow the
validated chain.

If lunarblock ever grows assumeutxo-style snapshot loading with a
background chainstate (work toward this exists in
`ChainState:dump_snapshot` and `:from_snapshot_blockhash`), then
Pattern C0's connect_block hook will silently index BOTH chainstates
into a single CF.TX_INDEX — producing a corrupted index where two
distinct blocks at the same height both have entries.

### BUG-22 (G28, P2, OPS) — No periodic locator flush

**File:** Pattern C0 commits the index inside the per-block batch,
so this is technically more durable than Core's 30s flush. But it
also means there is no "checkpoint progress" outside of the chainstate
tip; a long pause between blocks doesn't produce a fresh marker.
**Core:** `index/base.cpp:50, 254-259` `SYNC_LOCATOR_WRITE_INTERVAL{30s}`
caps "how far the index can fall behind on a crash".

P2 because Pattern C0 is effectively MORE conservative (every block
flushes), not less. Listed because it's a structural divergence
auditors should know about.

### BUG-23 (G30, P3, DEAD-CODE) — `src/txindex.lua` and `src/indexmanager.lua` are dead

**Files:** `src/txindex.lua` (262 LOC), `src/indexmanager.lua` (259 LOC).
**Evidence:**
```
$ grep -rn "require.*lunarblock\\.txindex\\|require.*lunarblock\\.indexmanager" \
       /home/work/hashhog/lunarblock/src/ \
       /home/work/hashhog/lunarblock/spec/
spec/txindex_spec.lua:17:    txindex = require("lunarblock.txindex")
src/indexmanager.lua:7:local txindex = require("lunarblock.txindex")
spec/indexmanager_spec.lua:17:    indexmanager = require("lunarblock.indexmanager")
```
No `main.lua`, `rpc.lua`, `utxo.lua`, or `sync.lua` requires either.

Worse, the dead code uses a DIFFERENT value layout
(`file_num/block_pos/tx_offset` 12 bytes) which is incompatible with
the live Pattern C0 (`block_hash/height_LE` 36 bytes). A future
contributor reading `src/txindex.lua` first will get the wrong mental
model. The dead-code comment `src/rpc.lua:8193` ("lunarblock txindex
stores file offsets, not block hashes") is FALSE for the live path —
it reflects the dead module's schema, not Pattern C0's.

Recommended remediation: delete `src/txindex.lua` and
`src/indexmanager.lua`, OR convert one into a thin façade around the
Pattern C0 schema and wire it through main.lua. Either choice
closes BUG-23. P3 because it's not a runtime defect today, but it's
a documented landmine for future audits.

## Notes for fix waves

A coherent fix-up campaign would tackle BUG-13 + BUG-18 + BUG-1 in
one wave (the `-coinstatsindex` enable + MuHash incremental +
`hash_type=muhash` RPC), then BUG-2 + BUG-10 + BUG-11 + BUG-12 in a
schema-migration wave (CDiskTxPos parity + fast FindTx), then
BUG-4..9 in an OPS wave (locator, getindexinfo, BlockUntilSynced).
BUG-23 (dead-code) can ride along with whichever wave touches the
production txindex path next.

The W121 BIP-158 codec audit already established lunarblock's
filterindex parity; the index-database infrastructure surfaced in
W133 is the missing scaffolding that would let txindex and a future
coinstatsindex share the same lifecycle as filterindex when wired
correctly.

## Cross-references

- W121 BIP-158 codec — established blockfilterindex byte-parity.
- W120 mempool RBF — adjacent to mempool persistence semantics (a
  sibling persistence shape).
- FIX-72 / FIX-76 / FIX-77 / FIX-80 — mapDeltas persistence (showed
  the same "Pattern X is the live path, the official factory is dead
  code" pattern).
- CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-2026-05-05.md
  — the cross-impl audit that drove Pattern C0 into existence.
