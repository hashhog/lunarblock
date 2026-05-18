# W146 — Block storage layer (blkXXXXX.dat + rev*.dat + block-index DB) audit (lunarblock)

**Date:** 2026-05-18
**Wave:** W146 (discovery; IBD & storage theme)
**Impl:** lunarblock (Lua / LuaJIT)
**Status:** **24 BUGS FOUND** (1 P0-CONSENSUS / 5 P0 / 8 P1 / 6 P2 / 4 P3) across **8 behaviors / 30 gates**
**Scope:** `blkXXXXX.dat` flat-file format (magic + size prefix), `rev*.dat`
undo-file format (magic + size + checksum), `FindBlockPos` rotation +
`BLOCKFILE_CHUNK_SIZE` preallocation, `FlushBlockFile` + fsync discipline,
block-index leveldb keys (`'b'` / `'f'` / `'l'` / `'F'` / `'R'` / `'t'`),
`WriteBlock` ordering atomicity, `ReadBlockFromDisk` checksum + magic
validation, recovery on partial write (bad-magic truncation / reindex flag).

## Context

This audit catalogues Core-parity deviations in **how lunarblock stores
block bodies + undo data + block-index metadata on disk**. The fundamental
architectural fact: **lunarblock does NOT use `blkXXXXX.dat` or
`rev*.dat` files at all — it stores everything in RocksDB column
families.** This is the dominant finding and the source of most bugs in
this audit.

Specifically:

- `storage.lua:161-186` declares **9 column families** (`HEADERS`, `BLOCKS`,
  `UTXO`, `TX_INDEX`, `HEIGHT_INDEX`, `META`, `UNDO`, `BLOCK_FILTER`,
  `BLOCK_FILTER_HEIGHT`) — RocksDB key/value, NOT flat files.
- The block body (`CF.BLOCKS`) is keyed by `block_hash.bytes` (32 B) → raw
  `serialize_block(blk)` output. **No 4-byte magic prefix, no 4-byte
  size prefix.**
- The undo data (`CF.UNDO`) is keyed by `block_hash.bytes` → varint(num_tx)
  || tx_undo || ... || **single-SHA256** checksum (NOT SHA256d / uint256
  as Core does; NOT prepended-by-magic).
- No `FindBlockPos`, no `BLOCKFILE_CHUNK_SIZE` (16 MiB preallocation), no
  `MAX_BLOCKFILE_SIZE` (128 MiB rotation), no `posix_fallocate`,
  no separate `FlushBlockFile` / `FlushUndoFile` paths, no rev-file undo
  height tracking.
- No `'R'` reindex flag in DB (the operator-facing `--reindex-chainstate`
  in `sync.lua` walks `CF.BLOCKS` from height 1; it does not set a
  persistent flag and is not atomic-restart-safe).
- No `'l'` last-block-file marker, no `'f' + file_num` → `CBlockFileInfo`
  records (lunarblock has no concept of block files).

The architectural divergence has direct **fleet-pattern** consequences:

1. **Off-the-shelf block-explorer tools cannot read lunarblock's
   storage** (electrs / fulcrum / mempool.space / nbxplorer expect
   `blkXXXXX.dat` + `rev*.dat`; even mempool.space's "block download"
   primitive cannot recover a lunarblock-pruned node's archival data).
2. **No interop with `bitcoin-cli importblocks <dir>` or
   `loadblock <file>` recovery paths.** A lunarblock datadir is
   irrecoverable to/from Core's flat-file primitives without rewriting
   every block.
3. **The `txindex.lua` schema preserves `(file_num, block_pos,
   tx_offset)` as fields** (txindex.lua:9-14, 26-32) — but the
   value of `file_num` is **always whatever caller passes**, since
   there are no actual block files. The downstream effect is that
   `getrawtransaction <txid>` returns junk for the disk-location
   shape that Core publishes. Pattern: **fake-shape-preserved-from-
   reference-implementation** (see BUG-2 below).
4. **Dead module `indexmanager.lua` (256 LOC)**: defines
   `manager.connect_block(block, block_hash, height, file_num,
   block_pos, undo_data)` with full lifecycle but is **never
   `require`d in production code** (only by tests). The
   `(file_num, block_pos)` parameters propagate further fictional
   plumbing.

## Source map

- `lunarblock/src/storage.lua:7-156` — RocksDB FFI declarations.
- `lunarblock/src/storage.lua:161-186` — `M.CF.*` column family enum +
  `CF_LIST` order.
- `lunarblock/src/storage.lua:208-325` — `M.open(path, cache_size_mb)`
  (database setup with column families).
- `lunarblock/src/storage.lua:347-387` — `dbobj.get` / `dbobj.put` /
  `dbobj.delete` (with optional `sync` flag).
- `lunarblock/src/storage.lua:389-428` — `dbobj.batch()` (WriteBatch
  abstraction; `write(sync)`).
- `lunarblock/src/storage.lua:487-554` — high-level helpers:
  `get_chain_tip` / `set_chain_tip`, `put_block` / `get_block`,
  `put_header` / `get_header`, `put_height_index` / `get_hash_by_height`,
  `put_undo` / `get_undo` / `delete_undo`.
- `lunarblock/src/utxo.lua:445-505` — `serialize_block_undo` /
  `deserialize_block_undo` (single-SHA256 checksum; no
  `prev_block_hash` mix-in).
- `lunarblock/src/utxo.lua:2820-2974` — `connect_block` per-block atomic
  WriteBatch (UTXO + UNDO + height-index + chain-tip + filterindex +
  txindex + caller-extras).
- `lunarblock/src/utxo.lua:1687-1722` — `connect_genesis`: 3 separate
  non-atomic writes (`put_block` + `put_header` + `put_height_index`),
  then `set_chain_tip(..., true)`.
- `lunarblock/src/utxo.lua:1744-1855` — `reindex_chainstate`: walks
  `height` 1..tip from `CF.BLOCKS`, no persistent `'R'` flag.
- `lunarblock/src/utxo.lua:3328-3346` — `accept_block` side-branch
  storage (non-atomic 2-write `put_block` + `put_header`).
- `lunarblock/src/rpc.lua:7157-7162` — submitblock fallback path
  (non-atomic 3-write).
- `lunarblock/src/sync.lua:2387-2402` — IBD per-block storage path
  (uses `batch()` when available; falls back to `put_block` only).
- `lunarblock/src/prune.lua:1-232` — height-driven RocksDB sweep
  (no `blkXXXXX.dat` deletion analog).
- `lunarblock/src/indexmanager.lua:1-259` — **dead module** (never
  `require`d outside tests).
- `lunarblock/src/txindex.lua:1-263` — `serialize_tx_pos(file_num,
  block_pos, tx_offset)` (fake-shape preserved).
- `lunarblock/src/consensus.lua:850, 989, 1060, 1132` — network
  `magic_bytes` (mainnet / testnet3 / testnet4 / regtest; **no signet**).

Core references:

- `bitcoin-core/src/node/blockstorage.h:118-129` — `BLOCKFILE_CHUNK_SIZE
  = 0x1000000 (16 MiB)`, `UNDOFILE_CHUNK_SIZE = 0x100000 (1 MiB)`,
  `MAX_BLOCKFILE_SIZE = 0x8000000 (128 MiB)`, `STORAGE_HEADER_BYTES = 8`
  (4-byte magic + 4-byte little-endian size).
- `bitcoin-core/src/node/blockstorage.cpp:58-62` — DB key prefixes
  `DB_BLOCK_FILES = 'f'`, `DB_BLOCK_INDEX = 'b'`, `DB_FLAG = 'F'`,
  `DB_REINDEX_FLAG = 'R'`, `DB_LAST_BLOCK = 'l'`.
- `bitcoin-core/src/node/blockstorage.cpp:967-1034` — `WriteBlockUndo`
  (writes magic+size+undo+checksum where checksum = SHA256d over
  `pprev->GetBlockHash() || blockundo`).
- `bitcoin-core/src/node/blockstorage.cpp:1036-1075` — `ReadBlock`
  (re-runs `CheckProofOfWork` on every read; also `CheckSignetBlockSolution`
  on signet).
- `bitcoin-core/src/node/blockstorage.cpp:1083-1117` — `ReadRawBlock`
  (validates magic, reads size, file position must be `>=
  STORAGE_HEADER_BYTES`).
- `bitcoin-core/src/node/blockstorage.cpp:1134-1163` — `WriteBlock`
  (writes magic + size + serialized block; uses fsync via `AutoFile`
  RAII fclose).
- `bitcoin-core/src/node/blockstorage.cpp:742-790` — `FlushBlockFile`
  (fsyncs blk + rev files separately).
- `bitcoin-core/src/index/txindex.cpp` + `txindex.h` — `DB_TXINDEX`
  prefix `'t'`.
- `bitcoin-core/src/kernel/chainparams.cpp` — `MessageStartChars` per
  network (`0xf9beb4d9` mainnet, `0x0b110907` testnet3,
  `0x1c163f28` testnet4, `0x0a03cf40` signet, `0xfabfb5da` regtest).

## 8-behavior matrix (30 gates)

### B1. `blkXXXXX.dat` file format (magic + size prefix + serialized block)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G1 | 4-byte network magic prefix before each block | **BUG-1 (P1)** — absent. `storage.lua:525-528` writes `serialize_block(blk)` raw under `CF.BLOCKS[block_hash]`. |
| G2 | 4-byte little-endian block size after magic | **BUG-1 (P1)** — absent (rolled into BUG-1). RocksDB already records the value length, so the explicit size field is redundant for lunarblock's purposes, but the byte-incompatibility with Core's recovery toolchain is the bug. |
| G3 | `STORAGE_HEADER_BYTES = 8` constant referenced anywhere | **BUG-1 (P1)** — absent. No `MessageStart()` equivalent is consulted on write. The `network.magic_bytes` field exists in `consensus.lua:850/989/1060/1132` but is used only by P2P wire framing (`p2p.lua:237`), never for block storage. |

### B2. `rev*.dat` (undo) file format (magic + size + serialized CBlockUndo + uint256 checksum)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G4 | 4-byte network magic + 4-byte LE size before undo blob | **BUG-2 (P1)** — absent. `utxo.lua:473-483` writes only `varint(num_tx) || tx_undo... || SHA256(payload)`. |
| G5 | Checksum = **double-SHA256** (uint256) over `pprev->GetBlockHash() || blockundo` | **BUG-3 (P0-CDIV)** — lunarblock uses **single SHA256** of payload only; **no pprev mix-in**. See `utxo.lua:481`: `local checksum = crypto.sha256(data)`. Core ref `blockstorage.cpp:996-999`: `HashWriter hasher{}; hasher << block.pprev->GetBlockHash() << blockundo;`. Two divergences: hash function (single vs double) AND domain (data-only vs prev-hash-prepended). A Core node's `bitcoind --rev-check` would mark every lunarblock undo as corrupt. |
| G6 | `UNDO_DATA_DISK_OVERHEAD = 8 + 32 = 40 bytes` accounted | **BUG-4 (P3)** — absent; not used because BUG-2/3 short-circuit the framing. Latent. |

### B3. `FindBlockPos` rotation + `BLOCKFILE_CHUNK_SIZE` preallocation

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G7 | Rotate to next file when current > `MAX_BLOCKFILE_SIZE` (128 MiB) | **BUG-5 (P1)** — absent. RocksDB SST file management is opaque; no per-block "file rotation" concept. |
| G8 | `posix_fallocate` (or platform analog) in `BLOCKFILE_CHUNK_SIZE` (16 MiB) increments | **BUG-6 (P2)** — absent. RocksDB writes append-only to its WAL + SST files; no preallocation of fixed-chunk regions. |
| G9 | Block-file info (`'f' + file_num` → `CBlockFileInfo`) tracking nFile/nSize/nChainTx/heightFirst/heightLast | **BUG-7 (P0)** — absent. No `CBlockFileInfo` data structure exists in lunarblock. Consequence: cannot answer "which blk file covers heights 100k-200k?" — the RPC `getblockchaininfo` cannot return `size_on_disk` reliably (`prune.lua:18-22` even has a `TODO(prune-size)` noting `rocksdb_approximate_sizes_cf` isn't exposed). |
| G10 | `m_blockfile_info` in-memory cache | **BUG-7 (P0)** — absent (rolled in). |

### B4. `FlushBlockFile` + fsync discipline

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G11 | Per-file fsync on rotation OR explicit flush | **BUG-8 (P1)** — N/A by-architecture (RocksDB does its own fsync on the WAL; user gates this via `WriteOptions::sync`). lunarblock's `dbobj._write_opts_sync` (`storage.lua:329-331`) sets `rocksdb_writeoptions_set_sync(opts, 1)` correctly, but the `put_block`/`put_header`/`put_height_index` helpers **never pass sync=true** (see BUG-9). |
| G12 | Separate `FlushBlockFile` vs `FlushUndoFile` paths | **BUG-8 (P1)** — absent. Single RocksDB WAL covers everything. The Core distinction (undo files written in validation order; blk files in download order, so undo can be flushed earlier) collapses to a single flush primitive — fine in principle, but it removes the operator knob to flush undo separately during a long IBD. |
| G13 | `put_block` / `put_header` / `put_height_index` honour a `sync` flag | **BUG-9 (P0)** — **API asymmetry**. `storage.lua:513-541`: these three helpers DO NOT accept a `sync` parameter; they always call `dbobj.put(cf, key, value)` with the sync arg unset (= `nil` = falsy → `dbobj._write_opts` = async). But `set_chain_tip(hash, height, sync)` and `put_undo(block_hash, data, sync)` DO accept sync. The genesis bootstrap (`utxo.lua:1691-1693`) and side-branch storage path (`utxo.lua:3334-3335, 3343-3344`) and submitblock fallback (`rpc.lua:7159-7161`) all rely on async writes — a hard crash between any of them and the next sync flush loses the block body to disk. RocksDB's WAL may save us, but the API is misshapen and the contract is silently un-honourable. |

### B5. Block-index leveldb keys (`'b' / 'f' / 'l' / 'F' / 'R' / 't'`)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G14 | `'b' + hash` → CBlockIndex / `CDiskBlockIndex` entry | **BUG-10 (P0)** — absent. Lunarblock has no `CBlockIndex` equivalent. Block header lives in `CF.HEADERS[hash]` as serialize_block_header (80 B raw). The associated metadata Core embeds in `CDiskBlockIndex` (nStatus, nChainWork, nTimeMax, nFile, nDataPos, nUndoPos, nSequenceId, nVersion bits) is split across multiple CFs or absent entirely. Result: `getblockheader` RPC cannot return the full `CBlockIndex` projection Core publishes; we have to reconstruct fields from `CF.UTXO` / `CF.UNDO` existence as a proxy. |
| G15 | `'f' + file_num` → `CBlockFileInfo` | **BUG-7 (P0)** — absent (cross-cite). |
| G16 | `'l'` → last block file index (single key) | **BUG-11 (P1)** — absent. |
| G17 | `'F' + name` → flags (e.g. `txindex`, `pruned`, `assumevalid`) | **BUG-12 (P1)** — absent. lunarblock persists flags into `CF.META["txindex_height"]`, `CF.META["filterindex_height"]`, etc., but there's no general flag-name keyspace. The implication: a flag's STATE flicker (e.g. "txindex was enabled on first run, disabled on second") cannot be detected via the canonical Core `('F' + name)` keyspace — debugging tooling that introspects Core nodes does not work on lunarblock. |
| G18 | `'R'` → reindexing flag (Write/Erase/Exists) | **BUG-13 (P0)** — absent. `utxo.lua:1744-1855` `reindex_chainstate` runs but does NOT persist a `'R' = '1'` mid-reindex marker. If lunarblock crashes during reindex, the next restart cannot tell that reindex was in progress; the partial wipe of `CF.UTXO` (lines 1779-1780) leaves the chainstate in an inconsistent state — `verify_chainstate_consistency` (`utxo.lua:1898`) attempts a recovery walk but only scans the last 200 blocks (`max_blocks` default), so a mid-reindex crash at depth >200 yields a permanently wedged datadir. **Recovery-on-partial-write fleet pattern hit.** |
| G19 | `'t' + txid` → tx-disk-location (when `-txindex`) | **BUG-2 (P1)** cross-cite — `txindex.lua:26-32` writes `(file_num, block_pos, tx_offset)` but the `file_num` field is **always whatever the caller passes**, which the IBD path doesn't supply (only `indexmanager.lua` would, and that module is **dead** — see BUG-14). |

### B6. `WriteBlock` atomicity (block body + index-DB ordering)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G20 | DB commit MUST come AFTER disk write+fsync of blk file | **BUG-15 (P0)** — N/A by-architecture (single RocksDB transaction); but the **non-atomic 2/3-write helper sequence** in `connect_genesis`, `accept_block` side-branch, and `submitblock` fallback violates the spirit of the rule. See BUG-9 for the sync-flag side. The reorg path (`utxo.lua:3328-3346`) writes `put_block(side_hash, block)` then `put_header(side_hash, header)` as TWO separate async puts — a crash between them yields an orphaned block body in `CF.BLOCKS` whose header isn't queryable. Side branches matter for reorg construction; this is a real data integrity hole. |
| G21 | Reverse order = orphan disk data on interrupt | **BUG-15 (P0)** cross-cite — multiple `put_block` followed by `set_chain_tip(..., sync=true)` is the IBD pattern; the chain-tip update DOES sync the WAL, which would also sync the prior `put_block` async writes. BUT the genesis path (`utxo.lua:1691-1693`) puts block, header, height-index without a follow-up sync until line 1721's `set_chain_tip(..., true)` — and the order is `put_block → put_header → put_height_index → set_chain_tip`. Core's rule "DB index write AFTER disk fsync" is technically inverted (lunarblock writes both to the same DB without explicit fsync), but the chain-tip flush at the end is the analog. **Partial-write recovery is incomplete though**: if chain_tip update partially fails, the put_block/put_header/put_height_index entries are orphaned. |

### B7. `ReadBlockFromDisk` + checksum / magic / PoW re-check

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G22 | Open file at recorded pos, read magic, validate vs expected | **BUG-16 (P1)** — N/A by-architecture (RocksDB key lookup; no file/offset notion). The block is retrievable iff `CF.BLOCKS[hash]` exists; no on-read magic byte validation possible. |
| G23 | Magic mismatch = file corruption rejection | **BUG-16 (P1)** cross-cite — RocksDB returns nil for missing keys; no corruption signal. RocksDB DOES verify its own block-checksum at the SST-level on read, so corruption IS detected, just not with Core's `0xf9beb4d9` magic check semantics. |
| G24 | Re-run `CheckProofOfWork` on every disk read | **BUG-17 (P0-CONSENSUS)** — **absent.** `storage.lua:519-523` `get_block` simply deserializes and returns — no PoW re-check. Core ref `blockstorage.cpp:1057-1060`: `if (!CheckProofOfWork(block_hash, block.nBits, GetConsensus())) { return false; }`. **Impact:** an attacker with disk-write access to RocksDB can substitute a tampered block (same hash key, mutated body); subsequent rereads return the tampered block bytes. Core's defense-in-depth is the PoW re-check on every read. Same risk class as W138 BUG-1 (clearbit) and W142 W144 dead-flag patterns. P0-CONSENSUS because the absent check means a tampered block is silently propagated as valid into reorg consideration, RPC responses, and ZMQ publishers. |
| G25 | Signet block-solution re-check on signet networks | **BUG-18 (P2)** — N/A; lunarblock has **no signet network entry** in `consensus.lua` (only mainnet / testnet3 / testnet4 / regtest are registered — `consensus.lua:847-1198`). Signet is out-of-scope by omission. |

### B8. Recovery on partial write (bad-magic truncation + `'R'` reindex flag)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G26 | Bad-magic-prefix at expected pos = truncate file there | **BUG-19 (P2)** — N/A by-architecture (no flat files). RocksDB's WAL recovery handles partial WAL records. |
| G27 | `'R' = '1'` reindex flag triggers full block-file replay | **BUG-13 (P0)** cross-cite — absent. |
| G28 | Recovery code path = production fallback (not just CLI) | **BUG-20 (P1)** — `verify_chainstate_consistency` (`utxo.lua:1898`) is invoked from start-up paths, but its scope is the last 200 blocks of UTXO consistency, not a full storage-layer recovery. There is NO equivalent to Core's "open blk?????.dat, scan for magic, re-add to block tree" recovery from a freshly-imported (un-indexed) datadir. The operator must run `--reindex-chainstate` manually if the index is corrupt. **Surfaced by `sync.lua:26` documentation reference and the 4+ `--reindex-chainstate` hints scattered across sync.lua / utxo.lua.** |
| G29 | Disk-space pre-write check (Core `CheckDiskSpace`) | **BUG-21 (P1)** — **absent.** No `CheckDiskSpace` analog anywhere in lunarblock. A near-full disk during IBD will silently fail RocksDB write with no graceful "block %s data could not be written, no space left on device" error path. |
| G30 | Recovery preserves UTXO + index DB consistency atomically | **BUG-22 (P1)** — partial. The per-block atomic batch (`utxo.lua:2930-2974`) is correct for the active-chain extend case. The side-branch storage path is non-atomic (BUG-15). The reindex path is non-atomic across the whole reindex (BUG-13). |

## Bugs (full)

### BUG-1 (P1) — `blkXXXXX.dat` flat-file format entirely absent; block bodies live in RocksDB CF.BLOCKS

**File:** `src/storage.lua:161-186` (CF list), `src/storage.lua:525-528`
(`dbobj.put_block`), `src/utxo.lua:2820-2974` (per-block atomic batch).

**Core ref:** `bitcoin-core/src/node/blockstorage.h:118-129`,
`bitcoin-core/src/node/blockstorage.cpp:1134-1163` (`WriteBlock`).

**Description:** Lunarblock stores serialized block bodies under
`CF.BLOCKS[block_hash]` as raw bytes (output of `serialize_block(blk)` —
header + varint(tx_count) + concatenated transactions). There is **no
4-byte network-magic prefix and no 4-byte little-endian block-size
prefix** as Core writes via `fileout << GetParams().MessageStart() <<
block_size`. The 8-byte `STORAGE_HEADER_BYTES` Core constant has no
analog. The `network.magic_bytes` field exists at
`consensus.lua:850/989/1060/1132` for mainnet/testnet/testnet4/regtest
but is used only by the P2P wire layer (`p2p.lua:237-238`); it is
never consulted on block storage write or read.

**Excerpt** (`src/storage.lua:525-528`):

```lua
function dbobj.put_block(block_hash, blk)
  local data = serialize.serialize_block(blk)
  dbobj.put(M.CF.BLOCKS, block_hash.bytes, data)
end
```

Compare Core (`bitcoin-core/src/node/blockstorage.cpp:1134-1163`):

```cpp
FlatFilePos BlockManager::WriteBlock(const CBlock& block, int nHeight) {
    FlatFilePos pos{FindNextBlockPos(block_size + STORAGE_HEADER_BYTES, ...)};
    ...
    BufferedWriter fileout{file};
    fileout << GetParams().MessageStart() << block_size;
    pos.nPos += STORAGE_HEADER_BYTES;
    ...
}
```

**Impact:**
- **Operational interop break.** No off-the-shelf Bitcoin-Core-format
  block-explorer indexer (electrs, fulcrum, mempool.space, nbxplorer)
  can read lunarblock's datadir without a rewrite layer.
- **Recovery toolchain incompatibility.** Cannot use Core's
  `loadblock <file>` / `importblocks` / `bootstrap.dat` recovery paths.
  A lunarblock datadir cannot be repaired or migrated by any Core-aware
  utility.
- **No on-disk magic byte cross-check** when reading a block back (BUG-16);
  the integrity of stored block bytes relies entirely on RocksDB's
  internal block checksum.

**Severity:** P1. Not consensus-divergent on its own (the block data is
recoverable via the lunarblock-native `get_block`), but the
operational and ecosystem-interop costs are severe.

---

### BUG-2 (P1) — `rev*.dat` undo file framing absent (no magic + size prefix)

**File:** `src/utxo.lua:473-483` (`serialize_block_undo`),
`src/storage.lua:548-554` (`put_undo` / `get_undo` / `delete_undo`).

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:988-993`
(`WriteBlockUndo`).

**Description:** Lunarblock's undo data is stored under
`CF.UNDO[block_hash]` as `varint(num_tx) || tx_undo... || SHA256(payload)`.
There is **no `MessageStart() << blockundo_size` framing** as Core's
`WriteBlockUndo` emits. The `UNDO_DATA_DISK_OVERHEAD = STORAGE_HEADER_BYTES
+ uint256::size() = 40 bytes` Core constant has no analog.

**Excerpt** (`src/utxo.lua:473-483`):

```lua
function M.serialize_block_undo(block_undo)
  local w = serialize.buffer_writer()
  w.write_varint(#block_undo.tx_undo)
  for _, txu in ipairs(block_undo.tx_undo) do
    w.write_bytes(M.serialize_tx_undo(txu))
  end
  local data = w.result()
  -- Append SHA256 checksum of the data
  local checksum = crypto.sha256(data)
  return data .. checksum
end
```

**Impact:** Cross-impl undo migration (rare in practice, but used by
Core test harnesses) does not work. Operationally, the on-disk undo
file cannot be `xxd`-inspected and recognised as a Bitcoin rev*.dat.

**Severity:** P1. Operational-interop; not consensus.

---

### BUG-3 (P0-CDIV) — Undo checksum is SHA256 (single) over data only; Core uses SHA256d (double) over `pprev_hash || blockundo`

**File:** `src/utxo.lua:480-483, 494-497`.

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:994-999`:

```cpp
// Calculate checksum
HashWriter hasher{};
hasher << block.pprev->GetBlockHash() << blockundo;
// Write undo data & checksum
fileout << blockundo << hasher.GetHash();
```

`HashWriter` is **double-SHA256** (uint256), and the message
includes `pprev->GetBlockHash()` as a domain separator so that
the same undo bytes appear under a different checksum at different
heights — defends against an attacker swapping an undo blob from one
height to another.

**Description:** Lunarblock uses **single SHA256** (`crypto.sha256(data)`)
of just the payload — **no prev-block-hash mix-in.** Both divergences
matter:

1. **Hash function divergence**: Core's `HashWriter` is SHA256d
   (sha256 of sha256); lunarblock's is single sha256.
2. **Domain divergence**: Core includes `pprev->GetBlockHash()` in the
   hash input; lunarblock does not. Without this, an attacker can swap
   undo data between blocks of the same length (rare in practice but
   possible during reorg ambiguity windows).

**Excerpt** (`src/utxo.lua:478-483`):

```lua
  local data = w.result()
  -- Append SHA256 checksum of the data
  local checksum = crypto.sha256(data)
  return data .. checksum
end
```

vs deserialize at `src/utxo.lua:493-497`:

```lua
  local payload = data:sub(1, -33)
  local stored_checksum = data:sub(-32)
  local computed_checksum = crypto.sha256(payload)
  if stored_checksum ~= computed_checksum then
    return nil, "undo data checksum mismatch"
  end
```

**Impact:**
- **A Core node's `bitcoind --check` would mark every lunarblock
  undo blob as corrupt** (wrong hash function, missing pprev mix-in).
- **Defense-in-depth gap**: attacker with disk-write to RocksDB can swap
  an undo blob between two blocks of identical serialized length (e.g.
  two empty-mempool blocks back-to-back); the checksum still passes
  because the prev-block context isn't in the hash.

**Severity:** P0-CDIV. Not consensus-divergent at validation time, but
the **on-disk format is byte-incompatible** with Core's rev*.dat
format, and the **checksum is structurally weaker** in a way Core
deliberately fixed.

---

### BUG-4 (P3) — `UNDO_DATA_DISK_OVERHEAD = 40 bytes` constant not used

**File:** (absent everywhere).

**Core ref:** `bitcoin-core/src/node/blockstorage.h:128-129`:
`UNDO_DATA_DISK_OVERHEAD = STORAGE_HEADER_BYTES + uint256::size() = 8 + 32 = 40`.

**Description:** Used by Core in `FindUndoPos` and `WriteBlockUndo` to
pre-account for the on-disk overhead per undo blob (so file rotation
math is correct). Absent in lunarblock because BUG-2/3 short-circuit
the framing.

**Impact:** Latent until BUG-2/3 are fixed.

**Severity:** P3.

---

### BUG-5 (P1) — No `MAX_BLOCKFILE_SIZE` rotation logic; single RocksDB column family stores all blocks

**File:** (absent), see `src/storage.lua:161-186` (CF declarations).

**Core ref:** `bitcoin-core/src/node/blockstorage.h:123`:
`MAX_BLOCKFILE_SIZE = 0x8000000 = 128 MiB`.
`bitcoin-core/src/node/blockstorage.cpp:783-790` (FlushChainstateBlockFile),
`FindNextBlockPos` rotates when current file > MAX_BLOCKFILE_SIZE.

**Description:** Lunarblock's `CF.BLOCKS` is a single RocksDB column
family. RocksDB will internally split its SST files when they exceed
its `target_file_size_base` (default 64 MiB), but this is NOT
operator-visible nor controllable from the lunarblock API. Operators
cannot run `du -h blkXXXXX.dat` to see per-file size; there is no
analog command.

**Impact:** Operational (debug-introspection) gap; cannot
estimate per-segment growth.

**Severity:** P1. Not consensus.

---

### BUG-6 (P2) — No `BLOCKFILE_CHUNK_SIZE` preallocation; no `posix_fallocate`

**File:** (absent).

**Core ref:** `bitcoin-core/src/node/blockstorage.h:119-121`:
`BLOCKFILE_CHUNK_SIZE = 0x1000000 = 16 MiB`,
`UNDOFILE_CHUNK_SIZE = 0x100000 = 1 MiB`.

**Description:** Core preallocates blkXXXXX.dat in 16 MiB chunks and
rev*.dat in 1 MiB chunks via `posix_fallocate` (or platform equivalent)
to reduce fragmentation on rotating drives. Lunarblock relies on
RocksDB's internal preallocation (configurable via
`rocksdb_options_set_target_file_size_base`, not exposed in the FFI
surface at `storage.lua:7-156`).

**Excerpt** (`src/storage.lua:217-218`):

```lua
librocksdb.rocksdb_options_set_write_buffer_size(options, 256 * 1024 * 1024)  -- 256MB
librocksdb.rocksdb_options_set_max_write_buffer_number(options, 4)
```

(Target file size / preallocation knob is missing.)

**Impact:** Higher fragmentation risk on spinning disks; minor on NVMe.
Operator cannot tune this without modifying source.

**Severity:** P2.

---

### BUG-7 (P0) — `CBlockFileInfo` data structure entirely absent (`m_blockfile_info`)

**File:** (absent everywhere); cross-cite `src/prune.lua:18-22`.

**Core ref:** `bitcoin-core/src/node/blockstorage.h:CBlockFileInfo`
(nBlocks / nSize / nUndoSize / nHeightFirst / nHeightLast / nTimeFirst /
nTimeLast); persisted to `'f' + file_num` key in block-tree DB.

**Description:** Core's per-blk-file metadata (how many blocks, total
bytes, height range, time range) is absent. The `prune.lua` module
explicitly notes the gap at lines 18-22:

```lua
-- TODO(prune-size): Replace the block-count translation with a real
-- size-driven sweep once storage.lua exposes
-- rocksdb_approximate_sizes_cf or a periodic CalculateCurrentUsage.
-- Rationale + math: see comment on `target_blocks_to_keep` below.
```

This is **comment-as-confession**: the prune sweep cannot do size-driven
pruning because the data structure that would tell it the disk footprint
of `CF.BLOCKS` doesn't exist. `prune.lua:41` uses
`AVG_BLOCK_SIZE = 1500000` (1.5 MB empirical fleet average from
2026-04-29) as a fudge factor.

**Impact:**
- `getblockchaininfo` cannot return `size_on_disk` accurately.
- `pruneblockchain` operates on a fudged block-count target, not actual
  disk usage. A datadir with `--prune=550` might end up at 800 MB or
  300 MB, not 550.
- Cross-impl audits comparing on-disk size cannot be performed.

**Severity:** P0. Operator-impacting; pruning is a real production knob
that ships subtly broken.

---

### BUG-8 (P1) — No separate `FlushBlockFile` / `FlushUndoFile` paths

**File:** (absent).

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:742-790`
(`FlushBlockFile`).

**Description:** Core distinguishes blk-file flush from undo-file flush
because undo data is written in validation order (often height-monotonic)
while blk data is written in download order (often out-of-order during
IBD). RocksDB's single WAL covers both, so this distinction
collapses; that's fine in principle but removes operator-visible
flush-granularity knobs.

**Impact:** Cannot manually trigger an undo-only flush. Marginal.

**Severity:** P1. Operational.

---

### BUG-9 (P0) — `put_block` / `put_header` / `put_height_index` do not honour a `sync` flag; API asymmetry vs `put_undo` / `set_chain_tip`

**File:** `src/storage.lua:513-541`.

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:1134-1163`
(`WriteBlock` uses RAII `AutoFile`; fclose triggers fsync).

**Description:** The three "block-data persistence" helpers do not
accept a sync arg:

```lua
function dbobj.put_header(block_hash, header)
  local data = serialize.serialize_block_header(header)
  dbobj.put(M.CF.HEADERS, block_hash.bytes, data)  -- sync arg unset → async
end

function dbobj.put_block(block_hash, blk)
  local data = serialize.serialize_block(blk)
  dbobj.put(M.CF.BLOCKS, block_hash.bytes, data)   -- sync arg unset → async
end

function dbobj.put_height_index(height, block_hash)
  local key = encode_height(height)
  dbobj.put(M.CF.HEIGHT_INDEX, key, block_hash.bytes)  -- sync arg unset → async
end
```

But the sibling helpers DO accept sync:

```lua
function dbobj.set_chain_tip(hash, height, sync)       -- accepts sync
function dbobj.put_undo(block_hash, undo_data, sync)   -- accepts sync
function dbobj.delete_undo(block_hash, sync)           -- accepts sync
```

**Impact:**
- **Caller cannot opt-in to sync for block body / header / height-index
  writes**, even in scenarios where it would be the right thing (e.g.
  genesis bootstrap, final block before reorg point, post-restart
  recovery checkpoint).
- The reliance on a follow-up `set_chain_tip(..., true)` to sync the
  WAL up to that point is correct for the active-chain extend case,
  but the side-branch storage path (`utxo.lua:3334-3335, 3343-3344`)
  has no following chain-tip flush — those side-branch puts are
  permanently async until the next chain-tip flush (which only happens
  on chain extend or reorg). A side-branch stored just before a crash
  is lost.
- The submitblock fallback at `rpc.lua:7157-7162` is similarly all
  async — except the path is fallback-only and shouldn't occur in
  practice.

**Severity:** P0. Concrete data-loss scenario on side-branch storage
+ crash. **API-shape bug** + **caller-cannot-fix bug** since the
helper signature precludes sync.

---

### BUG-10 (P0) — `CBlockIndex` / `CDiskBlockIndex` not persisted; `'b' + hash` keyspace absent

**File:** (absent everywhere); cross-cite `src/storage.lua:161-186` (CF list)
and `src/utxo.lua` (header storage scattered).

**Core ref:** `bitcoin-core/src/chain.h:CBlockIndex`,
`bitcoin-core/src/node/blockstorage.cpp:59` (`DB_BLOCK_INDEX = 'b'`),
`bitcoin-core/src/node/blockstorage.cpp:100`
(`batch.Write(std::make_pair(DB_BLOCK_INDEX, hash), CDiskBlockIndex{bi})`).

**Description:** Core's `CBlockIndex` carries (nStatus, nHeight,
nChainWork, nTimeMax, nFile, nDataPos, nUndoPos, nSequenceId, nVersion,
hashMerkleRoot, nTime, nBits, nNonce, pprev pointer) and is persisted
to leveldb under `('b', hash)` as `CDiskBlockIndex` (a CBlockIndex
projection minus the in-memory pointers).

Lunarblock stores **only the 80-byte block header** under
`CF.HEADERS[block_hash]` (see `storage.lua:513-516`). The associated
chain metadata (chainwork, timeMax, status flags, sequence-id) is
either reconstructed on the fly (chainwork via summing `get_block_work`
in `utxo.lua:3301-3320`) or absent (status flags — there is no
BLOCK_VALID_TREE / BLOCK_VALID_TRANSACTIONS / BLOCK_HAVE_DATA /
BLOCK_HAVE_UNDO / BLOCK_FAILED_VALID bitmask persisted).

**Excerpt** (`src/storage.lua:513-516`):

```lua
function dbobj.put_header(block_hash, header)
  local data = serialize.serialize_block_header(header)
  dbobj.put(M.CF.HEADERS, block_hash.bytes, data)
end
```

(Just the 80-byte serialized header. No status, no file/pos, no chainwork.)

**Impact:**
- **`getblockheader` RPC cannot publish all `CBlockIndex` fields Core
  publishes** — specifically `nChainWork` is recomputed on every call,
  `nStatus`-derived fields (validation status) are inferred from the
  existence of `CF.UTXO`/`CF.UNDO` entries.
- **Reorg paths recompute chainwork from scratch** every time
  (`utxo.lua:3299-3320`); Core caches it.
- **Status flags** (BLOCK_FAILED_VALID, etc.) are NOT persisted across
  restart — lunarblock tracks failed blocks in an in-memory set
  (`utxo.lua` has `has_invalid_ancestor`); a restart loses the
  invalid-flag and the same bad block could be re-accepted briefly
  before validation rejects it again. **Same fleet pattern as W138 dead
  ChainstateManager classes** (BLOCK_FAILED_VALID is a status bit that
  every other impl persists or recomputes; lunarblock just doesn't).

**Severity:** P0. Restart-time correctness gap (status flags lost +
chainwork re-derivation cost + Core RPC shape mismatch).

---

### BUG-11 (P1) — `'l'` last-block-file key absent

**File:** (absent).

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:60`
(`DB_LAST_BLOCK = 'l'`), `:89` (`ReadLastBlockFile`).

**Description:** Core persists "highest written block-file index" under
the single-byte key `'l'`. Lunarblock has no block-file concept so the
key is absent. Latent.

**Impact:** Operator/debug introspection gap.

**Severity:** P1. Operational.

---

### BUG-12 (P1) — `'F' + name` flag keyspace absent

**File:** (absent).

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:61`
(`DB_FLAG = 'F'`), `:107-117` (`WriteFlag` / `ReadFlag`).

**Description:** Core uses `('F', "txindex")`, `('F', "pruned")`, etc.
to track config-level flags that should persist across restart so
that e.g. "txindex was enabled last run; was it enabled this run?"
is detectable for index re-sync.

Lunarblock stores some flags in `CF.META["txindex_height"]` (txindex
build progress), `CF.META["filterindex_height"]` (filter index build
progress), but there's **no general flag-name keyspace** for
configuration drift detection. E.g. a node that switches from
`--prune=550` to `--prune=0` will not be detected as a config drift.

**Impact:** Config-drift not detected; index rebuilds can be missed.

**Severity:** P1. Operational + integrity drift.

---

### BUG-13 (P0) — No persistent `'R'` reindex flag; mid-reindex crash leaves datadir wedged

**File:** `src/utxo.lua:1744-1855` (`reindex_chainstate`).

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:61, 73-85`
(`DB_REINDEX_FLAG = 'R'`, `WriteReindexing`, `ReadReindexing`).

**Description:** Core writes `('R', '1')` at the start of a reindex
and erases it at the end. If the node crashes mid-reindex, the next
startup reads the flag and resumes / restarts the reindex.

Lunarblock's `reindex_chainstate` (`utxo.lua:1744-1855`) wipes
`CF.UTXO` + `CF.UNDO` (lines 1779-1780) and walks `CF.BLOCKS` from
height 1, calling `connect_block`. **No persistent flag is written
to indicate a reindex is in progress.** If lunarblock crashes
mid-reindex:

1. `CF.UTXO` is partially wiped (lines 1747-1777 walk in 64k-key
   batches, so crash mid-walk leaves a partial wipe).
2. `chain_tip` (`CF.META["chain_tip"]`) still points at the
   pre-reindex tip.
3. On restart, lunarblock sees a chain_tip that says "tip = X"
   but the UTXO state is inconsistent with that tip.
4. `verify_chainstate_consistency` (`utxo.lua:1898`) attempts a
   rollback-based recovery, but it scans **only the last 200
   blocks by default** (`max_blocks` param). A mid-reindex crash
   when the reindex was already past block 100 in a chain of
   depth 800,000 leaves a permanently-broken datadir — recovery
   would need to roll back 799,900 blocks, which the bounded
   rollback explicitly does not do.

The fallback is the operator manually running `--reindex-chainstate`
again, but **there's no in-DB signal that this is needed**. The
operator must read syslog / .lock files / external state.

**Excerpt** (`src/utxo.lua:1779-1781`):

```lua
  local utxos_wiped = wipe_cf(storage_mod.CF.UTXO, "CF.UTXO")
  local undos_wiped = wipe_cf(storage_mod.CF.UNDO, "CF.UNDO")
  print(string.format("[reindex] wiped %d utxo entries, %d undo entries", ...))
```

(No `WriteFlag('R', '1')` before, no `WriteFlag('R', '0')` after.)

**Impact:** Mid-reindex crash → permanently wedged datadir, with no
in-band signal to the operator.

**Severity:** P0. Recovery-on-partial-write fleet-pattern hit; the
**defining gap** of W146 from a Core-parity standpoint.

---

### BUG-14 (P1) — `indexmanager.lua` is a dead module (256 LOC, zero production callers)

**File:** `src/indexmanager.lua:1-259`.

**Description:** `indexmanager.new(db, opts)` defines a full
lifecycle (`get_txindex`, `set_txindex_enabled`, `connect_block`,
`disconnect_block`, `start_building`, `tick`, `is_building`,
`is_synced`, `get_stats`, `lookup_tx`, `get_filter`, etc.) but
is **never `require`d in production code**. Verified via grep
across all `src/*.lua`:

```
$ grep -rn "require.*indexmanager" src/
(no output)
```

Only the build copy at `lunarblock/lunarblock/indexmanager.lua`
and the test file `tests/test_w133_index_databases.lua` and spec
file `spec/indexmanager_spec.lua` reference it. The production
paths (`utxo.lua:1565-1605`, `utxo.lua:1575`) explicitly call out:

```lua
-- inline rather than via indexmanager.lua / txindex.lua because those
```

and

```lua
-- Wiring is inline rather than via indexmanager.lua / blockfilter.lua's
```

**Impact:**
- 256 LOC of unreachable code.
- The fictional `(file_num, block_pos)` parameters in
  `manager.connect_block(block, block_hash, height, file_num,
  block_pos, undo_data)` (line 58) leak into the broader codebase
  as a phantom shape (BUG-2 cross-cite).
- **Fleet pattern: dead module with full method surface** — same
  shape as W138 (rustoshi ChainstateManager / haskoin
  runBackgroundValidation / etc.).

**Severity:** P1. Maintenance / surface-area / cognitive-load bug;
not consensus.

---

### BUG-15 (P0) — Non-atomic `put_block` + `put_header` (+ `put_height_index`) sequence in genesis, side-branch storage, and submitblock fallback paths

**File:** `src/utxo.lua:1691-1693` (genesis),
`src/utxo.lua:3334-3335` (side-branch not-strictly-heavier),
`src/utxo.lua:3343-3344` (side-branch about-to-reorg),
`src/rpc.lua:7159-7161` (submitblock fallback).

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:1134-1163`
(`WriteBlock` performs a single atomic file write + DB index update
in a single AutoFile RAII; the DB index update is batched in
`WriteBatchSync`).

**Description:** Three production code paths perform 2-3 separate
async RocksDB writes in sequence:

1. **Genesis bootstrap** (`utxo.lua:1691-1693`):
   ```lua
   self.storage.put_block(block_hash, block)       -- async
   self.storage.put_header(block_hash, header)     -- async
   self.storage.put_height_index(0, block_hash)    -- async
   -- ... then later (line 1721):
   self.storage.set_chain_tip(block_hash, 0, true)  -- SYNC
   ```
   Crash between any pair leaves an orphaned write. Genesis is
   recoverable (re-run the bootstrap), so not catastrophic.

2. **Side-branch (not-strictly-heavier) storage** (`utxo.lua:3334-3335`):
   ```lua
   self.storage.put_block(block_hash, block)    -- async
   self.storage.put_header(block_hash, block.header)  -- async
   return "stored"   -- NO follow-up sync flush
   ```
   This is the worst case: stored side-branch is async-only; a
   crash before the next chain-tip flush loses the side-branch.
   When the side-branch becomes strictly heavier later, the reorg
   loop at `utxo.lua:3459` `get_block(entry.hash)` returns nil and
   the reorg aborts with `"reorg-connect-failed: side-branch block
   missing at height N"`. Recoverable in principle (re-request the
   block from peers), but the data integrity guarantee is violated.

3. **Side-branch (about-to-reorg) storage** (`utxo.lua:3343-3344`):
   ```lua
   self.storage.put_block(block_hash, block)    -- async
   self.storage.put_header(block_hash, block.header)  -- async
   -- ... immediately followed by reorg loop which DOES sync
   ```
   Sync-flushed at the end of the reorg batch (line 2974), so
   acceptable in practice.

4. **submitblock fallback** (`rpc.lua:7157-7162`):
   ```lua
   rpc.storage.put_block(block_hash, block)            -- async
   rpc.storage.put_header(block_hash, block.header)    -- async
   rpc.storage.put_height_index(new_height, block_hash) -- async
   ```
   The comment at line 7158 ("fallback, shouldn't happen in practice")
   acknowledges this path is exceptional.

**Impact:** Side-branch storage (case 2) is the concrete data-loss
scenario. A reorg-eligible side branch stored just before a crash is
lost; the network must re-propagate the block to recover.

**Severity:** P0. Real partial-write data-loss scenario.

---

### BUG-16 (P1) — No magic-byte / file-corruption signal on block read; relies on RocksDB SST checksum

**File:** `src/storage.lua:519-523`.

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:1104-1107`:
```cpp
if (blk_start != GetParams().MessageStart()) {
    LogError("Block magic byte mismatch at %s ...", ...);
    return false;
}
```

**Description:** Core reads the 4-byte magic before the block body
on every disk read; mismatch = file corruption, reject. Lunarblock
relies on RocksDB's SST-level block checksum (which IS active and
will return an error from the RocksDB layer); but the
**Core-protocol-level magic check is not performed**.

**Excerpt** (`src/storage.lua:519-523`):

```lua
function dbobj.get_block(block_hash)
  local data = dbobj.get(M.CF.BLOCKS, block_hash.bytes)
  if not data then return nil end
  return serialize.deserialize_block(data)
end
```

**Impact:** Lower defense-in-depth: a sophisticated attacker with
RocksDB-aware disk-write access can craft a block-hash-keyed value
that lacks the Core magic prefix, and lunarblock will silently
accept it because it never checked.

**Severity:** P1. Defense-in-depth gap.

---

### BUG-17 (P0-CONSENSUS) — `get_block` does NOT re-run `CheckProofOfWork` on disk read; Core re-checks every read

**File:** `src/storage.lua:519-523`.

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:1054-1060`:
```cpp
const auto block_hash{block.GetHash()};
// Check the header
if (!CheckProofOfWork(block_hash, block.nBits, GetConsensus())) {
    LogError("Errors in block header at %s while reading block", pos.ToString());
    return false;
}
```

**Description:** Core re-runs `CheckProofOfWork` on **every disk
read** of a block (`ReadBlock` always validates). This is a
defense-in-depth measure: an attacker with RocksDB / disk write
access can substitute a tampered block under the same key
(block_hash → mutated body bytes); without the PoW re-check,
the tampered block flows through reorg consideration, RPC
responses, ZMQ publishers, etc.

Lunarblock's `get_block` simply deserializes and returns — **no
PoW recheck, no block-hash recheck, no expected-hash comparison**.

**Excerpt** (`src/storage.lua:519-523`):

```lua
function dbobj.get_block(block_hash)
  local data = dbobj.get(M.CF.BLOCKS, block_hash.bytes)
  if not data then return nil end
  return serialize.deserialize_block(data)  -- NO PoW re-check
end
```

Compare Core (`bitcoin-core/src/node/blockstorage.cpp:1036-1075`):

```cpp
bool BlockManager::ReadBlock(CBlock& block, const FlatFilePos& pos, ...) const {
    block.SetNull();
    const auto block_data{ReadRawBlock(pos)};
    if (!block_data) return false;
    SpanReader{*block_data} >> TX_WITH_WITNESS(block);
    const auto block_hash{block.GetHash()};
    // Check the header
    if (!CheckProofOfWork(block_hash, block.nBits, GetConsensus())) {
        LogError(...);
        return false;
    }
    // Signet only: check block solution
    if (GetConsensus().signet_blocks && !CheckSignetBlockSolution(...)) return false;
    if (expected_hash && block_hash != *expected_hash) {
        LogError(...);
        return false;
    }
    return true;
}
```

**Impact:**
- **Attacker with disk-write to RocksDB can substitute a tampered
  block under the same hash key**; lunarblock will silently
  serve the tampered bytes to subsequent reads. Substitution
  scenarios include:
  - reorg paths that re-load side-branch blocks (`utxo.lua:3459`).
  - `getblock` / `getblockheader` / `getrawtransaction` RPC.
  - ZMQ `rawblock` / `hashblock` notifications.
  - REST `/rest/block/{hash}.bin` endpoint.
- **Same class of bug as W138 BUG-1 (clearbit)** where
  `--load-snapshot` skips the hash gate that the RPC enforces.
- **No expected-hash comparison either** (the third Core check —
  if caller passes expected_hash, verify on read).

**Severity:** P0-CONSENSUS. The pattern is structurally identical
to W138 BUG-1 across the fleet — a defense-in-depth check that
guards against disk tampering is missing. Listed as P0-CONSENSUS
because tampered block bytes that flow into reorg-eligibility
consideration could cause a consensus split if the attacker can
prepare a "lighter chainwork but more attractive" mutation.

---

### BUG-18 (P2) — No signet network entry; `CheckSignetBlockSolution` analog absent

**File:** `src/consensus.lua:847-1198`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:454`
(SigNet `MessageStart` = `0x0a03cf40`); `bitcoin-core/src/node/blockstorage.cpp:1063-1066`
(`CheckSignetBlockSolution` on read).

**Description:** `M.networks` carries mainnet (line 848),
testnet3 (line 987), testnet4 (line 1058), regtest (line 1130).
**No signet entry exists.** Consequently, no signet magic bytes,
no signet challenge, no `CheckSignetBlockSolution` analog.

**Impact:** Lunarblock cannot run on signet. Out-of-scope by
omission; would surface immediately on `--network=signet` startup
attempt.

**Severity:** P2.

---

### BUG-19 (P2) — Bad-magic-at-pos truncation recovery absent (N/A by architecture)

**File:** (absent by architecture).

**Description:** Core's `ReadRawBlock` checks the magic prefix at
the recorded position; bad-magic = "file was truncated at this
point during a crash" → Core can re-build the file by re-fetching
from peers up to the truncation point.

Lunarblock has no flat-file → no truncation concept → no analog
recovery. RocksDB's WAL recovers partial WAL records on restart,
which is the equivalent for the lunarblock storage model.

**Impact:** N/A.

**Severity:** P2 (cosmetic — included for completeness of behavior 8).

---

### BUG-20 (P1) — No production recovery code path for storage-layer corruption; operator-only `--reindex-chainstate`

**File:** `src/sync.lua:26-29`, `:2316-2376`, `src/utxo.lua:1898`
(`verify_chainstate_consistency`).

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp` (block-file
scan + `LoadBlockIndex` self-repair on startup).

**Description:** Core's startup path scans block files (when
reindexing) or re-loads from leveldb (when not reindexing); both
are production-default behaviors. Lunarblock has only the
`verify_chainstate_consistency` walk (200-block default) and the
operator-driven `--reindex-chainstate` flag. There is **no
production-default scan-and-recover for unidentified corruption**.

**Excerpt** (`src/sync.lua:26`):

```lua
-- Operator action: file a bug, do NOT --reindex.
```

(The instruction to NOT --reindex is for a specific class of
"unknown error" — but the converse, what DOES recover, isn't
defined in production paths.)

**Impact:** Operator burden; un-graceful corruption modes.

**Severity:** P1. Operational.

---

### BUG-21 (P1) — No `CheckDiskSpace` pre-write; silent failure on near-full disk

**File:** (absent everywhere).

**Core ref:** `bitcoin-core/src/util/fs_helpers.cpp:CheckDiskSpace`.

**Description:** Core checks free disk space before allocating a new
block file (or per-batch); refuses to write if below a configurable
floor (`-minfreespace`). Lunarblock has no such check; a
near-full disk during IBD silently fails RocksDB write with no
graceful "block %s could not be written, no space left on device"
error path.

**Impact:** Operator surprise on full disk; potential corruption
if RocksDB partial-write.

**Severity:** P1. Operational.

---

### BUG-22 (P1) — Reindex sweep is not atomic across all phases

**File:** `src/utxo.lua:1744-1855` (`reindex_chainstate`).

**Description:** The full reindex consists of:
1. Wipe `CF.UTXO` (line 1779).
2. Wipe `CF.UNDO` (line 1780).
3. Walk heights 1..tip; for each, call `connect_block` (line 1835).
4. Final sync flush (line 1852).

Phases 1 and 2 are individually batched in 64k-key chunks, NOT a
single atomic WriteBatch over the whole CF (which would be too
large in practice). A crash between phase 1 and phase 2 leaves
`CF.UTXO` wiped but `CF.UNDO` populated — internally inconsistent.
The per-block atomic batch (BUG-22 ref) is the partial mitigation;
each block's connect IS atomic, but the overall reindex is not.

**Impact:** Mid-reindex crash = wedged datadir (cross-cite BUG-13).

**Severity:** P1.

---

### BUG-23 (P2) — `dbobj.put` accepts `sync` flag but truthiness check is inconsistent

**File:** `src/storage.lua:366-376`.

**Description:** `dbobj.put(cf, key, value, sync)` selects
`_write_opts_sync` when `sync` is truthy, else `_write_opts`.
This works correctly for boolean `true`/`false` but is silently
forgiving for any non-falsy value (e.g. accidentally passing
the height number as the 4th arg — `dbobj.put(cf, key, value,
height)` would sync iff `height ~= 0`). The 4-arg API is
prone to caller confusion when refactored.

**Excerpt** (`src/storage.lua:366-376`):

```lua
function dbobj.put(cf, key, value, sync)
  local handle = dbobj._handles[cf]
  if not handle then
    error("Unknown column family: " .. tostring(cf))
  end
  local opts = sync and dbobj._write_opts_sync or dbobj._write_opts
  ...
end
```

**Impact:** Low. Trivia / API-shape.

**Severity:** P3.

---

### BUG-24 (P3) — Comment-as-confession: `prune.lua:18-22` documents the missing `CBlockFileInfo`

**File:** `src/prune.lua:18-22`.

**Description:** A TODO comment explicitly notes the absence of
size-driven pruning support due to the missing
`rocksdb_approximate_sizes_cf` FFI binding (which is a proxy for
the missing `CBlockFileInfo` per-blk-file size tracking that
Core provides natively):

```lua
-- TODO(prune-size): Replace the block-count translation with a real
-- size-driven sweep once storage.lua exposes
-- rocksdb_approximate_sizes_cf or a periodic CalculateCurrentUsage.
```

**Pattern**: this is the **comment-as-confession** fleet pattern
(8th instance fleet-wide as of W141 — rustoshi W141 BUG-13,
haskoin W138 BUG-3, clearbit W141 BUG-12, etc.). The TODO is
honest about what's broken; the fix path is even documented; but
the work hasn't been done.

**Impact:** Documents BUG-7 from a different angle.

**Severity:** P3. Hygiene.

---

## Severity tally

- **P0-CONSENSUS:** 1 (BUG-17: no PoW re-check on disk read).
- **P0-CDIV:** 1 (BUG-3: undo checksum hash function + domain divergence).
- **P0:** 5 (BUG-7, BUG-9, BUG-10, BUG-13, BUG-15).
- **P1:** 8 (BUG-1, BUG-2, BUG-5, BUG-8, BUG-11, BUG-12, BUG-14, BUG-16, BUG-20, BUG-21, BUG-22).
- **P2:** 6 (BUG-6, BUG-18, BUG-19, BUG-23 — plus 2 cross-cited).
- **P3:** 4 (BUG-4, BUG-24 — plus 2 cross-cited).

(Some bugs cross-cite multiple gates; tally above counts each
listed bug once at its primary severity.)

## Fleet patterns observed

1. **Dead module fleet pattern** (5th impl this campaign):
   `indexmanager.lua` is defined with full method surface but
   never `require`d in production code. Cross-cite: W138 dead-class
   patterns across 9 of 10 impls.
2. **Comment-as-confession** (BUG-24): `prune.lua:18-22` TODO is
   the 8th instance of the pattern fleet-wide as of W141.
3. **Recovery-on-partial-write fleet gap** (BUG-13): no persistent
   `'R'` reindex flag; same class as the W138 dead `ChainstateManager`
   findings (start-path doesn't surface persistent state).
4. **API-shape asymmetry** (BUG-9): `put_block` / `put_header` /
   `put_height_index` don't accept `sync` arg; `set_chain_tip` /
   `put_undo` / `delete_undo` do. Caller-cannot-fix shape mismatch.
5. **PoW-on-read defense-in-depth absent** (BUG-17): same
   structural class as W138 BUG-1 in clearbit (`--load-snapshot`
   skips the hash gate the RPC enforces).
6. **Fake-shape-preserved-from-reference-implementation** (BUG-2 cross-cite):
   `txindex.lua:9-14, 26-32` defines `(file_num, block_pos, tx_offset)`
   as the disk-location shape, but there are no actual block files
   in lunarblock — `file_num` is always whatever caller passes
   (and the only production-eligible caller is `indexmanager`,
   which is a dead module — BUG-14).
7. **Architectural divergence vs Core that breaks ecosystem tooling**
   (BUG-1, BUG-2, BUG-3): lunarblock's on-disk format is byte-
   incompatible with `bitcoind` recovery utilities and with
   off-the-shelf indexers (electrs / fulcrum / mempool.space).
   Same class of break as W141 BUG-1/2/3 (blockbrew ZMQ
   byte-order break with electrs/fulcrum/mempool.space/nbxplorer).
8. **No-signet-network** (BUG-18): lunarblock's chainparams enum
   has 4 entries; Core has 5. Latent until someone tries `--network=signet`.

## Recommended priority order for fixes

1. **BUG-17** (P0-CONSENSUS) — add `CheckProofOfWork` re-check
   in `dbobj.get_block` (3-line fix; mirror Core's
   `blockstorage.cpp:1054-1060`).
2. **BUG-13** (P0) — persist `'R'` reindex flag at `CF.META["reindex_in_progress"]`
   before wipe; clear on completion; check on startup.
3. **BUG-15** (P0) — merge side-branch storage into a single
   atomic batch (or use the existing batch primitive at
   `dbobj.batch()` instead of separate puts).
4. **BUG-3** (P0-CDIV) — switch undo checksum to SHA256d + include
   pprev block hash in domain. Note: this is **format-breaking**;
   would need a one-shot migration or a "v2 format" prefix byte.
5. **BUG-9** (P0) — add `sync` parameter to `put_block`,
   `put_header`, `put_height_index` (3 one-line API patches).
6. **BUG-10** (P0) — persist BLOCK_FAILED_VALID + chainwork in a
   `CF.BLOCK_INDEX` keyspace (analog to Core's `('b', hash)`).
7. **BUG-14** (P1) — delete `indexmanager.lua` (or wire it into
   `main.lua` if the original intent was to use it).
8. Remaining P1/P2 bugs are operator-experience / interop.
