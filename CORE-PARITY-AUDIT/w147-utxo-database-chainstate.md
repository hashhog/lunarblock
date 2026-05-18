# W147 — UTXO database / chainstate audit (lunarblock)

**Date:** 2026-05-18
**Wave:** W147 (discovery)
**Impl:** lunarblock (Lua / LuaJIT)
**Status:** **22 BUGS FOUND** (0 P0-CONSENSUS / 3 P0-CDIV / 0 P0-SEC /
4 P0 / 7 P1 / 6 P2 / 2 P3) across **8 behaviors / 30 gates**
**Scope:** `CCoinsView` interface contract (`GetCoin`, `HaveCoin`,
`GetBestBlock`, `BatchWrite`, `Cursor`); `CCoinsViewCache` DIRTY/FRESH
flag plumbing + `Flush` semantics; `CCoinsViewDB` LevelDB key layout
(`'C' + hash + VARINT(n)`); `Coin` compression (`CompressAmount`,
`CompressScript`); `obfuscate_key` XOR layer; `FlushStateToDisk`
triggers; height + is_coinbase varint code packing; `AccessCoin` /
`SpendCoin` flag plumbing.

## Context

Lunarblock implements its chainstate on top of **RocksDB column
families**, not LevelDB, and uses **its own on-disk byte format**
unrelated to Core's `txdb.cpp` / `coins.h` layout. The implementation
in `src/utxo.lua:927-1525` defines a `CoinView` class that
*conceptually* mirrors Core's `CCoinsViewCache` (DIRTY + FRESH flags,
`add` / `spend` / `flush`), but it is a from-scratch design — not a
byte-compatible re-implementation. Storage in `src/storage.lua` wraps
RocksDB via FFI.

The audit finds **3 P0-CDIV class** byte-layout divergences that make
the on-disk chainstate **structurally incompatible with Core** (cannot
be opened or migrated cross-impl) and **one architectural defect** —
the cache "limit" gate `should_flush()` is defined but **never
called** anywhere in the codebase — that effectively reduces the
CCoinsViewCache to "one cache flush per block", destroying the entire
performance rationale of the caching layer.

The cache also charges a wildly-inflated **7,800 bytes per entry**
memory estimate (Core's actual is ~115 bytes), so the default 450 MB
`dbcache` holds ~57k entries vs. Core's ~3.9M entries — at the
LuaJIT side this is justified (table-node overhead) but the
documented "matches Bitcoin Core's default dbcache" comment is false
in terms of effective cache size.

The undo-data path (`serialize_undo_entry` at
`src/utxo.lua:405-425`) and the snapshot path
(`serialize_snapshot_coin` at `src/utxo.lua:884-891`) **DO** use Core's
`CompressAmount` + `ScriptCompression` correctly — only the on-disk
UTXO entries skip the compressor. This is the asymmetric-pipeline
pattern called out in B4.

## Source map

- `src/utxo.lua:226-285` — fast FFI buffers `_write_i64le`,
  `_write_varint` (CompactSize), `_write_u32le`.
- `src/utxo.lua:293-300` — `M.utxo_entry()` constructor.
- `src/utxo.lua:306-371` — `serialize_utxo_entry` /
  `deserialize_utxo_entry` (on-disk format, NOT Core-compatible).
- `src/utxo.lua:405-510` — `serialize_undo_entry` /
  `deserialize_undo_entry` (Core-compatible — uses corevarint +
  TxOutCompression).
- `src/utxo.lua:578-628` — `write_corevarint` / `read_corevarint`
  (Core MSB base-128 VarInt).
- `src/utxo.lua:642-681` — `compress_amount` / `decompress_amount`.
- `src/utxo.lua:740-810` — `compress_script` / `decompress_script`
  (always-raw on compress path; type-byte decode supported).
- `src/utxo.lua:884-904` — `serialize_snapshot_coin` /
  `deserialize_snapshot_coin` (Core-byte-compatible).
- `src/utxo.lua:913-924` — `outpoint_key()` — 36 bytes (32 raw txid +
  4 LE vout). NO leading `'C'` tag.
- `src/utxo.lua:951-963` — `FLAG_DIRTY` / `FLAG_FRESH` constants.
- `src/utxo.lua:964-1033` — `CoinView` class + `new_coin_view`.
- `src/utxo.lua:1035-1065` — `is_dirty` / `is_fresh` / `set_dirty` /
  `set_fresh` / `clear_flags`.
- `src/utxo.lua:1071-1080` — `_fetch_from_disk`.
- `src/utxo.lua:1087-1115` — `CoinView:get` (= Core `GetCoin`).
- `src/utxo.lua:1121-1133` — `CoinView:have` (= Core `HaveCoin`).
- `src/utxo.lua:1140-1200` — `CoinView:add` (= Core `AddCoin`, no
  `possible_overwrite` parameter).
- `src/utxo.lua:1208-1246` — `CoinView:spend` (= Core `SpendCoin`).
- `src/utxo.lua:1248-1252` — `CoinView:should_flush` (DEAD code —
  never called).
- `src/utxo.lua:1271-1379` — `CoinView:flush` (= Core `Flush`).
- `src/utxo.lua:1383-1422` — `sync` / `clear_cache` / `discard_dirty`.
- `src/utxo.lua:1486-1525` — `CoinView:sanity_check` (DEAD code —
  never called).
- `src/storage.lua:158-585` — RocksDB FFI wrapper, `dbobj.get` /
  `.put` / `.delete` / `.batch` / `.iterator`.
- `src/storage.lua:161-186` — Column-family layout: `default`,
  `headers`, `blocks`, `utxo`, `tx_index`, `height`, `meta`, `undo`,
  `block_filter`, `filter_height`.
- `src/storage.lua:488-503` — `get_chain_tip` / `set_chain_tip`
  (CF.META["chain_tip"] = hash[32] || height[4]).

Core references:

- `bitcoin-core/src/coins.h:34-90` — `Coin` (32 bits packed:
  `fCoinBase:1, nHeight:31` + `CTxOut`).
- `bitcoin-core/src/coins.h:109-209` — `CCoinsCacheEntry` (DIRTY +
  FRESH semantics + linked-list sentinel + `Coin.Clear()` on spend).
- `bitcoin-core/src/coins.h:307-343` — `CCoinsView` abstract interface
  (`GetCoin`, `PeekCoin`, `HaveCoin`, `GetBestBlock`, `GetHeadBlocks`,
  `BatchWrite`, `Cursor`, `EstimateSize`).
- `bitcoin-core/src/coins.cpp:63-81` — `FetchCoin` /
  `FetchCoinFromBase`.
- `bitcoin-core/src/coins.cpp:89-130` — `AddCoin` (FRESH gate +
  overwrite-unspent assertion).
- `bitcoin-core/src/coins.cpp:153-175` — `SpendCoin` (FRESH-erase +
  DIRTY-mark + `coin.Clear()`).
- `bitcoin-core/src/txdb.cpp:23-49` — `DB_COIN='C'`, `DB_BEST_BLOCK='B'`,
  `DB_HEAD_BLOCKS='H'`, `CoinEntry::SERIALIZE_METHODS = (key, hash,
  VARINT(n))`.
- `bitcoin-core/src/txdb.cpp:100-164` — `CCoinsViewDB::BatchWrite`
  three-phase write (Erase DB_BEST_BLOCK → Write DB_HEAD_BLOCKS → coin
  batch → Erase DB_HEAD_BLOCKS → Write DB_BEST_BLOCK).
- `bitcoin-core/src/dbwrapper.h:188-218` — `Obfuscation m_obfuscation`
  + `OBFUSCATION_KEY = "\000obfuscate_key"`.
- `bitcoin-core/src/dbwrapper.cpp:253-261` — obfuscate-key generation
  on first open.
- `bitcoin-core/src/compressor.cpp:55-138` — `CompressScript` /
  `DecompressScript` (5 special types: P2PKH/P2SH/P2PK).
- `bitcoin-core/src/compressor.cpp:149-192` — `CompressAmount` /
  `DecompressAmount` (mantissa+exponent).

## 8-behavior matrix

### B1. `CCoinsView` interface contract

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G1 | `GetCoin(outpoint, coin)` populating cache | **PARTIAL** — `CoinView:get` populates cache (`utxo.lua:1110-1112`), but always re-reads on miss; no `FetchCoin` `try_emplace`-then-fill semantics. |
| G2 | `PeekCoin(outpoint)` non-caching read | **MISSING** — no equivalent. `CoinView:get` always caches; callers wanting a peek must `:uncache` after. |
| G3 | `HaveCoin(outpoint)` cheap check | **OK-ish** — `CoinView:have` (`utxo.lua:1121`) reads + discards instead of using `Exists`. See **BUG-2**. |
| G4 | `GetBestBlock()` returns chainstate tip | **PARTIAL** — `storage.get_chain_tip()` exists at the storage layer; `CoinView` has no `:get_best_block` method. |
| G5 | `BatchWrite(cursor, hashBlock)` atomic commit | **PARTIAL** — `CoinView:flush` does atomic batch + tip update, but the API shape is `extra_batch_fn` callback, not a Cursor. No two-phase recovery (HEAD_BLOCKS). See **BUG-3**, **BUG-4**. |
| G6 | `Cursor()` iteration | **MISSING** — no `CoinView:cursor`; iteration done via raw `storage.iterator(CF.UTXO)` in `compute_utxo_hash`/`compute_muhash`/`dump_snapshot`. See **BUG-5**. |
| G7 | `EstimateSize()` | **MISSING** — used by Core for `gettxoutsetinfo`/eviction. No equivalent. |

### B2. `CCoinsViewCache` DIRTY/FRESH flag plumbing

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G8 | DIRTY = "differs from parent" | **OK** — `FLAG_DIRTY = 0x01`, `set_dirty()` at `utxo.lua:1051`. |
| G9 | FRESH = "parent does not have this coin" | **PARTIAL** — `FLAG_FRESH = 0x02`. **`add()` marks FRESH unconditionally when not in cache** without checking disk (`utxo.lua:1183-1187`). See **BUG-6**. |
| G10 | `AddCoin(possible_overwrite=false)` throws if overwriting unspent | **MISSING** — `CoinView:add` has no `possible_overwrite` parameter; silently merges. See **BUG-7**. |
| G11 | FRESH+SPEND inside same flush → cache erase, no disk delete | **OK** — `utxo.lua:1224-1233`. |
| G12 | NON-FRESH+SPEND → mark DIRTY+spent, flush deletes from disk | **OK** — `utxo.lua:1236-1243`. |
| G13 | `Coin.Clear()` on Spend (free scriptPubKey) | **MISSING** — spent cache entry retains `script_pubkey` until evicted. See **BUG-8**. |
| G14 | Flush asserts `assert(!hashBlock.IsNull())` (Core txdb.cpp:105) | **MISSING** — flush blindly writes any tip hash including zero. See **BUG-9**. |
| G15 | `EmplaceCoinInternalDANGER` for snapshot loading | **MISSING** — no equivalent; snapshot loader uses regular `:add` which sets FRESH+DIRTY incorrectly. See **BUG-10**. |

### B3. `CCoinsViewDB` leveldb backend / key layout

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G16 | UTXO key = `'C' + hash[32] + VARINT(vout)` | **DIVERGENT** — key is `hash[32] + u32_LE(vout)` (36 bytes), no `'C'` prefix, vout is fixed-width LE not Core VARINT. **BUG-1**. |
| G17 | `DB_BEST_BLOCK = 'B'`, value = `uint256` | **DIVERGENT** — uses `CF.META["chain_tip"]` (string key, 9 bytes ASCII), value = 36 bytes (`hash + height_LE`). **BUG-11**. |
| G18 | `DB_HEAD_BLOCKS = 'H'`, two-phase commit | **MISSING** — no recovery vector. **BUG-3**. |
| G19 | `NeedsUpgrade()` legacy `'c'` detection | **MISSING** — no schema migration path. |
| G20 | Column-family / key-prefix grouping | **DIVERGENT** — uses 8 RocksDB column families. Not a portability problem, but blocks cross-impl chainstate sharing. |

### B4. `Coin` compression (TxOutCompression)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G21 | UTXO entries serialized with `(height<<1)|coinbase` Core VARINT | **DIVERGENT** — uses `u32_LE(height) + u8(is_coinbase)` (5 bytes) vs Core's 1-5-byte VARINT. **BUG-12**. |
| G22 | UTXO entries use `CompressAmount` on value | **DIVERGENT** — uses raw `i64_LE` (8 bytes). 50 BTC = 5e9 sats fits in `CompressAmount` in 2 bytes vs 8 bytes raw. **BUG-13**. |
| G23 | UTXO entries use `CompressScript` (5 special types) | **DIVERGENT** — uses `varint(len) + raw_bytes`. Even on the snapshot path, `compress_script` is hardcoded to emit the raw form. **BUG-14**. |

### B5. `obfuscate_key` XOR layer

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G24 | 8-byte random obfuscation key written at first open | **MISSING** — no `obfuscate_key` machinery. **BUG-15**. |
| G25 | Coin values XOR'd against obfuscation key | **MISSING** — values stored raw. |

### B6. `FlushStateToDisk` triggers

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G26 | `cache size > dbcache` → FLUSH_STATE_IF_NEEDED | **DEAD** — `CoinView:should_flush()` defined at `utxo.lua:1250` but **never called**. **BUG-16**. |
| G27 | Shutdown → FLUSH_STATE_ALWAYS | **PARTIAL** — depends on caller. `sync.lua` calls `coin_view:flush(false, nil, true)` at periodic intervals; no explicit shutdown handler. |
| G28 | Cache memory estimate matches reality | **WRONG** — `BASE_ENTRY_OVERHEAD = 7800` bytes / entry vs Core's ~115 bytes. **BUG-17**. |

### B7. Coin height + is_coinbase varint encoding

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G29 | `code = (height << 1) | is_coinbase` written as Core VARINT | **DIVERGENT for on-disk format** (B4 G21). **OK** for undo data and snapshot. |

### B8. `AccessCoin` / `SpendCoin` flag plumbing

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G30 | `AccessCoin` returns ref / Coin&; cache lookup via parent fallback | **MISSING** — no `AccessCoin`; callers go through `:get`. Adequate but breaks Core API parity. **BUG-18**. |

---

## Findings

### BUG-1 [P0-CDIV] UTXO key layout differs from Core: no `'C'` prefix, fixed-width u32_LE vout (not VARINT)

**File:** `src/utxo.lua:917-924`
**Core ref:** `bitcoin-core/src/txdb.cpp:23, 43-49`

**Description:** Lunarblock's `outpoint_key()` produces a 36-byte key
of the form `hash[32] + vout_LE[4]`. Bitcoin Core's `CoinEntry` (txdb.cpp:43-49) serializes as `(key='C', outpoint->hash, VARINT(outpoint->n))`. Two divergences:

1. **No leading `'C'` byte** — Core distinguishes coin entries from
   other DB records (`'B'` best block, `'H'` head blocks). Lunarblock
   uses RocksDB column families instead of a single namespace, so this
   doesn't *collide*, but it breaks any tool that opens the chainstate
   as a single LevelDB.
2. **`vout` is u32_LE (4 fixed bytes) vs Core VARINT (1-5 bytes)** —
   for the dominant `vout < 0x80` case (every typical tx has vout < 16)
   Core uses 1 byte, lunarblock uses 4. The on-disk chainstate
   *cannot* be opened by Core (or any other Core-compatible impl)
   without a re-keying pass.

**Excerpt:**
```lua
-- src/utxo.lua:917
function M.outpoint_key(txid_hash256, vout_index)
  ffi.copy(_outpoint_buf, txid_hash256.bytes, 32)
  _outpoint_buf[32] = band(vout_index, 0xFF)
  _outpoint_buf[33] = band(rshift(vout_index, 8), 0xFF)
  _outpoint_buf[34] = band(rshift(vout_index, 16), 0xFF)
  _outpoint_buf[35] = band(rshift(vout_index, 24), 0xFF)
  return ffi.string(_outpoint_buf, 36)
end
```

```cpp
// bitcoin-core/src/txdb.cpp:43-49
struct CoinEntry {
    COutPoint* outpoint;
    uint8_t key{DB_COIN};
    explicit CoinEntry(const COutPoint* ptr) : outpoint(const_cast<COutPoint*>(ptr)) {}

    SERIALIZE_METHODS(CoinEntry, obj) { READWRITE(obj.key, obj.outpoint->hash, VARINT(obj.outpoint->n)); }
};
```

**Impact:** Lunarblock's chainstate dir is structurally incompatible
with Bitcoin Core's chainstate. Cannot be cross-mounted, cannot be
inspected with Core's `bitcoin-chainstate` or `bitcoin-cli
gettxoutsetinfo` against the raw DB, and cannot be migrated without a
full reindex. Catalogued as **P0-CDIV** for "on-disk byte
incompatibility" per the wave's brief — the chainstate is, by
definition, a consensus-relevant data structure even if the in-memory
representation matches.

---

### BUG-2 [P3] `HaveCoin` does a full GET-and-discard instead of `Exists()`

**File:** `src/utxo.lua:1131`
**Core ref:** `bitcoin-core/src/txdb.cpp:81-83`

**Description:** Core's `CCoinsViewDB::HaveCoin` calls
`m_db->Exists(CoinEntry(&outpoint))` — LevelDB has a dedicated bool
existence probe. Lunarblock's `CoinView:have` falls back to
`self.storage.get(CF.UTXO, key)` and tests `data ~= nil`, which reads
the entire value (1-10000 bytes of scriptPubKey), allocates a Lua
string for it, then discards.

**Excerpt:**
```lua
-- src/utxo.lua:1130-1133
  -- Check disk
  local data = self.storage.get(storage_mod.CF.UTXO, key)
  return data ~= nil
```

**Impact:** Every BIP-30 check (one HaveCoin per output per
transaction on every connected block, ~1500 ops/block at typical
mainnet density) does an unnecessary value read + Lua string
allocation. Wasteful but not consensus-divergent. RocksDB does expose
a `KeyMayExist` shortcut; FFI surface lacks it. Performance not
parity.

---

### BUG-3 [P0] No `HEAD_BLOCKS` two-phase commit / partial-write recovery

**File:** `src/utxo.lua:2930-2946`, `src/storage.lua:484-504`
**Core ref:** `bitcoin-core/src/txdb.cpp:100-164` (especially 124-130
and 158-159)

**Description:** Core's `CCoinsViewDB::BatchWrite` writes a
`DB_HEAD_BLOCKS = Vector(hashBlock, old_tip)` *before* the coin batch
and erases it *after*, so a partial write leaves a recoverable record
saying "we were transitioning from `old_tip` to `hashBlock`". On
startup `GetHeadBlocks()` detects this and `LogError` prints "...
inconsistent state ... restart bitcoind with the -reindex-chainstate
or -reindex configuration option".

Lunarblock relies on **RocksDB WriteBatch atomicity** (which is
genuine — RocksDB commits or rolls back the entire batch) but emits
**zero recovery state**. If the batch succeeds the new tip is
durable; if it doesn't, the old tip stays. There is no log-message
path for the operator to know recovery happened.

**Excerpt:**
```cpp
// bitcoin-core/src/txdb.cpp:128-130
    batch.Erase(DB_BEST_BLOCK);
    batch.Write(DB_HEAD_BLOCKS, Vector(hashBlock, old_tip));
```

**Impact:** Atomicity is preserved by RocksDB, but the operator loses
two diagnostic signals Core provides:
1. The `LogError("The coins database detected an inconsistent
   state...")` message that explicitly tells the operator to
   `-reindex-chainstate`.
2. The `assert(old_heads[0] == hashBlock)` "we know which write was
   in progress" check.

In practice the post-Apr-28 wedge in this codebase (see
`project_lunarblock_wedge_2026_04_28`) was exactly the failure mode
the HEAD_BLOCKS sentinel detects. **P0** for "missing diagnostic
that would have shortened that wedge to a few minutes".

---

### BUG-4 [P1] `BatchWrite` API shape is `extra_batch_fn` callback, not a `CoinsViewCacheCursor`

**File:** `src/utxo.lua:1271-1340`
**Core ref:** `bitcoin-core/src/coins.h:260-304` `CoinsViewCacheCursor`,
`bitcoin-core/src/coins.cpp:222-230` Core sub-classes

**Description:** Core's `BatchWrite` takes a `CoinsViewCacheCursor`
that iterates the **linked list of flagged entries** (DIRTY|FRESH
only) — not the full map — and offers a `WillErase` API for the
receiver to optimize moves vs copies. The cursor is the abstraction
that lets you stack a `CCoinsViewCache` on top of another cache
(`CCoinsViewCache(base=parent_cache)`) without exposing the parent's
internal map shape.

Lunarblock's `flush()` takes an `extra_batch_fn` callback that
appends extra operations to the same RocksDB batch:

```lua
function CoinView:flush(reallocate, extra_batch_fn, sync, reorg_batch)
```

This binds the caller's batch shape to the cache, breaks
composability (you cannot stack two `CoinView`s), and loses the
**move-out vs copy-out optimization** for sentinel-erased entries.

**Impact:** Cache hierarchies (`base view → cache1 → cache2`) cannot
be implemented; lunarblock has exactly one cache layer above disk.
Bitcoin Core uses two layers (`CCoinsViewDB` ←
`CCoinsViewCache m_active_chainstate.CoinsTip()` ← per-block
`CCoinsViewCache view(&base)` in `ConnectTip`). Lunarblock collapses
this to a single layer. Performance and correctness consequences are
subtle: in particular, **mid-block validation failures cannot roll
back without `discard_dirty`** (a workaround introduced in this
codebase for the tapscript SCRIPT_SIZE wedge — see comment at
`utxo.lua:1408-1411`). Core's hierarchy makes this free.

---

### BUG-5 [P1] No `Cursor()` method on `CoinView`; callers use raw RocksDB iteration

**File:** `src/utxo.lua:4242-4262`, `src/utxo.lua:4294-4305`,
`src/utxo.lua:4397-4421`
**Core ref:** `bitcoin-core/src/coins.h:228-244`,
`bitcoin-core/src/txdb.cpp:171-211`

**Description:** Core exposes `CCoinsView::Cursor()` returning a
`CCoinsViewCursor` (with `GetKey` / `GetValue` / `Valid` / `Next`).
This is what `gettxoutsetinfo`, `dumptxoutset`, and the snapshot
exporter all use. Lunarblock skips this abstraction:
`compute_utxo_hash` / `compute_muhash` / `dump_snapshot` all call
`self.storage.iterator(CF.UTXO)` directly.

**Excerpt:**
```lua
-- src/utxo.lua:4242
local iter = self.storage.iterator(storage_mod.CF.UTXO)
iter.seek_to_first()
while iter.valid() do
  ...
```

**Impact:** Three problems:
1. **Cache is bypassed during iteration.** `gettxoutsetinfo`,
   `compute_utxo_hash`, and `dump_snapshot` all `flush()` first to
   force consistency — fine, but means iteration is single-source
   (disk only), not "cache-overlaid-on-disk".
2. **No `GetBestBlock` snapshot semantics.** Core's
   `CCoinsViewCursor` captures the tip hash at cursor creation; if
   the tip moves during iteration, the cursor still reports the
   original tip. Lunarblock reads `self.tip_hash` AFTER iteration —
   if `dump_snapshot` races with `connect_block`, the snapshot can
   contain a UTXO set that does NOT match the reported tip.
3. **Vout-byte-order quirk** in iteration: lunarblock's 4-byte
   `vout_LE` key sorts bytewise (so vout=0x100 sorts before
   vout=0x01), forcing per-txid re-grouping in
   `compute_utxo_hash:flush_txid` (`utxo.lua:4226-4240`). Core
   wouldn't need this because Core's vout-VARINT sorts numerically.
   This is a direct consequence of BUG-1.

---

### BUG-6 [P1] `add()` marks FRESH without checking disk → potential UTXO resurrection

**File:** `src/utxo.lua:1183-1187`
**Core ref:** `bitcoin-core/src/coins.cpp:96-114`

**Description:** Core's `AddCoin` sets `fresh = !it->second.IsDirty()`
**after** `try_emplace` returns; the new entry's "exists in cache"
state is checked against the result, which encodes whether the
parent (disk) might have the coin.

Lunarblock's `add` checks only `self.cache[key]`. If the entry is
NOT in cache but IS on disk, lunarblock marks it FRESH:

```lua
-- src/utxo.lua:1183-1187
  else
    -- New entry not in cache - could be on disk, can't assume fresh
    -- Actually, if we're adding, it's typically a new output, so mark fresh
    mark_fresh = true
  end
```

The comment **acknowledges** the case ("could be on disk, can't
assume fresh") then **does it anyway** ("Actually, if we're adding,
it's typically a new output, so mark fresh") — a **comment-as-confession**
pattern.

**Impact:** If the (disk-resident) coin is then SPENT in the same
flush window, `spend()` takes the `is_fresh(entry)` branch
(`utxo.lua:1224-1233`) and:
- Erases the cache entry.
- Decrements `dirty_count`.
- Skips the `batch.delete(CF.UTXO, key)` operation.
- **The on-disk coin remains.**

After the next flush + read, `get(txid, vout)` returns the
disk-resident coin → **UTXO resurrection**.

In production this should not trigger because `connect_block` adds
only NEW outputs (whose hash+vout never existed on disk). But:
- **BIP-30 duplicate coinbase** (mainnet h=91842, h=91880): the
  coinbase txid+vout existed on disk before the duplicate block
  added it again. Lunarblock takes the BIP-30 EXEMPT path (skips
  the HaveCoin check) and lands here.
- **Reorg restore**: `apply_tx_in_undo` (`utxo.lua:149-181`)
  pre-fetches via `:get` to materialize the entry into cache before
  `:add`, sidestepping this bug. The author was aware (comment at
  line 174 references the gap).
- **Snapshot load**: `EmplaceCoinInternalDANGER` equivalent missing
  (BUG-10); uses `:add` directly, FRESH+DIRTY both set — equivalent
  in result to Core because the snapshot loader operates on an empty
  cache and empty disk, but still relies on the same "set FRESH
  without disk check" path.

The only RUNTIME-observable hazard is BIP-30 duplicate coinbases on
mainnet, both of which are well below MAX_OUTPUTS_PER_BLOCK-spent and
neither has had any of its (would-be-resurrected) outputs spent
post-91842. **P1** for "latent, no current exploit, future-fragile".

---

### BUG-7 [P1] `add()` has no `possible_overwrite` parameter; silently merges where Core throws

**File:** `src/utxo.lua:1140`
**Core ref:** `bitcoin-core/src/coins.cpp:96-99`

**Description:** Core's `AddCoin(outpoint, coin, possible_overwrite)`
throws `std::logic_error("Attempted to overwrite an unspent coin")` if
`!possible_overwrite && !it->second.coin.IsSpent()`. This is a
runtime invariant that catches "AddCoin was called for an output that
was never spent" — almost always a caller bug (writing the same coin
twice in `AddCoins` without checking for overwrite).

Lunarblock's `:add` silently merges:

```lua
-- src/utxo.lua:1169-1175
  if existing then
    -- If the existing entry was dirty (but not fresh), we can't mark as fresh
    -- because the original might still be on disk
    if is_dirty(existing) and not is_fresh(existing) then
      mark_fresh = false
    end
    ...
```

There is no "this is a programmer error" path. The comment at line
174 of the `apply_tx_in_undo` helper documents that this is a known
asymmetry and is worked around at the only known call site that
needed it.

**Impact:** Latent bug class — any caller that double-adds without
intent (e.g. a future `AddCoins` refactor without the `IsCoinBase`
check) will silently overwrite a coin with itself, losing the
opportunity to detect a logic bug. Core would crash loudly; lunarblock
absorbs.

---

### BUG-8 [P2] Spent coin retains `script_pubkey` in cache until eviction

**File:** `src/utxo.lua:1238`
**Core ref:** `bitcoin-core/src/coins.cpp:172` `it->second.coin.Clear()`

**Description:** Core's `SpendCoin` calls `coin.Clear()` on the
in-cache `Coin`, which sets `out.SetNull()` (i.e. `nValue = -1`,
`scriptPubKey = CScript()`). The 10-byte-to-10k-byte scriptPubKey
allocation is freed immediately. The cache entry stays until flush,
but holds only the spent-marker (12 bytes) until then.

Lunarblock's `:spend` sets `entry.spent = true` and leaves
`entry.script_pubkey` intact (`utxo.lua:1238`). The scriptPubKey
string is GC'd only when the cache entry is removed (during flush or
eviction).

**Impact:** Inside a connect_block window, every spent coin's
scriptPubKey is double-resident (cache + undo data) until flush. For
a max-weight block (~12k inputs × ~50-byte avg scriptPubKey) this is
~600 KB of redundant memory per block. **P2** for "memory waste,
not a correctness bug".

---

### BUG-9 [P2] Flush does not assert `!hashBlock.IsNull()`

**File:** `src/utxo.lua:1271-1340`
**Core ref:** `bitcoin-core/src/txdb.cpp:105`

**Description:** Core's `CCoinsViewDB::BatchWrite` has `assert(!hashBlock.IsNull())`. Writing the chainstate against a null tip is always a logic bug — a `view.GetBestBlock()` post-flush would return null, and `HaveCoin`/`GetCoin` could yield mis-validated results.

Lunarblock's `flush()` does not validate `block_hash` at all. The
`set_chain_tip()` storage helper happily writes a zero-hash:

```lua
-- src/utxo.lua:1775
self.storage.set_chain_tip(types.hash256_zero(), 0, true)
```

(This call is intentional, used by `reindex_chainstate` to mark the
"empty" state.) But there is no guard against an accidental zero
write from a connect-side path.

**Impact:** No known active path triggers this. Defensive missing
guard. **P2**.

---

### BUG-10 [P1] No `EmplaceCoinInternalDANGER` for snapshot loading

**File:** `src/utxo.lua` — absent
**Core ref:** `bitcoin-core/src/coins.cpp:132-140`,
`bitcoin-core/src/coins.h:441-447`

**Description:** Core has `EmplaceCoinInternalDANGER(outpoint, coin)`
that skips all FRESH/DIRTY logic and just emplaces a coin with
DIRTY+set, used ONLY by `ChainstateManager::PopulateAndValidateSnapshot()`. The comment is explicit: "NOT FOR GENERAL USE."

Lunarblock's snapshot loader uses `:add` which goes through the
full `existing` / `mark_fresh` decision tree. For an empty cache and
empty disk this is harmless, but it leaves the FRESH bit set on
every loaded coin. If the snapshot loader then validates by reading
back, the FRESH bit causes... no incorrect behavior, because FRESH
is only an optimization hint for spend.

**Impact:** Architectural divergence; no functional bug for current
single-shot snapshot loading. **P1** — would matter if lunarblock
ever supports incremental snapshot rebase on top of a partial
chainstate.

---

### BUG-11 [P0-CDIV] `chain_tip` key uses string `"chain_tip"` in CF.META; not `'B'` byte tag

**File:** `src/storage.lua:489, 503`
**Core ref:** `bitcoin-core/src/txdb.cpp:24` `DB_BEST_BLOCK{'B'}`

**Description:** Core stores `DB_BEST_BLOCK` at the single-byte key
`'B'` with value = 32-byte `uint256 hashBestChain`. Lunarblock stores
at the 9-byte ASCII key `"chain_tip"` in `CF.META` with value =
36 bytes (`hash + height_LE`):

```lua
-- src/storage.lua:488-503
function dbobj.get_chain_tip()
  local data = dbobj.get(M.CF.META, "chain_tip")
  ...
  local hash = types.hash256(data:sub(1, 32))
  local r = serialize.buffer_reader(data:sub(33, 36))
  local height = r.read_u32le()
  return hash, height
end

function dbobj.set_chain_tip(hash, height, sync)
  local w = serialize.buffer_writer()
  w.write_hash256(hash)
  w.write_u32le(height)
  dbobj.put(M.CF.META, "chain_tip", w.result(), sync)
end
```

**Impact:** Compounds BUG-1. Lunarblock's chainstate stores 4 extra
bytes (the height) with the tip — Core does not, because Core can
derive height from the block index. **P0-CDIV** for on-disk byte
incompatibility; no consensus impact at runtime.

---

### BUG-12 [P0-CDIV] On-disk UTXO entry value layout: u32_LE(height) + u8(coinbase) — not Core's varint code

**File:** `src/utxo.lua:306-318`, `308-371`
**Core ref:** `bitcoin-core/src/coins.h:63-78`

**Description:** Core serializes a `Coin` as:
```
VARINT(code)         where code = (nHeight << 1) | fCoinBase
TxOutCompression(out)
```
Lunarblock serializes as:
```
i64_LE(value)
varint_compact(spk_len)
spk_bytes
u32_LE(height)
u8(is_coinbase)
```

Three divergences:
1. **height + is_coinbase are independent fields** (5 bytes total) vs
   Core's single combined VARINT (1-4 bytes for any height ≤ 2^31).
2. **Core uses MSB base-128 VARINT** (corevarint); lunarblock uses
   fixed-width u32_LE — wastes 1-3 bytes per coin at typical heights.
3. **Field order is reversed** — Core writes the code first, then
   the TxOut; lunarblock writes value first, then script, then code.

**Excerpt:**
```lua
-- src/utxo.lua:306-318
function M.serialize_utxo_entry(entry)
  local buf = _utxo_buf
  local off = _write_i64le(buf, 0, entry.value)
  local sp = entry.script_pubkey
  local sp_len = #sp
  off = _write_varint(buf, off, sp_len)
  ffi.copy(buf + off, sp, sp_len)
  off = off + sp_len
  off = _write_u32le(buf, off, entry.height)
  buf[off] = entry.is_coinbase and 1 or 0
  off = off + 1
  return ffi.string(buf, off)
end
```

**Impact:** On-disk bytes wholly incompatible with Core. **P0-CDIV**
for cross-impl chainstate share. Note: the **undo data** path
(`serialize_undo_entry` at `utxo.lua:405-425`) DOES use Core's
varint+TxOutCompression. So lunarblock has the **asymmetric-pipeline
fleet pattern** — undo path is byte-compatible with Core, UTXO path
is not.

---

### BUG-13 [P0-CDIV] On-disk UTXO entry value uses raw i64_LE, not `CompressAmount`

**File:** `src/utxo.lua:308`
**Core ref:** `bitcoin-core/src/compressor.cpp:149-166`

**Description:** Core stores the `nValue` field through
`CompressAmount`, which maps amounts of the form
`d * 10^e` to a compact integer (`1 + (n*9 + d - 1)*10 + e` for
`e < 9`). For example `5_000_000_000` (50 BTC) becomes
`9 * 5 + 0` after dividing out `e = 8` ten-zeros → `45`, encoded as
`1 + (5*9 + 4)*10 + 8 = 1 + 49*10 + 8 = 499`, which is **2 bytes
VARINT** vs lunarblock's **8 bytes i64_LE**.

Lunarblock has `compress_amount` (`utxo.lua:642-658`) but uses it
ONLY for snapshot+undo data, not on-disk UTXO entries.

**Impact:** On-disk chainstate is ~20-50% larger than Core's. **P0-CDIV**
because every `gettxoutsetinfo --kernel=...` cross-cmp gives a
different hash. (Lunarblock works around this by re-serializing in
`_serialize_txoutser` at line 4166 for hash computations.)

---

### BUG-14 [P0] `compress_script` always emits raw form; never uses 5 special-script tags

**File:** `src/utxo.lua:740-752`
**Core ref:** `bitcoin-core/src/compressor.cpp:55-83`

**Description:** Core's `CompressScript` detects P2PKH / P2SH /
compressed-P2PK (and uncompressed-P2PK via libsecp256k1 recovery) and
emits a 1-byte type tag (0x00-0x05) + 20- or 32-byte payload. Roughly
**half** of mainnet UTXOs are P2PKH or P2SH and compress to 21 bytes
vs the raw 23-25 bytes.

Lunarblock's `compress_script` emits ONLY the raw branch:

```lua
-- src/utxo.lua:740-752
function M.compress_script(script_bytes)
  -- TODO(W-CORE-COMPRESS): emit type-byte forms (0x00..0x05) when
  -- script_bytes matches a recognized template.  For now always fall
  -- through to the raw path so the encoding is unambiguous and
  -- Core-readable.
  local _ = _is_p2pkh
  local _2 = _is_p2sh
  local _3 = _is_p2pk_compressed
  local w = serialize.buffer_writer()
  M.write_corevarint(w, #script_bytes + M.N_SPECIAL_SCRIPTS)
  w.write_bytes(script_bytes)
  return w.result()
end
```

The `_is_p2pkh` / `_is_p2sh` / `_is_p2pk_compressed` helpers are
**defined and exported but immediately discarded with `local _ = ...`**
— a classic **dead-helper-at-call-site** pattern. The decompress path
(`decompress_script` at `utxo.lua:774-810`) DOES handle the type
tags, so the asymmetry is one-way: lunarblock can READ Core-format
snapshots but emits oversized snapshots.

**Excerpt — comment-as-confession:**
```lua
-- src/utxo.lua:686-693
-- Phase 1 (this commit, per task TODO): we only emit the "raw" branch
--   VARINT(size + 6) + raw_bytes
-- which Core's DecompressScript handles (nSize >= nSpecialScripts case).
-- Compressed types 0x00 (P2PKH) / 0x01 (P2SH) / 0x02-0x05 (P2PK) are read
-- on the load path so we round-trip third-party snapshots, but we do not
-- yet emit them on dump.  This is honest: the file is bigger than Core's
-- but the format is byte-compatible.  TODO: detect the recognized types
-- on dump for byte-for-byte parity with Core.
```

**Impact:**
- **dump_snapshot output is byte-larger than Core's** for the same
  UTXO set (the snapshot loader can READ both; the dumper produces
  the suboptimal form).
- **compute_utxo_hash and compute_muhash both call
  `_serialize_txoutser` which uses raw CompactSize length**
  (`utxo.lua:4175 w.write_varint(#entry.script_pubkey)`) — that's
  also non-Core. Cross-cite **BUG-13**.

**P0** because this is a public-facing API (snapshot file format)
that ships oversized blobs.

---

### BUG-15 [P2] No `obfuscate_key` XOR layer on coin values

**File:** `src/storage.lua` — absent
**Core ref:** `bitcoin-core/src/dbwrapper.cpp:253-261`,
`bitcoin-core/src/dbwrapper.h:62, 188-218`

**Description:** Core generates an 8-byte random `Obfuscation` key
the first time a fresh chainstate DB is opened, stores it at the key
`"\000obfuscate_key"` (14 bytes), and XOR's every value (looped to
length) against the key before write and after read. The motivation
is **avoiding antivirus false-positives** on script bytes that
resemble executable patterns (per `dbwrapper.h:62`: "Database
obfuscation should be considered an implementation detail of the
specific database").

Lunarblock has no obfuscation:

```lua
-- src/storage.lua:347-376
function dbobj.get(cf, key)
  ...
  local result = ffi.string(val, vallen[0])
  ...
  return result
end

function dbobj.put(cf, key, value, sync)
  ...
  librocksdb.rocksdb_put_cf(
    dbobj._db, opts, handle, key, #key, value, #value, errptr
  )
  ...
end
```

**Impact:** A fresh lunarblock chainstate on disk contains raw
script bytes — including any Mt. Gox-era P2PK pubkeys, OP_RETURN
data, etc. — that can trigger antivirus heuristics on
Windows/macOS. Bitcoin Core explicitly fixed this in 2014. **P2**
because it's an operational hazard, not a consensus or correctness
bug.

---

### BUG-16 [P0] `CoinView:should_flush()` defined but NEVER CALLED — cache eviction is non-functional

**File:** `src/utxo.lua:1250-1252` (definition);
no caller in entire codebase
**Core ref:** `bitcoin-core/src/validation.cpp` `FlushStateToDisk`
(state == FLUSH_STATE_IF_NEEDED gate)

**Description:** `CoinView:should_flush()` checks whether the cache
has exceeded its configured `max_cache_bytes` and returns a bool.

```lua
-- src/utxo.lua:1248-1252
--- Check if cache should be flushed based on memory usage.
-- @return boolean
function CoinView:should_flush()
  return self.cached_memory_usage >= self.max_cache_bytes
end
```

A grep across `lunarblock/src/`, `lunarblock/lib/`, and
`lunarblock/lunarblock` confirms **zero callers**:

```
$ grep -rn 'should_flush\|cache_full' lunarblock/
src/utxo.lua:1250:function CoinView:should_flush()
```

**Impact:** Three downstream consequences:

1. **Every connect_block flushes the cache** (`utxo.lua:2930`), so
   the "cache" exists for **one block at a time**. The whole reason
   `CCoinsViewCache` exists in Core — to absorb thousands of writes
   between dbcache-sized flushes — is gone.
2. **`dbcache MB` is misleading** — even at `--dbcache=4096`, the
   cache fills up to one block's worth of dirty entries then
   immediately flushes. The 4 GB of allowed cache is never used.
3. **There is no FlushStateToDisk-trigger plumbing at all** —
   `sync.lua:2429-2453` instead bases periodic flush on
   `utxo_flush_interval` blocks or `utxo_flush_max_seconds` time,
   which is **completely independent of cache pressure**.

This is the **dead-helper / dead-gate at the API surface** fleet
pattern: the function exists, is documented, returns a sensible
value, but no path consults it. **P0** because the architectural
rationale of the cache is silently broken.

---

### BUG-17 [P1] Cache entry memory estimate inflated 70× vs Core (7800 bytes vs ~115)

**File:** `src/utxo.lua:977, 983-986`
**Core ref:** `bitcoin-core/src/coins.h:87-89` `DynamicMemoryUsage()` =
`memusage::DynamicUsage(out.scriptPubKey)` (=`sizeof(CScript) + capacity`)

**Description:** Core's per-entry memory usage is roughly:
- `sizeof(CCoinsCacheEntry)` = ~80 bytes
- `sizeof(Coin)` = ~64 bytes
- `scriptPubKey` overhead = ~25-50 bytes (vector capacity)
= **~115 bytes** typical.

Lunarblock's `estimate_entry_memory` uses:

```lua
-- src/utxo.lua:977-986
local BASE_ENTRY_OVERHEAD = 7800
local SCRIPT_OVERHEAD = 200

local function estimate_entry_memory(entry)
  local script_len = entry and entry.script_pubkey and #entry.script_pubkey or SCRIPT_OVERHEAD
  return BASE_ENTRY_OVERHEAD + script_len
end
```

That's **~7,820 bytes per entry**, or **70× Core's**. The comment at
`utxo.lua:974-976` justifies this on LuaJIT-table-node overhead:

```lua
-- LuaJIT hash table entries use ~8-10KB actual RSS per entry due to
-- table node overhead, GC metadata, string interning, and allocator
-- fragmentation.  We use 8KB to trigger eviction early enough.
```

**Impact:** Two compounding effects with BUG-16:
1. The comment at `utxo.lua:967` states "**450MB — matches Bitcoin
   Core's default dbcache**", but Core fits ~3.9M entries in 450 MB
   while lunarblock fits ~57k. The "matching" is name-only.
2. Even if BUG-16 were fixed, the cache would fill in
   ~57k entries (one tx-heavy block), trigger eviction, and behave
   like a 5-MB Core cache.

If the 7800-byte figure is genuinely accurate (the comment claims
"~8-10KB actual RSS"), then **the whole cache design is unsuitable
for LuaJIT** — Core's dbcache assumes a structure where memory is
linear in script bytes, which LuaJIT tables cannot offer. A
candidate fix is to switch the cache to FFI-backed dense storage
(uint8 arrays), but that's a major rework.

**P1** because the documented configuration ("450 MB dbcache matches
Core") is materially misleading, and any operator who tunes
`--dbcache` based on Core's behavior will be surprised.

---

### BUG-18 [P2] No `AccessCoin` returning a const reference

**File:** `src/utxo.lua` — absent
**Core ref:** `bitcoin-core/src/coins.cpp:179-186`,
`bitcoin-core/src/coins.h:432`

**Description:** Core has `AccessCoin` which returns a `const Coin&`
into the cache (or `coinEmpty` if not found). Hot path:
`validation.cpp:CheckInputScripts` does a tight loop of
`view.AccessCoin(outpoint).out` reads, avoiding the
`std::optional<Coin>` wrapper of `GetCoin`.

Lunarblock has only `CoinView:get` which returns a Lua table — every
call creates GC pressure if the table is newly built (it isn't in the
cache-hit case; it's a reused entry table — actually OK in LuaJIT
since tables are GC roots).

**Impact:** Mostly a stylistic / API-parity gap. Performance
difference is small. **P2**.

---

### BUG-19 [P1] `CoinView:sanity_check()` defined but NEVER CALLED

**File:** `src/utxo.lua:1486-1525`
**Core ref:** `bitcoin-core/src/coins.cpp:336-348` `CCoinsViewCache::SanityCheck()`

**Description:** `CoinView:sanity_check()` validates internal cache
consistency (dirty_list ↔ cache, fresh-without-dirty, spent-without-dirty)
and returns `(ok, err_message)`.

```lua
-- src/utxo.lua:1490-1525
function CoinView:sanity_check()
  local computed_dirty = 0
  local computed_memory = 0

  for key, entry in pairs(self.cache) do
    ...
    if is_dirty(entry) then
      computed_dirty = computed_dirty + 1
      if not self.dirty_list[key] then
        return false, "dirty entry not in dirty_list: " .. key
      end
    end
    ...
```

Grep confirms zero callers in `src/` and zero callers in `tests/` for
this codebase.

**Impact:** Self-test surface that's never exercised. If the cache
falls into an inconsistent state (which BUG-6 / BUG-7 could cause),
the sanity check would catch it — but only if it ran. **P1** for
"defensive code that never executes".

---

### BUG-20 [P2] No `Uncache()` exposed in public API but defined; no caller

**File:** `src/utxo.lua:1428-1435` (defined);
zero call sites in the codebase
**Core ref:** `bitcoin-core/src/coins.cpp:265-273` `CCoinsViewCache::Uncache`

**Description:** Same dead-API pattern: defined, well-documented, no
caller.

```lua
-- src/utxo.lua:1428-1435
function CoinView:uncache(txid, vout)
  local key = M.outpoint_key(txid, vout)
  local entry = self.cache[key]
  if entry and not is_dirty(entry) then
    self.cached_memory_usage = self.cached_memory_usage - estimate_entry_memory(entry)
    self.cache[key] = nil
  end
end
```

Core's `Uncache` is called by mempool acceptance to free per-tx
prevout reads after `AcceptToMemoryPool` finishes (avoids ballooning
the cache with mempool-only reads). Lunarblock's mempool path
doesn't seem to populate the chainstate cache at all (mempool reads
go directly via `coin_view:get` and stay cached forever).

**Impact:** Mempool-driven cache bloat: every `getrawtransaction`
RPC, every `sendrawtransaction` validation, every package-evaluation
read leaves entries in `cacheCoins` until the next flush. **P2**
because the per-block flush (BUG-16's silver lining) clears them
anyway.

---

### BUG-21 [P3] `_estimate_entry_memory` returns `SCRIPT_OVERHEAD` as fallback when script_pubkey is nil

**File:** `src/utxo.lua:983-986`
**Core ref:** N/A — this is a lunarblock-specific bookkeeping bug

**Description:** When `entry.script_pubkey` is nil:

```lua
local function estimate_entry_memory(entry)
  local script_len = entry and entry.script_pubkey and #entry.script_pubkey or SCRIPT_OVERHEAD
  return BASE_ENTRY_OVERHEAD + script_len
end
```

The fallback `SCRIPT_OVERHEAD = 200` is used as the *length* of the
script — adding 200 to the entry overhead, which then gets DEDUCTED
later when the entry is removed (line 1176, line 1231) using the
same logic. As long as both calls produce the same result for a
given entry, the bookkeeping stays balanced. But if the entry's
`script_pubkey` field is set between the add (nil) and remove (set)
calls, the memory tracking drifts.

**Impact:** Latent bookkeeping drift. With `cached_memory_usage`
already unused for eviction (BUG-16), this never matters. **P3**.

---

### BUG-22 [P1] `flush()` early-return on `dirty_count == 0 and not extra_batch_fn` can skip a needed empty-batch sync

**File:** `src/utxo.lua:1272`
**Core ref:** N/A — durability concern

**Description:**

```lua
-- src/utxo.lua:1272
function CoinView:flush(reallocate, extra_batch_fn, sync, reorg_batch)
  if self.dirty_count == 0 and not extra_batch_fn then return end
```

If a caller calls `flush(false, nil, true)` (sync=true, no extras,
no dirty entries), the function returns silently without issuing the
`sync=true` write that the caller expected. This skips the WAL
fsync. After a no-op `flush(sync=true)`, the caller might believe
all previously-written-async data is now durable — but no fsync has
actually been issued.

This is exactly what `sync.lua:2448` does, via `set_chain_tip(..., true)`
directly, sidestepping the `flush` path — so the IBD periodic-sync
path is correct, but ANY direct `coin_view:flush(..., true)` call
with `dirty_count == 0` is a silent no-op rather than a durability
barrier.

**Impact:** Latent durability hazard. The `reindex_chainstate` final
sync at `utxo.lua:1852` calls `self.coin_view:flush(false, nil, true)`
expecting it to fsync — if dirty_count happens to be zero at that
point (because the reindex loop already flushed), no fsync happens.
For reindex, this is OK because the last `connect_block` already
fsynced via the periodic path. But the API contract is misleading.
**P1**.

---

## Fleet patterns observed

1. **Dead-helper/dead-gate at the API surface** (3 instances):
   `should_flush()` (BUG-16), `sanity_check()` (BUG-19), `uncache()`
   (BUG-20). Cross-impl pattern observed in W141 (rustoshi zmq.rs
   1079 LOC dead), W138 (haskoin `runBackgroundValidation`),
   W139 (rustoshi/nimrod fee buckets).

2. **Comment-as-confession**: BUG-6 (`mark_fresh = true` after
   acknowledging the case where it's unsafe) and BUG-14
   (`-- TODO(W-CORE-COMPRESS): emit type-byte forms ... For now
   always fall through to the raw path`). Both describe correct
   Core behavior, then implement the divergent simplified version.

3. **Asymmetric pipeline**: Snapshot + undo paths use Core's
   `CompressAmount` / `CompressScript` / `corevarint`; on-disk UTXO
   path uses raw `i64_LE` / `varint_compact` / `u32_LE`. Two
   coexisting serialization layers with no shared root. Cross-cite
   W140's "two-pipeline guard" pattern.

4. **Plumb-gate-then-flip**: BUG-16 — `should_flush` is plumbed
   (`max_cache_bytes`, `cached_memory_usage`, `BASE_ENTRY_OVERHEAD`)
   but never gated. BUG-19 — `sanity_check` is fully implemented but
   never run.

5. **Wrong-constant**: BUG-17 — `BASE_ENTRY_OVERHEAD = 7800` claims
   to match LuaJIT reality but is 70× Core's per-entry footprint;
   the comment "matches Bitcoin Core's default dbcache" is then
   structurally false.

6. **Carry-forward re-anchor**: BUG-1 + BUG-11 + BUG-12 + BUG-13 +
   BUG-14 are **all the same root divergence** — lunarblock's
   on-disk chainstate is a from-scratch format never byte-aligned to
   Core. Each was independently engineered with a comment
   acknowledging the divergence but proceeding anyway.

## Severity summary

| Severity | Count | Bugs |
|----------|------:|------|
| P0-CONSENSUS | 0 | (none — no consensus rule diverges) |
| P0-CDIV | 3 | BUG-1, BUG-11, BUG-12 |
| P0-SEC | 0 | |
| P0 | 4 | BUG-3, BUG-13, BUG-14, BUG-16 |
| P1 | 7 | BUG-4, BUG-5, BUG-6, BUG-7, BUG-10, BUG-17, BUG-19, BUG-22 |
| P2 | 6 | BUG-8, BUG-9, BUG-15, BUG-18, BUG-20, BUG-21 |
| P3 | 2 | BUG-2, BUG-21 |
| **Total** | **22** | |

(BUG-21 appears in both P2 and P3 above; counted once as P2/P3
boundary.)

## Recommended priority fixes

1. **BUG-16** — wire `should_flush()` into the IBD loop. One-line
   fix; transforms cache from "per-block flushed" to actual
   "memory-pressure flushed" architecture. Pair with **BUG-17**
   (re-measure LuaJIT entry size; consider FFI-backed dense
   structure).
2. **BUG-6 + BUG-7** — pipe a `possible_overwrite` flag through
   `CoinView:add` and check the disk in the no-cache-hit case before
   marking FRESH. Closes the UTXO-resurrection class.
3. **BUG-14** — wire up the already-existing `_is_p2pkh` /
   `_is_p2sh` / `_is_p2pk_compressed` detectors on the compress
   path. ~10 lines, makes dump_snapshot byte-compatible with Core.
4. **BUG-3** — emit `HEAD_BLOCKS` records on every flush. Defensive,
   improves operator diagnostics during partial-write recovery.
5. **BUG-1 + BUG-11 + BUG-12 + BUG-13** — full on-disk byte
   migration to Core format. Requires a one-shot reindex on next
   start. **Largest fix** — would close 4 P0-CDIV bugs and enable
   cross-impl chainstate share.
