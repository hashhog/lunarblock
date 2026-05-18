# W138 — assumeUTXO snapshots — lunarblock

Date: 2026-05-18
Wave: W138 (assumeUTXO snapshot serialization, load, activate, validate)
Impl: lunarblock (Lua / LuaJIT)
Scope: SnapshotMetadata wire format (utxo_snapshot.h/.cpp), loadtxoutset /
dumptxoutset RPCs (rpc/blockchain.cpp), ActivateSnapshot +
PopulateAndValidateSnapshot (validation.cpp:5588-5965),
MaybeCompleteSnapshotValidation (validation.cpp:5972-6080),
WriteSnapshotBaseBlockhash / ReadSnapshotBaseBlockhash / FindAssumeutxoChainstateDir
(node/utxo_snapshot.cpp:22-92), chainparams `m_assumeutxo_data` (kernel/
chainparams.cpp), AmountCompression / ScriptCompression / VarInt-core
(compressor.cpp + serialize.h).

References:
- bitcoin-core/src/node/utxo_snapshot.h (137 LOC) — SnapshotMetadata
  Serialize/Unserialize, SNAPSHOT_MAGIC_BYTES, SNAPSHOT_BLOCKHASH_FILENAME,
  SNAPSHOT_CHAINSTATE_SUFFIX, FindAssumeutxoChainstateDir.
- bitcoin-core/src/node/utxo_snapshot.cpp (95 LOC) — WriteSnapshotBaseBlockhash,
  ReadSnapshotBaseBlockhash, FindAssumeutxoChainstateDir implementations.
- bitcoin-core/src/validation.cpp:5588-6080 — ActivateSnapshot (eight
  precondition gates), PopulateAndValidateSnapshot, MaybeCompleteSnapshotValidation.
- bitcoin-core/src/validation.h:529-647 — Assumeutxo enum (VALIDATED /
  UNVALIDATED / INVALID), m_from_snapshot_blockhash, m_target_blockhash,
  m_target_utxohash, ChainstateRole.
- bitcoin-core/src/rpc/blockchain.cpp:3074-3445 — dumptxoutset (latest /
  rollback / TemporaryRollback / NetworkDisable RAII), loadtxoutset,
  getchainstates (returns per-chainstate `snapshot_blockhash`, `validated`).
- bitcoin-core/src/kernel/chainparams.cpp:158-183, 275, 380, 493, 611, 677 —
  m_assumeutxo_data for mainnet + testnet3 + testnet4 + signet + regtest;
  GetAvailableSnapshotHeights, AssumeutxoForHeight, AssumeutxoForBlockhash.
- bitcoin-core/src/compressor.h:20-86 — TxOutCompression / ScriptCompression /
  AmountCompression structure; nSpecialScripts = 6.
- bitcoin-core/src/compressor.cpp:55+ — CompressScript recognizing P2PKH / P2SH
  / P2PK-compressed / P2PK-uncompressed special types (0x00..0x05).
- BIPs: none directly (assumeUTXO is a Bitcoin Core feature, not a BIP).

Lunarblock surface:
- `src/utxo.lua` (4897 LOC) — entire surface lives here:
  - lines 508-905: SnapshotMetadata format constants + write_corevarint /
    read_corevarint / compress_amount / decompress_amount / compress_script /
    decompress_script / snapshot_metadata / serialize_snapshot_metadata /
    deserialize_snapshot_metadata / serialize_snapshot_coin /
    deserialize_snapshot_coin.
  - lines 1570-1573: ChainState.from_snapshot_blockhash field (the in-memory
    twin of Core's m_from_snapshot_blockhash). Initialized nil.
  - lines 4180-4308: compute_utxo_hash (HASH_SERIALIZED via SHA256d-HashWriter,
    used for the assumeutxo strict gate) + compute_muhash (gettxoutsetinfo
    only — NOT the assumeutxo commitment).
  - lines 4310-4487: dump_snapshot (writes SnapshotMetadata + per-txid
    grouped body in Core wire format). Genesis-coinbase exclusion correct.
    Fsync before close.
  - lines 4489-4565: _file_reader (Core VARINT / CompactSize buffered reader).
  - lines 4589-4765: ChainState:load_snapshot — duplicate-activation guard,
    work-exceeds-active guard, mempool-empty guard, network-magic check,
    per-coin height + MoneyRange guards, trailing-bytes EOF check, optional
    HASH_SERIALIZED gate, set from_snapshot_blockhash.
  - lines 4767-4895: SnapshotChainstate + BackgroundValidator
    (defined but NEVER instantiated / wired by main.lua / sync.lua / rpc.lua).
- `src/consensus.lua` (1685 LOC) — `assumeutxo` table per network
  (mainnet: 5 entries 840k-944k; testnet3 / testnet4 / regtest empty;
  hashhog-local entry at 944183), plus helpers `assumeutxo_for_height`,
  `assumeutxo_for_blockhash`, `has_assumeutxo`, `get_assumeutxo_heights`.
- `src/rpc.lua` (8592 LOC) —
  - lines 7548-7772: dumptxoutset (latest / rollback / options.rollback;
    NetworkDisable Lua-pcall analog; rewind→dump→reapply via
    rollback_chain_to / reapply_disconnected).
  - lines 7778-7872: loadtxoutset (peeks 51-byte header, looks up assumeutxo
    by base_blockhash, calls load_snapshot with au_height, active_tip_height,
    mempool).
- `src/main.lua` lines 575-649 — `run_import_utxo`: CLI-only `--import-utxo`
  mode, bypasses RPC. Opens chainstate, calls `cs:load_snapshot` directly
  (no expected_hash, no active_tip_height, no mempool), then sets tip_height
  from assumeutxo lookup and writes chain_tip to storage.

Lunarblock NOT present (structural gaps):
- **No on-disk persistence of `from_snapshot_blockhash`** — Core writes the
  base_blockhash to `<chainstate>/base_blockhash` file (utxo_snapshot.cpp:22-46)
  so a restart can rebuild m_from_snapshot_blockhash. lunarblock keeps it only
  in `ChainState.from_snapshot_blockhash` (in-RAM); after restart the snapshot
  status is silently forgotten and the `is once` duplicate-activation guard
  re-allows a second load.
- **No dual-chainstate dir layout** — Core uses `chainstate_snapshot` suffix
  (utxo_snapshot.h:128 `SNAPSHOT_CHAINSTATE_SUFFIX`) to keep the snapshot's
  UTXO set in a separate leveldb dir from the IBD chainstate, and runs both
  simultaneously (snapshot serves tip + IBD validates from genesis in
  background, MaybeRebalanceCaches between them). lunarblock has one
  RocksDB only; on load_snapshot it OVERWRITES the UTXO set in-place. No
  background-IBD-from-genesis happens.
- **No `MaybeCompleteSnapshotValidation`** — Core (validation.cpp:5972-6080)
  is the function that runs after background IBD catches up to
  snapshot_base_height, recomputes the HASH_SERIALIZED via the background
  chainstate's UTXO set, compares against the assumeutxo entry, and either
  promotes the snapshot from UNVALIDATED→VALIDATED or marks it INVALID and
  triggers a fatal-error + snapshot-dir rename. lunarblock has the
  BackgroundValidator class but it is never instantiated nor called.
- **No `m_assumeutxo` enum state** (Assumeutxo::VALIDATED / UNVALIDATED /
  INVALID) — lunarblock's ChainState carries only `from_snapshot_blockhash`
  (nil or set). No way to distinguish "loaded a snapshot but background
  validation still pending" from "loaded and validated".
- **No `m_target_blockhash` / `m_target_utxohash`** — Core's background
  chainstate tracks the snapshot block as its target so connect-block knows
  to stop there and trigger MaybeCompleteSnapshot. lunarblock has neither.
- **No `getchainstates` RPC** — Core (rpc/blockchain.cpp:3462+) exposes
  per-chainstate `snapshot_blockhash` and `validated` for monitoring.
  Absent in lunarblock — no way for a caller to know whether the current
  tip is built on a snapshot.
- **No `snapshot_blockhash` field in getblockchaininfo** —
  Core (rpc/blockchain.cpp:1824) emits this when active chainstate is from
  snapshot. Absent in lunarblock.
- **No best-headers ancestor check** at load — Core (validation.cpp:5622)
  refuses the load if `!m_best_header || m_best_header->GetAncestor(
  snapshot_start_block->nHeight) != snapshot_start_block`. lunarblock's
  loadtxoutset never checks this; a node loaded with a snapshot when a
  competing more-work header chain exists will silently use the snapshot.
- **No `BLOCK_FAILED_VALID` guard** at load — Core (validation.cpp:5617-5620)
  refuses the load if the snapshot_start_block is on an invalid chain.
  lunarblock checks neither `invalid_blocks` set nor the header chain.
- **No "snapshot block header must be in headers chain" check** —
  Core (validation.cpp:5611-5615) requires the base block header to appear
  in the blockman index BEFORE accepting the snapshot. lunarblock's
  loadtxoutset only does a brute-force scan via `get_hash_by_height` 0..tip
  inside the "not in chainparams" error branch (line 7828-7836) — and even
  then only to compute a height for an error string, not as a gate.
- **No FlushSnapshotToDisk mid-load** — Core (validation.cpp:5854-5856)
  periodically dumps the coins cache to leveldb when CoinsCacheSizeState
  reaches CRITICAL; lunarblock has a `coin_view:flush()` every 100k coins
  (utxo.lua:4704-4706) — adequate substitute, but flushes on a fixed
  interval rather than memory pressure.
- **No `EmplaceCoinInternalDANGER` analog** — Core's bulk-load path bypasses
  the cache's flag tracking (FRESH/DIRTY) since the snapshot writes are
  authoritative. lunarblock's `coin_view:add` (called from load_snapshot)
  goes through the normal add-with-flags path and re-runs flag bookkeeping
  for every coin (utxo.lua:4698) — correct, just slower.
- **No `m_chain_tx_count` recording** — Core records the snapshot's
  `m_chain_tx_count` into the snapshot_start_block's CBlockIndex
  (validation.cpp:5942-5944 + 3805) so verification-progress estimates work
  immediately after the load. lunarblock has the chainparams entry
  (consensus.lua:950, 955, 960, 965, 980) but never threads it back into the
  header chain — `getblockchaininfo.verificationprogress` will be
  meaningless after a snapshot load until background IBD catches up.
- **No NetworkDisable across all P2P paths** — lunarblock has
  `rpc.block_submission_paused` flag set during dumptxoutset rewind, but
  inspection of mempool.lua:6950-6953 shows the gate is only checked at one
  RPC site (submitblock); the P2P inbound block path (peerman:process_block)
  does not check this flag. Core's NetworkDisable RAII pauses ALL inbound
  via the connman.SetNetworkActive(false) primitive.
- **dumptxoutset.nchaintx is wrong** — Core
  (rpc/blockchain.cpp:3346): `result.pushKV("nchaintx", tip->m_chain_tx_count)`
  — cumulative tx count up to and including the tip. lunarblock
  (rpc.lua:7770): `nchaintx = result.coins_count` — the *UTXO* count, not
  the *tx* count. Off by ~10x on real chains.
- **compress_script always falls through to raw** — utxo.lua:740-752
  references `_is_p2pkh` / `_is_p2sh` / `_is_p2pk_compressed` only as
  `local _ = ...` no-ops (lines 745-747). Core (compressor.cpp:CompressScript)
  emits 1-byte type identifier + 20-byte hash (or 32-byte x-coord) for the
  recognized special scripts (4-6x smaller per coin). lunarblock dumps are
  byte-INCOMPATIBLE with Core dumps (same coins, different sizes) — Core
  CAN parse lunarblock's dumps (since the raw branch is a valid Core
  encoding), but `dumptxoutset` output will not be SHA256-identical to
  Core's, and the `txoutset_hash` returned in the RPC reply does NOT match
  what Core would compute over the same UTXO set.

## 30-gate audit matrix

Legend: PASS = correct vs Core. BUG = divergence vs Core. MISSING = feature
absent. PARTIAL = present but incomplete.

| #   | Gate                                                                                       | Status   | Notes |
|-----|--------------------------------------------------------------------------------------------|----------|-------|
| G1  | SnapshotMetadata SNAPSHOT_MAGIC_BYTES = 'utxo' || 0xff (5 bytes)                            | PASS     | `utxo.lua:546 M.SNAPSHOT_MAGIC = "utxo\xff"`. Wire-emitted at offset 0; deserialize rejects on mismatch at line 852. |
| G2  | SnapshotMetadata version = uint16 LE; VERSION = 2                                          | PASS     | `utxo.lua:547 M.SNAPSHOT_VERSION = 2`. write_u16le at 833. Read at line 856. |
| G3  | Unsupported snapshot version rejection (Core throws "Version of snapshot... not supported")| BUG      | utxo.lua:857-860 checks `version > M.SNAPSHOT_VERSION`; Core (utxo_snapshot.h:84) checks `!m_supported_versions.contains(version)`. lunarblock would accept version=1 (older snapshots) which Core rejects (Core only supports version=2). BUG-1 P2. |
| G4  | SnapshotMetadata network_magic check (Core uses MessageStartChars)                         | PARTIAL  | utxo.lua:862 reads `network_magic = r.read_bytes(4)`. load_snapshot at 4638-4641 compares `metadata.network_magic ~= self.network.magic_bytes` and returns a generic error. Core (utxo_snapshot.h:91-100) emits a "snapshot is for network X (mainnet/testnet/...)" error that includes the network name resolved via GetNetworkForMagic, so a misdirected operator sees the diagnostic. lunarblock's error string is bare. BUG-2 P2 (error fidelity). |
| G5  | SnapshotMetadata base_blockhash + coins_count fields                                       | PASS     | utxo.lua:863-864 read hash256 (32B) + u64le. Symmetric write at 835-836. |
| G6  | SnapshotMetadata header total = 51 bytes (5+2+4+32+8)                                      | PASS     | utxo.lua:514-519 comment; serialize_snapshot_metadata at 830-838 emits exactly 51 bytes; deserialize at 843 checks `#data < 51`. |
| G7  | dumptxoutset "type" arg parsing: latest / rollback / "" / -named rollback=H|hash           | PASS     | rpc.lua:7557-7651 handles all four. Error fidelity matches Core ("Invalid snapshot type \"X\" specified..."). |
| G8  | dumptxoutset.options.rollback by height or 64-hex blockhash                                | PARTIAL  | rpc.lua:7581-7616 resolves both. **However**, the by-hash branch scans `get_hash_by_height(0..tip)` linearly (line 7605-7609) — O(N) per call where N = tip height. Core (rpc/blockchain.cpp:3088) uses LookupBlockIndex which is O(1). For a tip at 900k+ this is a ~100ms self-DoS on every call. BUG-3 P2 (perf, not correctness). |
| G9  | dumptxoutset rejects rollback target above current tip                                     | PASS     | rpc.lua:7653-7656 raises with Core's exact "Rollback target above current tip" message. |
| G10 | dumptxoutset prune-mode pre-check (block not available)                                    | PASS     | rpc.lua:7669-7678 checks `pruner.enabled && target_height <= prune_height` and emits Core's exact "Block height X not available (pruned data). Use a height after Y." message. Strong. |
| G11 | dumptxoutset NetworkDisable RAII during rewind→dump→replay                                 | PARTIAL  | rpc.lua:7689-7693 sets `rpc.block_submission_paused = true`; cleared on every exit path 7750-7752. **However**, the flag is checked only at `submitblock` RPC (mempool.lua:6950-6953) — P2P inbound block flow does NOT check it. Core's NetworkDisable calls `connman.SetNetworkActive(false)` which closes the listening socket and refuses inbound peer messages. BUG-4 P2 (incomplete pause). |
| G12 | dumptxoutset rewind→dump→reapply via TemporaryRollback                                     | PASS     | rpc.lua:7700-7745: pcall around rollback_chain_to (utxo.lua:3835) → dump_snapshot → reapply_disconnected (utxo.lua:3881). reapply runs even on dump failure so the node ends at the original tip. Strong recovery semantics. |
| G13 | dumptxoutset atomic rename via `.incomplete` tempfile                                      | PASS     | rpc.lua:7715, 7726, 7735-7745. Writes to `path.incomplete`, fsyncs (utxo.lua:4473), then `os.rename`. Failures unlink the tempfile. Matches Core's tempfile-rename pattern. |
| G14 | dumptxoutset response keys: coins_written, base_hash, base_height, path, txoutset_hash, nchaintx | BUG | rpc.lua:7764-7771 emits all six keys. **nchaintx is WRONG**: Core (rpc/blockchain.cpp:3346) sets `nchaintx = tip->m_chain_tx_count` (cumulative tx-count to tip); lunarblock sets `nchaintx = result.coins_count` (UTXO count). At mainnet 944k these differ by ~1.3B vs ~165M — off by ~10x. Comment at rpc.lua:7770 acknowledges it as a TODO. BUG-5 P1 (RPC fidelity; downstream loadtxoutset progress estimators rely on this). |
| G15 | Refuse to clobber existing dumptxoutset path                                                | PASS     | rpc.lua:7568-7574 stats the target and refuses if it exists. Matches Core (rpc/blockchain.cpp behavior). |
| G16 | dump_snapshot per-coin serialization: write_corevarint(code = h*2+cb)                       | PASS     | utxo.lua:884-891. code computed correctly; write_corevarint with carry-by-one MSB-first base-128 encoding matches serialize.h:WriteVarInt byte-for-byte. Round-trip tested at utxo.lua:577-628. |
| G17 | dump_snapshot per-coin: write_corevarint(CompressAmount(value))                             | PASS     | utxo.lua:888 + 642-658. CompressAmount preserves all 19 digits of mainnet amounts; LuaJIT uint64_t arithmetic stays correct above 2^53. Round-trip via decompress_amount. |
| G18 | dump_snapshot per-coin scriptPubKey: ScriptCompression                                      | BUG      | utxo.lua:740-752: compress_script **always** falls through to the raw `VARINT(size+6) + bytes` branch. Lines 745-747 reference _is_p2pkh / _is_p2sh / _is_p2pk_compressed as `local _ = ...` no-ops. Core (compressor.cpp:CompressScript) emits type 0x00 (P2PKH, 21 bytes total: 1 type + 20 hash) for the 25-byte P2PKH; lunarblock emits VARINT(31) + 25 raw bytes (~26 bytes). For real Bitcoin snapshots where ~98% of outputs are P2PKH/P2WPKH/P2TR-style, this is a ~4x size penalty AND lunarblock dumps are NOT byte-identical to Core dumps over the same coin set. **txoutset_hash returned by dumptxoutset will NOT match Core's** (different bytes → different SHA256d). Acknowledged TODO at utxo.lua:741-744. BUG-6 P0 (cross-impl divergence — fleet-wide hash compare would split). |
| G19 | dump_snapshot per-txid grouping: txid + CompactSize(coins_per_txid)                         | PASS     | utxo.lua:4434-4438 (sort txids) + 4442-4455 (per-txid writev). RocksDB key layout (txid || vout LE) preserves Core's leveldb iteration order. Sort + numerical vout sort (line 4445-4449) matches Core's std::map<uint32_t,Coin> per-txid grouping. |
| G20 | dump_snapshot genesis-coinbase exclusion                                                    | PASS     | utxo.lua:4379-4392 + 4412-4418 skip the genesis-coinbase txid. Matches Core (validation.cpp:2337-2343 short-circuits ConnectBlock on genesis hash so the coinbase output never enters the UTXO set). Comment at 4370-4378 documents the rationale + W9 reorg-corpus discovery. |
| G21 | dump_snapshot fsync before close + atomic rename                                            | PASS     | utxo.lua:4310-4345 + 4473. _fsync_file flushes Lua's user-space buffer, then FILE* buffer (via file:flush), then OS via fileno+fsync. Mirrors Core's Fdatasync + close + rename pattern. |
| G22 | loadtxoutset peeks header, looks up assumeutxo_for_blockhash, refuses if absent             | PASS     | rpc.lua:7791-7847. Reads 51-byte header, calls consensus.assumeutxo_for_blockhash, emits Core's exact "Assumeutxo height in snapshot metadata not recognized (X) - refusing to load snapshot" string when absent. Strong — error-string match for cross-impl probes. |
| G23 | ActivateSnapshot duplicate-activation guard ("Can't activate a snapshot...more than once") | PARTIAL  | utxo.lua:4589-4596: checks `self.from_snapshot_blockhash` and refuses with Core's exact message. **However**, `from_snapshot_blockhash` is NOT persisted to disk (no Core utxo_snapshot.h:113 SNAPSHOT_BLOCKHASH_FILENAME analog). After daemon restart the field is nil and a second load is silently re-allowed. BUG-7 P1 (operator-mistake-class: snapshot loaded twice across restart corrupts UTXO set). |
| G24 | ActivateSnapshot best-headers-ancestor check (Core validation.cpp:5622)                     | MISSING  | Core: `if (!m_best_header || m_best_header->GetAncestor(snapshot_start_block->nHeight) != snapshot_start_block) return error("A forked headers-chain with more work...")`. lunarblock's loadtxoutset has NO such check. A node with a stale/forked header chain can load a snapshot anyway — and now serves a chain that competes with the network. BUG-8 P0 (consensus-class: divergent tip). |
| G25 | ActivateSnapshot snapshot_start_block must be in headers chain (Core line 5611)             | MISSING  | Core: `snapshot_start_block = m_blockman.LookupBlockIndex(base_blockhash); if (!snapshot_start_block) return error("The base block header must appear in the headers chain")`. lunarblock skips this gate. If headers have not been pre-synced, loadtxoutset will accept the snapshot, set `chain_state.tip_hash = metadata.base_blockhash`, but the resulting chain has no header backbone behind the snapshot tip — verifyblock / getblock / RPC dispatch on snapshot ancestors will all return "block not found". BUG-9 P0 (consensus-class: hollow chainstate). |
| G26 | ActivateSnapshot BLOCK_FAILED_VALID guard (Core line 5617-5620)                             | MISSING  | Core: `if (start_block_invalid) return error("The base block header is part of an invalid chain")`. lunarblock has an `invalid_blocks` set (utxo.lua:3917-3979 invalidate_block) but loadtxoutset never consults it. Operator could `invalidateblock` then `loadtxoutset` on that same block. BUG-10 P1. |
| G27 | ActivateSnapshot work-exceeds-active check                                                  | PARTIAL  | utxo.lua:4606-4611 checks `active_tip_height ~= nil && active_tip_height > 0 && snap_height <= active_tip_height`. **Uses HEIGHT as a proxy for work** — comment at 4601-4602 acknowledges "same network, same difficulty — higher height ≡ more work" but this is FALSE across forks of different difficulty / chain-work. Core (validation.cpp:5706-5708) uses `CBlockIndexWorkComparator()` over real chainwork. A snapshot at a lower height but higher work would be rejected. BUG-11 P1 (rare scenario, but not consensus-safe). |
| G28 | ActivateSnapshot mempool-empty guard                                                        | PASS     | utxo.lua:4613-4618 returns Core's exact "Can't activate a snapshot when mempool not empty" when mempool:size() > 0. RPC layer (rpc.lua:7854) passes mempool through. Strong. |
| G29 | PopulateAndValidateSnapshot per-coin guards: coin.nHeight > base_height (Core line 5814)    | PASS     | utxo.lua:4684-4687 raises Core's exact "Bad snapshot data after deserializing N coins" error string when entry.height > effective_base_height. |
| G30 | PopulateAndValidateSnapshot MoneyRange + trailing-bytes + HASH_SERIALIZED gate              | PARTIAL  | utxo.lua:4692-4696 MoneyRange via `entry.value < 0 or entry.value > consensus.MAX_MONEY` (PASS); 4710-4721 trailing-bytes check (PASS); 4734-4753 HASH_SERIALIZED check (PASS when `expected_hash` is passed). **However**, the RPC layer `loadtxoutset` (rpc.lua:7853) calls `load_snapshot(path, nil, au_height, active_tip, mempool)` — passes nil for expected_hash. This means the strict gate at utxo.lua:4734-4753 is bypassed; only the `--import-utxo` CLI path passes expected_hash (and even there main.lua:617 passes nil too). **The Core-equivalent strict gate at validation.cpp:5904-5915 ALWAYS runs**; lunarblock makes it optional and never invokes it from any caller. A maliciously-crafted snapshot with the right base_blockhash but wrong UTXOs would be silently accepted. BUG-12 P0 (consensus-class: trusts attacker-supplied data without hash check). |

Additional bugs observed outside the 30 gates (carry-over context):

- **BUG-13 P1**: `outpoint.n >= std::numeric_limits<uint32_t>::max()` overflow
  guard (Core validation.cpp:5815) absent in lunarblock. utxo.lua:4678 reads
  vout via `r.read_varint()` and consumes whatever value comes back; no upper
  bound. A snapshot with vout = 0xFFFFFFFF (uint32 max) would trip a Core
  rejection but lunarblock would accept it, then later coin_view:add would
  produce a 36-byte outpoint key with vout=0xFFFFFFFF that downstream code
  treats as the coinbase-marker-style sentinel (outpoint_key zeroes vout
  bytes 32-35 for coinbase — see utxo.lua:917-924 outpoint_key). Subtle.
- **BUG-14 P1**: BackgroundValidator class (utxo.lua:4809-4895) is **never
  instantiated** anywhere in the tree. `grep -rn 'new_background_validator\b'
  src/` returns nothing. The class is dead code. Its `step()` method does
  validation work but no main loop / sync.lua hook calls it. As a result
  lunarblock's snapshot loads NEVER complete a background-from-genesis
  validation, NEVER recompute the UTXO hash from a from-scratch chainstate,
  NEVER promote UNVALIDATED→VALIDATED. The fast-sync mode is effectively
  "trust the snapshot bytes forever".
- **BUG-15 P1**: SnapshotChainstate class (utxo.lua:4772-4806) is also dead
  code — no caller invokes `new_snapshot_chainstate`. The single-chainstate
  model is hard-coded.
- **BUG-16 P1**: No `m_chain_tx_count` threading. consensus.lua:950+ records
  the value (e.g. 991032194 for h=840k) but loadtxoutset / load_snapshot
  never write it into any block-index entry. `getblockchaininfo`'s
  verificationprogress (rpc.lua:1298) is `tip_height / 880000`, completely
  ignoring m_chain_tx_count. Post-snapshot the user sees "progress 95%"
  while background-IBD-from-genesis is at 0% (or rather doesn't exist).
- **BUG-17 P2**: No `getchainstates` RPC. rpc.lua registers
  `dumptxoutset` + `loadtxoutset` but not the third member of the trio.
  Cross-impl test-suite probes that read `chainstates[*].snapshot_blockhash`
  would fail with "method not found".
- **BUG-18 P2**: No `snapshot_blockhash` field in getblockchaininfo response
  (rpc.lua:1339-1359 result table). Core (rpc/blockchain.cpp:1824) emits
  `"It may be unknown when using assumeutxo"` field plus the actual
  snapshot_blockhash when active chainstate is snapshot-built.

## Cumulative findings

PASS: 14 gates (G1, G2, G5, G6, G7, G9, G10, G12, G13, G15, G16, G17, G19,
G20, G21, G22, G28, G29 — recount: 18 PASS).
PARTIAL: 6 gates (G4, G8, G11, G23, G27, G30).
BUG: 2 gates (G3, G14, G18).
MISSING: 3 gates (G24, G25, G26).

(Some gates list 1 status but log multiple BUGs in the same line; total
distinct BUG IDs catalogued: BUG-1 .. BUG-18.)

Total **18 distinct BUGs catalogued**. Distribution by severity:

- **P0 (consensus-divergent OR attacker-exploitable):**
  - BUG-6 (G18) — compress_script always-raw branch. lunarblock dumps are
    byte-INCOMPATIBLE with Core dumps over the same UTXO set; cross-impl
    snapshot exchange / fleet hash compare would split.
  - BUG-8 (G24) — best-headers-ancestor check missing. Forked-headers
    snapshot acceptance.
  - BUG-9 (G25) — snapshot_start_block-in-headers-chain check missing.
    Hollow chainstate possible.
  - BUG-12 (G30) — HASH_SERIALIZED strict gate optional and never invoked
    by either RPC or CLI loader. Trusts attacker-supplied snapshot UTXOs.

- **P1 (correctness / DoS / operator-error class):**
  - BUG-5 (G14) — nchaintx is UTXO count, not tx count. Off by ~10x.
  - BUG-7 (G23) — duplicate-activation guard does not survive restart
    (no on-disk persistence of from_snapshot_blockhash).
  - BUG-10 (G26) — BLOCK_FAILED_VALID guard missing on loadtxoutset.
  - BUG-11 (G27) — work-exceeds-active uses height-as-work-proxy
    (incorrect across forks of differing difficulty).
  - BUG-13 (outside G) — outpoint.n uint32-max overflow guard absent.
  - BUG-14 (outside G) — BackgroundValidator dead code; UNVALIDATED→VALIDATED
    transition NEVER happens.
  - BUG-15 (outside G) — SnapshotChainstate dead code; single-chainstate
    model hard-coded.
  - BUG-16 (outside G) — m_chain_tx_count never threaded into block index;
    verificationprogress nonsensical post-snapshot.

- **P2 (correctness, no consensus / no DoS):**
  - BUG-1 (G3) — version=1 acceptance (Core supports only version=2).
  - BUG-2 (G4) — generic network-magic-mismatch error string.
  - BUG-3 (G8) — by-hash rollback is O(N) linear scan instead of O(1).
  - BUG-4 (G11) — NetworkDisable pauses only the submitblock RPC site,
    not P2P inbound.
  - BUG-17 (outside G) — no getchainstates RPC.
  - BUG-18 (outside G) — no snapshot_blockhash field in getblockchaininfo.

## Top 5 findings

1. **BUG-12 P0 HASH_SERIALIZED strict gate is optional and never invoked.**
   `utxo.lua:4734-4753` correctly implements the SHA256d-via-HashWriter
   comparison against `expected_hash` and emits "snapshot hash mismatch
   (hash_serialized)" on mismatch. **Both callers pass nil for
   expected_hash**: rpc.lua:7853 (`load_snapshot(path, nil, au_height, ...)`)
   and main.lua:617 (`cs:load_snapshot(args.import_utxo)`). The chainparams
   `assumeutxo.hash_serialized` value (consensus.lua:949 etc.) is matched
   against the *blockhash* (rpc.lua:7811-7813
   `assumeutxo_for_blockhash(rpc.network, base_hash_hex)`) but the
   `hash_serialized` field is then DISCARDED. Core
   (validation.cpp:5912-5914): `if (AssumeutxoHash{maybe_stats->hashSerialized}
   != au_data.hash_serialized) return error("Bad snapshot content hash:
   expected X, got Y")` — runs ALWAYS, not optionally. **Real-world
   exposure**: a peer-distributed snapshot file with a valid base_blockhash
   header but maliciously rewritten UTXO body (e.g., extra coins,
   reassigned scripts) would be silently accepted by lunarblock and the
   node would serve a forked chain. **Fix shape**: at rpc.lua:7853 and
   main.lua:617, read `au_data.hash_serialized` (reverse from display-hex
   to natural-LE 32 bytes), and pass as expected_hash to load_snapshot.
   Test: feed a snapshot with the correct header but a single-coin-value
   delta in the body; expect rejection.

2. **BUG-8 / BUG-9 P0 missing best-headers / start-block-in-headers gates.**
   Core's loadtxoutset performs THREE structural checks before accepting a
   snapshot (validation.cpp:5611-5624): (a) snapshot_start_block must be in
   m_blockman.LookupBlockIndex (i.e., headers pre-synced to at least the
   snapshot height), (b) start_block must not be BLOCK_FAILED_VALID, and
   (c) m_best_header->GetAncestor(snapshot_start_block->nHeight) must equal
   snapshot_start_block (no competing more-work header chain exists).
   lunarblock has NONE of these. The brute-force `for h = 0, tip_height`
   scan at rpc.lua:7828-7836 is only invoked in the assumeutxo-not-found
   error branch and only to compute a height for a log message. **A node
   that has not yet completed headers sync** can load a snapshot anyway,
   and serve it as the active chain — peer responses for blocks at heights
   < snapshot_base will return "block not found". **A node with a malicious
   forked header chain** can load a competing snapshot to ratify the fork.
   Fix: add LookupBlockIndex(base_blockhash) ≠ nil check, invalid_blocks
   check, and header_chain.best_header.GetAncestor(snap_height) ==
   snapshot_start_block check before calling load_snapshot.

3. **BUG-6 P0 compress_script always-raw branch.** `utxo.lua:740-752`
   compress_script ALWAYS emits the raw branch `VARINT(size+6) + bytes`
   even when the script matches one of the 6 recognized special types
   (P2PKH 0x00 / P2SH 0x01 / P2PK-compressed 0x02-0x03 / P2PK-uncompressed
   0x04-0x05). The detection helpers `_is_p2pkh`, `_is_p2sh`,
   `_is_p2pk_compressed` are DEFINED (utxo.lua:699-728) but referenced only
   as `local _ = ...` no-ops at 745-747 — the comment at 741-744
   acknowledges this as a TODO ("Phase 1: we only emit the 'raw' branch").
   The **decompress side** correctly handles all six types (utxo.lua:774-810)
   so lunarblock CAN consume Core-emitted snapshots; but the asymmetry
   means **lunarblock-emitted snapshots are NOT byte-identical to
   Core-emitted snapshots** for the same UTXO set. The result is that
   `dumptxoutset.txoutset_hash` returned in the RPC reply (rpc.lua:7761-7770)
   is the SHA256d-via-HashWriter of the deserialized UTXO TxOutSer stream
   (which IS Core-compatible — see compute_utxo_hash), but if anyone later
   re-hashes the on-disk DUMP file (e.g., with `sha256sum utxo.dat` for
   cross-node integrity probes), the digests will differ. For real Bitcoin
   chainstates where ~95% of outputs are P2PKH/P2SH/P2WPKH/P2TR, the
   lunarblock dump is **~3-4x larger** than Core's. Fix: invoke
   _is_p2pkh / _is_p2sh / _is_p2pk_compressed in compress_script and emit
   type-byte forms 0x00..0x03; leave P2PK-uncompressed (0x04/0x05) for a
   follow-up since it requires libsecp256k1 round-trip.

4. **BUG-14 P1 BackgroundValidator dead code; UNVALIDATED state permanent.**
   `utxo.lua:4809-4895` defines BackgroundValidator with step(), progress(),
   is_complete(), get_error() methods. `grep` shows it is **never
   instantiated anywhere** — neither `main.lua`, `sync.lua`, nor `rpc.lua`
   calls `new_background_validator`. The class exists for completeness
   only. Core's MaybeCompleteSnapshotValidation (validation.cpp:5972-6080)
   is the canonical "snapshot acceptance is provisional until background
   IBD verifies the UTXO set from genesis"; lunarblock's snapshots are
   accepted **permanently and unconditionally** on initial load (modulo
   BUG-12 which compounds this). The operational consequence: a node that
   loaded an attacker-supplied snapshot will never reconcile via background
   IBD; the only recovery is `reindex_chainstate` (utxo.lua:1744). Real-world
   exposure depends on whether the snapshot source is trusted; the
   assumeutxo design INTENDS background validation to be a backstop against
   exactly that question. Fix: instantiate BackgroundValidator in main.lua's
   daemon loop when `chain_state.from_snapshot_blockhash ~= nil`, step it
   in the background-thread / coroutine, and on completion either commit
   `from_snapshot_blockhash = nil` (validated) or trigger a fatal error +
   datadir rename to `chainstate_invalidated/` (Core's
   InvalidateCoinsDBOnDisk pattern).

5. **BUG-7 P1 from_snapshot_blockhash not persisted across restart.**
   `utxo.lua:1573` initializes `ChainState.from_snapshot_blockhash = nil`
   in the constructor; `load_snapshot` at line 4762 sets it after a
   successful load; the duplicate-activation guard at 4594-4596 refuses a
   second load. **But the field is in-memory ONLY** — there is no analog
   to Core's `WriteSnapshotBaseBlockhash` / `ReadSnapshotBaseBlockhash`
   pair (utxo_snapshot.cpp:22-81) which writes the base_blockhash to
   `<chainstate>/base_blockhash` so the chainstate manager can rebuild
   the state on next startup. After daemon restart, `ChainState:init()`
   (utxo.lua:1625-1636) reads only the chain tip from storage; the
   from_snapshot field stays nil; a second loadtxoutset will go through.
   Operator-mistake-class: a user who loads a snapshot, restarts the
   daemon for ANY reason (config change, OOM, ops), and accidentally
   re-runs `loadtxoutset` will overwrite the UTXO set against a Coins
   cache that already contains the connected blocks since the snapshot.
   The resulting chainstate is corrupt and must be reindexed. Fix: write
   from_snapshot_blockhash into CF.META (a 32-byte value at key
   `"snapshot_base_blockhash"`) on successful load; read it in
   ChainState:init() and seed the field before the constructor returns.

## Universal patterns observed (carry-back to fleet)

1. **"dead-class-no-caller" pattern (5th occurrence in lunarblock alone)**:
   utxo.lua's `SnapshotChainstate` (4772-4806) and `BackgroundValidator`
   (4809-4895) define methods that have no callers anywhere. Similar to
   the pattern in W120 (validateRbfDiagram dead helper), W121 (BIP-157
   handler shells), W137 (analyzepsbt vsize/feerate nil). The lunarblock
   convention seems to be: write the type, then defer the wiring as a
   "future work" follow-up. Audit framework should flag this directly via
   a `grep -rn 'new_<class>\b'` source-grep gate on every new typed class.

2. **"strict-gate-made-optional" pattern**: BUG-12 (HASH_SERIALIZED gate
   exists but expected_hash defaults to nil and no caller passes it). Compare
   to FIX-72/76 mapDeltas persistence brief-error (where the gate existed
   but the codepath bypassed it). The fleet-wide audit framework should
   specifically check: "for every Core gate that is unconditional, the
   lunarblock equivalent must also be unconditional (no `if expected_hash`
   wrapper)".

3. **"height-as-work-proxy" anti-pattern**: BUG-11 explicitly uses tip
   height as monotone proxy for chainwork, with comment acknowledging the
   limitation. This pattern surfaces across multiple impls (rustoshi
   pre-FIX-XX, blockbrew pre-FIX-XX) — usually safe on mainnet but
   incorrect across forks of differing difficulty. The audit framework
   should flag any work comparison that operates on `height` rather than
   `chainwork`.

4. **"in-memory-only persistence" pattern**: BUG-7 (from_snapshot_blockhash
   nil-on-restart). Echoes W120 mapDeltas (load-side gap), W118 wallet
   bumpfee state. The audit framework should specifically check every
   `self.field = nil` ChainState initialization against a CF.META read in
   ChainState:init().

5. **"linear-scan-where-O(1)-exists" pattern**: BUG-3 (rpc.lua:7605-7609
   linear scan over heights 0..tip to resolve a blockhash → height).
   Similar to W124 operator UX gaps. The audit framework should flag any
   `for h = 0, tip` loop without a comment explaining why a hash-table
   lookup isn't appropriate.

## Out of scope

- BIP-371 Taproot snapshot fields (n/a — assumeUTXO is Bitcoin Core feature, no BIP).
- Migration from snapshot leveldb format to RocksDB format (lunarblock
  uses RocksDB throughout; no migration needed).
- Coordinated activation on regtest (lunarblock regtest assumeutxo table
  is empty; the chainparams design intentionally leaves it for tests to
  populate dynamically).
- Snapshot-as-pruning-source (Core's PruneAndFlush after snapshot
  activation). Pruning is W- pre-W138 scope.

## Test corpus

See `tests/test_w138_assumeutxo.lua` for 30 gate tests + structural-absence
tests for the 6 missing/partial features above.
