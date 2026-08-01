# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-31

First stable release. LunarBlock is a Bitcoin full node implementation in
Lua, targeting LuaJIT 2.1, with consensus, policy, and RPC behavior
differential-tested against Bitcoin Core (through v31).

### Features

- Full block and transaction validation (SegWit, Taproot, BIP68 sequence
  locks, sigop counting, PoW, merkle root), including Core's
  `script_flag_exceptions` for historical mainnet/testnet rule violators
- Script interpreter (stack-based VM, all standard opcodes, P2PKH, P2SH,
  P2WPKH, P2WSH, P2TR, BIP146 NULLFAIL)
- Header-first sync with PoW validation and difficulty adjustment;
  parallel block download with per-peer limits and adaptive stalling
- UTXO set with CoinView cache (dirty/fresh flags, flush strategy,
  connect/disconnect blocks); unbounded archive reorgs (pruning-gated
  depth cap only)
- Mempool: tx acceptance, fee validation, RBF (BIP125), CPFP via package
  acceptance, TRUC (v3) policy, and Core v31 cluster limits
  (64 transactions / 404,000 weight units per cluster) replacing the
  pre-v31 ancestor/descendant limits; ephemeral-dust 0-fee gate
  (Core `PreCheckEphemeralTx` parity)
- BIP-152 compact block relay, BIP-155 ADDRv2, BIP-324 v2 encrypted
  transport (disable with `--nov2transport`), BIP-9 versionbits tracking
- Eclipse-attack mitigations (bucketed addrman, anchor connections,
  outbound diversity), peer misbehavior scoring and bans
- HD wallet (BIP-32/44/84, key derivation, tx signing, WIF import/export),
  multi-wallet support, wallet encryption (AES-256-CBC), PSBT
  (createpsbt, decodepsbt, walletprocesspsbt), output descriptors
  (BIP380-386), miniscript compiler and satisfaction analysis
- Fee estimation (bucketed tracking, decay weighting, confirmation targets)
- Block template construction (BIP22 getblocktemplate, CPU miner)
- AssumeUTXO snapshot load/validation (Core `dumptxoutset` format)
- Indexes: txindex, blockfilterindex (BIP157/158), coinstatsindex
- REST API (read-only, `--rest`), ZMQ notifications, block pruning
- RocksDB storage with Snappy compression (graceful fallback to no
  compression when the linked librocksdb lacks Snappy)

### Release-candidate fixes since 0.1.0

- miniscript: `v:`-wrapper script generation no longer appends a spurious
  OP_VERIFY after a subexpression that already emitted its `-VERIFY` form
  (e.g. `v:pk(K)` is now `<key> CHECKSIGVERIFY`, matching Core's ToScript)
- miniscript policy parser: placeholder key names consisting of hex
  characters (e.g. "A") resolve via the key map instead of being silently
  misread as hex pubkeys
- base58: all-zero inputs no longer encode with a spurious extra `1`
  (Core `EncodeBase58` parity)
- storage: DB open falls back to `kNoCompression` with a warning when the
  linked librocksdb was built without Snappy (host portability)
- policy: adopt Core v31 `DEFAULT_MIN_RELAY_TX_FEE` = 100 sat/kvB
- test suite: stale assertions updated to intentional behavior changes
  (Core v31 cluster mempool limits, exact 256-bit chainwork
  representation, genesis filter-header chaining, `_type` field removal,
  ephemeral-dust standalone rejection); genuine known-gap trackers kept
  visible

### Infrastructure

- CI re-enabled (`.github/workflows/ci.yml`: Lua syntax check + Docker build)
- `lunarblock/` module shims regenerated and enforced by
  `tools/check-file-sync.sh`
- rockspec source URL corrected to `github.com/hashhog/lunarblock`

## [0.1.0] - 2026-03-08

Initial development series. 585 commits of consensus, P2P, wallet, and RPC
implementation with wave-based Core-differential audits (see git history).
