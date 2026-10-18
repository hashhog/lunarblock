# Architecture

lunarblock is plain Lua run by LuaJIT. Cryptography and storage go through LuaJIT's FFI
straight to C libraries (OpenSSL, libsecp256k1, RocksDB), and three small C helpers in
`csrc/` speed up hashing, script checks and UTXO reads. Every module lives in `src/`;
`lunarblock/` holds generated shims so that `require("lunarblock.<name>")` finds them
when the node is run from the repository root (`tools/regen-shims.sh` rebuilds them,
`tools/check-file-sync.sh` checks them).

## Main loop

`src/main.lua` parses the options, opens storage, loads the chain state, starts the RPC,
REST, metrics and P2P listeners, and then runs one event loop. Each pass reads from
sockets, processes P2P messages, connects downloaded blocks, accepts mempool
transactions and answers RPC requests. Long RPC calls yield back to the loop. Shutdown
signals are blocked in every thread and collected by the loop, so `SIGTERM` always ends
in an orderly shutdown.

## Moving parts

| Part | Files | Notes |
|---|---|---|
| Types and serialization | `src/types.lua`, `src/serialize.lua` | Transactions, blocks, compact sizes; 64-bit amounts use FFI integers. |
| Crypto | `src/crypto.lua`, `src/muhash.lua`, `src/sig_cache.lua`, `csrc/sha256_accel.c` | SHA-256 (SHA-NI/AVX2 when present), RIPEMD-160, secp256k1 ECDSA and Schnorr, MuHash3072, signature cache. |
| Script | `src/script.lua`, `src/miniscript.lua` | Interpreter for legacy, P2SH, SegWit v0 and Taproot (BIP-341/342) scripts. |
| Consensus rules | `src/consensus.lua`, `src/validation.lua` | Network parameters, soft-fork deployments, assume-valid, block and transaction checks, sigop and weight limits. |
| Parallel script checks | `src/script_check_worker.lua`, `csrc/parallel_verify.c` | Like Core's check queue: worker threads, each with its own Lua state, verify inputs while the main thread waits. `--par` sets the count. |
| Chain state | `src/utxo.lua` | UTXO cache with dirty/fresh flags, block connect and disconnect with undo data, reorgs, chain selection, AssumeUTXO snapshots (`loadtxoutset`, `--import-utxo`) with a background chain state. |
| Storage | `src/storage.lua`, `csrc/coin_prefetch.c` | One RocksDB database (`chainstate/`) with column families for headers, blocks, UTXOs, undo data, the height index and the optional indexes. Block bodies go to RocksDB blob files. |
| Indexes | `src/txindex.lua`, `src/blockfilter.lua`, `src/indexmanager.lua` | Transaction index, BIP-158 block filters, coin statistics, spent-outpoint index. All off by default. |
| Pruning | `src/prune.lua` | `--prune` and `pruneblockchain`. |
| Sync | `src/sync.lua` | Headers-first sync with anti-DoS header presync, parallel block download with per-peer limits and stall detection. |
| P2P | `src/p2p.lua`, `src/peer.lua`, `src/peerman.lua`, `src/bip324.lua`, `src/compact_block.lua`, `src/bloom.lua`, `src/erlay.lua`, `src/minisketch.lua`, `src/asmap.lua` | Message encoding, peer state, address manager with bucketing and anchors, BIP-324 v2 transport, BIP-152 compact blocks, BIP-37 bloom filters, BIP-330 (Erlay) sketches. |
| Mempool | `src/mempool.lua`, `src/mempool_persist.lua`, `src/fee.lua` | Policy checks, RBF, packages, ancestor/descendant and cluster limits, orphan pool, `mempool.dat`, fee estimation. |
| Mining | `src/mining.lua` | Block templates (`getblocktemplate`), `generatetoaddress`, `generateblock`. |
| RPC and REST | `src/rpc.lua`, `src/rest.lua`, `src/tip_notifier.lua` | JSON-RPC dispatch table, REST endpoints, wake-ups for the `waitfor*` calls. |
| Notifications | `src/zmq.lua` | ZeroMQ publishers. |
| Wallet | `src/wallet.lua`, `src/psbt.lua`, `src/bip39.lua`, `src/address.lua`, `src/bip21.lua`, `src/payjoin_*.lua` | HD keys (BIP-32/44/49/84/86), descriptors, coin selection, signing, encryption, PSBT (BIP-174/370), BIP-39 mnemonics, payjoin (BIP-78). Wallets are JSON files in the data directory. |
| Operations | `src/ops.lua`, `src/fault.lua`, `src/perf.lua` | Config file, logging, PID file, daemon mode, signals. Storage errors are raised as system faults, never as a verdict that a block is invalid. |

## Tests

- `spec/*_spec.lua`: busted specs, one or more per module. `spec/known_red.lua` lists
  tests that are expected to fail and are reported as pending, each with a reason.
- `tests/*.lua` and `test_*.lua` in the root: standalone scripts that print their own
  pass/fail counts and exit non-zero on failure. `spec/orphan_scripts_spec.lua` runs each
  of them as part of `make test`.
- `proof/r4/range-holes-closed.json`: recorded results that `tests/test_range_holes.lua`
  checks.
