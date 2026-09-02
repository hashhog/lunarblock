# lunarblock

A Bitcoin full node implementation in Lua, targeting LuaJIT 2.1.

## Status — v1.0.0

**Label: "Replay-pending — awaiting the stateless-replay run now in flight"**
(`receipts/RELEASE-v1.0-SCORECARD.md`, §What each label means). That label is
deliberately weaker than "Validated", and the scorecard spells out why: it means
lunarblock agreed with Core on every block the nightly instruments showed it — 169
distilled real mainnet blocks, 10 block-context corpus entries, and its row in the
nightly corpus sweep — and that a 26,067-height stateless replay was still running
when the release was written. **Until that run produces a `summary.json`, this node
has no from-genesis evidence at all.** The git tag `v0.1.0-beta1`
(`receipts/RELEASE-v1.0-FREEZE.md`) says the same thing from the other side: `rc`
is reserved for an independent from-genesis `--assumevalid=0` reproduction of
Core's UTXO-set commitment, and `beta` means that receipt does not exist
(`receipts/beta1-tag-drafts-2026-08-20.md:23-27`). Neither label certifies wallet
or fund-custody readiness — see `SECURITY.md`.

**lunarblock has not been shown to validate the chain from genesis, and on this
hardware it cannot finish trying.** There is no lunarblock row in the
reproduction ledger (`receipts/TRUST-ANCHOR.md:140-145`) and no lunarblock replay
ledger in `CORE-PARITY-AUDIT/replay-ledgers/`. `CHARTER.md` (§"R4 — Proven
validator", "Honest limit") measures lunarblock at ~609 blocks/hour, roughly two
months per from-genesis pass, and records the rung as unreachable for it without
different hardware or a native hot path; `receipts/TRUST-ANCHOR.md:172` says its genesis lineage is months out.
`receipts/TRUST-ANCHOR.md:187-198` (correction, 2026-09-01) additionally
retracts lunarblock's pre-2026-09-01 M2 boundary-campaign rows as script
evidence — those window blocks were connected with scripts **skipped** under the
default assumevalid: `submitblock` computes `skip_scripts` from
`consensus.should_skip_script_validation`, whose first condition is that
`network.assumevalid` is non-nil, and only `--noassumevalid` clears it
(`receipts/TRUST-ANCHOR.md:225-228`). A reader of this repository alone should
assume lunarblock's from-genesis validation is untested.

**Operator RPC parity: 56 of Bitcoin Core's 85.** From the 103-method R5
operator probe run 2026-09-01T18:26:42Z
(`tools/diff-test-artifacts/r5-probe/20260901T182642Z.json`): lunarblock 56 PASS
/ 29 FAIL, Bitcoin Core 85 PASS on the same probe, 18 methods unmeasured
(`SKIP-REGTEST`) for every node including Core. Cite the run, not "the score":
the probe ten minutes earlier
(`tools/diff-test-artifacts/r5-probe/20260901T181552Z.json`) scored lunarblock 58
with no deploy in between. **Three** of lunarblock's 29 failures are RPC
**timeouts** (`getblockheader`, `getblockchaininfo`, `getblock`) rather than wrong
answers; the other 26 are wrong answers, wrong error codes or wrong shapes. An
earlier draft said "several", which softened the score with a count the artifact
does not support.

**Known gaps in this repo** (`receipts/UNIT-BASELINE-v1.0.md`, 2026-09-01): the
unit suite is *measured, not fixed*, and 2026-09-01 was the **first time it had
ever been measured** — **256 failing tests** out of a total the baseline itself
marks NOT VERIFIED. None were triaged as test-bug or node-bug. The same pass
found the test runner writing `peers.dat`, `banlist.json`, `mempool.dat`,
`fee_estimates.json` and `*.log` into the repository (`6e2b2d2`).

**Fleet-wide comparison:** `receipts/RELEASE-v1.0-SCORECARD.md` in the hashhog
meta-repo, which is **not public** — see the note below.

> **The cited paths are NOT publicly readable — do not treat them as evidence.**
> Paths beginning `receipts/`, `tools/`, `docs/` and `CORE-PARITY-AUDIT/` refer to
> the hashhog meta-repo, which is a **private** repository, not to this one. They
> are provenance for the maintainers. From outside, any claim resting only on such
> a path is **unverified**, and you should read it as such.
>
> Two of those paths are unreadable even with the meta-repo in hand: the R5 probe
> JSON is gitignored (`.gitignore:60  tools/diff-test-artifacts/`) and so are the
> nightly `diffguard-*.log` files (`.gitignore:43  *.log`). Regenerate the probe
> JSON with `python3 tools/r5_probe.py` against a running fleet.
>
> **What you can check from this repository alone:** build it, run its own test
> suite, and reproduce its behaviour against Bitcoin Core yourself. That is the
> evidence this repo actually ships.

## Quick Start

### Docker

```bash
docker build -t lunarblock .
docker run -v lunarblock-data:/data -p 48351:48351 -p 48341:48341 lunarblock
```

### From Source

```bash
# Required: luajit, luasocket, lua-cjson, libsecp256k1, openssl, rocksdb
# Toolchain: LuaJIT 2.1 (rockspec: lua >= 5.1, luasocket >= 3.1.0, lua-cjson >= 2.1.0;
#   Dockerfile builds on debian:bookworm-slim apt packages). System libs loaded via
#   FFI: libcrypto (OpenSSL), libsecp256k1, librocksdb (C API) — Debian: apt install
#   libssl-dev libsecp256k1-dev librocksdb-dev lua-cjson lua-socket. Then run
#   `make build` to compile lib/sha256_accel.so (not tracked in git) before the
#   LD_LIBRARY_PATH=./lib commands below.
# Optional: lua-sec (luasec) — enables HTTPS/TLS termination on the
#           RPC server when --rpc-tls-cert/--rpc-tls-key are passed.
#           Install via `luarocks install luasec` or
#           `apt install lua-sec` on Debian/Ubuntu.  Without luasec
#           lunarblock runs fine in plaintext mode; the TLS flags
#           simply produce a clear startup error if you try to use them.
LD_LIBRARY_PATH=./lib luajit src/main.lua --help
LD_LIBRARY_PATH=./lib luajit src/main.lua --network mainnet
LD_LIBRARY_PATH=./lib luajit src/main.lua --regtest --nowalletcreate
```

## Features

- Full block and transaction validation (SegWit, Taproot, BIP68 sequence locks, sigop counting, PoW, merkle root)
- Script interpreter (stack-based VM, all standard opcodes, P2PKH, P2SH, P2WPKH, P2WSH, P2TR, BIP146 NULLFAIL)
- Header-first sync with PoW validation and difficulty adjustment
- Parallel block download with per-peer limits and adaptive stalling
- UTXO set with CoinView cache (dirty/fresh flags, flush strategy, connect/disconnect blocks)
- Mempool (tx acceptance, fee validation, RBF, CPFP, ancestor/descendant limits)
- BIP-152 compact block relay (SipHash-2-4, short txids, high-bandwidth mode)
- BIP-155 ADDRv2 (TorV3, I2P, CJDNS address support)
- BIP-324 v2 encrypted transport (can be disabled with `--nov2transport`)
- BIP-9 versionbits soft fork tracking
- Eclipse attack mitigations (bucketed addrman, anchor connections, outbound diversity)
- Peer misbehavior scoring and ban management
- Output descriptors (BIP380-386 parsing, checksum validation, address derivation)
- HD wallet (BIP-32/44/84, key derivation, tx signing, WIF import/export)
- Multi-wallet support (createwallet, loadwallet, unloadwallet, listwallets)
- Wallet encryption (AES-256-CBC with passphrase, walletpassphrase/walletlock)
- PSBT (createpsbt, decodepsbt, walletprocesspsbt)
- Fee estimation (bucketed tracking, decay weighting, confirmation targets)
- Block template construction (BIP22 getblocktemplate, coinbase creation, CPU miner)
- REST API (read-only, enabled with `--rest`)
- ZMQ notifications (hashblock, hashtx, rawblock, rawtx, sequence topics)
- Block pruning (0=disabled, 1=manual, >=550=target MB)
- Chain management (invalidateblock, reconsiderblock RPCs)
- Flat file block storage (Bitcoin Core compatible format)
- JIT profiling support (`--jitprofile`, `--jitverbose`)
- FFI bindings for performance-critical crypto (libsecp256k1, OpenSSL)

## Configuration

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--datadir DIR` | `~/.lunarblock` | Data directory |
| `--network NET` | `mainnet` | Network: mainnet, testnet, regtest |
| `--rpcport PORT` | per-network | RPC server port |
| `--rpcuser USER` | `lunarblock` | RPC username |
| `--rpcpassword PW` | empty | RPC password |
| `--rpc-tls-cert PATH` | none | PEM cert path — enables HTTPS RPC (pair with `--rpc-tls-key`; requires `luasec`) |
| `--rpc-tls-key PATH` | none | PEM private-key path — pair with `--rpc-tls-cert` |
| `--port PORT` | per-network | P2P listen port |
| `--maxpeers N` | `125` | Maximum peer connections |
| `--dbcache MB` | `450` | Database cache size in MB |
| `--connect IP:PORT` | none | Connect to specific peer |
| `--testnet` | off | Use testnet |
| `--regtest` | off | Use regtest |
| `--printtoconsole` | off | Print log to console |
| `--nowalletcreate` | off | Do not create wallet on first run |
| `--reindex` | off | Rebuild UTXO set from blocks |
| `--daemon` | off | Run as daemon |
| `--prune N` | `0` | Prune mode: 0=disabled, 1=manual, >=550=target MB |
| `--rest` | off | Enable REST API (no auth, read-only) |
| `--restport PORT` | `8080` | REST server port |
| `--zmqpubhashblock EP` | none | ZMQ endpoint for hashblock notifications |
| `--zmqpubhashtx EP` | none | ZMQ endpoint for hashtx notifications |
| `--zmqpubrawblock EP` | none | ZMQ endpoint for rawblock notifications |
| `--zmqpubrawtx EP` | none | ZMQ endpoint for rawtx notifications |
| `--zmqpubsequence EP` | none | ZMQ endpoint for sequence notifications |
| `--zmqpubhwm N` | `1000` | ZMQ high water mark |
| `--nov2transport` | off | Disable BIP-324 v2 encrypted transport |
| `--jitprofile` | off | Enable JIT profiling output |
| `--jitverbose` | off | Enable verbose JIT compilation logging |
| `--import-blocks FILE` | none | Import blocks from framed file (`-` for stdin) |
| `--import-utxo FILE` | none | Import UTXO snapshot from Core `dumptxoutset` file |

## RPC API

JSON-RPC 1.0/2.0 over HTTP with Basic auth, modelled on Bitcoin Core's. Not behaviourally compatible: on the 2026-09-01T18:26:42Z operator probe lunarblock answers 56 of the 103 probed methods correctly against Core's 85, with 29 failures — several of them RPC timeouts (`getblockheader`, `getblockchaininfo`) rather than wrong answers (`tools/diff-test-artifacts/r5-probe/20260901T182642Z.json`).

| Category | Methods |
|----------|---------|
| Blockchain | `getblockchaininfo`, `getblock`, `getblockhash`, `getblockheader`, `getblockcount`, `getbestblockhash`, `getchaintips`, `getdifficulty` |
| Transactions | `getrawtransaction`, `sendrawtransaction`, `decoderawtransaction` |
| Mempool | `getmempoolinfo`, `getrawmempool` |
| Mining | `getblocktemplate`, `submitblock`, `submitblocks`, `getmininginfo`, `generatetoaddress` |
| Network | `getnetworkinfo`, `getpeerinfo`, `getconnectioncount` |
| Wallet | `createwallet`, `loadwallet`, `unloadwallet`, `listwallets`, `listwalletdir`, `getwalletinfo`, `getnewaddress`, `getbalance`, `getbalances`, `listunspent`, `sendtoaddress`, `listtransactions`, `dumpprivkey` |
| Wallet Security | `encryptwallet`, `walletpassphrase`, `walletlock`, `walletpassphrasechange` |
| Descriptors | `getdescriptorinfo`, `deriveaddresses` |
| PSBT | `createpsbt`, `decodepsbt`, `walletprocesspsbt` |
| Util | `validateaddress`, `estimatesmartfee`, `getinfo` |
| Chain Mgmt | `invalidateblock`, `reconsiderblock` |
| Control | `stop` |

## Monitoring

No built-in Prometheus exporter. Monitor via RPC calls to `getblockchaininfo`, `getpeerinfo`, `getmempoolinfo`, and `getnetworkinfo`. JIT profiling output is available with `--jitprofile` for performance analysis.

## Architecture

lunarblock is built on LuaJIT 2.1 and uses its trace-based JIT compiler for the hot validation loops. "Near-native" would be an overstatement: the project measures lunarblock at ~609 blocks/hour on the reference machine — roughly two months for a single from-genesis pass — and records a full from-genesis validation as unreachable for it without different hardware or a native hot path (`CHARTER.md`, §"R4 — Proven validator" and §"R5", which notes that lunarblock "cannot complete a from-genesis validation" while exposing more Core RPCs than the flagship). The FFI (Foreign Function Interface) provides zero-overhead bindings to libsecp256k1 for ECDSA/Schnorr signature verification and OpenSSL for SHA256/RIPEMD160 hashing, avoiding the Lua/C boundary overhead that standard `lua_CFunction` bindings would introduce. Buffer pools and LRU caches reduce GC pressure during block processing.

The node runs on a single-threaded event loop with a 20Hz tick rate, processing P2P messages, mempool transactions, and RPC requests in each cycle. The peer manager handles connection pooling, DNS seed discovery, and eclipse attack mitigations through bucketed address management with netgroup diversity enforcement. Block download uses a parallel sliding window with per-peer limits and adaptive stall detection.

The storage layer uses RocksDB via FFI bindings with column families to separate block headers, block data, UTXO set, and chain state metadata. The CoinView cache maintains dirty/fresh flags matching Bitcoin Core's design, flushing to disk periodically during IBD and on shutdown. Flat file block storage follows the Bitcoin Core blk*.dat format for cross-implementation compatibility.

The wallet supports BIP-32/44/84 hierarchical deterministic key derivation with WIF import/export capability. Multi-wallet support allows creating, loading, and unloading named wallets at runtime. Wallet encryption uses AES-256-CBC with passphrase-based key derivation, and PSBT support enables multi-party signing workflows through createpsbt, decodepsbt, and walletprocesspsbt RPCs.

## License

MIT
