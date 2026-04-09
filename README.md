# lunarblock

A Bitcoin full node implementation in Lua, targeting LuaJIT 2.1.

## Quick Start

### Docker

```bash
docker build -t lunarblock .
docker run -v lunarblock-data:/data -p 48351:48351 -p 48341:48341 lunarblock
```

### From Source

```bash
# Requires: luajit, luasocket, lua-cjson, libsecp256k1, openssl, rocksdb
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
| `--import-utxo FILE` | none | Import UTXO snapshot from HDOG file |

## RPC API

Bitcoin Core-compatible JSON-RPC 1.0/2.0 over HTTP with Basic auth.

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

lunarblock is built on LuaJIT 2.1, leveraging its trace-based JIT compiler to achieve near-native speeds for the hot validation loops. The FFI (Foreign Function Interface) provides zero-overhead bindings to libsecp256k1 for ECDSA/Schnorr signature verification and OpenSSL for SHA256/RIPEMD160 hashing, avoiding the Lua/C boundary overhead that standard `lua_CFunction` bindings would introduce. Buffer pools and LRU caches reduce GC pressure during block processing.

The node runs on a single-threaded event loop with a 20Hz tick rate, processing P2P messages, mempool transactions, and RPC requests in each cycle. The peer manager handles connection pooling, DNS seed discovery, and eclipse attack mitigations through bucketed address management with netgroup diversity enforcement. Block download uses a parallel sliding window with per-peer limits and adaptive stall detection.

The storage layer uses RocksDB via FFI bindings with column families to separate block headers, block data, UTXO set, and chain state metadata. The CoinView cache maintains dirty/fresh flags matching Bitcoin Core's design, flushing to disk periodically during IBD and on shutdown. Flat file block storage follows the Bitcoin Core blk*.dat format for cross-implementation compatibility.

The wallet supports BIP-32/44/84 hierarchical deterministic key derivation with WIF import/export capability. Multi-wallet support allows creating, loading, and unloading named wallets at runtime. Wallet encryption uses AES-256-CBC with passphrase-based key derivation, and PSBT support enables multi-party signing workflows through createpsbt, decodepsbt, and walletprocesspsbt RPCs.

## License

MIT
