# lunarblock

A Bitcoin full node written from scratch in Lua, running on LuaJIT 2.1. One of the ten [hashhog](https://github.com/hashhog) nodes.

> **Experimental.** hashhog nodes are independent re-implementations of Bitcoin Core for research and testing. Do not use them with real funds.

## Status

| Area | State |
|---|---|
| Mainnet validation | Validated mainnet from genesis to height 958,794 with script checks on, in 48 consecutive ranges (each range starts from the UTXO set the previous one ended with). The final UTXO set matched Bitcoin Core's `gettxoutsetinfo` `hash_serialized_3` there (`29692050…6e7af0`, 166,180,925 coins). How to reproduce: [docs/status.md](docs/status.md). |
| Consensus vectors | Passes all 1,222 entries of Bitcoin Core's `script_tests.json` and Core's `sighash.json` vectors. See [docs/status.md](docs/status.md#cores-test-vectors). |
| RPC | 140 JSON-RPC methods: 127 with Core's names, plus 13 of lunarblock's own. Optional read-only REST. See [docs/rpc.md](docs/rpc.md). |
| P2P | Headers-first sync, parallel block download, BIP-324 v2 transport, BIP-152 compact blocks, BIP-155 addrv2. |
| Wallet | HD wallets (BIP-32/39/44/84/86), descriptors, PSBT, multi-wallet, encryption. No `sendmany`, `sendall`, `lockunspent` or labels. Not audited. |
| Known limitations | No signet. Initial sync is much slower than Bitcoin Core's. See [docs/status.md](docs/status.md#known-limitations). |

Last updated: 2026-10-17.

## Quick start

Needs LuaJIT 2.1, a C compiler, and the OpenSSL, libsecp256k1 and RocksDB libraries
(loaded through LuaJIT's FFI), plus LuaSocket and lua-cjson. On Debian 13:

```bash
sudo apt-get install -y build-essential git luajit libluajit-5.1-dev lua-socket lua-cjson libssl-dev libsecp256k1-dev librocksdb-dev
git clone https://github.com/hashhog/lunarblock.git
cd lunarblock
make build
LD_LIBRARY_PATH=./lib luajit src/main.lua --version
```

`make build` compiles three small C helpers into `lib/` (hardware SHA-256, parallel
script checks, parallel UTXO reads). The node runs without them, only slower.

Start a regtest node in a throwaway data directory and make an RPC call:

```bash
export DATADIR=$(mktemp -d)
LD_LIBRARY_PATH=./lib luajit src/main.lua --regtest --datadir "$DATADIR" --rpcpassword changeme > "$DATADIR/node.log" 2>&1 &
sleep 5
curl -s --user lunarblock:changeme -d '{"method":"getblockchaininfo","params":[]}' http://127.0.0.1:18443/
curl -s --user lunarblock:changeme -d '{"method":"stop","params":[]}' http://127.0.0.1:18443/
```

Other distributions, optional libraries (ZeroMQ, LuaSec for RPC over TLS) and the
LuaRocks route are in [docs/building.md](docs/building.md).

## Running

```bash
LD_LIBRARY_PATH=./lib luajit src/main.lua --datadir "$HOME/.lunarblock" --rpcpassword changeme
LD_LIBRARY_PATH=./lib luajit src/main.lua --network testnet4 --rpcpassword changeme
LD_LIBRARY_PATH=./lib luajit src/main.lua --regtest --rpcpassword changeme
```

Mainnet is the default. Flags take their value as the next argument (`--datadir DIR`);
only some also accept `--flag=value`, so use the space form. The default data directory
is `~/.lunarblock`; every network except mainnet uses a subdirectory named after it
(`~/.lunarblock/testnet4`, `~/.lunarblock/regtest`). `--testnet` selects testnet3.

| Network | P2P port | RPC port |
|---|---|---|
| mainnet | 8333 | 8332 |
| testnet4 (`--network testnet4`) | 48333 | 48332 |
| testnet3 (`--testnet`) | 18333 | 18332 |
| regtest (`--regtest`) | 18444 | 18443 |

RPC binds to `127.0.0.1`. P2P listens on all interfaces. A Prometheus metrics endpoint
listens on all interfaces, port 9332 (`--metricsport 0` turns it off; a busy port only
logs a warning).

Blocks are kept in RocksDB inside the data directory. An unpruned mainnet node stores
every block, so plan for at least as much fast disk as Bitcoin Core needs, or use
`--prune 550` (or larger, in MB). `--dbcache MB` sizes the RocksDB cache (default 450).
`--noassumevalid` checks every script from genesis instead of trusting the built-in
assume-valid block.

All flags, the config file, the data directory layout and logging are in
[docs/running.md](docs/running.md).

## RPC

lunarblock aims to match Bitcoin Core's JSON-RPC interface: same method names,
parameters, result shapes and error codes. It accepts HTTP Basic auth with user
`lunarblock` (change with `--rpcuser`) and the password from `--rpcpassword`. There is no
cookie file, and if `--rpcpassword` is empty (the default) the RPC port accepts requests
without any authentication, so always set one.

```bash
curl -s --user lunarblock:changeme \
  -d '{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":[]}' http://127.0.0.1:18443/
```

The method list and known differences from Core are in [docs/rpc.md](docs/rpc.md).

## Development

```bash
make test
```

The suite uses [busted](https://lunarmodules.github.io/busted/) and needs no network and no
running node. Two tests read Bitcoin Core's script and sighash vectors, which are not
vendored; [docs/status.md](docs/status.md#test-suite) shows how to fetch them and how to
install busted.

```
src/main.lua          entry point, command-line flags, main loop
src/validation.lua    block and transaction checks; src/script.lua is the interpreter
src/consensus.lua     network parameters, deployments, assume-valid
src/utxo.lua          chain state, UTXO cache, connect/disconnect, reorgs
src/storage.lua       RocksDB (via FFI): blocks, headers, UTXO set, undo, indexes
src/sync.lua          headers-first sync and block download
src/peer.lua, src/peerman.lua, src/p2p.lua   P2P messages, peers, addrman
src/mempool.lua       mempool policy, RBF, packages
src/rpc.lua           JSON-RPC; src/rest.lua is REST
src/wallet.lua        HD wallet; src/psbt.lua, src/miniscript.lua
spec/, tests/, test_*.lua   test suite (spec/orphan_scripts_spec.lua runs the scripts)
```

`lunarblock/` holds generated shims that forward `require("lunarblock.<name>")` to `src/`
(regenerate with `tools/regen-shims.sh`). The full map is
in [docs/architecture.md](docs/architecture.md). See [CONTRIBUTING.md](CONTRIBUTING.md)
before opening a pull request.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
