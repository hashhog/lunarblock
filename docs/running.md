# Running lunarblock

Start the node from the repository root:

```bash
LD_LIBRARY_PATH=./lib luajit src/main.lua [OPTIONS]
```

`--help` prints the option list and `--version` the version. Both exit at once.

## Command-line options

Options that take a value read it from the next argument (`--datadir DIR`). The ones
marked `=` also accept `--flag=value`; the others do not, and an unknown option stops
the node with `Unknown option: ...`. Boolean values may be `1/0`, `true/false`,
`yes/no` or `on/off`.

### General

| Option | Default | Meaning |
|---|---|---|
| `-d`, `--datadir DIR` | `~/.lunarblock` | Data directory. Non-mainnet networks use `DIR/<network>`. |
| `-n`, `--network NET` | `mainnet` | `mainnet`, `testnet4`, `testnet` (testnet3) or `regtest`. |
| `--testnet` | off | Same as `--network testnet` (testnet3). |
| `--regtest` | off | Same as `--network regtest`. |
| `--conf PATH` (`=`) | none | Read a config file (see below). |
| `--daemon` | off | Detach into the background; output goes to the log file. |
| `--pid PATH` (`=`) | `<datadir>/lunarblock.pid` | PID file. |
| `--ready-fd N` (`=`) | none | Write a ready token to file descriptor `N` once the listeners are up. |
| `--log PATH` (`=`) | `<datadir>/debug.log` | Log file. |
| `--debug CATS` (`=`) | none | Comma-separated log categories, or `1` for all: `net`, `mempool`, `rpc`, `bench`, `prune`, `zmq`, `validation`, `leveldb`, `tor`, `rand`, `addrman`, `ibd`, `consensus`, `p2p`, `wallet`. |
| `--printtoconsole` | off | Also copy category log lines to standard output. |
| `--nowalletcreate` | off | Do not create a default wallet on first start. |

### Validation and storage

| Option | Default | Meaning |
|---|---|---|
| `--dbcache MB` | `450` | RocksDB cache size. |
| `--par N` (`=`) | `0` | Script-check threads: `0` = one per CPU (up to 16), `1` = serial, negative = leave that many CPUs free. |
| `--noassumevalid[=BOOL]` | off | Check every script from genesis. |
| `--assumevalid HASH` (`=`) | built in | Trust scripts in ancestors of `HASH` instead of the built-in block; `0` is the same as `--noassumevalid`. |
| `--prune N` | `0` | `0` keeps every block, `1` prunes only on `pruneblockchain`, `550` or more is a target size in MB. |
| `--reindex-chainstate` | off | Wipe the UTXO set and undo data and reconnect every stored block. |
| `--reindex` | off | Currently the same as `--reindex-chainstate`. |
| `--txindex[=BOOL]` | off | Transaction index for `getrawtransaction` on confirmed transactions. |
| `--blockfilterindex[=BOOL]` | off | BIP-157/158 basic block filters (`getblockfilter`). |
| `--coinstatsindex[=BOOL]` | off | Per-height UTXO statistics (`gettxoutsetinfo` at past heights). |
| `--txospenderindex[=BOOL]` | off | Spent-outpoint index (`gettxspendingprevout` for confirmed spends). |
| `--import-blocks FILE` | none | Import blocks from a framed file (`-` for stdin), then exit. Each frame is a 4-byte little-endian height, a 4-byte little-endian size and the raw block. |
| `--import-utxo FILE` | none | Load a UTXO snapshot written by `dumptxoutset` (Core's format), then exit. If the snapshot's block is in the built-in assumeutxo table, the loaded set's hash must match it or the import fails. |
| `--mempool-fullrbf BOOL` (`=`) | `1` | Full replace-by-fee. `0` requires BIP-125 signalling. |

### Network

| Option | Default | Meaning |
|---|---|---|
| `--port PORT` | per network | P2P listen port. |
| `--bind ADDR[:PORT]` (`=`) | `0.0.0.0` and `[::]` | P2P listen address; repeat for several. |
| `--maxpeers N`, `--maxconnections N` (`=`) | `125` | Connection limit. |
| `--connect IP[:PORT]` | none | Connect only to this peer. |
| `--externalip IP[:PORT]` (`=`) | none | Address to advertise; repeatable; turns `--discover` off. |
| `--discover[=BOOL]`, `--nodiscover` | on | Learn the node's own address from outbound peers. |
| `--nov2transport` | off | Turn off BIP-324 encrypted transport. |
| `--asmap PATH` (`=`) | none | ASMap file for grouping peers by AS number. |
| `--peerbloomfilters BOOL` | `0` | Serve BIP-37 bloom filters. |
| `--peerblockfilters BOOL` (`=`) | `0` | Advertise BIP-157 filters. Has no effect yet: the BIP-157 P2P messages are not served. |

### RPC, REST, notifications, metrics

| Option | Default | Meaning |
|---|---|---|
| `--rpcport PORT` | per network | JSON-RPC port, bound to `127.0.0.1`. |
| `--rpcuser USER` | `lunarblock` | RPC user name. |
| `--rpcpassword PW` | empty | RPC password. Empty means no authentication. |
| `--rpc-tls-cert PATH`, `--rpc-tls-key PATH` (`=`) | none | Serve RPC over TLS; give both. Needs LuaSec. |
| `--rest` | off | Read-only REST API, no authentication, on `127.0.0.1`. |
| `--restport PORT` | `8080` | REST port. |
| `--zmqpubhashblock`, `--zmqpubhashtx`, `--zmqpubrawblock`, `--zmqpubrawtx`, `--zmqpubsequence ENDPOINT` | none | ZeroMQ publishers (Core's topics). Need libzmq. |
| `--zmqpubhwm N` | `1000` | ZeroMQ high-water mark. |
| `--metricsport PORT` | `9332` | Prometheus metrics on all interfaces; `0` turns it off. |
| `--jitprofile`, `--jitverbose` | off | Write LuaJIT profiler or trace output to `jit_profile.txt` / `jit_verbose.txt` in the data directory. |

## Config file

`--conf PATH` reads a `bitcoin.conf`-style file: `key=value` lines, `#` or `;` comments,
and optional `[main]`, `[test]` or `[regtest]` sections whose keys apply only to that
network. Keys outside a section apply to every network. Values are taken literally, so
do not quote them. Command-line options win over the file.

Recognised keys: `datadir`, `network`, `rpcport`, `rpcuser`, `rpcpassword`,
`rpc-tls-cert`, `rpc-tls-key`, `port`, `bind`, `maxpeers`, `maxconnections`, `dbcache`,
`connect`, `printtoconsole`, `nowalletcreate`, `daemon`, `reindex`, `prune`,
`metricsport`, `rest`, `restport`, `pid`, `debug`, `log`, `nov2transport`,
`peerbloomfilters`, `ready-fd`, `noassumevalid`, `assumevalid`, `externalip`, `discover`.
Other keys are ignored without a warning.

```bash
cat > "$DATADIR/lunarblock.conf" <<'EOF'
rpcpassword=changeme
[regtest]
rpcport=18555
EOF
LD_LIBRARY_PATH=./lib luajit src/main.lua --regtest --datadir "$DATADIR" --conf "$DATADIR/lunarblock.conf" > "$DATADIR/node.log" 2>&1 &
sleep 5
curl -s --user lunarblock:changeme -d '{"method":"getblockcount","params":[]}' http://127.0.0.1:18555/
curl -s --user lunarblock:changeme -d '{"method":"stop","params":[]}' http://127.0.0.1:18555/
```

The file is not read automatically; pass `--conf`. `config.example.toml` in the
repository root is in a different (TOML) layout that this parser does not read.

## Networks and ports

| Network | P2P | RPC |
|---|---|---|
| mainnet | 8333 | 8332 |
| testnet4 | 48333 | 48332 |
| testnet (testnet3) | 18333 | 18332 |
| regtest | 18444 | 18443 |

There is no signet.

## Data directory

For regtest started with `--datadir D`, files live in `D/regtest/`:

| Path | Contents |
|---|---|
| `chainstate/` | RocksDB: headers, blocks, UTXO set, undo data, height index and the optional indexes, as column families |
| `wallet.json`, `wallets/` | default wallet and named wallets |
| `mempool.dat` | mempool saved at shutdown, reloaded at start |
| `fee_estimates.dat` | fee estimator state |
| `peers.dat` | known peer addresses |
| `debug.log` | category log (see below) |
| `lunarblock.pid`, `.lock` | PID file and the lock that stops two nodes using one directory |

Blocks are stored in RocksDB, not in Core's `blk*.dat` files, so the data directory
cannot be shared with Bitcoin Core.

## Resources

An unpruned mainnet node stores every block, so plan for at least as much fast disk as
Bitcoin Core (several hundred GB), or use `--prune`. Memory use grows with `--dbcache`;
the node logs its resident size in its periodic `[DIAG] ... rss_kb=...` line, so you can
watch it.

## Logging

Startup messages and a progress line every few seconds go to standard output; redirect
it to a file as in the examples. Messages for the categories enabled with `--debug` go to
`debug.log` (or `--log PATH`), and also to standard output with `--printtoconsole`.
`SIGHUP` reopens the log file, for log rotation. `SIGINT` or `SIGTERM` (or the `stop` RPC)
shut the node down cleanly, saving the mempool and fee estimates.

## Monitoring

- `GET /health` on the RPC port returns `{"status":"ok","height":N,...}` while the node is
  responsive. It needs the RPC credentials like any other request.
- The metrics port serves Prometheus text format.
- The usual RPCs: `getblockchaininfo`, `getpeerinfo`, `getmempoolinfo`, `getnetworkinfo`.

```bash
curl -s --user lunarblock:changeme http://127.0.0.1:18443/health
curl -s http://127.0.0.1:9332/metrics | head
```
