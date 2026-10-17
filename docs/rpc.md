# RPC

lunarblock serves JSON-RPC over HTTP on `127.0.0.1` (port 8332 on mainnet, 18443 on
regtest; `--rpcport` changes it). It aims to match Bitcoin Core: the same method names,
parameters, result shapes and error codes. Requests may be JSON-RPC 1.0 or 2.0, single or
batched (up to 1,000 per batch).

## Authentication

HTTP Basic auth, user `--rpcuser` (default `lunarblock`) and password `--rpcpassword`.
There is no `.cookie` file and no `rpcauth`. With an empty password, the default, every
request is accepted without credentials, so set a password.

```bash
curl -s --user lunarblock:changeme \
  -d '{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":[]}' http://127.0.0.1:18443/
curl -s --user lunarblock:changeme \
  -d '[{"method":"getblockcount","params":[],"id":1},{"method":"getbestblockhash","params":[],"id":2}]' http://127.0.0.1:18443/
```

`help` lists every method; this table is the same list, grouped as Core groups them.

## Methods

140 methods. 127 have Core's names; 13 are lunarblock's own.

| Group | Methods |
|---|---|
| Blockchain (36) | `dumptxoutset`, `getbestblockhash`, `getblock`, `getblockchaininfo`, `getblockcount`, `getblockfilter`, `getblockfrompeer`, `getblockhash`, `getblockheader`, `getblockstats`, `getchainstates`, `getchaintips`, `getchaintxstats`, `getdeploymentinfo`, `getdifficulty`, `getmempoolancestors`, `getmempooldescendants`, `getmempoolentry`, `getmempoolinfo`, `getrawmempool`, `gettxout`, `gettxoutproof`, `gettxoutsetinfo`, `gettxspendingprevout`, `importmempool`, `loadtxoutset`, `preciousblock`, `pruneblockchain`, `savemempool`, `scanblocks`, `scantxoutset`, `verifychain`, `verifytxoutproof`, `waitforblock`, `waitforblockheight`, `waitfornewblock` |
| Control (6) | `getmemoryinfo`, `getrpcinfo`, `help`, `logging`, `stop`, `uptime` |
| Mining (7) | `getblocktemplate`, `getmininginfo`, `getnetworkhashps`, `getprioritisedtransactions`, `prioritisetransaction`, `submitblock`, `submitheader` |
| Generating and hidden (7) | `addpeeraddress`, `estimaterawfee`, `generateblock`, `generatetoaddress`, `getorphantxs`, `invalidateblock`, `reconsiderblock` |
| Network (14) | `addnode`, `clearbanned`, `disconnectnode`, `getaddednodeinfo`, `getaddrmaninfo`, `getconnectioncount`, `getnettotals`, `getnetworkinfo`, `getnodeaddresses`, `getpeerinfo`, `listbanned`, `ping`, `setban`, `setnetworkactive` |
| Raw transactions (19) | `analyzepsbt`, `combinepsbt`, `combinerawtransaction`, `converttopsbt`, `createpsbt`, `createrawtransaction`, `decodepsbt`, `decoderawtransaction`, `decodescript`, `descriptorprocesspsbt`, `finalizepsbt`, `fundrawtransaction`, `getrawtransaction`, `joinpsbts`, `sendrawtransaction`, `signrawtransactionwithkey`, `submitpackage`, `testmempoolaccept`, `utxoupdatepsbt` |
| Util (8) | `createmultisig`, `deriveaddresses`, `estimatesmartfee`, `getdescriptorinfo`, `getindexinfo`, `signmessagewithprivkey`, `validateaddress`, `verifymessage` |
| Wallet (30) | `backupwallet`, `bumpfee`, `createwallet`, `encryptwallet`, `getaddressinfo`, `getbalance`, `getbalances`, `getnewaddress`, `gettransaction`, `getwalletinfo`, `importdescriptors`, `listdescriptors`, `listtransactions`, `listunspent`, `listwalletdir`, `listwallets`, `loadwallet`, `psbtbumpfee`, `rescanblockchain`, `restorewallet`, `send`, `sendtoaddress`, `signmessage`, `signrawtransactionwithwallet`, `unloadwallet`, `walletcreatefundedpsbt`, `walletlock`, `walletpassphrase`, `walletpassphrasechange`, `walletprocesspsbt` |

### lunarblock's own methods

| Method | What it does |
|---|---|
| `getinfo` | Summary of chain, network and wallet state (Core removed its `getinfo` long ago). |
| `dumpprivkey`, `importprivkey` | Export or import one WIF key (Core dropped these with legacy wallets). |
| `getwalletmnemonic`, `importmnemonic` | Show the wallet's BIP-39 phrase, or create a wallet from one. |
| `getpayjoinrequest`, `sendpayjoinrequest` | BIP-78 payjoin, receiver and sender side. |
| `dumpmempool`, `loadmempool` | Write or read `mempool.dat` at a given path. |
| `submitblocks`, `submitblockbatch` | Submit several hex blocks in one call; returns one result per block. |
| `getsyncstate` | Header and block sync progress in one object. |
| `jitprofileflush` | Flush the LuaJIT profiler output (with `--jitprofile`). |

## Core methods not implemented

- Wallet: `abandontransaction`, `abortrescan`, `createwalletdescriptor`,
  `getaddressesbylabel`, `gethdkeys`, `getrawchangeaddress`, `getreceivedbyaddress`,
  `getreceivedbylabel`, `importprunedfunds`, `keypoolrefill`, `listaddressgroupings`,
  `listlabels`, `listlockunspent`, `listreceivedbyaddress`, `listreceivedbylabel`,
  `listsinceblock`, `lockunspent`, `migratewallet`, `removeprunedfunds`, `sendall`,
  `sendmany`, `setlabel`, `setwalletflag`, `simulaterawtransaction`,
  `walletdisplayaddress`, `enumeratesigners`.
- Blockchain and mempool: `getdescriptoractivity`, `getmempoolcluster`,
  `getmempoolfeeratediagram`.
- Other: `getzmqnotifications`, `getrawaddrman`, `generatetodescriptor`, `addconnection`,
  `sendmsgtopeer`, `setmocktime`, `mockscheduler`, `syncwithvalidationinterfacequeue`,
  `getprivatebroadcastinfo`, `abortprivatebroadcast`, `echo`, `echojson`, `echoipc`.

Without `setmocktime`, tests that move the clock cannot be run against lunarblock.

## Known differences from Core

- No cookie authentication; see above.
- `dumptxoutset` accepts Core's `rollback` option and returns `txoutset_hash`, which is
  the same `hash_serialized_3` value Core reports.

Everything else is meant to behave like Core. If you find a method whose answer differs
from Core's, please open an issue with both outputs.

## REST

With `--rest`, a read-only REST server listens on `127.0.0.1:8080` (`--restport`) without
authentication. It serves Core's endpoints: `/rest/block/<hash>`,
`/rest/block/notxdetails/<hash>`, `/rest/tx/<txid>`, `/rest/headers/<count>/<hash>`,
`/rest/blockhashbyheight/<height>`, `/rest/getutxos/...`, `/rest/mempool/info`,
`/rest/mempool/contents`, `/rest/chaininfo`, `/rest/blockfilter/...` and
`/rest/blockfilterheaders/...`, each with a `.json`, `.bin` or `.hex` suffix as in Core.

```bash
curl -s http://127.0.0.1:8080/rest/chaininfo.json
```
