# W125 — JSON-RPC error code parity audit (lunarblock)

**Date:** 2026-05-17  
**Wave:** W125 (discovery)  
**Impl:** lunarblock (Lua / LuaJIT)  
**Status:** **17 BUGS FOUND** (0 P0, 4 P1, 10 P2, 3 P3)

## Context

Audits lunarblock's `src/rpc.lua` JSON-RPC error envelope against
Bitcoin Core's `RPCErrorCode` enum in `src/rpc/protocol.h` and the
canonical call-site mappings in `src/rpc/*.cpp` and
`src/wallet/rpc/*.cpp`. Every Bitcoin RPC SDK / desktop wallet / monitoring
tool consumes the integer `error.code` to discriminate "invalid input"
from "wallet locked" from "node still warming up". Divergent codes break
those clients silently.

Reference: `bitcoin-core/src/rpc/protocol.h`,
`bitcoin-core/src/rpc/server.cpp`, `bitcoin-core/src/wallet/rpc/util.cpp`,
`bitcoin-core/src/wallet/rpc/encrypt.cpp`, BIP-323 (where applicable).

## Method

1. Enumerate the `M.ERROR` table in `src/rpc.lua` (line 226-245).
2. Grep every `error({...})` call site in `src/rpc.lua` (~297 sites).
3. For each registered RPC method (`self.methods[...]`), find the
   Core equivalent in `bitcoin-core/src/rpc/` and compare the error
   code raised for each failure path.
4. Categorise into 30 W125 gates (table below).
5. Land xfail tests in `tests/test_w125_error_parity.lua` covering
   the divergent paths.

## Error table comparison

### Core `RPCErrorCode` (bitcoin-core/src/rpc/protocol.h)

JSON-RPC 2.0 reserved codes (-32700 .. -32600), plus Bitcoin
application codes -1 .. -36 (with -2 reserved historical).

### lunarblock `M.ERROR` (src/rpc.lua:226-245)

```
PARSE_ERROR              = -32700   ✓
INVALID_REQUEST          = -32600   ✓
METHOD_NOT_FOUND         = -32601   ✓
INVALID_PARAMS           = -32602   ✓  (JSON-RPC structural)
INTERNAL_ERROR           = -32603   ✓
MISC_ERROR               = -1       ✓
FORBIDDEN                = -2       ✓  (reserved/historical)
TYPE_ERROR               = -3       ✓
WALLET_ERROR             = -4       ✓
INVALID_ADDRESS          = -5       ✓  (alias of Core RPC_INVALID_ADDRESS_OR_KEY)
INSUFFICIENT_FUNDS       = -6       ✓
OUT_OF_MEMORY            = -7       ✓
DESERIALIZATION_ERROR    = -22      ✓
VERIFY_ERROR             = -25      ✓
VERIFY_REJECTED          = -26      ✓
VERIFY_ALREADY_IN_CHAIN  = -27      ✓
IN_WARMUP                = -28      ✓ (defined but never used)
```

**Missing from `M.ERROR` table** (must be added or referenced as raw
integer literals, like `-29`, `-35`, `-18` are scattered today):

```
RPC_INVALID_PARAMETER           = -8   MISSING — most "value out of range" errors
RPC_CLIENT_NOT_CONNECTED        = -9   MISSING
RPC_CLIENT_IN_INITIAL_DOWNLOAD  = -10  MISSING
RPC_WALLET_INVALID_LABEL_NAME   = -11  MISSING
RPC_WALLET_KEYPOOL_RAN_OUT      = -12  MISSING
RPC_WALLET_UNLOCK_NEEDED        = -13  MISSING (≥14 call sites should use this)
RPC_WALLET_PASSPHRASE_INCORRECT = -14  MISSING (walletpassphrase / walletpassphrasechange)
RPC_WALLET_WRONG_ENC_STATE      = -15  MISSING (encryptwallet / walletlock)
RPC_WALLET_ENCRYPTION_FAILED    = -16  MISSING
RPC_WALLET_ALREADY_UNLOCKED     = -17  MISSING
RPC_WALLET_NOT_FOUND            = -18  used as raw literal in 2 places, not in table
RPC_WALLET_NOT_SPECIFIED        = -19  MISSING
RPC_DATABASE_ERROR              = -20  MISSING
RPC_CLIENT_NODE_ALREADY_ADDED   = -23  MISSING (addnode, setban already-banned)
RPC_CLIENT_NODE_NOT_ADDED       = -24  MISSING (addnode remove)
RPC_CLIENT_NODE_NOT_CONNECTED   = -29  used as raw literal in 1 place
RPC_CLIENT_INVALID_IP_OR_SUBNET = -30  MISSING (setban)
RPC_CLIENT_P2P_DISABLED         = -31  MISSING
RPC_METHOD_DEPRECATED           = -32  MISSING
RPC_CLIENT_MEMPOOL_DISABLED     = -33  MISSING
RPC_CLIENT_NODE_CAPACITY_REACHED= -34  MISSING
RPC_WALLET_ALREADY_LOADED       = -35  used as raw literal in 1 place
RPC_WALLET_ALREADY_EXISTS       = -36  MISSING (createwallet duplicate name)
```

22 codes missing from the constants table; ~3 used as raw integer
literals scattered in the code; ~19 not used at all. Many call sites
that *should* raise these codes fall back to `M.ERROR.WALLET_ERROR`,
`M.ERROR.MISC_ERROR`, or `M.ERROR.INVALID_PARAMS`. This is the root
cause of most of the bugs below.

## 30 W125 Audit Gates

| Gate | Description | Status | Core ref |
|------|-------------|--------|----------|
| G1   | RPC_PARSE_ERROR (-32700) emitted on invalid JSON body | PRESENT | rpc.lua:1106 ✓ |
| G2   | RPC_INVALID_REQUEST (-32600) emitted on non-object request | PRESENT | rpc.lua:1136 ✓ |
| G3   | RPC_METHOD_NOT_FOUND (-32601) emitted on unknown method | PRESENT | rpc.lua:1048 ✓ |
| G4   | RPC_INVALID_PARAMS (-32602) emitted on structurally invalid params | PARTIAL | overused; conflates with -8 |
| G5   | RPC_INTERNAL_ERROR (-32603) emitted on uncaught Lua error | PRESENT | rpc.lua:1069 ✓ |
| G6   | RPC_INVALID_PARAMETER (-8) emitted on out-of-range / semantically invalid values | **MISSING (BUG-1 P1)** | Code -8 not in M.ERROR; ~120 sites use -32602 instead |
| G7   | RPC_TYPE_ERROR (-3) emitted on wrong-type parameter | PARTIAL | only 2 sites use it (verifymessage); most use -32602 |
| G8   | RPC_MISC_ERROR (-1) reserved for std::exception equivalents | PARTIAL | overused for "X not available" cases that should be -31/-33 |
| G9   | RPC_WALLET_ERROR (-4) reserved for unspecified wallet problems | PARTIAL | overused; should narrow per-failure |
| G10  | RPC_INVALID_ADDRESS_OR_KEY (-5) for invalid address/key/block-not-found | PRESENT | INVALID_ADDRESS alias used correctly in many places |
| G11  | RPC_DESERIALIZATION_ERROR (-22) for bad hex / decode failures | PARTIAL | submitblock + decodepsbt ✓; sendrawtransaction + decoderawtransaction MISS (BUG-2) |
| G12  | RPC_VERIFY_REJECTED (-26) for mempool rejection | PRESENT | rpc.lua:2046 ✓ |
| G13  | RPC_VERIFY_ALREADY_IN_UTXO_SET (-27) for txn-already-in-mempool | PRESENT | rpc.lua:2044 ✓ |
| G14  | RPC_VERIFY_ERROR (-25) for general tx/block verify | PRESENT | generatetoaddress uses it; rare otherwise |
| G15  | RPC_IN_WARMUP (-28) emitted while node still loading | **MISSING (BUG-3 P2)** | constant defined, no call site; Core checks before every RPC |
| G16  | RPC_CLIENT_NOT_CONNECTED (-9) for getblocktemplate without peers | **MISSING (BUG-4 P2)** | rpc.lua:3869 has no peer check |
| G17  | RPC_CLIENT_IN_INITIAL_DOWNLOAD (-10) for getblocktemplate / importmempool during IBD | **MISSING (BUG-5 P2)** | not implemented |
| G18  | RPC_CLIENT_P2P_DISABLED (-31) for net-RPCs when peer manager missing | **MISSING (BUG-6 P1)** | uses MISC_ERROR (-1) in addnode/setban/listbanned/clearbanned/disconnectnode |
| G19  | RPC_CLIENT_NODE_ALREADY_ADDED (-23) for addnode/setban duplicate | **MISSING (BUG-7 P2)** | addnode add never raises this; setban "already banned" uses MISC_ERROR |
| G20  | RPC_CLIENT_NODE_NOT_ADDED (-24) for addnode remove on missing node | **MISSING (BUG-8 P2)** | addnode remove returns nil even when not added |
| G21  | RPC_CLIENT_NODE_NOT_CONNECTED (-29) for disconnectnode | PRESENT | rpc.lua:3225 ✓ (raw literal) |
| G22  | RPC_CLIENT_INVALID_IP_OR_SUBNET (-30) for setban / disconnectnode invalid IP | **MISSING (BUG-9 P2)** | uses INVALID_PARAMS instead |
| G23  | RPC_CLIENT_MEMPOOL_DISABLED (-33) when mempool disabled | **MISSING (BUG-10 P2)** | uses MISC_ERROR (-1) for "Mempool not available" |
| G24  | RPC_WALLET_NOT_FOUND (-18) for missing wallet | PARTIAL | used as raw literal in loadwallet/unloadwallet only; get_request_wallet path returns WALLET_ERROR |
| G25  | RPC_WALLET_NOT_SPECIFIED (-19) when multiple wallets loaded | **MISSING (BUG-11 P2)** | get_request_wallet returns WALLET_ERROR |
| G26  | RPC_WALLET_INSUFFICIENT_FUNDS (-6) for insufficient-funds errors | **MISSING (BUG-12 P1)** | wallet:6727 / 6731 use WALLET_ERROR (-4); INSUFFICIENT_FUNDS constant defined but unused |
| G27  | RPC_WALLET_UNLOCK_NEEDED (-13) for wallet-locked-on-sign | **MISSING (BUG-13 P1)** | ≥14 call sites use WALLET_ERROR (-4) for "Wallet is locked" |
| G28  | RPC_WALLET_PASSPHRASE_INCORRECT (-14) on wrong passphrase | **MISSING (BUG-14 P2)** | walletpassphrase / walletpassphrasechange use WALLET_ERROR |
| G29  | RPC_WALLET_WRONG_ENC_STATE (-15) for encryptwallet on encrypted / walletlock on unencrypted | **MISSING (BUG-15 P2)** | uses WALLET_ERROR; Core encrypt.cpp:49/138/203/260 |
| G30  | RPC_WALLET_ALREADY_LOADED (-35) / ALREADY_EXISTS (-36) emitted correctly | PARTIAL | ALREADY_LOADED used in loadwallet; ALREADY_EXISTS for duplicate createwallet MISSING (BUG-16 P3); RPC_METHOD_DEPRECATED (-32) MISSING (BUG-17 P3) |

**Score:** 8 PRESENT / 6 PARTIAL / 16 MISSING.

## Bug list

### BUG-1 — INVALID_PARAMS vs INVALID_PARAMETER conflation (P1)

`M.ERROR.INVALID_PARAMS = -32602` is the JSON-RPC 2.0 *structural*
invalid-params code, raised only when the params array/object shape
itself violates JSON-RPC. Core uses `RPC_INVALID_PARAMETER = -8` for
"value out of range / wrong type / missing parameter" application
errors — these are the application-layer cases.

lunarblock has ~120 call sites that pass `M.ERROR.INVALID_PARAMS`
(-32602) where Core uses `RPC_INVALID_PARAMETER` (-8). Examples:

| Site (rpc.lua line) | lunarblock | Core (file:line) | Core code |
|---|---|---|---|
| 1371 `getblockhash` "Height must be a number" | -32602 | blockchain.cpp:591 | -8 |
| 1374 `getblockhash` "Block height out of range" | -32602 | blockchain.cpp:591 | -8 |
| 1382 `getblockhash` "Block height out of range" | -32602 | blockchain.cpp:591 | -8 |
| 1404 `getblock` "Invalid block hash" | -32602 | (no analogue — Core auto-validates) | -8 |
| 2076 `getrawtransaction` "Invalid txid" | -32602 | (Core auto-rejects via Uint256) | -8 |
| 2407 `decoderawtransaction` "Transaction hex required" | -32602 | rawtx.cpp:439 | -22 (also wrong — BUG-2) |
| 2766 `estimatesmartfee` "conf_target must be numeric" | -32602 | fees.cpp ParseConfirmTarget | -8 |
| 3114 `gettxout` "vout must be a non-negative integer" | -32602 | (Core auto-validates) | -8 |
| 5181 `createwallet` "wallet_name is required" | -32602 | (Core required-arg check) | -8 |
| 5224 `loadwallet` "filename is required" | -32602 | (Core required-arg check) | -8 |
| 5864 `walletpassphrase` "passphrase is required" | -32602 | (Core required-arg check) | -8 |
| 6095 `importprivkey` "privkey is required" | -32602 | (Core required-arg check) | -8 |
| 6961 `submitblock` "Block hex data required" | -32602 | mining.cpp:1080 | -22 (also wrong — BUG-2) |

This is the largest single category. Severity P1 — RPC clients that
switch on error code can't distinguish "your request shape is broken"
from "your parameter value is wrong", which conflates protocol-level
bugs with application-level bugs.

**Refs:** Core `src/rpc/protocol.h` comment: "RPC_INVALID_PARAMS is
internally mapped to HTTP_BAD_REQUEST (400). It should not be used for
application-layer errors."

### BUG-2 — sendrawtransaction / decoderawtransaction wrong code for TX decode failure (P1)

| Method | lunarblock | Core code | Core file:line |
|---|---|---|---|
| `sendrawtransaction` | INTERNAL_ERROR (-32603) via `assert()` lift | -22 | mempool.cpp:96 |
| `decoderawtransaction` | INVALID_PARAMS (-32602) | -22 | rawtransaction.cpp:439 |

In `sendrawtransaction` (rpc.lua:2031): `assert(type(hex) == "string",
"Transaction hex required")` — a Lua assert with a string message
becomes a non-table exception, which the dispatcher (rpc.lua:1069)
wraps in `INTERNAL_ERROR (-32603)`. Core throws
`RPC_DESERIALIZATION_ERROR (-22)` with the message "TX decode failed.
Make sure the tx has at least one input."

In `decoderawtransaction` (rpc.lua:2407): "Transaction hex required"
raised with `INVALID_PARAMS (-32602)` — Core raises -22.

### BUG-3 — RPC_IN_WARMUP (-28) defined but never raised (P2)

`M.ERROR.IN_WARMUP = -28` (rpc.lua:244) is in the constants table but
no call site uses it. Core's `RPCServer::ExecuteCommand` (server.cpp:488)
fires `RPC_IN_WARMUP` before any handler runs if `IsRPCRunning()` is
false or `rpcWarmupStatus` is set. lunarblock has no warmup gate; every
RPC method becomes available the moment `RPCServer:new` returns,
including during the long initial chain-state load. RPC clients that
check for `-28` to wait out warmup will never see it.

### BUG-4 — getblocktemplate doesn't check connection (P2)

`getblocktemplate` (rpc.lua:3869) doesn't check peer count. Core
(mining.cpp:768-770) throws `RPC_CLIENT_NOT_CONNECTED (-9)` if peer
count is 0 on non-test chains. lunarblock returns a template regardless
— a miner using lunarblock would be told to mine atop an isolated node
without warning.

### BUG-5 — getblocktemplate doesn't check IBD (P2)

`getblocktemplate` (rpc.lua:3869) doesn't check `initialblockdownload`.
Core (mining.cpp:772-774) throws `RPC_CLIENT_IN_INITIAL_DOWNLOAD (-10)`
if `miner.isInitialBlockDownload()`. lunarblock will hand out a template
based on a partially-synced chain — that template would mine an orphan
block.

### BUG-6 — net RPCs use MISC_ERROR instead of CLIENT_P2P_DISABLED (P1)

When `rpc.peer_manager` is nil, Core throws
`RPC_CLIENT_P2P_DISABLED (-31)` ("Error: Peer-to-peer functionality
missing or disabled" — server_util.cpp:103). lunarblock uses
`MISC_ERROR (-1)` "peer manager not available" at:

- rpc.lua:2576 `addnode`
- rpc.lua:2654 `setban`
- rpc.lua:2724 `listbanned`
- rpc.lua:2746 `clearbanned`
- rpc.lua:3190 `disconnectnode`

Severity P1 because every NetMon / Sparrow Wallet / etc tooling switches
on -31 to gracefully degrade when the node was started with `-listen=0`
or P2P stack failed.

### BUG-7 — addnode add never raises CLIENT_NODE_ALREADY_ADDED (P2)

Core `addnode add` throws `RPC_CLIENT_NODE_ALREADY_ADDED (-23)` ("Error:
Node already added") at net.cpp:362 when the address is already in
`vAddedNodes`. lunarblock (rpc.lua:2591-2610) silently overwrites
`manual_peers[key]` and re-connects, no error. Same issue in `setban`
add (rpc.lua:2677): "Error: IP/Subnet already banned" raised with
`MISC_ERROR (-1)` but Core uses `-23`.

### BUG-8 — addnode remove never raises CLIENT_NODE_NOT_ADDED (P2)

Core `addnode remove` throws `RPC_CLIENT_NODE_NOT_ADDED (-24)` ("Error:
Node could not be removed. It has not been added previously.") at
net.cpp:368. lunarblock (rpc.lua:2618-2624) silently no-ops if the
peer was never added.

### BUG-9 — setban "Invalid IP/Subnet" uses INVALID_PARAMS (P2)

Core `setban` throws `RPC_CLIENT_INVALID_IP_OR_SUBNET (-30)` ("Error:
Invalid IP/Subnet") at net.cpp:780/811/1003. lunarblock (rpc.lua:2662)
uses `INVALID_PARAMS (-32602)` "Error: subnet (string) is required".

### BUG-10 — RPC_CLIENT_MEMPOOL_DISABLED (-33) never raised (P2)

When `rpc.mempool` is nil, Core's `EnsureMemPool()` throws
`RPC_CLIENT_MEMPOOL_DISABLED (-33)` ("Mempool disabled or instance not
found" — server_util.cpp:37). lunarblock uses `MISC_ERROR (-1)`
"Mempool not available" at rpc.lua:1990/2007/2967/2034/3322 etc.

### BUG-11 — RPC_WALLET_NOT_SPECIFIED (-19) never raised (P2)

When multiple wallets are loaded and no `/wallet/<name>` URI was used,
Core throws `RPC_WALLET_NOT_SPECIFIED (-19)` ("Multiple wallets are
loaded. Please select which wallet to use by requesting the RPC through
the /wallet/<walletname> URI path." — wallet/rpc/util.cpp:84).
lunarblock's `get_request_wallet` (rpc.lua:994) just returns the
default wallet without warning — silently uses the wrong wallet in
multi-wallet setups, no -19 surfaced.

### BUG-12 — Insufficient funds uses WALLET_ERROR (-4) instead of -6 (P1)

`M.ERROR.INSUFFICIENT_FUNDS = -6` is defined but never used. Two call
sites in `walletcreatefundedpsbt` (rpc.lua:6727, 6731) use
`WALLET_ERROR (-4)` with message "Insufficient funds". Core throws
`RPC_WALLET_INSUFFICIENT_FUNDS (-6)` (spend.cpp:187/1507/1509/1524/
1529/1547). Severity P1 — every wallet client distinguishes "send
failed because of fees" from generic wallet errors.

### BUG-13 — Wallet-locked uses WALLET_ERROR (-4) instead of -13 (P1)

At least 14 call sites raise `WALLET_ERROR (-4)` for "Wallet is locked":

- rpc.lua:5373 `getnewaddress`
- rpc.lua:5483 `sendtoaddress`
- rpc.lua:5814 `sendpayjoinrequest`
- rpc.lua:5971 `dumpprivkey`
- rpc.lua:6001 `getwalletmnemonic`
- rpc.lua:6090 `importprivkey`
- rpc.lua:6506 `signrawtransactionwithwallet`
- rpc.lua:5883 `walletlock` "Wallet is not encrypted" (separate — BUG-15)
- rpc.lua:5899 `encryptwallet` "Wallet is already encrypted" (BUG-15)
- (plus walletcreatefundedpsbt, bumpfee, psbtbumpfee paths via wallet:sign_inputs)

Core's `EnsureWalletIsUnlocked` (wallet/rpc/util.cpp:88-92) throws
`RPC_WALLET_UNLOCK_NEEDED (-13)` ("Error: Please enter the wallet
passphrase with walletpassphrase first.") at 14+ call sites.
Severity P1 — every wallet client switches on -13 to prompt for
passphrase.

### BUG-14 — Wrong passphrase uses WALLET_ERROR (-4) instead of -14 (P2)

`walletpassphrase` (rpc.lua:5869) and `walletpassphrasechange`
(rpc.lua:5944) raise `WALLET_ERROR (-4)` on "Wrong passphrase". Core
throws `RPC_WALLET_PASSPHRASE_INCORRECT (-14)` (wallet/rpc/encrypt.cpp:
76/78/162/164).

### BUG-15 — Wrong encryption state uses WALLET_ERROR (-4) instead of -15 (P2)

| lunarblock site (rpc.lua) | Condition | Core code | Core file:line |
|---|---|---|---|
| 5883 `walletlock` "Wallet is not encrypted" | unencrypted wallet | -15 | encrypt.cpp:203 |
| 5899 `encryptwallet` "Wallet is already encrypted" | already encrypted | -15 | encrypt.cpp:260 |
| 5869 (impl-side gap) | walletpassphrase on unencrypted | -15 | encrypt.cpp:49 |
| 5944 (impl-side gap) | walletpassphrasechange on unencrypted | -15 | encrypt.cpp:138 |

All four raise `WALLET_ERROR (-4)`. Core uses
`RPC_WALLET_WRONG_ENC_STATE (-15)`.

### BUG-16 — createwallet duplicate doesn't raise RPC_WALLET_ALREADY_EXISTS (P3)

`createwallet` (rpc.lua:5174) routes any failure through
`WALLET_ERROR (-4)`. Core's `HandleWalletError`
(wallet/rpc/util.cpp:142-144) maps `DatabaseStatus::FAILED_ALREADY_EXISTS`
to `RPC_WALLET_ALREADY_EXISTS (-36)`. Low-severity because most
operator scripts retry-on-any-error, but worth fixing for parity.

### BUG-17 — RPC_METHOD_DEPRECATED (-32) never raised (P3)

Several Core RPCs (`addmultisigaddress` deprecated dummy first arg —
wallet/rpc/coins.cpp:200) throw `RPC_METHOD_DEPRECATED (-32)`.
lunarblock doesn't implement any deprecation gates. P3 because
lunarblock doesn't ship deprecated APIs yet — pre-emptive parity for
when it does.

## Severity summary

| Severity | Count | Bugs |
|---|---|---|
| P0-CDIV  | 0 | — |
| P0       | 0 | — |
| P1       | 4 | BUG-1, BUG-2, BUG-6, BUG-12, BUG-13 (5 actually — recount below) |
| P2       | 10 | BUG-3, BUG-4, BUG-5, BUG-7, BUG-8, BUG-9, BUG-10, BUG-11, BUG-14, BUG-15 |
| P3       | 2 | BUG-16, BUG-17 |

(Re-counting: BUG-1, BUG-2, BUG-6, BUG-12, BUG-13 = 5 P1 = total 17 bugs.)

## Cross-impl pattern notes (W125)

- **JSON-RPC structural vs application code conflation**: lunarblock's
  120 sites of `INVALID_PARAMS (-32602)` is the single largest divergence.
  Mirrors the "code -32602 vs -8" confusion seen in W47b and earlier in
  this project; the root cause is that the constants table only names
  `INVALID_PARAMS` and devs reach for it for any param-value error.
- **Constants-table-as-allowlist**: `M.ERROR` has 17 entries, ~22 codes
  are missing. Patterns of raw integer literals (`-29`, `-35`, `-18`)
  reveal the "I knew the code, didn't bother to add it to the table"
  shortcut. The fix is to backfill the table.
- **Wallet-locked is the highest-frequency miss**: 14+ sites raise -4
  where Core raises -13. Every wallet client (Sparrow, Bitcoin Core
  bitcoin-cli, electrum-personal-server) treats -13 specially as
  "prompt for passphrase". With -4 the user gets a generic error and
  no UX path forward. P1.
- **Networking-disabled cluster**: -9, -10, -23, -24, -30, -31, -33,
  -34 — all 0-call-site in lunarblock. None are P0 in isolation but
  add up to a category-wide blindspot for operators of headless nodes.

## Test plan

xfail tests in `tests/test_w125_error_parity.lua` covering every gate
above. Tests construct a minimal RPCServer with the relevant subsystems
mocked / left nil, then invoke each RPC and assert the *expected* (Core)
error code via the `pcall` table-error path. Pre-fix: the divergent
ones xfail. Post-fix: flip to plain test.

## References

- `bitcoin-core/src/rpc/protocol.h` — `RPCErrorCode` enum
- `bitcoin-core/src/rpc/server.cpp` — `ExecuteCommand` warmup gate
- `bitcoin-core/src/rpc/server_util.cpp` — `EnsureMemPool`, `EnsureConnman`
- `bitcoin-core/src/wallet/rpc/util.cpp` — `EnsureWalletIsUnlocked`,
  `HandleWalletError`, `GetWalletForJSONRPCRequest`
- `bitcoin-core/src/wallet/rpc/encrypt.cpp` — wallet encryption error
  codes (walletpassphrase / walletlock / encryptwallet)
- `bitcoin-core/src/wallet/rpc/spend.cpp` — `RPC_WALLET_INSUFFICIENT_FUNDS`
- `bitcoin-core/src/rpc/net.cpp` — `addnode`, `setban`, `disconnectnode`
- `bitcoin-core/src/rpc/blockchain.cpp` — `getblockhash` -8 boundary
- `bitcoin-core/src/rpc/rawtransaction.cpp` — TX decode -22 boundary
- `bitcoin-core/src/rpc/mining.cpp` — `getblocktemplate` -9/-10 gates
- `bitcoin-core/src/rpc/mempool.cpp` — `sendrawtransaction` -22
- BIP-323 (no direct hit — BIP not applicable; included in scope for
  exhaustiveness)
