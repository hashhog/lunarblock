# W123 — Mining / GBT parity audit (lunarblock)

**Date:** 2026-05-17
**Wave:** W123 (discovery)
**Impl:** lunarblock (Lua / LuaJIT)
**Status:** **N BUGS** (1 P0-RPC / 6 P1-RPC / 8 P2-RPC) — 30 gates audited

## Context

W123 is a fleet-wide audit of Mining / `getblocktemplate` (GBT) RPC
parity against Bitcoin Core. Scope is the block-assembly pipeline
(`node/miner.cpp`), the mining-RPC surface (`rpc/mining.cpp`), and
BIP-22 / BIP-23 / BIP-141 / BIP-152 wire compliance.

Mining is **operator-facing** (not consensus-critical for IBD), so
divergences classify as P0/P1/P2-RPC rather than CDIV. A wrong GBT
response misroutes hashrate but does not silently corrupt the
blockchain; mining-pool integration is the primary failure mode.

References:
- `bitcoin-core/src/node/miner.cpp`
- `bitcoin-core/src/rpc/mining.cpp`
- BIP-22 (https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki)
- BIP-23 (https://github.com/bitcoin/bips/blob/master/bip-0023.mediawiki)
- BIP-141 (segwit witness commitment)
- BIP-152 (compact blocks)

## Audit gate map (30)

| Gate | Topic | Status | Note |
|------|-------|--------|------|
| G1   | `getblocktemplate` RPC method registered | PRESENT | `src/rpc.lua:3869` |
| G2   | GBT `mode=template` default | PRESENT | implicit (no parsing) |
| G3   | GBT `mode=proposal` (BIP-23 §"Proposals") | **MISSING** | BUG-1 — proposal mode silently treated as template |
| G4   | GBT enforces `segwit` rule client-side | **MISSING** | BUG-2 — Core throws if `setClientRules` doesn't contain "segwit" |
| G5   | GBT `longpollid` field | **MISSING** | BUG-3 — required by BIP-22 §"Long Polling"; field absent |
| G6   | GBT IBD / connection-count guard | **MISSING** | BUG-4 — Core throws `RPC_CLIENT_IN_INITIAL_DOWNLOAD` / `RPC_CLIENT_NOT_CONNECTED` on non-test chains |
| G7   | GBT `bits` from `GetNextWorkRequired` (retarget) | **PARTIAL** | BUG-5 — `bits = prev_header.bits` directly (mining.lua:382); diverges on every retarget boundary block |
| G8   | GBT `mintime` honors BIP-94 timewarp | **PARTIAL** | BUG-6 — `mintime = mtp + 1`; misses `max(mtp+1, prev_time - MAX_TIMEWARP)` clause on retarget boundary |
| G9   | GBT `mtp` from chain state | **MISSING** | BUG-7 — `chain_state.mtp` is never populated; fallback `os.time() - 3600` is wrong |
| G10  | GBT `transactions[i].sigops` accurate | **PARTIAL** | BUG-8 — hardcoded `sigops = 0` (mining.lua:485); BIP-22 says clients MUST NOT assume zero |
| G11  | GBT BIP-22 `depends` 1-based indexing | PRESENT | mining.lua:455-477 |
| G12  | GBT `default_witness_commitment` | PRESENT | mining.lua:451 |
| G13  | GBT `coinbasevalue` (subsidy + fees) | PRESENT | mining.lua:434 |
| G14  | GBT `coinbasetxn` (BIP-23 optional) | PARTIAL | emitted unconditionally (mining.lua:435); Core only emits `coinbasevalue` |
| G15  | GBT `coinbaseaux.flags` empty obj | PARTIAL | BUG-9 — emits `{flags = ""}`; Core emits `aux = {}` (empty obj) |
| G16  | GBT `rules` includes "csv" always | PRESENT | mining.lua:408 |
| G17  | GBT `rules` includes "!segwit"/"taproot" post-activation | PRESENT | mining.lua:409-412 |
| G18  | GBT `signet_challenge` field on signet | **MISSING** | BUG-10 — no signet chain support anywhere in network params |
| G19  | GBT `vbavailable` per BIP-9 deployments | PARTIAL | always emits `{}`; mainnet OK (no live deployments) — wrong for hypothetical signet/taproot-style soft-fork in progress |
| G20  | GBT `setClientRules` strips active-rule bits if unsupported | **MISSING** | BUG-11 — `setClientRules` is never parsed; can't refuse client missing required rule |
| G21  | `getmininginfo` RPC method | PRESENT | `src/rpc.lua:7218` |
| G22  | `getmininginfo.next` (Core ≥ v26) | PARTIAL | BUG-12 — `next.bits = bits_hex` (current tip's bits); Core uses NextEmptyBlockIndex |
| G23  | `getmininginfo.networkhashps` populated | **MISSING** | BUG-13 — hardcoded to 0; Core calls `getnetworkhashps().HandleRequest()` |
| G24  | `prioritisetransaction` RPC | **MISSING** | BUG-14 — entire RPC missing; mempool has no fee_delta plumbing |
| G25  | `getprioritisedtransactions` RPC | **MISSING** | BUG-14 (companion) |
| G26  | `submitblock` RPC | PRESENT | `src/rpc.lua:6949` |
| G27  | `submitblock` BIP-22 result strings (`duplicate`, `inconclusive`, `rejected`) | PRESENT | mining.lua / rpc.lua bip22_result() (16 canonical codes) |
| G28  | `submitheader` RPC | **MISSING** | BUG-15 — entire RPC missing |
| G29  | `generatetoaddress` RPC | PRESENT | `src/rpc.lua:3888` |
| G30  | `generatetoaddress` honors `maxtries` (param[2]) | **MISSING** | BUG-16 — third arg ignored; Core: `DEFAULT_MAX_TRIES` (1_000_000) |
| G31* | `generatetodescriptor` RPC | **MISSING** | (out-of-scope bonus gate; hidden Core RPC) |
| G32* | `generateblock` RPC | PRESENT | `src/rpc.lua:3645`; regtest-only guard correct |

(`G31` listed for completeness — bonus gate beyond the W123 standard 30 set.)

Counts:
- PRESENT: 10
- PARTIAL: 6
- MISSING: 14
- Bugs filed: **16** (1 P0-RPC / 7 P1-RPC / 8 P2-RPC)

## Findings

### BUG-1 (P0-RPC) — GBT `mode=proposal` (BIP-23) silently treated as new-template request

**Location:** `src/rpc.lua:3869-3885` (entire `getblocktemplate` handler)

`capabilities = ["proposal"]` is advertised back to the client (Core
parity at mining.lua:404), but the handler never reads `params[1].mode`
or `params[1].data`. A mining pool sending a proposal request gets a
fresh template back instead of `null` / `duplicate` / a rejection
string — so the pool's proposal-side block-rejection workflow is
silently broken.

Core mining.cpp:730-752: when `mode == "proposal"`, decode hex,
LookupBlockIndex for duplicates, then `TestBlockValidity(check_pow=false,
check_merkle_root=true)` and map through `BIP22ValidationResult`.

**Impact:** No mining pool that uses BIP-23 proposals (Stratum V2, btcd
pool software, etc.) can validate templates against lunarblock.
Advertised capability is a lie.

### BUG-2 (P1-RPC) — GBT does not enforce client `setClientRules.contains("segwit")`

**Location:** `src/rpc.lua:3869` (handler body — never reads `params[1].rules`)

Core mining.cpp:854-857: throws `RPC_INVALID_PARAMETER` with text
"`getblocktemplate must be called with the segwit rule set (call with
{"rules": ["segwit"]})`" if the client request doesn't contain "segwit"
in its rules array.

lunarblock accepts any GBT call (or none-at-all) and returns a template,
including for pre-segwit clients that wouldn't know to honor the
witness-commitment output and would mine an invalid block.

**Impact:** Pre-segwit clients silently produce invalid blocks.
Compatibility-shim signaling absent.

### BUG-3 (P1-RPC) — `longpollid` field missing from GBT response

**Location:** `src/mining.lua:425-453` (template response object)

BIP-22 §"Long Polling": the server SHOULD emit `longpollid` so clients
can pass it back in a follow-up call and have the server block until
the template changes (tip or mempool change). Core mining.cpp:1002:
`result.pushKV("longpollid", tip.GetHex() + ToString(nTransactionsUpdatedLast));`

lunarblock has no longpoll infrastructure (`nTransactionsUpdatedLast`
counter is also absent) and never emits the field, so a longpoll client
will either receive an error or busy-loop on plain GBT calls.

**Impact:** Mining pools using longpoll re-request templates every few
seconds, wasting network + CPU. Not a correctness bug per-se since
omitting `longpollid` is allowed by BIP-22 §"Long Polling" ("MAY emit"),
but a missing feature.

### BUG-4 (P1-RPC) — GBT no IBD / connection guard

**Location:** `src/rpc.lua:3869-3885`

Core mining.cpp:766-775 (non-test chains only):
```cpp
if (connman.GetNodeCount(ConnectionDirection::Both) == 0)
    throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, CLIENT_NAME " is not connected!");
if (miner.isInitialBlockDownload())
    throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, ...);
```

lunarblock returns a fresh template even when IBD is incomplete or no
peers are connected. A pool node that GBTs during IBD will receive a
template anchored at the partial chainstate tip and could mine an
orphan (or worse, an off-chain block).

### BUG-5 (P1-RPC) — GBT `bits` uses prev_header.bits, not `GetNextWorkRequired`

**Location:** `src/mining.lua:382`

```lua
local bits = chain_state.storage.get_header(prev_hash).bits
-- In a real implementation, compute next required bits at retarget heights
```

The comment is the confession. Bitcoin's difficulty retargets every
2016 blocks; at the boundary, `GetNextWorkRequired` produces a NEW
`nBits` and the template MUST use it. lunarblock continues to advertise
the previous epoch's bits at block N=2016k+0, causing the mined block
to fail `bad-diffbits` on every other node.

Core miner.cpp:220: `pblock->nBits = GetNextWorkRequired(pindexPrev,
pblock, chainparams.GetConsensus());`

`consensus.get_next_work_required` exists at `src/consensus.lua:401`
but is not called from the mining path — dead-helper-at-call-site.

**Impact:** Every 2016-th block produced via GBT on mainnet is wrong
(retarget boundary). On testnet/regtest with min-difficulty,
`GetNextWorkRequired` flips on inter-block-time, so the divergence is
much more frequent.

### BUG-6 (P1-RPC) — GBT `mintime` does not implement BIP-94 timewarp clause

**Location:** `src/mining.lua:442` (and `consensus.lua:41 MAX_TIMEWARP`)

```lua
mintime = mtp + 1,
```

Core miner.cpp:36-47 `GetMinimumTime`:
```cpp
int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
if (height % difficulty_adjustment_interval == 0) {
    min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
}
```

On retarget-boundary heights (height % 2016 == 0), `min_time` must be
`max(MTP+1, prev_time - 600)`. lunarblock just uses MTP+1, so on a
retarget boundary where prev_time was very low relative to MTP, the
miner is told the wrong minimum.

`MAX_TIMEWARP` exists in `consensus.lua:41` but is unused by the
mining path — dead-helper.

### BUG-7 (P1-RPC) — `chain_state.mtp` is never populated; fallback `os.time() - 3600` is wrong

**Location:** `src/mining.lua:266-267`

```lua
-- chain_state.mtp should be provided; fallback to current time - 3600 (1 hour ago)
local mtp = chain_state.mtp or (os.time() - 3600)
```

`ChainState` (utxo.lua:1538-1545) initializes `tip_hash` /
`tip_height` but never `mtp`. Every call to `create_block_template`
falls through to `os.time() - 3600`, which is **completely unrelated**
to the actual MTP.

Downstream consequences:
- `is_final_tx` uses this fake MTP, so it incorrectly classifies
  time-locked txs (BIP-113 violation, mining-side: txs that should be
  excluded get included; txs that should be included get excluded).
- `mintime` in the GBT response is `fake_mtp + 1` — off by ~3600 seconds
  in the typical case (since real MTP is roughly `os.time() - half-hour`).

**Recommended fix:** compute MTP from storage in
`create_block_template` (the helper exists: `compute_mtp_from_storage`
in utxo.lua:3132).

### BUG-8 (P1-RPC) — GBT `transactions[i].sigops` hardcoded to 0

**Location:** `src/mining.lua:485`

```lua
sigops = 0,  -- simplified
```

BIP-22 §"Format of Response":
> "if key is not present, sigop cost is unknown and clients MUST NOT
>  assume it is zero"

The lunarblock template DOES emit `sigops`, but always as 0. A
miner-side client reading the template can over-pack a block with
sigops-heavy txs above MAX_BLOCK_SIGOPS_COST because the per-tx
`sigops` it accumulates always says 0.

Note: the in-template sigops accounting that drives selection
(mining.lua:296-302) is also flawed — it calls
`count_script_sigops(input.scriptSig)` and
`count_script_sigops(output.scriptPubKey)` with `accurate=true` and
multiplies by WITNESS_SCALE_FACTOR. This is not the Core
`GetTransactionSigOpCost`:
- output `scriptPubKey` sigops are part of the spender's *input*
  context (when their script is the P2SH redeem or witness program),
  not the spendee's
- `accurate=true` over-counts OP_CHECKMULTISIG when not actually in
  P2SH/witness context
- witness sigops (CHECKSIG inside a P2WSH) are not counted at all

This means the per-tx `weight` is right but the per-tx `sigops`
**both** in the template emission AND in the chunk-fit gate are wrong.

### BUG-9 (P2-RPC) — `coinbaseaux.flags` non-standard field

**Location:** `src/mining.lua:433`

```lua
coinbaseaux = {flags = ""},
```

Core mining.cpp:938: `UniValue aux(UniValue::VOBJ);` — empty object.
The `flags` sub-key is a deprecated long-ago Core relic and has not
been emitted since v0.10 or so. Tools that parse `coinbaseaux` strictly
will see an unexpected key.

### BUG-10 (P2-RPC) — No signet chain support → no `signet_challenge` field

**Location:** `src/consensus.lua` (network params) + `src/mining.lua:443`

There is no `signet` network in `consensus.lua` networks list, no
`signet_challenge` advertised in any param, and the template never
emits `signet_challenge`. Signet mining (small testnet for protocol
researchers) is impossible. Core mining.cpp:1024-1026.

**Impact:** lunarblock cannot mine or participate as a signet peer.

### BUG-11 (P2-RPC) — `setClientRules` never parsed; client-rule active-bit stripping absent

**Location:** `src/rpc.lua:3869` and `src/mining.lua:250-453`

Core mining.cpp:754-760, 968-991: parses `template_request.rules`,
strips active deployment bits the client didn't sign for, throws on
active deployments the client doesn't support.

lunarblock ignores `template_request.rules` entirely. Every client
gets the same template regardless of which forks it claims to support.

Coupled with BUG-2 (no segwit guard), pre-segwit clients can be
silently handed segwit-required templates.

### BUG-12 (P2-RPC) — `getmininginfo.next.bits` = current bits, not next-block bits

**Location:** `src/rpc.lua:7256`

```lua
next = {
  height = tip_height + 1,
  bits = bits_hex,        -- ← current tip's bits, not next-block's
  ...
}
```

Core mining.cpp:480-487 calls `NextEmptyBlockIndex` which runs
`GetNextWorkRequired` for the upcoming block. On retarget boundaries
the value differs; on min-difficulty testnet it can differ on any
block whose neighbor exceeded 2*target_spacing.

### BUG-13 (P2-RPC) — `getmininginfo.networkhashps` hardcoded to 0

**Location:** `src/rpc.lua:7251`

```lua
networkhashps = 0,
```

Core mining.cpp:472:
`obj.pushKV("networkhashps", getnetworkhashps().HandleRequest(request));`

lunarblock DOES implement `getnetworkhashps` separately (rpc.lua:8101),
so the fix is to invoke it locally and embed the result.

### BUG-14 (P1-RPC) — `prioritisetransaction` + `getprioritisedtransactions` RPCs both missing

**Location:** `src/rpc.lua` (no matches for `prioritisetransaction`,
`getprioritisedtransactions`, `fee_delta`, `priorit`, `modify_fee` in
mempool.lua either)

Core mining.cpp:502-583. Mining pools and wallet UIs rely on this RPC
to bump-prioritize stuck txs into the next block template. Without it
there is no way to influence block selection beyond raw fee.

The dependent infrastructure (mempool fee-delta map, modify-fee on
entry, ancestor-fee adjustment) is also absent. This is roughly the
same shape of gap that other impls in W120 (mempool RBF audit) had
in their fee_delta accounting.

### BUG-15 (P1-RPC) — `submitheader` RPC missing

**Location:** `src/rpc.lua` (no method registration)

Core mining.cpp:1108-1146 `submitheader`. Used by lightweight clients
(BIP-157 light clients, fork monitors, and Core itself when bridging)
to submit candidate headers for validation without a full block body.

lunarblock has headers-first sync internally (rest.lua + sync.lua)
but does not expose the submit hook.

### BUG-16 (P2-RPC) — `generatetoaddress` ignores `maxtries`

**Location:** `src/rpc.lua:3888-3990`

Core mining.cpp:264-302: `generatetoaddress nblocks address maxtries`
defaults `maxtries` to `DEFAULT_MAX_TRIES (1_000_000)`. The CPU miner
gives up after this many nonces without finding a hash and returns the
empty array of generated blocks.

lunarblock reads `params[1]` and `params[2]` but **does not read
`params[3]`**. The internal `mine_block` defaults `max_nonce` to
`0xFFFFFFFF` (4.29 G nonces) and errors out with `MISC_ERROR` if it
fails — a regtest test that exercises the maxtries return value
would diverge.

## Summary

- **P0-RPC: 1** (BUG-1 proposal mode advertised but absent)
- **P1-RPC: 7** (BUG-2 / 3 / 4 / 5 / 6 / 7 / 8 / 14 / 15) — covers
  segwit-rule gate, longpoll, IBD guard, GetNextWorkRequired,
  BIP-94 mintime, MTP, sigops accuracy, prioritisetransaction,
  submitheader.
- **P2-RPC: 8** (BUG-9 / 10 / 11 / 12 / 13 / 16 + signet challenge +
  generatetodescriptor)

**Top blocker:** BUG-1 (GBT proposal advertised but treated as
template). Any mining-pool integration testing BIP-23 proposals first
will dead-on-arrival on lunarblock.

**Cheapest cluster to close:** BUG-5 / BUG-6 / BUG-7 / BUG-12 are all
"call the existing helper" fixes:
- BUG-5: `bits = consensus.get_next_work_required(...)` (helper exists)
- BUG-6: prepend the BIP-94 timewarp clause to `mintime`
- BUG-7: `mtp = compute_mtp_from_storage(storage, prev_hash)` (helper
  exists in utxo.lua:3132)
- BUG-12: same as BUG-5 but applied to `getmininginfo.next`

**Strongest aspect of the existing code:**
- `create_block_template` correctly implements ClampOptions semantics,
  MAX_CONSECUTIVE_FAILURES early-exit, block_reserved_weight = 8000
  starting weight, MAX_SEQUENCE_NONFINAL coinbase sequence, and
  `nLockTime = height - 1` coinbase locktime. Recent W93/W79
  hardening passes left the assembly-side bookkeeping in solid shape.
- BIP-22 `depends` array indexing is correct (1-based, matches
  setTxIndex semantics).

## Tests

`tests/test_w123_mining_gbt.lua`: 30 gates, all xfail-pre-fix where
applicable. Run:

```
cd /home/work/hashhog/lunarblock
luajit tests/test_w123_mining_gbt.lua
```

The test asserts each gate's PRESENT / PARTIAL / MISSING state from
the matrix above. Source-level absence checks (e.g. "no
`submitheader` registration in rpc.lua") protect against drive-by
stub-additions before a real implementation lands.

## References

- `bitcoin-core/src/node/miner.cpp` (lines 36-65 GetMinimumTime,
  79-120 ClampOptions/resetBlock, 122-237 CreateNewBlock,
  239-260 TestChunkBlockLimits, 262-334 addChunks)
- `bitcoin-core/src/rpc/mining.cpp` (lines 111-135 getnetworkhashps,
  219-302 generate*, 305-414 generateblock, 416-498 getmininginfo,
  502-583 prioritisetransaction, 615-1036 getblocktemplate,
  1056-1106 submitblock, 1108-1146 submitheader)
- `bitcoin-core/src/policy/policy.h` (constants
  DEFAULT_BLOCK_RESERVED_WEIGHT, MINIMUM_BLOCK_RESERVED_WEIGHT)
- BIP-22 (full GBT spec) / BIP-23 (proposals, longpoll) /
  BIP-141 (segwit witness commitment) / BIP-94 (timewarp)
