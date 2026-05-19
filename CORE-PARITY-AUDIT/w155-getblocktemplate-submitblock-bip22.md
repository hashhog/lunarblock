# W155 — getblocktemplate + submitblock + BIP-22/BIP-23 (lunarblock)

**Wave:** W155 — `getblocktemplate`, `submitblock`, `submitheader`,
`prioritisetransaction`, `getprioritisedtransactions`, `getmininginfo`,
`getnetworkhashps`; BIP-22 request: `mode` (`template`/`proposal`),
`capabilities`, `rules`, `longpollid`; BIP-22/23 response: `version`,
`rules`, `vbavailable`, `vbrequired`, `capabilities`, `previousblockhash`,
`transactions[]` (per-tx `data`/`txid`/`hash`/`depends`/`fee`/`sigops`/
`weight`), `coinbaseaux`, `coinbasevalue`, `coinbasetxn`, `longpollid`,
`target`, `mintime`, `mutable[]`, `noncerange`, `sigoplimit`,
`sizelimit`, `weightlimit`, `curtime`, `bits`, `height`,
`signet_challenge`, `default_witness_commitment`; BIP22ValidationResult
string set; BIP-9 `vbavailable`; BIP-94 timewarp `mintime`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/rpc/mining.cpp:587-603` — `BIP22ValidationResult`:
  state-valid → VNULL; state-error → throw `RPC_VERIFY_ERROR`;
  state-invalid → reject-reason string (or "rejected" if empty); fallback
  "valid?".
- `bitcoin-core/src/rpc/mining.cpp:615-1036` — `getblocktemplate`:
  parses `mode`/`capabilities`/`rules`/`longpollid`/`data`; proposal
  mode dispatches `TestBlockValidity(check_pow=false, check_merkle_root=true)`
  and short-circuits with `duplicate` / `duplicate-invalid` /
  `duplicate-inconclusive`; rejects non-test-chain when no peers connected
  (`RPC_CLIENT_NOT_CONNECTED`) or IBD (`RPC_CLIENT_IN_INITIAL_DOWNLOAD`);
  enforces `setClientRules.contains("segwit")` and (signet)
  `setClientRules.contains("signet")` else throws; emits
  `longpollid = tip.GetHex() + nTransactionsUpdatedLast`; emits
  `mintime = GetMinimumTime(pindexPrev, DifficultyAdjustmentInterval())`;
  divides `sigoplimit`/`sizelimit` by WITNESS_SCALE_FACTOR pre-segwit;
  omits `weightlimit` pre-segwit; emits `default_witness_commitment` from
  `coinbase.required_outputs[0].scriptPubKey`; emits `signet_challenge`
  only on signet chains; emits `coinbasevalue` ONLY (never `coinbasetxn`
  — that mode was removed years ago); per-tx `sigops` field is the
  PRECOMPUTED `tx_sigops.at(index_in_template)` (with pre-segwit
  divide-by-4); `vbavailable` is `OBJ_DYN` (JSON object), populated from
  `chainman.m_versionbitscache.GBTStatus`.
- `bitcoin-core/src/rpc/mining.cpp:1056-1106` — `submitblock`: accepts
  two args (`hexdata`, `dummy` — dummy ignored for BIP-22 compat);
  decodes hex → `CBlock`; `chainman.UpdateUncommittedBlockStructures`
  (so a coinbase that lacks the witness commitment but has a parent
  template that needs one gets one); installs a temporary
  `submitblock_StateCatcher` validation interface for THIS block hash;
  calls `ProcessNewBlock(force_processing=true, min_pow_checked=true)`;
  if accepted but `!new_block` → `duplicate`; if the catcher never fired
  → `inconclusive`; otherwise → `BIP22ValidationResult(state)`.
- `bitcoin-core/src/rpc/mining.cpp:1108-1146` — `submitheader`: accepts a
  bare 80-byte header in hex; refuses if the parent header isn't
  already known (forces sender to walk the chain).
- `bitcoin-core/src/rpc/mining.cpp:502-583` — `prioritisetransaction` and
  `getprioritisedtransactions`: three-arg `<txid> <dummy=0> <fee_delta>`;
  rejects `dummy != 0` (priority field deprecated post-0.15); satoshi
  amounts (mining RPCs use satoshis not BTC per BIP-22 note);
  `getprioritisedtransactions` is `OBJ_DYN` keyed by txid with
  `{fee_delta, in_mempool, modified_fee?}` sub-objects.
- `bitcoin-core/src/rpc/mining.cpp:1148-1167` — `RegisterMiningRPCCommands`:
  the eight visible commands are `getnetworkhashps`, `getmininginfo`,
  `prioritisetransaction`, `getprioritisedtransactions`,
  `getblocktemplate`, `submitblock`, `submitheader`, plus
  `hidden`: `generatetoaddress`, `generatetodescriptor`, `generateblock`,
  `generate`.
- `bitcoin-core/src/consensus/consensus.h:13` —
  `MAX_BLOCK_SERIALIZED_SIZE = 4000000` and `MAX_BLOCK_WEIGHT = 4000000`.
- `bitcoin-core/src/policy/policy.h:24-50` —
  `MAX_BLOCK_SIGOPS_COST = 80_000` and pre-segwit divide-by-4 (sigops
  becomes 20000; sizelimit becomes 1000000).
- `bitcoin-core/src/node/miner.cpp:36-65` — `GetMinimumTime` and
  `UpdateTime`: mintime = `pindexPrev->GetMedianTimePast() + 1`
  (BIP-94 retarget-boundary defence adds
  `max(prev_block_time - MAX_TIMEWARP, mtp+1)` on retarget heights);
  curtime = `max(GetMinimumTime, NodeClock::now())` so curtime can be
  bumped above wall-clock if MTP+1 is in the future.
- `bitcoin-core/src/node/miner.cpp:122-237` — `CreateNewBlock`:
  coinbase scriptSig is `CScript() << nHeight (<< OP_0)`,
  nLockTime = `nHeight - 1`, nSequence = `MAX_SEQUENCE_NONFINAL`,
  coinbase witness nonce size==32, `GenerateCoinbaseCommitment`,
  `UpdateTime`, `nBits = GetNextWorkRequired(pindexPrev, pblock, ...)`,
  `nNonce = 0`, final `TestBlockValidity(check_pow=false, check_merkle_root=false)`.
- `bitcoin-core/src/node/types.h:39-79` — `BlockCreateOptions`:
  default `coinbase_output_script{CScript() << OP_TRUE}`
  (**anyone-can-spend, NOT a burn address**). Pools/miners are expected
  to override this with their payout script. Core never burns funds in
  the default GBT path.

**Files audited**
- `lunarblock/src/mining.lua` — `create_block_template` (lines 250-494),
  `create_coinbase_tx` (lines 135-202), `mine_block` (lines 505-528),
  `clamp_options` (lines 215-237), `is_final_tx` (lines 43-72).
- `lunarblock/src/rpc.lua` —
  - `bip22_result` (lines 56-214) — single-source string mapper,
  - `M.classify_block_rejection` export (line 220),
  - `getblocktemplate` handler (lines 3869-3885),
  - `generatetoaddress` handler (lines 3888-3990),
  - `generateblock` handler (lines 3645-3866),
  - `submitblock` handler (lines 6949-7191),
  - `submitblocks` / `submitblockbatch` (lines 7196-7215),
  - `getmininginfo` (lines 7218-7262),
  - `getnetworkhashps` (lines 8101-8158).
- `lunarblock/src/consensus.lua` — `MAX_BLOCK_WEIGHT`,
  `MAX_BLOCK_SIGOPS_COST`, `MAX_BLOCK_SERIALIZED_SIZE` (lines 10-14),
  `get_next_work_required` (lines 401-480), `compute_block_version`
  (lines 744-774), `get_block_subsidy` (line 50+).
- `lunarblock/src/utxo.lua` — `ChainState:new_chain_state` (lines
  1535-1608) showing `tip_hash`/`tip_height`/`coin_view`/`sig_cache`/etc.
  but NO `mtp` field anywhere on the chain_state.

---

## Gate matrix (28 sub-gates / 14 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `mode` dispatch | G1: parse `mode` key, support `template`/`proposal` | **BUG-1 (P0-CDIV)** — handler never reads `params[1].mode`; `proposal` mode is unimplemented, server treats every call as `template` |
| 1 | … | G2: proposal short-circuit duplicate / duplicate-invalid / duplicate-inconclusive | **BUG-1 cross-cite** — no duplicate detection for proposed blocks |
| 1 | … | G3: proposal mode runs `TestBlockValidity(check_pow=false, check_merkle_root=true)` | **BUG-1 cross-cite** |
| 2 | `rules`/`capabilities` parsing | G4: parse client `rules` array; refuse if `segwit` not present | **BUG-2 (P0-CDIV)** — `setClientRules` not parsed; pre-segwit-aware miners would silently receive a post-segwit template with witness commitments |
| 2 | … | G5: refuse if `signet` not present on signet chains | **BUG-2 cross-cite** |
| 3 | `longpollid` | G6: parse `longpollid` and block until tip-change or mempool-change | **BUG-3 (P1)** — `longpollid` not parsed; not emitted in response either (next gate) |
| 3 | … | G7: emit `longpollid` in the template response | **BUG-3 cross-cite** — field absent from template, BIP-22 explicitly requires it |
| 4 | `bits` field | G8: compute via `GetNextWorkRequired(prev, pblock, params)` for the NEXT block | **BUG-4 (P0-CDIV) [carry-forward W154 BUG-1]** — `mining.lua:382` reads parent's `bits` instead of calling `consensus.get_next_work_required(height, ts, network, get_ancestor)` |
| 5 | `mintime` | G9: emit MTP+1 (with BIP-94 retarget bump) | **BUG-5 (P0-CDIV) [carry-forward W154 BUG-2/3]** — `chain_state.mtp` is NEVER populated (`utxo.lua:1535-1608` does not assign it); mining.lua:267 falls back to `os.time() - 3600`; BIP-113 mining-side broken on every call |
| 6 | `curtime` | G10: emit `max(GetMinimumTime, wall-clock)` | PARTIAL — emits `os.time()`, never bumps if MTP+1 is in the future (rare; mainly affects regtest with manipulated clocks) |
| 7 | Pre-segwit `sigoplimit`/`sizelimit`/`weightlimit` | G11: divide `sigoplimit` by `WITNESS_SCALE_FACTOR=4` pre-segwit | **BUG-6 (P1)** — always emits `MAX_BLOCK_SIGOPS_COST=80000`, even pre-segwit (Core: 20000) |
| 7 | … | G12: divide `sizelimit` by 4 pre-segwit | **BUG-6 cross-cite** — always 4000000 (Core pre-segwit: 1000000) |
| 7 | … | G13: omit `weightlimit` pre-segwit | **BUG-6 cross-cite** — always emits `weightlimit=4000000`; BIP-145 only defines this field post-segwit |
| 8 | `signet_challenge` | G14: emit on signet chains | **BUG-7 (P1)** — never emitted (no signet awareness in mining.lua) |
| 9 | Default coinbase payout | G15: anyone-can-spend `OP_TRUE` (Core default) | **BUG-8 (P0-FUNDS-BURN) [W154 BUG-NEW echo]** — default payout = `make_p2pkh_script(string.rep("\0", 20))` = burn address `1111111111111111111114oLvT2` |
| 10 | Per-tx `sigops` | G16: emit precomputed sigop count | **BUG-9 (P1) [carry-forward W154 BUG-6 surface]** — hardcoded `sigops = 0` for every tx; pool clients allocate the block sigop budget on false information |
| 11 | `coinbasevalue` vs `coinbasetxn` | G17: emit `coinbasevalue` always; `coinbasetxn` only with explicit client capability | **BUG-10 (P1)** — always emits both; `coinbasetxn` was a BIP-22 server-side mode that Core deleted years ago; non-standard miners may double-construct |
| 12 | IBD / no-peers refusal | G18: refuse when no P2P peers on non-test chain | **BUG-11 (P1)** — no peer-count check |
| 12 | … | G19: refuse when in IBD on non-test chain | **BUG-11 cross-cite** — getblockchaininfo computes IBD but getblocktemplate never consults it |
| 13 | BIP22ValidationResult shape | G20: state-error → JSON-RPC error throw with code RPC_VERIFY_ERROR | PARTIAL — accept_block throws `RPC_VERIFY_ERROR` for some paths and returns string for others; control flow is via `bip22_result` mapper, not strict state inspection |
| 13 | … | G21: state-invalid empty reject-reason → "rejected" | PASS (`bip22_result` line 213 default) |
| 13 | … | G22: state-valid → null | PASS (`return cjson.null` at line 7190) |
| 13 | … | G23: 9-token canonical key map (`duplicate`, `inconclusive`, `bad-cb-amount`, etc.) | PASS — line 64-77 enumerates 17 canonical tokens including the W125 9-token sweep set |
| 13 | … | G24: free-form English vs Core tokens for header-time/diff-bits/coinbase length | **BUG-12 (P1) [reject-string wire-parity slippage, 25+ tokens fleet pattern]** — `bip22_result` synthesises a `bad-cb-length` token from English "coinbase scriptsig too long/short/out of range" and a `bad-diffbits` token from "bad-diffbits" pattern, but the legacy fallback "rejected" path leaves any unmatched English assertion as-is |
| 14 | RPC surface completeness | G25: `prioritisetransaction` method exists | **BUG-13 (P0-CDIV)** — RPC method not defined; mining pools that prioritise CPFP/replacement candidates have no API |
| 14 | … | G26: `getprioritisedtransactions` method exists | **BUG-13 cross-cite** |
| 14 | … | G27: `submitheader` method exists | **BUG-14 (P1)** — RPC method not defined; header-only relay clients have no submit path |
| 14 | … | G28: `submitblock` accepts optional 2nd `dummy` arg per BIP-22 spec | **BUG-15 (P2)** — handler reads only `params[1]`; second arg silently ignored (this happens to be correct, but only by accident) |

---

## BUG-1 (P0-CDIV) — `getblocktemplate` does not implement `mode` dispatch; proposal mode is missing

**Severity:** P0-CDIV. BIP-23 introduces the `mode` request key with two
values: `"template"` (default; build a block template) and `"proposal"`
(validate a candidate block hex against current chain tip and return
`null`/`duplicate`/`duplicate-invalid`/`duplicate-inconclusive`/
`<reject-reason>` per the BIP22ValidationResult set). Bitcoin Core's
handler parses `mode` (`rpc/mining.cpp:719-727`) and dispatches:

```cpp
if (strMode == "proposal") {
    const UniValue& dataval = oparam.find_value("data");
    CBlock block; if (!DecodeHexBlk(...)) throw RPC_DESERIALIZATION_ERROR;
    uint256 hash = block.GetHash();
    const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);
    if (pindex) { /* duplicate variants */ }
    return BIP22ValidationResult(TestBlockValidity(..., check_pow=false, check_merkle_root=true));
}
if (strMode != "template")
    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
```

lunarblock's handler at `rpc.lua:3869-3885` is a one-pass dispatcher
that reads only `params[1].coinbase_payout` and builds a template
unconditionally. A `mode=proposal` request gets a template back instead
of a validation result. Pool software that uses GBT proposal mode to
pre-flight candidates (BTCC, P2Pool, getwork-style overlays) will
either consume CPU regenerating the work or, worse, mis-interpret the
template object as a validation success.

**File:** `lunarblock/src/rpc.lua:3869-3885`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:719-752`.

**Excerpt (lunarblock, mode never read)**
```lua
self.methods["getblocktemplate"] = function(rpc, params)
  if rpc.mining then
    local script_mod = require("lunarblock.script")
    local payout_script
    if params[1] and params[1].coinbase_payout then       -- non-standard knob
      payout_script = params[1].coinbase_payout
    else
      payout_script = script_mod.make_p2pkh_script(string.rep("\0", 20))
    end
    local template = rpc.mining.create_block_template(
      rpc.mempool, rpc.chain_state, rpc.network,
      payout_script
    )
    return template
  end
  error({code = M.ERROR.MISC_ERROR, message = "Mining not available"})
end
```

`mode`, `capabilities`, `rules`, `longpollid`, `data` are all silently
discarded.

**Impact:** BIP-23 proposal mode is non-functional; pool integrations
that rely on it fall back to the slow rebuild path or fail outright.

---

## BUG-2 (P0-CDIV) — `rules` array not parsed; segwit/signet client-capability negotiation skipped

**Severity:** P0-CDIV. Core hard-enforces two preconditions:

```cpp
if (consensusParams.signet_blocks && !setClientRules.contains("signet"))
    throw RPC_INVALID_PARAMETER("getblocktemplate must be called with the signet rule set");
if (!setClientRules.contains("segwit"))
    throw RPC_INVALID_PARAMETER("getblocktemplate must be called with the segwit rule set");
```

These gates exist so that a pre-segwit miner cannot accidentally receive
a post-segwit template (witness commitment in the coinbase, OP_RETURN
0xaa21a9ed vout, etc.) it cannot construct correctly. lunarblock's
handler never builds `setClientRules`; the template is identical
whether the client passed `rules=["segwit"]` or `rules=[]` or omitted
the field entirely. A legacy ASIC controller that thinks it's mining
pre-segwit will receive a witness-commitment vout it can't reconstruct
when assembling extra-nonce, producing an invalid block on submission.

**File:** `lunarblock/src/rpc.lua:3869-3885` (no `setClientRules`
construction); `lunarblock/src/mining.lua:402-412` (server-side `rules`
list is emitted unconditionally regardless of client capabilities).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:850-857`.

**Impact:** silent template/client capability mismatch; broken legacy
miner integration; no signet-mode gate (cross-cite BUG-7).

---

## BUG-3 (P1) — `longpollid` is neither emitted nor consumed

**Severity:** P1 ("BIP22 long-poll fleet pattern", expected baseline for
any GBT-using miner). BIP-22 section "Long Polling" requires the server
to emit `longpollid` (typically `<tip_hex><nTransactionsUpdated>`) in
every template response and to honor `longpollid` in the request by
blocking the response until either the best chain tip changes or the
mempool has changed enough to invalidate the prior template. lunarblock
emits neither and ignores the request-side field entirely.

`mining.lua:425-453` builds the template dict; there is no `longpollid`
key. `rpc.lua:3869-3885` does not consume the request field. A miner
pool that polls every 30 seconds (the legacy fallback when longpoll
isn't available) wastes server CPU rebuilding identical templates;
worse, the miner cannot subscribe to chain-tip changes — the new tip
gets a new template only on the next 30s poll, so up to 30 seconds of
hashpower is wasted on stale work after every new block.

**File:** `lunarblock/src/mining.lua:425-453` (template dict, no
longpollid); `lunarblock/src/rpc.lua:3869-3885` (no longpollid in
request).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:728, 783-845, 1002`.

**Impact:** mining efficiency loss (one tip-flip-worth of stale work per
block); no BIP-22-compliant long-poll API; pool software that
hard-requires longpollid (e.g. eloipool, p2pool) will refuse to
connect.

---

## BUG-4 (P0-CDIV) [carry-forward W154 BUG-1] — `bits` field copies parent's, ignoring `GetNextWorkRequired`

**Severity:** P0-CDIV. W154 BUG-1 already flagged that
`mining.lua:382` reads the parent's compact bits instead of computing
`GetNextWorkRequired` for the next block:

```lua
-- Get difficulty target
local bits = chain_state.storage.get_header(prev_hash).bits
-- In a real implementation, compute next required bits at retarget heights
```

The companion helper `consensus.get_next_work_required(height,
timestamp, network, get_ancestor)` exists at `consensus.lua:401-480`,
fully wired with BIP-94 timewarp support and testnet min-difficulty
rules. The template just doesn't call it. On regtest with
`pow_no_retarget=true` this is silently correct (the helper would have
returned `prev.header.bits` anyway). On mainnet/testnet at a retarget
boundary (`height % 2016 == 0`), the template emits the OLD target,
miners hash against the old target, the resulting block fails
ContextualCheckBlockHeader (`bad-diffbits`) on submission, and the
pool loses the hashpower window.

Since W155 = revisiting GBT, this is recorded as a BUG-4 entry to keep
the W155 audit comprehensive. **Active carry-forward** from W154 — fix
should be a single-line dispatch in `create_block_template`:

```lua
local bits = consensus.get_next_work_required(height, os.time(), network,
  function(h) ... ancestor lookup via storage.get_hash_by_height ... end)
```

**File:** `lunarblock/src/mining.lua:382`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:140-141` (`pblock->nBits
= GetNextWorkRequired(pindexPrev, pblock, ...)`).

**Impact:** retarget-boundary blocks (every 2016 blocks on
mainnet/testnet) get the wrong target; pool block production at the
boundary fails with `bad-diffbits`.

---

## BUG-5 (P0-CDIV) [carry-forward W154 BUG-2+3] — `mintime` is `os.time() - 3600` because `chain_state.mtp` is never populated

**Severity:** P0-CDIV. `mining.lua:266-267` reads
`chain_state.mtp or (os.time() - 3600)`. A grep over `lunarblock/src/`
shows `chain_state.mtp` is **never assigned anywhere**:

```
$ grep -rn 'chain_state\.mtp\|self\.mtp' lunarblock/src/
lunarblock/src/mining.lua:266:  -- chain_state.mtp should be provided; fallback to current time - 3600
lunarblock/src/mining.lua:267:  local mtp = chain_state.mtp or (os.time() - 3600)
```

`utxo.lua:1535-1608` is the canonical `ChainState:new_chain_state`
constructor; it sets `tip_hash`, `tip_height`, `coin_view`, `sig_cache`,
`callbacks`, but never `mtp`. The fallback `os.time() - 3600` is
universally taken. Consequences:

1. **`mintime` emitted to miners is `wall-clock - 3600 + 1`**, NOT
   `MTP+1`. Two regimes:
   - Active mainnet chain: wall-clock ≈ tip-time, so MTP ≈ wall-clock
     - ~30 minutes; `wall-clock - 3600 + 1 < MTP + 1` and the emitted
     mintime is lower than the actual MTP+1 floor. Miners think they
     can use a lower nTime than they actually can; submission fails
     with `time-too-old` if the miner picks a nTime in
     `(wall - 3600, MTP + 1)`.
   - Idle/stalled chain (e.g. regtest with no recent blocks):
     `wall - 3600` could exceed `MTP + 1` so emitted mintime is too
     HIGH, blocking the miner from low-time blocks (especially
     anti-fee-sniping templates).

2. **BIP-94 retarget-boundary defence not applied.** Core's
   `GetMinimumTime` bumps `mintime = max(mintime, prev_block_time -
   MAX_TIMEWARP=600)` when `height % 2016 == 0`. lunarblock's path
   doesn't even compute MTP, so there is no BIP-94 timewarp arm at all.

3. **Companion to `is_final_tx` MTP misuse.** The same `mtp` is fed
   into the `is_final_tx` selection loop (mining.lua:293) — non-final
   transactions are filtered against `wall - 3600` instead of MTP, so
   the mempool selection itself is wrong. This is what W154 BUG-2+3
   already flagged at the consensus surface; W155 records the
   BIP-22-side observable (mintime field is wrong).

**File:** `lunarblock/src/mining.lua:266-267, 442` (mintime emit);
`lunarblock/src/utxo.lua:1535-1608` (chain_state constructor never
sets `mtp`).

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47` (`GetMinimumTime`).

**Impact:** mining-side BIP-113 broken; BIP-94 timewarp defence absent;
template emits a wrong mintime that can stall pools at the floor or
permit too-low timestamps that get rejected on submission.

---

## BUG-6 (P1) — `sigoplimit`/`sizelimit`/`weightlimit` are not pre-segwit-aware

**Severity:** P1. Core (`rpc/mining.cpp:1007-1019`) divides
`sigoplimit` and `sizelimit` by `WITNESS_SCALE_FACTOR=4` when the next
block is pre-segwit (so a pre-segwit miner sees 20000 sigops / 1000000
size, which are the pre-segwit consensus caps), AND it **omits**
`weightlimit` entirely pre-segwit (weight is a BIP-141 / BIP-145
post-segwit concept). lunarblock emits the post-segwit values
unconditionally:

```lua
sigoplimit = consensus.MAX_BLOCK_SIGOPS_COST,            -- 80000
sizelimit = consensus.MAX_BLOCK_SERIALIZED_SIZE,         -- 4000000
weightlimit = consensus.MAX_BLOCK_WEIGHT,                -- 4000000
```

(`mining.lua:445-447`).

On regtest at height 1 (segwit_height=1 on regtest, so this is harmless
on regtest in practice), but the `mainnet`/`testnet3` segwit_height is
481824 / 834624 — any code path that asks for a template at height
< segwit_height (reindex with mining hooks, replay tools, archive
GBT-replay frameworks) gets the wrong caps. A pre-segwit miner that
trusts `sigoplimit=80000` and packs that many sigops into the block
would have it rejected on submission with `bad-blk-sigops`.

**File:** `lunarblock/src/mining.lua:445-447`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1007-1019`.

**Impact:** pre-segwit-window GBT clients get wrong limits; affects
replay/archive scenarios; on regtest where segwit activates at h=1,
benign in practice.

---

## BUG-7 (P1) — `signet_challenge` field never emitted on signet chains

**Severity:** P1. Core emits the per-network signet challenge (the
script every signet block coinbase must satisfy) in the template:

```cpp
if (consensusParams.signet_blocks) {
    result.pushKV("signet_challenge", HexStr(consensusParams.signet_challenge));
}
```

(`rpc/mining.cpp:1024-1026`). The challenge is the script the
signet-block-signer must produce a valid signature over for that
block's witness data. Without it, a signet miner has to look up the
challenge out-of-band (`getblockchaininfo.signet_challenge`) which is
extra round-trip.

lunarblock's template (`mining.lua:425-453`) has no `signet_challenge`
key. A grep for `signet_challenge` in `lunarblock/src/` returns zero
hits. Mining on signet requires the signing logic to be applied to
every candidate; without the field in the template, signet pool
plumbing has to fetch the challenge separately.

**File:** `lunarblock/src/mining.lua:425-453`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1024-1026`.

**Impact:** signet miners must perform extra RPC calls per template;
some signet pool stacks (typically ones that wrap multiple signet
networks) may refuse to mine if the field is absent.

---

## BUG-8 (P0-FUNDS-BURN) [W154 BUG-NEW echo] — default coinbase payout is a P2PKH burn address

**Severity:** P0-FUNDS-BURN. `rpc.lua:3876` reads:

```lua
if params[1] and params[1].coinbase_payout then
  payout_script = params[1].coinbase_payout
else
  payout_script = script_mod.make_p2pkh_script(string.rep("\0", 20))
end
```

`make_p2pkh_script(string.rep("\0", 20))` produces a P2PKH locked to
the 20-byte hash `0x000...000`. The corresponding Bitcoin address is
`1111111111111111111114oLvT2`, an unspendable burn address (no
preimage of the all-zero RIPEMD160 hash is known, and no private key
maps to it). Any pool that:

1. Issues `getblocktemplate` without the non-standard `coinbase_payout`
   knob,
2. Builds the coinbase from the template's `coinbasetxn.data` (BUG-10),
   OR takes `coinbasevalue` and constructs their own coinbase
   delegating the payout script to the template default,

will silently produce a block whose coinbase pays the subsidy + fees
(currently ~3.125 BTC + tens-of-thousands of sats in fees) to the burn
address. If mined, that subsidy + fees is permanently locked.

Bitcoin Core's equivalent default (`bitcoin-core/src/node/types.h:39-79`)
is `coinbase_output_script{CScript() << OP_TRUE}` — anyone-can-spend.
Funds aren't burned; whoever finds the block first claims them in a
follow-up transaction. lunarblock's choice of "all-zero P2PKH" is
strictly more dangerous than Core's "anyone-can-spend OP_TRUE" because
the OP_TRUE script is spendable.

This is the W155 echo of W154 BUG-NEW (which flagged the same default
in the lower-level `create_block_template`). The W155 surface is the
RPC handler, where the default is finalised before `mining.lua` ever
sees it.

A secondary issue: `params[1].coinbase_payout` is expected to be
**raw bytes**, but JSON values come in as strings (utf8/ascii). A
caller that passes a hex-encoded scriptPubKey will get a P2PKH that
locks to the hex characters interpreted as bytes — also unspendable in
practice. The handler does no hex-decode, no validation, no length
check.

**File:** `lunarblock/src/rpc.lua:3869-3885` (default payout); echo of
`lunarblock/src/mining.lua:362-366` (W154 BUG-NEW).

**Core ref:** `bitcoin-core/src/node/types.h:78` (default OP_TRUE).

**Impact:** any pool using lunarblock's GBT without explicit
`coinbase_payout` injection BURNS the block reward (3.125 BTC + fees).
At today's mainnet difficulty + price, a single mistakenly-mined block
costs roughly $200k.

---

## BUG-9 (P1) [carry-forward W154 BUG-6 surface] — Per-tx `sigops` field hardcoded to 0

**Severity:** P1. `mining.lua:485`:

```lua
template.transactions[#template.transactions + 1] = {
  ...
  sigops = 0,  -- simplified
  weight = entry.weight,
}
```

BIP-22 / Core (`rpc/mining.cpp:927-932`) emits the precomputed sigop
cost per tx (with pre-segwit divide-by-4 adjustment) so pool clients
can construct alternative block layouts (e.g. CPFP-only selection,
custom fee-rate skews) and verify they stay under
`MAX_BLOCK_SIGOPS_COST`. Hardcoding `sigops = 0` for every transaction
tells the client "this tx contributes zero sigops to the block cap"
— which is false. A pool that rebuilds the block with extra
high-sigop transactions would exceed the cap and have the submission
rejected with `bad-blk-sigops`.

This is the BIP-22 surface of W154 BUG-6 (which flagged that the
per-block accumulator `total_sigops` misses P2SH redeem-script sigops
and segwit witness-program sigops). Even fixing the accumulator
doesn't help here — the per-tx report is unconditionally zero.

**File:** `lunarblock/src/mining.lua:485`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:927-932`.

**Impact:** pool re-layouts produce over-sigops blocks rejected with
`bad-blk-sigops`; effectively forces pools to only use the template
as-is (no fee-rate optimisations).

---

## BUG-10 (P1) — `coinbasetxn` emitted unconditionally; non-standard server mode

**Severity:** P1. Per BIP-22, `coinbasetxn` is a server-side mode for
clients that declared the `"coinbasetxn"` capability (or, legacy: a
client that only supports building blocks from a server-supplied
complete coinbase). Bitcoin Core removed this mode years ago; modern
Core ONLY emits `coinbasevalue` (`rpc/mining.cpp:1001`) and the client
is expected to construct the coinbase. lunarblock emits BOTH:

```lua
coinbasevalue = coinbase_value,
coinbasetxn = {
  data = M.hex_encode(serialize.serialize_transaction(coinbase_tx, true)),
},
```

(`mining.lua:434-437`). A pool that picks up `coinbasetxn.data` and
mines that coinbase directly will mine the burn-address default
(BUG-8). A pool that tries to construct its own coinbase from
`coinbasevalue` and also takes `coinbasetxn` as authoritative might
end up with two coinbase txns in the block (and a different merkle
root from the one in the header). The cleanest behaviour is Core's:
emit only `coinbasevalue` and let the client own the coinbase.

**File:** `lunarblock/src/mining.lua:434-437`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1001` (only `coinbasevalue`
is emitted).

**Impact:** ambiguous template semantic; pool clients may mine the
default burn-address coinbase (BUG-8); BIP-22 wire-format divergence
from Core for the `coinbasetxn` capability negotiation.

---

## BUG-11 (P1) — getblocktemplate does not refuse during IBD or when no peers connected

**Severity:** P1. Core (`rpc/mining.cpp:766-775`):

```cpp
if (!miner.isTestChain()) {
    const CConnman& connman = EnsureConnman(node);
    if (connman.GetNodeCount(ConnectionDirection::Both) == 0) {
        throw RPC_CLIENT_NOT_CONNECTED("Bitcoin Core is not connected!");
    }
    if (miner.isInitialBlockDownload()) {
        throw RPC_CLIENT_IN_INITIAL_DOWNLOAD("... initial sync ...");
    }
}
```

These gates prevent a freshly-started node from issuing templates that
build on an out-of-date tip (which would orphan immediately on the
network) and prevent isolated nodes (no peers) from doing the same.
lunarblock's handler has neither gate — `rpc.lua:3869-3885` builds and
returns a template regardless of IBD or peer count. The
`getblockchaininfo` handler at `rpc.lua:1302-1307` does compute an IBD
flag (tip more than 24h behind wall-clock), so the data is available;
the GBT handler just doesn't consult it.

Failure mode: an operator runs `lunarblockd` from cold storage, the
node loads its tip from disk (months-old), peers haven't connected
yet, the operator's pool helper calls `getblocktemplate`, mines on the
stale tip, and the block orphans the moment a peer connects.

**File:** `lunarblock/src/rpc.lua:3869-3885`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:766-775`.

**Impact:** pre-sync mining produces orphans; lonely-node mining
(intentional or accidental fork) gets no warning.

---

## BUG-12 (P1) — Reject-string wire-parity slippage; `bip22_result` mapper depends on free-form English

**Severity:** P1 ("reject-string wire-parity slippage, 25+ tokens
fleet pattern" — first major lunarblock instance after the W125 nine-
token sweep). `rpc.lua:56-214` defines `bip22_result(err)`, a
single-source mapper that scans the internal error message for
substring patterns and emits one of ~17 canonical BIP22 tokens. The
canonical-keys table (line 64-77) handles exact-match and
`"<token>:"` prefix-match for already-canonicalised errors. But the
rest of the mapper relies on free-form English substring matches:

```lua
if s:find("proof of work") or s:find("invalid pow") or s:find("does not meet target") then
  return "high-hash"
end
if s:find("merkle root") and not s:find("witness") then
  return "bad-txnmrklroot"
end
if s:find("witness commitment") or s:find("witness nonce") then
  return "bad-witness-merkle-match"
end
...
if s:find("coinbase scriptsig") and (s:find("too long") or s:find("too short") or s:find("out of range")) then
  return "bad-cb-length"
end
```

This brittles the wire contract two ways:
1. Any internal error message that gets re-worded silently changes the
   BIP22 token emitted.
2. Any token that's only synthesised here (e.g. `bad-cb-length`
   above, `time-too-new`, `time-too-old`, `time-timewarp-attack`,
   `bad-version(0x...)`) depends on the upstream English-string
   producer also being grepped for. If a Lua `assert` somewhere emits
   `"assertion failed: validation.lua:220: ..."` instead of the
   expected English, the mapper falls through to `"rejected"` and the
   token is lost.

The previous wave (W125) fixed nine such tokens; this entry catalogues
the architectural risk that the same brittleness applies to every
non-canonical assertion in the validation/utxo/check_block stacks.
Better: pass a structured `{token, message}` table from the validator
to the RPC layer (the way Core does with `BlockValidationState`).

**File:** `lunarblock/src/rpc.lua:56-214`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:587-603`
(`BIP22ValidationResult` consumes `BlockValidationState`, a typed object,
NOT an English string).

**Impact:** ongoing wire-format risk; any future error-message re-word
or assertion change in `validation.lua` / `utxo.lua` silently changes
BIP22 token reporting.

---

## BUG-13 (P0-CDIV) — `prioritisetransaction` / `getprioritisedtransactions` RPCs absent

**Severity:** P0-CDIV. These are first-class Core RPCs
(`rpc/mining.cpp:502-583`) used by miners and operators to:
- bump (positive `fee_delta`) or suppress (negative `fee_delta`) the
  effective mining priority of a specific txid,
- inspect the current set of operator-imposed deltas.

A grep over `lunarblock/src/*.lua` returns ZERO hits for
`prioritisetransaction` or `getprioritisedtransactions`. The RPC table
in `rpc.lua` enumerates ~150 methods including `submitpackage`,
`testmempoolaccept`, `getrawmempool`, etc. but neither prioritisation
RPC is defined.

Failure mode: a pool that runs a CPFP-bumping cron (common pattern:
detect parent tx of an own-wallet child that has piled up below the
mempool min-relay-fee floor; bump the parent with
`prioritisetransaction` so the child gets mined too) silently no-ops.
Operator-driven tx priority overrides (e.g. a tx the operator wants
mined but that fell out of the fee-rate top 4MB) cannot be applied.

**File:** `lunarblock/src/rpc.lua` (no `prioritisetransaction` /
`getprioritisedtransactions` case).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:502-583`.

**Impact:** operator API gap; CPFP-bumping workflows don't work;
pool-side transaction prioritisation is non-functional.

---

## BUG-14 (P1) — `submitheader` RPC absent

**Severity:** P1. Core's `submitheader` (`rpc/mining.cpp:1108-1146`)
accepts a bare 80-byte header in hex and submits it to
`ProcessNewBlockHeaders`. The use case is header-relay clients
(neutrino-style SPV wallets, header-first sync helpers) that want to
inject a known-good header into the daemon's index without sending the
full block. A grep over `lunarblock/src/*.lua` returns ZERO hits for
`submitheader`.

There IS a `submitblock` (full-block submit) and `submitblocks` /
`submitblockbatch` (multi-full-block submit) but no header-only path.
Header-relay protocols that depend on `submitheader` simply error out
with `Method not found`.

**File:** `lunarblock/src/rpc.lua` (no `submitheader` case).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1108-1146`.

**Impact:** SPV-bridge / header-relay integrations cannot inject
headers; falls back to full-block paths (wasteful) or fails.

---

## BUG-15 (P2) — `submitblock` does not accept the 2nd `dummy` argument

**Severity:** P2. BIP-22 specifies `submitblock(hexdata, dummy)` with
the second arg ignored but accepted for compatibility. Core
(`rpc/mining.cpp:1056-1106`) declares the optional arg. lunarblock's
handler at `rpc.lua:6949-6961` reads only `params[1]` and never
references `params[2]`; a request that includes a `dummy` arg works by
accident because the extra positional arg is silently ignored by the
Lua handler's `local hexdata = params[1]` line.

This is benign in practice (most clients omit the dummy), but the
**named-arg** variant `{"hexdata": "...", "dummy": "..."}` would fail
since Lua tables-as-named-args isn't handled here. A pedantic BIP-22
client that always passes named args sees a hard error
(`INVALID_PARAMS`) instead of the documented-ignored behaviour.

**File:** `lunarblock/src/rpc.lua:6949-6961`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1063-1066`.

**Impact:** edge-case BIP-22 client compatibility; never a runtime
crash but a wire-spec gap.

---

## BUG-16 (P1) — `mutable` / `capabilities` / `transactions` empty-array
encoding bug (cjson `{} = object` vs `[] = array`)

**Severity:** P1 ("Lua/cjson empty-array fleet pattern"). cjson encodes
an empty Lua table `{}` as the JSON empty object `{}` by default
(because Lua has no distinction between map and array). The
convention in this repo is to tag empty arrays with
`cjson.empty_array_mt`:

```
$ grep -n 'cjson.empty_array' lunarblock/src/rpc.lua | wc -l
8
```

`mining.lua:425-453` never applies this metatable. The fields most at
risk are:

- `template.transactions = {}` (line 432) — emitted as `{}` when the
  mempool is empty, but BIP-22 specifies it as an array. Pool clients
  parsing `transactions[i]` would crash on `object is not array`.
- `template.vbavailable = {}` (line 417, `OBJ_DYN` per Core) — this
  one is correct (Core uses an object), so encoding as `{}` is fine.
- `template.capabilities` (line 426) and `rules` (line 408) — these
  always have at least one entry (`"proposal"` / `"csv"`), so they
  always encode as `[...]`. No risk in practice; if `rules` ever
  becomes empty, the wire would silently break.
- `coinbaseaux = {flags = ""}` (line 433) — this is an object with one
  key, correct.

**File:** `lunarblock/src/mining.lua:417, 425-453`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:897`
(`UniValue transactions(UniValue::VARR)` — explicitly array-typed).

**Impact:** when mempool is empty (regtest / fresh-start), `transactions`
is wire-encoded as `{}` instead of `[]`; strict pool clients
(JavaScript / Python) raise type errors.

---

## BUG-17 (P1) — `generateblock` and `generatetoaddress` skip script
validation only-by-coincidence (no skip_scripts knob)

**Severity:** P1. Both `generateblock` and `generatetoaddress`
(`rpc.lua:3645-3866, 3888-3990`) route through `chain_state:accept_block`
with `skip_scripts = false` hardcoded (and a Boolean-derived
assumevalid check just for `generatetoaddress`'s tip path). On regtest
this means every generate-call runs full script validation, which is
correct, but it forecloses the operator's ability to pass `--minpow
false` style flags or to skip validation for regression-test setup
blocks.

More importantly, `generateblock` re-builds the coinbase **after**
calling `create_block_template`, then re-computes the merkle root, but
does NOT re-compute the witness commitment in the original coinbase
template's witness vout — instead it builds a fresh coinbase via
`create_coinbase_tx(..., witness_commitment, payout_script)`. The
template's coinbase from `create_block_template` is discarded. This is
correct (it has to be, since the txs changed), but the path is
asymmetric with `generatetoaddress` which uses the template's coinbase
directly. A subtle bug-magnet: any future change to
`create_coinbase_tx`'s signature must be threaded through both call
sites.

**File:** `lunarblock/src/rpc.lua:3645-3866, 3888-3990`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::generateblock` (uses
`createNewBlock({.use_mempool=false})` with caller-supplied txns).

**Impact:** code-duplication / two-pipeline-guard pattern (16th
distinct lunarblock instance per W148 tracking); maintenance burden;
no consensus risk today.

---

## BUG-18 (P1) — `getmininginfo` emits dead fields and stale `currentblock*` values

**Severity:** P1. `rpc.lua:7242-7261`:

```lua
return {
  blocks = tip_height,
  currentblocksize = 0,    -- always 0
  currentblockweight = 0,  -- always 0
  currentblocktx = 0,      -- always 0
  bits = bits_hex,         -- of TIP, not next block
  difficulty = difficulty,
  ...
}
```

Core's `getmininginfo` (`rpc/mining.cpp:478-497`) emits
`currentblocksize`/`currentblockweight`/`currentblocktx` as fields
populated from the *most-recent* template (cached). lunarblock returns
0 for all three. A monitoring tool that reads `currentblockweight` to
detect "is the local node producing reasonable templates?" sees 0
indefinitely and either alerts (false-positive) or learns to ignore the
field (silent contract drift).

Also: `bits` returned is the TIP's bits, not the NEXT block's bits.
Core emits the tip's bits in `getmininginfo` (this is correct) but
duplicates them into the `next.bits` sub-object so the caller can
distinguish. lunarblock does emit `next.bits = bits_hex` (line 7256)
but that's the same bits string — the next-block compute (BUG-4) was
skipped.

**File:** `lunarblock/src/rpc.lua:7242-7261`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:478-497`.

**Impact:** monitoring contract drift; cross-cite BUG-4 next-block
bits.

---

## BUG-19 (P1) — `submitblock` does not call `UpdateUncommittedBlockStructures`

**Severity:** P1. Core's `submitblock` (`rpc/mining.cpp:1086-1090`):

```cpp
{
    LOCK(cs_main);
    const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
    if (pindex) {
        chainman.UpdateUncommittedBlockStructures(block, pindex);
    }
}
```

`UpdateUncommittedBlockStructures` (validation.cpp) is what populates
the coinbase witness commitment if a miner submitted a block whose
coinbase doesn't carry the BIP-141 `OP_RETURN 0x24 0xaa 0x21 0xa9 0xed
<wroot>` vout. This is required for clients that built the block from
a pre-segwit template (or any client that doesn't construct the
commitment itself). Without this step, the block fails
`CheckWitnessCommitment` and is rejected with `bad-witness-merkle-match`
EVEN IF the block is consensus-valid.

lunarblock's `submitblock` at `rpc.lua:6949-7191` skips this step
entirely. A miner that submits a block without the witness commitment
gets `bad-witness-merkle-match` instead of having the daemon fix it
up. This is a parity gap for legacy/compat miner integrations.

**File:** `lunarblock/src/rpc.lua:6949-7191`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1086-1090` and
`validation.cpp::UpdateUncommittedBlockStructures`.

**Impact:** legacy miner submissions without a pre-built witness
commitment are silently rejected; cross-impl divergence from Core
behaviour.

---

## BUG-20 (P1) — `submitblock` lacks the `StateCatcher` pattern; submit-result categorisation goes through error-string heuristics

**Severity:** P1. Core's `submitblock` (`rpc/mining.cpp:1092-1103`)
registers a `submitblock_StateCatcher` validation interface, runs
`ProcessNewBlock`, and reads the catcher's `state` to build the BIP22
result. If the catcher never fired (`!sc->found`), Core returns
`inconclusive`; if it did, the catcher's `BlockValidationState`
provides a typed `RejectReason` for `BIP22ValidationResult`.

lunarblock's submitblock at `rpc.lua:6949-7191` invokes
`accept_block` via `pcall`, then re-maps the resulting error string
back through `bip22_result` (BUG-12). The `accept_block` return values
are `(ok, err_string)` and the error string is whatever the validator
emitted — there is no structured state object. If the validator
internally validated successfully but the chain-tip didn't flip
(side-branch case), the path returns `cjson.null` (success), not
`inconclusive`. The "inconclusive" return is only ever produced via
the side-branch handler at line 7039, never via the catcher pattern.

A submission that hits a path the catcher would have caught (e.g.
race with another submitblock on the same hash) might receive
`duplicate` instead of `inconclusive` — same shape as the missing-
StateCatcher gap.

**File:** `lunarblock/src/rpc.lua:6949-7191`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1092-1103`.

**Impact:** non-conclusive result reporting; pools that distinguish
`inconclusive` from `duplicate` from `rejected` for retry logic see
wrong categorisation.

---

## BUG-21 (P1) — `chain_state.mtp` is plumbing-look-no-wire (consumer
exists, producer absent); fleet "dead-data plumbing" pattern

**Severity:** P1 ("dead-data plumbing" fleet pattern, ~3rd distinct
lunarblock instance after W138/W140 fleet sweep). `mining.lua:267`
reads `chain_state.mtp`, comments at line 266 say "should be provided"
— but no producer in the whole codebase ever assigns it:

```
$ grep -rn 'chain_state\.mtp\s*=\|self\.mtp\s*=' lunarblock/src/
(zero hits)
```

This is a textbook dead-data plumbing pattern: the consumer is wired
up, the value is plumbed into the template, but the producer was never
written. The fallback `os.time() - 3600` (BUG-5) became permanent.

Architectural fix is one-line: at the end of every successful
`connect_block`, set `chain_state.mtp = get_median_time_past(...)`.

**File:** `lunarblock/src/mining.lua:266-267`; consumer at
`utxo.lua:1535-1608` (constructor never sets) and any
`connect_block`/`accept_block` path (none update).

**Impact:** companion to BUG-5; documents the fix surface.

---

## BUG-22 (P1) — `default_witness_commitment` always emitted post-segwit, with no segwit-gating per BIP-145

**Severity:** P1. `mining.lua:451-452`:

```lua
default_witness_commitment = witness_commitment and
  M.hex_encode("\x6a\x24\xaa\x21\xa9\xed" .. witness_commitment) or nil,
```

This is gated only on `witness_commitment` (which is non-nil iff
`height >= network.segwit_height`). At first glance it matches Core,
which gates emission on `coinbase.required_outputs.size() > 0`. But
Core's check (`rpc/mining.cpp:1028-1030`):

```cpp
if (auto coinbase{block_template->getCoinbaseTx()}; coinbase.required_outputs.size() > 0) {
    CHECK_NONFATAL(coinbase.required_outputs.size() == 1);
    result.pushKV("default_witness_commitment", HexStr(coinbase.required_outputs[0].scriptPubKey));
}
```

emits the COINBASE's already-built commitment vout's scriptPubKey,
which embeds the 32-byte hash of `(witness_root || witness_nonce)`
where `witness_nonce` matches the coinbase's segwit witness data
(`witness_nonce = 0x00..` 32 bytes per BIP-141).

lunarblock recomputes the commitment from the witness merkle root and
a fresh `string.rep("\0", 32)` nonce — matching Core's nonce by
convention, so the emitted hex is consensus-valid for a coinbase whose
witness data is also 32 zero bytes. But IF a future change makes
`create_coinbase_tx`'s witness nonce non-zero (it's hardcoded at
`mining.lua:198, 357`), the emitted `default_witness_commitment` will
DIVERGE from the actual coinbase commitment, and any pool that builds
a coinbase from the template hex + replaces the commitment with the
`default_witness_commitment` would produce a block whose actual
commitment ≠ declared, failing `bad-witness-merkle-match` on submit.

Today this is a latent bug; the fix surface is "always derive the
emitted `default_witness_commitment` from the coinbase template's
actual commitment vout, never recompute" — same architecture as
Core.

**File:** `lunarblock/src/mining.lua:357, 451-452`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1028-1030`.

**Impact:** latent; will activate the first time the witness nonce is
made variable.

---

## BUG-23 (P1) — `extra` field "/LunarBlock/" is hardcoded in
`create_coinbase_tx` and not operator-configurable

**Severity:** P1. `mining.lua:363`:

```lua
local extra = "/LunarBlock/"
```

This is the pool/miner identification slug that goes into the
coinbase scriptSig after the BIP-34 height prefix. Bitcoin Core's
default is empty (`coinbase_output_script` defaults to OP_TRUE but the
scriptSig itself is left empty for the miner to fill via
extra-nonce). Pools that take the GBT template's `coinbasetxn.data`
(BUG-10) and submit as-is will mark blocks they mine as
"/LunarBlock/"-tagged — which is operator-relevant (block-explorer
identification, audit-trail spoofing risk).

A pool running multiple GBT-using daemons (Core + lunarblock failover)
that submits a "/LunarBlock/"-tagged block from the lunarblock side
inadvertently advertises lunarblock-as-pool-software. There's no flag
to override this.

Operator fix: thread `coinbase_aux` (Core's standard mechanism, BIP-22)
through the create_block_template config, and concatenate it to the
scriptSig instead of the hardcoded literal.

**File:** `lunarblock/src/mining.lua:363`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1000`
(`result.pushKV("coinbaseaux", std::move(aux))` — Core emits this for
the pool to populate the scriptSig).

**Impact:** pool identification leakage; cannot operate as a "Bitcoin
Core compatible" pool node without source patching.

---

## BUG-24 (P1) — `vbavailable` always empty; BIP-9 deployment state
machine plumbed but not consulted

**Severity:** P1. `mining.lua:415-417`:

```lua
-- vbavailable: map of pending versionbits deployment names to bit numbers.
-- We have no live BIP9 deployments in our state machine right now; emit empty
-- object.  Core: result.pushKV("vbavailable", vbavailable).
local vbavailable = {}
```

Core's GBT (`rpc/mining.cpp:965-994`) calls
`chainman.m_versionbitscache.GBTStatus(*pindexPrev, consensusParams)`
and iterates over `signalling` / `locked_in` / `active` sets, emitting
each deployment's name + bit number. lunarblock has a versionbits
state machine (consensus.lua:744-774 `compute_block_version` consults
`net.deployments` via `get_deployment_state_for_block`), but
`mining.lua:417` hardcodes `vbavailable = {}` and walks zero
deployments. Even on networks where the consensus module would report
`STARTED` / `LOCKED_IN` deployments, the template advertises none of
them.

This is benign on networks where all deployments are buried-active
(today's mainnet) but breaks signalling for any future soft fork —
operators using lunarblock for GBT will see no `vbavailable` entries
for `taproot`-class deployments and can't know which bits to set.

**File:** `lunarblock/src/mining.lua:415-417`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:965-994`.

**Impact:** soft-fork signalling not exposed in template; benign on
post-Taproot mainnet, blocking for testnet4 deployment cycles.

---

## BUG-25 (P2) — `bip22_result` line 105-117 BIP-34 / coinbase-length
ordering is fragile (comment-as-confession)

**Severity:** P2 ("comment-as-confession" fleet pattern, ~12th
distinct lunarblock instance). `rpc.lua:99-117` carries a multi-paragraph
comment explaining why the `bad-cb-height` / `bad-cb-length` arms must
come BEFORE the generic `script` catcher:

```lua
-- BIP34 coinbase height — MUST come before the generic "script" catcher below.
-- Bug fix (W79): original pattern s:find("bip34") (lowercase) missed the actual
-- error strings emitted by validation.check_block which used uppercase "BIP34:".
-- The first assert message contained "scriptSig" which caused s:find("script")
-- to fire first, returning the wrong code "block-script-verify-flag-failed".
-- The second assert message hit the default "rejected" fallback.
-- Fix: match "bad-cb-height" (now embedded literally in error messages by
-- validation.lua W79 fix) AND keep the legacy uppercase/lowercase patterns for
-- belt-and-suspenders.
```

This is a comment-as-confession: the function's correctness depends on
arm ordering that is not visible at the call-site, and a future
contributor reordering the arms (or adding a new arm above them) can
silently regress to the W79 bug. The right fix is to NOT depend on
substring matching at all (BUG-12), but in the interim, mark these
arm-order constraints with a `-- W79-CRITICAL: do not reorder` flag,
or refactor into a regex match table that compile-time prevents
reordering.

**File:** `lunarblock/src/rpc.lua:99-117`.

**Impact:** regression-risk in the BIP22 token mapper; reorder-and-
break failure mode that was already hit once (W79).

---

## BUG-26 (P1) — `submitblockbatch` alias retains the per-call
`pcall`-and-string fallback, so individual block failures don't surface
the BIP-22 token correctly

**Severity:** P1. `rpc.lua:7196-7215`:

```lua
self.methods["submitblocks"] = function(rpc, params)
  local blocks_hex = params[1]
  if type(blocks_hex) ~= "table" then
    error({code = M.ERROR.INVALID_PARAMS, ...})
  end
  local results = {}
  local submitblock_fn = rpc.methods["submitblock"]
  for i, hex in ipairs(blocks_hex) do
    local ok, result = pcall(submitblock_fn, rpc, {hex})
    if ok then
      results[i] = result
    else
      results[i] = tostring(result)    -- <-- not BIP22 token
    end
  end
  return results
end
```

When the inner `submitblock` throws (e.g. `RPC_DESERIALIZATION_ERROR`
for a malformed hex), the catch path stores `tostring(result)` —
which is the Lua representation of the thrown error table
(`"table: 0x..."`) rather than a BIP22 token. A batch importer that
inspects each element expects either `cjson.null` (success) or a
canonical BIP22 token; getting `"table: 0x7f8a000010"` instead is a
contract break.

Right fix: route through `bip22_result(tostring(result.message or
result))` like the inner handler does on its accept_block path.

**File:** `lunarblock/src/rpc.lua:7204-7209`.

**Core ref:** Core has no submitblockbatch RPC; this is a lunarblock
extension. The contract drift is internal-consistency.

**Impact:** batch-submit IBD tooling sees gibberish in per-block
result slots on parse failures; cannot distinguish `bad-cb-amount`
from a Lua VM error.

---

## Summary

**Bug count:** 26 (BUG-1 through BUG-26).

**Severity distribution:**
- **P0-CDIV:** 6 (BUG-1, BUG-2, BUG-4, BUG-5, BUG-13)
- **P0-FUNDS-BURN:** 1 (BUG-8)
- **P1:** 17 (BUG-3, BUG-6, BUG-7, BUG-9, BUG-10, BUG-11, BUG-12,
  BUG-14, BUG-16, BUG-17, BUG-18, BUG-19, BUG-20, BUG-21, BUG-22,
  BUG-23, BUG-24, BUG-26)
- **P2:** 2 (BUG-15, BUG-25)

Recount: P0-CDIV = BUG-1, BUG-2, BUG-4, BUG-5, BUG-13 = 5. Plus
BUG-8 P0-FUNDS-BURN = 6 P0-class. P1 = BUG-3, BUG-6, BUG-7, BUG-9,
BUG-10, BUG-11, BUG-12, BUG-14, BUG-16, BUG-17, BUG-18, BUG-19,
BUG-20, BUG-21, BUG-22, BUG-23, BUG-24, BUG-26 = 18. P2 = BUG-15,
BUG-25 = 2. Total = 5 + 1 + 18 + 2 = 26. ✓

**Fleet patterns confirmed:**
- **funds-burn** (BUG-8, W154 BUG-NEW echo) — second lunarblock
  instance; default GBT coinbase payout = all-zero P2PKH burn address
  rather than Core's `OP_TRUE` anyone-can-spend dummy
- **carry-forward** (BUG-4 ← W154 BUG-1; BUG-5 ← W154 BUG-2+3; BUG-9
  ← W154 BUG-6 surface; BUG-21 ← W154 BUG-2+3 architectural shape) —
  four W154 findings unchanged at the W155 surface; one full week
  open without remediation
- **dead-data plumbing** (BUG-21) — `chain_state.mtp` consumer exists,
  producer never written
- **reject-string wire-parity slippage** (BUG-12) — first major
  lunarblock case after the W125 nine-token sweep; mapper depends on
  free-form English, brittle to validator re-wording. 25+ tokens
  fleet tracking
- **comment-as-confession** (BUG-25) — 12th distinct lunarblock
  instance per W138/W144 tracking; the W79 BIP-34 ordering bug is
  preserved by a multi-paragraph comment documenting WHY the
  ordering is fragile
- **two-pipeline guard** (BUG-17) — 16th distinct lunarblock
  extension; `generateblock` rebuilds coinbase while `generatetoaddress`
  uses the template's coinbase
- **wire-format break** (BUG-16) — cjson empty-table-as-object
  encoding; `transactions = {}` is wire-encoded as `{}` when mempool
  is empty
- **30-of-30-gates-buggy** candidate: 28 sub-gates, 26 bugs (more bugs
  than gates due to multi-bug gates). Not 30-of-30 but high density;
  W155 = 5th candidate for the pattern after W139/W149/W150/W152/W154
- **wiring-look-but-no-wire** (BUG-1, BUG-13, BUG-14) — three W155
  RPC methods absent entirely (proposal mode, prioritisetransaction,
  submitheader)
- **fleet-wide BIP-22 gap**: missing `longpollid` (BUG-3), missing
  rules-parse (BUG-2), wrong per-tx `sigops` (BUG-9), wrong
  `bits`/`mintime` (BUG-4/BUG-5) — five orthogonal gaps converge on
  "lunarblock's GBT is regtest-mining-only; cannot serve a real pool"

**Top three findings:**
1. **BUG-8 (P0-FUNDS-BURN) — default GBT coinbase payout = burn
   address `1111111111111111111114oLvT2`.** Any pool that calls
   `getblocktemplate` without lunarblock's non-standard
   `coinbase_payout` knob, then mines the returned `coinbasetxn.data`
   as-is, burns the entire block reward (~3.125 BTC subsidy + tens of
   thousands sats in fees). This is W154 BUG-NEW echoed at the RPC
   handler surface — the dangerous default is fixed at the handler
   layer, so the mining module never sees the burn-address payout to
   reject it. Companion to BUG-10 (`coinbasetxn` emitted alongside
   `coinbasevalue` makes it more likely a pool naively mines the
   burn coinbase). Severity is "lose-3-BTC-per-mistakenly-mined-block".
2. **BUG-5 (P0-CDIV) — `chain_state.mtp` never populated; mining-side
   BIP-113 fundamentally broken.** The mining template's `mintime`
   field falls back to `os.time() - 3600` because the consumer at
   `mining.lua:267` reads `chain_state.mtp` and no producer in the
   codebase ever sets it. Compounding effects: (a) mempool selection
   uses the wrong MTP for `is_final_tx` (cross-cite W154 BUG-2+3);
   (b) BIP-94 retarget-boundary timewarp defence is entirely absent;
   (c) emitted `mintime` is wrong direction depending on active vs
   stalled chain. First-class architectural gap — single 1-line fix
   (add `chain_state.mtp = compute_mtp(...)` to every `connect_block`
   success path) closes BUG-5, BUG-21, and W154 BUG-2+3.
3. **BUG-1 + BUG-2 + BUG-13 + BUG-14 cluster (P0-CDIV BIP-22
   surface gap).** Four orthogonal RPC-surface gaps that together mean
   lunarblock cannot serve a Bitcoin-Core-compatible mining pool:
   (a) `proposal` mode not implemented — pre-flight block validation
   returns a fresh template instead of `BIP22ValidationResult`;
   (b) `rules` client-capability not parsed — segwit/signet gate
   absent, pre-segwit miners get post-segwit templates;
   (c) `prioritisetransaction` / `getprioritisedtransactions` RPCs
   absent — pool-side priority overrides non-functional;
   (d) `submitheader` RPC absent — header-relay SPV bridges error
   out. All four are "wiring-look-but-no-wire" — the surrounding
   infrastructure exists, the handlers were never written.

**Active carry-forward acknowledged**: BUG-4 (was W154 BUG-1), BUG-5
(was W154 BUG-2+3), BUG-9 (was W154 BUG-6 surface), BUG-21 (was W154
architectural shape of BUG-2+3). One full week open without
remediation; recommended for priority next fix wave.
