# W126 — BIP-152 Compact Blocks audit (lunarblock)

**Date:** 2026-05-17
**Wave:** W126 (discovery)
**Impl:** lunarblock (Lua / LuaJIT)
**Status:** **16 BUGS FOUND** (1 P0-CDIV, 6 P1, 7 P2, 2 P3)

## Context

Audits lunarblock's BIP-152 Compact Block Relay path: short-tx-id
SipHash key derivation, `sendcmpct` negotiation, `cmpctblock` /
`getblocktxn` / `blocktxn` message handling, `PartiallyDownloadedBlock`
reconstruction, and high-bandwidth peer management. Compact blocks
relay is the steady-state block-propagation path on mainnet — any
divergence here causes the node to drop back to a slow full-block
fetch round-trip or, worse, accept a malleated/invalid block.

A prior wave (W112, fixes in `0de7b2a` / earlier) closed 8 of the
most visible bugs (BUG-1 header-hash crash, BUG-2/3 nonce precision,
BUG-4 mempool wtxid iterator, BUG-5 HB announce, BUG-6 unused HB
helpers, BUG-7 depth enforcement, BUG-8 sendcmpct version gating).
W126 re-audits the full surface 6 months later against current Core
master to find regressions and gaps in the post-W112 plumbing — and
finds 13 new bugs concentrated in the cmpctblock handler (no PoW
check on header, no inflight tracking, no DoS misbehaving), the
getblocktxn handler (no MAX_BLOCKTXN_DEPTH, no out-of-bounds
misbehaving), the getdata path (MSG_CMPCT_BLOCK silently ignored),
and the HB peer state model (single `high_bandwidth` flag conflates
Core's `m_bip152_highbandwidth_to` and `_from`).

Reference: `bitcoin-core/src/blockencodings.cpp`,
`bitcoin-core/src/blockencodings.h`,
`bitcoin-core/src/net_processing.cpp` SENDCMPCT/CMPCTBLOCK/
GETBLOCKTXN/BLOCKTXN handlers, BIP-152.

## Method

1. Read Core references:
   - `blockencodings.h` (PartiallyDownloadedBlock, BlockTransactions,
     BlockTransactionsRequest, DifferenceFormatter, PrefilledTransaction,
     CBlockHeaderAndShortTxIDs, SHORTTXIDS_LENGTH).
   - `blockencodings.cpp` (InitData 9-gate validation, GetShortID,
     FillShortTxIDSelector, FillBlock + IsBlockMutated hook,
     extra_txn collision rules).
   - `net_processing.cpp` lines 138-141 (MAX_CMPCTBLOCK_DEPTH=5,
     MAX_BLOCKTXN_DEPTH=10), 199 (CMPCTBLOCKS_VERSION=2), 457-460
     (m_requested_hb_cmpctblocks + m_provides_cmpctblocks), 1272-1329
     (MaybeSetPeerAsAnnouncingHeaderAndIDs HB rotation), 2103-2152
     (NewPoWValidBlock fast-announce), 2461-2476 (MSG_CMPCT_BLOCK
     getdata response), 2598-2615 (SendBlockTransactions misbehaving
     for out-of-bounds), 3901-3917 (SENDCMPCT receive), 4245-4304
     (GETBLOCKTXN receive), 4466-4712 (CMPCTBLOCK receive +
     optimistic reconstruct + revert-to-header), 4714-4726 (BLOCKTXN
     receive).
   - `net_processing.h:47` (MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3).
   - `consensus/consensus.h` (MAX_BLOCK_WEIGHT/MIN_SERIALIZABLE
     _TRANSACTION_WEIGHT = 100000).

2. Enumerated lunarblock surface:
   - `src/compact_block.lua` (487 lines) — codec + PartiallyDownloadedBlock
     + HB helpers (select_high_bandwidth_peers, send_compact_negotiation).
   - `src/p2p.lua:935-1153` — sendcmpct / cmpctblock / getblocktxn /
     blocktxn serializer + deserializer; SHORTTXIDS_LENGTH=6.
   - `src/crypto.lua:1146-1282` — SipHash-2-4 + short-id derivation.
   - `src/peer.lua:892-902` — sendcmpct handler (v2 gating fixed in W112).
   - `src/peer.lua:892-977` — dispatch loop: cmpctblock / getblocktxn /
     blocktxn flow through the catch-all `message_handlers[...]` arm.
   - `src/peer.lua:756-758` — post-verack sends `sendcmpct(false, 2)`.
   - `src/peerman.lua:1888-1935` — `announce_block` HB cmpctblock path
     (W112 BUG-5/6 fix).
   - `src/main.lua:1543-1664` — cmpctblock / blocktxn / getblocktxn
     handler registration.

3. Classified 30 gates PRESENT / PARTIAL / MISSING.

4. Catalogued PARTIAL+MISSING as BUGs with priority.

5. 30 gate tests in `tests/test_w126_bip152_compact_blocks.lua` using
   `pass/fail/xfail_pre_fix` idiom (matches W121/W122/W125 lunarblock
   convention). PARTIAL/MISSING are exercised as `xfail_pre_fix`
   tests so the suite stays green pre-fix and naturally flips to
   `pass` when the fix lands.

6. Watched for: dead-helper-at-call-site (34-wave streak),
   comment-as-confession, well-engineered helper never wired.

7. LuaJIT bit-op audit (W122 BUG-1 / FIX-83 pattern): inspected
   `crypto.siphash24` (`bit.lshift` on uint64_t cdata: safe per
   LuaJIT bit-op extension), `siphash_key_from_header`
   (`bit.rshift(nonce64, i*8)` on cdata: safe), `compact_block_short_id`
   (`bit.band(<uint64_t>, 0xFFFFFFFFFFFFULL) & tonumber`: safe — 48
   bits < 2^53). **No bit-op bugs found** in the BIP-152 path.

## Gate matrix (30)

| # | Gate | Status | Code ref | Bug |
|---|------|--------|----------|-----|
| G1  | `CMPCTBLOCKS_VERSION == 2` (BIP-152 v2 / wtxid) | PRESENT | `compact_block.lua:16` | — |
| G2  | `MAX_CMPCTBLOCK_DEPTH == 5` (Core net_processing.cpp:138) | PRESENT | `compact_block.lua:19` | — |
| G3  | `SHORTTXIDS_LENGTH == 6` (BIP-152 §3.3) | PRESENT | `p2p.lua:966` | — |
| G4  | `MAX_CMPCTBLOCK_TX_COUNT == 100000` (Core blockencodings.cpp:64) | PRESENT | `compact_block.lua:30` | — |
| G5  | `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK == 3` (Core net_processing.h:47) | PRESENT (constant only) | `compact_block.lua:22` | BUG-1 (P1) |
| G6  | `MAX_BLOCKTXN_DEPTH == 10` (Core net_processing.cpp:140) | MISSING | n/a | BUG-2 (P1) |
| G7  | sendcmpct only enables compact when `version == 2` (W112 BUG-8 fix) | PRESENT | `peer.lua:897` | — |
| G8  | SipHash-2-4 short-id derivation matches Core test vectors | PRESENT | `crypto.lua:1198` | — |
| G9  | `siphash_key_from_header` = SHA256(header‖nonce) split (BIP-152 §3.2) | PRESENT | `crypto.lua:1254` | — |
| G10 | short-id is lower 48 bits of SipHash result | PRESENT | `crypto.lua:1278` | — |
| G11 | cmpctblock differential prefilled-index decoding | PRESENT | `p2p.lua:1046-1053` | — |
| G12 | getblocktxn differential index encode/decode round-trip | PRESENT | `p2p.lua:1079-1117` | — |
| G13 | PartiallyDownloadedBlock InitData 9-gate validation (G1-G9 of W112) | PRESENT | `compact_block.lua:134-323` | — |
| G14 | cmpctblock handler header **PoW + chain-connect** validation | MISSING | `main.lua:1543` | BUG-3 (P0-CDIV) |
| G15 | cmpctblock handler **anti-DoS work threshold** (low-work filter) | MISSING | `main.lua:1543` | BUG-4 (P1) |
| G16 | cmpctblock handler **LoadingBlocks/IBD guard** | MISSING | `main.lua:1543` | BUG-5 (P2) |
| G17 | cmpctblock handler **Misbehaving on INVALID InitData** | MISSING | `main.lua:1569` | BUG-6 (P1) |
| G18 | cmpctblock handler **inflight tracking + first-in-flight branch** | MISSING | `main.lua:1543` | BUG-7 (P2) |
| G19 | cmpctblock handler **optimistic reconstruction** (already in flight from another peer) | MISSING | `main.lua:1543` | BUG-8 (P2) |
| G20 | reconstruct() calls **IsBlockMutated hook** (Core FillBlock segwit_active arg) | PARTIAL (hook exists, never called) | `compact_block.lua:387,411` + `main.lua:1577,1623` | BUG-9 (P1) |
| G21 | InitData receives **extra_txn** (orphan/recently-evicted pool, Core vExtraTxnForCompact) | PARTIAL (param exists, never passed) | `compact_block.lua:134` + `main.lua:1568` | BUG-10 (P2) |
| G22 | getblocktxn handler **Misbehaving on out-of-bounds tx index** (Core SendBlockTransactions:2603) | MISSING | `main.lua:1650` | BUG-11 (P1) |
| G23 | getblocktxn handler **MAX_BLOCKTXN_DEPTH** enforcement + fallback-to-full-block | MISSING | `main.lua:1638` | (see BUG-2) |
| G24 | getdata handler **MSG_CMPCT_BLOCK** (inv.type=4) response (Core net_processing.cpp:2461) | MISSING | `main.lua:1666` | BUG-12 (P2) |
| G25 | sendcmpct **gated on `CommonVersion() >= SHORT_IDS_BLOCKS_VERSION (70014)`** | MISSING | `peer.lua:757` | BUG-13 (P3) |
| G26 | distinct `m_bip152_highbandwidth_to` vs `_from` state (Core CNode + CNodeState) | MISSING (collapsed into single `high_bandwidth` flag) | `peer.lua:166` | BUG-13b (P2) |
| G27 | **MaybeSetPeerAsAnnouncingHeaderAndIDs** outbound HB promotion after BlockChecked | MISSING | n/a | BUG-13c (P2) |
| G28 | HB peer cap == 3 enforced when adding HB peers (Core lNodesAnnouncingHeaderAndIDs.size() >= 3) | PARTIAL (cap constant exists in `select_high_bandwidth_peers`; never called by main wiring) | `compact_block.lua:427-448` | (subsumed by BUG-13c) |
| G29 | `NewPoWValidBlock`-equivalent fast-announce path + `m_most_recent_compact_block` cache | PARTIAL (announce_block called per-block; no caching, lazy-builds every send) | `peerman.lua:1908-1916` | BUG-14 (P3) |
| G30 | cmpctblock / blocktxn / getblocktxn explicit dispatch arms in `peer.lua:process_messages` | PARTIAL (falls through generic catch-all `message_handlers[...]`; cfilter has explicit arm) | `peer.lua:892-977` | (cosmetic — generic dispatch works) |

## Bugs

### BUG-1 (P1) — `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3` defined but never enforced

`src/compact_block.lua:22` exports the constant; nothing in
`main.lua` cmpctblock handler counts concurrent in-flight compact
block reconstructions per block hash. Core
(`net_processing.cpp:4577`) uses this to cap parallel
reconstructions to 3 peers per block, falling back to
`MaybeSetPeerAsAnnouncingHeaderAndIDs` to widen later. Without the
cap, a single block triggers as many `partial_block:init` /
`getblocktxn` round-trips as there are HB peers announcing it,
which (a) wastes upstream bandwidth and (b) opens a low-cost DoS
where N HB peers each announce the same block simultaneously.
**Pattern: dead-helper-at-call-site (35-wave streak +1).**

### BUG-2 (P1) — `MAX_BLOCKTXN_DEPTH = 10` not enforced in `getblocktxn` handler

`main.lua:1638-1664` services every `getblocktxn` from `db.get_block`
regardless of how deep the requested block is. Core
(`net_processing.cpp:4276-4302`) refuses to serve a `blocktxn` for
blocks more than 10 below the active tip and instead pushes a
`MSG_WITNESS_BLOCK` getdata into the peer's queue. This is a
deliberate anti-DoS measure: a peer can otherwise spam
`getblocktxn` for deep blocks and force expensive disk reads at low
cost. Lunarblock currently exposes that DoS surface — every disk
read fires straight to the peer regardless of depth.

### BUG-3 (P0-CDIV) — cmpctblock handler accepts header without PoW / chain-connect validation

`main.lua:1543-1600` does NOT validate the cmpctblock header's
PoW or chain-connect to a known prev_block. Core
(`net_processing.cpp:4483-4508`) calls
`m_blockman.LookupBlockIndex(hashPrevBlock)` to require the parent
exists, refuses the message if it doesn't (and `MaybeSendGetHeaders`
fires instead), checks
`prev_block->nChainWork + GetBlockProof(header) < AntiDoSWorkThreshold`
to reject low-work compact blocks, then calls
`ProcessNewBlockHeaders({{cmpctblock.header}}, ...)` which runs
`CheckBlockHeader` (PoW). Lunarblock skips all three. A malicious
peer can therefore feed lunarblock a fake header in a cmpctblock,
get the partial-block plumbing to spin up `getblocktxn` round-trips
for a non-existent chain, and waste lunarblock's bandwidth /
mempool lookups indefinitely. **Consensus surface**: the
reconstructed block reaches `block_downloader:handle_block` which
runs full validation, so a malformed header is eventually
rejected — but only AFTER the round-trip, and any state-mutation
the partial-block path triggers (mempool wtxid iteration, partial
storage on `peer.pending_compact`) happens prematurely. Closer
inspection: `block_downloader:handle_block` validates via
`accept_block` so consensus rejection is preserved; the gap is the
DoS surface ahead of validation. Classified **P0-CDIV** because
peers can drive the node into spurious work on attacker-chosen
hashes; not strict consensus divergence but high-DoS.

### BUG-4 (P1) — cmpctblock handler missing **anti-DoS work threshold** check

Even if the header connects (BUG-3), Core
(`net_processing.cpp:4490-4494`) rejects compact blocks whose
prev_block chainwork + this header's block proof is below
`GetAntiDoSWorkThreshold()` (~144 blocks of work below tip).
Without this filter, a peer can announce historical / minority-fork
compact blocks and force per-block work. Cleanup partner of BUG-3.

### BUG-5 (P2) — cmpctblock handler missing **LoadingBlocks/IBD guard**

Core (`net_processing.cpp:4468-4472`) drops `cmpctblock` and
`blocktxn` while `m_blockman.LoadingBlocks()` is true (IBD,
reindex). Lunarblock processes both regardless of `ibd_complete`,
which during IBD wastes mempool lookups (mempool will be
near-empty), drives `partial:init` into the `getblocktxn` round-trip
branch unconditionally, and contributes to the IBD slowdown
already known on lunarblock. Cheap to fix: early-return on
`block_downloader.ibd_complete == false`.

### BUG-6 (P1) — cmpctblock handler missing **Misbehaving on INVALID InitData**

`main.lua:1569-1573` prints `"compact block init error: ..."` and
returns when `partial:init()` returns an error string (G4/G5/G6
INVALID paths in `PartiallyDownloadedBlock:init`). Core
(`net_processing.cpp:4592-4595`) calls
`Misbehaving(peer, "invalid compact block")` and removes the block
request. Without that, a peer can repeatedly send malformed
compact blocks (out-of-order prefilled indexes, etc.) with zero
score accumulation — slow-burn DoS. Misbehaving primitive exists
on `peer:misbehaving(score, reason)` (used elsewhere in
`peer.lua:868,875`); a 100-point hit matches Core's
`Misbehaving` ≈ `fDisconnect=true` for "invalid object" category.

### BUG-7 (P2) — cmpctblock handler missing **inflight tracking + first-in-flight branch**

Core (`net_processing.cpp:4543-4634`) tracks `mapBlocksInFlight`
keyed by block hash and uses `first_in_flight` to decide whether to
issue a `getblocktxn` after a READ_STATUS_FAILED, or fall through
to giving up. Lunarblock has no equivalent — every cmpctblock from
every HB peer kicks off an independent partial-block reconstruction
which then issues its own `getblocktxn`. This compounds BUG-1.

### BUG-8 (P2) — cmpctblock handler missing **optimistic reconstruction** path

Core (`net_processing.cpp:4640-4654`) — when the block is already
in flight from another peer (or this peer already has too many
outstanding blocks), it still tries to reconstruct optimistically
into a `tempBlock` without issuing a fresh `getblocktxn`, and on
success goes straight to `ProcessBlock(pblock, force_processing=true)`.
This saves a round-trip in the common "we already saw this block
header via headers-first sync but a different peer is announcing
the same cmpctblock". Lunarblock skips the optimistic path
entirely — every cmpctblock is treated as fresh.

### BUG-9 (P1) — `reconstruct()` IsBlockMutated hook present but never wired

`src/compact_block.lua:387` accepts an optional `check_mutated`
callback and at line 411 returns `nil, "mutated block (possible
short ID collision)"` when the hook reports true. But the two call
sites in `main.lua` (`partial:reconstruct()` on line 1577 and 1623)
**both omit the argument**. Core (`blockencodings.cpp:219-221`)
unconditionally calls `IsBlockMutated(block, segwit_active)` before
returning READ_STATUS_OK, which catches witness-root malleability
and merkle-root mismatches that a 48-bit short-ID collision can
introduce. Without the hook, a malicious peer can craft two
transactions that hash to the same 48-bit short-ID, get one of
them into mempool, and then send a cmpctblock referring to the
OTHER one — lunarblock will assemble a block with the wrong
transaction body and submit it to `accept_block`, which will then
reject for merkle-root mismatch. That's a wasted round-trip + a
correctness footgun if the merkle-check is ever weakened.
**Pattern: dead-helper-at-call-site (35-wave streak +1).**

### BUG-10 (P2) — `init()` extra_txn parameter present but never passed

`src/compact_block.lua:134-323` accepts `extra_txn` (line-by-line
parity with Core's `vExtraTxnForCompact`: orphan pool + recently
evicted transactions). The block at line 287-320 implements the
extra_txn collision rules including the wtxid-comparison subtlety
in BUG-9 territory. `main.lua:1568` calls
`partial:init(cmpctblock, mempool)` — no extra_txn. Core
(`net_processing.cpp:4591,4642`) passes `vExtraTxnForCompact`
which is maintained by `txorphanage` + ATMP-side eviction queue.
Lunarblock has an `orphan_pool` (line 1069) but never feeds it into
the compact-block path, so any transaction in the orphanage that
would have completed the cmpctblock without a getblocktxn still
requires a round-trip. **Pattern: dead-helper-at-call-site (35-wave
streak +1).**

### BUG-11 (P1) — `getblocktxn` handler silently drops out-of-bounds indices

`main.lua:1647-1654`: for each requested index, the handler does
`tx = blk.transactions[index + 1]` and conditionally appends to
`transactions[]` if `tx` is non-nil. Core
(`net_processing.cpp:2602-2604`) calls
`Misbehaving(peer, "getblocktxn with out-of-bounds tx indices")`
and returns without sending blocktxn. The current behavior silently
emits a short `blocktxn` whose transaction count doesn't match the
requested index count — confusing for the requester, and gives a
malicious peer a zero-cost way to probe block contents (it can ask
for index 1e9 and get an empty `blocktxn` back, telling it the
block has fewer transactions than that).

### BUG-12 (P2) — `getdata` handler ignores `MSG_CMPCT_BLOCK` (inv.type = 4)

`p2p.lua:196` defines `MSG_CMPCT_BLOCK = 4` but
`main.lua:1666-1746` getdata handler matches only `MSG_WITNESS_TX`,
`MSG_TX`, `MSG_BLOCK`, `MSG_WITNESS_BLOCK`, `MSG_FILTERED_BLOCK`.
A peer that issues `getdata` with type=4 gets neither `cmpctblock`
nor `notfound` back — total silence. Core
(`net_processing.cpp:2461-2476`) responds with `cmpctblock` for
recent blocks (height >= tip - `MAX_CMPCTBLOCK_DEPTH`) and falls
back to a full `block` otherwise. **Pattern: enum-defined-but-not-
dispatched (sibling of dead-helper-at-call-site).**

### BUG-13 (P3) — sendcmpct sent unconditionally; should gate on `CommonVersion() >= SHORT_IDS_BLOCKS_VERSION` (70014)

`peer.lua:757` sends `sendcmpct(false, 2)` after every verack
without checking the peer's protocol version. Core
(`net_processing.cpp:3864`) gates this on
`GetCommonVersion() >= SHORT_IDS_BLOCKS_VERSION` (70014). Today
this is largely cosmetic since virtually all mainnet peers run >=
70015; the bug is that lunarblock will keep sending sendcmpct
forever even if a pre-70014 archival peer connects, and that peer
will accumulate misbehavior score for an unknown command.

### BUG-13b (P2) — single `high_bandwidth` flag conflates `m_bip152_highbandwidth_to` and `_from`

`peer.lua:166-167` declares a single `high_bandwidth = false` flag.
Core (`CNode::m_bip152_highbandwidth_to` /
`m_bip152_highbandwidth_from` in `net_processing.cpp:1318,1325,3915`)
distinguishes two directions:
* `_to`: WE asked THEM to be HB (we sent sendcmpct(true, 2)).
* `_from`: THEY asked US to be HB (they sent us sendcmpct(true, 2)).

These drive different code paths:
* `_to == true` gates the BUG-7 "send `getblocktxn` even when
  not-first-in-flight" branch (net_processing.cpp:4621).
* `_from == true` gates `announce_block`'s cmpctblock dispatch
  (BIP-152 § "Receiving sendcmpct").

In lunarblock the single flag is only ever set from a peer's
inbound `sendcmpct(announce=true, version=2)` — i.e., aliases
`_from` only. Lunarblock never sends `sendcmpct(true, 2)`
outbound, so `_to` is always implicitly false, which means the
optimistic-reconstruct-from-non-first-in-flight branch (BUG-8)
could never fire even if implemented.

### BUG-13c (P2) — no `MaybeSetPeerAsAnnouncingHeaderAndIDs`-equivalent (outbound HB promotion)

Core (`net_processing.cpp:1272-1329`) selects up to 3 of our
fastest-responding peers, sends them `sendcmpct(true, 2)` to
request HB cmpctblock announces FROM them, and rotates them via
`BlockChecked` after a successful block. Lunarblock never sends
`sendcmpct(true, 2)` outbound, so it never asks any peer to be its
HB source — every block arrives via full headers-first sync.
`compact_block.select_high_bandwidth_peers` exists but is wired
nowhere (it was deemed sufficient by W112 BUG-6 fix-doc to use
`peer.high_bandwidth` from incoming sendcmpct; the audit
re-confirms that conclusion was incomplete because it only
addresses the ANNOUNCE-side, not the REQUEST-side). **Pattern:
dead-helper-at-call-site (35-wave streak +1).**

### BUG-14 (P3) — `announce_block` rebuilds cmpctblock per-block; no `m_most_recent_compact_block` cache

`peerman.lua:1908-1916` lazy-builds the cmpctblock payload once
per `announce_block` call (per block, not per peer). Core caches
the most-recent compact block (`m_most_recent_compact_block` +
`m_most_recent_block_txs`) for use by both fast-announce (BIP-152
§ "Sending Compact Blocks") AND the MSG_CMPCT_BLOCK getdata
response (BUG-12). Lunarblock's per-block lazy is fine for the
announce path (one block, one alloc), but rebuilding on every
inbound MSG_CMPCT_BLOCK getdata (when BUG-12 is fixed) would
duplicate work — worth caching once when missing.

## Severity rollup

| Severity | Count | Bug IDs |
|----------|-------|---------|
| P0-CDIV  | 1 | BUG-3 |
| P1       | 6 | BUG-1, BUG-2, BUG-4, BUG-6, BUG-9, BUG-11 |
| P2       | 7 | BUG-5, BUG-7, BUG-8, BUG-10, BUG-12, BUG-13b, BUG-13c |
| P3       | 2 | BUG-13, BUG-14 |
| **Total entries** | **16** | (13 unique bug-classes; BUG-13/13b/13c are 3 facets of the same HB-state gap; BUG-2 covers both G6 and G23) |

## Patterns observed

1. **Dead-helper-at-call-site (35-wave streak +1)** — 3 instances
   in this audit:
   - `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK` constant exported, never
     enforced (BUG-1).
   - `reconstruct(check_mutated)` hook accepted, never passed
     (BUG-9).
   - `init(cmpctblock, mempool, extra_txn)` parameter accepted,
     never passed (BUG-10).
   - `select_high_bandwidth_peers` function defined, never called
     (BUG-13c).

2. **Enum-defined-but-not-dispatched** (sibling pattern, BUG-12):
   `MSG_CMPCT_BLOCK = 4` defined in `p2p.lua:196` INV_TYPE table
   but `main.lua:1666` getdata handler has no branch for it.
   First explicit appearance of this exact shape in lunarblock
   audits; consider tracking separately from dead-helper.

3. **State-flag conflation** (BUG-13b): single `high_bandwidth`
   collapses Core's bidirectional `_to`/`_from` state model. Affects
   correctness for any downstream code that wants to differentiate
   "peer asked us to be HB" from "we asked peer to be HB".

4. **Validation-bypass-via-pcall** (BUG-3/4/5/6 cluster): the
   cmpctblock handler is wrapped in a `pcall` that catches Lua
   errors but does not catch the absence of upstream Core-aligned
   validation. Pre-W112 the handler crashed; post-W112 it
   silently drops bad input. The pcall hides the gap.

5. **W112-fixed-bug-reintroduction-protection** (positive): every
   W112 fix tested in `test_w112_compact_blocks.lua` is still
   passing (verified — see test suite). W126 does not re-test
   those; it focuses on the NEW gaps revealed by re-aligning to
   current Core master.

## Out-of-scope (future waves)

- BIP-152 v1 (txid-based) — Core rejects v != 2 (line 3907) and
  lunarblock matches (peer.lua:897); intentional.
- HB peer rotation latency tuning (Core's "outbound HB peer in
  second slot" trick at net_processing.cpp:1301-1308) — only
  matters once BUG-13c lands.
- `MAX_HEADERS_RESULTS` / `MAX_LOCATOR_SZ` parity — already in
  `p2p.lua:187-189`; not strictly BIP-152 scope.
- ZMQ `hashblock` / `rawblock` notification timing in the compact
  block path — handled separately by W124-style operator audits.

## Test pass/fail expected

With the 13 BUGs above, the W126 test suite expects:
* G1-G4, G7-G13 (constants, codec, SipHash, InitData) — PASS.
* G5, G6, G14-G27 (the 13 bugs, expanded across gates) — XFAIL_PRE_FIX.
* G28-G30 (partial / cosmetic) — mix of PASS + XFAIL_PRE_FIX.

This matches the standard lunarblock audit pattern: every PRESENT
gate is a plain `test(...)`, every PARTIAL/MISSING gate is an
`xfail_pre_fix(...)` that documents the divergence and flips
naturally to PASS when the fix lands.
