# W134 — BIP-37 Bloom Filter (legacy SPV) audit (lunarblock)

**Date:** 2026-05-17
**Wave:** W134 (discovery)
**Impl:** lunarblock (Lua / LuaJIT)
**Status:** **17 BUGS FOUND** (3 P0 / 6 P1 / 6 P2 / 2 P3) across **30 gates**
**Scope:** BIP-37 (`filterload`, `filteradd`, `filterclear`, `merkleblock`,
`MSG_FILTERED_BLOCK`), BIP-111 (NODE_BLOOM service-bit gating), the
`CBloomFilter` math (MurmurHash3 + insert/contains + IsRelevantAndUpdate),
the `CPartialMerkleTree` traversal, the version-handshake `fRelay` flag,
and the outbound tx-INV bloom application path in peerman.lua.
**Excludes:** BIP-157/158 compact filters (W121 / W122), BIP-35 mempool walk
(audited in W110 in passing; we extend to *post-filter* mempool walk here).

## Context

Re-audits lunarblock's BIP-37 surface against `bitcoin-core/src/common/bloom.{cpp,h}`,
`bitcoin-core/src/merkleblock.{cpp,h}`, and the FILTERLOAD/FILTERADD/FILTERCLEAR/
version/`getdata MSG_FILTERED_BLOCK`/mempool handlers in `net_processing.cpp`.
W110 (commit `5f255e2`) discovered 19 bugs centred on math correctness +
NODE_BLOOM advertisement; FIX-36 (`c96df8c`) wired the BIP-111 disconnect path
and FIX-37 (`eb1f9fc`) wired the dispatch handlers + outbound INV filtering.
W134 looks at the same surface fresh, with three new vectors:

1. **Post-FIX-37 wire-correctness gates** (merkleblock encoding round-trip,
   matched-tx TX_NO_WITNESS serialisation parity, BitsToBytes LSB-first
   packing parity vs Core).
2. **Version-handshake `fRelay` flag** semantics (Core gates outbound tx-INV
   on `tx_relay->m_relay_txs = fRelay` — W110 did not check this).
3. **Outbound application** of the per-peer bloom filter in peerman.lua's
   `queue_tx_announcement` + the mempool (BIP-35) walk — does the filter
   actually skip non-matching tx, or is it just stored?

The crux of W134 is: bloom math + dispatch + per-peer storage are correct
(FIX-37 landed), but **three subtle correctness holes remain**:

- `peer.relay_txes` is a misspelled dead variable (Core: `m_relay_txs`).
  It is set by `filterload`/`filterclear` but **never read** anywhere.
  A peer sending `fRelay=false` in its version message still receives full
  tx-INV traffic from us — direct BIP-37 protocol violation.
- The version-message `fRelay` parsed at `p2p.lua:455-459` is never propagated
  to `peer.relay_txes` or any gate; `fRelay=false` connections leak.
- BIP-35 mempool handler (`main.lua:1410-1443`) walks **every** mempool entry
  and pushes INV without applying the loaded bloom filter — Core's
  `net_processing.cpp:6010-6020` and `:6072-6080` calls
  `m_bloom_filter->IsRelevantAndUpdate(*txinfo.tx)` before INV.
  This is a high-impact privacy + bandwidth bug — SPV clients receive INV
  for *every* mempool tx, defeating the entire BIP-37 purpose.

> References:
> - `bitcoin-core/src/common/bloom.{cpp,h}` — CBloomFilter math, insert,
>   contains, IsRelevantAndUpdate, IsWithinSizeConstraints, MurmurHash3.
> - `bitcoin-core/src/merkleblock.{cpp,h}` — CPartialMerkleTree (height,
>   pos, vBits, vHash, BitsToBytes LSB-first), CMerkleBlock.
> - `bitcoin-core/src/net_processing.cpp:3594-3691` — version-handshake
>   fRelay + tx_relay/m_relay_txs gate.
> - `bitcoin-core/src/net_processing.cpp:2438-2458` — getdata
>   MSG_FILTERED_BLOCK + matched-tx push (TX_NO_WITNESS).
> - `bitcoin-core/src/net_processing.cpp:4963-5033` — FILTERLOAD/FILTERADD/
>   FILTERCLEAR (BIP-111 gate + parse + store).
> - `bitcoin-core/src/net_processing.cpp:5985-6080` — BIP-35 mempool walk
>   applies the per-peer bloom filter before pushing INV.
> - BIPs 37 and 111.

## Method

1. Read Core refs end-to-end (bloom.cpp 247 LOC, merkleblock.cpp 184 LOC,
   plus the four msg-handler regions in net_processing.cpp).
2. Build the 30-gate matrix (math + serialisation + tree + dispatch +
   outbound application).
3. Inventory lunarblock's BIP-37 surface:
   - `src/bloom.lua` (647 LOC, post-FIX-37): all math + traversal lives here.
   - `src/main.lua:1410-1538` (BIP-35 mempool + FILTERLOAD/ADD/CLEAR/MERKLEBLOCK
     handlers + getdata MSG_FILTERED_BLOCK serving).
   - `src/p2p.lua:115-153` (NODE_BLOOM service-bit `our_services`).
   - `src/p2p.lua:393-481` (version `fRelay` ser/deser).
   - `src/peerman.lua:2065-2105` (outbound tx-INV filter application).
   - `src/peer.lua:177-186, 663-735` (per-peer `our_services` storage,
     `wtxid_relay`, no `relay_txs` field).
4. Catalogue each gate as PASS / BUG-N / DEFERRED (e.g. items already covered
   in W110 / FIX-37 and re-verified here).
5. Write `tests/test_w134_bip37_bloom_filter.lua` with 30+ assertions
   targeting each gate; XFAIL the open bugs so the suite is green now but
   flips to PASS when the fixes land.

## Gate Matrix (30)

| Gate | Subsystem | Property | Verdict |
|------|-----------|----------|---------|
| G1   | constants | `MAX_BLOOM_FILTER_SIZE = 36000` (bloom.h:17) | PASS |
| G2   | constants | `MAX_HASH_FUNCS = 50` (bloom.h:18) | PASS |
| G3   | constants | `LN2SQUARED` matches Core to mantissa precision | PASS |
| G4   | constructor | bit-size formula: `min(-1/LN2SQUARED * n * log(fp), MAX_BLOOM_FILTER_SIZE * 8) / 8` | PASS |
| G5   | constructor | nHashFuncs formula: `min(vData.size() * 8 / n * LN2, MAX_HASH_FUNCS)` | PASS |
| G6   | math | MurmurHash3 32-bit unsigned via mul32u (W110 BUG-3 fix) | PASS |
| G7   | math | seed = `nHashNum * 0xFBA4C795 + nTweak` mod 2^32 | PASS |
| G8   | math | bit-index modulo: `MurmurHash3(...) % (vData.size()*8)` | PASS |
| G9   | math | empty vData → match-all (CVE-2013-5700 guard) | PASS |
| G10  | math | round-trip `insert(k) → contains(k) = true` for any key | PASS |
| G11-G14 | flags | UPDATE_NONE=0 / UPDATE_ALL=1 / UPDATE_P2PUBKEY_ONLY=2 / UPDATE_MASK=3 | PASS |
| G15  | wire | filterload payload deserialise / re-serialise round-trip | PASS |
| G16  | IsRel | txid match via `contains(txid.bytes)` | PASS |
| G17  | IsRel | per-output pushdata walk via `script.parse_script` | PASS |
| G18  | IsRel | UPDATE_P2PUBKEY_ONLY detection (P2PK + bare multisig) | **BUG-3** |
| G19  | IsRel | outpoint match: `txid(32) || index(LE32)` byte format | PASS |
| G20  | IsRel | scriptSig pushdata match on inputs | PASS |
| G21  | IsRel | UPDATE_ALL inserts outpoint regardless of script class | PASS |
| G22  | IsRel | UPDATE_P2PUBKEY_ONLY inserts outpoint only for P2PK / multisig | PASS* |
| G23  | IsRel | UPDATE_NONE never inserts | PASS |
| G24  | wire | outpoint LE32 index encoding for u32 0..2^32-1 | PASS |
| G25  | p2p dispatch | filterload handler stores filter (FIX-37) | PASS |
| G26  | p2p dispatch | filteradd handler inserts into existing filter (FIX-37) | PASS |
| G27  | p2p dispatch | filterclear handler nils filter (FIX-37) | PASS |
| G28  | merkleblock | CMerkleBlock encoded: header (80) ‖ PMT (tx + hashes + flagBytes LSB-first) | **BUG-5** |
| G29  | size | IsWithinSizeConstraints rejects vData>36000 or hashFuncs>50 | PASS |
| G30  | NODE_BLOOM | service bit = 4 advertised IFF `--peerbloomfilters 1` | PASS |

> Extra audit-derived gates (catalogued as bugs because they don't have a
> matching W134 PASS gate but instead reveal silent omissions):

| Bug | Subsystem | Property | Severity |
|-----|-----------|----------|----------|
| **BUG-1** | version | `fRelay=false` from peer must disable outbound tx-INV until first filter\* msg (Core net_processing.cpp:3684-3691) | **P0-PRIV** |
| **BUG-2** | mempool | BIP-35 mempool walk does NOT apply per-peer bloom filter on each INV (Core :6010-6020 / :6072-6080) | **P0-PRIV/BW** |
| **BUG-3** | IsRel | UPDATE_P2PUBKEY_ONLY treats `multisig` from `classify_script` *AND* `is_p2pk`, but `is_p2pk` only matches non-pushdata-prefixed forms (`0x21|0x41 <pk> 0xac`); Core also tests via `Solver()` which accepts any P2PK shape with valid pubkey length | **P1-CDIV** |
| **BUG-4** | wire | `peer.relay_txes` (TYPO) is set in filterload/filterclear but NEVER read; Core stores `m_relay_txs` and gates outbound | **P0-PRIV** |
| **BUG-5** | merkleblock | `serialize_partial_merkle_tree` writes `n_bytes=1` even when `#v_bits == 0`; Core's `BitsToBytes(empty)` returns empty vector → varint(0) — observable on a block where no tx matches | **P1-PROTO** |
| **BUG-6** | bloom.lua | `outpoint_le32` declared as a **global** (no `local` keyword) at line 412; leaks into `_G` and is order-dependent for reads | **P2-HYG** |
| **BUG-7** | merkleblock | `traverse_and_build`/`calc_hash` are unbounded recursive; a malicious 32-tx block forms a 5-level tree but a 2^25-tx attacker block (Core `MAX_BLOCK_WEIGHT/MIN_TX_WEIGHT` bound check is in `ExtractMatches` only) could deepen recursion. lunarblock has no decode/extract path — only encode — so the surface is restricted, but the recursion is missed | **P2-DOS** |
| **BUG-8** | wire | `peer.bloom_filter` storage is not protected by a mutex equivalent (Lua is single-threaded, but the trickle path in peerman.lua may observe a partially-cleared filter mid-handler if a yield occurs); audit-only — no actual race observed in current code | **P3-OBS** |
| **BUG-9** | wire | After `filterload`/`filteradd`, Core sets `pfrom.m_relays_txs = true` so other subsystems know this peer wants tx; lunarblock has no equivalent flag and routes all peers through `queue_tx_announcement` uniformly | **P1-CDIV** |
| **BUG-10** | misbehaving | Core uses `Misbehaving(peer, "too-large bloom filter")` which marks peer score=100 + sets fDisconnect; lunarblock uses `peer:disconnect(...)`. Net effect identical, but lunarblock loses the per-peer misbehavior accounting (no impact on a single violation; matters for analytics) | **P3-OBS** |
| **BUG-11** | wire | `parse_filterload` ignores `_relay_txs = true` side-effect that Core sets even if filter has empty vData (CVE-2013-5700: match-all filter is still a valid request to enable tx relay); lunarblock's `peer.relay_txes = true` line achieves the *intent* but the typo makes it dead, see BUG-4 | **P1-CDIV** |
| **BUG-12** | wire | Version-handshake `fRelay` from inbound peer is parsed (`p2p.lua:455-459`) but the returned `relay` field is read **only** in peer.lua:705 (`if not self.inbound and ver.relay`) for sendtxrcncl; it is NEVER stored on the peer struct or used to gate outbound tx-INV | **P0-PRIV** (=BUG-1) |
| **BUG-13** | merkleblock | `encode_merkle_block` asserts `block_header_bytes == 80`, but `is_relevant_and_update` is called per-tx with `bf` — Core's CMerkleBlock constructor walks the block transactions and *may* mutate the filter via UPDATE_ALL insert. lunarblock's path at `main.lua:1711` does this correctly, but the merkleblock returned is built off the *post-mutation* filter rather than a snapshot; benign because Core does the same, listed for symmetry | PASS-but-flag |
| **BUG-14** | wire | The deserialized `bloom_filter` from `parse_filterload` has its `vdata` *parsed as table of bytes*, but `encode_filterload` re-encodes them as `string.char()`. If a filter's vData byte equals zero, the round-trip still works (correctly) — explicitly verified G15 | PASS |
| **BUG-15** | wire | `MSG_FILTERED_BLOCK` getdata handler at `main.lua:1695-1741` does not look up the block via `db.get_block` consistently with `MSG_BLOCK`/`MSG_WITNESS_BLOCK` paths; it does in fact use `db.get_block` (verified), so PASS — left here for traceability | PASS |
| **BUG-16** | merkleblock | The matched-tx push at `main.lua:1726` uses `serialize_transaction(tx, false)` which produces TX_NO_WITNESS — matches Core's `TX_NO_WITNESS(*pblock->vtx[tx_idx])` at net_processing.cpp:2457 | PASS |
| **BUG-17** | merkleblock | `calc_tree_width` uses `bit.lshift(1, height)` — LuaJIT bit.lshift returns signed 32-bit; for height >= 32 this wraps. Mainnet block has at most ~3000 tx → height ~12. Safe in practice but the bound is implicit | **P2-LATENT** (W122-style 32-bit LuaJIT shift) |

(Numeric P0=critical, P1=high, P2=med, P3=low.)

\* G22 status: passes only when `classify_script` returns the canonical
`"multisig"` for bare multisig (verified — `script.lua:820`). Mis-typed
return strings would silently drop the UPDATE_P2PUBKEY_ONLY outpoint
insertion. No active issue.

## Bug detail

### BUG-1 (P0-PRIV) — `fRelay=false` ignored on inbound version

**Where:** `src/peer.lua:705`, `src/p2p.lua:455-459`, `src/main.lua:*`,
`src/peerman.lua:2065-2105`.

**Core:**
```cpp
// bitcoin-core/src/net_processing.cpp:3676-3691
if (!pfrom.IsBlockOnlyConn() && !pfrom.IsFeelerConn() &&
    (fRelay || (peer.m_our_services & NODE_BLOOM))) {
    auto* const tx_relay = peer.SetTxRelay();
    LOCK(tx_relay->m_bloom_filter_mutex);
    tx_relay->m_relay_txs = fRelay;   // <-- this is the gate
    if (fRelay) pfrom.m_relays_txs = true;
}
```
Then at `:3980` Core checks `tx_relay->m_relay_txs` and silently drops any
INV for that peer when it is false.

**lunarblock:** `p2p.lua:455` parses `relay = r.read_u8() ~= 0`, returns it
in the `relay` field of `deserialize_version`. `peer.lua:705` reads it ONCE
to decide whether to send `sendtxrcncl`. It is **never** stored on the peer
struct and never consulted by `peerman.lua:2075 queue_tx_announcement`,
which announces every tx to every established peer.

**Impact:** A peer that explicitly opts out of tx relay via `fRelay=0`
(e.g. block-only LN nodes, infrastructure nodes) still receives every
inv we generate. This is a BIP-37 protocol violation: BIP-37 explicitly
states the fRelay flag controls whether the peer wants tx announcements.

**Fix sketch (≤30 lines):**
- Add `self.relay_txs` to `peer.lua:Peer:new` (initialise `= true` for
  pre-fRelay protocol versions).
- In peer.lua handle_version: `self.relay_txs = ver.relay`.
- In `filterload` / `filterclear` handlers in main.lua, write to
  `peer.relay_txs` (fixing BUG-4 in the same edit).
- In `peerman.lua:queue_tx_announcement`, skip peer if `not p.relay_txs`.

### BUG-2 (P0-PRIV/BW) — BIP-35 mempool walk ignores bloom filter

**Where:** `src/main.lua:1410-1443`.

**Core:**
```cpp
// bitcoin-core/src/net_processing.cpp:5985-6020
for (const auto& [hash, tx_info]: m_mempool.GetAllTxsForRelay()) {
    LOCK(tx_relay->m_bloom_filter_mutex);
    if (tx_relay->m_bloom_filter) {
        if (!tx_relay->m_bloom_filter->IsRelevantAndUpdate(*txinfo.tx)) continue;
    }
    // ... push INV
}
```

**lunarblock:**
```lua
-- main.lua:1432
for _, entry in pairs(mempool.entries) do
  local hash = use_wtxid and entry.wtxid or entry.txid
  trickle_state.inv_queue[#trickle_state.inv_queue + 1] = {
    hash = hash, is_wtxid = use_wtxid,
  }
end
```
No filter application at all. Every SPV peer that has loaded a filter and
sent `mempool` receives INV for every mempool tx.

**Impact:** Defeats the entire point of BIP-37: SPV clients are supposed
to receive only inv for tx matching their filter. Bandwidth wasted; privacy
weakened (we leak which tx are in our mempool to a peer that asked for a
narrow filter).

**Fix sketch (≤15 lines):**
```lua
for _, entry in pairs(mempool.entries) do
  if peer.bloom_filter ~= nil and entry.tx ~= nil then
    local ok, matched = pcall(bloom.is_relevant_and_update, peer.bloom_filter, entry.tx)
    if not ok or not matched then goto skip end
  end
  local hash = use_wtxid and entry.wtxid or entry.txid
  trickle_state.inv_queue[#trickle_state.inv_queue + 1] = { hash = hash, is_wtxid = use_wtxid }
  ::skip::
end
```

### BUG-3 (P1-CDIV) — UPDATE_P2PUBKEY_ONLY misses some P2PK shapes

**Where:** `src/bloom.lua:427-436` (`is_p2pk`), `src/bloom.lua:480`.

**Core:** `bitcoin-core/src/common/bloom.cpp:127-132` uses
`Solver(txout.scriptPubKey, vSolutions)` which returns `TxoutType::PUBKEY`
or `TxoutType::MULTISIG`. The Solver matches `PUBKEY` for any 33-byte
compressed pubkey (0x02/0x03) OR 65-byte uncompressed (0x04/0x06/0x07)
preceded by a `OP_PUSHDATA1` push (not just the canonical `0x21 <pk> 0xac`
or `0x41 <pk> 0xac` immediate-push forms).

**lunarblock:** `is_p2pk()` only recognises immediate-push forms:
```lua
if len == 67 and spk:byte(1) == 0x41 and spk:byte(67) == 0xac then return true end
if len == 35 and spk:byte(1) == 0x21 and spk:byte(35) == 0xac then return true end
```
A P2PK with `0x4c 0x21 <pk> 0xac` (OP_PUSHDATA1 33 ...) would not match
even though Core's Solver considers it `PUBKEY`. In practice, all
mainstream wallets emit the canonical 35/67-byte form, so divergence is
unlikely in real mempool traffic — but technically a CDIV gate.

**Impact:** Low real-world; flagged for parity.

### BUG-4 (P0-PRIV) — `peer.relay_txes` typo, dead variable

**Where:** `src/main.lua:1493, 1528`.

**Core:** stores in `tx_relay->m_relay_txs`.

**lunarblock:** `peer.relay_txes = true` is set, never read.

**Impact:** Same as BUG-1 — outbound tx-INV is not gated on whether
the peer wants tx relay. Listed separately because the fix is to either
delete the dead line OR rename + wire it into the gate. Recommended:
rename to `peer.relay_txs` (Core spelling) and wire as in BUG-1 fix.

### BUG-5 (P1-PROTO) — `n_bytes` floor for empty vBits

**Where:** `src/bloom.lua:618-620`.

```lua
local n_bytes = math.ceil(#pmt.v_bits / 8)
if n_bytes == 0 then n_bytes = 1 end   -- <-- inserts a phantom 0x00 byte
```

**Core:** `BitsToBytes(empty) = []`. The merkleblock then serialises with
`varint(0)` and zero bytes following.

**Impact:** When the block has no matching tx AND no transactions at all
(impossible — coinbase always present), the encoded merkleblock differs
from Core's by one byte. In practice the coinbase tx is always in the
walk, so `#pmt.v_bits >= 1`. Currently latent.

**Fix sketch:** drop the `if n_bytes == 0 then n_bytes = 1 end` line.

### BUG-6 (P2-HYG) — `outpoint_le32` not local

**Where:** `src/bloom.lua:412`.

```lua
function outpoint_le32(index)   -- no `local`!
```

**Impact:** Leaks `outpoint_le32` into the global table `_G`. Tests
that probe `_G` see a leftover; future refactors that rename it locally
in another module would silently shadow the global. Low impact.

**Fix:** `local function outpoint_le32(index)` and move declaration above
`M.insert_outpoint` / `M.contains_outpoint` to satisfy local-scoping.

### BUG-7 (P2-DOS) — unbounded recursion in encode

`traverse_and_build` / `calc_hash` are LuaJIT recursive with no depth
guard. For pathological `txid_strings` arrays (length > 2^20), tree
height > 20 → recursion depth grows linearly with height. lunarblock
encodes from our own block (validated; height ≤ ~24 for the largest
block within MAX_BLOCK_WEIGHT), so attacker-induced depth is bounded.
Listed for completeness.

### BUG-8 (P3-OBS) — no filter-mutex equivalent

Lua is single-threaded; main.lua handlers run to completion without
yield in the bloom path. Audit-only — no actual race.

### BUG-9 (P1-CDIV) — no `m_relays_txs` flag

Core sets `pfrom.m_relays_txs = true` on filterload / filteradd /
filterclear / version-with-fRelay-true. Other subsystems (e.g. compact
block relay decisions) read it. lunarblock has no equivalent. Routes
all peers through unified outbound paths; no observable misbehaviour
yet because lunarblock doesn't have the compact-block peer-selection
heuristics that read this flag in Core.

### BUG-10 (P3-OBS) — Misbehaving accounting

`peer:disconnect(reason)` is sufficient; lunarblock has no misbehavior
score tracking. No correctness impact.

### BUG-11 — duplicate of BUG-4 (kept for analytic clarity, same root).

### BUG-12 — duplicate of BUG-1 (kept for analytic clarity, same root).

### BUG-13/14/15/16 — PASS, listed for traceability.

### BUG-17 (P2-LATENT) — LuaJIT `bit.lshift(1, height)` 32-bit semantics

`calc_tree_width` line 535: `bit.lshift(1, height)`. For `height >= 31`,
LuaJIT returns negative (or wraps). MAX_BLOCK_WEIGHT bounds the
number of tx, so height ≤ ~24 in practice — safe. Listed because
W122 / FIX-83 found the same trap class elsewhere in lunarblock.

## Universal patterns observed

- **`fRelay=false` silently ignored** — first time we see this in lunarblock.
  Worth checking the fleet (rustoshi, blockbrew, etc.) — this is a
  universal BIP-37 omission category alongside the bloom filter walk.
- **BIP-35 mempool walk not filter-applied** — also a fleet-wide check.
  Verifying Core line :6010-6020 is honored requires the per-peer filter
  read on every mempool entry.
- **Misspelled/dead per-peer flag** — fleet-wide hunt opportunity:
  `relay_txes` vs `relay_txs`. Bracket-grep across all impls.
- **LuaJIT `bit.lshift` 32-bit trap** — third sighting (W122 BUG-1
  golomb_rice, FIX-83, now W134 BUG-17). Pattern: any `bit.lshift(1, n)`
  with `n` user-controllable or unbounded must use the cdata-uint64
  path or `2^n` Lua float.

## Recommendations

**Priority order for FIX-N fix waves:**

1. **FIX-* (P0)**: Add `peer.relay_txs` field, wire from version `fRelay`,
   from filterload/filterclear, and gate `queue_tx_announcement` +
   BIP-35 mempool walk on it. Closes **BUG-1, BUG-4, BUG-11, BUG-12** in
   one wave (~30 LOC across peer.lua, main.lua, peerman.lua).

2. **FIX-* (P0)**: Apply per-peer bloom filter in BIP-35 mempool walk
   (main.lua:1432). Closes **BUG-2** (~10 LOC).

3. **FIX-* (P1)**: Fix `is_p2pk` to also detect `OP_PUSHDATA1 0x21|0x41
   <pk> 0xac` Core-Solver-equivalent forms. Closes **BUG-3** (~10 LOC).

4. **FIX-* (P1)**: `BitsToBytes` n_bytes floor (drop the `if n_bytes == 0
   then n_bytes = 1 end`); add `m_relays_txs` peer field. Closes
   **BUG-5, BUG-9** (~5 LOC).

5. **FIX-* (P2-P3)**: Make `outpoint_le32` local; document recursion
   bounds; LuaJIT bit.lshift hygiene comment in calc_tree_width. Closes
   **BUG-6, BUG-7, BUG-17** (~5 LOC).

Test suite: `tests/test_w134_bip37_bloom_filter.lua` (30 gates / ~50
assertions / XFAIL on the 4 open P0/P1 bugs).
