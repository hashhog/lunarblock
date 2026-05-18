# W136 — BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay audit (lunarblock)

**Date:** 2026-05-17
**Wave:** W136 (discovery)
**Impl:** lunarblock (Lua / LuaJIT)
**Status:** **23 BUGS FOUND** (6 P0 / 6 P1 / 7 P2 / 4 P3) across **30 gates**
**Scope:** BIP-130 (sendheaders block-announce preference), BIP-133
(feefilter — peer announces minimum acceptable feerate), BIP-339
(wtxidrelay — wtxid-based tx-inv announcement opt-in). Includes:
feature-negotiation message ordering vs VERACK, common-version gating,
post-handshake periodic feefilter broadcasting + IBD MAX_MONEY override,
MoneyRange validation on incoming feefilter, outbound-tx-inv filtering
by the peer's m_fee_filter_received, wtxidrelay-after-VERACK disconnect
contract, MSG_WTX getdata handling.
**Excludes:** sendcmpct/BIP-152 (W126), addrv2/sendaddrv2/BIP-155 (W117),
sendtxrcncl/BIP-330 (own wave), addrman (W128).

## Context

Audits lunarblock's three feature-negotiation / per-peer relay-tuning
P2P messages against Bitcoin Core:

- `bitcoin-core/src/net_processing.cpp`
  - `MaybeSendSendHeaders` (5519–5538) — sends BIP-130 SENDHEADERS only
    AFTER initial-headers-sync completes (chainwork gate).
  - `MaybeSendFeefilter` (5540–5580) — periodic BIP-133 broadcast with
    exponential interval + IBD MAX_MONEY override + rounding via
    `FeeFilterRounder`.
  - WTXIDRELAY handler (3919–3939) — strict "between VERSION and VERACK"
    contract; receiving after `fSuccessfullyConnected` is a disconnect.
  - WTXIDRELAY send (3710–3712) — sent in response to peer's VERSION
    BEFORE VERACK, gated on `greatest_common_version >= WTXID_RELAY_VERSION`.
  - SENDHEADERS receive (3896–3899) — sets `peer.m_prefers_headers`.
  - FEEFILTER receive (5035–5044) — `MoneyRange(newFeeFilter)` validates;
    out-of-range silently dropped.
  - Outbound tx-inv filter check (6000, 6013, 6036, 6071) —
    `txinfo.fee < filterrate.GetFee(txinfo.vsize)` → skip.
- `bitcoin-core/src/policy/feerate.cpp` — `CFeeRate::GetFee(int32_t virtual_bytes)`.
- `bitcoin-core/src/policy/fees/block_policy_estimator.cpp` —
  `FeeFilterRounder::round` (1109–1119) and bucket construction
  (`MakeFeeSet`, 1077–1101).
- `bitcoin-core/src/node/protocol_version.h` —
  `SENDHEADERS_VERSION = 70012`, `FEEFILTER_VERSION = 70013`,
  `WTXID_RELAY_VERSION = 70016`.

The lunarblock surface is split across:

- `src/peer.lua:99-106` — `PRE_HANDSHAKE_ALLOWED` whitelist.
- `src/peer.lua:163-178` — Peer fields: `send_headers`, `fee_filter`,
  `wtxid_relay`.
- `src/peer.lua:633-744` — `Peer:start_handshake()` and
  `Peer:handle_version(payload)` (where Core sends WTXIDRELAY).
- `src/peer.lua:746-760` — `Peer:handle_verack()` (where lunarblock
  blasts `sendheaders` + `sendcmpct` + `feefilter` POST-handshake).
- `src/peer.lua:860-977` — `Peer:process_messages` dispatch loop
  (where SENDHEADERS / FEEFILTER / WTXIDRELAY are received).
- `src/peerman.lua:1888-1935` — `PeerManager:announce_block` (BIP-130
  consumer: prefers headers when `p.send_headers == true`).
- `src/peerman.lua:2075-2106` — `PeerManager:queue_tx_announcement` (BIP-339
  consumer: switches between MSG_TX and MSG_WTX based on `p.wtxid_relay`;
  no `p.fee_filter` check anywhere).
- `src/p2p.lua:497-498` — `serialize_sendheaders` / `deserialize_sendheaders`
  aliased to `serialize_empty`.
- `src/p2p.lua:918-933` — `serialize_feefilter` / `deserialize_feefilter`
  (u64le).
- `src/main.lua:1666-1746` — getdata handler (lacks MSG_WTX serving).

## Method

1. Read Core refs end-to-end (net_processing 6300 LOC tail, feerate.cpp,
   block_policy_estimator FeeFilterRounder, protocol_version.h).
2. Inventory lunarblock's surface (see grep map above).
3. Synthesize a 30-gate matrix covering message dispatch, ordering,
   version gating, payload validation, outbound consumer paths, and
   periodic-broadcast timers.
4. Catalogue divergences as BUG-N with file:line + Core reference.
5. Land xfail tests in `tests/test_w136_relay_flags.lua` exercising
   each bug pre-fix.

## Severity scoring

- **P0** — Correctness divergence visible at the protocol surface,
  bandwidth/DoS amplification vs Core, or wtxidrelay opt-in never
  reached (BIP-339 effectively unimplemented for outbound).
- **P1** — Missing strict-disconnect on protocol violation, or
  consumer-side path (e.g. fee-filter consult on outbound tx-inv) not
  wired so the message receives no behavioral effect.
- **P2** — Missing primitive (FeeFilterRounder, IBD override,
  AVG_FEEFILTER_BROADCAST_INTERVAL timer) that affects bandwidth
  privacy/efficiency, but transactions still flow.
- **P3** — Cosmetic / docs / dead-state.

## 30 W136 Audit Gates

| Gate | Description | Status | Core ref |
|------|-------------|--------|----------|
| G1   | `SENDHEADERS_VERSION = 70012` constant present | **MISSING** (BUG-1 P2) — no version constants module | protocol_version.h:24 |
| G2   | `FEEFILTER_VERSION = 70013` constant present | **MISSING** (BUG-2 P2) | protocol_version.h:27 |
| G3   | `WTXID_RELAY_VERSION = 70016` constant present | **MISSING** (BUG-3 P2) | protocol_version.h:36 |
| G4   | Outbound: SENDHEADERS sent gated on `common_version >= SENDHEADERS_VERSION` AND after initial-headers-sync complete (chainwork > MinimumChainWork) | **DIVERGENT** (BUG-4 P1) — `peer.lua:756` sends UNCONDITIONALLY at handshake-complete, no version check, no chainwork gate; ignores Core's `MaybeSendSendHeaders` (net_processing.cpp:5519-5538) | net_processing.cpp:5519-5538 |
| G5   | Inbound: SENDHEADERS receive sets `peer.m_prefers_headers = true` (no payload, no further side effect) | PRESENT (peer.lua:890-891 sets `self.send_headers = true`) | net_processing.cpp:3896-3899 |
| G6   | Inbound: SENDHEADERS receive does NOT validate "before verack" — accepted any time (Core: anywhere is fine, just sets prefers_headers) | PRESENT | net_processing.cpp:3896-3899 |
| G7   | Block-announce path: peers with `m_prefers_headers=true` get `headers` (BIP-130); others get `inv` | PRESENT (peerman.lua:1923-1929) | net_processing.cpp:5836-5928 |
| G8   | Sending us a feature-negotiation msg (wtxidrelay/sendaddrv2/sendtxrcncl) AFTER VERACK is a disconnect | **DIVERGENT** (BUG-5 P0) — `peer.lua:905-908` silently sets `self.wtxid_relay = true` post-handshake instead of disconnecting; same gap for sendaddrv2 (peer.lua:909-911) | net_processing.cpp:3919-3939 (wtxidrelay), 3943-3949 (sendaddrv2) |
| G9   | Outbound: WTXIDRELAY sent in response to peer VERSION, BEFORE VERACK, gated on `greatest_common_version >= WTXID_RELAY_VERSION` | **MISSING** (BUG-6 P0) — `Peer:handle_version` (peer.lua:694-708) sends sendaddrv2 + sendtxrcncl but NEVER wtxidrelay; `Peer:handle_verack` (post-handshake) doesn't either; consequence: lunarblock advertises PROTOCOL_VERSION 70016 but the wtxid-relay opt-in is never offered to peers, so no peer can switch us to wtxid relay even though `peer.wtxid_relay` flag exists | net_processing.cpp:3710-3712 |
| G10  | Outbound: WTXIDRELAY sent only when m_relays_txs (not block-relay-only / not feeler) | **N/A** (BUG-6 makes this moot; no block-relay-only conn tracking either — peerman.lua:2358) | net_processing.cpp:3710-3712 |
| G11  | Receiving duplicate WTXIDRELAY logs + ignores (not a disconnect) | **PARTIAL** (BUG-7 P3) — peer.lua:908 idempotently sets flag, no log, no count | net_processing.cpp:3932-3933 |
| G12  | Receiving WTXIDRELAY with peer.GetCommonVersion < WTXID_RELAY_VERSION ignores it (logs) | **MISSING** (BUG-8 P1) — peer.lua:905-908 sets flag regardless of peer version | net_processing.cpp:3935-3937 |
| G13  | Inbound: WTXIDRELAY received before VERSION drops the message (pre-handshake filter) | PRESENT (peer.lua:864-870 misbehaving on pre-version, 871-877 only PRE_HANDSHAKE_ALLOWED post-version) | net_processing.cpp:3810-3814 + 3919 |
| G14  | Inbound: FEEFILTER payload validated with MoneyRange (0..MAX_MONEY); out-of-range silently dropped | **MISSING** (BUG-9 P1) — peer.lua:903-904 stores ANY u64 (e.g. negative when read signed, or > MAX_MONEY); no validation | net_processing.cpp:5035-5044 |
| G15  | Inbound: FEEFILTER ignored when peer.GetCommonVersion < FEEFILTER_VERSION | **MISSING** (BUG-10 P2) — no version gate | net_processing.cpp:5543 (send-side analog; receive accepts) |
| G16  | Outbound: FEEFILTER sent only when `common_version >= FEEFILTER_VERSION` | **MISSING** (BUG-11 P2) — peer.lua:758 sends unconditionally to all peers regardless of version | net_processing.cpp:5543 |
| G17  | Outbound: FEEFILTER NOT sent to outbound block-relay-only peers | **N/A** (no block-relay-only conn tracking; BUG-12 P1) | net_processing.cpp:5546-5548 |
| G18  | Outbound: FEEFILTER NOT sent when `m_opts.ignore_incoming_txs` (-blocksonly) | **MISSING** (BUG-13 P2) — no -blocksonly CLI flag | net_processing.cpp:5542 |
| G19  | Outbound: FEEFILTER NOT sent to peers with `ForceRelay` permission | **MISSING** (BUG-14 P3) | net_processing.cpp:5545 |
| G20  | Outbound: periodic FEEFILTER broadcast every ~10 min (AVG_FEEFILTER_BROADCAST_INTERVAL) | **MISSING** (BUG-15 P1) — `peer.lua:758` sends ONCE at handshake; no `next_send_feefilter` timer | net_processing.cpp:5564-5572 |
| G21  | Outbound: in IBD, send MAX_MONEY filter (tell peers not to send any tx); on IBD exit re-send current filter | **MISSING** (BUG-16 P0) — no IBD-aware override; the hardcoded `100000` (100 sat/vB) blast actively diverges from Core's IBD-MAX_MONEY behavior; effectively lunarblock invites tx-inv during IBD and then never drops the threshold | net_processing.cpp:5552-5563 |
| G22  | Outbound: filter rounded via FeeFilterRounder (1.1× spacing buckets, 1e7 max, jitter) | **MISSING** (BUG-17 P1) — `serialize_feefilter(100000)` is a hardcoded literal; no rounder, no privacy quantization | block_policy_estimator.cpp:1077-1119 |
| G23  | Outbound: filterToSend = max(rounded, mempool.min_relay_feerate) | **MISSING** (BUG-18 P0) — hardcoded 100000 sat/kvB is 1000× the Core default DEFAULT_MIN_RELAY_TX_FEE (100 sat/kvB); peers will never relay txs below ~100 sat/vB worth of tx fee (massively over-restrictive) and the value is also unrelated to lunarblock's own mempool min-relay; net effect: lunarblock advertises the WRONG filter | net_processing.cpp:5567 |
| G24  | Outbound: re-send filter only when filterToSend != peer.m_fee_filter_sent | **MISSING** (BUG-19 P3) — moot due to G20/G15 | net_processing.cpp:5568-5571 |
| G25  | Outbound: bring-forward to MAX_FEEFILTER_CHANGE_DELAY if filter changed substantially (<3/4 or >4/3) | **MISSING** (BUG-20 P2) — moot due to G20 | net_processing.cpp:5574-5579 |
| G26  | Inbound consumer: outbound tx-inv filtered by `txinfo.fee < peer.fee_filter.GetFee(vsize)` — peers' BIP-133 filter is HONORED | **MISSING** (BUG-21 P0) — `peerman.lua:2075-2106` (`queue_tx_announcement`) checks bloom filter, switches MSG_TX/MSG_WTX, but NEVER consults `p.fee_filter`; result: lunarblock floods peers with sub-feerate txs they explicitly asked us not to send — wasted bandwidth + (mild) DoS surface | net_processing.cpp:6013, 6071 |
| G27  | Outbound INV path: respects `m_wtxid_relay` to choose MSG_WTX vs MSG_TX | PRESENT (peerman.lua:2096-2097, 2153) | net_processing.cpp:6007-6009, 6063-6065 |
| G28  | GETDATA serving: responds to MSG_WTX (=5) requests by serving witness tx; falls back to NOTFOUND when not in mempool | **MISSING** (BUG-22 P0) — `main.lua:1678` only handles `MSG_TX` and `MSG_WITNESS_TX`; MSG_WTX getdata is silently dropped → peer never receives the tx and eventually times out / re-asks; partial wtxid-relay support: outbound INV uses MSG_WTX but the GETDATA reply path is missing | net_processing.cpp:2518-2587 |
| G29  | Inbound INV handler: respects wtxid-relay choice — orphan parent fetching ALWAYS uses MSG_TX getdata regardless of peer.wtxid_relay | **NOT VERIFIED IN SCOPE** (main.lua:1290-1300 issues MSG_WTX getdata for MSG_WTX invs; orphan-parent-fetch flow not audited here) | net_processing.cpp:4056-4059 |
| G30  | Documentation: `PRE_HANDSHAKE_ALLOWED` whitelist comment includes `wtxidrelay = true` (peer.lua:102) but the implementation neither sends nor strictly enforces BIP-339 — stale-comment hazard | **DOCS-DIVERGENT** (BUG-23 P3) — comment claims compliance; behavior diverges; will mislead future readers; same applies to `feefilter = ...` comment (line 758) which advertises "100 sat/vB" as if intentional | peer.lua:99-106 + peer.lua:756-758 |

## Bugs (21)

> Severity legend mirrors W133: P0 = correctness/DoS / wire-visible
> divergence, P1 = missing primitive required for safe BIP compliance,
> P2 = bandwidth/perf/privacy regression vs Core, P3 = cosmetic/dead.

### BUG-1 (G1, P2, INFRA) — `SENDHEADERS_VERSION = 70012` constant absent

**File:** `src/p2p.lua` (no protocol-version sub-constants; only
`M.PROTOCOL_VERSION = 70016` at line 13).
**Core:** `node/protocol_version.h:24`.

Every BIP-130 / BIP-133 / BIP-339 gate Core has on
`pto.GetCommonVersion()` depends on these constants. Their absence
means lunarblock can't (and doesn't) gate any feature-negotiation
send/receive on the negotiated common version — it just always behaves
as if all peers are 70016. The version-too-old peer at peer.lua:687
(`< 70015`) is the only version threshold the code uses; everything
else assumes 70016.

P2 because the constants alone are a one-line fix; the consequences
(BUG-8, BUG-10, BUG-11, BUG-12) are tracked separately.

### BUG-2 (G2, P2, INFRA) — `FEEFILTER_VERSION = 70013` constant absent

**File:** `src/p2p.lua` (no constant).
**Core:** `node/protocol_version.h:27`.

Same shape as BUG-1, scoped to feefilter (BIP-133).

### BUG-3 (G3, P2, INFRA) — `WTXID_RELAY_VERSION = 70016` constant absent

**File:** `src/p2p.lua` (no constant).
**Core:** `node/protocol_version.h:36`.

Same shape as BUG-1, scoped to wtxid relay (BIP-339).

### BUG-4 (G4, P1, BIP-130) — SENDHEADERS sent too eagerly (no chainwork gate)

**File:** `src/peer.lua:746-760` (`Peer:handle_verack`):

```lua
function Peer:handle_verack()
  if self.handshake_complete then return end
  if self.state == M.STATE.VERACK_SENT or self.state == M.STATE.VERSION_SENT then
    self.state = M.STATE.ESTABLISHED
    self.handshake_complete = true
    self:send_message("sendheaders", "")  -- <-- BUG-4
    self:send_message("sendcmpct", p2p.serialize_sendcmpct(false, 2))
    self:send_message("feefilter", p2p.serialize_feefilter(100000))
  end
end
```

**Core:** `net_processing.cpp:5519-5538` `MaybeSendSendHeaders` (called
from SendMessages loop):

```cpp
// Delay sending SENDHEADERS (BIP 130) until we're done with an
// initial-headers-sync with this peer. Receiving headers announcements
// for new blocks while trying to sync their headers chain is
// problematic, because of the state tracking done.
if (!peer.m_sent_sendheaders && node.GetCommonVersion() >= SENDHEADERS_VERSION) {
    LOCK(cs_main);
    CNodeState &state = *State(node.GetId());
    if (state.pindexBestKnownBlock != nullptr &&
            state.pindexBestKnownBlock->nChainWork > m_chainman.MinimumChainWork()) {
        MakeAndPushMessage(node, NetMsgType::SENDHEADERS);
        peer.m_sent_sendheaders = true;
    }
}
```

Two divergences in one site:
1. No `common_version >= 70012` gate (toy-version peers will get SENDHEADERS).
2. No chainwork gate — lunarblock asks every peer to switch to headers
   announces **before completing initial-headers-sync** with that peer,
   which is exactly the failure mode the BIP-130 comment block in Core
   warns about. During IBD, a peer flooding us with new-block HEADERS
   instead of INV causes the same "state tracking done" problem.

P1 because the visible breakage is during IBD when SENDHEADERS misleads
the peer into pushing HEADERS announcements that lunarblock isn't yet
positioned to validate, but tip-sync still eventually converges.

### BUG-5 (G8, P0, BIP-339 + BIP-155) — WTXIDRELAY (and SENDADDRV2) after VERACK silently accepted

**File:** `src/peer.lua:905-911`:

```lua
elseif msg.command == "wtxidrelay" then
  -- BIP 339: wtxidrelay must be sent before verack
  -- Just acknowledge, no payload
  self.wtxid_relay = true
elseif msg.command == "sendaddrv2" then
  -- BIP 155: sendaddrv2 must be sent before verack
  self.send_addrv2 = true
```

**Core:** `net_processing.cpp:3919-3939` (wtxidrelay) and 3943-3949
(sendaddrv2):

```cpp
if (msg_type == NetMsgType::WTXIDRELAY) {
    if (pfrom.fSuccessfullyConnected) {
        // Disconnect peers that send a wtxidrelay message after VERACK.
        LogDebug(BCLog::NET, "wtxidrelay received after verack, %s", pfrom.DisconnectMsg());
        pfrom.fDisconnect = true;
        return;
    }
    ...
}
```

The pre-handshake whitelist (`peer.lua:99-106`) lists wtxidrelay /
sendaddrv2 as "Must be sent before VERACK" but the dispatcher
(`peer.lua:871-877`) only checks the whitelist while
`!handshake_complete`. After handshake completes, ALL messages fall
through to the message-type switch which silently sets the flag for
both wtxidrelay and sendaddrv2.

P0 because this:
- violates the BIP-339 wire contract,
- lets an attacker flip our `wtxid_relay` flag post-handshake (toggling
  outbound INV between MSG_TX and MSG_WTX without our consent),
- and contradicts the comment one line above. A peer that misbehaves
  here in Core gets disconnected; here it gets honored.

### BUG-6 (G9, P0, BIP-339) — WTXIDRELAY never sent (BIP-339 opt-in unreachable for inbound)

**File:** `src/peer.lua:694-708` (`Peer:handle_version`):

```lua
-- Send feature negotiation messages BEFORE verack (BIP155, BIP330, BIP339)
-- SENDADDRV2 (BIP155): signal addrv2 support so peer relays Tor/I2P/CJDNS to us.
if ver.version >= 70016 then
  self:send_message("sendaddrv2", p2p.serialize_sendaddrv2())
end

-- SENDTXRCNCL (BIP330): Erlay transaction reconciliation
if not self.inbound and ver.relay then
  ...
  self:send_message("sendtxrcncl", ...)
end
```

The comment claims "BIP155, BIP330, **BIP339**" but only BIP155 and
BIP330 are sent. WTXIDRELAY is missing entirely. **Result: lunarblock
advertises PROTOCOL_VERSION=70016 but never offers the wtxid-relay
opt-in to a peer.** A peer that respects "send wtxidrelay only if we
got it from the peer first" (which is what BIP-339 directs honest
clients to do) will never enable wtxid relay with us.

**Core:** `net_processing.cpp:3710-3712`:

```cpp
if (greatest_common_version >= WTXID_RELAY_VERSION) {
    MakeAndPushMessage(pfrom, NetMsgType::WTXIDRELAY);
}
```

Note the comment block at the head of the WTXIDRELAY receive handler
(`net_processing.cpp:3919-3921`):

> BIP339 defines feature negotiation of wtxidrelay, which must happen
> between VERSION and VERACK to avoid relay problems from switching
> after a connection is up.

So the only window to send it is between our receive of peer's VERSION
and our send of our VERACK — exactly where `Peer:handle_version` runs.

P0 because BIP-339 is effectively unimplemented for the outbound path
even though the `wtxid_relay` flag exists, `MSG_WTX` is wired in
`queue_tx_announcement`, and `PRE_HANDSHAKE_ALLOWED` includes
`wtxidrelay`.

### BUG-7 (G11, P3, BIP-339) — Duplicate WTXIDRELAY silently no-op (no log/count)

**File:** `src/peer.lua:905-908`.
**Core:** `net_processing.cpp:3932-3933`:

```cpp
} else {
    LogDebug(BCLog::NET, "ignoring duplicate wtxidrelay from peer=%d\n", pfrom.GetId());
}
```

Lunarblock just re-sets the flag (idempotent, OK on the wire), but
loses the diagnostic signal that a peer is sending duplicates. Low
severity but a useful indicator of buggy/malicious peer behavior.

### BUG-8 (G12, P1, BIP-339) — WTXIDRELAY accepted from peers below WTXID_RELAY_VERSION

**File:** `src/peer.lua:905-908`.
**Core:** `net_processing.cpp:3928-3937`:

```cpp
if (pfrom.GetCommonVersion() >= WTXID_RELAY_VERSION) {
    if (!peer.m_wtxid_relay) {
        peer.m_wtxid_relay = true;
        m_wtxid_relay_peers++;
    }
} else {
    LogDebug(BCLog::NET, "ignoring wtxidrelay due to old common version=%d from peer=%d\n", ...);
}
```

A peer that negotiates an old version (Core checks `peer.lua:687-689`
disconnects below 70015 so we'd only hit 70015) but sends wtxidrelay is
trying to opt-in to a feature their version doesn't support. Core
ignores; lunarblock honors → flips `wtxid_relay` → outbound INVs now
use MSG_WTX (=5) which a 70015 peer doesn't understand → the peer
discards them or disconnects.

### BUG-9 (G14, P1, BIP-133) — FEEFILTER payload not MoneyRange-validated

**File:** `src/peer.lua:903-904`:

```lua
elseif msg.command == "feefilter" then
  self.fee_filter = p2p.deserialize_feefilter(msg.payload)
```

**Core:** `net_processing.cpp:5036-5044`:

```cpp
CAmount newFeeFilter = 0;
vRecv >> newFeeFilter;
if (MoneyRange(newFeeFilter)) {
    if (auto tx_relay = peer.GetTxRelay(); tx_relay != nullptr) {
        tx_relay->m_fee_filter_received = newFeeFilter;
    }
    ...
}
return;
```

Two divergences:
1. Negative values are accepted (LuaJIT's `read_u64le` returns a
   number/cdata; downstream comparison code may silently treat any
   value > 2^53 as just a big number; downstream code may use
   `p.fee_filter` arithmetically and produce surprising results).
2. Values > MAX_MONEY (2.1e15) are accepted and would propagate into
   the consumer if BUG-21 were fixed.

Today this is only latent because BUG-21 means `p.fee_filter` is
inert. When BUG-21 is fixed, BUG-9 becomes a real attack surface.

### BUG-10 (G15, P2, BIP-133) — FEEFILTER accepted from peers below FEEFILTER_VERSION

**File:** `src/peer.lua:903-904` (no version check).
**Core:** `net_processing.cpp:5543` — but the receive side, like
WTXIDRELAY, simply stores any FEEFILTER message it gets. Strictly Core
doesn't gate the RECEIVE on version; it only gates the SEND. So this
is a defensive item only — Core's behavior is "accept", but combined
with BUG-11 it would matter when the peer sends one we shouldn't have
prompted.

Demoted to P2.

### BUG-11 (G16, P2, BIP-133) — FEEFILTER sent unconditionally (no FEEFILTER_VERSION gate)

**File:** `src/peer.lua:758`:

```lua
self:send_message("feefilter", p2p.serialize_feefilter(100000))
```

**Core:** `net_processing.cpp:5543`:

```cpp
if (pto.GetCommonVersion() < FEEFILTER_VERSION) return;
```

A peer that negotiates version < 70013 (would have to be < 70015 in
lunarblock, so this would already be disconnected — but the gate
should still exist for correctness when the lower bound changes).

### BUG-12 (G17, P1, BIP-133) — FEEFILTER sent to outbound block-relay-only peers (gate absent)

**File:** `src/peer.lua:758` (no block-relay-only check).
**Core:** `net_processing.cpp:5546-5548`:

```cpp
// Don't send feefilter messages to outbound block-relay-only peers since
// they should never announce transactions to us, regardless of feefilter
// state.
if (pto.IsBlockOnlyConn()) return;
```

Wider issue: lunarblock has no block-relay-only outbound concept
(`peerman.lua:2356-2360` literally says "treat all outbound as
full-relay"). So this gate is moot until that landing happens, but
when it does, the feefilter blast at handshake will leak our policy to
block-relay-only peers (mild privacy regression).

### BUG-13 (G18, P2, BIP-133) — FEEFILTER sent even with -blocksonly equivalent

**File:** `src/peer.lua:758` (no `ignore_incoming_txs` check).
**Core:** `net_processing.cpp:5542`:

```cpp
if (m_opts.ignore_incoming_txs) return;
```

Lunarblock has no `-blocksonly` CLI flag (`grep -rn "blocksonly"
src/`); the gate is moot until that lands.

### BUG-14 (G19, P3, BIP-133) — FEEFILTER not skipped for ForceRelay peers

**File:** `src/peer.lua:758`.
**Core:** `net_processing.cpp:5545`:

```cpp
if (pto.HasPermission(NetPermissionFlags::ForceRelay)) return;
```

Cosmetic — no NetPermissions concept in lunarblock at all.

### BUG-15 (G20, P1, BIP-133) — No periodic FEEFILTER broadcast (one-shot at handshake)

**File:** `src/peer.lua:758`.
**Core:** `net_processing.cpp:5564-5572`:

```cpp
if (current_time > peer.m_next_send_feefilter) {
    CAmount filterToSend = m_fee_filter_rounder.round(currentFilter);
    filterToSend = std::max(filterToSend, m_mempool.m_opts.min_relay_feerate.GetFeePerK());
    if (filterToSend != peer.m_fee_filter_sent) {
        MakeAndPushMessage(pto, NetMsgType::FEEFILTER, filterToSend);
        peer.m_fee_filter_sent = filterToSend;
    }
    peer.m_next_send_feefilter = current_time + m_rng.rand_exp_duration(AVG_FEEFILTER_BROADCAST_INTERVAL);
}
```

`AVG_FEEFILTER_BROADCAST_INTERVAL = 10min`. lunarblock fires once at
handshake and never updates. If our mempool fills and we want a higher
filter, peers never learn — they keep spamming us with sub-feerate
inv that we'll reject; if our mempool empties and we want a lower
filter, peers continue dropping txs we'd happily relay.

### BUG-16 (G21, P0, BIP-133) — No IBD MAX_MONEY override

**File:** `src/peer.lua:758` (hardcoded 100000).
**Core:** `net_processing.cpp:5552-5563`:

```cpp
if (m_chainman.IsInitialBlockDownload()) {
    // Received tx-inv messages are discarded when the active
    // chainstate is in IBD, so tell the peer to not send them.
    currentFilter = MAX_MONEY;
} else {
    static const CAmount MAX_FILTER{m_fee_filter_rounder.round(MAX_MONEY)};
    if (peer.m_fee_filter_sent == MAX_FILTER) {
        // Send the current filter if we sent MAX_FILTER previously
        // and made it out of IBD.
        peer.m_next_send_feefilter = 0us;
    }
}
```

Two consequences:
1. **In IBD lunarblock invites tx-inv it cannot validate**, wasting
   bandwidth and adding load to the validation path before the active
   chainstate is settled.
2. **On IBD exit, no re-broadcast triggers**, so even after the
   periodic-broadcast in BUG-15 lands, the IBD-MAX_MONEY → live-filter
   transition is invisible to peers.

P0 because this is the only feefilter gate Core sets at the wire-DoS
boundary; lunarblock's hardcoded 100000 sat/kvB happens to *partially*
mute peers, but the protocol intent (no-tx-during-IBD) is not signaled.

### BUG-17 (G22, P1, BIP-133) — No FeeFilterRounder (no bucket quantization, no privacy jitter)

**File:** `src/peer.lua:758` (hardcoded 100000).
**Core:** `block_policy_estimator.cpp:1077-1119`:

```cpp
FeeFilterRounder::FeeFilterRounder(...) :
    m_fee_set{MakeFeeSet(minIncrementalFee, MAX_FILTER_FEERATE, FEE_FILTER_SPACING)},
    ...

CAmount FeeFilterRounder::round(CAmount currentMinFee) {
    auto it = m_fee_set.lower_bound(currentMinFee);
    if (it == m_fee_set.end() ||
        (it != m_fee_set.begin() && rng % 3 != 0)) {
        --it;
    }
    return static_cast<CAmount>(*it);
}
```

The rounder serves a *privacy* purpose: by quantizing into log-spaced
buckets (1.1× spacing) with 2/3 chance of rounding down, the peer
can't tell from `feefilter` exactly what our mempool min is. Without
it, peers can fingerprint the exact mempool state from the precise
filter value — but lunarblock dodges this only because the hardcoded
100000 is constant.

### BUG-18 (G23, P0, BIP-133) — Hardcoded filter 100000 sat/kvB = 1000× Core default min-relay

**File:** `src/peer.lua:758`:

```lua
self:send_message("feefilter", p2p.serialize_feefilter(100000)) -- 100 sat/vB = 100000 sat/kvB
```

**Core:** `policy.h:70` `DEFAULT_MIN_RELAY_TX_FEE = 100` (sat/kvB),
plus `net_processing.cpp:5567` ensures we send at least our own
min-relay. Core's default tells peers "send me anything ≥ 0.1 sat/vB";
lunarblock's hardcoded value tells peers "send me only ≥ 100 sat/vB".

Practical effect on mainnet: the median fee-rate is far below 100
sat/vB, so most ordinary peers will respect the filter and not send us
inv for most new mempool entries → lunarblock observes a vastly
truncated mempool → fee estimation is broken, ZeroMQ tx-notify is
broken, RBF detection is broken, rebroadcast is broken.

P0 — silent + chain-impacting + violates the basic BIP-133 contract
that the value reflects OUR actual policy.

### BUG-19 (G24, P3, BIP-133) — No `filterToSend != peer.m_fee_filter_sent` short-circuit

**File:** `src/peer.lua:758` (no state, always sends).
**Core:** `net_processing.cpp:5568-5571`.

Moot until BUG-15 lands.

### BUG-20 (G25, P2, BIP-133) — No MAX_FEEFILTER_CHANGE_DELAY bring-forward on substantial change

**File:** `src/peer.lua:758`.
**Core:** `net_processing.cpp:5574-5579`:

```cpp
// If the fee filter has changed substantially and it's still more than
// MAX_FEEFILTER_CHANGE_DELAY until scheduled broadcast, then move the
// broadcast to within MAX_FEEFILTER_CHANGE_DELAY.
else if (current_time + MAX_FEEFILTER_CHANGE_DELAY < peer.m_next_send_feefilter &&
            (currentFilter < 3 * peer.m_fee_filter_sent / 4 ||
             currentFilter > 4 * peer.m_fee_filter_sent / 3)) {
    peer.m_next_send_feefilter = current_time + m_rng.randrange<...>(MAX_FEEFILTER_CHANGE_DELAY);
}
```

`MAX_FEEFILTER_CHANGE_DELAY = 5min`. Moot until BUG-15 lands.

### BUG-21 (G26, P0, BIP-133) — Outbound tx-inv filter NOT consulted (`p.fee_filter` is inert)

**File:** `src/peerman.lua:2075-2106` (`queue_tx_announcement`):

```lua
function PeerManager:queue_tx_announcement(txid, wtxid, tx)
  ...
  for _, p in ipairs(self.peer_list) do
    if p.state == peer_mod.STATE.ESTABLISHED then
      ...
      if p.bloom_filter ~= nil and tx ~= nil then
        ...
      end
      -- Use wtxid for peers that negotiated wtxidrelay (BIP 339)
      local hash = p.wtxid_relay and wtxid or txid
      local is_wtxid = p.wtxid_relay
      if not trickle.inv_known[hash] then
        trickle.inv_queue[#trickle.inv_queue + 1] = {hash = hash, is_wtxid = is_wtxid}
      end
      ...
```

No `p.fee_filter` check anywhere.

**Core:** `net_processing.cpp:6013` (mempool-respond path) and
`net_processing.cpp:6071` (trickle path):

```cpp
// Peer told you to not send transactions at that feerate? Don't bother sending it.
if (txinfo.fee < filterrate.GetFee(txinfo.vsize)) {
    continue;
}
```

Practical effect: when a peer sends us FEEFILTER N, they're telling us
"don't send me any tx with effective feerate below N sat/kvB". Core
honors. lunarblock IGNORES — every inv goes out regardless. The peer
will then either:
- spend bandwidth ignoring the inv (best case), or
- request the tx via getdata (we send a useless tx they reject), or
- downscore us (some Core forks track this).

P0 — protocol-visible, wastes bandwidth on every peer link, and
silently undoes the whole point of BIP-133.

### BUG-22 (G28, P0, BIP-339) — GETDATA does not serve MSG_WTX (=5)

**File:** `src/main.lua:1666-1746` (`peer_manager:register_handler("getdata", ...)`):

```lua
for _, item in ipairs(items) do
  if item.type == p2p.INV_TYPE.MSG_WITNESS_TX or item.type == p2p.INV_TYPE.MSG_TX then
    ...
  elseif item.type == p2p.INV_TYPE.MSG_BLOCK or item.type == p2p.INV_TYPE.MSG_WITNESS_BLOCK then
    ...
  elseif item.type == p2p.INV_TYPE.MSG_FILTERED_BLOCK then
    ...
  end
  -- MSG_WTX (=5) silently dropped here
end
```

**Core:** `net_processing.cpp:2530` `it->IsGenTxMsg()` accepts MSG_TX,
MSG_WTX, MSG_WITNESS_TX (and the MSG_FILTERED_BLOCK is handled
separately). All three TX-class inv types resolve to the same
`FindTxForGetData` lookup; only the serialization changes
(`maybe_with_witness = inv.IsMsgTx() ? TX_NO_WITNESS : TX_WITH_WITNESS`).

Practical consequence:
- We send a peer `inv` with MSG_WTX (via `queue_tx_announcement` when
  `p.wtxid_relay == true`).
- Peer asks for the tx with `getdata` MSG_WTX (=5).
- lunarblock's handler falls through silently.
- Peer never receives the tx, eventually times out.

Compounds the BUG-6 problem: even if WTXIDRELAY were sent and a peer
opted into wtxid relay, the actual tx-serving path is broken.

P0 — every wtxid-relay-mode tx interaction is broken; only MSG_TX
fallback works.

### BUG-23 (G30, P3, DOCS) — Stale-compliance comments

**File:** `src/peer.lua:99-106` (PRE_HANDSHAKE_ALLOWED claims BIP-130 /
BIP-339 / BIP-155 / BIP-330 all "compliant"), `src/peer.lua:756-758`
(comment "100 sat/vB = 100000 sat/kvB" treats the value as canonical),
`src/peer.lua:694` ("BEFORE verack (BIP155, BIP330, BIP339)" lists
BIP-339 that the body doesn't implement).

Future-reader hazard. Every line either lies (BIP-339) or papers over
a divergence (the 100000 hardcode looks intentional).

## Universal patterns observed

1. **Half-wired feature gate** — the receiver path of a feature (here,
   `peer.wtxid_relay`, `peer.fee_filter`) is wired into the dispatch
   loop and stored as a Peer field, but the consumer paths
   (`queue_tx_announcement`, `getdata` handler) don't consult the
   stored value. **BUG-21** (fee_filter inert) and **BUG-22** (wtxid
   relay incomplete) are both this pattern. Same pattern as W121
   BIP-157 wiring (FIX-71 plumbed the gate FALSE because the
   consumers weren't there).
2. **"Comment-as-confession"** — peer.lua:99-106 lists BIP-130 / 339
   / 155 / 330 as compliant in PRE_HANDSHAKE_ALLOWED, but the BIP-339
   path is never exercised. Same shape as W120 BUG-5 FullRBF and
   W122's blockbrew "test-comment-as-confession": prose that
   rationalizes a missing implementation. **BUG-23**.
3. **"Comment lies about scope" → cross-BIP audit risk** — peer.lua:694
   says "BIP155, BIP330, BIP339" but body sends 155 + 330 only. Any
   future audit reading only the comment block would conclude BIP-339
   is wired. Promotes the audit-framework lesson from W122: never
   trust the comment, grep for the actual `send_message` call.
4. **One-shot vs periodic broadcast** — feefilter is the canonical
   example here, but the pattern (state-setting message sent once at
   handshake then never re-evaluated) also applies to sendcmpct
   (W126) and sendaddrv2 (W117). lunarblock's
   `Peer:check_timeouts()` is the natural place to add a periodic
   evaluator.
5. **Hardcoded literal vs derived value** — `serialize_feefilter(100000)`
   is the bug pattern: instead of computing from
   `mempool.min_relay_feerate`, the value is frozen. Once the actual
   policy diverges from the literal (which it always does at runtime),
   the protocol message lies. Same shape as the lunarblock
   chainparams literals (well-trodden) and blockbrew's
   blockfilters.json deferral (W122).

## Out-of-scope (deferred)

- sendcmpct/BIP-152 (W126 already audited).
- sendaddrv2 / BIP-155 disconnect contract (W117 already audited, but
  BUG-5 here shows the same gap exists for sendaddrv2 post-VERACK).
- sendtxrcncl/BIP-330 (Erlay — separate wave).
- ProcessHeadersMessage and headers-sync state machine (W117 / W126).
- INVENTORY_BROADCAST_TARGET / INVENTORY_BROADCAST_MAX trickle limits
  (mempool / trickle wave).
- Sub-feerate orphan-parent-fetch (gate G29 noted but not audited).

## Test plan

`tests/test_w136_relay_flags.lua` lands 30 gate tests; 21 are
`test_xfail_pre_fix` (one per BUG-N), 9 are forward-regression /
present-state assertions. Expected outcome pre-fix:

- PASS: 9 (G5, G6, G7, G13, G27 + 4 source-grep assertions)
- XFAIL: 21 (one per bug)
- FAIL: 0

After a future BUG-N fix lands, the corresponding xfail flips to PASS
("[now PASSing -- BUG-N fix likely landed]") and the assertion logic
in the test catches the regression direction (e.g. G9 asserts
`peer.lua:handle_version` does call `send_message("wtxidrelay", ...)`
inside the post-VERSION pre-VERACK block).
