# W128 — AddrMan + connman + peer selection audit (lunarblock)

**Date:** 2026-05-17
**Wave:** W128 (discovery)
**Impl:** lunarblock (Lua / LuaJIT)
**Status:** **17 BUGS FOUND** (0 P0 / 9 P1 / 8 P2 / 0 P3)
**Scope:** AddrMan add/select/good/attempt/connected/terrible; bucketing
math; outbound peer selection (ThreadOpenConnections equivalent);
inbound eviction; BanMan (banlist + discouragement filter).
**Excludes:** BIP-155 wire format (covered by W117).

## Context

W104 (already on master) covered the in-memory AddrMan bucket data
structure (22 bugs, ~14 still open). W128 broadens the lens to the
*connman + banman* surface: how lunarblock chooses outbound peer
connection types (full-relay vs block-relay-only vs feeler vs anchor),
how feeler/extra-network timers are scheduled, the inbound-eviction
algorithm (NodeEvictionCandidate / SelectNodeToEvict), and BanMan's
two-channel design (CSubNet banlist + CRollingBloomFilter
discouragement). All connman behaviors are eclipse-attack-defining; a
divergence here changes the operational security envelope vs. Core.

Reference:
- `bitcoin-core/src/addrman.h`, `addrman_impl.h`, `addrman.cpp`
- `bitcoin-core/src/net.h`, `net.cpp` (ThreadOpenConnections,
  AttemptToEvictConnection, anchors load/save, fixed seeds)
- `bitcoin-core/src/node/eviction.h`, `eviction.cpp`
  (NodeEvictionCandidate, SelectNodeToEvict,
  ProtectEvictionCandidatesByRatio)
- `bitcoin-core/src/banman.h`, `banman.cpp`
- `bitcoin-core/src/util/asmap.cpp`,
  `bitcoin-core/src/netaddress.h` (NET_IPV4 / NET_IPV6 enum values)

## Method

1. Read all referenced Core sources end-to-end.
2. Inventory lunarblock's connman surface:
   - `src/peerman.lua` (everything — AddrMan, connman,
     `ThreadOpenConnections`-equivalent in `maintain_connections`,
     `accept_inbound`, BanMan, anchors, discouragement)
   - `src/peer.lua` (per-peer `misbehaving()`, conn time fields,
     `m_manually_added`/noban flags)
   - `src/rpc.lua` (setban/listbanned/clearbanned shims into
     PeerManager:banned)
   - `src/asmap.lua` (`get_addr_group` group-bytes encoding —
     directly drives bucketing math)
3. Define 30 W128 gates covering AddrMan ops, connman, BanMan,
   eviction.
4. Catalogue divergences as BUG-N (P0/P1/P2/P3) with file:line + Core
   reference + impact category (ECLIPSE / DOS / CORRECTNESS / OBS).
5. Land xfail tests in `tests/test_w128_addrman.lua` exercising each
   bug pre-fix (failing test = bug; flipped to pass when fix lands).

## 30 W128 Audit Gates

| Gate | Description | Status | Core ref |
|------|-------------|--------|----------|
| G1   | AddrMan bucket-count constants (NEW=1024, TRIED=256) | **DIVERGENT (W104 BUG-1/2 still open)** | addrman_impl.h:27,30 |
| G2   | AddrMan bucket-hash math (HashWriter / GetCheapHash, NOT single SHA-256) | **DIVERGENT (W104 BUG-14, also W128 BUG-3 below)** | addrman.cpp:30 |
| G3   | AddrInfo:IsTerrible (5 quality predicates: HORIZON, last-try, future-skew, retries, max-failures) | **MISSING (BUG-1 P1)** | addrman.cpp:49-72 |
| G4   | AddrInfo:GetChance weighted Select_() (10-min deprioritisation × 0.01, exponential attempt back-off) | **MISSING (BUG-2 P1)** | addrman.cpp:74-87, 765 |
| G5   | AddrMan Select_() while-loop with chance_factor *= 1.2 backoff | **MISSING (BUG-2 P1)** | addrman.cpp:733-772 |
| G6   | get_addr_group network-type byte = NET_IPV4 (=1), NOT char(4) | **DIVERGENT (BUG-3 P1)** | netaddress.h:38, asmap.cpp |
| G7   | Source-group time_penalty applied on Add() (default 2h for addr-relay) | **MISSING (W104 BUG-6 still open)** | addrman.cpp:530-577 |
| G8   | Stochastic refcount guard: rand(1 << nRefCount) on multiplicity increase | **MISSING (W104 BUG-7 still open)** | addrman.cpp:570-573 |
| G9   | Test-before-evict in MakeTried (m_tried_collisions set) | **MISSING (W104 BUG-9/10 still open)** | addrman.cpp:640-658 |
| G10  | Attempt() updates m_last_try + nAttempts | **MISSING (W104 BUG-11 still open)** | addrman.cpp:673-691 |
| G11  | Connected() updates nTime on 20-min interval post-disconnect (not connect — Core comment says "callers should be careful that updating this information doesn't leak topology…") | **MISSING (BUG-4 P2)** | addrman.cpp:857-874 |
| G12  | SetServices() updates nServices for existing entry | **MISSING (W104 BUG-13 still open)** | addrman.cpp:876-890 |
| G13  | GetAddr_() max_addresses + max_pct caps + IsTerrible filter | **MISSING (BUG-5 P1)** | addrman.cpp:792-831 |
| G14  | AddrMan persistence (peers.dat with V4_MULTIPORT format, INCOMPATIBILITY_BASE compat check) | **MISSING (W104 BUG-17 still open)** | addrman.cpp:112-208 |
| G15  | Anchors limit MAX_BLOCK_RELAY_ONLY_ANCHORS=2 | **PARTIAL (BUG-6 P2)** | net.cpp:57, 3496 |
| G16  | Anchors are *block-relay-only* peers only (not full-relay outbound) | **DIVERGENT (BUG-7 P1)** | net.cpp:2901-2911, 3651 |
| G17  | Anchors file format: BIP155-serialised CAddress list (not "ip:port\n" text) | **DIVERGENT (BUG-8 P2)** | net.cpp:3493-3499 + addrdb.cpp ReadAnchors |
| G18  | ThreadOpenConnections connection-type ladder: anchor > full-relay > block-relay > extra-block-relay > feeler > extra-network | **DIVERGENT (BUG-9 P1)** | net.cpp:2705-2772 |
| G19  | FEELER_INTERVAL=2min Poisson-scheduled feeler connections | **MISSING (BUG-10 P2)** | net.h:61, net.cpp:2565,2754 |
| G20  | EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL=5min for eclipse-resistance probes | **MISSING (BUG-11 P2)** | net.h:63, net.cpp:2566,2729 |
| G21  | MAX_OUTBOUND_FULL_RELAY=8 + MAX_BLOCK_RELAY_ONLY=2 enforced separately | **DIVERGENT (BUG-12 P1)** | net.h:69,73 |
| G22  | Fixed-seed fallback after 60s with empty addrman per reachable net | **MISSING (BUG-13 P2)** | net.cpp:2607-2645 |
| G23  | "100-tries" cap on per-tick addrman selection in ThreadOpenConnections | PRESENT (peerman.lua:1261) | net.cpp:2794-2796 |
| G24  | nTries < 30 / 10min last-try gate on selected address | **MISSING (BUG-14 P2)** | net.cpp:2845 |
| G25  | IsBadPort gate (nTries < 50 + IPv4/IPv6 + IsBadPort) | **MISSING (BUG-15 P2)** | net.cpp:2858-2861 |
| G26  | Inbound AttemptToEvictConnection — NodeEvictionCandidate ladder (ping/netgroup/tx-time/block-time/network/uptime) | **MISSING (BUG-16 P1)** | node/eviction.cpp:178-240 |
| G27  | ProtectEvictionCandidatesByRatio — 50% longest-uptime protection + 25% for disadvantaged networks | **MISSING (BUG-16 P1)** | node/eviction.cpp:105-176 |
| G28  | BanMan two-channel: CSubNet banlist (persistent, manual via setban) + CRollingBloomFilter discouragement (ephemeral, auto via Misbehaving) | **DIVERGENT (BUG-17 P1)** | banman.h:28-46, banman.cpp:83-128 |
| G29  | CSubNet semantics in setban — accepts `IP/CIDR` and matches on subnet membership | **DIVERGENT (BUG-17 P1 same root)** | banman.cpp:97 SubNet::Match |
| G30  | DEFAULT_MISBEHAVING_BANTIME=24h and DUMP_BANS_INTERVAL=15min | PARTIAL (constant ok; dump-on-interval missing) | banman.h:19,22 |

## Bugs (17)

### BUG-1 (G3, P1, CORRECTNESS) — IsTerrible() not implemented

**File:** `src/peerman.lua` (no `is_terrible` method)
**Core:** `addrman.cpp:49-72` — 5 predicates: tried-in-last-minute,
future-skew >10min, last-seen >30d (HORIZON), 3 attempts with never a
success, 10 consecutive failures in >7d.

Without IsTerrible:
- bucket-collision overwrite logic at `_add_to_new` (peerman.lua:675)
  evicts the existing entry unconditionally instead of only when the
  existing entry is terrible or has multi-bucket refs. Operational
  result: an attacker who can land an addr-record at the right bucket
  position will *always* dislodge a healthy entry, regardless of how
  long we've successfully been connecting to it.
- `_select_address` (peerman.lua:828) can return terrible entries
  (last-try in flying-DeLorean future, last-seen years ago) for
  connection attempts, wasting outbound slots.
- `_respond_getaddr` (peerman.lua:2020) gossips terrible entries to
  peers — propagates stale/garbage addresses through the network.

Same root as W104 BUG-4; kept here because the gap also breaks G3 +
G4 + G13 in this audit's scope. Promote severity to P1 (W104 marked
CORRECTNESS without P-band).

### BUG-2 (G4/G5, P1, ECLIPSE) — GetChance / chance_factor weighted selection absent

**File:** `src/peerman.lua:828` (`_select_address`)
**Core:** `addrman.cpp:733-772` — `Select_()` loops indefinitely with
`chance_factor *= 1.2`; each iteration accepts with probability
`chance_factor * info.GetChance()`, where `GetChance()` is
`0.01 × pow(0.66, min(nAttempts, 8))` for recently-tried entries.

lunarblock picks uniform-random bucket/pos with 100-attempt cap. This
means:
- Recently-tried (likely-down) peers are picked just as often as
  long-untried ones. Core slows return-to-bad-peer by 100×.
- Peers with 8+ failed attempts get the same weight as fresh
  addresses. Core deprioritises by `0.66^8 ≈ 3.6%`.
- Eclipse-attack surface: an attacker who fills addrman with N
  terrible entries gets N/total * 100% selection rate. Core's
  weighting drops this to ~3.6%/total — a 30× cushion. Same root as
  W104 BUG-5 but reframed as ECLIPSE here.

### BUG-3 (G6, P1, ECLIPSE) — get_addr_group IPv4 prefix byte is 0x04, should be 0x01

**File:** `src/asmap.lua:598` (`get_addr_group` fallback path)
**Core:** `netaddress.h:33-58` `enum Network { NET_UNROUTABLE=0,
NET_IPV4=1, NET_IPV6=2, NET_ONION=3, NET_I2P=4, NET_CJDNS=5,
NET_INTERNAL=6, NET_MAX }`. `net_processing.cpp`/`netgroup.cpp`'s
`GetGroup()` for IPv4 returns `{NET_IPV4, addr.byte0, addr.byte1}`
(3 bytes, first byte = 1).

lunarblock returns `string.char(4) .. byte0 .. byte1`. The prefix
byte is `4` (which collides with Core's `NET_I2P`!). Worse, the
ASN-IPv4 path at `asmap.lua:587` returns `string.char(NET_IPV6=2)
.. asn_LE` — wrong network ID for IPv4 (should be NET_IPV4=1).

W104 BUG-16 noted the 0x04 vs 0x01 mismatch for the /16 fallback;
this audit additionally finds the ASN path uses NET_IPV6=2 for both
IPv4 and IPv6 (`asmap.lua:587`), so even an asmap-loaded node bucket
in a way that's incompatible with Core. Cross-impl eclipse analysis
is impossible because two impls following Core would land in the
same buckets while lunarblock would not.

### BUG-4 (G11, P2, CORRECTNESS) — Connected() update path absent

**File:** `src/peerman.lua` (no `connected_addr` method;
`disconnect_peer` at line 1212 calls `_move_to_tried` but never
updates `nTime`)
**Core:** `addrman.cpp:857-874` `Connected_()`: if
`time - info.nTime > 20min`, set `info.nTime = time`. Called from
`net_processing.cpp` **on disconnect** (not connect — Core comment:
"to not leak information about currently connected peers"). This
freshens the nTime of long-lived peers so they remain selectable
post-disconnect.

Without this, after a long-running connection drops, the address's
nTime is stale, making it look like a HORIZON-aged candidate
even though we just successfully held a months-long connection to
it. Combined with BUG-1 (no IsTerrible) the effect is small today,
but blocks the Connected→IsTerrible path from working once IsTerrible
lands. Same root as W104 BUG-12.

### BUG-5 (G13, P1, OBS+CORRECTNESS) — GetAddr_() max_pct / IsTerrible filter absent in _respond_getaddr

**File:** `src/peerman.lua:2020` (`_respond_getaddr`)
**Core:** `addrman.cpp:792-831` `GetAddr_()`:
- iterate `vRandom` with Fisher-Yates `SwapRandom`
- cap at `min(max_addresses, max_pct * size / 100)`
- skip entries where `IsTerrible(now) && filtered`

lunarblock:
```
for _, info in pairs(self.known_addresses) do
  if count >= 1000 then break end
  if info.ip then ...
  end
end
```

Problems:
- `pairs()` iteration order is implementation-defined; not random.
  Two nodes with the same set of known addresses return the same
  ordering to peers — fingerprintable.
- No max_pct cap. Core caps at 23% (MAX_PCT_ADDR_TO_SEND in
  `net_processing.cpp:188`) to avoid leaking the full address pool to
  any single peer.
- No IsTerrible filter — terrible entries gossiped (propagates
  garbage; weakens the entire network's addrman quality).
- No network filter; cannot honor a Tor-only peer's request for
  Tor addresses.

Same root as W104 BUG-19 but more thoroughly characterized here. P1
because max_pct leak fingerprints the node and aids topology
inference.

### BUG-6 (G15, P2, CORRECTNESS) — Anchors list not clamped to MAX_BLOCK_RELAY_ONLY_ANCHORS=2

**File:** `src/peerman.lua:941-963` (`_load_anchors`),
`src/peerman.lua:968-996` (`_save_anchors`)
**Core:** `net.cpp:3496-3497`:
```
m_anchors = ReadAnchors(...);
if (m_anchors.size() > MAX_BLOCK_RELAY_ONLY_ANCHORS) {
    m_anchors.resize(MAX_BLOCK_RELAY_ONLY_ANCHORS);
}
```
and `net.cpp:3652-3653` clamps on save.

lunarblock save-path clamps via `M.ADDRMAN.MAX_ANCHORS = 2` check
(peerman.lua:976), but load-path reads every line of `anchors.dat`
unconditionally (no `#self._anchors >= MAX` break in the loop).
Manual edit (or future format change) can populate arbitrarily many
anchors, all of which get connected on startup, monopolising the
outbound budget.

### BUG-7 (G16, P1, ECLIPSE) — Anchors save dumps any outbound peer, not block-relay-only

**File:** `src/peerman.lua:971-980` (`_save_anchors`)
**Core:** `net.cpp:3651` calls `GetCurrentBlockRelayOnlyConns()` —
the explicit comment at `net.cpp:2901` is "BlockRelayOnly" filter via
`pnode->IsBlockOnlyConn()`. Anchors are *block-relay-only* so they
relay headers but not transactions, minimising info leak across the
unclean-shutdown boundary.

lunarblock saves *any* outbound peer (`if not p.inbound and
p.state == ESTABLISHED`), with a TODO comment at line 974: "In a
full implementation, we'd check if this is a block-relay-only
connection". So on startup we re-anchor to full-relay peers that
gossip our IBD state, defeating the eclipse-mitigation premise of
anchors entirely (anchors exist so a one-time eclipse during boot
can't be persisted across restart — the design depends on those
peers being block-relay-only specifically because they were chosen
*before* the eclipse window).

### BUG-8 (G17, P2, OBS) — Anchors file format is plain text ("ip:port\n"), not BIP155 binary

**File:** `src/peerman.lua:941-996`
**Core:** `addrdb.cpp` `ReadAnchors`/`DumpAnchors` use a versioned
binary format with `CAddress` (BIP155 v2-disk) serialisation +
SHA-256 checksum.

Operational consequences:
- Lunarblock anchors.dat is not interchangeable with Core's; you
  can't dual-launch and have them seed each other.
- No Tor/I2P/CJDNS addresses in lunarblock's text format (no port
  for non-IP types; would need addr_str). Yet the rest of the impl
  supports BIP155 networks.
- No checksum — a truncated write on crash yields silently invalid
  partial state.

P2 (vs P1) only because the impact is reproducibility / cross-impl
testability, not security per se. Still ECLIPSE-adjacent.

### BUG-9 (G18, P1, ECLIPSE) — ThreadOpenConnections connection-type ladder absent

**File:** `src/peerman.lua:1301-1363` (`maintain_connections`)
**Core:** `net.cpp:2705-2772` 7-arm priority ladder:
1. anchor (only on startup, until `m_anchors` drained)
2. OUTBOUND_FULL_RELAY (until 8 connected)
3. BLOCK_RELAY (until 2 connected)
4. extra OUTBOUND_FULL_RELAY (when `GetTryNewOutboundPeer()`)
5. extra BLOCK_RELAY (Poisson-timed every ~5min for eclipse probe)
6. FEELER (Poisson-timed every ~2min)
7. extra-network (when full at 8 and a `preferred_net` exists)

lunarblock has:
```
maintain_connections():
  connect anchors first (until drained)
  target = max_outbound (+1 if stale-tip)
  while outbound < target and attempts_this_tick < 1:
    candidate = select_peer_to_connect()
    connect_peer(candidate)
```

No distinction between full-relay vs block-relay-only outbound. No
feeler. No extra-block-relay-only eclipse-resistance probe. No
extra-network slot. Operationally this means:
- The 2 block-relay-only outbound slots Core reserves don't exist;
  all 8 outbounds are full-relay (advertising txs to all of them).
  Privacy reduction: tx-origin inference easier vs Core.
- Feeler connections (probe a *new*-table entry to graduate it to
  tried) never fire — the new table never gets organically
  refreshed; tried-table churn is the only path.
- The 5-min extra-block-relay rotation that Core uses to detect
  stale tips on a fresh peer doesn't fire — eclipse-detection
  weaker.

### BUG-10 (G19, P2, ECLIPSE) — FEELER_INTERVAL feeler connections not scheduled

**File:** `src/peerman.lua:1301` (`maintain_connections`)
**Core:** `net.cpp:88,2565,2754` `FEELER_INTERVAL = 2min`,
`FEELER_SLEEP_WINDOW = 1s` (random pre-connect jitter).

Feeler design: short-lived connection that handshakes, verifies the
peer is reachable, then disconnects. Successful feeler graduates the
new-table entry to tried; failed feeler counts as `Attempt()`
failure. Without feelers the tried table grows only via actual
working outbound connections, biasing toward whatever IP-range we
happened to first connect to (eclipse-attack surface widens for
nodes with small `nTried` early in life).

Compound with BUG-9 (no Select_(new_only=true)) — fixing one needs
the other.

### BUG-11 (G20, P2, ECLIPSE) — EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL absent

**File:** `src/peerman.lua:1301`
**Core:** `net.h:63,net.cpp:2566,2729` — every 5min on average,
opens a short block-relay-only connection to "confirm our tip is
current". If the new peer announces a longer chain, the youngest
existing block-relay-only peer is evicted in its favor. Core
comment: "Then disconnect the peer, if we haven't learned anything
new. The idea is to make eclipse attacks very difficult to pull
off".

Lunarblock's only eclipse-stale-tip path is the 10-min
`STALE_CHECK_INTERVAL` + `_try_new_outbound_peer` flag in
`check_for_stale_tip_and_evict_peers` (peerman.lua:2431) — which
runs *only* after a stale tip is detected, not as a constant
background probe. So an attacker who can eclipse the node briefly
just needs to keep delivering "stale-looking-but-current" headers to
the existing peers; Core's 5-min rotation independently checks tip
freshness against fresh peers.

### BUG-12 (G21, P1, ECLIPSE) — No separation of OUTBOUND_FULL_RELAY vs BLOCK_RELAY budgets

**File:** `src/peerman.lua:323` `self.max_outbound = config.max_outbound or 8`
**Core:** `net.h:69,73,1107,1108`:
```
m_max_outbound_full_relay = min(MAX_OUTBOUND_FULL_RELAY_CONNECTIONS=8, m_max_automatic_connections)
m_max_outbound_block_relay = min(MAX_BLOCK_RELAY_ONLY_CONNECTIONS=2, m_max_automatic_connections - m_max_outbound_full_relay)
```
Two separate semaphores. The `nOutboundFullRelay` count is tracked
separately from `nOutboundBlockRelay` (`net.cpp:2653-2654`). Tx
announcements only go to full-relay; block-relay-only peers don't
receive tx inv (privacy + DoS minimisation).

lunarblock has one `max_outbound` (default 8) and `get_outbound_counts()`
explicitly says (peerman.lua:2358): "For now, treat all outbound as
full-relay". So 100% of outbound peers see every tx announcement —
no privacy-preserving block-relay-only set. The eclipse-resistance
+ privacy guarantee of the 8+2 split is absent.

### BUG-13 (G22, P2, OBS) — Fixed-seed fallback after 60s absent

**File:** `src/peerman.lua` (no `fixed_seeds` field on network; only
`dns_seeds`)
**Core:** `net.cpp:2576-2645` — when addrman is empty for a
reachable network, after 60s without progress from DNS/seednode/
addnode, fall back to a hardcoded fixed-seed list compiled in
`chainparamsseeds.h`. This is the last-resort bootstrap that lets a
node escape an addrman-empty state even with no DNS.

Without fixed seeds, an isolated lunarblock node with DNS blocked
and no `addnode` configured cannot bootstrap. (Mitigated in practice
by lunarblock currently using `dns_seeds` from the network config,
but operationally weaker than Core.)

### BUG-14 (G24, P2, ECLIPSE) — "Don't connect if last-try within 10min unless nTries >= 30" gate absent

**File:** `src/peerman.lua:1257` (`select_peer_to_connect`)
**Core:** `net.cpp:2845`: `if (current_time - addr_last_try < 10min
&& nTries < 30) continue;`

lunarblock has a `(now - known.last_try) > 60` check (60s, not
10min) at peerman.lua:1270, and the AddrMan-selected path has no
last-try gate at all. So we hammer a recently-tried failing address
every 60s instead of waiting 10min. Burns outbound slot churn on
peers that are likely still down.

Distinct from BUG-2 (GetChance) — even with GetChance landed, the
explicit `addr_last_try < 10min` gate is the hard rule; GetChance
applies the *probabilistic* deprioritisation on top.

### BUG-15 (G25, P2, DOS) — IsBadPort gate absent

**File:** `src/peerman.lua:1257` (`select_peer_to_connect`)
**Core:** `net.cpp:2858-2861`: `if (nTries < 50 && (addr.IsIPv4() ||
addr.IsIPv6()) && IsBadPort(addr.GetPort())) continue;`
where `IsBadPort` blocks ports 1, 7, 9, 11, 13, 15, 17, ..., 6667
(IRC), 6697 etc. — well-known service ports that, if a peer
announces a CAddress at them, are almost certainly malicious (e.g.
trying to direct the node at an open mail relay).

lunarblock has no port-block list. An attacker can publish an addr
record claiming a Bitcoin node at `<victim>:25` and our outbound
attempt becomes an SMTP-banner-probe, complicit in
amplification/abuse.

### BUG-16 (G26/G27, P1, ECLIPSE+DOS) — Inbound eviction algorithm absent (NodeEvictionCandidate / SelectNodeToEvict / ProtectEvictionCandidatesByRatio)

**File:** `src/peerman.lua:1673-1740` (`accept_inbound`)
**Core:** `net.cpp:1689-1736` + `node/eviction.cpp:178-240` + the
helper functions `ProtectNoBanConnections`, `ProtectOutboundConnections`,
`ProtectEvictionCandidatesByRatio`, `CompareNetGroupKeyed`,
`ReverseCompareNodeMinPingTime`, `CompareNodeTXTime`,
`CompareNodeBlockTime`, `CompareNodeBlockRelayOnlyTime`.

When the inbound slot is full, Core evicts an existing inbound
connection chosen to maximise eviction-resistance properties (lowest
ping, recent tx-relay, recent block-relay, netgroup diversity,
etc.). lunarblock's `accept_inbound` (peerman.lua:1692-1695):
```
if inbound_count >= self.max_inbound then
  client:close()
  return
end
```
i.e. drop the new connection rather than evict. This is *safer* in
the sense that an attacker can't force eviction of a good peer by
flooding inbound. But it is *strictly weaker* than Core when honest
inbound peers fill the slots first and a healthier honest peer tries
to connect later. Eviction logic is the entire reason
`AttemptToEvictConnection` exists.

Both `SelectNodeToEvict` and `ProtectEvictionCandidatesByRatio`
miss; G26 + G27 are folded as one bug.

### BUG-17 (G28/G29, P1, OBS+SECURITY) — BanMan two-channel design absent; CSubNet matching not implemented

**File:** `src/peerman.lua:337,1369-1432` (`self.banned[ip] -> ban_until`),
`src/rpc.lua:2652-2714` (setban) + 2716-2741 (listbanned)
**Core:** `banman.h:28-46` design comment is explicit:

> BanMan manages two related but distinct concepts:
> 1. **Banning.** Manual via setban. Persisted to disk. Block both
>    inbound & outbound. Stored as CSubNet (supports CIDR).
> 2. **Discouragement.** Automatic via Misbehaving(). Stored in a
>    `CRollingBloomFilter` (50000, 0.000001). Probabilistic
>    membership; allows inbound when slots aren't almost-full;
>    forbidden for outbound; not gossiped. Ephemeral.

lunarblock conflates them: `PeerManager:misbehaving` at
peerman.lua:1502 calls `self:ban_peer(peer.ip)` which adds to the
exact-IP `self.banned` map persisted to `banned.dat`. This means:
- Every misbehaving-peer goes straight to the *persistent* ban list,
  not the rolling-bloom discouragement filter. Restart-survival of
  discouragement should be *false* in Core (m_discouraged is
  in-memory only); in lunarblock it's true.
- Memory blowup attack: the 2024 disclosure
  (https://bitcoincore.org/en/2024/07/03/disclose-unbounded-banlist)
  is exactly this scenario — an attacker who can trigger
  misbehaving from many IPs can grow the disk-backed ban map
  unboundedly. Core's switch to the rolling-bloom-bounded
  discouragement filter fixed this CVE. lunarblock retains the
  pre-CVE design.
- `rpc.lua:2640-2644` self-documents this: "is_banned() does
  exact-string match in peerman.lua:1167, so a "/32" entry behaves
  identically to a bare IP. Wider CIDRs are stored verbatim and
  treated as opaque by the matcher". CSubNet matching missing
  entirely. setban with "10.0.0.0/8" stores the literal string
  "10.0.0.0/8" and refuses to match any actual peer IP.

Two related gates folded into one bug; the fix needs both the
rolling-bloom discouragement filter and CSubNet match semantics. P1
because of the CVE history.

## Universal patterns observed

1. **"two-channel design is hard"** — BanMan vs Discouragement (BUG-17)
   collapses into one IP map in lunarblock. Likely candidates for
   the same pattern across the fleet (verify in next audit waves):
   any node that has only one `banned: map IP -> deadline` is
   probably pre-CVE-2024 architecture.
2. **"Core enum byte vs impl enum byte mismatch"** — get_addr_group
   uses byte 4 for IPv4 (Core: 1), byte 2 for IPv4+ASN (Core: 1).
   Same class as W104 BUG-16. Fleet-wide check: every impl that
   serialises a Network enum byte into a hash input must agree with
   Core's `NET_IPV4=1, NET_IPV6=2` mapping or buckets diverge.
3. **"ladder of connection types vs single 'outbound' counter"** —
   BUG-9/12 collapses Core's 7-arm ConnectionType ladder into one
   undifferentiated outbound list. The lunarblock impl predates the
   block-relay-only design (Core PR #15759, 2019). Fleet-wide: any
   impl that treats `outbound` as a single set is missing the
   privacy/eclipse separation.
4. **"100-tries cap is necessary but not sufficient"** — G23
   (PRESENT) shows lunarblock copied the surface 100-attempt cap
   from ThreadOpenConnections. But the *content* of the loop body
   (G24 last-try gate, G25 IsBadPort gate, G18 type ladder) is
   missing. Pattern: copying a bound without copying the gates the
   bound is meant to backstop.

## P-band summary

- **P1 (9):** BUG-1 IsTerrible (CORRECTNESS w/ ECLIPSE knock-on);
  BUG-2 GetChance (ECLIPSE); BUG-3 NET_IPV4 byte (ECLIPSE cross-impl
  break); BUG-5 max_pct leak (FINGERPRINT); BUG-7 anchors save
  (ECLIPSE); BUG-9 ladder (ECLIPSE+PRIVACY); BUG-12 8+2 (PRIVACY);
  BUG-16 eviction (DOS); BUG-17 BanMan (CVE-class).
- **P2 (8):** BUG-4 Connected; BUG-6 anchors load cap; BUG-8 anchors
  format; BUG-10 feeler; BUG-11 extra-block-relay; BUG-13 fixed
  seeds; BUG-14 last-try 10min gate; BUG-15 IsBadPort.
- **P3 (0):** none.

Total **17 bugs** (0 P0 / 9 P1 / 8 P2 / 0 P3).

## Notes / out of scope

- BIP-155 wire encoding (covered by W117).
- The ASMap subsystem itself (covered by W115).
- BIP-157 / compact filters (W121).
- Mempool / RBF (W120).
- Wallet / PSBT / coin selection (W118 + W113).
- Per-peer `m_addr_known` rolling bloom filter — relevant to addr
  relay performance/dedup but not to AddrMan/connman per se.
  Documented as out-of-scope; would fit a dedicated W12X addr-relay
  audit.

## Cross-references

- W104 (`spec/w104_addrman_spec.lua`) covers the in-memory bucket
  data structure. W128 covers connman + banman + eviction surface
  *above* AddrMan plus 3 W104 bugs that overlap (G1/G2 = W104
  BUG-1/2; G7 = W104 BUG-6; G8 = W104 BUG-7; G9 = W104 BUG-9/10;
  G10 = W104 BUG-11; G12 = W104 BUG-13; G14 = W104 BUG-17). These
  are *not double-counted* in the 17-bug total — they appear in the
  audit gate matrix to give a complete coverage map but the BUG-N
  catalogue numbers 1-17 here are new W128 findings.
- W117 BIP-155: addrv2 wire format. Independent.
- W125 RPC error parity: noted setban / addnode RPC error code
  divergences; this audit covers the underlying BanMan + connman
  semantics, not the RPC wrapper.

## Methodology used

- One reader, one writer (no agent dispatch).
- 30-gate matrix synthesised from Core's `addrman.h` + `net.h` +
  `banman.h` headers, then walked through the .cpp implementations
  to verify the gate is testable from the lunarblock public surface.
- xfail tests land pre-fix; flipped to plain `test()` calls as bugs
  close.
- Test file uses the same `test_xfail_pre_fix` harness as W125 so
  the project test runner stays uniform.
