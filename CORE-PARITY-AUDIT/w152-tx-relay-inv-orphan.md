# W152 — Tx relay + inv batching + orphan handling (lunarblock)

**Wave:** W152 — `RelayTransaction`, `InitiateTxBroadcastToAll`,
`AddTxAnnouncement`, ProcessMessage `inv` + `tx` + `getdata` + `notfound`
handlers, SendMessages inv-batching loop (`m_tx_inventory_to_send` /
`m_next_inv_send_time` / `INVENTORY_BROADCAST_PER_SECOND` Poisson timer),
TxRequestTracker (`TXID_RELAY_DELAY` / `NONPREF_PEER_TX_DELAY` /
`OVERLOADED_PEER_TX_DELAY` / `GETDATA_TX_INTERVAL` / `MAX_PEER_TX_REQUEST_IN_FLIGHT`),
`MAX_PEER_TX_ANNOUNCEMENTS` per-peer announcement cap, `MSG_TX` /
`MSG_WTX` / `MSG_WITNESS_TX` dispatch (BIP-339), TxOrphanage
(`DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER`, `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE`,
`AddTx` / `AddAnnouncer` / `EraseTx` / `EraseForPeer` / `EraseForBlock`
/ `LimitOrphans` / `OrphanByParent`), `m_lazy_recent_rejects` /
`m_lazy_recent_confirmed_transactions` AlreadyHave filters,
`RejectIncomingTxs` IBD gate, `m_tx_inventory_known_filter` (per-peer
50000-entry bloom), BIP-133 feefilter consumption (`m_fee_filter_received`).

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/net_processing.cpp:126` — `MAX_INV_SZ = 50000`.
- `bitcoin-core/src/net_processing.cpp:128` — `MAX_GETDATA_SZ = 1000`
  (outgoing getdata batch cap; NOT enforced on incoming).
- `bitcoin-core/src/net_processing.cpp:165-178` —
  `INBOUND_INVENTORY_BROADCAST_INTERVAL=5s`,
  `OUTBOUND_INVENTORY_BROADCAST_INTERVAL=2s`,
  `INVENTORY_BROADCAST_PER_SECOND=14`,
  `INVENTORY_BROADCAST_TARGET = 14 * 5 = 70` (per-burst target for inbound),
  `INVENTORY_BROADCAST_MAX = 1000` (per-transmission cap),
  `static_assert(INVENTORY_BROADCAST_MAX <= MAX_PEER_TX_ANNOUNCEMENTS)`.
- `bitcoin-core/src/net_processing.cpp:4037-4090` — `ProcessMessage(INV)`:
  `MAX_INV_SZ` ban-score gate, BIP-339 cross-filter (drop `MSG_TX` if
  `peer.m_wtxid_relay`; drop `MSG_WTX` if NOT `wtxid_relay`),
  `RejectIncomingTxs(pfrom)` IBD/relay-disabled gate (disconnect),
  `AddKnownTx(peer, inv.hash)` populates `m_tx_inventory_known_filter`,
  `m_txdownloadman.AddTxAnnouncement(...)` enforces
  `MAX_PEER_TX_ANNOUNCEMENTS=5000` per-peer.
- `bitcoin-core/src/net_processing.cpp:2244-2266` —
  `InitiateTxBroadcastToAll`: skip peers whose
  `m_next_inv_send_time == 0s` (handshake-not-complete), insert into
  `m_tx_inventory_to_send` only if NOT in `m_tx_inventory_known_filter`.
- `bitcoin-core/src/net_processing.cpp:5969-6090` — SendMessages tx-inv
  loop: per-peer Poisson timer (`NextInvToInbounds` for inbound,
  `rand_exp_duration(OUTBOUND_INVENTORY_BROADCAST_INTERVAL)` for outbound,
  seeded from `m_network_key` for inbound privacy); `if (!m_relay_txs)
  m_tx_inventory_to_send.clear()`; per-tx
  `tx_relay->m_fee_filter_received` gate; flush-batch when
  `vInv.size() == MAX_INV_SZ`.
- `bitcoin-core/src/node/txdownloadman.h:24-38` —
  `MAX_PEER_TX_REQUEST_IN_FLIGHT=100`, `MAX_PEER_TX_ANNOUNCEMENTS=5000`,
  `TXID_RELAY_DELAY=2s`, `NONPREF_PEER_TX_DELAY=2s`,
  `OVERLOADED_PEER_TX_DELAY=2s`, `GETDATA_TX_INTERVAL=60s`.
- `bitcoin-core/src/node/txdownloadman_impl.cpp:200-280` — delay
  composition logic for tx-request: `delay += NONPREF_PEER_TX_DELAY`
  (non-preferred), `delay += TXID_RELAY_DELAY` (legacy txid peer while
  wtxid peers available), `delay += OVERLOADED_PEER_TX_DELAY` (>100
  in-flight). On request: `RequestedTx(nodeid, ..., current_time +
  GETDATA_TX_INTERVAL)` reschedules the request to another announcer
  after the 60-second window.
- `bitcoin-core/src/node/txorphanage.h:18-145` —
  `DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER=404000`,
  `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE=3000`. Class surface:
  `AddTx(tx, peer)`, `AddAnnouncer(wtxid, peer)`, `GetTx(wtxid)`,
  `HaveTx(wtxid)`, `HaveTxFromPeer(wtxid, peer)`, `GetTxToReconsider`,
  `EraseTx(wtxid)`, `EraseForPeer(peer)`, `EraseForBlock(block)`,
  `AddChildrenToWorkSet(tx, rng)`, `HaveTxToReconsider`,
  `GetChildrenFromSamePeer(parent, nodeid)`, `GetOrphanTransactions`,
  `TotalOrphanUsage`, `UsageByPeer`, `SanityCheck`,
  `CountAnnouncements`, `CountUniqueOrphans`, `AnnouncementsFromPeer`,
  `LatencyScoreFromPeer`, `MaxGlobalLatencyScore`, `TotalLatencyScore`,
  `ReservedPeerUsage`, `MaxPeerLatencyScore`, `MaxGlobalUsage`.
- `bitcoin-core/src/node/txorphanage.cpp` — `EraseForBlock`: erases
  orphans included in OR invalidated by the block (the latter via
  `OrphansByPrevoutAndPeer` reverse map keyed by spent outpoint).
- `bitcoin-core/src/net_processing.cpp:608-612, 770-772` — AlreadyHave
  composition: `m_txrequest` ∩ `m_lazy_recent_rejects` ∩
  `m_lazy_recent_rejects_reconsiderable` ∩
  `m_lazy_recent_confirmed_transactions` ∩ `m_orphanage` ∩
  `m_pool.exists`.
- `bitcoin-core/src/net_processing.cpp:308-315` — `m_tx_inventory_to_send`
  (per-peer `set<Wtxid>`) and `m_next_inv_send_time` (per-peer
  `chrono::microseconds`); both guarded by `m_tx_inventory_mutex`.
- `bitcoin-core/src/net_processing.cpp` — `m_tx_inventory_known_filter`
  bloom (50000 entries, FP rate 0.000001) ages out announcements naturally
  rather than unbounded set growth.
- `bitcoin-core/src/net_processing.cpp:5063-5070` — incoming inv ban:
  `vInv.size() <= MAX_PEER_TX_ANNOUNCEMENTS + MAX_BLOCKS_IN_TRANSIT_PER_PEER`
  check.
- `bitcoin-core/src/net_processing.cpp` — `RejectIncomingTxs(peer)`:
  returns true if `peer.fRelayTxes == false`, peer is block-relay-only,
  or `m_chainman.IsInitialBlockDownload()`.

**Files audited**
- `src/p2p.lua` —
  `INV_TYPE = {ERROR=0, MSG_TX=1, MSG_BLOCK=2, MSG_FILTERED_BLOCK=3,
  MSG_CMPCT_BLOCK=4, MSG_WTX=5, MSG_WITNESS_TX=0x40000001,
  MSG_WITNESS_BLOCK=0x40000002}` (lines 191-200),
  `MAX_INV_SIZE=50000`, `MAX_GETDATA_SZ=1000`, `MAX_MESSAGE_SIZE=4_000_000`
  (lines 11, 185-188), `serialize_inv`/`deserialize_inv` (lines 533-563
  — `error("inv message size = N exceeds MAX_INV_SIZE")` raised on
  oversized count without Misbehaving call), `serialize_feefilter`
  /`deserialize_feefilter` (lines 921-934).
- `src/peer.lua` — `Peer:handle_version` (line 673,
  `if not self.inbound and ver.relay then ... sendtxrcncl ...`,
  ver.relay is the BIP-37 fRelay), `Peer:handle_verack` (line 747,
  sends `sendheaders`+`sendcmpct`+`feefilter(100000)` but
  **never `wtxidrelay`**), `Peer:process_messages` (line 804, message
  dispatch with NO pcall wrapping), `Peer:on` (line 1125), per-peer
  fields: `wtxid_relay=false` (177), `bloom_filter`, `fee_filter=0`
  (168), `known_txs={}` (173 — DEAD, never written), `known_blocks={}`
  (172 — DEAD, never written), `inflight_txs={}` (171 — DEAD, never
  written), `erlay_enabled=false` (220), `erlay_combined_salt=0` (224),
  `Peer:should_reconcile`/`Peer:initiate_reconciliation` (1012-1033 —
  DEAD, never called from production paths).
- `src/peerman.lua` — `M.TRICKLE = {OUTBOUND_INTERVAL=2.0,
  INBOUND_INTERVAL=5.0, MAX_INV_PER_MSG=35}` (36-43),
  `M.MISBEHAVIOR.TOO_MANY_MESSAGES=50` (26 — DEAD, never consulted),
  `M.poisson_delay(avg)` (281, uses unseeded `math.random()`),
  `M.shuffle(arr)` (296, uses unseeded `math.random()`),
  `PeerManager:_init_peer_trickle` (2044), `_cleanup_peer_trickle`
  (2058), `queue_tx_announcement` (2075 — NO check of `peer.relay_txes`,
  `peer.fee_filter`, `peer.erlay_enabled`), `_process_trickle` (2128 —
  `break` at line 2165 limits to ONE batch per tick per peer),
  `register_handler` (1971), `tick` (1781 — calls `p:process_messages()`
  with NO pcall).
- `src/mempool.lua` — `M.MAX_ORPHAN_TRANSACTIONS=100`,
  `M.MAX_ORPHAN_TX_SIZE=100000`, `M.MAX_ORPHANS_PER_PEER=100`,
  `M.ORPHAN_TX_EXPIRE_TIME=300` (2878-2881), `OrphanPool:add` (2922),
  `OrphanPool:_evict_oldest` (2985), `OrphanPool:remove_for_peer` (3047
  — DEAD at call-site, never wired into on_peer_disconnected),
  `OrphanPool:expire_stale` (3074), `OrphanPool:children_of` (3104 —
  O(N) walk per parent lookup), `OrphanPool:on_block_connected` (3127
  — only resolves children, never erases orphans IN the block or
  conflicting with block txs), `Mempool:has_wtxid` (2242 — O(N) scan
  over all mempool entries).
- `src/main.lua` — `inv` handler (1278 — NO pcall, NO BIP-339 cross-filter,
  NO IBD reject, NO `AddKnownTx` for sender, hardcoded MSG_WITNESS_TX
  in re-request for non-wtxid peers), `tx` handler (1325 — pcall present,
  ban-score 10 on error, NO IBD reject, NO trickle of orphan-revival on
  accept), `try_resolve_orphans` (1378 — does NOT call
  `queue_tx_announcement` on revival), `notfound` handler (1264 — NO pcall,
  ignores tx-type notfound items, no re-request from another peer),
  `getdata` handler (1666), `mempool` BIP-35 handler (1410 — bypasses
  bloom filter on response, ignores MAX_INV_PER_MSG queue limits),
  `filterload`/`filteradd`/`filterclear` handlers (1471, 1498, 1521 —
  set `peer.relay_txes=true`; otherwise never set), block-connected
  hook (1150 — orphan_pool.expire_stale only runs once per block).
- `src/rpc.lua` — `getpeerinfo.relaytxes` (2510 —
  `(p.version_info and p.version_info.relay) or true`, always TRUE on
  explicit opt-out).

---

## Gate matrix (33 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | inv-handler wire-DoS / ban-score | G1: oversized inv → Misbehaving + disconnect | **BUG-1 (P0-DoS)** — `deserialize_inv` raises Lua `error()` (p2p.lua:553) NOT wrapped in pcall by the inv handler (main.lua:1278) or by `Peer:process_messages` (peer.lua:804) or `PeerManager:tick` (peerman.lua:1789). Single 50001-entry inv terminates the daemon — LuaJIT assert-as-validation fleet pattern (W142 BUG-24 sibling) |
| 1 | … | G2: `inv` size also gated on `MAX_PEER_TX_ANNOUNCEMENTS + MAX_BLOCKS_IN_TRANSIT_PER_PEER=5016` | **BUG-2 (P1-DoS)** — never enforced (no `m_txdownloadman` equivalent; main.lua:1278 processes every announced txid without cap; Core net_processing.cpp:5063-5070). Carry-forward G6 from W103 (2025-12, never fixed) |
| 2 | BIP-339 cross-filter (inv handler) | G3: drop MSG_TX from `peer.wtxid_relay` peers | **BUG-3 (P1-CDIV)** — no cross-filter in main.lua:1281-1303; we accept BOTH MSG_TX and MSG_WTX from wtxid_relay peers. Core net_processing.cpp:4059-4063 silently `continue`s the mismatched kind. Carry-forward W103 G2 (open) |
| 2 | … | G4: drop MSG_WTX from non-wtxid-relay peers | **BUG-3 cross-cite** |
| 2 | … | G5: re-request inv uses MSG_WTX for wtxid_relay, MSG_WITNESS_TX otherwise | **BUG-4 (P1-CDIV)** — main.lua:1286 hardcodes `type = p2p.INV_TYPE.MSG_WITNESS_TX` for MSG_TX-class invs even when peer is wtxid_relay. The MSG_WTX branch (1295-1299) is correct, but the MSG_TX branch upgrades to MSG_WITNESS_TX universally — a wtxid_relay peer should receive an MSG_WTX getdata, not MSG_WITNESS_TX |
| 3 | BIP-339 outbound wtxidrelay negotiation | G6: send `wtxidrelay` to ALL peers between version and verack | **BUG-5 (P0-CDIV)** — lunarblock NEVER sends `wtxidrelay` outbound. peer.lua:740-743 sends only `verack`; peer.lua:756-758 sends `sendheaders`+`sendcmpct`+`feefilter`. Grep `send_message.*wtxidrelay` returns ZERO hits. Per BIP-339, BOTH peers must send it for wtxidrelay to activate — every outbound peer effectively stays in legacy txid relay forever. Fleet pattern (W136: "wtxidrelay never sent outbound") confirmed 2nd time |
| 3 | … | G7: wtxidrelay must arrive BEFORE verack (sender-side ordering) | **BUG-5 cross-cite** (we never send it at all) |
| 4 | inv reject during IBD | G8: `RejectIncomingTxs(peer)` ⇒ disconnect on tx-type inv during IBD | **BUG-6 (P1-CDIV)** — no IBD check in inv handler (main.lua:1278); tx invs are processed during IBD, getdata is sent. Core net_processing.cpp:4085-4087 disconnects: `"transaction (%s) inv sent in violation of protocol"`. lunarblock additionally has no `RejectIncomingTxs` analog for `peer.relay_txes == false` or block-relay-only |
| 4 | … | G9: tx handler IBD return-early | **BUG-7 (P0-CDIV)** — no IBD guard in main.lua:1325 (tx handler runs accept_transaction during IBD; W103 G4 carry-forward, still open). Orphans accumulate against the incomplete UTXO set; CPU/memory wasted; G6/G7 of W103 confirmed for the 3rd quarter running |
| 5 | AlreadyHave composition (recent_rejects / recent_confirmed / orphanage) | G10: skip getdata if txid in `m_lazy_recent_rejects` | **BUG-8 (P1-DoS)** — there is NO recent_rejects bloom in lunarblock; only `mempool:has(txid_hex)` is consulted (main.lua:1284). After rejecting a tx for any policy reason (low fee, duplicate-input, etc.), a peer can re-announce it → we re-request → re-validate → re-reject in a tight loop, amplifying CPU per peer. Core net_processing.cpp:608-612 closes this |
| 5 | … | G11: skip getdata if txid in `m_lazy_recent_confirmed_transactions` | **BUG-8 cross-cite** — no `recent_confirmed_transactions` analog; recently-mined txs trigger re-request on inv |
| 5 | … | G12: skip getdata if wtxid in `m_orphanage` | **BUG-9 (P1)** — `OrphanPool:has(wtxid_hex)` exists (mempool.lua:3031) and `has_by_txid` exists (3036), but the inv handler (main.lua:1278-1299) NEVER consults them. Result: announce of a known-orphan triggers redundant getdata and a duplicate-orphan reject when received |
| 6 | TxRequestTracker scheduler | G13: per-peer in-flight cap `MAX_PEER_TX_REQUEST_IN_FLIGHT=100` | **BUG-10 (P0-CDIV)** — `peer.inflight_txs={}` defined at peer.lua:171 but NEVER written or read anywhere in the codebase (grep returns ONE hit, the definition itself). No in-flight cap; carry-forward W103 G7 (still open). Compounds BUG-1 (oversized inv) and BUG-2 (no per-peer ann cap) to a multi-decade-old DoS surface |
| 6 | … | G14: `TXID_RELAY_DELAY=2s` for legacy txid peers when wtxid peers available | **BUG-10 cross-cite** — no delay anywhere; main.lua:1316 sends getdata immediately on inv |
| 6 | … | G15: `NONPREF_PEER_TX_DELAY=2s` for inbound/non-preferred peers | **BUG-10 cross-cite** |
| 6 | … | G16: `OVERLOADED_PEER_TX_DELAY=2s` for peers with >100 in-flight | **BUG-10 cross-cite** |
| 6 | … | G17: `GETDATA_TX_INTERVAL=60s` — reschedule request from another announcer on timeout | **BUG-10 cross-cite** — no timeout, no reschedule, no second-announcer fall-back. If first peer drops the getdata, tx is never re-requested |
| 7 | Outbound inv batching cadence | G18: `INVENTORY_BROADCAST_MAX=1000` per-transmission cap | **BUG-11 (P1)** — lunarblock's `MAX_INV_PER_MSG=35` (peerman.lua:42) is **28.5× lower** than Core's per-transmission cap; combined with `break` after one batch (peerman.lua:2165) the effective rate is 35/Poisson-interval — a single peer can fill its trickle queue with thousands of invs that take many minutes to drain |
| 7 | … | G19: per-peer Poisson seeded for inbound from per-network entropy (privacy) | **BUG-12 (P0-PRIVACY)** — `M.poisson_delay` (peerman.lua:281) uses unseeded `math.random()`. LuaJIT's global `math.random` state is **deterministic from process start** (xorshift seed reset on `math.randomseed` only; we call it ONCE in sync.lua:195 as a fallback for /dev/urandom-unavailable, NOT for tx-relay timing). Tx-origin timing-attack: an observer correlating inv-send times across peers can infer which tx originated locally vs forwarded. Core: `FastRandomContext(m_network_key).rand_exp_duration(...)` per-inbound seeded from a uint256 entropy source |
| 7 | … | G20: `m_next_inv_send_time == 0s` skip until handshake-complete | **BUG-13 (P1)** — `_init_peer_trickle` (peerman.lua:2044) seeds `next_send_time = now + poisson_delay(...)` for any ESTABLISHED peer; there is no 0-sentinel distinguishing "handshake done but inv-broadcast not yet armed". Edge case: a tx accepted between handshake and first trickle fires gets queued normally; not a bug today, but the sentinel architecture is missing. Core net_processing.cpp:2253-2257 actively gates on this |
| 8 | Outbound m_tx_inventory_known_filter | G21: per-peer "already announced to peer" filter populated on SEND | PARTIAL — `trickle.inv_known[hash] = true` at peerman.lua:2156 is populated on send. **BUG-14 (P1)** — unbounded `inv_known` table grows forever per peer (Core uses a 50000-entry bloom that ages out). On a long-running node with sustained tx traffic the per-peer table grows without bound, eventually exhausting heap |
| 8 | … | G22: filter ALSO populated when peer ANNOUNCED tx to us (AddKnownTx) | **BUG-15 (P0-CDIV)** — when a peer sends us an inv, lunarblock does NOT mark `trickle.inv_known[hash]` for that peer. Result: when we later accept the tx and call `queue_tx_announcement`, we re-announce back to the original sender — **echo back amplification**. Core net_processing.cpp:4088 `AddKnownTx(peer, inv.hash)` closes this. `peer.known_txs={}` defined at peer.lua:173 is DEAD (zero writes) — the data structure is plumbed and never used |
| 9 | BIP-133 feefilter (outbound respect) | G23: respect `peer.fee_filter` on outbound relay (skip tx if feerate < filter) | **BUG-16 (P1-BANDWIDTH)** — `peer.fee_filter` is RECEIVED at peer.lua:903-904 but `queue_tx_announcement` (peerman.lua:2075-2106) NEVER consults it. Wasted bandwidth on every low-fee tx-inv to peers that explicitly opted out. Core SendMessages tx loop: `if (tx.feerate < tx_relay->m_fee_filter_received) skip` |
| 9 | … | G24: send our feefilter dynamically tracking mempool min-relay-fee + AVG_FEEFILTER_BROADCAST_INTERVAL=10min | **BUG-17 (P1-BANDWIDTH+CDIV)** — peer.lua:758 sends `feefilter(100000)` **ONCE** at handshake, hardcoded to **100 sat/vB** (`100000` sat/kvB / 1000). Core's `DEFAULT_MIN_RELAY_TX_FEE` is `1000` sat/kvB (= 1 sat/vB). lunarblock advertises a **100× stricter** feefilter than Core. Mainnet effect: peers respecting BIP-133 will drop 95%+ of their normal-fee tx relay to us — we won't see most of the live mempool over tx-relay. Also: never updated as our mempool fills (Core re-broadcasts every 10min with current minRelayTxFee + dynamic component). Carry-forward: same hardcoded value W139/W141 audits flagged in fee-bucket plumbing |
| 9 | … | G25: feefilter wire interop — sat/kvB unit | PASS (p2p.lua:921 `write_i64le` matches Core), but **BUG-17 cross-cite** for value |
| 10 | TxOrphanage parity vs Core's TxOrphanage class surface | G26: `EraseForBlock` evicts orphans IN the block AND orphans whose inputs conflict with block txs | **BUG-18 (P0-CDIV)** — `OrphanPool:on_block_connected` (mempool.lua:3127-3139) only walks block-txs and returns CHILDREN of those txs for re-evaluation. It does NOT: (a) erase orphans whose wtxid matches a block-tx (the orphan is now mined; no point keeping it), (b) erase orphans that DOUBLE-SPEND coins spent in the block (these can never be valid — Core's `OrphansByPrevoutAndPeer` reverse map). Result: stale orphans pin per-peer capacity slots; double-spent orphans linger until ORPHAN_TX_EXPIRE_TIME (5min) or LRU eviction |
| 10 | … | G27: `EraseForPeer` (drop orphans from disconnected peer) wired to disconnect callback | **BUG-19 (P0)** — `OrphanPool:remove_for_peer` (mempool.lua:3047) EXISTS and is correct, but `grep -rn remove_for_peer` shows ZERO call sites outside the definition. `on_peer_disconnected` callback (peerman.lua:1244) does NOT invoke it. Orphans from a churning malicious peer accumulate against the per-peer cap (`MAX_ORPHANS_PER_PEER=100`) forever; reconnect-with-different-port resets the per-peer slot but old orphans still occupy global capacity. Dead-helper-at-call-site fleet pattern (W141 4th instance for lunarblock) |
| 10 | … | G28: AddAnnouncer multi-announcer bookkeeping (orphan announced by N peers; only erase last announcer triggers full removal) | **BUG-20 (P1-CDIV)** — `OrphanPool:add` (mempool.lua:2922) rejects on duplicate wtxid (`already-have-orphan`). Core: multiple peers can ANNOUNCE the same orphan; `AddAnnouncer(wtxid, peer)` augments the announcer set. `EraseForPeer` removes the peer from the set; the orphan stays as long as ≥1 announcer remains. lunarblock drops the second announcement entirely — useful info lost (e.g., for retry-with-different-peer) |
| 10 | … | G29: `LimitOrphans` runs on a timer / on AddTx, not only on block-connect | **BUG-21 (P1)** — `OrphanPool:expire_stale` is invoked ONLY from the block-connected hook (main.lua:1174). If no blocks arrive for `> ORPHAN_TX_EXPIRE_TIME` (5min), stale orphans accumulate AND new orphans are rejected on per-peer cap. testnet4 can stall for hours without a block; mainnet usually OK but a partition can trigger this. Core's LimitOrphans is timer/AddTx-driven |
| 10 | … | G30: `children_of` uses OrphanByParent reverse map (O(1) per parent) | **BUG-22 (P1-PERF)** — `OrphanPool:children_of` (mempool.lua:3104) walks the full `self.order` list (O(N)) on every parent lookup, then matches `missing_parents[parent_txid_hex]`. For 100 orphans averaging 10 missing parents and a 4000-tx block, `on_block_connected` does 4000 × 100 = 400,000 ops/block. Core uses `m_orphans_by_parent` keyed by outpoint (O(1) per outpoint). Also: lunarblock keys by TXID (not OUTPOINT), so two orphans spending DIFFERENT outputs of the same parent collide on parent-arrival re-feed |
| 11 | Wire-bug carry-forward / dead-code / surface dilution | G31: `Mempool:has_wtxid` O(N) scan for wtxid lookup | **BUG-23 (P1-PERF)** — `Mempool:has_wtxid` (mempool.lua:2242) scans ALL entries when `self.entries[wtxid_hex]` misses (the segwit fast-path miss = "almost always" for any segwit tx). For 30k-tx mempool + 50k-entry inv burst the inv handler does 30k × 50k = 1.5e9 string comparisons; combined with the missing per-peer ann cap (BUG-2) and missing inflight scheduler (BUG-10) this is a **direct DoS amplifier from one inv message**. Core: secondary `mapWtxidIndex` keyed by wtxid (O(1)) |
| 11 | … | G32: `peer.relay_txes` consulted on outbound relay | **BUG-24 (P0-CDIV)** — `ver.relay` (the BIP-37 fRelay byte in version msg) is READ at peer.lua:705 but **only to gate Erlay sendtxrcncl**. It is NEVER stored as `peer.relay_txes`. The field `peer.relay_txes` is set ONLY by `filterload`/`filterclear` handlers (main.lua:1493, 1528). Effect: a peer that sends `version{fRelay=false}` (explicitly block-relay-only inbound, e.g. a Lightning node that wants only blocks) STILL receives tx-invs from us. Compounds with BUG-16 (no feefilter respect) — we spam such peers with both inv AND tx data |
| 11 | … | G33: `getpeerinfo.relaytxes` reports peer's actual fRelay bit | **BUG-25 (P1-RPC)** — rpc.lua:2510: `relaytxes = (p.version_info and p.version_info.relay) or true`. When `version_info.relay == false`, the expression evaluates to `false or true == true` — the explicit opt-out is silently overwritten by the `or true` fallback. RPC ALWAYS reports `relaytxes=true`, even for explicit block-relay-only peers. Operator monitoring broken |
| 11 | … | G34: Erlay tx-reconciliation initiate path wired | **BUG-26 (P1-DEAD)** — `Peer:should_reconcile` (peer.lua:1012) and `Peer:initiate_reconciliation` (1033) exist; `erlay_enabled`/`erlay_combined_salt` are SET during handshake (peer.lua:920-924). But `grep -rn should_reconcile.*initiate` returns ZERO production callers. Erlay handshake completes, the daemon advertises BIP-330 capability, peer expects sketches — they never arrive. Plumb-handshake-then-never-use; classic dead-helper-at-call-site (5th lunarblock instance per W138/W139/W141/W149) |
| 11 | … | G35: TOO_MANY_MESSAGES rate-limit cap | **BUG-27 (P1-DEAD)** — `M.MISBEHAVIOR.TOO_MANY_MESSAGES = 50` (peerman.lua:26) defined but `grep -rn TOO_MANY_MESSAGES` shows ZERO consumers. No message-flood detection anywhere. Inv flood is bounded only by tcp recv (4MB max msg) and CPU |

---

## BUG-1 (P0-DoS) — `deserialize_inv` `error()` is not pcall'd in the inv handler → single oversized inv kills the daemon

**Severity:** P0-DoS. Bitcoin Core's
`ProcessMessage(NetMsgType::INV)` (net_processing.cpp:4040-4044)
calls `Misbehaving(peer, strprintf("inv message size = %u", vInv.size()))`
on `vInv.size() > MAX_INV_SZ` and returns from the function — peer is
ban-scored and disconnected. Critically, the *daemon* keeps running.

lunarblock's `p2p.deserialize_inv` (p2p.lua:549-563) raises a Lua
`error("inv message size = N exceeds MAX_INV_SIZE")` (line 553). The
inv handler at main.lua:1278 invokes it directly with NO pcall:

```lua
peer_manager:register_handler("inv", function(peer, payload)
    local items = p2p.deserialize_inv(payload)   -- error() propagates
    local to_request = {}
    for _, item in ipairs(items) do ... end
    ...
end)
```

The Lua error then climbs:
- `handler(self, msg.payload)` at peer.lua:970 — no pcall.
- `Peer:process_messages` at peer.lua:804 — no pcall.
- `p:process_messages()` at peerman.lua:1789 — no pcall.
- Bubbles out of `PeerManager:tick()`, which is called from the main
  event loop in `main.lua` — also no pcall around tick at the main
  scheduler I could find from grep `pcall.*tick`.

Result: a single inbound `inv` with `count = 50001` (5 bytes:
`varint(50001) = 0xfe 51 c3 00 00` then truncate) kills the daemon. Same
shape as W142 BUG-24 (LuaJIT assert-as-validation → wire-DoS) and same
fleet pattern as **assert-leaks-into-RPC-reject-reason** (W143 BUG-15).

Additionally `deserialize_locator` (599), `deserialize_headers` (641),
`deserialize_addr` (687), `deserialize_addrv2` (838) — same shape; the
**block** handler (main.lua:1247) DOES pcall, the **tx** handler
(main.lua:1325) DOES pcall, but **inv** and **notfound** (main.lua:1264)
and **headers** (line 1230 in the source) do not.

**File:** `src/p2p.lua:553` (error raise); `src/main.lua:1278-1319`
(inv handler, no pcall); `src/peer.lua:967-971` (handler dispatch);
`src/peerman.lua:1781-1804` (tick loop).

**Core ref:**
`bitcoin-core/src/net_processing.cpp:4040-4044`
(`if (vInv.size() > MAX_INV_SZ) { Misbehaving(peer, ...); return; }`).

**Impact:** wire-DoS — daemon dies on a single malicious inv. Trivial
to weaponize from any unauthenticated peer.

---

## BUG-3/4 (P1-CDIV) — BIP-339 cross-filter + getdata inv-type are wrong

**Severity:** P1-CDIV.

Core's `ProcessMessage(INV)` (net_processing.cpp:4059-4063):

```cpp
if (peer.m_wtxid_relay) {
    if (inv.IsMsgTx()) continue;    // ignore txid invs from wtxid peer
} else {
    if (inv.IsMsgWtx()) continue;   // ignore wtxid invs from txid peer
}
```

This serves two purposes: (a) a misconfigured/malicious peer cannot
push the wrong inv type; (b) for the wtxid_relay peer's MSG_TX inv we'd
otherwise compute a redundant request that maps to the same tx Core
already requested via the MSG_WTX path.

lunarblock (main.lua:1281-1303) accepts BOTH MSG_TX and MSG_WTX from
ANY peer without consulting `peer.wtxid_relay`:

```lua
for _, item in ipairs(items) do
    if item.type == p2p.INV_TYPE.MSG_TX or item.type == p2p.INV_TYPE.MSG_WITNESS_TX then
        local txid_hex = types.hash256_hex(item.hash)
        if not mempool:has(txid_hex) then
            to_request[#to_request + 1] = {
                type = p2p.INV_TYPE.MSG_WITNESS_TX,  -- ALWAYS upgrades to MSG_WITNESS_TX
                hash = item.hash,
            }
        end
    elseif item.type == p2p.INV_TYPE.MSG_WTX then
        ...
```

Two bugs in one block:

- **BUG-3**: no `peer.wtxid_relay` cross-filter. A wtxid_relay peer
  sending MSG_TX *should* be ignored (because MSG_WTX is the canonical
  channel and the same tx will arrive via MSG_WTX) but lunarblock
  re-requests it, causing duplicate getdata round-trips and increased
  bandwidth.
- **BUG-4**: when re-requesting an MSG_TX-class inv, the getdata always
  uses `MSG_WITNESS_TX` (0x40000001). For a `wtxid_relay` peer this is
  wrong — Core uses `MSG_WTX` for getdata against wtxid_relay peers
  (net_processing.cpp:6195 — "When wtxid relay is enabled, use MSG_WTX").
  Mixed-version peer interop breaks: a strict BIP-339 peer that
  *only* serves MSG_WTX getdata replies with `notfound` to our
  MSG_WITNESS_TX getdata.

**File:** `src/main.lua:1278-1319`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4059-4063` (cross-filter);
`bitcoin-core/src/net_processing.cpp:6190-6200` (re-request inv type).

**Impact:** redundant bandwidth, BIP-339 wire-format divergence. Same
fleet shape as W142 BIP-141/143 wire-format slippage findings.

---

## BUG-5 (P0-CDIV) — `wtxidrelay` NEVER sent outbound; BIP-339 effectively disabled for outbound peers

**Severity:** P0-CDIV.

Per BIP-339:

> Nodes that want to negotiate `wtxidrelay` MUST send a `wtxidrelay`
> message between the `version` and `verack` messages. **Both peers
> must send `wtxidrelay`** for it to be activated. Without `wtxidrelay`
> from both sides, tx relay falls back to txid relay.

lunarblock's outbound handshake (peer.lua:740-758):

```lua
function Peer:handle_verack()
  ...
  if self.state == M.STATE.VERACK_SENT or self.state == M.STATE.VERSION_SENT then
    self.state = M.STATE.ESTABLISHED
    self.handshake_complete = true
    self:send_message("sendheaders", "")
    self:send_message("sendcmpct", p2p.serialize_sendcmpct(false, 2))
    self:send_message("feefilter", p2p.serialize_feefilter(100000))
    -- ❌ NO send_message("wtxidrelay", "")
  end
end
```

`grep -rn 'send_message("wtxidrelay'` returns **ZERO hits**. lunarblock
RECEIVES wtxidrelay (peer.lua:905-908, sets `self.wtxid_relay = true`)
but never sends it. By BIP-339, this means `self.wtxid_relay` is set
true unilaterally on receipt — but the peer's view of US is
`m_wtxid_relay=false` (we never told them). The wire state is
asymmetric:

- We treat peer as wtxid_relay (use MSG_WTX channels for them).
- Peer treats us as legacy (sends only MSG_TX channels to us).

So our MSG_WTX getdata to a strict BIP-339 peer returns `notfound`;
our MSG_TX getdata works. The "use_wtxid" branch in
`queue_tx_announcement` (peerman.lua:2096) sends MSG_WTX invs to a peer
that — per BIP-339 — will *ignore* them because they think we didn't
negotiate.

**File:** `src/peer.lua:740-760` (verack handler — sends sendheaders/
sendcmpct/feefilter, missing wtxidrelay).

**Core ref:** `bitcoin-core/src/net_processing.cpp:5650-5660`
(SendMessages: `if (peer.IsPreferredDownloadPeer() && !peer.m_wtxid_relay
&& ... ) m_connman.PushMessage(... NetMsgType::WTXIDRELAY, ... )`).

**Impact:** every outbound peer connection effectively stays in legacy
txid relay forever. Compounds BUG-4 (we send MSG_WTX getdata to a peer
that thinks we negotiated MSG_TX) → silent notfound responses.
**Carry-forward** from W136 fleet finding "wtxidrelay never sent
outbound" (4 impls confirmed); lunarblock now confirmed as the 5th.

---

## BUG-8 (P1-DoS) — No `m_lazy_recent_rejects` / `m_lazy_recent_confirmed_transactions`; AlreadyHave is only `mempool:has`

**Severity:** P1-DoS.

Core's AlreadyHave (net_processing.cpp:608-612, 770-772) composes SIX
membership tests:
- `m_pool.exists(GenTxid)` (in mempool now)
- `m_orphanage.HaveTx(wtxid)` (in orphan pool now)
- `m_lazy_recent_rejects.contains(hash)` (rejected in last 120000 tx)
- `m_lazy_recent_rejects_reconsiderable.contains(hash)` (rejected but
  could be reconsidered, e.g. fee bump)
- `m_lazy_recent_confirmed_transactions.contains(hash)` (mined in last
  100000 tx)
- `m_txrequest.Count(...)` (we already have an outstanding request)

lunarblock checks ONE: `mempool:has(txid_hex)` (main.lua:1284).

Effect: when a peer announces a tx we've already rejected (low-fee,
duplicate-input, sigop-overflow), lunarblock re-requests it, re-runs
the full mempool acceptance pipeline (1400-line `accept_transaction`),
re-rejects it. Then the SAME peer (or any other peer that received the
same tx and propagated) re-announces; we re-request again; repeat.

A coordinated attack from N peers each announcing the same low-fee tx K
times per second produces N × K mempool acceptance attempts per second
on this node. For a 30-byte tx requiring ECDSA verification on 3
inputs, this is enough CPU to dominate the event loop. There is no
upper bound on this amplification (BUG-2 also missing: no per-peer
announcement cap).

Even without an active attacker, normal mempool churn re-requests
recently-mined transactions until they hit ORPHAN_TX_EXPIRE_TIME or
get pushed out of the mempool entries map.

**File:** `src/main.lua:1278-1303` (inv handler AlreadyHave check).

**Core ref:** `bitcoin-core/src/net_processing.cpp:608-612, 770-772`
(AlreadyHave); `bitcoin-core/src/node/txdownloadman.h:50-100`
(`m_lazy_recent_rejects` rolling bloom).

**Impact:** CPU DoS from peer-controlled re-announcements; bandwidth
amplification on the receive side.

---

## BUG-10 (P0-CDIV) — TxRequestTracker entirely absent: no per-peer in-flight cap, no delays, no GETDATA timeout, no reschedule

**Severity:** P0-CDIV.

Core's `TxRequestTracker` (txrequest.cpp / txdownloadman_impl.cpp) is
the canonical solution to a known DoS class: a peer announces a tx and
never delivers it; an honest tx is delayed indefinitely. Constants:

- `MAX_PEER_TX_REQUEST_IN_FLIGHT = 100` — per-peer outstanding getdata cap.
- `MAX_PEER_TX_ANNOUNCEMENTS = 5000` — per-peer queued announcement cap.
- `TXID_RELAY_DELAY = 2s` — extra delay for legacy txid peers when
  wtxid peers are available (prefer wtxid).
- `NONPREF_PEER_TX_DELAY = 2s` — extra delay for non-preferred (e.g.
  inbound) peers.
- `OVERLOADED_PEER_TX_DELAY = 2s` — extra delay when peer has > 100
  in-flight.
- `GETDATA_TX_INTERVAL = 60s` — after issuing getdata, re-schedule the
  request to another announcer if no tx arrives within 60s.

lunarblock has NONE of this. The inv handler (main.lua:1309-1318)
sends a getdata immediately, in a single message batched at
MAX_GETDATA_SZ=1000, to the first peer that announced it:

```lua
local i = 1
while i <= #to_request do
    local batch = {}
    local limit = math.min(i + p2p.MAX_GETDATA_SZ - 1, #to_request)
    for j = i, limit do batch[#batch + 1] = to_request[j] end
    peer:send_message("getdata", p2p.serialize_inv(batch))
    i = i + p2p.MAX_GETDATA_SZ
end
```

There is no `inflight_txs` set being mutated (the field is defined at
peer.lua:171 with zero writers/readers), no timer to detect missing
responses, no second-announcer fallback.

Direct consequences:

1. **Tx loss on peer drop**: peer announces, we send getdata, peer
   silently drops the request. We have no record we're waiting on
   anything; the tx is never re-requested even if 9 other peers also
   announced it.
2. **Echo amplification**: any peer can hold a tx hostage. They
   announce → we getdata → they don't reply. Honest peers also
   announced but we don't fall back to them.
3. **CPU amplification**: combined with BUG-2 (no per-peer ann cap),
   one peer can dump 50000 invs and force us to send 50000 getdata in
   a tight loop. Without a per-peer in-flight cap, lunarblock will hit
   the OS file-descriptor limit before the peer-side throttle kicks in.

**File:** `src/peer.lua:171` (dead `inflight_txs`); `src/main.lua:1309-1318`
(immediate batched getdata, no in-flight tracking).

**Core ref:**
- `bitcoin-core/src/node/txdownloadman.h:24-38` (constants).
- `bitcoin-core/src/node/txdownloadman_impl.cpp:200-280` (delay
  composition + GETDATA_TX_INTERVAL reschedule).
- `bitcoin-core/src/txrequest.cpp` (the actual scheduler).

**Impact:** carry-forward W103 G7 still open. Lacking the scheduler is
a multi-decade-old DoS surface that Core closed with PR #19988 (2021).
**Fleet pattern**: this is the same architecture-shape gap as W138's
`ChainstateManager` (defined-but-not-wired) — the data structure is
there (`inflight_txs={}` on Peer) but the production logic that should
mutate it does not exist.

---

## BUG-12 (P0-PRIVACY) — Trickle Poisson timer uses unseeded `math.random()` → tx-origin timing-attack

**Severity:** P0-PRIVACY.

Core's tx-relay Poisson delay (net_processing.cpp:5984-5986) uses
**per-peer entropy** for INBOUND peers (`NextInvToInbounds` seeds from
`m_network_key`, a `uint256` initialized from
`GetRandHash()` at startup) and `m_rng.rand_exp_duration` (a
`FastRandomContext` seeded from `GetRandBytes()`) for OUTBOUND. This
prevents two attackers from correlating timing across our outbound
fanout to identify which peer is the tx origin.

lunarblock (peerman.lua:281-287):

```lua
function M.poisson_delay(avg_interval)
  local u = math.random()
  if u == 0 then u = 1e-10 end
  return -math.log(u) * avg_interval
end
```

`math.random()` is LuaJIT's global `math.random`, which uses an
xorshift PRNG with a process-lifetime state. **It is never seeded for
tx-relay**. The only `math.randomseed` call in lunarblock is in
sync.lua:195 — and that ONLY runs as a fallback when /dev/urandom is
unavailable for the headers-presync commitment salt. In normal
deployment with `/dev/urandom` available, `math.random` runs with
LuaJIT's default-seed xorshift state — the same numerical sequence on
every process start.

`shuffle` (peerman.lua:296-299) uses the same `math.random`:

```lua
for i = n, 2, -1 do
    local j = math.random(1, i)
    ...
end
```

Attack scenario:
- Adversary connects two probe peers to our node.
- Adversary submits a transaction to peer 1.
- Adversary observes which other peer (peer 2) receives the inv first,
  and the inter-arrival timing.
- Because the Poisson delay is deterministic from process start, the
  attacker can fingerprint the daemon's RNG state by observing N
  successive trickle-fires, and then PREDICT which peer is the origin
  of the next tx.

Even without RNG state recovery, the lack of per-peer entropy means two
peers observing trickle timing can correlate easily — Core's design
goal of preventing this is fully defeated.

**File:** `src/peerman.lua:281-287` (poisson_delay), 293-302 (shuffle).

**Core ref:**
- `bitcoin-core/src/net_processing.cpp:5982-5988` (NextInvToInbounds /
  rand_exp_duration with per-peer + per-process entropy).
- `bitcoin-core/src/random.cpp` (FastRandomContext, `GetRandHash`).

**Impact:** tx-origin de-anonymization. Defeats the privacy goal of
trickle-relay entirely; CVE-class on a network with adversarial
spy nodes (Chainalysis, blocksci-style observatories). NB: even if
seeded, LuaJIT's xorshift is not cryptographically strong; the correct
fix is a `crypto.fastrandom` cipher-stream RNG.

---

## BUG-15 (P0-CDIV) — `AddKnownTx` missing: every accepted tx is re-relayed back to the original announcer (echo)

**Severity:** P0-CDIV.

Core's `m_tx_inventory_known_filter` is a per-peer 50000-entry rolling
bloom that tracks "we believe this peer already knows about this tx".
It is populated in TWO directions:

- **OUTBOUND**: when WE send an inv to peer, we add the txid to their
  known_filter (net_processing.cpp:6058).
- **INBOUND**: when peer sends an inv to us, we add the txid to their
  known_filter via `AddKnownTx` (net_processing.cpp:4088).

Effect: a tx received from peer X is never re-announced *back to* peer
X, because their known_filter contains it.

lunarblock has a per-peer `inv_known` table (peerman.lua:2050) that is
populated ONLY in direction (1): outbound, after `_process_trickle`
sends the batch (peerman.lua:2156):

```lua
trickle.inv_known[entry.hash] = true   -- mark as known after we sent
```

Direction (2) is missing entirely. There is no `AddKnownTx` call in
the inv handler (main.lua:1278-1319). The peer field `known_txs={}` at
peer.lua:173 is DEAD (zero writes anywhere).

Workflow with the bug:
1. Peer X sends `inv{MSG_TX, txid=T}` to us.
2. We getdata; receive tx; accept to mempool.
3. `queue_tx_announcement(txid)` walks all established peers and
   queues T on their trickle queue — including peer X (whose
   `inv_known[T]` is `nil` because we never marked it on receipt).
4. Next trickle tick, peer X receives `inv{MSG_TX, txid=T}` — the same
   txid they JUST sent us 200ms ago.

Direct consequences:

- **Echo bandwidth waste**: every received tx is re-sent to the
  original announcer. In a 100-peer mesh receiving 5 tx/s, this is
  500 echo-invs/s of wasted bandwidth — and the announcer reciprocates
  by adding the echoed inv to their inv_known and skipping the next
  re-announce. So the bug is *self-clearing* per-tx-per-peer over time,
  but the first round-trip is always a full echo back.
- **Privacy regression**: an attacker can identify which peer
  introduced a tx by timing — the peer who DOESN'T re-receive their
  own tx via echo is the origin.

**File:** `src/main.lua:1278-1319` (inv handler — no AddKnownTx call);
`src/peer.lua:173` (dead `known_txs`); `src/peerman.lua:2050, 2099,
2156` (inv_known populated only on send).

**Core ref:** `bitcoin-core/src/net_processing.cpp:4088`
(`AddKnownTx(peer, inv.hash)` in INV handler).

**Impact:** ~50% wasted tx-inv bandwidth in steady state; privacy
inference on tx origin. Fleet pattern: `known_txs` defined-but-dead is
same shape as `inflight_txs` defined-but-dead (BUG-10) and Erlay
`should_reconcile` defined-but-dead (BUG-26) — **lunarblock has at
least 3 distinct "data structure defined, production wiring absent"
instances in tx-relay alone**.

---

## BUG-16/17 (P1-BANDWIDTH+CDIV) — feefilter: never respected on send, 100× too strict on broadcast, hardcoded once at handshake

**Severity:** P1-BANDWIDTH + P1-CDIV.

**BUG-16 — outbound feefilter not respected.**

Core's SendMessages tx-inv loop (net_processing.cpp:6043-6058) gates
each tx against the receiving peer's `m_fee_filter_received`:

```cpp
for (auto wtxid : tx_relay->m_tx_inventory_to_send) {
    auto txinfo = m_pool.info(GenTxid::Wtxid(wtxid));
    if (txinfo.fee == 0 || txinfo.feeRate < tx_relay->m_fee_filter_received) continue;
    ...
    vInv.emplace_back(MSG_WTX, wtxid.ToUint256());
}
```

lunarblock's `queue_tx_announcement` (peerman.lua:2075-2106) and
`_process_trickle` (2128-2170) NEVER consult `peer.fee_filter`. The
field is RECEIVED at peer.lua:903-904 (`peer.fee_filter =
p2p.deserialize_feefilter(payload)`) and otherwise unread.

Effect: a peer that broadcast `feefilter(50000)` (50 sat/vB) gets every
low-fee tx-inv from us anyway. Bandwidth waste on every dust spam tx.

**BUG-17 — we broadcast 100 sat/vB, hardcoded, never updated.**

peer.lua:756-758:

```lua
self:send_message("feefilter", p2p.serialize_feefilter(100000))
-- 100 sat/vB = 100000 sat/kvB
```

This is sent ONCE per peer at verack, hardcoded to 100000 sat/kvB =
100 sat/vB.

Core's defaults:
- `DEFAULT_MIN_RELAY_TX_FEE = 1000` sat/kvB = 1 sat/vB (policy.h:70).
- Dynamic component: as the mempool fills past `-maxmempool`,
  `GetMinFee()` rises above the floor; the feefilter is rebroadcast on
  a `AVG_FEEFILTER_BROADCAST_INTERVAL = 10min` Poisson schedule
  (net_processing.cpp:185, ~6240).

lunarblock advertises **100× stricter** than Core's default minimum. On
mainnet at typical conditions:
- ~95% of legitimate tx pay 1-5 sat/vB.
- Peers respecting BIP-133 will silently drop all sub-100 sat/vB tx
  relay TO us.
- We see only the top-feerate-tail of the live network's tx flow over
  tx-relay.

Additionally we never re-broadcast feefilter as our mempool fills, so
even an operator running with the default 100 sat/vB is permanently
stuck at handshake-time value.

**File:** `src/peer.lua:758` (hardcoded send); `src/peer.lua:903-904`
(received but unread); `src/peerman.lua:2075-2170` (relay path never
consults `peer.fee_filter`).

**Core ref:**
- `bitcoin-core/src/policy/policy.h:70` (`DEFAULT_MIN_RELAY_TX_FEE`).
- `bitcoin-core/src/net_processing.cpp:6043-6058` (outbound filter check).
- `bitcoin-core/src/net_processing.cpp:185` (`AVG_FEEFILTER_BROADCAST_INTERVAL`).

**Impact:** broken mempool view on mainnet (BUG-17); doubled bandwidth
on outbound relay to feefilter-using peers (BUG-16). Both are mainnet-
observable today. **Fleet pattern**: same shape as W139 "fee_estimates
.dat interop missing" — feefilter is the wire-level half of fee
estimation; lunarblock botches both halves consistently.

---

## BUG-18 (P0-CDIV) — `OrphanPool:on_block_connected` does not erase orphans IN the block or orphans double-spent by the block

**Severity:** P0-CDIV.

Core's `TxOrphanage::EraseForBlock(const CBlock& block)`
(node/txorphanage.cpp) does TWO things on each block-connected:

1. For each block tx, walks `m_orphans_by_wtxid[blockTx.GetWitnessHash()]`
   and erases the orphan — it's mined now, no point keeping it.
2. For each spent outpoint in the block (i.e. `block.vtx[*].vin[*].prevout`),
   walks `m_orphans_by_prevout[outpoint]` and erases each orphan that
   tried to spend the same coin — those orphans now provably double-spend
   confirmed history and can never be valid.

lunarblock (mempool.lua:3127-3139):

```lua
function OrphanPool:on_block_connected(block)
  if not block or not block.transactions then return {} end
  local resolved = {}
  for _, tx in ipairs(block.transactions) do
    local txid = validation.compute_txid(tx)
    local parent_hex = types.hash256_hex(txid)
    local children = self:children_of(parent_hex)
    for _, c in ipairs(children) do
      resolved[#resolved + 1] = c   -- returns for re-feed
    end
  end
  return resolved
end
```

This ONLY walks block-tx → orphan-child relationships (parent arrived,
children re-feedable). It does NOT:

- Erase orphan O if `O.wtxid == blockTx.wtxid` for any block tx (mined-
  orphan case).
- Erase orphan O if `O.input.prevout == blockTx.input.prevout` for any
  block tx + matching index (double-spent orphan case).

Stale orphans pin per-peer capacity slots (`MAX_ORPHANS_PER_PEER=100`,
mempool.lua:2880) and the global cap (`MAX_ORPHAN_TRANSACTIONS=100`).
A malicious peer can churn orphans that conflict with confirmed history
to evict honest orphans from other peers via the LRU eviction
(`_evict_oldest` at mempool.lua:2985 + the eviction loop at 2961-2967).

**File:** `src/mempool.lua:3127-3139` (`on_block_connected`); no
reverse-map by outpoint.

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp::EraseForBlock`.

**Impact:** orphan-pool capacity DoS; honest orphans evicted by
attacker-controlled stale orphans. Pairs with BUG-19 (no
EraseForPeer on disconnect) for a churning-attacker scenario:
attacker connects, dumps 100 orphans conflicting with imminent block,
disconnects → orphans linger forever (BUG-19), block arrives, orphans
still occupy capacity because they're not in the block (BUG-18).

---

## BUG-19 (P0) — `OrphanPool:remove_for_peer` exists, never called from disconnect callback

**Severity:** P0.

`src/mempool.lua:3047-3063` defines a complete, correct
`OrphanPool:remove_for_peer(peer_id)` implementation that walks the
order list, removes entries authored by the disconnected peer, and
rebuilds the order — exactly as Core's `EraseForPeer`. Total: ~17 LOC.

`grep -rn remove_for_peer` across the codebase returns ONE hit (the
definition itself). It is never called.

The disconnect callback in `peerman.lua:1244` invokes only
`self.callbacks.on_peer_disconnected(p, reason)`. Following this in
main.lua: no registration of `on_peer_disconnected` that touches
`orphan_pool` exists. `grep -rn on_peer_disconnected` returns only the
default-nil callback registration (peerman.lua:351) and the dispatch
above.

Effect: a peer that contributes K orphans (up to 100) and disconnects
leaves K orphans in our pool, occupying:
- K slots of the global cap (`MAX_ORPHAN_TRANSACTIONS=100`).
- K slots of the per-peer cap under their `pid` key (which is keyed
  by "ip:port", so on RECONNECT-WITH-DIFFERENT-PORT they get a fresh
  100 slots while their old orphans still count globally).

A malicious peer can rotate ports (or even IPs in a Sybil scenario) to
fill the global orphan pool with stale orphans that never expire
(BUG-21: expire_stale only fires on block-connected, ORPHAN_TX_EXPIRE_TIME
= 300s, but if blocks come every 10 min, that's 0-300s between expiry
runs depending on how many blocks come; on testnet4 stalls, hours).

**File:** `src/mempool.lua:3047-3063` (correct impl); `src/peerman.lua:1244,
351` (callback never wired to orphan pool); `src/main.lua` (no
on_peer_disconnected registration).

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp::EraseForPeer`;
`bitcoin-core/src/net_processing.cpp::FinalizeNode` calls
`EraseForPeer` on every disconnect.

**Impact:** orphan-pool capacity DoS via peer churn; classic
**dead-helper-at-call-site** fleet pattern (W141: "function exists +
exported + called but no-op" — here the function exists + is correct
+ has ZERO call sites). 5th lunarblock instance of this pattern after
W138/W139/W144/W149.

---

## BUG-22 (P1-PERF) — `OrphanPool:children_of` O(N) full-scan per parent lookup

**Severity:** P1-PERF.

`OrphanPool:children_of(parent_txid_hex)` (mempool.lua:3104-3118)
walks the entire `self.order` list (up to `MAX_ORPHAN_TRANSACTIONS=100`)
on EVERY parent lookup, and for each entry, indexes
`e.missing_parents[parent_txid_hex]`:

```lua
function OrphanPool:children_of(parent_txid_hex)
  local out = {}
  for _, wtxid_hex in ipairs(self.order) do
    local e = self.entries[wtxid_hex]
    if e and e.missing_parents[parent_txid_hex] then
      out[#out + 1] = {tx=e.tx, wtxid_hex=wtxid_hex, ...}
    end
  end
  return out
end
```

Called once per block-tx from `on_block_connected` (mempool.lua:3127-3139).
For a 4000-tx block, this is 4000 × 100 = 400,000 ops per block. For a
mainnet-typical 2500-tx block, 250,000 ops. Per block. Inside the
hot path (block-connected → call within the validation lock).

Core uses `m_orphans_by_parent` (txorphanage.cpp) keyed by `COutPoint`
(outpoint = txid + vout-index), giving O(1) per outpoint and
O(B × max_inputs_per_block_tx) per block — typically 4000 × 4 = 16,000
ops, ~15× faster.

Additionally: lunarblock keys `missing_parents` by `parent_txid_hex`
(NOT by outpoint). If orphan A spends parent X output 0 and orphan B
spends parent X output 1, both have `missing_parents = {X=true}`. When
X arrives, both A and B are re-fed — but Core would re-feed only those
whose specific OUTPOINT is now spendable. The lunarblock heuristic
errs toward over-feeding (correct under most conditions, just wasteful).

**File:** `src/mempool.lua:3104-3118`.

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp` —
`m_orphans_by_parent` reverse map keyed by outpoint.

**Impact:** validation-lock hold time on block-connected scales with
orphan-pool size; minor today (100-orphan cap) but a real scaling
ceiling if the pool is ever expanded. Same architecture-shape gap as
BUG-23 (`Mempool:has_wtxid` O(N) scan): lunarblock prefers per-block
iteration over reverse-indexed lookup throughout the relay surface.

---

## BUG-24 (P0-CDIV) — `peer.relay_txes` ignores BIP-37 fRelay flag in version message; block-relay-only peers receive tx invs

**Severity:** P0-CDIV.

Core's `Peer::m_relay_txs` is set from `vRecv >> fRelay` in
`ProcessMessage(VERSION)` (net_processing.cpp): if `fRelay == false`,
this peer EXPLICITLY does not want tx invs. Used for Lightning nodes,
pruned nodes that don't relay, block-relay-only outbound peers, etc.

lunarblock parses the version message at p2p.lua:455-459 and exposes
`ver.relay` correctly. peer.lua:705 reads it ONCE — to gate Erlay
sendtxrcncl initiation. It is NEVER stored as `peer.relay_txes` or any
equivalent field. The field `peer.relay_txes` is ONLY set by
filterload/filterclear handlers (main.lua:1493, 1528):

```lua
peer.relay_txes = true   -- after filterload
peer.relay_txes = true   -- after filterclear
```

The relay path `queue_tx_announcement` (peerman.lua:2075-2106) doesn't
consult `peer.relay_txes` at all — only `peer.bloom_filter` (for BIP-37
filtering). So a peer that sent `version{fRelay=false}` and NEVER
loaded a bloom filter has:
- `peer.relay_txes == nil` (never set)
- `peer.bloom_filter == nil`

And our trickle code happily queues every tx-inv for them, sending
them tx invs they explicitly opted out of receiving.

**File:** `src/peer.lua:705` (ver.relay read, never stored to a relay
flag); `src/main.lua:1493, 1528` (relay_txes only set on filterload/
filterclear); `src/peerman.lua:2075-2106` (relay path).

**Core ref:** `bitcoin-core/src/net_processing.cpp` ProcessMessage
VERSION handler — `peer.m_relay_txs = fRelay` (around line 3700).

**Impact:** wire-protocol violation of BIP-37 fRelay; bandwidth waste
on opt-out peers; misclassification of block-relay-only outbound
connections (which lunarblock doesn't actually open today per the
"block-relay-only" comment at peerman.lua:974 — "In a full
implementation, we'd check if this is a block-relay-only connection"
— but the wire-side bug is still present and would matter as soon as
that gap is closed). Compounds with BUG-25 (RPC misreports relaytxes
always true).

---

## BUG-25 (P1-RPC) — `getpeerinfo.relaytxes` always returns true via `(false) or true` short-circuit

**Severity:** P1-RPC.

rpc.lua:2510:

```lua
relaytxes = (p.version_info and p.version_info.relay) or true,
```

Lua semantics: `(A) or B` returns `A` if A is truthy, else `B`. When
`p.version_info.relay == false` (peer explicitly sent `fRelay=false`),
the expression evaluates `(false) or true == true`. The opt-out is
silently overwritten by the `or true` fallback.

The intent was clearly: "default to true if version_info missing".
Correct expression: `(p.version_info and p.version_info.relay) ~= false`
or `p.version_info ~= nil and p.version_info.relay or (p.version_info == nil)`.

Effect: `getpeerinfo` always reports `relaytxes=true` for every peer,
including peers that explicitly opted out of tx relay via fRelay=false.
Operator monitoring tools that scrape getpeerinfo to identify
block-relay-only peers will see them all as full-relay.

**File:** `src/rpc.lua:2510`.

**Core ref:** `bitcoin-core/src/rpc/net.cpp` getpeerinfo —
`relaytxes: peer.m_relay_txs.load()`.

**Impact:** RPC misreport; monitoring/diagnostic tooling breaks for
mixed-relay deployments. Trivial fix (one-line).

---

## BUG-26 (P1-DEAD) — Erlay reconciliation: handshake completes, sketches never sent

**Severity:** P1-DEAD.

lunarblock's Erlay implementation (per BIP-330) is plumbed:
- `sendtxrcncl` sent outbound at peer.lua:706-708 (only for outbound
  full-relay).
- `sendtxrcncl` received at peer.lua:912-928, sets
  `self.erlay_enabled = true` + computes `erlay_combined_salt`.
- `Peer:should_reconcile()` (peer.lua:1012-1027) decides if it's time
  to initiate reconciliation.
- `Peer:initiate_reconciliation(wtxids)` (peer.lua:1033-…) builds and
  sends the sketch.

`grep -rn should_reconcile.*initiate` and `grep -rn initiate_reconciliation`
across `src/` show ZERO production callers. `_process_trickle` in
peerman.lua:2128 sends fanout invs to ALL peers regardless of
`erlay_enabled`. Erlay handshake completes; we advertise BIP-330
capability; peers expect sketches; sketches never arrive; we still
fanout invs as if Erlay wasn't negotiated. The bandwidth savings goal
of Erlay (40-50% reduction in tx-relay traffic) is unrealized.

Worse: a strict BIP-330 peer that PREFERS reconciliation over
fanout-inv will be confused — they receive fanout invs from a peer
that signed up for reconciliation. Wire-protocol drift.

**File:** `src/peer.lua:1012-1027` (`should_reconcile` defined, no
callers); `src/peer.lua:1033-…` (`initiate_reconciliation` defined, no
callers); `src/peerman.lua:2128-2170` (`_process_trickle` doesn't gate
on `erlay_enabled`).

**Core ref:** Bitcoin Core does NOT currently ship BIP-330 (the spec is
draft, Core has experimental support behind `-erlay` knob). The
relevant references for "feature plumbed but never invoked" pattern
are W138 ChainstateManager / W141 dead-helper-at-call-site.

**Impact:** wasted handshake bandwidth + protocol-state drift with
strict Erlay peers. Plus dead-data ~250 LOC across peer.lua + erlay.lua
+ minisketch.lua. **Fleet pattern**: 5th lunarblock dead-helper
instance (after W138/W139/W141/W149). Trends toward subsystem-rewrite
candidate; same "30-of-30-gates-buggy" template that W139 + W149 + W150
hit.

---

## BUG-27 (P1-DEAD) — `TOO_MANY_MESSAGES = 50` defined, never consulted

**Severity:** P1-DEAD.

peerman.lua:26:
```lua
M.MISBEHAVIOR = {
  ...
  TOO_MANY_MESSAGES = 50,      -- DoS protection: message flood
  ...
}
```

`grep -rn TOO_MANY_MESSAGES` returns ONE hit (the constant definition).
No consumer reads it. There is no message-flood detection or
rate-limiting in the peer message loop. A peer can fire arbitrary
messages as fast as TCP allows, bounded only by `MAX_MESSAGE_SIZE = 4 MB`
per message.

For tx-relay specifically: a peer can fire 10 `inv` messages per
second with `MAX_INV_SIZE = 50000` entries each = 500,000 inv items/s.
Combined with BUG-2 (no per-peer ann cap), BUG-10 (no inflight cap),
BUG-23 (O(N) wtxid scan per item) → CPU overload from any inbound peer
in O(seconds).

**File:** `src/peerman.lua:26` (defined); zero consumers.

**Core ref:** Bitcoin Core's per-message-type net-processing rate-
limiting (e.g. `MAX_ADDR_PROCESSING_TOKEN_BUCKET = 1000` in
net_processing.cpp ~190).

**Impact:** another instance of dead-data plumbing in tx-relay. The
constant exists; the wire-flood gate it was meant to enforce does not.
Trivial wire-DoS amplifier in combination with BUG-1, BUG-2, BUG-10,
BUG-23.

---

## Cross-cutting / fleet observations

- **"30-of-30-gates-buggy" 4th candidate confirmed**: this audit found
  **27 bugs across 35 gates** (≈77% bug-density), within striking
  distance of the W139 fee-estimation (30/30), W149 pruning (30/30),
  W150 ATMP (30+/30+) "subsystem rewrite candidate" benchmarks. The
  tx-relay path is structurally fragile across 4 dimensions
  simultaneously (wire-DoS, scheduler missing, privacy timing,
  orphanage data structures), and incremental patches will not close
  the gap — a coherent rewrite of `tx-relay/inv-pipeline.lua +
  tx-relay/orphanage.lua` modeled on Core's TxDownloadManager class is
  the structural fix.
- **LuaJIT assert-as-validation 3rd lunarblock-specific instance**:
  BUG-1 (deserialize_inv error()→ wire-DoS) joins W142 BUG-24 (LuaJIT
  assert→ fatal) and W143 BUG-15 (validation.lua:220 assert leaks into
  RPC reject reason). Same shape, three different surfaces.
- **dead-helper-at-call-site 5th lunarblock instance**: BUG-19
  (`OrphanPool:remove_for_peer` correct + ZERO call sites) +
  BUG-26 (Erlay `should_reconcile`/`initiate_reconciliation` correct +
  ZERO call sites) + BUG-10 (`peer.inflight_txs={}` defined + ZERO
  read/writes) + BUG-15 (`peer.known_txs={}` defined + ZERO writes) +
  BUG-27 (`TOO_MANY_MESSAGES=50` defined + ZERO reads) = **5 distinct
  dead-data instances in this wave alone**, joining W138/W139/W141/W149.
  Subsystem-rewrite signal.
- **two-pipeline guard 18th distinct extension**: the inv path
  populates `trickle.inv_known` from the OUTBOUND direction only
  (peerman.lua:2156), while a separate inbound `peer.known_txs={}` is
  defined-but-dead (peer.lua:173). Two parallel known-tx tracking
  structures, one alive on send, one dead on receive — same "two
  pipelines diverging" pattern as W144 STANDARD_SCRIPT_VERIFY_FLAGS
  (haskoin) / W127 tapscript MAX_SCRIPT_ELEMENT_SIZE bypass (camlcoin).
- **carry-forward open**: W103 G1 (MSG_WTX) and W103 G3 (relay path)
  were FIXED in 2025-12 patches (per the inline test annotations).
  W103 G2/G4/G5/G6/G7/G8 (IBD guards, per-peer cap, TxRequestTracker,
  wtxidrelay post-verack disconnect, etc.) remained open. This audit
  re-confirms ALL of W103's open items still open 5+ months later —
  **same fleet anti-pattern** as W125 reject-string slippage (lunarblock
  9-token sweep open across W125 + W145).
- **comment-as-confession 6th lunarblock instance**: peerman.lua:974
  `"In a full implementation, we'd check if this is a block-relay-only
  connection"` and main.lua:1422-1424 `"30k-tx mempool fans out across
  the next few ticks"` (false: with `break` after one batch at
  peerman.lua:2165, 30k/35 = 857 ticks). Both literal text confessions
  that the gate is incomplete. Joins W125 (lunarblock 9-token sweep),
  W143 (`utxo.lua:3490` reorg connect_block), W144 (BUG-12), W145
  (BUG-2/6 cluster), W150 (`mempool.lua:1762-1770` test_accept).
- **MSG_FILTERED_BLOCK = 1 of 10**: lunarblock IS the 1 implementation
  that DOES dispatch MSG_FILTERED_BLOCK correctly (main.lua:1695-1740).
  Cross-cite W134 fleet finding "MSG_FILTERED_BLOCK dispatch gap (7
  impls)" — lunarblock is in the safe 3.
