# W141 — ZMQ + REST + Notification scripts audit (lunarblock)

**Date:** 2026-05-18
**Wave:** W141 (discovery; bundled subsystem audit)
**Impl:** lunarblock (Lua / LuaJIT)
**Status:** **22 BUGS FOUND** (1 P0 / 6 P1 / 9 P2 / 6 P3) across **30 gates**
**Scope:** ZeroMQ pub-notifier (5 topics + sequence), REST HTTP server
(14 Core endpoints), and the **shell-out notification scripts**
(`-alertnotify`, `-blocknotify`, `-walletnotify`, `-startupnotify`,
`-shutdownnotify`) defined by Core's `init.cpp` / `wallet/init.cpp` /
`node/kernel_notifications.cpp`.

**BIPs:** none (operator-surface / extension subsystems, not consensus).

## Context

This is the **bundled** complement audit to W124 (operator experience) — the
prior wave only catalogued the **missing** notify hooks at the CLI surface
(BUG-12, G26-G28). W141 audits each subsystem **internally**: the ZMQ wire
format, the REST endpoint shape, and the notify-script semantics; it does NOT
re-confirm the CLI-MISSING side (assumed) but it DOES catalogue every
Core-parity deviation in the **existing** ZMQ + REST code, and the
**security boundary** of the eventual notify-script implementation
(shell injection, signal handling, blocking semantics).

## Source map

- `lunarblock/src/zmq.lua` — 608 LOC; FFI bindings to libzmq, 5 topic
  publishers (hashblock / hashtx / rawblock / rawtx / sequence), a test-only
  subscriber, and a higher-level `NotificationManager` wired from main.lua.
- `lunarblock/src/rest.lua` — 1967 LOC; HTTP/1.1 GET server (+ POST /payjoin
  via FIX-65) implementing 11 of Core's 14 `/rest/*` endpoints, plus
  helpers for the JSON shape.
- `lunarblock/src/main.lua:1091-1124` — wires ZMQ callbacks to chain_state
  and mempool callback registries.
- `lunarblock/src/main.lua:1345-1348` — fires `on_tx_added` ZMQ notify in
  the P2P `tx` handler after a successful mempool admission.
- `lunarblock/src/main.lua` lines **NO notify-script flags** (--alertnotify,
  --blocknotify, --walletnotify, --startupnotify, --shutdownnotify all
  absent); already catalogued in `audit/w124_operator_experience.md` G26-G28
  but called out below for completeness.

Core references:

- `bitcoin-core/src/zmq/zmqnotificationinterface.{cpp,h}` — topic
  registration, BlockConnected/BlockDisconnected/UpdatedBlockTip fan-out,
  IBD gate.
- `bitcoin-core/src/zmq/zmqpublishnotifier.{cpp,h}` — wire format,
  multipart message, per-notifier `nSequence`, hash byte-order
  (display = reversed).
- `bitcoin-core/src/zmq/zmqutil.{cpp,h}` — `unix:` → `ipc://` prefix
  normalization; `ADDR_PREFIX_IPC = "ipc://"` (zmqutil.h:13).
- `bitcoin-core/src/rest.{cpp,h}` — all 14 endpoints + format-suffix
  parsing + warmup gate.
- `bitcoin-core/src/init.cpp:2008-2018` — `-blocknotify` wiring with
  POST_INIT gate.
- `bitcoin-core/src/node/kernel_notifications.cpp:30-47` — `-alertnotify`
  with `SanitizeString` + single-quote shell escape.
- `bitcoin-core/src/wallet/wallet.cpp:1140-1163` — `-walletnotify`
  with `%s` / `%b` / `%h` / `%w` (ShellEscape'd wallet name).
- `bitcoin-core/src/txmempool.cpp:263-274` — `removeUnchecked` /
  `TransactionRemovedFromMempool` semantics; **BLOCK reason suppressed**
  from notification.
- `bitcoin-core/src/common/system.cpp:50-60` — `runCommand` shell-out
  helper used by all five notify-script flags.

## 30-gate matrix

### A. ZeroMQ wire & topic correctness (G1-G10)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G1 | 5 topics registered: `pubhashblock` / `pubhashtx` / `pubrawblock` / `pubrawtx` / `pubsequence` | **OK** — `zmq.lua:97-101`. |
| G2 | Topic-multipart wire format: `[topic, body, LE32(seq)]` | **OK** — `zmq.lua:266-282`. |
| G3 | Per-notifier-instance `nSequence` (uint32, starts at 0, wraps) | **OK in shape, BUG-1 in sharing semantics** — shared via `topic_seq` not per-Core-notifier. |
| G4 | Hash payload byte-order = reversed (display order) | **OK** — `reverse_bytes` in `notify_hashblock` / `notify_hashtx` / `notify_sequence`. |
| G5 | `SNDHWM` socket option set from `-zmqpub<topic>hwm` per-topic | **BUG-2** — only ONE global `hwm`; Core sets per-topic `-zmqpubhashblockhwm=N`. |
| G6 | `TCP_KEEPALIVE` set on every socket | **OK** — `zmq.lua:212-213`. |
| G7 | `ZMQ_IPV6` toggled based on `tcp://[IPv6]:port` detection | **BUG-3** — no IPv6 detection; lunarblock never sets `ZMQ_IPV6`. Core: `IsZMQAddressIPV6` (zmqpublishnotifier.cpp:82-93). |
| G8 | `unix:` prefix normalized to `ipc://` for libzmq | **BUG-4** — no normalization. Core: zmqnotificationinterface.cpp:62-64. |
| G9 | Multiple topics sharing an endpoint reuse one socket | **OK** — `endpoint_to_socket` map in `zmq.lua:193-225`. |
| G10 | `ZMQ_LINGER=0` set on shutdown for prompt close | **OK** — `zmq.lua:385-391`. |

### B. ZMQ event fan-out (block / tx flows) (G11-G18)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G11 | `UpdatedBlockTip` skipped during IBD (`fInitialDownload`) | **BUG-5** — no IBD gate; lunarblock fires hashblock/rawblock for **every** connected block including during IBD. Core: zmqnotificationinterface.cpp:151-159. |
| G12 | `UpdatedBlockTip` skipped when no new tip (`pindexNew == pindexFork`) | **BUG-5b** — same root cause; lunarblock has no concept of "tip-only" emit. |
| G13 | `BlockConnected` fans out hashtx + rawtx for **every** tx in block | **BUG-6 (P1)** — `NotificationManager:on_block_connected` (zmq.lua:558-566) only emits hashblock+rawblock+sequence-C; **never** loops `block.vtx` to emit hashtx/rawtx. Core: zmqnotificationinterface.cpp:185-190. |
| G14 | `BlockDisconnected` fans out hashtx + rawtx for **every** tx in disconnected block | **BUG-7 (P1)** — `NotificationManager:on_block_disconnected` only emits sequence-D; no hashtx/rawtx fan-out. Core: zmqnotificationinterface.cpp:200-205. |
| G15 | `BlockConnected` / `BlockDisconnected` driven by validation interface (historical-role aware) | **BUG-8 (P2)** — Core zmqnotificationinterface.cpp:182-184 explicitly returns when `role.historical` (background validation chainstate); lunarblock has no concept and would notify twice if it later adopts background sync. |
| G16 | `TransactionAddedToMempool` emits **both** `NotifyTransaction` (hashtx + rawtx) AND `NotifyTransactionAcceptance` (sequence-A) | **OK** — `on_tx_added` (zmq.lua:578-588) emits all three. |
| G17 | `TransactionRemovedFromMempool` suppressed when reason == `BLOCK` (already covered by BlockConnected fan-out) | **BUG-9 (P0)** — `mempool.lua:1893-1908` removes block-confirmed txs via `remove_transaction(txid, "confirmed")`; `main.lua:1116-1119`'s `on_tx_removed` hook then fires `notify_tx_removal` for **every** confirmed tx, causing **double-emission** with the (planned, missing G13) hashtx fan-out + an inappropriate sequence-R for a block-included tx. Core txmempool.cpp:269 explicitly checks `reason != MemPoolRemovalReason::BLOCK` before signalling. |
| G18 | mempool sequence number monotonically increments on **every** mempool mutation (add or remove), regardless of whether the notifier listener exists | **BUG-10 (P2)** — `NotificationManager.mempool_sequence` (zmq.lua:519+581+595) only increments **inside** the ZMQ callback. If the listener disables and re-enables ZMQ mid-session, sequence numbers leap; cross-restart they reset to 0 (Core's also resets to 1 cross-restart, but Core's seq is owned by `CTxMemPool::m_sequence_number` and is also live-readable via `getmempoolinfo.sequence` / RPC). Lunarblock has no in-mempool monotonic counter and exposes none via RPC. |

### C. REST endpoint coverage & shape (G19-G26)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G19 | `/rest/tx/<txid>.{bin,hex,json}` | **OK** — `rest.lua:594-722`. |
| G20 | `/rest/block/<hash>.{bin,hex,json}` and `/rest/block/notxdetails/<hash>.{bin,hex,json}` | **OK** — `rest.lua:410-590`. |
| G21 | `/rest/blockpart/<hash>?offset=N&size=N` (binary block-part for parallel block download) | **BUG-11 (P2)** — absent. Core: rest.cpp:481-498. |
| G22 | `/rest/blockfilter/<filtertype>/<hash>` + `/rest/blockfilterheaders/<filtertype>[/<count>]/<hash>` | **OK** — `rest.lua:1286-1375`; covers BIP-157 path-form AND `?count=N` query-form. |
| G23 | `/rest/headers/<count>/<hash>` + `/rest/headers/<hash>?count=N` | **OK** — `rest.lua:1755-1768`. |
| G24 | `/rest/chaininfo.json` | **OK** — `rest.lua:1101-1197` (per FIX-80 chain-name fix). |
| G25 | `/rest/mempool/{info,contents}.json` (with `verbose` + `mempool_sequence` query params) | **PARTIAL** — `verbose` honoured but `mempool_sequence` query param **never read** and the mutually-exclusive (`verbose=true&mempool_sequence=true`) check absent. Core rest.cpp:809-822. → **BUG-12 (P2)**. |
| G26 | `/rest/deploymentinfo[/hash]` JSON | **BUG-13 (P2)** — absent. Core: rest.cpp:743-779. Operator who reaches `/rest/chaininfo` softforks block now has no per-hash query. |

### D. REST format & input parsing (G27-G28)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G27 | `/rest/getutxos` accepts **POST-body** binary/hex outpoint list (in addition to URI scheme) | **BUG-14 (P2)** — `handle_getutxos` (rest.lua:863-1031) ONLY honours URI-scheme `txid-n/txid-n/...`; reads no POST body. Core rest.cpp:912 `req->ReadBody()` is the canonical entrypoint for HEX/BIN. |
| G28 | `/rest/spenttxouts/<hash>.{bin,hex,json}` (new in Core) | **BUG-15 (P2)** — absent. Core: rest.cpp:313-381. |

### E. Notify scripts (G29-G30)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G29 | `-blocknotify=<cmd>` + `-alertnotify=<cmd>` + `-walletnotify=<cmd>` + `-startupnotify=<cmd>` + `-shutdownnotify=<cmd>` CLI flags | **BUG-16 (P1)** — **all five absent**. (Cross-ref `audit/w124_operator_experience.md` G26-G28 BUG-12.) Lunarblock advertises ZMQ as the alternative; ZMQ requires a long-running listener; the notify-script flags are the trivially deployable alternative every operator expects. |
| G30 | Shell-injection hardening for the `%s` / `%w` substitution chain (when the flags eventually land) | **BUG-17 (P1, latent)** — pre-condition for landing G29: lunarblock's existing `os.execute("mkdir -p " .. datadir)` in `main.lua:409 / 594 / 719-720` already accepts unquoted operator-controlled paths. If `--datadir` contains shell metacharacters (`;` `&&` ``$()`` `` ` ``) the path is interpreted by `/bin/sh`. Core uses `fs::create_directories` (no shell). Same antipattern would carry into a naïve `-blocknotify` implementation. |

## Bugs (full)

### BUG-1 (P2) — `topic_seq` per-topic, not per-notifier-instance (G3 semantic mismatch)

**File:** `src/zmq.lua:181, 187-189, 261-263`.

**Core ref:** `zmqpublishnotifier.h:21` — `nSequence` is a member of
`CZMQAbstractPublishNotifier`. Each topic = a separate notifier object even
when two topics share the same socket via `mapPublishNotifiers`. Each
notifier instance owns its own `nSequence`. lunarblock maps
`topic_seq[topic]`, which yields the **same observable** wire output (one
counter per topic) when only one socket-binding-per-topic is configured.
The drift surfaces if the operator ever puts two notifiers for the SAME
topic at different endpoints — Core then has two `nSequence` counters
(one per notifier) and lunarblock has one shared.

**Severity:** P2 — Core's CLI doesn't expose multi-endpoint per-topic
either (each `-zmqpub<topic>=X` collapses to one notifier), so this is
a latent semantic difference, not a current bug.

---

### BUG-2 (P1) — Single `--zmqpubhwm` instead of per-topic `-zmqpub<topic>hwm` (G5)

**File:** `src/main.lua:53, 313-315, 1103`; `src/zmq.lua:182, 208-209`.

**Core ref:** `zmqnotificationinterface.cpp:69` — Core reads
`gArgs.GetIntArg(arg + "hwm", DEFAULT_ZMQ_SNDHWM)` PER topic, e.g.
`-zmqpubhashblockhwm=4096 -zmqpubrawtxhwm=100`. lunarblock has ONE
`--zmqpubhwm` flag and applies it to every socket.

**Impact:** Operator cannot tune per-topic outbound-buffer pressure
(rawblock streams up to 4 MB per message and benefits from a low HWM;
hashblock is 32 bytes and benefits from a high HWM).

**Severity:** P1 — visible operator-surface deviation.

**Fix sketch:** add `--zmqpubhashblockhwm`, `--zmqpubhashtxhwm`,
`--zmqpubrawblockhwm`, `--zmqpubrawtxhwm`, `--zmqpubsequencehwm` CLI
args; pass per-topic into `M.new` and look up by `topic` in the loop
at `zmq.lua:196`. Keep `--zmqpubhwm` as a global fallback default.

---

### BUG-3 (P1) — No `ZMQ_IPV6` socket option (G7)

**File:** `src/zmq.lua:206-225` (the per-socket init loop).

**Core ref:** `zmqpublishnotifier.cpp:82-136` — Core has
`IsZMQAddressIPV6()` parsing `tcp://[ipv6]:port`, then calls
`zmq_setsockopt(psocket, ZMQ_IPV6, &enable, sizeof(enable))`. On systems
where IPv6 must be explicitly opted in at the libzmq level (notably
OpenBSD and some libzmq builds), the bind fails silently without this.

**Impact:** Operator setting `-zmqpubhashblock=tcp://[::1]:28332` gets
a confusing "Failed to bind" error on affected platforms.

**Severity:** P1 — IPv6 deployments are a first-class Core feature.

---

### BUG-4 (P2) — No `unix:` → `ipc://` prefix normalization (G8)

**File:** `src/zmq.lua:215` (raw bind).

**Core ref:** `zmqnotificationinterface.cpp:62-64`:

```cpp
if (address.starts_with(ADDR_PREFIX_UNIX)) {
    address.replace(0, ADDR_PREFIX_UNIX.length(), ADDR_PREFIX_IPC);
}
```

Core lets operators write `-zmqpubhashblock=unix:/run/lunarblock.sock`
(per the `unix:` convention also used by `-rpcbind`); lunarblock requires
the verbatim libzmq form `ipc:///run/lunarblock.sock`.

**Impact:** Operator confusion; trivial copy-from-Core-config will fail.

---

### BUG-5 (P2) — `UpdatedBlockTip` fires during IBD (G11+G12)

**File:** `src/main.lua:1108-1114`; `src/zmq.lua:558-566`.

**Core ref:** `zmqnotificationinterface.cpp:151-159`:

```cpp
void CZMQNotificationInterface::UpdatedBlockTip(..., bool fInitialDownload) {
    if (fInitialDownload || pindexNew == pindexFork)
        return;
    ...NotifyBlock...
}
```

Core gates `hashblock` + `rawblock` emission on `fInitialDownload=false`.
lunarblock's `on_block_connected` callback (the only wiring path) fires
unconditionally on every block connect, INCLUDING during IBD. For a
mainnet IBD that connects ~880k blocks, the operator gets ~880k spurious
hashblock notifications.

**Impact:** ZMQ subscriber sees ~3 orders of magnitude more events than
Core during IBD; downstream tooling (block explorers, mempool indexers)
may melt under that load.

**Severity:** P2 — operational; doesn't corrupt anything but breaks
parity with every Core-compatible ZMQ consumer.

**Fix sketch:** add an `initial_block_download` flag to the
`NotificationManager` and check it in `on_block_connected` before
calling `notify_hashblock` / `notify_rawblock`. Sequence-C should
still fire (Core's `BlockConnected` path is IBD-independent — that's
intentional).

---

### BUG-6 (P1) — `BlockConnected` does NOT fan out hashtx/rawtx for tx in connected block (G13)

**File:** `src/zmq.lua:558-566` (`NotificationManager:on_block_connected`).

**Core ref:** `zmqnotificationinterface.cpp:180-196`:

```cpp
void CZMQNotificationInterface::BlockConnected(...) {
    if (role.historical) return;
    for (const CTransactionRef& ptx : pblock->vtx) {
        TryForEachAndRemoveFailed(notifiers, [&tx](...) {
            return notifier->NotifyTransaction(tx);  // hashtx + rawtx
        });
    }
    TryForEachAndRemoveFailed(notifiers, [pindexConnected](...) {
        return notifier->NotifyBlockConnect(pindexConnected);  // sequence-C
    });
}
```

lunarblock emits **only** hashblock + rawblock + sequence-C and never
loops `block.transactions` to emit hashtx + rawtx per Core's contract.
Subscribers depending on `hashtx` to react to confirmed txs (most block
explorers do, since `BlockConnected` is the canonical "confirmation"
event) will miss every confirmed tx unless they also subscribe to
`hashblock` and re-derive the txids themselves.

**Impact:** Core-compatible ZMQ subscribers receive different event
streams against lunarblock vs Core, breaking the canonical wire
contract.

**Severity:** P1 — observable wire-format deviation; high-impact
because EVERY confirmed tx is silently dropped.

---

### BUG-7 (P1) — `BlockDisconnected` does NOT fan out hashtx/rawtx for tx in disconnected block (G14)

**File:** `src/zmq.lua:570-573`.

**Core ref:** `zmqnotificationinterface.cpp:198-211`:

```cpp
void CZMQNotificationInterface::BlockDisconnected(...) {
    for (const CTransactionRef& ptx : pblock->vtx) {
        TryForEachAndRemoveFailed(notifiers, [&tx](...) {
            return notifier->NotifyTransaction(tx);  // hashtx + rawtx
        });
    }
    TryForEachAndRemoveFailed(notifiers, [pindexDisconnected](...) {
        return notifier->NotifyBlockDisconnect(pindexDisconnected);  // sequence-D
    });
}
```

Same shape as BUG-6 but for the disconnect path. On a reorg, Core
re-emits hashtx for every tx in the disconnected block (so subscribers
can re-pick-them-up if they re-enter the mempool); lunarblock only
emits sequence-D.

**Severity:** P1 — reorg-time wire deviation. Same root pattern as BUG-6.

---

### BUG-8 (P2) — No historical-role / background-validation gate (G15)

**File:** `src/zmq.lua:558-573`; `src/utxo.lua` chain_state has no
`role.historical` concept.

**Core ref:** `zmqnotificationinterface.cpp:182-184` — `if (role.historical) return;`.

When Core does background-validation against assumevalid / assumeutxo
snapshot, the "historical" chainstate connects blocks without firing
ZMQ. lunarblock does not implement background validation (audit
W138 in flight) so this is currently a latent gate — but if lunarblock
ever adopts assumeutxo, the existing ZMQ wiring will double-fire all
notifications.

**Severity:** P2 — latent; mark to revisit when assumeutxo lands.

---

### BUG-9 (P0) — Block-removal of txs fires sequence-R + hashtx instead of being suppressed (G17)

**File:** `src/mempool.lua:1893-1908` removes confirmed txs via
`remove_transaction(txid_hex, "confirmed")`; the callback then runs in
`src/main.lua:1116-1119` and fires `zmq_notifier:on_tx_removed(...)`
unconditionally.

**Core ref:** `bitcoin-core/src/txmempool.cpp:263-275`:

```cpp
void CTxMemPool::removeUnchecked(txiter it, MemPoolRemovalReason reason) {
    uint64_t mempool_sequence = GetAndIncrementSequence();
    if (reason != MemPoolRemovalReason::BLOCK && m_opts.signals) {
        // Clients interested in transactions included in blocks can
        // subscribe to the BlockConnected notification.
        m_opts.signals->TransactionRemovedFromMempool(...);
    }
    ...
}
```

Core SUPPRESSES `TransactionRemovedFromMempool` (which would emit
sequence-R) when the removal reason is `BLOCK` — because the
`BlockConnected` path is the canonical "this tx is in a block now"
notification, and emitting sequence-R for a confirmed tx is misleading
(a subscriber would think the tx was evicted, not confirmed).

lunarblock's `on_block_connected` (mempool.lua:1893) calls
`remove_transaction(txid_hex, "confirmed")` for every confirmed tx;
the `on_tx_removed` callback in main.lua:1116-1119 unconditionally
fires `zmq_notifier:on_tx_removed` which emits sequence-R + bumps
`mempool_sequence`. The subscriber observes:

```
sequence | <txid> | 'R' | <bumped_seq>  (lunarblock: spurious)
```

instead of the Core-canonical block-side sequence-C emission.

**Severity:** **P0** — wire-format deviation that mis-classifies every
confirmed tx as evicted. Will break any sender / block-explorer keying
off the sequence label.

**Fix sketch:** in `main.lua:1116-1119`, ignore reasons in the set
`{"confirmed", "block"}`; OR pipe the reason into
`NotificationManager:on_tx_removed(txid, reason)` and let it filter
inside `zmq.lua`. The latter is cleaner because it also makes the
"reason" available for future telemetry.

---

### BUG-10 (P2) — `mempool_sequence` not exposed via mempool; resets to 0 on every restart and is owned by the ZMQ NotificationManager (G18)

**File:** `src/zmq.lua:519, 581, 595` — `mempool_sequence` lives on the
NotificationManager.

**Core ref:** `bitcoin-core/src/txmempool.h:202` —
`mutable uint64_t m_sequence_number GUARDED_BY(cs){1};` lives on the
`CTxMemPool` itself, starts at **1** (not 0), and is exposed via
`getmempoolinfo.sequence` so RPC consumers can poll it without ZMQ.

lunarblock's counter:

1. Lives on the **ZMQ** NotificationManager — so if ZMQ is disabled the
   counter doesn't exist; consumers can't poll a `getmempoolinfo.sequence`
   shim (because `rpc.lua getmempoolinfo` returns no `sequence` field;
   see `rpc.lua` mempool-info handler).
2. Starts at **0** vs Core's **1**; subscribers replaying both nodes'
   sequences side-by-side will be off-by-one.
3. Bumps only when `on_tx_added` / `on_tx_removed` fire — which means
   if the operator disables ZMQ mid-session, the count freezes.

**Severity:** P2 — observable but rarely consumed; subscribers that pin
to Core's `getmempoolinfo.sequence` will misalign.

---

### BUG-11 (P2) — `/rest/blockpart/<hash>?offset=N&size=N` endpoint absent (G21)

**File:** `src/rest.lua` — no route.

**Core ref:** `rest.cpp:481-498` `rest_block_part`. Used by parallel
block-fetchers (block explorers, statoshi, certain SPV servers) to
stream a single block in chunks. lunarblock has `/rest/block/` (full
block) but cannot partial-fetch.

**Impact:** Tooling that prefers `blockpart` over `block` for memory
reasons (4 MB blocks at scale) won't work against lunarblock.

---

### BUG-12 (P2) — `/rest/mempool/contents` missing `mempool_sequence=` query parameter + missing mutex check (G25)

**File:** `src/rest.lua:1035-1064` `handle_mempool_contents`.

**Core ref:** `rest.cpp:800-822` — Core parses both `verbose` and
`mempool_sequence` query parameters, returns 400 if both are `true`
("Verbose results cannot contain mempool sequence values"), and stamps
the mempool sequence number on the response when `mempool_sequence=true`.

lunarblock:

- Reads only `verbose` (rest.lua:1040).
- Silently ignores `mempool_sequence`.
- Has no `MempoolToJSON(... mempool_sequence)` second path.

**Impact:** Subscribers depending on the canonical poll-by-sequence
flow (e.g. `getrawmempool true true` + `getrawmempool false true`)
cannot use REST as the JSON-RPC alternative.

---

### BUG-13 (P2) — `/rest/deploymentinfo[/hash]` endpoint absent (G26)

**File:** `src/rest.lua` — no route.

**Core ref:** `rest.cpp:741-779` `rest_deploymentinfo`. Returns the
`getdeploymentinfo` projection optionally for a specified block hash.
lunarblock's chaininfo includes a `softforks` block but the per-hash
query is a separate endpoint Core exposes for historic-fork analysis.

---

### BUG-14 (P2) — `/rest/getutxos` POST-body input absent (G27)

**File:** `src/rest.lua:863-1031` (`handle_getutxos`).

**Core ref:** `rest.cpp:911-986` — Core reads `req->ReadBody()` first
and only falls back to URI-scheme parsing when the body is empty.
Binary POST is the **only** way to query more than the URI scheme can
encode (URL length limits in some proxies cap at ~2 KB) and the only
way to query in `BINARY` format.

lunarblock supports URI-scheme exclusively; POST body is never read.

---

### BUG-15 (P2) — `/rest/spenttxouts/<hash>.{bin,hex,json}` endpoint absent (G28)

**File:** `src/rest.lua` — no route.

**Core ref:** `rest.cpp:313-381` `rest_spent_txouts` (new endpoint).
Returns the `BlockUndo` data per block (list of CTxOut lists, one per
non-coinbase tx). Used by indexers to walk the spent-output set without
re-traversing the chain. lunarblock has no `/rest/spenttxouts/`.

---

### BUG-16 (P1) — `-alertnotify` / `-blocknotify` / `-walletnotify` / `-startupnotify` / `-shutdownnotify` all absent (G29)

**File:** `src/main.lua:298-315` (the ZMQ flag block); no notify-script
flags adjacent or anywhere else.

**Core refs:**

- `bitcoin-core/src/init.cpp:485` `-alertnotify`
- `bitcoin-core/src/init.cpp:498` `-blocknotify`
- `bitcoin-core/src/init.cpp:529-530` `-startupnotify` / `-shutdownnotify`
- `bitcoin-core/src/wallet/init.cpp:75` `-walletnotify`
- `bitcoin-core/src/node/kernel_notifications.cpp:30-47` (alert wiring)

**Cross-ref:** `audit/w124_operator_experience.md` G26-G28 BUG-12 first
flagged this at the CLI-flag level; W141 confirms the entire wiring is
absent (signal handlers also don't fork a thread for the shutdown
command — there's no shutdown-time hook at all).

**Severity:** P1 — operator-surface feature parity. Notify scripts are
the trivially deployable alternative to ZMQ for tap-and-fire workflows
(webhook, paging, email).

---

### BUG-17 (P1, latent) — `os.execute("mkdir -p " .. datadir)` is shell-injectable; will carry into a naïve notify-script implementation (G30)

**File:** `src/main.lua:409, 594, 719, 720`; `src/wallet.lua:2424, 2552, 2681`.

**Core ref:** `bitcoin-core/src/common/system.cpp:38-65` — Core's
`runCommand` does call `std::system()` (so it IS interpreted by `/bin/sh`),
BUT Core sanitizes inputs before substitution:

- `-alertnotify`: `SanitizeString(strMessage)` strips non-safe chars +
  single-quote-wraps (`'msg'`) BEFORE `ReplaceAll(strCmd, "%s", safeStatus)`.
- `-walletnotify`: `%w` substituted via `ShellEscape(GetName())`
  (wallet/wallet.cpp:1160).
- Datadir, blocksdir, etc. are created via `fs::create_directories` —
  **never** `system()`.

lunarblock's `mkdir -p` calls pass `args.datadir` (operator-controlled)
verbatim to `/bin/sh`. If the operator runs lunarblock as themselves
the impact is "nothing the operator couldn't already do", but the
antipattern matters because:

1. The same antipattern will recur when notify-scripts land. A naïve
   `os.execute(args.blocknotify:gsub("%%s", block_hash))` is safe only
   because block-hash hex is constrained; but `--walletnotify=cmd %s %w`
   substituting `%w` (wallet NAME, operator-set!) is NOT safe without
   ShellEscape.
2. Modern Lua/LuaJIT has `os.exec`-without-shell via `posix.unistd.exec*`
   (luaposix); the project already FFI-binds to libc / libzmq, so
   loading the right syscall is cheap.

**Severity:** P1 (latent) — flagged here so the eventual G29 fix lands
with `ShellEscape` semantics from day one.

**Fix sketch:**

- Replace `os.execute("mkdir -p " .. p)` with `lfs.mkdir(p)` (LuaFileSystem)
  recursively or with a Lua function that calls `mkdir(2)` via FFI.
- Implement `shell_escape(s)` as `"'" .. s:gsub("'", "'\\''") .. "'"`
  (matches Core's `util/string.cpp` `ShellEscape`) and apply it to every
  `%s` / `%w` substitution in notify-script flags.

---

### BUG-18 (P3) — `ZMQ_SUBSCRIBE` subscriber side has no `ZMQ_UNSUBSCRIBE` path

**File:** `src/zmq.lua:415-503`.

**Core ref:** `zmqpublishnotifier.cpp` etc. — Core has a publisher-only
view; subscriber-side use is by external code. Lunarblock's
`ZMQSubscriber` is a test-helper; it doesn't expose unsubscribe, which
is fine for tests but makes the helper unusable for any consumer that
re-subscribes mid-flight.

**Severity:** P3 — test-helper polish only.

---

### BUG-19 (P3) — `encode_le64` overflow risk for sequences > 2^53

**File:** `src/zmq.lua:128-141`.

Lua 5.1 / LuaJIT base have 53-bit-precision doubles for numbers;
`math.floor(n / 4294967296)` works for sequences up to 2^53 (~9e15). A
mempool that issues > 9e15 events would silently produce a wrong high
half. This is theoretical (Core's `m_sequence_number` is uint64
starting at 1; reaching 2^53 takes 285 million years at 1 event/ms)
but documented for the record. LuaJIT's `bit64` extension or `ffi.new("uint64_t", n)`
would close the precision gap.

**Severity:** P3 — theoretical only.

---

### BUG-20 (P3) — REST `Connection: close` is always emitted even with HTTP/1.1 keepalive request

**File:** `src/rest.lua:221-226`.

Core's httpserver uses libevent's HTTP/1.1 connection management and
honours `Connection: keep-alive` when the client requests it. lunarblock
unconditionally sets `Connection: close` in every response, forcing
TCP teardown per request. For block explorers polling
`/rest/chaininfo.json` once per second this is benign; for high-rate
mempool pollers it adds TCP handshake overhead.

**Severity:** P3 — performance only.

---

### BUG-21 (P3) — REST `body_offset` math doesn't validate Content-Length < 0 or non-numeric

**File:** `src/rest.lua:1930-1952`.

`local clen = tonumber(headers["content-length"]) or 0` — if a hostile
client sends `Content-Length: -1` then `tonumber` returns `-1` and the
`> 0` gate trips; benign. But if the client sends `Content-Length: 0x10`
then `tonumber` returns `16`. Same as Core (`atoi` returns 16 too). Doc
note only.

**Severity:** P3.

---

### BUG-22 (P3) — REST + ZMQ both fire from the **same** thread as the main P2P loop

**File:** `src/main.lua:1108-1119, 1345-1347`; `src/zmq.lua:266-285`.

Core fires ZMQ notifications and runs REST in a dedicated thread pool
(`std::thread t(runCommand, ...).detach()` for notify-script too, and
libevent http server runs on its own threads). lunarblock fires ZMQ
synchronously inside the validation interface callback — if libzmq's
`zmq_msg_send` blocks (HWM exhausted), the entire node main loop blocks
with it. Same for REST — `tick()` is called from the main loop and
blocks until the client receives.

**Severity:** P3 — non-blocking by default for ZMQ_PUB (drops at HWM
rather than blocks unless `ZMQ_XPUB_NODROP` is set, which lunarblock
doesn't). Caught here because Core's threading model is the right
mental model to carry forward.

---

## Summary

- **22 bugs total**: 1 P0 / 6 P1 / 9 P2 / 6 P3.
- **1 universal pattern**: `MemPoolRemovalReason::BLOCK` suppression
  (BUG-9) is a Core-canon wire-shape rule lunarblock will share with
  every other impl in the fleet — flag for cross-impl audit framing in
  the next wave.
- **1 shell-injection-class latent pattern**: BUG-17 datadir mkdir →
  notify-script `%s/%w` substitution. **Must** be fixed BEFORE BUG-16
  (notify-script CLI flags) lands, otherwise the fix introduces a new
  attack surface.
- **3 absent REST endpoints**: `/rest/blockpart/`, `/rest/spenttxouts/`,
  `/rest/deploymentinfo/`. None block consensus but all are
  Core-canonical and tooling consumers expect them.
- **No `-alertnotify` / `-blocknotify` / `-walletnotify` /
  `-startupnotify` / `-shutdownnotify`**: cross-referenced from W124,
  bundled here for completeness.

## Out-of-scope (deliberate)

- ZMQ `getzmqnotifications` RPC method — covered in W125 (RPC error
  parity audit).
- `pubrawblock` getter callback (`get_block_by_index` in Core) — not
  applicable since lunarblock's `on_block_connected` already receives
  a serialized block (no callback indirection needed).
- BIP-157 `cfilters` / `cfheaders` over REST — already covered by W121
  and active in lunarblock per FIX-81.
- Notify-script semantics on Windows (`%w` ShellEscape Windows-specific
  in Core wallet/init.cpp:75) — lunarblock targets Linux-only.

## References

- `bitcoin-core/src/zmq/zmqnotificationinterface.cpp`
- `bitcoin-core/src/zmq/zmqpublishnotifier.cpp`
- `bitcoin-core/src/zmq/zmqpublishnotifier.h`
- `bitcoin-core/src/rest.cpp`
- `bitcoin-core/src/txmempool.cpp:263-275` (BUG-9 BLOCK suppression)
- `bitcoin-core/src/init.cpp:485, 498, 529-530, 2008-2018`
- `bitcoin-core/src/node/kernel_notifications.cpp:30-47`
- `bitcoin-core/src/wallet/wallet.cpp:1140-1163`
- `bitcoin-core/src/common/system.cpp:38-65`
- `audit/w124_operator_experience.md` (W124 — cross-ref for G26-G28)
