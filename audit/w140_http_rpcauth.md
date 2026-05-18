# W140 — HTTP server + rpcauth + cookie auth + JSON-RPC dispatch (lunarblock)

**Date:** 2026-05-18
**Wave:** W140 (discovery)
**Impl:** lunarblock (Lua / LuaJIT)
**Status:** **26 BUGS FOUND** (2 P0-SEC, 12 P1, 7 P2, 5 P3)

## Context

Audits lunarblock's HTTP/JSON-RPC server (`src/rpc.lua` HTTP-server section
~lines 8363-8590 + auth helpers ~lines 691-777) and the auth wire-up in
`src/main.lua` (~lines 14-176, 1993-2026) against:

* `bitcoin-core/src/httpserver.cpp` — libevent-backed HTTP listener,
  client allow-list (`ClientAllowed`/`InitHTTPAllowList`), bind plumbing
  (`HTTPBindAddresses`), libevent caps
  (`evhttp_set_max_headers_size = 8192`,
  `evhttp_set_max_body_size = MAX_SIZE = 32 MB`,
  `evhttp_set_timeout = DEFAULT_HTTP_SERVER_TIMEOUT = 30s`),
  work-queue / thread-pool dispatch
  (`DEFAULT_HTTP_THREADS = 16`, `DEFAULT_HTTP_WORKQUEUE = 64`,
  `HTTP_SERVICE_UNAVAILABLE` on overflow), prefix-vs-exact
  path-handler matching, `http_request_cb` early `HTTP_FORBIDDEN`
  on disallowed peer, `HTTP_BAD_METHOD` on `UNKNOWN` method.
* `bitcoin-core/src/httprpc.cpp` — JSON-RPC handler. POST-only
  (`HTTP_BAD_METHOD` otherwise), `Authorization: Basic` (Base64
  decode strict, colon-split, `TimingResistantEqual` for
  user+pass compare), `WWW-Authenticate: Basic realm="jsonrpc"`
  header on 401, 250 ms anti-brute-force sleep, `-rpcauth`
  (HMAC-SHA256(salt, password) hash compare), `-rpcwhitelist`
  per-user method allow-list, batch dispatch (`UniValue::VARR`),
  notifications (no response — but only when `jsonrpc:"2.0"` and
  no `id`; otherwise legacy v1 behavior responds), `HTTP_NO_CONTENT`
  for all-notifications batch, `JSONRPCError` HTTP status mapping
  (`-32600 → 400`, `-32601 → 404`, others → 500).
* `bitcoin-core/src/rpc/request.cpp` — `GenerateAuthCookie` (32 random
  bytes hex, `__cookie__:<hex>` written via `.tmp` + atomic rename,
  permissions per `-rpccookieperms`, fallback `0077` umask),
  `GetAuthCookie`, `DeleteAuthCookie`, `JSONRPCRequest::parse` (id
  optional, jsonrpc version 1.0 vs 2.0 dispatch, method must be string,
  params must be array/object/null).
* `bitcoin-core/src/rpc/server.cpp` — `JSONRPCExec`,
  `RPC_IN_WARMUP` gate, `RPC_INVALID_PARAMETER` on duplicate keys.
* `bitcoin-core/share/rpcauth/rpcauth.py` — Salt+HMAC tool used to
  generate `-rpcauth=user:salt$hmac` strings.
* `bitcoin-core/src/init.cpp` — `InitRPCAuthentication` (resolution
  order: `-rpcpassword` set → plain → auto-hash with random salt;
  otherwise `GenerateAuthCookie`; `-rpcauth` always merged in).

BIP refs: none. RPC framing is a Bitcoin Core convention, not a BIP.

## Method

1. Read Core references end-to-end.
2. Identify each end-to-end behavior (bind, allowlist, headers cap,
   body cap, timeout, Basic auth, cookie auth, rpcauth, whitelist,
   path routing, notification rules, batch rules, version
   negotiation, HTTP status mapping).
3. Synthesize 30 W140 gates.
4. Classify each gate against lunarblock’s `src/rpc.lua` HTTP-server,
   `parse_http_request`, `check_auth`, `handle_request`, the
   `RPCServer:tick()` body loop, and the auth wiring in `src/main.lua`.
5. Catalogue every divergence as a BUG with severity (P0-SEC for
   exploitable / authentication-bypass class; P1 for protocol or
   functional parity miss; P2 for client-observable behavior miss;
   P3 for ergonomic / surface miss).
6. Land xfail tests in `tests/test_w140_http_rpcauth.lua`.

## File map

* `src/rpc.lua:691-731` — `M.parse_http_request` (HTTP request parser).
* `src/rpc.lua:737-762` — `M.build_http_response` (status + body).
* `src/rpc.lua:768-777` — `M.check_auth` (Basic auth verifier).
* `src/rpc.lua:626-651` — `M.base64_decode` (used by `check_auth`).
* `src/rpc.lua:935-988` — `M.new(config)` (RPCServer constructor).
* `src/rpc.lua:1029-1195` — `handle_single_request` + `handle_request`
  (JSON-RPC dispatch, single/batch).
* `src/rpc.lua:8367-8424` — `_init_tls_context` (FIX-64, W119).
* `src/rpc.lua:8426-8590` — `start()` / `tick()` / `stop()` (server lifecycle).
* `src/main.lua:14-77` — `default_args()` (rpcuser/rpcpassword defaults).
* `src/main.lua:151-176` — CLI flag parser (`--rpcuser`/`--rpcpassword`/TLS).
* `src/main.lua:1993-2026` — RPC server config wire-up.

## 30 W140 audit gates

| Gate | Description | Status | Core ref |
|------|-------------|--------|----------|
| G1   | Bind to 127.0.0.1 by default; require explicit `--rpcbind`+`--rpcallowip` for non-loopback exposure | PARTIAL | bind hardcoded 127.0.0.1 ✓ but `--rpcbind`/`--rpcallowip` *flags do not exist* (BUG-1 P3) |
| G2   | `ClientAllowed`/`InitHTTPAllowList` — IPv4/v6 loopback always allowed; subnets parsed via `LookupSubNet` | **MISSING (BUG-2 P3)** | httpserver.cpp:137-168 — lunarblock has zero peer-address ACL machinery |
| G3   | `evhttp_set_max_headers_size(http, 8192)` — total header-block cap | **MISSING (BUG-3 P1)** | httpserver.cpp:51,409 — `tick()` reads headers in unbounded loop until empty line |
| G4   | `evhttp_set_max_body_size(http, 32 MB)` — body cap from `MAX_SIZE = 0x02000000` | **MISSING (BUG-4 P1 / borderline P0-SEC DoS)** | httpserver.cpp:410, serialize.h:34 — `tick()` blindly does `client:receive(content_length)` for whatever the client claims |
| G5   | `evhttp_set_timeout(http, 30s)` per-connection idle timeout | PARTIAL | client:settimeout(1) per-receive after headers; 5s for TLS handshake — no overall connection cap |
| G6   | Thread-pool dispatch with `DEFAULT_HTTP_WORKQUEUE = 64` and `HTTP_SERVICE_UNAVAILABLE` on overflow | **MISSING (BUG-5 P2)** | httpserver.cpp:255-258 — lunarblock is single-threaded serial tick; no overflow signaling |
| G7   | Path routing — `/` exact-match registers JSON-RPC; `/wallet/` prefix-match registers wallet-aware JSON-RPC; everything else `HTTP_NOT_FOUND` | PARTIAL | rpc.lua:8537-8541 wallet prefix ✓; but ALL non-`/health` POSTs reach JSON-RPC regardless of path (BUG-6 P2) — Core 404s |
| G8   | POST-only for JSON-RPC; non-POST returns `HTTP_BAD_METHOD` (405) | **MISSING (BUG-7 P2)** | httprpc.cpp:107-109 — lunarblock returns 404 for non-POST non-`/health` (rpc.lua:8575) |
| G9   | `Authorization: Basic ...` Base64 decode strict (`DecodeBase64` returns optional; `%4 != 0` rejected, invalid chars rejected) | PARTIAL | rpc.lua:626-651 silently drops invalid chars via `gsub`, treats missing as 0 (BUG-8 P2 — malleability, not exploitable) |
| G10  | `TimingResistantEqual` constant-time user+pass comparison | **MISSING (BUG-9 P0-SEC)** | httprpc.cpp:66,77 + strencodings.h:202-210 — lunarblock uses `decoded == expected` (rpc.lua:776) — timing-side-channel on rpcpassword |
| G11  | Empty `-rpcpassword` triggers cookie auth via `GenerateAuthCookie` (32 random hex bytes, `__cookie__:<hex>`, atomic rename, perms 0600) | **MISSING (BUG-10 P0-SEC)** | httprpc.cpp:245-268 + rpc/request.cpp:100-146 — lunarblock has no cookie generation at all. When `--rpcpassword` is empty (the default!), auth is **silently disabled** (rpc.lua:8529 `if self.password ~= ""` ) — every request 200s. |
| G12  | `-rpcauth=user:salt$hmac` HMAC-SHA256 hashed-password support; merged with `-rpcuser`/`-rpcpassword` | **MISSING (BUG-11 P1)** | httprpc.cpp:290-304 — no flag, no parsing, no HMAC verify |
| G13  | Plain `-rpcuser`/`-rpcpassword` is hashed in-process with a random salt; only the HMAC is retained for comparison | **MISSING (BUG-12 P1)** | httprpc.cpp:276-288 — lunarblock retains the plaintext password in `self.password` (rpc.lua:943) and compares plaintext on every request |
| G14  | `WWW-Authenticate: Basic realm="jsonrpc"` header on 401 | **MISSING (BUG-13 P2)** | httprpc.cpp:33,114,130 — lunarblock 401 reply has no `WWW-Authenticate` (rpc.lua:8530) — non-conformant per RFC 7235 §4.1; some clients (cURL `--anyauth`, httpie) won't retry with credentials |
| G15  | 250 ms `UninterruptibleSleep` on bad-password 401 (brute-force deterrent) | **MISSING (BUG-14 P1)** | httprpc.cpp:127-128 — no sleep; an unsleepy 401 lets an attacker run thousands of guesses/s, particularly on cookie format (`__cookie__:<64-hex>`) |
| G16  | `-rpcwhitelist=user:method,method` per-user method allow-list + `-rpcwhitelistdefault` | **MISSING (BUG-15 P1)** | httprpc.cpp:38-39,144-191,306-326 — no per-user method gating at all |
| G17  | JSON parse error → JSON-RPC `-32700 PARSE_ERROR`, HTTP 200 with error envelope (legacy) or 200 (v2) | PRESENT | rpc.lua:1102-1108 ✓ |
| G18  | JSON-RPC version negotiation — `jsonrpc:"1.0"` ⇒ v1-legacy, `"2.0"` ⇒ v2, otherwise raise `RPC_INVALID_REQUEST` | **MISSING (BUG-16 P1)** | request.cpp:214-230 — lunarblock never reads `request.jsonrpc` (rpc.lua:1033-1035) — all behavior is legacy-v1-shaped regardless of what the client claims |
| G19  | Notifications (`id` missing + `jsonrpc:"2.0"`) get no response; `HTTP_NO_CONTENT` (204) | PARTIAL (BUG-17 P1) | request.h:66 `IsNotification` is V2-only — lunarblock treats *any* missing id as a notification (rpc.lua:1038) regardless of `jsonrpc` field. Legacy v1.0 clients that omit `id` will get 204 from lunarblock and an actual response from Core. |
| G20  | Method-must-be-string validation, raise `RPC_INVALID_REQUEST -32600` on null/missing/non-string method | **MISSING (BUG-18 P1)** | request.cpp:233-238 — lunarblock returns `METHOD_NOT_FOUND -32601` for null/missing method (rpc.lua:1046-1051) — wrong code |
| G21  | Params type validation: array/object/null only; otherwise `RPC_INVALID_REQUEST` | **MISSING (BUG-19 P2)** | request.cpp:245-252 — lunarblock’s `params = request.params or {}` happily accepts strings/numbers/booleans as `params`, then the handler crashes via `INTERNAL_ERROR -32603` |
| G22  | Batch: `RPC_INVALID_REQUEST` on non-array element, executes others, `HTTP_NO_CONTENT` if all-notifications | PARTIAL | rpc.lua:1129-1151 ✓ for shape + 204; but max batch size is custom (1000) — Core has no max (BUG-20 P3) |
| G23  | HTTP status mapping for JSON-RPC errors: `-32600 → 400`, `-32601 → 404`, others → 500 | **MISSING (BUG-21 P1)** | httprpc.cpp:41-59 `JSONErrorReply` — lunarblock returns 200 for every JSON-RPC error envelope (no status override outside batch oversize), so clients can’t use the HTTP status code to route errors |
| G24  | After-shutdown requests get `HTTP_SERVICE_UNAVAILABLE` (503) via `http_reject_request_cb` | **MISSING (BUG-22 P3)** | httpserver.cpp:291-296 — lunarblock’s `stop()` just closes the socket; in-flight connections see EOF mid-response |
| G25  | `-rpccookieperms` + `-norpccookiefile` knobs | **MISSING — N/A bug-11** | rpc/request.cpp:88,247-256 — subsumed by BUG-10 |
| G26  | Bind error logging (warn-on-bind-fail / warn-on-bind-any) | PARTIAL | bind error from `assert()` in rpc.lua:8442 — crashes process with stack trace, no structured logging |
| G27  | `Content-Length: 0` and `Content-Length: <body length>` validated; reject if mismatch / multiple headers | PARTIAL | rpc.lua:8505-8506 parses Content-Length case-insensitively but last-wins on duplicates (BUG-23 — see below); no rejection on conflicting/duplicate (request-smuggling vector) (P1 BUG-23) |
| G28  | `Transfer-Encoding: chunked` handled correctly (or rejected if not supported) | **MISSING (BUG-24 P1)** | rpc.lua tick() never inspects `Transfer-Encoding` — a chunked POST will be silently mis-framed; body read by `Content-Length` (which is omitted for chunked) reads zero bytes ⇒ parse-error reply with HTTP 200 |
| G29  | TLS — libevent + OpenSSL with TLSv1.2+ baseline, ALPN, optional client cert | PARTIAL | FIX-64 (W119) wired luasec with TLSv1.2+ baseline ✓; no ALPN, no client cert, no `-rpcsslciphers`; "any" protocol with `no_tlsv1`/`no_tlsv1_1` options is fine. Minor (BUG-25 P3) — no negotiated-cipher logging |
| G30  | Pre-auth liveness/health endpoint — Core does **not** ship one; any deviation must justify the info disclosure | PARTIAL (BUG-26 P2) | `GET /health` (rpc.lua:8559-8566) leaks tip height and `version=lunarblock` to any unauthenticated client. Could fingerprint lunarblock and expose chain progress to a network-adjacent attacker. Distinct from Core. |

**Score:** 3 PRESENT / 8 PARTIAL / 19 MISSING.

## Bug list

### BUG-1 — `--rpcbind` / `--rpcallowip` flags do not exist (P3)

`src/main.lua:14-77` has no `--rpcbind` or `--rpcallowip` flag. The
RPC server is hardwired to `127.0.0.1` (rpc.lua:940, main.lua:1995).
An operator cannot expose the RPC server to a private subnet with the
usual Bitcoin pattern (`-rpcbind=10.0.0.2 -rpcallowip=10.0.0.0/24`).
For loopback-only deployments this is sufficient; otherwise the
operator has to port-forward through SSH or another reverse proxy.

**Severity:** P3. Operational gap, not a correctness gap.

---

### BUG-2 — No `ClientAllowed`/`InitHTTPAllowList` machinery (P3)

`bitcoin-core/src/httpserver.cpp:137-168` checks the peer's `CNetAddr`
against `rpc_allow_subnets` and replies `HTTP_FORBIDDEN` (403) before
any auth processing. lunarblock has no equivalent. Coupled with
BUG-1 (no `--rpcbind` non-loopback path) this is mitigated for the
default deployment, but if a future fix wave adds `--rpcbind`, the
allowlist must come with it.

**Severity:** P3 (paired with BUG-1).

---

### BUG-3 — No request-header-block size cap (P1)

`bitcoin-core/src/httpserver.cpp:51,409` caps headers at
`MAX_HEADERS_SIZE = 8192`. lunarblock's `tick()` reads
headers in an unbounded `while true do client:receive("*l")` loop
(rpc.lua:8500-8507) until an empty line is seen. A peer can stream
megabytes of headers; LuaSocket `receive("*l")` will keep buffering
each line.

**Severity:** P1 (memory DoS on a single connection; single-threaded
event loop blocks during the whole header read). Bounded only by
the 1s `settimeout(1)`.

---

### BUG-4 — No request body size cap (P1, borderline P0-SEC)

`bitcoin-core/src/httpserver.cpp:410` caps body via
`evhttp_set_max_body_size(http, MAX_SIZE)` where `MAX_SIZE =
0x02000000` (32 MB, serialize.h:34). lunarblock blindly does:

```lua
body_data = client:receive(content_length) or ""
```

…for whatever `content_length` the client claims, capped only by the
1s receive timeout. A peer can send `Content-Length: 4294967295` and
LuaSocket will try to buffer 4 GB; the timeout may abort the buffer
mid-allocate but a malicious peer can also slowly trickle bytes
within the 1s window per loop iteration.

**Severity:** P1, leaning P0-SEC because there is *no* cap and it's
network-reachable (even from loopback only — a compromised local
process can DoS the node).

---

### BUG-5 — No work-queue / thread-pool overflow signaling (P2)

`bitcoin-core/src/httpserver.cpp:255-258` returns
`HTTP_SERVICE_UNAVAILABLE` (503) when more than
`DEFAULT_HTTP_WORKQUEUE = 64` requests are queued.

lunarblock is intentionally single-threaded serial-tick (one accept
per main-loop tick, see comments at rpc.lua:8462-8466). When a slow
handler is running, all subsequent clients block on `accept()` (or
get dropped by LuaSocket's listen backlog of 32 at rpc.lua:8443).
Clients see TCP-level resets, not application-level 503.

**Severity:** P2. Functional parity gap for monitoring clients that
key off the HTTP 503 to back off.

---

### BUG-6 — Non-`/health` POSTs to any path are processed as JSON-RPC (P2)

`bitcoin-core/src/httpserver.cpp:236-251` walks `pathHandlers` looking
for a registered handler at the URI's prefix; only `/` (exact) and
`/wallet/` (prefix) are registered. Any other URI returns
`HTTP_NOT_FOUND` (404).

lunarblock's `tick()` ignores `path` once it's past the wallet
extraction:

```lua
if method == "POST" then
  local response_body, status_override = self:handle_request(body, wallet_name)
  ...
else
  client:send(M.build_http_response(404, '{"error":"Not found"}'))
end
```

So `POST /admin`, `POST /reset`, `POST /` and `POST /wallet/foo` all
dispatch to the same JSON-RPC handler. (Auth is still required, so
this is not a security bypass — it's a parity miss that breaks
clients that rely on a 404 to discover endpoint topology.)

**Severity:** P2.

---

### BUG-7 — Non-POST returns 404 instead of `HTTP_BAD_METHOD` (P2)

`bitcoin-core/src/httprpc.cpp:107-109` returns
`HTTP_BAD_METHOD (405)` with body
`"JSONRPC server handles only POST requests"` for non-POST requests.

lunarblock returns `HTTP_NOT_FOUND (404)` (rpc.lua:8575). Curl
clients that check status will not distinguish "wrong method" from
"endpoint doesn't exist".

**Severity:** P2.

---

### BUG-8 — Permissive Base64 decoder for the Authorization header (P2)

`bitcoin-core/src/util/strencodings.cpp:110-143` returns
`std::nullopt` on:
* `str.size() % 4 != 0`
* any non-Base64 character

lunarblock's `M.base64_decode` (rpc.lua:626-651):
* silently strips invalid characters via `gsub("[^%w%+/=]", "")`
* treats missing characters as 0 (`or 0`)

So `Basic <garbage>` decodes to garbage rather than failing
explicitly. The comparison at rpc.lua:776 still requires equality to
`user:pass` so this is not directly exploitable, but it's a
divergence from Core's strict semantics. If a future change ever
compares the *decoded* bytes against something other than the
expected user:pass (e.g. logs the user), an attacker could inject
arbitrary bytes.

**Severity:** P2 (malleability, defense-in-depth).

---

### BUG-9 — Non-constant-time password comparison (P0-SEC) ⚠️

`bitcoin-core/src/httprpc.cpp:66,77` uses
`TimingResistantEqual(std::string_view, std::string_view)` for the
user comparison AND for the HMAC-output comparison
(`bitcoin-core/src/util/strencodings.h:202-210`).

lunarblock's `M.check_auth` (rpc.lua:776):

```lua
return decoded == expected
```

Lua's `==` on strings short-circuits on the first byte mismatch.
This leaks a timing side channel proportional to the matching
prefix length of the user:pass payload.

For a 64-character hex cookie password, a network-side attacker
with sufficient sampling can recover the cookie one byte at a time
in O(64 * 256) = ~16k requests. From localhost the timing
resolution may be too coarse for full recovery, but from a remote
network with even modest jitter the leak is real.

Since lunarblock is by default loopback-only this is **localhost-only
exploitable** today — a malicious local process can recover the RPC
password (or rpcuser) via timing. Still P0-SEC because the entire
point of authentication is to defend against local-process
escalation.

**Fix shape:** implement a constant-time compare (XOR-and-accumulate
over equal-length buffers; reject differing lengths first).

**Severity:** P0-SEC.

---

### BUG-10 — Empty rpcpassword bypasses authentication entirely (P0-SEC) ⚠️⚠️⚠️

The most critical finding.

`src/main.lua:20` defaults `args.rpcpassword = ""`.
`src/rpc.lua:943` carries that into `self.password`.
`src/rpc.lua:8529`:

```lua
if self.password ~= "" and not M.check_auth(headers, self.username, self.password) then
```

If the operator never sets `--rpcpassword`, the condition is false
and **the auth check is skipped**. Every POST is accepted without
credentials, including wallet operations (`sendtoaddress`,
`dumpprivkey`, `signmessage` …) on whatever wallet is loaded.

In Bitcoin Core, an empty `-rpcpassword` triggers
`GenerateAuthCookie` (httprpc.cpp:245-268) which writes a `.cookie`
file with 32 cryptographically random bytes as the password.
Clients without filesystem access to the datadir cannot
authenticate.

**Combined with the default `metricsport = 9332` bind on `0.0.0.0`
(out of scope for W140 but observed) and BUG-4 (no body cap), an
operator running lunarblock with default flags has:**
* RPC server on loopback with no auth → any local process can drain
  the wallet.
* Metrics server on 0.0.0.0 with no auth → anyone on the LAN can
  scrape chain height / mempool size.

**Fix shape:** when `rpcpassword == ""`, generate a `.cookie` file in
the datadir with `__cookie__:<32 random bytes hex>` content
(`bitcoin-core/src/rpc/request.cpp:100-146`); use a temp+rename for
atomicity; persist that user/password pair as `self.username` and
`self.password` so the auth check is always non-empty.

**Severity:** P0-SEC. **Default install is auth-bypassed.**

---

### BUG-11 — No `-rpcauth=user:salt$hmac` support (P1)

`bitcoin-core/src/httprpc.cpp:290-304` parses one or more
`-rpcauth=user:hex_salt$hex_hmac` lines and accepts any matching
user/HMAC combination. Many multi-user / hardened deployments
(cold-storage signing, monitoring + read-only ops, etc.) depend on
this — it lets bitcoin.conf hold the hashed credential rather than
the plaintext password.

lunarblock has no `--rpcauth` flag, no HMAC support, no salt
support. There's no parallel mechanism either (e.g. a hashed-
password file).

**Severity:** P1. Real-world operational requirement.

---

### BUG-12 — Plaintext password retained in memory and compared per request (P1)

`bitcoin-core/src/httprpc.cpp:276-288` immediately HMAC-hashes the
plaintext `-rpcpassword` with a fresh random salt and discards the
plaintext. Only `(user, salt, hmac)` is retained in `g_rpcauth`.

lunarblock's `self.password` (rpc.lua:943) is the plaintext from
`args.rpcpassword`. It lives in the LuaJIT VM for the lifetime of
the process. A core dump or LuaJIT FFI memory exposure (e.g. via a
parser bug) would expose the credential. Comparing the same
plaintext on every request also forfeits the *defense in depth*
provided by the HMAC.

**Severity:** P1.

---

### BUG-13 — No `WWW-Authenticate: Basic realm="jsonrpc"` on 401 (P2)

`bitcoin-core/src/httprpc.cpp:33,114,130` always sends:

```
WWW-Authenticate: Basic realm="jsonrpc"
```

on every 401 response.

lunarblock just sends `HTTP/1.1 401 Unauthorized` with body
`{"error":"Unauthorized"}` and no WWW-Authenticate header
(rpc.lua:8530). Per RFC 7235 §4.1 a 401 response **must** carry a
WWW-Authenticate header. Clients like curl with `--anyauth`
inspect WWW-Authenticate to decide which scheme to try; without it
they may not retry with credentials.

**Severity:** P2.

---

### BUG-14 — No anti-brute-force 250 ms sleep on bad auth (P1)

`bitcoin-core/src/httprpc.cpp:127-128`:

```cpp
UninterruptibleSleep(std::chrono::milliseconds{250});
```

…on every failed auth attempt. This caps bad-password attempts at
4/s/connection (Core's thread pool can serve several in parallel
but each one blocks 250 ms).

lunarblock has no such sleep. On a fast local socket an attacker
can drive thousands of guesses/second. Coupled with BUG-9 (timing
side channel) and BUG-10 (default no-auth) the brute-force surface
is wide.

**Severity:** P1. (P0-SEC if combined with non-loopback exposure,
but the current loopback-only binding mitigates.)

---

### BUG-15 — No per-user method whitelist (`-rpcwhitelist`) (P1)

`bitcoin-core/src/httprpc.cpp:38-39,144-191,306-326` implements:
* `-rpcwhitelist=user:method1,method2` — restrict per-user.
* `-rpcwhitelistdefault=1` — deny-by-default, allowlist must opt-in.

Operators that want a "monitoring user" with only
`getblockcount`/`getmempoolinfo` allowed have no way to express
that in lunarblock. Once authenticated, every method is callable
(including `dumpprivkey`, `walletpassphrase`, etc.).

**Severity:** P1.

---

### BUG-16 — `jsonrpc` field is never read (P1)

`bitcoin-core/src/rpc/request.cpp:214-230` parses
`request.jsonrpc`; only `"1.0"` and `"2.0"` are accepted, others
raise `RPC_INVALID_REQUEST`.

lunarblock never inspects `request.jsonrpc` (rpc.lua:1033-1035 only
reads `method`, `params`, `id`). Two consequences:

1. The server cannot distinguish v1 legacy clients from v2 clients,
   which forces wrong behavior at G19 (notifications).
2. A v2 client gets v1-shaped error envelopes (`error.code` instead
   of `error.code` *and* `error.data`, plus the v2 spec mandates
   `jsonrpc: "2.0"` on the response — lunarblock's response is also
   missing that field).

**Severity:** P1.

---

### BUG-17 — Notifications fire on missing id regardless of jsonrpc version (P1)

`bitcoin-core/src/rpc/request.h:66`:

```cpp
bool IsNotification() const {
    return !id.has_value() && m_json_version == JSONRPCVersion::V2;
}
```

Notifications require **both** missing id **and** jsonrpc v2.

lunarblock (rpc.lua:1038):

```lua
local is_notification = (id == nil)
```

Any v1.0 (or version-unspecified) client that omits `id` gets a
`HTTP_NO_CONTENT` (204) reply, where Core would respond with a real
result envelope. This breaks bitcoin-cli compatibility tests that
omit `id` on simple calls and expect a result back.

**Severity:** P1.

---

### BUG-18 — Wrong error code for null/missing method (P1)

`bitcoin-core/src/rpc/request.cpp:233-238` raises
`RPC_INVALID_REQUEST (-32600)` when `method` is null or non-string.

lunarblock falls through to the dispatch table lookup with
`method = nil`:

```lua
local handler = self.methods[method]  -- nil index → nil
if not handler then
  ...
  return {
    error = {code = M.ERROR.METHOD_NOT_FOUND, message = ...},  -- -32601
  }
end
```

So a JSON request with `{"jsonrpc":"2.0","id":1}` (no method) gets
`-32601 METHOD_NOT_FOUND` instead of `-32600 INVALID_REQUEST`.

**Severity:** P1. Wrong code per JSON-RPC spec.

---

### BUG-19 — Non-array/non-object params are silently accepted (P2)

`bitcoin-core/src/rpc/request.cpp:245-252`:

```cpp
if (valParams.isArray() || valParams.isObject())
    params = valParams;
else if (valParams.isNull())
    params = UniValue(UniValue::VARR);
else
    throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array or object");
```

lunarblock (rpc.lua:1034):

```lua
local params = request.params or {}
```

Passes through whatever shape `params` has. If `params` is a
string `"hello"`, the handler will likely throw a Lua type error
deep inside, surfacing as `-32603 INTERNAL_ERROR` rather than the
correct `-32600 INVALID_REQUEST`.

**Severity:** P2.

---

### BUG-20 — Custom hard cap of 1000 on batch size (P3)

lunarblock enforces `MAX_BATCH_SIZE = 1000` at rpc.lua:1027,1118.
Core has no per-batch hard cap (only `MAX_SIZE = 32 MB` body cap).
Clients sending batches close to or above 1000 will see lunarblock-
specific 400s.

**Severity:** P3. Custom hard caps are common; flagged only because
Core has no such limit.

---

### BUG-21 — JSON-RPC errors return HTTP 200 instead of mapping to HTTP status (P1)

`bitcoin-core/src/httprpc.cpp:41-59` `JSONErrorReply`:

```cpp
int nStatus = HTTP_INTERNAL_SERVER_ERROR;       // 500 default
int code = objError.find_value("code").getInt<int>();
if      (code == RPC_INVALID_REQUEST)  nStatus = HTTP_BAD_REQUEST;   // 400
else if (code == RPC_METHOD_NOT_FOUND) nStatus = HTTP_NOT_FOUND;     // 404
```

lunarblock returns HTTP 200 for every JSON-RPC error envelope (the
only HTTP status override path is "batch too large" → 400 in
rpc.lua:1124, and 204 for notifications). Clients that route on
HTTP status get the wrong signal.

**Severity:** P1.

---

### BUG-22 — Shutdown drops in-flight requests instead of returning 503 (P3)

`bitcoin-core/src/httpserver.cpp:291-296` swaps the request callback
to `http_reject_request_cb` after shutdown begins, replying
`HTTP_SERVICE_UNAVAILABLE`. lunarblock's `stop()` just closes the
socket (rpc.lua:8584-8589). Clients with an in-flight read see
TCP EOF mid-response.

**Severity:** P3.

---

### BUG-23 — Duplicate `Content-Length` header silently last-wins (P1)

`src/rpc.lua:8505-8506` parses Content-Length in a loop inside
`tick()`, and `M.parse_http_request` (line 717-719) overwrites on
duplicate headers (`headers[key:lower()] = value`). Per RFC 7230
§3.3.2, duplicate `Content-Length` is a smuggling vector and must
be rejected. Combined with the `Transfer-Encoding` gap (BUG-24)
this is the classic CL.TE / TE.CL request-smuggling primitive.

For a loopback-only server with no upstream proxy this is mostly
hypothetical, but if a reverse proxy is ever placed in front of
lunarblock (TLS terminator, IP allowlist enforcer) this becomes a
real smuggling vector.

**Severity:** P1.

---

### BUG-24 — `Transfer-Encoding: chunked` not handled and not rejected (P1)

lunarblock's `tick()` never inspects `Transfer-Encoding`. A
`POST / HTTP/1.1` with `Transfer-Encoding: chunked` and no
`Content-Length` will:
1. Default content_length to 0.
2. Read zero body bytes.
3. `parse_http_request` returns method/path/headers/empty-body.
4. `cjson.decode("")` fails ⇒ `-32700 PARSE_ERROR` response.

The leftover chunked body bytes remain on the socket, but the
server has already closed via `client:close()`. No actual
smuggling because there's no upstream proxy, but if one is added
(BUG-23 partner) the smuggling lands.

Core via libevent handles chunked transparently.

**Severity:** P1.

---

### BUG-25 — TLS lacks ALPN, client-cert support, and cipher logging (P3)

FIX-64 (W119) wired luasec with TLSv1.2+ baseline ✓, but:
* No ALPN advertising `http/1.1`.
* No `--rpc-tls-cacert` for client-cert verification (Core path is
  similar — most deployments don't use client certs).
* No negotiated cipher / protocol logged on each handshake.

**Severity:** P3.

---

### BUG-26 — Pre-auth `/health` discloses tip height and impl version (P2)

`src/rpc.lua:8559-8566`:

```lua
if method == "GET" and path == "/health" then
  local height = (self.chain_state and self.chain_state.tip_height) or -1
  local body = string.format(
    '{"status":"ok","height":%d,"version":"lunarblock"}\n', height)
```

* `tip_height` is sensitive — a remote attacker on the same subnet
  can detect IBD completion / stall / reorg.
* `version=lunarblock` lets an attacker fingerprint the impl
  (distinct from "bitcoind") to pick exploits targeted at this code.

Core has no `/health` endpoint at all. The endpoint is documented
as a supervisor liveness probe (comments at rpc.lua:8552-8558), but
the disclosure is broader than necessary. A correct shape would be
`{"status":"ok"}` with no version, and gated to bind-equal-loopback
(i.e. only respond if peer IP is loopback).

**Severity:** P2.

---

## Most-impactful findings (security summary)

### P0-SEC

1. **BUG-10 — default install is auth-bypassed** when operator
   doesn't set `--rpcpassword`. Empty password skips auth check
   (`self.password ~= ""` short-circuit, rpc.lua:8529). Core
   auto-generates a `.cookie` file in this case (Core
   `httprpc.cpp:245-268`).
2. **BUG-9 — non-constant-time password compare** at rpc.lua:776
   (`decoded == expected`). Lua string `==` short-circuits at first
   byte mismatch, leaking a timing oracle. Core uses
   `TimingResistantEqual` (`util/strencodings.h:202-210`).

### P1 borderline P0-SEC

3. **BUG-4 — no body size cap.** A 1-byte connection can claim
   `Content-Length: 4294967295` and force LuaSocket to attempt a 4 GB
   buffer. Core caps via `evhttp_set_max_body_size(http, MAX_SIZE)`
   = 32 MB.
4. **BUG-14 — no 250 ms anti-brute-force sleep** on failed auth.
   Combined with BUG-9 and BUG-10 makes credential-recovery /
   guessing trivial on a fast local socket.

## Concurrent-wave coordination

Three other audit waves run in parallel. This audit touches:

* New: `audit/w140_http_rpcauth.md`
* New: `tests/test_w140_http_rpcauth.lua`

…neither of which collides with the W134/W135/W136/W137/W138/W139
audits. Common files this wave reads but does NOT modify:

* `src/rpc.lua` — read for HTTP-server section, `parse_http_request`,
  `check_auth`, `base64_decode`, `handle_request`, `handle_single_request`.
* `src/main.lua` — read for arg parser and RPC server wire-up.

No production source is changed.

## Reproducibility

```bash
cd /home/work/hashhog/lunarblock
luajit tests/test_w140_http_rpcauth.lua
```

Expected output: G1-G30 gates printed, xfail markers for BUG-1 … BUG-26
flagged paths, plain PASS for the few present gates.

## Out-of-scope (separate future waves)

* Prometheus metrics binding on `0.0.0.0` (main.lua:2053) — adjacent
  but distinct subsystem. Worth a separate P0-SEC fix wave.
* REST server (`src/rest.lua`) — runs without auth by Core parity
  (Core's REST is the same), but lunarblock's REST is BOUND to
  127.0.0.1 only (main.lua:2034) so the surface is constrained.
* ZMQ pub/sub auth — none today, but Core also ships ZMQ without
  auth.
* `getrpcinfo` / `help` RPC parity — covered in W125.
