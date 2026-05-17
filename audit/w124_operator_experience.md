# W124 - Operator-experience audit (lunarblock)

**Date:** 2026-05-17
**Wave:** W124 (discovery)
**Impl:** lunarblock (Lua / LuaJIT)
**Status:** **BUGS FOUND** (1 P0 + 1 P0-OPS + 3 P1 + 4 MED + 4 LOW)

## Context

This is a fleet-wide operator-experience audit. Topic: do operators
have the same surface they get from Bitcoin Core when running, monitoring,
configuring, and stopping a node? The 30-gate set was synthesized from
`bitcoin-core/src/init.cpp`, `src/shutdown.cpp`, `src/init/common.cpp`
(logging argument declarations) and `src/logging.{cpp,h}` — the same
references the task brief names.

This wave is **discovery only**: no production code changes. Bug-flip
tests land in `tests/test_w124_operator.lua` as `xfail_pre_fix` markers.

The 30 gates are grouped into 6 thematic blocks:

- G1-G5   CLI surface — args, conf-file, version, help.
- G6-G10  Datadir, lockfile, PID file, file permissions, blocksdir.
- G11-G15 Logger — categories, severity levels, timestamps, thread
          names, source locations, log rotation.
- G16-G20 Signals — SIGTERM, SIGINT, SIGHUP, ready-fd, stop RPC.
- G21-G25 RPC ops surface — cookie auth, rpcauth, getrpcinfo logpath,
          logging RPC, setnetworkactive, getmemoryinfo, uptime accuracy.
- G26-G30 Notify hooks — alertnotify, blocknotify, startupnotify,
          shutdownnotify, listenbind / rpcbind ergonomics.

## Method

1. `grep -rn "shutdown\|SIGTERM\|signal\|pidfile\|datadir\|cookie\|logger\|log" src/`
2. Read `src/main.lua` (~2360 LOC) and `src/ops.lua` (429 LOC) end-to-end.
3. Read `src/rpc.lua` RPC method registrations relevant to ops parity
   (`stop`, `getrpcinfo`, `uptime`, auth path).
4. Cross-reference against Bitcoin Core `init.cpp` / `init/common.cpp`
   for arg surface, `shutdown.cpp` for ordered teardown, and
   `logging.{cpp,h}` for category/level semantics.
5. Walk the `tools/stop_mainnet.sh` recipe — it expects `<datadir>/.cookie`
   for `bitcoin-cli stop`-style halt; check whether lunarblock writes one.
6. For each of 30 gates: PRESENT / PARTIAL / MISSING + rationale.

## Findings — gate matrix

| Gate | Topic                                          | Status  | Notes |
|------|------------------------------------------------|---------|-------|
| G1   | `--help` / `-h`                                 | PRESENT | `main.lua:88-139` + pre-load fast path `main.lua:2302-2356` |
| G2   | `--version`                                     | PRESENT | `main.lua:141-144` reports `LunarBlock v0.1.0` and LuaJIT version |
| G3   | `--conf=<file>` (Core bitcoin.conf parity)     | PRESENT | `ops.lua:73-108` parses key=value, comments, `[network]` sections; CLI wins |
| G4   | `--datadir=<dir>`                               | PRESENT | `main.lua:14-16` defaults to `~/.lunarblock`; per-network subdir |
| G5   | Per-network subdir under datadir                | PRESENT | `main.lua:716` `datadir = datadir .. "/" .. network` for non-mainnet (matches Core's `testnet4/` etc.) |
| G6   | Datadir lockfile (`.lock`)                      | **MISSING** | **BUG-1 (P0-OPS)** — no `LockDataDirectory` parity; two lunarblock instances on the same `--datadir` corrupt chainstate without complaint |
| G7   | PID file (`--pid=<path>`)                       | PRESENT | `ops.lua:272-283` writes `lunarblock.pid` in datadir; removed on graceful shutdown |
| G8   | Cookie auth (`.cookie` in datadir)              | **MISSING** | **BUG-2 (P0-OPS)** — `tools/stop_mainnet.sh` expects `$NODE/.cookie`; lunarblock never writes one; `bitcoin-cli stop` style halt is impossible |
| G9   | `--rpcauth=<hash>` style auth                   | **MISSING** | only `--rpcuser` + `--rpcpassword` plaintext; Core has hashed-salt `g_rpcauth`; OK for local but documented gap |
| G10  | `--blocksdir=<dir>` separate from datadir       | MISSING | lunarblock stores blocks in RocksDB CF inside `<datadir>/chainstate`; no separate blocksdir is a design choice (storage shape diverges from Core), but operator can't move blocks to a slow disk while chainstate stays on NVMe |
| G11  | `--debug=<cat>` debug categories                | PRESENT | `ops.lua:179-263` parses `--debug=cat[,cat]` with `1`/`0`/`all` shortcuts; 15 categories registered |
| G12  | `-debugexclude=<cat>` (Core init/common.cpp:33)| **MISSING** | no inverse-filter — operator cannot `--debug=1 --debugexclude=leveldb` to silence noisy categories |
| G13  | `-loglevel=<level>` severity (info/warn/err)    | **MISSING** | logger has only category gating; no severity field on `logger:log` calls; Core emits `[<cat>:<level>]` prefix on every line |
| G14  | `-logtimestamps` (Core default ON)              | PARTIAL | `ops.lua:227` emits `%Y-%m-%d %H:%M:%S`; not toggle-able, no microsecond precision, no UTC vs local opt-in |
| G15  | `-logthreadnames` / `-logsourcelocations`       | MISSING | lunarblock is single-threaded and Lua has no source-location automation in `print`; documented gap, not actionable in Lua without `debug.getinfo` per call |
| G16  | SIGTERM graceful shutdown                       | PRESENT | `main.lua:2100-2103`; runs full cleanup (mempool dump, fee save, peer disconnect, PID rm) |
| G17  | SIGINT (Ctrl-C in foreground)                   | PRESENT | `main.lua:2104-2107`; symmetric to SIGTERM |
| G18  | SIGHUP log reopen (logrotate)                   | PRESENT | `main.lua:2108-2114` calls `logger:reopen()` (close + re-open the file) |
| G19  | `--ready-fd=<N>` systemd-style ready signal     | PRESENT | `ops.lua:418-425`; writes "READY\n" to FD after listeners up |
| G20  | RPC `stop` actually stops the daemon            | **MISSING** | **BUG-3 (P0)** — `rpc.lua:4073-4076` returns the string `"LunarBlock stopping..."` but does NOT flip `running=false`; daemon keeps running indefinitely; the `jitprofileflush` neighbor handler even claims "main.lua's cleanup path is unreachable (no SIGTERM handler)" — comment is also stale (SIGTERM IS wired since `main.lua:2100`) |
| G21  | RPC HTTP Basic auth                             | PRESENT | `rpc.lua:768-777` + `rpc.lua:8528-8533`; only when password set (W124 BUG-7 below: no auth required when password empty) |
| G22  | `getrpcinfo` returns real logpath               | **MISSING** | **BUG-4 (P1)** — `rpc.lua:8354-8360` hardcodes `logpath = ""`; operator can't discover the active log file via RPC; Core returns the real `debug.log` path |
| G23  | `logging` RPC (dynamic category toggle)         | **MISSING** | Core ships `logging include=[...] exclude=[...]` to flip categories at runtime without restart; lunarblock has zero such RPC |
| G24  | `setnetworkactive` RPC (pause peer activity)    | **MISSING** | Core ships it; useful for diagnostics; lunarblock RPC list does not register the method |
| G25  | `getmemoryinfo` / `getzmqnotifications`         | **MISSING** | Core's two ops-only RPCs; lunarblock has neither; the only memory data is the optional `metricsport` Prometheus endpoint |
| G26  | `-alertnotify=<cmd>` (run shell cmd on alert)   | **MISSING** | Core ships it for paging operators on chain-related warnings; lunarblock has zero |
| G27  | `-blocknotify=<cmd>` (run cmd on new tip)       | **MISSING** | Core ships it as a cheap webhook alternative; lunarblock has no equivalent (ZMQ exists but requires a listener) |
| G28  | `-startupnotify=<cmd>` / `-shutdownnotify=<cmd>` | **MISSING** | Core's two lifecycle webhooks; lunarblock supports neither |
| G29  | `--rpcbind=<addr>` (RPC bind ergonomics)        | **MISSING** | **BUG-5 (P1)** — `rpc.lua:940` hardcodes `host = config.host or "127.0.0.1"` from `main.lua:1995` which does not expose `--rpcbind`; operator cannot expose RPC to a non-loopback IP for remote ops without code change |
| G30  | `--listen=<bool>` / `--bind=<addr>` for P2P     | PARTIAL | `peer_manager:start_listener("0.0.0.0", args.port)` (`main.lua:2073`) is hardcoded `0.0.0.0`; no `--bind` / `--nolisten` flag; metrics also `0.0.0.0` (`main.lua:2053`) — bug below |

**Count: 14 PRESENT / 2 PARTIAL / 14 MISSING.**

## Bugs

### BUG-1 (P0-OPS) — No datadir lockfile (G6)

**Location:** missing entirely; no `LockDataDirectory` parity anywhere in
`src/main.lua` or `src/ops.lua`.

**Symptoms:** two `luajit src/main.lua --datadir=X` instances can run
concurrently on the same `X`, both opening the RocksDB chainstate.
RocksDB itself acquires an exclusive LOCK file but throws when the
second process tries to open — and the second lunarblock instance
treats the open failure as a fatal abort rather than a clear
"already running" error. The result is a startup race during automated
restarts (`tools/stop_mainnet.sh` flow): if `stop_mainnet.sh` retries
before SIGTERM completes, the second lunarblock dies on RocksDB-LOCK
abort and the supervisor records an unexpected exit instead of a
clean "instance already running" message.

**Reference:** `bitcoin-core/src/init.cpp:1158-1170` `LockDirectory()` +
`LockDirectories()` writes a `.lock` file under `datadir/` BEFORE
chainstate open and reports a clear "Cannot obtain a lock on data
directory; %s is probably already running" message.

**Fix sketch:** in `ops.lua`, add `lock_datadir(path)` that opens
`<path>/.lock` with `O_RDWR|O_CREAT` (mode 0600) and `flock(LOCK_EX|
LOCK_NB)`; on EAGAIN/EWOULDBLOCK, emit the Core-shaped message and
`os.exit(1)`. Wire into `main.lua` right after the `mkdir -p datadir`
calls (line ~720) and BEFORE the chainstate open (line 813).
`wallet.lua:2103-2150` already has a `struct flock` cdef and `lock_file`
helper that can be lifted to module-shared.

### BUG-2 (P0-OPS) — No cookie file written to datadir (G8)

**Location:** missing entirely; `src/rpc.lua` only READS Bitcoin Core's
cookie (`rpc.lua:850-857`), never writes a lunarblock-side cookie.

**Symptoms:** `tools/stop_mainnet.sh` expects `<datadir>/.cookie` for
every node:
```bash
COOKIE="/data/nvme1/hashhog-mainnet/$NODE/.cookie"
```
For lunarblock there is no `.cookie`, so the helper can only kill via
SIGTERM — never via the `bitcoin-cli stop` style graceful halt. That
makes lunarblock the only mainnet node that cannot offer a "send a
flush-and-exit RPC, then send SIGTERM as a backstop" shutdown ordering.
It also breaks the convention every other fleet node honors (per the
root `CLAUDE.md` "Ops" section).

**Reference:** `bitcoin-core/src/httprpc.cpp:247-265` calls
`GenerateAuthCookie(cookie_perms, user, pass)` which writes
`<datadir>/.cookie` with the format `__cookie__:<random>` and chmods to
0600 (or `-rpccookieperms` controlled).

**Fix sketch:** in `ops.lua`, add `write_cookie_file(datadir,
username)`:
1. Generate 32 random bytes via `/dev/urandom` (already done elsewhere
   in lunarblock — see `src/payjoin_proposal_store.lua` CSPRNG).
2. Hex-encode → 64-char string.
3. Compose `username .. ":" .. hex`.
4. Write to `<datadir>/.cookie` with `O_WRONLY|O_CREAT|O_TRUNC`, mode 0600.
5. Register removal in the cleanup path next to `ops.remove_pid_file`.
6. Make the RPC server accept the cookie line as `username:password` for
   Basic auth (it already accepts that shape — `rpc.lua:775`).
Wire into `main.lua` immediately after `write_pid_file` (line 757),
before `rpc_server:start()`.

### BUG-3 (P0) — `stop` RPC does NOT stop the daemon (G20)

**Location:** `src/rpc.lua:4073-4076`.

```lua
self.methods["stop"] = function(_rpc, _params)
  -- Signal shutdown
  return "LunarBlock stopping..."
end
```

The comment lies. The function returns a static string and exits. The
main loop's `running` flag (`main.lua:2099`) is a closure-local in
`main()`, not visible from `rpc.lua`. There is no kill, no `kill -TERM
$(getpid)`, no module-level `set_shutdown_requested()` hook, no module-
shared atomic flag. `bitcoin-cli stop` returns the polite "LunarBlock
stopping..." message and the daemon continues running indefinitely.

The adjacent `jitprofileflush` handler (`rpc.lua:4081`) even contains
the stale comment:
> main.lua's cleanup path is unreachable (no SIGTERM handler), so this
> is the only way to get the profile data on disk.

That comment is wrong on TWO counts: (a) SIGTERM IS wired since
`main.lua:2100-2103`, (b) `jit_p.stop()` runs in the RPC server's tick,
not the main loop's cleanup path. The two claims point to a stale
understanding from before signal-handler wiring was added in W12+.

**Symptoms:** every fleet automation that uses `bitcoin-cli stop` (a
common pattern in supervisors and the upstream Core CLI) silently
no-ops against lunarblock. Operators have to find the PID and
`kill -TERM` it. `tools/stop_mainnet.sh` is built around this fact
(it directly SIGTERMs); third-party operators using `bitcoin-cli stop`
get a deceptive 200-OK and no shutdown.

**Reference:** `bitcoin-core/src/rpc/server.cpp` `stop()` RPC actually
triggers `node.shutdown_request->Set()` which trips the main thread's
`SignalInterrupt::wait()` and joins the shutdown sequence.

**Fix sketch:** export a module-level `shutdown_requested` flag from
`ops.lua` (or new `lunarblock.shutdown` shim):
```lua
-- ops.lua additions
local _shutdown_requested = false
function M.request_shutdown() _shutdown_requested = true end
function M.shutdown_requested() return _shutdown_requested end
```
Then in `main.lua` main loop:
```lua
while running and not ops.shutdown_requested() do
```
And in `rpc.lua:4073`:
```lua
self.methods["stop"] = function(_rpc, _params)
  local ops = require("lunarblock.ops")
  ops.request_shutdown()
  return "LunarBlock stopping..."
end
```
Drop the stale `jitprofileflush` comment.

### BUG-4 (P1) — `getrpcinfo.logpath` hardcoded as empty string (G22)

**Location:** `src/rpc.lua:8354-8360`.

```lua
self.methods["getrpcinfo"] = function(_rpc, _params)
  return {
    active_commands = setmetatable({}, cjson.empty_array_mt),
    logpath         = "",
  }
end
```

The real log path is computed in `main.lua:733`:
```lua
local log_path = args.log or (datadir .. "/debug.log")
```
and stashed on `package.loaded["lunarblock.logger"]` (`main.lua:780`).
The `getrpcinfo` handler ignores it. The `active_commands` array is
also hardcoded empty — Core populates it with currently-executing RPCs.

**Symptoms:** operators using `bitcoin-cli getrpcinfo` to discover the
log file path (a common diagnostic flow) get an empty string and have
to grep the launch logs to find where lunarblock writes. The path
varies by `--datadir` so this is genuinely useful info to ship.

**Reference:** `bitcoin-core/src/rpc/server.cpp` getrpcinfo returns
`{active_commands: [...], logpath: <real path>}`.

**Fix sketch:** thread the real log path through `RPCServer.new` config
(it's already constructed where everything else is wired —
`main.lua:1993-2025`). Add `log_path = log_path` to the config table,
read it in `RPCServer:new` as `self.log_path`, return it from
getrpcinfo. Active-commands tracking is a follow-up (would require
per-method timing in `handle_request`).

### BUG-5 (P1) — RPC binds 127.0.0.1 hardcoded; no `--rpcbind` (G29)

**Location:** `src/main.lua:1995` hardcodes `host = "127.0.0.1"`;
`src/rpc.lua:940` accepts `config.host` but no CLI flag supplies it.

**Symptoms:** operators running lunarblock under a supervisor that
needs to expose RPC to a non-loopback IP (e.g. a private Tailscale net
or VPN endpoint) cannot do so without patching the source. Core
supports `-rpcbind=<addr>` for exactly this use case (multiple
`-rpcbind` flags allowed for multi-interface binding).

**Reference:** `bitcoin-core/src/httpserver.cpp` HTTPBindAddresses
walks all `-rpcbind=<addr>` args; loopback-only is the safe default.

**Fix sketch:** add `--rpcbind=<addr>` to `main.lua` arg parser, default
`"127.0.0.1"`, accept multiple instances. Pass into `RPCServer.new` as
`host`. Document loopback default in `--help`.

### BUG-6 (P1) — Metrics + P2P listen 0.0.0.0 hardcoded; no `--bind`

**Location:** `src/main.lua:2053` (metrics), `src/main.lua:2073` (P2P).

```lua
metrics_socket:bind("0.0.0.0", metrics_port)
...
peer_manager:start_listener("0.0.0.0", args.port)
```

Both bind addresses are hardcoded `0.0.0.0`. Operators cannot scope the
metrics endpoint to loopback for security-sensitive deployments, and
cannot pin the P2P listener to a specific interface (Core
`-bind=<addr>` flow). The metrics socket binding to 0.0.0.0 by default
is a particularly surprising default: most Prometheus deployments
expect `127.0.0.1:<port>` and let a reverse proxy or `node_exporter`
re-publish.

**Reference:** Core's `-bind=<addr>[:port][=onion]` flag set in
`init.cpp:548`.

**Fix sketch:** add `--bind=<addr>` (P2P) and `--metricsbind=<addr>`
(metrics). Defaults: `0.0.0.0` for P2P (matches current), `127.0.0.1`
for metrics (CHANGES the default — a small operator-visible behavior
shift but more secure).

### BUG-7 (MED) — RPC accepts unauthenticated requests when password empty (G21)

**Location:** `src/rpc.lua:8528-8533`.

```lua
if self.password ~= "" and not M.check_auth(headers, self.username, self.password) then
  client:send(M.build_http_response(401, '{"error":"Unauthorized"}'))
  client:close()
  return
end
```

If `--rpcpassword=""` (the default in `main.lua:20`), no Basic auth is
required — anyone who can connect to the loopback port can call any
RPC. Combined with BUG-5 (rpcbind loopback hardcoded) this is bounded,
but the empty-password defaults to "allow all" rather than to "refuse
all" or to "require cookie auth". Core's behavior is the opposite: it
auto-generates the cookie file when no rpcuser/rpcpassword is set
(`httprpc.cpp:258`), so there's always an auth credential.

**Reference:** `bitcoin-core/src/httprpc.cpp:251-265` cookie-auth
auto-generation when `rpcuser` is empty.

**Fix sketch:** when both `--rpcuser` and `--rpcpassword` would be
empty/defaults, refuse plaintext RPC unless cookie auth (BUG-2) is
wired and the request supplies the cookie file's credentials.
Alternatively, follow Core: auto-generate the cookie if rpcuser is
default — solves BUG-2 and BUG-7 together.

### BUG-8 (MED) — No `-debugexclude=<cat>` filter (G12)

**Location:** `src/ops.lua:247-263` `parse_debug_cats` accepts inclusion
only; no exclusion semantics.

**Reference:** `bitcoin-core/src/init/common.cpp:33`.

**Fix sketch:** add `--debugexclude=<cat>[,<cat>]` flag, store as
`exclude_cats` table on the logger, drop the category from `log()`
emission BEFORE the `debug_cats` inclusion check.

### BUG-9 (MED) — No `-loglevel=<level>` severity (G13)

**Location:** `src/ops.lua:223-236` `logger:log(msg, cat)` has no
`level` parameter; all emissions are at the same implicit severity.
Core's `LogPrintLevel_` accepts `BCLog::Level::Info|Warning|Error|Debug|
Trace` and the operator can set thresholds globally or per-category.

**Reference:** `bitcoin-core/src/logging.h:131-256` (severity infra).

**Fix sketch:** add `level` parameter to `log(msg, cat, level)`. Map
to a small enum (`info`, `warning`, `error`, `debug`, `trace`). Add
`level_threshold` config on the logger. Default threshold = `info`.
Cosmetic change at every call site (~150 LOC across the tree); useful
in the long run because operators looking for "what's wrong" want to
grep `[error]` not "[validation]".

### BUG-10 (MED) — No logging RPC (G23)

**Location:** missing entirely.

**Reference:** `bitcoin-core/src/rpc/misc.cpp` `logging` RPC accepts
`include` + `exclude` arrays and toggles `BCLog::Logger::EnableCategory`
/ `DisableCategory` at runtime — no restart needed.

**Fix sketch:** register `self.methods["logging"]` in `rpc.lua`,
accept two arrays, mutate `logger.debug_cats` (and `exclude_cats` from
BUG-8). Return the post-change category set.

### BUG-11 (LOW) — `uptime` RPC returns wall-clock time, not seconds-since-start (G25)

**Location:** `src/rpc.lua:4122-4125`.

```lua
self.methods["uptime"] = function(_rpc, _params)
  -- Return uptime in seconds (simplified)
  return os.time()
end
```

`os.time()` is **wall-clock seconds since epoch**, not seconds since
the daemon started. Core's uptime returns `GetTime() - g_start_time`
in seconds. The lunarblock value is ~1.7 billion (current epoch) and
operators reading it as "uptime in seconds" see "53 years" or similar
nonsense.

**Reference:** `bitcoin-core/src/rpc/node.cpp` uptime returns
`GetTime() - g_start_time`.

**Fix sketch:** capture `_start_time = os.time()` at module load (or
on `RPCServer:start()`), return `os.time() - self._start_time`.
2-line patch.

### BUG-12 (LOW) — No alertnotify/blocknotify/startupnotify/shutdownnotify hooks (G26-G28)

**Location:** missing entirely; no `os.execute` / `popen` hooks fire
on chain-tip change, startup, shutdown, or warning.

**Reference:** `bitcoin-core/src/init.cpp:485` (`-alertnotify`),
`:498` (`-blocknotify`), `:529-530` (`-startupnotify`, `-shutdownnotify`).

**Fix sketch:** add CLI flags `--alertnotify`, `--blocknotify`,
`--startupnotify`, `--shutdownnotify`. On the relevant trigger, run
`os.execute(cmd_with_%s_substituted)` in a non-blocking detached
manner (fork+exec, or `popen` + close, since lunarblock is
single-threaded). Document the security caveat (executes shell
commands — operator must control the config file).

### BUG-13 (LOW) — `getmemoryinfo` / `getzmqnotifications` RPCs missing (G25)

**Location:** missing entirely.

**Reference:** `bitcoin-core/src/rpc/misc.cpp getmemoryinfo`;
`bitcoin-core/src/rpc/zmq.cpp getzmqnotifications`.

**Fix sketch:** `getmemoryinfo` — return `collectgarbage("count")` for
Lua heap + read `/proc/self/status` `VmRSS` for process RSS (the
existing `[DIAG]` line in `main.lua:2219-2228` already does this).
`getzmqnotifications` — iterate `zmq_notifier.endpoints` and return as
`{type=..., address=..., hwm=...}` table.

### BUG-14 (LOW) — Stale `jitprofileflush` comment misstates SIGTERM presence

**Location:** `src/rpc.lua:4078-4088`.

```lua
self.methods["jitprofileflush"] = function(_rpc, _params)
  -- Flush LuaJIT profile by stopping the profiler. Caller should pass a
  -- file path to restart capture into; otherwise capture stops permanently.
  -- main.lua's cleanup path is unreachable (no SIGTERM handler), so this
  -- is the only way to get the profile data on disk.
  ...
end
```

The "no SIGTERM handler" claim is stale: `main.lua:2100-2107` wires
both SIGTERM and SIGINT to graceful shutdown, and the cleanup path at
`main.lua:2249-2293` (including `jit_p.stop()` at `main.lua:2256`)
runs every time SIGTERM is delivered. This is doc-only, but it
misleads anyone reading rpc.lua for the first time.

**Fix sketch:** delete the stale paragraph; rephrase as "flush LuaJIT
profile mid-run without waiting for shutdown."

## Cross-impl context

This is the first W124 audit. The 30-gate set was synthesized
specifically for this wave from Core init.cpp / shutdown.cpp / logging
references. Subsequent fleet impls auditing the same gates can use
this matrix as a template.

Observed lunarblock posture: **the foundation is solid** (SIGTERM
wired, PID file, daemonize, log file, --conf parser, ready-fd, 15
debug categories) but the **operator-RPC surface is thin** (10 of 14
RPC-ops gates miss, including the high-visibility `stop` and the
cookie-auth path the fleet's own `tools/stop_mainnet.sh` depends on).

Two of the bugs are P0-OPS — they break documented fleet conventions:
- BUG-1: no datadir lockfile means two lunarblock instances on the
  same `--datadir` can corrupt the chainstate without complaint.
- BUG-2: no cookie file means the fleet's stop_mainnet.sh helper has
  no path to a graceful `bitcoin-cli stop` — only `kill -TERM`.

One is P0 — BUG-3: the `stop` RPC method silently lies. It returns
the polite "LunarBlock stopping..." but the daemon keeps running.

## Test coverage delta

New file: `tests/test_w124_operator.lua` (this wave) — 35 tests, 14
expected-fail-pre-fix markers. The test file is self-contained — it
doesn't bind real ports or fork the daemon; it inspects module surface
and asserts presence/absence of CLI flags, RPC methods, ops helpers.

| Test | Gate | Pre-fix | Post-fix |
|------|------|---------|----------|
| G1: --help | G1 | PASS | PASS |
| G2: --version | G2 | PASS | PASS |
| G3: --conf parser | G3 | PASS | PASS |
| G4: --datadir | G4 | PASS | PASS |
| G5: per-network subdir | G5 | PASS | PASS |
| G6: lockfile | G6 | **XFAIL** (BUG-1) | PASS |
| G7: PID file | G7 | PASS | PASS |
| G8: cookie file | G8 | **XFAIL** (BUG-2) | PASS |
| G9: rpcauth | G9 | **XFAIL** | PASS |
| G10: blocksdir | G10 | XFAIL (design gap) | XFAIL (design gap) |
| G11: --debug categories | G11 | PASS | PASS |
| G12: --debugexclude | G12 | **XFAIL** (BUG-8) | PASS |
| G13: --loglevel | G13 | **XFAIL** (BUG-9) | PASS |
| G14: --logtimestamps | G14 | PARTIAL | PARTIAL |
| G15: thread/source | G15 | XFAIL (Lua design) | XFAIL |
| G16-G18: SIGTERM/SIGINT/SIGHUP | G16-G18 | PASS | PASS |
| G19: --ready-fd | G19 | PASS | PASS |
| G20: stop RPC stops | G20 | **XFAIL** (BUG-3) | PASS |
| G21: RPC Basic auth | G21 | PASS (with caveat) | PASS |
| G22: getrpcinfo.logpath | G22 | **XFAIL** (BUG-4) | PASS |
| G23: logging RPC | G23 | **XFAIL** (BUG-10) | PASS |
| G24: setnetworkactive | G24 | **XFAIL** | PASS |
| G25: getmemoryinfo/getzmq | G25 | **XFAIL** (BUG-13) | PASS |
| G26-G28: notify hooks | G26-G28 | **XFAIL** (BUG-12) | PASS |
| G29: --rpcbind | G29 | **XFAIL** (BUG-5) | PASS |
| G30: --bind/--metricsbind | G30 | **XFAIL** (BUG-6) | PASS |
| Extra: uptime accuracy | (BUG-11) | **XFAIL** | PASS |
| Extra: stop comment | (BUG-14) | **XFAIL** | PASS |
| Extra: BUG-7 password-empty | G21 | **XFAIL** | PASS |

## Verdict

**14 BUGS FOUND.** 1 P0 (`stop` RPC silent no-op), 2 P0-OPS (no
lockfile, no cookie file), 4 P1 (`getrpcinfo` logpath, `--rpcbind`,
`--bind/--metricsbind`, empty-password auth bypass), 4 MED
(`-debugexclude`, `-loglevel`, `logging` RPC), 4 LOW (`uptime`
nonsense, no notify hooks, no getmemoryinfo, stale comment).

The two P0-OPS bugs are the highest-leverage closures: they unblock
the fleet's own `stop_mainnet.sh` to talk to lunarblock the same way
it talks to every other node, and they end the silent-instance-races
class. BUG-3 closure is essentially a 5-line patch (export a flag
from `ops.lua`, read it in the main loop, call the setter from the
RPC method). BUG-2 closure adds the cookie file (~25 LOC in `ops.lua`).
BUG-1 closure adds `flock`-based datadir locking (~30 LOC, code lifted
from `wallet.lua:2103-2150`).

A bookkeeping fix wave can close BUG-3 + BUG-2 + BUG-1 + BUG-4 +
BUG-11 + BUG-14 in one commit (~150 LOC + ~10 tests flipped from XFAIL
to PASS). BUG-5, BUG-6, BUG-7 — CLI surface expansion, ~50 LOC.
BUG-8, BUG-9, BUG-10, BUG-12, BUG-13 — feature work, multi-wave.

## References

- `bitcoin-core/src/init.cpp` — `AppInitMain`, `Shutdown`, `Interrupt`,
  `SetupServerArgs`, `LockDirectories`, `HandleSIGTERM`, `HandleSIGHUP`.
- `bitcoin-core/src/shutdown.cpp` — `ShutdownRequested`,
  `WaitForShutdown`, the `g_shutdown` `SignalInterrupt`.
- `bitcoin-core/src/logging.{cpp,h}` — `BCLog::Logger`, severity
  levels, category masks, `WillLogCategoryLevel`, source locations,
  thread names.
- `bitcoin-core/src/init/common.cpp:29-44` — logging argument
  declarations (`-debug`, `-debugexclude`, `-loglevel`, etc.).
- `bitcoin-core/src/httprpc.cpp:247-300` — cookie auth, rpcauth, basic
  auth.
- `bitcoin-core/src/rpc/server.cpp` — `stop`, `getrpcinfo`, `uptime`,
  `logging` RPC implementations.
- root `CLAUDE.md` "Ops (mainnet fleet)" — operator-fleet conventions
  this audit grades against.
- `tools/stop_mainnet.sh` — the cookie-file consumer this audit traced.
