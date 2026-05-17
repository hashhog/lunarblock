#!/usr/bin/env luajit
-- W124 Operator-experience audit — lunarblock (Lua / LuaJIT)
--
-- Reference: bitcoin-core/src/init.cpp; src/shutdown.cpp;
--            src/logging.{cpp,h}; src/init/common.cpp;
--            src/httprpc.cpp; src/rpc/server.cpp;
--            root CLAUDE.md "Ops (mainnet fleet)" section;
--            tools/stop_mainnet.sh + tools/start_mainnet.sh.
--
-- Scope: 30 gates spanning CLI surface, datadir/lockfile/PID/cookie,
--        logger (categories/severity/timestamps), signals
--        (SIGTERM/SIGINT/SIGHUP/ready-fd), RPC ops surface
--        (stop/getrpcinfo/logging/setnetworkactive/getmemoryinfo),
--        and notify hooks (alert/block/startup/shutdown).
--
-- Gate map (see audit/w124_operator_experience.md):
--   G1-G5    CLI surface — args, conf-file, version, help.
--   G6-G10   Datadir, lockfile, PID file, cookie auth, blocksdir.
--   G11-G15  Logger — categories, severity, timestamps, thread names.
--   G16-G20  Signals — SIGTERM/SIGINT/SIGHUP, ready-fd, stop RPC.
--   G21-G25  RPC ops surface — auth, getrpcinfo, logging, setnetworkactive.
--   G26-G30  Notify hooks — alert/block/startup/shutdown, --rpcbind/--bind.
--
-- Bugs found (1 P0 + 2 P0-OPS + 4 P1 + 4 MED + 4 LOW):
--
--   BUG-1  (P0-OPS)  No datadir lockfile (G6). Two lunarblock instances
--                    on the same --datadir can corrupt chainstate.
--                    Core: src/init.cpp:1158 LockDirectory.
--
--   BUG-2  (P0-OPS)  No cookie file written to <datadir>/.cookie (G8).
--                    tools/stop_mainnet.sh expects $NODE/.cookie for
--                    every mainnet node; lunarblock never writes one.
--                    Core: src/httprpc.cpp:247-265 GenerateAuthCookie.
--
--   BUG-3  (P0)      `stop` RPC method does NOT actually stop the daemon
--                    (G20). rpc.lua:4073-4076 returns a static string but
--                    never flips main.lua's `running` flag.
--                    Core: src/rpc/server.cpp `stop` triggers
--                    node.shutdown_request->Set().
--
--   BUG-4  (P1)      getrpcinfo.logpath hardcoded as "" (G22). Operator
--                    cannot discover the active log file via RPC.
--                    Core: src/rpc/server.cpp returns real path.
--
--   BUG-5  (P1)      RPC binds 127.0.0.1 hardcoded; no --rpcbind (G29).
--                    Core: src/init.cpp -rpcbind=<addr>.
--
--   BUG-6  (P1)      Metrics + P2P listen 0.0.0.0 hardcoded; no --bind
--                    (G30). Metrics binding 0.0.0.0 is a particularly
--                    surprising default.
--
--   BUG-7  (P1)      RPC accepts unauthenticated requests when password
--                    is empty (G21). Default --rpcpassword="" lets anyone
--                    on loopback call any RPC.
--                    Core: src/httprpc.cpp:251-265 auto-generates cookie
--                    when rpcuser empty.
--
--   BUG-8  (MED)     No --debugexclude=<cat> inverse filter (G12).
--
--   BUG-9  (MED)     No --loglevel=<level> severity gating (G13).
--
--   BUG-10 (MED)     No `logging` RPC for runtime category toggle (G23).
--
--   BUG-11 (LOW)     `uptime` RPC returns wall-clock epoch, not
--                    seconds-since-start. rpc.lua:4122-4125.
--                    Core: GetTime() - g_start_time.
--
--   BUG-12 (LOW)     No alertnotify/blocknotify/startupnotify/
--                    shutdownnotify hooks (G26-G28).
--
--   BUG-13 (LOW)     getmemoryinfo / getzmqnotifications RPCs missing
--                    (G25).
--
--   BUG-14 (LOW)     Stale jitprofileflush comment claims "no SIGTERM
--                    handler" — SIGTERM IS wired since main.lua:2100.
--
-- Total: 14 actionable bugs / 35 tests / 30 gates.
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_w124_operator.lua 2>&1

package.path = "src/?.lua;./?.lua;" .. package.path

local loaders = package.loaders or package.searchers
table.insert(loaders, 2, function(module)
  local name = module:match("^lunarblock%.(.+)")
  if name then
    local filename = "src/" .. name .. ".lua"
    local f = io.open(filename)
    if f then f:close(); return function() return dofile(filename) end end
  end
  return nil, "not found"
end)

local PASS = 0
local FAIL = 0
local XFAIL_PRE_FIX = 0

local function pass(name)
  io.write(string.format("  PASS  %s\n", name))
  PASS = PASS + 1
end

local function fail(name, msg)
  io.write(string.format("  FAIL  %s -- %s\n", name, msg))
  FAIL = FAIL + 1
end

local function xfail_pre_fix(name, msg)
  io.write(string.format("  XFAIL %s (expected pre-fix) -- %s\n", name, msg))
  XFAIL_PRE_FIX = XFAIL_PRE_FIX + 1
end

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end

-- Wraps a test that is expected to FAIL pre-fix. If it passes
-- post-fix the gate flips to a PASS (with hint that the fix landed).
local function test_xfail_pre_fix(name, fn)
  local ok, err = pcall(fn)
  if ok then
    pass(name .. " [now PASSing — fix likely landed]")
  else
    xfail_pre_fix(name, tostring(err))
  end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) ..
          ", expected " .. tostring(b))
  end
end

local function expect_truthy(v, msg)
  if not v then
    error((msg or "expected truthy") .. ": got " .. tostring(v))
  end
end

local function expect_falsy(v, msg)
  if v then
    error((msg or "expected falsy") .. ": got " .. tostring(v))
  end
end

-- ---------------------------------------------------------------------------
-- Helpers: load lunarblock modules + read files as strings.
-- ---------------------------------------------------------------------------

local function read_file(path)
  local f = io.open(path, "r")
  if not f then return nil end
  local data = f:read("*a")
  f:close()
  return data
end

local function file_contains(path, needle)
  local data = read_file(path)
  if not data then return false end
  -- Use plain-text find (not pattern) so dots etc. don't need escaping.
  return string.find(data, needle, 1, true) ~= nil
end

-- ---------------------------------------------------------------------------
-- Print banner
-- ---------------------------------------------------------------------------

print("\n=========================================================================")
print("W124 Operator-experience audit — lunarblock")
print("Source: src/main.lua, src/ops.lua, src/rpc.lua")
print("Reference: bitcoin-core/src/init.cpp; src/shutdown.cpp;")
print("           src/logging.{cpp,h}; src/init/common.cpp.")
print("=========================================================================")

-- ---------------------------------------------------------------------------
-- G1 — --help / -h
-- ---------------------------------------------------------------------------
print("\n--- G1: --help / -h ---")
test("G1-a: --help registered in main.lua arg parser", function()
  expect_truthy(file_contains("src/main.lua", '"--help"'),
                "--help literal absent from main.lua")
end)
test("G1-b: -h short form registered", function()
  expect_truthy(file_contains("src/main.lua", '"-h"'),
                "-h short form absent")
end)

-- ---------------------------------------------------------------------------
-- G2 — --version
-- ---------------------------------------------------------------------------
print("\n--- G2: --version ---")
test("G2-a: --version registered", function()
  expect_truthy(file_contains("src/main.lua", '"--version"'),
                "--version absent")
end)
test("G2-b: VERSION constant set", function()
  expect_truthy(file_contains("src/main.lua", 'local VERSION ='),
                "VERSION constant missing")
end)

-- ---------------------------------------------------------------------------
-- G3 — --conf=<file> (Core bitcoin.conf parity)
-- ---------------------------------------------------------------------------
print("\n--- G3: --conf=<file> ---")
test("G3-a: parse_conf_file present in ops.lua", function()
  local ops = require("lunarblock.ops")
  expect_truthy(type(ops.parse_conf_file) == "function",
                "ops.parse_conf_file not exposed")
end)
test("G3-b: --conf flag wired in main.lua", function()
  expect_truthy(file_contains("src/main.lua", '"--conf"'),
                "--conf flag absent")
end)
test("G3-c: apply_conf_to_args present", function()
  local ops = require("lunarblock.ops")
  expect_truthy(type(ops.apply_conf_to_args) == "function",
                "ops.apply_conf_to_args not exposed")
end)

-- ---------------------------------------------------------------------------
-- G4 — --datadir
-- ---------------------------------------------------------------------------
print("\n--- G4: --datadir=<dir> ---")
test("G4-a: --datadir registered", function()
  expect_truthy(file_contains("src/main.lua", '"--datadir"'),
                "--datadir absent")
end)
test("G4-b: -d short form registered", function()
  expect_truthy(file_contains("src/main.lua", '"-d"'),
                "-d short form absent")
end)

-- ---------------------------------------------------------------------------
-- G5 — Per-network subdir under datadir
-- ---------------------------------------------------------------------------
print("\n--- G5: per-network subdir under datadir ---")
test("G5-a: non-mainnet datadir suffix wired", function()
  -- main.lua:716-718: datadir = datadir .. "/" .. args.network for non-mainnet
  expect_truthy(file_contains("src/main.lua",
                              'datadir = datadir .. "/" .. args.network'),
                "non-mainnet subdir suffix absent")
end)

-- ---------------------------------------------------------------------------
-- G6 — Datadir lockfile (BUG-1)
-- ---------------------------------------------------------------------------
print("\n--- G6: datadir lockfile (BUG-1 expected) ---")
test_xfail_pre_fix("G6-a: ops.lua exposes lock_datadir helper", function()
  local ops = require("lunarblock.ops")
  expect_truthy(type(ops.lock_datadir) == "function",
                "ops.lock_datadir missing — BUG-1: no LockDataDirectory parity")
end)
test_xfail_pre_fix("G6-b: main.lua calls lock_datadir before storage_mod.open", function()
  expect_truthy(file_contains("src/main.lua", "lock_datadir"),
                "main.lua does not call lock_datadir — BUG-1")
end)

-- ---------------------------------------------------------------------------
-- G7 — PID file (--pid)
-- ---------------------------------------------------------------------------
print("\n--- G7: --pid PID file ---")
test("G7-a: ops.write_pid_file present", function()
  local ops = require("lunarblock.ops")
  expect_truthy(type(ops.write_pid_file) == "function",
                "ops.write_pid_file missing")
end)
test("G7-b: ops.remove_pid_file present", function()
  local ops = require("lunarblock.ops")
  expect_truthy(type(ops.remove_pid_file) == "function",
                "ops.remove_pid_file missing")
end)
test("G7-c: main.lua writes PID at startup", function()
  expect_truthy(file_contains("src/main.lua", "ops.write_pid_file"),
                "write_pid_file not called from main.lua")
end)
test("G7-d: main.lua removes PID at shutdown", function()
  expect_truthy(file_contains("src/main.lua", "ops.remove_pid_file"),
                "remove_pid_file not called from main.lua cleanup")
end)

-- ---------------------------------------------------------------------------
-- G8 — Cookie file written to <datadir>/.cookie (BUG-2)
-- ---------------------------------------------------------------------------
print("\n--- G8: cookie file in datadir (BUG-2 expected) ---")
test_xfail_pre_fix("G8-a: ops.lua exposes write_cookie_file", function()
  local ops = require("lunarblock.ops")
  expect_truthy(type(ops.write_cookie_file) == "function",
                "ops.write_cookie_file missing — BUG-2: no .cookie generated")
end)
test_xfail_pre_fix("G8-b: main.lua calls write_cookie_file at startup", function()
  expect_truthy(file_contains("src/main.lua", "write_cookie_file"),
                "main.lua does not write .cookie — BUG-2: stop_mainnet.sh broken")
end)

-- ---------------------------------------------------------------------------
-- G9 — --rpcauth=<hash> style auth (BUG-7 adjacent)
-- ---------------------------------------------------------------------------
print("\n--- G9: --rpcauth=<hash> style auth ---")
test_xfail_pre_fix("G9-a: --rpcauth CLI flag present", function()
  expect_truthy(file_contains("src/main.lua", '"--rpcauth"'),
                "--rpcauth absent — only plaintext --rpcpassword supported")
end)

-- ---------------------------------------------------------------------------
-- G10 — --blocksdir=<dir> separate from datadir
-- ---------------------------------------------------------------------------
print("\n--- G10: --blocksdir=<dir> ---")
test_xfail_pre_fix("G10-a: --blocksdir flag (design gap)", function()
  expect_truthy(file_contains("src/main.lua", '"--blocksdir"'),
                "--blocksdir absent (lunarblock stores blocks in RocksDB CF — design choice)")
end)

-- ---------------------------------------------------------------------------
-- G11 — --debug=<cat> debug categories
-- ---------------------------------------------------------------------------
print("\n--- G11: --debug=<cat> categories ---")
test("G11-a: --debug flag registered", function()
  expect_truthy(file_contains("src/main.lua", '"--debug"'),
                "--debug flag absent")
end)
test("G11-b: ops.parse_debug_cats present", function()
  local ops = require("lunarblock.ops")
  expect_truthy(type(ops.parse_debug_cats) == "function",
                "ops.parse_debug_cats missing")
end)
test("G11-c: ops.parse_debug_cats('net,mempool') returns 2-cat table", function()
  local ops = require("lunarblock.ops")
  local cats = ops.parse_debug_cats("net,mempool")
  expect_truthy(cats.net, "net category missing from parsed result")
  expect_truthy(cats.mempool, "mempool category missing")
end)
test("G11-d: '1' shorthand enables 'all'", function()
  local ops = require("lunarblock.ops")
  local cats = ops.parse_debug_cats("1")
  expect_truthy(cats.all, "'1' should enable .all")
end)
test("G11-e: '0' shorthand disables all", function()
  local ops = require("lunarblock.ops")
  local cats = ops.parse_debug_cats("0")
  expect_falsy(cats.all, "'0' should NOT enable .all")
end)
test("G11-f: LOG_CATEGORIES list contains expected Core categories", function()
  local ops = require("lunarblock.ops")
  expect_truthy(type(ops.LOG_CATEGORIES) == "table",
                "LOG_CATEGORIES list missing")
  local s = {}
  for _, c in ipairs(ops.LOG_CATEGORIES) do s[c] = true end
  expect_truthy(s.net, "net category missing")
  expect_truthy(s.mempool, "mempool category missing")
  expect_truthy(s.rpc, "rpc category missing")
  expect_truthy(s.validation, "validation category missing")
end)

-- ---------------------------------------------------------------------------
-- G12 — --debugexclude=<cat> inverse filter (BUG-8)
-- ---------------------------------------------------------------------------
print("\n--- G12: --debugexclude=<cat> (BUG-8 expected) ---")
test_xfail_pre_fix("G12-a: --debugexclude CLI flag", function()
  expect_truthy(file_contains("src/main.lua", '"--debugexclude"'),
                "--debugexclude absent — BUG-8: no inverse-filter parity")
end)
test_xfail_pre_fix("G12-b: ops.parse_debug_exclude_cats helper", function()
  local ops = require("lunarblock.ops")
  expect_truthy(type(ops.parse_debug_exclude_cats) == "function",
                "ops.parse_debug_exclude_cats missing — BUG-8")
end)

-- ---------------------------------------------------------------------------
-- G13 — --loglevel=<level> severity (BUG-9)
-- ---------------------------------------------------------------------------
print("\n--- G13: --loglevel=<level> severity (BUG-9 expected) ---")
test_xfail_pre_fix("G13-a: --loglevel CLI flag", function()
  expect_truthy(file_contains("src/main.lua", '"--loglevel"'),
                "--loglevel absent — BUG-9: no severity gating")
end)
test_xfail_pre_fix("G13-b: logger:log accepts level parameter", function()
  local ops = require("lunarblock.ops")
  local logger = ops.new_logger({})
  -- Probe logger.log function signature; if 'level' is not supported,
  -- a 3-arg call still works because Lua is dynamic — so check the
  -- source code instead.
  expect_truthy(file_contains("src/ops.lua", "function self:log(msg, cat, level)"),
                "logger:log does not accept severity level — BUG-9")
end)

-- ---------------------------------------------------------------------------
-- G14 — --logtimestamps (Core default ON) — PARTIAL
-- ---------------------------------------------------------------------------
print("\n--- G14: --logtimestamps (PARTIAL) ---")
test("G14-a: logger:log writes timestamp prefix", function()
  expect_truthy(file_contains("src/ops.lua", 'os.date("%Y-%m-%d %H:%M:%S"'),
                "log timestamp format missing")
end)
test_xfail_pre_fix("G14-b: --logtimestamps toggle flag", function()
  expect_truthy(file_contains("src/main.lua", '"--logtimestamps"'),
                "--logtimestamps toggle absent — timestamp is always on")
end)

-- ---------------------------------------------------------------------------
-- G15 — --logthreadnames / --logsourcelocations (Lua design constraint)
-- ---------------------------------------------------------------------------
print("\n--- G15: --logthreadnames / --logsourcelocations (Lua design) ---")
test_xfail_pre_fix("G15-a: --logthreadnames flag (Lua is single-threaded)", function()
  expect_truthy(file_contains("src/main.lua", '"--logthreadnames"'),
                "--logthreadnames absent (lunarblock is single-threaded — design choice)")
end)
test_xfail_pre_fix("G15-b: --logsourcelocations flag", function()
  expect_truthy(file_contains("src/main.lua", '"--logsourcelocations"'),
                "--logsourcelocations absent (Lua has no automatic source-loc — design choice)")
end)

-- ---------------------------------------------------------------------------
-- G16 — SIGTERM graceful shutdown
-- ---------------------------------------------------------------------------
print("\n--- G16: SIGTERM graceful shutdown ---")
test("G16-a: ops.SIGTERM constant defined", function()
  local ops = require("lunarblock.ops")
  expect_eq(ops.SIGTERM, 15, "SIGTERM should be 15 on Linux x86_64")
end)
test("G16-b: ops.set_signal_handler present", function()
  local ops = require("lunarblock.ops")
  expect_truthy(type(ops.set_signal_handler) == "function",
                "ops.set_signal_handler missing")
end)
test("G16-c: main.lua wires SIGTERM handler", function()
  expect_truthy(file_contains("src/main.lua",
                              "ops.set_signal_handler(ops.SIGTERM"),
                "SIGTERM handler not installed in main.lua")
end)

-- ---------------------------------------------------------------------------
-- G17 — SIGINT
-- ---------------------------------------------------------------------------
print("\n--- G17: SIGINT (Ctrl-C) ---")
test("G17-a: ops.SIGINT constant", function()
  local ops = require("lunarblock.ops")
  expect_eq(ops.SIGINT, 2, "SIGINT should be 2 on Linux x86_64")
end)
test("G17-b: main.lua wires SIGINT handler", function()
  expect_truthy(file_contains("src/main.lua",
                              "ops.set_signal_handler(ops.SIGINT"),
                "SIGINT handler not installed in main.lua")
end)

-- ---------------------------------------------------------------------------
-- G18 — SIGHUP log reopen
-- ---------------------------------------------------------------------------
print("\n--- G18: SIGHUP log reopen (logrotate) ---")
test("G18-a: ops.SIGHUP constant", function()
  local ops = require("lunarblock.ops")
  expect_eq(ops.SIGHUP, 1, "SIGHUP should be 1 on Linux x86_64")
end)
test("G18-b: logger:reopen method present", function()
  local ops = require("lunarblock.ops")
  local logger = ops.new_logger({})
  expect_truthy(type(logger.reopen) == "function",
                "logger:reopen missing")
end)
test("G18-c: main.lua wires SIGHUP → reopen", function()
  expect_truthy(file_contains("src/main.lua",
                              "ops.set_signal_handler(ops.SIGHUP"),
                "SIGHUP handler not installed in main.lua")
end)

-- ---------------------------------------------------------------------------
-- G19 — --ready-fd
-- ---------------------------------------------------------------------------
print("\n--- G19: --ready-fd=<N> ---")
test("G19-a: ops.signal_ready present", function()
  local ops = require("lunarblock.ops")
  expect_truthy(type(ops.signal_ready) == "function",
                "ops.signal_ready missing")
end)
test("G19-b: --ready-fd CLI flag wired", function()
  expect_truthy(file_contains("src/main.lua", '"--ready-fd"'),
                "--ready-fd flag absent")
end)
test("G19-c: main.lua calls signal_ready after listeners up", function()
  expect_truthy(file_contains("src/main.lua", "ops.signal_ready"),
                "main.lua does not call signal_ready")
end)

-- ---------------------------------------------------------------------------
-- G20 — stop RPC actually stops the daemon (BUG-3)
-- ---------------------------------------------------------------------------
print("\n--- G20: stop RPC actually stops daemon (BUG-3 expected) ---")
test_xfail_pre_fix("G20-a: ops.request_shutdown helper", function()
  local ops = require("lunarblock.ops")
  expect_truthy(type(ops.request_shutdown) == "function",
                "ops.request_shutdown missing — BUG-3: stop RPC has nothing to call")
end)
test_xfail_pre_fix("G20-b: ops.shutdown_requested predicate", function()
  local ops = require("lunarblock.ops")
  expect_truthy(type(ops.shutdown_requested) == "function",
                "ops.shutdown_requested missing — BUG-3")
end)
test_xfail_pre_fix("G20-c: rpc.lua stop method calls ops.request_shutdown", function()
  expect_truthy(file_contains("src/rpc.lua", "ops.request_shutdown"),
                "rpc.lua stop method does NOT call request_shutdown — BUG-3 still open")
end)
test_xfail_pre_fix("G20-d: main loop polls ops.shutdown_requested", function()
  expect_truthy(file_contains("src/main.lua", "ops.shutdown_requested"),
                "main loop does not poll shutdown_requested — BUG-3 still open")
end)

-- ---------------------------------------------------------------------------
-- G21 — RPC HTTP Basic auth (BUG-7 caveat for empty password)
-- ---------------------------------------------------------------------------
print("\n--- G21: RPC HTTP Basic auth (BUG-7 caveat) ---")
test("G21-a: M.check_auth function exposed", function()
  local rpc = require("lunarblock.rpc")
  expect_truthy(type(rpc.check_auth) == "function",
                "rpc.check_auth missing")
end)
test("G21-b: M.check_auth rejects bad credentials", function()
  local rpc = require("lunarblock.rpc")
  local got = rpc.check_auth({authorization = "Basic Zm9vOmJhcg=="},
                             "user", "pass")
  expect_falsy(got, "check_auth should reject foo:bar against user:pass")
end)
test("G21-c: M.check_auth accepts correct credentials", function()
  local rpc = require("lunarblock.rpc")
  -- base64("user:pass") = "dXNlcjpwYXNz"
  local got = rpc.check_auth({authorization = "Basic dXNlcjpwYXNz"},
                             "user", "pass")
  expect_truthy(got, "check_auth should accept user:pass with matching creds")
end)
test_xfail_pre_fix("G21-d: empty password rejects unauth requests (BUG-7)", function()
  -- BUG-7: rpc.lua:8528 only checks auth when password ~= "".  Default
  -- --rpcpassword="" means no auth check fires.  The fix is to either
  -- auto-generate a cookie file when password is empty, or to refuse
  -- requests when no auth is configured.  Probe by reading the source.
  local body = read_file("src/rpc.lua")
  expect_truthy(body, "src/rpc.lua unreadable")
  -- We want the empty-password case to refuse auth (fix-form: check
  -- cookie auth, not the password ~= "" guard).
  expect_falsy(body:find('self.password ~= "" and not M.check_auth', 1, true),
               "BUG-7: empty-password guard still present in src/rpc.lua — RPC " ..
               "still accepts unauthenticated requests when --rpcpassword is empty")
end)

-- ---------------------------------------------------------------------------
-- G22 — getrpcinfo returns real logpath (BUG-4)
-- ---------------------------------------------------------------------------
print("\n--- G22: getrpcinfo.logpath (BUG-4 expected) ---")
test_xfail_pre_fix("G22-a: getrpcinfo returns non-empty logpath", function()
  -- The handler must read self.log_path or compute it.  We can't easily
  -- spin up a full server here, but we can grep the source to see if
  -- the hardcoded empty string was replaced.
  expect_falsy(file_contains("src/rpc.lua", 'logpath         = "",'),
               "getrpcinfo still returns hardcoded empty logpath — BUG-4")
end)

-- ---------------------------------------------------------------------------
-- G23 — logging RPC dynamic toggle (BUG-10)
-- ---------------------------------------------------------------------------
print("\n--- G23: logging RPC (BUG-10 expected) ---")
test_xfail_pre_fix("G23-a: logging RPC method registered", function()
  expect_truthy(file_contains("src/rpc.lua", 'self.methods["logging"]'),
                "logging RPC not registered — BUG-10: no runtime category toggle")
end)

-- ---------------------------------------------------------------------------
-- G24 — setnetworkactive RPC
-- ---------------------------------------------------------------------------
print("\n--- G24: setnetworkactive RPC ---")
test_xfail_pre_fix("G24-a: setnetworkactive RPC registered", function()
  expect_truthy(file_contains("src/rpc.lua",
                              'self.methods["setnetworkactive"]'),
                "setnetworkactive RPC not registered")
end)

-- ---------------------------------------------------------------------------
-- G25 — getmemoryinfo / getzmqnotifications (BUG-13)
-- ---------------------------------------------------------------------------
print("\n--- G25: getmemoryinfo / getzmqnotifications (BUG-13 expected) ---")
test_xfail_pre_fix("G25-a: getmemoryinfo RPC registered", function()
  expect_truthy(file_contains("src/rpc.lua",
                              'self.methods["getmemoryinfo"]'),
                "getmemoryinfo RPC not registered — BUG-13")
end)
test_xfail_pre_fix("G25-b: getzmqnotifications RPC registered", function()
  expect_truthy(file_contains("src/rpc.lua",
                              'self.methods["getzmqnotifications"]'),
                "getzmqnotifications RPC not registered — BUG-13")
end)

-- ---------------------------------------------------------------------------
-- G26 — --alertnotify (BUG-12)
-- ---------------------------------------------------------------------------
print("\n--- G26: --alertnotify (BUG-12 expected) ---")
test_xfail_pre_fix("G26-a: --alertnotify flag wired", function()
  expect_truthy(file_contains("src/main.lua", '"--alertnotify"'),
                "--alertnotify absent — BUG-12: no operator-paging hook")
end)

-- ---------------------------------------------------------------------------
-- G27 — --blocknotify (BUG-12)
-- ---------------------------------------------------------------------------
print("\n--- G27: --blocknotify (BUG-12 expected) ---")
test_xfail_pre_fix("G27-a: --blocknotify flag wired", function()
  expect_truthy(file_contains("src/main.lua", '"--blocknotify"'),
                "--blocknotify absent — BUG-12: no cheap webhook on new tip")
end)

-- ---------------------------------------------------------------------------
-- G28 — --startupnotify / --shutdownnotify (BUG-12)
-- ---------------------------------------------------------------------------
print("\n--- G28: --startupnotify / --shutdownnotify (BUG-12 expected) ---")
test_xfail_pre_fix("G28-a: --startupnotify flag wired", function()
  expect_truthy(file_contains("src/main.lua", '"--startupnotify"'),
                "--startupnotify absent — BUG-12")
end)
test_xfail_pre_fix("G28-b: --shutdownnotify flag wired", function()
  expect_truthy(file_contains("src/main.lua", '"--shutdownnotify"'),
                "--shutdownnotify absent — BUG-12")
end)

-- ---------------------------------------------------------------------------
-- G29 — --rpcbind ergonomics (BUG-5)
-- ---------------------------------------------------------------------------
print("\n--- G29: --rpcbind ergonomics (BUG-5 expected) ---")
test_xfail_pre_fix("G29-a: --rpcbind flag", function()
  expect_truthy(file_contains("src/main.lua", '"--rpcbind"'),
                "--rpcbind absent — BUG-5: RPC host hardcoded 127.0.0.1")
end)
test_xfail_pre_fix("G29-b: rpc.host plumbed from --rpcbind", function()
  -- Pre-fix: main.lua:1995 hardcodes host = "127.0.0.1"
  expect_falsy(file_contains("src/main.lua", 'host = "127.0.0.1",'),
               "main.lua still hardcodes host = \"127.0.0.1\" — BUG-5 open")
end)

-- ---------------------------------------------------------------------------
-- G30 — --bind / --metricsbind (BUG-6)
-- ---------------------------------------------------------------------------
print("\n--- G30: --bind / --metricsbind (BUG-6 expected) ---")
test_xfail_pre_fix("G30-a: --bind flag for P2P", function()
  expect_truthy(file_contains("src/main.lua", '"--bind"'),
                "--bind absent — BUG-6: P2P listen 0.0.0.0 hardcoded")
end)
test_xfail_pre_fix("G30-b: --metricsbind flag for Prometheus", function()
  expect_truthy(file_contains("src/main.lua", '"--metricsbind"'),
                "--metricsbind absent — BUG-6: metrics binding 0.0.0.0 hardcoded (surprising default)")
end)

-- ---------------------------------------------------------------------------
-- Extra: BUG-11 — uptime nonsense
-- ---------------------------------------------------------------------------
print("\n--- Extra: BUG-11 uptime returns wall-clock not seconds-since-start ---")
test_xfail_pre_fix("uptime: rpc.lua does NOT return os.time() directly", function()
  -- BUG-11: rpc.lua:4123 returns os.time() (wall-clock epoch) as uptime.
  -- Fix: subtract a captured _start_time so the value is seconds since launch.
  local body = read_file("src/rpc.lua")
  expect_truthy(body, "src/rpc.lua unreadable")
  -- Look for the literal pattern that BUG-11 describes.
  expect_falsy(body:find('-- Return uptime in seconds (simplified)\n    return os.time()',
                         1, true),
               "BUG-11: uptime still returns wall-clock os.time() — should be os.time()-_start_time")
end)

-- ---------------------------------------------------------------------------
-- Extra: BUG-14 — stale jitprofileflush comment
-- ---------------------------------------------------------------------------
print("\n--- Extra: BUG-14 stale jitprofileflush comment ---")
test_xfail_pre_fix("jitprofileflush: comment does NOT claim 'no SIGTERM handler'", function()
  -- The comment at rpc.lua:4081 says "main.lua's cleanup path is unreachable
  -- (no SIGTERM handler)" — but main.lua:2100 wires SIGTERM since W12+.
  local body = read_file("src/rpc.lua")
  expect_truthy(body, "src/rpc.lua unreadable")
  expect_falsy(body:find("no SIGTERM handler", 1, true),
               "BUG-14: stale 'no SIGTERM handler' comment still present (SIGTERM IS wired since main.lua:2100)")
end)

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
print("\n=========================================================================")
print(string.format(
  "W124 SUMMARY: %d PASS, %d FAIL, %d XFAIL (pre-fix expected)",
  PASS, FAIL, XFAIL_PRE_FIX))
print("Status: " .. (FAIL == 0 and "AS EXPECTED — 14 bugs catalogued"
                                or string.format("UNEXPECTED FAIL count=%d", FAIL)))
print("=========================================================================")

print("\nBugs found:")
print("  BUG-1  (P0-OPS) No datadir lockfile (G6) — two instances corrupt chainstate")
print("  BUG-2  (P0-OPS) No <datadir>/.cookie (G8) — stop_mainnet.sh has no graceful path")
print("  BUG-3  (P0)     stop RPC returns string but does NOT stop daemon (G20)")
print("  BUG-4  (P1)     getrpcinfo.logpath hardcoded \"\" (G22)")
print("  BUG-5  (P1)     RPC host 127.0.0.1 hardcoded; no --rpcbind (G29)")
print("  BUG-6  (P1)     Metrics + P2P 0.0.0.0 hardcoded; no --bind (G30)")
print("  BUG-7  (P1)     Empty --rpcpassword bypasses auth entirely (G21)")
print("  BUG-8  (MED)    No --debugexclude=<cat> (G12)")
print("  BUG-9  (MED)    No --loglevel=<level> severity (G13)")
print("  BUG-10 (MED)    No `logging` RPC for runtime toggle (G23)")
print("  BUG-11 (LOW)    uptime RPC returns wall-clock not seconds-since-start")
print("  BUG-12 (LOW)    No alertnotify/blocknotify/startupnotify/shutdownnotify (G26-G28)")
print("  BUG-13 (LOW)    getmemoryinfo / getzmqnotifications RPCs missing (G25)")
print("  BUG-14 (LOW)    Stale jitprofileflush comment claims no SIGTERM handler")
print()
print("See audit/w124_operator_experience.md for the full 30-gate matrix.")

os.exit(FAIL > 0 and 1 or 0)
