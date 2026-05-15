#!/usr/bin/env luajit
-- test_fix64_tls.lua — FIX-64 HTTPS/TLS RPC server termination tests
--
-- W119 found that lunarblock has no luasec dep and no TLS layer in the
-- RPC server: every JSON-RPC POST travels in cleartext.  This is fine in
-- the canonical loopback-only / VPN-only deployment, but operators have
-- no opt-in path to wrap the listener even when --rpcuser/--rpcpassword
-- are set.  FIX-64 adds:
--
--   * --rpc-tls-cert PATH + --rpc-tls-key PATH CLI flags
--   * luasec-wrapped TLS handshake on accepted sockets when BOTH paths
--     are set
--   * fatal error if only ONE path is set (config mistake)
--   * fatal error if luasec missing AND TLS flags ARE set
--   * graceful pass-through (no luasec required) when TLS flags NOT set
--
-- Bitcoin Core reference: src/httpserver.cpp — libevent + OpenSSL.
-- This Lua port uses luasec instead; same shape: bind plain TCP socket,
-- wrap accepted client with ssl context, complete handshake before parse.
--
-- BIP-78 §"Protocol" requires HTTPS for PayJoin receivers, so this gate
-- is a strict prerequisite for any operator running PayJoin in
-- production (W119 BIP-78 audit).
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_fix64_tls.lua

package.path = "src/?.lua;./?.lua;" .. package.path

-- Load src/<name>.lua under the "lunarblock.<name>" namespace so the
-- rpc module's `require("lunarblock.<X>")` calls resolve.
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

local PASS, FAIL = 0, 0

local function pass(name)
  print(string.format("  PASS  %s", name))
  PASS = PASS + 1
end

local function fail(name, msg)
  print(string.format("  FAIL  %s — %s", name, msg))
  FAIL = FAIL + 1
end

local function assert_eq(actual, expected, name)
  if actual == expected then pass(name)
  else fail(name, string.format("expected %s, got %s",
                                tostring(expected), tostring(actual)))
  end
end

local function assert_match(actual, pattern, name)
  if type(actual) == "string" and actual:match(pattern) then pass(name)
  else fail(name, string.format("expected string matching %q, got %s",
                                tostring(pattern), tostring(actual)))
  end
end

local function assert_truthy(v, name)
  if v then pass(name)
  else fail(name, "expected truthy, got " .. tostring(v))
  end
end

--------------------------------------------------------------------------------
-- Capability detection
--------------------------------------------------------------------------------

local HAVE_LUASEC = pcall(require, "ssl")
local HAVE_OPENSSL_CLI = (os.execute("openssl version >/dev/null 2>&1") == 0
                          or os.execute("openssl version >/dev/null 2>&1") == true)

print("FIX-64 TLS RPC tests")
print(string.format("  luasec available: %s", tostring(HAVE_LUASEC)))
print(string.format("  openssl CLI available: %s", tostring(HAVE_OPENSSL_CLI)))

--------------------------------------------------------------------------------
-- Self-signed cert helper
--------------------------------------------------------------------------------

local TMP_DIR = string.format("/tmp/lunarblock-fix64-%d", os.time())
os.execute("rm -rf " .. TMP_DIR)
os.execute("mkdir -p " .. TMP_DIR)
local CERT_PATH = TMP_DIR .. "/cert.pem"
local KEY_PATH  = TMP_DIR .. "/key.pem"

local function gen_self_signed()
  -- Single-shot openssl req: writes both key + cert in PEM.  We pin
  -- subj to a non-resolvable CN so a misconfigured test runner never
  -- accidentally trusts this cert.
  local cmd = string.format(
    "openssl req -x509 -newkey rsa:2048 -nodes -keyout %s -out %s " ..
    "-days 1 -subj '/CN=lunarblock-fix64-test' >/dev/null 2>&1",
    KEY_PATH, CERT_PATH)
  return os.execute(cmd)
end

local cert_ready = false
if HAVE_OPENSSL_CLI then
  local rc = gen_self_signed()
  -- Lua 5.1 returns 0 / >0 from os.execute; 5.2+ returns boolean.
  cert_ready = (rc == 0) or (rc == true)
end

print(string.format("  self-signed cert generated: %s (at %s, %s)",
                    tostring(cert_ready), CERT_PATH, KEY_PATH))

--------------------------------------------------------------------------------
-- Helper: build a bare RPCServer struct without calling M.new()
--------------------------------------------------------------------------------
--
-- M.new() calls :register_methods() which builds the full handler
-- catalog and requires the full backing fleet of chain_state/mempool/
-- wallet/etc objects.  For these tests we only exercise
-- :_init_tls_context(), so we mint the minimal struct directly.

local function bare_server(opts)
  local rpc = require("lunarblock.rpc")
  -- Steal the RPCServer metatable via a stub call to M.new() with a
  -- minimal config.  We DON'T call :start() so register_methods's
  -- runtime requirements don't matter; we only need the method table.
  --
  -- Cleaner: expose RPCServer through M directly.  Until then, build
  -- the metatable lookup via the public constructor and reset fields.
  local s
  -- M.new requires only a few primitive defaults; nil chain_state etc.
  -- is fine for the no-tick tests below.
  local ok, server_or_err = pcall(rpc.new, {})
  if not ok then
    -- Some impls of register_methods deref config fields; fall back to
    -- a manual setmetatable using the RPCServer table.  We probe for it
    -- via __index off the returned object — but since pcall failed,
    -- introspect the module table directly.  As a last resort, just
    -- error here so the test runner surfaces it.
    error("rpc.new failed in test harness: " .. tostring(server_or_err))
  end
  s = server_or_err
  -- Reset the fields we care about for TLS tests; the inherited
  -- register_methods() output is left alone (we never call them).
  s.tls_cert_path = opts.tls_cert_path
  s.tls_key_path  = opts.tls_key_path
  s.tls_ctx       = nil
  return s
end

--------------------------------------------------------------------------------
-- Test: TLS not requested (neither flag set) → no error, no ctx
--------------------------------------------------------------------------------
do
  local s = bare_server({tls_cert_path = nil, tls_key_path = nil})
  local ctx, err = s:_init_tls_context()
  assert_eq(ctx, nil, "no flags: returns nil ctx")
  assert_eq(err, nil, "no flags: returns nil err (plaintext path)")
end

do
  local s = bare_server({tls_cert_path = "", tls_key_path = ""})
  local ctx, err = s:_init_tls_context()
  assert_eq(ctx, nil, "empty-string flags: returns nil ctx")
  assert_eq(err, nil, "empty-string flags: returns nil err")
end

--------------------------------------------------------------------------------
-- Test: mismatched flags → fatal error
--------------------------------------------------------------------------------
do
  local s = bare_server({tls_cert_path = "/tmp/some-cert.pem", tls_key_path = nil})
  local ctx, err = s:_init_tls_context()
  assert_eq(ctx, nil, "cert-only: nil ctx")
  assert_match(err, "must both be set", "cert-only: clear mismatch error")
end

do
  local s = bare_server({tls_cert_path = nil, tls_key_path = "/tmp/some-key.pem"})
  local ctx, err = s:_init_tls_context()
  assert_eq(ctx, nil, "key-only: nil ctx")
  assert_match(err, "must both be set", "key-only: clear mismatch error")
end

--------------------------------------------------------------------------------
-- Test: nonexistent cert/key paths → fatal error
--------------------------------------------------------------------------------
if HAVE_LUASEC then
  local s = bare_server({
    tls_cert_path = "/tmp/lunarblock-fix64-does-not-exist-cert.pem",
    tls_key_path  = "/tmp/lunarblock-fix64-does-not-exist-key.pem",
  })
  local ctx, err = s:_init_tls_context()
  assert_eq(ctx, nil, "nonexistent paths: nil ctx")
  assert_match(err, "unreadable", "nonexistent paths: clear unreadable error")
else
  print("  SKIP  nonexistent-paths test (luasec unavailable)")
end

--------------------------------------------------------------------------------
-- Test: luasec missing AND TLS flags set → fatal error with install hint
--------------------------------------------------------------------------------
-- We simulate "luasec missing" by stubbing package.loaded.ssl to nil and
-- replacing the full loader chain with one that fails specifically for
-- "ssl".  Other modules don't need to load here — they're already cached
-- in package.loaded from prior requires in this test file.  This runs
-- even on hosts that DO have luasec installed.
do
  local saved_loaded   = package.loaded.ssl
  local saved_preload  = package.preload.ssl
  local saved_searchers = {}
  local searchers = package.loaders or package.searchers
  for i = 1, #searchers do saved_searchers[i] = searchers[i] end

  package.loaded.ssl = nil
  package.preload.ssl = nil
  -- Empty the searcher list, then install a single guard that fails for
  -- "ssl" specifically.  Anything else would fall through and error from
  -- require itself, which is fine — we don't load anything else here.
  for i = #searchers, 1, -1 do searchers[i] = nil end
  searchers[1] = function(mod)
    if mod == "ssl" then
      return "\n\t[fix64-test stub] ssl module hidden for graceful-degrade test"
    end
    return nil
  end

  local s = bare_server({
    tls_cert_path = CERT_PATH,  -- doesn't matter, we error before reading
    tls_key_path  = KEY_PATH,
  })
  local ctx, err = s:_init_tls_context()

  -- Restore state BEFORE asserts so a failed assert can't leave the
  -- test process unable to require("ssl") for later cases.
  for i = #searchers, 1, -1 do searchers[i] = nil end
  for i = 1, #saved_searchers do searchers[i] = saved_searchers[i] end
  package.loaded.ssl  = saved_loaded
  package.preload.ssl = saved_preload

  assert_eq(ctx, nil, "luasec-missing: nil ctx")
  assert_match(err, "luarocks install luasec", "luasec-missing: install hint present")
  assert_match(err, "luasec required", "luasec-missing: 'required' wording present")
end

--------------------------------------------------------------------------------
-- Test: real cert + real key + luasec installed → ctx returned
--------------------------------------------------------------------------------
if HAVE_LUASEC and cert_ready then
  local s = bare_server({
    tls_cert_path = CERT_PATH,
    tls_key_path  = KEY_PATH,
  })
  local ctx, err = s:_init_tls_context()
  assert_eq(err, nil, "real cert+key: nil err")
  assert_truthy(ctx, "real cert+key: ctx returned")
else
  print("  SKIP  real-cert path test (luasec=" ..
        tostring(HAVE_LUASEC) .. ", cert_ready=" .. tostring(cert_ready) .. ")")
end

--------------------------------------------------------------------------------
-- Helper: pump server:tick() repeatedly until a child curl process
-- finishes.  We can't drive client + server in one Lua thread because
-- LuaSocket's accept→handshake→receive sequence is fully synchronous;
-- a coroutine yields at the wrong granularity.  Fork the client via
-- io.popen and poll the server tick loop in the parent.
--
-- Returns the curl stdout (status line + headers + body) and the curl
-- exit code (0 on success).
local function pump_with_curl(server, curl_cmd, max_seconds)
  -- Open the child non-blockingly via popen.  popen() itself blocks
  -- only until the shell starts the child, not until curl finishes.
  local child = io.popen(curl_cmd, "r")
  if not child then return nil, -1, "popen failed" end

  local socket = require("socket")
  local start_ts = os.time()
  -- Drive tick() in a tight loop with a small sleep so we yield to OS.
  -- Tick is non-blocking on accept (settimeout(0)); when no client is
  -- waiting it returns immediately.  When a client IS waiting it does
  -- the full handshake + parse + reply + close inline, then returns.
  while os.time() - start_ts < max_seconds do
    pcall(server.tick, server)
    socket.select(nil, nil, 0.01)
    -- Cheap is-child-done probe: peek 1 byte via popen object?  Lua
    -- doesn't expose fd-level non-blocking on popen handles portably.
    -- We approximate "done" by reading the full output then close()
    -- once we've ticked long enough or detect content.
    -- Instead: loop a fixed budget, then close() will block on child
    -- exit (curl exits quickly after server replies).
  end
  local body = child:read("*a")
  local close_ok, _, rc = child:close()
  -- Lua 5.1 close() returns true on success; can't easily extract rc.
  -- Use the body content as the success signal: a non-empty body w/
  -- "HTTP/" prefix means curl saw a response.
  return body, (close_ok and 0 or 1), nil
end

--------------------------------------------------------------------------------
-- Test: HTTPS round-trip via real listener + curl client
--------------------------------------------------------------------------------
-- End-to-end smoke: bind RPC server with TLS, drive curl --insecure
-- against /health (no auth required), confirm 200 + JSON body.
-- This is the load-bearing test that proves the whole chain works.
local have_curl = (os.execute("curl --version >/dev/null 2>&1") == 0
                   or os.execute("curl --version >/dev/null 2>&1") == true)

if HAVE_LUASEC and cert_ready and have_curl then
  local rpc = require("lunarblock.rpc")
  local socket = require("socket")

  -- Pick an ephemeral port so we don't conflict with anything.
  -- Bind+release+rebind: not race-free but adequate for a single-shot test.
  local probe = socket.tcp4()
  probe:setoption("reuseaddr", true)
  assert(probe:bind("127.0.0.1", 0))
  local _, port = probe:getsockname()
  probe:close()

  local server = rpc.new({
    host = "127.0.0.1",
    rpcport = port,
    rpcuser = "lunarblock",
    rpcpassword = "",  -- empty password skips Basic-auth check (gates /health)
    rpc_tls_cert = CERT_PATH,
    rpc_tls_key  = KEY_PATH,
  })

  local ok, start_err = pcall(server.start, server)
  if not ok then
    fail("https round-trip: server:start", tostring(start_err))
  else
    -- --insecure: self-signed cert, no CA to verify against.
    -- --max-time 3: bound the call so a server bug doesn't hang the test.
    -- -i: include response headers in output (status line + Content-Type).
    -- --tls-max 1.3 / --tlsv1.2: belt-and-suspenders for the TLS range.
    local cmd = string.format(
      "curl -s -i --insecure --max-time 3 https://127.0.0.1:%d/health " ..
      "2>/dev/null", port)
    local body, rc, perr = pump_with_curl(server, cmd, 4)
    server:stop()
    if not body then
      fail("https round-trip: curl pipe", tostring(perr))
    else
      assert_match(body, "HTTP/1%.[01] 200",
                   "https round-trip: 200 OK status line")
      assert_match(body, "[Cc]ontent.[Tt]ype:.*json",
                   "https round-trip: JSON content-type")
      assert_match(body, '"status":"ok"',
                   "https round-trip: /health body present")
    end
  end
else
  print("  SKIP  https round-trip test (luasec=" ..
        tostring(HAVE_LUASEC) .. ", cert_ready=" ..
        tostring(cert_ready) .. ", curl=" .. tostring(have_curl) .. ")")
end

--------------------------------------------------------------------------------
-- Test: HTTP backward-compat — no flags, no luasec dependency, no TLS wrap
--------------------------------------------------------------------------------
-- Confirms an existing plaintext deployment is unaffected by FIX-64.
if have_curl then
  local rpc = require("lunarblock.rpc")
  local socket = require("socket")

  local probe = socket.tcp4()
  probe:setoption("reuseaddr", true)
  assert(probe:bind("127.0.0.1", 0))
  local _, port = probe:getsockname()
  probe:close()

  local server = rpc.new({
    host = "127.0.0.1",
    rpcport = port,
    rpcuser = "lunarblock",
    rpcpassword = "",
    -- INTENTIONALLY no rpc_tls_cert / rpc_tls_key
  })

  local ok, err = pcall(server.start, server)
  if not ok then
    fail("plaintext backward-compat: server:start", tostring(err))
  else
    assert_eq(server.tls_ctx, nil, "plaintext: tls_ctx nil after start")
    local cmd = string.format(
      "curl -s -i --max-time 3 http://127.0.0.1:%d/health 2>/dev/null", port)
    local body, rc, perr = pump_with_curl(server, cmd, 4)
    server:stop()
    if not body then
      fail("plaintext backward-compat: curl pipe", tostring(perr))
    else
      assert_match(body, "HTTP/1%.[01] 200",
                   "plaintext backward-compat: 200 OK")
      assert_match(body, '"status":"ok"',
                   "plaintext backward-compat: /health body")
    end
  end
else
  print("  SKIP  plaintext backward-compat test (curl unavailable)")
end

--------------------------------------------------------------------------------
-- Cleanup + summary
--------------------------------------------------------------------------------
os.execute("rm -rf " .. TMP_DIR)

print("")
print(string.format("FIX-64 TLS RPC: %d PASS, %d FAIL", PASS, FAIL))
if FAIL > 0 then os.exit(1) end
