#!/usr/bin/env luajit
-- W140 HTTP server + rpcauth + cookie auth + JSON-RPC dispatch audit (lunarblock)
--
-- Reference:
--   bitcoin-core/src/httpserver.cpp       (ClientAllowed, InitHTTPAllowList,
--                                          HTTPBindAddresses, MAX_HEADERS_SIZE,
--                                          MAX_SIZE body cap, work-queue)
--   bitcoin-core/src/httprpc.cpp          (HTTPReq_JSONRPC, RPCAuthorized,
--                                          CheckUserAuthorized, InitRPCAuthentication,
--                                          WWW-Authenticate, 250ms sleep)
--   bitcoin-core/src/rpc/request.cpp      (GenerateAuthCookie, JSONRPCRequest::parse,
--                                          IsNotification, method/params validation)
--   bitcoin-core/src/rpc/server.cpp       (JSONRPCExec)
--   bitcoin-core/src/util/strencodings.h  (TimingResistantEqual)
--   bitcoin-core/share/rpcauth/rpcauth.py (salt + HMAC-SHA256 hashed creds)
--
-- Scope:
--   Verify lunarblock's HTTP/JSON-RPC server semantics against Core's.
--   Tests cover request-parser, auth check, JSON-RPC dispatch shape,
--   notification rules, error code mapping, HTTP status mapping.
--
--   Live socket tests are deliberately avoided so the suite is hermetic.
--   tick() helpers are exercised via parse_http_request + check_auth +
--   handle_request, which are the same functions the live tick() loop
--   calls inline.
--
-- Gate map (W140):
--   G1   Bind defaults to 127.0.0.1; no --rpcbind/--rpcallowip flags
--   G2   ClientAllowed/allowlist machinery
--   G3   MAX_HEADERS_SIZE = 8192 cap
--   G4   MAX_SIZE body cap = 32 MB
--   G5   evhttp_set_timeout = 30s connection cap
--   G6   Work-queue overflow -> HTTP 503
--   G7   /, /wallet/ path routing; 404 for others
--   G8   POST-only; non-POST -> HTTP 405
--   G9   Base64 decode strict (Core DecodeBase64)
--   G10  Constant-time user+pass compare (TimingResistantEqual)
--   G11  Cookie auth on empty rpcpassword (GenerateAuthCookie)
--   G12  -rpcauth=user:salt$hmac HMAC-SHA256 support
--   G13  Plaintext password salted+hashed in-process; plaintext discarded
--   G14  WWW-Authenticate: Basic realm="jsonrpc" on 401
--   G15  250ms UninterruptibleSleep deterrent on bad auth
--   G16  -rpcwhitelist per-user method allow-list
--   G17  Invalid JSON -> -32700 PARSE_ERROR
--   G18  jsonrpc field parsed ("1.0"/"2.0" only; else -32600)
--   G19  Notifications: id missing + jsonrpc:"2.0" -> 204
--   G20  Missing/non-string method -> -32600 INVALID_REQUEST
--   G21  Non-array/non-object params -> -32600 INVALID_REQUEST
--   G22  Batch: invalid element -> -32600; all-notifications -> 204
--   G23  HTTP status mapping: -32600->400, -32601->404, others->500
--   G24  Post-shutdown 503 via http_reject_request_cb
--   G25  -rpccookieperms / -norpccookiefile knobs
--   G26  Bind error structured logging
--   G27  Duplicate Content-Length rejected
--   G28  Transfer-Encoding: chunked supported or rejected
--   G29  TLS ALPN / client-cert / cipher logging
--   G30  Pre-auth /health endpoint info disclosure

package.path = "src/?.lua;src/?/init.lua;" .. package.path

local rpc = require("lunarblock.rpc")
local cjson = require("cjson")

-- ---------------------------------------------------------------------------
-- Scaffolding
-- ---------------------------------------------------------------------------

local PASS = 0
local FAIL = 0
local XFAIL = 0
local BUGS = {}

local function pass(name) io.write(string.format("  PASS  %s\n", name)); PASS = PASS + 1 end
local function fail(name, msg) io.write(string.format("  FAIL  %s -- %s\n", name, msg)); FAIL = FAIL + 1 end
local function xfail_pre_fix(name, msg) io.write(string.format("  XFAIL %s -- %s\n", name, msg)); XFAIL = XFAIL + 1 end

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end

local function test_xfail(name, bug_id, fn)
  local ok, err = pcall(fn)
  if ok then
    pass(name .. " [now PASSing — " .. bug_id .. " fix likely landed]")
  else
    xfail_pre_fix(name .. " (" .. bug_id .. ")", tostring(err))
  end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) .. ", expected " .. tostring(b), 2)
  end
end

local function expect_truthy(v, msg)
  if not v then error((msg or "expected truthy") .. ": got " .. tostring(v), 2) end
end

local function expect_falsy(v, msg)
  if v then error((msg or "expected falsy") .. ": got " .. tostring(v), 2) end
end

local function bug(id, sev) BUGS[#BUGS + 1] = id .. " (" .. sev .. ")" end

local function build_server(cfg)
  cfg = cfg or {}
  local consensus = require("lunarblock.consensus")
  cfg.network = cfg.network or consensus.networks.regtest
  return rpc.new(cfg)
end

-- Encode plain "user:pass" string to base64 (we use Core's alphabet).
local function b64encode(s)
  local alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  local pad = (3 - #s % 3) % 3
  local padded = s .. string.rep("\0", pad)
  local out = {}
  for i = 1, #padded, 3 do
    local b1, b2, b3 = padded:byte(i, i + 2)
    local n = b1 * 65536 + b2 * 256 + b3
    out[#out + 1] = alpha:sub(math.floor(n / 262144) % 64 + 1, math.floor(n / 262144) % 64 + 1)
    out[#out + 1] = alpha:sub(math.floor(n / 4096)  % 64 + 1, math.floor(n / 4096)  % 64 + 1)
    out[#out + 1] = alpha:sub(math.floor(n / 64)    % 64 + 1, math.floor(n / 64)    % 64 + 1)
    out[#out + 1] = alpha:sub(n % 64 + 1, n % 64 + 1)
  end
  local s2 = table.concat(out)
  if pad > 0 then s2 = s2:sub(1, -pad - 1) .. string.rep("=", pad) end
  return s2
end

print("\n=========================================================================")
print("W140 HTTP server + rpcauth + cookie auth + JSON-RPC dispatch — lunarblock")
print("Source: src/rpc.lua HTTP-server + auth helpers; src/main.lua wire-up")
print("Reference: bitcoin-core/src/httpserver.cpp + httprpc.cpp + rpc/request.cpp")
print("=========================================================================")

-- ---------------------------------------------------------------------------
-- G1: Bind defaults to 127.0.0.1; no --rpcbind / --rpcallowip flags
-- ---------------------------------------------------------------------------
print("\n--- G1: Bind defaults to 127.0.0.1; --rpcbind/--rpcallowip absent ---")
test("G1-a: RPCServer host defaults to 127.0.0.1", function()
  local s = build_server({})
  expect_eq(s.host, "127.0.0.1", "default host")
end)
test_xfail("G1-b: --rpcbind flag exists in CLI parser", "BUG-1", function()
  -- BUG-1: main.lua has no --rpcbind parser path. Grep the source.
  local f = io.open("src/main.lua", "r"); local src = f:read("*a"); f:close()
  expect_truthy(src:find("[%-][%-]rpcbind", 1, false), "--rpcbind flag")
end)
test_xfail("G1-c: --rpcallowip flag exists in CLI parser", "BUG-1", function()
  local f = io.open("src/main.lua", "r"); local src = f:read("*a"); f:close()
  expect_truthy(src:find("[%-][%-]rpcallowip", 1, false), "--rpcallowip flag")
end)
bug("BUG-1", "P3")

-- ---------------------------------------------------------------------------
-- G2: ClientAllowed / InitHTTPAllowList machinery
-- ---------------------------------------------------------------------------
print("\n--- G2: ClientAllowed / InitHTTPAllowList ---")
test_xfail("G2: server exposes a client_allowed(addr) function", "BUG-2", function()
  -- BUG-2: rpc.lua has no ClientAllowed equivalent.
  local f = io.open("src/rpc.lua", "r"); local src = f:read("*a"); f:close()
  expect_truthy(src:find("client_allowed", 1, true) or src:find("ClientAllowed", 1, true),
                "ClientAllowed/client_allowed function")
end)
bug("BUG-2", "P3")

-- ---------------------------------------------------------------------------
-- G3: MAX_HEADERS_SIZE = 8192 cap (request header block)
-- ---------------------------------------------------------------------------
print("\n--- G3: MAX_HEADERS_SIZE = 8192 cap ---")
test_xfail("G3: parse_http_request enforces 8192-byte header-block cap", "BUG-3", function()
  -- Synthesize an oversized header block; expect parse failure
  -- with explicit "headers too large" error. Today it'll succeed
  -- because parse_http_request just looks for \r\n\r\n.
  local big = string.rep("X-Pad: " .. string.rep("a", 200) .. "\r\n", 50)  -- ~10 KB
  local data = "POST / HTTP/1.1\r\n" ..
               "Host: x\r\n" ..
               big ..
               "Content-Length: 0\r\n\r\n"
  local method, path, headers, body = rpc.parse_http_request(data)
  -- BUG-3 expectation: this should fail with a "headers too large" error,
  -- but lunarblock happily returns POST/, ...
  if method == nil then
    return  -- Already correct (fix landed)
  end
  error("expected oversized-headers rejection; got method=" .. tostring(method))
end)
bug("BUG-3", "P1")

-- ---------------------------------------------------------------------------
-- G4: MAX_SIZE body cap = 32 MB
-- ---------------------------------------------------------------------------
print("\n--- G4: MAX_SIZE body cap = 32 MB ---")
test_xfail("G4: tick() refuses Content-Length > 32 MB", "BUG-4", function()
  -- We can't run tick() against a fake socket cleanly here, but we can
  -- verify that there's a body-size constant defined and a guard.  The
  -- naive `content_length > 0` guard already in rpc.lua does NOT count;
  -- a real cap compares against a multi-byte threshold (e.g. > 33554432).
  local f = io.open("src/rpc.lua", "r"); local src = f:read("*a"); f:close()
  local has_cap = src:find("MAX_BODY_SIZE", 1, true)
                  or src:find("MAX_REQUEST_SIZE", 1, true)
                  or src:find("0x02000000", 1, true)         -- Core's MAX_SIZE
                  or src:find("33554432", 1, true)            -- 32 MB decimal
                  or src:find("content_length%s*>%s*%d%d%d", 1, false)  -- > triple-digit
  expect_truthy(has_cap, "body-size cap (a guard with a real threshold)")
end)
bug("BUG-4", "P1")

-- ---------------------------------------------------------------------------
-- G5: 30s connection idle cap
-- ---------------------------------------------------------------------------
print("\n--- G5: 30s per-connection idle cap ---")
test("G5: per-receive 1s timeout exists (rpc.lua:8493)", function()
  -- Present, but only per-receive; no overall cap. Mark PARTIAL.
  local f = io.open("src/rpc.lua", "r"); local src = f:read("*a"); f:close()
  -- "settimeout(1)" — use pattern mode (plain=false) to match parens.
  expect_truthy(src:find("settimeout%(1%)", 1, false), "per-receive 1s timeout")
end)

-- ---------------------------------------------------------------------------
-- G6: Work-queue overflow → 503
-- ---------------------------------------------------------------------------
print("\n--- G6: Work-queue overflow → 503 ---")
test_xfail("G6: HTTP 503 emitted when worker queue full", "BUG-5", function()
  -- BUG-5: no worker queue exists. Single-threaded serial tick.
  local f = io.open("src/rpc.lua", "r"); local src = f:read("*a"); f:close()
  expect_truthy(src:find("HTTP/1.1 503", 1, true) or src:find("Service Unavailable", 1, true),
                "503 path")
end)
bug("BUG-5", "P2")

-- ---------------------------------------------------------------------------
-- G7: Path routing (/ exact, /wallet/ prefix, 404 otherwise)
-- ---------------------------------------------------------------------------
print("\n--- G7: Path routing ---")
test_xfail("G7-a: POST /admin returns 404, not dispatch to JSON-RPC", "BUG-6", function()
  -- We can only verify via static grep that the tick path has a
  -- whitelist of acceptable URIs before reaching handle_request.
  local f = io.open("src/rpc.lua", "r"); local src = f:read("*a"); f:close()
  -- Core-equivalent shape: a 404 emitted when path ~= "/" and not /wallet/
  expect_truthy(src:find('path ~= "/"', 1, true) or src:find('path%s*~=%s*"/"', 1, false),
                "exact / match")
end)
bug("BUG-6", "P2")

-- ---------------------------------------------------------------------------
-- G8: POST-only; non-POST → 405
-- ---------------------------------------------------------------------------
print("\n--- G8: POST-only / 405 for non-POST ---")
test_xfail("G8: PUT/DELETE returns HTTP 405 Bad Method", "BUG-7", function()
  -- Static: lunarblock returns 404 for non-POST (rpc.lua:8575).
  local f = io.open("src/rpc.lua", "r"); local src = f:read("*a"); f:close()
  expect_truthy(src:find("405", 1, true) or src:find("Bad Method", 1, true),
                "HTTP 405 path")
end)
bug("BUG-7", "P2")

-- ---------------------------------------------------------------------------
-- G9: Base64 decode strict
-- ---------------------------------------------------------------------------
print("\n--- G9: Base64 decode strict ---")
test_xfail("G9-a: base64_decode rejects non-Base64 chars (no silent strip)", "BUG-8", function()
  -- Core's DecodeBase64 returns nil; lunarblock's gsubs invalid chars away.
  local decoded = rpc.base64_decode("AB#%CD")
  -- If the fix landed, decoded would be nil/false.
  if decoded == nil or decoded == false then return end
  error("permissive base64: got " .. tostring(decoded) .. " (should reject)")
end)
test_xfail("G9-b: base64_decode rejects len % 4 != 0", "BUG-8", function()
  -- Core: returns nil for str.size() % 4 != 0
  local decoded = rpc.base64_decode("ABC")  -- 3 chars, not %4
  if decoded == nil or decoded == false then return end
  error("permissive base64: 3-char input decoded to " .. tostring(decoded))
end)
bug("BUG-8", "P2")

-- ---------------------------------------------------------------------------
-- G10: Constant-time compare (TimingResistantEqual)
-- ---------------------------------------------------------------------------
print("\n--- G10: Constant-time password compare (P0-SEC) ---")
test_xfail("G10: check_auth uses constant-time compare", "BUG-9", function()
  -- We can't directly measure timing here. Verify via static grep
  -- that check_auth uses something other than naive ==.
  local f = io.open("src/rpc.lua", "r"); local src = f:read("*a"); f:close()
  -- The check_auth source body
  local s, e = src:find("function M%.check_auth", 1, false)
  if not s then error("check_auth not found") end
  local body = src:sub(s, s + 600)
  -- Bad form: "return decoded == expected"
  if body:find("decoded%s*==%s*expected") then
    error("check_auth uses naive == (timing oracle)")
  end
end)
bug("BUG-9", "P0-SEC")

-- ---------------------------------------------------------------------------
-- G11: Cookie auth on empty rpcpassword
-- ---------------------------------------------------------------------------
print("\n--- G11: Cookie auth on empty rpcpassword (P0-SEC) ---")
test_xfail("G11-a: empty rpcpassword does NOT bypass auth", "BUG-10", function()
  -- The critical P0-SEC test. self.password = "" disables auth check.
  local s = build_server({rpcuser = "anyone", rpcpassword = ""})
  -- Read the source of tick() to verify the bypass exists.
  local f = io.open("src/rpc.lua", "r"); local src = f:read("*a"); f:close()
  -- The bypass condition: `if self.password ~= "" and not M.check_auth(...)`
  -- — note that an empty password skips check_auth entirely.
  if src:find('self%.password%s*~=%s*""', 1, false) then
    error("empty rpcpassword bypasses auth (rpc.lua:8529)")
  end
end)
test_xfail("G11-b: GenerateAuthCookie-equivalent function exists", "BUG-10", function()
  local f = io.open("src/rpc.lua", "r"); local src = f:read("*a"); f:close()
  expect_truthy(src:find("generate_auth_cookie", 1, true)
                or src:find("GenerateAuthCookie", 1, true)
                or src:find("__cookie__", 1, true),
                "cookie generator")
end)
test_xfail("G11-c: __cookie__ user prefix used when auto-cookie", "BUG-10", function()
  local f = io.open("src/rpc.lua", "r"); local src = f:read("*a"); f:close()
  expect_truthy(src:find("__cookie__", 1, true), "__cookie__ literal")
end)
bug("BUG-10", "P0-SEC")

-- ---------------------------------------------------------------------------
-- G12: -rpcauth=user:salt$hmac support
-- ---------------------------------------------------------------------------
print("\n--- G12: -rpcauth=user:salt$hmac support ---")
test_xfail("G12: --rpcauth flag accepted by main.lua", "BUG-11", function()
  local f = io.open("src/main.lua", "r"); local src = f:read("*a"); f:close()
  expect_truthy(src:find("[%-][%-]rpcauth", 1, false), "--rpcauth flag")
end)
test_xfail("G12: rpcauth list verified via HMAC-SHA256", "BUG-11", function()
  local f = io.open("src/rpc.lua", "r"); local src = f:read("*a"); f:close()
  expect_truthy(src:find("hmac_sha256", 1, true) or src:find("HMAC_SHA256", 1, true),
                "HMAC-SHA256 reference in rpc.lua")
end)
bug("BUG-11", "P1")

-- ---------------------------------------------------------------------------
-- G13: Plaintext password salted+hashed; plaintext discarded
-- ---------------------------------------------------------------------------
print("\n--- G13: Plaintext password hashed in-process ---")
test_xfail("G13: self.password is HMAC, not plaintext", "BUG-12", function()
  -- After M.new(), the plaintext should not be retrievable.
  local s = build_server({rpcuser = "u", rpcpassword = "p"})
  if s.password == "p" then
    error("plaintext rpcpassword retained as self.password")
  end
end)
bug("BUG-12", "P1")

-- ---------------------------------------------------------------------------
-- G14: WWW-Authenticate header on 401
-- ---------------------------------------------------------------------------
print("\n--- G14: WWW-Authenticate header on 401 ---")
test_xfail("G14: 401 response includes WWW-Authenticate", "BUG-13", function()
  local f = io.open("src/rpc.lua", "r"); local src = f:read("*a"); f:close()
  expect_truthy(src:find("WWW%-Authenticate", 1, false), "WWW-Authenticate header")
end)
bug("BUG-13", "P2")

-- ---------------------------------------------------------------------------
-- G15: 250ms sleep on bad auth
-- ---------------------------------------------------------------------------
print("\n--- G15: 250ms anti-brute-force sleep ---")
test_xfail("G15: tick() sleeps 250ms before sending 401", "BUG-14", function()
  local f = io.open("src/rpc.lua", "r"); local src = f:read("*a"); f:close()
  -- LuaSocket has socket.sleep(0.25) for 250ms
  expect_truthy(src:find("sleep%(0%.25", 1, false) or src:find("sleep%(250", 1, false),
                "anti-brute-force sleep")
end)
bug("BUG-14", "P1")

-- ---------------------------------------------------------------------------
-- G16: -rpcwhitelist per-user method allow-list
-- ---------------------------------------------------------------------------
print("\n--- G16: Per-user method whitelist ---")
test_xfail("G16: --rpcwhitelist flag accepted by main.lua", "BUG-15", function()
  local f = io.open("src/main.lua", "r"); local src = f:read("*a"); f:close()
  expect_truthy(src:find("[%-][%-]rpcwhitelist", 1, false), "--rpcwhitelist flag")
end)
bug("BUG-15", "P1")

-- ---------------------------------------------------------------------------
-- G17: Invalid JSON → -32700
-- ---------------------------------------------------------------------------
print("\n--- G17: PARSE_ERROR -32700 on invalid JSON ---")
test("G17: handle_request returns -32700 on bad JSON", function()
  local s = build_server({})
  local body = s:handle_request("{not valid json")
  local parsed = cjson.decode(body)
  expect_eq(parsed.error.code, -32700, "PARSE_ERROR code")
end)

-- ---------------------------------------------------------------------------
-- G18: jsonrpc field parsed and validated
-- ---------------------------------------------------------------------------
print("\n--- G18: jsonrpc version field parsed ---")
test_xfail("G18-a: jsonrpc:'9.9' rejected with -32600", "BUG-16", function()
  local s = build_server({})
  local body = s:handle_request('{"jsonrpc":"9.9","method":"getblockcount","id":1}')
  local parsed = cjson.decode(body)
  -- Core raises -32600; lunarblock returns whatever the handler returns
  -- (or -32601 for unknown methods).  Guard for cjson.null on error.
  local code = type(parsed.error) == "table" and parsed.error.code or nil
  expect_eq(code, -32600, "INVALID_REQUEST on bad jsonrpc")
end)
test_xfail("G18-b: response includes jsonrpc:'2.0' on v2 request", "BUG-16", function()
  local s = build_server({})
  local body = s:handle_request('{"jsonrpc":"2.0","method":"getblockcount","id":1}')
  local parsed = cjson.decode(body)
  expect_eq(parsed.jsonrpc, "2.0", "echoed jsonrpc version")
end)
bug("BUG-16", "P1")

-- ---------------------------------------------------------------------------
-- G19: Notifications require id missing AND jsonrpc:"2.0"
-- ---------------------------------------------------------------------------
print("\n--- G19: Notifications require id missing + jsonrpc:2.0 ---")
test_xfail("G19: v1 request with no id still gets a response", "BUG-17", function()
  -- lunarblock currently returns nil ⇒ "" body (204). Core would respond.
  local s = build_server({})
  local body = s:handle_request('{"method":"getblockcount"}')
  -- If body is empty, lunarblock treated this as a notification: BUG-17
  if body == "" or body == nil then
    error("v1 missing-id treated as notification; should get a response")
  end
end)
bug("BUG-17", "P1")

-- ---------------------------------------------------------------------------
-- G20: Missing/non-string method → -32600
-- ---------------------------------------------------------------------------
print("\n--- G20: Missing/non-string method → -32600 ---")
test_xfail("G20-a: missing method returns -32600 INVALID_REQUEST", "BUG-18", function()
  local s = build_server({})
  local body = s:handle_request('{"jsonrpc":"2.0","id":1}')
  local parsed = cjson.decode(body)
  expect_eq(parsed.error.code, -32600, "INVALID_REQUEST on missing method")
end)
test_xfail("G20-b: non-string method returns -32600", "BUG-18", function()
  local s = build_server({})
  local body = s:handle_request('{"jsonrpc":"2.0","method":42,"id":1}')
  local parsed = cjson.decode(body)
  expect_eq(parsed.error.code, -32600, "INVALID_REQUEST on numeric method")
end)
bug("BUG-18", "P1")

-- ---------------------------------------------------------------------------
-- G21: Non-array/non-object params → -32600
-- ---------------------------------------------------------------------------
print("\n--- G21: Non-array/non-object params → -32600 ---")
test_xfail("G21: string params returns -32600", "BUG-19", function()
  local s = build_server({})
  local body = s:handle_request('{"jsonrpc":"2.0","method":"getblockcount","params":"hi","id":1}')
  local parsed = cjson.decode(body)
  local code = type(parsed.error) == "table" and parsed.error.code or nil
  expect_eq(code, -32600, "INVALID_REQUEST on string params")
end)
bug("BUG-19", "P2")

-- ---------------------------------------------------------------------------
-- G22: Batch shape & MAX_BATCH_SIZE deviation
-- ---------------------------------------------------------------------------
print("\n--- G22: Batch shape + size cap ---")
test("G22-a: batch with invalid element returns -32600 for that slot", function()
  local s = build_server({})
  local body = s:handle_request('[{"jsonrpc":"2.0","method":"getblockcount","id":1},"not-an-object"]')
  local parsed = cjson.decode(body)
  -- Find the non-object slot's error.  cjson.null is a sentinel userdata
  -- so we must check type before indexing .code.
  local found = false
  for _, r in ipairs(parsed) do
    if type(r) == "table" and type(r.error) == "table" and r.error.code == -32600 then
      found = true
    end
  end
  expect_truthy(found, "INVALID_REQUEST on non-object element")
end)
test_xfail("G22-b: no custom MAX_BATCH_SIZE = 1000 hard cap", "BUG-20", function()
  -- Core has no batch hard cap.
  if rpc.MAX_BATCH_SIZE then
    error("custom MAX_BATCH_SIZE = " .. tostring(rpc.MAX_BATCH_SIZE)
          .. " — Core has none")
  end
end)
bug("BUG-20", "P3")

-- ---------------------------------------------------------------------------
-- G23: HTTP status mapping for JSON-RPC errors
-- ---------------------------------------------------------------------------
print("\n--- G23: HTTP status mapping for JSON-RPC errors ---")
test_xfail("G23-a: -32600 INVALID_REQUEST maps to HTTP 400", "BUG-21", function()
  -- handle_request returns (body, status_override). The status_override
  -- for INVALID_REQUEST should be 400 per Core JSONErrorReply.
  local s = build_server({})
  local body, status = s:handle_request('{"jsonrpc":"2.0","method":42,"id":1}')
  expect_eq(status, 400, "HTTP 400 status override on -32600")
end)
test_xfail("G23-b: -32601 METHOD_NOT_FOUND maps to HTTP 404", "BUG-21", function()
  local s = build_server({})
  local body, status = s:handle_request('{"jsonrpc":"2.0","method":"nonexistent_xyz","id":1}')
  expect_eq(status, 404, "HTTP 404 status override on -32601")
end)
bug("BUG-21", "P1")

-- ---------------------------------------------------------------------------
-- G24: Post-shutdown 503
-- ---------------------------------------------------------------------------
print("\n--- G24: Post-shutdown 503 reply ---")
test_xfail("G24: shutdown swaps handler to return 503", "BUG-22", function()
  local f = io.open("src/rpc.lua", "r"); local src = f:read("*a"); f:close()
  -- Look for a reject-after-shutdown path.
  expect_truthy(src:find("503", 1, true) or src:find("shutting down", 1, false),
                "shutdown 503 path")
end)
bug("BUG-22", "P3")

-- ---------------------------------------------------------------------------
-- G25: -rpccookieperms (subsumed by BUG-10)
-- ---------------------------------------------------------------------------
print("\n--- G25: -rpccookieperms / -norpccookiefile ---")
test_xfail("G25: --rpccookieperms accepted by main.lua", "BUG-10", function()
  local f = io.open("src/main.lua", "r"); local src = f:read("*a"); f:close()
  expect_truthy(src:find("[%-][%-]rpccookieperms", 1, false), "--rpccookieperms flag")
end)

-- ---------------------------------------------------------------------------
-- G26: Bind error structured logging
-- ---------------------------------------------------------------------------
print("\n--- G26: Bind error structured logging ---")
test("G26: start() uses assert() (loud, but not structured)", function()
  local f = io.open("src/rpc.lua", "r"); local src = f:read("*a"); f:close()
  expect_truthy(src:find("assert%(self%.server_socket:bind", 1, false), "bind via assert")
  -- Not a parity bug per se; documentation only.
end)

-- ---------------------------------------------------------------------------
-- G27: Duplicate Content-Length rejected (request smuggling)
-- ---------------------------------------------------------------------------
print("\n--- G27: Duplicate Content-Length rejected ---")
test_xfail("G27: parse_http_request rejects duplicate Content-Length", "BUG-23", function()
  local data = "POST / HTTP/1.1\r\n" ..
               "Host: x\r\n" ..
               "Content-Length: 5\r\n" ..
               "Content-Length: 3\r\n\r\n" ..
               "hello"
  local method, path, headers, body = rpc.parse_http_request(data)
  -- Core/libevent would reject. lunarblock takes the last value (3 → "hel").
  if method == nil then return end  -- fix landed
  error("permissive: duplicate Content-Length accepted, body='" ..
        tostring(body) .. "'")
end)
bug("BUG-23", "P1")

-- ---------------------------------------------------------------------------
-- G28: Transfer-Encoding: chunked handled or rejected
-- ---------------------------------------------------------------------------
print("\n--- G28: Transfer-Encoding: chunked ---")
test_xfail("G28: chunked POST is parsed correctly or rejected", "BUG-24", function()
  local f = io.open("src/rpc.lua", "r"); local src = f:read("*a"); f:close()
  -- Look for any Transfer-Encoding handling.
  expect_truthy(src:find("[Tt]ransfer%-[Ee]ncoding", 1, false), "Transfer-Encoding handling")
end)
bug("BUG-24", "P1")

-- ---------------------------------------------------------------------------
-- G29: TLS — ALPN / client cert / cipher logging
-- ---------------------------------------------------------------------------
print("\n--- G29: TLS extras (ALPN / client cert) ---")
test("G29-a: TLS context uses TLSv1.2+ baseline", function()
  -- W119 FIX-64 already verified. Static check is sufficient.
  local f = io.open("src/rpc.lua", "r"); local src = f:read("*a"); f:close()
  expect_truthy(src:find("no_tlsv1_1", 1, true), "no_tlsv1_1 option")
end)
test_xfail("G29-b: ALPN advertises http/1.1", "BUG-25", function()
  local f = io.open("src/rpc.lua", "r"); local src = f:read("*a"); f:close()
  expect_truthy(src:find("alpn", 1, false), "ALPN config")
end)
bug("BUG-25", "P3")

-- ---------------------------------------------------------------------------
-- G30: Pre-auth /health endpoint info disclosure
-- ---------------------------------------------------------------------------
print("\n--- G30: Pre-auth /health endpoint info disclosure ---")
test_xfail("G30-a: /health does not echo impl name", "BUG-26", function()
  local f = io.open("src/rpc.lua", "r"); local src = f:read("*a"); f:close()
  -- Today: '"version":"lunarblock"' is hardcoded in tick().
  if src:find('"version":"lunarblock"', 1, true) then
    error("/health discloses impl name to unauthed clients")
  end
end)
test_xfail("G30-b: /health does not echo chain tip height", "BUG-26", function()
  local f = io.open("src/rpc.lua", "r"); local src = f:read("*a"); f:close()
  if src:find('"height":%%d', 1, false) and src:find('tip_height', 1, true) then
    error("/health discloses tip_height to unauthed clients")
  end
end)
bug("BUG-26", "P2")

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
print("\n=========================================================================")
print(string.format("Pass: %d  Fail: %d  XFail-pre-fix: %d", PASS, FAIL, XFAIL))
print(string.format("Bugs catalogued: %d", #BUGS))
for _, b in ipairs(BUGS) do io.write("  ", b, "\n") end
print("=========================================================================")

if FAIL > 0 then os.exit(1) end
os.exit(0)
