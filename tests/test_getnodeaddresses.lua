#!/usr/bin/env luajit
-- getnodeaddresses Core-shape parity regression — lunarblock (Lua / LuaJIT)
--
-- Reference: bitcoin-core/src/rpc/net.cpp:911-970 (getnodeaddresses)
--            bitcoin-core/src/netbase.cpp:100-128 (ParseNetwork / GetNetworkName)
--
-- The handler already exists (src/rpc.lua:3326) and is Core-correct; this
-- file is the missing regression test.  Core's getnodeaddresses returns a
-- JSON ARRAY of objects, each with EXACTLY 5 keys in THIS ORDER:
--   time     unix seconds         INTEGER
--   services raw services bitfield INTEGER (NOT hex)
--   address  ToStringAddr literal  STRING  (NO port)
--   port                           INTEGER
--   network  ipv4|ipv6|onion|i2p|cjdns|not_publicly_routable|internal STRING
--
-- Arg shape: getnodeaddresses ( count "network" )
--   count default 1; count==0 -> ALL; count<0 -> error -8 'Address count out of range'.
--   network optional, lowercased, only ipv4|ipv6|onion|i2p|cjdns else
--     error -8 'Network not recognized: <raw>' (raw casing preserved).
--   Empty addrman -> [].
--
-- Because cjson does NOT preserve key order, the handler builds the JSON by
-- hand and returns {_raw_json=<string>}; the dispatcher splices it in.  This
-- test asserts BOTH the decoded values AND the literal byte order of the keys.
--
-- Gate map:
--   G1   empty known_addresses -> result is []
--   G2   one IPv4 entry, default count -> 1 object, exact 5 keys/types, network=ipv4, address has NO port
--   G3   raw-JSON key ORDER is time,services,address,port,network (string.find positions)
--   G4   services emitted as INTEGER not hex (inject 0x409/1033 -> decoded==1033, raw has '"services":1033')
--   G5   count==0 returns ALL injected
--   G6   count<0 -> error -8, exact message 'Address count out of range'
--   G7   network filter 'IPV4' (mixed case) lowercases and matches
--   G8   unrecognized network 'foobar' -> error -8, exact 'Network not recognized: foobar'
--   G9   network='onion' filters to only the injected .onion entry
--   G10  count caps result to min(count, total)

package.path = "src/?.lua;src/?/init.lua;" .. package.path

local rpc       = require("lunarblock.rpc")
local cjson     = require("cjson")
local consensus = require("lunarblock.consensus")
local peerman   = require("lunarblock.peerman")
local p2p       = require("lunarblock.p2p")

-- ---------------------------------------------------------------------------
-- Test scaffolding (mirrors tests/test_w125_error_parity.lua)
-- ---------------------------------------------------------------------------

local PASS, FAIL = 0, 0

local function pass(name)
  io.write(string.format("  PASS  %s\n", name))
  PASS = PASS + 1
end

local function fail(name, msg)
  io.write(string.format("  FAIL  %s -- %s\n", name, msg))
  FAIL = FAIL + 1
end

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) ..
          ", expected " .. tostring(b), 2)
  end
end

local function expect_true(cond, msg)
  if not cond then error(msg or "expected true", 2) end
end

-- Build an RPCServer wired to a fresh regtest PeerManager.  Returns the
-- server and its peer_manager so each test can seed known_addresses.
local function build_server()
  local pm = peerman.new(consensus.networks.regtest)
  local server = rpc.new({
    network      = consensus.networks.regtest,
    peer_manager = pm,
  })
  return server, pm
end

-- Invoke the handler directly; returns ok, result-or-err.
local function call_gna(server, params)
  local handler = server.methods["getnodeaddresses"]
  if not handler then error("getnodeaddresses not registered", 2) end
  return pcall(handler, server, params)
end

-- Decode a successful {_raw_json=...} result into a Lua array.
local function decode(result)
  expect_true(type(result) == "table", "result must be a table")
  expect_true(type(result._raw_json) == "string",
              "result must carry a _raw_json string")
  return cjson.decode(result._raw_json), result._raw_json
end

print("\n=========================================================================")
print("getnodeaddresses Core-shape parity — lunarblock")
print("Handler: src/rpc.lua:3326   Ref: bitcoin-core/src/rpc/net.cpp:911-970")
print("=========================================================================\n")

-- ---------------------------------------------------------------------------
-- G1: empty known_addresses -> []
-- ---------------------------------------------------------------------------
test("G1: empty addrman returns []", function()
  local server = build_server()
  local ok, result = call_gna(server, {})
  expect_true(ok, "call failed: " .. tostring(result))
  local arr, raw = decode(result)
  expect_eq(#arr, 0, "array length")
  expect_eq(raw, "[]", "raw JSON for empty addrman")
end)

-- ---------------------------------------------------------------------------
-- G2: one IPv4 entry, default count -> 1 object, exact 5 keys + types
-- ---------------------------------------------------------------------------
test("G2: single IPv4, default count -> 1 object, exact shape/types", function()
  local server, pm = build_server()
  pm:add_known_address("203.0.113.7", 8333,
    bit.bor(p2p.SERVICES.NODE_NETWORK, p2p.SERVICES.NODE_WITNESS), 1700000000)
  local ok, result = call_gna(server, {})
  expect_true(ok, "call failed: " .. tostring(result))
  local arr = decode(result)
  expect_eq(#arr, 1, "array length")
  local o = arr[1]

  -- EXACTLY 5 keys, no more.
  local nkeys = 0
  for _ in pairs(o) do nkeys = nkeys + 1 end
  expect_eq(nkeys, 5, "object key count")

  -- Presence of each key.
  for _, k in ipairs({ "time", "services", "address", "port", "network" }) do
    expect_true(o[k] ~= nil, "missing key: " .. k)
  end

  -- Types: time/services/port integer, address/network string.
  expect_eq(type(o.time), "number", "time type")
  expect_eq(o.time, math.floor(o.time), "time is integral")
  expect_eq(type(o.services), "number", "services type")
  expect_eq(o.services, math.floor(o.services), "services is integral")
  expect_eq(type(o.port), "number", "port type")
  expect_eq(o.port, math.floor(o.port), "port is integral")
  expect_eq(type(o.address), "string", "address type")
  expect_eq(type(o.network), "string", "network type")

  -- Values.
  expect_eq(o.time, 1700000000, "time value")
  expect_eq(o.address, "203.0.113.7", "address literal")
  expect_eq(o.port, 8333, "port value")
  expect_eq(o.network, "ipv4", "network classification")

  -- address must carry NO port (Core ToStringAddr).
  expect_true(o.address:find(":", 1, true) == nil, "address must not contain ':'")
  expect_true(o.address:find(tostring(8333), 1, true) == nil,
              "address must not embed the port")
end)

-- ---------------------------------------------------------------------------
-- G3: raw-JSON key ORDER is time,services,address,port,network
-- cjson would reorder a decoded table, so assert on the literal string.
-- ---------------------------------------------------------------------------
test("G3: raw-JSON key order is time,services,address,port,network", function()
  local server, pm = build_server()
  pm:add_known_address("198.51.100.4", 18333, p2p.SERVICES.NODE_NETWORK, 1699999999)
  local ok, result = call_gna(server, {})
  expect_true(ok, "call failed: " .. tostring(result))
  local _, raw = decode(result)

  local p_time     = raw:find('"time"',     1, true)
  local p_services = raw:find('"services"', 1, true)
  local p_address  = raw:find('"address"',  1, true)
  local p_port     = raw:find('"port"',     1, true)
  local p_network  = raw:find('"network"',  1, true)

  expect_true(p_time, "time key present in raw JSON")
  expect_true(p_services, "services key present in raw JSON")
  expect_true(p_address, "address key present in raw JSON")
  expect_true(p_port, "port key present in raw JSON")
  expect_true(p_network, "network key present in raw JSON")

  expect_true(p_time < p_services, "time before services")
  expect_true(p_services < p_address, "services before address")
  expect_true(p_address < p_port, "address before port")
  expect_true(p_port < p_network, "port before network")
end)

-- ---------------------------------------------------------------------------
-- G4: services emitted as INTEGER not hex
-- ---------------------------------------------------------------------------
test("G4: services emitted as integer (1033), not hex", function()
  local server, pm = build_server()
  -- 0x409 = 1033 = NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED.
  pm:add_known_address("192.0.2.1", 8333, 0x409, 1700000001)
  local ok, result = call_gna(server, {})
  expect_true(ok, "call failed: " .. tostring(result))
  local arr, raw = decode(result)
  expect_eq(arr[1].services, 1033, "decoded services value")
  expect_true(raw:find('"services":1033', 1, true) ~= nil,
              'raw JSON must contain "services":1033')
  -- No hex form.
  expect_true(raw:lower():find("0x", 1, true) == nil,
              "services must not be hex-encoded")
end)

-- ---------------------------------------------------------------------------
-- G5: count==0 returns ALL injected
-- ---------------------------------------------------------------------------
test("G5: count==0 returns all injected", function()
  local server, pm = build_server()
  pm:add_known_address("203.0.113.1", 8333, p2p.SERVICES.NODE_NETWORK, 1700000010)
  pm:add_known_address("203.0.113.2", 8333, p2p.SERVICES.NODE_NETWORK, 1700000011)
  pm:add_known_address("203.0.113.3", 8333, p2p.SERVICES.NODE_NETWORK, 1700000012)
  local ok, result = call_gna(server, { 0 })
  expect_true(ok, "call failed: " .. tostring(result))
  local arr = decode(result)
  expect_eq(#arr, 3, "count==0 returns all 3")
end)

-- ---------------------------------------------------------------------------
-- G6: count<0 -> error -8 'Address count out of range'
-- ---------------------------------------------------------------------------
test("G6: count<0 -> error -8 'Address count out of range'", function()
  local server = build_server()
  local ok, err = call_gna(server, { -1 })
  expect_true(not ok, "expected error, call succeeded")
  expect_true(type(err) == "table" and err.code, "structured error expected")
  expect_eq(err.code, -8, "error code")
  expect_eq(err.message, "Address count out of range", "error message")
end)

-- ---------------------------------------------------------------------------
-- G7: network filter 'IPV4' (mixed case) lowercases and matches
-- ---------------------------------------------------------------------------
test("G7: network filter 'IPV4' (mixed case) matches IPv4 entries", function()
  local server, pm = build_server()
  pm:add_known_address("203.0.113.20", 8333, p2p.SERVICES.NODE_NETWORK, 1700000020)
  local ok, result = call_gna(server, { 0, "IPV4" })
  expect_true(ok, "call failed: " .. tostring(result))
  local arr = decode(result)
  expect_eq(#arr, 1, "IPV4 (mixed case) matched the ipv4 entry")
  expect_eq(arr[1].network, "ipv4", "network classification")
end)

-- ---------------------------------------------------------------------------
-- G8: unrecognized network 'foobar' -> error -8, raw casing preserved
-- ---------------------------------------------------------------------------
test("G8: network 'foobar' -> error -8 'Network not recognized: foobar'", function()
  local server = build_server()
  local ok, err = call_gna(server, { 1, "foobar" })
  expect_true(not ok, "expected error, call succeeded")
  expect_true(type(err) == "table" and err.code, "structured error expected")
  expect_eq(err.code, -8, "error code")
  expect_eq(err.message, "Network not recognized: foobar", "error message")
end)

test("G8b: unrecognized network preserves raw casing ('FooBar')", function()
  local server = build_server()
  local ok, err = call_gna(server, { 1, "FooBar" })
  expect_true(not ok, "expected error, call succeeded")
  expect_eq(err.code, -8, "error code")
  expect_eq(err.message, "Network not recognized: FooBar", "raw casing preserved")
end)

-- ---------------------------------------------------------------------------
-- G9: network='onion' filters to only the injected .onion entry
-- ---------------------------------------------------------------------------
test("G9: network='onion' filters to only the .onion entry", function()
  local server, pm = build_server()
  -- One IPv4 + one onion (seeded directly so we can set addr_str/network_id).
  pm:add_known_address("203.0.113.30", 8333, p2p.SERVICES.NODE_NETWORK, 1700000030)
  pm.known_addresses["onion:9001"] = {
    ip         = "onion",
    addr_str   = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
    port       = 9001,
    services   = p2p.SERVICES.NODE_NETWORK,
    timestamp  = 1700000031,
    network_id = p2p.NET_ID.TORV3,
    attempts   = 0,
    last_try   = 0,
  }
  local ok, result = call_gna(server, { 0, "onion" })
  expect_true(ok, "call failed: " .. tostring(result))
  local arr = decode(result)
  expect_eq(#arr, 1, "only the onion entry matched")
  expect_eq(arr[1].network, "onion", "network classification")
  expect_eq(arr[1].address,
    "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
    "onion address literal")
  expect_eq(arr[1].port, 9001, "onion port")
  -- onion address must not embed the port either.
  expect_true(arr[1].address:find(":", 1, true) == nil,
              "onion address must not contain ':'")
end)

-- ---------------------------------------------------------------------------
-- G10: count caps result to min(count, total)
-- ---------------------------------------------------------------------------
test("G10: count caps result to min(count, total)", function()
  local server, pm = build_server()
  for i = 1, 5 do
    pm:add_known_address("203.0.113." .. (100 + i), 8333,
      p2p.SERVICES.NODE_NETWORK, 1700000100 + i)
  end
  -- count=2 < total=5 -> exactly 2.
  local ok, result = call_gna(server, { 2 })
  expect_true(ok, "call failed: " .. tostring(result))
  local arr = decode(result)
  expect_eq(#arr, 2, "count=2 caps to 2 of 5")

  -- count=10 > total=5 -> all 5 (min(count,total)).
  local ok2, result2 = call_gna(server, { 10 })
  expect_true(ok2, "call failed: " .. tostring(result2))
  local arr2 = decode(result2)
  expect_eq(#arr2, 5, "count=10 caps to total 5")
end)

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
print("\n=========================================================================")
io.write(string.format("getnodeaddresses parity — PASS: %d  FAIL: %d\n", PASS, FAIL))
print("=========================================================================")

if FAIL > 0 then os.exit(1) end
os.exit(0)
