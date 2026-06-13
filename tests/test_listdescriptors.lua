#!/usr/bin/env luajit
-- listdescriptors Core-shape parity regression — lunarblock (Lua / LuaJIT)
--
-- Reference: bitcoin-core/src/wallet/rpc/backup.cpp::listdescriptors (464-572)
--            bitcoin-core/src/script/descriptor.cpp DescriptorChecksum /
--            AddChecksum (the trailing "#<8-char checksum>").
--
-- listdescriptors returns an OBJECT:
--   { wallet_name = <string>,
--     descriptors = [ { desc, timestamp, active, [internal], [range], [next],
--                       [next_index] } ... ] }
-- sorted by the descriptor STRING (backup.cpp:541-543). Each entry's `desc`
-- carries the trailing "#checksum". `internal` is emitted ONLY for active
-- descriptors; `range`/`next`/`next_index` ONLY for ranged descriptors. Default
-- private=false emits the PUBLIC descriptor; private=true on a watch-only wallet
-- throws RPC_WALLET_ERROR -4 (backup.cpp:500-502).
--
-- lunarblock's descriptor store is the watch-only set populated by
-- importdescriptors (Wallet:add_watch_descriptor -> wallet.watch_addrs); the
-- imports there are non-active + non-ranged, so each entry emits exactly
-- desc/timestamp/active and OMITS internal/range/next (Core parity). This test
-- runs entirely in-process: it builds a WalletManager on a temp datadir, creates
-- a watch-only wallet, drives the REAL importdescriptors handler to populate the
-- store, then calls listdescriptors and asserts the shape + a correct checksum.
--
-- Gate map:
--   G1  empty wallet -> { wallet_name, descriptors=[] }
--   G2  one wpkh() import -> 1 entry, exact key set {desc,timestamp,active}
--   G3  desc carries the correct "#<8-char checksum>" (recomputed independently)
--   G4  timestamp echoes the import time; active=false; no internal/range/next
--   G5  multiple descriptors are SORTED by descriptor string
--   G6  private=true on a watch-only wallet -> RPC_WALLET_ERROR -4

package.path = "src/?.lua;src/?/init.lua;" .. package.path

local rpc       = require("lunarblock.rpc")
local wallet    = require("lunarblock.wallet")
local address   = require("lunarblock.address")
local consensus = require("lunarblock.consensus")

-- ---------------------------------------------------------------------------
-- Test scaffolding (mirrors tests/test_getnodeaddresses.lua)
-- ---------------------------------------------------------------------------
local PASS, FAIL = 0, 0

local function pass(name)
  io.write(string.format("  PASS  %s\n", name)); PASS = PASS + 1
end
local function fail(name, msg)
  io.write(string.format("  FAIL  %s -- %s\n", name, msg)); FAIL = FAIL + 1
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

-- Network for the in-process wallet/rpc. regtest is the cheapest harness.
local NET = consensus.networks.regtest

-- Two compressed public keys (33 bytes / 66 hex). Used as wpkh() args, which
-- resolve to watch-only P2WPKH descriptors (resolve_descriptor_spk).
local PUB_A = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
local PUB_B = "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

-- Build a "desc#checksum" string from a descriptor body, using the impl's own
-- checksum routine (the one importdescriptors REQUIRE-validates against).
local function with_checksum(body)
  local cs = address.descriptor_checksum(body)
  expect_true(cs ~= nil and #cs == 8, "checksum is 8 chars for: " .. body)
  return body .. "#" .. cs
end

-- Build a fresh RPCServer wired to a watch-only wallet on a throwaway datadir.
-- Returns server, wallet_manager. No chain_state/mempool: imports use
-- timestamp="now" so importdescriptors takes the no-rescan path.
local function build_server()
  local datadir = os.tmpname()
  os.remove(datadir)                 -- tmpname makes a file; we want a dir prefix
  os.execute("mkdir -p '" .. datadir .. "'")
  local mgr = wallet.new_manager(datadir, NET, nil)
  local w, err = mgr:create_wallet("watchonly", { disable_private_keys = true })
  expect_true(w ~= nil, "create watch-only wallet: " .. tostring(err))
  local server = rpc.new({ network = NET, wallet_manager = mgr })
  return server, mgr
end

-- Drive the real importdescriptors handler with one request element.
local function import_desc(server, desc_with_csum, timestamp)
  local handler = server.methods["importdescriptors"]
  expect_true(handler ~= nil, "importdescriptors registered")
  local req = { desc = desc_with_csum, timestamp = timestamp or "now" }
  local ok, res = pcall(handler, server, { { req } })
  expect_true(ok, "importdescriptors call failed: " .. tostring(res))
  expect_true(type(res) == "table" and res[1] and res[1].success == true,
              "import not successful: " ..
              (res and res[1] and res[1].error and res[1].error.message or "?"))
end

-- Call listdescriptors; returns ok, result-or-err.
local function call_ld(server, params)
  local handler = server.methods["listdescriptors"]
  if not handler then error("listdescriptors not registered", 2) end
  return pcall(handler, server, params or {})
end

local function key_count(t)
  local n = 0; for _ in pairs(t) do n = n + 1 end; return n
end

print("\n=========================================================================")
print("listdescriptors Core-shape parity — lunarblock")
print("Handler: src/rpc.lua  Ref: bitcoin-core/src/wallet/rpc/backup.cpp:464-572")
print("=========================================================================\n")

-- ---------------------------------------------------------------------------
-- G1: empty wallet -> { wallet_name="watchonly", descriptors=[] }
-- ---------------------------------------------------------------------------
test("G1: empty wallet -> wallet_name + empty descriptors array", function()
  local server = build_server()
  local ok, res = call_ld(server, {})
  expect_true(ok, "call failed: " .. tostring(res))
  expect_eq(res.wallet_name, "watchonly", "wallet_name")
  expect_true(type(res.descriptors) == "table", "descriptors is a table")
  expect_eq(#res.descriptors, 0, "descriptors empty")
end)

-- ---------------------------------------------------------------------------
-- G2: one wpkh() import -> 1 entry, exact key set {desc,timestamp,active}
-- ---------------------------------------------------------------------------
test("G2: single import -> 1 entry with exactly desc/timestamp/active", function()
  local server = build_server()
  local d = with_checksum("wpkh(" .. PUB_A .. ")")
  import_desc(server, d, "now")
  local ok, res = call_ld(server, {})
  expect_true(ok, "call failed: " .. tostring(res))
  expect_eq(#res.descriptors, 1, "one descriptor")
  local e = res.descriptors[1]
  -- Exactly three keys: desc, timestamp, active (internal/range/next omitted).
  expect_eq(key_count(e), 3, "entry has exactly 3 keys")
  expect_true(e.desc ~= nil, "desc present")
  expect_true(e.timestamp ~= nil, "timestamp present")
  expect_true(e.active ~= nil, "active present")
  expect_true(e.internal == nil, "internal OMITTED for non-active descriptor")
  expect_true(e.range == nil, "range OMITTED for non-ranged descriptor")
  expect_true(e.next == nil, "next OMITTED for non-ranged descriptor")
  expect_true(e.next_index == nil, "next_index OMITTED for non-ranged descriptor")
end)

-- ---------------------------------------------------------------------------
-- G3: desc carries the correct trailing "#<8-char checksum>"
-- ---------------------------------------------------------------------------
test("G3: desc carries the correct 8-char checksum (recomputed)", function()
  local server = build_server()
  local body = "wpkh(" .. PUB_A .. ")"
  import_desc(server, with_checksum(body), "now")
  local ok, res = call_ld(server, {})
  expect_true(ok, "call failed: " .. tostring(res))
  local got = res.descriptors[1].desc
  -- Split at the hash sign and re-verify the checksum independently of import.
  local sep = got:find("#", 1, true)
  expect_true(sep ~= nil, "desc has a '#' checksum separator")
  local got_body = got:sub(1, sep - 1)
  local got_csum = got:sub(sep + 1)
  expect_eq(got_body, body, "descriptor body round-trips")
  expect_eq(#got_csum, 8, "checksum is 8 chars")
  expect_eq(got_csum, address.descriptor_checksum(body), "checksum is correct")
  -- And the full string validates via the impl's verifier.
  expect_true(address.validate_descriptor_checksum(got), "desc validates")
end)

-- ---------------------------------------------------------------------------
-- G4: timestamp echoes import time; active=false; default private=false PUBLIC
-- ---------------------------------------------------------------------------
test("G4: timestamp echoes import time, active=false, public form", function()
  local server = build_server()
  local body = "wpkh(" .. PUB_A .. ")"
  import_desc(server, with_checksum(body), 1455191478)  -- explicit numeric ts
  local ok, res = call_ld(server, {})
  expect_true(ok, "call failed: " .. tostring(res))
  local e = res.descriptors[1]
  expect_eq(e.timestamp, 1455191478, "timestamp echoes import time")
  expect_eq(e.active, false, "watch-only import is not active")
  -- Default private=false: the emitted desc is the PUBLIC (hex-pubkey) form,
  -- never a WIF/xprv. wpkh(<hex pubkey>) is already public by construction.
  expect_true(e.desc:find(PUB_A, 1, true) ~= nil, "public pubkey present in desc")
end)

-- ---------------------------------------------------------------------------
-- G5: multiple descriptors are SORTED by descriptor string (Core 541-543)
-- ---------------------------------------------------------------------------
test("G5: descriptors sorted by descriptor string", function()
  local server = build_server()
  local body_a = "wpkh(" .. PUB_A .. ")"   -- 02f9...
  local body_b = "wpkh(" .. PUB_B .. ")"   -- 0379...
  -- Import in REVERSE sorted order to prove the handler sorts, not insert order.
  import_desc(server, with_checksum(body_b), "now")
  import_desc(server, with_checksum(body_a), "now")
  local ok, res = call_ld(server, {})
  expect_true(ok, "call failed: " .. tostring(res))
  expect_eq(#res.descriptors, 2, "two descriptors")
  local d1 = res.descriptors[1].desc
  local d2 = res.descriptors[2].desc
  expect_true(d1 < d2, "entries are sorted ascending by desc string")
  -- 0379... < 02f9... is FALSE; "02..." sorts before "0379...", so PUB_A first.
  expect_true(d1:find(PUB_A, 1, true) ~= nil, "lexicographically-first is PUB_A")
  expect_true(d2:find(PUB_B, 1, true) ~= nil, "second is PUB_B")
end)

-- ---------------------------------------------------------------------------
-- G6: private=true on a watch-only wallet -> RPC_WALLET_ERROR -4 (backup.cpp)
-- ---------------------------------------------------------------------------
test("G6: private=true on watch-only wallet throws -4", function()
  local server = build_server()
  import_desc(server, with_checksum("wpkh(" .. PUB_A .. ")"), "now")
  local ok, err = call_ld(server, { true })
  expect_true(not ok, "private=true should throw on watch-only wallet")
  expect_true(type(err) == "table", "error is a structured {code,message}")
  expect_eq(err.code, -4, "RPC_WALLET_ERROR code")
  expect_eq(err.message,
            "Can't get private descriptor string for watch-only wallets",
            "Core-exact watch-only message")
end)

-- ---------------------------------------------------------------------------
print(string.format("\n%d passed, %d failed\n", PASS, FAIL))
os.exit(FAIL == 0 and 0 or 1)
