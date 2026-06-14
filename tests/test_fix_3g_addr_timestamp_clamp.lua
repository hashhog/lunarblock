#!/usr/bin/env luajit
-- Finding 3G: ADDR/ADDRV2 peer-timestamp clamp — lunarblock
--
-- Reference: bitcoin-core/src/net_processing.cpp:5678-5680
--
--   if (addr.nTime <= NodeSeconds{100000000s} || addr.nTime > current_time + 10min) {
--       addr.nTime = std::chrono::time_point_cast<std::chrono::seconds>(
--                       current_time - 5 * 24h);
--   }
--
-- Core does NOT drop addresses with out-of-range timestamps; it clamps them to
-- (now - 5 days) and stores them.  lunarblock's previous code silently dropped
-- any address whose timestamp was outside the window [now-10800, now+600],
-- which caused peers with pre-2001 or far-future timestamps to be lost.
--
-- This test FAILS against the old code (drop on bad ts) and PASSES after the
-- fix (clamp to now-5days then store unconditionally).
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_fix_3g_addr_timestamp_clamp.lua 2>&1

package.path = "src/?.lua;src/?/init.lua;" .. package.path

local peerman   = require("lunarblock.peerman")
local consensus = require("lunarblock.consensus")
local p2p       = require("lunarblock.p2p")

-- ---------------------------------------------------------------------------
-- Scaffolding
-- ---------------------------------------------------------------------------
local PASS, FAIL = 0, 0

local function pass(name) io.write(string.format("  PASS  %s\n", name)); PASS = PASS + 1 end
local function fail(name, msg) io.write(string.format("  FAIL  %s -- %s\n", name, msg)); FAIL = FAIL + 1 end
local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) .. ", expected " .. tostring(b), 2)
  end
end
local function expect_not_nil(v, msg)
  if v == nil then error((msg or "expected non-nil"), 2) end
end
local function expect_nil(v, msg)
  if v ~= nil then error((msg or "expected nil") .. ": got " .. tostring(v), 2) end
end
local function expect_true(v, msg)
  if not v then error((msg or "expected true") .. ": got " .. tostring(v), 2) end
end

local function make_pm()
  local tmpdir = os.tmpname()
  os.remove(tmpdir)
  os.execute("mkdir -p " .. tmpdir)
  local pm = peerman.new(consensus.networks.regtest, nil, { data_dir = tmpdir })
  return pm, tmpdir
end

local function rm_dir(path)
  if path and path ~= "" and path ~= "/" then os.execute("rm -rf " .. path) end
end

-- Constants mirroring Core
local PRE2001_CUTOFF  = 100000000          -- Core: NodeSeconds{100000000s}
local FUTURE_GRACE    = 600                -- Core: 10min = 600s
local CLAMP_DELTA     = 5 * 24 * 60 * 60  -- Core: 5 * 24h = 432000s
-- Routable test IPs (not RFC5737 / RFC1918 / loopback)
local IP_A = "5.6.7.8"
local IP_B = "8.8.8.8"
local IP_C = "1.2.3.4"
local IP_D = "9.9.9.9"

-- ---------------------------------------------------------------------------
print("\n=========================================================================")
print("3G addr/addrv2 timestamp clamp — lunarblock")
print("Reference: bitcoin-core/src/net_processing.cpp:5678-5680")
print("=========================================================================")
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- G1: handle_addr — pre-2001 timestamp stored, clamped to now-5days
-- Without fix: address is dropped (timestamp <= now-10800 gate blocks it).
-- With fix:    address is stored with timestamp == now-5days.
-- ---------------------------------------------------------------------------
print("\n--- G1: handle_addr — pre-2001 timestamp clamped and stored ---")

test("G1-a: pre-2001 addr (ts=0) is stored, NOT dropped", function()
  local pm, d = make_pm()
  local now = os.time()
  local payload = p2p.serialize_addr({{ timestamp = 0, services = 1, ip = IP_A, port = 8333 }})
  pm:handle_addr(nil, payload)
  local stored = pm.known_addresses[IP_A .. ":8333"]
  expect_not_nil(stored, "address with ts=0 must be stored (Core clamps, not drops)")
  rm_dir(d)
end)

test("G1-b: pre-2001 addr (ts=100000000) is stored, NOT dropped", function()
  local pm, d = make_pm()
  local payload = p2p.serialize_addr({{
    timestamp = PRE2001_CUTOFF, services = 1, ip = IP_B, port = 8333
  }})
  pm:handle_addr(nil, payload)
  local stored = pm.known_addresses[IP_B .. ":8333"]
  expect_not_nil(stored, "address with ts=100000000 must be stored (boundary: Core clamps <=100000000)")
  rm_dir(d)
end)

test("G1-c: pre-2001 addr timestamp is clamped to now-5days (not kept as-is)", function()
  local pm, d = make_pm()
  local now = os.time()
  local payload = p2p.serialize_addr({{ timestamp = 12345, services = 1, ip = IP_A, port = 8333 }})
  pm:handle_addr(nil, payload)
  local stored = pm.known_addresses[IP_A .. ":8333"]
  expect_not_nil(stored, "address must be stored")
  local expected = now - CLAMP_DELTA
  local diff = math.abs(stored.timestamp - expected)
  expect_true(diff <= 2,
    "clamped timestamp must be now-5days (got " .. stored.timestamp ..
    ", expected ~" .. expected .. ", diff=" .. diff .. "s)")
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- G2: handle_addr — far-future timestamp clamped to now-5days, not dropped
-- Without fix: address is dropped (timestamp > now+600 gate blocks it).
-- With fix:    address is stored with timestamp == now-5days.
-- ---------------------------------------------------------------------------
print("\n--- G2: handle_addr — far-future timestamp clamped and stored ---")

test("G2-a: future addr (ts=now+3600) is stored, NOT dropped", function()
  local pm, d = make_pm()
  local now = os.time()
  local payload = p2p.serialize_addr({{
    timestamp = now + 3600, services = 1, ip = IP_C, port = 8333
  }})
  pm:handle_addr(nil, payload)
  local stored = pm.known_addresses[IP_C .. ":8333"]
  expect_not_nil(stored, "address with future ts must be stored (Core clamps, not drops)")
  rm_dir(d)
end)

test("G2-b: future addr timestamp is clamped to now-5days (not the future value)", function()
  local pm, d = make_pm()
  local now = os.time()
  local future_ts = now + 3600
  local payload = p2p.serialize_addr({{
    timestamp = future_ts, services = 1, ip = IP_D, port = 8333
  }})
  pm:handle_addr(nil, payload)
  local stored = pm.known_addresses[IP_D .. ":8333"]
  expect_not_nil(stored, "address must be stored")
  -- Must NOT store the raw future value
  expect_true(stored.timestamp < now,
    "clamped timestamp must be in the past (got " .. stored.timestamp .. ", now=" .. now .. ")")
  -- Must be approximately now-5days
  local expected = now - CLAMP_DELTA
  local diff = math.abs(stored.timestamp - expected)
  expect_true(diff <= 2,
    "clamped timestamp must be now-5days (got " .. stored.timestamp ..
    ", expected ~" .. expected .. ", diff=" .. diff .. "s)")
  rm_dir(d)
end)

test("G2-c: boundary ts=now+601 is clamped (> now+600 triggers clamp)", function()
  local pm, d = make_pm()
  local now = os.time()
  local payload = p2p.serialize_addr({{
    timestamp = now + 601, services = 1, ip = IP_A, port = 8334
  }})
  pm:handle_addr(nil, payload)
  local stored = pm.known_addresses[IP_A .. ":8334"]
  expect_not_nil(stored, "ts=now+601 must be stored after clamp")
  local expected = now - CLAMP_DELTA
  local diff = math.abs(stored.timestamp - expected)
  expect_true(diff <= 2, "ts=now+601 must clamp to now-5days (diff=" .. diff .. "s)")
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- G3: handle_addr — in-range timestamp is stored as-is (no clamping)
-- Regression check: valid timestamps must not be clamped.
-- ---------------------------------------------------------------------------
print("\n--- G3: handle_addr — in-range timestamps pass through unchanged ---")

test("G3-a: recent addr (ts=now-3600) stored with original timestamp", function()
  local pm, d = make_pm()
  local now = os.time()
  local recent_ts = now - 3600
  local payload = p2p.serialize_addr({{ timestamp = recent_ts, services = 1, ip = IP_B, port = 8333 }})
  pm:handle_addr(nil, payload)
  local stored = pm.known_addresses[IP_B .. ":8333"]
  expect_not_nil(stored, "recent-timestamp address must be stored")
  local diff = math.abs(stored.timestamp - recent_ts)
  expect_true(diff <= 2,
    "in-range timestamp must not be clamped (got " .. stored.timestamp ..
    ", expected " .. recent_ts .. ", diff=" .. diff .. "s)")
  rm_dir(d)
end)

test("G3-b: boundary ts=now+600 is NOT clamped (exactly at the grace window)", function()
  -- Core: clamp iff nTime > current_time + 10min.  Exactly +600 is not >.
  local pm, d = make_pm()
  local now = os.time()
  local boundary_ts = now + 600
  local payload = p2p.serialize_addr({{ timestamp = boundary_ts, services = 1, ip = IP_C, port = 8334 }})
  pm:handle_addr(nil, payload)
  local stored = pm.known_addresses[IP_C .. ":8334"]
  expect_not_nil(stored, "ts=now+600 must be stored")
  -- The stored value should be close to now+600 (read back via u32le round-trip,
  -- which truncates to 32 bits — but that's fine for values around 'now').
  local diff = math.abs(stored.timestamp - boundary_ts)
  expect_true(diff <= 2,
    "ts=now+600 must NOT be clamped (got " .. stored.timestamp ..
    ", expected " .. boundary_ts .. ", diff=" .. diff .. "s)")
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- G4: handle_addrv2 — same clamp applied to BIP-155 addrv2 messages
-- ---------------------------------------------------------------------------
print("\n--- G4: handle_addrv2 — pre-2001 and future timestamps clamped ---")

test("G4-a: addrv2 pre-2001 ts stored (not dropped)", function()
  local pm, d = make_pm()
  local now = os.time()
  -- Construct a minimal addrv2 payload: IPv4, 4-byte addr
  local addr_bytes = string.char(5, 6, 7, 8)  -- 5.6.7.8
  local payload = p2p.serialize_addrv2({{
    timestamp    = 999,  -- far pre-2001
    services     = 1,
    network_id   = p2p.NET_ID.IPV4,
    addr_bytes   = addr_bytes,
    ip           = "5.6.7.8",
    port         = 8333,
  }})
  pm:handle_addrv2(nil, payload)
  local stored = pm.known_addresses["5.6.7.8:8333"]
  expect_not_nil(stored, "addrv2 with pre-2001 ts must be stored after clamp")
  local expected = now - CLAMP_DELTA
  local diff = math.abs(stored.timestamp - expected)
  expect_true(diff <= 2,
    "addrv2 pre-2001 ts must clamp to now-5days (diff=" .. diff .. "s)")
  rm_dir(d)
end)

test("G4-b: addrv2 future ts (now+7200) stored with clamped value", function()
  local pm, d = make_pm()
  local now = os.time()
  local addr_bytes = string.char(8, 8, 8, 8)  -- 8.8.8.8
  local payload = p2p.serialize_addrv2({{
    timestamp    = now + 7200,
    services     = 1,
    network_id   = p2p.NET_ID.IPV4,
    addr_bytes   = addr_bytes,
    ip           = "8.8.8.8",
    port         = 8333,
  }})
  pm:handle_addrv2(nil, payload)
  local stored = pm.known_addresses["8.8.8.8:8333"]
  expect_not_nil(stored, "addrv2 with future ts must be stored after clamp")
  local expected = now - CLAMP_DELTA
  local diff = math.abs(stored.timestamp - expected)
  expect_true(diff <= 2,
    "addrv2 future ts must clamp to now-5days (diff=" .. diff .. "s)")
  rm_dir(d)
end)

test("G4-c: addrv2 in-range ts stored as-is (regression check)", function()
  local pm, d = make_pm()
  local now = os.time()
  local recent_ts = now - 1800  -- 30min ago
  local addr_bytes = string.char(1, 2, 3, 4)  -- 1.2.3.4
  local payload = p2p.serialize_addrv2({{
    timestamp    = recent_ts,
    services     = 1,
    network_id   = p2p.NET_ID.IPV4,
    addr_bytes   = addr_bytes,
    ip           = "1.2.3.4",
    port         = 8333,
  }})
  pm:handle_addrv2(nil, payload)
  local stored = pm.known_addresses["1.2.3.4:8333"]
  expect_not_nil(stored, "addrv2 with in-range ts must be stored")
  local diff = math.abs(stored.timestamp - recent_ts)
  expect_true(diff <= 2,
    "addrv2 in-range ts must not be clamped (diff=" .. diff .. "s)")
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
print("\n=========================================================================")
print("3G addr/addrv2 timestamp clamp — summary")
print("=========================================================================")
io.write(string.format("\n  PASS: %d\n  FAIL: %d\n\n", PASS, FAIL))
if FAIL > 0 then os.exit(1) end
os.exit(0)
