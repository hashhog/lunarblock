#!/usr/bin/env luajit
-- Service-flags audit (2026-06-11) — lunarblock full-node advertised bitset.
--
-- Asserts the bitset returned by p2p.our_services() for a full node matches
-- Bitcoin Core's full-node local services: 0xC09 =
--   NODE_NETWORK(0x1) | NODE_WITNESS(0x8) | NODE_NETWORK_LIMITED(0x400)
--   | NODE_P2P_V2(0x800).
--
-- Two corrections this test guards:
--   (1) NODE_NETWORK_LIMITED (BIP-159, 1<<10 = 0x400) is advertised
--       UNCONDITIONALLY by every Core full node — it is part of the base
--       g_local_services value (bitcoin-core/src/init.cpp:863:
--       `ServiceFlags g_local_services = ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS);`).
--       It must NOT be gated on prune_mode.  prune controls whether
--       NODE_NETWORK is ADDED, not NODE_NETWORK_LIMITED.
--   (2) NODE_P2P_V2 (BIP-324, 1<<11 = 0x800) is advertised because lunarblock
--       runs the v2 encrypted transport DEFAULT-ON (peer.lua:229
--       `use_v2 ~= false`), mirroring Core init.cpp:987-990 (OR when
--       -v2transport enabled, DEFAULT_V2_TRANSPORT).  use_v2=false suppresses
--       it (honest — never claim a capability we won't run).
--
-- Reference:
--   bitcoin-core/src/protocol.h  — NODE_NETWORK=1, NODE_WITNESS=8,
--                                  NODE_NETWORK_LIMITED=1<<10, NODE_P2P_V2=1<<11
--   bitcoin-core/src/init.cpp:863 — base g_local_services
--   bitcoin-core/src/init.cpp:987-990 — NODE_P2P_V2 when v2transport on
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_service_flags_full_node.lua 2>&1

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

local p2p = require("lunarblock.p2p")
local bit = require("bit")

local PASS = 0
local FAIL = 0

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
    error((msg or "mismatch")
      .. string.format(": got 0x%X, expected 0x%X", a, b))
  end
end

local function expect_set(s, flag, msg)
  if bit.band(s, flag) == 0 then
    error((msg or "flag not set")
      .. string.format(": services=0x%X missing 0x%X", s, flag))
  end
end

local function expect_clear(s, flag, msg)
  if bit.band(s, flag) ~= 0 then
    error((msg or "flag unexpectedly set")
      .. string.format(": services=0x%X has 0x%X", s, flag))
  end
end

-- ---------------------------------------------------------------------------
-- Constants sanity
-- ---------------------------------------------------------------------------
print("\n--- SERVICES table constants ---")

test("S1: NODE_NETWORK = 0x1", function()
  expect_eq(p2p.SERVICES.NODE_NETWORK, 0x1)
end)
test("S2: NODE_WITNESS = 0x8", function()
  expect_eq(p2p.SERVICES.NODE_WITNESS, 0x8)
end)
test("S3: NODE_NETWORK_LIMITED = 0x400 (1<<10)", function()
  expect_eq(p2p.SERVICES.NODE_NETWORK_LIMITED, 0x400)
end)
test("S4: NODE_P2P_V2 = 0x800 (1<<11) — newly added", function()
  expect_eq(p2p.SERVICES.NODE_P2P_V2, 0x800)
end)

-- ---------------------------------------------------------------------------
-- THE headline assertion: full-node advertised bitset == 0xC09.
-- ---------------------------------------------------------------------------
print("\n--- Full-node advertised bitset == 0xC09 ---")

local NODE_NETWORK         = 0x1
local NODE_WITNESS         = 0x8
local NODE_NETWORK_LIMITED = 0x400
local NODE_P2P_V2          = 0x800
local FULL_NODE            = 0xC09  -- NETWORK|WITNESS|NETWORK_LIMITED|P2P_V2

test("T1: our_services(no bloom, no prune, no cf, v2 default) == 0xC09", function()
  -- Default full node: peerbloomfilters=false, prune_mode=false,
  -- compactfilters=nil, use_v2 omitted (defaults true).
  local s = p2p.our_services(false, false, nil)
  expect_eq(s, FULL_NODE, "default full-node services")
end)

test("T2: explicit use_v2=true also == 0xC09", function()
  local s = p2p.our_services(false, false, nil, true)
  expect_eq(s, FULL_NODE)
end)

test("T3: every expected bit present (NETWORK|WITNESS|NETWORK_LIMITED|P2P_V2)", function()
  local s = p2p.our_services(false, false, nil)
  expect_set(s, NODE_NETWORK,         "NODE_NETWORK")
  expect_set(s, NODE_WITNESS,         "NODE_WITNESS")
  expect_set(s, NODE_NETWORK_LIMITED, "NODE_NETWORK_LIMITED")
  expect_set(s, NODE_P2P_V2,          "NODE_P2P_V2")
end)

-- ---------------------------------------------------------------------------
-- Correction 1: NODE_NETWORK_LIMITED is UNCONDITIONAL (not prune-gated).
-- ---------------------------------------------------------------------------
print("\n--- NODE_NETWORK_LIMITED advertised unconditionally ---")

test("L1: NETWORK_LIMITED set when prune_mode=false (was the bug)", function()
  local s = p2p.our_services(false, false, nil)
  expect_set(s, NODE_NETWORK_LIMITED,
    "NODE_NETWORK_LIMITED must be advertised by a non-pruned full node "
    .. "(Core base g_local_services, init.cpp:863)")
end)

test("L2: NETWORK_LIMITED also set when prune_mode=true (idempotent)", function()
  local s = p2p.our_services(false, true, nil)
  expect_set(s, NODE_NETWORK_LIMITED,
    "still set under prune — flag is in the base set regardless")
end)

test("L3: prune_mode does NOT change NETWORK_LIMITED presence", function()
  local s_noprune = p2p.our_services(false, false, nil)
  local s_prune   = p2p.our_services(false, true,  nil)
  expect_eq(bit.band(s_noprune, NODE_NETWORK_LIMITED),
            bit.band(s_prune,   NODE_NETWORK_LIMITED),
            "NETWORK_LIMITED bit identical regardless of prune")
end)

-- ---------------------------------------------------------------------------
-- Correction 2: NODE_P2P_V2 advertised default-on, suppressible (honest).
-- ---------------------------------------------------------------------------
print("\n--- NODE_P2P_V2 default-on, suppressible ---")

test("V1: P2P_V2 set by default (v2 transport runs default-on)", function()
  local s = p2p.our_services(false, false, nil)
  expect_set(s, NODE_P2P_V2,
    "lunarblock runs BIP-324 v2 default-on (peer.lua:229) ⇒ advertise")
end)

test("V2: use_v2=false suppresses P2P_V2 (no faking)", function()
  local s = p2p.our_services(false, false, nil, false)
  expect_clear(s, NODE_P2P_V2,
    "v2 disabled for this peer ⇒ must NOT advertise NODE_P2P_V2")
  -- With v2 off, the remaining full-node bitset is 0x409.
  expect_eq(s, bit.bor(NODE_NETWORK, NODE_WITNESS, NODE_NETWORK_LIMITED),
    "v2-off bitset == 0x409")
end)

test("V3: nil use_v2 == omitted use_v2 (both default-on)", function()
  expect_eq(p2p.our_services(false, false, nil),
            p2p.our_services(false, false, nil, nil),
            "nil v2 arg equals omitted")
end)

-- ---------------------------------------------------------------------------
-- Composition with the optional bits (regression: don't break existing gates).
-- ---------------------------------------------------------------------------
print("\n--- composition with optional bits ---")

test("C1: peerbloomfilters adds NODE_BLOOM on top of full-node set", function()
  local s = p2p.our_services(true, false, nil)
  expect_eq(s, bit.bor(FULL_NODE, p2p.SERVICES.NODE_BLOOM),
    "bloom on top of 0xC09")
end)

test("C2: NODE_BLOOM absent by default", function()
  local s = p2p.our_services(false, false, nil)
  expect_clear(s, p2p.SERVICES.NODE_BLOOM, "no bloom by default")
end)

-- ===========================================================================
-- Summary
-- ===========================================================================
print("\n=========================================================================")
print(string.format("service-flags full-node bitset: %d PASS / %d FAIL", PASS, FAIL))
print(string.format("full-node advertised services = 0x%X (expect 0xC09)",
      p2p.our_services(false, false, nil)))
print("=========================================================================")

if FAIL > 0 then os.exit(1) end
