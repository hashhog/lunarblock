#!/usr/bin/env luajit
-- FIX-71 W121 BUG-2 — NODE_COMPACT_FILTERS service-bit gate plumbing
--
-- Plumbs (without flipping) the BIP-157 NODE_COMPACT_FILTERS = 64
-- advertisement.  The bit STAYS dark until peer.lua:854 ships
-- case branches for the 6 BIP-157 wire messages (getcfilters,
-- cfilter, getcfheaders, cfheaders, getcfcheckpt, cfcheckpt).
--
-- Gate function: p2p.should_advertise_compact_filters(opts) AND's 3
-- conditions:
--   (a) opts.peerblockfilters         — operator opt-in
--                                       (mirrors -peerblockfilters in
--                                       bitcoin-core/src/init.cpp:993)
--   (b) opts.blockfilterindex_enabled — basic filter index running
--                                       (so RPC/REST/index responses
--                                       can actually be served)
--   (c) p2p.BIP157_P2P_DISPATCH_PRESENT — peer.lua:854 case branches
--                                       for the 6 cf* messages
--                                       (currently false)
--
-- Forward-regression guards:
--   Test A: should_advertise_compact_filters() is FALSE in default
--           state (the canonical pre-flip state of FIX-71).
--   Test B: source-level grep — assert no unconditional OR of
--           NODE_COMPACT_FILTERS lives outside our_services().
--   Test C: documentation — when peer.lua:854 dispatch is registered,
--           BIP157_P2P_DISPATCH_PRESENT flips and the gate evaluates
--           true (we can simulate this via opts.bip157_dispatch_present).
--
-- Reference:
--   bitcoin-core/src/protocol.h        — NODE_COMPACT_FILTERS=64 (1<<6)
--   bitcoin-core/src/init.cpp          — peerblockfilters AND filter
--                                        types include BASIC ⇒ OR bit
--   bitcoin-core/src/index/base.cpp    — IsSynced() — index readiness
--   BIP-157                            — Service Bit, Wire Messages
--   BIP-158                            — Filter content & encoding
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_fix71_compact_filters_gate.lua 2>&1

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
    error((msg or "mismatch") .. ": got " .. tostring(a) .. ", expected " .. tostring(b))
  end
end

local function expect_true(v, msg)
  if not v then error(msg or "expected true, got false") end
end

local function expect_false(v, msg)
  if v then error(msg or "expected false, got true") end
end

local function read_file(path)
  local f = io.open(path, "r")
  if not f then return "" end
  local s = f:read("*a"); f:close(); return s
end

-- ---------------------------------------------------------------------------
-- Test A: should_advertise_compact_filters() returns FALSE in default state.
-- ---------------------------------------------------------------------------
print("\n--- Test A: gate defaults to FALSE (dispatch absent) ---")

test("A1: gate function exists", function()
  expect_eq(type(p2p.should_advertise_compact_filters), "function",
    "p2p.should_advertise_compact_filters must be callable")
end)

test("A2: BIP157_P2P_DISPATCH_PRESENT module flag exists and is false", function()
  expect_eq(p2p.BIP157_P2P_DISPATCH_PRESENT, false,
    "peer.lua:854 has no BIP-157 case branches; flag must be false")
end)

test("A3: gate with empty opts → false", function()
  expect_false(p2p.should_advertise_compact_filters(),
    "no opts ⇒ no advertisement")
  expect_false(p2p.should_advertise_compact_filters({}),
    "empty opts ⇒ no advertisement")
end)

test("A4: gate with peerblockfilters only → false", function()
  expect_false(p2p.should_advertise_compact_filters({
    peerblockfilters = true,
  }), "missing blockfilterindex_enabled")
end)

test("A5: gate with blockfilterindex only → false", function()
  expect_false(p2p.should_advertise_compact_filters({
    blockfilterindex_enabled = true,
  }), "missing peerblockfilters")
end)

test("A6: gate with both opts true but dispatch absent → false", function()
  expect_false(p2p.should_advertise_compact_filters({
    peerblockfilters = true,
    blockfilterindex_enabled = true,
  }), "(a)+(b) true but (c) dispatch absent ⇒ no advertisement")
end)

test("A7: explicit bip157_dispatch_present=false overrides → false", function()
  expect_false(p2p.should_advertise_compact_filters({
    peerblockfilters = true,
    blockfilterindex_enabled = true,
    bip157_dispatch_present = false,
  }), "explicit (c)=false ⇒ no advertisement")
end)

test("A8: explicit bip157_dispatch_present=true with both opts → true", function()
  expect_true(p2p.should_advertise_compact_filters({
    peerblockfilters = true,
    blockfilterindex_enabled = true,
    bip157_dispatch_present = true,
  }), "drilling all 3 ⇒ gate fires (proves wiring)")
end)

-- ---------------------------------------------------------------------------
-- Test B: source-level regression guard.
-- ---------------------------------------------------------------------------
print("\n--- Test B: source-level regression guard ---")

test("B1: no unconditional `bit.bor(.*NODE_COMPACT_FILTERS)` outside gate", function()
  local violations = {}
  for _, path in ipairs({"src/p2p.lua", "src/peer.lua", "src/peerman.lua",
                          "src/main.lua", "src/sync.lua"}) do
    local src = read_file(path)
    for line in src:gmatch("[^\n]+") do
      if line:find("bit%.bor.*NODE_COMPACT_FILTERS") then
        local idx = src:find(line, 1, true)
        if idx then
          local window = src:sub(math.max(1, idx - 400), idx)
          if not window:find("should_advertise_compact_filters") then
            violations[#violations + 1] = path .. ": " .. line
          end
        end
      end
    end
  end
  expect_eq(#violations, 0,
    "found ungated NODE_COMPACT_FILTERS OR(s): "
    .. table.concat(violations, "; "))
end)

test("B2: no `services |= NODE_COMPACT_FILTERS` (Core-style) in any file", function()
  -- Lua doesn't have |= but cover the pattern people might add by mistake.
  local violations = {}
  for _, path in ipairs({"src/p2p.lua", "src/peer.lua", "src/peerman.lua",
                          "src/main.lua", "src/sync.lua"}) do
    local src = read_file(path)
    -- Pattern: any line containing "+ NODE_COMPACT_FILTERS" or
    -- "+ p2p.SERVICES.NODE_COMPACT_FILTERS" outside of constant tables.
    for line in src:gmatch("[^\n]+") do
      if line:find("%+%s*[%w._]*NODE_COMPACT_FILTERS") then
        violations[#violations + 1] = path .. ": " .. line
      end
    end
  end
  expect_eq(#violations, 0,
    "found Core-style |= NODE_COMPACT_FILTERS: "
    .. table.concat(violations, "; "))
end)

test("B3: peer.lua dispatch table still lacks BIP-157 cases (audit invariant)", function()
  -- The W121 BUG-1 root state: the audit framework asserts this stays
  -- true until a future FIX wave lands the 6 case branches in peer.lua.
  -- If this test fails (i.e. dispatch present) AND BIP157_P2P_DISPATCH_
  -- PRESENT is still false, that is a regression — the flag must flip
  -- atomically with the dispatch.
  local peer_src = read_file("src/peer.lua")
  local has_getcfilters = peer_src:find('"getcfilters"', 1, true) ~= nil
  local has_cfilter = peer_src:find('elseif msg%.command == "cfilter"') ~= nil
  -- (the constants exist as docstrings/comments in p2p.lua but not as
  --  dispatch cases in peer.lua)
  if has_getcfilters and has_cfilter then
    expect_eq(p2p.BIP157_P2P_DISPATCH_PRESENT, true,
      "peer.lua dispatch wired but module flag still false — fix the flag")
  else
    expect_eq(p2p.BIP157_P2P_DISPATCH_PRESENT, false,
      "peer.lua dispatch absent — flag correctly false")
  end
end)

-- ---------------------------------------------------------------------------
-- Test C: documentation / forward-compatibility.
-- ---------------------------------------------------------------------------
print("\n--- Test C: forward-compatibility (gate flips when dispatch lands) ---")

test("C1: our_services accepts compactfilters_opts third arg", function()
  -- Backward-compat: calling without the 3rd arg still works.
  local s_2arg = p2p.our_services(false, false)
  local s_3arg = p2p.our_services(false, false, nil)
  expect_eq(s_2arg, s_3arg, "nil third arg matches 2-arg call")
end)

test("C2: NODE_COMPACT_FILTERS appears in services bitfield when gate fires", function()
  local s = p2p.our_services(false, false, {
    peerblockfilters = true,
    blockfilterindex_enabled = true,
    bip157_dispatch_present = true,
  })
  expect_true(bit.band(s, p2p.SERVICES.NODE_COMPACT_FILTERS) ~= 0,
    "gate-fired ⇒ bit set in services bitfield")
  -- NODE_NETWORK and NODE_WITNESS are unconditionally set.
  expect_true(bit.band(s, p2p.SERVICES.NODE_NETWORK) ~= 0,
    "NODE_NETWORK still set")
  expect_true(bit.band(s, p2p.SERVICES.NODE_WITNESS) ~= 0,
    "NODE_WITNESS still set")
end)

test("C3: opts.peerblockfilters is the operator-controlled opt-in", function()
  -- Even with index enabled + dispatch present, no advertisement
  -- without the operator's explicit --peerblockfilters opt-in.
  expect_false(p2p.should_advertise_compact_filters({
    peerblockfilters = false,
    blockfilterindex_enabled = true,
    bip157_dispatch_present = true,
  }), "operator must opt in via --peerblockfilters")
end)

test("C4: gate respects opts.blockfilterindex_enabled — refusal to lie", function()
  -- Index not running ⇒ can't actually serve getcfilters ⇒ don't claim.
  expect_false(p2p.should_advertise_compact_filters({
    peerblockfilters = true,
    blockfilterindex_enabled = false,
    bip157_dispatch_present = true,
  }), "no filter index ⇒ no advertisement (refusal to lie)")
end)

test("C5: when BIP157_P2P_DISPATCH_PRESENT flips, gate evaluates module flag", function()
  -- Simulate the post-future-fix world by temporarily flipping the flag.
  -- This documents the contract: only ONE source line changes when the
  -- dispatch lands.
  local saved = p2p.BIP157_P2P_DISPATCH_PRESENT
  p2p.BIP157_P2P_DISPATCH_PRESENT = true
  local ok, err = pcall(function()
    expect_true(p2p.should_advertise_compact_filters({
      peerblockfilters = true,
      blockfilterindex_enabled = true,
      -- No bip157_dispatch_present override — falls through to module flag.
    }), "module flag flip ⇒ gate fires automatically")
  end)
  p2p.BIP157_P2P_DISPATCH_PRESENT = saved
  if not ok then error(err) end
end)

test("C6: main.lua args.peerblockfilters default is false", function()
  -- Sanity check the CLI default matches Core (DEFAULT_PEERBLOCKFILTERS=false).
  local main_src = read_file("src/main.lua")
  expect_true(main_src:find("peerblockfilters = false") ~= nil,
    "main.lua defines peerblockfilters = false default")
end)

test("C7: peerman.lua plumbs both gate inputs into peer_mod.new", function()
  local peerman_src = read_file("src/peerman.lua")
  expect_true(peerman_src:find("peerblockfilters = self%.config%.peerblockfilters") ~= nil,
    "peerman.lua hands off peerblockfilters to peer_mod.new")
  expect_true(peerman_src:find("blockfilterindex_enabled = self%.config%.blockfilterindex_enabled") ~= nil,
    "peerman.lua hands off blockfilterindex_enabled to peer_mod.new")
end)

-- ===========================================================================
-- Summary
-- ===========================================================================
print("\n=========================================================================")
print(string.format("FIX-71 NODE_COMPACT_FILTERS gate: %d PASS / %d FAIL", PASS, FAIL))
print("Gate state: BIP157_P2P_DISPATCH_PRESENT=" ..
      tostring(p2p.BIP157_P2P_DISPATCH_PRESENT) ..
      " (FALSE = bit stays dark until peer.lua:854 dispatch ships)")
print("=========================================================================")

if FAIL > 0 then os.exit(1) end
