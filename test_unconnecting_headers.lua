#!/usr/bin/env luajit
-- Tests for the per-peer MAX_NUM_UNCONNECTING_HEADERS_MSGS=10 counter
-- (Bitcoin Core net_processing.cpp parity, Pattern B closure).
--
-- Run with: LD_LIBRARY_PATH=./lib luajit test_unconnecting_headers.lua
--
-- Reference:
--   bitcoin-core/src/net_processing.cpp MAX_NUM_UNCONNECTING_HEADERS_MSGS
--   ProcessHeadersMessage's nUnconnectingHeaders state machine
--   CORE-PARITY-AUDIT/_header-sync-dos-cross-impl-audit-2026-05-06-part1.md
--   (Pattern B), extended to Part-2 impls.
--
-- Pre-fix: lunarblock returned (-1, "unknown parent: ...") from
-- HeaderChain:handle_headers on the FIRST orphan header, and main.lua
-- ran `peer_manager:add_ban_score(peer, 100, err)` — instant ban after
-- a single transient reorg/fork delivery.  Post-fix: tolerate up to 10
-- successive unconnecting batches before banning, mirroring Core.

package.path = "src/?.lua;" .. package.path
package.preload["lunarblock.types"] = function() return require("types") end
package.preload["lunarblock.serialize"] = function() return require("serialize") end
package.preload["lunarblock.crypto"] = function() return require("crypto") end
package.preload["lunarblock.script"] = function() return require("script") end
package.preload["lunarblock.consensus"] = function() return require("consensus") end
package.preload["lunarblock.validation"] = function() return require("validation") end
package.preload["lunarblock.p2p"] = function() return require("p2p") end

local sync = require("sync")

-- -------------------------------------------------------------------
-- Mini test harness (matches the conventions in test_presync.lua)
-- -------------------------------------------------------------------

local function assert_eq(expected, actual, msg)
  if expected ~= actual then
    error(string.format("%s: expected %s, got %s", msg or "assertion failed",
      tostring(expected), tostring(actual)))
  end
end

local function assert_true(value, msg)
  if not value then
    error(msg or "expected true")
  end
end

local function assert_false(value, msg)
  if value then
    error(msg or "expected false")
  end
end

local function test(name, fn)
  io.write("  " .. name .. " ... ")
  io.flush()
  local ok, err = pcall(fn)
  if ok then
    print("PASS")
    return true
  else
    print("FAIL: " .. tostring(err))
    return false
  end
end

-- Stand-in for a Peer object — only the fields the counter touches.
local function make_peer(id)
  return { id = id, ip = "127.0.0.1" }
end

-- Standalone HeaderChain (storage stub — these tests don't touch it).
local storage_stub = {
  CF = {},
  get = function() return nil end,
  put = function() end,
  put_header = function() end,
  put_height_index = function() end,
}

local function make_chain()
  -- new_header_chain doesn't touch the network table for the counter
  -- helpers we're testing, so an empty stub is safe.
  return sync.new_header_chain({ name = "regtest" }, storage_stub)
end

print("== Unconnecting-headers counter ==")

local passed = 0
local failed = 0

if test("constant matches Core (= 10)", function()
  assert_eq(10, sync.MAX_NUM_UNCONNECTING_HEADERS_MSGS)
end) then passed = passed + 1 else failed = failed + 1 end

if test("under-threshold (10 bumps) does not signal exceeded", function()
  local chain = make_chain()
  local peer = make_peer(1)
  for i = 1, 10 do
    local exceeded = chain:note_unconnecting_headers(peer)
    assert_false(exceeded, string.format("call #%d should not exceed", i))
    assert_eq(i, chain:get_unconnecting_headers_count(peer))
  end
end) then passed = passed + 1 else failed = failed + 1 end

if test("11th bump exceeds threshold", function()
  local chain = make_chain()
  local peer = make_peer(2)
  for _ = 1, 10 do
    chain:note_unconnecting_headers(peer)
  end
  local exceeded = chain:note_unconnecting_headers(peer)
  assert_true(exceeded, "11th bump should exceed")
end) then passed = passed + 1 else failed = failed + 1 end

if test("reset clears counter (Core: nUnconnectingHeaders = 0)", function()
  local chain = make_chain()
  local peer = make_peer(3)
  for _ = 1, 5 do
    chain:note_unconnecting_headers(peer)
  end
  assert_eq(5, chain:get_unconnecting_headers_count(peer))
  chain:reset_unconnecting_headers(peer)
  assert_eq(0, chain:get_unconnecting_headers_count(peer))
  -- Subsequent unconnecting starts fresh.
  chain:note_unconnecting_headers(peer)
  assert_eq(1, chain:get_unconnecting_headers_count(peer))
end) then passed = passed + 1 else failed = failed + 1 end

if test("per-peer counters are independent", function()
  local chain = make_chain()
  local peer_a = make_peer("a")
  local peer_b = make_peer("b")
  for _ = 1, 10 do
    chain:note_unconnecting_headers(peer_a)
  end
  assert_eq(10, chain:get_unconnecting_headers_count(peer_a))
  assert_eq(0, chain:get_unconnecting_headers_count(peer_b))
  -- Peer B's first message does NOT trip.
  local exceeded_b = chain:note_unconnecting_headers(peer_b)
  assert_false(exceeded_b, "peer B's first bump should not exceed")
  -- Peer A's 11th bump trips.
  local exceeded_a = chain:note_unconnecting_headers(peer_a)
  assert_true(exceeded_a, "peer A's 11th bump should exceed")
end) then passed = passed + 1 else failed = failed + 1 end

print("\n===========================================")
print(string.format("Results: %d passed, %d failed", passed, failed))

if failed > 0 then
  os.exit(1)
else
  print("\nAll tests passed!")
  os.exit(0)
end
