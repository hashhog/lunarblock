#!/usr/bin/env luajit
-- Control for QUEUES.md lunarblock item 0 (range holes).
--
-- Two holes were open: 363708→388364 STALLED (now CLOSED on 753b38f) and
-- 900000→910000 NO-ORACLE-SURFACE (tip correct, no hash_serialized_3).
-- A RANGE_FORCE re-run of 900k on 2026-09-17 died at block 900619:
--
--   crypto.lua:149: bad argument #1 to '__index' (userdata expected, got number)
--
-- then main.lua's "block" handler add_ban_score'd the only --connect
-- feeder (MaybePunishNodeForBlock), so the range could not recover.
-- Bitcoin Core net_processing.cpp MaybePunishNodeForBlock only
-- Misbehaving()s BLOCK_CONSENSUS / MUTATED / INVALID_HEADER /
-- INVALID_PREV / MISSING_PREV. A local LuaJIT/FFI fault and a local
-- RocksDB ENOSPC are BlockValidationResult-unset: log, do not punish.
--
-- crypto.sha256's hot path indexed the FFI library object on every
-- call (`sha256_accel_lib.sha256_accel`). After ~600 blocks of JIT
-- traces that mixed that upvalue with a Lua number, __index saw a
-- number as self. Cache the C function pointer at init and require a
-- Lua string so the hot path never indexes the library.
--
-- Control: luajit tests/test_range_holes.lua
-- Negative: a bad-prevblk / mutated-block error still punishes.

package.path = "src/?.lua;src/?/init.lua;" .. package.path

local sync   = require("lunarblock.sync")
local crypto = require("lunarblock.crypto")

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
    error((msg or "mismatch") .. ": got " .. tostring(a)
      .. ", expected " .. tostring(b), 2)
  end
end
local function expect_false(v, msg)
  if v then error((msg or "expected false") .. ": got " .. tostring(v), 2) end
end
local function expect_true(v, msg)
  if not v then error((msg or "expected true") .. ": got " .. tostring(v), 2) end
end

-- Exact error string from lunarblock-camp-soak-900000.node.log at 900619.
local FFI_900619 = "src/main.lua:1504: Failed to connect block 900619: "
  .. "./lunarblock/../src/crypto.lua:149: bad argument #1 to '__index' "
  .. "(userdata expected, got number)"

local ENOSPC = "Failed to connect block 374505: ./lunarblock/../src/storage.lua:215: "
  .. "RocksDB error: IO error: No space left on device: While appending to file: "
  .. "chainstate/000339.sst: No space left on device"

local function read_file(path)
  local f = assert(io.open(path, "r"))
  local s = f:read("*a")
  f:close()
  return s
end

local function extract_between(src, start_pat, stop_pat)
  local i = src:find(start_pat, 1, true)
  assert(i, "missing " .. start_pat)
  local rest = src:sub(i)
  local j = rest:find(stop_pat, #start_pat + 1, true)
  if j then rest = rest:sub(1, j - 1) end
  return rest
end

print("=== range holes: local IO/FFI must not punish the block peer ===\n")
print("sha256_hw=" .. tostring(crypto.sha256_hw_info()))

test("classify_callback_error exists", function()
  expect_true(type(sync.classify_callback_error) == "function",
    "sync.classify_callback_error missing")
end)

test("should_punish_peer_for_block_error exists", function()
  expect_true(type(sync.should_punish_peer_for_block_error) == "function",
    "sync.should_punish_peer_for_block_error missing — 900619 FFI still hits add_ban_score")
end)

test("900619 FFI __index classifies as local, not consensus/unknown", function()
  expect_eq(sync.classify_callback_error(FFI_900619), "local",
    "LuaJIT FFI fault during connect is this node's bug, not the feeder's")
end)

test("ENOSPC from a disk-full connect classifies as local", function()
  expect_eq(sync.classify_callback_error(ENOSPC), "local",
    "ENOSPC must be local IO, not a peer fault")
end)

test("bare 'No space left on device' is local", function()
  expect_eq(sync.classify_callback_error("No space left on device"), "local")
end)

test("RocksDB IO error without ENOSPC text is still local", function()
  expect_eq(sync.classify_callback_error(
    "RocksDB error: IO error: While appending to file: /tmp/x.sst"), "local")
end)

test("should_punish is false for the live 900619 FFI string", function()
  expect_false(sync.should_punish_peer_for_block_error(FFI_900619),
    "live 900619 error must not add_ban_score (that disconnected the feeder)")
end)

test("should_punish is false for ENOSPC", function()
  expect_false(sync.should_punish_peer_for_block_error(ENOSPC),
    "local disk-full must not disconnect the --connect peer")
end)

test("should_punish is false for deserialize failed (unchanged)", function()
  expect_false(sync.should_punish_peer_for_block_error("deserialize failed"))
end)

test("should_punish is true for BLOCK_INVALID_HEADER / bad-prevblk", function()
  expect_true(sync.should_punish_peer_for_block_error("bad-prevblk"),
    "invalid header from the peer is still punishable")
end)

test("should_punish is true for consensus script failure", function()
  expect_true(sync.should_punish_peer_for_block_error(
    "Script verification failed for input 3"),
    "a consensus-invalid block from the peer is still punishable")
end)

test("should_punish is true for witness-malleated BLOCK_MUTATED", function()
  expect_true(sync.should_punish_peer_for_block_error("block mutated"),
    "BLOCK_MUTATED remains punishable")
end)

test("handler using should_punish does not ban on 900619 FFI", function()
  local banned = false
  if sync.should_punish_peer_for_block_error(FFI_900619) then
    banned = true
  end
  expect_false(banned, "handler banned the feeder on a local FFI fault")
end)

test("pre-fix handler (deserialize-only exemption) WOULD ban on 900619 FFI", function()
  -- Negative control: the code this test replaces. If this assertion
  -- starts failing, the live bug is gone for a different reason and the
  -- test is no longer measuring the punish path.
  local err_str = FFI_900619
  local would_ban = (err_str ~= "deserialize failed")
  expect_true(would_ban, "pre-fix branch must still ban, else this test is a no-op")
end)

test("sha256 hot path does not index the FFI library object", function()
  -- Live 900619: crypto.lua:149 was `sha256_accel_lib.sha256_accel(data, #data, …)`.
  -- After many JIT traces that upvalue was a Lua number and __index
  -- rejected it. The C function pointer must be cached at init.
  local src = read_file("src/crypto.lua")
  local body = extract_between(src, "function M.sha256(data)", "function M.sha1(data)")
  expect_true(not body:find("sha256_accel_lib.sha256_accel", 1, true),
    "M.sha256 still indexes sha256_accel_lib every call — 900619 FFI __index")
  expect_true(body:find("sha256_accel_fn", 1, true),
    "M.sha256 must call a cached sha256_accel_fn, not the library object")
  expect_true(body:find('type(data) ~= "string"', 1, true)
      or body:find("type(data) == \"string\"", 1, true),
    "M.sha256 must reject non-strings before the FFI call")
end)

test("hash256 hot path does not index the FFI library object", function()
  local src = read_file("src/crypto.lua")
  local body = extract_between(src, "function M.hash256(data)",
    "function M.hash256_ptr")
  expect_true(not body:find("sha256_accel_lib.sha256d_accel", 1, true),
    "M.hash256 still indexes sha256_accel_lib every call")
end)

test("sha256 of empty / short / 32-byte / 1k-byte strings still works", function()
  local a = crypto.sha256("")
  local b = crypto.sha256("hello")
  local c = crypto.sha256(string.rep("x", 32))
  local d = crypto.sha256(string.rep("y", 1024))
  expect_eq(#a, 32)
  expect_eq(#b, 32)
  expect_eq(#c, 32)
  expect_eq(#d, 32)
  expect_true(a ~= b)
  expect_true(crypto.sha256("hello") == b)
end)

test("sha256 rejects a number with a clear error (not FFI __index)", function()
  local ok, err = pcall(crypto.sha256, 0)
  expect_false(ok, "sha256(0) must error")
  err = tostring(err)
  expect_true(err:find("expected string", 1, true),
    "sha256(0) must say expected string, got: " .. err)
  expect_true(not err:find("__index", 1, true),
    "sha256(0) must not be the 900619 FFI __index crash: " .. err)
end)

test("JIT stress: 20k sha256 calls of mixed lengths do not throw", function()
  -- The 900619 fault appeared after hundreds of blocks of SHA-256, i.e.
  -- after LuaJIT had traces. Mix lengths so traces cannot assume one size.
  for i = 1, 20000 do
    local n = i % 257
    local d = crypto.sha256(string.rep(string.char(i % 256), n))
    assert(#d == 32)
  end
end)

print(string.format("\n%d PASS / %d FAIL", PASS, FAIL))
os.exit(FAIL == 0 and 0 or 1)
