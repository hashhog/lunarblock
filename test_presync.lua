#!/usr/bin/env luajit
-- Simple test runner for presync anti-DoS mechanism
-- Run with: LD_LIBRARY_PATH=./lib luajit test_presync.lua

package.path = "src/?.lua;" .. package.path
-- Set up lunarblock.X aliases
package.preload["lunarblock.types"] = function() return require("types") end
package.preload["lunarblock.serialize"] = function() return require("serialize") end
package.preload["lunarblock.crypto"] = function() return require("crypto") end
package.preload["lunarblock.script"] = function() return require("script") end
package.preload["lunarblock.consensus"] = function() return require("consensus") end
package.preload["lunarblock.validation"] = function() return require("validation") end
package.preload["lunarblock.p2p"] = function() return require("p2p") end

local types = require("types")
local consensus = require("consensus")
local validation = require("validation")
local crypto = require("crypto")
local sync = require("sync")

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

-- Create a valid header extending from a parent (regtest difficulty)
local function create_valid_header(parent_hash, timestamp, bits)
  bits = bits or 0x207fffff  -- regtest difficulty
  timestamp = timestamp or os.time()
  return types.block_header(
    1,               -- version
    parent_hash,     -- prev_hash
    types.hash256_zero(),  -- merkle_root
    timestamp,
    bits,
    0                -- nonce (we'll find valid one)
  )
end

-- Find a valid nonce for a header (brute force for regtest difficulty)
local function find_valid_nonce(header)
  local target = consensus.bits_to_target(header.bits)
  for nonce = 0, 1000000 do
    header.nonce = nonce
    local hash = validation.compute_block_hash(header)
    if consensus.hash_meets_target(hash.bytes, target) then
      return true
    end
  end
  return false
end

-- Create a chain of valid headers
local function create_header_chain(parent_hash, base_timestamp, count, bits)
  local headers = {}
  local current_hash = parent_hash
  local timestamp = base_timestamp

  for i = 1, count do
    timestamp = timestamp + 600
    local header = create_valid_header(current_hash, timestamp, bits)
    assert(find_valid_nonce(header), "Failed to find valid nonce for header " .. i)
    headers[i] = header
    current_hash = validation.compute_block_hash(header)
  end

  return headers
end

print("\n=== PRESYNC/REDOWNLOAD Anti-DoS Tests ===\n")

local passed = 0
local failed = 0

print("256-bit work arithmetic:")

if test("parses hex work values", function()
  local zero = consensus.work_from_hex(string.rep("00", 64))
  assert_eq(32, #zero, "zero length")
  for i = 1, 32 do
    assert_eq(0, zero:byte(i), "zero byte " .. i)
  end

  local one = consensus.work_from_hex(string.rep("00", 62) .. "01")
  assert_eq(1, one:byte(32), "one value")
end) then passed = passed + 1 else failed = failed + 1 end

if test("compares work values correctly", function()
  local zero = consensus.work_from_hex(string.rep("00", 64))
  local one = consensus.work_from_hex(string.rep("00", 62) .. "01")
  local two = consensus.work_from_hex(string.rep("00", 62) .. "02")

  assert_eq(0, consensus.work_compare(zero, zero), "zero == zero")
  assert_eq(-1, consensus.work_compare(zero, one), "zero < one")
  assert_eq(1, consensus.work_compare(one, zero), "one > zero")
  assert_eq(-1, consensus.work_compare(one, two), "one < two")
end) then passed = passed + 1 else failed = failed + 1 end

if test("adds work values correctly", function()
  local one = consensus.work_from_hex(string.rep("00", 62) .. "01")
  local two = consensus.work_from_hex(string.rep("00", 62) .. "02")

  local sum = consensus.work_add(one, one)
  assert_eq(0, consensus.work_compare(sum, two), "1 + 1 = 2")

  -- Test carry
  local ff = consensus.work_from_hex(string.rep("00", 62) .. "ff")
  local sum2 = consensus.work_add(ff, one)
  local expected = consensus.work_from_hex(string.rep("00", 60) .. "0100")
  assert_eq(0, consensus.work_compare(sum2, expected), "ff + 1 = 100 (carry)")
end) then passed = passed + 1 else failed = failed + 1 end

if test("calculates block work from bits", function()
  local work = consensus.get_block_work(0x207fffff)  -- regtest
  assert_eq(32, #work, "work length")

  -- Higher difficulty = more work
  local easy_work = consensus.get_block_work(0x207fffff)
  local hard_work = consensus.get_block_work(0x1d00ffff)
  assert_eq(1, consensus.work_compare(hard_work, easy_work), "hard > easy")
end) then passed = passed + 1 else failed = failed + 1 end

print("\nHeadersSyncState creation:")

if test("creates sync state with correct initial values", function()
  local genesis_hash = types.hash256(string.rep("\x00", 32))
  local chain_start = {
    hash = genesis_hash,
    height = 0,
    work = consensus.work_zero()
  }

  local state = sync.new_headers_sync_state("peer1", consensus.networks.regtest, chain_start)

  assert_true(state ~= nil, "state created")
  assert_eq("presync", state:get_state(), "initial state")
  assert_true(not state:is_complete(), "not complete")
  assert_true(state:needs_headers(), "needs headers")
end) then passed = passed + 1 else failed = failed + 1 end

print("\nPRESYNC phase:")

local network = {
  name = "test",
  genesis = consensus.networks.regtest.genesis,
  pow_limit_bits = 0x207fffff,
  pow_no_retarget = true,
  pow_allow_min_difficulty = true,
  min_chain_work = string.rep("00", 60) .. "00001000",
}

local genesis_hash = types.hash256(string.rep("\x00", 32))
local chain_start = {
  hash = genesis_hash,
  height = 0,
  work = consensus.work_zero()
}

if test("processes valid headers and accumulates work", function()
  local state = sync.new_headers_sync_state("peer1", network, chain_start)

  local headers = create_header_chain(
    genesis_hash,
    consensus.networks.regtest.genesis.timestamp,
    10,
    0x207fffff
  )

  local ok, err = state:process_presync(headers)
  assert_true(ok, "process_presync should succeed: " .. tostring(err))

  local stats = state:get_stats()
  assert_eq(10, stats.count, "header count")
  assert_eq(10, stats.height, "height")
end) then passed = passed + 1 else failed = failed + 1 end

if test("rejects non-continuous headers", function()
  local state = sync.new_headers_sync_state("peer1", network, chain_start)

  local bad_headers = {
    create_valid_header(
      types.hash256(string.rep("\xff", 32)),  -- wrong parent
      consensus.networks.regtest.genesis.timestamp + 600
    )
  }
  find_valid_nonce(bad_headers[1])

  local ok, err = state:process_presync(bad_headers)
  assert_true(not ok, "should fail")
  assert_true(err:match("non%-continuous"), "error message")
end) then passed = passed + 1 else failed = failed + 1 end

if test("rejects headers with invalid PoW", function()
  local state = sync.new_headers_sync_state("peer1", network, chain_start)

  local bad_header = types.block_header(
    1,
    genesis_hash,
    types.hash256_zero(),
    os.time(),
    0x03000001,  -- very high difficulty
    0
  )

  local ok, err = state:process_presync({bad_header})
  assert_true(not ok, "should fail")
  assert_true(err:match("proof of work"), "error message")
end) then passed = passed + 1 else failed = failed + 1 end

if test("transitions to REDOWNLOAD when min_chain_work reached", function()
  local low_work_network = {
    name = "test",
    genesis = consensus.networks.regtest.genesis,
    pow_limit_bits = 0x207fffff,
    pow_no_retarget = true,
    pow_allow_min_difficulty = true,
    min_chain_work = string.rep("00", 62) .. "0001",  -- very low
  }

  local state = sync.new_headers_sync_state("peer1", low_work_network, chain_start)

  local headers = create_header_chain(
    genesis_hash,
    consensus.networks.regtest.genesis.timestamp,
    5,
    0x207fffff
  )

  local ok, _ = state:process_presync(headers)
  assert_true(ok, "process_presync should succeed")
  assert_eq("redownload", state:get_state(), "should transition to redownload")
end) then passed = passed + 1 else failed = failed + 1 end

print("\nREDOWNLOAD phase:")

if test("processes redownloaded headers and reaches FINAL", function()
  local low_work_network = {
    name = "test",
    genesis = consensus.networks.regtest.genesis,
    pow_limit_bits = 0x207fffff,
    pow_no_retarget = true,
    pow_allow_min_difficulty = true,
    min_chain_work = string.rep("00", 62) .. "0001",
  }

  local state = sync.new_headers_sync_state("peer1", low_work_network, chain_start)

  local headers = create_header_chain(
    genesis_hash,
    consensus.networks.regtest.genesis.timestamp,
    10,
    0x207fffff
  )

  state:process_presync(headers)
  assert_eq("redownload", state:get_state(), "should be in redownload")

  local accepted, err = state:process_redownload(headers)
  assert_true(err == nil, "should not error: " .. tostring(err))
  assert_true(accepted ~= nil, "should return accepted")
  assert_eq("final", state:get_state(), "should be complete")
  assert_true(state:is_complete(), "is_complete should be true")
end) then passed = passed + 1 else failed = failed + 1 end

if test("rejects non-continuous headers in redownload", function()
  local low_work_network = {
    name = "test",
    genesis = consensus.networks.regtest.genesis,
    pow_limit_bits = 0x207fffff,
    pow_no_retarget = true,
    pow_allow_min_difficulty = true,
    min_chain_work = string.rep("00", 62) .. "0001",
  }

  local state = sync.new_headers_sync_state("peer1", low_work_network, chain_start)

  local headers = create_header_chain(
    genesis_hash,
    consensus.networks.regtest.genesis.timestamp,
    5,
    0x207fffff
  )
  state:process_presync(headers)
  assert_eq("redownload", state:get_state())

  -- Try wrong headers
  local bad_headers = create_header_chain(
    types.hash256(string.rep("\xff", 32)),  -- wrong parent
    consensus.networks.regtest.genesis.timestamp,
    5,
    0x207fffff
  )

  local accepted, err = state:process_redownload(bad_headers)
  assert_true(accepted == nil, "should fail")
  assert_true(err:match("non%-continuous"), "error message")
end) then passed = passed + 1 else failed = failed + 1 end

print("\nLow-work attack simulation:")

if test("memory usage stays bounded during attack", function()
  local high_work_network = {
    name = "test",
    genesis = consensus.networks.regtest.genesis,
    pow_limit_bits = 0x207fffff,
    pow_no_retarget = true,
    pow_allow_min_difficulty = true,
    min_chain_work = string.rep("00", 50) .. string.rep("ff", 14),
  }

  local state = sync.new_headers_sync_state("attacker", high_work_network, chain_start)

  local attack_headers = create_header_chain(
    genesis_hash,
    consensus.networks.regtest.genesis.timestamp,
    100,
    0x207fffff
  )

  local ok, _ = state:process_presync(attack_headers)
  assert_true(ok, "should accept headers")
  assert_eq("presync", state:get_state(), "should stay in presync")

  local stats = state:get_stats()
  assert_eq(100, stats.count, "header count")
  assert_true(#state.presync.commitments <= 1, "bounded commitments")
end) then passed = passed + 1 else failed = failed + 1 end

print("\n===========================================")
print(string.format("Results: %d passed, %d failed", passed, failed))

if failed > 0 then
  os.exit(1)
else
  print("\nAll tests passed!")
  os.exit(0)
end
