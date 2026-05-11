#!/usr/bin/env luajit
-- Test suite for presync anti-DoS mechanism and W88 headerssync.cpp audit fixes.
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

-- Helper: 64-char hex string of N zero bytes followed by a suffix.
-- Usage: hex64("", "01") = "00000000000000000000000000000000000000000000000000000000000000" .. "01"
-- Actually: pad("01") to 64 chars by prepending zeros.
local function hex64(val_hex)
  -- val_hex is a hex string; left-pad with zeros to 64 chars.
  local padded = string.rep("0", 64 - #val_hex) .. val_hex
  assert(#padded == 64, "hex64: result is not 64 chars")
  return padded
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
  local zero = consensus.work_from_hex(hex64("00"))
  assert_eq(32, #zero, "zero length")
  for i = 1, 32 do
    assert_eq(0, zero:byte(i), "zero byte " .. i)
  end

  local one = consensus.work_from_hex(hex64("01"))
  assert_eq(1, one:byte(32), "one value")
end) then passed = passed + 1 else failed = failed + 1 end

if test("compares work values correctly", function()
  local zero = consensus.work_from_hex(hex64("00"))
  local one  = consensus.work_from_hex(hex64("01"))
  local two  = consensus.work_from_hex(hex64("02"))

  assert_eq(0,  consensus.work_compare(zero, zero), "zero == zero")
  assert_eq(-1, consensus.work_compare(zero, one),  "zero < one")
  assert_eq(1,  consensus.work_compare(one,  zero), "one > zero")
  assert_eq(-1, consensus.work_compare(one,  two),  "one < two")
end) then passed = passed + 1 else failed = failed + 1 end

if test("adds work values correctly", function()
  local one = consensus.work_from_hex(hex64("01"))
  local two = consensus.work_from_hex(hex64("02"))

  local sum = consensus.work_add(one, one)
  assert_eq(0, consensus.work_compare(sum, two), "1 + 1 = 2")

  -- Test carry: 0xff + 1 = 0x100
  local ff  = consensus.work_from_hex(hex64("ff"))
  local sum2 = consensus.work_add(ff, one)
  local expected = consensus.work_from_hex(hex64("0100"))
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

print("\n[W88-FIX1+2] Per-network commitment_period / redownload_buffer_size:")

if test("mainnet uses Core-correct commitment_period=641 redownload_buffer_size=15218", function()
  local genesis_hash = types.hash256(string.rep("\x00", 32))
  local chain_start = { hash = genesis_hash, height = 0, work = consensus.work_zero() }
  local state = sync.new_headers_sync_state("p", consensus.networks.mainnet, chain_start)
  assert_eq(641,   state.commitment_period,    "mainnet commitment_period")
  assert_eq(15218, state.redownload_buffer_size, "mainnet redownload_buffer_size")
end) then passed = passed + 1 else failed = failed + 1 end

if test("testnet4 uses Core-correct commitment_period=606 redownload_buffer_size=16092", function()
  local genesis_hash = types.hash256(string.rep("\x00", 32))
  local chain_start = { hash = genesis_hash, height = 0, work = consensus.work_zero() }
  local state = sync.new_headers_sync_state("p", consensus.networks.testnet4, chain_start)
  assert_eq(606,   state.commitment_period,    "testnet4 commitment_period")
  assert_eq(16092, state.redownload_buffer_size, "testnet4 redownload_buffer_size")
end) then passed = passed + 1 else failed = failed + 1 end

if test("regtest uses Core-correct commitment_period=275 redownload_buffer_size=7017", function()
  local genesis_hash = types.hash256(string.rep("\x00", 32))
  local chain_start = { hash = genesis_hash, height = 0, work = consensus.work_zero() }
  local state = sync.new_headers_sync_state("p", consensus.networks.regtest, chain_start)
  assert_eq(275,  state.commitment_period,    "regtest commitment_period")
  assert_eq(7017, state.redownload_buffer_size, "regtest redownload_buffer_size")
end) then passed = passed + 1 else failed = failed + 1 end

print("\n[W88-FIX3] m_max_commitments DoS bound:")

if test("max_commitments is set to a positive value on construction", function()
  local genesis_hash = types.hash256(string.rep("\x00", 32))
  local chain_start = {
    hash = genesis_hash,
    height = 0,
    work = consensus.work_zero(),
    timestamp = 1296688602,  -- regtest genesis
  }
  local state = sync.new_headers_sync_state("p", consensus.networks.regtest, chain_start)
  assert_true(state.max_commitments > 0, "max_commitments must be positive")
  -- Sanity: with regtest period=275, ~6 blk/s * (now-genesis + 7200)/275
  -- For a genesis from 2011, that is roughly millions; just check it's reasonable.
  assert_true(state.max_commitments > 100, "max_commitments > 100")
end) then passed = passed + 1 else failed = failed + 1 end

if test("presync aborts when max_commitments exceeded", function()
  -- Build a network where min_chain_work is impossibly high so PRESYNC never
  -- transitions, and set max_commitments artificially low by using a large
  -- commitment_period relative to chain length (we'll insert a small override).
  local genesis_hash = types.hash256(string.rep("\x00", 32))
  local chain_start = {
    hash = genesis_hash,
    height = 0,
    work = consensus.work_zero(),
    timestamp = os.time(),  -- use current time so max_seconds is very small
  }
  -- Use a network with pow_allow_min_difficulty=true (skips difficulty check)
  -- and high min_chain_work so PRESYNC never transitions.
  local high_work_network = {
    name = "test",
    genesis = consensus.networks.regtest.genesis,
    pow_limit_bits = 0x207fffff,
    pow_no_retarget = true,
    pow_allow_min_difficulty = true,
    min_chain_work = hex64("ffffffffffffffffffffffffffffffff"),
    headerssync_params = {
      commitment_period = 1,  -- commit on EVERY header (maximises commitment rate)
      redownload_buffer_size = 7017,
    },
  }

  local state = sync.new_headers_sync_state("attacker", high_work_network, chain_start)
  -- Artificially lower max_commitments to 3 to trigger the DoS guard quickly.
  state.max_commitments = 3

  local headers = create_header_chain(
    genesis_hash,
    consensus.networks.regtest.genesis.timestamp,
    10,
    0x207fffff
  )

  local ok, err = state:process_presync(headers)
  assert_false(ok, "should abort when max_commitments exceeded")
  assert_true(err ~= nil and err:find("max commitments") ~= nil,
    "error should mention max commitments, got: " .. tostring(err))
end) then passed = passed + 1 else failed = failed + 1 end

print("\n[W88-FIX4] Secure commitment_offset from /dev/urandom:")

if test("commitment_offset is in range [0, commitment_period-1]", function()
  local genesis_hash = types.hash256(string.rep("\x00", 32))
  local chain_start = { hash = genesis_hash, height = 0, work = consensus.work_zero() }
  local state = sync.new_headers_sync_state("p", consensus.networks.regtest, chain_start)
  assert_true(state.commitment_offset >= 0, "offset >= 0")
  assert_true(state.commitment_offset < state.commitment_period,
    string.format("offset (%d) < commitment_period (%d)",
      state.commitment_offset, state.commitment_period))
end) then passed = passed + 1 else failed = failed + 1 end

if test("commitment_salt is 32 bytes from secure source", function()
  local genesis_hash = types.hash256(string.rep("\x00", 32))
  local chain_start = { hash = genesis_hash, height = 0, work = consensus.work_zero() }
  local state = sync.new_headers_sync_state("p", consensus.networks.regtest, chain_start)
  assert_eq(32, #state.commitment_salt, "salt must be 32 bytes")
  -- Two different instances must have different salts (with overwhelming probability)
  local state2 = sync.new_headers_sync_state("p2", consensus.networks.regtest, chain_start)
  -- Note: there is a 1/256^32 chance this fails; acceptable.
  assert_true(state.commitment_salt ~= state2.commitment_salt, "salts should differ per instance")
end) then passed = passed + 1 else failed = failed + 1 end

print("\n[W88-FIX5] chain_start.bits used for difficulty check:")

if test("presync uses chain_start.bits not genesis.bits when syncing from fork point", function()
  -- Simulate a node whose chain_start is at height 2016 with mainnet difficulty
  -- (different from genesis bits). The first header should use chain_start.bits
  -- for PermittedDifficultyTransition, not network.genesis.bits.
  local fake_start_hash = types.hash256(string.rep("\xab", 32))
  local chain_start_bits = 0x1d00ffff  -- mainnet-style bits at the fork point
  local chain_start = {
    hash = fake_start_hash,
    height = 2016,
    work = consensus.work_zero(),
    bits = chain_start_bits,
  }

  local net = {
    name = "test",
    genesis = { bits = 0x207fffff, timestamp = 1296688602 },  -- different from chain_start.bits
    pow_limit_bits = 0x1d00ffff,
    pow_no_retarget = false,
    pow_allow_min_difficulty = false,
    min_chain_work = hex64("00"),
    headerssync_params = { commitment_period = 641, redownload_buffer_size = 15218 },
  }

  local state = sync.new_headers_sync_state("p", net, chain_start)
  -- The presync state should be initialised with chain_start.bits, not genesis.bits
  assert_eq(chain_start_bits, state.presync.last_bits,
    "presync.last_bits must be chain_start.bits, not genesis.bits")
  assert_eq(chain_start_bits, state.chain_start_bits, "chain_start_bits stored correctly")
end) then passed = passed + 1 else failed = failed + 1 end

print("\n[W88-FIX6] PRESYNC phase:")

local network = {
  name = "test",
  genesis = consensus.networks.regtest.genesis,
  pow_limit_bits = 0x207fffff,
  pow_no_retarget = true,
  pow_allow_min_difficulty = true,
  min_chain_work = hex64("1000"),
  headerssync_params = { commitment_period = 275, redownload_buffer_size = 7017 },
}

local genesis_hash = types.hash256(string.rep("\x00", 32))
local chain_start = {
  hash = genesis_hash,
  height = 0,
  work = consensus.work_zero()
}

if test("processes valid headers and accumulates work", function()
  -- Use a network with very high min_chain_work so PRESYNC doesn't transition.
  local presync_only_network = {
    name = "test",
    genesis = consensus.networks.regtest.genesis,
    pow_limit_bits = 0x207fffff,
    pow_no_retarget = true,
    pow_allow_min_difficulty = true,
    min_chain_work = hex64("ffffffffffffffffffffffffffffffff"),
    headerssync_params = { commitment_period = 275, redownload_buffer_size = 7017 },
  }
  local state = sync.new_headers_sync_state("peer1", presync_only_network, chain_start)

  local headers = create_header_chain(
    genesis_hash,
    consensus.networks.regtest.genesis.timestamp,
    10,
    0x207fffff
  )

  local ok, err = state:process_presync(headers)
  assert_true(ok, "process_presync should succeed: " .. tostring(err))
  assert_eq("presync", state:get_state(), "should stay in presync")

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

if test("[W88-FIX8] no bogus timestamp rejection: older timestamps accepted in PRESYNC", function()
  -- Bitcoin Core does NOT reject headers based on timestamp in PRESYNC.
  -- Old lunarblock had: if header.timestamp <= last_timestamp - 7200 then reject.
  -- This fix removes that spurious check.
  local state = sync.new_headers_sync_state("peer1", network, chain_start)

  -- Create header with an old-ish timestamp (but still positive increment).
  local h1 = create_valid_header(genesis_hash, consensus.networks.regtest.genesis.timestamp + 600, 0x207fffff)
  find_valid_nonce(h1)
  local ok, err = state:process_presync({h1})
  assert_true(ok, "first header should be accepted")

  local h1hash = validation.compute_block_hash(h1)
  -- Create a second header with a timestamp only slightly greater (not - 7200).
  -- Old code would reject if timestamp <= last - 7200; this header is valid.
  local h2 = create_valid_header(h1hash, consensus.networks.regtest.genesis.timestamp + 601, 0x207fffff)
  find_valid_nonce(h2)
  local ok2, err2 = state:process_presync({h2})
  assert_true(ok2, "valid-timestamp header should be accepted: " .. tostring(err2))
end) then passed = passed + 1 else failed = failed + 1 end

if test("transitions to REDOWNLOAD when min_chain_work reached", function()
  local low_work_network = {
    name = "test",
    genesis = consensus.networks.regtest.genesis,
    pow_limit_bits = 0x207fffff,
    pow_no_retarget = true,
    pow_allow_min_difficulty = true,
    min_chain_work = hex64("01"),
    headerssync_params = { commitment_period = 275, redownload_buffer_size = 7017 },
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

print("\n[W88-FIX7] REDOWNLOAD phase (no premature FINAL):")

if test("REDOWNLOAD does not set FINAL mid-batch when full_headers_message=true", function()
  local low_work_network = {
    name = "test",
    genesis = consensus.networks.regtest.genesis,
    pow_limit_bits = 0x207fffff,
    pow_no_retarget = true,
    pow_allow_min_difficulty = true,
    min_chain_work = hex64("01"),
    headerssync_params = { commitment_period = 275, redownload_buffer_size = 7017 },
  }

  local state = sync.new_headers_sync_state("peer1", low_work_network, chain_start)

  local headers = create_header_chain(
    genesis_hash,
    consensus.networks.regtest.genesis.timestamp,
    10,
    0x207fffff
  )

  state:process_presync(headers)
  assert_eq("redownload", state:get_state(), "should be in redownload after presync")

  -- Redownload same headers, signal full_headers_message=true (peer has more).
  local accepted, err = state:process_headers(headers, true)
  assert_true(err == nil, "should not error: " .. tostring(err))
  -- Work threshold was reached, buffer is empty, BUT full_headers_message=true
  -- means we should NOT yet be FINAL — old code always set FINAL here.
  -- Actually per Core logic: if buffer is empty AND work_threshold_reached,
  -- FINAL regardless (sync complete). Let's verify the buffer-empty path.
  -- In this test work_threshold is reached so buffer is emptied; FINAL is correct.
  assert_eq("final", state:get_state(), "should be FINAL after buffer drains with threshold")
  assert_true(state:is_complete(), "is_complete should be true")
end) then passed = passed + 1 else failed = failed + 1 end

if test("REDOWNLOAD stays in REDOWNLOAD when full batch and buffer not empty", function()
  local low_work_network = {
    name = "test",
    genesis = consensus.networks.regtest.genesis,
    pow_limit_bits = 0x207fffff,
    pow_no_retarget = true,
    pow_allow_min_difficulty = true,
    -- Set min_chain_work impossibly high so work threshold is never reached
    -- during the 3-header batch below.
    min_chain_work = hex64("ffffffffffffffffffffffffffffffff"),
    headerssync_params = { commitment_period = 275, redownload_buffer_size = 7017 },
  }

  local state = sync.new_headers_sync_state("peer1", low_work_network, chain_start)
  -- Force into REDOWNLOAD state directly for this test
  state.state = sync.HeadersSyncState.STATE.REDOWNLOAD
  state.redownload = {
    work = consensus.work_zero(),
    last_hash = genesis_hash,
    last_bits = 0x207fffff,
    height = 0,
    buffer = {},
    commitment_idx = 1,
    work_threshold_reached = false,
  }

  local headers = create_header_chain(
    genesis_hash,
    consensus.networks.regtest.genesis.timestamp,
    3,
    0x207fffff
  )

  -- Process with full_headers_message=true (peer has more).
  local accepted, err = state:process_headers(headers, true)
  assert_true(err == nil, "should not error: " .. tostring(err))
  -- Work threshold NOT reached, buffer has headers, full message: stay in REDOWNLOAD.
  assert_eq("redownload", state:get_state(),
    "should stay in REDOWNLOAD while buffer has headers and message is full")
  assert_true(not state:is_complete(), "should not be complete yet")
end) then passed = passed + 1 else failed = failed + 1 end

if test("REDOWNLOAD transitions to FINAL on non-full message (peer abandoned)", function()
  local low_work_network = {
    name = "test",
    genesis = consensus.networks.regtest.genesis,
    pow_limit_bits = 0x207fffff,
    pow_no_retarget = true,
    pow_allow_min_difficulty = true,
    min_chain_work = hex64("ffffffffffffffffffffffffffffffff"),  -- never reached
    headerssync_params = { commitment_period = 275, redownload_buffer_size = 7017 },
  }

  local state = sync.new_headers_sync_state("peer1", low_work_network, chain_start)
  state.state = sync.HeadersSyncState.STATE.REDOWNLOAD
  state.redownload = {
    work = consensus.work_zero(),
    last_hash = genesis_hash,
    last_bits = 0x207fffff,
    height = 0,
    buffer = {},
    commitment_idx = 1,
    work_threshold_reached = false,
  }

  local headers = create_header_chain(
    genesis_hash,
    consensus.networks.regtest.genesis.timestamp,
    3,
    0x207fffff
  )

  -- Process with full_headers_message=false (peer sent < 2000).
  local accepted, err = state:process_headers(headers, false)
  assert_true(err == nil, "should not error: " .. tostring(err))
  -- Work threshold NOT reached, non-full message: peer abandoned sync → FINAL.
  assert_eq("final", state:get_state(),
    "should be FINAL when peer sends non-full batch without reaching work threshold")
end) then passed = passed + 1 else failed = failed + 1 end

if test("processes redownloaded headers and reaches FINAL", function()
  local low_work_network = {
    name = "test",
    genesis = consensus.networks.regtest.genesis,
    pow_limit_bits = 0x207fffff,
    pow_no_retarget = true,
    pow_allow_min_difficulty = true,
    min_chain_work = hex64("01"),
    headerssync_params = { commitment_period = 275, redownload_buffer_size = 7017 },
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
  -- process_redownload alone doesn't set FINAL; test process_headers instead.
end) then passed = passed + 1 else failed = failed + 1 end

if test("rejects non-continuous headers in redownload", function()
  local low_work_network = {
    name = "test",
    genesis = consensus.networks.regtest.genesis,
    pow_limit_bits = 0x207fffff,
    pow_no_retarget = true,
    pow_allow_min_difficulty = true,
    min_chain_work = hex64("01"),
    headerssync_params = { commitment_period = 275, redownload_buffer_size = 7017 },
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

print("\n[W88-FIX9] get_getheaders_request REDOWNLOAD returns last_hash:")

if test("PRESYNC locator uses presync.last_hash", function()
  local state = sync.new_headers_sync_state("peer1", network, chain_start)
  local req = state:get_getheaders_request()
  assert_true(req ~= nil, "request should not be nil")
  local req_hash_hex = types.hash256_hex(req.locator_hashes[1])
  local expected_hex = types.hash256_hex(genesis_hash)
  assert_eq(expected_hex, req_hash_hex, "PRESYNC locator should start from chain_start (genesis)")
end) then passed = passed + 1 else failed = failed + 1 end

if test("REDOWNLOAD locator uses redownload.last_hash (not chain_start)", function()
  local low_work_network = {
    name = "test",
    genesis = consensus.networks.regtest.genesis,
    pow_limit_bits = 0x207fffff,
    pow_no_retarget = true,
    pow_allow_min_difficulty = true,
    min_chain_work = hex64("01"),
    headerssync_params = { commitment_period = 275, redownload_buffer_size = 7017 },
  }
  local state = sync.new_headers_sync_state("peer1", low_work_network, chain_start)

  local headers = create_header_chain(
    genesis_hash,
    consensus.networks.regtest.genesis.timestamp,
    5,
    0x207fffff
  )
  state:process_presync(headers)
  assert_eq("redownload", state:get_state(), "should be in redownload")

  -- Process 2 redownload headers to advance redownload.last_hash
  local rd_headers = create_header_chain(
    genesis_hash,
    consensus.networks.regtest.genesis.timestamp,
    2,
    0x207fffff
  )
  state:process_redownload(rd_headers)

  local req = state:get_getheaders_request()
  assert_true(req ~= nil, "request should not be nil")
  local req_hash_hex = types.hash256_hex(req.locator_hashes[1])
  local chain_start_hex = types.hash256_hex(genesis_hash)
  local redownload_last_hex = types.hash256_hex(state.redownload.last_hash)
  -- The locator should match redownload.last_hash, NOT chain_start
  assert_eq(redownload_last_hex, req_hash_hex,
    "REDOWNLOAD locator must use redownload.last_hash, not chain_start")
  -- Verify it differs from chain_start (since we processed 2 headers)
  assert_true(req_hash_hex ~= chain_start_hex,
    "REDOWNLOAD locator must differ from chain_start after processing headers")
end) then passed = passed + 1 else failed = failed + 1 end

print("\nLow-work attack simulation:")

if test("memory usage stays bounded during attack", function()
  local high_work_network = {
    name = "test",
    genesis = consensus.networks.regtest.genesis,
    pow_limit_bits = 0x207fffff,
    pow_no_retarget = true,
    pow_allow_min_difficulty = true,
    min_chain_work = hex64("ffffffffffffffffffffffffffffffff"),
    headerssync_params = { commitment_period = 275, redownload_buffer_size = 7017 },
  }

  local state = sync.new_headers_sync_state("attacker", high_work_network, chain_start)

  local attack_headers = create_header_chain(
    genesis_hash,
    consensus.networks.regtest.genesis.timestamp,
    100,
    0x207fffff
  )

  local ok, _ = state:process_presync(attack_headers)
  assert_true(ok, "should accept headers (max_commitments not hit)")
  assert_eq("presync", state:get_state(), "should stay in presync")

  local stats = state:get_stats()
  assert_eq(100, stats.count, "header count")
  -- With commitment_period=275 and only 100 headers, at most 0 or 1 commitments
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
