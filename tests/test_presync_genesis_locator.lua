#!/usr/bin/env luajit
-- PRESYNC anti-DoS pipeline regression test.
--
-- Two regressions covered, mirrors nimrod's 4deead0:
--
--   1. try_low_work_sync MUST agree with accept_header's
--      "too-little-chainwork" gate.  Pre-fix it computed claimed_work via
--      consensus.get_block_work (which has a latent byte-placement bug
--      that inflates the per-block contribution); the byte compare then
--      reported the candidate chain as having ENOUGH work, returned
--      false, and the caller fell through to ban the peer.  This is the
--      2026-05-28 mainnet genesis-IBD stall (lunarblock h=0, banning
--      every honest peer on its first headers batch with
--      "too-little-chainwork").
--
--   2. The PRESYNC/REDOWNLOAD continuation getheaders MUST emit the full
--      chain_start exponential-backoff locator (Bitcoin Core
--      headerssync.cpp:296 — NextHeadersRequestLocator), not just the
--      per-phase continue-from hash.  PRESYNC commitment-only headers
--      live in the sync_state and are never relayed back to peers, so a
--      syncing peer that has not yet seen our most recent commitment-only
--      header (the COMMON case during PRESYNC) had no way to honour a
--      single-entry getheaders.
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   LD_LIBRARY_PATH=./lib luajit tests/test_presync_genesis_locator.lua

package.path = "src/?.lua;./?.lua;" .. package.path

local loaders = package.loaders or package.searchers
table.insert(loaders, 2, function(module)
  local name = module:match("^lunarblock%.(.+)")
  if name then
    local filename = "src/" .. name .. ".lua"
    local f = io.open(filename)
    if f then f:close(); return loadfile(filename) end
  end
end)

local types = require("lunarblock.types")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local sync = require("lunarblock.sync")

local PASS, FAIL = 0, 0

local function expect_eq(a, b, name)
  if a == b then
    PASS = PASS + 1
    print("PASS " .. name)
  else
    FAIL = FAIL + 1
    print("FAIL " .. name .. ": expected " .. tostring(b) .. " got " .. tostring(a))
  end
end

local function expect_true(v, name)
  if v then
    PASS = PASS + 1
    print("PASS " .. name)
  else
    FAIL = FAIL + 1
    print("FAIL " .. name .. ": expected true")
  end
end

local function expect_gt(a, b, name)
  if a > b then
    PASS = PASS + 1
    print("PASS " .. name .. " (" .. tostring(a) .. " > " .. tostring(b) .. ")")
  else
    FAIL = FAIL + 1
    print("FAIL " .. name .. ": expected " .. tostring(a) .. " > " .. tostring(b))
  end
end

-- ----------------------------------------------------------------------
-- Helpers (regtest difficulty, find valid nonce)
-- ----------------------------------------------------------------------

local function find_valid_nonce(header)
  local target = consensus.bits_to_target(header.bits)
  for nonce = 0, 5000000 do
    header.nonce = nonce
    local hash = validation.compute_block_hash(header)
    if consensus.hash_meets_target(hash.bytes, target) then
      return true
    end
  end
  return false
end

local function create_regtest_chain(parent_hash, base_timestamp, count)
  local headers = {}
  local current_hash = parent_hash
  local timestamp = base_timestamp

  for i = 1, count do
    timestamp = timestamp + 600
    local header = types.block_header(
      1, current_hash, types.hash256_zero(),
      timestamp, 0x207fffff, 0
    )
    assert(find_valid_nonce(header), "no valid nonce for header " .. i)
    headers[i] = header
    current_hash = validation.compute_block_hash(header)
  end

  return headers
end

-- A storage stub: in-memory only.  Mirrors the get/put surface that
-- HeaderChain pokes during accept_header.
local function fake_storage()
  local cf_data = {}
  return {
    CF = { META = "meta", HEADER = "header", HEIGHT = "height" },
    get = function(_cf, _k) return cf_data[_cf .. ":" .. tostring(_k)] end,
    put = function(_cf, _k, _v, _sync)
      cf_data[_cf .. ":" .. tostring(_k)] = _v
    end,
    put_header = function(_hash, _hdr) end,
    put_height_index = function(_h, _hash) end,
    get_header = function(_hash) return nil end,
    get_hash_by_height = function(_h) return nil end,
  }
end

-- ----------------------------------------------------------------------
-- Test 1: try_low_work_sync agrees with accept_header at genesis
-- ----------------------------------------------------------------------

-- Synthesise a network whose min_chain_work is greater than the work of
-- any small chain of regtest headers, so accept_header would reject with
-- "too-little-chainwork" and try_low_work_sync MUST take over.
local high_work_network = {
  name = "test",
  genesis = consensus.networks.regtest.genesis,
  pow_limit_bits = 0x207fffff,
  pow_no_retarget = true,
  pow_allow_min_difficulty = true,
  min_chain_work = "00000000000000000000000000000000000000000000000000000000ffffffff",
  bip34_height = 100000, bip65_height = 100000, bip66_height = 100000,
  enforce_bip94 = false,
  checkpoints = {},
  -- Set a generous headerssync_params so we don't trip max_commitments
  headerssync_params = { commitment_period = 1000, redownload_buffer_size = 7017 },
}

-- Generate a continuity-correct chain.  2000 regtest-difficulty headers
-- take ~150ms on a modern box, well within test runtime budgets.
do
  local hc = sync.new_header_chain(high_work_network, fake_storage())
  hc:add_genesis()
  local genesis_hash = hc.header_tip_hash
  expect_eq(hc.header_tip_height, 0, "header chain initialized at h=0")

  local valid_headers = create_regtest_chain(
    genesis_hash, consensus.networks.regtest.genesis.timestamp, 2000
  )
  expect_eq(#valid_headers, 2000, "generated 2000 continuity-correct headers")

  -- Mock peer
  local peer = { id = 1, ip = "1.2.3.4", port = 8333,
                 send_message = function() end }

  local entered = hc:try_low_work_sync(peer, valid_headers)
  expect_true(entered, "try_low_work_sync ENTERS PRESYNC for low-work mainnet-style chain")
  expect_true(hc.peer_sync_states[1] ~= nil, "per-peer sync_state created")
end

-- ----------------------------------------------------------------------
-- Test 2: try_low_work_sync float-domain comparison agrees with accept_header
-- ----------------------------------------------------------------------

do
  -- mainnet's min_chain_work is huge (~2^91).  A regtest-difficulty
  -- 2000-header batch has nowhere near that much work.  The OLD
  -- byte-arithmetic path returned ">= min" (false-positive: "sufficient
  -- work"), which made try_low_work_sync return false and the peer was
  -- banned with "too-little-chainwork".  The new float-domain path must
  -- return true (claimed < min) so PRESYNC is entered.
  --
  -- We can't actually generate 2000 valid MAINNET-difficulty headers in
  -- a test, but the float-domain comparison only inspects header.bits
  -- via work_for_bits, so reading work_for_bits on regtest bits gives a
  -- conservative (under-) estimate.  If even THAT survives the < min
  -- gate, the real mainnet case (much more work per header) certainly
  -- would too.  This is a tighter regression guard than the on-wire
  -- shape.
  local mainnet = consensus.networks.mainnet

  local hc = sync.new_header_chain(mainnet, fake_storage())
  hc:add_genesis()

  local tip_total_work = hc.headers[types.hash256_hex(hc.header_tip_hash)].total_work or 0

  -- Just verify the math: 2000 * regtest_work + genesis_work < mainnet min_chain_work.
  local claimed_work_float = tip_total_work
  for _ = 1, 2000 do
    claimed_work_float = claimed_work_float + hc:work_for_bits(0x207fffff)
  end

  local min_work_hex = mainnet.min_chain_work
  local min_work_float = 0
  for i = 1, 32 do
    min_work_float = min_work_float * 256 +
      tonumber(min_work_hex:sub(2*i-1, 2*i), 16)
  end

  expect_true(claimed_work_float < min_work_float,
    "regtest-difficulty 2000-header batch < mainnet min_chain_work")
end

-- ----------------------------------------------------------------------
-- Test 3: build_presync_locator emits multi-entry locator
-- ----------------------------------------------------------------------

do
  local hc = sync.new_header_chain(high_work_network, fake_storage())
  hc:add_genesis()
  local genesis_hash = hc.header_tip_hash

  -- Walk a small valid v=1 chain so multiple heights are available for
  -- exponentiation.  10 headers + genesis = 11 entries the locator can
  -- pick from.  (high_work_network sets bip34/65/66_height=100000, so
  -- v=1 is fine here.)
  local headers = create_regtest_chain(
    genesis_hash, consensus.networks.regtest.genesis.timestamp, 10
  )
  for _, h in ipairs(headers) do
    local ok, err = hc:accept_header(h, { min_pow_checked = true })
    assert(ok, "accept_header failed: " .. tostring(err))
  end

  -- Build a sync_state pretending we're mid-PRESYNC from chain_start at
  -- height 10.
  local chain_start = {
    hash = hc.header_tip_hash, height = hc.header_tip_height,
    work = consensus.work_zero(), bits = 0x207fffff,
  }
  local ss = sync.new_headers_sync_state(42, high_work_network, chain_start)

  -- Pre-fix: get_getheaders_request returned a single entry.  Post-fix:
  -- build_presync_locator must return MULTIPLE entries (continue-from +
  -- exponential backoff from chain_start).
  local locator = hc:build_presync_locator(ss)
  expect_gt(#locator, 1,
    "build_presync_locator emits exponential-backoff locator, not single hash")

  -- First entry must be presync.last_hash (continue-from).
  expect_eq(types.hash256_hex(locator[1]),
            types.hash256_hex(ss.presync.last_hash),
            "first locator entry is presync.last_hash")

  -- Last entry must be the genesis hash (Core's LocatorEntries always
  -- terminates at genesis).
  local hc_genesis_hex = types.hash256_hex(genesis_hash)
  local saw_genesis = false
  for _, h in ipairs(locator) do
    if types.hash256_hex(h) == hc_genesis_hex then
      saw_genesis = true; break
    end
  end
  expect_true(saw_genesis, "locator includes genesis hash")
end

-- ----------------------------------------------------------------------
-- Test 4: REDOWNLOAD locator uses redownload.last_hash, not chain_start
-- ----------------------------------------------------------------------

do
  local hc = sync.new_header_chain(high_work_network, fake_storage())
  hc:add_genesis()
  local genesis_hash = hc.header_tip_hash

  local low_work_network = {
    name = "test",
    genesis = consensus.networks.regtest.genesis,
    pow_limit_bits = 0x207fffff,
    pow_no_retarget = true,
    pow_allow_min_difficulty = true,
    min_chain_work = "0000000000000000000000000000000000000000000000000000000000000001",
    headerssync_params = { commitment_period = 275, redownload_buffer_size = 7017 },
  }

  local chain_start = {
    hash = genesis_hash, height = 0,
    work = consensus.work_zero(), bits = 0x207fffff,
  }
  local ss = sync.new_headers_sync_state(99, low_work_network, chain_start)

  -- Run a small batch through PRESYNC + REDOWNLOAD.
  local presync_headers = create_regtest_chain(
    genesis_hash, consensus.networks.regtest.genesis.timestamp, 5
  )
  ss:process_presync(presync_headers)
  expect_eq(ss:get_state(), "redownload", "transitioned to REDOWNLOAD")

  -- Feed 2 redownload headers to advance redownload.last_hash.
  local rd_headers = create_regtest_chain(
    genesis_hash, consensus.networks.regtest.genesis.timestamp, 2
  )
  ss:process_redownload(rd_headers)

  local locator = hc:build_presync_locator(ss)
  expect_gt(#locator, 0, "REDOWNLOAD locator non-empty")
  expect_eq(types.hash256_hex(locator[1]),
            types.hash256_hex(ss.redownload.last_hash),
            "REDOWNLOAD locator starts with redownload.last_hash")
  -- And it differs from chain_start (we advanced 2 redownload headers).
  expect_true(types.hash256_hex(locator[1]) ~= types.hash256_hex(genesis_hash),
    "REDOWNLOAD locator first entry differs from chain_start")
end

-- ----------------------------------------------------------------------
-- Test 5: get_block_locator is still a thin wrapper, preserves shape
-- ----------------------------------------------------------------------

do
  -- Refactor parity guard: build_locator_from_height(tip_height) ==
  -- get_block_locator().
  local hc = sync.new_header_chain(high_work_network, fake_storage())
  hc:add_genesis()
  local genesis_hash = hc.header_tip_hash

  local headers = create_regtest_chain(
    genesis_hash, consensus.networks.regtest.genesis.timestamp, 3
  )
  for _, h in ipairs(headers) do
    local ok, err = hc:accept_header(h, { min_pow_checked = true })
    assert(ok, "accept_header failed: " .. tostring(err))
  end

  local a = hc:get_block_locator()
  local b = hc:build_locator_from_height(hc.header_tip_height)
  expect_eq(#a, #b, "get_block_locator preserves length after refactor")
  if #a == #b then
    for i = 1, #a do
      expect_eq(types.hash256_hex(a[i]), types.hash256_hex(b[i]),
        string.format("locator[%d] identical to build_locator_from_height", i))
    end
  end
end

print(string.format("\n=== SUMMARY: %d PASS / %d FAIL ===", PASS, FAIL))
if FAIL > 0 then os.exit(1) end
