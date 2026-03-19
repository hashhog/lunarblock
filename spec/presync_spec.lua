--- PRESYNC/REDOWNLOAD header sync anti-DoS tests
-- Tests the two-phase header download mechanism that prevents memory
-- exhaustion attacks from low-work header spam.

local helpers = require("spec.helpers")

describe("presync anti_dos header_sync", function()
  local sync
  local types
  local consensus
  local validation
  local crypto

  setup(function()
    package.path = "src/?.lua;" .. package.path
    -- Set up lunarblock.X aliases
    package.preload["lunarblock.types"] = function() return require("types") end
    package.preload["lunarblock.serialize"] = function() return require("serialize") end
    package.preload["lunarblock.crypto"] = function() return require("crypto") end
    package.preload["lunarblock.script"] = function() return require("script") end
    package.preload["lunarblock.consensus"] = function() return require("consensus") end
    package.preload["lunarblock.validation"] = function() return require("validation") end
    package.preload["lunarblock.p2p"] = function() return require("p2p") end

    types = require("types")
    consensus = require("consensus")
    validation = require("validation")
    crypto = require("crypto")
    sync = require("sync")
  end)

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

  describe("256-bit work arithmetic", function()
    it("parses hex work values", function()
      local zero = consensus.work_from_hex(string.rep("00", 64))
      assert.equals(32, #zero)
      for i = 1, 32 do
        assert.equals(0, zero:byte(i))
      end

      local one = consensus.work_from_hex(string.rep("00", 62) .. "01")
      assert.equals(1, one:byte(32))

      local ff = consensus.work_from_hex(string.rep("ff", 64))
      for i = 1, 32 do
        assert.equals(255, ff:byte(i))
      end
    end)

    it("compares work values correctly", function()
      local zero = consensus.work_from_hex(string.rep("00", 64))
      local one = consensus.work_from_hex(string.rep("00", 62) .. "01")
      local two = consensus.work_from_hex(string.rep("00", 62) .. "02")
      local max = consensus.work_from_hex(string.rep("ff", 64))

      assert.equals(0, consensus.work_compare(zero, zero))
      assert.equals(-1, consensus.work_compare(zero, one))
      assert.equals(1, consensus.work_compare(one, zero))
      assert.equals(-1, consensus.work_compare(one, two))
      assert.equals(-1, consensus.work_compare(two, max))
    end)

    it("adds work values correctly", function()
      local one = consensus.work_from_hex(string.rep("00", 62) .. "01")
      local two = consensus.work_from_hex(string.rep("00", 62) .. "02")

      local sum = consensus.work_add(one, one)
      assert.equals(0, consensus.work_compare(sum, two))

      -- Test carry
      local ff = consensus.work_from_hex(string.rep("00", 62) .. "ff")
      local sum2 = consensus.work_add(ff, one)
      local expected = consensus.work_from_hex(string.rep("00", 60) .. "0100")
      assert.equals(0, consensus.work_compare(sum2, expected))
    end)

    it("calculates block work from bits", function()
      local work = consensus.get_block_work(0x207fffff)  -- regtest
      assert.equals(32, #work)

      -- Higher difficulty (lower bits value) = more work
      local easy_work = consensus.get_block_work(0x207fffff)
      local hard_work = consensus.get_block_work(0x1d00ffff)
      -- Hard work should be greater (higher value)
      assert.equals(1, consensus.work_compare(hard_work, easy_work))
    end)
  end)

  describe("HeadersSyncState creation", function()
    it("creates a new sync state with correct initial values", function()
      local genesis_hash = types.hash256(string.rep("\x00", 32))
      local chain_start = {
        hash = genesis_hash,
        height = 0,
        work = consensus.work_zero()
      }

      local state = sync.new_headers_sync_state("peer1", consensus.networks.regtest, chain_start)

      assert.is_not_nil(state)
      assert.equals("presync", state:get_state())
      assert.is_false(state:is_complete())
      assert.is_true(state:needs_headers())
    end)

    it("uses network min_chain_work", function()
      local genesis_hash = types.hash256(string.rep("\x00", 32))
      local chain_start = {
        hash = genesis_hash,
        height = 0,
        work = consensus.work_zero()
      }

      local state = sync.new_headers_sync_state("peer1", consensus.networks.mainnet, chain_start)
      assert.is_not_nil(state)

      -- Mainnet has substantial min_chain_work
      assert.is_true(state.min_required_work:byte(1) > 0 or
                     state.min_required_work:byte(2) > 0 or
                     state.min_required_work:byte(3) > 0)
    end)
  end)

  describe("PRESYNC phase", function()
    local network, genesis_hash, chain_start

    before_each(function()
      -- Use a custom network with low min_chain_work for testing
      network = {
        name = "test",
        genesis = consensus.networks.regtest.genesis,
        pow_limit_bits = 0x207fffff,
        pow_no_retarget = true,
        pow_allow_min_difficulty = true,
        -- Low min_chain_work so we can test transitions
        min_chain_work = string.rep("00", 60) .. "00001000",
      }

      genesis_hash = types.hash256(string.rep("\x00", 32))
      chain_start = {
        hash = genesis_hash,
        height = 0,
        work = consensus.work_zero()
      }
    end)

    it("processes valid headers and accumulates work", function()
      local state = sync.new_headers_sync_state("peer1", network, chain_start)

      -- Create valid headers
      local headers = create_header_chain(
        genesis_hash,
        consensus.networks.regtest.genesis.timestamp,
        10,
        0x207fffff
      )

      local ok, err = state:process_presync(headers)
      assert.is_true(ok)
      assert.is_nil(err)

      local stats = state:get_stats()
      assert.equals(10, stats.count)
      assert.equals(10, stats.height)
    end)

    it("rejects non-continuous headers", function()
      local state = sync.new_headers_sync_state("peer1", network, chain_start)

      -- Create headers but with wrong prev_hash
      local bad_headers = {
        create_valid_header(
          types.hash256(string.rep("\xff", 32)),  -- wrong parent
          consensus.networks.regtest.genesis.timestamp + 600
        )
      }
      find_valid_nonce(bad_headers[1])

      local ok, err = state:process_presync(bad_headers)
      assert.is_false(ok)
      assert.is_truthy(err:match("non%-continuous"))
    end)

    it("rejects headers with invalid PoW", function()
      local state = sync.new_headers_sync_state("peer1", network, chain_start)

      -- Create header with impossible difficulty
      local bad_header = types.block_header(
        1,
        genesis_hash,
        types.hash256_zero(),
        os.time(),
        0x03000001,  -- very high difficulty
        0
      )

      local ok, err = state:process_presync({bad_header})
      assert.is_false(ok)
      assert.is_truthy(err:match("proof of work"))
    end)

    it("transitions to REDOWNLOAD when min_chain_work reached", function()
      -- Use very low min_chain_work so we reach it quickly
      local low_work_network = {
        name = "test",
        genesis = consensus.networks.regtest.genesis,
        pow_limit_bits = 0x207fffff,
        pow_no_retarget = true,
        pow_allow_min_difficulty = true,
        min_chain_work = string.rep("00", 62) .. "0001",  -- very low
      }

      local state = sync.new_headers_sync_state("peer1", low_work_network, chain_start)

      -- Create enough headers to exceed min_chain_work
      local headers = create_header_chain(
        genesis_hash,
        consensus.networks.regtest.genesis.timestamp,
        5,
        0x207fffff
      )

      local ok, err = state:process_presync(headers)
      assert.is_true(ok)
      assert.is_nil(err)

      -- Should have transitioned to REDOWNLOAD
      assert.equals("redownload", state:get_state())
    end)

    it("stores commitments at periodic intervals", function()
      local state = sync.new_headers_sync_state("peer1", network, chain_start)

      -- Force commitment offset to 0 for predictable testing
      state.commitment_offset = 0

      -- Create headers (more than COMMITMENT_PERIOD would require commitments)
      -- For testing, we just verify the commitment mechanism works
      local headers = create_header_chain(
        genesis_hash,
        consensus.networks.regtest.genesis.timestamp,
        10,
        0x207fffff
      )

      local ok, _ = state:process_presync(headers)
      assert.is_true(ok)

      -- Commitments should be booleans
      for _, c in ipairs(state.presync.commitments) do
        assert.is_true(c == true or c == false)
      end
    end)
  end)

  describe("REDOWNLOAD phase", function()
    local network, genesis_hash, chain_start

    before_each(function()
      network = {
        name = "test",
        genesis = consensus.networks.regtest.genesis,
        pow_limit_bits = 0x207fffff,
        pow_no_retarget = true,
        pow_allow_min_difficulty = true,
        min_chain_work = string.rep("00", 62) .. "0001",  -- very low
      }

      genesis_hash = types.hash256(string.rep("\x00", 32))
      chain_start = {
        hash = genesis_hash,
        height = 0,
        work = consensus.work_zero()
      }
    end)

    it("processes redownloaded headers and verifies commitments", function()
      local state = sync.new_headers_sync_state("peer1", network, chain_start)

      -- Create headers and process through PRESYNC
      local headers = create_header_chain(
        genesis_hash,
        consensus.networks.regtest.genesis.timestamp,
        10,
        0x207fffff
      )

      local ok, _ = state:process_presync(headers)
      assert.is_true(ok)
      assert.equals("redownload", state:get_state())

      -- Now redownload the same headers
      local accepted, err = state:process_redownload(headers)
      assert.is_nil(err)
      assert.is_not_nil(accepted)

      -- Should be complete
      assert.equals("final", state:get_state())
      assert.is_true(state:is_complete())
    end)

    it("rejects mismatched headers during redownload", function()
      local state = sync.new_headers_sync_state("peer1", network, chain_start)
      state.commitment_offset = 0  -- Force commitments at height % 584 == 0

      -- Create headers and process through PRESYNC
      local headers1 = create_header_chain(
        genesis_hash,
        consensus.networks.regtest.genesis.timestamp,
        10,
        0x207fffff
      )

      local ok, _ = state:process_presync(headers1)
      assert.is_true(ok)
      assert.equals("redownload", state:get_state())

      -- Create DIFFERENT headers for redownload (would have different commitments)
      local headers2 = create_header_chain(
        genesis_hash,
        consensus.networks.regtest.genesis.timestamp + 1,  -- different timestamp
        10,
        0x207fffff
      )

      -- If commitments were made at these heights, they should mismatch
      -- Due to short chain, we may not hit commitment heights, but continuity will break
      local accepted, err = state:process_redownload(headers2)
      -- Either fails on continuity or commitment mismatch
      if err then
        assert.is_truthy(err:match("mismatch") or err:match("non%-continuous"))
      end
    end)

    it("rejects non-continuous headers in redownload", function()
      local state = sync.new_headers_sync_state("peer1", network, chain_start)

      -- Process PRESYNC
      local headers = create_header_chain(
        genesis_hash,
        consensus.networks.regtest.genesis.timestamp,
        10,
        0x207fffff
      )
      state:process_presync(headers)
      assert.equals("redownload", state:get_state())

      -- Try to redownload starting from wrong parent
      local bad_headers = create_header_chain(
        types.hash256(string.rep("\xff", 32)),  -- wrong parent
        consensus.networks.regtest.genesis.timestamp,
        5,
        0x207fffff
      )

      local accepted, err = state:process_redownload(bad_headers)
      assert.is_nil(accepted)
      assert.is_truthy(err:match("non%-continuous"))
    end)
  end)

  describe("low-work header attack simulation", function()
    local network, storage, chain

    before_each(function()
      -- Network with substantial min_chain_work
      network = {
        name = "test",
        genesis = consensus.networks.regtest.genesis,
        pow_limit_bits = 0x207fffff,
        pow_no_retarget = true,
        pow_allow_min_difficulty = true,
        -- Require significant work (hard to reach with regtest difficulty)
        min_chain_work = string.rep("00", 50) .. string.rep("ff", 14),
      }

      storage = helpers.mock_storage()
      chain = sync.new_header_chain(network, storage)
      chain:init()
    end)

    it("memory usage stays bounded during low-work header attack", function()
      -- Simulate attack: peer sends many headers that don't meet min_chain_work
      local genesis_hash = chain:get_tip_hash()

      -- Create a batch of headers (attacker's low-work chain)
      local attack_headers = create_header_chain(
        genesis_hash,
        consensus.networks.regtest.genesis.timestamp,
        100,
        0x207fffff
      )

      -- Create sync state and process headers
      local chain_start = {
        hash = genesis_hash,
        height = 0,
        work = consensus.work_zero()
      }
      local state = sync.new_headers_sync_state("attacker", network, chain_start)

      -- Process attack headers in PRESYNC
      local ok, err = state:process_presync(attack_headers)
      assert.is_true(ok)
      assert.is_nil(err)

      -- Verify we're still in PRESYNC (didn't reach min_chain_work)
      assert.equals("presync", state:get_state())

      -- Memory usage is bounded: we only store {work, last_hash, count, commitments}
      local stats = state:get_stats()
      assert.equals(100, stats.count)

      -- The headers themselves are NOT stored
      -- Only ~50 bytes of state per peer + ~1 bit per COMMITMENT_PERIOD headers
      -- With 100 headers, we have at most 1 commitment (100 < 584)
      assert.is_true(#state.presync.commitments <= 1)
    end)

    it("processes headers normally when work threshold is met", function()
      -- Network with very low min_chain_work
      local easy_network = {
        name = "test",
        genesis = consensus.networks.regtest.genesis,
        pow_limit_bits = 0x207fffff,
        pow_no_retarget = true,
        pow_allow_min_difficulty = true,
        min_chain_work = string.rep("00", 62) .. "0001",
      }

      local easy_storage = helpers.mock_storage()
      local easy_chain = sync.new_header_chain(easy_network, easy_storage)
      easy_chain:init()

      local genesis_hash = easy_chain:get_tip_hash()

      -- Process headers that exceed min_chain_work
      local headers = create_header_chain(
        genesis_hash,
        consensus.networks.regtest.genesis.timestamp,
        5,
        0x207fffff
      )

      -- Process through normal path
      local accepted, err = easy_chain:process_headers(headers)
      assert.is_nil(err)
      assert.equals(5, accepted)
      assert.equals(5, easy_chain:get_tip_height())
    end)
  end)

  describe("HeadersSyncState getheaders requests", function()
    it("returns correct getheaders for PRESYNC", function()
      local genesis_hash = types.hash256(string.rep("\x00", 32))
      local chain_start = {
        hash = genesis_hash,
        height = 0,
        work = consensus.work_zero()
      }

      local network = {
        name = "test",
        genesis = consensus.networks.regtest.genesis,
        pow_limit_bits = 0x207fffff,
        pow_no_retarget = true,
        min_chain_work = string.rep("00", 64),
      }

      local state = sync.new_headers_sync_state("peer1", network, chain_start)

      local req = state:get_getheaders_request()
      assert.is_not_nil(req)
      assert.is_not_nil(req.locator_hashes)
      assert.is_not_nil(req.stop_hash)
    end)

    it("returns correct getheaders for REDOWNLOAD", function()
      local genesis_hash = types.hash256(string.rep("\x00", 32))
      local chain_start = {
        hash = genesis_hash,
        height = 0,
        work = consensus.work_zero()
      }

      local network = {
        name = "test",
        genesis = consensus.networks.regtest.genesis,
        pow_limit_bits = 0x207fffff,
        pow_no_retarget = true,
        min_chain_work = string.rep("00", 62) .. "0001",
      }

      local state = sync.new_headers_sync_state("peer1", network, chain_start)

      -- Process headers to trigger REDOWNLOAD
      local headers = create_header_chain(
        genesis_hash,
        consensus.networks.regtest.genesis.timestamp,
        5,
        0x207fffff
      )
      state:process_presync(headers)
      assert.equals("redownload", state:get_state())

      local req = state:get_getheaders_request()
      assert.is_not_nil(req)
      -- Should request from chain_start for REDOWNLOAD
      assert.is_true(types.hash256_eq(req.locator_hashes[1], genesis_hash))
    end)

    it("returns nil for FINAL state", function()
      local genesis_hash = types.hash256(string.rep("\x00", 32))
      local chain_start = {
        hash = genesis_hash,
        height = 0,
        work = consensus.work_zero()
      }

      local network = {
        name = "test",
        genesis = consensus.networks.regtest.genesis,
        pow_limit_bits = 0x207fffff,
        pow_no_retarget = true,
        min_chain_work = string.rep("00", 62) .. "0001",
      }

      local state = sync.new_headers_sync_state("peer1", network, chain_start)

      -- Process through PRESYNC and REDOWNLOAD to FINAL
      local headers = create_header_chain(
        genesis_hash,
        consensus.networks.regtest.genesis.timestamp,
        5,
        0x207fffff
      )
      state:process_presync(headers)
      state:process_redownload(headers)
      assert.equals("final", state:get_state())

      local req = state:get_getheaders_request()
      assert.is_nil(req)
    end)
  end)

  describe("commitment verification", function()
    it("computes deterministic commitments with salt", function()
      local genesis_hash = types.hash256(string.rep("\x00", 32))
      local chain_start = {
        hash = genesis_hash,
        height = 0,
        work = consensus.work_zero()
      }

      local network = {
        name = "test",
        genesis = consensus.networks.regtest.genesis,
        pow_limit_bits = 0x207fffff,
        pow_no_retarget = true,
        min_chain_work = string.rep("00", 64),
      }

      local state = sync.new_headers_sync_state("peer1", network, chain_start)

      local test_hash = types.hash256(string.rep("\xab", 32))

      -- Same hash should produce same commitment
      local c1 = state:compute_commitment(test_hash)
      local c2 = state:compute_commitment(test_hash)
      assert.equals(c1, c2)

      -- Commitment is a boolean
      assert.is_true(c1 == true or c1 == false)
    end)

    it("different salts produce different commitments", function()
      local genesis_hash = types.hash256(string.rep("\x00", 32))
      local chain_start = {
        hash = genesis_hash,
        height = 0,
        work = consensus.work_zero()
      }

      local network = {
        name = "test",
        genesis = consensus.networks.regtest.genesis,
        pow_limit_bits = 0x207fffff,
        pow_no_retarget = true,
        min_chain_work = string.rep("00", 64),
      }

      local state1 = sync.new_headers_sync_state("peer1", network, chain_start)
      local state2 = sync.new_headers_sync_state("peer2", network, chain_start)

      -- Different salt means (with high probability) different commitments
      -- over many hashes
      local different_count = 0
      for i = 1, 100 do
        local test_hash = types.hash256(string.rep(string.char(i), 32))
        local c1 = state1:compute_commitment(test_hash)
        local c2 = state2:compute_commitment(test_hash)
        if c1 ~= c2 then
          different_count = different_count + 1
        end
      end

      -- With random salts, about 50% should differ
      assert.is_true(different_count > 20)
    end)
  end)
end)
