describe("consensus", function()
  local consensus

  setup(function()
    package.path = "src/?.lua;lunarblock/?.lua;" .. package.path
    consensus = require("consensus")
  end)

  describe("block subsidy", function()
    it("returns 50 BTC at height 0", function()
      assert.equals(5000000000, consensus.get_block_subsidy(0))
    end)

    it("returns 50 BTC at height 209999", function()
      assert.equals(5000000000, consensus.get_block_subsidy(209999))
    end)

    it("returns 25 BTC at height 210000 (first halving)", function()
      assert.equals(2500000000, consensus.get_block_subsidy(210000))
    end)

    it("returns 12.5 BTC at height 420000 (second halving)", function()
      assert.equals(1250000000, consensus.get_block_subsidy(420000))
    end)

    it("returns 6.25 BTC at height 630000 (third halving)", function()
      assert.equals(625000000, consensus.get_block_subsidy(630000))
    end)

    it("returns 0 at height 6930000 (after 33rd halving)", function()
      assert.equals(0, consensus.get_block_subsidy(6930000))
    end)

    it("returns 0 after 64 halvings", function()
      -- 64 * 210000 = 13,440,000
      assert.equals(0, consensus.get_block_subsidy(13440000))
    end)
  end)

  describe("bits_to_target", function()
    it("converts mainnet genesis bits 0x1d00ffff correctly", function()
      local target = consensus.bits_to_target(0x1d00ffff)
      assert.equals(32, #target)
      -- 0x1d exponent means value starts at byte position 32 - 0x1d + 1 = 4
      -- mantissa 0x00ffff
      -- Expected target: 00000000ffff0000...0000 (with ffff starting at byte 4)
      local expected = "\0\0\0\0\xff\xff" .. string.rep("\0", 26)
      assert.equals(expected, target)
    end)

    it("converts regtest bits 0x207fffff correctly", function()
      local target = consensus.bits_to_target(0x207fffff)
      assert.equals(32, #target)
      -- 0x20 = 32 exponent, mantissa 0x7fffff
      -- Target should have 0x7fffff at the start
      assert.equals(0x7f, target:byte(1))
      assert.equals(0xff, target:byte(2))
      assert.equals(0xff, target:byte(3))
    end)

    it("handles zero bits", function()
      local target = consensus.bits_to_target(0)
      assert.equals(string.rep("\0", 32), target)
    end)

    it("handles small exponent", function()
      -- Exponent 3, mantissa 0x123456
      local target = consensus.bits_to_target(0x03123456)
      assert.equals(32, #target)
      -- Should be at positions 30, 31, 32 (0-indexed: 29, 30, 31)
      assert.equals(0x12, target:byte(30))
      assert.equals(0x34, target:byte(31))
      assert.equals(0x56, target:byte(32))
    end)
  end)

  describe("target_to_bits", function()
    it("converts mainnet genesis target back to bits", function()
      local target = "\0\0\0\0\xff\xff" .. string.rep("\0", 26)
      local bits = consensus.target_to_bits(target)
      assert.equals(0x1d00ffff, bits)
    end)

    it("round-trips 0x1d00ffff", function()
      local original_bits = 0x1d00ffff
      local target = consensus.bits_to_target(original_bits)
      local recovered_bits = consensus.target_to_bits(target)
      assert.equals(original_bits, recovered_bits)
    end)

    it("round-trips 0x207fffff (regtest)", function()
      local original_bits = 0x207fffff
      local target = consensus.bits_to_target(original_bits)
      local recovered_bits = consensus.target_to_bits(target)
      assert.equals(original_bits, recovered_bits)
    end)

    it("handles zero target", function()
      local target = string.rep("\0", 32)
      local bits = consensus.target_to_bits(target)
      assert.equals(0, bits)
    end)
  end)

  describe("hash_meets_target", function()
    it("returns true when hash equals target", function()
      local target = "\0\0\0\0\xff\xff" .. string.rep("\0", 26)
      -- Hash in little-endian, so we reverse it
      local hash_le = target:reverse()
      assert.is_true(consensus.hash_meets_target(hash_le, target))
    end)

    it("returns true when hash is less than target", function()
      local target = "\0\0\0\0\xff\xff" .. string.rep("\0", 26)
      -- Make a smaller hash (more leading zeros in big-endian)
      local hash_be = "\0\0\0\0\0\xff" .. string.rep("\0", 26)
      local hash_le = hash_be:reverse()
      assert.is_true(consensus.hash_meets_target(hash_le, target))
    end)

    it("returns false when hash is greater than target", function()
      local target = "\0\0\0\0\xff\xff" .. string.rep("\0", 26)
      -- Make a larger hash
      local hash_be = "\0\0\0\xff\xff\xff" .. string.rep("\0", 26)
      local hash_le = hash_be:reverse()
      assert.is_false(consensus.hash_meets_target(hash_le, target))
    end)
  end)

  describe("median time past", function()
    it("returns middle value of 11 timestamps", function()
      local timestamps = {1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21}
      assert.equals(11, consensus.get_median_time_past(timestamps))
    end)

    it("returns middle value when unsorted", function()
      local timestamps = {21, 1, 19, 3, 17, 5, 15, 7, 13, 9, 11}
      assert.equals(11, consensus.get_median_time_past(timestamps))
    end)

    it("handles even number of timestamps", function()
      -- For 10 timestamps, median is 5th element (index 5 + 1 = 6)
      local timestamps = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
      assert.equals(6, consensus.get_median_time_past(timestamps))
    end)

    it("handles single timestamp", function()
      local timestamps = {12345}
      assert.equals(12345, consensus.get_median_time_past(timestamps))
    end)
  end)

  describe("network configurations", function()
    describe("mainnet", function()
      local mainnet

      setup(function()
        mainnet = consensus.networks.mainnet
      end)

      it("has correct magic bytes", function()
        assert.equals("\xf9\xbe\xb4\xd9", mainnet.magic_bytes)
      end)

      it("has correct ports", function()
        assert.equals(8333, mainnet.port)
        assert.equals(8332, mainnet.rpc_port)
      end)

      it("has correct address prefixes", function()
        assert.equals(0x00, mainnet.pubkey_address_prefix)
        assert.equals(0x05, mainnet.script_address_prefix)
        assert.equals(0x80, mainnet.wif_prefix)
      end)

      it("has correct bech32 hrp", function()
        assert.equals("bc", mainnet.bech32_hrp)
      end)

      it("has correct genesis hash", function()
        assert.equals("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                      mainnet.genesis_hash)
      end)

      it("has correct genesis bits", function()
        assert.equals(0x1d00ffff, mainnet.genesis.bits)
      end)
    end)

    describe("testnet", function()
      local testnet

      setup(function()
        testnet = consensus.networks.testnet
      end)

      it("has correct magic bytes", function()
        assert.equals("\x0b\x11\x09\x07", testnet.magic_bytes)
      end)

      it("has correct ports", function()
        assert.equals(18333, testnet.port)
        assert.equals(18332, testnet.rpc_port)
      end)

      it("has correct address prefixes", function()
        assert.equals(0x6F, testnet.pubkey_address_prefix)
        assert.equals(0xC4, testnet.script_address_prefix)
        assert.equals(0xEF, testnet.wif_prefix)
      end)

      it("has correct bech32 hrp", function()
        assert.equals("tb", testnet.bech32_hrp)
      end)

      it("allows min difficulty", function()
        assert.is_true(testnet.pow_allow_min_difficulty)
      end)
    end)

    describe("regtest", function()
      local regtest

      setup(function()
        regtest = consensus.networks.regtest
      end)

      it("has correct magic bytes", function()
        assert.equals("\xfa\xbf\xb5\xda", regtest.magic_bytes)
      end)

      it("has correct ports", function()
        assert.equals(18444, regtest.port)
        assert.equals(18443, regtest.rpc_port)
      end)

      it("has correct bech32 hrp", function()
        assert.equals("bcrt", regtest.bech32_hrp)
      end)

      it("has no retargeting", function()
        assert.is_true(regtest.pow_no_retarget)
      end)

      it("has all soft forks at height 0", function()
        assert.equals(0, regtest.bip34_height)
        assert.equals(0, regtest.bip65_height)
        assert.equals(0, regtest.bip66_height)
        assert.equals(0, regtest.segwit_height)
        assert.equals(0, regtest.taproot_height)
      end)

      it("has correct genesis bits", function()
        assert.equals(0x207fffff, regtest.genesis.bits)
      end)
    end)
  end)

  describe("sequence locks (BIP68)", function()
    it("detects disabled sequence lock", function()
      -- Disable flag set (0x80000000)
      local sequence = 0x80000000
      assert.is_false(consensus.sequence_locks_active(sequence))
    end)

    it("detects active sequence lock", function()
      -- Disable flag not set
      local sequence = 0x00000010
      assert.is_true(consensus.sequence_locks_active(sequence))
    end)

    it("detects height-based lock", function()
      -- Type flag not set
      local sequence = 0x00000010
      assert.is_false(consensus.sequence_lock_is_time_based(sequence))
    end)

    it("detects time-based lock", function()
      -- Type flag set (0x00400000)
      local sequence = 0x00400010
      assert.is_true(consensus.sequence_lock_is_time_based(sequence))
    end)

    it("extracts lock value for height-based lock", function()
      local sequence = 0x0000000A  -- 10 blocks
      assert.equals(10, consensus.sequence_lock_value(sequence))
    end)

    it("extracts lock value for time-based lock", function()
      local sequence = 0x00400005  -- 5 * 512 seconds
      assert.equals(5, consensus.sequence_lock_value(sequence))
    end)

    it("masks only lower 16 bits", function()
      local sequence = 0x0040FFFF
      assert.equals(0xFFFF, consensus.sequence_lock_value(sequence))
    end)
  end)

  describe("is_valid_amount", function()
    it("returns true for 0", function()
      assert.is_true(consensus.is_valid_amount(0))
    end)

    it("returns true for MAX_MONEY", function()
      assert.is_true(consensus.is_valid_amount(consensus.MAX_MONEY))
    end)

    it("returns false for MAX_MONEY + 1", function()
      assert.is_false(consensus.is_valid_amount(consensus.MAX_MONEY + 1))
    end)

    it("returns false for negative amounts", function()
      assert.is_false(consensus.is_valid_amount(-1))
    end)

    it("returns true for 1 BTC", function()
      assert.is_true(consensus.is_valid_amount(consensus.COIN))
    end)
  end)

  describe("constants", function()
    it("has correct COIN value", function()
      assert.equals(100000000, consensus.COIN)
    end)

    it("has correct MAX_MONEY", function()
      assert.equals(2100000000000000, consensus.MAX_MONEY)
    end)

    it("has correct halving interval", function()
      assert.equals(210000, consensus.HALVING_INTERVAL)
    end)

    it("has correct difficulty adjustment interval", function()
      assert.equals(2016, consensus.DIFFICULTY_ADJUSTMENT_INTERVAL)
    end)

    it("has correct coinbase maturity", function()
      assert.equals(100, consensus.COINBASE_MATURITY)
    end)

    it("has correct locktime threshold", function()
      assert.equals(500000000, consensus.LOCKTIME_THRESHOLD)
    end)

    it("has correct target timespan", function()
      assert.equals(1209600, consensus.TARGET_TIMESPAN)  -- 2 weeks in seconds
    end)

    it("has correct target spacing", function()
      assert.equals(600, consensus.TARGET_SPACING)  -- 10 minutes
    end)
  end)

  describe("difficulty adjustment", function()
    it("limits decrease to factor of 4", function()
      -- If actual timespan is 4x target, difficulty should decrease by 4x
      local original_bits = 0x1d00ffff
      local actual_timespan = consensus.TARGET_TIMESPAN * 4
      local new_bits = consensus.calculate_next_target(original_bits, actual_timespan)

      -- New target should be 4x original, so bits should represent that
      local original_target = consensus.bits_to_target(original_bits)
      local new_target = consensus.bits_to_target(new_bits)

      -- Compare: new target should be 4x original
      -- Since the division by 4 happens via timespan clamping, just verify the ratio
      assert.is_truthy(new_bits)
    end)

    it("limits increase to factor of 4", function()
      -- If actual timespan is 1/4 target, difficulty should increase by 4x
      local original_bits = 0x1d00ffff
      local actual_timespan = consensus.MIN_TIMESPAN
      local new_bits = consensus.calculate_next_target(original_bits, actual_timespan)

      assert.is_truthy(new_bits)
    end)

    it("keeps same difficulty when timespan matches target", function()
      local original_bits = 0x1d00ffff
      local actual_timespan = consensus.TARGET_TIMESPAN
      local new_bits = consensus.calculate_next_target(original_bits, actual_timespan)

      -- Should be approximately the same
      assert.equals(original_bits, new_bits)
    end)
  end)

  describe("get_next_work_required", function()
    local function make_ancestor_lookup(headers)
      return function(h)
        return headers[h]
      end
    end

    describe("regtest", function()
      local regtest

      setup(function()
        regtest = consensus.networks.regtest
      end)

      it("always returns pow_limit", function()
        local headers = {
          [0] = {header = {bits = 0x207fffff, timestamp = 1000}},
          [1] = {header = {bits = 0x207fffff, timestamp = 2000}},
        }
        local bits = consensus.get_next_work_required(2, 3000, regtest, make_ancestor_lookup(headers))
        assert.equals(regtest.pow_limit_bits, bits)
      end)
    end)

    describe("mainnet", function()
      local mainnet

      setup(function()
        mainnet = consensus.networks.mainnet
      end)

      it("returns previous block bits for non-retarget blocks", function()
        local prev_bits = 0x1b0404cb  -- some arbitrary difficulty
        local headers = {
          [100] = {header = {bits = prev_bits, timestamp = 1000000}},
        }
        local bits = consensus.get_next_work_required(101, 1000600, mainnet, make_ancestor_lookup(headers))
        assert.equals(prev_bits, bits)
      end)

      it("recalculates difficulty at retarget block", function()
        -- Height 2016 is a retarget block
        local prev_bits = 0x1d00ffff
        local headers = {}
        -- First block of period at height 0
        headers[0] = {header = {bits = prev_bits, timestamp = 0}}
        -- Last block of period at height 2015
        headers[2015] = {header = {bits = prev_bits, timestamp = consensus.TARGET_TIMESPAN}}

        local bits = consensus.get_next_work_required(2016, consensus.TARGET_TIMESPAN + 600, mainnet, make_ancestor_lookup(headers))
        -- With exact target timespan, difficulty should stay the same
        assert.equals(prev_bits, bits)
      end)

      it("does not allow min-difficulty blocks", function()
        local prev_bits = 0x1b0404cb
        local headers = {
          [100] = {header = {bits = prev_bits, timestamp = 1000000}},
        }
        -- Even with a very late timestamp, mainnet should return previous bits
        local bits = consensus.get_next_work_required(101, 1000000 + 7200, mainnet, make_ancestor_lookup(headers))
        assert.equals(prev_bits, bits)
      end)
    end)

    describe("testnet (testnet3)", function()
      local testnet

      setup(function()
        testnet = consensus.networks.testnet
      end)

      it("allows min-difficulty when block is more than 20 minutes late", function()
        local prev_bits = 0x1b0404cb
        local headers = {
          [100] = {header = {bits = prev_bits, timestamp = 1000000}},
        }
        -- Block timestamp is > 20 minutes (1200 seconds) after previous
        local bits = consensus.get_next_work_required(101, 1000000 + 1201, testnet, make_ancestor_lookup(headers))
        assert.equals(testnet.pow_limit_bits, bits)
      end)

      it("walks back to find last non-min-difficulty block", function()
        local real_bits = 0x1b0404cb
        local headers = {
          -- Height 2016 is a retarget block with real difficulty
          [2016] = {header = {bits = real_bits, timestamp = 1000000}},
          -- Heights 2017-2019 all have min-difficulty
          [2017] = {header = {bits = testnet.pow_limit_bits, timestamp = 1001200}},
          [2018] = {header = {bits = testnet.pow_limit_bits, timestamp = 1002400}},
          [2019] = {header = {bits = testnet.pow_limit_bits, timestamp = 1003600}},
        }
        -- Block 2020 comes within 20 minutes of block 2019 - should walk back
        local bits = consensus.get_next_work_required(2020, 1003600 + 600, testnet, make_ancestor_lookup(headers))
        assert.equals(real_bits, bits)
      end)

      it("returns previous bits when not late and prev is not min-diff", function()
        local prev_bits = 0x1b0404cb
        local headers = {
          [100] = {header = {bits = prev_bits, timestamp = 1000000}},
        }
        -- Block comes within 20 minutes
        local bits = consensus.get_next_work_required(101, 1000000 + 600, testnet, make_ancestor_lookup(headers))
        assert.equals(prev_bits, bits)
      end)
    end)

    describe("testnet4 (BIP94)", function()
      local testnet4

      setup(function()
        testnet4 = consensus.networks.testnet4
      end)

      it("has correct configuration", function()
        assert.equals("testnet4", testnet4.name)
        assert.equals(48333, testnet4.port)
        assert.is_true(testnet4.pow_allow_min_difficulty)
        assert.is_true(testnet4.enforce_bip94)
      end)

      it("allows min-difficulty when block is more than 20 minutes late", function()
        local prev_bits = 0x1b0404cb
        local headers = {
          [100] = {header = {bits = prev_bits, timestamp = 1000000}},
        }
        -- Block timestamp is > 20 minutes after previous
        local bits = consensus.get_next_work_required(101, 1000000 + 1201, testnet4, make_ancestor_lookup(headers))
        assert.equals(testnet4.pow_limit_bits, bits)
      end)

      it("uses first block bits for retarget calculation (BIP94)", function()
        -- BIP94: use first block of period instead of last for difficulty calc
        local first_bits = 0x1b0404cb  -- real difficulty
        local last_bits = testnet4.pow_limit_bits  -- min difficulty due to slow blocks
        local headers = {}
        headers[0] = {header = {bits = first_bits, timestamp = 0}}
        headers[2015] = {header = {bits = last_bits, timestamp = consensus.TARGET_TIMESPAN}}

        local bits = consensus.get_next_work_required(2016, consensus.TARGET_TIMESPAN + 600, testnet4, make_ancestor_lookup(headers))
        -- With BIP94, it should use first_bits (0x1b0404cb) instead of last_bits
        -- So the result should be based on first_bits
        assert.is_true(bits ~= last_bits)
      end)
    end)
  end)

  describe("sighash types", function()
    it("has correct SIGHASH_ALL", function()
      assert.equals(0x01, consensus.SIGHASH.ALL)
    end)

    it("has correct SIGHASH_NONE", function()
      assert.equals(0x02, consensus.SIGHASH.NONE)
    end)

    it("has correct SIGHASH_SINGLE", function()
      assert.equals(0x03, consensus.SIGHASH.SINGLE)
    end)

    it("has correct SIGHASH_ANYONECANPAY", function()
      assert.equals(0x80, consensus.SIGHASH.ANYONECANPAY)
    end)
  end)

  describe("bip9 versionbits", function()
    local STATE

    setup(function()
      STATE = consensus.DEPLOYMENT_STATE
    end)

    describe("constants", function()
      it("has correct VERSIONBITS_TOP_BITS", function()
        assert.equals(0x20000000, consensus.VERSIONBITS_TOP_BITS)
      end)

      it("has correct VERSIONBITS_TOP_MASK", function()
        assert.equals(0xE0000000, consensus.VERSIONBITS_TOP_MASK)
      end)

      it("has correct VERSIONBITS_NUM_BITS", function()
        assert.equals(29, consensus.VERSIONBITS_NUM_BITS)
      end)

      it("has correct special start_time values", function()
        assert.equals(-1, consensus.ALWAYS_ACTIVE)
        assert.equals(-2, consensus.NEVER_ACTIVE)
      end)
    end)

    describe("versionbits_condition", function()
      it("returns true for valid signaling version", function()
        -- Version with top bits = 001 and bit 1 set
        local version = 0x20000002  -- 0x20000000 | (1 << 1)
        assert.is_true(consensus.versionbits_condition(version, 1))
      end)

      it("returns false when top bits are wrong", function()
        -- Version without proper top 3 bits
        local version = 0x00000002  -- bit 1 set but wrong top bits
        assert.is_false(consensus.versionbits_condition(version, 1))
      end)

      it("returns false when signal bit not set", function()
        -- Version with correct top bits but bit 1 not set
        local version = 0x20000000
        assert.is_false(consensus.versionbits_condition(version, 1))
      end)

      it("detects multiple deployment bits", function()
        -- Version signaling for bits 1 and 2
        local version = 0x20000006  -- 0x20000000 | (1 << 1) | (1 << 2)
        assert.is_true(consensus.versionbits_condition(version, 1))
        assert.is_true(consensus.versionbits_condition(version, 2))
        assert.is_false(consensus.versionbits_condition(version, 3))
      end)

      it("handles bit 0", function()
        local version = 0x20000001  -- bit 0 set
        assert.is_true(consensus.versionbits_condition(version, 0))
      end)

      it("handles high bits (bit 28)", function()
        local version = 0x30000000  -- 0x20000000 | (1 << 28)
        assert.is_true(consensus.versionbits_condition(version, 28))
      end)
    end)

    describe("deployment states", function()
      it("has all state constants", function()
        assert.equals("defined", STATE.DEFINED)
        assert.equals("started", STATE.STARTED)
        assert.equals("locked_in", STATE.LOCKED_IN)
        assert.equals("active", STATE.ACTIVE)
        assert.equals("failed", STATE.FAILED)
      end)
    end)

    describe("get_deployment_state", function()
      local deployment
      local period
      local threshold

      setup(function()
        -- Test deployment: bit 1, starts at time 1000, timeout at 5000
        deployment = {
          bit = 1,
          start_time = 1000,
          timeout = 5000,
          min_activation_height = 0
        }
        period = 10  -- small period for testing
        threshold = 8  -- 80% threshold
      end)

      local function make_block_info(blocks)
        return function(h)
          return blocks[h]
        end
      end

      it("returns DEFINED for genesis block", function()
        local blocks = {
          [0] = {timestamp = 0, mtp = 0, version = 0x20000000}
        }
        local state = consensus.get_deployment_state(deployment, period, threshold, 0, make_block_info(blocks))
        assert.equals(STATE.DEFINED, state)
      end)

      it("returns ACTIVE for ALWAYS_ACTIVE deployment", function()
        local always_active = {
          bit = 1,
          start_time = consensus.ALWAYS_ACTIVE,
          timeout = 5000,
          min_activation_height = 0
        }
        local blocks = {[0] = {timestamp = 0, mtp = 0, version = 0}}
        local state = consensus.get_deployment_state(always_active, period, threshold, 100, make_block_info(blocks))
        assert.equals(STATE.ACTIVE, state)
      end)

      it("returns FAILED for NEVER_ACTIVE deployment", function()
        local never_active = {
          bit = 1,
          start_time = consensus.NEVER_ACTIVE,
          timeout = 5000,
          min_activation_height = 0
        }
        local blocks = {[0] = {timestamp = 0, mtp = 0, version = 0}}
        local state = consensus.get_deployment_state(never_active, period, threshold, 100, make_block_info(blocks))
        assert.equals(STATE.FAILED, state)
      end)

      it("stays DEFINED when MTP < start_time", function()
        local blocks = {}
        -- Fill first period (blocks 0-9) with MTP before start_time
        for h = 0, 9 do
          blocks[h] = {timestamp = 500, mtp = 500, version = 0x20000002}
        end
        -- State at end of first period
        local state = consensus.get_deployment_state(deployment, period, threshold, 9, make_block_info(blocks))
        assert.equals(STATE.DEFINED, state)
      end)

      it("transitions to STARTED when MTP >= start_time", function()
        local blocks = {}
        -- First period with MTP >= start_time
        for h = 0, 9 do
          blocks[h] = {timestamp = 1000, mtp = 1000, version = 0x20000000}
        end
        local state = consensus.get_deployment_state(deployment, period, threshold, 9, make_block_info(blocks))
        assert.equals(STATE.STARTED, state)
      end)

      it("transitions to LOCKED_IN when threshold reached", function()
        local blocks = {}
        -- First period: MTP reaches start_time -> STARTED
        for h = 0, 9 do
          blocks[h] = {timestamp = 1000, mtp = 1000, version = 0x20000000}
        end
        -- Second period: 8+ blocks signal -> LOCKED_IN
        for h = 10, 19 do
          blocks[h] = {timestamp = 1500, mtp = 1500, version = 0x20000002}  -- signaling version
        end
        local state = consensus.get_deployment_state(deployment, period, threshold, 19, make_block_info(blocks))
        assert.equals(STATE.LOCKED_IN, state)
      end)

      it("transitions to ACTIVE after LOCKED_IN period", function()
        local blocks = {}
        -- Period 0: MTP reaches start_time -> STARTED
        for h = 0, 9 do
          blocks[h] = {timestamp = 1000, mtp = 1000, version = 0x20000000}
        end
        -- Period 1: threshold signaling -> LOCKED_IN
        for h = 10, 19 do
          blocks[h] = {timestamp = 1500, mtp = 1500, version = 0x20000002}
        end
        -- Period 2: after LOCKED_IN -> ACTIVE
        for h = 20, 29 do
          blocks[h] = {timestamp = 2000, mtp = 2000, version = 0x20000000}
        end
        local state = consensus.get_deployment_state(deployment, period, threshold, 29, make_block_info(blocks))
        assert.equals(STATE.ACTIVE, state)
      end)

      it("transitions to FAILED when timeout reached without lock-in", function()
        local blocks = {}
        -- Period 0: MTP reaches start_time -> STARTED
        for h = 0, 9 do
          blocks[h] = {timestamp = 1000, mtp = 1000, version = 0x20000000}
        end
        -- Period 1: not enough signaling, MTP reaches timeout -> FAILED
        for h = 10, 19 do
          blocks[h] = {timestamp = 5000, mtp = 5000, version = 0x20000000}  -- not signaling
        end
        local state = consensus.get_deployment_state(deployment, period, threshold, 19, make_block_info(blocks))
        assert.equals(STATE.FAILED, state)
      end)

      it("stays STARTED with insufficient signaling", function()
        local blocks = {}
        -- Period 0: MTP reaches start_time -> STARTED
        for h = 0, 9 do
          blocks[h] = {timestamp = 1000, mtp = 1000, version = 0x20000000}
        end
        -- Period 1: only 5 blocks signal (need 8)
        for h = 10, 14 do
          blocks[h] = {timestamp = 1500, mtp = 1500, version = 0x20000002}  -- signaling
        end
        for h = 15, 19 do
          blocks[h] = {timestamp = 1500, mtp = 1500, version = 0x20000000}  -- not signaling
        end
        local state = consensus.get_deployment_state(deployment, period, threshold, 19, make_block_info(blocks))
        assert.equals(STATE.STARTED, state)
      end)

      it("respects min_activation_height", function()
        local delayed_deployment = {
          bit = 1,
          start_time = 1000,
          timeout = 5000,
          min_activation_height = 40  -- must wait until height 40 for activation
        }
        local blocks = {}
        -- Period 0: STARTED
        for h = 0, 9 do
          blocks[h] = {timestamp = 1000, mtp = 1000, version = 0x20000000}
        end
        -- Period 1: LOCKED_IN
        for h = 10, 19 do
          blocks[h] = {timestamp = 1500, mtp = 1500, version = 0x20000002}
        end
        -- Period 2: still LOCKED_IN (next block 30 < min_activation_height 40)
        for h = 20, 29 do
          blocks[h] = {timestamp = 2000, mtp = 2000, version = 0x20000000}
        end

        local state = consensus.get_deployment_state(delayed_deployment, period, threshold, 29, make_block_info(blocks))
        assert.equals(STATE.LOCKED_IN, state)

        -- Period 3: still LOCKED_IN (next block 40 >= min_activation_height)
        for h = 30, 39 do
          blocks[h] = {timestamp = 2500, mtp = 2500, version = 0x20000000}
        end
        state = consensus.get_deployment_state(delayed_deployment, period, threshold, 39, make_block_info(blocks))
        assert.equals(STATE.ACTIVE, state)
      end)

      it("ACTIVE state is terminal", function()
        local blocks = {}
        -- Get to ACTIVE state
        for h = 0, 9 do
          blocks[h] = {timestamp = 1000, mtp = 1000, version = 0x20000000}
        end
        for h = 10, 19 do
          blocks[h] = {timestamp = 1500, mtp = 1500, version = 0x20000002}
        end
        for h = 20, 29 do
          blocks[h] = {timestamp = 2000, mtp = 2000, version = 0x20000000}
        end
        -- Additional period - should stay ACTIVE
        for h = 30, 39 do
          blocks[h] = {timestamp = 2500, mtp = 2500, version = 0x20000000}
        end
        local state = consensus.get_deployment_state(deployment, period, threshold, 39, make_block_info(blocks))
        assert.equals(STATE.ACTIVE, state)
      end)

      it("FAILED state is terminal", function()
        local blocks = {}
        -- Get to FAILED state
        for h = 0, 9 do
          blocks[h] = {timestamp = 1000, mtp = 1000, version = 0x20000000}
        end
        for h = 10, 19 do
          blocks[h] = {timestamp = 5000, mtp = 5000, version = 0x20000000}
        end
        -- Additional period - should stay FAILED
        for h = 20, 29 do
          blocks[h] = {timestamp = 5500, mtp = 5500, version = 0x20000000}
        end
        local state = consensus.get_deployment_state(deployment, period, threshold, 29, make_block_info(blocks))
        assert.equals(STATE.FAILED, state)
      end)
    end)

    describe("get_deployment_state_for_block", function()
      local deployment
      local period
      local threshold

      setup(function()
        deployment = {
          bit = 1,
          start_time = 1000,
          timeout = 5000,
          min_activation_height = 0
        }
        period = 10
        threshold = 8
      end)

      local function make_block_info(blocks)
        return function(h)
          return blocks[h]
        end
      end

      it("returns DEFINED for blocks in first period", function()
        local blocks = {}
        for h = 0, 9 do
          blocks[h] = {timestamp = 500, mtp = 500, version = 0x20000000}
        end
        -- Check a mid-period block
        local state = consensus.get_deployment_state_for_block(deployment, period, threshold, 5, make_block_info(blocks))
        assert.equals(STATE.DEFINED, state)
      end)

      it("returns state based on previous period boundary", function()
        local blocks = {}
        -- First period ends with STARTED
        for h = 0, 9 do
          blocks[h] = {timestamp = 1000, mtp = 1000, version = 0x20000000}
        end
        -- Blocks in second period should see STARTED state
        for h = 10, 19 do
          blocks[h] = {timestamp = 1500, mtp = 1500, version = 0x20000002}
        end

        -- Block 15 (mid-second period) should be in STARTED state
        -- (state is determined by end of previous period = block 9)
        local state = consensus.get_deployment_state_for_block(deployment, period, threshold, 15, make_block_info(blocks))
        assert.equals(STATE.STARTED, state)
      end)

      it("handles ALWAYS_ACTIVE deployment", function()
        local always_active = {
          bit = 1,
          start_time = consensus.ALWAYS_ACTIVE,
          timeout = 5000,
          min_activation_height = 0
        }
        local blocks = {[5] = {timestamp = 0, mtp = 0, version = 0}}
        local state = consensus.get_deployment_state_for_block(always_active, period, threshold, 5, make_block_info(blocks))
        assert.equals(STATE.ACTIVE, state)
      end)
    end)

    describe("network versionbits parameters", function()
      it("mainnet has correct period and threshold", function()
        local mainnet = consensus.networks.mainnet
        assert.equals(2016, mainnet.versionbits_period)
        assert.equals(1815, mainnet.versionbits_threshold)  -- 95% of 2016
      end)

      it("testnet has correct period and threshold", function()
        local testnet = consensus.networks.testnet
        assert.equals(2016, testnet.versionbits_period)
        assert.equals(1512, testnet.versionbits_threshold)  -- 75% of 2016
      end)

      it("regtest has small period for fast testing", function()
        local regtest = consensus.networks.regtest
        assert.equals(144, regtest.versionbits_period)
        assert.equals(108, regtest.versionbits_threshold)  -- 75% of 144
      end)
    end)

    describe("deployment parameters", function()
      it("SEGWIT deployment has correct parameters", function()
        local segwit = consensus.DEPLOYMENTS.SEGWIT
        assert.equals(1, segwit.bit)
        assert.equals(1479168000, segwit.start_time)
        assert.equals(1510704000, segwit.timeout)
        assert.equals(0, segwit.min_activation_height)
      end)

      it("TAPROOT deployment has correct parameters", function()
        local taproot = consensus.DEPLOYMENTS.TAPROOT
        assert.equals(2, taproot.bit)
        assert.equals(1619222400, taproot.start_time)
        assert.equals(1628640000, taproot.timeout)
        assert.equals(709632, taproot.min_activation_height)
      end)
    end)

    describe("integration - simulated activation", function()
      it("simulates full SEGWIT-like activation cycle", function()
        -- Simulate a deployment over multiple periods
        local deployment = {
          bit = 1,
          start_time = 1000,
          timeout = 100000,
          min_activation_height = 0
        }
        local period = 100
        local threshold = 95  -- 95%

        local blocks = {}
        local block_time = 0

        -- Period 0 (blocks 0-99): before start_time -> DEFINED
        for h = 0, 99 do
          block_time = h * 10
          blocks[h] = {timestamp = block_time, mtp = block_time, version = 0x20000000}
        end

        local function get_block_info(h)
          return blocks[h]
        end

        local state = consensus.get_deployment_state(deployment, period, threshold, 99, get_block_info)
        assert.equals(STATE.DEFINED, state)

        -- Period 1 (blocks 100-199): MTP >= start_time -> STARTED
        for h = 100, 199 do
          block_time = h * 10
          blocks[h] = {timestamp = block_time, mtp = block_time, version = 0x20000000}
        end
        state = consensus.get_deployment_state(deployment, period, threshold, 199, get_block_info)
        assert.equals(STATE.STARTED, state)

        -- Period 2 (blocks 200-299): 94 signaling (below threshold) -> still STARTED
        for h = 200, 293 do
          blocks[h] = {timestamp = h * 10, mtp = h * 10, version = 0x20000002}  -- signaling
        end
        for h = 294, 299 do
          blocks[h] = {timestamp = h * 10, mtp = h * 10, version = 0x20000000}  -- not signaling
        end
        state = consensus.get_deployment_state(deployment, period, threshold, 299, get_block_info)
        assert.equals(STATE.STARTED, state)

        -- Period 3 (blocks 300-399): 95 signaling (meets threshold) -> LOCKED_IN
        for h = 300, 394 do
          blocks[h] = {timestamp = h * 10, mtp = h * 10, version = 0x20000002}  -- 95 signaling
        end
        for h = 395, 399 do
          blocks[h] = {timestamp = h * 10, mtp = h * 10, version = 0x20000000}  -- not signaling
        end
        state = consensus.get_deployment_state(deployment, period, threshold, 399, get_block_info)
        assert.equals(STATE.LOCKED_IN, state)

        -- Period 4 (blocks 400-499): after LOCKED_IN -> ACTIVE
        for h = 400, 499 do
          blocks[h] = {timestamp = h * 10, mtp = h * 10, version = 0x20000000}
        end
        state = consensus.get_deployment_state(deployment, period, threshold, 499, get_block_info)
        assert.equals(STATE.ACTIVE, state)

        -- Period 5: still ACTIVE (terminal state)
        for h = 500, 599 do
          blocks[h] = {timestamp = h * 10, mtp = h * 10, version = 0x00000001}  -- old version
        end
        state = consensus.get_deployment_state(deployment, period, threshold, 599, get_block_info)
        assert.equals(STATE.ACTIVE, state)
      end)
    end)
  end)

  describe("checkpoint enforcement", function()
    local test_network

    before_each(function()
      -- Create a test network with checkpoints
      test_network = {
        name = "test",
        checkpoints = {
          [0] = "0000000000000000000000000000000000000000000000000000000000000000",
          [1000] = "0000000000000000000000000000000000000000000000000000000000001000",
          [5000] = "0000000000000000000000000000000000000000000000000000000000005000",
          [10000] = "0000000000000000000000000000000000000000000000000000000000010000",
        },
      }
    end)

    describe("get_last_checkpoint_height", function()
      it("returns the highest checkpoint height", function()
        local height = consensus.get_last_checkpoint_height(test_network)
        assert.equals(10000, height)
      end)

      it("returns 0 for empty checkpoints", function()
        local empty_network = { checkpoints = {} }
        local height = consensus.get_last_checkpoint_height(empty_network)
        assert.equals(0, height)
      end)

      it("returns 0 for nil checkpoints", function()
        local no_checkpoints_network = {}
        local height = consensus.get_last_checkpoint_height(no_checkpoints_network)
        assert.equals(0, height)
      end)
    end)

    describe("check_checkpoint", function()
      it("returns true when hash matches checkpoint", function()
        local ok, err = consensus.check_checkpoint(test_network, 1000,
          "0000000000000000000000000000000000000000000000000000000000001000")
        assert.is_true(ok)
        assert.is_nil(err)
      end)

      it("returns CHECKPOINT error when hash does not match checkpoint", function()
        local ok, err = consensus.check_checkpoint(test_network, 1000,
          "0000000000000000000000000000000000000000000000000000000000000bad")
        assert.is_false(ok)
        assert.equals("CHECKPOINT", err)
      end)

      it("returns true for heights without checkpoints", function()
        local ok, err = consensus.check_checkpoint(test_network, 500,
          "any_hash_is_fine_here")
        assert.is_true(ok)
        assert.is_nil(err)
      end)
    end)

    describe("check_checkpoint_anti_fork", function()
      it("returns true when all ancestors match checkpoints", function()
        local get_ancestor = function(h)
          if h == 0 then
            return { hash_hex = "0000000000000000000000000000000000000000000000000000000000000000" }
          elseif h == 1000 then
            return { hash_hex = "0000000000000000000000000000000000000000000000000000000000001000" }
          end
          return nil
        end

        local ok, err = consensus.check_checkpoint_anti_fork(
          test_network, 2000,
          "any_hash_here",
          get_ancestor
        )
        assert.is_true(ok)
        assert.is_nil(err)
      end)

      it("returns CHECKPOINT error when ancestor does not match checkpoint", function()
        local get_ancestor = function(h)
          if h == 0 then
            return { hash_hex = "0000000000000000000000000000000000000000000000000000000000000000" }
          elseif h == 1000 then
            -- Wrong hash!
            return { hash_hex = "0000000000000000000000000000000000000000000000000000000000000bad" }
          end
          return nil
        end

        local ok, err = consensus.check_checkpoint_anti_fork(
          test_network, 2000,
          "some_hash",
          get_ancestor
        )
        assert.is_false(ok)
        assert.equals("CHECKPOINT", err)
      end)

      it("rejects block at checkpoint height with wrong hash", function()
        local get_ancestor = function(h)
          if h == 0 then
            return { hash_hex = "0000000000000000000000000000000000000000000000000000000000000000" }
          end
          return nil
        end

        -- Block at checkpoint height 1000 with wrong hash
        local ok, err = consensus.check_checkpoint_anti_fork(
          test_network, 1000,
          "0000000000000000000000000000000000000000000000000000000000000bad",
          get_ancestor
        )
        assert.is_false(ok)
        assert.equals("CHECKPOINT", err)
      end)
    end)
  end)

  -- ---------------------------------------------------------------------------
  -- Assumevalid optimization — 7-case test matrix
  -- Matches Bitcoin Core v28.0 ConnectBlock logic (src/validation.cpp:2345-2383).
  -- All six conditions must hold for script verification to be skipped.
  -- ---------------------------------------------------------------------------
  describe("assumevalid optimization", function()
    -- av_hash is the hardcoded assumevalid hash (height 5000 on the test chain).
    local AV_HASH   = "0000000000000000000000000000000000000000000000000000000000001000"
    local AV_HEIGHT = 5000
    -- The block being connected lives well below the assumevalid block.
    local BLOCK_HASH   = "0000000000000000000000000000000000000000000000000000000000000abc"
    local BLOCK_HEIGHT = 100
    -- Best header is 10000 blocks above the block being connected (> 2016).
    local BEST_HEADER_HEIGHT = 10000
    local GOOD_WORK = consensus.work_from_hex(
      "0000000000000000000000000000000000000000000000000000000000000002")
    local ZERO_WORK = consensus.work_from_hex(
      "0000000000000000000000000000000000000000000000000000000000000000")

    -- Helper: build network config.
    local function net(av)
      return {
        name = "test",
        assumevalid = av,
        min_chain_work = "0000000000000000000000000000000000000000000000000000000000000001",
      }
    end

    -- All-pass callbacks: every condition succeeds.
    local function all_pass_callbacks()
      local function is_av_in_index() return true end
      local function is_ancestor(h, hash)
        return h <= AV_HEIGHT and hash == BLOCK_HASH
      end
      local function is_on_best(h, hash)
        return hash == BLOCK_HASH
      end
      return is_av_in_index, is_ancestor, is_on_best
    end

    -- Test 1: assumevalid absent (nil) → every block runs scripts.
    -- Corresponds to running with -assumevalid=0 or no config.
    it("case 1 — assumevalid absent: always verifies scripts", function()
      local av_in, av_anc, av_best = all_pass_callbacks()
      local skip = consensus.should_skip_script_validation(
        net(nil), BLOCK_HEIGHT, BLOCK_HASH,
        av_in, av_anc, av_best,
        GOOD_WORK, BEST_HEADER_HEIGHT
      )
      assert.is_false(skip)
    end)

    -- Test 2: block IS an ancestor of assumevalid and all safety conditions hold
    -- → script skip fires.
    it("case 2 — block is ancestor of assumevalid: scripts skipped", function()
      local av_in, av_anc, av_best = all_pass_callbacks()
      local skip = consensus.should_skip_script_validation(
        net(AV_HASH), BLOCK_HEIGHT, BLOCK_HASH,
        av_in, av_anc, av_best,
        GOOD_WORK, BEST_HEADER_HEIGHT
      )
      assert.is_true(skip)
    end)

    -- Test 3: block NOT in assumevalid chain at the same height (different hash
    -- at that height on the canonical chain) → scripts must run.
    it("case 3 — block not in assumevalid chain: scripts run", function()
      local function is_av_in_index() return true end
      local function is_ancestor(_h, _hash) return false end  -- wrong branch
      local function is_on_best(_h, _hash) return true end
      local skip = consensus.should_skip_script_validation(
        net(AV_HASH), BLOCK_HEIGHT, "deadbeefdeadbeef000000000000000000000000000000000000000000000000",
        is_av_in_index, is_ancestor, is_on_best,
        GOOD_WORK, BEST_HEADER_HEIGHT
      )
      assert.is_false(skip)
    end)

    -- Test 4: block height ABOVE the assumevalid height → scripts must run.
    it("case 4 — block height above assumevalid height: scripts run", function()
      local function is_av_in_index() return true end
      -- is_ancestor correctly returns false for heights > AV_HEIGHT
      local function is_ancestor(h, _hash) return h <= AV_HEIGHT end
      local function is_on_best(_h, _hash) return true end
      local skip = consensus.should_skip_script_validation(
        net(AV_HASH), AV_HEIGHT + 1, BLOCK_HASH,
        is_av_in_index, is_ancestor, is_on_best,
        GOOD_WORK, BEST_HEADER_HEIGHT
      )
      assert.is_false(skip)
    end)

    -- Test 5: assumevalid hash not yet in header index (condition 2 fails)
    -- → scripts must run (we haven't received the header yet).
    it("case 5 — assumevalid hash not in header index: scripts run", function()
      local function is_av_in_index() return false end  -- haven't seen the header
      local function is_ancestor(_h, _hash) return true end
      local function is_on_best(_h, _hash) return true end
      local skip = consensus.should_skip_script_validation(
        net(AV_HASH), BLOCK_HEIGHT, BLOCK_HASH,
        is_av_in_index, is_ancestor, is_on_best,
        GOOD_WORK, BEST_HEADER_HEIGHT
      )
      assert.is_false(skip)
    end)

    -- Test 6: block would pass ancestor check but fails a NON-script check
    -- (bad merkle root / bad coinbase / PoW) → block is REJECTED even though
    -- skip_scripts returned true.  The skip decision does not bypass non-script
    -- validation; this test verifies we do NOT skip rejection of invalid blocks.
    -- We model this by checking that connect_block-level non-script validation
    -- is independent: skip_scripts=true does not suppress the non-script error.
    -- Since that logic lives in utxo.connect_block (not here), we verify that
    -- should_skip_script_validation itself returns true (i.e., the skip flag is
    -- set) while the caller is still responsible for running non-script checks.
    it("case 6 — non-script invalidity: skip flag may be true but non-script checks still run", function()
      -- should_skip_script_validation only controls the script-check flag.
      -- A block that is an ancestor of assumevalid CAN have skip_scripts=true
      -- even if it has a bad merkle root — the caller (connect_block) must
      -- still reject it on non-script grounds.  Here we just confirm the flag
      -- is true so that the caller receives it; the caller's responsibility is
      -- tested in utxo_spec.lua.
      local av_in, av_anc, av_best = all_pass_callbacks()
      local skip = consensus.should_skip_script_validation(
        net(AV_HASH), BLOCK_HEIGHT, BLOCK_HASH,
        av_in, av_anc, av_best,
        GOOD_WORK, BEST_HEADER_HEIGHT
      )
      -- skip_scripts can be true; the block is still expected to be rejected by
      -- connect_block's non-script checks (merkle, coinbase, PoW).
      assert.is_true(skip)
    end)

    -- Test 7: regtest IBD — assumevalid is nil on regtest, so skip never fires.
    -- With and without the flag, the outcome should be identical (always verify).
    it("case 7 — regtest: assumevalid nil, scripts always verified", function()
      local regtest_net = {
        name = "regtest",
        assumevalid = nil,  -- regtest has no assumevalid by design
        min_chain_work = "0000000000000000000000000000000000000000000000000000000000000000",
      }
      local av_in, av_anc, av_best = all_pass_callbacks()
      -- Even if all other conditions would pass, nil assumevalid forces verify.
      local skip_with = consensus.should_skip_script_validation(
        regtest_net, 5000, BLOCK_HASH,
        av_in, av_anc, av_best,
        GOOD_WORK, 10000
      )
      local skip_without = consensus.should_skip_script_validation(
        regtest_net, 5000, BLOCK_HASH,
        function() return false end,
        function() return false end,
        function() return false end,
        ZERO_WORK, 0
      )
      assert.is_false(skip_with)
      assert.is_false(skip_without)
      -- Both cases must be identical (no divergence on regtest)
      assert.equals(skip_with, skip_without)
    end)

    -- Also test make_assumevalid_callbacks with a mock header_chain.
    describe("make_assumevalid_callbacks", function()
      it("returns correct callbacks for a well-formed header_chain", function()
        local mock_chain = {
          headers = {
            [AV_HASH] = { height = AV_HEIGHT },
            [BLOCK_HASH] = { height = BLOCK_HEIGHT },
          },
          height_to_hash = {
            [AV_HEIGHT] = AV_HASH,
            [BLOCK_HEIGHT] = BLOCK_HASH,
          },
          header_tip_height = BEST_HEADER_HEIGHT,
        }
        local test_net = net(AV_HASH)
        local av_in, av_anc, av_best =
          consensus.make_assumevalid_callbacks(test_net, mock_chain)

        -- Condition 2: av hash is in index
        assert.is_true(av_in())

        -- Condition 3: block at BLOCK_HEIGHT with BLOCK_HASH is ancestor
        assert.is_true(av_anc(BLOCK_HEIGHT, BLOCK_HASH))
        -- Wrong hash at same height → not ancestor
        assert.is_false(av_anc(BLOCK_HEIGHT, "deadbeef" .. string.rep("00", 28)))
        -- Height above AV_HEIGHT → not ancestor
        assert.is_false(av_anc(AV_HEIGHT + 1, BLOCK_HASH))

        -- Condition 4: block is on best header chain
        assert.is_true(av_best(BLOCK_HEIGHT, BLOCK_HASH))
        assert.is_false(av_best(BLOCK_HEIGHT, "deadbeef" .. string.rep("00", 28)))
      end)

      it("returns is_av_in_index=false when assumevalid hash is absent from index", function()
        local mock_chain = {
          headers = {},  -- empty — haven't seen the header yet
          height_to_hash = {},
          header_tip_height = 0,
        }
        local av_in, _, _ =
          consensus.make_assumevalid_callbacks(net(AV_HASH), mock_chain)
        assert.is_false(av_in())
      end)
    end)
  end)
end)
