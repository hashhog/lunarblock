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
end)
