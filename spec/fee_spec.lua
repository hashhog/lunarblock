describe("fee", function()
  local fee

  setup(function()
    fee = require("lunarblock.fee")
  end)

  describe("bucket generation", function()
    it("generates exponentially spaced buckets", function()
      assert.is_true(#fee.FEE_BUCKETS > 0)
      assert.is_true(fee.BUCKET_COUNT > 0)
      -- First bucket should be MIN_BUCKET_FEE
      assert.are.equal(fee.MIN_BUCKET_FEE, fee.FEE_BUCKETS[1])
      -- Buckets should be increasing
      for i = 2, fee.BUCKET_COUNT do
        assert.is_true(fee.FEE_BUCKETS[i] > fee.FEE_BUCKETS[i-1])
      end
    end)
  end)

  describe("get_bucket_index", function()
    it("returns bucket 1 for minimum fee rate", function()
      assert.are.equal(1, fee.get_bucket_index(1))
    end)

    it("returns correct bucket for mid-range fee", function()
      -- Fee rate of 10 sat/vB should be in a middle bucket
      local idx = fee.get_bucket_index(10)
      assert.is_true(idx > 1)
      assert.is_true(idx < fee.BUCKET_COUNT)
    end)

    it("returns highest bucket for very high fee", function()
      local idx = fee.get_bucket_index(50000)
      assert.are.equal(fee.BUCKET_COUNT, idx)
    end)

    it("returns bucket 1 for sub-minimum fee", function()
      local idx = fee.get_bucket_index(0.5)
      assert.are.equal(1, idx)
    end)

    it("returns appropriate bucket for boundary values", function()
      -- Fee at exactly a bucket boundary
      local bucket_fee = fee.FEE_BUCKETS[5]
      local idx = fee.get_bucket_index(bucket_fee)
      -- Should return bucket 5 or higher depending on exact boundary
      assert.is_true(idx >= 4)
      assert.is_true(idx <= 5)
    end)
  end)

  describe("FeeEstimator", function()
    local estimator

    before_each(function()
      estimator = fee.new(25)  -- Small max_target for testing
    end)

    it("creates with correct initial state", function()
      assert.are.equal(25, estimator.max_target)
      assert.are.equal(0, estimator.best_height)
      assert.are.same({}, estimator.unconfirmed)
      -- Check confirmed table structure
      assert.is_table(estimator.confirmed[1])
      assert.is_table(estimator.confirmed[1][1])
      assert.are.equal(0, estimator.confirmed[1][1].count)
      assert.are.equal(0, estimator.confirmed[1][1].total)
    end)

    describe("track_tx", function()
      it("tracks unconfirmed transaction", function()
        estimator:track_tx("abc123", 10, 100)
        assert.is_not_nil(estimator.unconfirmed["abc123"])
        assert.are.equal(100, estimator.unconfirmed["abc123"].entry_height)
        assert.are.equal(10, estimator.unconfirmed["abc123"].fee_rate)
      end)
    end)

    describe("tx_confirmed", function()
      it("records confirmation and removes from unconfirmed", function()
        estimator:track_tx("tx1", 50, 100)
        estimator:tx_confirmed("tx1", 102)  -- Confirmed 2 blocks later

        -- Transaction should be removed from unconfirmed
        assert.is_nil(estimator.unconfirmed["tx1"])

        -- Get the bucket for fee rate 50
        local bucket = fee.get_bucket_index(50)

        -- Check that targets >= 2 have success recorded
        assert.are.equal(1, estimator.confirmed[2][bucket].count)
        assert.are.equal(1, estimator.confirmed[2][bucket].total)
        assert.are.equal(1, estimator.confirmed[3][bucket].count)
        assert.are.equal(1, estimator.confirmed[3][bucket].total)

        -- Check that target 1 has failure recorded
        assert.are.equal(0, estimator.confirmed[1][bucket].count)
        assert.are.equal(1, estimator.confirmed[1][bucket].total)
      end)

      it("handles confirmation in same block (1 block)", function()
        estimator:track_tx("tx1", 100, 100)
        estimator:tx_confirmed("tx1", 100)  -- Same block

        local bucket = fee.get_bucket_index(100)
        -- blocks_to_confirm should be clamped to 1
        assert.are.equal(1, estimator.confirmed[1][bucket].count)
        assert.are.equal(1, estimator.confirmed[1][bucket].total)
      end)

      it("ignores unknown transaction", function()
        -- Should not error
        estimator:tx_confirmed("unknown", 100)
      end)
    end)

    describe("tx_removed", function()
      it("removes transaction from tracking", function()
        estimator:track_tx("tx1", 50, 100)
        assert.is_not_nil(estimator.unconfirmed["tx1"])
        estimator:tx_removed("tx1")
        assert.is_nil(estimator.unconfirmed["tx1"])
      end)
    end)

    describe("on_block", function()
      it("updates best height", function()
        estimator:on_block(500)
        assert.are.equal(500, estimator.best_height)
      end)

      it("applies decay to bucket data", function()
        -- Add some data
        estimator:track_tx("tx1", 50, 100)
        estimator:tx_confirmed("tx1", 101)

        local bucket = fee.get_bucket_index(50)
        local initial_count = estimator.confirmed[1][bucket].count
        local initial_total = estimator.confirmed[1][bucket].total

        -- Apply one block of decay
        estimator:on_block(102)

        local new_count = estimator.confirmed[1][bucket].count
        local new_total = estimator.confirmed[1][bucket].total

        -- Values should be decayed
        assert.is_true(new_count < initial_count)
        assert.is_true(new_total < initial_total)
        -- Decay factor is 0.998
        assert.are.near(initial_count * 0.998, new_count, 0.0001)
      end)
    end)

    describe("estimate_fee", function()
      it("returns conservative estimate with no data", function()
        local fee_rate, reliable = estimator:estimate_fee(2)
        assert.are.equal(fee.FEE_BUCKETS[fee.BUCKET_COUNT], fee_rate)
        assert.is_false(reliable)
      end)

      it("returns appropriate fee with sufficient data", function()
        -- Add many transactions at fee rate ~50 sat/vB that confirm in 1 block
        local bucket = fee.get_bucket_index(50)
        for _ = 1, 20 do
          estimator.confirmed[1][bucket].count = estimator.confirmed[1][bucket].count + 1
          estimator.confirmed[1][bucket].total = estimator.confirmed[1][bucket].total + 1
        end

        local fee_rate, reliable = estimator:estimate_fee(1)
        assert.is_true(reliable)
        assert.are.equal(fee.FEE_BUCKETS[bucket], fee_rate)
      end)

      it("respects success threshold", function()
        local bucket = fee.get_bucket_index(100)
        -- 8 successes out of 10 = 80% (below 85% threshold)
        estimator.confirmed[1][bucket].count = 8
        estimator.confirmed[1][bucket].total = 10

        local fee_rate, reliable = estimator:estimate_fee(1, 0.85)
        -- Should not use this bucket (80% < 85%)
        if reliable then
          assert.is_true(fee_rate ~= fee.FEE_BUCKETS[bucket] or fee.FEE_BUCKETS[bucket] == fee.FEE_BUCKETS[fee.BUCKET_COUNT])
        end

        -- But with 70% threshold it should be OK
        -- We need a bucket with enough data that passes
        local higher_bucket = bucket + 1
        if higher_bucket <= fee.BUCKET_COUNT then
          estimator.confirmed[1][higher_bucket].count = 18
          estimator.confirmed[1][higher_bucket].total = 20
          fee_rate, reliable = estimator:estimate_fee(1, 0.70)
          assert.is_true(reliable)
        end
      end)

      it("clamps target to valid range", function()
        -- Target above max_target
        local fee_rate1, _ = estimator:estimate_fee(100)
        -- Target at max_target
        local fee_rate2, _ = estimator:estimate_fee(estimator.max_target)
        assert.are.equal(fee_rate1, fee_rate2)

        -- Target below 1
        local fee_rate3, _ = estimator:estimate_fee(0)
        local fee_rate4, _ = estimator:estimate_fee(1)
        assert.are.equal(fee_rate3, fee_rate4)
      end)
    end)

    describe("estimate_smart_fee", function()
      it("falls back to longer target when data sparse", function()
        local fee_rate, actual_target = estimator:estimate_smart_fee(2)
        -- With no data, should fall back to max target
        assert.are.equal(1, fee_rate)  -- Minimum relay fee
        assert.are.equal(estimator.max_target, actual_target)
      end)

      it("uses requested target when data available", function()
        -- Add good data for target 2
        local bucket = fee.get_bucket_index(30)
        estimator.confirmed[2][bucket].count = 50
        estimator.confirmed[2][bucket].total = 55

        local fee_rate, actual_target = estimator:estimate_smart_fee(2)
        assert.are.equal(2, actual_target)
        assert.are.equal(fee.FEE_BUCKETS[bucket], fee_rate)
      end)

      it("tries double target before fallback", function()
        -- Add data for target 4 but not target 2
        local bucket = fee.get_bucket_index(20)
        estimator.confirmed[4][bucket].count = 8  -- 80% > 60% threshold for relaxed target
        estimator.confirmed[4][bucket].total = 10

        local fee_rate, actual_target = estimator:estimate_smart_fee(2)
        assert.are.equal(4, actual_target)
        assert.are.equal(fee.FEE_BUCKETS[bucket], fee_rate)
      end)
    end)

    describe("multiple transactions", function()
      it("handles multiple transactions at different fee rates", function()
        -- High fee tx - confirms in 1 block
        estimator:track_tx("high", 500, 100)
        estimator:tx_confirmed("high", 100)

        -- Medium fee tx - confirms in 3 blocks
        estimator:track_tx("med", 50, 100)
        estimator:tx_confirmed("med", 103)

        -- Low fee tx - confirms in 10 blocks
        estimator:track_tx("low", 5, 100)
        estimator:tx_confirmed("low", 110)

        local high_bucket = fee.get_bucket_index(500)
        local med_bucket = fee.get_bucket_index(50)
        local low_bucket = fee.get_bucket_index(5)

        -- High fee confirms for all targets
        assert.are.equal(1, estimator.confirmed[1][high_bucket].count)

        -- Medium fee: success for target >= 3, failure for 1, 2
        assert.are.equal(0, estimator.confirmed[1][med_bucket].count)
        assert.are.equal(1, estimator.confirmed[1][med_bucket].total)
        assert.are.equal(1, estimator.confirmed[3][med_bucket].count)

        -- Low fee: success for target >= 10
        assert.are.equal(1, estimator.confirmed[10][low_bucket].count)
        assert.are.equal(0, estimator.confirmed[5][low_bucket].count)
      end)
    end)
  end)
end)
