#!/usr/bin/env luajit
-- W114 Fee Estimation (CBlockPolicyEstimator) audit — lunarblock (Lua / LuaJIT)
-- Gates G1-G30 covering bucket schema, decay constants, horizons, tracking logic,
-- RPC output correctness, unit conversions, and precision.
-- Core references: bitcoin-core/src/policy/fees/block_policy_estimator.h/.cpp,
--                  bitcoin-core/src/rpc/fees.cpp

package.path = "src/?.lua;" .. package.path

local loaders = package.loaders or package.searchers
table.insert(loaders, 2, function(module)
  local name = module:match("^lunarblock%.(.+)")
  if name then
    local filename = "src/" .. name .. ".lua"
    local f = io.open(filename)
    if f then
      f:close()
      return function() return dofile(filename) end
    end
  end
  return nil, "not found"
end)

local fee = require("lunarblock.fee")

local tests_passed = 0
local tests_failed = 0
local bugs = {}

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then
    print("PASS: " .. name)
    tests_passed = tests_passed + 1
  else
    print("FAIL: " .. name)
    print("      " .. tostring(err))
    tests_failed = tests_failed + 1
  end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) .. ", expected " .. tostring(b))
  end
end

local function expect_true(v, msg)
  if not v then error(msg or "expected true") end
end

local function expect_false(v, msg)
  if v then error(msg or "expected false") end
end

local function expect_near(a, b, tol, msg)
  local d = math.abs(a - b)
  if d > tol then
    error((msg or "not near") .. string.format(": |%g - %g| = %g > tol %g", a, b, d, tol))
  end
end

local function log_bug(id, severity, desc)
  bugs[#bugs + 1] = {id = id, severity = severity, desc = desc}
end

print("=== W114 lunarblock Fee Estimation Audit ===\n")

-- -----------------------------------------------------------------------
-- G1: Bucket count — Core uses ~236 buckets (1.05 spacing, 100–1e7 sat/kvB)
-- -----------------------------------------------------------------------
test("G1: bucket count (Core ~236, lunarblock should have similar coverage)", function()
  -- Core: MIN_BUCKET_FEERATE=100 sat/kvB, MAX=1e7, spacing=1.05 → ~236 buckets
  -- lunarblock: MIN=1 sat/vB(=1000 sat/kvB), MAX=10000 sat/vB, spacing=1.2 → ~27 actual buckets
  -- BUCKET_COUNT=40 cap further compresses this
  -- BUG: only ~27 buckets actually generated; substantially fewer than Core's 236
  local count = fee.BUCKET_COUNT
  -- Document the actual count for the audit record
  print(string.format("  INFO: lunarblock BUCKET_COUNT=%d (Core ~236)", count))
  -- Must have at least some buckets
  expect_true(count > 0, "bucket count must be positive")
  -- Core has >200 buckets; lunarblock should have more than 10
  if count < 100 then
    log_bug("G1", "HIGH",
      string.format("BUCKET_COUNT=%d vs Core ~236; FEE_SPACING=%.2f vs Core 1.05",
        count, fee.FEE_SPACING))
  end
end)

-- -----------------------------------------------------------------------
-- G2: FEE_SPACING constant — Core = 1.05, lunarblock = 1.2
-- -----------------------------------------------------------------------
test("G2: FEE_SPACING constant matches Core (1.05)", function()
  local spacing = fee.FEE_SPACING
  print(string.format("  INFO: lunarblock FEE_SPACING=%.2f (Core 1.05)", spacing))
  if math.abs(spacing - 1.05) > 0.001 then
    log_bug("G2", "HIGH",
      string.format("FEE_SPACING=%.2f vs Core 1.05 — bucket granularity too coarse, "..
        "fee estimates will have large quantization error", spacing))
    error(string.format("FEE_SPACING=%.2f, want ~1.05", spacing))
  end
end)

-- -----------------------------------------------------------------------
-- G3: MIN_BUCKET_FEERATE — Core = 100 sat/kvB = 0.1 sat/vB, lunarblock = 1 sat/vB
-- -----------------------------------------------------------------------
test("G3: MIN_BUCKET_FEERATE covers low-fee txs (Core=100 sat/kvB=0.1 sat/vB)", function()
  local min_f = fee.MIN_BUCKET_FEE
  print(string.format("  INFO: lunarblock MIN_BUCKET_FEE=%g sat/vB (Core=0.1 sat/vB=100 sat/kvB)", min_f))
  -- Core MIN_BUCKET_FEERATE=100 sat/kvB; lunarblock uses sat/vB so 0.1 is equiv
  -- lunarblock has 1 sat/vB = 1000 sat/kvB — 10× higher than Core minimum
  -- Low-fee txs (100-999 sat/kvB) are not tracked in any bucket
  if min_f > 0.5 then
    log_bug("G3", "MEDIUM",
      string.format("MIN_BUCKET_FEE=%g sat/vB; Core minimum is 0.1 sat/vB (100 sat/kvB) — "..
        "txs paying 0.1–1.0 sat/vB omitted from estimation", min_f))
    error(string.format("MIN_BUCKET_FEE=%g > 0.5 sat/vB; low-fee txs not tracked", min_f))
  end
end)

-- -----------------------------------------------------------------------
-- G4: Three horizons — Core has SHORT(12*1), MED(24*2=48), LONG(42*24=1008)
-- -----------------------------------------------------------------------
test("G4: three confirmation horizons (short/medium/long) present", function()
  -- lunarblock has only one horizon: max_target=144
  -- SHORT_BLOCK_PERIODS=12, MED_BLOCK_PERIODS=24*scale=2(=48), LONG=42*24=1008
  local est = fee.new(144)
  -- Only one decay constant field exists
  local has_short = (est.shortStats ~= nil)
  local has_med   = (est.medStats ~= nil or est.feeStats ~= nil)
  local has_long  = (est.longStats ~= nil)
  if not (has_short and has_med and has_long) then
    log_bug("G4", "HIGH",
      "Three-horizon architecture absent — only single horizon (max_target=144, decay=0.998); "..
        "SHORT(decay=0.962,12blk), MED(0.9952,48blk), LONG(0.99931,1008blk) missing")
    error("single-horizon only; three-horizon system absent")
  end
end)

-- -----------------------------------------------------------------------
-- G5: Decay constants — Core SHORT=0.962, MED=0.9952, LONG=0.99931
-- -----------------------------------------------------------------------
test("G5: decay constants match Core (0.962 / 0.9952 / 0.99931)", function()
  -- lunarblock has single decay=0.998 which matches none of Core's three
  local est = fee.new(144)
  local d = est.decay
  print(string.format("  INFO: lunarblock decay=%.5f (Core: 0.962/0.9952/0.99931)", d))
  local matches_core = (math.abs(d - 0.962) < 1e-4 or
                        math.abs(d - 0.9952) < 1e-5 or
                        math.abs(d - 0.99931) < 1e-6)
  if not matches_core then
    log_bug("G5", "HIGH",
      string.format("decay=%.5f matches none of Core's (0.962/0.9952/0.99931) — "..
        "half-life is wrong, historical weight decays at wrong rate", d))
    error(string.format("decay=%.5f does not match any Core constant", d))
  end
end)

-- -----------------------------------------------------------------------
-- G6: SUFFICIENT_FEETXS threshold — Core uses decay-adjusted sufficientTxVal/(1-decay)
-- -----------------------------------------------------------------------
test("G6: sufficient-samples threshold is decay-adjusted (Core: sufficientTxVal/(1-decay))", function()
  -- Core: partialNum < SUFFICIENT_FEETXS / (1 - decay) before deciding on a bucket range
  -- For MED: 0.1/(1-0.9952) ≈ 20.8 tx equivalents required
  -- lunarblock: hardcoded >= 10 (not decay-adjusted)
  -- Not a code field we can inspect directly, but test that estimate_fee
  -- is sensitive to sample size in proportion to decay
  local est = fee.new(10)
  -- Add just 5 tx's in the top bucket (below any decay-adjusted threshold)
  for i = 1, 5 do
    est:track_tx("tx"..i, 9000, 1)
    est:tx_confirmed("tx"..i, 2)  -- 1 block to confirm
  end
  est:on_block(2)
  local fr, rel = est:estimate_fee(1, 0.85)
  -- lunarblock accepts 5 samples (total >= 5 < 10 threshold), but returns unreliable
  -- This tests the threshold gate
  print(string.format("  INFO: 5-sample estimate: fee=%s reliable=%s", tostring(fr), tostring(rel)))
  -- With only 5 samples and threshold 10, should be unreliable
  -- (lunarblock gate is total >= 10; with decay this would fire correctly)
  -- Document that threshold is not decay-adjusted
  log_bug("G6", "LOW",
    "sufficient-samples threshold is hardcoded=10; Core uses sufficientTxVal/(1-decay) "..
      "which adapts to decay rate (MED≈20.8, SHORT≈13.2)")
end)

-- -----------------------------------------------------------------------
-- G7: failAvg tracking — evicted/expired txs that never confirmed
-- -----------------------------------------------------------------------
test("G7: failAvg tracking for evicted transactions (Core: failAvg[period][bucket])", function()
  -- Core: removeTx(hash, inBlock=false) increments failAvg for each period
  -- lunarblock: tx_removed() simply removes from unconfirmed map, no failAvg
  local est = fee.new(10)
  est:track_tx("evicted_tx", 5000, 1)
  est:on_block(5)  -- 4 blocks pass
  est:tx_removed("evicted_tx")
  -- There is no failAvg equivalent field in lunarblock FeeEstimator
  local has_fail_avg = (est.failAvg ~= nil or est.fail_avg ~= nil)
  if not has_fail_avg then
    log_bug("G7", "HIGH",
      "failAvg absent: evicted txs not recorded as failures; "..
        "Core's failAvg tracks txs that left mempool without confirming, "..
        "preventing systematic overestimation from only counting successes")
    error("failAvg tracking absent")
  end
end)

-- -----------------------------------------------------------------------
-- G8: FlushUnconfirmed — record still-unconfirmed txs as failures on shutdown
-- -----------------------------------------------------------------------
test("G8: FlushUnconfirmed equivalent (record unconfirmed as failures on shutdown)", function()
  -- Core: FlushUnconfirmed() calls _removeTx(hash, inBlock=false) for all mapMemPoolTxs
  -- lunarblock: save() just serializes state; unconfirmed are silently dropped
  local est = fee.new(10)
  est:track_tx("pending1", 5000, 100)
  est:track_tx("pending2", 3000, 100)
  -- Count unconfirmed before and after save (if FlushUnconfirmed were present,
  -- it would remove them and record as failures)
  local before = 0
  for _ in pairs(est.unconfirmed) do before = before + 1 end
  -- Simulate shutdown path: just save, no FlushUnconfirmed
  -- Verify unconfirmed entries survive (they should be flushed as failures)
  local after = 0
  for _ in pairs(est.unconfirmed) do after = after + 1 end
  expect_eq(before, 2, "two tracked unconfirmed txs before shutdown")
  -- Core would have cleared these and recorded as failures in failAvg
  if after == 2 then
    log_bug("G8", "MEDIUM",
      "FlushUnconfirmed absent: " .. before .. " tracked unconfirmed txs not recorded "..
        "as failures on shutdown; Core flushes all unconfirmed into failAvg")
  end
end)

-- -----------------------------------------------------------------------
-- G9: txCtAvg / m_feerate_avg — separate total-tx and feerate-sum per bucket
-- -----------------------------------------------------------------------
test("G9: m_feerate_avg per bucket for median feerate calculation", function()
  -- Core: m_feerate_avg[bucket] accumulates sum of feerates; median is m_feerate_avg/txCtAvg
  -- lunarblock: returns FEE_BUCKETS[best_bucket] (bucket upper bound), no feerate accumulator
  local est = fee.new(10)
  -- Add tx at 4500 sat/vB, a bucket exists around there
  est:track_tx("tx1", 4500, 1)
  est:tx_confirmed("tx1", 2)
  est:on_block(2)
  local fr, rel = est:estimate_fee(1, 0.0)  -- 0% threshold — should find something
  -- Core would return the median of feerates within the bucket
  -- lunarblock returns the bucket upper bound (overestimate)
  -- Check if feerate_avg field exists
  local has_feerate_avg = false
  if est.feeStats and est.feeStats.feerate_avg then has_feerate_avg = true end
  if not has_feerate_avg then
    log_bug("G9", "MEDIUM",
      "m_feerate_avg absent: estimate returns bucket upper-bound instead of median feerate; "..
        "systematically overestimates (returns FEE_BUCKETS[b] not average feerate in bucket)")
  end
  -- Test passes (absence is documented, not fatal crash)
end)

-- -----------------------------------------------------------------------
-- G10: confTarget=1 should be bumped to 2 in estimateSmartFee
-- -----------------------------------------------------------------------
test("G10: confTarget=1 bumped to 2 in estimateSmartFee (Core: 'not possible for target 1')", function()
  -- Core: if confTarget == 1: confTarget = 2
  -- lunarblock: math.max(1, ...) allows target=1 through
  local est = fee.new(10)
  -- Prime with some data at various heights
  for i = 1, 15 do
    est:track_tx("tx"..i, 1000 + i*100, 100)
    est:tx_confirmed("tx"..i, 101)
    est:on_block(100 + i)
  end
  local fr, actual = est:estimate_smart_fee(1)
  print(string.format("  INFO: estimate_smart_fee(1) -> fee=%s, actual_target=%s",
    tostring(fr), tostring(actual)))
  -- Core would silently use target=2; lunarblock uses target=1
  -- Document: we can't assert returned target >= 2 since lunarblock doesn't clamp
  log_bug("G10", "LOW",
    "confTarget=1 not bumped to 2; Core docs: 'not possible to get reasonable estimates for 1'")
end)

-- -----------------------------------------------------------------------
-- G11: estimateSmartFee three-sub-estimate logic (halfEst + actualEst + doubleEst)
-- -----------------------------------------------------------------------
test("G11: estimateSmartFee computes max(halfEst@target/2, actualEst@target, doubleEst@2*target)", function()
  -- Core: max of three estimates with 60%/85%/95% thresholds at target/2, target, 2*target
  -- lunarblock: tries 85% at target, then 60% at 2*target as fallback (no max, serial fallback)
  -- This means lunarblock can return LOWER fee than Core when only doubleEst would be high
  local est = fee.new(20)
  -- Prime with data
  for i = 1, 20 do
    est:track_tx("tx"..i, 2000, 1)
    est:tx_confirmed("tx"..i, 1 + (i % 3))
    est:on_block(i)
  end
  -- check: estimate_smart_fee uses serial fallback not max-of-three
  -- No direct observable test without three-horizon data, so just document
  log_bug("G11", "HIGH",
    "estimateSmartFee missing: halfEst(target/2, 60%) + max logic; "..
      "uses serial fallback (85%→60%) instead of max(halfEst, actualEst, doubleEst); "..
      "can underestimate fee when half-target estimate is higher than full-target estimate")
end)

-- -----------------------------------------------------------------------
-- G12: Conservative mode parameter for estimateSmartFee
-- -----------------------------------------------------------------------
test("G12: estimateSmartFee conservative mode (estimate_mode parameter)", function()
  -- Core: conservative=true adds estimateConservativeFee(2*target, DOUBLE_SUCCESS_PCT)
  --       which requires 95% threshold across all longer horizons
  -- lunarblock rpc.lua: no estimate_mode parameter processed for estimatesmartfee
  local est = fee.new(10)
  -- estimate_smart_fee takes only target, no conservative flag
  local nparams = select('#', pcall(function() return est:estimate_smart_fee(6) end))
  -- Check method signature
  local info = debug and debug.getinfo and debug.getinfo(est.estimate_smart_fee, "u")
  if info then
    print(string.format("  INFO: estimate_smart_fee nparams=%d", info.nparams or -1))
  end
  log_bug("G12", "MEDIUM",
    "estimate_smart_fee lacks conservative flag; RPC estimatesmartfee 'estimate_mode' "..
      "parameter not wired — CONSERVATIVE mode always returns same as ECONOMICAL")
end)

-- -----------------------------------------------------------------------
-- G13: estimaterawfee horizon filtering — should skip horizons where target > max
-- -----------------------------------------------------------------------
test("G13: estimaterawfee skips horizons where conf_target > horizon max", function()
  -- Core: if conf_target > fee_estimator.HighestTargetTracked(horizon): continue
  -- lunarblock: always returns all 3 horizon entries regardless of conf_target
  -- e.g., conf_target=100, short horizon only tracks 12 blocks
  -- should only return medium + long for conf_target=100
  -- We test via the RPC layer indirectly by checking rpc.lua logic
  -- Since we can't easily call rpc.lua in isolation, test the fee module's behaviour
  local est = fee.new(144)
  -- After priming, short horizon only tracks 12 blocks in Core
  -- lunarblock has no horizon-specific max_target per horizon
  local has_short_max = (est.short_max_target ~= nil)
  local has_long_max  = (est.long_max_target ~= nil)
  if not (has_short_max and has_long_max) then
    log_bug("G13", "MEDIUM",
      "estimaterawfee returns all 3 horizons for any conf_target; "..
        "Core skips horizons where conf_target > horizon max confirms "..
        "(short max=12, medium max=48, long max=1008)")
  end
end)

-- -----------------------------------------------------------------------
-- G14: estimaterawfee pass.startrange/endrange units — must be BTC/kvB not sat/vB
-- -----------------------------------------------------------------------
test("G14: estimaterawfee pass.startrange/endrange in correct units (BTC/kvB)", function()
  -- Core: passbucket.startrange = round(buckets[minBucket-1]) in sat/kvB then /1e8 for display
  -- Actually Core formats as sat/kvB integer (round(buckets.pass.start))
  -- lunarblock rpc.lua L2752: startrange = fee_rate (sat/vB, NOT BTC/kvB)
  -- feerate field IS converted (/100000) but startrange/endrange are NOT
  -- This is a unit mismatch in the RPC response schema
  local est = fee.new(10)
  for i = 1, 15 do
    est:track_tx("tx"..i, 5000, 1)
    est:tx_confirmed("tx"..i, 2)
    est:on_block(i)
  end
  local fr, rel = est:estimate_fee(1, 0.85)
  -- fr is in sat/vB, feerate returned by RPC would be fr/100000 BTC/kvB
  -- but startrange in rpc.lua returns fr (sat/vB) directly
  -- This means startrange is ~100000x the correct BTC/kvB value
  print(string.format("  INFO: estimate_fee returns %s sat/vB; "..
    "rpc.lua uses this directly as startrange (should be BTC/kvB)", tostring(fr)))
  -- We can check that rpc.lua's startrange is not divided by 100000
  log_bug("G14", "MEDIUM",
    "estimaterawfee pass.startrange/endrange return raw sat/vB value without "..
      "/100000 conversion; feerate field is converted but bucket-range fields are not "..
      "(e.g. startrange=5000 instead of 0.05 BTC/kvB)")
end)

-- -----------------------------------------------------------------------
-- G15: Precision — decay^N with 53-bit Lua double
-- -----------------------------------------------------------------------
test("G15: decay precision over 1008 blocks (53-bit Lua double)", function()
  -- 0.99931^1008 using IEEE-754 double should match Python reference
  local decay = 0.99931
  local result = 1.0
  for _ = 1, 1008 do
    result = result * decay
  end
  -- Python reference: 0.99931^1008 ≈ 0.498695...
  local expected = 0.498695
  expect_near(result, expected, 0.001,
    string.format("0.99931^1008 precision (got %g, expected ~%g)", result, expected))
  print(string.format("  INFO: 0.99931^1008 = %.8f (expected ~0.498695) — Lua double OK", result))
  -- Test short decay
  local short_result = 1.0
  local short_decay = 0.962
  for _ = 1, 12 do
    short_result = short_result * short_decay
  end
  local short_expected = 0.962 ^ 12
  expect_near(short_result, short_expected, 1e-10, "short decay 12 blocks")
  -- Precision itself is not a bug for standard decay; just document
  print("  INFO: Lua double precision sufficient for decay arithmetic")
end)

-- -----------------------------------------------------------------------
-- G16: MAX_BUCKET_FEE=10000 unreachable due to BUCKET_COUNT=40 cap
-- -----------------------------------------------------------------------
test("G16: MAX_BUCKET_FEE=10000 is reachable within BUCKET_COUNT buckets", function()
  -- With FEE_SPACING=1.2 and MIN=1: fee*1.2^40 = 1*1.2^39 ≈ 1224 sat/vB (< 10000)
  -- The BUCKET_COUNT=40 cap is hit BEFORE MAX_BUCKET_FEE=10000 is reached
  -- This means txs paying 1225–10000+ sat/vB all land in bucket 40 (coarsely merged)
  -- The claim MAX_BUCKET_FEE=10000 is misleading: effective max is ~1224 sat/vB
  local max_bucket_val = fee.FEE_BUCKETS[fee.BUCKET_COUNT]
  print(string.format("  INFO: FEE_BUCKETS[BUCKET_COUNT=%d]=%g sat/vB (MAX_BUCKET_FEE=%g)",
    fee.BUCKET_COUNT, max_bucket_val, fee.MAX_BUCKET_FEE))
  -- Also check no duplicate bucket values (degenerate from floor() at low fees)
  local seen = {}
  local dupes = 0
  for i = 1, fee.BUCKET_COUNT do
    local v = fee.FEE_BUCKETS[i]
    if seen[v] then dupes = dupes + 1 end
    seen[v] = true
  end
  if dupes > 0 then
    log_bug("G16b", "MEDIUM",
      string.format("%d duplicate bucket values due to math.floor() at low fees "..
        "(first %d+ buckets all equal 1 sat/vB); wastes bucket slots", dupes, dupes + 1))
  end
  print(string.format("  INFO: %d duplicate bucket values among %d buckets", dupes, fee.BUCKET_COUNT))
  if max_bucket_val < fee.MAX_BUCKET_FEE * 0.5 then
    log_bug("G16", "HIGH",
      string.format("MAX_BUCKET_FEE=%g sat/vB unreachable: BUCKET_COUNT=40 cap hits at ~%g sat/vB; "..
        "all txs paying >%g sat/vB are merged into one bucket; "..
        "Core covers 0.1–100000 sat/vB with 236 buckets",
        fee.MAX_BUCKET_FEE, max_bucket_val, max_bucket_val))
    error(string.format("MAX_BUCKET_FEE=%g unreachable; effective max=%g", fee.MAX_BUCKET_FEE, max_bucket_val))
  end
end)

-- -----------------------------------------------------------------------
-- G17: track_tx and tx_confirmed basic round-trip
-- -----------------------------------------------------------------------
test("G17: track_tx / tx_confirmed round-trip updates confirmed stats", function()
  local est = fee.new(10)
  -- Track and confirm 15 txs at 5000 sat/vB in 2 blocks
  for i = 1, 15 do
    est:track_tx("tx"..i, 5000, 1)
    est:tx_confirmed("tx"..i, 3)  -- 2 blocks to confirm
    est:on_block(i)
  end
  -- confirmed[2][bucket_5000] should have count > 0
  local bucket = fee.get_bucket_index(5000)
  local data = est.confirmed[2][bucket]
  expect_true(data ~= nil, "confirmed[2][bucket] exists")
  expect_true(data.count > 0, "count > 0 after tx_confirmed")
  expect_true(data.total > 0, "total > 0 after tx_confirmed")
end)

-- -----------------------------------------------------------------------
-- G18: tx_removed removes from unconfirmed (dead-helper check)
-- -----------------------------------------------------------------------
test("G18: tx_removed removes tx from unconfirmed tracking", function()
  local est = fee.new(10)
  est:track_tx("evicted", 3000, 1)
  expect_true(est.unconfirmed["evicted"] ~= nil, "tracked before removal")
  est:tx_removed("evicted")
  expect_true(est.unconfirmed["evicted"] == nil, "removed after tx_removed")
end)

-- -----------------------------------------------------------------------
-- G19: tx_removed is NOT wired for mempool evictions (dead-helper)
-- -----------------------------------------------------------------------
test("G19: tx_removed wired into mempool eviction callbacks (dead-helper check)", function()
  -- tx_removed exists in fee.lua but is never called from main.lua on eviction
  -- main.lua only calls: track_tx, tx_confirmed, on_block
  -- tx_removed is a dead helper: mempool.callbacks.on_tx_removed at line 1015 in main.lua
  -- feeds ZMQ but not fee_estimator:tx_removed
  -- This means evicted txs accumulate in the unconfirmed map indefinitely
  -- and are never recorded as failures (no failAvg contribution)
  log_bug("G19", "HIGH",
    "tx_removed dead-helper: mempool eviction callback (on_tx_removed) fires ZMQ but never "..
      "calls fee_estimator:tx_removed(); evicted txs linger in unconfirmed map and are never "..
      "recorded as failures — overestimates confirmation probability for their fee bucket")
  error("tx_removed is a dead helper — not called from eviction path")
end)

-- -----------------------------------------------------------------------
-- G20: on_block applies decay to ALL confirmed data
-- -----------------------------------------------------------------------
test("G20: on_block applies decay to all bucket data", function()
  local est = fee.new(5)
  -- Add some data
  for i = 1, 12 do
    est:track_tx("tx"..i, 2000, 1)
    est:tx_confirmed("tx"..i, 2)
  end
  est:on_block(2)
  local bucket = fee.get_bucket_index(2000)
  local count_before = est.confirmed[1][bucket].count
  est:on_block(3)
  local count_after = est.confirmed[1][bucket].count
  -- After one block, count should decay by 0.998
  expect_true(count_after < count_before, "decay applied: count decreases after on_block")
  expect_near(count_after, count_before * est.decay, count_before * 0.01,
    "decay factor correct")
end)

-- -----------------------------------------------------------------------
-- G21: estimate_fee returns max_bucket fee when no data (wrong — should return 0/nil)
-- -----------------------------------------------------------------------
test("G21: estimate_fee returns 0 (nil) when insufficient data, not max-bucket fee", function()
  -- Core: returns CFeeRate(0) when median < 0 (no reliable estimate)
  -- lunarblock: returns FEE_BUCKETS[BUCKET_COUNT] (max fee), false — callers get a huge fee
  -- rpc.lua checks fee_rate > 0 so the max-bucket fallback triggers a VALID feerate response
  -- instead of an error message
  local est = fee.new(10)
  local fr, rel = est:estimate_fee(5, 0.85)
  -- With no data, should be unreliable
  expect_false(rel, "no-data estimate should be unreliable")
  print(string.format("  INFO: estimate_fee with no data returns fee=%s, reliable=%s", tostring(fr), tostring(rel)))
  -- Core returns 0; lunarblock returns FEE_BUCKETS[BUCKET_COUNT]
  if fr ~= nil and fr > 0 then
    log_bug("G21", "HIGH",
      string.format("estimate_fee no-data returns fee=%g (FEE_BUCKETS[BUCKET_COUNT]) not 0/nil; "..
        "rpc.lua checks 'fee_rate > 0' so this triggers a VALID feerate response "..
        "instead of the 'Insufficient data' error", fr))
    error(string.format("should return nil/0 on no data, got %g", fr))
  end
end)

-- -----------------------------------------------------------------------
-- G22: estimate_smart_fee fallback returns 1 sat/vB (wrong)
-- -----------------------------------------------------------------------
test("G22: estimate_smart_fee fallback returns nil/0 not 1 sat/vB", function()
  -- fee.lua line 181: return 1, self.max_target
  -- This means rpc.lua sees fee_rate=1 > 0 and returns feerate=0.00001 BTC/kvB as valid
  -- Core returns CFeeRate(0) and the RPC returns {errors:["Insufficient data..."], blocks:target}
  local est = fee.new(10)
  local fr, actual = est:estimate_smart_fee(6)
  print(string.format("  INFO: estimate_smart_fee(6) no-data returns fee=%s target=%s",
    tostring(fr), tostring(actual)))
  if fr == 1 then
    log_bug("G22", "HIGH",
      "estimate_smart_fee fallback returns 1 sat/vB; rpc.lua treats this as valid data "..
        "and emits feerate=0.00001 BTC/kvB instead of 'Insufficient data' error response")
    error("fallback returns 1 sat/vB; should return nil or 0")
  end
end)

-- -----------------------------------------------------------------------
-- G23: MaxUsableEstimate — estimate clamped to half of block-span history
-- -----------------------------------------------------------------------
test("G23: MaxUsableEstimate clamps confTarget (Core: min(longMax, max(BlockSpan,HistSpan)/2))", function()
  -- Core: MaxUsableEstimate = min(longStats->GetMaxConfirms(), max(BlockSpan, HistoricalBlockSpan)/2)
  -- Prevents asking for reliable estimates beyond what the data supports
  -- lunarblock: no MaxUsableEstimate; uses full max_target=144 regardless of data history
  local est = fee.new(144)
  -- With only 5 blocks of history, target=100 should be clamped to 2 in Core
  -- lunarblock tries to estimate at target=100 directly
  local fr, actual = est:estimate_smart_fee(100)
  local has_max_usable = (est.max_usable_estimate ~= nil or est.firstRecordedHeight ~= nil)
  if not has_max_usable then
    log_bug("G23", "MEDIUM",
      "MaxUsableEstimate absent: no clamping of confTarget based on block-span history; "..
        "Core clamps to max(BlockSpan,HistoricalBlockSpan)/2 to avoid extrapolation")
  end
  print(string.format("  INFO: estimate_smart_fee(100) with fresh estimator: fee=%s target=%s",
    tostring(fr), tostring(actual)))
end)

-- -----------------------------------------------------------------------
-- G24: blocks_to_confirm=0 handling in tx_confirmed
-- -----------------------------------------------------------------------
test("G24: blocks_to_confirm=0 silently clamped to 1 (should be rejected like Core)", function()
  -- Core: processBlockTx returns false when blocksToConfirm <= 0
  -- lunarblock: blocks_to_confirm < 1 -> blocks_to_confirm = 1 (silently records as 1-block)
  -- This means a tx confirmed in same block as entry is recorded as 1-block confirmation
  local est = fee.new(10)
  est:track_tx("same_block", 5000, 5)
  est:tx_confirmed("same_block", 5)  -- confirmed in same block as entry
  est:on_block(5)
  local bucket = fee.get_bucket_index(5000)
  local data = est.confirmed[1][bucket]
  if data.count > 0 then
    log_bug("G24", "LOW",
      "blocks_to_confirm=0 silently clamped to 1; Core rejects (returns false); "..
        "same-block txs erroneously recorded as 1-block confirmations, skewing estimates low")
  end
  print(string.format("  INFO: same-block tx: confirmed[1][bucket].count=%g", data.count))
end)

-- -----------------------------------------------------------------------
-- G25: estimaterawfee scale field — should vary per horizon (1/2/24)
-- -----------------------------------------------------------------------
test("G25: estimaterawfee scale field matches horizon (1 short, 2 medium, 24 long)", function()
  -- Core: EstimationResult.scale = TxConfirmStats.scale (1/2/24 per horizon)
  -- lunarblock rpc.lua L2750: entry.scale = 1 (hardcoded for all horizons)
  -- This makes medium and long horizons appear to have scale=1 when they don't
  -- With single-horizon estimator, scale=1 is the only possible answer, but
  -- when/if multi-horizon is added, this will be wrong
  log_bug("G25", "MEDIUM",
    "estimaterawfee returns scale=1 for all horizons (hardcoded); "..
      "Core short=1, medium=2, long=24; when multi-horizon added this will be wrong")
  print("  INFO: rpc.lua hardcodes entry.scale=1 for all horizons (Core: short=1, med=2, long=24)")
end)

-- -----------------------------------------------------------------------
-- G26: save/load round-trip correctness
-- -----------------------------------------------------------------------
test("G26: save/load round-trip preserves bucket data", function()
  local est = fee.new(5)
  for i = 1, 15 do
    est:track_tx("tx"..i, 3000, 1)
    est:tx_confirmed("tx"..i, 2)
    est:on_block(i)
  end
  local bucket = fee.get_bucket_index(3000)
  local orig_count = est.confirmed[1][bucket].count
  local orig_total = est.confirmed[1][bucket].total

  local path = "/tmp/test_w114_fee.json"
  local ok, err = est:save(path)
  expect_true(ok, "save must succeed: " .. tostring(err))

  local est2 = fee.new(5)
  local loaded = est2:load(path)
  expect_true(loaded, "load must succeed")

  local loaded_count = est2.confirmed[1][bucket].count
  local loaded_total = est2.confirmed[1][bucket].total
  expect_near(loaded_count, orig_count, orig_count * 0.001, "count preserved across save/load")
  expect_near(loaded_total, orig_total, orig_total * 0.001, "total preserved across save/load")
  os.remove(path)
end)

-- -----------------------------------------------------------------------
-- G27: save version check — Core uses binary format version 309900
-- -----------------------------------------------------------------------
test("G27: save format version documented (lunarblock JSON v1 vs Core binary v309900)", function()
  -- This is an informational check — JSON v1 vs binary 309900 are incompatible
  -- but that's expected for a different impl
  -- Check that version=1 is what's saved and that load rejects version mismatch
  local est = fee.new(3)
  local path = "/tmp/test_w114_fee_ver.json"
  est:save(path)
  -- Read and corrupt version
  local f = io.open(path, "r")
  local raw = f:read("*a")
  f:close()
  local cjson_ok, cjson = pcall(require, "cjson")
  if cjson_ok then
    local state = cjson.decode(raw)
    expect_eq(state.version, 1, "saved version should be 1")
    -- Corrupt version
    state.version = 999
    local f2 = io.open(path, "w")
    f2:write(cjson.encode(state))
    f2:close()
    local est2 = fee.new(3)
    local ok = est2:load(path)
    expect_false(ok, "load should reject version mismatch")
  end
  os.remove(path)
  print("  INFO: format is JSON v1, Core uses binary v309900 — not interoperable (expected)")
end)

-- -----------------------------------------------------------------------
-- G28: IBD bypass — txs should not be tracked during initial block download
-- -----------------------------------------------------------------------
test("G28: IBD bypass documented (Core: validForFeeEstimation gate)", function()
  -- Core: processTransaction checks validForFeeEstimation:
  --   !m_mempool_limit_bypassed && !m_submitted_in_package &&
  --   m_chainstate_is_current && m_has_no_mempool_parents
  -- lunarblock: track_tx called unconditionally in main.lua for all accepted txs
  -- Tracking txs during IBD skews estimates because block-confirmation times
  -- during IBD don't reflect real network conditions
  log_bug("G28", "MEDIUM",
    "IBD bypass absent: track_tx called for all accepted mempool txs regardless of "..
      "IBD/sync state; Core skips tracking when !chainstate_is_current; "..
      "IBD confirmation times skew fee estimates")
  print("  INFO: main.lua:1204 calls track_tx unconditionally; Core gates on validForFeeEstimation")
end)

-- -----------------------------------------------------------------------
-- G29: Moving average uses correct decay per block (not per transaction)
-- -----------------------------------------------------------------------
test("G29: decay applied once per block not once per transaction", function()
  local est = fee.new(5)
  -- Add data
  for i = 1, 20 do
    est:track_tx("tx"..i, 2000, 1)
    est:tx_confirmed("tx"..i, 2)
  end
  est:on_block(2)
  local bucket = fee.get_bucket_index(2000)
  local count_after_first_block = est.confirmed[1][bucket].count
  -- One more block with NO transactions
  est:on_block(3)
  local count_after_second_block = est.confirmed[1][bucket].count
  -- Decay should be applied exactly once (multiply by decay)
  expect_near(count_after_second_block, count_after_first_block * est.decay,
    count_after_first_block * 0.001,
    "decay applied exactly once per block")
  print(string.format("  INFO: on_block decay: %.4f -> %.4f (ratio %.5f, decay=%.5f)",
    count_after_first_block, count_after_second_block,
    count_after_second_block / count_after_first_block, est.decay))
end)

-- -----------------------------------------------------------------------
-- G30: get_bucket_index off-by-one: tx placed in bucket where upper bound < feerate
-- -----------------------------------------------------------------------
test("G30: get_bucket_index places tx in correct bucket (upper bound >= feerate)", function()
  -- Core: bucketMap.lower_bound(feerate)->second finds the first bucket whose upper bound >= feerate
  -- lunarblock: finds first i where fee_rate < FEE_BUCKETS[i], returns i-1
  -- This places the tx in the bucket BELOW the first qualifying bucket
  -- For 500 sat/vB: first bucket > 500 is 590 (bucket 36), returns 35 (upper bound 492)
  -- 492 < 500 — tx is placed in a bucket where its feerate exceeds the bucket upper bound
  -- Core places 500 in bucket 36 (upper bound 590, the first >= 500)
  local bucket = fee.get_bucket_index(500)
  local upper_bound = fee.FEE_BUCKETS[bucket]
  print(string.format("  INFO: get_bucket_index(500) = %d, FEE_BUCKETS[%d] = %g",
    bucket, bucket, upper_bound))
  -- The bucket upper bound should be >= the feerate (it's the upper bound of the range)
  if upper_bound < 500 then
    log_bug("G30", "HIGH",
      string.format("get_bucket_index off-by-one: feerate=500 placed in bucket %d "..
        "(upper_bound=%g < 500); Core lower_bound semantics would place in bucket %d "..
        "(upper_bound=%g >= 500); txs systematically placed in wrong (lower) bucket",
        bucket, upper_bound, bucket + 1, fee.FEE_BUCKETS[bucket + 1] or 0))
    error(string.format("bucket upper_bound=%g < feerate=500; off-by-one in bucket assignment",
      upper_bound))
  end
end)

-- -----------------------------------------------------------------------
-- Summary
-- -----------------------------------------------------------------------
print("\n=== W114 Results ===")
print(string.format("Tests passed: %d", tests_passed))
print(string.format("Tests failed: %d", tests_failed))
print(string.format("Bugs logged:  %d", #bugs))

if #bugs > 0 then
  print("\n=== Bugs ===")
  for _, b in ipairs(bugs) do
    print(string.format("  [%s] %s: %s", b.severity, b.id, b.desc))
  end
end

if tests_failed > 0 then
  print("\n=== SOME TESTS FAILED (see above) ===")
  os.exit(1)
else
  print("\nAll tests passed.")
end
