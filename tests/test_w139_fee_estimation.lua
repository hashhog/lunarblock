#!/usr/bin/env luajit
-- W139 Fee Estimation Engine (CBlockPolicyEstimator) audit — lunarblock
-- Algorithmic-internal gates G1..G30 covering: file persistence (binary
-- version 309900, MAX_FILE_AGE stale-file guard, FEE_FLUSH_INTERVAL),
-- TxConfirmStats structure (m_feerate_avg, txCtAvg, oldUnconfTxs,
-- ClearCurrent circular buffer), three-horizon scales, EstimateMedianVal
-- range-merging with decay-adjusted threshold, failBucket emission,
-- failAvg consumption, estimateSmartFee max(half,full,double,conservative)
-- composition, MaxUsableEstimate history-aware clamp, FeeReason emission,
-- estimaterawfee per-horizon real bucket emission + unit semantics + horizon
-- skip + scale field, estimatesmartfee clamp to MinRelayFee/GetMinFee,
-- estimate_mode parameter, CValidationInterface reactor wiring, IBD/package/
-- chained-children gating, reorg handling, FlushUnconfirmed, FeeFilterRounder,
-- mempool-load seeding.
--
-- Distinct from W114 (test_w114_fee_estimation.lua) — W114 caught the surface
-- divergences (bucket count, decay constants, single-vs-three horizon); W139
-- exercises the algorithm internals and wiring layer.
--
-- Test framework: each xfail BODY asserts "Core feature is present".  When
-- the bug exists (feature absent) the assertion fails -> XFAIL.  When the fix
-- lands (feature present) the assertion passes -> XPASS (audit can retire bug).
--
-- Core refs:
--   bitcoin-core/src/policy/fees/block_policy_estimator.{h,cpp}
--   bitcoin-core/src/policy/fees/block_policy_estimator_args.{h,cpp}
--   bitcoin-core/src/policy/feerate.{h,cpp}
--   bitcoin-core/src/rpc/fees.cpp

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
local xfails = 0
local xpasses = 0
local bugs = {}

local function read_file(path)
  local f = io.open(path, "r")
  if not f then return "" end
  local src = f:read("*a")
  f:close()
  return src
end

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

-- An "xfail" test asserts the CORE FEATURE IS PRESENT.  When the bug is still
-- there (feature absent) the assertion fails → XFAIL (expected pre-fix).
-- When the fix has landed (feature present) the assertion passes → XPASS
-- (audit can retire the bug).
local function xfail(name, bug_id, severity, desc, fn)
  bugs[#bugs + 1] = {id = bug_id, severity = severity, desc = desc}
  local ok, err = pcall(fn)
  if not ok then
    print("XFAIL: " .. name .. " (" .. bug_id .. " " .. severity .. ")")
    xfails = xfails + 1
  else
    print("XPASS: " .. name .. " (" .. bug_id .. " " .. severity .. ") — fix has landed; retire bug")
    xpasses = xpasses + 1
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

local function expect_near(a, b, tol, msg)
  local d = math.abs(a - b)
  if d > tol then
    error((msg or "not near") .. string.format(": |%g - %g| = %g > tol %g", a, b, d, tol))
  end
end

print("=== W139 lunarblock Fee Estimation Engine Audit ===\n")

-- ---------------------------------------------------------------------------
-- G1 — binary fee_estimates.dat with CURRENT_FEES_FILE_VERSION = 309900
-- ---------------------------------------------------------------------------
xfail("G1: fee_estimates.dat binary v309900 layout", "BUG-1", "P2",
  "save() writes JSON v1; Core writes binary i32(309900) header + nBestSeenHeight "..
  "+ {first,best}RecordedHeight + buckets + feeStats + shortStats + longStats", function()
  local est = fee.new(10)
  local path = "/tmp/test_w139_g1.dat"
  est:save(path)
  local f = io.open(path, "rb")
  local first4 = f:read(4)
  f:close()
  os.remove(path)
  -- Binary 309900 LE = 0x4C 0x8A 0x04 0x00
  -- JSON starts with '{' (0x7B)
  local b0 = string.byte(first4, 1)
  -- ASSERT: file is binary (b0 == 0x4C from LE 309900) OR at minimum NOT JSON
  if b0 == 0x7B then
    error("file starts with JSON '{' (0x7B); Core binary starts with LE i32 309900 (0x4C...)")
  end
end)

-- ---------------------------------------------------------------------------
-- G2 — MAX_FILE_AGE = 60h stale guard on load
-- ---------------------------------------------------------------------------
xfail("G2: load() refuses stale fee_estimates.dat (> 60h)", "BUG-2", "P1",
  "Core refuses to load a fee file older than MAX_FILE_AGE=60h unless "..
  "DEFAULT_ACCEPT_STALE_FEE_ESTIMATES=true; lunarblock load() has no age check", function()
  local est1 = fee.new(10)
  for i = 1, 15 do
    est1:track_tx("tx"..i, 5000, 1)
    est1:tx_confirmed("tx"..i, 2)
    est1:on_block(i)
  end
  local path = "/tmp/test_w139_g2.dat"
  est1:save(path)
  -- Back-date to 100h ago (Jan 1 2026)
  os.execute("touch -t 202601010000 " .. path)
  local est2 = fee.new(10)
  local ok = est2:load(path)
  os.remove(path)
  -- ASSERT: load refuses stale file (Core behavior)
  if ok then
    error("load() accepted stale file > 60h old; Core refuses without -acceptstalefeeestimates")
  end
end)

-- ---------------------------------------------------------------------------
-- G3 — -acceptstalefeeestimates CLI override
-- ---------------------------------------------------------------------------
xfail("G3: -acceptstalefeeestimates CLI flag exists", "BUG-3", "P3",
  "Core has DEFAULT_ACCEPT_STALE_FEE_ESTIMATES=false toggle; lunarblock has no flag", function()
  local src = read_file("src/main.lua")
  -- ASSERT: flag is plumbed into main.lua argparse
  if not src:find("acceptstalefeeestimates") then
    error("-acceptstalefeeestimates flag absent from main.lua")
  end
end)

-- ---------------------------------------------------------------------------
-- G4 — FEE_FLUSH_INTERVAL = 1h periodic flush during running
-- ---------------------------------------------------------------------------
xfail("G4: fee_estimates flushed every 1h, not only on shutdown", "BUG-4", "P2",
  "Core has FEE_FLUSH_INTERVAL=1h scheduler call; lunarblock only saves at shutdown", function()
  local src = read_file("src/main.lua")
  -- ASSERT: a periodic flush call exists
  local has_periodic =
    src:find("FEE_FLUSH_INTERVAL") or
    src:find("FlushFeeEstimates") or
    (src:find("fee_estimator:save") and src:find("hour"))
  if not has_periodic then
    error("no periodic fee_estimator flush found (only shutdown-time save)")
  end
end)

-- ---------------------------------------------------------------------------
-- G5 — TxConfirmStats separate class
-- ---------------------------------------------------------------------------
xfail("G5: TxConfirmStats helper class with (decay, scale, maxPeriods)", "BUG-5", "P1",
  "Core has a TxConfirmStats class instantiated three times for short/med/long; "..
  "lunarblock has a single FeeEstimator with one decay/max_target", function()
  local est = fee.new(10)
  -- ASSERT: three separate stats objects exist
  local has_separated = (est.feeStats ~= nil and est.shortStats ~= nil and est.longStats ~= nil)
  if not has_separated then
    error("TxConfirmStats helper class with feeStats/shortStats/longStats absent")
  end
end)

-- ---------------------------------------------------------------------------
-- G6 — periodTarget = (confTarget + scale - 1) / scale ceiling division
-- ---------------------------------------------------------------------------
xfail("G6: scale-aware periodTarget ceiling rounding", "BUG-6", "P1",
  "Core: periodsToConfirm = (blocksToConfirm + scale - 1) / scale; "..
  "lunarblock records at raw 1-block granularity (no scale)", function()
  local est = fee.new(48)
  -- ASSERT: estimator carries a scale field
  local has_scale = (est.scale ~= nil) or (est.feeStats and est.feeStats.scale ~= nil)
  if not has_scale then
    error("no scale field on estimator (Core: SHORT_SCALE=1/MED_SCALE=2/LONG_SCALE=24)")
  end
end)

-- ---------------------------------------------------------------------------
-- G7 — ClearCurrent(nBlockHeight) circular-buffer roll
-- ---------------------------------------------------------------------------
xfail("G7: ClearCurrent unconfTxs[h%size][bucket] circular buffer", "BUG-7", "P1",
  "Core rolls per-block-of-entry circular buffer; "..
  "lunarblock on_block only decays, no per-entry-height tracking", function()
  local est = fee.new(10)
  -- ASSERT: unconfTxs[Y][X] circular-buffer field exists
  local has_circular = (est.unconfTxs ~= nil) or
                       (est.feeStats and est.feeStats.unconfTxs ~= nil)
  if not has_circular then
    error("unconfTxs[Y][X] circular buffer absent")
  end
end)

-- ---------------------------------------------------------------------------
-- G8 — oldUnconfTxs[bucket] carryover
-- ---------------------------------------------------------------------------
xfail("G8: oldUnconfTxs[bucket] carryover counter", "BUG-8", "P1",
  "Core: txs aged past GetMaxConfirms() land in oldUnconfTxs[bucket]; "..
  "lunarblock has no equivalent → extraNum always 0 in EstimateMedianVal", function()
  local est = fee.new(10)
  -- ASSERT: oldUnconfTxs[bucket] field exists
  local has_old = (est.oldUnconfTxs ~= nil) or (est.old_unconf_txs ~= nil) or
                  (est.feeStats and est.feeStats.oldUnconfTxs ~= nil)
  if not has_old then
    error("oldUnconfTxs[bucket] carryover counter absent")
  end
end)

-- ---------------------------------------------------------------------------
-- G9 — m_feerate_avg[bucket] sum-of-feerates for within-bucket median
-- ---------------------------------------------------------------------------
xfail("G9: m_feerate_avg[bucket] separate from txCtAvg; median = sum/count", "BUG-9", "P0",
  "Core accumulates m_feerate_avg[bucket] += feerate and reports "..
  "median = m_feerate_avg[j] / txCtAvg[j]; lunarblock returns "..
  "FEE_BUCKETS[best_bucket] (the bucket UPPER bound)", function()
  local est = fee.new(10)
  for i = 1, 15 do
    est:track_tx("tx"..i, 5100, 1)
    est:tx_confirmed("tx"..i, 2)
    est:on_block(i)
  end
  -- ASSERT: m_feerate_avg field present, OR estimate returns median (not upper bound)
  local has_field = (est.m_feerate_avg ~= nil) or
                    (est.feeStats and est.feeStats.feerate_avg ~= nil) or
                    (est.feeStats and est.feeStats.m_feerate_avg ~= nil)
  if not has_field then
    -- Also accept: estimate returns ~5100 (median) not FEE_BUCKETS[bucket] (upper)
    local fr, rel = est:estimate_fee(1, 0.5)
    local bucket = fee.get_bucket_index(5100)
    local upper = fee.FEE_BUCKETS[bucket]
    -- If lunarblock returned 5100 ± 5%, it found the median; if it returned upper, it didn't
    if not (fr and math.abs(fr - 5100) < 250) then
      error(string.format("estimate=%s ≠ median 5100 (~bucket upper %s); m_feerate_avg field also absent",
        tostring(fr), tostring(upper)))
    end
  end
end)

-- ---------------------------------------------------------------------------
-- G10 — txCtAvg[bucket] separate 1D total-tx counter
-- ---------------------------------------------------------------------------
xfail("G10: txCtAvg[bucket] decoupled from per-target confirmed[t][b]", "BUG-10", "P1",
  "Core has txCtAvg[bucket] as a single 1D array; lunarblock collapses "..
  "into confirmed[t][b].total so cross-target totals require summing", function()
  local est = fee.new(10)
  -- ASSERT: a separate 1D txCtAvg[bucket] field exists
  local has_field = (est.txCtAvg ~= nil) or (est.tx_ct_avg ~= nil) or
                    (est.feeStats and est.feeStats.txCtAvg ~= nil)
  if not has_field then
    error("txCtAvg[bucket] 1D counter absent (only 2D confirmed[t][b])")
  end
end)

-- ---------------------------------------------------------------------------
-- G11 — EstimateMedianVal range-merging with decay-adjusted threshold
-- ---------------------------------------------------------------------------
xfail("G11: range-merge buckets until partialNum >= sufficientTxVal/(1-decay)", "BUG-11", "P0",
  "Core merges adjacent buckets until enough samples; lunarblock skips "..
  "buckets with < 10 samples (hardcoded, not decay-adjusted)", function()
  local est = fee.new(10)
  -- Sparse data: 5 txs/bucket (< 10 lunarblock threshold), 3 ADJACENT but
  -- DISTINCT buckets (lower feerates where bucket spacing < 24%).
  -- Buckets 22/26/30 (feerates 46/95/197 sat/vB) are distinct buckets.
  -- Core would range-merge to 15 samples and produce a reliable estimate.
  -- lunarblock evaluates each bucket independently: each has only 5 samples,
  -- which is < its hardcoded 10-sample threshold → none pass → unreliable.
  for i = 1, 5 do
    est:track_tx("a"..i, 50, 1)
    est:tx_confirmed("a"..i, 2)
    est:track_tx("b"..i, 100, 1)
    est:tx_confirmed("b"..i, 2)
    est:track_tx("c"..i, 200, 1)
    est:tx_confirmed("c"..i, 2)
  end
  est:on_block(2)
  -- Verify 3 distinct buckets received the data
  local b_a = fee.get_bucket_index(50)
  local b_b = fee.get_bucket_index(100)
  local b_c = fee.get_bucket_index(200)
  if b_a == b_c then
    -- Sanity check: if buckets collapsed, the test premise breaks; abort the assertion.
    error("test premise broken: buckets collapsed (b_a="..b_a.." b_c="..b_c.."); cannot probe range-merge")
  end
  -- ASSERT: estimator returns a reliable estimate from merged buckets
  local fr, rel = est:estimate_fee(1, 0.85)
  if not rel then
    error("range-merging absent: 15 confirmed across 3 sparse buckets ("..
          b_a.."/"..b_b.."/"..b_c..") failed reliability test")
  end
end)

-- ---------------------------------------------------------------------------
-- G12 — EstimationResult.fail bucket
-- ---------------------------------------------------------------------------
xfail("G12: EstimationResult emits both pass and fail buckets", "BUG-12", "P1",
  "Core returns EstimationResult{pass, fail, decay, scale}; "..
  "lunarblock returns only (fee_rate, reliable)", function()
  local est = fee.new(10)
  for i = 1, 12 do
    est:track_tx("tx"..i, 5000, 1)
    est:tx_confirmed("tx"..i, 2)
    est:on_block(i)
  end
  -- ASSERT: third return value is an EstimationResult struct with pass+fail
  local fr, rel, result = est:estimate_fee(1, 0.85)
  if not (result and (result.pass or result.fail)) then
    error("estimate_fee returns no EstimationResult struct with pass+fail buckets")
  end
end)

-- ---------------------------------------------------------------------------
-- G13 — failAvg consumed in estimate_fee
-- ---------------------------------------------------------------------------
xfail("G13: failAvg subtracted from success rate in estimate_fee", "BUG-13", "P1",
  "Core: nConf / (totalNum + failNum + extraNum) >= successBreakPoint; "..
  "lunarblock estimate_fee uses confirmed[t][b].count/total only, "..
  "ignoring failAvg even though FIX-49 populates it", function()
  local est = fee.new(10)
  -- Pump 12 confirmed at bucket 5000 (just enough for the 10-sample threshold)
  for i = 1, 12 do
    est:track_tx("conf"..i, 5000, 1)
    est:tx_confirmed("conf"..i, 2)
  end
  est:on_block(2)
  -- Now pump 50 evicted at the SAME bucket — huge failAvg
  for i = 1, 50 do
    est:track_tx("evict"..i, 5000, 2)
  end
  est:on_block(5)
  for i = 1, 50 do
    est:tx_removed("evict"..i, "evicted")
  end
  -- ASSERT: estimate_fee returns unreliable because failAvg dominates
  -- Core: 12 / (12 + 50 + ~0) = ~19% success → far below 0.85 → unreliable
  -- lunarblock (bug): 12 / 12 = 100% → reliable
  local fr, rel = est:estimate_fee(1, 0.85)
  if rel then
    error("estimate marked reliable despite ~50/62 failAvg in bucket (failAvg ignored)")
  end
end)

-- ---------------------------------------------------------------------------
-- G14 — estimateSmartFee max(halfEst, fullEst, doubleEst, [consEst])
-- ---------------------------------------------------------------------------
xfail("G14: estimate_smart_fee computes max of half/full/double thresholds", "BUG-14", "P0",
  "Core: max(halfEst@target/2 60%, fullEst@target 85%, doubleEst@2*target 95%); "..
  "lunarblock falls back serially 85% → 60% → 1 sat/vB", function()
  local est = fee.new(20)
  -- ASSERT: estimate_smart_fee has the third "conservative" parameter
  local info = debug and debug.getinfo and debug.getinfo(est.estimate_smart_fee, "u")
  local nparams = (info and info.nparams) or 0
  -- nparams includes self; Core signature is estimateSmartFee(confTarget, *feeCalc, conservative)
  -- → in Lua self + target + conservative = 3
  if nparams < 3 then
    error(string.format("estimate_smart_fee has %d params; Core has (target, *result, conservative) ~3",
      nparams))
  end
end)

-- ---------------------------------------------------------------------------
-- G15 — confTarget==1 → 2 clamp
-- ---------------------------------------------------------------------------
xfail("G15: confTarget=1 bumped to 2 in estimate_smart_fee", "BUG-15", "P1",
  "Core: if confTarget == 1: confTarget = 2; lunarblock allows 1 through", function()
  local est = fee.new(10)
  for i = 1, 15 do
    est:track_tx("tx"..i, 5000, 1)
    est:tx_confirmed("tx"..i, 2)
    est:on_block(i)
  end
  local fr, target = est:estimate_smart_fee(1)
  -- ASSERT: returned target >= 2
  if target and target < 2 then
    error(string.format("estimate_smart_fee(1) returned target=%s; Core would clamp to 2", tostring(target)))
  end
end)

-- ---------------------------------------------------------------------------
-- G16 — MaxUsableEstimate clamps target to half of observed block history
-- ---------------------------------------------------------------------------
xfail("G16: MaxUsableEstimate clamps target to max(BlockSpan, HistoricalBlockSpan)/2", "BUG-16", "P1",
  "Core has firstRecordedHeight/historicalFirst/historicalBest fields and "..
  "uses them to clamp confTarget; lunarblock has none of these", function()
  local est = fee.new(144)
  -- ASSERT: BlockSpan tracking present (firstRecordedHeight or similar)
  local has_block_span = (est.firstRecordedHeight ~= nil) or (est.first_recorded_height ~= nil) or
                         (est.historicalFirst ~= nil) or (est.historical_first ~= nil)
  if not has_block_span then
    error("no firstRecordedHeight/historicalFirst — MaxUsableEstimate cannot clamp")
  end
end)

-- ---------------------------------------------------------------------------
-- G17 — FeeReason / FeeCalculation.reason emission
-- ---------------------------------------------------------------------------
xfail("G17: estimate_smart_fee returns a reason field (HALF/FULL/DOUBLE/CONSERVATIVE)", "BUG-17", "P2",
  "Core's FeeCalculation has a 'reason' enum so callers know which "..
  "sub-estimate produced the answer; lunarblock returns only (fee_rate, target)", function()
  local est = fee.new(10)
  for i = 1, 15 do
    est:track_tx("tx"..i, 5000, 1)
    est:tx_confirmed("tx"..i, 2)
    est:on_block(i)
  end
  local fr, target, reason = est:estimate_smart_fee(6)
  -- ASSERT: a reason value is returned
  if reason == nil then
    error("estimate_smart_fee returns no 'reason' value (Core: HALF_ESTIMATE/FULL_ESTIMATE/...)")
  end
end)

-- ---------------------------------------------------------------------------
-- G18 — estimaterawfee per-horizon real bucket emission
-- ---------------------------------------------------------------------------
xfail("G18: estimaterawfee emits real per-horizon pass.{startrange, endrange, withintarget, totalconfirmed, inmempool, leftmempool}", "BUG-18", "P0",
  "Core fills passbucket with round(buckets[minBucket-1]), round(buckets[maxBucket]), "..
  "and real counts; lunarblock synthesizes startrange=endrange=feerate (= the answer itself)", function()
  local src = read_file("src/rpc.lua")
  -- ASSERT: rpc.lua no longer synthesizes startrange = fee_rate
  if src:find("startrange = fee_rate") or src:find("endrange = fee_rate") then
    error("rpc.lua estimaterawfee still uses synthetic startrange = fee_rate (the answer)")
  end
end)

-- ---------------------------------------------------------------------------
-- G19 — startrange/endrange units (sat/kvB int not sat/vB)
-- ---------------------------------------------------------------------------
xfail("G19: estimaterawfee pass.startrange/endrange in sat/kvB integers", "BUG-19", "P1",
  "Core: round(buckets.pass.start) emits sat/kvB integer; "..
  "lunarblock emits fee_rate in sat/vB without /1000 conversion", function()
  local src = read_file("src/rpc.lua")
  -- ASSERT: rpc.lua converts startrange to sat/kvB or BTC/kvB
  if src:find("startrange = fee_rate$") or src:find("startrange = fee_rate,") then
    error("estimaterawfee startrange still in sat/vB (no /1000 or /100000 conversion)")
  end
end)

-- ---------------------------------------------------------------------------
-- G20 — estimaterawfee skips horizons where conf_target > max
-- ---------------------------------------------------------------------------
xfail("G20: estimaterawfee skips horizons where conf_target > horizon max", "BUG-20", "P2",
  "Core: if conf_target > HighestTargetTracked(horizon): continue; "..
  "lunarblock always emits all three horizon keys", function()
  local src = read_file("src/rpc.lua")
  -- ASSERT: rpc.lua has a horizon-skip check (e.g., "if conf_target > 12" for short, etc.)
  local has_skip =
    src:find("conf_target > 12") or       -- short max
    src:find("conf_target > 48") or       -- medium max
    src:find("conf_target > horizon") or
    src:find("HighestTargetTracked")
  if not has_skip then
    error("estimaterawfee always emits all 3 horizons; no conf_target > horizon-max skip")
  end
end)

-- ---------------------------------------------------------------------------
-- G21 — entry.scale = (1|2|24) per horizon
-- ---------------------------------------------------------------------------
xfail("G21: estimaterawfee entry.scale is 1/2/24 per horizon (not hardcoded 1)", "BUG-21", "P3",
  "Core: short=1, medium=2, long=24; lunarblock hardcodes 1", function()
  local src = read_file("src/rpc.lua")
  -- ASSERT: scale varies per horizon (look for medium=2 or long=24 assignment near entry.scale)
  -- Currently rpc.lua just does `entry.scale = 1`.  When fixed, should be a table lookup
  -- or conditional based on `name`.
  if src:match("entry%.scale = 1\n") and not src:find("entry%.scale = 24") then
    error("entry.scale hardcoded to 1 for all horizons; Core: short=1, medium=2, long=24")
  end
end)

-- ---------------------------------------------------------------------------
-- G22 — estimatesmartfee clamps to MinRelayFee/GetMinFee
-- ---------------------------------------------------------------------------
xfail("G22: estimatesmartfee clamps to max(answer, GetMinFee, MinRelayFee)", "BUG-22", "P0",
  "Core: feeRate = max({feeRate, mempool.GetMinFee(), min_relay_feerate}); "..
  "lunarblock returns raw estimator output", function()
  local src = read_file("src/rpc.lua")
  -- ASSERT: estimatesmartfee method invokes get_min_fee or min_relay_fee
  -- Find the estimatesmartfee method body
  local mstart = src:find('methods%["estimatesmartfee"%]')
  if not mstart then error("estimatesmartfee method not found") end
  local mend = src:find("methods%[", mstart + 1) or (mstart + 1500)
  local body = src:sub(mstart, math.min(mend, #src))
  local has_clamp = body:find("min_relay_fee") or body:find("get_min_fee") or
                    body:find("GetMinFee") or body:find("MinRelayFee")
  if not has_clamp then
    error("estimatesmartfee returns raw estimator output without min_relay_fee/get_min_fee clamp")
  end
end)

-- ---------------------------------------------------------------------------
-- G23 — estimate_mode parameter threaded to conservative= flag
-- ---------------------------------------------------------------------------
xfail("G23: estimatesmartfee reads params[2] estimate_mode and threads conservative=", "BUG-23", "P0",
  "Core: fee_mode in {ECONOMICAL, CONSERVATIVE, UNSET}; "..
  "lunarblock ignores params[2]", function()
  local src = read_file("src/rpc.lua")
  local mstart = src:find('methods%["estimatesmartfee"%]')
  if not mstart then error("estimatesmartfee method not found") end
  -- Find the matching end of this method (next "self.methods[" marker)
  local mend = src:find('self%.methods%[', mstart + 1) or (mstart + 1500)
  local body = src:sub(mstart, math.min(mend, #src))
  -- ASSERT: estimatesmartfee body reads params[2] OR processes estimate_mode
  -- Must be CODE (not just a comment); look for tokens unlikely to appear in docstrings:
  --   local <name> = params[2]      — assignment
  --   estimate_mode = ...           — variable assignment
  --   conservative =                — variable assignment
  --   :estimate_smart_fee(*, conservative)  — passed as arg
  local has_logic =
    body:find("local%s+%w+%s*=%s*params%[2%]") or
    body:find("estimate_mode%s*=") or
    body:find("conservative%s*=") or
    body:find("estimate_smart_fee%([^)]*,%s*[a-z_]+")  -- third positional arg
  if not has_logic then
    error("estimatesmartfee ignores params[2] estimate_mode (no conservative= or params[2] assignment)")
  end
end)

-- ---------------------------------------------------------------------------
-- G24 — CFeeRate ceiling rounding for relay floor on estimator input
-- ---------------------------------------------------------------------------
xfail("G24: estimator input fee_rate computed with ceiling division", "BUG-24", "P2",
  "Core: CFeeRate(fee, vsize) uses FeePerVSize then EvaluateFeeUp for relay-floor; "..
  "lunarblock mempool.lua:1289 uses float / for entry.fee_rate (≤1 sat/kvB drift)", function()
  local src = read_file("src/mempool.lua")
  -- ASSERT: entry.fee_rate uses ceiling rounding (math.ceil) on the relay path
  -- The W96 comment already mentions this for the dust threshold; we want it for entry.fee_rate too.
  local has_ceil_fee_rate =
    src:match("entry%.fee_rate.*math%.ceil") or
    src:match("fee_rate_per_kb = math%.ceil") or
    src:match("entry%.fee_rate = math%.ceil")
  if not has_ceil_fee_rate then
    error("entry.fee_rate computed with float division (math.ceil absent for fee_rate)")
  end
end)

-- ---------------------------------------------------------------------------
-- G25 — CValidationInterface contract names
-- ---------------------------------------------------------------------------
xfail("G25: engine driven by CValidationInterface reactor (TransactionAddedToMempool / MempoolTransactionsRemovedForBlock)", "BUG-25", "P2",
  "Core has 3 explicit reactor methods receiving NewMempoolTransactionInfo "..
  "and RemovedMempoolTransactionInfo with snapshotted fee/vsize/height; "..
  "lunarblock invokes from block_connected by recomputing txid", function()
  local src = read_file("src/fee.lua") .. read_file("src/main.lua")
  -- ASSERT: lunarblock has a method or call site named after one of the Core reactor methods
  local has_reactor =
    src:find("TransactionAddedToMempool") or
    src:find("MempoolTransactionsRemovedForBlock") or
    src:find("processTransaction") or
    src:find("transaction_added_to_mempool") or
    src:find("mempool_transactions_removed_for_block")
  if not has_reactor then
    error("no CValidationInterface-style reactor method; engine driven from on_block_connected callback")
  end
end)

-- ---------------------------------------------------------------------------
-- G26 — validForFeeEstimation gate (IBD / package / chained-children)
-- ---------------------------------------------------------------------------
xfail("G26: track_tx skipped when !chainstate_is_current || submitted_in_package || has_mempool_parents", "BUG-26", "P0",
  "Core: validForFeeEstimation = !mempool_limit_bypassed && !submitted_in_package "..
  "&& chainstate_is_current && has_no_mempool_parents; lunarblock track_tx is "..
  "unconditional in main.lua:1343", function()
  local src = read_file("src/main.lua")
  local idx = src:find("fee_estimator:track_tx")
  if not idx then error("track_tx call site not found in main.lua") end
  -- Check ±400 chars around the call for any validForFeeEstimation gate
  local window = src:sub(math.max(1, idx - 400), math.min(#src, idx + 200))
  -- ASSERT: a gating predicate exists near the call
  local gated =
    window:find("is_initial_block_download") or
    window:find("in_ibd") or
    window:find("chainstate_is_current") or
    window:find("has_no_mempool_parents") or
    window:find("submitted_in_package") or
    window:find("validForFeeEstimation") or
    window:find("valid_for_fee_estimation")
  if not gated then
    error("track_tx call is ungated (no IBD/package/parents check) at main.lua:1343")
  end
end)

-- ---------------------------------------------------------------------------
-- G27 — reorg / disconnect-tip handling
-- ---------------------------------------------------------------------------
xfail("G27: reorg-safe — disconnect rolls back tx_confirmed, no double-count on reconnect", "BUG-27", "P0",
  "Core: processBlock early-returns when nBlockHeight <= nBestSeenHeight; "..
  "lunarblock on_block_connected callback has no equivalent guard and no "..
  "on_block_disconnected hook into the fee estimator", function()
  local est = fee.new(10)
  -- ASSERT: estimator has a disconnect-tip-style method
  local has_disconnect = (est.tx_disconnected ~= nil) or
                         (est.on_block_disconnected ~= nil) or
                         (est.disconnect_tip ~= nil) or
                         (est.disconnect_block ~= nil) or
                         (est.processBlockDisconnect ~= nil)
  if not has_disconnect then
    error("no disconnect-tip API on fee estimator (txs from reorg'd block never un-recorded)")
  end
end)

-- ---------------------------------------------------------------------------
-- G28 — FlushUnconfirmed at shutdown
-- ---------------------------------------------------------------------------
xfail("G28: FlushUnconfirmed converts tracked unconfirmed → failAvg on shutdown/save", "BUG-28", "P1",
  "Core: FlushUnconfirmed loops mapMemPoolTxs calling _removeTx(inBlock=false) "..
  "before Write; lunarblock save() never touches unconfirmed", function()
  local est = fee.new(10)
  est:track_tx("pending1", 5000, 100)
  est:track_tx("pending2", 5000, 100)
  est:on_block(105)
  local bucket = fee.get_bucket_index(5000)
  local fail_before = (est.failAvg and est.failAvg[1] and est.failAvg[1][bucket] and
                       est.failAvg[1][bucket].count) or 0
  local path = "/tmp/test_w139_g28.json"
  est:save(path)
  os.remove(path)
  local fail_after = (est.failAvg and est.failAvg[1] and est.failAvg[1][bucket] and
                      est.failAvg[1][bucket].count) or 0
  -- ASSERT: save() promoted unconfirmed → failAvg (Core's FlushUnconfirmed behavior)
  if fail_after <= fail_before then
    error("save() did NOT promote unconfirmed to failAvg; FlushUnconfirmed absent")
  end
end)

-- ---------------------------------------------------------------------------
-- G29 — FeeFilterRounder primitive
-- ---------------------------------------------------------------------------
xfail("G29: FeeFilterRounder type with 1.1-spaced fee_set + insecure_rand 1-in-3 down-round", "BUG-29", "P1",
  "Core: FeeFilterRounder::round quantizes via MakeFeeSet seeded by min_incremental_fee "..
  "with privacy down-rounding; lunarblock has no FeeFilterRounder", function()
  local fee_mod = require("lunarblock.fee")
  -- ASSERT: a FeeFilterRounder symbol or method exists in fee module
  if not (fee_mod.FeeFilterRounder or fee_mod.fee_filter_rounder or
          fee_mod.fee_filter_round or fee_mod.MakeFeeSet) then
    error("FeeFilterRounder primitive absent from lunarblock.fee module")
  end
end)

-- ---------------------------------------------------------------------------
-- G30 — mempool-load seeds estimator on restart
-- ---------------------------------------------------------------------------
xfail("G30: mempool_persist load_mempool seeds fee_estimator via processTransaction", "BUG-30", "P1",
  "Core: TransactionAddedToMempool fires for every replayed-from-disk tx, "..
  "feeding the estimator; lunarblock fee_estimator init runs AFTER mempool "..
  "load but track_tx is only wired into the P2P tx handler (main.lua:1343), "..
  "not the load path (mempool_persist.lua)", function()
  local src = read_file("src/mempool_persist.lua")
  -- ASSERT: mempool_persist references fee_estimator
  if not (src:find("fee_estimator") or src:find("track_tx") or
          src:find("TransactionAddedToMempool")) then
    error("mempool_persist.lua does not seed the fee_estimator on load")
  end
end)

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
print("\n=== W139 Results ===")
print(string.format("Tests passed (real): %d", tests_passed))
print(string.format("Tests failed: %d", tests_failed))
print(string.format("XFAIL (expected pre-fix): %d", xfails))
print(string.format("XPASS (fix has landed, retire bug): %d", xpasses))
print(string.format("Bugs catalogued: %d", #bugs))

if #bugs > 0 then
  print("\n=== Bugs ===")
  local by_sev = {P0 = 0, P1 = 0, P2 = 0, P3 = 0}
  for _, b in ipairs(bugs) do
    by_sev[b.severity] = (by_sev[b.severity] or 0) + 1
    print(string.format("  [%s] %s: %s", b.severity, b.id, b.desc))
  end
  print(string.format("\nSeverity breakdown: P0=%d, P1=%d, P2=%d, P3=%d",
    by_sev.P0, by_sev.P1, by_sev.P2, by_sev.P3))
end

if tests_failed > 0 then
  print("\n=== SOME REAL TESTS FAILED (see above) ===")
  os.exit(1)
else
  print("\n(All xfails are EXPECTED to fail until fixes land. tests_failed counts only un-xfail'd failures.)")
end
