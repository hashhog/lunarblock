--- Fee estimation engine
-- Tracks confirmation times for transactions and provides fee rate recommendations
-- Uses a bucketed approach similar to Bitcoin Core

local M = {}

-- Fee rate buckets in sat/vB, exponentially spaced
M.FEE_BUCKETS = {}
M.BUCKET_COUNT = 40
M.MIN_BUCKET_FEE = 1        -- 1 sat/vB
M.MAX_BUCKET_FEE = 10000    -- 10000 sat/vB
M.FEE_SPACING = 1.2         -- Exponential spacing factor

-- Generate buckets
do
  local fee = M.MIN_BUCKET_FEE
  for i = 1, M.BUCKET_COUNT do
    M.FEE_BUCKETS[i] = math.floor(fee)
    fee = fee * M.FEE_SPACING
    if fee > M.MAX_BUCKET_FEE then
      M.BUCKET_COUNT = i
      break
    end
  end
end

--- Get bucket index for a fee rate
-- @param fee_rate Fee rate in sat/vB
-- @return Bucket index (1-based)
function M.get_bucket_index(fee_rate)
  for i = 1, M.BUCKET_COUNT do
    if fee_rate < M.FEE_BUCKETS[i] then
      return math.max(1, i - 1)
    end
  end
  return M.BUCKET_COUNT
end

local FeeEstimator = {}
FeeEstimator.__index = FeeEstimator

--- Create a new FeeEstimator
-- @param max_target Maximum confirmation target in blocks (default 144)
-- @return FeeEstimator instance
function M.new(max_target)
  local self = setmetatable({}, FeeEstimator)
  self.max_target = max_target or 144  -- Max confirmation target in blocks
  -- For each target, track success/total counts per bucket
  -- confirmed[target][bucket] = {count, total}
  self.confirmed = {}
  for t = 1, self.max_target do
    self.confirmed[t] = {}
    for b = 1, M.BUCKET_COUNT do
      self.confirmed[t][b] = {count = 0, total = 0}
    end
  end
  -- Track unconfirmed transactions
  self.unconfirmed = {}  -- txid_hex -> {bucket, entry_height}
  self.best_height = 0
  -- Decay factor: exponentially weight recent data more heavily
  self.decay = 0.998
  return self
end

--- Track a new unconfirmed transaction
-- @param txid_hex Transaction ID in hex
-- @param fee_rate Fee rate in sat/vB
-- @param height Block height when transaction entered mempool
function FeeEstimator:track_tx(txid_hex, fee_rate, height)
  local bucket = M.get_bucket_index(fee_rate)
  self.unconfirmed[txid_hex] = {
    bucket = bucket,
    entry_height = height,
    fee_rate = fee_rate,
  }
end

--- Record that a transaction was confirmed
-- @param txid_hex Transaction ID in hex
-- @param confirmed_height Block height where transaction was confirmed
function FeeEstimator:tx_confirmed(txid_hex, confirmed_height)
  local info = self.unconfirmed[txid_hex]
  if not info then return end

  local blocks_to_confirm = confirmed_height - info.entry_height
  if blocks_to_confirm < 1 then blocks_to_confirm = 1 end
  if blocks_to_confirm > self.max_target then
    blocks_to_confirm = self.max_target
  end

  -- Record confirmation for all targets >= blocks_to_confirm
  for t = blocks_to_confirm, self.max_target do
    local bucket_data = self.confirmed[t][info.bucket]
    bucket_data.count = bucket_data.count + 1
    bucket_data.total = bucket_data.total + 1
  end

  -- Record failure for targets < blocks_to_confirm
  for t = 1, blocks_to_confirm - 1 do
    local bucket_data = self.confirmed[t][info.bucket]
    bucket_data.total = bucket_data.total + 1
  end

  self.unconfirmed[txid_hex] = nil
end

--- Remove a transaction from tracking (e.g., evicted from mempool)
-- @param txid_hex Transaction ID in hex
function FeeEstimator:tx_removed(txid_hex)
  self.unconfirmed[txid_hex] = nil
end

--- Process a new block, applying decay to historical data
-- @param height New best block height
function FeeEstimator:on_block(height)
  self.best_height = height
  -- Apply decay to all buckets
  for t = 1, self.max_target do
    for b = 1, M.BUCKET_COUNT do
      local d = self.confirmed[t][b]
      d.count = d.count * self.decay
      d.total = d.total * self.decay
    end
  end
end

--- Estimate fee rate for a confirmation target
-- @param target Desired confirmation in N blocks
-- @param success_threshold Minimum success rate (default 0.85 = 85%)
-- @return fee_rate Fee rate in sat/vB, reliable Whether estimate is reliable
function FeeEstimator:estimate_fee(target, success_threshold)
  success_threshold = success_threshold or 0.85
  target = math.min(target, self.max_target)
  target = math.max(target, 1)

  -- Walk buckets from highest to lowest fee rate
  -- Find the lowest bucket where the success rate >= threshold
  local best_bucket = M.BUCKET_COUNT
  local passed = false

  for b = M.BUCKET_COUNT, 1, -1 do
    local data = self.confirmed[target][b]
    if data.total >= 10 then  -- Need minimum sample size
      local rate = data.count / data.total
      if rate >= success_threshold then
        best_bucket = b
        passed = true
      else
        -- Once we drop below threshold at a higher fee, stop
        if passed then break end
      end
    end
  end

  if not passed then
    -- Not enough data, return a conservative estimate
    -- Use the highest bucket (very high fee rate)
    return M.FEE_BUCKETS[M.BUCKET_COUNT], false
  end

  return M.FEE_BUCKETS[best_bucket], true
end

--- Smart fee estimation with fallbacks
-- @param target Desired confirmation target in blocks
-- @return fee_rate Fee rate in sat/vB, actual_target Actual target used
function FeeEstimator:estimate_smart_fee(target)
  -- Try the requested target first, then relax if needed
  local fee, reliable = self:estimate_fee(target, 0.85)
  if reliable then
    return fee, target
  end

  -- Try double the target
  fee, reliable = self:estimate_fee(target * 2, 0.60)
  if reliable then
    return fee, target * 2
  end

  -- Fallback: use minimum relay fee
  return 1, self.max_target
end

return M
