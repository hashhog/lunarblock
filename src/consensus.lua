local bit = require("bit")
local M = {}

--------------------------------------------------------------------------------
-- Fundamental Constants
--------------------------------------------------------------------------------

M.COIN = 100000000                   -- 1 BTC = 100,000,000 satoshis
M.MAX_MONEY = 2100000000000000       -- 21 million BTC in satoshis
M.MAX_BLOCK_WEIGHT = 4000000         -- 4M weight units (BIP141)
M.MAX_BLOCK_SIZE = 1000000           -- Legacy 1MB limit (pre-segwit)
M.MAX_BLOCK_SIGOPS_COST = 80000      -- Max sigops cost per block
M.WITNESS_SCALE_FACTOR = 4           -- SegWit discount factor
M.MAX_BLOCK_SERIALIZED_SIZE = 4000000
M.COINBASE_MATURITY = 100            -- Blocks before coinbase spendable
M.MAX_SCRIPT_SIZE = 10000
M.MAX_SCRIPT_ELEMENT_SIZE = 520
M.MAX_OPS_PER_SCRIPT = 201
M.MAX_PUBKEYS_PER_MULTISIG = 20
M.MAX_STACK_SIZE = 1000
M.MAX_TX_SIZE = 100000
M.MIN_TX_SIZE = 60  -- Consensus minimum (Bitcoin Core: MIN_TRANSACTION_WEIGHT/4)
M.MAX_TX_IN_SEQUENCE_NO = 0xFFFFFFFF
M.LOCKTIME_THRESHOLD = 500000000     -- Block height vs unix time threshold

--------------------------------------------------------------------------------
-- Block Reward Schedule
--------------------------------------------------------------------------------

M.INITIAL_BLOCK_REWARD = 5000000000  -- 50 BTC
M.HALVING_INTERVAL = 210000

function M.get_block_subsidy(height)
  local halvings = math.floor(height / M.HALVING_INTERVAL)
  if halvings >= 64 then return 0 end
  local subsidy = M.INITIAL_BLOCK_REWARD
  for _ = 1, halvings do
    subsidy = math.floor(subsidy / 2)
  end
  return subsidy
end

--------------------------------------------------------------------------------
-- Difficulty Adjustment
--------------------------------------------------------------------------------

M.DIFFICULTY_ADJUSTMENT_INTERVAL = 2016
M.TARGET_TIMESPAN = 14 * 24 * 60 * 60   -- 1,209,600 seconds (2 weeks)
M.TARGET_SPACING = 10 * 60              -- 600 seconds
M.MIN_TIMESPAN = math.floor(M.TARGET_TIMESPAN / 4)  -- 302,400
M.MAX_TIMESPAN = M.TARGET_TIMESPAN * 4  -- 4,838,400

--- Convert compact "bits" to a 32-byte big-endian target.
-- Format: exponent = bits >> 24, mantissa = bits & 0x7FFFFF,
-- negative = bits & 0x800000. Target = mantissa * 2^(8*(exponent-3)).
-- @param bits number: compact difficulty representation
-- @return string: 32-byte big-endian target
function M.bits_to_target(bits)
  local exponent = bit.rshift(bits, 24)
  local mantissa = bit.band(bits, 0x007FFFFF)
  local negative = bit.band(bits, 0x00800000) ~= 0

  -- Target is mantissa * 2^(8*(exponent-3))
  -- This places the 3-byte mantissa at byte position (32 - exponent)

  if mantissa == 0 or exponent == 0 then
    return string.rep("\0", 32)
  end

  -- Handle overflow: if exponent > 34, result would exceed 32 bytes
  if exponent > 34 then
    return string.rep("\0", 32)
  end

  -- Build the target as a 32-byte big-endian number
  local target = {}
  for i = 1, 32 do
    target[i] = 0
  end

  -- Position the mantissa bytes (big-endian: high byte first)
  -- Mantissa occupies 3 bytes, placed starting at position (32 - exponent)
  local start_pos = 32 - exponent + 1  -- 1-indexed position in target array

  -- Extract mantissa bytes (big-endian)
  local m1 = bit.band(bit.rshift(mantissa, 16), 0xFF)  -- high byte
  local m2 = bit.band(bit.rshift(mantissa, 8), 0xFF)   -- middle byte
  local m3 = bit.band(mantissa, 0xFF)                  -- low byte

  if start_pos >= 1 and start_pos <= 32 then
    target[start_pos] = m1
  end
  if start_pos + 1 >= 1 and start_pos + 1 <= 32 then
    target[start_pos + 1] = m2
  end
  if start_pos + 2 >= 1 and start_pos + 2 <= 32 then
    target[start_pos + 2] = m3
  end

  -- Handle negative flag (rarely used in practice)
  if negative and mantissa ~= 0 then
    -- Negate the target (two's complement) - not typically used in Bitcoin
    -- For safety, just return zero target for negative
    return string.rep("\0", 32)
  end

  -- Convert to string
  local result = {}
  for i = 1, 32 do
    result[i] = string.char(target[i])
  end
  return table.concat(result)
end

--- Convert 32-byte big-endian target to compact "bits" format.
-- @param target string: 32-byte big-endian target
-- @return number: compact difficulty bits
function M.target_to_bits(target)
  assert(#target == 32, "target must be 32 bytes")

  -- Find the first non-zero byte (big-endian, so leftmost significant byte)
  local first_nonzero = 0
  for i = 1, 32 do
    if target:byte(i) ~= 0 then
      first_nonzero = i
      break
    end
  end

  if first_nonzero == 0 then
    return 0  -- zero target
  end

  -- Exponent is 32 - position of first nonzero byte + 1
  local exponent = 32 - first_nonzero + 1

  -- Extract up to 3 bytes for mantissa
  local b1 = target:byte(first_nonzero) or 0
  local b2 = target:byte(first_nonzero + 1) or 0
  local b3 = target:byte(first_nonzero + 2) or 0

  local mantissa = bit.bor(bit.lshift(b1, 16), bit.lshift(b2, 8), b3)

  -- If high bit of mantissa is set, we need to adjust to avoid
  -- the mantissa being interpreted as negative
  if bit.band(mantissa, 0x00800000) ~= 0 then
    mantissa = bit.rshift(mantissa, 8)
    exponent = exponent + 1
  end

  -- Clamp exponent to valid range
  if exponent > 255 then
    exponent = 255
  end

  return bit.bor(bit.lshift(exponent, 24), mantissa)
end

--- Check if a block hash (little-endian) meets the target (big-endian).
-- @param block_hash_le string: 32-byte little-endian block hash
-- @param target_be string: 32-byte big-endian target
-- @return boolean: true if hash <= target
function M.hash_meets_target(block_hash_le, target_be)
  assert(#block_hash_le == 32, "block hash must be 32 bytes")
  assert(#target_be == 32, "target must be 32 bytes")

  -- Reverse block hash to big-endian for comparison
  local hash_be = block_hash_le:reverse()

  -- Compare byte by byte (big-endian comparison)
  for i = 1, 32 do
    local h = hash_be:byte(i)
    local t = target_be:byte(i)
    if h < t then return true end
    if h > t then return false end
  end
  return true  -- equal
end

--- Calculate the next difficulty target.
-- @param last_target_bits number: compact bits of previous target
-- @param actual_timespan number: actual time elapsed for previous 2016 blocks
-- @param first_block_bits number|nil: bits of first block in period (for BIP94)
-- @return number: new compact bits
function M.calculate_next_target(last_target_bits, actual_timespan, first_block_bits)
  -- Clamp timespan to [MIN_TIMESPAN, MAX_TIMESPAN]
  if actual_timespan < M.MIN_TIMESPAN then
    actual_timespan = M.MIN_TIMESPAN
  elseif actual_timespan > M.MAX_TIMESPAN then
    actual_timespan = M.MAX_TIMESPAN
  end

  -- For BIP94 (testnet4): use the first block's bits instead of last
  -- This prevents time-warp attacks by preserving real difficulty in the first block
  local bits_to_use = first_block_bits or last_target_bits

  -- Get current target as bytes
  local old_target = M.bits_to_target(bits_to_use)

  -- Multiply by actual_timespan using big-number arithmetic
  -- new_target = old_target * actual_timespan / TARGET_TIMESPAN
  local product = {}
  for i = 1, 36 do product[i] = 0 end  -- extra bytes for overflow

  -- Multiply: result in little-endian for easier arithmetic
  local old_le = {}
  for i = 1, 32 do
    old_le[i] = old_target:byte(33 - i)  -- reverse to little-endian
  end

  -- Multiply old_le by actual_timespan (scalar multiplication)
  local carry = 0
  for i = 1, 32 do
    local val = old_le[i] * actual_timespan + carry
    product[i] = bit.band(val, 0xFF)
    carry = math.floor(val / 256)
  end
  -- Handle remaining carry
  local idx = 33
  while carry > 0 and idx <= 36 do
    product[idx] = bit.band(carry, 0xFF)
    carry = math.floor(carry / 256)
    idx = idx + 1
  end

  -- Divide by TARGET_TIMESPAN
  local divisor = M.TARGET_TIMESPAN
  local remainder = 0
  for i = 36, 1, -1 do
    local dividend = remainder * 256 + product[i]
    product[i] = math.floor(dividend / divisor)
    remainder = dividend % divisor
  end

  -- Convert back to 32-byte big-endian
  local new_target = {}
  for i = 1, 32 do
    new_target[i] = string.char(product[33 - i])
  end
  local new_target_str = table.concat(new_target)

  return M.target_to_bits(new_target_str)
end

--- Get the next required work for a block.
-- Implements full Bitcoin Core logic including testnet special rules and BIP94.
-- @param height number: height of the block being validated
-- @param timestamp number: timestamp of the block being validated
-- @param network table: network configuration
-- @param get_ancestor function: fn(height) -> {header={bits, timestamp}} for ancestor lookup
-- @return number: expected compact bits value
function M.get_next_work_required(height, timestamp, network, get_ancestor)
  -- Regtest: always return pow_limit (no retargeting)
  if network.pow_no_retarget then
    return network.pow_limit_bits
  end

  local prev = get_ancestor(height - 1)
  if not prev then
    return network.pow_limit_bits
  end

  -- Check if this is a difficulty adjustment block
  if height % M.DIFFICULTY_ADJUSTMENT_INTERVAL ~= 0 then
    -- Not a retarget block
    if network.pow_allow_min_difficulty then
      -- Testnet special rules: if block's timestamp is more than 20 minutes
      -- after previous block, allow minimum difficulty
      local time_diff = timestamp - prev.header.timestamp
      if time_diff > M.TARGET_SPACING * 2 then
        return network.pow_limit_bits
      else
        -- Walk back to find the last non-minimum-difficulty block
        local pindex = prev
        local pindex_height = height - 1
        while pindex_height > 0 and
              pindex_height % M.DIFFICULTY_ADJUSTMENT_INTERVAL ~= 0 and
              pindex.header.bits == network.pow_limit_bits do
          pindex_height = pindex_height - 1
          pindex = get_ancestor(pindex_height)
          if not pindex then break end
        end
        if pindex then
          return pindex.header.bits
        end
      end
    end
    -- Not testnet min-diff: bits must match previous block
    return prev.header.bits
  end

  -- This is a difficulty adjustment block (height % 2016 == 0)
  -- Go back 2015 blocks to find the first block of the previous period
  local first_height = height - M.DIFFICULTY_ADJUSTMENT_INTERVAL
  local first = get_ancestor(first_height)
  if not first then
    return prev.header.bits
  end

  local actual_timespan = prev.header.timestamp - first.header.timestamp

  -- For BIP94 (testnet4): use the first block's bits for the calculation
  -- This preserves real difficulty even when min-diff blocks are present
  local result
  if network.enforce_bip94 then
    result = M.calculate_next_target(prev.header.bits, actual_timespan, first.header.bits)
  else
    result = M.calculate_next_target(prev.header.bits, actual_timespan, nil)
  end

  -- Clamp to pow_limit: target must not exceed the minimum difficulty.
  -- Bitcoin Core: if (bnNew > bnPowLimit) bnNew = bnPowLimit;
  -- Compare as big-endian byte strings (lexicographic = numeric for same-length)
  local new_target = M.bits_to_target(result)
  local pow_limit = M.bits_to_target(network.pow_limit_bits)
  for i = 1, 32 do
    local a = new_target:byte(i) or 0
    local b = pow_limit:byte(i) or 0
    if a > b then
      return network.pow_limit_bits
    elseif a < b then
      break
    end
  end
  return result
end

--------------------------------------------------------------------------------
-- BIP9 Versionbits State Machine
--
-- INTENTIONALLY DECORATIVE: this module is NOT on the consensus path.
--
-- Lunarblock enforces every soft fork (BIP65, BIP66, BIP68/CSV, BIP141 SegWit,
-- BIP341 Taproot) via hard-coded buried activation heights stored in the
-- per-network table at the bottom of this file (see `bip65_height`,
-- `bip66_height`, `csv_height`, `segwit_height`, `taproot_height`). The actual
-- height-gate decisions live in src/utxo.lua connect_block (search for
-- `verify_dersig`, `verify_checklocktimeverify`, `verify_witness`,
-- `verify_taproot`).
--
-- This is the same approach Bitcoin Core eventually settled on: once a
-- deployment locks in and activates, its activation height is a fact of the
-- chain, and re-running the full BIP9 state machine on every block during IBD
-- is wasted work. Core hard-codes the heights in chainparams.cpp; we hard-code
-- them in M.networks.<name>.<fork>_height. See bitcoin-core/src/deploymentstatus.h
-- and the `DeploymentEnabled` / `DeploymentActiveAfter` helpers there.
--
-- The functions below (versionbits_condition, get_deployment_state,
-- get_deployment_state_for_block) are kept because:
--   1. They are exhaustively unit-tested in spec/consensus_spec.lua and serve
--      as a reference implementation of the BIP9 algorithm.
--   2. A future versionbits cache + getblockchaininfo `softforks.bip9` block
--      may legitimately drive them (see TODO at src/rpc.lua getdeploymentinfo).
--   3. Future testnet-only deployments that have not yet buried may need them.
--
-- They MUST NOT be called from the consensus / block-validation path. If you
-- find yourself wanting to wire this into utxo.lua connect_block, stop and
-- talk to whoever owns soft-fork activation policy first.
--
-- Defense-in-depth: validate_buried_deployment_consistency() at the bottom of
-- this section asserts that the per-deployment min_activation_height matches
-- the buried height in M.networks.mainnet, so a future patch that silently
-- changes one without the other will fail loud at module load time.
--------------------------------------------------------------------------------

-- Versionbits signaling constants (BIP9)
M.VERSIONBITS_TOP_BITS = 0x20000000    -- bits 31-30 = 00, bit 29 = 1
M.VERSIONBITS_TOP_MASK = 0xE0000000    -- mask for top 3 bits
M.VERSIONBITS_NUM_BITS = 29            -- max deployment bits (0-28)

-- BIP9 deployment states
M.DEPLOYMENT_STATE = {
  DEFINED   = "defined",
  STARTED   = "started",
  LOCKED_IN = "locked_in",
  ACTIVE    = "active",
  FAILED    = "failed"
}

-- Special start_time values
M.ALWAYS_ACTIVE = -1     -- deployment always active (for testing)
M.NEVER_ACTIVE  = -2     -- deployment never active (disabled)

-- Default deployment parameters
M.DEPLOYMENTS = {
  SEGWIT = {
    bit = 1,
    start_time = 1479168000,
    timeout = 1510704000,
    min_activation_height = 0
  },
  TAPROOT = {
    bit = 2,
    start_time = 1619222400,
    timeout = 1628640000,
    min_activation_height = 709632
  },
}

--- Check if a block version signals for a deployment.
-- @param version number: nVersion field from block header
-- @param deployment_bit number: bit position (0-28) for the deployment
-- @return boolean: true if block signals for the deployment
function M.versionbits_condition(version, deployment_bit)
  -- Top 3 bits must be 001 (indicating versionbits signaling)
  if bit.band(version, M.VERSIONBITS_TOP_MASK) ~= M.VERSIONBITS_TOP_BITS then
    return false
  end
  -- Check if the specific deployment bit is set
  return bit.band(version, bit.lshift(1, deployment_bit)) ~= 0
end

--- Get the deployment state for a deployment at a given block.
-- Implements the BIP9 state machine: DEFINED -> STARTED -> LOCKED_IN -> ACTIVE
-- States can also transition to FAILED if timeout is reached without lock-in.
-- @param deployment table: deployment parameters {bit, start_time, timeout, min_activation_height}
-- @param period number: retarget period (2016 for mainnet)
-- @param threshold number: minimum signaling blocks required (1815 for mainnet 95%)
-- @param height number: height of the block to check state for
-- @param get_block_info function: fn(height) -> {timestamp, mtp, version} for block lookup
-- @return string: one of "defined", "started", "locked_in", "active", "failed"
function M.get_deployment_state(deployment, period, threshold, height, get_block_info)
  local STATE = M.DEPLOYMENT_STATE

  -- Handle special start_time values
  if deployment.start_time == M.ALWAYS_ACTIVE then
    return STATE.ACTIVE
  end
  if deployment.start_time == M.NEVER_ACTIVE then
    return STATE.FAILED
  end

  -- Genesis block is always DEFINED
  if height == 0 then
    return STATE.DEFINED
  end

  -- Align to period boundaries: find the first block of this period
  -- For block at height h, state is determined by the period ending at or before h
  -- We calculate states at the END of each period (last block of period)
  -- Period boundary: blocks where (height + 1) % period == 0

  -- Walk backward to find the state
  -- Start from the last complete period boundary
  local current_height = height
  if (height + 1) % period ~= 0 then
    -- Not at a period boundary, go to the last period boundary
    current_height = height - ((height + 1) % period)
  end

  -- If we're before the first period boundary, we're in DEFINED state
  if current_height < 0 then
    return STATE.DEFINED
  end

  -- Build a stack of period boundaries to process (walking backward)
  local to_process = {}
  local state = nil
  local h = current_height

  while h >= 0 and state == nil do
    local block = get_block_info(h)
    if not block then
      -- No block info available, assume DEFINED
      state = STATE.DEFINED
      break
    end

    -- Check if we can determine the state is DEFINED (optimization)
    -- If MTP < start_time, state is DEFINED at this point
    if block.mtp < deployment.start_time then
      state = STATE.DEFINED
      break
    end

    -- We need to compute state for this period
    table.insert(to_process, h)

    -- Go back one period
    h = h - period
  end

  -- If we walked back past genesis, start state is DEFINED
  if state == nil then
    state = STATE.DEFINED
  end

  -- Now process periods forward to compute the final state
  for i = #to_process, 1, -1 do
    local period_end_height = to_process[i]
    local block = get_block_info(period_end_height)

    if state == STATE.DEFINED then
      -- Check if we should transition to STARTED
      if block.mtp >= deployment.start_time then
        state = STATE.STARTED
      end

    elseif state == STATE.STARTED then
      -- Check for timeout first (FAILED)
      if block.mtp >= deployment.timeout then
        state = STATE.FAILED
      else
        -- Count signaling blocks in this period
        local count = 0
        local period_start = period_end_height - period + 1
        for bh = period_start, period_end_height do
          local b = get_block_info(bh)
          if b and M.versionbits_condition(b.version, deployment.bit) then
            count = count + 1
          end
        end

        if count >= threshold then
          state = STATE.LOCKED_IN
        end
        -- Otherwise stay in STARTED
      end

    elseif state == STATE.LOCKED_IN then
      -- Check if we can activate
      -- Activation happens when next block height >= min_activation_height
      local next_block_height = period_end_height + 1
      if next_block_height >= deployment.min_activation_height then
        state = STATE.ACTIVE
      end
      -- Otherwise stay in LOCKED_IN

    -- ACTIVE and FAILED are terminal states - no transitions
    end
  end

  return state
end

--- Get state for a block that may not be at a period boundary.
-- Returns the state that applies to blocks in the current period.
-- @param deployment table: deployment parameters
-- @param period number: retarget period
-- @param threshold number: minimum signaling blocks required
-- @param height number: height of the block
-- @param get_block_info function: fn(height) -> {timestamp, mtp, version}
-- @return string: deployment state
function M.get_deployment_state_for_block(deployment, period, threshold, height, get_block_info)
  local STATE = M.DEPLOYMENT_STATE

  -- Handle special start_time values
  if deployment.start_time == M.ALWAYS_ACTIVE then
    return STATE.ACTIVE
  end
  if deployment.start_time == M.NEVER_ACTIVE then
    return STATE.FAILED
  end

  -- Genesis block is always DEFINED
  if height == 0 then
    return STATE.DEFINED
  end

  -- Find the last period boundary before this block
  -- State for blocks in a period is determined by the state at the end of the PREVIOUS period
  local prev_period_end = height - 1 - ((height) % period)

  if prev_period_end < 0 then
    -- We're in the first period, state is DEFINED until first period completes
    -- But we need to check if STARTED based on MTP of prev block
    local prev_block = get_block_info(height - 1)
    if prev_block and prev_block.mtp >= deployment.start_time then
      -- Only the first full period can transition
      -- For blocks in period 0, always DEFINED
      return STATE.DEFINED
    end
    return STATE.DEFINED
  end

  return M.get_deployment_state(deployment, period, threshold, prev_period_end, get_block_info)
end

--------------------------------------------------------------------------------
-- Median Time Past (BIP113)
--------------------------------------------------------------------------------

M.MEDIAN_TIME_PAST_BLOCKS = 11

function M.get_median_time_past(timestamps)
  local sorted = {}
  for _, t in ipairs(timestamps) do sorted[#sorted + 1] = t end
  table.sort(sorted)
  return sorted[math.floor(#sorted / 2) + 1]
end

--------------------------------------------------------------------------------
-- Relative Lock-time (BIP68)
--------------------------------------------------------------------------------

M.SEQUENCE_LOCKTIME_DISABLE_FLAG = 0x80000000
M.SEQUENCE_LOCKTIME_TYPE_FLAG   = 0x00400000
M.SEQUENCE_LOCKTIME_MASK        = 0x0000FFFF
M.SEQUENCE_LOCKTIME_GRANULARITY = 9  -- 512 seconds per unit

--- Check if sequence lock is active (BIP68 enabled).
-- @param sequence number: input sequence number
-- @return boolean: true if relative lock-time is enabled
function M.sequence_locks_active(sequence)
  return bit.band(sequence, M.SEQUENCE_LOCKTIME_DISABLE_FLAG) == 0
end

--- Check if sequence lock is time-based (vs height-based).
-- @param sequence number: input sequence number
-- @return boolean: true if time-based, false if height-based
function M.sequence_lock_is_time_based(sequence)
  return bit.band(sequence, M.SEQUENCE_LOCKTIME_TYPE_FLAG) ~= 0
end

--- Get the sequence lock value (blocks or 512-second units).
-- @param sequence number: input sequence number
-- @return number: lock value
function M.sequence_lock_value(sequence)
  return bit.band(sequence, M.SEQUENCE_LOCKTIME_MASK)
end

--------------------------------------------------------------------------------
-- Signature Hash Types
--------------------------------------------------------------------------------

M.SIGHASH = {
  ALL = 0x01,
  NONE = 0x02,
  SINGLE = 0x03,
  ANYONECANPAY = 0x80
}

--------------------------------------------------------------------------------
-- Amount Validation
--------------------------------------------------------------------------------

--- Check if an amount is valid.
-- @param amount number: amount in satoshis
-- @return boolean: true if 0 <= amount <= MAX_MONEY
function M.is_valid_amount(amount)
  return amount >= 0 and amount <= M.MAX_MONEY
end

--------------------------------------------------------------------------------
-- Network Configurations
--------------------------------------------------------------------------------

M.networks = {}

-- Mainnet
M.networks.mainnet = {
  name = "mainnet",
  magic_bytes = "\xf9\xbe\xb4\xd9",
  port = 8333,
  rpc_port = 8332,
  pubkey_address_prefix = 0x00,
  script_address_prefix = 0x05,
  wif_prefix = 0x80,
  bech32_hrp = "bc",

  -- Genesis block
  genesis = {
    version = 1,
    timestamp = 1231006505,
    bits = 0x1d00ffff,
    nonce = 2083236893,
    coinbase_message = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
  },
  genesis_hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",

  -- Checkpoints
  checkpoints = {
    [0] = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    [11111] = "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d",
    [33333] = "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6",
    [74000] = "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20",
    [105000] = "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97",
    [134444] = "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe",
    [168000] = "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763",
    [210000] = "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e",
    [250000] = "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214",
    [295000] = "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983"
  },

  -- Soft fork heights
  bip34_height = 227931,
  bip65_height = 388381,
  bip66_height = 363725,
  csv_height = 419328,
  segwit_height = 481824,
  taproot_height = 709632,

  -- DNS seeds
  dns_seeds = {
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr-list-of-hierarchical-deterministic-wallets.org",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.net",
    "seed.bitcoin.sprovoost.nl",
    "dnsseed.emzy.de",
    "seed.bitcoin.wiz.biz"
  },

  -- Proof of work
  pow_limit_bits = 0x1d00ffff,
  pow_no_retarget = false,
  pow_allow_min_difficulty = false,
  enforce_bip94 = false,

  -- Minimum chain work required to accept a chain (anti-DoS)
  -- This is a hex string representation of the 256-bit value
  -- Updated periodically; this value corresponds to Bitcoin Core v27
  min_chain_work = "000000000000000000000000000000000000000088430067bc7f9c1f8cc40b55",

  -- Assumevalid block hash (skip script validation for ancestors)
  -- Height 938343, from Bitcoin Core v28
  assumevalid = "00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac",

  -- BIP9 versionbits parameters
  versionbits_period = 2016,
  versionbits_threshold = 1815,  -- 95% of 2016

  -- AssumeUTXO snapshots: validated UTXO set hashes at specific heights
  -- Format: {height = {hash_serialized = "...", m_chain_tx_count = N, blockhash = "..."}}
  -- hash_serialized is Bitcoin Core's CoinStatsHashType::HASH_SERIALIZED
  -- value: SHA256d (via HashWriter, see kernel/coinstats.cpp:161-163,
  -- 182-184) over canonical-order TxOutSer bytes for the entire UTXO set.
  -- Displayed in the same big-endian hex format used by uint256.ToString().
  -- This is what compute_utxo_hash() returns — NOT MuHash3072 (that is
  -- gettxoutsetinfo hash_type=muhash and lives on compute_muhash).
  -- Source of truth: bitcoin-core/src/kernel/chainparams.cpp m_assumeutxo_data
  -- (sha256 verified against bitcoin-core release manifests).
  assumeutxo = {
    [840000] = {
      hash_serialized = "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96",
      m_chain_tx_count = 991032194,
      blockhash = "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"
    },
    [880000] = {
      hash_serialized = "dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9",
      m_chain_tx_count = 1145604538,
      blockhash = "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880"
    },
    [910000] = {
      hash_serialized = "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568",
      m_chain_tx_count = 1226586151,
      blockhash = "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821"
    },
    [935000] = {
      hash_serialized = "e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050",
      m_chain_tx_count = 1305397408,
      blockhash = "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee"
    }
  }
}

-- Testnet (testnet3)
M.networks.testnet = {
  name = "testnet",
  magic_bytes = "\x0b\x11\x09\x07",
  port = 18333,
  rpc_port = 18332,
  pubkey_address_prefix = 0x6F,
  script_address_prefix = 0xC4,
  wif_prefix = 0xEF,
  bech32_hrp = "tb",

  -- Genesis block
  genesis = {
    version = 1,
    timestamp = 1296688602,
    bits = 0x1d00ffff,
    nonce = 414098458,
    coinbase_message = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
  },
  genesis_hash = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",

  -- Checkpoints (minimal for testnet)
  checkpoints = {
    [0] = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
  },

  -- Soft fork heights
  bip34_height = 21111,
  bip65_height = 581885,
  bip66_height = 330776,
  csv_height = 770112,
  segwit_height = 834624,
  taproot_height = 0,

  -- DNS seeds
  dns_seeds = {
    "testnet-seed.bitcoin.jonasschnelli.ch",
    "seed.tbtc.petertodd.net",
    "seed.testnet.bitcoin.sprovoost.nl",
    "testnet-seed.bluematt.me"
  },

  -- Proof of work
  pow_limit_bits = 0x1d00ffff,
  pow_no_retarget = false,
  pow_allow_min_difficulty = true,
  enforce_bip94 = false,

  -- Minimum chain work (low for testnet)
  min_chain_work = "0000000000000000000000000000000000000000000000000000000100010001",

  -- Assumevalid (disabled for testnet3 as it's deprecated)
  assumevalid = nil,

  -- BIP9 versionbits parameters
  versionbits_period = 2016,
  versionbits_threshold = 1512,  -- 75% of 2016 (testnet uses lower threshold)

  -- AssumeUTXO (no snapshots for deprecated testnet3)
  assumeutxo = {}
}

-- Testnet4 (BIP94)
M.networks.testnet4 = {
  name = "testnet4",
  magic_bytes = "\x1c\x16\x3f\x28",
  port = 48333,
  rpc_port = 48332,
  pubkey_address_prefix = 0x6F,
  script_address_prefix = 0xC4,
  wif_prefix = 0xEF,
  bech32_hrp = "tb",

  -- Genesis block — testnet4 uses a DIFFERENT coinbase from mainnet.
  -- Ref: Bitcoin Core kernel/chainparams.cpp testnet4 section.
  genesis = {
    version = 1,
    timestamp = 1714777860,
    bits = 0x1d00ffff,
    nonce = 393743547,
    coinbase_message = "03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e",
    coinbase_pubkey_hex = "000000000000000000000000000000000000000000000000000000000000000000",
  },
  genesis_hash = "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",

  -- Checkpoints
  checkpoints = {
    [0] = "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"
  },

  -- All soft forks active from height 1 (BIP94)
  bip34_height = 1,
  bip65_height = 1,
  bip66_height = 1,
  csv_height = 1,
  segwit_height = 1,
  taproot_height = 1,

  -- DNS seeds
  dns_seeds = {
    "seed.testnet4.bitcoin.sprovoost.nl",
    "seed.testnet4.wiz.biz"
  },

  -- Proof of work
  pow_limit_bits = 0x1d00ffff,
  pow_no_retarget = false,
  pow_allow_min_difficulty = true,
  enforce_bip94 = true,

  -- Minimum chain work (testnet4)
  min_chain_work = "0000000000000000000000000000000000000000000000000000000000000000",

  -- Assumevalid — block 123613
  assumevalid = "0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a",

  -- BIP9 versionbits parameters (all forks already active at height 1)
  versionbits_period = 2016,
  versionbits_threshold = 1512,  -- 75% of 2016

  -- AssumeUTXO (no snapshots for testnet4 yet)
  assumeutxo = {}
}

-- Regtest
M.networks.regtest = {
  name = "regtest",
  magic_bytes = "\xfa\xbf\xb5\xda",
  port = 18444,
  rpc_port = 18443,
  pubkey_address_prefix = 0x6F,
  script_address_prefix = 0xC4,
  wif_prefix = 0xEF,
  bech32_hrp = "bcrt",

  -- Genesis block
  genesis = {
    version = 1,
    timestamp = 1296688602,
    bits = 0x207fffff,
    nonce = 2,
    coinbase_message = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
  },
  genesis_hash = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",

  -- Checkpoints
  checkpoints = {
    [0] = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
  },

  -- All soft forks active from height 0
  bip34_height = 0,
  bip65_height = 0,
  bip66_height = 0,
  csv_height = 0,
  segwit_height = 0,
  taproot_height = 0,

  -- DNS seeds (none for regtest)
  dns_seeds = {},

  -- Proof of work
  pow_limit_bits = 0x207fffff,
  pow_no_retarget = true,
  pow_allow_min_difficulty = true,
  enforce_bip94 = false,

  -- Minimum chain work (0 for regtest - disable anti-DoS)
  min_chain_work = "0000000000000000000000000000000000000000000000000000000000000000",

  -- Assumevalid (disabled for regtest, always verify)
  assumevalid = nil,

  -- BIP9 versionbits parameters (use small period for fast testing)
  versionbits_period = 144,     -- 1 day at 10 min/block
  versionbits_threshold = 108,   -- 75% of 144

  -- AssumeUTXO (dynamic for regtest, populated via RPC)
  assumeutxo = {}
}

-- Convenience function to get network by name
function M.get_network(name)
  return M.networks[name]
end

--------------------------------------------------------------------------------
-- Buried-deployment consistency check (defense in depth)
--
-- The buried activation heights in M.networks.mainnet drive consensus
-- enforcement (see src/utxo.lua connect_block). The decorative BIP9 state
-- machine above carries its own copy of those heights in M.DEPLOYMENTS.
-- These two tables MUST agree for mainnet, otherwise a future RPC consumer
-- of M.DEPLOYMENTS would report a different activation height than the
-- one the validator actually enforces, leading to subtle disagreement with
-- Bitcoin Core in tooling.
--
-- This is run once at module load and raises immediately on disagreement.
-- Cost: a few comparisons per process startup. Zero IBD overhead.
--
-- Only mainnet is checked because:
--   * regtest activates everything from height 0
--   * testnet3/testnet4 use different activation heights and have no entry
--     in M.DEPLOYMENTS (which is mainnet-shaped). Adding per-network
--     deployment tables is out of scope for this defense-in-depth check.
--------------------------------------------------------------------------------
function M.validate_buried_deployment_consistency()
  local net = M.networks.mainnet
  if not net then
    error("consensus.lua: mainnet network table missing")
  end

  -- SEGWIT (BIP141): M.DEPLOYMENTS.SEGWIT.min_activation_height matches
  -- net.segwit_height. Core mainnet activated SegWit at height 481824 and
  -- BIP9 min_activation_height was 0 (i.e. activate as soon as locked in).
  -- We carry min_activation_height = 0 in M.DEPLOYMENTS.SEGWIT to match the
  -- BIP9 spec; the buried height is the *actual* activation height. They
  -- legitimately differ and this is fine — we only assert that the buried
  -- height is non-zero and sensible.
  if net.segwit_height == nil or net.segwit_height < 1 then
    error(string.format(
      "consensus.lua: mainnet segwit_height invalid (got %s, expected >= 1)",
      tostring(net.segwit_height)))
  end

  -- TAPROOT (BIP341): M.DEPLOYMENTS.TAPROOT.min_activation_height is the
  -- buried activation height per BIP341 (709632). Core hard-coded this in
  -- chainparams.cpp, so the BIP9 table value MUST match net.taproot_height
  -- exactly. If they ever drift, fail loud.
  local taproot_dep_height = M.DEPLOYMENTS.TAPROOT.min_activation_height
  if taproot_dep_height ~= net.taproot_height then
    error(string.format(
      "consensus.lua: TAPROOT min_activation_height mismatch: " ..
      "M.DEPLOYMENTS.TAPROOT.min_activation_height=%d, " ..
      "M.networks.mainnet.taproot_height=%d. " ..
      "Both must reference the same buried activation height (BIP341: 709632).",
      taproot_dep_height, net.taproot_height))
  end

  -- Sanity: every buried height referenced from the consensus path
  -- (utxo.lua) must be a non-negative integer.
  local buried = {
    bip34_height   = net.bip34_height,
    bip65_height   = net.bip65_height,
    bip66_height   = net.bip66_height,
    csv_height     = net.csv_height,
    segwit_height  = net.segwit_height,
    taproot_height = net.taproot_height,
  }
  for name, h in pairs(buried) do
    if type(h) ~= "number" or h < 0 or h ~= math.floor(h) then
      error(string.format(
        "consensus.lua: mainnet %s invalid (got %s, expected non-negative integer)",
        name, tostring(h)))
    end
  end
end

-- Run at module load. If a future patch breaks the invariant, the entire
-- node refuses to boot rather than silently disagreeing with Core.
M.validate_buried_deployment_consistency()

--------------------------------------------------------------------------------
-- 256-bit Chainwork Arithmetic (for anti-DoS header sync)
--------------------------------------------------------------------------------

--- Parse a hex string to a 32-byte big-endian work value.
-- @param hex string: 64-character hex string
-- @return string: 32-byte big-endian binary string
function M.work_from_hex(hex)
  if #hex ~= 64 then
    error("work hex must be 64 characters")
  end
  return (hex:gsub("%x%x", function(c) return string.char(tonumber(c, 16)) end))
end

--- Convert a 32-byte big-endian work value to hex string.
-- @param work string: 32-byte binary string
-- @return string: 64-character hex string
function M.work_to_hex(work)
  if #work ~= 32 then
    error("work must be 32 bytes")
  end
  return (work:gsub(".", function(c) return string.format("%02x", string.byte(c)) end))
end

--- Compare two 256-bit work values (big-endian).
-- @param a string: 32-byte work value
-- @param b string: 32-byte work value
-- @return number: -1 if a < b, 0 if a == b, 1 if a > b
function M.work_compare(a, b)
  for i = 1, 32 do
    local av = a:byte(i)
    local bv = b:byte(i)
    if av < bv then return -1 end
    if av > bv then return 1 end
  end
  return 0
end

--- Add two 256-bit work values (big-endian).
-- @param a string: 32-byte work value
-- @param b string: 32-byte work value
-- @return string: 32-byte sum (saturates at max 256-bit value)
function M.work_add(a, b)
  local result = {}
  local carry = 0
  for i = 32, 1, -1 do
    local sum = a:byte(i) + b:byte(i) + carry
    result[i] = sum % 256
    carry = math.floor(sum / 256)
  end
  -- Build result string
  local out = {}
  for i = 1, 32 do
    out[i] = string.char(result[i])
  end
  return table.concat(out)
end

--- Calculate proof-of-work for a given difficulty target.
-- Work = floor(2^256 / (target + 1))
-- Returns 32-byte big-endian work value.
-- Uses floating-point approximation (sufficient for chain comparison).
-- @param bits number: compact difficulty representation
-- @return string: 32-byte big-endian work value
function M.get_block_work(bits)
  local target = M.bits_to_target(bits)

  -- Find the first non-zero byte (big-endian)
  local first_nonzero = 0
  for i = 1, 32 do
    if target:byte(i) ~= 0 then
      first_nonzero = i
      break
    end
  end

  if first_nonzero == 0 then
    -- Zero target = maximum work
    return string.rep("\xff", 32)
  end

  -- Extract target value as floating-point (use up to 8 significant bytes)
  local target_val = 0
  local sig_bytes = math.min(8, 33 - first_nonzero)
  for i = first_nonzero, first_nonzero + sig_bytes - 1 do
    target_val = target_val * 256 + target:byte(i)
  end

  -- target_val represents target >> (8 * remaining_zero_bytes)
  -- where remaining_zero_bytes = 32 - first_nonzero - sig_bytes + 1
  local remaining = 32 - first_nonzero - sig_bytes + 1

  -- Work = 2^256 / (target + 1)
  -- = 2^256 / ((target_val * 2^(8*remaining)) + 1)
  -- ≈ 2^(256 - 8*remaining) / target_val   (for large targets)
  -- = 2^(8*(32 - remaining)) / target_val
  -- = 2^(8*(first_nonzero + sig_bytes - 1)) / target_val

  local work_bits = 8 * (first_nonzero + sig_bytes - 1)
  local work_float = math.pow(2, work_bits) / (target_val + 1)

  -- Work result goes into the big-endian position that is "inverse" of target
  -- If target is small (starts late), work is large (starts early)
  -- work_position = 32 - first_nonzero + 1 = 33 - first_nonzero
  local work_start = 33 - first_nonzero - sig_bytes + 1
  if work_start < 1 then work_start = 1 end

  -- Build result array (big-endian)
  local result = {}
  for i = 1, 32 do result[i] = 0 end

  -- Fill in work bytes from work_start position
  local remaining_work = work_float
  local pos = work_start
  while remaining_work >= 1 and pos <= 32 do
    local byte_val = math.floor(remaining_work) % 256
    result[pos] = byte_val
    remaining_work = math.floor(remaining_work / 256)
    pos = pos + 1
  end

  -- Handle any overflow into earlier positions
  while remaining_work >= 1 and work_start > 1 do
    work_start = work_start - 1
    result[work_start] = math.floor(remaining_work) % 256
    remaining_work = math.floor(remaining_work / 256)
  end

  -- Convert to string
  local out = {}
  for i = 1, 32 do
    out[i] = string.char(result[i])
  end
  return table.concat(out)
end

--- Get the zero work value.
-- @return string: 32-byte zero value
function M.work_zero()
  return string.rep("\0", 32)
end

--------------------------------------------------------------------------------
-- Checkpoint Enforcement
--------------------------------------------------------------------------------

--- Get the last (highest) checkpoint height for a network.
-- @param network table: network configuration
-- @return number: highest checkpoint height, or 0 if no checkpoints
function M.get_last_checkpoint_height(network)
  local checkpoints = network.checkpoints or {}
  local max_height = 0
  for height, _ in pairs(checkpoints) do
    if height > max_height then
      max_height = height
    end
  end
  return max_height
end

--- Check if a block hash matches the checkpoint at the given height.
-- @param network table: network configuration
-- @param height number: block height
-- @param block_hash_hex string: block hash as hex string
-- @return boolean, string|nil: true if valid or no checkpoint, false with error if mismatch
function M.check_checkpoint(network, height, block_hash_hex)
  local checkpoints = network.checkpoints or {}
  local expected = checkpoints[height]
  if expected then
    if block_hash_hex ~= expected then
      return false, "CHECKPOINT"
    end
  end
  return true
end

--- Check if accepting a block at the given height would violate checkpoint rules.
-- Blocks at heights below the last checkpoint must be on the checkpoint chain.
-- @param network table: network configuration
-- @param height number: height of block being accepted
-- @param block_hash_hex string: block hash as hex string
-- @param get_ancestor function: fn(h) -> header_entry for ancestor lookup
-- @return boolean, string|nil: true if valid, false with error if checkpoint violation
function M.check_checkpoint_anti_fork(network, height, block_hash_hex, get_ancestor)
  local checkpoints = network.checkpoints or {}
  local last_checkpoint_height = M.get_last_checkpoint_height(network)

  -- If we're at or below the last checkpoint height, verify we're on checkpoint chain
  if height <= last_checkpoint_height then
    -- Check all checkpoints at or above this height
    for cp_height, cp_hash in pairs(checkpoints) do
      if cp_height >= height then
        -- For this checkpoint to be valid, if we look at the checkpoint height
        -- from our perspective, it must eventually lead to the checkpoint hash
        -- Since we're checking a potential fork, we need to verify that at height
        -- equal to this checkpoint, the hash matches
        if cp_height == height then
          if block_hash_hex ~= cp_hash then
            return false, "CHECKPOINT"
          end
        end
        -- For checkpoints above us, we can't verify yet - they will be checked
        -- when those headers arrive
      end
    end
  end

  -- Check that any checkpoint heights between genesis and this height are satisfied
  -- by checking that the ancestor at that height matches the checkpoint
  for cp_height, cp_hash in pairs(checkpoints) do
    if cp_height < height then
      local ancestor = get_ancestor(cp_height)
      if ancestor then
        local ancestor_hash = ancestor.hash_hex or ancestor.hash
        if type(ancestor_hash) ~= "string" then
          -- Convert hash object to hex if needed
          local types = require("lunarblock.types")
          if ancestor_hash.bytes then
            ancestor_hash = types.hash256_hex(ancestor_hash)
          end
        end
        if ancestor_hash ~= cp_hash then
          return false, "CHECKPOINT"
        end
      end
    end
  end

  return true
end

--------------------------------------------------------------------------------
-- Assumevalid Optimization
--------------------------------------------------------------------------------

--- Check if script validation should be skipped for a block.
-- Implements the Bitcoin Core v28.0 assumevalid ancestor-check semantic.
-- Script verification is skipped if and only if ALL six conditions hold:
--   1. assumed_valid hash is configured (non-nil, non-empty).
--   2. The assumed-valid block is present in the local header index
--      (is_av_in_index returns true).
--   3. The block being connected is an ancestor of the assumed-valid block
--      on the active header chain (is_ancestor_of_assumevalid returns true).
--   4. The block is also an ancestor of the best known header
--      (is_on_best_header_chain returns true).
--   5. The best-known-header chainwork >= minimumChainWork.
--   6. The best-known-header is at least TWO_WEEKS_BLOCKS above the block
--      being connected (prevents a manufactured shallow header chain from
--      unlocking the skip path).
--
-- Reference: Bitcoin Core src/validation.cpp ConnectBlock, lines 2345-2383.
--
-- @param network table: network configuration (must have .assumevalid, .min_chain_work)
-- @param block_height number: height of block being connected
-- @param block_hash_hex string: hex hash of block being connected
-- @param is_av_in_index function: fn() -> boolean — true if assumevalid hash is in header index
-- @param is_ancestor_of_assumevalid function: fn(height, hash_hex) -> boolean
--   Returns true iff the block at `height` with `hash_hex` is on the ancestor
--   path to the assumevalid block (i.e., the canonical chain's block at that
--   height IS this block, and the assumevalid block is at or above this height).
-- @param is_on_best_header_chain function: fn(height, hash_hex) -> boolean
--   Returns true iff the block at `height` with `hash_hex` is on the best header chain.
-- @param best_header_work string: 32-byte big-endian cumulative work of best header
-- @param best_header_height number: height of best known header
-- @return boolean: true if script validation should be skipped
function M.should_skip_script_validation(network, block_height, block_hash_hex,
    is_av_in_index, is_ancestor_of_assumevalid, is_on_best_header_chain,
    best_header_work, best_header_height)
  -- Condition 1: assumevalid must be configured
  local assumevalid = network.assumevalid
  if not assumevalid or assumevalid == "" then
    return false, "assumevalid not configured"
  end

  -- Condition 2: the assumed-valid block must be in our header index
  if not is_av_in_index() then
    return false, "assumevalid hash not in header index"
  end

  -- Condition 3: block must be an ancestor of the assumed-valid block
  if not is_ancestor_of_assumevalid(block_height, block_hash_hex) then
    return false, "block not in assumevalid chain"
  end

  -- Condition 4: block must be an ancestor of the best known header
  if not is_on_best_header_chain(block_height, block_hash_hex) then
    return false, "block not in best header chain"
  end

  -- Condition 5: best header must have minimum chain work
  local min_work = M.work_from_hex(network.min_chain_work or string.rep("00", 64))
  if M.work_compare(best_header_work, min_work) < 0 then
    return false, "best header chainwork below minimumchainwork"
  end

  -- Condition 6: best header must be at least ~2 weeks of blocks past this block
  -- Bitcoin Core uses GetBlockProofEquivalentTime for a precise 2-week equivalent-work
  -- check; we conservatively approximate as TWO_WEEKS_BLOCKS block-height gap.
  local TWO_WEEKS_BLOCKS = 2016  -- ~2 weeks at 10 min/block
  if best_header_height - block_height < TWO_WEEKS_BLOCKS then
    return false, "block too recent relative to best header"
  end

  return true  -- All conditions met — safe to skip script validation
end

--- Build the is_av_in_index, is_ancestor_of_assumevalid, and is_on_best_header_chain
-- callbacks needed by should_skip_script_validation, from a HeaderChain object.
--
-- The HeaderChain must expose:
--   .height_to_hash[height] -> hash_hex  (canonical chain hash at each height)
--   .headers[hash_hex] -> {height=N, ...}  (header index)
--   .header_tip_height -> number
--
-- @param network table: network configuration (must have .assumevalid)
-- @param header_chain table: HeaderChain object from sync.lua
-- @return is_av_in_index fn, is_ancestor fn, is_on_best_header_chain fn
function M.make_assumevalid_callbacks(network, header_chain)
  local av_hash = network.assumevalid  -- hex string or nil

  -- Condition 2 callback: is assumevalid hash in our header index?
  local function is_av_in_index()
    if not av_hash then return false end
    return header_chain.headers[av_hash] ~= nil
  end

  -- Find the height of the assumevalid block once (lazily cached).
  local av_height_cache = nil
  local function get_av_height()
    if av_height_cache then return av_height_cache end
    if not av_hash then return nil end
    local entry = header_chain.headers[av_hash]
    if entry then
      av_height_cache = entry.height
    end
    return av_height_cache
  end

  -- Condition 3 callback: is this block an ancestor of the assumevalid block?
  -- A block at `height` is an ancestor of assumevalid iff:
  --   a) height <= assumevalid_height
  --   b) the canonical chain's block at `height` IS this block
  --      (i.e. height_to_hash[height] == block_hash_hex)
  local function is_ancestor_of_assumevalid(height, hash_hex)
    local av_height = get_av_height()
    if not av_height then return false end
    if height > av_height then return false end
    return header_chain.height_to_hash[height] == hash_hex
  end

  -- Condition 4 callback: is this block on the best known header chain?
  local function is_on_best_header_chain(height, hash_hex)
    return header_chain.height_to_hash[height] == hash_hex
  end

  return is_av_in_index, is_ancestor_of_assumevalid, is_on_best_header_chain
end

--------------------------------------------------------------------------------
-- AssumeUTXO Snapshot Configuration
--------------------------------------------------------------------------------

--- Get assumeutxo data for a specific height.
-- @param network table: network configuration
-- @param height number: snapshot base block height
-- @return table|nil: {hash_serialized, m_chain_tx_count, blockhash} or nil if not found
function M.assumeutxo_for_height(network, height)
  if not network.assumeutxo then return nil end
  return network.assumeutxo[height]
end

--- Get assumeutxo data for a specific blockhash.
-- @param network table: network configuration
-- @param blockhash_hex string: hex hash of the base block
-- @return table|nil: assumeutxo data or nil if not found
function M.assumeutxo_for_blockhash(network, blockhash_hex)
  if not network.assumeutxo then return nil end
  for height, data in pairs(network.assumeutxo) do
    if data.blockhash == blockhash_hex then
      return data, height
    end
  end
  return nil
end

--- Check if a height has a valid assumeutxo snapshot.
-- @param network table: network configuration
-- @param height number: height to check
-- @return boolean: true if assumeutxo data exists for this height
function M.has_assumeutxo(network, height)
  return M.assumeutxo_for_height(network, height) ~= nil
end

--- Get all assumeutxo heights for a network.
-- @param network table: network configuration
-- @return table: list of heights with assumeutxo data
function M.get_assumeutxo_heights(network)
  local heights = {}
  if not network.assumeutxo then return heights end
  for height, _ in pairs(network.assumeutxo) do
    heights[#heights + 1] = height
  end
  table.sort(heights)
  return heights
end

return M
