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
M.MIN_TX_SIZE = 82
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
-- @return number: new compact bits
function M.calculate_next_target(last_target_bits, actual_timespan)
  -- Clamp timespan to [MIN_TIMESPAN, MAX_TIMESPAN]
  if actual_timespan < M.MIN_TIMESPAN then
    actual_timespan = M.MIN_TIMESPAN
  elseif actual_timespan > M.MAX_TIMESPAN then
    actual_timespan = M.MAX_TIMESPAN
  end

  -- Get current target as bytes
  local old_target = M.bits_to_target(last_target_bits)

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

--------------------------------------------------------------------------------
-- BIP9 Deployment Parameters
--------------------------------------------------------------------------------

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
  pow_allow_min_difficulty = false
}

-- Testnet
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
  pow_allow_min_difficulty = true
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
  pow_allow_min_difficulty = true
}

-- Convenience function to get network by name
function M.get_network(name)
  return M.networks[name]
end

return M
