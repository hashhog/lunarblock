local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local p2p = require("lunarblock.p2p")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local crypto = require("lunarblock.crypto")
local perf = require("lunarblock.perf")
local M = {}

--------------------------------------------------------------------------------
-- HeadersSyncState: Anti-DoS header synchronization (PRESYNC/REDOWNLOAD)
--------------------------------------------------------------------------------
-- Implements a two-phase header download to prevent memory exhaustion attacks
-- where a peer sends millions of low-work headers.
--
-- PRESYNC phase: Accept headers without storing them; track only:
--   - Cumulative work (256-bit)
--   - Last header hash
--   - Header count
--   - 1-bit commitments (salted hash) at periodic intervals
--
-- Once cumulative work reaches min_chain_work, transition to REDOWNLOAD:
--   - Request all headers again from genesis
--   - Verify commitments match
--   - Store headers permanently
--
-- Reference: Bitcoin Core headerssync.cpp/h

local HeadersSyncState = {}
HeadersSyncState.__index = HeadersSyncState

-- Sync states
HeadersSyncState.STATE = {
  PRESYNC = "presync",
  REDOWNLOAD = "redownload",
  FINAL = "final"
}

-- Parameters for commitment tracking
local COMMITMENT_PERIOD = 584  -- Store 1 commitment every N headers
local REDOWNLOAD_BUFFER_SIZE = 144  -- Buffer headers before accepting

--- Create a new HeadersSyncState instance for a peer.
-- @param peer_id number|string: identifier for the peer
-- @param network table: network configuration
-- @param chain_start table: {hash, height, work} of the chain start point
-- @return HeadersSyncState: new sync state instance
function M.new_headers_sync_state(peer_id, network, chain_start)
  local self = setmetatable({}, HeadersSyncState)

  self.peer_id = peer_id
  self.network = network

  -- Parse minimum required work from network config
  self.min_required_work = consensus.work_from_hex(
    network.min_chain_work or string.rep("00", 64)
  )

  -- Chain start point (where we begin syncing from)
  self.chain_start_hash = chain_start.hash
  self.chain_start_height = chain_start.height
  self.chain_start_work = chain_start.work or consensus.work_zero()

  -- Current state
  self.state = HeadersSyncState.STATE.PRESYNC

  -- PRESYNC tracking (memory-efficient)
  self.presync = {
    work = self.chain_start_work,  -- Accumulated work (32-byte big-endian)
    last_hash = chain_start.hash,  -- Hash of last processed header
    last_bits = network.genesis.bits,  -- bits of last header (for difficulty check)
    last_timestamp = network.genesis.timestamp,  -- timestamp of last header
    count = 0,  -- Number of headers processed
    height = chain_start.height,  -- Current height
    commitments = {},  -- 1-bit commitments (boolean array)
  }

  -- Random salt for commitment hashing (anti-grinding)
  -- Use /dev/urandom for secure random bytes
  local f = io.open("/dev/urandom", "rb")
  if f then
    self.commitment_salt = f:read(32)
    f:close()
  else
    -- Fallback to Lua random (NOT cryptographically secure)
    math.randomseed(os.time() + os.clock() * 1000000)
    local bytes = {}
    for i = 1, 32 do
      bytes[i] = string.char(math.random(0, 255))
    end
    self.commitment_salt = table.concat(bytes)
  end

  -- Random offset for commitment positions (0 to COMMITMENT_PERIOD-1)
  self.commitment_offset = math.random(0, COMMITMENT_PERIOD - 1)

  -- REDOWNLOAD tracking
  self.redownload = {
    work = self.chain_start_work,
    last_hash = chain_start.hash,
    last_bits = network.genesis.bits,
    last_timestamp = network.genesis.timestamp,
    height = chain_start.height,
    buffer = {},  -- Buffered headers awaiting acceptance
    commitment_idx = 1,  -- Next commitment to verify
    work_threshold_reached = false,
  }

  return self
end

--- Get the current sync state.
-- @return string: "presync", "redownload", or "final"
function HeadersSyncState:get_state()
  return self.state
end

--- Get PRESYNC statistics for display/logging.
-- @return table: {work_hex, height, count, state}
function HeadersSyncState:get_stats()
  if self.state == HeadersSyncState.STATE.PRESYNC then
    return {
      work_hex = consensus.work_to_hex(self.presync.work),
      height = self.presync.height,
      count = self.presync.count,
      state = self.state
    }
  else
    return {
      work_hex = consensus.work_to_hex(self.redownload.work),
      height = self.redownload.height,
      count = #self.redownload.buffer,
      state = self.state
    }
  end
end

--- Compute a 1-bit commitment for a header hash.
-- Uses salted hashing to prevent attacker from pre-computing collisions.
-- @param block_hash hash256: block hash to commit to
-- @return boolean: commitment bit (true or false)
function HeadersSyncState:compute_commitment(block_hash)
  -- Hash: SHA256(salt || block_hash)
  local data = self.commitment_salt .. block_hash.bytes
  local hash = crypto.sha256(data)
  -- Take LSB of first byte as commitment
  return (hash:byte(1) % 2) == 1
end

--- Check if difficulty transition is permitted.
-- Simplified check: ensure bits don't change by more than 4x in either direction.
-- @param prev_bits number: previous block's bits
-- @param next_bits number: next block's bits
-- @param height number: height of next block
-- @return boolean: true if transition is valid
function HeadersSyncState:permitted_difficulty_transition(prev_bits, next_bits, height)
  -- At difficulty adjustment boundary, allow any valid transition
  if height % consensus.DIFFICULTY_ADJUSTMENT_INTERVAL == 0 then
    return true
  end

  -- For testnet with min difficulty rules
  if self.network.pow_allow_min_difficulty then
    -- Allow transition to min difficulty
    if next_bits == self.network.pow_limit_bits then
      return true
    end
    -- Also allow returning to prev difficulty
    return true  -- Simplified for testnet
  end

  -- Non-adjustment block: bits must match previous
  return prev_bits == next_bits
end

--------------------------------------------------------------------------------
-- PRESYNC Phase
--------------------------------------------------------------------------------

--- Process headers in PRESYNC phase.
-- Validates PoW and accumulates work without storing headers.
-- @param headers table: list of block_header objects
-- @return boolean, string|nil: success, error message
function HeadersSyncState:process_presync(headers)
  for _, header in ipairs(headers) do
    -- Verify continuity (header connects to last)
    local prev_hex = types.hash256_hex(header.prev_hash)
    local last_hex = types.hash256_hex(self.presync.last_hash)
    if prev_hex ~= last_hex then
      return false, "non-continuous header in presync"
    end

    local next_height = self.presync.height + 1

    -- Check difficulty transition
    if not self:permitted_difficulty_transition(
      self.presync.last_bits, header.bits, next_height
    ) then
      return false, "invalid difficulty transition in presync"
    end

    -- Verify PoW
    local hash = validation.compute_block_hash(header)
    local target = consensus.bits_to_target(header.bits)
    if not consensus.hash_meets_target(hash.bytes, target) then
      return false, "invalid proof of work in presync"
    end

    -- Check timestamp > previous timestamp (simplified MTP check)
    if header.timestamp <= self.presync.last_timestamp - 7200 then
      return false, "timestamp too old in presync"
    end

    -- Accumulate work
    local block_work = consensus.get_block_work(header.bits)
    self.presync.work = consensus.work_add(self.presync.work, block_work)

    -- Store commitment at periodic intervals
    if (next_height % COMMITMENT_PERIOD) == self.commitment_offset then
      local commitment = self:compute_commitment(hash)
      self.presync.commitments[#self.presync.commitments + 1] = commitment
    end

    -- Update state
    self.presync.last_hash = hash
    self.presync.last_bits = header.bits
    self.presync.last_timestamp = header.timestamp
    self.presync.height = next_height
    self.presync.count = self.presync.count + 1
  end

  -- Check if we've reached minimum required work
  if consensus.work_compare(self.presync.work, self.min_required_work) >= 0 then
    -- Transition to REDOWNLOAD
    self:transition_to_redownload()
  end

  return true
end

--- Transition from PRESYNC to REDOWNLOAD phase.
function HeadersSyncState:transition_to_redownload()
  self.state = HeadersSyncState.STATE.REDOWNLOAD

  -- Reset redownload state to chain start
  self.redownload = {
    work = self.chain_start_work,
    last_hash = self.chain_start_hash,
    last_bits = self.network.genesis.bits,
    last_timestamp = self.network.genesis.timestamp,
    height = self.chain_start_height,
    buffer = {},
    commitment_idx = 1,
    work_threshold_reached = false,
  }
end

--- Check if PRESYNC is complete and ready for REDOWNLOAD.
-- @return boolean: true if work threshold reached
function HeadersSyncState:presync_complete()
  return self.state == HeadersSyncState.STATE.REDOWNLOAD
end

--- Get the getheaders request parameters for current state.
-- @return table: {locator_hashes, stop_hash}
function HeadersSyncState:get_getheaders_request()
  if self.state == HeadersSyncState.STATE.PRESYNC then
    -- Continue from last PRESYNC header
    return {
      locator_hashes = {self.presync.last_hash},
      stop_hash = types.hash256_zero()
    }
  elseif self.state == HeadersSyncState.STATE.REDOWNLOAD then
    -- Start from chain start for REDOWNLOAD
    return {
      locator_hashes = {self.chain_start_hash},
      stop_hash = types.hash256_zero()
    }
  else
    return nil
  end
end

--------------------------------------------------------------------------------
-- REDOWNLOAD Phase
--------------------------------------------------------------------------------

--- Process headers in REDOWNLOAD phase.
-- Validates headers and verifies commitments match PRESYNC.
-- @param headers table: list of block_header objects
-- @return table|nil, string|nil: accepted headers ready for storage, error
function HeadersSyncState:process_redownload(headers)
  local accepted = {}

  for _, header in ipairs(headers) do
    -- Verify continuity
    local prev_hex = types.hash256_hex(header.prev_hash)
    local last_hex = types.hash256_hex(self.redownload.last_hash)
    if prev_hex ~= last_hex then
      return nil, "non-continuous header in redownload"
    end

    local next_height = self.redownload.height + 1

    -- Check difficulty transition
    if not self:permitted_difficulty_transition(
      self.redownload.last_bits, header.bits, next_height
    ) then
      return nil, "invalid difficulty transition in redownload"
    end

    -- Verify PoW
    local hash = validation.compute_block_hash(header)
    local target = consensus.bits_to_target(header.bits)
    if not consensus.hash_meets_target(hash.bytes, target) then
      return nil, "invalid proof of work in redownload"
    end

    -- Accumulate work
    local block_work = consensus.get_block_work(header.bits)
    self.redownload.work = consensus.work_add(self.redownload.work, block_work)

    -- Check if we've reached work threshold
    if not self.redownload.work_threshold_reached then
      if consensus.work_compare(self.redownload.work, self.min_required_work) >= 0 then
        self.redownload.work_threshold_reached = true
      end
    end

    -- Verify commitment at periodic intervals
    if not self.redownload.work_threshold_reached then
      if (next_height % COMMITMENT_PERIOD) == self.commitment_offset then
        local idx = self.redownload.commitment_idx
        if idx > #self.presync.commitments then
          return nil, "commitment overrun in redownload"
        end

        local expected = self.presync.commitments[idx]
        local actual = self:compute_commitment(hash)
        if expected ~= actual then
          return nil, "commitment mismatch in redownload"
        end

        self.redownload.commitment_idx = idx + 1
      end
    end

    -- Update state
    self.redownload.last_hash = hash
    self.redownload.last_bits = header.bits
    self.redownload.last_timestamp = header.timestamp
    self.redownload.height = next_height

    -- Add to buffer
    self.redownload.buffer[#self.redownload.buffer + 1] = {
      header = header,
      hash = hash,
      height = next_height
    }
  end

  -- Release buffered headers that have sufficient commitments verified
  -- (or all if work threshold reached)
  if self.redownload.work_threshold_reached or
     #self.redownload.buffer > REDOWNLOAD_BUFFER_SIZE then
    -- Release headers from buffer
    if self.redownload.work_threshold_reached then
      -- Release all
      for _, entry in ipairs(self.redownload.buffer) do
        accepted[#accepted + 1] = entry
      end
      self.redownload.buffer = {}
      self.state = HeadersSyncState.STATE.FINAL
    else
      -- Release oldest entries, keeping REDOWNLOAD_BUFFER_SIZE
      while #self.redownload.buffer > REDOWNLOAD_BUFFER_SIZE do
        local entry = table.remove(self.redownload.buffer, 1)
        accepted[#accepted + 1] = entry
      end
    end
  end

  return accepted
end

--- Process headers based on current state.
-- @param headers table: list of block_header objects
-- @return table|nil, string|nil: accepted headers (for storage), error
function HeadersSyncState:process_headers(headers)
  if self.state == HeadersSyncState.STATE.PRESYNC then
    local ok, err = self:process_presync(headers)
    if not ok then
      return nil, err
    end
    return {}, nil  -- No headers accepted yet in PRESYNC
  elseif self.state == HeadersSyncState.STATE.REDOWNLOAD then
    return self:process_redownload(headers)
  else
    return nil, "sync already complete"
  end
end

--- Check if sync is complete.
-- @return boolean: true if FINAL state
function HeadersSyncState:is_complete()
  return self.state == HeadersSyncState.STATE.FINAL
end

--- Check if we need to request more headers.
-- @return boolean: true if more headers needed
function HeadersSyncState:needs_headers()
  return self.state ~= HeadersSyncState.STATE.FINAL
end

-- Export the class
M.HeadersSyncState = HeadersSyncState

--------------------------------------------------------------------------------
-- HeaderChain: In-memory index for block headers
--------------------------------------------------------------------------------

local HeaderChain = {}
HeaderChain.__index = HeaderChain

--- Create a new HeaderChain instance.
-- @param network table: Network configuration (from consensus.networks)
-- @param storage table: Storage backend (from storage.open)
-- @return HeaderChain: New header chain instance
function M.new_header_chain(network, storage)
  local self = setmetatable({}, HeaderChain)
  self.network = network
  self.storage = storage
  self.header_tip_hash = nil     -- hash256 of current best header
  self.header_tip_height = -1
  self.headers = {}              -- hash_hex -> {header, height, total_work}
  self.height_to_hash = {}       -- height -> hash_hex
  self.syncing = false
  self.sync_peer = nil           -- peer currently syncing headers from
  return self
end

--------------------------------------------------------------------------------
-- Initialization
--------------------------------------------------------------------------------

--- Initialize the header chain from storage or genesis.
function HeaderChain:init()
  -- Check if we have a stored header tip (separate from chain tip!)
  io.stdout:write("  Checking header tip...\n"); io.stdout:flush()
  local tip_hash, tip_height = self:get_header_tip()
  if tip_hash then
    io.stdout:write(string.format("  Header tip: height=%d\n", tip_height)); io.stdout:flush()
    -- Load the header chain from storage
    self:load_from_storage(tip_hash, tip_height)
  else
    io.stdout:write("  No header tip found, starting from genesis\n"); io.stdout:flush()
    -- Start from genesis
    self:add_genesis()
  end
end

--- Get the header tip from storage (NOT the chain tip).
-- @return hash256|nil, number|nil: tip hash and height
function HeaderChain:get_header_tip()
  local data = self.storage.get(self.storage.CF.META, "header_tip")
  if not data or #data < 36 then
    return nil, nil
  end
  local hash = types.hash256(data:sub(1, 32))
  local r = serialize.buffer_reader(data:sub(33, 36))
  local height = r.read_u32le()
  return hash, height
end

--- Set the header tip in storage (NOT the chain tip).
-- @param hash hash256: tip hash
-- @param height number: tip height
-- @param sync boolean: whether to sync to disk
function HeaderChain:set_header_tip(hash, height, sync)
  local w = serialize.buffer_writer()
  w.write_hash256(hash)
  w.write_u32le(height)
  self.storage.put(self.storage.CF.META, "header_tip", w.result(), sync)
end

--- Load header chain from storage starting from a known tip.
-- @param tip_hash hash256: known tip hash
-- @param tip_height number: known tip height
function HeaderChain:load_from_storage(tip_hash, tip_height)
  -- Walk backwards from tip to genesis loading headers (without work yet)
  io.stdout:write(string.format("  Loading %d headers from storage...\n", tip_height + 1))
  io.stdout:flush()
  local current_hash = tip_hash
  local current_height = tip_height
  local loaded = 0

  while current_height >= 0 do
    local header = self.storage.get_header(current_hash)
    if not header then
      break
    end

    local hash_hex = types.hash256_hex(current_hash)
    self.headers[hash_hex] = {
      header = header,
      height = current_height,
      total_work = 0,  -- placeholder, filled in forward pass below
    }
    self.height_to_hash[current_height] = hash_hex
    loaded = loaded + 1

    if loaded % 10000 == 0 then
      io.stdout:write(string.format("  Loaded %d/%d headers...\n", loaded, tip_height + 1))
      io.stdout:flush()
    end

    if current_height == 0 then
      break
    end

    current_hash = header.prev_hash
    current_height = current_height - 1
  end

  io.stdout:write(string.format("  Loaded %d headers, computing work...\n", loaded))
  io.stdout:flush()

  -- Forward pass: compute total_work incrementally from genesis to tip
  local cumulative_work = 0
  for h = 0, tip_height do
    local hash_hex = self.height_to_hash[h]
    if hash_hex then
      local entry = self.headers[hash_hex]
      if entry and entry.header then
        cumulative_work = cumulative_work + self:work_for_bits(entry.header.bits)
        entry.total_work = cumulative_work
      end
    end
  end

  self.header_tip_hash = tip_hash
  self.header_tip_height = tip_height
end

--- Calculate total work from genesis to a given height.
-- This is called during load_from_storage.
-- @param height number: target height
-- @return number: total accumulated work
function HeaderChain:calculate_total_work_from_storage(height)
  -- For efficiency during loading, we calculate work incrementally
  -- This simplified version returns a placeholder; real impl would walk chain
  -- In practice, during load we compute this as we go
  local total = 0
  for h = 0, height do
    local hash_hex = self.height_to_hash[h]
    if hash_hex then
      local entry = self.headers[hash_hex]
      if entry and entry.header then
        total = total + self:work_for_bits(entry.header.bits)
      end
    else
      -- Not yet loaded; we'll compute during load
      local block_hash = self.storage.get_hash_by_height(h)
      if block_hash then
        local header = self.storage.get_header(block_hash)
        if header then
          total = total + self:work_for_bits(header.bits)
        end
      end
    end
  end
  return total
end

--- Add genesis block to the chain.
function HeaderChain:add_genesis()
  local gen = self.network.genesis

  -- Build genesis coinbase exactly matching Bitcoin Core to compute correct merkle root
  local msg = gen.coinbase_message
  -- scriptSig: PUSH4(486604799_le) PUSH1(0x04) PUSH_N(message)
  -- 486604799 = 0x1d00ffff, always hardcoded in Bitcoin Core's CreateGenesisBlock
  -- For messages > 75 bytes, use OP_PUSHDATA1 (0x4c) + length byte
  local msg_push
  if #msg > 75 then
    msg_push = "\x4c" .. string.char(#msg) .. msg  -- OP_PUSHDATA1
  else
    msg_push = string.char(#msg) .. msg
  end
  local script_sig = "\x04\xff\xff\x00\x1d\x01\x04" .. msg_push
  local coinbase_input = types.txin(
    types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
    script_sig, 0xFFFFFFFF
  )
  -- Use network-specific pubkey if provided, otherwise default to Satoshi's key
  local pubkey_hex = gen.coinbase_pubkey_hex or "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
  local pubkey = ""
  for i = 1, #pubkey_hex, 2 do
    pubkey = pubkey .. string.char(tonumber(pubkey_hex:sub(i, i+1), 16))
  end
  local output_script = string.char(#pubkey) .. pubkey .. "\xac"
  local subsidy = consensus.get_block_subsidy(0)
  local coinbase_tx = types.transaction(1,
    {coinbase_input},
    {types.txout(subsidy, output_script)},
    0)
  local txid = validation.compute_txid(coinbase_tx)
  local merkle_root = txid  -- single tx: merkle root == txid

  local header = types.block_header(
    gen.version,
    types.hash256_zero(),  -- prev_hash (genesis has no parent)
    merkle_root,
    gen.timestamp,
    gen.bits,
    gen.nonce
  )
  local hash = validation.compute_block_hash(header)
  local hash_hex = types.hash256_hex(hash)

  self.headers[hash_hex] = {
    header = header,
    height = 0,
    total_work = self:work_for_bits(gen.bits),
  }
  self.height_to_hash[0] = hash_hex
  self.header_tip_hash = hash
  self.header_tip_height = 0

  -- Store in database
  self.storage.put_header(hash, header)
  self.storage.put_height_index(0, hash)
  self:set_header_tip(hash, 0, true)
end

--------------------------------------------------------------------------------
-- Work Calculation
--------------------------------------------------------------------------------

--- Calculate proof-of-work for a given difficulty target.
-- Work = 2^256 / (target + 1)
-- Uses floating-point approximation (sufficient for chain comparison).
-- @param bits number: compact difficulty representation
-- @return number: work value
function HeaderChain:work_for_bits(bits)
  local target = consensus.bits_to_target(bits)

  -- Convert target to a number (use first 8 significant bytes)
  local target_num = 0
  for i = 1, 32 do
    if target:byte(i) ~= 0 then
      for j = i, math.min(i + 7, 32) do
        target_num = target_num * 256 + target:byte(j)
      end
      target_num = target_num * (256 ^ (32 - math.min(i + 7, 32)))
      break
    end
  end

  if target_num == 0 then
    return math.huge
  end

  -- Work = 2^256 / (target + 1)
  -- We use 2^256 ≈ 1.157920892373162e+77
  return 1.157920892373162e+77 / (target_num + 1)
end

--------------------------------------------------------------------------------
-- Header Processing
--------------------------------------------------------------------------------

--- Process a batch of headers received from a peer.
-- @param headers table: list of block_header objects
-- @param peer table: peer that sent the headers (optional, for banning)
-- @return number, string|nil: count accepted, error message if failed
function HeaderChain:process_headers(headers, peer)
  local accepted = 0

  for _, header in ipairs(headers) do
    local ok, err = self:accept_header(header)
    if not ok then
      return accepted, err
    end
    accepted = accepted + 1
  end

  if accepted > 0 then
    -- Persist the new header tip (NOT chain tip!)
    self:set_header_tip(self.header_tip_hash, self.header_tip_height, false)
  end

  return accepted, nil
end

--- Validate and accept a single header.
-- @param header block_header: header to validate
-- @return boolean, string|nil: success flag, error message
function HeaderChain:accept_header(header)
  -- 1. Compute the hash
  local hash = validation.compute_block_hash(header)
  local hash_hex = types.hash256_hex(hash)

  -- 2. Check if we already have this header
  if self.headers[hash_hex] then
    return true  -- Already known, skip
  end

  -- 3. Check that we have the parent
  local prev_hex = types.hash256_hex(header.prev_hash)
  local parent = self.headers[prev_hex]
  if not parent then
    return false, "unknown parent: " .. prev_hex
  end

  -- 4. Validate proof of work
  local target = consensus.bits_to_target(header.bits)
  if not consensus.hash_meets_target(hash.bytes, target) then
    return false, "insufficient proof of work"
  end

  -- 5. Check timestamp (must be > median time past of previous 11 blocks)
  local height = parent.height + 1
  local mtp_timestamps = self:get_past_timestamps(prev_hex, consensus.MEDIAN_TIME_PAST_BLOCKS)
  local mtp = consensus.get_median_time_past(mtp_timestamps)
  if header.timestamp <= mtp then
    return false, "timestamp not greater than median time past"
  end

  -- 6. Check difficulty target using consensus.get_next_work_required
  -- This handles mainnet, testnet3 walk-back, BIP94/testnet4, and regtest
  local chain = self
  local expected_bits = consensus.get_next_work_required(
    height,
    header.timestamp,
    self.network,
    function(h)
      local hex = chain.height_to_hash[h]
      if hex then return chain.headers[hex] end
      return nil
    end
  )
  if header.bits ~= expected_bits then
    return false, string.format("wrong difficulty: expected 0x%08x got 0x%08x",
      expected_bits, header.bits)
  end

  -- 7. Check against checkpoints
  local ok, cp_err = consensus.check_checkpoint(self.network, height, hash_hex)
  if not ok then
    return false, cp_err
  end

  -- 7b. Check anti-fork: reject headers that would create a fork before last checkpoint
  local chain = self
  local ok2, fork_err = consensus.check_checkpoint_anti_fork(
    self.network, height, hash_hex,
    function(h)
      local hex = chain.height_to_hash[h]
      if hex then
        local entry = chain.headers[hex]
        if entry then
          return { hash_hex = hex, header = entry.header }
        end
      end
      return nil
    end
  )
  if not ok2 then
    return false, fork_err
  end

  -- 8. Accept the header
  local work = parent.total_work + self:work_for_bits(header.bits)
  self.headers[hash_hex] = {
    header = header,
    height = height,
    total_work = work,
  }
  self.height_to_hash[height] = hash_hex

  -- Store in database
  self.storage.put_header(hash, header)
  self.storage.put_height_index(height, hash)

  -- Update tip if this chain has more total work
  local current_tip_work = 0
  if self.header_tip_hash then
    local tip_entry = self.headers[types.hash256_hex(self.header_tip_hash)]
    if tip_entry then
      current_tip_work = tip_entry.total_work
    end
  end

  if work > current_tip_work then
    self.header_tip_hash = hash
    self.header_tip_height = height
  end

  return true
end

--------------------------------------------------------------------------------
-- Difficulty Adjustment
--------------------------------------------------------------------------------

--- Calculate the next required difficulty target.
-- @param height number: height of the block being validated
-- @param header block_header: header being validated
-- @return number: expected compact bits value
function HeaderChain:calculate_next_work_required(height, header)
  local chain = self
  return consensus.get_next_work_required(
    height,
    header.timestamp,
    self.network,
    function(h)
      local hex = chain.height_to_hash[h]
      if hex then return chain.headers[hex] end
      return nil
    end
  )
end

--------------------------------------------------------------------------------
-- Block Locator
--------------------------------------------------------------------------------

--- Build a block locator for getheaders messages.
-- Returns hashes starting from tip, going back with exponentially increasing gaps:
-- tip, tip-1, tip-2, ..., tip-9, tip-11, tip-15, tip-23, tip-39, ..., genesis
-- @return table: list of hash256 objects
function HeaderChain:get_block_locator()
  local hashes = {}
  local step = 1
  local height = self.header_tip_height

  while height >= 0 do
    local hex = self.height_to_hash[height]
    if hex then
      local entry = self.headers[hex]
      if entry then
        hashes[#hashes + 1] = validation.compute_block_hash(entry.header)
      end
    end

    if height == 0 then
      break
    end

    height = height - step
    if height < 0 then
      height = 0
    end

    if #hashes >= 10 then
      step = step * 2
    end
  end

  return hashes
end

--------------------------------------------------------------------------------
-- Helper Functions
--------------------------------------------------------------------------------

--- Get timestamps of past N blocks for MTP calculation.
-- @param hash_hex string: hex hash of starting block
-- @param count number: number of timestamps to retrieve
-- @return table: list of timestamps (may be less than count near genesis)
function HeaderChain:get_past_timestamps(hash_hex, count)
  local timestamps = {}
  local current = hash_hex

  for _ = 1, count do
    local entry = self.headers[current]
    if not entry then
      break
    end
    timestamps[#timestamps + 1] = entry.header.timestamp
    current = types.hash256_hex(entry.header.prev_hash)
  end

  return timestamps
end

--- Get a header entry by hash.
-- @param hash hash256: block hash
-- @return table|nil: {header, height, total_work} or nil
function HeaderChain:get_header(hash)
  local hash_hex = types.hash256_hex(hash)
  return self.headers[hash_hex]
end

--- Get a header entry by height.
-- @param height number: block height
-- @return table|nil: {header, height, total_work} or nil
function HeaderChain:get_header_at_height(height)
  local hash_hex = self.height_to_hash[height]
  if not hash_hex then
    return nil
  end
  return self.headers[hash_hex]
end

--- Get the current tip hash.
-- @return hash256|nil: current tip hash
function HeaderChain:get_tip_hash()
  return self.header_tip_hash
end

--- Get the current tip height.
-- @return number: current tip height (-1 if uninitialized)
function HeaderChain:get_tip_height()
  return self.header_tip_height
end

--------------------------------------------------------------------------------
-- Sync Controller with Anti-DoS (PRESYNC/REDOWNLOAD)
--------------------------------------------------------------------------------

--- Check if a chain's work is below the minimum threshold.
-- @param total_work string: 32-byte cumulative work
-- @return boolean: true if below minimum
function HeaderChain:is_low_work_chain(total_work)
  local min_work = consensus.work_from_hex(
    self.network.min_chain_work or string.rep("00", 64)
  )
  return consensus.work_compare(total_work, min_work) < 0
end

--- Get the current chain work as a 32-byte big-endian value.
-- @return string: 32-byte cumulative work
function HeaderChain:get_chain_work()
  if self.header_tip_hash then
    local tip_hex = types.hash256_hex(self.header_tip_hash)
    local entry = self.headers[tip_hex]
    if entry then
      -- Convert floating-point work to approximate 32-byte value
      -- This is a simplification; for full precision we'd track work as bytes
      local work_float = entry.total_work
      local result = {}
      for i = 1, 32 do result[i] = 0 end
      -- Approximate conversion (sufficient for comparison with min_chain_work)
      local remaining = work_float
      for i = 32, 1, -1 do
        if remaining <= 0 then break end
        result[i] = math.floor(remaining % 256)
        remaining = math.floor(remaining / 256)
      end
      local out = {}
      for i = 1, 32 do out[i] = string.char(result[i]) end
      return table.concat(out)
    end
  end
  return consensus.work_zero()
end

--- Start header synchronization with a peer.
-- @param peer table: peer connection to sync from
function HeaderChain:start_sync(peer)
  self.syncing = true
  self.sync_peer = peer

  -- Initialize per-peer sync state tracking if not present
  self.peer_sync_states = self.peer_sync_states or {}

  local locator = self:get_block_locator()
  local payload = p2p.serialize_getheaders(
    p2p.PROTOCOL_VERSION,
    locator,
    types.hash256_zero()  -- no stop hash = get all
  )

  peer:send_message("getheaders", payload)
end

--- Try to initiate low-work header sync (PRESYNC/REDOWNLOAD).
-- Called when headers from peer would extend our chain but we haven't
-- verified they have sufficient work yet.
-- @param peer table: peer sending headers
-- @param headers table: headers received
-- @return boolean: true if low-work sync was initiated
function HeaderChain:try_low_work_sync(peer, headers)
  -- Get peer ID for tracking
  local peer_id = peer.id or tostring(peer)

  -- Check if we already have a sync state for this peer
  self.peer_sync_states = self.peer_sync_states or {}
  if self.peer_sync_states[peer_id] then
    return false  -- Already syncing with this peer
  end

  -- Calculate claimed work from headers
  local claimed_work = self:get_chain_work()
  for _, header in ipairs(headers) do
    local block_work = consensus.get_block_work(header.bits)
    claimed_work = consensus.work_add(claimed_work, block_work)
  end

  -- Check if claimed work is below minimum
  local min_work = consensus.work_from_hex(
    self.network.min_chain_work or string.rep("00", 64)
  )

  if consensus.work_compare(claimed_work, min_work) >= 0 then
    -- Chain has sufficient work, use normal sync
    return false
  end

  -- Only initiate low-work sync if we got a full batch (peer may have more)
  if #headers < 2000 then
    -- Chain doesn't have enough work and peer has no more headers
    return false
  end

  -- Create HeadersSyncState for this peer
  local chain_start = {
    hash = self.header_tip_hash,
    height = self.header_tip_height,
    work = self:get_chain_work()
  }

  local sync_state = M.new_headers_sync_state(peer_id, self.network, chain_start)
  self.peer_sync_states[peer_id] = sync_state

  -- Process the headers through PRESYNC
  local ok, err = sync_state:process_presync(headers)
  if not ok then
    -- Invalid headers - remove sync state
    self.peer_sync_states[peer_id] = nil
    return false
  end

  return true
end

--- Continue low-work header sync for a peer.
-- @param peer table: peer sending headers
-- @param headers table: headers received
-- @return table|nil, string|nil: accepted headers, error
function HeaderChain:continue_low_work_sync(peer, headers)
  local peer_id = peer.id or tostring(peer)
  local sync_state = self.peer_sync_states[peer_id]

  if not sync_state then
    return nil, "no sync state for peer"
  end

  -- Process headers based on current state
  local accepted, err = sync_state:process_headers(headers)
  if err then
    -- Invalid headers - remove sync state
    self.peer_sync_states[peer_id] = nil
    return nil, err
  end

  -- If sync is complete, cleanup
  if sync_state:is_complete() then
    self.peer_sync_states[peer_id] = nil
  end

  return accepted
end

--- Handle incoming headers message from a peer.
-- @param peer table: peer that sent the message
-- @param payload string: raw headers message payload
-- @return number, string|nil: count accepted (-1 for error), error message
function HeaderChain:handle_headers(peer, payload)
  -- Deserialize headers
  local headers = p2p.deserialize_headers(payload)

  if #headers == 0 then
    -- Sync complete - we're caught up
    self.syncing = false
    self.sync_peer = nil
    return 0
  end

  -- Check if this peer is in low-work sync mode (PRESYNC/REDOWNLOAD)
  local peer_id = peer.id or tostring(peer)
  self.peer_sync_states = self.peer_sync_states or {}
  local sync_state = self.peer_sync_states[peer_id]

  if sync_state then
    -- Continue low-work sync
    local accepted_entries, err = self:continue_low_work_sync(peer, headers)
    if err then
      return -1, err
    end

    -- Add accepted headers from REDOWNLOAD to our chain
    local accepted_count = 0
    if accepted_entries then
      for _, entry in ipairs(accepted_entries) do
        local ok, accept_err = self:accept_header(entry.header)
        if not ok then
          return accepted_count, accept_err
        end
        accepted_count = accepted_count + 1
      end
    end

    -- Request more headers if still syncing
    if sync_state:needs_headers() then
      local req = sync_state:get_getheaders_request()
      if req then
        local send_payload = p2p.serialize_getheaders(
          p2p.PROTOCOL_VERSION,
          req.locator_hashes,
          req.stop_hash
        )
        peer:send_message("getheaders", send_payload)
      end
    else
      -- Sync complete
      self.syncing = false
      self.sync_peer = nil
    end

    if accepted_count > 0 then
      self:set_header_tip(self.header_tip_hash, self.header_tip_height, false)
    end

    return accepted_count
  end

  -- Normal sync path - process headers directly
  local accepted, err = self:process_headers(headers, peer)
  if err then
    -- Check if this is just an unknown parent due to low-work chain
    -- In that case, try to initiate PRESYNC
    if err:match("unknown parent") and self:try_low_work_sync(peer, headers) then
      -- Low-work sync initiated, request more headers
      local new_sync_state = self.peer_sync_states[peer_id]
      if new_sync_state then
        local req = new_sync_state:get_getheaders_request()
        if req then
          local send_payload = p2p.serialize_getheaders(
            p2p.PROTOCOL_VERSION,
            req.locator_hashes,
            req.stop_hash
          )
          peer:send_message("getheaders", send_payload)
        end
      end
      return 0  -- Headers queued in PRESYNC, not yet accepted
    end
    -- Invalid headers - caller should ban peer
    return -1, err
  end

  -- If we got a full batch (2000 headers), request more
  if #headers >= 2000 then
    self:start_sync(peer)
  else
    -- Less than full batch means we're caught up
    self.syncing = false
    self.sync_peer = nil
  end

  return accepted
end

--- Check if we're currently syncing headers.
-- @return boolean: true if syncing
function HeaderChain:is_syncing()
  return self.syncing
end

--- Get the peer we're currently syncing from.
-- @return table|nil: sync peer or nil
function HeaderChain:get_sync_peer()
  return self.sync_peer
end

--- Stop the current sync operation.
function HeaderChain:stop_sync()
  self.syncing = false
  self.sync_peer = nil
end

--- Get the low-work sync state for a peer.
-- @param peer table: peer to query
-- @return HeadersSyncState|nil: sync state or nil
function HeaderChain:get_peer_sync_state(peer)
  local peer_id = peer.id or tostring(peer)
  self.peer_sync_states = self.peer_sync_states or {}
  return self.peer_sync_states[peer_id]
end

--- Clear the low-work sync state for a peer.
-- @param peer table: peer to clear
function HeaderChain:clear_peer_sync_state(peer)
  local peer_id = peer.id or tostring(peer)
  self.peer_sync_states = self.peer_sync_states or {}
  self.peer_sync_states[peer_id] = nil
end

-- Export the HeaderChain class for direct access if needed
M.HeaderChain = HeaderChain

--------------------------------------------------------------------------------
-- BlockDownloader: Manages block downloading during IBD
--------------------------------------------------------------------------------

local BlockDownloader = {}
BlockDownloader.__index = BlockDownloader

--- Create a new BlockDownloader instance.
-- @param header_chain HeaderChain: The header chain for block ordering
-- @param storage table: Storage backend
-- @param network table: Network configuration
-- @return BlockDownloader: New block downloader instance
function M.new_block_downloader(header_chain, storage, network)
  local self = setmetatable({}, BlockDownloader)
  self.header_chain = header_chain
  self.storage = storage
  self.network = network
  self.download_window = 1024       -- Max blocks in-flight total
  self.blocks_per_peer = 16         -- Max blocks requested per peer at once
  self.next_download_height = 0     -- Next block height to request
  self.next_connect_height = 0      -- Next block height to connect to chain
  self.pending_blocks = {}          -- hash_hex -> {block, height, hash}
  self.inflight = {}                -- hash_hex -> {peer, request_time, timeout}
  self.peer_inflight = {}           -- peer -> count of in-flight requests
  -- Base timeout before considering stalled. W65 raised 20 -> 60: a 20 s
  -- timeout is too aggressive for 1 MB+ old-era blocks when the pure-Lua
  -- deserialize on the main thread takes several seconds per block under
  -- concurrent multi-peer ingestion. Observed at height 565,083 on
  -- 2026-04-18: 30+ peers issued getdata, block in transit timed out at
  -- 20 s before finishing reassembly, re-requested, timed out again — for
  -- 5.75 h. 60 s matches Bitcoin Core's block-download timeout floor.
  self.base_stall_timeout = 60
  self.max_stall_timeout = 120      -- Maximum stall timeout
  self.ibd_complete = false
  self.connect_callback = nil       -- Called when a block is connected: fn(block, height, hash)
  -- IBD durability: how often to fsync the chainstate to disk. The
  -- per-block flush goes to RocksDB with sync=false (memtable + WAL
  -- in OS page cache); at this cadence we issue a sync write so the
  -- WAL up to that point is fsync'd. Bounds data loss on a hard
  -- crash (EMFILE / OOM / power loss) to at most utxo_flush_interval
  -- blocks of work.
  --
  -- Was 2000 before 2026-04-28; lowered to 200 after the
  -- h=938,344 wedge (project_lunarblock_wedge_2026_04_28). 200 blocks
  -- is ~30s at typical IBD rate; we additionally force a sync if more
  -- than utxo_flush_max_seconds wall-clock have elapsed since the
  -- last sync, so a slow IBD stretch can't extend the loss window.
  self.utxo_flush_interval = 200
  self.utxo_flush_max_seconds = 60
  self.last_flush_height = 0
  self.last_flush_time = 0
  self.peer_round_robin = 1         -- Persistent round-robin index across schedule_downloads calls
  self.last_connect_advance = 0     -- Timestamp when next_connect_height last advanced
  self.connect_stall_timeout = 90   -- Seconds without connection progress before forced reset
  self.max_blocks_per_connect = 8   -- Max blocks to connect per call (prevents RPC starvation)
  -- W72 instrumentation: per-window deserialize/hash stats. Replaced with
  -- a fresh table after each [W72-DESER] log line so averages are
  -- rolling-window not lifetime.  Removed when the Tier-3 FFI deserialize
  -- path lands.
  self.deser_win = { n = 0, t = 0, h_t = 0, b = 0, txs = 0, d_max = 0, h_max = 0 }
  self.deser_lifetime = 0
  self.deser_log_every = 500
  -- W75 instrumentation: per-window connect_pending_blocks phase timings.
  -- The W72 deser-only probe proved deserialize is ~84 ms/block on the
  -- overnight-run-2 mainnet sync — but overall cadence is ~900 ms/block
  -- (≈4000 blk/hr).  The remaining ~800 ms/block lives in check_block →
  -- connect_callback (UTXO apply) → put_block → set_chain_tip → flush.
  -- This window attributes it per-phase so a future Tier-3 optimisation
  -- targets the right hot spot instead of guessing.
  self.conn_win = { n = 0, validate_t = 0, cb_t = 0, put_t = 0, tip_t = 0,
                    flush_t = 0, total_t = 0,
                    v_max = 0, cb_max = 0, p_max = 0, total_max = 0 }
  self.conn_lifetime = 0
  self.conn_log_every = 500
  return self
end

--------------------------------------------------------------------------------
-- Download Scheduling
--------------------------------------------------------------------------------

--- Schedule block downloads across available peers.
-- Uses round-robin assignment with per-peer in-flight tracking.
-- @param peers table: list of established peers with NODE_NETWORK service
function BlockDownloader:schedule_downloads(peers)
  if #peers == 0 then return end
  if self.ibd_complete then return end

  local socket = require("socket")
  local now = socket.gettime()

  -- Check for stalled requests and handle adaptive timeout
  local had_stalls = false
  for hash_hex, info in pairs(self.inflight) do
    if now - info.request_time > info.timeout then
      -- Do NOT score misbehavior for stalling block downloads during IBD.
      -- Old blocks may legitimately be slow to serve (peer rate-limits, pruned
      -- nodes, network congestion). Scoring +N per stalled entry caused mass
      -- peer disconnection storms: a peer with 10+ stalled inflight entries
      -- would hit the 100-threshold in a single schedule_downloads pass,
      -- causing all peers to disconnect simultaneously and stalling IBD for
      -- minutes (W21 RPC starvation fix). Instead, just re-request from
      -- other peers by leaving had_stalls=true (cursor reset below).
      -- Stalled request - remove from inflight and peer tracking
      self.inflight[hash_hex] = nil
      if self.peer_inflight[info.peer] then
        self.peer_inflight[info.peer] = self.peer_inflight[info.peer] - 1
        if self.peer_inflight[info.peer] <= 0 then
          self.peer_inflight[info.peer] = nil
        end
      end
      had_stalls = true
    end
  end

  -- Calculate how many more blocks we can request
  local inflight_count = 0
  for _ in pairs(self.inflight) do inflight_count = inflight_count + 1 end
  local available = self.download_window - inflight_count
  if available <= 0 then return end

  -- Reset download cursor when there are gaps between the connection cursor
  -- and the download cursor but nothing is in-flight. This ensures blocks
  -- that were never received (peer disconnected, pruned node, etc.) get
  -- re-requested from different peers.
  if had_stalls or (inflight_count == 0 and self.next_download_height > self.next_connect_height) then
    self.next_download_height = self.next_connect_height
  end

  -- Detect persistent connection stall: if next_connect_height hasn't advanced
  -- for connect_stall_timeout seconds, force a full reset. This is the
  -- last-resort safety net for wedges where the block at next_connect_height
  -- is being requested-and-timed-out repeatedly without ever reaching
  -- handle_block (peer black-hole, pending-eviction, CPU-starved event loop).
  --
  -- W65 FIX: The timer is driven by actual next_connect_height advance,
  -- stamped in connect_pending_blocks (success path + invalid-skip path).
  -- Previously the else-branch here re-armed the timer whenever
  -- next_download_height <= next_connect_height, which the had_stalls
  -- reset above forces true every 5-10 s under stall pressure. Result:
  -- the 90 s recovery timer was dead code under exactly the conditions
  -- it was meant to catch. Observed at mainnet height 565,083 on
  -- 2026-04-18: node stuck 5.75 h, recovery never fired once.
  if self.last_connect_advance == 0 then
    self.last_connect_advance = now
  end
  if now - self.last_connect_advance > self.connect_stall_timeout then
    -- Surgical recovery: clear ONLY the inflight entry for the block that's
    -- actually blocking progress at next_connect_height. Leaving other
    -- peers' inflight alone prevents the LATE_ARRIVAL burst seen under the
    -- old nuclear-clear: ~990 healthy inflight blocks would arrive shortly
    -- after the reset but be rejected by handle_block's W71 guard, wasting
    -- the peers' bandwidth and forcing a re-download of the whole window.
    -- The W46 FORCE RE-REQUEST path below handles the actual re-request for
    -- the stuck hash on every scheduler pass.
    local cleared = 0
    local stuck_hash_hex = self.header_chain.height_to_hash[self.next_connect_height]
    if stuck_hash_hex then
      local info = self.inflight[stuck_hash_hex]
      if info then
        if self.peer_inflight[info.peer] then
          self.peer_inflight[info.peer] = self.peer_inflight[info.peer] - 1
          if self.peer_inflight[info.peer] <= 0 then
            self.peer_inflight[info.peer] = nil
          end
        end
        self.inflight[stuck_hash_hex] = nil
        cleared = 1
      end
    end
    -- W71 zombie sweep: drop pending entries behind the cursor. Defence in
    -- depth against future code paths that re-seed below the cursor; the
    -- primary guard is in handle_block. Do NOT evict far-ahead pending —
    -- those blocks will connect naturally once the cursor catches up.
    local evicted = 0
    for k, p in pairs(self.pending_blocks) do
      if p.height < self.next_connect_height then
        self.pending_blocks[k] = nil
        evicted = evicted + 1
      end
    end
    -- Reset the timer so we don't re-enter every scheduler tick; the real
    -- signal of recovery is connect_pending_blocks advancing
    -- next_connect_height, which stamps last_connect_advance afresh.
    self.last_connect_advance = now
    print(string.format(
      "STALL RECOVERY: connection stuck at %d for >%ds, cleared %d stuck inflight, evicted %d zombie pending",
      self.next_connect_height, self.connect_stall_timeout, cleared, evicted))
    -- Recalculate inflight count after clearing
    inflight_count = 0
    for _ in pairs(self.inflight) do inflight_count = inflight_count + 1 end
    available = self.download_window - inflight_count
  end

  -- Filter peers with available slots AND that can actually serve blocks
  -- (peers advertising height=0 or very low height cannot serve IBD blocks)
  local min_useful_height = self.next_connect_height
  local available_peers = {}
  for _, p in ipairs(peers) do
    local peer_count = self.peer_inflight[p] or 0
    if peer_count < self.blocks_per_peer and (p.start_height or 0) >= min_useful_height then
      available_peers[#available_peers + 1] = p
    end
  end
  if #available_peers == 0 then return end

  -- Build requests per peer (batch multiple inv items per getdata)
  local peer_requests = {}
  for _, p in ipairs(available_peers) do
    peer_requests[p] = {}
  end

  -- W46 FORCE RE-REQUEST: if the connector is stuck at next_connect_height
  -- because the block was never received (header in memory, nothing in pending
  -- or storage), issue a fresh getdata for it BEFORE the normal cursor-based
  -- loop. Without this, next_download_height has already moved past so the
  -- normal loop never touches this height, and the three fallback paths
  -- (STALL RECOVERY, had_stalls reset, invalid-block skip) do not fire
  -- because no inflight exists to time out. Rate-limited to once every 30s
  -- per stuck hash so we don't spam peers.
  if self.next_connect_height < self.next_download_height then
    local stuck_hash_hex = self.header_chain.height_to_hash[self.next_connect_height]
    if stuck_hash_hex
      and not self.inflight[stuck_hash_hex]
      and not self.pending_blocks[stuck_hash_hex] then
      self._force_rerequest_last = self._force_rerequest_last or {}
      local last = self._force_rerequest_last[stuck_hash_hex] or 0
      if now - last >= 30 then
        local entry = self.header_chain.headers[stuck_hash_hex]
        if entry then
          local picked = nil
          for _, p in ipairs(available_peers) do
            local pc = self.peer_inflight[p] or 0
            if pc < self.blocks_per_peer then
              picked = p
              break
            end
          end
          if picked then
            self._force_rerequest_last[stuck_hash_hex] = now
            local stuck_block_hash = validation.compute_block_hash(entry.header)
            peer_requests[picked][#peer_requests[picked] + 1] = {
              type = p2p.INV_TYPE.MSG_WITNESS_BLOCK,
              hash = stuck_block_hash,
            }
            self.inflight[stuck_hash_hex] = {
              peer = picked,
              request_time = now,
              timeout = self.base_stall_timeout,
            }
            available = available - 1
            print(string.format(
              "FORCE-REREQUEST (W46): height=%d hash=%s peer=%s",
              self.next_connect_height, stuck_hash_hex,
              tostring(picked.address or picked.ip or "?")))
          end
        end
      end
    end
  end

  -- Use persistent round-robin index to avoid always assigning the first
  -- block to the same peer after stall-induced cursor resets.
  local peer_idx = self.peer_round_robin
  local height = self.next_download_height
  local tip = self.header_chain.header_tip_height

  -- Log scheduling state periodically (once per minute) to aid debugging stalls
  local _sched_now = now
  if not self._last_sched_log or _sched_now - self._last_sched_log > 60 then
    self._last_sched_log = _sched_now
    print(string.format("schedule_downloads: next_dl=%d next_conn=%d tip=%d available=%d peers=%d had_stalls=%s",
      self.next_download_height, self.next_connect_height, tip, available, #available_peers,
      tostring(had_stalls)))
  end

  -- Don't download too far ahead of connection cursor
  local max_ahead = self.next_connect_height + self.download_window
  while height <= tip and height <= max_ahead and available > 0 do
    local hash_hex = self.header_chain.height_to_hash[height]
    if not hash_hex then break end

    -- Skip if already downloaded or in-flight
    if not self.pending_blocks[hash_hex] and not self.inflight[hash_hex] then
      -- Check if block already in storage. For blocks near the connection
      -- cursor, skip the storage check — connect_pending_blocks will load
      -- them from storage if needed. Only skip downloads for blocks well
      -- ahead of the connection cursor (which are truly already connected).
      local entry = self.header_chain.headers[hash_hex]
      if entry then
        local block_hash = validation.compute_block_hash(entry.header)
        local need_download = true

        -- Only check storage for blocks ahead of next_connect_height.
        -- Blocks AT or NEAR next_connect_height might be in storage but
        -- not yet connected (stored before callback succeeded). Those are
        -- handled by connect_pending_blocks' storage fallback, so we skip
        -- downloading them to avoid wasting bandwidth.
        if height > self.next_connect_height then
          local existing = self.storage.get(self.storage.CF.BLOCKS, block_hash.bytes)
          if existing then
            need_download = false
          end
        end

        if need_download then
          -- Find a peer with available slots (round-robin)
          local attempts = 0
          local scheduled = false
          while attempts < #available_peers do
            local p = available_peers[((peer_idx - 1) % #available_peers) + 1]
            local peer_count = self.peer_inflight[p] or 0
            local reqs = peer_requests[p]

            if peer_count + #reqs < self.blocks_per_peer then
              reqs[#reqs + 1] = {
                type = p2p.INV_TYPE.MSG_WITNESS_BLOCK,
                hash = block_hash
              }
              self.inflight[hash_hex] = {
                peer = p,
                request_time = now,
                timeout = self.base_stall_timeout
              }
              available = available - 1
              peer_idx = peer_idx + 1
              scheduled = true
              break
            end
            peer_idx = peer_idx + 1
            attempts = attempts + 1
          end
          -- W47: if every peer is saturated at blocks_per_peer, do NOT
          -- advance `height`. Breaking keeps next_download_height parked
          -- so this height is retried next schedule_downloads call.
          -- Without this break, the outer loop skipped the height (never
          -- enqueued, never inflight, never pending) and relied on W46's
          -- force-rerequest to recover it one-at-a-time at the connect
          -- cursor — which capped IBD at ~800 blocks/hr.
          if not scheduled then
            break
          end
        end
      end
    end
    height = height + 1
  end

  self.next_download_height = height
  self.peer_round_robin = peer_idx  -- Persist round-robin index

  -- Send batched getdata requests
  for p, items in pairs(peer_requests) do
    if #items > 0 then
      -- Update peer inflight count
      self.peer_inflight[p] = (self.peer_inflight[p] or 0) + #items
      p:send_message("getdata", p2p.serialize_inv(items))
    end
  end
end

--------------------------------------------------------------------------------
-- Block Receipt Handling
--------------------------------------------------------------------------------

--- Handle a notfound response for a block hash.
-- Removes the block from inflight so it can be re-requested from a different peer.
-- @param hash_hex string: hex hash of the block not found
-- @param peer table: peer that sent the notfound
function BlockDownloader:handle_notfound(hash_hex, peer)
  local info = self.inflight[hash_hex]
  if info then
    self.inflight[hash_hex] = nil
    if self.peer_inflight[info.peer] then
      self.peer_inflight[info.peer] = self.peer_inflight[info.peer] - 1
      if self.peer_inflight[info.peer] <= 0 then
        self.peer_inflight[info.peer] = nil
      end
    end
    -- Reset download cursor to re-request this block from another peer
    local entry = self.header_chain.headers[hash_hex]
    if entry and entry.height <= self.next_download_height then
      self.next_download_height = entry.height
    end
  end
end

--- Handle a received block from a peer.
-- @param peer table: peer that sent the block
-- @param block_data string: raw block message payload
-- @return boolean, string|nil: success flag, error message
function BlockDownloader:handle_block(peer, block_data)
  -- Deserialize the block + compute the block hash.  Timed for W72: the
  -- working hypothesis is that pure-Lua deserialize dominates the IBD
  -- per-block budget on 1 MB+ blocks; the sync-constructor comment on
  -- base_stall_timeout explicitly blames "pure-Lua deserialize on the
  -- main thread takes several seconds per block".  Before we spend days
  -- on an FFI replacement we want the actual ms-per-block number.
  local t0 = perf.now()
  -- Pure-Lua deserialize_block raises on malformed wire data via the
  -- error()/assert() calls in serialize.lua. Without pcall here, the
  -- throw propagates through main.lua:687 → peer.lua:745 (neither
  -- wraps the handler) and kills the peer's message-processing loop.
  -- Result: a malformed block payload silently drops the peer AND
  -- the inflight entry never clears at line 1622, so the cursor
  -- wedges until STALL RECOVERY fires 90s later. Observed on mainnet
  -- 2026-04-19 at heights 647,650-647,740 as the `in_pending=no,
  -- block_in_storage=no` pattern in connect_pending_blocks stall log.
  local ok_d, block = pcall(serialize.deserialize_block, block_data)
  if not ok_d then
    print(string.format("[BLOCK-DROP] DESER_FAIL peer=%s bytes=%d err=%s",
      tostring(peer and peer.addr), #block_data, tostring(block)))
    return false, "deserialize failed"
  end
  local t1 = perf.now()
  local hash = validation.compute_block_hash(block.header)
  local t2 = perf.now()
  local hash_hex = types.hash256_hex(hash)

  local w = self.deser_win
  local d = t1 - t0
  local h = t2 - t1
  w.n = w.n + 1
  w.t = w.t + d
  w.h_t = w.h_t + h
  w.b = w.b + #block_data
  w.txs = w.txs + #block.transactions
  if d > w.d_max then w.d_max = d end
  if h > w.h_max then w.h_max = h end
  self.deser_lifetime = self.deser_lifetime + 1
  if w.n >= self.deser_log_every then
    local mb_s = (w.b / 1048576) / math.max(w.t, 1e-9)
    print(string.format(
      "[W72-DESER] window=%d total=%d deser_avg=%.2fms hash_avg=%.2fms bytes_avg=%.0f txs_avg=%.0f d_max=%.1fms h_max=%.1fms throughput=%.1f MB/s",
      w.n, self.deser_lifetime,
      (w.t / w.n) * 1000, (w.h_t / w.n) * 1000,
      w.b / w.n, w.txs / w.n,
      w.d_max * 1000, w.h_max * 1000, mb_s))
    self.deser_win = { n = 0, t = 0, h_t = 0, b = 0, txs = 0, d_max = 0, h_max = 0 }
  end

  -- Update adaptive timeout on success (decay toward base)
  local info = self.inflight[hash_hex]
  if info and info.peer == peer then
    -- Success: reduce timeout toward base
    info.timeout = math.max(self.base_stall_timeout, info.timeout / 2)
  end

  -- Remove from inflight and update peer tracking
  if self.inflight[hash_hex] then
    local inflight_peer = self.inflight[hash_hex].peer
    self.inflight[hash_hex] = nil
    if self.peer_inflight[inflight_peer] then
      self.peer_inflight[inflight_peer] = self.peer_inflight[inflight_peer] - 1
      if self.peer_inflight[inflight_peer] <= 0 then
        self.peer_inflight[inflight_peer] = nil
      end
    end
  end

  -- Find the height for this block
  local entry = self.header_chain.headers[hash_hex]
  if not entry then
    -- Unknown block, ignore
    return true
  end

  -- W71: drop late-arrivals for already-connected heights. Without this,
  -- duplicate responses (e.g. peers replying to a getdata after W65
  -- STALL RECOVERY already cleared the inflight entry) accumulate in
  -- pending_blocks as zombies. Over long stall/rerequest cycles they
  -- fill the 1024-slot buffer; once max_height across pending falls
  -- below next_connect_height, the eviction check
  --   `entry.height < max_height`
  -- rejects every new-cursor block instead of evicting a zombie,
  -- wedging IBD permanently. Observed on mainnet at height 576466
  -- on 2026-04-18 (2h+ wedge, Pending=1024 pinned, 421 re-requests).
  if entry.height < self.next_connect_height then
    print(string.format("[BLOCK-DROP] LATE_ARRIVAL height=%d next_connect=%d hash=%s",
      entry.height, self.next_connect_height, hash_hex:sub(1, 16)))
    return true
  end

  -- Bound the pending buffer to prevent OOM. At ~500KB per mainnet block,
  -- 1024 blocks ≈ 512MB. The cap MUST match download_window — otherwise
  -- prefetched blocks at the far end of the window get evicted back to the
  -- network, and when next_connect_height advances near them, they must be
  -- re-requested (adding ~1-3 min per-block latency at the cursor).
  -- Observed in Wave 32: pending=512 with window=1024 caused per-block
  -- stalls every ~1 min, throttling IBD to ~1,500 blk/hr.
  local pending_cap = self.download_window  -- match download_window (1024)
  local pending_count = 0
  for _ in pairs(self.pending_blocks) do pending_count = pending_count + 1 end
  if pending_count >= pending_cap then
    -- Evict the block furthest from the connection cursor
    local max_height_hex, max_height = nil, -1
    for k, p in pairs(self.pending_blocks) do
      if p.height > max_height then
        max_height = p.height
        max_height_hex = k
      end
    end
    if max_height_hex and entry.height < max_height then
      self.pending_blocks[max_height_hex] = nil
    else
      print(string.format("[BLOCK-DROP] BUFFER_FULL pending=%d cap=%d height=%d max_in_buf=%d hash=%s",
        pending_count, pending_cap, entry.height, max_height, hash_hex:sub(1, 16)))
      return true  -- This block is even further ahead, drop it
    end
  end

  -- Store in pending
  self.pending_blocks[hash_hex] = {
    block = block,
    height = entry.height,
    hash = hash,
  }

  -- Try to connect blocks in order
  return self:connect_pending_blocks()
end

--------------------------------------------------------------------------------
-- Block Connection
--------------------------------------------------------------------------------

--- Connect pending blocks in height order.
-- Processes blocks sequentially starting from next_connect_height.
-- Limits blocks per call to self.max_blocks_per_connect so the outer main
-- loop can service RPC requests between batches (prevents event-loop starvation).
-- @return boolean, string|nil: success flag, error message
function BlockDownloader:connect_pending_blocks()
  -- Connect blocks in height order starting from next_connect_height
  local blocks_this_call = 0
  while true do
    -- Yield back to event loop after max_blocks_per_connect blocks to allow
    -- RPC and P2P I/O to be serviced (W21 cooperative-loop starvation fix).
    if blocks_this_call >= self.max_blocks_per_connect then
      break
    end
    local hash_hex = self.header_chain.height_to_hash[self.next_connect_height]
    if not hash_hex then
      -- Debug: missing header at this height
      local socket = require("socket")
      local now = socket.gettime()
      if not self._last_missing_log or now - self._last_missing_log > 60 then
        self._last_missing_log = now
        print(string.format("connect_pending_blocks: no header for height %d (header_tip=%d)",
          self.next_connect_height, self.header_chain.header_tip_height))
      end
      break
    end

    local pending = self.pending_blocks[hash_hex]

    -- If the block is not in pending_blocks, check storage. This handles
    -- the case where a block was stored (put_block) in a previous attempt
    -- but the UTXO connection failed or the process was restarted before
    -- next_connect_height was advanced. Without this fallback, the
    -- scheduler sees the block in storage and never re-downloads it,
    -- while connect_pending_blocks cannot find it in pending — deadlock.
    if not pending then
      local entry = self.header_chain.headers[hash_hex]
      if entry then
        local block_hash = validation.compute_block_hash(entry.header)
        local block_data = self.storage.get(self.storage.CF.BLOCKS, block_hash.bytes)
        if block_data then
          local deser_ok, block = pcall(serialize.deserialize_block, block_data)
          if deser_ok and block then
            pending = {
              block = block,
              height = entry.height,
              hash = block_hash,
            }
            print(string.format("Recovered block %d from storage (was stored but not connected)",
              entry.height))
          else
            print(string.format("Warning: corrupted block %d in storage, will re-download: %s",
              entry.height, tostring(block)))
          end
        end
      end
    end

    if not pending then
      -- Debug: log why connection stalled (but only once per minute to avoid spam)
      local socket = require("socket")
      local now = socket.gettime()
      if not self._last_stall_log or now - self._last_stall_log > 60 then
        self._last_stall_log = now
        local in_pending = self.pending_blocks[hash_hex] and "yes" or "no"
        -- W46: print full hash (not sub(1,16)) and probe whether the in-memory
        -- headers map has an entry for hash_hex. This distinguishes two failure
        -- modes: header_in_mem=false means height_to_hash / headers consistency
        -- gap; header_in_mem=true means the block was never downloaded/stored.
        local header_in_mem = self.header_chain.headers[hash_hex] ~= nil
        local block_in_storage = "unknown"
        if header_in_mem then
          local entry = self.header_chain.headers[hash_hex]
          local block_hash = validation.compute_block_hash(entry.header)
          block_in_storage = self.storage.get(self.storage.CF.BLOCKS, block_hash.bytes) and "yes" or "no"
        end
        print(string.format("connect_pending_blocks: stalled at height %d, hash_hex=%s, in_pending=%s, header_in_mem=%s, block_in_storage=%s",
          self.next_connect_height, hash_hex or "NIL", in_pending,
          tostring(header_in_mem), block_in_storage))
      end
      break
    end

    -- Validate the full block
    local _cp0 = perf.now()
    local ok, err = pcall(function()
      validation.check_block(pending.block, self.network, pending.height)
    end)
    local _cp1 = perf.now()

    if not ok then
      -- Invalid block, remove from pending and skip this height.
      -- Incrementing next_connect_height prevents permanent stall on a
      -- block that repeatedly fails context-free validation.
      self.pending_blocks[hash_hex] = nil
      print(string.format("Skipping invalid block at height %d: %s",
        self.next_connect_height, tostring(err)))
      self.next_connect_height = self.next_connect_height + 1
      -- Reset stall-recovery timer: skipping is still cursor advance.
      local _sock = require("socket")
      self.last_connect_advance = _sock.gettime()
      -- Continue loop to try next height rather than returning immediately
      goto continue_loop
    end

    -- Notify callback (for UTXO updates, etc.) BEFORE storing the block.
    -- This ensures that if the callback fails, the block is NOT in storage
    -- and the scheduler will re-download it on the next attempt.
    if self.connect_callback then
      local cb_ok, cb_err = pcall(self.connect_callback, pending.block, pending.height, pending.hash)
      if not cb_ok then
        -- Callback failed (e.g., UTXO validation error). Remove from pending
        -- but do NOT advance height — the block may need to be retried after
        -- fixing state. Do NOT store to disk so the scheduler re-downloads it.
        self.pending_blocks[hash_hex] = nil
        print(string.format("Block %d connect callback failed: %s",
          self.next_connect_height, tostring(cb_err)))
        return false, cb_err
      end
    end
    local _cp2 = perf.now()

    -- Store the block AFTER successful connection (callback passed)
    self.storage.put_block(pending.hash, pending.block)
    local _cp3 = perf.now()
    self.storage.set_chain_tip(pending.hash, pending.height, false)
    local _cp4 = perf.now()

    -- Clear cached serialization data to free memory
    for _, tx in ipairs(pending.block.transactions) do
      tx._cached_base_data = nil
      tx._cached_witness_data = nil
      tx._cached_txid = nil
      tx._cached_wtxid = nil
    end

    self.pending_blocks[hash_hex] = nil
    self.next_connect_height = self.next_connect_height + 1
    blocks_this_call = blocks_this_call + 1

    -- Reset stall timer on successful connection
    local _sock = require("socket")
    self.last_connect_advance = _sock.gettime()

    -- Flush UTXO set periodically during IBD. The sync=true write of
    -- chain_tip fsyncs the WAL up to that point, durably persisting
    -- ALL prior writes (the per-block atomic batch from connect_block,
    -- which ran with sync=false). Two trigger conditions:
    --   1. utxo_flush_interval blocks since last sync (bounds loss-by-block)
    --   2. utxo_flush_max_seconds wall-clock since last sync (bounds
    --      loss-by-time, in case IBD is slow due to disk pressure /
    --      compaction lag, which is exactly the regime where a crash
    --      becomes more likely).
    local _flush_t = 0
    do
      local _now = require("socket").gettime()
      if self.last_flush_time == 0 then
        self.last_flush_time = _now
      end
      local block_trigger = self.next_connect_height - self.last_flush_height >= self.utxo_flush_interval
      local time_trigger = _now - self.last_flush_time >= self.utxo_flush_max_seconds
      if block_trigger or time_trigger then
        local _fp0 = perf.now()
        self.storage.set_chain_tip(pending.hash, pending.height, true)  -- sync write
        _flush_t = perf.now() - _fp0
        self.last_flush_height = self.next_connect_height
        self.last_flush_time = _now
      end
    end

    -- W75 instrumentation: accumulate per-phase timings for this block into
    -- the rolling window and emit a summary every conn_log_every blocks.
    -- Only success-path blocks count — invalid-skip and callback-failure
    -- paths exit above without reaching here.
    do
      local cw = self.conn_win
      local _vt = _cp1 - _cp0   -- validate
      local _ct = _cp2 - _cp1   -- connect_callback (UTXO apply)
      local _pt = _cp3 - _cp2   -- storage.put_block
      local _tt = _cp4 - _cp3   -- storage.set_chain_tip (async)
      local _total = _vt + _ct + _pt + _tt + _flush_t
      cw.n = cw.n + 1
      cw.validate_t = cw.validate_t + _vt
      cw.cb_t = cw.cb_t + _ct
      cw.put_t = cw.put_t + _pt
      cw.tip_t = cw.tip_t + _tt
      cw.flush_t = cw.flush_t + _flush_t
      cw.total_t = cw.total_t + _total
      if _vt > cw.v_max then cw.v_max = _vt end
      if _ct > cw.cb_max then cw.cb_max = _ct end
      if _pt > cw.p_max then cw.p_max = _pt end
      if _total > cw.total_max then cw.total_max = _total end
      self.conn_lifetime = self.conn_lifetime + 1
      if cw.n >= self.conn_log_every then
        print(string.format(
          "[W75-CONN] window=%d total=%d validate_avg=%.1fms cb_avg=%.1fms put_avg=%.1fms tip_avg=%.1fms flush_avg=%.1fms total_avg=%.1fms v_max=%.0fms cb_max=%.0fms p_max=%.0fms t_max=%.0fms",
          cw.n, self.conn_lifetime,
          (cw.validate_t / cw.n) * 1000, (cw.cb_t / cw.n) * 1000,
          (cw.put_t / cw.n) * 1000, (cw.tip_t / cw.n) * 1000,
          (cw.flush_t / cw.n) * 1000, (cw.total_t / cw.n) * 1000,
          cw.v_max * 1000, cw.cb_max * 1000, cw.p_max * 1000, cw.total_max * 1000))
        self.conn_win = { n = 0, validate_t = 0, cb_t = 0, put_t = 0, tip_t = 0,
                          flush_t = 0, total_t = 0,
                          v_max = 0, cb_max = 0, p_max = 0, total_max = 0 }
      end
    end

    -- Periodic incremental GC to prevent LuaJIT table bloat
    if self.next_connect_height % 1000 == 0 then
      collectgarbage("step", 100)
    end

    -- Log progress periodically
    if self.next_connect_height % 10000 == 0 then
      local progress = self.next_connect_height / self.header_chain.header_tip_height * 100
      io.write(string.format("\rIBD Progress: %d / %d (%.1f%%)",
        self.next_connect_height, self.header_chain.header_tip_height, progress))
      io.flush()
    end

    ::continue_loop::
  end

  -- Check if IBD is complete
  if self.next_connect_height > self.header_chain.header_tip_height then
    self.ibd_complete = true
    print("\nInitial Block Download complete!")
  end

  return true
end

--------------------------------------------------------------------------------
-- IBD Status
--------------------------------------------------------------------------------

--- Check if IBD is complete.
-- @return boolean: true if all blocks downloaded and connected
function BlockDownloader:is_complete()
  return self.ibd_complete
end

--- Get the next height to connect.
-- @return number: next height waiting to be connected
function BlockDownloader:get_connect_height()
  return self.next_connect_height
end

--- Get the count of blocks in-flight.
-- @return number: count of pending downloads
function BlockDownloader:get_inflight_count()
  local count = 0
  for _ in pairs(self.inflight) do count = count + 1 end
  return count
end

--- Get the count of blocks pending connection.
-- @return number: count of downloaded but unconnected blocks
function BlockDownloader:get_pending_count()
  local count = 0
  for _ in pairs(self.pending_blocks) do count = count + 1 end
  return count
end

-- Export the BlockDownloader class
M.BlockDownloader = BlockDownloader

--------------------------------------------------------------------------------
-- IBD Orchestration
--------------------------------------------------------------------------------

--- Run Initial Block Download.
-- Orchestrates header sync followed by block download.
-- @param header_chain HeaderChain: The header chain
-- @param storage table: Storage backend
-- @param network table: Network configuration
-- @param peer_manager table: Peer manager for connections
-- @return BlockDownloader|nil, string|nil: downloader instance or nil, error
function M.run_ibd(header_chain, storage, network, peer_manager)
  -- 1. Get established peers
  local peers = peer_manager:get_established_peers()
  if #peers == 0 then
    return nil, "no peers"
  end

  -- 2. Pick best peer (highest start_height) for header sync
  local best_peer = peers[1]
  for _, p in ipairs(peers) do
    if p.start_height and best_peer.start_height and p.start_height > best_peer.start_height then
      best_peer = p
    end
  end

  -- 3. Start header sync if needed
  if not header_chain.syncing then
    header_chain:start_sync(best_peer)
  end

  -- 4. Create block downloader
  local downloader = M.new_block_downloader(header_chain, storage, network)

  -- 5. Register message handlers
  peer_manager:register_handler("block", function(peer, payload)
    downloader:handle_block(peer, payload)
  end)

  peer_manager:register_handler("headers", function(peer, payload)
    header_chain:handle_headers(peer, payload)
  end)

  return downloader
end

return M
