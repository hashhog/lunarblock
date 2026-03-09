local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local crypto = require("lunarblock.crypto")
local p2p = require("lunarblock.p2p")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local M = {}

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
  local tip_hash, tip_height = self:get_header_tip()
  if tip_hash then
    -- Load the header chain from storage
    self:load_from_storage(tip_hash, tip_height)
  else
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
  -- Walk backwards from tip to genesis loading headers
  local current_hash = tip_hash
  local current_height = tip_height

  while current_height >= 0 do
    local header = self.storage.get_header(current_hash)
    if not header then
      break
    end

    local hash_hex = types.hash256_hex(current_hash)
    self.headers[hash_hex] = {
      header = header,
      height = current_height,
      total_work = self:calculate_total_work_from_storage(current_height),
    }
    self.height_to_hash[current_height] = hash_hex

    if current_height == 0 then
      break
    end

    current_hash = header.prev_hash
    current_height = current_height - 1
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
  local header = types.block_header(
    gen.version,
    types.hash256_zero(),  -- prev_hash (genesis has no parent)
    types.hash256_zero(),  -- merkle root (computed later for full block)
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

  -- 6. Check difficulty target
  if not self.network.pow_no_retarget then
    if height % consensus.DIFFICULTY_ADJUSTMENT_INTERVAL == 0 then
      local expected_bits = self:calculate_next_work_required(height, header)
      if header.bits ~= expected_bits then
        return false, string.format("wrong difficulty: expected 0x%08x got 0x%08x",
          expected_bits, header.bits)
      end
    elseif not self.network.pow_allow_min_difficulty then
      if header.bits ~= parent.header.bits then
        return false, "unexpected difficulty change"
      end
    end
  end

  -- 7. Check against checkpoints
  local checkpoints = self.network.checkpoints or {}
  local expected_checkpoint = checkpoints[height]
  if expected_checkpoint then
    if hash_hex ~= expected_checkpoint then
      return false, "checkpoint mismatch at height " .. height
    end
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
-- @param header block_header: header being validated (unused but for consistency)
-- @return number: expected compact bits value
function HeaderChain:calculate_next_work_required(height, header)
  -- Find the block 2016 blocks ago
  local first_height = height - consensus.DIFFICULTY_ADJUSTMENT_INTERVAL
  local first_hex = self.height_to_hash[first_height]
  local first = self.headers[first_hex]

  local last_hex = self.height_to_hash[height - 1]
  local last = self.headers[last_hex]

  if not first or not last then
    -- Shouldn't happen if chain is continuous
    return header.bits
  end

  local actual_timespan = last.header.timestamp - first.header.timestamp
  local new_target = consensus.calculate_next_target(last.header.bits, actual_timespan)
  return new_target
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
-- Sync Controller
--------------------------------------------------------------------------------

--- Start header synchronization with a peer.
-- @param peer table: peer connection to sync from
function HeaderChain:start_sync(peer)
  self.syncing = true
  self.sync_peer = peer

  local locator = self:get_block_locator()
  local payload = p2p.serialize_getheaders(
    p2p.PROTOCOL_VERSION,
    locator,
    types.hash256_zero()  -- no stop hash = get all
  )

  peer:send_message("getheaders", payload)
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

  local accepted, err = self:process_headers(headers, peer)
  if err then
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

-- Export the HeaderChain class for direct access if needed
M.HeaderChain = HeaderChain

return M
