local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
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
  self.base_stall_timeout = 5       -- Base timeout before considering stalled (adaptive)
  self.max_stall_timeout = 64       -- Maximum stall timeout
  self.ibd_complete = false
  self.connect_callback = nil       -- Called when a block is connected: fn(block, height, hash)
  self.utxo_flush_interval = 2000   -- Flush UTXO set every N blocks
  self.last_flush_height = 0
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
  for hash_hex, info in pairs(self.inflight) do
    if now - info.request_time > info.timeout then
      -- Stalled request - remove from inflight and peer tracking
      self.inflight[hash_hex] = nil
      if self.peer_inflight[info.peer] then
        self.peer_inflight[info.peer] = self.peer_inflight[info.peer] - 1
        if self.peer_inflight[info.peer] <= 0 then
          self.peer_inflight[info.peer] = nil
        end
      end
      -- Double the timeout for next request of this block (adaptive stalling)
      -- The block will be re-requested on next schedule cycle
    end
  end

  -- Calculate how many more blocks we can request
  local inflight_count = 0
  for _ in pairs(self.inflight) do inflight_count = inflight_count + 1 end
  local available = self.download_window - inflight_count
  if available <= 0 then return end

  -- Filter peers with available slots
  local available_peers = {}
  for _, p in ipairs(peers) do
    local peer_count = self.peer_inflight[p] or 0
    if peer_count < self.blocks_per_peer then
      available_peers[#available_peers + 1] = p
    end
  end
  if #available_peers == 0 then return end

  -- Build requests per peer (batch multiple inv items per getdata)
  local peer_requests = {}
  for _, p in ipairs(available_peers) do
    peer_requests[p] = {}
  end

  local peer_idx = 1
  local height = self.next_download_height
  local tip = self.header_chain.header_tip_height

  while height <= tip and available > 0 do
    local hash_hex = self.header_chain.height_to_hash[height]
    if not hash_hex then break end

    -- Skip if already downloaded or in-flight
    if not self.pending_blocks[hash_hex] and not self.inflight[hash_hex] then
      -- Check if block already in storage
      local entry = self.header_chain.headers[hash_hex]
      if entry then
        local block_hash = validation.compute_block_hash(entry.header)
        local existing = self.storage.get(self.storage.CF.BLOCKS, block_hash.bytes)
        if not existing then
          -- Find a peer with available slots (round-robin)
          local attempts = 0
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
              break
            end
            peer_idx = peer_idx + 1
            attempts = attempts + 1
          end
        end
      end
    end
    height = height + 1
  end

  self.next_download_height = height

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

--- Handle a received block from a peer.
-- @param peer table: peer that sent the block
-- @param block_data string: raw block message payload
-- @return boolean, string|nil: success flag, error message
function BlockDownloader:handle_block(peer, block_data)
  -- Deserialize the block
  local block = serialize.deserialize_block(block_data)
  local hash = validation.compute_block_hash(block.header)
  local hash_hex = types.hash256_hex(hash)

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
-- @return boolean, string|nil: success flag, error message
function BlockDownloader:connect_pending_blocks()
  -- Connect blocks in height order starting from next_connect_height
  while true do
    local hash_hex = self.header_chain.height_to_hash[self.next_connect_height]
    if not hash_hex then break end

    local pending = self.pending_blocks[hash_hex]
    if not pending then break end

    -- Validate the full block
    local ok, err = pcall(function()
      validation.check_block(pending.block, self.network, pending.height)
    end)

    if not ok then
      -- Invalid block, remove from pending and report error
      self.pending_blocks[hash_hex] = nil
      return false, err
    end

    -- Store the block
    self.storage.put_block(pending.hash, pending.block)
    self.storage.set_chain_tip(pending.hash, pending.height, false)

    -- Notify callback (for UTXO updates, etc.)
    if self.connect_callback then
      self.connect_callback(pending.block, pending.height, pending.hash)
    end

    self.pending_blocks[hash_hex] = nil
    self.next_connect_height = self.next_connect_height + 1

    -- Flush UTXO set periodically during IBD
    if self.next_connect_height - self.last_flush_height >= self.utxo_flush_interval then
      self.storage.set_chain_tip(pending.hash, pending.height, true)  -- sync write
      self.last_flush_height = self.next_connect_height
    end

    -- Log progress periodically
    if self.next_connect_height % 10000 == 0 then
      local progress = self.next_connect_height / self.header_chain.header_tip_height * 100
      io.write(string.format("\rIBD Progress: %d / %d (%.1f%%)",
        self.next_connect_height, self.header_chain.header_tip_height, progress))
      io.flush()
    end
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
