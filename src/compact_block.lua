--- BIP152 Compact Block Relay
-- Implements compact block construction, short ID computation, and block reconstruction.
-- Reference: Bitcoin Core blockencodings.cpp
local crypto = require("lunarblock.crypto")
local serialize = require("lunarblock.serialize")
local p2p = require("lunarblock.p2p")
local validation = require("lunarblock.validation")
local ffi = require("ffi")
local M = {}

--------------------------------------------------------------------------------
-- Constants
--------------------------------------------------------------------------------

-- Compact block version (2 = wtxid-based, per BIP152)
M.CMPCTBLOCKS_VERSION = 2

-- Maximum depth from tip to serve compact blocks
M.MAX_CMPCTBLOCK_DEPTH = 5

-- Maximum concurrent compact block requests per block hash
M.MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3

-- Maximum high-bandwidth peers
M.MAX_HIGH_BANDWIDTH_PEERS = 3

--------------------------------------------------------------------------------
-- Compact Block Construction
--------------------------------------------------------------------------------

--- Create a compact block from a full block.
-- @param block table: full block with header and transactions
-- @param nonce number: random 64-bit nonce for short ID computation
-- @return table: compact block data {header, nonce, short_ids, prefilled_txns}
function M.create_compact_block(block, nonce)
  local header_bytes = serialize.serialize_block_header(block.header)
  local k0, k1 = crypto.siphash_key_from_header(header_bytes, nonce)

  local short_ids = {}
  local prefilled_txns = {}

  -- Always prefill the coinbase (index 0)
  prefilled_txns[1] = { index = 0, tx = block.transactions[1] }

  -- Compute short IDs for remaining transactions
  for i = 2, #block.transactions do
    local tx = block.transactions[i]
    -- Compute wtxid for short ID (BIP152 v2)
    local wtxid = validation.compute_wtxid(tx)
    local short_id = crypto.compact_block_short_id(k0, k1, wtxid.bytes)
    short_ids[#short_ids + 1] = short_id
  end

  return {
    header = block.header,
    nonce = nonce,
    short_ids = short_ids,
    prefilled_txns = prefilled_txns,
  }
end

--- Serialize a compact block for network transmission.
-- @param compact_block table: compact block from create_compact_block
-- @return string: serialized cmpctblock message payload
function M.serialize(compact_block)
  return p2p.serialize_cmpctblock(
    compact_block.header,
    compact_block.nonce,
    compact_block.short_ids,
    compact_block.prefilled_txns
  )
end

--- Deserialize a compact block from network data.
-- @param data string: cmpctblock message payload
-- @return table: deserialized compact block
function M.deserialize(data)
  return p2p.deserialize_cmpctblock(data)
end

--------------------------------------------------------------------------------
-- Partially Downloaded Block
--------------------------------------------------------------------------------

local PartiallyDownloadedBlock = {}
PartiallyDownloadedBlock.__index = PartiallyDownloadedBlock

--- Create a new partially downloaded block.
-- @return table: PartiallyDownloadedBlock instance
function M.new_partial_block()
  local self = setmetatable({}, PartiallyDownloadedBlock)
  self.header = nil
  self.txn_available = {}   -- index -> transaction or nil
  self.prefilled_count = 0
  self.mempool_count = 0
  self.tx_count = 0
  self.k0 = nil
  self.k1 = nil
  self.short_id_map = {}    -- short_id -> index
  return self
end

--- Initialize the partial block from a compact block.
-- Attempts to fill transactions from mempool.
-- @param cmpctblock table: deserialized compact block
-- @param mempool table: mempool object with get_by_wtxid method (optional)
-- @return string|nil: error message or nil on success
function PartiallyDownloadedBlock:init(cmpctblock, mempool)
  if not cmpctblock.header then
    return "invalid compact block: missing header"
  end

  self.header = cmpctblock.header
  self.tx_count = p2p.cmpctblock_tx_count(cmpctblock)

  -- Initialize transaction slots
  for i = 1, self.tx_count do
    self.txn_available[i] = nil
  end

  -- Process prefilled transactions
  for _, prefilled in ipairs(cmpctblock.prefilled_txns) do
    local index = prefilled.index + 1  -- Convert to 1-based
    if index < 1 or index > self.tx_count then
      return "invalid prefilled index: " .. (prefilled.index)
    end
    if self.txn_available[index] then
      return "duplicate prefilled index: " .. (prefilled.index)
    end
    self.txn_available[index] = prefilled.tx
    self.prefilled_count = self.prefilled_count + 1
  end

  -- Compute SipHash key
  local header_bytes = serialize.serialize_block_header(self.header)
  self.k0, self.k1 = crypto.siphash_key_from_header(header_bytes, cmpctblock.nonce)

  -- Build short ID to index map
  local short_idx = 1
  for i = 1, self.tx_count do
    if not self.txn_available[i] then
      if short_idx > #cmpctblock.short_ids then
        return "short ID count mismatch"
      end
      local short_id = cmpctblock.short_ids[short_idx]
      -- Check for collision
      if self.short_id_map[short_id] then
        -- Short ID collision - need to request full block
        return "short ID collision"
      end
      self.short_id_map[short_id] = i
      short_idx = short_idx + 1
    end
  end

  -- Try to fill from mempool
  if mempool and mempool.iter_by_wtxid then
    for wtxid, tx in mempool:iter_by_wtxid() do
      local short_id = crypto.compact_block_short_id(self.k0, self.k1, wtxid)
      local index = self.short_id_map[short_id]
      if index and not self.txn_available[index] then
        -- Verify wtxid matches (to handle collisions)
        local computed_wtxid = validation.compute_wtxid(tx)
        if computed_wtxid.bytes == wtxid then
          self.txn_available[index] = tx
          self.mempool_count = self.mempool_count + 1
        end
      end
    end
  end

  return nil
end

--- Check if a transaction at index is available.
-- @param index number: 1-based transaction index
-- @return boolean: true if transaction is available
function PartiallyDownloadedBlock:is_tx_available(index)
  return self.txn_available[index] ~= nil
end

--- Get list of missing transaction indices.
-- @return table: list of 0-based indices for getblocktxn request
function PartiallyDownloadedBlock:get_missing_indices()
  local missing = {}
  for i = 1, self.tx_count do
    if not self.txn_available[i] then
      missing[#missing + 1] = i - 1  -- Convert to 0-based for protocol
    end
  end
  return missing
end

--- Check if the block is complete.
-- @return boolean: true if all transactions are available
function PartiallyDownloadedBlock:is_complete()
  for i = 1, self.tx_count do
    if not self.txn_available[i] then
      return false
    end
  end
  return true
end

--- Fill missing transactions from a blocktxn response.
-- @param transactions table: list of transactions in order
-- @return string|nil: error message or nil on success
function PartiallyDownloadedBlock:fill_from_blocktxn(transactions)
  local tx_idx = 1
  for i = 1, self.tx_count do
    if not self.txn_available[i] then
      if tx_idx > #transactions then
        return "not enough transactions in blocktxn"
      end
      self.txn_available[i] = transactions[tx_idx]
      tx_idx = tx_idx + 1
    end
  end

  if tx_idx <= #transactions then
    return "too many transactions in blocktxn"
  end

  return nil
end

--- Reconstruct the full block.
-- @return table|nil, string: full block or nil with error message
function PartiallyDownloadedBlock:reconstruct()
  if not self:is_complete() then
    return nil, "block is not complete"
  end

  local transactions = {}
  for i = 1, self.tx_count do
    transactions[i] = self.txn_available[i]
  end

  local types = require("lunarblock.types")
  return types.block(self.header, transactions), nil
end

M.PartiallyDownloadedBlock = PartiallyDownloadedBlock

--------------------------------------------------------------------------------
-- High-Bandwidth Peer Management
--------------------------------------------------------------------------------

--- Select up to 3 peers for high-bandwidth compact block relay.
-- @param peers table: list of connected peers with compact block support
-- @return table: list of selected peers for high-bandwidth mode
function M.select_high_bandwidth_peers(peers)
  local candidates = {}

  for _, peer in ipairs(peers) do
    if peer.provides_compact and peer.compact_version == 2 then
      candidates[#candidates + 1] = peer
    end
  end

  -- Sort by latency (prefer lower latency peers)
  table.sort(candidates, function(a, b)
    return (a.latency_ms or 999999) < (b.latency_ms or 999999)
  end)

  -- Select up to MAX_HIGH_BANDWIDTH_PEERS
  local selected = {}
  for i = 1, math.min(#candidates, M.MAX_HIGH_BANDWIDTH_PEERS) do
    selected[i] = candidates[i]
  end

  return selected
end

--- Send sendcmpct to a peer to enable high-bandwidth mode.
-- @param peer table: peer object
-- @param high_bandwidth boolean: enable high-bandwidth mode
function M.send_compact_negotiation(peer, high_bandwidth)
  local payload = p2p.serialize_sendcmpct(high_bandwidth, M.CMPCTBLOCKS_VERSION)
  peer:send_message("sendcmpct", payload)
end

--------------------------------------------------------------------------------
-- Compact Block Response
--------------------------------------------------------------------------------

--- Create getblocktxn request for missing transactions.
-- @param block_hash hash256: block hash
-- @param partial_block table: PartiallyDownloadedBlock instance
-- @return string: serialized getblocktxn payload
function M.create_getblocktxn(block_hash, partial_block)
  local missing = partial_block:get_missing_indices()
  return p2p.serialize_getblocktxn(block_hash, missing)
end

--- Create blocktxn response for a getblocktxn request.
-- @param block table: full block
-- @param indexes table: list of 0-based transaction indices
-- @return string: serialized blocktxn payload
function M.create_blocktxn(block, indexes)
  local block_hash = crypto.hash256_type(serialize.serialize_block_header(block.header))
  local transactions = {}
  for _, index in ipairs(indexes) do
    local tx = block.transactions[index + 1]  -- Convert to 1-based
    if tx then
      transactions[#transactions + 1] = tx
    end
  end
  return p2p.serialize_blocktxn(block_hash, transactions)
end

return M
