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

-- Maximum transactions in a compact block.
-- Core: MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT = 4000000 / 40 = 100000
-- (blockencodings.cpp:64, consensus/consensus.h)
M.MAX_CMPCTBLOCK_TX_COUNT = 100000

-- Maximum bucket depth in the short-ID hash map before we declare DoS / hash-flood.
-- Core: bucket_size > 12 → READ_STATUS_FAILED (blockencodings.cpp:110)
M.MAX_SHORT_ID_BUCKET_SIZE = 12

-- Maximum prefilled-transaction index (fits in uint16, per DifferenceFormatter).
-- Core: lastprefilledindex > numeric_limits<uint16_t>::max() → INVALID (blockencodings.cpp:78)
M.MAX_PREFILLED_INDEX = 65535

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
  self.extra_count = 0
  self.tx_count = 0
  self.k0 = nil
  self.k1 = nil
  self.short_id_map = {}    -- short_id -> index
  return self
end

--- Initialize the partial block from a compact block.
-- Attempts to fill transactions from mempool.
-- @param cmpctblock table: deserialized compact block
-- @param mempool table: mempool object with iter_by_wtxid method (optional)
-- @param extra_txn table: extra {wtxid_bytes, tx} pairs beyond mempool (optional)
-- @return string|nil: error message or nil on success
--
-- Gates (matching Bitcoin Core blockencodings.cpp::PartiallyDownloadedBlock::InitData):
--  G1  header null or both-lists-empty → INVALID
--  G2  total tx count > 100000 → INVALID
--  G3  already initialized (header not nil or txn_available not empty) → INVALID
--  G4  null tx inside a prefilled entry → INVALID
--  G5  lastprefilledindex > 65535 → INVALID
--  G6  lastprefilledindex jumps beyond (short_ids + prefilled_so_far) → INVALID
--  G7  any short-ID map bucket depth > 12 → FAILED (DoS protection)
--  G8  short-ID duplicate in cmpctblock → FAILED (short ID collision)
--  G9  mempool collision: two txns map to same short ID → dequeue both
function PartiallyDownloadedBlock:init(cmpctblock, mempool, extra_txn)
  -- G1: header null check and both-lists-empty check
  -- (Core blockencodings.cpp:62-63)
  if not cmpctblock.header then
    return "invalid compact block: missing header"
  end
  if #cmpctblock.short_ids == 0 and #cmpctblock.prefilled_txns == 0 then
    return "invalid compact block: both short_ids and prefilled_txns are empty"
  end

  -- G2: total transaction count limit
  -- MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT = 4000000 / 40 = 100000
  -- (Core blockencodings.cpp:64-65)
  local total_tx_count = #cmpctblock.short_ids + #cmpctblock.prefilled_txns
  if total_tx_count > M.MAX_CMPCTBLOCK_TX_COUNT then
    return "invalid compact block: too many transactions"
  end

  -- G3: re-initialization guard — prevent calling init twice on same object
  -- (Core blockencodings.cpp:67)
  if self.header ~= nil or #self.txn_available > 0 then
    return "invalid compact block: already initialized"
  end

  self.header = cmpctblock.header
  self.tx_count = total_tx_count

  -- Initialize transaction slots
  for i = 1, self.tx_count do
    self.txn_available[i] = nil
  end

  -- Process prefilled transactions
  -- Core uses a cumulative lastprefilledindex (differential offsets are decoded by
  -- DifferenceFormatter before reaching here; each prefilled.index is already the
  -- absolute 0-based index in the block).
  local lastprefilledindex = -1
  for i, prefilled in ipairs(cmpctblock.prefilled_txns) do
    -- G4: null tx check (Core blockencodings.cpp:74-76)
    if not prefilled.tx then
      return "invalid compact block: null transaction in prefilled"
    end

    -- Accumulate absolute index from the stored (already-decoded) absolute index.
    -- Note: p2p.lua deserialize_cmpctblock already decodes differential → absolute
    -- index, so prefilled.index is already absolute 0-based.
    local abs_index = prefilled.index

    -- G5: lastprefilledindex must not exceed uint16 max (Core line 78-79)
    if abs_index > M.MAX_PREFILLED_INDEX then
      return "invalid compact block: prefilled index overflows uint16"
    end
    if abs_index <= lastprefilledindex then
      return "invalid compact block: prefilled index not increasing"
    end
    lastprefilledindex = abs_index

    -- G6: prefilled index must not jump past (num_short_ids + num_prefilled_so_far)
    -- i.e. lastprefilledindex <= shorttxids.size() + (i - 1)   [0-based comparison]
    -- (Core blockencodings.cpp:80-85)
    if abs_index > #cmpctblock.short_ids + (i - 1) then
      return "invalid compact block: prefilled index skips beyond available short IDs"
    end

    local slot = abs_index + 1  -- Convert to 1-based
    if self.txn_available[slot] then
      return "invalid compact block: duplicate prefilled index"
    end
    self.txn_available[slot] = prefilled.tx
    self.prefilled_count = self.prefilled_count + 1
  end

  -- Compute SipHash key from header + nonce
  local header_bytes = serialize.serialize_block_header(self.header)
  self.k0, self.k1 = crypto.siphash_key_from_header(header_bytes, cmpctblock.nonce)

  -- Build short ID to block-index map.
  -- Track per-bucket depth for DoS protection (G7).
  -- Use a bucket-depth counter keyed the same way as the short_id_map.
  local bucket_depth = {}  -- short_id -> count of times seen
  local index_offset = 0
  for i = 1, self.tx_count do
    -- Skip over slots already filled by prefilled txns
    if not self.txn_available[i] then
      local short_id = cmpctblock.short_ids[i - index_offset]
      if not short_id then
        return "invalid compact block: short ID count mismatch"
      end

      -- G7: bucket depth > 12 → DoS protection (Core blockencodings.cpp:110-111)
      -- This approximates the unordered_map bucket-size check: well-formed blocks
      -- should have a roughly uniform short-ID distribution.
      bucket_depth[short_id] = (bucket_depth[short_id] or 0) + 1
      if bucket_depth[short_id] > M.MAX_SHORT_ID_BUCKET_SIZE then
        return nil, true  -- READ_STATUS_FAILED: hash-flood DoS
      end

      -- G8: short ID collision within cmpctblock itself (Core line 115-116)
      if self.short_id_map[short_id] then
        return nil, true  -- READ_STATUS_FAILED: short ID collision
      end
      self.short_id_map[short_id] = i
    else
      index_offset = index_offset + 1
    end
  end

  -- G8 final check: the number of entries in short_id_map must equal #short_ids
  -- (Core blockencodings.cpp:115-116 — separate map.size() != cmpctblock.shorttxids.size() check)
  local map_count = 0
  for _ in pairs(self.short_id_map) do map_count = map_count + 1 end
  if map_count ~= #cmpctblock.short_ids then
    return nil, true  -- READ_STATUS_FAILED: short ID collision
  end

  -- Try to fill from mempool
  -- G9: collision handling — two mempool txns map to same short ID → dequeue both
  -- (Core blockencodings.cpp:118-144)
  local have_txn = {}  -- track which slots have been claimed (separate from txn_available)
  -- Mark prefilled slots as already have
  for i = 1, self.tx_count do
    if self.txn_available[i] then
      have_txn[i] = true
    end
  end

  local short_id_count = #cmpctblock.short_ids
  if mempool and mempool.iter_by_wtxid then
    for wtxid, tx in mempool:iter_by_wtxid() do
      local short_id = crypto.compact_block_short_id(self.k0, self.k1, wtxid)
      local index = self.short_id_map[short_id]
      if index then
        if not have_txn[index] then
          self.txn_available[index] = tx
          have_txn[index] = true
          self.mempool_count = self.mempool_count + 1
        else
          -- Two mempool txns hash to same short ID → clear the slot so we request it
          if self.txn_available[index] then
            self.txn_available[index] = nil
            self.mempool_count = self.mempool_count - 1
          end
        end
      end
      -- Early exit when all short IDs are satisfied
      if self.mempool_count == short_id_count then
        break
      end
    end
  end

  -- Extra txn pool (recently evicted, orphan pool, etc.)
  -- (Core blockencodings.cpp:147-176)
  if extra_txn then
    for _, entry in ipairs(extra_txn) do
      local wtxid_bytes = entry[1]
      local tx = entry[2]
      local short_id = crypto.compact_block_short_id(self.k0, self.k1, wtxid_bytes)
      local index = self.short_id_map[short_id]
      if index then
        if not have_txn[index] then
          self.txn_available[index] = tx
          have_txn[index] = true
          self.mempool_count = self.mempool_count + 1
          self.extra_count = self.extra_count + 1
        else
          -- Collision between mempool and extra, or two extra txns.
          -- Only dequeue if wtxid actually differs (use raw wtxid comparison).
          -- Core: compare GetWitnessHash() — here we compare the wtxid bytes
          -- (Core blockencodings.cpp:163-169)
          if self.txn_available[index] then
            local existing_wtxid = validation.compute_wtxid(self.txn_available[index])
            if existing_wtxid.bytes ~= wtxid_bytes then
              self.txn_available[index] = nil
              self.mempool_count = self.mempool_count - 1
              if self.extra_count > 0 then
                self.extra_count = self.extra_count - 1
              end
            end
          end
        end
      end
      if self.mempool_count == short_id_count then
        break
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

--- Reconstruct the full block from all available transactions.
-- After reconstruction the object is invalidated — header is cleared and
-- txn_available is wiped.  This matches Core's FillBlock semantics:
--   header.SetNull(); txn_available.clear();
-- (Core blockencodings.cpp:211-212)
--
-- @param check_mutated optional function(block) → bool: mutation check hook.
--   If provided, called after assembling the block; returns nil,"mutated block"
--   when it returns true.  Mirrors Core's IsBlockMutated call in FillBlock.
-- @return table|nil, string: full block or nil with error message
function PartiallyDownloadedBlock:reconstruct(check_mutated)
  -- G10: header null check — must be initialized (Core blockencodings.cpp:193)
  if not self.header then
    return nil, "not initialized"
  end

  if not self:is_complete() then
    return nil, "block is not complete"
  end

  local transactions = {}
  for i = 1, self.tx_count do
    transactions[i] = self.txn_available[i]
  end

  local types = require("lunarblock.types")
  local block = types.block(self.header, transactions)

  -- G11: invalidate the object after filling — prevents double-use
  -- (Core blockencodings.cpp:211-212)
  self.header = nil
  self.txn_available = {}

  -- G12: mutation check hook (Core blockencodings.cpp:219-221)
  if check_mutated and check_mutated(block) then
    return nil, "mutated block (possible short ID collision)"
  end

  return block, nil
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
