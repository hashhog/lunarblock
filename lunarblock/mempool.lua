local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local validation = require("lunarblock.validation")
local consensus = require("lunarblock.consensus")
local M = {}

--------------------------------------------------------------------------------
-- Mempool Policy Constants
--------------------------------------------------------------------------------

M.DEFAULT_MAX_MEMPOOL_SIZE = 300 * 1024 * 1024  -- 300 MB
M.DEFAULT_MIN_RELAY_FEE = 1000    -- 1 sat/vB in sat/KB
M.DEFAULT_MAX_TX_FEE = 1000000    -- 0.01 BTC max fee (policy, not consensus)
M.MAX_ANCESTORS = 25              -- Max unconfirmed ancestor chain
M.MAX_DESCENDANTS = 25            -- Max unconfirmed descendant chain
M.MAX_ANCESTOR_SIZE = 101000      -- Max total vsize of ancestor chain
M.MAX_DESCENDANT_SIZE = 101000    -- Max total vsize of descendant chain
M.REPLACEMENT_MIN_FEE_BUMP = 1000 -- Minimum fee increase for RBF (sat/KB)

--------------------------------------------------------------------------------
-- Outpoint Key Helper
--------------------------------------------------------------------------------

--- Generate a 36-byte key for outpoint lookups.
-- @param txid_hash256 hash256: The transaction id
-- @param vout_index number: The output index
-- @return string: 36-byte binary key
function M.outpoint_key(txid_hash256, vout_index)
  local w = serialize.buffer_writer()
  w.write_hash256(txid_hash256)
  w.write_u32le(vout_index)
  return w.result()
end

--------------------------------------------------------------------------------
-- Mempool Entry
--------------------------------------------------------------------------------

--- Create a mempool entry for a transaction.
-- @param tx transaction: The transaction
-- @param txid hash256: The transaction id
-- @param fee number: Fee in satoshis
-- @param vsize number: Virtual size
-- @param height number: Block height when added
-- @param time number: Unix timestamp when added (optional)
-- @return table: Mempool entry
function M.mempool_entry(tx, txid, fee, vsize, height, time)
  return {
    tx = tx,
    txid = txid,               -- hash256
    wtxid = validation.compute_wtxid(tx),
    fee = fee,                  -- satoshis
    vsize = vsize,              -- virtual size (weight / 4)
    weight = validation.get_tx_weight(tx),
    size = #serialize.serialize_transaction(tx, true),
    fee_rate = fee / vsize,     -- sat/vB
    height = height,            -- block height when added
    time = time or os.time(),   -- unix timestamp when added
    ancestors = {},             -- set of txid_hex -> true
    descendants = {},           -- set of txid_hex -> true
    ancestor_count = 0,
    descendant_count = 0,
    ancestor_size = 0,
    descendant_size = 0,
    ancestor_fees = 0,
    descendant_fees = 0,
    spends_from = {},           -- outpoint_key -> txid_hex of parent in mempool
  }
end

--------------------------------------------------------------------------------
-- Mempool Object
--------------------------------------------------------------------------------

local Mempool = {}
Mempool.__index = Mempool

--- Create a new mempool.
-- @param chain_state table: The chain state (with coin_view and tip_height)
-- @param config table: Optional configuration
-- @return Mempool: New mempool instance
function M.new(chain_state, config)
  local self = setmetatable({}, Mempool)
  self.chain_state = chain_state
  self.max_size = (config and config.max_mempool_size) or M.DEFAULT_MAX_MEMPOOL_SIZE
  self.min_relay_fee = (config and config.min_relay_fee) or M.DEFAULT_MIN_RELAY_FEE
  self.entries = {}            -- txid_hex -> MempoolEntry
  self.outpoint_to_tx = {}    -- outpoint_key -> txid_hex (tracks which tx spends each output)
  self.total_size = 0          -- Current memory usage estimate
  self.tx_count = 0
  return self
end

--------------------------------------------------------------------------------
-- Transaction Acceptance
--------------------------------------------------------------------------------

--- Accept a transaction into the mempool.
-- @param tx transaction: The transaction to accept
-- @param allow_rbf boolean: Whether to allow RBF replacement (default true)
-- @return boolean, string, number: success, txid_hex or error message, fee
function Mempool:accept_transaction(tx, allow_rbf)
  if allow_rbf == nil then allow_rbf = true end
  local txid = validation.compute_txid(tx)
  local txid_hex = types.hash256_hex(txid)

  -- 1. Check if we already have this transaction
  if self.entries[txid_hex] then
    return false, "tx already in mempool"
  end

  -- 2. Basic structure validation
  local pcall_ok, check_ok, is_coinbase = pcall(validation.check_transaction, tx)
  if not pcall_ok then
    return false, "invalid transaction structure"
  end
  if not check_ok then
    return false, "invalid transaction structure"
  end
  if is_coinbase then
    return false, "coinbase transactions not accepted"
  end

  -- 3. Check all inputs exist (in UTXO set or mempool)
  local input_total = 0
  local missing_inputs = false
  local conflicts = {}  -- existing mempool txs that spend the same outputs

  for _, inp in ipairs(tx.inputs) do
    local outpoint_key = M.outpoint_key(inp.prev_out.hash, inp.prev_out.index)

    -- Check if another mempool tx already spends this output
    local existing_spender = self.outpoint_to_tx[outpoint_key]
    if existing_spender then
      if allow_rbf then
        conflicts[existing_spender] = true
      else
        return false, "conflict with existing mempool tx"
      end
    end

    -- Look up UTXO from chain state
    local utxo = self.chain_state.coin_view:get(inp.prev_out.hash, inp.prev_out.index)

    -- If not in UTXO set, check if it's an output of a mempool tx
    if not utxo then
      local prev_txid_hex = types.hash256_hex(inp.prev_out.hash)
      local parent_entry = self.entries[prev_txid_hex]
      if parent_entry and inp.prev_out.index < #parent_entry.tx.outputs then
        local out = parent_entry.tx.outputs[inp.prev_out.index + 1]
        utxo = {
          value = out.value,
          script_pubkey = out.script_pubkey,
          height = parent_entry.height,
          is_coinbase = false,
        }
      else
        missing_inputs = true
      end
    end

    if utxo then
      input_total = input_total + utxo.value
      -- Coinbase maturity
      if utxo.is_coinbase then
        local tip_height = self.chain_state.tip_height
        if tip_height - utxo.height < consensus.COINBASE_MATURITY then
          return false, "spending immature coinbase"
        end
      end
    end
  end

  if missing_inputs then
    return false, "missing inputs"
  end

  -- 4. Calculate fee
  local output_total = 0
  for _, out in ipairs(tx.outputs) do
    output_total = output_total + out.value
  end
  local fee = input_total - output_total
  if fee < 0 then
    return false, "outputs exceed inputs"
  end

  -- 5. Check fee rate
  local weight = validation.get_tx_weight(tx)
  local vsize = math.ceil(weight / consensus.WITNESS_SCALE_FACTOR)
  local fee_rate_per_kb = fee * 1000 / vsize
  if fee_rate_per_kb < self.min_relay_fee then
    return false, string.format("fee rate too low: %.2f < %d sat/KB",
      fee_rate_per_kb, self.min_relay_fee)
  end

  -- 6. Handle RBF conflicts
  if next(conflicts) then
    -- BIP125: check that new tx pays higher fee
    local old_total_fee = 0
    for conflict_txid_hex in pairs(conflicts) do
      local conflict_entry = self.entries[conflict_txid_hex]
      if conflict_entry then
        old_total_fee = old_total_fee + conflict_entry.fee
        -- All conflicting txs must signal replaceability (sequence < 0xFFFFFFFE)
        for _, inp in ipairs(conflict_entry.tx.inputs) do
          if inp.sequence >= 0xFFFFFFFE then
            return false, "conflicting tx does not signal RBF"
          end
        end
      end
    end
    if fee <= old_total_fee then
      return false, "replacement fee not higher than original"
    end
    -- Remove conflicting transactions
    for conflict_txid_hex in pairs(conflicts) do
      self:remove_transaction(conflict_txid_hex, "replaced")
    end
  end

  -- 7. Compute ancestors (with proper deduplication) and check limits
  -- Build the full set of unique in-mempool ancestors
  local ancestors = {}  -- txid_hex -> true (set of all ancestors)
  local direct_parents = {}  -- txid_hex -> entry (direct parents only)

  for _, inp in ipairs(tx.inputs) do
    local prev_hex = types.hash256_hex(inp.prev_out.hash)
    local parent = self.entries[prev_hex]
    if parent then
      direct_parents[prev_hex] = parent
      ancestors[prev_hex] = true
      -- Include all of parent's ancestors (properly deduped via set)
      for anc_hex in pairs(parent.ancestors) do
        ancestors[anc_hex] = true
      end
    end
  end

  -- Count unique ancestors and sum their sizes/fees
  local ancestor_count = 1  -- include self
  local ancestor_size = vsize  -- include self
  local ancestor_fees = fee  -- include self

  for anc_hex in pairs(ancestors) do
    local anc_entry = self.entries[anc_hex]
    if anc_entry then
      ancestor_count = ancestor_count + 1
      ancestor_size = ancestor_size + anc_entry.vsize
      ancestor_fees = ancestor_fees + anc_entry.fee
    end
  end

  if ancestor_count > M.MAX_ANCESTORS then
    return false, "too many ancestors: " .. ancestor_count
  end
  if ancestor_size > M.MAX_ANCESTOR_SIZE then
    return false, "ancestor size too large: " .. ancestor_size
  end

  -- 7b. Check descendant limits for ALL ancestors
  -- Adding this transaction would add 1 to descendant_count and vsize to descendant_size
  -- for every ancestor (including direct parents)
  for anc_hex in pairs(ancestors) do
    local anc_entry = self.entries[anc_hex]
    if anc_entry then
      local new_desc_count = anc_entry.descendant_count + 1
      local new_desc_size = anc_entry.descendant_size + vsize
      if new_desc_count > M.MAX_DESCENDANTS then
        return false, "too many descendants for ancestor " .. anc_hex:sub(1, 16)
      end
      if new_desc_size > M.MAX_DESCENDANT_SIZE then
        return false, "descendant size too large for ancestor " .. anc_hex:sub(1, 16)
      end
    end
  end

  -- 8. Add to mempool
  local entry = M.mempool_entry(tx, txid, fee, vsize, self.chain_state.tip_height, os.time())
  entry.ancestor_count = ancestor_count - 1  -- exclude self
  entry.ancestor_size = ancestor_size - vsize  -- exclude self
  entry.ancestor_fees = ancestor_fees - fee  -- exclude self
  entry.ancestors = ancestors
  self.entries[txid_hex] = entry
  self.tx_count = self.tx_count + 1
  self.total_size = self.total_size + entry.size

  -- Track outpoint spending and parent relationships
  for _, inp in ipairs(tx.inputs) do
    local outpoint_key = M.outpoint_key(inp.prev_out.hash, inp.prev_out.index)
    self.outpoint_to_tx[outpoint_key] = txid_hex

    local prev_hex = types.hash256_hex(inp.prev_out.hash)
    if direct_parents[prev_hex] then
      entry.spends_from[outpoint_key] = prev_hex
    end
  end

  -- Update ALL ancestors with descendant info (not just direct parents)
  -- Each ancestor gets this new tx added as a descendant
  for anc_hex in pairs(ancestors) do
    local anc_entry = self.entries[anc_hex]
    if anc_entry then
      anc_entry.descendants[txid_hex] = true
      anc_entry.descendant_count = anc_entry.descendant_count + 1
      anc_entry.descendant_size = anc_entry.descendant_size + vsize
      anc_entry.descendant_fees = anc_entry.descendant_fees + fee
    end
  end

  -- 9. Evict low-fee transactions if mempool exceeds max size
  self:trim()

  return true, txid_hex, fee
end

--------------------------------------------------------------------------------
-- Transaction Removal
--------------------------------------------------------------------------------

--- Remove a transaction from the mempool.
-- @param txid_hex string: Transaction id as hex string
-- @param reason string: Reason for removal (for logging)
function Mempool:remove_transaction(txid_hex, reason)
  local entry = self.entries[txid_hex]
  if not entry then return end

  -- Remove descendants first (recursive)
  -- Copy the table to avoid modification during iteration
  local desc_list = {}
  for desc_hex in pairs(entry.descendants) do
    desc_list[#desc_list + 1] = desc_hex
  end
  for _, desc_hex in ipairs(desc_list) do
    self:remove_transaction(desc_hex, reason)
  end

  -- Clean up outpoint tracking
  for _, inp in ipairs(entry.tx.inputs) do
    local outpoint_key = M.outpoint_key(inp.prev_out.hash, inp.prev_out.index)
    self.outpoint_to_tx[outpoint_key] = nil
  end

  -- Update ALL ancestors (not just direct parents)
  -- Remove this tx from their descendants set and decrement counts
  for anc_hex in pairs(entry.ancestors) do
    local anc_entry = self.entries[anc_hex]
    if anc_entry then
      anc_entry.descendants[txid_hex] = nil
      anc_entry.descendant_count = anc_entry.descendant_count - 1
      anc_entry.descendant_size = anc_entry.descendant_size - entry.vsize
      anc_entry.descendant_fees = anc_entry.descendant_fees - entry.fee
    end
  end

  self.total_size = self.total_size - entry.size
  self.tx_count = self.tx_count - 1
  self.entries[txid_hex] = nil
end

--------------------------------------------------------------------------------
-- Block Connection
--------------------------------------------------------------------------------

--- Handle block connection (remove confirmed transactions).
-- @param block block: The connected block
function Mempool:on_block_connected(block)
  for _, tx in ipairs(block.transactions) do
    local txid = validation.compute_txid(tx)
    local txid_hex = types.hash256_hex(txid)
    if self.entries[txid_hex] then
      self:remove_transaction(txid_hex, "confirmed")
    end
    -- Also remove conflicting transactions
    for _, inp in ipairs(tx.inputs) do
      local outpoint_key = M.outpoint_key(inp.prev_out.hash, inp.prev_out.index)
      local conflict = self.outpoint_to_tx[outpoint_key]
      if conflict and conflict ~= txid_hex then
        self:remove_transaction(conflict, "conflict")
      end
    end
  end
end

--------------------------------------------------------------------------------
-- Mempool Trimming
--------------------------------------------------------------------------------

--- Evict low-fee transactions when mempool exceeds max size.
function Mempool:trim()
  while self.total_size > self.max_size do
    -- Find the entry with the lowest descendant fee rate
    -- (total fee of this tx + descendants) / (total size of this tx + descendants)
    local worst_hex = nil
    local worst_rate = math.huge
    for hex, entry in pairs(self.entries) do
      local rate = (entry.fee + entry.descendant_fees) /
                   (entry.vsize + entry.descendant_size)
      if rate < worst_rate then
        worst_rate = rate
        worst_hex = hex
      end
    end
    if not worst_hex then break end
    self:remove_transaction(worst_hex, "evicted")
  end
end

--------------------------------------------------------------------------------
-- Mempool Queries
--------------------------------------------------------------------------------

--- Get all entries sorted by ancestor fee rate for block template construction.
-- Higher ancestor fee rate = better candidate for inclusion.
-- @return table: Array of mempool entries sorted by ancestor fee rate (descending)
function Mempool:get_sorted_entries()
  local sorted = {}
  for _, entry in pairs(self.entries) do
    sorted[#sorted + 1] = entry
  end
  table.sort(sorted, function(a, b)
    local rate_a = (a.fee + a.ancestor_fees) / (a.vsize + a.ancestor_size)
    local rate_b = (b.fee + b.ancestor_fees) / (b.vsize + b.ancestor_size)
    return rate_a > rate_b
  end)
  return sorted
end

--- Get mempool statistics.
-- @return table: Mempool info
function Mempool:get_info()
  return {
    size = self.tx_count,
    bytes = self.total_size,
    usage = self.total_size,
    maxmempool = self.max_size,
    mempoolminfee = self.min_relay_fee,
  }
end

--- Get all transaction ids in the mempool.
-- @return table: Array of txid hex strings
function Mempool:get_raw_mempool()
  local txids = {}
  for hex in pairs(self.entries) do
    txids[#txids + 1] = hex
  end
  return txids
end

--- Get a specific mempool entry.
-- @param txid_hex string: Transaction id as hex string
-- @return table: Mempool entry or nil
function Mempool:get_entry(txid_hex)
  return self.entries[txid_hex]
end

--- Check if a transaction is in the mempool.
-- @param txid_hex string: Transaction id as hex string
-- @return boolean: True if transaction is in mempool
function Mempool:has(txid_hex)
  return self.entries[txid_hex] ~= nil
end

--- Check descendant limits for a potential new child transaction.
-- @param parent_txid_hex string: Parent transaction id
-- @param child_vsize number: Virtual size of the potential child
-- @return boolean: True if limits would be satisfied
function Mempool:check_descendant_limits(parent_txid_hex, child_vsize)
  local parent = self.entries[parent_txid_hex]
  if not parent then return true end  -- Parent not in mempool

  local new_desc_count = parent.descendant_count + 1
  local new_desc_size = parent.descendant_size + child_vsize

  if new_desc_count > M.MAX_DESCENDANTS then
    return false
  end
  if new_desc_size > M.MAX_DESCENDANT_SIZE then
    return false
  end
  return true
end

return M
