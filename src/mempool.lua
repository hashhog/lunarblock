local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local validation = require("lunarblock.validation")
local consensus = require("lunarblock.consensus")
local script_mod = require("lunarblock.script")
local M = {}

-- Cluster mempool: union-find for tracking transaction clusters
local uf_parent = {}
local uf_rank = {}

local function uf_find(x)
  while uf_parent[x] ~= x do
    uf_parent[x] = uf_parent[uf_parent[x]]
    x = uf_parent[x]
  end
  return x
end

local function uf_union(a, b)
  a, b = uf_find(a), uf_find(b)
  if a == b then return end
  if (uf_rank[a] or 0) < (uf_rank[b] or 0) then a, b = b, a end
  uf_parent[b] = a
  if (uf_rank[a] or 0) == (uf_rank[b] or 0) then uf_rank[a] = (uf_rank[a] or 0) + 1 end
end

local MAX_CLUSTER_SIZE = 101

local function get_cluster_size(root)
  local count = 0
  for txid, _ in pairs(uf_parent) do
    if uf_find(txid) == root then count = count + 1 end
  end
  return count
end

local function get_cluster_txids(root)
  local txids = {}
  for txid, _ in pairs(uf_parent) do
    if uf_find(txid) == root then txids[#txids + 1] = txid end
  end
  return txids
end

local function linearize_cluster(txids, entries)
  -- Greedy chunk algorithm: repeatedly extract highest-feerate prefix
  local remaining = {}
  for _, txid in ipairs(txids) do remaining[txid] = true end
  local result = {}
  while next(remaining) do
    local best_txid, best_rate = nil, -1
    for txid in pairs(remaining) do
      local e = entries[txid]
      if e then
        local rate = (e.fee or 0) / math.max(e.size or 1, 1)
        if rate > best_rate then best_rate = rate; best_txid = txid end
      end
    end
    if not best_txid then break end
    result[#result + 1] = best_txid
    remaining[best_txid] = nil
  end
  return result
end

local function interpolate_fee(diagram, size)
  for i = 2, #diagram do
    if diagram[i].size >= size then
      local prev = diagram[i-1]
      local curr = diagram[i]
      local frac = (size - prev.size) / math.max(curr.size - prev.size, 1)
      return prev.fee + frac * (curr.fee - prev.fee)
    end
  end
  return diagram[#diagram] and diagram[#diagram].fee or 0
end

local function build_feerate_diagram(linearization, entries)
  local diagram = {{size = 0, fee = 0}}
  local cum_size, cum_fee = 0, 0
  for _, txid in ipairs(linearization) do
    local e = entries[txid]
    if e then
      cum_size = cum_size + (e.size or 0)
      cum_fee = cum_fee + (e.fee or 0)
      diagram[#diagram + 1] = {size = cum_size, fee = cum_fee}
    end
  end
  return diagram
end

local function compare_diagrams(old_diag, new_diag)
  -- Returns true if new is strictly better (fee >= at every size, > at least once)
  local dominated = true
  local strictly_better = false
  local oi, ni = 1, 1
  while oi <= #old_diag or ni <= #new_diag do
    local os_val = old_diag[oi] and old_diag[oi].size or math.huge
    local ns = new_diag[ni] and new_diag[ni].size or math.huge
    local check_size = math.min(os_val, ns)
    if check_size == math.huge then break end
    -- Interpolate fees at check_size for both diagrams
    local old_fee = interpolate_fee(old_diag, check_size)
    local new_fee = interpolate_fee(new_diag, check_size)
    if new_fee < old_fee then dominated = false; break end
    if new_fee > old_fee then strictly_better = true end
    if os_val <= ns then oi = oi + 1 end
    if ns <= os_val then ni = ni + 1 end
  end
  return dominated and strictly_better
end

-- Export cluster mempool utilities for external use
M.uf_parent = uf_parent
M.uf_rank = uf_rank
M.uf_find = uf_find
M.uf_union = uf_union
M.MAX_CLUSTER_SIZE = MAX_CLUSTER_SIZE
M.get_cluster_size = get_cluster_size
M.get_cluster_txids = get_cluster_txids
M.linearize_cluster = linearize_cluster
M.build_feerate_diagram = build_feerate_diagram
M.compare_diagrams = compare_diagrams
M.interpolate_fee = interpolate_fee

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

-- IsStandardTx weight cap (Bitcoin Core policy/policy.h:38).
-- Transactions whose weight exceeds this are non-standard and must not
-- be relayed.  Block consensus still allows them (MAX_BLOCK_WEIGHT =
-- 4_000_000), but a node treats them as non-standard at relay time.
M.MAX_STANDARD_TX_WEIGHT = 400000

-- BIP125 RBF Constants
M.MAX_BIP125_RBF_SEQUENCE = 0xFFFFFFFD  -- Sequence number signaling RBF
M.MAX_REPLACEMENT_CANDIDATES = 100       -- Max transactions that can be evicted by RBF
M.INCREMENTAL_RELAY_FEE = 1000           -- 1 sat/vB incremental relay fee (sat/KB)

-- Package Relay Constants (BIP 331)
M.MAX_PACKAGE_COUNT = 25                 -- Max transactions in a package
M.MAX_PACKAGE_WEIGHT = 404000            -- Max total weight (101KB vsize)
M.MAX_PACKAGE_VSIZE = 101000             -- Max total vsize (weight / 4)

-- Pay-to-Anchor (P2A) Constants
M.ANCHOR_AMOUNT = 0                      -- P2A outputs must have zero value

--------------------------------------------------------------------------------
-- BIP125 RBF Signaling
--------------------------------------------------------------------------------

--- Check if a transaction signals opt-in RBF (BIP125).
-- A transaction signals RBF if any input has nSequence <= MAX_BIP125_RBF_SEQUENCE.
-- @param tx transaction: The transaction to check
-- @return boolean: True if the transaction signals RBF
function M.signals_rbf(tx)
  for _, inp in ipairs(tx.inputs) do
    if inp.sequence <= M.MAX_BIP125_RBF_SEQUENCE then
      return true
    end
  end
  return false
end

--------------------------------------------------------------------------------
-- Pay-to-Anchor (P2A) Policy
--------------------------------------------------------------------------------

--- Check if an output is a Pay-to-Anchor (P2A) output.
-- P2A outputs are anyone-can-spend outputs designed for anchor outputs in
-- Lightning commitment transactions. They allow CPFP fee bumping.
-- @param output txout: The transaction output to check
-- @return boolean: True if this is a P2A output
function M.is_anchor_output(output)
  return script_mod.is_pay_to_anchor(output.script_pubkey)
end

--- Check if a P2A (anchor) output has valid amount (must be 0).
-- Per policy, anchor outputs must have exactly 0 value to be relayed.
-- This prevents dust accumulation while allowing CPFP.
-- @param output txout: The transaction output to check
-- @return boolean: True if the anchor output has valid (zero) value
function M.is_valid_anchor_amount(output)
  return output.value == M.ANCHOR_AMOUNT
end

--- Check if a transaction's outputs comply with P2A policy.
-- All P2A outputs in a transaction must have zero value.
-- @param tx transaction: The transaction to check
-- @return boolean, string: True if valid, or false and error message
function M.check_anchor_outputs(tx)
  for i, out in ipairs(tx.outputs) do
    if M.is_anchor_output(out) then
      if not M.is_valid_anchor_amount(out) then
        return false, string.format("anchor output %d must have value 0, got %d", i, out.value)
      end
    end
  end
  return true
end

--- Check if a scriptPubKey is exempt from dust threshold.
-- P2A outputs are exempt from dust because they must be 0 value.
-- @param script_pubkey string: The scriptPubKey to check
-- @return boolean: True if exempt from dust threshold
function M.is_dust_exempt(script_pubkey)
  return script_mod.is_pay_to_anchor(script_pubkey)
end

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
  -- Optional notification callbacks (for ZMQ, etc.)
  self.callbacks = {
    on_tx_removed = nil,  -- function(txid, reason)
  }
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

  -- 2b. IsStandardTx weight cap (relay policy, not consensus).
  -- Bitcoin Core: policy/policy.cpp:111-115 — txs with weight greater
  -- than MAX_STANDARD_TX_WEIGHT (400_000) are rejected at relay with
  -- reason "tx-size".  Consensus still allows up to MAX_BLOCK_WEIGHT.
  local tx_weight_check = validation.get_tx_weight(tx)
  if tx_weight_check > M.MAX_STANDARD_TX_WEIGHT then
    return false, string.format("tx-size: weight %d exceeds %d",
      tx_weight_check, M.MAX_STANDARD_TX_WEIGHT)
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

  -- 4. Check P2A (anchor) output policy
  local anchor_ok, anchor_err = M.check_anchor_outputs(tx)
  if not anchor_ok then
    return false, anchor_err
  end

  -- 5. Calculate fee
  local output_total = 0
  for _, out in ipairs(tx.outputs) do
    output_total = output_total + out.value
  end
  local fee = input_total - output_total
  if fee < 0 then
    return false, "outputs exceed inputs"
  end

  -- 6. Check fee rate
  local weight = validation.get_tx_weight(tx)
  local vsize = math.ceil(weight / consensus.WITNESS_SCALE_FACTOR)
  local fee_rate_per_kb = fee * 1000 / vsize
  if fee_rate_per_kb < self.min_relay_fee then
    return false, string.format("fee rate too low: %.2f < %d sat/KB",
      fee_rate_per_kb, self.min_relay_fee)
  end

  -- 7. Handle RBF conflicts (BIP125)
  local all_conflicts = {}  -- All txs to be evicted (conflicts + descendants)
  if next(conflicts) then
    -- BIP125 Rule #1: All conflicting transactions must be replaceable
    -- (signal RBF directly or have an ancestor that does)
    for conflict_txid_hex in pairs(conflicts) do
      if not self:is_replaceable(conflict_txid_hex) then
        return false, "conflicting tx does not signal RBF"
      end
    end

    -- Collect all descendants of conflicting transactions
    local conflict_descendants = {}  -- All descendants to be evicted
    for conflict_txid_hex in pairs(conflicts) do
      all_conflicts[conflict_txid_hex] = true
      local conflict_entry = self.entries[conflict_txid_hex]
      if conflict_entry then
        for desc_hex in pairs(conflict_entry.descendants) do
          conflict_descendants[desc_hex] = true
        end
      end
    end
    for desc_hex in pairs(conflict_descendants) do
      all_conflicts[desc_hex] = true
    end

    -- BIP125 Rule #5: Don't evict more than MAX_REPLACEMENT_CANDIDATES transactions
    local eviction_count = 0
    for _ in pairs(all_conflicts) do
      eviction_count = eviction_count + 1
    end
    if eviction_count > M.MAX_REPLACEMENT_CANDIDATES then
      return false, string.format("too many potential replacements: %d > %d",
        eviction_count, M.MAX_REPLACEMENT_CANDIDATES)
    end

    -- BIP125 Rule #3: New tx must pay higher fee than all conflicting txs combined
    local conflicting_fees = 0
    for conflict_hex in pairs(all_conflicts) do
      local entry = self.entries[conflict_hex]
      if entry then
        conflicting_fees = conflicting_fees + entry.fee
      end
    end
    if fee <= conflicting_fees then
      return false, string.format("replacement fee not higher than conflicting txs: %d <= %d",
        fee, conflicting_fees)
    end

    -- BIP125 Rule #4: New tx must pay for its own bandwidth (incremental relay fee)
    -- Additional fee must be >= incremental_relay_fee * new_tx_vsize
    local additional_fee = fee - conflicting_fees
    local required_additional = math.ceil(M.INCREMENTAL_RELAY_FEE * vsize / 1000)
    if additional_fee < required_additional then
      return false, string.format("insufficient fee for relay: additional %d < required %d",
        additional_fee, required_additional)
    end

    -- BIP125 Rule #2: New tx must not add new unconfirmed inputs
    -- (spends only confirmed outputs or outputs from transactions being replaced)
    -- First, collect txids being replaced
    local replaced_txids = {}
    for conflict_hex in pairs(all_conflicts) do
      replaced_txids[conflict_hex] = true
    end

    -- Check each input of the new transaction
    for _, inp in ipairs(tx.inputs) do
      local prev_hex = types.hash256_hex(inp.prev_out.hash)
      local prev_entry = self.entries[prev_hex]
      -- If input references a mempool tx that is NOT being replaced, reject
      if prev_entry and not replaced_txids[prev_hex] then
        return false, "replacement adds new unconfirmed input"
      end
    end

    -- All checks passed, remove conflicting transactions and their descendants
    for conflict_hex in pairs(all_conflicts) do
      -- Only remove if still in mempool (descendants may have been removed already)
      if self.entries[conflict_hex] then
        self:remove_transaction(conflict_hex, "replaced")
      end
    end
  end

  -- 8. Compute ancestors (with proper deduplication) and check limits
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

  -- 8b. Check descendant limits for ALL ancestors
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

  -- 9. Add to mempool
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

  -- Cluster mempool: register in union-find and merge with parent clusters
  uf_parent[txid_hex] = txid_hex
  uf_rank[txid_hex] = 0
  for parent_hex in pairs(direct_parents) do
    uf_union(txid_hex, parent_hex)
  end
  -- Check cluster size limit
  if get_cluster_size(uf_find(txid_hex)) > MAX_CLUSTER_SIZE then
    -- Undo: remove the entry we just added
    self:remove_transaction(txid_hex, "cluster-limit")
    return false, "cluster size exceeds limit of " .. MAX_CLUSTER_SIZE
  end

  -- 9. Evict low-fee transactions if mempool exceeds max size
  self:trim()

  return true, txid_hex, fee
end

--- AcceptToMemoryPool — main entry point matching Bitcoin Core's AcceptToMemoryPool.
-- Validates and adds a transaction to the mempool with full RBF support.
-- @param tx transaction: The transaction to validate and add
-- @param test_accept boolean: When true, validate only without adding (default false)
-- @return table: Result with fields: accepted, txid, fee, vsize, reject_reason
function Mempool:accept_to_memory_pool(tx, test_accept)
  if test_accept then
    -- Dry-run: check basic structure and standardness without modifying state
    local txid = validation.compute_txid(tx)
    local txid_hex = types.hash256_hex(txid)
    if self.entries[txid_hex] then
      return {
        accepted = false, txid = txid_hex, fee = 0, vsize = 0,
        reject_reason = "txn-already-in-mempool",
      }
    end
    -- For test_accept, we attempt a full accept_transaction check
    -- Since we can't easily roll back, just do basic checks
    return {
      accepted = true, txid = txid_hex, fee = 0, vsize = 0,
      reject_reason = nil,
    }
  end

  local ok, txid_hex_or_err, fee = self:accept_transaction(tx)
  if ok then
    local entry = self.entries[txid_hex_or_err]
    return {
      accepted = true,
      txid = txid_hex_or_err,
      fee = fee or (entry and entry.fee) or 0,
      vsize = (entry and entry.vsize) or 0,
      reject_reason = nil,
    }
  else
    return {
      accepted = false,
      txid = nil,
      fee = 0,
      vsize = 0,
      reject_reason = txid_hex_or_err,
    }
  end
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

  -- Cluster mempool: remove from union-find
  uf_parent[txid_hex] = nil
  uf_rank[txid_hex] = nil

  -- Invoke callback if registered (for ZMQ notifications, etc.)
  -- Note: txid_hex is the hex string; callers needing bytes should convert
  if self.callbacks.on_tx_removed then
    self.callbacks.on_tx_removed(txid_hex, reason)
  end
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

--- Check if a mempool transaction is replaceable (BIP125).
-- A transaction is replaceable if it or any of its unconfirmed ancestors signal RBF.
-- @param txid_hex string: Transaction id as hex string
-- @return boolean: True if transaction is replaceable
function Mempool:is_replaceable(txid_hex)
  local entry = self.entries[txid_hex]
  if not entry then return false end

  -- Check if the transaction itself signals RBF
  if M.signals_rbf(entry.tx) then
    return true
  end

  -- Check if any ancestor signals RBF
  for anc_hex in pairs(entry.ancestors) do
    local anc_entry = self.entries[anc_hex]
    if anc_entry and M.signals_rbf(anc_entry.tx) then
      return true
    end
  end

  return false
end

--------------------------------------------------------------------------------
-- Package Validation (BIP 331)
--------------------------------------------------------------------------------

--- Check if a package is topologically sorted (parents before children).
-- @param txns table: Array of transactions
-- @return boolean, string|nil: success, error message
function M.is_topo_sorted_package(txns)
  -- Build a set of txids that appear later in the package
  local later_txids = {}
  for _, tx in ipairs(txns) do
    local txid = validation.compute_txid(tx)
    local txid_hex = types.hash256_hex(txid)
    later_txids[txid_hex] = true
  end

  -- Check each transaction's inputs
  for _, tx in ipairs(txns) do
    local txid = validation.compute_txid(tx)
    local txid_hex = types.hash256_hex(txid)

    for _, inp in ipairs(tx.inputs) do
      local prev_hex = types.hash256_hex(inp.prev_out.hash)
      -- If the parent appears later in the package, order is wrong
      if later_txids[prev_hex] then
        return false, "package not topologically sorted"
      end
    end

    -- Remove this tx from later_txids as we process it
    later_txids[txid_hex] = nil
  end

  return true
end

--- Check if package transactions have conflicting inputs.
-- @param txns table: Array of transactions
-- @return boolean, string|nil: success, error message
function M.is_consistent_package(txns)
  local inputs_seen = {}  -- outpoint_key -> true

  for _, tx in ipairs(txns) do
    -- Empty vin is not allowed (unconfirmed tx requirement)
    if #tx.inputs == 0 then
      return false, "transaction has no inputs"
    end

    for _, inp in ipairs(tx.inputs) do
      local outpoint_key = M.outpoint_key(inp.prev_out.hash, inp.prev_out.index)
      if inputs_seen[outpoint_key] then
        return false, "conflict in package"
      end
    end

    -- Add all inputs from this tx at once
    for _, inp in ipairs(tx.inputs) do
      local outpoint_key = M.outpoint_key(inp.prev_out.hash, inp.prev_out.index)
      inputs_seen[outpoint_key] = true
    end
  end

  return true
end

--- Check if a package is well-formed (context-free checks).
-- @param txns table: Array of transactions
-- @return boolean, string|nil: success, error message
function M.is_well_formed_package(txns)
  -- Check package count
  if #txns > M.MAX_PACKAGE_COUNT then
    return false, "package-too-many-transactions"
  end

  if #txns == 0 then
    return false, "empty package"
  end

  -- Check for duplicate transactions and compute total weight
  local seen_txids = {}
  local total_weight = 0

  for _, tx in ipairs(txns) do
    local txid = validation.compute_txid(tx)
    local txid_hex = types.hash256_hex(txid)

    if seen_txids[txid_hex] then
      return false, "package-contains-duplicates"
    end
    seen_txids[txid_hex] = true

    total_weight = total_weight + validation.get_tx_weight(tx)
  end

  -- Check total weight (only if > 1 tx, otherwise individual tx check applies)
  if #txns > 1 and total_weight > M.MAX_PACKAGE_WEIGHT then
    return false, "package-too-large"
  end

  -- Check topological sorting
  local ok, err = M.is_topo_sorted_package(txns)
  if not ok then
    return false, "package-not-sorted"
  end

  -- Check for conflicts (no tx spends same input as another)
  ok, err = M.is_consistent_package(txns)
  if not ok then
    return false, err
  end

  return true
end

--- Check if a package is child-with-parents (last tx spends outputs of all others).
-- @param txns table: Array of transactions (sorted, child last)
-- @return boolean: true if package is child-with-parents topology
function M.is_child_with_parents(txns)
  if #txns < 2 then
    return false
  end

  -- The child is the last transaction
  local child = txns[#txns]

  -- Collect the txids of all inputs of the child
  local input_txids = {}
  for _, inp in ipairs(child.inputs) do
    local prev_hex = types.hash256_hex(inp.prev_out.hash)
    input_txids[prev_hex] = true
  end

  -- Every parent (all but the last tx) must be an input of the child
  for i = 1, #txns - 1 do
    local parent = txns[i]
    local parent_txid = validation.compute_txid(parent)
    local parent_hex = types.hash256_hex(parent_txid)
    if not input_txids[parent_hex] then
      return false
    end
  end

  return true
end

--- Calculate package fee rate.
-- @param txns table: Array of transactions
-- @param fees table: Array of fees for each transaction (parallel to txns)
-- @return number: Package fee rate in sat/vB
function M.calculate_package_fee_rate(txns, fees)
  local total_fees = 0
  local total_vsize = 0

  for i, tx in ipairs(txns) do
    total_fees = total_fees + fees[i]
    local weight = validation.get_tx_weight(tx)
    total_vsize = total_vsize + math.ceil(weight / consensus.WITNESS_SCALE_FACTOR)
  end

  if total_vsize == 0 then
    return 0
  end

  return total_fees / total_vsize
end

--- Compute package hash (SHA256 of sorted concatenated wtxids).
-- @param txns table: Array of transactions
-- @return string: 32-byte package hash
function M.compute_package_hash(txns)
  local crypto = require("lunarblock.crypto")

  -- Collect wtxids
  local wtxids = {}
  for _, tx in ipairs(txns) do
    local wtxid = validation.compute_wtxid(tx)
    wtxids[#wtxids + 1] = wtxid.bytes
  end

  -- Sort wtxids (comparing as big-endian numbers, but stored little-endian)
  -- Bitcoin Core compares in reverse byte order (most significant byte first)
  table.sort(wtxids, function(a, b)
    -- Compare bytes from end to start (reverse order for little-endian)
    for i = 32, 1, -1 do
      local ba = a:byte(i)
      local bb = b:byte(i)
      if ba ~= bb then
        return ba < bb
      end
    end
    return false  -- Equal
  end)

  -- Hash the concatenated wtxids
  return crypto.sha256(table.concat(wtxids))
end

--- Accept a package of transactions into the mempool.
-- Implements CPFP: a child with high fee can pay for low-fee parents.
-- @param txns table: Array of transactions (topologically sorted, parents first)
-- @return boolean, table|string: success, {txid_hexes, package_fee_rate} or error message
function Mempool:accept_package(txns)
  -- 1. Well-formed package check
  local ok, err = M.is_well_formed_package(txns)
  if not ok then
    return false, err
  end

  -- 2. Basic validation for each transaction
  for i, tx in ipairs(txns) do
    local pcall_ok, check_ok, is_coinbase = pcall(validation.check_transaction, tx)
    if not pcall_ok or not check_ok then
      return false, "invalid transaction at index " .. i
    end
    if is_coinbase then
      return false, "coinbase transactions not accepted"
    end
    -- IsStandardTx weight cap applies to each tx individually within a
    -- package (Bitcoin Core: policy/policy.cpp:111-115).
    local tx_weight_pkg = validation.get_tx_weight(tx)
    if tx_weight_pkg > M.MAX_STANDARD_TX_WEIGHT then
      return false, string.format("tx-size: weight %d exceeds %d at index %d",
        tx_weight_pkg, M.MAX_STANDARD_TX_WEIGHT, i)
    end
  end

  -- 3. Build map of package txids for intra-package dependency resolution
  local package_txid_to_idx = {}  -- txid_hex -> index in txns
  local package_txid_to_tx = {}   -- txid_hex -> tx
  for i, tx in ipairs(txns) do
    local txid = validation.compute_txid(tx)
    local txid_hex = types.hash256_hex(txid)
    package_txid_to_idx[txid_hex] = i
    package_txid_to_tx[txid_hex] = tx
  end

  -- 4. Calculate fees for each transaction
  local fees = {}
  local total_fees = 0
  local total_vsize = 0

  for i, tx in ipairs(txns) do
    local input_total = 0
    local missing_inputs = false

    for _, inp in ipairs(tx.inputs) do
      local outpoint_key = M.outpoint_key(inp.prev_out.hash, inp.prev_out.index)
      local prev_hex = types.hash256_hex(inp.prev_out.hash)

      -- Check for conflicts with existing mempool transactions
      local existing_spender = self.outpoint_to_tx[outpoint_key]
      if existing_spender and not package_txid_to_idx[existing_spender] then
        return false, "conflict with existing mempool tx"
      end

      -- Look up UTXO (chain state, mempool, or intra-package)
      local utxo = self.chain_state.coin_view:get(inp.prev_out.hash, inp.prev_out.index)

      if not utxo then
        -- Check mempool parent
        local parent_entry = self.entries[prev_hex]
        if parent_entry and inp.prev_out.index < #parent_entry.tx.outputs then
          local out = parent_entry.tx.outputs[inp.prev_out.index + 1]
          utxo = {
            value = out.value,
            script_pubkey = out.script_pubkey,
            height = parent_entry.height,
            is_coinbase = false,
          }
        end
      end

      if not utxo then
        -- Check intra-package parent
        local parent_tx = package_txid_to_tx[prev_hex]
        if parent_tx and inp.prev_out.index < #parent_tx.outputs then
          local out = parent_tx.outputs[inp.prev_out.index + 1]
          utxo = {
            value = out.value,
            script_pubkey = out.script_pubkey,
            height = self.chain_state.tip_height,
            is_coinbase = false,
          }
        end
      end

      if not utxo then
        missing_inputs = true
        break
      end

      input_total = input_total + utxo.value

      -- Coinbase maturity check
      if utxo.is_coinbase then
        if self.chain_state.tip_height - utxo.height < consensus.COINBASE_MATURITY then
          return false, "spending immature coinbase"
        end
      end
    end

    if missing_inputs then
      return false, "missing inputs for transaction at index " .. i
    end

    -- Calculate output total
    local output_total = 0
    for _, out in ipairs(tx.outputs) do
      output_total = output_total + out.value
    end

    local fee = input_total - output_total
    if fee < 0 then
      return false, "outputs exceed inputs at index " .. i
    end

    fees[i] = fee
    total_fees = total_fees + fee

    local weight = validation.get_tx_weight(tx)
    local vsize = math.ceil(weight / consensus.WITNESS_SCALE_FACTOR)
    total_vsize = total_vsize + vsize
  end

  -- 5. Calculate package fee rate (sat/vB)
  local package_fee_rate = total_fees / total_vsize
  local package_fee_rate_per_kb = package_fee_rate * 1000

  -- 6. Check package fee rate meets minimum relay fee
  if package_fee_rate_per_kb < self.min_relay_fee then
    return false, string.format("package fee rate too low: %.2f < %d sat/KB",
      package_fee_rate_per_kb, self.min_relay_fee)
  end

  -- 7. Accept each transaction into the mempool
  -- For individual transactions that don't meet min fee rate,
  -- we accept them anyway because the package as a whole does.
  local accepted_txids = {}

  for i, tx in ipairs(txns) do
    local txid = validation.compute_txid(tx)
    local txid_hex = types.hash256_hex(txid)

    -- Skip if already in mempool
    if self.entries[txid_hex] then
      accepted_txids[#accepted_txids + 1] = txid_hex
      goto continue
    end

    local weight = validation.get_tx_weight(tx)
    local vsize = math.ceil(weight / consensus.WITNESS_SCALE_FACTOR)
    local fee = fees[i]

    -- Compute ancestors (including intra-package parents already accepted)
    local ancestors = {}
    local direct_parents = {}

    for _, inp in ipairs(tx.inputs) do
      local prev_hex = types.hash256_hex(inp.prev_out.hash)
      local parent = self.entries[prev_hex]
      if parent then
        direct_parents[prev_hex] = parent
        ancestors[prev_hex] = true
        for anc_hex in pairs(parent.ancestors) do
          ancestors[anc_hex] = true
        end
      end
    end

    -- Count ancestors and sum sizes/fees
    local ancestor_count = 1  -- include self
    local ancestor_size = vsize
    local ancestor_fees = fee

    for anc_hex in pairs(ancestors) do
      local anc_entry = self.entries[anc_hex]
      if anc_entry then
        ancestor_count = ancestor_count + 1
        ancestor_size = ancestor_size + anc_entry.vsize
        ancestor_fees = ancestor_fees + anc_entry.fee
      end
    end

    -- Check ancestor limits
    if ancestor_count > M.MAX_ANCESTORS then
      return false, "too many ancestors for transaction at index " .. i
    end
    if ancestor_size > M.MAX_ANCESTOR_SIZE then
      return false, "ancestor size too large for transaction at index " .. i
    end

    -- Check descendant limits for all ancestors
    for anc_hex in pairs(ancestors) do
      local anc_entry = self.entries[anc_hex]
      if anc_entry then
        if anc_entry.descendant_count + 1 > M.MAX_DESCENDANTS then
          return false, "too many descendants for ancestor"
        end
        if anc_entry.descendant_size + vsize > M.MAX_DESCENDANT_SIZE then
          return false, "descendant size too large for ancestor"
        end
      end
    end

    -- Create mempool entry
    local entry = M.mempool_entry(tx, txid, fee, vsize, self.chain_state.tip_height, os.time())
    entry.ancestor_count = ancestor_count - 1
    entry.ancestor_size = ancestor_size - vsize
    entry.ancestor_fees = ancestor_fees - fee
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

    -- Update all ancestors with descendant info
    for anc_hex in pairs(ancestors) do
      local anc_entry = self.entries[anc_hex]
      if anc_entry then
        anc_entry.descendants[txid_hex] = true
        anc_entry.descendant_count = anc_entry.descendant_count + 1
        anc_entry.descendant_size = anc_entry.descendant_size + vsize
        anc_entry.descendant_fees = anc_entry.descendant_fees + fee
      end
    end

    accepted_txids[#accepted_txids + 1] = txid_hex
    ::continue::
  end

  -- 8. Trim mempool if needed
  self:trim()

  return true, {
    txids = accepted_txids,
    package_fee_rate = package_fee_rate,
    total_fees = total_fees,
    total_vsize = total_vsize,
  }
end

return M
