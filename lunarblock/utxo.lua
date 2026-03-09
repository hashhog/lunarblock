local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local crypto = require("lunarblock.crypto")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local script = require("lunarblock.script")
local storage_mod = require("lunarblock.storage")
local perf = require("lunarblock.perf")
local M = {}

--------------------------------------------------------------------------------
-- UTXO Entry
--------------------------------------------------------------------------------

-- A UTXO entry represents a single unspent transaction output
-- Stored in the database keyed by outpoint (txid + vout_index)
function M.utxo_entry(value, script_pubkey, height, is_coinbase)
  return {
    value = value,                 -- int64 satoshis
    script_pubkey = script_pubkey, -- raw script bytes
    height = height,               -- block height where this output was created
    is_coinbase = is_coinbase,     -- boolean, for maturity check
  }
end

--------------------------------------------------------------------------------
-- UTXO Entry Serialization
--------------------------------------------------------------------------------

function M.serialize_utxo_entry(entry)
  local w = serialize.buffer_writer()
  w.write_i64le(entry.value)
  w.write_varstr(entry.script_pubkey)
  w.write_u32le(entry.height)
  w.write_u8(entry.is_coinbase and 1 or 0)
  return w.result()
end

function M.deserialize_utxo_entry(data)
  local r = serialize.buffer_reader(data)
  return M.utxo_entry(
    r.read_i64le(),
    r.read_varstr(),
    r.read_u32le(),
    r.read_u8() == 1
  )
end

--------------------------------------------------------------------------------
-- Outpoint Key
--------------------------------------------------------------------------------

-- Generate a 36-byte key for database lookups (32-byte txid + 4-byte vout index)
function M.outpoint_key(txid_hash256, vout_index)
  local w = serialize.buffer_writer()
  w.write_hash256(txid_hash256)
  w.write_u32le(vout_index)
  return w.result()  -- 36 bytes
end

--------------------------------------------------------------------------------
-- CoinView Cache
--------------------------------------------------------------------------------

-- UTXO cache sizing:
-- Default cache size: 50000 entries (~200MB for typical UTXOs)
-- Can be tuned via --dbcache flag (in MB)
--
-- Cache sizing formula:
--   entries = (dbcache_mb * 1024 * 1024) / avg_utxo_size
--   avg_utxo_size ~= 4096 bytes (outpoint + script + metadata)
--   So 200MB => ~51200 entries, 450MB => ~115200 entries

local CoinView = {}
CoinView.__index = CoinView

--- Configure UTXO cache based on dbcache setting.
-- @param opts table: {dbcache=MB}
-- @return number: calculated max entries
function M.configure_cache(opts)
  local dbcache_mb = opts and opts.dbcache or 200
  local avg_entry_bytes = 4096
  return math.floor((dbcache_mb * 1024 * 1024) / avg_entry_bytes)
end

function M.new_coin_view(storage, opts)
  local self = setmetatable({}, CoinView)
  self.storage = storage
  local max_entries = M.configure_cache(opts)
  self.lru = perf.new_lru_cache(max_entries)
  self.dirty = {}    -- set of outpoint_keys that need to be flushed
  self.spent = {}    -- outpoint_keys marked as spent (separate from LRU)
  return self
end

function CoinView:get(txid, vout)
  local key = M.outpoint_key(txid, vout)

  -- Check spent marker first
  if self.spent[key] then return nil end

  -- Check LRU cache
  local entry = self.lru:get(key)
  if entry then return entry end

  -- Load from database
  local data = self.storage.get(storage_mod.CF.UTXO, key)
  if not data then return nil end
  entry = M.deserialize_utxo_entry(data)
  self.lru:put(key, entry)
  return entry
end

function CoinView:add(txid, vout, entry)
  local key = M.outpoint_key(txid, vout)
  self.lru:put(key, entry)
  self.spent[key] = nil  -- clear spent marker if re-adding
  self.dirty[key] = true
end

function CoinView:spend(txid, vout)
  local key = M.outpoint_key(txid, vout)
  local entry = self:get(txid, vout)
  if not entry then return nil, "UTXO not found" end
  self.lru:remove(key)
  self.spent[key] = entry  -- store for undo data
  self.dirty[key] = true
  return entry
end

function CoinView:flush()
  -- Write all dirty entries to database in a batch
  local batch = self.storage.batch()
  for key, _ in pairs(self.dirty) do
    if self.spent[key] then
      batch.delete(storage_mod.CF.UTXO, key)
    else
      local entry = self.lru:get(key)
      if entry then
        batch.put(storage_mod.CF.UTXO, key, M.serialize_utxo_entry(entry))
      end
    end
  end
  batch.write(false)
  batch.destroy()
  self.dirty = {}
  self.spent = {}
end

function CoinView:clear_cache()
  self.lru:clear()
  self.dirty = {}
  self.spent = {}
end

--- Get cache statistics.
function CoinView:cache_stats()
  return self.lru:stats()
end

--------------------------------------------------------------------------------
-- ChainState Manager
--------------------------------------------------------------------------------

local ChainState = {}
ChainState.__index = ChainState

function M.new_chain_state(storage, network)
  local self = setmetatable({}, ChainState)
  self.storage = storage
  self.network = network or consensus.networks.mainnet
  self.coin_view = M.new_coin_view(storage)
  self.tip_hash = nil
  self.tip_height = -1
  return self
end

function ChainState:init()
  local hash, height = self.storage.get_chain_tip()
  if hash then
    self.tip_hash = hash
    self.tip_height = height
  end
end

--------------------------------------------------------------------------------
-- Connect Block
--------------------------------------------------------------------------------

function ChainState:connect_block(block, height, block_hash)
  -- 1. Validate all transactions have valid inputs (except coinbase)
  local total_fees = 0

  for tx_idx, tx in ipairs(block.transactions) do
    local txid = validation.compute_txid(tx)
    local is_coinbase = (tx_idx == 1)

    if not is_coinbase then
      -- Validate each input
      local input_total = 0

      for inp_idx, inp in ipairs(tx.inputs) do
        -- Look up the UTXO being spent
        local utxo = self.coin_view:get(inp.prev_out.hash, inp.prev_out.index)
        assert(utxo, string.format("Missing UTXO for input %d of tx %s",
          inp_idx, types.hash256_hex(txid)))

        -- Coinbase maturity check
        if utxo.is_coinbase then
          assert(height - utxo.height >= consensus.COINBASE_MATURITY,
            "Coinbase output not mature")
        end

        -- Script verification
        local flags = {
          verify_p2sh = height >= self.network.bip34_height,
          verify_dersig = height >= self.network.bip66_height,
          verify_checklocktimeverify = height >= self.network.bip65_height,
          verify_checksequenceverify = height >= self.network.csv_height,
          verify_witness = height >= self.network.segwit_height,
          verify_nulldummy = height >= self.network.segwit_height,
        }

        local checker = validation.make_sig_checker(
          tx, inp_idx - 1, utxo.value, utxo.script_pubkey, flags
        )

        -- Determine which scripts to run based on output type
        local script_type = script.classify_script(utxo.script_pubkey)

        if script_type == "p2wpkh" or script_type == "p2wsh" then
          -- SegWit: scriptSig must be empty, use witness stack
          assert(#inp.script_sig == 0, "SegWit input must have empty scriptSig")
          -- Execute witness program
          local witness_stack = inp.witness or {}
          if script_type == "p2wpkh" then
            -- P2WPKH: witness = {sig, pubkey}, execute synthetic P2PKH
            assert(#witness_stack == 2, "P2WPKH requires exactly 2 witness items")
            local pkh = utxo.script_pubkey:sub(3, 22)
            local synthetic_script = script.make_p2pkh_script(pkh)
            local stack = {witness_stack[1], witness_stack[2]}
            local segwit_flags = {}
            for k, v in pairs(flags) do segwit_flags[k] = v end
            segwit_flags.is_segwit = true
            local segwit_checker = validation.make_sig_checker(
              tx, inp_idx - 1, utxo.value, utxo.script_pubkey, segwit_flags
            )
            local result = script.execute_script(synthetic_script, stack, segwit_flags, segwit_checker)
            assert(#result > 0 and script.cast_to_bool(result[#result]),
              "P2WPKH script verification failed")
          elseif script_type == "p2wsh" then
            -- P2WSH: last witness item is the script
            local witness_script = witness_stack[#witness_stack]
            local script_hash = crypto.sha256(witness_script)
            assert(script_hash == utxo.script_pubkey:sub(3, 34),
              "P2WSH script hash mismatch")
            local stack = {}
            for i = 1, #witness_stack - 1 do
              stack[i] = witness_stack[i]
            end
            local segwit_flags = {}
            for k, v in pairs(flags) do segwit_flags[k] = v end
            segwit_flags.is_segwit = true
            segwit_flags.witness_script = witness_script
            local segwit_checker = validation.make_sig_checker(
              tx, inp_idx - 1, utxo.value, utxo.script_pubkey, segwit_flags
            )
            local result = script.execute_script(witness_script, stack, segwit_flags, segwit_checker)
            assert(#result > 0 and script.cast_to_bool(result[#result]),
              "P2WSH script verification failed")
          end
        else
          -- Legacy or P2SH
          local ok = script.verify_script(inp.script_sig, utxo.script_pubkey, flags, checker)
          assert(ok, "Script verification failed for input " .. inp_idx)
        end

        input_total = input_total + utxo.value

        -- Spend the UTXO
        self.coin_view:spend(inp.prev_out.hash, inp.prev_out.index)
      end

      -- Check output total <= input total
      local output_total = 0
      for _, out in ipairs(tx.outputs) do
        output_total = output_total + out.value
      end
      assert(input_total >= output_total,
        "Transaction outputs exceed inputs")
      total_fees = total_fees + (input_total - output_total)
    end

    -- Add outputs to UTXO set
    for vout_idx, out in ipairs(tx.outputs) do
      -- Don't add provably unspendable outputs (OP_RETURN)
      if #out.script_pubkey == 0 or out.script_pubkey:byte(1) ~= 0x6a then
        self.coin_view:add(txid, vout_idx - 1, M.utxo_entry(
          out.value, out.script_pubkey, height, is_coinbase
        ))
      end
    end
  end

  -- Verify coinbase value
  local subsidy = consensus.get_block_subsidy(height)
  local coinbase_value = 0
  for _, out in ipairs(block.transactions[1].outputs) do
    coinbase_value = coinbase_value + out.value
  end
  assert(coinbase_value <= subsidy + total_fees,
    string.format("Coinbase value too high: %d > %d + %d",
      coinbase_value, subsidy, total_fees))

  -- Flush UTXO changes to database
  self.coin_view:flush()

  -- Update chain tip
  self.tip_hash = block_hash
  self.tip_height = height
  self.storage.set_chain_tip(block_hash, height, true)

  return true, total_fees
end

--------------------------------------------------------------------------------
-- Disconnect Block (for chain reorganization)
--------------------------------------------------------------------------------

function ChainState:disconnect_block(block, height, block_hash, undo_data)
  -- Process transactions in reverse order
  for tx_idx = #block.transactions, 1, -1 do
    local tx = block.transactions[tx_idx]
    local txid = validation.compute_txid(tx)
    local is_coinbase = (tx_idx == 1)

    -- Remove outputs from UTXO set
    for vout_idx = 1, #tx.outputs do
      local out = tx.outputs[vout_idx]
      -- Only spend if we added it (not OP_RETURN)
      if #out.script_pubkey == 0 or out.script_pubkey:byte(1) ~= 0x6a then
        self.coin_view:spend(txid, vout_idx - 1)
      end
    end

    -- Restore spent inputs (requires undo data)
    if not is_coinbase and undo_data then
      -- undo_data should contain the spent UTXOs for this transaction
      local tx_undo = undo_data[tx_idx]
      if tx_undo then
        for inp_idx, inp in ipairs(tx.inputs) do
          local spent_utxo = tx_undo[inp_idx]
          if spent_utxo then
            self.coin_view:add(inp.prev_out.hash, inp.prev_out.index, spent_utxo)
          end
        end
      end
    end
  end

  self.coin_view:flush()
  self.tip_height = height - 1
  -- tip_hash would need to be set to the previous block's hash
  -- (caller should provide this)
end

--------------------------------------------------------------------------------
-- UTXO Statistics
--------------------------------------------------------------------------------

function ChainState:get_utxo_stats()
  -- Iterate over the UTXO set and compute statistics
  local count = 0
  local total_value = 0
  local iter = self.storage.iterator(storage_mod.CF.UTXO)
  iter.seek_to_first()
  while iter.valid() do
    local data = iter.value()
    local entry = M.deserialize_utxo_entry(data)
    count = count + 1
    total_value = total_value + entry.value
    iter.next()
  end
  iter.destroy()
  return {
    utxo_count = count,
    total_value = total_value,
    total_btc = total_value / consensus.COIN,
  }
end

return M
