-- Transaction Index for lunarblock
-- Implements optional -txindex functionality to enable fast lookup of
-- confirmed transactions by txid without requiring a blockhash hint.
--
-- Reference: Bitcoin Core index/txindex.cpp
--
-- Index format:
--   key: txid (32 bytes)
--   value: file_num (4B LE) + block_pos (4B LE) + tx_offset (4B LE)
--
-- The index stores the disk location where the transaction can be found:
--   - file_num: which blk*.dat file contains the block
--   - block_pos: byte offset of the block data in the file
--   - tx_offset: byte offset of the transaction within the block (after header)

local serialize = require("lunarblock.serialize")
local storage = require("lunarblock.storage")
local validation = require("lunarblock.validation")
local types = require("lunarblock.types")

local M = {}

-- Tx index entry serialization format: 12 bytes
-- [file_num: 4B LE][block_pos: 4B LE][tx_offset: 4B LE]

local function serialize_tx_pos(file_num, block_pos, tx_offset)
  local w = serialize.buffer_writer()
  w.write_u32le(file_num)
  w.write_u32le(block_pos)
  w.write_u32le(tx_offset)
  return w.result()
end

local function deserialize_tx_pos(data)
  if not data or #data < 12 then
    return nil
  end
  local r = serialize.buffer_reader(data)
  return {
    file_num = r.read_u32le(),
    block_pos = r.read_u32le(),
    tx_offset = r.read_u32le(),
  }
end

--- Create a new transaction index instance
-- @param db table: storage database object
-- @param enabled boolean: whether txindex is enabled
-- @return table: txindex object
function M.new(db, enabled)
  local txindex = {
    _db = db,
    _enabled = enabled or false,
    _synced = false,
    _best_height = -1,
  }

  --- Check if tx index is enabled
  -- @return boolean: true if enabled
  function txindex.is_enabled()
    return txindex._enabled
  end

  --- Set enabled state
  -- @param enabled boolean: new enabled state
  function txindex.set_enabled(enabled)
    txindex._enabled = enabled
  end

  --- Check if tx index is synced with chain
  -- @return boolean: true if synced
  function txindex.is_synced()
    return txindex._synced
  end

  --- Get the best indexed height
  -- @return number: best indexed height (-1 if none)
  function txindex.get_best_height()
    local data = txindex._db.get(storage.CF.META, "txindex_height")
    if data and #data >= 4 then
      local r = serialize.buffer_reader(data)
      return r.read_u32le()
    end
    return -1
  end

  --- Set the best indexed height
  -- @param height number: best height
  function txindex.set_best_height(height)
    local w = serialize.buffer_writer()
    w.write_u32le(height)
    txindex._db.put(storage.CF.META, "txindex_height", w.result())
    txindex._best_height = height
  end

  --- Index a single transaction
  -- @param txid hash256: transaction id
  -- @param file_num number: block file number
  -- @param block_pos number: position of block in file
  -- @param tx_offset number: offset of tx within block data
  function txindex.put_tx(txid, file_num, block_pos, tx_offset)
    if not txindex._enabled then return end
    local key = txid.bytes
    local value = serialize_tx_pos(file_num, block_pos, tx_offset)
    txindex._db.put(storage.CF.TX_INDEX, key, value)
  end

  --- Remove a transaction from the index
  -- @param txid hash256: transaction id
  function txindex.delete_tx(txid)
    if not txindex._enabled then return end
    txindex._db.delete(storage.CF.TX_INDEX, txid.bytes)
  end

  --- Look up a transaction's disk location
  -- @param txid hash256: transaction id
  -- @return table|nil: {file_num, block_pos, tx_offset} or nil if not found
  function txindex.lookup_tx(txid)
    if not txindex._enabled then
      return nil, "txindex not enabled"
    end
    local key = txid.bytes
    local data = txindex._db.get(storage.CF.TX_INDEX, key)
    if not data then
      return nil, "transaction not found"
    end
    return deserialize_tx_pos(data)
  end

  --- Index all transactions in a block during connect_block
  -- @param block table: block object with transactions
  -- @param height number: block height
  -- @param file_num number: block file number
  -- @param block_pos number: position of block data in file
  function txindex.connect_block(block, height, file_num, block_pos)
    if not txindex._enabled then return end

    -- Skip genesis block (outputs not spendable, following Bitcoin Core)
    if height == 0 then
      txindex.set_best_height(0)
      return
    end

    local batch = txindex._db.batch()

    -- Calculate the offset of each transaction within the block
    -- Block format: [header 80B] [tx_count varint] [tx1] [tx2] ...
    -- We need to track cumulative offset after the tx count
    local tx_count = #block.transactions
    local tx_count_size = 1
    if tx_count >= 0xFD and tx_count <= 0xFFFF then
      tx_count_size = 3
    elseif tx_count >= 0x10000 then
      tx_count_size = 5
    end

    -- Start offset after header (80 bytes) + tx_count varint
    local current_offset = 80 + tx_count_size

    for _, tx in ipairs(block.transactions) do
      local txid = validation.compute_txid(tx)
      local value = serialize_tx_pos(file_num, block_pos, current_offset)
      batch.put(storage.CF.TX_INDEX, txid.bytes, value)

      -- Advance offset by serialized transaction size
      local tx_data = serialize.serialize_transaction(tx, true)
      current_offset = current_offset + #tx_data
    end

    -- Update best height
    local w = serialize.buffer_writer()
    w.write_u32le(height)
    batch.put(storage.CF.META, "txindex_height", w.result())

    batch.write()
    batch.destroy()

    txindex._best_height = height
  end

  --- Remove all transactions in a block during disconnect_block (reorg)
  -- @param block table: block object with transactions
  -- @param height number: block height being disconnected
  function txindex.disconnect_block(block, height)
    if not txindex._enabled then return end

    local batch = txindex._db.batch()

    for _, tx in ipairs(block.transactions) do
      local txid = validation.compute_txid(tx)
      batch.delete(storage.CF.TX_INDEX, txid.bytes)
    end

    -- Update best height to previous block
    local new_height = height - 1
    local w = serialize.buffer_writer()
    w.write_u32le(new_height)
    batch.put(storage.CF.META, "txindex_height", w.result())

    batch.write()
    batch.destroy()

    txindex._best_height = new_height
  end

  --- Build the index from scratch using a block iterator
  -- Uses coroutines to yield periodically and avoid blocking
  -- @param get_block_at_height function: function(height) -> block, file_num, block_pos
  -- @param chain_height number: current chain height
  -- @param yield_interval number: how many blocks between yields (default 100)
  -- @return coroutine: the building coroutine
  function txindex.build_async(get_block_at_height, chain_height, yield_interval)
    yield_interval = yield_interval or 100

    return coroutine.create(function()
      local start_height = txindex.get_best_height() + 1

      for height = start_height, chain_height do
        local block, file_num, block_pos = get_block_at_height(height)
        if block then
          txindex.connect_block(block, height, file_num, block_pos)
        end

        -- Yield periodically to avoid blocking
        if height % yield_interval == 0 then
          coroutine.yield({
            type = "progress",
            current = height,
            total = chain_height,
          })
        end
      end

      txindex._synced = true
      coroutine.yield({
        type = "complete",
        indexed_height = chain_height,
      })
    end)
  end

  --- Get index statistics
  -- @return table: {enabled, synced, best_height}
  function txindex.get_stats()
    return {
      enabled = txindex._enabled,
      synced = txindex._synced,
      best_height = txindex.get_best_height(),
    }
  end

  -- Initialize best height from db
  txindex._best_height = txindex.get_best_height()

  return txindex
end

-- Export serialization functions for testing
M.serialize_tx_pos = serialize_tx_pos
M.deserialize_tx_pos = deserialize_tx_pos

return M
