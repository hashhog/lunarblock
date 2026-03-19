-- Index Manager for lunarblock
-- Coordinates optional indexes (txindex, block filter index) and handles
-- background building using coroutines to avoid blocking the main event loop.
--
-- Reference: Bitcoin Core index/base.cpp

local txindex = require("lunarblock.txindex")
local blockfilter = require("lunarblock.blockfilter")

local M = {}

--- Create a new index manager
-- @param db table: storage database object
-- @param opts table: options {txindex=bool, blockfilterindex=bool}
-- @return table: index manager object
function M.new(db, opts)
  opts = opts or {}

  local manager = {
    _db = db,
    _txindex = txindex.new(db, opts.txindex or false),
    _filterindex = blockfilter.new_index(db, opts.blockfilterindex or false),
    _build_coroutines = {},  -- active building coroutines
    _synced = false,
  }

  --- Get the transaction index
  -- @return table: txindex object
  function manager.get_txindex()
    return manager._txindex
  end

  --- Get the block filter index
  -- @return table: blockfilter index object
  function manager.get_filterindex()
    return manager._filterindex
  end

  --- Enable/disable transaction index
  -- @param enabled boolean: new state
  function manager.set_txindex_enabled(enabled)
    manager._txindex.set_enabled(enabled)
  end

  --- Enable/disable block filter index
  -- @param enabled boolean: new state
  function manager.set_filterindex_enabled(enabled)
    manager._filterindex.set_enabled(enabled)
  end

  --- Handle block connection (called during normal operation)
  -- @param block table: block object
  -- @param block_hash hash256: block hash
  -- @param height number: block height
  -- @param file_num number: block file number (for txindex)
  -- @param block_pos number: position in block file (for txindex)
  -- @param undo_data table: spent outputs (for blockfilter)
  function manager.connect_block(block, block_hash, height, file_num, block_pos, undo_data)
    -- Update txindex
    if manager._txindex.is_enabled() then
      manager._txindex.connect_block(block, height, file_num, block_pos)
    end

    -- Update filter index
    if manager._filterindex.is_enabled() then
      manager._filterindex.connect_block(block, block_hash, height, undo_data)
    end
  end

  --- Handle block disconnection (reorg)
  -- @param block table: block object
  -- @param block_hash hash256: block hash
  -- @param height number: block height
  function manager.disconnect_block(block, block_hash, height)
    -- Update txindex
    if manager._txindex.is_enabled() then
      manager._txindex.disconnect_block(block, height)
    end

    -- Update filter index
    if manager._filterindex.is_enabled() then
      manager._filterindex.disconnect_block(block_hash, height)
    end
  end

  --- Start background index building
  -- @param get_block_at_height function: retrieves block data
  --   For txindex: function(height) -> block, file_num, block_pos
  --   For filterindex: function(height) -> block, block_hash, undo_data
  -- @param chain_height number: current chain height
  -- @param yield_interval number: blocks between yields (default 100)
  function manager.start_building(get_block_at_height, chain_height, yield_interval)
    yield_interval = yield_interval or 100

    -- Start txindex building if needed
    if manager._txindex.is_enabled() then
      local txindex_height = manager._txindex.get_best_height()
      if txindex_height < chain_height then
        local coro = manager._txindex.build_async(
          get_block_at_height,
          chain_height,
          yield_interval
        )
        manager._build_coroutines.txindex = {
          coroutine = coro,
          name = "txindex",
          start_height = txindex_height + 1,
        }
      end
    end

    -- Start filter index building if needed
    if manager._filterindex.is_enabled() then
      local filter_height = manager._filterindex.get_best_height()
      if filter_height < chain_height then
        local coro = manager._filterindex.build_async(
          get_block_at_height,
          chain_height,
          yield_interval
        )
        manager._build_coroutines.filterindex = {
          coroutine = coro,
          name = "filterindex",
          start_height = filter_height + 1,
        }
      end
    end
  end

  --- Tick background building - call this from the main event loop
  -- Resumes each building coroutine once per tick
  -- @return table: status of each index build {name, progress, total, complete}
  function manager.tick()
    local results = {}

    for key, build_info in pairs(manager._build_coroutines) do
      local coro = build_info.coroutine
      if coroutine.status(coro) ~= "dead" then
        local success, result = coroutine.resume(coro)
        if success and result then
          if result.type == "progress" then
            results[#results + 1] = {
              name = build_info.name,
              current = result.current,
              total = result.total,
              complete = false,
            }
          elseif result.type == "complete" then
            results[#results + 1] = {
              name = build_info.name,
              current = result.indexed_height,
              total = result.indexed_height,
              complete = true,
            }
            manager._build_coroutines[key] = nil
          end
        elseif not success then
          -- Coroutine errored
          results[#results + 1] = {
            name = build_info.name,
            error = result,
            complete = true,
          }
          manager._build_coroutines[key] = nil
        end
      else
        -- Coroutine finished
        manager._build_coroutines[key] = nil
      end
    end

    -- Update synced state
    local all_synced = true
    if manager._txindex.is_enabled() and not manager._txindex.is_synced() then
      all_synced = false
    end
    if manager._filterindex.is_enabled() and not manager._filterindex.is_synced() then
      all_synced = false
    end
    manager._synced = all_synced

    return results
  end

  --- Check if any indexes are currently building
  -- @return boolean: true if building
  function manager.is_building()
    return next(manager._build_coroutines) ~= nil
  end

  --- Check if all enabled indexes are synced
  -- @return boolean: true if all synced
  function manager.is_synced()
    return manager._synced
  end

  --- Get overall index status
  -- @return table: {txindex={...}, filterindex={...}, building=bool, synced=bool}
  function manager.get_stats()
    return {
      txindex = manager._txindex.get_stats(),
      filterindex = manager._filterindex.get_stats(),
      building = manager.is_building(),
      synced = manager.is_synced(),
    }
  end

  --- Lookup a transaction by txid
  -- @param txid hash256: transaction id
  -- @return table|nil: {file_num, block_pos, tx_offset} or nil
  function manager.lookup_tx(txid)
    return manager._txindex.lookup_tx(txid)
  end

  --- Get block filter by hash
  -- @param block_hash hash256: block hash
  -- @return table|nil: {filter, filter_hash, filter_header} or nil
  function manager.get_filter(block_hash)
    return manager._filterindex.get_filter(block_hash)
  end

  --- Get block filter by height
  -- @param height number: block height
  -- @return table|nil: filter info or nil
  function manager.get_filter_by_height(height)
    return manager._filterindex.get_filter_by_height(height)
  end

  --- Get a range of filter headers
  -- @param start_height number: start height
  -- @param stop_height number: stop height
  -- @return table: list of filter headers
  function manager.get_filter_headers(start_height, stop_height)
    return manager._filterindex.get_filter_headers(start_height, stop_height)
  end

  --- Check if an element matches a block's filter
  -- @param block_hash hash256: block hash
  -- @param element string: element to check
  -- @return boolean|nil: true if might match, nil if filter not found
  function manager.match_filter(block_hash, element)
    local filter_info = manager._filterindex.get_filter(block_hash)
    if not filter_info then
      return nil, "filter not found"
    end
    return blockfilter.match_gcs_filter(
      filter_info.filter,
      element,
      block_hash,
      blockfilter.BASIC_FILTER_P,
      blockfilter.BASIC_FILTER_M
    )
  end

  return manager
end

return M
