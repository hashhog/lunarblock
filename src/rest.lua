--- REST API server for lightweight clients
-- Provides read-only access to blocks, transactions, UTXO, and mempool data.
-- No authentication required (unlike JSON-RPC).

local socket = require("socket")
local cjson = require("cjson")
local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local validation = require("lunarblock.validation")
local consensus = require("lunarblock.consensus")
local script_mod = require("lunarblock.script")
local address_mod = require("lunarblock.address")
local bit = require("bit")

local M = {}

--------------------------------------------------------------------------------
-- Constants
--------------------------------------------------------------------------------

M.MAX_GETUTXOS_OUTPOINTS = 15   -- Max outpoints per getutxos request
M.MAX_HEADERS_COUNT = 2000      -- Max headers per request
M.DEFAULT_HEADERS_COUNT = 5     -- Default ?count= when omitted (Core parity, rest.cpp:518)

-- BIP-157 filter type names → numeric type id.
-- Bitcoin Core: BlockFilterTypeByName ("basic" → BlockFilterType::BASIC = 0).
M.FILTER_TYPE_BY_NAME = {
  basic = 0,
}

--------------------------------------------------------------------------------
-- Response Format Types
--------------------------------------------------------------------------------

M.FORMAT = {
  JSON = "json",
  BIN = "bin",
  HEX = "hex",
}

--------------------------------------------------------------------------------
-- Hex Encoding/Decoding
--------------------------------------------------------------------------------

local function hex_encode(data)
  local hex = {}
  for i = 1, #data do
    hex[i] = string.format("%02x", data:byte(i))
  end
  return table.concat(hex)
end

local function hex_decode(hex_str)
  local bytes = {}
  for i = 1, #hex_str, 2 do
    bytes[#bytes + 1] = string.char(tonumber(hex_str:sub(i, i + 1), 16))
  end
  return table.concat(bytes)
end

--------------------------------------------------------------------------------
-- Script Disassembly
--------------------------------------------------------------------------------

local function disassemble_script(script_bytes)
  if #script_bytes == 0 then
    return ""
  end
  local ok, ops = pcall(script_mod.parse_script, script_bytes)
  if not ok then
    return "[error]"
  end
  local parts = {}
  for _, op in ipairs(ops) do
    local opcode = op.opcode
    local data = op.data
    if data then
      parts[#parts + 1] = hex_encode(data)
    elseif opcode == 0x00 then
      parts[#parts + 1] = "OP_0"
    elseif opcode >= 0x01 and opcode <= 0x4b then
      parts[#parts + 1] = "OP_PUSHBYTES_" .. opcode
    elseif script_mod.OP_NAMES[opcode] then
      parts[#parts + 1] = script_mod.OP_NAMES[opcode]
    else
      parts[#parts + 1] = string.format("0x%02x", opcode)
    end
  end
  return table.concat(parts, " ")
end

--------------------------------------------------------------------------------
-- ScriptPubKey Decoding
--------------------------------------------------------------------------------

local function decode_script_pubkey(script_pubkey, network)
  local result = {
    asm = disassemble_script(script_pubkey),
    hex = hex_encode(script_pubkey),
  }

  local script_type, program = script_mod.classify_script(script_pubkey)

  local type_map = {
    p2pkh = "pubkeyhash",
    p2sh = "scripthash",
    p2wpkh = "witness_v0_keyhash",
    p2wsh = "witness_v0_scripthash",
    p2tr = "witness_v1_taproot",
    nulldata = "nulldata",
    nonstandard = "nonstandard",
  }
  result.type = type_map[script_type] or "nonstandard"

  -- P2PK detection
  if #script_pubkey == 35 and script_pubkey:byte(1) == 0x21 and script_pubkey:byte(35) == 0xac then
    result.type = "pubkey"
  elseif #script_pubkey == 67 and script_pubkey:byte(1) == 0x41 and script_pubkey:byte(67) == 0xac then
    result.type = "pubkey"
  end

  -- Multisig detection
  if #script_pubkey >= 3 and script_pubkey:byte(#script_pubkey) == 0xae then
    local first = script_pubkey:byte(1)
    if first >= 0x51 and first <= 0x60 then
      result.type = "multisig"
    end
  end

  -- Extract address
  local network_name = network and network.name or "mainnet"
  local hrp = address_mod.BECH32_HRP[network_name] or "bc"

  if script_type == "p2pkh" and program then
    local version = network_name == "mainnet" and 0x00 or 0x6F
    result.address = address_mod.base58check_encode(version, program)
  elseif script_type == "p2sh" and program then
    local version = network_name == "mainnet" and 0x05 or 0xC4
    result.address = address_mod.base58check_encode(version, program)
  elseif script_type == "p2wpkh" and program then
    result.address = address_mod.segwit_encode(hrp, 0, program)
  elseif script_type == "p2wsh" and program then
    result.address = address_mod.segwit_encode(hrp, 0, program)
  elseif script_type == "p2tr" and program then
    result.address = address_mod.segwit_encode(hrp, 1, program)
  end

  return result
end

--------------------------------------------------------------------------------
-- URL Parsing
--------------------------------------------------------------------------------

--- Parse format suffix from path (e.g., ".json", ".bin", ".hex")
-- @param path string: URL path like "/rest/block/abc.json"
-- @return string, string: path without suffix, format type
local function parse_format(path)
  -- Remove query string if present
  local base_path = path:match("^([^?]+)")
  if not base_path then
    base_path = path
  end

  local path_without_suffix, suffix = base_path:match("^(.+)%.(%w+)$")
  if suffix then
    local format_map = {
      json = M.FORMAT.JSON,
      bin = M.FORMAT.BIN,
      hex = M.FORMAT.HEX,
    }
    local format = format_map[suffix:lower()]
    if format then
      return path_without_suffix, format
    end
  end

  -- No recognized format suffix
  return base_path, nil
end

--- Parse query parameters from URL
-- @param url string: Full URL with potential query string
-- @return table: key-value pairs of query parameters
local function parse_query(url)
  local params = {}
  local query = url:match("%?(.+)$")
  if query then
    for pair in query:gmatch("[^&]+") do
      local key, value = pair:match("([^=]+)=?(.*)")
      if key then
        params[key] = value or ""
      end
    end
  end
  return params
end

--------------------------------------------------------------------------------
-- HTTP Response Building
--------------------------------------------------------------------------------

local function build_response(status, body, content_type)
  content_type = content_type or "text/plain"
  local status_text = {
    [200] = "OK",
    [400] = "Bad Request",
    [404] = "Not Found",
    [500] = "Internal Server Error",
    [503] = "Service Unavailable",
  }

  local response = string.format(
    "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
    status, status_text[status] or "Unknown", content_type, #body, body
  )
  return response
end

local function error_response(status, message)
  return build_response(status, message .. "\r\n", "text/plain")
end

local function json_response(data)
  return build_response(200, cjson.encode(data) .. "\n", "application/json")
end

local function bin_response(data)
  return build_response(200, data, "application/octet-stream")
end

local function hex_response(data)
  return build_response(200, hex_encode(data) .. "\n", "text/plain")
end

--------------------------------------------------------------------------------
-- Difficulty Calculation
--------------------------------------------------------------------------------

local function calculate_difficulty(bits_val)
  local nshift = bit.rshift(bits_val, 24)
  local mantissa = bit.band(bits_val, 0x00ffffff)
  if mantissa == 0 then
    return 0
  end

  local diff = 0x0000ffff / mantissa

  while nshift < 29 do
    diff = diff * 256.0
    nshift = nshift + 1
  end
  while nshift > 29 do
    diff = diff / 256.0
    nshift = nshift - 1
  end

  return diff
end

--------------------------------------------------------------------------------
-- Chaininfo Helpers (duplicated from rpc.lua to keep rest.lua dependency-free)
--
-- Bitcoin Core's rest_chaininfo (rest.cpp:716) just shells out to
-- getblockchaininfo().HandleRequest().  We can't do that here without dragging
-- the entire rpc.lua module (~6600 LOC) into rest.lua just for one helper, so
-- the chaininfo body is reproduced from rpc.lua's getblockchaininfo handler
-- (rpc.lua:819-920) plus the buried-softfork helper.  Keep this in sync if
-- you change the RPC shape.
--------------------------------------------------------------------------------

--- Convert compact bits to 64-char big-endian hex target string (Core format).
-- Mirrors rpc.lua bits_to_target_hex.
-- @param bits number: compact nBits
-- @return string: 64-char lowercase hex
local function bits_to_target_hex(bits)
  local target = consensus.bits_to_target(bits)
  local hex = {}
  for i = 1, 32 do
    hex[i] = string.format("%02x", target:byte(i))
  end
  return table.concat(hex)
end

--- Get median time of past 11 blocks.
-- Mirrors rpc.lua get_median_time_past.
-- @param storage table: Storage object
-- @param tip_hash hash256: Chain tip hash
-- @return number: Median timestamp
local function get_median_time_past(storage, tip_hash)
  if not storage or not tip_hash then
    return os.time()
  end

  local timestamps = {}
  local current_hash = tip_hash

  for _ = 1, 11 do
    local header = storage.get_header(current_hash)
    if not header then break end
    timestamps[#timestamps + 1] = header.timestamp
    current_hash = header.prev_hash
  end

  if #timestamps == 0 then
    return os.time()
  end

  table.sort(timestamps)
  -- Bitcoin Core: pbegin[(pend-pbegin)/2] (upper-middle for even n).
  -- Lua 1-indexed equivalent: floor(n/2)+1.
  local n = #timestamps
  return timestamps[math.floor(n / 2) + 1]
end

--- build_deployment_state: buried-softfork projection.
-- Mirrors rpc.lua build_deployment_state (rpc.lua:765-808).
-- @param tip_height number
-- @param net table: network params
-- @return table: deployments keyed by name
local function build_deployment_state(tip_height, net)
  local function buried_entry(activation_height)
    local h = activation_height or 0
    return {
      type                  = "buried",
      active                = tip_height >= h,
      height                = h,
      min_activation_height = h,
    }
  end

  local deployments = {}
  if net.bip34_height   then deployments.bip34   = buried_entry(net.bip34_height) end
  if net.bip65_height   then deployments.bip65   = buried_entry(net.bip65_height) end
  if net.bip66_height   then deployments.bip66   = buried_entry(net.bip66_height) end
  if net.csv_height     then deployments.csv     = buried_entry(net.csv_height) end
  if net.segwit_height  then deployments.segwit  = buried_entry(net.segwit_height) end
  if net.taproot_height then deployments.taproot = buried_entry(net.taproot_height) end

  -- testdummy: always buried-active (regtest test vehicle).
  deployments.testdummy = {
    type                  = "buried",
    active                = true,
    height                = 0,
    min_activation_height = 0,
  }

  return deployments
end

--------------------------------------------------------------------------------
-- REST Server Object
--------------------------------------------------------------------------------

local RESTServer = {}
RESTServer.__index = RESTServer

function M.new(config)
  local self = setmetatable({}, RESTServer)
  self.host = config.host or "127.0.0.1"
  self.port = config.rest_port or 8080
  self.server_socket = nil
  self.chain_state = config.chain_state
  self.mempool = config.mempool
  self.storage = config.storage
  self.network = config.network or consensus.networks.mainnet
  -- Optional pruner (lunarblock.prune); when present, exposed via /rest/chaininfo
  -- pruneheight / automatic_pruning fields exactly as getblockchaininfo does.
  self.pruner = config.pruner
  -- Optional index_manager (lunarblock.indexmanager); required for the
  -- /rest/blockfilter/* endpoints.  When nil, those endpoints return 400.
  -- We accept either index_manager (preferred) or filter_index directly.
  self.index_manager = config.index_manager
  self.filter_index = config.filter_index
    or (self.index_manager and self.index_manager.get_filterindex
        and self.index_manager.get_filterindex())
  self.running = false
  return self
end

--------------------------------------------------------------------------------
-- REST Endpoint Handlers
--------------------------------------------------------------------------------

--- GET /rest/block/<hash>.[json|bin|hex]
-- Returns block data
function RESTServer:handle_block(hash_hex, format, notxdetails)
  if #hash_hex ~= 64 then
    return error_response(400, "Invalid hash: " .. hash_hex)
  end

  if not self.storage then
    return error_response(500, "Storage not available")
  end

  local hash = types.hash256_from_hex(hash_hex)
  local block = self.storage.get_block(hash)
  if not block then
    return error_response(404, hash_hex .. " not found")
  end

  local block_data = serialize.serialize_block(block)

  if format == M.FORMAT.BIN then
    return bin_response(block_data)
  elseif format == M.FORMAT.HEX then
    return hex_response(block_data)
  elseif format == M.FORMAT.JSON then
    -- Build JSON response
    local block_height = nil

    -- Try to find block height
    if self.storage.iterator then
      local iter = self.storage.iterator("height")
      if iter then
        iter.seek_to_first()
        while iter.valid() do
          local v = iter.value()
          if v and #v == 32 and v == hash.bytes then
            local k = iter.key()
            block_height = k:byte(1) * 16777216 + k:byte(2) * 65536 + k:byte(3) * 256 + k:byte(4)
            break
          end
          iter.next()
        end
        iter.destroy()
      end
    end

    -- Calculate confirmations
    local confirmations = 1
    if block_height and self.chain_state and self.chain_state.tip_height then
      confirmations = self.chain_state.tip_height - block_height + 1
    end

    -- Calculate sizes
    local block_size = #block_data
    local stripped_size = #serialize.serialize_block_without_witness(block)
    local block_weight = stripped_size * 3 + block_size

    -- Build tx list
    local tx_list
    if notxdetails then
      -- Just txids
      tx_list = {}
      for _, tx in ipairs(block.transactions) do
        tx_list[#tx_list + 1] = types.hash256_hex(validation.compute_txid(tx))
      end
    else
      -- Full transactions
      tx_list = {}
      for i, tx in ipairs(block.transactions) do
        local txid = validation.compute_txid(tx)
        local wtxid = validation.compute_wtxid(tx)
        local tx_weight = validation.get_tx_weight(tx)
        local tx_size = #serialize.serialize_transaction(tx, true)
        local vsize = math.ceil(tx_weight / consensus.WITNESS_SCALE_FACTOR)

        -- Check if coinbase
        local is_coinbase = false
        local null_hash = string.rep("\0", 32)
        if #tx.inputs == 1 and tx.inputs[1].prev_out.hash.bytes == null_hash and
           tx.inputs[1].prev_out.index == 0xFFFFFFFF then
          is_coinbase = true
        end

        -- Build vin
        local vin = {}
        for j, inp in ipairs(tx.inputs) do
          local vin_entry = {}
          if is_coinbase and j == 1 then
            vin_entry.coinbase = hex_encode(inp.script_sig)
            vin_entry.sequence = inp.sequence
            if inp.witness and #inp.witness > 0 then
              vin_entry.txinwitness = {}
              for k, wit in ipairs(inp.witness) do
                vin_entry.txinwitness[k] = hex_encode(wit)
              end
            end
          else
            vin_entry.txid = types.hash256_hex(inp.prev_out.hash)
            vin_entry.vout = inp.prev_out.index
            vin_entry.scriptSig = {
              asm = disassemble_script(inp.script_sig),
              hex = hex_encode(inp.script_sig),
            }
            vin_entry.sequence = inp.sequence
            if inp.witness and #inp.witness > 0 then
              vin_entry.txinwitness = {}
              for k, wit in ipairs(inp.witness) do
                vin_entry.txinwitness[k] = hex_encode(wit)
              end
            end
          end
          vin[j] = vin_entry
        end

        -- Build vout
        local vout = {}
        for j, out in ipairs(tx.outputs) do
          vout[j] = {
            value = out.value / consensus.COIN,
            n = j - 1,
            scriptPubKey = decode_script_pubkey(out.script_pubkey, self.network),
          }
        end

        tx_list[i] = {
          txid = types.hash256_hex(txid),
          hash = types.hash256_hex(wtxid),
          version = tx.version,
          size = tx_size,
          vsize = vsize,
          weight = tx_weight,
          locktime = tx.locktime,
          vin = vin,
          vout = vout,
        }
      end
    end

    -- Get previous block hash
    local previousblockhash = nil
    local zero_hash = string.rep("\0", 32)
    if block.header.prev_hash.bytes ~= zero_hash then
      previousblockhash = types.hash256_hex(block.header.prev_hash)
    end

    -- Get next block hash
    local nextblockhash = nil
    if block_height and self.storage.get_hash_by_height then
      local next_hash = self.storage.get_hash_by_height(block_height + 1)
      if next_hash then
        nextblockhash = types.hash256_hex(next_hash)
      end
    end

    local result = {
      hash = hash_hex,
      confirmations = confirmations,
      size = block_size,
      strippedsize = stripped_size,
      weight = block_weight,
      height = block_height or 0,
      version = block.header.version,
      versionHex = string.format("%08x", block.header.version),
      merkleroot = types.hash256_hex(block.header.merkle_root),
      tx = tx_list,
      time = block.header.timestamp,
      nonce = block.header.nonce,
      bits = string.format("%08x", block.header.bits),
      difficulty = calculate_difficulty(block.header.bits),
      nTx = #block.transactions,
    }

    if previousblockhash then
      result.previousblockhash = previousblockhash
    end
    if nextblockhash then
      result.nextblockhash = nextblockhash
    end

    return json_response(result)
  else
    return error_response(400, "output format not found (available: .bin, .hex, .json)")
  end
end

--- GET /rest/tx/<txid>.[json|bin|hex]
-- Returns transaction data
function RESTServer:handle_tx(txid_hex, format)
  if #txid_hex ~= 64 then
    return error_response(400, "Invalid hash: " .. txid_hex)
  end

  local tx = nil
  local found_blockhash = nil
  local block_time = nil

  -- Check mempool first
  if self.mempool then
    local entry = self.mempool:get_entry(txid_hex)
    if entry then
      tx = entry.tx
    end
  end

  -- Check transaction index
  if not tx and self.storage and self.storage.get then
    local txid_bytes = types.hash256_from_hex(txid_hex)
    local tx_index_data = self.storage.get("tx_index", txid_bytes.bytes)
    if tx_index_data and #tx_index_data >= 32 then
      local index_block_hash = types.hash256(tx_index_data:sub(1, 32))
      found_blockhash = types.hash256_hex(index_block_hash)
      local block = self.storage.get_block(index_block_hash)
      if block then
        for _, btx in ipairs(block.transactions) do
          local btx_txid = types.hash256_hex(validation.compute_txid(btx))
          if btx_txid == txid_hex then
            tx = btx
            block_time = block.header.timestamp
            break
          end
        end
      end
    end
  end

  if not tx then
    return error_response(404, txid_hex .. " not found")
  end

  local tx_data = serialize.serialize_transaction(tx, true)

  if format == M.FORMAT.BIN then
    return bin_response(tx_data)
  elseif format == M.FORMAT.HEX then
    return hex_response(tx_data)
  elseif format == M.FORMAT.JSON then
    local txid = validation.compute_txid(tx)
    local wtxid = validation.compute_wtxid(tx)
    local weight = validation.get_tx_weight(tx)
    local size = #tx_data
    local vsize = math.ceil(weight / consensus.WITNESS_SCALE_FACTOR)

    -- Check if coinbase
    local is_coinbase = false
    local null_hash = string.rep("\0", 32)
    if #tx.inputs == 1 and tx.inputs[1].prev_out.hash.bytes == null_hash and
       tx.inputs[1].prev_out.index == 0xFFFFFFFF then
      is_coinbase = true
    end

    -- Build vin
    local vin = {}
    for i, inp in ipairs(tx.inputs) do
      local vin_entry = {}
      if is_coinbase and i == 1 then
        vin_entry.coinbase = hex_encode(inp.script_sig)
        vin_entry.sequence = inp.sequence
        if inp.witness and #inp.witness > 0 then
          vin_entry.txinwitness = {}
          for j, wit in ipairs(inp.witness) do
            vin_entry.txinwitness[j] = hex_encode(wit)
          end
        end
      else
        vin_entry.txid = types.hash256_hex(inp.prev_out.hash)
        vin_entry.vout = inp.prev_out.index
        vin_entry.scriptSig = {
          asm = disassemble_script(inp.script_sig),
          hex = hex_encode(inp.script_sig),
        }
        vin_entry.sequence = inp.sequence
        if inp.witness and #inp.witness > 0 then
          vin_entry.txinwitness = {}
          for j, wit in ipairs(inp.witness) do
            vin_entry.txinwitness[j] = hex_encode(wit)
          end
        end
      end
      vin[i] = vin_entry
    end

    -- Build vout
    local vout = {}
    for i, out in ipairs(tx.outputs) do
      vout[i] = {
        value = out.value / consensus.COIN,
        n = i - 1,
        scriptPubKey = decode_script_pubkey(out.script_pubkey, self.network),
      }
    end

    local result = {
      txid = types.hash256_hex(txid),
      hash = types.hash256_hex(wtxid),
      version = tx.version,
      size = size,
      vsize = vsize,
      weight = weight,
      locktime = tx.locktime,
      vin = vin,
      vout = vout,
    }

    if found_blockhash then
      result.blockhash = found_blockhash
      if block_time then
        result.time = block_time
        result.blocktime = block_time
      end
    end

    return json_response(result)
  else
    return error_response(400, "output format not found (available: .bin, .hex, .json)")
  end
end

--- GET /rest/headers/<count>/<hash>.[json|bin]
-- Returns block headers
function RESTServer:handle_headers(count_str, hash_hex, format)
  local count = tonumber(count_str)
  if not count or count < 1 or count > M.MAX_HEADERS_COUNT then
    return error_response(400, string.format("Header count is invalid or out of acceptable range (1-%d): %s",
      M.MAX_HEADERS_COUNT, count_str))
  end

  if #hash_hex ~= 64 then
    return error_response(400, "Invalid hash: " .. hash_hex)
  end

  if not self.storage then
    return error_response(500, "Storage not available")
  end

  local hash = types.hash256_from_hex(hash_hex)
  local headers = {}

  -- Get headers starting from hash
  local current_hash = hash
  for _ = 1, count do
    local header = self.storage.get_header(current_hash)
    if not header then break end
    headers[#headers + 1] = header

    -- Get next header (need to find it via height index)
    local block_height = nil
    if self.storage.iterator then
      local iter = self.storage.iterator("height")
      if iter then
        iter.seek_to_first()
        while iter.valid() do
          local v = iter.value()
          if v and #v == 32 and v == current_hash.bytes then
            local k = iter.key()
            block_height = k:byte(1) * 16777216 + k:byte(2) * 65536 + k:byte(3) * 256 + k:byte(4)
            break
          end
          iter.next()
        end
        iter.destroy()
      end
    end

    if block_height and self.storage.get_hash_by_height then
      local next_hash = self.storage.get_hash_by_height(block_height + 1)
      if next_hash then
        current_hash = next_hash
      else
        break
      end
    else
      break
    end
  end

  if #headers == 0 then
    return error_response(404, hash_hex .. " not found")
  end

  if format == M.FORMAT.BIN then
    local w = serialize.buffer_writer()
    for _, header in ipairs(headers) do
      w.write_i32le(header.version)
      w.write_hash256(header.prev_hash)
      w.write_hash256(header.merkle_root)
      w.write_u32le(header.timestamp)
      w.write_u32le(header.bits)
      w.write_u32le(header.nonce)
    end
    return bin_response(w.result())
  elseif format == M.FORMAT.HEX then
    local w = serialize.buffer_writer()
    for _, header in ipairs(headers) do
      w.write_i32le(header.version)
      w.write_hash256(header.prev_hash)
      w.write_hash256(header.merkle_root)
      w.write_u32le(header.timestamp)
      w.write_u32le(header.bits)
      w.write_u32le(header.nonce)
    end
    return hex_response(w.result())
  elseif format == M.FORMAT.JSON then
    local json_headers = {}
    for _, header in ipairs(headers) do
      json_headers[#json_headers + 1] = {
        version = header.version,
        previousblockhash = types.hash256_hex(header.prev_hash),
        merkleroot = types.hash256_hex(header.merkle_root),
        time = header.timestamp,
        bits = string.format("%08x", header.bits),
        nonce = header.nonce,
        difficulty = calculate_difficulty(header.bits),
      }
    end
    return json_response(json_headers)
  else
    return error_response(400, "output format not found (available: .bin, .hex, .json)")
  end
end

--- GET /rest/blockhashbyheight/<height>.[json|bin|hex]
-- Returns block hash at height
function RESTServer:handle_blockhashbyheight(height_str, format)
  local height = tonumber(height_str)
  if not height or height < 0 then
    return error_response(400, "Invalid height: " .. height_str)
  end

  if not self.storage then
    return error_response(500, "Storage not available")
  end

  -- Check if height is beyond tip
  local tip_height = self.chain_state and self.chain_state.tip_height or 0
  if height > tip_height then
    return error_response(404, "Block height out of range")
  end

  local hash = self.storage.get_hash_by_height(height)
  if not hash then
    return error_response(404, "Block not found at height " .. height)
  end

  if format == M.FORMAT.BIN then
    return bin_response(hash.bytes)
  elseif format == M.FORMAT.HEX then
    return build_response(200, types.hash256_hex(hash) .. "\n", "text/plain")
  elseif format == M.FORMAT.JSON then
    return json_response({blockhash = types.hash256_hex(hash)})
  else
    return error_response(400, "output format not found (available: .bin, .hex, .json)")
  end
end

--- GET /rest/getutxos/<checkmempool>/<txid>-<n>/....[json|bin]
-- Check UTXO existence
function RESTServer:handle_getutxos(path_parts, format)
  if not self.storage then
    return error_response(500, "Storage not available")
  end

  local check_mempool = false
  local outpoints = {}

  for _, part in ipairs(path_parts) do
    if part == "checkmempool" then
      check_mempool = true
    elseif part ~= "" then
      local txid_str, index_str = part:match("^([0-9a-fA-F]+)%-(%d+)$")
      if not txid_str or #txid_str ~= 64 then
        return error_response(400, "Parse error")
      end
      local index = tonumber(index_str)
      if not index then
        return error_response(400, "Parse error")
      end
      outpoints[#outpoints + 1] = {
        txid = types.hash256_from_hex(txid_str),
        index = index,
      }
    end
  end

  if #outpoints == 0 then
    return error_response(400, "Error: empty request")
  end

  if #outpoints > M.MAX_GETUTXOS_OUTPOINTS then
    return error_response(400, string.format("Error: max outpoints exceeded (max: %d, tried: %d)",
      M.MAX_GETUTXOS_OUTPOINTS, #outpoints))
  end

  -- Check UTXO existence
  local hits = {}
  local utxos = {}
  local bitmap = {}
  local bitmap_str = ""

  for i, op in ipairs(outpoints) do
    local found = false
    local utxo_entry = nil

    -- Build outpoint key
    local outpoint_key = op.txid.bytes .. string.char(
      bit.band(op.index, 0xFF),
      bit.band(bit.rshift(op.index, 8), 0xFF),
      bit.band(bit.rshift(op.index, 16), 0xFF),
      bit.band(bit.rshift(op.index, 24), 0xFF)
    )

    -- Check mempool if requested
    if check_mempool and self.mempool then
      -- Check if spent in mempool
      local txid_hex = types.hash256_hex(op.txid)
      local spent = false
      for _, entry in pairs(self.mempool.entries or {}) do
        for _, inp in ipairs(entry.tx.inputs) do
          if types.hash256_hex(inp.prev_out.hash) == txid_hex and inp.prev_out.index == op.index then
            spent = true
            break
          end
        end
        if spent then break end
      end
      if spent then
        hits[i] = false
        bitmap_str = bitmap_str .. "0"
        goto continue
      end
    end

    -- Check UTXO set
    if self.storage.get then
      local utxo_data = self.storage.get("utxo", outpoint_key)
      if utxo_data then
        found = true
        -- Parse UTXO entry: height (4 bytes) + coinbase (1 byte) + value (8 bytes) + script
        local r = serialize.buffer_reader(utxo_data)
        local height = r.read_u32le()
        local is_coinbase = r.read_u8() == 1
        local value = r.read_u64le()
        local script_len = r.remaining()
        local script_pubkey = r.read_bytes(script_len)

        utxo_entry = {
          height = height,
          value = value,
          script_pubkey = script_pubkey,
          is_coinbase = is_coinbase,
        }
      end
    end

    hits[i] = found
    bitmap_str = bitmap_str .. (found and "1" or "0")
    if found then
      utxos[#utxos + 1] = utxo_entry
    end

    ::continue::
  end

  -- Build bitmap bytes
  local bitmap_bytes = {}
  for i = 1, #outpoints do
    local byte_idx = math.floor((i - 1) / 8) + 1
    local bit_idx = (i - 1) % 8
    bitmap_bytes[byte_idx] = (bitmap_bytes[byte_idx] or 0) + (hits[i] and 1 or 0) * (2 ^ bit_idx)
  end

  local bitmap_data = ""
  for i = 1, math.ceil(#outpoints / 8) do
    bitmap_data = bitmap_data .. string.char(bitmap_bytes[i] or 0)
  end

  -- Get chain height and hash
  local active_height = self.chain_state and self.chain_state.tip_height or 0
  local active_hash = self.chain_state and self.chain_state.tip_hash or types.hash256_zero()

  if format == M.FORMAT.BIN then
    local w = serialize.buffer_writer()
    w.write_u32le(active_height)
    w.write_hash256(active_hash)
    w.write_bytes(bitmap_data)
    -- Write UTXOs
    w.write_varint(#utxos)
    for _, utxo in ipairs(utxos) do
      w.write_u32le(0)  -- nTxVerDummy
      w.write_u32le(utxo.height)
      w.write_u64le(utxo.value)
      w.write_varstr(utxo.script_pubkey)
    end
    return bin_response(w.result())
  elseif format == M.FORMAT.HEX then
    local w = serialize.buffer_writer()
    w.write_u32le(active_height)
    w.write_hash256(active_hash)
    w.write_bytes(bitmap_data)
    w.write_varint(#utxos)
    for _, utxo in ipairs(utxos) do
      w.write_u32le(0)
      w.write_u32le(utxo.height)
      w.write_u64le(utxo.value)
      w.write_varstr(utxo.script_pubkey)
    end
    return hex_response(w.result())
  elseif format == M.FORMAT.JSON then
    local utxos_json = {}
    for _, utxo in ipairs(utxos) do
      utxos_json[#utxos_json + 1] = {
        height = utxo.height,
        value = utxo.value / consensus.COIN,
        scriptPubKey = decode_script_pubkey(utxo.script_pubkey, self.network),
      }
    end
    return json_response({
      chainHeight = active_height,
      chaintipHash = types.hash256_hex(active_hash),
      bitmap = bitmap_str,
      utxos = utxos_json,
    })
  else
    return error_response(400, "output format not found (available: .bin, .hex, .json)")
  end
end

--- GET /rest/mempool/contents.json
-- Returns mempool contents
function RESTServer:handle_mempool_contents(query_params)
  if not self.mempool then
    return error_response(404, "Mempool disabled or instance not found")
  end

  local verbose = query_params.verbose ~= "false"

  if verbose then
    local result = {}
    for txid_hex, entry in pairs(self.mempool.entries or {}) do
      result[txid_hex] = {
        vsize = entry.vsize,
        weight = entry.weight,
        fee = entry.fee / consensus.COIN,
        time = entry.time,
        height = entry.height,
        descendantcount = entry.descendant_count or 1,
        descendantsize = entry.descendant_size or entry.vsize,
        ancestorcount = entry.ancestor_count or 1,
        ancestorsize = entry.ancestor_size or entry.vsize,
      }
    end
    return json_response(result)
  else
    local txids = {}
    for txid_hex, _ in pairs(self.mempool.entries or {}) do
      txids[#txids + 1] = txid_hex
    end
    return json_response(txids)
  end
end

--- GET /rest/mempool/info.json
-- Returns mempool statistics
function RESTServer:handle_mempool_info()
  if not self.mempool then
    return error_response(404, "Mempool disabled or instance not found")
  end

  local info = self.mempool:get_info()

  -- Calculate total fees
  local total_fee = 0
  for _, entry in pairs(self.mempool.entries or {}) do
    total_fee = total_fee + (entry.fee or 0)
  end

  local mempool_min_fee = info.mempoolminfee or 1000
  local min_relay_fee = self.mempool.min_relay_fee or 1000

  return json_response({
    loaded = true,
    size = info.size,
    bytes = info.bytes,
    usage = info.usage,
    total_fee = total_fee / consensus.COIN,
    maxmempool = info.maxmempool,
    mempoolminfee = mempool_min_fee / 100000000,
    minrelaytxfee = min_relay_fee / 100000000,
  })
end

--- GET /rest/chaininfo.json
-- Returns blockchain state.  Mirrors Bitcoin Core's rest_chaininfo
-- (rest.cpp:716), which just delegates to getblockchaininfo().HandleRequest().
-- We reproduce the rpc.lua getblockchaininfo handler shape here (rpc.lua:819).
function RESTServer:handle_chaininfo(format)
  if format ~= M.FORMAT.JSON then
    return error_response(400, "output format not found (available: json)")
  end

  local tip_height = 0
  local tip_hash = types.hash256_zero()
  local header_height = 0
  local difficulty = 1.0
  local mediantime = os.time()
  local current_bits = self.network.pow_limit_bits

  if self.chain_state then
    tip_height = self.chain_state.tip_height or 0
    tip_hash = self.chain_state.tip_hash or types.hash256_zero()
    header_height = self.chain_state.header_tip_height or tip_height

    if self.storage then
      local header = self.storage.get_header(tip_hash)
      if header then
        current_bits = header.bits
        difficulty = calculate_difficulty(header.bits)
        mediantime = get_median_time_past(self.storage, tip_hash)
      end
    else
      difficulty = calculate_difficulty(current_bits)
    end
  end

  -- Verification progress estimate
  local estimated_total_blocks = 880000
  if self.network.name == "testnet" or self.network.name == "testnet4" then
    estimated_total_blocks = 2800000
  elseif self.network.name == "regtest" then
    estimated_total_blocks = tip_height > 0 and tip_height or 1
  end
  local verification_progress = tip_height / estimated_total_blocks
  if verification_progress > 1.0 then verification_progress = 1.0 end

  -- IBD heuristic: tip > 24h old.
  local initial_block_download = false
  if self.storage and self.chain_state and self.chain_state.tip_hash then
    local header = self.storage.get_header(self.chain_state.tip_hash)
    if header then
      local age = os.time() - header.timestamp
      initial_block_download = age > 24 * 60 * 60
    end
  end

  local chainwork = self.chain_state and self.chain_state.chainwork
  if not chainwork then
    chainwork = string.rep("0", 64)
  end

  local softforks = build_deployment_state(tip_height, self.network)

  -- Pruning shape: same projection as getblockchaininfo.  `pruned` is always
  -- present; `pruneheight` and `automatic_pruning` only when prune is on.
  local pruner = self.pruner
  local is_pruned = pruner and pruner.enabled or false

  local tip_bits_hex = string.format("%08x", current_bits)
  local tip_target_hex = bits_to_target_hex(current_bits)
  local tip_time = 0
  if self.storage and self.chain_state and self.chain_state.tip_hash then
    local h = self.storage.get_header(self.chain_state.tip_hash)
    if h then tip_time = h.timestamp end
  end

  local result = {
    chain = self.network.name,
    blocks = tip_height,
    headers = header_height,
    bestblockhash = types.hash256_hex(tip_hash),
    difficulty = difficulty,
    time = tip_time,
    mediantime = mediantime,
    verificationprogress = verification_progress,
    initialblockdownload = initial_block_download,
    chainwork = chainwork,
    bits = tip_bits_hex,
    target = tip_target_hex,
    pruned = is_pruned,
    softforks = softforks,
    warnings = "",
  }
  if is_pruned then
    result.pruneheight = pruner.prune_height > 0
      and (pruner.prune_height + 1) or 0
    result.automatic_pruning = pruner.automatic and true or false
    if pruner.automatic then
      result.prune_target_size = pruner.target_mb * 1024 * 1024
    end
  end

  return json_response(result)
end

--------------------------------------------------------------------------------
-- BIP-157 Block-Filter Helpers
--------------------------------------------------------------------------------

--- Look up a filter for a block hash.  Tries the wired filter_index first
-- (preferred), then falls back to a direct CF read so REST works even when
-- the consumer hasn't passed an index_manager.  Returns the same shape as
-- blockfilter.new_index().get_filter(): {filter, filter_hash, filter_header}.
-- @param self  RESTServer
-- @param block_hash hash256
-- @return table|nil, string|nil
local function lookup_filter(self, block_hash)
  if self.filter_index and self.filter_index.is_enabled
     and self.filter_index.is_enabled() then
    local info, err = self.filter_index.get_filter(block_hash)
    if info then return info end
    return nil, err
  end
  -- Direct fallback: read the raw CF entry put_filter wrote.
  if self.storage and self.storage.get then
    local data = self.storage.get("block_filter", block_hash.bytes)
    if not data then
      return nil, "filter not found"
    end
    local r = serialize.buffer_reader(data)
    return {
      filter_hash   = r.read_hash256(),
      filter_header = r.read_hash256(),
      filter        = r.read_varstr(),
    }
  end
  return nil, "filter index not enabled"
end

--- Walk forward from a starting block hash, collecting filters for up to
-- `count` blocks on the active chain.  Mirrors rest_filter_header's loop
-- (rest.cpp:546-561) which uses ActiveChain::Next.  Here we use the height
-- index: locate height-of-hash, then get_hash_by_height(h+1), etc.
-- @return table list of filter-info entries, in order
local function walk_filters_forward(self, start_hash, count)
  local results = {}
  if not self.storage then return results end

  -- Find starting height via the height index iterator.
  local start_height = nil
  if self.storage.iterator then
    local iter = self.storage.iterator("height")
    if iter then
      iter.seek_to_first()
      while iter.valid() do
        local v = iter.value()
        if v and #v == 32 and v == start_hash.bytes then
          local k = iter.key()
          start_height = k:byte(1) * 16777216 + k:byte(2) * 65536
                       + k:byte(3) * 256 + k:byte(4)
          break
        end
        iter.next()
      end
      iter.destroy()
    end
  end

  if not start_height then return results end

  for h = start_height, start_height + count - 1 do
    local hash
    if h == start_height then
      hash = start_hash
    elseif self.storage.get_hash_by_height then
      hash = self.storage.get_hash_by_height(h)
    end
    if not hash then break end

    local info = lookup_filter(self, hash)
    if not info then break end
    results[#results + 1] = info

    if #results >= count then break end
  end

  return results
end

--- GET /rest/blockfilter/<filtertype>/<hash>.[bin|hex|json]
-- Returns the BIP-157 GCS filter for a single block.  Reference:
-- bitcoin-core/src/rest.cpp::rest_block_filter (rest.cpp:622).
function RESTServer:handle_blockfilter(filtertype_str, hash_hex, format)
  if not M.FILTER_TYPE_BY_NAME[filtertype_str:lower()] then
    return error_response(400, "Unknown filtertype " .. filtertype_str)
  end
  if #hash_hex ~= 64 or not hash_hex:match("^[0-9a-fA-F]+$") then
    return error_response(400, "Invalid hash: " .. hash_hex)
  end
  if not (self.filter_index or self.storage) then
    return error_response(400, "Index is not enabled for filtertype " .. filtertype_str)
  end

  local block_hash = types.hash256_from_hex(hash_hex)
  local info, err = lookup_filter(self, block_hash)
  if not info then
    return error_response(404, "Filter not found." ..
      ((err and " " .. err) or ""))
  end

  local encoded = info.filter or ""

  if format == M.FORMAT.BIN then
    -- Core writes `DataStream ssResp; ssResp << filter;` which serializes the
    -- filter as a CompactSize-prefixed bytestring.
    local w = serialize.buffer_writer()
    w.write_varstr(encoded)
    return bin_response(w.result())
  elseif format == M.FORMAT.HEX then
    local w = serialize.buffer_writer()
    w.write_varstr(encoded)
    return hex_response(w.result())
  elseif format == M.FORMAT.JSON then
    return json_response({ filter = hex_encode(encoded) })
  else
    return error_response(400, "output format not found (available: .bin, .hex, .json)")
  end
end

--- GET /rest/blockfilterheaders/<filtertype>/<count>/<hash>.[bin|hex|json]
-- (and the new ?count= form via /rest/blockfilterheaders/<filtertype>/<hash>)
-- Returns up to `count` filter headers walking forward from hash on the
-- active chain.  Reference: bitcoin-core/src/rest.cpp::rest_filter_header
-- (rest.cpp:500).
function RESTServer:handle_blockfilterheaders(filtertype_str, count_str, hash_hex, format)
  if not M.FILTER_TYPE_BY_NAME[filtertype_str:lower()] then
    return error_response(400, "Unknown filtertype " .. filtertype_str)
  end
  local count = tonumber(count_str)
  if not count or count < 1 or count > M.MAX_HEADERS_COUNT then
    return error_response(400, string.format(
      "Header count is invalid or out of acceptable range (1-%d): %s",
      M.MAX_HEADERS_COUNT, tostring(count_str)))
  end
  if #hash_hex ~= 64 or not hash_hex:match("^[0-9a-fA-F]+$") then
    return error_response(400, "Invalid hash: " .. hash_hex)
  end
  if not (self.filter_index or self.storage) then
    return error_response(400, "Index is not enabled for filtertype " .. filtertype_str)
  end

  local block_hash = types.hash256_from_hex(hash_hex)
  local infos = walk_filters_forward(self, block_hash, count)
  if #infos == 0 then
    return error_response(404, "Filter not found.")
  end

  if format == M.FORMAT.BIN then
    -- Core's serialization is `for (const uint256& h : hs) ssHeader << h;`
    -- which is a raw concatenation of 32-byte little-endian hashes (uint256
    -- internal byte order is the same byte order we hold the hash in).
    local w = serialize.buffer_writer()
    for _, info in ipairs(infos) do
      w.write_hash256(info.filter_header)
    end
    return bin_response(w.result())
  elseif format == M.FORMAT.HEX then
    local w = serialize.buffer_writer()
    for _, info in ipairs(infos) do
      w.write_hash256(info.filter_header)
    end
    return hex_response(w.result())
  elseif format == M.FORMAT.JSON then
    local arr = {}
    for i, info in ipairs(infos) do
      arr[i] = types.hash256_hex(info.filter_header)
    end
    return json_response(arr)
  else
    return error_response(400, "output format not found (available: .bin, .hex, .json)")
  end
end

--------------------------------------------------------------------------------
-- Request Router
--------------------------------------------------------------------------------

function RESTServer:route(method, path)
  if method ~= "GET" then
    return error_response(400, "Only GET method is supported")
  end

  local clean_path, format = parse_format(path)
  local query_params = parse_query(path)

  -- /rest/block/<hash>
  local hash_hex = clean_path:match("^/rest/block/notxdetails/([0-9a-fA-F]+)$")
  if hash_hex then
    format = format or M.FORMAT.JSON
    return self:handle_block(hash_hex, format, true)
  end

  hash_hex = clean_path:match("^/rest/block/([0-9a-fA-F]+)$")
  if hash_hex then
    format = format or M.FORMAT.JSON
    return self:handle_block(hash_hex, format, false)
  end

  -- /rest/tx/<txid>
  local txid_hex = clean_path:match("^/rest/tx/([0-9a-fA-F]+)$")
  if txid_hex then
    format = format or M.FORMAT.JSON
    return self:handle_tx(txid_hex, format)
  end

  -- /rest/headers/<count>/<hash>  (path form, deprecated upstream but still
  -- accepted for back-compat — Core rest.cpp:474-484 keeps both.)
  local count_str, header_hash = clean_path:match("^/rest/headers/(%d+)/([0-9a-fA-F]+)$")
  if count_str and header_hash then
    format = format or M.FORMAT.JSON
    return self:handle_headers(count_str, header_hash, format)
  end

  -- /rest/headers/<hash>?count=N  (query-param form, Core rest.cpp:485-495).
  -- Default count=5 when omitted, matching Core's GetQueryParameter("count").value_or("5").
  header_hash = clean_path:match("^/rest/headers/([0-9a-fA-F]+)$")
  if header_hash then
    format = format or M.FORMAT.JSON
    local q_count = query_params.count or tostring(M.DEFAULT_HEADERS_COUNT)
    return self:handle_headers(q_count, header_hash, format)
  end

  -- /rest/blockhashbyheight/<height>
  local height_str = clean_path:match("^/rest/blockhashbyheight/(%d+)$")
  if height_str then
    format = format or M.FORMAT.JSON
    return self:handle_blockhashbyheight(height_str, format)
  end

  -- /rest/getutxos/<checkmempool>/<txid-n>/...
  local getutxos_path = clean_path:match("^/rest/getutxos/(.*)$")
  if getutxos_path then
    format = format or M.FORMAT.JSON
    local parts = {}
    for part in getutxos_path:gmatch("[^/]+") do
      parts[#parts + 1] = part
    end
    return self:handle_getutxos(parts, format)
  end

  -- /rest/mempool/contents
  if clean_path:match("^/rest/mempool/contents$") then
    if format ~= M.FORMAT.JSON then
      return error_response(400, "output format not found (available: json)")
    end
    return self:handle_mempool_contents(query_params)
  end

  -- /rest/mempool/info
  if clean_path:match("^/rest/mempool/info$") then
    if format ~= M.FORMAT.JSON then
      return error_response(400, "output format not found (available: json)")
    end
    return self:handle_mempool_info()
  end

  -- /rest/chaininfo  (json only, like Core)
  if clean_path:match("^/rest/chaininfo$") then
    format = format or M.FORMAT.JSON
    return self:handle_chaininfo(format)
  end

  -- /rest/blockfilterheaders/<filtertype>/<count>/<hash>  (path-form count)
  --   or /rest/blockfilterheaders/<filtertype>/<hash>?count=N (query-form)
  -- Match path-form first since it's more specific.
  local fh_type, fh_count, fh_hash = clean_path:match(
    "^/rest/blockfilterheaders/([^/]+)/(%d+)/([0-9a-fA-F]+)$")
  if fh_type and fh_count and fh_hash then
    format = format or M.FORMAT.JSON
    return self:handle_blockfilterheaders(fh_type, fh_count, fh_hash, format)
  end
  fh_type, fh_hash = clean_path:match(
    "^/rest/blockfilterheaders/([^/]+)/([0-9a-fA-F]+)$")
  if fh_type and fh_hash then
    format = format or M.FORMAT.JSON
    fh_count = query_params.count or tostring(M.DEFAULT_HEADERS_COUNT)
    return self:handle_blockfilterheaders(fh_type, fh_count, fh_hash, format)
  end

  -- /rest/blockfilter/<filtertype>/<hash>
  local bf_type, bf_hash = clean_path:match(
    "^/rest/blockfilter/([^/]+)/([0-9a-fA-F]+)$")
  if bf_type and bf_hash then
    format = format or M.FORMAT.JSON
    return self:handle_blockfilter(bf_type, bf_hash, format)
  end

  return error_response(404, "Not found")
end

--------------------------------------------------------------------------------
-- HTTP Request Parsing
--------------------------------------------------------------------------------

local function parse_http_request(data)
  local header_end = data:find("\r\n\r\n")
  if not header_end then return nil, "incomplete request" end

  local header_section = data:sub(1, header_end - 1)

  local lines = {}
  for line in header_section:gmatch("[^\r\n]+") do
    lines[#lines + 1] = line
  end

  if #lines == 0 then return nil, "empty request" end

  local method, path = lines[1]:match("^(%w+)%s+(%S+)")
  if not method then return nil, "invalid request line" end

  return method, path
end

--------------------------------------------------------------------------------
-- HTTP Server
--------------------------------------------------------------------------------

function RESTServer:start()
  -- tcp4() not tcp(): setoption("reuseaddr", true) silently fails on a
  -- generic master socket under LuaSocket 3.0, which lets bind() race the
  -- OS TIME_WAIT window on a stop/relaunch. Same fix as rpc.lua / peerman.lua.
  self.server_socket = socket.tcp4()
  assert(self.server_socket:setoption("reuseaddr", true))
  assert(self.server_socket:bind(self.host, self.port))
  assert(self.server_socket:listen(32))
  self.server_socket:settimeout(0.1)
  self.running = true
  print("REST server listening on " .. self.host .. ":" .. self.port)
end

function RESTServer:tick()
  if not self.running then return end

  local client = self.server_socket:accept()
  if not client then return end

  client:settimeout(5)

  -- Read HTTP request
  local data = ""
  while true do
    local chunk, err, partial = client:receive(8192)
    chunk = chunk or partial
    if chunk then data = data .. chunk end
    if err == "closed" or err == "timeout" then break end
    -- Check if we have full headers
    local header_end = data:find("\r\n\r\n")
    if header_end then
      break  -- REST is read-only, no body needed
    end
  end

  if #data == 0 then
    client:close()
    return
  end

  local method, path = parse_http_request(data)
  if not method then
    client:send(error_response(400, "Bad request"))
    client:close()
    return
  end

  local response = self:route(method, path)
  client:send(response)
  client:close()
end

function RESTServer:stop()
  self.running = false
  if self.server_socket then
    self.server_socket:close()
    self.server_socket = nil
  end
end

return M
