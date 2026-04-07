--- JSON-RPC 1.0/2.0 server over HTTP
-- Exposes Bitcoin Core-compatible RPC interface

local socket = require("socket")
local cjson = require("cjson")
local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local validation = require("lunarblock.validation")
local consensus = require("lunarblock.consensus")
local p2p = require("lunarblock.p2p")
local script_mod = require("lunarblock.script")
local address_mod = require("lunarblock.address")
local bit = require("bit")
local storage_mod = require("lunarblock.storage")
local M = {}

--------------------------------------------------------------------------------
-- RPC Error Codes
--------------------------------------------------------------------------------

M.ERROR = {
  PARSE_ERROR = -32700,
  INVALID_REQUEST = -32600,
  METHOD_NOT_FOUND = -32601,
  INVALID_PARAMS = -32602,
  INTERNAL_ERROR = -32603,
  -- Bitcoin-specific
  MISC_ERROR = -1,
  FORBIDDEN = -2,
  TYPE_ERROR = -3,
  WALLET_ERROR = -4,
  INVALID_ADDRESS = -5,
  INSUFFICIENT_FUNDS = -6,
  OUT_OF_MEMORY = -7,
  DESERIALIZATION_ERROR = -22,
  VERIFY_ERROR = -25,
  VERIFY_REJECTED = -26,
  VERIFY_ALREADY_IN_CHAIN = -27,
  IN_WARMUP = -28,
}

--------------------------------------------------------------------------------
-- Script Disassembly
--------------------------------------------------------------------------------

--- Disassemble a script to human-readable ASM format.
-- @param script_bytes string: The raw script bytes
-- @return string: Space-separated assembly representation
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
      -- Push data: show as hex
      parts[#parts + 1] = M.hex_encode(data)
    elseif opcode == 0x00 then
      parts[#parts + 1] = "OP_0"
    elseif opcode >= 0x01 and opcode <= 0x4b then
      -- Direct push but no data (shouldn't happen with valid parse)
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

--- Decode a scriptPubKey into RPC-compatible format.
-- Returns an object with: type, asm, hex, and optionally address.
-- @param script_pubkey string: The raw scriptPubKey bytes
-- @param network table: Network configuration for address encoding
-- @return table: Decoded scriptPubKey object
function M.decode_script_pubkey(script_pubkey, network)
  local result = {
    asm = disassemble_script(script_pubkey),
    hex = M.hex_encode(script_pubkey),
  }

  -- Classify the script type
  local script_type, program = script_mod.classify_script(script_pubkey)

  -- Map to Bitcoin Core type names
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

  -- Check for bare pubkey (P2PK): <pubkey> OP_CHECKSIG
  -- 33/35 bytes: compressed pubkey (33) + OP_CHECKSIG OR uncompressed pubkey (65) + OP_CHECKSIG
  if #script_pubkey == 35 and script_pubkey:byte(1) == 0x21 and script_pubkey:byte(35) == 0xac then
    result.type = "pubkey"
  elseif #script_pubkey == 67 and script_pubkey:byte(1) == 0x41 and script_pubkey:byte(67) == 0xac then
    result.type = "pubkey"
  end

  -- Check for multisig: OP_M <pubkey>... OP_N OP_CHECKMULTISIG
  if #script_pubkey >= 3 and script_pubkey:byte(#script_pubkey) == 0xae then
    local first = script_pubkey:byte(1)
    if first >= 0x51 and first <= 0x60 then  -- OP_1 to OP_16
      result.type = "multisig"
    end
  end

  -- Try to extract address
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
-- Base64 Encoding/Decoding
--------------------------------------------------------------------------------

function M.base64_decode(data)
  local b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  local lookup = {}
  for i = 1, #b64 do lookup[b64:sub(i, i)] = i - 1 end

  data = data:gsub("[^%w%+/=]", "")
  local result = {}
  for i = 1, #data, 4 do
    local a = lookup[data:sub(i, i)] or 0
    local b = lookup[data:sub(i+1, i+1)] or 0
    local c = lookup[data:sub(i+2, i+2)] or 0
    local d = lookup[data:sub(i+3, i+3)] or 0
    local n = a * 262144 + b * 4096 + c * 64 + d
    result[#result + 1] = string.char(
      math.floor(n / 65536) % 256,
      math.floor(n / 256) % 256,
      n % 256
    )
  end
  local s = table.concat(result)
  local pad = data:match("(=*)$")
  if pad and #pad > 0 then
    s = s:sub(1, -(#pad + 1))
  end
  return s
end

--------------------------------------------------------------------------------
-- Hex Encoding/Decoding
--------------------------------------------------------------------------------

function M.hex_encode(data)
  local hex = {}
  for i = 1, #data do
    hex[i] = string.format("%02x", data:byte(i))
  end
  return table.concat(hex)
end

function M.hex_decode(hex)
  local bytes = {}
  for i = 1, #hex, 2 do
    bytes[#bytes + 1] = string.char(tonumber(hex:sub(i, i + 1), 16))
  end
  return table.concat(bytes)
end

--------------------------------------------------------------------------------
-- HTTP Request Parsing
--------------------------------------------------------------------------------

function M.parse_http_request(data)
  -- Parse a raw HTTP request
  -- Return: method, path, headers, body
  local header_end = data:find("\r\n\r\n")
  if not header_end then return nil, "incomplete request" end

  local header_section = data:sub(1, header_end - 1)
  local body = data:sub(header_end + 4)

  local lines = {}
  for line in header_section:gmatch("[^\r\n]+") do
    lines[#lines + 1] = line
  end

  if #lines == 0 then return nil, "empty request" end

  -- Parse request line
  local method, path = lines[1]:match("^(%w+)%s+(%S+)")
  if not method then return nil, "invalid request line" end

  -- Parse headers
  local headers = {}
  for i = 2, #lines do
    local key, value = lines[i]:match("^([^:]+):%s*(.+)")
    if key then
      headers[key:lower()] = value
    end
  end

  -- Check Content-Length and read body
  local content_length = tonumber(headers["content-length"] or 0)
  if #body < content_length then
    return nil, "incomplete body"
  end
  body = body:sub(1, content_length)

  return method, path, headers, body
end

--------------------------------------------------------------------------------
-- HTTP Response Building
--------------------------------------------------------------------------------

function M.build_http_response(status, body, content_type)
  content_type = content_type or "application/json"
  local status_text = {
    [200] = "OK",
    [204] = "No Content",
    [400] = "Bad Request",
    [401] = "Unauthorized",
    [403] = "Forbidden",
    [404] = "Not Found",
    [500] = "Internal Server Error",
  }

  -- 204 No Content should not have a body or Content-Length
  if status == 204 then
    return string.format(
      "HTTP/1.1 %d %s\r\nConnection: keep-alive\r\n\r\n",
      status, status_text[status]
    )
  end

  local response = string.format(
    "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s",
    status, status_text[status] or "Unknown", content_type, #body, body
  )
  return response
end

--------------------------------------------------------------------------------
-- HTTP Basic Authentication
--------------------------------------------------------------------------------

function M.check_auth(headers, username, password)
  local auth = headers["authorization"]
  if not auth then return false end
  local scheme, creds = auth:match("^(%w+)%s+(.+)")
  if scheme ~= "Basic" then return false end
  -- Decode base64
  local decoded = M.base64_decode(creds)
  local expected = username .. ":" .. password
  return decoded == expected
end

--------------------------------------------------------------------------------
-- Difficulty Calculation
--------------------------------------------------------------------------------

--- Calculate difficulty from compact "bits" representation.
-- Matches Bitcoin Core's GetDifficulty function:
-- difficulty = 0x0000ffff / (bits & 0x00ffffff) * 256^(29 - (bits >> 24))
-- @param bits number: compact difficulty representation
-- @return number: difficulty as floating point
local function calculate_difficulty(bits)
  local nshift = bit.rshift(bits, 24)
  local mantissa = bit.band(bits, 0x00ffffff)
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

--- Calculate chainwork from target.
-- Chainwork = 2^256 / (target + 1)
-- Since we can't do 256-bit math easily, we approximate using the bits format.
-- @param bits number: compact difficulty representation
-- @return string: chainwork as hex string (64 chars)
local function calculate_chainwork_from_bits(bits)
  local target = consensus.bits_to_target(bits)
  -- For proper chainwork, we need 256-bit division
  -- Chainwork = floor(2^256 / (target + 1))
  -- We'll compute this incrementally by tracking the work per block

  -- Convert target to a number for simplified calculation
  -- This is an approximation for display purposes
  local target_value = 0
  for i = 1, 32 do
    target_value = target_value * 256 + target:byte(i)
  end
  -- Can't represent 2^256 directly, so we use difficulty relationship
  -- work_per_block ≈ difficulty * 2^32
  -- For display, we just return a hex representation
  return string.rep("0", 64)  -- Placeholder - actual calculation requires big integers
end

--- Get median time of past 11 blocks.
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
  return timestamps[math.ceil(#timestamps / 2)]
end

--------------------------------------------------------------------------------
-- RPC Server Object
--------------------------------------------------------------------------------

local RPCServer = {}
RPCServer.__index = RPCServer

function M.new(config)
  local self = setmetatable({}, RPCServer)
  self.host = config.host or "127.0.0.1"
  self.port = config.rpcport or 8332
  self.username = config.rpcuser or "lunarblock"
  self.password = config.rpcpassword or ""
  self.server_socket = nil
  self.methods = {}        -- method_name -> handler function
  self.chain_state = config.chain_state
  self.mempool = config.mempool
  self.peer_manager = config.peer_manager
  self.storage = config.storage
  self.network = config.network or consensus.networks.mainnet
  self.fee_estimator = config.fee_estimator
  self.wallet = config.wallet  -- Legacy single wallet (for backward compat)
  self.wallet_manager = config.wallet_manager  -- Multi-wallet manager
  self.datadir = config.datadir
  self.mining = config.mining
  self.block_downloader = config.block_downloader
  self.running = false
  self.request_wallet = nil  -- Current request's wallet context
  -- Register built-in methods
  self:register_methods()
  return self
end

--- Get wallet for current request context.
-- @param name string|nil: Explicit wallet name (optional)
-- @return Wallet|nil: Wallet instance
-- @return string|nil: Error message if wallet not found
function RPCServer:get_request_wallet(name)
  -- If wallet manager is available, use it
  if self.wallet_manager then
    if name then
      local wallet = self.wallet_manager:get_wallet(name)
      if not wallet then
        return nil, "Requested wallet \"" .. name .. "\" does not exist or is not loaded"
      end
      return wallet
    end
    -- Use request context wallet if set
    if self.request_wallet then
      return self.request_wallet
    end
    -- Use default wallet
    local wallet, _ = self.wallet_manager:get_default_wallet()
    if not wallet then
      return nil, "No wallet is loaded. Load a wallet with loadwallet or create one with createwallet"
    end
    return wallet
  end
  -- Legacy single wallet mode
  if self.wallet then
    return self.wallet
  end
  return nil, "No wallet is loaded"
end

--------------------------------------------------------------------------------
-- RPC Request Handling
--------------------------------------------------------------------------------

-- Maximum batch size (Bitcoin Core default)
M.MAX_BATCH_SIZE = 1000

--- Process a single JSON-RPC request object.
-- @param request table: Parsed JSON-RPC request
-- @return table|nil: Response object, or nil for notifications
function RPCServer:handle_single_request(request)
  local method = request.method
  local params = request.params or {}
  local id = request.id

  -- Check if this is a notification (no id field at all)
  local is_notification = (id == nil)

  local handler = self.methods[method]
  if not handler then
    -- Notifications should not return errors either
    if is_notification then
      return nil
    end
    return {
      result = cjson.null,
      error = {code = M.ERROR.METHOD_NOT_FOUND, message = "Method not found: " .. tostring(method)},
      id = id,
    }
  end

  local success, result = pcall(handler, self, params)
  if not success then
    -- Notifications should not return errors
    if is_notification then
      return nil
    end
    -- Check if it's a structured error
    if type(result) == "table" and result.code then
      return {
        result = cjson.null,
        error = {code = result.code, message = result.message or "Error"},
        id = id,
      }
    end
    return {
      result = cjson.null,
      error = {code = M.ERROR.INTERNAL_ERROR, message = tostring(result)},
      id = id,
    }
  end

  -- Notifications should not return responses
  if is_notification then
    return nil
  end

  return {
    result = result,
    error = cjson.null,
    id = id,
  }
end

--- Handle a JSON-RPC request body (singleton or batch).
-- @param request_body string: Raw JSON request body
-- @return string, number|nil: JSON response body, optional HTTP status override
function RPCServer:handle_request(request_body)
  local ok, parsed = pcall(cjson.decode, request_body)
  if not ok then
    return cjson.encode({
      result = cjson.null,
      error = {code = M.ERROR.PARSE_ERROR, message = "Parse error"},
      id = cjson.null,
    }), nil
  end

  -- Check for batch request: array with numeric keys
  -- JSON arrays in cjson have consecutive integer keys starting at 1
  if type(parsed) == "table" and parsed[1] ~= nil then
    -- This is a batch request
    local batch_size = #parsed

    -- Enforce max batch size
    if batch_size > M.MAX_BATCH_SIZE then
      return cjson.encode({
        result = cjson.null,
        error = {code = M.ERROR.INVALID_REQUEST,
                 message = "Batch request exceeds maximum size of " .. M.MAX_BATCH_SIZE},
        id = cjson.null,
      }), 400
    end

    -- Process each request in the batch
    local responses = {}
    for i = 1, batch_size do
      local request = parsed[i]
      -- Each element must be an object
      if type(request) ~= "table" or request[1] ~= nil then
        -- Invalid request element (not an object)
        responses[#responses + 1] = {
          result = cjson.null,
          error = {code = M.ERROR.INVALID_REQUEST, message = "Invalid Request object"},
          id = cjson.null,
        }
      else
        local response = self:handle_single_request(request)
        -- Only include non-nil responses (notifications return nil)
        if response ~= nil then
          responses[#responses + 1] = response
        end
      end
    end

    -- If all requests were notifications, return no content
    if #responses == 0 and batch_size > 0 then
      return "", 204
    end

    return cjson.encode(responses), nil
  end

  -- Singleton request
  local response = self:handle_single_request(parsed)

  -- Handle notification (no response)
  if response == nil then
    return "", 204
  end

  return cjson.encode(response), nil
end

--------------------------------------------------------------------------------
-- RPC Method Registration
--------------------------------------------------------------------------------

function RPCServer:register_methods()
  -- Blockchain methods
  self.methods["getblockchaininfo"] = function(rpc, _params)
    local tip_height = 0
    local tip_hash = types.hash256_zero()
    local header_height = 0
    local difficulty = 1.0
    local mediantime = os.time()
    local current_bits = rpc.network.pow_limit_bits

    if rpc.chain_state then
      tip_height = rpc.chain_state.tip_height or 0
      tip_hash = rpc.chain_state.tip_hash or types.hash256_zero()
      header_height = rpc.chain_state.header_tip_height or tip_height

      -- Get current block's bits for difficulty calculation
      if rpc.storage then
        local header = rpc.storage.get_header(tip_hash)
        if header then
          current_bits = header.bits
          difficulty = calculate_difficulty(header.bits)
          mediantime = get_median_time_past(rpc.storage, tip_hash)
        end
      else
        difficulty = calculate_difficulty(current_bits)
      end
    end

    -- Calculate verification progress estimate
    local estimated_total_blocks = 880000  -- Approximate mainnet height
    if rpc.network.name == "testnet" or rpc.network.name == "testnet4" then
      estimated_total_blocks = 2800000
    elseif rpc.network.name == "regtest" then
      estimated_total_blocks = tip_height > 0 and tip_height or 1
    end
    local verification_progress = tip_height / estimated_total_blocks
    if verification_progress > 1.0 then verification_progress = 1.0 end

    -- Check if in initial block download (simplified: if tip is more than 24h behind)
    local initial_block_download = false
    if rpc.storage and rpc.chain_state and rpc.chain_state.tip_hash then
      local header = rpc.storage.get_header(rpc.chain_state.tip_hash)
      if header then
        local age = os.time() - header.timestamp
        initial_block_download = age > 24 * 60 * 60
      end
    end

    -- Calculate cumulative chainwork
    -- This is a simplified estimate - proper implementation requires storing chainwork per block
    local chainwork = rpc.chain_state and rpc.chain_state.chainwork
    if not chainwork then
      chainwork = string.rep("0", 64)  -- Default to zeros if not tracked
    end

    -- Build softforks table
    local softforks = {}
    if rpc.network.bip34_height then
      softforks.bip34 = {type = "buried", active = tip_height >= rpc.network.bip34_height, height = rpc.network.bip34_height}
    end
    if rpc.network.bip66_height then
      softforks.bip66 = {type = "buried", active = tip_height >= rpc.network.bip66_height, height = rpc.network.bip66_height}
    end
    if rpc.network.bip65_height then
      softforks.bip65 = {type = "buried", active = tip_height >= rpc.network.bip65_height, height = rpc.network.bip65_height}
    end
    if rpc.network.csv_height then
      softforks.csv = {type = "buried", active = tip_height >= rpc.network.csv_height, height = rpc.network.csv_height}
    end
    if rpc.network.segwit_height then
      softforks.segwit = {type = "buried", active = tip_height >= rpc.network.segwit_height, height = rpc.network.segwit_height}
    end
    if rpc.network.taproot_height then
      softforks.taproot = {type = "buried", active = tip_height >= rpc.network.taproot_height, height = rpc.network.taproot_height}
    end

    return {
      chain = rpc.network.name,
      blocks = tip_height,
      headers = header_height,
      bestblockhash = types.hash256_hex(tip_hash),
      difficulty = difficulty,
      mediantime = mediantime,
      verificationprogress = verification_progress,
      initialblockdownload = initial_block_download,
      chainwork = chainwork,
      pruned = false,
      softforks = softforks,
    }
  end

  self.methods["getblockhash"] = function(rpc, params)
    local height = params[1]
    if type(height) ~= "number" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Height must be a number"})
    end
    if height < 0 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Block height out of range"})
    end
    if not rpc.storage then
      error({code = M.ERROR.MISC_ERROR, message = "Storage not available"})
    end
    -- Check if height is beyond current tip
    local tip_height = rpc.chain_state and rpc.chain_state.tip_height or 0
    if height > tip_height then
      error({code = M.ERROR.INVALID_PARAMS, message = "Block height out of range"})
    end
    local hash = rpc.storage.get_hash_by_height(height)
    if not hash then
      error({code = M.ERROR.MISC_ERROR, message = "Block not found"})
    end
    return types.hash256_hex(hash)
  end

  self.methods["getblock"] = function(rpc, params)
    local blockhash = params[1]
    local verbosity = params[2]
    -- Default verbosity is 1
    if verbosity == nil or verbosity == cjson.null then
      verbosity = 1
    end
    -- Handle boolean for backwards compatibility (true = 1, false = 0)
    if verbosity == true then verbosity = 1
    elseif verbosity == false then verbosity = 0
    end

    if type(blockhash) ~= "string" or #blockhash ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid block hash"})
    end
    if not rpc.storage then
      error({code = M.ERROR.MISC_ERROR, message = "Storage not available"})
    end

    local hash = types.hash256_from_hex(blockhash)
    local block = rpc.storage.get_block(hash)
    if not block then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Block not found"})
    end

    -- Verbosity 0: return raw hex
    if verbosity == 0 then
      return M.hex_encode(serialize.serialize_block(block))
    end

    -- Get block height from height index (reverse lookup)
    local block_height = nil
    if rpc.chain_state and rpc.chain_state.tip_height then
      -- Try to find height by iterating (expensive) or from chain state
      -- For efficiency, we iterate height index
      local iter = rpc.storage.iterator("height")
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
    if block_height and rpc.chain_state and rpc.chain_state.tip_height then
      confirmations = rpc.chain_state.tip_height - block_height + 1
    end

    -- Calculate block size and weight
    local block_data = serialize.serialize_block(block)
    local block_size = #block_data
    local block_weight = validation.get_block_weight and validation.get_block_weight(block)
    if not block_weight then
      -- Calculate weight: base_size * 3 + total_size
      local base_size = #serialize.serialize_block_without_witness(block)
      block_weight = base_size * 3 + block_size
    end

    -- Calculate stripped size (without witness)
    local stripped_size = #serialize.serialize_block_without_witness(block)

    -- Calculate difficulty from bits
    local difficulty = calculate_difficulty(block.header.bits)

    -- Get nextblockhash if we have a height
    local nextblockhash = nil
    if block_height and rpc.storage then
      local next_hash = rpc.storage.get_hash_by_height(block_height + 1)
      if next_hash then
        nextblockhash = types.hash256_hex(next_hash)
      end
    end

    -- Get previousblockhash
    local prevhash = block.header.prev_hash
    local previousblockhash = nil
    -- Check if prev_hash is not all zeros (genesis block has no previous)
    local zero_hash = string.rep("\0", 32)
    if prevhash.bytes ~= zero_hash then
      previousblockhash = types.hash256_hex(prevhash)
    end

    -- Get median time past
    local mediantime = get_median_time_past(rpc.storage, hash)

    -- Build transaction list based on verbosity
    local tx_list
    if verbosity == 1 then
      -- Just txids
      tx_list = {}
      for _, tx in ipairs(block.transactions) do
        tx_list[#tx_list + 1] = types.hash256_hex(validation.compute_txid(tx))
      end
    elseif verbosity >= 2 then
      -- Full decoded transactions
      tx_list = {}
      for i, tx in ipairs(block.transactions) do
        local txid = validation.compute_txid(tx)
        local wtxid = validation.compute_wtxid(tx)
        local weight = validation.get_tx_weight(tx)
        local size = #serialize.serialize_transaction(tx, true)
        local base_size = #serialize.serialize_transaction(tx, false)
        local vsize = math.ceil(weight / consensus.WITNESS_SCALE_FACTOR)

        -- Check if coinbase
        local is_coinbase = false
        local null_hash = string.rep("\0", 32)
        if #tx.inputs == 1 and tx.inputs[1].prev_out.hash.bytes == null_hash and
           tx.inputs[1].prev_out.index == 0xFFFFFFFF then
          is_coinbase = true
        end

        -- Build vin array
        local vin = {}
        for j, inp in ipairs(tx.inputs) do
          local vin_entry = {}
          if is_coinbase and j == 1 then
            vin_entry.coinbase = M.hex_encode(inp.script_sig)
            vin_entry.sequence = inp.sequence
            if inp.witness and #inp.witness > 0 then
              vin_entry.txinwitness = {}
              for k, wit in ipairs(inp.witness) do
                vin_entry.txinwitness[k] = M.hex_encode(wit)
              end
            end
          else
            vin_entry.txid = types.hash256_hex(inp.prev_out.hash)
            vin_entry.vout = inp.prev_out.index
            vin_entry.scriptSig = {
              asm = disassemble_script(inp.script_sig),
              hex = M.hex_encode(inp.script_sig),
            }
            vin_entry.sequence = inp.sequence
            if inp.witness and #inp.witness > 0 then
              vin_entry.txinwitness = {}
              for k, wit in ipairs(inp.witness) do
                vin_entry.txinwitness[k] = M.hex_encode(wit)
              end
            end
          end
          vin[j] = vin_entry
        end

        -- Build vout array
        local vout = {}
        for j, out in ipairs(tx.outputs) do
          vout[j] = {
            value = out.value / consensus.COIN,
            n = j - 1,
            scriptPubKey = M.decode_script_pubkey(out.script_pubkey, rpc.network),
          }
        end

        tx_list[i] = {
          txid = types.hash256_hex(txid),
          hash = types.hash256_hex(wtxid),
          version = tx.version,
          size = size,
          vsize = vsize,
          weight = weight,
          locktime = tx.locktime,
          vin = vin,
          vout = vout,
          hex = M.hex_encode(serialize.serialize_transaction(tx, true)),
        }
      end
    end

    -- Build result
    local result = {
      hash = blockhash,
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
      mediantime = mediantime,
      nonce = block.header.nonce,
      bits = string.format("%08x", block.header.bits),
      difficulty = difficulty,
      nTx = #block.transactions,
    }

    if previousblockhash then
      result.previousblockhash = previousblockhash
    end
    if nextblockhash then
      result.nextblockhash = nextblockhash
    end

    return result
  end

  self.methods["getblockcount"] = function(rpc, _params)
    if rpc.chain_state then
      return rpc.chain_state.tip_height or 0
    end
    return 0
  end

  self.methods["getbestblockhash"] = function(rpc, _params)
    if rpc.chain_state then
      return types.hash256_hex(rpc.chain_state.tip_hash or types.hash256_zero())
    end
    return types.hash256_hex(types.hash256_zero())
  end

  -- Block invalidation methods
  self.methods["invalidateblock"] = function(rpc, params)
    local blockhash = params[1]
    if type(blockhash) ~= "string" or #blockhash ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid block hash"})
    end
    if not rpc.chain_state then
      error({code = M.ERROR.MISC_ERROR, message = "Chain state not available"})
    end

    local hash = types.hash256_from_hex(blockhash)

    -- Check if the block exists
    if not rpc.storage then
      error({code = M.ERROR.MISC_ERROR, message = "Storage not available"})
    end
    local header = rpc.storage.get_header(hash)
    if not header then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Block not found"})
    end

    -- Invalidate the block
    local ok, err = rpc.chain_state:invalidate_block(hash)
    if not ok then
      error({code = M.ERROR.MISC_ERROR, message = err or "Failed to invalidate block"})
    end

    return cjson.null
  end

  self.methods["reconsiderblock"] = function(rpc, params)
    local blockhash = params[1]
    if type(blockhash) ~= "string" or #blockhash ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid block hash"})
    end
    if not rpc.chain_state then
      error({code = M.ERROR.MISC_ERROR, message = "Chain state not available"})
    end

    local hash = types.hash256_from_hex(blockhash)

    -- Check if the block exists
    if not rpc.storage then
      error({code = M.ERROR.MISC_ERROR, message = "Storage not available"})
    end
    local header = rpc.storage.get_header(hash)
    if not header then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Block not found"})
    end

    -- Reconsider the block
    local ok, err = rpc.chain_state:reconsider_block(hash)
    if not ok then
      error({code = M.ERROR.MISC_ERROR, message = err or "Failed to reconsider block"})
    end

    return cjson.null
  end

  -- Mempool methods
  self.methods["getmempoolinfo"] = function(rpc, _params)
    local info
    if rpc.mempool then
      info = rpc.mempool:get_info()
    else
      info = {
        size = 0,
        bytes = 0,
        usage = 0,
        maxmempool = 300 * 1024 * 1024,
        mempoolminfee = 1000,
      }
    end

    -- Calculate total fees
    local total_fee = 0
    if rpc.mempool then
      for _, entry in pairs(rpc.mempool.entries) do
        total_fee = total_fee + entry.fee
      end
    end

    -- Convert fee rates to BTC/kvB for Bitcoin Core compatibility
    local mempool_min_fee = info.mempoolminfee or 1000  -- sat/kvB
    local min_relay_fee = (rpc.mempool and rpc.mempool.min_relay_fee) or 1000  -- sat/kvB

    return {
      loaded = true,  -- mempool is always loaded once we're serving RPCs
      size = info.size,
      bytes = info.bytes,
      usage = info.usage,
      total_fee = total_fee / consensus.COIN,  -- in BTC
      maxmempool = info.maxmempool,
      mempoolminfee = mempool_min_fee / 100000000,  -- Convert sat/kvB to BTC/kvB
      minrelaytxfee = min_relay_fee / 100000000,  -- Convert sat/kvB to BTC/kvB
    }
  end

  self.methods["getrawmempool"] = function(rpc, params)
    local verbose = params[1] or false
    if not rpc.mempool then
      if verbose then return {} end
      return {}
    end
    if not verbose then
      return rpc.mempool:get_raw_mempool()
    end
    -- Verbose: return details for each tx
    local result = {}
    for _, txid_hex in ipairs(rpc.mempool:get_raw_mempool()) do
      local entry = rpc.mempool:get_entry(txid_hex)
      if entry then
        result[txid_hex] = {
          vsize = entry.vsize,
          weight = entry.weight,
          fee = entry.fee / consensus.COIN,
          time = entry.time,
          height = entry.height,
          descendantcount = entry.descendant_count,
          descendantsize = entry.descendant_size,
          descendantfees = entry.descendant_fees,
          ancestorcount = entry.ancestor_count,
          ancestorsize = entry.ancestor_size,
          ancestorfees = entry.ancestor_fees,
        }
      end
    end
    return result
  end

  -- Transaction methods
  self.methods["sendrawtransaction"] = function(rpc, params)
    local hex = params[1]
    assert(type(hex) == "string", "Transaction hex required")
    local raw = M.hex_decode(hex)
    local tx = serialize.deserialize_transaction(raw)
    assert(rpc.mempool, "Mempool not available")
    local ok, txid_hex = rpc.mempool:accept_transaction(tx)
    if not ok then
      error({code = M.ERROR.VERIFY_REJECTED, message = txid_hex})
    end
    -- Broadcast to peers
    if rpc.peer_manager then
      local txid = validation.compute_txid(tx)
      local inv_payload = p2p.serialize_inv({
        {type = p2p.INV_TYPE.MSG_WITNESS_TX, hash = txid}
      })
      rpc.peer_manager:broadcast("inv", inv_payload)
    end
    return txid_hex
  end

  self.methods["getrawtransaction"] = function(rpc, params)
    local txid_hex = params[1]
    local verbose = params[2] or false
    local blockhash_hex = params[3]

    -- Validate txid parameter
    if type(txid_hex) ~= "string" or #txid_hex ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid txid"})
    end

    -- Validate blockhash if provided
    if blockhash_hex ~= nil and blockhash_hex ~= cjson.null then
      if type(blockhash_hex) ~= "string" or #blockhash_hex ~= 64 then
        error({code = M.ERROR.INVALID_PARAMS, message = "Invalid blockhash"})
      end
    else
      blockhash_hex = nil
    end

    local tx = nil
    local block = nil
    local block_height = nil
    local block_time = nil
    local found_blockhash = nil
    local in_mempool = false

    -- Lookup order: mempool first (if no blockhash provided), then storage/txindex

    -- 1. Check mempool first (only if blockhash not specified)
    if not blockhash_hex and rpc.mempool then
      local entry = rpc.mempool:get_entry(txid_hex)
      if entry then
        tx = entry.tx
        in_mempool = true
      end
    end

    -- 2. If blockhash provided, search that specific block
    if not tx and blockhash_hex and rpc.storage then
      local block_hash = types.hash256_from_hex(blockhash_hex)
      block = rpc.storage.get_block(block_hash)
      if not block then
        error({code = M.ERROR.INVALID_ADDRESS, message = "Block hash not found"})
      end
      -- Search for transaction in block
      for _, btx in ipairs(block.transactions) do
        local btx_txid = types.hash256_hex(validation.compute_txid(btx))
        if btx_txid == txid_hex then
          tx = btx
          found_blockhash = blockhash_hex
          -- Look up block height and time
          local iter = rpc.storage.iterator(rpc.storage._handles and "height" or nil)
          if rpc.storage.get then
            -- Try to get height from metadata
            local height_data = rpc.storage.get("height", block_hash.bytes)
            if height_data then
              local r = serialize.buffer_reader(height_data)
              block_height = r.read_u32le()
            end
          end
          block_time = block.header.timestamp
          break
        end
      end
      if not tx then
        error({code = M.ERROR.INVALID_ADDRESS,
               message = "No such transaction found in the provided block. Use gettransaction for wallet transactions."})
      end
    end

    -- 3. Check transaction index if available and tx still not found
    if not tx and rpc.storage then
      local txid_bytes = types.hash256_from_hex(txid_hex)
      -- Try TX_INDEX column family
      local tx_index_data = rpc.storage.get and rpc.storage.get("tx_index", txid_bytes.bytes)
      if tx_index_data then
        -- TX index stores: block_hash (32 bytes) + offset (optional)
        if #tx_index_data >= 32 then
          local index_block_hash = types.hash256(tx_index_data:sub(1, 32))
          found_blockhash = types.hash256_hex(index_block_hash)
          block = rpc.storage.get_block(index_block_hash)
          if block then
            -- Find tx in block
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
    end

    -- If still not found, return error
    if not tx then
      local msg
      if blockhash_hex then
        msg = "No such transaction found in the provided block. Use gettransaction for wallet transactions."
      elseif rpc.storage and rpc.storage.get then
        msg = "No such mempool or blockchain transaction. Use gettransaction for wallet transactions."
      else
        msg = "No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries. Use gettransaction for wallet transactions."
      end
      error({code = M.ERROR.INVALID_ADDRESS, message = msg})
    end

    -- Non-verbose: return raw hex
    if not verbose then
      return M.hex_encode(serialize.serialize_transaction(tx, true))
    end

    -- Verbose: build detailed response
    local weight = validation.get_tx_weight(tx)
    local size = #serialize.serialize_transaction(tx, true)
    local base_size = #serialize.serialize_transaction(tx, false)
    local vsize = math.ceil(weight / consensus.WITNESS_SCALE_FACTOR)
    local txid = validation.compute_txid(tx)
    local wtxid = validation.compute_wtxid(tx)

    -- Build vin array
    local vin = {}
    local is_coinbase = false
    local null_hash = string.rep("\0", 32)
    if #tx.inputs == 1 and tx.inputs[1].prev_out.hash.bytes == null_hash and
       tx.inputs[1].prev_out.index == 0xFFFFFFFF then
      is_coinbase = true
    end

    for i, inp in ipairs(tx.inputs) do
      local vin_entry = {}
      if is_coinbase and i == 1 then
        vin_entry.coinbase = M.hex_encode(inp.script_sig)
        vin_entry.sequence = inp.sequence
        if inp.witness and #inp.witness > 0 then
          vin_entry.txinwitness = {}
          for j, wit in ipairs(inp.witness) do
            vin_entry.txinwitness[j] = M.hex_encode(wit)
          end
        end
      else
        vin_entry.txid = types.hash256_hex(inp.prev_out.hash)
        vin_entry.vout = inp.prev_out.index
        vin_entry.scriptSig = {
          asm = disassemble_script(inp.script_sig),
          hex = M.hex_encode(inp.script_sig),
        }
        vin_entry.sequence = inp.sequence
        if inp.witness and #inp.witness > 0 then
          vin_entry.txinwitness = {}
          for j, wit in ipairs(inp.witness) do
            vin_entry.txinwitness[j] = M.hex_encode(wit)
          end
        end
      end
      vin[i] = vin_entry
    end

    -- Build vout array
    local vout = {}
    for i, out in ipairs(tx.outputs) do
      vout[i] = {
        value = out.value / consensus.COIN,
        n = i - 1,
        scriptPubKey = M.decode_script_pubkey(out.script_pubkey, rpc.network),
      }
    end

    -- Build result
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
      hex = M.hex_encode(serialize.serialize_transaction(tx, true)),
    }

    -- Add block info if transaction is confirmed
    if found_blockhash then
      result.blockhash = found_blockhash
      if block_time then
        result.time = block_time
        result.blocktime = block_time
      end

      -- Calculate confirmations
      if rpc.chain_state and rpc.chain_state.tip_height then
        local tip_height = rpc.chain_state.tip_height
        -- Try to get block height from storage
        if not block_height and rpc.storage then
          local block_hash = types.hash256_from_hex(found_blockhash)
          -- Look up height from height_index in reverse
          -- This is expensive - in production, store height in tx_index
          local iter = rpc.storage.iterator("height")
          if iter then
            iter.seek_to_first()
            while iter.valid() do
              local k = iter.key()
              local v = iter.value()
              if v and #v == 32 and v == block_hash.bytes then
                -- Decode height from key (4-byte big-endian)
                block_height = k:byte(1) * 16777216 + k:byte(2) * 65536 + k:byte(3) * 256 + k:byte(4)
                break
              end
              iter.next()
            end
            iter.destroy()
          end
        end

        if block_height then
          result.confirmations = tip_height - block_height + 1
        else
          result.confirmations = 1  -- Default to 1 if height unknown
        end
      end
    end

    return result
  end

  self.methods["decoderawtransaction"] = function(_rpc, params)
    local hex = params[1]
    assert(type(hex) == "string", "Transaction hex required")
    local raw = M.hex_decode(hex)
    local tx = serialize.deserialize_transaction(raw)
    local txid = validation.compute_txid(tx)

    local vin = {}
    for i, inp in ipairs(tx.inputs) do
      vin[i] = {
        txid = types.hash256_hex(inp.prev_out.hash),
        vout = inp.prev_out.index,
        scriptSig = {
          hex = M.hex_encode(inp.script_sig),
        },
        sequence = inp.sequence,
      }
    end

    local vout = {}
    for i, out in ipairs(tx.outputs) do
      vout[i] = {
        value = out.value / consensus.COIN,
        n = i - 1,
        scriptPubKey = {
          hex = M.hex_encode(out.script_pubkey),
        },
      }
    end

    return {
      txid = types.hash256_hex(txid),
      version = tx.version,
      locktime = tx.locktime,
      vin = vin,
      vout = vout,
    }
  end

  -- Network methods
  self.methods["getnetworkinfo"] = function(rpc, _params)
    local connections = 0
    if rpc.peer_manager then
      connections = #rpc.peer_manager.peer_list
    end
    return {
      version = 10000,
      subversion = "/LunarBlock:0.1.0/",
      protocolversion = p2p.PROTOCOL_VERSION,
      connections = connections,
      networks = {{name = "ipv4", reachable = true}},
      relayfee = 0.00001,
      localaddresses = {},
    }
  end

  self.methods["getpeerinfo"] = function(rpc, _params)
    local peers = {}
    if rpc.peer_manager then
      for _, p in ipairs(rpc.peer_manager.peer_list) do
        peers[#peers + 1] = {
          addr = p.ip .. ":" .. p.port,
          services = string.format("%016x", p.services or 0),
          lastsend = math.floor(p.last_send or 0),
          lastrecv = math.floor(p.last_recv or 0),
          subver = p.user_agent or "",
          inbound = p.inbound or false,
          startingheight = p.start_height or 0,
          pingtime = (p.latency_ms or 0) / 1000,
          banscore = p.ban_score or 0,
        }
      end
    end
    return peers
  end

  self.methods["getconnectioncount"] = function(rpc, _params)
    if rpc.peer_manager then
      return #rpc.peer_manager.peer_list
    end
    return 0
  end

  -- Fee estimation
  self.methods["estimatesmartfee"] = function(rpc, params)
    local conf_target = params[1] or 6
    if rpc.fee_estimator then
      local fee_rate, actual_target = rpc.fee_estimator:estimate_smart_fee(conf_target)
      return {
        feerate = fee_rate / 100000,  -- Convert sat/vB to BTC/kB
        blocks = actual_target,
      }
    end
    return {feerate = 0.00001, blocks = conf_target}
  end

  -- Mining
  self.methods["getblocktemplate"] = function(rpc, params)
    if rpc.mining then
      local script_mod = require("lunarblock.script")
      local payout_script
      if params[1] and params[1].coinbase_payout then
        payout_script = params[1].coinbase_payout
      else
        payout_script = script_mod.make_p2pkh_script(string.rep("\0", 20))
      end
      local template = rpc.mining.create_block_template(
        rpc.mempool, rpc.chain_state, rpc.network,
        payout_script
      )
      return template
    end
    error({code = M.ERROR.MISC_ERROR, message = "Mining not available"})
  end

  -- Mining RPC: generatetoaddress
  self.methods["generatetoaddress"] = function(rpc, params)
    local nblocks = params[1]
    local address = params[2]
    if type(nblocks) ~= "number" or nblocks < 1 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid nblocks"})
    end
    if type(address) ~= "string" or #address == 0 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid address"})
    end
    if not rpc.mining then
      error({code = M.ERROR.MISC_ERROR, message = "Mining module not available"})
    end

    -- Decode address to script_pubkey
    local addr_type, addr_data = address_mod.decode_address(address, rpc.network.name)
    if not addr_type then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Invalid address: " .. tostring(addr_data)})
    end

    local payout_script
    if addr_type == "p2pkh" then
      payout_script = script_mod.make_p2pkh_script(addr_data)
    elseif addr_type == "p2sh" then
      payout_script = script_mod.make_p2sh_script(addr_data)
    elseif addr_type == "p2wpkh" then
      payout_script = script_mod.make_p2wpkh_script(addr_data)
    elseif addr_type == "p2wsh" then
      payout_script = script_mod.make_p2wsh_script(addr_data)
    elseif addr_type == "p2tr" then
      payout_script = script_mod.make_p2tr_script(addr_data)
    else
      error({code = M.ERROR.INVALID_ADDRESS, message = "Unsupported address type: " .. addr_type})
    end

    local block_hashes = {}
    for _ = 1, nblocks do
      -- Create block template
      local _template, block = rpc.mining.create_block_template(
        rpc.mempool, rpc.chain_state, rpc.network, payout_script
      )

      -- Mine the block (CPU mining for regtest)
      local found, block_hash = rpc.mining.mine_block(block)
      if not found then
        error({code = M.ERROR.MISC_ERROR, message = "Failed to mine block (nonce exhausted)"})
      end

      -- Store block/header/height_index atomically with UTXO flush
      local new_height = rpc.chain_state.tip_height + 1
      local block_data = serialize.serialize_block(block)
      local header_data = serialize.serialize_block_header(block.header)
      local height_key = string.char(
        math.floor(new_height / 16777216) % 256,
        math.floor(new_height / 65536) % 256,
        math.floor(new_height / 256) % 256,
        new_height % 256
      )
      local hash_bytes = block_hash.bytes
      local store_batch_fn = function(batch)
        batch.put(storage_mod.CF.BLOCKS, hash_bytes, block_data)
        batch.put(storage_mod.CF.HEADERS, hash_bytes, header_data)
        batch.put(storage_mod.CF.HEIGHT_INDEX, height_key, hash_bytes)
      end

      -- Connect the block to chain state (skip full script validation for self-mined blocks)
      local ok, err = rpc.chain_state:connect_block(block, new_height, block_hash, nil, nil, true, nil, false, store_batch_fn)
      if not ok then
        error({code = M.ERROR.VERIFY_ERROR, message = "Failed to connect block: " .. tostring(err)})
      end

      block_hashes[#block_hashes + 1] = types.hash256_hex(block_hash)

      -- Broadcast inv to peers so they learn about the new block
      if rpc.peer_manager then
        local inv_payload = p2p.serialize_inv({
          {type = p2p.INV_TYPE.MSG_BLOCK, hash = block_hash}
        })
        rpc.peer_manager:broadcast("inv", inv_payload)
      end
    end

    return block_hashes
  end

  -- Utility methods
  self.methods["validateaddress"] = function(rpc, params)
    local address_mod = require("lunarblock.address")
    local addr = params[1]
    assert(type(addr) == "string", "Address required")
    local addr_type = address_mod.decode_address(addr, rpc.network.name)
    return {
      isvalid = addr_type ~= nil,
      address = addr,
    }
  end

  self.methods["stop"] = function(_rpc, _params)
    -- Signal shutdown
    return "LunarBlock stopping..."
  end

  self.methods["help"] = function(rpc, params)
    if params[1] then
      return "Help for " .. params[1] .. " not yet implemented"
    end
    local methods_list = {}
    for name in pairs(rpc.methods) do
      methods_list[#methods_list + 1] = name
    end
    table.sort(methods_list)
    return table.concat(methods_list, "\n")
  end

  self.methods["getinfo"] = function(rpc, _params)
    local tip_height = 0
    if rpc.chain_state then
      tip_height = rpc.chain_state.tip_height or 0
    end
    local connections = 0
    if rpc.peer_manager then
      connections = #rpc.peer_manager.peer_list
    end
    return {
      version = 10000,
      protocolversion = p2p.PROTOCOL_VERSION,
      blocks = tip_height,
      connections = connections,
      testnet = rpc.network.name ~= "mainnet",
      relayfee = 0.00001,
    }
  end

  self.methods["uptime"] = function(_rpc, _params)
    -- Return uptime in seconds (simplified)
    return os.time()
  end

  ----------------------------------------------------------------------------
  -- PSBT Methods (BIP174)
  ----------------------------------------------------------------------------

  self.methods["createpsbt"] = function(rpc, params)
    local psbt_mod = require("lunarblock.psbt")
    local inputs_raw = params[1]
    local outputs_raw = params[2]
    local locktime = params[3] or 0
    local replaceable = params[4]  -- ignored for now, RBF is default

    -- Suppress unused warning
    local _ = replaceable

    if type(inputs_raw) ~= "table" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Inputs must be an array"})
    end
    if type(outputs_raw) ~= "table" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Outputs must be an array"})
    end

    -- Build transaction inputs
    local inputs = {}
    for _, inp in ipairs(inputs_raw) do
      if type(inp.txid) ~= "string" or #inp.txid ~= 64 then
        error({code = M.ERROR.INVALID_PARAMS, message = "Invalid input txid"})
      end
      if type(inp.vout) ~= "number" then
        error({code = M.ERROR.INVALID_PARAMS, message = "Invalid input vout"})
      end
      local txid = types.hash256_from_hex(inp.txid)
      local sequence = inp.sequence or 0xFFFFFFFD  -- Default to RBF-enabled
      inputs[#inputs + 1] = types.txin(
        types.outpoint(txid, inp.vout),
        "",  -- Empty scriptSig
        sequence
      )
    end

    -- Build transaction outputs
    local outputs = {}
    for _, out_spec in ipairs(outputs_raw) do
      -- Outputs can be: {address: amount} or {"data": hex}
      for key, val in pairs(out_spec) do
        if key == "data" then
          -- OP_RETURN output
          local data_bytes = M.hex_decode(val)
          local script_pubkey = script_mod.make_nulldata_script(data_bytes)
          outputs[#outputs + 1] = types.txout(0, script_pubkey)
        else
          -- Address output
          local addr = key
          local amount = val
          if type(amount) ~= "number" then
            error({code = M.ERROR.INVALID_PARAMS, message = "Invalid output amount"})
          end
          local addr_type, program = address_mod.decode_address(addr, rpc.network.name)
          if not addr_type then
            error({code = M.ERROR.INVALID_ADDRESS, message = "Invalid address: " .. addr})
          end
          local script_pubkey
          if addr_type == "p2wpkh" then
            script_pubkey = script_mod.make_p2wpkh_script(program)
          elseif addr_type == "p2wsh" then
            script_pubkey = script_mod.make_p2wsh_script(program)
          elseif addr_type == "p2pkh" then
            script_pubkey = script_mod.make_p2pkh_script(program)
          elseif addr_type == "p2sh" then
            script_pubkey = script_mod.make_p2sh_script(program)
          elseif addr_type == "p2tr" then
            script_pubkey = script_mod.make_p2tr_script(program)
          else
            error({code = M.ERROR.INVALID_ADDRESS, message = "Unsupported address type"})
          end
          local satoshis = math.floor(amount * consensus.COIN + 0.5)
          outputs[#outputs + 1] = types.txout(satoshis, script_pubkey)
        end
        break  -- Only one key per output object
      end
    end

    -- Create unsigned transaction
    local tx = types.transaction(2, inputs, outputs, locktime)

    -- Create PSBT
    local psbt = psbt_mod.new(tx)

    -- Return base64 encoded PSBT
    return psbt_mod.to_base64(psbt)
  end

  self.methods["decodepsbt"] = function(rpc, params)
    local psbt_mod = require("lunarblock.psbt")
    local psbt_b64 = params[1]

    if type(psbt_b64) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "PSBT string required"})
    end

    local ok, psbt = pcall(psbt_mod.from_base64, psbt_b64)
    if not ok then
      error({code = M.ERROR.DESERIALIZATION_ERROR, message = "Invalid PSBT: " .. tostring(psbt)})
    end

    -- Suppress unused warning
    local _ = rpc

    return psbt_mod.decode(psbt)
  end

  self.methods["analyzepsbt"] = function(rpc, params)
    local psbt_mod = require("lunarblock.psbt")
    local psbt_b64 = params[1]

    if type(psbt_b64) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "PSBT string required"})
    end

    local ok, psbt = pcall(psbt_mod.from_base64, psbt_b64)
    if not ok then
      error({code = M.ERROR.DESERIALIZATION_ERROR, message = "Invalid PSBT: " .. tostring(psbt)})
    end

    -- Suppress unused warning
    local _ = rpc

    local inputs = {}
    for i, inp in ipairs(psbt.inputs) do
      local have, need = psbt_mod.get_signature_status(psbt, i - 1)
      local input_info = {
        has_utxo = inp.witness_utxo ~= nil or inp.non_witness_utxo ~= nil,
        is_final = psbt_mod.input_is_signed(inp),
        next = "unknown",
      }

      if psbt_mod.input_is_signed(inp) then
        input_info.next = "extractor"
      elseif have >= need and need > 0 then
        input_info.next = "finalizer"
      elseif inp.witness_utxo or inp.non_witness_utxo then
        input_info.next = "signer"
      else
        input_info.next = "updater"
        input_info.missing = {utxo = true}
      end

      inputs[i] = input_info
    end

    local next_role = "unknown"
    local all_final = true
    local needs_sigs = false
    local needs_utxo = false

    for _, inp_info in ipairs(inputs) do
      if not inp_info.is_final then
        all_final = false
      end
      if inp_info.next == "signer" then
        needs_sigs = true
      end
      if inp_info.next == "updater" then
        needs_utxo = true
      end
    end

    if all_final then
      next_role = "extractor"
    elseif needs_utxo then
      next_role = "updater"
    elseif needs_sigs then
      next_role = "signer"
    else
      next_role = "finalizer"
    end

    return {
      inputs = inputs,
      estimated_vsize = nil,  -- TODO: Calculate
      estimated_feerate = nil,
      fee = nil,
      next = next_role,
    }
  end

  self.methods["combinepsbt"] = function(rpc, params)
    local psbt_mod = require("lunarblock.psbt")
    local psbts_b64 = params[1]

    if type(psbts_b64) ~= "table" or #psbts_b64 < 1 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Array of PSBTs required"})
    end

    -- Suppress unused warning
    local _ = rpc

    -- Parse all PSBTs
    local psbts = {}
    for i, b64 in ipairs(psbts_b64) do
      local ok, psbt = pcall(psbt_mod.from_base64, b64)
      if not ok then
        error({code = M.ERROR.DESERIALIZATION_ERROR, message = "Invalid PSBT at index " .. (i - 1)})
      end
      psbts[#psbts + 1] = psbt
    end

    -- Combine
    local ok, combined = pcall(psbt_mod.combine, psbts)
    if not ok then
      error({code = M.ERROR.MISC_ERROR, message = "Cannot combine PSBTs: " .. tostring(combined)})
    end

    return psbt_mod.to_base64(combined)
  end

  self.methods["finalizepsbt"] = function(rpc, params)
    local psbt_mod = require("lunarblock.psbt")
    local psbt_b64 = params[1]
    local extract = params[2]
    if extract == nil then extract = true end

    if type(psbt_b64) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "PSBT string required"})
    end

    -- Suppress unused warning
    local _ = rpc

    local ok, psbt = pcall(psbt_mod.from_base64, psbt_b64)
    if not ok then
      error({code = M.ERROR.DESERIALIZATION_ERROR, message = "Invalid PSBT: " .. tostring(psbt)})
    end

    -- Finalize all inputs
    local complete = psbt_mod.finalize(psbt)

    local result = {
      psbt = psbt_mod.to_base64(psbt),
      complete = complete,
    }

    -- Extract if requested and complete
    if extract and complete then
      local ok2, tx = pcall(psbt_mod.extract, psbt)
      if ok2 then
        result.hex = M.hex_encode(serialize.serialize_transaction(tx, true))
      end
    end

    return result
  end

  self.methods["utxoupdatepsbt"] = function(rpc, params)
    local psbt_mod = require("lunarblock.psbt")
    local psbt_b64 = params[1]
    -- params[2] would be descriptors (not implemented)

    if type(psbt_b64) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "PSBT string required"})
    end

    local ok, psbt = pcall(psbt_mod.from_base64, psbt_b64)
    if not ok then
      error({code = M.ERROR.DESERIALIZATION_ERROR, message = "Invalid PSBT: " .. tostring(psbt)})
    end

    -- Look up UTXOs from storage
    if rpc.storage then
      local storage_mod = require("lunarblock.storage")
      local utxo_mod = require("lunarblock.utxo")

      for i, tx_input in ipairs(psbt.tx.inputs) do
        local inp = psbt.inputs[i]

        -- Skip if already has UTXO info
        if inp.witness_utxo or inp.non_witness_utxo then
          goto continue
        end

        -- Look up UTXO
        local outpoint_key = tx_input.prev_out.hash.bytes .. string.char(
          bit.band(tx_input.prev_out.index, 0xFF),
          bit.band(bit.rshift(tx_input.prev_out.index, 8), 0xFF),
          bit.band(bit.rshift(tx_input.prev_out.index, 16), 0xFF),
          bit.band(bit.rshift(tx_input.prev_out.index, 24), 0xFF)
        )

        local utxo_data = rpc.storage.get(storage_mod.CF.UTXO, outpoint_key)
        if utxo_data then
          local entry = utxo_mod.deserialize_utxo_entry(utxo_data)
          -- Determine if segwit based on script type
          local script_type = script_mod.classify_script(entry.script_pubkey)
          if script_type == "p2wpkh" or script_type == "p2wsh" or script_type == "p2tr" then
            inp.witness_utxo = {
              value = entry.value,
              script_pubkey = entry.script_pubkey,
            }
          else
            -- For legacy, we'd need the full previous tx
            -- For now, just use witness_utxo format
            inp.witness_utxo = {
              value = entry.value,
              script_pubkey = entry.script_pubkey,
            }
          end
        end

        ::continue::
      end
    end

    return psbt_mod.to_base64(psbt)
  end

  self.methods["walletprocesspsbt"] = function(rpc, params)
    local psbt_mod = require("lunarblock.psbt")
    local psbt_b64 = params[1]
    local sign = params[2]
    local sighash_type = params[3]  -- "ALL", "NONE", etc.
    local bip32derivs = params[4]

    -- Suppress unused warnings
    local _ = {sighash_type, bip32derivs}

    if sign == nil then sign = true end

    if type(psbt_b64) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "PSBT string required"})
    end

    local ok, psbt = pcall(psbt_mod.from_base64, psbt_b64)
    if not ok then
      error({code = M.ERROR.DESERIALIZATION_ERROR, message = "Invalid PSBT: " .. tostring(psbt)})
    end

    -- Update UTXOs from wallet's known UTXOs
    if rpc.wallet then
      for i, tx_input in ipairs(psbt.tx.inputs) do
        local inp = psbt.inputs[i]

        -- Skip if already has UTXO info
        if inp.witness_utxo or inp.non_witness_utxo then
          goto continue_utxo
        end

        -- Look up in wallet UTXOs
        local key = tx_input.prev_out.hash.bytes .. string.char(
          bit.band(tx_input.prev_out.index, 0xFF),
          bit.band(bit.rshift(tx_input.prev_out.index, 8), 0xFF),
          bit.band(bit.rshift(tx_input.prev_out.index, 16), 0xFF),
          bit.band(bit.rshift(tx_input.prev_out.index, 24), 0xFF)
        )

        local utxo = rpc.wallet.utxos[key]
        if utxo then
          inp.witness_utxo = {
            value = utxo.value,
            script_pubkey = utxo.script_pubkey,
          }
        end

        ::continue_utxo::
      end
    end

    -- Sign inputs if requested
    if sign and rpc.wallet then
      -- Check wallet is unlocked
      if rpc.wallet.is_encrypted and rpc.wallet.is_locked then
        error({code = M.ERROR.WALLET_ERROR, message = "Wallet is locked"})
      end

      for i, tx_input in ipairs(psbt.tx.inputs) do
        local inp = psbt.inputs[i]

        -- Skip if already finalized
        if psbt_mod.input_is_signed(inp) then
          goto continue_sign
        end

        -- Get UTXO script
        local script_pubkey
        if inp.witness_utxo then
          script_pubkey = inp.witness_utxo.script_pubkey
        elseif inp.non_witness_utxo then
          local prev_out = inp.non_witness_utxo.outputs[tx_input.prev_out.index + 1]
          if prev_out then
            script_pubkey = prev_out.script_pubkey
          end
        end

        if not script_pubkey then
          goto continue_sign
        end

        -- Find address from script
        local script_type, hash_or_program = script_mod.classify_script(script_pubkey)
        local addr

        if script_type == "p2wpkh" then
          local hrp = rpc.wallet.network.bech32_hrp or address_mod.BECH32_HRP[rpc.wallet.network.name] or "bc"
          addr = address_mod.segwit_encode(hrp, 0, hash_or_program)
        elseif script_type == "p2pkh" then
          local version = rpc.wallet.network.pubkey_address_prefix
          addr = address_mod.base58check_encode(version, hash_or_program)
        end

        if addr and rpc.wallet.keys[addr] then
          local key_info = rpc.wallet.keys[addr]
          if key_info.privkey then
            psbt_mod.sign_input(psbt, i - 1, key_info.privkey, key_info.pubkey)
          end
        end

        ::continue_sign::
      end
    end

    -- Check if complete
    local complete = psbt_mod.is_complete(psbt)

    return {
      psbt = psbt_mod.to_base64(psbt),
      complete = complete,
    }
  end

  self.methods["converttopsbt"] = function(rpc, params)
    local psbt_mod = require("lunarblock.psbt")
    local hex_tx = params[1]
    local permitsigdata = params[2]
    local iswitness = params[3]

    -- Suppress unused warnings
    local _ = {rpc, iswitness}

    if type(hex_tx) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Transaction hex required"})
    end

    local ok, tx = pcall(function()
      return serialize.deserialize_transaction(M.hex_decode(hex_tx))
    end)
    if not ok then
      error({code = M.ERROR.DESERIALIZATION_ERROR, message = "Invalid transaction"})
    end

    -- Check for existing signatures
    local has_sigs = false
    for _, inp in ipairs(tx.inputs) do
      if #inp.script_sig > 0 or (inp.witness and #inp.witness > 0) then
        has_sigs = true
        break
      end
    end

    if has_sigs and not permitsigdata then
      error({code = M.ERROR.DESERIALIZATION_ERROR,
             message = "Inputs must not have scriptSigs/witnesses. Set permitsigdata=true to strip them."})
    end

    -- Strip signatures if present
    if has_sigs then
      for _, inp in ipairs(tx.inputs) do
        inp.script_sig = ""
        inp.witness = {}
      end
      tx.segwit = false
    end

    local psbt = psbt_mod.new(tx)
    return psbt_mod.to_base64(psbt)
  end

  self.methods["joinpsbts"] = function(rpc, params)
    local psbt_mod = require("lunarblock.psbt")
    local psbts_b64 = params[1]

    if type(psbts_b64) ~= "table" or #psbts_b64 < 1 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Array of PSBTs required"})
    end

    -- Suppress unused warning
    local _ = rpc

    -- Parse all PSBTs
    local psbts = {}
    for i, b64 in ipairs(psbts_b64) do
      local ok, psbt = pcall(psbt_mod.from_base64, b64)
      if not ok then
        error({code = M.ERROR.DESERIALIZATION_ERROR, message = "Invalid PSBT at index " .. (i - 1)})
      end
      psbts[#psbts + 1] = psbt
    end

    -- Join: create new transaction with all inputs and outputs
    local all_inputs = {}
    local all_outputs = {}
    local all_psbt_inputs = {}
    local all_psbt_outputs = {}

    for _, psbt in ipairs(psbts) do
      for j, inp in ipairs(psbt.tx.inputs) do
        all_inputs[#all_inputs + 1] = inp
        all_psbt_inputs[#all_psbt_inputs + 1] = psbt.inputs[j]
      end
      for j, out in ipairs(psbt.tx.outputs) do
        all_outputs[#all_outputs + 1] = out
        all_psbt_outputs[#all_psbt_outputs + 1] = psbt.outputs[j]
      end
    end

    -- Create new transaction
    local tx = types.transaction(2, all_inputs, all_outputs, 0)

    -- Create new PSBT
    local result = psbt_mod.new(tx)
    result.inputs = all_psbt_inputs
    result.outputs = all_psbt_outputs

    return psbt_mod.to_base64(result)
  end

  ----------------------------------------------------------------------------
  -- Output Descriptor Methods (BIP380-386)
  ----------------------------------------------------------------------------

  self.methods["getdescriptorinfo"] = function(rpc, params)
    local descriptor = params[1]

    if type(descriptor) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Descriptor string required"})
    end

    local info, err = address_mod.get_descriptor_info(descriptor)
    if not info then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid descriptor: " .. (err or "unknown error")})
    end

    -- Suppress unused warning
    local _ = rpc

    return info
  end

  self.methods["deriveaddresses"] = function(rpc, params)
    local descriptor = params[1]
    local range = params[2]

    if type(descriptor) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Descriptor string required"})
    end

    -- Validate checksum is present
    if not descriptor:find("#") then
      error({code = M.ERROR.INVALID_PARAMS, message = "Missing checksum"})
    end

    -- Validate checksum
    local is_valid = address_mod.validate_descriptor_checksum(descriptor)
    if not is_valid then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid checksum"})
    end

    local range_start = 0
    local range_end = 0

    if range then
      if type(range) == "number" then
        range_start = 0
        range_end = range
      elseif type(range) == "table" then
        range_start = range[1] or 0
        range_end = range[2] or range[1] or 0
      end
    end

    -- Check that range is valid
    if range_start < 0 or range_end < range_start then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid range"})
    end

    -- Check max range
    if range_end - range_start > 10000 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Range too large"})
    end

    -- Derive addresses
    local network_name = rpc.network and rpc.network.name or "mainnet"
    local addresses, err = address_mod.derive_addresses(descriptor, range_start, range_end, network_name)

    if not addresses then
      error({code = M.ERROR.MISC_ERROR, message = "Failed to derive addresses: " .. (err or "unknown error")})
    end

    return addresses
  end

  ----------------------------------------------------------------------------
  -- Multi-Wallet Management RPCs
  ----------------------------------------------------------------------------

  --- createwallet: Create and load a new wallet.
  -- @param wallet_name string: Name for the new wallet
  -- @param disable_private_keys boolean: Disable private keys (watch-only)
  -- @param blank boolean: Create blank wallet (no keys)
  -- @param passphrase string: Encryption passphrase (optional)
  -- @param descriptors boolean: Use descriptors (always true)
  -- @return table: {name, warnings}
  self.methods["createwallet"] = function(rpc, params)
    if not rpc.wallet_manager then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet manager not available"})
    end

    local wallet_name = params[1] or params.wallet_name
    if wallet_name == nil then
      error({code = M.ERROR.INVALID_PARAMS, message = "wallet_name is required"})
    end

    -- Parse options
    local disable_private_keys = params[2] or params.disable_private_keys or false
    local blank = params[3] or params.blank or false
    local passphrase = params[4] or params.passphrase
    -- params[5] descriptors (ignored, always true)
    -- params[6] load_on_startup (ignored in our implementation)

    local options = {
      disable_private_keys = disable_private_keys,
      blank = blank,
      passphrase = passphrase,
    }

    local wallet, err = rpc.wallet_manager:create_wallet(wallet_name, options)
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err or "Failed to create wallet"})
    end

    local warnings = {}
    if passphrase and passphrase == "" then
      warnings[#warnings + 1] = "Empty string given as passphrase, wallet will not be encrypted."
    end

    return {
      name = wallet_name,
      warnings = warnings,
    }
  end

  --- loadwallet: Load a wallet from a wallet file.
  -- @param filename string: Wallet name (directory name under wallets/)
  -- @param load_on_startup boolean: (ignored)
  -- @return table: {name, warnings}
  self.methods["loadwallet"] = function(rpc, params)
    if not rpc.wallet_manager then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet manager not available"})
    end

    local filename = params[1] or params.filename
    if filename == nil then
      error({code = M.ERROR.INVALID_PARAMS, message = "filename is required"})
    end

    local wallet, err = rpc.wallet_manager:load_wallet(filename)
    if not wallet then
      -- Check for specific errors
      if err and err:find("already loaded") then
        error({code = -35, message = err})  -- RPC_WALLET_ALREADY_LOADED
      elseif err and err:find("not found") then
        error({code = -18, message = err})  -- RPC_WALLET_NOT_FOUND
      else
        error({code = M.ERROR.WALLET_ERROR, message = err or "Failed to load wallet"})
      end
    end

    return {
      name = filename,
      warnings = {},
    }
  end

  --- unloadwallet: Unload a wallet.
  -- @param wallet_name string: Wallet name (optional, uses request context)
  -- @param load_on_startup boolean: (ignored)
  -- @return table: {warnings}
  self.methods["unloadwallet"] = function(rpc, params)
    if not rpc.wallet_manager then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet manager not available"})
    end

    -- Get wallet name from params or request context
    local wallet_name = params[1] or params.wallet_name
    if wallet_name == nil then
      -- Try to get from request context
      if rpc.request_wallet then
        -- Find name by matching wallet instance
        for name, w in pairs(rpc.wallet_manager.wallets) do
          if w == rpc.request_wallet then
            wallet_name = name
            break
          end
        end
      end
      if wallet_name == nil then
        -- Use default wallet
        local _, name = rpc.wallet_manager:get_default_wallet()
        wallet_name = name
      end
    end

    if wallet_name == nil then
      error({code = M.ERROR.WALLET_ERROR, message = "No wallet specified and no default wallet loaded"})
    end

    local ok, err = rpc.wallet_manager:unload_wallet(wallet_name)
    if not ok then
      if err and err:find("not loaded") then
        error({code = -18, message = err})  -- RPC_WALLET_NOT_FOUND
      else
        error({code = M.ERROR.WALLET_ERROR, message = err or "Failed to unload wallet"})
      end
    end

    return {
      warnings = {},
    }
  end

  --- listwallets: List currently loaded wallets.
  -- @return table: Array of wallet names
  self.methods["listwallets"] = function(rpc, _params)
    if not rpc.wallet_manager then
      -- Legacy mode: return single wallet or empty
      if rpc.wallet then
        return {""}
      end
      return {}
    end

    return rpc.wallet_manager:list_wallets()
  end

  --- listwalletdir: List wallets in the wallet directory.
  -- @return table: {wallets: [{name, warnings}]}
  self.methods["listwalletdir"] = function(rpc, _params)
    if not rpc.wallet_manager then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet manager not available"})
    end

    local wallet_list = rpc.wallet_manager:list_wallet_dir()
    local wallets = {}
    for _, info in ipairs(wallet_list) do
      wallets[#wallets + 1] = {
        name = info.name,
      }
    end

    return {
      wallets = wallets,
    }
  end

  --- getwalletinfo: Get wallet state info.
  -- @return table: Wallet information
  self.methods["getwalletinfo"] = function(rpc, _params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    -- Find wallet name
    local wallet_name = ""
    if rpc.wallet_manager then
      for name, w in pairs(rpc.wallet_manager.wallets) do
        if w == wallet then
          wallet_name = name
          break
        end
      end
    end

    return {
      walletname = wallet_name,
      walletversion = 1,
      format = "json",
      txcount = 0,  -- TODO: track transactions
      keypoolsize = wallet.gap_limit - wallet.next_external_index,
      keypoolsize_hd_internal = wallet.gap_limit - wallet.next_internal_index,
      private_keys_enabled = not wallet.is_locked and wallet.master_key ~= nil,
      avoid_reuse = false,
      scanning = false,
      descriptors = true,
      external_signer = false,
      blank = wallet.master_key == nil and wallet.encrypted_master_key == nil,
    }
  end

  --- getnewaddress: Get a new receiving address.
  -- @param label string: (ignored)
  -- @param address_type string: Address type (optional)
  -- @return string: New address
  self.methods["getnewaddress"] = function(rpc, params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    if wallet.is_locked then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet is locked"})
    end

    -- params[1] is label (ignored), params[2] is address_type
    local address_type = params[2] or params.address_type
    if address_type and address_type ~= wallet.address_type then
      -- Temporarily change address type
      local old_type = wallet.address_type
      wallet.address_type = address_type
      local addr = wallet:get_new_address()
      wallet.address_type = old_type
      return addr
    end

    return wallet:get_new_address()
  end

  --- getbalance: Get wallet balance.
  -- @return number: Balance in BTC
  self.methods["getbalance"] = function(rpc, _params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    -- Rescan UTXOs if chain_state is available
    if rpc.chain_state then
      wallet:scan_utxos(rpc.chain_state)
    end

    local balance = wallet:get_balance()
    return balance / 100000000  -- Convert satoshis to BTC
  end

  --- getbalances: Get detailed balance info.
  -- @return table: Balance details
  self.methods["getbalances"] = function(rpc, _params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    -- Rescan UTXOs if chain_state is available
    if rpc.chain_state then
      wallet:scan_utxos(rpc.chain_state)
    end
    if rpc.mempool then
      wallet:scan_mempool(rpc.mempool)
    end

    local details = wallet:get_balance_details()
    return {
      mine = {
        trusted = details.confirmed / 100000000,
        untrusted_pending = details.unconfirmed / 100000000,
        immature = 0,
      },
      watchonly = {
        trusted = 0,
        untrusted_pending = 0,
        immature = 0,
      },
    }
  end

  --- listunspent: List unspent transaction outputs.
  -- @return table: Array of UTXOs
  self.methods["listunspent"] = function(rpc, params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    -- Rescan UTXOs if chain_state is available
    if rpc.chain_state then
      wallet:scan_utxos(rpc.chain_state)
    end

    local min_conf = params[1] or params.minconf or 1
    local include_unconfirmed = min_conf == 0

    local utxos = wallet:list_unspent(include_unconfirmed)
    local result = {}
    for _, u in ipairs(utxos) do
      result[#result + 1] = {
        txid = u.txid,
        vout = u.vout,
        address = u.address,
        amount = u.value / 100000000,
        confirmations = u.confirmations or 0,
        spendable = true,
        solvable = true,
        safe = (u.confirmations or 0) >= min_conf,
      }
    end

    return result
  end

  --- sendtoaddress: Send to a Bitcoin address.
  -- @param address string: Recipient address
  -- @param amount number: Amount in BTC
  -- @return string: Transaction ID
  self.methods["sendtoaddress"] = function(rpc, params)
    local wallet, werr = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = werr})
    end

    if wallet.is_locked then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet is locked"})
    end

    local addr = params[1] or params.address
    local amount = params[2] or params.amount

    if not addr then
      error({code = M.ERROR.INVALID_PARAMS, message = "address is required"})
    end
    if not amount then
      error({code = M.ERROR.INVALID_PARAMS, message = "amount is required"})
    end

    -- Convert BTC to satoshis
    local amount_sat = math.floor(amount * 100000000 + 0.5)

    -- Rescan UTXOs
    if rpc.chain_state then
      wallet:scan_utxos(rpc.chain_state)
    end

    -- Set mempool for transaction submission
    if rpc.mempool then
      wallet:set_mempool(rpc.mempool)
    end

    -- Create and send transaction
    local recipients = {{address = addr, amount = amount_sat}}
    local tx, err = wallet:send_to(recipients)
    if not tx then
      error({code = M.ERROR.WALLET_ERROR, message = err or "Failed to create transaction"})
    end

    -- Return txid as hex
    local crypto = require("lunarblock.crypto")
    local txid = crypto.sha256d(rpc.storage and
      require("lunarblock.serialize").serialize_transaction(tx, false) or
      tx.txid or "")
    return M.hex_encode(txid:reverse())
  end

  --- walletpassphrase: Unlock wallet with passphrase.
  -- @param passphrase string: Wallet passphrase
  -- @param timeout number: Seconds to keep unlocked (ignored, stays unlocked)
  self.methods["walletpassphrase"] = function(rpc, params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    local passphrase = params[1] or params.passphrase
    if not passphrase then
      error({code = M.ERROR.INVALID_PARAMS, message = "passphrase is required"})
    end

    local ok, unlock_err = wallet:unlock(passphrase)
    if not ok then
      error({code = M.ERROR.WALLET_ERROR, message = unlock_err or "Wrong passphrase"})
    end

    return cjson.null
  end

  --- walletlock: Lock the wallet.
  self.methods["walletlock"] = function(rpc, _params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    if not wallet.is_encrypted then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet is not encrypted"})
    end

    wallet:lock()
    return cjson.null
  end

  --- encryptwallet: Encrypt the wallet with a passphrase.
  -- @param passphrase string: Encryption passphrase
  self.methods["encryptwallet"] = function(rpc, params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    if wallet.is_encrypted then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet is already encrypted"})
    end

    local passphrase = params[1] or params.passphrase
    if not passphrase or passphrase == "" then
      error({code = M.ERROR.INVALID_PARAMS, message = "passphrase is required"})
    end

    wallet:encrypt(passphrase)

    -- Save wallet
    if rpc.wallet_manager then
      for name, w in pairs(rpc.wallet_manager.wallets) do
        if w == wallet then
          local path = rpc.wallet_manager:get_wallet_path(name)
          wallet:save(path)
          break
        end
      end
    end

    return "wallet encrypted; The keypool has been flushed and a new HD seed was generated."
  end

  --- walletpassphrasechange: Change wallet passphrase.
  -- @param oldpassphrase string: Current passphrase
  -- @param newpassphrase string: New passphrase
  self.methods["walletpassphrasechange"] = function(rpc, params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    local old_pass = params[1] or params.oldpassphrase
    local new_pass = params[2] or params.newpassphrase

    if not old_pass then
      error({code = M.ERROR.INVALID_PARAMS, message = "oldpassphrase is required"})
    end
    if not new_pass then
      error({code = M.ERROR.INVALID_PARAMS, message = "newpassphrase is required"})
    end

    local ok, change_err = wallet:change_passphrase(old_pass, new_pass)
    if not ok then
      error({code = M.ERROR.WALLET_ERROR, message = change_err or "Wrong passphrase"})
    end

    -- Save wallet
    if rpc.wallet_manager then
      for name, w in pairs(rpc.wallet_manager.wallets) do
        if w == wallet then
          local path = rpc.wallet_manager:get_wallet_path(name)
          wallet:save(path)
          break
        end
      end
    end

    return cjson.null
  end

  --- dumpprivkey: Dump private key for an address.
  -- @param address string: Address to dump key for
  -- @return string: Private key in WIF format
  self.methods["dumpprivkey"] = function(rpc, params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    if wallet.is_locked then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet is locked"})
    end

    local addr = params[1] or params.address
    if not addr then
      error({code = M.ERROR.INVALID_PARAMS, message = "address is required"})
    end

    local wif, dump_err = wallet:dump_privkey(addr)
    if not wif then
      error({code = M.ERROR.WALLET_ERROR, message = dump_err or "Address not found in wallet"})
    end

    return wif
  end

  --- importprivkey: Import a private key.
  -- @param privkey string: Private key in WIF format
  -- @param label string: (ignored)
  -- @param rescan boolean: (ignored)
  self.methods["importprivkey"] = function(rpc, params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    if wallet.is_locked then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet is locked"})
    end

    local wif = params[1] or params.privkey
    if not wif then
      error({code = M.ERROR.INVALID_PARAMS, message = "privkey is required"})
    end

    local addr, import_err = wallet:import_privkey(wif)
    if not addr then
      error({code = M.ERROR.WALLET_ERROR, message = import_err or "Invalid private key"})
    end

    -- Save wallet
    if rpc.wallet_manager then
      for name, w in pairs(rpc.wallet_manager.wallets) do
        if w == wallet then
          local path = rpc.wallet_manager:get_wallet_path(name)
          wallet:save(path)
          break
        end
      end
    end

    return cjson.null
  end

  ----------------------------------------------------------------------------
  -- Additional Blockchain / Mining / Mempool RPCs
  ----------------------------------------------------------------------------

  --- getblockheader: Return block header by hash.
  -- @param hash string: Block hash hex
  -- @param verbose boolean: true for JSON, false for raw hex (default true)
  self.methods["getblockheader"] = function(rpc, params)
    local blockhash = params[1]
    local verbose = params[2]
    if verbose == nil or verbose == cjson.null then verbose = true end

    if type(blockhash) ~= "string" or #blockhash ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid block hash"})
    end
    if not rpc.storage then
      error({code = M.ERROR.MISC_ERROR, message = "Storage not available"})
    end

    local hash = types.hash256_from_hex(blockhash)
    local header = rpc.storage.get_header(hash)
    if not header then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Block not found"})
    end

    -- Verbosity false: return serialized header hex
    if not verbose then
      return M.hex_encode(serialize.serialize_block_header(header))
    end

    -- Look up height
    local block_height = nil
    if rpc.chain_state and rpc.chain_state.tip_height and rpc.storage.get_hash_by_height then
      for h = 0, rpc.chain_state.tip_height do
        local hh = rpc.storage.get_hash_by_height(h)
        if hh and hh.bytes == hash.bytes then
          block_height = h
          break
        end
      end
    end

    local confirmations = 1
    if block_height and rpc.chain_state and rpc.chain_state.tip_height then
      confirmations = rpc.chain_state.tip_height - block_height + 1
    end

    local difficulty = calculate_difficulty(header.bits)
    local mediantime = get_median_time_past(rpc.storage, hash)

    local nextblockhash = nil
    if block_height and rpc.storage.get_hash_by_height then
      local nh = rpc.storage.get_hash_by_height(block_height + 1)
      if nh then nextblockhash = types.hash256_hex(nh) end
    end

    local previousblockhash = nil
    local zero_hash = string.rep("\0", 32)
    if header.prev_hash and header.prev_hash.bytes ~= zero_hash then
      previousblockhash = types.hash256_hex(header.prev_hash)
    end

    return {
      hash = blockhash,
      confirmations = confirmations,
      height = block_height or 0,
      version = header.version,
      versionHex = string.format("%08x", header.version),
      merkleroot = types.hash256_hex(header.merkle_root),
      time = header.timestamp,
      mediantime = mediantime,
      nonce = header.nonce,
      bits = string.format("%08x", header.bits),
      difficulty = difficulty,
      chainwork = string.rep("0", 64),
      nTx = 0,
      previousblockhash = previousblockhash,
      nextblockhash = nextblockhash,
    }
  end

  --- getchaintips: Return information about all known chain tips.
  self.methods["getchaintips"] = function(rpc, _params)
    local tip_height = 0
    local tip_hash = types.hash256_zero()
    if rpc.chain_state then
      tip_height = rpc.chain_state.tip_height or 0
      tip_hash = rpc.chain_state.tip_hash or types.hash256_zero()
    end
    return {{
      height = tip_height,
      hash = types.hash256_hex(tip_hash),
      branchlen = 0,
      status = "active",
    }}
  end

  --- getdifficulty: Return the proof-of-work difficulty as a multiple of minimum.
  self.methods["getdifficulty"] = function(rpc, _params)
    local current_bits = rpc.network.pow_limit_bits
    if rpc.chain_state and rpc.storage then
      local tip_hash = rpc.chain_state.tip_hash
      if tip_hash then
        local header = rpc.storage.get_header(tip_hash)
        if header then
          current_bits = header.bits
        end
      end
    end
    return calculate_difficulty(current_bits)
  end

  --- submitblock: Submit a new block to the network.
  -- @param hexdata string: Block data in hex
  self.methods["submitblock"] = function(rpc, params)
    local hexdata = params[1]
    if type(hexdata) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Block hex data required"})
    end

    local t_start = os.clock()
    local raw = M.hex_decode(hexdata)
    local ok_deser, block = pcall(serialize.deserialize_block, raw)
    if not ok_deser or not block then
      error({code = M.ERROR.DESERIALIZATION_ERROR, message = "Block decode failed"})
    end
    local t_deser = os.clock()

    -- Basic validation
    local ok_val, val_err = pcall(validation.check_block, block)
    local t_validate = os.clock()
    if not ok_val then
      return tostring(val_err)
    end
    if not val_err then
      return "invalid"
    end

    -- Compute block hash
    local block_hash = validation.compute_block_hash(block.header)

    -- Check if this block extends our current tip
    if rpc.chain_state and rpc.chain_state.tip_height then
      local prev_hash = block.header.prev_hash
      local tip_hash = rpc.chain_state.tip_hash

      if not types.hash256_eq(prev_hash, tip_hash) then
        -- Block does not extend our tip. Check if it's a duplicate (already
        -- connected) by seeing if our chain already includes this hash.
        -- NOTE: We cannot use storage.get_header() for duplicate detection
        -- because headers are stored during header-first sync long before
        -- block bodies are downloaded and connected. Instead, check if the
        -- block data (not just header) exists in storage, which is only
        -- written after successful connection.
        if rpc.storage then
          local existing_block = rpc.storage.get(rpc.storage.CF.BLOCKS, block_hash.bytes)
          if existing_block then
            return "duplicate"
          end
        end
        return "prev-blk-not-found"
      end
    end

    -- Determine height: tip + 1 since we verified prev_hash == tip_hash above
    local new_height = (rpc.chain_state and rpc.chain_state.tip_height or 0) + 1

    -- If chain_state has a connect_block method, use it.
    -- Block/header/height_index storage writes are included in the same atomic
    -- WriteBatch as the UTXO flush and chain tip update via caller_batch_fn.
    -- This prevents a crash from leaving the height index pointing to a block
    -- whose UTXOs haven't been applied.
    if rpc.chain_state and rpc.chain_state.connect_block then
      -- During bulk import (many sequential submitblock calls), skip fsync on
      -- most blocks and only sync every 500 blocks to amortize the cost.
      -- After IBD, post-tip blocks are rare enough that always syncing is fine,
      -- but the height check below handles both cases.
      rpc._submitblock_count = (rpc._submitblock_count or 0) + 1
      local nosync = (rpc._submitblock_count % 500 ~= 0)

      -- Use the original raw bytes instead of re-serializing the block
      local block_data = raw
      local header_data = serialize.serialize_block_header(block.header)
      local height_key = string.char(
        math.floor(new_height / 16777216) % 256,
        math.floor(new_height / 65536) % 256,
        math.floor(new_height / 256) % 256,
        new_height % 256
      )
      local hash_bytes = block_hash.bytes
      local storage_ref = rpc.storage

      -- Batch function: write block, header, and height index atomically
      local store_batch_fn
      if storage_ref then
        store_batch_fn = function(batch)
          batch.put(storage_mod.CF.BLOCKS, hash_bytes, block_data)
          batch.put(storage_mod.CF.HEADERS, hash_bytes, header_data)
          batch.put(storage_mod.CF.HEIGHT_INDEX, height_key, hash_bytes)
        end
      end

      local ok_conn, conn_err = pcall(rpc.chain_state.connect_block, rpc.chain_state, block, new_height, block_hash, nil, nil, true, nil, nosync, store_batch_fn)
      local t_connect = os.clock()
      if not ok_conn then
        return tostring(conn_err)
      end
      if not conn_err then
        return "invalid"
      end

      -- Periodic timing log
      if new_height % 100 == 0 then
        io.stderr:write(string.format(
          "Block %d: deser=%.3f val=%.3f connect=%.3f total=%.3f txs=%d\n",
          new_height, t_deser - t_start, t_validate - t_deser,
          t_connect - t_validate, t_connect - t_start, #block.transactions))
      end

      -- Clear cached serialization data to free memory
      for _, tx in ipairs(block.transactions) do
        tx._cached_base_data = nil
        tx._cached_witness_data = nil
        tx._cached_txid = nil
        tx._cached_wtxid = nil
      end
    elseif rpc.storage then
      -- No chain_state — just store block data (fallback, shouldn't happen in practice)
      rpc.storage.put_block(block_hash, block)
      rpc.storage.put_header(block_hash, block.header)
      rpc.storage.put_height_index(new_height, block_hash)
    end

    -- Sync block_downloader so P2P sync doesn't try to re-connect this block
    if rpc.block_downloader and rpc.block_downloader.next_connect_height then
      if new_height >= rpc.block_downloader.next_connect_height then
        rpc.block_downloader.next_connect_height = new_height + 1
        rpc.block_downloader.next_download_height = new_height + 1
        -- Clear any pending/inflight for the block we just connected
        local connected_hex = types.hash256_hex(block_hash)
        rpc.block_downloader.pending_blocks[connected_hex] = nil
        if rpc.block_downloader.inflight[connected_hex] then
          local inf = rpc.block_downloader.inflight[connected_hex]
          if rpc.block_downloader.peer_inflight[inf.peer] then
            rpc.block_downloader.peer_inflight[inf.peer] = rpc.block_downloader.peer_inflight[inf.peer] - 1
            if rpc.block_downloader.peer_inflight[inf.peer] <= 0 then
              rpc.block_downloader.peer_inflight[inf.peer] = nil
            end
          end
          rpc.block_downloader.inflight[connected_hex] = nil
        end
      end
    end

    -- Notify mempool of new block
    if rpc.mempool then
      rpc.mempool:on_block_connected(block)
    end

    return cjson.null  -- success
  end

  --- getmininginfo: Return mining-related information.
  self.methods["getmininginfo"] = function(rpc, _params)
    local tip_height = 0
    local difficulty = 1.0
    local current_bits = rpc.network.pow_limit_bits

    if rpc.chain_state then
      tip_height = rpc.chain_state.tip_height or 0
      if rpc.storage and rpc.chain_state.tip_hash then
        local header = rpc.storage.get_header(rpc.chain_state.tip_hash)
        if header then
          current_bits = header.bits
          difficulty = calculate_difficulty(header.bits)
        end
      end
    end

    local pooledtx = 0
    if rpc.mempool then
      pooledtx = rpc.mempool.tx_count or 0
    end

    return {
      blocks = tip_height,
      difficulty = difficulty,
      networkhashps = 0,
      pooledtx = pooledtx,
      chain = rpc.network.name,
    }
  end

  --- listtransactions: Return recent transactions for a wallet.
  -- @param label string: Label filter (unused, "*" for all)
  -- @param count number: Number of transactions (default 10)
  -- @param skip number: Number to skip (default 0)
  self.methods["listtransactions"] = function(rpc, params)
    local _label = params[1] or "*"
    local count = params[2] or 10
    local skip = params[3] or 0

    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    -- If the wallet has a get_transactions method, use it
    if wallet.get_transactions then
      local txns = wallet:get_transactions(count, skip)
      return txns or {}
    end

    -- Fallback: return empty list
    return {}
  end

  --- testmempoolaccept: Dry-run mempool validation for raw transactions.
  -- @param rawtxs table: Array of hex-encoded raw transactions
  self.methods["testmempoolaccept"] = function(rpc, params)
    local rawtxs = params[1]
    if type(rawtxs) ~= "table" then
      error({code = M.ERROR.INVALID_PARAMS, message = "rawtxs must be an array"})
    end

    if not rpc.mempool then
      error({code = M.ERROR.MISC_ERROR, message = "Mempool not available"})
    end

    local results = {}
    for _, hex in ipairs(rawtxs) do
      local entry = {txid = "", allowed = false}
      local ok_d, tx = pcall(function()
        local raw = M.hex_decode(hex)
        return serialize.deserialize_transaction(raw)
      end)
      if not ok_d or not tx then
        entry["reject-reason"] = "decode-failed"
        results[#results + 1] = entry
      else
        local txid = validation.compute_txid(tx)
        entry.txid = types.hash256_hex(txid)
        -- Check basic structure
        local ok_chk, chk_ok, is_coinbase = pcall(validation.check_transaction, tx)
        if not ok_chk or not chk_ok then
          entry["reject-reason"] = "invalid-structure"
        elseif is_coinbase then
          entry["reject-reason"] = "coinbase"
        elseif rpc.mempool.entries[entry.txid] then
          entry["reject-reason"] = "txn-already-in-mempool"
        else
          -- Dry-run: attempt acceptance and then roll back
          -- For simplicity, just check if accept_transaction would succeed
          -- without actually modifying the mempool.
          -- We use a lightweight check here.
          local weight = validation.get_tx_weight(tx)
          local vsize = math.ceil(weight / consensus.WITNESS_SCALE_FACTOR)
          entry.vsize = vsize
          entry.allowed = true
          -- Try to compute fees
          local input_total = 0
          local missing = false
          for _, inp in ipairs(tx.inputs) do
            local mempool_mod = require("lunarblock.mempool")
            local outpoint_key = mempool_mod.outpoint_key(inp.prev_out.hash, inp.prev_out.index)
            local utxo = rpc.chain_state and rpc.chain_state.coin_view and
                         rpc.chain_state.coin_view:get(inp.prev_out.hash, inp.prev_out.index)
            if utxo then
              input_total = input_total + utxo.value
            else
              missing = true
            end
          end
          if missing then
            entry.allowed = false
            entry["reject-reason"] = "missing-inputs"
          else
            local output_total = 0
            for _, out in ipairs(tx.outputs) do
              output_total = output_total + out.value
            end
            local fee = input_total - output_total
            if fee < 0 then
              entry.allowed = false
              entry["reject-reason"] = "outputs-exceed-inputs"
            else
              entry.fees = {base = fee / 1e8}
            end
          end
        end
        results[#results + 1] = entry
      end
    end
    return results
  end
end

--------------------------------------------------------------------------------
-- HTTP Server
--------------------------------------------------------------------------------

function RPCServer:start()
  self.server_socket = socket.tcp()
  self.server_socket:setoption("reuseaddr", true)
  assert(self.server_socket:bind(self.host, self.port))
  assert(self.server_socket:listen(32))
  self.server_socket:settimeout(0)  -- Non-blocking accept
  self.running = true
  print("RPC server listening on " .. self.host .. ":" .. self.port)
end

function RPCServer:tick()
  if not self.running then return end

  -- Accept a new connection
  local client = self.server_socket:accept()
  if not client then return end

  client:settimeout(5)
  -- Read HTTP headers line-by-line, then read exact body by Content-Length.
  -- This avoids the LuaSocket receive(n) blocking issue where it waits for
  -- exactly n bytes or timeout.
  local headers_raw = {}
  local content_length = 0
  while true do
    local line, err = client:receive("*l")
    if not line or line == "" then break end  -- empty line = end of headers
    if err then break end
    headers_raw[#headers_raw + 1] = line
    local cl = line:match("^[Cc]ontent%-[Ll]ength:%s*(%d+)")
    if cl then content_length = tonumber(cl) end
  end
  -- Read exact body
  local body_data = ""
  if content_length > 0 then
    body_data = client:receive(content_length) or ""
  end
  -- Reconstruct full request for parse_http_request
  local data = table.concat(headers_raw, "\r\n") .. "\r\n\r\n" .. body_data

  if #data == 0 then
    client:close()
    return
  end

  local method, path, headers, body = M.parse_http_request(data)
  if not method then
    client:send(M.build_http_response(400, '{"error":"Bad request"}'))
    client:close()
    return
  end

  -- Check authentication
  if self.password ~= "" and not M.check_auth(headers, self.username, self.password) then
    client:send(M.build_http_response(401, '{"error":"Unauthorized"}'))
    client:close()
    return
  end

  -- Extract wallet name from path: /wallet/<name>
  local wallet_name = nil
  if path and path:match("^/wallet/") then
    wallet_name = path:match("^/wallet/(.+)$") or ""
  elseif path and path == "/wallet/" then
    wallet_name = ""
  end

  -- Set request wallet context
  self.request_wallet = nil
  if wallet_name and self.wallet_manager then
    local wallet = self.wallet_manager:get_wallet(wallet_name)
    if wallet then
      self.request_wallet = wallet
    end
  end

  -- Handle JSON-RPC
  if method == "POST" then
    local response_body, status_override = self:handle_request(body, wallet_name)
    local status = status_override or 200
    client:send(M.build_http_response(status, response_body))
  else
    client:send(M.build_http_response(404, '{"error":"Not found"}'))
  end

  -- Clear request context
  self.request_wallet = nil

  client:close()
end

function RPCServer:stop()
  self.running = false
  if self.server_socket then
    self.server_socket:close()
    self.server_socket = nil
  end
end

return M
