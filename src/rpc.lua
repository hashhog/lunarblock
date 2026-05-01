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

-- Fast hex encode using pre-built lookup table
local _hex_chars = {}
for i = 0, 255 do _hex_chars[i] = string.format("%02x", i) end

function M.hex_encode(data)
  local hex = {}
  for i = 1, #data do
    hex[i] = _hex_chars[data:byte(i)]
  end
  return table.concat(hex)
end

-- Fast hex decode using FFI: single allocation instead of per-byte strings
local ffi = require("ffi")
local _hex_lut = ffi.new("uint8_t[256]")
for i = 0, 255 do _hex_lut[i] = 255 end
for i = 0, 9 do _hex_lut[string.byte("0") + i] = i end
for i = 0, 5 do _hex_lut[string.byte("a") + i] = 10 + i end
for i = 0, 5 do _hex_lut[string.byte("A") + i] = 10 + i end

function M.hex_decode(hex)
  local len = #hex
  if len == 0 then return "" end
  local out_len = math.floor(len / 2)
  local buf = ffi.new("uint8_t[?]", out_len)
  for i = 0, out_len - 1 do
    local hi = _hex_lut[hex:byte(i * 2 + 1)]
    local lo = _hex_lut[hex:byte(i * 2 + 2)]
    buf[i] = hi * 16 + lo
  end
  return ffi.string(buf, out_len)
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
  -- Assumevalid ancestor-check callbacks (from consensus.make_assumevalid_callbacks)
  self.header_chain = config.header_chain
  self.av_in_index = config.av_in_index
  self.av_is_ancestor = config.av_is_ancestor
  self.av_on_best_chain = config.av_on_best_chain
  -- Pruner (lunarblock.prune) — when enabled, gates block-body lookups
  -- and exposes pruneheight / automatic_pruning in getblockchaininfo.
  -- nil/disabled is the historical default.
  self.pruner = config.pruner
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
-- Shared softfork/deployment helper
--------------------------------------------------------------------------------

-- build_deployment_state: single source of truth for buried-softfork state.
-- Returns a table keyed by deployment name, each value being:
--   { type, active, height, min_activation_height }
-- Both getblockchaininfo (via .softforks) and getdeploymentinfo (via
-- .deployments) project from this table; neither reads from a stale cache or
-- a hard-coded activation table of its own.
--
-- @param tip_height  number  current chain tip height (or target block height)
-- @param net         table   network params (rpc.network)
-- @return table
local function build_deployment_state(tip_height, net)
  local function buried_entry(activation_height)
    local h = activation_height or 0
    return {
      type                = "buried",
      active              = tip_height >= h,
      height              = h,
      min_activation_height = h,
    }
  end

  local deployments = {}

  if net.bip34_height then
    deployments.bip34 = buried_entry(net.bip34_height)
  end
  if net.bip65_height then
    deployments.bip65 = buried_entry(net.bip65_height)
  end
  if net.bip66_height then
    deployments.bip66 = buried_entry(net.bip66_height)
  end
  if net.csv_height then
    deployments.csv = buried_entry(net.csv_height)
  end
  if net.segwit_height then
    deployments.segwit = buried_entry(net.segwit_height)
  end
  if net.taproot_height then
    deployments.taproot = buried_entry(net.taproot_height)
  end

  -- testdummy: not tracked independently; always buried-active.
  -- On regtest all softforks activate at height 0; on mainnet/testnet this
  -- deployment was only ever a test vehicle and is always active.
  deployments.testdummy = {
    type                = "buried",
    active              = true,
    height              = 0,
    min_activation_height = 0,
  }

  return deployments
end

-- Expose for testing
M.build_deployment_state = build_deployment_state

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

    -- Build softforks table via the shared deployment helper so that
    -- getblockchaininfo.softforks and getdeploymentinfo.deployments always
    -- read from the same source of truth.
    local softforks = build_deployment_state(tip_height, rpc.network)

    -- Pruning fields. We mirror Bitcoin Core's getblockchaininfo output
    -- shape (rpc/blockchain.cpp:1447-1456): `pruned` is always present;
    -- `pruneheight` and `automatic_pruning` are only added when prune
    -- mode is on. `pruneheight` is the first UNPRUNED block (Bitcoin
    -- Core: prune_height ? value+1 : 0).
    local pruner = rpc.pruner
    local is_pruned = pruner and pruner.enabled or false
    local result = {
      chain = rpc.network.name,
      blocks = tip_height,
      headers = header_height,
      bestblockhash = types.hash256_hex(tip_hash),
      difficulty = difficulty,
      mediantime = mediantime,
      verificationprogress = verification_progress,
      initialblockdownload = initial_block_download,
      chainwork = chainwork,
      pruned = is_pruned,
      softforks = softforks,
    }
    if is_pruned then
      result.pruneheight = pruner.prune_height > 0
        and (pruner.prune_height + 1) or 0
      result.automatic_pruning = pruner.automatic and true or false
      if pruner.automatic then
        -- Bytes, matching Bitcoin Core's `prune_target_size`
        result.prune_target_size = pruner.target_mb * 1024 * 1024
      end
    end
    return result
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
      -- Check whether this is a known-but-pruned block. We never delete
      -- CF.HEADERS, so the header is still around even after the body
      -- is pruned. If header exists AND its height has been pruned,
      -- mirror Bitcoin Core's RPC_MISC_ERROR + "Block not available
      -- (pruned data)" string (rpc/blockchain.cpp:677).
      if rpc.pruner and rpc.pruner.enabled then
        local header = rpc.storage.get_header(hash)
        if header then
          -- Reverse-lookup height for this hash via the height index.
          -- This is O(prune_height) worst case but only runs on the
          -- error path; fast path (block present) never reaches here.
          local found_height = nil
          local iter = rpc.storage.iterator("height")
          if iter then
            iter.seek_to_first()
            while iter.valid() do
              local v = iter.value()
              if v and #v == 32 and v == hash.bytes then
                local k = iter.key()
                found_height = k:byte(1) * 16777216 + k:byte(2) * 65536
                  + k:byte(3) * 256 + k:byte(4)
                break
              end
              iter.next()
            end
            iter.destroy()
          end
          if found_height and rpc.pruner:is_pruned(found_height) then
            error({code = M.ERROR.MISC_ERROR,
                   message = "Block not available (pruned data)"})
          end
        end
      end
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

  -- W70: canonical sync-state RPC. See spec/getsyncstate.md in the
  -- hashhog meta-repo for the full field-by-field contract.
  self.methods["getsyncstate"] = function(rpc, _params)
    local tip_height = 0
    local tip_hash = types.hash256_zero()
    if rpc.chain_state then
      tip_height = rpc.chain_state.tip_height or 0
      tip_hash = rpc.chain_state.tip_hash or tip_hash
    end

    local best_header_height = tip_height
    local best_header_hash = tip_hash
    if rpc.header_chain then
      if rpc.header_chain.header_tip_height and rpc.header_chain.header_tip_height >= 0 then
        best_header_height = rpc.header_chain.header_tip_height
      end
      if rpc.header_chain.header_tip_hash then
        best_header_hash = rpc.header_chain.header_tip_hash
      end
    end

    -- IBD: tip is >24h behind wall clock by the header timestamp of
    -- the current best block, or we have no tip at all. Matches the
    -- logic already in getblockchaininfo.
    local ibd = true
    if rpc.storage and rpc.chain_state and rpc.chain_state.tip_hash then
      local header = rpc.storage.get_header(rpc.chain_state.tip_hash)
      if header then
        local age = os.time() - header.timestamp
        ibd = age > 24 * 60 * 60
      end
    end

    local num_peers = 0
    if rpc.peer_manager then
      num_peers = #rpc.peer_manager.peer_list
    end

    -- verification_progress: tip / best_header_height, clamped to [0, 1].
    local verification_progress = cjson.null
    if best_header_height > 0 then
      local vp = tip_height / best_header_height
      if vp > 1.0 then vp = 1.0 end
      if vp < 0.0 then vp = 0.0 end
      verification_progress = vp
    end

    local blocks_in_flight = cjson.null
    local blocks_pending_connect = cjson.null
    if rpc.block_downloader then
      if rpc.block_downloader.get_inflight_count then
        blocks_in_flight = rpc.block_downloader:get_inflight_count()
      end
      if rpc.block_downloader.get_pending_count then
        blocks_pending_connect = rpc.block_downloader:get_pending_count()
      end
    end

    -- Chain label in Bitcoin Core's canonical shape.
    local chain_label = cjson.null
    if rpc.network and rpc.network.name then
      local name = rpc.network.name
      if name == "mainnet" then
        chain_label = "main"
      elseif name == "testnet" or name == "testnet3" then
        chain_label = "test"
      else
        -- testnet4, signet, regtest are identical in both conventions.
        chain_label = name
      end
    end

    return {
      tip_height = tip_height,
      tip_hash = types.hash256_hex(tip_hash),
      best_header_height = best_header_height,
      best_header_hash = types.hash256_hex(best_header_hash),
      initial_block_download = ibd,
      num_peers = num_peers,
      verification_progress = verification_progress,
      blocks_in_flight = blocks_in_flight,
      blocks_pending_connect = blocks_pending_connect,
      -- Lunarblock does not currently track the wall-clock time of the
      -- last tip advance; morning reviewers add if needed.
      last_block_received_time = cjson.null,
      chain = chain_label,
      protocol_version = p2p.PROTOCOL_VERSION,
    }
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
      incrementalrelayfee = 0.00001,
      unbroadcastcount = 0,
      fullrbf = true,
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
        local fee_btc = entry.fee / consensus.COIN
        result[txid_hex] = {
          vsize = entry.vsize,
          weight = entry.weight,
          fee = fee_btc,
          modifiedfee = fee_btc,
          time = entry.time,
          height = entry.height,
          descendantcount = entry.descendant_count or 1,
          descendantsize = entry.descendant_size or entry.vsize,
          descendantfees = entry.descendant_fees or entry.fee,
          ancestorcount = entry.ancestor_count or 1,
          ancestorsize = entry.ancestor_size or entry.vsize,
          ancestorfees = entry.ancestor_fees or entry.fee,
          wtxid = entry.wtxid or txid_hex,
          fees = {
            base = fee_btc,
            modified = fee_btc,
            ancestor = (entry.ancestor_fees or entry.fee) / consensus.COIN,
            descendant = (entry.descendant_fees or entry.fee) / consensus.COIN,
          },
          depends = entry.depends or {},
          spentby = entry.spent_by or {},
          ["bip125-replaceable"] = true,
          unbroadcast = false,
        }
      end
    end
    return result
  end

  -- Bitcoin Core-compatible mempool.dat dump/load.
  -- See bitcoin-core/src/node/mempool_persist.cpp for the on-disk format.
  -- The file lives at <datadir>/mempool.dat by convention; an explicit
  -- absolute path may be passed as params[1].
  self.methods["dumpmempool"] = function(rpc, params)
    if not rpc.mempool then
      error({code = M.ERROR.MISC_ERROR, message = "Mempool not available"})
    end
    if not rpc.datadir then
      error({code = M.ERROR.MISC_ERROR, message = "Datadir not configured"})
    end
    local mempool_persist_mod = require("lunarblock.mempool_persist")
    local path = (params and params[1]) or (rpc.datadir .. "/mempool.dat")
    local ok, count_or_err = mempool_persist_mod.dump(rpc.mempool, path)
    if not ok then
      error({code = M.ERROR.MISC_ERROR,
        message = "Could not dump mempool: " .. tostring(count_or_err)})
    end
    return { filename = path, count = count_or_err }
  end

  self.methods["loadmempool"] = function(rpc, params)
    if not rpc.mempool then
      error({code = M.ERROR.MISC_ERROR, message = "Mempool not available"})
    end
    if not rpc.datadir then
      error({code = M.ERROR.MISC_ERROR, message = "Datadir not configured"})
    end
    local mempool_persist_mod = require("lunarblock.mempool_persist")
    local path = (params and params[1]) or (rpc.datadir .. "/mempool.dat")
    local ok, stats = mempool_persist_mod.load(rpc.mempool, path)
    if not ok then
      error({code = M.ERROR.MISC_ERROR,
        message = "Could not load mempool: " .. tostring(stats)})
    end
    return {
      filename = path,
      accepted = stats.count or 0,
      failed = stats.failed or 0,
      expired = stats.expired or 0,
      already_there = stats.already_there or 0,
    }
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
    local connections_in = 0
    local connections_out = 0
    if rpc.peer_manager then
      connections = #rpc.peer_manager.peer_list
      for _, p in ipairs(rpc.peer_manager.peer_list) do
        if p.inbound then
          connections_in = connections_in + 1
        else
          connections_out = connections_out + 1
        end
      end
    end
    return {
      version = 250000,
      subversion = "/LunarBlock:0.1.0/",
      protocolversion = p2p.PROTOCOL_VERSION,
      localservices = "0000000000000009",
      localservicesnames = {"NETWORK", "WITNESS"},
      localrelay = true,
      timeoffset = 0,
      networkactive = true,
      connections = connections,
      connections_in = connections_in,
      connections_out = connections_out,
      networks = {
        {name = "ipv4", limited = false, reachable = true, proxy = "", proxy_randomize_credentials = false},
        {name = "ipv6", limited = false, reachable = true, proxy = "", proxy_randomize_credentials = false},
      },
      relayfee = 0.00001,
      incrementalfee = 0.00001,
      localaddresses = {},
      warnings = "",
    }
  end

  self.methods["getpeerinfo"] = function(rpc, _params)
    local peers = {}
    if rpc.peer_manager then
      for i, p in ipairs(rpc.peer_manager.peer_list) do
        local svc = p.services or 0
        local svc_names = {}
        if bit.band(svc, 1) ~= 0 then svc_names[#svc_names + 1] = "NETWORK" end
        if bit.band(svc, 8) ~= 0 then svc_names[#svc_names + 1] = "WITNESS" end
        if bit.band(svc, 1024) ~= 0 then svc_names[#svc_names + 1] = "NETWORK_LIMITED" end
        local is_inbound = p.inbound or false
        peers[#peers + 1] = {
          id = i - 1,
          addr = p.ip .. ":" .. p.port,
          network = "ipv4",
          services = string.format("%016x", svc),
          servicesnames = svc_names,
          relaytxes = (p.version_info and p.version_info.relay) or true,
          lastsend = math.floor(p.last_send or 0),
          lastrecv = math.floor(p.last_recv or 0),
          bytessent = p.bytes_sent or 0,
          bytesrecv = p.bytes_recv or 0,
          conntime = math.floor(p.conn_time or 0),
          timeoffset = (p.version_info and p.version_recv_time and p.version_recv_time > 0)
            and (p.version_info.timestamp - math.floor(p.version_recv_time))
            or 0,
          pingtime = (p.latency_ms or 0) / 1000,
          version = (p.version_info and p.version_info.version) or 0,
          subver = p.user_agent or "",
          inbound = is_inbound,
          bip152_hb_to = false,
          bip152_hb_from = false,
          startingheight = p.start_height or 0,
          synced_headers = -1,
          synced_blocks = -1,
          inflight = {},
          connection_type = is_inbound and "inbound" or "outbound-full-relay",
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

  -- Manual peer control — minimal Bitcoin Core `addnode` parity.  Supports
  -- "onetry" and "add" (both initiate an outbound connection) and "remove"
  -- (disconnect + forget).  Used by the hashhog localhost IBD mesh (see
  -- memory/project_local_peer_ibd_setup.md).
  --
  -- BIP324 v2 negotiation: addnode follows the same path as automatic
  -- outbound peers — `connect_peer` defaults to v2 unless the node was
  -- launched with `--nov2transport`, identical to the inbound responder
  -- path in `accept_inbound`.  The previous always-on localhost v1 force
  -- was a debugging artifact from when not every fleet sibling spoke v2;
  -- operators who still want it can pass `--nov2transport` (global) and
  -- rustoshi/haskoin/hotbuns inbounds will negotiate v1 the same way.
  self.methods["addnode"] = function(rpc, params)
    local node = params and params[1]
    local command = params and params[2]
    if type(node) ~= "string" or type(command) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "addnode requires <node> <command>"})
    end
    if not rpc.peer_manager then
      error({code = M.ERROR.MISC_ERROR, message = "peer manager not available"})
    end
    local ip, port_str = node:match("^([^:]+):?(%d*)$")
    if not ip or ip == "" then
      error({code = M.ERROR.INVALID_PARAMS, message = "invalid node address: " .. node})
    end
    local port = tonumber(port_str)
    if not port or port == 0 then
      port = rpc.peer_manager.network and rpc.peer_manager.network.port or 8333
    end
    -- Defer to connect_peer's default (config.nov2transport).  No
    -- per-target override — keeps the negotiation path identical for
    -- localhost and remote targets, matching the inbound side.
    local use_v2_override = nil
    local key = ip .. ":" .. port
    if command == "add" then
      -- Persist: register in manual_peers so the tick-level
      -- _reconnect_manual_peers() keeps reconnecting after remote-side
      -- eviction.  Failure here is non-fatal — the reconnect loop will
      -- pick it up on the next tick.
      rpc.peer_manager.manual_peers[key] = {
        ip = ip,
        port = port,
        use_v2_override = use_v2_override,
        last_try = 0,
        attempts = 0,
        success_count = 0,
      }
      local ok, err = rpc.peer_manager:connect_peer(ip, port, true, use_v2_override, true)
      if not ok then
        -- Don't erase from manual_peers — reconnect loop owns the retry.
        -- Surface the first-attempt failure via RPC error for visibility.
        error({code = M.ERROR.MISC_ERROR, message = "initial connect failed (will retry): " .. tostring(err)})
      end
      return nil
    elseif command == "onetry" then
      -- One-shot: do NOT persist in manual_peers.
      local ok, err = rpc.peer_manager:connect_peer(ip, port, true, use_v2_override, true)
      if not ok then
        error({code = M.ERROR.MISC_ERROR, message = "failed to connect: " .. tostring(err)})
      end
      return nil
    elseif command == "remove" then
      rpc.peer_manager.manual_peers[key] = nil
      local p = rpc.peer_manager.peers and rpc.peer_manager.peers[key]
      if p then
        rpc.peer_manager:disconnect_peer(p, "removed by addnode RPC")
      end
      return nil
    else
      error({code = M.ERROR.INVALID_PARAMS, message = "invalid addnode command: " .. command})
    end
  end

  -- Fee estimation
  self.methods["estimatesmartfee"] = function(rpc, params)
    local conf_target = params[1] or 6
    if type(conf_target) ~= "number" then
      error({code = M.ERROR.INVALID_PARAMS, message = "conf_target must be numeric"})
    end
    conf_target = math.max(1, math.min(1008, math.floor(conf_target)))
    if rpc.fee_estimator then
      local fee_rate, actual_target = rpc.fee_estimator:estimate_smart_fee(conf_target)
      if fee_rate and fee_rate > 0 then
        return {
          feerate = fee_rate / 100000,  -- Convert sat/vB to BTC/kvB
          blocks = actual_target or conf_target,
        }
      end
    end
    return {errors = {"Insufficient data or no feerate found"}, blocks = conf_target}
  end

  -- estimaterawfee: raw fee estimator output for a confirmation target.
  -- Bitcoin Core: bitcoin-core/src/rpc/fees.cpp::estimaterawfee.  Returns one
  -- entry per estimation horizon (short=12, medium=144, long=1008 blocks); each
  -- entry exposes the raw bucket data ("feerate" + "decay"-weighted "pass" /
  -- "fail" counts).  We map the existing FeeEstimator to a single conservative
  -- bucket per horizon — the structure matches Core's response so RPC clients
  -- that expect the schema parse cleanly even when our estimator has less
  -- granular bucket data than Core's policy/fees.cpp.
  self.methods["estimaterawfee"] = function(rpc, params)
    local conf_target = params[1] or 6
    if type(conf_target) ~= "number" then
      error({code = M.ERROR.INVALID_PARAMS, message = "conf_target must be numeric"})
    end
    local threshold = params[2]
    if threshold ~= nil and threshold ~= cjson.null and type(threshold) ~= "number" then
      error({code = M.ERROR.INVALID_PARAMS, message = "threshold must be numeric"})
    end
    threshold = (type(threshold) == "number") and threshold or 0.95
    conf_target = math.max(1, math.min(1008, math.floor(conf_target)))

    local horizons = { short = 12, medium = 144, long = 1008 }
    local result = {}
    for name, _ in pairs(horizons) do
      local entry = { fail = cjson.null, errors = cjson.null }
      if rpc.fee_estimator then
        local fee_rate, reliable = rpc.fee_estimator:estimate_fee(conf_target, threshold)
        if fee_rate and fee_rate > 0 then
          entry.feerate = fee_rate / 100000  -- sat/vB -> BTC/kvB
          entry.decay = rpc.fee_estimator.decay or 0.998
          entry.scale = 1
          entry.pass = {
            startrange = fee_rate,
            endrange = fee_rate,
            withintarget = reliable and 1 or 0,
            totalconfirmed = reliable and 1 or 0,
            inmempool = 0,
            leftmempool = 0,
          }
        else
          entry.errors = { "Insufficient data or no feerate found" }
        end
      else
        entry.errors = { "Fee estimation not available" }
      end
      result[name] = entry
    end
    return result
  end

  --- signmessage / verifymessage (BIP-137 "Bitcoin Signed Message"):
  -- Bitcoin Core references:
  --   bitcoin-core/src/rpc/signmessage.cpp        (RPC entrypoints)
  --   bitcoin-core/src/common/signmessage.cpp     (MessageHash/MessageSign/MessageVerify)
  -- Hash construction:
  --   double-SHA256( varstr("Bitcoin Signed Message:\n") || varstr(message) ).
  -- Wire format: 65-byte signature, base64-encoded.
  --   header = 27 + recid + (compressed ? 4 : 0)
  -- We implement signmessagewithprivkey (no wallet keystore lookup) and
  -- verifymessage (P2PKH only — Core also rejects non-PKHash destinations).
  local MESSAGE_MAGIC = "Bitcoin Signed Message:\n"

  local function message_hash(message)
    local crypto = require("lunarblock.crypto")
    local w = serialize.buffer_writer()
    w.write_varstr(MESSAGE_MAGIC)
    w.write_varstr(message)
    return crypto.hash256(w.result())
  end

  -- signmessagewithprivkey "<wif_or_hex_privkey>" "<message>" -> base64 sig
  -- Wallet-keystore variant ("signmessage <address> <msg>") is gated on
  -- self.wallet / self.wallet_manager exposing per-address privkeys; we accept
  -- the same RPC name for parity but require the privkey form when no
  -- wallet keystore is available.  See TODO(rpc) below.
  self.methods["signmessagewithprivkey"] = function(_rpc, params)
    local privkey_str = params and params[1]
    local message = params and params[2]
    if type(privkey_str) ~= "string" or type(message) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "Usage: signmessagewithprivkey <privkey> <message>"})
    end
    local crypto = require("lunarblock.crypto")
    local privkey32, compressed
    -- Accept WIF or raw 64-hex
    local addr_mod = require("lunarblock.address")
    if #privkey_str == 64 and privkey_str:match("^[0-9A-Fa-f]+$") then
      privkey32 = M.hex_decode(privkey_str)
      compressed = true
    else
      -- Best-effort WIF decode
      local version, payload = addr_mod.base58check_decode(privkey_str)
      if not version or not payload then
        error({code = M.ERROR.INVALID_ADDRESS, message = "Invalid private key"})
      end
      if #payload == 33 and payload:byte(33) == 0x01 then
        privkey32 = payload:sub(1, 32)
        compressed = true
      elseif #payload == 32 then
        privkey32 = payload
        compressed = false
      else
        error({code = M.ERROR.INVALID_ADDRESS, message = "Invalid private key"})
      end
    end
    local h = message_hash(message)
    local sig65, err = crypto.ecdsa_sign_recoverable_compact(privkey32, h, compressed)
    if not sig65 then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Sign failed: " .. tostring(err)})
    end
    local psbt_mod = require("lunarblock.psbt")
    return psbt_mod.base64_encode(sig65)
  end

  -- signmessage <address> <message>: requires wallet keystore.  Until the
  -- wallet-keystore privkey lookup lands (TODO(rpc): wallet keystore
  -- per-address privkey export), behave like signmessagewithprivkey when
  -- callers pass a privkey string instead of an address, otherwise return
  -- WALLET_ERROR with a clear message.
  self.methods["signmessage"] = function(rpc, params)
    local addr_or_priv = params and params[1]
    local message = params and params[2]
    if type(addr_or_priv) ~= "string" or type(message) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "Usage: signmessage <address> <message>"})
    end
    -- Heuristic: a 64-char hex string is a privkey; otherwise probe
    -- decode_address (wrapped in pcall — it raises on non-base58 inputs
    -- that aren't bech32 either).
    local looks_like_privkey = (#addr_or_priv == 64
      and addr_or_priv:match("^[0-9A-Fa-f]+$") ~= nil)
    if not looks_like_privkey then
      local addr_mod = require("lunarblock.address")
      local ok, addr_type = pcall(addr_mod.decode_address, addr_or_priv,
        rpc.network and rpc.network.name)
      if ok and addr_type then
        -- Looks like an address; we'd need to look up the privkey by
        -- address in the wallet keystore.  Wallets in lunarblock currently
        -- expose HD-derived addresses but not a per-address privkey export
        -- hook on the RPC surface.
        -- TODO(rpc): wire signmessage <address> -> wallet:get_privkey_for_address.
        error({code = M.ERROR.WALLET_ERROR,
          message = "signmessage by address requires wallet keystore lookup; " ..
                    "use signmessagewithprivkey or pass a WIF/hex privkey directly"})
      end
    end
    -- Fall through: treat first arg as a privkey (WIF or 64-hex).
    return self.methods["signmessagewithprivkey"](rpc, params)
  end

  self.methods["verifymessage"] = function(rpc, params)
    local address = params and params[1]
    local signature = params and params[2]
    local message = params and params[3]
    if type(address) ~= "string" or type(signature) ~= "string" or type(message) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "Usage: verifymessage <address> <signature> <message>"})
    end
    local addr_mod = require("lunarblock.address")
    local crypto = require("lunarblock.crypto")
    local addr_type, addr_hash = addr_mod.decode_address(address, rpc.network and rpc.network.name)
    if not addr_type then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Invalid address"})
    end
    if addr_type ~= "p2pkh" then
      -- Bitcoin Core rejects non-PKHash destinations (RPC_TYPE_ERROR).
      error({code = M.ERROR.TYPE_ERROR, message = "Address does not refer to key"})
    end
    local sig65 = M.base64_decode(signature)
    if #sig65 ~= 65 then
      error({code = M.ERROR.TYPE_ERROR, message = "Malformed base64 encoding"})
    end
    local h = message_hash(message)
    local pub, err = crypto.ecdsa_recover_compact(sig65, h)
    if not pub then
      -- Not signed / pubkey not recovered -> Core returns false (not an error).
      return false
    end
    -- Compare hash160(pub) to the P2PKH hash160 in the address.
    local recovered_hash160 = crypto.hash160(pub)
    return recovered_hash160 == addr_hash
  end

  -- savemempool: alias for dumpmempool (Bitcoin Core: rpc/mempool.cpp::savemempool).
  -- Returns only the filename (Core's schema), not the full dump stats.
  self.methods["savemempool"] = function(rpc, params)
    if not rpc.mempool then
      error({code = M.ERROR.MISC_ERROR, message = "Mempool not available"})
    end
    if not rpc.datadir then
      error({code = M.ERROR.MISC_ERROR, message = "Datadir not configured"})
    end
    local mempool_persist_mod = require("lunarblock.mempool_persist")
    local path = (params and params[1]) or (rpc.datadir .. "/mempool.dat")
    local ok, count_or_err = mempool_persist_mod.dump(rpc.mempool, path)
    if not ok then
      error({code = M.ERROR.MISC_ERROR,
        message = "Unable to dump mempool to disk: " .. tostring(count_or_err)})
    end
    return { filename = path }
  end

  -- Mempool entry/ancestor/descendant introspection.
  -- Bitcoin Core: rpc/mempool.cpp::{getmempoolentry,getmempoolancestors,getmempooldescendants}.
  -- Each walks the in-memory CTxMemPool graph; we mirror that with the
  -- ancestor/descendant sets already maintained on each Mempool entry.
  local function format_mempool_entry(entry, txid_hex)
    local fee_btc = entry.fee / consensus.COIN
    return {
      vsize = entry.vsize,
      weight = entry.weight,
      fee = fee_btc,
      modifiedfee = fee_btc,
      time = entry.time,
      height = entry.height,
      descendantcount = entry.descendant_count or 1,
      descendantsize = entry.descendant_size or entry.vsize,
      descendantfees = entry.descendant_fees or entry.fee,
      ancestorcount = entry.ancestor_count or 1,
      ancestorsize = entry.ancestor_size or entry.vsize,
      ancestorfees = entry.ancestor_fees or entry.fee,
      wtxid = entry.wtxid or txid_hex,
      fees = {
        base = fee_btc,
        modified = fee_btc,
        ancestor = (entry.ancestor_fees or entry.fee) / consensus.COIN,
        descendant = (entry.descendant_fees or entry.fee) / consensus.COIN,
      },
      depends = entry.depends or {},
      spentby = entry.spent_by or {},
      ["bip125-replaceable"] = true,
      unbroadcast = false,
    }
  end

  self.methods["getmempoolentry"] = function(rpc, params)
    local txid_hex = params and params[1]
    if type(txid_hex) ~= "string" or #txid_hex ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid txid"})
    end
    if not rpc.mempool then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Transaction not in mempool"})
    end
    local entry = rpc.mempool:get_entry(txid_hex)
    if not entry then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Transaction not in mempool"})
    end
    return format_mempool_entry(entry, txid_hex)
  end

  self.methods["getmempoolancestors"] = function(rpc, params)
    local txid_hex = params and params[1]
    local verbose = (params and params[2]) or false
    if type(txid_hex) ~= "string" or #txid_hex ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid txid"})
    end
    if not rpc.mempool then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Transaction not in mempool"})
    end
    local entry = rpc.mempool:get_entry(txid_hex)
    if not entry then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Transaction not in mempool"})
    end
    if not verbose then
      local out = {}
      for anc_hex in pairs(entry.ancestors or {}) do
        out[#out + 1] = anc_hex
      end
      return out
    end
    local out = {}
    for anc_hex in pairs(entry.ancestors or {}) do
      local anc_entry = rpc.mempool:get_entry(anc_hex)
      if anc_entry then
        out[anc_hex] = format_mempool_entry(anc_entry, anc_hex)
      end
    end
    return out
  end

  self.methods["getmempooldescendants"] = function(rpc, params)
    local txid_hex = params and params[1]
    local verbose = (params and params[2]) or false
    if type(txid_hex) ~= "string" or #txid_hex ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid txid"})
    end
    if not rpc.mempool then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Transaction not in mempool"})
    end
    local entry = rpc.mempool:get_entry(txid_hex)
    if not entry then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Transaction not in mempool"})
    end
    if not verbose then
      local out = {}
      for desc_hex in pairs(entry.descendants or {}) do
        out[#out + 1] = desc_hex
      end
      return out
    end
    local out = {}
    for desc_hex in pairs(entry.descendants or {}) do
      local desc_entry = rpc.mempool:get_entry(desc_hex)
      if desc_entry then
        out[desc_hex] = format_mempool_entry(desc_entry, desc_hex)
      end
    end
    return out
  end

  -- gettxout: return UTXO info if unspent at the chain tip.
  -- Bitcoin Core: src/rpc/blockchain.cpp::gettxout.
  -- Reads through chain_state.coin_view (which transparently consults the
  -- in-memory cache then the RocksDB UTXO column family).  The
  -- include_mempool branch matches Core's CCoinsViewMemPool wrapper:
  -- a tx in mempool that spends the outpoint hides it; a tx in mempool that
  -- creates the outpoint exposes it (with confirmations=0).
  self.methods["gettxout"] = function(rpc, params)
    local txid_hex = params and params[1]
    local n = params and params[2]
    local include_mempool = true
    if params and params[3] ~= nil and params[3] ~= cjson.null then
      include_mempool = params[3] and true or false
    end
    if type(txid_hex) ~= "string" or #txid_hex ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid txid"})
    end
    if type(n) ~= "number" or n < 0 or n ~= math.floor(n) then
      error({code = M.ERROR.INVALID_PARAMS, message = "vout must be a non-negative integer"})
    end
    if not rpc.chain_state or not rpc.chain_state.coin_view then
      error({code = M.ERROR.MISC_ERROR, message = "Chain state not available"})
    end

    local txid = types.hash256_from_hex(txid_hex)

    -- Check if mempool spends this outpoint (hides confirmed UTXO).
    if include_mempool and rpc.mempool then
      local mempool_mod = require("lunarblock.mempool")
      local op_key = mempool_mod.outpoint_key(txid, n)
      local spender = rpc.mempool.outpoint_to_tx and rpc.mempool.outpoint_to_tx[op_key]
      if spender then
        return cjson.null
      end
    end

    local entry = rpc.chain_state.coin_view:get(txid, n)
    local utxo_height = entry and entry.height
    local is_coinbase = entry and entry.is_coinbase or false

    -- If not in confirmed UTXO and mempool inclusion is on, see if a
    -- mempool tx creates this output (height=0/MEMPOOL_HEIGHT semantics).
    if not entry and include_mempool and rpc.mempool then
      local mp_entry = rpc.mempool:get_entry(txid_hex)
      if mp_entry and mp_entry.tx and mp_entry.tx.outputs[n + 1] then
        local out = mp_entry.tx.outputs[n + 1]
        entry = {
          value = out.value,
          script_pubkey = out.script_pubkey,
          height = nil,
          is_coinbase = false,
        }
        is_coinbase = false
        utxo_height = nil  -- signals mempool height -> confirmations=0
      end
    end

    if not entry then
      return cjson.null
    end

    local tip_height = rpc.chain_state.tip_height or 0
    local tip_hash_hex
    if rpc.chain_state.tip_hash then
      tip_hash_hex = types.hash256_hex(rpc.chain_state.tip_hash)
    else
      tip_hash_hex = string.rep("0", 64)
    end
    local confirmations
    if utxo_height then
      confirmations = math.max(0, tip_height - utxo_height + 1)
    else
      confirmations = 0
    end

    return {
      bestblock = tip_hash_hex,
      confirmations = confirmations,
      value = entry.value / consensus.COIN,
      scriptPubKey = M.decode_script_pubkey(entry.script_pubkey, rpc.network),
      coinbase = is_coinbase,
    }
  end

  -- disconnectnode: address (ip:port) OR nodeid.  Bitcoin Core:
  -- src/rpc/net.cpp::disconnectnode.  Returns null on success; raises
  -- CLIENT_NODE_NOT_CONNECTED-style error if no such peer.
  self.methods["disconnectnode"] = function(rpc, params)
    if not rpc.peer_manager then
      error({code = M.ERROR.MISC_ERROR, message = "peer manager not available"})
    end
    local address = params and params[1]
    local nodeid = params and params[2]
    if (address == nil or address == cjson.null or address == "") and
       (nodeid == nil or nodeid == cjson.null) then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "Either 'address' or 'nodeid' must be provided"})
    end
    if address ~= nil and address ~= cjson.null and address ~= "" and
       nodeid ~= nil and nodeid ~= cjson.null then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "Only one of 'address' or 'nodeid' must be provided"})
    end

    local target_peer = nil
    if type(address) == "string" and #address > 0 then
      target_peer = rpc.peer_manager.peers and rpc.peer_manager.peers[address]
      if not target_peer then
        -- Linear search: peers may be keyed by canonical "ip:port" but caller
        -- could pass "ip" without port; match either.
        for _, p in ipairs(rpc.peer_manager.peer_list or {}) do
          if (p.ip .. ":" .. p.port) == address or p.ip == address then
            target_peer = p
            break
          end
        end
      end
    elseif type(nodeid) == "number" then
      -- nodeid is the 0-based index into peer_list (matches getpeerinfo "id").
      local pl = rpc.peer_manager.peer_list or {}
      target_peer = pl[nodeid + 1]
    end

    if not target_peer then
      error({code = -29 --[[ CLIENT_NODE_NOT_CONNECTED ]],
        message = "Node not found in connected nodes"})
    end
    rpc.peer_manager:disconnect_peer(target_peer, "disconnectnode RPC")
    -- Also unlink from manual_peers so the reconnect loop does not undo us.
    if rpc.peer_manager.manual_peers then
      local key = target_peer.ip .. ":" .. target_peer.port
      rpc.peer_manager.manual_peers[key] = nil
    end
    return cjson.null
  end

  -- getnettotals: cumulative bytes-in / bytes-out.  Bitcoin Core:
  -- src/rpc/net.cpp::getnettotals -> CConnman::GetTotalBytesRecv /
  -- GetTotalBytesSent (src/net.cpp).  Core keeps a single pair of monotonic
  -- counters that DON'T reset when a peer disconnects.
  --
  -- Implementation: PeerManager.totals = {bytes_recv, bytes_sent} are the
  -- cumulative globals; disconnect_peer / stop accumulate the final
  -- per-peer counters into them.  At RPC time we add the still-connected
  -- peers' counters on top so the number is up-to-the-second.
  self.methods["getnettotals"] = function(rpc, _params)
    local total_recv = 0
    local total_sent = 0
    if rpc.peer_manager then
      if rpc.peer_manager.totals then
        total_recv = total_recv + (rpc.peer_manager.totals.bytes_recv or 0)
        total_sent = total_sent + (rpc.peer_manager.totals.bytes_sent or 0)
      end
      if rpc.peer_manager.peer_list then
        for _, p in ipairs(rpc.peer_manager.peer_list) do
          total_recv = total_recv + (p.bytes_recv or 0)
          total_sent = total_sent + (p.bytes_sent or 0)
        end
      end
    end
    return {
      totalbytesrecv = total_recv,
      totalbytessent = total_sent,
      timemillis = math.floor(socket.gettime() * 1000),
      uploadtarget = {
        timeframe = 86400,
        target = 0,
        target_reached = false,
        serve_historical_blocks = true,
        bytes_left_in_cycle = 0,
        time_left_in_cycle = 0,
      },
    }
  end

  -- getblockstats: per-block statistics.  Bitcoin Core:
  -- src/rpc/blockchain.cpp::getblockstats.  Selectable stat keys via
  -- params[2]; default is everything we can compute without the block-undo
  -- (which would give us per-input prevout values for fees / feerates).
  --
  -- Limits:
  --   * Stats that need fees or input prevout values (avgfee, totalfee,
  --     avgfeerate, min/maxfee, min/maxfeerate, medianfee,
  --     feerate_percentiles, utxo_increase_actual, utxo_size_inc_actual)
  --     require the block-undo data; we expose them when storage.get_undo
  --     returns data, otherwise mark as `nil` (Core sets them to 0 for the
  --     genesis block — matching that convention only when undo is missing).
  self.methods["getblockstats"] = function(rpc, params)
    if not rpc.storage or not rpc.chain_state then
      error({code = M.ERROR.MISC_ERROR, message = "Storage not available"})
    end
    local hash_or_height = params and params[1]
    if hash_or_height == nil or hash_or_height == cjson.null then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "hash_or_height is required"})
    end

    local block_hash, height
    if type(hash_or_height) == "number" then
      height = math.floor(hash_or_height)
      if rpc.storage.get_hash_by_height then
        block_hash = rpc.storage.get_hash_by_height(height)
      end
      if not block_hash then
        error({code = M.ERROR.INVALID_PARAMS,
          message = "Block not found at height " .. height})
      end
    elseif type(hash_or_height) == "string" then
      if #hash_or_height ~= 64 then
        error({code = M.ERROR.INVALID_PARAMS, message = "Invalid block hash"})
      end
      block_hash = types.hash256_from_hex(hash_or_height)
    else
      error({code = M.ERROR.INVALID_PARAMS,
        message = "hash_or_height must be a hash string or numeric height"})
    end

    local block = rpc.storage.get_block(block_hash)
    if not block then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Block not found"})
    end

    local requested = nil
    if params and params[2] and params[2] ~= cjson.null then
      requested = {}
      for _, name in ipairs(params[2]) do
        requested[name] = true
      end
    end
    local function want(name)
      return requested == nil or requested[name]
    end

    -- Try to load and decode BlockUndo so we can populate fee/feerate stats.
    -- BlockUndo entries are aligned with non-coinbase txs: vtxundo[1] -> tx[2].
    -- See bitcoin-core/src/rpc/blockchain.cpp::getblockstats (loop_inputs path).
    local block_undo = nil
    if rpc.storage.get_undo then
      local undo_raw = rpc.storage.get_undo(block_hash)
      if undo_raw then
        local utxo_mod = require("lunarblock.utxo")
        local ok, decoded = pcall(utxo_mod.deserialize_block_undo, undo_raw)
        if ok and decoded and type(decoded) == "table" and decoded.tx_undo then
          block_undo = decoded
        end
      end
    end

    local txs = block.transactions
    local total_size = 0
    local total_weight = 0
    local total_out = 0  -- excludes coinbase output total
    local outputs = 0
    local inputs = 0
    local txsize_array = {}
    local swtxs, swtotal_size, swtotal_weight = 0, 0, 0
    local maxtxsize, mintxsize = 0, math.huge
    local utxos_count = 0
    -- Fee/feerate accumulators (only populated when block_undo is present).
    local fee_array = {}
    local feerate_array = {}      -- {{feerate_satvb, weight}, ...}
    local total_fee = 0
    local maxfee, minfee = 0, math.huge
    local maxfeerate, minfeerate = 0, math.huge
    -- Coinbase index: tx[1].
    for i, tx in ipairs(txs) do
      local tx_size = #serialize.serialize_transaction(tx, true)
      local tx_weight = validation.get_tx_weight(tx)
      outputs = outputs + #tx.outputs
      -- Segwit detection: any tx with at least one non-empty witness vector.
      local has_witness = false
      for _, inp in ipairs(tx.inputs) do
        if inp.witness and #inp.witness > 0 then
          has_witness = true; break
        end
      end
      if has_witness then
        swtxs = swtxs + 1
        swtotal_size = swtotal_size + tx_size
        swtotal_weight = swtotal_weight + tx_weight
      end
      if i > 1 then
        inputs = inputs + #tx.inputs
        local tx_total_out = 0
        for _, out in ipairs(tx.outputs) do
          total_out = total_out + out.value
          tx_total_out = tx_total_out + out.value
        end
        total_size = total_size + tx_size
        total_weight = total_weight + tx_weight
        txsize_array[#txsize_array + 1] = tx_size
        if tx_size > maxtxsize then maxtxsize = tx_size end
        if tx_size < mintxsize then mintxsize = tx_size end

        -- Per-tx fee via BlockUndo (matches Core's loop_inputs path).
        if block_undo then
          local txu = block_undo.tx_undo[i - 1]
          if txu and txu.prev_outputs then
            local tx_total_in = 0
            for _, prev in ipairs(txu.prev_outputs) do
              tx_total_in = tx_total_in + (prev.value or 0)
            end
            local txfee = tx_total_in - tx_total_out
            -- Negative fees are nonsensical (would mean undo lookup mismatch);
            -- clamp to 0 so we don't poison aggregates.
            if txfee < 0 then txfee = 0 end
            fee_array[#fee_array + 1] = txfee
            total_fee = total_fee + txfee
            if txfee > maxfee then maxfee = txfee end
            if txfee < minfee then minfee = txfee end
            -- Feerate in sat/vbyte = (txfee * 4) / weight.
            local feerate = 0
            if tx_weight > 0 then
              feerate = math.floor((txfee * consensus.WITNESS_SCALE_FACTOR) / tx_weight)
            end
            feerate_array[#feerate_array + 1] = {feerate, tx_weight}
            if feerate > maxfeerate then maxfeerate = feerate end
            if feerate < minfeerate then minfeerate = feerate end
          end
        end
      end
      -- utxo_increase counts spendable outputs created (cheap heuristic;
      -- Core also subtracts unspendable scripts -- TODO(rpc) when we
      -- expose script_mod.is_unspendable).
      utxos_count = utxos_count + #tx.outputs
    end
    if mintxsize == math.huge then mintxsize = 0 end
    if minfee == math.huge then minfee = 0 end
    if minfeerate == math.huge then minfeerate = 0 end

    -- Bitcoin Core's CalculateTruncatedMedian: sort, average two middle
    -- elements when even-sized, else pick the middle.
    local function truncated_median(arr)
      if #arr == 0 then return 0 end
      table.sort(arr)
      if #arr % 2 == 0 then
        return math.floor((arr[#arr / 2] + arr[#arr / 2 + 1]) / 2)
      end
      return arr[math.ceil(#arr / 2)]
    end

    -- Bitcoin Core's CalculatePercentilesByWeight: sort by feerate, then walk
    -- the cumulative-weight axis emitting percentiles at 10/25/50/75/90.
    local function feerate_percentiles_calc()
      local result = {0, 0, 0, 0, 0}
      if #feerate_array == 0 or total_weight == 0 then return result end
      table.sort(feerate_array, function(a, b) return a[1] < b[1] end)
      local thresholds = {
        total_weight / 10.0,
        total_weight / 4.0,
        total_weight / 2.0,
        (total_weight * 3.0) / 4.0,
        (total_weight * 9.0) / 10.0,
      }
      local next_idx = 1
      local cumulative = 0
      for _, e in ipairs(feerate_array) do
        cumulative = cumulative + e[2]
        while next_idx <= 5 and cumulative >= thresholds[next_idx] do
          result[next_idx] = e[1]
          next_idx = next_idx + 1
        end
      end
      -- Fill remaining with the largest feerate (matches Core).
      local last = feerate_array[#feerate_array][1]
      for i = next_idx, 5 do
        result[i] = last
      end
      return result
    end

    if not height and rpc.storage.iterator then
      -- Reverse-lookup height; relatively cheap given height index is small.
      local iter = rpc.storage.iterator("height")
      if iter then
        iter.seek_to_first()
        while iter.valid() do
          local k = iter.key()
          local v = iter.value()
          if v and #v == 32 and v == block_hash.bytes then
            height = k:byte(1) * 16777216 + k:byte(2) * 65536 + k:byte(3) * 256 + k:byte(4)
            break
          end
          iter.next()
        end
        iter.destroy()
      end
    end

    local result = {
      blockhash = types.hash256_hex(block_hash),
      time = block.header and block.header.timestamp or 0,
      height = height,
      ins = inputs,
      outs = outputs,
      txs = #txs,
      total_size = total_size,
      total_weight = total_weight,
      total_out = total_out,
      swtotal_size = swtotal_size,
      swtotal_weight = swtotal_weight,
      swtxs = swtxs,
      mintxsize = mintxsize,
      maxtxsize = maxtxsize,
      avgtxsize = (#txs > 1) and math.floor(total_size / (#txs - 1)) or 0,
      mediantxsize = (function()
        if #txsize_array == 0 then return 0 end
        table.sort(txsize_array)
        return txsize_array[math.ceil(#txsize_array / 2)]
      end)(),
      utxo_increase = utxos_count - inputs,
      utxo_size_inc = 0,  -- TODO(rpc): wire PER_UTXO_OVERHEAD-based size delta
      subsidy = consensus.get_block_subsidy and height
        and consensus.get_block_subsidy(height) or 0,
      mediantime = (function()
        if not rpc.storage.get_header or not block.header then return 0 end
        local timestamps = {}
        local cur = block.header.prev_hash
        for _ = 1, 11 do
          local h = cur and rpc.storage.get_header(cur)
          if not h then break end
          timestamps[#timestamps + 1] = h.timestamp
          cur = h.prev_hash
        end
        if #timestamps == 0 then return block.header.timestamp end
        table.sort(timestamps)
        return timestamps[math.ceil(#timestamps / 2)]
      end)(),
      -- Fee/feerate stats: zero if BlockUndo wasn't available, otherwise
      -- computed from per-tx prev-output values via BlockUndo (matches
      -- bitcoin-core/src/rpc/blockchain.cpp::getblockstats loop_inputs).
      avgfee = (block_undo and #txs > 1) and math.floor(total_fee / (#txs - 1)) or 0,
      avgfeerate = (block_undo and total_weight > 0)
        and math.floor((total_fee * consensus.WITNESS_SCALE_FACTOR) / total_weight) or 0,
      totalfee = block_undo and total_fee or 0,
      maxfee = block_undo and maxfee or 0,
      maxfeerate = block_undo and maxfeerate or 0,
      medianfee = block_undo and truncated_median(fee_array) or 0,
      minfee = block_undo and minfee or 0,
      minfeerate = block_undo and minfeerate or 0,
      feerate_percentiles = block_undo and feerate_percentiles_calc() or {0, 0, 0, 0, 0},
      -- _actual variants subtract unspendable script outputs; we don't yet
      -- expose script_mod.is_unspendable, so they trail utxo_increase /
      -- utxo_size_inc until that helper lands.
      utxo_increase_actual = 0, utxo_size_inc_actual = 0,
    }

    -- Filter by requested stats
    if requested then
      local filtered = {}
      for k, _ in pairs(requested) do
        filtered[k] = result[k]
      end
      return filtered
    end
    return result
  end

  -- submitpackage: pipe to mempool:accept_package, then re-emit results in
  -- Core's schema.  Bitcoin Core: src/rpc/mempool.cpp::submitpackage.
  -- Wallet-side propagation (broadcasting an inv per tx) is handled the
  -- same way sendrawtransaction does it.
  self.methods["submitpackage"] = function(rpc, params)
    if not rpc.mempool then
      error({code = M.ERROR.MISC_ERROR, message = "Mempool not available"})
    end
    local pkg = params and params[1]
    if type(pkg) ~= "table" or pkg[1] == nil then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "package must be a non-empty array of raw tx hex strings"})
    end
    local txs = {}
    for i, hex in ipairs(pkg) do
      if type(hex) ~= "string" then
        error({code = M.ERROR.INVALID_PARAMS,
          message = "package[" .. i .. "] is not a hex string"})
      end
      local ok, tx = pcall(serialize.deserialize_transaction, M.hex_decode(hex))
      if not ok then
        error({code = M.ERROR.DESERIALIZATION_ERROR,
          message = "package[" .. i .. "] failed to deserialize: " .. tostring(tx)})
      end
      txs[i] = tx
    end
    local accept_ok, err_or_results = rpc.mempool:accept_package(txs)
    local tx_results = {}
    -- accept_package returns (true, {...}) on success or (false, err_msg).
    if accept_ok then
      for _, tx in ipairs(txs) do
        local txid = validation.compute_txid(tx)
        local wtxid = validation.compute_wtxid(tx)
        local txid_hex = types.hash256_hex(txid)
        local wtxid_hex = types.hash256_hex(wtxid)
        local entry = rpc.mempool:get_entry(txid_hex)
        local fee_btc = entry and (entry.fee / consensus.COIN) or 0
        local vsize = entry and entry.vsize or 0
        tx_results[wtxid_hex] = {
          txid = txid_hex,
          vsize = vsize,
          fees = {
            base = fee_btc,
          },
        }
      end
      -- Broadcast via inv (matches sendrawtransaction).
      if rpc.peer_manager then
        local invs = {}
        for _, tx in ipairs(txs) do
          local txid = validation.compute_txid(tx)
          invs[#invs + 1] = {type = p2p.INV_TYPE.MSG_WITNESS_TX, hash = txid}
        end
        local inv_payload = p2p.serialize_inv(invs)
        rpc.peer_manager:broadcast("inv", inv_payload)
      end
      return {
        package_msg = "success",
        ["tx-results"] = tx_results,
        ["replaced-transactions"] = {},
      }
    end
    return {
      package_msg = tostring(err_or_results),
      ["tx-results"] = tx_results,
      ["replaced-transactions"] = {},
    }
  end

  -- generateblock <output> <transactions> [<submit>] -- regtest only.
  -- Bitcoin Core: src/rpc/mining.cpp::generateblock.  Mines a block
  -- containing the listed transactions (or txids referencing already-in
  -- mempool transactions) directed at the given output address.  We collect
  -- fees from the caller-provided txs into the coinbase output value
  -- (coinbase value = subsidy + sum(fees)).  For mempool-resident txs we
  -- read the precomputed `entry.fee`; for raw-hex txs we resolve each input
  -- via chain_state.coin_view (and fall back to mempool entries created
  -- earlier in the same call, allowing in-block tx chains).
  self.methods["generateblock"] = function(rpc, params)
    if not rpc.mining then
      error({code = M.ERROR.MISC_ERROR, message = "Mining not available"})
    end
    if not rpc.network or rpc.network.name ~= "regtest" then
      error({code = M.ERROR.MISC_ERROR,
        message = "generateblock is only available on regtest"})
    end
    local output = params and params[1]
    local tx_list = params and params[2]
    local submit = true
    if params and params[3] ~= nil and params[3] ~= cjson.null then
      submit = params[3] and true or false
    end
    if type(output) ~= "string" or #output == 0 then
      error({code = M.ERROR.INVALID_PARAMS, message = "output address is required"})
    end
    if type(tx_list) ~= "table" then
      error({code = M.ERROR.INVALID_PARAMS, message = "transactions must be an array"})
    end

    -- Decode payout address -> script_pubkey
    local addr_type, addr_data = address_mod.decode_address(output, rpc.network.name)
    if not addr_type then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Invalid output address"})
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
      error({code = M.ERROR.INVALID_ADDRESS, message = "Unsupported address type"})
    end

    -- Resolve each entry: a 64-char hex txid references an in-mempool tx,
    -- everything else is treated as raw tx hex.  Track per-entry fee where
    -- known (mempool entries) so we can collect fees into the coinbase.
    local provided_txs = {}
    local known_fee = {}     -- per-index fee in satoshis (mempool path only)
    local intra_block = {}   -- txid_hex -> {vout_idx -> {value, script}}
                             -- so a later raw tx can spend an earlier one
    for i, item in ipairs(tx_list) do
      if type(item) ~= "string" then
        error({code = M.ERROR.INVALID_PARAMS,
          message = "transactions[" .. i .. "] is not a hex string"})
      end
      if #item == 64 and item:match("^[0-9A-Fa-f]+$") then
        if not rpc.mempool then
          error({code = M.ERROR.MISC_ERROR,
            message = "Mempool not available; cannot resolve mempool txid"})
        end
        local entry = rpc.mempool:get_entry(item:lower())
        if not entry then
          error({code = M.ERROR.INVALID_ADDRESS,
            message = "transactions[" .. i .. "] references unknown txid"})
        end
        provided_txs[#provided_txs + 1] = entry.tx
        known_fee[#provided_txs] = entry.fee or 0
      else
        local ok, tx = pcall(serialize.deserialize_transaction, M.hex_decode(item))
        if not ok then
          error({code = M.ERROR.DESERIALIZATION_ERROR,
            message = "transactions[" .. i .. "] failed to deserialize"})
        end
        provided_txs[#provided_txs + 1] = tx
      end
    end

    -- Compute total fees over the provided txs so we can pay them out via
    -- the coinbase (Core ref: src/rpc/mining.cpp::generateblock builds the
    -- block via createNewBlock with use_mempool=false, which leaves the
    -- coinbase at subsidy; we deliberately diverge to support fee
    -- collection for test frameworks that mine fee-paying txs).
    local total_fees = 0
    for i, tx in ipairs(provided_txs) do
      if known_fee[i] then
        total_fees = total_fees + known_fee[i]
      else
        -- Resolve each input via chain_state.coin_view, falling back to
        -- the mempool (for parents already accepted) and to intra-block
        -- siblings (for tx-chains in the caller's list).
        local tx_in_value = 0
        local resolved_all = true
        for _, inp in ipairs(tx.inputs) do
          local prev_hex = types.hash256_hex(inp.prev_out.hash)
          local val
          -- 1) chain UTXO set
          if rpc.chain_state and rpc.chain_state.coin_view
              and rpc.chain_state.coin_view.get then
            local entry = rpc.chain_state.coin_view:get(inp.prev_out.hash, inp.prev_out.index)
            if entry then val = entry.value end
          end
          -- 2) intra-block sibling tx
          if not val and intra_block[prev_hex] then
            local sibling = intra_block[prev_hex][inp.prev_out.index]
            if sibling then val = sibling.value end
          end
          -- 3) mempool entry (parent tx in same call series, where caller
          --    passed the parent as a mempool txid)
          if not val and rpc.mempool then
            local mp_entry = rpc.mempool:get_entry(prev_hex)
            if mp_entry and mp_entry.tx and mp_entry.tx.outputs[inp.prev_out.index + 1] then
              val = mp_entry.tx.outputs[inp.prev_out.index + 1].value
            end
          end
          if not val then
            resolved_all = false
            break
          end
          tx_in_value = tx_in_value + val
        end
        if resolved_all then
          local tx_out_value = 0
          for _, out in ipairs(tx.outputs) do
            tx_out_value = tx_out_value + out.value
          end
          local fee = tx_in_value - tx_out_value
          if fee > 0 then total_fees = total_fees + fee end
        end
      end
      -- Index this tx's outputs so a later sibling can resolve them.
      local txid_hex = types.hash256_hex(validation.compute_txid(tx))
      intra_block[txid_hex] = {}
      for vout_idx, out in ipairs(tx.outputs) do
        intra_block[txid_hex][vout_idx - 1] = {value = out.value, script = out.script_pubkey}
      end
    end

    -- Build a normal block template via the mempool (gives us a coinbase at
    -- subsidy, segwit witness-commitment scaffolding, and the next-bits
    -- target), then replace the non-coinbase tx list with the caller's txs
    -- and rebuild the coinbase to reflect subsidy + total_fees.
    local _template, block = rpc.mining.create_block_template(
      rpc.mempool, rpc.chain_state, rpc.network, payout_script
    )

    local height = rpc.chain_state.tip_height + 1
    local subsidy = consensus.get_block_subsidy(height)

    -- Replace mempool-selected txs with caller-supplied txs.
    block.transactions = {}
    for _, tx in ipairs(provided_txs) do
      block.transactions[#block.transactions + 1] = tx
    end

    -- Rebuild the coinbase: same height/extra/payout scaffolding as the
    -- template's coinbase, but value = subsidy + total_fees, and witness
    -- commitment recomputed over the new (caller-supplied) tx list.
    local witness_commitment = nil
    if height >= rpc.network.segwit_height then
      local crypto_mod = require("lunarblock.crypto")
      local wtx_hashes = {types.hash256_zero()}  -- coinbase wtxid placeholder
      for _, tx in ipairs(provided_txs) do
        wtx_hashes[#wtx_hashes + 1] = validation.compute_wtxid(tx)
      end
      local witness_root = crypto_mod.compute_merkle_root(wtx_hashes)
      local witness_nonce = string.rep("\0", 32)
      witness_commitment = crypto_mod.hash256(witness_root.bytes .. witness_nonce)
    end
    local coinbase = rpc.mining.create_coinbase_tx(
      height, subsidy + total_fees, "/LunarBlock/", witness_commitment, payout_script
    )
    table.insert(block.transactions, 1, coinbase)

    -- Recompute the merkle root over the new tx set.
    local tx_hashes = {}
    for i, tx in ipairs(block.transactions) do
      tx_hashes[i] = validation.compute_txid(tx)
    end
    block.header.merkle_root = require("lunarblock.crypto").compute_merkle_root(tx_hashes)

    local found, block_hash = rpc.mining.mine_block(block)
    if not found then
      error({code = M.ERROR.MISC_ERROR,
        message = "Failed to mine block (nonce exhausted)"})
    end

    if submit then
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
      local ok, err = rpc.chain_state:connect_block(
        block, new_height, block_hash, nil, nil, false, nil, false, store_batch_fn
      )
      if not ok then
        error({code = M.ERROR.VERIFY_ERROR,
          message = "Failed to connect block: " .. tostring(err)})
      end
    end

    local result = { hash = types.hash256_hex(block_hash) }
    if not submit then
      result.hex = M.hex_encode(serialize.serialize_block(block))
    end
    return result
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

      -- Connect the block to chain state.
      -- Self-mined blocks are always at the chain tip (well above any assumevalid height),
      -- so skip_scripts will be false in practice.  Still use the proper check for
      -- correctness in case assumevalid is unset or the height happens to fall below it.
      local gen_skip_scripts = false
      if rpc.av_in_index and rpc.av_is_ancestor and rpc.av_on_best_chain and rpc.header_chain then
        local gen_hash_hex = types.hash256_hex(block_hash)
        local gen_bh_work = rpc.header_chain:get_chain_work()
        local gen_bh_height = rpc.header_chain.header_tip_height or 0
        gen_skip_scripts = consensus.should_skip_script_validation(
          rpc.network, new_height, gen_hash_hex,
          rpc.av_in_index, rpc.av_is_ancestor, rpc.av_on_best_chain,
          gen_bh_work, gen_bh_height
        )
      end
      local ok, err = rpc.chain_state:connect_block(block, new_height, block_hash, nil, nil, gen_skip_scripts, nil, false, store_batch_fn)
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

  self.methods["jitprofileflush"] = function(_rpc, _params)
    -- Flush LuaJIT profile by stopping the profiler. Caller should pass a
    -- file path to restart capture into; otherwise capture stops permanently.
    -- main.lua's cleanup path is unreachable (no SIGTERM handler), so this
    -- is the only way to get the profile data on disk.
    local ok, jit_p = pcall(require, "jit.p")
    if not ok then
      return { error = "jit.p not available" }
    end
    jit_p.stop()
    return { flushed = true }
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

      -- Compute skip_scripts via the real assumevalid ancestor-check semantic.
      -- Falls back to false (always verify) if header_chain callbacks are unavailable.
      local skip_scripts = false
      if rpc.av_in_index and rpc.av_is_ancestor and rpc.av_on_best_chain and rpc.header_chain then
        local block_hash_hex = types.hash256_hex(block_hash)
        local best_header_work = rpc.header_chain:get_chain_work()
        local best_header_height = rpc.header_chain.header_tip_height or 0
        skip_scripts = consensus.should_skip_script_validation(
          rpc.network, new_height, block_hash_hex,
          rpc.av_in_index, rpc.av_is_ancestor, rpc.av_on_best_chain,
          best_header_work, best_header_height
        )
      end

      local ok_conn, conn_err = pcall(rpc.chain_state.connect_block, rpc.chain_state, block, new_height, block_hash, nil, nil, skip_scripts, nil, nosync, store_batch_fn)
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

  --- submitblocks: Submit multiple blocks in one RPC call for faster IBD.
  -- @param params array of hex-encoded blocks
  -- @return array of results (null = success, string = error)
  self.methods["submitblocks"] = function(rpc, params)
    local blocks_hex = params[1]
    if type(blocks_hex) ~= "table" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Array of block hex data required"})
    end
    local results = {}
    local submitblock_fn = rpc.methods["submitblock"]
    for i, hex in ipairs(blocks_hex) do
      local ok, result = pcall(submitblock_fn, rpc, {hex})
      if ok then
        results[i] = result
      else
        results[i] = tostring(result)
      end
    end
    return results
  end

  -- Alias for compatibility with feed-sequential.py
  self.methods["submitblockbatch"] = self.methods["submitblocks"]

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

  -- getdeploymentinfo: returns deployment state for each known softfork.
  -- All deployments in lunarblock are buried (enforced from genesis or a fixed
  -- activation height). A reference BIP9 state machine exists in
  -- src/consensus.lua (versionbits_condition / get_deployment_state /
  -- get_deployment_state_for_block), exhaustively unit-tested in
  -- spec/consensus_spec.lua, but it is INTENTIONALLY NOT on the consensus
  -- path — see the long comment block at the top of the BIP9 section in
  -- consensus.lua. There is no versionbits cache, so this RPC returns only
  -- the buried fields (type, active, height, min_activation_height) without
  -- a bip9.status / bip9.since sub-object. Wiring the state machine into the
  -- response would require a versionbits cache and is the natural followup
  -- if/when a future deployment ships unburied.
  self.methods["getdeploymentinfo"] = function(rpc, params)
    -- Resolve the target block
    local target_height
    local target_hash_hex

    if params[1] and params[1] ~= cjson.null then
      local blockhash_hex = params[1]
      if type(blockhash_hex) ~= "string" or #blockhash_hex ~= 64 then
        error({code = M.ERROR.INVALID_PARAMS, message = "Invalid block hash"})
      end
      if not rpc.storage then
        error({code = M.ERROR.MISC_ERROR, message = "Storage not available"})
      end
      local hash = types.hash256_from_hex(blockhash_hex)
      -- Verify the block exists
      local header = rpc.storage.get_header(hash)
      if not header then
        error({code = M.ERROR.INVALID_ADDRESS, message = "Block not found"})
      end
      target_hash_hex = blockhash_hex
      -- Derive height by searching the height index
      target_height = nil
      if rpc.chain_state and rpc.chain_state.tip_height and rpc.storage.iterator then
        local iter = rpc.storage.iterator("height")
        if iter then
          iter.seek_to_first()
          while iter.valid() do
            local v = iter.value()
            if v and #v == 32 and v == hash.bytes then
              local k = iter.key()
              target_height = k:byte(1) * 16777216 + k:byte(2) * 65536 + k:byte(3) * 256 + k:byte(4)
              break
            end
            iter.next()
          end
          iter.destroy()
        end
      end
      -- Fall back to tip height if we cannot resolve height
      if not target_height then
        target_height = rpc.chain_state and rpc.chain_state.tip_height or 0
      end
    else
      -- Default: chain tip
      target_height = rpc.chain_state and rpc.chain_state.tip_height or 0
      if rpc.chain_state and rpc.chain_state.tip_hash then
        target_hash_hex = types.hash256_hex(rpc.chain_state.tip_hash)
      else
        target_hash_hex = string.rep("00", 32)
      end
    end

    -- Use the shared deployment helper so this RPC reads from the same
    -- source of truth as getblockchaininfo.softforks.
    local deployments = build_deployment_state(target_height, rpc.network)

    return {
      hash        = target_hash_hex,
      height      = target_height,
      deployments = deployments,
    }
  end

  -- dumptxoutset: write the serialized UTXO set to a file in Bitcoin Core
  -- wire format.  Mirrors bitcoin-core/src/rpc/blockchain.cpp dumptxoutset.
  -- params[1] = path (string).  Returns {coins_written, base_hash,
  -- base_height, path, txoutset_hash, nchaintx}.
  self.methods["dumptxoutset"] = function(rpc, params)
    if not rpc.chain_state then
      error({code = M.ERROR.MISC_ERROR, message = "Chain state not available"})
    end
    local path = params and params[1]
    if type(path) ~= "string" or path == "" then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "dumptxoutset requires a path string"})
    end
    -- Refuse to clobber an existing file (matches Core dumptxoutset).
    local probe = io.open(path, "rb")
    if probe then
      probe:close()
      error({code = M.ERROR.MISC_ERROR,
        message = "path already exists: " .. path})
    end

    local utxo_mod = require("lunarblock.utxo")
    local _ = utxo_mod  -- chain_state.dump_snapshot dispatches via :method
    local tmppath = path .. ".incomplete"
    local result, err = rpc.chain_state:dump_snapshot(tmppath)
    if not result then
      os.remove(tmppath)
      error({code = M.ERROR.MISC_ERROR, message = err or "dump failed"})
    end
    local rok, rerr = os.rename(tmppath, path)
    if not rok then
      os.remove(tmppath)
      error({code = M.ERROR.MISC_ERROR,
        message = "rename failed: " .. tostring(rerr)})
    end

    local base_hash_hex = types.hash256_hex(result.base_blockhash)
    local hash_hex = ""
    for i = 1, 32 do
      hash_hex = hash_hex .. string.format("%02x", result.hash:byte(i))
    end
    return {
      coins_written = result.coins_count,
      base_hash     = base_hash_hex,
      base_height   = result.base_height,
      path          = path,
      txoutset_hash = hash_hex,
      nchaintx      = result.coins_count,  -- caller can read m_chain_tx_count from chainparams
    }
  end

  -- loadtxoutset: load a serialized UTXO snapshot file (Bitcoin Core wire
  -- format) into the chainstate.  Mirrors loadtxoutset in
  -- bitcoin-core/src/rpc/blockchain.cpp.  params[1] = path.
  -- Validates against chainparams.assumeutxo before accepting.
  self.methods["loadtxoutset"] = function(rpc, params)
    if not rpc.chain_state then
      error({code = M.ERROR.MISC_ERROR, message = "Chain state not available"})
    end
    local path = params and params[1]
    if type(path) ~= "string" or path == "" then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "loadtxoutset requires a path string"})
    end

    -- Peek at metadata to learn the base blockhash, then look up the
    -- assumeutxo entry for that hash.  Reject the load if the chainparams
    -- table does not list this base block (matches Core's safeguard).
    local utxo_mod = require("lunarblock.utxo")
    local f, ferr = io.open(path, "rb")
    if not f then
      error({code = M.ERROR.MISC_ERROR,
        message = "failed to open snapshot: " .. tostring(ferr)})
    end
    local hdr = f:read(51)
    f:close()
    if not hdr or #hdr < 51 then
      error({code = M.ERROR.DESERIALIZATION_ERROR,
        message = "snapshot header truncated"})
    end
    local meta, merr = utxo_mod.deserialize_snapshot_metadata(hdr)
    if not meta then
      error({code = M.ERROR.DESERIALIZATION_ERROR, message = merr})
    end
    if meta.network_magic ~= rpc.network.magic_bytes then
      error({code = M.ERROR.MISC_ERROR,
        message = "snapshot is for a different network"})
    end
    local base_hash_hex = types.hash256_hex(meta.base_blockhash)
    local au_data, au_height = consensus.assumeutxo_for_blockhash(
      rpc.network, base_hash_hex)
    if not au_data then
      -- Core-strict whitelist (bitcoin-core/src/validation.cpp:5775-5780):
      -- after looking up the snapshot's base block in the header index to
      -- recover its height, refuse the load if AssumeutxoForHeight(height)
      -- returns nullopt.  Emit Core's exact error string so cross-impl
      -- consensus-diff probes can match on it byte-for-byte.
      --
      -- We don't carry a hash->height index, so derive the height from
      -- whatever local source we can: the network's genesis hash short-
      -- circuits to 0; otherwise fall back to the height-index by
      -- scanning around the chain tip; otherwise report it as unknown.
      local base_height
      if base_hash_hex == rpc.network.genesis_hash then
        base_height = 0
      elseif rpc.storage and rpc.storage.get_hash_by_height
          and rpc.chain_state and rpc.chain_state.tip_height then
        for h = 0, rpc.chain_state.tip_height do
          local hh = rpc.storage.get_hash_by_height(h)
          if hh and types.hash256_hex(hh) == base_hash_hex then
            base_height = h
            break
          end
        end
      end
      local height_str
      if base_height ~= nil then
        height_str = tostring(base_height)
      else
        height_str = "?"
      end
      error({code = M.ERROR.MISC_ERROR,
        message = "Assumeutxo height in snapshot metadata not recognized ("
          .. height_str .. ") - refusing to load snapshot"})
    end

    local ok, lerr = rpc.chain_state:load_snapshot(path)
    if not ok then
      error({code = M.ERROR.MISC_ERROR,
        message = lerr or "load failed"})
    end

    -- Update the in-memory tip height to match the snapshot base.
    rpc.chain_state.tip_height = au_height
    if rpc.storage and rpc.storage.set_chain_tip then
      rpc.storage.set_chain_tip(rpc.chain_state.tip_hash, au_height, true)
    end

    return {
      coins_loaded     = meta.coins_count,
      tip_hash         = base_hash_hex,
      base_height      = au_height,
      path             = path,
    }
  end
end

--------------------------------------------------------------------------------
-- HTTP Server
--------------------------------------------------------------------------------

function RPCServer:start()
  -- Use tcp4() (not tcp()) so setoption("reuseaddr", true) actually succeeds
  -- on LuaSocket 3.0 — on this build setsockopt fails on a generic master
  -- socket returned by tcp(), leaving bind() to fail with "address already
  -- in use" during the TIME_WAIT window after a clean SIGTERM restart.
  self.server_socket = socket.tcp4()
  assert(self.server_socket:setoption("reuseaddr", true))
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

  client:settimeout(1)  -- 1s max per read (was 5s) to limit event-loop blocking
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

  -- /health: GET endpoint for process supervisors.  No auth required so
  -- supervisors don't need RPC creds.  Returns 200 with a small JSON body
  -- whenever the RPC server's tick is running — supervisors can use this
  -- as a "the daemon is responsive" probe.  We deliberately do NOT report
  -- IBD-completion status here; this is a *liveness* check, not readiness.
  -- Reference: bitcoin-core does not ship /health; this is a lunarblock
  -- ergonomic addition for supervised deployments.
  if method == "GET" and path == "/health" then
    local height = (self.chain_state and self.chain_state.tip_height) or -1
    local body = string.format(
      '{"status":"ok","height":%d,"version":"lunarblock"}\n', height)
    client:send(M.build_http_response(200, body, "application/json"))
    self.request_wallet = nil
    client:close()
    return
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
