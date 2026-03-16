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
    [400] = "Bad Request",
    [401] = "Unauthorized",
    [403] = "Forbidden",
    [404] = "Not Found",
    [500] = "Internal Server Error",
  }
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
  self.wallet = config.wallet
  self.mining = config.mining
  self.running = false
  -- Register built-in methods
  self:register_methods()
  return self
end

--------------------------------------------------------------------------------
-- RPC Request Handling
--------------------------------------------------------------------------------

function RPCServer:handle_request(request_body)
  local ok, request = pcall(cjson.decode, request_body)
  if not ok then
    return cjson.encode({
      result = cjson.null,
      error = {code = M.ERROR.PARSE_ERROR, message = "Parse error"},
      id = cjson.null,
    })
  end

  local method = request.method
  local params = request.params or {}
  local id = request.id

  local handler = self.methods[method]
  if not handler then
    return cjson.encode({
      result = cjson.null,
      error = {code = M.ERROR.METHOD_NOT_FOUND, message = "Method not found: " .. tostring(method)},
      id = id,
    })
  end

  local success, result = pcall(handler, self, params)
  if not success then
    -- Check if it's a structured error
    if type(result) == "table" and result.code then
      return cjson.encode({
        result = cjson.null,
        error = {code = result.code, message = result.message or "Error"},
        id = id,
      })
    end
    return cjson.encode({
      result = cjson.null,
      error = {code = M.ERROR.INTERNAL_ERROR, message = tostring(result)},
      id = id,
    })
  end

  return cjson.encode({
    result = result,
    error = cjson.null,
    id = id,
  })
end

--------------------------------------------------------------------------------
-- RPC Method Registration
--------------------------------------------------------------------------------

function RPCServer:register_methods()
  -- Blockchain methods
  self.methods["getblockchaininfo"] = function(rpc, _params)
    local tip_height = 0
    local tip_hash = types.hash256_zero()
    if rpc.chain_state then
      tip_height = rpc.chain_state.tip_height or 0
      tip_hash = rpc.chain_state.tip_hash or types.hash256_zero()
    end
    return {
      chain = rpc.network.name,
      blocks = tip_height,
      headers = tip_height,
      bestblockhash = types.hash256_hex(tip_hash),
      difficulty = 1.0,  -- simplified
      mediantime = os.time(),
      verificationprogress = 1.0,
      initialblockdownload = false,
      chainwork = "0000000000000000000000000000000000000000000000000000000000000000",
      pruned = false,
    }
  end

  self.methods["getblockhash"] = function(rpc, params)
    local height = params[1]
    assert(type(height) == "number", "Height must be a number")
    assert(rpc.storage, "Storage not available")
    local hash = rpc.storage.get_hash_by_height(height)
    assert(hash, "Block height out of range")
    return types.hash256_hex(hash)
  end

  self.methods["getblock"] = function(rpc, params)
    local blockhash = params[1]
    local verbosity = params[2] or 1
    assert(type(blockhash) == "string" and #blockhash == 64, "Invalid block hash")
    assert(rpc.storage, "Storage not available")
    local hash = types.hash256_from_hex(blockhash)
    local block = rpc.storage.get_block(hash)
    assert(block, "Block not found")

    if verbosity == 0 then
      -- Return raw hex
      return M.hex_encode(serialize.serialize_block(block))
    end

    -- Return JSON object
    local txids = {}
    for _, tx in ipairs(block.transactions) do
      txids[#txids + 1] = types.hash256_hex(validation.compute_txid(tx))
    end
    return {
      hash = blockhash,
      confirmations = 1,
      size = #serialize.serialize_block(block),
      weight = 0,  -- simplified
      height = 0,  -- would need height index lookup
      version = block.header.version,
      merkleroot = types.hash256_hex(block.header.merkle_root),
      tx = txids,
      time = block.header.timestamp,
      nonce = block.header.nonce,
      bits = string.format("%08x", block.header.bits),
      previousblockhash = types.hash256_hex(block.header.prev_hash),
    }
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

  -- Mempool methods
  self.methods["getmempoolinfo"] = function(rpc, _params)
    if rpc.mempool then
      return rpc.mempool:get_info()
    end
    return {
      size = 0,
      bytes = 0,
      usage = 0,
      maxmempool = 300 * 1024 * 1024,
      mempoolminfee = 1000,
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
end

--------------------------------------------------------------------------------
-- HTTP Server
--------------------------------------------------------------------------------

function RPCServer:start()
  self.server_socket = socket.tcp()
  self.server_socket:setoption("reuseaddr", true)
  assert(self.server_socket:bind(self.host, self.port))
  assert(self.server_socket:listen(32))
  self.server_socket:settimeout(0.1)  -- Short timeout for non-blocking accept
  self.running = true
  print("RPC server listening on " .. self.host .. ":" .. self.port)
end

function RPCServer:tick()
  if not self.running then return end

  -- Accept a new connection
  local client = self.server_socket:accept()
  if not client then return end

  client:settimeout(5)
  -- Read the full HTTP request
  local data = ""
  while true do
    local chunk, err, partial = client:receive(8192)
    chunk = chunk or partial
    if chunk then data = data .. chunk end
    if err == "closed" or err == "timeout" then break end
    -- Check if we have the full request
    local header_end = data:find("\r\n\r\n")
    if header_end then
      local content_length = data:match("[Cc]ontent%-[Ll]ength:%s*(%d+)")
      if content_length then
        content_length = tonumber(content_length)
        if #data >= header_end + 3 + content_length then break end
      else
        break
      end
    end
  end

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

  -- Suppress unused warning
  local _ = path

  -- Check authentication
  if self.password ~= "" and not M.check_auth(headers, self.username, self.password) then
    client:send(M.build_http_response(401, '{"error":"Unauthorized"}'))
    client:close()
    return
  end

  -- Handle JSON-RPC
  if method == "POST" then
    local response_body = self:handle_request(body)
    client:send(M.build_http_response(200, response_body))
  else
    client:send(M.build_http_response(404, '{"error":"Not found"}'))
  end

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
