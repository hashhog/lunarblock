local crypto = require("lunarblock.crypto")
local serialize = require("lunarblock.serialize")
local types = require("lunarblock.types")
local M = {}

--------------------------------------------------------------------------------
-- Constants
--------------------------------------------------------------------------------

M.HEADER_SIZE = 24
M.MAX_MESSAGE_SIZE = 32 * 1024 * 1024  -- 32 MB max message

M.PROTOCOL_VERSION = 70016

M.SERVICES = {
  NODE_NONE = 0,
  NODE_NETWORK = 1,
  NODE_GETUTXO = 2,
  NODE_BLOOM = 4,
  NODE_WITNESS = 8,
  NODE_COMPACT_FILTERS = 64,
  NODE_NETWORK_LIMITED = 1024,
}

M.INV_TYPE = {
  ERROR = 0,
  MSG_TX = 1,
  MSG_BLOCK = 2,
  MSG_FILTERED_BLOCK = 3,
  MSG_CMPCT_BLOCK = 4,
  MSG_WITNESS_TX = 0x40000001,
  MSG_WITNESS_BLOCK = 0x40000002,
}

--------------------------------------------------------------------------------
-- Command Encoding/Decoding
--------------------------------------------------------------------------------

--- Pad or truncate command to exactly 12 bytes with null padding.
-- @param cmd string: command name (e.g., "version", "verack")
-- @return string: 12-byte null-padded command
function M.encode_command(cmd)
  if #cmd > 12 then
    cmd = cmd:sub(1, 12)
  end
  return cmd .. string.rep("\0", 12 - #cmd)
end

--- Extract command name from 12-byte null-padded string.
-- @param bytes12 string: 12-byte command field
-- @return string: command name with null padding stripped
function M.decode_command(bytes12)
  assert(#bytes12 == 12, "command field must be 12 bytes")
  local null_pos = bytes12:find("\0")
  if null_pos then
    return bytes12:sub(1, null_pos - 1)
  end
  return bytes12
end

--------------------------------------------------------------------------------
-- Message Framing
--------------------------------------------------------------------------------

--- Build a complete P2P message with header and payload.
-- @param magic_bytes string: 4-byte network magic
-- @param command string: command name
-- @param payload string: message payload (may be empty)
-- @return string: complete message (header + payload)
function M.make_message(magic_bytes, command, payload)
  assert(#magic_bytes == 4, "magic must be 4 bytes")
  payload = payload or ""

  local checksum = crypto.hash256(payload):sub(1, 4)

  local w = serialize.buffer_writer()
  w.write_bytes(magic_bytes)
  w.write_bytes(M.encode_command(command))
  w.write_u32le(#payload)
  w.write_bytes(checksum)
  w.write_bytes(payload)

  return w.result()
end

--- Parse a 24-byte message header.
-- @param data24 string: 24 bytes of header data
-- @return table|nil: {magic, command, length, checksum} or nil if invalid
function M.parse_header(data24)
  if #data24 < 24 then return nil end

  local magic = data24:sub(1, 4)
  local command = M.decode_command(data24:sub(5, 16))
  local r = serialize.buffer_reader(data24:sub(17, 24))
  local length = r.read_u32le()
  local checksum = data24:sub(21, 24)

  return {
    magic = magic,
    command = command,
    length = length,
    checksum = checksum,
  }
end

--- Verify payload checksum.
-- @param payload string: message payload
-- @param expected_checksum string: 4-byte expected checksum
-- @return boolean: true if valid
function M.verify_checksum(payload, expected_checksum)
  local actual = crypto.hash256(payload):sub(1, 4)
  return actual == expected_checksum
end

--------------------------------------------------------------------------------
-- IP Address Helpers
--------------------------------------------------------------------------------

--- Convert IPv4 address string to 16-byte IPv4-mapped IPv6.
-- Format: 10 zero bytes + 0xFF 0xFF + 4 IPv4 bytes
-- @param ip_str string: IPv4 address (e.g., "127.0.0.1")
-- @return string: 16-byte IPv4-mapped IPv6 address
function M.ip_to_bytes(ip_str)
  -- Parse IPv4 address
  local a, b, c, d = ip_str:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then
    -- Invalid or IPv6 - for now, return zero address
    return string.rep("\0", 10) .. "\xff\xff" .. string.rep("\0", 4)
  end

  a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)

  -- Validate range
  if a > 255 or b > 255 or c > 255 or d > 255 then
    return string.rep("\0", 10) .. "\xff\xff" .. string.rep("\0", 4)
  end

  -- Build IPv4-mapped IPv6: 10 zeros + 0xFF 0xFF + 4 IPv4 bytes
  return string.rep("\0", 10) .. "\xff\xff" .. string.char(a, b, c, d)
end

--- Convert 16-byte IPv4-mapped IPv6 to IPv4 string.
-- @param bytes16 string: 16-byte address
-- @return string: IPv4 address string or IPv6 representation
function M.bytes_to_ip(bytes16)
  assert(#bytes16 == 16, "address must be 16 bytes")

  -- Check for IPv4-mapped IPv6 prefix: 10 zeros + 0xFF 0xFF
  local prefix = bytes16:sub(1, 12)
  local expected_prefix = string.rep("\0", 10) .. "\xff\xff"

  if prefix == expected_prefix then
    -- IPv4-mapped, extract IPv4 part
    local a, b, c, d = bytes16:byte(13, 16)
    return string.format("%d.%d.%d.%d", a, b, c, d)
  end

  -- Check for all zeros (::)
  if bytes16 == string.rep("\0", 16) then
    return "0.0.0.0"
  end

  -- Full IPv6 - return hex representation
  local parts = {}
  for i = 1, 16, 2 do
    local high, low = bytes16:byte(i, i + 1)
    parts[#parts + 1] = string.format("%x", high * 256 + low)
  end
  return table.concat(parts, ":")
end

--------------------------------------------------------------------------------
-- Network Address Serialization
--------------------------------------------------------------------------------

--- Serialize a network address (26 bytes without timestamp, 30 with).
-- @param services number: service flags
-- @param ip_str string: IP address
-- @param port number: port number
-- @param include_timestamp boolean: whether to include timestamp
-- @param timestamp number: unix timestamp (optional)
-- @return string: serialized network address
function M.serialize_net_addr(services, ip_str, port, include_timestamp, timestamp)
  local w = serialize.buffer_writer()

  if include_timestamp then
    w.write_u32le(timestamp or os.time())
  end

  w.write_u64le(services)
  w.write_bytes(M.ip_to_bytes(ip_str))
  w.write_u16be(port)  -- Port is big-endian!

  return w.result()
end

--- Deserialize a network address.
-- @param reader buffer_reader: buffer reader positioned at address
-- @param include_timestamp boolean: whether timestamp is included
-- @return table: {timestamp, services, ip, port}
function M.deserialize_net_addr(reader, include_timestamp)
  local timestamp = nil
  if include_timestamp then
    timestamp = reader.read_u32le()
  end

  local services = reader.read_u64le()
  local ip = M.bytes_to_ip(reader.read_bytes(16))
  local port = reader.read_u16be()  -- Port is big-endian!

  return {
    timestamp = timestamp,
    services = services,
    ip = ip,
    port = port,
  }
end

--------------------------------------------------------------------------------
-- Version Message
--------------------------------------------------------------------------------

--- Serialize a version message.
-- @param opts table: version message fields
-- @return string: serialized version payload
function M.serialize_version(opts)
  opts = opts or {}
  local w = serialize.buffer_writer()

  w.write_i32le(opts.version or M.PROTOCOL_VERSION)
  w.write_u64le(opts.services or M.SERVICES.NODE_NETWORK + M.SERVICES.NODE_WITNESS)
  w.write_i64le(opts.timestamp or os.time())

  -- Receiver address (no timestamp in version message)
  w.write_u64le(opts.recv_services or 0)
  w.write_bytes(M.ip_to_bytes(opts.recv_ip or "0.0.0.0"))
  w.write_u16be(opts.recv_port or 8333)

  -- Sender address (no timestamp in version message)
  w.write_u64le(opts.from_services or opts.services or M.SERVICES.NODE_NETWORK)
  w.write_bytes(M.ip_to_bytes(opts.from_ip or "0.0.0.0"))
  w.write_u16be(opts.from_port or 0)

  -- Nonce
  w.write_u64le(opts.nonce or math.random(0, 2^52))

  -- User agent (varstr)
  w.write_varstr(opts.user_agent or "/LunarBlock:0.1.0/")

  -- Start height
  w.write_i32le(opts.start_height or 0)

  -- Relay flag (BIP37)
  w.write_u8(opts.relay and 1 or 0)

  return w.result()
end

--- Deserialize a version message.
-- @param data string: version payload
-- @return table: version message fields
function M.deserialize_version(data)
  local r = serialize.buffer_reader(data)

  local version = r.read_i32le()
  local services = r.read_u64le()
  local timestamp = r.read_i64le()

  -- Receiver address
  local recv_services = r.read_u64le()
  local recv_ip = M.bytes_to_ip(r.read_bytes(16))
  local recv_port = r.read_u16be()

  -- Sender address
  local from_services = r.read_u64le()
  local from_ip = M.bytes_to_ip(r.read_bytes(16))
  local from_port = r.read_u16be()

  -- Nonce
  local nonce = r.read_u64le()

  -- User agent
  local user_agent = r.read_varstr()

  -- Start height
  local start_height = r.read_i32le()

  -- Relay flag (optional, defaults to true for older protocols)
  local relay = true
  if not r.is_eof() then
    relay = r.read_u8() ~= 0
  end

  return {
    version = version,
    services = services,
    timestamp = timestamp,
    recv_services = recv_services,
    recv_ip = recv_ip,
    recv_port = recv_port,
    from_services = from_services,
    from_ip = from_ip,
    from_port = from_port,
    nonce = nonce,
    user_agent = user_agent,
    start_height = start_height,
    relay = relay,
  }
end

--------------------------------------------------------------------------------
-- Simple Messages (verack, sendheaders, getaddr - empty payload)
--------------------------------------------------------------------------------

--- Serialize an empty message (verack, sendheaders, getaddr).
-- @return string: empty payload
function M.serialize_empty()
  return ""
end

--- Deserialize an empty message.
-- @return table: empty table
function M.deserialize_empty(_data)
  return {}
end

-- Aliases for clarity
M.serialize_verack = M.serialize_empty
M.deserialize_verack = M.deserialize_empty
M.serialize_sendheaders = M.serialize_empty
M.deserialize_sendheaders = M.deserialize_empty
M.serialize_getaddr = M.serialize_empty
M.deserialize_getaddr = M.deserialize_empty

--------------------------------------------------------------------------------
-- Ping/Pong Messages
--------------------------------------------------------------------------------

--- Serialize a ping message.
-- @param nonce number: 64-bit nonce
-- @return string: serialized ping payload
function M.serialize_ping(nonce)
  local w = serialize.buffer_writer()
  w.write_u64le(nonce)
  return w.result()
end

--- Deserialize a ping message.
-- @param data string: ping payload
-- @return number: nonce
function M.deserialize_ping(data)
  local r = serialize.buffer_reader(data)
  return r.read_u64le()
end

-- Pong is identical to ping
M.serialize_pong = M.serialize_ping
M.deserialize_pong = M.deserialize_ping

--------------------------------------------------------------------------------
-- Inventory Messages (inv, getdata, notfound)
--------------------------------------------------------------------------------

--- Serialize an inventory message.
-- @param inventory table: list of {type, hash} items
-- @return string: serialized inventory payload
function M.serialize_inv(inventory)
  local w = serialize.buffer_writer()
  w.write_varint(#inventory)
  for _, item in ipairs(inventory) do
    w.write_u32le(item.type)
    w.write_hash256(item.hash)
  end
  return w.result()
end

--- Deserialize an inventory message.
-- @param data string: inventory payload
-- @return table: list of {type, hash} items
function M.deserialize_inv(data)
  local r = serialize.buffer_reader(data)
  local count = r.read_varint()
  local items = {}
  for i = 1, count do
    items[i] = {
      type = r.read_u32le(),
      hash = r.read_hash256(),
    }
  end
  return items
end

-- getdata and notfound use the same format as inv
M.serialize_getdata = M.serialize_inv
M.deserialize_getdata = M.deserialize_inv
M.serialize_notfound = M.serialize_inv
M.deserialize_notfound = M.deserialize_inv

--------------------------------------------------------------------------------
-- Block Locator Messages (getblocks, getheaders)
--------------------------------------------------------------------------------

--- Serialize a getblocks message.
-- @param version number: protocol version
-- @param block_locator_hashes table: list of hash256 objects
-- @param hash_stop hash256: stop hash (all zeros for max)
-- @return string: serialized getblocks payload
function M.serialize_getblocks(version, block_locator_hashes, hash_stop)
  local w = serialize.buffer_writer()
  w.write_u32le(version)
  w.write_varint(#block_locator_hashes)
  for _, hash in ipairs(block_locator_hashes) do
    w.write_hash256(hash)
  end
  w.write_hash256(hash_stop or types.hash256_zero())
  return w.result()
end

--- Deserialize a getblocks message.
-- @param data string: getblocks payload
-- @return table: {version, block_locator_hashes, hash_stop}
function M.deserialize_getblocks(data)
  local r = serialize.buffer_reader(data)
  local version = r.read_u32le()
  local count = r.read_varint()
  local block_locator_hashes = {}
  for i = 1, count do
    block_locator_hashes[i] = r.read_hash256()
  end
  local hash_stop = r.read_hash256()
  return {
    version = version,
    block_locator_hashes = block_locator_hashes,
    hash_stop = hash_stop,
  }
end

-- getheaders uses identical format
M.serialize_getheaders = M.serialize_getblocks
M.deserialize_getheaders = M.deserialize_getblocks

--------------------------------------------------------------------------------
-- Headers Message
--------------------------------------------------------------------------------

--- Serialize a headers message.
-- @param headers table: list of block_header objects
-- @return string: serialized headers payload
function M.serialize_headers(headers)
  local w = serialize.buffer_writer()
  w.write_varint(#headers)
  for _, header in ipairs(headers) do
    w.write_bytes(serialize.serialize_block_header(header))
    w.write_varint(0)  -- tx_count always 0 in headers message
  end
  return w.result()
end

--- Deserialize a headers message.
-- @param data string: headers payload
-- @return table: list of block_header objects
function M.deserialize_headers(data)
  local r = serialize.buffer_reader(data)
  local count = r.read_varint()
  local headers = {}
  for i = 1, count do
    headers[i] = serialize.deserialize_block_header(r)
    r.read_varint()  -- skip tx_count (always 0)
  end
  return headers
end

--------------------------------------------------------------------------------
-- Block and Transaction Messages
--------------------------------------------------------------------------------

-- Use serialize module functions directly for block and tx
M.serialize_block = serialize.serialize_block
M.deserialize_block = serialize.deserialize_block
M.serialize_tx = serialize.serialize_transaction
M.deserialize_tx = serialize.deserialize_transaction

--------------------------------------------------------------------------------
-- Addr Message
--------------------------------------------------------------------------------

--- Serialize an addr message.
-- @param addresses table: list of {timestamp, services, ip, port}
-- @return string: serialized addr payload
function M.serialize_addr(addresses)
  local w = serialize.buffer_writer()
  w.write_varint(#addresses)
  for _, addr in ipairs(addresses) do
    w.write_u32le(addr.timestamp or os.time())
    w.write_u64le(addr.services or 0)
    w.write_bytes(M.ip_to_bytes(addr.ip or "0.0.0.0"))
    w.write_u16be(addr.port or 8333)
  end
  return w.result()
end

--- Deserialize an addr message.
-- @param data string: addr payload
-- @return table: list of {timestamp, services, ip, port}
function M.deserialize_addr(data)
  local r = serialize.buffer_reader(data)
  local count = r.read_varint()
  local addresses = {}
  for i = 1, count do
    addresses[i] = {
      timestamp = r.read_u32le(),
      services = r.read_u64le(),
      ip = M.bytes_to_ip(r.read_bytes(16)),
      port = r.read_u16be(),
    }
  end
  return addresses
end

--------------------------------------------------------------------------------
-- Feefilter Message
--------------------------------------------------------------------------------

--- Serialize a feefilter message.
-- @param feerate number: fee rate in satoshis per KB
-- @return string: serialized feefilter payload
function M.serialize_feefilter(feerate)
  local w = serialize.buffer_writer()
  w.write_u64le(feerate)
  return w.result()
end

--- Deserialize a feefilter message.
-- @param data string: feefilter payload
-- @return number: fee rate in satoshis per KB
function M.deserialize_feefilter(data)
  local r = serialize.buffer_reader(data)
  return r.read_u64le()
end

--------------------------------------------------------------------------------
-- Sendcmpct Message
--------------------------------------------------------------------------------

--- Serialize a sendcmpct message.
-- @param announce boolean: whether to announce compact blocks
-- @param version number: compact blocks version
-- @return string: serialized sendcmpct payload
function M.serialize_sendcmpct(announce, version)
  local w = serialize.buffer_writer()
  w.write_u8(announce and 1 or 0)
  w.write_u64le(version)
  return w.result()
end

--- Deserialize a sendcmpct message.
-- @param data string: sendcmpct payload
-- @return table: {announce, version}
function M.deserialize_sendcmpct(data)
  local r = serialize.buffer_reader(data)
  return {
    announce = r.read_u8() ~= 0,
    version = r.read_u64le(),
  }
end

--------------------------------------------------------------------------------
-- Reject Message
--------------------------------------------------------------------------------

--- Deserialize a reject message.
-- @param data string: reject payload
-- @return table: {message, ccode, reason, hash}
function M.deserialize_reject(data)
  local r = serialize.buffer_reader(data)
  local message = r.read_varstr()
  local ccode = r.read_u8()
  local reason = r.read_varstr()

  -- Optional 32-byte hash (for tx/block rejects)
  local hash = nil
  if r.remaining() >= 32 then
    hash = r.read_hash256()
  end

  return {
    message = message,
    ccode = ccode,
    reason = reason,
    hash = hash,
  }
end

--- Serialize a reject message.
-- @param message string: rejected message type
-- @param ccode number: rejection code
-- @param reason string: human-readable reason
-- @param hash hash256: optional hash of rejected item
-- @return string: serialized reject payload
function M.serialize_reject(message, ccode, reason, hash)
  local w = serialize.buffer_writer()
  w.write_varstr(message)
  w.write_u8(ccode)
  w.write_varstr(reason)
  if hash then
    w.write_hash256(hash)
  end
  return w.result()
end

return M
