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

--- Compute the service-flags bitfield we advertise to peers.
-- @param peerbloomfilters boolean: include NODE_BLOOM (BIP-35 mempool support)
-- @return number: services bitfield (NODE_NETWORK|NODE_WITNESS [|NODE_BLOOM])
function M.our_services(peerbloomfilters)
  local s = require("bit").bor(M.SERVICES.NODE_NETWORK, M.SERVICES.NODE_WITNESS)
  if peerbloomfilters then
    s = require("bit").bor(s, M.SERVICES.NODE_BLOOM)
  end
  return s
end

--------------------------------------------------------------------------------
-- BIP155 Network IDs and Address Sizes
--------------------------------------------------------------------------------

-- BIP155 network identifiers
M.NET_ID = {
  IPV4 = 1,    -- 4-byte IPv4 address
  IPV6 = 2,    -- 16-byte IPv6 address
  TORV2 = 3,   -- 10-byte TorV2 address (deprecated, no longer relayed)
  TORV3 = 4,   -- 32-byte TorV3 address (ed25519 public key)
  I2P = 5,     -- 32-byte I2P address (SHA256 of destination)
  CJDNS = 6,   -- 16-byte CJDNS address
}

-- Expected address sizes for each network type
M.NET_ADDR_SIZE = {
  [M.NET_ID.IPV4] = 4,
  [M.NET_ID.IPV6] = 16,
  [M.NET_ID.TORV2] = 10,  -- deprecated
  [M.NET_ID.TORV3] = 32,
  [M.NET_ID.I2P] = 32,
  [M.NET_ID.CJDNS] = 16,
}

-- Maximum address size (BIP155)
M.MAX_ADDRV2_SIZE = 512

M.INV_TYPE = {
  ERROR = 0,
  MSG_TX = 1,
  MSG_BLOCK = 2,
  MSG_FILTERED_BLOCK = 3,
  MSG_CMPCT_BLOCK = 4,
  MSG_WTX = 5,                    -- BIP 339: wtxid-based tx relay
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
M.serialize_sendaddrv2 = M.serialize_empty   -- BIP155: empty payload
M.deserialize_sendaddrv2 = M.deserialize_empty

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
-- BIP155 Addrv2 Message (variable-length network addresses)
--------------------------------------------------------------------------------

--- Convert raw address bytes to a displayable string for various network types.
-- @param network_id number: BIP155 network identifier
-- @param addr_bytes string: raw address bytes
-- @return string: displayable address string
function M.addr_bytes_to_string(network_id, addr_bytes)
  if network_id == M.NET_ID.IPV4 then
    if #addr_bytes ~= 4 then return nil end
    return string.format("%d.%d.%d.%d",
      addr_bytes:byte(1), addr_bytes:byte(2),
      addr_bytes:byte(3), addr_bytes:byte(4))
  elseif network_id == M.NET_ID.IPV6 then
    if #addr_bytes ~= 16 then return nil end
    -- Check for IPv4-mapped IPv6 (::ffff:a.b.c.d)
    local prefix = addr_bytes:sub(1, 12)
    if prefix == string.rep("\0", 10) .. "\xff\xff" then
      return string.format("%d.%d.%d.%d",
        addr_bytes:byte(13), addr_bytes:byte(14),
        addr_bytes:byte(15), addr_bytes:byte(16))
    end
    -- Full IPv6 representation
    local parts = {}
    for i = 1, 16, 2 do
      local high, low = addr_bytes:byte(i, i + 1)
      parts[#parts + 1] = string.format("%x", high * 256 + low)
    end
    return table.concat(parts, ":")
  elseif network_id == M.NET_ID.TORV3 then
    -- TorV3: 32-byte ed25519 pubkey, displayed as base32 + ".onion"
    if #addr_bytes ~= 32 then return nil end
    -- For display, we just show hex (full base32 encoding would require checksum)
    local hex = ""
    for i = 1, #addr_bytes do
      hex = hex .. string.format("%02x", addr_bytes:byte(i))
    end
    return hex .. ".onion"
  elseif network_id == M.NET_ID.I2P then
    -- I2P: 32-byte SHA256, displayed as base32 + ".b32.i2p"
    if #addr_bytes ~= 32 then return nil end
    local hex = ""
    for i = 1, #addr_bytes do
      hex = hex .. string.format("%02x", addr_bytes:byte(i))
    end
    return hex .. ".b32.i2p"
  elseif network_id == M.NET_ID.CJDNS then
    -- CJDNS: 16-byte address (must start with 0xFC)
    if #addr_bytes ~= 16 then return nil end
    -- Display as IPv6-style hex
    local parts = {}
    for i = 1, 16, 2 do
      local high, low = addr_bytes:byte(i, i + 1)
      parts[#parts + 1] = string.format("%x", high * 256 + low)
    end
    return table.concat(parts, ":")
  end
  -- Unknown network type
  return nil
end

--- Convert a displayable address string to raw bytes for various network types.
-- @param network_id number: BIP155 network identifier
-- @param addr_str string: displayable address string
-- @return string|nil: raw address bytes, or nil if invalid
function M.string_to_addr_bytes(network_id, addr_str)
  if network_id == M.NET_ID.IPV4 then
    local a, b, c, d = addr_str:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
    return string.char(a, b, c, d)
  elseif network_id == M.NET_ID.IPV6 then
    -- Simplified: parse colon-separated hex groups
    local parts = {}
    for part in (addr_str .. ":"):gmatch("([^:]*):") do
      parts[#parts + 1] = part
    end
    if #parts ~= 8 then return nil end
    local bytes = {}
    for _, part in ipairs(parts) do
      local val = tonumber(part, 16) or 0
      bytes[#bytes + 1] = string.char(math.floor(val / 256), val % 256)
    end
    return table.concat(bytes)
  end
  -- For TORV3, I2P, CJDNS: expect raw bytes (32 or 16)
  return nil
end

--- Serialize an addrv2 message (BIP155).
-- @param addresses table: list of {timestamp, services, network_id, addr_bytes, port}
-- @return string: serialized addrv2 payload
function M.serialize_addrv2(addresses)
  local w = serialize.buffer_writer()
  w.write_varint(#addresses)
  for _, addr in ipairs(addresses) do
    -- timestamp (uint32)
    w.write_u32le(addr.timestamp or os.time())
    -- services (compact size)
    w.write_varint(addr.services or 0)
    -- network_id (uint8)
    local net_id = addr.network_id or M.NET_ID.IPV4
    w.write_u8(net_id)
    -- addr_bytes (compact size + bytes)
    local addr_bytes = addr.addr_bytes
    if not addr_bytes and addr.ip then
      -- Convert from IP string if addr_bytes not provided
      if net_id == M.NET_ID.IPV4 then
        addr_bytes = M.string_to_addr_bytes(M.NET_ID.IPV4, addr.ip)
      elseif net_id == M.NET_ID.IPV6 then
        -- Check if it's an IPv4 address being sent as IPv6
        local a, b, c, d = addr.ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
        if a then
          -- IPv4 address - send as IPv4
          net_id = M.NET_ID.IPV4
          addr_bytes = string.char(tonumber(a), tonumber(b), tonumber(c), tonumber(d))
        end
      end
    end
    addr_bytes = addr_bytes or string.rep("\0", 4)
    w.write_varint(#addr_bytes)
    w.write_bytes(addr_bytes)
    -- port (uint16 big-endian)
    w.write_u16be(addr.port or 8333)
  end
  return w.result()
end

--- Deserialize an addrv2 message (BIP155).
-- @param data string: addrv2 payload
-- @return table: list of {timestamp, services, network_id, addr_bytes, addr_str, port, valid}
function M.deserialize_addrv2(data)
  local r = serialize.buffer_reader(data)
  local count = r.read_varint()
  local addresses = {}
  for i = 1, count do
    local timestamp = r.read_u32le()
    local services = r.read_varint()
    local network_id = r.read_u8()
    local addr_len = r.read_varint()

    -- Validate address length
    local valid = true
    local expected_len = M.NET_ADDR_SIZE[network_id]
    if expected_len and addr_len ~= expected_len then
      valid = false  -- Wrong size for known network type
    end
    if addr_len > M.MAX_ADDRV2_SIZE then
      valid = false  -- Address too long
    end

    local addr_bytes = r.read_bytes(addr_len)
    local port = r.read_u16be()

    -- Skip deprecated TORV2 addresses
    if network_id == M.NET_ID.TORV2 then
      valid = false
    end

    -- Validate CJDNS prefix (must start with 0xFC)
    if network_id == M.NET_ID.CJDNS and valid then
      if #addr_bytes < 1 or addr_bytes:byte(1) ~= 0xFC then
        valid = false
      end
    end

    -- Convert to displayable string
    local addr_str = nil
    if valid then
      addr_str = M.addr_bytes_to_string(network_id, addr_bytes)
    end

    -- For IPv4/IPv6, also set the ip field for backwards compatibility
    local ip = nil
    if valid and (network_id == M.NET_ID.IPV4 or network_id == M.NET_ID.IPV6) then
      ip = addr_str
    end

    addresses[i] = {
      timestamp = timestamp,
      services = services,
      network_id = network_id,
      addr_bytes = addr_bytes,
      addr_str = addr_str,
      ip = ip,
      port = port,
      valid = valid,
    }
  end
  return addresses
end

--- Check if an address is compatible with a peer (for addr relay).
-- Peers without addrv2 can only receive IPv4/IPv6 addresses.
-- @param peer_wants_addrv2 boolean: whether peer sent sendaddrv2
-- @param addr table: address entry with network_id field
-- @return boolean: true if address can be sent to this peer
function M.is_addr_compatible(peer_wants_addrv2, addr)
  local net_id = addr.network_id or M.NET_ID.IPV4
  if peer_wants_addrv2 then
    -- Addrv2 peers can receive all address types (except deprecated TORV2)
    return net_id ~= M.NET_ID.TORV2
  else
    -- Non-addrv2 peers can only receive IPv4 and IPv6
    return net_id == M.NET_ID.IPV4 or net_id == M.NET_ID.IPV6
  end
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
-- Sendcmpct Message (BIP152)
--------------------------------------------------------------------------------

--- Serialize a sendcmpct message.
-- @param announce boolean: whether to announce compact blocks (high-bandwidth mode)
-- @param version number: compact blocks version (1 = txid, 2 = wtxid)
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
-- Compact Block Messages (BIP152)
--------------------------------------------------------------------------------

-- Short txid length in bytes
M.SHORTTXIDS_LENGTH = 6

--- Serialize a prefilled transaction for cmpctblock.
-- Index is encoded as a differential offset from the previous prefilled tx.
-- @param index number: differential index (offset from previous)
-- @param tx table: transaction object
-- @return string: serialized prefilled transaction
local function serialize_prefilled_tx(index, tx)
  local w = serialize.buffer_writer()
  w.write_varint(index)
  w.write_bytes(serialize.serialize_transaction(tx, true))  -- always include witness
  return w.result()
end

--- Serialize a cmpctblock message.
-- @param header table: block_header object
-- @param nonce number: 64-bit random nonce for short ID computation
-- @param short_ids table: list of 6-byte short transaction IDs (as numbers)
-- @param prefilled_txns table: list of {index, tx} for prefilled transactions
-- @return string: serialized cmpctblock payload
function M.serialize_cmpctblock(header, nonce, short_ids, prefilled_txns)
  local w = serialize.buffer_writer()

  -- Header (80 bytes)
  w.write_bytes(serialize.serialize_block_header(header))

  -- Nonce (8 bytes)
  w.write_u64le(nonce)

  -- Short IDs (varint count + 6 bytes each)
  w.write_varint(#short_ids)
  for _, short_id in ipairs(short_ids) do
    -- Write 6 bytes little-endian
    for i = 0, 5 do
      local byte = math.floor(short_id / (256 ^ i)) % 256
      w.write_u8(byte)
    end
  end

  -- Prefilled transactions (varint count + each prefilled)
  w.write_varint(#prefilled_txns)
  local last_index = -1
  for _, item in ipairs(prefilled_txns) do
    -- Differential encoding: index is offset from (last_index + 1)
    local diff_index = item.index - last_index - 1
    w.write_varint(diff_index)
    w.write_bytes(serialize.serialize_transaction(item.tx, true))
    last_index = item.index
  end

  return w.result()
end

--- Deserialize a cmpctblock message.
-- @param data string: cmpctblock payload
-- @return table: {header, nonce, short_ids, prefilled_txns}
function M.deserialize_cmpctblock(data)
  local r = serialize.buffer_reader(data)

  -- Header (80 bytes)
  local header = serialize.deserialize_block_header(r)

  -- Nonce (8 bytes)
  local nonce = r.read_u64le()

  -- Short IDs
  local short_id_count = r.read_varint()
  local short_ids = {}
  for i = 1, short_id_count do
    -- Read 6 bytes little-endian as a number
    local short_id = 0
    for j = 0, 5 do
      short_id = short_id + r.read_u8() * (256 ^ j)
    end
    short_ids[i] = short_id
  end

  -- Prefilled transactions with differential decoding
  local prefilled_count = r.read_varint()
  local prefilled_txns = {}
  local last_index = -1
  for i = 1, prefilled_count do
    local diff_index = r.read_varint()
    local index = last_index + diff_index + 1
    local tx = serialize.deserialize_transaction(r)
    prefilled_txns[i] = { index = index, tx = tx }
    last_index = index
  end

  return {
    header = header,
    nonce = nonce,
    short_ids = short_ids,
    prefilled_txns = prefilled_txns,
  }
end

--- Get the total transaction count in a compact block.
-- @param cmpctblock table: deserialized compact block
-- @return number: total transaction count
function M.cmpctblock_tx_count(cmpctblock)
  return #cmpctblock.short_ids + #cmpctblock.prefilled_txns
end

--------------------------------------------------------------------------------
-- GetBlockTxn Message (BIP152)
--------------------------------------------------------------------------------

--- Serialize a getblocktxn message.
-- Request missing transactions by their indices.
-- @param block_hash hash256: block hash
-- @param indexes table: list of transaction indices to request
-- @return string: serialized getblocktxn payload
function M.serialize_getblocktxn(block_hash, indexes)
  local w = serialize.buffer_writer()
  w.write_hash256(block_hash)

  -- Differential encoding of indices
  w.write_varint(#indexes)
  local last_index = -1
  for _, index in ipairs(indexes) do
    local diff = index - last_index - 1
    w.write_varint(diff)
    last_index = index
  end

  return w.result()
end

--- Deserialize a getblocktxn message.
-- @param data string: getblocktxn payload
-- @return table: {block_hash, indexes}
function M.deserialize_getblocktxn(data)
  local r = serialize.buffer_reader(data)
  local block_hash = r.read_hash256()

  -- Differential decoding of indices
  local count = r.read_varint()
  local indexes = {}
  local last_index = -1
  for i = 1, count do
    local diff = r.read_varint()
    local index = last_index + diff + 1
    indexes[i] = index
    last_index = index
  end

  return {
    block_hash = block_hash,
    indexes = indexes,
  }
end

--------------------------------------------------------------------------------
-- BlockTxn Message (BIP152)
--------------------------------------------------------------------------------

--- Serialize a blocktxn message.
-- Response to getblocktxn with the requested transactions.
-- @param block_hash hash256: block hash
-- @param transactions table: list of transaction objects
-- @return string: serialized blocktxn payload
function M.serialize_blocktxn(block_hash, transactions)
  local w = serialize.buffer_writer()
  w.write_hash256(block_hash)
  w.write_varint(#transactions)
  for _, tx in ipairs(transactions) do
    w.write_bytes(serialize.serialize_transaction(tx, true))  -- always include witness
  end
  return w.result()
end

--- Deserialize a blocktxn message.
-- @param data string: blocktxn payload
-- @return table: {block_hash, transactions}
function M.deserialize_blocktxn(data)
  local r = serialize.buffer_reader(data)
  local block_hash = r.read_hash256()
  local count = r.read_varint()
  local transactions = {}
  for i = 1, count do
    transactions[i] = serialize.deserialize_transaction(r)
  end
  return {
    block_hash = block_hash,
    transactions = transactions,
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

--------------------------------------------------------------------------------
-- BIP157/158 Compact Block Filter Messages
--------------------------------------------------------------------------------

-- Filter types
M.FILTER_TYPE = {
  BASIC = 0,
}

--- Serialize a getcfilters message (request compact block filters).
-- @param filter_type number: filter type (0 = basic)
-- @param start_height number: start block height
-- @param stop_hash hash256: stop block hash
-- @return string: serialized getcfilters payload
function M.serialize_getcfilters(filter_type, start_height, stop_hash)
  local w = serialize.buffer_writer()
  w.write_u8(filter_type)
  w.write_u32le(start_height)
  w.write_hash256(stop_hash)
  return w.result()
end

--- Deserialize a getcfilters message.
-- @param data string: getcfilters payload
-- @return table: {filter_type, start_height, stop_hash}
function M.deserialize_getcfilters(data)
  local r = serialize.buffer_reader(data)
  return {
    filter_type = r.read_u8(),
    start_height = r.read_u32le(),
    stop_hash = r.read_hash256(),
  }
end

--- Serialize a cfilter message (compact block filter).
-- @param filter_type number: filter type
-- @param block_hash hash256: block hash
-- @param filter_data string: encoded filter bytes
-- @return string: serialized cfilter payload
function M.serialize_cfilter(filter_type, block_hash, filter_data)
  local w = serialize.buffer_writer()
  w.write_u8(filter_type)
  w.write_hash256(block_hash)
  w.write_varstr(filter_data)
  return w.result()
end

--- Deserialize a cfilter message.
-- @param data string: cfilter payload
-- @return table: {filter_type, block_hash, filter_data}
function M.deserialize_cfilter(data)
  local r = serialize.buffer_reader(data)
  return {
    filter_type = r.read_u8(),
    block_hash = r.read_hash256(),
    filter_data = r.read_varstr(),
  }
end

--- Serialize a getcfheaders message (request filter headers).
-- @param filter_type number: filter type
-- @param start_height number: start block height
-- @param stop_hash hash256: stop block hash
-- @return string: serialized getcfheaders payload
function M.serialize_getcfheaders(filter_type, start_height, stop_hash)
  local w = serialize.buffer_writer()
  w.write_u8(filter_type)
  w.write_u32le(start_height)
  w.write_hash256(stop_hash)
  return w.result()
end

--- Deserialize a getcfheaders message.
-- @param data string: getcfheaders payload
-- @return table: {filter_type, start_height, stop_hash}
function M.deserialize_getcfheaders(data)
  local r = serialize.buffer_reader(data)
  return {
    filter_type = r.read_u8(),
    start_height = r.read_u32le(),
    stop_hash = r.read_hash256(),
  }
end

--- Serialize a cfheaders message (filter headers).
-- @param filter_type number: filter type
-- @param stop_hash hash256: stop block hash
-- @param prev_filter_header hash256: filter header for block at start_height - 1
-- @param filter_hashes table: list of filter hashes (hash256)
-- @return string: serialized cfheaders payload
function M.serialize_cfheaders(filter_type, stop_hash, prev_filter_header, filter_hashes)
  local w = serialize.buffer_writer()
  w.write_u8(filter_type)
  w.write_hash256(stop_hash)
  w.write_hash256(prev_filter_header)
  w.write_varint(#filter_hashes)
  for _, hash in ipairs(filter_hashes) do
    w.write_hash256(hash)
  end
  return w.result()
end

--- Deserialize a cfheaders message.
-- @param data string: cfheaders payload
-- @return table: {filter_type, stop_hash, prev_filter_header, filter_hashes}
function M.deserialize_cfheaders(data)
  local r = serialize.buffer_reader(data)
  local filter_type = r.read_u8()
  local stop_hash = r.read_hash256()
  local prev_filter_header = r.read_hash256()
  local count = r.read_varint()
  local filter_hashes = {}
  for i = 1, count do
    filter_hashes[i] = r.read_hash256()
  end
  return {
    filter_type = filter_type,
    stop_hash = stop_hash,
    prev_filter_header = prev_filter_header,
    filter_hashes = filter_hashes,
  }
end

--- Serialize a getcfcheckpt message (request filter checkpoints).
-- @param filter_type number: filter type
-- @param stop_hash hash256: stop block hash
-- @return string: serialized getcfcheckpt payload
function M.serialize_getcfcheckpt(filter_type, stop_hash)
  local w = serialize.buffer_writer()
  w.write_u8(filter_type)
  w.write_hash256(stop_hash)
  return w.result()
end

--- Deserialize a getcfcheckpt message.
-- @param data string: getcfcheckpt payload
-- @return table: {filter_type, stop_hash}
function M.deserialize_getcfcheckpt(data)
  local r = serialize.buffer_reader(data)
  return {
    filter_type = r.read_u8(),
    stop_hash = r.read_hash256(),
  }
end

--- Serialize a cfcheckpt message (filter checkpoints).
-- @param filter_type number: filter type
-- @param stop_hash hash256: stop block hash
-- @param filter_headers table: list of checkpoint filter headers
-- @return string: serialized cfcheckpt payload
function M.serialize_cfcheckpt(filter_type, stop_hash, filter_headers)
  local w = serialize.buffer_writer()
  w.write_u8(filter_type)
  w.write_hash256(stop_hash)
  w.write_varint(#filter_headers)
  for _, header in ipairs(filter_headers) do
    w.write_hash256(header)
  end
  return w.result()
end

--- Deserialize a cfcheckpt message.
-- @param data string: cfcheckpt payload
-- @return table: {filter_type, stop_hash, filter_headers}
function M.deserialize_cfcheckpt(data)
  local r = serialize.buffer_reader(data)
  local filter_type = r.read_u8()
  local stop_hash = r.read_hash256()
  local count = r.read_varint()
  local filter_headers = {}
  for i = 1, count do
    filter_headers[i] = r.read_hash256()
  end
  return {
    filter_type = filter_type,
    stop_hash = stop_hash,
    filter_headers = filter_headers,
  }
end

--------------------------------------------------------------------------------
-- BIP324 V2 Transport Support
--------------------------------------------------------------------------------

-- Short message type IDs for v2 transport (BIP324)
-- ID 0 means 12-byte string encoding follows
M.V2_MESSAGE_IDS = {
  [0] = "",            -- Long encoding follows
  [1] = "addr",
  [2] = "block",
  [3] = "blocktxn",
  [4] = "cmpctblock",
  [5] = "feefilter",
  [6] = "filteradd",
  [7] = "filterclear",
  [8] = "filterload",
  [9] = "getblocks",
  [10] = "getblocktxn",
  [11] = "getdata",
  [12] = "getheaders",
  [13] = "headers",
  [14] = "inv",
  [15] = "mempool",
  [16] = "merkleblock",
  [17] = "notfound",
  [18] = "ping",
  [19] = "pong",
  [20] = "sendcmpct",
  [21] = "tx",
  [22] = "getcfilters",
  [23] = "cfilter",
  [24] = "getcfheaders",
  [25] = "cfheaders",
  [26] = "getcfcheckpt",
  [27] = "cfcheckpt",
  [28] = "addrv2",
  -- 29-32 reserved
}

-- Reverse map: message type string to 1-byte ID
M.V2_MESSAGE_MAP = {}
for id, name in pairs(M.V2_MESSAGE_IDS) do
  if name ~= "" then
    M.V2_MESSAGE_MAP[name] = id
  end
end

--- Encode a message type for v2 transport.
-- Uses short 1-byte encoding if available, otherwise 12-byte string.
-- @param msg_type string: message type (e.g., "ping", "version")
-- @return string: encoded message type prefix
function M.encode_v2_message_type(msg_type)
  local short_id = M.V2_MESSAGE_MAP[msg_type]
  if short_id then
    -- Short encoding: 1-byte ID
    return string.char(short_id)
  else
    -- Long encoding: 0x00 + 12-byte null-padded command
    local cmd = msg_type:sub(1, 12)
    cmd = cmd .. string.rep("\0", 12 - #cmd)
    return "\0" .. cmd
  end
end

--- Decode message type from v2 transport contents.
-- @param contents string: packet contents (starts with type prefix)
-- @return string|nil, number: message type and bytes consumed, or nil on error
function M.decode_v2_message_type(contents)
  if #contents == 0 then
    return nil, 0
  end

  local first_byte = contents:byte(1)
  if first_byte ~= 0 then
    -- Short encoding
    local msg_type = M.V2_MESSAGE_IDS[first_byte]
    if not msg_type or msg_type == "" then
      return nil, 0  -- Unknown short ID
    end
    return msg_type, 1
  else
    -- Long encoding: 12-byte null-padded command
    if #contents < 13 then
      return nil, 0  -- Not enough data
    end
    local cmd = contents:sub(2, 13)
    -- Find end of command (first null or end of 12 bytes)
    local cmd_end = cmd:find("\0")
    if cmd_end then
      cmd = cmd:sub(1, cmd_end - 1)
    end
    -- Validate command characters (printable ASCII)
    for i = 1, #cmd do
      local c = cmd:byte(i)
      if c < 0x20 or c > 0x7F then
        return nil, 0  -- Invalid character
      end
    end
    return cmd, 13
  end
end

--------------------------------------------------------------------------------
-- Package Relay Messages (BIP 331)
--------------------------------------------------------------------------------

-- Package relay version
M.PKG_RELAY_VERSION = 1

--- Serialize a sendpackages message.
-- Sent during version handshake to negotiate package relay support.
-- @param version number: package relay version (1)
-- @return string: serialized sendpackages payload
function M.serialize_sendpackages(version)
  local w = serialize.buffer_writer()
  w.write_u64le(version)
  return w.result()
end

--- Deserialize a sendpackages message.
-- @param data string: sendpackages payload
-- @return table: {version}
function M.deserialize_sendpackages(data)
  local r = serialize.buffer_reader(data)
  return {
    version = r.read_u64le(),
  }
end

--- Serialize an ancpkginfo message.
-- Announces that package info is available for a transaction.
-- Sent for a 1p1c package when we have the parent and announce the child.
-- @param wtxid hash256: wtxid of the child transaction
-- @return string: serialized ancpkginfo payload
function M.serialize_ancpkginfo(wtxid)
  local w = serialize.buffer_writer()
  w.write_hash256(wtxid)
  return w.result()
end

--- Deserialize an ancpkginfo message.
-- @param data string: ancpkginfo payload
-- @return table: {wtxid}
function M.deserialize_ancpkginfo(data)
  local r = serialize.buffer_reader(data)
  return {
    wtxid = r.read_hash256(),
  }
end

--- Serialize a getpkgtxns message.
-- Request transactions for a package identified by package hash.
-- @param package_hash hash256: package hash (computed from sorted wtxids)
-- @param wtxids table: list of wtxids being requested
-- @return string: serialized getpkgtxns payload
function M.serialize_getpkgtxns(package_hash, wtxids)
  local w = serialize.buffer_writer()
  w.write_hash256(package_hash)
  w.write_varint(#wtxids)
  for _, wtxid in ipairs(wtxids) do
    w.write_hash256(wtxid)
  end
  return w.result()
end

--- Deserialize a getpkgtxns message.
-- @param data string: getpkgtxns payload
-- @return table: {package_hash, wtxids}
function M.deserialize_getpkgtxns(data)
  local r = serialize.buffer_reader(data)
  local package_hash = r.read_hash256()
  local count = r.read_varint()
  local wtxids = {}
  for i = 1, count do
    wtxids[i] = r.read_hash256()
  end
  return {
    package_hash = package_hash,
    wtxids = wtxids,
  }
end

--- Serialize a pkgtxns message.
-- Response to getpkgtxns with the requested transactions.
-- @param package_hash hash256: package hash
-- @param transactions table: list of transaction objects
-- @return string: serialized pkgtxns payload
function M.serialize_pkgtxns(package_hash, transactions)
  local w = serialize.buffer_writer()
  w.write_hash256(package_hash)
  w.write_varint(#transactions)
  for _, tx in ipairs(transactions) do
    w.write_bytes(serialize.serialize_transaction(tx, true))  -- always include witness
  end
  return w.result()
end

--- Deserialize a pkgtxns message.
-- @param data string: pkgtxns payload
-- @return table: {package_hash, transactions}
function M.deserialize_pkgtxns(data)
  local r = serialize.buffer_reader(data)
  local package_hash = r.read_hash256()
  local count = r.read_varint()
  local transactions = {}
  for i = 1, count do
    transactions[i] = serialize.deserialize_transaction(r)
  end
  return {
    package_hash = package_hash,
    transactions = transactions,
  }
end

--- Serialize a pckginfo1 message.
-- Package info for 1-parent-1-child (1p1c) packages.
-- @param parent_wtxid hash256: wtxid of parent transaction
-- @param child_wtxid hash256: wtxid of child transaction
-- @return string: serialized pckginfo1 payload
function M.serialize_pckginfo1(parent_wtxid, child_wtxid)
  local w = serialize.buffer_writer()
  w.write_hash256(parent_wtxid)
  w.write_hash256(child_wtxid)
  return w.result()
end

--- Deserialize a pckginfo1 message.
-- @param data string: pckginfo1 payload
-- @return table: {parent_wtxid, child_wtxid}
function M.deserialize_pckginfo1(data)
  local r = serialize.buffer_reader(data)
  return {
    parent_wtxid = r.read_hash256(),
    child_wtxid = r.read_hash256(),
  }
end

--------------------------------------------------------------------------------
-- BIP330 Erlay Messages
--------------------------------------------------------------------------------

--- Serialize a sendtxrcncl message.
-- Sent during handshake to negotiate Erlay transaction reconciliation.
-- @param version number: Erlay version (currently 1)
-- @param salt number: 64-bit reconciliation salt
-- @return string: serialized sendtxrcncl payload
function M.serialize_sendtxrcncl(version, salt)
  local w = serialize.buffer_writer()
  w.write_u32le(version)
  w.write_u64le(salt)
  return w.result()
end

--- Deserialize a sendtxrcncl message.
-- @param data string: sendtxrcncl payload
-- @return table: {version, salt}
function M.deserialize_sendtxrcncl(data)
  local r = serialize.buffer_reader(data)
  return {
    version = r.read_u32le(),
    salt = r.read_u64le(),
  }
end

--- Serialize a reqrecon message (request reconciliation).
-- @param set_size number: size of our reconciliation set for this peer
-- @param q number: difference coefficient (scaled by 2^16)
-- @return string: serialized reqrecon payload
function M.serialize_reqrecon(set_size, q)
  local w = serialize.buffer_writer()
  w.write_varint(set_size)
  w.write_u16le(math.floor(q * 65536))  -- Q scaled to uint16
  return w.result()
end

--- Deserialize a reqrecon message.
-- @param data string: reqrecon payload
-- @return table: {set_size, q}
function M.deserialize_reqrecon(data)
  local r = serialize.buffer_reader(data)
  return {
    set_size = r.read_varint(),
    q = r.read_u16le() / 65536,
  }
end

--- Serialize a sketch message.
-- @param sketch_bytes string: serialized minisketch
-- @return string: serialized sketch payload
function M.serialize_sketch(sketch_bytes)
  local w = serialize.buffer_writer()
  w.write_varint(#sketch_bytes)
  w.write_bytes(sketch_bytes)
  return w.result()
end

--- Deserialize a sketch message.
-- @param data string: sketch payload
-- @return string: sketch bytes
function M.deserialize_sketch(data)
  local r = serialize.buffer_reader(data)
  local len = r.read_varint()
  return r.read_bytes(len)
end

--- Serialize a reconcildiff message.
-- Sent after reconciliation to request missing transactions.
-- @param success boolean: whether reconciliation succeeded
-- @param want_txids table: list of short txids we want (only if success=true)
-- @return string: serialized reconcildiff payload
function M.serialize_reconcildiff(success, want_txids)
  local w = serialize.buffer_writer()
  w.write_u8(success and 1 or 0)
  if success then
    w.write_varint(#want_txids)
    for _, short_id in ipairs(want_txids) do
      w.write_u32le(short_id)
    end
  end
  return w.result()
end

--- Deserialize a reconcildiff message.
-- @param data string: reconcildiff payload
-- @return table: {success, want_txids}
function M.deserialize_reconcildiff(data)
  local r = serialize.buffer_reader(data)
  local success = r.read_u8() == 1
  local want_txids = {}
  if success then
    local count = r.read_varint()
    for i = 1, count do
      want_txids[i] = r.read_u32le()
    end
  end
  return {
    success = success,
    want_txids = want_txids,
  }
end

return M
