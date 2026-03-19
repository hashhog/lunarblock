local socket = require("socket")
local crypto = require("lunarblock.crypto")
local p2p = require("lunarblock.p2p")
local M = {}

--------------------------------------------------------------------------------
-- SOCKS5 Constants (RFC 1928)
--------------------------------------------------------------------------------

M.SOCKS_VERSION = 0x05

-- Authentication methods
M.SOCKS_AUTH = {
  NO_AUTH = 0x00,       -- No authentication required
  GSSAPI = 0x01,        -- GSSAPI
  USER_PASS = 0x02,     -- Username/password (RFC 1929)
  NO_ACCEPTABLE = 0xFF, -- No acceptable methods
}

-- SOCKS5 commands
M.SOCKS_CMD = {
  CONNECT = 0x01,
  BIND = 0x02,
  UDP_ASSOCIATE = 0x03,
}

-- Address types
M.SOCKS_ATYP = {
  IPV4 = 0x01,
  DOMAINNAME = 0x03,
  IPV6 = 0x04,
}

-- Reply codes
M.SOCKS_REPLY = {
  SUCCEEDED = 0x00,
  GENFAILURE = 0x01,        -- General failure
  NOTALLOWED = 0x02,        -- Connection not allowed by ruleset
  NETUNREACHABLE = 0x03,    -- Network unreachable
  HOSTUNREACHABLE = 0x04,   -- Host unreachable
  CONNREFUSED = 0x05,       -- Connection refused
  TTLEXPIRED = 0x06,        -- TTL expired
  CMDUNSUPPORTED = 0x07,    -- Command not supported
  ATYPEUNSUPPORTED = 0x08,  -- Address type not supported
  -- Tor-specific extension codes
  TOR_HS_DESC_NOT_FOUND = 0xF0,
  TOR_HS_DESC_INVALID = 0xF1,
  TOR_HS_INTRO_FAILED = 0xF2,
  TOR_HS_REND_FAILED = 0xF3,
  TOR_HS_MISSING_CLIENT_AUTH = 0xF4,
  TOR_HS_WRONG_CLIENT_AUTH = 0xF5,
  TOR_HS_BAD_ADDRESS = 0xF6,
  TOR_HS_INTRO_TIMEOUT = 0xF7,
}

--------------------------------------------------------------------------------
-- I2P SAM Constants
--------------------------------------------------------------------------------

M.I2P_SAM_PORT = 7656   -- Default SAM bridge port
M.I2P_DEFAULT_PORT = 0  -- I2P doesn't use ports (SAM 3.1)

--------------------------------------------------------------------------------
-- Network Types
--------------------------------------------------------------------------------

M.NETWORK_TYPE = {
  IPV4 = "ipv4",
  IPV6 = "ipv6",
  ONION = "onion",
  I2P = "i2p",
}

--------------------------------------------------------------------------------
-- Error Messages
--------------------------------------------------------------------------------

local SOCKS5_ERROR_STRINGS = {
  [M.SOCKS_REPLY.GENFAILURE] = "general failure",
  [M.SOCKS_REPLY.NOTALLOWED] = "connection not allowed",
  [M.SOCKS_REPLY.NETUNREACHABLE] = "network unreachable",
  [M.SOCKS_REPLY.HOSTUNREACHABLE] = "host unreachable",
  [M.SOCKS_REPLY.CONNREFUSED] = "connection refused",
  [M.SOCKS_REPLY.TTLEXPIRED] = "TTL expired",
  [M.SOCKS_REPLY.CMDUNSUPPORTED] = "command not supported",
  [M.SOCKS_REPLY.ATYPEUNSUPPORTED] = "address type not supported",
  [M.SOCKS_REPLY.TOR_HS_DESC_NOT_FOUND] = "onion service descriptor not found",
  [M.SOCKS_REPLY.TOR_HS_DESC_INVALID] = "onion service descriptor invalid",
  [M.SOCKS_REPLY.TOR_HS_INTRO_FAILED] = "onion service introduction failed",
  [M.SOCKS_REPLY.TOR_HS_REND_FAILED] = "onion service rendezvous failed",
  [M.SOCKS_REPLY.TOR_HS_MISSING_CLIENT_AUTH] = "onion service missing client authorization",
  [M.SOCKS_REPLY.TOR_HS_WRONG_CLIENT_AUTH] = "onion service wrong client authorization",
  [M.SOCKS_REPLY.TOR_HS_BAD_ADDRESS] = "onion service invalid address",
  [M.SOCKS_REPLY.TOR_HS_INTRO_TIMEOUT] = "onion service introduction timed out",
}

--- Get error string for SOCKS5 reply code.
-- @param code number: SOCKS5 reply code
-- @return string: human-readable error message
function M.socks5_error_string(code)
  return SOCKS5_ERROR_STRINGS[code] or string.format("unknown error (0x%02x)", code)
end

--------------------------------------------------------------------------------
-- Address Detection
--------------------------------------------------------------------------------

--- Detect the network type of an address.
-- @param addr string: address string
-- @return string: network type (ipv4, ipv6, onion, i2p)
function M.detect_network_type(addr)
  if not addr then return nil end

  -- Check for I2P (.b32.i2p suffix)
  if addr:match("%.b32%.i2p$") then
    return M.NETWORK_TYPE.I2P
  end

  -- Check for Tor v3 onion (56 chars base32 + .onion)
  if addr:match("%.onion$") then
    local onion_part = addr:gsub("%.onion$", "")
    if #onion_part == 56 then
      return M.NETWORK_TYPE.ONION
    end
    -- Legacy v2 onion (16 chars) - deprecated but detect it
    if #onion_part == 16 then
      return M.NETWORK_TYPE.ONION
    end
  end

  -- Check for IPv6 (contains colons)
  if addr:find(":") then
    return M.NETWORK_TYPE.IPV6
  end

  -- Check for IPv4 (dotted decimal)
  if addr:match("^%d+%.%d+%.%d+%.%d+$") then
    return M.NETWORK_TYPE.IPV4
  end

  -- Default to domain name (treat as IPv4 for routing)
  return M.NETWORK_TYPE.IPV4
end

--- Check if an address is a Tor .onion address.
-- @param addr string: address string
-- @return boolean: true if it's an onion address
function M.is_onion(addr)
  return M.detect_network_type(addr) == M.NETWORK_TYPE.ONION
end

--- Check if an address is an I2P address.
-- @param addr string: address string
-- @return boolean: true if it's an I2P address
function M.is_i2p(addr)
  return M.detect_network_type(addr) == M.NETWORK_TYPE.I2P
end

--------------------------------------------------------------------------------
-- SOCKS5 Proxy Client
--------------------------------------------------------------------------------

local Socks5Proxy = {}
Socks5Proxy.__index = Socks5Proxy

--- Create a new SOCKS5 proxy client.
-- @param host string: proxy host (default "127.0.0.1")
-- @param port number: proxy port (default 9050)
-- @param username string: optional username for authentication
-- @param password string: optional password for authentication
-- @return Socks5Proxy: new proxy object
function M.new_socks5(host, port, username, password)
  local self = setmetatable({}, Socks5Proxy)
  self.host = host or "127.0.0.1"
  self.port = port or 9050
  self.username = username
  self.password = password
  self.timeout = 20  -- 20 seconds for Tor (can be slow)
  self.stream_isolation = false  -- Generate unique credentials per connection
  self.isolation_counter = 0
  return self
end

--- Enable Tor stream isolation (unique credentials per connection).
-- This makes Tor use separate circuits for each connection.
function Socks5Proxy:enable_stream_isolation()
  self.stream_isolation = true
end

--- Generate stream isolation credentials.
-- @return string, string: username, password pair
function Socks5Proxy:_generate_isolation_credentials()
  self.isolation_counter = self.isolation_counter + 1
  -- Generate random-looking but deterministic credentials
  local rand_bytes = crypto.sha256(string.format("lunarblock:%d:%d", os.time(), self.isolation_counter))
  local user = string.format("lunarblock%d", self.isolation_counter)
  local pass = crypto.to_hex(rand_bytes:sub(1, 8))
  return user, pass
end

--- Receive exactly n bytes from socket with timeout.
-- @param sock socket: the socket
-- @param n number: number of bytes to receive
-- @param timeout number: timeout in seconds
-- @return string|nil: received data or nil on error
-- @return string: error message if failed
function Socks5Proxy:_recv_exact(sock, n, timeout)
  local data = ""
  local start_time = socket.gettime()
  sock:settimeout(0.1)  -- Short timeout for polling

  while #data < n do
    if socket.gettime() - start_time > timeout then
      return nil, "timeout"
    end
    local chunk, err = sock:receive(n - #data)
    if chunk then
      data = data .. chunk
    elseif err ~= "timeout" then
      return nil, err
    end
  end

  return data
end

--- Perform SOCKS5 handshake and connect to target.
-- @param dest string: destination address (IP or domain)
-- @param dest_port number: destination port
-- @return socket|nil: connected socket on success
-- @return string: error message on failure
function Socks5Proxy:connect(dest, dest_port)
  -- Validate destination
  if not dest or #dest == 0 then
    return nil, "empty destination"
  end
  if #dest > 255 then
    return nil, "hostname too long (max 255 chars)"
  end

  -- Connect to proxy
  local sock = socket.tcp()
  sock:settimeout(self.timeout)

  local ok, err = sock:connect(self.host, self.port)
  if not ok then
    sock:close()
    return nil, "failed to connect to proxy: " .. (err or "unknown")
  end

  -- Determine authentication method
  local use_auth = self.username and self.password
  if self.stream_isolation then
    use_auth = true
  end

  -- Step 1: Send version identifier/method selection
  local methods
  if use_auth then
    methods = string.char(
      M.SOCKS_VERSION,
      2,  -- 2 methods
      M.SOCKS_AUTH.NO_AUTH,
      M.SOCKS_AUTH.USER_PASS
    )
  else
    methods = string.char(
      M.SOCKS_VERSION,
      1,  -- 1 method
      M.SOCKS_AUTH.NO_AUTH
    )
  end

  local sent, send_err = sock:send(methods)
  if not sent then
    sock:close()
    return nil, "failed to send method selection: " .. (send_err or "unknown")
  end

  -- Step 2: Receive method selection response
  local resp, recv_err = self:_recv_exact(sock, 2, self.timeout)
  if not resp then
    sock:close()
    return nil, "failed to receive method response: " .. (recv_err or "unknown")
  end

  local version = resp:byte(1)
  local method = resp:byte(2)

  if version ~= M.SOCKS_VERSION then
    sock:close()
    return nil, string.format("proxy returned wrong SOCKS version: %d", version)
  end

  -- Step 3: Handle authentication if required
  if method == M.SOCKS_AUTH.USER_PASS then
    local username, password
    if self.stream_isolation then
      username, password = self:_generate_isolation_credentials()
    else
      username, password = self.username, self.password
    end

    if not username or not password then
      sock:close()
      return nil, "proxy requires authentication but no credentials provided"
    end

    -- RFC 1929 username/password authentication
    local auth_request = string.char(0x01)  -- version
      .. string.char(#username) .. username
      .. string.char(#password) .. password

    sent, send_err = sock:send(auth_request)
    if not sent then
      sock:close()
      return nil, "failed to send authentication: " .. (send_err or "unknown")
    end

    local auth_resp
    auth_resp, recv_err = self:_recv_exact(sock, 2, self.timeout)
    if not auth_resp then
      sock:close()
      return nil, "failed to receive auth response: " .. (recv_err or "unknown")
    end

    if auth_resp:byte(1) ~= 0x01 or auth_resp:byte(2) ~= 0x00 then
      sock:close()
      return nil, "proxy authentication failed"
    end

  elseif method == M.SOCKS_AUTH.NO_AUTH then
    -- No authentication required, continue
  elseif method == M.SOCKS_AUTH.NO_ACCEPTABLE then
    sock:close()
    return nil, "proxy rejected all authentication methods"
  else
    sock:close()
    return nil, string.format("proxy requested unknown auth method: 0x%02x", method)
  end

  -- Step 4: Send CONNECT request
  -- Use domain name type (0x03) for all addresses to let proxy resolve
  -- This is important for .onion addresses which can only be resolved by Tor
  local connect_request = string.char(
    M.SOCKS_VERSION,     -- VER
    M.SOCKS_CMD.CONNECT, -- CMD
    0x00,                -- RSV (reserved)
    M.SOCKS_ATYP.DOMAINNAME  -- ATYP
  )
  connect_request = connect_request .. string.char(#dest)  -- domain length
  connect_request = connect_request .. dest                 -- domain name
  -- Port in network byte order (big endian)
  connect_request = connect_request .. string.char(
    math.floor(dest_port / 256),
    dest_port % 256
  )

  sent, send_err = sock:send(connect_request)
  if not sent then
    sock:close()
    return nil, "failed to send connect request: " .. (send_err or "unknown")
  end

  -- Step 5: Receive CONNECT response
  -- Response: VER REP RSV ATYP BND.ADDR BND.PORT
  local conn_resp
  conn_resp, recv_err = self:_recv_exact(sock, 4, self.timeout)
  if not conn_resp then
    sock:close()
    return nil, "failed to receive connect response: " .. (recv_err or "unknown")
  end

  version = conn_resp:byte(1)
  local reply = conn_resp:byte(2)
  -- local rsv = conn_resp:byte(3)
  local atyp = conn_resp:byte(4)

  if version ~= M.SOCKS_VERSION then
    sock:close()
    return nil, string.format("proxy returned wrong SOCKS version in reply: %d", version)
  end

  if reply ~= M.SOCKS_REPLY.SUCCEEDED then
    sock:close()
    return nil, "proxy connect failed: " .. M.socks5_error_string(reply)
  end

  -- Read and discard bound address based on type
  local addr_len
  if atyp == M.SOCKS_ATYP.IPV4 then
    addr_len = 4
  elseif atyp == M.SOCKS_ATYP.IPV6 then
    addr_len = 16
  elseif atyp == M.SOCKS_ATYP.DOMAINNAME then
    local len_byte
    len_byte, recv_err = self:_recv_exact(sock, 1, self.timeout)
    if not len_byte then
      sock:close()
      return nil, "failed to receive bound address length"
    end
    addr_len = len_byte:byte(1)
  else
    sock:close()
    return nil, string.format("proxy returned unknown address type: 0x%02x", atyp)
  end

  -- Read bound address
  local bound_addr
  bound_addr, recv_err = self:_recv_exact(sock, addr_len, self.timeout)
  if not bound_addr then
    sock:close()
    return nil, "failed to receive bound address"
  end

  -- Read bound port (2 bytes)
  local bound_port_bytes
  bound_port_bytes, recv_err = self:_recv_exact(sock, 2, self.timeout)
  if not bound_port_bytes then
    sock:close()
    return nil, "failed to receive bound port"
  end

  -- Connection established! Set non-blocking mode and return socket
  sock:settimeout(0)
  return sock
end

--------------------------------------------------------------------------------
-- I2P SAM Protocol Client
--------------------------------------------------------------------------------

local I2PSam = {}
I2PSam.__index = I2PSam

--- Create a new I2P SAM client.
-- @param host string: SAM bridge host (default "127.0.0.1")
-- @param port number: SAM bridge port (default 7656)
-- @param private_key_file string: path to persistent private key file (optional)
-- @return I2PSam: new SAM client object
function M.new_i2p_sam(host, port, private_key_file)
  local self = setmetatable({}, I2PSam)
  self.host = host or "127.0.0.1"
  self.port = port or M.I2P_SAM_PORT
  self.private_key_file = private_key_file
  self.timeout = 180  -- 3 minutes (I2P lookups can be slow)
  self.control_sock = nil
  self.session_id = nil
  self.my_destination = nil  -- Our I2P address
  self.my_addr = nil         -- Our .b32.i2p address
  self.private_key = nil     -- Our private key (base64)
  return self
end

--- Swap between standard Base64 and I2P Base64.
-- I2P uses - and ~ instead of + and /
-- @param str string: base64 string
-- @return string: converted string
local function swap_i2p_base64(str)
  return str:gsub("[%-~+/]", {
    ["-"] = "+",
    ["~"] = "/",
    ["+"] = "-",
    ["/"] = "~",
  })
end

--- Receive a line (up to newline) from socket.
-- @param sock socket: the socket
-- @param timeout number: timeout in seconds
-- @return string|nil: received line (without newline)
-- @return string: error message if failed
function I2PSam:_recv_line(sock, timeout)
  local data = ""
  local start_time = socket.gettime()
  sock:settimeout(0.1)

  while true do
    if socket.gettime() - start_time > timeout then
      return nil, "timeout"
    end
    local char, err = sock:receive(1)
    if char then
      if char == "\n" then
        return data
      end
      data = data .. char
    elseif err ~= "timeout" then
      return nil, err
    end
  end
end

--- Parse SAM reply into key-value pairs.
-- @param line string: SAM reply line
-- @return table: parsed key-value pairs
function I2PSam:_parse_reply(line)
  local result = {}
  for part in line:gmatch("%S+") do
    local key, value = part:match("([^=]+)=(.+)")
    if key then
      result[key] = value
    else
      result[part] = true
    end
  end
  return result
end

--- Send request and get reply from SAM.
-- @param sock socket: the socket
-- @param request string: SAM request
-- @param check_ok boolean: check for RESULT=OK (default true)
-- @return table: parsed reply
-- @return string: error message if failed
function I2PSam:_send_request(sock, request, check_ok)
  if check_ok == nil then check_ok = true end

  local sent, err = sock:send(request .. "\n")
  if not sent then
    return nil, "failed to send: " .. (err or "unknown")
  end

  local reply_line, recv_err = self:_recv_line(sock, self.timeout)
  if not reply_line then
    return nil, "failed to receive: " .. (recv_err or "unknown")
  end

  local reply = self:_parse_reply(reply_line)
  reply._raw = reply_line

  if check_ok and reply.RESULT ~= "OK" then
    local msg = reply.MESSAGE or "unknown error"
    return nil, string.format("SAM error: RESULT=%s MESSAGE=%s", reply.RESULT or "nil", msg)
  end

  return reply
end

--- Perform SAM HELLO handshake.
-- @param sock socket: the socket
-- @return boolean: true on success
-- @return string: error message if failed
function I2PSam:_hello(sock)
  local reply, err = self:_send_request(sock, "HELLO VERSION MIN=3.1 MAX=3.1")
  if not reply then
    return nil, err
  end
  return true
end

--- Create a new socket and perform HELLO.
-- @return socket: connected socket with HELLO complete
-- @return string: error message if failed
function I2PSam:_connect_and_hello()
  local sock = socket.tcp()
  sock:settimeout(self.timeout)

  local ok, err = sock:connect(self.host, self.port)
  if not ok then
    sock:close()
    return nil, "failed to connect to SAM bridge: " .. (err or "unknown")
  end

  ok, err = self:_hello(sock)
  if not ok then
    sock:close()
    return nil, err
  end

  return sock
end

--- Derive .b32.i2p address from destination.
-- @param dest_binary string: binary destination data
-- @return string: .b32.i2p address
function I2PSam:_dest_to_addr(dest_binary)
  local hash = crypto.sha256(dest_binary)
  -- Base32 encode and add suffix
  local base32_chars = "abcdefghijklmnopqrstuvwxyz234567"
  local result = ""
  local bits = 0
  local accum = 0

  for i = 1, #hash do
    accum = accum * 256 + hash:byte(i)
    bits = bits + 8
    while bits >= 5 do
      bits = bits - 5
      local index = math.floor(accum / (2 ^ bits)) % 32
      result = result .. base32_chars:sub(index + 1, index + 1)
      accum = accum % (2 ^ bits)
    end
  end

  if bits > 0 then
    local index = (accum * (2 ^ (5 - bits))) % 32
    result = result .. base32_chars:sub(index + 1, index + 1)
  end

  return result .. ".b32.i2p"
end

--- Generate a new I2P destination.
-- @return string: private key in I2P base64
-- @return string: error message if failed
function I2PSam:_generate_destination()
  local sock, err = self:_connect_and_hello()
  if not sock then
    return nil, err
  end

  -- Use EdDSA signature type (7) for modern destinations
  local reply
  reply, err = self:_send_request(sock, "DEST GENERATE SIGNATURE_TYPE=7", false)
  sock:close()

  if not reply then
    return nil, err
  end

  local priv = reply.PRIV
  if not priv then
    return nil, "no PRIV in DEST GENERATE reply"
  end

  return priv
end

--- Create an I2P session.
-- @return boolean: true on success
-- @return string: error message if failed
function I2PSam:create_session()
  if self.control_sock then
    return true  -- Already have a session
  end

  -- Connect and hello
  local sock, err = self:_connect_and_hello()
  if not sock then
    return nil, err
  end

  -- Generate or load private key
  local private_key
  if self.private_key_file then
    local f = io.open(self.private_key_file, "r")
    if f then
      private_key = f:read("*a")
      f:close()
    end
  end

  if not private_key then
    private_key, err = self:_generate_destination()
    if not private_key then
      sock:close()
      return nil, err
    end

    -- Save if file specified
    if self.private_key_file then
      local f = io.open(self.private_key_file, "w")
      if f then
        f:write(private_key)
        f:close()
      end
    end
  end

  self.private_key = private_key

  -- Generate session ID
  local rand_bytes = crypto.sha256(tostring(os.time()) .. tostring(math.random()))
  self.session_id = crypto.to_hex(rand_bytes:sub(1, 5))

  -- Create session
  local request = string.format(
    "SESSION CREATE STYLE=STREAM ID=%s DESTINATION=%s i2cp.leaseSetEncType=4,0 inbound.quantity=3 outbound.quantity=3",
    self.session_id,
    private_key
  )

  local reply
  reply, err = self:_send_request(sock, request)
  if not reply then
    sock:close()
    return nil, err
  end

  -- Extract our destination and convert to .b32.i2p
  local dest = reply.DESTINATION
  if dest then
    -- Decode I2P base64 to binary
    local std_b64 = swap_i2p_base64(dest)
    -- Simple base64 decode (we only need the hash)
    local decoded = ""
    local b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    local bits = 0
    local accum = 0

    for i = 1, #std_b64 do
      local c = std_b64:sub(i, i)
      local val = b64chars:find(c)
      if val then
        accum = accum * 64 + (val - 1)
        bits = bits + 6
        while bits >= 8 do
          bits = bits - 8
          local byte_val = math.floor(accum / (2 ^ bits)) % 256
          decoded = decoded .. string.char(byte_val)
          accum = accum % (2 ^ bits)
        end
      end
    end

    self.my_destination = decoded
    self.my_addr = self:_dest_to_addr(decoded)
  end

  self.control_sock = sock
  return true
end

--- Connect to an I2P destination.
-- @param dest string: destination address (.b32.i2p)
-- @return socket|nil: connected socket on success
-- @return string: error message if failed
function I2PSam:connect(dest)
  -- Ensure session exists
  local ok, err = self:create_session()
  if not ok then
    return nil, err
  end

  -- Create new socket for this connection
  local sock
  sock, err = self:_connect_and_hello()
  if not sock then
    return nil, err
  end

  -- Lookup the destination
  local lookup_reply
  lookup_reply, err = self:_send_request(sock, "NAMING LOOKUP NAME=" .. dest, false)
  if not lookup_reply then
    sock:close()
    return nil, err
  end

  if lookup_reply.RESULT ~= "OK" then
    sock:close()
    return nil, "I2P lookup failed: " .. (lookup_reply.MESSAGE or lookup_reply.RESULT or "unknown")
  end

  local full_dest = lookup_reply.VALUE
  if not full_dest then
    sock:close()
    return nil, "no VALUE in NAMING LOOKUP reply"
  end

  -- Connect to the destination
  local connect_request = string.format(
    "STREAM CONNECT ID=%s DESTINATION=%s SILENT=false",
    self.session_id,
    full_dest
  )

  local connect_reply
  connect_reply, err = self:_send_request(sock, connect_request, false)
  if not connect_reply then
    sock:close()
    return nil, err
  end

  local result = connect_reply.RESULT
  if result ~= "OK" then
    sock:close()
    if result == "INVALID_ID" then
      -- Session invalid, need to recreate
      self:disconnect_session()
      return nil, "I2P session invalid, needs recreation"
    end
    return nil, "I2P connect failed: " .. (connect_reply.MESSAGE or result or "unknown")
  end

  -- Connection established
  sock:settimeout(0)
  return sock
end

--- Accept an inbound I2P connection.
-- @return socket|nil: connected socket on success
-- @return string: peer address
-- @return string: error message if failed
function I2PSam:accept()
  -- Ensure session exists
  local ok, err = self:create_session()
  if not ok then
    return nil, nil, err
  end

  -- Create new socket for accepting
  local sock
  sock, err = self:_connect_and_hello()
  if not sock then
    return nil, nil, err
  end

  -- Send STREAM ACCEPT
  local accept_request = string.format("STREAM ACCEPT ID=%s SILENT=false", self.session_id)
  local reply
  reply, err = self:_send_request(sock, accept_request, false)
  if not reply then
    sock:close()
    return nil, nil, err
  end

  if reply.RESULT ~= "OK" then
    sock:close()
    if reply.RESULT == "INVALID_ID" then
      self:disconnect_session()
      return nil, nil, "I2P session invalid"
    end
    return nil, nil, "I2P accept failed: " .. (reply.MESSAGE or reply.RESULT or "unknown")
  end

  -- Wait for incoming connection
  -- The next line will contain the peer's destination
  local peer_dest
  peer_dest, err = self:_recv_line(sock, self.timeout)
  if not peer_dest then
    sock:close()
    return nil, nil, "failed to receive peer destination: " .. (err or "unknown")
  end

  -- Convert to .b32.i2p address
  local std_b64 = swap_i2p_base64(peer_dest)
  local decoded = ""
  local b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  local bits = 0
  local accum = 0

  for i = 1, #std_b64 do
    local c = std_b64:sub(i, i)
    local val = b64chars:find(c)
    if val then
      accum = accum * 64 + (val - 1)
      bits = bits + 6
      while bits >= 8 do
        bits = bits - 8
        local byte_val = math.floor(accum / (2 ^ bits)) % 256
        decoded = decoded .. string.char(byte_val)
        accum = accum % (2 ^ bits)
      end
    end
  end

  local peer_addr = self:_dest_to_addr(decoded)

  sock:settimeout(0)
  return sock, peer_addr
end

--- Disconnect the I2P session.
function I2PSam:disconnect_session()
  if self.control_sock then
    self.control_sock:close()
    self.control_sock = nil
  end
  self.session_id = nil
end

--- Get our I2P address.
-- @return string: .b32.i2p address
function I2PSam:get_my_address()
  return self.my_addr
end

--------------------------------------------------------------------------------
-- Proxy Configuration
--------------------------------------------------------------------------------

local ProxyConfig = {}
ProxyConfig.__index = ProxyConfig

--- Create a new proxy configuration.
-- @return ProxyConfig: new configuration object
function M.new_config()
  local self = setmetatable({}, ProxyConfig)
  self.socks5_proxy = nil    -- Socks5Proxy object for Tor
  self.i2p_sam = nil         -- I2PSam object for I2P
  self.onlynet = nil         -- Network restriction (onion, i2p, ipv4, ipv6)
  self.proxy_dns = false     -- Resolve DNS through proxy
  return self
end

--- Configure SOCKS5 proxy (for Tor).
-- @param host string: proxy host
-- @param port number: proxy port
-- @param stream_isolation boolean: enable Tor stream isolation
function ProxyConfig:set_socks5_proxy(host, port, stream_isolation)
  self.socks5_proxy = M.new_socks5(host, port)
  if stream_isolation then
    self.socks5_proxy:enable_stream_isolation()
  end
end

--- Configure I2P SAM.
-- @param host string: SAM bridge host
-- @param port number: SAM bridge port
-- @param private_key_file string: path to private key file
function ProxyConfig:set_i2p_sam(host, port, private_key_file)
  self.i2p_sam = M.new_i2p_sam(host, port, private_key_file)
end

--- Set network restriction.
-- @param net string: network to allow (onion, i2p, ipv4, ipv6, or nil for all)
function ProxyConfig:set_onlynet(net)
  if net then
    net = net:lower()
    if net ~= "onion" and net ~= "i2p" and net ~= "ipv4" and net ~= "ipv6" then
      error("invalid onlynet value: " .. net)
    end
  end
  self.onlynet = net
end

--- Check if an address is allowed by network restriction.
-- @param addr string: address to check
-- @return boolean: true if allowed
function ProxyConfig:is_address_allowed(addr)
  if not self.onlynet then
    return true  -- No restriction
  end

  local net_type = M.detect_network_type(addr)

  if self.onlynet == "onion" then
    return net_type == M.NETWORK_TYPE.ONION
  elseif self.onlynet == "i2p" then
    return net_type == M.NETWORK_TYPE.I2P
  elseif self.onlynet == "ipv4" then
    return net_type == M.NETWORK_TYPE.IPV4
  elseif self.onlynet == "ipv6" then
    return net_type == M.NETWORK_TYPE.IPV6
  end

  return false
end

--- Connect to an address using the appropriate proxy.
-- @param addr string: target address
-- @param port number: target port
-- @return socket|nil: connected socket
-- @return string: error message if failed
function ProxyConfig:connect(addr, port)
  -- Check network restriction
  if not self:is_address_allowed(addr) then
    return nil, "address not allowed by onlynet restriction"
  end

  local net_type = M.detect_network_type(addr)

  -- I2P addresses must use I2P SAM
  if net_type == M.NETWORK_TYPE.I2P then
    if not self.i2p_sam then
      return nil, "no I2P SAM configured for I2P address"
    end
    return self.i2p_sam:connect(addr)
  end

  -- Onion addresses must use SOCKS5 proxy (Tor)
  if net_type == M.NETWORK_TYPE.ONION then
    if not self.socks5_proxy then
      return nil, "no SOCKS5 proxy configured for onion address"
    end
    return self.socks5_proxy:connect(addr, port)
  end

  -- Regular addresses: use proxy if configured and proxy_dns enabled
  if self.socks5_proxy and self.proxy_dns then
    return self.socks5_proxy:connect(addr, port)
  end

  -- Direct connection
  local sock = socket.tcp()
  sock:settimeout(5)
  local ok, err = sock:connect(addr, port)
  if not ok then
    sock:close()
    return nil, err
  end
  sock:settimeout(0)
  return sock
end

--- Resolve DNS through proxy (for DNS leak prevention).
-- This actually connects through the proxy and lets it resolve.
-- @param hostname string: hostname to resolve
-- @param port number: port to connect to (for SOCKS5 CONNECT)
-- @return socket|nil: connected socket (as a side effect of resolution)
-- @return string: error message if failed
function ProxyConfig:resolve_through_proxy(hostname, port)
  if not self.socks5_proxy then
    return nil, "no SOCKS5 proxy configured"
  end
  return self.socks5_proxy:connect(hostname, port)
end

return M
