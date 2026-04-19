local socket = require("socket")
local p2p = require("lunarblock.p2p")
local bip324 = require("lunarblock.bip324")
local proxy_mod = require("lunarblock.proxy")
local erlay = require("lunarblock.erlay")
local bit = require("bit")
local ffi = require("ffi")
local M = {}

--------------------------------------------------------------------------------
-- FFI Poll (avoids callbacks, allows JIT compilation)
--------------------------------------------------------------------------------

-- Define poll structure and function
-- This avoids FFI callbacks which prevent JIT compilation of surrounding code
ffi.cdef[[
  typedef struct { int fd; short events; short revents; } pollfd_t;
  int poll(pollfd_t* fds, unsigned long nfds, int timeout);
]]

local POLLIN = 1   -- Data available to read
local POLLOUT = 4  -- Writing possible

local pollfd_cache = ffi.new("pollfd_t")

--- Check if a socket is readable without blocking.
-- Uses direct poll() syscall instead of FFI callbacks to allow JIT compilation.
-- @param socket_fd number: socket file descriptor
-- @param timeout_ms number: timeout in milliseconds (default 0 = non-blocking)
-- @return boolean: true if socket has data available
function M.poll_readable(socket_fd, timeout_ms)
  pollfd_cache.fd = socket_fd
  pollfd_cache.events = POLLIN
  pollfd_cache.revents = 0
  local ret = ffi.C.poll(pollfd_cache, 1, timeout_ms or 0)
  return ret > 0 and bit.band(pollfd_cache.revents, POLLIN) ~= 0
end

--- Check if a socket is writable without blocking.
-- @param socket_fd number: socket file descriptor
-- @param timeout_ms number: timeout in milliseconds (default 0)
-- @return boolean: true if socket can accept writes
function M.poll_writable(socket_fd, timeout_ms)
  pollfd_cache.fd = socket_fd
  pollfd_cache.events = POLLOUT
  pollfd_cache.revents = 0
  local ret = ffi.C.poll(pollfd_cache, 1, timeout_ms or 0)
  return ret > 0 and bit.band(pollfd_cache.revents, POLLOUT) ~= 0
end

--- Poll multiple sockets for readability.
-- Batches poll calls to minimize FFI overhead.
-- @param fds table: array of socket file descriptors
-- @param timeout_ms number: timeout in milliseconds
-- @return table: array of booleans indicating readability
function M.poll_readable_multi(fds, timeout_ms)
  local n = #fds
  if n == 0 then return {} end

  local pollfds = ffi.new("pollfd_t[?]", n)
  for i = 1, n do
    pollfds[i - 1].fd = fds[i]
    pollfds[i - 1].events = POLLIN
    pollfds[i - 1].revents = 0
  end

  local ret = ffi.C.poll(pollfds, n, timeout_ms or 0)
  local results = {}
  for i = 1, n do
    results[i] = ret > 0 and bit.band(pollfds[i - 1].revents, POLLIN) ~= 0
  end
  return results
end

--------------------------------------------------------------------------------
-- Peer States
--------------------------------------------------------------------------------

M.STATE = {
  DISCONNECTED = "disconnected",
  CONNECTING = "connecting",
  CONNECTED = "connected",      -- TCP connected, awaiting handshake
  V2_KEY_SENT = "v2_key_sent",  -- V2: sent our ElligatorSwift key
  V2_KEY_RECV = "v2_key_recv",  -- V2: received peer's key, awaiting garbage terminator
  V2_READY = "v2_ready",        -- V2: encryption ready, awaiting version packet
  VERSION_SENT = "version_sent",
  VERACK_SENT = "verack_sent",
  ESTABLISHED = "established",  -- Handshake complete, ready for messages
  DISCONNECTING = "disconnecting",
}

--------------------------------------------------------------------------------
-- Pre-Handshake Allowed Messages (Bitcoin Core: net_processing.cpp)
--------------------------------------------------------------------------------

-- Messages allowed before handshake completion (fSuccessfullyConnected)
-- See Bitcoin Core net_processing.cpp: version, verack, and feature negotiation
-- messages that must be sent between VERSION and VERACK.
M.PRE_HANDSHAKE_ALLOWED = {
  version = true,
  verack = true,
  wtxidrelay = true,   -- BIP 339: Must be sent before VERACK
  sendaddrv2 = true,   -- BIP 155: Must be sent before VERACK
  sendheaders = true,  -- BIP 130: Accepted pre-handshake
  sendtxrcncl = true,  -- BIP 330: Must be sent before VERACK
}

-- Handshake timeout in seconds (60 seconds per spec)
M.HANDSHAKE_TIMEOUT = 60

--------------------------------------------------------------------------------
-- Peer Object
--------------------------------------------------------------------------------

local Peer = {}
Peer.__index = Peer

--- Create a new Peer object.
-- @param ip string: peer IP address
-- @param port number: peer port (optional, defaults to network.port)
-- @param network table: network configuration from consensus module
-- @param our_height number: our current blockchain height (optional)
-- @param use_v2 boolean: use BIP324 v2 encrypted transport (optional, default true)
-- @param proxy_config table: proxy configuration (optional)
-- @return Peer: new peer object
function M.new(ip, port, network, our_height, use_v2, proxy_config)
  local self = setmetatable({}, Peer)
  self.ip = ip
  self.port = port or (network and network.port) or 8333
  self.network = network
  self.state = M.STATE.DISCONNECTED
  self.socket = nil
  self.recv_buffer = ""           -- Accumulates incoming bytes
  self.version_info = nil         -- Peer's version message data
  self.services = 0
  self.start_height = 0
  self.user_agent = ""
  self.nonce = 0                  -- Our nonce for this connection
  self.our_height = our_height or 0
  self.last_send = 0
  self.last_recv = 0
  self.bytes_sent = 0
  self.bytes_recv = 0
  self.conn_time = 0           -- Set on CONNECT, used by getpeerinfo.conntime
  self.last_ping_time = 0
  self.last_pong_time = 0
  self.ping_nonce = 0
  self.latency_ms = 0
  self.ban_score = 0
  self.inbound = false
  self.send_headers = false       -- Peer requested headers announcements
  self.send_compact = false       -- Peer supports compact blocks
  self.compact_version = 0        -- Compact block version (1 = txid, 2 = wtxid)
  self.high_bandwidth = false     -- Peer wants high-bandwidth compact blocks
  self.provides_compact = false   -- Peer will provide compact blocks if requested
  self.fee_filter = 0             -- Minimum fee rate (sat/KB) peer accepts
  self.message_handlers = {}      -- command -> handler function
  self.inflight_blocks = {}       -- block hashes we've requested
  self.inflight_txs = {}          -- tx hashes we've requested
  self.known_blocks = {}          -- block hashes peer has announced
  self.known_txs = {}             -- tx hashes peer has announced
  self.handshake_complete = false -- True after version/verack exchange
  self.version_received = false   -- True after receiving their version
  self.handshake_start_time = 0   -- When connection started (for timeout)
  self.wtxid_relay = false        -- BIP 339: peer wants wtxid for tx relay
  self.send_addrv2 = false        -- BIP 155: peer supports addrv2

  -- Erlay (BIP330)
  self.erlay_enabled = false      -- True if Erlay was negotiated
  self.erlay_version = 0          -- Negotiated Erlay version
  self.erlay_salt = 0             -- Our Erlay salt
  self.erlay_their_salt = 0       -- Their Erlay salt
  self.erlay_combined_salt = 0    -- Combined salt for reconciliation
  self.erlay_last_recon = 0       -- Time of last reconciliation
  self.erlay_recon_pending = false -- Waiting for reconciliation response

  -- V2 transport (BIP324)
  self.use_v2 = (use_v2 ~= false) -- Default to v2, can disable with false
  self.v2_transport = nil         -- V2Transport object (created on connect)
  self.v2_active = false          -- True when v2 encryption is active
  self.v2_handshake_done = false  -- True after v2 crypto handshake complete
  self.session_id = nil           -- BIP324 session ID (32 bytes)

  -- Proxy configuration
  self.proxy_config = proxy_config -- ProxyConfig object from proxy module
  self.network_type = proxy_mod.detect_network_type(ip) -- Network type (ipv4, ipv6, onion, i2p)
  self.connected_via_proxy = false -- True if connected through a proxy
  return self
end

--------------------------------------------------------------------------------
-- Connection Methods
--------------------------------------------------------------------------------

--- Connect to the peer.
-- @param timeout number: connection timeout in seconds (default 5)
-- @return boolean: true on success
-- @return string: error message on failure
function Peer:connect(timeout)
  self.state = M.STATE.CONNECTING
  local ok, err

  -- Determine if we need to use a proxy
  local need_proxy = false
  if self.proxy_config then
    -- Check network restriction
    if not self.proxy_config:is_address_allowed(self.ip) then
      self:disconnect("address not allowed by onlynet restriction")
      return false, "address not allowed by onlynet restriction"
    end

    -- Onion and I2P addresses require proxy
    if self.network_type == proxy_mod.NETWORK_TYPE.ONION or
       self.network_type == proxy_mod.NETWORK_TYPE.I2P then
      need_proxy = true
    end

    -- Use proxy for all connections if proxy_dns is enabled (DNS leak prevention)
    if self.proxy_config.proxy_dns then
      need_proxy = true
    end
  end

  if need_proxy and self.proxy_config then
    -- Connect through proxy
    self.socket, err = self.proxy_config:connect(self.ip, self.port)
    if not self.socket then
      self:disconnect("proxy connect failed: " .. (err or "unknown"))
      return false, err
    end
    self.connected_via_proxy = true

    -- For onion/I2P addresses, disable v2 transport (already encrypted)
    if self.network_type == proxy_mod.NETWORK_TYPE.ONION or
       self.network_type == proxy_mod.NETWORK_TYPE.I2P then
      self.use_v2 = false
    end
  else
    -- Direct connection
    self.socket = socket.tcp()
    -- Use 0.5s timeout for connect (was 5s) to limit event-loop blocking when
    -- peers are unreachable. Combined with 1-attempt-per-tick in maintain_connections,
    -- RPC latency is bounded at ~500ms per reconnect event (W21 starvation fix).
    self.socket:settimeout(timeout or 0.5)
    ok, err = self.socket:connect(self.ip, self.port)
    if not ok then
      self:disconnect("connect failed: " .. (err or "unknown"))
      return false, err
    end
    self.socket:settimeout(0)  -- Non-blocking after connection
  end

  self.state = M.STATE.CONNECTED
  self.last_recv = socket.gettime()
  self.conn_time = socket.gettime()
  self.handshake_start_time = socket.gettime()  -- Start handshake timer

  -- Initialize v2 transport if enabled
  if self.use_v2 then
    self.v2_transport = bip324.V2Transport(self.network.magic_bytes, true, self.ip, self.port)
  end

  return true
end

--- Start v2 handshake (send ElligatorSwift key + garbage).
function Peer:start_v2_handshake()
  if not self.v2_transport then return false end

  -- Send our public key + garbage
  local handshake_bytes = self.v2_transport:get_handshake_bytes()
  local sent, err = self.socket:send(handshake_bytes)
  if not sent then
    self:disconnect("v2 handshake send failed: " .. (err or "unknown"))
    return false
  end
  self.state = M.STATE.V2_KEY_SENT
  self.last_send = socket.gettime()
  self.bytes_sent = self.bytes_sent + #handshake_bytes
  return true
end

--- Process v2 handshake data.
-- @return boolean: true if handshake complete, false if need more data
-- @return string|nil: error message on failure
function Peer:process_v2_handshake()
  if not self.v2_transport then return false, "no v2 transport" end

  local ok, err = self.v2_transport:recv_bytes(self.recv_buffer)
  self.recv_buffer = ""  -- V2Transport handles its own buffering

  if not ok then
    self:disconnect("v2 handshake failed: " .. (err or "unknown"))
    return false, err
  end

  -- Check for v1 fallback
  if self.v2_transport:is_v1() then
    -- Peer is using v1, fallback
    self.use_v2 = false
    self.v2_active = false
    self.recv_buffer = self.v2_transport:get_v1_prefix()
    self.v2_transport = nil
    self.state = M.STATE.CONNECTED
    return true  -- Continue with v1
  end

  -- Check if v2 cipher is ready
  if self.v2_transport:ready_to_send() and not self.v2_handshake_done then
    -- Cipher initialized, send garbage terminator + version packet
    local version_bytes = self.v2_transport:make_version_packet()
    local sent, send_err = self.socket:send(version_bytes)
    if not sent then
      self:disconnect("v2 version send failed: " .. (send_err or "unknown"))
      return false, send_err
    end
    self.state = M.STATE.V2_READY
    self.last_send = socket.gettime()
    self.bytes_sent = self.bytes_sent + #version_bytes
    self.v2_handshake_done = true
    self.session_id = self.v2_transport:get_session_id()
  end

  -- Check if v2 handshake is complete (ready to send and have received version)
  if self.v2_transport.recv_state >= bip324.RecvState.APP then
    self.v2_active = true
    self.state = M.STATE.CONNECTED  -- Ready for normal handshake
    return true
  end

  return false  -- Need more data
end

--- Disconnect from the peer.
-- @param reason string: reason for disconnection (optional, for logging)
function Peer:disconnect(reason)
  -- [wave7 instrumentation] surface silent v2 handshake disconnects
  if self.state ~= M.STATE.DISCONNECTED then
    io.stderr:write(string.format(
      "[%s] V2DIAG peer=%s:%s state=%s v2=%s reason=%s\n",
      os.date("!%Y-%m-%dT%H:%M:%SZ"), tostring(self.ip), tostring(self.port),
      tostring(self.state), tostring(self.use_v2), tostring(reason or "?")))
    io.stderr:flush()
  end
  if self.socket then
    self.socket:close()
    self.socket = nil
  end
  self.state = M.STATE.DISCONNECTED
  self.recv_buffer = ""
  self.handshake_complete = false
  self.version_received = false
  -- reason is available for logging if needed
  self.disconnect_reason = reason
end

--- Increment misbehavior score and disconnect if threshold exceeded.
-- @param score number: points to add to ban score
-- @param reason string: reason for misbehavior
-- @return boolean: true if peer was disconnected
function Peer:misbehaving(score, reason)
  self.ban_score = self.ban_score + score
  if self.ban_score >= 100 then
    self:disconnect("misbehaving: " .. (reason or "score exceeded"))
    return true
  end
  return false
end

--------------------------------------------------------------------------------
-- Message Sending
--------------------------------------------------------------------------------

--- Send a P2P message to the peer.
-- @param command string: message command (e.g., "version", "verack")
-- @param payload string: message payload (optional, defaults to empty)
-- @return boolean: true on success
function Peer:send_message(command, payload)
  if self.state == M.STATE.DISCONNECTED then return false end
  if not self.socket then return false end
  payload = payload or ""

  local msg
  if self.v2_active and self.v2_transport then
    -- V2 encrypted transport
    msg = self.v2_transport:encrypt_message(command, payload)
  else
    -- V1 plaintext transport
    msg = p2p.make_message(self.network.magic_bytes, command, payload)
  end

  local sent, err = self.socket:send(msg)
  if not sent then
    self:disconnect("send failed: " .. (err or "unknown"))
    return false
  end
  self.last_send = socket.gettime()
  self.bytes_sent = self.bytes_sent + #msg
  return true
end

--------------------------------------------------------------------------------
-- Message Receiving
--------------------------------------------------------------------------------

--- Receive and parse messages from the peer.
-- Uses buffered reads to handle partial messages.
-- @return table: list of {command=string, payload=string} tables
function Peer:recv_messages()
  local messages = {}

  if self.state == M.STATE.DISCONNECTED or not self.socket then
    return messages
  end

  -- Read available bytes
  local data, err, partial = self.socket:receive(65536)
  data = data or partial
  if data and #data > 0 then
    self.recv_buffer = self.recv_buffer .. data
    self.last_recv = socket.gettime()
    self.bytes_recv = self.bytes_recv + #data
  elseif err == "closed" then
    self:disconnect("connection closed by peer")
    return messages
  end

  -- V2 encrypted transport
  if self.v2_active and self.v2_transport then
    -- Feed data to v2 transport
    local ok, v2_err = self.v2_transport:recv_bytes(self.recv_buffer)
    self.recv_buffer = ""  -- V2 transport handles buffering
    if not ok then
      self:disconnect("v2 recv failed: " .. (v2_err or "unknown"))
      return messages
    end

    -- Get all ready messages
    while self.v2_transport:message_ready() do
      local cmd, payload, decode_err = self.v2_transport:get_message()
      if cmd then
        messages[#messages + 1] = {command = cmd, payload = payload}
      else
        self:disconnect("v2 decode failed: " .. (decode_err or "unknown"))
        return messages
      end
    end

    return messages
  end

  -- V1 plaintext transport
  while #self.recv_buffer >= p2p.HEADER_SIZE do
    local header = p2p.parse_header(self.recv_buffer:sub(1, p2p.HEADER_SIZE))
    if not header then
      self:disconnect("invalid message header")
      break
    end
    -- Check magic
    if header.magic ~= self.network.magic_bytes then
      self:disconnect("wrong network magic")
      break
    end
    -- Check size
    if header.length > p2p.MAX_MESSAGE_SIZE then
      self:disconnect("message too large: " .. header.length)
      break
    end
    local total = p2p.HEADER_SIZE + header.length
    if #self.recv_buffer < total then break end  -- Need more data

    local payload = self.recv_buffer:sub(p2p.HEADER_SIZE + 1, total)
    self.recv_buffer = self.recv_buffer:sub(total + 1)

    -- Verify checksum
    if not p2p.verify_checksum(payload, header.checksum) then
      self:disconnect("checksum mismatch for " .. header.command)
      break
    end

    messages[#messages + 1] = {command = header.command, payload = payload}
  end

  return messages
end

--------------------------------------------------------------------------------
-- Handshake
--------------------------------------------------------------------------------

--- Start the version handshake (called by outbound peer).
-- For v2 peers, this is called after v2 crypto handshake completes.
function Peer:start_handshake()
  -- If v2 is enabled but not yet established, start v2 handshake first
  if self.use_v2 and not self.v2_active and self.v2_transport then
    return self:start_v2_handshake()
  end

  -- Generate random nonce for this connection
  self.nonce = math.random(1, 2^52)
  -- Send version message
  local payload = p2p.serialize_version({
    version = p2p.PROTOCOL_VERSION,
    services = bit.bor(p2p.SERVICES.NODE_NETWORK, p2p.SERVICES.NODE_WITNESS),
    timestamp = os.time(),
    recv_services = 0,
    recv_ip = self.ip,
    recv_port = self.port,
    from_services = bit.bor(p2p.SERVICES.NODE_NETWORK, p2p.SERVICES.NODE_WITNESS),
    from_ip = "0.0.0.0",
    from_port = 0,
    nonce = self.nonce,
    user_agent = "/LunarBlock:0.1.0/",
    start_height = self.our_height,
    relay = true,
  })
  self:send_message("version", payload)
  self.state = M.STATE.VERSION_SENT
end

--- Handle a received version message.
-- @param payload string: version message payload
function Peer:handle_version(payload)
  -- Ignore redundant version messages
  if self.version_received then
    return
  end
  -- Deserialize version message
  local ver = p2p.deserialize_version(payload)
  self.version_info = ver
  self.services = ver.services
  self.start_height = ver.start_height
  self.user_agent = ver.user_agent
  self.version_received = true
  -- Check minimum protocol version (70015 for segwit)
  if ver.version < 70015 then
    self:disconnect("protocol version too old: " .. ver.version)
    return
  end
  -- Check for self-connection via nonce
  -- (caller should check nonce against known connections)

  -- Send feature negotiation messages BEFORE verack (BIP330, BIP155, BIP339)
  -- SENDTXRCNCL (BIP330): Erlay transaction reconciliation
  -- Only send to outbound full relay peers (not block-only connections)
  if not self.inbound and ver.relay then
    self.erlay_salt = erlay.generate_salt()
    self:send_message("sendtxrcncl", p2p.serialize_sendtxrcncl(erlay.VERSION, self.erlay_salt))
  end

  -- Inbound peers must send their own version message back (both sides send
  -- version in the Bitcoin protocol).  Outbound peers already sent version via
  -- start_handshake(), so only do this for inbound connections.
  if self.inbound and self.state == M.STATE.CONNECTED then
    self.nonce = math.random(1, 2^52)
    local ver_payload = p2p.serialize_version({
      version = p2p.PROTOCOL_VERSION,
      services = bit.bor(p2p.SERVICES.NODE_NETWORK, p2p.SERVICES.NODE_WITNESS),
      timestamp = os.time(),
      recv_services = ver.services,
      recv_ip = self.ip,
      recv_port = self.port,
      from_services = bit.bor(p2p.SERVICES.NODE_NETWORK, p2p.SERVICES.NODE_WITNESS),
      from_ip = "0.0.0.0",
      from_port = 0,
      nonce = self.nonce,
      user_agent = "/LunarBlock:0.1.0/",
      start_height = self.our_height,
      relay = true,
    })
    self:send_message("version", ver_payload)
    self.state = M.STATE.VERSION_SENT
  end

  -- Send verack
  self:send_message("verack", "")
  if self.state == M.STATE.VERSION_SENT then
    self.state = M.STATE.VERACK_SENT
  end
end

--- Handle a received verack message.
function Peer:handle_verack()
  -- Ignore redundant verack messages (Bitcoin Core: silently ignore)
  if self.handshake_complete then
    return
  end
  if self.state == M.STATE.VERACK_SENT or self.state == M.STATE.VERSION_SENT then
    self.state = M.STATE.ESTABLISHED
    self.handshake_complete = true
    -- Send post-handshake messages
    self:send_message("sendheaders", "")
    self:send_message("sendcmpct", p2p.serialize_sendcmpct(false, 2))
    self:send_message("feefilter", p2p.serialize_feefilter(100000)) -- 100 sat/vB = 100000 sat/kvB
  end
end

--------------------------------------------------------------------------------
-- Ping/Pong
--------------------------------------------------------------------------------

--- Send a ping message.
function Peer:send_ping()
  self.ping_nonce = math.random(1, 2^52)
  self.last_ping_time = socket.gettime()
  self:send_message("ping", p2p.serialize_ping(self.ping_nonce))
end

--- Handle a received ping message.
-- @param payload string: ping payload
function Peer:handle_ping(payload)
  local nonce = p2p.deserialize_ping(payload)
  self:send_message("pong", p2p.serialize_ping(nonce))
end

--- Handle a received pong message.
-- @param payload string: pong payload
function Peer:handle_pong(payload)
  local nonce = p2p.deserialize_ping(payload)
  if nonce == self.ping_nonce then
    self.last_pong_time = socket.gettime()
    self.latency_ms = (self.last_pong_time - self.last_ping_time) * 1000
  end
end

--------------------------------------------------------------------------------
-- Message Dispatch
--------------------------------------------------------------------------------

--- Check if a message is allowed before handshake completion.
-- @param command string: message command
-- @return boolean: true if allowed
function Peer:is_pre_handshake_allowed(command)
  return M.PRE_HANDSHAKE_ALLOWED[command] == true
end

--- Process all received messages.
-- Enforces pre-handshake filtering per Bitcoin Core net_processing.cpp.
-- @return table: list of processed messages
function Peer:process_messages()
  -- Handle v2 handshake states
  if self.state == M.STATE.V2_KEY_SENT or
     self.state == M.STATE.V2_KEY_RECV or
     self.state == M.STATE.V2_READY then
    -- Read data for v2 handshake
    local data, err, partial = self.socket:receive(65536)
    data = data or partial
    if data and #data > 0 then
      self.recv_buffer = self.recv_buffer .. data
      self.last_recv = socket.gettime()
      self.bytes_recv = self.bytes_recv + #data
    elseif err == "closed" then
      self:disconnect("connection closed by peer")
      return {}
    end

    -- Process v2 handshake
    local complete, v2_err = self:process_v2_handshake()
    if v2_err then
      return {}  -- Disconnected
    end
    if complete then
      -- Handshake complete (v2 or v1 fallback), now start version handshake
      self:start_handshake()
    end
    return {}  -- No application messages yet
  end

  local messages = self:recv_messages()
  local processed = {}
  for _, msg in ipairs(messages) do
    -- Pre-handshake filtering (Bitcoin Core: fSuccessfullyConnected check)
    -- Before version: only version allowed
    -- Before verack: only PRE_HANDSHAKE_ALLOWED messages
    if not self.version_received then
      -- Must receive version first (Bitcoin Core: pfrom.nVersion == 0 check)
      if msg.command ~= "version" then
        -- Increment misbehavior score and drop message
        self:misbehaving(10, "non-version message before version: " .. msg.command)
        goto continue
      end
    elseif not self.handshake_complete then
      -- After version but before verack: only allow specific messages
      if not self:is_pre_handshake_allowed(msg.command) then
        -- Increment misbehavior score and drop message
        self:misbehaving(10, "unsupported message prior to verack: " .. msg.command)
        goto continue
      end
    end

    processed[#processed + 1] = msg

    if msg.command == "version" then
      self:handle_version(msg.payload)
    elseif msg.command == "verack" then
      self:handle_verack()
    elseif msg.command == "ping" then
      self:handle_ping(msg.payload)
    elseif msg.command == "pong" then
      self:handle_pong(msg.payload)
    elseif msg.command == "sendheaders" then
      self.send_headers = true
    elseif msg.command == "sendcmpct" then
      local sc = p2p.deserialize_sendcmpct(msg.payload)
      -- Only accept compact blocks version 2 (wtxid-based, BIP152)
      if sc.version == 2 then
        self.provides_compact = true
        self.high_bandwidth = sc.announce
        self.compact_version = sc.version
      end
      self.send_compact = sc.announce
    elseif msg.command == "feefilter" then
      self.fee_filter = p2p.deserialize_feefilter(msg.payload)
    elseif msg.command == "wtxidrelay" then
      -- BIP 339: wtxidrelay must be sent before verack
      -- Just acknowledge, no payload
      self.wtxid_relay = true
    elseif msg.command == "sendaddrv2" then
      -- BIP 155: sendaddrv2 must be sent before verack
      self.send_addrv2 = true
    elseif msg.command == "sendtxrcncl" then
      -- BIP 330: Erlay transaction reconciliation
      -- Must be received before verack, only from outbound peers for us
      if not self.handshake_complete then
        local rcncl = p2p.deserialize_sendtxrcncl(msg.payload)
        self.erlay_their_salt = rcncl.salt
        -- If we also sent sendtxrcncl, Erlay is now negotiated
        if self.erlay_salt > 0 then
          self.erlay_enabled = true
          self.erlay_version = math.min(rcncl.version, erlay.VERSION)
          -- Combined salt: XOR of both salts
          self.erlay_combined_salt = bit.bxor(
            tonumber(bit.band(self.erlay_salt, 0xFFFFFFFF)),
            tonumber(bit.band(self.erlay_their_salt, 0xFFFFFFFF))
          )
        end
      end
    else
      -- Dispatch to registered handler
      local handler = self.message_handlers[msg.command]
      if handler then
        handler(self, msg.payload)
      end
    end

    ::continue::
  end
  return processed
end

--------------------------------------------------------------------------------
-- Timeouts and Keepalive
--------------------------------------------------------------------------------

--- Check for timeouts and send keepalive pings.
function Peer:check_timeouts()
  local now = socket.gettime()
  -- Handshake timeout: 60 seconds from connection start
  -- This is stricter than the old 90-second inactivity check
  if not self.handshake_complete and self.state ~= M.STATE.DISCONNECTED then
    if self.handshake_start_time > 0 and now - self.handshake_start_time > M.HANDSHAKE_TIMEOUT then
      self:disconnect("handshake timeout")
      return
    end
  end
  -- Disconnect if no messages received for 20 minutes
  if self.last_recv > 0 and now - self.last_recv > 1200 then
    self:disconnect("inactivity timeout (20 minutes)")
    return
  end
  -- Send ping every 2 minutes if no activity
  if self.state == M.STATE.ESTABLISHED and now - self.last_send > 120 then
    self:send_ping()
  end
end

--------------------------------------------------------------------------------
-- Erlay Reconciliation (BIP330)
--------------------------------------------------------------------------------

--- Check if Erlay reconciliation should be initiated.
-- Only outbound peers initiate reconciliation (~2 second interval).
-- @return boolean: true if should initiate reconciliation
function Peer:should_reconcile()
  if not self.erlay_enabled then
    return false
  end
  if self.inbound then
    return false  -- Only outbound peers initiate
  end
  if self.erlay_recon_pending then
    return false  -- Already waiting for response
  end
  local now = socket.gettime()
  if now - self.erlay_last_recon < erlay.RECON_INTERVAL then
    return false  -- Too soon
  end
  return true
end

--- Initiate Erlay reconciliation with this peer.
-- Builds and sends a sketch of pending transactions.
-- @param wtxids table: list of wtxids to reconcile
-- @return boolean: true if reconciliation was initiated
function Peer:initiate_reconciliation(wtxids)
  if not self.erlay_enabled or self.erlay_recon_pending then
    return false
  end

  -- Compute short txids using combined salt
  local short_ids = erlay.compute_short_txids(self.erlay_combined_salt, wtxids)

  -- Estimate capacity and build sketch
  local capacity = erlay.estimate_capacity(#wtxids)
  local sketch = erlay.build_sketch(short_ids, capacity)
  local sketch_bytes = sketch:serialize()
  sketch:destroy()

  -- Send sketch message
  self:send_message("sketch", p2p.serialize_sketch(sketch_bytes))

  self.erlay_recon_pending = true
  self.erlay_last_recon = socket.gettime()

  return true
end

--- Handle a received sketch message during reconciliation.
-- Decodes differences and sends reconcildiff response.
-- @param sketch_bytes string: serialized remote sketch
-- @param local_wtxids table: our wtxids
-- @return table|nil, table|nil: have_wtxids (to send), want_short_ids (to request)
function Peer:handle_sketch(sketch_bytes, local_wtxids)
  if not self.erlay_enabled then
    return nil, nil
  end

  -- Compute local short txids
  local local_shorts = erlay.compute_short_txids(self.erlay_combined_salt, local_wtxids)

  -- Build short -> wtxid map
  local short_to_wtxid = {}
  for i, wtxid in ipairs(local_wtxids) do
    short_to_wtxid[local_shorts[i]] = wtxid
  end

  -- Reconcile sketches
  local have, want, err = erlay.reconcile_sketches(sketch_bytes, local_shorts, erlay.DEFAULT_CAPACITY)

  if not have then
    -- Reconciliation failed, send failure response
    self:send_message("reconcildiff", p2p.serialize_reconcildiff(false, {}))
    return nil, nil, err
  end

  -- Convert 'have' short IDs to wtxids (transactions we have that peer wants)
  local have_wtxids = {}
  for _, short in ipairs(have) do
    local wtxid = short_to_wtxid[short]
    if wtxid then
      have_wtxids[#have_wtxids + 1] = wtxid
    end
  end

  -- Send success response with short IDs we want
  self:send_message("reconcildiff", p2p.serialize_reconcildiff(true, want))

  self.erlay_recon_pending = false

  return have_wtxids, want
end

--- Handle a received reconcildiff response.
-- @param success boolean: whether reconciliation succeeded
-- @param want_short_ids table: short txids the peer wants from us
-- @return boolean: success status
function Peer:handle_reconcildiff(success, want_short_ids)
  self.erlay_recon_pending = false

  if not success then
    -- Reconciliation failed on peer side, fall back to flooding
    return false
  end

  -- want_short_ids contains the transactions we need to send to peer
  -- The caller should convert these to wtxids and send via getdata
  return true
end

--------------------------------------------------------------------------------
-- Message Handler Registration
--------------------------------------------------------------------------------

--- Register a custom message handler.
-- @param command string: message command to handle
-- @param handler function: handler function(peer, payload)
function Peer:on(command, handler)
  self.message_handlers[command] = handler
end

return M
