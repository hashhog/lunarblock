local socket = require("socket")
local p2p = require("lunarblock.p2p")
local bit = require("bit")
local M = {}

--------------------------------------------------------------------------------
-- Peer States
--------------------------------------------------------------------------------

M.STATE = {
  DISCONNECTED = "disconnected",
  CONNECTING = "connecting",
  CONNECTED = "connected",      -- TCP connected, awaiting handshake
  VERSION_SENT = "version_sent",
  VERACK_SENT = "verack_sent",
  ESTABLISHED = "established",  -- Handshake complete, ready for messages
  DISCONNECTING = "disconnecting",
}

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
-- @return Peer: new peer object
function M.new(ip, port, network, our_height)
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
  self.last_ping_time = 0
  self.last_pong_time = 0
  self.ping_nonce = 0
  self.latency_ms = 0
  self.ban_score = 0
  self.inbound = false
  self.send_headers = false       -- Peer requested headers announcements
  self.send_compact = false       -- Peer supports compact blocks
  self.fee_filter = 0             -- Minimum fee rate (sat/KB) peer accepts
  self.message_handlers = {}      -- command -> handler function
  self.inflight_blocks = {}       -- block hashes we've requested
  self.inflight_txs = {}          -- tx hashes we've requested
  self.known_blocks = {}          -- block hashes peer has announced
  self.known_txs = {}             -- tx hashes peer has announced
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
  self.socket = socket.tcp()
  self.socket:settimeout(timeout or 5)
  local ok, err = self.socket:connect(self.ip, self.port)
  if not ok then
    self:disconnect("connect failed: " .. (err or "unknown"))
    return false, err
  end
  self.socket:settimeout(0)  -- Non-blocking after connection
  self.state = M.STATE.CONNECTED
  self.last_recv = socket.gettime()
  return true
end

--- Disconnect from the peer.
-- @param reason string: reason for disconnection (optional, for logging)
function Peer:disconnect(reason)
  if self.socket then
    self.socket:close()
    self.socket = nil
  end
  self.state = M.STATE.DISCONNECTED
  self.recv_buffer = ""
  -- reason is available for logging if needed
  self.disconnect_reason = reason
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
  local msg = p2p.make_message(self.network.magic_bytes, command, payload)
  local sent, err = self.socket:send(msg)
  if not sent then
    self:disconnect("send failed: " .. (err or "unknown"))
    return false
  end
  self.last_send = socket.gettime()
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
  elseif err == "closed" then
    self:disconnect("connection closed by peer")
    return messages
  end

  -- Parse complete messages
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
function Peer:start_handshake()
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
  -- Deserialize version message
  local ver = p2p.deserialize_version(payload)
  self.version_info = ver
  self.services = ver.services
  self.start_height = ver.start_height
  self.user_agent = ver.user_agent
  -- Check minimum protocol version (70015 for segwit)
  if ver.version < 70015 then
    self:disconnect("protocol version too old: " .. ver.version)
    return
  end
  -- Check for self-connection via nonce
  -- (caller should check nonce against known connections)
  -- Send verack
  self:send_message("verack", "")
  if self.state == M.STATE.VERSION_SENT then
    self.state = M.STATE.VERACK_SENT
  end
end

--- Handle a received verack message.
function Peer:handle_verack()
  if self.state == M.STATE.VERACK_SENT or self.state == M.STATE.VERSION_SENT then
    self.state = M.STATE.ESTABLISHED
    -- Send post-handshake messages
    self:send_message("sendheaders", "")
    self:send_message("sendcmpct", p2p.serialize_sendcmpct(false, 2))
    self:send_message("feefilter", p2p.serialize_feefilter(1000)) -- 1 sat/vB minimum
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

--- Process all received messages.
-- @return table: list of processed messages
function Peer:process_messages()
  local messages = self:recv_messages()
  for _, msg in ipairs(messages) do
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
      self.send_compact = sc.announce
    elseif msg.command == "feefilter" then
      self.fee_filter = p2p.deserialize_feefilter(msg.payload)
    else
      -- Dispatch to registered handler
      local handler = self.message_handlers[msg.command]
      if handler then
        handler(self, msg.payload)
      end
    end
  end
  return messages
end

--------------------------------------------------------------------------------
-- Timeouts and Keepalive
--------------------------------------------------------------------------------

--- Check for timeouts and send keepalive pings.
function Peer:check_timeouts()
  local now = socket.gettime()
  -- Disconnect if no messages received for 90 seconds during handshake
  if self.state ~= M.STATE.ESTABLISHED and self.state ~= M.STATE.DISCONNECTED then
    if self.last_recv > 0 and now - self.last_recv > 90 then
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
-- Message Handler Registration
--------------------------------------------------------------------------------

--- Register a custom message handler.
-- @param command string: message command to handle
-- @param handler function: handler function(peer, payload)
function Peer:on(command, handler)
  self.message_handlers[command] = handler
end

return M
