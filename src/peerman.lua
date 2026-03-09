local socket = require("socket")
local peer_mod = require("lunarblock.peer")
local p2p = require("lunarblock.p2p")
local M = {}

--------------------------------------------------------------------------------
-- PeerManager Object
--------------------------------------------------------------------------------

local PeerManager = {}
PeerManager.__index = PeerManager

--- Create a new PeerManager.
-- @param network table: network configuration from consensus module
-- @param storage table: storage layer instance (optional)
-- @param config table: configuration options (optional)
-- @return PeerManager: new peer manager instance
function M.new(network, storage, config)
  local self = setmetatable({}, PeerManager)
  self.network = network
  self.storage = storage
  config = config or {}
  self.config = config
  self.max_outbound = config.max_outbound or 8
  self.max_inbound = config.max_inbound or 117
  self.max_peers = config.max_peers or 125
  self.peers = {}              -- ip:port -> Peer object
  self.peer_list = {}          -- ordered list for iteration
  self.known_addresses = {}    -- ip:port -> {ip, port, services, timestamp, attempts, last_try}
  self.banned = {}             -- ip -> ban_until_timestamp
  self.our_nonces = {}         -- set of nonces we've used (detect self-connect)
  self.our_height = 0
  self.listen_socket = nil
  self.message_handlers = {}   -- command -> handler(peer, payload)
  self.callbacks = {
    on_peer_connected = nil,
    on_peer_disconnected = nil,
    on_peer_established = nil,
  }
  return self
end

--------------------------------------------------------------------------------
-- DNS Seed Discovery
--------------------------------------------------------------------------------

--- Discover peer addresses from DNS seeds.
-- @return number: count of new addresses found
function PeerManager:discover_from_dns()
  if not self.network or not self.network.dns_seeds then
    return 0
  end

  local count = 0
  for _, seed in ipairs(self.network.dns_seeds) do
    local results = socket.dns.getaddrinfo(seed)
    if results then
      for _, addr in ipairs(results) do
        if addr.family == "inet" then
          local port = self.network.default_port or self.network.port or 8333
          local key = addr.addr .. ":" .. port
          if not self.known_addresses[key] then
            self.known_addresses[key] = {
              ip = addr.addr,
              port = port,
              services = p2p.SERVICES.NODE_NETWORK,
              timestamp = os.time(),
              attempts = 0,
              last_try = 0,
            }
            count = count + 1
          end
        end
      end
    end
  end
  return count
end

--------------------------------------------------------------------------------
-- Known Address Management
--------------------------------------------------------------------------------

--- Add a known address to the pool.
-- @param ip string: IP address
-- @param port number: port number
-- @param services number: service flags (optional)
-- @param timestamp number: unix timestamp (optional)
-- @return boolean: true if address was added (new)
function PeerManager:add_known_address(ip, port, services, timestamp)
  local key = ip .. ":" .. port
  if self.known_addresses[key] then
    return false
  end
  self.known_addresses[key] = {
    ip = ip,
    port = port,
    services = services or p2p.SERVICES.NODE_NETWORK,
    timestamp = timestamp or os.time(),
    attempts = 0,
    last_try = 0,
  }
  return true
end

--- Get the count of known addresses.
-- @return number: count of known addresses
function PeerManager:get_known_address_count()
  local count = 0
  for _ in pairs(self.known_addresses) do
    count = count + 1
  end
  return count
end

--------------------------------------------------------------------------------
-- Peer Connection Management
--------------------------------------------------------------------------------

--- Connect to a peer.
-- @param ip string: peer IP address
-- @param port number: peer port
-- @return boolean: true on success
-- @return string: error message on failure
function PeerManager:connect_peer(ip, port)
  local key = ip .. ":" .. port
  if self.peers[key] then return false, "already connected" end
  if self.banned[ip] and self.banned[ip] > os.time() then
    return false, "peer is banned"
  end
  if #self.peer_list >= self.max_peers then
    return false, "max peers reached"
  end

  local p = peer_mod.new(ip, port, self.network, self.our_height)
  -- Register all our message handlers
  for cmd, handler in pairs(self.message_handlers) do
    p:on(cmd, handler)
  end

  local ok, err = p:connect()
  if not ok then
    -- Update known_addresses attempt count
    if self.known_addresses[key] then
      self.known_addresses[key].attempts = self.known_addresses[key].attempts + 1
      self.known_addresses[key].last_try = os.time()
    end
    return false, err
  end

  self.peers[key] = p
  self.peer_list[#self.peer_list + 1] = p
  self.our_nonces[p.nonce] = true
  p:start_handshake()

  if self.callbacks.on_peer_connected then
    self.callbacks.on_peer_connected(p)
  end

  return true
end

--- Disconnect a peer.
-- @param p Peer: peer to disconnect
-- @param reason string: reason for disconnection (optional)
function PeerManager:disconnect_peer(p, reason)
  local key = p.ip .. ":" .. p.port
  p:disconnect(reason)
  self.peers[key] = nil
  for i, peer in ipairs(self.peer_list) do
    if peer == p then
      table.remove(self.peer_list, i)
      break
    end
  end
  self.our_nonces[p.nonce] = nil
  if self.callbacks.on_peer_disconnected then
    self.callbacks.on_peer_disconnected(p, reason)
  end
end

--------------------------------------------------------------------------------
-- Peer Selection
--------------------------------------------------------------------------------

--- Select a peer candidate for outbound connection.
-- Prefers peers with fewer failed connection attempts.
-- @return table|nil: address info or nil if no candidates
function PeerManager:select_peer_to_connect()
  local candidates = {}
  local now = os.time()
  for key, info in pairs(self.known_addresses) do
    if not self.peers[key]
       and (not self.banned[info.ip] or self.banned[info.ip] <= now)
       and (now - info.last_try) > 60 then
      candidates[#candidates + 1] = info
    end
  end
  if #candidates == 0 then return nil end
  -- Sort by fewest attempts, pick random from top candidates
  table.sort(candidates, function(a, b) return a.attempts < b.attempts end)
  local top = math.min(#candidates, 10)
  return candidates[math.random(1, top)]
end

--------------------------------------------------------------------------------
-- Connection Maintenance
--------------------------------------------------------------------------------

--- Maintain outbound connections by connecting to new peers if below target.
function PeerManager:maintain_connections()
  -- Count current outbound connections
  local outbound = 0
  for _, p in ipairs(self.peer_list) do
    if not p.inbound then outbound = outbound + 1 end
  end

  -- Connect to more peers if below target
  while outbound < self.max_outbound do
    local candidate = self:select_peer_to_connect()
    if not candidate then
      -- No candidates; try DNS discovery
      if self:discover_from_dns() == 0 then break end
      candidate = self:select_peer_to_connect()
      if not candidate then break end
    end
    local ok = self:connect_peer(candidate.ip, candidate.port)
    if ok then outbound = outbound + 1 end
  end
end

--------------------------------------------------------------------------------
-- Ban Management
--------------------------------------------------------------------------------

--- Ban a peer's IP address.
-- @param ip string: IP address to ban
-- @param duration number: ban duration in seconds (default 24 hours)
function PeerManager:ban_peer(ip, duration)
  duration = duration or 86400  -- Default 24 hours
  self.banned[ip] = os.time() + duration
  -- Disconnect any active connections from this IP
  local to_disconnect = {}
  for _, p in ipairs(self.peer_list) do
    if p.ip == ip then
      to_disconnect[#to_disconnect + 1] = p
    end
  end
  for _, p in ipairs(to_disconnect) do
    self:disconnect_peer(p, "banned")
  end
end

--- Check if an IP is banned.
-- @param ip string: IP address to check
-- @return boolean: true if banned
function PeerManager:is_banned(ip)
  return self.banned[ip] and self.banned[ip] > os.time()
end

--- Add to a peer's ban score and ban if threshold exceeded.
-- @param peer Peer: peer to add score to
-- @param score number: ban score to add
-- @param reason string: reason for the score (optional)
function PeerManager:add_ban_score(peer, score, reason)
  peer.ban_score = peer.ban_score + score
  if peer.ban_score >= 100 then
    self:ban_peer(peer.ip)
    self:disconnect_peer(peer, "ban score exceeded: " .. (reason or ""))
  end
end

--------------------------------------------------------------------------------
-- Addr Message Handling
--------------------------------------------------------------------------------

--- Handle received addr message.
-- @param peer Peer: peer that sent the message
-- @param payload string: addr message payload
function PeerManager:handle_addr(peer, payload)
  -- Suppress unused warning
  local _ = peer
  local addresses = p2p.deserialize_addr(payload)
  local now = os.time()
  for _, addr in ipairs(addresses) do
    -- Only accept addresses with recent timestamps (within 3 hours)
    if addr.timestamp > now - 10800 and addr.timestamp <= now + 600 then
      local key = addr.ip .. ":" .. addr.port
      if not self.known_addresses[key] then
        self.known_addresses[key] = {
          ip = addr.ip,
          port = addr.port,
          services = addr.services,
          timestamp = addr.timestamp,
          attempts = 0,
          last_try = 0,
        }
      end
    end
  end
end

--------------------------------------------------------------------------------
-- Inbound Connection Listener
--------------------------------------------------------------------------------

--- Start the inbound connection listener.
-- @param bind_ip string: IP to bind to (default "0.0.0.0")
-- @param port number: port to listen on (default network default port)
-- @return boolean: true on success
-- @return string: error message on failure
function PeerManager:start_listener(bind_ip, port)
  self.listen_socket = socket.tcp()
  local ok, err = self.listen_socket:setoption("reuseaddr", true)
  if not ok then
    self.listen_socket:close()
    self.listen_socket = nil
    return false, err
  end
  local listen_port = port or (self.network and self.network.port) or 8333
  ok, err = self.listen_socket:bind(bind_ip or "0.0.0.0", listen_port)
  if not ok then
    self.listen_socket:close()
    self.listen_socket = nil
    return false, err
  end
  ok, err = self.listen_socket:listen(32)
  if not ok then
    self.listen_socket:close()
    self.listen_socket = nil
    return false, err
  end
  self.listen_socket:settimeout(0)
  return true
end

--- Accept inbound connections.
function PeerManager:accept_inbound()
  if not self.listen_socket then return end
  local client, err = self.listen_socket:accept()
  if not client then
    -- No connection waiting (timeout or error)
    local _ = err
    return
  end

  local ip, port = client:getpeername()
  if self.banned[ip] and self.banned[ip] > os.time() then
    client:close()
    return
  end

  local inbound_count = 0
  for _, p in ipairs(self.peer_list) do
    if p.inbound then inbound_count = inbound_count + 1 end
  end
  if inbound_count >= self.max_inbound then
    client:close()
    return
  end

  local p = peer_mod.new(ip, port, self.network, self.our_height)
  p.socket = client
  p.state = peer_mod.STATE.CONNECTED
  p.inbound = true
  client:settimeout(0)

  for cmd, handler in pairs(self.message_handlers) do
    p:on(cmd, handler)
  end

  local key = ip .. ":" .. port
  self.peers[key] = p
  self.peer_list[#self.peer_list + 1] = p

  if self.callbacks.on_peer_connected then
    self.callbacks.on_peer_connected(p)
  end
end

--------------------------------------------------------------------------------
-- Event Loop
--------------------------------------------------------------------------------

--- Process one tick of the event loop.
-- Accepts inbound connections, processes messages, checks timeouts,
-- and maintains outbound connections.
function PeerManager:tick()
  -- Accept inbound connections
  self:accept_inbound()

  -- Process messages from all peers
  local disconnected = {}
  for _, p in ipairs(self.peer_list) do
    if p.state ~= peer_mod.STATE.DISCONNECTED then
      p:process_messages()
      p:check_timeouts()
      -- Check if state became ESTABLISHED (newly completed handshake)
      if p.state == peer_mod.STATE.ESTABLISHED and not p._established_notified then
        p._established_notified = true
        if self.callbacks.on_peer_established then
          self.callbacks.on_peer_established(p)
        end
      end
    end
    if p.state == peer_mod.STATE.DISCONNECTED then
      disconnected[#disconnected + 1] = p
    end
  end

  -- Clean up disconnected peers
  for _, p in ipairs(disconnected) do
    self:disconnect_peer(p, "disconnected")
  end

  -- Maintain outbound connections
  self:maintain_connections()
end

--- Run the main event loop.
-- @param interval number: seconds between ticks (default 0.1)
function PeerManager:run(interval)
  interval = interval or 0.1  -- 100ms between ticks
  while true do
    self:tick()
    socket.sleep(interval)
  end
end

--------------------------------------------------------------------------------
-- Broadcast and Query Methods
--------------------------------------------------------------------------------

--- Broadcast a message to all established peers.
-- @param command string: message command
-- @param payload string: message payload
-- @param filter_fn function: optional filter function(peer) -> boolean
function PeerManager:broadcast(command, payload, filter_fn)
  for _, p in ipairs(self.peer_list) do
    if p.state == peer_mod.STATE.ESTABLISHED then
      if not filter_fn or filter_fn(p) then
        p:send_message(command, payload)
      end
    end
  end
end

--- Get all established peers.
-- @return table: list of established Peer objects
function PeerManager:get_established_peers()
  local result = {}
  for _, p in ipairs(self.peer_list) do
    if p.state == peer_mod.STATE.ESTABLISHED then
      result[#result + 1] = p
    end
  end
  return result
end

--- Get peer count by state.
-- @return number, number, number: total, outbound, inbound counts
function PeerManager:get_peer_counts()
  local outbound = 0
  local inbound = 0
  for _, p in ipairs(self.peer_list) do
    if p.inbound then
      inbound = inbound + 1
    else
      outbound = outbound + 1
    end
  end
  return #self.peer_list, outbound, inbound
end

--------------------------------------------------------------------------------
-- Message Handler Registration
--------------------------------------------------------------------------------

--- Register a message handler.
-- @param command string: message command to handle
-- @param handler function: handler function(peer, payload)
function PeerManager:register_handler(command, handler)
  self.message_handlers[command] = handler
  -- Also register on existing peers
  for _, p in ipairs(self.peer_list) do
    p:on(command, handler)
  end
end

--------------------------------------------------------------------------------
-- Shutdown
--------------------------------------------------------------------------------

--- Stop the peer manager and disconnect all peers.
function PeerManager:stop()
  for _, p in ipairs(self.peer_list) do
    p:disconnect("shutdown")
  end
  self.peer_list = {}
  self.peers = {}
  if self.listen_socket then
    self.listen_socket:close()
    self.listen_socket = nil
  end
end

return M
