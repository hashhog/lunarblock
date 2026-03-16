local socket = require("socket")
local peer_mod = require("lunarblock.peer")
local p2p = require("lunarblock.p2p")
local crypto = require("lunarblock.crypto")
local M = {}

--------------------------------------------------------------------------------
-- Misbehavior Score Constants
--------------------------------------------------------------------------------

M.MISBEHAVIOR = {
  INVALID_BLOCK_HEADER = 100,  -- Instant ban: invalid PoW or header structure
  INVALID_BLOCK = 100,         -- Instant ban: block fails validation
  INVALID_TRANSACTION = 10,    -- Minor violation: tx fails validation
  UNSOLICITED_DATA = 20,       -- Sent data we didn't request
  TOO_MANY_MESSAGES = 50,      -- DoS protection: message flood
  BAN_THRESHOLD = 100,         -- Score at which peer is banned
  DEFAULT_BAN_DURATION = 86400, -- 24 hours in seconds
}

--------------------------------------------------------------------------------
-- Transaction Trickling Constants (BIP: privacy-preserving relay)
-- Reference: Bitcoin Core net_processing.cpp INVENTORY_BROADCAST_INTERVAL
--------------------------------------------------------------------------------

M.TRICKLE = {
  -- Average Poisson delay for outbound peers (less privacy concern)
  OUTBOUND_INTERVAL = 2.0,
  -- Average Poisson delay for inbound peers (more privacy)
  INBOUND_INTERVAL = 5.0,
  -- Maximum inv entries per message (keeps messages small)
  MAX_INV_PER_MSG = 35,
}

--------------------------------------------------------------------------------
-- Address Manager Constants (Eclipse Attack Mitigation)
-- Reference: Bitcoin Core addrman.h, addrman_impl.h
--------------------------------------------------------------------------------

M.ADDRMAN = {
  -- Number of buckets in the "new" table (addresses we haven't connected to yet)
  NEW_BUCKET_COUNT = 256,
  -- Number of buckets in the "tried" table (addresses we've connected to)
  TRIED_BUCKET_COUNT = 64,
  -- Number of entries per bucket
  BUCKET_SIZE = 64,
  -- Maximum number of anchors to persist
  MAX_ANCHORS = 2,
  -- Number of tried buckets per source group
  TRIED_BUCKETS_PER_GROUP = 8,
  -- Number of new buckets per source group
  NEW_BUCKETS_PER_SOURCE_GROUP = 64,
  -- Maximum times an address can appear in new buckets
  NEW_BUCKETS_PER_ADDRESS = 8,
}

--------------------------------------------------------------------------------
-- Network Group Utilities (Eclipse Attack Mitigation)
-- Reference: Bitcoin Core netgroup.cpp GetGroup()
--------------------------------------------------------------------------------

--- Get the network group for an IP address.
-- For IPv4, this is the /16 subnet (first two octets).
-- For IPv6, this is typically the /32.
-- @param ip string: IP address string (e.g., "192.168.1.1")
-- @return string: group identifier bytes
function M.get_addr_group(ip)
  -- Parse IPv4 address
  local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if a and b then
    -- IPv4: return /16 subnet (first two octets)
    return string.char(4) .. string.char(tonumber(a)) .. string.char(tonumber(b))
  end

  -- Parse IPv6 address (simplified: take first 32 bits)
  local parts = {}
  for part in (ip .. ":"):gmatch("([^:]*):") do
    parts[#parts + 1] = part
  end
  if #parts >= 2 then
    -- IPv6: return /32 (first two 16-bit groups)
    local p1 = tonumber(parts[1], 16) or 0
    local p2 = tonumber(parts[2], 16) or 0
    return string.char(6) ..
           string.char(bit.rshift(p1, 8)) ..
           string.char(bit.band(p1, 0xff)) ..
           string.char(bit.rshift(p2, 8)) ..
           string.char(bit.band(p2, 0xff))
  end

  -- Unknown format: use IP as-is
  return string.char(0) .. ip
end

--- Get a unique key for an address (for bucket position calculation).
-- @param ip string: IP address
-- @param port number: port number
-- @return string: key bytes
function M.get_addr_key(ip, port)
  return ip .. ":" .. tostring(port)
end

--- Calculate deterministic bucket hash.
-- @param nkey string: secret key for randomization
-- @param ... string: additional components to hash
-- @return number: 32-bit hash value
function M.addr_hash(nkey, ...)
  local data = nkey
  for i = 1, select("#", ...) do
    data = data .. (select(i, ...) or "")
  end
  local h = crypto.sha256(data)
  -- Return first 4 bytes as little-endian uint32
  return h:byte(1) + h:byte(2) * 256 + h:byte(3) * 65536 + h:byte(4) * 16777216
end

--- Get the bucket number for a "tried" address.
-- @param nkey string: secret key
-- @param ip string: address IP
-- @param port number: address port
-- @return number: bucket number (0-based)
function M.get_tried_bucket(nkey, ip, port)
  local key = M.get_addr_key(ip, port)
  local group = M.get_addr_group(ip)

  -- hash1 = HASH(nKey, GetKey())
  local hash1 = M.addr_hash(nkey, key)

  -- hash2 = HASH(nKey, group, hash1 % TRIED_BUCKETS_PER_GROUP)
  local group_bucket = hash1 % M.ADDRMAN.TRIED_BUCKETS_PER_GROUP
  local hash2 = M.addr_hash(nkey, group, string.char(group_bucket))

  return hash2 % M.ADDRMAN.TRIED_BUCKET_COUNT
end

--- Get the bucket number for a "new" address.
-- @param nkey string: secret key
-- @param ip string: address IP
-- @param port number: address port
-- @param src_ip string: source IP that told us about this address
-- @return number: bucket number (0-based)
function M.get_new_bucket(nkey, ip, port, src_ip)
  local group = M.get_addr_group(ip)
  local src_group = M.get_addr_group(src_ip or ip)

  -- hash1 = HASH(nKey, group, src_group)
  local hash1 = M.addr_hash(nkey, group, src_group)

  -- hash2 = HASH(nKey, src_group, hash1 % NEW_BUCKETS_PER_SOURCE_GROUP)
  local source_bucket = hash1 % M.ADDRMAN.NEW_BUCKETS_PER_SOURCE_GROUP
  local hash2 = M.addr_hash(nkey, src_group, string.char(source_bucket))

  return hash2 % M.ADDRMAN.NEW_BUCKET_COUNT
end

--- Get the position within a bucket for an address.
-- @param nkey string: secret key
-- @param is_new boolean: true for new table, false for tried
-- @param bucket number: bucket number
-- @param ip string: address IP
-- @param port number: address port
-- @return number: position (0-based)
function M.get_bucket_position(nkey, is_new, bucket, ip, port)
  local key = M.get_addr_key(ip, port)
  local tag = is_new and "N" or "K"
  local hash = M.addr_hash(nkey, tag, string.char(bucket % 256), key)
  return hash % M.ADDRMAN.BUCKET_SIZE
end

--------------------------------------------------------------------------------
-- Poisson Timer (exponential distribution for random delays)
--------------------------------------------------------------------------------

--- Generate a random delay using Poisson process (exponential distribution).
-- @param avg_interval number: average time between events in seconds
-- @return number: next event time (random delay from now)
function M.poisson_delay(avg_interval)
  -- Exponential distribution: -ln(U) * avg_interval where U is uniform(0,1)
  -- math.random() returns (0,1] so we use 1 - math.random() to avoid log(0)
  local u = math.random()
  if u == 0 then u = 1e-10 end  -- Avoid log(0)
  return -math.log(u) * avg_interval
end

--------------------------------------------------------------------------------
-- Fisher-Yates Shuffle (for privacy-preserving random ordering)
--------------------------------------------------------------------------------

--- Shuffle an array in-place using Fisher-Yates algorithm.
-- @param arr table: array to shuffle
-- @return table: the same array, now shuffled
function M.shuffle(arr)
  local n = #arr
  for i = n, 2, -1 do
    local j = math.random(1, i)
    arr[i], arr[j] = arr[j], arr[i]
  end
  return arr
end

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
  self.data_dir = config.data_dir or "."
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

  -- Initialize address manager (eclipse attack mitigation)
  self:_init_addrman()

  -- Load persisted bans from disk
  self:_load_bans()

  -- Load and connect to anchor peers
  self:_load_anchors()

  return self
end

--------------------------------------------------------------------------------
-- Address Manager Initialization (Eclipse Attack Mitigation)
--------------------------------------------------------------------------------

--- Initialize the address manager with new/tried bucketing.
-- Called during PeerManager construction.
function PeerManager:_init_addrman()
  -- Generate a random secret key for deterministic bucket assignment
  -- This key should persist across restarts ideally, but for now we regenerate
  math.randomseed(os.time() + (socket.gettime() * 1000000) % 1000000)
  local key_bytes = {}
  for i = 1, 32 do
    key_bytes[i] = string.char(math.random(0, 255))
  end
  self._addrman_key = table.concat(key_bytes)

  -- New table: 256 buckets, each with 64 entries
  -- Stores addresses we've heard about but haven't connected to
  self._new_buckets = {}
  for i = 0, M.ADDRMAN.NEW_BUCKET_COUNT - 1 do
    self._new_buckets[i] = {}  -- bucket_pos -> {ip, port, services, timestamp, src_ip, ref_count}
  end
  self._new_count = 0

  -- Tried table: 64 buckets, each with 64 entries
  -- Stores addresses we've successfully connected to
  self._tried_buckets = {}
  for i = 0, M.ADDRMAN.TRIED_BUCKET_COUNT - 1 do
    self._tried_buckets[i] = {}  -- bucket_pos -> {ip, port, services, timestamp, last_success}
  end
  self._tried_count = 0

  -- Map from address key to entry for quick lookup
  self._addr_info = {}  -- ip:port -> {in_tried, new_refs[], ...}

  -- Connected /16 subnets for outbound diversity
  self._outbound_groups = {}  -- group -> count

  -- Anchor connections for eclipse mitigation
  self._anchors = {}  -- list of {ip, port} to connect on startup
end

--- Add an address to the "new" table.
-- @param ip string: IP address
-- @param port number: port number
-- @param services number: service flags
-- @param timestamp number: unix timestamp
-- @param src_ip string: source IP that told us about this address
-- @return boolean: true if added
function PeerManager:_add_to_new(ip, port, services, timestamp, src_ip)
  local key = ip .. ":" .. port
  local info = self._addr_info[key]

  -- If already in tried table, don't add to new
  if info and info.in_tried then
    return false
  end

  -- Calculate bucket and position
  local bucket = M.get_new_bucket(self._addrman_key, ip, port, src_ip)
  local pos = M.get_bucket_position(self._addrman_key, true, bucket, ip, port)

  -- Check if this address is already in this bucket
  local existing = self._new_buckets[bucket][pos]
  if existing and existing.ip == ip and existing.port == port then
    -- Update timestamp if newer
    if timestamp > existing.timestamp then
      existing.timestamp = timestamp
    end
    return false
  end

  -- If slot is occupied by different address, maybe evict
  if existing then
    -- Don't add if we've already reached max refs for this address
    if info and info.new_ref_count >= M.ADDRMAN.NEW_BUCKETS_PER_ADDRESS then
      return false
    end
    -- Evict the existing entry
    self:_remove_from_new_bucket(bucket, pos)
  end

  -- Add to bucket
  self._new_buckets[bucket][pos] = {
    ip = ip,
    port = port,
    services = services or p2p.SERVICES.NODE_NETWORK,
    timestamp = timestamp or os.time(),
    src_ip = src_ip or ip,
  }
  self._new_count = self._new_count + 1

  -- Update addr_info
  if not info then
    info = {in_tried = false, new_ref_count = 0, new_refs = {}}
    self._addr_info[key] = info
  end
  info.new_ref_count = info.new_ref_count + 1
  info.new_refs[bucket] = pos

  return true
end

--- Remove an address from a specific new bucket position.
-- @param bucket number: bucket number
-- @param pos number: position in bucket
function PeerManager:_remove_from_new_bucket(bucket, pos)
  local entry = self._new_buckets[bucket][pos]
  if not entry then return end

  local key = entry.ip .. ":" .. entry.port
  local info = self._addr_info[key]
  if info then
    info.new_ref_count = info.new_ref_count - 1
    info.new_refs[bucket] = nil
    if info.new_ref_count == 0 and not info.in_tried then
      self._addr_info[key] = nil
    end
  end

  self._new_buckets[bucket][pos] = nil
  self._new_count = self._new_count - 1
end

--- Move an address to the "tried" table after successful connection.
-- @param ip string: IP address
-- @param port number: port number
-- @return boolean: true if moved to tried
function PeerManager:_move_to_tried(ip, port)
  local key = ip .. ":" .. port
  local info = self._addr_info[key]

  -- If already in tried, just update timestamp
  if info and info.in_tried then
    local bucket = info.tried_bucket
    local pos = info.tried_pos
    if self._tried_buckets[bucket] and self._tried_buckets[bucket][pos] then
      self._tried_buckets[bucket][pos].last_success = os.time()
    end
    return true
  end

  -- Calculate tried bucket and position
  local bucket = M.get_tried_bucket(self._addrman_key, ip, port)
  local pos = M.get_bucket_position(self._addrman_key, false, bucket, ip, port)

  -- Check if slot is occupied
  local existing = self._tried_buckets[bucket][pos]
  if existing then
    -- Evict existing entry back to new
    self:_evict_from_tried(bucket, pos)
  end

  -- Get services/timestamp from new table or known_addresses
  local services = p2p.SERVICES.NODE_NETWORK
  local timestamp = os.time()
  if info and info.new_ref_count > 0 then
    -- Find first new entry for this address
    for b, p in pairs(info.new_refs) do
      local entry = self._new_buckets[b][p]
      if entry then
        services = entry.services
        timestamp = entry.timestamp
        break
      end
    end
    -- Remove from all new buckets
    for b, p in pairs(info.new_refs) do
      self._new_buckets[b][p] = nil
      self._new_count = self._new_count - 1
    end
  elseif self.known_addresses[key] then
    services = self.known_addresses[key].services
    timestamp = self.known_addresses[key].timestamp
  end

  -- Add to tried bucket
  self._tried_buckets[bucket][pos] = {
    ip = ip,
    port = port,
    services = services,
    timestamp = timestamp,
    last_success = os.time(),
  }
  self._tried_count = self._tried_count + 1

  -- Update addr_info
  if not info then
    info = {new_ref_count = 0, new_refs = {}}
    self._addr_info[key] = info
  end
  info.in_tried = true
  info.tried_bucket = bucket
  info.tried_pos = pos
  info.new_ref_count = 0
  info.new_refs = {}

  return true
end

--- Evict an entry from the tried table back to new.
-- @param bucket number: bucket number
-- @param pos number: position in bucket
function PeerManager:_evict_from_tried(bucket, pos)
  local entry = self._tried_buckets[bucket][pos]
  if not entry then return end

  local key = entry.ip .. ":" .. entry.port
  local info = self._addr_info[key]
  if info then
    info.in_tried = false
    info.tried_bucket = nil
    info.tried_pos = nil
  end

  -- Add back to new table
  self:_add_to_new(entry.ip, entry.port, entry.services, entry.timestamp, entry.ip)

  self._tried_buckets[bucket][pos] = nil
  self._tried_count = self._tried_count - 1
end

--- Select a random address from the address manager.
-- Prefers tried addresses over new addresses.
-- @param new_only boolean: only select from new table (optional)
-- @return table|nil: {ip, port, services} or nil
function PeerManager:_select_address(new_only)
  local use_tried = not new_only and self._tried_count > 0 and
                    (self._new_count == 0 or math.random() < 0.5)

  if use_tried then
    -- Select from tried table
    local attempts = 0
    while attempts < 100 do
      local bucket = math.random(0, M.ADDRMAN.TRIED_BUCKET_COUNT - 1)
      local pos = math.random(0, M.ADDRMAN.BUCKET_SIZE - 1)
      local entry = self._tried_buckets[bucket][pos]
      if entry then
        return {ip = entry.ip, port = entry.port, services = entry.services}
      end
      attempts = attempts + 1
    end
  end

  -- Select from new table
  local attempts = 0
  while attempts < 100 do
    local bucket = math.random(0, M.ADDRMAN.NEW_BUCKET_COUNT - 1)
    local pos = math.random(0, M.ADDRMAN.BUCKET_SIZE - 1)
    local entry = self._new_buckets[bucket][pos]
    if entry then
      return {ip = entry.ip, port = entry.port, services = entry.services}
    end
    attempts = attempts + 1
  end

  return nil
end

--- Get address manager statistics.
-- @return table: {new_count, tried_count, new_buckets, tried_buckets}
function PeerManager:get_addrman_stats()
  return {
    new_count = self._new_count,
    tried_count = self._tried_count,
    new_bucket_count = M.ADDRMAN.NEW_BUCKET_COUNT,
    tried_bucket_count = M.ADDRMAN.TRIED_BUCKET_COUNT,
    bucket_size = M.ADDRMAN.BUCKET_SIZE,
  }
end

--------------------------------------------------------------------------------
-- Outbound Diversity (Eclipse Attack Mitigation)
--------------------------------------------------------------------------------

--- Check if adding an outbound connection to this IP would violate diversity.
-- Rejects peers from the same /16 subnet as existing outbound connections.
-- @param ip string: IP address to check
-- @return boolean: true if connection would be allowed
function PeerManager:_check_outbound_diversity(ip)
  local group = M.get_addr_group(ip)
  -- Allow if no existing connections from this group
  return not self._outbound_groups[group] or self._outbound_groups[group] == 0
end

--- Track an outbound connection for diversity checking.
-- @param ip string: IP address
function PeerManager:_add_outbound_group(ip)
  local group = M.get_addr_group(ip)
  self._outbound_groups[group] = (self._outbound_groups[group] or 0) + 1
end

--- Remove tracking for an outbound connection.
-- @param ip string: IP address
function PeerManager:_remove_outbound_group(ip)
  local group = M.get_addr_group(ip)
  if self._outbound_groups[group] then
    self._outbound_groups[group] = self._outbound_groups[group] - 1
    if self._outbound_groups[group] <= 0 then
      self._outbound_groups[group] = nil
    end
  end
end

--------------------------------------------------------------------------------
-- Anchor Connections (Eclipse Attack Mitigation)
-- Reference: Bitcoin Core net.cpp AnchorConnections
--------------------------------------------------------------------------------

--- Load anchor peers from anchors.dat.
-- Anchors are block-relay-only peers that persist across restarts.
function PeerManager:_load_anchors()
  local path = self.data_dir .. "/anchors.dat"
  local f = io.open(path, "r")
  if not f then
    self._anchors = {}
    return
  end

  self._anchors = {}
  for line in f:lines() do
    local ip, port_str = line:match("^([^:]+):(%d+)$")
    if ip and port_str then
      local port = tonumber(port_str)
      if port then
        self._anchors[#self._anchors + 1] = {ip = ip, port = port}
      end
    end
  end
  f:close()

  -- Delete anchors file after loading (Bitcoin Core behavior)
  -- This prevents stale anchors after unclean shutdowns
  os.remove(path)
end

--- Save anchor peers to anchors.dat on shutdown.
-- Saves up to 2 block-relay-only outbound connections.
function PeerManager:_save_anchors()
  local anchors_to_save = {}

  -- Collect block-relay-only outbound peers
  for _, p in ipairs(self.peer_list) do
    if not p.inbound and p.state == peer_mod.STATE.ESTABLISHED then
      -- In a full implementation, we'd check if this is a block-relay-only connection
      -- For now, just save outbound peers
      if #anchors_to_save < M.ADDRMAN.MAX_ANCHORS then
        anchors_to_save[#anchors_to_save + 1] = {ip = p.ip, port = p.port}
      end
    end
  end

  if #anchors_to_save == 0 then
    return
  end

  local path = self.data_dir .. "/anchors.dat"
  local f = io.open(path, "w")
  if not f then
    return
  end

  for _, anchor in ipairs(anchors_to_save) do
    f:write(anchor.ip .. ":" .. tostring(anchor.port) .. "\n")
  end
  f:close()
end

--- Get the list of loaded anchors (for testing).
-- @return table: list of {ip, port}
function PeerManager:get_anchors()
  return self._anchors or {}
end

--- Connect to anchor peers.
-- Called during startup to establish anchor connections first.
function PeerManager:_connect_to_anchors()
  for _, anchor in ipairs(self._anchors) do
    if not self.peers[anchor.ip .. ":" .. anchor.port] then
      -- Try to connect to anchor
      self:connect_peer(anchor.ip, anchor.port)
    end
  end
  -- Clear anchors after attempting connections
  self._anchors = {}
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
            -- Also add to address manager new table
            self:_add_to_new(addr.addr, port, p2p.SERVICES.NODE_NETWORK, os.time(), "dns")
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
-- @param skip_diversity boolean: skip outbound diversity check (for anchors)
-- @return boolean: true on success
-- @return string: error message on failure
function PeerManager:connect_peer(ip, port, skip_diversity)
  local key = ip .. ":" .. port
  if self.peers[key] then return false, "already connected" end
  if self.banned[ip] and self.banned[ip] > os.time() then
    return false, "peer is banned"
  end
  if #self.peer_list >= self.max_peers then
    return false, "max peers reached"
  end

  -- Check outbound diversity (eclipse attack mitigation)
  if not skip_diversity and not self:_check_outbound_diversity(ip) then
    return false, "same /16 subnet as existing peer"
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

  -- Track outbound connection group
  self:_add_outbound_group(ip)

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

  -- If this was an established outbound connection, move to tried table
  if not p.inbound and p.state == peer_mod.STATE.ESTABLISHED then
    self:_move_to_tried(p.ip, p.port)
  end

  -- Remove outbound group tracking
  if not p.inbound then
    self:_remove_outbound_group(p.ip)
  end

  p:disconnect(reason)
  self.peers[key] = nil
  for i, peer in ipairs(self.peer_list) do
    if peer == p then
      table.remove(self.peer_list, i)
      break
    end
  end
  self.our_nonces[p.nonce] = nil
  -- Clean up trickling state
  self:_cleanup_peer_trickle(p)
  if self.callbacks.on_peer_disconnected then
    self.callbacks.on_peer_disconnected(p, reason)
  end
end

--------------------------------------------------------------------------------
-- Peer Selection
--------------------------------------------------------------------------------

--- Select a peer candidate for outbound connection.
-- Uses the address manager with new/tried bucketing.
-- Enforces outbound diversity (no two peers from same /16 subnet).
-- @return table|nil: address info or nil if no candidates
function PeerManager:select_peer_to_connect()
  local now = os.time()

  -- First try to select from address manager
  for _ = 1, 100 do
    local addr = self:_select_address()
    if addr then
      local key = addr.ip .. ":" .. addr.port
      if not self.peers[key]
         and (not self.banned[addr.ip] or self.banned[addr.ip] <= now)
         and self:_check_outbound_diversity(addr.ip) then
        -- Check last_try from known_addresses
        local known = self.known_addresses[key]
        if not known or (now - known.last_try) > 60 then
          return {ip = addr.ip, port = addr.port, services = addr.services}
        end
      end
    end
  end

  -- Fall back to known_addresses
  local candidates = {}
  for key, info in pairs(self.known_addresses) do
    if not self.peers[key]
       and (not self.banned[info.ip] or self.banned[info.ip] <= now)
       and (now - info.last_try) > 60
       and self:_check_outbound_diversity(info.ip) then
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
-- Prioritizes anchor connections on startup for eclipse attack mitigation.
function PeerManager:maintain_connections()
  -- Count current outbound connections
  local outbound = 0
  for _, p in ipairs(self.peer_list) do
    if not p.inbound then outbound = outbound + 1 end
  end

  -- First, try to connect to any remaining anchor peers (eclipse mitigation)
  if self._anchors and #self._anchors > 0 then
    while #self._anchors > 0 and outbound < self.max_outbound do
      local anchor = table.remove(self._anchors, 1)
      local key = anchor.ip .. ":" .. anchor.port
      if not self.peers[key] and not self:is_banned(anchor.ip) then
        -- Skip diversity check for anchors (they're trusted from previous session)
        local ok = self:connect_peer(anchor.ip, anchor.port, true)
        if ok then outbound = outbound + 1 end
      end
    end
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
  duration = duration or M.MISBEHAVIOR.DEFAULT_BAN_DURATION
  local ban_until = os.time() + duration
  self.banned[ip] = ban_until

  -- Persist ban to disk
  self:_save_bans()

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

--- Unban a peer's IP address.
-- @param ip string: IP address to unban
function PeerManager:unban_peer(ip)
  self.banned[ip] = nil
  self:_save_bans()
end

--- Clear all expired bans from memory and disk.
function PeerManager:clear_expired_bans()
  local now = os.time()
  local changed = false
  for ip, ban_until in pairs(self.banned) do
    if ban_until <= now then
      self.banned[ip] = nil
      changed = true
    end
  end
  if changed then
    self:_save_bans()
  end
end

--- Get list of all banned IPs with expiry times.
-- @return table: list of {ip, ban_until} entries
function PeerManager:get_banned_list()
  local result = {}
  local now = os.time()
  for ip, ban_until in pairs(self.banned) do
    if ban_until > now then
      result[#result + 1] = {ip = ip, ban_until = ban_until}
    end
  end
  return result
end

--- Check if an IP is banned.
-- @param ip string: IP address to check
-- @return boolean: true if banned
function PeerManager:is_banned(ip)
  return self.banned[ip] and self.banned[ip] > os.time()
end

--- Log misbehavior and add to ban score.
-- Reference: Bitcoin Core net_processing.cpp Misbehaving()
-- @param peer Peer: peer that misbehaved
-- @param score number: ban score to add
-- @param reason string: reason for the misbehavior
function PeerManager:misbehaving(peer, score, reason)
  reason = reason or "unspecified"
  local old_score = peer.ban_score
  peer.ban_score = peer.ban_score + score

  -- Log the misbehavior
  local key = peer.ip .. ":" .. peer.port
  print(string.format(
    "[misbehaving] peer=%s score +%d (%d -> %d): %s",
    key, score, old_score, peer.ban_score, reason
  ))

  -- Check if threshold exceeded
  if peer.ban_score >= M.MISBEHAVIOR.BAN_THRESHOLD then
    print(string.format(
      "[misbehaving] peer=%s ban threshold reached, banning",
      key
    ))
    self:ban_peer(peer.ip)
    self:disconnect_peer(peer, "ban score exceeded: " .. reason)
  end
end

--- Add to a peer's ban score and ban if threshold exceeded.
-- Alias for misbehaving() for backwards compatibility.
-- @param peer Peer: peer to add score to
-- @param score number: ban score to add
-- @param reason string: reason for the score (optional)
function PeerManager:add_ban_score(peer, score, reason)
  self:misbehaving(peer, score, reason)
end

--------------------------------------------------------------------------------
-- Addr Message Handling
--------------------------------------------------------------------------------

--- Handle received addr message.
-- @param peer Peer: peer that sent the message
-- @param payload string: addr message payload
function PeerManager:handle_addr(peer, payload)
  local addresses = p2p.deserialize_addr(payload)
  local now = os.time()
  local src_ip = peer and peer.ip or "unknown"
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
      -- Add to address manager new table with source tracking
      self:_add_to_new(addr.ip, addr.port, addr.services, addr.timestamp, src_ip)
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
-- maintains outbound connections, and processes transaction trickling.
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
        -- Initialize trickling state for newly established peer
        self:_init_peer_trickle(p)
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

  -- Process transaction trickling (batched, randomized inv sending)
  self:_process_trickle()

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
-- Transaction Trickling (Privacy-Preserving Relay)
-- Reference: Bitcoin Core net_processing.cpp SendMessages(), INVENTORY_BROADCAST_INTERVAL
--------------------------------------------------------------------------------

--- Initialize trickling state for a peer.
-- Called when a peer completes handshake. Sets up inv_queue and Poisson timer.
-- @param p Peer: peer to initialize
function PeerManager:_init_peer_trickle(p)
  local key = p.ip .. ":" .. p.port
  local interval = p.inbound and M.TRICKLE.INBOUND_INTERVAL or M.TRICKLE.OUTBOUND_INTERVAL
  self._peer_trickle = self._peer_trickle or {}
  self._peer_trickle[key] = {
    inv_queue = {},                              -- {hash, is_wtxid} entries to announce
    inv_known = {},                              -- hashes we've already sent (bloom filter substitute)
    next_send_time = socket.gettime() + M.poisson_delay(interval),
  }
end

--- Clean up trickling state for a peer.
-- Called when a peer disconnects.
-- @param p Peer: peer to clean up
function PeerManager:_cleanup_peer_trickle(p)
  local key = p.ip .. ":" .. p.port
  if self._peer_trickle then
    self._peer_trickle[key] = nil
  end
end

--- Queue a transaction announcement for all established peers.
-- Uses trickling: queues inv entries for later batched, randomized sending.
-- @param txid string: transaction id (hash256 as raw bytes)
-- @param wtxid string: witness transaction id (hash256 as raw bytes, optional)
function PeerManager:queue_tx_announcement(txid, wtxid)
  wtxid = wtxid or txid  -- Non-segwit: wtxid equals txid
  for _, p in ipairs(self.peer_list) do
    if p.state == peer_mod.STATE.ESTABLISHED then
      local key = p.ip .. ":" .. p.port
      local trickle = self._peer_trickle and self._peer_trickle[key]
      if trickle then
        -- Use wtxid for peers that negotiated wtxidrelay (BIP 339)
        local hash = p.wtxid_relay and wtxid or txid
        local is_wtxid = p.wtxid_relay
        -- Don't re-announce transactions the peer already knows about
        if not trickle.inv_known[hash] then
          trickle.inv_queue[#trickle.inv_queue + 1] = {hash = hash, is_wtxid = is_wtxid}
        end
      end
    end
  end
end

--- Get the pending inv queue for a peer (for testing).
-- @param p Peer: peer to check
-- @return table|nil: inv_queue array or nil if not found
function PeerManager:get_peer_inv_queue(p)
  local key = p.ip .. ":" .. p.port
  local trickle = self._peer_trickle and self._peer_trickle[key]
  return trickle and trickle.inv_queue
end

--- Get the next trickle send time for a peer (for testing).
-- @param p Peer: peer to check
-- @return number|nil: next send time or nil if not found
function PeerManager:get_peer_next_send_time(p)
  local key = p.ip .. ":" .. p.port
  local trickle = self._peer_trickle and self._peer_trickle[key]
  return trickle and trickle.next_send_time
end

--- Process trickle timers for all peers and send batched inv messages.
-- Called from tick(). Shuffles entries for privacy, sends up to MAX_INV_PER_MSG per peer.
function PeerManager:_process_trickle()
  if not self._peer_trickle then return end

  local now = socket.gettime()

  for _, p in ipairs(self.peer_list) do
    if p.state == peer_mod.STATE.ESTABLISHED then
      local key = p.ip .. ":" .. p.port
      local trickle = self._peer_trickle[key]
      if trickle and now >= trickle.next_send_time then
        -- Time to send! Schedule next send with Poisson delay.
        local interval = p.inbound and M.TRICKLE.INBOUND_INTERVAL or M.TRICKLE.OUTBOUND_INTERVAL
        trickle.next_send_time = now + M.poisson_delay(interval)

        -- Shuffle queue for privacy (Fisher-Yates)
        M.shuffle(trickle.inv_queue)

        -- Send batches of up to MAX_INV_PER_MSG
        while #trickle.inv_queue > 0 do
          local batch = {}
          local batch_size = math.min(#trickle.inv_queue, M.TRICKLE.MAX_INV_PER_MSG)

          for _ = 1, batch_size do
            local entry = table.remove(trickle.inv_queue, 1)
            -- Use MSG_WTX for wtxid, MSG_TX for txid
            local inv_type = entry.is_wtxid and p2p.INV_TYPE.MSG_WTX or p2p.INV_TYPE.MSG_TX
            batch[#batch + 1] = {type = inv_type, hash = entry.hash}
            -- Mark as known so we don't re-announce
            trickle.inv_known[entry.hash] = true
          end

          if #batch > 0 then
            local payload = p2p.serialize_inv(batch)
            p:send_message("inv", payload)
          end

          -- Only send one batch per tick per peer (rate limiting)
          break
        end
      end
    end
  end
end

--- Clear the inv_known filter for a peer (e.g., after reconnect).
-- @param p Peer: peer to clear
function PeerManager:clear_peer_inv_known(p)
  local key = p.ip .. ":" .. p.port
  local trickle = self._peer_trickle and self._peer_trickle[key]
  if trickle then
    trickle.inv_known = {}
  end
end

--------------------------------------------------------------------------------
-- Shutdown
--------------------------------------------------------------------------------

--- Stop the peer manager and disconnect all peers.
-- Saves anchor connections for eclipse attack mitigation.
function PeerManager:stop()
  -- Save anchors before disconnecting peers
  self:_save_anchors()

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

--------------------------------------------------------------------------------
-- Ban Persistence
--------------------------------------------------------------------------------

--- Get the path to the ban list file.
-- @return string: path to banned.dat
function PeerManager:_get_ban_file_path()
  return self.data_dir .. "/banned.dat"
end

--- Save the current ban list to disk.
function PeerManager:_save_bans()
  local path = self:_get_ban_file_path()
  local f = io.open(path, "w")
  if not f then
    -- Can't write, just continue with in-memory bans
    return
  end

  local now = os.time()
  for ip, ban_until in pairs(self.banned) do
    -- Only persist bans that haven't expired
    if ban_until > now then
      f:write(ip .. ":" .. tostring(ban_until) .. "\n")
    end
  end
  f:close()
end

--- Load the ban list from disk.
function PeerManager:_load_bans()
  local path = self:_get_ban_file_path()
  local f = io.open(path, "r")
  if not f then
    -- No ban file, start with empty list
    return
  end

  local now = os.time()
  for line in f:lines() do
    -- Parse "ip:timestamp" format
    local ip, timestamp_str = line:match("^([^:]+):(%d+)$")
    if ip and timestamp_str then
      local ban_until = tonumber(timestamp_str)
      if ban_until and ban_until > now then
        self.banned[ip] = ban_until
      end
    end
  end
  f:close()
end

return M
