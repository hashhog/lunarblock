local socket = require("socket")
local peer_mod = require("lunarblock.peer")
local p2p = require("lunarblock.p2p")
local crypto = require("lunarblock.crypto")
local proxy_mod = require("lunarblock.proxy")
local M = {}

--------------------------------------------------------------------------------
-- Misbehavior Score Constants
--------------------------------------------------------------------------------

M.MISBEHAVIOR = {
  INVALID_BLOCK_HEADER = 100,  -- Instant ban: invalid PoW or header structure
  INVALID_BLOCK = 100,         -- Instant ban: block fails validation
  INVALID_TRANSACTION = 10,    -- Minor violation: tx fails validation
  UNSOLICITED_DATA = 5,        -- Sent data we didn't request
  HEADERS_DONT_CONNECT = 20,   -- Headers that don't connect to our chain
  BLOCK_DOWNLOAD_STALL = 50,   -- Stalling block download
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
-- Stale Tip Detection & Eviction Constants
-- Reference: Bitcoin Core net_processing.cpp
--------------------------------------------------------------------------------

M.STALE_TIP = {
  -- Time between stale tip checks (10 minutes)
  STALE_CHECK_INTERVAL = 600,
  -- Time to wait before considering a peer for eviction based on chain sync (20 minutes)
  CHAIN_SYNC_TIMEOUT = 1200,
  -- Grace period for peer to respond to getheaders (2 minutes)
  HEADERS_RESPONSE_TIME = 120,
  -- Minimum time a peer must be connected before eviction (30 seconds)
  MINIMUM_CONNECT_TIME = 30,
  -- Interval to check for extra peer eviction (45 seconds)
  EXTRA_PEER_CHECK_INTERVAL = 45,
  -- Maximum number of outbound peers that can be protected from eviction
  MAX_OUTBOUND_PEERS_TO_PROTECT = 4,
  -- Target outbound full-relay connections
  TARGET_OUTBOUND_FULL_RELAY = 8,
  -- Target block-relay-only connections
  TARGET_BLOCK_RELAY_ONLY = 2,
}

--------------------------------------------------------------------------------
-- Network Group Utilities (Eclipse Attack Mitigation)
-- Reference: Bitcoin Core netgroup.cpp GetGroup()
--------------------------------------------------------------------------------

--- Get the network group for an address.
-- For IPv4, this is the /16 subnet (first two octets).
-- For IPv6, this is typically the /32.
-- For TOR/I2P/CJDNS, the network type itself is the group.
-- @param ip string: IP address string (e.g., "192.168.1.1")
-- @param network_id number: BIP155 network ID (optional)
-- @return string: group identifier bytes
function M.get_addr_group(ip, network_id)
  -- For non-IP networks (BIP155), use network type as group
  if network_id then
    if network_id == p2p.NET_ID.TORV3 then
      return string.char(p2p.NET_ID.TORV3)  -- All TorV3 in one group
    elseif network_id == p2p.NET_ID.I2P then
      return string.char(p2p.NET_ID.I2P)     -- All I2P in one group
    elseif network_id == p2p.NET_ID.CJDNS then
      return string.char(p2p.NET_ID.CJDNS)   -- All CJDNS in one group
    end
  end

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

  -- Stale tip detection state (Bitcoin Core: CheckForStaleTipAndEvictPeers)
  self._last_tip_update = socket.gettime()
  self._stale_tip_check_time = socket.gettime() + M.STALE_TIP.STALE_CHECK_INTERVAL
  self._extra_peer_check_time = socket.gettime() + M.STALE_TIP.EXTRA_PEER_CHECK_INTERVAL
  self._try_new_outbound_peer = false
  self._initial_sync_finished = false
  self._blocks_in_flight = {}  -- global tracking of block hashes being downloaded
  self._peer_chain_sync = {}   -- ip:port -> {timeout, work_header, sent_getheaders, protect}

  -- Per-peer best known block tracking
  self._peer_best_block = {}   -- ip:port -> {hash, height, work}
  self._peer_last_block_ann = {}  -- ip:port -> timestamp of last block announcement
  self._peer_connect_time = {}   -- ip:port -> connection time

  -- Proxy configuration (Tor/I2P support)
  self.proxy_config = nil      -- ProxyConfig object from proxy module

  -- Initialize proxy if configured
  if config.proxy then
    self:_init_proxy(config)
  end

  -- Initialize address manager (eclipse attack mitigation)
  self:_init_addrman()

  -- Load persisted bans from disk
  self:_load_bans()

  -- Load and connect to anchor peers
  self:_load_anchors()

  return self
end

--------------------------------------------------------------------------------
-- Proxy Initialization (Tor/I2P Support)
--------------------------------------------------------------------------------

--- Initialize proxy configuration from config options.
-- @param config table: configuration with proxy settings
function PeerManager:_init_proxy(config)
  self.proxy_config = proxy_mod.new_config()

  -- SOCKS5 proxy for Tor (e.g., -proxy=127.0.0.1:9050)
  if config.proxy then
    local host, port = config.proxy:match("^([^:]+):(%d+)$")
    if host and port then
      self.proxy_config:set_socks5_proxy(host, tonumber(port), config.proxy_stream_isolation)
    end
  end

  -- I2P SAM bridge (e.g., -i2psam=127.0.0.1:7656)
  if config.i2psam then
    local host, port = config.i2psam:match("^([^:]+):(%d+)$")
    if host and port then
      local keyfile = config.i2p_private_key or (self.data_dir .. "/i2p_private_key")
      self.proxy_config:set_i2p_sam(host, tonumber(port), keyfile)
    end
  end

  -- Network restriction (e.g., -onlynet=onion or -onlynet=i2p)
  if config.onlynet then
    self.proxy_config:set_onlynet(config.onlynet)
  end

  -- DNS over proxy (prevents DNS leaks when using Tor)
  if config.proxy_dns ~= false then
    self.proxy_config.proxy_dns = true
  end
end

--- Get our advertised addresses for privacy networks.
-- @return table: {onion = ".onion addr", i2p = ".b32.i2p addr"}
function PeerManager:get_local_addresses()
  local addresses = {}

  if self.proxy_config and self.proxy_config.i2p_sam then
    local i2p_addr = self.proxy_config.i2p_sam:get_my_address()
    if i2p_addr then
      addresses.i2p = i2p_addr
    end
  end

  -- Tor hidden service address would be configured separately
  -- (requires reading from torrc or control port)

  return addresses
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
-- When proxy_dns is enabled, this skips regular DNS and relies on
-- addresses learned from peer addr/addrv2 messages (no DNS leaks).
-- @return number: count of new addresses found
function PeerManager:discover_from_dns()
  if not self.network or not self.network.dns_seeds then
    return 0
  end

  -- If using proxy with DNS leak prevention, don't do DNS lookups
  -- Rely on addr messages from connected peers instead
  if self.proxy_config and self.proxy_config.proxy_dns then
    -- DNS seeds can't be resolved through SOCKS5 (no DNS query support)
    -- We rely on connecting to known hardcoded peers or addr gossip
    return 0
  end

  -- If onlynet is set to a privacy network, skip DNS (privacy leak)
  if self.proxy_config and self.proxy_config.onlynet then
    local onlynet = self.proxy_config.onlynet
    if onlynet == "onion" or onlynet == "i2p" then
      return 0
    end
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

  -- Check network restriction (onlynet)
  if self.proxy_config and not self.proxy_config:is_address_allowed(ip) then
    return false, "address not allowed by onlynet restriction"
  end

  -- Check outbound diversity (eclipse attack mitigation)
  -- Skip for privacy network addresses (Tor/I2P are in single groups anyway)
  local net_type = proxy_mod.detect_network_type(ip)
  local is_privacy_net = net_type == proxy_mod.NETWORK_TYPE.ONION or
                         net_type == proxy_mod.NETWORK_TYPE.I2P
  if not skip_diversity and not is_privacy_net and not self:_check_outbound_diversity(ip) then
    return false, "same /16 subnet as existing peer"
  end

  -- Create peer with proxy configuration
  local use_v2 = not self.config.nov2transport
  local p = peer_mod.new(ip, port, self.network, self.our_height, use_v2, self.proxy_config)
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

  -- Initialize chain sync state for stale tip detection
  self:_init_peer_chain_sync(p)

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
  -- Clean up chain sync state
  self:_cleanup_peer_chain_sync(p)
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
-- Also opens extra outbound connection when tip is stale (to find better chain).
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

  -- Determine connection target (allow one extra if tip is stale)
  local target = self.max_outbound
  if self._try_new_outbound_peer and target > 0 then
    target = target + 1  -- Allow one extra outbound when searching for better chain
  end

  -- Connect to more peers if below target
  while outbound < target do
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
-- Addr/Addrv2 Message Handling (BIP155)
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
          network_id = p2p.NET_ID.IPV4,  -- Legacy addr is always IPv4/IPv6
          attempts = 0,
          last_try = 0,
        }
      end
      -- Add to address manager new table with source tracking
      self:_add_to_new(addr.ip, addr.port, addr.services, addr.timestamp, src_ip)
    end
  end
end

--- Handle received addrv2 message (BIP155).
-- @param peer Peer: peer that sent the message
-- @param payload string: addrv2 message payload
function PeerManager:handle_addrv2(peer, payload)
  local addresses = p2p.deserialize_addrv2(payload)
  local now = os.time()
  local src_ip = peer and peer.ip or "unknown"
  for _, addr in ipairs(addresses) do
    -- Skip invalid addresses
    if not addr.valid then
      goto continue
    end
    -- Only accept addresses with recent timestamps (within 3 hours)
    if addr.timestamp > now - 10800 and addr.timestamp <= now + 600 then
      -- For non-IP network types, use addr_str as the key
      local addr_key = addr.addr_str or addr.ip
      if addr_key then
        local key = addr_key .. ":" .. addr.port
        if not self.known_addresses[key] then
          self.known_addresses[key] = {
            ip = addr.ip,                    -- May be nil for TOR/I2P/CJDNS
            addr_str = addr.addr_str,        -- Full address string
            addr_bytes = addr.addr_bytes,    -- Raw address bytes
            port = addr.port,
            services = addr.services,
            timestamp = addr.timestamp,
            network_id = addr.network_id,
            attempts = 0,
            last_try = 0,
          }
        end
        -- Only add to connection pool if it's an IP address we can connect to
        if addr.ip then
          self:_add_to_new(addr.ip, addr.port, addr.services, addr.timestamp, src_ip)
        end
      end
    end
    ::continue::
  end
end

--- Serialize addresses for a peer, using addrv2 if they support it.
-- @param peer Peer: peer to send to
-- @param addresses table: list of address entries from known_addresses
-- @return string: serialized payload (addr or addrv2 format)
-- @return string: command name ("addr" or "addrv2")
function PeerManager:serialize_addr_for_peer(peer, addresses)
  if peer.send_addrv2 then
    -- Filter to addresses compatible with addrv2
    local addrv2_list = {}
    for _, addr in ipairs(addresses) do
      if p2p.is_addr_compatible(true, addr) then
        addrv2_list[#addrv2_list + 1] = {
          timestamp = addr.timestamp,
          services = addr.services,
          network_id = addr.network_id or p2p.NET_ID.IPV4,
          addr_bytes = addr.addr_bytes,
          ip = addr.ip,
          port = addr.port,
        }
      end
    end
    return p2p.serialize_addrv2(addrv2_list), "addrv2"
  else
    -- Legacy addr format: only IPv4/IPv6
    local addr_list = {}
    for _, addr in ipairs(addresses) do
      if p2p.is_addr_compatible(false, addr) and addr.ip then
        addr_list[#addr_list + 1] = {
          timestamp = addr.timestamp,
          services = addr.services,
          ip = addr.ip,
          port = addr.port,
        }
      end
    end
    return p2p.serialize_addr(addr_list), "addr"
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
  local listen_port = port or (self.network and self.network.port) or 8333
  -- Use tcp() + bind() + listen() manually, skipping setoption
  -- which fails on some luasocket builds.
  local sock = socket.tcp()
  if not sock then return false, "failed to create socket" end
  local ok, err = sock:bind(bind_ip or "0.0.0.0", listen_port)
  if not ok then
    sock:close()
    return false, err
  end
  ok, err = sock:listen(32)
  if not ok then
    sock:close()
    return false, err
  end
  self.listen_socket = sock
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

  local inbound_v2 = not self.config.nov2transport
  local p = peer_mod.new(ip, port, self.network, self.our_height, inbound_v2)
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

  -- Check for stale tip and evict extra outbound peers
  self:check_for_stale_tip_and_evict_peers()

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
-- Stale Tip Detection & Extra Outbound Peer Eviction
-- Reference: Bitcoin Core net_processing.cpp ConsiderEviction, EvictExtraOutboundPeers
--------------------------------------------------------------------------------

--- Record that the chain tip was updated.
-- Called when a new block is connected to the best chain.
function PeerManager:record_tip_update()
  self._last_tip_update = socket.gettime()
end

--- Get the time of the last tip update.
-- @return number: timestamp of last tip update
function PeerManager:get_last_tip_update()
  return self._last_tip_update
end

--- Check if the tip may be stale.
-- Tip is stale if more than 3x block interval old AND no blocks in-flight.
-- @return boolean: true if tip may be stale
function PeerManager:tip_may_be_stale()
  local now = socket.gettime()
  local pow_target_spacing = self.network and self.network.pow_target_spacing or 600
  local stale_threshold = pow_target_spacing * 3  -- 30 minutes for mainnet

  -- Tip is stale if no update in 3x block interval and no blocks in flight
  local blocks_in_flight_count = 0
  for _ in pairs(self._blocks_in_flight) do
    blocks_in_flight_count = blocks_in_flight_count + 1
  end

  return (now - self._last_tip_update) > stale_threshold and blocks_in_flight_count == 0
end

--- Update a peer's best known block.
-- Called when receiving headers or blocks from a peer.
-- @param p Peer: the peer
-- @param height number: best known block height
-- @param hash string: best known block hash (optional)
-- @param work number: cumulative chain work (optional)
function PeerManager:set_peer_best_block(p, height, hash, work)
  local key = p.ip .. ":" .. p.port
  self._peer_best_block[key] = {
    height = height,
    hash = hash,
    work = work or 0,
  }
end

--- Get a peer's best known block info.
-- @param p Peer: the peer
-- @return table|nil: {height, hash, work} or nil
function PeerManager:get_peer_best_block(p)
  local key = p.ip .. ":" .. p.port
  return self._peer_best_block[key]
end

--- Record that a peer announced a new block.
-- @param p Peer: the peer
-- @param hash string: block hash (optional)
function PeerManager:record_peer_block_announcement(p, hash)
  local _ = hash  -- hash is optional, for future use
  local key = p.ip .. ":" .. p.port
  self._peer_last_block_ann[key] = socket.gettime()
end

--- Get the timestamp of a peer's last block announcement.
-- @param p Peer: the peer
-- @return number: timestamp or 0 if never
function PeerManager:get_peer_last_block_announcement(p)
  local key = p.ip .. ":" .. p.port
  return self._peer_last_block_ann[key] or 0
end

--- Initialize chain sync state for a peer.
-- Called when peer is connected.
-- @param p Peer: the peer
function PeerManager:_init_peer_chain_sync(p)
  local key = p.ip .. ":" .. p.port
  self._peer_chain_sync[key] = {
    timeout = 0,          -- timeout timestamp (0 = not set)
    work_header = nil,    -- reference header when timeout was set {height, hash}
    sent_getheaders = false,
    protect = false,      -- protected from eviction
  }
  self._peer_connect_time[key] = socket.gettime()
end

--- Clean up chain sync state for a peer.
-- Called when peer is disconnected.
-- @param p Peer: the peer
function PeerManager:_cleanup_peer_chain_sync(p)
  local key = p.ip .. ":" .. p.port
  self._peer_chain_sync[key] = nil
  self._peer_best_block[key] = nil
  self._peer_last_block_ann[key] = nil
  self._peer_connect_time[key] = nil
end

--- Get the chain sync state for a peer (for testing).
-- @param p Peer: the peer
-- @return table|nil: chain sync state
function PeerManager:get_peer_chain_sync(p)
  local key = p.ip .. ":" .. p.port
  return self._peer_chain_sync[key]
end

--- Consider evicting a peer based on chain sync state.
-- Reference: Bitcoin Core net_processing.cpp ConsiderEviction()
-- @param p Peer: outbound peer to consider
-- @param now number: current timestamp
function PeerManager:consider_eviction(p, now)
  local key = p.ip .. ":" .. p.port
  local sync_state = self._peer_chain_sync[key]

  -- Only consider outbound peers that have started syncing
  if not sync_state or p.inbound or sync_state.protect then
    return
  end

  -- fSyncStarted equivalent: check if peer is established
  if p.state ~= peer_mod.STATE.ESTABLISHED then
    return
  end

  local peer_best = self._peer_best_block[key]
  local peer_height = peer_best and peer_best.height or 0

  -- If peer's best known block >= our tip, reset timeout
  if peer_height >= self.our_height then
    if sync_state.timeout ~= 0 then
      sync_state.timeout = 0
      sync_state.work_header = nil
      sync_state.sent_getheaders = false
    end
    return
  end

  -- Peer's best block is behind our tip
  if sync_state.timeout == 0 or
     (sync_state.work_header and peer_height >= sync_state.work_header.height) then
    -- Set/reset timeout based on current tip
    sync_state.timeout = now + M.STALE_TIP.CHAIN_SYNC_TIMEOUT
    sync_state.work_header = {height = self.our_height}
    sync_state.sent_getheaders = false
  elseif sync_state.timeout > 0 and now > sync_state.timeout then
    -- Timeout exceeded
    if sync_state.sent_getheaders then
      -- Already sent getheaders and still behind - disconnect
      self:disconnect_peer(p, "outbound peer has old chain")
    else
      -- Send a getheaders to give peer a chance
      if p.state == peer_mod.STATE.ESTABLISHED then
        -- Send getheaders with our tip
        local getheaders_payload = p2p.serialize_getheaders(
          p2p.PROTOCOL_VERSION,
          {},  -- empty locator = from genesis
          p2p.ZERO_HASH
        )
        p:send_message("getheaders", getheaders_payload)
      end
      sync_state.sent_getheaders = true
      -- Extend timeout by HEADERS_RESPONSE_TIME
      sync_state.timeout = now + M.STALE_TIP.HEADERS_RESPONSE_TIME
    end
  end
end

--- Get count of outbound connections.
-- @return number, number: full-relay count, block-relay-only count
function PeerManager:get_outbound_counts()
  local full_relay = 0
  local block_only = 0
  for _, p in ipairs(self.peer_list) do
    if not p.inbound then
      -- For now, treat all outbound as full-relay
      -- A full implementation would track block-relay-only separately
      full_relay = full_relay + 1
    end
  end
  return full_relay, block_only
end

--- Check if we have extra outbound peers beyond targets.
-- @return number: count of extra full-relay peers
function PeerManager:get_extra_full_outbound_count()
  local full_relay, _ = self:get_outbound_counts()
  local target = M.STALE_TIP.TARGET_OUTBOUND_FULL_RELAY
  return math.max(0, full_relay - target)
end

--- Evict extra outbound peers.
-- Reference: Bitcoin Core net_processing.cpp EvictExtraOutboundPeers()
-- @param now number: current timestamp
function PeerManager:evict_extra_outbound_peers(now)
  local extra_count = self:get_extra_full_outbound_count()
  if extra_count <= 0 then
    return
  end

  -- Find the outbound peer with the oldest block announcement
  local worst_peer = nil
  local oldest_announcement = math.huge

  for _, p in ipairs(self.peer_list) do
    if not p.inbound and p.state == peer_mod.STATE.ESTABLISHED then
      local key = p.ip .. ":" .. p.port
      local sync_state = self._peer_chain_sync[key]

      -- Skip protected peers
      if sync_state and sync_state.protect then
        goto continue
      end

      local last_ann = self._peer_last_block_ann[key] or 0
      if last_ann < oldest_announcement then
        oldest_announcement = last_ann
        worst_peer = p
      end
    end
    ::continue::
  end

  if worst_peer then
    local key = worst_peer.ip .. ":" .. worst_peer.port
    local connect_time = self._peer_connect_time[key] or 0

    -- Only disconnect if connected for minimum time and no blocks in-flight
    if (now - connect_time) > M.STALE_TIP.MINIMUM_CONNECT_TIME then
      -- Check no blocks in-flight from this peer
      local has_inflight = false
      for _, info in pairs(self._blocks_in_flight) do
        if info.peer == worst_peer then
          has_inflight = true
          break
        end
      end

      if not has_inflight then
        self:disconnect_peer(worst_peer, "evicting extra outbound peer")
        -- Stop trying new outbound peers after successful eviction
        self._try_new_outbound_peer = false
      end
    end
  end
end

--- Check for stale tip and manage extra outbound peers.
-- Reference: Bitcoin Core net_processing.cpp CheckForStaleTipAndEvictPeers()
function PeerManager:check_for_stale_tip_and_evict_peers()
  local now = socket.gettime()

  -- Run eviction check every EXTRA_PEER_CHECK_INTERVAL
  if now >= self._extra_peer_check_time then
    self._extra_peer_check_time = now + M.STALE_TIP.EXTRA_PEER_CHECK_INTERVAL

    -- Consider eviction for each outbound peer
    for _, p in ipairs(self.peer_list) do
      if not p.inbound then
        self:consider_eviction(p, now)
      end
    end

    -- Evict extra outbound peers if we have any
    self:evict_extra_outbound_peers(now)
  end

  -- Run stale tip check every STALE_CHECK_INTERVAL
  if now >= self._stale_tip_check_time then
    self._stale_tip_check_time = now + M.STALE_TIP.STALE_CHECK_INTERVAL

    if self:tip_may_be_stale() then
      -- Allow extra outbound connections
      self._try_new_outbound_peer = true
    elseif self._try_new_outbound_peer then
      -- Tip is no longer stale, stop trying new peers
      self._try_new_outbound_peer = false
    end
  end
end

--- Check if we should try connecting to extra outbound peers.
-- @return boolean: true if extra outbound connection allowed
function PeerManager:should_try_new_outbound_peer()
  return self._try_new_outbound_peer
end

--- Set whether to try new outbound peers (for testing).
-- @param try_new boolean: whether to try new peers
function PeerManager:set_try_new_outbound_peer(try_new)
  self._try_new_outbound_peer = try_new
end

--- Record that a block is in-flight from a peer.
-- @param hash string: block hash
-- @param p Peer: peer downloading from
function PeerManager:record_block_in_flight(hash, p)
  self._blocks_in_flight[hash] = {peer = p, time = socket.gettime()}
end

--- Remove a block from in-flight tracking.
-- @param hash string: block hash
function PeerManager:remove_block_in_flight(hash)
  self._blocks_in_flight[hash] = nil
end

--- Check if a block is in-flight.
-- @param hash string: block hash
-- @return boolean: true if in-flight
function PeerManager:is_block_in_flight(hash)
  return self._blocks_in_flight[hash] ~= nil
end

--- Get count of blocks in-flight.
-- @return number: count
function PeerManager:get_blocks_in_flight_count()
  local count = 0
  for _ in pairs(self._blocks_in_flight) do
    count = count + 1
  end
  return count
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
