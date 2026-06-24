local socket = require("socket")
local peer_mod = require("lunarblock.peer")
local p2p = require("lunarblock.p2p")
local crypto = require("lunarblock.crypto")
local proxy_mod = require("lunarblock.proxy")
local bip324 = require("lunarblock.bip324")
local asmap_mod = require("lunarblock.asmap")
local M = {}

-- Maximum asmap file size (8 MiB). Mirrors Bitcoin Core init.cpp.
-- FIX-50 / W115 BUG-3: guard against OOM from oversized asmap file.
local MAX_ASMAP_FILESIZE = asmap_mod.MAX_ASMAP_FILE_SIZE
M.MAX_ASMAP_FILESIZE = MAX_ASMAP_FILESIZE

--------------------------------------------------------------------------------
-- Misbehavior Score Constants
--------------------------------------------------------------------------------

M.MISBEHAVIOR = {
  INVALID_BLOCK_HEADER = 100,  -- Instant ban: invalid PoW or header structure
  INVALID_BLOCK = 100,         -- Instant ban: block fails validation
  INVALID_TRANSACTION = 10,    -- Minor violation: tx fails validation
  UNSOLICITED_DATA = 5,        -- Sent data we didn't request
  HEADERS_DONT_CONNECT = 20,   -- Headers that don't connect to our chain
  BLOCK_DOWNLOAD_STALL = 10,   -- Stalling block download (was 50; 50 caused mass-disconnect storms during IBD)
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
  -- Minimum time before the next feeler connection (Core net.h:61 FEELER_INTERVAL = 2min = 120s).
  -- A feeler is a short-lived probe to ONE address from the NEW table: on a
  -- successful handshake the address is promoted NEW->TRIED (keeping the TRIED
  -- table fresh = Core's primary eclipse-attack mitigation), then disconnected.
  FEELER_INTERVAL = 120,
}

--------------------------------------------------------------------------------
-- connman anti-eclipse / addr anti-DoS constants
-- Reference: Bitcoin Core src/net.h + src/net_processing.cpp
--------------------------------------------------------------------------------

M.CONNMAN = {
  -- At most one in-flight feeler at a time (Core net.h:75 MAX_FEELER_CONNECTIONS = 1).
  MAX_FEELER_CONNECTIONS = 1,
  -- getaddr response cap: at most 23% of the addrman, hard-capped at 1000
  -- (Core net_processing.cpp:188 MAX_PCT_ADDR_TO_SEND, :190 MAX_ADDR_TO_SEND).
  MAX_PCT_ADDR_TO_SEND = 23,
  MAX_ADDR_TO_SEND = 1000,
  -- Inbound-addr token bucket (Core net_processing.cpp:193/197):
  -- refill rate 0.1 token/s, capped at 1000 tokens, one token spent per
  -- processed address. Shared by the addr AND addrv2 handlers (Core routes
  -- both through the same ProcessAddrs bucket, net_processing.cpp:4022/5625)
  -- so an attacker cannot bypass the limit by switching to addrv2.
  MAX_ADDR_RATE_PER_SECOND = 0.1,
  MAX_ADDR_PROCESSING_TOKEN_BUCKET = 1000,
}

--------------------------------------------------------------------------------
-- Network Group Utilities (Eclipse Attack Mitigation)
-- Reference: Bitcoin Core netgroup.cpp GetGroup()
--------------------------------------------------------------------------------

--- Get the network group for an address.
-- When M._asmap_data is loaded (non-nil/non-empty), delegates to
-- asmap_mod.get_addr_group() which returns the ASN-derived group bytes
-- for IPv4/IPv6.  This closes BUG-9 (get_addr_group always used /16 or
-- /32 even when asmap was loaded).
-- For non-IP networks (BIP155), always returns the network-type byte.
-- Falls back to /16 (IPv4) or /32 (IPv6) prefix when no asmap is loaded.
--
-- Module-level asmap state: M._asmap_data (string|nil), set by
-- peerman_mod.set_asmap() or PeerManager:load_asmap().
-- @param ip string: IP address string (e.g., "192.168.1.1")
-- @param network_id number: BIP155 network ID (optional)
-- @return string: group identifier bytes
function M.get_addr_group(ip, network_id)
  -- Delegate to asmap module; it handles non-IP networks, ASN lookup,
  -- and /16//32 fallback consistently.
  return asmap_mod.get_addr_group(M._asmap_data, ip, network_id)
end

-- Module-level asmap data (nil = not loaded).
-- Set via M.set_asmap() below, or PeerManager:load_asmap().
M._asmap_data = nil

--- Set the module-level asmap data used by get_addr_group and bucket functions.
-- @param asmap string|nil: raw asmap bytes from asmap_mod.load_asmap()
function M.set_asmap(asmap)
  M._asmap_data = asmap
end

--- Return true when an asmap is currently loaded.
-- Mirrors Core's NetGroupManager::UsingASMap().
function M.using_asmap()
  return asmap_mod.using_asmap(M._asmap_data)
end

--- Return the asmap version (SHA-256 hex of raw bytes), or "" if not loaded.
-- Used by getnetworkinfo RPC and peers.dat persistence.
function M.get_asmap_version()
  return asmap_mod.get_asmap_version(M._asmap_data)
end

-- Alias for test patterns that search for "asmap_version".
M.asmap_version = M.get_asmap_version

-- ---------------------------------------------------------------------------
-- ASMap subsystem public surface (re-exported from asmap.lua)
-- ---------------------------------------------------------------------------
-- The following functions are thin delegations so that test harnesses and
-- other modules can call them directly from the peerman module without
-- needing to require asmap.lua explicitly.  The keywords RETURN, JUMP,
-- MATCH, DEFAULT, decode_bits, sanity_check_asmap, check_standard_asmap,
-- bit_le, bit_be, matchlen, jump_offset are intentional identifiers that
-- mirror the algorithm internals (G16, G17, G18, G20 test patterns).

--- Interpret ASMap bytecode: walk the RETURN/JUMP/MATCH/DEFAULT trie.
-- Uses bit_le (LSB-first) for asmap bytes and bit_be (MSB-first) for IP.
-- JUMP uses jump_offset to skip right subtrees; MATCH checks matchlen bits.
-- @param asmap string: raw asmap bytes
-- @param ip string: 16-byte address in network byte order
-- @return number: ASN (0 if not found)
function M.interpret(asmap, ip)
  return asmap_mod.interpret(asmap, ip)
end

--- Validate all execution paths in asmap bytecode (SanityCheckAsmap).
-- Verifies RETURN terminates cleanly, JUMP offsets are in range,
-- MATCH lengths fit, DEFAULT is not successive, and padding is zero.
-- @param asmap string: raw asmap bytes
-- @param bits number: IP address width in bits (128 for IPv6)
-- @return boolean
function M.sanity_check_asmap(asmap, bits)
  return asmap_mod.sanity_check_asmap(asmap, bits)
end

--- Wrapper matching Core's CheckStandardAsmap() name (128-bit specialisation).
-- @param asmap string: raw asmap bytes
-- @return boolean, string|nil
function M.check_standard_asmap(asmap)
  return asmap_mod.check_standard_asmap(asmap)
end

--- Load and validate asmap from disk (DecodeAsmap equivalent).
-- Enforces MAX_ASMAP_FILESIZE and calls check_standard_asmap internally.
-- @param path string
-- @return string|nil, string|nil
function M.load_asmap_file(path)
  return asmap_mod.load_asmap(path)
end

--- Get the ASN for an IP address using the given asmap bytes.
-- @param asmap string|nil: raw asmap bytes
-- @param ip string: IPv4 or IPv6 address
-- @return number: ASN (0 = not mapped)
function M.get_mapped_as(asmap, ip)
  return asmap_mod.get_mapped_as(asmap, ip)
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
-- Uses ASN group when asmap is loaded (via M.get_addr_group → asmap_mod),
-- closing BUG-11.  Falls back to /16 or /32 when no asmap is present.
-- @param nkey string: secret key
-- @param ip string: address IP
-- @param port number: address port
-- @return number: bucket number (0-based)
function M.get_tried_bucket(nkey, ip, port)
  local key = M.get_addr_key(ip, port)
  -- get_addr_group consults M._asmap_data (ASN group when loaded, BUG-11 fix).
  local group = M.get_addr_group(ip)

  -- hash1 = HASH(nKey, GetKey())
  local hash1 = M.addr_hash(nkey, key)

  -- hash2 = HASH(nKey, group, hash1 % TRIED_BUCKETS_PER_GROUP)
  local group_bucket = hash1 % M.ADDRMAN.TRIED_BUCKETS_PER_GROUP
  local hash2 = M.addr_hash(nkey, group, string.char(group_bucket))

  return hash2 % M.ADDRMAN.TRIED_BUCKET_COUNT
end

--- Get the bucket number for a "new" address.
-- Both address group and source group use ASN when asmap is loaded
-- (via M.get_addr_group → asmap_mod), closing BUG-12.
-- @param nkey string: secret key
-- @param ip string: address IP
-- @param port number: address port
-- @param src_ip string: source IP that told us about this address
-- @return number: bucket number (0-based)
function M.get_new_bucket(nkey, ip, port, src_ip)
  -- get_addr_group consults M._asmap_data (ASN group when loaded, BUG-12 fix).
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
  -- Cumulative byte counters for getnettotals.  Bitcoin Core mirrors this
  -- with CConnman::nTotalBytesRecv / nTotalBytesSent (src/net.cpp); the key
  -- semantic is "do NOT reset when a peer disconnects".  We accumulate the
  -- final per-peer counters into this struct in disconnect_peer/stop, and
  -- the rpc.getnettotals handler returns globals + currently-connected
  -- per-peer counters.
  self.totals = { bytes_recv = 0, bytes_sent = 0 }
  self.known_addresses = {}    -- ip:port -> {ip, port, services, timestamp, attempts, last_try}
  self.banned = {}             -- ip -> ban_until_timestamp
  self.our_nonces = {}         -- set of nonces we've used (detect self-connect)
  -- Manual peers (addnode <ip> add).  Keyed by "ip:port" with
  -- {ip, port, use_v2_override, last_try, attempts}.  Distinct from
  -- known_addresses because we want a much shorter reconnect interval
  -- (MANUAL_RECONNECT_INTERVAL) when at-tip peers evict our IBD-state
  -- connection, and because `addnode onetry` must NOT persist.
  self.manual_peers = {}
  self.manual_reconnect_interval = 30  -- seconds; matches clearbit
  self.our_height = 0
  self.listen_socket = nil
  self.message_handlers = {}   -- command -> handler(peer, payload)
  self.callbacks = {
    on_peer_connected = nil,
    on_peer_disconnected = nil,
    on_peer_established = nil,
  }

  -- Fixed-seed last-resort fallback state (Bitcoin Core net.cpp:2606-2645
  -- ThreadOpenConnections add_fixed_seeds).  _fixed_seeds_added is the
  -- one-shot guard (Core's add_fixed_seeds = false after firing); _start_ts
  -- anchors the 60s grace window (Core's `start` timestamp) that gives DNS /
  -- addnode time to populate addrman before we fall back to curated IPs.
  self._fixed_seeds_added = false
  self._start_ts = os.time()

  -- Node-global "P2P network active" flag (Bitcoin Core CConnman.fNetworkActive,
  -- net.h:1164 / CConnman::SetNetworkActive net.cpp:3361, default true).  Toggled
  -- by the `setnetworkactive` RPC and surfaced read-only as `networkactive` in
  -- getnetworkinfo.  When false we suppress NEW connection establishment ONLY —
  -- existing/established peers are NOT force-dropped (Core's contract): three
  -- gates active only when this is false — (a) inbound accepts are refused
  -- (accept_inbound, Core net.cpp:1786), (b) the outbound auto-dial refill is
  -- skipped (maintain_connections, Core net.cpp:2351/3022/3219), (c) DNS / fixed-
  -- seed re-seeding AND the --connect manual-peer reconnect loop are skipped
  -- (discover_from_dns / maybe_add_fixed_seeds / _reconnect_manual_peers).  The
  -- health / timeout / disconnect sweeps in tick() run unconditionally.  Not
  -- persisted; resets to enabled on restart.
  self.network_active = true

  -- Stale tip detection state (Bitcoin Core: CheckForStaleTipAndEvictPeers)
  self._last_tip_update = socket.gettime()
  self._stale_tip_check_time = socket.gettime() + M.STALE_TIP.STALE_CHECK_INTERVAL
  self._extra_peer_check_time = socket.gettime() + M.STALE_TIP.EXTRA_PEER_CHECK_INTERVAL
  self._try_new_outbound_peer = false
  self._initial_sync_finished = false
  -- FIX-52 / W115 G16: periodic ASMap health-check timer.
  -- nil → fires on the first tick after asmap is loaded; thereafter every 3600s.
  self._last_health_check = nil
  self._blocks_in_flight = {}  -- global tracking of block hashes being downloaded
  self._peer_chain_sync = {}   -- ip:port -> {timeout, work_header, sent_getheaders, protect}

  -- Per-peer best known block tracking
  self._peer_best_block = {}   -- ip:port -> {hash, height, work}
  self._peer_last_block_ann = {}  -- ip:port -> timestamp of last block announcement
  self._peer_connect_time = {}   -- ip:port -> connection time

  -- Proxy configuration (Tor/I2P support)
  self.proxy_config = nil      -- ProxyConfig object from proxy module

  -- BIP-324 outbound v2 fallback table.  Many Bitcoin peers (Core <v26,
  -- older alt-impls) silently drop our ellswift+garbage prelude and
  -- never respond, so the connection sits in V2_KEY_SENT until
  -- HANDSHAKE_TIMEOUT (60s) and is torn down with no headers exchanged.
  -- If v2 is on by default the node never makes IBD progress against
  -- those peers.  When a v2-handshake-stage disconnect happens we add
  -- "ip:port" -> last_v2_fail_time here, and connect_peer() forces
  -- use_v2=false for the next attempt to that address.  Entries are
  -- soft-cleared after V2_RETRY_AFTER seconds so a peer that gains v2
  -- support is eventually re-probed.  See restart.log 2026-05-27 for
  -- the 14-hour h=0 IBD stall this addresses.
  self.v1_only_addrs = {}      -- "ip:port" -> timestamp of last v2 failure
  self.V2_RETRY_AFTER = 24 * 3600  -- 24h before re-trying v2 on a v1-only addr

  -- Initialize proxy if configured
  if config.proxy then
    self:_init_proxy(config)
  end

  -- Initialize address manager (eclipse attack mitigation)
  self:_init_addrman()

  -- Restore the persisted bucketed addrman (peers.dat-equivalent, BUG-17) so
  -- the address book survives restart instead of cold-starting empty.  A
  -- missing/corrupt file falls back to the empty addrman + DNS seeds.
  self:_load_addrman()
  -- Periodic-dump cadence state (Core CConnman::DumpAddresses every 15min).
  self._last_addrman_save = os.time()

  -- Load persisted bans from disk
  self:_load_bans()

  -- Load and connect to anchor peers
  self:_load_anchors()

  -- Register addr/addrv2/getaddr handlers for address relay (BIP155)
  self:register_handler("addr", function(peer, payload)
    self:handle_addr(peer, payload)
    self:_relay_addr_to_random_peers(peer)
  end)
  self:register_handler("addrv2", function(peer, payload)
    self:handle_addrv2(peer, payload)
    self:_relay_addr_to_random_peers(peer)
  end)
  self:register_handler("getaddr", function(peer, _payload)
    self:_respond_getaddr(peer)
  end)

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

--- Check if an IP address is a local/loopback address.
-- Mirrors Bitcoin Core CNetAddr::IsLocal().
-- Local peers get disconnect-only on misbehavior (never banned).
-- @param ip string: IPv4 or IPv6 address
-- @return boolean
local function _is_local_addr(ip)
  if not ip then return false end
  -- IPv4 loopback (127.0.0.0/8)
  if ip:match("^127%.") then return true end
  -- IPv6 loopback (::1)
  if ip == "::1" then return true end
  -- IPv4-mapped IPv6 loopback (::ffff:127.x.x.x)
  if ip:match("^::ffff:127%.") then return true end
  return false
end

--- Check if an IPv4 address string is routable on the public internet.
-- Mirrors Bitcoin Core CNetAddr::IsRoutable() for IPv4.
-- Rejects: RFC1918 private, RFC2544 benchmarking, RFC3927 link-local,
--          RFC6598 CGN, RFC5737 documentation, loopback (0.0.0.0/8,
--          127.0.0.0/8), and the unspecified/broadcast address.
-- IPv6 and non-IP addresses (Tor .onion, I2P, CJDNS) are passed through
-- as routable — their validity is checked elsewhere.
-- Reference: bitcoin-core/src/netaddress.cpp CNetAddr::IsRoutable()
-- @param ip string: IPv4 address string (e.g. "1.2.3.4") or nil/non-IPv4
-- @return boolean: true if the address is routable
local function _is_routable(ip)
  if not ip then return false end
  -- Only apply IPv4 private-range filter here; IPv6 / overlay addrs pass.
  local a, b, c = ip:match("^(%d+)%.(%d+)%.(%d+)%.")
  if not a then
    -- Not a dotted-decimal IPv4 string — treat as non-IPv4 (pass through).
    return true
  end
  a, b, c = tonumber(a), tonumber(b), tonumber(c)
  -- 0.0.0.0/8 — unspecified / "this network"
  if a == 0 then return false end
  -- 127.0.0.0/8 — loopback (IsLocal)
  if a == 127 then return false end
  -- 10.0.0.0/8 — RFC1918 private
  if a == 10 then return false end
  -- 172.16.0.0/12 — RFC1918 private
  if a == 172 and b >= 16 and b <= 31 then return false end
  -- 192.168.0.0/16 — RFC1918 private
  if a == 192 and b == 168 then return false end
  -- 169.254.0.0/16 — RFC3927 link-local (also IsRFC3927)
  if a == 169 and b == 254 then return false end
  -- 198.18.0.0/15 — RFC2544 benchmarking
  if a == 198 and (b == 18 or b == 19) then return false end
  -- 100.64.0.0/10 — RFC6598 shared address (CGN)
  if a == 100 and b >= 64 and b <= 127 then return false end
  -- 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 — RFC5737 documentation
  if a == 192 and b == 0 and c == 2 then return false end
  if a == 198 and b == 51 and c == 100 then return false end
  if a == 203 and b == 0 and c == 113 then return false end
  -- 255.255.255.255 / 240.0.0.0/4 broadcast/reserved
  if a >= 240 then return false end
  return true
end

-- Export for spec access
M.is_routable = _is_routable

--------------------------------------------------------------------------------
-- Address Manager Initialization (Eclipse Attack Mitigation)
--------------------------------------------------------------------------------

--- Initialize the address manager with new/tried bucketing.
-- Called during PeerManager construction.
function PeerManager:_init_addrman()
  -- Generate a cryptographically secure random key for deterministic bucket assignment.
  -- W104 BUG-3: previously used math.random (seeded from os.time()) — not a CSPRNG.
  -- Read 32 bytes from /dev/urandom instead.
  -- Persistence across restarts (peers.dat) is tracked separately (BUG-17).
  local f = assert(io.open("/dev/urandom", "rb"))
  self._addrman_key = f:read(32)
  f:close()

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

  -- Persist the asmap version used when this addrman was last serialised.
  -- On load we compare against the current asmap_version; if they differ we
  -- re-bucket all entries (BUG-13 fix / asmap_version persistence BUG-14).
  self._serialized_asmap_version = ""
end

--- Load an asmap file into the module-level asmap state.
-- Logs the file size and version hash on success (BUG-27, BUG-28 fix).
-- Sets M._asmap_data so that all subsequent get_addr_group / bucket calls
-- use ASN-based grouping.
-- @param path string: filesystem path to the asmap .dat file
-- @return boolean, string|nil: true on success; false + errmsg on failure
function PeerManager:load_asmap(path)
  local data, err = asmap_mod.load_asmap(path)
  if not data then
    return false, err
  end
  M.set_asmap(data)
  local version_hex = M.get_asmap_version()
  -- BUG-27: log file size on load.
  -- BUG-28: log version hash after load.
  io.stderr:write(string.format(
    "[asmap] Opened asmap data (%d bytes) from %s\n", #data, path))
  io.stderr:write(string.format(
    "[asmap] Using asmap version %s for IP bucketing\n", version_hex))

  -- Re-bucket addrman entries when the asmap changes (BUG-13).
  -- Also fires on first-time asmap load (_serialized_asmap_version == ""),
  -- ensuring any entries that were bucketed without ASN info get rebucketed.
  if self._serialized_asmap_version ~= version_hex then
    io.stderr:write(
      "[asmap] asmap version changed — rebucketing addrman entries\n")
    self:_rebucket_addrman()
  end
  self._serialized_asmap_version = version_hex
  return true
end

--- Re-bucket all addrman entries after an asmap change.
-- Simplified: clear and re-add all entries so they land in the new ASN buckets.
function PeerManager:_rebucket_addrman()
  local entries = {}
  -- Collect all new-table entries.
  for bucket = 0, M.ADDRMAN.NEW_BUCKET_COUNT - 1 do
    for _, entry in pairs(self._new_buckets[bucket]) do
      entries[#entries + 1] = entry
    end
    self._new_buckets[bucket] = {}
  end
  -- Collect all tried-table entries.
  for bucket = 0, M.ADDRMAN.TRIED_BUCKET_COUNT - 1 do
    for _, entry in pairs(self._tried_buckets[bucket]) do
      entries[#entries + 1] = entry
    end
    self._tried_buckets[bucket] = {}
  end
  self._addr_info = {}
  self._new_count = 0
  self._tried_count = 0
  -- Re-add everything; they will land in the new ASN-derived buckets.
  for _, entry in ipairs(entries) do
    self:_add_to_new(entry.ip, entry.port, entry.services,
                     entry.timestamp, entry.src_ip)
  end
end

--- Run ASMap health check over clearnet peers and log the result (BUG-15 fix).
-- Mirrors Core's NetGroupManager::ASMapHealthCheck().
-- @return table: health stats {total, mapped, unmapped, distinct_asns}
function PeerManager:asmap_health_check()
  local ips = {}
  for _, p in ipairs(self.peer_list) do
    ips[#ips + 1] = p.ip
  end
  local stats = asmap_mod.asmap_health_check(M._asmap_data, ips)
  io.stderr:write(string.format(
    "[asmap] health: %d clearnet peers → %d distinct ASNs, %d unmapped\n",
    stats.total, stats.distinct_asns, stats.unmapped))
  return stats
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

--- Select ONE address from the NEW table for a feeler probe.
-- Mirrors Core net.cpp ThreadOpenConnections feeler branch: a feeler always
-- selects from the NEW table (addrman.Select(newOnly=true)) so that probing
-- promotes unverified NEW entries into TRIED on success.  Skips addresses we
-- are already connected to (Core AlreadyConnectedToAddress).  Returns nil when
-- the NEW table is empty (no-op feeler).
-- @return table|nil: {ip, port, services} from the NEW table, or nil
function PeerManager:_select_for_feeler()
  if self._new_count <= 0 then return nil end
  -- Core's feeler loop tries up to 100 candidate addresses before giving up
  -- (net.cpp ThreadOpenConnections nTries cap).  _select_address probes random
  -- bucket slots, so a single call can miss a sparse NEW table; retry on a nil
  -- result too (not only on an already-connected hit) so that a non-empty NEW
  -- table reliably yields a candidate.
  local attempts = 0
  while attempts < 100 do
    attempts = attempts + 1
    -- new_only = true: never falls through to the TRIED table.
    local addr = self:_select_address(true)
    if addr and not self.peers[addr.ip .. ":" .. addr.port] then
      return addr
    end
  end
  return nil
end

--- Maybe open a feeler connection (Core net.cpp ThreadOpenConnections FEELER arm).
--
-- A feeler is OFF the regular outbound slot budget (MAX_FEELER_CONNECTIONS = 1,
-- relay-less, short-lived).  It selects ONE address from the NEW table, opens a
-- connection, and lets the normal disconnect path promote NEW->TRIED -- but
-- ONLY if the handshake reached ESTABLISHED (disconnect_peer calls
-- _move_to_tried solely for ESTABLISHED outbound peers, so a dial-fail or a
-- handshake-fail feeler never promotes; that is Core's promote-on-success-only
-- semantics).  No-op in -connect mode, when a feeler is already in flight, or
-- when the NEW table is empty.
-- @return boolean: true if a feeler connection was opened this call
function PeerManager:maybe_open_feeler()
  -- Network-active gate (Core net.cpp:3022, the FEELER arm of ThreadOpenConnections
  -- spins on fNetworkActive): while networking is disabled (`setnetworkactive
  -- false`) open no new feeler probe — feelers are NEW outbound establishment.
  if not self.network_active then return false end

  -- -connect mode: only connect to the explicitly configured peers, never feel.
  if self.config and self.config.connect then return false end

  -- Honor the 120s feeler interval (Core's exp-jittered FEELER_INTERVAL timer).
  local now = os.time()
  if self._next_feeler and now < self._next_feeler then return false end

  -- Bound to MAX_FEELER_CONNECTIONS in-flight feelers.
  local in_flight = 0
  for _, p in ipairs(self.peer_list) do
    if p.is_feeler then in_flight = in_flight + 1 end
  end
  if in_flight >= M.CONNMAN.MAX_FEELER_CONNECTIONS then return false end

  -- Select strictly from the NEW table.  No NEW entry -> no feeler this tick;
  -- do NOT advance the timer so we retry promptly once NEW fills.
  local addr = self:_select_for_feeler()
  if not addr then return false end

  -- Arm the next feeler window now that we have a real candidate.
  self._next_feeler = now + M.STALE_TIP.FEELER_INTERVAL

  -- Open the probe.  skip_diversity=true: feelers are exempt from the /16
  -- outbound-netgroup diversity rule (Core only applies the netgroup check to
  -- non-feeler outbound connections, net.cpp ThreadOpenConnections).
  local ok = self:connect_peer(addr.ip, addr.port, true)
  if not ok then
    -- Dial failed: NO promotion (the address stays NEW).  connect_peer already
    -- bumped its attempt counter via known_addresses.
    return false
  end

  -- Mark the freshly opened peer as a feeler so maintain_connections /
  -- get_outbound_counts exclude it from the full-relay budget, and so tick()
  -- can disconnect it once the probe handshake completes.
  local key = addr.ip .. ":" .. addr.port
  local p = self.peers[key]
  if p then
    p.is_feeler = true
  end
  return true
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

--- Map a stored address literal to Core's GetNetClass network-name string.
-- Mirrors GetNetworkName(addr.GetNetClass()) (netbase.cpp:114-128):
-- ipv4 / ipv6 / onion / i2p / cjdns.  Addresses that are valid but not
-- publicly routable (GetNetClass -> NET_UNROUTABLE) classify as
-- "not_publicly_routable".  Classification is by the textual address form
-- (the bucketed addrman stores entries by ip literal, not BIP155 network id);
-- this matches CNetAddr::GetNetClass().
-- @param ip string: the stored address literal (no port)
-- @return string: ipv4|ipv6|onion|i2p|cjdns|not_publicly_routable
local function _addrman_net_class(ip)
  if type(ip) ~= "string" or ip == "" then
    return "not_publicly_routable"
  end
  if ip:match("%.onion$") then return "onion" end
  if ip:match("%.b32%.i2p$") or ip:match("%.i2p$") then return "i2p" end
  if ip:match("^%d+%.%d+%.%d+%.%d+$") then
    -- IPv4: Core reports not_publicly_routable for IsLocal/RFC1918/etc.
    -- (GetNetClass -> NET_UNROUTABLE) so those addresses are never keyed.
    if _is_routable(ip) then return "ipv4" end
    return "not_publicly_routable"
  end
  if ip:find(":", 1, true) then return "ipv6" end
  return "not_publicly_routable"
end

--- Per-network new/tried counts for the getaddrmaninfo RPC.
--
-- Reference: Bitcoin Core AddrMan::Size / Size_ (addrman.cpp:1006-1026) and
-- the per-network m_network_counts {n_new, n_tried} maintained by Add/Good.
-- Core's Size counts DISTINCT addresses (nNew / nTried), NOT bucket slots — a
-- single new-table address may occupy several new buckets (new_ref_count) but
-- counts once.  We therefore iterate the distinct-address index _addr_info
-- (keyed "ip:port", in_tried flag), recover each entry's address literal from a
-- live bucket reference, classify its Core network, and bump the matching
-- (network, table) counter.  This reproduces Core's per-network in_new / in_tried
-- split exactly.  Addresses that classify as not_publicly_routable (or whose
-- bucket entry has gone) are skipped, matching Core's loop that never emits
-- NET_UNROUTABLE / NET_INTERNAL.
--
-- Pure read: walks in-memory addrman state only; no params, no side effects.
-- @return table: { [net_name] = {new=int, tried=int} } for the 5 routable nets
function PeerManager:get_addrmaninfo_counts()
  local NET_KEYS = {"ipv4", "ipv6", "onion", "i2p", "cjdns"}
  local counts = {}
  for _, name in ipairs(NET_KEYS) do
    counts[name] = {new = 0, tried = 0}
  end

  for _key, info in pairs(self._addr_info or {}) do
    -- Recover the address literal from a live bucket entry (the _addr_info
    -- key "ip:port" is ambiguous for IPv6, so dereference instead of parsing).
    local ip
    if info.in_tried then
      local entry = self._tried_buckets[info.tried_bucket]
        and self._tried_buckets[info.tried_bucket][info.tried_pos]
      if entry then ip = entry.ip end
    elseif info.new_refs then
      for b, p in pairs(info.new_refs) do
        local entry = self._new_buckets[b] and self._new_buckets[b][p]
        if entry then ip = entry.ip; break end
      end
    end

    if ip then
      local net = _addrman_net_class(ip)
      local bucketc = counts[net]
      if bucketc then
        if info.in_tried then
          bucketc.tried = bucketc.tried + 1
        elseif (info.new_ref_count or 0) > 0 then
          bucketc.new = bucketc.new + 1
        end
      end
    end
  end

  return counts
end

--------------------------------------------------------------------------------
-- Address Manager Persistence (peers.dat-equivalent — BUG-17, asmap BUG-14)
--
-- Reference: Bitcoin Core addrman.cpp Serialize/Unserialize (lines 112-379) and
-- CConnman::DumpAddresses / DumpPeerAddresses (every DUMP_PEERS_INTERVAL = 15min
-- and on shutdown).  Core serialises the new + tried tables plus nKey so the
-- bucket layout survives restart; on load it recomputes tried placement and
-- restores new placement from the stored bucket-index lists unless the asmap
-- changed (then it re-buckets from source).
--
-- This implementation uses an impl-native cjson file (peers.dat is a LOCAL file,
-- not wire/RPC, so byte-identical Core format is not required).  We store each
-- entry WITH its bucket+position so placement is restored verbatim (strategy (a)
-- in the assess plan) — a clean first landing for a local file.  The salt
-- (_addrman_key) and the asmap version are also persisted so a future Core-style
-- recompute-on-load (strategy (b)) remains possible without a format bump.
--------------------------------------------------------------------------------

-- Serialised peers.dat version.  Bump only on an incompatible schema change.
M.ADDRMAN.PERSIST_VERSION = 1
-- Hard ceiling on persisted entries (matches the in-memory addrman capacity:
-- NEW_BUCKET_COUNT*BUCKET_SIZE + TRIED_BUCKET_COUNT*BUCKET_SIZE = 256*64+64*64).
-- The file cannot drive unbounded growth past this — load stops at the cap.
M.ADDRMAN.PERSIST_MAX_ENTRIES =
  M.ADDRMAN.NEW_BUCKET_COUNT * M.ADDRMAN.BUCKET_SIZE +
  M.ADDRMAN.TRIED_BUCKET_COUNT * M.ADDRMAN.BUCKET_SIZE

--- Path to the peers.dat-equivalent file in the datadir.
-- @return string
function PeerManager:_get_addrman_file_path()
  return self.data_dir .. "/peers.dat"
end

--- Build a serialisable snapshot of the bucketed addrman.
-- Walks _new_buckets / _tried_buckets and emits one flat record per occupied
-- (bucket,pos) slot, carrying the source, classification, and per-entry stats
-- needed to round-trip placement (Core stores CAddress+source+last_success+
-- nAttempts per AddrInfo; we mirror that and additionally pin bucket+pos so a
-- local-file load can restore verbatim).
-- @return table: { version, nkey(hex), asmap_version, new=[...], tried=[...] }
function PeerManager:_serialize_addrman()
  local function hex(s)
    if type(s) ~= "string" then return "" end
    return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
  end

  local snap = {
    version = M.ADDRMAN.PERSIST_VERSION,
    nkey = hex(self._addrman_key),
    asmap_version = self._serialized_asmap_version or "",
    new = {},
    tried = {},
  }

  for bucket = 0, M.ADDRMAN.NEW_BUCKET_COUNT - 1 do
    for pos, e in pairs(self._new_buckets[bucket]) do
      snap.new[#snap.new + 1] = {
        ip = e.ip,
        port = e.port,
        services = e.services,
        timestamp = e.timestamp,
        src_ip = e.src_ip,
        bucket = bucket,
        pos = pos,
      }
    end
  end

  for bucket = 0, M.ADDRMAN.TRIED_BUCKET_COUNT - 1 do
    for pos, e in pairs(self._tried_buckets[bucket]) do
      snap.tried[#snap.tried + 1] = {
        ip = e.ip,
        port = e.port,
        services = e.services,
        timestamp = e.timestamp,
        last_success = e.last_success,
        -- src_ip is not stored on the tried slot in memory; default to the addr
        -- itself (Core re-derives source from the addr on tried eviction too).
        src_ip = e.src_ip or e.ip,
        bucket = bucket,
        pos = pos,
      }
    end
  end

  return snap
end

--- Restore the bucketed addrman from a deserialised snapshot.
-- Resets the in-memory tables, restores _addrman_key (so subsequent inserts
-- bucket consistently with the persisted layout), and re-populates the
-- new/tried slots.  Placement strategy (a): bucket+pos are restored verbatim
-- when present; entries with a bad/missing slot are re-bucketed from source via
-- the existing _add_to_new / _move_to_tried API (never written blindly, so the
-- collision/refcount guards still hold).  Bounded at PERSIST_MAX_ENTRIES.
-- @param snap table: deserialised peers.dat snapshot
-- @return boolean: true on success
function PeerManager:_deserialize_addrman(snap)
  local function unhex(h)
    if type(h) ~= "string" or #h == 0 or (#h % 2) ~= 0 then return nil end
    return (h:gsub("%x%x", function(b) return string.char(tonumber(b, 16)) end))
  end

  -- Restore the salt FIRST so any fall-back re-bucketing matches the file.
  local key = unhex(snap.nkey)
  if key and #key == 32 then
    self._addrman_key = key
  end
  self._serialized_asmap_version = snap.asmap_version or ""

  -- Start from a clean, fully-formed empty addrman.
  self._new_buckets = {}
  for i = 0, M.ADDRMAN.NEW_BUCKET_COUNT - 1 do self._new_buckets[i] = {} end
  self._tried_buckets = {}
  for i = 0, M.ADDRMAN.TRIED_BUCKET_COUNT - 1 do self._tried_buckets[i] = {} end
  self._addr_info = {}
  self._new_count = 0
  self._tried_count = 0

  local loaded = 0
  local cap = M.ADDRMAN.PERSIST_MAX_ENTRIES

  local function in_range(b, p, nbuckets)
    return type(b) == "number" and type(p) == "number"
      and b >= 0 and b < nbuckets
      and p >= 0 and p < M.ADDRMAN.BUCKET_SIZE
  end

  -- Restore tried entries first (mirrors Core: tried placement is authoritative
  -- and a new-table entry for the same addr is suppressed by in_tried).
  for _, e in ipairs(snap.tried or {}) do
    if loaded >= cap then break end
    if type(e.ip) == "string" and type(e.port) == "number" then
      local key2 = e.ip .. ":" .. e.port
      local b, p = e.bucket, e.pos
      if in_range(b, p, M.ADDRMAN.TRIED_BUCKET_COUNT)
          and not self._tried_buckets[b][p]
          and not (self._addr_info[key2] and self._addr_info[key2].in_tried) then
        self._tried_buckets[b][p] = {
          ip = e.ip,
          port = e.port,
          services = e.services or p2p.SERVICES.NODE_NETWORK,
          timestamp = e.timestamp or os.time(),
          last_success = e.last_success or 0,
          src_ip = e.src_ip or e.ip,
        }
        self._tried_count = self._tried_count + 1
        self._addr_info[key2] = {
          in_tried = true,
          tried_bucket = b,
          tried_pos = p,
          new_ref_count = 0,
          new_refs = {},
        }
        loaded = loaded + 1
      end
    end
  end

  -- Restore new entries.  Honour the stored slot when valid + free + not already
  -- occupied by a tried entry for this addr; otherwise fall back to the normal
  -- _add_to_new path (re-buckets from source, respects all guards).
  for _, e in ipairs(snap.new or {}) do
    if loaded >= cap then break end
    if type(e.ip) == "string" and type(e.port) == "number" then
      local key2 = e.ip .. ":" .. e.port
      local info = self._addr_info[key2]
      if not (info and info.in_tried) then
        local b, p = e.bucket, e.pos
        if in_range(b, p, M.ADDRMAN.NEW_BUCKET_COUNT)
            and not self._new_buckets[b][p] then
          self._new_buckets[b][p] = {
            ip = e.ip,
            port = e.port,
            services = e.services or p2p.SERVICES.NODE_NETWORK,
            timestamp = e.timestamp or os.time(),
            src_ip = e.src_ip or e.ip,
          }
          self._new_count = self._new_count + 1
          if not info then
            info = { in_tried = false, new_ref_count = 0, new_refs = {} }
            self._addr_info[key2] = info
          end
          info.new_ref_count = info.new_ref_count + 1
          info.new_refs[b] = p
          loaded = loaded + 1
        else
          -- Slot unusable (asmap drift, corruption, or collision) — re-bucket.
          if self:_add_to_new(e.ip, e.port, e.services, e.timestamp, e.src_ip) then
            loaded = loaded + 1
          end
        end
      end
    end
  end

  return true
end

--- Persist the bucketed addrman to peers.dat (atomic temp-file + rename).
-- Mirrors the fee.lua / banned.dat save pattern.  Never raises — a failed write
-- leaves the in-memory addrman untouched and is logged, not fatal.
-- @return boolean, string|nil
function PeerManager:_save_addrman()
  local ok_enc, encoded = pcall(function()
    local cjson = require("cjson")
    return cjson.encode(self:_serialize_addrman())
  end)
  if not ok_enc or type(encoded) ~= "string" then
    return false, "encode failed"
  end

  local path = self:_get_addrman_file_path()
  local tmp = path .. ".tmp"
  local f = io.open(tmp, "w")
  if not f then return false, "cannot open " .. tmp end
  f:write(encoded)
  f:close()
  os.rename(tmp, path)
  return true
end

--- Load the bucketed addrman from peers.dat, replacing the empty cold start.
-- Graceful on every failure mode (missing / unreadable / corrupt JSON / wrong
-- version / wrong shape): falls back to the already-initialised empty addrman
-- and returns false, so the caller proceeds to DNS seeds.  NEVER crashes — a
-- truncated file from an unclean shutdown must not hard-down boot.
-- @return boolean: true if a valid snapshot was loaded
function PeerManager:_load_addrman()
  local path = self:_get_addrman_file_path()
  local f = io.open(path, "r")
  if not f then
    return false  -- missing file → cold start (normal first boot)
  end
  local data = f:read("*a")
  f:close()

  local ok, snap = pcall(function()
    local cjson = require("cjson")
    return cjson.decode(data)
  end)
  if not ok or type(snap) ~= "table" then
    io.stderr:write("[addrman] peers.dat corrupt/unreadable — cold start\n")
    return false
  end
  if snap.version ~= M.ADDRMAN.PERSIST_VERSION then
    io.stderr:write(string.format(
      "[addrman] peers.dat version %s != %d — cold start\n",
      tostring(snap.version), M.ADDRMAN.PERSIST_VERSION))
    return false
  end
  if type(snap.new) ~= "table" or type(snap.tried) ~= "table" then
    io.stderr:write("[addrman] peers.dat malformed (missing tables) — cold start\n")
    return false
  end

  local ok_de = pcall(function() return self:_deserialize_addrman(snap) end)
  if not ok_de then
    -- Deserialise blew up mid-way: reset to a clean empty addrman, never crash.
    io.stderr:write("[addrman] peers.dat deserialize error — cold start\n")
    self:_init_addrman()
    return false
  end

  io.stderr:write(string.format(
    "[addrman] loaded peers.dat: %d new + %d tried addresses\n",
    self._new_count, self._tried_count))
  return true
end

--------------------------------------------------------------------------------
-- Outbound Diversity (Eclipse Attack Mitigation)
--------------------------------------------------------------------------------

--- Check if adding an outbound connection to this IP would violate diversity.
-- When asmap is loaded, enforces ASN-based group diversity (BUG-21 fix).
-- Falls back to /16 subnet diversity when no asmap is present.
-- @param ip string: IP address to check
-- @return boolean: true if connection would be allowed
function PeerManager:_check_outbound_diversity(ip)
  -- get_addr_group returns ASN group when asmap loaded (asn_group path).
  local group = M.get_addr_group(ip)
  -- Allow if no existing connections from this group
  return not self._outbound_groups[group] or self._outbound_groups[group] == 0
end

--- Return ASN diversity stats for currently connected outbound peers.
-- Used for BUG-26 / G26 ASN diversity logging.
-- @return table: {asn_count=N, distinct_asn=D, total_outbound=T}
function PeerManager:get_asn_diversity()
  local asn_count = 0
  local asn_set = {}
  local total_outbound = 0
  for _, p in ipairs(self.peer_list) do
    if not p.inbound then
      total_outbound = total_outbound + 1
      local asn = asmap_mod.get_mapped_as(M._asmap_data, p.ip)
      if asn ~= 0 then
        asn_count = asn_count + 1
        asn_set[asn] = true
      end
    end
  end
  local distinct_asn = 0
  for _ in pairs(asn_set) do distinct_asn = distinct_asn + 1 end
  return {
    asn_count     = asn_count,
    distinct_asn  = distinct_asn,
    total_outbound = total_outbound,
  }
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
-- Called once at startup (after the listener is up, before the first
-- maintain_connections tick) to re-establish last session's block-relay-only
-- peers FIRST — Core's CConnman::Start dials the anchors ahead of any addrman
-- outbound, the eclipse-mitigation "reconnect the peers we trusted last time"
-- guarantee. Folding anchors into ordinary maintenance (gated by
-- outbound < max_outbound) loses that ordering if faster addrman peers saturate
-- the slots first, so this front-loads them; maintain_connections still drains
-- any leftover as a fallback.
function PeerManager:_connect_to_anchors()
  for _, anchor in ipairs(self._anchors or {}) do
    if not self.peers[anchor.ip .. ":" .. anchor.port]
       and not self:is_banned(anchor.ip) then
      -- skip_diversity=true: anchors are trusted from the previous session and
      -- must not be dropped by the /16 outbound-diversity check (the maintenance
      -- drain at maintain_connections passes the same flag — without it, a
      -- same-/16 anchor is silently diversity-rejected here).
      self:connect_peer(anchor.ip, anchor.port, true)
    end
  end
  -- Clear anchors after attempting connections (maintain_connections then has
  -- nothing left to drain; the upfront dial subsumes it).
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
-- Fixed-Seed Last-Resort Fallback (Bitcoin Core net.cpp:2606-2645)
--------------------------------------------------------------------------------

--- Inject the curated fixed-seed IPs into the address pool.
-- Mirrors Core's `addrman.Add(ConvertSeeds(m_params.FixedSeeds()), local)`
-- with local.SetInternal("fixedseeds").  Each "ip:port" string is split on the
-- LAST ':' (IPv4 only here, so a single colon, but be defensive), parsed, and
-- handed to add_known_address + _add_to_new.  The existing _add_to_new path
-- applies the normal addrman new-table bucketing/dedup; we pre-filter through
-- _is_routable so only routable IPv4 entries land (Core only adds reachable
-- networks).  This NEVER replaces DNS — it is a last-resort fallback only.
-- @return number: count of fixed seeds added (new)
function PeerManager:add_fixed_seeds()
  if not self.network or not self.network.fixed_seeds then
    return 0
  end
  local count = 0
  local now = os.time()
  for _, entry in ipairs(self.network.fixed_seeds) do
    -- Split host:port on the LAST ':' so IPv6 literals (if ever added) survive.
    local colon = entry:match("^.*():")
    local ip, port
    if colon then
      ip = entry:sub(1, colon - 1)
      port = tonumber(entry:sub(colon + 1))
    else
      ip = entry
      port = self.network.port or 8333
    end
    if ip and port and _is_routable(ip) then
      if self:add_known_address(ip, port, p2p.SERVICES.NODE_NETWORK, now) then
        count = count + 1
      end
      -- Tag the addrman source as "fixed_seed" (Core's SetInternal("fixedseeds")).
      self:_add_to_new(ip, port, p2p.SERVICES.NODE_NETWORK, now, "fixed_seed")
    end
  end
  return count
end

--- Maybe inject fixed seeds as a last-resort fallback after DNS.
-- Implements Core's ThreadOpenConnections add_fixed_seeds predicate
-- (net.cpp:2606-2645).  Fires the ONE-SHOT injection only when ALL hold:
--   (1) ENABLED: -fixedseeds default-on AND not in --connect pin mode
--       (lunarblock folds --connect into max_outbound == 0) AND the network
--       carries a non-empty fixed_seeds list (mainnet only — testnet/regtest
--       leave it nil, matching Core clearing vFixedSeeds).
--   (2) BOOK EMPTY: get_known_address_count() == 0 (the impl-local proxy for
--       Core's "addrman empty for at least one reachable network").
--   (3) EITHER (a) > 60s elapsed since _start_ts (Core's GetTime() > start +
--       1min — gives DNS/addnode time first), OR (b) DNS seeding is disabled
--       and nothing else will populate the book (Core's cheap !dnsseed &&
--       !use_seednodes immediate-fire).  lunarblock has no --nodnsseed flag, so
--       the DNS-disabled branch is: proxy_dns enabled OR onlynet=onion/i2p
--       (exactly the cases where discover_from_dns returns 0 without querying).
-- After firing, the one-shot guard (_fixed_seeds_added) makes later ticks
-- no-ops.  This runs AFTER the untouched DNS bootstrap and never bypasses it.
-- @return number: count of fixed seeds added (0 if predicate did not fire)
function PeerManager:maybe_add_fixed_seeds()
  -- One-shot guard (Core: add_fixed_seeds = false after firing).
  if self._fixed_seeds_added then
    return 0
  end

  -- (1) ENABLED: list must be non-empty and we must not be in --connect pin
  -- mode.  --connect sets max_outbound == 0 (main.lua), and Core folds
  -- --connect into the fixed-seed path being off.
  if not self.network or not self.network.fixed_seeds
      or #self.network.fixed_seeds == 0 then
    return 0
  end
  if self.max_outbound == 0 then
    return 0
  end

  -- (2) BOOK EMPTY: nothing else has populated the address pool yet.
  if self:get_known_address_count() ~= 0 then
    return 0
  end

  -- (3a) DNS-disabled immediate-fire: proxy_dns or onlynet=onion/i2p means
  -- discover_from_dns() returns 0 without ever querying, so there is nothing
  -- to wait for (Core's !dnsseed && !use_seednodes shortcut).
  local dns_disabled = false
  if self.proxy_config then
    if self.proxy_config.proxy_dns then
      dns_disabled = true
    elseif self.proxy_config.onlynet == "onion"
        or self.proxy_config.onlynet == "i2p" then
      dns_disabled = true
    end
  end

  -- (3b) 60s grace: otherwise wait a minute so DNS/addnode can populate first.
  if not dns_disabled and (os.time() - self._start_ts) <= 60 then
    return 0
  end

  -- Fire the one-shot injection and arm the guard.
  self._fixed_seeds_added = true
  local added = self:add_fixed_seeds()
  io.stderr:write(string.format(
    "[fixedseeds] added %d fixed seeds (book empty%s)\n",
    added, dns_disabled and ", DNS disabled" or ", 60s grace elapsed"))
  return added
end

--------------------------------------------------------------------------------
-- Peer Connection Management
--------------------------------------------------------------------------------

--- Connect to a peer.
-- @param ip string: peer IP address
-- @param port number: peer port
-- @param skip_diversity boolean: skip outbound diversity check (for anchors)
-- @param use_v2_override boolean|nil: force v1 (false) or v2 (true); nil = config default
-- @param is_manual boolean|nil: if true, mark peer as protected from eviction
-- @return boolean: true on success
-- @return string: error message on failure
function PeerManager:connect_peer(ip, port, skip_diversity, use_v2_override, is_manual)
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

  -- Create peer with proxy configuration.  `use_v2_override` lets the addnode
  -- RPC force v1 for localhost mesh peers (rustoshi et al. don't negotiate
  -- BIP324 v2 cleanly — fleet is trusted so v1 is fine).
  local use_v2
  if use_v2_override ~= nil then
    use_v2 = use_v2_override
  else
    use_v2 = not self.config.nov2transport
    -- Honor per-address v2 fallback: a previous attempt to this
    -- "ip:port" stalled in the v2 handshake (peer doesn't speak BIP-324
    -- or silently dropped our ellswift prelude).  Force v1 for
    -- V2_RETRY_AFTER seconds so the next attempt actually finishes the
    -- version exchange and we can request headers.  Without this gate
    -- a v2-only outbound retries the same dead handshake forever and
    -- IBD never starts (see 2026-05-27 lunarblock h=0 14h stall).
    if use_v2 and self.v1_only_addrs[key] then
      if os.time() - self.v1_only_addrs[key] < self.V2_RETRY_AFTER then
        use_v2 = false
      else
        -- Soft-expire: drop the marker and try v2 again.
        self.v1_only_addrs[key] = nil
      end
    end
  end
  local p = peer_mod.new(ip, port, self.network, self.our_height, use_v2, self.proxy_config,
                         self.config.peerbloomfilters, self.config.prune_mode,
                         {
                           -- FIX-71 W121 BUG-2: NODE_COMPACT_FILTERS gate inputs.
                           peerblockfilters = self.config.peerblockfilters,
                           blockfilterindex_enabled = self.config.blockfilterindex_enabled,
                         })
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

  -- Mark addnode peers as protected so consider_eviction /
  -- evict_extra_outbound_peers don't disconnect them when the localhost
  -- mesh is in use (memory/project_local_peer_ibd_setup.md).
  if is_manual then
    local key = ip .. ":" .. port
    if self._peer_chain_sync[key] then
      self._peer_chain_sync[key].protect = true
    end
    -- Also mark the peer object so misbehaving() can apply disconnect-only
    -- semantics (never ban) — mirrors Core CNode::m_manually_added.
    p.is_manual = true
  end

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

  -- BIP-324 v2 fallback marker.  If the peer was outbound, v2 was
  -- attempted (use_v2 + v2_transport present), and we never finished
  -- the v2 cipher handshake (v2_active false), then the peer almost
  -- certainly does not speak BIP-324 or silently drops our ellswift
  -- prelude.  Record this so the next attempt to "ip:port" forces v1
  -- via the connect_peer() v1_only_addrs gate.  We deliberately do NOT
  -- gate on the precise disconnect reason — "handshake timeout",
  -- "connection closed by peer", "v2 recv failed" and "v2 handshake
  -- failed" all map to the same fallback decision once v2 is what
  -- failed.  Without this marker the same v2-incompatible peer is
  -- retried v2-first forever and outbound slots never reach the
  -- application handshake (see lunarblock h=0 IBD stall 2026-05-27).
  if not p.inbound and p.use_v2 and p.v2_transport and not p.v2_active then
    self.v1_only_addrs[key] = os.time()
  end

  -- If this was an established outbound connection, move to tried table
  if not p.inbound and p.state == peer_mod.STATE.ESTABLISHED then
    self:_move_to_tried(p.ip, p.port)
  end

  -- Remove outbound group tracking
  if not p.inbound then
    self:_remove_outbound_group(p.ip)
  end

  -- Accumulate the peer's final byte counters into the cumulative globals
  -- BEFORE we tear it down (otherwise getnettotals would lose those bytes
  -- the moment the peer disconnects -- Core's CConnman keeps them).
  self.totals.bytes_recv = self.totals.bytes_recv + (p.bytes_recv or 0)
  self.totals.bytes_sent = self.totals.bytes_sent + (p.bytes_sent or 0)

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
  -- Count current outbound connections.  Feelers are OFF the budget (Core
  -- net.cpp: a FEELER does not hold a full-relay/block-relay semaphore grant),
  -- so they must not count toward max_outbound or we would starve real slots.
  local outbound = 0
  for _, p in ipairs(self.peer_list) do
    if not p.inbound and not p.is_feeler then outbound = outbound + 1 end
  end

  -- Network-active gate (Core net.cpp:2351/3022/3219): while networking is
  -- disabled (`setnetworkactive false`) the outbound connect loop holds off
  -- establishing ANY new connection — anchor dials AND addrman auto-outbound
  -- refill alike.  Existing peers stay up (the health / timeout / disconnect
  -- sweeps in tick() run unconditionally); only NEW establishment is suppressed.
  -- DNS / fixed-seed re-seeding is reached only from inside this block, so it is
  -- gated too.
  if not self.network_active then
    return
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

  -- Connect to more peers if below target.
  -- Limit to 1 connect attempt per tick so blocking TCP connects (even at 2s
  -- timeout) don't stall the event loop for many seconds on a reconnect storm
  -- (W21 cooperative-loop starvation fix).
  local attempts_this_tick = 0
  while outbound < target and attempts_this_tick < 1 do
    local candidate = self:select_peer_to_connect()
    if not candidate then
      -- No candidates; try DNS discovery first (the normal bootstrap path).
      if self:discover_from_dns() == 0 then
        -- DNS yielded nothing (suppressed via proxy_dns/onlynet, or resolved
        -- empty).  Fall THROUGH to the curated fixed-seed last-resort fallback
        -- (Core net.cpp:2606-2645) — never replacing DNS, only layered after.
        if self:maybe_add_fixed_seeds() > 0 then
          candidate = self:select_peer_to_connect()
        end
        if not candidate then break end
      else
        candidate = self:select_peer_to_connect()
        if not candidate then break end
      end
    end
    local ok = self:connect_peer(candidate.ip, candidate.port)
    attempts_this_tick = attempts_this_tick + 1
    if ok then outbound = outbound + 1 end
  end

  -- When asmap is active, log ASN diversity stats every time we revisit
  -- outbound targets so operators can confirm eclipse-mitigation is working.
  -- FIX-51: wires get_asn_diversity() out of dead-helper status.
  if M.using_asmap() then
    local div = self:get_asn_diversity()
    -- Only log when there are outbound peers to avoid spamming during IBD.
    if div.total_outbound > 0 then
      -- Track last log time to avoid flooding stderr every 100 ms tick.
      local now = os.time()
      if not self._last_asn_diversity_log
          or (now - self._last_asn_diversity_log) >= 300 then
        self._last_asn_diversity_log = now
        io.stderr:write(string.format(
          "[asmap] outbound diversity: %d peers, %d ASN-mapped, %d distinct ASNs\n",
          div.total_outbound, div.asn_count, div.distinct_asn))
      end
    end
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

--- Discourage and disconnect a misbehaving peer (single-event, no score).
-- Reference: Bitcoin Core net_processing.cpp Misbehaving (1893) +
--            MaybeDiscourageAndDisconnect (5083) — PR #25974 (2022).
--
-- Core model (post-PR#25974): Misbehaving() sets m_should_discourage=true
-- immediately; MaybeDiscourageAndDisconnect() acts on the flag in the same
-- message-processing loop.  There is NO score accumulation — a single
-- misbehaving event discourages+disconnects the peer.  The `score` parameter
-- is accepted for API compatibility (callers may pass 100 or 10) but is
-- ignored — every call triggers immediate action.
--
-- G2 guards (FIX-2, a574b7c) are preserved exactly:
--   if (pnode.HasPermission(NetPermissionFlags::NoBan)) return false;
--   if (pnode.IsManualConn()) return false;   -- disconnect only, never ban
--   if (pnode.addr.IsLocal()) { disconnect only }
--   else { Discourage(pnode.addr); }
--   pnode.fDisconnect = true;
--
-- @param peer Peer: peer that misbehaved
-- @param score number: ignored (kept for call-site compatibility)
-- @param reason string: reason for the misbehavior
function PeerManager:misbehaving(peer, score, reason)
  reason = reason or "unspecified"

  -- Guard: NoBan-whitelisted peers are NEVER banned or disconnected
  -- (mirrors NetPermissionFlags::NoBan). Log for observability only.
  if peer.noban then
    local key = peer.ip .. ":" .. (peer.port or 0)
    print(string.format(
      "[misbehaving] peer=%s (noban) skipping ban/disconnect: %s",
      key, reason
    ))
    return
  end

  local key = peer.ip .. ":" .. (peer.port or 0)
  print(string.format(
    "[misbehaving] peer=%s single-event discourage: %s",
    key, reason
  ))

  -- Guard: manual (addnode) peers are only DISCONNECTED, never banned
  -- (mirrors CNode::m_manually_added).
  if peer.is_manual then
    print(string.format(
      "[misbehaving] peer=%s (manual) disconnect-only (no ban): %s",
      key, reason
    ))
    self:disconnect_peer(peer, "misbehaving (manual peer): " .. reason)
    return
  end

  -- Guard: local/loopback peers get disconnect-only treatment (mirrors
  -- Core's IsLocal() branch in MaybeDiscourageAndDisconnect).
  if _is_local_addr(peer.ip) then
    print(string.format(
      "[misbehaving] peer=%s (local) disconnect-only (no ban): %s",
      key, reason
    ))
    self:disconnect_peer(peer, "misbehaving (local peer): " .. reason)
    return
  end

  -- Regular inbound/outbound peer: discourage IP and disconnect immediately.
  print(string.format(
    "[misbehaving] peer=%s discouraging and disconnecting",
    key
  ))
  self:ban_peer(peer.ip)
  self:disconnect_peer(peer, "misbehaving: " .. reason)
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

--- Apply Core's inbound-addr rate limiting to a freshly received address list.
--
-- Mirrors net_processing.cpp ProcessAddrs (~5625): a per-peer token bucket
-- starting at 1.0, refilled by elapsed_seconds * MAX_ADDR_RATE_PER_SECOND(0.1)
-- and capped at MAX_ADDR_PROCESSING_TOKEN_BUCKET(1000); one token is spent per
-- admitted address, and the excess is DROPPED for rate-limited (non-whitelist)
-- peers.  This ONE helper is shared by both handle_addr and handle_addrv2 so an
-- attacker cannot bypass the limit by switching to the addrv2 message -- Core
-- routes ADDR and ADDRV2 through the same ProcessAddrs bucket
-- (net_processing.cpp:4022).
--
-- DIVERGENCE FROM CORE (documented per task): Core initialises the bucket to
-- 1.0 and tops it up by +MAX_ADDR_TO_SEND(1000) once when WE send a getaddr
-- (net_processing.cpp:3767).  lunarblock NEVER sends getaddr (no getaddr-send
-- path exists anywhere in src/), so that +1000 top-up has no trigger and is
-- intentionally not wired.  We init to 1.0 exactly as Core does -- we do NOT
-- claim Core inits to 1000.
--
-- @param peer Peer: source peer (carries the shared bucket state)
-- @param addresses table: list of decoded address entries
-- @return table: the admitted sublist (excess dropped for rate-limited peers)
function PeerManager:_rate_limit_addrs(peer, addresses)
  if not peer then return addresses end

  -- Initialise the shared bucket on first use (Core: m_addr_token_bucket = 1.0).
  local mono = socket.gettime()
  if peer.addr_token_bucket == nil then
    peer.addr_token_bucket = 1.0
    peer.addr_token_timestamp = mono
  end

  -- Refill: elapsed * 0.1, capped at 1000.  Don't refill past the cap.
  if peer.addr_token_bucket < M.CONNMAN.MAX_ADDR_PROCESSING_TOKEN_BUCKET then
    local elapsed = mono - (peer.addr_token_timestamp or mono)
    if elapsed < 0 then elapsed = 0 end
    local increment = elapsed * M.CONNMAN.MAX_ADDR_RATE_PER_SECOND
    peer.addr_token_bucket = math.min(
      peer.addr_token_bucket + increment,
      M.CONNMAN.MAX_ADDR_PROCESSING_TOKEN_BUCKET)
  end
  peer.addr_token_timestamp = mono

  -- Whitelisted (NoBan/manual) peers are exempt from the limit -- closest
  -- analogue to Core's NetPermissionFlags::Addr exemption.
  local rate_limited = not (peer.noban or peer.is_manual)

  local admitted = {}
  for _, addr in ipairs(addresses) do
    if peer.addr_token_bucket < 1.0 then
      if rate_limited then
        -- Out of tokens: drop the rest for a rate-limited peer.
        goto continue
      end
      -- Non-rate-limited peer: admit without spending (bucket may stay <1).
    else
      peer.addr_token_bucket = peer.addr_token_bucket - 1.0
    end
    admitted[#admitted + 1] = addr
    ::continue::
  end
  return admitted
end

--- Handle received addr message.
-- @param peer Peer: peer that sent the message
-- @param payload string: addr message payload
function PeerManager:handle_addr(peer, payload)
  local addresses = p2p.deserialize_addr(payload)
  -- Rate-limit BEFORE processing (shared bucket; see _rate_limit_addrs).
  addresses = self:_rate_limit_addrs(peer, addresses)
  local now = os.time()
  local src_ip = peer and peer.ip or "unknown"
  for _, addr in ipairs(addresses) do
    -- Reject non-routable addresses (RFC1918, loopback, link-local, etc.).
    -- Mirrors Bitcoin Core CNetAddr::IsRoutable() guard in AddrMan::Add().
    if not _is_routable(addr.ip) then
      goto continue
    end
    -- Core net_processing.cpp:5678-5680: clamp timestamps that are pre-2001
    -- (nTime <= 100000000) or more than 10 minutes in the future to
    -- (now - 5*24*60*60).  Core does NOT drop these addresses; it clamps and
    -- stores them.  The previous drop-if-outside-3h guard was wrong.
    local ts = addr.timestamp
    if ts <= 100000000 or ts > now + 600 then
      ts = now - 5 * 24 * 60 * 60
    end
    local key = addr.ip .. ":" .. addr.port
    if not self.known_addresses[key] then
      self.known_addresses[key] = {
        ip = addr.ip,
        port = addr.port,
        services = addr.services,
        timestamp = ts,
        network_id = p2p.NET_ID.IPV4,  -- Legacy addr is always IPv4/IPv6
        attempts = 0,
        last_try = 0,
      }
    end
    -- Add to address manager new table with source tracking
    self:_add_to_new(addr.ip, addr.port, addr.services, ts, src_ip)
    ::continue::
  end
end

--- Handle received addrv2 message (BIP155).
-- @param peer Peer: peer that sent the message
-- @param payload string: addrv2 message payload
function PeerManager:handle_addrv2(peer, payload)
  local addresses = p2p.deserialize_addrv2(payload)
  -- Rate-limit BEFORE processing, sharing the SAME per-peer bucket as
  -- handle_addr so an addrv2 flood cannot bypass the addr rate limit.
  addresses = self:_rate_limit_addrs(peer, addresses)
  local now = os.time()
  local src_ip = peer and peer.ip or "unknown"
  for _, addr in ipairs(addresses) do
    -- Skip invalid addresses
    if not addr.valid then
      goto continue
    end
    -- Core net_processing.cpp:5678-5680: clamp timestamps that are pre-2001
    -- (nTime <= 100000000) or more than 10 minutes in the future to
    -- (now - 5*24*60*60).  Core does NOT drop these addresses; it clamps and
    -- stores them.  The previous drop-if-outside-3h guard was wrong.
    local ts = addr.timestamp
    if ts <= 100000000 or ts > now + 600 then
      ts = now - 5 * 24 * 60 * 60
    end
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
          timestamp = ts,
          network_id = addr.network_id,
          attempts = 0,
          last_try = 0,
        }
      end
      -- Only add to connection pool if it's a routable IP address.
      -- _is_routable rejects RFC1918/loopback/link-local for IPv4;
      -- non-IPv4 overlay addresses (Tor/I2P/CJDNS) pass through.
      if addr.ip and _is_routable(addr.ip) then
        self:_add_to_new(addr.ip, addr.port, addr.services, ts, src_ip)
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
  -- Use tcp4() so setoption("reuseaddr", true) actually succeeds on this
  -- LuaSocket 3.0 build (setsockopt fails on the generic tcp() master socket).
  -- Without SO_REUSEADDR, bind() fails with "address already in use" during
  -- the TIME_WAIT window after a clean SIGTERM relaunch.
  local sock = socket.tcp4()
  if not sock then return false, "failed to create socket" end
  local ok, err = sock:setoption("reuseaddr", true)
  if not ok then
    sock:close()
    return false, err
  end
  ok, err = sock:bind(bind_ip or "0.0.0.0", listen_port)
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
--- Enable/disable all NEW P2P network activity (Bitcoin Core CConnman::SetNetworkActive,
-- net.cpp:3361).  Idempotent: when the flag already equals *state* this logs and
-- early-returns with no notification (Core's `if (fNetworkActive == active) return;`).
-- Otherwise it flips the flag.  Does NOT disconnect existing/established peers —
-- only suppresses establishing NEW connections (inbound accept, outbound auto-dial
-- refill, DNS/fixed-seed re-seeding, and the --connect manual reconnect loop).
-- Returns the read-back value (Core's `GetNetworkActive()`), which absent a race
-- equals *state*.  Not persisted; resets to enabled on restart.
-- @param state boolean
-- @return boolean: the network-active flag after the toggle
function PeerManager:set_network_active(state)
  state = state and true or false
  if self.network_active == state then
    io.stderr:write(string.format("[net] SetNetworkActive: %s (unchanged)\n", tostring(state)))
    return self.network_active
  end
  self.network_active = state
  io.stderr:write(string.format("[net] SetNetworkActive: %s\n", tostring(state)))
  return self.network_active
end

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

  -- Network-active gate (Core net.cpp:1786): while networking is disabled
  -- (`setnetworkactive false`) refuse NEW inbound connections.  Existing peers
  -- are untouched — only new establishment is suppressed.
  if not self.network_active then
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
  local p = peer_mod.new(ip, port, self.network, self.our_height, inbound_v2, nil,
                         self.config.peerbloomfilters, self.config.prune_mode,
                         {
                           -- FIX-71 W121 BUG-2: NODE_COMPACT_FILTERS gate inputs.
                           peerblockfilters = self.config.peerblockfilters,
                           blockfilterindex_enabled = self.config.blockfilterindex_enabled,
                         })
  p.socket = client
  p.state = peer_mod.STATE.CONNECTED
  p.inbound = true
  -- conn_time / handshake_start_time are normally set by Peer:connect (the
  -- outbound TCP connect path); inbound peers bypass that, so initialize
  -- them here to keep the handshake-timeout watchdog (peer.lua check_timeouts)
  -- correct and getpeerinfo.conntime sane.
  p.conn_time = socket.gettime()
  p.last_recv = socket.gettime()
  p.handshake_start_time = socket.gettime()
  client:settimeout(0)

  -- BIP-324 v2 inbound: build a responder-mode V2Transport now so the
  -- transport state machine has its keypair/garbage prepared.  The actual
  -- decision to *send* our 64-byte ellswift pubkey is deferred to
  -- Peer:drive_inbound_v2_handshake() which first peeks 16 bytes to
  -- distinguish v1 from v2 (sending v2 garbage on a v1-only peer would
  -- corrupt the v1 framing on the remote and get us banned).  See
  -- W82-style inbound v2 plumbing in clearbit/peer.zig:899-930.
  if inbound_v2 then
    p.v2_transport = bip324.V2Transport(
      self.network.magic_bytes, false, ip, port)
  end

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
--- Reconnect dropped manual peers (addnode <ip> add).
-- When a remote at-tip peer evicts our IBD-state connection ("behind our
-- tip"), the mesh would permanently lose it without this.  Matches Bitcoin
-- Core ThreadOpenConnections periodic manual-peer reconnect.  onetry peers
-- are NOT in manual_peers, so they stay one-shot.
function PeerManager:_reconnect_manual_peers()
  -- Network-active gate (Core net.cpp:2351/3022/3219): while networking is
  -- disabled (`setnetworkactive false`) hold off re-establishing dropped manual
  -- / --connect pinned peers too — only NEW establishment is suppressed; the
  -- still-connected manual peers are left untouched.
  if not self.network_active then
    return
  end
  local now = os.time()
  for key, entry in pairs(self.manual_peers) do
    -- Already connected?  Nothing to do.
    if not self.peers[key] then
      -- Throttle: don't re-attempt faster than manual_reconnect_interval.
      if not entry.last_try or (now - entry.last_try) >= self.manual_reconnect_interval then
        entry.last_try = now
        entry.attempts = (entry.attempts or 0) + 1
        local ok, _err = self:connect_peer(
          entry.ip, entry.port, true, entry.use_v2_override, true
        )
        if ok then
          entry.success_count = (entry.success_count or 0) + 1
          print(string.format(
            "[MANUAL-RECONNECT] reconnected %s (attempt %d, total reconnects %d)",
            key, entry.attempts, entry.success_count
          ))
        end
        -- Failures are expected (remote may still be evicting us); the
        -- next tick + throttle window will retry.  Don't log to avoid
        -- log spam during sustained eviction.
      end
    end
  end
end

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
        -- Feeler: the handshake SUCCEEDED -> mark for disconnect.  The promotion
        -- NEW->TRIED happens in disconnect_peer (_move_to_tried for ESTABLISHED
        -- outbound peers), so a feeler that reaches ESTABLISHED is promoted and
        -- one that never does (dial/handshake fail) is not -- Core's
        -- promote-on-success-only semantics.  Feelers carry no relay, so we do
        -- NOT init trickling for them.
        if p.is_feeler then
          p._feeler_done = true
        else
          -- Initialize trickling state for newly established peer
          self:_init_peer_trickle(p)
          if self.callbacks.on_peer_established then
            self.callbacks.on_peer_established(p)
          end
        end
      end
    end
    if p.state == peer_mod.STATE.DISCONNECTED then
      disconnected[#disconnected + 1] = p
    elseif p._feeler_done then
      -- Feeler probe finished its handshake: tear it down (which promotes the
      -- address NEW->TRIED via disconnect_peer/_move_to_tried).
      disconnected[#disconnected + 1] = p
    end
  end

  -- Clean up disconnected peers
  for _, p in ipairs(disconnected) do
    self:disconnect_peer(p, p._feeler_done and "feeler" or "disconnected")
  end

  -- Process transaction trickling (batched, randomized inv sending)
  self:_process_trickle()

  -- Check for stale tip and evict extra outbound peers
  self:check_for_stale_tip_and_evict_peers()

  -- Maintain outbound connections
  self:maintain_connections()

  -- Periodically open a short-lived feeler to a NEW-table address to keep the
  -- TRIED table fresh (Core net.cpp ThreadOpenConnections FEELER arm,
  -- FEELER_INTERVAL=120s).  Off the regular outbound budget; promotes on
  -- handshake-success only.
  self:maybe_open_feeler()

  -- Periodic ASMap health check every 3600s (1 hour).
  -- FIX-52 / W115 G16: mirrors Core's init.cpp ASMapHealthCheck() call after
  -- peers.dat load; here we repeat it hourly so operators can confirm
  -- eclipse-mitigation is still healthy at runtime (not just at startup).
  if M.using_asmap() then
    local now_h = os.time()
    if not self._last_health_check
        or (now_h - self._last_health_check) >= 3600 then
      self._last_health_check = now_h
      self:asmap_health_check()
    end
  end

  -- Periodic addrman dump every 900s (15 min).  Mirrors Core's
  -- CConnman::DumpAddresses() / DUMP_PEERS_INTERVAL so a crash/kill (no clean
  -- stop()) still leaves a recent peers.dat to restore on the next boot.
  do
    local now_s = os.time()
    if not self._last_addrman_save
        or (now_s - self._last_addrman_save) >= 900 then
      self._last_addrman_save = now_s
      self:_save_addrman()
    end
  end

  -- Reconnect dropped manual peers last, AFTER stale-tip eviction has
  -- had its chance.  Running every tick is cheap — the per-entry
  -- throttle (manual_reconnect_interval) gates actual connect attempts.
  self:_reconnect_manual_peers()
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

--- Announce a newly connected block to all established peers.
-- Per BIP-130, peers that previously sent a `sendheaders` message expect
-- header announces (`headers` with one entry); other peers get the legacy
-- `inv` announce. Without this branch, peers that opted into headers
-- announces never receive direct header notifications and must wait for
-- the next inv→getheaders→headers round-trip, slowing tip propagation
-- and contributing to header-sync DoS surface area.
--
-- Reference: bitcoin-core/src/net_processing.cpp PeerManagerImpl::MaybeSendBlock
-- and camlcoin/lib/peer_manager.ml::announce_block.
--
-- W112 BUG-5/BUG-6 fix: HB peers (high_bandwidth=true) now receive an
-- unsolicited cmpctblock directly.  Non-HB peers continue to get headers
-- (if they sent sendheaders) or inv.  compact_block.create_compact_block is
-- called lazily (only when there is at least one HB peer) to avoid the cost
-- when no HB peers are present.
--
-- @param block_hash hash256: block hash object
-- @param header table: block_header object (for headers announce)
-- @param full_block table: full block object (optional; needed for HB cmpctblock)
-- @param filter_fn function: optional filter function(peer) -> boolean
function PeerManager:announce_block(block_hash, header, full_block, filter_fn)
  -- Backward-compat: callers that pass only (block_hash, header) without full_block
  -- will get nil for full_block; HB path is simply skipped in that case.
  if type(full_block) == "function" then
    -- Old 3-arg call: announce_block(hash, header, filter_fn)
    filter_fn = full_block
    full_block = nil
  end

  local inv_payload = p2p.serialize_inv({
    {type = p2p.INV_TYPE.MSG_BLOCK, hash = block_hash}
  })
  local headers_payload = nil
  local cmpctblock_payload = nil  -- built lazily for HB peers

  for _, p in ipairs(self.peer_list) do
    if p.state == peer_mod.STATE.ESTABLISHED then
      if not filter_fn or filter_fn(p) then
        -- HB peers: send unsolicited cmpctblock (BIP-152 Section 3.1)
        if p.high_bandwidth and p.provides_compact and full_block then
          if not cmpctblock_payload then
            -- Lazy-require compact_block to avoid circular dependency at module load.
            local cb_mod = require("lunarblock.compact_block")
            local serialize_mod = require("lunarblock.serialize")
            local nonce_val = math.random(0, 2^52)  -- 52-bit safe for Lua double
            local cb = cb_mod.create_compact_block(full_block, nonce_val)
            cmpctblock_payload = serialize_mod and cb and p2p.serialize_cmpctblock(
              cb.header, cb.nonce, cb.short_ids, cb.prefilled_txns)
          end
          if cmpctblock_payload then
            p:send_message("cmpctblock", cmpctblock_payload)
            goto continue_peer
          end
        end
        -- Non-HB: headers or inv
        if p.send_headers and header then
          if not headers_payload then
            headers_payload = p2p.serialize_headers({header})
          end
          p:send_message("headers", headers_payload)
        else
          p:send_message("inv", inv_payload)
        end
        ::continue_peer::
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

--- Relay addresses to up to 2 random connected peers (not back to source).
-- Implements Bitcoin Core's RelayAddress behavior.
-- @param source Peer: the peer that sent us the addresses
function PeerManager:_relay_addr_to_random_peers(source)
  local candidates = {}
  for _, p in ipairs(self.peer_list) do
    if p ~= source and p.state == "connected" then
      candidates[#candidates + 1] = p
    end
  end
  if #candidates == 0 then return end

  -- Shuffle
  for i = #candidates, 2, -1 do
    local j = math.random(1, i)
    candidates[i], candidates[j] = candidates[j], candidates[i]
  end

  -- Pick up to 2 and send some addresses
  local n = math.min(2, #candidates)
  -- Collect up to 10 addresses to relay
  local addr_list = {}
  local count = 0
  for _, info in pairs(self.known_addresses) do
    if count >= 10 then break end
    if info.ip then
      addr_list[#addr_list + 1] = info
      count = count + 1
    end
  end
  if count == 0 then return end

  for i = 1, n do
    local target = candidates[i]
    local payload, cmd = self:serialize_addr_for_peer(target, addr_list)
    target:send_message(cmd, payload)
  end
end

--- Respond to a getaddr message with our addresses, applying Core's anti-DoS
--- guards (net_processing.cpp GETADDR handler, ~4816).
--
--   * Ignore getaddr from OUTBOUND peers (anti-fingerprinting: an attacker
--     could otherwise stamp our addrman via fake addresses and read them back).
--   * Answer only the FIRST getaddr per connection; ignore repeats
--     (Core m_getaddr_recvd).
--   * Cap the response at min(MAX_ADDR_TO_SEND, floor(0.23 * addrman_size))
--     (Core MAX_PCT_ADDR_TO_SEND=23, MAX_ADDR_TO_SEND=1000; the percentage
--     cap is INTEGER division/floor per addrman.cpp:800).  This is the
--     getaddr-reply cap ONLY; the getnodeaddresses RPC dump path
--     (rpc.lua) reads known_addresses directly and stays uncapped.
-- @param peer Peer: peer that requested addresses
function PeerManager:_respond_getaddr(peer)
  -- Ignore getaddr from outbound connections.  peer.inbound is true only for
  -- accepted (inbound) connections; outbound peers (including feelers) have
  -- inbound=false.
  if peer and peer.inbound == false then
    return
  end

  -- Only one getaddr response per connection.
  if peer and peer.getaddr_recvd then
    return
  end
  if peer then peer.getaddr_recvd = true end

  -- Compute the 23%-of-addrman cap (min with the 1000 absolute cap).
  -- Core uses INTEGER division (FLOOR): GetAddr_ computes
  --   nNodes = max_pct * nNodes / 100   (addrman.cpp:800, size_t division)
  -- then min()s with MAX_ADDR_TO_SEND. So e.g. an addrman of 10 yields
  -- floor(23*10/100) = 2 (NOT ceil's 3). Use math.floor to match exactly —
  -- a previous ceil here over-sent by one whenever 23*size was not a
  -- multiple of 100.
  local addrman_size = self:get_known_address_count()
  local pct_cap = math.floor(addrman_size * M.CONNMAN.MAX_PCT_ADDR_TO_SEND / 100)
  local cap = math.min(M.CONNMAN.MAX_ADDR_TO_SEND, pct_cap)

  local addr_list = {}
  local count = 0
  for _, info in pairs(self.known_addresses) do
    if count >= cap then break end
    if info.ip then
      addr_list[#addr_list + 1] = info
      count = count + 1
    end
  end
  if count > 0 then
    local payload, cmd = self:serialize_addr_for_peer(peer, addr_list)
    peer:send_message(cmd, payload)
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
-- BIP-37: if a peer has loaded a bloom filter (peer.bloom_filter ~= nil) the
-- transaction is checked against the filter; only matching txs are queued.
-- Reference: bitcoin-core/src/net_processing.cpp SendMessages() — filters
-- outbound tx inv via tx_relay->m_bloom_filter->IsRelevantAndUpdate().
-- @param txid  string: transaction id (hash256 as raw bytes)
-- @param wtxid string: witness transaction id (hash256 as raw bytes, optional)
-- @param tx    table:  deserialized transaction object (optional; required for
--                      bloom-filter matching when the peer has loaded a filter)
function PeerManager:queue_tx_announcement(txid, wtxid, tx)
  wtxid = wtxid or txid  -- Non-segwit: wtxid equals txid
  for _, p in ipairs(self.peer_list) do
    if p.state == peer_mod.STATE.ESTABLISHED then
      local key = p.ip .. ":" .. p.port
      local trickle = self._peer_trickle and self._peer_trickle[key]
      if trickle then
        -- BIP-37: per-peer bloom filter check (FIX-37).
        -- Skip this peer if it has a loaded filter that rejects the tx.
        -- If no filter is loaded (peer.bloom_filter == nil) the tx is always
        -- relayed (unconditional relay, same as Core when no filter is set).
        if p.bloom_filter ~= nil and tx ~= nil then
          local bloom = require("lunarblock.bloom")
          local ok_pcall, matched = pcall(bloom.is_relevant_and_update, p.bloom_filter, tx)
          if not ok_pcall or not matched then
            -- tx does not match this peer's filter — skip it
            goto continue_peer
          end
        end

        -- Use wtxid for peers that negotiated wtxidrelay (BIP 339)
        local hash = p.wtxid_relay and wtxid or txid
        local is_wtxid = p.wtxid_relay
        -- Don't re-announce transactions the peer already knows about
        if not trickle.inv_known[hash] then
          trickle.inv_queue[#trickle.inv_queue + 1] = {hash = hash, is_wtxid = is_wtxid}
        end
        ::continue_peer::
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
    -- Feelers are off-budget (Core net.cpp: FEELER holds no outbound slot);
    -- exclude them from both the full-relay and block-relay counts.
    if not p.inbound and not p.is_feeler then
      -- For now, treat all (non-feeler) outbound as full-relay
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
  -- Persist the bucketed addrman (peers.dat) and anchors before tear-down so
  -- the address book + bucket layout survive the restart (Core dumps addresses
  -- on shutdown via DumpAddresses()).
  self:_save_addrman()
  self:_save_anchors()

  for _, p in ipairs(self.peer_list) do
    -- Roll the per-peer counters into the cumulative totals before tear-down
    -- (matches CConnman::Stop semantics).
    self.totals.bytes_recv = self.totals.bytes_recv + (p.bytes_recv or 0)
    self.totals.bytes_sent = self.totals.bytes_sent + (p.bytes_sent or 0)
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

-- Expose PeerManager metatable so tests can borrow individual methods
-- (e.g. misbehaving()) without constructing a full I/O-bound instance.
M.PeerManager = PeerManager

return M
