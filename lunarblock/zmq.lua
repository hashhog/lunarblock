--- ZeroMQ pub/sub notifications for real-time streaming
-- Implements Bitcoin Core-compatible ZMQ topics: hashblock, hashtx, rawblock, rawtx, sequence
-- Reference: /home/max/hashhog/bitcoin/src/zmq/zmqpublishnotifier.cpp

local ffi = require("ffi")
local bit = require("bit")
local M = {}

--------------------------------------------------------------------------------
-- ZMQ FFI Bindings
--------------------------------------------------------------------------------

ffi.cdef[[
  typedef struct zmq_msg_t {
    unsigned char _[64];
  } zmq_msg_t;

  // Context management
  void *zmq_ctx_new(void);
  int zmq_ctx_term(void *context);
  int zmq_ctx_shutdown(void *context);

  // Socket management
  void *zmq_socket(void *context, int type);
  int zmq_close(void *socket);
  int zmq_bind(void *socket, const char *addr);
  int zmq_setsockopt(void *socket, int option_name, const void *option_value, size_t option_len);

  // Message management
  int zmq_msg_init_size(zmq_msg_t *msg, size_t size);
  int zmq_msg_close(zmq_msg_t *msg);
  void *zmq_msg_data(zmq_msg_t *msg);
  int zmq_msg_send(zmq_msg_t *msg, void *socket, int flags);

  // Polling (for recv in tests)
  typedef struct zmq_pollitem_t {
    void *socket;
    int fd;
    short events;
    short revents;
  } zmq_pollitem_t;

  int zmq_poll(zmq_pollitem_t *items, int nitems, long timeout);
  int zmq_msg_init(zmq_msg_t *msg);
  int zmq_msg_recv(zmq_msg_t *msg, void *socket, int flags);
  size_t zmq_msg_size(zmq_msg_t *msg);
  int zmq_connect(void *socket, const char *addr);
  int zmq_getsockopt(void *socket, int option_name, void *option_value, size_t *option_len);
]]

-- Socket types
M.ZMQ_PUB = 1
M.ZMQ_SUB = 2

-- Socket options
M.ZMQ_SNDHWM = 23       -- Send high water mark
M.ZMQ_RCVHWM = 24       -- Receive high water mark
M.ZMQ_LINGER = 17       -- Socket linger timeout
M.ZMQ_SUBSCRIBE = 6     -- Subscribe filter
M.ZMQ_TCP_KEEPALIVE = 34
M.ZMQ_RCVMORE = 13      -- More message parts to follow

-- Send/recv flags
M.ZMQ_SNDMORE = 2       -- More parts to follow
M.ZMQ_DONTWAIT = 1      -- Non-blocking

-- Poll events
M.ZMQ_POLLIN = 1

-- Load libzmq
local libzmq
local zmq_available = false

local function try_load_zmq()
  local ok, lib = pcall(ffi.load, "zmq")
  if ok then
    libzmq = lib
    zmq_available = true
    return true
  end
  return false
end

-- Try to load on module initialization
try_load_zmq()

--- Check if ZMQ is available.
-- @return boolean: true if libzmq is loaded
function M.is_available()
  return zmq_available
end

--------------------------------------------------------------------------------
-- Topic Constants
--------------------------------------------------------------------------------

M.TOPIC_HASHBLOCK = "hashblock"
M.TOPIC_HASHTX = "hashtx"
M.TOPIC_RAWBLOCK = "rawblock"
M.TOPIC_RAWTX = "rawtx"
M.TOPIC_SEQUENCE = "sequence"

-- Sequence message labels (for mempool events)
M.LABEL_ADDED = string.byte('A')       -- Transaction added to mempool
M.LABEL_REMOVED = string.byte('R')     -- Transaction removed from mempool
M.LABEL_CONNECTED = string.byte('C')   -- Block connected
M.LABEL_DISCONNECTED = string.byte('D') -- Block disconnected

--------------------------------------------------------------------------------
-- Helper Functions
--------------------------------------------------------------------------------

--- Encode a 32-bit integer as little-endian bytes.
-- @param n number: integer to encode
-- @return string: 4 bytes LE
local function encode_le32(n)
  return string.char(
    bit.band(n, 0xFF),
    bit.band(bit.rshift(n, 8), 0xFF),
    bit.band(bit.rshift(n, 16), 0xFF),
    bit.band(bit.rshift(n, 24), 0xFF)
  )
end

--- Encode a 64-bit integer as little-endian bytes.
-- @param n number: integer to encode
-- @return string: 8 bytes LE
local function encode_le64(n)
  local low = bit.band(n, 0xFFFFFFFF)
  local high = math.floor(n / 4294967296)
  return string.char(
    bit.band(low, 0xFF),
    bit.band(bit.rshift(low, 8), 0xFF),
    bit.band(bit.rshift(low, 16), 0xFF),
    bit.band(bit.rshift(low, 24), 0xFF),
    bit.band(high, 0xFF),
    bit.band(bit.rshift(high, 8), 0xFF),
    bit.band(bit.rshift(high, 16), 0xFF),
    bit.band(bit.rshift(high, 24), 0xFF)
  )
end

--- Reverse bytes (for hash display).
-- Bitcoin hashes are stored little-endian but displayed big-endian.
-- @param data string: bytes to reverse
-- @return string: reversed bytes
local function reverse_bytes(data)
  local result = {}
  for i = #data, 1, -1 do
    result[#result + 1] = data:sub(i, i)
  end
  return table.concat(result)
end

--------------------------------------------------------------------------------
-- ZMQ Publisher
--------------------------------------------------------------------------------

local ZMQPublisher = {}
ZMQPublisher.__index = ZMQPublisher

--- Create a new ZMQ publisher.
-- @param config table: Configuration options
--   - endpoints table: Map of topic -> endpoint (e.g., {hashblock = "tcp://127.0.0.1:28332"})
--   - hwm number: High water mark (default 1000)
-- @return ZMQPublisher|nil, string|nil: publisher or nil, error message
function M.new(config)
  if not zmq_available then
    return nil, "ZMQ not available"
  end

  local self = setmetatable({}, ZMQPublisher)

  self.ctx = libzmq.zmq_ctx_new()
  if self.ctx == nil then
    return nil, "Failed to create ZMQ context"
  end

  self.sockets = {}       -- endpoint -> socket
  self.topic_socket = {}  -- topic -> socket
  self.topic_seq = {}     -- topic -> sequence number (uint32)
  self.hwm = config.hwm or 1000
  self.endpoints = config.endpoints or {}
  self.enabled = false

  -- Initialize sequence counters for each topic
  for _, topic in ipairs({M.TOPIC_HASHBLOCK, M.TOPIC_HASHTX, M.TOPIC_RAWBLOCK, M.TOPIC_RAWTX, M.TOPIC_SEQUENCE}) do
    self.topic_seq[topic] = 0
  end

  -- Create and bind sockets for each unique endpoint
  -- Multiple topics can share the same endpoint/socket
  local endpoint_to_socket = {}
  local topics_enabled = 0

  for topic, endpoint in pairs(self.endpoints) do
    if endpoint and endpoint ~= "" then
      local sock = endpoint_to_socket[endpoint]
      if not sock then
        -- Create new socket for this endpoint
        sock = libzmq.zmq_socket(self.ctx, M.ZMQ_PUB)
        if sock == nil then
          self:shutdown()
          return nil, "Failed to create ZMQ socket"
        end

        -- Set high water mark
        local hwm_val = ffi.new("int[1]", self.hwm)
        libzmq.zmq_setsockopt(sock, M.ZMQ_SNDHWM, hwm_val, ffi.sizeof(hwm_val))

        -- Enable TCP keepalive
        local keepalive = ffi.new("int[1]", 1)
        libzmq.zmq_setsockopt(sock, M.ZMQ_TCP_KEEPALIVE, keepalive, ffi.sizeof(keepalive))

        -- Bind to endpoint
        local rc = libzmq.zmq_bind(sock, endpoint)
        if rc ~= 0 then
          libzmq.zmq_close(sock)
          self:shutdown()
          return nil, "Failed to bind to " .. endpoint
        end

        endpoint_to_socket[endpoint] = sock
        self.sockets[endpoint] = sock
      end

      self.topic_socket[topic] = sock
      topics_enabled = topics_enabled + 1
    end
  end

  self.enabled = topics_enabled > 0
  return self
end

--- Check if a specific topic is enabled.
-- @param topic string: Topic name
-- @return boolean
function ZMQPublisher:is_enabled(topic)
  return self.topic_socket[topic] ~= nil
end

--- Check if any topic is enabled.
-- @return boolean
function ZMQPublisher:has_notifications()
  return self.enabled
end

--- Send a multipart ZMQ message.
-- Format: [topic, body, sequence_le32]
-- @param topic string: Topic name (hashblock, hashtx, etc.)
-- @param body string: Message body
-- @return boolean: true on success
function ZMQPublisher:send(topic, body)
  local sock = self.topic_socket[topic]
  if not sock then
    return false
  end

  -- Get and increment sequence number (wraps at 2^32)
  local seq = self.topic_seq[topic]
  self.topic_seq[topic] = bit.band(seq + 1, 0xFFFFFFFF)
  local seq_bytes = encode_le32(seq)

  -- Send multipart: topic | body | sequence
  local parts = {topic, body, seq_bytes}
  for i, part in ipairs(parts) do
    local msg = ffi.new("zmq_msg_t")
    if libzmq.zmq_msg_init_size(msg, #part) ~= 0 then
      return false
    end

    ffi.copy(libzmq.zmq_msg_data(msg), part, #part)

    local flags = (i < #parts) and M.ZMQ_SNDMORE or 0
    local rc = libzmq.zmq_msg_send(msg, sock, flags)
    libzmq.zmq_msg_close(msg)

    if rc == -1 then
      return false
    end
  end

  return true
end

--- Notify block hash.
-- @param block_hash string: 32-byte block hash (internal byte order)
-- @return boolean
function ZMQPublisher:notify_hashblock(block_hash)
  if not self:is_enabled(M.TOPIC_HASHBLOCK) then
    return false
  end
  -- Send hash in big-endian (display) order, matching Bitcoin Core
  return self:send(M.TOPIC_HASHBLOCK, reverse_bytes(block_hash))
end

--- Notify transaction hash.
-- @param txid string: 32-byte transaction ID (internal byte order)
-- @return boolean
function ZMQPublisher:notify_hashtx(txid)
  if not self:is_enabled(M.TOPIC_HASHTX) then
    return false
  end
  -- Send hash in big-endian (display) order, matching Bitcoin Core
  return self:send(M.TOPIC_HASHTX, reverse_bytes(txid))
end

--- Notify raw block.
-- @param block_data string: Serialized block bytes
-- @return boolean
function ZMQPublisher:notify_rawblock(block_data)
  if not self:is_enabled(M.TOPIC_RAWBLOCK) then
    return false
  end
  return self:send(M.TOPIC_RAWBLOCK, block_data)
end

--- Notify raw transaction.
-- @param tx_data string: Serialized transaction bytes
-- @return boolean
function ZMQPublisher:notify_rawtx(tx_data)
  if not self:is_enabled(M.TOPIC_RAWTX) then
    return false
  end
  return self:send(M.TOPIC_RAWTX, tx_data)
end

--- Notify sequence event (mempool or block events).
-- Format: 32-byte hash | 1-byte label | optional 8-byte LE mempool_sequence
-- Labels: A=added, R=removed, C=connected, D=disconnected
-- @param hash string: 32-byte hash (internal byte order)
-- @param label number: Label byte (A/R/C/D)
-- @param mempool_sequence number|nil: Mempool sequence number (for A/R events)
-- @return boolean
function ZMQPublisher:notify_sequence(hash, label, mempool_sequence)
  if not self:is_enabled(M.TOPIC_SEQUENCE) then
    return false
  end

  -- Build message: hash (BE) | label | optional mempool_sequence (LE)
  local body
  if mempool_sequence then
    body = reverse_bytes(hash) .. string.char(label) .. encode_le64(mempool_sequence)
  else
    body = reverse_bytes(hash) .. string.char(label)
  end

  return self:send(M.TOPIC_SEQUENCE, body)
end

--- Notify block connected.
-- @param block_hash string: 32-byte block hash
-- @return boolean
function ZMQPublisher:notify_block_connect(block_hash)
  return self:notify_sequence(block_hash, M.LABEL_CONNECTED)
end

--- Notify block disconnected.
-- @param block_hash string: 32-byte block hash
-- @return boolean
function ZMQPublisher:notify_block_disconnect(block_hash)
  return self:notify_sequence(block_hash, M.LABEL_DISCONNECTED)
end

--- Notify transaction added to mempool.
-- @param txid string: 32-byte transaction ID
-- @param mempool_sequence number: Mempool sequence number
-- @return boolean
function ZMQPublisher:notify_tx_acceptance(txid, mempool_sequence)
  return self:notify_sequence(txid, M.LABEL_ADDED, mempool_sequence)
end

--- Notify transaction removed from mempool.
-- @param txid string: 32-byte transaction ID
-- @param mempool_sequence number: Mempool sequence number
-- @return boolean
function ZMQPublisher:notify_tx_removal(txid, mempool_sequence)
  return self:notify_sequence(txid, M.LABEL_REMOVED, mempool_sequence)
end

--- Shutdown the publisher, closing all sockets and context.
function ZMQPublisher:shutdown()
  -- Set linger to 0 for immediate close
  local linger = ffi.new("int[1]", 0)

  for _, sock in pairs(self.sockets) do
    if sock ~= nil then
      libzmq.zmq_setsockopt(sock, M.ZMQ_LINGER, linger, ffi.sizeof(linger))
      libzmq.zmq_close(sock)
    end
  end
  self.sockets = {}
  self.topic_socket = {}

  if self.ctx ~= nil then
    libzmq.zmq_ctx_term(self.ctx)
    self.ctx = nil
  end

  self.enabled = false
end

--------------------------------------------------------------------------------
-- ZMQ Subscriber (for testing)
--------------------------------------------------------------------------------

local ZMQSubscriber = {}
ZMQSubscriber.__index = ZMQSubscriber

--- Create a new ZMQ subscriber (for testing).
-- @param endpoint string: Endpoint to connect to
-- @param topics table: List of topic strings to subscribe to
-- @return ZMQSubscriber|nil, string|nil
function M.new_subscriber(endpoint, topics)
  if not zmq_available then
    return nil, "ZMQ not available"
  end

  local self = setmetatable({}, ZMQSubscriber)

  self.ctx = libzmq.zmq_ctx_new()
  if self.ctx == nil then
    return nil, "Failed to create ZMQ context"
  end

  self.sock = libzmq.zmq_socket(self.ctx, M.ZMQ_SUB)
  if self.sock == nil then
    libzmq.zmq_ctx_term(self.ctx)
    return nil, "Failed to create ZMQ socket"
  end

  -- Subscribe to topics
  for _, topic in ipairs(topics) do
    libzmq.zmq_setsockopt(self.sock, M.ZMQ_SUBSCRIBE, topic, #topic)
  end

  -- Connect to endpoint
  local rc = libzmq.zmq_connect(self.sock, endpoint)
  if rc ~= 0 then
    libzmq.zmq_close(self.sock)
    libzmq.zmq_ctx_term(self.ctx)
    return nil, "Failed to connect to " .. endpoint
  end

  return self
end

--- Receive a multipart message.
-- @param timeout_ms number: Timeout in milliseconds (-1 for infinite)
-- @return table|nil: Array of message parts, or nil on timeout
function ZMQSubscriber:recv(timeout_ms)
  local pollitem = ffi.new("zmq_pollitem_t[1]", {{
    socket = self.sock,
    fd = 0,
    events = M.ZMQ_POLLIN,
    revents = 0,
  }})

  local rc = libzmq.zmq_poll(pollitem, 1, timeout_ms)
  if rc <= 0 then
    return nil  -- Timeout or error
  end

  local parts = {}
  local more = ffi.new("int[1]", 1)
  local more_size = ffi.new("size_t[1]", ffi.sizeof(more))

  while more[0] ~= 0 do
    local msg = ffi.new("zmq_msg_t")
    libzmq.zmq_msg_init(msg)

    rc = libzmq.zmq_msg_recv(msg, self.sock, 0)
    if rc == -1 then
      libzmq.zmq_msg_close(msg)
      break
    end

    local size = libzmq.zmq_msg_size(msg)
    local data = libzmq.zmq_msg_data(msg)
    parts[#parts + 1] = ffi.string(data, size)
    libzmq.zmq_msg_close(msg)

    libzmq.zmq_getsockopt(self.sock, M.ZMQ_RCVMORE, more, more_size)
  end

  return #parts > 0 and parts or nil
end

--- Close the subscriber.
function ZMQSubscriber:close()
  if self.sock then
    local linger = ffi.new("int[1]", 0)
    libzmq.zmq_setsockopt(self.sock, M.ZMQ_LINGER, linger, ffi.sizeof(linger))
    libzmq.zmq_close(self.sock)
    self.sock = nil
  end

  if self.ctx then
    libzmq.zmq_ctx_term(self.ctx)
    self.ctx = nil
  end
end

--------------------------------------------------------------------------------
-- Notification Manager
--------------------------------------------------------------------------------

local NotificationManager = {}
NotificationManager.__index = NotificationManager

--- Create a notification manager that wraps ZMQ publishing.
-- @param config table: Configuration with endpoint settings
-- @return NotificationManager
function M.new_notification_manager(config)
  local self = setmetatable({}, NotificationManager)

  self.publisher = nil
  self.mempool_sequence = 0
  self.enabled = false

  -- Check if any ZMQ endpoints are configured
  local endpoints = {}
  if config.zmqpubhashblock then
    endpoints[M.TOPIC_HASHBLOCK] = config.zmqpubhashblock
  end
  if config.zmqpubhashtx then
    endpoints[M.TOPIC_HASHTX] = config.zmqpubhashtx
  end
  if config.zmqpubrawblock then
    endpoints[M.TOPIC_RAWBLOCK] = config.zmqpubrawblock
  end
  if config.zmqpubrawtx then
    endpoints[M.TOPIC_RAWTX] = config.zmqpubrawtx
  end
  if config.zmqpubsequence then
    endpoints[M.TOPIC_SEQUENCE] = config.zmqpubsequence
  end

  -- Create publisher if any endpoints are configured
  if next(endpoints) then
    local pub, err = M.new({endpoints = endpoints, hwm = config.zmqpubhwm or 1000})
    if pub then
      self.publisher = pub
      self.enabled = true
    else
      -- Log error but don't fail
      io.stderr:write("Warning: Failed to initialize ZMQ: " .. (err or "unknown") .. "\n")
    end
  end

  return self
end

--- Notify that a block was connected.
-- @param block_hash string: 32-byte block hash
-- @param block_data string|nil: Serialized block (for rawblock)
function NotificationManager:on_block_connected(block_hash, block_data)
  if not self.enabled then return end

  self.publisher:notify_hashblock(block_hash)
  if block_data then
    self.publisher:notify_rawblock(block_data)
  end
  self.publisher:notify_block_connect(block_hash)
end

--- Notify that a block was disconnected.
-- @param block_hash string: 32-byte block hash
function NotificationManager:on_block_disconnected(block_hash)
  if not self.enabled then return end
  self.publisher:notify_block_disconnect(block_hash)
end

--- Notify that a transaction was added to mempool.
-- @param txid string: 32-byte transaction ID
-- @param tx_data string|nil: Serialized transaction (for rawtx)
function NotificationManager:on_tx_added(txid, tx_data)
  if not self.enabled then return end

  self.mempool_sequence = self.mempool_sequence + 1

  self.publisher:notify_hashtx(txid)
  if tx_data then
    self.publisher:notify_rawtx(tx_data)
  end
  self.publisher:notify_tx_acceptance(txid, self.mempool_sequence)
end

--- Notify that a transaction was removed from mempool.
-- @param txid string: 32-byte transaction ID
function NotificationManager:on_tx_removed(txid)
  if not self.enabled then return end

  self.mempool_sequence = self.mempool_sequence + 1
  self.publisher:notify_tx_removal(txid, self.mempool_sequence)
end

--- Shutdown notifications.
function NotificationManager:shutdown()
  if self.publisher then
    self.publisher:shutdown()
    self.publisher = nil
  end
  self.enabled = false
end

return M
