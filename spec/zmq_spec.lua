--- ZMQ notification tests
-- Tests the ZeroMQ pub/sub notification interface

local socket = require("socket")

-- Helper functions
local function hex_to_bytes(hex)
  return (hex:gsub("%x%x", function(c)
    return string.char(tonumber(c, 16))
  end))
end

local function bytes_to_hex(bytes)
  return (bytes:gsub(".", function(c)
    return string.format("%02x", string.byte(c))
  end))
end

local function reverse_bytes(data)
  local result = {}
  for i = #data, 1, -1 do
    result[#result + 1] = data:sub(i, i)
  end
  return table.concat(result)
end

local function decode_le32(data)
  local b1, b2, b3, b4 = data:byte(1, 4)
  return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
end

local function decode_le64(data)
  local low = decode_le32(data:sub(1, 4))
  local high = decode_le32(data:sub(5, 8))
  return low + high * 4294967296
end

describe("zmq", function()
  local zmq

  setup(function()
    zmq = require("lunarblock.zmq")
  end)

  describe("availability", function()
    it("has is_available function", function()
      assert.is_function(zmq.is_available)
    end)

    it("returns boolean for is_available", function()
      local available = zmq.is_available()
      assert.is_boolean(available)
    end)
  end)

  describe("topic constants", function()
    it("defines hashblock topic", function()
      assert.equals("hashblock", zmq.TOPIC_HASHBLOCK)
    end)

    it("defines hashtx topic", function()
      assert.equals("hashtx", zmq.TOPIC_HASHTX)
    end)

    it("defines rawblock topic", function()
      assert.equals("rawblock", zmq.TOPIC_RAWBLOCK)
    end)

    it("defines rawtx topic", function()
      assert.equals("rawtx", zmq.TOPIC_RAWTX)
    end)

    it("defines sequence topic", function()
      assert.equals("sequence", zmq.TOPIC_SEQUENCE)
    end)
  end)

  describe("sequence labels", function()
    it("defines added label as A", function()
      assert.equals(string.byte('A'), zmq.LABEL_ADDED)
    end)

    it("defines removed label as R", function()
      assert.equals(string.byte('R'), zmq.LABEL_REMOVED)
    end)

    it("defines connected label as C", function()
      assert.equals(string.byte('C'), zmq.LABEL_CONNECTED)
    end)

    it("defines disconnected label as D", function()
      assert.equals(string.byte('D'), zmq.LABEL_DISCONNECTED)
    end)
  end)

  -- Integration tests (require libzmq)
  describe("publisher creation", function()
    local has_zmq = zmq.is_available()

    if not has_zmq then
      pending("ZMQ not available, skipping integration tests")
      return
    end

    it("creates publisher with no endpoints", function()
      local pub, err = zmq.new({endpoints = {}})
      assert.is_not_nil(pub)
      assert.is_nil(err)
      assert.is_false(pub:has_notifications())
      pub:shutdown()
    end)

    it("creates publisher with hashblock endpoint", function()
      local pub, err = zmq.new({
        endpoints = {
          [zmq.TOPIC_HASHBLOCK] = "tcp://127.0.0.1:28332"
        }
      })
      assert.is_not_nil(pub)
      assert.is_nil(err)
      assert.is_true(pub:has_notifications())
      assert.is_true(pub:is_enabled(zmq.TOPIC_HASHBLOCK))
      assert.is_false(pub:is_enabled(zmq.TOPIC_HASHTX))
      pub:shutdown()
    end)

    it("creates publisher with multiple endpoints", function()
      local pub, err = zmq.new({
        endpoints = {
          [zmq.TOPIC_HASHBLOCK] = "tcp://127.0.0.1:28333",
          [zmq.TOPIC_HASHTX] = "tcp://127.0.0.1:28334",
          [zmq.TOPIC_RAWBLOCK] = "tcp://127.0.0.1:28335",
        }
      })
      assert.is_not_nil(pub)
      assert.is_nil(err)
      assert.is_true(pub:is_enabled(zmq.TOPIC_HASHBLOCK))
      assert.is_true(pub:is_enabled(zmq.TOPIC_HASHTX))
      assert.is_true(pub:is_enabled(zmq.TOPIC_RAWBLOCK))
      assert.is_false(pub:is_enabled(zmq.TOPIC_RAWTX))
      pub:shutdown()
    end)

    it("shares socket for same endpoint", function()
      -- All topics on same port
      local pub, err = zmq.new({
        endpoints = {
          [zmq.TOPIC_HASHBLOCK] = "tcp://127.0.0.1:28336",
          [zmq.TOPIC_HASHTX] = "tcp://127.0.0.1:28336",
        }
      })
      assert.is_not_nil(pub)
      assert.is_nil(err)
      -- Both topics should be enabled
      assert.is_true(pub:is_enabled(zmq.TOPIC_HASHBLOCK))
      assert.is_true(pub:is_enabled(zmq.TOPIC_HASHTX))
      pub:shutdown()
    end)
  end)

  describe("publisher-subscriber communication", function()
    local has_zmq = zmq.is_available()

    if not has_zmq then
      pending("ZMQ not available, skipping integration tests")
      return
    end

    local pub, sub

    before_each(function()
      -- Use unique port for each test to avoid conflicts
      local port = 28340 + math.random(100)
      local endpoint = "tcp://127.0.0.1:" .. port

      pub = zmq.new({
        endpoints = {
          [zmq.TOPIC_HASHBLOCK] = endpoint,
          [zmq.TOPIC_HASHTX] = endpoint,
          [zmq.TOPIC_RAWBLOCK] = endpoint,
          [zmq.TOPIC_RAWTX] = endpoint,
          [zmq.TOPIC_SEQUENCE] = endpoint,
        }
      })
      assert.is_not_nil(pub)

      sub = zmq.new_subscriber(endpoint, {
        zmq.TOPIC_HASHBLOCK,
        zmq.TOPIC_HASHTX,
        zmq.TOPIC_RAWBLOCK,
        zmq.TOPIC_RAWTX,
        zmq.TOPIC_SEQUENCE,
      })
      assert.is_not_nil(sub)

      -- Give time for connection to establish
      socket.sleep(0.1)
    end)

    after_each(function()
      if sub then sub:close() end
      if pub then pub:shutdown() end
    end)

    it("sends and receives hashblock notification", function()
      -- Sample block hash (32 bytes)
      local block_hash = hex_to_bytes("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
      assert.equals(32, #block_hash)

      pub:notify_hashblock(block_hash)

      local msg = sub:recv(1000)
      assert.is_not_nil(msg)
      assert.equals(3, #msg)  -- topic, body, sequence

      assert.equals(zmq.TOPIC_HASHBLOCK, msg[1])
      assert.equals(32, #msg[2])
      -- Body should be reversed (big-endian display order)
      assert.equals(reverse_bytes(block_hash), msg[2])
      assert.equals(4, #msg[3])  -- 4-byte sequence
      assert.equals(0, decode_le32(msg[3]))  -- First message, seq=0
    end)

    it("sends and receives hashtx notification", function()
      local txid = hex_to_bytes("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
      assert.equals(32, #txid)

      pub:notify_hashtx(txid)

      local msg = sub:recv(1000)
      assert.is_not_nil(msg)
      assert.equals(3, #msg)

      assert.equals(zmq.TOPIC_HASHTX, msg[1])
      assert.equals(reverse_bytes(txid), msg[2])
    end)

    it("sends and receives rawblock notification", function()
      local block_data = "This is mock block data for testing"

      pub:notify_rawblock(block_data)

      local msg = sub:recv(1000)
      assert.is_not_nil(msg)
      assert.equals(3, #msg)

      assert.equals(zmq.TOPIC_RAWBLOCK, msg[1])
      assert.equals(block_data, msg[2])
    end)

    it("sends and receives rawtx notification", function()
      local tx_data = "Mock transaction bytes"

      pub:notify_rawtx(tx_data)

      local msg = sub:recv(1000)
      assert.is_not_nil(msg)
      assert.equals(3, #msg)

      assert.equals(zmq.TOPIC_RAWTX, msg[1])
      assert.equals(tx_data, msg[2])
    end)

    it("sends and receives block connect sequence notification", function()
      local block_hash = hex_to_bytes("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")

      pub:notify_block_connect(block_hash)

      local msg = sub:recv(1000)
      assert.is_not_nil(msg)
      assert.equals(3, #msg)

      assert.equals(zmq.TOPIC_SEQUENCE, msg[1])
      -- Body: 32-byte hash (BE) + 1-byte label
      assert.equals(33, #msg[2])
      assert.equals(reverse_bytes(block_hash), msg[2]:sub(1, 32))
      assert.equals(string.byte('C'), msg[2]:byte(33))
    end)

    it("sends and receives block disconnect sequence notification", function()
      local block_hash = hex_to_bytes("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321")

      pub:notify_block_disconnect(block_hash)

      local msg = sub:recv(1000)
      assert.is_not_nil(msg)

      assert.equals(zmq.TOPIC_SEQUENCE, msg[1])
      assert.equals(33, #msg[2])
      assert.equals(string.byte('D'), msg[2]:byte(33))
    end)

    it("sends and receives tx acceptance sequence notification", function()
      local txid = hex_to_bytes("1111111111111111111111111111111111111111111111111111111111111111")
      local mempool_seq = 12345

      pub:notify_tx_acceptance(txid, mempool_seq)

      local msg = sub:recv(1000)
      assert.is_not_nil(msg)

      assert.equals(zmq.TOPIC_SEQUENCE, msg[1])
      -- Body: 32-byte hash + 1-byte label + 8-byte mempool_sequence
      assert.equals(41, #msg[2])
      assert.equals(reverse_bytes(txid), msg[2]:sub(1, 32))
      assert.equals(string.byte('A'), msg[2]:byte(33))
      assert.equals(mempool_seq, decode_le64(msg[2]:sub(34, 41)))
    end)

    it("sends and receives tx removal sequence notification", function()
      local txid = hex_to_bytes("2222222222222222222222222222222222222222222222222222222222222222")
      local mempool_seq = 67890

      pub:notify_tx_removal(txid, mempool_seq)

      local msg = sub:recv(1000)
      assert.is_not_nil(msg)

      assert.equals(zmq.TOPIC_SEQUENCE, msg[1])
      assert.equals(41, #msg[2])
      assert.equals(string.byte('R'), msg[2]:byte(33))
      assert.equals(mempool_seq, decode_le64(msg[2]:sub(34, 41)))
    end)

    it("increments sequence number per topic", function()
      local hash1 = string.rep("\x01", 32)
      local hash2 = string.rep("\x02", 32)
      local hash3 = string.rep("\x03", 32)

      -- Send 3 hashblock notifications
      pub:notify_hashblock(hash1)
      pub:notify_hashblock(hash2)
      pub:notify_hashblock(hash3)

      -- Receive and check sequences
      local msg1 = sub:recv(1000)
      local msg2 = sub:recv(1000)
      local msg3 = sub:recv(1000)

      assert.equals(0, decode_le32(msg1[3]))
      assert.equals(1, decode_le32(msg2[3]))
      assert.equals(2, decode_le32(msg3[3]))
    end)

    it("maintains separate sequence per topic", function()
      local hash = string.rep("\xaa", 32)
      local tx_data = "tx data"

      -- Send one of each
      pub:notify_hashblock(hash)
      pub:notify_hashtx(hash)
      pub:notify_rawblock(tx_data)

      -- Each should have sequence 0
      local msg1 = sub:recv(1000)
      local msg2 = sub:recv(1000)
      local msg3 = sub:recv(1000)

      assert.equals(0, decode_le32(msg1[3]))
      assert.equals(0, decode_le32(msg2[3]))
      assert.equals(0, decode_le32(msg3[3]))
    end)
  end)

  describe("notification manager", function()
    local has_zmq = zmq.is_available()

    if not has_zmq then
      pending("ZMQ not available, skipping integration tests")
      return
    end

    it("creates manager with no config", function()
      local mgr = zmq.new_notification_manager({})
      assert.is_not_nil(mgr)
      assert.is_false(mgr.enabled)
      mgr:shutdown()
    end)

    it("creates manager with endpoints", function()
      local port = 28450 + math.random(100)
      local endpoint = "tcp://127.0.0.1:" .. port

      local mgr = zmq.new_notification_manager({
        zmqpubhashblock = endpoint,
        zmqpubhashtx = endpoint,
      })
      assert.is_not_nil(mgr)
      assert.is_true(mgr.enabled)
      mgr:shutdown()
    end)

    it("tracks mempool sequence", function()
      local port = 28460 + math.random(100)
      local endpoint = "tcp://127.0.0.1:" .. port

      local mgr = zmq.new_notification_manager({
        zmqpubsequence = endpoint,
      })

      local sub = zmq.new_subscriber(endpoint, {zmq.TOPIC_SEQUENCE})
      socket.sleep(0.1)

      local txid = string.rep("\x11", 32)

      mgr:on_tx_added(txid, nil)
      mgr:on_tx_added(txid, nil)
      mgr:on_tx_removed(txid)

      local msg1 = sub:recv(1000)
      local msg2 = sub:recv(1000)
      local msg3 = sub:recv(1000)

      -- Mempool sequences should be 1, 2, 3
      assert.equals(1, decode_le64(msg1[2]:sub(34, 41)))
      assert.equals(2, decode_le64(msg2[2]:sub(34, 41)))
      assert.equals(3, decode_le64(msg3[2]:sub(34, 41)))

      sub:close()
      mgr:shutdown()
    end)

    it("publishes block connected events", function()
      local port = 28470 + math.random(100)
      local endpoint = "tcp://127.0.0.1:" .. port

      local mgr = zmq.new_notification_manager({
        zmqpubhashblock = endpoint,
        zmqpubrawblock = endpoint,
        zmqpubsequence = endpoint,
      })

      local sub = zmq.new_subscriber(endpoint, {
        zmq.TOPIC_HASHBLOCK,
        zmq.TOPIC_RAWBLOCK,
        zmq.TOPIC_SEQUENCE,
      })
      socket.sleep(0.1)

      local block_hash = string.rep("\xbb", 32)
      local block_data = "raw block bytes"

      mgr:on_block_connected(block_hash, block_data)

      -- Should receive hashblock, rawblock, and sequence (connect)
      local received = {}
      for _ = 1, 3 do
        local msg = sub:recv(1000)
        if msg then
          received[msg[1]] = msg
        end
      end

      assert.is_not_nil(received[zmq.TOPIC_HASHBLOCK])
      assert.is_not_nil(received[zmq.TOPIC_RAWBLOCK])
      assert.is_not_nil(received[zmq.TOPIC_SEQUENCE])

      assert.equals(reverse_bytes(block_hash), received[zmq.TOPIC_HASHBLOCK][2])
      assert.equals(block_data, received[zmq.TOPIC_RAWBLOCK][2])
      assert.equals(string.byte('C'), received[zmq.TOPIC_SEQUENCE][2]:byte(33))

      sub:close()
      mgr:shutdown()
    end)
  end)
end)
