--- P2P handshake integration tests
-- Tests the version/verack handshake sequence using mock peers

local helpers = require("spec.helpers")

describe("P2P handshake", function()
  local peer_module
  local p2p
  local consensus
  local net

  setup(function()
    package.path = "src/?.lua;" .. package.path
    -- Set up lunarblock.X aliases
    package.preload["lunarblock.types"] = function() return require("types") end
    package.preload["lunarblock.serialize"] = function() return require("serialize") end
    package.preload["lunarblock.crypto"] = function() return require("crypto") end
    package.preload["lunarblock.script"] = function() return require("script") end
    package.preload["lunarblock.consensus"] = function() return require("consensus") end
    package.preload["lunarblock.p2p"] = function() return require("p2p") end
    package.preload["lunarblock.peer"] = function() return require("peer") end

    peer_module = require("peer")
    p2p = require("p2p")
    consensus = require("consensus")
  end)

  before_each(function()
    net = consensus.networks.regtest
  end)

  describe("version message construction", function()
    it("constructs a valid version message payload", function()
      local payload = p2p.serialize_version({
        version = p2p.PROTOCOL_VERSION,
        services = p2p.SERVICES.NODE_NETWORK,
        timestamp = os.time(),
        recv_services = 0,
        recv_ip = "127.0.0.1",
        recv_port = 18444,
        from_services = p2p.SERVICES.NODE_NETWORK,
        from_ip = "0.0.0.0",
        from_port = 0,
        nonce = 12345,
        user_agent = "/LunarBlock:test/",
        start_height = 0,
        relay = true,
      })

      assert.is_not_nil(payload)
      assert.is_true(#payload >= 85)  -- Minimum version message size

      -- Deserialize and verify
      local ver = p2p.deserialize_version(payload)
      assert.is_true(ver.version >= 70015)
      assert.equals("/LunarBlock:test/", ver.user_agent)
      assert.equals(12345, ver.nonce)
      assert.equals(0, ver.start_height)
    end)

    it("includes protocol version >= 70015 for segwit", function()
      local payload = p2p.serialize_version({
        version = p2p.PROTOCOL_VERSION,
        services = 9,
        timestamp = os.time(),
        recv_services = 0,
        recv_ip = "0.0.0.0",
        recv_port = 0,
        from_services = 9,
        from_ip = "0.0.0.0",
        from_port = 0,
        nonce = 1,
        user_agent = "/test/",
        start_height = 100,
        relay = true,
      })

      local ver = p2p.deserialize_version(payload)
      assert.is_true(ver.version >= 70015)
    end)
  end)

  describe("message wrapping", function()
    it("wraps messages with correct network magic for mainnet", function()
      local mainnet = consensus.networks.mainnet
      local payload = "test"
      local wrapped = p2p.make_message(mainnet.magic_bytes, "ping", payload)

      -- Check magic bytes at start
      local magic = wrapped:sub(1, 4)
      assert.equals(helpers.hex_to_bytes("f9beb4d9"), magic)
    end)

    it("wraps messages with correct network magic for regtest", function()
      local regtest = consensus.networks.regtest
      local payload = "test"
      local wrapped = p2p.make_message(regtest.magic_bytes, "ping", payload)

      -- Check magic bytes at start
      local magic = wrapped:sub(1, 4)
      assert.equals(helpers.hex_to_bytes("fabfb5da"), magic)
    end)

    it("includes correct command in header", function()
      local wrapped = p2p.make_message(net.magic_bytes, "version", "payload")
      local header = p2p.parse_header(wrapped:sub(1, p2p.HEADER_SIZE))

      assert.equals("version", header.command)
    end)

    it("includes correct payload length", function()
      local payload = "hello world"
      local wrapped = p2p.make_message(net.magic_bytes, "ping", payload)
      local header = p2p.parse_header(wrapped:sub(1, p2p.HEADER_SIZE))

      assert.equals(#payload, header.length)
    end)

    it("includes valid checksum", function()
      local payload = "test payload"
      local wrapped = p2p.make_message(net.magic_bytes, "addr", payload)
      local header = p2p.parse_header(wrapped:sub(1, p2p.HEADER_SIZE))
      local msg_payload = wrapped:sub(p2p.HEADER_SIZE + 1)

      assert.is_true(p2p.verify_checksum(msg_payload, header.checksum))
    end)
  end)

  describe("verack response", function()
    it("verack message has empty payload", function()
      local wrapped = p2p.make_message(net.magic_bytes, "verack", "")
      local header = p2p.parse_header(wrapped:sub(1, p2p.HEADER_SIZE))

      assert.equals("verack", header.command)
      assert.equals(0, header.length)
    end)
  end)

  describe("mock peer handshake", function()
    it("mock peer captures sent messages", function()
      local mock = helpers.mock_peer({
        start_height = 100,
        user_agent = "/TestNode/",
      })

      mock:send_message("version", "test_payload")
      mock:send_message("verack", "")

      assert.equals(2, #mock.sent)
      assert.equals("version", mock.sent[1].command)
      assert.equals("test_payload", mock.sent[1].payload)
      assert.equals("verack", mock.sent[2].command)
      assert.equals("", mock.sent[2].payload)
    end)

    it("mock peer filters messages by command", function()
      local mock = helpers.mock_peer()

      mock:send_message("ping", "1")
      mock:send_message("pong", "2")
      mock:send_message("ping", "3")

      local pings = mock:messages_for("ping")
      assert.equals(2, #pings)
      assert.equals("1", pings[1].payload)
      assert.equals("3", pings[2].payload)
    end)
  end)

  describe("ping/pong", function()
    it("serializes and deserializes ping nonce", function()
      local nonce = 123456789012345
      local payload = p2p.serialize_ping(nonce)

      assert.equals(8, #payload)

      local decoded = p2p.deserialize_ping(payload)
      assert.equals(nonce, decoded)
    end)

    it("round-trips various nonce values", function()
      local nonces = { 0, 1, 255, 65535, 0xFFFFFFFF, 2^52 - 1 }

      for _, n in ipairs(nonces) do
        local payload = p2p.serialize_ping(n)
        local decoded = p2p.deserialize_ping(payload)
        assert.equals(n, decoded)
      end
    end)
  end)

  describe("sendheaders message", function()
    it("sendheaders has empty payload", function()
      local wrapped = p2p.make_message(net.magic_bytes, "sendheaders", "")
      local header = p2p.parse_header(wrapped:sub(1, p2p.HEADER_SIZE))

      assert.equals("sendheaders", header.command)
      assert.equals(0, header.length)
    end)
  end)

  describe("feefilter message", function()
    it("serializes and deserializes fee rate", function()
      local fee_rate = 1000  -- 1 sat/vB minimum
      local payload = p2p.serialize_feefilter(fee_rate)

      assert.equals(8, #payload)

      local decoded = p2p.deserialize_feefilter(payload)
      assert.equals(fee_rate, decoded)
    end)
  end)

  describe("sendcmpct message", function()
    it("serializes and deserializes compact block settings", function()
      local payload = p2p.serialize_sendcmpct(true, 2)

      local decoded = p2p.deserialize_sendcmpct(payload)
      assert.is_true(decoded.announce)
      assert.equals(2, decoded.version)
    end)

    it("round-trips compact block settings", function()
      local settings = {
        { announce = true, version = 1 },
        { announce = false, version = 2 },
        { announce = true, version = 2 },
      }

      for _, s in ipairs(settings) do
        local payload = p2p.serialize_sendcmpct(s.announce, s.version)
        local decoded = p2p.deserialize_sendcmpct(payload)
        assert.equals(s.announce, decoded.announce)
        assert.equals(s.version, decoded.version)
      end
    end)
  end)
end)
