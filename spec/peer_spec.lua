local peer_module = require("lunarblock.peer")
local p2p = require("lunarblock.p2p")
local consensus = require("lunarblock.consensus")
local socket = require("socket")

describe("peer", function()
  local mainnet = consensus.networks.mainnet

  describe("Peer.new", function()
    it("creates a peer with initial disconnected state", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet, 100)
      assert.equal(peer_module.STATE.DISCONNECTED, p.state)
      assert.equal("127.0.0.1", p.ip)
      assert.equal(8333, p.port)
      assert.equal(100, p.our_height)
      assert.equal("", p.recv_buffer)
      assert.is_nil(p.socket)
    end)

    it("uses default port from network if not specified", function()
      local p = peer_module.new("127.0.0.1", nil, mainnet)
      assert.equal(8333, p.port)
    end)

    it("initializes all tracking tables as empty", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      assert.same({}, p.message_handlers)
      assert.same({}, p.inflight_blocks)
      assert.same({}, p.inflight_txs)
      assert.same({}, p.known_blocks)
      assert.same({}, p.known_txs)
    end)
  end)

  describe("Peer:on (message handler registration)", function()
    it("registers custom message handlers", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      local called = false
      p:on("inv", function(peer, payload)
        called = true
      end)
      assert.is_function(p.message_handlers["inv"])
    end)
  end)

  describe("message buffering", function()
    it("accumulates partial data in recv_buffer", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      -- Simulate partial data
      p.recv_buffer = "partial"
      assert.equal("partial", p.recv_buffer)
      p.recv_buffer = p.recv_buffer .. "_more"
      assert.equal("partial_more", p.recv_buffer)
    end)
  end)

  describe("connection with mock server", function()
    local server
    local server_port = 19333

    -- Create a simple TCP server for testing
    before_each(function()
      server = socket.tcp()
      server:setoption("reuseaddr", true)
      local ok, err = server:bind("127.0.0.1", server_port)
      if not ok then
        -- Try next port if bind fails
        server_port = server_port + 1
        server:bind("127.0.0.1", server_port)
      end
      server:listen(1)
      server:settimeout(0.1)
    end)

    after_each(function()
      if server then
        server:close()
        server = nil
      end
    end)

    it("connects to a server and transitions to CONNECTED state", function()
      local p = peer_module.new("127.0.0.1", server_port, mainnet)
      local ok = p:connect(1)
      assert.is_true(ok)
      assert.equal(peer_module.STATE.CONNECTED, p.state)
      assert.is_not_nil(p.socket)
      p:disconnect()
    end)

    it("fails connection to non-existent server", function()
      local p = peer_module.new("127.0.0.1", 19999, mainnet)
      local ok, err = p:connect(0.1)
      assert.is_false(ok)
      assert.equal(peer_module.STATE.DISCONNECTED, p.state)
    end)

    it("transitions to DISCONNECTED after disconnect()", function()
      local p = peer_module.new("127.0.0.1", server_port, mainnet)
      p:connect(1)
      assert.equal(peer_module.STATE.CONNECTED, p.state)
      p:disconnect("test disconnect")
      assert.equal(peer_module.STATE.DISCONNECTED, p.state)
      assert.is_nil(p.socket)
      assert.equal("test disconnect", p.disconnect_reason)
    end)
  end)

  describe("version handshake with mock server", function()
    local server
    local server_port = 19334
    local client_sock

    before_each(function()
      server = socket.tcp()
      server:setoption("reuseaddr", true)
      local ok = server:bind("127.0.0.1", server_port)
      if not ok then
        server_port = server_port + 1
        server:bind("127.0.0.1", server_port)
      end
      server:listen(1)
      server:settimeout(1)
    end)

    after_each(function()
      if client_sock then
        client_sock:close()
        client_sock = nil
      end
      if server then
        server:close()
        server = nil
      end
    end)

    it("sends version and transitions to VERSION_SENT", function()
      local p = peer_module.new("127.0.0.1", server_port, mainnet, 500)
      p:connect(1)
      -- Accept connection on server side
      client_sock = server:accept()
      client_sock:settimeout(1)

      p:start_handshake()
      assert.equal(peer_module.STATE.VERSION_SENT, p.state)
      assert.is_true(p.nonce > 0)

      -- Server should receive version message
      local data = client_sock:receive(200)
      assert.is_not_nil(data)
      assert.is_true(#data >= p2p.HEADER_SIZE)

      -- Parse header
      local header = p2p.parse_header(data:sub(1, p2p.HEADER_SIZE))
      assert.equal("version", header.command)

      p:disconnect()
    end)

    it("completes handshake with version/verack exchange", function()
      local p = peer_module.new("127.0.0.1", server_port, mainnet, 500)
      p:connect(1)
      client_sock = server:accept()
      client_sock:settimeout(1)

      p:start_handshake()
      assert.equal(peer_module.STATE.VERSION_SENT, p.state)

      -- Read the version message from peer
      local data = client_sock:receive(200)
      assert.is_not_nil(data)

      -- Server sends version back
      local server_version = p2p.serialize_version({
        version = 70016,
        services = 9,
        timestamp = os.time(),
        recv_services = 9,
        recv_ip = "127.0.0.1",
        recv_port = server_port,
        from_services = 9,
        from_ip = "127.0.0.1",
        from_port = 8333,
        nonce = 12345,
        user_agent = "/MockServer:1.0/",
        start_height = 800000,
        relay = true,
      })
      local version_msg = p2p.make_message(mainnet.magic_bytes, "version", server_version)
      client_sock:send(version_msg)

      -- Process peer's messages
      socket.sleep(0.05)
      p:process_messages()
      assert.equal(peer_module.STATE.VERACK_SENT, p.state)
      assert.equal("/MockServer:1.0/", p.user_agent)
      assert.equal(800000, p.start_height)

      -- Read verack that peer sent
      local verack_data = client_sock:receive(50)

      -- Server sends verack
      local verack_msg = p2p.make_message(mainnet.magic_bytes, "verack", "")
      client_sock:send(verack_msg)

      -- Process verack
      socket.sleep(0.05)
      p:process_messages()
      assert.equal(peer_module.STATE.ESTABLISHED, p.state)

      p:disconnect()
    end)

    it("rejects old protocol versions", function()
      local p = peer_module.new("127.0.0.1", server_port, mainnet)
      p:connect(1)
      client_sock = server:accept()
      client_sock:settimeout(1)

      p:start_handshake()

      -- Read version from peer
      client_sock:receive(200)

      -- Send old protocol version
      local old_version = p2p.serialize_version({
        version = 60002,  -- Too old
        services = 1,
        timestamp = os.time(),
        recv_services = 0,
        recv_ip = "0.0.0.0",
        recv_port = 0,
        from_services = 1,
        from_ip = "0.0.0.0",
        from_port = 0,
        nonce = 99,
        user_agent = "/OldNode/",
        start_height = 100,
        relay = true,
      })
      local msg = p2p.make_message(mainnet.magic_bytes, "version", old_version)
      client_sock:send(msg)

      socket.sleep(0.05)
      p:process_messages()
      assert.equal(peer_module.STATE.DISCONNECTED, p.state)
      assert.is_true(p.disconnect_reason:find("protocol version too old") ~= nil)
    end)
  end)

  describe("ping/pong", function()
    local server
    local server_port = 19335
    local client_sock

    before_each(function()
      server = socket.tcp()
      server:setoption("reuseaddr", true)
      local ok = server:bind("127.0.0.1", server_port)
      if not ok then
        server_port = server_port + 1
        server:bind("127.0.0.1", server_port)
      end
      server:listen(1)
      server:settimeout(1)
    end)

    after_each(function()
      if client_sock then
        client_sock:close()
        client_sock = nil
      end
      if server then
        server:close()
        server = nil
      end
    end)

    it("sends ping and measures latency from pong", function()
      local p = peer_module.new("127.0.0.1", server_port, mainnet)
      p:connect(1)
      p.state = peer_module.STATE.ESTABLISHED
      client_sock = server:accept()
      client_sock:settimeout(1)

      -- Send ping
      p:send_ping()
      assert.is_true(p.ping_nonce > 0)
      assert.is_true(p.last_ping_time > 0)

      -- Read ping on server
      local data = client_sock:receive(100)
      local header = p2p.parse_header(data:sub(1, p2p.HEADER_SIZE))
      assert.equal("ping", header.command)
      local payload = data:sub(p2p.HEADER_SIZE + 1, p2p.HEADER_SIZE + header.length)
      local nonce = p2p.deserialize_ping(payload)

      -- Send pong back with same nonce
      socket.sleep(0.01)  -- Small delay for latency measurement
      local pong_msg = p2p.make_message(mainnet.magic_bytes, "pong", p2p.serialize_ping(nonce))
      client_sock:send(pong_msg)

      socket.sleep(0.05)
      p:process_messages()
      assert.is_true(p.latency_ms > 0)
      assert.is_true(p.last_pong_time > p.last_ping_time)

      p:disconnect()
    end)

    it("responds to ping with pong", function()
      local p = peer_module.new("127.0.0.1", server_port, mainnet)
      p:connect(1)
      p.state = peer_module.STATE.ESTABLISHED
      client_sock = server:accept()
      client_sock:settimeout(1)

      -- Send ping from server
      local ping_nonce = 123456789
      local ping_msg = p2p.make_message(mainnet.magic_bytes, "ping", p2p.serialize_ping(ping_nonce))
      client_sock:send(ping_msg)

      socket.sleep(0.05)
      p:process_messages()

      -- Read pong on server
      local data = client_sock:receive(100)
      assert.is_not_nil(data)
      local header = p2p.parse_header(data:sub(1, p2p.HEADER_SIZE))
      assert.equal("pong", header.command)
      local payload = data:sub(p2p.HEADER_SIZE + 1, p2p.HEADER_SIZE + header.length)
      local nonce = p2p.deserialize_ping(payload)
      assert.equal(ping_nonce, nonce)

      p:disconnect()
    end)
  end)

  describe("wrong network magic", function()
    local server
    local server_port = 19336
    local client_sock

    before_each(function()
      server = socket.tcp()
      server:setoption("reuseaddr", true)
      local ok = server:bind("127.0.0.1", server_port)
      if not ok then
        server_port = server_port + 1
        server:bind("127.0.0.1", server_port)
      end
      server:listen(1)
      server:settimeout(1)
    end)

    after_each(function()
      if client_sock then
        client_sock:close()
        client_sock = nil
      end
      if server then
        server:close()
        server = nil
      end
    end)

    it("disconnects on wrong magic bytes", function()
      local p = peer_module.new("127.0.0.1", server_port, mainnet)
      p:connect(1)
      p.state = peer_module.STATE.ESTABLISHED
      client_sock = server:accept()
      client_sock:settimeout(1)

      -- Send message with testnet magic on mainnet connection
      local testnet = consensus.networks.testnet
      local wrong_msg = p2p.make_message(testnet.magic_bytes, "ping", p2p.serialize_ping(123))
      client_sock:send(wrong_msg)

      socket.sleep(0.05)
      p:process_messages()
      assert.equal(peer_module.STATE.DISCONNECTED, p.state)
      assert.equal("wrong network magic", p.disconnect_reason)
    end)
  end)

  describe("timeout detection", function()
    it("detects handshake timeout", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.VERSION_SENT
      -- Simulate last_recv 100 seconds ago
      p.last_recv = socket.gettime() - 100

      p:check_timeouts()
      assert.equal(peer_module.STATE.DISCONNECTED, p.state)
      assert.equal("handshake timeout", p.disconnect_reason)
    end)

    it("does not timeout established connections during handshake timeout window", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.ESTABLISHED
      p.last_recv = socket.gettime() - 100
      p.last_send = socket.gettime()  -- Recent send

      p:check_timeouts()
      -- Should still be established (100s < 1200s inactivity timeout)
      assert.equal(peer_module.STATE.ESTABLISHED, p.state)
    end)

    it("detects 20-minute inactivity timeout", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.ESTABLISHED
      -- Simulate last_recv 25 minutes ago
      p.last_recv = socket.gettime() - 1500

      p:check_timeouts()
      assert.equal(peer_module.STATE.DISCONNECTED, p.state)
      assert.is_true(p.disconnect_reason:find("inactivity timeout") ~= nil)
    end)
  end)

  describe("message handler dispatch", function()
    it("handles sendheaders message", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.ESTABLISHED
      assert.is_false(p.send_headers)

      -- Simulate receiving sendheaders
      -- We'll inject it into recv_buffer and call process_messages
      local msg = p2p.make_message(mainnet.magic_bytes, "sendheaders", "")
      p.recv_buffer = msg

      -- Need a mock socket that returns nothing
      p.socket = setmetatable({}, {
        __index = function(_, key)
          if key == "receive" then
            return function() return nil, "timeout", "" end
          end
        end
      })

      p:process_messages()
      assert.is_true(p.send_headers)
    end)

    it("handles feefilter message", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.ESTABLISHED
      assert.equal(0, p.fee_filter)

      local payload = p2p.serialize_feefilter(2000)
      local msg = p2p.make_message(mainnet.magic_bytes, "feefilter", payload)
      p.recv_buffer = msg
      p.socket = setmetatable({}, {
        __index = function(_, key)
          if key == "receive" then
            return function() return nil, "timeout", "" end
          end
        end
      })

      p:process_messages()
      assert.equal(2000, p.fee_filter)
    end)

    it("handles sendcmpct message", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.ESTABLISHED
      assert.is_false(p.send_compact)

      local payload = p2p.serialize_sendcmpct(true, 2)
      local msg = p2p.make_message(mainnet.magic_bytes, "sendcmpct", payload)
      p.recv_buffer = msg
      p.socket = setmetatable({}, {
        __index = function(_, key)
          if key == "receive" then
            return function() return nil, "timeout", "" end
          end
        end
      })

      p:process_messages()
      assert.is_true(p.send_compact)
    end)

    it("dispatches to custom handlers", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.ESTABLISHED

      local received_payload = nil
      p:on("addr", function(peer, payload)
        received_payload = payload
      end)

      local addr_payload = "test_payload"
      local msg = p2p.make_message(mainnet.magic_bytes, "addr", addr_payload)
      p.recv_buffer = msg
      p.socket = setmetatable({}, {
        __index = function(_, key)
          if key == "receive" then
            return function() return nil, "timeout", "" end
          end
        end
      })

      p:process_messages()
      assert.equal(addr_payload, received_payload)
    end)
  end)

  describe("partial message buffering", function()
    it("waits for complete message before parsing", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.ESTABLISHED

      -- Create a full message
      local msg = p2p.make_message(mainnet.magic_bytes, "ping", p2p.serialize_ping(123))

      -- Split it in half
      local half = math.floor(#msg / 2)
      local first_half = msg:sub(1, half)
      local second_half = msg:sub(half + 1)

      -- First read: only partial data
      p.recv_buffer = first_half
      p.socket = setmetatable({}, {
        __index = function(_, key)
          if key == "receive" then
            return function() return nil, "timeout", "" end
          end
        end
      })

      local messages = p:recv_messages()
      assert.equal(0, #messages)
      assert.equal(first_half, p.recv_buffer)

      -- Second read: remaining data
      p.recv_buffer = p.recv_buffer .. second_half
      messages = p:recv_messages()
      assert.equal(1, #messages)
      assert.equal("ping", messages[1].command)
    end)

    it("parses multiple messages in single buffer", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.ESTABLISHED

      -- Create two messages
      local msg1 = p2p.make_message(mainnet.magic_bytes, "ping", p2p.serialize_ping(111))
      local msg2 = p2p.make_message(mainnet.magic_bytes, "ping", p2p.serialize_ping(222))

      p.recv_buffer = msg1 .. msg2
      p.socket = setmetatable({}, {
        __index = function(_, key)
          if key == "receive" then
            return function() return nil, "timeout", "" end
          end
        end
      })

      local messages = p:recv_messages()
      assert.equal(2, #messages)
      assert.equal("ping", messages[1].command)
      assert.equal("ping", messages[2].command)
    end)
  end)

  describe("pre-handshake filtering", function()
    local mock_socket = function()
      return setmetatable({}, {
        __index = function(_, key)
          if key == "receive" then
            return function() return nil, "timeout", "" end
          end
        end
      })
    end

    it("rejects non-version message before version received", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.CONNECTED
      p.socket = mock_socket()
      assert.is_false(p.version_received)
      assert.is_false(p.handshake_complete)

      -- Send ping before version - should be rejected
      local ping_msg = p2p.make_message(mainnet.magic_bytes, "ping", p2p.serialize_ping(123))
      p.recv_buffer = ping_msg

      local processed = p:process_messages()
      assert.equal(0, #processed)  -- Message dropped
      assert.equal(10, p.ban_score)  -- Misbehavior scored
    end)

    it("allows version message before handshake", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.VERSION_SENT
      p.socket = mock_socket()

      local version_payload = p2p.serialize_version({
        version = 70016,
        services = 9,
        timestamp = os.time(),
        recv_services = 0,
        recv_ip = "0.0.0.0",
        recv_port = 0,
        from_services = 9,
        from_ip = "0.0.0.0",
        from_port = 0,
        nonce = 12345,
        user_agent = "/Test/",
        start_height = 800000,
        relay = true,
      })
      local msg = p2p.make_message(mainnet.magic_bytes, "version", version_payload)
      p.recv_buffer = msg

      local processed = p:process_messages()
      assert.equal(1, #processed)
      assert.is_true(p.version_received)
      assert.equal(0, p.ban_score)
    end)

    it("allows pre-handshake messages after version but before verack", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.VERACK_SENT
      p.version_received = true
      p.socket = mock_socket()

      -- sendheaders is allowed before handshake complete
      local msg = p2p.make_message(mainnet.magic_bytes, "sendheaders", "")
      p.recv_buffer = msg

      local processed = p:process_messages()
      assert.equal(1, #processed)
      assert.is_true(p.send_headers)
      assert.equal(0, p.ban_score)
    end)

    it("rejects data messages before verack", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.VERACK_SENT
      p.version_received = true
      p.handshake_complete = false
      p.socket = mock_socket()

      -- inv message is not allowed before handshake
      -- (using empty payload for simplicity)
      local msg = p2p.make_message(mainnet.magic_bytes, "inv", "\x00")
      p.recv_buffer = msg

      local processed = p:process_messages()
      assert.equal(0, #processed)  -- Message dropped
      assert.equal(10, p.ban_score)
    end)

    it("allows all messages after handshake complete", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.ESTABLISHED
      p.version_received = true
      p.handshake_complete = true
      p.socket = mock_socket()

      -- ping should be allowed after handshake
      local ping_msg = p2p.make_message(mainnet.magic_bytes, "ping", p2p.serialize_ping(123))
      p.recv_buffer = ping_msg

      local processed = p:process_messages()
      assert.equal(1, #processed)
      assert.equal("ping", processed[1].command)
      assert.equal(0, p.ban_score)
    end)

    it("handles wtxidrelay before verack", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.VERACK_SENT
      p.version_received = true
      p.socket = mock_socket()

      -- wtxidrelay is allowed (and expected) before verack
      local msg = p2p.make_message(mainnet.magic_bytes, "wtxidrelay", "")
      p.recv_buffer = msg

      local processed = p:process_messages()
      assert.equal(1, #processed)
      assert.is_true(p.wtxid_relay)
      assert.equal(0, p.ban_score)
    end)

    it("handles sendaddrv2 before verack", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.VERACK_SENT
      p.version_received = true
      p.socket = mock_socket()

      -- sendaddrv2 is allowed before verack
      local msg = p2p.make_message(mainnet.magic_bytes, "sendaddrv2", "")
      p.recv_buffer = msg

      local processed = p:process_messages()
      assert.equal(1, #processed)
      assert.is_true(p.send_addrv2)
      assert.equal(0, p.ban_score)
    end)

    it("accumulates misbehavior score and disconnects at threshold", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.CONNECTED
      p.socket = mock_socket()

      -- Send 10 invalid messages (10 points each = 100 total = disconnect)
      for i = 1, 10 do
        local ping_msg = p2p.make_message(mainnet.magic_bytes, "ping", p2p.serialize_ping(i))
        p.recv_buffer = ping_msg
        p:process_messages()
        if p.state == peer_module.STATE.DISCONNECTED then
          break
        end
      end

      assert.equal(peer_module.STATE.DISCONNECTED, p.state)
      assert.is_true(p.disconnect_reason:find("misbehaving") ~= nil)
    end)

    it("sets handshake_complete after full version/verack exchange", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.VERSION_SENT
      p.socket = mock_socket()

      -- Receive version from peer
      local version_payload = p2p.serialize_version({
        version = 70016,
        services = 9,
        timestamp = os.time(),
        recv_services = 0,
        recv_ip = "0.0.0.0",
        recv_port = 0,
        from_services = 9,
        from_ip = "0.0.0.0",
        from_port = 0,
        nonce = 12345,
        user_agent = "/Test/",
        start_height = 800000,
        relay = true,
      })
      local version_msg = p2p.make_message(mainnet.magic_bytes, "version", version_payload)
      p.recv_buffer = version_msg
      p:process_messages()

      assert.is_true(p.version_received)
      assert.is_false(p.handshake_complete)

      -- Receive verack from peer
      local verack_msg = p2p.make_message(mainnet.magic_bytes, "verack", "")
      p.recv_buffer = verack_msg
      p:process_messages()

      assert.is_true(p.handshake_complete)
      assert.equal(peer_module.STATE.ESTABLISHED, p.state)
    end)
  end)

  describe("handshake timeout", function()
    it("disconnects if handshake not complete within 60 seconds", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.VERSION_SENT
      p.handshake_start_time = socket.gettime() - 61  -- 61 seconds ago
      p.last_recv = socket.gettime() - 10
      p.handshake_complete = false

      p:check_timeouts()
      assert.equal(peer_module.STATE.DISCONNECTED, p.state)
      assert.equal("handshake timeout", p.disconnect_reason)
    end)

    it("does not timeout if handshake completes in time", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.VERSION_SENT
      p.handshake_start_time = socket.gettime() - 30  -- 30 seconds ago
      p.last_recv = socket.gettime()
      p.handshake_complete = false

      p:check_timeouts()
      assert.equal(peer_module.STATE.VERSION_SENT, p.state)  -- Still connected
    end)

    it("does not timeout established connections", function()
      local p = peer_module.new("127.0.0.1", 8333, mainnet)
      p.state = peer_module.STATE.ESTABLISHED
      p.handshake_start_time = socket.gettime() - 100  -- 100 seconds ago
      p.handshake_complete = true
      p.last_recv = socket.gettime()

      p:check_timeouts()
      assert.equal(peer_module.STATE.ESTABLISHED, p.state)
    end)

    it("uses HANDSHAKE_TIMEOUT constant of 60 seconds", function()
      assert.equal(60, peer_module.HANDSHAKE_TIMEOUT)
    end)
  end)

  describe("PRE_HANDSHAKE_ALLOWED list", function()
    it("contains version", function()
      assert.is_true(peer_module.PRE_HANDSHAKE_ALLOWED.version)
    end)

    it("contains verack", function()
      assert.is_true(peer_module.PRE_HANDSHAKE_ALLOWED.verack)
    end)

    it("contains wtxidrelay", function()
      assert.is_true(peer_module.PRE_HANDSHAKE_ALLOWED.wtxidrelay)
    end)

    it("contains sendaddrv2", function()
      assert.is_true(peer_module.PRE_HANDSHAKE_ALLOWED.sendaddrv2)
    end)

    it("contains sendheaders", function()
      assert.is_true(peer_module.PRE_HANDSHAKE_ALLOWED.sendheaders)
    end)

    it("does not contain inv", function()
      assert.is_nil(peer_module.PRE_HANDSHAKE_ALLOWED.inv)
    end)

    it("does not contain tx", function()
      assert.is_nil(peer_module.PRE_HANDSHAKE_ALLOWED.tx)
    end)

    it("does not contain block", function()
      assert.is_nil(peer_module.PRE_HANDSHAKE_ALLOWED.block)
    end)
  end)
end)
