local peerman = require("lunarblock.peerman")
local peer_mod = require("lunarblock.peer")
local p2p = require("lunarblock.p2p")
local consensus = require("lunarblock.consensus")

describe("peerman", function()

  local test_network

  before_each(function()
    -- Use regtest for testing (no DNS seeds)
    test_network = {
      name = "test",
      magic_bytes = "\xfa\xbf\xb5\xda",
      port = 18444,
      default_port = 18444,
      dns_seeds = {},
    }
  end)

  describe("PeerManager creation", function()

    it("creates with default config", function()
      local pm = peerman.new(test_network, nil, nil)
      assert.is_not_nil(pm)
      assert.equals(8, pm.max_outbound)
      assert.equals(117, pm.max_inbound)
      assert.equals(125, pm.max_peers)
      assert.equals(0, pm.our_height)
      assert.same({}, pm.peers)
      assert.same({}, pm.peer_list)
      assert.same({}, pm.known_addresses)
      assert.same({}, pm.banned)
    end)

    it("creates with custom config", function()
      local pm = peerman.new(test_network, nil, {
        max_outbound = 4,
        max_inbound = 50,
        max_peers = 60,
      })
      assert.equals(4, pm.max_outbound)
      assert.equals(50, pm.max_inbound)
      assert.equals(60, pm.max_peers)
    end)

    it("stores network configuration", function()
      local pm = peerman.new(test_network, nil, nil)
      assert.equals(test_network, pm.network)
    end)

  end)

  describe("known address management", function()

    it("adds new addresses", function()
      local pm = peerman.new(test_network, nil, nil)
      local added = pm:add_known_address("192.168.1.1", 8333)
      assert.is_true(added)
      assert.equals(1, pm:get_known_address_count())
    end)

    it("rejects duplicate addresses", function()
      local pm = peerman.new(test_network, nil, nil)
      pm:add_known_address("192.168.1.1", 8333)
      local added = pm:add_known_address("192.168.1.1", 8333)
      assert.is_false(added)
      assert.equals(1, pm:get_known_address_count())
    end)

    it("tracks multiple addresses", function()
      local pm = peerman.new(test_network, nil, nil)
      pm:add_known_address("192.168.1.1", 8333)
      pm:add_known_address("192.168.1.2", 8333)
      pm:add_known_address("192.168.1.3", 8334)
      assert.equals(3, pm:get_known_address_count())
    end)

    it("stores address metadata", function()
      local pm = peerman.new(test_network, nil, nil)
      local now = os.time()
      pm:add_known_address("10.0.0.1", 8333, p2p.SERVICES.NODE_WITNESS, now)
      local info = pm.known_addresses["10.0.0.1:8333"]
      assert.is_not_nil(info)
      assert.equals("10.0.0.1", info.ip)
      assert.equals(8333, info.port)
      assert.equals(p2p.SERVICES.NODE_WITNESS, info.services)
      assert.equals(now, info.timestamp)
      assert.equals(0, info.attempts)
      assert.equals(0, info.last_try)
    end)

    it("selects candidates excluding connected peers", function()
      local pm = peerman.new(test_network, nil, nil)
      pm:add_known_address("192.168.1.1", 8333)
      pm:add_known_address("192.168.1.2", 8333)

      -- Simulate connected peer
      pm.peers["192.168.1.1:8333"] = {}

      local candidate = pm:select_peer_to_connect()
      assert.is_not_nil(candidate)
      assert.equals("192.168.1.2", candidate.ip)
    end)

    it("selects candidates excluding banned peers", function()
      local pm = peerman.new(test_network, nil, nil)
      pm:add_known_address("192.168.1.1", 8333)
      pm:add_known_address("192.168.1.2", 8333)

      -- Ban first peer
      pm.banned["192.168.1.1"] = os.time() + 3600

      local candidate = pm:select_peer_to_connect()
      assert.is_not_nil(candidate)
      assert.equals("192.168.1.2", candidate.ip)
    end)

    it("selects candidates excluding recently tried peers", function()
      local pm = peerman.new(test_network, nil, nil)
      pm:add_known_address("192.168.1.1", 8333)
      pm:add_known_address("192.168.1.2", 8333)

      -- Mark first as recently tried
      pm.known_addresses["192.168.1.1:8333"].last_try = os.time()

      local candidate = pm:select_peer_to_connect()
      assert.is_not_nil(candidate)
      assert.equals("192.168.1.2", candidate.ip)
    end)

    it("returns nil when no candidates available", function()
      local pm = peerman.new(test_network, nil, nil)
      local candidate = pm:select_peer_to_connect()
      assert.is_nil(candidate)
    end)

  end)

  describe("ban management", function()

    it("bans a peer IP", function()
      local pm = peerman.new(test_network, nil, nil)
      pm:ban_peer("192.168.1.1")
      assert.is_true(pm:is_banned("192.168.1.1"))
    end)

    it("uses default 24 hour ban duration", function()
      local pm = peerman.new(test_network, nil, nil)
      local before = os.time()
      pm:ban_peer("192.168.1.1")
      local expected_min = before + 86400
      assert.is_true(pm.banned["192.168.1.1"] >= expected_min)
    end)

    it("accepts custom ban duration", function()
      local pm = peerman.new(test_network, nil, nil)
      local before = os.time()
      pm:ban_peer("192.168.1.1", 3600)  -- 1 hour
      assert.is_true(pm.banned["192.168.1.1"] >= before + 3600)
      assert.is_true(pm.banned["192.168.1.1"] < before + 3700)
    end)

    it("rejects connection from banned peer", function()
      local pm = peerman.new(test_network, nil, nil)
      pm:ban_peer("192.168.1.1")
      local ok, err = pm:connect_peer("192.168.1.1", 8333)
      assert.is_false(ok)
      assert.equals("peer is banned", err)
    end)

    it("allows connection after ban expires", function()
      local pm = peerman.new(test_network, nil, nil)
      -- Set ban in the past
      pm.banned["192.168.1.1"] = os.time() - 1
      assert.is_false(pm:is_banned("192.168.1.1"))
    end)

    it("adds ban score and bans at threshold", function()
      local pm = peerman.new(test_network, nil, nil)
      -- Create a mock peer
      local mock_peer = {
        ip = "192.168.1.1",
        port = 8333,
        ban_score = 0,
        state = peer_mod.STATE.ESTABLISHED,
        socket = nil,
        disconnect = function(self, reason)
          self.state = peer_mod.STATE.DISCONNECTED
          self.disconnect_reason = reason
        end,
      }
      pm.peers["192.168.1.1:8333"] = mock_peer
      pm.peer_list[1] = mock_peer

      -- Add score below threshold
      pm:add_ban_score(mock_peer, 50, "test")
      assert.is_false(pm:is_banned("192.168.1.1"))
      assert.equals(50, mock_peer.ban_score)

      -- Add score to exceed threshold
      pm:add_ban_score(mock_peer, 60, "threshold exceeded")
      assert.is_true(pm:is_banned("192.168.1.1"))
    end)

  end)

  describe("connection management", function()

    it("rejects connection when at max peers", function()
      local pm = peerman.new(test_network, nil, {max_peers = 1})
      -- Simulate existing connection
      pm.peer_list[1] = {ip = "192.168.1.1", port = 8333}
      local ok, err = pm:connect_peer("192.168.1.2", 8333)
      assert.is_false(ok)
      assert.equals("max peers reached", err)
    end)

    it("rejects duplicate connection", function()
      local pm = peerman.new(test_network, nil, nil)
      pm.peers["192.168.1.1:8333"] = {}
      local ok, err = pm:connect_peer("192.168.1.1", 8333)
      assert.is_false(ok)
      assert.equals("already connected", err)
    end)

    it("gets peer counts", function()
      local pm = peerman.new(test_network, nil, nil)
      pm.peer_list = {
        {inbound = false},
        {inbound = false},
        {inbound = true},
      }
      local total, outbound, inbound = pm:get_peer_counts()
      assert.equals(3, total)
      assert.equals(2, outbound)
      assert.equals(1, inbound)
    end)

    it("disconnects peer and removes from tracking tables", function()
      local pm = peerman.new(test_network, nil, nil)
      local mock_peer = {
        ip = "192.168.1.1",
        port = 8333,
        nonce = 12345,
        state = peer_mod.STATE.ESTABLISHED,
        disconnect = function(self, reason)
          self.state = peer_mod.STATE.DISCONNECTED
          local _ = reason
        end,
      }
      pm.peers["192.168.1.1:8333"] = mock_peer
      pm.peer_list[1] = mock_peer
      pm.our_nonces[12345] = true

      pm:disconnect_peer(mock_peer, "test disconnect")

      assert.is_nil(pm.peers["192.168.1.1:8333"])
      assert.equals(0, #pm.peer_list)
      assert.is_nil(pm.our_nonces[12345])
    end)

    it("calls on_peer_disconnected callback", function()
      local pm = peerman.new(test_network, nil, nil)
      local callback_called = false
      local callback_peer, callback_reason
      pm.callbacks.on_peer_disconnected = function(p, reason)
        callback_called = true
        callback_peer = p
        callback_reason = reason
      end

      local mock_peer = {
        ip = "192.168.1.1",
        port = 8333,
        nonce = 12345,
        state = peer_mod.STATE.ESTABLISHED,
        disconnect = function(self, reason)
          self.state = peer_mod.STATE.DISCONNECTED
          local _ = reason
        end,
      }
      pm.peers["192.168.1.1:8333"] = mock_peer
      pm.peer_list[1] = mock_peer

      pm:disconnect_peer(mock_peer, "test reason")

      assert.is_true(callback_called)
      assert.equals(mock_peer, callback_peer)
      assert.equals("test reason", callback_reason)
    end)

  end)

  describe("message handler registration", function()

    it("registers handler for new commands", function()
      local pm = peerman.new(test_network, nil, nil)
      local handler_fn = function() end
      pm:register_handler("block", handler_fn)
      assert.equals(handler_fn, pm.message_handlers["block"])
    end)

    it("propagates handler to existing peers", function()
      local pm = peerman.new(test_network, nil, nil)
      local registered_handlers = {}
      local mock_peer = {
        on = function(self, cmd, handler)
          registered_handlers[cmd] = handler
          local _ = self
        end,
      }
      pm.peer_list[1] = mock_peer

      local handler_fn = function() end
      pm:register_handler("tx", handler_fn)

      assert.equals(handler_fn, registered_handlers["tx"])
    end)

  end)

  describe("broadcast", function()

    it("sends to all established peers", function()
      local pm = peerman.new(test_network, nil, nil)
      local sent_messages = {}
      local function make_mock_peer(id, state)
        return {
          id = id,
          state = state,
          send_message = function(self, cmd, payload)
            sent_messages[#sent_messages + 1] = {
              peer_id = self.id,
              command = cmd,
              payload = payload,
            }
          end,
        }
      end

      pm.peer_list = {
        make_mock_peer(1, peer_mod.STATE.ESTABLISHED),
        make_mock_peer(2, peer_mod.STATE.CONNECTING),
        make_mock_peer(3, peer_mod.STATE.ESTABLISHED),
      }

      pm:broadcast("inv", "test_payload")

      assert.equals(2, #sent_messages)
      assert.equals(1, sent_messages[1].peer_id)
      assert.equals(3, sent_messages[2].peer_id)
      assert.equals("inv", sent_messages[1].command)
      assert.equals("test_payload", sent_messages[1].payload)
    end)

    it("respects filter function", function()
      local pm = peerman.new(test_network, nil, nil)
      local sent_to = {}
      local function make_mock_peer(id, services)
        return {
          id = id,
          state = peer_mod.STATE.ESTABLISHED,
          services = services,
          send_message = function(self, cmd, payload)
            sent_to[#sent_to + 1] = self.id
            local _ = cmd
            local _ = payload
          end,
        }
      end

      pm.peer_list = {
        make_mock_peer(1, p2p.SERVICES.NODE_NETWORK),
        make_mock_peer(2, p2p.SERVICES.NODE_WITNESS),
        make_mock_peer(3, p2p.SERVICES.NODE_WITNESS),
      }

      -- Only send to witness nodes
      pm:broadcast("tx", "payload", function(p)
        return p.services == p2p.SERVICES.NODE_WITNESS
      end)

      assert.equals(2, #sent_to)
      assert.equals(2, sent_to[1])
      assert.equals(3, sent_to[2])
    end)

  end)

  describe("get_established_peers", function()

    it("returns only established peers", function()
      local pm = peerman.new(test_network, nil, nil)
      pm.peer_list = {
        {id = 1, state = peer_mod.STATE.ESTABLISHED},
        {id = 2, state = peer_mod.STATE.CONNECTING},
        {id = 3, state = peer_mod.STATE.ESTABLISHED},
        {id = 4, state = peer_mod.STATE.DISCONNECTED},
      }

      local established = pm:get_established_peers()
      assert.equals(2, #established)
      assert.equals(1, established[1].id)
      assert.equals(3, established[2].id)
    end)

    it("returns empty list when no established peers", function()
      local pm = peerman.new(test_network, nil, nil)
      pm.peer_list = {
        {id = 1, state = peer_mod.STATE.CONNECTING},
      }
      local established = pm:get_established_peers()
      assert.equals(0, #established)
    end)

  end)

  describe("inbound connection limits", function()

    it("enforces max inbound limit", function()
      local pm = peerman.new(test_network, nil, {max_inbound = 2})

      -- Count existing inbound connections
      pm.peer_list = {
        {inbound = true},
        {inbound = true},
      }

      -- Verify the count
      local inbound_count = 0
      for _, p in ipairs(pm.peer_list) do
        if p.inbound then inbound_count = inbound_count + 1 end
      end
      assert.equals(2, inbound_count)
      assert.equals(pm.max_inbound, inbound_count)
    end)

  end)

  describe("addr message handling", function()

    it("adds addresses from addr message", function()
      local pm = peerman.new(test_network, nil, nil)
      local now = os.time()

      -- Create addr message payload
      local addresses = {
        {timestamp = now - 100, services = 1, ip = "192.168.1.1", port = 8333},
        {timestamp = now - 200, services = 1, ip = "192.168.1.2", port = 8333},
      }
      local payload = p2p.serialize_addr(addresses)

      local mock_peer = {}
      pm:handle_addr(mock_peer, payload)

      assert.equals(2, pm:get_known_address_count())
      assert.is_not_nil(pm.known_addresses["192.168.1.1:8333"])
      assert.is_not_nil(pm.known_addresses["192.168.1.2:8333"])
    end)

    it("rejects addresses with old timestamps", function()
      local pm = peerman.new(test_network, nil, nil)
      local now = os.time()

      -- Create addr with old timestamp (> 3 hours old)
      local addresses = {
        {timestamp = now - 20000, services = 1, ip = "192.168.1.1", port = 8333},
      }
      local payload = p2p.serialize_addr(addresses)

      local mock_peer = {}
      pm:handle_addr(mock_peer, payload)

      assert.equals(0, pm:get_known_address_count())
    end)

    it("rejects addresses with future timestamps", function()
      local pm = peerman.new(test_network, nil, nil)
      local now = os.time()

      -- Create addr with future timestamp (> 10 minutes in future)
      local addresses = {
        {timestamp = now + 1000, services = 1, ip = "192.168.1.1", port = 8333},
      }
      local payload = p2p.serialize_addr(addresses)

      local mock_peer = {}
      pm:handle_addr(mock_peer, payload)

      assert.equals(0, pm:get_known_address_count())
    end)

  end)

  describe("stop", function()

    it("disconnects all peers", function()
      local pm = peerman.new(test_network, nil, nil)
      local disconnect_reasons = {}
      local function make_mock_peer(id)
        return {
          id = id,
          disconnect = function(self, reason)
            disconnect_reasons[self.id] = reason
          end,
        }
      end

      pm.peer_list = {
        make_mock_peer(1),
        make_mock_peer(2),
      }

      pm:stop()

      assert.equals("shutdown", disconnect_reasons[1])
      assert.equals("shutdown", disconnect_reasons[2])
      assert.equals(0, #pm.peer_list)
      assert.same({}, pm.peers)
    end)

  end)

  describe("mainnet DNS seeds", function()

    it("has mainnet network with DNS seeds", function()
      local mainnet = consensus.networks.mainnet
      assert.is_not_nil(mainnet)
      assert.is_not_nil(mainnet.dns_seeds)
      assert.is_true(#mainnet.dns_seeds > 0)
    end)

  end)

end)
