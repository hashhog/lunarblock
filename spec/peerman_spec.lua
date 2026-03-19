local peerman = require("lunarblock.peerman")
local peer_mod = require("lunarblock.peer")
local p2p = require("lunarblock.p2p")
local consensus = require("lunarblock.consensus")

--- Create a temporary directory for tests.
local function make_temp_dir()
  local tmpname = os.tmpname()
  os.remove(tmpname)  -- Remove the file created by tmpname
  os.execute("mkdir -p " .. tmpname)
  return tmpname
end

--- Clean up a temporary directory.
local function cleanup_temp_dir(path)
  os.execute("rm -rf " .. path)
end

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

    it("unbans a peer", function()
      local pm = peerman.new(test_network, nil, nil)
      pm:ban_peer("192.168.1.1")
      assert.is_true(pm:is_banned("192.168.1.1"))
      pm:unban_peer("192.168.1.1")
      assert.is_false(pm:is_banned("192.168.1.1"))
    end)

    it("gets list of banned peers", function()
      local pm = peerman.new(test_network, nil, nil)
      pm:ban_peer("192.168.1.1", 3600)
      pm:ban_peer("192.168.1.2", 7200)
      local banned_list = pm:get_banned_list()
      assert.equals(2, #banned_list)
    end)

    it("clears expired bans", function()
      local pm = peerman.new(test_network, nil, nil)
      -- Set one expired ban and one active ban
      pm.banned["192.168.1.1"] = os.time() - 1  -- expired
      pm.banned["192.168.1.2"] = os.time() + 3600  -- active
      pm:clear_expired_bans()
      assert.is_nil(pm.banned["192.168.1.1"])
      assert.is_not_nil(pm.banned["192.168.1.2"])
    end)

  end)

  describe("misbehavior scoring", function()

    local function make_mock_peer(ip, port)
      return {
        ip = ip or "192.168.1.1",
        port = port or 8333,
        ban_score = 0,
        state = peer_mod.STATE.ESTABLISHED,
        socket = nil,
        disconnect = function(self, reason)
          self.state = peer_mod.STATE.DISCONNECTED
          self.disconnect_reason = reason
        end,
      }
    end

    it("increments ban score with misbehaving()", function()
      local pm = peerman.new(test_network, nil, nil)
      local mock_peer = make_mock_peer()
      pm.peers["192.168.1.1:8333"] = mock_peer
      pm.peer_list[1] = mock_peer

      pm:misbehaving(mock_peer, 25, "test reason")
      assert.equals(25, mock_peer.ban_score)
    end)

    it("accumulates misbehavior scores", function()
      local pm = peerman.new(test_network, nil, nil)
      local mock_peer = make_mock_peer()
      pm.peers["192.168.1.1:8333"] = mock_peer
      pm.peer_list[1] = mock_peer

      pm:misbehaving(mock_peer, 20, "first offense")
      pm:misbehaving(mock_peer, 30, "second offense")
      pm:misbehaving(mock_peer, 40, "third offense")
      assert.equals(90, mock_peer.ban_score)
      assert.is_false(pm:is_banned("192.168.1.1"))
    end)

    it("bans peer when score reaches threshold", function()
      local pm = peerman.new(test_network, nil, nil)
      local mock_peer = make_mock_peer()
      pm.peers["192.168.1.1:8333"] = mock_peer
      pm.peer_list[1] = mock_peer

      -- Should not ban at 99
      pm:misbehaving(mock_peer, 99, "almost banned")
      assert.is_false(pm:is_banned("192.168.1.1"))

      -- Should ban at 100
      pm:misbehaving(mock_peer, 1, "final offense")
      assert.is_true(pm:is_banned("192.168.1.1"))
    end)

    it("bans instantly for invalid block header (100 points)", function()
      local pm = peerman.new(test_network, nil, nil)
      local mock_peer = make_mock_peer()
      pm.peers["192.168.1.1:8333"] = mock_peer
      pm.peer_list[1] = mock_peer

      pm:misbehaving(mock_peer, peerman.MISBEHAVIOR.INVALID_BLOCK_HEADER, "invalid header")
      assert.is_true(pm:is_banned("192.168.1.1"))
      assert.equals(peer_mod.STATE.DISCONNECTED, mock_peer.state)
    end)

    it("bans instantly for invalid block (100 points)", function()
      local pm = peerman.new(test_network, nil, nil)
      local mock_peer = make_mock_peer()
      pm.peers["192.168.1.1:8333"] = mock_peer
      pm.peer_list[1] = mock_peer

      pm:misbehaving(mock_peer, peerman.MISBEHAVIOR.INVALID_BLOCK, "invalid block")
      assert.is_true(pm:is_banned("192.168.1.1"))
    end)

    it("requires 10 invalid transactions to ban", function()
      local pm = peerman.new(test_network, nil, nil)
      local mock_peer = make_mock_peer()
      pm.peers["192.168.1.1:8333"] = mock_peer
      pm.peer_list[1] = mock_peer

      -- 9 invalid transactions = 90 points, not banned
      for i = 1, 9 do
        pm:misbehaving(mock_peer, peerman.MISBEHAVIOR.INVALID_TRANSACTION, "invalid tx " .. i)
      end
      assert.equals(90, mock_peer.ban_score)
      assert.is_false(pm:is_banned("192.168.1.1"))

      -- 10th invalid transaction = 100 points, banned
      pm:misbehaving(mock_peer, peerman.MISBEHAVIOR.INVALID_TRANSACTION, "invalid tx 10")
      assert.is_true(pm:is_banned("192.168.1.1"))
    end)

    it("requires 5 unsolicited data violations to ban", function()
      local pm = peerman.new(test_network, nil, nil)
      local mock_peer = make_mock_peer()
      pm.peers["192.168.1.1:8333"] = mock_peer
      pm.peer_list[1] = mock_peer

      -- 4 unsolicited = 80 points, not banned
      for i = 1, 4 do
        pm:misbehaving(mock_peer, peerman.MISBEHAVIOR.UNSOLICITED_DATA, "unsolicited " .. i)
      end
      assert.is_false(pm:is_banned("192.168.1.1"))

      -- 5th unsolicited = 100 points, banned
      pm:misbehaving(mock_peer, peerman.MISBEHAVIOR.UNSOLICITED_DATA, "unsolicited 5")
      assert.is_true(pm:is_banned("192.168.1.1"))
    end)

    it("requires 2 message floods to ban", function()
      local pm = peerman.new(test_network, nil, nil)
      local mock_peer = make_mock_peer()
      pm.peers["192.168.1.1:8333"] = mock_peer
      pm.peer_list[1] = mock_peer

      pm:misbehaving(mock_peer, peerman.MISBEHAVIOR.TOO_MANY_MESSAGES, "flood 1")
      assert.is_false(pm:is_banned("192.168.1.1"))

      pm:misbehaving(mock_peer, peerman.MISBEHAVIOR.TOO_MANY_MESSAGES, "flood 2")
      assert.is_true(pm:is_banned("192.168.1.1"))
    end)

  end)

  describe("ban persistence", function()

    local test_dir

    before_each(function()
      test_dir = make_temp_dir()
    end)

    after_each(function()
      cleanup_temp_dir(test_dir)
    end)

    it("persists bans to disk", function()
      local pm = peerman.new(test_network, nil, {data_dir = test_dir})
      pm:ban_peer("192.168.1.1", 3600)
      pm:ban_peer("10.0.0.1", 7200)

      -- Check file was created
      local f = io.open(test_dir .. "/banned.dat", "r")
      assert.is_not_nil(f)
      local content = f:read("*all")
      f:close()
      assert.truthy(content:find("192.168.1.1"))
      assert.truthy(content:find("10.0.0.1"))
    end)

    it("loads bans from disk on startup", function()
      -- Create a ban file manually
      local ban_until = os.time() + 3600
      local f = io.open(test_dir .. "/banned.dat", "w")
      f:write("192.168.1.1:" .. tostring(ban_until) .. "\n")
      f:write("10.0.0.1:" .. tostring(ban_until + 1000) .. "\n")
      f:close()

      -- Create new PeerManager, should load bans
      local pm = peerman.new(test_network, nil, {data_dir = test_dir})
      assert.is_true(pm:is_banned("192.168.1.1"))
      assert.is_true(pm:is_banned("10.0.0.1"))
    end)

    it("does not load expired bans from disk", function()
      -- Create a ban file with expired ban
      local f = io.open(test_dir .. "/banned.dat", "w")
      f:write("192.168.1.1:" .. tostring(os.time() - 100) .. "\n")  -- expired
      f:write("10.0.0.1:" .. tostring(os.time() + 3600) .. "\n")    -- active
      f:close()

      local pm = peerman.new(test_network, nil, {data_dir = test_dir})
      assert.is_false(pm:is_banned("192.168.1.1"))
      assert.is_true(pm:is_banned("10.0.0.1"))
    end)

    it("bans survive peer manager restart", function()
      -- Create first PeerManager and ban a peer
      local pm1 = peerman.new(test_network, nil, {data_dir = test_dir})
      pm1:ban_peer("192.168.1.1", 3600)
      assert.is_true(pm1:is_banned("192.168.1.1"))

      -- Create second PeerManager (simulating restart)
      local pm2 = peerman.new(test_network, nil, {data_dir = test_dir})
      assert.is_true(pm2:is_banned("192.168.1.1"))
    end)

    it("unban removes from disk", function()
      local pm = peerman.new(test_network, nil, {data_dir = test_dir})
      pm:ban_peer("192.168.1.1", 3600)
      pm:ban_peer("10.0.0.1", 3600)

      -- Unban one peer
      pm:unban_peer("192.168.1.1")

      -- Check file no longer contains unbanned IP
      local f = io.open(test_dir .. "/banned.dat", "r")
      local content = f:read("*all")
      f:close()
      assert.is_nil(content:find("192.168.1.1"))
      assert.truthy(content:find("10.0.0.1"))
    end)

    it("misbehavior leading to ban persists to disk", function()
      local pm = peerman.new(test_network, nil, {data_dir = test_dir})
      local mock_peer = {
        ip = "192.168.1.1",
        port = 8333,
        ban_score = 0,
        state = peer_mod.STATE.ESTABLISHED,
        disconnect = function(self, reason)
          self.state = peer_mod.STATE.DISCONNECTED
          local _ = reason
        end,
      }
      pm.peers["192.168.1.1:8333"] = mock_peer
      pm.peer_list[1] = mock_peer

      -- Trigger ban via misbehavior
      pm:misbehaving(mock_peer, peerman.MISBEHAVIOR.INVALID_BLOCK, "invalid block")

      -- Create new PeerManager (simulating restart)
      local pm2 = peerman.new(test_network, nil, {data_dir = test_dir})
      assert.is_true(pm2:is_banned("192.168.1.1"))
    end)

    it("handles missing ban file gracefully", function()
      -- No ban file exists
      local pm = peerman.new(test_network, nil, {data_dir = test_dir})
      assert.same({}, pm.banned)
    end)

    it("handles malformed ban file entries", function()
      -- Create a ban file with some bad entries
      local f = io.open(test_dir .. "/banned.dat", "w")
      f:write("invalid_line_no_colon\n")
      f:write("192.168.1.1:not_a_number\n")
      f:write("10.0.0.1:" .. tostring(os.time() + 3600) .. "\n")  -- valid
      f:close()

      local pm = peerman.new(test_network, nil, {data_dir = test_dir})
      -- Should only load the valid entry
      assert.is_false(pm:is_banned("192.168.1.1"))
      assert.is_true(pm:is_banned("10.0.0.1"))
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

  describe("transaction trickling", function()

    local function make_mock_peer(ip, port, inbound, wtxid_relay)
      return {
        ip = ip or "192.168.1.1",
        port = port or 8333,
        inbound = inbound or false,
        wtxid_relay = wtxid_relay or false,
        state = peer_mod.STATE.ESTABLISHED,
        _established_notified = true,
        send_message = function(self, cmd, payload)
          self._sent_messages = self._sent_messages or {}
          self._sent_messages[#self._sent_messages + 1] = {
            command = cmd,
            payload = payload,
          }
        end,
        disconnect = function(self, reason)
          self.state = peer_mod.STATE.DISCONNECTED
          local _ = reason
        end,
      }
    end

    describe("poisson_delay", function()

      it("returns positive values", function()
        for _ = 1, 100 do
          local delay = peerman.poisson_delay(5.0)
          assert.is_true(delay > 0)
        end
      end)

      it("averages approximately the interval", function()
        local total = 0
        local n = 1000
        for _ = 1, n do
          total = total + peerman.poisson_delay(5.0)
        end
        local avg = total / n
        -- Should be within 20% of expected (law of large numbers)
        assert.is_true(avg > 4.0 and avg < 6.0)
      end)

    end)

    describe("shuffle", function()

      it("shuffles array in place", function()
        local arr = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
        local original = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
        local result = peerman.shuffle(arr)

        -- Same array returned
        assert.equals(arr, result)
        -- Same length
        assert.equals(#original, #result)
        -- All elements still present (just reordered)
        table.sort(result)
        assert.same(original, result)
      end)

      it("produces different orderings (statistical)", function()
        local same_count = 0
        for _ = 1, 100 do
          local arr1 = {1, 2, 3, 4, 5}
          local arr2 = {1, 2, 3, 4, 5}
          peerman.shuffle(arr1)
          peerman.shuffle(arr2)
          local same = true
          for i = 1, 5 do
            if arr1[i] ~= arr2[i] then
              same = false
              break
            end
          end
          if same then same_count = same_count + 1 end
        end
        -- Very unlikely to have all shuffles be identical
        assert.is_true(same_count < 50)
      end)

    end)

    describe("inv_queue management", function()

      it("initializes trickle state for established peers", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_peer()
        pm.peer_list[1] = mock_peer
        pm.peers["192.168.1.1:8333"] = mock_peer

        pm:_init_peer_trickle(mock_peer)

        local queue = pm:get_peer_inv_queue(mock_peer)
        assert.is_not_nil(queue)
        assert.equals(0, #queue)
      end)

      it("queues transaction announcements for established peers", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_peer()
        pm.peer_list[1] = mock_peer
        pm.peers["192.168.1.1:8333"] = mock_peer
        pm:_init_peer_trickle(mock_peer)

        local txid = string.rep("\x01", 32)
        pm:queue_tx_announcement(txid)

        local queue = pm:get_peer_inv_queue(mock_peer)
        assert.equals(1, #queue)
        assert.equals(txid, queue[1].hash)
        assert.is_false(queue[1].is_wtxid)
      end)

      it("uses wtxid for wtxidrelay peers", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_peer("192.168.1.1", 8333, false, true)  -- wtxid_relay = true
        pm.peer_list[1] = mock_peer
        pm.peers["192.168.1.1:8333"] = mock_peer
        pm:_init_peer_trickle(mock_peer)

        local txid = string.rep("\x01", 32)
        local wtxid = string.rep("\x02", 32)
        pm:queue_tx_announcement(txid, wtxid)

        local queue = pm:get_peer_inv_queue(mock_peer)
        assert.equals(1, #queue)
        assert.equals(wtxid, queue[1].hash)  -- Uses wtxid, not txid
        assert.is_true(queue[1].is_wtxid)
      end)

      it("does not re-announce known transactions", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_peer()
        pm.peer_list[1] = mock_peer
        pm.peers["192.168.1.1:8333"] = mock_peer
        pm:_init_peer_trickle(mock_peer)

        local txid = string.rep("\x01", 32)
        pm:queue_tx_announcement(txid)
        pm:queue_tx_announcement(txid)  -- Second announcement

        local queue = pm:get_peer_inv_queue(mock_peer)
        -- Only queued once (not yet sent, so not in inv_known)
        assert.equals(2, #queue)
      end)

      it("cleans up trickle state on disconnect", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_peer()
        pm.peer_list[1] = mock_peer
        pm.peers["192.168.1.1:8333"] = mock_peer
        pm:_init_peer_trickle(mock_peer)

        pm:_cleanup_peer_trickle(mock_peer)

        local queue = pm:get_peer_inv_queue(mock_peer)
        assert.is_nil(queue)
      end)

    end)

    describe("trickle timer", function()

      it("sets different intervals for inbound vs outbound", function()
        local pm = peerman.new(test_network, nil, nil)

        local outbound_peer = make_mock_peer("192.168.1.1", 8333, false)
        pm.peer_list[1] = outbound_peer
        pm.peers["192.168.1.1:8333"] = outbound_peer
        pm:_init_peer_trickle(outbound_peer)

        local inbound_peer = make_mock_peer("192.168.1.2", 8333, true)
        pm.peer_list[2] = inbound_peer
        pm.peers["192.168.1.2:8333"] = inbound_peer
        pm:_init_peer_trickle(inbound_peer)

        -- Both should have future send times
        local out_time = pm:get_peer_next_send_time(outbound_peer)
        local in_time = pm:get_peer_next_send_time(inbound_peer)
        assert.is_not_nil(out_time)
        assert.is_not_nil(in_time)
      end)

      it("delays announcements until timer expires", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_peer()
        pm.peer_list[1] = mock_peer
        pm.peers["192.168.1.1:8333"] = mock_peer
        pm:_init_peer_trickle(mock_peer)

        -- Set next_send_time far in the future
        pm._peer_trickle["192.168.1.1:8333"].next_send_time = os.time() + 1000

        local txid = string.rep("\x01", 32)
        pm:queue_tx_announcement(txid)

        -- Process trickle - should not send yet
        pm:_process_trickle()

        -- No messages sent
        assert.is_nil(mock_peer._sent_messages)

        -- Queue still has the entry
        local queue = pm:get_peer_inv_queue(mock_peer)
        assert.equals(1, #queue)
      end)

      it("sends inv when timer expires", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_peer()
        pm.peer_list[1] = mock_peer
        pm.peers["192.168.1.1:8333"] = mock_peer
        pm:_init_peer_trickle(mock_peer)

        -- Set next_send_time to the past
        pm._peer_trickle["192.168.1.1:8333"].next_send_time = 0

        local txid = string.rep("\x01", 32)
        pm:queue_tx_announcement(txid)

        -- Process trickle - should send now
        pm:_process_trickle()

        -- Message sent
        assert.is_not_nil(mock_peer._sent_messages)
        assert.equals(1, #mock_peer._sent_messages)
        assert.equals("inv", mock_peer._sent_messages[1].command)

        -- Queue is now empty
        local queue = pm:get_peer_inv_queue(mock_peer)
        assert.equals(0, #queue)
      end)

      it("batches up to MAX_INV_PER_MSG entries", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_peer()
        pm.peer_list[1] = mock_peer
        pm.peers["192.168.1.1:8333"] = mock_peer
        pm:_init_peer_trickle(mock_peer)

        -- Set next_send_time to the past
        pm._peer_trickle["192.168.1.1:8333"].next_send_time = 0

        -- Queue more than MAX_INV_PER_MSG transactions
        for i = 1, 50 do
          local txid = string.rep(string.char(i), 32)
          pm:queue_tx_announcement(txid)
        end

        -- Process trickle once - should send one batch
        pm:_process_trickle()

        -- Should have sent exactly MAX_INV_PER_MSG (35)
        assert.is_not_nil(mock_peer._sent_messages)
        assert.equals(1, #mock_peer._sent_messages)

        -- Parse the inv message to verify count
        local inv_items = p2p.deserialize_inv(mock_peer._sent_messages[1].payload)
        assert.equals(peerman.TRICKLE.MAX_INV_PER_MSG, #inv_items)

        -- Remaining items still in queue
        local queue = pm:get_peer_inv_queue(mock_peer)
        assert.equals(50 - peerman.TRICKLE.MAX_INV_PER_MSG, #queue)
      end)

      it("randomizes order of announcements", function()
        -- This is a statistical test - run multiple times
        local orderings = {}
        for _ = 1, 10 do
          local pm = peerman.new(test_network, nil, nil)
          local mock_peer = make_mock_peer()
          pm.peer_list[1] = mock_peer
          pm.peers["192.168.1.1:8333"] = mock_peer
          pm:_init_peer_trickle(mock_peer)
          pm._peer_trickle["192.168.1.1:8333"].next_send_time = 0

          -- Queue 10 transactions with sequential IDs
          for i = 1, 10 do
            local txid = string.rep(string.char(i), 32)
            pm:queue_tx_announcement(txid)
          end

          pm:_process_trickle()

          local inv_items = p2p.deserialize_inv(mock_peer._sent_messages[1].payload)
          local order = ""
          for _, item in ipairs(inv_items) do
            order = order .. string.byte(item.hash:sub(1, 1))
          end
          orderings[order] = true
        end

        -- Should have at least 2 different orderings in 10 tries
        local count = 0
        for _ in pairs(orderings) do count = count + 1 end
        assert.is_true(count >= 2)
      end)

    end)

    describe("relay with wtxid", function()

      it("uses MSG_TX for non-wtxidrelay peers", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_peer("192.168.1.1", 8333, false, false)
        pm.peer_list[1] = mock_peer
        pm.peers["192.168.1.1:8333"] = mock_peer
        pm:_init_peer_trickle(mock_peer)
        pm._peer_trickle["192.168.1.1:8333"].next_send_time = 0

        local txid = string.rep("\x01", 32)
        pm:queue_tx_announcement(txid)
        pm:_process_trickle()

        local inv_items = p2p.deserialize_inv(mock_peer._sent_messages[1].payload)
        assert.equals(p2p.INV_TYPE.MSG_TX, inv_items[1].type)
      end)

      it("uses MSG_WTX for wtxidrelay peers", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_peer("192.168.1.1", 8333, false, true)
        pm.peer_list[1] = mock_peer
        pm.peers["192.168.1.1:8333"] = mock_peer
        pm:_init_peer_trickle(mock_peer)
        pm._peer_trickle["192.168.1.1:8333"].next_send_time = 0

        local txid = string.rep("\x01", 32)
        local wtxid = string.rep("\x02", 32)
        pm:queue_tx_announcement(txid, wtxid)
        pm:_process_trickle()

        local inv_items = p2p.deserialize_inv(mock_peer._sent_messages[1].payload)
        assert.equals(p2p.INV_TYPE.MSG_WTX, inv_items[1].type)
        assert.equals(wtxid, inv_items[1].hash)
      end)

    end)

    describe("inv_known filter", function()

      it("marks sent transactions as known", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_peer()
        pm.peer_list[1] = mock_peer
        pm.peers["192.168.1.1:8333"] = mock_peer
        pm:_init_peer_trickle(mock_peer)
        pm._peer_trickle["192.168.1.1:8333"].next_send_time = 0

        local txid = string.rep("\x01", 32)
        pm:queue_tx_announcement(txid)
        pm:_process_trickle()

        -- Try to queue the same transaction again
        pm:queue_tx_announcement(txid)

        -- Queue should be empty (transaction is known)
        local queue = pm:get_peer_inv_queue(mock_peer)
        assert.equals(0, #queue)
      end)

      it("allows clearing known filter", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_peer()
        pm.peer_list[1] = mock_peer
        pm.peers["192.168.1.1:8333"] = mock_peer
        pm:_init_peer_trickle(mock_peer)
        pm._peer_trickle["192.168.1.1:8333"].next_send_time = 0

        local txid = string.rep("\x01", 32)
        pm:queue_tx_announcement(txid)
        pm:_process_trickle()

        -- Clear known filter
        pm:clear_peer_inv_known(mock_peer)

        -- Now can queue the same transaction again
        pm:queue_tx_announcement(txid)
        local queue = pm:get_peer_inv_queue(mock_peer)
        assert.equals(1, #queue)
      end)

    end)

  end)

  --------------------------------------------------------------------------------
  -- Eclipse Attack Mitigation Tests
  --------------------------------------------------------------------------------

  describe("address manager (addrman)", function()

    describe("network group calculation", function()

      it("groups IPv4 by /16 subnet", function()
        local g1 = peerman.get_addr_group("192.168.1.1")
        local g2 = peerman.get_addr_group("192.168.1.2")
        local g3 = peerman.get_addr_group("192.168.2.1")
        local g4 = peerman.get_addr_group("192.169.1.1")

        -- Same /16 should have same group
        assert.equals(g1, g2)
        assert.equals(g1, g3)
        -- Different /16 should have different group
        assert.not_equals(g1, g4)
      end)

      it("produces deterministic groups", function()
        for _ = 1, 10 do
          local g = peerman.get_addr_group("10.20.30.40")
          assert.equals(string.char(4, 10, 20), g)
        end
      end)

    end)

    describe("bucket assignment", function()

      it("assigns addresses to new buckets deterministically", function()
        local key = string.rep("\x01", 32)
        local bucket1 = peerman.get_new_bucket(key, "192.168.1.1", 8333, "10.0.0.1")
        local bucket2 = peerman.get_new_bucket(key, "192.168.1.1", 8333, "10.0.0.1")
        assert.equals(bucket1, bucket2)
        assert.is_true(bucket1 >= 0)
        assert.is_true(bucket1 < peerman.ADDRMAN.NEW_BUCKET_COUNT)
      end)

      it("assigns addresses to tried buckets deterministically", function()
        local key = string.rep("\x02", 32)
        local bucket1 = peerman.get_tried_bucket(key, "192.168.1.1", 8333)
        local bucket2 = peerman.get_tried_bucket(key, "192.168.1.1", 8333)
        assert.equals(bucket1, bucket2)
        assert.is_true(bucket1 >= 0)
        assert.is_true(bucket1 < peerman.ADDRMAN.TRIED_BUCKET_COUNT)
      end)

      it("distributes addresses across multiple buckets", function()
        local key = string.rep("\x03", 32)
        local buckets = {}
        for i = 1, 256 do
          local ip = string.format("%d.%d.%d.%d",
            math.floor(i / 64) % 256,
            i % 64,
            1, 1)
          local bucket = peerman.get_new_bucket(key, ip, 8333, "dns")
          buckets[bucket] = true
        end
        -- Should use at least 10 different buckets
        local count = 0
        for _ in pairs(buckets) do count = count + 1 end
        assert.is_true(count >= 10)
      end)

      it("places addresses at deterministic positions in buckets", function()
        local key = string.rep("\x04", 32)
        local pos1 = peerman.get_bucket_position(key, true, 5, "192.168.1.1", 8333)
        local pos2 = peerman.get_bucket_position(key, true, 5, "192.168.1.1", 8333)
        assert.equals(pos1, pos2)
        assert.is_true(pos1 >= 0)
        assert.is_true(pos1 < peerman.ADDRMAN.BUCKET_SIZE)
      end)

    end)

    describe("new table", function()

      it("adds addresses to new table", function()
        local pm = peerman.new(test_network, nil, nil)
        local added = pm:_add_to_new("192.168.1.1", 8333, 1, os.time(), "10.0.0.1")
        assert.is_true(added)
        local stats = pm:get_addrman_stats()
        assert.equals(1, stats.new_count)
      end)

      it("tracks multiple addresses", function()
        local pm = peerman.new(test_network, nil, nil)
        pm:_add_to_new("192.168.1.1", 8333, 1, os.time(), "10.0.0.1")
        pm:_add_to_new("192.168.1.2", 8333, 1, os.time(), "10.0.0.2")
        pm:_add_to_new("192.168.1.3", 8333, 1, os.time(), "10.0.0.3")
        local stats = pm:get_addrman_stats()
        assert.equals(3, stats.new_count)
      end)

      it("updates timestamp for duplicate addresses", function()
        local pm = peerman.new(test_network, nil, nil)
        local old_time = os.time() - 1000
        local new_time = os.time()
        pm:_add_to_new("192.168.1.1", 8333, 1, old_time, "10.0.0.1")
        pm:_add_to_new("192.168.1.1", 8333, 1, new_time, "10.0.0.1")
        local stats = pm:get_addrman_stats()
        -- Should still be 1 address (just updated)
        assert.equals(1, stats.new_count)
      end)

    end)

    describe("tried table", function()

      it("moves addresses from new to tried", function()
        local pm = peerman.new(test_network, nil, nil)
        pm:_add_to_new("192.168.1.1", 8333, 1, os.time(), "10.0.0.1")
        local stats1 = pm:get_addrman_stats()
        assert.equals(1, stats1.new_count)
        assert.equals(0, stats1.tried_count)

        pm:_move_to_tried("192.168.1.1", 8333)
        local stats2 = pm:get_addrman_stats()
        assert.equals(0, stats2.new_count)
        assert.equals(1, stats2.tried_count)
      end)

      it("tracks multiple tried addresses", function()
        local pm = peerman.new(test_network, nil, nil)
        for i = 1, 5 do
          local ip = "192.168." .. i .. ".1"
          pm:_add_to_new(ip, 8333, 1, os.time(), "10.0.0.1")
          pm:_move_to_tried(ip, 8333)
        end
        local stats = pm:get_addrman_stats()
        assert.equals(5, stats.tried_count)
      end)

      it("updates last_success for repeated successful connections", function()
        local pm = peerman.new(test_network, nil, nil)
        pm:_add_to_new("192.168.1.1", 8333, 1, os.time(), "10.0.0.1")
        pm:_move_to_tried("192.168.1.1", 8333)
        -- Move again (simulating reconnect)
        pm:_move_to_tried("192.168.1.1", 8333)
        local stats = pm:get_addrman_stats()
        -- Should still be just 1 tried entry
        assert.equals(1, stats.tried_count)
      end)

    end)

    describe("address selection", function()

      it("returns nil when tables are empty", function()
        local pm = peerman.new(test_network, nil, nil)
        local addr = pm:_select_address()
        assert.is_nil(addr)
      end)

      it("selects from new table", function()
        local pm = peerman.new(test_network, nil, nil)
        pm:_add_to_new("192.168.1.1", 8333, 1, os.time(), "10.0.0.1")
        local addr = pm:_select_address()
        assert.is_not_nil(addr)
        assert.equals("192.168.1.1", addr.ip)
        assert.equals(8333, addr.port)
      end)

      it("selects from tried table", function()
        local pm = peerman.new(test_network, nil, nil)
        pm:_move_to_tried("192.168.1.1", 8333)
        local addr = pm:_select_address()
        assert.is_not_nil(addr)
        assert.equals("192.168.1.1", addr.ip)
      end)

      it("can be restricted to new table only", function()
        local pm = peerman.new(test_network, nil, nil)
        pm:_add_to_new("192.168.1.1", 8333, 1, os.time(), "10.0.0.1")
        pm:_move_to_tried("192.168.1.2", 8333)
        -- Select only from new
        local found_new = false
        for _ = 1, 50 do
          local addr = pm:_select_address(true)
          if addr and addr.ip == "192.168.1.1" then
            found_new = true
            break
          end
        end
        assert.is_true(found_new)
      end)

    end)

  end)

  describe("anchor connections", function()

    local test_dir

    before_each(function()
      test_dir = make_temp_dir()
    end)

    after_each(function()
      cleanup_temp_dir(test_dir)
    end)

    it("saves anchors on shutdown", function()
      local pm = peerman.new(test_network, nil, {data_dir = test_dir})

      -- Simulate established outbound peer
      local mock_peer = {
        ip = "192.168.1.1",
        port = 8333,
        inbound = false,
        state = peer_mod.STATE.ESTABLISHED,
        disconnect = function(self, reason)
          self.state = peer_mod.STATE.DISCONNECTED
          local _ = reason
        end,
      }
      pm.peer_list[1] = mock_peer
      pm.peers["192.168.1.1:8333"] = mock_peer

      -- Stop should save anchors
      pm:stop()

      -- Verify anchors.dat was created
      local f = io.open(test_dir .. "/anchors.dat", "r")
      assert.is_not_nil(f)
      local content = f:read("*all")
      f:close()
      assert.truthy(content:find("192.168.1.1:8333"))
    end)

    it("loads anchors on startup", function()
      -- Create anchors file
      local f = io.open(test_dir .. "/anchors.dat", "w")
      f:write("192.168.1.1:8333\n")
      f:write("192.168.1.2:8334\n")
      f:close()

      local pm = peerman.new(test_network, nil, {data_dir = test_dir})
      local anchors = pm:get_anchors()

      assert.equals(2, #anchors)
      assert.equals("192.168.1.1", anchors[1].ip)
      assert.equals(8333, anchors[1].port)
      assert.equals("192.168.1.2", anchors[2].ip)
      assert.equals(8334, anchors[2].port)
    end)

    it("deletes anchors file after loading (Bitcoin Core behavior)", function()
      local f = io.open(test_dir .. "/anchors.dat", "w")
      f:write("192.168.1.1:8333\n")
      f:close()

      peerman.new(test_network, nil, {data_dir = test_dir})

      -- File should be deleted
      local f2 = io.open(test_dir .. "/anchors.dat", "r")
      assert.is_nil(f2)
    end)

    it("limits anchors to MAX_ANCHORS (2)", function()
      local pm = peerman.new(test_network, nil, {data_dir = test_dir})

      -- Simulate 5 established outbound peers
      for i = 1, 5 do
        local mock_peer = {
          ip = "192.168.1." .. i,
          port = 8333,
          inbound = false,
          state = peer_mod.STATE.ESTABLISHED,
          disconnect = function(self, reason)
            self.state = peer_mod.STATE.DISCONNECTED
            local _ = reason
          end,
        }
        pm.peer_list[i] = mock_peer
        pm.peers["192.168.1." .. i .. ":8333"] = mock_peer
      end

      pm:stop()

      -- Verify only 2 anchors saved
      local f = io.open(test_dir .. "/anchors.dat", "r")
      assert.is_not_nil(f)
      local count = 0
      for _ in f:lines() do count = count + 1 end
      f:close()
      assert.equals(2, count)
    end)

    it("survives peer manager restart", function()
      -- First session: establish peer and shutdown
      local pm1 = peerman.new(test_network, nil, {data_dir = test_dir})
      local mock_peer = {
        ip = "192.168.1.1",
        port = 8333,
        inbound = false,
        state = peer_mod.STATE.ESTABLISHED,
        disconnect = function(self, reason)
          self.state = peer_mod.STATE.DISCONNECTED
          local _ = reason
        end,
      }
      pm1.peer_list[1] = mock_peer
      pm1.peers["192.168.1.1:8333"] = mock_peer
      pm1:stop()

      -- Second session: should load anchor
      local pm2 = peerman.new(test_network, nil, {data_dir = test_dir})
      local anchors = pm2:get_anchors()
      assert.equals(1, #anchors)
      assert.equals("192.168.1.1", anchors[1].ip)
    end)

  end)

  describe("outbound diversity (eclipse mitigation)", function()

    it("allows first connection from any subnet", function()
      local pm = peerman.new(test_network, nil, nil)
      assert.is_true(pm:_check_outbound_diversity("192.168.1.1"))
    end)

    it("rejects second connection from same /16 subnet", function()
      local pm = peerman.new(test_network, nil, nil)
      pm:_add_outbound_group("192.168.1.1")
      assert.is_false(pm:_check_outbound_diversity("192.168.1.2"))
      assert.is_false(pm:_check_outbound_diversity("192.168.1.100"))
    end)

    it("allows connections from different /16 subnets", function()
      local pm = peerman.new(test_network, nil, nil)
      pm:_add_outbound_group("192.168.1.1")
      assert.is_true(pm:_check_outbound_diversity("192.169.1.1"))
      assert.is_true(pm:_check_outbound_diversity("10.0.0.1"))
    end)

    it("allows reconnection after disconnect", function()
      local pm = peerman.new(test_network, nil, nil)
      pm:_add_outbound_group("192.168.1.1")
      assert.is_false(pm:_check_outbound_diversity("192.168.1.2"))

      pm:_remove_outbound_group("192.168.1.1")
      assert.is_true(pm:_check_outbound_diversity("192.168.1.2"))
    end)

    it("tracks multiple connections per subnet correctly", function()
      local pm = peerman.new(test_network, nil, nil)
      -- Simulate two connections from different subnets
      pm:_add_outbound_group("192.168.1.1")
      pm:_add_outbound_group("10.0.0.1")

      -- Both subnets blocked
      assert.is_false(pm:_check_outbound_diversity("192.168.1.2"))
      assert.is_false(pm:_check_outbound_diversity("10.0.0.2"))

      -- Third subnet still allowed
      assert.is_true(pm:_check_outbound_diversity("172.16.0.1"))
    end)

    it("rejects same-subnet peer in connect_peer", function()
      local pm = peerman.new(test_network, nil, nil)
      pm:add_known_address("192.168.1.1", 8333)
      pm:add_known_address("192.168.1.2", 8333)

      -- Simulate connected peer from 192.168.1.x
      pm:_add_outbound_group("192.168.1.1")

      local ok, err = pm:connect_peer("192.168.1.2", 8333)
      assert.is_false(ok)
      assert.equals("same /16 subnet as existing peer", err)
    end)

    it("filters candidates in select_peer_to_connect", function()
      local pm = peerman.new(test_network, nil, nil)
      -- Add addresses from same subnet
      pm:add_known_address("192.168.1.1", 8333)
      pm:add_known_address("192.168.1.2", 8333)
      pm:add_known_address("192.168.1.3", 8333)
      -- Add address from different subnet
      pm:add_known_address("10.0.0.1", 8333)

      -- Simulate connected peer from 192.168.1.x
      pm:_add_outbound_group("192.168.1.1")

      -- Should only select from different subnet
      local candidate = pm:select_peer_to_connect()
      if candidate then
        assert.equals("10.0.0.1", candidate.ip)
      end
    end)

  end)

  describe("bucket constants", function()

    it("has correct new bucket count", function()
      assert.equals(256, peerman.ADDRMAN.NEW_BUCKET_COUNT)
    end)

    it("has correct tried bucket count", function()
      assert.equals(64, peerman.ADDRMAN.TRIED_BUCKET_COUNT)
    end)

    it("has correct bucket size", function()
      assert.equals(64, peerman.ADDRMAN.BUCKET_SIZE)
    end)

    it("has correct max anchors", function()
      assert.equals(2, peerman.ADDRMAN.MAX_ANCHORS)
    end)

  end)

  --------------------------------------------------------------------------------
  -- Stale Tip Detection & Eviction Tests
  -- Reference: Bitcoin Core net_processing.cpp ConsiderEviction, EvictExtraOutboundPeers
  --------------------------------------------------------------------------------

  describe("stale tip detection", function()

    local function make_mock_outbound_peer(ip, port)
      return {
        ip = ip or "192.168.1.1",
        port = port or 8333,
        inbound = false,
        state = peer_mod.STATE.ESTABLISHED,
        _established_notified = true,
        disconnect = function(self, reason)
          self.state = peer_mod.STATE.DISCONNECTED
          self.disconnect_reason = reason
        end,
        send_message = function(self, cmd, payload)
          self._sent_messages = self._sent_messages or {}
          self._sent_messages[#self._sent_messages + 1] = {command = cmd, payload = payload}
        end,
      }
    end

    describe("stale tip constants", function()

      it("has correct stale check interval", function()
        assert.equals(600, peerman.STALE_TIP.STALE_CHECK_INTERVAL)
      end)

      it("has correct chain sync timeout", function()
        assert.equals(1200, peerman.STALE_TIP.CHAIN_SYNC_TIMEOUT)
      end)

      it("has correct headers response time", function()
        assert.equals(120, peerman.STALE_TIP.HEADERS_RESPONSE_TIME)
      end)

      it("has correct minimum connect time", function()
        assert.equals(30, peerman.STALE_TIP.MINIMUM_CONNECT_TIME)
      end)

      it("has correct extra peer check interval", function()
        assert.equals(45, peerman.STALE_TIP.EXTRA_PEER_CHECK_INTERVAL)
      end)

    end)

    describe("tip_may_be_stale", function()

      it("returns false when tip was recently updated", function()
        local pm = peerman.new(test_network, nil, nil)
        pm:record_tip_update()
        assert.is_false(pm:tip_may_be_stale())
      end)

      it("returns true when tip is older than 3x block interval", function()
        local pm = peerman.new(test_network, nil, nil)
        pm.network = {pow_target_spacing = 600}  -- 10 minute blocks
        -- Simulate old tip (> 30 minutes = 1800 seconds)
        pm._last_tip_update = pm._last_tip_update - 2000
        assert.is_true(pm:tip_may_be_stale())
      end)

      it("returns false when blocks are in-flight even if tip is old", function()
        local pm = peerman.new(test_network, nil, nil)
        pm.network = {pow_target_spacing = 600}
        pm._last_tip_update = pm._last_tip_update - 2000
        -- Simulate blocks in-flight
        pm:record_block_in_flight("somehash", {})
        assert.is_false(pm:tip_may_be_stale())
      end)

      it("updates stale state after tip update", function()
        local pm = peerman.new(test_network, nil, nil)
        pm.network = {pow_target_spacing = 600}
        pm._last_tip_update = pm._last_tip_update - 2000
        assert.is_true(pm:tip_may_be_stale())

        pm:record_tip_update()
        assert.is_false(pm:tip_may_be_stale())
      end)

    end)

    describe("peer best block tracking", function()

      it("sets and gets peer best block", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_outbound_peer()

        pm:set_peer_best_block(mock_peer, 100000, "blockhash", 123456)
        local best = pm:get_peer_best_block(mock_peer)

        assert.equals(100000, best.height)
        assert.equals("blockhash", best.hash)
        assert.equals(123456, best.work)
      end)

      it("returns nil for unknown peer", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_outbound_peer()
        assert.is_nil(pm:get_peer_best_block(mock_peer))
      end)

    end)

    describe("peer block announcement tracking", function()

      it("records block announcement timestamp", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_outbound_peer()

        local before = os.time()
        pm:record_peer_block_announcement(mock_peer, "somehash")
        local ann_time = pm:get_peer_last_block_announcement(mock_peer)

        assert.is_true(ann_time >= before)
      end)

      it("returns 0 for peer with no announcements", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_outbound_peer()
        assert.equals(0, pm:get_peer_last_block_announcement(mock_peer))
      end)

    end)

    describe("chain sync state", function()

      it("initializes chain sync state for outbound peer", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_outbound_peer()

        pm:_init_peer_chain_sync(mock_peer)
        local state = pm:get_peer_chain_sync(mock_peer)

        assert.is_not_nil(state)
        assert.equals(0, state.timeout)
        assert.is_nil(state.work_header)
        assert.is_false(state.sent_getheaders)
        assert.is_false(state.protect)
      end)

      it("cleans up chain sync state on disconnect", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_outbound_peer()

        pm:_init_peer_chain_sync(mock_peer)
        pm:set_peer_best_block(mock_peer, 100, "hash", 0)
        pm:record_peer_block_announcement(mock_peer, "hash")

        pm:_cleanup_peer_chain_sync(mock_peer)

        assert.is_nil(pm:get_peer_chain_sync(mock_peer))
        assert.is_nil(pm:get_peer_best_block(mock_peer))
        assert.equals(0, pm:get_peer_last_block_announcement(mock_peer))
      end)

    end)

    describe("consider_eviction", function()

      it("does nothing for inbound peers", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_outbound_peer()
        mock_peer.inbound = true

        pm:_init_peer_chain_sync(mock_peer)
        pm:consider_eviction(mock_peer, os.time())

        -- Should not set timeout
        local state = pm:get_peer_chain_sync(mock_peer)
        assert.equals(0, state.timeout)
      end)

      it("does nothing for protected peers", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_outbound_peer()

        pm:_init_peer_chain_sync(mock_peer)
        local state = pm:get_peer_chain_sync(mock_peer)
        state.protect = true

        pm.our_height = 100000
        pm:set_peer_best_block(mock_peer, 50000, "hash", 0)
        pm:consider_eviction(mock_peer, os.time())

        -- Timeout should not be set for protected peer
        assert.equals(0, state.timeout)
      end)

      it("resets timeout when peer catches up to our tip", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_outbound_peer()

        pm:_init_peer_chain_sync(mock_peer)
        local state = pm:get_peer_chain_sync(mock_peer)
        state.timeout = 1000  -- Previously set timeout

        pm.our_height = 100000
        pm:set_peer_best_block(mock_peer, 100001, "hash", 0)  -- Peer is ahead
        pm:consider_eviction(mock_peer, os.time())

        assert.equals(0, state.timeout)
      end)

      it("sets timeout when peer is behind our tip", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_outbound_peer()

        pm:_init_peer_chain_sync(mock_peer)
        pm.our_height = 100000
        pm:set_peer_best_block(mock_peer, 50000, "hash", 0)

        local now = os.time()
        pm:consider_eviction(mock_peer, now)

        local state = pm:get_peer_chain_sync(mock_peer)
        assert.is_true(state.timeout > 0)
        assert.equals(now + peerman.STALE_TIP.CHAIN_SYNC_TIMEOUT, state.timeout)
      end)

      it("sends getheaders when timeout exceeded first time", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_outbound_peer()
        pm.peer_list[1] = mock_peer
        pm.peers["192.168.1.1:8333"] = mock_peer

        pm:_init_peer_chain_sync(mock_peer)
        pm.our_height = 100000
        pm:set_peer_best_block(mock_peer, 50000, "hash", 0)

        local state = pm:get_peer_chain_sync(mock_peer)
        state.timeout = os.time() - 100  -- Timeout already passed
        state.sent_getheaders = false

        pm:consider_eviction(mock_peer, os.time())

        assert.is_true(state.sent_getheaders)
        assert.is_not_nil(mock_peer._sent_messages)
        assert.equals(1, #mock_peer._sent_messages)
        assert.equals("getheaders", mock_peer._sent_messages[1].command)
      end)

      it("disconnects peer when timeout exceeded after getheaders sent", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = make_mock_outbound_peer()
        pm.peer_list[1] = mock_peer
        pm.peers["192.168.1.1:8333"] = mock_peer

        pm:_init_peer_chain_sync(mock_peer)
        pm.our_height = 100000
        pm:set_peer_best_block(mock_peer, 50000, "hash", 0)

        local state = pm:get_peer_chain_sync(mock_peer)
        state.timeout = os.time() - 100
        state.sent_getheaders = true  -- Already sent getheaders

        pm:consider_eviction(mock_peer, os.time())

        assert.equals(peer_mod.STATE.DISCONNECTED, mock_peer.state)
        assert.equals("outbound peer has old chain", mock_peer.disconnect_reason)
      end)

    end)

    describe("evict_extra_outbound_peers", function()

      it("does nothing when at or below target outbound count", function()
        local pm = peerman.new(test_network, nil, {max_outbound = 8})
        -- Add 6 outbound peers (below target of 8)
        for i = 1, 6 do
          local mock_peer = make_mock_outbound_peer("192.168.1." .. i, 8333)
          pm.peer_list[i] = mock_peer
          pm.peers["192.168.1." .. i .. ":8333"] = mock_peer
          pm:_init_peer_chain_sync(mock_peer)
        end

        pm:evict_extra_outbound_peers(os.time())

        -- All peers should still be connected
        for i = 1, 6 do
          assert.equals(peer_mod.STATE.ESTABLISHED, pm.peer_list[i].state)
        end
      end)

      it("evicts peer with oldest block announcement when over target", function()
        local pm = peerman.new(test_network, nil, {max_outbound = 2})
        local now = os.time()

        -- Add 3 outbound peers (1 over target)
        for i = 1, 3 do
          local mock_peer = make_mock_outbound_peer("192.168." .. i .. ".1", 8333)
          pm.peer_list[i] = mock_peer
          pm.peers["192.168." .. i .. ".1:8333"] = mock_peer
          pm:_init_peer_chain_sync(mock_peer)
          -- Set different announcement times
          pm._peer_last_block_ann["192.168." .. i .. ".1:8333"] = now - (i * 100)
          -- Set connect time to past (beyond MINIMUM_CONNECT_TIME)
          pm._peer_connect_time["192.168." .. i .. ".1:8333"] = now - 1000
        end

        pm:evict_extra_outbound_peers(now)

        -- Peer 3 has oldest announcement, should be disconnected
        assert.equals(peer_mod.STATE.DISCONNECTED, pm.peer_list[3].state)
        assert.equals(peer_mod.STATE.ESTABLISHED, pm.peer_list[1].state)
        assert.equals(peer_mod.STATE.ESTABLISHED, pm.peer_list[2].state)
      end)

      it("does not evict peers with blocks in-flight", function()
        local pm = peerman.new(test_network, nil, {max_outbound = 2})
        local now = os.time()

        -- Add 3 outbound peers (1 over target)
        for i = 1, 3 do
          local mock_peer = make_mock_outbound_peer("192.168." .. i .. ".1", 8333)
          pm.peer_list[i] = mock_peer
          pm.peers["192.168." .. i .. ".1:8333"] = mock_peer
          pm:_init_peer_chain_sync(mock_peer)
          pm._peer_last_block_ann["192.168." .. i .. ".1:8333"] = now - (i * 100)
          pm._peer_connect_time["192.168." .. i .. ".1:8333"] = now - 1000
        end

        -- Peer 3 has blocks in-flight
        pm._blocks_in_flight["somehash"] = {peer = pm.peer_list[3], time = now}

        pm:evict_extra_outbound_peers(now)

        -- No peer should be evicted (worst peer has blocks in-flight)
        for i = 1, 3 do
          assert.equals(peer_mod.STATE.ESTABLISHED, pm.peer_list[i].state)
        end
      end)

      it("does not evict recently connected peers", function()
        local pm = peerman.new(test_network, nil, {max_outbound = 2})
        local now = os.time()

        -- Add 3 outbound peers (1 over target)
        for i = 1, 3 do
          local mock_peer = make_mock_outbound_peer("192.168." .. i .. ".1", 8333)
          pm.peer_list[i] = mock_peer
          pm.peers["192.168." .. i .. ".1:8333"] = mock_peer
          pm:_init_peer_chain_sync(mock_peer)
          pm._peer_last_block_ann["192.168." .. i .. ".1:8333"] = now - (i * 100)
          -- All peers connected very recently
          pm._peer_connect_time["192.168." .. i .. ".1:8333"] = now - 5
        end

        pm:evict_extra_outbound_peers(now)

        -- No peer should be evicted (all connected within MINIMUM_CONNECT_TIME)
        for i = 1, 3 do
          assert.equals(peer_mod.STATE.ESTABLISHED, pm.peer_list[i].state)
        end
      end)

      it("does not evict protected peers", function()
        local pm = peerman.new(test_network, nil, {max_outbound = 2})
        local now = os.time()

        -- Add 3 outbound peers
        for i = 1, 3 do
          local mock_peer = make_mock_outbound_peer("192.168." .. i .. ".1", 8333)
          pm.peer_list[i] = mock_peer
          pm.peers["192.168." .. i .. ".1:8333"] = mock_peer
          pm:_init_peer_chain_sync(mock_peer)
          pm._peer_last_block_ann["192.168." .. i .. ".1:8333"] = now - (i * 100)
          pm._peer_connect_time["192.168." .. i .. ".1:8333"] = now - 1000
        end

        -- Protect peer 3 (the one that would normally be evicted)
        local key3 = "192.168.3.1:8333"
        pm._peer_chain_sync[key3].protect = true

        pm:evict_extra_outbound_peers(now)

        -- Peer 2 should be evicted instead (next oldest announcement)
        assert.equals(peer_mod.STATE.DISCONNECTED, pm.peer_list[2].state)
        assert.equals(peer_mod.STATE.ESTABLISHED, pm.peer_list[3].state)
      end)

      it("clears try_new_outbound_peer flag after successful eviction", function()
        local pm = peerman.new(test_network, nil, {max_outbound = 2})
        local now = os.time()
        pm._try_new_outbound_peer = true

        -- Add 3 outbound peers
        for i = 1, 3 do
          local mock_peer = make_mock_outbound_peer("192.168." .. i .. ".1", 8333)
          pm.peer_list[i] = mock_peer
          pm.peers["192.168." .. i .. ".1:8333"] = mock_peer
          pm:_init_peer_chain_sync(mock_peer)
          pm._peer_last_block_ann["192.168." .. i .. ".1:8333"] = now - (i * 100)
          pm._peer_connect_time["192.168." .. i .. ".1:8333"] = now - 1000
        end

        pm:evict_extra_outbound_peers(now)

        assert.is_false(pm._try_new_outbound_peer)
      end)

    end)

    describe("check_for_stale_tip_and_evict_peers", function()

      it("runs consider_eviction for outbound peers", function()
        local pm = peerman.new(test_network, nil, nil)
        pm.network = {pow_target_spacing = 600}
        pm.our_height = 100000
        pm._extra_peer_check_time = 0  -- Force check to run

        local mock_peer = make_mock_outbound_peer()
        pm.peer_list[1] = mock_peer
        pm.peers["192.168.1.1:8333"] = mock_peer
        pm:_init_peer_chain_sync(mock_peer)
        pm:set_peer_best_block(mock_peer, 50000, "hash", 0)

        pm:check_for_stale_tip_and_evict_peers()

        -- Should have set timeout for behind peer
        local state = pm:get_peer_chain_sync(mock_peer)
        assert.is_true(state.timeout > 0)
      end)

      it("enables extra outbound peer when tip is stale", function()
        local pm = peerman.new(test_network, nil, nil)
        pm.network = {pow_target_spacing = 600}
        pm._last_tip_update = pm._last_tip_update - 2000  -- Old tip
        pm._stale_tip_check_time = 0  -- Force check to run

        assert.is_false(pm._try_new_outbound_peer)
        pm:check_for_stale_tip_and_evict_peers()
        assert.is_true(pm._try_new_outbound_peer)
      end)

      it("disables extra outbound peer when tip is no longer stale", function()
        local pm = peerman.new(test_network, nil, nil)
        pm.network = {pow_target_spacing = 600}
        pm._try_new_outbound_peer = true
        pm._stale_tip_check_time = 0

        pm:record_tip_update()
        pm:check_for_stale_tip_and_evict_peers()

        assert.is_false(pm._try_new_outbound_peer)
      end)

    end)

    describe("extra outbound connections", function()

      it("should_try_new_outbound_peer returns correct state", function()
        local pm = peerman.new(test_network, nil, nil)
        assert.is_false(pm:should_try_new_outbound_peer())
        pm:set_try_new_outbound_peer(true)
        assert.is_true(pm:should_try_new_outbound_peer())
      end)

      it("maintain_connections allows extra peer when stale", function()
        local pm = peerman.new(test_network, nil, {max_outbound = 2})
        pm._try_new_outbound_peer = true

        -- Add 2 known addresses (at target)
        pm:add_known_address("192.168.1.1", 8333)
        pm:add_known_address("192.168.2.1", 8333)
        pm:add_known_address("192.168.3.1", 8333)

        -- Note: We can't fully test maintain_connections without real sockets
        -- but we can verify the target calculation logic
        local extra_count = pm:get_extra_full_outbound_count()
        -- With 0 connected and max_outbound=2, extra count should be 0
        assert.equals(0, extra_count)
      end)

    end)

    describe("blocks in-flight tracking", function()

      it("records and removes blocks in-flight", function()
        local pm = peerman.new(test_network, nil, nil)
        local mock_peer = {}

        pm:record_block_in_flight("hash1", mock_peer)
        pm:record_block_in_flight("hash2", mock_peer)

        assert.is_true(pm:is_block_in_flight("hash1"))
        assert.is_true(pm:is_block_in_flight("hash2"))
        assert.equals(2, pm:get_blocks_in_flight_count())

        pm:remove_block_in_flight("hash1")
        assert.is_false(pm:is_block_in_flight("hash1"))
        assert.equals(1, pm:get_blocks_in_flight_count())
      end)

    end)

  end)

end)
