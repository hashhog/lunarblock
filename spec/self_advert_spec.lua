-- Self-address advertisement (Bitcoin Core -externalip / -discover /
-- GetLocalAddrForPeer / MaybeSendAddr parity).  See peerman.lua
-- "Self-address advertisement".
local peerman = require("lunarblock.peerman")
local peer_mod = require("lunarblock.peer")
local p2p = require("lunarblock.p2p")

local function make_temp_dir()
  local tmpname = os.tmpname()
  os.remove(tmpname)
  os.execute("mkdir -p " .. tmpname)
  return tmpname
end

describe("self-address advertisement", function()
  local test_network = {
    name = "test", magic_bytes = "\xfa\xbf\xb5\xda",
    port = 18444, default_port = 18444, dns_seeds = {},
  }
  local tmp, pm

  -- A listening PeerManager (fake bound socket on port 8342) out of IBD.
  local function new_pm(cfg)
    cfg = cfg or {}
    cfg.data_dir = tmp
    local m = peerman.new(test_network, nil, cfg)
    m.listen_sockets = { { socket = nil, host = "0.0.0.0", port = 8342, bound_port = 8342 } }
    m.is_ibd_func = function() return false end
    return m
  end

  local function mock_peer(opts)
    local sent = {}
    local p = {
      ip = opts.ip, port = opts.port or 8333, inbound = opts.inbound or false,
      is_feeler = opts.is_feeler, send_addrv2 = opts.send_addrv2 or false,
      state = peer_mod.STATE.ESTABLISHED, our_services = opts.services or 0xc09,
      version_info = { recv_ip = opts.recv_ip or "0.0.0.0", recv_port = opts.recv_port or 0 },
      sent = sent,
    }
    function p:send_message(cmd, payload) sent[#sent + 1] = { cmd = cmd, payload = payload } end
    return p
  end

  before_each(function()
    tmp = make_temp_dir()
    pm = new_pm()
  end)
  after_each(function() os.execute("rm -rf " .. tmp) end)

  describe("routable filter", function()
    it("accepts public IPv4 / IPv6", function()
      assert.is_true(peerman.is_publicly_routable("1.2.3.4"))
      assert.is_true(peerman.is_publicly_routable("76.38.7.169"))
      assert.is_true(peerman.is_publicly_routable("2600:1700::1"))
      assert.is_true(peerman.is_publicly_routable("::ffff:8.8.8.8"))
    end)
    it("rejects private, loopback, link-local, doc, reserved and non-IP", function()
      for _, a in ipairs({ "10.0.0.1", "192.168.1.128", "172.16.5.5", "127.0.0.1",
          "0.0.0.0", "169.254.1.1", "100.64.0.1", "192.0.2.1", "198.51.100.7",
          "203.0.113.9", "255.255.255.255", "::", "::1", "fe80::1", "fd00::1",
          "fc00::5", "2001:db8::1", "2001:10::1", "ff02::1", "::ffff:10.0.0.1",
          "abc.onion", "not-an-ip", "1.2.3.256" }) do
        assert.is_false(peerman.is_publicly_routable(a), a)
      end
    end)
    it("parses and canonicalises IPv6", function()
      assert.equals("2001:db8::1", peerman.parse_ip("2001:0db8:0:0:0:0:0:1").str)
      assert.equals("1.2.3.4", peerman.parse_ip("::ffff:1.2.3.4").str)
      assert.equals(16, #peerman.parse_ip("2600:1700::1").bytes)
    end)
    it("parses --externalip specs", function()
      local ip, port = peerman.parse_external_ip("1.2.3.4")
      assert.equals("1.2.3.4", ip); assert.is_nil(port)
      ip, port = peerman.parse_external_ip("1.2.3.4:9999")
      assert.equals("1.2.3.4", ip); assert.equals(9999, port)
      ip, port = peerman.parse_external_ip("[2600:1700::1]:8342")
      assert.equals("2600:1700::1", ip); assert.equals(8342, port)
      ip, port = peerman.parse_external_ip("2600:1700::1")
      assert.equals("2600:1700::1", ip); assert.is_nil(port)
      assert.is_nil((peerman.parse_external_ip("bogus")))
      assert.is_nil((peerman.parse_external_ip("1.2.3.4:0")))
    end)
  end)

  describe("--externalip", function()
    it("adds a LOCAL_MANUAL entry with the listen port", function()
      assert.is_true(pm:add_external_ip("1.2.3.4"))
      local l = pm:get_local_addresses()
      assert.equals(1, #l)
      assert.same({ address = "1.2.3.4", port = 8342, score = 4 }, l[1])
    end)
    it("keeps an explicit port", function()
      assert.is_true(pm:add_external_ip("1.2.3.4", 9999))
      assert.equals(9999, pm:get_local_addresses()[1].port)
    end)
    it("refuses non-routable addresses", function()
      assert.is_false(pm:add_external_ip("192.168.1.128"))
      assert.equals(0, #pm:get_local_addresses())
    end)
  end)

  describe("discovery from addr_recv", function()
    it("records an outbound peer's view of us with OUR listen port", function()
      local p = mock_peer({ ip = "8.8.8.8", recv_ip = "76.38.7.169", recv_port = 51234 })
      assert.is_true(pm:note_version_addr_recv(p, 1000))
      local l = pm:list_local_addresses(1000)
      assert.same({ address = "76.38.7.169", port = 8342, score = 1 }, l[1])
    end)
    it("scores by distinct peer netgroups, not peers", function()
      pm:note_version_addr_recv(mock_peer({ ip = "8.8.8.8", recv_ip = "76.38.7.169" }), 1000)
      pm:note_version_addr_recv(mock_peer({ ip = "8.8.4.4", recv_ip = "76.38.7.169" }), 1001) -- same /16
      assert.equals(1, pm:list_local_addresses(1001)[1].score)
      pm:note_version_addr_recv(mock_peer({ ip = "9.9.9.9", recv_ip = "76.38.7.169" }), 1002)
      assert.equals(2, pm:list_local_addresses(1002)[1].score)
    end)
    it("ignores non-routable peers or reported addresses", function()
      assert.is_false(pm:note_version_addr_recv(mock_peer({ ip = "127.0.0.1", recv_ip = "76.38.7.169" }), 1))
      assert.is_false(pm:note_version_addr_recv(mock_peer({ ip = "8.8.8.8", recv_ip = "192.168.1.128" }), 1))
      assert.equals(0, #pm:list_local_addresses(1))
    end)
    it("inbound peers only confirm an existing entry", function()
      assert.is_false(pm:note_version_addr_recv(
        mock_peer({ ip = "8.8.8.8", recv_ip = "76.38.7.169", inbound = true }), 1))
      pm:note_version_addr_recv(mock_peer({ ip = "9.9.9.9", recv_ip = "76.38.7.169" }), 2)
      assert.is_true(pm:note_version_addr_recv(
        mock_peer({ ip = "8.8.8.8", recv_ip = "76.38.7.169", inbound = true }), 3))
      assert.equals(2, pm:list_local_addresses(3)[1].score)
    end)
    it("is off with discover=false or when not listening", function()
      local nd = new_pm({ discover = false })
      assert.is_false(nd:note_version_addr_recv(mock_peer({ ip = "8.8.8.8", recv_ip = "76.38.7.169" }), 1))
      pm.listen_sockets = {}
      assert.is_false(pm:note_version_addr_recv(mock_peer({ ip = "8.8.8.8", recv_ip = "76.38.7.169" }), 1))
    end)
    it("expires discovered entries after 3h, never manual ones", function()
      pm:add_external_ip("1.2.3.4")
      pm:note_version_addr_recv(mock_peer({ ip = "8.8.8.8", recv_ip = "76.38.7.169" }), 1000)
      assert.equals(2, #pm:list_local_addresses(1000))
      local l = pm:list_local_addresses(1000 + 3 * 3600 + 1)
      assert.equals(1, #l)
      assert.equals("1.2.3.4", l[1].address)
    end)
    it("caps discovered entries at 8", function()
      for i = 1, 12 do
        pm:note_version_addr_recv(mock_peer({ ip = "8.8.8.8", recv_ip = "76.38.7." .. i }), 1000 + i)
      end
      assert.equals(8, #pm:list_local_addresses(1100))
    end)
  end)

  describe("addr / addrv2 self-announcement", function()
    it("sends one legacy addr with our services, time now and the listen port", function()
      pm:add_external_ip("1.2.3.4")
      local p = mock_peer({ ip = "127.0.0.1", services = 0xc09 })
      assert.is_true(pm:maybe_send_local_addr(p, 1700000000))
      assert.equals(1, #p.sent)
      assert.equals("addr", p.sent[1].cmd)
      local list = p2p.deserialize_addr(p.sent[1].payload)
      assert.equals(1, #list)
      assert.equals("1.2.3.4", list[1].ip)
      assert.equals(8342, list[1].port)
      assert.equals(0xc09, list[1].services)
      assert.equals(1700000000, list[1].timestamp)
    end)
    it("sends addrv2 to a sendaddrv2 peer", function()
      pm:add_external_ip("1.2.3.4")
      local p = mock_peer({ ip = "127.0.0.1", send_addrv2 = true })
      assert.is_true(pm:maybe_send_local_addr(p, 1700000000))
      assert.equals("addrv2", p.sent[1].cmd)
      local list = p2p.deserialize_addrv2(p.sent[1].payload)
      assert.equals(1, #list)
      assert.equals(p2p.NET_ID.IPV4, list[1].network_id)
      assert.equals("1.2.3.4", list[1].addr_str)
      assert.equals(8342, list[1].port)
      assert.equals(1700000000, list[1].timestamp)
    end)
    it("encodes an IPv6 address correctly in legacy addr", function()
      pm:add_external_ip("2600:1700::1")
      local p = mock_peer({ ip = "2a01:4f8::2" })
      assert.is_true(pm:maybe_send_local_addr(p, 1700000000))
      local raw = p.sent[1].payload
      -- varint(1) + u32 time + u64 services, then the 16 address bytes
      assert.equals(peerman.parse_ip("2600:1700::1").bytes, raw:sub(14, 29))
    end)
    it("sends nothing when there is no usable address", function()
      local p = mock_peer({ ip = "127.0.0.1" })
      assert.is_false(pm:maybe_send_local_addr(p, 1))
      assert.equals(0, #p.sent)
    end)
    it("does not advertise a discovered address confirmed by only one netgroup", function()
      pm:note_version_addr_recv(mock_peer({ ip = "8.8.8.8", recv_ip = "76.38.7.169" }), 1)
      local p = mock_peer({ ip = "127.0.0.1" })
      assert.is_false(pm:maybe_send_local_addr(p, 2))
      pm:note_version_addr_recv(mock_peer({ ip = "9.9.9.9", recv_ip = "76.38.7.169" }), 3)
      local p2 = mock_peer({ ip = "127.0.0.1" })
      assert.is_true(pm:maybe_send_local_addr(p2, 4))
      assert.equals("76.38.7.169", p2p.deserialize_addr(p2.sent[1].payload)[1].ip)
    end)
    it("an outbound peer's own view supplies the IP but keeps our listen port", function()
      local p = mock_peer({ ip = "8.8.8.8", recv_ip = "76.38.7.169", recv_port = 51234 })
      assert.is_true(pm:maybe_send_local_addr(p, 1))
      local a = p2p.deserialize_addr(p.sent[1].payload)[1]
      assert.equals("76.38.7.169", a.ip)
      assert.equals(8342, a.port)
    end)
    it("an inbound peer's own view supplies IP and port", function()
      local p = mock_peer({ ip = "8.8.8.8", recv_ip = "76.38.7.169", recv_port = 8342, inbound = true })
      assert.is_true(pm:maybe_send_local_addr(p, 1))
      assert.equals(8342, p2p.deserialize_addr(p.sent[1].payload)[1].port)
    end)
    it("never announces to feelers or when not listening", function()
      pm:add_external_ip("1.2.3.4")
      local f = mock_peer({ ip = "127.0.0.1", is_feeler = true })
      assert.is_false(pm:maybe_send_local_addr(f, 1))
      pm.listen_sockets = {}
      local p = mock_peer({ ip = "127.0.0.1" })
      assert.is_false(pm:maybe_send_local_addr(p, 1))
      assert.equals(0, #f.sent + #p.sent)
    end)
    it("re-announces only when the Poisson timer is due", function()
      pm:add_external_ip("1.2.3.4")
      local p = mock_peer({ ip = "127.0.0.1" })
      assert.is_true(pm:maybe_send_local_addr(p, 1000))
      assert.is_false(pm:maybe_send_local_addr(p, 1001))
      assert.is_true(p._next_local_addr_send > 1000)
      assert.is_true(pm:maybe_send_local_addr(p, p._next_local_addr_send))
      assert.equals(2, #p.sent)
    end)
  end)

  describe("IBD gate", function()
    it("withholds the announcement in IBD and sends on the first tick after", function()
      pm:add_external_ip("1.2.3.4")
      local in_ibd = true
      pm.is_ibd_func = function() return in_ibd end
      local p = mock_peer({ ip = "127.0.0.1" })
      p._established_notified = true
      pm.peer_list = { p }
      assert.is_false(pm:maybe_send_local_addr(p, 1000))
      assert.is_nil(p._next_local_addr_send)  -- timer untouched
      pm:_process_local_addr_timers(1000)
      assert.equals(0, #p.sent)
      in_ibd = false
      pm:_process_local_addr_timers(1030)      -- < CHECK_INTERVAL: not yet
      assert.equals(0, #p.sent)
      pm:_process_local_addr_timers(1060)
      assert.equals(1, #p.sent)
      assert.equals("1.2.3.4", p2p.deserialize_addr(p.sent[1].payload)[1].ip)
    end)
    it("an erroring IBD probe counts as IBD", function()
      pm:add_external_ip("1.2.3.4")
      pm.is_ibd_func = function() error("boom") end
      assert.is_false(pm:maybe_send_local_addr(mock_peer({ ip = "127.0.0.1" }), 1))
    end)
  end)
end)
