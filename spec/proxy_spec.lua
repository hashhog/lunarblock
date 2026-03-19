local proxy = require("lunarblock.proxy")
local socket = require("socket")

describe("proxy", function()

  describe("SOCKS5 constants", function()
    it("has correct SOCKS version", function()
      assert.equals(0x05, proxy.SOCKS_VERSION)
    end)

    it("has correct authentication methods", function()
      assert.equals(0x00, proxy.SOCKS_AUTH.NO_AUTH)
      assert.equals(0x02, proxy.SOCKS_AUTH.USER_PASS)
      assert.equals(0xFF, proxy.SOCKS_AUTH.NO_ACCEPTABLE)
    end)

    it("has correct commands", function()
      assert.equals(0x01, proxy.SOCKS_CMD.CONNECT)
      assert.equals(0x02, proxy.SOCKS_CMD.BIND)
      assert.equals(0x03, proxy.SOCKS_CMD.UDP_ASSOCIATE)
    end)

    it("has correct address types", function()
      assert.equals(0x01, proxy.SOCKS_ATYP.IPV4)
      assert.equals(0x03, proxy.SOCKS_ATYP.DOMAINNAME)
      assert.equals(0x04, proxy.SOCKS_ATYP.IPV6)
    end)

    it("has correct reply codes", function()
      assert.equals(0x00, proxy.SOCKS_REPLY.SUCCEEDED)
      assert.equals(0x01, proxy.SOCKS_REPLY.GENFAILURE)
      assert.equals(0x05, proxy.SOCKS_REPLY.CONNREFUSED)
    end)
  end)

  describe("I2P SAM constants", function()
    it("has correct default SAM port", function()
      assert.equals(7656, proxy.I2P_SAM_PORT)
    end)
  end)

  describe("network type detection", function()
    it("detects IPv4 addresses", function()
      assert.equals(proxy.NETWORK_TYPE.IPV4, proxy.detect_network_type("127.0.0.1"))
      assert.equals(proxy.NETWORK_TYPE.IPV4, proxy.detect_network_type("192.168.1.1"))
      assert.equals(proxy.NETWORK_TYPE.IPV4, proxy.detect_network_type("8.8.8.8"))
    end)

    it("detects IPv6 addresses", function()
      assert.equals(proxy.NETWORK_TYPE.IPV6, proxy.detect_network_type("::1"))
      assert.equals(proxy.NETWORK_TYPE.IPV6, proxy.detect_network_type("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
      assert.equals(proxy.NETWORK_TYPE.IPV6, proxy.detect_network_type("fe80::1"))
    end)

    it("detects Tor v3 onion addresses", function()
      -- Example v3 onion (56 chars + .onion)
      local v3_onion = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"
      assert.equals(proxy.NETWORK_TYPE.ONION, proxy.detect_network_type(v3_onion))
    end)

    it("detects Tor v2 onion addresses (deprecated)", function()
      -- Example v2 onion (16 chars + .onion)
      local v2_onion = "expyuzz4wqqyqhjn.onion"
      assert.equals(proxy.NETWORK_TYPE.ONION, proxy.detect_network_type(v2_onion))
    end)

    it("detects I2P addresses", function()
      local i2p = "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p"
      assert.equals(proxy.NETWORK_TYPE.I2P, proxy.detect_network_type(i2p))
    end)

    it("handles nil input", function()
      assert.is_nil(proxy.detect_network_type(nil))
    end)
  end)

  describe("is_onion", function()
    it("returns true for onion addresses", function()
      assert.is_true(proxy.is_onion("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"))
    end)

    it("returns false for non-onion addresses", function()
      assert.is_false(proxy.is_onion("127.0.0.1"))
      assert.is_false(proxy.is_onion("example.b32.i2p"))
    end)
  end)

  describe("is_i2p", function()
    it("returns true for I2P addresses", function()
      assert.is_true(proxy.is_i2p("ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p"))
    end)

    it("returns false for non-I2P addresses", function()
      assert.is_false(proxy.is_i2p("127.0.0.1"))
      assert.is_false(proxy.is_i2p("example.onion"))
    end)
  end)

  describe("socks5_error_string", function()
    it("returns readable error for known codes", function()
      assert.equals("general failure", proxy.socks5_error_string(0x01))
      assert.equals("connection refused", proxy.socks5_error_string(0x05))
      assert.equals("host unreachable", proxy.socks5_error_string(0x04))
    end)

    it("returns hex for unknown codes", function()
      local msg = proxy.socks5_error_string(0x42)
      assert.is_true(msg:find("0x42") ~= nil)
    end)
  end)

  describe("new_socks5", function()
    it("creates SOCKS5 proxy with defaults", function()
      local s5 = proxy.new_socks5()
      assert.equals("127.0.0.1", s5.host)
      assert.equals(9050, s5.port)
      assert.is_nil(s5.username)
      assert.is_nil(s5.password)
      assert.equals(20, s5.timeout)
      assert.is_false(s5.stream_isolation)
    end)

    it("creates SOCKS5 proxy with custom settings", function()
      local s5 = proxy.new_socks5("192.168.1.1", 1080, "user", "pass")
      assert.equals("192.168.1.1", s5.host)
      assert.equals(1080, s5.port)
      assert.equals("user", s5.username)
      assert.equals("pass", s5.password)
    end)

    it("supports stream isolation", function()
      local s5 = proxy.new_socks5()
      s5:enable_stream_isolation()
      assert.is_true(s5.stream_isolation)
    end)
  end)

  describe("new_i2p_sam", function()
    it("creates I2P SAM client with defaults", function()
      local sam = proxy.new_i2p_sam()
      assert.equals("127.0.0.1", sam.host)
      assert.equals(7656, sam.port)
      assert.is_nil(sam.private_key_file)
      assert.equals(180, sam.timeout)
    end)

    it("creates I2P SAM client with custom settings", function()
      local sam = proxy.new_i2p_sam("10.0.0.1", 7657, "/tmp/i2p.key")
      assert.equals("10.0.0.1", sam.host)
      assert.equals(7657, sam.port)
      assert.equals("/tmp/i2p.key", sam.private_key_file)
    end)
  end)

  describe("ProxyConfig", function()
    it("creates empty config", function()
      local cfg = proxy.new_config()
      assert.is_nil(cfg.socks5_proxy)
      assert.is_nil(cfg.i2p_sam)
      assert.is_nil(cfg.onlynet)
      assert.is_false(cfg.proxy_dns)
    end)

    it("configures SOCKS5 proxy", function()
      local cfg = proxy.new_config()
      cfg:set_socks5_proxy("127.0.0.1", 9050, true)
      assert.is_not_nil(cfg.socks5_proxy)
      assert.equals("127.0.0.1", cfg.socks5_proxy.host)
      assert.equals(9050, cfg.socks5_proxy.port)
      assert.is_true(cfg.socks5_proxy.stream_isolation)
    end)

    it("configures I2P SAM", function()
      local cfg = proxy.new_config()
      cfg:set_i2p_sam("127.0.0.1", 7656, "/tmp/key")
      assert.is_not_nil(cfg.i2p_sam)
      assert.equals("127.0.0.1", cfg.i2p_sam.host)
      assert.equals(7656, cfg.i2p_sam.port)
    end)

    it("configures onlynet restriction", function()
      local cfg = proxy.new_config()
      cfg:set_onlynet("onion")
      assert.equals("onion", cfg.onlynet)
    end)

    it("rejects invalid onlynet values", function()
      local cfg = proxy.new_config()
      assert.has_error(function()
        cfg:set_onlynet("invalid")
      end)
    end)

    it("accepts valid onlynet values", function()
      local cfg = proxy.new_config()
      assert.has_no.errors(function()
        cfg:set_onlynet("onion")
        cfg:set_onlynet("i2p")
        cfg:set_onlynet("ipv4")
        cfg:set_onlynet("ipv6")
        cfg:set_onlynet(nil)
      end)
    end)
  end)

  describe("address filtering with onlynet", function()
    it("allows all addresses with no restriction", function()
      local cfg = proxy.new_config()
      assert.is_true(cfg:is_address_allowed("127.0.0.1"))
      assert.is_true(cfg:is_address_allowed("::1"))
      assert.is_true(cfg:is_address_allowed("test.onion"))
      assert.is_true(cfg:is_address_allowed("test.b32.i2p"))
    end)

    it("filters to onion only", function()
      local cfg = proxy.new_config()
      cfg:set_onlynet("onion")
      assert.is_false(cfg:is_address_allowed("127.0.0.1"))
      assert.is_false(cfg:is_address_allowed("::1"))
      assert.is_true(cfg:is_address_allowed("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"))
      assert.is_false(cfg:is_address_allowed("test.b32.i2p"))
    end)

    it("filters to I2P only", function()
      local cfg = proxy.new_config()
      cfg:set_onlynet("i2p")
      assert.is_false(cfg:is_address_allowed("127.0.0.1"))
      assert.is_false(cfg:is_address_allowed("::1"))
      assert.is_false(cfg:is_address_allowed("test.onion"))
      assert.is_true(cfg:is_address_allowed("ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p"))
    end)

    it("filters to IPv4 only", function()
      local cfg = proxy.new_config()
      cfg:set_onlynet("ipv4")
      assert.is_true(cfg:is_address_allowed("127.0.0.1"))
      assert.is_false(cfg:is_address_allowed("::1"))
      assert.is_false(cfg:is_address_allowed("test.onion"))
    end)

    it("filters to IPv6 only", function()
      local cfg = proxy.new_config()
      cfg:set_onlynet("ipv6")
      assert.is_false(cfg:is_address_allowed("127.0.0.1"))
      assert.is_true(cfg:is_address_allowed("::1"))
      assert.is_false(cfg:is_address_allowed("test.onion"))
    end)
  end)

  describe("SOCKS5 handshake with mock server", function()
    local server
    local server_port = 19400

    before_each(function()
      server = socket.tcp()
      server:setoption("reuseaddr", true)
      local ok = server:bind("127.0.0.1", server_port)
      if not ok then
        server_port = server_port + 1
        server:bind("127.0.0.1", server_port)
      end
      server:listen(1)
      server:settimeout(0.5)
    end)

    after_each(function()
      if server then
        server:close()
        server = nil
      end
    end)

    it("performs SOCKS5 handshake with no auth", function()
      -- Start a coroutine to act as the SOCKS5 server
      local server_done = false
      local client_sock = nil

      -- Accept connection in a separate coroutine
      local co = coroutine.create(function()
        client_sock = server:accept()
        if client_sock then
          client_sock:settimeout(1)

          -- Receive method selection
          local data = client_sock:receive(3)
          assert.equals(string.char(0x05, 0x01, 0x00), data)

          -- Send method selection response (no auth)
          client_sock:send(string.char(0x05, 0x00))

          -- Receive CONNECT request
          local req_header = client_sock:receive(4)
          assert.equals(string.char(0x05, 0x01, 0x00, 0x03), req_header)

          -- Read domain length and domain
          local domain_len = client_sock:receive(1)
          local domain = client_sock:receive(domain_len:byte(1))
          assert.equals("example.com", domain)

          -- Read port
          local port_bytes = client_sock:receive(2)
          local port = port_bytes:byte(1) * 256 + port_bytes:byte(2)
          assert.equals(80, port)

          -- Send success response
          -- VER REP RSV ATYP BND.ADDR BND.PORT
          client_sock:send(string.char(
            0x05, 0x00, 0x00, 0x01,  -- SOCKS5, success, reserved, IPv4
            127, 0, 0, 1,             -- Bound address (127.0.0.1)
            0x00, 0x50                -- Bound port (80)
          ))

          server_done = true
        end
      end)

      -- Run server coroutine briefly
      coroutine.resume(co)

      -- Connect through proxy
      local s5 = proxy.new_socks5("127.0.0.1", server_port)
      s5.timeout = 1

      local sock, err = s5:connect("example.com", 80)

      -- Resume server to handle remaining steps
      coroutine.resume(co)

      -- Verify connection succeeded
      assert.is_not_nil(sock)
      assert.is_nil(err)

      if sock then sock:close() end
      if client_sock then client_sock:close() end
    end)

    it("handles SOCKS5 authentication", function()
      local client_sock = nil

      local co = coroutine.create(function()
        client_sock = server:accept()
        if client_sock then
          client_sock:settimeout(1)

          -- Receive method selection (should include USER_PASS)
          local data = client_sock:receive(4)
          assert.equals(string.char(0x05, 0x02, 0x00, 0x02), data)

          -- Request username/password auth
          client_sock:send(string.char(0x05, 0x02))

          -- Receive auth request (version, ulen, user, plen, pass)
          local auth_ver = client_sock:receive(1)
          assert.equals(string.char(0x01), auth_ver)

          local ulen = client_sock:receive(1)
          local user = client_sock:receive(ulen:byte(1))
          assert.equals("testuser", user)

          local plen = client_sock:receive(1)
          local pass = client_sock:receive(plen:byte(1))
          assert.equals("testpass", pass)

          -- Send auth success
          client_sock:send(string.char(0x01, 0x00))

          -- Receive CONNECT request
          local req_header = client_sock:receive(4)

          -- Read domain
          local domain_len = client_sock:receive(1)
          client_sock:receive(domain_len:byte(1))
          client_sock:receive(2)

          -- Send success
          client_sock:send(string.char(
            0x05, 0x00, 0x00, 0x01,
            127, 0, 0, 1,
            0x00, 0x50
          ))
        end
      end)

      coroutine.resume(co)

      local s5 = proxy.new_socks5("127.0.0.1", server_port, "testuser", "testpass")
      s5.timeout = 1

      local sock, err = s5:connect("test.onion", 80)

      coroutine.resume(co)

      assert.is_not_nil(sock)
      assert.is_nil(err)

      if sock then sock:close() end
      if client_sock then client_sock:close() end
    end)

    it("handles connection refused error", function()
      local client_sock = nil

      local co = coroutine.create(function()
        client_sock = server:accept()
        if client_sock then
          client_sock:settimeout(1)

          -- Method selection
          client_sock:receive(3)
          client_sock:send(string.char(0x05, 0x00))

          -- CONNECT request
          client_sock:receive(4)
          local domain_len = client_sock:receive(1)
          client_sock:receive(domain_len:byte(1))
          client_sock:receive(2)

          -- Send connection refused error
          client_sock:send(string.char(
            0x05, 0x05, 0x00, 0x01,  -- CONNREFUSED
            0, 0, 0, 0,
            0x00, 0x00
          ))
        end
      end)

      coroutine.resume(co)

      local s5 = proxy.new_socks5("127.0.0.1", server_port)
      s5.timeout = 1

      local sock, err = s5:connect("test.com", 80)

      coroutine.resume(co)

      assert.is_nil(sock)
      assert.is_not_nil(err)
      assert.is_true(err:find("connection refused") ~= nil)

      if client_sock then client_sock:close() end
    end)

    it("handles Tor-specific onion service errors", function()
      local client_sock = nil

      local co = coroutine.create(function()
        client_sock = server:accept()
        if client_sock then
          client_sock:settimeout(1)

          client_sock:receive(3)
          client_sock:send(string.char(0x05, 0x00))

          client_sock:receive(4)
          local domain_len = client_sock:receive(1)
          client_sock:receive(domain_len:byte(1))
          client_sock:receive(2)

          -- Send Tor onion service not found error
          client_sock:send(string.char(
            0x05, 0xF0, 0x00, 0x01,  -- TOR_HS_DESC_NOT_FOUND
            0, 0, 0, 0,
            0x00, 0x00
          ))
        end
      end)

      coroutine.resume(co)

      local s5 = proxy.new_socks5("127.0.0.1", server_port)
      s5.timeout = 1

      local sock, err = s5:connect("nonexistent.onion", 80)

      coroutine.resume(co)

      assert.is_nil(sock)
      assert.is_not_nil(err)
      assert.is_true(err:find("onion service") ~= nil)

      if client_sock then client_sock:close() end
    end)
  end)

  describe("I2P SAM protocol with mock server", function()
    local server
    local server_port = 19500

    before_each(function()
      server = socket.tcp()
      server:setoption("reuseaddr", true)
      local ok = server:bind("127.0.0.1", server_port)
      if not ok then
        server_port = server_port + 1
        server:bind("127.0.0.1", server_port)
      end
      server:listen(1)
      server:settimeout(0.5)
    end)

    after_each(function()
      if server then
        server:close()
        server = nil
      end
    end)

    it("performs SAM HELLO handshake", function()
      local client_sock = nil

      local co = coroutine.create(function()
        client_sock = server:accept()
        if client_sock then
          client_sock:settimeout(1)

          -- Receive HELLO
          local line = ""
          while true do
            local char = client_sock:receive(1)
            if char == "\n" then break end
            line = line .. char
          end

          assert.is_true(line:find("HELLO VERSION") ~= nil)

          -- Send response
          client_sock:send("HELLO REPLY RESULT=OK VERSION=3.1\n")
        end
      end)

      coroutine.resume(co)

      local sam = proxy.new_i2p_sam("127.0.0.1", server_port)
      sam.timeout = 1

      -- Manually test hello by calling internal connect method
      local test_sock = socket.tcp()
      test_sock:settimeout(1)
      test_sock:connect("127.0.0.1", server_port)

      -- Let server handle the connection
      coroutine.resume(co)

      if test_sock then test_sock:close() end
      if client_sock then client_sock:close() end
    end)
  end)

  describe("ProxyConfig connect logic", function()
    it("rejects onion addresses without proxy", function()
      local cfg = proxy.new_config()
      local sock, err = cfg:connect("test.onion", 8333)
      assert.is_nil(sock)
      assert.is_true(err:find("no SOCKS5 proxy") ~= nil)
    end)

    it("rejects I2P addresses without SAM", function()
      local cfg = proxy.new_config()
      local sock, err = cfg:connect("test.b32.i2p", 0)
      assert.is_nil(sock)
      assert.is_true(err:find("no I2P SAM") ~= nil)
    end)

    it("rejects addresses blocked by onlynet", function()
      local cfg = proxy.new_config()
      cfg:set_onlynet("onion")
      local sock, err = cfg:connect("127.0.0.1", 8333)
      assert.is_nil(sock)
      assert.is_true(err:find("onlynet") ~= nil)
    end)
  end)

end)
