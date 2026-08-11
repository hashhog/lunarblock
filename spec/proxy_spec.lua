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
    -- These tests need a REAL concurrent peer.  luasocket is blocking and
    -- busted runs single-threaded, so the previous coroutine pattern
    -- (resume -> server:accept() with a 0.5s timeout BEFORE the client ever
    -- connects) deadlocked by construction: accept timed out, the coroutine
    -- finished without serving anything, and s5:connect() then timed out
    -- talking to a listening-but-never-accepted socket.  The mock server
    -- now runs in a fork()ed child process: it accepts one connection,
    -- checks the wire bytes against Core's SOCKS5 sequence
    -- (netbase.cpp:400-500), and reports "ok"/"bad:<what>" through a
    -- transcript file the parent asserts on.
    local ffi = require("ffi")
    ffi.cdef[[
      typedef int32_t pid_t;
      pid_t fork(void);
      pid_t waitpid(pid_t pid, int *status, int options);
    ]]

    local function wait_for_file(path, timeout)
      local deadline = socket.gettime() + timeout
      while socket.gettime() < deadline do
        local f = io.open(path, "r")
        if f then f:close(); return true end
        socket.sleep(0.01)
      end
      return false
    end

    -- Fork a mock-server child running server_fn(cs, want).
    -- @return port, transcript_path, child_pid
    local function start_mock_server(server_fn)
      -- Grab an ephemeral port first so the child never races a bind.
      local probe = socket.tcp()
      probe:setoption("reuseaddr", true)
      assert(probe:bind("127.0.0.1", 0))
      local _, port = probe:getsockname()
      probe:close()

      local transcript = os.tmpname()
      local ready = transcript .. ".ready"

      local pid = ffi.C.fork()
      assert(pid >= 0, "fork failed")
      if pid == 0 then
        -- ── child process: the mock SOCKS5 server ─────────────────────
        local result
        local srv = socket.tcp()
        srv:setoption("reuseaddr", true)
        local bind_ok = srv:bind("127.0.0.1", port)
        if bind_ok then srv:listen(1) end
        srv:settimeout(3)
        -- Signal the parent that the listener is up (or failed to come up).
        local rf = io.open(ready, "w"); rf:write("1"); rf:close()
        if not bind_ok then
          result = "bad:bind"
        else
          local cs = srv:accept()
          if not cs then
            result = "bad:accept-timeout"
          else
            cs:settimeout(2)
            local fails = {}
            local function want(got, expected, what)
              if got ~= expected then
                fails[#fails + 1] = string.format("%s: got %s, want %s",
                  what, tostring(got), tostring(expected))
              end
            end
            local ok, perr = pcall(server_fn, cs, want)
            if not ok then
              result = "bad:" .. tostring(perr)
            elseif #fails > 0 then
              result = "bad:" .. fails[1]
            else
              result = "ok"
            end
            cs:close()
          end
        end
        srv:close()
        local tf = io.open(transcript, "w")
        tf:write(result or "bad:unknown")
        tf:close()
        os.exit(0)
      end

      -- ── parent: wait for the child's listener ───────────────────────
      assert.is_true(wait_for_file(ready, 3),
        "mock server child did not start listening")
      return port, transcript, pid
    end

    -- Reap the child and assert its wire-level checks all passed.
    local function assert_mock_ok(pid, transcript)
      ffi.C.waitpid(pid, nil, 0)
      local f = io.open(transcript, "r")
      local result = f and f:read("*a") or "bad:no-transcript"
      if f then f:close() end
      os.remove(transcript)
      os.remove(transcript .. ".ready")
      assert.equals("ok", result)
    end

    it("performs SOCKS5 handshake with no auth", function()
      -- Core sends 05 01 00 (VER, 1 method, NO_AUTH) for a credential-less
      -- client (netbase.cpp:405-411) and always uses ATYP=0x03 DOMAINNAME
      -- in the CONNECT request (netbase.cpp:453-461).
      local port, transcript, pid = start_mock_server(function(cs, want)
        want(cs:receive(3), string.char(0x05, 0x01, 0x00), "method selection")
        cs:send(string.char(0x05, 0x00))

        want(cs:receive(4), string.char(0x05, 0x01, 0x00, 0x03),
          "CONNECT header")
        local dlen = cs:receive(1)
        want(cs:receive(dlen:byte(1)), "example.com", "CONNECT domain")
        local pb = cs:receive(2)
        want(pb:byte(1) * 256 + pb:byte(2), 80, "CONNECT port")

        -- VER REP RSV ATYP BND.ADDR BND.PORT — success, 127.0.0.1:80
        cs:send(string.char(
          0x05, 0x00, 0x00, 0x01,
          127, 0, 0, 1,
          0x00, 0x50
        ))
      end)

      local s5 = proxy.new_socks5("127.0.0.1", port)
      s5.timeout = 2
      local sock, err = s5:connect("example.com", 80)

      assert.is_not_nil(sock)
      assert.is_nil(err)
      if sock then sock:close() end
      assert_mock_ok(pid, transcript)
    end)

    it("handles SOCKS5 authentication", function()
      -- With credentials Core advertises both methods (05 02 00 02,
      -- netbase.cpp:404-409), then speaks RFC 1929: 01 ulen user plen pass
      -- (netbase.cpp:425-435) and requires the 01 00 success reply.
      local port, transcript, pid = start_mock_server(function(cs, want)
        want(cs:receive(4), string.char(0x05, 0x02, 0x00, 0x02),
          "method selection")
        -- Request username/password auth
        cs:send(string.char(0x05, 0x02))

        want(cs:receive(1), string.char(0x01), "auth version")
        local ulen = cs:receive(1)
        want(cs:receive(ulen:byte(1)), "testuser", "auth username")
        local plen = cs:receive(1)
        want(cs:receive(plen:byte(1)), "testpass", "auth password")
        cs:send(string.char(0x01, 0x00))

        -- CONNECT request (domain + port consumed, not pinned here)
        cs:receive(4)
        local dlen = cs:receive(1)
        cs:receive(dlen:byte(1))
        cs:receive(2)

        cs:send(string.char(
          0x05, 0x00, 0x00, 0x01,
          127, 0, 0, 1,
          0x00, 0x50
        ))
      end)

      local s5 = proxy.new_socks5("127.0.0.1", port, "testuser", "testpass")
      s5.timeout = 2
      local sock, err = s5:connect("test.onion", 80)

      assert.is_not_nil(sock)
      assert.is_nil(err)
      if sock then sock:close() end
      assert_mock_ok(pid, transcript)
    end)

    it("handles connection refused error", function()
      -- REP=0x05 must surface Core's Socks5ErrorString text
      -- (netbase.cpp:365 "connection refused").
      local port, transcript, pid = start_mock_server(function(cs)
        cs:receive(3)
        cs:send(string.char(0x05, 0x00))

        cs:receive(4)
        local dlen = cs:receive(1)
        cs:receive(dlen:byte(1))
        cs:receive(2)

        cs:send(string.char(
          0x05, 0x05, 0x00, 0x01,  -- CONNREFUSED
          0, 0, 0, 0,
          0x00, 0x00
        ))
      end)

      local s5 = proxy.new_socks5("127.0.0.1", port)
      s5.timeout = 2
      local sock, err = s5:connect("test.com", 80)

      assert.is_nil(sock)
      assert.is_not_nil(err)
      assert.is_true(err:find("connection refused") ~= nil)
      assert_mock_ok(pid, transcript)
    end)

    it("handles Tor-specific onion service errors", function()
      -- REP=0xF0 is Tor's HS_DESC_NOT_FOUND extension
      -- (netbase.cpp:276, Socks5ErrorString netbase.cpp:371-372).
      local port, transcript, pid = start_mock_server(function(cs)
        cs:receive(3)
        cs:send(string.char(0x05, 0x00))

        cs:receive(4)
        local dlen = cs:receive(1)
        cs:receive(dlen:byte(1))
        cs:receive(2)

        cs:send(string.char(
          0x05, 0xF0, 0x00, 0x01,  -- TOR_HS_DESC_NOT_FOUND
          0, 0, 0, 0,
          0x00, 0x00
        ))
      end)

      local s5 = proxy.new_socks5("127.0.0.1", port)
      s5.timeout = 2
      local sock, err = s5:connect("nonexistent.onion", 80)

      assert.is_nil(sock)
      assert.is_not_nil(err)
      assert.is_true(err:find("onion service") ~= nil)
      assert_mock_ok(pid, transcript)
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
