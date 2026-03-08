describe("p2p", function()
  local p2p = require("lunarblock.p2p")
  local types = require("lunarblock.types")
  local consensus = require("lunarblock.consensus")
  local crypto = require("lunarblock.crypto")

  local mainnet_magic = consensus.networks.mainnet.magic_bytes

  describe("command encoding/decoding", function()
    it("round-trips 'version'", function()
      local encoded = p2p.encode_command("version")
      assert.equals(12, #encoded)
      assert.equals("version", p2p.decode_command(encoded))
    end)

    it("round-trips 'verack'", function()
      local encoded = p2p.encode_command("verack")
      assert.equals(12, #encoded)
      assert.equals("verack", p2p.decode_command(encoded))
    end)

    it("round-trips 'tx'", function()
      local encoded = p2p.encode_command("tx")
      assert.equals(12, #encoded)
      assert.equals("tx", p2p.decode_command(encoded))
    end)

    it("round-trips 'block'", function()
      local encoded = p2p.encode_command("block")
      assert.equals(12, #encoded)
      assert.equals("block", p2p.decode_command(encoded))
    end)

    it("truncates commands longer than 12 bytes", function()
      local encoded = p2p.encode_command("verylongcommandname")
      assert.equals(12, #encoded)
      assert.equals("verylongcomm", p2p.decode_command(encoded))
    end)

    it("pads short commands with null bytes", function()
      local encoded = p2p.encode_command("tx")
      assert.equals("tx\0\0\0\0\0\0\0\0\0\0", encoded)
    end)
  end)

  describe("message framing", function()
    it("make_message produces correct 24-byte header", function()
      local payload = "test payload"
      local msg = p2p.make_message(mainnet_magic, "test", payload)

      -- Total message is 24-byte header + payload
      assert.equals(24 + #payload, #msg)

      -- Parse the header
      local header = p2p.parse_header(msg:sub(1, 24))
      assert.is_not_nil(header)
      assert.equals(mainnet_magic, header.magic)
      assert.equals("test", header.command)
      assert.equals(#payload, header.length)
    end)

    it("make_message produces valid checksum", function()
      local payload = "test payload"
      local msg = p2p.make_message(mainnet_magic, "test", payload)

      local header = p2p.parse_header(msg:sub(1, 24))
      assert.is_true(p2p.verify_checksum(payload, header.checksum))
    end)

    it("parse_header extracts correct fields", function()
      local payload = ""
      local msg = p2p.make_message(mainnet_magic, "verack", payload)
      local header = p2p.parse_header(msg:sub(1, 24))

      assert.equals(mainnet_magic, header.magic)
      assert.equals("verack", header.command)
      assert.equals(0, header.length)
    end)

    it("parse_header returns nil for short data", function()
      local header = p2p.parse_header("short")
      assert.is_nil(header)
    end)

    it("verify_checksum accepts valid checksum", function()
      local payload = "hello world"
      local checksum = crypto.hash256(payload):sub(1, 4)
      assert.is_true(p2p.verify_checksum(payload, checksum))
    end)

    it("verify_checksum rejects invalid checksum", function()
      local payload = "hello world"
      local bad_checksum = "\x00\x00\x00\x00"
      assert.is_false(p2p.verify_checksum(payload, bad_checksum))
    end)
  end)

  describe("IP address conversion", function()
    it("round-trips 127.0.0.1", function()
      local bytes = p2p.ip_to_bytes("127.0.0.1")
      assert.equals(16, #bytes)
      assert.equals("127.0.0.1", p2p.bytes_to_ip(bytes))
    end)

    it("round-trips 0.0.0.0", function()
      local bytes = p2p.ip_to_bytes("0.0.0.0")
      assert.equals(16, #bytes)
      assert.equals("0.0.0.0", p2p.bytes_to_ip(bytes))
    end)

    it("round-trips 192.168.1.1", function()
      local bytes = p2p.ip_to_bytes("192.168.1.1")
      assert.equals(16, #bytes)
      assert.equals("192.168.1.1", p2p.bytes_to_ip(bytes))
    end)

    it("round-trips 255.255.255.255", function()
      local bytes = p2p.ip_to_bytes("255.255.255.255")
      assert.equals(16, #bytes)
      assert.equals("255.255.255.255", p2p.bytes_to_ip(bytes))
    end)

    it("produces IPv4-mapped IPv6 format", function()
      local bytes = p2p.ip_to_bytes("1.2.3.4")
      -- First 10 bytes should be zeros
      assert.equals(string.rep("\0", 10), bytes:sub(1, 10))
      -- Next 2 bytes should be 0xFF 0xFF
      assert.equals("\xff\xff", bytes:sub(11, 12))
      -- Last 4 bytes should be the IPv4 address
      assert.equals("\x01\x02\x03\x04", bytes:sub(13, 16))
    end)
  end)

  describe("version message", function()
    it("serialize/deserialize round-trip with all fields", function()
      local opts = {
        version = 70016,
        services = 9,  -- NODE_NETWORK | NODE_WITNESS
        timestamp = 1234567890,
        recv_services = 1,
        recv_ip = "192.168.1.1",
        recv_port = 8333,
        from_services = 9,
        from_ip = "10.0.0.1",
        from_port = 18333,
        nonce = 12345678901234,
        user_agent = "/LunarBlock:0.1.0/",
        start_height = 800000,
        relay = true,
      }

      local payload = p2p.serialize_version(opts)
      local decoded = p2p.deserialize_version(payload)

      assert.equals(opts.version, decoded.version)
      assert.equals(opts.services, decoded.services)
      assert.equals(opts.timestamp, decoded.timestamp)
      assert.equals(opts.recv_services, decoded.recv_services)
      assert.equals(opts.recv_ip, decoded.recv_ip)
      assert.equals(opts.recv_port, decoded.recv_port)
      assert.equals(opts.from_services, decoded.from_services)
      assert.equals(opts.from_ip, decoded.from_ip)
      assert.equals(opts.from_port, decoded.from_port)
      assert.equals(opts.nonce, decoded.nonce)
      assert.equals(opts.user_agent, decoded.user_agent)
      assert.equals(opts.start_height, decoded.start_height)
      assert.equals(opts.relay, decoded.relay)
    end)

    it("uses default values when opts is empty", function()
      local payload = p2p.serialize_version({})
      local decoded = p2p.deserialize_version(payload)

      assert.equals(p2p.PROTOCOL_VERSION, decoded.version)
      assert.equals("/LunarBlock:0.1.0/", decoded.user_agent)
    end)

    it("handles relay=false correctly", function()
      local opts = { relay = false }
      local payload = p2p.serialize_version(opts)
      local decoded = p2p.deserialize_version(payload)
      assert.is_false(decoded.relay)
    end)
  end)

  describe("ping/pong messages", function()
    it("ping round-trip with nonce", function()
      local nonce = 9876543210
      local payload = p2p.serialize_ping(nonce)
      assert.equals(8, #payload)
      local decoded = p2p.deserialize_ping(payload)
      assert.equals(nonce, decoded)
    end)

    it("pong round-trip with nonce", function()
      local nonce = 1234567890123
      local payload = p2p.serialize_pong(nonce)
      assert.equals(8, #payload)
      local decoded = p2p.deserialize_pong(payload)
      assert.equals(nonce, decoded)
    end)

    it("handles large nonces", function()
      local nonce = 2^52 - 1  -- Max safe integer
      local payload = p2p.serialize_ping(nonce)
      local decoded = p2p.deserialize_ping(payload)
      assert.equals(nonce, decoded)
    end)
  end)

  describe("inventory messages", function()
    it("serialize/deserialize round-trip with multiple items", function()
      local hash1 = types.hash256(string.rep("\x01", 32))
      local hash2 = types.hash256(string.rep("\x02", 32))
      local hash3 = types.hash256(string.rep("\x03", 32))

      local inventory = {
        { type = p2p.INV_TYPE.MSG_TX, hash = hash1 },
        { type = p2p.INV_TYPE.MSG_BLOCK, hash = hash2 },
        { type = p2p.INV_TYPE.MSG_WITNESS_TX, hash = hash3 },
      }

      local payload = p2p.serialize_inv(inventory)
      local decoded = p2p.deserialize_inv(payload)

      assert.equals(3, #decoded)
      assert.equals(p2p.INV_TYPE.MSG_TX, decoded[1].type)
      assert.equals(hash1.bytes, decoded[1].hash.bytes)
      assert.equals(p2p.INV_TYPE.MSG_BLOCK, decoded[2].type)
      assert.equals(hash2.bytes, decoded[2].hash.bytes)
      assert.equals(p2p.INV_TYPE.MSG_WITNESS_TX, decoded[3].type)
      assert.equals(hash3.bytes, decoded[3].hash.bytes)
    end)

    it("handles empty inventory", function()
      local inventory = {}
      local payload = p2p.serialize_inv(inventory)
      local decoded = p2p.deserialize_inv(payload)
      assert.equals(0, #decoded)
    end)

    it("getdata uses same format as inv", function()
      local hash = types.hash256(string.rep("\xAB", 32))
      local items = {{ type = p2p.INV_TYPE.MSG_BLOCK, hash = hash }}

      local payload = p2p.serialize_getdata(items)
      local decoded = p2p.deserialize_getdata(payload)

      assert.equals(1, #decoded)
      assert.equals(p2p.INV_TYPE.MSG_BLOCK, decoded[1].type)
    end)

    it("notfound uses same format as inv", function()
      local hash = types.hash256(string.rep("\xCD", 32))
      local items = {{ type = p2p.INV_TYPE.MSG_TX, hash = hash }}

      local payload = p2p.serialize_notfound(items)
      local decoded = p2p.deserialize_notfound(payload)

      assert.equals(1, #decoded)
      assert.equals(p2p.INV_TYPE.MSG_TX, decoded[1].type)
    end)
  end)

  describe("getblocks/getheaders messages", function()
    it("getblocks serialize/deserialize round-trip", function()
      local hash1 = types.hash256(string.rep("\x11", 32))
      local hash2 = types.hash256(string.rep("\x22", 32))
      local stop_hash = types.hash256(string.rep("\xFF", 32))

      local payload = p2p.serialize_getblocks(70016, {hash1, hash2}, stop_hash)
      local decoded = p2p.deserialize_getblocks(payload)

      assert.equals(70016, decoded.version)
      assert.equals(2, #decoded.block_locator_hashes)
      assert.equals(hash1.bytes, decoded.block_locator_hashes[1].bytes)
      assert.equals(hash2.bytes, decoded.block_locator_hashes[2].bytes)
      assert.equals(stop_hash.bytes, decoded.hash_stop.bytes)
    end)

    it("getheaders uses same format as getblocks", function()
      local hash = types.hash256(string.rep("\xAA", 32))
      local stop = types.hash256_zero()

      local payload = p2p.serialize_getheaders(70015, {hash}, stop)
      local decoded = p2p.deserialize_getheaders(payload)

      assert.equals(70015, decoded.version)
      assert.equals(1, #decoded.block_locator_hashes)
      assert.equals(hash.bytes, decoded.block_locator_hashes[1].bytes)
    end)

    it("handles empty block locator", function()
      local payload = p2p.serialize_getblocks(70016, {}, types.hash256_zero())
      local decoded = p2p.deserialize_getblocks(payload)

      assert.equals(0, #decoded.block_locator_hashes)
    end)
  end)

  describe("headers message", function()
    it("serialize/deserialize round-trip with multiple headers", function()
      local header1 = types.block_header(
        1,
        types.hash256(string.rep("\x00", 32)),
        types.hash256(string.rep("\x11", 32)),
        1231006505,
        0x1d00ffff,
        2083236893
      )
      local header2 = types.block_header(
        1,
        types.hash256(string.rep("\x22", 32)),
        types.hash256(string.rep("\x33", 32)),
        1231006506,
        0x1d00ffff,
        12345
      )

      local payload = p2p.serialize_headers({header1, header2})
      local decoded = p2p.deserialize_headers(payload)

      assert.equals(2, #decoded)
      assert.equals(header1.version, decoded[1].version)
      assert.equals(header1.timestamp, decoded[1].timestamp)
      assert.equals(header1.bits, decoded[1].bits)
      assert.equals(header1.nonce, decoded[1].nonce)
      assert.equals(header2.version, decoded[2].version)
      assert.equals(header2.timestamp, decoded[2].timestamp)
    end)

    it("handles empty headers list", function()
      local payload = p2p.serialize_headers({})
      local decoded = p2p.deserialize_headers(payload)
      assert.equals(0, #decoded)
    end)
  end)

  describe("addr message", function()
    it("serialize/deserialize round-trip", function()
      local addresses = {
        { timestamp = 1700000000, services = 1, ip = "192.168.1.1", port = 8333 },
        { timestamp = 1700000001, services = 9, ip = "10.0.0.1", port = 18333 },
      }

      local payload = p2p.serialize_addr(addresses)
      local decoded = p2p.deserialize_addr(payload)

      assert.equals(2, #decoded)
      assert.equals(addresses[1].timestamp, decoded[1].timestamp)
      assert.equals(addresses[1].services, decoded[1].services)
      assert.equals(addresses[1].ip, decoded[1].ip)
      assert.equals(addresses[1].port, decoded[1].port)
      assert.equals(addresses[2].timestamp, decoded[2].timestamp)
      assert.equals(addresses[2].services, decoded[2].services)
      assert.equals(addresses[2].ip, decoded[2].ip)
      assert.equals(addresses[2].port, decoded[2].port)
    end)

    it("handles empty address list", function()
      local payload = p2p.serialize_addr({})
      local decoded = p2p.deserialize_addr(payload)
      assert.equals(0, #decoded)
    end)
  end)

  describe("feefilter message", function()
    it("round-trip with feerate", function()
      local feerate = 1000  -- 1000 sat/KB
      local payload = p2p.serialize_feefilter(feerate)
      assert.equals(8, #payload)
      local decoded = p2p.deserialize_feefilter(payload)
      assert.equals(feerate, decoded)
    end)

    it("handles large feerate", function()
      local feerate = 1000000000  -- 1 BTC/KB
      local payload = p2p.serialize_feefilter(feerate)
      local decoded = p2p.deserialize_feefilter(payload)
      assert.equals(feerate, decoded)
    end)
  end)

  describe("sendcmpct message", function()
    it("round-trip with announce=true", function()
      local payload = p2p.serialize_sendcmpct(true, 2)
      local decoded = p2p.deserialize_sendcmpct(payload)
      assert.is_true(decoded.announce)
      assert.equals(2, decoded.version)
    end)

    it("round-trip with announce=false", function()
      local payload = p2p.serialize_sendcmpct(false, 1)
      local decoded = p2p.deserialize_sendcmpct(payload)
      assert.is_false(decoded.announce)
      assert.equals(1, decoded.version)
    end)
  end)

  describe("reject message", function()
    it("deserialize reject with hash", function()
      local hash = types.hash256(string.rep("\xAB", 32))
      local payload = p2p.serialize_reject("tx", 0x10, "invalid", hash)
      local decoded = p2p.deserialize_reject(payload)

      assert.equals("tx", decoded.message)
      assert.equals(0x10, decoded.ccode)
      assert.equals("invalid", decoded.reason)
      assert.equals(hash.bytes, decoded.hash.bytes)
    end)

    it("deserialize reject without hash", function()
      local payload = p2p.serialize_reject("version", 0x01, "obsolete", nil)
      local decoded = p2p.deserialize_reject(payload)

      assert.equals("version", decoded.message)
      assert.equals(0x01, decoded.ccode)
      assert.equals("obsolete", decoded.reason)
      assert.is_nil(decoded.hash)
    end)
  end)

  describe("constants", function()
    it("has correct header size", function()
      assert.equals(24, p2p.HEADER_SIZE)
    end)

    it("has correct max message size", function()
      assert.equals(32 * 1024 * 1024, p2p.MAX_MESSAGE_SIZE)
    end)

    it("has correct protocol version", function()
      assert.equals(70016, p2p.PROTOCOL_VERSION)
    end)

    it("has correct service flags", function()
      assert.equals(0, p2p.SERVICES.NODE_NONE)
      assert.equals(1, p2p.SERVICES.NODE_NETWORK)
      assert.equals(8, p2p.SERVICES.NODE_WITNESS)
      assert.equals(1024, p2p.SERVICES.NODE_NETWORK_LIMITED)
    end)

    it("has correct inventory types", function()
      assert.equals(0, p2p.INV_TYPE.ERROR)
      assert.equals(1, p2p.INV_TYPE.MSG_TX)
      assert.equals(2, p2p.INV_TYPE.MSG_BLOCK)
      assert.equals(0x40000001, p2p.INV_TYPE.MSG_WITNESS_TX)
      assert.equals(0x40000002, p2p.INV_TYPE.MSG_WITNESS_BLOCK)
    end)
  end)
end)
