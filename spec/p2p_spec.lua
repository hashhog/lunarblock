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

    it("has correct compact block inventory type", function()
      assert.equals(4, p2p.INV_TYPE.MSG_CMPCT_BLOCK)
    end)

    it("has short txid length constant", function()
      assert.equals(6, p2p.SHORTTXIDS_LENGTH)
    end)
  end)

  describe("BIP152 cmpctblock message", function()
    it("serialize/deserialize round-trip with header and nonce", function()
      local header = types.block_header(
        1,
        types.hash256(string.rep("\x00", 32)),
        types.hash256(string.rep("\x11", 32)),
        1231006505,
        0x1d00ffff,
        2083236893
      )

      local short_ids = { 0x112233445566, 0xAABBCCDDEEFF }
      local nonce = 0x123456789ABCDEF

      -- Create a simple coinbase transaction for prefilled
      local coinbase_tx = types.transaction(
        1,
        {types.txin(types.outpoint(types.hash256(string.rep("\x00", 32)), 0xFFFFFFFF), "\x04\xFF\xFF\x00\x1D", 0xFFFFFFFF)},
        {types.txout(5000000000, "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac")},
        0
      )

      local prefilled_txns = {{ index = 0, tx = coinbase_tx }}

      local payload = p2p.serialize_cmpctblock(header, nonce, short_ids, prefilled_txns)
      local decoded = p2p.deserialize_cmpctblock(payload)

      assert.equals(header.version, decoded.header.version)
      assert.equals(header.timestamp, decoded.header.timestamp)
      assert.equals(header.bits, decoded.header.bits)
      assert.equals(header.nonce, decoded.header.nonce)
      assert.equals(nonce, decoded.nonce)
      assert.equals(2, #decoded.short_ids)
      assert.equals(short_ids[1], decoded.short_ids[1])
      assert.equals(short_ids[2], decoded.short_ids[2])
      assert.equals(1, #decoded.prefilled_txns)
      assert.equals(0, decoded.prefilled_txns[1].index)
    end)

    it("handles empty short_ids list", function()
      local header = types.block_header(
        1,
        types.hash256(string.rep("\x00", 32)),
        types.hash256(string.rep("\x11", 32)),
        1231006505,
        0x1d00ffff,
        1
      )

      local coinbase_tx = types.transaction(
        1,
        {types.txin(types.outpoint(types.hash256(string.rep("\x00", 32)), 0xFFFFFFFF), "\x04", 0xFFFFFFFF)},
        {types.txout(5000000000, "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac")},
        0
      )

      local payload = p2p.serialize_cmpctblock(header, 0, {}, {{ index = 0, tx = coinbase_tx }})
      local decoded = p2p.deserialize_cmpctblock(payload)

      assert.equals(0, #decoded.short_ids)
      assert.equals(1, #decoded.prefilled_txns)
    end)

    it("cmpctblock_tx_count returns correct total", function()
      local cmpctblock = {
        short_ids = { 1, 2, 3, 4, 5 },
        prefilled_txns = {{ index = 0, tx = {} }},
      }
      assert.equals(6, p2p.cmpctblock_tx_count(cmpctblock))
    end)
  end)

  describe("BIP152 getblocktxn message", function()
    it("serialize/deserialize round-trip", function()
      local block_hash = types.hash256(string.rep("\xAB", 32))
      local indexes = { 1, 3, 5, 10, 100 }

      local payload = p2p.serialize_getblocktxn(block_hash, indexes)
      local decoded = p2p.deserialize_getblocktxn(payload)

      assert.equals(block_hash.bytes, decoded.block_hash.bytes)
      assert.equals(5, #decoded.indexes)
      assert.equals(1, decoded.indexes[1])
      assert.equals(3, decoded.indexes[2])
      assert.equals(5, decoded.indexes[3])
      assert.equals(10, decoded.indexes[4])
      assert.equals(100, decoded.indexes[5])
    end)

    it("handles empty indexes", function()
      local block_hash = types.hash256(string.rep("\xCD", 32))
      local payload = p2p.serialize_getblocktxn(block_hash, {})
      local decoded = p2p.deserialize_getblocktxn(payload)

      assert.equals(block_hash.bytes, decoded.block_hash.bytes)
      assert.equals(0, #decoded.indexes)
    end)

    it("uses differential encoding for indexes", function()
      local block_hash = types.hash256(string.rep("\x00", 32))
      -- Consecutive indexes should compress well
      local indexes = { 0, 1, 2, 3, 4 }

      local payload = p2p.serialize_getblocktxn(block_hash, indexes)
      local decoded = p2p.deserialize_getblocktxn(payload)

      for i, idx in ipairs(indexes) do
        assert.equals(idx, decoded.indexes[i])
      end
    end)
  end)

  describe("BIP152 blocktxn message", function()
    it("serialize/deserialize round-trip", function()
      local block_hash = types.hash256(string.rep("\xEF", 32))

      local tx1 = types.transaction(
        2,
        {types.txin(types.outpoint(types.hash256(string.rep("\x01", 32)), 0), "", 0xFFFFFFFF)},
        {types.txout(1000000, "\x00\x14" .. string.rep("\x00", 20))},
        0
      )
      local tx2 = types.transaction(
        2,
        {types.txin(types.outpoint(types.hash256(string.rep("\x02", 32)), 1), "", 0xFFFFFFFF)},
        {types.txout(2000000, "\x00\x14" .. string.rep("\x11", 20))},
        0
      )

      local transactions = { tx1, tx2 }

      local payload = p2p.serialize_blocktxn(block_hash, transactions)
      local decoded = p2p.deserialize_blocktxn(payload)

      assert.equals(block_hash.bytes, decoded.block_hash.bytes)
      assert.equals(2, #decoded.transactions)
      assert.equals(tx1.version, decoded.transactions[1].version)
      assert.equals(tx2.version, decoded.transactions[2].version)
    end)

    it("handles empty transactions list", function()
      local block_hash = types.hash256(string.rep("\xFF", 32))
      local payload = p2p.serialize_blocktxn(block_hash, {})
      local decoded = p2p.deserialize_blocktxn(payload)

      assert.equals(block_hash.bytes, decoded.block_hash.bytes)
      assert.equals(0, #decoded.transactions)
    end)
  end)

  describe("BIP155 addrv2 message", function()
    it("has correct network ID constants", function()
      assert.equals(1, p2p.NET_ID.IPV4)
      assert.equals(2, p2p.NET_ID.IPV6)
      assert.equals(3, p2p.NET_ID.TORV2)
      assert.equals(4, p2p.NET_ID.TORV3)
      assert.equals(5, p2p.NET_ID.I2P)
      assert.equals(6, p2p.NET_ID.CJDNS)
    end)

    it("has correct address size constants", function()
      assert.equals(4, p2p.NET_ADDR_SIZE[p2p.NET_ID.IPV4])
      assert.equals(16, p2p.NET_ADDR_SIZE[p2p.NET_ID.IPV6])
      assert.equals(10, p2p.NET_ADDR_SIZE[p2p.NET_ID.TORV2])
      assert.equals(32, p2p.NET_ADDR_SIZE[p2p.NET_ID.TORV3])
      assert.equals(32, p2p.NET_ADDR_SIZE[p2p.NET_ID.I2P])
      assert.equals(16, p2p.NET_ADDR_SIZE[p2p.NET_ID.CJDNS])
    end)

    it("serialize/deserialize round-trip with IPv4", function()
      local addresses = {
        {
          timestamp = 1700000000,
          services = 1033,
          network_id = p2p.NET_ID.IPV4,
          addr_bytes = string.char(192, 168, 1, 1),
          port = 8333,
        },
      }

      local payload = p2p.serialize_addrv2(addresses)
      local decoded = p2p.deserialize_addrv2(payload)

      assert.equals(1, #decoded)
      assert.equals(1700000000, decoded[1].timestamp)
      assert.equals(1033, decoded[1].services)
      assert.equals(p2p.NET_ID.IPV4, decoded[1].network_id)
      assert.equals("192.168.1.1", decoded[1].ip)
      assert.equals(8333, decoded[1].port)
      assert.is_true(decoded[1].valid)
    end)

    it("serialize/deserialize round-trip with IPv6", function()
      local ipv6_bytes = string.rep("\x20\x01", 8)  -- 2001:2001:2001:...
      local addresses = {
        {
          timestamp = 1700000001,
          services = 9,
          network_id = p2p.NET_ID.IPV6,
          addr_bytes = ipv6_bytes,
          port = 8333,
        },
      }

      local payload = p2p.serialize_addrv2(addresses)
      local decoded = p2p.deserialize_addrv2(payload)

      assert.equals(1, #decoded)
      assert.equals(p2p.NET_ID.IPV6, decoded[1].network_id)
      assert.equals(16, #decoded[1].addr_bytes)
      assert.is_true(decoded[1].valid)
    end)

    it("serialize/deserialize round-trip with TorV3", function()
      local torv3_pubkey = string.rep("\xAB", 32)  -- 32-byte ed25519 pubkey
      local addresses = {
        {
          timestamp = 1700000002,
          services = 1,
          network_id = p2p.NET_ID.TORV3,
          addr_bytes = torv3_pubkey,
          port = 8333,
        },
      }

      local payload = p2p.serialize_addrv2(addresses)
      local decoded = p2p.deserialize_addrv2(payload)

      assert.equals(1, #decoded)
      assert.equals(p2p.NET_ID.TORV3, decoded[1].network_id)
      assert.equals(32, #decoded[1].addr_bytes)
      assert.equals(torv3_pubkey, decoded[1].addr_bytes)
      assert.is_true(decoded[1].valid)
      -- addr_str should end with .onion
      assert.truthy(decoded[1].addr_str:match("%.onion$"))
    end)

    it("serialize/deserialize round-trip with I2P", function()
      local i2p_hash = string.rep("\xCD", 32)  -- 32-byte SHA256 of destination
      local addresses = {
        {
          timestamp = 1700000003,
          services = 1,
          network_id = p2p.NET_ID.I2P,
          addr_bytes = i2p_hash,
          port = 8333,
        },
      }

      local payload = p2p.serialize_addrv2(addresses)
      local decoded = p2p.deserialize_addrv2(payload)

      assert.equals(1, #decoded)
      assert.equals(p2p.NET_ID.I2P, decoded[1].network_id)
      assert.equals(32, #decoded[1].addr_bytes)
      assert.equals(i2p_hash, decoded[1].addr_bytes)
      assert.is_true(decoded[1].valid)
      -- addr_str should end with .b32.i2p
      assert.truthy(decoded[1].addr_str:match("%.b32%.i2p$"))
    end)

    it("serialize/deserialize round-trip with CJDNS", function()
      local cjdns_bytes = "\xFC" .. string.rep("\xEF", 15)  -- Must start with 0xFC
      local addresses = {
        {
          timestamp = 1700000004,
          services = 1,
          network_id = p2p.NET_ID.CJDNS,
          addr_bytes = cjdns_bytes,
          port = 8333,
        },
      }

      local payload = p2p.serialize_addrv2(addresses)
      local decoded = p2p.deserialize_addrv2(payload)

      assert.equals(1, #decoded)
      assert.equals(p2p.NET_ID.CJDNS, decoded[1].network_id)
      assert.equals(16, #decoded[1].addr_bytes)
      assert.is_true(decoded[1].valid)
    end)

    it("rejects CJDNS without 0xFC prefix", function()
      local bad_cjdns = "\x00" .. string.rep("\xEF", 15)  -- Missing 0xFC prefix
      local addresses = {
        {
          timestamp = 1700000005,
          services = 1,
          network_id = p2p.NET_ID.CJDNS,
          addr_bytes = bad_cjdns,
          port = 8333,
        },
      }

      local payload = p2p.serialize_addrv2(addresses)
      local decoded = p2p.deserialize_addrv2(payload)

      assert.equals(1, #decoded)
      assert.is_false(decoded[1].valid)  -- Invalid due to missing 0xFC prefix
    end)

    it("marks deprecated TORV2 as invalid", function()
      local torv2_bytes = string.rep("\x12", 10)  -- 10-byte TorV2
      local addresses = {
        {
          timestamp = 1700000006,
          services = 1,
          network_id = p2p.NET_ID.TORV2,
          addr_bytes = torv2_bytes,
          port = 8333,
        },
      }

      local payload = p2p.serialize_addrv2(addresses)
      local decoded = p2p.deserialize_addrv2(payload)

      assert.equals(1, #decoded)
      assert.is_false(decoded[1].valid)  -- TORV2 is deprecated
    end)

    it("rejects wrong address size for known network types", function()
      -- IPv4 should be 4 bytes, not 8
      local addresses = {
        {
          timestamp = 1700000007,
          services = 1,
          network_id = p2p.NET_ID.IPV4,
          addr_bytes = string.rep("\x01", 8),  -- Wrong size
          port = 8333,
        },
      }

      local payload = p2p.serialize_addrv2(addresses)
      local decoded = p2p.deserialize_addrv2(payload)

      assert.equals(1, #decoded)
      assert.is_false(decoded[1].valid)  -- Wrong size for IPv4
    end)

    it("handles multiple addresses with mixed network types", function()
      local addresses = {
        {
          timestamp = 1700000000,
          services = 1,
          network_id = p2p.NET_ID.IPV4,
          addr_bytes = string.char(10, 0, 0, 1),
          port = 8333,
        },
        {
          timestamp = 1700000001,
          services = 1,
          network_id = p2p.NET_ID.TORV3,
          addr_bytes = string.rep("\xAA", 32),
          port = 8333,
        },
        {
          timestamp = 1700000002,
          services = 1,
          network_id = p2p.NET_ID.I2P,
          addr_bytes = string.rep("\xBB", 32),
          port = 8333,
        },
      }

      local payload = p2p.serialize_addrv2(addresses)
      local decoded = p2p.deserialize_addrv2(payload)

      assert.equals(3, #decoded)
      assert.equals(p2p.NET_ID.IPV4, decoded[1].network_id)
      assert.equals("10.0.0.1", decoded[1].ip)
      assert.is_true(decoded[1].valid)

      assert.equals(p2p.NET_ID.TORV3, decoded[2].network_id)
      assert.is_true(decoded[2].valid)

      assert.equals(p2p.NET_ID.I2P, decoded[3].network_id)
      assert.is_true(decoded[3].valid)
    end)

    it("handles empty address list", function()
      local payload = p2p.serialize_addrv2({})
      local decoded = p2p.deserialize_addrv2(payload)
      assert.equals(0, #decoded)
    end)

    it("services field uses compact size encoding", function()
      -- Large services value should use compact size
      local addresses = {
        {
          timestamp = 1700000000,
          services = 0x0409,  -- NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED
          network_id = p2p.NET_ID.IPV4,
          addr_bytes = string.char(127, 0, 0, 1),
          port = 8333,
        },
      }

      local payload = p2p.serialize_addrv2(addresses)
      local decoded = p2p.deserialize_addrv2(payload)

      assert.equals(1, #decoded)
      assert.equals(0x0409, decoded[1].services)
    end)

    it("sendaddrv2 is an empty message", function()
      local payload = p2p.serialize_sendaddrv2()
      assert.equals("", payload)
      local decoded = p2p.deserialize_sendaddrv2(payload)
      assert.same({}, decoded)
    end)
  end)

  describe("BIP155 address compatibility", function()
    it("IPv4 is compatible with legacy addr", function()
      local addr = { network_id = p2p.NET_ID.IPV4 }
      assert.is_true(p2p.is_addr_compatible(false, addr))
      assert.is_true(p2p.is_addr_compatible(true, addr))
    end)

    it("IPv6 is compatible with legacy addr", function()
      local addr = { network_id = p2p.NET_ID.IPV6 }
      assert.is_true(p2p.is_addr_compatible(false, addr))
      assert.is_true(p2p.is_addr_compatible(true, addr))
    end)

    it("TorV3 is not compatible with legacy addr", function()
      local addr = { network_id = p2p.NET_ID.TORV3 }
      assert.is_false(p2p.is_addr_compatible(false, addr))
      assert.is_true(p2p.is_addr_compatible(true, addr))
    end)

    it("I2P is not compatible with legacy addr", function()
      local addr = { network_id = p2p.NET_ID.I2P }
      assert.is_false(p2p.is_addr_compatible(false, addr))
      assert.is_true(p2p.is_addr_compatible(true, addr))
    end)

    it("CJDNS is not compatible with legacy addr", function()
      local addr = { network_id = p2p.NET_ID.CJDNS }
      assert.is_false(p2p.is_addr_compatible(false, addr))
      assert.is_true(p2p.is_addr_compatible(true, addr))
    end)

    it("TORV2 is not compatible with anyone", function()
      local addr = { network_id = p2p.NET_ID.TORV2 }
      assert.is_false(p2p.is_addr_compatible(false, addr))
      assert.is_false(p2p.is_addr_compatible(true, addr))
    end)
  end)

  describe("BIP155 address string conversion", function()
    it("converts IPv4 bytes to string", function()
      local str = p2p.addr_bytes_to_string(p2p.NET_ID.IPV4, string.char(192, 168, 1, 100))
      assert.equals("192.168.1.100", str)
    end)

    it("converts IPv4-mapped IPv6 to IPv4 string", function()
      local bytes = string.rep("\0", 10) .. "\xff\xff" .. string.char(10, 0, 0, 1)
      local str = p2p.addr_bytes_to_string(p2p.NET_ID.IPV6, bytes)
      assert.equals("10.0.0.1", str)
    end)

    it("converts TorV3 bytes to .onion string", function()
      local pubkey = string.rep("\xAB", 32)
      local str = p2p.addr_bytes_to_string(p2p.NET_ID.TORV3, pubkey)
      assert.truthy(str:match("%.onion$"))
    end)

    it("converts I2P bytes to .b32.i2p string", function()
      local hash = string.rep("\xCD", 32)
      local str = p2p.addr_bytes_to_string(p2p.NET_ID.I2P, hash)
      assert.truthy(str:match("%.b32%.i2p$"))
    end)

    it("returns nil for invalid address size", function()
      local str = p2p.addr_bytes_to_string(p2p.NET_ID.IPV4, "abc")  -- Not 4 bytes
      assert.is_nil(str)
    end)
  end)
end)
