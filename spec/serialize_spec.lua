describe("serialize", function()
  local serialize, types

  setup(function()
    serialize = require("lunarblock.serialize")
    types = require("lunarblock.types")
  end)

  describe("buffer_writer", function()
    it("writes u8", function()
      local w = serialize.buffer_writer()
      w.write_u8(0)
      w.write_u8(255)
      w.write_u8(128)
      local result = w.result()
      assert.equal(3, #result)
      assert.equal(0, result:byte(1))
      assert.equal(255, result:byte(2))
      assert.equal(128, result:byte(3))
    end)

    it("writes u16le", function()
      local w = serialize.buffer_writer()
      w.write_u16le(0x0102)
      local result = w.result()
      assert.equal(2, #result)
      assert.equal(0x02, result:byte(1))
      assert.equal(0x01, result:byte(2))
    end)

    it("writes u32le", function()
      local w = serialize.buffer_writer()
      w.write_u32le(0x01020304)
      local result = w.result()
      assert.equal(4, #result)
      assert.equal(0x04, result:byte(1))
      assert.equal(0x03, result:byte(2))
      assert.equal(0x02, result:byte(3))
      assert.equal(0x01, result:byte(4))
    end)

    it("writes i32le with negative values", function()
      local w = serialize.buffer_writer()
      w.write_i32le(-1)
      local result = w.result()
      assert.equal(4, #result)
      assert.equal(0xFF, result:byte(1))
      assert.equal(0xFF, result:byte(2))
      assert.equal(0xFF, result:byte(3))
      assert.equal(0xFF, result:byte(4))
    end)

    it("writes u64le", function()
      local w = serialize.buffer_writer()
      w.write_u64le(0x0102030405060708)
      local result = w.result()
      assert.equal(8, #result)
      assert.equal(0x08, result:byte(1))
      assert.equal(0x07, result:byte(2))
      assert.equal(0x06, result:byte(3))
      assert.equal(0x05, result:byte(4))
      assert.equal(0x04, result:byte(5))
      assert.equal(0x03, result:byte(6))
      assert.equal(0x02, result:byte(7))
      assert.equal(0x01, result:byte(8))
    end)

    it("tracks length correctly", function()
      local w = serialize.buffer_writer()
      assert.equal(0, w.length())
      w.write_u8(1)
      assert.equal(1, w.length())
      w.write_u32le(0)
      assert.equal(5, w.length())
      w.write_bytes("hello")
      assert.equal(10, w.length())
    end)
  end)

  describe("buffer_reader", function()
    it("reads u8", function()
      local r = serialize.buffer_reader(string.char(0, 255, 128))
      assert.equal(0, r.read_u8())
      assert.equal(255, r.read_u8())
      assert.equal(128, r.read_u8())
      assert.is_true(r.is_eof())
    end)

    it("reads u16le", function()
      local r = serialize.buffer_reader(string.char(0x02, 0x01))
      assert.equal(0x0102, r.read_u16le())
    end)

    it("reads u32le", function()
      local r = serialize.buffer_reader(string.char(0x04, 0x03, 0x02, 0x01))
      assert.equal(0x01020304, r.read_u32le())
    end)

    it("reads i32le with negative values", function()
      local r = serialize.buffer_reader(string.char(0xFF, 0xFF, 0xFF, 0xFF))
      assert.equal(-1, r.read_i32le())
    end)

    it("reads u64le", function()
      local r = serialize.buffer_reader(string.char(0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01))
      assert.equal(0x0102030405060708, r.read_u64le())
    end)

    it("reads bytes", function()
      local r = serialize.buffer_reader("hello world")
      assert.equal("hello", r.read_bytes(5))
      assert.equal(" ", r.read_bytes(1))
      assert.equal("world", r.read_bytes(5))
    end)

    it("tracks position and remaining", function()
      local r = serialize.buffer_reader("12345")
      assert.equal(1, r.position())
      assert.equal(5, r.remaining())
      r.read_bytes(2)
      assert.equal(3, r.position())
      assert.equal(3, r.remaining())
    end)

    it("throws on unexpected end of data", function()
      local r = serialize.buffer_reader("ab")
      assert.has_error(function()
        r.read_u32le()
      end)
    end)
  end)

  describe("integer round-trip", function()
    local function test_roundtrip_u8(val)
      local w = serialize.buffer_writer()
      w.write_u8(val)
      local r = serialize.buffer_reader(w.result())
      assert.equal(val, r.read_u8())
    end

    local function test_roundtrip_u16le(val)
      local w = serialize.buffer_writer()
      w.write_u16le(val)
      local r = serialize.buffer_reader(w.result())
      assert.equal(val, r.read_u16le())
    end

    local function test_roundtrip_u32le(val)
      local w = serialize.buffer_writer()
      w.write_u32le(val)
      local r = serialize.buffer_reader(w.result())
      assert.equal(val, r.read_u32le())
    end

    local function test_roundtrip_i32le(val)
      local w = serialize.buffer_writer()
      w.write_i32le(val)
      local r = serialize.buffer_reader(w.result())
      assert.equal(val, r.read_i32le())
    end

    local function test_roundtrip_u64le(val)
      local w = serialize.buffer_writer()
      w.write_u64le(val)
      local r = serialize.buffer_reader(w.result())
      assert.equal(val, r.read_u64le())
    end

    local function test_roundtrip_i64le(val)
      local w = serialize.buffer_writer()
      w.write_i64le(val)
      local r = serialize.buffer_reader(w.result())
      assert.equal(val, r.read_i64le())
    end

    it("round-trips u8 values", function()
      test_roundtrip_u8(0)
      test_roundtrip_u8(1)
      test_roundtrip_u8(127)
      test_roundtrip_u8(128)
      test_roundtrip_u8(255)
    end)

    it("round-trips u16le values", function()
      test_roundtrip_u16le(0)
      test_roundtrip_u16le(1)
      test_roundtrip_u16le(0x00FF)
      test_roundtrip_u16le(0xFF00)
      test_roundtrip_u16le(0xFFFF)
    end)

    it("round-trips u32le values", function()
      test_roundtrip_u32le(0)
      test_roundtrip_u32le(1)
      test_roundtrip_u32le(0x12345678)
      test_roundtrip_u32le(0xFFFFFFFF)
    end)

    it("round-trips i32le values", function()
      test_roundtrip_i32le(0)
      test_roundtrip_i32le(1)
      test_roundtrip_i32le(-1)
      test_roundtrip_i32le(2147483647)
      test_roundtrip_i32le(-2147483648)
    end)

    it("round-trips u64le values", function()
      test_roundtrip_u64le(0)
      test_roundtrip_u64le(1)
      test_roundtrip_u64le(0xFFFFFFFF)
      test_roundtrip_u64le(0x100000000)
      -- 2^53 - 1 is max safe integer for double precision
      test_roundtrip_u64le(9007199254740991)
    end)

    it("round-trips i64le values", function()
      test_roundtrip_i64le(0)
      test_roundtrip_i64le(1)
      test_roundtrip_i64le(-1)
      test_roundtrip_i64le(2100000000000000) -- max satoshis
    end)
  end)

  describe("varint", function()
    local function test_varint(val, expected_len)
      local w = serialize.buffer_writer()
      w.write_varint(val)
      local result = w.result()
      if expected_len then
        assert.equal(expected_len, #result, "expected length for " .. val)
      end
      local r = serialize.buffer_reader(result)
      assert.equal(val, r.read_varint(), "round-trip for " .. val)
    end

    it("encodes single byte varints (0-0xFC)", function()
      test_varint(0, 1)
      test_varint(1, 1)
      test_varint(0xFC, 1)
    end)

    it("encodes 0xFD with 3 bytes", function()
      test_varint(0xFD, 3)
    end)

    it("encodes 0xFE with 3 bytes", function()
      test_varint(0xFE, 3)
    end)

    it("encodes 0xFFFF with 3 bytes", function()
      test_varint(0xFFFF, 3)
    end)

    it("encodes 0x10000 with 5 bytes", function()
      test_varint(0x10000, 5)
    end)

    it("encodes 0xFFFFFFFE with 5 bytes", function()
      test_varint(0xFFFFFFFE, 5)
    end)

    it("encodes 0xFFFFFFFF with 5 bytes", function()
      test_varint(0xFFFFFFFF, 5)
    end)

    it("encodes 0x100000000 with 9 bytes", function()
      test_varint(0x100000000, 9)
    end)
  end)

  describe("varstr", function()
    it("round-trips empty string", function()
      local w = serialize.buffer_writer()
      w.write_varstr("")
      local r = serialize.buffer_reader(w.result())
      assert.equal("", r.read_varstr())
    end)

    it("round-trips short string", function()
      local w = serialize.buffer_writer()
      w.write_varstr("hello")
      local result = w.result()
      assert.equal(6, #result) -- 1 byte length + 5 bytes data
      local r = serialize.buffer_reader(result)
      assert.equal("hello", r.read_varstr())
    end)

    it("round-trips long string", function()
      local long_str = string.rep("x", 300)
      local w = serialize.buffer_writer()
      w.write_varstr(long_str)
      local result = w.result()
      assert.equal(303, #result) -- 3 bytes length (0xFD prefix + 2 bytes) + 300 bytes data
      local r = serialize.buffer_reader(result)
      assert.equal(long_str, r.read_varstr())
    end)
  end)

  describe("hash256", function()
    it("writes and reads hash256", function()
      local h = types.hash256(string.rep("\xab", 32))
      local w = serialize.buffer_writer()
      w.write_hash256(h)
      local result = w.result()
      assert.equal(32, #result)

      local r = serialize.buffer_reader(result)
      local h2 = r.read_hash256()
      assert.is_true(types.hash256_eq(h, h2))
    end)
  end)

  describe("block header serialization", function()
    it("serializes to 80 bytes", function()
      local prev = types.hash256(string.rep("\x01", 32))
      local merkle = types.hash256(string.rep("\x02", 32))
      local hdr = types.block_header(1, prev, merkle, 1231006505, 0x1d00ffff, 2083236893)
      local data = serialize.serialize_block_header(hdr)
      assert.equal(80, #data)
    end)

    it("round-trips block header", function()
      local prev = types.hash256(string.rep("\x01", 32))
      local merkle = types.hash256(string.rep("\x02", 32))
      local hdr = types.block_header(1, prev, merkle, 1231006505, 0x1d00ffff, 2083236893)

      local data = serialize.serialize_block_header(hdr)
      local hdr2 = serialize.deserialize_block_header(data)

      assert.equal(hdr.version, hdr2.version)
      assert.is_true(types.hash256_eq(hdr.prev_hash, hdr2.prev_hash))
      assert.is_true(types.hash256_eq(hdr.merkle_root, hdr2.merkle_root))
      assert.equal(hdr.timestamp, hdr2.timestamp)
      assert.equal(hdr.bits, hdr2.bits)
      assert.equal(hdr.nonce, hdr2.nonce)
    end)

    it("deserializes the Bitcoin genesis block header", function()
      -- Genesis block header in hex (80 bytes)
      local genesis_hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
      local genesis_bytes = {}
      for i = 1, #genesis_hex, 2 do
        genesis_bytes[#genesis_bytes + 1] = string.char(tonumber(genesis_hex:sub(i, i + 1), 16))
      end
      local data = table.concat(genesis_bytes)
      assert.equal(80, #data)

      local hdr = serialize.deserialize_block_header(data)
      assert.equal(1, hdr.version)
      assert.equal(1231006505, hdr.timestamp)
      assert.equal(0x1d00ffff, hdr.bits)
      assert.equal(2083236893, hdr.nonce)

      -- prev_hash should be all zeros
      assert.is_true(types.hash256_eq(hdr.prev_hash, types.hash256_zero()))

      -- merkle_root as displayed (big-endian): 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
      local merkle_hex = types.hash256_hex(hdr.merkle_root)
      assert.equal("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b", merkle_hex)
    end)

    it("round-trips the genesis block header bytes", function()
      local genesis_hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
      local genesis_bytes = {}
      for i = 1, #genesis_hex, 2 do
        genesis_bytes[#genesis_bytes + 1] = string.char(tonumber(genesis_hex:sub(i, i + 1), 16))
      end
      local original = table.concat(genesis_bytes)

      local hdr = serialize.deserialize_block_header(original)
      local reserialized = serialize.serialize_block_header(hdr)
      assert.equal(original, reserialized)
    end)
  end)

  describe("transaction serialization", function()
    it("serializes and deserializes a simple legacy transaction", function()
      local prev_hash = types.hash256(string.rep("\xab", 32))
      local inp = types.txin(types.outpoint(prev_hash, 0), "\x00\x14", 0xFFFFFFFF)
      local out = types.txout(5000000000, "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac")
      local tx = types.transaction(1, {inp}, {out}, 0)

      local data = serialize.serialize_transaction(tx, false)
      local tx2 = serialize.deserialize_transaction(data)

      assert.equal(tx.version, tx2.version)
      assert.equal(#tx.inputs, #tx2.inputs)
      assert.equal(#tx.outputs, #tx2.outputs)
      assert.equal(tx.locktime, tx2.locktime)
      assert.is_false(tx2.segwit)

      assert.is_true(types.hash256_eq(tx.inputs[1].prev_out.hash, tx2.inputs[1].prev_out.hash))
      assert.equal(tx.inputs[1].prev_out.index, tx2.inputs[1].prev_out.index)
      assert.equal(tx.inputs[1].script_sig, tx2.inputs[1].script_sig)
      assert.equal(tx.inputs[1].sequence, tx2.inputs[1].sequence)

      assert.equal(tx.outputs[1].value, tx2.outputs[1].value)
      assert.equal(tx.outputs[1].script_pubkey, tx2.outputs[1].script_pubkey)
    end)

    it("serializes and deserializes a segwit transaction", function()
      local prev_hash = types.hash256(string.rep("\xcd", 32))
      local inp = types.txin(types.outpoint(prev_hash, 1), "", 0xFFFFFFFE)
      inp.witness = { string.rep("\x30", 71), string.rep("\x02", 33) }
      local out1 = types.txout(100000, "\x00\x14" .. string.rep("\x11", 20))
      local out2 = types.txout(200000, "\x00\x14" .. string.rep("\x22", 20))
      local tx = types.transaction(2, {inp}, {out1, out2}, 500000)
      tx.segwit = true

      local data = serialize.serialize_transaction(tx, true)
      local tx2 = serialize.deserialize_transaction(data)

      assert.equal(tx.version, tx2.version)
      assert.is_true(tx2.segwit)
      assert.equal(#tx.inputs, #tx2.inputs)
      assert.equal(#tx.outputs, #tx2.outputs)
      assert.equal(tx.locktime, tx2.locktime)

      assert.equal(2, #tx2.inputs[1].witness)
      assert.equal(tx.inputs[1].witness[1], tx2.inputs[1].witness[1])
      assert.equal(tx.inputs[1].witness[2], tx2.inputs[1].witness[2])
    end)

    it("handles multiple inputs and outputs", function()
      local inputs = {}
      local outputs = {}
      for i = 1, 5 do
        local h = types.hash256(string.rep(string.char(i), 32))
        inputs[i] = types.txin(types.outpoint(h, i - 1), string.rep("x", i * 10), 0xFFFFFFFF - i)
      end
      for i = 1, 10 do
        outputs[i] = types.txout(i * 1000000, string.rep("y", 25))
      end

      local tx = types.transaction(1, inputs, outputs, 12345)
      local data = serialize.serialize_transaction(tx, false)
      local tx2 = serialize.deserialize_transaction(data)

      assert.equal(5, #tx2.inputs)
      assert.equal(10, #tx2.outputs)
      for i = 1, 5 do
        assert.is_true(types.hash256_eq(inputs[i].prev_out.hash, tx2.inputs[i].prev_out.hash))
        assert.equal(inputs[i].prev_out.index, tx2.inputs[i].prev_out.index)
      end
      for i = 1, 10 do
        assert.equal(outputs[i].value, tx2.outputs[i].value)
      end
    end)

    it("handles coinbase transaction (null prevout)", function()
      local null_hash = types.hash256_zero()
      local inp = types.txin(types.outpoint(null_hash, 0xFFFFFFFF), "\x04\xff\xff\x00\x1d\x01\x04", 0xFFFFFFFF)
      local out = types.txout(5000000000, "\x41" .. string.rep("\x04", 65) .. "\xac")
      local tx = types.transaction(1, {inp}, {out}, 0)

      local data = serialize.serialize_transaction(tx, false)
      local tx2 = serialize.deserialize_transaction(data)

      assert.is_true(types.hash256_eq(types.hash256_zero(), tx2.inputs[1].prev_out.hash))
      assert.equal(0xFFFFFFFF, tx2.inputs[1].prev_out.index)
    end)
  end)

  describe("block serialization", function()
    it("serializes and deserializes a block with one transaction", function()
      local prev = types.hash256_zero()
      local merkle = types.hash256(string.rep("\x4a", 32))
      local hdr = types.block_header(1, prev, merkle, 1231006505, 0x1d00ffff, 2083236893)

      local null_hash = types.hash256_zero()
      local inp = types.txin(types.outpoint(null_hash, 0xFFFFFFFF), "\x04coinbase", 0xFFFFFFFF)
      local out = types.txout(5000000000, "\x41" .. string.rep("\x04", 65) .. "\xac")
      local coinbase = types.transaction(1, {inp}, {out}, 0)

      local blk = types.block(hdr, {coinbase})
      local data = serialize.serialize_block(blk)
      local blk2 = serialize.deserialize_block(data)

      assert.equal(hdr.version, blk2.header.version)
      assert.equal(hdr.timestamp, blk2.header.timestamp)
      assert.equal(1, #blk2.transactions)
      assert.equal(coinbase.version, blk2.transactions[1].version)
    end)

    it("serializes and deserializes a block with multiple transactions", function()
      local prev = types.hash256(string.rep("\x01", 32))
      local merkle = types.hash256(string.rep("\x02", 32))
      local hdr = types.block_header(2, prev, merkle, 1600000000, 0x1a00ffff, 12345)

      local txs = {}
      for i = 1, 3 do
        local h = types.hash256(string.rep(string.char(i), 32))
        local inp = types.txin(types.outpoint(h, 0), "sig", 0xFFFFFFFF)
        local out = types.txout(i * 1000000, "script")
        txs[i] = types.transaction(1, {inp}, {out}, 0)
      end

      local blk = types.block(hdr, txs)
      local data = serialize.serialize_block(blk)
      local blk2 = serialize.deserialize_block(data)

      assert.equal(3, #blk2.transactions)
      for i = 1, 3 do
        assert.equal(txs[i].outputs[1].value, blk2.transactions[i].outputs[1].value)
      end
    end)
  end)
end)
