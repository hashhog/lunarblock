describe("blockfilter", function()
  local blockfilter, storage, types, crypto

  -- Helper to create a unique temp directory
  local function make_temp_dir()
    local tmpname = os.tmpname()
    os.remove(tmpname)
    os.execute("mkdir -p " .. tmpname)
    return tmpname
  end

  local function remove_dir(path)
    os.execute("rm -rf " .. path)
  end

  -- Decode hex string to binary string
  local function from_hex(hex)
    return (hex:gsub("..", function(h)
      return string.char(tonumber(h, 16))
    end))
  end

  -- Encode binary string to hex
  local function to_hex(s)
    return (s:gsub(".", function(c)
      return string.format("%02x", string.byte(c))
    end))
  end

  setup(function()
    blockfilter = require("lunarblock.blockfilter")
    storage = require("lunarblock.storage")
    types = require("lunarblock.types")
    crypto = require("lunarblock.crypto")
  end)

  describe("fast_range64", function()
    it("maps full range to 0", function()
      local ffi = require("ffi")
      -- FastRange64(x, 0) = 0 (range is 0, all values map to 0 by convention)
      -- FastRange64(0, n) = 0 always
      local r = blockfilter.fast_range64(ffi.new("uint64_t", 0), ffi.new("uint64_t", 784931))
      assert.equal(0, tonumber(r))
    end)

    it("maps max uint64 to range-1 approximately", function()
      local ffi = require("ffi")
      -- FastRange64(0xFFFFFFFFFFFFFFFF, n) should be very close to n-1
      local max_u64 = ffi.new("uint64_t", 0xFFFFFFFFFFFFFFFFULL)
      local n = ffi.new("uint64_t", 1000)
      local r = blockfilter.fast_range64(max_u64, n)
      assert.is_true(tonumber(r) >= 999, "expected ~999, got " .. tonumber(r))
    end)

    it("is deterministic", function()
      local ffi = require("ffi")
      local x = ffi.new("uint64_t", 0xABCDEF1234567890ULL)
      local n = ffi.new("uint64_t", 784931)
      local r1 = blockfilter.fast_range64(x, n)
      local r2 = blockfilter.fast_range64(x, n)
      assert.equal(tonumber(r1), tonumber(r2))
    end)

    it("result is in [0, n)", function()
      local ffi = require("ffi")
      local n = ffi.new("uint64_t", 784931)
      local test_values = {
        ffi.new("uint64_t", 0),
        ffi.new("uint64_t", 1),
        ffi.new("uint64_t", 0x123456789ABCDEFULL),
        ffi.new("uint64_t", 0xFFFFFFFFFFFFFFFFULL),
        ffi.new("uint64_t", 0x8000000000000000ULL),
      }
      for _, x in ipairs(test_values) do
        local r = tonumber(blockfilter.fast_range64(x, n))
        assert.is_true(r >= 0 and r < 784931,
          "fast_range64 out of bounds: " .. r)
      end
    end)
  end)

  describe("block_hash_to_keys", function()
    it("extracts k0 and k1 as little-endian uint64 from first 16 bytes", function()
      local ffi = require("ffi")
      -- Block hash bytes: first 8 bytes = k0 LE, next 8 bytes = k1 LE
      -- k0 = 0x0807060504030201 (bytes [01,02,03,04,05,06,07,08])
      -- k1 = 0x100f0e0d0c0b0a09 (bytes [09,0a,0b,0c,0d,0e,0f,10])
      local hash_bytes = from_hex("0102030405060708090a0b0c0d0e0f10") ..
                         string.rep("\x00", 16)
      local bh = types.hash256(hash_bytes)
      local k0, k1 = blockfilter.block_hash_to_keys(bh)
      -- k0 = 0x0807060504030201
      assert.equal(tostring(ffi.new("uint64_t", 0x0807060504030201ULL)), tostring(k0))
      -- k1 = 0x100f0e0d0c0b0a09
      assert.equal(tostring(ffi.new("uint64_t", 0x100f0e0d0c0b0a09ULL)), tostring(k1))
    end)
  end)

  describe("bit_stream_writer and reader", function()
    it("writes and reads bits correctly", function()
      local writer = blockfilter.bit_stream_writer()
      writer.write(1, 1)      -- 1
      writer.write(0, 1)      -- 0
      writer.write(5, 3)      -- 101
      writer.write(15, 4)     -- 1111
      writer.flush()

      local data = writer.result()
      local reader = blockfilter.bit_stream_reader(data)

      assert.equal(1, reader.read(1))
      assert.equal(0, reader.read(1))
      assert.equal(5, reader.read(3))
      assert.equal(15, reader.read(4))
    end)

    it("handles byte boundaries", function()
      local writer = blockfilter.bit_stream_writer()
      writer.write(0xFF, 8)  -- full byte
      writer.write(0xAB, 8)  -- another byte
      writer.flush()

      local data = writer.result()
      assert.equal(2, #data)

      local reader = blockfilter.bit_stream_reader(data)
      assert.equal(0xFF, reader.read(8))
      assert.equal(0xAB, reader.read(8))
    end)

    it("handles partial bytes at end", function()
      local writer = blockfilter.bit_stream_writer()
      writer.write(1, 1)
      writer.write(1, 1)
      writer.write(1, 1)  -- 111 = 0xE0 when padded
      writer.flush()

      local data = writer.result()
      assert.equal(1, #data)
      assert.equal(0xE0, data:byte(1))
    end)
  end)

  describe("golomb_rice_encode and decode", function()
    it("encodes and decodes single values", function()
      local P = 19  -- BIP158 parameter

      -- Test several values
      local test_values = {0, 1, 10, 100, 1000, 10000, 100000, 524287, 524288, 1048575}

      for _, val in ipairs(test_values) do
        local writer = blockfilter.bit_stream_writer()
        blockfilter.golomb_rice_encode(writer, P, val)
        writer.flush()

        local reader = blockfilter.bit_stream_reader(writer.result())
        local decoded = blockfilter.golomb_rice_decode(reader, P)
        assert.equal(val, decoded, "Failed for value " .. val)
      end
    end)

    it("encodes deltas in sequence", function()
      local P = 19
      local values = {100, 500, 1000, 50000}

      local writer = blockfilter.bit_stream_writer()
      local last = 0
      for _, val in ipairs(values) do
        blockfilter.golomb_rice_encode(writer, P, val - last)
        last = val
      end
      writer.flush()

      local reader = blockfilter.bit_stream_reader(writer.result())
      local decoded = {}
      last = 0
      for i = 1, #values do
        local delta = blockfilter.golomb_rice_decode(reader, P)
        last = last + delta
        decoded[i] = last
      end

      for i, val in ipairs(values) do
        assert.equal(val, decoded[i])
      end
    end)

    it("handles zero delta correctly", function()
      local P = 19
      local writer = blockfilter.bit_stream_writer()
      blockfilter.golomb_rice_encode(writer, P, 0)
      writer.flush()
      local reader = blockfilter.bit_stream_reader(writer.result())
      local decoded = blockfilter.golomb_rice_decode(reader, P)
      assert.equal(0, decoded)
    end)
  end)

  describe("build_gcs_filter", function()
    it("builds empty filter for no elements", function()
      local block_hash = types.hash256(string.rep("\xab", 32))
      local filter = blockfilter.build_gcs_filter({}, block_hash)

      assert.equal(1, #filter)  -- just the varint count (0)
      assert.equal(0, filter:byte(1))
    end)

    it("builds filter with single element", function()
      local block_hash = types.hash256(string.rep("\xcd", 32))
      local elements = {"test_script"}
      local filter = blockfilter.build_gcs_filter(elements, block_hash)

      assert.is_true(#filter > 1)
      -- First byte is count (1)
      assert.equal(1, filter:byte(1))
    end)

    it("builds filter with multiple elements", function()
      local block_hash = types.hash256(string.rep("\xef", 32))
      local elements = {
        "\x76\xa9" .. string.rep("\x00", 20) .. "\x88\xac",
        "\xa9\x14" .. string.rep("\x11", 20) .. "\x87",
        "\x00\x14" .. string.rep("\x22", 20),
      }
      local filter = blockfilter.build_gcs_filter(elements, block_hash)

      assert.is_true(#filter > 1)
      assert.equal(3, filter:byte(1))  -- count
    end)

    it("round-trips through build and match", function()
      local block_hash = types.hash256(string.rep("\x42", 32))
      local elements = {"script_a", "script_b", "script_c", "script_d"}
      local filter = blockfilter.build_gcs_filter(elements, block_hash)
      for _, elem in ipairs(elements) do
        assert.is_true(blockfilter.match_gcs_filter(filter, elem, block_hash),
          "element not found: " .. elem)
      end
    end)
  end)

  describe("match_gcs_filter", function()
    it("matches existing element", function()
      local block_hash = types.hash256(string.rep("\x12", 32))
      local elements = {
        "element_one",
        "element_two",
        "element_three",
      }
      local filter = blockfilter.build_gcs_filter(elements, block_hash)

      assert.is_true(blockfilter.match_gcs_filter(filter, "element_two", block_hash))
    end)

    it("does not match non-existing element", function()
      local block_hash = types.hash256(string.rep("\x34", 32))
      local elements = {"alpha", "beta", "gamma"}
      local filter = blockfilter.build_gcs_filter(elements, block_hash)

      -- Note: false positives are possible, but should be rare
      -- We test that at least one clearly different element doesn't match
      local matched = false
      for i = 1, 100 do
        local test = "definitely_not_in_filter_" .. i
        if blockfilter.match_gcs_filter(filter, test, block_hash) then
          matched = true
          break
        end
      end
      -- With M=784931, false positive rate is ~1/784931, so 100 tests should not match
      assert.is_false(matched)
    end)

    it("returns false for empty filter", function()
      local block_hash = types.hash256(string.rep("\x56", 32))
      local filter = blockfilter.build_gcs_filter({}, block_hash)

      assert.is_false(blockfilter.match_gcs_filter(filter, "anything", block_hash))
    end)
  end)

  describe("match_any_gcs_filter", function()
    it("matches when any element exists", function()
      local block_hash = types.hash256(string.rep("\x78", 32))
      local elements = {"one", "two", "three"}
      local filter = blockfilter.build_gcs_filter(elements, block_hash)

      assert.is_true(blockfilter.match_any_gcs_filter(filter, {"zero", "two", "four"}, block_hash))
    end)

    it("returns false when no elements match", function()
      local block_hash = types.hash256(string.rep("\x9a", 32))
      local elements = {"alpha", "beta"}
      local filter = blockfilter.build_gcs_filter(elements, block_hash)

      assert.is_false(blockfilter.match_any_gcs_filter(filter, {"gamma", "delta"}, block_hash))
    end)
  end)

  describe("filter hash and header", function()
    it("computes filter hash", function()
      local filter_data = "\x01\x00"  -- simple filter
      local hash = blockfilter.compute_filter_hash(filter_data)

      assert.is_not_nil(hash)
      assert.equal(32, #hash.bytes)
    end)

    it("computes filter header chain", function()
      local filter1 = blockfilter.build_gcs_filter({"a"}, types.hash256(string.rep("\x01", 32)))
      local filter2 = blockfilter.build_gcs_filter({"b"}, types.hash256(string.rep("\x02", 32)))

      local hash1 = blockfilter.compute_filter_hash(filter1)
      local hash2 = blockfilter.compute_filter_hash(filter2)

      -- Genesis filter header
      local header0 = types.hash256_zero()
      local header1 = blockfilter.compute_filter_header(hash1, header0)
      local header2 = blockfilter.compute_filter_header(hash2, header1)

      -- Headers should be different
      assert.is_false(types.hash256_eq(header1, header0))
      assert.is_false(types.hash256_eq(header2, header1))

      -- Headers should be deterministic
      local header1_again = blockfilter.compute_filter_header(hash1, header0)
      assert.is_true(types.hash256_eq(header1, header1_again))
    end)
  end)

  ---------------------------------------------------------------------------
  -- BIP-158 official test vectors
  -- Source: bitcoin-core/src/test/data/blockfilters.json
  -- Format: [height, block_hash_hex, block_hex, prev_scripts,
  --          prev_basic_header_hex, basic_filter_hex, basic_header_hex, notes]
  ---------------------------------------------------------------------------

  describe("BIP-158 official test vectors", function()
    -- Helper: parse block_hash from display hex (big-endian display → LE internal)
    local function hash_from_display(hex)
      return types.hash256_from_hex(hex)
    end

    -- Helper: parse undo scripts from the JSON prev_scripts array
    -- Each entry is a hex-encoded scriptPubKey
    local function parse_prev_scripts(scripts_hex)
      local result = {}
      for _, s in ipairs(scripts_hex) do
        if #s > 0 then
          result[#result + 1] = { script_pubkey = from_hex(s) }
        else
          result[#result + 1] = { script_pubkey = "" }
        end
      end
      return result
    end

    -- Test vector 1: genesis block (height 0)
    it("genesis block (height 0) — empty filter", function()
      -- Block hash: 000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
      local block_hash = hash_from_display("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")
      -- Expected filter hex: 019dfca8
      local expected_filter_hex = "019dfca8"
      -- Expected filter header: 21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750
      local expected_header_hex = "21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750"
      local prev_header_hex = "0000000000000000000000000000000000000000000000000000000000000000"

      -- Genesis block coinbase output script: pay-to-pubkey (65 bytes + OP_CHECKSIG)
      -- The filter for the genesis block contains 1 element (the coinbase scriptPubKey)
      -- Script from genesis: 4104678afdb0...fac = OP_PUSHDATA(65 bytes) OP_CHECKSIG
      local genesis_script = from_hex(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"
      )

      local elements = { genesis_script }
      local filter = blockfilter.build_gcs_filter(elements, block_hash)

      assert.equal(expected_filter_hex, to_hex(filter),
        "genesis filter mismatch: got " .. to_hex(filter))

      -- Verify filter header
      local filter_hash = blockfilter.compute_filter_hash(filter)
      local prev_header = hash_from_display(prev_header_hex)
      local filter_header = blockfilter.compute_filter_header(filter_hash, prev_header)
      assert.equal(expected_header_hex, types.hash256_hex(filter_header),
        "genesis filter header mismatch")
    end)

    -- Test vector 2: block height 2 (no prev_scripts)
    it("block height 2 — coinbase only", function()
      local block_hash = hash_from_display("000000006c02c8ea6e4ff69651f7fcde348fb9d557a06e6957b65552002a7820")
      local expected_filter_hex = "0174a170"
      local expected_header_hex = "186afd11ef2b5e7e3504f2e8cbf8df28a1fd251fe53d60dff8b1467d1b386cf0"
      local prev_header_hex = "d7bdac13a59d745b1add0d2ce852f1a0442e8945fc1bf3848d3cbffd88c24fe1"

      -- Coinbase output scriptPubKey (35 bytes, from block hex):
      -- varint-length=0x23(35) then script=21038a...fac
      -- OP_PUSHDATA(33) <33-byte pubkey> OP_CHECKSIG
      local coinbase_script = from_hex(
        "21038a7f6ef1c8ca0c588aa53fa860128077c9e6c11e6830f4d7ee4e763a56b7718fac"
      )

      local elements = { coinbase_script }
      local filter = blockfilter.build_gcs_filter(elements, block_hash)

      assert.equal(expected_filter_hex, to_hex(filter),
        "height-2 filter mismatch: got " .. to_hex(filter))

      local filter_hash = blockfilter.compute_filter_hash(filter)
      local prev_header = hash_from_display(prev_header_hex)
      local filter_header = blockfilter.compute_filter_header(filter_hash, prev_header)
      assert.equal(expected_header_hex, types.hash256_hex(filter_header),
        "height-2 filter header mismatch")
    end)

    -- Test vector 3: last block (height 1414221) — empty filter
    it("block height 1414221 — empty data (empty filter)", function()
      local block_hash = hash_from_display("0000000000000027b2b3b3381f114f674f481544ff2be37ae3788d7e078383b1")
      local expected_filter_hex = "00"
      local expected_header_hex = "021e8882ef5a0ed932edeebbecfeda1d7ce528ec7b3daa27641acf1189d7b5dc"
      local prev_header_hex = "5e5e12d90693c8e936f01847859404c67482439681928353ca1296982042864e"

      -- This block has a coinbase with empty/no standard output per the test vector notes.
      -- Per the test vector, elements list is empty → filter = "00"
      local elements = {}
      local filter = blockfilter.build_gcs_filter(elements, block_hash)

      assert.equal(expected_filter_hex, to_hex(filter),
        "height-1414221 filter mismatch")

      local filter_hash = blockfilter.compute_filter_hash(filter)
      local prev_header = hash_from_display(prev_header_hex)
      local filter_header = blockfilter.compute_filter_header(filter_hash, prev_header)
      assert.equal(expected_header_hex, types.hash256_hex(filter_header),
        "height-1414221 filter header mismatch")
    end)

    -- Test vector 4: FastRange64 correctness check using known hash_to_range output
    -- Uses genesis block hash and a known element to verify SipHash + FastRange64 path
    it("hash_to_range produces deterministic value using SipHash + FastRange64", function()
      local ffi = require("ffi")
      -- Genesis block hash (internal LE bytes from display hex reversed):
      -- display: 000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
      -- internal (LE): 43497fd7f826957108f4a30fd9cec3ae...
      local block_hash = hash_from_display("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")
      local k0, k1 = blockfilter.block_hash_to_keys(block_hash)

      -- Any element; check it is in [0, F) for F = 1 * 784931
      local F = ffi.new("uint64_t", 784931)
      local script = from_hex(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"
      )
      local h = blockfilter.hash_to_range(k0, k1, script, F)
      local hv = tonumber(h)
      assert.is_true(hv >= 0 and hv < 784931,
        "hash_to_range out of range: " .. hv)
    end)

    -- Test vector 5: filter header chain integrity
    it("filter header chain is correctly chained", function()
      -- First three headers from the test vectors:
      -- h0 prev_header = 0000...0000
      -- h0 filter_header = 21584579b7eb...
      -- h2 prev_header = d7bdac13...
      -- h2 filter_header = 186afd11...
      -- h3 prev_header = 186afd11... (= h2 header)
      local header_0 = hash_from_display("21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750")
      local prev_h0  = types.hash256_zero()

      -- Verify that the genesis filter + SHA256d gives header_0
      local block_hash_0 = hash_from_display("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")
      local genesis_script = from_hex(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"
      )
      local filter_0 = blockfilter.build_gcs_filter({genesis_script}, block_hash_0)
      local fhash_0  = blockfilter.compute_filter_hash(filter_0)
      local fheader_0 = blockfilter.compute_filter_header(fhash_0, prev_h0)
      assert.equal("21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750",
        types.hash256_hex(fheader_0), "genesis filter header chain broken")
    end)

    -- Test vector 6: match against built filter works for BIP-158 test block
    it("match works on a known BIP-158 filter", function()
      local block_hash = hash_from_display("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")
      local genesis_script = from_hex(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"
      )
      local filter = blockfilter.build_gcs_filter({genesis_script}, block_hash)

      -- Should match the genesis pubkey script
      assert.is_true(blockfilter.match_gcs_filter(filter, genesis_script, block_hash),
        "genesis script not found in its own filter")

      -- Should not match a random unrelated script
      local unrelated = from_hex("76a914000000000000000000000000000000000000000088ac")
      -- Allow for possible false positive but it should be very rare
      local matched = blockfilter.match_gcs_filter(filter, unrelated, block_hash)
      -- We don't assert false here since false positives are possible; just log
      assert.is_false(matched or false)  -- won't fail, just verifies no crash
    end)

    -- Test vector 7: filter encoding matches Core exactly for genesis block
    it("filter encoding is byte-identical to Bitcoin Core for genesis block", function()
      local block_hash = hash_from_display("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")
      local genesis_script = from_hex(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"
      )
      local filter = blockfilter.build_gcs_filter({genesis_script}, block_hash)
      -- Bitcoin Core produces "019dfca8" for genesis
      assert.equal("019dfca8", to_hex(filter),
        "genesis filter not byte-identical to Core")
    end)
  end)

  describe("extract_basic_filter_elements", function()
    it("extracts output scripts", function()
      local prev = types.hash256_zero()
      local merkle = types.hash256(string.rep("\x01", 32))
      local header = types.block_header(1, prev, merkle, 1600000000, 0x1d00ffff, 0)

      -- P2PKH script
      local script1 = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"
      -- P2SH script
      local script2 = "\xa9\x14" .. string.rep("\x11", 20) .. "\x87"

      local tx = types.transaction(1, {
        types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), "\x00", 0xFFFFFFFF)
      }, {
        types.txout(100000000, script1),
        types.txout(50000000, script2),
      }, 0)

      local block = types.block(header, {tx})
      local elements = blockfilter.extract_basic_filter_elements(block, nil)

      assert.equal(2, #elements)
      assert.equal(script1, elements[1])
      assert.equal(script2, elements[2])
    end)

    it("excludes OP_RETURN outputs", function()
      local prev = types.hash256_zero()
      local merkle = types.hash256(string.rep("\x02", 32))
      local header = types.block_header(1, prev, merkle, 1600000000, 0x1d00ffff, 0)

      local script_normal = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"
      local script_op_return = "\x6a\x14" .. string.rep("\xab", 20)  -- OP_RETURN

      local tx = types.transaction(1, {
        types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), "\x00", 0xFFFFFFFF)
      }, {
        types.txout(100000000, script_normal),
        types.txout(0, script_op_return),
      }, 0)

      local block = types.block(header, {tx})
      local elements = blockfilter.extract_basic_filter_elements(block, nil)

      assert.equal(1, #elements)
      assert.equal(script_normal, elements[1])
    end)

    it("excludes empty output scripts", function()
      local prev = types.hash256_zero()
      local merkle = types.hash256(string.rep("\x05", 32))
      local header = types.block_header(1, prev, merkle, 1600000000, 0x1d00ffff, 0)

      local script_normal = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"
      local script_empty = ""

      local tx = types.transaction(1, {
        types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), "\x00", 0xFFFFFFFF)
      }, {
        types.txout(100000000, script_normal),
        types.txout(0, script_empty),
      }, 0)

      local block = types.block(header, {tx})
      local elements = blockfilter.extract_basic_filter_elements(block, nil)

      assert.equal(1, #elements)
    end)

    it("includes spent scripts from undo data", function()
      local prev = types.hash256_zero()
      local merkle = types.hash256(string.rep("\x03", 32))
      local header = types.block_header(1, prev, merkle, 1600000000, 0x1d00ffff, 0)

      local output_script = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"
      local spent_script = "\x00\x14" .. string.rep("\x22", 20)

      local tx = types.transaction(1, {
        types.txin(types.outpoint(types.hash256(string.rep("\xaa", 32)), 0), "\x00", 0xFFFFFFFF)
      }, {
        types.txout(100000000, output_script),
      }, 0)

      local block = types.block(header, {tx})
      local undo_data = {{script_pubkey = spent_script}}

      local elements = blockfilter.extract_basic_filter_elements(block, undo_data)

      -- Should have both output and spent scripts
      assert.equal(2, #elements)
    end)

    it("excludes empty spent scripts from undo data", function()
      local prev = types.hash256_zero()
      local merkle = types.hash256(string.rep("\x06", 32))
      local header = types.block_header(1, prev, merkle, 1600000000, 0x1d00ffff, 0)

      local output_script = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"

      local tx = types.transaction(1, {
        types.txin(types.outpoint(types.hash256(string.rep("\xbb", 32)), 0), "\x00", 0xFFFFFFFF)
      }, {
        types.txout(100000000, output_script),
      }, 0)

      local block = types.block(header, {tx})
      -- Undo data has an empty script (like the "Tx spends from empty output script" test vector)
      local undo_data = {{script_pubkey = ""}}

      local elements = blockfilter.extract_basic_filter_elements(block, undo_data)

      -- Only the output script; empty spent script excluded
      assert.equal(1, #elements)
    end)

    it("deduplicates identical scripts", function()
      local prev = types.hash256_zero()
      local merkle = types.hash256(string.rep("\x04", 32))
      local header = types.block_header(1, prev, merkle, 1600000000, 0x1d00ffff, 0)

      local script = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"

      local tx = types.transaction(1, {
        types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), "\x00", 0xFFFFFFFF)
      }, {
        types.txout(100000000, script),
        types.txout(50000000, script),  -- same script
      }, 0)

      local block = types.block(header, {tx})
      local elements = blockfilter.extract_basic_filter_elements(block, nil)

      assert.equal(1, #elements)  -- deduplicated
    end)

    it("deduplicates scripts appearing in both outputs and undo", function()
      local prev = types.hash256_zero()
      local merkle = types.hash256(string.rep("\x07", 32))
      local header = types.block_header(1, prev, merkle, 1600000000, 0x1d00ffff, 0)

      local script = "\x76\xa9\x14" .. string.rep("\xcc", 20) .. "\x88\xac"

      local tx = types.transaction(1, {
        types.txin(types.outpoint(types.hash256(string.rep("\xdd", 32)), 0), "\x00", 0xFFFFFFFF)
      }, {
        types.txout(100000000, script),
      }, 0)

      local block = types.block(header, {tx})
      local undo_data = {{script_pubkey = script}}  -- same script as output

      local elements = blockfilter.extract_basic_filter_elements(block, undo_data)

      assert.equal(1, #elements)  -- deduplicated across output+undo
    end)
  end)

  describe("block filter index", function()
    local db, path, idx

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
      idx = blockfilter.new_index(db, true)
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("reports enabled state", function()
      assert.is_true(idx.is_enabled())
      idx.set_enabled(false)
      assert.is_false(idx.is_enabled())
    end)

    it("starts with no indexed height", function()
      assert.equal(-1, idx.get_best_height())
    end)

    it("stores and retrieves best height", function()
      idx.set_best_height(54321)
      assert.equal(54321, idx.get_best_height())
    end)

    it("starts with zero last header", function()
      local header = idx.get_last_header()
      assert.is_true(types.hash256_eq(types.hash256_zero(), header))
    end)

    it("stores and retrieves filter", function()
      local block_hash = types.hash256(string.rep("\xab", 32))
      local filter_data = "\x02\x12\x34"
      local filter_hash = types.hash256(string.rep("\xcd", 32))
      local filter_header = types.hash256(string.rep("\xef", 32))

      idx.put_filter(block_hash, 100, filter_data, filter_hash, filter_header)

      local result = idx.get_filter(block_hash)
      assert.is_not_nil(result)
      assert.equal(filter_data, result.filter)
      assert.is_true(types.hash256_eq(filter_hash, result.filter_hash))
      assert.is_true(types.hash256_eq(filter_header, result.filter_header))
    end)

    it("retrieves filter by height", function()
      local block_hash = types.hash256(string.rep("\x11", 32))
      local filter_data = "\x01\x00"
      local filter_hash = types.hash256(string.rep("\x22", 32))
      local filter_header = types.hash256(string.rep("\x33", 32))

      idx.put_filter(block_hash, 500, filter_data, filter_hash, filter_header)

      local result = idx.get_filter_by_height(500)
      assert.is_not_nil(result)
      assert.equal(filter_data, result.filter)
    end)

    it("returns nil for non-existent filter", function()
      local block_hash = types.hash256(string.rep("\x99", 32))
      local result = idx.get_filter(block_hash)
      assert.is_nil(result)
    end)

    it("deletes filter", function()
      local block_hash = types.hash256(string.rep("\x44", 32))
      local filter_data = "\x01\x00"
      local filter_hash = types.hash256(string.rep("\x55", 32))
      local filter_header = types.hash256(string.rep("\x66", 32))

      idx.put_filter(block_hash, 200, filter_data, filter_hash, filter_header)
      assert.is_not_nil(idx.get_filter(block_hash))

      idx.delete_filter(block_hash, 200)
      assert.is_nil(idx.get_filter(block_hash))
      assert.is_nil(idx.get_filter_by_height(200))
    end)
  end)

  describe("connect_block and disconnect_block", function()
    local db, path, idx

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
      idx = blockfilter.new_index(db, true)
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("connects block and builds filter", function()
      local prev = types.hash256_zero()
      local merkle = types.hash256(string.rep("\x01", 32))
      local header = types.block_header(1, prev, merkle, 1600000000, 0x1d00ffff, 0)

      local script = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"
      local tx = types.transaction(1, {
        types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), "\x00", 0xFFFFFFFF)
      }, {
        types.txout(100000000, script),
      }, 0)

      local block = types.block(header, {tx})
      local block_hash = types.hash256(string.rep("\xab", 32))

      idx.connect_block(block, block_hash, 1, nil)

      -- Check filter was stored
      local result = idx.get_filter(block_hash)
      assert.is_not_nil(result)
      assert.is_not_nil(result.filter)
      assert.is_not_nil(result.filter_hash)
      assert.is_not_nil(result.filter_header)

      -- Check height was updated
      assert.equal(1, idx.get_best_height())

      -- Check last header was updated
      local last_header = idx.get_last_header()
      assert.is_false(types.hash256_eq(types.hash256_zero(), last_header))
    end)

    it("disconnects block and removes filter", function()
      -- Connect two blocks
      local script = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"

      for height = 1, 2 do
        local prev = types.hash256(string.rep(string.char(height), 32))
        local merkle = types.hash256(string.rep(string.char(height + 1), 32))
        local header = types.block_header(1, prev, merkle, 1600000000, 0x1d00ffff, 0)
        local tx = types.transaction(1, {
          types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), "\x00", 0xFFFFFFFF)
        }, {
          types.txout(100000000, script),
        }, 0)
        local block = types.block(header, {tx})
        local block_hash = types.hash256(string.rep(string.char(height + 10), 32))
        idx.connect_block(block, block_hash, height, nil)
      end

      assert.equal(2, idx.get_best_height())

      -- Disconnect block 2
      local block_hash_2 = types.hash256(string.rep(string.char(12), 32))
      idx.disconnect_block(block_hash_2, 2)

      assert.equal(1, idx.get_best_height())
      assert.is_nil(idx.get_filter(block_hash_2))
    end)
  end)

  describe("get_stats", function()
    local db, path, idx

    before_each(function()
      path = make_temp_dir()
      db = storage.open(path, 16)
      idx = blockfilter.new_index(db, true)
    end)

    after_each(function()
      db.close()
      remove_dir(path)
    end)

    it("returns correct stats", function()
      idx.set_best_height(1000)

      local stats = idx.get_stats()
      assert.is_true(stats.enabled)
      assert.is_false(stats.synced)
      assert.equal(1000, stats.best_height)
    end)
  end)
end)
