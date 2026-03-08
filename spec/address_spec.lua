-- Helper to convert hex string to binary
local function hex_to_bin(hex)
  return (hex:gsub('..', function(cc)
    return string.char(tonumber(cc, 16))
  end))
end

-- Helper to convert binary to hex string
local function bin_to_hex(bin)
  local hex = {}
  for i = 1, #bin do
    hex[i] = string.format("%02x", bin:byte(i))
  end
  return table.concat(hex)
end

describe("address", function()
  local address
  local crypto

  setup(function()
    package.path = "src/?.lua;" .. package.path
    address = require("lunarblock.address")
    crypto = require("lunarblock.crypto")
  end)

  describe("Base58 encode/decode", function()
    it("round-trips simple byte strings", function()
      local test_cases = {
        "hello",
        "Bitcoin",
        "\x00\x01\x02\x03",
        string.rep("x", 100),
      }
      for _, data in ipairs(test_cases) do
        local encoded = address.base58_encode(data)
        local decoded = address.base58_decode(encoded)
        assert.equals(data, decoded)
      end
    end)

    it("handles leading zero bytes", function()
      local data = "\x00\x00\x00abc"
      local encoded = address.base58_encode(data)
      -- Leading zeros become '1's
      assert.equals("1", encoded:sub(1, 1))
      assert.equals("1", encoded:sub(2, 2))
      assert.equals("1", encoded:sub(3, 3))
      local decoded = address.base58_decode(encoded)
      assert.equals(data, decoded)
    end)

    it("handles all-zero input", function()
      local data = "\x00\x00\x00"
      local encoded = address.base58_encode(data)
      assert.equals("111", encoded)
      local decoded = address.base58_decode(encoded)
      assert.equals(data, decoded)
    end)

    it("handles empty string", function()
      local encoded = address.base58_encode("")
      assert.equals("", encoded)
      local decoded = address.base58_decode("")
      assert.equals("", decoded)
    end)

    it("encodes known test vector", function()
      -- "Hello World" -> 2NEpo7TZRRrLZSi2U
      local data = "Hello World"
      local encoded = address.base58_encode(data)
      assert.equals("JxF12TrwUP45BMd", encoded)
    end)
  end)

  describe("Base58Check encode/decode", function()
    it("round-trips with version byte", function()
      local payload = hex_to_bin("751e76e8199196d454941c45d1b3a323f1433bd6")
      local encoded = address.base58check_encode(0x00, payload)
      local version, decoded_payload = address.base58check_decode(encoded)
      assert.equals(0x00, version)
      assert.equals(payload, decoded_payload)
    end)

    it("rejects corrupted checksum", function()
      local payload = hex_to_bin("751e76e8199196d454941c45d1b3a323f1433bd6")
      local encoded = address.base58check_encode(0x00, payload)
      -- Corrupt the last character
      local corrupted = encoded:sub(1, -2) .. (encoded:sub(-1) == "a" and "b" or "a")
      local version, err = address.base58check_decode(corrupted)
      assert.is_nil(version)
      assert.equals("Base58Check checksum mismatch", err)
    end)

    it("rejects too-short data", function()
      local version, err = address.base58check_decode("111")
      assert.is_nil(version)
      assert.equals("Base58Check data too short", err)
    end)
  end)

  describe("Known mainnet P2PKH address decoding", function()
    it("decodes Satoshi's genesis address", function()
      -- 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa - Satoshi's address
      local addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
      local version, payload = address.base58check_decode(addr)
      assert.equals(0x00, version)
      assert.equals(20, #payload)
      -- The pubkey hash for this address
      assert.equals("62e907b15cbf27d5425399ebf6f0fb50ebb88f18", bin_to_hex(payload))
    end)

    it("decodes another known P2PKH address", function()
      -- Address derived from compressed pubkey with privkey=1
      -- Compressed pubkey: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
      -- Hash160: 751e76e8199196d454941c45d1b3a323f1433bd6
      local addr = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
      local version, payload = address.base58check_decode(addr)
      assert.equals(0x00, version)
      assert.equals("751e76e8199196d454941c45d1b3a323f1433bd6", bin_to_hex(payload))
    end)
  end)

  describe("Bech32 address decoding (v0)", function()
    it("decodes known Bech32 P2WPKH address", function()
      -- bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
      -- This is the P2WPKH address for the hash160 of compressed pubkey with privkey=1
      -- witness program: 751e76e8199196d454941c45d1b3a323f1433bd6
      local addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
      local witness_version, program = address.segwit_decode("bc", addr)
      assert.equals(0, witness_version)
      assert.equals(20, #program)
      assert.equals("751e76e8199196d454941c45d1b3a323f1433bd6", bin_to_hex(program))
    end)

    it("decodes Bech32 P2WSH address", function()
      -- A 32-byte witness program (P2WSH)
      local hrp = "bc"
      local program = hex_to_bin("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")
      local encoded = address.segwit_encode(hrp, 0, program)
      local dec_version, dec_program = address.segwit_decode(hrp, encoded)
      assert.equals(0, dec_version)
      assert.equals(program, dec_program)
    end)
  end)

  describe("Bech32m P2TR address decoding (v1)", function()
    it("decodes known Bech32m P2TR address", function()
      -- BIP350 test vector: bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0
      local addr = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
      local witness_version, program = address.segwit_decode("bc", addr)
      assert.equals(1, witness_version)
      assert.equals(32, #program)
      -- Verify the expected witness program
      assert.equals("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", bin_to_hex(program))
    end)

    it("round-trips Taproot address", function()
      local hrp = "bc"
      local xonly_pubkey = hex_to_bin("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")
      local encoded = address.segwit_encode(hrp, 1, xonly_pubkey)
      -- Should start with bc1p (p = witness v1)
      assert.equals("bc1p", encoded:sub(1, 4))
      local dec_version, dec_program = address.segwit_decode(hrp, encoded)
      assert.equals(1, dec_version)
      assert.equals(xonly_pubkey, dec_program)
    end)
  end)

  describe("SegWit encode/decode round-trip", function()
    it("round-trips witness v0 20-byte program (P2WPKH)", function()
      local hrp = "bc"
      local program = hex_to_bin("751e76e8199196d454941c45d1b3a323f1433bd6")
      local encoded = address.segwit_encode(hrp, 0, program)
      local dec_version, dec_program = address.segwit_decode(hrp, encoded)
      assert.equals(0, dec_version)
      assert.equals(program, dec_program)
    end)

    it("round-trips witness v0 32-byte program (P2WSH)", function()
      local hrp = "bc"
      local program = hex_to_bin("0000000000000000000000000000000000000000000000000000000000000000")
      local encoded = address.segwit_encode(hrp, 0, program)
      local dec_version, dec_program = address.segwit_decode(hrp, encoded)
      assert.equals(0, dec_version)
      assert.equals(program, dec_program)
    end)

    it("round-trips witness v1 32-byte program (P2TR)", function()
      local hrp = "bc"
      local program = hex_to_bin("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
      local encoded = address.segwit_encode(hrp, 1, program)
      local dec_version, dec_program = address.segwit_decode(hrp, encoded)
      assert.equals(1, dec_version)
      assert.equals(program, dec_program)
    end)

    it("works with testnet hrp", function()
      local hrp = "tb"
      local program = hex_to_bin("751e76e8199196d454941c45d1b3a323f1433bd6")
      local encoded = address.segwit_encode(hrp, 0, program)
      assert.equals("tb1", encoded:sub(1, 3))
      local dec_version, dec_program = address.segwit_decode(hrp, encoded)
      assert.equals(0, dec_version)
      assert.equals(program, dec_program)
    end)
  end)

  describe("Bech32 vs Bech32m spec enforcement", function()
    it("witness v0 uses bech32", function()
      local hrp = "bc"
      local program = hex_to_bin("751e76e8199196d454941c45d1b3a323f1433bd6")
      local encoded = address.segwit_encode(hrp, 0, program)
      -- Decode should detect bech32
      local dec_hrp, data, spec = address.bech32_decode(encoded)
      assert.equals("bc", dec_hrp)
      assert.equals("bech32", spec)
    end)

    it("witness v1+ uses bech32m", function()
      local hrp = "bc"
      local program = hex_to_bin("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")
      local encoded = address.segwit_encode(hrp, 1, program)
      -- Decode should detect bech32m
      local dec_hrp, data, spec = address.bech32_decode(encoded)
      assert.equals("bc", dec_hrp)
      assert.equals("bech32m", spec)
    end)
  end)

  describe("Public key to address generation", function()
    -- Test with known private key = 1
    local privkey = hex_to_bin("0000000000000000000000000000000000000000000000000000000000000001")

    it("generates correct P2PKH address from compressed pubkey", function()
      local pubkey = crypto.pubkey_from_privkey(privkey, true)
      local addr = address.pubkey_to_p2pkh(pubkey, "mainnet")
      -- Known address for this pubkey
      assert.equals("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", addr)
    end)

    it("generates correct P2WPKH address from compressed pubkey", function()
      local pubkey = crypto.pubkey_from_privkey(privkey, true)
      local addr = address.pubkey_to_p2wpkh(pubkey, "mainnet")
      -- Known bech32 address for hash160 751e76e8199196d454941c45d1b3a323f1433bd6
      assert.equals("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", addr)
    end)

    it("generates different addresses for testnet", function()
      local pubkey = crypto.pubkey_from_privkey(privkey, true)
      local mainnet_addr = address.pubkey_to_p2pkh(pubkey, "mainnet")
      local testnet_addr = address.pubkey_to_p2pkh(pubkey, "testnet")
      assert.is_not.equals(mainnet_addr, testnet_addr)
      -- Testnet P2PKH starts with m or n
      assert.is_true(testnet_addr:sub(1, 1) == "m" or testnet_addr:sub(1, 1) == "n")
    end)

    it("generates testnet P2WPKH with tb prefix", function()
      local pubkey = crypto.pubkey_from_privkey(privkey, true)
      local addr = address.pubkey_to_p2wpkh(pubkey, "testnet")
      assert.equals("tb1", addr:sub(1, 3))
    end)
  end)

  describe("decode_address", function()
    it("detects P2PKH addresses", function()
      local addr_type, payload = address.decode_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", "mainnet")
      assert.equals("p2pkh", addr_type)
      assert.equals(20, #payload)
    end)

    it("detects P2WPKH addresses", function()
      local addr_type, payload = address.decode_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "mainnet")
      assert.equals("p2wpkh", addr_type)
      assert.equals(20, #payload)
    end)

    it("detects P2TR addresses", function()
      -- Use BIP350 test vector
      local addr_type, payload = address.decode_address("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "mainnet")
      assert.equals("p2tr", addr_type)
      assert.equals(32, #payload)
    end)
  end)

  describe("P2SH and P2WSH addresses", function()
    it("generates P2SH address from script", function()
      -- Simple redeem script: OP_1
      local script = "\x51"
      local addr = address.script_to_p2sh(script, "mainnet")
      -- P2SH addresses start with '3'
      assert.equals("3", addr:sub(1, 1))
      -- Round trip through decode
      local version, payload = address.base58check_decode(addr)
      assert.equals(0x05, version)
      assert.equals(20, #payload)
    end)

    it("generates P2WSH address from script", function()
      local script = "\x51"
      local addr = address.script_to_p2wsh(script, "mainnet")
      -- P2WSH addresses start with bc1q
      assert.equals("bc1q", addr:sub(1, 4))
      local witness_version, program = address.segwit_decode("bc", addr)
      assert.equals(0, witness_version)
      assert.equals(32, #program)  -- SHA256 of script
    end)
  end)

  describe("P2TR (Taproot) address generation", function()
    it("generates P2TR address from x-only pubkey", function()
      local xonly = hex_to_bin("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")
      local addr = address.xonly_pubkey_to_p2tr(xonly, "mainnet")
      -- P2TR addresses start with bc1p
      assert.equals("bc1p", addr:sub(1, 4))
      local witness_version, program = address.segwit_decode("bc", addr)
      assert.equals(1, witness_version)
      assert.equals(xonly, program)
    end)
  end)

  describe("convert_bits", function()
    it("converts 8-bit to 5-bit with padding", function()
      local input = {0xFF}  -- 11111111
      local output = address.convert_bits(input, 8, 5, true)
      -- 11111111 -> 11111 111xx -> 31, 28 (with padding)
      assert.equals(31, output[1])
      assert.equals(28, output[2])
    end)

    it("converts 5-bit to 8-bit without padding", function()
      local input = {31, 28}  -- 11111 11100
      local output = address.convert_bits(input, 5, 8, false)
      -- Should produce 11111111 = 255, with valid zero padding
      assert.equals(255, output[1])
    end)

    it("rejects invalid padding", function()
      -- 5-bit values that produce non-zero padding when converted to 8-bit
      local input = {31, 31}  -- 11111 11111 -> would need non-zero padding
      local output, err = address.convert_bits(input, 5, 8, false)
      assert.is_nil(output)
      assert.is_not_nil(err)
    end)
  end)
end)
