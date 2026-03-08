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

describe("crypto", function()
  local crypto
  local types

  setup(function()
    package.path = "src/?.lua;" .. package.path
    crypto = require("lunarblock.crypto")
    types = require("lunarblock.types")
  end)

  describe("sha256", function()
    it("hashes empty string correctly", function()
      local result = crypto.sha256("")
      local expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      assert.equals(expected, bin_to_hex(result))
    end)

    it("hashes 'hello' correctly", function()
      local result = crypto.sha256("hello")
      local expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
      assert.equals(expected, bin_to_hex(result))
    end)

    it("hashes 'abc' correctly", function()
      local result = crypto.sha256("abc")
      local expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
      assert.equals(expected, bin_to_hex(result))
    end)
  end)

  describe("hash256 (double SHA-256)", function()
    it("double-hashes 'hello' correctly", function()
      local result = crypto.hash256("hello")
      -- SHA256(SHA256("hello"))
      -- First: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
      -- Second: 9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50
      local expected = "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"
      assert.equals(expected, bin_to_hex(result))
    end)

    it("hashes genesis block header correctly", function()
      -- Bitcoin genesis block header (80 bytes)
      local header_hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
      local header = hex_to_bin(header_hex)
      local hash = crypto.hash256(header)
      -- Bitcoin displays hashes in big-endian, but hash256 returns little-endian
      -- The expected hash reversed:
      local expected_le = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000"
      assert.equals(expected_le, bin_to_hex(hash))
    end)
  end)

  describe("ripemd160", function()
    it("hashes empty string correctly", function()
      local result = crypto.ripemd160("")
      local expected = "9c1185a5c5e9fc54612808977ee8f548b2258d31"
      assert.equals(expected, bin_to_hex(result))
    end)

    it("hashes 'hello' correctly", function()
      local result = crypto.ripemd160("hello")
      local expected = "108f07b8382412612c048d07d13f814118445acd"
      assert.equals(expected, bin_to_hex(result))
    end)
  end)

  describe("hash160 (RIPEMD160(SHA256(x)))", function()
    it("computes HASH160 for known public key", function()
      -- Uncompressed public key for private key = 1
      local pubkey_hex = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
      local pubkey = hex_to_bin(pubkey_hex)
      local hash = crypto.hash160(pubkey)
      -- This should match 91b24bf9f5288532960ac687abb035127b1d28a5 (address: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH)
      local expected = "91b24bf9f5288532960ac687abb035127b1d28a5"
      assert.equals(expected, bin_to_hex(hash))
    end)

    it("computes HASH160 for compressed public key", function()
      -- Compressed public key for private key = 1
      local pubkey_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      local pubkey = hex_to_bin(pubkey_hex)
      local hash = crypto.hash160(pubkey)
      -- Expected hash for compressed pubkey
      local expected = "751e76e8199196d454941c45d1b3a323f1433bd6"
      assert.equals(expected, bin_to_hex(hash))
    end)
  end)

  describe("hmac_sha512", function()
    it("computes HMAC-SHA512 for known test vector", function()
      -- Test vector from RFC 4231
      local key = hex_to_bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
      local data = "Hi There"
      local result = crypto.hmac_sha512(key, data)
      local expected = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
      assert.equals(expected, bin_to_hex(result))
    end)
  end)

  describe("ecdsa operations", function()
    -- Known test private key (NOT for production use!)
    local test_privkey = hex_to_bin("0000000000000000000000000000000000000000000000000000000000000001")

    it("derives compressed public key from private key", function()
      local pubkey = crypto.pubkey_from_privkey(test_privkey, true)
      assert.is_not_nil(pubkey)
      assert.equals(33, #pubkey)
      local expected = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      assert.equals(expected, bin_to_hex(pubkey))
    end)

    it("derives uncompressed public key from private key", function()
      local pubkey = crypto.pubkey_from_privkey(test_privkey, false)
      assert.is_not_nil(pubkey)
      assert.equals(65, #pubkey)
      local expected = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
      assert.equals(expected, bin_to_hex(pubkey))
    end)

    it("sign and verify round-trip works", function()
      -- Create a message hash (32 bytes)
      local msg_hash = crypto.sha256("test message")
      assert.equals(32, #msg_hash)

      -- Sign the message
      local sig = crypto.ecdsa_sign(test_privkey, msg_hash)
      assert.is_not_nil(sig)
      assert.is_true(#sig >= 68 and #sig <= 72)  -- DER signatures vary in length

      -- Get the public key
      local pubkey = crypto.pubkey_from_privkey(test_privkey, true)

      -- Verify the signature
      local valid = crypto.ecdsa_verify(pubkey, sig, msg_hash)
      assert.is_true(valid)
    end)

    it("verification fails with wrong message", function()
      local msg_hash1 = crypto.sha256("test message 1")
      local msg_hash2 = crypto.sha256("test message 2")

      local sig = crypto.ecdsa_sign(test_privkey, msg_hash1)
      local pubkey = crypto.pubkey_from_privkey(test_privkey, true)

      -- Verify with wrong message should fail
      local valid = crypto.ecdsa_verify(pubkey, sig, msg_hash2)
      assert.is_false(valid)
    end)

    it("verification fails with wrong public key", function()
      local msg_hash = crypto.sha256("test message")
      local sig = crypto.ecdsa_sign(test_privkey, msg_hash)

      -- Different private key
      local other_privkey = hex_to_bin("0000000000000000000000000000000000000000000000000000000000000002")
      local other_pubkey = crypto.pubkey_from_privkey(other_privkey, true)

      -- Verify with wrong pubkey should fail
      local valid = crypto.ecdsa_verify(other_pubkey, sig, msg_hash)
      assert.is_false(valid)
    end)

    it("returns error for invalid public key", function()
      local msg_hash = crypto.sha256("test message")
      local sig = crypto.ecdsa_sign(test_privkey, msg_hash)

      -- Invalid pubkey (wrong length/format)
      local invalid_pubkey = string.rep("\0", 33)
      local valid, err = crypto.ecdsa_verify(invalid_pubkey, sig, msg_hash)
      assert.is_false(valid)
      assert.equals("invalid public key", err)
    end)
  end)

  describe("merkle root computation", function()
    it("returns zero hash for empty list", function()
      local root = crypto.compute_merkle_root({})
      assert.equals("hash256", root._type)
      assert.equals(string.rep("\0", 32), root.bytes)
    end)

    it("returns single hash unchanged for one transaction", function()
      local tx_hash = types.hash256(crypto.hash256("tx1"))
      local root = crypto.compute_merkle_root({tx_hash})
      assert.equals(tx_hash.bytes, root.bytes)
    end)

    it("computes merkle root for two transactions", function()
      local tx1 = types.hash256(crypto.hash256("tx1"))
      local tx2 = types.hash256(crypto.hash256("tx2"))
      local root = crypto.compute_merkle_root({tx1, tx2})

      -- Manual computation: hash256(tx1 || tx2)
      local expected = crypto.hash256(tx1.bytes .. tx2.bytes)
      assert.equals(expected, root.bytes)
    end)

    it("computes merkle root for three transactions (odd count)", function()
      local tx1 = types.hash256(crypto.hash256("tx1"))
      local tx2 = types.hash256(crypto.hash256("tx2"))
      local tx3 = types.hash256(crypto.hash256("tx3"))
      local root = crypto.compute_merkle_root({tx1, tx2, tx3})

      -- Level 1: hash(tx1||tx2), hash(tx3||tx3) (tx3 duplicated)
      local h12 = crypto.hash256(tx1.bytes .. tx2.bytes)
      local h33 = crypto.hash256(tx3.bytes .. tx3.bytes)
      -- Level 2 (root): hash(h12 || h33)
      local expected = crypto.hash256(h12 .. h33)
      assert.equals(expected, root.bytes)
    end)

    it("computes merkle root for four transactions", function()
      local tx1 = types.hash256(crypto.hash256("tx1"))
      local tx2 = types.hash256(crypto.hash256("tx2"))
      local tx3 = types.hash256(crypto.hash256("tx3"))
      local tx4 = types.hash256(crypto.hash256("tx4"))
      local root = crypto.compute_merkle_root({tx1, tx2, tx3, tx4})

      -- Level 1: hash(tx1||tx2), hash(tx3||tx4)
      local h12 = crypto.hash256(tx1.bytes .. tx2.bytes)
      local h34 = crypto.hash256(tx3.bytes .. tx4.bytes)
      -- Level 2 (root): hash(h12 || h34)
      local expected = crypto.hash256(h12 .. h34)
      assert.equals(expected, root.bytes)
    end)
  end)

  describe("hash256_type", function()
    it("returns a hash256 type object", function()
      local result = crypto.hash256_type("test")
      assert.equals("hash256", result._type)
      assert.equals(32, #result.bytes)
    end)
  end)

  describe("hash160_type", function()
    it("returns a hash160 type object", function()
      local result = crypto.hash160_type("test")
      assert.equals("hash160", result._type)
      assert.equals(20, #result.bytes)
    end)
  end)
end)
