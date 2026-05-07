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

  describe("schnorr (BIP340)", function()
    -- BIP340 test vector 0
    -- https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
    local bip340_test_vector = {
      secret_key = "0000000000000000000000000000000000000000000000000000000000000003",
      public_key = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
      message = "0000000000000000000000000000000000000000000000000000000000000000",
      signature = "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
    }

    it("verifies valid BIP340 signature", function()
      local pubkey = hex_to_bin(bip340_test_vector.public_key)
      local sig = hex_to_bin(bip340_test_vector.signature)
      local msg = hex_to_bin(bip340_test_vector.message)

      local valid = crypto.schnorr_verify(pubkey, sig, msg)
      assert.is_true(valid)
    end)

    it("rejects signature with wrong message", function()
      local pubkey = hex_to_bin(bip340_test_vector.public_key)
      local sig = hex_to_bin(bip340_test_vector.signature)
      local wrong_msg = hex_to_bin("0000000000000000000000000000000000000000000000000000000000000001")

      local valid = crypto.schnorr_verify(pubkey, sig, wrong_msg)
      assert.is_false(valid)
    end)

    it("rejects signature with wrong public key", function()
      -- Different x-only pubkey (from privkey = 2)
      local wrong_pubkey = hex_to_bin("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
      local sig = hex_to_bin(bip340_test_vector.signature)
      local msg = hex_to_bin(bip340_test_vector.message)

      local valid = crypto.schnorr_verify(wrong_pubkey, sig, msg)
      assert.is_false(valid)
    end)

    it("rejects invalid public key", function()
      -- All zeros is not a valid x-only pubkey
      local invalid_pubkey = string.rep("\x00", 32)
      local sig = hex_to_bin(bip340_test_vector.signature)
      local msg = hex_to_bin(bip340_test_vector.message)

      local valid, err = crypto.schnorr_verify(invalid_pubkey, sig, msg)
      assert.is_false(valid)
      assert.equals("invalid x-only public key", err)
    end)

    -- BIP-340 published test vectors exercising schnorr_sign.
    -- Source: bitcoin-core/src/secp256k1/src/modules/schnorrsig/tests_impl.h
    -- (the libsecp256k1 vendored vectors, identical to bip-0340/test-vectors.csv).
    -- All inputs deterministic; sig output is byte-identical given the aux_rand.
    local bip340_signing_vectors = {
      {
        index = 0,
        secret_key = "0000000000000000000000000000000000000000000000000000000000000003",
        public_key = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        aux_rand   = "0000000000000000000000000000000000000000000000000000000000000000",
        message    = "0000000000000000000000000000000000000000000000000000000000000000",
        signature  = "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
      },
      {
        index = 1,
        secret_key = "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef",
        public_key = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        aux_rand   = "0000000000000000000000000000000000000000000000000000000000000001",
        message    = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        signature  = "6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a",
      },
      {
        index = 2,
        secret_key = "c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9",
        public_key = "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
        aux_rand   = "c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906",
        message    = "7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c",
        signature  = "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7",
      },
      {
        index = 3,
        secret_key = "0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710",
        public_key = "25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517",
        aux_rand   = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        message    = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        signature  = "7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3",
      },
    }

    it("schnorr_sign matches BIP-340 vector 0 (sk=3, msg=0, aux=0)", function()
      local v = bip340_signing_vectors[1]
      local sk = hex_to_bin(v.secret_key)
      local msg = hex_to_bin(v.message)
      local aux = hex_to_bin(v.aux_rand)
      local sig, err = crypto.schnorr_sign(sk, msg, aux)
      assert.is_nil(err)
      assert.is_string(sig)
      assert.equals(64, #sig)
      assert.equals(v.signature, bin_to_hex(sig))
    end)

    it("schnorr_sign matches BIP-340 signing vectors 1-3 (non-zero aux + message)", function()
      -- Vectors copied verbatim from bip-0340/test-vectors.csv (rows 1-3),
      -- cross-checked against bitcoin-core/src/secp256k1/src/modules/schnorrsig/tests_impl.h.
      for i = 2, #bip340_signing_vectors do
        local v = bip340_signing_vectors[i]
        local sk = hex_to_bin(v.secret_key)
        local pk = hex_to_bin(v.public_key)
        local msg = hex_to_bin(v.message)
        local aux = hex_to_bin(v.aux_rand)
        local sig = crypto.schnorr_sign(sk, msg, aux)
        assert.equals(v.signature, bin_to_hex(sig),
          "BIP-340 vector " .. tostring(v.index) .. " signature mismatch")
        -- And the produced sig must verify under the published xonly pubkey.
        assert.is_true(crypto.schnorr_verify(pk, sig, msg),
          "BIP-340 vector " .. tostring(v.index) .. " verify failed")
      end
    end)

    it("schnorr_sign result verifies via schnorr_verify (cross-check)", function()
      local v = bip340_signing_vectors[1]
      local sk = hex_to_bin(v.secret_key)
      local pk = hex_to_bin(v.public_key)
      local msg = hex_to_bin(v.message)
      local aux = hex_to_bin(v.aux_rand)
      local sig = crypto.schnorr_sign(sk, msg, aux)
      assert.is_true(crypto.schnorr_verify(pk, sig, msg))
    end)

    it("schnorr_sign default aux_rand (nil) equals all-zero aux_rand", function()
      -- Per BIP-340 §"Default Signing", NULL aux is equivalent to zeros.
      local v = bip340_signing_vectors[1]
      local sk = hex_to_bin(v.secret_key)
      local msg = hex_to_bin(v.message)
      local sig_default = crypto.schnorr_sign(sk, msg, nil)
      local sig_zero = crypto.schnorr_sign(sk, msg, string.rep("\x00", 32))
      assert.equals(bin_to_hex(sig_zero), bin_to_hex(sig_default))
    end)

    it("schnorr_sign round-trips for random (sk, msg) pairs", function()
      for _ = 1, 16 do
        local sk = crypto.random_bytes(32)
        -- Force a valid (non-zero, < n) seckey by setting the high byte to a
        -- safe value. Skipping CSPRNG-rejection edge cases keeps the test
        -- hermetic without weakening the signing path itself.
        sk = string.char(0x42) .. sk:sub(2)
        local msg = crypto.random_bytes(32)
        local sig, err = crypto.schnorr_sign(sk, msg, crypto.random_bytes(32))
        assert.is_nil(err)
        assert.equals(64, #sig)
        -- Recover the x-only pubkey from sk (drop parity byte from compressed).
        local pk_compressed = crypto.pubkey_from_privkey(sk, true)
        assert.is_string(pk_compressed)
        local pk_xonly = pk_compressed:sub(2, 33)
        assert.is_true(crypto.schnorr_verify(pk_xonly, sig, msg))
      end
    end)

    it("schnorr_sign rejects all-zero seckey (invalid for the curve)", function()
      local sk = string.rep("\x00", 32)
      local msg = string.rep("\x00", 32)
      local sig, err = crypto.schnorr_sign(sk, msg, nil)
      assert.is_nil(sig)
      assert.matches("keypair_create", err)
    end)

    it("schnorr_sign asserts on wrong-length privkey", function()
      assert.has_error(function()
        crypto.schnorr_sign(string.rep("\x01", 31), string.rep("\x00", 32))
      end)
    end)

    it("schnorr_sign asserts on wrong-length msg", function()
      assert.has_error(function()
        crypto.schnorr_sign(string.rep("\x01", 32), string.rep("\x00", 33))
      end)
    end)

    it("schnorr_sign asserts on wrong-length aux_rand", function()
      assert.has_error(function()
        crypto.schnorr_sign(
          string.rep("\x01", 32), string.rep("\x00", 32), string.rep("\xff", 16)
        )
      end)
    end)

    it("taproot_tweak_seckey produces a seckey whose xonly pubkey matches tweak_pubkey", function()
      -- BIP-341: applying TapTweak on the seckey side and on the pubkey side
      -- must yield the same x-only output. This is the round-trip the wallet
      -- relies on for BIP-86 key-path spends.
      local sk = string.rep("\x42", 32)
      local pk_compressed = crypto.pubkey_from_privkey(sk, true)
      local internal_xonly = pk_compressed:sub(2, 33)
      local tweak = crypto.tagged_hash("TapTweak", internal_xonly)

      local tweaked_sk, err = crypto.taproot_tweak_seckey(sk, tweak)
      assert.is_nil(err)
      assert.equals(32, #tweaked_sk)

      -- xonly(pubkey_from_privkey(tweaked_sk)) must equal tweak_pubkey side.
      local tweaked_pk = crypto.pubkey_from_privkey(tweaked_sk, true)
      local tweaked_xonly_via_sk = tweaked_pk:sub(2, 33)
      local tweaked_xonly_via_pk = crypto.tweak_pubkey(internal_xonly, tweak)
      assert.equals(bin_to_hex(tweaked_xonly_via_pk), bin_to_hex(tweaked_xonly_via_sk))

      -- And the tweaked seckey signs in a way that verifies under the tweaked
      -- xonly pubkey — the property the wallet's P2TR signing branch needs.
      local msg = crypto.sha256("taproot-tweak-roundtrip")
      local sig = crypto.schnorr_sign(tweaked_sk, msg, string.rep("\x00", 32))
      assert.is_true(crypto.schnorr_verify(tweaked_xonly_via_pk, sig, msg))
    end)

    it("taproot_tweak_seckey rejects all-zero seckey", function()
      local sk = string.rep("\x00", 32)
      local tweak = string.rep("\x00", 32)
      local out, err = crypto.taproot_tweak_seckey(sk, tweak)
      assert.is_nil(out)
      assert.matches("keypair_create", err)
    end)
  end)

  describe("sha256_init streaming", function()
    it("produces same result as single-call sha256", function()
      local data1 = "hello "
      local data2 = "world"
      local full_data = data1 .. data2

      local hasher = crypto.sha256_init()
      hasher.update(data1)
      hasher.update(data2)
      local streaming_result = hasher.final()

      local single_result = crypto.sha256(full_data)

      assert.equals(bin_to_hex(single_result), bin_to_hex(streaming_result))
    end)

    it("handles empty updates", function()
      local hasher = crypto.sha256_init()
      hasher.update("")
      hasher.update("test")
      hasher.update("")
      local result = hasher.final()

      assert.equals(bin_to_hex(crypto.sha256("test")), bin_to_hex(result))
    end)

    it("rejects double final() instead of double-freeing EVP_MD_CTX", function()
      local hasher = crypto.sha256_init()
      hasher.update("x")
      hasher.final()
      local ok, err = pcall(function() hasher.final() end)
      assert.is_false(ok)
      assert.is_truthy(tostring(err):find("final%(%) called after final%(%)"))
    end)

    it("rejects update() after final()", function()
      local hasher = crypto.sha256_init()
      hasher.final()
      local ok, err = pcall(function() hasher.update("x") end)
      assert.is_false(ok)
      assert.is_truthy(tostring(err):find("update%(%) called after final%(%)"))
    end)
  end)

  describe("hmac_sha256", function()
    it("computes HMAC-SHA256 for known test vector", function()
      -- Test vector from RFC 4231
      local key = hex_to_bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
      local data = "Hi There"
      local result = crypto.hmac_sha256(key, data)
      local expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
      assert.equals(expected, bin_to_hex(result))
    end)
  end)

  describe("random_bytes", function()
    it("returns requested number of bytes", function()
      local bytes16 = crypto.random_bytes(16)
      local bytes32 = crypto.random_bytes(32)
      local bytes64 = crypto.random_bytes(64)

      assert.equals(16, #bytes16)
      assert.equals(32, #bytes32)
      assert.equals(64, #bytes64)
    end)

    it("returns different values on successive calls", function()
      local r1 = crypto.random_bytes(32)
      local r2 = crypto.random_bytes(32)
      local r3 = crypto.random_bytes(32)

      assert.is_not.equals(r1, r2)
      assert.is_not.equals(r2, r3)
      assert.is_not.equals(r1, r3)
    end)
  end)

  describe("siphash24", function()
    it("computes SipHash-2-4 for known test vector", function()
      local ffi = require("ffi")
      -- Test vector from SipHash paper
      -- Key: 00 01 02 ... 0f
      -- Data: 00 01 02 ... 0e (15 bytes)
      -- Expected: a129ca61 49be45e5
      local k0 = ffi.new("uint64_t", 0x0706050403020100ULL)
      local k1 = ffi.new("uint64_t", 0x0f0e0d0c0b0a0908ULL)
      local data = string.char(
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e
      )

      local result = crypto.siphash24(k0, k1, data)

      -- Expected: 0xa129ca6149be45e5 (little-endian)
      local expected = ffi.new("uint64_t", 0xa129ca6149be45e5ULL)
      assert.equals(tostring(expected), tostring(result))
    end)
  end)

  describe("ffi buffer reuse", function()
    it("multiple hash calls work correctly without interference", function()
      -- Ensure FFI buffers are properly managed
      local results = {}
      for i = 1, 100 do
        results[i] = crypto.sha256("test" .. i)
      end

      -- Verify each hash is unique and correct
      for i = 1, 100 do
        local expected = crypto.sha256("test" .. i)
        assert.equals(bin_to_hex(expected), bin_to_hex(results[i]))
      end
    end)

    it("interleaved hash operations work correctly", function()
      -- SHA256 then RIPEMD160 then SHA256 again
      local sha1 = crypto.sha256("first")
      local ripe = crypto.ripemd160("second")
      local sha2 = crypto.sha256("third")

      assert.equals(32, #sha1)
      assert.equals(20, #ripe)
      assert.equals(32, #sha2)

      -- Verify results are correct
      assert.equals(bin_to_hex(crypto.sha256("first")), bin_to_hex(sha1))
      assert.equals(bin_to_hex(crypto.ripemd160("second")), bin_to_hex(ripe))
      assert.equals(bin_to_hex(crypto.sha256("third")), bin_to_hex(sha2))
    end)
  end)
end)
