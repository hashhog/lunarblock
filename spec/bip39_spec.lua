-- Helpers
local function bin_to_hex(bin)
  local hex = {}
  for i = 1, #bin do
    hex[i] = string.format("%02x", bin:byte(i))
  end
  return table.concat(hex)
end

local function hex_to_bin(hex)
  return (hex:gsub("..", function(cc) return string.char(tonumber(cc, 16)) end))
end

describe("bip39", function()
  local bip39

  setup(function()
    package.path = "src/?.lua;" .. package.path
    bip39 = require("lunarblock.bip39")
  end)

  --------------------------------------------------------------------------
  -- Wordlist sanity
  --------------------------------------------------------------------------
  describe("wordlist", function()
    it("has exactly 2048 entries", function()
      assert.are.equal(2048, #bip39.wordlist)
    end)

    it("starts with abandon, ends with zoo (BIP-39 English)", function()
      assert.are.equal("abandon", bip39.wordlist[1])
      assert.are.equal("zoo", bip39.wordlist[2048])
    end)
  end)

  --------------------------------------------------------------------------
  -- TREZOR test vectors
  -- Source: https://github.com/trezor/python-mnemonic/blob/master/vectors.json
  -- (passphrase "TREZOR" for all vectors)
  --------------------------------------------------------------------------
  local function check_vector(name, ent_hex, expected_words, expected_seed_hex)
    it("vector " .. name .. ": entropy_to_mnemonic", function()
      local ent = hex_to_bin(ent_hex)
      local words = bip39.entropy_to_mnemonic(ent)
      assert.are.equal(expected_words, table.concat(words, " "))
    end)

    it("vector " .. name .. ": mnemonic_to_entropy roundtrip", function()
      local got_ent, err = bip39.mnemonic_to_entropy(expected_words)
      assert.is_nil(err)
      assert.are.equal(ent_hex, bin_to_hex(got_ent))
    end)

    it("vector " .. name .. ": mnemonic_to_seed (BYTE-IDENTITY)", function()
      local seed = bip39.mnemonic_to_seed(expected_words, "TREZOR")
      assert.are.equal(64, #seed)
      -- Per-byte hex equality. This is the haskoin-iteration-collapse
      -- trap: a wrong-iter-count seed is still 64 bytes and deterministic,
      -- so length + repeatability alone won't catch it.
      local got_hex = bin_to_hex(seed)
      assert.are.equal(expected_seed_hex, got_hex)
      -- Belt-and-suspenders: explicit per-byte byte() compare to make the
      -- check obvious in failure messages.
      for i = 1, 64 do
        local want = tonumber(expected_seed_hex:sub(i * 2 - 1, i * 2), 16)
        assert.are.equal(want, seed:byte(i),
          "seed byte mismatch at index " .. i)
      end
    end)
  end

  -- Vector 1: 12 words, all-zeros entropy
  check_vector(
    "12-word zeros",
    "00000000000000000000000000000000",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
  )

  -- Vector 2: 12 words, 0x7f * 16 entropy
  check_vector(
    "12-word 0x7f",
    "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"
  )

  -- Vector 3: 24 words, 0x80 * 32 entropy (canonical TREZOR vector,
  -- entry "8080..." in trezor/python-mnemonic/vectors.json).
  check_vector(
    "24-word 0x80",
    "8080808080808080808080808080808080808080808080808080808080808080",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
    "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f"
  )

  --------------------------------------------------------------------------
  -- Empty-passphrase vector (TREZOR vectors include this case too)
  -- entropy = 0x00..00 (16 bytes), passphrase = ""
  -- Expected seed (TREZOR JSON) — passphrase=""  is rarely published, but
  -- we cover it via determinism + length here. If we add a published
  -- empty-passphrase TREZOR vector later, replace this test.
  --------------------------------------------------------------------------
  describe("mnemonic_to_seed empty-passphrase determinism", function()
    it("produces a deterministic 64-byte seed for empty passphrase", function()
      local m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      local s1 = bip39.mnemonic_to_seed(m, "")
      local s2 = bip39.mnemonic_to_seed(m)  -- nil → ""
      assert.are.equal(64, #s1)
      assert.are.equal(s1, s2)
    end)
  end)

  --------------------------------------------------------------------------
  -- Checksum validation
  --------------------------------------------------------------------------
  describe("mnemonic_to_entropy checksum", function()
    it("accepts a valid 12-word mnemonic", function()
      local ok = bip39.validate_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
      assert.is_true(ok)
    end)

    it("rejects a 12-word mnemonic with corrupted last word", function()
      -- Replacing the last word breaks the checksum bits.
      local bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
      local ok, err = bip39.validate_mnemonic(bad)
      assert.is_false(ok)
      assert.is_truthy(err)
      assert.is_truthy(err:match("checksum"))
    end)

    it("rejects a mnemonic with an unknown word", function()
      local bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword"
      local ok, err = bip39.validate_mnemonic(bad)
      assert.is_false(ok)
      assert.is_truthy(err)
      assert.is_truthy(err:match("not in BIP%-39"))
    end)

    it("rejects an invalid word count", function()
      local bad = "abandon abandon abandon"
      local ok, err = bip39.validate_mnemonic(bad)
      assert.is_false(ok)
      assert.is_truthy(err:match("word count"))
    end)

    it("rejects a mnemonic with corrupted middle word", function()
      -- "winner" → "abandon" in vector 2 should break the checksum.
      local bad = "legal abandon thank year wave sausage worth useful legal winner thank yellow"
      local ok, err = bip39.validate_mnemonic(bad)
      assert.is_false(ok)
      assert.is_truthy(err)
    end)
  end)

  --------------------------------------------------------------------------
  -- Entropy length validation
  --------------------------------------------------------------------------
  describe("entropy_to_mnemonic input validation", function()
    it("accepts 16/20/24/28/32 byte entropy", function()
      for _, n in ipairs({16, 20, 24, 28, 32}) do
        local ent = string.rep("\0", n)
        local words = bip39.entropy_to_mnemonic(ent)
        assert.is_table(words)
        local n_expected = ({[16]=12,[20]=15,[24]=18,[28]=21,[32]=24})[n]
        assert.are.equal(n_expected, #words)
      end
    end)

    it("rejects bad entropy lengths", function()
      assert.has_error(function() bip39.entropy_to_mnemonic(string.rep("\0", 15)) end)
      assert.has_error(function() bip39.entropy_to_mnemonic(string.rep("\0", 33)) end)
      assert.has_error(function() bip39.entropy_to_mnemonic("") end)
    end)
  end)

  --------------------------------------------------------------------------
  -- generate_mnemonic round-trip
  --------------------------------------------------------------------------
  describe("generate_mnemonic", function()
    it("round-trips entropy → mnemonic → entropy for all sizes", function()
      for _, n in ipairs({12, 15, 18, 21, 24}) do
        local words, ent = bip39.generate_mnemonic(n)
        assert.are.equal(n, #words)
        local got, err = bip39.mnemonic_to_entropy(words)
        assert.is_nil(err)
        assert.are.equal(ent, got)
        assert.is_true(bip39.validate_mnemonic(words))
      end
    end)
  end)

  --------------------------------------------------------------------------
  -- Wallet integration: import_mnemonic + get_mnemonic
  --------------------------------------------------------------------------
  describe("wallet integration", function()
    local wallet
    local consensus

    setup(function()
      wallet = require("lunarblock.wallet")
      consensus = require("lunarblock.consensus")
    end)

    it("import_mnemonic builds a usable wallet", function()
      local m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      local w, err = wallet.import_mnemonic(m, "TREZOR", consensus.networks.mainnet)
      assert.is_nil(err)
      assert.is_truthy(w)
      assert.is_false(w.is_locked)
      -- Wallet should expose addresses (gap_limit=20 by default).
      assert.is_true(#w.addresses >= 1)
    end)

    it("import_mnemonic rejects bad checksum", function()
      local bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
      local w, err = wallet.import_mnemonic(bad, "", consensus.networks.mainnet)
      assert.is_nil(w)
      assert.is_truthy(err)
      assert.is_truthy(err:match("checksum"))
    end)

    it("get_mnemonic round-trips through encrypt/lock/unlock", function()
      local m = "legal winner thank year wave sausage worth useful legal winner thank yellow"
      local w, err = wallet.import_mnemonic(m, "", consensus.networks.mainnet, nil, "wallet-pw")
      assert.is_nil(err)
      assert.is_truthy(w)
      assert.is_true(w.is_encrypted)

      local words = w:get_mnemonic()
      assert.are.equal(m, table.concat(words, " "))

      w:lock()
      local _, locked_err = w:get_mnemonic()
      assert.is_truthy(locked_err)
      assert.is_truthy(locked_err:match("locked"))

      assert.is_true(w:unlock("wallet-pw"))
      local words2 = w:get_mnemonic()
      assert.are.equal(m, table.concat(words2, " "))
    end)

    it("legacy from_seed wallets have no mnemonic", function()
      local seed = string.rep("\0", 32)
      local w = wallet.from_seed(seed, consensus.networks.mainnet)
      local words, err = w:get_mnemonic()
      assert.is_nil(words)
      assert.is_truthy(err)
      assert.is_truthy(err:match("not created"))
    end)

    it("seed derivation matches BIP-39 spec for vector 1", function()
      -- The wallet master key should match what BIP-32 produces from the
      -- BIP-39 seed for vector 1 (passphrase "TREZOR"). This is the
      -- end-to-end check that our PBKDF2 + master_key_from_seed wiring
      -- produces something Trezor / Sparrow / Electrum could re-derive.
      local m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      local seed = bip39.mnemonic_to_seed(m, "TREZOR")
      local from_mnemonic = wallet.master_key_from_seed(seed)
      local imported, err = wallet.import_mnemonic(m, "TREZOR", nil)
      assert.is_nil(err)
      assert.are.equal(from_mnemonic.key, imported.master_key.key)
      assert.are.equal(from_mnemonic.chain_code, imported.master_key.chain_code)
    end)
  end)
end)
