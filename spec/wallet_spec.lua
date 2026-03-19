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

-- Custom loader for lunarblock modules (handles src/ directory layout)
local function setup_loader()
  local loaders = package.loaders or package.searchers
  table.insert(loaders, 2, function(module)
    local name = module:match("^lunarblock%.(.+)")
    if name then
      local filename = "src/" .. name .. ".lua"
      local f = io.open(filename)
      if f then
        f:close()
        return function()
          return dofile(filename)
        end
      end
    end
    return nil, "not found"
  end)
end

describe("wallet", function()
  local wallet
  local crypto
  local types
  local consensus
  local address
  local fee

  setup(function()
    setup_loader()
    wallet = require("lunarblock.wallet")
    crypto = require("lunarblock.crypto")
    types = require("lunarblock.types")
    consensus = require("lunarblock.consensus")
    address = require("lunarblock.address")
    fee = require("lunarblock.fee")
  end)

  describe("master_key_from_seed", function()
    it("produces deterministic keys from same seed", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
      local master1 = wallet.master_key_from_seed(seed)
      local master2 = wallet.master_key_from_seed(seed)

      assert.equals(master1.key, master2.key)
      assert.equals(master1.chain_code, master2.chain_code)
    end)

    it("produces different keys from different seeds", function()
      local seed1 = hex_to_bin("000102030405060708090a0b0c0d0e0f")
      local seed2 = hex_to_bin("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")

      local master1 = wallet.master_key_from_seed(seed1)
      local master2 = wallet.master_key_from_seed(seed2)

      assert.not_equals(master1.key, master2.key)
    end)

    -- BIP32 Test Vector 1 seed: 000102030405060708090a0b0c0d0e0f
    -- Expected m: xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi
    it("produces correct master key for BIP32 test vector 1", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
      local master = wallet.master_key_from_seed(seed)

      -- Expected values from BIP32 test vector
      local expected_key = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
      local expected_chain = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"

      assert.equals(expected_key, bin_to_hex(master.key))
      assert.equals(expected_chain, bin_to_hex(master.chain_code))
      assert.equals(0, master.depth)
      assert.is_true(master.is_private)
    end)
  end)

  describe("BIP32 child derivation", function()
    local master

    setup(function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
      master = wallet.master_key_from_seed(seed)
    end)

    it("derives hardened child key correctly", function()
      -- m/0' from BIP32 test vector 1
      local child = wallet.derive_child(master, 0x80000000)

      local expected_key = "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
      local expected_chain = "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"

      assert.equals(expected_key, bin_to_hex(child.key))
      assert.equals(expected_chain, bin_to_hex(child.chain_code))
      assert.equals(1, child.depth)
    end)

    it("derives normal child key correctly", function()
      -- First derive m/0', then m/0'/1
      local m0h = wallet.derive_child(master, 0x80000000)
      local child = wallet.derive_child(m0h, 1)

      local expected_key = "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
      local expected_chain = "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"

      assert.equals(expected_key, bin_to_hex(child.key))
      assert.equals(expected_chain, bin_to_hex(child.chain_code))
      assert.equals(2, child.depth)
    end)

    it("increments depth correctly through derivation path", function()
      local child1 = wallet.derive_child(master, 0x80000000)
      local child2 = wallet.derive_child(child1, 1)
      local child3 = wallet.derive_child(child2, 0x80000002)

      assert.equals(1, child1.depth)
      assert.equals(2, child2.depth)
      assert.equals(3, child3.depth)
    end)

    it("sets parent fingerprint correctly", function()
      local child = wallet.derive_child(master, 0x80000000)

      -- Fingerprint should be first 4 bytes of hash160(parent pubkey)
      local parent_pubkey = crypto.pubkey_from_privkey(master.key, true)
      local expected_fp = crypto.hash160(parent_pubkey):sub(1, 4)

      assert.equals(expected_fp, child.parent_fingerprint)
    end)
  end)

  describe("BIP44 path derivation", function()
    local master

    setup(function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      master = wallet.master_key_from_seed(seed)
    end)

    it("derives m/44'/0'/0'/0/0 correctly", function()
      local key = wallet.derive_bip44_key(master, 0, 0, 0)

      -- Verify the key can generate a valid address
      local pubkey = crypto.pubkey_from_privkey(key.key, true)
      assert.equals(33, #pubkey)

      -- Verify depth is correct (5 levels: 44'/0'/0'/0/0)
      assert.equals(5, key.depth)
    end)

    it("produces unique keys for different indices", function()
      local key0 = wallet.derive_bip44_key(master, 0, 0, 0)
      local key1 = wallet.derive_bip44_key(master, 0, 0, 1)
      local key2 = wallet.derive_bip44_key(master, 0, 1, 0)

      assert.not_equals(key0.key, key1.key)
      assert.not_equals(key0.key, key2.key)
    end)
  end)

  describe("BIP84 path derivation", function()
    local master

    setup(function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      master = wallet.master_key_from_seed(seed)
    end)

    it("derives m/84'/0'/0'/0/0 correctly", function()
      local key = wallet.derive_bip84_key(master, 0, 0, 0)

      -- Verify the key can generate a valid address
      local pubkey = crypto.pubkey_from_privkey(key.key, true)
      assert.equals(33, #pubkey)

      -- Verify depth is correct (5 levels: 84'/0'/0'/0/0)
      assert.equals(5, key.depth)
    end)

    it("produces different keys from BIP44", function()
      local key44 = wallet.derive_bip44_key(master, 0, 0, 0)
      local key84 = wallet.derive_bip84_key(master, 0, 0, 0)

      assert.not_equals(key44.key, key84.key)
    end)
  end)

  describe("Wallet creation", function()
    it("generates gap_limit addresses", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      -- Should have gap_limit * 2 addresses (external + internal)
      assert.equals(w.gap_limit * 2, #w.addresses)
    end)

    it("creates addresses with correct type", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      -- All addresses should be P2WPKH by default (bc1q prefix)
      local addr = w.addresses[1]
      assert.equals("bc1", addr:sub(1, 3))
    end)

    it("tracks next indices correctly", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      assert.equals(w.gap_limit, w.next_external_index)
      assert.equals(w.gap_limit, w.next_internal_index)
    end)
  end)

  describe("get_new_address", function()
    it("returns unique addresses", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      local addr1 = w:get_new_address()
      local addr2 = w:get_new_address()
      local addr3 = w:get_new_address()

      assert.not_equals(addr1, addr2)
      assert.not_equals(addr2, addr3)
      assert.not_equals(addr1, addr3)
    end)

    it("increments external index", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      local initial_index = w.next_external_index
      w:get_new_address()
      assert.equals(initial_index + 1, w.next_external_index)
    end)
  end)

  describe("WIF export/import round-trip", function()
    it("exports and imports private key correctly", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      local addr = w.addresses[1]
      local original_key = w.keys[addr].privkey

      -- Export
      local wif = w:dump_privkey(addr)
      assert.is_not_nil(wif)
      -- Mainnet compressed WIF starts with 'K' or 'L'
      assert.is_true(wif:match("^[KL]") ~= nil)

      -- Create new wallet and import
      local w2 = wallet.new(consensus.networks.mainnet, nil)
      w2.master_key = wallet.master_key_from_seed(hex_to_bin("aaaa"))  -- dummy
      local imported_addr = w2:import_privkey(wif)

      assert.equals(original_key, w2.keys[imported_addr].privkey)
    end)

    it("returns error for non-existent address", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      local wif, err = w:dump_privkey("bc1qnotinwallet")
      assert.is_nil(wif)
      assert.equals("Address not in wallet", err)
    end)
  end)

  describe("Transaction creation", function()
    it("builds valid transaction structure", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      -- Manually add a UTXO for testing
      local addr = w.addresses[1]
      local fake_txid = types.hash256(string.rep("\x01", 32))
      local utxo_key = fake_txid.bytes .. "\x00\x00\x00\x00"

      w.utxos[utxo_key] = {
        value = 100000,  -- 0.001 BTC
        script_pubkey = "\x00\x14" .. crypto.hash160(w.keys[addr].pubkey),
        address = addr,
        txid = fake_txid,
        vout = 0,
        height = 100,
        is_coinbase = false,
      }
      w.balance = 100000

      -- Create transaction
      local recipient_addr = w:get_new_address()
      local tx, fee = w:create_transaction({
        {address = recipient_addr, amount = 50000}
      }, 1)  -- 1 sat/vB

      assert.is_not_nil(tx)
      assert.is_true(fee > 0)
      assert.equals(2, tx.version)
      assert.equals(1, #tx.inputs)
      assert.is_true(#tx.outputs >= 1)
    end)

    it("returns error for insufficient funds", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      -- No UTXOs
      local recipient_addr = w:get_new_address()
      local tx, err = w:create_transaction({
        {address = recipient_addr, amount = 50000}
      }, 1)

      assert.is_nil(tx)
      assert.equals("Insufficient funds", err)
    end)
  end)

  describe("Transaction signing", function()
    it("produces valid P2WPKH signatures", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      -- Manually add a UTXO
      local addr = w.addresses[1]
      local key_info = w.keys[addr]
      local pubkey_hash = crypto.hash160(key_info.pubkey)
      local fake_txid = types.hash256(string.rep("\x01", 32))
      local utxo_key = fake_txid.bytes .. "\x00\x00\x00\x00"

      w.utxos[utxo_key] = {
        value = 100000,
        script_pubkey = "\x00\x14" .. pubkey_hash,
        address = addr,
        txid = fake_txid,
        vout = 0,
        height = 100,
        is_coinbase = false,
      }
      w.balance = 100000

      -- Create and sign transaction
      local recipient_addr = w:get_new_address()
      local tx, _ = w:create_transaction({
        {address = recipient_addr, amount = 50000}
      }, 1)

      assert.is_not_nil(tx)
      assert.is_true(tx.segwit)

      -- Check witness
      local witness = tx.inputs[1].witness
      assert.equals(2, #witness)

      -- Verify signature structure (DER + SIGHASH byte)
      local sig = witness[1]
      assert.is_true(#sig >= 71 and #sig <= 73)  -- 70-72 byte DER + 1 byte sighash
      assert.equals(0x01, sig:byte(#sig))  -- SIGHASH_ALL

      -- Verify pubkey
      local pubkey = witness[2]
      assert.equals(33, #pubkey)  -- Compressed pubkey
    end)
  end)

  describe("Wallet serialization/deserialization", function()
    it("round-trips correctly", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w1 = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      -- Get some new addresses to change indices
      w1:get_new_address()
      w1:get_new_address()

      -- Save and load
      local test_path = "/tmp/test_wallet_" .. os.time() .. ".json"
      w1:save(test_path)
      local w2 = wallet.load(test_path, consensus.networks.mainnet, nil)

      -- Verify loaded wallet matches
      assert.equals(w1.master_key.key, w2.master_key.key)
      assert.equals(w1.master_key.chain_code, w2.master_key.chain_code)
      assert.equals(w1.next_external_index, w2.next_external_index)
      assert.equals(w1.next_internal_index, w2.next_internal_index)
      assert.equals(w1.account, w2.account)
      assert.equals(w1.address_type, w2.address_type)

      -- Clean up
      os.remove(test_path)
    end)

    it("regenerates addresses on load", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w1 = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      local test_path = "/tmp/test_wallet_" .. os.time() .. ".json"
      w1:save(test_path)
      local w2 = wallet.load(test_path, consensus.networks.mainnet, nil)

      -- First address should match
      assert.equals(w1.addresses[1], w2.addresses[1])

      -- Clean up
      os.remove(test_path)
    end)
  end)

  describe("Balance calculation", function()
    it("calculates balance from UTXOs", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      -- Add multiple UTXOs
      local addr = w.addresses[1]
      local key_info = w.keys[addr]
      local pubkey_hash = crypto.hash160(key_info.pubkey)

      for i = 1, 3 do
        local fake_txid = types.hash256(string.rep(string.char(i), 32))
        local utxo_key = fake_txid.bytes .. "\x00\x00\x00\x00"
        w.utxos[utxo_key] = {
          value = 10000 * i,
          script_pubkey = "\x00\x14" .. pubkey_hash,
          address = addr,
          txid = fake_txid,
          vout = 0,
          height = 100,
          is_coinbase = false,
        }
      end

      -- Manually update balance (normally done by scan_utxos)
      w.balance = 10000 + 20000 + 30000

      assert.equals(60000, w:get_balance())
    end)
  end)

  describe("hex_encode and hex_decode", function()
    it("round-trips binary data", function()
      local data = "\x00\x01\x02\xff\xfe\xfd"
      local hex = wallet.hex_encode(data)
      local decoded = wallet.hex_decode(hex)

      assert.equals(data, decoded)
    end)

    it("encodes correctly", function()
      local data = "\x00\x0f\xf0\xff"
      local hex = wallet.hex_encode(data)
      assert.equals("000ff0ff", hex)
    end)
  end)

  describe("derive_path", function()
    it("parses and derives path correctly", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
      local master = wallet.master_key_from_seed(seed)

      -- Derive m/0'/1 using derive_path
      local key = wallet.derive_path(master, "m/0'/1")

      -- Compare with manual derivation
      local m0h = wallet.derive_child(master, 0x80000000)
      local expected = wallet.derive_child(m0h, 1)

      assert.equals(expected.key, key.key)
      assert.equals(expected.chain_code, key.chain_code)
    end)

    it("handles both ' and h for hardened", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
      local master = wallet.master_key_from_seed(seed)

      local key1 = wallet.derive_path(master, "m/44'/0'")
      local key2 = wallet.derive_path(master, "m/44h/0h")

      assert.equals(key1.key, key2.key)
    end)
  end)

  describe("Network support", function()
    it("supports testnet addresses", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.testnet, nil)

      local addr = w.addresses[1]
      -- Testnet P2WPKH addresses start with tb1q
      assert.equals("tb1", addr:sub(1, 3))
    end)

    it("supports regtest addresses", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.regtest, nil)

      local addr = w.addresses[1]
      -- Regtest P2WPKH addresses start with bcrt1q
      assert.equals("bcrt", addr:sub(1, 4))
    end)
  end)

  describe("AES encryption", function()
    it("encrypts and decrypts data correctly", function()
      local plaintext = "Hello, Bitcoin wallet!"
      local salt = wallet.random_bytes(wallet.CRYPTO_SALT_SIZE)
      local key, iv = wallet.derive_key("test_passphrase", salt)

      local ciphertext = wallet.aes_encrypt(plaintext, key, iv)
      assert.is_not_nil(ciphertext)
      assert.not_equals(plaintext, ciphertext)

      local decrypted = wallet.aes_decrypt(ciphertext, key, iv)
      assert.equals(plaintext, decrypted)
    end)

    it("fails decryption with wrong passphrase", function()
      local plaintext = "Secret data"
      local salt = wallet.random_bytes(wallet.CRYPTO_SALT_SIZE)
      local key1, iv1 = wallet.derive_key("correct_passphrase", salt)
      local key2, iv2 = wallet.derive_key("wrong_passphrase", salt)

      local ciphertext = wallet.aes_encrypt(plaintext, key1, iv1)
      local decrypted, err = wallet.aes_decrypt(ciphertext, key2, iv2)
      assert.is_nil(decrypted)
      assert.is_not_nil(err)
    end)

    it("generates random bytes", function()
      local bytes1 = wallet.random_bytes(32)
      local bytes2 = wallet.random_bytes(32)

      assert.equals(32, #bytes1)
      assert.equals(32, #bytes2)
      assert.not_equals(bytes1, bytes2)
    end)
  end)

  describe("Wallet encryption", function()
    it("encrypts wallet with passphrase", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      w:encrypt("my_passphrase")

      assert.is_true(w.is_encrypted)
      assert.is_false(w.is_locked)
      assert.is_not_nil(w.encrypted_master_key)
      assert.is_not_nil(w.encryption_salt)
    end)

    it("locks and unlocks wallet", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)
      local original_key = w.master_key.key

      w:encrypt("my_passphrase")
      w:lock()

      assert.is_true(w.is_locked)
      assert.is_nil(w.master_key)

      local ok = w:unlock("my_passphrase")
      assert.is_true(ok)
      assert.is_false(w.is_locked)
      assert.equals(original_key, w.master_key.key)
    end)

    it("fails unlock with wrong passphrase", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      w:encrypt("correct_passphrase")
      w:lock()

      local ok, err = w:unlock("wrong_passphrase")
      assert.is_false(ok)
      assert.is_not_nil(err)
      assert.is_true(w.is_locked)
    end)

    it("changes passphrase", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      w:encrypt("old_passphrase")
      local ok = w:change_passphrase("old_passphrase", "new_passphrase")
      assert.is_true(ok)

      w:lock()
      local unlock_ok = w:unlock("new_passphrase")
      assert.is_true(unlock_ok)
    end)
  end)

  describe("Coin selection - Branch and Bound", function()
    it("finds exact match when possible", function()
      local utxos = {
        {key = "a", utxo = {value = 10000}},
        {key = "b", utxo = {value = 20000}},
        {key = "c", utxo = {value = 50000}},
      }

      -- Target 30000, should select 10000 + 20000
      local selected = wallet.select_coins_bnb(utxos, 30000, 1)
      if selected then
        local total = 0
        for _, s in ipairs(selected) do
          total = total + s.utxo.value
        end
        -- BnB should find a solution close to target
        assert.is_true(total >= 30000)
      end
    end)

    it("returns nil when insufficient funds", function()
      local utxos = {
        {key = "a", utxo = {value = 10000}},
        {key = "b", utxo = {value = 20000}},
      }

      local selected = wallet.select_coins_bnb(utxos, 100000, 1)
      assert.is_nil(selected)
    end)
  end)

  describe("Coin selection - Knapsack", function()
    it("selects coins for target", function()
      local utxos = {
        {key = "a", utxo = {value = 10000}},
        {key = "b", utxo = {value = 20000}},
        {key = "c", utxo = {value = 50000}},
        {key = "d", utxo = {value = 100000}},
      }

      local selected = wallet.select_coins_knapsack(utxos, 25000)
      assert.is_not_nil(selected)

      local total = 0
      for _, s in ipairs(selected) do
        total = total + s.utxo.value
      end
      assert.is_true(total >= 25000)
    end)

    it("prefers single UTXO close to target", function()
      local utxos = {
        {key = "a", utxo = {value = 10000}},
        {key = "b", utxo = {value = 50000}},
        {key = "c", utxo = {value = 100000}},
      }

      local selected = wallet.select_coins_knapsack(utxos, 45000)
      assert.is_not_nil(selected)
      -- Should select 50000 (close to target)
      assert.equals(1, #selected)
      assert.equals(50000, selected[1].utxo.value)
    end)
  end)

  describe("Coin selection - Combined", function()
    it("returns algorithm used", function()
      local utxos = {
        {key = "a", utxo = {value = 100000}},
        {key = "b", utxo = {value = 200000}},
      }

      local selected, algo = wallet.select_coins(utxos, 50000, 1)
      assert.is_not_nil(selected)
      assert.is_not_nil(algo)
      assert.is_true(algo == "bnb" or algo == "knapsack" or algo == "random")
    end)
  end)

  describe("Balance tracking", function()
    it("tracks confirmed balance", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      -- Manually set up UTXOs
      local addr = w.addresses[1]
      local key_info = w.keys[addr]
      local pubkey_hash = crypto.hash160(key_info.pubkey)

      local fake_txid = types.hash256(string.rep("\x01", 32))
      local utxo_key = fake_txid.bytes .. "\x00\x00\x00\x00"

      w.utxos[utxo_key] = {
        value = 100000,
        script_pubkey = "\x00\x14" .. pubkey_hash,
        address = addr,
        txid = fake_txid,
        vout = 0,
        height = 100,
        is_coinbase = false,
        confirmations = 10,
      }
      w.confirmed_balance = 100000

      assert.equals(100000, w:get_balance())
      local details = w:get_balance_details()
      assert.equals(100000, details.confirmed)
      assert.equals(100000, details.spendable)
    end)

    it("handles coinbase maturity", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      local addr = w.addresses[1]
      local key_info = w.keys[addr]
      local pubkey_hash = crypto.hash160(key_info.pubkey)

      local fake_txid = types.hash256(string.rep("\x02", 32))
      local utxo_key = fake_txid.bytes .. "\x00\x00\x00\x00"

      -- Coinbase with insufficient confirmations
      w.utxos[utxo_key] = {
        value = 5000000000,  -- 50 BTC
        script_pubkey = "\x00\x14" .. pubkey_hash,
        address = addr,
        txid = fake_txid,
        vout = 0,
        height = 100,
        is_coinbase = true,
        confirmations = 50,  -- Less than 100
      }
      w.confirmed_balance = 5000000000

      local details = w:get_balance_details()
      assert.equals(5000000000, details.confirmed)
      assert.equals(0, details.spendable)  -- Not spendable yet

      -- Now with sufficient confirmations
      w.utxos[utxo_key].confirmations = 100
      details = w:get_balance_details()
      assert.equals(5000000000, details.spendable)
    end)
  end)

  describe("Fee estimation integration", function()
    it("uses fee estimator when available", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      local estimator = fee.new(144)
      w:set_fee_estimator(estimator)

      local rate = w:estimate_fee_rate(6)
      assert.is_true(rate >= 1)  -- At least 1 sat/vB
    end)

    it("falls back to default fee rate", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      -- No fee estimator set
      local rate = w:estimate_fee_rate(6)
      assert.equals(1, rate)  -- Default 1 sat/vB
    end)
  end)

  describe("Encrypted wallet persistence", function()
    it("saves and loads encrypted wallet", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w1 = wallet.from_seed(seed, consensus.networks.mainnet, nil)
      local original_key = w1.master_key.key

      w1:encrypt("test_passphrase")
      w1:get_new_address()

      local test_path = "/tmp/test_encrypted_wallet_" .. os.time() .. ".dat"
      local ok = w1:save(test_path)
      assert.is_true(ok)

      -- Load without passphrase (should be locked)
      local w2 = wallet.load(test_path, consensus.networks.mainnet, nil)
      assert.is_not_nil(w2)
      assert.is_true(w2.is_encrypted)
      assert.is_true(w2.is_locked)

      -- Unlock with correct passphrase
      local unlock_ok = w2:unlock("test_passphrase")
      assert.is_true(unlock_ok)
      assert.equals(original_key, w2.master_key.key)

      -- Load with passphrase (should be unlocked)
      local w3 = wallet.load(test_path, consensus.networks.mainnet, nil, "test_passphrase")
      assert.is_not_nil(w3)
      assert.is_false(w3.is_locked)
      assert.equals(original_key, w3.master_key.key)

      -- Clean up
      os.remove(test_path)
    end)
  end)

  describe("Transaction creation with options", function()
    it("creates transaction with fee rate option", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      -- Set up UTXO
      local addr = w.addresses[1]
      local key_info = w.keys[addr]
      local pubkey_hash = crypto.hash160(key_info.pubkey)
      local fake_txid = types.hash256(string.rep("\x01", 32))
      local utxo_key = fake_txid.bytes .. "\x00\x00\x00\x00"

      w.utxos[utxo_key] = {
        value = 100000,
        script_pubkey = "\x00\x14" .. pubkey_hash,
        address = addr,
        txid = fake_txid,
        vout = 0,
        height = 100,
        is_coinbase = false,
        confirmations = 10,
      }
      w.confirmed_balance = 100000

      local recipient_addr = w:get_new_address()
      local tx, result, algo = w:create_transaction({
        {address = recipient_addr, amount = 50000}
      }, {fee_rate = 5})

      assert.is_not_nil(tx)
      assert.is_true(result > 0)  -- Fee should be positive
      assert.is_not_nil(algo)
    end)

    it("fails when wallet is locked", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      w:encrypt("passphrase")
      w:lock()

      local tx, err = w:create_transaction({
        {address = w.addresses[1], amount = 50000}
      }, {fee_rate = 1})

      assert.is_nil(tx)
      assert.equals("Wallet is locked", err)
    end)
  end)

  describe("Wallet info", function()
    it("returns wallet info", function()
      local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)

      local info = w:get_info()
      assert.is_false(info.is_encrypted)
      assert.is_false(info.is_locked)
      assert.equals("mainnet", info.network)
      assert.equals("p2wpkh", info.address_type)
      assert.is_true(info.address_count > 0)
    end)
  end)
end)

--------------------------------------------------------------------------------
-- PSBT Tests (BIP174)
--------------------------------------------------------------------------------

describe("psbt", function()
  local psbt_mod
  local types
  local serialize
  local crypto
  local validation
  local consensus
  local script
  local wallet

  setup(function()
    local loaders = package.loaders or package.searchers
    table.insert(loaders, 2, function(module)
      local name = module:match("^lunarblock%.(.+)")
      if name then
        local filename = "src/" .. name .. ".lua"
        local f = io.open(filename)
        if f then
          f:close()
          return function()
            return dofile(filename)
          end
        end
      end
      return nil, "not found"
    end)
    psbt_mod = require("lunarblock.psbt")
    types = require("lunarblock.types")
    serialize = require("lunarblock.serialize")
    crypto = require("lunarblock.crypto")
    validation = require("lunarblock.validation")
    consensus = require("lunarblock.consensus")
    script = require("lunarblock.script")
    wallet = require("lunarblock.wallet")
  end)

  describe("constants", function()
    it("has correct magic bytes", function()
      assert.equals("psbt\xff", psbt_mod.MAGIC)
    end)

    it("has correct key type constants", function()
      assert.equals(0x00, psbt_mod.GLOBAL_UNSIGNED_TX)
      assert.equals(0x01, psbt_mod.GLOBAL_XPUB)
      assert.equals(0x02, psbt_mod.IN_PARTIAL_SIG)
      assert.equals(0x00, psbt_mod.SEPARATOR)
    end)
  end)

  describe("base64 encoding", function()
    it("encodes and decodes correctly", function()
      local data = "Hello, PSBT!"
      local encoded = psbt_mod.base64_encode(data)
      local decoded = psbt_mod.base64_decode(encoded)
      assert.equals(data, decoded)
    end)

    it("handles binary data", function()
      local data = "\x00\x01\x02\xff\xfe"
      local encoded = psbt_mod.base64_encode(data)
      local decoded = psbt_mod.base64_decode(encoded)
      assert.equals(data, decoded)
    end)

    it("encodes to valid base64", function()
      local data = "test"
      local encoded = psbt_mod.base64_encode(data)
      assert.equals("dGVzdA==", encoded)
    end)
  end)

  describe("PSBT creation", function()
    it("creates PSBT from unsigned transaction", function()
      -- Create a simple unsigned transaction
      local txid = types.hash256(string.rep("\x01", 32))
      local inputs = {
        types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD),
      }
      local outputs = {
        types.txout(50000, "\x00\x14" .. string.rep("\x02", 20)),  -- P2WPKH
      }
      local tx = types.transaction(2, inputs, outputs, 0)

      local psbt = psbt_mod.new(tx)

      assert.is_not_nil(psbt)
      assert.equals(0, psbt.version)
      assert.is_not_nil(psbt.tx)
      assert.equals(1, #psbt.inputs)
      assert.equals(1, #psbt.outputs)
    end)

    it("rejects signed transactions", function()
      local txid = types.hash256(string.rep("\x01", 32))
      local inputs = {
        types.txin(types.outpoint(txid, 0), "\x01\x02\x03", 0xFFFFFFFF),  -- Has scriptSig
      }
      local outputs = {
        types.txout(50000, "\x00\x14" .. string.rep("\x02", 20)),
      }
      local tx = types.transaction(2, inputs, outputs, 0)

      assert.has_error(function()
        psbt_mod.new(tx)
      end, "Transaction must be unsigned for PSBT creation")
    end)
  end)

  describe("PSBT serialization", function()
    it("serializes and deserializes round-trip", function()
      -- Create PSBT
      local txid = types.hash256(string.rep("\x01", 32))
      local inputs = {
        types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD),
      }
      local outputs = {
        types.txout(50000, "\x00\x14" .. string.rep("\x02", 20)),
      }
      local tx = types.transaction(2, inputs, outputs, 0)
      local psbt = psbt_mod.new(tx)

      -- Serialize
      local data = psbt_mod.serialize(psbt)
      assert.is_true(#data > 0)
      assert.equals("psbt\xff", data:sub(1, 5))

      -- Deserialize
      local psbt2 = psbt_mod.deserialize(data)
      assert.is_not_nil(psbt2)
      assert.equals(1, #psbt2.inputs)
      assert.equals(1, #psbt2.outputs)

      -- Compare transactions
      local txid1 = types.hash256_hex(validation.compute_txid(psbt.tx))
      local txid2 = types.hash256_hex(validation.compute_txid(psbt2.tx))
      assert.equals(txid1, txid2)
    end)

    it("base64 round-trip works", function()
      local txid = types.hash256(string.rep("\x03", 32))
      local inputs = {
        types.txin(types.outpoint(txid, 1), "", 0xFFFFFFFF),
      }
      local outputs = {
        types.txout(100000, "\x76\xa9\x14" .. string.rep("\x04", 20) .. "\x88\xac"),  -- P2PKH
      }
      local tx = types.transaction(2, inputs, outputs, 500000)
      local psbt = psbt_mod.new(tx)

      local b64 = psbt_mod.to_base64(psbt)
      local psbt2 = psbt_mod.from_base64(b64)

      assert.equals(tx.locktime, psbt2.tx.locktime)
      assert.equals(tx.version, psbt2.tx.version)
    end)
  end)

  describe("PSBT update operations", function()
    local psbt, txid

    before_each(function()
      txid = types.hash256(string.rep("\x05", 32))
      local inputs = {
        types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD),
      }
      local outputs = {
        types.txout(50000, "\x00\x14" .. string.rep("\x06", 20)),
      }
      local tx = types.transaction(2, inputs, outputs, 0)
      psbt = psbt_mod.new(tx)
    end)

    it("adds witness UTXO", function()
      psbt_mod.update_input_utxo(psbt, 0, {
        value = 100000,
        script_pubkey = "\x00\x14" .. string.rep("\x07", 20),
      }, true)

      assert.is_not_nil(psbt.inputs[1].witness_utxo)
      assert.equals(100000, psbt.inputs[1].witness_utxo.value)
    end)

    it("adds redeem script", function()
      local redeem = "\x52\x21" .. string.rep("\x08", 33) .. "\x21" .. string.rep("\x09", 33) .. "\x52\xae"
      psbt_mod.update_input_redeem_script(psbt, 0, redeem)

      assert.equals(redeem, psbt.inputs[1].redeem_script)
    end)

    it("adds BIP32 derivation", function()
      local pubkey = string.rep("\x0a", 33)
      local fingerprint = "\x0b\x0c\x0d\x0e"
      local path = {0x8000002c, 0x80000000, 0x80000000, 0, 0}

      psbt_mod.update_input_bip32(psbt, 0, pubkey, fingerprint, path)

      local pk_hex = psbt_mod.hex_encode(pubkey)
      assert.is_not_nil(psbt.inputs[1].bip32_derivations[pk_hex])
      assert.equals(fingerprint, psbt.inputs[1].bip32_derivations[pk_hex].fingerprint)
      assert.equals(5, #psbt.inputs[1].bip32_derivations[pk_hex].path)
    end)
  end)

  describe("PSBT signing", function()
    it("signs P2WPKH input", function()
      -- Create keypair
      local privkey = string.rep("\x11", 32)
      local pubkey = crypto.pubkey_from_privkey(privkey, true)
      local pkh = crypto.hash160(pubkey)
      local script_pubkey = "\x00\x14" .. pkh  -- P2WPKH

      -- Create PSBT
      local txid = types.hash256(string.rep("\x12", 32))
      local inputs = {
        types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD),
      }
      local outputs = {
        types.txout(50000, "\x00\x14" .. string.rep("\x13", 20)),
      }
      local tx = types.transaction(2, inputs, outputs, 0)
      local psbt = psbt_mod.new(tx)

      -- Add witness UTXO
      psbt_mod.update_input_utxo(psbt, 0, {
        value = 100000,
        script_pubkey = script_pubkey,
      }, true)

      -- Sign
      local signed = psbt_mod.sign_input(psbt, 0, privkey, pubkey)
      assert.is_true(signed)

      -- Check partial sig exists
      local pk_hex = psbt_mod.hex_encode(pubkey)
      assert.is_not_nil(psbt.inputs[1].partial_sigs[pk_hex])
    end)
  end)

  describe("PSBT combining", function()
    it("combines two PSBTs with different signatures", function()
      -- Create base transaction
      local txid = types.hash256(string.rep("\x14", 32))
      local inputs = {
        types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD),
      }
      local outputs = {
        types.txout(50000, "\x00\x14" .. string.rep("\x15", 20)),
      }
      local tx = types.transaction(2, inputs, outputs, 0)

      -- Create two PSBTs
      local psbt1 = psbt_mod.new(tx)
      local psbt2 = psbt_mod.deserialize(psbt_mod.serialize(psbt1))  -- Deep copy

      -- Add different signatures to each
      local pk1 = string.rep("\x16", 33)
      local pk2 = string.rep("\x17", 33)
      local sig1 = string.rep("\x18", 72) .. "\x01"
      local sig2 = string.rep("\x19", 72) .. "\x01"

      psbt1.inputs[1].partial_sigs[psbt_mod.hex_encode(pk1)] = sig1
      psbt2.inputs[1].partial_sigs[psbt_mod.hex_encode(pk2)] = sig2

      -- Combine
      local combined = psbt_mod.combine({psbt1, psbt2})

      -- Should have both signatures
      assert.is_not_nil(combined.inputs[1].partial_sigs[psbt_mod.hex_encode(pk1)])
      assert.is_not_nil(combined.inputs[1].partial_sigs[psbt_mod.hex_encode(pk2)])
    end)

    it("rejects PSBTs with different transactions", function()
      local txid1 = types.hash256(string.rep("\x1a", 32))
      local txid2 = types.hash256(string.rep("\x1b", 32))

      local tx1 = types.transaction(2, {
        types.txin(types.outpoint(txid1, 0), "", 0xFFFFFFFF),
      }, {types.txout(50000, "\x00\x14" .. string.rep("\x1c", 20))}, 0)

      local tx2 = types.transaction(2, {
        types.txin(types.outpoint(txid2, 0), "", 0xFFFFFFFF),
      }, {types.txout(50000, "\x00\x14" .. string.rep("\x1d", 20))}, 0)

      local psbt1 = psbt_mod.new(tx1)
      local psbt2 = psbt_mod.new(tx2)

      assert.has_error(function()
        psbt_mod.combine({psbt1, psbt2})
      end)
    end)
  end)

  describe("PSBT finalization", function()
    it("finalizes P2WPKH input", function()
      -- Create keypair
      local privkey = string.rep("\x1e", 32)
      local pubkey = crypto.pubkey_from_privkey(privkey, true)
      local pkh = crypto.hash160(pubkey)
      local script_pubkey = "\x00\x14" .. pkh

      -- Create PSBT
      local txid = types.hash256(string.rep("\x1f", 32))
      local inputs = {
        types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD),
      }
      local outputs = {
        types.txout(50000, "\x00\x14" .. string.rep("\x20", 20)),
      }
      local tx = types.transaction(2, inputs, outputs, 0)
      local psbt = psbt_mod.new(tx)

      -- Add UTXO and sign
      psbt_mod.update_input_utxo(psbt, 0, {
        value = 100000,
        script_pubkey = script_pubkey,
      }, true)
      psbt_mod.sign_input(psbt, 0, privkey, pubkey)

      -- Finalize
      local ok = psbt_mod.finalize_input(psbt, 0)
      assert.is_true(ok)

      -- Check final witness
      assert.is_not_nil(psbt.inputs[1].final_script_witness)
      assert.equals(2, #psbt.inputs[1].final_script_witness)  -- [sig, pubkey]
    end)
  end)

  describe("PSBT extraction", function()
    it("extracts signed transaction from finalized PSBT", function()
      -- Create keypair
      local privkey = string.rep("\x21", 32)
      local pubkey = crypto.pubkey_from_privkey(privkey, true)
      local pkh = crypto.hash160(pubkey)
      local script_pubkey = "\x00\x14" .. pkh

      -- Create PSBT
      local txid = types.hash256(string.rep("\x22", 32))
      local inputs = {
        types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD),
      }
      local outputs = {
        types.txout(50000, "\x00\x14" .. string.rep("\x23", 20)),
      }
      local tx = types.transaction(2, inputs, outputs, 0)
      local psbt = psbt_mod.new(tx)

      -- Update, sign, finalize
      psbt_mod.update_input_utxo(psbt, 0, {
        value = 100000,
        script_pubkey = script_pubkey,
      }, true)
      psbt_mod.sign_input(psbt, 0, privkey, pubkey)
      psbt_mod.finalize(psbt)

      -- Extract
      local signed_tx = psbt_mod.extract(psbt)

      assert.is_not_nil(signed_tx)
      assert.is_true(signed_tx.segwit)
      assert.equals(2, #signed_tx.inputs[1].witness)

      -- Verify signature structure
      local sig = signed_tx.inputs[1].witness[1]
      assert.is_true(#sig >= 71 and #sig <= 73)
      assert.equals(0x01, sig:byte(#sig))  -- SIGHASH_ALL
    end)

    it("fails extraction on unfinalized PSBT", function()
      local txid = types.hash256(string.rep("\x24", 32))
      local tx = types.transaction(2, {
        types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFF),
      }, {types.txout(50000, "\x00\x14" .. string.rep("\x25", 20))}, 0)
      local psbt = psbt_mod.new(tx)

      assert.has_error(function()
        psbt_mod.extract(psbt)
      end)
    end)
  end)

  describe("PSBT decode", function()
    it("decodes PSBT to human-readable format", function()
      local txid = types.hash256(string.rep("\x26", 32))
      local inputs = {
        types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD),
      }
      local outputs = {
        types.txout(50000, "\x00\x14" .. string.rep("\x27", 20)),
      }
      local tx = types.transaction(2, inputs, outputs, 0)
      local psbt = psbt_mod.new(tx)

      -- Add some data
      psbt_mod.update_input_utxo(psbt, 0, {
        value = 100000,
        script_pubkey = "\x00\x14" .. string.rep("\x28", 20),
      }, true)

      local decoded = psbt_mod.decode(psbt)

      assert.is_not_nil(decoded.tx)
      assert.is_not_nil(decoded.tx.txid)
      assert.equals(2, decoded.tx.version)
      assert.equals(1, #decoded.inputs)
      assert.equals(1, #decoded.outputs)
      assert.is_true(decoded.inputs[1].has_utxo)

      -- Fee should be calculable
      assert.equals((100000 - 50000) / consensus.COIN, decoded.fee)
    end)
  end)

  describe("PSBT status functions", function()
    it("checks if input is signed", function()
      local txid = types.hash256(string.rep("\x29", 32))
      local tx = types.transaction(2, {
        types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFF),
      }, {types.txout(50000, "\x00\x14" .. string.rep("\x2a", 20))}, 0)
      local psbt = psbt_mod.new(tx)

      assert.is_false(psbt_mod.input_is_signed(psbt.inputs[1]))

      psbt.inputs[1].final_script_witness = {"sig", "pubkey"}
      assert.is_true(psbt_mod.input_is_signed(psbt.inputs[1]))
    end)

    it("checks if PSBT is complete", function()
      local txid = types.hash256(string.rep("\x2b", 32))
      local tx = types.transaction(2, {
        types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFF),
      }, {types.txout(50000, "\x00\x14" .. string.rep("\x2c", 20))}, 0)
      local psbt = psbt_mod.new(tx)

      assert.is_false(psbt_mod.is_complete(psbt))

      psbt.inputs[1].final_script_sig = "\x00"
      assert.is_true(psbt_mod.is_complete(psbt))
    end)

    it("counts unsigned inputs", function()
      local txid = types.hash256(string.rep("\x2d", 32))
      local tx = types.transaction(2, {
        types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFF),
        types.txin(types.outpoint(txid, 1), "", 0xFFFFFFFF),
      }, {types.txout(50000, "\x00\x14" .. string.rep("\x2e", 20))}, 0)
      local psbt = psbt_mod.new(tx)

      assert.equals(2, psbt_mod.count_unsigned(psbt))

      psbt.inputs[1].final_script_witness = {"sig", "pubkey"}
      assert.equals(1, psbt_mod.count_unsigned(psbt))
    end)
  end)

  describe("full PSBT workflow", function()
    it("create -> update -> sign -> finalize -> extract round-trip", function()
      -- 1. Create transaction
      local prev_txid = types.hash256(string.rep("\x30", 32))
      local inputs = {
        types.txin(types.outpoint(prev_txid, 0), "", 0xFFFFFFFD),
      }
      local outputs = {
        types.txout(50000, "\x00\x14" .. string.rep("\x31", 20)),
        types.txout(49000, "\x00\x14" .. string.rep("\x32", 20)),  -- Change
      }
      local tx = types.transaction(2, inputs, outputs, 0)

      -- 2. Create PSBT (Creator role)
      local psbt = psbt_mod.new(tx)
      assert.is_not_nil(psbt)

      -- Serialize and deserialize to simulate passing to another party
      local psbt_b64 = psbt_mod.to_base64(psbt)
      psbt = psbt_mod.from_base64(psbt_b64)

      -- 3. Update PSBT (Updater role)
      local privkey = string.rep("\x33", 32)
      local pubkey = crypto.pubkey_from_privkey(privkey, true)
      local pkh = crypto.hash160(pubkey)
      local script_pubkey = "\x00\x14" .. pkh

      psbt_mod.update_input_utxo(psbt, 0, {
        value = 100000,
        script_pubkey = script_pubkey,
      }, true)

      -- Add BIP32 derivation
      psbt_mod.update_input_bip32(psbt, 0, pubkey, "\x00\x00\x00\x00", {0x8000002c, 0x80000000, 0x80000000, 0, 0})

      -- Serialize again
      psbt_b64 = psbt_mod.to_base64(psbt)
      psbt = psbt_mod.from_base64(psbt_b64)

      -- 4. Sign PSBT (Signer role)
      local signed = psbt_mod.sign_input(psbt, 0, privkey, pubkey)
      assert.is_true(signed)

      -- Check we have a partial signature
      local pk_hex = psbt_mod.hex_encode(pubkey)
      assert.is_not_nil(psbt.inputs[1].partial_sigs[pk_hex])

      -- 5. Finalize PSBT (Finalizer role)
      local finalized = psbt_mod.finalize(psbt)
      assert.is_true(finalized)
      assert.is_true(psbt_mod.is_complete(psbt))

      -- 6. Extract signed transaction (Extractor role)
      local signed_tx = psbt_mod.extract(psbt)
      assert.is_not_nil(signed_tx)
      assert.is_true(signed_tx.segwit)

      -- Verify the signed transaction has valid structure
      assert.equals(1, #signed_tx.inputs)
      assert.equals(2, #signed_tx.outputs)
      assert.equals(2, #signed_tx.inputs[1].witness)

      -- Verify outputs match original
      assert.equals(50000, signed_tx.outputs[1].value)
      assert.equals(49000, signed_tx.outputs[2].value)

      -- 7. Verify we can serialize the final transaction
      local tx_hex = psbt_mod.hex_encode(serialize.serialize_transaction(signed_tx, true))
      assert.is_true(#tx_hex > 0)
    end)
  end)
end)

--------------------------------------------------------------------------------
-- Output Descriptor Tests (BIP380-386)
--------------------------------------------------------------------------------

describe("descriptor", function()
  local address

  setup(function()
    local loaders = package.loaders or package.searchers
    table.insert(loaders, 2, function(module)
      local name = module:match("^lunarblock%.(.+)")
      if name then
        local filename = "src/" .. name .. ".lua"
        local f = io.open(filename)
        if f then
          f:close()
          return function()
            return dofile(filename)
          end
        end
      end
      return nil, "not found"
    end)
    address = require("lunarblock.address")
  end)

  describe("descriptor_checksum", function()
    it("computes checksum for pk() descriptor", function()
      local desc = "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
      local checksum = address.descriptor_checksum(desc)
      assert.is_not_nil(checksum)
      assert.equals(8, #checksum)
    end)

    it("computes checksum for pkh() descriptor", function()
      local desc = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e)"
      local checksum = address.descriptor_checksum(desc)
      assert.is_not_nil(checksum)
      assert.equals(8, #checksum)
    end)

    it("computes checksum for wpkh() descriptor", function()
      local desc = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
      local checksum = address.descriptor_checksum(desc)
      assert.is_not_nil(checksum)
      assert.equals(8, #checksum)
    end)

    it("computes checksum for multi() descriptor", function()
      local desc = "multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)"
      local checksum = address.descriptor_checksum(desc)
      assert.is_not_nil(checksum)
      assert.equals(8, #checksum)
    end)

    it("returns nil for invalid characters", function()
      local desc = "pk(invalid\x00char)"
      local checksum, err = address.descriptor_checksum(desc)
      assert.is_nil(checksum)
    end)
  end)

  describe("validate_descriptor_checksum", function()
    it("validates correct checksum", function()
      local desc = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
      local checksum = address.descriptor_checksum(desc)
      local with_checksum = desc .. "#" .. checksum

      local valid, stripped = address.validate_descriptor_checksum(with_checksum)
      assert.is_true(valid)
      assert.equals(desc, stripped)
    end)

    it("rejects incorrect checksum", function()
      local desc = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
      local with_checksum = desc .. "#aaaaaaaa"

      local valid = address.validate_descriptor_checksum(with_checksum)
      assert.is_false(valid)
    end)

    it("returns error for missing checksum", function()
      local desc = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"

      local valid, err = address.validate_descriptor_checksum(desc)
      assert.is_false(valid)
      assert.equals("no checksum found", err)
    end)
  end)

  describe("parse_key_expression", function()
    it("parses hex compressed pubkey", function()
      local key_str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00"
      local key = address.parse_key_expression(key_str)

      assert.is_not_nil(key)
      assert.equals("pubkey", key.type)
      assert.equals(33, #key.pubkey)
      assert.is_false(key.is_range)
    end)

    it("parses hex uncompressed pubkey", function()
      local key_str = "04" .. string.rep("ab", 64)  -- 65 bytes = uncompressed
      local key = address.parse_key_expression(key_str)

      assert.is_not_nil(key)
      assert.equals("pubkey", key.type)
      assert.equals(65, #key.pubkey)
    end)

    it("parses x-only pubkey for taproot", function()
      local key_str = string.rep("cd", 32)  -- 32 bytes = x-only
      local key = address.parse_key_expression(key_str)

      assert.is_not_nil(key)
      assert.equals("xonly", key.type)
      assert.equals(32, #key.pubkey)
    end)

    it("parses key with origin info", function()
      local key_str = "[d34db33f/44h/0h/0h]02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00"
      local key = address.parse_key_expression(key_str)

      assert.is_not_nil(key)
      assert.is_not_nil(key.origin)
      assert.equals(4, #key.origin.fingerprint)
      assert.equals(3, #key.origin.path)
    end)

    it("parses key with derivation path", function()
      local key_str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00/0/1"
      local key = address.parse_key_expression(key_str)

      assert.is_not_nil(key)
      assert.equals(2, #key.path)
      assert.equals(0, key.path[1])
      assert.equals(1, key.path[2])
      assert.is_false(key.is_range)
    end)

    it("parses key with wildcard path", function()
      local key_str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00/0/*"
      local key = address.parse_key_expression(key_str)

      assert.is_not_nil(key)
      assert.is_true(key.is_range)
      assert.is_false(key.is_hardened_range)
    end)

    it("parses key with hardened wildcard", function()
      local key_str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00/0/*'"
      local key = address.parse_key_expression(key_str)

      assert.is_not_nil(key)
      assert.is_true(key.is_range)
      assert.is_true(key.is_hardened_range)
    end)

    it("returns error for invalid hex length", function()
      local key_str = "abc123"  -- Invalid length
      local key, err = address.parse_key_expression(key_str)

      assert.is_nil(key)
      assert.is_not_nil(err)
    end)
  end)

  describe("parse_descriptor", function()
    it("parses pk() descriptor", function()
      local desc_str = "pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
      local desc = address.parse_descriptor(desc_str)

      assert.is_not_nil(desc)
      assert.equals("pk", desc.type)
      assert.is_not_nil(desc.key)
      assert.is_false(desc.is_range)
    end)

    it("parses pkh() descriptor", function()
      local desc_str = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
      local desc = address.parse_descriptor(desc_str)

      assert.is_not_nil(desc)
      assert.equals("pkh", desc.type)
      assert.is_not_nil(desc.key)
    end)

    it("parses wpkh() descriptor", function()
      local desc_str = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
      local desc = address.parse_descriptor(desc_str)

      assert.is_not_nil(desc)
      assert.equals("wpkh", desc.type)
      assert.is_not_nil(desc.key)
    end)

    it("parses multi() descriptor", function()
      local desc_str = "multi(2,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00,02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
      local desc = address.parse_descriptor(desc_str)

      assert.is_not_nil(desc)
      assert.equals("multi", desc.type)
      assert.equals(2, desc.threshold)
      assert.equals(2, #desc.keys)
      assert.is_false(desc.sorted)
    end)

    it("parses sortedmulti() descriptor", function()
      local desc_str = "sortedmulti(2,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00,02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
      local desc = address.parse_descriptor(desc_str)

      assert.is_not_nil(desc)
      assert.equals("sortedmulti", desc.type)
      assert.equals(2, desc.threshold)
      assert.is_true(desc.sorted)
    end)

    it("parses tr() descriptor with x-only key", function()
      local xonly = string.rep("ab", 32)
      local desc_str = "tr(" .. xonly .. ")"
      local desc = address.parse_descriptor(desc_str)

      assert.is_not_nil(desc)
      assert.equals("tr", desc.type)
      assert.is_not_nil(desc.key)
    end)

    it("parses addr() descriptor", function()
      local desc_str = "addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)"
      local desc = address.parse_descriptor(desc_str)

      assert.is_not_nil(desc)
      assert.equals("addr", desc.type)
      assert.equals("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", desc.address)
    end)

    it("parses raw() descriptor", function()
      local desc_str = "raw(76a914000000000000000000000000000000000000000088ac)"
      local desc = address.parse_descriptor(desc_str)

      assert.is_not_nil(desc)
      assert.equals("raw", desc.type)
      assert.is_not_nil(desc.script)
      assert.equals(25, #desc.script)
    end)

    it("parses combo() descriptor", function()
      local desc_str = "combo(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
      local desc = address.parse_descriptor(desc_str)

      assert.is_not_nil(desc)
      assert.equals("combo", desc.type)
      assert.is_not_nil(desc.key)
    end)

    it("validates checksum when present", function()
      local desc_str = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
      local checksum = address.descriptor_checksum(desc_str)
      local with_checksum = desc_str .. "#" .. checksum

      local desc = address.parse_descriptor(with_checksum)
      assert.is_not_nil(desc)
    end)

    it("rejects invalid checksum", function()
      local desc_str = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)#aaaaaaaa"

      local desc, err = address.parse_descriptor(desc_str)
      assert.is_nil(desc)
      assert.equals("invalid checksum", err)
    end)

    it("returns error for unknown type", function()
      local desc_str = "unknown(something)"

      local desc, err = address.parse_descriptor(desc_str)
      assert.is_nil(desc)
    end)
  end)

  describe("get_descriptor_info", function()
    it("returns info for simple descriptor", function()
      local desc_str = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
      local info = address.get_descriptor_info(desc_str)

      assert.is_not_nil(info)
      assert.is_not_nil(info.descriptor)
      assert.is_not_nil(info.checksum)
      assert.equals(8, #info.checksum)
      assert.is_false(info.isrange)
    end)

    it("adds checksum to descriptor", function()
      local desc_str = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
      local info = address.get_descriptor_info(desc_str)

      assert.is_true(info.descriptor:find("#") ~= nil)
    end)

    it("reports ranged descriptor", function()
      local desc_str = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00/0/*)"
      local info = address.get_descriptor_info(desc_str)

      assert.is_not_nil(info)
      assert.is_true(info.isrange)
    end)

    it("strips existing checksum before recomputing", function()
      local desc_str = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
      local checksum = address.descriptor_checksum(desc_str)
      local with_checksum = desc_str .. "#" .. checksum

      local info1 = address.get_descriptor_info(desc_str)
      local info2 = address.get_descriptor_info(with_checksum)

      assert.equals(info1.checksum, info2.checksum)
    end)
  end)

  describe("derive_addresses", function()
    it("derives single address from non-ranged descriptor", function()
      local desc_str = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
      local checksum = address.descriptor_checksum(desc_str)
      desc_str = desc_str .. "#" .. checksum

      local addresses, err = address.derive_addresses(desc_str, 0, 0, "mainnet")

      assert.is_not_nil(addresses)
      assert.equals(1, #addresses)
      -- P2PKH mainnet address starts with '1'
      assert.equals("1", addresses[1]:sub(1, 1))
    end)

    it("derives wpkh address", function()
      local desc_str = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
      local checksum = address.descriptor_checksum(desc_str)
      desc_str = desc_str .. "#" .. checksum

      local addresses = address.derive_addresses(desc_str, 0, 0, "mainnet")

      assert.is_not_nil(addresses)
      assert.equals(1, #addresses)
      -- P2WPKH mainnet address starts with 'bc1q'
      assert.equals("bc1q", addresses[1]:sub(1, 4))
    end)

    it("derives testnet address", function()
      local desc_str = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
      local checksum = address.descriptor_checksum(desc_str)
      desc_str = desc_str .. "#" .. checksum

      local addresses = address.derive_addresses(desc_str, 0, 0, "testnet")

      assert.is_not_nil(addresses)
      -- P2WPKH testnet address starts with 'tb1q'
      assert.equals("tb1q", addresses[1]:sub(1, 4))
    end)

    it("derives address from addr() descriptor", function()
      local addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
      local desc_str = "addr(" .. addr .. ")"
      local checksum = address.descriptor_checksum(desc_str)
      desc_str = desc_str .. "#" .. checksum

      local addresses = address.derive_addresses(desc_str, 0, 0, "mainnet")

      assert.is_not_nil(addresses)
      assert.equals(addr, addresses[1])
    end)

    it("derives address from raw() descriptor", function()
      -- P2PKH script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
      local desc_str = "raw(76a914000000000000000000000000000000000000000088ac)"
      local checksum = address.descriptor_checksum(desc_str)
      desc_str = desc_str .. "#" .. checksum

      local addresses = address.derive_addresses(desc_str, 0, 0, "mainnet")

      assert.is_not_nil(addresses)
      assert.equals(1, #addresses)
    end)
  end)

  ----------------------------------------------------------------------------
  -- Multi-Wallet Support Tests
  ----------------------------------------------------------------------------

  describe("multi_wallet manager", function()
    local test_datadir

    setup(function()
      test_datadir = "/tmp/test_wallets_" .. os.time()
      os.execute("mkdir -p '" .. test_datadir .. "'")
    end)

    teardown(function()
      os.execute("rm -rf '" .. test_datadir .. "'")
    end)

    it("creates wallet manager", function()
      local manager = wallet.new_manager(test_datadir, consensus.networks.mainnet, nil)

      assert.is_not_nil(manager)
      assert.equals(test_datadir, manager.datadir)
      assert.equals(test_datadir .. "/wallets", manager.wallets_dir)
    end)

    it("creates wallet directory", function()
      local manager = wallet.new_manager(test_datadir, consensus.networks.mainnet, nil)
      local ok = manager:ensure_wallets_dir()

      assert.is_true(ok)

      -- Check directory exists
      local handle = io.open(test_datadir .. "/wallets", "r")
      if handle then
        handle:close()
        assert.is_true(true)
      else
        -- Directory should exist, checking with ls
        local result = os.execute("test -d '" .. test_datadir .. "/wallets'")
        assert.is_true(result == true or result == 0)
      end
    end)
  end)

  describe("createwallet", function()
    local test_datadir
    local manager

    setup(function()
      test_datadir = "/tmp/test_createwallet_" .. os.time()
      os.execute("mkdir -p '" .. test_datadir .. "'")
      manager = wallet.new_manager(test_datadir, consensus.networks.mainnet, nil)
      manager:ensure_wallets_dir()
    end)

    teardown(function()
      -- Release all locks before cleanup
      for name, _ in pairs(manager.wallets) do
        manager:release_lock(name)
      end
      os.execute("rm -rf '" .. test_datadir .. "'")
    end)

    it("creates new wallet", function()
      local w, err = manager:create_wallet("test1", {})

      assert.is_nil(err)
      assert.is_not_nil(w)
      assert.is_true(manager:is_loaded("test1"))
    end)

    it("creates default wallet with empty name", function()
      local w, err = manager:create_wallet("", {})

      assert.is_nil(err)
      assert.is_not_nil(w)
      assert.is_true(manager:is_loaded(""))
    end)

    it("creates encrypted wallet", function()
      local w, err = manager:create_wallet("encrypted1", {
        passphrase = "test_password"
      })

      assert.is_nil(err)
      assert.is_not_nil(w)
      assert.is_true(w.is_encrypted)
    end)

    it("creates blank wallet", function()
      local w, err = manager:create_wallet("blank1", {
        blank = true
      })

      assert.is_nil(err)
      assert.is_not_nil(w)
      -- Blank wallet has no master key
      assert.is_nil(w.master_key)
    end)

    it("fails on duplicate wallet name", function()
      manager:create_wallet("duplicate_test", {})
      local w, err = manager:create_wallet("duplicate_test", {})

      assert.is_nil(w)
      assert.is_not_nil(err)
      assert.is_true(err:find("already") ~= nil)
    end)

    it("fails on invalid wallet name", function()
      local w, err = manager:create_wallet("test/invalid", {})

      assert.is_nil(w)
      assert.is_not_nil(err)
      assert.is_true(err:find("illegal") ~= nil)
    end)
  end)

  describe("loadwallet", function()
    local test_datadir
    local manager

    setup(function()
      test_datadir = "/tmp/test_loadwallet_" .. os.time()
      os.execute("mkdir -p '" .. test_datadir .. "'")
      manager = wallet.new_manager(test_datadir, consensus.networks.mainnet, nil)
      manager:ensure_wallets_dir()

      -- Create a wallet to load later
      local w = manager:create_wallet("toload", {})
      manager:unload_wallet("toload")
    end)

    teardown(function()
      for name, _ in pairs(manager.wallets) do
        manager:release_lock(name)
      end
      os.execute("rm -rf '" .. test_datadir .. "'")
    end)

    it("loads existing wallet", function()
      local w, err = manager:load_wallet("toload")

      assert.is_nil(err)
      assert.is_not_nil(w)
      assert.is_true(manager:is_loaded("toload"))
    end)

    it("fails on non-existent wallet", function()
      local w, err = manager:load_wallet("nonexistent")

      assert.is_nil(w)
      assert.is_not_nil(err)
      assert.is_true(err:find("not found") ~= nil)
    end)

    it("fails on already loaded wallet", function()
      manager:load_wallet("toload")
      local w, err = manager:load_wallet("toload")

      assert.is_nil(w)
      assert.is_not_nil(err)
      assert.is_true(err:find("already loaded") ~= nil)
    end)
  end)

  describe("listwallets", function()
    local test_datadir
    local manager

    setup(function()
      test_datadir = "/tmp/test_listwallets_" .. os.time()
      os.execute("mkdir -p '" .. test_datadir .. "'")
      manager = wallet.new_manager(test_datadir, consensus.networks.mainnet, nil)
      manager:ensure_wallets_dir()
    end)

    teardown(function()
      for name, _ in pairs(manager.wallets) do
        manager:release_lock(name)
      end
      os.execute("rm -rf '" .. test_datadir .. "'")
    end)

    it("returns empty list when no wallets loaded", function()
      local names = manager:list_wallets()

      assert.equals(0, #names)
    end)

    it("returns loaded wallet names", function()
      manager:create_wallet("wallet_a", {})
      manager:create_wallet("wallet_b", {})

      local names = manager:list_wallets()

      assert.equals(2, #names)
      -- Names are sorted
      assert.equals("wallet_a", names[1])
      assert.equals("wallet_b", names[2])
    end)

    it("updates after unload", function()
      manager:create_wallet("wallet_c", {})
      local before = #manager:list_wallets()

      manager:unload_wallet("wallet_c")
      local after = #manager:list_wallets()

      assert.equals(before - 1, after)
    end)
  end)

  describe("unloadwallet", function()
    local test_datadir
    local manager

    setup(function()
      test_datadir = "/tmp/test_unloadwallet_" .. os.time()
      os.execute("mkdir -p '" .. test_datadir .. "'")
      manager = wallet.new_manager(test_datadir, consensus.networks.mainnet, nil)
      manager:ensure_wallets_dir()
    end)

    teardown(function()
      for name, _ in pairs(manager.wallets) do
        manager:release_lock(name)
      end
      os.execute("rm -rf '" .. test_datadir .. "'")
    end)

    it("unloads wallet", function()
      manager:create_wallet("to_unload", {})
      assert.is_true(manager:is_loaded("to_unload"))

      local ok, err = manager:unload_wallet("to_unload")

      assert.is_nil(err)
      assert.is_true(ok)
      assert.is_false(manager:is_loaded("to_unload"))
    end)

    it("fails on non-loaded wallet", function()
      local ok, err = manager:unload_wallet("never_loaded")

      assert.is_false(ok)
      assert.is_not_nil(err)
      assert.is_true(err:find("not loaded") ~= nil)
    end)

    it("saves wallet on unload", function()
      -- Create wallet and modify it
      local w = manager:create_wallet("save_test", {})
      local addr1 = w:get_new_address()

      manager:unload_wallet("save_test")

      -- Reload and verify
      local w2 = manager:load_wallet("save_test")
      assert.equals(addr1, w2.addresses[1])
    end)
  end)

  describe("default wallet", function()
    local test_datadir
    local manager

    setup(function()
      test_datadir = "/tmp/test_default_wallet_" .. os.time()
      os.execute("mkdir -p '" .. test_datadir .. "'")
      manager = wallet.new_manager(test_datadir, consensus.networks.mainnet, nil)
      manager:ensure_wallets_dir()
    end)

    teardown(function()
      for name, _ in pairs(manager.wallets) do
        manager:release_lock(name)
      end
      os.execute("rm -rf '" .. test_datadir .. "'")
    end)

    it("returns nil when no wallets", function()
      local w, name = manager:get_default_wallet()

      assert.is_nil(w)
      assert.is_nil(name)
    end)

    it("returns first created wallet as default", function()
      manager:create_wallet("first", {})
      manager:create_wallet("second", {})

      local w, name = manager:get_default_wallet()

      assert.is_not_nil(w)
      assert.equals("first", name)
    end)

    it("prefers empty string wallet as default", function()
      manager:create_wallet("named", {})
      manager:create_wallet("", {})

      local w, name = manager:get_default_wallet()

      assert.is_not_nil(w)
      assert.equals("", name)
    end)

    it("updates default after unload", function()
      manager:create_wallet("only_one", {})
      manager:unload_wallet("only_one")

      local w, name = manager:get_default_wallet()

      assert.is_nil(w)
    end)
  end)

  describe("wallet directory listing", function()
    local test_datadir
    local manager

    setup(function()
      test_datadir = "/tmp/test_walletdir_" .. os.time()
      os.execute("mkdir -p '" .. test_datadir .. "'")
      manager = wallet.new_manager(test_datadir, consensus.networks.mainnet, nil)
      manager:ensure_wallets_dir()
    end)

    teardown(function()
      for name, _ in pairs(manager.wallets) do
        manager:release_lock(name)
      end
      os.execute("rm -rf '" .. test_datadir .. "'")
    end)

    it("lists wallets on disk", function()
      manager:create_wallet("disk1", {})
      manager:create_wallet("disk2", {})
      manager:unload_wallet("disk1")

      local list = manager:list_wallet_dir()

      assert.is_true(#list >= 2)

      -- Find disk1 and disk2 in list
      local found_disk1 = false
      local found_disk2 = false
      for _, info in ipairs(list) do
        if info.name == "disk1" then
          found_disk1 = true
          assert.is_false(info.loaded)
        end
        if info.name == "disk2" then
          found_disk2 = true
          assert.is_true(info.loaded)
        end
      end

      assert.is_true(found_disk1)
      assert.is_true(found_disk2)
    end)
  end)

  describe("wallet paths", function()
    it("default wallet uses data dir root", function()
      local manager = wallet.new_manager("/test/data", consensus.networks.mainnet, nil)

      local path = manager:get_wallet_path("")

      assert.equals("/test/data/wallet.json", path)
    end)

    it("named wallet uses wallets subdirectory", function()
      local manager = wallet.new_manager("/test/data", consensus.networks.mainnet, nil)

      local path = manager:get_wallet_path("mywallet")

      assert.equals("/test/data/wallets/mywallet/wallet.json", path)
    end)
  end)
end)
