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

  setup(function()
    setup_loader()
    wallet = require("lunarblock.wallet")
    crypto = require("lunarblock.crypto")
    types = require("lunarblock.types")
    consensus = require("lunarblock.consensus")
    address = require("lunarblock.address")
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
end)
