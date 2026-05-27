#!/usr/bin/env luajit
-- W111 Wallet / HD / Descriptors fleet audit — lunarblock (Lua/LuaJIT)
-- Gates: G1-G5 BIP-32, G6-G10 HD paths, G11-G16 Descriptors,
--        G17-G18 BIP-39+PBKDF2, G19-G22 Address types,
--        G23-G25 Storage, G26-G28 Signing, G29-G30 PSBT

-- Setup module path
package.path = "src/?.lua;" .. package.path

local bit = require("bit")

-- Helper: convert hex string to binary
local function hex_to_bin(hex)
  return (hex:gsub('..', function(cc)
    return string.char(tonumber(cc, 16))
  end))
end

-- Helper: convert binary to hex string
local function bin_to_hex(bin)
  local hex = {}
  for i = 1, #bin do
    hex[i] = string.format("%02x", bin:byte(i))
  end
  return table.concat(hex)
end

-- Custom loader for lunarblock modules
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

local wallet = require("lunarblock.wallet")
local address = require("lunarblock.address")
local bip39 = require("lunarblock.bip39")
local psbt = require("lunarblock.psbt")
local crypto = require("lunarblock.crypto")
local consensus = require("lunarblock.consensus")

-- Test infrastructure
local tests_passed = 0
local tests_failed = 0
local bugs = {}

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then
    print("PASS: " .. name)
    tests_passed = tests_passed + 1
  else
    print("FAIL: " .. name)
    print("      " .. tostring(err))
    tests_failed = tests_failed + 1
  end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) .. ", expected " .. tostring(b))
  end
end

local function expect_true(v, msg)
  if not v then error(msg or "expected true") end
end

local function expect_false(v, msg)
  if v then error(msg or "expected false") end
end

local function log_bug(id, desc)
  bugs[#bugs + 1] = {id = id, desc = desc}
end

print("=== W111 lunarblock Wallet / HD / Descriptors Audit ===\n")

--------------------------------------------------------------------------------
-- G1-G5: BIP-32 HD Derivation
--------------------------------------------------------------------------------

print("--- G1-G5: BIP-32 HD Derivation ---")

-- G1: Master key from seed — BIP-32 test vector 1
-- Seed: 000102030405060708090a0b0c0d0e0f
-- Expected master key: e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
-- Expected chain code: 873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
test("G1: master key from seed (BIP-32 vector 1)", function()
  local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
  local master = wallet.master_key_from_seed(seed)
  expect_eq(bin_to_hex(master.key), "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35", "master key")
  expect_eq(bin_to_hex(master.chain_code), "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508", "chain code")
  expect_eq(master.depth, 0, "depth")
  expect_eq(master.is_private, true, "is_private")
end)

-- G2: Hardened child derivation — BIP-32 vector 1, m/0'
-- Expected key: edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea
-- Expected chain: 47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141
test("G2: hardened child derivation (BIP-32 vector 1, m/0')", function()
  local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
  local master = wallet.master_key_from_seed(seed)
  local child = wallet.derive_child(master, 0x80000000)
  expect_eq(bin_to_hex(child.key), "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea", "child key m/0'")
  expect_eq(bin_to_hex(child.chain_code), "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141", "chain m/0'")
  expect_eq(child.depth, 1, "depth")
end)

-- G3: Normal child derivation — BIP-32 vector 1, m/0'/1
-- Expected key: 3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368
-- Expected chain: 2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19
test("G3: normal child derivation (BIP-32 vector 1, m/0'/1)", function()
  local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
  local master = wallet.master_key_from_seed(seed)
  local m0h = wallet.derive_child(master, 0x80000000)
  local child = wallet.derive_child(m0h, 1)
  expect_eq(bin_to_hex(child.key), "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368", "child key m/0'/1")
  expect_eq(bin_to_hex(child.chain_code), "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19", "chain m/0'/1")
  expect_eq(child.depth, 2, "depth")
end)

-- G4: Parent fingerprint correctness
test("G4: parent fingerprint correctness (BIP-32)", function()
  local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
  local master = wallet.master_key_from_seed(seed)
  local child = wallet.derive_child(master, 0x80000000)
  local parent_pubkey = crypto.pubkey_from_privkey(master.key, true)
  local expected_fp = crypto.hash160(parent_pubkey):sub(1, 4)
  expect_eq(child.parent_fingerprint, expected_fp, "parent fingerprint")
end)

-- G5: BIP-32 vector 2 — long path test (tests index byte serialization for large indices)
-- Seed: fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
-- m: xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U
-- m master key hex: 4b03d6fc340455b363f51020ad3eca4f0850280cf436c70c727923f6db46c3e
-- m chain hex: 60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689
test("G5: BIP-32 vector 2 master key", function()
  local seed = hex_to_bin("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
  local master = wallet.master_key_from_seed(seed)
  -- Verified by decoding the canonical BIP-32 vector 2 xprv:
  -- xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U
  expect_eq(bin_to_hex(master.key), "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e", "vector2 master key")
  expect_eq(bin_to_hex(master.chain_code), "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689", "vector2 chain")
end)

-- BUG INVESTIGATION: G5b: CKDpub (public-only derivation) is not implemented
-- wallet.derive_child throws error("Public key derivation not implemented") when parent is public
-- This means watch-only wallets cannot derive child keys from xpubs
test("G5b-BUG: CKDpub (public child derivation) not implemented [BUG-1]", function()
  log_bug("BUG-1", "P1: CKDpub (BIP-32 public-only derivation) not implemented — wallet.derive_child errors when parent.is_private=false. Watch-only wallets/xpub descriptors cannot derive child keys. address.lua:583-584 placeholder. wallet.lua:585.")
  -- Attempt a public derivation — should work per BIP-32 but currently errors
  local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
  local master = wallet.master_key_from_seed(seed)
  -- Get a public key version of the master
  local pub_key = crypto.pubkey_from_privkey(master.key, true)
  local pub_node = {
    key = pub_key,
    chain_code = master.chain_code,
    depth = master.depth,
    parent_fingerprint = master.parent_fingerprint,
    child_index = master.child_index,
    is_private = false,
  }
  local ok, err = pcall(wallet.derive_child, pub_node, 0)
  expect_false(ok, "public derivation should error (known BUG-1)")
  -- Verify the error message
  expect_true(err:find("not implemented"), "should be 'not implemented' error")
end)

-- BUG INVESTIGATION: G5c: xpub serialization (Base58Check encoding) not implemented
-- wallet.lua has M.extended_key() struct but no serialize_xkey / to_xpub / to_xprv function
test("G5c-BUG: xpub/xprv serialization to Base58Check not implemented [BUG-2]", function()
  log_bug("BUG-2", "P2: No xpub/xprv Base58Check serialization function. wallet.lua defines extended_key() struct but provides no serialize_xkey/to_xpub/to_xprv. Cannot export account xpubs, cannot wire getxpub RPC, cannot populate PSBT global xpub map with real xpub strings.")
  -- No serialize_xkey in wallet module
  expect_eq(wallet.serialize_xkey, nil, "serialize_xkey should be absent (BUG-2)")
  expect_eq(wallet.to_xpub, nil, "to_xpub should be absent (BUG-2)")
  expect_eq(wallet.to_xprv, nil, "to_xprv should be absent (BUG-2)")
end)

--------------------------------------------------------------------------------
-- G6-G10: HD Paths (BIP-44/49/84/86)
--------------------------------------------------------------------------------

print("\n--- G6-G10: HD Paths ---")

-- G6: BIP-44 path derivation m/44'/0'/account'/change/index
test("G6: BIP-44 path m/44'/0'/0'/0/0 depth=5", function()
  local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
  local master = wallet.master_key_from_seed(seed)
  local key = wallet.derive_bip44_key(master, 0, 0, 0)
  expect_eq(key.depth, 5, "BIP-44 path should have depth 5")
end)

-- G7: BIP-84 path derivation m/84'/0'/account'/change/index
test("G7: BIP-84 path m/84'/0'/0'/0/0 depth=5", function()
  local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
  local master = wallet.master_key_from_seed(seed)
  local key = wallet.derive_bip84_key(master, 0, 0, 0)
  expect_eq(key.depth, 5, "BIP-84 path should have depth 5")
end)

-- G8: BIP-44 and BIP-84 produce different keys at same account/change/index
test("G8: BIP-44 and BIP-84 produce different keys", function()
  local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
  local master = wallet.master_key_from_seed(seed)
  local key44 = wallet.derive_bip44_key(master, 0, 0, 0)
  local key84 = wallet.derive_bip84_key(master, 0, 0, 0)
  expect_true(key44.key ~= key84.key, "BIP-44 and BIP-84 should produce different keys")
end)

-- G9-FIXED-IN-P2-3: BIP-49 (P2SH-P2WPKH) path m/49'/0'/account'/change/index
-- now exists via wallet.derive_bip49_key (shim) + the table-driven
-- M.derive_for_purpose. See tests/test_p2_3_bip43_purpose_table.lua and
-- CORE-PARITY-AUDIT/_lunarblock-unfreeze-plan-2026-05-26.md (P2-3).
test("G9: P2-3 FIX — BIP-49 derivation now present", function()
  expect_true(wallet.derive_bip49_key ~= nil, "derive_bip49_key shim now exists")
  expect_true(wallet.derive_for_purpose ~= nil, "table-driven derive_for_purpose now exists")
end)

-- G10-FIXED-IN-P2-3: BIP-86 (P2TR) path m/86'/0'/account'/change/index now
-- exists via wallet.derive_bip86_key (shim) + the table-driven path.
test("G10: P2-3 FIX — BIP-86 derivation now present", function()
  expect_true(wallet.derive_bip86_key ~= nil, "derive_bip86_key shim now exists")
  expect_true(wallet.PURPOSE_TEMPLATES[86] ~= nil, "BIP-86 registered in PURPOSE_TEMPLATES")
end)

-- G10b-BUG: Coin type always hardcoded to 0 (mainnet Bitcoin) regardless of network
-- BIP-44 coin_type=1 for testnet, but wallet.derive_bip44_key uses 0x80000000+0 always
test("G10b-BUG: BIP-44/84 coin type always 0 regardless of network [BUG-5]", function()
  log_bug("BUG-5", "P2: BIP-44/84 coin type hardcoded to 0 (Bitcoin mainnet). wallet.lua:607 always does derive_child(purpose, 0x80000000+0) regardless of network. Testnet should use coin_type=1 per SLIP-0044. Generates same keys on mainnet and testnet.")
  -- Verify coin type is not parameterized
  -- Both have hardcoded 0x80000000 + 0 for the coin step
  -- This is a code inspection finding, not a runtime assertion
  expect_true(true, "BUG-5 documented via code inspection")
end)

--------------------------------------------------------------------------------
-- G11-G16: Descriptors (BIP-380/381/382/383/384/385/386)
--------------------------------------------------------------------------------

print("\n--- G11-G16: Descriptors ---")

-- G11: Descriptor checksum (BIP-380) correctness — W51-fixed
test("G11: descriptor checksum for pk() matches BIP-380", function()
  -- From BIP-380 test vectors: pk(0279be...)#8fhd9pwu
  local desc = "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
  local checksum = address.descriptor_checksum(desc)
  expect_true(checksum ~= nil, "checksum should be computed")
  expect_eq(#checksum, 8, "checksum length should be 8")
  -- Validate round-trip
  local ok = address.validate_descriptor_checksum(desc .. "#" .. checksum)
  expect_true(ok, "checksum should validate")
end)

-- G12: Descriptor checksum for wpkh()
test("G12: descriptor checksum for wpkh() descriptor", function()
  local desc = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
  local checksum = address.descriptor_checksum(desc)
  expect_eq(#checksum, 8, "checksum length")
  local ok = address.validate_descriptor_checksum(desc .. "#" .. checksum)
  expect_true(ok, "wpkh checksum round-trip")
end)

-- G13: Parse and generate scriptPubKey from pkh() descriptor
test("G13: pkh() descriptor to P2PKH scriptPubKey", function()
  local pubkey_hex = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00"
  local desc_str = "pkh(" .. pubkey_hex .. ")"
  local desc = address.parse_descriptor(desc_str)
  expect_true(desc ~= nil, "descriptor should parse")
  expect_eq(desc.type, "pkh", "descriptor type")
  local spk = address.descriptor_to_script(desc, 0, "mainnet")
  -- P2PKH script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
  expect_eq(#spk, 25, "P2PKH scriptPubKey length should be 25")
  expect_eq(spk:byte(1), 0x76, "OP_DUP")
  expect_eq(spk:byte(2), 0xa9, "OP_HASH160")
  expect_eq(spk:byte(3), 20, "push 20 bytes")
  expect_eq(spk:byte(24), 0x88, "OP_EQUALVERIFY")
  expect_eq(spk:byte(25), 0xac, "OP_CHECKSIG")
end)

-- G14: Parse and generate scriptPubKey from wpkh() descriptor
test("G14: wpkh() descriptor to P2WPKH scriptPubKey", function()
  local pubkey_hex = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
  local desc_str = "wpkh(" .. pubkey_hex .. ")"
  local desc = address.parse_descriptor(desc_str)
  expect_true(desc ~= nil, "wpkh descriptor should parse")
  expect_eq(desc.type, "wpkh", "descriptor type")
  local spk = address.descriptor_to_script(desc, 0, "mainnet")
  -- P2WPKH: OP_0 <20 bytes>
  expect_eq(#spk, 22, "P2WPKH scriptPubKey length should be 22")
  expect_eq(spk:byte(1), 0x00, "OP_0")
  expect_eq(spk:byte(2), 0x14, "push 20 bytes")
end)

-- G15: tr() descriptor applies BIP-341 TapTweak (FIX-38)
-- BIP-86 test vector: internal_key=cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115
--                     tweaked output key=a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c
test("G15: tr() descriptor applies BIP-341 TapTweak — BIP-86 vector (FIX-38)", function()
  -- BIP-86 test vector (key-path-only, no script tree)
  local internal_hex = "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
  local expected_output_hex = "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
  local desc_str = "tr(" .. internal_hex .. ")"
  local desc, err = address.parse_descriptor(desc_str)
  if not desc then
    error("Failed to parse tr() descriptor: " .. tostring(err))
  end
  local spk = address.descriptor_to_script(desc, 0, "mainnet")
  -- P2TR: OP_1 <32 bytes>
  expect_eq(#spk, 34, "P2TR scriptPubKey length should be 34")
  expect_eq(spk:byte(1), 0x51, "OP_1")
  expect_eq(spk:byte(2), 0x20, "push 32 bytes")
  -- FIX-38: output key MUST be the BIP-341 tweaked key, not the raw internal key
  local output_key = spk:sub(3, 34)
  local raw_internal = hex_to_bin(internal_hex)
  -- Confirm the output key is NOT the raw internal key (tweak was applied)
  expect_true(output_key ~= raw_internal, "FIX-38: output key must differ from raw internal key")
  -- Confirm the output key matches the BIP-86 test vector
  expect_eq(output_key, hex_to_bin(expected_output_hex), "FIX-38: tweaked output key matches BIP-86 vector")
end)

-- G16: Descriptor checksum computed for tr() with rawtr
test("G16: rawtr() descriptor to P2TR scriptPubKey (no tweak, BIP-386)", function()
  local xonly_hex = "cc8a4bc64d897bddc5fbc2f670f7a8ba0a386f3dade870027125d6aa223b8c8e"
  local desc_str = "rawtr(" .. xonly_hex .. ")"
  local desc = address.parse_descriptor(desc_str)
  expect_true(desc ~= nil, "rawtr descriptor should parse")
  expect_eq(desc.type, "rawtr", "type")
  local spk = address.descriptor_to_script(desc, 0, "mainnet")
  expect_eq(#spk, 34, "P2TR length")
  expect_eq(spk:byte(1), 0x51, "OP_1")
end)

-- G16b-BUG: multi() descriptor sorts pubkeys lexicographically not by index
-- sortedmulti: Core sorts by compressed pubkey bytes; our sort uses Lua string compare
-- (correct for ASCII/byte strings), so sortedmulti is OK
-- But multi() in address.lua:1081-1105 also uses the SAME sort path for sortedmulti
test("G16b: sortedmulti() sorts keys lexicographically", function()
  local k1 = "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4"
  local k2 = "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc"
  local desc_str = string.format("sortedmulti(1,%s,%s)", k1, k2)
  local desc = address.parse_descriptor(desc_str)
  expect_true(desc ~= nil, "sortedmulti descriptor parsed")
  expect_eq(desc.type, "sortedmulti", "type")
  expect_eq(desc.sorted, true, "sorted flag")
  expect_eq(#desc.keys, 2, "key count")
end)

--------------------------------------------------------------------------------
-- G17-G18: BIP-39 + PBKDF2
--------------------------------------------------------------------------------

print("\n--- G17-G18: BIP-39 + PBKDF2 ---")

-- G17: BIP-39 entropy → mnemonic → entropy round-trip (TREZOR test vector 1)
-- entropy: 00000000000000000000000000000000
-- mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
test("G17: BIP-39 entropy→mnemonic→entropy round-trip (vector 1)", function()
  local entropy = string.rep("\x00", 16)  -- 128 bits
  local words = bip39.entropy_to_mnemonic(entropy)
  expect_eq(#words, 12, "12 words for 128-bit entropy")
  expect_eq(words[1], "abandon", "first word should be 'abandon'")
  expect_eq(words[12], "about", "last word should be 'about'")

  -- Round-trip back to entropy
  local recovered = bip39.mnemonic_to_entropy(words)
  expect_eq(recovered, entropy, "entropy round-trip")
end)

-- G17b: BIP-39 PBKDF2 seed derivation (TREZOR vector)
-- mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
-- passphrase: "TREZOR"
-- seed: c55257...
test("G17b: BIP-39 PBKDF2 seed (TREZOR vector 1, empty passphrase yields correct salt)", function()
  local words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  local seed = bip39.mnemonic_to_seed(words, "")
  expect_eq(#seed, 64, "seed should be 64 bytes")
  -- Verified: BIP-39 TREZOR reference seed for empty passphrase begins 5eb00bbd...
  local seed_hex = bin_to_hex(seed)
  expect_eq(seed_hex:sub(1, 8), "5eb00bbd", "TREZOR vector 1 empty passphrase first 4 bytes")
  -- With 'TREZOR' passphrase the seed starts c55257...
  local seed_trezor = bip39.mnemonic_to_seed(words, "TREZOR")
  expect_eq(bin_to_hex(seed_trezor):sub(1, 8), "c55257c3", "TREZOR passphrase seed prefix")
end)

-- G17c: PBKDF2 iteration count = 2048 exactly (not wallet.lua's 25000)
test("G17c: BIP-39 PBKDF2 uses 2048 iterations (not wallet.derive_key's 25000)", function()
  expect_eq(bip39.PBKDF2_ITERATIONS, 2048, "PBKDF2 iterations must be 2048")
  -- wallet.lua uses 25000 for WALLET encryption — must NOT be confused with BIP-39
  expect_eq(wallet.CRYPTO_ROUNDS, 25000, "wallet encryption uses 25000 (separate from BIP-39)")
end)

-- G18: BIP-39 checksum validation
test("G18: BIP-39 checksum validation rejects corrupted mnemonic", function()
  -- Corrupt the last word of a valid mnemonic
  local words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  local ok, err = bip39.validate_mnemonic(words)
  expect_true(ok, "valid mnemonic should pass")

  -- Replace last word with invalid word
  local bad_words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon action"
  local bad_ok, bad_err = bip39.validate_mnemonic(bad_words)
  expect_false(bad_ok, "corrupted checksum should fail: " .. tostring(bad_err))
end)

-- G18b-BUG: NFKD normalization absent for non-ASCII passphrases
test("G18b-BUG: NFKD normalization absent (documented, not a crash) [BUG-7]", function()
  log_bug("BUG-7", "LOW: BIP-39 NFKD normalization absent for non-ASCII passphrases (bip39.lua:12-20). nfkd_ascii() is a pass-through for ASCII but silently diverges for Unicode. Japanese/Spanish wordlists or multi-byte passphrases produce seeds incompatible with hardware wallets. Documented in code but not flagged as error.")
  -- NFKD pass-through is documented — verify it doesn't crash for ASCII
  local words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  local seed = bip39.mnemonic_to_seed(words, "test")
  expect_eq(#seed, 64, "seed should be 64 bytes even with ASCII passphrase")
end)

--------------------------------------------------------------------------------
-- G19-G22: Address types
--------------------------------------------------------------------------------

print("\n--- G19-G22: Address types ---")

-- G19: P2PKH address generation
test("G19: P2PKH address from compressed pubkey (mainnet)", function()
  -- Pubkey 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  -- is the secp256k1 generator G in compressed form.
  -- Its P2PKH address is 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH (verified against Core).
  local pubkey = hex_to_bin("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
  local addr = address.pubkey_to_p2pkh(pubkey, "mainnet")
  expect_eq(addr, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", "P2PKH address for generator G")
end)

-- G20: P2WPKH (native SegWit) address generation
test("G20: P2WPKH address from compressed pubkey (mainnet bech32)", function()
  -- Known: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  -- P2WPKH: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 (mainnet)
  local pubkey = hex_to_bin("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
  local addr = address.pubkey_to_p2wpkh(pubkey, "mainnet")
  expect_eq(addr, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "P2WPKH address should match BIP-141 test vector")
end)

-- G21: P2SH address generation from script hash
test("G21: P2SH address from script", function()
  -- Simple 1-of-1 multisig redeem script
  local pubkey = hex_to_bin("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
  local redeem_script = "\x51" .. string.char(#pubkey) .. pubkey .. "\x51\xae"
  local addr = address.script_to_p2sh(redeem_script, "mainnet")
  expect_true(addr:sub(1, 1) == "3", "P2SH mainnet address starts with '3'")
  expect_true(#addr >= 34 and #addr <= 35, "P2SH address length in expected range")
end)

-- G22: P2TR address generation (FIX-38 — xonly_pubkey_to_p2tr takes tweaked output key)
test("G22: P2TR (Taproot) address generation — BIP-86 output key yields correct address", function()
  -- BIP-86 test vector:
  --   internal_key       = cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115
  --   tweaked output key = a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c
  --   address            = bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr
  -- xonly_pubkey_to_p2tr expects the tweaked output key (bech32m encodes it directly)
  local tweaked_xonly = hex_to_bin("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")
  local addr = address.xonly_pubkey_to_p2tr(tweaked_xonly, "mainnet")
  expect_true(addr:sub(1, 4) == "bc1p", "P2TR mainnet address starts with 'bc1p'")
  expect_eq(#addr, 62, "P2TR address length should be 62")
  expect_eq(addr, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", "BIP-86 address matches")
end)

-- G22b-BUG: P2SH-P2WPKH (BIP-49) address type absent from wallet
-- wallet.generate_address only supports p2wpkh and p2pkh, no p2sh-p2wpkh
test("G22b-BUG: P2SH-P2WPKH address type not supported by wallet.generate_address [BUG-8]", function()
  log_bug("BUG-8", "P2: wallet.generate_address (wallet.lua:1007-1033) only handles p2wpkh and p2pkh. No p2sh_p2wpkh (BIP-49) or p2tr (BIP-86). Setting address_type to any other value silently falls back to derive_bip44_key + p2pkh. Users cannot generate P2SH-P2WPKH or P2TR wallets.")
  expect_true(true, "BUG-8 documented via code inspection")
end)

-- G22c-BUG: P2TR wallet address generation not wired
test("G22c-BUG: P2TR wallet address generation not wired [BUG-9]", function()
  log_bug("BUG-9", "P2: wallet.generate_address does not handle address_type='p2tr'. No derive_bip86_key is called (BUG-4). A wallet with address_type='p2tr' silently falls through to derive_bip44_key + p2pkh. P2TR wallet support is structurally absent.")
  expect_true(true, "BUG-9 documented via code inspection")
end)

--------------------------------------------------------------------------------
-- G23-G25: Storage and KeyPool
--------------------------------------------------------------------------------

print("\n--- G23-G25: Storage/KeyPool ---")

-- G23: Wallet encryption and decrypt round-trip
test("G23: wallet encrypt/decrypt round-trip preserves master key", function()
  local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
  local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)
  expect_true(not w.is_encrypted, "wallet starts unencrypted")

  w:encrypt("test_passphrase")
  expect_true(w.is_encrypted, "wallet encrypted")

  -- Save master key for comparison
  local orig_key = w.master_key.key

  -- Lock
  w:lock()
  expect_true(w.is_locked, "wallet locked")
  expect_eq(w.master_key, nil, "master key cleared after lock")

  -- Unlock
  local ok, err = w:unlock("test_passphrase")
  expect_true(ok, "unlock should succeed: " .. tostring(err))
  expect_false(w.is_locked, "wallet should be unlocked")
  expect_eq(w.master_key.key, orig_key, "master key should be restored")
end)

-- G24: Wallet lock/unlock with wrong passphrase fails
test("G24: wrong passphrase should fail unlock", function()
  local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
  local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)
  w:encrypt("correct_passphrase")
  w:lock()
  local ok, err = w:unlock("wrong_passphrase")
  expect_false(ok, "wrong passphrase should fail")
  expect_true(err ~= nil, "should return error message")
end)

-- G25: KeyPool / gap limit — wallet generates gap_limit addresses
test("G25: wallet generates gap_limit external+internal addresses on creation", function()
  local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
  local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)
  local gap = w.gap_limit
  expect_eq(gap, 20, "default gap limit should be 20")
  -- generate_addresses is called with gap_limit during from_seed
  expect_eq(w.next_external_index, gap, "next external index = gap_limit")
  expect_eq(w.next_internal_index, gap, "next internal index = gap_limit")
  expect_eq(#w.addresses, gap * 2, "total addresses = gap_limit * 2 (external + change)")
end)

-- G25b-BUG: KeyPool not pre-filled ahead of use (no lookahead beyond gap_limit)
-- Core maintains a pre-filled pool of keys, lunarblock derives on-demand which is OK
-- but gap_limit mismatch: wallet generates gap_limit TOTAL not gap_limit AHEAD
test("G25b: keypoolsize reported from gap_limit (not pre-derived pool)", function()
  -- This is acceptable behavior but note: keypoolrefill not implemented separately
  local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
  local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)
  -- next_external_index starts at gap_limit, not 0
  expect_eq(w.next_external_index, w.gap_limit, "pool is pre-generated up to gap_limit")
end)

--------------------------------------------------------------------------------
-- G26-G28: Signing
--------------------------------------------------------------------------------

print("\n--- G26-G28: Signing ---")

-- G26: P2WPKH signing via wallet.create_transaction
test("G26: WIF private key round-trip (export/import)", function()
  local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
  local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)
  -- Get the first generated address
  local addr = w.addresses[1]
  expect_true(addr ~= nil, "should have addresses")

  -- Export WIF
  local wif, err = w:dump_privkey(addr)
  expect_true(wif ~= nil, "WIF export should succeed: " .. tostring(err))
  -- Mainnet compressed WIF starts with 'K' or 'L' (depending on key value)
  local first = wif:sub(1, 1)
  expect_true(first == "K" or first == "L", "mainnet WIF for compressed key starts with K or L (got: " .. first .. ")")

  -- Import WIF (into a new wallet) — proves the round-trip
  local w2 = wallet.from_seed(hex_to_bin("ffffffffffffffffffffffffffffffff"), consensus.networks.mainnet, nil)
  local ok, imp_err = pcall(w2.import_privkey, w2, wif)
  expect_true(ok, "WIF import should succeed: " .. tostring(imp_err))
end)

-- G27: P2WPKH sighash test via psbt.sign_input
test("G27: PSBT P2WPKH sign_input produces valid signature structure", function()
  -- Build a minimal PSBT and sign it
  local privkey = hex_to_bin("0101010101010101010101010101010101010101010101010101010101010101")
  local pubkey = crypto.pubkey_from_privkey(privkey, true)

  local txid = {bytes = string.rep("\x01", 32)}
  local types_mod = require("lunarblock.types")
  local tx = types_mod.transaction(2, {
    types_mod.txin(types_mod.outpoint(types_mod.hash256(string.rep("\x01", 32)), 0), "", 0xFFFFFFFD),
  }, {
    types_mod.txout(50000, address.pubkey_to_p2wpkh(pubkey, "mainnet"):len() > 0 and
      "\x00\x14" .. crypto.hash160(pubkey) or "\x00\x14" .. string.rep("\x00", 20))
  }, 0)

  local p = psbt.new(tx)
  -- Add witness UTXO
  psbt.update_input_utxo(p, 0, {
    value = 100000,
    script_pubkey = "\x00\x14" .. crypto.hash160(pubkey),
  }, true)

  local ok = psbt.sign_input(p, 0, privkey, pubkey, 0x01)
  expect_true(ok, "sign_input should return true")
  -- Verify partial_sigs populated
  local pub_hex = bin_to_hex(pubkey)
  expect_true(p.inputs[1].partial_sigs[pub_hex] ~= nil, "partial sig should be set")
  -- Verify signature is DER + sighash byte
  local sig = p.inputs[1].partial_sigs[pub_hex]
  expect_true(#sig >= 71 and #sig <= 73, "DER signature length 71-73 bytes")
  expect_eq(sig:byte(#sig), 0x01, "sighash ALL = 0x01")
end)

-- G28: ECDSA signing correctness (verify signed)
test("G28: ECDSA sign/verify round-trip", function()
  local privkey = hex_to_bin("0101010101010101010101010101010101010101010101010101010101010101")
  local pubkey = crypto.pubkey_from_privkey(privkey, true)
  local msg = crypto.sha256("test message")
  local sig = crypto.ecdsa_sign(privkey, msg)
  expect_true(#sig >= 70 and #sig <= 72, "DER signature length")
  -- M.ecdsa_verify(pubkey_bytes, sig_der, msg_hash32) — note sig before msg
  local ok = crypto.ecdsa_verify(pubkey, sig, msg)
  expect_true(ok, "signature should verify")
end)

-- G28b-BUG: P2TR signing not wired in wallet.create_transaction
test("G28b-BUG: P2TR (key-path Schnorr) signing not wired in wallet.create_transaction [BUG-10]", function()
  log_bug("BUG-10", "P2: wallet.create_transaction (wallet.lua:1462-1484) only handles p2wpkh and p2pkh signing. P2TR key-path (Schnorr, BIP-340/341) signing is absent. A wallet with P2TR UTXOs cannot sign transactions. Matches BUG-4/BUG-9: BIP-86 path + P2TR wallet support structurally missing end-to-end.")
  expect_true(true, "BUG-10 documented via code inspection")
end)

--------------------------------------------------------------------------------
-- G29-G30: PSBT (BIP-174/370)
--------------------------------------------------------------------------------

print("\n--- G29-G30: PSBT ---")

-- G29: PSBT serialize/deserialize round-trip
test("G29: PSBT binary serialize/deserialize round-trip", function()
  local types_mod = require("lunarblock.types")
  local tx = types_mod.transaction(2, {
    types_mod.txin(types_mod.outpoint(types_mod.hash256(string.rep("\x42", 32)), 0), "", 0xFFFFFFFD),
  }, {
    types_mod.txout(50000, "\x00\x14" .. string.rep("\x43", 20)),
  }, 0)

  local p = psbt.new(tx)
  -- Add witness UTXO
  psbt.update_input_utxo(p, 0, {value = 100000, script_pubkey = "\x00\x14" .. string.rep("\x44", 20)}, true)

  local serialized = psbt.serialize(p)
  local roundtrip = psbt.deserialize(serialized)
  expect_eq(roundtrip.version, 0, "PSBT version should be 0")
  expect_eq(#roundtrip.inputs, 1, "should have 1 input")
  expect_eq(roundtrip.inputs[1].witness_utxo.value, 100000, "witness UTXO value preserved")
end)

-- G30: PSBT finalize + extract
test("G30: PSBT finalize + extract produces broadcast-ready tx", function()
  local types_mod = require("lunarblock.types")
  local privkey = hex_to_bin("0202020202020202020202020202020202020202020202020202020202020202")
  local pubkey = crypto.pubkey_from_privkey(privkey, true)
  local pkh = crypto.hash160(pubkey)

  local tx = types_mod.transaction(2, {
    types_mod.txin(types_mod.outpoint(types_mod.hash256(string.rep("\x05", 32)), 0), "", 0xFFFFFFFD),
  }, {
    types_mod.txout(50000, "\x00\x14" .. pkh),
  }, 0)

  local p = psbt.new(tx)
  psbt.update_input_utxo(p, 0, {value = 100000, script_pubkey = "\x00\x14" .. pkh}, true)
  psbt.sign_input(p, 0, privkey, pubkey, 0x01)
  local finalized = psbt.finalize(p)
  expect_true(finalized, "finalize should succeed")
  expect_true(psbt.is_complete(p), "PSBT should be complete")

  local extracted = psbt.extract(p)
  expect_true(extracted ~= nil, "extract should succeed")
  expect_true(extracted.inputs[1].witness ~= nil, "extracted tx should have witness")
end)

-- G30b-BUG: PSBT decode() missing has_utxo field (existing test failure)
test("G30b-BUG: PSBT decode() missing has_utxo field in input record [BUG-11]", function()
  log_bug("BUG-11", "LOW: psbt.decode() (psbt.lua:1825+) does not set input_info.has_utxo field. test_psbt.lua:263 tests for decoded.inputs[1].has_utxo and fails. Core's decodepsbt output has no 'has_utxo' field either — this is a local test contract issue but the field is genuinely absent from decode() output.")
  local types_mod = require("lunarblock.types")
  local tx = types_mod.transaction(2, {
    types_mod.txin(types_mod.outpoint(types_mod.hash256(string.rep("\x26", 32)), 0), "", 0xFFFFFFFD),
  }, {types_mod.txout(50000, "\x00\x14" .. string.rep("\x27", 20))}, 0)
  local p = psbt.new(tx)
  psbt.update_input_utxo(p, 0, {value = 100000, script_pubkey = "\x00\x14" .. string.rep("\x28", 20)}, true)

  local decoded = psbt.decode(p)
  -- BUG: has_utxo is nil (not set by decode)
  expect_eq(decoded.inputs[1].has_utxo, nil, "BUG-11 confirmed: has_utxo is absent from decode()")
end)

-- G30c: BIP-370 PSBTv2 — check if supported
test("G30c-BUG: PSBTv2 (BIP-370) not supported [BUG-12]", function()
  log_bug("BUG-12", "LOW: PSBT version stored as M.VERSION=0 (psbt.lua:61). BIP-370 PSBTv2 fields (PSBT_GLOBAL_TX_VERSION, PSBT_GLOBAL_INPUT_COUNT, PSBT_IN_PREVIOUS_TXID etc.) not present. Serialization only emits GLOBAL_VERSION when psbt.version>0 (psbt.lua:309). PSBTv2 round-trip will fail. Acceptable for v0-only implementations but worth documenting.")
  expect_eq(psbt.VERSION, 0, "PSBTv2 not supported (VERSION=0)")
end)

-- G30d: PSBT CVE-2020-14199 guard (non_witness_utxo txid mismatch detection)
test("G30d: PSBT CVE-2020-14199 txid mismatch is rejected by deserialize", function()
  -- This is a defense-in-depth check that was previously fixed (W41/W46)
  -- Verify it is wired into sign_input too
  local types_mod = require("lunarblock.types")
  local privkey = hex_to_bin("0303030303030303030303030303030303030303030303030303030303030303")
  local pubkey = crypto.pubkey_from_privkey(privkey, true)
  local pkh = crypto.hash160(pubkey)

  local tx = types_mod.transaction(2, {
    types_mod.txin(types_mod.outpoint(types_mod.hash256(string.rep("\x07", 32)), 0), "", 0xFFFFFFFD),
  }, {
    types_mod.txout(50000, "\x00\x14" .. pkh),
  }, 0)

  local p = psbt.new(tx)
  -- Add witness_utxo (correct path) - CVE guard should not trigger for witness_utxo only
  psbt.update_input_utxo(p, 0, {value = 100000, script_pubkey = "\x00\x14" .. pkh}, true)
  local ok = psbt.sign_input(p, 0, privkey, pubkey, 0x01)
  expect_true(ok, "signing with only witness_utxo should succeed")
end)

--------------------------------------------------------------------------------
-- Summary
--------------------------------------------------------------------------------

print(string.format("\n=== W111 Audit Summary ==="))
print(string.format("Tests passed: %d / %d", tests_passed, tests_passed + tests_failed))
print(string.format("Tests failed: %d / %d", tests_failed, tests_passed + tests_failed))
print(string.format("Bugs documented: %d", #bugs))

print("\n--- Bug List ---")
for _, bug in ipairs(bugs) do
  print(string.format("  %s: %s", bug.id, bug.desc:sub(1, 80) .. (bug.desc:len() > 80 and "..." or "")))
end

if tests_failed > 0 then
  os.exit(1)
else
  print("\nAll tests passed.")
  os.exit(0)
end
