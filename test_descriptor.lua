#!/usr/bin/env luajit
-- Test output descriptors (BIP380-386)

package.path = "lunarblock/?.lua;src/?.lua;" .. package.path

-- Load address module (which contains descriptor functions)
local address = require("address")

-- Test helpers
local tests_passed = 0
local tests_failed = 0

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then
    print("✓ " .. name)
    tests_passed = tests_passed + 1
  else
    print("✗ " .. name)
    print("  Error: " .. tostring(err))
    tests_failed = tests_failed + 1
  end
end

local function eq(a, b, msg)
  if a ~= b then
    error((msg or "assertion failed") .. ": expected " .. tostring(b) .. ", got " .. tostring(a))
  end
end

local function ne(a, b, msg)
  if a == b then
    error((msg or "assertion failed") .. ": expected different values, got " .. tostring(a))
  end
end

local function truthy(v, msg)
  if not v then
    error(msg or "expected truthy value")
  end
end

local function falsy(v, msg)
  if v then
    error(msg or "expected falsy value")
  end
end

--------------------------------------------------------------------------------
-- Descriptor Checksum Tests
--------------------------------------------------------------------------------

print("\n=== Descriptor Checksum Tests ===\n")

test("computes 8-character checksum for pk() descriptor", function()
  local desc = "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
  local checksum = address.descriptor_checksum(desc)
  truthy(checksum, "checksum should not be nil")
  eq(#checksum, 8, "checksum should be 8 characters")
end)

test("computes checksum for pkh() descriptor", function()
  local desc = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
  local checksum = address.descriptor_checksum(desc)
  truthy(checksum, "checksum should not be nil")
  eq(#checksum, 8, "checksum should be 8 characters")
end)

test("computes checksum for wpkh() descriptor", function()
  local desc = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
  local checksum = address.descriptor_checksum(desc)
  truthy(checksum, "checksum should not be nil")
  eq(#checksum, 8, "checksum should be 8 characters")
end)

test("computes checksum for multi() descriptor", function()
  local desc = "multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)"
  local checksum = address.descriptor_checksum(desc)
  truthy(checksum, "checksum should not be nil")
  eq(#checksum, 8, "checksum should be 8 characters")
end)

test("checksum is deterministic", function()
  local desc = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
  local checksum1 = address.descriptor_checksum(desc)
  local checksum2 = address.descriptor_checksum(desc)
  eq(checksum1, checksum2, "same descriptor should produce same checksum")
end)

test("different descriptors produce different checksums", function()
  local desc1 = "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
  local desc2 = "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
  local checksum1 = address.descriptor_checksum(desc1)
  local checksum2 = address.descriptor_checksum(desc2)
  ne(checksum1, checksum2, "different descriptors should have different checksums")
end)

--------------------------------------------------------------------------------
-- Checksum Validation Tests
--------------------------------------------------------------------------------

print("\n=== Checksum Validation Tests ===\n")

test("validates correct checksum", function()
  local desc = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
  local checksum = address.descriptor_checksum(desc)
  local with_checksum = desc .. "#" .. checksum

  local valid, stripped = address.validate_descriptor_checksum(with_checksum)
  truthy(valid, "should validate correct checksum")
  eq(stripped, desc, "should return stripped descriptor")
end)

test("rejects incorrect checksum", function()
  local desc = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
  local with_checksum = desc .. "#aaaaaaaa"

  local valid = address.validate_descriptor_checksum(with_checksum)
  falsy(valid, "should reject incorrect checksum")
end)

test("returns error for missing checksum", function()
  local desc = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"

  local valid, err = address.validate_descriptor_checksum(desc)
  falsy(valid, "should return false for missing checksum")
  eq(err, "no checksum found", "should return appropriate error")
end)

--------------------------------------------------------------------------------
-- Key Expression Parsing Tests
--------------------------------------------------------------------------------

print("\n=== Key Expression Parsing Tests ===\n")

test("parses hex compressed pubkey (33 bytes)", function()
  local key_str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00"
  local key = address.parse_key_expression(key_str)

  truthy(key, "should parse key")
  eq(key.type, "pubkey", "should be pubkey type")
  eq(#key.pubkey, 33, "should be 33 bytes (compressed)")
  falsy(key.is_range, "should not be ranged")
end)

test("parses hex uncompressed pubkey (65 bytes)", function()
  local key_str = "04" .. string.rep("ab", 64)
  local key = address.parse_key_expression(key_str)

  truthy(key, "should parse key")
  eq(key.type, "pubkey", "should be pubkey type")
  eq(#key.pubkey, 65, "should be 65 bytes (uncompressed)")
end)

test("parses x-only pubkey (32 bytes)", function()
  local key_str = string.rep("cd", 32)
  local key = address.parse_key_expression(key_str)

  truthy(key, "should parse key")
  eq(key.type, "xonly", "should be xonly type")
  eq(#key.pubkey, 32, "should be 32 bytes")
end)

test("parses key with origin info", function()
  local key_str = "[d34db33f/44h/0h/0h]02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00"
  local key = address.parse_key_expression(key_str)

  truthy(key, "should parse key")
  truthy(key.origin, "should have origin info")
  eq(#key.origin.fingerprint, 4, "fingerprint should be 4 bytes")
  eq(#key.origin.path, 3, "should have 3 path elements")
end)

test("parses key with derivation path", function()
  local key_str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00/0/1"
  local key = address.parse_key_expression(key_str)

  truthy(key, "should parse key")
  eq(#key.path, 2, "should have 2 path elements")
  eq(key.path[1], 0, "first element should be 0")
  eq(key.path[2], 1, "second element should be 1")
  falsy(key.is_range, "should not be ranged")
end)

test("parses key with wildcard path", function()
  local key_str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00/0/*"
  local key = address.parse_key_expression(key_str)

  truthy(key, "should parse key")
  truthy(key.is_range, "should be ranged")
  falsy(key.is_hardened_range, "should not be hardened range")
end)

test("parses key with hardened wildcard", function()
  local key_str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00/0/*'"
  local key = address.parse_key_expression(key_str)

  truthy(key, "should parse key")
  truthy(key.is_range, "should be ranged")
  truthy(key.is_hardened_range, "should be hardened range")
end)

test("returns error for invalid hex length", function()
  local key_str = "abc123"
  local key, err = address.parse_key_expression(key_str)

  falsy(key, "should not parse invalid key")
  truthy(err, "should return error")
end)

--------------------------------------------------------------------------------
-- Descriptor Parsing Tests
--------------------------------------------------------------------------------

print("\n=== Descriptor Parsing Tests ===\n")

test("parses pk() descriptor", function()
  local desc_str = "pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
  local desc = address.parse_descriptor(desc_str)

  truthy(desc, "should parse descriptor")
  eq(desc.type, "pk", "should be pk type")
  truthy(desc.key, "should have key")
  falsy(desc.is_range, "should not be ranged")
end)

test("parses pkh() descriptor", function()
  local desc_str = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
  local desc = address.parse_descriptor(desc_str)

  truthy(desc, "should parse descriptor")
  eq(desc.type, "pkh", "should be pkh type")
  truthy(desc.key, "should have key")
end)

test("parses wpkh() descriptor", function()
  local desc_str = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
  local desc = address.parse_descriptor(desc_str)

  truthy(desc, "should parse descriptor")
  eq(desc.type, "wpkh", "should be wpkh type")
  truthy(desc.key, "should have key")
end)

test("parses multi() descriptor", function()
  local desc_str = "multi(2,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00,02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
  local desc = address.parse_descriptor(desc_str)

  truthy(desc, "should parse descriptor")
  eq(desc.type, "multi", "should be multi type")
  eq(desc.threshold, 2, "threshold should be 2")
  eq(#desc.keys, 2, "should have 2 keys")
  falsy(desc.sorted, "should not be sorted")
end)

test("parses sortedmulti() descriptor", function()
  local desc_str = "sortedmulti(2,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00,02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
  local desc = address.parse_descriptor(desc_str)

  truthy(desc, "should parse descriptor")
  eq(desc.type, "sortedmulti", "should be sortedmulti type")
  eq(desc.threshold, 2, "threshold should be 2")
  truthy(desc.sorted, "should be sorted")
end)

test("parses tr() descriptor with x-only key", function()
  local xonly = string.rep("ab", 32)
  local desc_str = "tr(" .. xonly .. ")"
  local desc = address.parse_descriptor(desc_str)

  truthy(desc, "should parse descriptor")
  eq(desc.type, "tr", "should be tr type")
  truthy(desc.key, "should have key")
end)

test("parses addr() descriptor", function()
  local desc_str = "addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)"
  local desc = address.parse_descriptor(desc_str)

  truthy(desc, "should parse descriptor")
  eq(desc.type, "addr", "should be addr type")
  eq(desc.address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "should have correct address")
end)

test("parses raw() descriptor", function()
  local desc_str = "raw(76a914000000000000000000000000000000000000000088ac)"
  local desc = address.parse_descriptor(desc_str)

  truthy(desc, "should parse descriptor")
  eq(desc.type, "raw", "should be raw type")
  truthy(desc.script, "should have script")
  eq(#desc.script, 25, "P2PKH script should be 25 bytes")
end)

test("parses combo() descriptor", function()
  local desc_str = "combo(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
  local desc = address.parse_descriptor(desc_str)

  truthy(desc, "should parse descriptor")
  eq(desc.type, "combo", "should be combo type")
  truthy(desc.key, "should have key")
end)

test("validates checksum when present", function()
  local desc_str = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
  local checksum = address.descriptor_checksum(desc_str)
  local with_checksum = desc_str .. "#" .. checksum

  local desc = address.parse_descriptor(with_checksum)
  truthy(desc, "should parse descriptor with valid checksum")
end)

test("rejects invalid checksum", function()
  local desc_str = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)#aaaaaaaa"

  local desc, err = address.parse_descriptor(desc_str)
  falsy(desc, "should not parse descriptor with invalid checksum")
  eq(err, "invalid checksum", "should return checksum error")
end)

test("returns error for unknown type", function()
  local desc_str = "unknown(something)"

  local desc, err = address.parse_descriptor(desc_str)
  falsy(desc, "should not parse unknown descriptor type")
end)

--------------------------------------------------------------------------------
-- get_descriptor_info Tests
--------------------------------------------------------------------------------

print("\n=== getdescriptorinfo Tests ===\n")

test("returns info for simple descriptor", function()
  local desc_str = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
  local info = address.get_descriptor_info(desc_str)

  truthy(info, "should return info")
  truthy(info.descriptor, "should have descriptor")
  truthy(info.checksum, "should have checksum")
  eq(#info.checksum, 8, "checksum should be 8 characters")
  falsy(info.isrange, "should not be ranged")
end)

test("adds checksum to descriptor", function()
  local desc_str = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
  local info = address.get_descriptor_info(desc_str)

  truthy(info.descriptor:find("#"), "descriptor should have checksum separator")
end)

test("reports ranged descriptor", function()
  local desc_str = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00/0/*)"
  local info = address.get_descriptor_info(desc_str)

  truthy(info, "should return info")
  truthy(info.isrange, "should report as ranged")
end)

test("strips existing checksum before recomputing", function()
  local desc_str = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
  local checksum = address.descriptor_checksum(desc_str)
  local with_checksum = desc_str .. "#" .. checksum

  local info1 = address.get_descriptor_info(desc_str)
  local info2 = address.get_descriptor_info(with_checksum)

  eq(info1.checksum, info2.checksum, "checksums should match")
end)

--------------------------------------------------------------------------------
-- derive_addresses Tests
--------------------------------------------------------------------------------

print("\n=== deriveaddresses Tests ===\n")

test("derives single address from non-ranged pkh() descriptor", function()
  local desc_str = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
  local checksum = address.descriptor_checksum(desc_str)
  desc_str = desc_str .. "#" .. checksum

  local addresses, err = address.derive_addresses(desc_str, 0, 0, "mainnet")

  truthy(addresses, "should return addresses: " .. tostring(err))
  eq(#addresses, 1, "should return exactly 1 address")
  -- P2PKH mainnet address starts with '1'
  eq(addresses[1]:sub(1, 1), "1", "address should start with '1'")
end)

test("derives wpkh address", function()
  local desc_str = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
  local checksum = address.descriptor_checksum(desc_str)
  desc_str = desc_str .. "#" .. checksum

  local addresses = address.derive_addresses(desc_str, 0, 0, "mainnet")

  truthy(addresses, "should return addresses")
  eq(#addresses, 1, "should return exactly 1 address")
  -- P2WPKH mainnet address starts with 'bc1q'
  eq(addresses[1]:sub(1, 4), "bc1q", "address should start with 'bc1q'")
end)

test("derives testnet address", function()
  local desc_str = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)"
  local checksum = address.descriptor_checksum(desc_str)
  desc_str = desc_str .. "#" .. checksum

  local addresses = address.derive_addresses(desc_str, 0, 0, "testnet")

  truthy(addresses, "should return addresses")
  -- P2WPKH testnet address starts with 'tb1q'
  eq(addresses[1]:sub(1, 4), "tb1q", "address should start with 'tb1q'")
end)

test("derives address from addr() descriptor", function()
  local addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
  local desc_str = "addr(" .. addr .. ")"
  local checksum = address.descriptor_checksum(desc_str)
  desc_str = desc_str .. "#" .. checksum

  local addresses = address.derive_addresses(desc_str, 0, 0, "mainnet")

  truthy(addresses, "should return addresses")
  eq(addresses[1], addr, "should return same address")
end)

test("derives address from raw() descriptor", function()
  -- P2PKH script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
  local desc_str = "raw(76a914000000000000000000000000000000000000000088ac)"
  local checksum = address.descriptor_checksum(desc_str)
  desc_str = desc_str .. "#" .. checksum

  local addresses = address.derive_addresses(desc_str, 0, 0, "mainnet")

  truthy(addresses, "should return addresses")
  eq(#addresses, 1, "should return exactly 1 address")
end)

--------------------------------------------------------------------------------
-- Summary
--------------------------------------------------------------------------------

print("\n" .. string.rep("=", 50))
print(string.format("Tests passed: %d", tests_passed))
print(string.format("Tests failed: %d", tests_failed))
print(string.rep("=", 50))

if tests_failed > 0 then
  os.exit(1)
end
