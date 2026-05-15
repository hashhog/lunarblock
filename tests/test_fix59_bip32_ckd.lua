#!/usr/bin/env luajit
-- test_fix59_bip32_ckd.lua — FIX-59 BIP-32 CKD (CKDpriv + CKDpub) vectors.
--
-- Closes W118 G6-BUG-1 (P0): address.derive_child previously returned
-- IL alone instead of (parse256(IL) + k_par) mod n. CKDpub was a no-op
-- ("not yet implemented").
--
-- Tests:
--   1. BIP-32 Test Vector 1, full m -> m/0'/1/2'/2/1000000000 path.
--      Validates CKDpriv at every step (priv + chain_code + matching pub).
--   2. BIP-32 Test Vector 2, full m -> m/0/2147483647'/1/2147483646'/2 path.
--      Validates CKDpriv across very large normal AND hardened indices.
--   3. CKDpub at a non-hardened step: starting from an xpub-only ancestor,
--      drive the same IL-tweak-add path that BIP-32 takes for watch-only
--      wallets, and confirm the pubkey matches the privkey-derived pubkey.
--      This is the "two-pipeline-within-impl" test — wallet.lua had a
--      correct add_mod_n for the priv side but no pub side at all.
--   4. Negative: forge a tweak >= n and assert ec_seckey_tweak_add /
--      ec_pubkey_tweak_add both return nil + an "invalid derivation" error
--      (BIP-32 says the caller should advance to index+1).
--   5. Confirm src/address.lua no longer contains the "INCORRECT for real"
--      placeholder string.
--
-- Reference test vectors: BIP-32 §"Test vector 1" and §"Test vector 2"
-- (github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_fix59_bip32_ckd.lua

package.path = "src/?.lua;./?.lua;" .. package.path

-- Load src/<name>.lua under the "lunarblock.<name>" namespace.
local loaders = package.loaders or package.searchers
table.insert(loaders, 2, function(module)
  local name = module:match("^lunarblock%.(.+)")
  if name then
    local filename = "src/" .. name .. ".lua"
    local f = io.open(filename)
    if f then f:close(); return function() return dofile(filename) end end
  end
  return nil, "not found"
end)

local address = require("lunarblock.address")
local crypto  = require("lunarblock.crypto")

-- Helpers ------------------------------------------------------------
local function hex_to_bin(hex)
  return (hex:gsub('..', function(cc) return string.char(tonumber(cc, 16)) end))
end

local function bin_to_hex(bin)
  local hex = {}
  for i = 1, #bin do hex[i] = string.format("%02x", bin:byte(i)) end
  return table.concat(hex)
end

local PASS, FAIL = 0, 0

local function pass(name) io.write(string.format("  PASS  %s\n", name)); PASS = PASS + 1 end
local function fail(name, msg) io.write(string.format("  FAIL  %s -- %s\n", name, msg)); FAIL = FAIL + 1 end

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) .. ", expected " .. tostring(b))
  end
end

local function expect_true(v, msg)
  if not v then error(msg or "expected true") end
end

print("=== FIX-59 BIP-32 CKD vectors (closes W118 G6-BUG-1) ===\n")

-- ===================================================================
-- Master key derivation (shared by both pipelines)
-- ===================================================================

-- Derive master (k_master, c_master, K_master) from a seed.
-- I = HMAC-SHA512(Key = "Bitcoin seed", Data = S); IL = k, IR = c.
local function master_from_seed(seed)
  local I = crypto.hmac_sha512("Bitcoin seed", seed)
  local k = I:sub(1, 32)
  local c = I:sub(33, 64)
  local K = crypto.pubkey_from_privkey(k, true)
  return k, c, K
end

-- ===================================================================
-- BIP-32 Test Vector 1
-- seed = 000102030405060708090a0b0c0d0e0f
-- Path: m -> m/0' -> m/0'/1 -> m/0'/1/2' -> m/0'/1/2'/2
--                                       -> m/0'/1/2'/2/1000000000
-- ===================================================================
print("--- BIP-32 Test Vector 1 (CKDpriv full path) ---")

local TV1_SEED = hex_to_bin("000102030405060708090a0b0c0d0e0f")

-- (chain_code, private_key, public_key) expected at each step.
-- Extracted from the BIP-32 spec's xprv/xpub blobs (positions 14..45 = c,
-- 47..78 = privkey, and the matching xpub pubkey at positions 46..78).
local TV1 = {
  m = {
    cc  = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
    k   = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
    K   = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
  },
  ["m/0'"] = {
    cc  = "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
    k   = "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
    K   = "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
    idx = 0x80000000,
  },
  ["m/0'/1"] = {
    cc  = "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
    k   = "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
    K   = "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c",
    idx = 1,
  },
  ["m/0'/1/2'"] = {
    cc  = "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
    k   = "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
    K   = "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
    idx = 0x80000000 + 2,
  },
  ["m/0'/1/2'/2"] = {
    cc  = "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
    k   = "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
    K   = "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29",
    idx = 2,
  },
  ["m/0'/1/2'/2/1000000000"] = {
    cc  = "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
    k   = "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
    K   = "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011",
    idx = 1000000000,
  },
}

-- Drive the full chain. Each step asserts: priv, chain_code, and that the
-- pubkey CKDpriv emits matches the spec's xpub pubkey for that path.
test("TV1 m master", function()
  local k, c, K = master_from_seed(TV1_SEED)
  expect_eq(bin_to_hex(k), TV1["m"].k, "m priv")
  expect_eq(bin_to_hex(c), TV1["m"].cc, "m chain_code")
  expect_eq(bin_to_hex(K), TV1["m"].K, "m pubkey")
end)

-- Run all five non-master steps.
local TV1_STEPS = { "m/0'", "m/0'/1", "m/0'/1/2'", "m/0'/1/2'/2",
                    "m/0'/1/2'/2/1000000000" }
local TV1_PARENT = { "m", "m/0'", "m/0'/1", "m/0'/1/2'", "m/0'/1/2'/2" }

for i, path in ipairs(TV1_STEPS) do
  local parent_path = TV1_PARENT[i]
  test("TV1 CKDpriv " .. path, function()
    local pk = hex_to_bin(TV1[parent_path].k)
    local cc = hex_to_bin(TV1[parent_path].cc)
    local pub = hex_to_bin(TV1[parent_path].K)
    local child_pub, child_cc, err, child_priv =
      address.derive_child(pub, cc, TV1[path].idx, pk)
    expect_true(err == nil, "no error: " .. tostring(err))
    expect_eq(bin_to_hex(child_priv), TV1[path].k, "priv")
    expect_eq(bin_to_hex(child_cc),   TV1[path].cc, "chain_code")
    expect_eq(bin_to_hex(child_pub),  TV1[path].K, "pubkey")
  end)
end

-- ===================================================================
-- BIP-32 Test Vector 2
-- seed = fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
-- Path: m -> m/0 -> m/0/2147483647' -> m/0/2147483647'/1
--                                  -> m/0/2147483647'/1/2147483646'
--                                  -> m/0/2147483647'/1/2147483646'/2
-- Exercises (a) very-large normal index and (b) consecutive hardened.
-- ===================================================================
print("\n--- BIP-32 Test Vector 2 (CKDpriv, large + multi-hardened) ---")

local TV2_SEED = hex_to_bin(
  "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2" ..
  "9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")

local TV2 = {
  m = {
    cc = "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
    k  = "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
    K  = "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
  },
  ["m/0"] = {
    cc = "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c",
    k  = "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
    K  = "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea",
    idx = 0,
  },
  ["m/0/2147483647'"] = {
    cc = "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9",
    k  = "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
    K  = "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b",
    idx = 0x80000000 + 2147483647,
  },
  ["m/0/2147483647'/1"] = {
    cc = "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb",
    k  = "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
    K  = "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9",
    idx = 1,
  },
  ["m/0/2147483647'/1/2147483646'"] = {
    cc = "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29",
    k  = "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
    K  = "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0",
    idx = 0x80000000 + 2147483646,
  },
  ["m/0/2147483647'/1/2147483646'/2"] = {
    cc = "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271",
    k  = "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
    K  = "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c",
    idx = 2,
  },
}

test("TV2 m master", function()
  local k, c, K = master_from_seed(TV2_SEED)
  expect_eq(bin_to_hex(k), TV2["m"].k, "m priv")
  expect_eq(bin_to_hex(c), TV2["m"].cc, "m chain_code")
  expect_eq(bin_to_hex(K), TV2["m"].K, "m pubkey")
end)

local TV2_STEPS = {
  "m/0", "m/0/2147483647'", "m/0/2147483647'/1",
  "m/0/2147483647'/1/2147483646'", "m/0/2147483647'/1/2147483646'/2",
}
local TV2_PARENT = {
  "m", "m/0", "m/0/2147483647'", "m/0/2147483647'/1",
  "m/0/2147483647'/1/2147483646'",
}

for i, path in ipairs(TV2_STEPS) do
  local parent_path = TV2_PARENT[i]
  test("TV2 CKDpriv " .. path, function()
    local pk = hex_to_bin(TV2[parent_path].k)
    local cc = hex_to_bin(TV2[parent_path].cc)
    local pub = hex_to_bin(TV2[parent_path].K)
    local child_pub, child_cc, err, child_priv =
      address.derive_child(pub, cc, TV2[path].idx, pk)
    expect_true(err == nil, "no error: " .. tostring(err))
    expect_eq(bin_to_hex(child_priv), TV2[path].k, "priv")
    expect_eq(bin_to_hex(child_cc),   TV2[path].cc, "chain_code")
    expect_eq(bin_to_hex(child_pub),  TV2[path].K, "pubkey")
  end)
end

-- ===================================================================
-- CKDpub — non-hardened path with NO parent privkey (watch-only).
-- For each non-hardened step in TV1, derive from xpub alone and confirm
-- the pubkey + chain code match the priv-derived spec values.
-- This proves both pipelines (CKDpriv and CKDpub) converge.
-- ===================================================================
print("\n--- BIP-32 CKDpub (watch-only / xpub-only) ---")

-- Only non-hardened steps from TV1: m/0'/1 (from m/0'), m/0'/1/2'/2 (from
-- m/0'/1/2'), and m/0'/1/2'/2/1000000000 (from m/0'/1/2'/2).
local CKDPUB_STEPS = {
  { parent = "m/0'",          child = "m/0'/1",                  idx = 1          },
  { parent = "m/0'/1/2'",     child = "m/0'/1/2'/2",             idx = 2          },
  { parent = "m/0'/1/2'/2",   child = "m/0'/1/2'/2/1000000000",  idx = 1000000000 },
}

for _, s in ipairs(CKDPUB_STEPS) do
  test("CKDpub " .. s.child .. " (no privkey)", function()
    local pub = hex_to_bin(TV1[s.parent].K)
    local cc  = hex_to_bin(TV1[s.parent].cc)
    -- No privkey passed -> exercises ec_pubkey_tweak_add path.
    local child_pub, child_cc, err, child_priv =
      address.derive_child(pub, cc, s.idx, nil)
    expect_true(err == nil, "no error: " .. tostring(err))
    expect_eq(child_priv, nil, "no priv from pub-only derive")
    expect_eq(bin_to_hex(child_cc),  TV1[s.child].cc, "chain_code")
    expect_eq(bin_to_hex(child_pub), TV1[s.child].K,  "pubkey matches priv-derived")
  end)
end

-- Hardened from pubkey-only MUST refuse.
test("CKDpub hardened refuses (BIP-32: hardened needs parent privkey)", function()
  local pub = hex_to_bin(TV1["m"].K)
  local cc  = hex_to_bin(TV1["m"].cc)
  local _, _, err = address.derive_child(pub, cc, 0x80000000, nil)
  expect_true(err ~= nil, "must error on hardened+no-privkey")
end)

-- ===================================================================
-- Negative: BIP-32 invalid-derivation handling.
-- libsecp256k1's tweak_add rejects tweak >= n; we forge such a tweak
-- and assert both wrappers refuse.
-- ===================================================================
print("\n--- Negative: tweak >= n must be rejected ---")

-- secp256k1 order n. Anything >= n is invalid as a tweak; the function
-- must return nil with an error so the caller can advance to index+1
-- per BIP-32 §"Private parent key -> private child key".
local TWEAK_GE_N =
  hex_to_bin("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

test("ec_seckey_tweak_add rejects tweak >= n", function()
  local parent = hex_to_bin(TV1["m"].k)
  local out, err = crypto.ec_seckey_tweak_add(parent, TWEAK_GE_N)
  expect_eq(out, nil, "must return nil")
  expect_true(err ~= nil, "must report error")
end)

test("ec_pubkey_tweak_add rejects tweak >= n", function()
  local parent = hex_to_bin(TV1["m"].K)
  local out, err = crypto.ec_pubkey_tweak_add(parent, TWEAK_GE_N, true)
  expect_eq(out, nil, "must return nil")
  expect_true(err ~= nil, "must report error")
end)

-- ===================================================================
-- Source assertion: "INCORRECT for real use" must be gone.
-- ===================================================================
test("src/address.lua no longer claims 'INCORRECT for real use'", function()
  local f = assert(io.open("src/address.lua", "r"))
  local content = f:read("*a"); f:close()
  expect_eq(content:find("INCORRECT for real"), nil,
            "address.lua still annotated INCORRECT")
end)

-- ===================================================================
print(string.format("\nResults: %d PASS / %d FAIL\n", PASS, FAIL))
os.exit(FAIL == 0 and 0 or 1)
