#!/usr/bin/env luajit
-- test_p2_1_p2_2_wallet_security.lua — Phase 2 unfreeze fixes (P2-1 + P2-2).
--
-- P2-1 (W161 master_key plaintext P0): wallet.serialize() must NEVER write
-- the literal master_key + chain_code bytes to disk, even for "unencrypted"
-- (no-user-passphrase) wallets. Plaintext-on-disk is a P0-FUNDSLOSS shape
-- documented in the impl-triage decision 2026-05-19. Closed here by always
-- encrypting the master_key at rest with a fixed AT_REST_PHRASE-derived key
-- when no user passphrase is set. This is NOT a security boundary on its
-- own (the AT_REST_PHRASE is a public constant), but it (a) closes the
-- catalogue P0 shape, (b) makes the "no plaintext master key on disk"
-- invariant testable, and (c) mirrors clearbit's f302997 fix model.
--
-- P2-2 (W118 G6-BUG-1 2nd carry-forward / W161 BUG-18): wallet.derive_child
-- previously retried with `index + 1` on parse256(IL) >= n or k_i == 0 with
-- NO check that the increment stayed inside the same hardened range. A
-- non-hardened index of 0x7FFFFFFF that failed IL-validity jumped to
-- 0x80000000 (first hardened), silently changing the derivation type and
-- producing a key inconsistent with Bitcoin Core (CKey::Derive enforces the
-- range stays the same). Closed here by erroring out on the boundary cross.
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_p2_1_p2_2_wallet_security.lua

package.path = "src/?.lua;./?.lua;" .. package.path

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

local wallet    = require("lunarblock.wallet")
local consensus = require("lunarblock.consensus")
local crypto    = require("lunarblock.crypto")

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
local function expect_true(v, msg) if not v then error(msg or "expected true") end end
local function expect_false(v, msg) if v then error(msg or "expected false") end end
local function expect_contains(haystack, needle, msg)
  if not haystack or not haystack:find(needle, 1, true) then
    error((msg or "expected to contain")
      .. ": needle=" .. tostring(needle)
      .. " haystack=" .. tostring(haystack))
  end
end
local function expect_not_contains(haystack, needle, msg)
  if haystack and haystack:find(needle, 1, true) then
    error((msg or "expected NOT to contain")
      .. ": needle=" .. tostring(needle)
      .. " haystack=" .. tostring(haystack))
  end
end

print("=== P2-1 + P2-2 Wallet Security Fixes (lunarblock unfreeze Phase 2) ===\n")

-- ======================================================================
-- P2-1: master_key encrypted at rest even for "unencrypted" wallets
-- ======================================================================
print("--- P2-1: master_key never plaintext on disk ---")

-- T1: unencrypted wallet round-trips through serialize without exposing the
--     literal master_key hex anywhere in the JSON blob.
test("P2-1/T1: serialize() of unencrypted wallet does NOT contain literal master_key bytes", function()
  local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
  local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)
  expect_false(w.is_encrypted, "wallet should be unencrypted")
  expect_true(w.master_key ~= nil, "wallet should have master_key in memory")

  local master_hex = bin_to_hex(w.master_key.key)
  local chain_hex  = bin_to_hex(w.master_key.chain_code)
  local blob = w:serialize()

  -- Pre-fix bug: the JSON contained "master_key":"<hex>" and "master_chain_code":"<hex>"
  -- as literal plaintext bytes. Post-fix: these fields are gone and only the
  -- at-rest-encrypted ciphertext is present.
  expect_not_contains(blob, master_hex, "serialized blob must not contain literal master_key bytes")
  expect_not_contains(blob, chain_hex,  "serialized blob must not contain literal chain_code bytes")
  expect_contains(blob, "at_rest_encrypted_master", "blob must contain new ciphertext field")
  expect_contains(blob, "at_rest_salt", "blob must contain at-rest salt")
end)

-- T2: round-trip — save + load reconstructs the same master_key.
test("P2-1/T2: serialize+load preserves master_key bytes (round-trip)", function()
  local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
  local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)
  local orig_key   = w.master_key.key
  local orig_chain = w.master_key.chain_code

  -- Round-trip via tmpfile.
  local tmppath = os.tmpname()
  local ok, err = w:save(tmppath)
  expect_true(ok, "save: " .. tostring(err))

  local loaded, lerr = wallet.load(tmppath, consensus.networks.mainnet, nil)
  expect_true(loaded ~= nil, "load failed: " .. tostring(lerr))
  expect_eq(loaded.master_key.key,        orig_key,   "master_key round-trips")
  expect_eq(loaded.master_key.chain_code, orig_chain, "chain_code round-trips")
  expect_false(loaded.is_encrypted, "loaded wallet is still 'unencrypted' from user POV")
  expect_false(loaded.is_locked, "loaded at-rest wallet is unlocked")
  os.remove(tmppath)
end)

-- T3: round-trip with mnemonic — mnemonic also at-rest-encrypted, not plaintext.
test("P2-1/T3: serialize() of unencrypted wallet with mnemonic does NOT leak mnemonic words", function()
  local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
  local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)
  -- Inject a known mnemonic.
  w.mnemonic_words = {
    "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
    "abandon", "abandon", "abandon", "abandon", "abandon", "about"
  }

  local blob = w:serialize()
  expect_not_contains(blob, "\"mnemonic\":", "plaintext mnemonic field absent")
  expect_not_contains(blob, "abandon", "literal mnemonic word absent")
  expect_contains(blob, "at_rest_encrypted_mnemonic", "encrypted mnemonic field present")
end)

-- T4: legacy back-compat — a pre-fix wallet file with plaintext master_key
--     must still load (so existing on-disk wallets don't brick), but the
--     fix path takes over on next save.
test("P2-1/T4: legacy plaintext master_key wallets still load (back-compat)", function()
  -- Hand-craft a legacy JSON blob with plaintext master_key.
  local legacy = ('{"version":1,"network":"mainnet","address_type":"p2wpkh",' ..
                  '"account":0,"next_external_index":0,"next_internal_index":0,' ..
                  '"is_encrypted":false,' ..
                  '"master_key":"%s","master_chain_code":"%s"}'):format(
    string.rep("ab", 32), string.rep("cd", 32))
  local tmppath = os.tmpname()
  local fh = io.open(tmppath, "w")
  fh:write(legacy)
  fh:close()

  -- Suppress the deprecation stderr warning during this test by swapping
  -- the io.stderr file handle for an in-memory file we discard. LuaJIT's
  -- io.stderr is a userdata FILE*, so we replace the table entry rather
  -- than its method.
  local orig_stderr = io.stderr
  io.stderr = io.open("/dev/null", "w") or orig_stderr
  local loaded, lerr = wallet.load(tmppath, consensus.networks.mainnet, nil)
  if io.stderr ~= orig_stderr then io.stderr:close() end
  io.stderr = orig_stderr

  expect_true(loaded ~= nil, "legacy wallet failed to load: " .. tostring(lerr))
  expect_eq(bin_to_hex(loaded.master_key.key), string.rep("ab", 32), "legacy master_key preserved")
  expect_eq(bin_to_hex(loaded.master_key.chain_code), string.rep("cd", 32), "legacy chain_code preserved")
  os.remove(tmppath)
end)

-- T5: user-encrypted wallets remain encrypted on disk (no regression on
--     the existing encryption path).
test("P2-1/T5: user-encrypted wallets retain encrypted_master_key serialization", function()
  local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
  local w = wallet.from_seed(seed, consensus.networks.mainnet, nil)
  w:encrypt("strong-passphrase")
  expect_true(w.is_encrypted, "wallet encrypted")

  local master_hex = bin_to_hex(w.master_key.key)
  local blob = w:serialize()
  expect_not_contains(blob, master_hex, "user-encrypted blob must not contain plaintext master_key")
  expect_contains(blob, "encrypted_master_key", "user-encrypted field still present")
  expect_not_contains(blob, "at_rest_encrypted_master", "user-encrypted wallets do not use the at-rest field")
end)

-- ======================================================================
-- P2-2: derive_child retry must not cross hardened boundary
-- ======================================================================
print("\n--- P2-2: BIP-32 derive_child retry boundary check ---")

-- T6: happy-path regression — BIP-32 test vector 1 still derives correctly
--     end-to-end (proves the retry refactor didn't break the normal path).
test("P2-2/T6: BIP-32 TV1 m/0'/1 still derives correctly post-fix", function()
  local m = wallet.master_key_from_seed(hex_to_bin("000102030405060708090a0b0c0d0e0f"))
  local h = wallet.derive_child(m, 0x80000000)         -- m/0'
  local c = wallet.derive_child(h, 1)                  -- m/0'/1
  -- BIP-32 TV1 m/0'/1 expected private key.
  expect_eq(bin_to_hex(c.key),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
            "TV1 m/0'/1 private key matches BIP-32")
end)

-- T7: retry crossing into hardened range (0x7FFFFFFF -> 0x80000000) MUST
--     error rather than silently change derivation type. We force the retry
--     by monkey-patching crypto.hmac_sha512 so it returns IL >= n exactly
--     when called for index 0x7FFFFFFF on a known parent. After the retry
--     attempt we restore the original primitive.
test("P2-2/T7: retry from 0x7FFFFFFF into hardened range raises 'cannot cross hardened boundary'", function()
  local m = wallet.master_key_from_seed(hex_to_bin("000102030405060708090a0b0c0d0e0f"))

  -- Build a 64-byte HMAC output where IL = n (the secp256k1 order — the
  -- smallest value >= n, guaranteed to fail is_valid_key). IR can be
  -- anything 32 bytes long; we use 0x42 repeated.
  local SECP256K1_N_HEX =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
  local bad_hmac = hex_to_bin(SECP256K1_N_HEX) .. string.rep("\x42", 32)

  local orig_hmac = crypto.hmac_sha512
  crypto.hmac_sha512 = function(key, data)
    -- Force-fail IL validity unconditionally so retry kicks in on every call.
    return bad_hmac
  end

  local ok, err = pcall(wallet.derive_child, m, 0x7FFFFFFF)
  crypto.hmac_sha512 = orig_hmac

  expect_false(ok, "derive_child must error on hardened-boundary retry")
  expect_contains(tostring(err),
                  "cannot cross hardened boundary",
                  "error must name the boundary-cross condition")
end)

-- T8: retry from 0xFFFFFFFF (last valid index) MUST error with "exhausted"
--     instead of silently wrapping to 0.
test("P2-2/T8: retry from 0xFFFFFFFF raises 'derivation exhausted'", function()
  local m = wallet.master_key_from_seed(hex_to_bin("000102030405060708090a0b0c0d0e0f"))
  local SECP256K1_N_HEX =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
  local bad_hmac = hex_to_bin(SECP256K1_N_HEX) .. string.rep("\x42", 32)

  local orig_hmac = crypto.hmac_sha512
  crypto.hmac_sha512 = function() return bad_hmac end
  local ok, err = pcall(wallet.derive_child, m, 0xFFFFFFFF)
  crypto.hmac_sha512 = orig_hmac

  expect_false(ok, "derive_child must error on exhaustion")
  expect_contains(tostring(err),
                  "exhausted",
                  "error must name the exhaustion condition")
end)

-- T9: retry from a normal interior index (e.g. 5) does NOT error — should
--     recurse to (index + 1) within the same range. We arrange the
--     monkey-patched HMAC to fail once then succeed, by counting calls.
test("P2-2/T9: retry from interior non-boundary index succeeds (no false positive)", function()
  local m = wallet.master_key_from_seed(hex_to_bin("000102030405060708090a0b0c0d0e0f"))
  local SECP256K1_N_HEX =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
  local bad_hmac = hex_to_bin(SECP256K1_N_HEX) .. string.rep("\x42", 32)

  local orig_hmac = crypto.hmac_sha512
  local call_count = 0
  crypto.hmac_sha512 = function(key, data)
    call_count = call_count + 1
    if call_count == 1 then return bad_hmac end
    return orig_hmac(key, data)
  end

  local ok, child = pcall(wallet.derive_child, m, 5)
  crypto.hmac_sha512 = orig_hmac

  expect_true(ok, "retry within same range must succeed: " .. tostring(child))
  expect_eq(child.child_index, 6, "child should have advanced to index+1")
end)

-- ======================================================================
-- Summary
-- ======================================================================
print(string.format("\nResults: %d PASS / %d FAIL\n", PASS, FAIL))
os.exit(FAIL == 0 and 0 or 1)
