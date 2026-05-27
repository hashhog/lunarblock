#!/usr/bin/env luajit
-- test_p2_3_bip43_purpose_table.lua — Phase 2 unfreeze fix P2-3.
--
-- P2-3 ("Generalize BIP-43 purpose-code handling"): refactor the wallet's
-- 3 hardcoded `if address_type == "p2wpkh" then ... else ...` branches in
-- src/wallet.lua (unlock, generate_address, import_privkey) into a
-- table-driven lookup over `M.PURPOSE_TEMPLATES`.  Each purpose-code entry
-- (44/49/84/86) maps to:
--   * BIP-43 derivation template (m/purpose'/coin_type'/account'/change/idx)
--   * Output type ("p2pkh" | "p2sh-p2wpkh" | "p2wpkh" | "p2tr")
--   * Wallet address_type string (for back-compat with serialised wallets)
--
-- Closes: lunarblock unfreeze plan P2-3 — "Closed BIP-43 ecosystem at
-- wallet layer" structural finding from W138-W161 audit waves.
-- Reference: CORE-PARITY-AUDIT/_lunarblock-unfreeze-plan-2026-05-26.md
--            (search "P2-3").
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_p2_3_bip43_purpose_table.lua

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
local crypto    = require("lunarblock.crypto")
local address   = require("lunarblock.address")
local consensus = require("lunarblock.consensus")

-- Tiny test harness -----------------------------------------------------
local PASS, FAIL = 0, 0
local function pass(name) io.write(string.format("  PASS  %s\n", name)); PASS = PASS + 1 end
local function fail(name, msg) io.write(string.format("  FAIL  %s -- %s\n", name, msg)); FAIL = FAIL + 1 end
local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end
local function expect_eq(a, b, msg)
  if a ~= b then error((msg or "mismatch") .. ": got " .. tostring(a) ..
                       ", expected " .. tostring(b)) end
end
local function expect_true(v, msg) if not v then error(msg or "expected true") end end
local function expect_nil(v, msg)
  if v ~= nil then error((msg or "expected nil") .. ", got " .. tostring(v)) end
end
local function expect_error(fn, pat, msg)
  local ok, err = pcall(fn)
  if ok then error((msg or "expected error") .. " (got success)") end
  if pat and not tostring(err):find(pat) then
    error((msg or "wrong error") ..
          " — wanted /" .. pat .. "/, got: " .. tostring(err))
  end
end

local function hex_to_bin(hex)
  return (hex:gsub('..', function(cc) return string.char(tonumber(cc, 16)) end))
end
local function bin_to_hex(bin)
  local out = {}
  for i = 1, #bin do out[i] = string.format("%02x", bin:byte(i)) end
  return table.concat(out)
end

print("=== P2-3: Table-driven BIP-43 purpose-code handling ===\n")

-- ----------------------------------------------------------------------
-- T1: PURPOSE_TEMPLATES has all 4 canonical BIPs (44 / 49 / 84 / 86) and
-- each entry carries the required template fields.
-- ----------------------------------------------------------------------
print("--- T1: PURPOSE_TEMPLATES table shape ---")
test("T1: PURPOSE_TEMPLATES contains 44 / 49 / 84 / 86", function()
  for _, p in ipairs({44, 49, 84, 86}) do
    local tmpl = wallet.PURPOSE_TEMPLATES[p]
    expect_true(tmpl ~= nil, "PURPOSE_TEMPLATES[" .. p .. "] should exist")
    expect_true(type(tmpl.name) == "string", "tmpl.name is string")
    expect_true(type(tmpl.output_type) == "string", "tmpl.output_type is string")
    expect_true(type(tmpl.address_type) == "string", "tmpl.address_type is string")
    expect_eq(tmpl.bip_number, p, "tmpl.bip_number matches key")
  end
end)

test("T1b: output_type values match the BIP spec for each purpose", function()
  expect_eq(wallet.PURPOSE_TEMPLATES[44].output_type, "p2pkh",       "BIP-44 → P2PKH")
  expect_eq(wallet.PURPOSE_TEMPLATES[49].output_type, "p2sh-p2wpkh", "BIP-49 → P2SH-P2WPKH")
  expect_eq(wallet.PURPOSE_TEMPLATES[84].output_type, "p2wpkh",      "BIP-84 → P2WPKH")
  expect_eq(wallet.PURPOSE_TEMPLATES[86].output_type, "p2tr",        "BIP-86 → P2TR")
end)

-- ----------------------------------------------------------------------
-- T2: Reverse map (address_type → purpose) works for every registered
-- template and rejects unknown address_types.
-- ----------------------------------------------------------------------
print("\n--- T2: address_type ↔ purpose round-trip ---")
test("T2: purpose_for_address_type round-trips for canonical types + Core synonyms", function()
  -- Canonical (internal) names.
  expect_eq(wallet.purpose_for_address_type("p2pkh"),       44)
  expect_eq(wallet.purpose_for_address_type("p2sh-p2wpkh"), 49)
  expect_eq(wallet.purpose_for_address_type("p2wpkh"),      84)
  expect_eq(wallet.purpose_for_address_type("p2tr"),        86)
  -- Core RPC synonyms (per src/wallet/rpc/addresses.cpp::OutputTypeFromString)
  -- are translated transparently so a Core-compatible RPC client works
  -- without learning lunarblock's internal vocabulary.
  expect_eq(wallet.purpose_for_address_type("legacy"),      44, "legacy → BIP-44")
  expect_eq(wallet.purpose_for_address_type("p2sh-segwit"), 49, "p2sh-segwit → BIP-49")
  expect_eq(wallet.purpose_for_address_type("bech32"),      84, "bech32 → BIP-84")
  expect_eq(wallet.purpose_for_address_type("bech32m"),     86, "bech32m → BIP-86")
  -- True garbage still returns nil.
  expect_nil(wallet.purpose_for_address_type("bogus"))
  expect_nil(wallet.purpose_for_address_type(""))
end)

test("T2b: address_type_for_purpose round-trips", function()
  expect_eq(wallet.address_type_for_purpose(44), "p2pkh")
  expect_eq(wallet.address_type_for_purpose(49), "p2sh-p2wpkh")
  expect_eq(wallet.address_type_for_purpose(84), "p2wpkh")
  expect_eq(wallet.address_type_for_purpose(86), "p2tr")
  expect_nil(wallet.address_type_for_purpose(43), "BIP-43 itself is meta, not derivable")
end)

-- ----------------------------------------------------------------------
-- T3: derive_for_purpose rejects unsupported purpose codes loudly.
-- This is the "unsupported purpose code rejection" required by the P2-3
-- task brief.
-- ----------------------------------------------------------------------
print("\n--- T3: unsupported purpose rejection ---")
test("T3: derive_for_purpose errors with helpful message on unknown purpose", function()
  local seed = string.rep("\xab", 32)
  local master = wallet.master_key_from_seed(seed)
  expect_error(
    function() wallet.derive_for_purpose(master, 1234567, 0, 0, 0, 0) end,
    "unsupported BIP%-43 purpose code 1234567",
    "BIP-1234567 should be rejected"
  )
  expect_error(
    function() wallet.derive_for_purpose(master, 43, 0, 0, 0, 0) end,
    "unsupported BIP%-43 purpose code 43",
    "BIP-43 itself is a meta-BIP and not a derivation purpose"
  )
end)

test("T3b: pubkey_to_address_for_purpose errors on unknown purpose", function()
  local seed = string.rep("\xcd", 32)
  local master = wallet.master_key_from_seed(seed)
  local key    = wallet.derive_bip44_key(master, 0, 0, 0)
  local pubkey = crypto.pubkey_from_privkey(key.key, true)
  expect_error(
    function() wallet.pubkey_to_address_for_purpose(99, pubkey, "mainnet") end,
    "unsupported BIP%-43 purpose code 99",
    "purpose 99 should be rejected"
  )
end)

-- ----------------------------------------------------------------------
-- T4: Happy path — derive_for_purpose under purpose 44 produces the same
-- key as the legacy derive_bip44_key shim. This guards against silent
-- regression of the back-compat shim.
-- ----------------------------------------------------------------------
print("\n--- T4: legacy shim parity with table-driven derivation ---")
test("T4: derive_for_purpose(44) byte-matches derive_bip44_key (back-compat)", function()
  local seed = string.rep("\xef", 32)
  local master = wallet.master_key_from_seed(seed)
  local via_table = wallet.derive_for_purpose(master, 44, 0, 0, 0, 0)
  local via_shim  = wallet.derive_bip44_key(master, 0, 0, 0)
  expect_eq(bin_to_hex(via_table.key), bin_to_hex(via_shim.key), "private key matches")
  expect_eq(bin_to_hex(via_table.chain_code), bin_to_hex(via_shim.chain_code), "chain_code matches")
  expect_eq(via_table.depth, via_shim.depth, "depth matches")
end)

test("T4b: derive_for_purpose(84) byte-matches derive_bip84_key (back-compat)", function()
  local seed = string.rep("\xef", 32)
  local master = wallet.master_key_from_seed(seed)
  local via_table = wallet.derive_for_purpose(master, 84, 0, 0, 0, 0)
  local via_shim  = wallet.derive_bip84_key(master, 0, 0, 0)
  expect_eq(bin_to_hex(via_table.key), bin_to_hex(via_shim.key))
end)

test("T4c: BIP-49 and BIP-86 derivation paths differ from BIP-44 / BIP-84", function()
  local seed = string.rep("\xef", 32)
  local master = wallet.master_key_from_seed(seed)
  local k44 = wallet.derive_bip44_key(master, 0, 0, 0)
  local k49 = wallet.derive_bip49_key(master, 0, 0, 0)
  local k84 = wallet.derive_bip84_key(master, 0, 0, 0)
  local k86 = wallet.derive_bip86_key(master, 0, 0, 0)
  local hexes = {bin_to_hex(k44.key), bin_to_hex(k49.key),
                 bin_to_hex(k84.key), bin_to_hex(k86.key)}
  for i = 1, #hexes do
    for j = i + 1, #hexes do
      expect_true(hexes[i] ~= hexes[j],
        "purpose " .. i .. " and " .. j .. " must derive distinct keys (got both " .. hexes[i] .. ")")
    end
  end
end)

-- ----------------------------------------------------------------------
-- T5: pubkey_to_address_for_purpose emits the correct address SHAPE for
-- each output_type. We don't pin exact strings here (those vary per pubkey)
-- but we check the leading-byte / HRP signatures that are 1:1 with the
-- output type, which is what a downstream Core would parse.
-- ----------------------------------------------------------------------
print("\n--- T5: pubkey_to_address_for_purpose dispatches by output_type ---")
test("T5: each purpose emits an address with the right encoding prefix", function()
  local seed = string.rep("\x11", 32)
  local master = wallet.master_key_from_seed(seed)
  local cases = {
    {purpose = 44, prefix_pat = "^1",   why = "BIP-44 P2PKH (base58 '1...')"},
    {purpose = 49, prefix_pat = "^3",   why = "BIP-49 P2SH-P2WPKH (base58 '3...')"},
    {purpose = 84, prefix_pat = "^bc1q", why = "BIP-84 native P2WPKH (bech32 'bc1q...')"},
    {purpose = 86, prefix_pat = "^bc1p", why = "BIP-86 P2TR (bech32m 'bc1p...')"},
  }
  for _, c in ipairs(cases) do
    local key = wallet.derive_for_purpose(master, c.purpose, 0, 0, 0, 0)
    local pubkey = crypto.pubkey_from_privkey(key.key, true)
    local addr = wallet.pubkey_to_address_for_purpose(c.purpose, pubkey, "mainnet")
    expect_true(addr:find(c.prefix_pat) ~= nil,
      c.why .. " — got address: " .. tostring(addr))
  end
end)

-- ----------------------------------------------------------------------
-- T6: P2TR key-path address-derivation applies the BIP-341 TapTweak with
-- an empty merkle root, per BIP-86. We use the well-known BIP-86 test
-- vector pair (internal_key → tweaked_output_key) from BIP-86 §"Test
-- Vectors". This catches the latent inconsistency where an impl forgets
-- the tweak and just publishes the raw internal key as the output key.
--
-- BIP-86 vector:
--   internal_key = cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115
--   output_key   = a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c
-- (G15 in tests/test_w111_wallet.lua already pins this via the
--  descriptor path; here we confirm pubkey_to_address_for_purpose(86, ...)
--  takes the same code path.)
-- ----------------------------------------------------------------------
print("\n--- T6: BIP-86 TapTweak applied (no funds-burn vs raw internal) ---")
test("T6: P2TR address bytes match BIP-86 vector (TapTweak applied)", function()
  -- Use the BIP-86 vector internal key as if it were the pubkey body
  -- (we prepend an arbitrary parity byte 0x02; pubkey_to_address_for_purpose
  -- discards the parity byte and works on the x-only suffix only).
  local internal_xonly = hex_to_bin("cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115")
  local fake_compressed_pubkey = "\x02" .. internal_xonly
  local addr = wallet.pubkey_to_address_for_purpose(86, fake_compressed_pubkey, "mainnet")
  -- Confirm the encoded program is the TWEAKED key, not the raw internal.
  -- decode_address strips bech32m + returns the 32-byte program.
  local addr_type, witness_program = address.decode_address(addr, "mainnet")
  expect_eq(addr_type, "p2tr", "address decodes as P2TR")
  expect_eq(#witness_program, 32, "P2TR witness program is 32 bytes")
  expect_true(witness_program ~= internal_xonly,
    "BIP-86: output key MUST be tweaked, not the raw internal key — silent funds-burn otherwise")
  expect_eq(bin_to_hex(witness_program),
            "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
            "BIP-86: tweaked output key matches the canonical test vector")
end)

-- ----------------------------------------------------------------------
-- T7: BIP-49 P2SH-P2WPKH address is the P2SH of the P2WPKH redeem script
-- (NOT a P2PKH of the same pubkey).
-- ----------------------------------------------------------------------
print("\n--- T7: BIP-49 P2SH-P2WPKH is P2SH-of-witness, not legacy P2PKH ---")
test("T7: BIP-49 address ≠ BIP-44 address for the same pubkey", function()
  local seed = string.rep("\x22", 32)
  local master = wallet.master_key_from_seed(seed)
  -- Use the same key for both to isolate the address-builder difference
  -- (the derivation paths differ, but here we're testing address dispatch
  -- given a fixed pubkey, not derivation).
  local key = wallet.derive_bip44_key(master, 0, 0, 0)
  local pubkey = crypto.pubkey_from_privkey(key.key, true)
  local addr_44 = wallet.pubkey_to_address_for_purpose(44, pubkey, "mainnet")
  local addr_49 = wallet.pubkey_to_address_for_purpose(49, pubkey, "mainnet")
  expect_true(addr_44:sub(1, 1) == "1", "BIP-44 P2PKH starts with '1'")
  expect_true(addr_49:sub(1, 1) == "3", "BIP-49 P2SH-P2WPKH starts with '3'")
  expect_true(addr_44 ~= addr_49, "same pubkey must produce different addresses")
end)

-- ----------------------------------------------------------------------
-- T8: End-to-end on a real wallet — generate_address dispatches via the
-- table for every address_type, never silently falls back to BIP-44.
-- ----------------------------------------------------------------------
print("\n--- T8: Wallet:generate_address routes via table for all 4 address_types ---")
test("T8: address_type=p2sh-p2wpkh produces a '3...' address (NOT '1...')", function()
  local w = wallet.new(consensus.networks.mainnet)
  w.master_key = wallet.master_key_from_seed(string.rep("\x33", 32))
  w.is_locked = false
  w.address_type = "p2sh-p2wpkh"
  local addr = w:get_new_address()
  expect_true(addr:sub(1, 1) == "3",
    "BIP-49 wallet must produce '3...' addresses (silent BIP-44 fallback was the bug)")
  expect_eq(w.keys[addr].type, "p2sh-p2wpkh", "key_info.type tracks address_type")
end)

test("T8b: address_type=p2tr produces a 'bc1p...' bech32m address", function()
  local w = wallet.new(consensus.networks.mainnet)
  w.master_key = wallet.master_key_from_seed(string.rep("\x44", 32))
  w.is_locked = false
  w.address_type = "p2tr"
  local addr = w:get_new_address()
  expect_true(addr:find("^bc1p") ~= nil,
    "BIP-86 wallet must produce 'bc1p...' addresses (silent BIP-44 fallback was the bug)")
  expect_eq(w.keys[addr].type, "p2tr", "key_info.type tracks address_type")
end)

test("T8c: address_type=p2wpkh and p2pkh still work (no regression)", function()
  local w1 = wallet.new(consensus.networks.mainnet)
  w1.master_key = wallet.master_key_from_seed(string.rep("\x55", 32))
  w1.is_locked = false
  w1.address_type = "p2wpkh"
  local a1 = w1:get_new_address()
  expect_true(a1:find("^bc1q") ~= nil, "p2wpkh address starts bc1q")

  local w2 = wallet.new(consensus.networks.mainnet)
  w2.master_key = wallet.master_key_from_seed(string.rep("\x55", 32))
  w2.is_locked = false
  w2.address_type = "p2pkh"
  local a2 = w2:get_new_address()
  expect_true(a2:sub(1, 1) == "1", "p2pkh address starts '1'")
end)

test("T8d: unknown address_type errors with helpful message", function()
  local w = wallet.new(consensus.networks.mainnet)
  w.master_key = wallet.master_key_from_seed(string.rep("\x66", 32))
  w.is_locked = false
  w.address_type = "p2tr-script-tree"  -- not in PURPOSE_TEMPLATES
  expect_error(
    function() w:get_new_address() end,
    "unsupported wallet%.address_type",
    "unknown address_type should error loudly, not silently fall through"
  )
end)

test("T8e: Core RPC synonyms (legacy / bech32 / p2sh-segwit / bech32m) work", function()
  -- A Core-compatible client should be able to drive lunarblock without
  -- learning our internal naming; the synonym map handles the translation.
  local cases = {
    {synonym = "legacy",      prefix_pat = "^1",   why = "legacy → p2pkh"},
    {synonym = "p2sh-segwit", prefix_pat = "^3",   why = "p2sh-segwit → p2sh-p2wpkh"},
    {synonym = "bech32",      prefix_pat = "^bc1q", why = "bech32 → p2wpkh"},
    {synonym = "bech32m",     prefix_pat = "^bc1p", why = "bech32m → p2tr"},
  }
  for _, c in ipairs(cases) do
    local w = wallet.new(consensus.networks.mainnet)
    w.master_key = wallet.master_key_from_seed(string.rep("\x77", 32))
    w.is_locked = false
    w.address_type = c.synonym
    local addr = w:get_new_address()
    expect_true(addr:find(c.prefix_pat) ~= nil,
      c.why .. " — synonym should route via canonical lookup; got: " .. tostring(addr))
    -- key_info.type should be the CANONICAL string, not the synonym, so
    -- unlock()'s lookup never has to walk the synonym map.
    expect_eq(w.keys[addr].type, wallet.canonical_address_type(c.synonym),
      c.why .. " — key_info.type should be canonical, not the RPC synonym")
  end
end)

-- ----------------------------------------------------------------------
-- T9: Adding a new purpose at runtime via add_purpose invalidates the
-- reverse-map cache. Future-proofing hook validation.
-- ----------------------------------------------------------------------
print("\n--- T9: add_purpose extension hook ---")
test("T9: add_purpose lets new BIPs join the table without code changes", function()
  -- Pretend we want to add a hypothetical BIP-XYZ at purpose 1729.
  local saved = wallet.PURPOSE_TEMPLATES[1729]  -- should be nil; defensive
  wallet.add_purpose(1729, {
    name         = "BIP-1729 hypothetical",
    output_type  = "p2pkh",
    address_type = "p2pkh-1729",
    bip_number   = 1729,
  })
  expect_eq(wallet.purpose_for_address_type("p2pkh-1729"), 1729,
    "reverse-map cache was invalidated and rebuilt")
  -- Cleanup so we don't leak state into other tests.
  wallet.PURPOSE_TEMPLATES[1729] = saved
  wallet.add_purpose(44, wallet.PURPOSE_TEMPLATES[44])  -- triggers cache rebuild
  expect_nil(wallet.purpose_for_address_type("p2pkh-1729"),
    "cache invalidation works after removal too")
end)

-- ----------------------------------------------------------------------
-- Summary
-- ----------------------------------------------------------------------
print(string.format("\nResults: %d PASS / %d FAIL", PASS, FAIL))
os.exit(FAIL == 0 and 0 or 1)
