#!/usr/bin/env luajit
-- test_fix63_decode_address_network.lua — FIX-63 strict per-network
-- Base58 version-byte validation in address.decode_address.
--
-- Background: FIX-62 surfaced this latent bug while landing the BIP-21
-- "bitcoin:" URI parser.  Before this fix, decode_address(addr, network)
-- accepted EITHER mainnet (0x00 P2PKH / 0x05 P2SH) OR testnet (0x6F /
-- 0xC4) regardless of the network arg, silently letting mainnet
-- '1A1zP1...' addresses parse on a testnet wallet (and vice versa).
-- That is a cross-network payment hazard: a testnet wallet handed a
-- mainnet address would happily build a transaction "for" it.
--
-- Bitcoin Core's CBitcoinAddress::IsValid (src/key_io.cpp) does a
-- strict per-network check via params.Base58Prefix(PUBKEY_ADDRESS) and
-- params.Base58Prefix(SCRIPT_ADDRESS).  This test mirrors that
-- contract.  Bech32 was already correctly HRP-checked by segwit_decode,
-- so the bech32 cases below are sanity coverage rather than regression
-- fixes.
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_fix63_decode_address_network.lua

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
local function expect_nil(v, msg)
  if v ~= nil then
    error((msg or "expected nil") .. ", got " .. tostring(v))
  end
end
local function expect_truthy(v, msg)
  if not v then error(msg or "expected truthy, got nil/false") end
end

-- Address corpus.  These are well-known, fixed test addresses that any
-- Base58Check / bech32 reference implementation accepts.
local ADDR = {
  -- Mainnet P2PKH (Bitcoin genesis-block coinbase) — version byte 0x00.
  P2PKH_MAIN  = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
  -- Testnet P2PKH — version byte 0x6F.  Widely circulated test addr.
  P2PKH_TEST  = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
  -- Mainnet P2SH — version byte 0x05.
  P2SH_MAIN   = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
  -- Testnet P2SH — version byte 0xC4.
  P2SH_TEST   = "2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br",
  -- Bech32 (BIP-173 vector) — mainnet P2WPKH.
  BECH32_MAIN = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
  -- Bech32 — testnet P2WPKH.  BIP-173 §"Test vectors for Bech32".
  BECH32_TEST = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
  -- Bech32 — regtest P2WPKH.  Same hash160 as above, HRP=bcrt.
  BECH32_REGT = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
}

print("=== FIX-63 decode_address strict per-network version-byte ===\n")

-- ================================================================== --
-- Section 1 — P2PKH per-network accept                                --
-- ================================================================== --
print("--- Section 1: P2PKH per-network accept ---\n")

test("P2PKH mainnet '1A1zP1...' parses on mainnet", function()
  local t, p = address.decode_address(ADDR.P2PKH_MAIN, "mainnet")
  expect_eq(t, "p2pkh")
  expect_truthy(p)
  expect_eq(#p, 20, "P2PKH program is 20-byte hash160")
end)

test("P2PKH testnet 'm....' parses on testnet", function()
  local t, p = address.decode_address(ADDR.P2PKH_TEST, "testnet")
  expect_eq(t, "p2pkh")
  expect_eq(#p, 20)
end)

test("P2PKH testnet 'm....' parses on regtest (shares testnet prefixes)", function()
  local t, p = address.decode_address(ADDR.P2PKH_TEST, "regtest")
  expect_eq(t, "p2pkh")
end)

test("P2PKH testnet 'm....' parses on signet (shares testnet prefixes)", function()
  local t, p = address.decode_address(ADDR.P2PKH_TEST, "signet")
  expect_eq(t, "p2pkh")
end)

-- ================================================================== --
-- Section 2 — P2PKH cross-network REJECT (the FIX-63 hazard)          --
-- ================================================================== --
print("\n--- Section 2: P2PKH cross-network REJECT ---\n")

test("P2PKH mainnet '1A1zP1...' REJECTED on testnet", function()
  local t, err = address.decode_address(ADDR.P2PKH_MAIN, "testnet")
  expect_nil(t, "wrong-network mainnet P2PKH must be rejected")
  expect_eq(err, "wrong-network address")
end)

test("P2PKH testnet 'm....' REJECTED on mainnet", function()
  local t, err = address.decode_address(ADDR.P2PKH_TEST, "mainnet")
  expect_nil(t, "wrong-network testnet P2PKH must be rejected")
  expect_eq(err, "wrong-network address")
end)

test("P2PKH mainnet REJECTED on regtest", function()
  local t, err = address.decode_address(ADDR.P2PKH_MAIN, "regtest")
  expect_nil(t)
  expect_eq(err, "wrong-network address")
end)

test("P2PKH mainnet REJECTED on signet", function()
  local t, err = address.decode_address(ADDR.P2PKH_MAIN, "signet")
  expect_nil(t)
  expect_eq(err, "wrong-network address")
end)

-- ================================================================== --
-- Section 3 — P2SH per-network accept                                 --
-- ================================================================== --
print("\n--- Section 3: P2SH per-network accept ---\n")

test("P2SH mainnet '3....' parses on mainnet", function()
  local t, p = address.decode_address(ADDR.P2SH_MAIN, "mainnet")
  expect_eq(t, "p2sh")
  expect_eq(#p, 20)
end)

test("P2SH testnet '2....' parses on testnet", function()
  local t, p = address.decode_address(ADDR.P2SH_TEST, "testnet")
  expect_eq(t, "p2sh")
  expect_eq(#p, 20)
end)

test("P2SH testnet '2....' parses on regtest", function()
  local t, p = address.decode_address(ADDR.P2SH_TEST, "regtest")
  expect_eq(t, "p2sh")
end)

-- ================================================================== --
-- Section 4 — P2SH cross-network REJECT                               --
-- ================================================================== --
print("\n--- Section 4: P2SH cross-network REJECT ---\n")

test("P2SH mainnet '3....' REJECTED on testnet", function()
  local t, err = address.decode_address(ADDR.P2SH_MAIN, "testnet")
  expect_nil(t)
  expect_eq(err, "wrong-network address")
end)

test("P2SH testnet '2....' REJECTED on mainnet", function()
  local t, err = address.decode_address(ADDR.P2SH_TEST, "mainnet")
  expect_nil(t)
  expect_eq(err, "wrong-network address")
end)

test("P2SH mainnet REJECTED on regtest", function()
  local t, err = address.decode_address(ADDR.P2SH_MAIN, "regtest")
  expect_nil(t)
  expect_eq(err, "wrong-network address")
end)

-- ================================================================== --
-- Section 5 — Bech32 HRP sanity (regression coverage; pre-existing)   --
-- ================================================================== --
-- segwit_decode already enforces HRP equality.  After FIX-63 the failure
-- mode is a clean "wrong-network address" instead of a base58_decode
-- assert raise (decode_address now probes other-network HRPs before
-- falling through to Base58Check).
print("\n--- Section 5: bech32 HRP sanity ---\n")

test("bech32 mainnet 'bc1...' parses on mainnet", function()
  local t, p = address.decode_address(ADDR.BECH32_MAIN, "mainnet")
  expect_eq(t, "p2wpkh")
  expect_eq(#p, 20)
end)

test("bech32 mainnet 'bc1...' REJECTED on testnet (no assert raise)", function()
  -- Pre-FIX-63: this CRASHED with 'Invalid Base58 character: 0' because
  -- decode_address fell through to base58check_decode after segwit HRP
  -- mismatch.  Post-FIX-63: clean wrong-network error.
  local t, err = address.decode_address(ADDR.BECH32_MAIN, "testnet")
  expect_nil(t)
  expect_eq(err, "wrong-network address")
end)

test("bech32 testnet 'tb1...' parses on testnet", function()
  local t, p = address.decode_address(ADDR.BECH32_TEST, "testnet")
  expect_eq(t, "p2wpkh")
  expect_eq(#p, 20)
end)

test("bech32 testnet 'tb1...' REJECTED on mainnet (no assert raise)", function()
  local t, err = address.decode_address(ADDR.BECH32_TEST, "mainnet")
  expect_nil(t)
  expect_eq(err, "wrong-network address")
end)

test("bech32 regtest 'bcrt1...' parses on regtest", function()
  local t, p = address.decode_address(ADDR.BECH32_REGT, "regtest")
  expect_eq(t, "p2wpkh")
  expect_eq(#p, 20)
end)

test("bech32 regtest 'bcrt1...' REJECTED on mainnet", function()
  local t, err = address.decode_address(ADDR.BECH32_REGT, "mainnet")
  expect_nil(t)
  expect_eq(err, "wrong-network address")
end)

test("bech32 regtest 'bcrt1...' REJECTED on testnet", function()
  -- regtest and testnet have DIFFERENT HRPs (bcrt vs tb) even though
  -- they share Base58 prefixes.
  local t, err = address.decode_address(ADDR.BECH32_REGT, "testnet")
  expect_nil(t)
  expect_eq(err, "wrong-network address")
end)

-- ================================================================== --
-- Section 6 — Regression: in-network callers in wallet.lua still work --
-- ================================================================== --
print("\n--- Section 6: in-network regression coverage ---\n")

-- wallet.lua passes `self.network.name` to decode_address when building
-- outputs.  Each address type x network combination it can receive must
-- still resolve.  This is the same set of in-network combinations that
-- shipped before FIX-63 — we're asserting we didn't break them.
local regression_pairs = {
  -- {address,            network,    expected_type, expected_program_len}
  {ADDR.P2PKH_MAIN,       "mainnet",  "p2pkh",  20},
  {ADDR.P2PKH_TEST,       "testnet",  "p2pkh",  20},
  {ADDR.P2PKH_TEST,       "regtest",  "p2pkh",  20},
  {ADDR.P2PKH_TEST,       "signet",   "p2pkh",  20},
  {ADDR.P2SH_MAIN,        "mainnet",  "p2sh",   20},
  {ADDR.P2SH_TEST,        "testnet",  "p2sh",   20},
  {ADDR.P2SH_TEST,        "regtest",  "p2sh",   20},
  {ADDR.BECH32_MAIN,      "mainnet",  "p2wpkh", 20},
  {ADDR.BECH32_TEST,      "testnet",  "p2wpkh", 20},
  {ADDR.BECH32_REGT,      "regtest",  "p2wpkh", 20},
}

for i, row in ipairs(regression_pairs) do
  local addr, net, expect_t, expect_len = row[1], row[2], row[3], row[4]
  test(string.format("regression[%d]: %s @ %s -> %s", i, addr:sub(1, 16), net, expect_t),
    function()
      local t, p = address.decode_address(addr, net)
      expect_eq(t, expect_t)
      expect_eq(#p, expect_len)
    end)
end

-- ================================================================== --
-- Section 7 — Garbage / unknown still returns nil (not a crash)       --
-- ================================================================== --
print("\n--- Section 7: unknown formats ---\n")

test("unknown garbage returns nil with 'Unknown address format'", function()
  -- 'junk' fails segwit (no bech32 separator and no HRP match) and
  -- happens to be valid Base58 (j,u,n,k all in alphabet) but is too
  -- short for base58check (< 5 bytes after decode); base58check_decode
  -- returns nil "too short" rather than raising.
  local t, err = address.decode_address("junk", "mainnet")
  expect_nil(t)
  expect_truthy(err)
end)

test("network=nil defaults to mainnet (back-compat with existing callers)", function()
  -- Some callers (rpc.lua signmessage) pass network=nil when rpc.network
  -- isn't set up; we must preserve the historical default.
  local t, p = address.decode_address(ADDR.P2PKH_MAIN)  -- no network arg
  expect_eq(t, "p2pkh")
  expect_eq(#p, 20)
end)

test("network=nil rejects testnet address (default-mainnet contract)", function()
  local t, err = address.decode_address(ADDR.P2PKH_TEST)
  expect_nil(t)
  expect_eq(err, "wrong-network address")
end)

-- ================================================================== --
-- Section 8 — bip21.lua workaround removal: BIP-21 cross-network      --
-- still rejects (delegated to decode_address now)                     --
-- ================================================================== --
print("\n--- Section 8: BIP-21 still rejects cross-network ---\n")

local bip21 = require("lunarblock.bip21")

test("BIP-21 testnet addr on mainnet still rejected (FIX-62 behavior preserved)", function()
  local r = bip21.parse("bitcoin:" .. ADDR.P2PKH_TEST, "mainnet")
  expect_truthy(r.err, "BIP-21 must reject cross-network address")
  expect_truthy(r.err:lower():find("not valid for network", 1, true),
                "expected BIP-21 to surface 'not valid for network'")
end)

test("BIP-21 mainnet addr on testnet still rejected (FIX-62 behavior preserved)", function()
  local r = bip21.parse("bitcoin:" .. ADDR.P2PKH_MAIN, "testnet")
  expect_truthy(r.err)
end)

test("BIP-21 mainnet addr on mainnet still ok (regression)", function()
  local r = bip21.parse("bitcoin:" .. ADDR.P2PKH_MAIN, "mainnet")
  expect_nil(r.err)
  expect_eq(r.addr_type, "p2pkh")
end)

test("BIP-21 testnet addr on testnet still ok (regression)", function()
  local r = bip21.parse("bitcoin:" .. ADDR.P2PKH_TEST, "testnet")
  expect_nil(r.err)
  expect_eq(r.addr_type, "p2pkh")
end)

-- ================================================================== --
-- Summary                                                              --
-- ================================================================== --
print(string.format("\n=== FIX-63 decode_address strict network: %d PASS / %d FAIL ===",
                    PASS, FAIL))
if FAIL > 0 then os.exit(1) end
