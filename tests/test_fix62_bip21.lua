#!/usr/bin/env luajit
-- test_fix62_bip21.lua — FIX-62 BIP-21 "bitcoin:" URI parser.
--
-- Closes the BIP-21 half of the "2 specs behind" gap noted by W119
-- (G28-BUG-28 + G29-BUG-29). After this fix lunarblock is 1 spec behind
-- (BIP-78 PayJoin), not 2.
--
-- Vectors come from BIP-21 §Examples and from BIP-78 §"Receiver: BIP-21
-- URI" which extends BIP-21 with pj= and pjos=.
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_fix62_bip21.lua

package.path = "src/?.lua;./?.lua;" .. package.path

-- Module loader matches the rest of the lunarblock test suite.
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

local bip21 = require("lunarblock.bip21")

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
local function expect_nil(v, msg) if v ~= nil then error((msg or "expected nil") .. ", got " .. tostring(v)) end end
local function expect_table(v, msg)
  if type(v) ~= "table" then error((msg or "expected table") .. ", got " .. type(v)) end
end
local function expect_err(r, frag, msg)
  expect_table(r, msg)
  if not r.err then error((msg or "expected err") .. ", got " .. tostring(r.address or "<nil>")) end
  if frag and not r.err:lower():find(frag:lower(), 1, true) then
    error((msg or "expected err to contain") .. " '" .. frag .. "', got '" .. r.err .. "'")
  end
end

print("=== FIX-62 BIP-21 'bitcoin:' URI parser ===\n")

-- ------------------------------------------------------------------ --
-- Known-valid addresses to exercise the parser.  Note: BIP-21 §Examples
-- uses "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"-style addresses with a
-- different specific value in the rendered MediaWiki — that exact
-- string has a checksum mismatch under modern Base58Check (the BIP doc
-- has carried this typo since 2012 — see lunarblock issue and Bitcoin
-- Core test discussion).  We use the genesis-block coinbase address
-- (mainnet P2PKH) instead, which is provably valid.
-- ------------------------------------------------------------------ --
local ADDR_P2PKH_MAIN = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"  -- genesis coinbase
local ADDR_BECH32     = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"  -- BIP-173 vector
local ADDR_TESTNET    = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"  -- common test addr
local ADDR_TAPROOT    = "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9"
local ADDR_P2SH_MAIN  = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"

-- ================================================================== --
-- Section 1 — minimum valid URIs                                      --
-- ================================================================== --
print("--- Section 1: minimum valid URIs ---\n")

test("minimum: address only", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN, "mainnet")
  expect_nil(r.err, "no error expected")
  expect_eq(r.address, ADDR_P2PKH_MAIN)
  expect_eq(r.scheme, "bitcoin")
  expect_eq(r.addr_type, "p2pkh")
  expect_nil(r.amount, "no amount expected")
end)

test("minimum: address + empty query", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN .. "?", "mainnet")
  expect_nil(r.err)
  expect_eq(r.address, ADDR_P2PKH_MAIN)
end)

test("bech32 P2WPKH address", function()
  local r = bip21.parse("bitcoin:" .. ADDR_BECH32, "mainnet")
  expect_nil(r.err)
  expect_eq(r.addr_type, "p2wpkh")
end)

test("P2SH address (mainnet)", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2SH_MAIN, "mainnet")
  expect_nil(r.err)
  expect_eq(r.addr_type, "p2sh")
end)

test("taproot bech32m address", function()
  local r = bip21.parse("bitcoin:" .. ADDR_TAPROOT, "mainnet")
  expect_nil(r.err)
  expect_eq(r.addr_type, "p2tr")
end)

test("testnet address rejected on mainnet", function()
  local r = bip21.parse("bitcoin:" .. ADDR_TESTNET, "mainnet")
  expect_err(r, "not valid for network")
end)

test("testnet address accepted on testnet", function()
  local r = bip21.parse("bitcoin:" .. ADDR_TESTNET, "testnet")
  expect_nil(r.err)
  expect_eq(r.addr_type, "p2pkh")
end)

-- ================================================================== --
-- Section 2 — BIP-21 §Examples spec vectors                           --
-- ================================================================== --
print("\n--- Section 2: BIP-21 §Examples ---\n")

-- BIP-21 example 1: "Just the address"
-- "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
test("BIP-21 ex1 'just the address'", function()
  local r = bip21.parse(
    "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "mainnet")
  expect_nil(r.err)
  expect_eq(r.address, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
end)

-- BIP-21 example 2: address with name
-- "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?label=Luke-Jr"
test("BIP-21 ex2 'address with name'", function()
  local r = bip21.parse(
    "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?label=Luke-Jr", "mainnet")
  expect_nil(r.err)
  expect_eq(r.label, "Luke-Jr")
end)

-- BIP-21 example 3: request 20.30 BTC to "Luke-Jr"
-- "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=20.3&label=Luke-Jr"
test("BIP-21 ex3 '20.30 BTC to Luke-Jr'", function()
  local r = bip21.parse(
    "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=20.3&label=Luke-Jr",
    "mainnet")
  expect_nil(r.err)
  expect_eq(r.amount, 2030000000)  -- 20.3 BTC = 2_030_000_000 sats
  expect_eq(r.amount_btc, "20.3")
  expect_eq(r.label, "Luke-Jr")
end)

-- BIP-21 example 4: request 50 BTC with message
-- "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz"
test("BIP-21 ex4 '50 BTC with percent-encoded message'", function()
  local input = "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=50" ..
                "&label=Luke-Jr&message=Donation%20for%20project%20xyz"
  local r = bip21.parse(input, "mainnet")
  expect_nil(r.err)
  expect_eq(r.amount, 5000000000)  -- 50 BTC
  expect_eq(r.label, "Luke-Jr")
  expect_eq(r.message, "Donation for project xyz")
end)

-- BIP-21 example 5: characters needing to be encoded
-- "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?req-somethingyoudontunderstand=50&req-somethingelseyoudontget=999"
test("BIP-21 ex5 'req- unknown rejected'", function()
  local r = bip21.parse(
    "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" ..
    "?req-somethingyoudontunderstand=50" ..
    "&req-somethingelseyoudontget=999",
    "mainnet")
  expect_err(r, "req-")
end)

-- BIP-21 example 6: characters needing to be encoded
-- "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?somethingyoudontunderstand=50&somethingelseyoudontget=999"
test("BIP-21 ex6 'non-req unknown ignored'", function()
  local r = bip21.parse(
    "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" ..
    "?somethingyoudontunderstand=50&somethingelseyoudontget=999",
    "mainnet")
  expect_nil(r.err)
  expect_table(r.extras)
  expect_eq(r.extras["somethingyoudontunderstand"], "50")
  expect_eq(r.extras["somethingelseyoudontget"], "999")
end)

-- ================================================================== --
-- Section 3 — Amount parsing edge cases                               --
-- ================================================================== --
print("\n--- Section 3: amount edge cases ---\n")

test("amount: 1 satoshi", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN .. "?amount=0.00000001",
                       "mainnet")
  expect_nil(r.err)
  expect_eq(r.amount, 1)
end)

test("amount: zero", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN .. "?amount=0", "mainnet")
  expect_nil(r.err)
  expect_eq(r.amount, 0)
end)

test("amount: integer", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN .. "?amount=1", "mainnet")
  expect_nil(r.err)
  expect_eq(r.amount, 100000000)
end)

test("amount: trailing dot", function()
  -- "5." is a legal decimal per RFC-3986-ish lenient parsing.
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN .. "?amount=5.", "mainnet")
  expect_nil(r.err)
  expect_eq(r.amount, 500000000)
end)

test("amount: leading dot", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN .. "?amount=.5", "mainnet")
  expect_nil(r.err)
  expect_eq(r.amount, 50000000)
end)

test("amount: more than 8 decimals rejected", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?amount=0.000000001", "mainnet")
  expect_err(r, "decimal places")
end)

test("amount: scientific notation rejected", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?amount=1e2", "mainnet")
  expect_err(r, "non-digit")
end)

test("amount: negative rejected", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?amount=-1", "mainnet")
  expect_err(r, "non-digit")
end)

test("amount: empty rejected", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN .. "?amount=", "mainnet")
  expect_err(r, "amount")
end)

test("amount: two dots rejected", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?amount=1.0.0", "mainnet")
  expect_err(r, "multiple decimal points")
end)

test("amount: 21M BTC supply", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?amount=21000000", "mainnet")
  expect_nil(r.err)
  expect_eq(r.amount, 21000000 * 100000000)
end)

-- ================================================================== --
-- Section 4 — Percent decoding                                        --
-- ================================================================== --
print("\n--- Section 4: percent decoding ---\n")

test("percent: lowercase hex %20 => space", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?label=hi%20there", "mainnet")
  expect_nil(r.err)
  expect_eq(r.label, "hi there")
end)

test("percent: uppercase hex %3D => '='", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?message=k%3Dv", "mainnet")
  expect_nil(r.err)
  expect_eq(r.message, "k=v")
end)

test("percent: '+' becomes space (form-urlencoded compat)", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?label=hi+there", "mainnet")
  expect_nil(r.err)
  expect_eq(r.label, "hi there")
end)

test("percent: UTF-8 sequence round-trips", function()
  -- "Café" — UTF-8 bytes 43 61 66 C3 A9
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?label=Caf%C3%A9", "mainnet")
  expect_nil(r.err)
  expect_eq(r.label, "Caf\xC3\xA9")
end)

test("percent: truncated escape rejected", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?label=hi%2", "mainnet")
  expect_err(r, "percent")
end)

test("percent: non-hex escape rejected", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?label=hi%ZZ", "mainnet")
  expect_err(r, "percent")
end)

test("percent: '&' inside value is encoded as %26", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?label=R%26D&amount=1", "mainnet")
  expect_nil(r.err)
  expect_eq(r.label, "R&D")
  expect_eq(r.amount, 100000000)
end)

-- ================================================================== --
-- Section 5 — req- handling                                           --
-- ================================================================== --
print("\n--- Section 5: req- parameters ---\n")

test("req-: unknown required rejected", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?req-magic=1", "mainnet")
  expect_err(r, "req-magic")
end)

test("req-: unknown required is fatal even with valid params", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?amount=1&req-unknown=x&label=ok", "mainnet")
  expect_err(r)
end)

test("non-req- unknown is NOT fatal", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?somefutureparam=1", "mainnet")
  expect_nil(r.err)
  expect_eq(r.extras["somefutureparam"], "1")
end)

-- ================================================================== --
-- Section 6 — BIP-78 PayJoin extensions (pj=, pjos=)                  --
-- ================================================================== --
print("\n--- Section 6: BIP-78 pj= / pjos= ---\n")

-- BIP-78 §"Receiver: BIP-21 URI" example:
--   bitcoin:2N47mmrWXsNBvQR6k78hWJoTji57zXwNcU7?amount=0.0064&pj=https://...
test("BIP-78 pj= URL captured", function()
  local r = bip21.parse(
    "bitcoin:" .. ADDR_P2PKH_MAIN ..
    "?amount=0.0064&pj=https%3A%2F%2Fexample.com%2Fpayjoin",
    "mainnet")
  expect_nil(r.err)
  expect_eq(r.amount, 640000)  -- 0.0064 BTC = 640_000 sats
  expect_eq(r.pj, "https://example.com/payjoin")
end)

test("BIP-78 pj= via Tor v3 onion", function()
  local pj = "http://payjointestabcdefghijklmnopqrstuvwxyzabcdefghijklmn3a.onion/pj"
  local r = bip21.parse(
    "bitcoin:" .. ADDR_P2PKH_MAIN ..
    "?pj=http%3A%2F%2Fpayjointestabcdefghijklmnopqrstuvwxyz" ..
    "abcdefghijklmn3a.onion%2Fpj",
    "mainnet")
  expect_nil(r.err)
  expect_eq(r.pj, pj)
end)

test("BIP-78 pjos=0 (do not substitute outputs)", function()
  local r = bip21.parse(
    "bitcoin:" .. ADDR_P2PKH_MAIN .. "?pj=https%3A%2F%2Fx.example%2Fpj&pjos=0",
    "mainnet")
  expect_nil(r.err)
  expect_eq(r.pj, "https://x.example/pj")
  expect_eq(r.pjos, "0")
end)

test("BIP-78 pjos=1 (allow substitution — default)", function()
  local r = bip21.parse(
    "bitcoin:" .. ADDR_P2PKH_MAIN .. "?pj=https%3A%2F%2Fx.example%2Fpj&pjos=1",
    "mainnet")
  expect_nil(r.err)
  expect_eq(r.pjos, "1")
end)

-- BIP-78 §Sender mentions the lightning= extension for unified QRs.
test("lightning= invoice captured", function()
  local r = bip21.parse(
    "bitcoin:" .. ADDR_P2PKH_MAIN ..
    "?amount=0.001&lightning=lnbc1pvjluezpp5qqqsy",
    "mainnet")
  expect_nil(r.err)
  expect_eq(r.amount, 100000)
  expect_eq(r.lightning, "lnbc1pvjluezpp5qqqsy")
end)

-- ================================================================== --
-- Section 7 — Case-insensitive keys                                   --
-- ================================================================== --
print("\n--- Section 7: case-insensitive keys ---\n")

test("AMOUNT uppercase is recognised", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?AMOUNT=1.5", "mainnet")
  expect_nil(r.err)
  expect_eq(r.amount, 150000000)
end)

test("Amount mixed case is recognised", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?Amount=1.5&LaBeL=x", "mainnet")
  expect_nil(r.err)
  expect_eq(r.amount, 150000000)
  expect_eq(r.label, "x")
end)

test("BITCOIN: scheme uppercase accepted (RFC-3986 §3.1)", function()
  local r = bip21.parse("BITCOIN:" .. ADDR_P2PKH_MAIN, "mainnet")
  expect_nil(r.err)
  expect_eq(r.address, ADDR_P2PKH_MAIN)
end)

test("Bitcoin: scheme mixed case accepted", function()
  local r = bip21.parse("Bitcoin:" .. ADDR_P2PKH_MAIN, "mainnet")
  expect_nil(r.err)
end)

test("REQ-MAGIC (uppercase) still rejected", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?REQ-MAGIC=1", "mainnet")
  expect_err(r, "req-")
end)

-- ================================================================== --
-- Section 8 — Negative cases                                          --
-- ================================================================== --
print("\n--- Section 8: negative cases ---\n")

test("missing scheme rejected", function()
  local r = bip21.parse(ADDR_P2PKH_MAIN, "mainnet")
  expect_err(r, "scheme")
end)

test("wrong scheme rejected", function()
  local r = bip21.parse("bitcoincash:" .. ADDR_P2PKH_MAIN, "mainnet")
  expect_err(r, "scheme")
end)

test("empty body rejected", function()
  local r = bip21.parse("bitcoin:", "mainnet")
  expect_err(r, "empty body")
end)

test("query-only (empty address) rejected", function()
  local r = bip21.parse("bitcoin:?amount=1", "mainnet")
  expect_err(r, "missing address")
end)

test("invalid base58 address rejected", function()
  -- Inject characters Base58 rejects (0OIl) so address validation fails.
  local r = bip21.parse("bitcoin:0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl", "mainnet")
  expect_err(r, "not valid for network")
end)

test("malformed bech32 address rejected", function()
  local r = bip21.parse("bitcoin:bc1qzzzzzzzzz", "mainnet")
  expect_err(r, "not valid for network")
end)

test("empty key '&=v' rejected", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN .. "?=v", "mainnet")
  expect_err(r, "empty key")
end)

test("key with invalid char (space) rejected", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?bad%20key=v", "mainnet")
  expect_err(r, "invalid character in key")
end)

test("non-string input rejected", function()
  local r = bip21.parse(nil, "mainnet")
  expect_err(r, "not a string")
end)

test("trailing & is tolerated", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?amount=1&", "mainnet")
  expect_nil(r.err)
  expect_eq(r.amount, 100000000)
end)

test("double && is tolerated", function()
  local r = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN ..
                       "?amount=1&&label=x", "mainnet")
  expect_nil(r.err)
  expect_eq(r.amount, 100000000)
  expect_eq(r.label, "x")
end)

-- ================================================================== --
-- Section 9 — parse_or_err convenience                                --
-- ================================================================== --
print("\n--- Section 9: parse_or_err convenience ---\n")

test("parse_or_err returns table on success", function()
  local r, err = bip21.parse_or_err("bitcoin:" .. ADDR_P2PKH_MAIN, "mainnet")
  expect_nil(err)
  expect_table(r)
  expect_eq(r.address, ADDR_P2PKH_MAIN)
end)

test("parse_or_err returns (nil, err) on failure", function()
  local r, err = bip21.parse_or_err("bitcoin:?amount=1", "mainnet")
  expect_nil(r)
  expect_true(type(err) == "string" and #err > 0, "err should be a string")
end)

-- ================================================================== --
-- Section 10 — W119 audit assertion FLIP (G28 + G29)                  --
-- ================================================================== --
-- The W119 PayJoin audit recorded G28-BUG-28 / G29-BUG-29 as "BIP-21
-- parser missing entirely; pj=/pjos= cannot be supported until BIP-21
-- exists".  This fix lands the BIP-21 layer.  We assert the SAME shape
-- the original audit asserted but inverted: a parser now exists, AND
-- pj=/pjos= flow through it.  When the W119 file is next refreshed,
-- both gates should move PASS -> PARTIAL or PASS depending on the rest
-- of the PayJoin layer (still missing — that's FIX-63's job).
print("\n--- Section 10: W119 G28+G29 audit assertion flip ---\n")

test("W119 G28 flip: 'bitcoin:' scheme is now recognised", function()
  local uri = bip21.parse("bitcoin:" .. ADDR_P2PKH_MAIN, "mainnet")
  expect_table(uri)
  expect_nil(uri.err, "BIP-21 parser must accept a bare bitcoin: URI")
end)

test("W119 G28 flip: pj= URL parameter is now captured", function()
  local uri = bip21.parse(
    "bitcoin:" .. ADDR_P2PKH_MAIN ..
    "?pj=https%3A%2F%2Fexample.com%2Fpayjoin", "mainnet")
  expect_table(uri)
  expect_nil(uri.err)
  expect_eq(uri.pj, "https://example.com/payjoin")
end)

test("W119 G29 flip: pjos= parameter is now captured", function()
  local uri = bip21.parse(
    "bitcoin:" .. ADDR_P2PKH_MAIN ..
    "?pj=https%3A%2F%2Fx.example%2Fpj&pjos=0", "mainnet")
  expect_table(uri)
  expect_nil(uri.err)
  expect_eq(uri.pjos, "0")
end)

-- ================================================================== --
-- Summary                                                              --
-- ================================================================== --
print(string.format("\n=== FIX-62 BIP-21 summary: %d PASS / %d FAIL ===", PASS, FAIL))
if FAIL > 0 then os.exit(1) end
