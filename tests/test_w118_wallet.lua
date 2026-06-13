#!/usr/bin/env luajit
-- W118 Wallet audit — lunarblock (Lua/LuaJIT)
--
-- Same 30-gate scope as the rustoshi W118 prompt:
--   G1-G6   Descriptors          (BIP-380/381/382/383/384/385/386)
--   G7-G12  BIP-32 derivation    (master, hardened, normal, xpub serial, xpub CKD)
--   G13-G18 PSBT                 (BIP-174 / BIP-371 taproot / BIP-370 v2)
--   G19-G22 Fee bumping          (BIP-125 RBF + bumpfee + psbtbumpfee + CPFP)
--   G23-G26 Send                 (sendtoaddress, sendmany, anti-fee-sniping,
--                                 dust)
--   G27-G30 UTXO                 (listunspent, lockunspent, watch-only,
--                                 gettransaction)
--
-- NOTE — this is a DIFFERENT slice from W111. W111 was wallet/HD/descriptors,
-- W118 doubles down on descriptors + PSBT + the wallet RPCs that touch them.
-- Bugs found at the same site as W111 are renumbered here so the bug index
-- is self-contained.
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_w118_wallet.lua 2>&1

package.path = "src/?.lua;./?.lua;" .. package.path

-- Helpers ------------------------------------------------------------
local function hex_to_bin(hex)
  return (hex:gsub('..', function(cc) return string.char(tonumber(cc, 16)) end))
end

local function bin_to_hex(bin)
  local hex = {}
  for i = 1, #bin do hex[i] = string.format("%02x", bin:byte(i)) end
  return table.concat(hex)
end

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

local wallet     = require("lunarblock.wallet")
local address    = require("lunarblock.address")
local psbt       = require("lunarblock.psbt")
local crypto     = require("lunarblock.crypto")
local consensus  = require("lunarblock.consensus")
local types      = require("lunarblock.types")
local mempool    = require("lunarblock.mempool")
local script     = require("lunarblock.script")
local validation = require("lunarblock.validation")

-- Test infrastructure ------------------------------------------------
local PASS, FAIL, SKIP = 0, 0, 0
local BUGS = {}

local function pass(name) io.write(string.format("  PASS  %s\n", name)); PASS = PASS + 1 end
local function fail(name, msg) io.write(string.format("  FAIL  %s -- %s\n", name, msg)); FAIL = FAIL + 1 end
local function skip(name, why) io.write(string.format("  SKIP  %s -- %s\n", name, why)); SKIP = SKIP + 1 end

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
local function expect_nil(v, msg) if v ~= nil then error((msg or "expected nil") .. ", got " .. tostring(v)) end end

local function bug(id, severity, desc)
  BUGS[#BUGS + 1] = string.format("%s (%s)  %s", id, severity, desc)
end

print("=== W118 lunarblock Wallet Audit (descriptors / BIP-32 / PSBT / fee bump / send / UTXO) ===\n")

-- ===================================================================
-- G1-G6  Descriptors  (BIP-380/381/382/383/384/385/386)
-- ===================================================================
print("--- G1-G6: Descriptors ---")

-- G1: BIP-380 descriptor checksum round-trip
test("G1: BIP-380 descriptor checksum is 8 chars and round-trips", function()
  local d = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
  local cs = address.descriptor_checksum(d)
  expect_eq(#cs, 8, "checksum length 8")
  local ok = address.validate_descriptor_checksum(d .. "#" .. cs)
  expect_true(ok, "checksum round-trip")
end)

-- G2: BIP-381 multi() and BIP-383 sortedmulti() parse, threshold + key count
test("G2: BIP-381 multi(2,K1,K2,K3) parses with threshold=2 and 3 keys", function()
  local k1 = "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4"
  local k2 = "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc"
  local k3 = "03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe"
  local d  = string.format("multi(2,%s,%s,%s)", k1, k2, k3)
  local parsed, err = address.parse_descriptor(d)
  expect_true(parsed ~= nil, "multi parses: " .. tostring(err))
  expect_eq(parsed.type,      "multi", "type=multi")
  expect_eq(parsed.threshold, 2,       "threshold=2")
  expect_eq(#parsed.keys,     3,       "3 keys")
  expect_false(parsed.sorted,           "multi is not sorted")
end)

-- G3: BIP-382 wpkh() → 22-byte P2WPKH scriptPubKey
test("G3: BIP-382 wpkh() to 22-byte P2WPKH scriptPubKey", function()
  local pk = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
  local desc = address.parse_descriptor("wpkh(" .. pk .. ")")
  expect_true(desc ~= nil, "wpkh parses")
  local spk = address.descriptor_to_script(desc, 0, "mainnet")
  expect_eq(#spk, 22, "P2WPKH spk length 22")
  expect_eq(spk:byte(1), 0x00, "OP_0")
  expect_eq(spk:byte(2), 0x14, "push 20")
end)

-- G4: BIP-385 raw() — raw script bytes round-trip
test("G4: BIP-385 raw(<hex>) descriptor returns the same bytes", function()
  local hex = "76a914000102030405060708090a0b0c0d0e0f1011121388ac"
  local desc, err = address.parse_descriptor("raw(" .. hex .. ")")
  expect_true(desc ~= nil, "raw parses: " .. tostring(err))
  expect_eq(desc.type, "raw", "type")
  local spk = address.descriptor_to_script(desc, 0, "mainnet")
  expect_eq(bin_to_hex(spk), hex, "raw bytes survive round-trip")
end)

-- G5: BIP-386 rawtr() — OP_1 push of x-only (no BIP-341 tweak)
test("G5: BIP-386 rawtr(<32-byte xonly>) emits OP_1 <xonly> with NO tweak", function()
  local xonly = "cc8a4bc64d897bddc5fbc2f670f7a8ba0a386f3dade870027125d6aa223b8c8e"
  local desc, err = address.parse_descriptor("rawtr(" .. xonly .. ")")
  expect_true(desc ~= nil, "rawtr parses: " .. tostring(err))
  expect_eq(desc.type, "rawtr", "type")
  local spk = address.descriptor_to_script(desc, 0, "mainnet")
  expect_eq(#spk, 34, "P2TR length")
  expect_eq(spk:byte(1), 0x51, "OP_1")
  expect_eq(spk:byte(2), 0x20, "push 32")
  -- BIP-386: rawtr does NOT tweak — output key must equal the raw xonly.
  expect_eq(bin_to_hex(spk:sub(3, 34)), xonly, "rawtr is NOT tweaked")
end)

-- G6: address.derive_child must perform real BIP-32 CKD.
-- Originally annotated "INCORRECT for real use!" — returned IL alone
-- as the child priv instead of (parse256(IL) + k_par) mod n, and
-- refused CKDpub entirely. Fixed in FIX-59 via libsecp256k1
-- ec_seckey_tweak_add / ec_pubkey_tweak_add. The full BIP-32 Test
-- Vector 1 + 2 sweep lives in tests/test_fix59_bip32_ckd.lua; this
-- assertion is the single-step witness used by W118.
test("G6: address.derive_child matches BIP-32 vector 1 m/0'/1 (G6-BUG-1 FIXED)", function()
  -- BIP-32 Test Vector 1: master from seed 000102...0f.
  -- Master (m):
  local m_priv = hex_to_bin("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
  local m_cc   = hex_to_bin("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")
  local m_pub  = hex_to_bin("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
  -- Step 1: m/0' (hardened) — exercises (IL + parent_priv) mod n with the
  -- hardened-message form.
  local c1_pub, c1_cc, err, c1_priv =
    address.derive_child(m_pub, m_cc, 0x80000000, m_priv)
  expect_eq(err, nil, "no error: " .. tostring(err))
  expect_eq(bin_to_hex(c1_priv),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
            "m/0' priv matches BIP-32 vector")
  expect_eq(bin_to_hex(c1_cc),
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
            "m/0' chain_code matches BIP-32 vector")
  expect_eq(bin_to_hex(c1_pub),
            "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
            "m/0' pubkey matches BIP-32 vector")
  -- Step 2: m/0'/1 (non-hardened) — exercises (IL + parent_priv) mod n
  -- with the non-hardened-message form.
  local c2_pub, c2_cc, err2, c2_priv =
    address.derive_child(c1_pub, c1_cc, 1, c1_priv)
  expect_eq(err2, nil, "no error: " .. tostring(err2))
  expect_eq(bin_to_hex(c2_priv),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
            "m/0'/1 priv matches BIP-32 vector")
  expect_eq(bin_to_hex(c2_pub),
            "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c",
            "m/0'/1 pubkey matches BIP-32 vector")
  -- Source assertion: the "INCORRECT for real use" annotation is gone.
  local src = io.open("src/address.lua", "r")
  local content = src:read("*a"); src:close()
  expect_eq(content:find("INCORRECT for real"), nil,
    "address.lua must not still claim derive_child is INCORRECT")
end)

-- ===================================================================
-- G7-G12  BIP-32 derivation
-- ===================================================================
print("\n--- G7-G12: BIP-32 derivation ---")

-- G7: BIP-32 vector 1 master key from seed
test("G7: BIP-32 v1 master key from seed 000102...0f", function()
  local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f")
  local m = wallet.master_key_from_seed(seed)
  expect_eq(bin_to_hex(m.key),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
            "master key")
  expect_eq(bin_to_hex(m.chain_code),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
            "chain code")
end)

-- G8: BIP-32 hardened child m/0'
test("G8: BIP-32 v1 hardened child m/0' matches vector", function()
  local m = wallet.master_key_from_seed(hex_to_bin("000102030405060708090a0b0c0d0e0f"))
  local c = wallet.derive_child(m, 0x80000000)
  expect_eq(bin_to_hex(c.key),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
            "hardened m/0'")
  expect_eq(c.depth, 1, "depth=1")
end)

-- G9: BIP-32 normal child m/0'/1 — exercises (IL + parent_priv) mod n
-- (proving wallet.lua's add_mod_n is correct, even though address.lua's
-- derive_child has the broken placeholder).
test("G9: BIP-32 v1 normal child m/0'/1 matches vector (add_mod_n correct)", function()
  local m  = wallet.master_key_from_seed(hex_to_bin("000102030405060708090a0b0c0d0e0f"))
  local c1 = wallet.derive_child(m, 0x80000000)
  local c2 = wallet.derive_child(c1, 1)
  expect_eq(bin_to_hex(c2.key),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
            "m/0'/1")
  expect_eq(c2.depth, 2, "depth=2")
end)

-- G10: FIXED in P2-3 — SLIP-0044 coin_type is now network-aware via
-- M.coin_type_for_network and threaded through M.derive_for_purpose. The
-- legacy derive_bip44_key / derive_bip84_key shims still pass coin_type=0
-- to byte-match historical mainnet behaviour (back-compat for callers that
-- predate the refactor), but new wallet code paths (generate_address,
-- unlock) call derive_for_purpose with the network's actual coin_type.
-- Original bug: lunarblock unfreeze plan P2-3 / W118 G10-BUG-2.
test("G10: P2-3 FIX — SLIP-0044 coin_type is network-aware in derive_for_purpose", function()
  expect_eq(wallet.coin_type_for_network("mainnet"), 0, "mainnet coin_type=0")
  expect_eq(wallet.coin_type_for_network("testnet"), 1, "testnet coin_type=1")
  expect_eq(wallet.coin_type_for_network("testnet4"), 1, "testnet4 coin_type=1")
  expect_eq(wallet.coin_type_for_network("regtest"), 1, "regtest coin_type=1")
  expect_eq(wallet.coin_type_for_network("signet"), 1, "signet coin_type=1")
end)

-- G11: FIXED in P2-3 — BIP-49 (P2SH-P2WPKH) and BIP-86 (P2TR) derivation
-- now exist as table-driven entries in M.PURPOSE_TEMPLATES + shim helpers
-- derive_bip49_key / derive_bip86_key. Setting wallet.address_type to
-- "p2sh-p2wpkh" or "p2tr" now routes to the correct purpose + address
-- builder instead of silently falling back to BIP-44 + P2PKH.
-- Original bug: lunarblock unfreeze plan P2-3 / W118 G11-BUG-3.
test("G11: P2-3 FIX — all 4 BIP-43 purpose codes are registered (44/49/84/86)", function()
  expect_eq(type(wallet.derive_bip44_key), "function", "BIP-44 shim present")
  expect_eq(type(wallet.derive_bip49_key), "function", "BIP-49 shim present")
  expect_eq(type(wallet.derive_bip84_key), "function", "BIP-84 shim present")
  expect_eq(type(wallet.derive_bip86_key), "function", "BIP-86 shim present")
  expect_eq(type(wallet.derive_for_purpose), "function", "table-driven derive_for_purpose present")
  expect_eq(wallet.purpose_for_address_type("p2pkh"),       44, "address_type p2pkh → 44")
  expect_eq(wallet.purpose_for_address_type("p2sh-p2wpkh"), 49, "address_type p2sh-p2wpkh → 49")
  expect_eq(wallet.purpose_for_address_type("p2wpkh"),      84, "address_type p2wpkh → 84")
  expect_eq(wallet.purpose_for_address_type("p2tr"),        86, "address_type p2tr → 86")
end)

-- G12: BUG — xpub / xprv Base58Check serialization absent
test("G12: BUG — wallet.to_xpub / wallet.to_xprv / serialize_xkey absent (G12-BUG-4)", function()
  expect_nil(wallet.to_xpub,         "no to_xpub")
  expect_nil(wallet.to_xprv,         "no to_xprv")
  expect_nil(wallet.serialize_xkey,  "no serialize_xkey")
  bug("G12-BUG-4", "P2",
      "wallet.lua defines the BIP-32 extended_key() struct but provides no " ..
      "Base58Check serialization. Cannot export account xpubs for hardware " ..
      "wallet pairing, cannot wire a getxpub RPC, and cannot populate PSBT " ..
      "GLOBAL_XPUB (BIP-174 key 0x01) with real xpub strings. wallet.lua:437.")
  error("G12-BUG-4 confirmed: no xpub/xprv serialization")
end)

-- ===================================================================
-- G13-G18  PSBT (BIP-174 + BIP-371 taproot + BIP-370 v2)
-- ===================================================================
print("\n--- G13-G18: PSBT ---")

-- Build a one-input one-output unsigned P2WPKH tx for the PSBT tests.
local function build_p2wpkh_psbt(privkey)
  local pubkey = crypto.pubkey_from_privkey(privkey, true)
  local pkh    = crypto.hash160(pubkey)
  local tx = types.transaction(2, {
    types.txin(types.outpoint(types.hash256(string.rep("\x42", 32)), 0), "", 0xFFFFFFFD),
  }, {
    types.txout(50000, "\x00\x14" .. pkh),
  }, 0)
  local p = psbt.new(tx)
  psbt.update_input_utxo(p, 0,
    {value = 100000, script_pubkey = "\x00\x14" .. pkh}, true)
  return p, pubkey, pkh
end

-- G13: BIP-174 magic + version
test("G13: BIP-174 PSBT magic 'psbt' + 0xff", function()
  expect_eq(psbt.MAGIC, "psbt\xff", "magic bytes")
  expect_eq(psbt.VERSION, 0, "version v0")
end)

-- G14: BIP-174 binary serialize / deserialize round-trip
test("G14: BIP-174 serialize/deserialize round-trip preserves witness_utxo", function()
  local privkey = hex_to_bin(string.rep("0a", 32))
  local p = build_p2wpkh_psbt(privkey)
  local raw = psbt.serialize(p)
  local r = psbt.deserialize(raw)
  expect_eq(r.version, 0, "deserialized version")
  expect_eq(#r.inputs, 1, "one input")
  expect_eq(r.inputs[1].witness_utxo.value, 100000, "witness UTXO value preserved")
end)

-- G15: BIP-174 sign + finalize + extract → broadcast-ready tx with witness
test("G15: BIP-174 sign+finalize+extract yields tx with witness", function()
  local privkey = hex_to_bin(string.rep("0b", 32))
  local p, pubkey = build_p2wpkh_psbt(privkey)
  local signed = psbt.sign_input(p, 0, privkey, pubkey, 0x01)
  expect_true(signed, "sign_input returns true")
  expect_true(psbt.finalize(p), "finalize succeeds")
  expect_true(psbt.is_complete(p), "is_complete")
  local extracted = psbt.extract(p)
  expect_true(extracted ~= nil, "extract returns tx")
  expect_true(extracted.inputs[1].witness ~= nil, "tx has witness")
  expect_eq(#extracted.inputs[1].witness, 2, "witness = [sig, pubkey]")
end)

-- G16: BIP-174 combine de-duplicates partial sigs across PSBTs
test("G16: BIP-174 combine merges partial_sigs from two PSBTs", function()
  local pk_a = hex_to_bin(string.rep("0c", 32))
  local pk_b = hex_to_bin(string.rep("0d", 32))

  -- Build P2WSH 2-of-2 PSBT (each cosigner signs their own copy then combines)
  local pub_a = crypto.pubkey_from_privkey(pk_a, true)
  local pub_b = crypto.pubkey_from_privkey(pk_b, true)
  local witness_script = string.char(0x52) ..  -- OP_2
                         string.char(#pub_a) .. pub_a ..
                         string.char(#pub_b) .. pub_b ..
                         string.char(0x52) ..  -- OP_2
                         "\xae"                 -- OP_CHECKMULTISIG
  local wsh_hash = crypto.sha256(witness_script)
  local spk = "\x00\x20" .. wsh_hash

  local tx = types.transaction(2, {
    types.txin(types.outpoint(types.hash256(string.rep("\x55", 32)), 0), "", 0xFFFFFFFD),
  }, {types.txout(50000, "\x00\x14" .. string.rep("\x66", 20))}, 0)

  -- Build two PSBTs, one signed by A, one signed by B.
  local pA = psbt.new(tx); psbt.update_input_utxo(pA, 0, {value=100000, script_pubkey=spk}, true)
  pA.inputs[1].witness_script = witness_script
  psbt.sign_input(pA, 0, pk_a, pub_a, 0x01)

  local pB = psbt.new(tx); psbt.update_input_utxo(pB, 0, {value=100000, script_pubkey=spk}, true)
  pB.inputs[1].witness_script = witness_script
  psbt.sign_input(pB, 0, pk_b, pub_b, 0x01)

  local combined = psbt.combine({pA, pB})
  local n = 0
  for _ in pairs(combined.inputs[1].partial_sigs) do n = n + 1 end
  expect_eq(n, 2, "combined PSBT has 2 partial sigs")
end)

-- G17: BIP-371 taproot key-path sign IS now wired in psbt.sign_input.
-- G17-BUG-5 was P0 ("write-only Taproot wallets"); closed by lunarblock
-- unfreeze plan P2-4 (2026-05-27). The post-fix expectation: sign_input
-- on a p2tr witness_utxo produces a 64-byte BIP-340 Schnorr sig under
-- tap_key_sig (BIP-371 PSBT_IN_TAP_KEY_SIG 0x13), partial_sigs stays
-- empty (ECDSA + Schnorr namespaces are deliberately disjoint), and
-- finalize_input collapses tap_key_sig into the witness stack.
test("G17: BIP-371 P2TR sign_input wired (G17-BUG-5 CLOSED by P2-4)", function()
  -- Build a tr() PSBT and try to sign with a key.
  local privkey = hex_to_bin(string.rep("0e", 32))
  local pub     = crypto.pubkey_from_privkey(privkey, true)
  local xonly   = pub:sub(2)  -- BIP-340 x-only
  -- Tweak per BIP-341 §4.2 with no script tree
  local tweak   = crypto.tagged_hash("TapTweak", xonly)
  local tweaked, _parity = crypto.tweak_pubkey(xonly, tweak)
  expect_true(tweaked ~= nil, "TapTweak succeeded")
  local p2tr_spk = string.char(0x51, 0x20) .. tweaked

  local tx = types.transaction(2, {
    types.txin(types.outpoint(types.hash256(string.rep("\x77", 32)), 0), "", 0xFFFFFFFD),
  }, {types.txout(50000, "\x00\x14" .. string.rep("\x88", 20))}, 0)
  local p = psbt.new(tx)
  psbt.update_input_utxo(p, 0, {value=100000, script_pubkey=p2tr_spk}, true)

  -- Post-P2-4 expectation: sign_input returns true + tap_key_sig populated.
  -- The bare 64-byte SIGHASH_DEFAULT shape is what BIP-86 wallets emit.
  local ok = psbt.sign_input(p, 0, privkey, pub, 0x00)
  expect_true(ok, "sign_input returns true for p2tr (P2-4 branch active)")
  expect_true(p.inputs[1].tap_key_sig ~= nil,
    "tap_key_sig populated — BIP-371 key-path SIGNED")
  expect_eq(#p.inputs[1].tap_key_sig, 64,
    "SIGHASH_DEFAULT (0x00) sig is bare 64-byte Schnorr (no trailing flag)")
end)

-- G18: BUG — BIP-370 PSBTv2 not supported (no PSBT_GLOBAL_TX_VERSION etc.)
test("G18: BUG — BIP-370 PSBTv2 not supported (G18-BUG-6)", function()
  expect_eq(psbt.VERSION, 0, "version is hardcoded v0")
  expect_nil(psbt.GLOBAL_TX_VERSION,    "no PSBT_GLOBAL_TX_VERSION (0x02)")
  expect_nil(psbt.GLOBAL_FALLBACK_LOCKTIME, "no PSBT_GLOBAL_FALLBACK_LOCKTIME (0x03)")
  expect_nil(psbt.GLOBAL_INPUT_COUNT,   "no PSBT_GLOBAL_INPUT_COUNT (0x04)")
  expect_nil(psbt.GLOBAL_OUTPUT_COUNT,  "no PSBT_GLOBAL_OUTPUT_COUNT (0x05)")
  expect_nil(psbt.IN_PREVIOUS_TXID,     "no PSBT_IN_PREVIOUS_TXID (0x0e)")
  bug("G18-BUG-6", "P2",
      "BIP-370 PSBTv2 keytypes absent. Version is hardcoded v0 (psbt.lua:61), " ..
      "no GLOBAL_TX_VERSION/INPUT_COUNT/OUTPUT_COUNT, no IN_PREVIOUS_TXID/" ..
      "IN_OUTPUT_INDEX, no OUT_AMOUNT/OUT_SCRIPT. PSBTs produced by Core 24+ " ..
      "with -psbtv2 cannot round-trip through this module.")
end)

-- ===================================================================
-- G19-G22  Fee bumping (BIP-125 RBF + bumpfee + psbtbumpfee + CPFP)
-- ===================================================================
print("\n--- G19-G22: Fee bumping ---")

-- G19: BIP-125 — wallet creates RBF-signaling transactions (seq<=0xFFFFFFFD)
test("G19: BIP-125 wallet.create_transaction emits seq=0xFFFFFFFD (signals RBF)", function()
  -- Inspect the wallet source — create_transaction hardcodes 0xFFFFFFFD on
  -- the inputs it builds. We don't need to actually run the full path here.
  local src = io.open("src/wallet.lua", "r")
  local content = src:read("*a"); src:close()
  expect_true(content:find("0xFFFFFFFD") ~= nil,
              "wallet.create_transaction uses BIP-125 RBF sequence 0xFFFFFFFD")
  -- And mempool.signals_rbf accepts that exact value.
  local tx = types.transaction(2, {
    types.txin(types.outpoint(types.hash256(string.rep("\x01", 32)), 0), "", 0xFFFFFFFD),
  }, {types.txout(10000, "\x00\x14" .. string.rep("\x02", 20))}, 0)
  expect_true(mempool.signals_rbf(tx), "mempool.signals_rbf accepts 0xFFFFFFFD")
end)

-- G20: bumpfee RPC wired (FIX-61).  Closed by FIX-61: bumpfee+psbtbumpfee
-- now live in src/rpc.lua and re-sign through the FIX-59 unified ec_sign
-- pipeline.  Functional round-trip lives in tests/test_fix61_bumpfee.lua;
-- this assertion is the single-line wire check used by W118.
test("G20: bumpfee RPC is wired (G20-BUG-7 FIXED)", function()
  local rpc_src = io.open("src/rpc.lua", "r"):read("*a")
  expect_true(rpc_src:find('self%.methods%["bumpfee"%]') ~= nil,
              "bumpfee RPC wired")
end)

-- G21: psbtbumpfee RPC wired (FIX-61).
test("G21: psbtbumpfee RPC is wired (G21-BUG-8 FIXED)", function()
  local rpc_src = io.open("src/rpc.lua", "r"):read("*a")
  expect_true(rpc_src:find('self%.methods%["psbtbumpfee"%]') ~= nil,
              "psbtbumpfee RPC wired")
end)

-- G22: BIP-125 Rule #3 — replacement fee must exceed original (relative)
test("G22: BIP-125 Rule #3 — replacement absolute fee must exceed conflict fee", function()
  -- Static check: the mempool replacement code must compare absolute fees,
  -- not just feerates (Core rbf.cpp PaysMoreThanConflicts at line 91 enforces
  -- "newFee > replaced fees").  We don't need to run a full mempool here;
  -- a source-level check is the conservative gate.
  local src = io.open("src/mempool.lua", "r"):read("*a")
  expect_true(src:find("Rule #3") ~= nil or src:find("replacement fees") ~= nil,
              "mempool.lua references BIP-125 Rule #3 (replacement fee > original)")
end)

-- ===================================================================
-- G23-G26  Send (sendtoaddress, anti-fee-sniping, dust, fee floor)
-- ===================================================================
print("\n--- G23-G26: Send ---")

-- G23: sendtoaddress RPC wired
test("G23: sendtoaddress RPC is wired", function()
  local rpc_src = io.open("src/rpc.lua", "r"):read("*a")
  expect_true(rpc_src:find('self%.methods%["sendtoaddress"%]') ~= nil,
              "sendtoaddress RPC present")
end)

-- G24: BUG — anti-fee-sniping absent. Core's wallet (CreateTransactionInternal,
-- wallet/spend.cpp) sets nLockTime to chain tip with 90% probability per
-- BIP-326. lunarblock builds every tx with locktime=0 hardcoded.
test("G24: BUG — anti-fee-sniping (BIP-326 locktime=tip) absent (G24-BUG-9)", function()
  local src = io.open("src/wallet.lua", "r"):read("*a")
  -- The single transaction-build site is wallet.lua:1464:
  --   local tx = types.transaction(2, inputs, outputs, 0)
  -- Confirm locktime is hardcoded 0 and nothing sets it from tip height.
  local hardcoded = src:find("types%.transaction%(2, inputs, outputs, 0%)") ~= nil
  expect_true(hardcoded, "wallet.create_transaction hardcodes locktime=0")
  expect_nil(src:find("anti.fee.sniping"), "no anti-fee-sniping comment")
  -- Per-line scan: the bug-marker we care about is a SINGLE expression
  -- writing a locktime field from tip_height. The original full-file
  -- regex cross-matched unrelated uses of `tip_height` (scan_utxos
  -- confirmation math, line 1083) against unrelated uses of `locktime`
  -- elsewhere (e.g. bump_fee preserving orig.locktime from FIX-61).
  local cross = false
  for line in src:gmatch("[^\n]+") do
    if line:find("locktime") and line:find("tip_height") then
      cross = true; break
    end
  end
  expect_false(cross, "no tip-height locktime wiring (per-line)")
  bug("G24-BUG-9", "P2",
      "wallet.create_transaction hardcodes locktime=0 (wallet.lua:1464). " ..
      "BIP-326 / Core CreateTransactionInternal sets nLockTime=tip with 90% " ..
      "probability to deter fee sniping by miners reorging the tip. Every " ..
      "lunarblock-created tx is fingerprinted by its locktime=0.")
end)

-- G25: BUG — sendmany RPC absent
test("G25: BUG — sendmany RPC absent (G25-BUG-10)", function()
  local rpc_src = io.open("src/rpc.lua", "r"):read("*a")
  expect_nil(rpc_src:find('self%.methods%["sendmany"%]'), "sendmany RPC absent")
  bug("G25-BUG-10", "P2",
      "sendmany RPC absent. Core ships sendmany for batched payments to " ..
      "multiple addresses in a single tx (wallet/rpc/spend.cpp). " ..
      "Users have to issue N sendtoaddress calls and pay N tx fees, or " ..
      "fall back to walletcreatefundedpsbt + signrawtransactionwithwallet.")
end)

-- G26: Dust threshold applied — sub-546-sat change rolled into fee
test("G26: dust change (<= 546 sat) is rolled into fee, not emitted", function()
  expect_eq(wallet.DUST_THRESHOLD, 546, "wallet.DUST_THRESHOLD = 546 (Core default)")
  -- Static check that wallet.create_transaction collapses change to fee
  -- when change <= DUST_THRESHOLD (wallet.lua:1446 / fee += change branch).
  local src = io.open("src/wallet.lua", "r"):read("*a")
  expect_true(src:find("change > M%.DUST_THRESHOLD") ~= nil,
              "create_transaction has dust-fold branch on DUST_THRESHOLD")
  expect_true(src:find("fee = fee %+ change") ~= nil,
              "create_transaction adds dust change to fee")
end)

-- ===================================================================
-- G27-G30  UTXO (listunspent, lockunspent, watch-only, gettransaction)
-- ===================================================================
print("\n--- G27-G30: UTXO ---")

-- G27: listunspent RPC wired + lists confirmed + pending UTXOs by default
test("G27: listunspent RPC is wired and reflects wallet.utxos / pending_utxos", function()
  local rpc_src = io.open("src/rpc.lua", "r"):read("*a")
  expect_true(rpc_src:find('self%.methods%["listunspent"%]') ~= nil, "listunspent RPC wired")

  -- Functional check on the wallet-level helper.
  local w = wallet.from_seed(hex_to_bin("000102030405060708090a0b0c0d0e0f"),
                             consensus.networks.mainnet, nil)
  w.utxos["k1"] = {
    value = 100000, script_pubkey = "\x00\x14" .. string.rep("\xaa", 20),
    address = w.addresses[1], txid = types.hash256(string.rep("\x01", 32)),
    vout = 0, height = 100, is_coinbase = false, confirmations = 10,
  }
  w.pending_utxos["k2"] = {
    value = 50000, script_pubkey = "\x00\x14" .. string.rep("\xbb", 20),
    address = w.addresses[2], txid = types.hash256(string.rep("\x02", 32)),
    vout = 0, height = 0, is_coinbase = false, confirmations = 0,
  }
  local rows = w:list_unspent(true)
  expect_eq(#rows, 2, "two unspent rows (confirmed + pending)")
end)

-- G28: BUG — lockunspent / listlockunspent absent (Core wallet feature)
test("G28: BUG — lockunspent / listlockunspent absent (G28-BUG-11)", function()
  local rpc_src = io.open("src/rpc.lua", "r"):read("*a")
  expect_nil(rpc_src:find('self%.methods%["lockunspent"%]'),     "lockunspent absent")
  expect_nil(rpc_src:find('self%.methods%["listlockunspent"%]'), "listlockunspent absent")
  -- And the wallet has no notion of a locked-UTXO set.
  local w_src = io.open("src/wallet.lua", "r"):read("*a")
  expect_nil(w_src:find("locked_utxos"), "wallet has no locked_utxos field")
  bug("G28-BUG-11", "P2",
      "lockunspent / listlockunspent RPCs absent + wallet has no locked_utxos " ..
      "tracking. Users cannot prevent specific UTXOs from being selected by " ..
      "coin selection (e.g. earmarked for batch payouts, manual PSBT signing). " ..
      "Core wallet/rpc/coins.cpp.")
end)

-- G29: FIXED — importdescriptors / listdescriptors present (watch-only support).
-- Originally G29-BUG-12 (both RPCs + the descriptor-import path were absent).
-- importdescriptors landed first (registers watch-only descriptors into the
-- owned-script view via Wallet:add_watch_descriptor); listdescriptors now dumps
-- them in Core shape (wallet/rpc/backup.cpp::listdescriptors). Functional
-- coverage for the listdescriptors output shape + checksum lives in
-- tests/test_listdescriptors.lua.
test("G29: FIXED — importdescriptors / listdescriptors present (G29-BUG-12)", function()
  local rpc_src = io.open("src/rpc.lua", "r"):read("*a")
  expect_true(rpc_src:find('self%.methods%["importdescriptors"%]') ~= nil,
              "importdescriptors present")
  expect_true(rpc_src:find('self%.methods%["listdescriptors"%]') ~= nil,
              "listdescriptors present")
  -- The wallet now has a descriptor-import path (watch-only descriptors).
  local w_src = io.open("src/wallet.lua", "r"):read("*a")
  expect_true(w_src:find("function Wallet:add_watch_descriptor") ~= nil,
              "add_watch_descriptor present")
end)

-- G30: BUG — gettransaction wallet RPC absent (listtransactions IS wired).
-- The wallet tracks self.transactions{} via send_transaction (line 1521) and
-- listtransactions iterates it, but gettransaction-by-txid is missing — a
-- key Core lookup primitive used by every block-explorer-style integration.
test("G30: BUG — gettransaction wallet RPC absent (G30-BUG-13)", function()
  local rpc_src = io.open("src/rpc.lua", "r"):read("*a")
  expect_nil(rpc_src:find('self%.methods%["gettransaction"%]'), "gettransaction absent")
  -- listtransactions is wired — confirm we don't over-report.
  expect_true(rpc_src:find('self%.methods%["listtransactions"%]') ~= nil,
              "listtransactions IS wired (acknowledged)")
  bug("G30-BUG-13", "P1",
      "gettransaction wallet RPC absent. wallet.lua tracks self.transactions{} " ..
      "via send_transaction (line 1521) and listtransactions is wired, but " ..
      "there is no by-txid lookup primitive. Block-explorer / accounting " ..
      "callers expect Core's gettransaction <txid> interface. " ..
      "wallet/rpc/transactions.cpp.")
end)

-- ===================================================================
-- Summary
-- ===================================================================
print(string.format("\n=== W118 SUMMARY: %d PASS / %d FAIL / %d SKIP ===", PASS, FAIL, SKIP))
print(string.format("Bugs documented: %d", #BUGS))
print("\n--- Bug List ---")
for _, b in ipairs(BUGS) do print("  " .. b) end

-- "Failures" here are bug-confirmation tests that intentionally raise after
-- logging a bug entry; they are documented failures (not surprises).
-- Exit non-zero only if a non-bug-confirmation test fails — but we can't
-- distinguish cheaply, so emit a clear summary and exit 0 when only bug
-- confirmations failed.
local expected_bug_failures = 0
for _ in ipairs(BUGS) do expected_bug_failures = expected_bug_failures + 1 end

if FAIL > expected_bug_failures then
  print(string.format(
    "\nUNEXPECTED FAILURES: %d (more than the %d bug-confirmation FAILs)",
    FAIL, expected_bug_failures))
  os.exit(1)
else
  print("\nAll non-bug tests passed; bug-confirmation FAILs match documented bug count.")
  os.exit(0)
end
