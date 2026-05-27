#!/usr/bin/env luajit
-- test_p2_4_p2tr_signer.lua — Phase 2 unfreeze fix P2-4.
--
-- P2-4 ("Wire Taproot (BIP-86) signer"): wallet + PSBT signers must
-- produce a valid Schnorr signature for a P2TR key-path input.  Before
-- this fix the wallet's `_sign_inputs` fell through to the legacy ECDSA
-- branch for `key_info.type == "p2tr"`, emitting a DER-encoded ECDSA sig
-- the network rejects on a v1 segwit output.  PSBT `sign_input` returned
-- `false` ("Unsupported script type") for any P2TR input, so a wallet
-- could deposit to a BIP-86 address but could never spend.  That's the
-- "write-only Taproot wallets" P0 from the W161 audit + the 2026-05-19
-- impl-triage decision.
--
-- This test exercises:
--   T1  sign_input_p2tr_keypath produces a 64-byte BIP-340 Schnorr sig
--       under SIGHASH_DEFAULT that verifies against the BIP-86 tweaked
--       output key extracted from the scriptPubKey.
--   T2  Wallet:_sign_inputs end-to-end: build a tx with a single P2TR
--       input from a wallet-generated address, run the signer, verify
--       the witness against the consensus sighash + tweaked output key.
--   T3  Wallet:_sign_inputs handles mixed (P2WPKH + P2TR) inputs in one
--       tx (BIP-341 commits to the prevouts of every input).
--   T4  PSBT sign_input + finalize_input round-trip on a P2TR input
--       produces a witness whose single element is the same Schnorr sig
--       the wallet signer emits.
--   T5  Non-default sighash types (e.g. 0x01 SIGHASH_ALL_TAPROOT) get a
--       65-byte witness item with the trailing hash-type byte.
--   T6  Funds-burn guard: the address-side TapTweak (in
--       pubkey_to_address_for_purpose) and the sign-side TapTweak (in
--       sign_input_p2tr_keypath) MUST agree byte-for-byte on the same
--       internal key; if they drift, every BIP-86 sig is unspendable.
--
-- Closes: lunarblock unfreeze plan P2-4 — "write-only Taproot wallets"
-- W161 P0.  Reference:
-- CORE-PARITY-AUDIT/_lunarblock-unfreeze-plan-2026-05-26.md (P2-4).
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_p2_4_p2tr_signer.lua

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
local psbt      = require("lunarblock.psbt")
local crypto    = require("lunarblock.crypto")
local script    = require("lunarblock.script")
local types     = require("lunarblock.types")
local address   = require("lunarblock.address")
local validation = require("lunarblock.validation")
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
  if a ~= b then
    error((msg or "mismatch") ..
          ": got " .. tostring(a) .. ", expected " .. tostring(b))
  end
end
local function expect_true(v, msg) if not v then error(msg or "expected true") end end
local function expect_nil(v, msg)
  if v ~= nil then error((msg or "expected nil") .. ", got " .. tostring(v)) end
end

local function hex_to_bin(hex)
  return (hex:gsub('..', function(cc) return string.char(tonumber(cc, 16)) end))
end
local function bin_to_hex(bin)
  local out = {}
  for i = 1, #bin do out[i] = string.format("%02x", bin:byte(i)) end
  return table.concat(out)
end

-- Helper: build a 1-input + 1-output spend transaction for testing.  The
-- prev_out hash is arbitrary (sighash is what we care about); the output
-- script is a tiny P2WPKH "burn" address that the test never tries to
-- spend (we only need the sighash to be well-formed).
local function make_spend_tx(spk_being_spent, value_being_spent)
  local prev_hash = types.hash256(string.rep("\x42", 32))
  local prev_out  = types.outpoint(prev_hash, 0)
  local txin      = types.txin(prev_out)
  local dummy_pkh = string.rep("\x11", 20)
  local txout     = types.txout(value_being_spent - 1000,
                                script.make_p2wpkh_script(dummy_pkh))
  local tx = types.transaction(2, {txin}, {txout}, 0)
  tx.segwit = true
  return tx
end

print("=== P2-4: BIP-86 P2TR key-path signer ===\n")

-- ----------------------------------------------------------------------
-- T1: sign_input_p2tr_keypath end-to-end (raw API) — sign, then verify
-- against the BIP-86 tweaked output key.  This is the smallest possible
-- happy-path: 1 input, 1 output, SIGHASH_DEFAULT, no annex.
-- ----------------------------------------------------------------------
print("--- T1: sign_input_p2tr_keypath produces a verifiable Schnorr sig ---")
test("T1: sign + schnorr_verify round-trip against BIP-86 output key", function()
  -- Fixed key for determinism.  Internal key (33-byte compressed) is
  -- derived; we extract the 32-byte x-only and compute the tweaked output
  -- key the same way pubkey_to_address_for_purpose(86, ...) does.
  local privkey = string.rep("\xab", 32)
  local internal_pub = crypto.pubkey_from_privkey(privkey, true)
  local internal_xonly = internal_pub:sub(2, 33)
  expect_eq(#internal_xonly, 32, "x-only key extraction")

  -- Tweaked output key — exactly the same call the address builder makes
  -- (any drift here is the silent-funds-burn shape T6 guards against).
  local tweak = crypto.tagged_hash("TapTweak", internal_xonly)
  local output_xonly = crypto.tweak_pubkey(internal_xonly, tweak)
  expect_true(output_xonly ~= nil, "tweak_pubkey ok")
  expect_eq(#output_xonly, 32, "tweaked output key is 32 bytes")

  -- Build a transaction that spends a P2TR output paying to the tweaked
  -- output key (this is what a BIP-86 wallet emits for its own address).
  local spk = script.make_p2tr_script(output_xonly)
  expect_eq(#spk, 34, "P2TR scriptPubKey is 34 bytes (OP_1 + push32 + 32)")
  local tx = make_spend_tx(spk, 100000)

  local prev_outputs = {{ value = 100000, script_pubkey = spk }}

  -- Default SIGHASH_DEFAULT => 64-byte witness item.
  local witness_item, err = wallet.sign_input_p2tr_keypath(
    tx, 0, prev_outputs, privkey
  )
  expect_true(witness_item ~= nil, "sign_input_p2tr_keypath returned: " .. tostring(err))
  expect_eq(#witness_item, 64,
    "SIGHASH_DEFAULT must produce a bare 64-byte sig (no trailing hash-type byte)")

  -- Recompute the sighash + verify against the tweaked output key (same
  -- shape the consensus interpreter does at script_verify time).
  local sighash, sherr = validation.signature_hash_taproot(
    tx, 0, wallet.SIGHASH_DEFAULT, prev_outputs, 0, nil, nil, nil
  )
  expect_true(sighash ~= nil, "sighash recompute: " .. tostring(sherr))

  local ok = crypto.schnorr_verify(output_xonly, witness_item, sighash)
  expect_true(ok, "schnorr_verify must succeed against tweaked output key — " ..
                  "if this fails, the address-side tweak (used to build the " ..
                  "scriptPubKey) and the sign-side tweak (in " ..
                  "sign_input_p2tr_keypath) have drifted, which would silently " ..
                  "burn funds for every BIP-86 wallet user.")
end)

-- T1b: invalid input lengths must error loudly (not return a sig).
test("T1b: privkey length validation", function()
  local prev = {{ value = 1000, script_pubkey = string.rep("\x51\x20", 1) .. string.rep("\x00", 32) }}
  local tx = make_spend_tx(prev[1].script_pubkey, 1000)
  local _, err = wallet.sign_input_p2tr_keypath(tx, 0, prev, "too short")
  expect_true(err ~= nil, "short privkey should error")
end)

test("T1c: prev_outputs length mismatch errors", function()
  local privkey = string.rep("\xab", 32)
  local internal_pub = crypto.pubkey_from_privkey(privkey, true)
  local internal_xonly = internal_pub:sub(2, 33)
  local tweak = crypto.tagged_hash("TapTweak", internal_xonly)
  local output_xonly = crypto.tweak_pubkey(internal_xonly, tweak)
  local spk = script.make_p2tr_script(output_xonly)
  local tx = make_spend_tx(spk, 100000)
  -- empty prev_outputs (tx has 1 input)
  local _, err = wallet.sign_input_p2tr_keypath(tx, 0, {}, privkey)
  expect_true(err ~= nil, "missing prev_outputs should error")
end)

-- ----------------------------------------------------------------------
-- T2: End-to-end Wallet:_sign_inputs on a P2TR input from a real
-- generated address.  Before P2-4 this fell through to the ECDSA branch
-- and emitted an unspendable witness.
-- ----------------------------------------------------------------------
print("\n--- T2: Wallet:_sign_inputs handles P2TR via key_info.type ---")
test("T2: wallet-generated P2TR address + _sign_inputs verifies on-chain shape", function()
  local w = wallet.new(consensus.networks.mainnet)
  w.master_key = wallet.master_key_from_seed(string.rep("\x44", 32))
  w.is_locked = false
  w.address_type = "p2tr"
  local addr = w:get_new_address()
  expect_true(addr:find("^bc1p") ~= nil, "should be bech32m: " .. tostring(addr))

  local key_info = w.keys[addr]
  expect_eq(key_info.type, "p2tr", "key_info.type tracks address_type")
  expect_true(key_info.privkey ~= nil, "unlocked wallet has privkey")

  -- The address decodes back to the tweaked output key.
  local addr_type, output_xonly = address.decode_address(addr, "mainnet")
  expect_eq(addr_type, "p2tr")
  expect_eq(#output_xonly, 32)

  -- Build a tx that spends a single P2TR UTXO from this wallet.
  local spk = script.make_p2tr_script(output_xonly)
  local tx = make_spend_tx(spk, 50000)
  local input_utxos = {
    { value = 50000, script_pubkey = spk, address = addr },
  }
  local ok, err = w:_sign_inputs(tx, input_utxos)
  expect_true(ok, "_sign_inputs returned: " .. tostring(err))

  -- Witness must be a single 64-byte item (BIP-86 SIGHASH_DEFAULT shape).
  expect_eq(#tx.inputs[1].witness, 1, "P2TR witness has exactly one item")
  expect_eq(#tx.inputs[1].witness[1], 64,
    "BIP-86 SIGHASH_DEFAULT sig is a bare 64-byte Schnorr (no trailing flag)")
  expect_eq(tx.inputs[1].script_sig, "",
    "P2TR scriptSig must be empty (witness-only spend)")

  -- Verify against the tweaked output key recovered from the address.
  local prev_outputs = {{ value = 50000, script_pubkey = spk }}
  local sighash = validation.signature_hash_taproot(
    tx, 0, wallet.SIGHASH_DEFAULT, prev_outputs, 0, nil, nil, nil
  )
  local ok_verify = crypto.schnorr_verify(output_xonly, tx.inputs[1].witness[1], sighash)
  expect_true(ok_verify,
    "wallet sig MUST verify against the address's tweaked output key — " ..
    "the address-tweak and sign-tweak must be identical")
end)

-- ----------------------------------------------------------------------
-- T3: Mixed-input tx (1 P2WPKH + 1 P2TR).  BIP-341 commits to the
-- prevouts of EVERY input, not just the one being signed — the wallet
-- signer must build the full prev_outputs array.
-- ----------------------------------------------------------------------
print("\n--- T3: mixed P2WPKH + P2TR inputs in a single tx ---")
test("T3: BIP-341 prev_outputs spans every input (not just the taproot one)", function()
  -- Wallet 1: P2WPKH
  local w_pkh = wallet.new(consensus.networks.mainnet)
  w_pkh.master_key = wallet.master_key_from_seed(string.rep("\x71", 32))
  w_pkh.is_locked = false
  w_pkh.address_type = "p2wpkh"
  local addr_pkh = w_pkh:get_new_address()
  local pkh_keyinfo = w_pkh.keys[addr_pkh]

  -- Wallet 2: P2TR (separate keys; we merge them into a single signing
  -- wallet to test the mixed-input path without faking the keystore).
  local w_tr = wallet.new(consensus.networks.mainnet)
  w_tr.master_key = wallet.master_key_from_seed(string.rep("\x72", 32))
  w_tr.is_locked = false
  w_tr.address_type = "p2tr"
  local addr_tr = w_tr:get_new_address()
  local tr_keyinfo = w_tr.keys[addr_tr]

  -- Build a single mixed-key wallet (cheaper than scripting two
  -- signers).  network/master_key don't matter here — we're going to
  -- run _sign_inputs against the merged self.keys table.
  local w = wallet.new(consensus.networks.mainnet)
  w.is_locked = false
  w.keys[addr_pkh] = pkh_keyinfo
  w.keys[addr_tr]  = tr_keyinfo

  -- Prevouts: P2WPKH at input 0, P2TR at input 1.  The scriptPubKey for
  -- P2WPKH is the OP_0 <hash160(pubkey)> script.
  local spk_pkh = script.make_p2wpkh_script(crypto.hash160(pkh_keyinfo.pubkey))
  local _addr_type, output_xonly = address.decode_address(addr_tr, "mainnet")
  local spk_tr = script.make_p2tr_script(output_xonly)

  -- Build the 2-input tx.
  local txins = {
    types.txin(types.outpoint(types.hash256(string.rep("\x33", 32)), 0)),
    types.txin(types.outpoint(types.hash256(string.rep("\x34", 32)), 1)),
  }
  local txout = types.txout(99000,
    script.make_p2wpkh_script(string.rep("\xFF", 20)))
  local tx = types.transaction(2, txins, {txout}, 0)
  tx.segwit = true

  local input_utxos = {
    { value = 50000, script_pubkey = spk_pkh, address = addr_pkh },
    { value = 50000, script_pubkey = spk_tr,  address = addr_tr  },
  }
  local ok, err = w:_sign_inputs(tx, input_utxos)
  expect_true(ok, "_sign_inputs returned: " .. tostring(err))

  -- P2WPKH witness: 2 items (sig+pubkey).  P2TR witness: 1 item (sig).
  expect_eq(#tx.inputs[1].witness, 2, "P2WPKH witness = [sig, pubkey]")
  expect_eq(#tx.inputs[2].witness, 1, "P2TR witness = [sig]")
  expect_eq(#tx.inputs[2].witness[1], 64, "P2TR sig is 64 bytes (SIGHASH_DEFAULT)")

  -- Verify the P2TR sig against the BIP-341 sighash built from BOTH
  -- prevouts (this is the crux: if the signer used only the per-input
  -- prevout, the sighash would mismatch and verification would fail).
  local prev_outputs = {
    { value = 50000, script_pubkey = spk_pkh },
    { value = 50000, script_pubkey = spk_tr  },
  }
  local sighash = validation.signature_hash_taproot(
    tx, 1, wallet.SIGHASH_DEFAULT, prev_outputs, 0, nil, nil, nil
  )
  local ok_verify = crypto.schnorr_verify(output_xonly, tx.inputs[2].witness[1], sighash)
  expect_true(ok_verify, "P2TR sig must verify against full-prevouts sighash")
end)

-- ----------------------------------------------------------------------
-- T4: PSBT sign_input + finalize_input round-trip on a P2TR input.
-- ----------------------------------------------------------------------
print("\n--- T4: PSBT P2TR round-trip (sign + finalize) ---")
test("T4: PSBT sign_input + finalize for P2TR produces verifiable witness", function()
  local privkey = string.rep("\xa9", 32)
  local pubkey = crypto.pubkey_from_privkey(privkey, true)
  local internal_xonly = pubkey:sub(2, 33)
  local tweak = crypto.tagged_hash("TapTweak", internal_xonly)
  local output_xonly = crypto.tweak_pubkey(internal_xonly, tweak)
  local spk = script.make_p2tr_script(output_xonly)

  local tx = make_spend_tx(spk, 200000)
  local p = psbt.new(tx)
  p.inputs[1].witness_utxo = { value = 200000, script_pubkey = spk }

  -- Sign via psbt.sign_input — this used to return false for P2TR.
  local ok = psbt.sign_input(p, 0, privkey, pubkey)
  expect_true(ok, "psbt.sign_input must succeed for P2TR")
  expect_true(p.inputs[1].tap_key_sig ~= nil, "tap_key_sig populated")
  expect_eq(#p.inputs[1].tap_key_sig, 64, "tap_key_sig is 64 bytes (SIGHASH_DEFAULT)")

  -- partial_sigs must stay empty (BIP-371 keeps the ECDSA + Schnorr
  -- namespaces strictly separate to avoid SigCache cross-talk).
  local n_partial = 0
  for _, _ in pairs(p.inputs[1].partial_sigs) do n_partial = n_partial + 1 end
  expect_eq(n_partial, 0, "partial_sigs (ECDSA) must NOT be populated by P2TR sign")

  -- Finalize.
  local fok = psbt.finalize_input(p, 0)
  expect_true(fok, "finalize_input must succeed for P2TR")
  expect_eq(p.inputs[1].final_script_sig, "", "final_script_sig empty")
  expect_eq(#p.inputs[1].final_script_witness, 1, "final witness has 1 item")
  expect_eq(#p.inputs[1].final_script_witness[1], 64,
    "final witness item is the bare 64-byte Schnorr sig")
  expect_true(p.inputs[1].tap_key_sig == nil,
    "BIP-174: producer/finalizer fields cleared after finalize")

  -- Extract the signed tx + verify against the address-side tweaked key.
  local signed = psbt.extract(p)
  local prev_outputs = {{ value = 200000, script_pubkey = spk }}
  local sighash = validation.signature_hash_taproot(
    signed, 0, wallet.SIGHASH_DEFAULT, prev_outputs, 0, nil, nil, nil
  )
  local ok_verify = crypto.schnorr_verify(output_xonly, signed.inputs[1].witness[1], sighash)
  expect_true(ok_verify, "PSBT-signed tx must verify against tweaked output key")
end)

-- T4b: PSBT sign refuses if witness_utxo missing on every input (BIP-371
-- says taproot inputs MUST carry witness_utxo).
test("T4b: PSBT P2TR signing errors when prevouts are missing", function()
  local privkey = string.rep("\xa9", 32)
  local pubkey = crypto.pubkey_from_privkey(privkey, true)
  local internal_xonly = pubkey:sub(2, 33)
  local tweak = crypto.tagged_hash("TapTweak", internal_xonly)
  local output_xonly = crypto.tweak_pubkey(internal_xonly, tweak)
  local spk = script.make_p2tr_script(output_xonly)

  local tx = make_spend_tx(spk, 200000)
  local p = psbt.new(tx)
  -- Deliberately do NOT set witness_utxo or non_witness_utxo.
  local pok, perr = pcall(psbt.sign_input, p, 0, privkey, pubkey)
  expect_true(not pok, "sign_input must raise without UTXO info")
  expect_true(tostring(perr):find("Missing UTXO information") ~= nil,
    "error should be about missing UTXO; got: " .. tostring(perr))
end)

-- ----------------------------------------------------------------------
-- T5: Non-default sighash types append the trailing hash-type byte.
-- ----------------------------------------------------------------------
print("\n--- T5: non-default sighash types produce 65-byte witness items ---")
test("T5: SIGHASH_ALL (0x01) on key-path adds trailing flag byte", function()
  local privkey = string.rep("\xcc", 32)
  local internal_pub = crypto.pubkey_from_privkey(privkey, true)
  local internal_xonly = internal_pub:sub(2, 33)
  local tweak = crypto.tagged_hash("TapTweak", internal_xonly)
  local output_xonly = crypto.tweak_pubkey(internal_xonly, tweak)
  local spk = script.make_p2tr_script(output_xonly)

  local tx = make_spend_tx(spk, 75000)
  local prev_outputs = {{ value = 75000, script_pubkey = spk }}

  -- 0x01 == SIGHASH_ALL (taproot variant — not SIGHASH_DEFAULT).  Per
  -- BIP-341 the wire format is `sig || 0x01` (65 bytes).
  local witness_item, err = wallet.sign_input_p2tr_keypath(
    tx, 0, prev_outputs, privkey, 0x01
  )
  expect_true(witness_item ~= nil, "sign returned: " .. tostring(err))
  expect_eq(#witness_item, 65, "non-default sighash → 65-byte witness item")
  expect_eq(witness_item:byte(65), 0x01, "trailing byte is the sighash type")

  -- Verify the leading 64 bytes against the sighash computed with the
  -- same hash_type the signer used.
  local sighash = validation.signature_hash_taproot(
    tx, 0, 0x01, prev_outputs, 0, nil, nil, nil
  )
  local ok = crypto.schnorr_verify(output_xonly, witness_item:sub(1, 64), sighash)
  expect_true(ok, "SIGHASH_ALL sig must verify after stripping the flag byte")
end)

-- ----------------------------------------------------------------------
-- T6: Funds-burn guard — the TapTweak the address-side computes MUST
-- equal the one the sign-side computes.  This is the single point of
-- failure for "user deposits to a lunarblock address but never spends".
-- ----------------------------------------------------------------------
print("\n--- T6: Address-side and sign-side TapTweak agree (funds-burn guard) ---")
test("T6: pubkey_to_address_for_purpose(86) and sign_input_p2tr_keypath agree", function()
  -- Use the canonical BIP-86 vector internal key.
  local internal_xonly_hex = "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
  local internal_xonly = hex_to_bin(internal_xonly_hex)

  -- Address-side tweak (what the receive flow does).
  local addr_tweak = crypto.tagged_hash("TapTweak", internal_xonly)
  local addr_output_key = crypto.tweak_pubkey(internal_xonly, addr_tweak)
  expect_eq(bin_to_hex(addr_output_key),
            "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
            "BIP-86 vector output key (sanity check on the test inputs themselves)")

  -- Sign-side: pick an arbitrary privkey whose pubkey we'll use as the
  -- internal key (the actual internal key for vector reproduction would
  -- require a privkey we don't have; we use a fresh key here to prove
  -- the sign-side and address-side functions BOTH call the same tagged-
  -- hash + same tweak_pubkey primitives and never drift).
  local privkey = string.rep("\xee", 32)
  local pub = crypto.pubkey_from_privkey(privkey, true)
  local internal2 = pub:sub(2, 33)
  local addr_str = wallet.pubkey_to_address_for_purpose(86, pub, "mainnet")
  local addr_type, output_from_addr = address.decode_address(addr_str, "mainnet")
  expect_eq(addr_type, "p2tr")

  -- Now sign + verify against the SAME output key the address encodes.
  local spk = script.make_p2tr_script(output_from_addr)
  local tx = make_spend_tx(spk, 12345)
  local prev_outputs = {{ value = 12345, script_pubkey = spk }}
  local witness_item = wallet.sign_input_p2tr_keypath(tx, 0, prev_outputs, privkey)
  expect_true(witness_item ~= nil, "sign_input_p2tr_keypath ok")

  local sighash = validation.signature_hash_taproot(
    tx, 0, wallet.SIGHASH_DEFAULT, prev_outputs, 0, nil, nil, nil
  )
  local ok = crypto.schnorr_verify(output_from_addr, witness_item, sighash)
  expect_true(ok,
    "If this fails, the receive flow and the spend flow have drifted on " ..
    "TapTweak — every BIP-86 wallet user's funds would be unspendable.")
end)

-- ----------------------------------------------------------------------
-- Summary
-- ----------------------------------------------------------------------
io.write(string.format("\n%d passed, %d failed\n", PASS, FAIL))
os.exit(FAIL > 0 and 1 or 0)
