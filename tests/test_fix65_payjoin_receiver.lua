#!/usr/bin/env luajit
--
-- FIX-65 — BIP-78 PayJoin receiver foundation tests.
--
-- Closes the BIP-78 half of the W119 "2 specs behind" gap that FIX-62
-- left open (BIP-21 URI parser landed there).  After this fix lunarblock
-- is 0 specs behind: BIP-21 sender URI + BIP-78 receiver endpoint both
-- wired.
--
-- Scope: receiver-side foundation.  Sender flow, RPCs, Tor routing,
-- TLS cert validation, double-receive guard, anti-UTXO-probe, replay
-- protection (W119 G2/G3, G10-G13, G18-G20, G22-G27, G30) remain in
-- "MISSING" status — they are deferred to later fix waves.
--
-- We exercise:
--   * Round-trip: build an Original PSBT (one P2WPKH input, one payment
--                 output to a wallet address, one change output), POST
--                 it through RESTServer:handle_payjoin(), parse the
--                 base64 response back into a PSBT, and assert:
--                   (a) input count = original + 1 (receiver contributed)
--                   (b) payment output value bumped by exactly the
--                       receiver UTXO value (anti-snoop amount
--                       obfuscation, BIP-78 §Receiver)
--                   (c) receiver's added psbt.input has final_script_witness
--                       populated (P2WPKH stack: [sig, pubkey], 2 items)
--                   (d) witness signature actually verifies against the
--                       wallet pubkey via crypto.ecdsa_verify (no second
--                       signing pipeline — the receiver signed through
--                       the FIX-61 _sign_inputs path).
--   * Error path: empty body          -> 400 + "original-psbt-rejected"
--   * Error path: invalid base64      -> 400 + "original-psbt-rejected"
--   * Error path: v=99                -> 400 + "version-unsupported"
--   * Error path: no payment output   -> 400 + "original-psbt-rejected"
--                 to a wallet address
--   * Error path: no wallet UTXO      -> 400 + "not-enough-money"
--                 (empty wallet)
--   * Audit-flip + single-pipeline anchor (FIX-61 reuse): src/rest.lua
--     handle_payjoin() must call self.wallet:_sign_inputs(...), proving
--     the receiver-input signing goes through the SAME unified pipeline
--     bump_fee + create_transaction use.  Any divergence here would be
--     a regression of the W118 anti-pattern FIX-59 closed.
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_fix65_payjoin_receiver.lua
--

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

local rest_mod   = require("lunarblock.rest")
local wallet_mod = require("lunarblock.wallet")
local types      = require("lunarblock.types")
local consensus  = require("lunarblock.consensus")
local crypto     = require("lunarblock.crypto")
local script_mod = require("lunarblock.script")
local address_mod= require("lunarblock.address")
local serialize  = require("lunarblock.serialize")
local validation = require("lunarblock.validation")
local psbt_mod   = require("lunarblock.psbt")

-- Test infra ----------------------------------------------------------
local PASS, FAIL = 0, 0
local function pass(n) print("  PASS  " .. n); PASS = PASS + 1 end
local function fail(n, m) print("  FAIL  " .. n .. " -- " .. tostring(m)); FAIL = FAIL + 1 end
local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, err) end
end

local function expect_eq(a, b, msg)
  if a ~= b then error((msg or "mismatch") ..
    ": got " .. tostring(a) .. ", expected " .. tostring(b)) end
end
local function expect_true(v, m) if not v then error(m or "expected true") end end
local function expect_nil(v, m) if v ~= nil then error((m or "expected nil") .. ", got " .. tostring(v)) end end
local function expect_match(s, frag, m)
  if type(s) ~= "string" or not s:find(frag, 1, true) then
    error((m or "no match") .. ": '" .. tostring(s) .. "' missing '" .. tostring(frag) .. "'")
  end
end

print("=== FIX-65 BIP-78 PayJoin receiver foundation ===\n")

-- Helpers -------------------------------------------------------------

-- Build a minimal wallet with one P2WPKH key + one confirmed UTXO.  The
-- wallet's network is regtest so segwit_encode uses the "bcrt" HRP.
local function build_receiver_wallet(seed, utxo_value)
  local w = wallet_mod.new(consensus.networks.regtest)
  local privkey = crypto.sha256("fix65-receiver-" .. seed)
  local pubkey = crypto.pubkey_from_privkey(privkey, true)
  local pkh = crypto.hash160(pubkey)
  local spk = script_mod.make_p2wpkh_script(pkh)
  local addr = address_mod.pubkey_to_p2wpkh(pubkey, "regtest")

  w.is_locked = false
  w.is_encrypted = false
  w.keys[addr] = {privkey = privkey, pubkey = pubkey, type = "p2wpkh"}
  w.addresses[#w.addresses + 1] = addr

  local prev_txid = types.hash256(string.rep("\xCD", 32))
  local outpoint_key = prev_txid.bytes .. string.char(0, 0, 0, 0)
  w.utxos[outpoint_key] = {
    value = utxo_value, script_pubkey = spk, address = addr,
    txid = prev_txid, vout = 0, height = 1, is_coinbase = false,
    confirmations = 100,
  }
  w.confirmed_balance = utxo_value

  function w:get_available_utxos(_)
    return {{utxo = w.utxos[outpoint_key]}}
  end

  return w, addr, pubkey
end

-- Build an Original PSBT (sender side simulation):
--   tx version 2, one P2WPKH input (sender UTXO), two outputs:
--     [1] payment output -> receiver_addr (`pay_amt` sats)
--     [2] change output  -> sender's own change script
-- Returns base64 string ready to POST.
local function build_original_psbt(receiver_addr, pay_amt)
  local sender_priv = crypto.sha256("fix65-sender")
  local sender_pub  = crypto.pubkey_from_privkey(sender_priv, true)
  local sender_pkh  = crypto.hash160(sender_pub)
  local sender_spk  = script_mod.make_p2wpkh_script(sender_pkh)

  -- Sender's prev outpoint (we don't sign it for the foundation test; the
  -- PSBT is just the "Original" payload — receiver doesn't need a signed
  -- input to demonstrate the foundation, only a parseable PSBT).
  local sender_prev_txid = types.hash256(string.rep("\xEF", 32))
  local input = types.txin(
    types.outpoint(sender_prev_txid, 0),
    "",
    0xFFFFFFFD)

  -- Payment output to the receiver.
  local recv_type, recv_program = address_mod.decode_address(receiver_addr, "regtest")
  expect_eq(recv_type, "p2wpkh", "receiver address is p2wpkh")
  local recv_spk = script_mod.make_p2wpkh_script(recv_program)

  local tx = types.transaction(2,
    {input},
    {
      types.txout(pay_amt,  recv_spk),
      types.txout(100000,   sender_spk),  -- sender change
    },
    0)
  tx.segwit = true

  local p = psbt_mod.new(tx)
  -- Sender populates witness_utxo on its input (BIP-78 §Receiver checks
  -- want this; we don't enforce in the foundation but include it for
  -- realism).
  p.inputs[1].witness_utxo = {value = 500000, script_pubkey = sender_spk}
  return psbt_mod.to_base64(p), sender_pub
end

-- ---- Test 1: end-to-end PayJoin round-trip --------------------------
test("PayJoin round-trip: receiver contributes input + bumps payment output", function()
  local recv_utxo_value = 250000
  local pay_amt = 50000
  local w, recv_addr, recv_pub = build_receiver_wallet("rt1", recv_utxo_value)
  local server = rest_mod.new({wallet = w, network = consensus.networks.regtest})

  local b64_orig, _ = build_original_psbt(recv_addr, pay_amt)
  local resp = server:handle_payjoin({v = "1"}, b64_orig)

  -- HTTP/1.1 200 + Content-Type pinned to text/plain; charset=utf-8.
  expect_match(resp, "HTTP/1.1 200", "status 200")
  expect_match(resp, "text/plain; charset=utf-8", "Content-Type per BIP-78")

  -- Extract body (after the blank line that ends the headers).
  local body = resp:match("\r\n\r\n(.*)$")
  expect_true(body and #body > 0, "non-empty body")
  body = body:gsub("\n$", "")  -- trim trailing newline

  -- Parse response PSBT.
  local proposal = psbt_mod.from_base64(body)
  expect_true(proposal and proposal.tx, "response is a parseable PSBT")

  -- (a) input count = original (1) + receiver-contributed (1) = 2.
  expect_eq(#proposal.tx.inputs, 2, "receiver added one input")

  -- (b) payment output value bumped by receiver's UTXO value.
  expect_eq(proposal.tx.outputs[1].value, pay_amt + recv_utxo_value,
    "payment output increased by receiver UTXO value (anti-snoop)")

  -- (c) receiver's added psbt input (index 2) has final_script_witness
  -- populated as a P2WPKH stack [sig, pubkey].
  local recv_in = proposal.inputs[2]
  expect_true(recv_in ~= nil, "receiver psbt input slot present")
  expect_true(recv_in.final_script_witness ~= nil,
    "receiver input finalized via final_script_witness")
  expect_eq(#recv_in.final_script_witness, 2,
    "P2WPKH witness has 2 elements [sig, pubkey]")
  expect_eq(recv_in.final_script_witness[2], recv_pub,
    "second witness element is the receiver pubkey")

  -- (d) signature actually verifies (proves the receiver signed via the
  -- FIX-61 _sign_inputs pipeline — NOT a stub or no-op).
  local sig_with_hashtype = recv_in.final_script_witness[1]
  expect_true(#sig_with_hashtype >= 9 and #sig_with_hashtype <= 73,
    "DER sig + hashtype byte in plausible length range")
  local hashtype = sig_with_hashtype:byte(#sig_with_hashtype)
  expect_eq(hashtype, consensus.SIGHASH.ALL, "SIGHASH_ALL appended")
  local sig_der = sig_with_hashtype:sub(1, -2)

  -- Recompute the segwit-v0 sighash the receiver should have signed.
  local pkh = crypto.hash160(recv_pub)
  local script_code = script_mod.make_p2pkh_script(pkh)
  local sighash = validation.signature_hash_segwit_v0(
    proposal.tx, 1,  -- 0-based input index 1 == receiver's added input
    script_code, recv_utxo_value, consensus.SIGHASH.ALL)
  expect_true(crypto.ecdsa_verify(recv_pub, sig_der, sighash),
    "receiver signature verifies against pubkey + recomputed sighash")
end)

-- ---- Test 2: error — empty body ------------------------------------
test("error: empty body -> 400 original-psbt-rejected", function()
  local w = build_receiver_wallet("e1", 100000)
  local server = rest_mod.new({wallet = w, network = consensus.networks.regtest})
  local resp = server:handle_payjoin({v = "1"}, "")
  expect_match(resp, "HTTP/1.1 400", "status 400")
  expect_match(resp, "original-psbt-rejected", "errorCode original-psbt-rejected")
  expect_match(resp, "text/plain; charset=utf-8", "Content-Type per BIP-78")
end)

-- ---- Test 3: error — non-base64 garbage ----------------------------
test("error: invalid base64 -> 400 original-psbt-rejected", function()
  local w = build_receiver_wallet("e2", 100000)
  local server = rest_mod.new({wallet = w, network = consensus.networks.regtest})
  -- "!!!" is excluded by the base64_decode filter; result decodes to ""
  -- which fails the magic-bytes check.  Either way the receiver MUST
  -- emit original-psbt-rejected.
  local resp = server:handle_payjoin({v = "1"}, "!!!not-base64!!!")
  expect_match(resp, "HTTP/1.1 400", "status 400")
  expect_match(resp, "original-psbt-rejected", "errorCode original-psbt-rejected")
end)

-- ---- Test 4: error — version mismatch ------------------------------
test("error: v=99 -> 400 version-unsupported", function()
  local w, recv_addr = build_receiver_wallet("e3", 100000)
  local server = rest_mod.new({wallet = w, network = consensus.networks.regtest})
  local b64 = build_original_psbt(recv_addr, 50000)
  local resp = server:handle_payjoin({v = "99"}, b64)
  expect_match(resp, "HTTP/1.1 400", "status 400")
  expect_match(resp, "version-unsupported", "errorCode version-unsupported")
end)

-- ---- Test 5: error — no payment output to wallet -------------------
test("error: PSBT pays no wallet address -> 400 original-psbt-rejected", function()
  local w = build_receiver_wallet("e4", 100000)
  local server = rest_mod.new({wallet = w, network = consensus.networks.regtest})

  -- Build a PSBT that pays a DIFFERENT (non-wallet) address.
  local other_priv = crypto.sha256("fix65-other-recipient")
  local other_pub  = crypto.pubkey_from_privkey(other_priv, true)
  local other_addr = address_mod.pubkey_to_p2wpkh(other_pub, "regtest")
  local b64 = build_original_psbt(other_addr, 50000)

  local resp = server:handle_payjoin({v = "1"}, b64)
  expect_match(resp, "HTTP/1.1 400", "status 400")
  expect_match(resp, "original-psbt-rejected", "errorCode original-psbt-rejected")
end)

-- ---- Test 6: error — receiver has no UTXOs -------------------------
test("error: empty receiver wallet -> 400 not-enough-money", function()
  local w, recv_addr = build_receiver_wallet("e5", 100000)
  -- Wipe UTXOs to simulate an empty wallet.  Override get_available_utxos
  -- to return nothing.
  function w:get_available_utxos(_) return {} end
  local server = rest_mod.new({wallet = w, network = consensus.networks.regtest})
  local b64 = build_original_psbt(recv_addr, 50000)
  local resp = server:handle_payjoin({v = "1"}, b64)
  expect_match(resp, "HTTP/1.1 400", "status 400")
  expect_match(resp, "not-enough-money", "errorCode not-enough-money")
end)

-- ---- Test 7: error — PayJoin disabled (no wallet) ------------------
test("error: no wallet configured -> 400 unavailable", function()
  local server = rest_mod.new({network = consensus.networks.regtest})
  -- No wallet set at all on the server.
  local resp = server:handle_payjoin({v = "1"}, "anything")
  expect_match(resp, "HTTP/1.1 400", "status 400")
  expect_match(resp, "unavailable", "errorCode unavailable")
end)

-- ---- Test 8: single-pipeline anchor (FIX-61 reuse) -----------------
--
-- Static source-level assertion: src/rest.lua handle_payjoin MUST call
-- self.wallet:_sign_inputs(...) — proving the receiver-input signing
-- goes through the same unified pipeline create_transaction and
-- bump_fee use.  Any divergence here would mean we accidentally
-- introduced a second signing pipeline, which is exactly the W118
-- anti-pattern FIX-59 + FIX-61 eliminated.
--
-- This is the lunarblock equivalent of FIX-61 test 17.
test("PayJoin receiver routes signing through Wallet:_sign_inputs (no 2nd pipe)", function()
  local f = io.open("src/rest.lua", "r"); local src = f:read("*a"); f:close()

  -- Locate handle_payjoin.
  local helper_start = src:find("function RESTServer:handle_payjoin")
  expect_true(helper_start ~= nil, "handle_payjoin defined")

  local helper_end = src:find("\nfunction", helper_start + 1) or #src
  local helper_body = src:sub(helper_start, helper_end)

  -- Must call _sign_inputs through self.wallet (the FIX-61 pipeline).
  expect_true(helper_body:find("self%.wallet:_sign_inputs") ~= nil,
    "handle_payjoin calls self.wallet:_sign_inputs (FIX-61 pipeline)")

  -- And must NOT introduce a parallel sighash + ecdsa_sign path.
  -- (We allow validation.signature_hash_* + crypto.ecdsa_sign to appear
  -- elsewhere in rest.lua, but NOT inside handle_payjoin.  This is the
  -- "no 2nd pipeline" anchor.)
  expect_nil(helper_body:find("crypto%.ecdsa_sign"),
    "handle_payjoin does not call crypto.ecdsa_sign directly")
  expect_nil(helper_body:find("signature_hash_segwit_v0"),
    "handle_payjoin does not compute its own segwit sighash")
end)

-- ---- Test 9: audit-flip — W119 G1 marker ---------------------------
test("W119 G1 audit marker flipped (POST /payjoin route present in rest.lua)", function()
  local f = io.open("src/rest.lua", "r"); local src = f:read("*a"); f:close()
  expect_true(src:find("payjoin") ~= nil, "src/rest.lua references payjoin")
  expect_true(src:find('clean_post == "/payjoin"') ~= nil,
    "src/rest.lua routes POST /payjoin")
  expect_true(src:find("handle_payjoin") ~= nil,
    "src/rest.lua has handle_payjoin method")
end)

-- ---- Test 10: audit-flip — W119 G17 marker -------------------------
test("W119 G17 audit marker flipped (4 BIP-78 error codes in source)", function()
  local f = io.open("src/rest.lua", "r"); local src = f:read("*a"); f:close()
  for _, code in ipairs({"unavailable", "not%-enough%-money",
                         "version%-unsupported", "original%-psbt%-rejected"}) do
    expect_true(src:find(code) ~= nil,
      "rest.lua source contains BIP-78 error code: " .. code:gsub("%%", ""))
  end
end)

-- Summary -------------------------------------------------------------
print(string.format("\n=== FIX-65 SUMMARY: %d PASS / %d FAIL ===", PASS, FAIL))
os.exit(FAIL == 0 and 0 or 1)
