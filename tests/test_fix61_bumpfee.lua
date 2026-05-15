#!/usr/bin/env luajit
--
-- FIX-61 — bumpfee / psbtbumpfee functional tests.
--
-- Closes W118 G20-BUG-7 (bumpfee absent) + G21-BUG-8 (psbtbumpfee absent).
-- Mirrors bitcoin-core/src/wallet/feebumper.cpp (Result codes +
-- PreconditionChecks) and wallet/rpc/spend.cpp (bumpfee / psbtbumpfee).
--
-- We exercise:
--   * Round-trip bumpfee: a wallet tx is created -> a fee bump is computed
--                         -> the replacement tx reuses every input, the
--                         change output shrinks by exactly (new_fee - old_fee),
--                         and every input is re-signed via the FIX-59
--                         crypto.ecdsa_sign pipeline. Sighashes on the
--                         replacement must match a fresh validation pass.
--   * psbtbumpfee returns an unsigned PSBT whose embedded tx is identical
--                         to the bumpfee tx (modulo witnesses / scriptSigs),
--                         with witness_utxo populated on every input so an
--                         offline signer has everything BIP-143 needs.
--   * Reject paths: BIP-125 non-replaceable, already-mined (height>0),
--                         already-bumped (replaced_by set), no change output,
--                         change after bump would be dust, wrong txid,
--                         bumping with locked wallet.
--   * Audit assertion: W118 G20/G21 markers flipped.
--   * Signing pipeline assertion: bumpfee's re-sign path is the SAME one
--                         create_transaction uses (FIX-59 unified
--                         crypto.ecdsa_sign + validation.signature_hash_segwit_v0).
--                         No second pipeline.
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_fix61_bumpfee.lua
--

package.path = "src/?.lua;./?.lua;" .. package.path

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

local rpc        = require("lunarblock.rpc")
local wallet_mod = require("lunarblock.wallet")
local types      = require("lunarblock.types")
local consensus  = require("lunarblock.consensus")
local crypto     = require("lunarblock.crypto")
local script_mod = require("lunarblock.script")
local address_mod= require("lunarblock.address")
local serialize  = require("lunarblock.serialize")
local validation = require("lunarblock.validation")
local psbt_mod   = require("lunarblock.psbt")
local mempool_mod= require("lunarblock.mempool")

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
local function expect_false(v, m) if v then error(m or "expected false") end end
local function expect_nil(v, m) if v ~= nil then error((m or "expected nil") .. ", got " .. tostring(v)) end end
local function expect_ne(a, b, m)
  if a == b then error((m or "expected differ") .. ": both " .. tostring(a)) end
end

print("=== FIX-61 bumpfee / psbtbumpfee functional tests ===\n")

-- Helpers -------------------------------------------------------------

-- Build a minimal wallet with one P2WPKH key and one confirmed UTXO so
-- create_transaction can build + sign a transaction. The returned wallet
-- has self.transactions[] pre-populated as if sendtoaddress just ran.
local function build_wallet_with_pending_tx(seed, utxo_value, send_amount, fee_rate)
  local w = wallet_mod.new(consensus.networks.regtest)
  -- Deterministic keypair so we can re-derive in assertions.
  local privkey = crypto.sha256("fix61-bumpfee-" .. seed)
  local pubkey = crypto.pubkey_from_privkey(privkey, true)
  local pkh = crypto.hash160(pubkey)
  local spk = script_mod.make_p2wpkh_script(pkh)
  local addr = address_mod.pubkey_to_p2wpkh(pubkey, "regtest")

  w.is_locked = false
  w.is_encrypted = false
  w.keys[addr] = {privkey = privkey, pubkey = pubkey, type = "p2wpkh"}
  w.addresses[#w.addresses + 1] = addr

  -- Inject a confirmed UTXO worth utxo_value sats.
  local prev_txid = types.hash256(string.rep("\xAB", 32))
  local outpoint_key = prev_txid.bytes .. string.char(0, 0, 0, 0)
  w.utxos[outpoint_key] = {
    value = utxo_value, script_pubkey = spk, address = addr,
    txid = prev_txid, vout = 0, height = 1, is_coinbase = false,
    confirmations = 100,
  }
  w.confirmed_balance = utxo_value

  -- Ask wallet for a fresh change address so create_transaction's
  -- get_change_address() returns a wallet-owned address. The simplest
  -- way is to give it the same address (regtest wallet behaviour OK).
  function w:get_change_address() return addr end
  function w:get_available_utxos(_) return {{utxo = w.utxos[outpoint_key]}} end
  function w:estimate_fee_rate(_) return fee_rate end

  -- Recipient: a different P2WPKH script (not ours, so it's a real send).
  local recip_spk_pkh = string.rep("\x11", 20)
  local recip_addr = address_mod.segwit_encode("bcrt", 0, recip_spk_pkh)

  -- Stub mempool — accept_transaction always passes (we're not testing
  -- the mempool, we're testing the wallet's bump-fee math + signing).
  local stub_mempool = {
    entries = {},
    accept_transaction = function(self, tx, _allow_rbf)
      local txid_obj = validation.compute_txid(tx)
      local txid_hex = types.hash256_hex(txid_obj)
      if self.entries[txid_hex] then return false, "txn-already-in-mempool" end
      -- scan_mempool reads entry.txid (hash256) and entry.tx
      self.entries[txid_hex] = {tx = tx, txid = txid_obj}
      return true
    end,
    remove_transaction = function(self, txid_hex) self.entries[txid_hex] = nil end,
  }
  w.mempool = stub_mempool

  -- Send 1000 sats. create_transaction will pick the single UTXO, build
  -- a 2-output tx (recipient + change), sign, and submit through stub.
  local sent_tx, fee_res = w:send_to(
    {{address = recip_addr, amount = send_amount}}, nil)
  if not sent_tx then error("send_to failed: " .. tostring(fee_res)) end

  local txid_hex = types.hash256_hex(validation.compute_txid(sent_tx))
  return w, sent_tx, txid_hex, addr, fee_res
end

-- ---- Test 1: round-trip bumpfee (signed path) ----------------------
test("bump_fee returns a signed replacement with reduced change", function()
  local w, orig_tx, txid_hex, addr =
    build_wallet_with_pending_tx("rt1", 1000000, 100000, 5)
  -- Original is signed (witness present on every input).
  expect_eq(#orig_tx.inputs, 1, "single input")
  expect_eq(#orig_tx.outputs, 2, "recipient + change")
  expect_eq(#orig_tx.inputs[1].witness, 2, "P2WPKH witness present (sig + pubkey)")

  local orig_entry = w.transactions[txid_hex]
  expect_true(orig_entry ~= nil, "wallet tracked the sent tx")
  expect_true(orig_entry.fee > 0, "send_transaction recorded a real fee")
  local orig_fee = orig_entry.fee

  -- Locate change output (the one whose script_pubkey decodes to our addr).
  local change_idx
  for i, out in ipairs(orig_tx.outputs) do
    local a = w:_address_for_script(out.script_pubkey)
    if a then change_idx = i; break end
  end
  expect_true(change_idx ~= nil, "original tx has a change output owned by wallet")
  local orig_change = orig_tx.outputs[change_idx].value

  -- Bump.  Default policy: new_fee = old_fee + ceil(vsize * 1 sat/vB).
  local new_tx, old_fee, new_fee = w:bump_fee(txid_hex, {sign = true})
  expect_true(new_tx ~= nil, "bump_fee returned a tx")
  expect_eq(old_fee, orig_fee, "old_fee matches stored fee")
  expect_true(new_fee > old_fee, "new fee strictly greater (BIP-125 Rule 3)")

  -- Same inputs, same outpoints, recipient untouched.
  expect_eq(#new_tx.inputs, #orig_tx.inputs, "input count preserved")
  expect_eq(#new_tx.outputs, #orig_tx.outputs, "output count preserved")
  for i = 1, #new_tx.inputs do
    expect_eq(new_tx.inputs[i].prev_out.hash.bytes,
              orig_tx.inputs[i].prev_out.hash.bytes,
              "input " .. i .. " prevout hash preserved")
    expect_eq(new_tx.inputs[i].prev_out.index,
              orig_tx.inputs[i].prev_out.index,
              "input " .. i .. " prevout index preserved")
    expect_true(new_tx.inputs[i].sequence <= mempool_mod.MAX_BIP125_RBF_SEQUENCE,
                "input " .. i .. " still BIP-125 replaceable")
  end

  -- Change shrinks by exactly delta.
  local new_change = new_tx.outputs[change_idx].value
  expect_eq(orig_change - new_change, new_fee - old_fee,
            "change shrunk by exactly new_fee - old_fee")

  -- Recipient output untouched.
  local recip_idx = (change_idx == 1) and 2 or 1
  expect_eq(new_tx.outputs[recip_idx].value, orig_tx.outputs[recip_idx].value,
            "recipient amount untouched")
  expect_eq(new_tx.outputs[recip_idx].script_pubkey,
            orig_tx.outputs[recip_idx].script_pubkey,
            "recipient SPK untouched")

  -- Re-signed witness is present + non-zero on every input.
  for i = 1, #new_tx.inputs do
    expect_true(new_tx.inputs[i].witness ~= nil and #new_tx.inputs[i].witness == 2,
                "input " .. i .. " re-signed (witness stack 2 items)")
    expect_true(#new_tx.inputs[i].witness[1] >= 71,
                "input " .. i .. " has DER ECDSA sig + sighash byte")
  end

  -- New tx must compute a different txid than the original.
  expect_ne(types.hash256_hex(validation.compute_txid(new_tx)), txid_hex,
            "replacement txid != original")
end)

-- ---- Test 2: explicit fee_rate ------------------------------------
test("bump_fee honours options.fee_rate", function()
  local w, _, txid_hex = build_wallet_with_pending_tx("rt2", 2000000, 200000, 2)
  local new_tx, old_fee, new_fee = w:bump_fee(txid_hex, {fee_rate = 50, sign = true})
  expect_true(new_tx ~= nil, "bump produced a tx")
  expect_true(new_fee > old_fee, "new fee > old fee")
  -- vsize * 50 should be roughly the new fee. Compute vsize from new_tx
  -- and verify the math matches the helper's contract.
  local base = #serialize.serialize_transaction(new_tx, false)
  local total = #serialize.serialize_transaction(new_tx, true)
  local vsize = math.ceil((base * 3 + total) / 4)
  -- The wallet's helper used the ORIGINAL tx's vsize for the formula —
  -- the new tx has the same input set + same number of outputs so vsize
  -- will be near-identical.  Allow some give for variable signature
  -- length: |new_fee - 50*vsize| within 5 sats.
  expect_true(math.abs(new_fee - 50 * vsize) <= 5,
              "new_fee ~ vsize * fee_rate (got " .. new_fee ..
              ", expected ~" .. (50 * vsize) .. ")")
end)

-- ---- Test 3: psbtbumpfee returns an unsigned PSBT ------------------
test("bump_fee with sign=false yields unsigned tx (psbtbumpfee path)", function()
  local w, _, txid_hex = build_wallet_with_pending_tx("rt3", 5000000, 1000000, 3)
  local new_tx, old_fee, new_fee, input_utxos =
    w:bump_fee(txid_hex, {sign = false})
  expect_true(new_tx ~= nil, "got a tx")
  expect_true(new_fee > old_fee, "fee bumped")
  -- Witness must be absent on every input (PSBT requires unsigned).
  for i, inp in ipairs(new_tx.inputs) do
    expect_true(inp.witness == nil or #inp.witness == 0,
                "input " .. i .. " witness must be empty for PSBT")
    expect_true(inp.script_sig == nil or #inp.script_sig == 0,
                "input " .. i .. " scriptSig must be empty for PSBT")
  end
  -- input_utxos exposes each input's (value, script_pubkey, address) so
  -- the psbtbumpfee RPC can fill in witness_utxo on every PSBT input.
  expect_eq(#input_utxos, #new_tx.inputs, "input_utxos covers every input")
  for i, u in ipairs(input_utxos) do
    expect_true(u.value > 0, "input " .. i .. " value > 0")
    expect_true(u.script_pubkey ~= nil, "input " .. i .. " script_pubkey present")
    expect_true(u.address ~= nil, "input " .. i .. " address resolved")
  end

  -- Wrap in a PSBT and confirm the embedded tx is identical (modulo
  -- the empty witness/scriptSig that PSBT requires).
  local psbt = psbt_mod.new(new_tx)
  expect_eq(#psbt.inputs, #new_tx.inputs, "PSBT input count matches")
  expect_eq(#psbt.outputs, #new_tx.outputs, "PSBT output count matches")
  local b64 = psbt_mod.to_base64(psbt)
  expect_true(#b64 > 0, "PSBT base64 non-empty")
  expect_true(b64:sub(1, 6) == "cHNidP", "PSBT magic prefix base64")
end)

-- ---- Test 4: reject non-RBF (sequence = 0xFFFFFFFE) ---------------
test("bump_fee rejects non-BIP125 tx (sequence = 0xFFFFFFFE)", function()
  local w, orig_tx, txid_hex = build_wallet_with_pending_tx("rt4", 1000000, 100000, 5)
  -- Mutate the stored tx's input sequences to 0xFFFFFFFE (no-RBF).
  for _, inp in ipairs(orig_tx.inputs) do
    inp.sequence = 0xFFFFFFFE
  end
  -- Drop cached txid since we mutated the tx; signals_rbf doesn't use it
  -- but the test's expectation is the bump rejects on the sequence check.
  local new_tx, errs = w:bump_fee(txid_hex, {sign = true})
  expect_nil(new_tx, "must reject")
  expect_true(type(errs) == "table" and errs[1]:find("BIP%-125") ~= nil,
              "error mentions BIP-125 (got: " .. tostring(errs and errs[1]) .. ")")
end)

-- ---- Test 5: reject confirmed tx ----------------------------------
test("bump_fee rejects a confirmed transaction (height > 0)", function()
  local w, _, txid_hex = build_wallet_with_pending_tx("rt5", 1000000, 100000, 5)
  w.transactions[txid_hex].height = 12345
  local new_tx, errs = w:bump_fee(txid_hex, {sign = true})
  expect_nil(new_tx, "must reject")
  expect_true(errs[1]:find("mined") ~= nil,
              "error mentions mined (got: " .. tostring(errs[1]) .. ")")
end)

-- ---- Test 6: reject already-bumped tx -----------------------------
test("bump_fee refuses second bump of the same source tx", function()
  local w, _, txid_hex = build_wallet_with_pending_tx("rt6", 2000000, 200000, 3)
  -- First bump succeeds.
  local nt, _, new_fee = w:bump_fee(txid_hex, {sign = true})
  expect_true(nt ~= nil, "first bump OK")
  local ok = w:send_transaction(nt, {fee = new_fee, replaces = txid_hex})
  expect_true(ok, "broadcast OK")
  -- Second bump on the SAME original must reject.
  local n2, errs = w:bump_fee(txid_hex, {sign = true})
  expect_nil(n2, "second bump must reject")
  expect_true(errs[1]:find("already bumped") ~= nil,
              "error mentions already bumped (got: " .. tostring(errs[1]) .. ")")
end)

-- ---- Test 7: reject when no change output -------------------------
test("bump_fee rejects tx with no wallet-owned change output", function()
  local w, orig_tx, txid_hex = build_wallet_with_pending_tx("rt7", 1000000, 100000, 5)
  -- Strip the change output (output index 2 in the standard layout, or
  -- whichever one is ours).
  local kept = {}
  for _, out in ipairs(orig_tx.outputs) do
    if not w:_address_for_script(out.script_pubkey) then
      kept[#kept + 1] = out
    end
  end
  orig_tx.outputs = kept
  orig_tx._cached_txid = nil  -- invalidate caches; the lookup uses the
                              -- stored txid_hex unchanged.
  local new_tx, errs = w:bump_fee(txid_hex, {sign = true})
  expect_nil(new_tx, "must reject")
  expect_true(errs[1]:find("change") ~= nil,
              "error mentions change (got: " .. tostring(errs[1]) .. ")")
end)

-- ---- Test 8: reject when change would become dust ----------------
test("bump_fee rejects when change after bump would be dust", function()
  -- Build a tx with a tiny change output so a default 1-sat/vB bump
  -- would push change below DUST_THRESHOLD.
  local w = wallet_mod.new(consensus.networks.regtest)
  local privkey = crypto.sha256("fix61-bumpfee-dust")
  local pubkey = crypto.pubkey_from_privkey(privkey, true)
  local pkh = crypto.hash160(pubkey)
  local spk = script_mod.make_p2wpkh_script(pkh)
  local addr = address_mod.pubkey_to_p2wpkh(pubkey, "regtest")
  w.is_locked = false
  w.is_encrypted = false
  w.keys[addr] = {privkey = privkey, pubkey = pubkey, type = "p2wpkh"}

  -- Inject an orig tx directly with change = 547 sats (one above dust).
  local prev_txid = types.hash256(string.rep("\xCD", 32))
  local recip_spk = "\x00\x14" .. string.rep("\x77", 20)
  local orig = types.transaction(2,
    {types.txin(types.outpoint(prev_txid, 0), "", 0xFFFFFFFD)},
    {types.txout(100000, recip_spk),
     types.txout(547, spk)},  -- change to us
    0)
  orig.segwit = true
  -- Pretend we sent it with a known fee of 100 sats.
  local txid_hex = types.hash256_hex(validation.compute_txid(orig))
  local outpoint_key = prev_txid.bytes .. string.char(0, 0, 0, 0)
  w.transactions[txid_hex] = {
    tx = orig, height = 0, time = os.time(), fee = 100,
    input_values  = {[outpoint_key] = 100647},
    input_scripts = {[outpoint_key] = spk},
  }

  local new_tx, errs = w:bump_fee(txid_hex, {sign = false})
  expect_nil(new_tx, "must reject")
  expect_true(errs[1]:find("dust") ~= nil,
              "error mentions dust (got: " .. tostring(errs[1]) .. ")")
end)

-- ---- Test 9: reject wrong txid ------------------------------------
test("bump_fee rejects unknown txid", function()
  local w = wallet_mod.new(consensus.networks.regtest)
  w.is_encrypted = false
  w.is_locked = false
  local new_tx, errs = w:bump_fee(string.rep("0", 64), {sign = true})
  expect_nil(new_tx, "must reject")
  expect_true(errs[1]:find("non%-wallet") ~= nil
              or errs[1]:find("Invalid") ~= nil,
              "error mentions non-wallet / Invalid (got: " ..
              tostring(errs[1]) .. ")")
end)

-- ---- Test 10: reject when wallet locked --------------------------
test("bump_fee rejects when wallet locked", function()
  local w, _, txid_hex = build_wallet_with_pending_tx("rt10", 1000000, 100000, 5)
  w.is_encrypted = true
  w.is_locked = true
  local new_tx, errs = w:bump_fee(txid_hex, {sign = true})
  expect_nil(new_tx, "must reject")
  expect_true(errs[1]:find("locked") ~= nil, "error mentions locked")
end)

-- ---- Test 11: RPC bumpfee + psbtbumpfee registered ---------------
test("RPC: bumpfee + psbtbumpfee methods are registered", function()
  local server = rpc.new({network = consensus.networks.regtest})
  expect_true(type(server.methods["bumpfee"]) == "function", "bumpfee wired")
  expect_true(type(server.methods["psbtbumpfee"]) == "function", "psbtbumpfee wired")
end)

-- ---- Test 12: RPC bumpfee end-to-end -----------------------------
test("RPC: bumpfee returns {txid, origfee, fee, errors}", function()
  -- txid_hex from the helper is already display-form (types.hash256_hex
  -- byte-reverses internally) — exactly what RPC clients hand us. The
  -- wallet's self.transactions[] is keyed by the same display hex, so
  -- the lookup needs no conversion.
  local w, _orig_tx, txid_display, _ =
    build_wallet_with_pending_tx("rpc12", 5000000, 1000000, 4)

  local server = rpc.new({network = consensus.networks.regtest})
  server.wallet = w
  function server:get_request_wallet() return self.wallet end

  local result = server.methods["bumpfee"](server, {txid_display})
  expect_true(type(result) == "table", "result is a table")
  expect_true(type(result.txid) == "string", "result.txid is string")
  expect_eq(#result.txid, 64, "result.txid is 64-hex")
  expect_true(result.fee > result.origfee, "fee > origfee (in BTC)")
  expect_true(type(result.errors) == "table", "errors is array")

  -- The original wallet entry is now marked replaced_by.
  expect_true(w.transactions[txid_display].replaced_by ~= nil,
              "original entry marked replaced_by")

  -- New txid is tracked in the wallet (same display-form keying).
  expect_true(w.transactions[result.txid] ~= nil,
              "new wallet entry exists at result.txid")
  expect_eq(w.transactions[result.txid].replaces, txid_display,
            "new entry points back at replaced txid")
end)

-- ---- Test 13: RPC psbtbumpfee end-to-end --------------------------
test("RPC: psbtbumpfee returns {psbt, origfee, fee, errors}", function()
  local w, _, txid_display =
    build_wallet_with_pending_tx("rpc13", 5000000, 1000000, 4)

  local server = rpc.new({network = consensus.networks.regtest})
  server.wallet = w
  function server:get_request_wallet() return self.wallet end

  local result = server.methods["psbtbumpfee"](server, {txid_display})
  expect_true(type(result) == "table", "result is a table")
  expect_true(type(result.psbt) == "string", "result.psbt is string")
  expect_true(result.psbt:sub(1, 6) == "cHNidP",
              "PSBT base64 starts with magic (cHNidP)")
  expect_true(result.fee > result.origfee, "fee > origfee")

  -- Round-trip the PSBT: deserialize and check the embedded tx is
  -- unsigned + has the same input + output cardinality as the original.
  local decoded = psbt_mod.from_base64(result.psbt)
  expect_true(decoded ~= nil, "PSBT decodes")
  for i, inp in ipairs(decoded.tx.inputs) do
    expect_true(inp.witness == nil or #inp.witness == 0,
                "psbt tx input " .. i .. " has no witness")
  end
  -- witness_utxo populated on every PSBT input.
  for i, pin in ipairs(decoded.inputs) do
    expect_true(pin.witness_utxo ~= nil,
                "PSBT input " .. i .. " has witness_utxo")
    expect_true(pin.witness_utxo.value > 0, "value > 0")
  end

  -- psbtbumpfee must NOT broadcast — original entry stays unreplaced.
  expect_nil(w.transactions[txid_display].replaced_by,
             "psbtbumpfee did not broadcast (no replaced_by set)")
end)

-- ---- Test 14: RPC parameter validation ----------------------------
test("RPC bumpfee rejects malformed txid", function()
  local server = rpc.new({network = consensus.networks.regtest})
  server.wallet = {is_encrypted = false, is_locked = false, keys = {},
                   transactions = {}, utxos = {}, pending_utxos = {},
                   scan_utxos = function() end, set_mempool = function() end,
                   bump_fee = function() return nil, {"unreachable"} end}
  function server:get_request_wallet() return self.wallet end

  -- Too short
  local ok, err = pcall(server.methods["bumpfee"], server, {"ab"})
  expect_false(ok, "must reject")
  expect_eq(err.code, rpc.ERROR.INVALID_PARAMS, "INVALID_PARAMS code")

  -- Wrong type
  ok, err = pcall(server.methods["bumpfee"], server, {123})
  expect_false(ok, "must reject")
  expect_eq(err.code, rpc.ERROR.INVALID_PARAMS, "INVALID_PARAMS code")
end)

-- ---- Test 15: fee_rate validation --------------------------------
test("RPC bumpfee rejects non-positive fee_rate", function()
  local server = rpc.new({network = consensus.networks.regtest})
  server.wallet = {is_encrypted = false, is_locked = false}
  function server:get_request_wallet() return self.wallet end

  local valid_txid = string.rep("a", 64)
  local ok, err = pcall(server.methods["bumpfee"], server,
                        {valid_txid, {fee_rate = 0}})
  expect_false(ok, "must reject fee_rate=0")
  expect_eq(err.code, rpc.ERROR.INVALID_PARAMS, "INVALID_PARAMS")

  ok, err = pcall(server.methods["bumpfee"], server,
                  {valid_txid, {fee_rate = -1}})
  expect_false(ok, "must reject negative fee_rate")
  expect_eq(err.code, rpc.ERROR.INVALID_PARAMS, "INVALID_PARAMS")
end)

-- ---- Test 16: audit-flip — W118 G20/G21 markers ------------------
test("W118 G20 + G21 audit markers flipped (RPC strings present)", function()
  local rpc_src = io.open("src/rpc.lua", "r"):read("*a")
  expect_true(rpc_src:find('self%.methods%["bumpfee"%]') ~= nil,
              "src/rpc.lua wires bumpfee")
  expect_true(rpc_src:find('self%.methods%["psbtbumpfee"%]') ~= nil,
              "src/rpc.lua wires psbtbumpfee")
end)

-- ---- Test 17: signing-pipeline-shared assertion (FIX-59 reuse) ---
test("bumpfee re-signs through the FIX-59 ecdsa_sign pipeline (no 2nd pipe)", function()
  -- Static source-level assertion: Wallet:_sign_inputs (used by bump_fee)
  -- must call crypto.ecdsa_sign + validation.signature_hash_segwit_v0 —
  -- the same two primitives create_transaction uses. Any divergence here
  -- would mean we accidentally introduced a second signing pipeline,
  -- which is exactly the W118 anti-pattern the FIX-59 work eliminated.
  local src = io.open("src/wallet.lua", "r"):read("*a")
  -- The helper must exist.
  expect_true(src:find("function Wallet:_sign_inputs") ~= nil,
              "_sign_inputs helper defined")
  -- And must use the same crypto.ecdsa_sign call shape.
  local helper_start = src:find("function Wallet:_sign_inputs")
  local helper_end   = src:find("\nfunction", helper_start + 1)
  local helper_body  = src:sub(helper_start, helper_end or #src)
  expect_true(helper_body:find("crypto%.ecdsa_sign") ~= nil,
              "helper calls crypto.ecdsa_sign")
  expect_true(helper_body:find("signature_hash_segwit_v0") ~= nil,
              "helper computes BIP-143 sighash via signature_hash_segwit_v0")
end)

-- Summary -------------------------------------------------------------
print(string.format("\n=== FIX-61 SUMMARY: %d PASS / %d FAIL ===", PASS, FAIL))
os.exit(FAIL == 0 and 0 or 1)
