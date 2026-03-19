#!/usr/bin/env luajit
-- Simple PSBT test script

-- Setup module paths
package.path = "lunarblock/?.lua;src/?.lua;" .. package.path

local psbt = require("lunarblock.psbt")
local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local crypto = require("lunarblock.crypto")
local validation = require("lunarblock.validation")
local consensus = require("lunarblock.consensus")

local function test(name, func)
  io.write("Testing: " .. name .. " ... ")
  local ok, err = pcall(func)
  if ok then
    print("PASS")
  else
    print("FAIL: " .. tostring(err))
  end
end

print("=== PSBT Module Tests ===\n")

test("MAGIC constant", function()
  assert(psbt.MAGIC == "psbt\xff", "incorrect magic")
end)

test("base64 encode/decode", function()
  local data = "Hello, PSBT!"
  local encoded = psbt.base64_encode(data)
  local decoded = psbt.base64_decode(encoded)
  assert(decoded == data, "round-trip failed")
end)

test("base64 binary data", function()
  local data = "\x00\x01\x02\xff\xfe"
  local encoded = psbt.base64_encode(data)
  local decoded = psbt.base64_decode(encoded)
  assert(decoded == data, "binary round-trip failed")
end)

test("create PSBT from unsigned tx", function()
  local txid = types.hash256(string.rep("\x01", 32))
  local inputs = {
    types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD),
  }
  local outputs = {
    types.txout(50000, "\x00\x14" .. string.rep("\x02", 20)),
  }
  local tx = types.transaction(2, inputs, outputs, 0)

  local p = psbt.new(tx)
  assert(p ~= nil, "PSBT is nil")
  assert(p.version == 0, "wrong version")
  assert(#p.inputs == 1, "wrong input count")
  assert(#p.outputs == 1, "wrong output count")
end)

test("reject signed transaction", function()
  local txid = types.hash256(string.rep("\x01", 32))
  local inputs = {
    types.txin(types.outpoint(txid, 0), "\x01\x02\x03", 0xFFFFFFFF),
  }
  local outputs = {
    types.txout(50000, "\x00\x14" .. string.rep("\x02", 20)),
  }
  local tx = types.transaction(2, inputs, outputs, 0)

  local ok, _ = pcall(psbt.new, tx)
  assert(not ok, "should have rejected signed tx")
end)

test("serialize/deserialize round-trip", function()
  local txid = types.hash256(string.rep("\x03", 32))
  local inputs = {
    types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD),
  }
  local outputs = {
    types.txout(50000, "\x00\x14" .. string.rep("\x04", 20)),
  }
  local tx = types.transaction(2, inputs, outputs, 0)
  local p = psbt.new(tx)

  local data = psbt.serialize(p)
  assert(data:sub(1, 5) == "psbt\xff", "missing magic")

  local p2 = psbt.deserialize(data)
  assert(#p2.inputs == 1, "wrong input count after deserialize")
  assert(#p2.outputs == 1, "wrong output count after deserialize")

  local txid1 = types.hash256_hex(validation.compute_txid(p.tx))
  local txid2 = types.hash256_hex(validation.compute_txid(p2.tx))
  assert(txid1 == txid2, "txid mismatch")
end)

test("base64 round-trip", function()
  local txid = types.hash256(string.rep("\x05", 32))
  local inputs = {
    types.txin(types.outpoint(txid, 1), "", 0xFFFFFFFF),
  }
  local outputs = {
    types.txout(100000, "\x76\xa9\x14" .. string.rep("\x06", 20) .. "\x88\xac"),
  }
  local tx = types.transaction(2, inputs, outputs, 500000)
  local p = psbt.new(tx)

  local b64 = psbt.to_base64(p)
  local p2 = psbt.from_base64(b64)

  assert(p2.tx.locktime == tx.locktime, "locktime mismatch")
  assert(p2.tx.version == tx.version, "version mismatch")
end)

test("add witness UTXO", function()
  local txid = types.hash256(string.rep("\x07", 32))
  local tx = types.transaction(2, {
    types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD),
  }, {types.txout(50000, "\x00\x14" .. string.rep("\x08", 20))}, 0)
  local p = psbt.new(tx)

  psbt.update_input_utxo(p, 0, {
    value = 100000,
    script_pubkey = "\x00\x14" .. string.rep("\x09", 20),
  }, true)

  assert(p.inputs[1].witness_utxo ~= nil, "witness_utxo not set")
  assert(p.inputs[1].witness_utxo.value == 100000, "wrong value")
end)

test("add redeem script", function()
  local txid = types.hash256(string.rep("\x0a", 32))
  local tx = types.transaction(2, {
    types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD),
  }, {types.txout(50000, "\x00\x14" .. string.rep("\x0b", 20))}, 0)
  local p = psbt.new(tx)

  local redeem = "\x52\x21" .. string.rep("\x0c", 33) .. "\x21" .. string.rep("\x0d", 33) .. "\x52\xae"
  psbt.update_input_redeem_script(p, 0, redeem)

  assert(p.inputs[1].redeem_script == redeem, "redeem script mismatch")
end)

test("sign P2WPKH input", function()
  local privkey = string.rep("\x11", 32)
  local pubkey = crypto.pubkey_from_privkey(privkey, true)
  local pkh = crypto.hash160(pubkey)
  local script_pubkey = "\x00\x14" .. pkh

  local txid = types.hash256(string.rep("\x12", 32))
  local tx = types.transaction(2, {
    types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD),
  }, {types.txout(50000, "\x00\x14" .. string.rep("\x13", 20))}, 0)
  local p = psbt.new(tx)

  psbt.update_input_utxo(p, 0, {
    value = 100000,
    script_pubkey = script_pubkey,
  }, true)

  local signed = psbt.sign_input(p, 0, privkey, pubkey)
  assert(signed, "signing failed")

  local pk_hex = psbt.hex_encode(pubkey)
  assert(p.inputs[1].partial_sigs[pk_hex] ~= nil, "partial sig not found")
end)

test("combine PSBTs", function()
  local txid = types.hash256(string.rep("\x14", 32))
  local tx = types.transaction(2, {
    types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD),
  }, {types.txout(50000, "\x00\x14" .. string.rep("\x15", 20))}, 0)

  local p1 = psbt.new(tx)
  local p2 = psbt.deserialize(psbt.serialize(p1))

  local pk1 = string.rep("\x16", 33)
  local pk2 = string.rep("\x17", 33)
  local sig1 = string.rep("\x18", 72) .. "\x01"
  local sig2 = string.rep("\x19", 72) .. "\x01"

  p1.inputs[1].partial_sigs[psbt.hex_encode(pk1)] = sig1
  p2.inputs[1].partial_sigs[psbt.hex_encode(pk2)] = sig2

  local combined = psbt.combine({p1, p2})

  assert(combined.inputs[1].partial_sigs[psbt.hex_encode(pk1)] ~= nil, "missing sig 1")
  assert(combined.inputs[1].partial_sigs[psbt.hex_encode(pk2)] ~= nil, "missing sig 2")
end)

test("finalize P2WPKH input", function()
  local privkey = string.rep("\x1e", 32)
  local pubkey = crypto.pubkey_from_privkey(privkey, true)
  local pkh = crypto.hash160(pubkey)
  local script_pubkey = "\x00\x14" .. pkh

  local txid = types.hash256(string.rep("\x1f", 32))
  local tx = types.transaction(2, {
    types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD),
  }, {types.txout(50000, "\x00\x14" .. string.rep("\x20", 20))}, 0)
  local p = psbt.new(tx)

  psbt.update_input_utxo(p, 0, {
    value = 100000,
    script_pubkey = script_pubkey,
  }, true)
  psbt.sign_input(p, 0, privkey, pubkey)

  local ok = psbt.finalize_input(p, 0)
  assert(ok, "finalization failed")
  assert(p.inputs[1].final_script_witness ~= nil, "no final witness")
  assert(#p.inputs[1].final_script_witness == 2, "wrong witness count")
end)

test("extract signed transaction", function()
  local privkey = string.rep("\x21", 32)
  local pubkey = crypto.pubkey_from_privkey(privkey, true)
  local pkh = crypto.hash160(pubkey)
  local script_pubkey = "\x00\x14" .. pkh

  local txid = types.hash256(string.rep("\x22", 32))
  local tx = types.transaction(2, {
    types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD),
  }, {types.txout(50000, "\x00\x14" .. string.rep("\x23", 20))}, 0)
  local p = psbt.new(tx)

  psbt.update_input_utxo(p, 0, {
    value = 100000,
    script_pubkey = script_pubkey,
  }, true)
  psbt.sign_input(p, 0, privkey, pubkey)
  psbt.finalize(p)

  local signed_tx = psbt.extract(p)
  assert(signed_tx ~= nil, "extraction failed")
  assert(signed_tx.segwit, "not segwit")
  assert(#signed_tx.inputs[1].witness == 2, "wrong witness count")

  local sig = signed_tx.inputs[1].witness[1]
  assert(#sig >= 71 and #sig <= 73, "invalid sig length")
  assert(sig:byte(#sig) == 0x01, "wrong sighash type")
end)

test("decode PSBT", function()
  local txid = types.hash256(string.rep("\x26", 32))
  local tx = types.transaction(2, {
    types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD),
  }, {types.txout(50000, "\x00\x14" .. string.rep("\x27", 20))}, 0)
  local p = psbt.new(tx)

  psbt.update_input_utxo(p, 0, {
    value = 100000,
    script_pubkey = "\x00\x14" .. string.rep("\x28", 20),
  }, true)

  local decoded = psbt.decode(p)
  assert(decoded.tx ~= nil, "no tx")
  assert(decoded.tx.txid ~= nil, "no txid")
  assert(decoded.tx.version == 2, "wrong version")
  assert(#decoded.inputs == 1, "wrong input count")
  assert(#decoded.outputs == 1, "wrong output count")
  assert(decoded.inputs[1].has_utxo, "utxo not detected")
  assert(decoded.fee == (100000 - 50000) / consensus.COIN, "wrong fee")
end)

test("PSBT status functions", function()
  local txid = types.hash256(string.rep("\x29", 32))
  local tx = types.transaction(2, {
    types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFF),
  }, {types.txout(50000, "\x00\x14" .. string.rep("\x2a", 20))}, 0)
  local p = psbt.new(tx)

  assert(not psbt.input_is_signed(p.inputs[1]), "should not be signed")
  assert(not psbt.is_complete(p), "should not be complete")
  assert(psbt.count_unsigned(p) == 1, "wrong unsigned count")

  p.inputs[1].final_script_witness = {"sig", "pubkey"}
  assert(psbt.input_is_signed(p.inputs[1]), "should be signed")
  assert(psbt.is_complete(p), "should be complete")
  assert(psbt.count_unsigned(p) == 0, "should be 0 unsigned")
end)

test("full workflow: create -> update -> sign -> finalize -> extract", function()
  -- 1. Create transaction
  local prev_txid = types.hash256(string.rep("\x30", 32))
  local tx = types.transaction(2, {
    types.txin(types.outpoint(prev_txid, 0), "", 0xFFFFFFFD),
  }, {
    types.txout(50000, "\x00\x14" .. string.rep("\x31", 20)),
    types.txout(49000, "\x00\x14" .. string.rep("\x32", 20)),
  }, 0)

  -- 2. Create PSBT (Creator)
  local p = psbt.new(tx)

  -- Serialize and deserialize (simulate transfer)
  local b64 = psbt.to_base64(p)
  p = psbt.from_base64(b64)

  -- 3. Update (Updater)
  local privkey = string.rep("\x33", 32)
  local pubkey = crypto.pubkey_from_privkey(privkey, true)
  local pkh = crypto.hash160(pubkey)
  local script_pubkey = "\x00\x14" .. pkh

  psbt.update_input_utxo(p, 0, {
    value = 100000,
    script_pubkey = script_pubkey,
  }, true)

  psbt.update_input_bip32(p, 0, pubkey, "\x00\x00\x00\x00",
    {0x8000002c, 0x80000000, 0x80000000, 0, 0})

  -- 4. Sign (Signer)
  local signed = psbt.sign_input(p, 0, privkey, pubkey)
  assert(signed, "signing failed")

  -- 5. Finalize (Finalizer)
  local finalized = psbt.finalize(p)
  assert(finalized, "finalization failed")
  assert(psbt.is_complete(p), "not complete")

  -- 6. Extract (Extractor)
  local signed_tx = psbt.extract(p)
  assert(signed_tx ~= nil, "extraction failed")
  assert(signed_tx.segwit, "not segwit")
  assert(#signed_tx.inputs == 1, "wrong input count")
  assert(#signed_tx.outputs == 2, "wrong output count")
  assert(signed_tx.outputs[1].value == 50000, "wrong output 1 value")
  assert(signed_tx.outputs[2].value == 49000, "wrong output 2 value")

  -- Verify we can serialize the final tx
  local tx_hex = psbt.hex_encode(serialize.serialize_transaction(signed_tx, true))
  assert(#tx_hex > 0, "empty tx hex")
end)

print("\n=== All Tests Complete ===")
