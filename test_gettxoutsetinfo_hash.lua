#!/usr/bin/env luajit
-- Regression test for gettxoutsetinfo.hash_serialized_3 (W?? cleanup).
--
-- Verifies the RPC method now returns SHA256d (Core HashWriter::GetHash)
-- of the canonical TxOutSer stream over the chainstate, instead of the
-- previous all-zero stub at src/rpc.lua:5646.
--
-- Per bitcoin-core/src/kernel/coinstats.cpp:161-163 + hash.h:115-119:
--   hash_serialized_3 = SHA256d(streamed TxOutSer per (outpoint, coin))
-- where coins are visited in (txid lex-asc, vout uint32-asc) order, and
-- the RPC field is hex-encoded big-endian (uint256.GetHex byte-reverse).
--
-- Run: luajit test_gettxoutsetinfo_hash.lua

package.path = "lunarblock/?.lua;src/?.lua;" .. package.path

local rpc = require("lunarblock.rpc")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local types = require("lunarblock.types")
local crypto = require("lunarblock.crypto")
local script_mod = require("lunarblock.script")
local storage_mod = require("lunarblock.storage")
local cjson = require("cjson")

local function test(name, func)
  io.write("Testing: " .. name .. " ... ")
  local ok, err = pcall(func)
  if ok then
    print("PASS")
  else
    print("FAIL: " .. tostring(err))
    os.exit(1)
  end
end

local function tmp_path(tag)
  return "/tmp/lb_gettxoutsetinfo_" .. tag .. "_" ..
    os.time() .. "_" .. math.random(1000000)
end

local function reverse_hex(raw_bytes)
  -- Match the rpc.lua reversal: byte 32 first, byte 1 last.
  assert(#raw_bytes == 32, "expected 32 raw bytes")
  local out = {}
  for i = 32, 1, -1 do
    out[#out + 1] = string.format("%02x", raw_bytes:byte(i))
  end
  return table.concat(out)
end

-- ---------------------------------------------------------------------------
-- Test 1: empty UTXO set returns canonical SHA256d("") in big-endian hex.
--
-- HashWriter with zero bytes written returns SHA256d of the empty input.
-- SHA256("")  = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
-- SHA256d("") = SHA256(e3b0...b855) = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
-- Big-endian display (Core uint256::GetHex):
--   56944c5d3f98413ec45cf5454553810cccfc 9928e0578270 ad9 591376 12e0e0f65d
-- We compute the expected value via crypto.sha256 to keep the constant
-- in one place and avoid a transcription bug in the test.
-- ---------------------------------------------------------------------------
print("=== gettxoutsetinfo.hash_serialized_3 regression tests ===\n")

test("empty UTXO set returns SHA256d('') in big-endian hex", function()
  local db = storage_mod.open(tmp_path("empty"))
  -- Build a chain_state but DON'T call init() — connect_genesis adds a
  -- coinbase to the UTXO set, which would make the hash non-empty.
  -- We want the pure SHA256d-of-empty to verify the wiring.
  local cs = utxo.new_chain_state(db, consensus.networks.regtest)
  -- Provide a tip so the RPC handler doesn't bail on the early guard.
  cs.tip_hash = types.hash256(string.rep("\x00", 32))
  cs.tip_height = 0

  local server = rpc.new({
    chain_state = cs,
    storage = db,
    network = consensus.networks.regtest,
  })

  local request = '{"jsonrpc":"1.0","method":"gettxoutsetinfo","params":[],"id":1}'
  local response = server:handle_request(request)
  local decoded = cjson.decode(response)

  db.close()

  assert(decoded.error == cjson.null,
    "rpc returned error: " .. cjson.encode(decoded.error))
  assert(decoded.result, "missing result")
  local got_hex = decoded.result.hash_serialized_3
  assert(type(got_hex) == "string", "hash_serialized_3 not a string")
  assert(#got_hex == 64,
    "hash_serialized_3 length " .. #got_hex .. " (expected 64)")

  -- Independent reference: SHA256d of the empty string, reversed for
  -- Core's big-endian display.
  local single = crypto.sha256("")
  local sha_d = crypto.sha256(single)
  local expected_hex = reverse_hex(sha_d)

  assert(got_hex == expected_hex, string.format(
    "hash_serialized_3 mismatch:\n  got:      %s\n  expected: %s",
    got_hex, expected_hex))
  -- Hard guard against the old stub regression.
  assert(got_hex ~= string.rep("0", 64),
    "hash_serialized_3 still returns the all-zero stub")
  assert(decoded.result.txouts == 0,
    "txouts should be 0 (got " .. tostring(decoded.result.txouts) .. ")")
end)

-- ---------------------------------------------------------------------------
-- Test 2: known fixture UTXO set returns the SHA256d of the canonical
-- TxOutSer stream byte-for-byte.  Mirrors the assumeutxo strict-gate
-- contract at validation.cpp:5904-5915 so any future regression there
-- (e.g. swapping in MuHash) is also caught here.
-- ---------------------------------------------------------------------------
test("known UTXO fixture matches independently-streamed SHA256d", function()
  local db = storage_mod.open(tmp_path("fixture"))
  local cs = utxo.new_chain_state(db, consensus.networks.regtest)
  -- Skip init() so the chainstate has only our fixtures and we can
  -- compute the expected hash from a fixed reference stream.

  -- Three UTXOs across two txids; one with vout 256 to exercise the
  -- group-by-txid + numeric-vout-sort path that compute_utxo_hash uses
  -- (matching Core's std::map<uint32_t, Coin>).  Same pattern as
  -- spec/utxo_snapshot_core_spec.lua "compute_utxo_hash returns
  -- SHA256d of canonical TxOutSer stream" test.
  local txid_a = types.hash256(string.rep("\x10", 32))
  local txid_b = types.hash256(string.rep("\x20", 32))
  local fixtures = {
    { txid = txid_a, vout = 1,
      entry = utxo.utxo_entry(50,
        script_mod.make_p2pkh_script(string.rep("\x33", 20)), 11, true) },
    { txid = txid_a, vout = 256,
      entry = utxo.utxo_entry(99,
        script_mod.make_p2pkh_script(string.rep("\x44", 20)), 12, false) },
    { txid = txid_b, vout = 0,
      entry = utxo.utxo_entry(7,
        script_mod.make_p2pkh_script(string.rep("\x55", 20)), 13, false) },
  }
  for _, f in ipairs(fixtures) do
    cs.coin_view:add(f.txid, f.vout, f.entry)
  end
  cs.coin_view:flush()

  cs.tip_hash = types.hash256(string.rep("\xab", 32))
  cs.tip_height = 13

  -- Independent reference: stream TxOutSer in (txid lex, vout asc)
  -- order through a single SHA256 then once more for SHA256d.
  local ref = crypto.sha256_init()
  ref.update(utxo.serialize_txoutser(
    utxo.outpoint_key(txid_a, 1),   fixtures[1].entry))
  ref.update(utxo.serialize_txoutser(
    utxo.outpoint_key(txid_a, 256), fixtures[2].entry))
  ref.update(utxo.serialize_txoutser(
    utxo.outpoint_key(txid_b, 0),   fixtures[3].entry))
  local expected_raw = crypto.sha256(ref.final())
  local expected_hex = reverse_hex(expected_raw)

  local server = rpc.new({
    chain_state = cs,
    storage = db,
    network = consensus.networks.regtest,
  })

  local request = '{"jsonrpc":"1.0","method":"gettxoutsetinfo","params":[],"id":1}'
  local response = server:handle_request(request)
  local decoded = cjson.decode(response)
  db.close()

  assert(decoded.error == cjson.null,
    "rpc returned error: " .. cjson.encode(decoded.error))
  local got_hex = decoded.result.hash_serialized_3
  assert(got_hex == expected_hex, string.format(
    "hash_serialized_3 mismatch:\n  got:      %s\n  expected: %s",
    got_hex, expected_hex))
  assert(got_hex ~= string.rep("0", 64),
    "hash_serialized_3 still returns the all-zero stub")
  assert(decoded.result.txouts == 3,
    "txouts mismatch: got " .. tostring(decoded.result.txouts))
  -- 50 + 99 + 7 = 156 sats
  assert(decoded.result.total_amount == 156 / 1e8,
    "total_amount mismatch: " .. tostring(decoded.result.total_amount))
end)

print("\nAll tests passed.")
