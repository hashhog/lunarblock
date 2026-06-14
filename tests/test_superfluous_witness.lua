#!/usr/bin/env luajit
-- test_superfluous_witness.lua
-- Regression test for Finding D (BUG-5/6 in w142 notes):
--   A transaction serialised with the BIP-144 segwit marker (0x00) + flag
--   (0x01) bytes but with every input's witness stack empty MUST be rejected
--   during deserialisation with "Superfluous witness record".
--
-- Bitcoin Core reference:
--   src/primitives/transaction.h:228-231
--     if (!tx.HasWitness()) {
--       throw std::ios_base::failure("Superfluous witness record");
--     }
--
-- camlcoin reference pattern:
--   camlcoin/lib/serialize.ml:264-266
--     if List.for_all (fun wit -> wit.Types.items = []) w then
--       failwith "Superfluous witness record";
--
-- Test vector: 63-byte tx hex that parses cleanly in every field except the
-- consensus rule (segwit marker+flag set, single input, witness stack = 0 items).
--   0100000000010100...(32 zero bytes)...00 00000000 ffffffff
--   01 00f2052a01000000 00 00 00000000
--   Bytes: ver(4)+marker(1)+flag(1)+vin_cnt(1)+outpoint(36)+script(1)+seq(4)
--          +vout_cnt(1)+value(8)+scriptPubKey(1)+witness_stack_cnt(1)+locktime(4) = 63
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   LD_LIBRARY_PATH=./lib luajit tests/test_superfluous_witness.lua

package.path = "src/?.lua;./?.lua;" .. package.path

local loaders = package.loaders or package.searchers
table.insert(loaders, 2, function(module)
  local name = module:match("^lunarblock%.(.+)")
  if name then
    local filename = "src/" .. name .. ".lua"
    local f = io.open(filename)
    if f then f:close(); return loadfile(filename) end
  end
end)

local serialize = require("lunarblock.serialize")

local PASS, FAIL = 0, 0

local function expect_true(v, name)
  if v then
    PASS = PASS + 1
    print("PASS " .. name)
  else
    FAIL = FAIL + 1
    print("FAIL " .. name)
  end
end

local function hex_decode(h)
  local out = {}
  for i = 1, #h, 2 do
    out[#out + 1] = string.char(tonumber(h:sub(i, i + 1), 16))
  end
  return table.concat(out)
end

-- -------------------------------------------------------------------------
-- Test 1: the 63-byte "superfluous witness" vector MUST be rejected.
--
-- This is the canonical Core test vector: marker+flag set but the single
-- input's witness stack has 0 items.  Core rejects at UnserializeTransaction
-- line 228-231 (HasWitness() == false -> ios_base::failure).
-- -------------------------------------------------------------------------
do
  -- 126 hex chars = 63 bytes (the canonical Core-cited test vector)
  local TX_HEX = "0100000000010100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0100f2052a01000000000000000000"
  local raw = hex_decode(TX_HEX)
  local ok, err = pcall(serialize.deserialize_transaction, raw)
  expect_true(not ok, "superfluous-witness vector is rejected")
  expect_true(
    not ok and type(err) == "string" and err:find("Superfluous witness record"),
    "rejection message contains 'Superfluous witness record'"
  )
end

-- -------------------------------------------------------------------------
-- Test 2: same structure but with a 1-byte witness item MUST be accepted.
--
-- Confirms the guard is narrowly scoped: non-empty witness keeps passing.
-- -------------------------------------------------------------------------
do
  local w = serialize.buffer_writer()
  w.write_i32le(1)       -- version
  w.write_u8(0x00)       -- BIP-144 marker
  w.write_u8(0x01)       -- BIP-144 flag
  w.write_varint(1)      -- 1 input
  for _ = 1, 32 do w.write_u8(0) end  -- prev hash
  w.write_u32le(0)       -- prev index
  w.write_varint(0)      -- empty scriptSig
  w.write_u32le(0xffffffff)  -- sequence
  w.write_varint(1)      -- 1 output
  w.write_i64le(5000000000)
  w.write_varint(0)      -- empty scriptPubKey
  -- witness for input 0: 1 item of 1 byte (non-empty -> HasWitness() true)
  w.write_varint(1)
  w.write_varstr("\x42")
  w.write_u32le(0)       -- locktime
  local raw = w.result()

  local ok, tx = pcall(serialize.deserialize_transaction, raw)
  expect_true(ok, "valid segwit tx with non-empty witness is accepted")
  expect_true(
    ok and tx.segwit == true,
    "valid segwit tx has segwit=true"
  )
  expect_true(
    ok and tx.inputs[1] and #tx.inputs[1].witness == 1,
    "valid segwit tx witness stack has 1 item"
  )
end

-- -------------------------------------------------------------------------
-- Test 3: multi-input tx where ALL inputs have empty stacks MUST be rejected.
--
-- Ensures the check iterates over all inputs, not just the first.
-- -------------------------------------------------------------------------
do
  local w = serialize.buffer_writer()
  w.write_i32le(1)
  w.write_u8(0x00)
  w.write_u8(0x01)
  w.write_varint(2)      -- 2 inputs
  for _ = 1, 2 do
    for _ = 1, 32 do w.write_u8(0) end
    w.write_u32le(0)
    w.write_varint(0)
    w.write_u32le(0xffffffff)
  end
  w.write_varint(1)
  w.write_i64le(5000000000)
  w.write_varint(0)
  -- witness for input 0: empty
  w.write_varint(0)
  -- witness for input 1: empty
  w.write_varint(0)
  w.write_u32le(0)
  local raw = w.result()

  local ok, err = pcall(serialize.deserialize_transaction, raw)
  expect_true(not ok, "2-input tx with all-empty witnesses is rejected")
  expect_true(
    not ok and type(err) == "string" and err:find("Superfluous witness record"),
    "2-input rejection message contains 'Superfluous witness record'"
  )
end

-- -------------------------------------------------------------------------
-- Test 4: 2-input tx where only the SECOND input has a witness MUST be
-- accepted (HasWitness() true if any input has a non-empty stack).
-- -------------------------------------------------------------------------
do
  local w = serialize.buffer_writer()
  w.write_i32le(1)
  w.write_u8(0x00)
  w.write_u8(0x01)
  w.write_varint(2)
  for _ = 1, 2 do
    for _ = 1, 32 do w.write_u8(0) end
    w.write_u32le(0)
    w.write_varint(0)
    w.write_u32le(0xffffffff)
  end
  w.write_varint(1)
  w.write_i64le(5000000000)
  w.write_varint(0)
  -- witness for input 0: empty
  w.write_varint(0)
  -- witness for input 1: 1 item
  w.write_varint(1)
  w.write_varstr("\x01")
  w.write_u32le(0)
  local raw = w.result()

  local ok, tx = pcall(serialize.deserialize_transaction, raw)
  expect_true(ok, "2-input tx where only input 1 has witness is accepted")
  expect_true(
    ok and tx.segwit == true,
    "2-input partial-witness tx has segwit=true"
  )
end

-- -------------------------------------------------------------------------
-- Test 5: legacy (non-segwit) tx is unaffected by the guard.
-- -------------------------------------------------------------------------
do
  local w = serialize.buffer_writer()
  w.write_i32le(1)
  w.write_varint(1)
  for _ = 1, 32 do w.write_u8(0) end
  w.write_u32le(0)
  w.write_varint(0)
  w.write_u32le(0xffffffff)
  w.write_varint(1)
  w.write_i64le(5000000000)
  w.write_varint(0)
  w.write_u32le(0)
  local raw = w.result()

  local ok, tx = pcall(serialize.deserialize_transaction, raw)
  expect_true(ok, "legacy non-segwit tx is accepted")
  expect_true(ok and tx.segwit == false, "legacy tx has segwit=false")
end

print(string.format("\n=== SUMMARY: %d PASS / %d FAIL ===", PASS, FAIL))
if FAIL > 0 then os.exit(1) end
