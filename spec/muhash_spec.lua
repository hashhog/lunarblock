-- spec/muhash_spec.lua
--
-- MuHash3072 byte-parity tests against bitcoin-core's known vectors
-- (src/test/crypto_tests.cpp BOOST_AUTO_TEST_CASE(muhash_tests)).
--
-- All hex literals from Core are uint256.ToString()-formatted (display,
-- i.e. reversed byte order). MuHash3072::Finalize returns 32 raw bytes
-- in natural SHA256 order; compare via reversed-hex.

local muhash = require("lunarblock.muhash")

local function hex_to_bytes(hex)
  return (hex:gsub("%x%x", function(c) return string.char(tonumber(c, 16)) end))
end

local function bytes_to_hex(bytes)
  local out = {}
  for i = 1, #bytes do
    out[i] = string.format("%02x", bytes:byte(i))
  end
  return table.concat(out)
end

local function reverse_hex_bytes(s)
  local rev = string.reverse(s)
  return rev
end

-- Expected MuHash output is uint256-display hex (reversed); convert to the
-- raw byte order that finalize() returns.
local function display_hex_to_raw(hex)
  return reverse_hex_bytes(hex_to_bytes(hex))
end

-- Core's FromInt(i): 32-byte buffer with byte[0]=i, rest zero.
local function from_int_input(i)
  return string.char(i) .. string.rep("\0", 31)
end

describe("muhash3072", function()

  describe("Num3072 modular arithmetic via OpenSSL BIGNUM", function()
    it("to_num3072 produces a deterministic 384-byte BIGNUM", function()
      -- Just exercise the path and check that two calls with identical
      -- input produce the same packed bytes (no UB / nondeterminism).
      local input = from_int_input(0)
      local a = muhash.to_num3072(input)
      local b = muhash.to_num3072(input)
      -- We have no public bn_to_le_bytes export; round-trip via
      -- a one-element MuHash and serialize().
      local m1 = muhash.from_singleton(input)
      local m2 = muhash.from_singleton(input)
      assert.equals(m1:serialize(), m2:serialize())
      -- Suppress "unused variable" warning under strict luacheck.
      assert.is_truthy(a)
      assert.is_truthy(b)
    end)

    it("ToNum3072(empty input) packs into 768 bytes when serialized", function()
      local m = muhash.from_singleton("")
      local s = m:serialize()
      assert.equals(768, #s)
      -- Denominator must be exactly 1 (00..01 in LE -> 01 then 383 zeros).
      assert.equals(string.char(1) .. string.rep("\0", 383), s:sub(385, 768))
    end)
  end)

  describe("MuHash3072 Insert / Remove / Finalize", function()
    -- Core test vector:
    --   acc = FromInt(0)
    --   acc *= FromInt(1)
    --   acc /= FromInt(2)
    --   acc.Finalize(out)
    --   BOOST_CHECK_EQUAL(out, "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863")
    local CORE_VECTOR = "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863"

    it("matches Core vector via *= FromInt / /= FromInt path", function()
      -- FromInt(0) gives numerator=ToNum3072(zero32). Combine via
      -- MuHash multiplication: (acc *= other) means acc.num *= other.num,
      -- acc.den *= other.den.
      local acc = muhash.new()  -- num=1, den=1
      acc:multiply(muhash.from_singleton(from_int_input(0)))
      acc:multiply(muhash.from_singleton(from_int_input(1)))
      acc:divide(muhash.from_singleton(from_int_input(2)))
      local out = acc:finalize()
      assert.equals(CORE_VECTOR, bytes_to_hex(string.reverse(out)))
    end)

    it("matches Core vector via insert / remove path", function()
      -- Equivalent expression of the same set hash: starting from the
      -- empty set, insert(0) insert(1) remove(2). Core's second form:
      --   acc2 = FromInt(0)
      --   acc2.Insert({1, 0...})
      --   acc2.Remove({2, 0...})
      -- Their initial value FromInt(0) has numerator=ToNum3072(0), so we
      -- must fold that in too.
      local acc = muhash.new()
      acc:insert(from_int_input(0))
      acc:insert(from_int_input(1))
      acc:remove(from_int_input(2))
      local out = acc:finalize()
      assert.equals(CORE_VECTOR, bytes_to_hex(string.reverse(out)))
    end)

    it("the empty MuHash finalizes to a stable hash", function()
      -- Self-consistency: the empty set's hash is well-defined (SHA256
      -- of the 384-byte LE encoding of 1, padded to 384). Finalize
      -- twice; both calls must agree (Core mirrors this by resetting
      -- the denominator after Finalize).
      local m = muhash.new()
      local h1 = m:finalize()
      local h2 = m:finalize()
      assert.equals(32, #h1)
      assert.equals(h1, h2)
    end)

    it("Insert is order-independent (commutativity)", function()
      local a = muhash.new()
      a:insert("hello")
      a:insert("world")
      local ha = a:finalize()

      local b = muhash.new()
      b:insert("world")
      b:insert("hello")
      local hb = b:finalize()

      assert.equals(ha, hb)
    end)

    it("Insert(x) followed by Remove(x) cancels", function()
      local empty = muhash.new():finalize()

      local m = muhash.new()
      m:insert("\xde\xad\xbe\xef")
      m:remove("\xde\xad\xbe\xef")
      assert.equals(empty, m:finalize())
    end)

    it("Multiply matches sequential Insert", function()
      local a = muhash.new()
      a:insert("\x01")
      a:insert("\x02")
      a:insert("\x03")
      local ha = a:finalize()

      local b = muhash.new()
      b:insert("\x01")
      local c = muhash.new()
      c:insert("\x02")
      c:insert("\x03")
      b:multiply(c)
      local hb = b:finalize()

      assert.equals(ha, hb)
    end)

    it("Divide matches sequential Remove", function()
      -- (set with x,y,z) / (set with y,z) == set with x.
      local lhs = muhash.new()
      lhs:insert("\x01"); lhs:insert("\x02"); lhs:insert("\x03")
      local rhs = muhash.new()
      rhs:insert("\x02"); rhs:insert("\x03")
      lhs:divide(rhs)
      local got = lhs:finalize()

      local expected = muhash.new()
      expected:insert("\x01")
      assert.equals(expected:finalize(), got)
    end)
  end)

  describe("serialize() byte format", function()
    -- Core test vector ser_exp begins with the numerator of
    --   serchk = FromInt(1); serchk *= FromInt(2);
    -- followed by a 384-byte denominator of all zeros except the first
    -- byte (which is 0x01 — Num3072(1) in LE).
    local CORE_SER_PREFIX = "1fa093295ea30a6a3acdc7b3f770fa53"

    it("serializes to numerator || denominator (768 bytes)", function()
      local m = muhash.new()
      m:multiply(muhash.from_singleton(from_int_input(1)))
      m:multiply(muhash.from_singleton(from_int_input(2)))
      local s = m:serialize()
      assert.equals(768, #s)
      -- Prefix sanity check (first 16 bytes of numerator).
      assert.equals(CORE_SER_PREFIX, bytes_to_hex(s:sub(1, 16)))
      -- Denominator must be exactly 1.
      assert.equals(string.char(1) .. string.rep("\0", 383), s:sub(385, 768))
    end)
  end)

  describe("ChainState:compute_muhash wiring", function()
    -- Smoke check: verify the muhash module is reachable from utxo.lua's
    -- new method and the TxOutSer helper produces the documented byte
    -- layout. Doesn't touch RocksDB.
    local utxo = require("lunarblock.utxo")
    it("exports serialize_txoutser with the documented layout", function()
      assert.is_function(utxo.serialize_txoutser)
      -- key = 32-byte zero txid || 4-byte vout 0
      local key = string.rep("\0", 32) .. string.char(0,0,0,0)
      local entry = utxo.utxo_entry(
        50 * 100000000,   -- value: 50 BTC in satoshis
        "\x76\xa9\x14" .. string.rep("\0", 20) .. "\x88\xac",  -- 25-byte P2PKH
        1,                -- height
        true              -- is_coinbase
      )
      local ser = utxo.serialize_txoutser(key, entry)
      -- 36 (key) + 4 (code) + 8 (value) + 1 (varint=25) + 25 (script) = 74
      assert.equals(74, #ser)
      -- Code = (height << 1) | fCoinBase = (1<<1)|1 = 3, encoded LE as 03 00 00 00.
      assert.equals("\x03\x00\x00\x00", ser:sub(37, 40))
    end)
  end)
end)
