-- ARCH-2 (2026-10-04): the fast BlockUndo serializer must be byte-identical
-- to the reference path it replaced (utxo._serialize_block_undo_reference).
-- Undo bytes are an on-disk format read back by disconnect_block on every
-- reorg, so any divergence is a stored-data corruption, not a perf detail.
local utxo = require("lunarblock.utxo")
local ffi = require("ffi")

local function hex(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end
local function unhex(h) return (h:gsub("..", function(x) return string.char(tonumber(x, 16)) end)) end

-- Generator point G: a valid uncompressed pubkey (P2PK special case 0x04/0x05).
local G_UNC = unhex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  .. "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
-- Same x with y not on the curve: must fall through to the generic path.
local BAD_UNC = G_UNC:sub(1, 33) .. string.rep("\x11", 32)

local function rnd_bytes(rng, n)
  local t = {}
  for i = 1, n do t[i] = string.char(rng(0, 255)) end
  return table.concat(t)
end

local function scripts(rng)
  return {
    "\x76\xa9\x14" .. rnd_bytes(rng, 20) .. "\x88\xac",          -- P2PKH
    "\xa9\x14" .. rnd_bytes(rng, 20) .. "\x87",                   -- P2SH
    "\x21\x02" .. rnd_bytes(rng, 32) .. "\xac",                   -- P2PK compressed
    "\x21\x03" .. rnd_bytes(rng, 32) .. "\xac",
    "\x21\x07" .. rnd_bytes(rng, 32) .. "\xac",                   -- bad prefix: generic
    "\x41" .. G_UNC .. "\xac",                                    -- P2PK uncompressed (valid)
    "\x41" .. BAD_UNC .. "\xac",                                  -- off-curve: generic
    "\x00\x14" .. rnd_bytes(rng, 20),                             -- P2WPKH
    "\x51\x20" .. rnd_bytes(rng, 32),                             -- P2TR
    "",                                                           -- empty
    "\x6a" .. rnd_bytes(rng, 80),                                 -- OP_RETURN-ish
    rnd_bytes(rng, 121),                                          -- VARINT 2-byte length
    rnd_bytes(rng, 10001),                                        -- > MAX_SCRIPT_SIZE
    "\x76\xa9\x14" .. rnd_bytes(rng, 20) .. "\x88\xad",          -- near-P2PKH: generic
  }
end

local VALUES = {
  0, 1, 9, 10, 11, 99, 100, 546, 1000, 12345, 100000000, 123456789,
  2099999997690000, 2100000000000000, 1e14 - 1, 1e14, 1e14 + 10,
  5000000000, 999999999999999, 4294967296, 4294967295,
}

local HEIGHTS = { 0, 1, 63, 64, 127, 128, 16383, 16384, 227931, 650000, 958794, 2^31 - 1 }

local function build(rng, ntx, nin)
  local sc = scripts(rng)
  local tx_undo = {}
  for t = 1, ntx do
    local prev = {}
    for i = 1, nin do
      local v = VALUES[rng(1, #VALUES)]
      if rng(1, 8) == 1 then v = rng(0, 2^31) * rng(1, 1000) end
      local h = HEIGHTS[rng(1, #HEIGHTS)]
      local e = utxo.utxo_entry(v, sc[rng(1, #sc)], h, rng(0, 1) == 1)
      prev[i] = e
    end
    tx_undo[t] = utxo.tx_undo(prev)
  end
  return utxo.block_undo(tx_undo)
end

describe("fast serialize_block_undo", function()
  it("is byte-identical to the reference over randomized blocks", function()
    local seed = 4242
    math.randomseed(seed)
    local rng = math.random
    local n = 0
    for iter = 1, 60 do
      local bu = build(rng, rng(0, 12), rng(0, 9))
      local a = utxo._serialize_block_undo_reference(bu)
      local b = utxo.serialize_block_undo(bu)
      assert.are.equal(#a, #b, "length differs at iter " .. iter)
      assert.are.equal(hex(a), hex(b), "bytes differ at iter " .. iter)
      n = n + 1
    end
    assert.are.equal(60, n)
  end)

  it("covers every amount / height edge and every script class", function()
    math.randomseed(7)
    local rng = math.random
    local sc = scripts(rng)
    local prev = {}
    for _, v in ipairs(VALUES) do
      for _, h in ipairs(HEIGHTS) do
        for _, s in ipairs(sc) do
          prev[#prev + 1] = utxo.utxo_entry(v, s, h, (#prev % 2) == 0)
        end
      end
    end
    local bu = utxo.block_undo({ utxo.tx_undo(prev) })
    assert.are.equal(hex(utxo._serialize_block_undo_reference(bu)),
                     hex(utxo.serialize_block_undo(bu)))
  end)

  it("matches the reference for cdata amounts and heights (fallback path)", function()
    local s = "\x00\x14" .. string.rep("\x42", 20)
    local prev = {
      utxo.utxo_entry(ffi.new("uint64_t", 2100000000000000ULL), s, 650000, false),
      utxo.utxo_entry(ffi.new("int64_t", 123456789LL), s, 1, true),
      utxo.utxo_entry(5000000000, s, ffi.new("uint32_t", 958794), false),
    }
    local bu = utxo.block_undo({ utxo.tx_undo(prev) })
    assert.are.equal(hex(utxo._serialize_block_undo_reference(bu)),
                     hex(utxo.serialize_block_undo(bu)))
  end)

  it("matches the reference for CompactSize counts >= 0xFD and empty undo", function()
    math.randomseed(99)
    local rng = math.random
    local big = build(rng, 300, 1)
    assert.are.equal(hex(utxo._serialize_block_undo_reference(big)),
                     hex(utxo.serialize_block_undo(big)))
    local wide = build(rng, 1, 400)  -- many inputs in one tx
    assert.are.equal(hex(utxo._serialize_block_undo_reference(wide)),
                     hex(utxo.serialize_block_undo(wide)))
    local empty = utxo.block_undo({})
    assert.are.equal(hex(utxo._serialize_block_undo_reference(empty)),
                     hex(utxo.serialize_block_undo(empty)))
  end)

  -- Decoded undo (the shape disconnect_block reads back) re-serializes the
  -- same way on both paths.  (Not data == reserialize(data): the format is
  -- lossy for >MAX_SCRIPT_SIZE scripts, which decode as OP_RETURN, on both.)
  it("agrees with the reference on deserialized undo", function()
    math.randomseed(1)
    local bu = build(math.random, 5, 5)
    local data = utxo.serialize_block_undo(bu)
    local back = assert(utxo.deserialize_block_undo(data))
    assert.are.equal(#bu.tx_undo, #back.tx_undo)
    assert.are.equal(hex(utxo._serialize_block_undo_reference(back)),
                     hex(utxo.serialize_block_undo(back)))
  end)
end)
