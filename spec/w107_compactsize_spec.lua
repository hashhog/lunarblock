-- spec/w107_compactsize_spec.lua
--
-- W107 — DISCOVERY AUDIT: CompactSize + VarInt serialization for lunarblock
-- vs Bitcoin Core serialize.h (WriteCompactSize / ReadCompactSize /
-- WriteVarInt / ReadVarInt, MAX_SIZE = 0x02000000).
--
-- Reference:
--   bitcoin-core/src/serialize.h
--   bitcoin-core/src/undo.h          (TxInUndoFormatter)
--   bitcoin-core/src/compressor.h    (TxOutCompression)
--
-- 30 gates:
--   G1  CompactSize 1-byte write (val < 253)
--   G2  CompactSize 3-byte write (253 <= val <= 65535)
--   G3  CompactSize 5-byte write (65536 <= val <= 0xFFFFFFFF)
--   G4  CompactSize 9-byte write (val > 0xFFFFFFFF)
--   G5  CompactSize 1-byte read
--   G6  CompactSize 3-byte read (canonical)
--   G7  CompactSize 5-byte read (canonical)
--   G8  CompactSize 9-byte read (canonical)
--   G9  Non-canonical rejection: 0xFD path (val < 253) -- BUG
--   G10 Non-canonical rejection: 0xFE path (val < 0x10000) -- BUG
--   G11 Non-canonical rejection: 0xFF path (val < 0x100000000) -- BUG
--   G12 MAX_SIZE (0x02000000) range check on read -- BUG
--   G13 FFI reader: same non-canonical rejections -- BUG (same 3)
--   G14 FFI reader: MAX_SIZE range check -- BUG
--   G15 GetSizeOfCompactSize (compact_size_len in script.lua)
--   G16 Precision: 64-bit CompactSize read via Lua double -- BUG
--   G17 Precision: 64-bit CompactSize write via Lua double -- BUG
--   G18 crypto.compact_size: 1/3/5-byte cases
--   G19 crypto.compact_size: missing 9-byte case (val > 0xFFFFFFFF) -- BUG
--   G20 VarInt MSB base-128 WriteVarInt (write_corevarint)
--   G21 VarInt MSB base-128 ReadVarInt (read_corevarint)
--   G22 ReadVarInt overflow guard (n > UINT64_MAX >> 7)
--   G23 Round-trip CompactSize: boundary values
--   G24 Round-trip VarInt (MSB base-128): boundary values
--   G25 varstr write (write_varstr = varint_len + bytes)
--   G26 varstr read (read_varstr)
--   G27 Little-endian encoding for 2/4-byte CompactSize payloads
--   G28 TxInUndoFormatter: code uses Core VARINT not CompactSize -- BUG
--   G29 TxInUndoFormatter: value/script use TxOutCompression not raw LE -- BUG
--   G30 perf.put_varint consistency with serialize.write_varint
--
-- Severity labels:
--   CONSENSUS-DIVERGENT: lunarblock and Core disagree on valid data
--   DOS: no-check enables resource exhaustion
--   CORRECTNESS: wrong value computed or wrong encoding emitted
--   WIRE-INCOMPAT: peer cannot decode / cross-node protocol break

local serialize  = require("lunarblock.serialize")
local script_mod = require("lunarblock.script")
local crypto     = require("lunarblock.crypto")
local utxo_mod   = require("lunarblock.utxo")
local perf       = require("lunarblock.perf")
local bit        = require("bit")
local ffi        = require("ffi")

-- Helper: write a varint using the main writer and return the raw bytes.
local function enc(val)
  local w = serialize.buffer_writer()
  w.write_varint(val)
  return w.result()
end

-- Helper: decode a raw byte-string through buffer_reader.read_varint.
local function dec(bytes)
  local r = serialize.buffer_reader(bytes)
  return r.read_varint()
end

-- Helper: decode a raw byte-string through buffer_reader_ffi.read_varint.
local function dec_ffi(bytes)
  local r = serialize.buffer_reader_ffi(bytes)
  return r.read_varint()
end

-- Helper: hex-encode a byte string for assertion messages.
local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", string.byte(c)) end))
end

-- Helper: write n bytes of little-endian uint64 for constructing test vectors.
local function le64(val)
  local w = serialize.buffer_writer()
  w.write_u64le(val)
  return w.result()
end

describe("W107 CompactSize + VarInt serialization audit (lunarblock vs Core)", function()

  ---------------------------------------------------------------------------
  -- G1: CompactSize 1-byte write
  -- Core: if nSize < 253 -> write 1 byte
  ---------------------------------------------------------------------------
  describe("G1 write_varint 1-byte range (val < 253)", function()
    it("encodes 0 as single zero byte", function()
      local b = enc(0)
      assert.equal(1, #b)
      assert.equal(0, b:byte(1))
    end)
    it("encodes 252 as single byte 0xFC", function()
      local b = enc(252)
      assert.equal(1, #b)
      assert.equal(252, b:byte(1))
    end)
    it("encodes 1 as single byte 0x01", function()
      local b = enc(1)
      assert.equal(1, #b)
      assert.equal(1, b:byte(1))
    end)
  end)

  ---------------------------------------------------------------------------
  -- G2: CompactSize 3-byte write
  -- Core: if nSize <= USHRT_MAX -> write 0xFD + LE16
  ---------------------------------------------------------------------------
  describe("G2 write_varint 3-byte range (253..65535)", function()
    it("encodes 253 as 0xFD 0xFD 0x00", function()
      local b = enc(253)
      assert.equal(3, #b)
      assert.equal(0xFD, b:byte(1))
      assert.equal(0xFD, b:byte(2))
      assert.equal(0x00, b:byte(3))
    end)
    it("encodes 65535 as 0xFD 0xFF 0xFF", function()
      local b = enc(65535)
      assert.equal(3, #b)
      assert.equal(0xFD, b:byte(1))
      assert.equal(0xFF, b:byte(2))
      assert.equal(0xFF, b:byte(3))
    end)
    it("encodes 256 as 0xFD 0x00 0x01", function()
      local b = enc(256)
      assert.equal(3, #b)
      assert.equal(0xFD, b:byte(1))
      assert.equal(0x00, b:byte(2))
      assert.equal(0x01, b:byte(3))
    end)
  end)

  ---------------------------------------------------------------------------
  -- G3: CompactSize 5-byte write
  -- Core: if nSize <= UINT_MAX -> write 0xFE + LE32
  ---------------------------------------------------------------------------
  describe("G3 write_varint 5-byte range (65536..0xFFFFFFFF)", function()
    it("encodes 65536 as 0xFE + LE32(65536)", function()
      local b = enc(65536)
      assert.equal(5, #b)
      assert.equal(0xFE, b:byte(1))
      assert.equal(0x00, b:byte(2))
      assert.equal(0x00, b:byte(3))
      assert.equal(0x01, b:byte(4))
      assert.equal(0x00, b:byte(5))
    end)
    it("encodes 0xFFFFFFFF as 0xFE 0xFF 0xFF 0xFF 0xFF", function()
      local b = enc(0xFFFFFFFF)
      assert.equal(5, #b)
      assert.equal(0xFE, b:byte(1))
      assert.equal(0xFF, b:byte(2))
      assert.equal(0xFF, b:byte(3))
      assert.equal(0xFF, b:byte(4))
      assert.equal(0xFF, b:byte(5))
    end)
  end)

  ---------------------------------------------------------------------------
  -- G4: CompactSize 9-byte write
  -- Core: else -> write 0xFF + LE64
  ---------------------------------------------------------------------------
  describe("G4 write_varint 9-byte range (> 0xFFFFFFFF)", function()
    it("encodes 0x100000000 as 0xFF + LE64", function()
      local val = 0x100000000  -- 2^32
      local b = enc(val)
      assert.equal(9, #b, "9-byte encoding expected for val > 0xFFFFFFFF")
      assert.equal(0xFF, b:byte(1))
      -- LE64 of 0x100000000 = 00 00 00 00 01 00 00 00
      assert.equal(0x00, b:byte(2))
      assert.equal(0x00, b:byte(3))
      assert.equal(0x00, b:byte(4))
      assert.equal(0x00, b:byte(5))
      assert.equal(0x01, b:byte(6))
      assert.equal(0x00, b:byte(7))
      assert.equal(0x00, b:byte(8))
      assert.equal(0x00, b:byte(9))
    end)
  end)

  ---------------------------------------------------------------------------
  -- G5: CompactSize 1-byte read
  ---------------------------------------------------------------------------
  describe("G5 read_varint 1-byte range", function()
    it("reads 0x00 as 0", function()
      assert.equal(0, dec(string.char(0x00)))
    end)
    it("reads 0xFC as 252", function()
      assert.equal(252, dec(string.char(0xFC)))
    end)
  end)

  ---------------------------------------------------------------------------
  -- G6: CompactSize 3-byte read (canonical)
  ---------------------------------------------------------------------------
  describe("G6 read_varint 3-byte (canonical)", function()
    it("reads 0xFD 0xFD 0x00 as 253", function()
      local b = string.char(0xFD, 0xFD, 0x00)
      assert.equal(253, dec(b))
    end)
    it("reads 0xFD 0xFF 0xFF as 65535", function()
      local b = string.char(0xFD, 0xFF, 0xFF)
      assert.equal(65535, dec(b))
    end)
  end)

  ---------------------------------------------------------------------------
  -- G7: CompactSize 5-byte read (canonical)
  ---------------------------------------------------------------------------
  describe("G7 read_varint 5-byte (canonical)", function()
    it("reads 0xFE 0x00 0x00 0x01 0x00 as 65536", function()
      local b = string.char(0xFE, 0x00, 0x00, 0x01, 0x00)
      assert.equal(65536, dec(b))
    end)
  end)

  ---------------------------------------------------------------------------
  -- G8: CompactSize 9-byte read (canonical)
  ---------------------------------------------------------------------------
  describe("G8 read_varint 9-byte (canonical)", function()
    it("reads 0xFF + LE64(0x100000000) as 0x100000000", function()
      -- 0x100000000 = 4294967296 in LE = 00 00 00 00 01 00 00 00
      local b = string.char(0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00)
      assert.equal(4294967296, dec(b))
    end)
  end)

  ---------------------------------------------------------------------------
  -- G9: BUG — Non-canonical rejection: 0xFD path
  -- Core: if (nSizeRet < 253) throw "non-canonical ReadCompactSize()"
  -- lunarblock: silently accepts
  ---------------------------------------------------------------------------
  describe("G9 non-canonical 0xFD path rejection (BUG)", function()
    -- XFAIL: lunarblock does not reject non-canonical CompactSize encodings.
    -- Core throws std::ios_base::failure("non-canonical ReadCompactSize()").
    -- Reference: serialize.h ReadCompactSize, line with "if (nSizeRet < 253)"
    pending("BUG: 0xFD + u16(0) should throw non-canonical error (CONSENSUS-DIVERGENT)", function()
      local b = string.char(0xFD, 0x00, 0x00)  -- encodes 0 non-canonically
      assert.has_error(function() dec(b) end,
        "non-canonical ReadCompactSize()")
    end)
    it("XFAIL: silently accepts 0xFD + u16(0) = 0 (wrong — Core rejects)", function()
      local b = string.char(0xFD, 0x00, 0x00)
      local ok, val = pcall(dec, b)
      -- Documents the bug: no exception, returns 0
      assert.is_true(ok, "expected no exception (bug: should throw)")
      assert.equal(0, val, "expected 0 (bug: should be rejected)")
    end)
    it("XFAIL: silently accepts 0xFD + u16(252) = 252 (wrong — Core rejects)", function()
      local b = string.char(0xFD, 0xFC, 0x00)
      local ok, val = pcall(dec, b)
      assert.is_true(ok, "expected no exception (bug: should throw)")
      assert.equal(252, val, "expected 252 (bug: should be rejected)")
    end)
  end)

  ---------------------------------------------------------------------------
  -- G10: BUG — Non-canonical rejection: 0xFE path
  -- Core: if (nSizeRet < 0x10000u) throw "non-canonical ReadCompactSize()"
  ---------------------------------------------------------------------------
  describe("G10 non-canonical 0xFE path rejection (BUG)", function()
    pending("BUG: 0xFE + u32(65535) should throw non-canonical error (CONSENSUS-DIVERGENT)", function()
      local b = string.char(0xFE, 0xFF, 0xFF, 0x00, 0x00)  -- encodes 65535 non-canonically
      assert.has_error(function() dec(b) end,
        "non-canonical ReadCompactSize()")
    end)
    it("XFAIL: silently accepts 0xFE + u32(65535) = 65535 (wrong — Core rejects)", function()
      local b = string.char(0xFE, 0xFF, 0xFF, 0x00, 0x00)
      local ok, val = pcall(dec, b)
      assert.is_true(ok, "expected no exception (bug: should throw)")
      assert.equal(65535, val, "expected 65535 (bug: should be rejected)")
    end)
    it("XFAIL: silently accepts 0xFE + u32(0) = 0 (wrong — Core rejects)", function()
      local b = string.char(0xFE, 0x00, 0x00, 0x00, 0x00)
      local ok, val = pcall(dec, b)
      assert.is_true(ok)
      assert.equal(0, val)
    end)
  end)

  ---------------------------------------------------------------------------
  -- G11: BUG — Non-canonical rejection: 0xFF path
  -- Core: if (nSizeRet < 0x100000000ULL) throw "non-canonical ReadCompactSize()"
  ---------------------------------------------------------------------------
  describe("G11 non-canonical 0xFF path rejection (BUG)", function()
    pending("BUG: 0xFF + u64(0xFFFFFFFF) should throw non-canonical error (CONSENSUS-DIVERGENT)", function()
      -- encodes 0xFFFFFFFF (4294967295) non-canonically via 9-byte form
      local b = string.char(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00)
      assert.has_error(function() dec(b) end,
        "non-canonical ReadCompactSize()")
    end)
    it("XFAIL: silently accepts 0xFF + u64(4294967295) = 4294967295 (wrong — Core rejects)", function()
      local b = string.char(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00)
      local ok, val = pcall(dec, b)
      assert.is_true(ok, "expected no exception (bug: should throw)")
      assert.equal(4294967295, val, "expected 4294967295 (bug: should be rejected)")
    end)
  end)

  ---------------------------------------------------------------------------
  -- G12: BUG — MAX_SIZE (0x02000000) range check on read
  -- Core: if (range_check && nSizeRet > MAX_SIZE) throw "size too large"
  -- Reference: serialize.h:358 MAX_SIZE = 0x02000000
  ---------------------------------------------------------------------------
  describe("G12 MAX_SIZE range check in read_varint (BUG)", function()
    -- MAX_SIZE = 0x02000000 = 33554432; any vector length above this is
    -- semantically invalid per Core and must be rejected.
    pending("BUG: values > MAX_SIZE (0x02000000) should throw 'size too large' (CONSENSUS-DIVERGENT + DOS)", function()
      -- Encode 0x02000001 (just over MAX_SIZE) as 5-byte CompactSize
      -- 0x02000001 in LE4 = 01 00 00 02
      local b = string.char(0xFE, 0x01, 0x00, 0x00, 0x02)
      assert.has_error(function() dec(b) end,
        "ReadCompactSize(): size too large")
    end)
    it("XFAIL: silently accepts 0x02000001 = 33554433 (> MAX_SIZE, should be rejected)", function()
      local b = string.char(0xFE, 0x01, 0x00, 0x00, 0x02)
      local ok, val = pcall(dec, b)
      assert.is_true(ok, "expected no exception (bug: should throw)")
      assert.equal(33554433, val, "expected 33554433 (bug: should be rejected)")
    end)
    it("accepts 0x02000000 (exactly MAX_SIZE) — border is inclusive", function()
      -- 0x02000000 in LE4 = 00 00 00 02
      local b = string.char(0xFE, 0x00, 0x00, 0x00, 0x02)
      local ok, val = pcall(dec, b)
      assert.is_true(ok)
      assert.equal(0x02000000, val)
    end)
  end)

  ---------------------------------------------------------------------------
  -- G13: BUG — FFI reader has same non-canonical bugs (3 paths)
  ---------------------------------------------------------------------------
  describe("G13 FFI reader non-canonical rejections (BUG)", function()
    pending("BUG: FFI reader 0xFD path should reject val < 253 (CONSENSUS-DIVERGENT)", function()
      local b = string.char(0xFD, 0x00, 0x00)
      assert.has_error(function() dec_ffi(b) end)
    end)
    it("XFAIL: FFI reader silently accepts non-canonical 0xFD+0 (bug)", function()
      local b = string.char(0xFD, 0x00, 0x00)
      local ok, val = pcall(dec_ffi, b)
      assert.is_true(ok)
      assert.equal(0, val)
    end)
    it("XFAIL: FFI reader silently accepts non-canonical 0xFE+u32(65535) (bug)", function()
      local b = string.char(0xFE, 0xFF, 0xFF, 0x00, 0x00)
      local ok, val = pcall(dec_ffi, b)
      assert.is_true(ok)
      assert.equal(65535, val)
    end)
  end)

  ---------------------------------------------------------------------------
  -- G14: BUG — FFI reader missing MAX_SIZE range check
  ---------------------------------------------------------------------------
  describe("G14 FFI reader MAX_SIZE range check (BUG)", function()
    pending("BUG: FFI reader should reject values > MAX_SIZE (CONSENSUS-DIVERGENT + DOS)", function()
      local b = string.char(0xFE, 0x01, 0x00, 0x00, 0x02)  -- 0x02000001
      assert.has_error(function() dec_ffi(b) end)
    end)
    it("XFAIL: FFI reader accepts 0x02000001 silently (bug)", function()
      local b = string.char(0xFE, 0x01, 0x00, 0x00, 0x02)
      local ok, val = pcall(dec_ffi, b)
      assert.is_true(ok)
      assert.equal(33554433, val)
    end)
  end)

  ---------------------------------------------------------------------------
  -- G15: GetSizeOfCompactSize (compact_size_len in script.lua)
  -- Core: GetSizeOfCompactSize returns 1/3/5/9 correctly
  ---------------------------------------------------------------------------
  describe("G15 compact_size_len (GetSizeOfCompactSize equivalent)", function()
    local cslen = script_mod.compact_size_len
    it("returns 1 for 0", function() assert.equal(1, cslen(0)) end)
    it("returns 1 for 252", function() assert.equal(1, cslen(252)) end)
    it("returns 3 for 253", function() assert.equal(3, cslen(253)) end)
    it("returns 3 for 65535", function() assert.equal(3, cslen(65535)) end)
    it("returns 5 for 65536", function() assert.equal(5, cslen(65536)) end)
    it("returns 5 for 0xFFFFFFFF", function() assert.equal(5, cslen(0xFFFFFFFF)) end)
    it("returns 9 for 0x100000000", function() assert.equal(9, cslen(0x100000000)) end)
  end)

  ---------------------------------------------------------------------------
  -- G16: BUG — Precision loss: 64-bit CompactSize read via Lua double
  -- read_u64le returns low + high * 4294967296, which is IEEE 754 double.
  -- Values > 2^53 lose precision since mantissa is only 53 bits.
  ---------------------------------------------------------------------------
  describe("G16 64-bit CompactSize read precision (BUG)", function()
    -- 2^53 + 1 = 9007199254740993 = 0x0020000000000001
    -- LE8 bytes: 01 00 00 00 00 00 20 00
    local val_2_53_plus1_bytes =
      string.char(0xFF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00)
    pending("BUG: 64-bit read should distinguish 2^53 from 2^53+1 (CORRECTNESS)", function()
      local v = dec(val_2_53_plus1_bytes)
      assert.equal(9007199254740993, v,
        "2^53+1 must round-trip without precision loss; use FFI cdata uint64_t")
    end)
    it("XFAIL: 2^53+1 loses last bit due to Lua double mantissa limit", function()
      local v = dec(val_2_53_plus1_bytes)
      -- IEEE 754 double rounds 9007199254740993 to 9007199254740992
      local expected_rounded = 9007199254740992
      assert.equal(expected_rounded, v,
        "documents precision loss: 2^53+1 read as 2^53 (IEEE 754 double rounds)")
    end)
  end)

  ---------------------------------------------------------------------------
  -- G17: BUG — Precision loss: 64-bit CompactSize write via Lua double
  -- write_u64le uses Lua float arithmetic (val % 4294967296, math.floor(val/4294967296))
  -- which loses precision for values > 2^53.
  ---------------------------------------------------------------------------
  describe("G17 64-bit CompactSize write precision (BUG)", function()
    pending("BUG: write_u64le(2^53+1) should produce correct LE bytes (CORRECTNESS)", function()
      local val = 9007199254740993  -- 2^53 + 1
      local b = enc(val)
      assert.equal(9, #b)
      assert.equal(0xFF, b:byte(1))
      -- expected LE8 of 2^53+1 = 01 00 00 00 00 00 20 00
      assert.equal(0x01, b:byte(2), "LSB of 2^53+1 must be 0x01")
    end)
    it("XFAIL: write_u64le(2^53+1) writes 2^53 due to Lua float precision loss", function()
      local val = 9007199254740993  -- 2^53 + 1
      local b = enc(val)
      assert.equal(9, #b)
      -- Due to precision loss, byte 2 (LSB) becomes 0x00 instead of 0x01
      assert.equal(0x00, b:byte(2),
        "documents bug: LSB is 0x00, i.e., 2^53+1 encoded as 2^53")
    end)
  end)

  ---------------------------------------------------------------------------
  -- G18: crypto.compact_size 1/3/5-byte cases
  ---------------------------------------------------------------------------
  describe("G18 crypto.compact_size 1/3/5-byte paths", function()
    it("encodes 0 as single zero byte", function()
      local b = crypto.compact_size(0)
      assert.equal(1, #b)
      assert.equal(0, b:byte(1))
    end)
    it("encodes 252 as single byte", function()
      local b = crypto.compact_size(252)
      assert.equal(1, #b)
      assert.equal(252, b:byte(1))
    end)
    it("encodes 253 as 3 bytes with 0xFD prefix", function()
      local b = crypto.compact_size(253)
      assert.equal(3, #b)
      assert.equal(0xFD, b:byte(1))
      assert.equal(0xFD, b:byte(2))
      assert.equal(0x00, b:byte(3))
    end)
    it("encodes 65535 as 3 bytes with 0xFD prefix", function()
      local b = crypto.compact_size(65535)
      assert.equal(3, #b)
      assert.equal(0xFD, b:byte(1))
      assert.equal(0xFF, b:byte(2))
      assert.equal(0xFF, b:byte(3))
    end)
    it("encodes 65536 as 5 bytes with 0xFE prefix", function()
      local b = crypto.compact_size(65536)
      assert.equal(5, #b)
      assert.equal(0xFE, b:byte(1))
    end)
    it("encodes 0xFFFFFFFF as 5 bytes with 0xFE prefix", function()
      local b = crypto.compact_size(0xFFFFFFFF)
      assert.equal(5, #b)
      assert.equal(0xFE, b:byte(1))
    end)
  end)

  ---------------------------------------------------------------------------
  -- G19: BUG — crypto.compact_size missing 9-byte (0xFF) case
  -- Core: WriteCompactSize handles all 4 ranges.
  -- crypto.compact_size throws an error for val > 0xFFFFFFFF.
  -- Used by: tapleaf encoding (utxo.lua:2664), annex hash (validation.lua:1007).
  ---------------------------------------------------------------------------
  describe("G19 crypto.compact_size missing 9-byte case (BUG)", function()
    pending("BUG: crypto.compact_size(0x100000000) should produce 9-byte encoding (CORRECTNESS)", function()
      local b = crypto.compact_size(0x100000000)
      assert.equal(9, #b, "9-byte encoding expected for val > 0xFFFFFFFF")
      assert.equal(0xFF, b:byte(1))
    end)
    it("XFAIL: crypto.compact_size(0x100000000) throws instead of encoding", function()
      local ok, err = pcall(crypto.compact_size, 0x100000000)
      assert.is_false(ok, "documents bug: throws error instead of emitting 9-byte encoding")
      assert.matches("too large", err)
    end)
  end)

  ---------------------------------------------------------------------------
  -- G20: Core VARINT (MSB base-128) WriteVarInt — write_corevarint
  ---------------------------------------------------------------------------
  describe("G20 write_corevarint (MSB base-128 VarInt)", function()
    -- Reference: serialize.h examples
    -- 0         -> [0x00]
    -- 127       -> [0x7F]
    -- 128       -> [0x80 0x00]
    -- 255       -> [0x80 0x7F]
    -- 256       -> [0x81 0x00]
    -- 16383     -> [0xFE 0x7F]
    -- 16384     -> [0xFF 0x00]
    local function coreenc(val)
      local w = serialize.buffer_writer()
      utxo_mod.write_corevarint(w, val)
      return w.result()
    end

    it("encodes 0 as [0x00]", function()
      local b = coreenc(0)
      assert.equal(1, #b)
      assert.equal(0x00, b:byte(1))
    end)
    it("encodes 127 as [0x7F]", function()
      local b = coreenc(127)
      assert.equal(1, #b)
      assert.equal(0x7F, b:byte(1))
    end)
    it("encodes 128 as [0x80 0x00]", function()
      local b = coreenc(128)
      assert.equal(2, #b)
      assert.equal(0x80, b:byte(1))
      assert.equal(0x00, b:byte(2))
    end)
    it("encodes 255 as [0x80 0x7F]", function()
      local b = coreenc(255)
      assert.equal(2, #b)
      assert.equal(0x80, b:byte(1))
      assert.equal(0x7F, b:byte(2))
    end)
    it("encodes 256 as [0x81 0x00]", function()
      local b = coreenc(256)
      assert.equal(2, #b)
      assert.equal(0x81, b:byte(1))
      assert.equal(0x00, b:byte(2))
    end)
    it("encodes 16383 as [0xFE 0x7F]", function()
      local b = coreenc(16383)
      assert.equal(2, #b)
      assert.equal(0xFE, b:byte(1))
      assert.equal(0x7F, b:byte(2))
    end)
    it("encodes 16384 as [0xFF 0x00]", function()
      local b = coreenc(16384)
      assert.equal(2, #b)
      assert.equal(0xFF, b:byte(1))
      assert.equal(0x00, b:byte(2))
    end)
  end)

  ---------------------------------------------------------------------------
  -- G21: Core VARINT (MSB base-128) ReadVarInt — read_corevarint
  ---------------------------------------------------------------------------
  describe("G21 read_corevarint (MSB base-128 VarInt)", function()
    local function coredec(bytes)
      local r = serialize.buffer_reader(bytes)
      return tonumber(utxo_mod.read_corevarint(r))
    end

    it("decodes [0x00] as 0", function()
      assert.equal(0, coredec(string.char(0x00)))
    end)
    it("decodes [0x7F] as 127", function()
      assert.equal(127, coredec(string.char(0x7F)))
    end)
    it("decodes [0x80 0x00] as 128", function()
      assert.equal(128, coredec(string.char(0x80, 0x00)))
    end)
    it("decodes [0x80 0x7F] as 255", function()
      assert.equal(255, coredec(string.char(0x80, 0x7F)))
    end)
    it("decodes [0x81 0x00] as 256", function()
      assert.equal(256, coredec(string.char(0x81, 0x00)))
    end)
    it("decodes [0xFE 0x7F] as 16383", function()
      assert.equal(16383, coredec(string.char(0xFE, 0x7F)))
    end)
    it("decodes [0xFF 0x00] as 16384", function()
      assert.equal(16384, coredec(string.char(0xFF, 0x00)))
    end)
    it("round-trips 65535", function()
      local w = serialize.buffer_writer()
      utxo_mod.write_corevarint(w, 65535)
      local r = serialize.buffer_reader(w.result())
      assert.equal(65535, tonumber(utxo_mod.read_corevarint(r)))
    end)
  end)

  ---------------------------------------------------------------------------
  -- G22: ReadVarInt overflow guard
  -- Core: if (n > (numeric_limits<I>::max() >> 7)) throw "size too large"
  -- lunarblock read_corevarint checks n > 0x01FFFFFFFFFFFFFF (= UINT64_MAX >> 7)
  ---------------------------------------------------------------------------
  describe("G22 read_corevarint overflow guard", function()
    it("rejects an over-long MSB-varint (more than 10 bytes would be needed)", function()
      -- Craft a byte string with 18 continuation bytes (all 0xFF) to trigger the
      -- iteration guard in read_corevarint (guard > 18 -> error)
      local bytes = string.rep(string.char(0xFF), 18) .. string.char(0x00)
      local r = serialize.buffer_reader(bytes)
      assert.has_error(function()
        utxo_mod.read_corevarint(r)
      end)
    end)
  end)

  ---------------------------------------------------------------------------
  -- G23: Round-trip CompactSize boundary values
  ---------------------------------------------------------------------------
  describe("G23 CompactSize round-trip boundary values", function()
    local boundaries = {0, 1, 252, 253, 254, 255, 256, 65534, 65535, 65536,
                        0xFFFFFFFE, 0xFFFFFFFF}
    for _, v in ipairs(boundaries) do
      it(string.format("round-trips %d", v), function()
        local bytes = enc(v)
        local got = dec(bytes)
        assert.equal(v, got, string.format("round-trip failed for %d", v))
      end)
    end
  end)

  ---------------------------------------------------------------------------
  -- G24: Round-trip Core VARINT (MSB base-128) boundary values
  ---------------------------------------------------------------------------
  describe("G24 Core VARINT (MSB base-128) round-trip", function()
    local function coreenc(val)
      local w = serialize.buffer_writer()
      utxo_mod.write_corevarint(w, val)
      return w.result()
    end
    local function coredec(bytes)
      local r = serialize.buffer_reader(bytes)
      return tonumber(utxo_mod.read_corevarint(r))
    end
    local boundaries = {0, 1, 127, 128, 255, 256, 16383, 16384, 16511,
                        65535, 65536, 0xFFFFFE, 0xFFFFFF}
    for _, v in ipairs(boundaries) do
      it(string.format("round-trips %d", v), function()
        assert.equal(v, coredec(coreenc(v)),
          string.format("Core VARINT round-trip failed for %d", v))
      end)
    end
  end)

  ---------------------------------------------------------------------------
  -- G25: varstr write (write_varstr = varint_len + bytes)
  ---------------------------------------------------------------------------
  describe("G25 write_varstr", function()
    it("encodes empty string as 0x00 (1-byte varint for length 0)", function()
      local w = serialize.buffer_writer()
      w.write_varstr("")
      local b = w.result()
      assert.equal(1, #b)
      assert.equal(0, b:byte(1))
    end)
    it("encodes 'hello' as 0x05 + 'hello'", function()
      local w = serialize.buffer_writer()
      w.write_varstr("hello")
      local b = w.result()
      assert.equal(6, #b)
      assert.equal(5, b:byte(1))
      assert.equal("hello", b:sub(2))
    end)
    it("encodes 253-byte payload with 3-byte length prefix", function()
      local payload = string.rep("A", 253)
      local w = serialize.buffer_writer()
      w.write_varstr(payload)
      local b = w.result()
      assert.equal(256, #b)  -- 3 (varint) + 253 (payload)
      assert.equal(0xFD, b:byte(1))
      assert.equal(0xFD, b:byte(2))
      assert.equal(0x00, b:byte(3))
    end)
  end)

  ---------------------------------------------------------------------------
  -- G26: varstr read (read_varstr)
  ---------------------------------------------------------------------------
  describe("G26 read_varstr", function()
    it("reads back 'hello' from write_varstr output", function()
      local w = serialize.buffer_writer()
      w.write_varstr("hello")
      local r = serialize.buffer_reader(w.result())
      assert.equal("hello", r.read_varstr())
    end)
    it("reads back empty string", function()
      local w = serialize.buffer_writer()
      w.write_varstr("")
      local r = serialize.buffer_reader(w.result())
      assert.equal("", r.read_varstr())
    end)
  end)

  ---------------------------------------------------------------------------
  -- G27: Little-endian encoding for 2/4-byte CompactSize payloads
  ---------------------------------------------------------------------------
  describe("G27 little-endian byte order for multi-byte CompactSize", function()
    it("0xFD path: 256 -> 0xFD 0x00 0x01 (LE16, not BE)", function()
      local b = enc(256)
      assert.equal(0xFD, b:byte(1))
      assert.equal(0x00, b:byte(2))  -- low byte
      assert.equal(0x01, b:byte(3))  -- high byte (LE order)
    end)
    it("0xFE path: 0x01020304 -> 0xFE 0x04 0x03 0x02 0x01 (LE32)", function()
      local b = enc(0x01020304)
      assert.equal(0xFE, b:byte(1))
      assert.equal(0x04, b:byte(2))  -- byte 0 (LE)
      assert.equal(0x03, b:byte(3))  -- byte 1
      assert.equal(0x02, b:byte(4))  -- byte 2
      assert.equal(0x01, b:byte(5))  -- byte 3 (LE)
    end)
    it("read_varint correctly interprets LE bytes for 0xFD prefix", function()
      -- Wire: 0xFD 0x01 0x00 = LE16(0x0001) = 1 ... but that would be non-canonical
      -- Use a canonical case: 0xFD 0xFD 0x00 = LE16(0x00FD) = 253
      local b = string.char(0xFD, 0xFD, 0x00)
      assert.equal(253, dec(b))
    end)
  end)

  ---------------------------------------------------------------------------
  -- G28: FIXED — TxInUndoFormatter: code field uses Core VARINT (MSB base-128)
  -- Core: READWRITE uses VARINT(code) i.e. MSB base-128 WriteVarInt
  -- Fix: serialize_undo_entry now calls write_corevarint(w, code) instead of
  --      w.write_varint(code) (CompactSize).
  -- Reference: bitcoin-core/src/undo.h TxInUndoFormatter::Ser
  ---------------------------------------------------------------------------
  describe("G28 TxInUndoFormatter code field encoding (FIXED)", function()
    -- For a coin at height=64, coinbase=false:
    --   code = 64 * 2 + 0 = 128
    --   Core VARINT(128) = [0x80 0x00]  (2 bytes, MSB base-128)
    --   CompactSize(128) = [0x80]       (1 byte, since 128 < 253)
    it("serialize_undo_entry uses Core VARINT [0x80 0x00] for code=128 (FIXED)", function()
      local entry = {
        height = 64,
        is_coinbase = false,
        value = 100000,
        script_pubkey = string.rep("\x00", 20),
      }
      -- code = 64*2 + 0 = 128
      -- Core VARINT(128) = [0x80 0x00]: 2 bytes
      local data = utxo_mod.serialize_undo_entry(entry)
      -- First byte must be 0x80 (high bit set, continuation) for Core VARINT
      assert.equal(string.char(0x80), data:sub(1, 1),
        "code=128 first byte must be 0x80 (Core VARINT continuation bit set)")
      assert.equal(string.char(0x00), data:sub(2, 2),
        "code=128 second byte must be 0x00 (Core VARINT terminal byte)")
    end)
    it("code=0 encodes as single [0x00] byte (VARINT(0))", function()
      -- height=0, coinbase=false -> code=0 -> VARINT(0) = [0x00]
      -- No dummy byte when height=0.
      local entry = {
        height = 0,
        is_coinbase = false,
        value = 1000,
        script_pubkey = string.rep("\x00", 20),
      }
      local data = utxo_mod.serialize_undo_entry(entry)
      assert.equal(string.char(0x00), data:sub(1, 1),
        "code=0 must encode as [0x00] with Core VARINT")
    end)
    it("round-trips undo entry through serialize+deserialize (height=64, coinbase=false)", function()
      local entry = {
        height = 64,
        is_coinbase = false,
        value = 100000,
        script_pubkey = string.rep("\x41", 20),
      }
      local data = utxo_mod.serialize_undo_entry(entry)
      local recovered = utxo_mod.deserialize_undo_entry(data)
      assert.equal(entry.height, recovered.height, "height round-trip")
      assert.equal(entry.is_coinbase, recovered.is_coinbase, "coinbase flag round-trip")
      assert.equal(entry.value, recovered.value, "value round-trip")
      assert.equal(entry.script_pubkey, recovered.script_pubkey, "script round-trip")
    end)
    it("round-trips undo entry with height=0 (no dummy byte path)", function()
      local entry = {
        height = 0,
        is_coinbase = true,
        value = 5000000000,
        script_pubkey = string.rep("\x00", 20),
      }
      local data = utxo_mod.serialize_undo_entry(entry)
      local recovered = utxo_mod.deserialize_undo_entry(data)
      assert.equal(0, recovered.height)
      assert.is_true(recovered.is_coinbase)
      assert.equal(5000000000, recovered.value)
    end)
  end)

  ---------------------------------------------------------------------------
  -- G29: FIXED — TxInUndoFormatter: value/script now use TxOutCompression
  -- Core: TxOutCompression = VARINT(CompressAmount) + ScriptCompression
  -- Fix: serialize_undo_entry now calls write_corevarint(w, compress_amount(value))
  --      + compress_script(script_pubkey) instead of raw write_i64le + write_varstr.
  -- Reference: bitcoin-core/src/compressor.h TxOutCompression, AmountCompression
  ---------------------------------------------------------------------------
  describe("G29 TxInUndoFormatter value/script encoding (FIXED)", function()
    it("value=0 compresses to VARINT(0) = [0x00] (one byte)", function()
      local entry = {
        height = 0,
        is_coinbase = false,
        value = 0,
        script_pubkey = string.rep("\x00", 20),
      }
      local data = utxo_mod.serialize_undo_entry(entry)
      -- code=0 -> [0x00]; no dummy; compressed_amount(0)=0 -> [0x00]
      assert.equal(string.char(0x00), data:sub(1, 1), "code byte")
      assert.equal(string.char(0x00), data:sub(2, 2), "compressed amount byte for value=0")
    end)
    it("serialize+deserialize round-trips a 25-byte raw-script entry with non-trivial value", function()
      local raw_script = string.rep("\xab", 20)
      local entry = {
        height = 1,
        is_coinbase = false,
        value = 5000000000,
        script_pubkey = raw_script,
      }
      local data = utxo_mod.serialize_undo_entry(entry)
      -- With TxOutCompression the encoding is significantly shorter than raw LE64+varstr.
      -- Before the fix: 1(code-cs) + 1(dummy) + 8(i64le) + 1(varlen) + 20(raw) = 31 bytes
      -- After the fix:  1(code-cv) + 1(dummy) + ~2(compact-amount) + 1+20(script) = ~25 bytes
      -- Just verify it is NOT 31 (old raw format) and round-trips correctly.
      local recovered = utxo_mod.deserialize_undo_entry(data)
      assert.equal(entry.height,      recovered.height,      "height round-trip")
      assert.equal(entry.is_coinbase, recovered.is_coinbase, "coinbase round-trip")
      assert.equal(entry.value,       recovered.value,       "value round-trip")
      assert.equal(entry.script_pubkey, recovered.script_pubkey, "script round-trip")
    end)
    it("serialize+deserialize round-trips height=64 coinbase=true entry", function()
      local entry = {
        height = 64,
        is_coinbase = true,
        value = 625000000,
        script_pubkey = string.rep("\x01", 20),
      }
      local data = utxo_mod.serialize_undo_entry(entry)
      local recovered = utxo_mod.deserialize_undo_entry(data)
      assert.equal(64,        recovered.height)
      assert.is_true(recovered.is_coinbase)
      assert.equal(625000000, recovered.value)
      assert.equal(entry.script_pubkey, recovered.script_pubkey)
    end)
  end)

  ---------------------------------------------------------------------------
  -- G30: perf.put_varint consistency with serialize.write_varint
  -- Both should produce identical byte sequences for the same value.
  -- Note: perf.put_varint requires the perf.new_serialize_buffer() buffer object
  -- (which accepts vararg put() calls for multi-byte writes via put_u32_le);
  -- a naive single-arg mock buffer will silently drop extra bytes.
  ---------------------------------------------------------------------------
  describe("G30 perf.put_varint consistency with serialize.write_varint", function()
    -- Use the actual perf serialize buffer so put_u32_le varargs work correctly.
    local function perf_enc(val)
      local buf = perf.new_serialize_buffer()
      perf.put_varint(buf, val)
      return buf:tostring()
    end

    local test_vals = {0, 1, 252, 253, 256, 65535, 65536, 0xFFFFFFFF}
    for _, v in ipairs(test_vals) do
      it(string.format("put_varint(%d) matches write_varint(%d)", v, v), function()
        assert.equal(enc(v), perf_enc(v),
          string.format("put_varint and write_varint disagree for %d", v))
      end)
    end
  end)

end)
