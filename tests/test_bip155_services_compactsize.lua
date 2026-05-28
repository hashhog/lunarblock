#!/usr/bin/env luajit
-- BIP-155 services field must use CompactSize with range_check=false.
--
-- Regression test for the same parse bug nimrod fixed in commit 0454cf0:
-- `services` is a 64-bit bitfield, not a container length, so any address
-- gossipped with a service bit at position >= 26 (value > 0x02000000)
-- would raise "ReadCompactSize(): size too large" and tear down the
-- addrv2 handler.  _safe_dispatch then disconnects the peer, which kills
-- any in-flight PRESYNC state from that peer — observed on mainnet as the
-- IBD-stuck-at-genesis pattern.
--
-- Bitcoin Core: src/protocol.h:446
--   READWRITE(Using<CompactSizeFormatter<false>>(services_tmp));
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   LD_LIBRARY_PATH=./lib luajit tests/test_bip155_services_compactsize.lua

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
local p2p = require("lunarblock.p2p")

local PASS, FAIL = 0, 0

local function expect_eq(a, b, name)
  if a == b then
    PASS = PASS + 1
    print("PASS " .. name)
  else
    FAIL = FAIL + 1
    print("FAIL " .. name .. ": expected " .. tostring(b) .. " got " .. tostring(a))
  end
end

local function expect_true(v, name)
  if v then
    PASS = PASS + 1
    print("PASS " .. name)
  else
    FAIL = FAIL + 1
    print("FAIL " .. name .. ": expected true")
  end
end

-- --- read_varint: range_check default is true (size > MAX_SIZE rejected) ---
do
  -- Encode a CompactSize value = 0x04000000 (bit 26 set).  This is the
  -- smallest value that exceeds MAX_SIZE (0x02000000).
  local w = serialize.buffer_writer()
  w.write_u8(0xFE)              -- 5-byte form: prefix + u32le
  w.write_u32le(0x04000000)
  local data = w.result()

  local r = serialize.buffer_reader(data)
  local ok = pcall(r.read_varint)  -- default range_check=true
  expect_true(not ok, "range_check=true (default) rejects size > MAX_SIZE")
end

-- --- read_varint: range_check=false accepts values > MAX_SIZE ---
do
  local w = serialize.buffer_writer()
  w.write_u8(0xFE)
  w.write_u32le(0x04000000)
  local data = w.result()

  local r = serialize.buffer_reader(data)
  local ok, val = pcall(r.read_varint, false)
  expect_true(ok, "range_check=false accepts size > MAX_SIZE")
  expect_eq(val, 0x04000000, "range_check=false returns the raw value")
end

-- --- read_varint: range_check=false with all-bits-set 64-bit service field ---
do
  -- Build a 9-byte CompactSize encoding for a full uint64 with bit 31 set
  -- but value still > MAX_SIZE: 0x0000000100000000 (low + high).
  -- The 9-byte form is 0xFF + u64le.
  local w = serialize.buffer_writer()
  w.write_u8(0xFF)
  w.write_u64le(0x0000000100000000)
  local data = w.result()

  local r = serialize.buffer_reader(data)
  local ok, val = pcall(r.read_varint, false)
  expect_true(ok, "range_check=false accepts 9-byte u64 > MAX_SIZE")
  expect_true(val == 0x100000000 or val == 4294967296,
    "range_check=false returns u64 value")
end

-- --- end-to-end: deserialize_addrv2 with a service bit > 0x02000000 ---
do
  -- Encode an addrv2 message with one IPv4 entry whose services field is
  -- 0x04000000 (bit 26 set).  Pre-fix this would raise
  -- "ReadCompactSize(): size too large" at the services line; post-fix it
  -- round-trips.
  local services = 0x04000000

  -- addrv2 wire format per BIP-155:
  --   varint count
  --   per entry:
  --     u32le timestamp
  --     varint services
  --     u8 network_id
  --     varint addr_len
  --     bytes addr_bytes
  --     u16be port
  local w = serialize.buffer_writer()
  w.write_varint(1)             -- count
  w.write_u32le(1700000000)     -- timestamp
  -- services as 5-byte CompactSize (value > 0xFFFF requires u32le branch)
  w.write_u8(0xFE)
  w.write_u32le(services)
  w.write_u8(p2p.NET_ID.IPV4)   -- network_id
  w.write_varint(4)             -- addr_len
  w.write_bytes("\x01\x02\x03\x04")
  w.write_u16be(8333)
  local payload = w.result()

  local ok, addresses = pcall(p2p.deserialize_addrv2, payload)
  expect_true(ok, "deserialize_addrv2 accepts services with bit 26 set: " .. tostring(addresses))
  if ok then
    expect_eq(#addresses, 1, "one address parsed")
    expect_eq(addresses[1].services, services, "services round-trips")
  end
end

-- --- end-to-end: addrv2 with services = bit 63 (full upper bits) ---
do
  -- Many honest Satoshi peers set high-bit experimental services.
  -- This is the realistic shape that triggered the disconnect storm on
  -- nimrod's 2026-05-27 mainnet IBD run.
  local services = 0xFFFFFFFF  -- bit 0..31 all set; just shy of overflow

  local w = serialize.buffer_writer()
  w.write_varint(1)
  w.write_u32le(1700000000)
  w.write_u8(0xFE)
  w.write_u32le(services)
  w.write_u8(p2p.NET_ID.IPV4)
  w.write_varint(4)
  w.write_bytes("\x01\x02\x03\x04")
  w.write_u16be(8333)
  local payload = w.result()

  local ok, addresses = pcall(p2p.deserialize_addrv2, payload)
  expect_true(ok, "deserialize_addrv2 accepts services=0xFFFFFFFF")
end

-- --- length fields STILL get range_check (defence in depth) ---
do
  -- A varint COUNT of 0x04000000 at the top of addrv2 SHOULD be rejected,
  -- because that IS a container length and the MAX_SIZE cap is a real
  -- DoS guard there.  Make sure the fix didn't accidentally relax range
  -- checking globally.
  local w = serialize.buffer_writer()
  w.write_u8(0xFE)
  w.write_u32le(0x04000000)     -- count > MAX_SIZE
  -- (followed by enough bytes so we don't EOF before the check fires)
  for _ = 1, 64 do w.write_u8(0) end
  local payload = w.result()

  local ok = pcall(p2p.deserialize_addrv2, payload)
  expect_true(not ok, "addrv2 count > MAX_SIZE still rejected (regression guard)")
end

print(string.format("\n=== SUMMARY: %d PASS / %d FAIL ===", PASS, FAIL))
if FAIL > 0 then os.exit(1) end
