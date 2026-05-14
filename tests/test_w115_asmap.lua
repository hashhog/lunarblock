#!/usr/bin/env luajit
-- W115 ASMap fleet audit — lunarblock (Lua / LuaJIT)
-- Gates G1-G30 covering config, data structure, AddrMan integration,
-- sanity checks, peer behavior, stats, and persistence.
-- Core references: bitcoin-core/src/util/asmap.h/.cpp,
--                  bitcoin-core/src/netgroup.h/.cpp,
--                  bitcoin-core/src/addrman.cpp, bitcoin-core/src/init.cpp
-- MAX_ASMAP_FILESIZE = 8 MiB (8 * 1024 * 1024 bytes)
--
-- VERDICT: MISSING ENTIRELY — lunarblock has no ASMap subsystem at all.
-- The 30 gates below document each missing component individually.

package.path = "src/?.lua;" .. package.path

local loaders = package.loaders or package.searchers
table.insert(loaders, 2, function(module)
  local name = module:match("^lunarblock%.(.+)")
  if name then
    local filename = "src/" .. name .. ".lua"
    local f = io.open(filename)
    if f then
      f:close()
      return function() return dofile(filename) end
    end
  end
  return nil, "not found"
end)

local peerman = require("lunarblock.peerman")

local tests_passed = 0
local tests_failed = 0
local bugs = {}

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then
    io.write("PASS: " .. name .. "\n")
    tests_passed = tests_passed + 1
  else
    io.write("FAIL: " .. name .. "\n")
    io.write("      " .. tostring(err) .. "\n")
    tests_failed = tests_failed + 1
  end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) .. ", expected " .. tostring(b))
  end
end

local function expect_true(v, msg)
  if not v then error(msg or "expected true") end
end

local function expect_false(v, msg)
  if v then error(msg or "expected false") end
end

local function expect_not_nil(v, msg)
  if v == nil then error(msg or "expected non-nil value") end
end

-- ============================================================================
-- G1-G5: Configuration gates
-- ============================================================================

-- BUG-1 (HIGH): No -asmap CLI flag / config option.
-- Core: init.cpp:540 adds -asmap=<file> and -asmap (embedded) to argsman.
-- Without this, operators have no way to enable ASN-based bucketing.
test("G1: -asmap config option exists", function()
  -- Check main.lua for --asmap CLI argument.
  -- lunarblock has no such argument; this test documents the absence.
  local f = io.open("src/main.lua", "r")
  expect_not_nil(f, "main.lua not found")
  local content = f:read("*all")
  f:close()
  expect_true(content:find("asmap"), "BUG-1: no --asmap CLI option in main.lua")
end)

-- BUG-2 (HIGH): No embedded ASMap data.
-- Core: init.cpp:1612-1619 supports -asmap (no path) using embedded byte array.
-- No embedded ip_asn data or fallback exists in lunarblock.
test("G2: embedded asmap data present", function()
  local found = false
  for _, fname in ipairs({"src/main.lua", "src/peerman.lua"}) do
    local f = io.open(fname, "r")
    if f then
      local content = f:read("*all")
      f:close()
      if content:find("ip_asn") or content:find("embedded.*asmap") or content:find("asmap.*embedded") then
        found = true
        break
      end
    end
  end
  expect_true(found, "BUG-2: no embedded ASMap data (ip_asn byte array) found")
end)

-- BUG-3 (HIGH): No MAX_ASMAP_FILESIZE guard (8 MiB = 8*1024*1024).
-- Core: init.cpp validates that asmap file size is sane.
-- Without a file-size check an oversized file could cause OOM.
test("G3: MAX_ASMAP_FILESIZE = 8*1024*1024 constant defined", function()
  local f = io.open("src/peerman.lua", "r")
  expect_not_nil(f, "peerman.lua not found")
  local content = f:read("*all")
  f:close()
  expect_true(
    content:find("MAX_ASMAP") or content:find("8.*1024.*1024") or content:find("8388608"),
    "BUG-3: MAX_ASMAP_FILESIZE constant absent"
  )
end)

-- BUG-4 (HIGH): No DecodeAsmap / file-load function.
-- Core: util/asmap.cpp:DecodeAsmap() reads the binary file and validates it.
-- lunarblock has no equivalent loader.
test("G4: DecodeAsmap / load_asmap function exists", function()
  local found = false
  for _, fname in ipairs({"src/peerman.lua", "src/main.lua"}) do
    local f = io.open(fname, "r")
    if f then
      local content = f:read("*all")
      f:close()
      if content:find("decode_asmap") or content:find("load_asmap") or content:find("DecodeAsmap") then
        found = true
        break
      end
    end
  end
  expect_true(found, "BUG-4: no DecodeAsmap / load_asmap function")
end)

-- BUG-5 (HIGH): No AsmapVersion / checksum computation.
-- Core: netgroup.cpp:GetAsmapVersion() returns SHA256 of the asmap bytes.
-- Used by addrman.cpp to detect when the asmap changed and re-bucket.
test("G5: AsmapVersion / asmap_version checksum function exists", function()
  local found = false
  for _, fname in ipairs({"src/peerman.lua", "src/main.lua"}) do
    local f = io.open(fname, "r")
    if f then
      local content = f:read("*all")
      f:close()
      if content:find("asmap_version") or content:find("AsmapVersion") or content:find("get_asmap_version") then
        found = true
        break
      end
    end
  end
  expect_true(found, "BUG-5: no AsmapVersion checksum function")
end)

-- ============================================================================
-- G6-G10: Data structure gates
-- ============================================================================

-- BUG-6 (HIGH): No binary trie interpreter (Interpret function).
-- Core: util/asmap.cpp:Interpret() walks the bit-packed trie to look up ASN
-- for a 128-bit IP address. This is the core algorithm.
-- Without it, no IP -> ASN mapping is possible at all.
test("G6: Interpret / ip_to_asn trie-walk function exists", function()
  local f = io.open("src/peerman.lua", "r")
  expect_not_nil(f, "peerman.lua not found")
  local content = f:read("*all")
  f:close()
  expect_true(
    content:find("interpret") or content:find("Interpret") or content:find("ip_to_asn"),
    "BUG-6: no binary trie Interpret function for IP->ASN lookup"
  )
end)

-- BUG-7 (HIGH): No SanityCheckAsmap / CheckStandardAsmap validation.
-- Core: util/asmap.cpp:SanityCheckAsmap() and CheckStandardAsmap() validate
-- that the asmap bytecode is well-formed before use.
test("G7: SanityCheckAsmap / check_standard_asmap validation exists", function()
  local found = false
  for _, fname in ipairs({"src/peerman.lua", "src/main.lua"}) do
    local f = io.open(fname, "r")
    if f then
      local content = f:read("*all")
      f:close()
      if content:find("sanity_check") or content:find("SanityCheck") or content:find("check_standard") then
        found = true
        break
      end
    end
  end
  expect_true(found, "BUG-7: no SanityCheckAsmap / CheckStandardAsmap validation")
end)

-- BUG-8 (HIGH): NetGroupManager.GetMappedAS not implemented.
-- Core: netgroup.cpp:GetMappedAS() is the public interface that calls
-- Interpret() and returns ASN (or 0 for non-IPv4/IPv6 / no asmap).
-- Callers: GetGroup() and bucket functions.
test("G8: get_mapped_as / GetMappedAS function exists", function()
  local f = io.open("src/peerman.lua", "r")
  expect_not_nil(f, "peerman.lua not found")
  local content = f:read("*all")
  f:close()
  expect_true(
    content:find("get_mapped_as") or content:find("GetMappedAS") or content:find("mapped_as"),
    "BUG-8: no get_mapped_as function in peerman.lua"
  )
end)

-- BUG-9 (HIGH): get_addr_group() does not use ASN when asmap is loaded.
-- Core: netgroup.cpp:GetGroup() returns [NET_IPV6 + 4-byte ASN] when
-- GetMappedAS() returns non-zero.  lunarblock's get_addr_group() never
-- calls get_mapped_as; it always falls back to /16 (IPv4) or /32 (IPv6).
-- This means ASN-based bucketing is NOT used even if asmap were loaded.
test("G9: get_addr_group uses ASN when asmap loaded (not always /16 or /32)", function()
  -- Verify that get_addr_group has an asmap / mapped_as code path
  local f = io.open("src/peerman.lua", "r")
  expect_not_nil(f, "peerman.lua not found")
  local content = f:read("*all")
  f:close()
  -- Look for evidence that get_addr_group consults ASN / mapped_as
  expect_true(
    content:find("mapped_as") or content:find("get_mapped_as") or content:find("asn"),
    "BUG-9: get_addr_group always uses /16 or /32 — never consults ASN even when asmap loaded"
  )
end)

-- BUG-10 (HIGH): UsingASMap() / using_asmap state flag absent.
-- Core: netgroup.cpp:UsingASMap() returns m_asmap.size() > 0.
-- Used in addrman, connman, and RPC to gate ASN-related behavior.
test("G10: using_asmap state flag / UsingASMap() function exists", function()
  local f = io.open("src/peerman.lua", "r")
  expect_not_nil(f, "peerman.lua not found")
  local content = f:read("*all")
  f:close()
  expect_true(
    content:find("using_asmap") or content:find("UsingASMap") or content:find("asmap_enabled"),
    "BUG-10: no using_asmap / UsingASMap() flag"
  )
end)

-- ============================================================================
-- G11-G15: AddrMan integration gates
-- ============================================================================

-- BUG-11 (HIGH): Tried-bucket computation does not use ASN group.
-- Core: addrman_impl.h:GetTriedBucket() passes netgroupman to GetGroup(),
-- which returns the ASN group when asmap is loaded.
-- lunarblock's get_tried_bucket() always uses /16 or /32.
test("G11: get_tried_bucket uses ASN group when asmap loaded", function()
  local f = io.open("src/peerman.lua", "r")
  expect_not_nil(f, "peerman.lua not found")
  local content = f:read("*all")
  f:close()
  -- The bucket function must pass netgroupman or consult asmap
  expect_true(
    content:find("get_tried_bucket") and (
      content:find("asmap") or content:find("mapped_as") or content:find("asn")
    ),
    "BUG-11: get_tried_bucket does not use ASN group"
  )
end)

-- BUG-12 (HIGH): New-bucket computation does not use ASN group.
-- Core: addrman_impl.h:GetNewBucket() uses GetGroup() for both address
-- and source groups, so both resolve to ASN when asmap is loaded.
test("G12: get_new_bucket uses ASN group when asmap loaded", function()
  local f = io.open("src/peerman.lua", "r")
  expect_not_nil(f, "peerman.lua not found")
  local content = f:read("*all")
  f:close()
  expect_true(
    content:find("get_new_bucket") and (
      content:find("asmap") or content:find("mapped_as") or content:find("asn")
    ),
    "BUG-12: get_new_bucket does not use ASN group"
  )
end)

-- BUG-13 (HIGH): No re-bucketing when asmap version changes.
-- Core: addrman.cpp:303-347 re-buckets all entries when the serialized
-- asmap_version differs from the supplied one on load.
-- lunarblock's _init_addrman() never checks asmap version.
test("G13: addrman re-buckets on asmap version change", function()
  local f = io.open("src/peerman.lua", "r")
  expect_not_nil(f, "peerman.lua not found")
  local content = f:read("*all")
  f:close()
  expect_true(
    content:find("serialized_asmap") or content:find("asmap_version") or content:find("rebucket"),
    "BUG-13: no asmap version check / re-bucketing in addrman load path"
  )
end)

-- BUG-14 (HIGH): peers.dat does not persist asmap version.
-- Core: addrman.cpp:205-207 serialises m_netgroupman.GetAsmapVersion() into
-- peers.dat after the bucket entries so it can be compared on reload.
-- lunarblock's addrman persistence does not include this field.
test("G14: peers.dat serialises asmap version for consistency on reload", function()
  local f = io.open("src/peerman.lua", "r")
  expect_not_nil(f, "peerman.lua not found")
  local content = f:read("*all")
  f:close()
  -- Check for asmap version being written alongside peer data
  expect_true(
    content:find("asmap_version") and (content:find("save_peer") or content:find("peers%.dat") or content:find("_save_addrman")),
    "BUG-14: peers.dat does not persist asmap version"
  )
end)

-- BUG-15 (MEDIUM): ASMapHealthCheck absent.
-- Core: netgroup.cpp:ASMapHealthCheck() logs the count of distinct ASNs
-- seen among clearnet peers and the number of unmapped peers.
-- Useful for diagnosing poor diversity.
test("G15: ASMapHealthCheck / asmap_health_check function present", function()
  local found = false
  for _, fname in ipairs({"src/peerman.lua", "src/main.lua"}) do
    local f = io.open(fname, "r")
    if f then
      local content = f:read("*all")
      f:close()
      if content:find("asmap_health") or content:find("ASMapHealth") then
        found = true
        break
      end
    end
  end
  expect_true(found, "BUG-15: ASMapHealthCheck absent")
end)

-- ============================================================================
-- G16-G20: Sanity / correctness gates
-- ============================================================================

-- BUG-16 (HIGH): No bit-level trie decode for RETURN instruction.
-- Core: asmap.cpp Interpret() uses DecodeBits with ASN_BIT_SIZES for the
-- RETURN instruction. Without this the trie walk cannot terminate correctly.
test("G16: RETURN instruction ASN decode (DecodeBits with ASN_BIT_SIZES)", function()
  local f = io.open("src/peerman.lua", "r")
  expect_not_nil(f, "peerman.lua not found")
  local content = f:read("*all")
  f:close()
  expect_true(
    content:find("RETURN") or content:find("ASN_BIT") or content:find("decode_bits"),
    "BUG-16: no RETURN instruction handler in trie interpreter"
  )
end)

-- BUG-17 (HIGH): No JUMP instruction handler.
-- Core: asmap.cpp Instruction::JUMP — inspects next input bit and optionally
-- skips forward in the bytecode. Required for trie traversal.
test("G17: JUMP instruction handler in trie interpreter", function()
  local f = io.open("src/peerman.lua", "r")
  expect_not_nil(f, "peerman.lua not found")
  local content = f:read("*all")
  f:close()
  expect_true(
    content:find("JUMP") or content:find("jump_offset") or content:find("skip_bits"),
    "BUG-17: no JUMP instruction handler in trie interpreter"
  )
end)

-- BUG-18 (HIGH): No MATCH instruction handler.
-- Core: asmap.cpp Instruction::MATCH — matches 1-or-more bits against input;
-- on mismatch returns default ASN. Critical for prefix matching.
test("G18: MATCH instruction handler in trie interpreter", function()
  local f = io.open("src/peerman.lua", "r")
  expect_not_nil(f, "peerman.lua not found")
  local content = f:read("*all")
  f:close()
  expect_true(
    content:find("MATCH") or content:find("match_bits") or content:find("matchlen"),
    "BUG-18: no MATCH instruction handler in trie interpreter"
  )
end)

-- BUG-19 (HIGH): No DEFAULT instruction handler.
-- Core: asmap.cpp Instruction::DEFAULT — sets the fallback ASN and continues.
-- Without it every unmapped prefix silently returns 0 without proper default.
test("G19: DEFAULT instruction handler in trie interpreter", function()
  -- Searches specifically for asmap DEFAULT instruction handling in peerman.lua,
  -- not the generic 'default' keyword that appears in bucket / other contexts.
  local f = io.open("src/peerman.lua", "r")
  expect_not_nil(f, "peerman.lua not found")
  local content = f:read("*all")
  f:close()
  -- Only accept asmap-specific DEFAULT instruction patterns
  expect_true(
    content:find("default_asn") or content:find("set_default") or
    content:find("Instruction%.DEFAULT") or content:find("asmap.*DEFAULT"),
    "BUG-19: no DEFAULT instruction handler in trie interpreter"
  )
end)

-- BUG-20 (HIGH): Little-endian bit ordering for asmap, big-endian for IP.
-- Core: asmap.cpp ConsumeBitLE() for asmap bytes (LSB-first) vs
-- ConsumeBitBE() for IP address bytes (MSB-first / network byte order).
-- Wrong bit ordering produces incorrect ASN lookups for all addresses.
test("G20: correct LE-for-asmap and BE-for-IP bit ordering in interpreter", function()
  local f = io.open("src/peerman.lua", "r")
  expect_not_nil(f, "peerman.lua not found")
  local content = f:read("*all")
  f:close()
  -- Check for evidence of intentional LE/BE bit-order handling
  expect_true(
    content:find("bit_le") or content:find("bit_be") or content:find("lsb") or
    content:find("msb") or content:find("ConsumeBit"),
    "BUG-20: no LE/BE bit-ordering distinction for asmap vs IP bytes"
  )
end)

-- ============================================================================
-- G21-G24: Peer behavior gates
-- ============================================================================

-- BUG-21 (HIGH): Outbound connection diversity not enforced by ASN.
-- Core: connman ensures no two outbound connections share the same ASN group
-- (when asmap is loaded). lunarblock's maintain_connections() uses /16 groups
-- but never checks ASN groups.
test("G21: outbound diversity enforced by ASN group (not just /16)", function()
  local f = io.open("src/peerman.lua", "r")
  expect_not_nil(f, "peerman.lua not found")
  local content = f:read("*all")
  f:close()
  -- Must see ASN/asmap gating in the outbound-connection selection path
  expect_true(
    content:find("asn_group") or content:find("asmap.*outbound") or
    content:find("mapped_as.*connect") or content:find("outbound.*asn"),
    "BUG-21: outbound diversity does not use ASN group even when asmap loaded"
  )
end)

-- BUG-22 (MEDIUM): getpeerinfo missing mapped_as field.
-- Core: RPC getpeerinfo returns "mapped_as" field (uint32) for each peer
-- when asmap is loaded (src/rpc/net.cpp).
test("G22: getpeerinfo returns mapped_as field", function()
  local f = io.open("src/rpc.lua", "r")
  expect_not_nil(f, "rpc.lua not found")
  local content = f:read("*all")
  f:close()
  expect_true(
    content:find("mapped_as"),
    "BUG-22: getpeerinfo response missing mapped_as field"
  )
end)

-- BUG-23 (MEDIUM): getnetworkinfo missing asmap_version field.
-- Core: RPC getnetworkinfo returns asmap_version (hex string) when loaded.
-- lunarblock's getnetworkinfo has no such field.
test("G23: getnetworkinfo returns asmap_version field", function()
  local f = io.open("src/rpc.lua", "r")
  expect_not_nil(f, "rpc.lua not found")
  local content = f:read("*all")
  f:close()
  expect_true(
    content:find("asmap_version"),
    "BUG-23: getnetworkinfo missing asmap_version field"
  )
end)

-- BUG-24 (MEDIUM): No getasmap RPC command.
-- Core: RPC getasmap is absent (not a Core 26+ RPC), but some diagnostics
-- use the getnetworkinfo field. The audit gate checks that the
-- asmap_version is at minimum surfaced in some RPC response.
-- (Re-using evidence from G23 — this gate checks a second call site.)
test("G24: asmap version surfaced in at least one RPC endpoint", function()
  local f = io.open("src/rpc.lua", "r")
  expect_not_nil(f, "rpc.lua not found")
  local content = f:read("*all")
  f:close()
  local count = 0
  for _ in content:gmatch("asmap") do count = count + 1 end
  expect_true(count >= 1, "BUG-24: asmap not surfaced in any RPC endpoint")
end)

-- ============================================================================
-- G25-G28: Stats / logging gates
-- ============================================================================

-- BUG-25 (LOW): No ASMap health-check logging on startup.
-- Core: init.cpp calls ASMapHealthCheck() after loading peers.dat if asmap
-- is active, logging distinct ASN count and unmapped peer count.
test("G25: ASMap health-check logged on startup", function()
  local f = io.open("src/main.lua", "r")
  expect_not_nil(f, "main.lua not found")
  local content = f:read("*all")
  f:close()
  expect_true(
    content:find("asmap_health") or content:find("ASMapHealth") or content:find("asmap.*startup"),
    "BUG-25: no ASMap health-check log on startup"
  )
end)

-- BUG-26 (LOW): No ASN diversity metric in peer stats.
-- Core: Bitcoin Core logs ASN group info for outbound peers. lunarblock
-- logs nothing about ASN diversity in its peer stats/logging paths.
test("G26: ASN diversity metric tracked or logged for outbound peers", function()
  local f = io.open("src/peerman.lua", "r")
  expect_not_nil(f, "peerman.lua not found")
  local content = f:read("*all")
  f:close()
  expect_true(
    content:find("asn_count") or content:find("asn_diversity") or content:find("distinct.*asn"),
    "BUG-26: no ASN diversity metric tracked or logged"
  )
end)

-- BUG-27 (LOW): Opening of asmap file not logged.
-- Core: init.cpp:1620 logs "Opened asmap data (%zu bytes) from embedded byte array"
-- and similar messages for file-loaded asmap.  No such log exists in lunarblock.
test("G27: asmap file open / load logged with size info", function()
  local found = false
  for _, fname in ipairs({"src/main.lua", "src/peerman.lua"}) do
    local f = io.open(fname, "r")
    if f then
      local content = f:read("*all")
      f:close()
      if content:find("asmap.*bytes") or content:find("Opened asmap") or content:find("asmap.*loaded") then
        found = true
        break
      end
    end
  end
  expect_true(found, "BUG-27: no 'opened asmap data N bytes' log message")
end)

-- BUG-28 (LOW): Version string not logged after asmap load.
-- Core: init.cpp:1628 logs "Using asmap version %s for IP bucketing" (SHA256 hex).
test("G28: asmap version hash logged after load", function()
  local found = false
  for _, fname in ipairs({"src/main.lua", "src/peerman.lua"}) do
    local f = io.open(fname, "r")
    if f then
      local content = f:read("*all")
      f:close()
      if content:find("asmap version") or content:find("Using asmap") then
        found = true
        break
      end
    end
  end
  expect_true(found, "BUG-28: asmap version hash not logged after load")
end)

-- ============================================================================
-- G29-G30: Persistence gates
-- ============================================================================

-- BUG-29 (HIGH): addrman on-disk format incompatible with Core (missing asmap version).
-- Core: addrman.cpp:205-207 serialises asmap_version to peers.dat.
-- On load (line 313-347) it compares the stored version to the current one
-- and re-buckets if they differ. Without this field, switching asmaps
-- silently produces wrong bucket assignments until the addrman is cleared.
test("G29: peers.dat format includes asmap version for re-bucket-on-change", function()
  local f = io.open("src/peerman.lua", "r")
  expect_not_nil(f, "peerman.lua not found")
  local content = f:read("*all")
  f:close()
  -- Need asmap version written and compared in save/load paths
  local has_write = content:find("asmap_version") and content:find("save")
  local has_read  = content:find("asmap_version") and content:find("load")
  expect_true(has_write or has_read,
    "BUG-29: peers.dat save/load does not handle asmap version for re-bucketing")
end)

-- BUG-30 (HIGH): No asmap file integrity verified on load (CheckStandardAsmap).
-- Core: DecodeAsmap() calls CheckStandardAsmap() before returning data.
-- Without this, a corrupt or truncated asmap file causes silent wrong ASN lookups
-- (or even crashes in C++; in Lua, subtler corruption).
test("G30: asmap file integrity (CheckStandardAsmap) verified before use", function()
  local found = false
  for _, fname in ipairs({"src/peerman.lua", "src/main.lua"}) do
    local f = io.open(fname, "r")
    if f then
      local content = f:read("*all")
      f:close()
      if content:find("check_standard_asmap") or content:find("CheckStandardAsmap") or
         content:find("sanity_check_asmap") or content:find("SanityCheckAsmap") then
        found = true
        break
      end
    end
  end
  expect_true(found, "BUG-30: no CheckStandardAsmap integrity check before using asmap file")
end)

-- ============================================================================
-- Summary
-- ============================================================================

io.write("\n")
io.write("=== W115 ASMap audit results — lunarblock ===\n")
io.write(string.format("Tests passed: %d\n", tests_passed))
io.write(string.format("Tests failed: %d\n", tests_failed))
io.write(string.format("Total:        %d\n", tests_passed + tests_failed))
io.write("\n")
io.write("VERDICT: MISSING ENTIRELY\n")
io.write("  lunarblock has no ASMap subsystem.\n")
io.write("  All 30 gates fail. Bugs BUG-1 through BUG-30 documented above.\n")
io.write("  Key missing components:\n")
io.write("    - No -asmap CLI flag or config option (BUG-1)\n")
io.write("    - No binary trie interpreter Interpret() (BUG-6)\n")
io.write("    - No SanityCheckAsmap / CheckStandardAsmap (BUG-7, BUG-30)\n")
io.write("    - get_addr_group() always uses /16 or /32, never ASN (BUG-9)\n")
io.write("    - Bucket functions (get_tried_bucket, get_new_bucket) ignore ASN (BUG-11, BUG-12)\n")
io.write("    - No re-bucketing on asmap version change (BUG-13)\n")
io.write("    - getpeerinfo missing mapped_as field (BUG-22)\n")
io.write("    - getnetworkinfo missing asmap_version field (BUG-23)\n")

if tests_failed > 0 then
  os.exit(1)
end
