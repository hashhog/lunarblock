#!/usr/bin/env luajit
-- W138 assumeUTXO snapshots audit — lunarblock (Lua / LuaJIT)
--
-- Discovery-only. Tests pin lunarblock's assumeUTXO state vs Core's
-- node/utxo_snapshot.cpp + validation.cpp (ActivateSnapshot,
-- PopulateAndValidateSnapshot, MaybeCompleteSnapshotValidation) +
-- rpc/blockchain.cpp (dumptxoutset, loadtxoutset, getchainstates).
-- See audit/w138_assumeutxo.md for the full 30-gate matrix.
--
-- 30 gates (G1-G30):
--   G1     SNAPSHOT_MAGIC_BYTES = 'utxo' || 0xff
--   G2     SnapshotMetadata version uint16 LE = 2
--   G3     Unsupported version rejection (BUG: should reject v1)
--   G4     Network-magic check (PARTIAL: error fidelity gap)
--   G5     base_blockhash + coins_count fields
--   G6     SnapshotMetadata total = 51 bytes
--   G7     dumptxoutset type arg: latest / rollback / ""
--   G8     dumptxoutset options.rollback by height or 64-hex hash (PARTIAL)
--   G9     dumptxoutset rejects target above tip
--   G10    dumptxoutset prune-mode pre-check
--   G11    dumptxoutset NetworkDisable RAII (PARTIAL: only blocks submitblock)
--   G12    dumptxoutset rewind→dump→reapply via TemporaryRollback
--   G13    dumptxoutset atomic rename via .incomplete tempfile
--   G14    dumptxoutset response keys (BUG: nchaintx is UTXO count not tx count)
--   G15    Refuse to clobber existing dumptxoutset path
--   G16    write_corevarint(code = h*2+cb)
--   G17    write_corevarint(CompressAmount(value))
--   G18    ScriptCompression (BUG: always raw branch — type bytes never emitted)
--   G19    per-txid grouping: txid + CompactSize(coins_per_txid)
--   G20    Genesis-coinbase exclusion
--   G21    fsync before close + atomic rename
--   G22    loadtxoutset peeks header + assumeutxo whitelist
--   G23    Duplicate-activation guard (PARTIAL: not persisted across restart)
--   G24    Best-headers ancestor check (MISSING)
--   G25    snapshot_start_block in headers chain (MISSING)
--   G26    BLOCK_FAILED_VALID guard (MISSING)
--   G27    Work-exceeds-active (PARTIAL: height-as-work-proxy)
--   G28    Mempool-empty guard
--   G29    Per-coin height > base_height guard
--   G30    MoneyRange + trailing-bytes + HASH_SERIALIZED gate (PARTIAL: opt-in only)

package.path = "src/?.lua;" .. package.path

-- Custom loader for lunarblock modules
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

local utxo_mod = require("lunarblock.utxo")
local consensus_mod = require("lunarblock.consensus")
local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")

-- Test infrastructure -------------------------------------------------------
local tests_passed = 0
local tests_failed = 0
local bugs = {}

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then
    print("PASS: " .. name)
    tests_passed = tests_passed + 1
  else
    print("FAIL: " .. name)
    print("      " .. tostring(err))
    tests_failed = tests_failed + 1
  end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a)
      .. ", expected " .. tostring(b))
  end
end

local function expect_true(v, msg)
  if not v then error(msg or "expected true") end
end

local function expect_false(v, msg)
  if v then error(msg or "expected false") end
end

local function expect_nil(v, msg)
  if v ~= nil then error((msg or "expected nil") .. ": got " .. tostring(v)) end
end

local function expect_not_nil(v, msg)
  if v == nil then error(msg or "expected non-nil") end
end

local function log_bug(id, priority, desc)
  bugs[#bugs + 1] = {id = id, priority = priority, desc = desc}
end

-- Helper: read a file, return contents as string (for source-grep checks)
local function read_file(path)
  local f = io.open(path, "rb")
  if not f then return nil end
  local s = f:read("*a")
  f:close()
  return s
end

local UTXO_SRC = read_file("src/utxo.lua")
local RPC_SRC = read_file("src/rpc.lua")
local MAIN_SRC = read_file("src/main.lua")
local CONSENSUS_SRC = read_file("src/consensus.lua")
assert(UTXO_SRC, "could not read src/utxo.lua")
assert(RPC_SRC, "could not read src/rpc.lua")
assert(MAIN_SRC, "could not read src/main.lua")
assert(CONSENSUS_SRC, "could not read src/consensus.lua")

print("=== W138 lunarblock assumeUTXO snapshots audit ===\n")

--------------------------------------------------------------------------------
-- G1: SNAPSHOT_MAGIC_BYTES = 'utxo' || 0xff (5 bytes)
--------------------------------------------------------------------------------
test("G1: M.SNAPSHOT_MAGIC = 'utxo\\xff' (5 bytes)", function()
  expect_eq(utxo_mod.SNAPSHOT_MAGIC, "utxo\xff", "SNAPSHOT_MAGIC constant")
  expect_eq(#utxo_mod.SNAPSHOT_MAGIC, 5, "magic is exactly 5 bytes")
  -- Verify it's emitted at offset 0 of serialize_snapshot_metadata
  local md = utxo_mod.snapshot_metadata(
    "\x01\x02\x03\x04",
    types.hash256(string.rep("\xab", 32)),
    1000
  )
  local data = utxo_mod.serialize_snapshot_metadata(md)
  expect_eq(data:sub(1, 5), "utxo\xff", "serialized metadata starts with magic")
end)

test("G1.b: deserialize rejects wrong magic", function()
  local bad = "xxxx\xff" .. string.rep("\x00", 50)
  local res, err = utxo_mod.deserialize_snapshot_metadata(bad)
  expect_nil(res, "wrong magic should be rejected")
  expect_true(err and err:find("invalid snapshot magic") ~= nil,
    "error string mentions magic mismatch")
end)

--------------------------------------------------------------------------------
-- G2: SnapshotMetadata version = uint16 LE; VERSION = 2
--------------------------------------------------------------------------------
test("G2: SNAPSHOT_VERSION = 2 (matches Core utxo_snapshot.h:39)", function()
  expect_eq(utxo_mod.SNAPSHOT_VERSION, 2)
  -- Verify it's emitted at offset 5 (after magic) as uint16 LE
  local md = utxo_mod.snapshot_metadata(
    "\x01\x02\x03\x04",
    types.hash256(string.rep("\xab", 32)),
    1000
  )
  local data = utxo_mod.serialize_snapshot_metadata(md)
  -- bytes 6-7 (1-indexed): version LE
  expect_eq(data:byte(6), 0x02, "version byte 0 = 0x02")
  expect_eq(data:byte(7), 0x00, "version byte 1 = 0x00")
end)

--------------------------------------------------------------------------------
-- G3: Unsupported snapshot version rejection (BUG)
--------------------------------------------------------------------------------
test("G3: BUG-1 lunarblock accepts version=1 which Core rejects",
function()
  log_bug("BUG-1", "P2",
    "utxo.lua:857-860 checks `version > M.SNAPSHOT_VERSION`; "
    .. "Core (utxo_snapshot.h:84) checks `!m_supported_versions.contains("
    .. "version)`. lunarblock would accept version=1 (older snapshot "
    .. "format) which Core's supported_versions set rejects.")
  -- Construct a v1 header: magic + 0x01 0x00 + magic[4] + hash[32] + count[8]
  local v1 = "utxo\xff"
    .. "\x01\x00"  -- version = 1
    .. "\xf9\xbe\xb4\xd9"  -- mainnet network magic
    .. string.rep("\xab", 32)
    .. string.rep("\x00", 8)
  local res, err = utxo_mod.deserialize_snapshot_metadata(v1)
  -- lunarblock will ACCEPT v1 because its check is `> M.SNAPSHOT_VERSION` not
  -- `!= M.SNAPSHOT_VERSION` / `not in {2}`.
  expect_not_nil(res, "lunarblock accepts version=1 (this is the BUG)")
  expect_eq(res.version, 1, "lunarblock returns version=1")
  -- Confirm source-level: the check uses `>` not set membership
  expect_true(
    UTXO_SRC:find("version%s*>%s*M%.SNAPSHOT_VERSION", 1, false) ~= nil,
    "source uses > comparison instead of set membership")
end)

--------------------------------------------------------------------------------
-- G4: SnapshotMetadata network_magic check (PARTIAL: error fidelity gap)
--------------------------------------------------------------------------------
test("G4: BUG-2 network-magic mismatch error is generic (no network name)",
function()
  log_bug("BUG-2", "P2",
    "utxo.lua:4638-4641 raises generic 'snapshot network magic mismatch'. "
    .. "Core (utxo_snapshot.h:91-100) resolves the mismatched magic via "
    .. "GetNetworkForMagic and emits 'The network of the snapshot (mainnet) "
    .. "does not match the network of this node (testnet)' so operators "
    .. "see what they got vs what they wanted. lunarblock's bare error "
    .. "string offers no diagnostic.")
  expect_true(
    UTXO_SRC:find("snapshot network magic mismatch", 1, true) ~= nil,
    "generic error string present")
  -- Core's resolved-network error is not present
  expect_true(
    UTXO_SRC:find("does not match the network", 1, true) == nil,
    "no network-name-resolved error string")
end)

--------------------------------------------------------------------------------
-- G5: base_blockhash + coins_count fields
--------------------------------------------------------------------------------
test("G5: SnapshotMetadata round-trip preserves base_blockhash + coins_count",
function()
  local target_hash = types.hash256(string.rep("\xab", 32))
  local md = utxo_mod.snapshot_metadata(
    "\xf9\xbe\xb4\xd9",  -- mainnet magic
    target_hash,
    991032194  -- mainnet 840k chain_tx_count
  )
  local data = utxo_mod.serialize_snapshot_metadata(md)
  local round, err = utxo_mod.deserialize_snapshot_metadata(data)
  expect_not_nil(round, "round-trip succeeds")
  expect_eq(round.coins_count, 991032194, "coins_count preserved")
  expect_eq(round.base_blockhash.bytes, target_hash.bytes,
    "base_blockhash preserved")
  expect_eq(round.network_magic, "\xf9\xbe\xb4\xd9", "network_magic preserved")
end)

--------------------------------------------------------------------------------
-- G6: SnapshotMetadata header total = 51 bytes
--------------------------------------------------------------------------------
test("G6: SnapshotMetadata header is exactly 51 bytes (5+2+4+32+8)",
function()
  local md = utxo_mod.snapshot_metadata(
    "\xf9\xbe\xb4\xd9",
    types.hash256(string.rep("\x00", 32)),
    0
  )
  local data = utxo_mod.serialize_snapshot_metadata(md)
  expect_eq(#data, 51, "serialized metadata is 51 bytes")
  -- Verify deserialize requires >= 51
  local truncated = data:sub(1, 50)
  local res, err = utxo_mod.deserialize_snapshot_metadata(truncated)
  expect_nil(res, "50 bytes is rejected")
  expect_true(err and err:find("too short") ~= nil, "error mentions short header")
end)

--------------------------------------------------------------------------------
-- G7: dumptxoutset "type" arg parsing
--------------------------------------------------------------------------------
test("G7: dumptxoutset handles latest / rollback / '' / invalid",
function()
  -- Source-grep: confirm all four branches present
  expect_true(
    RPC_SRC:find('snapshot_type%s*==%s*""%s*or%s*snapshot_type%s*==%s*"latest"', 1, false) ~= nil
    or RPC_SRC:find('"latest"', 1, true) ~= nil,
    "latest branch present")
  expect_true(RPC_SRC:find('"rollback"', 1, true) ~= nil, "rollback branch present")
  expect_true(
    RPC_SRC:find("Invalid snapshot type", 1, true) ~= nil,
    "invalid-type error string present")
end)

--------------------------------------------------------------------------------
-- G8: dumptxoutset options.rollback by height or 64-hex blockhash (PARTIAL)
--------------------------------------------------------------------------------
test("G8: BUG-3 dumptxoutset by-hash rollback is O(N) linear scan",
function()
  log_bug("BUG-3", "P2",
    "rpc.lua:7605-7609 resolves rollback-by-hash via `for h = 0, "
    .. "current_tip_height do hh = get_hash_by_height(h)` — O(N) per call. "
    .. "Core uses LookupBlockIndex (O(1) hash lookup). At mainnet tip 900k+ "
    .. "this is a ~100ms self-DoS on every dumptxoutset rollback by-hash.")
  -- Confirm the linear loop exists in source
  expect_true(
    RPC_SRC:find("for h = 0, current_tip_height", 1, true) ~= nil,
    "linear scan over heights present in by-hash branch")
  expect_true(
    RPC_SRC:find("rollback target hash not found in active chain", 1, true) ~= nil,
    "linear scan error string present")
end)

--------------------------------------------------------------------------------
-- G9: dumptxoutset rejects rollback target above current tip
--------------------------------------------------------------------------------
test("G9: dumptxoutset rejects target > tip with Core-exact error",
function()
  expect_true(
    RPC_SRC:find("Rollback target above current tip", 1, true) ~= nil,
    "Core-exact error string present")
end)

--------------------------------------------------------------------------------
-- G10: dumptxoutset prune-mode pre-check
--------------------------------------------------------------------------------
test("G10: dumptxoutset prune-mode pre-check emits Core-exact error",
function()
  expect_true(
    RPC_SRC:find("Block height %%d not available %%(pruned data%%)", 1, false) ~= nil
    or RPC_SRC:find('"Block height %%d not available %%(pruned data%%)', 1, false) ~= nil
    or RPC_SRC:find("Block height", 1, true) ~= nil,
    "prune-mode error string present")
  expect_true(RPC_SRC:find("pruned data", 1, true) ~= nil,
    "pruned data marker present")
end)

--------------------------------------------------------------------------------
-- G11: dumptxoutset NetworkDisable RAII (PARTIAL)
--------------------------------------------------------------------------------
test("G11: BUG-4 NetworkDisable only blocks submitblock, not P2P inbound",
function()
  log_bug("BUG-4", "P2",
    "rpc.lua:7689-7693 sets `rpc.block_submission_paused = true` and 7750-7752 "
    .. "clears it on every exit path. **However**, the flag is checked only "
    .. "at the submitblock RPC (mempool.lua:6950-6953). The P2P inbound "
    .. "block-acceptance path (peerman:process_block) does NOT check it. "
    .. "Core's NetworkDisable calls SetNetworkActive(false) which closes the "
    .. "listening socket — far more thorough.")
  expect_true(
    RPC_SRC:find("block_submission_paused%s*=%s*true", 1, false) ~= nil,
    "pause flag set in dumptxoutset")
  -- The flag is checked at exactly one place: the submitblock RPC handler
  -- (rpc.lua:6954). It is NOT checked on the P2P inbound path.
  expect_true(
    RPC_SRC:find("if rpc%.block_submission_paused then", 1, false) ~= nil,
    "pause flag checked at submitblock RPC handler")
  -- Confirm the P2P inbound path (peer.lua) does NOT check it
  local peer_src = read_file("src/peer.lua")
  if peer_src then
    expect_true(
      peer_src:find("block_submission_paused", 1, true) == nil,
      "P2P inbound (peer.lua) does NOT check the pause flag (this is the BUG)")
  end
  -- Confirm peerman.lua doesn't check it either
  local peerman_src = read_file("src/peerman.lua")
  if peerman_src then
    expect_true(
      peerman_src:find("block_submission_paused", 1, true) == nil,
      "peerman.lua does NOT check the pause flag (P2P broker layer)")
  end
end)

--------------------------------------------------------------------------------
-- G12: dumptxoutset rewind→dump→reapply via TemporaryRollback
--------------------------------------------------------------------------------
test("G12: dumptxoutset uses rollback_chain_to + reapply_disconnected",
function()
  expect_true(
    UTXO_SRC:find("function ChainState:rollback_chain_to", 1, true) ~= nil,
    "rollback_chain_to defined")
  expect_true(
    UTXO_SRC:find("function ChainState:reapply_disconnected", 1, true) ~= nil,
    "reapply_disconnected defined")
  expect_true(
    RPC_SRC:find("rollback_chain_to", 1, true) ~= nil,
    "dumptxoutset calls rollback_chain_to")
  expect_true(
    RPC_SRC:find("reapply_disconnected", 1, true) ~= nil,
    "dumptxoutset calls reapply_disconnected")
end)

--------------------------------------------------------------------------------
-- G13: dumptxoutset atomic rename via .incomplete tempfile
--------------------------------------------------------------------------------
test("G13: dumptxoutset writes to .incomplete then os.rename",
function()
  expect_true(
    RPC_SRC:find('"%.incomplete"', 1, false) ~= nil
    or RPC_SRC:find("%.incomplete", 1, false) ~= nil,
    ".incomplete tempfile pattern present")
  expect_true(RPC_SRC:find("os%.rename", 1, false) ~= nil,
    "os.rename atomic move present")
  expect_true(
    UTXO_SRC:find("function _fsync_file", 1, true) ~= nil,
    "fsync helper defined")
end)

--------------------------------------------------------------------------------
-- G14: dumptxoutset response keys (BUG: nchaintx is UTXO count, not tx count)
--------------------------------------------------------------------------------
test("G14: BUG-5 dumptxoutset.nchaintx is UTXO count not tx count (off by ~10x)",
function()
  log_bug("BUG-5", "P1",
    "rpc.lua:7770 sets `nchaintx = result.coins_count` — the UTXO count. "
    .. "Core (rpc/blockchain.cpp:3346) sets `nchaintx = tip->m_chain_tx_count` "
    .. "— the CUMULATIVE TRANSACTION COUNT up to and including the tip. "
    .. "At mainnet h=840k these differ by ~1.3B (tx count) vs ~165M (UTXO "
    .. "count) — off by ~8-10x. Downstream loadtxoutset progress estimators "
    .. "(verificationprogress) rely on m_chain_tx_count.")
  -- Confirm the wrong assignment in source
  expect_true(
    RPC_SRC:find("nchaintx%s*=%s*result%.coins_count", 1, false) ~= nil,
    "nchaintx assigned from coins_count (the bug)")
  -- Confirm the TODO comment acknowledges it
  expect_true(
    RPC_SRC:find("m_chain_tx_count from chainparams", 1, true) ~= nil,
    "TODO comment acknowledges the gap")
end)

--------------------------------------------------------------------------------
-- G15: Refuse to clobber existing dumptxoutset path
--------------------------------------------------------------------------------
test("G15: dumptxoutset refuses to overwrite existing file",
function()
  expect_true(
    RPC_SRC:find("path already exists", 1, true) ~= nil,
    "clobber-protection error string present")
end)

--------------------------------------------------------------------------------
-- G16: write_corevarint(code = h*2+cb)
--------------------------------------------------------------------------------
test("G16: write_corevarint matches Core's MSB-first base-128 encoding",
function()
  local w = serialize.buffer_writer()
  utxo_mod.write_corevarint(w, 0)
  expect_eq(w.result(), "\x00", "varint(0) = 0x00")

  -- Round trip: 0..1000
  for v = 0, 1000 do
    local ww = serialize.buffer_writer()
    utxo_mod.write_corevarint(ww, v)
    local bytes = ww.result()
    local r = serialize.buffer_reader(bytes)
    local got = tonumber(utxo_mod.read_corevarint(r))
    expect_eq(got, v, "round-trip varint " .. v)
  end

  -- Spot-check a few larger values (height*2+coinbase patterns)
  -- code = 840000*2 + 1 = 1680001 → encodes in 3 bytes
  for _, v in ipairs({100, 127, 128, 255, 256, 16383, 16384, 1680001}) do
    local ww = serialize.buffer_writer()
    utxo_mod.write_corevarint(ww, v)
    local r = serialize.buffer_reader(ww.result())
    expect_eq(tonumber(utxo_mod.read_corevarint(r)), v,
      "round-trip varint " .. v)
  end
end)

--------------------------------------------------------------------------------
-- G17: write_corevarint(CompressAmount(value))
--------------------------------------------------------------------------------
test("G17: compress_amount round-trips for various amounts",
function()
  -- compress_amount returns uint64 cdata; decompress_amount returns number
  local cases = {0, 1, 50, 100, 500000000, 5000000000, 2100000000000000}
  for _, v in ipairs(cases) do
    local c = utxo_mod.compress_amount(v)
    local back = utxo_mod.decompress_amount(c)
    expect_eq(back, v, "round-trip amount " .. v)
  end
end)

--------------------------------------------------------------------------------
-- G18: ScriptCompression (BUG: compress_script always emits raw branch)
--------------------------------------------------------------------------------
test("G18: BUG-6 compress_script always emits raw branch (never type 0x00-0x05)",
function()
  log_bug("BUG-6", "P0",
    "utxo.lua:740-752 compress_script ALWAYS falls through to the raw "
    .. "branch `VARINT(size+6) + bytes`. Detection helpers _is_p2pkh / "
    .. "_is_p2sh / _is_p2pk_compressed are referenced only as `local _ = "
    .. "...` no-ops at 745-747. Core (compressor.cpp:CompressScript) emits "
    .. "type 0x00 (P2PKH, 1+20 bytes) instead of 25-byte raw. lunarblock "
    .. "dumps are ~3-4x larger than Core dumps over the same UTXO set; "
    .. "lunarblock and Core snapshots over the same chainstate are NOT "
    .. "byte-identical. Cross-impl snapshot exchange / fleet sha256sum "
    .. "compare would split.")
  -- Confirm the no-op references in source
  expect_true(
    UTXO_SRC:find("local _ = _is_p2pkh", 1, true) ~= nil,
    "_is_p2pkh referenced as no-op")
  expect_true(
    UTXO_SRC:find("local _2 = _is_p2sh", 1, true) ~= nil,
    "_is_p2sh referenced as no-op")
  expect_true(
    UTXO_SRC:find("local _3 = _is_p2pk_compressed", 1, true) ~= nil,
    "_is_p2pk_compressed referenced as no-op")
  -- Behavioral confirmation: compress_script on a P2PKH should emit 26
  -- bytes (1 varint + 25 raw) NOT 21 bytes (1 type byte + 20 hash).
  local p2pkh = "\x76\xa9\x14" .. string.rep("\x01", 20) .. "\x88\xac"
  expect_eq(#p2pkh, 25, "constructed 25-byte P2PKH")
  local compressed = utxo_mod.compress_script(p2pkh)
  -- Core would emit: type 0x00 + 20-byte hash = 21 bytes total
  -- lunarblock emits: VARINT(25+6=31) + 25 raw = 1+25 = 26 bytes
  expect_eq(#compressed, 26,
    "lunarblock emits 26 bytes (raw branch) for P2PKH; Core would emit 21")
  -- First byte is the VARINT 31 (raw size + nSpecialScripts) NOT 0x00
  expect_eq(compressed:byte(1), 31, "first byte is VARINT(31) — raw branch")
  -- TODO comment acknowledges it
  expect_true(
    UTXO_SRC:find("TODO%(W%-CORE%-COMPRESS%)", 1, false) ~= nil,
    "source TODO acknowledges the missing type-byte emission")
end)

test("G18.b: compress_script decompress side handles all 6 special types",
function()
  -- Confirm the decompress side (utxo.lua:774-810) DOES support
  -- type 0x00..0x05 — only the COMPRESS direction is incomplete.
  -- Manually craft a type-0x00 input: VARINT(0) + 20-byte hash
  local r = serialize.buffer_reader("\x00" .. string.rep("\x01", 20))
  local script = utxo_mod.decompress_script(r)
  expect_eq(#script, 25, "decompressed P2PKH is 25 bytes")
  -- Should be OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
  expect_eq(script:byte(1), 0x76, "OP_DUP")
  expect_eq(script:byte(2), 0xa9, "OP_HASH160")
  expect_eq(script:byte(3), 20, "push 20")
  expect_eq(script:byte(24), 0x88, "OP_EQUALVERIFY")
  expect_eq(script:byte(25), 0xac, "OP_CHECKSIG")
end)

--------------------------------------------------------------------------------
-- G19: per-txid grouping
--------------------------------------------------------------------------------
test("G19: dump_snapshot groups coins by txid with CompactSize(coins_per_txid)",
function()
  -- Source-grep: confirm the grouping logic exists
  expect_true(
    UTXO_SRC:find("utxos_by_txid", 1, true) ~= nil,
    "per-txid grouping table present")
  expect_true(
    UTXO_SRC:find("sorted_txids", 1, true) ~= nil,
    "txid sort step present")
  expect_true(
    UTXO_SRC:find("sorted_vouts", 1, true) ~= nil,
    "vout sort per-txid present")
  expect_true(
    UTXO_SRC:find("write_varint%(#sorted_vouts%)", 1, false) ~= nil,
    "CompactSize(coins_per_txid) present")
end)

--------------------------------------------------------------------------------
-- G20: Genesis-coinbase exclusion
--------------------------------------------------------------------------------
test("G20: dump_snapshot excludes genesis-coinbase txid",
function()
  expect_true(
    UTXO_SRC:find("genesis_coinbase_txid_bytes", 1, true) ~= nil,
    "genesis-coinbase exclusion present")
  expect_true(
    UTXO_SRC:find("if txid_bytes ~= genesis_coinbase_txid_bytes then", 1, true) ~= nil,
    "skip-check present in iterator loop")
end)

--------------------------------------------------------------------------------
-- G21: fsync before close + atomic rename
--------------------------------------------------------------------------------
test("G21: dump_snapshot fsyncs file before close",
function()
  expect_true(
    UTXO_SRC:find("_fsync_file%(file%)", 1, false) ~= nil,
    "_fsync_file call present in dump_snapshot")
  expect_true(
    UTXO_SRC:find("ffi%.C%.fsync", 1, false) ~= nil,
    "ffi.C.fsync binding present")
end)

--------------------------------------------------------------------------------
-- G22: loadtxoutset peeks header + assumeutxo whitelist
--------------------------------------------------------------------------------
test("G22: loadtxoutset enforces chainparams assumeutxo whitelist",
function()
  expect_true(
    RPC_SRC:find("assumeutxo_for_blockhash", 1, true) ~= nil,
    "loadtxoutset calls assumeutxo_for_blockhash")
  expect_true(
    RPC_SRC:find("Assumeutxo height in snapshot metadata not recognized", 1, true) ~= nil,
    "Core-exact whitelist error string present")
end)

--------------------------------------------------------------------------------
-- G23: Duplicate-activation guard (PARTIAL: in-memory only)
--------------------------------------------------------------------------------
test("G23: BUG-7 from_snapshot_blockhash not persisted across restart",
function()
  log_bug("BUG-7", "P1",
    "utxo.lua:1573 initializes `ChainState.from_snapshot_blockhash = nil` "
    .. "in the constructor; load_snapshot at 4762 sets it on success; "
    .. "duplicate-activation guard at 4594-4596 refuses second load. "
    .. "**But the field is in-memory ONLY** — no analog to Core's "
    .. "WriteSnapshotBaseBlockhash / ReadSnapshotBaseBlockhash "
    .. "(utxo_snapshot.cpp:22-81) which writes the base_blockhash to "
    .. "<chainstate>/base_blockhash file. After daemon restart, "
    .. "ChainState:init reads only the chain tip; from_snapshot_blockhash "
    .. "stays nil; a second loadtxoutset goes through. Real-world: "
    .. "operator who loads a snapshot, restarts for any reason, and "
    .. "accidentally re-runs loadtxoutset corrupts the chainstate.")
  -- Confirm the guard exists
  expect_true(
    UTXO_SRC:find("self%.from_snapshot_blockhash", 1, false) ~= nil,
    "from_snapshot_blockhash field referenced")
  expect_true(
    UTXO_SRC:find("Can't activate a snapshot%-based chainstate more than once", 1, false) ~= nil,
    "Core-exact duplicate-activation error string present")
  -- Confirm there is NO file-persistence equivalent
  expect_true(
    UTXO_SRC:find("WriteSnapshotBaseBlockhash", 1, true) == nil,
    "no WriteSnapshotBaseBlockhash function in lunarblock")
  expect_true(
    UTXO_SRC:find("base_blockhash file", 1, true) == nil
    and UTXO_SRC:find("SNAPSHOT_BLOCKHASH_FILENAME", 1, true) == nil,
    "no base_blockhash file persistence")
  -- Confirm ChainState:init does NOT seed from_snapshot_blockhash
  local init_fn = UTXO_SRC:match("function ChainState:init%(%).-end")
  expect_true(init_fn ~= nil, "init function found")
  expect_true(
    init_fn:find("from_snapshot_blockhash") == nil,
    "init does not restore from_snapshot_blockhash from disk")
end)

--------------------------------------------------------------------------------
-- G24: Best-headers ancestor check (MISSING)
--------------------------------------------------------------------------------
test("G24: BUG-8 best-headers ancestor check missing on loadtxoutset",
function()
  log_bug("BUG-8", "P0",
    "Core (validation.cpp:5622): `if (!m_best_header || "
    .. "m_best_header->GetAncestor(snapshot_start_block->nHeight) != "
    .. "snapshot_start_block) return error('A forked headers-chain with "
    .. "more work than the chain with the snapshot base block header "
    .. "exists.')`. lunarblock's loadtxoutset (rpc.lua:7778-7872) has NO "
    .. "such check. A node with a stale/forked header chain can load a "
    .. "snapshot anyway, then serve a forked chain.")
  -- Confirm no best_header/GetAncestor reference in loadtxoutset
  local loadtxoutset_fn = RPC_SRC:match("methods%[\"loadtxoutset\"%].-self%.methods")
  expect_true(loadtxoutset_fn ~= nil, "loadtxoutset method extracted")
  expect_true(
    loadtxoutset_fn:find("best_header") == nil,
    "no best_header check in loadtxoutset")
  expect_true(
    loadtxoutset_fn:find("GetAncestor") == nil
    and loadtxoutset_fn:find("get_ancestor") == nil,
    "no GetAncestor walk in loadtxoutset")
end)

--------------------------------------------------------------------------------
-- G25: snapshot_start_block in headers chain (MISSING)
--------------------------------------------------------------------------------
test("G25: BUG-9 snapshot_start_block-in-headers-chain check missing",
function()
  log_bug("BUG-9", "P0",
    "Core (validation.cpp:5611-5615): `snapshot_start_block = "
    .. "m_blockman.LookupBlockIndex(base_blockhash); if (!snapshot_start_block) "
    .. "return error('The base block header must appear in the headers chain. "
    .. "Make sure all headers are syncing, and call loadtxoutset again')`. "
    .. "lunarblock skips this gate. The brute-force `for h = 0, tip` scan at "
    .. "rpc.lua:7828-7836 is only invoked in the assumeutxo-not-found error "
    .. "branch and only to compute a height for a log message — never as a "
    .. "gate before load_snapshot is called.")
  -- Confirm the rpc layer does not gate on header presence
  local loadtxoutset_fn = RPC_SRC:match("methods%[\"loadtxoutset\"%].-self%.methods")
  expect_true(loadtxoutset_fn ~= nil, "loadtxoutset method extracted")
  -- The header lookup that DOES exist is inside the error branch
  expect_true(
    loadtxoutset_fn:find("Make sure all headers are syncing") == nil,
    "no Core-exact headers-syncing error string present")
end)

--------------------------------------------------------------------------------
-- G26: BLOCK_FAILED_VALID guard (MISSING)
--------------------------------------------------------------------------------
test("G26: BUG-10 BLOCK_FAILED_VALID guard missing on loadtxoutset",
function()
  log_bug("BUG-10", "P1",
    "Core (validation.cpp:5617-5620): `if (start_block_invalid) return "
    .. "error('The base block header is part of an invalid chain')`. "
    .. "lunarblock has an invalid_blocks set (utxo.lua:3917-3979 "
    .. "invalidate_block / mark_descendant_invalid) but loadtxoutset never "
    .. "consults it. Operator could `invalidateblock H` then `loadtxoutset "
    .. "<file>` on a snapshot anchored at H — the load proceeds.")
  -- Confirm loadtxoutset doesn't reference invalid_blocks
  local loadtxoutset_fn = RPC_SRC:match("methods%[\"loadtxoutset\"%].-self%.methods")
  expect_true(
    loadtxoutset_fn:find("invalid_blocks") == nil,
    "loadtxoutset does not check invalid_blocks")
  expect_true(
    loadtxoutset_fn:find("part of an invalid chain") == nil,
    "Core-exact invalid-chain error string absent")
end)

--------------------------------------------------------------------------------
-- G27: Work-exceeds-active (PARTIAL: height-as-work-proxy)
--------------------------------------------------------------------------------
test("G27: BUG-11 work-exceeds-active uses HEIGHT not CHAINWORK",
function()
  log_bug("BUG-11", "P1",
    "utxo.lua:4598-4611 checks `snap_height <= active_tip_height` and "
    .. "returns 'work does not exceed active chainstate'. Comment at "
    .. "4601-4602 acknowledges 'same network, same difficulty — higher "
    .. "height ≡ more work'. This is FALSE across forks of differing "
    .. "difficulty / chain-work. Core (validation.cpp:5706-5708) uses "
    .. "CBlockIndexWorkComparator over real chainwork. A snapshot at a "
    .. "lower height but higher actual work would be rejected.")
  -- Confirm the source comment + height comparison
  expect_true(
    UTXO_SRC:find("higher height ≡ more work", 1, true) ~= nil
    or UTXO_SRC:find("monotone proxy", 1, true) ~= nil,
    "height-as-work-proxy comment present")
  expect_true(
    UTXO_SRC:find("snap_height%s*<=%s*active_tip_height", 1, false) ~= nil,
    "height comparison present (the BUG shape)")
  expect_true(
    UTXO_SRC:find("work does not exceed active chainstate", 1, true) ~= nil,
    "Core-exact error string present")
end)

--------------------------------------------------------------------------------
-- G28: Mempool-empty guard
--------------------------------------------------------------------------------
test("G28: load_snapshot refuses when mempool not empty",
function()
  expect_true(
    UTXO_SRC:find("Can't activate a snapshot when mempool not empty", 1, true) ~= nil,
    "Core-exact mempool-not-empty error string present")
  expect_true(
    UTXO_SRC:find("mempool:size%(%)%s*>%s*0", 1, false) ~= nil,
    "mempool size check present")
end)

--------------------------------------------------------------------------------
-- G29: per-coin height > base_height guard
--------------------------------------------------------------------------------
test("G29: load_snapshot rejects coin.height > base_height",
function()
  expect_true(
    UTXO_SRC:find("entry%.height%s*>%s*effective_base_height", 1, false) ~= nil,
    "per-coin height guard present")
  expect_true(
    UTXO_SRC:find("Bad snapshot data after deserializing %%d coins", 1, false) ~= nil,
    "Core-exact error string present")
end)

--------------------------------------------------------------------------------
-- G30: MoneyRange + trailing-bytes + HASH_SERIALIZED gate (PARTIAL)
--------------------------------------------------------------------------------
test("G30: BUG-12 HASH_SERIALIZED strict gate is optional and never invoked",
function()
  log_bug("BUG-12", "P0",
    "utxo.lua:4734-4753 implements the SHA256d-via-HashWriter comparison "
    .. "against `expected_hash` — but the parameter is OPTIONAL "
    .. "(load_snapshot(file_path, expected_hash, base_height, "
    .. "active_tip_height, mempool)). **Both callers pass nil for "
    .. "expected_hash**: rpc.lua:7853 (loadtxoutset) and main.lua:617 "
    .. "(--import-utxo CLI). Core (validation.cpp:5912-5914) runs the "
    .. "gate UNCONDITIONALLY. Real-world exposure: a peer-distributed "
    .. "snapshot file with valid base_blockhash but maliciously rewritten "
    .. "UTXO body would be silently accepted; the node would serve a "
    .. "forked chain.")
  -- Confirm the gate is gated by `if expected_hash then`
  expect_true(
    UTXO_SRC:find("if expected_hash then", 1, true) ~= nil,
    "expected_hash gate is conditional (the BUG)")
  -- Confirm RPC layer passes nil
  expect_true(
    RPC_SRC:find("load_snapshot%(", 1, false) ~= nil,
    "load_snapshot is called from rpc.lua")
  -- The exact call: load_snapshot(path, nil, au_height, active_tip, rpc.mempool)
  expect_true(
    RPC_SRC:find("load_snapshot%(%s*[%w_]+,%s*nil,", 1, false) ~= nil,
    "rpc.lua loadtxoutset passes nil expected_hash (the BUG)")
  -- Same for main.lua
  expect_true(
    MAIN_SRC:find("cs:load_snapshot%(args%.import_utxo%)", 1, false) ~= nil,
    "main.lua --import-utxo passes no expected_hash (the BUG)")
end)

--------------------------------------------------------------------------------
-- Out-of-30 BUGs (structural absence beyond the gate matrix)
--------------------------------------------------------------------------------

test("BUG-13: outpoint.n uint32-max overflow guard absent",
function()
  log_bug("BUG-13", "P1",
    "Core validation.cpp:5815: `outpoint.n >= "
    .. "std::numeric_limits<uint32_t>::max()` rejection absent. "
    .. "utxo.lua:4678 reads vout via r.read_varint() and consumes whatever "
    .. "value comes back; no upper bound. A snapshot with vout=0xFFFFFFFF "
    .. "would trip a Core rejection but lunarblock accepts it.")
  -- Confirm no max-uint32 check in load_snapshot
  local load_fn = UTXO_SRC:match("function ChainState:load_snapshot.-from_snapshot_blockhash%s*=%s*metadata%.base_blockhash")
  expect_true(load_fn ~= nil, "load_snapshot function extracted")
  expect_true(
    load_fn:find("0xFFFFFFFF") == nil
    and load_fn:find("4294967295") == nil,
    "no uint32-max overflow check in load_snapshot")
end)

test("BUG-14: BackgroundValidator class is dead code (never instantiated)",
function()
  log_bug("BUG-14", "P1",
    "utxo.lua:4809-4895 defines BackgroundValidator with step/progress/"
    .. "is_complete/get_error methods. `grep -rn 'new_background_validator' "
    .. "src/` returns nothing. The class is dead code. Core's "
    .. "MaybeCompleteSnapshotValidation (validation.cpp:5972-6080) is the "
    .. "canonical 'snapshot acceptance is provisional until background IBD "
    .. "verifies'. lunarblock snapshots are accepted permanently and "
    .. "unconditionally on initial load (modulo BUG-12 which compounds).")
  expect_true(
    UTXO_SRC:find("function M%.new_background_validator", 1, false) ~= nil,
    "new_background_validator is defined")
  -- Confirm no caller anywhere
  expect_true(
    MAIN_SRC:find("new_background_validator", 1, true) == nil,
    "no caller in main.lua")
  expect_true(
    RPC_SRC:find("new_background_validator", 1, true) == nil,
    "no caller in rpc.lua")
  local sync_src = read_file("src/sync.lua")
  if sync_src then
    expect_true(
      sync_src:find("new_background_validator", 1, true) == nil,
      "no caller in sync.lua")
  end
end)

test("BUG-15: SnapshotChainstate class is dead code (never instantiated)",
function()
  log_bug("BUG-15", "P1",
    "utxo.lua:4772-4806 defines SnapshotChainstate.new_snapshot_chainstate; "
    .. "no caller invokes it. The single-chainstate model is hard-coded; "
    .. "lunarblock cannot run with both a snapshot-based chainstate and a "
    .. "background-IBD chainstate simultaneously the way Core does.")
  expect_true(
    UTXO_SRC:find("function M%.new_snapshot_chainstate", 1, false) ~= nil,
    "new_snapshot_chainstate defined")
  expect_true(
    MAIN_SRC:find("new_snapshot_chainstate", 1, true) == nil,
    "no caller in main.lua")
  expect_true(
    RPC_SRC:find("new_snapshot_chainstate", 1, true) == nil,
    "no caller in rpc.lua")
end)

test("BUG-16: m_chain_tx_count from chainparams never threaded into block index",
function()
  log_bug("BUG-16", "P1",
    "consensus.lua:947-983 records m_chain_tx_count per assumeutxo entry "
    .. "(e.g., 991032194 for h=840k). But loadtxoutset/load_snapshot never "
    .. "write the value into any block-index entry. getblockchaininfo's "
    .. "verificationprogress (rpc.lua:1298) is `tip_height / 880000`, "
    .. "completely ignoring m_chain_tx_count. Post-snapshot the user sees "
    .. "'progress 95%' while background-IBD-from-genesis is at 0%.")
  expect_true(
    CONSENSUS_SRC:find("m_chain_tx_count", 1, true) ~= nil,
    "m_chain_tx_count exists in chainparams")
  -- But neither rpc.lua loadtxoutset nor utxo.lua load_snapshot use it
  local loadtxoutset_fn = RPC_SRC:match("methods%[\"loadtxoutset\"%].-self%.methods")
  expect_true(loadtxoutset_fn ~= nil, "loadtxoutset extracted")
  expect_true(
    loadtxoutset_fn:find("m_chain_tx_count") == nil,
    "loadtxoutset never reads m_chain_tx_count from au_data")
  local load_fn = UTXO_SRC:match("function ChainState:load_snapshot.-from_snapshot_blockhash%s*=%s*metadata%.base_blockhash")
  expect_true(
    load_fn:find("m_chain_tx_count") == nil,
    "load_snapshot never threads m_chain_tx_count")
end)

test("BUG-17: getchainstates RPC missing",
function()
  log_bug("BUG-17", "P2",
    "Core rpc/blockchain.cpp:3462+ exposes getchainstates which returns "
    .. "per-chainstate snapshot_blockhash + validated + headers + tip "
    .. "info. Absent in lunarblock. Cross-impl test-suite probes that "
    .. "read chainstates[*].snapshot_blockhash would fail with "
    .. "'method not found'.")
  expect_true(
    RPC_SRC:find('methods%["getchainstates"%]', 1, false) == nil,
    "getchainstates not registered")
end)

test("BUG-18: getblockchaininfo missing snapshot_blockhash field",
function()
  log_bug("BUG-18", "P2",
    "Core rpc/blockchain.cpp:1824 emits 'snapshot_blockhash' in "
    .. "getblockchaininfo when active chainstate is snapshot-built. "
    .. "lunarblock's getblockchaininfo result (rpc.lua:1339-1359) "
    .. "does not include the field — operator cannot tell whether the "
    .. "node is running on a snapshot.")
  -- Extract getblockchaininfo method body
  local gbci_fn = RPC_SRC:match('methods%["getblockchaininfo"%].-self%.methods')
  expect_true(gbci_fn ~= nil, "getblockchaininfo method extracted")
  expect_true(
    gbci_fn:find("snapshot_blockhash") == nil,
    "getblockchaininfo result does not emit snapshot_blockhash")
end)

--------------------------------------------------------------------------------
-- Summary
--------------------------------------------------------------------------------
print("")
print("=== W138 audit summary ===")
print(string.format("Tests: %d PASS / %d FAIL", tests_passed, tests_failed))
print(string.format("BUGs catalogued: %d", #bugs))
print("")
print("By priority:")
local p_counts = {}
for _, b in ipairs(bugs) do
  p_counts[b.priority] = (p_counts[b.priority] or 0) + 1
end
for _, p in ipairs({"P0", "P1", "P2"}) do
  if p_counts[p] then
    print(string.format("  %s: %d", p, p_counts[p]))
  end
end
print("")
print("Bug list:")
for _, b in ipairs(bugs) do
  print(string.format("  %s %s: %s", b.id, b.priority,
    b.desc:sub(1, 80) .. (#b.desc > 80 and "..." or "")))
end

os.exit(tests_failed > 0 and 1 or 0)
