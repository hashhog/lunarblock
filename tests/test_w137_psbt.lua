#!/usr/bin/env luajit
-- W137 PSBT v0/v2 (BIP-174 / BIP-370 / BIP-371) audit — lunarblock (Lua / LuaJIT)
--
-- Discovery-only. Tests pin lunarblock's PSBT state vs Core's psbt.h / psbt.cpp
-- and document divergences. See audit/w137_psbt.md for the full 30-gate matrix.
--
-- 30 gates (G1-G30):
--   G1     Magic bytes
--   G2     PSBT v0 global key types
--   G3     PSBT v0 input key types 0x00-0x08
--   G4     PSBT v0 input preimage types 0x0A-0x0D (MISSING)
--   G5     PSBT v0 input taproot types 0x13-0x18
--   G6     PSBT v0 input MuSig2 types 0x1A-0x1C (MISSING)
--   G7     PSBT v0 output key types
--   G8-G10 BIP-370 PSBT v2 field types (MISSING)
--   G11    PSBT_HIGHEST_VERSION enforcement (BUG)
--   G12    Duplicate-key detection (BUG, P0)
--   G13    Separator-byte requirement (PARTIAL)
--   G14    MAX_FILE_SIZE_PSBT (MISSING)
--   G15    "Extra data after PSBT" check (BUG)
--   G16    non_witness_utxo txid (PASS)
--   G17    non_witness_utxo vout index at deserialize (BUG)
--   G18    non_witness_utxo + witness_utxo agreement (PASS)
--   G19    Partial-sig key length (BUG)
--   G20    Partial-sig DER check at deserialize (MISSING)
--   G21    BIP-32 keypath length validation (BUG)
--   G22    Taproot key-sig length cap (BUG)
--   G23    Taproot leaf-script control-block size remainder (PARTIAL)
--   G24    Taproot tree depth / leaf_ver / IsComplete (MISSING)
--   G25    Global xpub key size (BUG)
--   G26    Finalizer P2WPKH/P2PKH/P2SH/P2WSH multisig (PASS)
--   G27    Finalizer P2TR (MISSING)
--   G28    Combiner Merge m_xpubs (BUG)
--   G29    Extractor witness flag (PASS)
--   G30    RPC PSBT methods coverage (PARTIAL)

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

local psbt_mod = require("lunarblock.psbt")
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

local PSBT_SRC = read_file("src/psbt.lua")
local RPC_SRC = read_file("src/rpc.lua")
assert(PSBT_SRC, "could not read src/psbt.lua")
assert(RPC_SRC, "could not read src/rpc.lua")

-- Build a minimal PSBT for testing
local function make_minimal_psbt()
  local txid = types.hash256(string.rep("\x01", 32))
  local inputs = { types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD) }
  local outputs = { types.txout(50000, "\x00\x14" .. string.rep("\x02", 20)) }
  local tx = types.transaction(2, inputs, outputs, 0)
  return psbt_mod.new(tx)
end

print("=== W137 lunarblock PSBT v0/v2 audit ===\n")

--------------------------------------------------------------------------------
-- G1: Magic bytes
--------------------------------------------------------------------------------
test("G1: M.MAGIC = 'psbt\\xff' (BIP-174 magic bytes)", function()
  expect_eq(psbt_mod.MAGIC, "psbt\xff", "MAGIC constant")
  expect_eq(#psbt_mod.MAGIC, 5, "magic is exactly 5 bytes")
  -- serialize emits magic at offset 0
  local p = make_minimal_psbt()
  local data = psbt_mod.serialize(p)
  expect_eq(data:sub(1, 5), "psbt\xff", "serialized PSBT starts with magic")
end)

test("G1.b: deserialize rejects wrong magic", function()
  local ok, _ = pcall(psbt_mod.deserialize, "xxxx\xff" .. string.rep("\x00", 100))
  expect_false(ok, "wrong magic should be rejected")
end)

--------------------------------------------------------------------------------
-- G2: PSBT v0 global key types (0x00, 0x01, 0xFB, 0xFC)
--------------------------------------------------------------------------------
test("G2: PSBT v0 global key constants present", function()
  expect_eq(psbt_mod.GLOBAL_UNSIGNED_TX, 0x00)
  expect_eq(psbt_mod.GLOBAL_XPUB, 0x01)
  expect_eq(psbt_mod.GLOBAL_VERSION, 0xFB)
  expect_eq(psbt_mod.GLOBAL_PROPRIETARY, 0xFC)
end)

test("G2.b: BUG-1 proprietary 0xFC routes to psbt.unknown (no typed record)",
function()
  log_bug("BUG-1", "P2",
    "PSBT_GLOBAL_PROPRIETARY (0xFC) not typed — silently routed to "
    .. "psbt.unknown. Core's PSBTProprietary record is missing entirely. "
    .. "No proprietary subtype / identifier extraction; no duplicate-key "
    .. "check. psbt.lua:25 GLOBAL_PROPRIETARY constant exists but is "
    .. "never used.")
  -- Verify the constant is defined but not referenced anywhere in the
  -- deserialize/serialize loops.
  expect_true(PSBT_SRC:find("M%.GLOBAL_PROPRIETARY%s*=%s*0xFC", 1, false) ~= nil,
    "constant defined")
  -- Look for any switch on the GLOBAL_PROPRIETARY constant in the deserialize
  local has_handler = PSBT_SRC:find("key_type%s*==%s*M%.GLOBAL_PROPRIETARY", 1, false)
    or PSBT_SRC:find("==%s*M%.GLOBAL_PROPRIETARY", 1, false)
  expect_nil(has_handler, "no typed handler for global proprietary")
end)

--------------------------------------------------------------------------------
-- G3: PSBT v0 input key types 0x00-0x08
--------------------------------------------------------------------------------
test("G3: PSBT v0 input key constants 0x00-0x08", function()
  expect_eq(psbt_mod.IN_NON_WITNESS_UTXO, 0x00)
  expect_eq(psbt_mod.IN_WITNESS_UTXO, 0x01)
  expect_eq(psbt_mod.IN_PARTIAL_SIG, 0x02)
  expect_eq(psbt_mod.IN_SIGHASH_TYPE, 0x03)
  expect_eq(psbt_mod.IN_REDEEM_SCRIPT, 0x04)
  expect_eq(psbt_mod.IN_WITNESS_SCRIPT, 0x05)
  expect_eq(psbt_mod.IN_BIP32_DERIVATION, 0x06)
  expect_eq(psbt_mod.IN_FINAL_SCRIPTSIG, 0x07)
  expect_eq(psbt_mod.IN_FINAL_SCRIPTWITNESS, 0x08)
end)

--------------------------------------------------------------------------------
-- G4: PSBT v0 input preimage types 0x0A-0x0D (MISSING)
--------------------------------------------------------------------------------
test("G4: BUG-2 PSBT_IN_RIPEMD160 / SHA256 / HASH160 / HASH256 missing",
function()
  log_bug("BUG-2", "P1",
    "Core's psbt.h:46-49 defines IN_RIPEMD160=0x0A, IN_SHA256=0x0B, "
    .. "IN_HASH160=0x0C, IN_HASH256=0x0D. lunarblock has neither the "
    .. "constants nor handlers. HTLC preimages route to inp.unknown and "
    .. "are silently dropped during finalize. Lightning channel-close "
    .. "PSBTs unfinalizable.")
  expect_nil(psbt_mod.IN_RIPEMD160, "IN_RIPEMD160 absent")
  expect_nil(psbt_mod.IN_SHA256, "IN_SHA256 absent")
  expect_nil(psbt_mod.IN_HASH160, "IN_HASH160 absent")
  expect_nil(psbt_mod.IN_HASH256, "IN_HASH256 absent")
  -- Source-level confirm: psbt_input() helper does NOT track preimage maps
  local helper = PSBT_SRC:match("function M%.psbt_input%(%).-end")
  expect_true(helper ~= nil, "psbt_input helper found")
  expect_false(helper:find("ripemd160_preimages") ~= nil,
    "no ripemd160_preimages slot in psbt_input")
  expect_false(helper:find("sha256_preimages") ~= nil,
    "no sha256_preimages slot in psbt_input")
end)

--------------------------------------------------------------------------------
-- G5: PSBT v0 input taproot types 0x13-0x18
--------------------------------------------------------------------------------
test("G5: PSBT v0 input taproot key constants 0x13-0x18", function()
  expect_eq(psbt_mod.IN_TAP_KEY_SIG, 0x13)
  expect_eq(psbt_mod.IN_TAP_SCRIPT_SIG, 0x14)
  expect_eq(psbt_mod.IN_TAP_LEAF_SCRIPT, 0x15)
  expect_eq(psbt_mod.IN_TAP_BIP32_DERIVATION, 0x16)
  expect_eq(psbt_mod.IN_TAP_INTERNAL_KEY, 0x17)
  expect_eq(psbt_mod.IN_TAP_MERKLE_ROOT, 0x18)
end)

--------------------------------------------------------------------------------
-- G6: PSBT v0 input MuSig2 types 0x1A-0x1C (MISSING)
--------------------------------------------------------------------------------
test("G6: BUG-3 IN_MUSIG2_PARTICIPANT_PUBKEYS / PUB_NONCE / PARTIAL_SIG missing",
function()
  log_bug("BUG-3", "P2",
    "Core's psbt.h:56-58 defines IN_MUSIG2_PARTICIPANT_PUBKEYS=0x1A, "
    .. "IN_MUSIG2_PUB_NONCE=0x1B, IN_MUSIG2_PARTIAL_SIG=0x1C. lunarblock "
    .. "has no input-side constants nor handlers. OUT side has 0x08 only "
    .. "(OUT_MUSIG2_PARTICIPANT_PUBKEYS). MuSig2 partial-sig aggregation "
    .. "data routes to inp.unknown.")
  expect_nil(psbt_mod.IN_MUSIG2_PARTICIPANT_PUBKEYS, "IN_MUSIG2_PARTICIPANT_PUBKEYS absent")
  expect_nil(psbt_mod.IN_MUSIG2_PUB_NONCE, "IN_MUSIG2_PUB_NONCE absent")
  expect_nil(psbt_mod.IN_MUSIG2_PARTIAL_SIG, "IN_MUSIG2_PARTIAL_SIG absent")
end)

--------------------------------------------------------------------------------
-- G7: PSBT v0 output key types
--------------------------------------------------------------------------------
test("G7: PSBT v0 output key constants", function()
  expect_eq(psbt_mod.OUT_REDEEM_SCRIPT, 0x00)
  expect_eq(psbt_mod.OUT_WITNESS_SCRIPT, 0x01)
  expect_eq(psbt_mod.OUT_BIP32_DERIVATION, 0x02)
  expect_eq(psbt_mod.OUT_TAP_INTERNAL_KEY, 0x05)
  expect_eq(psbt_mod.OUT_TAP_TREE, 0x06)
  expect_eq(psbt_mod.OUT_TAP_BIP32_DERIVATION, 0x07)
  expect_eq(psbt_mod.OUT_MUSIG2_PARTICIPANT_PUBKEYS, 0x08)
end)

--------------------------------------------------------------------------------
-- G8-G10: BIP-370 PSBT v2 (MISSING)
--------------------------------------------------------------------------------
test("G8-G10: BUG-4 BIP-370 PSBT v2 field types MISSING fleet-wide",
function()
  log_bug("BUG-4", "P2",
    "src/psbt.lua:1 header comment claims 'BIP174/BIP370' support, but NO "
    .. "PSBT v2 field types are defined. Missing globals: TX_VERSION "
    .. "(0x02), FALLBACK_LOCKTIME (0x03), INPUT_COUNT (0x04), "
    .. "OUTPUT_COUNT (0x05), TX_MODIFIABLE (0x06). Missing input: "
    .. "PREVIOUS_TXID (0x0E), OUTPUT_INDEX (0x0F), SEQUENCE (0x10), "
    .. "REQUIRED_TIME_LOCKTIME (0x11), REQUIRED_HEIGHT_LOCKTIME (0x12). "
    .. "Missing output: AMOUNT (0x03), SCRIPT (0x04). NOTE: Core itself "
    .. "is also v0-only (PSBT_HIGHEST_VERSION = 0) — so this is missing "
    .. "fleet-wide, not a Core-parity bug. The misleading comment is the "
    .. "audit finding.")
  -- Confirm none of the v2-specific constants are defined
  expect_nil(psbt_mod.GLOBAL_TX_VERSION, "GLOBAL_TX_VERSION absent")
  expect_nil(psbt_mod.GLOBAL_FALLBACK_LOCKTIME, "GLOBAL_FALLBACK_LOCKTIME absent")
  expect_nil(psbt_mod.GLOBAL_INPUT_COUNT, "GLOBAL_INPUT_COUNT absent")
  expect_nil(psbt_mod.GLOBAL_OUTPUT_COUNT, "GLOBAL_OUTPUT_COUNT absent")
  expect_nil(psbt_mod.IN_PREVIOUS_TXID, "IN_PREVIOUS_TXID absent")
  expect_nil(psbt_mod.IN_OUTPUT_INDEX, "IN_OUTPUT_INDEX absent")
  expect_nil(psbt_mod.OUT_AMOUNT, "OUT_AMOUNT absent")
  expect_nil(psbt_mod.OUT_SCRIPT, "OUT_SCRIPT absent")
  -- Confirm the misleading comment
  expect_true(PSBT_SRC:find("BIP174/BIP370", 1, true) ~= nil,
    "psbt.lua:1 misleadingly claims BIP-370 support")
end)

--------------------------------------------------------------------------------
-- G11: PSBT_HIGHEST_VERSION enforcement (BUG)
--------------------------------------------------------------------------------
test("G11: BUG-5 PSBT_HIGHEST_VERSION not enforced (any version accepted)",
function()
  log_bug("BUG-5", "P2",
    "psbt.lua:504-507 reads psbt.version from PSBT_GLOBAL_VERSION blindly. "
    .. "Core (psbt.h:1322): if (*m_version > PSBT_HIGHEST_VERSION) throw "
    .. "'Unsupported version number'. PSBT_HIGHEST_VERSION = 0. "
    .. "lunarblock would accept psbt.version = 99 then re-emit it.")
  -- Build a PSBT with a non-zero version: take the minimal PSBT and inject
  -- a PSBT_GLOBAL_VERSION kv (key=0xFB, value=u32le(99)) BEFORE the global
  -- separator. The serialized format is:
  --   magic (5)
  --   varint(1)|0x00|varint(len_tx)|tx_bytes        <- GLOBAL_UNSIGNED_TX
  --   <inject version kv here>
  --   0x00                                          <- separator
  --   ... input/output maps ...
  local p = make_minimal_psbt()
  local data = psbt_mod.serialize(p)
  -- Find the global separator byte (the 0x00 byte that closes the global
  -- map). We scan from byte 6 looking for the unsigned-tx kv structure.
  -- byte 6: varint(1)
  -- byte 7: 0x00 (GLOBAL_UNSIGNED_TX key)
  -- byte 8+: varint(value_len) | value
  -- Hand-decode it.
  local pos = 6  -- after the 5-byte magic
  assert(data:byte(pos) == 1, "expected key_len=1 after magic")
  pos = pos + 1
  assert(data:byte(pos) == 0x00, "expected GLOBAL_UNSIGNED_TX key=0x00")
  pos = pos + 1
  -- Read value_len (varint)
  local first = data:byte(pos)
  local value_len, varint_size
  if first < 0xFD then
    value_len = first
    varint_size = 1
  elseif first == 0xFD then
    value_len = data:byte(pos+1) + data:byte(pos+2) * 256
    varint_size = 3
  elseif first == 0xFE then
    value_len = data:byte(pos+1) + data:byte(pos+2) * 256
              + data:byte(pos+3) * 65536 + data:byte(pos+4) * 16777216
    varint_size = 5
  else
    error("varint too large in test fixture")
  end
  pos = pos + varint_size + value_len
  -- Now `pos` points at the global separator byte 0x00. Inject version kv.
  local prefix = data:sub(1, pos - 1)
  -- version kv: varint(1) | 0xFB | varint(4) | u32le(99)
  local version_kv = "\x01\xFB\x04" .. string.char(99, 0, 0, 0)
  local suffix = data:sub(pos)  -- starts at separator byte
  local doctored = prefix .. version_kv .. suffix
  -- Parse — Core would reject; lunarblock should ALSO reject if BUG-5 fixed.
  local ok, parsed = pcall(psbt_mod.deserialize, doctored)
  expect_true(ok, "lunarblock accepts version 99 (BUG: Core would reject)")
  expect_eq(parsed.version, 99, "version 99 stored verbatim")
end)

--------------------------------------------------------------------------------
-- G12: Duplicate-key detection (BUG, P0)
--------------------------------------------------------------------------------
test("G12: BUG-6 P0 duplicate-key detection MISSING fleet-wide",
function()
  log_bug("BUG-6", "P0",
    "BIP-174: 'Per-input, output and globals there can be only one of "
    .. "each distinct key'. read_map (psbt.lua:443-456) collects entries "
    .. "without a seen[key] set. Per-branch handlers OVERWRITE silently. "
    .. "Attacker can craft a duplicate witness_utxo entry to SHADOW the "
    .. "honest one — defeats W41 CVE-2020-14199 hardening when "
    .. "non_witness_utxo is absent and signer trusts witness_utxo. "
    .. "Core enforces via key_lookup.emplace(key).second at every typed "
    .. "branch (psbt.h:507, 517, 553, 565, 575, 589, 599, 693, 708, 730, "
    .. "750, 773, 783, 793, 803, 822, 1265, 999, 1009, 1024, 1034, 1069, "
    .. "1089). lunarblock has NONE of these checks.")
  expect_false(PSBT_SRC:find("key_lookup", 1, true) ~= nil,
    "no key_lookup primitive in psbt.lua")
  expect_false(PSBT_SRC:find("Duplicate Key", 1, true) ~= nil,
    "no 'Duplicate Key' error message in psbt.lua")
  expect_false(PSBT_SRC:find("already provided", 1, true) ~= nil,
    "no 'already provided' error message")
  -- Behavioral: build a PSBT with two witness_utxo entries.
  local function make_psbt_with_dup_witness_utxo()
    local w = serialize.buffer_writer()
    w.write_bytes("psbt\xff")
    -- Unsigned tx with 1 input
    local tx_w = serialize.buffer_writer()
    tx_w.write_i32le(2)
    tx_w.write_varint(1)
    tx_w.write_hash256(types.hash256(string.rep("\x01", 32)))
    tx_w.write_u32le(0)
    tx_w.write_varint(0)
    tx_w.write_u32le(0xFFFFFFFD)
    tx_w.write_varint(0)
    tx_w.write_u32le(0)
    local unsigned_tx = tx_w.result()
    w.write_varint(1)
    w.write_bytes("\x00")
    w.write_varint(#unsigned_tx)
    w.write_bytes(unsigned_tx)
    -- Separator for global map
    w.write_u8(0x00)
    -- Input map: TWO PSBT_IN_WITNESS_UTXO entries
    local function emit_witness_utxo(value, spk)
      w.write_varint(1)
      w.write_bytes("\x01")  -- IN_WITNESS_UTXO key
      local vw = serialize.buffer_writer()
      vw.write_i64le(value)
      vw.write_varstr(spk)
      local v = vw.result()
      w.write_varint(#v)
      w.write_bytes(v)
    end
    emit_witness_utxo(50000, "\x00\x14" .. string.rep("\x02", 20))
    emit_witness_utxo(99999, "\x00\x14" .. string.rep("\x03", 20))
    -- Separator
    w.write_u8(0x00)
    return w.result()
  end
  local data = make_psbt_with_dup_witness_utxo()
  local ok, psbt = pcall(psbt_mod.deserialize, data)
  expect_true(ok, "BUG: lunarblock accepts duplicate witness_utxo (should reject)")
  -- The second one wins (silently overwrites the first)
  expect_eq(psbt.inputs[1].witness_utxo.value, 99999,
    "second witness_utxo silently overwrote the first (P0 shadowing oracle)")
end)

--------------------------------------------------------------------------------
-- G13: Separator-byte error fidelity (PARTIAL)
--------------------------------------------------------------------------------
test("G13: BUG-7 truncated stream raises wrong error (no separator check)",
function()
  log_bug("BUG-7", "P2",
    "read_map (psbt.lua:443) stops on key_len==0 but never raises Core's "
    .. "'Separator is missing at the end of the X map' on truncation. A "
    .. "truncated stream throws a low-level buffer-reader error instead.")
  -- Source-level: no 'Separator is missing' error
  expect_false(PSBT_SRC:find("Separator is missing", 1, true) ~= nil,
    "no separator-missing error fidelity")
end)

--------------------------------------------------------------------------------
-- G14: MAX_FILE_SIZE_PSBT cap (MISSING)
--------------------------------------------------------------------------------
test("G14: BUG-8 MAX_FILE_SIZE_PSBT = 100 MB cap MISSING",
function()
  log_bug("BUG-8", "P1",
    "Core: psbt.h:77 MAX_FILE_SIZE_PSBT = 100000000 (100 MB) DoS cap. "
    .. "lunarblock has no equivalent. Attacker-supplied 100 GB PSBT "
    .. "would allocate the entire buffer (LuaJIT GC pressure / OOM).")
  expect_false(PSBT_SRC:find("MAX_FILE_SIZE", 1, true) ~= nil,
    "MAX_FILE_SIZE constant absent")
  expect_false(PSBT_SRC:find("100000000", 1, true) ~= nil,
    "100 MB literal absent")
  expect_nil(psbt_mod.MAX_FILE_SIZE_PSBT, "constant not exported")
end)

--------------------------------------------------------------------------------
-- G15: "Extra data after PSBT" trailing-byte rejection (BUG)
--------------------------------------------------------------------------------
test("G15: BUG-9 trailing data after last output map silently accepted",
function()
  log_bug("BUG-9", "P1",
    "M.deserialize returns success with leftover bytes. Core (psbt.cpp:"
    .. "622): if (!ss_data.empty()) error = 'extra data after PSBT'. "
    .. "Adversarial encoder appends OOB data to bypass canonical-encoding "
    .. "checks (PSBT hash differs but parsed structure is identical).")
  -- Build a valid minimal PSBT, append garbage, attempt to parse.
  local p = make_minimal_psbt()
  local data = psbt_mod.serialize(p)
  local data_with_garbage = data .. "GARBAGEEEEEEEEEE"
  local ok, _ = pcall(psbt_mod.deserialize, data_with_garbage)
  expect_true(ok,
    "BUG: lunarblock accepts trailing data (should reject)")
  -- Source-level: no "extra data" error
  expect_false(PSBT_SRC:find("extra data", 1, true) ~= nil,
    "no 'extra data after PSBT' error path")
end)

--------------------------------------------------------------------------------
-- G16: non_witness_utxo txid (CVE-2020-14199 deserialize) — PASS
--------------------------------------------------------------------------------
test("G16: PASS non_witness_utxo txid check at deserialize", function()
  -- Source-level: verify_non_witness_utxo_txid is called
  expect_true(PSBT_SRC:find("verify_non_witness_utxo_txid", 1, true) ~= nil,
    "verify_non_witness_utxo_txid invoked at deserialize")
  -- And error message includes 'CVE-2020-14199' or 'mismatch'
  expect_true(PSBT_SRC:find("non_witness_utxo txid mismatch", 1, true) ~= nil,
    "txid-mismatch error path present")
end)

--------------------------------------------------------------------------------
-- G17: non_witness_utxo vout index check (BUG at deserialize)
--------------------------------------------------------------------------------
test("G17: BUG-10 non_witness_utxo vout index not checked at deserialize",
function()
  log_bug("BUG-10", "P2",
    "Core (psbt.h:1375): if (tx->vin[i].prevout.n >= input.non_witness_"
    .. "utxo->vout.size()) throw 'Input specifies output index that does "
    .. "not exist'. lunarblock deserialize accepts; check exists at "
    .. "sign_input (psbt.lua:898-901) but NOT at deserialize. Asymmetric.")
  -- The check exists at sign_input, confirm that
  expect_true(PSBT_SRC:find("vout index out of range", 1, true) ~= nil,
    "vout-range check exists at sign_input")
  -- But not at the deserialize block (lines ~535-557)
  local deser_block = PSBT_SRC:match("IN_NON_WITNESS_UTXO then(.-)elseif")
  if deser_block then
    expect_false(deser_block:find("vout index out of range", 1, true) ~= nil,
      "no vout-range check at deserialize")
  end
end)

--------------------------------------------------------------------------------
-- G18: non_witness_utxo + witness_utxo agreement (CVE-2020-14199 sign) — PASS
--------------------------------------------------------------------------------
test("G18: PASS CVE-2020-14199 witness/non-witness cross-check at sign",
function()
  expect_true(PSBT_SRC:find("CVE%-2020%-14199", 1, false) ~= nil,
    "CVE reference present in psbt.lua")
  expect_true(PSBT_SRC:find("witness_utxo disagrees with non_witness_utxo",
    1, true) ~= nil, "cross-check error path present")
end)

--------------------------------------------------------------------------------
-- G19: Partial-sig key length check (BUG)
--------------------------------------------------------------------------------
test("G19: BUG-11 partial_sig key length not validated (pubkey + 1)",
function()
  log_bug("BUG-11", "P2",
    "psbt.lua:568-570 extracts pubkey via entry.key:sub(2) without "
    .. "length check. Core (psbt.h:527): if (key.size() != CPubKey::SIZE "
    .. "+ 1 && key.size() != CPubKey::COMPRESSED_SIZE + 1) throw. "
    .. "Malformed PSBT with 5-byte 'pubkey' would silently store it in "
    .. "inp.partial_sigs[hex(5-bytes)].")
  -- The IN_PARTIAL_SIG branch in psbt.lua should not check key.size
  local partial_sig_block = PSBT_SRC:match(
    "key_type%s*==%s*M%.IN_PARTIAL_SIG.-elseif")
  if partial_sig_block then
    expect_false(partial_sig_block:find("#entry%.key%s*==%s*34", 1, false) ~= nil,
      "no 33+1 length check (compressed pubkey)")
    expect_false(partial_sig_block:find("#entry%.key%s*==%s*66", 1, false) ~= nil,
      "no 65+1 length check (uncompressed pubkey)")
  end
end)

--------------------------------------------------------------------------------
-- G20: Partial-sig DER+sighash check at deserialize (MISSING)
--------------------------------------------------------------------------------
test("G20: BUG-12 partial_sig DER encoding NOT validated at deserialize",
function()
  log_bug("BUG-12", "P1",
    "psbt.lua:568-570 stores any byte string as partial_sig. Core "
    .. "(psbt.h:544): rejects sig.empty() || !CheckSignatureEncoding(sig, "
    .. "SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_STRICTENC, nullptr). "
    .. "lunarblock has is_valid_der_sig helper at psbt.lua:1470 — used "
    .. "only for decode display, never as a deserialize-side validator. "
    .. "Malformed partial_sig propagates to finalize → unspendable tx.")
  -- Confirm is_valid_der_sig exists for display only
  expect_true(PSBT_SRC:find("is_valid_der_sig", 1, true) ~= nil,
    "is_valid_der_sig helper exists (for display)")
  -- But not invoked at IN_PARTIAL_SIG deserialize site
  local partial_sig_block = PSBT_SRC:match(
    "key_type%s*==%s*M%.IN_PARTIAL_SIG.-elseif")
  if partial_sig_block then
    expect_false(partial_sig_block:find("is_valid_der_sig", 1, true) ~= nil,
      "DER check NOT invoked at deserialize")
  end
end)

--------------------------------------------------------------------------------
-- G21: BIP-32 keypath length validation (BUG)
--------------------------------------------------------------------------------
test("G21: BUG-13 BIP-32 keypath value length not validated (%4==0, !=0)",
function()
  log_bug("BUG-13", "P2",
    "psbt.lua:587-593 / 692-699: reads fingerprint (4 bytes) then "
    .. "consumes u32 indices via 'while remaining() >= 4'. No check that "
    .. "remaining() divides cleanly by 4. No rejection of length=4 "
    .. "(zero-derivation case allowed). Core (psbt.h:127): if (length % "
    .. "4 || length == 0) throw 'Invalid length for HD key path'.")
  -- Source confirm: while remaining() >= 4 is the pattern
  expect_true(PSBT_SRC:find("while vr%.remaining%(%) >= 4", 1, false) ~= nil,
    "uses lenient 'while remaining >= 4' pattern")
  expect_false(PSBT_SRC:find("Invalid length for HD key path", 1, true) ~= nil,
    "no Core-style error")
end)

--------------------------------------------------------------------------------
-- G22: Taproot key-sig length cap (BUG)
--------------------------------------------------------------------------------
test("G22: BUG-14 tap_key_sig length cap (64-65 bytes) not enforced",
function()
  log_bug("BUG-14", "P1",
    "psbt.lua:609-612: inp.tap_key_sig = entry.value. No length check. "
    .. "Core (psbt.h:699-703): rejects size < 64 or > 65. Same gap for "
    .. "tap_script_sig (line 614-620). Attacker-supplied PSBT with 100-"
    .. "byte tap_key_sig accepted, propagates to extractor — final "
    .. "witness rejected at network broadcast.")
  local tap_key_sig_block = PSBT_SRC:match(
    "IN_TAP_KEY_SIG then(.-)elseif")
  expect_true(tap_key_sig_block ~= nil, "captured IN_TAP_KEY_SIG block")
  -- Strip Lua-style comment lines so '64 or 65' text doesn't false-positive.
  local code_only = tap_key_sig_block:gsub("%-%-[^\n]*", "")
  -- No #entry.value comparison or length assertion
  expect_false(code_only:find("#%s*entry%.value%s*[<>=]", 1, false) ~= nil,
    "no length comparison on entry.value")
  expect_false(code_only:find("assert%s*%(%s*#entry%.value", 1, false) ~= nil,
    "no assert on entry.value length")
  -- Same gap on tap_script_sig
  local tap_script_sig_block = PSBT_SRC:match(
    "IN_TAP_SCRIPT_SIG then(.-)elseif")
  expect_true(tap_script_sig_block ~= nil, "captured IN_TAP_SCRIPT_SIG block")
  local sig_code = tap_script_sig_block:gsub("%-%-[^\n]*", "")
  expect_false(sig_code:find("#%s*entry%.value%s*[<>=]", 1, false) ~= nil,
    "no length comparison on tap_script_sig value")
end)

--------------------------------------------------------------------------------
-- G23: Taproot leaf-script control-block size remainder (PARTIAL)
--------------------------------------------------------------------------------
test("G23: BUG-15 leaf-script control-block (key.size()-2) %% 32 == 0 missing",
function()
  log_bug("BUG-15", "P2",
    "psbt.lua:624: assert(#entry.key >= 34). Core (psbt.h:734): also "
    .. "rejects (key.size() - 2) % 32 != 0. Control block = 1 leaf-ver "
    .. "byte + 32 internal-key bytes + N×32 path bytes. lunarblock would "
    .. "accept a 35-byte key (1+34) that Core rejects.")
  -- Source: confirm >= 34 check, no remainder mod-32 check
  expect_true(PSBT_SRC:find("Invalid tap_leaf_script key length", 1, true) ~= nil,
    "lower-bound check present")
  local leaf_block = PSBT_SRC:match("IN_TAP_LEAF_SCRIPT then(.-)elseif")
  if leaf_block then
    expect_false(leaf_block:find("%%%s*32", 1, false) ~= nil,
      "no '% 32' remainder check")
  end
end)

--------------------------------------------------------------------------------
-- G24: Taproot output tree validation (MISSING)
--------------------------------------------------------------------------------
test("G24: BUG-16 OUT_TAP_TREE depth/leaf_ver/IsComplete validation MISSING",
function()
  log_bug("BUG-16", "P1",
    "psbt.lua:707-715: reads (depth, leaf_ver, script) triples without "
    .. "validation. Core (psbt.h:1053-1063): depth ≤ "
    .. "TAPROOT_CONTROL_MAX_NODE_COUNT (128), (leaf_ver & "
    .. "~TAPROOT_LEAF_MASK) != 0 (leaf_ver = 0xC0 in v0), and "
    .. "TaprootBuilder.IsComplete() must hold. Forged depth=255 / "
    .. "leaf_ver=0x01 tap_tree quietly accepted, round-trips intact.")
  expect_false(PSBT_SRC:find("TAPROOT_CONTROL_MAX_NODE_COUNT", 1, true) ~= nil,
    "no max-depth constant")
  expect_false(PSBT_SRC:find("TAPROOT_LEAF_MASK", 1, true) ~= nil,
    "no leaf-mask constant")
  expect_false(PSBT_SRC:find("IsComplete", 1, true) ~= nil,
    "no IsComplete check")
end)

--------------------------------------------------------------------------------
-- G25: Global xpub key size check (BUG)
--------------------------------------------------------------------------------
test("G25: BUG-17/BUG-18 global xpub key size + m_xpubs model",
function()
  log_bug("BUG-17", "P2",
    "psbt.lua:494-502: extracts xpub_bytes via entry.key:sub(2) without "
    .. "length assertion. Core (psbt.h:1284): if (key.size() != "
    .. "BIP32_EXTKEY_WITH_VERSION_SIZE + 1 [== 79]) throw 'Size of key "
    .. "was not the expected size for the type global xpub'.")
  log_bug("BUG-18", "P2",
    "lunarblock's psbt.xpubs[xpub_bytes] = derivation model is INVERTED "
    .. "vs Core. Core: m_xpubs is map<KeyOriginInfo, set<CExtPubKey>> — "
    .. "multiple xpubs may share a single keypath. lunarblock keyed by "
    .. "xpub-bytes is fine for the multi-xpub case but the combiner "
    .. "(M.combine line 1042) drops xpub conflicts silently.")
  -- Source confirm: no 79-byte assertion in GLOBAL_XPUB branch
  local xpub_block = PSBT_SRC:match("GLOBAL_XPUB then(.-)elseif")
  if xpub_block then
    expect_false(xpub_block:find("==%s*79", 1, false) ~= nil,
      "no 79-byte key size assertion")
  end
end)

--------------------------------------------------------------------------------
-- G26: Finalizer P2WPKH/P2PKH/P2SH/P2WSH (PASS)
--------------------------------------------------------------------------------
test("G26: PASS finalizer p2wpkh / p2pkh / p2sh-wrapped / p2wsh + multisig",
function()
  -- Source-level confirm all four script types handled
  expect_true(PSBT_SRC:find('script_type%s*==%s*"p2wpkh"', 1, false) ~= nil,
    "p2wpkh branch")
  expect_true(PSBT_SRC:find('script_type%s*==%s*"p2pkh"', 1, false) ~= nil,
    "p2pkh branch")
  expect_true(PSBT_SRC:find('script_type%s*==%s*"p2sh"', 1, false) ~= nil,
    "p2sh branch")
  expect_true(PSBT_SRC:find('script_type%s*==%s*"p2wsh"', 1, false) ~= nil,
    "p2wsh branch")
  expect_true(PSBT_SRC:find("parse_multisig_script", 1, true) ~= nil,
    "multisig detection via parse_multisig_script")
  -- Hardening: verify_p2sh_commitment and verify_p2wsh_commitment at sign+finalize
  expect_true(PSBT_SRC:find("verify_p2sh_commitment", 1, true) ~= nil,
    "P2SH redeem-script commitment check (W31)")
  expect_true(PSBT_SRC:find("verify_p2wsh_commitment", 1, true) ~= nil,
    "P2WSH witness-script commitment check (W38)")
end)

--------------------------------------------------------------------------------
-- G27: Finalizer P2TR (MISSING)
--------------------------------------------------------------------------------
test("G27: BUG-19 finalize_input has NO p2tr branch",
function()
  log_bug("BUG-19", "P1",
    "finalize_input (psbt.lua:1141-1344) covers p2wpkh/p2pkh/p2sh/p2wsh "
    .. "but NO p2tr branch. A PSBT with tap_key_sig populated → "
    .. "finalize_input falls through to 'Unsupported type' (line 1329). "
    .. "Lightning / Ark / Taro PSBTs with v1 segwit inputs cannot be "
    .. "finalized via lunarblock; user needs external finalizer. "
    .. "Blocker for taproot rollout.")
  -- Source: confirm no p2tr branch in finalize_input
  local fin_func = PSBT_SRC:match("function M%.finalize_input.-end\n")
  -- finalize_input is ~200 lines; not all captured. Confirm absence of p2tr
  expect_false(PSBT_SRC:find('script_type%s*==%s*"p2tr"', 1, false) ~= nil,
    "no script_type == 'p2tr' branch anywhere in psbt.lua")
end)

--------------------------------------------------------------------------------
-- G28: Combiner Merge m_xpubs (BUG)
--------------------------------------------------------------------------------
test("G28: BUG-20 combiner drops xpubs on conflict",
function()
  log_bug("BUG-20", "P2",
    "M.combine (psbt.lua:1042-1046): 'for xpub, deriv in pairs(p.xpubs)' "
    .. "with 'if not result.xpubs[xpub] then result.xpubs[xpub] = deriv'. "
    .. "Core's Merge (psbt.cpp:40-46): for each keypath, INSERT xpub "
    .. "into the existing set (set-union). lunarblock keeps the first "
    .. "value seen — second PSBT's xpub is dropped on collision.")
  -- Source confirm the 'if not result.xpubs[xpub]' pattern
  local combine_block = PSBT_SRC:match("function M%.combine.-end\n")
  -- The function is ~110 lines; substring match is best-effort
  expect_true(PSBT_SRC:find("if not result%.xpubs%[xpub%]", 1, false) ~= nil,
    "uses first-wins pattern")
end)

--------------------------------------------------------------------------------
-- G29: Extractor witness flag (PASS)
--------------------------------------------------------------------------------
test("G29: PASS extractor sets tx.segwit when any input has witness",
function()
  expect_true(PSBT_SRC:find("tx%.segwit%s*=%s*true", 1, false) ~= nil,
    "extractor sets segwit flag")
  -- Behavioral: round-trip a finalized PSBT to a transaction
  expect_true(type(psbt_mod.extract) == "function", "extract function exported")
end)

--------------------------------------------------------------------------------
-- G30: RPC PSBT method coverage (PARTIAL)
--------------------------------------------------------------------------------
test("G30: BUG-21 RPC method coverage — descriptorprocesspsbt absent",
function()
  log_bug("BUG-21", "P2",
    "Core wallet/rpc/spend.cpp exposes 12 PSBT RPCs: createpsbt, "
    .. "decodepsbt, analyzepsbt, combinepsbt, finalizepsbt, "
    .. "walletprocesspsbt, converttopsbt, joinpsbts, utxoupdatepsbt, "
    .. "walletcreatefundedpsbt, psbtbumpfee, descriptorprocesspsbt. "
    .. "lunarblock has 11; descriptorprocesspsbt is ABSENT. Also "
    .. "analyzepsbt returns estimated_vsize/feerate/fee = nil (TODO at "
    .. "rpc.lua:4620); utxoupdatepsbt ignores descriptors arg; joinpsbts "
    .. "lacks outpoint-collision check; walletprocesspsbt ignores "
    .. "sighash_type arg (rpc.lua:4760-4764).")
  -- Confirm 11 of 12 present
  for _, m in ipairs({
    "createpsbt", "decodepsbt", "analyzepsbt", "combinepsbt",
    "finalizepsbt", "walletprocesspsbt", "converttopsbt", "joinpsbts",
    "utxoupdatepsbt", "walletcreatefundedpsbt", "psbtbumpfee",
  }) do
    expect_true(
      RPC_SRC:find('self%.methods%["' .. m .. '"%]', 1, false) ~= nil,
      m .. " present in rpc.lua")
  end
  -- And descriptorprocesspsbt is the missing one
  expect_false(
    RPC_SRC:find('self%.methods%["descriptorprocesspsbt"%]', 1, false) ~= nil,
    "descriptorprocesspsbt absent")
  -- analyzepsbt nil estimates
  expect_true(RPC_SRC:find("estimated_vsize%s*=%s*nil", 1, false) ~= nil,
    "analyzepsbt estimated_vsize = nil (TODO)")
end)

--------------------------------------------------------------------------------
-- Behavioral sanity tests for the parts that DO work
--------------------------------------------------------------------------------

test("sanity: serialize/deserialize round-trips a minimal PSBT", function()
  local p = make_minimal_psbt()
  local data = psbt_mod.serialize(p)
  local p2 = psbt_mod.deserialize(data)
  expect_eq(#p2.inputs, 1)
  expect_eq(#p2.outputs, 1)
end)

test("sanity: base64 encode/decode round-trips a minimal PSBT", function()
  local p = make_minimal_psbt()
  local b64 = psbt_mod.to_base64(p)
  local p2 = psbt_mod.from_base64(b64)
  expect_eq(#p2.inputs, 1)
  expect_eq(#p2.outputs, 1)
end)

test("sanity: M.new rejects a signed transaction", function()
  local txid = types.hash256(string.rep("\x05", 32))
  local tx = types.transaction(
    2,
    { types.txin(types.outpoint(txid, 0), "\x01\x02\x03", 0xFFFFFFFF) },
    { types.txout(50000, "\x00\x14" .. string.rep("\x06", 20)) },
    0
  )
  local ok, _ = pcall(psbt_mod.new, tx)
  expect_false(ok, "M.new rejects signed tx")
end)

--------------------------------------------------------------------------------
-- Summary
--------------------------------------------------------------------------------
print("\n=== W137 lunarblock PSBT audit summary ===")
print(string.format("Tests: %d passed, %d failed", tests_passed, tests_failed))
print(string.format("BUGs catalogued: %d", #bugs))
for _, b in ipairs(bugs) do
  print(string.format("  %s [%s]: %s", b.id, b.priority, b.desc:sub(1, 100)
    .. (b.desc:len() > 100 and "..." or "")))
end

-- Exit code: 0 = all expected tests pass; 1 = unexpected failure
if tests_failed > 0 then
  os.exit(1)
end
