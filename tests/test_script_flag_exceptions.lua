#!/usr/bin/env luajit
-- Regression test: script_flag_exceptions parity with Bitcoin Core.
--
-- Bitcoin Core's GetBlockScriptFlags (validation.cpp:2249-2289) is a THREE-STEP
-- sequence and the ORDER IS LOAD-BEARING:
--
--   step 1  BASE       P2SH | WITNESS | TAPROOT, UNCONDITIONALLY, every block
--                      (:2262).  No BIP16Height, no taprootHeight in this path.
--   step 2  EXCEPTION  on a block-hash hit in script_flag_exceptions, REPLACE
--                      the whole flag set with the table value (:2264-2267).
--                      An assignment, NOT an early return.
--   step 3  HEIGHT     OR DERSIG/CLTV/CSV/NULLDUMMY on top of step 2 (:2268-2286).
--
-- This test exercises the REAL production function
-- (consensus.get_block_script_flags), the same one src/utxo.lua connect_block
-- calls for both script verification and sigop counting.  It deliberately does
-- NOT re-implement the logic: the previous version of this file carried a local
-- copy of connect_block's inline code, which meant it could only ever confirm
-- that the copy agreed with itself.  It duly passed while production had two
-- real divergences (see the "pins the fix" groups below).
--
-- Reference: bitcoin-core/src/kernel/chainparams.cpp:85-88, 210-211.
--            bitcoin-core/src/validation.cpp:2249-2289.
--
-- Run: luajit tests/test_script_flag_exceptions.lua

package.path = "./src/?.lua;" .. package.path
package.cpath = "./lib/?.so;" .. package.cpath

local consensus = require("lunarblock.consensus")
local types     = require("lunarblock.types")

local pass, fail = 0, 0
local function check(name, cond, detail)
  if cond then
    io.write("PASS: " .. name .. "\n")
    pass = pass + 1
  else
    io.write("FAIL: " .. name .. (detail and (" -- " .. tostring(detail)) or "") .. "\n")
    fail = fail + 1
  end
end

-- The production function under test.  No local re-implementation.
local get_block_script_flags = consensus.get_block_script_flags

-- Render a flags table as a sorted "{A|B|C}" string for readable failures.
local function render(flags)
  local ks = {}
  for k, v in pairs(flags) do if v then ks[#ks + 1] = k end end
  table.sort(ks)
  return "{" .. table.concat(ks, "|") .. "}"
end

-- ---------------------------------------------------------------------------
-- Test group A: Exception table structure
-- ---------------------------------------------------------------------------
print("=== A: Exception table structure ===\n")

check("A1: SCRIPT_FLAG_EXCEPTIONS exists",
  type(consensus.SCRIPT_FLAG_EXCEPTIONS) == "table")

check("A2: mainnet entry is a table",
  type(consensus.SCRIPT_FLAG_EXCEPTIONS.mainnet) == "table")

check("A3: testnet entry is a table",
  type(consensus.SCRIPT_FLAG_EXCEPTIONS.testnet) == "table")

check("A4: testnet4 entry is a table",
  type(consensus.SCRIPT_FLAG_EXCEPTIONS.testnet4) == "table")

check("A5: regtest entry is a table",
  type(consensus.SCRIPT_FLAG_EXCEPTIONS.regtest) == "table")

-- Canonical hashes + heights (kernel/chainparams.cpp:85-88, 210-211).
local MAINNET_BIP16_HEX   = "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
local MAINNET_TAPROOT_HEX = "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"
local TESTNET3_BIP16_HEX  = "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"

local MAINNET_BIP16_HEIGHT   = 170060  -- BIP16 violator block height
local MAINNET_TAPROOT_HEIGHT = 692261  -- Taproot violator block height
local TESTNET3_BIP16_HEIGHT  = 514     -- testnet3 BIP16 violator (approx)

local mn_bip16_entry   = consensus.SCRIPT_FLAG_EXCEPTIONS.mainnet[MAINNET_BIP16_HEX]
local mn_taproot_entry = consensus.SCRIPT_FLAG_EXCEPTIONS.mainnet[MAINNET_TAPROOT_HEX]
local tn3_bip16_entry  = consensus.SCRIPT_FLAG_EXCEPTIONS.testnet[TESTNET3_BIP16_HEX]

check("A6: mainnet BIP16 exception entry exists",
  type(mn_bip16_entry) == "table")

check("A7: mainnet BIP16 exception entry is empty (SCRIPT_VERIFY_NONE)",
  type(mn_bip16_entry) == "table" and next(mn_bip16_entry) == nil,
  "entry has unexpected fields")

check("A8: mainnet Taproot exception entry exists",
  type(mn_taproot_entry) == "table")

check("A9: mainnet Taproot exception has verify_p2sh=true",
  type(mn_taproot_entry) == "table" and mn_taproot_entry.verify_p2sh == true)

check("A10: mainnet Taproot exception has verify_witness=true",
  type(mn_taproot_entry) == "table" and mn_taproot_entry.verify_witness == true)

check("A11: mainnet Taproot exception does NOT have verify_taproot",
  type(mn_taproot_entry) == "table" and not mn_taproot_entry.verify_taproot,
  "verify_taproot should be nil/false for taproot violator")

check("A12: testnet3 BIP16 exception entry exists",
  type(tn3_bip16_entry) == "table")

check("A13: testnet3 BIP16 exception entry is empty (SCRIPT_VERIFY_NONE)",
  type(tn3_bip16_entry) == "table" and next(tn3_bip16_entry) == nil,
  "entry has unexpected fields")

check("A14: testnet4 exception table is empty",
  next(consensus.SCRIPT_FLAG_EXCEPTIONS.testnet4) == nil)

check("A15: regtest exception table is empty",
  next(consensus.SCRIPT_FLAG_EXCEPTIONS.regtest) == nil)

-- ---------------------------------------------------------------------------
-- Test group B: Hash round-trip + byte-reversed negative control
-- ---------------------------------------------------------------------------
print("\n=== B: Hash byte-order / display-hex round-trip ===\n")

-- The exception table is keyed by DISPLAY-order (big-endian) hex, which is what
-- types.hash256_hex returns (types.lua:25-31 reverses the internal little-endian
-- bytes).  Same orientation as the BIP-30 exemption tables in utxo.lua.
local function hex_roundtrip(hex_str)
  local h = types.hash256_from_hex(hex_str)
  return types.hash256_hex(h)
end

check("B1: mainnet BIP16 hash round-trips correctly",
  hex_roundtrip(MAINNET_BIP16_HEX) == MAINNET_BIP16_HEX,
  hex_roundtrip(MAINNET_BIP16_HEX))

check("B2: mainnet Taproot hash round-trips correctly",
  hex_roundtrip(MAINNET_TAPROOT_HEX) == MAINNET_TAPROOT_HEX,
  hex_roundtrip(MAINNET_TAPROOT_HEX))

check("B3: testnet3 BIP16 hash round-trips correctly",
  hex_roundtrip(TESTNET3_BIP16_HEX) == TESTNET3_BIP16_HEX,
  hex_roundtrip(TESTNET3_BIP16_HEX))

-- B4/B5: byte-reversed NEGATIVE CONTROL.  If the table were ever "fixed" to
-- internal (little-endian) order, or the lookup started feeding raw internal
-- bytes, the reversed key would hit.  A byte-reversed hash is just some other
-- block: it must get the normal base flags, TAPROOT included.
local function reverse_hex(hex_str)
  local h = types.hash256_from_hex(hex_str)                -- display hex -> internal
  return types.hash256_hex({ bytes = h.bytes:reverse() })  -- byte-reversed
end

local rev_taproot_hex = reverse_hex(MAINNET_TAPROOT_HEX)
check("B4: byte-reversed Taproot hash is NOT a key in the exception table",
  consensus.SCRIPT_FLAG_EXCEPTIONS.mainnet[rev_taproot_hex] == nil,
  rev_taproot_hex)

local flags_rev = get_block_script_flags(consensus.networks.mainnet,
  MAINNET_TAPROOT_HEIGHT, types.hash256_from_hex(rev_taproot_hex))
check("B5: byte-reversed Taproot hash gets NORMAL flags (keeps TAPROOT)",
  flags_rev.verify_taproot == true and flags_rev.verify_p2sh == true,
  render(flags_rev))

-- ---------------------------------------------------------------------------
-- Test group C: the three Core-authoritative results (the acceptance criterion)
--
-- These are the assertions that pin the fix.  Pre-fix, lunarblock folded the
-- height gates into the base table and then let the exception REPLACE the whole
-- thing, so [692261] returned P2SH|WITNESS alone — dropping DERSIG|CLTV|CSV|
-- NULLDUMMY, all four active at that height.  That is a FALSE-ACCEPT.
-- ---------------------------------------------------------------------------
print("\n=== C: Core-authoritative results at the real heights ===\n")

local MAINNET = consensus.networks.mainnet
local TESTNET = consensus.networks.testnet

-- C-group 1: [170060] -> SCRIPT_VERIFY_NONE.
-- The exception value is NONE and none of the four height gates are active at
-- 170060 (bip66=363725, bip65=388381, csv=419328, segwit=481824), so step 3
-- adds nothing and the result is genuinely empty.
local mn_bip16_hash  = types.hash256_from_hex(MAINNET_BIP16_HEX)
local flags_mn_bip16 = get_block_script_flags(MAINNET, MAINNET_BIP16_HEIGHT, mn_bip16_hash)

check("C1: [170060] BIP16 violator -> NONE (no flags at all)",
  next(flags_mn_bip16) == nil, render(flags_mn_bip16))
check("C2: [170060] verify_p2sh is false (exception wiped the base P2SH)",
  not flags_mn_bip16.verify_p2sh)
check("C3: [170060] verify_witness is false",
  not flags_mn_bip16.verify_witness)
check("C4: [170060] verify_taproot is false",
  not flags_mn_bip16.verify_taproot)

-- C-group 2: [692261] -> P2SH|WITNESS|DERSIG|CLTV|CSV|NULLDUMMY, TAPROOT stripped.
local mn_taproot_hash  = types.hash256_from_hex(MAINNET_TAPROOT_HEX)
local flags_mn_taproot = get_block_script_flags(MAINNET, MAINNET_TAPROOT_HEIGHT, mn_taproot_hash)

check("C5: [692261] Taproot violator -> verify_p2sh=true",
  flags_mn_taproot.verify_p2sh == true, render(flags_mn_taproot))
check("C6: [692261] Taproot violator -> verify_witness=true",
  flags_mn_taproot.verify_witness == true, render(flags_mn_taproot))
check("C7: [692261] Taproot violator -> verify_taproot STRIPPED",
  not flags_mn_taproot.verify_taproot, render(flags_mn_taproot))
-- The four an early-return implementation would drop.  BIP66/65/CSV/SegWit are
-- all long active at 692261; Core ORs them on top of the exception value.
check("C8: [692261] verify_dersig=true (BIP66 active, OR'd AFTER the exception)",
  flags_mn_taproot.verify_dersig == true, render(flags_mn_taproot))
check("C9: [692261] verify_checklocktimeverify=true (BIP65 active)",
  flags_mn_taproot.verify_checklocktimeverify == true, render(flags_mn_taproot))
check("C10: [692261] verify_checksequenceverify=true (CSV active)",
  flags_mn_taproot.verify_checksequenceverify == true, render(flags_mn_taproot))
check("C11: [692261] verify_nulldummy=true (BIP147, rides SegWit)",
  flags_mn_taproot.verify_nulldummy == true, render(flags_mn_taproot))
check("C12: [692261] exact flag set matches Core",
  render(flags_mn_taproot) == "{verify_checklocktimeverify|verify_checksequenceverify|"
    .. "verify_dersig|verify_nulldummy|verify_p2sh|verify_witness}",
  render(flags_mn_taproot))

-- C-group 3: CONTROL — a non-exception hash at the SAME height keeps TAPROOT.
local DUMMY_HEX  = "0000000000000000000000000000000000000000000000000000000000000001"
local dummy_hash = types.hash256_from_hex(DUMMY_HEX)
local flags_ctrl = get_block_script_flags(MAINNET, MAINNET_TAPROOT_HEIGHT, dummy_hash)

check("C13: [control @692261] non-exception hash KEEPS verify_taproot",
  flags_ctrl.verify_taproot == true, render(flags_ctrl))
check("C14: [control @692261] full set = base + all four height gates",
  render(flags_ctrl) == "{verify_checklocktimeverify|verify_checksequenceverify|"
    .. "verify_dersig|verify_nulldummy|verify_p2sh|verify_taproot|verify_witness}",
  render(flags_ctrl))

-- C-group 4: testnet3 BIP16 violator -> NONE.
local tn3_bip16_hash = types.hash256_from_hex(TESTNET3_BIP16_HEX)
local flags_tn3      = get_block_script_flags(TESTNET, TESTNET3_BIP16_HEIGHT, tn3_bip16_hash)
check("C15: [testnet3 514] BIP16 violator -> NONE",
  next(flags_tn3) == nil, render(flags_tn3))

-- C16: the module table must NOT be aliased/mutated by the calls above.
check("C16: SCRIPT_FLAG_EXCEPTIONS entry unchanged after a call (no aliasing)",
  render(consensus.SCRIPT_FLAG_EXCEPTIONS.mainnet[MAINNET_TAPROOT_HEX])
    == "{verify_p2sh|verify_witness}",
  render(consensus.SCRIPT_FLAG_EXCEPTIONS.mainnet[MAINNET_TAPROOT_HEX]))

-- ---------------------------------------------------------------------------
-- Test group D: base flags are UNCONDITIONAL (no height gate on the big three)
--
-- Core dropped BIP16Height and taprootHeight from this path in v23: P2SH,
-- WITNESS and TAPROOT are on for EVERY block, with the two violating blocks
-- handled by the exception table instead.  Height-gating them is a divergence,
-- and the pre-fix lunarblock code did exactly that
-- (verify_witness = height >= segwit_height, verify_taproot = height >=
-- taproot_height).  The old D3/D6 assertions in this file asserted that gated
-- behaviour (taproot false at a pre-activation height); they are replaced below
-- by D3/D5, which assert Core's unconditional base.
-- ---------------------------------------------------------------------------
print("\n=== D: unconditional P2SH|WITNESS|TAPROOT base ===\n")

local flags_early = get_block_script_flags(MAINNET, MAINNET_BIP16_HEIGHT, dummy_hash)
check("D1: non-exception hash at h=170060 — verify_p2sh=true",
  flags_early.verify_p2sh == true, render(flags_early))
check("D2: non-exception hash at h=170060 — verify_witness=true (UNCONDITIONAL, not segwit-gated)",
  flags_early.verify_witness == true, render(flags_early))
check("D3: non-exception hash at h=170060 — verify_taproot=true (UNCONDITIONAL, not height-gated)",
  flags_early.verify_taproot == true, render(flags_early))
check("D4: non-exception hash at h=170060 — verify_dersig=false (BIP66 not yet active)",
  not flags_early.verify_dersig, render(flags_early))
check("D5: non-exception hash at h=0 (genesis) — base three still on, no height gates",
  (function()
    local f = get_block_script_flags(MAINNET, 0, dummy_hash)
    return f.verify_p2sh == true and f.verify_witness == true and f.verify_taproot == true
      and not f.verify_dersig and not f.verify_nulldummy
  end)(),
  render(get_block_script_flags(MAINNET, 0, dummy_hash)))

-- D6..D9: buried-deployment boundaries use >= (DeploymentActiveAt semantics:
-- index.nHeight >= DeploymentHeight, deploymentstatus.h).
check("D6: dersig off at bip66_height-1, on at bip66_height",
  not get_block_script_flags(MAINNET, MAINNET.bip66_height - 1, dummy_hash).verify_dersig
  and get_block_script_flags(MAINNET, MAINNET.bip66_height, dummy_hash).verify_dersig == true)
check("D7: cltv off at bip65_height-1, on at bip65_height",
  not get_block_script_flags(MAINNET, MAINNET.bip65_height - 1, dummy_hash).verify_checklocktimeverify
  and get_block_script_flags(MAINNET, MAINNET.bip65_height, dummy_hash).verify_checklocktimeverify == true)
check("D8: csv off at csv_height-1, on at csv_height",
  not get_block_script_flags(MAINNET, MAINNET.csv_height - 1, dummy_hash).verify_checksequenceverify
  and get_block_script_flags(MAINNET, MAINNET.csv_height, dummy_hash).verify_checksequenceverify == true)
check("D9: nulldummy off at segwit_height-1, on at segwit_height",
  not get_block_script_flags(MAINNET, MAINNET.segwit_height - 1, dummy_hash).verify_nulldummy
  and get_block_script_flags(MAINNET, MAINNET.segwit_height, dummy_hash).verify_nulldummy == true)

-- D10/D11: no cross-network exception pollution.
local flags_tn4 = get_block_script_flags(consensus.networks.testnet4, 1,
  types.hash256_from_hex(MAINNET_BIP16_HEX))
check("D10: testnet4 does not inherit the mainnet BIP16 exception",
  flags_tn4.verify_p2sh == true and flags_tn4.verify_taproot == true, render(flags_tn4))

local flags_reg = get_block_script_flags(consensus.networks.regtest, 1,
  types.hash256_from_hex(MAINNET_BIP16_HEX))
check("D11: regtest does not inherit the mainnet BIP16 exception",
  flags_reg.verify_p2sh == true and flags_reg.verify_taproot == true, render(flags_reg))

-- D12: nil block hash (context-free callers) → base + height gates, no crash.
local flags_nil = get_block_script_flags(MAINNET, MAINNET_TAPROOT_HEIGHT, nil)
check("D12: nil block_hash skips the exception lookup and keeps the base",
  flags_nil.verify_taproot == true and flags_nil.verify_dersig == true, render(flags_nil))

-- D13: a display-hex string is accepted as well as a hash256 table.
local flags_hexarg = get_block_script_flags(MAINNET, MAINNET_TAPROOT_HEIGHT, MAINNET_TAPROOT_HEX)
check("D13: hex-string block_hash hits the same exception as the hash256 form",
  render(flags_hexarg) == render(flags_mn_taproot), render(flags_hexarg))

-- ---------------------------------------------------------------------------
-- Test group E: NO POLICY FLAGS in the block-validation set.
-- STANDARD_SCRIPT_VERIFY_FLAGS (policy/policy.h:125) must never leak here.
-- ---------------------------------------------------------------------------
print("\n=== E: no policy flags in the consensus set ===\n")

local POLICY_ONLY = {
  "verify_nullfail", "verify_cleanstack", "verify_low_s", "verify_strictenc",
  "verify_minimaldata", "verify_minimalif", "verify_witness_pubkeytype",
  "verify_const_scriptcode", "verify_sigpushonly",
  "verify_discourage_upgradable_nops",
}
local leaked = {}
for _, h in ipairs({0, MAINNET_BIP16_HEIGHT, MAINNET_TAPROOT_HEIGHT, 900000}) do
  local f = get_block_script_flags(MAINNET, h, dummy_hash)
  for _, name in ipairs(POLICY_ONLY) do
    if f[name] then leaked[#leaked + 1] = name .. "@" .. h end
  end
end
check("E1: no STANDARD/policy flag appears at any height",
  #leaked == 0, table.concat(leaked, ", "))

-- ---------------------------------------------------------------------------
-- Test group F: sigop counting consumes the SAME exception-aware flags.
-- Core passes the identical `flags` value to GetTransactionSigOpCost
-- (validation.cpp:2565), which gates P2SH sigops on SCRIPT_VERIFY_P2SH
-- (tx_verify.cpp:150-152); CountWitnessSigOps returns 0 with WITNESS clear
-- (interpreter.cpp:2140-2142).  At 170060 the exception is NONE, so neither
-- contributes — a hash-blind {p2sh=true, ...} sigop table over-counts.
-- ---------------------------------------------------------------------------
print("\n=== F: sigop flags are exception-aware ===\n")

local sf_170060 = get_block_script_flags(MAINNET, MAINNET_BIP16_HEIGHT, mn_bip16_hash)
check("F1: [170060] sigop flags have verify_p2sh false → no P2SH sigops counted",
  not sf_170060.verify_p2sh, render(sf_170060))
check("F2: [170060] sigop flags have verify_witness false → CountWitnessSigOps=0",
  not sf_170060.verify_witness, render(sf_170060))

local sf_692261 = get_block_script_flags(MAINNET, MAINNET_TAPROOT_HEIGHT, mn_taproot_hash)
check("F3: [692261] sigop flags keep verify_p2sh (exception value is P2SH|WITNESS)",
  sf_692261.verify_p2sh == true, render(sf_692261))
check("F4: [692261] sigop flags keep verify_witness",
  sf_692261.verify_witness == true, render(sf_692261))

-- F5: connect_block must use the shared, exception-aware table for sigops, and
-- must compute it OUTSIDE the skip_script_validation guard (sigops are counted
-- on every connect; scripts are not).  Guards against a regression to a
-- separate hash-blind sigop table.
local utxo_src = assert(io.open("src/utxo.lua", "r")):read("*a")
check("F5: connect_block derives sigop_flags from block_script_flags (no hash-blind copy)",
  utxo_src:find("local sigop_flags = block_script_flags", 1, true) ~= nil
  and utxo_src:find(
    "consensus.get_block_script_flags(self.network, height, block_hash)", 1, true) ~= nil,
  "src/utxo.lua no longer wires sigop_flags to the exception-aware flags")

-- ---------------------------------------------------------------------------
io.write(string.format("\n=== %d passed, %d failed ===\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
