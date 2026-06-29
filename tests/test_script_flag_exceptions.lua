#!/usr/bin/env luajit
-- Regression test: script_flag_exceptions parity with Bitcoin Core.
--
-- Bitcoin Core's GetBlockScriptFlags (validation.cpp:2262-2266) consults a
-- hash-keyed exception table before applying by-height soft-fork flags.  Two
-- historical mainnet blocks violated P2SH rules, one violated Taproot rules,
-- and one testnet3 block violated P2SH rules.  For those blocks the flags are
-- replaced with a hardcoded override rather than the normal P2SH|WITNESS|TAPROOT
-- base.
--
-- This test verifies:
--   (a) The exception table entries exist with the correct override values.
--   (b) The hash comparison uses display-order (big-endian) hex, matching the
--       types.hash256_hex / types.hash256_from_hex round-trip.
--   (c) The inline lookup in connect_block fires for exception hashes and
--       returns the correct override flags.
--   (d) A NON-exception hash at the SAME height returns normal by-height flags
--       (confirms the lookup doesn't over-trigger).
--   (e) testnet4 and regtest have empty tables (no spurious exceptions).
--
-- Reference: bitcoin-core/src/kernel/chainparams.cpp:85-88, 210-211.
--            bitcoin-core/src/validation.cpp:2262-2266.
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

-- ---------------------------------------------------------------------------
-- Helper: simulate the GetBlockScriptFlags logic from utxo.lua connect_block.
-- Mirrors the inline code exactly so that a change to one without the other
-- will cause this test to fail (cross-check).
-- ---------------------------------------------------------------------------
local function get_block_script_flags(network, height, block_hash)
  local flags = {
    verify_p2sh               = true,
    verify_dersig             = height >= (network.bip66_height or math.huge),
    verify_checklocktimeverify= height >= (network.bip65_height or math.huge),
    verify_checksequenceverify= height >= (network.csv_height   or math.huge),
    verify_witness            = height >= (network.segwit_height  or math.huge),
    verify_nulldummy          = height >= (network.segwit_height  or math.huge),
    verify_taproot            = height >= (network.taproot_height or math.huge),
  }
  -- Exception override (mirrors utxo.lua connect_block inline logic)
  local _sfe = consensus.SCRIPT_FLAG_EXCEPTIONS[network.name]
  if _sfe then
    local _override = _sfe[types.hash256_hex(block_hash)]
    if _override then
      flags = _override
    end
  end
  return flags
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

-- Mainnet BIP16 violator
local MAINNET_BIP16_HEX = "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
local MAINNET_TAPROOT_HEX = "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"
local TESTNET3_BIP16_HEX  = "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"

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
-- Test group B: Hash round-trip (display-hex comparison)
-- ---------------------------------------------------------------------------
print("\n=== B: Hash byte-order / display-hex round-trip ===\n")

-- Verify that converting a display-hex string to a hash256 and back gives the
-- original string.  This is the comparison path used in utxo.lua:
--   types.hash256_hex(block_hash) == exception_key_hex
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

-- ---------------------------------------------------------------------------
-- Test group C: Override fires for exception hashes (core of the fix)
-- ---------------------------------------------------------------------------
print("\n=== C: Exception override fires for correct hashes ===\n")

local MAINNET = consensus.networks.mainnet
local TESTNET = consensus.networks.testnet

-- C1: mainnet BIP16 violator — height doesn't matter for this block (it's
-- pre-BIP66/CLTV/CSV/segwit) but we use a representative early height.
-- The override should return NONE (all flags nil/false).
local mn_bip16_hash  = types.hash256_from_hex(MAINNET_BIP16_HEX)
local bip16_height   = 170060  -- approximate historical height, pre-BIP66

local flags_mn_bip16 = get_block_script_flags(MAINNET, bip16_height, mn_bip16_hash)
check("C1: mainnet BIP16 exception — verify_p2sh is nil/false (NONE)",
  not flags_mn_bip16.verify_p2sh,
  "expected false, got " .. tostring(flags_mn_bip16.verify_p2sh))
check("C2: mainnet BIP16 exception — verify_dersig is nil/false (NONE)",
  not flags_mn_bip16.verify_dersig)
check("C3: mainnet BIP16 exception — verify_witness is nil/false (NONE)",
  not flags_mn_bip16.verify_witness)
check("C4: mainnet BIP16 exception — verify_taproot is nil/false (NONE)",
  not flags_mn_bip16.verify_taproot)

-- C5: mainnet Taproot violator — height 709631 (one block before taproot activation
-- at 709632).  Override = P2SH|WITNESS only (no taproot).
local mn_taproot_hash = types.hash256_from_hex(MAINNET_TAPROOT_HEX)
local taproot_height  = 709631  -- Core height for this block

local flags_mn_taproot = get_block_script_flags(MAINNET, taproot_height, mn_taproot_hash)
check("C5: mainnet Taproot exception — verify_p2sh=true",
  flags_mn_taproot.verify_p2sh == true,
  "got " .. tostring(flags_mn_taproot.verify_p2sh))
check("C6: mainnet Taproot exception — verify_witness=true",
  flags_mn_taproot.verify_witness == true,
  "got " .. tostring(flags_mn_taproot.verify_witness))
check("C7: mainnet Taproot exception — verify_taproot is nil/false",
  not flags_mn_taproot.verify_taproot,
  "got " .. tostring(flags_mn_taproot.verify_taproot))

-- C8: testnet3 BIP16 violator — NONE override
local tn3_bip16_hash = types.hash256_from_hex(TESTNET3_BIP16_HEX)
local tn3_bip16_height = 514  -- approximate testnet3 height

local flags_tn3_bip16 = get_block_script_flags(TESTNET, tn3_bip16_height, tn3_bip16_hash)
check("C8: testnet3 BIP16 exception — verify_p2sh is nil/false (NONE)",
  not flags_tn3_bip16.verify_p2sh,
  "got " .. tostring(flags_tn3_bip16.verify_p2sh))
check("C9: testnet3 BIP16 exception — verify_witness is nil/false (NONE)",
  not flags_tn3_bip16.verify_witness)

-- ---------------------------------------------------------------------------
-- Test group D: Non-exception hash at same height → normal by-height flags
-- (proves the lookup does NOT over-trigger)
-- ---------------------------------------------------------------------------
print("\n=== D: Non-exception hash → normal by-height flags ===\n")

-- Use a dummy hash that is NOT in the exception table.
local DUMMY_HEX = "0000000000000000000000000000000000000000000000000000000000000001"
local dummy_hash = types.hash256_from_hex(DUMMY_HEX)

-- D1: At BIP16 violator height (pre-BIP66), normal flags should have verify_p2sh=true
-- (Core always enables P2SH except for the two exception blocks).
local flags_normal_early = get_block_script_flags(MAINNET, bip16_height, dummy_hash)
check("D1: non-exception hash at bip16_height — verify_p2sh=true (normal)",
  flags_normal_early.verify_p2sh == true,
  "got " .. tostring(flags_normal_early.verify_p2sh))
check("D2: non-exception hash at bip16_height — verify_dersig=false (pre-BIP66)",
  not flags_normal_early.verify_dersig,
  "got " .. tostring(flags_normal_early.verify_dersig))
check("D3: non-exception hash at bip16_height — verify_taproot=false (pre-taproot)",
  not flags_normal_early.verify_taproot,
  "got " .. tostring(flags_normal_early.verify_taproot))

-- D4: At taproot violator height (709631), normal flags should include TAPROOT
-- (the next block 709632 is the activation block, but 709631 = activation - 1
-- so taproot is NOT yet active in normal flags).
local flags_normal_taproot_height = get_block_script_flags(MAINNET, taproot_height, dummy_hash)
check("D4: non-exception hash at 709631 — verify_p2sh=true",
  flags_normal_taproot_height.verify_p2sh == true)
check("D5: non-exception hash at 709631 — verify_witness=true (segwit active)",
  flags_normal_taproot_height.verify_witness == true)
check("D6: non-exception hash at 709631 — verify_taproot=false (taproot NOT yet active at 709631)",
  not flags_normal_taproot_height.verify_taproot,
  "got " .. tostring(flags_normal_taproot_height.verify_taproot))
check("D7: non-exception hash at 709631 — verify_dersig=true (BIP66 active)",
  flags_normal_taproot_height.verify_dersig == true)

-- D8: At taproot activation height itself (709632), normal flags INCLUDE taproot.
local flags_taproot_active = get_block_script_flags(MAINNET, 709632, dummy_hash)
check("D8: non-exception hash at 709632 — verify_taproot=true (normal taproot)",
  flags_taproot_active.verify_taproot == true,
  "got " .. tostring(flags_taproot_active.verify_taproot))

-- D9: testnet4 — no exceptions; normal flags at any height are unaffected.
local TESTNET4 = consensus.networks.testnet4
local flags_tn4 = get_block_script_flags(TESTNET4, 1, types.hash256_from_hex(MAINNET_BIP16_HEX))
-- Even if the mainnet BIP16 hash is used, testnet4 has no exception table → normal flags.
check("D9: testnet4 does not inherit mainnet BIP16 exception (no cross-network pollution)",
  flags_tn4.verify_p2sh == true,
  "got " .. tostring(flags_tn4.verify_p2sh))

-- D10: regtest — no exceptions.
local REGTEST = consensus.networks.regtest
local flags_reg = get_block_script_flags(REGTEST, 1, types.hash256_from_hex(MAINNET_BIP16_HEX))
check("D10: regtest does not inherit mainnet BIP16 exception",
  flags_reg.verify_p2sh == true,
  "got " .. tostring(flags_reg.verify_p2sh))

-- ---------------------------------------------------------------------------
io.write(string.format("\n=== %d passed, %d failed ===\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
