-- Glass-box wave 2 (2026-07-01): BIP-68 sequence locks must be enforced for
-- transactions whose nVersion has the high bit set (read signed via read_i32le).
--
-- Reference: bitcoin-core/src/consensus/tx_verify.cpp:51
--   bool fEnforceBIP68 = tx.version >= 2 && flags & LOCKTIME_VERIFY_SEQUENCE;
-- with tx.version being uint32_t (primitives/transaction.h:293), so the compare
-- is UNSIGNED. Version 0xFFFFFFFF therefore ENTERS enforcement.
--
-- Bug: lunarblock's connect-block gate bip68_version_active (utxo.lua:29-30)
-- already reinterprets version as unsigned, but calculate_sequence_locks
-- (validation.lua) used a SIGNED `tx.version < 2` check. read_i32le sign-extends
-- 0xFFFFFFFF to -1, so `-1 < 2` was true → it returned (-1,-1) and SKIPPED the
-- BIP-68 height-lock computation → a non-final tx was ACCEPTED where Core rejects
-- (bad-txns-nonfinal). The two paths disagreed exactly on high-bit versions.
--
-- Exact failing input (from the finding):
--   block height 500000 (>= csv_height 419328), tx nVersion=0xFFFFFFFF (== -1
--   signed), one input spending a coin created at height 499999 (1 block deep),
--   nSequence=0x00000002 (disable clear, type clear, relative-height lock = 2).
--   Core: nMinHeight = 499999 + 2 - 1 = 500000 >= 500000 → SequenceLocks false
--   → REJECT. Pre-fix lunarblock: returns (-1,-1) → check passes → ACCEPT.

describe("BIP-68 sequence locks enforce high-bit tx.version (unsigned, Core parity)", function()
  local validation
  local types
  local consensus

  setup(function()
    package.path = "src/?.lua;" .. package.path
    package.preload["lunarblock.types"]     = function() return require("types") end
    package.preload["lunarblock.serialize"] = function() return require("serialize") end
    package.preload["lunarblock.crypto"]    = function() return require("crypto") end
    package.preload["lunarblock.script"]    = function() return require("script") end
    package.preload["lunarblock.consensus"] = function() return require("consensus") end
    types      = require("types")
    validation = require("validation")
    consensus  = require("consensus")
  end)

  -- Build a tx with a given (possibly high-bit / signed) version and one input.
  local function make_tx(version, sequence)
    local tx = types.transaction(version, {}, {}, 0)
    local h = types.hash256(string.rep("\x01", 32))
    tx.inputs[1] = types.txin(types.outpoint(h, 0), "\x00", sequence)
    tx.outputs[1] = types.txout(50000, string.rep("\x00", 25))
    return tx
  end

  it("nVersion=0xFFFFFFFF (signed -1) still computes the relative-height lock", function()
    -- read_i32le sign-extends 0xFFFFFFFF to -1; that is what tx.version holds.
    local tx = make_tx(-1, 0x00000002)
    local coin_height = 499999
    local block_height = 500000
    local min_h, min_t = validation.calculate_sequence_locks(
      tx, block_height,
      function() return coin_height end,   -- get_utxo_height
      function() return 0 end,             -- get_block_mtp
      true)                                -- enforce_bip68 (csv active at 500000)

    -- Core nMinHeight = coin_height + lock_value - 1 = 499999 + 2 - 1 = 500000.
    -- Pre-fix lunarblock returned -1 here (signed version < 2 short-circuit).
    assert.equals(500000, min_h)
    assert.equals(-1, min_t)
  end)

  it("a non-final high-bit-version tx is REJECTED at the height Core rejects it", function()
    local tx = make_tx(-1, 0x00000002)
    local coin_height = 499999
    local block_height = 500000
    local min_h, min_t = validation.calculate_sequence_locks(
      tx, block_height,
      function() return coin_height end,
      function() return 0 end,
      true)
    -- min_height 500000 >= block_height 500000 → sequence locks NOT satisfied.
    local ok = validation.check_sequence_locks(min_h, min_t, block_height, 0)
    assert.is_false(ok)  -- REJECT (bad-txns-nonfinal), matching Core
  end)

  it("one block later (height 500001) the same tx becomes final (control)", function()
    local tx = make_tx(-1, 0x00000002)
    local min_h, min_t = validation.calculate_sequence_locks(
      tx, 500001,
      function() return 499999 end,
      function() return 0 end,
      true)
    assert.equals(500000, min_h)
    assert.is_true(validation.check_sequence_locks(min_h, min_t, 500001, 0))
  end)
end)
