-- W80 BIP-68 + BIP-112 + BIP-113 sequence-locks comprehensive test
-- Reference: bitcoin-core/src/consensus/tx_verify.cpp:39-110
--            bitcoin-core/src/primitives/transaction.h:60-115
--            bitcoin-core/src/script/interpreter.cpp:561-593, :1782-1825
--
-- 21 gates tested:
-- BIP-68 CalculateSequenceLocks gates 1-6 (tx_verify.cpp:39-94)
-- BIP-68 EvaluateSequenceLocks gates 7-8 (tx_verify.cpp:97-105)
-- BIP-112 CheckSequence gates 9-13 (interpreter.cpp:1782-1825)
-- BIP-112 OP_CHECKSEQUENCEVERIFY gates 14-19 (interpreter.cpp:561-593)
-- BIP-113 MTP gates 20-21 (chain.h:233-244, tx_verify.cpp:100)

describe("BIP-68 + BIP-112 + BIP-113 sequence locks (W80)", function()
  local validation
  local types
  local consensus
  local script
  local bit

  -- BIP-68 constants (from transaction.h:60-115)
  local DISABLE_FLAG  = 0x80000000  -- bit 31: disables relative lock-time
  local TYPE_FLAG     = 0x00400000  -- bit 22: 0=height, 1=time (512s units)
  local MASK          = 0x0000FFFF  -- bits 0-15: lock value
  local GRANULARITY   = 9           -- shift: multiply by 512
  local SEQUENCE_FINAL = 0xFFFFFFFF -- SEQUENCE_FINAL: no lock, also disables nLockTime

  setup(function()
    bit = require("bit")
    package.path = "src/?.lua;" .. package.path
    package.preload["lunarblock.types"]     = function() return require("types") end
    package.preload["lunarblock.serialize"] = function() return require("serialize") end
    package.preload["lunarblock.crypto"]    = function() return require("crypto") end
    package.preload["lunarblock.script"]    = function() return require("script") end
    package.preload["lunarblock.consensus"] = function() return require("consensus") end
    types     = require("types")
    validation = require("validation")
    consensus = require("consensus")
    script    = require("script")
  end)

  -- Helper: make a simple v2 tx with given per-input sequences
  local function make_tx(version, sequences)
    local tx = types.transaction(version, {}, {}, 0)
    for i, seq in ipairs(sequences) do
      local h = types.hash256(string.rep(string.char(i), 32))
      tx.inputs[i] = types.txin(types.outpoint(h, 0), "\x00", seq)
    end
    tx.outputs[1] = types.txout(50000, string.rep("\x00", 25))
    return tx
  end

  -- Helper: constant-returning callbacks
  local function const_height(h)
    return function() return h end
  end
  local function const_mtp(t)
    return function() return t end
  end

  ---------------------------------------------------------------------------
  -- BIP-68 CalculateSequenceLocks: gates 1-6 (tx_verify.cpp:39-94)
  ---------------------------------------------------------------------------
  describe("BIP-68 CalculateSequenceLocks", function()

    -- Gate 1: enforce_bip68 = false OR tx.version < 2 → return -1,-1 immediately
    it("[gate 1] returns -1,-1 when enforce_bip68=false regardless of sequences", function()
      local tx = make_tx(2, {10})
      local min_h, min_t = validation.calculate_sequence_locks(
        tx, 200, const_height(100), const_mtp(1000000), false)
      assert.equals(-1, min_h)
      assert.equals(-1, min_t)
    end)

    it("[gate 1] returns -1,-1 for version 1 even with enforce_bip68=true", function()
      local tx = make_tx(1, {10})
      local min_h, min_t = validation.calculate_sequence_locks(
        tx, 200, const_height(100), const_mtp(1000000), true)
      assert.equals(-1, min_h)
      assert.equals(-1, min_t)
    end)

    -- Gate 2: DISABLE_FLAG set → skip input (prevHeight zeroed in Core)
    it("[gate 2] input with DISABLE_FLAG set is skipped — contributes nothing", function()
      -- Both inputs have DISABLE_FLAG; must get -1,-1
      local tx = make_tx(2, {
        bit.bor(DISABLE_FLAG, 10),
        bit.bor(DISABLE_FLAG, 20),
      })
      local min_h, min_t = validation.calculate_sequence_locks(
        tx, 300, const_height(100), const_mtp(1000000), true)
      assert.equals(-1, min_h)
      assert.equals(-1, min_t)
    end)

    it("[gate 2] only active input counts when one is disabled", function()
      -- Input 1: DISABLE_FLAG set (skip)
      -- Input 2: height-based, 5 blocks, UTXO at 200 → min_height = 200+5-1 = 204
      local seqs = {bit.bor(DISABLE_FLAG, 99), 5}
      local tx = make_tx(2, seqs)
      local heights = {999, 200}
      local function get_h(inp)
        for i, inp2 in ipairs(tx.inputs) do
          if inp2 == inp then return heights[i] end
        end
      end
      local min_h, min_t = validation.calculate_sequence_locks(
        tx, 300, get_h, const_mtp(0), true)
      assert.equals(204, min_h)
      assert.equals(-1, min_t)
    end)

    it("[gate 2] SEQUENCE_FINAL (0xFFFFFFFF) has DISABLE_FLAG — skipped", function()
      local tx = make_tx(2, {SEQUENCE_FINAL})
      local min_h, min_t = validation.calculate_sequence_locks(
        tx, 200, const_height(100), const_mtp(1000000), true)
      assert.equals(-1, min_h)
      assert.equals(-1, min_t)
    end)

    it("[gate 2] 0xFFFFFFFE has DISABLE_FLAG (bit 31 set) — skipped", function()
      local tx = make_tx(2, {0xFFFFFFFE})
      local min_h, min_t = validation.calculate_sequence_locks(
        tx, 200, const_height(100), const_mtp(1000000), true)
      assert.equals(-1, min_h)
      assert.equals(-1, min_t)
    end)

    -- Gate 3: TYPE_FLAG determines time vs height
    -- Gate 6: height-based: min_height = max(min_height, coin_height + mask - 1)
    it("[gates 3,6] height-based lock: min_height = coin_height + lock_value - 1", function()
      -- seq = 10 (no TYPE_FLAG), UTXO at height 100
      -- Core: min_height = max(-1, 100 + 10 - 1) = 109
      local tx = make_tx(2, {10})
      local min_h, min_t = validation.calculate_sequence_locks(
        tx, 200, const_height(100), const_mtp(0), true)
      assert.equals(109, min_h)
      assert.equals(-1, min_t)
    end)

    it("[gates 3,6] height-based lock value = 0 → min_height = coin_height - 1", function()
      -- seq = 0 (height-based, no wait), UTXO at height 50
      -- min_height = max(-1, 50 + 0 - 1) = 49
      local tx = make_tx(2, {0})
      local min_h, min_t = validation.calculate_sequence_locks(
        tx, 200, const_height(50), const_mtp(0), true)
      assert.equals(49, min_h)
      assert.equals(-1, min_t)
    end)

    it("[gates 3,6] height-based lock value = 0xFFFF (max) → correct", function()
      -- max height lock: coin at height 1, lock = 65535 → min = 1 + 65535 - 1 = 65535
      local tx = make_tx(2, {MASK})  -- MASK = 0xFFFF
      local min_h, min_t = validation.calculate_sequence_locks(
        tx, 100000, const_height(1), const_mtp(0), true)
      assert.equals(65535, min_h)
      assert.equals(-1, min_t)
    end)

    -- Gate 4: time-based: coin_time = get_block_mtp(max(coin_height-1, 0))
    -- Gate 5: min_time = max(min_time, coin_time + (mask << GRAN) - 1)
    it("[gates 3,4,5] time-based lock: coin_time = MTP of block before UTXO block", function()
      -- seq = TYPE_FLAG | 10 → time-based, 10 * 512 = 5120 seconds
      -- UTXO at height 100 → query MTP at height 99
      -- Core: nCoinTime = GetAncestor(max(100-1,0)).GetMedianTimePast()
      -- min_time = max(-1, mtp_at_99 + 5120 - 1)
      local seq = bit.bor(TYPE_FLAG, 10)
      local tx = make_tx(2, {seq})
      local mtp_at_99 = 1600000000
      local function get_mtp(h)
        if h == 99 then return mtp_at_99 end
        return 0
      end
      local min_h, min_t = validation.calculate_sequence_locks(
        tx, 200, const_height(100), get_mtp, true)
      assert.equals(-1, min_h)
      assert.equals(mtp_at_99 + 10 * 512 - 1, min_t)
    end)

    it("[gate 4] genesis UTXO (coin_height=0): query MTP at height max(-1,0)=0", function()
      -- UTXO in genesis block (height 0) → query MTP at max(0-1, 0) = 0
      local seq = bit.bor(TYPE_FLAG, 1)
      local tx = make_tx(2, {seq})
      local mtp_at_0 = 1231006505  -- genesis timestamp
      local function get_mtp(h)
        if h == 0 then return mtp_at_0 end
        return 0
      end
      local min_h, min_t = validation.calculate_sequence_locks(
        tx, 200, const_height(0), get_mtp, true)
      assert.equals(-1, min_h)
      assert.equals(mtp_at_0 + 1 * 512 - 1, min_t)
    end)

    it("[gate 5] time-based lock value = 0xFFFF (max): correct seconds", function()
      -- max time lock: 65535 * 512 = 33553920 seconds
      local seq = bit.bor(TYPE_FLAG, MASK)
      local tx = make_tx(2, {seq})
      local coin_mtp = 1000000
      local expected_min_t = coin_mtp + 65535 * 512 - 1
      local min_h, min_t = validation.calculate_sequence_locks(
        tx, 200, const_height(10), const_mtp(coin_mtp), true)
      assert.equals(-1, min_h)
      assert.equals(expected_min_t, min_t)
    end)

    it("[gate 5] takes maximum across multiple time-based inputs", function()
      -- Input 1: TYPE_FLAG | 10, UTXO height 100, mtp@99 = 1000000 → 1005119
      -- Input 2: TYPE_FLAG | 5,  UTXO height 200, mtp@199 = 2000000 → 2002559
      -- max = 2002559
      local seq1 = bit.bor(TYPE_FLAG, 10)
      local seq2 = bit.bor(TYPE_FLAG, 5)
      local tx = make_tx(2, {seq1, seq2})
      local heights = {100, 200}
      local mtps = {[99] = 1000000, [199] = 2000000}
      local function get_h(inp)
        for i, inp2 in ipairs(tx.inputs) do
          if inp2 == inp then return heights[i] end
        end
      end
      local function get_mtp(h)
        return mtps[h] or 0
      end
      local min_h, min_t = validation.calculate_sequence_locks(
        tx, 300, get_h, get_mtp, true)
      assert.equals(-1, min_h)
      assert.equals(2000000 + 5 * 512 - 1, min_t)  -- 2002559
    end)

    it("[gates 3-6] mixed height and time locks take respective maxima", function()
      -- Input 1: height-based, 10 blocks, UTXO at 100 → min_height = 109
      -- Input 2: time-based, 10 units, UTXO at 50, mtp@49 = 1000000 → min_time = 1005119
      local tx = make_tx(2, {10, bit.bor(TYPE_FLAG, 10)})
      local heights = {100, 50}
      local function get_h(inp)
        for i, inp2 in ipairs(tx.inputs) do
          if inp2 == inp then return heights[i] end
        end
      end
      local function get_mtp(h)
        return (h == 49) and 1000000 or 0
      end
      local min_h, min_t = validation.calculate_sequence_locks(
        tx, 300, get_h, get_mtp, true)
      assert.equals(109, min_h)
      assert.equals(1005119, min_t)
    end)
  end)

  ---------------------------------------------------------------------------
  -- BIP-68 EvaluateSequenceLocks: gates 7-8 (tx_verify.cpp:97-105)
  ---------------------------------------------------------------------------
  describe("BIP-68 EvaluateSequenceLocks (check_sequence_locks)", function()

    -- Gate 7: lockPair.first >= block.nHeight → false
    it("[gate 7] fails when min_height >= block_height (strict less than required)", function()
      -- min_height = 110 (last invalid), block_height = 110: NOT valid (need > 110)
      assert.is_false(validation.check_sequence_locks(110, -1, 110, 9999))
    end)

    it("[gate 7] passes when min_height < block_height", function()
      -- min_height = 109, block_height = 110: valid (110 > 109)
      assert.is_true(validation.check_sequence_locks(109, -1, 110, 9999))
    end)

    it("[gate 7] fails when block_height is only 1 below min_height+1", function()
      -- min_height = 199 (last invalid), block_height = 199: fail
      assert.is_false(validation.check_sequence_locks(199, -1, 199, 9999))
    end)

    -- Gate 8: lockPair.second >= block.pprev->GetMedianTimePast() → false
    -- (BIP-113: the MTP used is that of the previous block)
    it("[gate 8] fails when min_time >= prev_block_mtp", function()
      -- min_time = 1005119, prev_mtp = 1005119: NOT valid (need > 1005119)
      assert.is_false(validation.check_sequence_locks(-1, 1005119, 200, 1005119))
    end)

    it("[gate 8] passes when min_time < prev_block_mtp (BIP-113 MTP)", function()
      -- min_time = 1005119, prev_mtp = 1005120: valid
      assert.is_true(validation.check_sequence_locks(-1, 1005119, 200, 1005120))
    end)

    it("[gates 7,8] passes with -1,-1 (no locks) even at genesis", function()
      assert.is_true(validation.check_sequence_locks(-1, -1, 0, 0))
    end)

    it("[gates 7,8] fails when height locked but time not", function()
      -- min_height = 200, block_height = 199 → fail
      assert.is_false(validation.check_sequence_locks(200, -1, 199, 9999))
    end)

    it("[gates 7,8] fails when time locked but height ok", function()
      -- min_time = 2000000, prev_mtp = 1999999 → fail
      assert.is_false(validation.check_sequence_locks(-1, 2000000, 1000, 1999999))
    end)

    -- Integration: calculate → check round-trip
    it("[integration] height-based: locked for exactly 10 blocks", function()
      -- UTXO at height 100, seq = 10 blocks, BIP-68 active
      -- min_height = 109; valid at block 110+
      local tx = make_tx(2, {10})
      local min_h, min_t = validation.calculate_sequence_locks(
        tx, 200, const_height(100), const_mtp(0), true)
      -- Block 109: min_height(109) >= block_height(109) → FAIL
      assert.is_false(validation.check_sequence_locks(min_h, min_t, 109, 0))
      -- Block 110: min_height(109) < block_height(110) → PASS
      assert.is_true(validation.check_sequence_locks(min_h, min_t, 110, 0))
    end)

    it("[integration] time-based: locked until 512 seconds after UTXO MTP", function()
      -- UTXO at height 100, seq = TYPE_FLAG|1 (512 seconds), MTP@99 = 1000000
      -- min_time = 1000000 + 512 - 1 = 1000511
      -- Valid when prev_block_mtp >= 1000512
      local seq = bit.bor(TYPE_FLAG, 1)
      local tx = make_tx(2, {seq})
      local function get_mtp(h)
        return (h == 99) and 1000000 or 0
      end
      local min_h, min_t = validation.calculate_sequence_locks(
        tx, 200, const_height(100), get_mtp, true)
      assert.equals(1000511, min_t)
      -- prev_mtp = 1000511: NOT valid (1000511 >= 1000511)
      assert.is_false(validation.check_sequence_locks(min_h, min_t, 200, 1000511))
      -- prev_mtp = 1000512: valid
      assert.is_true(validation.check_sequence_locks(min_h, min_t, 200, 1000512))
    end)
  end)

  ---------------------------------------------------------------------------
  -- BIP-112 CheckSequence: gates 9-13 (interpreter.cpp:1782-1825)
  -- Tested for all three checker implementations (make_sig_checker,
  -- make_tapscript_checker, make_collecting_sig_checker)
  ---------------------------------------------------------------------------
  describe("BIP-112 CheckSequence via make_sig_checker", function()

    -- Helper: make checker for input 0 of tx
    local function make_checker(tx)
      return validation.make_sig_checker(tx, 0, 50000, "", {})
    end

    -- Gate 9: tx.version < 2 → false (Core: interpreter.cpp:1789-1791)
    it("[gate 9] returns false when tx.version < 2", function()
      local tx = make_tx(1, {100})
      assert.is_false(make_checker(tx).check_sequence(10))
    end)

    it("[gate 9] returns false even when script sequence = 0 and version = 1", function()
      local tx = make_tx(1, {100})
      assert.is_false(make_checker(tx).check_sequence(0))
    end)

    -- Gate 10: txToSequence & DISABLE_FLAG → false (interpreter.cpp:1796-1798)
    it("[gate 10] returns false when input sequence has DISABLE_FLAG", function()
      -- Input has DISABLE_FLAG → fail CSV even if script doesn't
      local tx = make_tx(2, {bit.bor(DISABLE_FLAG, 10)})
      assert.is_false(make_checker(tx).check_sequence(5))
    end)

    it("[gate 10] SEQUENCE_FINAL in input → false", function()
      local tx = make_tx(2, {SEQUENCE_FINAL})
      assert.is_false(make_checker(tx).check_sequence(5))
    end)

    it("[gate 10] 0xFFFFFFFE in input (DISABLE_FLAG set) → false", function()
      local tx = make_tx(2, {0xFFFFFFFE})
      assert.is_false(make_checker(tx).check_sequence(5))
    end)

    -- Gate 11/12: type-mismatch → false (interpreter.cpp:1813-1818)
    it("[gate 12] fails when script is time-based but input is height-based", function()
      -- Script: TYPE_FLAG | 10 (time), Input: 10 (height)
      local tx = make_tx(2, {10})
      assert.is_false(make_checker(tx).check_sequence(bit.bor(TYPE_FLAG, 10)))
    end)

    it("[gate 12] fails when script is height-based but input is time-based", function()
      -- Script: 10 (height), Input: TYPE_FLAG | 20 (time)
      local tx = make_tx(2, {bit.bor(TYPE_FLAG, 20)})
      assert.is_false(make_checker(tx).check_sequence(10))
    end)

    -- Gate 13: nSequenceMasked > txToSequenceMasked → false (interpreter.cpp:1822-1823)
    it("[gate 13] fails when script sequence value > input sequence value", function()
      local tx = make_tx(2, {100})
      assert.is_false(make_checker(tx).check_sequence(101))
    end)

    it("[gate 13] passes when script value == input value (equal is valid)", function()
      local tx = make_tx(2, {100})
      assert.is_true(make_checker(tx).check_sequence(100))
    end)

    it("[gate 13] passes when script value < input value", function()
      local tx = make_tx(2, {100})
      assert.is_true(make_checker(tx).check_sequence(50))
    end)

    it("[gate 13] passes when script value = 0 (no wait)", function()
      -- Script pushes 0: min lock time satisfied by any non-disabled input
      local tx = make_tx(2, {1})
      assert.is_true(make_checker(tx).check_sequence(0))
    end)

    -- Script sequence disable flag (gate 14 equivalent in CheckSequence)
    it("[script DISABLE_FLAG] passes (NOP) when script sequence has DISABLE_FLAG", function()
      -- BIP-112: if script_sequence & DISABLE_FLAG → behaves as NOP (pass)
      local tx = make_tx(2, {10})
      assert.is_true(make_checker(tx).check_sequence(bit.bor(DISABLE_FLAG, 10)))
    end)

    -- Time-based comparison
    it("[gate 13] time-based: passes when script time <= input time", function()
      -- Script: TYPE_FLAG | 5, Input: TYPE_FLAG | 10
      local script_seq = bit.bor(TYPE_FLAG, 5)
      local inp_seq = bit.bor(TYPE_FLAG, 10)
      local tx = make_tx(2, {inp_seq})
      assert.is_true(make_checker(tx).check_sequence(script_seq))
    end)

    it("[gate 13] time-based: fails when script time > input time", function()
      -- Script: TYPE_FLAG | 11, Input: TYPE_FLAG | 10
      local script_seq = bit.bor(TYPE_FLAG, 11)
      local inp_seq = bit.bor(TYPE_FLAG, 10)
      local tx = make_tx(2, {inp_seq})
      assert.is_false(make_checker(tx).check_sequence(script_seq))
    end)

    it("[gate 13] time-based: passes when equal", function()
      local s = bit.bor(TYPE_FLAG, 10)
      local tx = make_tx(2, {s})
      assert.is_true(make_checker(tx).check_sequence(s))
    end)
  end)

  ---------------------------------------------------------------------------
  -- BIP-112 CheckSequence via make_tapscript_checker
  -- Tapscript also uses CSV; same 21 gates apply.
  ---------------------------------------------------------------------------
  describe("BIP-112 CheckSequence via make_tapscript_checker", function()

    local function make_tapchecker(tx)
      -- Minimal prev_outputs for tapscript checker
      local prev_outputs = {}
      for i = 1, #tx.inputs do
        prev_outputs[i] = {value = 50000, script_pubkey = ""}
      end
      -- tapleaf_hash = 32 zero bytes (test only)
      local tapleaf_hash = string.rep("\x00", 32)
      return validation.make_tapscript_checker(tx, 0, prev_outputs, tapleaf_hash, nil)
    end

    -- Gate 9: tx.version < 2 → false
    it("[gate 9] returns false when tx.version < 2 (tapscript)", function()
      local tx = make_tx(1, {100})
      assert.is_false(make_tapchecker(tx).check_sequence(10))
    end)

    -- Gate 10: input DISABLE_FLAG → false
    it("[gate 10] input with DISABLE_FLAG returns false (tapscript)", function()
      local tx = make_tx(2, {bit.bor(DISABLE_FLAG, 10)})
      assert.is_false(make_tapchecker(tx).check_sequence(5))
    end)

    -- Gate 12: type mismatch → false
    it("[gate 12] type mismatch fails (tapscript)", function()
      local tx = make_tx(2, {10})  -- height-based
      assert.is_false(make_tapchecker(tx).check_sequence(bit.bor(TYPE_FLAG, 5)))
    end)

    -- Gate 13: script > input → false
    it("[gate 13] script value > input value fails (tapscript)", function()
      local tx = make_tx(2, {100})
      assert.is_false(make_tapchecker(tx).check_sequence(101))
    end)

    it("[gate 13] script value <= input value passes (tapscript)", function()
      local tx = make_tx(2, {100})
      assert.is_true(make_tapchecker(tx).check_sequence(100))
      assert.is_true(make_tapchecker(tx).check_sequence(50))
    end)

    it("[script DISABLE_FLAG] NOP when script has DISABLE_FLAG (tapscript)", function()
      local tx = make_tx(2, {10})
      assert.is_true(make_tapchecker(tx).check_sequence(bit.bor(DISABLE_FLAG, 10)))
    end)
  end)

  ---------------------------------------------------------------------------
  -- BIP-112 CheckSequence via make_collecting_sig_checker
  ---------------------------------------------------------------------------
  describe("BIP-112 CheckSequence via make_collecting_sig_checker", function()

    local function make_collect_checker(tx)
      local collector = {}
      return validation.make_collecting_sig_checker(
        tx, 0, 50000, "", {}, collector, nil, false)
    end

    -- Gate 9
    it("[gate 9] returns false when tx.version < 2 (collecting)", function()
      local tx = make_tx(1, {100})
      assert.is_false(make_collect_checker(tx).check_sequence(10))
    end)

    -- Gate 10
    it("[gate 10] input DISABLE_FLAG → false (collecting)", function()
      local tx = make_tx(2, {bit.bor(DISABLE_FLAG, 5)})
      assert.is_false(make_collect_checker(tx).check_sequence(1))
    end)

    -- Gate 12
    it("[gate 12] type mismatch → false (collecting)", function()
      local tx = make_tx(2, {10})
      assert.is_false(make_collect_checker(tx).check_sequence(bit.bor(TYPE_FLAG, 5)))
    end)

    -- Gate 13
    it("[gate 13] script > input → false (collecting)", function()
      local tx = make_tx(2, {50})
      assert.is_false(make_collect_checker(tx).check_sequence(51))
    end)

    it("[gate 13] script <= input → true (collecting)", function()
      local tx = make_tx(2, {50})
      assert.is_true(make_collect_checker(tx).check_sequence(50))
    end)

    it("[script DISABLE_FLAG] NOP when script has DISABLE_FLAG (collecting)", function()
      local tx = make_tx(2, {10})
      assert.is_true(make_collect_checker(tx).check_sequence(bit.bor(DISABLE_FLAG, 10)))
    end)
  end)

  ---------------------------------------------------------------------------
  -- BIP-112 OP_CHECKSEQUENCEVERIFY opcode: gates 14-19
  -- (interpreter.cpp:561-593)
  ---------------------------------------------------------------------------
  describe("BIP-112 OP_CHECKSEQUENCEVERIFY opcode gates", function()

    -- Build a minimal checker that controls check_sequence outcome
    local function make_mock_checker(version, inp_seq)
      local tx = make_tx(version, {inp_seq})
      return validation.make_sig_checker(tx, 0, 50000, "", {})
    end

    -- Gate 14: CSV flag not set → NOP3 (no stack change, no error)
    it("[gate 14] OP_CSV acts as NOP3 when verify_checksequenceverify=false", function()
      -- Build a script: PUSH(10) OP_CHECKSEQUENCEVERIFY OP_DROP OP_1
      -- Without CSV flag, CSV is a NOP → stack retains 10, DROP removes it, OP_1 pushes 1
      local tx = make_tx(2, {100})
      local checker = validation.make_sig_checker(tx, 0, 50000, "", {})
      local flags_no_csv = { verify_checksequenceverify = false }
      local csv_op = string.char(script.OP.OP_CHECKSEQUENCEVERIFY)
      local drop_op = string.char(script.OP.OP_DROP)
      local op1 = string.char(script.OP.OP_1)
      local scr = string.char(1, 10) .. csv_op .. drop_op .. op1
      -- execute_script(script_bytes, stack, flags, checker)
      local ok, result = pcall(script.execute_script, scr, {}, flags_no_csv, checker)
      assert.is_true(ok, "should not throw: " .. tostring(result))
    end)

    -- Gate 14: CSV + discourage_upgradable_nops → fail
    it("[gate 14] OP_CSV with discourage_nops raises error when CSV disabled", function()
      local tx = make_tx(2, {100})
      local checker = validation.make_sig_checker(tx, 0, 50000, "", {})
      local flags = { verify_checksequenceverify = false,
                      verify_discourage_upgradable_nops = true }
      local csv_op = string.char(script.OP.OP_CHECKSEQUENCEVERIFY)
      local scr = string.char(1, 10) .. csv_op
      -- execute_script(script_bytes, stack, flags, checker)
      local ok, err = pcall(script.execute_script, scr, {}, flags, checker)
      assert.is_false(ok)
    end)

    -- Gate 17: negative sequence → error
    it("[gate 17] OP_CSV with negative value on stack raises error", function()
      local tx = make_tx(2, {100})
      local checker = validation.make_sig_checker(tx, 0, 50000, "", {})
      local flags = { verify_checksequenceverify = true }
      -- Push -1 onto stack: OP_1NEGATE = 0x4f
      local op_neg1 = string.char(0x4f)
      local csv_op = string.char(script.OP.OP_CHECKSEQUENCEVERIFY)
      local scr = op_neg1 .. csv_op
      -- execute_script(script_bytes, stack, flags, checker)
      local ok, err = pcall(script.execute_script, scr, {}, flags, checker)
      assert.is_false(ok, "negative sequence should fail: " .. tostring(err))
    end)

    -- Gate 18: DISABLE_FLAG in script value → NOP (pass through)
    it("[gate 18] OP_CSV with DISABLE_FLAG in script value is a NOP", function()
      -- A positive 5-byte push where bit 31 of the value is set:
      -- value = 0x80000000 = 2147483648; encoded in 5 bytes as 00 00 00 80 00
      -- (last byte 0x00 avoids sign bit, so positive)
      local tx = make_tx(2, {100})
      local checker = validation.make_sig_checker(tx, 0, 50000, "", {})
      local flags = { verify_checksequenceverify = true }
      local seq_val_bytes = "\x00\x00\x00\x80\x00"  -- little-endian 2147483648, 5 bytes
      local push5 = string.char(5) .. seq_val_bytes
      local csv_op = string.char(script.OP.OP_CHECKSEQUENCEVERIFY)
      local drop_op = string.char(script.OP.OP_DROP)
      local op1 = string.char(script.OP.OP_1)
      local scr = push5 .. csv_op .. drop_op .. op1
      -- execute_script(script_bytes, stack, flags, checker)
      local ok, err = pcall(script.execute_script, scr, {}, flags, checker)
      assert.is_true(ok, "CSV with DISABLE_FLAG should be NOP: " .. tostring(err))
    end)

    -- Gate 19: check_sequence fails → UNSATISFIED_LOCKTIME
    it("[gate 19] OP_CSV fails when lock condition not met", function()
      -- Input sequence = 10, script requires 100 → fail
      local tx = make_tx(2, {10})
      local checker = validation.make_sig_checker(tx, 0, 50000, "", {})
      local flags = { verify_checksequenceverify = true }
      local push100 = string.char(1, 100)
      local csv_op = string.char(script.OP.OP_CHECKSEQUENCEVERIFY)
      local scr = push100 .. csv_op
      -- execute_script(script_bytes, stack, flags, checker)
      local ok, err = pcall(script.execute_script, scr, {}, flags, checker)
      assert.is_false(ok, "should fail: script requires 100, input has 10")
    end)

    it("[gate 19] OP_CSV passes when lock condition met", function()
      -- Input sequence = 100, script requires 10 → pass
      local tx = make_tx(2, {100})
      local checker = validation.make_sig_checker(tx, 0, 50000, "", {})
      local flags = { verify_checksequenceverify = true }
      local push10 = string.char(1, 10)
      local csv_op = string.char(script.OP.OP_CHECKSEQUENCEVERIFY)
      local drop_op = string.char(script.OP.OP_DROP)
      local op1 = string.char(script.OP.OP_1)
      local scr = push10 .. csv_op .. drop_op .. op1
      -- execute_script(script_bytes, stack, flags, checker)
      local ok, err = pcall(script.execute_script, scr, {}, flags, checker)
      assert.is_true(ok, "should pass: " .. tostring(err))
    end)
  end)

  ---------------------------------------------------------------------------
  -- BIP-113 Median Time Past: gates 20-21
  -- (chain.h:231-244 + tx_verify.cpp:97-104)
  ---------------------------------------------------------------------------
  describe("BIP-113 Median Time Past", function()

    -- Gate 20: 11 block window, returns middle element
    it("[gate 20] MTP of 11 timestamps is the 6th in sorted order", function()
      -- sorted: 1,3,5,7,9,11,13,15,17,19,21 → index 6 = 11
      local ts = {21, 1, 19, 3, 17, 5, 15, 7, 13, 9, 11}
      assert.equals(11, consensus.get_median_time_past(ts))
    end)

    it("[gate 20] MTP of 9 timestamps is the 5th in sorted order", function()
      -- 9 elements: floor(9/2)+1 = 5th; sorted {1,2,3,4,5,6,7,8,9} → 5
      local ts = {9, 7, 5, 3, 1, 2, 4, 6, 8}
      assert.equals(5, consensus.get_median_time_past(ts))
    end)

    it("[gate 20] MTP of 1 timestamp is that timestamp", function()
      assert.equals(9999, consensus.get_median_time_past({9999}))
    end)

    it("[gate 20] constant timestamps → returns that value", function()
      local ts = {}
      for i = 1, 11 do ts[i] = 1234567890 end
      assert.equals(1234567890, consensus.get_median_time_past(ts))
    end)

    -- Gate 21: EvaluateSequenceLocks uses MTP of PREV block (BIP-113)
    -- Core: block.pprev->GetMedianTimePast() at tx_verify.cpp:100
    it("[gate 21] check_sequence_locks uses prev_block_mtp (BIP-113 context)", function()
      -- min_time = T; must satisfy T < prev_block_mtp (prev block's MTP)
      -- Simulating: block being validated is at height H; we pass in the
      -- pre-computed MTP of the previous block as prev_block_mtp.
      local T = 1600000000
      -- prev_block_mtp = T: fail (T >= T)
      assert.is_false(validation.check_sequence_locks(-1, T, 500, T))
      -- prev_block_mtp = T+1: pass (T < T+1)
      assert.is_true(validation.check_sequence_locks(-1, T, 500, T + 1))
    end)

    it("[gate 21] time lock uses MTP not block timestamp (BIP-113 isolation)", function()
      -- This verifies the interface contract: check_sequence_locks takes
      -- prev_block_mtp, not raw block timestamp. The caller (connect_block)
      -- must provide the correctly-computed MTP.
      -- min_time = 1000511, prev_mtp = 1000512 → pass
      assert.is_true(validation.check_sequence_locks(-1, 1000511, 200, 1000512))
      -- min_time = 1000511, prev_mtp = 1000511 → fail (BIP-113 strict <)
      assert.is_false(validation.check_sequence_locks(-1, 1000511, 200, 1000511))
    end)

    -- MTP MEDIAN_TIME_PAST_BLOCKS constant
    it("[gate 20] MEDIAN_TIME_PAST_BLOCKS constant is 11", function()
      assert.equals(11, consensus.MEDIAN_TIME_PAST_BLOCKS)
    end)
  end)

  ---------------------------------------------------------------------------
  -- Edge cases and LuaJIT-specific tests
  ---------------------------------------------------------------------------
  describe("LuaJIT bit-op edge cases for BIP-68", function()

    it("bit.band with DISABLE_FLAG returns non-zero for 0xFFFFFFFF", function()
      -- LuaJIT signed 32-bit: 0xFFFFFFFF → -1; bit.band(-1, -2147483648) = -2147483648
      -- -2147483648 ~= 0 → sequence_locks_active returns false
      assert.is_false(consensus.sequence_locks_active(0xFFFFFFFF))
    end)

    it("bit.band with DISABLE_FLAG returns zero for 0x7FFFFFFF", function()
      -- 0x7FFFFFFF has bit 31 clear → active
      assert.is_true(consensus.sequence_locks_active(0x7FFFFFFF))
    end)

    it("bit.lshift for max time lock value does not overflow 32-bit signed range", function()
      -- 0xFFFF << 9 = 33553920, fits in 32-bit signed (max 2147483647)
      local bit = require("bit")
      local lock_seconds = bit.lshift(0xFFFF, 9)
      assert.equals(33553920, lock_seconds)
      assert.is_true(lock_seconds > 0, "must be positive (no 32-bit overflow)")
    end)

    it("coin_time + max_lock_seconds arithmetic stays in float64", function()
      -- Largest realistic coin_time + max lock_seconds
      -- coin_time ~ 2^31 (unix 2038), lock_seconds = 33553920
      local bit = require("bit")
      local coin_time = 2147483647  -- max int32 timestamp
      local lock_seconds = bit.lshift(0xFFFF, 9)  -- 33553920
      local result = coin_time + lock_seconds - 1
      -- Expected: 2181037566; float64 can represent up to 2^53 exactly
      assert.equals(2147483647 + 33553920 - 1, result)
    end)

    it("sequence_lock_value extracts lower 16 bits only", function()
      -- Bits 16-21 and 22+ should be masked out
      assert.equals(0, consensus.sequence_lock_value(0xFFFF0000))
      assert.equals(0xFFFF, consensus.sequence_lock_value(0xFFFF))
      assert.equals(0x1234, consensus.sequence_lock_value(0x00401234))
    end)

    it("TYPE_FLAG detection is correct for both height and time types", function()
      assert.is_false(consensus.sequence_lock_is_time_based(0x00000001))  -- height
      assert.is_false(consensus.sequence_lock_is_time_based(0x003FFFFF))  -- height (no TYPE_FLAG)
      assert.is_true(consensus.sequence_lock_is_time_based(0x00400000))   -- time (TYPE_FLAG only)
      assert.is_true(consensus.sequence_lock_is_time_based(0x004000FF))   -- time
    end)
  end)
end)
