-- W81: BIP-65 CHECKLOCKTIMEVERIFY + IsFinalTx + BIP-113 MTP comprehensive test
-- Reference: bitcoin-core/src/script/interpreter.cpp:522-558, :1745-1779
--            bitcoin-core/src/consensus/tx_verify.cpp:17-37
--            bitcoin-core/src/script/script.h:47 (LOCKTIME_THRESHOLD=500_000_000)
--            bitcoin-core/src/primitives/transaction.h:72 (SEQUENCE_FINAL=0xFFFFFFFF)
--
-- Gates tested (15 total):
-- BIP-65 opcode gates 1-5 (interpreter.cpp:522-558)
-- CheckLockTime gates 6-10 (interpreter.cpp:1745-1779)
-- IsFinalTx gates 11-15 (tx_verify.cpp:17-37)

describe("BIP-65 CLTV + IsFinalTx + BIP-113 (W81)", function()
  local validation
  local types
  local consensus
  local script
  local mining
  local bit

  local LOCKTIME_THRESHOLD = 500000000  -- script.h:47
  local SEQUENCE_FINAL = 0xFFFFFFFF     -- transaction.h:72

  setup(function()
    bit = require("bit")
    package.path = "src/?.lua;" .. package.path
    package.preload["lunarblock.types"]     = function() return require("types") end
    package.preload["lunarblock.serialize"] = function() return require("serialize") end
    package.preload["lunarblock.crypto"]    = function() return require("crypto") end
    package.preload["lunarblock.script"]    = function() return require("script") end
    package.preload["lunarblock.consensus"] = function() return require("consensus") end
    package.preload["lunarblock.validation"] = function() return require("validation") end
    package.preload["lunarblock.mining"]    = function() return require("mining") end
    types      = require("types")
    validation = require("validation")
    consensus  = require("consensus")
    script     = require("script")
    mining     = require("mining")
  end)

  ---------------------------------------------------------------------------
  -- Helpers
  ---------------------------------------------------------------------------

  -- Make a minimal transaction with given locktime and per-input sequences.
  local function make_tx(locktime, sequences, version)
    version = version or 1
    local tx = types.transaction(version, {}, {}, locktime)
    for i, seq in ipairs(sequences) do
      local h = types.hash256(string.rep(string.char(i), 32))
      tx.inputs[i] = types.txin(types.outpoint(h, 0), "\x00", seq)
    end
    tx.outputs[1] = types.txout(50000, string.rep("\x00", 25))
    return tx
  end

  -- Build a checker that mirrors make_sig_checker semantics for test.
  -- Uses validation.make_sig_checker with a fake P2PKH prev_output.
  local function make_checker(tx, input_idx)
    input_idx = input_idx or 0
    local prev_output_value = 50000
    local prev_script_pubkey = string.rep("\x00", 25)
    local flags = { verify_checklocktimeverify = true }
    return validation.make_sig_checker(
      tx, input_idx, prev_output_value, prev_script_pubkey, flags)
  end

  -- Build a script: <locktime_bytes> OP_CHECKLOCKTIMEVERIFY
  -- Returns the binary script to execute.
  local function cltv_script(locktime_num)
    local locktime_bytes = script.script_num_encode(locktime_num)
    -- OP_PUSHDATA for locktime_bytes (length 1-5)
    local push_op
    if #locktime_bytes == 0 then
      push_op = "\x00"  -- OP_0
    else
      push_op = string.char(#locktime_bytes) .. locktime_bytes  -- OP_PUSHDATA1..5
    end
    return push_op .. "\xb1"  -- 0xb1 = OP_CHECKLOCKTIMEVERIFY
  end

  -- Execute a CLTV script with given tx and input_index.
  -- Returns ok (bool), err (string or nil).
  local function run_cltv(tx, locktime_num, input_idx)
    input_idx = input_idx or 0
    local prev_output_value = 50000
    local prev_script_pubkey = string.rep("\x00", 25)
    local flags = {
      verify_checklocktimeverify = true,
      verify_minimaldata = false,
    }
    local checker = validation.make_sig_checker(
      tx, input_idx, prev_output_value, prev_script_pubkey, flags)
    local sc = cltv_script(locktime_num)
    local ok, err = pcall(function()
      script.execute_script(sc, {}, flags, checker)
    end)
    if ok then
      return true, nil
    else
      return false, tostring(err)
    end
  end

  ---------------------------------------------------------------------------
  -- Gate 1: OP_CHECKLOCKTIMEVERIFY stack-empty check
  -- interpreter.cpp:529-530: SCRIPT_ERR_INVALID_STACK_OPERATION
  ---------------------------------------------------------------------------
  describe("gate 1: empty stack → error", function()
    it("CLTV on empty stack raises error", function()
      local tx = make_tx(100, {0})
      local flags = { verify_checklocktimeverify = true }
      local checker = make_checker(tx, 0)
      local ok, err = pcall(function()
        -- Script: just OP_CHECKLOCKTIMEVERIFY, no locktime push
        script.execute_script("\xb1", {}, flags, checker)
      end)
      assert.is_false(ok, "expected error on empty stack")
      assert.truthy(err:find("CHECKLOCKTIMEVERIFY") or err:find("stack"))
    end)
  end)

  ---------------------------------------------------------------------------
  -- Gate 2: 5-byte CScriptNum (not 4-byte limit)
  -- interpreter.cpp:546: CScriptNum nLockTime(stacktop(-1), fRequireMinimal, 5)
  -- 5-byte numbers allow up to 2^39-1, avoiding year-2038 problem.
  ---------------------------------------------------------------------------
  describe("gate 2: 5-byte script number for locktime", function()
    it("accepts 5-byte encoded locktime (> 2^31)", function()
      -- 0x80000001 encoded as 5-byte: \x01\x00\x00\x00\x80\x00 (sign byte)
      -- Use a concrete 5-byte encoding: value = 0x100000000 = 4294967296
      -- Encoded as 5 bytes: \x00\x00\x00\x00\x01 (little-endian, no sign bit)
      -- tx.locktime must be >= value for the check to pass, but locktime is uint32 (max 4294967295)
      -- So any 5-byte value > 0xFFFFFFFF will fail because tx.locktime can't match.
      -- The gate is: the decode succeeds (no "script number too long" error).
      -- Test: encode 4_000_000_000 as 5-byte push → decode must succeed (not throw "too long")
      local val = 4000000000  -- > 2^31, needs 5 bytes
      local locktime_bytes = script.script_num_encode(val)
      assert.equals(5, #locktime_bytes, "4000000000 requires 5 bytes")
      local decoded = script.script_num_decode(locktime_bytes, 5, false)
      assert.equals(val, decoded)
    end)

    it("4-byte limit would reject locktime > 2^31; 5-byte allows it", function()
      local val = 2200000000  -- > 2^31, fits in 5 bytes
      local locktime_bytes = script.script_num_encode(val)
      -- With 4-byte limit: error
      local ok4 = pcall(function()
        script.script_num_decode(locktime_bytes, 4, false)
      end)
      assert.is_false(ok4, "4-byte limit should reject > 2^31 encodings")
      -- With 5-byte limit: succeeds
      local val5 = script.script_num_decode(locktime_bytes, 5, false)
      assert.equals(val, val5)
    end)
  end)

  ---------------------------------------------------------------------------
  -- Gate 3: CLTV does NOT consume the stack top
  -- interpreter.cpp: stacktop(-1) is read-only; stack remains unchanged.
  ---------------------------------------------------------------------------
  describe("gate 3: CLTV leaves stack unchanged (peek, not pop)", function()
    it("stack top is unchanged after successful CLTV", function()
      -- tx.locktime = 1000, script_locktime = 500: CLTV passes
      local tx = make_tx(1000, {0})
      local flags = { verify_checklocktimeverify = true, verify_minimaldata = false }
      local checker = make_checker(tx, 0)
      -- Initial stack: push the locktime value 500
      local initial_stack = { script.script_num_encode(500) }
      local stack_copy = { initial_stack[1] }
      -- Execute just OP_CHECKLOCKTIMEVERIFY (0xb1) directly
      local ok, err = pcall(function()
        script.execute_script("\xb1", initial_stack, flags, checker)
      end)
      assert.is_true(ok, "CLTV should succeed: " .. tostring(err))
      -- Stack must still contain the original element unchanged
      assert.equals(1, #initial_stack, "stack should still have 1 element")
      assert.equals(stack_copy[1], initial_stack[1],
        "stack top bytes must be unchanged (peek, not pop+re-encode)")
    end)

    it("non-minimal encoded locktime bytes are preserved on stack", function()
      -- Non-minimal encoding: 0x64\x00 for value 100 (minimal would be 0x64)
      -- With verify_minimaldata=false, decode should succeed and stack should be
      -- left with the ORIGINAL bytes (not re-encoded to minimal form).
      local tx = make_tx(1000, {0})
      local flags = { verify_checklocktimeverify = true, verify_minimaldata = false }
      local checker = make_checker(tx, 0)
      local non_minimal = "\x64\x00"  -- non-minimal encoding of 100
      local initial_stack = { non_minimal }
      local ok, err = pcall(function()
        script.execute_script("\xb1", initial_stack, flags, checker)
      end)
      assert.is_true(ok, "CLTV should succeed: " .. tostring(err))
      assert.equals(1, #initial_stack, "stack should still have 1 element")
      assert.equals(non_minimal, initial_stack[1],
        "non-minimal bytes must be preserved (stack not re-encoded)")
    end)
  end)

  ---------------------------------------------------------------------------
  -- Gate 4: negative locktime → SCRIPT_ERR_NEGATIVE_LOCKTIME
  -- interpreter.cpp:551-552: if (nLockTime < 0) → error
  ---------------------------------------------------------------------------
  describe("gate 4: negative locktime rejected", function()
    it("rejects script_locktime = -1", function()
      local tx = make_tx(100, {0})
      local flags = { verify_checklocktimeverify = true }
      local checker = make_checker(tx, 0)
      -- Push -1 onto stack then run CLTV
      local stk = { script.script_num_encode(-1) }
      local ok, err = pcall(function()
        script.execute_script("\xb1", stk, flags, checker)
      end)
      assert.is_false(ok, "negative locktime must fail")
      assert.truthy(tostring(err):find("negative") or tostring(err):find("locktime"))
    end)

    it("rejects script_locktime = -1000", function()
      local tx = make_tx(100, {0})
      local flags = { verify_checklocktimeverify = true }
      local checker = make_checker(tx, 0)
      local stk = { script.script_num_encode(-1000) }
      local ok = pcall(function()
        script.execute_script("\xb1", stk, flags, checker)
      end)
      assert.is_false(ok, "negative locktime must fail")
    end)
  end)

  ---------------------------------------------------------------------------
  -- Gate 5: CLTV disabled acts as NOP2
  -- interpreter.cpp:524-527
  ---------------------------------------------------------------------------
  describe("gate 5: CLTV inactive → NOP2 (no-op)", function()
    it("CLTV with verify_checklocktimeverify=false acts as NOP (passes)", function()
      -- Even if locktime would fail, when CLTV is disabled it's NOP
      local tx = make_tx(100, {SEQUENCE_FINAL})  -- would fail CLTV
      local flags = { verify_checklocktimeverify = false }
      local checker = make_checker(tx, 0)
      -- Stack with locktime 9999 (would fail: > tx.locktime=100, and SEQUENCE_FINAL)
      local stk = { script.script_num_encode(9999) }
      local ok = pcall(function()
        script.execute_script("\xb1", stk, flags, checker)
      end)
      assert.is_true(ok, "CLTV disabled = NOP, must not fail")
      -- Stack top must remain unchanged
      assert.equals(1, #stk)
    end)
  end)

  ---------------------------------------------------------------------------
  -- CheckLockTime gate 6: SEQUENCE_FINAL → fail
  -- interpreter.cpp:1775-1776: if (SEQUENCE_FINAL == vin[nIn].nSequence) return false
  ---------------------------------------------------------------------------
  describe("gate 6: CheckLockTime — SEQUENCE_FINAL input → fail", function()
    it("check_locktime fails when input sequence is 0xFFFFFFFF", function()
      local tx = make_tx(100, {SEQUENCE_FINAL})
      local checker = make_checker(tx, 0)
      assert.is_false(checker.check_locktime(50))
    end)

    it("check_locktime passes when input sequence is not SEQUENCE_FINAL", function()
      local tx = make_tx(100, {0xFFFFFFFE})
      local checker = make_checker(tx, 0)
      assert.is_true(checker.check_locktime(50))
    end)

    it("CLTV execution fails when input nSequence == SEQUENCE_FINAL", function()
      local tx = make_tx(100, {SEQUENCE_FINAL})
      local ok, err = run_cltv(tx, 50, 0)
      assert.is_false(ok, "SEQUENCE_FINAL input must cause CLTV failure")
    end)
  end)

  ---------------------------------------------------------------------------
  -- CheckLockTime gate 7: type mismatch (height vs time)
  -- interpreter.cpp:1754-1758: types must match (both < threshold or both >= threshold)
  ---------------------------------------------------------------------------
  describe("gate 7: CheckLockTime — type mismatch → fail", function()
    it("fails when script is height-based but tx.locktime is time-based", function()
      -- script_locktime = 100 (height), tx.locktime = 500000001 (time)
      local tx = make_tx(500000001, {0})
      local checker = make_checker(tx, 0)
      assert.is_false(checker.check_locktime(100),
        "height script vs time tx must fail")
    end)

    it("fails when script is time-based but tx.locktime is height-based", function()
      -- script_locktime = 500000001 (time), tx.locktime = 100 (height)
      local tx = make_tx(100, {0})
      local checker = make_checker(tx, 0)
      assert.is_false(checker.check_locktime(500000001),
        "time script vs height tx must fail")
    end)

    it("passes when both are height-based", function()
      local tx = make_tx(200, {0})
      local checker = make_checker(tx, 0)
      assert.is_true(checker.check_locktime(100))
    end)

    it("passes when both are time-based", function()
      local tx = make_tx(500000100, {0})
      local checker = make_checker(tx, 0)
      assert.is_true(checker.check_locktime(500000001))
    end)
  end)

  ---------------------------------------------------------------------------
  -- CheckLockTime gate 8: script_locktime <= tx_locktime
  -- interpreter.cpp:1762-1763: if (nLockTime > txTo->nLockTime) return false
  ---------------------------------------------------------------------------
  describe("gate 8: CheckLockTime — value comparison", function()
    it("fails when script_locktime > tx_locktime (height)", function()
      local tx = make_tx(100, {0})
      local checker = make_checker(tx, 0)
      assert.is_false(checker.check_locktime(101))
    end)

    it("passes when script_locktime == tx_locktime (height)", function()
      local tx = make_tx(100, {0})
      local checker = make_checker(tx, 0)
      assert.is_true(checker.check_locktime(100))
    end)

    it("passes when script_locktime < tx_locktime (height)", function()
      local tx = make_tx(100, {0})
      local checker = make_checker(tx, 0)
      assert.is_true(checker.check_locktime(99))
    end)

    it("fails when script_locktime > tx_locktime (time)", function()
      local tx = make_tx(500000100, {0})
      local checker = make_checker(tx, 0)
      assert.is_false(checker.check_locktime(500000101))
    end)

    it("passes when script_locktime == tx_locktime (time)", function()
      local tx = make_tx(500000100, {0})
      local checker = make_checker(tx, 0)
      assert.is_true(checker.check_locktime(500000100))
    end)
  end)

  ---------------------------------------------------------------------------
  -- Gate 9: CLTV script_locktime = 0 always passes (locktime 0 is minimal)
  ---------------------------------------------------------------------------
  describe("gate 9: script_locktime = 0 always passes (no-lock)", function()
    it("script_locktime=0 passes regardless of tx.locktime", function()
      local tx = make_tx(0, {0})
      local checker = make_checker(tx, 0)
      assert.is_true(checker.check_locktime(0))
    end)
  end)

  ---------------------------------------------------------------------------
  -- Gate 10: end-to-end CLTV via script execution
  ---------------------------------------------------------------------------
  describe("gate 10: end-to-end CLTV script execution", function()
    it("CLTV passes: script_locktime=50, tx.locktime=100, seq=0", function()
      local tx = make_tx(100, {0})
      local ok, err = run_cltv(tx, 50, 0)
      assert.is_true(ok, tostring(err))
    end)

    it("CLTV passes: script_locktime=100, tx.locktime=100, seq=0", function()
      local tx = make_tx(100, {0})
      local ok, err = run_cltv(tx, 100, 0)
      assert.is_true(ok, tostring(err))
    end)

    it("CLTV fails: script_locktime=101, tx.locktime=100, seq=0", function()
      local tx = make_tx(100, {0})
      local ok = run_cltv(tx, 101, 0)
      assert.is_false(ok)
    end)

    it("CLTV fails when input sequence is SEQUENCE_FINAL even if value ok", function()
      local tx = make_tx(100, {SEQUENCE_FINAL})
      local ok = run_cltv(tx, 50, 0)
      assert.is_false(ok)
    end)

    it("CLTV passes: time-based, script=500000001, tx.locktime=500000002, seq=0", function()
      local tx = make_tx(500000002, {0})
      local ok, err = run_cltv(tx, 500000001, 0)
      assert.is_true(ok, tostring(err))
    end)
  end)

  ---------------------------------------------------------------------------
  -- IsFinalTx gates 11-15 (tx_verify.cpp:17-37)
  ---------------------------------------------------------------------------
  describe("IsFinalTx (tx_verify.cpp:17-37)", function()

    -- Gate 11: nLockTime == 0 → always final
    describe("gate 11: nLockTime=0 → final", function()
      it("locktime=0 is always final regardless of height/mtp", function()
        assert.is_true(mining.is_final_tx(make_tx(0, {0}), 1000, 900000001))
        assert.is_true(mining.is_final_tx(make_tx(0, {0}), 0, 0))
      end)
    end)

    -- Gate 12: height-based strict less-than (nLockTime < nBlockHeight)
    describe("gate 12: height-based locktime", function()
      it("locktime < height → final", function()
        assert.is_true(mining.is_final_tx(make_tx(100, {0}), 101, 900000001))
      end)

      it("locktime == height → NOT final (strict less-than)", function()
        -- Core: (int64_t)tx.nLockTime < nBlockHeight → locktime must be STRICTLY less
        -- locktime=100, height=100 → 100 < 100 is false → not final by locktime alone
        -- sequences not all SEQUENCE_FINAL → NOT final
        assert.is_false(mining.is_final_tx(make_tx(100, {0}), 100, 900000001))
      end)

      it("locktime > height → NOT final", function()
        assert.is_false(mining.is_final_tx(make_tx(200, {0}), 100, 900000001))
      end)
    end)

    -- Gate 13: time-based strict less-than
    describe("gate 13: time-based locktime (LOCKTIME_THRESHOLD boundary)", function()
      it("locktime < mtp → final (time-based)", function()
        assert.is_true(mining.is_final_tx(make_tx(500000001, {0}), 100, 500000002))
      end)

      it("locktime == mtp → NOT final (strict less-than)", function()
        assert.is_false(mining.is_final_tx(make_tx(500000001, {0}), 100, 500000001))
      end)

      it("locktime > mtp → NOT final", function()
        assert.is_false(mining.is_final_tx(make_tx(500000002, {0}), 100, 500000001))
      end)

      -- LOCKTIME_THRESHOLD boundary: 499999999 is height-based, 500000000 is time-based
      it("locktime=LOCKTIME_THRESHOLD-1 (499999999) is height-based", function()
        -- height=500000000 > 499999999 → final
        assert.is_true(mining.is_final_tx(make_tx(LOCKTIME_THRESHOLD - 1, {0}),
          LOCKTIME_THRESHOLD, 600000000))
      end)

      it("locktime=LOCKTIME_THRESHOLD (500000000) is time-based", function()
        -- mtp=500000001 > 500000000 → final (time-based)
        assert.is_true(mining.is_final_tx(make_tx(LOCKTIME_THRESHOLD, {0}),
          1000, LOCKTIME_THRESHOLD + 1))
        -- If using height=LOCKTIME_THRESHOLD+1 with time mtp < LOCKTIME_THRESHOLD:
        -- type mismatch would be wrong; the threshold separates the two domains
        -- in IsFinalTx directly (no separate type-check: uses locktime value directly)
      end)
    end)

    -- Gate 14: SEQUENCE_FINAL on ALL inputs → final regardless of locktime
    describe("gate 14: all SEQUENCE_FINAL → final", function()
      it("unsatisfied height locktime + all SEQUENCE_FINAL → final", function()
        assert.is_true(mining.is_final_tx(
          make_tx(999999999, {SEQUENCE_FINAL}), 100, 900000001))
      end)

      it("unsatisfied time locktime + all SEQUENCE_FINAL → final", function()
        assert.is_true(mining.is_final_tx(
          make_tx(900000000, {SEQUENCE_FINAL}), 100, 500000001))
      end)

      it("multi-input: ALL SEQUENCE_FINAL → final", function()
        assert.is_true(mining.is_final_tx(
          make_tx(999, {SEQUENCE_FINAL, SEQUENCE_FINAL}), 100, 900000001))
      end)
    end)

    -- Gate 15: ANY non-SEQUENCE_FINAL + unsatisfied locktime → NOT final
    describe("gate 15: any non-SEQUENCE_FINAL + unsatisfied locktime → not final", function()
      it("one non-SEQUENCE_FINAL input makes tx non-final", function()
        assert.is_false(mining.is_final_tx(
          make_tx(500, {SEQUENCE_FINAL, 0}), 100, 900000001))
      end)

      it("sequence=0 (non-SEQUENCE_FINAL) → not final", function()
        assert.is_false(mining.is_final_tx(make_tx(500, {0}), 100, 900000001))
      end)

      it("sequence=0xFFFFFFFE (one below SEQUENCE_FINAL) → not final", function()
        assert.is_false(mining.is_final_tx(
          make_tx(500, {0xFFFFFFFE}), 100, 900000001))
      end)
    end)
  end)

  ---------------------------------------------------------------------------
  -- BIP-113: time-based IsFinalTx uses MTP not block timestamp
  -- tx_verify.cpp:21: uses nBlockTime argument which is MTP when BIP113 active
  -- The switch from block_timestamp to MTP is done in utxo.lua connect_block.
  ---------------------------------------------------------------------------
  describe("BIP-113: MTP vs block timestamp selection", function()
    it("time-based locktime uses MTP not block timestamp", function()
      -- Scenario: block.timestamp=600000000, MTP=500000001
      -- tx.locktime=500000002 (time-based)
      -- With block.timestamp: 500000002 < 600000000 → FINAL (wrong pre-BIP113)
      -- With MTP: 500000002 < 500000001 is FALSE → NOT FINAL (correct BIP113)
      local tx = make_tx(500000002, {0})
      local block_ts  = 600000000
      local mtp       = 500000001
      -- Using block timestamp would incorrectly mark this as final:
      local with_block_ts = mining.is_final_tx(tx, 100, block_ts)
      assert.is_true(with_block_ts,
        "with block_timestamp (pre-BIP113): would be final (unsecure)")
      -- Using MTP correctly rejects it:
      local with_mtp = mining.is_final_tx(tx, 100, mtp)
      assert.is_false(with_mtp,
        "with MTP (BIP-113): must not be final when locktime > MTP")
    end)

    it("LOCKTIME_THRESHOLD boundary: 499999999 → height domain (mtp irrelevant)", function()
      local tx = make_tx(LOCKTIME_THRESHOLD - 1, {0})
      -- height=LOCKTIME_THRESHOLD (500000000) > 499999999 → final by height check
      assert.is_true(mining.is_final_tx(tx, LOCKTIME_THRESHOLD, 100000))
    end)

    it("LOCKTIME_THRESHOLD boundary: 500000000 → time domain (height irrelevant)", function()
      local tx = make_tx(LOCKTIME_THRESHOLD, {0})
      -- mtp=LOCKTIME_THRESHOLD+1 > LOCKTIME_THRESHOLD → final by time check
      assert.is_true(mining.is_final_tx(tx, 1000, LOCKTIME_THRESHOLD + 1))
      -- height=LOCKTIME_THRESHOLD+1 alone does NOT make it final
      -- because 500000000 >= LOCKTIME_THRESHOLD → time domain → compare against mtp
      -- mtp=100 < 500000000 → not final
      assert.is_false(mining.is_final_tx(tx, LOCKTIME_THRESHOLD + 1, 100))
    end)
  end)

  ---------------------------------------------------------------------------
  -- Edge cases
  ---------------------------------------------------------------------------
  describe("edge cases", function()
    it("empty inputs list: no sequence check → final (Core: for loop doesn't execute)", function()
      -- tx with no inputs: the SEQUENCE_FINAL loop body never executes → returns true
      local tx = types.transaction(1, {}, {}, 999)
      assert.is_true(mining.is_final_tx(tx, 100, 900000001),
        "tx with no inputs and unsatisfied locktime: all-SEQUENCE_FINAL vacuously true")
    end)

    it("CLTV with script_locktime=0 and tx.locktime=0: passes", function()
      local tx = make_tx(0, {0})
      local ok, err = run_cltv(tx, 0, 0)
      assert.is_true(ok, tostring(err))
    end)

    it("tapscript checker check_locktime: same logic as sig checker", function()
      -- Verify all three check_locktime implementations are consistent
      local tx = make_tx(100, {SEQUENCE_FINAL})
      local prev_outputs = {{ value = 50000, script_pubkey = "" }}
      local tapleaf_hash = string.rep("\x00", 32)
      local tap_checker = validation.make_tapscript_checker(tx, 0, prev_outputs, tapleaf_hash, nil)
      assert.is_false(tap_checker.check_locktime(50),
        "tapscript checker: SEQUENCE_FINAL must fail")

      local tx2 = make_tx(100, {0})
      local prev_outputs2 = {{ value = 50000, script_pubkey = "" }}
      local tap_checker2 = validation.make_tapscript_checker(tx2, 0, prev_outputs2, tapleaf_hash, nil)
      assert.is_true(tap_checker2.check_locktime(50),
        "tapscript checker: locktime=50 <= tx.locktime=100 with seq=0 must pass")
    end)
  end)

end)
