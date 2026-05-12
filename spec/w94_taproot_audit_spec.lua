-- W94 BIP-341/342 Taproot + tapscript comprehensive audit.
-- Covers the 8 bug classes closed in this wave against Bitcoin Core
-- script/interpreter.cpp:1872-1998 (VerifyTaprootCommitment, VerifyWitnessProgram,
-- ExecuteWitnessScript) and EvalChecksigTapscript (interpreter.cpp:347-385).
--
-- Bug classes:
--   1. OP_CHECKSIGADD missing unknown-pubkey-type forward soft-fork branch.
--      Pre-fix: lunarblock called check_sig with 33-byte pubkey; libsecp
--      xonly-parse rejected; `error()` propagated and the input was
--      rejected. Core treats success=true unconditionally — SPLIT (Core
--      accepts the spend, lunarblock would reject).
--   2. OP_CHECKSIGADD missing empty-pubkey gate (TAPSCRIPT_EMPTY_PUBKEY
--      fires regardless of sig.empty()). With (sig="", pubkey="") Core
--      rejects; pre-fix lunarblock accepted via the `#sig == 0` branch.
--   3. OP_CHECKSIGADD error-path used Lua `error()` rather than
--      `return nil, "SIG_SCHNORR"` — diverged from the other tapscript
--      opcodes and from the Core `return false` pattern.
--   4. TAPROOT_CONTROL_MAX_SIZE upper bound (4129) missing in script.lua
--      verify_witness_program AND utxo.lua native P2TR path. A 4193-byte
--      (33 + 32*130) control block satisfies (size - 33) % 32 == 0 but
--      Core rejects with TAPROOT_WRONG_CONTROL_SIZE.
--   5. BIP-341 hash_type range gate (Core interpreter.cpp:1516 accepts
--      only {0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83}). Pre-fix
--      lunarblock would compute a sighash for any explicit-sigbyte and
--      Schnorr-verify against it — accept/reject divergence depending on
--      whether the resulting hash collided with a forged sig.
--   6. ExecuteWitnessScript missing the initial-state MAX_STACK_SIZE
--      (tapscript-only) and per-element MAX_SCRIPT_ELEMENT_SIZE checks.
--   7. SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE relay/policy gate
--      missing in tapscript OP_CHECKSIG/OP_CHECKSIGVERIFY/OP_CHECKSIGADD.
--   8. P2SH-wrapped Taproot (witness v1 + 32-byte program under a P2SH
--      redeem) MUST NOT activate Taproot rules (Core interpreter.cpp:1947
--      `!is_p2sh`). It must fall through to the forward-soft-fork
--      catch-all (anyone-can-spend).

describe("W94 BIP-341/342 Taproot + tapscript audit", function()
  local script
  local validation

  setup(function()
    package.path = "src/?.lua;" .. package.path
    script = require("lunarblock.script")
    validation = require("lunarblock.validation")
  end)

  --------------------------------------------------------------------------
  -- Bug 5: BIP-341 hash_type range gate
  --------------------------------------------------------------------------
  describe("BIP-341 hash_type range gate", function()
    it("accepts the 7 BIP-341 hash_types Core accepts (interpreter.cpp:1516)", function()
      assert.is_true(validation.is_valid_taproot_hash_type(0x00))
      assert.is_true(validation.is_valid_taproot_hash_type(0x01))
      assert.is_true(validation.is_valid_taproot_hash_type(0x02))
      assert.is_true(validation.is_valid_taproot_hash_type(0x03))
      assert.is_true(validation.is_valid_taproot_hash_type(0x81))
      assert.is_true(validation.is_valid_taproot_hash_type(0x82))
      assert.is_true(validation.is_valid_taproot_hash_type(0x83))
    end)

    it("rejects every other byte (Core consensus split surface)", function()
      -- 0x04..0x80 and 0x84..0xFF: Core returns false from
      -- SignatureHashSchnorr; lunarblock pre-W94 would compute a sighash
      -- and verify against it.
      assert.is_false(validation.is_valid_taproot_hash_type(0x04))
      assert.is_false(validation.is_valid_taproot_hash_type(0x05))
      assert.is_false(validation.is_valid_taproot_hash_type(0x10))
      assert.is_false(validation.is_valid_taproot_hash_type(0x7f))
      assert.is_false(validation.is_valid_taproot_hash_type(0x80))
      assert.is_false(validation.is_valid_taproot_hash_type(0x84))
      assert.is_false(validation.is_valid_taproot_hash_type(0xC0))
      assert.is_false(validation.is_valid_taproot_hash_type(0xFE))
      assert.is_false(validation.is_valid_taproot_hash_type(0xFF))
    end)
  end)

  --------------------------------------------------------------------------
  -- Bug 1, 2, 3, 7: OP_CHECKSIGADD parity with EvalChecksigTapscript
  --------------------------------------------------------------------------
  describe("OP_CHECKSIGADD against EvalChecksigTapscript semantics", function()
    -- Wire a minimal stand-in checker that returns false (forces the
    -- check_sig branch to fail). We don't need a real Schnorr verify
    -- here; we only need to validate the surrounding control flow.
    local function make_failing_checker()
      return {
        check_sig = function() return false end,
      }
    end

    --- Build a tapscript that ends in OP_CHECKSIGADD with the given
    --- (sig, num, pubkey) on the stack. Returns the bytes and the
    --- pre-loaded initial stack. We don't run through verify_taproot
    --- here — we drive execute_script directly with is_tapscript=true.
    local function checksigadd_setup(sig, num, pubkey)
      return string.char(0xba), { sig, num, pubkey }
    end

    it("Bug 1 + 7: sig non-empty + pubkey size 33 (unknown) succeeds (forward soft-fork)", function()
      -- Core: EvalChecksigTapscript sets success=true, skips Schnorr verify,
      -- returns true. OP_CHECKSIGADD pushes num+1.
      local script_bytes, stack = checksigadd_setup(
        string.rep("\x42", 64),    -- 64-byte sig (non-empty)
        string.char(0x07),          -- num = 7 (CScriptNum push)
        string.rep("\x33", 33)      -- 33-byte unknown pubkey
      )
      local result, err = script.execute_script(script_bytes, stack, {
        is_tapscript = true,
        validation_weight_init = true,
        validation_weight_left = 1000,
      }, make_failing_checker())
      assert.is_not_nil(result, "expected success, got error: " .. tostring(err))
      -- Stack should hold num + 1 = 8 → CScriptNum encoding = "\x08".
      assert.equals(1, #result)
      assert.equals(string.char(0x08), result[1])
    end)

    it("Bug 7: DISCOURAGE_UPGRADABLE_PUBKEYTYPE policy reject on unknown pubkey", function()
      local script_bytes, stack = checksigadd_setup(
        string.rep("\x42", 64),
        string.char(0x07),
        string.rep("\x33", 33)
      )
      local result, err = script.execute_script(script_bytes, stack, {
        is_tapscript = true,
        validation_weight_init = true,
        validation_weight_left = 1000,
        verify_discourage_upgradable_pubkeytype = true,
      }, make_failing_checker())
      assert.is_nil(result)
      assert.equals("DISCOURAGE_UPGRADABLE_PUBKEYTYPE", err)
    end)

    it("Bug 2: sig empty + pubkey empty rejects TAPSCRIPT_EMPTY_PUBKEY", function()
      -- Pre-fix: pushed `n` and accepted. Core rejects unconditionally.
      local script_bytes, stack = checksigadd_setup(
        "",                         -- empty sig
        string.char(0x05),          -- num = 5
        ""                          -- empty pubkey
      )
      local result, err = script.execute_script(script_bytes, stack, {
        is_tapscript = true,
        validation_weight_init = true,
        validation_weight_left = 1000,
      }, make_failing_checker())
      assert.is_nil(result)
      assert.equals("TAPSCRIPT_EMPTY_PUBKEY", err)
    end)

    it("Bug 2: sig non-empty + pubkey empty also rejects TAPSCRIPT_EMPTY_PUBKEY", function()
      local script_bytes, stack = checksigadd_setup(
        string.rep("\x42", 64),
        string.char(0x05),
        ""
      )
      local result, err = script.execute_script(script_bytes, stack, {
        is_tapscript = true,
        validation_weight_init = true,
        validation_weight_left = 1000,
      }, make_failing_checker())
      assert.is_nil(result)
      assert.equals("TAPSCRIPT_EMPTY_PUBKEY", err)
    end)

    it("Bug 3: sig non-empty + 32-byte pubkey + failing verify returns SIG_SCHNORR (no Lua error)", function()
      local script_bytes, stack = checksigadd_setup(
        string.rep("\x42", 64),
        string.char(0x05),
        string.rep("\x77", 32)      -- 32-byte (looks like real xonly)
      )
      -- check_sig returns false → SIG_SCHNORR, NOT a Lua error().
      local result, err = script.execute_script(script_bytes, stack, {
        is_tapscript = true,
        validation_weight_init = true,
        validation_weight_left = 1000,
      }, make_failing_checker())
      assert.is_nil(result)
      assert.equals("SIG_SCHNORR", err)
    end)

    it("happy path: 32-byte pubkey + passing verify pushes num + 1", function()
      local script_bytes, stack = checksigadd_setup(
        string.rep("\x42", 64),
        string.char(0x05),
        string.rep("\x77", 32)
      )
      local checker = { check_sig = function() return true end }
      local result, err = script.execute_script(script_bytes, stack, {
        is_tapscript = true,
        validation_weight_init = true,
        validation_weight_left = 1000,
      }, checker)
      assert.is_not_nil(result, err)
      assert.equals(string.char(0x06), result[1])  -- 5 + 1
    end)

    it("empty-sig short-circuit: pushes num unchanged, no weight decrement", function()
      local script_bytes, stack = checksigadd_setup(
        "",
        string.char(0x05),
        string.rep("\x77", 32)
      )
      local checker = { check_sig = function() return true end }
      local flags = {
        is_tapscript = true,
        validation_weight_init = true,
        validation_weight_left = 0,  -- 0 budget; empty sig must NOT decrement
      }
      local result, err = script.execute_script(script_bytes, stack, flags, checker)
      assert.is_not_nil(result, err)
      assert.equals(string.char(0x05), result[1])
      assert.equals(0, flags.validation_weight_left)
    end)
  end)

  --------------------------------------------------------------------------
  -- Bug 7: OP_CHECKSIG/OP_CHECKSIGVERIFY DISCOURAGE_UPGRADABLE_PUBKEYTYPE
  --------------------------------------------------------------------------
  describe("OP_CHECKSIG family DISCOURAGE_UPGRADABLE_PUBKEYTYPE", function()
    it("OP_CHECKSIG rejects unknown pubkey when discourage flag set", function()
      -- stack layout: sig, pubkey (top); script: OP_CHECKSIG (0xac)
      local result, err = script.execute_script(string.char(0xac),
        { string.rep("\x42", 64), string.rep("\x33", 33) },
        { is_tapscript = true,
          validation_weight_init = true,
          validation_weight_left = 1000,
          verify_discourage_upgradable_pubkeytype = true },
        {})
      assert.is_nil(result)
      assert.equals("DISCOURAGE_UPGRADABLE_PUBKEYTYPE", err)
    end)

    it("OP_CHECKSIG accepts unknown pubkey without discourage flag (forward SF)", function()
      local result, err = script.execute_script(string.char(0xac),
        { string.rep("\x42", 64), string.rep("\x33", 33) },
        { is_tapscript = true,
          validation_weight_init = true,
          validation_weight_left = 1000 },
        {})
      assert.is_not_nil(result, err)
      assert.equals("\x01", result[1])  -- vchTrue
    end)

    it("OP_CHECKSIG with 32-byte pubkey + failing verify returns SIG_SCHNORR", function()
      local result, err = script.execute_script(string.char(0xac),
        { string.rep("\x42", 64), string.rep("\x77", 32) },
        { is_tapscript = true,
          validation_weight_init = true,
          validation_weight_left = 1000 },
        { check_sig = function() return false end })
      assert.is_nil(result)
      assert.equals("SIG_SCHNORR", err)
    end)

    it("OP_CHECKSIGVERIFY rejects unknown pubkey when discourage flag set", function()
      -- OP_CHECKSIGVERIFY = 0xad
      local result, err = script.execute_script(string.char(0xad),
        { string.rep("\x42", 64), string.rep("\x33", 33) },
        { is_tapscript = true,
          validation_weight_init = true,
          validation_weight_left = 1000,
          verify_discourage_upgradable_pubkeytype = true },
        {})
      assert.is_nil(result)
      assert.equals("DISCOURAGE_UPGRADABLE_PUBKEYTYPE", err)
    end)

    it("OP_CHECKSIGVERIFY with empty sig fails CHECKSIGVERIFY (no error())", function()
      local result, err = script.execute_script(string.char(0xad),
        { "", string.rep("\x77", 32) },
        { is_tapscript = true,
          validation_weight_init = true,
          validation_weight_left = 1000 },
        { check_sig = function() return true end })
      assert.is_nil(result)
      assert.equals("CHECKSIGVERIFY", err)
    end)
  end)

  --------------------------------------------------------------------------
  -- Bug 4: TAPROOT_CONTROL_MAX_SIZE upper bound (4129)
  --------------------------------------------------------------------------
  describe("Taproot control-block size bounds", function()
    -- We can't drive verify_witness_program end-to-end without a real
    -- pubkey-key commitment, but we can prove the gate fires before any
    -- cryptography is invoked by checking that the wrong-size error
    -- bubbles up first.
    it("rejects 4193-byte control block (33 + 32*130) as TAPROOT_WRONG_CONTROL_SIZE", function()
      -- Build a 4193-byte control block. (size - 33) / 32 == 130, well
      -- past the BIP-341 max of 128 nodes. (size - 33) % 32 == 0 so the
      -- pre-W94 stride check would have passed.
      local cb = string.char(0xc0) .. string.rep("\x00", 4192)
      assert.equals(4193, #cb)
      assert.equals(0, (#cb - 33) % 32)
      local script_bytes = "\x51"  -- OP_TRUE tap leaf (will never run)
      local witness = { script_bytes, cb }
      local ok, err = script.verify_witness_program(
        witness, 1, string.rep("\x55", 32),
        { verify_taproot = true }, {}, false)
      assert.is_nil(ok)
      assert.equals("TAPROOT_WRONG_CONTROL_SIZE", err)
    end)

    it("rejects 32-byte control block (< 33) as TAPROOT_WRONG_CONTROL_SIZE", function()
      local cb = string.rep("\x00", 32)
      local script_bytes = "\x51"
      local witness = { script_bytes, cb }
      local ok, err = script.verify_witness_program(
        witness, 1, string.rep("\x55", 32),
        { verify_taproot = true }, {}, false)
      assert.is_nil(ok)
      assert.equals("TAPROOT_WRONG_CONTROL_SIZE", err)
    end)

    it("rejects 34-byte control block (mis-aligned stride) as TAPROOT_WRONG_CONTROL_SIZE", function()
      local cb = string.rep("\x00", 34)  -- 33 + 1, fails (% 32) check
      local script_bytes = "\x51"
      local witness = { script_bytes, cb }
      local ok, err = script.verify_witness_program(
        witness, 1, string.rep("\x55", 32),
        { verify_taproot = true }, {}, false)
      assert.is_nil(ok)
      assert.equals("TAPROOT_WRONG_CONTROL_SIZE", err)
    end)
  end)

  --------------------------------------------------------------------------
  -- Bug 6: ExecuteWitnessScript initial-state checks for TAPSCRIPT
  --------------------------------------------------------------------------
  describe("ExecuteWitnessScript initial-state checks", function()
    it("rejects tapscript with initial witness stack > MAX_STACK_SIZE (1000) → STACK_SIZE", function()
      -- 1001 items on the stack before any opcode runs. Core
      -- interpreter.cpp:1855 rejects after the OP_SUCCESS pre-scan.
      local big_stack = {}
      for i = 1, 1001 do big_stack[i] = "\x01" end
      local result, err = script.execute_witness_script("\x51", big_stack, {
        is_tapscript = true,
        validation_weight_init = true,
        validation_weight_left = 1000,
      }, {})
      assert.is_nil(result)
      assert.equals("STACK_SIZE", err)
    end)

    it("allows tapscript with initial witness stack at exactly MAX_STACK_SIZE", function()
      local stack = {}
      for i = 1, 1000 do stack[i] = "\x01" end
      -- script: 1000x OP_DROP. Initial stack is 1000 (= cap), then each
      -- DROP pops one. Reaches stack-size 0 at the end (EVAL_FALSE).
      -- We don't care about the outcome — just that the entry STACK_SIZE
      -- gate does NOT fire.
      local script_bytes = string.rep(string.char(0x75), 1000)
      local result, err = script.execute_witness_script(script_bytes, stack, {
        is_tapscript = true,
        validation_weight_init = true,
        validation_weight_left = 1000,
      }, {})
      if err then
        assert.are_not.equal("STACK_SIZE", err)
      end
    end)

    it("rejects witness with a >520-byte initial element as PUSH_SIZE", function()
      -- 521-byte initial witness item triggers the per-element gate
      -- BEFORE EvalScript runs.
      local oversize = string.rep("\xFF", 521)
      local result, err = script.execute_witness_script("\x51",
        { oversize, "\x01" }, {
          is_tapscript = true,
          validation_weight_init = true,
          validation_weight_left = 1000,
        }, {})
      assert.is_nil(result)
      assert.equals("PUSH_SIZE", err)
    end)

    it("OP_SUCCESS overrides PUSH_SIZE check (Core: pre-scan short-circuits)", function()
      -- OP_RESERVED (0x50) is an OP_SUCCESS byte. A tapscript starting
      -- with it must succeed even if the witness has oversize elements.
      local oversize = string.rep("\xFF", 521)
      local result, err = script.execute_witness_script(string.char(0x50),
        { oversize }, {
          is_tapscript = true,
          validation_weight_init = true,
          validation_weight_left = 1000,
        }, {})
      assert.is_true(result, err)
    end)

    it("non-tapscript witness execution does NOT enforce MAX_STACK_SIZE on entry", function()
      -- Core only enforces the tapscript-only stack-on-entry cap; for
      -- WITNESS_V0 the in-loop check applies. We assert the same shape
      -- by ensuring a >1000 witness stack on a non-tapscript path is
      -- NOT rejected with STACK_SIZE *immediately*. (Whatever happens
      -- next in the interpreter is fine; we only care this gate is gated.)
      local big_stack = {}
      for i = 1, 1001 do big_stack[i] = "\x01" end
      -- We run a minimal witness-v0 script that immediately drops a
      -- handful of items; STACK_SIZE check pre-script would fire if
      -- our gate were over-strict.
      local result, err = script.execute_witness_script(string.char(0x75),
        big_stack, { is_witness_v0 = true }, {})
      -- We don't care about the outcome, only that the failure mode is
      -- NOT an early STACK_SIZE on entry.
      if err then
        assert.are_not.equal("STACK_SIZE", err)
      end
    end)
  end)

  --------------------------------------------------------------------------
  -- Bug 8: P2SH-wrapped Taproot must not activate Taproot rules
  --------------------------------------------------------------------------
  describe("P2SH-wrapped Taproot disabled", function()
    it("is_p2sh=true falls through to forward-soft-fork catch-all (true)", function()
      -- 32-byte program + verify_taproot flag + is_p2sh=true: Core's
      -- VerifyWitnessProgram (`!is_p2sh`) skips the Taproot branch and
      -- treats this as the forward-SF catch-all → returns true.
      local ok, err = script.verify_witness_program(
        {}, 1, string.rep("\x55", 32),
        { verify_taproot = true }, {}, true)
      assert.is_true(ok, err)
    end)

    it("is_p2sh=true with DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM flag", function()
      -- Catch-all also honors the relay-only DISCOURAGE flag.
      local ok, err = script.verify_witness_program(
        {}, 1, string.rep("\x55", 32),
        { verify_taproot = true,
          verify_discourage_upgradable_witness = true }, {}, true)
      assert.is_nil(ok)
      assert.equals("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM", err)
    end)

    it("is_p2sh=false STILL takes the Taproot branch (control case)", function()
      -- With is_p2sh=false the v1+32 branch DOES activate; an empty
      -- witness should produce WITNESS_PROGRAM_WITNESS_EMPTY (the first
      -- check inside the Taproot block, before any commitment math).
      local ok, err = script.verify_witness_program(
        {}, 1, string.rep("\x55", 32),
        { verify_taproot = true }, {}, false)
      assert.is_nil(ok)
      assert.equals("WITNESS_PROGRAM_WITNESS_EMPTY", err)
    end)
  end)
end)
