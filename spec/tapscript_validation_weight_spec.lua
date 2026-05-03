-- Tests for BIP-342 tapscript validation-weight budget tracking.
-- Per Bitcoin Core interpreter.cpp:362, every non-empty
-- OP_CHECKSIG / OP_CHECKSIGVERIFY / OP_CHECKSIGADD inside a tapscript
-- must decrement a per-input validation-weight counter by
-- VALIDATION_WEIGHT_PER_SIGOP_PASSED (50). Empty signatures don't
-- consume budget. Negative residue aborts with TAPSCRIPT_VALIDATION_WEIGHT.

describe("tapscript validation-weight budget", function()
  local script

  setup(function()
    package.path = "src/?.lua;" .. package.path
    script = require("lunarblock.script")
  end)

  describe("compact_size_len", function()
    it("matches Core's GetSizeOfCompactSize", function()
      assert.equals(1, script.compact_size_len(0))
      assert.equals(1, script.compact_size_len(0xfc))
      assert.equals(3, script.compact_size_len(0xfd))
      assert.equals(3, script.compact_size_len(0xffff))
      assert.equals(5, script.compact_size_len(0x10000))
      assert.equals(5, script.compact_size_len(0xffffffff))
      assert.equals(9, script.compact_size_len(0x100000000))
    end)
  end)

  describe("serialized_witness_stack_size", function()
    it("matches Core's ::GetSerializeSize(witness.stack)", function()
      -- Empty stack: just the count compact-size byte.
      assert.equals(1, script.serialized_witness_stack_size({}))

      -- One 64-byte item: 1 (count) + 1 (item len prefix) + 64 (bytes).
      local s64 = string.rep("\x00", 64)
      assert.equals(66, script.serialized_witness_stack_size({s64}))

      -- Two items, 100 + 33 bytes:
      local s100 = string.rep("\x00", 100)
      local s33  = string.rep("\x00", 33)
      assert.equals(1 + (1 + 100) + (1 + 33),
                    script.serialized_witness_stack_size({s100, s33}))
    end)
  end)

  describe("OP_CHECKSIG budget gate", function()
    -- Drive OP_CHECKSIG via execute_script with a pre-seeded budget so
    -- we can verify the gate without the full BIP-341 control-block
    -- + merkle-path setup.
    local PK32 = string.rep("\x02", 32)
    local SIG64 = string.rep("\x42", 64)
    local OP_CHECKSIG = "\xac"

    -- Script: <sig> <pubkey> OP_CHECKSIG
    local function build_checksig_script(sig, pk)
      local s = ""
      if #sig == 0 then
        s = s .. "\x00"  -- OP_0 (empty sig)
      else
        s = s .. string.char(#sig) .. sig
      end
      s = s .. string.char(#pk) .. pk
      s = s .. OP_CHECKSIG
      return s
    end

    it("exhausted budget aborts CHECKSIG (32-byte pubkey)", function()
      local checker = {check_sig = function() return false end}
      local s = build_checksig_script(SIG64, PK32)
      local result, err = script.execute_script(s, {}, {
        is_tapscript = true,
        validation_weight_init = true,
        validation_weight_left = 49,
      }, checker)
      assert.is_nil(result)
      assert.equals("TAPSCRIPT_VALIDATION_WEIGHT", err)
    end)

    it("sufficient budget runs CHECKSIG to completion", function()
      -- check_sig returns true; CHECKSIG pushes true.
      local checker = {check_sig = function() return true end}
      local flags = {
        is_tapscript = true,
        validation_weight_init = true,
        validation_weight_left = 50,
      }
      local s = build_checksig_script(SIG64, PK32)
      local result, err = script.execute_script(s, {}, flags, checker)
      assert.is_table(result)
      assert.is_nil(err)
      -- Budget exactly drained.
      assert.equals(0, flags.validation_weight_left)
    end)

    it("empty sig consumes no budget (32-byte pubkey)", function()
      local checker = {check_sig = function() return false end}
      local flags = {
        is_tapscript = true,
        validation_weight_init = true,
        validation_weight_left = 0,
      }
      -- Empty sig + 32-byte pubkey: pushes false, no budget touch.
      local s = build_checksig_script("", PK32)
      local result, err = script.execute_script(s, {}, flags, checker)
      -- Result is the script's residual stack ([false]).
      assert.is_table(result)
      assert.is_nil(err)
      assert.equals(0, flags.validation_weight_left)
    end)

    it("unknown pubkey type with non-empty sig also consumes budget", function()
      -- Per Core: "Passing with an upgradable public key version is
      -- also counted." Non-32-byte pubkey + non-empty sig must
      -- decrement the budget.
      local PK33 = string.rep("\x02", 33)
      local checker = {check_sig = function() return false end}
      local flags = {
        is_tapscript = true,
        validation_weight_init = true,
        validation_weight_left = 0,
      }
      local s = build_checksig_script(SIG64, PK33)
      local result, err = script.execute_script(s, {}, flags, checker)
      assert.is_nil(result)
      assert.equals("TAPSCRIPT_VALIDATION_WEIGHT", err)
    end)
  end)

  describe("OP_CHECKSIGADD budget gate", function()
    local PK32 = string.rep("\x02", 32)
    local SIG64 = string.rep("\x42", 64)
    local OP_CHECKSIGADD = "\xba"

    it("exhausted budget aborts CHECKSIGADD", function()
      local checker = {check_sig = function() return true end}
      -- Stack (bottom→top): sig, num=0, pubkey
      local s = string.char(#SIG64) .. SIG64
                 .. "\x00"
                 .. string.char(#PK32) .. PK32
                 .. OP_CHECKSIGADD
      local result, err = script.execute_script(s, {}, {
        is_tapscript = true,
        validation_weight_init = true,
        validation_weight_left = 0,
      }, checker)
      assert.is_nil(result)
      assert.equals("TAPSCRIPT_VALIDATION_WEIGHT", err)
    end)

    it("empty sig consumes no budget on CHECKSIGADD", function()
      local checker = {check_sig = function() return false end}
      local flags = {
        is_tapscript = true,
        validation_weight_init = true,
        validation_weight_left = 0,
      }
      -- Stack (bottom→top): empty sig, num=5, pubkey
      local s = "\x00"  -- OP_0 (empty sig)
                 .. "\x55"  -- OP_5 (num=5)
                 .. string.char(#PK32) .. PK32
                 .. OP_CHECKSIGADD
      local result, err = script.execute_script(s, {}, flags, checker)
      assert.is_table(result)
      assert.is_nil(err)
      assert.equals(0, flags.validation_weight_left)
    end)
  end)

  describe("legacy / SegWit-v0 paths are unaffected", function()
    it("CHECKSIG on non-tapscript path doesn't consult budget", function()
      -- No is_tapscript flag, no budget seeded. Legacy CHECKSIG with
      -- empty sig + uncompressed pubkey just pushes false; the path
      -- must not error on the (uninitialized) budget.
      local checker = {check_sig = function() return false end}
      local PK33 = string.rep("\x02", 33)
      local s = "\x00" .. string.char(#PK33) .. PK33 .. "\xac"
      local result, err = script.execute_script(s, {}, {}, checker)
      assert.is_table(result)
      assert.is_nil(err)
    end)
  end)
end)
