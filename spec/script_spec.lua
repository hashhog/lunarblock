-- Helper to convert hex string to binary
local function hex_to_bin(hex)
  return (hex:gsub('..', function(cc)
    return string.char(tonumber(cc, 16))
  end))
end

-- Helper to convert binary to hex string
local function bin_to_hex(bin)
  local hex = {}
  for i = 1, #bin do
    hex[i] = string.format("%02x", bin:byte(i))
  end
  return table.concat(hex)
end

describe("script", function()
  local script

  setup(function()
    package.path = "src/?.lua;" .. package.path
    script = require("lunarblock.script")
  end)

  describe("script_num_encode/decode round-trip", function()
    local test_values = {0, 1, -1, 127, 128, -128, 255, 256, -256, 32767, -32768}

    for _, n in ipairs(test_values) do
      it("round-trips " .. n, function()
        local encoded = script.script_num_encode(n)
        local decoded = script.script_num_decode(encoded)
        assert.equals(n, decoded)
      end)
    end

    it("encodes 0 as empty string", function()
      assert.equals("", script.script_num_encode(0))
    end)

    it("encodes 1 as 0x01", function()
      assert.equals("\x01", script.script_num_encode(1))
    end)

    it("encodes -1 as 0x81", function()
      assert.equals("\x81", script.script_num_encode(-1))
    end)

    it("encodes 127 as 0x7f", function()
      assert.equals("\x7f", script.script_num_encode(127))
    end)

    it("encodes 128 as 0x80 0x00", function()
      assert.equals("\x80\x00", script.script_num_encode(128))
    end)

    it("encodes -128 as 0x80 0x80", function()
      assert.equals("\x80\x80", script.script_num_encode(-128))
    end)

    it("encodes 255 as 0xff 0x00", function()
      assert.equals("\xff\x00", script.script_num_encode(255))
    end)

    it("encodes 256 as 0x00 0x01", function()
      assert.equals("\x00\x01", script.script_num_encode(256))
    end)

    it("encodes -256 as 0x00 0x81", function()
      assert.equals("\x00\x81", script.script_num_encode(-256))
    end)
  end)

  describe("cast_to_bool", function()
    it("returns false for empty string", function()
      assert.is_false(script.cast_to_bool(""))
    end)

    it("returns false for single zero byte", function()
      assert.is_false(script.cast_to_bool("\x00"))
    end)

    it("returns false for negative zero (0x80)", function()
      assert.is_false(script.cast_to_bool("\x80"))
    end)

    it("returns true for 0x01", function()
      assert.is_true(script.cast_to_bool("\x01"))
    end)

    it("returns false for multi-byte negative zero", function()
      assert.is_false(script.cast_to_bool("\x00\x00\x80"))
    end)

    it("returns true for non-zero multi-byte value", function()
      assert.is_true(script.cast_to_bool("\x01\x00"))
    end)

    it("returns true for value with high bit set but not negative zero", function()
      assert.is_true(script.cast_to_bool("\x00\x81"))
    end)
  end)

  describe("parse_script and build_script round-trip", function()
    it("round-trips P2PKH script", function()
      local pubkey_hash = string.rep("\x42", 20)
      local p2pkh = script.make_p2pkh_script(pubkey_hash)
      local ops = script.parse_script(p2pkh)
      local rebuilt = script.build_script(ops)
      assert.equals(p2pkh, rebuilt)
    end)

    it("round-trips P2SH script", function()
      local script_hash = string.rep("\x42", 20)
      local p2sh = script.make_p2sh_script(script_hash)
      local ops = script.parse_script(p2sh)
      local rebuilt = script.build_script(ops)
      assert.equals(p2sh, rebuilt)
    end)

    it("round-trips P2WPKH script", function()
      local pubkey_hash = string.rep("\x42", 20)
      local p2wpkh = script.make_p2wpkh_script(pubkey_hash)
      local ops = script.parse_script(p2wpkh)
      local rebuilt = script.build_script(ops)
      assert.equals(p2wpkh, rebuilt)
    end)

    it("round-trips P2WSH script", function()
      local script_hash = string.rep("\x42", 32)
      local p2wsh = script.make_p2wsh_script(script_hash)
      local ops = script.parse_script(p2wsh)
      local rebuilt = script.build_script(ops)
      assert.equals(p2wsh, rebuilt)
    end)

    it("round-trips P2TR script", function()
      local xonly_pubkey = string.rep("\x42", 32)
      local p2tr = script.make_p2tr_script(xonly_pubkey)
      local ops = script.parse_script(p2tr)
      local rebuilt = script.build_script(ops)
      assert.equals(p2tr, rebuilt)
    end)

    it("parses PUSHDATA1 correctly", function()
      -- Create a script with 76-byte push (requires PUSHDATA1)
      local data = string.rep("x", 76)
      local s = string.char(0x4c, 76) .. data
      local ops = script.parse_script(s)
      assert.equals(1, #ops)
      assert.equals(0x4c, ops[1].opcode)
      assert.equals(data, ops[1].data)
    end)

    it("parses PUSHDATA2 correctly", function()
      -- Create a script with 256-byte push (requires PUSHDATA2)
      local data = string.rep("x", 256)
      local s = string.char(0x4d, 0x00, 0x01) .. data
      local ops = script.parse_script(s)
      assert.equals(1, #ops)
      assert.equals(0x4d, ops[1].opcode)
      assert.equals(data, ops[1].data)
    end)
  end)

  describe("classify_script", function()
    it("identifies P2PKH script", function()
      local pubkey_hash = string.rep("\x42", 20)
      local p2pkh = script.make_p2pkh_script(pubkey_hash)
      local script_type, hash = script.classify_script(p2pkh)
      assert.equals("p2pkh", script_type)
      assert.equals(pubkey_hash, hash)
    end)

    it("identifies P2SH script", function()
      local script_hash = string.rep("\x42", 20)
      local p2sh = script.make_p2sh_script(script_hash)
      local script_type, hash = script.classify_script(p2sh)
      assert.equals("p2sh", script_type)
      assert.equals(script_hash, hash)
    end)

    it("identifies P2WPKH script", function()
      local pubkey_hash = string.rep("\x42", 20)
      local p2wpkh = script.make_p2wpkh_script(pubkey_hash)
      local script_type, hash = script.classify_script(p2wpkh)
      assert.equals("p2wpkh", script_type)
      assert.equals(pubkey_hash, hash)
    end)

    it("identifies P2WSH script", function()
      local script_hash = string.rep("\x42", 32)
      local p2wsh = script.make_p2wsh_script(script_hash)
      local script_type, hash = script.classify_script(p2wsh)
      assert.equals("p2wsh", script_type)
      assert.equals(script_hash, hash)
    end)

    it("identifies P2TR script", function()
      local xonly_pubkey = string.rep("\x42", 32)
      local p2tr = script.make_p2tr_script(xonly_pubkey)
      local script_type, hash = script.classify_script(p2tr)
      assert.equals("p2tr", script_type)
      assert.equals(xonly_pubkey, hash)
    end)

    it("identifies nulldata script", function()
      local nulldata = "\x6a\x04test"
      local script_type, hash = script.classify_script(nulldata)
      assert.equals("nulldata", script_type)
      assert.is_nil(hash)
    end)

    it("identifies nonstandard script", function()
      local nonstandard = "\x51\x51\x93"  -- OP_1 OP_1 OP_ADD
      local script_type, hash = script.classify_script(nonstandard)
      assert.equals("nonstandard", script_type)
      assert.is_nil(hash)
    end)

    -- WITNESS_UNKNOWN: a witness program with version >= 1 that is NOT the
    -- canonical v1+32 Taproot shape (e.g. v1 16-byte) is classified
    -- WITNESS_UNKNOWN by Core Solver (solver.cpp:172-175: witnessversion != 0),
    -- NOT nonstandard.  Relay-standardness only.  Regression: the pre-fix
    -- version range started at OP_2 (0x52), dropping all non-Taproot v1
    -- programs through to NONSTANDARD.
    it("classifies a v1 non-Taproot witness program as witness_unknown", function()
      -- OP_1 push(16 bytes): 0x51 0x10 <16> -- v1 witness program, 16-byte program
      local v1_16 = "\x51\x10" .. string.rep("\xab", 16)
      local script_type, hash = script.classify_script(v1_16)
      assert.equals("witness_unknown", script_type)
      assert.is_nil(hash)
    end)

    it("classifies a v2 witness program as witness_unknown", function()
      -- OP_2 push(32 bytes): 0x52 0x20 <32>
      local v2_32 = "\x52\x20" .. string.rep("\xab", 32)
      assert.equals("witness_unknown", script.classify_script(v2_32))
    end)

    it("keeps a v1+32 Taproot output as p2tr (not witness_unknown)", function()
      local p2tr = "\x51\x20" .. string.rep("\x42", 32)
      assert.equals("p2tr", script.classify_script(p2tr))
    end)

    it("keeps P2A (51 02 4e 73) as p2a, not witness_unknown", function()
      assert.equals("p2a", script.classify_script("\x51\x02\x4e\x73"))
    end)

    -- Bare multisig with a PUSHDATA-prefixed pubkey push.  Core MatchMultisig
    -- reads each key via GetScriptOp (decodes OP_PUSHDATA1/2/4) and accepts iff
    -- CPubKey::ValidSize (33 or 65).  Relay-standardness only.  Regression: the
    -- pre-fix walk only accepted direct pushes + OP_PUSHDATA1.
    it("classifies bare multisig with an OP_PUSHDATA2-prefixed pubkey", function()
      local pk = string.rep("\x03", 33)
      -- OP_1 OP_PUSHDATA2 <33,0> <33B pk> OP_1 OP_CHECKMULTISIG
      local ms = "\x51" .. "\x4d\x21\x00" .. pk .. "\x51\xae"
      local script_type, meta = script.classify_script(ms)
      assert.equals("multisig", script_type)
      assert.equals("1_1", meta)
    end)

    it("classifies bare multisig with an OP_PUSHDATA4-prefixed pubkey", function()
      local pk = string.rep("\x03", 33)
      -- OP_1 OP_PUSHDATA4 <33,0,0,0> <33B pk> OP_1 OP_CHECKMULTISIG
      local ms = "\x51" .. "\x4e\x21\x00\x00\x00" .. pk .. "\x51\xae"
      assert.equals("multisig", script.classify_script(ms))
    end)

    it("rejects a PUSHDATA-prefixed non-pubkey-size push as multisig (ValidSize gate)", function()
      -- OP_1 OP_PUSHDATA1 <32> <32 bytes> OP_1 OP_CHECKMULTISIG -- 32 != 33/65
      local ms = "\x51" .. "\x4c\x20" .. string.rep("\x03", 32) .. "\x51\xae"
      assert.equals("nonstandard", script.classify_script(ms))
    end)
  end)

  describe("execute_script arithmetic", function()
    it("OP_1 OP_2 OP_ADD OP_3 OP_EQUAL leaves true on stack", function()
      -- OP_1 (0x51), OP_2 (0x52), OP_ADD (0x93), OP_3 (0x53), OP_EQUAL (0x87)
      local s = "\x51\x52\x93\x53\x87"
      local stack = script.execute_script(s)
      assert.equals(1, #stack)
      assert.is_true(script.cast_to_bool(stack[1]))
    end)

    it("OP_1 OP_2 OP_ADD OP_4 OP_EQUAL leaves false on stack", function()
      local s = "\x51\x52\x93\x54\x87"
      local stack = script.execute_script(s)
      assert.equals(1, #stack)
      assert.is_false(script.cast_to_bool(stack[1]))
    end)

    it("OP_5 OP_3 OP_SUB equals 2", function()
      local s = "\x55\x53\x94"  -- OP_5 OP_3 OP_SUB
      local stack = script.execute_script(s)
      assert.equals(1, #stack)
      assert.equals(2, script.script_num_decode(stack[1]))
    end)

    it("OP_1ADD increments", function()
      local s = "\x54\x8b"  -- OP_4 OP_1ADD
      local stack = script.execute_script(s)
      assert.equals(5, script.script_num_decode(stack[1]))
    end)

    it("OP_1SUB decrements", function()
      local s = "\x54\x8c"  -- OP_4 OP_1SUB
      local stack = script.execute_script(s)
      assert.equals(3, script.script_num_decode(stack[1]))
    end)

    it("OP_NEGATE negates", function()
      local s = "\x54\x8f"  -- OP_4 OP_NEGATE
      local stack = script.execute_script(s)
      assert.equals(-4, script.script_num_decode(stack[1]))
    end)

    it("OP_ABS returns absolute value", function()
      local s = "\x4f\x90"  -- OP_1NEGATE OP_ABS
      local stack = script.execute_script(s)
      assert.equals(1, script.script_num_decode(stack[1]))
    end)

    it("OP_NOT returns 1 for 0", function()
      local s = "\x00\x91"  -- OP_0 OP_NOT
      local stack = script.execute_script(s)
      assert.equals(1, script.script_num_decode(stack[1]))
    end)

    it("OP_NOT returns 0 for non-zero", function()
      local s = "\x51\x91"  -- OP_1 OP_NOT
      local stack = script.execute_script(s)
      assert.equals(0, script.script_num_decode(stack[1]))
    end)

    it("OP_MIN returns minimum", function()
      local s = "\x55\x53\xa3"  -- OP_5 OP_3 OP_MIN
      local stack = script.execute_script(s)
      assert.equals(3, script.script_num_decode(stack[1]))
    end)

    it("OP_MAX returns maximum", function()
      local s = "\x55\x53\xa4"  -- OP_5 OP_3 OP_MAX
      local stack = script.execute_script(s)
      assert.equals(5, script.script_num_decode(stack[1]))
    end)

    it("OP_WITHIN returns true when in range", function()
      local s = "\x53\x52\x55\xa5"  -- OP_3 OP_2 OP_5 OP_WITHIN (is 3 in [2,5)?)
      local stack = script.execute_script(s)
      assert.is_true(script.cast_to_bool(stack[1]))
    end)

    it("OP_WITHIN returns false when out of range", function()
      local s = "\x55\x52\x54\xa5"  -- OP_5 OP_2 OP_4 OP_WITHIN (is 5 in [2,4)?)
      local stack = script.execute_script(s)
      assert.is_false(script.cast_to_bool(stack[1]))
    end)
  end)

  describe("execute_script flow control", function()
    it("OP_IF OP_1 OP_ELSE OP_2 OP_ENDIF with true initial value", function()
      local s = "\x51\x63\x51\x67\x52\x68"  -- OP_1 OP_IF OP_1 OP_ELSE OP_2 OP_ENDIF
      local stack = script.execute_script(s)
      assert.equals(1, #stack)
      assert.equals(1, script.script_num_decode(stack[1]))
    end)

    it("OP_IF OP_1 OP_ELSE OP_2 OP_ENDIF with false initial value", function()
      local s = "\x00\x63\x51\x67\x52\x68"  -- OP_0 OP_IF OP_1 OP_ELSE OP_2 OP_ENDIF
      local stack = script.execute_script(s)
      assert.equals(1, #stack)
      assert.equals(2, script.script_num_decode(stack[1]))
    end)

    it("OP_NOTIF executes else branch when true", function()
      local s = "\x51\x64\x51\x67\x52\x68"  -- OP_1 OP_NOTIF OP_1 OP_ELSE OP_2 OP_ENDIF
      local stack = script.execute_script(s)
      assert.equals(1, #stack)
      assert.equals(2, script.script_num_decode(stack[1]))
    end)

    it("nested IF/ELSE/ENDIF works", function()
      -- OP_1 OP_IF OP_1 OP_IF OP_3 OP_ELSE OP_4 OP_ENDIF OP_ELSE OP_5 OP_ENDIF
      local s = "\x51\x63\x51\x63\x53\x67\x54\x68\x67\x55\x68"
      local stack = script.execute_script(s)
      assert.equals(1, #stack)
      assert.equals(3, script.script_num_decode(stack[1]))
    end)

    it("OP_RETURN in non-executing branch does not terminate", function()
      -- OP_0 OP_IF OP_RETURN OP_ENDIF OP_1
      local s = "\x00\x63\x6a\x68\x51"
      local stack = script.execute_script(s)
      assert.equals(1, #stack)
      assert.equals(1, script.script_num_decode(stack[1]))
    end)

    it("OP_RETURN in executing branch terminates with error", function()
      local s = "\x51\x6a"  -- OP_1 OP_RETURN
      assert.has_error(function()
        script.execute_script(s)
      end)
    end)

    it("OP_VERIFY with true value succeeds", function()
      local s = "\x51\x69\x52"  -- OP_1 OP_VERIFY OP_2
      local stack = script.execute_script(s)
      assert.equals(1, #stack)
      assert.equals(2, script.script_num_decode(stack[1]))
    end)

    it("OP_VERIFY with false value fails", function()
      local s = "\x00\x69"  -- OP_0 OP_VERIFY
      assert.has_error(function()
        script.execute_script(s)
      end)
    end)
  end)

  describe("execute_script stack operations", function()
    it("OP_DUP duplicates top element", function()
      local s = "\x53\x76"  -- OP_3 OP_DUP
      local stack = script.execute_script(s)
      assert.equals(2, #stack)
      assert.equals(3, script.script_num_decode(stack[1]))
      assert.equals(3, script.script_num_decode(stack[2]))
    end)

    it("OP_DROP removes top element", function()
      local s = "\x53\x54\x75"  -- OP_3 OP_4 OP_DROP
      local stack = script.execute_script(s)
      assert.equals(1, #stack)
      assert.equals(3, script.script_num_decode(stack[1]))
    end)

    it("OP_SWAP swaps top two elements", function()
      local s = "\x53\x54\x7c"  -- OP_3 OP_4 OP_SWAP
      local stack = script.execute_script(s)
      assert.equals(2, #stack)
      assert.equals(4, script.script_num_decode(stack[1]))
      assert.equals(3, script.script_num_decode(stack[2]))
    end)

    it("OP_ROT rotates top three elements", function()
      local s = "\x51\x52\x53\x7b"  -- OP_1 OP_2 OP_3 OP_ROT
      local stack = script.execute_script(s)
      assert.equals(3, #stack)
      -- ROT: a b c -> b c a
      assert.equals(2, script.script_num_decode(stack[1]))
      assert.equals(3, script.script_num_decode(stack[2]))
      assert.equals(1, script.script_num_decode(stack[3]))
    end)

    it("OP_OVER copies second-to-top", function()
      local s = "\x53\x54\x78"  -- OP_3 OP_4 OP_OVER
      local stack = script.execute_script(s)
      assert.equals(3, #stack)
      assert.equals(3, script.script_num_decode(stack[1]))
      assert.equals(4, script.script_num_decode(stack[2]))
      assert.equals(3, script.script_num_decode(stack[3]))
    end)

    it("OP_PICK picks element by index", function()
      local s = "\x51\x52\x53\x52\x79"  -- OP_1 OP_2 OP_3 OP_2 OP_PICK
      local stack = script.execute_script(s)
      assert.equals(4, #stack)
      assert.equals(1, script.script_num_decode(stack[4]))  -- top is copy of bottom
    end)

    it("OP_ROLL removes and pushes element by index", function()
      local s = "\x51\x52\x53\x52\x7a"  -- OP_1 OP_2 OP_3 OP_2 OP_ROLL
      local stack = script.execute_script(s)
      assert.equals(3, #stack)
      assert.equals(1, script.script_num_decode(stack[3]))  -- 1 moved to top
    end)

    it("OP_DEPTH pushes stack depth", function()
      local s = "\x51\x52\x53\x74"  -- OP_1 OP_2 OP_3 OP_DEPTH
      local stack = script.execute_script(s)
      assert.equals(4, #stack)
      assert.equals(3, script.script_num_decode(stack[4]))
    end)

    it("OP_TOALTSTACK and OP_FROMALTSTACK work", function()
      local s = "\x53\x6b\x54\x6c"  -- OP_3 OP_TOALTSTACK OP_4 OP_FROMALTSTACK
      local stack = script.execute_script(s)
      assert.equals(2, #stack)
      assert.equals(4, script.script_num_decode(stack[1]))
      assert.equals(3, script.script_num_decode(stack[2]))
    end)

    it("OP_2DUP duplicates top two", function()
      local s = "\x53\x54\x6e"  -- OP_3 OP_4 OP_2DUP
      local stack = script.execute_script(s)
      assert.equals(4, #stack)
      assert.equals(3, script.script_num_decode(stack[1]))
      assert.equals(4, script.script_num_decode(stack[2]))
      assert.equals(3, script.script_num_decode(stack[3]))
      assert.equals(4, script.script_num_decode(stack[4]))
    end)

    it("OP_SIZE pushes size of top element", function()
      local s = "\x04test\x82"  -- push "test" then OP_SIZE
      local stack = script.execute_script(s)
      assert.equals(2, #stack)
      assert.equals("test", stack[1])
      assert.equals(4, script.script_num_decode(stack[2]))
    end)
  end)

  describe("execute_script crypto operations", function()
    local crypto

    setup(function()
      crypto = require("lunarblock.crypto")
    end)

    it("OP_HASH160 computes HASH160", function()
      local s = "\x05hello\xa9"  -- push "hello" then OP_HASH160
      local stack = script.execute_script(s)
      assert.equals(1, #stack)
      local expected = crypto.hash160("hello")
      assert.equals(expected, stack[1])
    end)

    it("OP_HASH256 computes double SHA256", function()
      local s = "\x05hello\xaa"  -- push "hello" then OP_HASH256
      local stack = script.execute_script(s)
      assert.equals(1, #stack)
      local expected = crypto.hash256("hello")
      assert.equals(expected, stack[1])
    end)

    it("OP_SHA256 computes single SHA256", function()
      local s = "\x05hello\xa8"  -- push "hello" then OP_SHA256
      local stack = script.execute_script(s)
      assert.equals(1, #stack)
      local expected = crypto.sha256("hello")
      assert.equals(expected, stack[1])
    end)

    it("OP_RIPEMD160 computes RIPEMD160", function()
      local s = "\x05hello\xa6"  -- push "hello" then OP_RIPEMD160
      local stack = script.execute_script(s)
      assert.equals(1, #stack)
      local expected = crypto.ripemd160("hello")
      assert.equals(expected, stack[1])
    end)
  end)

  describe("P2PKH execution", function()
    local crypto

    setup(function()
      crypto = require("lunarblock.crypto")
    end)

    it("P2PKH pattern with mock checker returning true", function()
      local pubkey = string.rep("\x11", 33)  -- mock compressed pubkey
      local pubkey_hash = crypto.hash160(pubkey)  -- Use correct hash for the pubkey

      -- Build scriptPubKey
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      -- Create initial stack: [signature, pubkey]
      local sig = "mocksig"
      local stack = {sig, pubkey}

      -- Create checker that always validates
      local checker = {
        check_sig = function(s, pk)
          return s == sig and pk == pubkey
        end
      }

      -- Execute
      local result = script.execute_script(script_pubkey, stack, {}, checker)
      assert.equals(1, #result)
      assert.is_true(script.cast_to_bool(result[1]))
    end)

    it("P2PKH pattern with mock checker returning false", function()
      local pubkey = string.rep("\x11", 33)
      local pubkey_hash = crypto.hash160(pubkey)

      local script_pubkey = script.make_p2pkh_script(pubkey_hash)
      local sig = "mocksig"
      local stack = {sig, pubkey}

      -- Checker that always fails
      local checker = {
        check_sig = function(s, pk)
          return false
        end
      }

      local result = script.execute_script(script_pubkey, stack, {}, checker)
      assert.equals(1, #result)
      assert.is_false(script.cast_to_bool(result[1]))
    end)
  end)

  describe("CHECKMULTISIG", function()
    it("2-of-3 CHECKMULTISIG with mock checker succeeds", function()
      -- Build 2-of-3 multisig script
      -- OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG
      local pk1 = string.rep("\x01", 33)
      local pk2 = string.rep("\x02", 33)
      local pk3 = string.rep("\x03", 33)
      local sig1 = "sig1"
      local sig2 = "sig2"

      local script_pubkey = script.build_script({
        {opcode = script.OP.OP_2, data = nil},
        {opcode = 33, data = pk1},
        {opcode = 33, data = pk2},
        {opcode = 33, data = pk3},
        {opcode = script.OP.OP_3, data = nil},
        {opcode = script.OP.OP_CHECKMULTISIG, data = nil},
      })

      -- Stack: dummy, sig1, sig2 (bottom to top)
      local stack = {"", sig1, sig2}

      -- Checker that validates sig1 with pk1 and sig2 with pk2
      local checker = {
        check_sig = function(sig, pk)
          if sig == sig1 and pk == pk1 then return true end
          if sig == sig2 and pk == pk2 then return true end
          return false
        end
      }

      local result = script.execute_script(script_pubkey, stack, {}, checker)
      assert.equals(1, #result)
      assert.is_true(script.cast_to_bool(result[1]))
    end)

    it("2-of-3 CHECKMULTISIG fails when not enough valid sigs", function()
      local pk1 = string.rep("\x01", 33)
      local pk2 = string.rep("\x02", 33)
      local pk3 = string.rep("\x03", 33)
      local sig1 = "sig1"
      local sig2 = "badsig"

      local script_pubkey = script.build_script({
        {opcode = script.OP.OP_2, data = nil},
        {opcode = 33, data = pk1},
        {opcode = 33, data = pk2},
        {opcode = 33, data = pk3},
        {opcode = script.OP.OP_3, data = nil},
        {opcode = script.OP.OP_CHECKMULTISIG, data = nil},
      })

      local stack = {"", sig1, sig2}

      local checker = {
        check_sig = function(sig, pk)
          if sig == sig1 and pk == pk1 then return true end
          return false
        end
      }

      local result = script.execute_script(script_pubkey, stack, {}, checker)
      assert.equals(1, #result)
      assert.is_false(script.cast_to_bool(result[1]))
    end)

    it("CHECKMULTISIG enforces NULLDUMMY flag", function()
      local pk1 = string.rep("\x01", 33)
      local sig1 = "sig1"

      local script_pubkey = script.build_script({
        {opcode = script.OP.OP_1, data = nil},
        {opcode = 33, data = pk1},
        {opcode = script.OP.OP_1, data = nil},
        {opcode = script.OP.OP_CHECKMULTISIG, data = nil},
      })

      -- Stack with non-empty dummy
      local stack = {"xx", sig1}

      local checker = {
        check_sig = function(sig, pk) return true end
      }

      -- Without NULLDUMMY flag, should succeed
      local result = script.execute_script(script_pubkey, stack, {}, checker)
      assert.is_true(script.cast_to_bool(result[1]))

      -- With NULLDUMMY flag, should fail
      stack = {"xx", sig1}
      assert.has_error(function()
        script.execute_script(script_pubkey, stack, {verify_nulldummy = true}, checker)
      end)
    end)
  end)

  describe("disabled opcodes", function()
    local disabled_ops = {
      {0x7e, "OP_CAT"},
      {0x7f, "OP_SUBSTR"},
      {0x80, "OP_LEFT"},
      {0x81, "OP_RIGHT"},
      {0x83, "OP_INVERT"},
      {0x84, "OP_AND"},
      {0x85, "OP_OR"},
      {0x86, "OP_XOR"},
      {0x8d, "OP_2MUL"},
      {0x8e, "OP_2DIV"},
      {0x95, "OP_MUL"},
      {0x96, "OP_DIV"},
      {0x97, "OP_MOD"},
      {0x98, "OP_LSHIFT"},
      {0x99, "OP_RSHIFT"},
    }

    for _, op_info in ipairs(disabled_ops) do
      local opcode, name = op_info[1], op_info[2]
      it(name .. " raises error", function()
        -- Push some data and try the disabled opcode
        local s = "\x51\x51" .. string.char(opcode)
        assert.has_error(function()
          script.execute_script(s)
        end, "disabled opcode")
      end)
    end
  end)

  describe("reserved opcodes", function()
    it("OP_RESERVED raises error when executed", function()
      local s = "\x50"
      assert.has_error(function()
        script.execute_script(s)
      end)
    end)

    it("OP_VER raises error when executed", function()
      local s = "\x62"
      assert.has_error(function()
        script.execute_script(s)
      end)
    end)

    it("OP_RESERVED1 raises error when executed", function()
      local s = "\x89"
      assert.has_error(function()
        script.execute_script(s)
      end)
    end)

    it("OP_RESERVED2 raises error when executed", function()
      local s = "\x8a"
      assert.has_error(function()
        script.execute_script(s)
      end)
    end)

    it("OP_VERIF always fails even in non-executing branch", function()
      local s = "\x00\x63\x65\x68"  -- OP_0 OP_IF OP_VERIF OP_ENDIF
      assert.has_error(function()
        script.execute_script(s)
      end)
    end)
  end)

  describe("verify_script", function()
    it("simple script verification succeeds", function()
      -- scriptSig: OP_1
      -- scriptPubKey: OP_1 OP_EQUAL
      local script_sig = "\x51"
      local script_pubkey = "\x51\x87"

      local result = script.verify_script(script_sig, script_pubkey)
      assert.is_true(result)
    end)

    it("simple script verification fails when not equal", function()
      -- scriptSig: OP_2
      -- scriptPubKey: OP_1 OP_EQUAL
      local script_sig = "\x52"
      local script_pubkey = "\x51\x87"

      local result = script.verify_script(script_sig, script_pubkey)
      assert.is_false(result)
    end)

    it("P2SH verify_script with embedded P2PKH redeem script", function()
      local crypto = require("lunarblock.crypto")

      -- Create a simple redeem script (OP_1 OP_EQUAL)
      local redeem_script = "\x51\x87"
      local script_hash = crypto.hash160(redeem_script)

      -- scriptPubKey is P2SH pattern
      local script_pubkey = script.make_p2sh_script(script_hash)

      -- scriptSig pushes OP_1 and the redeem script
      local script_sig = script.build_script({
        {opcode = script.OP.OP_1, data = nil},
        {opcode = #redeem_script, data = redeem_script},
      })

      local result = script.verify_script(script_sig, script_pubkey, {verify_p2sh = true})
      assert.is_true(result)
    end)

    it("P2SH fails when redeem script fails", function()
      local crypto = require("lunarblock.crypto")

      -- Create a simple redeem script (OP_1 OP_EQUAL)
      local redeem_script = "\x51\x87"
      local script_hash = crypto.hash160(redeem_script)
      local script_pubkey = script.make_p2sh_script(script_hash)

      -- scriptSig pushes OP_2 (wrong value) and the redeem script
      local script_sig = script.build_script({
        {opcode = script.OP.OP_2, data = nil},
        {opcode = #redeem_script, data = redeem_script},
      })

      local result = script.verify_script(script_sig, script_pubkey, {verify_p2sh = true})
      assert.is_false(result)
    end)
  end)

  describe("OP_EQUAL and OP_EQUALVERIFY", function()
    it("OP_EQUAL returns true for equal values", function()
      local s = "\x04test\x04test\x87"
      local stack = script.execute_script(s)
      assert.is_true(script.cast_to_bool(stack[1]))
    end)

    it("OP_EQUAL returns false for unequal values", function()
      local s = "\x04test\x05other\x87"
      local stack = script.execute_script(s)
      assert.is_false(script.cast_to_bool(stack[1]))
    end)

    it("OP_EQUALVERIFY succeeds for equal values", function()
      local s = "\x04test\x04test\x88\x51"
      local stack = script.execute_script(s)
      assert.equals(1, #stack)
    end)

    it("OP_EQUALVERIFY fails for unequal values", function()
      local s = "\x04test\x05other\x88"
      assert.has_error(function()
        script.execute_script(s)
      end)
    end)
  end)

  describe("opcode limit", function()
    it("exceeding 201 opcodes fails", function()
      -- Create a script with 202 OP_NOPs
      local parts = {}
      for i = 1, 202 do
        parts[i] = "\x61"  -- OP_NOP
      end
      local s = table.concat(parts)

      assert.has_error(function()
        script.execute_script(s)
      end, "too many opcodes")
    end)

    it("exactly 201 opcodes succeeds", function()
      local parts = {}
      for i = 1, 201 do
        parts[i] = "\x61"
      end
      local s = table.concat(parts)

      -- Should not error
      local stack = script.execute_script(s)
      assert.equals(0, #stack)
    end)
  end)

  describe("OP_CHECKSIGADD", function()
    -- BIP342 / Core interpreter.cpp:1089 stack layout (bottom -> top):
    --   sig, num, pubkey
    -- Pop order from top: pubkey, num, sig.
    -- Pre-fix lunarblock popped pubkey, sig, num — wrong by stack-design,
    -- but masked here because the original tests pushed in the buggy order.
    -- Tests below now reflect the BIP342 layout.
    it("increments counter when signature is valid", function()
      local pk = string.rep("\x01", 32)
      local sig = "validsig"

      local checker = {
        check_sig = function(s, p)
          return s == sig and p == pk
        end
      }

      -- BIP342 stack: sig, num, pk (bottom to top); OP_CHECKSIGADD pushes
      -- num+1=1 because the sig is valid.
      local s = script.build_script({
        {opcode = #sig, data = sig},            -- sig (bottom)
        {opcode = script.OP.OP_0, data = nil},  -- num = 0
        {opcode = #pk, data = pk},              -- pubkey (top)
        {opcode = script.OP.OP_CHECKSIGADD, data = nil},
      })

      local result = script.execute_script(s, {}, {}, checker)
      assert.equals(1, #result)
      assert.equals(1, script.script_num_decode(result[1]))
    end)

    it("does not increment for empty signature", function()
      local pk = string.rep("\x01", 32)

      local checker = {
        check_sig = function(s, p)
          return false
        end
      }

      -- BIP342 stack: empty sig, num=5, pk
      local s = script.build_script({
        {opcode = script.OP.OP_0, data = nil},  -- empty sig (bottom)
        {opcode = script.OP.OP_5, data = nil},  -- num = 5
        {opcode = #pk, data = pk},              -- pubkey (top)
        {opcode = script.OP.OP_CHECKSIGADD, data = nil},
      })

      local result = script.execute_script(s, {}, {}, checker)
      assert.equals(1, #result)
      assert.equals(5, script.script_num_decode(result[1]))  -- unchanged
    end)
  end)

  describe("is_push_only", function()
    it("returns true for OP_0", function()
      assert.is_true(script.is_push_only("\x00"))
    end)

    it("returns true for direct push (1-75 bytes)", function()
      -- 5-byte push
      assert.is_true(script.is_push_only("\x05hello"))
    end)

    it("returns true for OP_PUSHDATA1", function()
      -- PUSHDATA1 with 76 bytes
      local data = string.rep("x", 76)
      local s = string.char(0x4c, 76) .. data
      assert.is_true(script.is_push_only(s))
    end)

    it("returns true for OP_PUSHDATA2", function()
      -- PUSHDATA2 with 256 bytes
      local data = string.rep("x", 256)
      local s = string.char(0x4d, 0x00, 0x01) .. data
      assert.is_true(script.is_push_only(s))
    end)

    it("returns true for OP_1NEGATE", function()
      assert.is_true(script.is_push_only("\x4f"))
    end)

    it("returns true for OP_RESERVED", function()
      -- OP_RESERVED (0x50) is considered push-only per Bitcoin Core
      assert.is_true(script.is_push_only("\x50"))
    end)

    it("returns true for OP_1 through OP_16", function()
      for op = 0x51, 0x60 do
        assert.is_true(script.is_push_only(string.char(op)))
      end
    end)

    it("returns true for multiple push ops", function()
      -- OP_1 <sig> <pubkey>
      local s = "\x51" .. "\x05hello" .. "\x06world!"
      assert.is_true(script.is_push_only(s))
    end)

    it("returns false for OP_NOP (0x61)", function()
      assert.is_false(script.is_push_only("\x61"))
    end)

    it("returns false for OP_DUP", function()
      assert.is_false(script.is_push_only("\x76"))
    end)

    it("returns false for OP_HASH160", function()
      assert.is_false(script.is_push_only("\xa9"))
    end)

    it("returns false for OP_CHECKSIG", function()
      assert.is_false(script.is_push_only("\xac"))
    end)

    it("returns false for script with push and non-push ops", function()
      -- OP_1 OP_DUP
      assert.is_false(script.is_push_only("\x51\x76"))
    end)

    it("returns false for P2PKH scriptPubKey", function()
      local pubkey_hash = string.rep("\x42", 20)
      local p2pkh = script.make_p2pkh_script(pubkey_hash)
      assert.is_false(script.is_push_only(p2pkh))
    end)

    it("returns true for empty script", function()
      assert.is_true(script.is_push_only(""))
    end)
  end)

  describe("P2SH push-only scriptSig enforcement", function()
    local crypto

    setup(function()
      crypto = require("lunarblock.crypto")
    end)

    it("fails P2SH with scriptSig containing OP_DUP", function()
      -- Create a simple redeem script
      local redeem_script = "\x51\x87"  -- OP_1 OP_EQUAL
      local script_hash = crypto.hash160(redeem_script)
      local script_pubkey = script.make_p2sh_script(script_hash)

      -- scriptSig with OP_DUP (0x76) which is not push-only
      -- OP_1 OP_DUP OP_DROP <redeem_script>
      local script_sig = "\x51\x76\x75" .. string.char(#redeem_script) .. redeem_script

      local result, err = script.verify_script(script_sig, script_pubkey, {verify_p2sh = true})
      assert.is_nil(result)
      assert.equals("SIG_PUSHONLY", err)
    end)

    it("fails P2SH with scriptSig containing OP_NOP", function()
      local redeem_script = "\x51\x87"  -- OP_1 OP_EQUAL
      local script_hash = crypto.hash160(redeem_script)
      local script_pubkey = script.make_p2sh_script(script_hash)

      -- scriptSig with OP_NOP (0x61)
      local script_sig = "\x61\x51" .. string.char(#redeem_script) .. redeem_script

      local result, err = script.verify_script(script_sig, script_pubkey, {verify_p2sh = true})
      assert.is_nil(result)
      assert.equals("SIG_PUSHONLY", err)
    end)

    it("fails P2SH with scriptSig containing OP_CHECKSIG", function()
      local redeem_script = "\x51\x87"
      local script_hash = crypto.hash160(redeem_script)
      local script_pubkey = script.make_p2sh_script(script_hash)

      -- scriptSig with OP_CHECKSIG (0xac)
      local script_sig = "\xac" .. string.char(#redeem_script) .. redeem_script

      local result, err = script.verify_script(script_sig, script_pubkey, {verify_p2sh = true})
      assert.is_nil(result)
      assert.equals("SIG_PUSHONLY", err)
    end)

    it("succeeds P2SH with valid push-only scriptSig", function()
      local redeem_script = "\x51\x87"  -- OP_1 OP_EQUAL
      local script_hash = crypto.hash160(redeem_script)
      local script_pubkey = script.make_p2sh_script(script_hash)

      -- scriptSig with only pushes: OP_1 <redeem_script>
      local script_sig = script.build_script({
        {opcode = script.OP.OP_1, data = nil},
        {opcode = #redeem_script, data = redeem_script},
      })

      local result, err = script.verify_script(script_sig, script_pubkey, {verify_p2sh = true})
      assert.is_nil(err)
      assert.is_true(result)
    end)

    it("push-only check is unconditional for P2SH (not flag-gated)", function()
      -- Even with verify_p2sh = true, the push-only check should happen
      local redeem_script = "\x51\x87"
      local script_hash = crypto.hash160(redeem_script)
      local script_pubkey = script.make_p2sh_script(script_hash)

      -- scriptSig with OP_ADD (non-push)
      local script_sig = "\x51\x51\x93" .. string.char(#redeem_script) .. redeem_script

      local result, err = script.verify_script(script_sig, script_pubkey, {verify_p2sh = true})
      assert.is_nil(result)
      assert.equals("SIG_PUSHONLY", err)
    end)
  end)

  describe("unknown NOPs are treated as NOP", function()
    it("OP_NOP1 does nothing", function()
      local s = "\x51\xb0\x52"  -- OP_1 OP_NOP1 OP_2
      local stack = script.execute_script(s)
      assert.equals(2, #stack)
    end)

    it("unknown NOPs (0xb3-0xb9) do nothing", function()
      for opcode = 0xb3, 0xb9 do
        local s = "\x51" .. string.char(opcode) .. "\x52"
        local stack = script.execute_script(s)
        assert.equals(2, #stack)
      end
    end)
  end)

  describe("SCRIPT_VERIFY_NULLFAIL (BIP146)", function()
    describe("OP_CHECKSIG with NULLFAIL flag", function()
      it("allows empty signature when sig check fails", function()
        local pk = string.rep("\x01", 33)

        -- Checker that always rejects signatures
        local checker = {
          check_sig = function(sig, pubkey)
            return false
          end
        }

        -- Stack: empty_sig, pubkey
        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_CHECKSIG, data = nil},
        })
        local stack = {"", pk}

        -- With NULLFAIL flag, empty sig on failed check should succeed (returns false)
        local result, err = script.execute_script(script_pubkey, stack, {verify_nullfail = true}, checker)
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.is_false(script.cast_to_bool(result[1]))
      end)

      it("rejects non-empty signature when sig check fails", function()
        local pk = string.rep("\x01", 33)
        local sig = "invalid_sig"

        -- Checker that always rejects signatures
        local checker = {
          check_sig = function(s, pubkey)
            return false
          end
        }

        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_CHECKSIG, data = nil},
        })
        local stack = {sig, pk}

        -- With NULLFAIL flag, non-empty sig on failed check should error
        local result, err = script.execute_script(script_pubkey, stack, {verify_nullfail = true}, checker)
        assert.is_nil(result)
        assert.equals("NULLFAIL", err)
      end)

      it("allows non-empty signature when sig check succeeds", function()
        local pk = string.rep("\x01", 33)
        local sig = "valid_sig"

        -- Checker that accepts specific sig
        local checker = {
          check_sig = function(s, pubkey)
            return s == sig and pubkey == pk
          end
        }

        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_CHECKSIG, data = nil},
        })
        local stack = {sig, pk}

        -- With NULLFAIL flag, valid sig should succeed
        local result, err = script.execute_script(script_pubkey, stack, {verify_nullfail = true}, checker)
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.is_true(script.cast_to_bool(result[1]))
      end)

      it("allows non-empty signature when NULLFAIL flag is not set", function()
        local pk = string.rep("\x01", 33)
        local sig = "invalid_sig"

        -- Checker that always rejects
        local checker = {
          check_sig = function(s, pubkey)
            return false
          end
        }

        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_CHECKSIG, data = nil},
        })
        local stack = {sig, pk}

        -- Without NULLFAIL flag, non-empty failed sig should still work (returns false)
        local result, err = script.execute_script(script_pubkey, stack, {}, checker)
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.is_false(script.cast_to_bool(result[1]))
      end)
    end)

    describe("OP_CHECKSIGVERIFY with NULLFAIL flag", function()
      it("rejects non-empty signature when sig check fails", function()
        local pk = string.rep("\x01", 33)
        local sig = "invalid_sig"

        local checker = {
          check_sig = function(s, pubkey)
            return false
          end
        }

        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_CHECKSIGVERIFY, data = nil},
        })
        local stack = {sig, pk}

        -- With NULLFAIL flag, should return NULLFAIL error (not CHECKSIGVERIFY failed)
        local result, err = script.execute_script(script_pubkey, stack, {verify_nullfail = true}, checker)
        assert.is_nil(result)
        assert.equals("NULLFAIL", err)
      end)
    end)

    describe("OP_CHECKMULTISIG with NULLFAIL flag", function()
      it("allows empty signatures when multisig fails", function()
        local pk1 = string.rep("\x01", 33)
        local pk2 = string.rep("\x02", 33)

        -- Checker that always rejects
        local checker = {
          check_sig = function(s, pubkey)
            return false
          end
        }

        -- 2-of-2 multisig: OP_2 <pk1> <pk2> OP_2 OP_CHECKMULTISIG
        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_2, data = nil},
          {opcode = 33, data = pk1},
          {opcode = 33, data = pk2},
          {opcode = script.OP.OP_2, data = nil},
          {opcode = script.OP.OP_CHECKMULTISIG, data = nil},
        })

        -- Stack: dummy, empty_sig1, empty_sig2 (all empty)
        local stack = {"", "", ""}

        -- With NULLFAIL flag, empty sigs on failed check should succeed (returns false)
        local result, err = script.execute_script(script_pubkey, stack, {verify_nullfail = true}, checker)
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.is_false(script.cast_to_bool(result[1]))
      end)

      it("rejects non-empty signature when multisig fails", function()
        local pk1 = string.rep("\x01", 33)
        local pk2 = string.rep("\x02", 33)

        -- Checker that always rejects
        local checker = {
          check_sig = function(s, pubkey)
            return false
          end
        }

        -- 2-of-2 multisig
        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_2, data = nil},
          {opcode = 33, data = pk1},
          {opcode = 33, data = pk2},
          {opcode = script.OP.OP_2, data = nil},
          {opcode = script.OP.OP_CHECKMULTISIG, data = nil},
        })

        -- Stack: dummy, sig1, sig2 where sig1 is non-empty
        local stack = {"", "badsig", ""}

        -- With NULLFAIL flag, non-empty sig on failed check should error
        local result, err = script.execute_script(script_pubkey, stack, {verify_nullfail = true}, checker)
        assert.is_nil(result)
        assert.equals("NULLFAIL", err)
      end)

      it("rejects when any signature is non-empty on failure", function()
        local pk1 = string.rep("\x01", 33)
        local pk2 = string.rep("\x02", 33)

        -- Checker that always rejects
        local checker = {
          check_sig = function(s, pubkey)
            return false
          end
        }

        -- 2-of-2 multisig
        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_2, data = nil},
          {opcode = 33, data = pk1},
          {opcode = 33, data = pk2},
          {opcode = script.OP.OP_2, data = nil},
          {opcode = script.OP.OP_CHECKMULTISIG, data = nil},
        })

        -- Stack: dummy, empty_sig1, non_empty_sig2
        local stack = {"", "", "badsig"}

        -- With NULLFAIL flag, should error because second sig is non-empty
        local result, err = script.execute_script(script_pubkey, stack, {verify_nullfail = true}, checker)
        assert.is_nil(result)
        assert.equals("NULLFAIL", err)
      end)

      it("allows non-empty signatures when multisig succeeds", function()
        local pk1 = string.rep("\x01", 33)
        local pk2 = string.rep("\x02", 33)
        local sig1 = "sig1"
        local sig2 = "sig2"

        -- Checker that accepts specific sigs
        local checker = {
          check_sig = function(s, pubkey)
            if s == sig1 and pubkey == pk1 then return true end
            if s == sig2 and pubkey == pk2 then return true end
            return false
          end
        }

        -- 2-of-2 multisig
        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_2, data = nil},
          {opcode = 33, data = pk1},
          {opcode = 33, data = pk2},
          {opcode = script.OP.OP_2, data = nil},
          {opcode = script.OP.OP_CHECKMULTISIG, data = nil},
        })

        -- Stack: dummy, sig1, sig2 (valid)
        local stack = {"", sig1, sig2}

        -- With NULLFAIL flag, valid sigs should succeed
        local result, err = script.execute_script(script_pubkey, stack, {verify_nullfail = true}, checker)
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.is_true(script.cast_to_bool(result[1]))
      end)

      it("allows non-empty signatures when NULLFAIL flag is not set", function()
        local pk1 = string.rep("\x01", 33)
        local pk2 = string.rep("\x02", 33)

        -- Checker that always rejects
        local checker = {
          check_sig = function(s, pubkey)
            return false
          end
        }

        -- 2-of-2 multisig
        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_2, data = nil},
          {opcode = 33, data = pk1},
          {opcode = 33, data = pk2},
          {opcode = script.OP.OP_2, data = nil},
          {opcode = script.OP.OP_CHECKMULTISIG, data = nil},
        })

        -- Stack: dummy, sig1, sig2 where sigs are non-empty
        local stack = {"", "badsig1", "badsig2"}

        -- Without NULLFAIL flag, non-empty failed sigs should still work (returns false)
        local result, err = script.execute_script(script_pubkey, stack, {}, checker)
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.is_false(script.cast_to_bool(result[1]))
      end)
    end)

    describe("OP_CHECKMULTISIGVERIFY with NULLFAIL flag", function()
      it("rejects non-empty signature when multisig fails", function()
        local pk1 = string.rep("\x01", 33)

        local checker = {
          check_sig = function(s, pubkey)
            return false
          end
        }

        -- 1-of-1 multisig verify
        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_1, data = nil},
          {opcode = 33, data = pk1},
          {opcode = script.OP.OP_1, data = nil},
          {opcode = script.OP.OP_CHECKMULTISIGVERIFY, data = nil},
        })

        local stack = {"", "badsig"}

        -- With NULLFAIL flag, should return NULLFAIL error
        local result, err = script.execute_script(script_pubkey, stack, {verify_nullfail = true}, checker)
        assert.is_nil(result)
        assert.equals("NULLFAIL", err)
      end)
    end)
  end)

  describe("SCRIPT_VERIFY_WITNESS_PUBKEYTYPE (BIP141)", function()
    describe("OP_CHECKSIG with witness_pubkeytype flag", function()
      it("accepts compressed pubkey (33 bytes, 0x02 prefix) in witness v0", function()
        -- 33-byte compressed pubkey with 0x02 prefix
        local compressed_pk = "\x02" .. string.rep("\x42", 32)
        local sig = "validsig"

        local checker = {
          check_sig = function(s, pk)
            return s == sig and pk == compressed_pk
          end
        }

        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_CHECKSIG, data = nil},
        })
        local stack = {sig, compressed_pk}

        -- With witness_pubkeytype flag AND is_witness_v0, compressed key should succeed
        local flags = {verify_witness_pubkeytype = true, is_witness_v0 = true}
        local result, err = script.execute_script(script_pubkey, stack, flags, checker)
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.is_true(script.cast_to_bool(result[1]))
      end)

      it("accepts compressed pubkey (33 bytes, 0x03 prefix) in witness v0", function()
        -- 33-byte compressed pubkey with 0x03 prefix
        local compressed_pk = "\x03" .. string.rep("\x42", 32)
        local sig = "validsig"

        local checker = {
          check_sig = function(s, pk)
            return s == sig and pk == compressed_pk
          end
        }

        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_CHECKSIG, data = nil},
        })
        local stack = {sig, compressed_pk}

        local flags = {verify_witness_pubkeytype = true, is_witness_v0 = true}
        local result, err = script.execute_script(script_pubkey, stack, flags, checker)
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.is_true(script.cast_to_bool(result[1]))
      end)

      it("rejects uncompressed pubkey (65 bytes, 0x04 prefix) in witness v0", function()
        -- 65-byte uncompressed pubkey with 0x04 prefix
        local uncompressed_pk = "\x04" .. string.rep("\x42", 64)
        local sig = "validsig"

        local checker = {
          check_sig = function(s, pk)
            return true  -- Would be valid if pubkey check passed
          end
        }

        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_CHECKSIG, data = nil},
        })
        local stack = {sig, uncompressed_pk}

        -- With witness_pubkeytype flag AND is_witness_v0, uncompressed key should fail
        local flags = {verify_witness_pubkeytype = true, is_witness_v0 = true}
        local result, err = script.execute_script(script_pubkey, stack, flags, checker)
        assert.is_nil(result)
        assert.equals("WITNESS_PUBKEYTYPE", err)
      end)

      it("allows uncompressed pubkey when not in witness v0", function()
        -- 65-byte uncompressed pubkey with 0x04 prefix
        local uncompressed_pk = "\x04" .. string.rep("\x42", 64)
        local sig = "validsig"

        local checker = {
          check_sig = function(s, pk)
            return s == sig and pk == uncompressed_pk
          end
        }

        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_CHECKSIG, data = nil},
        })
        local stack = {sig, uncompressed_pk}

        -- With witness_pubkeytype flag but NOT is_witness_v0, uncompressed key should pass
        local flags = {verify_witness_pubkeytype = true, is_witness_v0 = false}
        local result, err = script.execute_script(script_pubkey, stack, flags, checker)
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.is_true(script.cast_to_bool(result[1]))
      end)

      it("allows uncompressed pubkey when witness_pubkeytype flag not set", function()
        -- 65-byte uncompressed pubkey
        local uncompressed_pk = "\x04" .. string.rep("\x42", 64)
        local sig = "validsig"

        local checker = {
          check_sig = function(s, pk)
            return s == sig and pk == uncompressed_pk
          end
        }

        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_CHECKSIG, data = nil},
        })
        local stack = {sig, uncompressed_pk}

        -- Without witness_pubkeytype flag, uncompressed key should pass
        local flags = {is_witness_v0 = true}  -- witness v0 but no pubkeytype flag
        local result, err = script.execute_script(script_pubkey, stack, flags, checker)
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.is_true(script.cast_to_bool(result[1]))
      end)

      it("rejects wrong-length pubkey in witness v0", function()
        -- 32-byte key (wrong length)
        local wrong_len_pk = string.rep("\x42", 32)
        local sig = "validsig"

        local checker = {
          check_sig = function(s, pk)
            return true
          end
        }

        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_CHECKSIG, data = nil},
        })
        local stack = {sig, wrong_len_pk}

        local flags = {verify_witness_pubkeytype = true, is_witness_v0 = true}
        local result, err = script.execute_script(script_pubkey, stack, flags, checker)
        assert.is_nil(result)
        assert.equals("WITNESS_PUBKEYTYPE", err)
      end)
    end)

    describe("OP_CHECKSIGVERIFY with witness_pubkeytype flag", function()
      it("rejects uncompressed pubkey in witness v0", function()
        local uncompressed_pk = "\x04" .. string.rep("\x42", 64)
        local sig = "validsig"

        local checker = {
          check_sig = function(s, pk) return true end
        }

        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_CHECKSIGVERIFY, data = nil},
        })
        local stack = {sig, uncompressed_pk}

        local flags = {verify_witness_pubkeytype = true, is_witness_v0 = true}
        local result, err = script.execute_script(script_pubkey, stack, flags, checker)
        assert.is_nil(result)
        assert.equals("WITNESS_PUBKEYTYPE", err)
      end)
    end)

    describe("OP_CHECKMULTISIG with witness_pubkeytype flag", function()
      it("accepts all compressed pubkeys in witness v0", function()
        local pk1 = "\x02" .. string.rep("\x01", 32)
        local pk2 = "\x03" .. string.rep("\x02", 32)
        local sig1 = "sig1"

        local checker = {
          check_sig = function(sig, pk)
            return sig == sig1 and pk == pk1
          end
        }

        -- 1-of-2 multisig
        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_1, data = nil},
          {opcode = 33, data = pk1},
          {opcode = 33, data = pk2},
          {opcode = script.OP.OP_2, data = nil},
          {opcode = script.OP.OP_CHECKMULTISIG, data = nil},
        })
        local stack = {"", sig1}  -- dummy, sig1

        local flags = {verify_witness_pubkeytype = true, is_witness_v0 = true}
        local result, err = script.execute_script(script_pubkey, stack, flags, checker)
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.is_true(script.cast_to_bool(result[1]))
      end)

      it("rejects if any pubkey is uncompressed in witness v0", function()
        local pk1 = "\x02" .. string.rep("\x01", 32)  -- compressed
        local pk2 = "\x04" .. string.rep("\x02", 64)  -- uncompressed
        local sig1 = "sig1"

        local checker = {
          check_sig = function(sig, pk)
            return sig == sig1 and pk == pk1
          end
        }

        -- 1-of-2 multisig where one key is uncompressed
        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_1, data = nil},
          {opcode = 33, data = pk1},
          {opcode = 65, data = pk2},  -- uncompressed key
          {opcode = script.OP.OP_2, data = nil},
          {opcode = script.OP.OP_CHECKMULTISIG, data = nil},
        })
        local stack = {"", sig1}

        local flags = {verify_witness_pubkeytype = true, is_witness_v0 = true}
        local result, err = script.execute_script(script_pubkey, stack, flags, checker)
        assert.is_nil(result)
        assert.equals("WITNESS_PUBKEYTYPE", err)
      end)

      it("allows uncompressed pubkey in multisig when not witness v0", function()
        local pk1 = "\x04" .. string.rep("\x01", 64)  -- uncompressed
        local sig1 = "sig1"

        local checker = {
          check_sig = function(sig, pk)
            return sig == sig1 and pk == pk1
          end
        }

        -- 1-of-1 multisig with uncompressed key
        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_1, data = nil},
          {opcode = 65, data = pk1},
          {opcode = script.OP.OP_1, data = nil},
          {opcode = script.OP.OP_CHECKMULTISIG, data = nil},
        })
        local stack = {"", sig1}

        -- Not witness v0, so uncompressed should be allowed
        local flags = {verify_witness_pubkeytype = true, is_witness_v0 = false}
        local result, err = script.execute_script(script_pubkey, stack, flags, checker)
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.is_true(script.cast_to_bool(result[1]))
      end)
    end)

    describe("OP_CHECKMULTISIGVERIFY with witness_pubkeytype flag", function()
      it("rejects uncompressed pubkey in witness v0", function()
        local pk1 = "\x04" .. string.rep("\x01", 64)  -- uncompressed
        local sig1 = "sig1"

        local checker = {
          check_sig = function(sig, pk) return true end
        }

        local script_pubkey = script.build_script({
          {opcode = script.OP.OP_1, data = nil},
          {opcode = 65, data = pk1},
          {opcode = script.OP.OP_1, data = nil},
          {opcode = script.OP.OP_CHECKMULTISIGVERIFY, data = nil},
        })
        local stack = {"", sig1}

        local flags = {verify_witness_pubkeytype = true, is_witness_v0 = true}
        local result, err = script.execute_script(script_pubkey, stack, flags, checker)
        assert.is_nil(result)
        assert.equals("WITNESS_PUBKEYTYPE", err)
      end)
    end)
  end)

  describe("SCRIPT_VERIFY_MINIMALIF (BIP341/342)", function()
    -- MINIMALIF: The argument to OP_IF/OP_NOTIF must be exactly:
    -- - Empty string "" (false)
    -- - Exactly "\x01" (true)
    -- Any other value (including "\x00", "\x02", multi-byte values) must fail.
    -- For tapscript: mandatory consensus rule
    -- For witness v0: enforced when verify_minimalif flag is set

    describe("OP_IF with MINIMALIF in tapscript", function()
      it("accepts empty string (takes else branch)", function()
        -- OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        local s = "\x00\x63\x52\x67\x53\x68"
        local flags = {is_tapscript = true}
        local result, err = script.execute_script(s, {}, flags, {})
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.equals(3, script.script_num_decode(result[1]))  -- else branch
      end)

      it("accepts exactly 0x01 (takes if branch)", function()
        -- Push \x01, OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        local s = "\x01\x01\x63\x52\x67\x53\x68"
        local flags = {is_tapscript = true}
        local result, err = script.execute_script(s, {}, flags, {})
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.equals(2, script.script_num_decode(result[1]))  -- if branch
      end)

      it("rejects 0x02 as non-minimal true", function()
        -- Push \x02, OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        local s = "\x01\x02\x63\x52\x67\x53\x68"
        local flags = {is_tapscript = true}
        local result, err = script.execute_script(s, {}, flags, {})
        assert.is_nil(result)
        assert.equals("MINIMALIF", err)
      end)

      it("rejects 0x00 as non-minimal false", function()
        -- Push single 0x00 byte, OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        local s = "\x01\x00\x63\x52\x67\x53\x68"
        local flags = {is_tapscript = true}
        local result, err = script.execute_script(s, {}, flags, {})
        assert.is_nil(result)
        assert.equals("MINIMALIF", err)
      end)

      it("rejects multi-byte value 0x01 0x00", function()
        -- Push 2 bytes \x01\x00, OP_IF
        local s = "\x02\x01\x00\x63\x52\x67\x53\x68"
        local flags = {is_tapscript = true}
        local result, err = script.execute_script(s, {}, flags, {})
        assert.is_nil(result)
        assert.equals("MINIMALIF", err)
      end)

      it("rejects 0x80 (negative zero)", function()
        -- Push \x80, OP_IF
        local s = "\x01\x80\x63\x52\x67\x53\x68"
        local flags = {is_tapscript = true}
        local result, err = script.execute_script(s, {}, flags, {})
        assert.is_nil(result)
        assert.equals("MINIMALIF", err)
      end)
    end)

    describe("OP_NOTIF with MINIMALIF in tapscript", function()
      it("accepts empty string (takes if branch since NOTIF inverts)", function()
        -- OP_0 OP_NOTIF OP_2 OP_ELSE OP_3 OP_ENDIF
        local s = "\x00\x64\x52\x67\x53\x68"
        local flags = {is_tapscript = true}
        local result, err = script.execute_script(s, {}, flags, {})
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.equals(2, script.script_num_decode(result[1]))  -- if branch (NOT of false)
      end)

      it("accepts exactly 0x01 (takes else branch since NOTIF inverts)", function()
        -- Push \x01, OP_NOTIF OP_2 OP_ELSE OP_3 OP_ENDIF
        local s = "\x01\x01\x64\x52\x67\x53\x68"
        local flags = {is_tapscript = true}
        local result, err = script.execute_script(s, {}, flags, {})
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.equals(3, script.script_num_decode(result[1]))  -- else branch (NOT of true)
      end)

      it("rejects 0x02 as non-minimal true", function()
        -- Push \x02, OP_NOTIF
        local s = "\x01\x02\x64\x52\x67\x53\x68"
        local flags = {is_tapscript = true}
        local result, err = script.execute_script(s, {}, flags, {})
        assert.is_nil(result)
        assert.equals("MINIMALIF", err)
      end)
    end)

    describe("OP_IF with MINIMALIF in witness v0", function()
      it("enforces MINIMALIF when verify_minimalif flag is set", function()
        -- Push \x02, OP_IF
        local s = "\x01\x02\x63\x52\x67\x53\x68"
        local flags = {is_witness_v0 = true, verify_minimalif = true}
        local result, err = script.execute_script(s, {}, flags, {})
        assert.is_nil(result)
        assert.equals("MINIMALIF", err)
      end)

      it("does not enforce MINIMALIF when flag is not set", function()
        -- Push \x02, OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        -- Without MINIMALIF flag, \x02 is truthy and takes IF branch
        local s = "\x01\x02\x63\x52\x67\x53\x68"
        local flags = {is_witness_v0 = true}  -- no verify_minimalif
        local result, err = script.execute_script(s, {}, flags, {})
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.equals(2, script.script_num_decode(result[1]))  -- if branch (0x02 is truthy)
      end)

      it("accepts 0x01 with verify_minimalif flag", function()
        -- Push \x01, OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        local s = "\x01\x01\x63\x52\x67\x53\x68"
        local flags = {is_witness_v0 = true, verify_minimalif = true}
        local result, err = script.execute_script(s, {}, flags, {})
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.equals(2, script.script_num_decode(result[1]))
      end)

      it("accepts empty string with verify_minimalif flag", function()
        -- OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        local s = "\x00\x63\x52\x67\x53\x68"
        local flags = {is_witness_v0 = true, verify_minimalif = true}
        local result, err = script.execute_script(s, {}, flags, {})
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.equals(3, script.script_num_decode(result[1]))  -- else branch
      end)
    end)

    describe("MINIMALIF does not apply to legacy scripts", function()
      it("allows 0x02 in legacy script without witness flags", function()
        -- Push \x02, OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        local s = "\x01\x02\x63\x52\x67\x53\x68"
        local flags = {}  -- no witness flags
        local result, err = script.execute_script(s, {}, flags, {})
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.equals(2, script.script_num_decode(result[1]))  -- if branch (0x02 is truthy)
      end)

      it("allows multi-byte values in legacy script", function()
        -- Push 2 bytes \x01\x00 (value 1), OP_IF
        local s = "\x02\x01\x00\x63\x52\x67\x53\x68"
        local flags = {}
        local result, err = script.execute_script(s, {}, flags, {})
        assert.is_nil(err)
        assert.equals(1, #result)
        -- \x01\x00 is truthy (non-zero), so takes if branch
        assert.equals(2, script.script_num_decode(result[1]))
      end)
    end)

    describe("MINIMALIF in non-executing branches", function()
      it("does not check MINIMALIF in non-executing IF branch", function()
        -- OP_0 OP_IF (not executing) OP_0 OP_IF OP_1 OP_ENDIF OP_ENDIF OP_5
        -- The inner OP_IF's condition is never evaluated, so MINIMALIF doesn't apply
        local s = "\x00\x63\x00\x63\x51\x68\x68\x55"
        local flags = {is_tapscript = true}
        local result, err = script.execute_script(s, {}, flags, {})
        assert.is_nil(err)
        assert.equals(1, #result)
        assert.equals(5, script.script_num_decode(result[1]))
      end)
    end)
  end)

  describe("Witness CLEANSTACK enforcement (BIP141)", function()
    -- BIP141: Witness scripts implicitly require cleanstack behavior.
    -- After execution, the stack must have exactly 1 element (the true result).
    -- This is NOT flag-gated like legacy CLEANSTACK.

    describe("execute_witness_script with cleanstack", function()
      it("succeeds when stack has exactly 1 true element", function()
        -- Script: OP_1 (leaves exactly 1 element on stack)
        local s = "\x51"
        local ok, err = script.execute_witness_script(s, {}, {}, {})
        assert.is_nil(err)
        assert.is_true(ok)
      end)

      it("fails with CLEANSTACK when stack is empty", function()
        -- Script: OP_1 OP_DROP (leaves 0 elements on stack)
        local s = "\x51\x75"
        local ok, err = script.execute_witness_script(s, {}, {}, {})
        assert.is_nil(ok)
        assert.equals("CLEANSTACK", err)
      end)

      it("fails with CLEANSTACK when stack has 2 elements", function()
        -- Script: OP_1 OP_1 (leaves 2 elements on stack)
        local s = "\x51\x51"
        local ok, err = script.execute_witness_script(s, {}, {}, {})
        assert.is_nil(ok)
        assert.equals("CLEANSTACK", err)
      end)

      it("fails with CLEANSTACK when stack has 3 elements", function()
        -- Script: OP_1 OP_2 OP_3 (leaves 3 elements on stack)
        local s = "\x51\x52\x53"
        local ok, err = script.execute_witness_script(s, {}, {}, {})
        assert.is_nil(ok)
        assert.equals("CLEANSTACK", err)
      end)

      it("fails with EVAL_FALSE when single element is empty", function()
        -- Script: OP_0 (leaves 1 element but it's false)
        local s = "\x00"
        local ok, err = script.execute_witness_script(s, {}, {}, {})
        assert.is_nil(ok)
        assert.equals("EVAL_FALSE", err)
      end)

      it("fails with EVAL_FALSE when single element is negative zero", function()
        -- Push negative zero (0x80) and leave on stack
        local s = "\x01\x80"  -- push 1 byte: 0x80
        local ok, err = script.execute_witness_script(s, {}, {}, {})
        assert.is_nil(ok)
        assert.equals("EVAL_FALSE", err)
      end)

      it("passes cleanstack with arithmetic resulting in true", function()
        -- Script: OP_1 OP_2 OP_ADD OP_3 OP_EQUAL (1+2=3, leaves OP_TRUE)
        local s = "\x51\x52\x93\x53\x87"
        local ok, err = script.execute_witness_script(s, {}, {}, {})
        assert.is_nil(err)
        assert.is_true(ok)
      end)

      it("fails cleanstack with arithmetic leaving extra elements", function()
        -- Script: OP_1 OP_2 OP_ADD (leaves 1 element but also have initial)
        -- Start with OP_5 on stack, then push 1+2, result is 2 elements
        local s = "\x51\x52\x93"  -- OP_1 OP_2 OP_ADD leaves 3 on stack
        local ok, err = script.execute_witness_script(s, {"\x05"}, {}, {})  -- Start with 5
        assert.is_nil(ok)
        assert.equals("CLEANSTACK", err)
      end)
    end)

    describe("P2WPKH cleanstack integration", function()
      local crypto

      setup(function()
        crypto = require("lunarblock.crypto")
      end)

      it("succeeds with proper P2PKH execution via witness", function()
        local pubkey = "\x02" .. string.rep("\x42", 32)  -- compressed pubkey
        local pubkey_hash = crypto.hash160(pubkey)
        local sig = "validsig"

        -- P2PKH script executed by P2WPKH: OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG
        local synthetic_script = script.make_p2pkh_script(pubkey_hash)

        local checker = {
          check_sig = function(s, pk)
            return s == sig and pk == pubkey
          end
        }

        -- Witness stack is [sig, pubkey], cleanstack should pass (1 true element left)
        local ok, err = script.execute_witness_script(synthetic_script, {sig, pubkey}, {}, checker)
        assert.is_nil(err)
        assert.is_true(ok)
      end)
    end)

    describe("P2WSH cleanstack integration", function()
      it("fails cleanstack for script leaving extra items", function()
        -- Witness script that intentionally leaves 2 items
        -- OP_1 OP_1 (2 items on stack)
        local witness_script = "\x51\x51"
        local ok, err = script.execute_witness_script(witness_script, {}, {}, {})
        assert.is_nil(ok)
        assert.equals("CLEANSTACK", err)
      end)

      it("succeeds for script properly consuming inputs", function()
        -- Simple script: OP_ADD OP_5 OP_EQUAL
        -- With initial stack [2, 3], result is 1 true element
        local witness_script = "\x93\x55\x87"  -- OP_ADD OP_5 OP_EQUAL
        local stack = {script.script_num_encode(2), script.script_num_encode(3)}
        local ok, err = script.execute_witness_script(witness_script, stack, {}, {})
        assert.is_nil(err)
        assert.is_true(ok)
      end)

      it("fails cleanstack for multisig leaving extra items", function()
        local pk1 = "\x02" .. string.rep("\x01", 32)
        local sig1 = "sig1"

        -- 1-of-1 multisig that succeeds but leaves extra item
        -- OP_1 <pk> OP_1 OP_CHECKMULTISIG OP_1
        local witness_script = script.build_script({
          {opcode = script.OP.OP_1, data = nil},
          {opcode = 33, data = pk1},
          {opcode = script.OP.OP_1, data = nil},
          {opcode = script.OP.OP_CHECKMULTISIG, data = nil},
          {opcode = script.OP.OP_1, data = nil},  -- Extra push!
        })

        local checker = {
          check_sig = function(s, pk) return s == sig1 and pk == pk1 end
        }

        -- Stack: dummy, sig1
        local stack = {"", sig1}
        local ok, err = script.execute_witness_script(witness_script, stack, {}, checker)
        assert.is_nil(ok)
        assert.equals("CLEANSTACK", err)
      end)
    end)

    describe("cleanstack is NOT flag-gated for witness", function()
      it("cleanstack is enforced even without CLEANSTACK flag", function()
        -- Without any flags, cleanstack should still be enforced
        local s = "\x51\x51"  -- OP_1 OP_1 (2 elements)
        local ok, err = script.execute_witness_script(s, {}, {}, {})
        assert.is_nil(ok)
        assert.equals("CLEANSTACK", err)
      end)

      it("cleanstack is enforced with various flag combinations", function()
        local s = "\x51\x51"  -- OP_1 OP_1 (2 elements)
        local flags = {
          verify_p2sh = true,
          verify_witness = true,
          verify_nullfail = true,
        }
        local ok, err = script.execute_witness_script(s, {}, flags, {})
        assert.is_nil(ok)
        assert.equals("CLEANSTACK", err)
      end)
    end)
  end)

  describe("pay-to-anchor (P2A)", function()
    describe("is_pay_to_anchor", function()
      it("returns true for exact P2A script", function()
        -- P2A script: OP_1 (0x51), PUSH 2 bytes (0x02), 0x4e, 0x73
        local p2a_script = "\x51\x02\x4e\x73"
        assert.is_true(script.is_pay_to_anchor(p2a_script))
      end)

      it("returns true for P2A_SCRIPT constant", function()
        assert.is_true(script.is_pay_to_anchor(script.P2A_SCRIPT))
      end)

      it("returns false for P2TR script (34 bytes)", function()
        -- P2TR: OP_1 (0x51), PUSH 32 bytes (0x20), <32 bytes>
        local p2tr_script = "\x51\x20" .. string.rep("\x00", 32)
        assert.is_false(script.is_pay_to_anchor(p2tr_script))
      end)

      it("returns false for P2WPKH script", function()
        local p2wpkh = "\x00\x14" .. string.rep("\x00", 20)
        assert.is_false(script.is_pay_to_anchor(p2wpkh))
      end)

      it("returns false for P2WSH script", function()
        local p2wsh = "\x00\x20" .. string.rep("\x00", 32)
        assert.is_false(script.is_pay_to_anchor(p2wsh))
      end)

      it("returns false for empty script", function()
        assert.is_false(script.is_pay_to_anchor(""))
      end)

      it("returns false for wrong witness version", function()
        -- witness v0 with 2-byte program (invalid but distinct from P2A)
        local wrong_version = "\x00\x02\x4e\x73"
        assert.is_false(script.is_pay_to_anchor(wrong_version))
      end)

      it("returns false for wrong anchor bytes", function()
        -- OP_1 PUSH 2 bytes, but different program
        local wrong_bytes = "\x51\x02\x00\x00"
        assert.is_false(script.is_pay_to_anchor(wrong_bytes))
      end)

      it("returns false for partial match (prefix only)", function()
        local partial = "\x51\x02\x4e"
        assert.is_false(script.is_pay_to_anchor(partial))
      end)

      it("returns false for P2A with extra bytes appended", function()
        local extended = "\x51\x02\x4e\x73\x00"
        assert.is_false(script.is_pay_to_anchor(extended))
      end)
    end)

    describe("is_pay_to_anchor_witness", function()
      it("returns true for witness v1 with correct 2-byte program", function()
        assert.is_true(script.is_pay_to_anchor_witness(1, "\x4e\x73"))
      end)

      it("returns false for witness v0", function()
        assert.is_false(script.is_pay_to_anchor_witness(0, "\x4e\x73"))
      end)

      it("returns false for witness v2", function()
        assert.is_false(script.is_pay_to_anchor_witness(2, "\x4e\x73"))
      end)

      it("returns false for wrong program", function()
        assert.is_false(script.is_pay_to_anchor_witness(1, "\x00\x00"))
      end)

      it("returns false for longer program (32 bytes like P2TR)", function()
        assert.is_false(script.is_pay_to_anchor_witness(1, string.rep("\x00", 32)))
      end)
    end)

    describe("make_p2a_script", function()
      it("creates correct P2A script", function()
        local p2a = script.make_p2a_script()
        assert.equals("\x51\x02\x4e\x73", p2a)
        assert.equals(4, #p2a)
      end)

      it("creates script that is recognized as P2A", function()
        local p2a = script.make_p2a_script()
        assert.is_true(script.is_pay_to_anchor(p2a))
      end)

      it("equals P2A_SCRIPT constant", function()
        assert.equals(script.P2A_SCRIPT, script.make_p2a_script())
      end)
    end)

    describe("classify_script for P2A", function()
      it("classifies P2A script correctly", function()
        local script_type, hash = script.classify_script(script.P2A_SCRIPT)
        assert.equals("p2a", script_type)
        assert.is_nil(hash)  -- P2A has no hash payload
      end)

      it("distinguishes P2A from P2TR", function()
        -- P2TR: 34 bytes
        local p2tr_script = "\x51\x20" .. string.rep("\xab", 32)
        local script_type = script.classify_script(p2tr_script)
        assert.equals("p2tr", script_type)
      end)

      it("P2A classification takes precedence over other OP_1 scripts", function()
        -- P2A is specifically 4 bytes: 51 02 4e 73
        local script_type = script.classify_script("\x51\x02\x4e\x73")
        assert.equals("p2a", script_type)
      end)
    end)

    describe("P2A script bytes", function()
      it("has correct byte values", function()
        local p2a = script.P2A_SCRIPT
        assert.equals(0x51, p2a:byte(1))  -- OP_1
        assert.equals(0x02, p2a:byte(2))  -- PUSH 2 bytes
        assert.equals(0x4e, p2a:byte(3))  -- First anchor byte
        assert.equals(0x73, p2a:byte(4))  -- Second anchor byte
      end)

      it("represents witness v1 program with 2-byte data", function()
        -- Witness v1 (OP_1 = 0x51) with 2-byte program (0x4e73)
        local p2a = script.P2A_SCRIPT
        -- Verify it's a valid witness program format
        local version = p2a:byte(1) - 0x50  -- OP_1 = 0x51, so version = 1
        local program_len = p2a:byte(2)
        local program = p2a:sub(3)
        assert.equals(1, version)
        assert.equals(2, program_len)
        assert.equals("\x4e\x73", program)
      end)
    end)
  end)

  -- Regression test for the 945,394 wedge: verify_witness_program must
  -- recognise BIP-444 P2A and treat all other unknown witness versions
  -- (incl. v1 + non-32 program length) as anyone-can-spend per BIP141 /
  -- Core script/interpreter.cpp:1947-1998. Pre-fix lunarblock failed
  -- v1 + non-32 with WITNESS_PROGRAM_WRONG_LENGTH, rejecting the P2A
  -- spend in mainnet block 945,394 tx 26b9fa21bb16d8fb... input 0
  -- (prevout scriptPubKey 51024e73 = OP_1 <0x4e73>).
  describe("verify_witness_program forward-soft-fork compatibility (945,394)", function()
    it("accepts P2A spend (v1 + 0x4e73) with empty witness", function()
      local ok, err = script.verify_witness_program({}, 1, "\x4e\x73",
        {verify_taproot = true}, nil)
      assert.is_true(ok)
      assert.is_nil(err)
    end)

    it("accepts P2A even when verify_taproot is off", function()
      local ok, err = script.verify_witness_program({}, 1, "\x4e\x73", {}, nil)
      assert.is_true(ok)
      assert.is_nil(err)
    end)

    it("accepts P2A even when DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM is set", function()
      -- Per Core interpreter.cpp:1990 P2A returns true unconditionally —
      -- the DISCOURAGE flag does NOT apply to P2A.
      local ok, err = script.verify_witness_program({}, 1, "\x4e\x73",
        {verify_taproot = true, verify_discourage_upgradable_witness = true}, nil)
      assert.is_true(ok)
      assert.is_nil(err)
    end)

    it("accepts unknown v1 program length (anyone-can-spend)", function()
      -- v1 + 4-byte program: not Taproot, not P2A; must be anyone-can-spend.
      local ok, err = script.verify_witness_program({}, 1, "\x00\x01\x02\x03",
        {verify_taproot = true}, nil)
      assert.is_true(ok)
      assert.is_nil(err)
    end)

    it("DISCOURAGE flag rejects unknown v1 length (relay-only)", function()
      -- v1 + 30-byte program (not P2TR, not P2A); with DISCOURAGE flag
      -- it must fail; without the flag it would succeed.
      local ok, err = script.verify_witness_program({}, 1, string.rep("\x00", 30),
        {verify_taproot = true, verify_discourage_upgradable_witness = true}, nil)
      assert.is_nil(ok)
      assert.equals("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM", err)
    end)

    it("accepts unknown witness version (v2)", function()
      -- v2 + arbitrary program: anyone-can-spend.
      local ok, err = script.verify_witness_program({}, 2, string.rep("\x00", 32),
        {verify_taproot = true}, nil)
      assert.is_true(ok)
      assert.is_nil(err)
    end)

    it("v0 + non-20/non-32 still fails WITNESS_PROGRAM_WRONG_LENGTH", function()
      -- The v0 length check is consensus per BIP141 and must NOT have
      -- been weakened by the P2A fix.
      local ok, err = script.verify_witness_program({}, 0, string.rep("\x00", 16),
        {verify_taproot = true}, nil)
      assert.is_nil(ok)
      assert.equals("WITNESS_PROGRAM_WRONG_LENGTH", err)
    end)
  end)

  -- Regression test for the 944,186 wedge: BIP342 tapscripts must be
  -- exempt from MAX_SCRIPT_SIZE (10,000 bytes). Pre-fix, large
  -- ordinals/inscription tapscripts (e.g. 64,349 bytes in mainnet block
  -- 944,186 tx c6ff4027... vin[0]) failed with SCRIPT_ERR_SCRIPT_SIZE.
  -- See project_lunarblock_wedge_2026_04_28.
  describe("BIP342 tapscript MAX_SCRIPT_SIZE exemption", function()
    it("rejects >10,000 byte legacy script (BASE/WITNESS_V0)", function()
      -- Build a 10,001-byte stream of OP_NOP (0x61). OP_NOP doesn't grow
      -- the stack so we can isolate the size-gate behaviour from
      -- stack-overflow / op-count side effects.
      -- Note: legacy MAX_OPS_PER_SCRIPT is 201; this script has 10,001
      -- counted opcodes so it would fail either way for legacy. The point
      -- here is that execute_script returns SCRIPT_SIZE *before* counting,
      -- so that's the failure mode we expect.
      local big = string.rep("\x61", 10001)
      local result, err = script.execute_script(big, {}, {}, {})
      assert.is_nil(result)
      assert.equals("SCRIPT_SIZE", err)
    end)

    it("accepts >10,000 byte tapscript (is_tapscript=true)", function()
      -- Same script size but tapscript flag set: must NOT trip SCRIPT_SIZE.
      -- Use OP_NOP so we don't run into stack-size limits while exercising
      -- the size gate. (Real ordinals tapscripts use giant push payloads
      -- via OP_PUSHDATA, not 10K loose opcodes; this is a synthetic test
      -- focused on the size gate alone.)
      local big = string.rep("\x61", 10001)
      local result, err = script.execute_script(big,
        {}, {is_tapscript = true}, {})
      -- Must not fail with SCRIPT_SIZE. With is_tapscript, the op-count
      -- assert is also waived, so this should return an empty stack.
      assert.not_equals("SCRIPT_SIZE", err)
      assert.is_table(result)
    end)

    it("accepts ~64KB tapscript (mainnet 944,186 ordinals scale)", function()
      -- Reproduce the exact size class that wedged lunarblock at 944,186:
      -- 64,349-byte tapscript. We use OP_NOP padding (no real ordinals
      -- push payload) — the goal is to assert the size gate, not Schnorr
      -- verification.
      local big = string.rep("\x61", 64349)
      local result, err = script.execute_script(big,
        {}, {is_tapscript = true}, {})
      assert.not_equals("SCRIPT_SIZE", err)
      assert.is_table(result)
    end)

    it("MAX_OPS_PER_SCRIPT is also waived for tapscript", function()
      -- BIP342: tapscript exempts MAX_OPS_PER_SCRIPT (201). Large ordinals
      -- tapscripts can have far more than 201 counted opcodes.
      -- 250 OP_NOPs (0x61) -> over the 201-op legacy limit.
      local many_ops = string.rep("\x61", 250)
      -- Legacy: must fail "too many opcodes" (raised via assert)
      local ok_legacy = pcall(function()
        script.execute_script(many_ops, {}, {}, {})
      end)
      assert.is_false(ok_legacy)
      -- Tapscript: must NOT fail with the op-count assert.
      local ok_tap = pcall(function()
        script.execute_script(many_ops, {}, {is_tapscript = true}, {})
      end)
      assert.is_true(ok_tap)
    end)
  end)

  -- Regression test for the 944,188 wedge: OP_CHECKSIGADD pop order.
  --
  -- Per BIP342 / Core interpreter.cpp:1089 the stack layout for
  -- OP_CHECKSIGADD is `(sig num pubkey -- num)` with pubkey on top.
  -- The correct pop order from top is: pubkey, num, sig.
  --
  -- Pre-fix lunarblock popped pubkey, sig, n — i.e. the second and third
  -- pops were swapped, handing the 64-byte Schnorr sig to pop_num() and
  -- wedging mainnet block 944,188 with "script number too long".
  -- See project_lunarblock_wedge_2026_04_28.
  describe("BIP342 OP_CHECKSIGADD pop order (944,188 wedge)", function()
    local OP_CHECKSIGADD = "\xba"
    -- 64-byte all-zero Schnorr sig (treated as "empty sig pass-through" by
    -- the no-op checker; checker stub below returns false unconditionally).
    local SIG64 = string.rep("\x00", 64)
    -- 32-byte all-zero x-only pubkey
    local PK32 = string.rep("\x00", 32)

    it("pops pubkey, num, sig in that order (no-op checker)", function()
      -- Build script: <push64 sig> <push 0> <push32 pubkey> OP_CHECKSIGADD
      -- With a checker that always returns false AND empty-sig short
      -- circuit: real sig is non-empty so this would error. Use empty sig.
      -- Final stack layout (bottom->top): "" (empty sig), 0 (num), pk32 (pubkey).
      local empty_sig = ""
      local script_bytes =
        "\x00" ..                    -- OP_0 (empty sig)
        "\x00" ..                    -- OP_0 (num=0)
        "\x20" .. PK32 ..            -- pubkey push (32B)
        OP_CHECKSIGADD
      -- Checker stub: returns false (no signature verification).
      local checker = {check_sig = function() return false end}
      local stack, err = script.execute_script(
        script_bytes, {}, {is_tapscript = true}, checker)
      -- Empty sig + invalid sig path: push n unchanged (still 0).
      assert.is_table(stack)
      assert.is_nil(err)
      assert.equals(0, script.script_num_decode(stack[1]))
    end)

    it("64-byte sig with num=0, valid sig, increments num", function()
      -- Real-world shape: 64-byte sig, num=0, 32-byte pubkey.
      -- Pre-fix lunarblock would treat the 64B sig as `n` and assert
      -- "script number too long". Post-fix the pop order is correct
      -- and the script runs to completion.
      local script_bytes =
        "\x40" .. SIG64 ..           -- 64B sig push
        "\x00" ..                    -- OP_0 (num=0)
        "\x20" .. PK32 ..            -- 32B pubkey push
        OP_CHECKSIGADD
      local checker = {check_sig = function() return true end}
      local stack, err = script.execute_script(
        script_bytes, {}, {is_tapscript = true}, checker)
      -- Valid path: num+1 = 1 pushed.
      assert.is_table(stack)
      assert.is_nil(err)
      assert.equals(1, script.script_num_decode(stack[1]))
    end)

    it("64-byte sig with num=2 increments to 3 on valid sig", function()
      -- Verifies pop_num reads num correctly (not the sig).
      local script_bytes =
        "\x40" .. SIG64 ..           -- 64B sig
        "\x52" ..                    -- OP_2 (num=2)
        "\x20" .. PK32 ..            -- pubkey
        OP_CHECKSIGADD
      local checker = {check_sig = function() return true end}
      local stack, err = script.execute_script(
        script_bytes, {}, {is_tapscript = true}, checker)
      assert.is_table(stack)
      assert.is_nil(err)
      assert.equals(3, script.script_num_decode(stack[1]))
    end)
  end)

  -- ---------------------------------------------------------------------------
  -- BIP-66 / signature encoding comprehensive tests (W82)
  -- Reference: bitcoin-core/src/script/interpreter.cpp:64-227
  --
  -- All gates are exercised via execute_script with OP_CHECKSIG (0xAC) and
  -- a mock checker so real ECDSA verification is bypassed.  The stack is
  -- pre-loaded [sig, pubkey] (pubkey on top) and the script is just the
  -- single opcode byte.
  --
  -- A minimal valid DER sig (9 bytes, hashtype 0x01):
  --   30 06 02 01 01 02 01 01 01
  -- ---------------------------------------------------------------------------
  describe("BIP-66 IsValidSignatureEncoding gates (verify_dersig)", function()
    -- OP_CHECKSIG opcode byte
    local OP_CHECKSIG = "\xac"
    -- A 33-byte compressed pubkey (02 + 32 bytes).  The checker stub ignores it.
    local PUBKEY = "\x02" .. string.rep("\x01", 32)
    -- Mock checker: always returns true so NULLFAIL is never triggered
    local checker_ok = { check_sig = function() return true end }
    -- Mock checker: always returns false (triggers NULLFAIL for non-empty sigs)
    local checker_fail = { check_sig = function() return false end }

    -- Helper: run OP_CHECKSIG with the given sig on the stack, dersig flag set.
    -- Returns result, err from execute_script.
    local function run_checksig_dersig(sig, pubkey_arg)
      local pk = pubkey_arg or PUBKEY
      return script.execute_script(OP_CHECKSIG, {sig, pk},
        {verify_dersig = true}, checker_ok)
    end

    -- The minimal valid sig used as a baseline throughout this block
    local VALID_SIG = "\x30\x06\x02\x01\x01\x02\x01\x01\x01"

    it("accepts a minimal valid DER sig (9 bytes)", function()
      local result, err = run_checksig_dersig(VALID_SIG)
      assert.is_nil(err)
      assert.is_table(result)
    end)

    it("accepts empty signature (always allowed per spec)", function()
      -- Empty sig bypasses all encoding checks; the checker returns true.
      local result, err = run_checksig_dersig("")
      assert.is_nil(err)
      assert.is_table(result)
    end)

    -- Gate 1: minimum size < 9
    it("rejects sig shorter than 9 bytes (SIG_DER)", function()
      -- 8-byte sig: 30 05 02 01 01 02 01 01 (missing hashtype)
      local short_sig = "\x30\x05\x02\x01\x01\x02\x01\x01"
      local result, err = run_checksig_dersig(short_sig)
      assert.is_nil(result)
      assert.equals("SIG_DER", err)
    end)

    -- Gate 2: maximum size > 73
    it("rejects sig longer than 73 bytes (SIG_DER)", function()
      -- 74-byte sig: compound byte + filler
      local long_sig = "\x30" .. string.rep("\x00", 73)
      local result, err = run_checksig_dersig(long_sig)
      assert.is_nil(result)
      assert.equals("SIG_DER", err)
    end)

    -- Gate 3: first byte must be 0x30 (compound)
    it("rejects sig not starting with 0x30 (SIG_DER)", function()
      -- Replace 0x30 with 0x31
      local bad_sig = "\x31\x06\x02\x01\x01\x02\x01\x01\x01"
      local result, err = run_checksig_dersig(bad_sig)
      assert.is_nil(result)
      assert.equals("SIG_DER", err)
    end)

    -- Gate 4: byte[1] must equal len - 3
    it("rejects sig where total-length field is wrong (SIG_DER)", function()
      -- VALID_SIG has byte[1]=0x06 = 9-3 = 6; change to 0x07
      local bad_sig = "\x30\x07\x02\x01\x01\x02\x01\x01\x01"
      local result, err = run_checksig_dersig(bad_sig)
      assert.is_nil(result)
      assert.equals("SIG_DER", err)
    end)

    -- Gate 5: 5 + lenR must be < len (lenR too large)
    it("rejects sig where lenR would exceed buffer (SIG_DER)", function()
      -- lenR = 0x20 (32) but total sig is only 9 bytes
      local bad_sig = "\x30\x06\x02\x20\x01\x02\x01\x01\x01"
      local result, err = run_checksig_dersig(bad_sig)
      assert.is_nil(result)
      assert.equals("SIG_DER", err)
    end)

    -- Gate 6: lenR + lenS + 7 must equal len
    it("rejects sig where length sum is inconsistent (SIG_DER)", function()
      -- R-len=1, S-len=2 but actual total is 9 (should be 10)
      -- 30 06 02 01 01 02 02 01 01 → lenR+lenS+7 = 1+2+7=10 ≠ 9
      local bad_sig = "\x30\x06\x02\x01\x01\x02\x02\x01\x01"
      local result, err = run_checksig_dersig(bad_sig)
      assert.is_nil(result)
      assert.equals("SIG_DER", err)
    end)

    -- Gate 7: byte[2] must be 0x02 (R integer marker)
    it("rejects sig where R marker is not 0x02 (SIG_DER)", function()
      -- Replace R marker 0x02 with 0x03
      local bad_sig = "\x30\x06\x03\x01\x01\x02\x01\x01\x01"
      local result, err = run_checksig_dersig(bad_sig)
      assert.is_nil(result)
      assert.equals("SIG_DER", err)
    end)

    -- Gate 8: lenR must not be zero
    it("rejects sig with zero-length R (SIG_DER)", function()
      -- 30 06 02 00 00 02 01 01 01  (lenR=0; but total-length stays 6 so
      -- lenR+lenS+7=0+?+7 check will also fail; craft carefully)
      -- Use: 30 04 02 00 02 01 01 01 (total 8 bytes — gate 1 fires first)
      -- Better: 30 05 02 00 02 01 01 01 01 (9 bytes, lenR=0)
      -- byte[1]=5, lenR=0, lenS must satisfy 0+lenS+7=8 so lenS=1
      -- 30 05 02 00 02 01 01 01 → 8 bytes < 9 (gate 1 fires)
      -- Need 9 bytes: 30 06 02 00 02 01 01 01 01 (lenR=0, lenS=1, len=9, byte[1]=6=9-3)
      -- lenR+lenS+7 = 0+1+7=8 ≠ 9 → gate 6 fires first
      -- The only way to hit gate 8 independently is to have lenR=0 and
      -- everything else consistent.  That requires: total=0+lenS+7+3 bytes.
      -- With lenS=1: total=11... but then we also need byte[1]=total-3=8.
      -- 30 08 02 00 02 01 01 01 01 XX XX (11 bytes) — but gate 5 would fire
      -- since 5+0=5 < 9 (ok), so proceed to gate 6: 0+1+7=8 ≠ 11 → gate 6.
      -- It's impossible to isolate gate 8 from gate 6 in a pure byte sequence
      -- without crafting a 10-byte sig.  Use 10 bytes:
      -- len=10, byte[1]=7, lenR=0, lenS=lenS, total: 0+lenS+7=10 → lenS=3
      -- 5+0=5 < 10 (ok gate 5), byte[2]=0x02 (ok), lenR=0 → gate 8 fires
      -- 30 07 02 00 02 03 XX XX XX 01  (10 bytes)
      local bad_sig = "\x30\x07\x02\x00\x02\x03\x01\x01\x01\x01"
      local result, err = run_checksig_dersig(bad_sig)
      assert.is_nil(result)
      assert.equals("SIG_DER", err)
    end)

    -- Gate 9: R must not be negative (high bit of first R byte must be 0)
    it("rejects sig where R is negative (high bit set) (SIG_DER)", function()
      -- Replace R data byte 0x01 with 0x81 (high bit set)
      local bad_sig = "\x30\x06\x02\x01\x81\x02\x01\x01\x01"
      local result, err = run_checksig_dersig(bad_sig)
      assert.is_nil(result)
      assert.equals("SIG_DER", err)
    end)

    -- Gate 10: R must not be excessively padded (0x00 followed by byte without high bit)
    it("rejects sig where R has unnecessary zero padding (SIG_DER)", function()
      -- R = 0x00 0x01 (lenR=2, first byte 0x00, second byte 0x01 — high bit clear)
      -- total = 2+1+7 = 10, byte[1] = 10-3 = 7
      -- 30 07 02 02 00 01 02 01 01 01  (10 bytes)
      local bad_sig = "\x30\x07\x02\x02\x00\x01\x02\x01\x01\x01"
      local result, err = run_checksig_dersig(bad_sig)
      assert.is_nil(result)
      assert.equals("SIG_DER", err)
    end)

    -- Gate 11: byte at S-marker position must be 0x02
    it("rejects sig where S marker is not 0x02 (SIG_DER)", function()
      -- S marker (byte at lenR+4 = 5 in C++, i.e. sig:byte(lenR+5)=6th byte) = 0x03
      -- VALID_SIG = 30 06 02 01 01 [02] 01 01 01; replace S marker with 0x03
      local bad_sig = "\x30\x06\x02\x01\x01\x03\x01\x01\x01"
      local result, err = run_checksig_dersig(bad_sig)
      assert.is_nil(result)
      assert.equals("SIG_DER", err)
    end)

    -- Gate 12: lenS must not be zero
    it("rejects sig with zero-length S (SIG_DER)", function()
      -- S-len=0: 30 05 02 01 01 02 00 01  (8 bytes < 9 → gate 1 first)
      -- Need to craft so gate 12 fires: lenR=1, lenS=0 → total=1+0+7=8 < 9 (gate 1)
      -- lenR=2, lenS=0 → total=2+0+7=9 ✓
      -- byte[1]=9-3=6, byte[3]=lenR=2, byte[6]=lenS=0
      -- byte[4..5]=R data, byte[7..]=S marker check won't get there...
      -- Actually gate 5: 5+2=7 < 9 ✓; gate 6: 2+0+7=9 ✓
      -- byte[2]=0x02 (R marker), lenR=2, R data bytes, then S marker at byte[7]
      -- 30 06 02 02 01 01 02 00 01 (9 bytes, byte[1]=6, lenR=2, R=01 01,
      -- S marker at byte[lenR+5]=byte[7]=0x02, lenS=byte[lenR+6]=byte[8]=0)
      -- lenR+lenS+7 = 2+0+7 = 9 ✓ -- gate 6 OK, gate 12 fires
      local bad_sig = "\x30\x06\x02\x02\x01\x01\x02\x00\x01"
      local result, err = run_checksig_dersig(bad_sig)
      assert.is_nil(result)
      assert.equals("SIG_DER", err)
    end)

    -- Gate 13: S must not be negative (high bit of first S byte must be 0)
    it("rejects sig where S is negative (high bit set) (SIG_DER)", function()
      -- S data byte 0x01 → 0x81
      local bad_sig = "\x30\x06\x02\x01\x01\x02\x01\x81\x01"
      local result, err = run_checksig_dersig(bad_sig)
      assert.is_nil(result)
      assert.equals("SIG_DER", err)
    end)

    -- Gate 14: S must not be excessively padded
    it("rejects sig where S has unnecessary zero padding (SIG_DER)", function()
      -- S = 0x00 0x01 (lenS=2, first byte 0x00, second byte 0x01 without high bit)
      -- total = 1+2+7 = 10, byte[1] = 7
      -- 30 07 02 01 01 02 02 00 01 01  (10 bytes)
      local bad_sig = "\x30\x07\x02\x01\x01\x02\x02\x00\x01\x01"
      local result, err = run_checksig_dersig(bad_sig)
      assert.is_nil(result)
      assert.equals("SIG_DER", err)
    end)

    -- Boundary: sig with S having leading 0x00 for sign-bit is valid
    it("accepts sig where S has necessary 0x00 padding (high bit set on next byte)", function()
      -- S = 0x00 0x81 (lenS=2, 0x00 padding because 0x81 has high bit set)
      -- total = 1+2+7 = 10, byte[1] = 7
      -- R=1 byte, S=2 bytes: 30 07 02 01 01 02 02 00 81 01  (10 bytes)
      local good_sig = "\x30\x07\x02\x01\x01\x02\x02\x00\x81\x01"
      local result, err = run_checksig_dersig(good_sig)
      assert.is_nil(err)
      assert.is_table(result)
    end)
  end)

  describe("BIP-66 IsDefinedHashtypeSignature (verify_strictenc)", function()
    local OP_CHECKSIG = "\xac"
    local PUBKEY = "\x02" .. string.rep("\x01", 32)
    local checker_ok = { check_sig = function() return true end }
    -- Base valid DER sig bytes (without hashtype appended):
    -- 30 06 02 01 01 02 01 01 [hashtype]
    local SIG_BASE = "\x30\x06\x02\x01\x01\x02\x01\x01"

    local function run_checksig_strictenc(sig)
      return script.execute_script(OP_CHECKSIG, {sig, PUBKEY},
        {verify_strictenc = true}, checker_ok)
    end

    -- Valid hashtypes: 0x01 (ALL), 0x02 (NONE), 0x03 (SINGLE)
    -- and their ANYONECANPAY variants (0x81, 0x82, 0x83)
    for _, ht in ipairs({0x01, 0x02, 0x03, 0x81, 0x82, 0x83}) do
      local ht_byte = ht
      it(string.format("accepts hashtype 0x%02x", ht_byte), function()
        local sig = SIG_BASE .. string.char(ht_byte)
        local result, err = run_checksig_strictenc(sig)
        assert.is_nil(err)
        assert.is_table(result)
      end)
    end

    -- Invalid hashtypes
    for _, ht in ipairs({0x00, 0x04, 0x05, 0x7f, 0x80, 0x84, 0xff}) do
      local ht_byte = ht
      it(string.format("rejects hashtype 0x%02x (SIG_HASHTYPE)", ht_byte), function()
        local sig = SIG_BASE .. string.char(ht_byte)
        local result, err = run_checksig_strictenc(sig)
        assert.is_nil(result)
        assert.equals("SIG_HASHTYPE", err)
      end)
    end

    it("empty sig is exempt from hashtype check", function()
      -- Empty sigs bypass all encoding checks
      local result, err = run_checksig_strictenc("")
      assert.is_nil(err)
      assert.is_table(result)
    end)
  end)

  describe("BIP-66 IsLowDERSignature (verify_low_s)", function()
    local OP_CHECKSIG = "\xac"
    local PUBKEY = "\x02" .. string.rep("\x01", 32)
    local checker_ok = { check_sig = function() return true end }

    local function run_checksig_low_s(sig)
      return script.execute_script(OP_CHECKSIG, {sig, PUBKEY},
        {verify_low_s = true}, checker_ok)
    end

    it("accepts sig with S = 0x01 (clearly low)", function()
      -- 30 06 02 01 01 02 01 01 01  (S=0x01)
      local sig = "\x30\x06\x02\x01\x01\x02\x01\x01\x01"
      local result, err = run_checksig_low_s(sig)
      assert.is_nil(err)
      assert.is_table(result)
    end)

    it("accepts sig with S exactly equal to half-order (boundary)", function()
      -- half_order = 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
      -- S as 32 bytes (no sign-extension needed, high bit clear)
      -- lenS = 32, lenR = 1, total = 1+32+7 = 40, byte[1] = 37
      local half_s = "\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" ..
                     "\x5d\x57\x6e\x73\x57\xa4\x50\x1d\xdf\xe9\x2f\x46\x68\x1b\x20\xa0"
      -- Sig: 30 25 02 01 01 02 20 [half_s] 01
      -- header(1)+total_len(1)+R_marker(1)+lenR(1)+R(1)+S_marker(1)+lenS(1)+S(32)+hashtype(1) = 40
      local sig = "\x30\x25\x02\x01\x01\x02\x20" .. half_s .. "\x01"
      assert.equals(40, #sig)
      local result, err = run_checksig_low_s(sig)
      assert.is_nil(err)
      assert.is_table(result)
    end)

    it("rejects sig with S above half-order (SIG_HIGH_S)", function()
      -- S = half_order + 1:
      -- 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1
      -- High bit is clear (0x7F...) so no sign-extension needed.
      local high_s = "\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" ..
                     "\x5d\x57\x6e\x73\x57\xa4\x50\x1d\xdf\xe9\x2f\x46\x68\x1b\x20\xa1"
      local sig = "\x30\x25\x02\x01\x01\x02\x20" .. high_s .. "\x01"
      assert.equals(40, #sig)
      local result, err = run_checksig_low_s(sig)
      assert.is_nil(result)
      assert.equals("SIG_HIGH_S", err)
    end)

    it("rejects sig with S = curve order - 1 (clearly high)", function()
      -- n-1 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140
      -- High bit set (0xFF) so needs 0x00 prefix; lenS=33
      -- lenR=1, lenS=33, total=1+33+7=41, byte[1]=38=0x26
      local high_s_33 = "\x00" ..
                        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe" ..
                        "\xba\xae\xdc\xe6\xaf\x48\xa0\x3b\xbf\xd2\x5e\x8c\xd0\x36\x41\x40"
      -- Sig: 30 26 02 01 01 02 21 [high_s_33] 01
      -- header(1) + total_len(1) + R_marker(1) + lenR(1) + R(1) + S_marker(1) + lenS(1) + S(33) + hashtype(1) = 41
      local sig = "\x30\x26\x02\x01\x01\x02\x21" .. high_s_33 .. "\x01"
      assert.equals(41, #sig)
      local result, err = run_checksig_low_s(sig)
      assert.is_nil(result)
      assert.equals("SIG_HIGH_S", err)
    end)

    it("rejects sig with S equal to curve order (SIG_HIGH_S)", function()
      -- n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
      -- With 0x00 prefix: lenS=33
      local order_s = "\x00" ..
                      "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe" ..
                      "\xba\xae\xdc\xe6\xaf\x48\xa0\x3b\xbf\xd2\x5e\x8c\xd0\x36\x41\x41"
      local sig = "\x30\x26\x02\x01\x01\x02\x21" .. order_s .. "\x01"
      assert.equals(41, #sig)
      local result, err = run_checksig_low_s(sig)
      assert.is_nil(result)
      assert.equals("SIG_HIGH_S", err)
    end)

    it("empty sig is exempt from low-S check", function()
      local result, err = run_checksig_low_s("")
      assert.is_nil(err)
      assert.is_table(result)
    end)
  end)

  describe("BIP-66 pubkey encoding gates", function()
    local OP_CHECKSIG = "\xac"
    -- Valid minimal DER sig with hashtype 0x01
    local VALID_SIG = "\x30\x06\x02\x01\x01\x02\x01\x01\x01"
    local checker_ok = { check_sig = function() return true end }

    describe("IsCompressedOrUncompressedPubKey (verify_strictenc)", function()
      local function run_checksig_strictenc_pubkey(pubkey)
        return script.execute_script(OP_CHECKSIG, {VALID_SIG, pubkey},
          {verify_strictenc = true}, checker_ok)
      end

      it("accepts compressed pubkey 02 prefix (33 bytes)", function()
        local pk = "\x02" .. string.rep("\x01", 32)
        local result, err = run_checksig_strictenc_pubkey(pk)
        assert.is_nil(err)
        assert.is_table(result)
      end)

      it("accepts compressed pubkey 03 prefix (33 bytes)", function()
        local pk = "\x03" .. string.rep("\x01", 32)
        local result, err = run_checksig_strictenc_pubkey(pk)
        assert.is_nil(err)
        assert.is_table(result)
      end)

      it("accepts uncompressed pubkey 04 prefix (65 bytes)", function()
        local pk = "\x04" .. string.rep("\x01", 64)
        local result, err = run_checksig_strictenc_pubkey(pk)
        assert.is_nil(err)
        assert.is_table(result)
      end)

      it("rejects 02-prefix key with wrong length (PUBKEYTYPE)", function()
        -- 02 with 32 bytes (34 total instead of 33)
        local pk = "\x02" .. string.rep("\x01", 33)
        local result, err = run_checksig_strictenc_pubkey(pk)
        assert.is_nil(result)
        assert.equals("PUBKEYTYPE", err)
      end)

      it("rejects 04-prefix key with wrong length (PUBKEYTYPE)", function()
        -- 04 with 63 bytes (64 total instead of 65)
        local pk = "\x04" .. string.rep("\x01", 63)
        local result, err = run_checksig_strictenc_pubkey(pk)
        assert.is_nil(result)
        assert.equals("PUBKEYTYPE", err)
      end)

      it("rejects 05-prefix key (PUBKEYTYPE)", function()
        local pk = "\x05" .. string.rep("\x01", 32)
        local result, err = run_checksig_strictenc_pubkey(pk)
        assert.is_nil(result)
        assert.equals("PUBKEYTYPE", err)
      end)

      it("rejects hybrid 06-prefix key (PUBKEYTYPE)", function()
        -- Hybrid form 0x06/0x07 (65 bytes) was accepted in early Bitcoin,
        -- but IsCompressedOrUncompressedPubKey explicitly rejects them.
        local pk = "\x06" .. string.rep("\x01", 64)
        local result, err = run_checksig_strictenc_pubkey(pk)
        assert.is_nil(result)
        assert.equals("PUBKEYTYPE", err)
      end)

      it("rejects hybrid 07-prefix key (PUBKEYTYPE)", function()
        local pk = "\x07" .. string.rep("\x01", 64)
        local result, err = run_checksig_strictenc_pubkey(pk)
        assert.is_nil(result)
        assert.equals("PUBKEYTYPE", err)
      end)
    end)

    describe("IsCompressedPubKey (verify_witness_pubkeytype, witness-v0)", function()
      local function run_checksig_witness_pubkeytype(pubkey)
        -- verify_witness_pubkeytype + is_witness_v0 mirrors SigVersion::WITNESS_V0
        return script.execute_script(OP_CHECKSIG, {VALID_SIG, pubkey},
          {verify_witness_pubkeytype = true, is_witness_v0 = true}, checker_ok)
      end

      it("accepts 02-prefix compressed key (33 bytes)", function()
        local pk = "\x02" .. string.rep("\x01", 32)
        local result, err = run_checksig_witness_pubkeytype(pk)
        assert.is_nil(err)
        assert.is_table(result)
      end)

      it("accepts 03-prefix compressed key (33 bytes)", function()
        local pk = "\x03" .. string.rep("\x01", 32)
        local result, err = run_checksig_witness_pubkeytype(pk)
        assert.is_nil(err)
        assert.is_table(result)
      end)

      it("rejects uncompressed 04-prefix key in witness-v0 (WITNESS_PUBKEYTYPE)", function()
        local pk = "\x04" .. string.rep("\x01", 64)
        local result, err = run_checksig_witness_pubkeytype(pk)
        assert.is_nil(result)
        assert.equals("WITNESS_PUBKEYTYPE", err)
      end)

      it("rejects 33-byte key with wrong prefix in witness-v0 (WITNESS_PUBKEYTYPE)", function()
        local pk = "\x05" .. string.rep("\x01", 32)
        local result, err = run_checksig_witness_pubkeytype(pk)
        assert.is_nil(result)
        assert.equals("WITNESS_PUBKEYTYPE", err)
      end)

      it("WITNESS_PUBKEYTYPE not enforced when is_witness_v0 is false", function()
        -- When is_witness_v0 is absent, the witness-pubkeytype gate does not fire.
        local pk = "\x04" .. string.rep("\x01", 64)
        local result, err = script.execute_script(OP_CHECKSIG, {VALID_SIG, pk},
          {verify_witness_pubkeytype = true}, checker_ok)
        assert.is_nil(err)
        assert.is_table(result)
      end)
    end)
  end)

  describe("BIP-66 gate interaction: verify_dersig vs verify_strictenc vs verify_low_s", function()
    local OP_CHECKSIG = "\xac"
    local PUBKEY = "\x02" .. string.rep("\x01", 32)
    local checker_ok = { check_sig = function() return true end }
    -- A structurally valid DER sig with a defined hashtype 0x01
    local VALID_SIG = "\x30\x06\x02\x01\x01\x02\x01\x01\x01"
    -- An encoding-invalid sig (total-length wrong)
    local BAD_DER = "\x30\x07\x02\x01\x01\x02\x01\x01\x01"
    -- A valid DER sig but with hashtype 0x04 (undefined)
    local BAD_HASHTYPE = "\x30\x06\x02\x01\x01\x02\x01\x01\x04"

    it("verify_dersig alone rejects bad DER", function()
      local result, err = script.execute_script(OP_CHECKSIG, {BAD_DER, PUBKEY},
        {verify_dersig = true}, checker_ok)
      assert.is_nil(result)
      assert.equals("SIG_DER", err)
    end)

    it("no flags: bad DER and bad hashtype are silently accepted", function()
      -- Without any encoding flags, everything passes the encoding checks
      local result1, err1 = script.execute_script(OP_CHECKSIG, {BAD_DER, PUBKEY}, {}, checker_ok)
      assert.is_nil(err1)
      assert.is_table(result1)
      local result2, err2 = script.execute_script(OP_CHECKSIG, {BAD_HASHTYPE, PUBKEY}, {}, checker_ok)
      assert.is_nil(err2)
      assert.is_table(result2)
    end)

    it("verify_strictenc alone rejects bad hashtype but not bad DER structure", function()
      -- With STRICTENC, bad hashtype fails
      local result1, err1 = script.execute_script(OP_CHECKSIG, {BAD_HASHTYPE, PUBKEY},
        {verify_strictenc = true}, checker_ok)
      assert.is_nil(result1)
      assert.equals("SIG_HASHTYPE", err1)
      -- But also validates DER encoding (STRICTENC implies DER check)
      local result2, err2 = script.execute_script(OP_CHECKSIG, {BAD_DER, PUBKEY},
        {verify_strictenc = true}, checker_ok)
      assert.is_nil(result2)
      assert.equals("SIG_DER", err2)
    end)

    it("empty sig always bypasses all encoding flags", function()
      local flags_list = {
        {verify_dersig = true},
        {verify_low_s = true},
        {verify_strictenc = true},
        {verify_dersig = true, verify_low_s = true, verify_strictenc = true},
      }
      for _, flags in ipairs(flags_list) do
        local result, err = script.execute_script(OP_CHECKSIG, {"", PUBKEY}, flags, checker_ok)
        assert.is_nil(err)
        assert.is_table(result)
      end
    end)
  end)

  describe("OP_CHECKSEQUENCEVERIFY stack preservation (Core parity)", function()
    -- Regression for glassbox finding 2026-07-01: CSV must leave stacktop(-1)
    -- byte-for-byte intact (interpreter.cpp:574 reads a const CScriptNum and
    -- breaks without touching the stack). Pre-fix lunarblock did
    -- `pop_num(5); push(script_num_encode(sequence))`, replacing the original
    -- element with its MINIMAL re-encoding. For a non-minimal push "\x05\x00"
    -- (== 5) that mutated a 2-byte element into a 1-byte one, diverging from
    -- Core when a downstream OP_SIZE observes the top element.
    --
    -- scriptPubKey: PUSH2("\x05\x00") OP_CSV OP_SIZE OP_2 OP_NUMEQUAL
    -- hex: 02 05 00 b2 82 52 9c
    it("leaves the non-minimal stacktop untouched so OP_SIZE sees 2 bytes", function()
      local script_pubkey = hex_to_bin("020500b282529c")
      local checker = {
        check_sequence = function(_) return true end,
      }
      -- MINIMALDATA not set (consensus/block-connect flags omit it), so the
      -- non-minimal push "\x05\x00" decodes fine and the CSV check passes.
      local result, err = script.execute_script(
        script_pubkey, {}, {verify_checksequenceverify = true}, checker)
      assert.is_nil(err)
      assert.is_table(result)
      -- OP_SIZE does not consume its operand, so the original CSV element
      -- remains under the boolean result; the accept decision is the top.
      -- Core: element left as "\x05\x00" -> OP_SIZE=2 -> OP_2 OP_NUMEQUAL TRUE.
      -- Pre-fix lunarblock: element re-encoded to "\x05" -> OP_SIZE=1 -> FALSE.
      assert.is_true(script.cast_to_bool(result[#result]))
    end)
  end)
end)
