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
    it("increments counter when signature is valid", function()
      local pk = string.rep("\x01", 32)
      local sig = "validsig"

      local checker = {
        check_sig = function(s, p)
          return s == sig and p == pk
        end
      }

      -- Stack: 0, sig, pk (bottom to top)
      -- OP_CHECKSIGADD should push 1
      local s = script.build_script({
        {opcode = script.OP.OP_0, data = nil},  -- push 0
        {opcode = #sig, data = sig},
        {opcode = #pk, data = pk},
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

      -- Stack: 5, empty sig, pk
      local s = script.build_script({
        {opcode = script.OP.OP_5, data = nil},
        {opcode = script.OP.OP_0, data = nil},  -- empty sig
        {opcode = #pk, data = pk},
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

  -- Regression test for the 944,188 wedge: BIP342 tapscripts permit 5-byte
  -- CScriptNum operands for stack-numeric ops (e.g. OP_1ADD/OP_ADD/OP_PICK),
  -- not just the 4-byte legacy cap. Pre-fix, pop_num() always used max_len=4
  -- and asserted "script number too long" when a tapscript op consumed a
  -- legitimate 5-byte intermediate. Core's interpreter.cpp uses
  -- `nMaxNumSize = 5` for SigVersion::TAPSCRIPT.
  -- See project_lunarblock_wedge_2026_04_28.
  describe("BIP342 tapscript 5-byte CScriptNum support", function()
    -- A 5-byte positive CScriptNum: 2^31 = 0x80000000.
    -- Bitcoin Script encoding: 4 little-endian bytes 0x00 0x00 0x00 0x80
    -- triggers a sign-byte (high bit set, but value is positive), giving
    -- the 5-byte encoding 0x00 0x00 0x00 0x80 0x00.
    local FIVE_BYTE_PUSH = "\x05\x00\x00\x00\x80\x00"  -- OP_PUSHBYTES_5 + 5 bytes
    local OP_1ADD = "\x8b"

    it("rejects 5-byte CScriptNum in legacy execution", function()
      -- Push 0x80000000 (5 bytes), then OP_1ADD which pops_num with
      -- legacy 4-byte cap and must trip "script number too long".
      local script_bytes = FIVE_BYTE_PUSH .. OP_1ADD
      local ok = pcall(function()
        script.execute_script(script_bytes, {}, {}, {})
      end)
      assert.is_false(ok)
    end)

    it("accepts 5-byte CScriptNum in tapscript execution", function()
      -- Same script with is_tapscript=true: pop_num() defaults to 5 bytes,
      -- so OP_1ADD reads 0x80000000 (= 2^31), increments to 2^31+1, and
      -- pushes the result back. Must NOT raise "script number too long".
      local script_bytes = FIVE_BYTE_PUSH .. OP_1ADD
      local stack, err = script.execute_script(
        script_bytes, {}, {is_tapscript = true}, {})
      assert.is_table(stack)
      assert.is_nil(err)
      -- Result on stack should be 2^31 + 1 = 2147483649, encoded as 5 bytes.
      assert.equals(2147483649, script.script_num_decode(stack[1], 5))
    end)

    it("4-byte CScriptNum still works in tapscript", function()
      -- Sanity: tapscript must accept normal 4-byte operands too.
      -- Push 0x7fffffff (4 bytes, max positive without sign byte), OP_1ADD.
      local four_byte_push = "\x04\xff\xff\xff\x7f"
      local script_bytes = four_byte_push .. OP_1ADD
      local stack, err = script.execute_script(
        script_bytes, {}, {is_tapscript = true}, {})
      assert.is_table(stack)
      assert.is_nil(err)
      -- 0x7fffffff + 1 = 0x80000000 = 2147483648.
      assert.equals(2147483648, script.script_num_decode(stack[1], 5))
    end)
  end)
end)
