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
end)
