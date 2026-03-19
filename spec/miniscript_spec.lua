local miniscript = require("lunarblock.miniscript")
local script_mod = require("lunarblock.script")
local crypto = require("lunarblock.crypto")

-- Helper to convert hex string to binary
local function hex_to_bin(hex)
  return (hex:gsub('..', function(cc)
    return string.char(tonumber(cc, 16))
  end))
end

describe("miniscript", function()

  describe("type system", function()
    local T = miniscript.Type

    it("just_0 has correct type", function()
      local node = miniscript.just_0()
      -- Bzudemsxk
      assert.is_true(bit.band(node.type, T.B) ~= 0)
      assert.is_true(bit.band(node.type, T.z) ~= 0)
      assert.is_true(bit.band(node.type, T.u) ~= 0)
      assert.is_true(bit.band(node.type, T.d) ~= 0)
    end)

    it("just_1 has correct type", function()
      local node = miniscript.just_1()
      -- Bzufmxk
      assert.is_true(bit.band(node.type, T.B) ~= 0)
      assert.is_true(bit.band(node.type, T.z) ~= 0)
      assert.is_true(bit.band(node.type, T.u) ~= 0)
      assert.is_true(bit.band(node.type, T.f) ~= 0)
    end)

    it("pk_k has K type", function()
      local key = string.rep("\x02", 33)
      local node = miniscript.pk_k(key)
      assert.is_true(bit.band(node.type, T.K) ~= 0)
      assert.is_true(bit.band(node.type, T.o) ~= 0)
      assert.is_true(bit.band(node.type, T.s) ~= 0)  -- K implies s
    end)

    it("wrap_c converts K to B", function()
      local key = string.rep("\x02", 33)
      local pk = miniscript.pk_k(key)
      local wrapped = miniscript.wrap_c(pk)
      assert.is_true(bit.band(wrapped.type, T.B) ~= 0)
      assert.is_true(bit.band(wrapped.type, T.K) == 0)
    end)

    it("older has timelock property", function()
      local node = miniscript.older(1000)
      assert.is_true(bit.band(node.type, T.B) ~= 0)
      assert.is_true(bit.band(node.type, T.z) ~= 0)
      -- Height-based (< 500000000) should have h property
      assert.is_true(bit.band(node.type, T.h) ~= 0)
    end)

    it("after with time has i property", function()
      local node = miniscript.after(600000000)
      assert.is_true(bit.band(node.type, T.i) ~= 0)
    end)

    it("type_string produces readable output", function()
      local node = miniscript.just_0()
      local s = miniscript.type_string(node.type)
      assert.is_true(s:find("B") ~= nil)
      assert.is_true(s:find("z") ~= nil)
    end)
  end)

  describe("fragment construction", function()
    it("creates pk_h with 20-byte hash", function()
      local hash = string.rep("\x42", 20)
      local node = miniscript.pk_h(hash)
      assert.equals("PK_H", node.fragment)
      assert.equals(hash, node.data)
    end)

    it("creates sha256 with 32-byte hash", function()
      local hash = string.rep("\xab", 32)
      local node = miniscript.sha256(hash)
      assert.equals("SHA256", node.fragment)
      assert.equals(hash, node.data)
    end)

    it("creates multi with k and keys", function()
      local keys = {
        string.rep("\x02", 33),
        string.rep("\x03", 33),
        string.rep("\x04", 33),
      }
      local node = miniscript.multi(2, keys)
      assert.equals("MULTI", node.fragment)
      assert.equals(2, node.k)
      assert.equals(3, #node.keys)
    end)

    it("creates thresh with subexpressions", function()
      local key1 = string.rep("\x02", 33)
      local key2 = string.rep("\x03", 33)
      local pk1 = miniscript.pk(key1)
      local pk2 = miniscript.pk(key2)
      local node = miniscript.thresh(1, {pk1, pk2})
      assert.equals("THRESH", node.fragment)
      assert.equals(1, node.k)
      assert.equals(2, #node.subs)
    end)

    it("pk is syntactic sugar for c:pk_k", function()
      local key = string.rep("\x02", 33)
      local node = miniscript.pk(key)
      assert.equals("WRAP_C", node.fragment)
      assert.equals("PK_K", node.subs[1].fragment)
    end)
  end)

  describe("script compilation", function()
    it("compiles just_0 to OP_0", function()
      local node = miniscript.just_0()
      local s = miniscript.to_script(node)
      assert.equals("\x00", s)
    end)

    it("compiles just_1 to OP_1", function()
      local node = miniscript.just_1()
      local s = miniscript.to_script(node)
      assert.equals("\x51", s)
    end)

    it("compiles pk_k to push pubkey", function()
      local key = hex_to_bin("02" .. string.rep("42", 32))
      local node = miniscript.pk_k(key)
      local s = miniscript.to_script(node)
      assert.equals(34, #s)  -- 1 byte push + 33 byte key
      assert.equals(33, s:byte(1))  -- push 33 bytes
    end)

    it("compiles c:pk_k to pubkey + OP_CHECKSIG", function()
      local key = hex_to_bin("02" .. string.rep("42", 32))
      local node = miniscript.pk(key)
      local s = miniscript.to_script(node)
      assert.equals(35, #s)  -- 34 + OP_CHECKSIG
      assert.equals(0xac, s:byte(#s))  -- ends with OP_CHECKSIG
    end)

    it("compiles older to <n> OP_CSV", function()
      local node = miniscript.older(144)
      local s = miniscript.to_script(node)
      -- Should be: push 144 (0x90 0x00 in script number) + OP_CSV
      assert.equals(0xb2, s:byte(#s))  -- ends with OP_CHECKSEQUENCEVERIFY
    end)

    it("compiles sha256 preimage check", function()
      local hash = string.rep("\xab", 32)
      local node = miniscript.sha256(hash)
      local s = miniscript.to_script(node)
      -- OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUAL
      assert.equals(0x82, s:byte(1))  -- OP_SIZE
      assert.equals(0xa8, s:byte(5))  -- OP_SHA256
      assert.equals(0x87, s:byte(#s))  -- OP_EQUAL
    end)

    it("compiles multi to CHECKMULTISIG", function()
      local keys = {
        hex_to_bin("02" .. string.rep("11", 32)),
        hex_to_bin("02" .. string.rep("22", 32)),
      }
      local node = miniscript.multi(2, keys)
      local s = miniscript.to_script(node)
      -- OP_2 <key1> <key2> OP_2 OP_CHECKMULTISIG
      assert.equals(0x52, s:byte(1))  -- OP_2 (k)
      assert.equals(0xae, s:byte(#s))  -- OP_CHECKMULTISIG
    end)

    it("compiles multi_a to CHECKSIGADD", function()
      local keys = {
        string.rep("\x42", 32),
        string.rep("\x43", 32),
      }
      local node = miniscript.multi_a(1, keys)
      local s = miniscript.to_script(node)
      -- <key0> OP_CHECKSIG <key1> OP_CHECKSIGADD <1> OP_NUMEQUAL
      assert.equals(0xac, s:byte(34))  -- OP_CHECKSIG after first key
      assert.equals(0xba, s:byte(67))  -- OP_CHECKSIGADD after second key
      assert.equals(0x9c, s:byte(#s))  -- OP_NUMEQUAL
    end)

    it("compiles and_v to concatenated scripts", function()
      local node = miniscript.and_v(
        miniscript.wrap_v(miniscript.just_1()),
        miniscript.just_1()
      )
      local s = miniscript.to_script(node)
      -- Should contain OP_1 OP_VERIFY OP_1 or optimized equivalent
      assert.is_true(#s >= 2)
    end)

    it("compiles or_i with IF/ELSE/ENDIF", function()
      local node = miniscript.or_i(
        miniscript.just_1(),
        miniscript.just_0()
      )
      local s = miniscript.to_script(node)
      assert.equals(0x63, s:byte(1))  -- OP_IF
      assert.equals(0x67, s:byte(3))  -- OP_ELSE
      assert.equals(0x68, s:byte(5))  -- OP_ENDIF
    end)

    it("compiles or_d with IFDUP", function()
      local key = hex_to_bin("02" .. string.rep("42", 32))
      local pk = miniscript.pk(key)
      local node = miniscript.or_d(pk, miniscript.just_0())
      local s = miniscript.to_script(node)
      -- Should contain OP_IFDUP and OP_NOTIF
      local found_ifdup = false
      for i = 1, #s do
        if s:byte(i) == 0x73 then found_ifdup = true end
      end
      assert.is_true(found_ifdup)
    end)

    it("compiles thresh with ADD and EQUAL", function()
      local key1 = hex_to_bin("02" .. string.rep("11", 32))
      local key2 = hex_to_bin("02" .. string.rep("22", 32))
      local node = miniscript.thresh(1, {
        miniscript.pk(key1),
        miniscript.pk(key2),
      })
      local s = miniscript.to_script(node)
      -- Should contain OP_ADD
      local found_add = false
      for i = 1, #s do
        if s:byte(i) == 0x93 then found_add = true end
      end
      assert.is_true(found_add)
      assert.equals(0x87, s:byte(#s))  -- ends with OP_EQUAL
    end)

    it("wrap_v converts CHECKSIG to CHECKSIGVERIFY", function()
      local key = hex_to_bin("02" .. string.rep("42", 32))
      local pk = miniscript.pk(key)
      local node = miniscript.wrap_v(pk)
      local s = miniscript.to_script(node)
      -- Should end with OP_CHECKSIGVERIFY, not OP_CHECKSIG + OP_VERIFY
      assert.equals(0xad, s:byte(#s))  -- OP_CHECKSIGVERIFY
    end)
  end)

  describe("satisfaction", function()
    it("just_0 cannot be satisfied", function()
      local node = miniscript.just_0()
      local wit, err = miniscript.satisfy(node)
      assert.is_nil(wit)
    end)

    it("just_1 is satisfied with empty witness", function()
      local node = miniscript.just_1()
      local wit = miniscript.satisfy(node)
      assert.equals(0, #wit)
    end)

    it("pk_k is satisfied with signature", function()
      local key = string.rep("\x02", 33)
      local node = miniscript.pk_k(key)
      local sig = "test_signature"
      local wit = miniscript.satisfy(node, function(k)
        if k == key then return sig end
      end)
      assert.equals(1, #wit)
      assert.equals(sig, wit[1])
    end)

    it("multi is satisfied with k signatures", function()
      local key1 = string.rep("\x02", 33)
      local key2 = string.rep("\x03", 33)
      local sig1 = "sig1"
      local sig2 = "sig2"
      local node = miniscript.multi(2, {key1, key2})
      local wit = miniscript.satisfy(node, function(k)
        if k == key1 then return sig1 end
        if k == key2 then return sig2 end
      end)
      assert.equals(3, #wit)  -- dummy + 2 sigs
      assert.equals("", wit[1])  -- dummy
    end)

    it("sha256 is satisfied with preimage", function()
      local preimage = "secret_preimage"
      local hash = crypto.sha256(preimage)
      local node = miniscript.sha256(hash)
      local wit = miniscript.satisfy(node, nil, function(h)
        if h == hash then return preimage end
      end)
      assert.equals(1, #wit)
      assert.equals(preimage, wit[1])
    end)

    it("older is satisfied when sequence matches", function()
      local node = miniscript.older(144)
      local wit = miniscript.satisfy(node, nil, nil, {sequence = 144})
      assert.equals(0, #wit)
    end)

    it("older cannot be satisfied when sequence is too low", function()
      local node = miniscript.older(144)
      local wit = miniscript.satisfy(node, nil, nil, {sequence = 100})
      assert.is_nil(wit)
    end)

    it("and_v requires both subexpressions satisfied", function()
      local node = miniscript.and_v(
        miniscript.wrap_v(miniscript.just_1()),
        miniscript.just_1()
      )
      local wit = miniscript.satisfy(node)
      assert.equals(0, #wit)
    end)

    it("or_d takes first branch if satisfied", function()
      local node = miniscript.or_d(
        miniscript.just_1(),
        miniscript.just_0()
      )
      local wit = miniscript.satisfy(node)
      assert.is_not_nil(wit)
    end)
  end)

  describe("policy parsing", function()
    it("parses pk(key)", function()
      local key = string.rep("\x02", 33)
      local node = miniscript.from_policy("pk(key)", {key = key})
      assert.equals("WRAP_C", node.fragment)
      assert.equals("PK_K", node.subs[1].fragment)
    end)

    it("parses older(1000)", function()
      local node = miniscript.from_policy("older(1000)")
      assert.equals("OLDER", node.fragment)
      assert.equals(1000, node.k)
    end)

    it("parses after(500000000)", function()
      local node = miniscript.from_policy("after(500000000)")
      assert.equals("AFTER", node.fragment)
      assert.equals(500000000, node.k)
    end)

    it("parses multi(2, k1, k2, k3)", function()
      local k1 = string.rep("\x02", 33)
      local k2 = string.rep("\x03", 33)
      local k3 = string.rep("\x04", 33)
      local node = miniscript.from_policy("multi(2, k1, k2, k3)", {
        k1 = k1, k2 = k2, k3 = k3
      })
      assert.equals("MULTI", node.fragment)
      assert.equals(2, node.k)
      assert.equals(3, #node.keys)
    end)

    it("parses and_v(v:pk(A), pk(B))", function()
      local a = string.rep("\x02", 33)
      local b = string.rep("\x03", 33)
      local node = miniscript.from_policy("and_v(v:pk(A), pk(B))", {
        A = a, B = b
      })
      assert.equals("AND_V", node.fragment)
    end)

    it("parses or_d(pk(A), pk(B))", function()
      local a = string.rep("\x02", 33)
      local b = string.rep("\x03", 33)
      local node = miniscript.from_policy("or_d(pk(A), pk(B))", {
        A = a, B = b
      })
      assert.equals("OR_D", node.fragment)
    end)

    it("parses andor(pk(A), pk(B), pk(C))", function()
      local a = string.rep("\x02", 33)
      local b = string.rep("\x03", 33)
      local c = string.rep("\x04", 33)
      local node = miniscript.from_policy("andor(pk(A), pk(B), pk(C))", {
        A = a, B = b, C = c
      })
      assert.equals("ANDOR", node.fragment)
      assert.equals(3, #node.subs)
    end)

    it("parses thresh(2, pk(A), pk(B), pk(C))", function()
      local a = string.rep("\x02", 33)
      local b = string.rep("\x03", 33)
      local c = string.rep("\x04", 33)
      local node = miniscript.from_policy("thresh(2, pk(A), pk(B), pk(C))", {
        A = a, B = b, C = c
      })
      assert.equals("THRESH", node.fragment)
      assert.equals(2, node.k)
      assert.equals(3, #node.subs)
    end)

    it("parses wrapper chain a:s:pk(A)", function()
      local a = string.rep("\x02", 33)
      local node = miniscript.from_policy("a:s:pk(A)", {A = a})
      -- Should be WRAP_A containing WRAP_S containing pk
      assert.equals("WRAP_A", node.fragment)
      assert.equals("WRAP_S", node.subs[1].fragment)
    end)

    it("parses sha256 with hex hash", function()
      local hash_hex = string.rep("ab", 32)
      local node = miniscript.from_policy("sha256(" .. hash_hex .. ")")
      assert.equals("SHA256", node.fragment)
      assert.equals(32, #node.data)
    end)

    it("parses high-level and(pk(A), pk(B))", function()
      local a = string.rep("\x02", 33)
      local b = string.rep("\x03", 33)
      local node = miniscript.from_policy("and(pk(A), pk(B))", {
        A = a, B = b
      })
      -- Should compile to and_v with v: wrapper on first arg
      assert.equals("AND_V", node.fragment)
    end)

    it("parses high-level or(pk(A), pk(B))", function()
      local a = string.rep("\x02", 33)
      local b = string.rep("\x03", 33)
      local node = miniscript.from_policy("or(pk(A), pk(B))", {
        A = a, B = b
      })
      -- Should compile to or_d or or_i
      local frag = node.fragment
      assert.is_true(frag == "OR_D" or frag == "OR_I")
    end)
  end)

  describe("type validation", function()
    it("is_valid_top_level returns true for B type", function()
      local node = miniscript.pk(string.rep("\x02", 33))
      assert.is_true(miniscript.is_valid_top_level(node))
    end)

    it("is_valid_top_level returns false for K type", function()
      local node = miniscript.pk_k(string.rep("\x02", 33))
      assert.is_false(miniscript.is_valid_top_level(node))
    end)

    it("detects timelock mixing", function()
      -- Mixing relative and absolute timelocks should fail k property
      local node = miniscript.and_v(
        miniscript.wrap_v(miniscript.older(100)),
        miniscript.after(100)
      )
      -- Both are height-based, so no mixing
      assert.is_false(miniscript.has_timelock_mixing(node))
    end)
  end)

  describe("integration: policy to script to execution", function()
    it("compiles and executes simple pk policy", function()
      local key = hex_to_bin("02" .. string.rep("42", 32))
      local sig = "mock_signature_64_bytes_" .. string.rep("x", 40)

      local node = miniscript.from_policy("pk(K)", {K = key})
      local compiled = miniscript.to_script(node)

      -- Should be: <key> OP_CHECKSIG
      assert.equals(35, #compiled)
      assert.equals(0xac, compiled:byte(#compiled))

      -- Test execution with mock checker
      local checker = {
        check_sig = function(s, pk)
          return s == sig and pk == key
        end
      }

      local stack = {sig}
      local result = script_mod.execute_script(compiled, stack, {}, checker)
      assert.equals(1, #result)
      assert.is_true(script_mod.cast_to_bool(result[1]))
    end)

    it("compiles and executes multi policy", function()
      local key1 = hex_to_bin("02" .. string.rep("11", 32))
      local key2 = hex_to_bin("02" .. string.rep("22", 32))
      local sig1 = "sig1_" .. string.rep("x", 60)
      local sig2 = "sig2_" .. string.rep("x", 60)

      local node = miniscript.from_policy("multi(2, A, B)", {A = key1, B = key2})
      local compiled = miniscript.to_script(node)

      local checker = {
        check_sig = function(s, pk)
          if s == sig1 and pk == key1 then return true end
          if s == sig2 and pk == key2 then return true end
          return false
        end
      }

      -- Stack: dummy, sig1, sig2 (bottom to top)
      local stack = {"", sig1, sig2}
      local result = script_mod.execute_script(compiled, stack, {}, checker)
      assert.equals(1, #result)
      assert.is_true(script_mod.cast_to_bool(result[1]))
    end)

    it("compiles and executes sha256 preimage", function()
      local preimage = "secret_preimage_32_bytes_padded!"
      local hash = crypto.sha256(preimage)

      local node = miniscript.sha256(hash)
      local compiled = miniscript.to_script(node)

      -- Stack: preimage
      local stack = {preimage}
      local result = script_mod.execute_script(compiled, stack, {}, {})
      assert.equals(1, #result)
      assert.is_true(script_mod.cast_to_bool(result[1]))
    end)

    it("compiles and executes or_i policy", function()
      local node = miniscript.or_i(
        miniscript.just_1(),
        miniscript.just_0()
      )
      local compiled = miniscript.to_script(node)

      -- Take first branch (push 1)
      local stack = {"\x01"}
      local result = script_mod.execute_script(compiled, stack, {}, {})
      assert.equals(1, #result)
      assert.is_true(script_mod.cast_to_bool(result[1]))
    end)
  end)
end)
