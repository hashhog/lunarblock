-- cffix-lunarblock-tapscript-condition-stack
--
-- Tapscript is exempt from MAX_SCRIPT_SIZE and MAX_OPS_PER_SCRIPT (BIP342), so
-- a script of D nested true OP_IFs is legal at any D the block weight allows.
-- execute_script used to keep the IF state as a table of booleans and walk the
-- WHOLE table on every opcode to decide "are we executing?" (and again on every
-- OP_ELSE), so such a script cost O(D^2) table reads. Core's ConditionStack
-- (src/script/interpreter.cpp, class ConditionStack) keeps only the stack size
-- and the position of the first false entry, which makes all_true(),
-- push_back(), pop_back() and toggle_top() O(1).
--
-- The work test below counts executed Lua source lines in src/script.lua with
-- debug.sethook. That counter needs no hook in the interpreter, so it measures
-- the base commit and the fix with the same instrument. It is linear in D for
-- an O(1) condition stack (ratio ~2 per doubling of D) and quadratic for the
-- old table walk (ratio ~4).
--
-- The semantic tests pin that the O(1) structure decides every branch exactly
-- like the old walk: hand-written cases (false entry below a toggled top,
-- NOTIF, unbalanced ELSE/ENDIF) and a seeded differential against a reference
-- model of the boolean-table semantics over random IF/NOTIF/ELSE/ENDIF scripts
-- in all three sigversions.

describe("tapscript condition stack (cffix-lunarblock-tapscript-condition-stack)", function()
  local script
  local SCRIPT_SRC

  setup(function()
    package.path = "src/?.lua;" .. package.path
    script = require("lunarblock.script")
    SCRIPT_SRC = debug.getinfo(script.execute_script, "S").source
  end)

  local OP_0, OP_1, OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF = 0x00, 0x51, 0x63, 0x64, 0x67, 0x68
  local OP_DROP, OP_RETURN = 0x75, 0x6a

  -- (OP_1 OP_IF) x D, OP_ENDIF x D, OP_1
  local function nested_true_ifs(d)
    return string.rep(string.char(OP_1, OP_IF), d) .. string.rep(string.char(OP_ENDIF), d)
      .. string.char(OP_1)
  end

  -- Run one tapscript with a line hook that counts lines executed inside
  -- src/script.lua. `cap` bounds the run: once the count passes it the hook
  -- raises, so a quadratic interpreter fails fast instead of running minutes.
  local function count_lines(bytes, cap)
    local n = 0
    local capped = false
    local function hook()
      local info = debug.getinfo(2, "S")
      if info and info.source == SCRIPT_SRC then
        n = n + 1
        if n > cap then
          capped = true
          debug.sethook()
          error("line budget exceeded")
        end
      end
    end
    debug.sethook(hook, "l")
    local ok, res, err = pcall(script.execute_script, bytes, {}, { is_tapscript = true }, {})
    debug.sethook()
    return n, capped, ok, res, err
  end

  it("does linear work for nested true tapscript IFs (D = 2k, 4k, 8k)", function()
    local CAP = 20000000
    local counts = {}
    local report = {}
    for _, d in ipairs({ 2000, 4000, 8000 }) do
      local n, capped, ok, res, err = count_lines(nested_true_ifs(d), CAP)
      if not capped then
        assert.is_true(ok, "execute_script raised: " .. tostring(res))
        assert.is_nil(err)
        assert.equals(1, #res)
        assert.equals("\1", res[1])
      end
      counts[#counts + 1] = n
      report[#report + 1] = string.format("D=%d lines=%d%s", d, n, capped and " (CAPPED)" or "")
      if capped then break end
    end
    local msg = table.concat(report, ", ")
    -- A capped run is already far past any linear budget (20M lines for at
    -- most 24k opcodes); larger D is skipped so the failure stays fast.
    assert.equals(3, #counts, "line budget exceeded, work is super-linear: " .. msg)
    assert.is_true(counts[3] <= CAP, "line budget exceeded, work is super-linear: " .. msg)
    -- Linear work doubles with D; the old O(D) walk per opcode quadruples.
    assert.is_true(counts[2] <= 2.5 * counts[1], "D 2k->4k not linear: " .. msg)
    assert.is_true(counts[3] <= 2.5 * counts[2], "D 4k->8k not linear: " .. msg)
    -- And the absolute cost per nesting level stays small (a few dozen lines
    -- per opcode, ~140 per nesting level here), not proportional to D.
    assert.is_true(counts[3] <= 300 * 8000, "D=8k cost not O(D): " .. msg)
  end)

  -- Assemble a list of byte values / strings into a script.
  local function asm(t)
    local out = {}
    for _, v in ipairs(t) do
      out[#out + 1] = type(v) == "number" and string.char(v) or v
    end
    return table.concat(out)
  end

  local function run(bytes, flags)
    local ok, res, err = pcall(script.execute_script, bytes, {}, flags or { is_tapscript = true }, {})
    if not ok then return "ERR" end
    if res == nil then return "FAIL:" .. tostring(err) end
    local parts = {}
    for i, v in ipairs(res) do
      local h = {}
      for k = 1, #v do h[k] = string.format("%02x", v:byte(k)) end
      parts[i] = table.concat(h)
    end
    return "OK:" .. table.concat(parts, ",")
  end

  it("ELSE under a false outer branch does not start executing", function()
    -- 0 IF  1 IF  ELSE <0x02> ENDIF  ELSE <0x03> ENDIF : outer false, so the
    -- inner ELSE must stay non-executing; only the outer ELSE pushes 0x03.
    local s = asm({ OP_0, OP_IF, OP_1, OP_IF, OP_ELSE, 0x01, "\2", OP_ENDIF,
      OP_ELSE, 0x01, "\3", OP_ENDIF })
    assert.equals("OK:03", run(s))
  end)

  it("toggles back to executing after a nested false IF closes", function()
    -- 1 IF 0 IF <2> ELSE <3> ENDIF <4> ELSE <5> ENDIF
    local s = asm({ OP_1, OP_IF, OP_0, OP_IF, 0x01, "\2", OP_ELSE, 0x01, "\3", OP_ENDIF,
      0x01, "\4", OP_ELSE, 0x01, "\5", OP_ENDIF })
    assert.equals("OK:03,04", run(s))
  end)

  it("double ELSE flips the top twice", function()
    -- 1 IF <2> ELSE <3> ELSE <4> ENDIF  -> 02, 04
    local s = asm({ OP_1, OP_IF, 0x01, "\2", OP_ELSE, 0x01, "\3", OP_ELSE, 0x01, "\4", OP_ENDIF })
    assert.equals("OK:02,04", run(s))
  end)

  it("NOTIF inverts the condition", function()
    local s = asm({ OP_0, OP_NOTIF, 0x01, "\7", OP_ENDIF })
    assert.equals("OK:07", run(s))
  end)

  it("OP_RETURN inside a false branch is skipped", function()
    local s = asm({ OP_0, OP_IF, OP_RETURN, OP_ENDIF, OP_1 })
    assert.equals("OK:01", run(s))
  end)

  it("unbalanced ELSE, ENDIF and missing ENDIF still fail", function()
    assert.equals("ERR", run(asm({ OP_ELSE, OP_1 })))
    assert.equals("ERR", run(asm({ OP_ENDIF, OP_1 })))
    assert.equals("ERR", run(asm({ OP_1, OP_IF, OP_1 })))
    -- An ENDIF after the stack is already empty again is unbalanced.
    assert.equals("ERR", run(asm({ OP_1, OP_IF, OP_ENDIF, OP_ENDIF, OP_1 })))
  end)

  -- Reference model: the pre-fix boolean-table semantics, kept independent of
  -- src/script.lua. Supports only the opcodes the generator emits.
  local function reference(ops, minimal)
    local stack, ifs = {}, {}
    local function executing()
      for _, v in ipairs(ifs) do if not v then return false end end
      return true
    end
    for _, op in ipairs(ops) do
      if op == OP_IF or op == OP_NOTIF then
        if executing() then
          if #stack == 0 then return "ERR" end
          local v = table.remove(stack)
          if minimal and (#v > 1 or (#v == 1 and v:byte(1) ~= 1)) then return "FAIL:MINIMALIF" end
          local b = false
          for k = 1, #v do
            if v:byte(k) ~= 0 and not (k == #v and v:byte(k) == 0x80) then b = true end
          end
          if op == OP_NOTIF then b = not b end
          ifs[#ifs + 1] = b
        else
          ifs[#ifs + 1] = false
        end
      elseif op == OP_ELSE then
        if #ifs == 0 then return "ERR" end
        local parent = true
        for j = 1, #ifs - 1 do if not ifs[j] then parent = false end end
        if parent then ifs[#ifs] = not ifs[#ifs] end
      elseif op == OP_ENDIF then
        if #ifs == 0 then return "ERR" end
        ifs[#ifs] = nil
      elseif executing() then
        if op == OP_0 then stack[#stack + 1] = ""
        elseif op == OP_1 then stack[#stack + 1] = "\1"
        elseif op == 0x52 then stack[#stack + 1] = "\2"
        elseif op == OP_DROP then
          if #stack == 0 then return "ERR" end
          stack[#stack] = nil
        end
      end
    end
    if #ifs ~= 0 then return "ERR" end
    local parts = {}
    for i, v in ipairs(stack) do
      local h = {}
      for k = 1, #v do h[k] = string.format("%02x", v:byte(k)) end
      parts[i] = table.concat(h)
    end
    return "OK:" .. table.concat(parts, ",")
  end

  it("matches the reference IF/ELSE model on 30,000 random scripts across sigversions", function()
    local alphabet = { OP_0, OP_1, 0x52, OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF, OP_DROP }
    local modes = {
      { flags = { is_tapscript = true }, minimal = true },
      { flags = { is_witness_v0 = true, verify_minimalif = true }, minimal = true },
      { flags = { is_witness_v0 = true }, minimal = false },
      { flags = {}, minimal = false },
    }
    -- Deterministic Park-Miller generator (products stay below 2^46, so it
    -- is exact in doubles) so the run is reproducible without math.random.
    local seed = 0x5eed
    local function rnd(n)
      seed = (seed * 16807) % 2147483647
      return math.floor(seed / 2147483647 * n) + 1
    end
    local mismatches = {}
    local outcomes = {}
    for i = 1, 30000 do
      local len = rnd(24)
      local ops = {}
      for k = 1, len do ops[k] = alphabet[rnd(#alphabet)] end
      local mode = modes[(i % #modes) + 1]
      local want = reference(ops, mode.minimal)
      local got = run(asm(ops), mode.flags)
      local kind = want:sub(1, 2)
      outcomes[kind] = (outcomes[kind] or 0) + 1
      if got ~= want and #mismatches < 5 then
        local h = {}
        for k, o in ipairs(ops) do h[k] = string.format("%02x", o) end
        mismatches[#mismatches + 1] = table.concat(h) .. " want=" .. want .. " got=" .. got
      end
    end
    assert.equals(0, #mismatches, table.concat(mismatches, "\n"))
    -- Coverage guard: the generator must produce balanced scripts that run to
    -- completion, not only errors, or a broken toggle could hide.
    assert.is_true((outcomes["OK"] or 0) >= 1000, "too few completed scripts")
  end)
end)
