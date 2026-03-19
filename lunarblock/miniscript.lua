-- Miniscript: A structured subset of Bitcoin Script
-- Enables analysis, composition, and optimization of spending conditions
-- Reference: BIP 379, Bitcoin Core miniscript.cpp/h

local script = require("lunarblock.script")
local crypto = require("lunarblock.crypto")
local M = {}

--------------------------------------------------------------------------------
-- Type System
-- Types use bitmask representation for efficient composition checks
--------------------------------------------------------------------------------

-- Base types (mutually exclusive)
M.Type = {
  B = 0x00000001,  -- Base expression: outputs 1 on satisfaction, 0 on dissatisfaction
  V = 0x00000002,  -- Verify: outputs nothing, cannot be dissatisfied
  K = 0x00000004,  -- Key: outputs pubkey, needs CHECKSIG to become B
  W = 0x00000008,  -- Wrapped: takes input from one below stack top

  -- Stack argument properties
  z = 0x00000010,  -- Zero-arg: consumes 0 stack elements
  o = 0x00000020,  -- One-arg: consumes exactly 1 stack element
  n = 0x00000040,  -- Nonzero: satisfaction has nonzero top stack

  -- Dissatisfaction properties
  d = 0x00000080,  -- Dissatisfiable: has easy dissatisfaction
  u = 0x00000100,  -- Unit: on satisfaction, pushes exactly 1

  -- Malleability properties
  e = 0x00000200,  -- Expression: dissatisfaction is nonmalleable
  f = 0x00000400,  -- Forced: dissatisfactions involve signature
  s = 0x00000800,  -- Safe: satisfactions involve signature
  m = 0x00001000,  -- Nonmalleable: every satisfaction is nonmalleable
  x = 0x00002000,  -- Expensive verify: can't cheaply convert to V

  -- Timelock properties
  g = 0x00004000,  -- Contains relative time timelock (older)
  h = 0x00008000,  -- Contains relative height timelock (older)
  i = 0x00010000,  -- Contains absolute time timelock (after)
  j = 0x00020000,  -- Contains absolute height timelock (after)
  k = 0x00040000,  -- No timelock mixing
}

local T = M.Type
local band, bor, bnot = bit.band, bit.bor, bit.bnot

-- Check if type has a specific property
local function has(t, prop)
  return band(t, prop) ~= 0
end

-- Compute base type (exactly one of B, V, K, W)
local function base_type(t)
  return band(t, bor(T.B, T.V, T.K, T.W))
end

-- Check for conflicting types (used in validation)
local function validate_type(t)
  -- Exactly one base type
  local bt = base_type(t)
  if bt ~= T.B and bt ~= T.V and bt ~= T.K and bt ~= T.W then
    return false, "must have exactly one base type"
  end

  -- z conflicts with o and n
  if has(t, T.z) and (has(t, T.o) or has(t, T.n)) then
    return false, "z conflicts with o and n"
  end

  -- n conflicts with W
  if has(t, T.n) and has(t, T.W) then
    return false, "n conflicts with W"
  end

  -- V conflicts with d, u, e
  if has(t, T.V) and (has(t, T.d) or has(t, T.u) or has(t, T.e)) then
    return false, "V conflicts with d, u, e"
  end

  -- d conflicts with f
  if has(t, T.d) and has(t, T.f) then
    return false, "d conflicts with f"
  end

  return true
end

-- Sanitize type: apply implied properties
local function sanitize_type(t)
  -- K implies u and s
  if has(t, T.K) then
    t = bor(t, T.u, T.s)
  end
  -- e implies d and f (but f conflicts with d, so e actually implies nonmalleable dissatisfaction)
  -- Actually in miniscript: e implies d (dissatisfiable with unique dissatisfaction)
  if has(t, T.e) then
    t = bor(t, T.d)
  end
  -- V implies f (cannot be dissatisfied, so all dissatisfaction paths involve signature failure)
  if has(t, T.V) then
    t = bor(t, T.f)
  end
  return t
end

--------------------------------------------------------------------------------
-- Fragment types
--------------------------------------------------------------------------------

M.Fragment = {
  JUST_0 = "JUST_0",
  JUST_1 = "JUST_1",
  PK_K = "PK_K",
  PK_H = "PK_H",
  OLDER = "OLDER",
  AFTER = "AFTER",
  SHA256 = "SHA256",
  HASH256 = "HASH256",
  RIPEMD160 = "RIPEMD160",
  HASH160 = "HASH160",
  WRAP_A = "WRAP_A",
  WRAP_S = "WRAP_S",
  WRAP_C = "WRAP_C",
  WRAP_D = "WRAP_D",
  WRAP_V = "WRAP_V",
  WRAP_J = "WRAP_J",
  WRAP_N = "WRAP_N",
  AND_V = "AND_V",
  AND_B = "AND_B",
  OR_B = "OR_B",
  OR_C = "OR_C",
  OR_D = "OR_D",
  OR_I = "OR_I",
  ANDOR = "ANDOR",
  THRESH = "THRESH",
  MULTI = "MULTI",
  MULTI_A = "MULTI_A",
}

local F = M.Fragment

--------------------------------------------------------------------------------
-- Node structure
--------------------------------------------------------------------------------

-- Create a new miniscript node
local function make_node(fragment, opts)
  opts = opts or {}
  return {
    fragment = fragment,
    type = opts.type or 0,
    k = opts.k,              -- threshold or locktime value
    keys = opts.keys,        -- list of pubkeys
    data = opts.data,        -- hash data for preimage checks
    subs = opts.subs or {},  -- child nodes
    script_len = opts.script_len or 0,
    ops = opts.ops or 0,
    -- For Tapscript mode
    tapscript = opts.tapscript or false,
  }
end

--------------------------------------------------------------------------------
-- Type computation for each fragment
--------------------------------------------------------------------------------

-- LOCKTIME_THRESHOLD: 500,000,000 (timestamps vs block heights)
local LOCKTIME_THRESHOLD = 500000000

local function compute_type(node)
  local frag = node.fragment

  if frag == F.JUST_0 then
    -- Bzudemsxk: always false
    return bor(T.B, T.z, T.u, T.d, T.e, T.m, T.s, T.x, T.k)

  elseif frag == F.JUST_1 then
    -- Bzufmxk: always true
    return bor(T.B, T.z, T.u, T.f, T.m, T.x, T.k)

  elseif frag == F.PK_K then
    -- Konudemsxk: raw pubkey (needs OP_CHECKSIG)
    return bor(T.K, T.o, T.n, T.u, T.d, T.e, T.m, T.s, T.x, T.k)

  elseif frag == F.PK_H then
    -- Knudemsxk: pubkey hash (needs pubkey + OP_CHECKSIG)
    return bor(T.K, T.n, T.u, T.d, T.e, T.m, T.s, T.x, T.k)

  elseif frag == F.OLDER then
    -- Bzfmxk + g or h depending on value
    local t = bor(T.B, T.z, T.f, T.m, T.x, T.k)
    if node.k >= LOCKTIME_THRESHOLD then
      t = bor(t, T.g)  -- relative time
    else
      t = bor(t, T.h)  -- relative height
    end
    return t

  elseif frag == F.AFTER then
    -- Bzfmxk + i or j depending on value
    local t = bor(T.B, T.z, T.f, T.m, T.x, T.k)
    if node.k >= LOCKTIME_THRESHOLD then
      t = bor(t, T.i)  -- absolute time
    else
      t = bor(t, T.j)  -- absolute height
    end
    return t

  elseif frag == F.SHA256 or frag == F.HASH256 or frag == F.RIPEMD160 or frag == F.HASH160 then
    -- Bonudmk: hash preimage check
    return bor(T.B, T.o, T.n, T.u, T.d, T.m, T.k)

  elseif frag == F.WRAP_A then
    -- W from B
    local sub = node.subs[1]
    if not has(sub.type, T.B) then return nil end
    local t = bor(T.W, band(sub.type, bor(T.d, T.u, T.e, T.f, T.s, T.m, T.g, T.h, T.i, T.j, T.k)))
    return t

  elseif frag == F.WRAP_S then
    -- W from Bo
    local sub = node.subs[1]
    if not has(sub.type, T.B) or not has(sub.type, T.o) then return nil end
    local t = bor(T.W, band(sub.type, bor(T.d, T.u, T.e, T.f, T.s, T.m, T.x, T.g, T.h, T.i, T.j, T.k)))
    return t

  elseif frag == F.WRAP_C then
    -- B from K (adds CHECKSIG)
    local sub = node.subs[1]
    if not has(sub.type, T.K) then return nil end
    local t = bor(T.B, T.u, T.s, band(sub.type, bor(T.o, T.n, T.d, T.e, T.f, T.m, T.g, T.h, T.i, T.j, T.k)))
    return t

  elseif frag == F.WRAP_D then
    -- B from Vz (adds OP_DUP OP_IF ... OP_ENDIF)
    local sub = node.subs[1]
    if not has(sub.type, T.V) or not has(sub.type, T.z) then return nil end
    local t = bor(T.B, T.o, T.n, T.d, T.x, band(sub.type, bor(T.f, T.s, T.m, T.g, T.h, T.i, T.j, T.k)))
    return t

  elseif frag == F.WRAP_V then
    -- V from B (adds OP_VERIFY or converts to -VERIFY)
    local sub = node.subs[1]
    if not has(sub.type, T.B) then return nil end
    local t = bor(T.V, T.f, band(sub.type, bor(T.z, T.o, T.n, T.s, T.m, T.x, T.g, T.h, T.i, T.j, T.k)))
    return t

  elseif frag == F.WRAP_J then
    -- B from Bn (adds OP_SIZE OP_0NOTEQUAL OP_IF ... OP_ENDIF)
    local sub = node.subs[1]
    if not has(sub.type, T.B) or not has(sub.type, T.n) then return nil end
    local t = bor(T.B, T.o, T.n, T.d, T.x, band(sub.type, bor(T.u, T.f, T.s, T.m, T.g, T.h, T.i, T.j, T.k)))
    return t

  elseif frag == F.WRAP_N then
    -- B from B (adds OP_0NOTEQUAL)
    local sub = node.subs[1]
    if not has(sub.type, T.B) then return nil end
    local t = bor(T.B, T.u, T.x, band(sub.type, bor(T.z, T.o, T.n, T.d, T.e, T.f, T.s, T.m, T.g, T.h, T.i, T.j, T.k)))
    return t

  elseif frag == F.AND_V then
    -- X from V, Y from B/K/V
    local x, y = node.subs[1], node.subs[2]
    if not has(x.type, T.V) then return nil end
    local y_base = base_type(y.type)
    if y_base ~= T.B and y_base ~= T.K and y_base ~= T.V then return nil end

    local t = y_base
    -- z if both z
    if has(x.type, T.z) and has(y.type, T.z) then t = bor(t, T.z) end
    -- o if z+o or o+z
    if (has(x.type, T.z) and has(y.type, T.o)) or (has(x.type, T.o) and has(y.type, T.z)) then
      t = bor(t, T.o)
    end
    -- n from y
    if has(y.type, T.n) then t = bor(t, T.n) end
    -- u from y
    if has(y.type, T.u) then t = bor(t, T.u) end
    -- f if both f
    if has(x.type, T.f) and has(y.type, T.f) then t = bor(t, T.f) end
    -- s if either s
    if has(x.type, T.s) or has(y.type, T.s) then t = bor(t, T.s) end
    -- m if both m and s (has signature)
    if has(x.type, T.m) and has(y.type, T.m) and (has(x.type, T.s) or has(y.type, T.s)) then
      t = bor(t, T.m)
    end
    -- x from y
    if has(y.type, T.x) then t = bor(t, T.x) end
    -- Timelock properties union
    t = bor(t, band(bor(x.type, y.type), bor(T.g, T.h, T.i, T.j)))
    -- k if both k and no mixing
    if has(x.type, T.k) and has(y.type, T.k) then
      local x_time = bor(band(x.type, T.g), band(x.type, T.i))
      local x_height = bor(band(x.type, T.h), band(x.type, T.j))
      local y_time = bor(band(y.type, T.g), band(y.type, T.i))
      local y_height = bor(band(y.type, T.h), band(y.type, T.j))
      if not (x_time ~= 0 and y_height ~= 0) and not (x_height ~= 0 and y_time ~= 0) then
        t = bor(t, T.k)
      end
    end
    return t

  elseif frag == F.AND_B then
    -- B from B, W
    local x, y = node.subs[1], node.subs[2]
    if not has(x.type, T.B) then return nil end
    if not has(y.type, T.W) then return nil end

    local t = T.B
    -- z if both z
    if has(x.type, T.z) and has(y.type, T.z) then t = bor(t, T.z) end
    -- o if z+o or o+z
    if (has(x.type, T.z) and has(y.type, T.o)) or (has(x.type, T.o) and has(y.type, T.z)) then
      t = bor(t, T.o)
    end
    -- n from x
    if has(x.type, T.n) then t = bor(t, T.n) end
    -- d if both d
    if has(x.type, T.d) and has(y.type, T.d) then t = bor(t, T.d) end
    -- u if both u
    if has(x.type, T.u) and has(y.type, T.u) then t = bor(t, T.u) end
    -- e (dissatisfiable uniquely)
    if has(x.type, T.e) and has(y.type, T.e) then t = bor(t, T.e) end
    -- f if both f
    if has(x.type, T.f) and has(y.type, T.f) then t = bor(t, T.f) end
    -- s if either s
    if has(x.type, T.s) or has(y.type, T.s) then t = bor(t, T.s) end
    -- m if complex conditions
    if has(x.type, T.m) and has(y.type, T.m) then
      if has(x.type, T.e) and has(y.type, T.e) and (has(x.type, T.s) or has(y.type, T.s)) then
        t = bor(t, T.m)
      end
    end
    t = bor(t, T.x)
    -- Timelock properties union
    t = bor(t, band(bor(x.type, y.type), bor(T.g, T.h, T.i, T.j)))
    -- k property
    if has(x.type, T.k) and has(y.type, T.k) then
      local x_time = bor(band(x.type, T.g), band(x.type, T.i))
      local x_height = bor(band(y.type, T.h), band(y.type, T.j))
      local y_time = bor(band(y.type, T.g), band(y.type, T.i))
      local y_height = bor(band(y.type, T.h), band(y.type, T.j))
      if not (x_time ~= 0 and y_height ~= 0) and not (x_height ~= 0 and y_time ~= 0) then
        t = bor(t, T.k)
      end
    end
    return t

  elseif frag == F.OR_B then
    -- B from Bd, Wd
    local x, y = node.subs[1], node.subs[2]
    if not has(x.type, T.B) or not has(x.type, T.d) then return nil end
    if not has(y.type, T.W) or not has(y.type, T.d) then return nil end

    local t = bor(T.B, T.d, T.x)
    -- z if both z
    if has(x.type, T.z) and has(y.type, T.z) then t = bor(t, T.z) end
    -- o if z+o or o+z
    if (has(x.type, T.z) and has(y.type, T.o)) or (has(x.type, T.o) and has(y.type, T.z)) then
      t = bor(t, T.o)
    end
    -- u if both u
    if has(x.type, T.u) and has(y.type, T.u) then t = bor(t, T.u) end
    -- e if both e
    if has(x.type, T.e) and has(y.type, T.e) then t = bor(t, T.e) end
    -- s if both s
    if has(x.type, T.s) and has(y.type, T.s) then t = bor(t, T.s) end
    -- m if both e and s
    if has(x.type, T.e) and has(y.type, T.e) and has(x.type, T.s) and has(y.type, T.s) then
      if has(x.type, T.m) and has(y.type, T.m) then
        t = bor(t, T.m)
      end
    end
    -- Timelock properties union
    t = bor(t, band(bor(x.type, y.type), bor(T.g, T.h, T.i, T.j)))
    -- k: complex, simplified
    if has(x.type, T.k) and has(y.type, T.k) then
      t = bor(t, T.k)
    end
    return t

  elseif frag == F.OR_C then
    -- V from Bdu, V
    local x, y = node.subs[1], node.subs[2]
    if not has(x.type, T.B) or not has(x.type, T.d) or not has(x.type, T.u) then return nil end
    if not has(y.type, T.V) then return nil end

    local t = bor(T.V, T.f)
    -- z if both z
    if has(x.type, T.z) and has(y.type, T.z) then t = bor(t, T.z) end
    -- o if z+o or o+z
    if (has(x.type, T.z) and has(y.type, T.o)) or (has(x.type, T.o) and has(y.type, T.z)) then
      t = bor(t, T.o)
    end
    -- s if both s
    if has(x.type, T.s) and has(y.type, T.s) then t = bor(t, T.s) end
    -- m conditions
    if has(x.type, T.e) and has(x.type, T.m) and has(y.type, T.m) and has(x.type, T.s) and has(y.type, T.s) then
      t = bor(t, T.m)
    end
    t = bor(t, T.x)
    t = bor(t, band(bor(x.type, y.type), bor(T.g, T.h, T.i, T.j)))
    if has(x.type, T.k) and has(y.type, T.k) then t = bor(t, T.k) end
    return t

  elseif frag == F.OR_D then
    -- B from Bdu, B
    local x, y = node.subs[1], node.subs[2]
    if not has(x.type, T.B) or not has(x.type, T.d) or not has(x.type, T.u) then return nil end
    if not has(y.type, T.B) then return nil end

    local t = T.B
    -- z if both z
    if has(x.type, T.z) and has(y.type, T.z) then t = bor(t, T.z) end
    -- o if z+o or o+z
    if (has(x.type, T.z) and has(y.type, T.o)) or (has(x.type, T.o) and has(y.type, T.z)) then
      t = bor(t, T.o)
    end
    -- d from y
    if has(y.type, T.d) then t = bor(t, T.d) end
    -- u from y
    if has(y.type, T.u) then t = bor(t, T.u) end
    -- e if y.e and both s
    if has(y.type, T.e) and has(x.type, T.s) and has(y.type, T.s) then t = bor(t, T.e) end
    -- f from y
    if has(y.type, T.f) then t = bor(t, T.f) end
    -- s if both s
    if has(x.type, T.s) and has(y.type, T.s) then t = bor(t, T.s) end
    -- m
    if has(x.type, T.e) and has(x.type, T.m) and has(y.type, T.m) and has(x.type, T.s) and has(y.type, T.s) then
      t = bor(t, T.m)
    end
    t = bor(t, T.x)
    t = bor(t, band(bor(x.type, y.type), bor(T.g, T.h, T.i, T.j)))
    if has(x.type, T.k) and has(y.type, T.k) then t = bor(t, T.k) end
    return t

  elseif frag == F.OR_I then
    -- Result from first satisfiable path
    local x, y = node.subs[1], node.subs[2]
    local x_base = base_type(x.type)
    local y_base = base_type(y.type)
    if x_base ~= y_base then return nil end
    if x_base ~= T.B and x_base ~= T.K and x_base ~= T.V then return nil end

    local t = x_base
    -- o if both o
    if has(x.type, T.o) and has(y.type, T.o) then t = bor(t, T.o) end
    -- d if either d
    if has(x.type, T.d) or has(y.type, T.d) then t = bor(t, T.d) end
    -- u if both u
    if has(x.type, T.u) and has(y.type, T.u) then t = bor(t, T.u) end
    -- e if both e
    if has(x.type, T.e) and has(y.type, T.e) then t = bor(t, T.e) end
    -- f if both f
    if has(x.type, T.f) and has(y.type, T.f) then t = bor(t, T.f) end
    -- s if both s
    if has(x.type, T.s) and has(y.type, T.s) then t = bor(t, T.s) end
    -- m if both m and s
    if has(x.type, T.m) and has(y.type, T.m) and has(x.type, T.s) and has(y.type, T.s) then
      t = bor(t, T.m)
    end
    t = bor(t, T.x)
    t = bor(t, band(bor(x.type, y.type), bor(T.g, T.h, T.i, T.j)))
    if has(x.type, T.k) and has(y.type, T.k) then t = bor(t, T.k) end
    return t

  elseif frag == F.ANDOR then
    -- ANDOR(X, Y, Z): X ? Y : Z
    local x, y, z = node.subs[1], node.subs[2], node.subs[3]
    if not has(x.type, T.B) or not has(x.type, T.d) or not has(x.type, T.u) then return nil end
    local y_base = base_type(y.type)
    local z_base = base_type(z.type)
    if y_base ~= z_base then return nil end
    if y_base ~= T.B and y_base ~= T.K and y_base ~= T.V then return nil end

    local t = y_base
    -- z if all z
    if has(x.type, T.z) and has(y.type, T.z) and has(z.type, T.z) then t = bor(t, T.z) end
    -- o if conditions met
    local x_z = has(x.type, T.z)
    local x_o = has(x.type, T.o)
    local y_z = has(y.type, T.z)
    local y_o = has(y.type, T.o)
    local z_z = has(z.type, T.z)
    local z_o = has(z.type, T.o)
    if (x_z and y_o and z_o) or (x_o and y_z and z_z) then
      t = bor(t, T.o)
    end
    -- d from z
    if has(z.type, T.d) then t = bor(t, T.d) end
    -- u if both y and z u
    if has(y.type, T.u) and has(z.type, T.u) then t = bor(t, T.u) end
    -- e
    if has(z.type, T.e) and (has(x.type, T.s) or has(y.type, T.s)) and has(z.type, T.s) then
      t = bor(t, T.e)
    end
    -- f
    if has(y.type, T.f) and has(z.type, T.f) then t = bor(t, T.f) end
    -- s
    if (has(x.type, T.s) or has(y.type, T.s)) and has(z.type, T.s) then t = bor(t, T.s) end
    -- m
    if has(x.type, T.e) and has(y.type, T.m) and has(z.type, T.m) and
       (has(x.type, T.s) or has(y.type, T.s)) and has(z.type, T.s) then
      t = bor(t, T.m)
    end
    t = bor(t, T.x)
    t = bor(t, band(bor(bor(x.type, y.type), z.type), bor(T.g, T.h, T.i, T.j)))
    if has(x.type, T.k) and has(y.type, T.k) and has(z.type, T.k) then t = bor(t, T.k) end
    return t

  elseif frag == F.THRESH then
    -- thresh(k, X1, ..., Xn) where all Xi are Bdu
    local k = node.k
    local subs = node.subs
    local n = #subs
    if k < 1 or k > n then return nil end

    local t = bor(T.B, T.d, T.u)
    local all_z = true
    local all_m = true
    local all_e = true
    local count_s = 0

    for i, sub in ipairs(subs) do
      if not has(sub.type, T.B) or not has(sub.type, T.d) or not has(sub.type, T.u) then
        return nil
      end
      if not has(sub.type, T.z) then all_z = false end
      if not has(sub.type, T.m) then all_m = false end
      if not has(sub.type, T.e) then all_e = false end
      if has(sub.type, T.s) then count_s = count_s + 1 end
      -- Timelock union
      t = bor(t, band(sub.type, bor(T.g, T.h, T.i, T.j)))
    end

    if all_z then t = bor(t, T.z) end
    if all_e and count_s >= n - k then t = bor(t, T.e) end
    if count_s >= n - k + 1 then t = bor(t, T.s) end
    if all_m and all_e and count_s >= n - k then t = bor(t, T.m) end
    t = bor(t, T.x)

    -- k property: all k and no mixing
    local any_time = false
    local any_height = false
    for _, sub in ipairs(subs) do
      if not has(sub.type, T.k) then return bor(t, 0) end
      if band(sub.type, bor(T.g, T.i)) ~= 0 then any_time = true end
      if band(sub.type, bor(T.h, T.j)) ~= 0 then any_height = true end
    end
    if not (any_time and any_height) then t = bor(t, T.k) end
    return t

  elseif frag == F.MULTI then
    -- multi(k, key1, ..., keyn) - P2WSH only
    return bor(T.B, T.n, T.u, T.d, T.e, T.m, T.s, T.k)

  elseif frag == F.MULTI_A then
    -- multi_a(k, key1, ..., keyn) - Tapscript only
    return bor(T.B, T.u, T.d, T.e, T.m, T.s, T.k)
  end

  return nil
end

--------------------------------------------------------------------------------
-- Node constructors
--------------------------------------------------------------------------------

function M.just_0()
  local node = make_node(F.JUST_0)
  node.type = compute_type(node)
  return node
end

function M.just_1()
  local node = make_node(F.JUST_1)
  node.type = compute_type(node)
  return node
end

function M.pk_k(pubkey)
  assert(type(pubkey) == "string", "pubkey must be a string")
  local node = make_node(F.PK_K, {keys = {pubkey}})
  node.type = compute_type(node)
  return node
end

function M.pk_h(pubkey_hash)
  assert(type(pubkey_hash) == "string" and #pubkey_hash == 20, "pubkey_hash must be 20 bytes")
  local node = make_node(F.PK_H, {data = pubkey_hash})
  node.type = compute_type(node)
  return node
end

function M.older(n)
  assert(type(n) == "number" and n >= 1 and n < 0x80000000, "older value out of range")
  local node = make_node(F.OLDER, {k = n})
  node.type = compute_type(node)
  return node
end

function M.after(n)
  assert(type(n) == "number" and n >= 1 and n < 0x80000000, "after value out of range")
  local node = make_node(F.AFTER, {k = n})
  node.type = compute_type(node)
  return node
end

function M.sha256(hash)
  assert(type(hash) == "string" and #hash == 32, "sha256 hash must be 32 bytes")
  local node = make_node(F.SHA256, {data = hash})
  node.type = compute_type(node)
  return node
end

function M.hash256(hash)
  assert(type(hash) == "string" and #hash == 32, "hash256 hash must be 32 bytes")
  local node = make_node(F.HASH256, {data = hash})
  node.type = compute_type(node)
  return node
end

function M.ripemd160(hash)
  assert(type(hash) == "string" and #hash == 20, "ripemd160 hash must be 20 bytes")
  local node = make_node(F.RIPEMD160, {data = hash})
  node.type = compute_type(node)
  return node
end

function M.hash160(hash)
  assert(type(hash) == "string" and #hash == 20, "hash160 hash must be 20 bytes")
  local node = make_node(F.HASH160, {data = hash})
  node.type = compute_type(node)
  return node
end

-- Wrappers
function M.wrap_a(sub)
  local node = make_node(F.WRAP_A, {subs = {sub}})
  node.type = compute_type(node)
  assert(node.type, "wrap_a requires B-type subexpression")
  return node
end

function M.wrap_s(sub)
  local node = make_node(F.WRAP_S, {subs = {sub}})
  node.type = compute_type(node)
  assert(node.type, "wrap_s requires Bo-type subexpression")
  return node
end

function M.wrap_c(sub)
  local node = make_node(F.WRAP_C, {subs = {sub}})
  node.type = compute_type(node)
  assert(node.type, "wrap_c requires K-type subexpression")
  return node
end

function M.wrap_d(sub)
  local node = make_node(F.WRAP_D, {subs = {sub}})
  node.type = compute_type(node)
  assert(node.type, "wrap_d requires Vz-type subexpression")
  return node
end

function M.wrap_v(sub)
  local node = make_node(F.WRAP_V, {subs = {sub}})
  node.type = compute_type(node)
  assert(node.type, "wrap_v requires B-type subexpression")
  return node
end

function M.wrap_j(sub)
  local node = make_node(F.WRAP_J, {subs = {sub}})
  node.type = compute_type(node)
  assert(node.type, "wrap_j requires Bn-type subexpression")
  return node
end

function M.wrap_n(sub)
  local node = make_node(F.WRAP_N, {subs = {sub}})
  node.type = compute_type(node)
  assert(node.type, "wrap_n requires B-type subexpression")
  return node
end

-- Binary combinators
function M.and_v(x, y)
  local node = make_node(F.AND_V, {subs = {x, y}})
  node.type = compute_type(node)
  assert(node.type, "and_v requires V and B/K/V subexpressions")
  return node
end

function M.and_b(x, y)
  local node = make_node(F.AND_B, {subs = {x, y}})
  node.type = compute_type(node)
  assert(node.type, "and_b requires B and W subexpressions")
  return node
end

function M.or_b(x, y)
  local node = make_node(F.OR_B, {subs = {x, y}})
  node.type = compute_type(node)
  assert(node.type, "or_b requires Bd and Wd subexpressions")
  return node
end

function M.or_c(x, y)
  local node = make_node(F.OR_C, {subs = {x, y}})
  node.type = compute_type(node)
  assert(node.type, "or_c requires Bdu and V subexpressions")
  return node
end

function M.or_d(x, y)
  local node = make_node(F.OR_D, {subs = {x, y}})
  node.type = compute_type(node)
  assert(node.type, "or_d requires Bdu and B subexpressions")
  return node
end

function M.or_i(x, y)
  local node = make_node(F.OR_I, {subs = {x, y}})
  node.type = compute_type(node)
  assert(node.type, "or_i requires matching base type subexpressions")
  return node
end

-- Ternary combinator
function M.andor(x, y, z)
  local node = make_node(F.ANDOR, {subs = {x, y, z}})
  node.type = compute_type(node)
  assert(node.type, "andor requires Bdu, and matching base types for Y/Z")
  return node
end

-- Multi-signature
function M.multi(k, keys)
  assert(type(k) == "number" and k >= 1 and k <= #keys, "k must be 1 <= k <= n")
  assert(#keys >= 1 and #keys <= 20, "must have 1-20 keys")
  local node = make_node(F.MULTI, {k = k, keys = keys})
  node.type = compute_type(node)
  return node
end

function M.multi_a(k, keys)
  assert(type(k) == "number" and k >= 1 and k <= #keys, "k must be 1 <= k <= n")
  assert(#keys >= 1, "must have at least 1 key")
  local node = make_node(F.MULTI_A, {k = k, keys = keys, tapscript = true})
  node.type = compute_type(node)
  return node
end

-- Threshold
function M.thresh(k, subs)
  assert(type(k) == "number" and k >= 1 and k <= #subs, "k must be 1 <= k <= n")
  local node = make_node(F.THRESH, {k = k, subs = subs})
  node.type = compute_type(node)
  assert(node.type, "thresh requires Bdu subexpressions")
  return node
end

-- Syntactic sugar
function M.and_n(x, y)
  -- AND_N(X,Y) = ANDOR(X, Y, 0)
  return M.andor(x, y, M.just_0())
end

function M.pk(pubkey)
  -- pk(K) = c:pk_k(K)
  return M.wrap_c(M.pk_k(pubkey))
end

function M.pkh(pubkey_hash)
  -- pkh(H) = c:pk_h(H)
  return M.wrap_c(M.pk_h(pubkey_hash))
end

--------------------------------------------------------------------------------
-- Script compilation
--------------------------------------------------------------------------------

-- Helper to build script number pushes
local function push_script_num(n)
  if n == 0 then
    return "\x00"  -- OP_0
  elseif n >= 1 and n <= 16 then
    return string.char(0x50 + n)  -- OP_1 through OP_16
  elseif n == -1 then
    return "\x4f"  -- OP_1NEGATE
  else
    local bytes = script.script_num_encode(n)
    if #bytes <= 0x4b then
      return string.char(#bytes) .. bytes
    else
      error("number too large for minimal push")
    end
  end
end

-- Helper to push arbitrary data
local function push_data(data)
  local len = #data
  if len == 0 then
    return "\x00"  -- OP_0
  elseif len <= 0x4b then
    return string.char(len) .. data
  elseif len <= 0xff then
    return "\x4c" .. string.char(len) .. data
  elseif len <= 0xffff then
    return "\x4d" .. string.char(len % 256) .. string.char(math.floor(len / 256)) .. data
  else
    error("data too large")
  end
end

local OP = script.OP

-- Convert miniscript node to Bitcoin Script
-- followed_by_verify: true if the result will be followed by OP_VERIFY (for -VERIFY optimization)
local function to_script(node, followed_by_verify)
  local frag = node.fragment

  if frag == F.JUST_0 then
    return "\x00"  -- OP_0

  elseif frag == F.JUST_1 then
    return "\x51"  -- OP_1

  elseif frag == F.PK_K then
    -- Just push the pubkey
    return push_data(node.keys[1])

  elseif frag == F.PK_H then
    -- OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY
    return "\x76\xa9" .. push_data(node.data) .. "\x88"

  elseif frag == F.OLDER then
    -- <n> OP_CHECKSEQUENCEVERIFY
    return push_script_num(node.k) .. "\xb2"

  elseif frag == F.AFTER then
    -- <n> OP_CHECKLOCKTIMEVERIFY
    return push_script_num(node.k) .. "\xb1"

  elseif frag == F.SHA256 then
    -- OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUAL
    local s = "\x82\x01\x20\x88\xa8" .. push_data(node.data) .. "\x87"
    return s

  elseif frag == F.HASH256 then
    -- OP_SIZE <32> OP_EQUALVERIFY OP_HASH256 <hash> OP_EQUAL
    local s = "\x82\x01\x20\x88\xaa" .. push_data(node.data) .. "\x87"
    return s

  elseif frag == F.RIPEMD160 then
    -- OP_SIZE <20> OP_EQUALVERIFY OP_RIPEMD160 <hash> OP_EQUAL
    local s = "\x82\x01\x14\x88\xa6" .. push_data(node.data) .. "\x87"
    return s

  elseif frag == F.HASH160 then
    -- OP_SIZE <20> OP_EQUALVERIFY OP_HASH160 <hash> OP_EQUAL
    local s = "\x82\x01\x14\x88\xa9" .. push_data(node.data) .. "\x87"
    return s

  elseif frag == F.WRAP_A then
    -- OP_TOALTSTACK [X] OP_FROMALTSTACK
    return "\x6b" .. to_script(node.subs[1], false) .. "\x6c"

  elseif frag == F.WRAP_S then
    -- OP_SWAP [X]
    return "\x7c" .. to_script(node.subs[1], followed_by_verify)

  elseif frag == F.WRAP_C then
    -- [X] OP_CHECKSIG or OP_CHECKSIGVERIFY
    local sub_script = to_script(node.subs[1], false)
    if followed_by_verify then
      return sub_script .. "\xad"  -- OP_CHECKSIGVERIFY
    else
      return sub_script .. "\xac"  -- OP_CHECKSIG
    end

  elseif frag == F.WRAP_D then
    -- OP_DUP OP_IF [X] OP_ENDIF
    return "\x76\x63" .. to_script(node.subs[1], false) .. "\x68"

  elseif frag == F.WRAP_V then
    local sub = node.subs[1]
    local sub_script = to_script(sub, true)
    -- If sub ends with OP_CHECKSIG, convert to OP_CHECKSIGVERIFY
    -- If sub ends with OP_CHECKMULTISIG, convert to OP_CHECKMULTISIGVERIFY
    -- If sub ends with OP_EQUAL, convert to OP_EQUALVERIFY
    -- Otherwise add OP_VERIFY
    local last = sub_script:byte(#sub_script)
    if last == 0xac then  -- OP_CHECKSIG -> OP_CHECKSIGVERIFY
      return sub_script:sub(1, -2) .. "\xad"
    elseif last == 0xae then  -- OP_CHECKMULTISIG -> OP_CHECKMULTISIGVERIFY
      return sub_script:sub(1, -2) .. "\xaf"
    elseif last == 0x87 then  -- OP_EQUAL -> OP_EQUALVERIFY
      return sub_script:sub(1, -2) .. "\x88"
    elseif last == 0x9c then  -- OP_NUMEQUAL -> OP_NUMEQUALVERIFY
      return sub_script:sub(1, -2) .. "\x9d"
    else
      -- Can't convert, add explicit VERIFY
      return sub_script .. "\x69"
    end

  elseif frag == F.WRAP_J then
    -- OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF
    return "\x82\x92\x63" .. to_script(node.subs[1], false) .. "\x68"

  elseif frag == F.WRAP_N then
    -- [X] OP_0NOTEQUAL
    return to_script(node.subs[1], false) .. "\x92"

  elseif frag == F.AND_V then
    -- [X] [Y]
    local x_script = to_script(node.subs[1], false)
    local y_script = to_script(node.subs[2], followed_by_verify)
    return x_script .. y_script

  elseif frag == F.AND_B then
    -- [X] [Y] OP_BOOLAND
    return to_script(node.subs[1], false) .. to_script(node.subs[2], false) .. "\x9a"

  elseif frag == F.OR_B then
    -- [X] [Y] OP_BOOLOR
    return to_script(node.subs[1], false) .. to_script(node.subs[2], false) .. "\x9b"

  elseif frag == F.OR_C then
    -- [X] OP_NOTIF [Y] OP_ENDIF
    return to_script(node.subs[1], false) .. "\x64" .. to_script(node.subs[2], followed_by_verify) .. "\x68"

  elseif frag == F.OR_D then
    -- [X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF
    return to_script(node.subs[1], false) .. "\x73\x64" .. to_script(node.subs[2], followed_by_verify) .. "\x68"

  elseif frag == F.OR_I then
    -- OP_IF [X] OP_ELSE [Y] OP_ENDIF
    return "\x63" .. to_script(node.subs[1], followed_by_verify) .. "\x67" ..
           to_script(node.subs[2], followed_by_verify) .. "\x68"

  elseif frag == F.ANDOR then
    -- [X] OP_NOTIF [Z] OP_ELSE [Y] OP_ENDIF
    return to_script(node.subs[1], false) .. "\x64" ..
           to_script(node.subs[3], followed_by_verify) .. "\x67" ..
           to_script(node.subs[2], followed_by_verify) .. "\x68"

  elseif frag == F.THRESH then
    -- [X1] ([Xi] OP_ADD)* <k> OP_EQUAL
    local parts = {to_script(node.subs[1], false)}
    for i = 2, #node.subs do
      parts[#parts + 1] = to_script(node.subs[i], false)
      parts[#parts + 1] = "\x93"  -- OP_ADD
    end
    parts[#parts + 1] = push_script_num(node.k)
    if followed_by_verify then
      parts[#parts + 1] = "\x88"  -- OP_EQUALVERIFY
    else
      parts[#parts + 1] = "\x87"  -- OP_EQUAL
    end
    return table.concat(parts)

  elseif frag == F.MULTI then
    -- <k> <key1> ... <keyn> <n> OP_CHECKMULTISIG
    local parts = {push_script_num(node.k)}
    for _, key in ipairs(node.keys) do
      parts[#parts + 1] = push_data(key)
    end
    parts[#parts + 1] = push_script_num(#node.keys)
    if followed_by_verify then
      parts[#parts + 1] = "\xaf"  -- OP_CHECKMULTISIGVERIFY
    else
      parts[#parts + 1] = "\xae"  -- OP_CHECKMULTISIG
    end
    return table.concat(parts)

  elseif frag == F.MULTI_A then
    -- <key0> OP_CHECKSIG (<keyi> OP_CHECKSIGADD)* <k> OP_NUMEQUAL
    local parts = {push_data(node.keys[1]), "\xac"}  -- first key + OP_CHECKSIG
    for i = 2, #node.keys do
      parts[#parts + 1] = push_data(node.keys[i])
      parts[#parts + 1] = "\xba"  -- OP_CHECKSIGADD
    end
    parts[#parts + 1] = push_script_num(node.k)
    if followed_by_verify then
      parts[#parts + 1] = "\x9d"  -- OP_NUMEQUALVERIFY
    else
      parts[#parts + 1] = "\x9c"  -- OP_NUMEQUAL
    end
    return table.concat(parts)
  end

  error("unknown fragment: " .. tostring(frag))
end

function M.to_script(node)
  return to_script(node, false)
end

--------------------------------------------------------------------------------
-- Satisfaction generation
--------------------------------------------------------------------------------

-- InputStack represents a witness stack with metadata
local function make_input_stack(opts)
  opts = opts or {}
  return {
    available = opts.available or "YES",  -- YES, NO, MAYBE
    has_sig = opts.has_sig or false,
    malleable = opts.malleable or false,
    non_canon = opts.non_canon or false,
    size = opts.size or 0,
    stack = opts.stack or {},
  }
end

-- Empty stack (used for satisfaction that doesn't need witness items)
local EMPTY = make_input_stack({available = "YES", size = 0, stack = {}})

-- Invalid stack (cannot satisfy)
local INVALID = make_input_stack({available = "NO", size = 0, stack = {}})

-- Concatenate two input stacks
local function concat_stacks(a, b)
  if a.available == "NO" or b.available == "NO" then
    return INVALID
  end
  local new_stack = {}
  for _, item in ipairs(a.stack) do
    new_stack[#new_stack + 1] = item
  end
  for _, item in ipairs(b.stack) do
    new_stack[#new_stack + 1] = item
  end
  return make_input_stack({
    available = (a.available == "YES" and b.available == "YES") and "YES" or "MAYBE",
    has_sig = a.has_sig or b.has_sig,
    malleable = a.malleable or b.malleable,
    non_canon = a.non_canon or b.non_canon,
    size = a.size + b.size,
    stack = new_stack,
  })
end

-- Choose the better of two input stacks
-- For satisfaction: prefer smaller non-malleable stack
-- For dissatisfaction: prefer larger (for adversarial analysis) or smaller depending on context
local function choose_stack(a, b, prefer_smaller)
  if a.available == "NO" then return b end
  if b.available == "NO" then return a end

  -- Prefer non-malleable
  if a.malleable and not b.malleable then return b end
  if b.malleable and not a.malleable then return a end

  -- Prefer canonical
  if a.non_canon and not b.non_canon then return b end
  if b.non_canon and not a.non_canon then return a end

  -- Prefer YES over MAYBE
  if a.available == "YES" and b.available == "MAYBE" then return a end
  if b.available == "YES" and a.available == "MAYBE" then return b end

  -- Prefer smaller/larger based on context
  if prefer_smaller then
    return a.size <= b.size and a or b
  else
    return a.size >= b.size and a or b
  end
end

-- Generate satisfaction/dissatisfaction for a node
-- key_lookup: function(pubkey) -> signature or nil
-- preimage_lookup: function(hash) -> preimage or nil
-- ctx: {locktime, sequence, ...} for timelock validation
local function produce_input(node, key_lookup, preimage_lookup, ctx)
  local frag = node.fragment
  ctx = ctx or {}

  local function sig_input(pubkey)
    local sig = key_lookup and key_lookup(pubkey)
    if sig then
      return make_input_stack({
        available = "YES",
        has_sig = true,
        size = #sig,
        stack = {sig},
      })
    else
      return make_input_stack({available = "MAYBE", has_sig = true, size = 65, stack = {""}})
    end
  end

  local function preimage_input(hash, size)
    local preimage = preimage_lookup and preimage_lookup(hash)
    if preimage then
      return make_input_stack({
        available = "YES",
        size = #preimage,
        stack = {preimage},
      })
    else
      return make_input_stack({available = "MAYBE", size = size, stack = {string.rep("\x00", size)}})
    end
  end

  if frag == F.JUST_0 then
    return {sat = INVALID, nsat = EMPTY}

  elseif frag == F.JUST_1 then
    return {sat = EMPTY, nsat = INVALID}

  elseif frag == F.PK_K then
    local sig = sig_input(node.keys[1])
    return {
      sat = sig,
      nsat = make_input_stack({available = "YES", size = 0, stack = {""}}),
    }

  elseif frag == F.PK_H then
    -- Need pubkey + signature
    -- Dissatisfaction: need pubkey + empty sig
    local sig = key_lookup and key_lookup(node.data .. "_pkh")
    local pubkey = ctx.pubkey_for_hash and ctx.pubkey_for_hash(node.data)
    if sig and pubkey then
      return {
        sat = make_input_stack({
          available = "YES", has_sig = true,
          size = #sig + #pubkey,
          stack = {sig, pubkey},
        }),
        nsat = pubkey and make_input_stack({
          available = "YES", size = #pubkey,
          stack = {"", pubkey},
        }) or INVALID,
      }
    else
      return {
        sat = make_input_stack({available = "MAYBE", has_sig = true, size = 66 + 33, stack = {"", ""}}),
        nsat = make_input_stack({available = "MAYBE", size = 33, stack = {"", ""}}),
      }
    end

  elseif frag == F.OLDER then
    -- Check sequence
    if ctx.sequence and ctx.sequence >= node.k then
      return {sat = EMPTY, nsat = INVALID}
    else
      return {sat = INVALID, nsat = INVALID}
    end

  elseif frag == F.AFTER then
    -- Check locktime
    if ctx.locktime and ctx.locktime >= node.k then
      return {sat = EMPTY, nsat = INVALID}
    else
      return {sat = INVALID, nsat = INVALID}
    end

  elseif frag == F.SHA256 or frag == F.HASH256 then
    local preimage = preimage_input(node.data, 32)
    return {
      sat = preimage,
      nsat = make_input_stack({available = "YES", malleable = true, size = 32, stack = {string.rep("\x00", 32)}}),
    }

  elseif frag == F.RIPEMD160 or frag == F.HASH160 then
    local preimage = preimage_input(node.data, 20)
    return {
      sat = preimage,
      nsat = make_input_stack({available = "YES", malleable = true, size = 20, stack = {string.rep("\x00", 20)}}),
    }

  elseif frag == F.WRAP_A or frag == F.WRAP_S or frag == F.WRAP_N then
    -- Pass through
    return produce_input(node.subs[1], key_lookup, preimage_lookup, ctx)

  elseif frag == F.WRAP_C then
    return produce_input(node.subs[1], key_lookup, preimage_lookup, ctx)

  elseif frag == F.WRAP_D then
    local sub = produce_input(node.subs[1], key_lookup, preimage_lookup, ctx)
    -- Satisfaction: 1 + sub.sat (take the if branch)
    -- Dissatisfaction: 0 (don't take the if branch)
    local sat = concat_stacks(sub.sat, make_input_stack({size = 1, stack = {"\x01"}}))
    return {
      sat = sat,
      nsat = make_input_stack({available = "YES", size = 0, stack = {""}}),
    }

  elseif frag == F.WRAP_V then
    local sub = produce_input(node.subs[1], key_lookup, preimage_lookup, ctx)
    return {sat = sub.sat, nsat = INVALID}

  elseif frag == F.WRAP_J then
    local sub = produce_input(node.subs[1], key_lookup, preimage_lookup, ctx)
    -- Dissatisfaction with j wrapper: just push 0 (size check fails, goes to endif)
    local nsat = sub.nsat
    if nsat.available ~= "NO" then
      -- Mark as potentially malleable since attacker could use sub's dissatisfaction
      nsat = make_input_stack({available = "YES", malleable = true, size = 0, stack = {""}})
    else
      nsat = make_input_stack({available = "YES", size = 0, stack = {""}})
    end
    return {sat = sub.sat, nsat = nsat}

  elseif frag == F.AND_V then
    local x = produce_input(node.subs[1], key_lookup, preimage_lookup, ctx)
    local y = produce_input(node.subs[2], key_lookup, preimage_lookup, ctx)
    local sat = concat_stacks(x.sat, y.sat)
    -- Dissatisfaction: satisfy x, dissatisfy y (non-canonical since x was satisfied)
    local nsat = concat_stacks(x.sat, y.nsat)
    if nsat.available ~= "NO" then
      nsat.non_canon = true
    end
    return {sat = sat, nsat = nsat}

  elseif frag == F.AND_B then
    local x = produce_input(node.subs[1], key_lookup, preimage_lookup, ctx)
    local y = produce_input(node.subs[2], key_lookup, preimage_lookup, ctx)
    local sat = concat_stacks(x.sat, y.sat)
    -- Dissatisfaction: any combination that makes BOOLAND return false
    local nsat1 = concat_stacks(x.nsat, y.nsat)
    local nsat2 = concat_stacks(x.sat, y.nsat)
    local nsat3 = concat_stacks(x.nsat, y.sat)
    nsat2.malleable = true
    nsat3.malleable = true
    local nsat = choose_stack(choose_stack(nsat1, nsat2, true), nsat3, true)
    return {sat = sat, nsat = nsat}

  elseif frag == F.OR_B then
    local x = produce_input(node.subs[1], key_lookup, preimage_lookup, ctx)
    local y = produce_input(node.subs[2], key_lookup, preimage_lookup, ctx)
    -- Satisfaction: either branch succeeds
    local sat1 = concat_stacks(x.sat, y.nsat)
    local sat2 = concat_stacks(x.nsat, y.sat)
    local sat3 = concat_stacks(x.sat, y.sat)
    sat3.malleable = true
    local sat = choose_stack(choose_stack(sat1, sat2, true), sat3, true)
    -- Dissatisfaction: both fail
    local nsat = concat_stacks(x.nsat, y.nsat)
    return {sat = sat, nsat = nsat}

  elseif frag == F.OR_C then
    local x = produce_input(node.subs[1], key_lookup, preimage_lookup, ctx)
    local y = produce_input(node.subs[2], key_lookup, preimage_lookup, ctx)
    -- Satisfaction: x succeeds, or x fails and y succeeds
    local sat1 = x.sat
    local sat2 = concat_stacks(x.nsat, y.sat)
    local sat = choose_stack(sat1, sat2, true)
    return {sat = sat, nsat = INVALID}

  elseif frag == F.OR_D then
    local x = produce_input(node.subs[1], key_lookup, preimage_lookup, ctx)
    local y = produce_input(node.subs[2], key_lookup, preimage_lookup, ctx)
    -- Satisfaction: x succeeds, or x fails and y succeeds
    local sat1 = x.sat
    local sat2 = concat_stacks(x.nsat, y.sat)
    local sat = choose_stack(sat1, sat2, true)
    -- Dissatisfaction: x fails and y fails
    local nsat = concat_stacks(x.nsat, y.nsat)
    return {sat = sat, nsat = nsat}

  elseif frag == F.OR_I then
    local x = produce_input(node.subs[1], key_lookup, preimage_lookup, ctx)
    local y = produce_input(node.subs[2], key_lookup, preimage_lookup, ctx)
    -- Satisfaction: pick the branch with better satisfaction
    local sat1 = concat_stacks(x.sat, make_input_stack({size = 1, stack = {"\x01"}}))
    local sat2 = concat_stacks(y.sat, make_input_stack({size = 0, stack = {""}}))
    local sat = choose_stack(sat1, sat2, true)
    -- Dissatisfaction: pick either branch's dissatisfaction
    local nsat1 = concat_stacks(x.nsat, make_input_stack({size = 1, stack = {"\x01"}}))
    local nsat2 = concat_stacks(y.nsat, make_input_stack({size = 0, stack = {""}}))
    local nsat = choose_stack(nsat1, nsat2, true)
    return {sat = sat, nsat = nsat}

  elseif frag == F.ANDOR then
    local x = produce_input(node.subs[1], key_lookup, preimage_lookup, ctx)
    local y = produce_input(node.subs[2], key_lookup, preimage_lookup, ctx)
    local z = produce_input(node.subs[3], key_lookup, preimage_lookup, ctx)
    -- Satisfaction: x+y or not(x)+z
    local sat1 = concat_stacks(x.sat, y.sat)
    local sat2 = concat_stacks(x.nsat, z.sat)
    local sat = choose_stack(sat1, sat2, true)
    -- Dissatisfaction: x+not(y) (non-canonical) or not(x)+not(z)
    local nsat1 = concat_stacks(x.sat, y.nsat)
    if nsat1.available ~= "NO" then nsat1.non_canon = true end
    local nsat2 = concat_stacks(x.nsat, z.nsat)
    local nsat = choose_stack(nsat1, nsat2, true)
    return {sat = sat, nsat = nsat}

  elseif frag == F.THRESH then
    -- Dynamic programming for threshold
    local n = #node.subs
    local k = node.k
    local sub_results = {}
    for i, sub in ipairs(node.subs) do
      sub_results[i] = produce_input(sub, key_lookup, preimage_lookup, ctx)
    end

    -- sats[j] = best stack for exactly j satisfactions
    local sats = {}
    sats[0] = EMPTY
    for i = 1, n do
      local new_sats = {}
      for j = 0, math.min(i, k) do
        local candidates = {}
        -- Don't satisfy sub[i]: carry forward sats[j]
        if sats[j] and sats[j].available ~= "NO" then
          candidates[#candidates + 1] = concat_stacks(sats[j], sub_results[i].nsat)
        end
        -- Satisfy sub[i]: use sats[j-1] + sub[i].sat
        if j > 0 and sats[j-1] and sats[j-1].available ~= "NO" then
          candidates[#candidates + 1] = concat_stacks(sats[j-1], sub_results[i].sat)
        end
        new_sats[j] = candidates[1] or INVALID
        for c = 2, #candidates do
          new_sats[j] = choose_stack(new_sats[j], candidates[c], true)
        end
      end
      sats = new_sats
    end

    local sat = sats[k] or INVALID
    -- For dissatisfaction: any count != k
    local nsat = sats[0] or INVALID
    for j = 1, n do
      if j ~= k and sats[j] then
        nsat = choose_stack(nsat, sats[j], true)
      end
    end
    return {sat = sat, nsat = nsat}

  elseif frag == F.MULTI then
    local k = node.k
    local n = #node.keys

    -- Collect signatures for available keys
    local sigs = {}
    for i, key in ipairs(node.keys) do
      local sig = key_lookup and key_lookup(key)
      if sig then
        sigs[#sigs + 1] = {idx = i, sig = sig}
      end
    end

    if #sigs >= k then
      -- Build satisfaction with first k signatures (in order)
      table.sort(sigs, function(a, b) return a.idx < b.idx end)
      local stack = {""}  -- Dummy element first
      for i = 1, k do
        stack[#stack + 1] = sigs[i].sig
      end
      return {
        sat = make_input_stack({available = "YES", has_sig = true, size = k * 65 + 1, stack = stack}),
        nsat = make_input_stack({available = "YES", size = n + 1, stack = {string.rep("", n + 1)}}),
      }
    else
      -- Can't satisfy yet
      return {
        sat = make_input_stack({available = "MAYBE", has_sig = true, size = k * 65 + 1, stack = {}}),
        nsat = make_input_stack({available = "YES", size = n + 1, stack = {string.rep("", n + 1)}}),
      }
    end

  elseif frag == F.MULTI_A then
    local k = node.k
    local n = #node.keys

    -- Collect signatures for available keys
    local stack = {}
    local count = 0
    for i = n, 1, -1 do
      local sig = key_lookup and key_lookup(node.keys[i])
      if sig and count < k then
        stack[#stack + 1] = sig
        count = count + 1
      else
        stack[#stack + 1] = ""  -- Empty sig for non-participating key
      end
    end

    if count >= k then
      return {
        sat = make_input_stack({available = "YES", has_sig = true, size = k * 64, stack = stack}),
        nsat = make_input_stack({available = "YES", size = 0, stack = {string.rep("", n)}}),
      }
    else
      return {
        sat = make_input_stack({available = "MAYBE", has_sig = true, size = k * 64, stack = stack}),
        nsat = make_input_stack({available = "YES", size = 0, stack = {string.rep("", n)}}),
      }
    end
  end

  return {sat = INVALID, nsat = INVALID}
end

function M.satisfy(node, key_lookup, preimage_lookup, ctx)
  local result = produce_input(node, key_lookup, preimage_lookup, ctx)
  if result.sat.available == "NO" then
    return nil, "cannot satisfy"
  end
  return result.sat.stack
end

function M.get_satisfaction_size(node, key_lookup, preimage_lookup, ctx)
  local result = produce_input(node, key_lookup, preimage_lookup, ctx)
  return result.sat.size
end

--------------------------------------------------------------------------------
-- Policy language parser
-- Parses high-level policy like: and(pk(A),or(pk(B),older(1000)))
--------------------------------------------------------------------------------

local function hex_to_bin(hex)
  return (hex:gsub('..', function(cc)
    return string.char(tonumber(cc, 16))
  end))
end

-- Parse a policy string and compile to miniscript
function M.from_policy(policy_str, key_map)
  key_map = key_map or {}
  local pos = 1

  local function peek()
    return policy_str:sub(pos, pos)
  end

  local function advance()
    pos = pos + 1
  end

  local function skip_ws()
    while peek():match("%s") do advance() end
  end

  local function expect(ch)
    skip_ws()
    if peek() ~= ch then
      error("expected '" .. ch .. "' at position " .. pos .. ", got '" .. peek() .. "'")
    end
    advance()
  end

  local function read_ident()
    skip_ws()
    local start = pos
    while pos <= #policy_str and policy_str:sub(pos, pos):match("[%w_]") do
      pos = pos + 1
    end
    return policy_str:sub(start, pos - 1)
  end

  local function read_number()
    skip_ws()
    local start = pos
    while pos <= #policy_str and policy_str:sub(pos, pos):match("%d") do
      pos = pos + 1
    end
    return tonumber(policy_str:sub(start, pos - 1))
  end

  local function read_hex()
    skip_ws()
    local start = pos
    while pos <= #policy_str and policy_str:sub(pos, pos):match("[%da-fA-F]") do
      pos = pos + 1
    end
    return policy_str:sub(start, pos - 1)
  end

  local function read_key()
    skip_ws()
    -- Key can be: hex pubkey, or identifier that maps to a key
    local ch = peek()
    if ch:match("[%da-fA-F]") then
      local hex = read_hex()
      return hex_to_bin(hex)
    else
      local name = read_ident()
      local key = key_map[name]
      if not key then
        error("unknown key: " .. name)
      end
      return key
    end
  end

  local parse_expr  -- forward declaration

  local function parse_wrappers_and_expr()
    skip_ws()
    -- Check for wrapper prefix: a:, s:, c:, d:, v:, j:, n:, t:, l:, u:
    local wrappers = {}
    while true do
      local saved_pos = pos
      local ch = peek()
      if ch:match("[asdcvjntlu]") then
        advance()
        if peek() == ":" then
          advance()
          wrappers[#wrappers + 1] = ch
        else
          -- Not a wrapper, backtrack
          pos = saved_pos
          break
        end
      else
        break
      end
    end

    local node = parse_expr()

    -- Apply wrappers in reverse order
    for i = #wrappers, 1, -1 do
      local w = wrappers[i]
      if w == "a" then
        node = M.wrap_a(node)
      elseif w == "s" then
        node = M.wrap_s(node)
      elseif w == "c" then
        node = M.wrap_c(node)
      elseif w == "d" then
        node = M.wrap_d(node)
      elseif w == "v" then
        node = M.wrap_v(node)
      elseif w == "j" then
        node = M.wrap_j(node)
      elseif w == "n" then
        node = M.wrap_n(node)
      elseif w == "t" then
        -- t: = and_v(X, 1)
        node = M.and_v(node, M.just_1())
      elseif w == "l" then
        -- l: = or_i(0, X)
        node = M.or_i(M.just_0(), node)
      elseif w == "u" then
        -- u: = or_i(X, 0)
        node = M.or_i(node, M.just_0())
      end
    end

    return node
  end

  parse_expr = function()
    skip_ws()

    -- Check for "0" or "1"
    local ch = peek()
    if ch == "0" then
      advance()
      return M.just_0()
    elseif ch == "1" then
      advance()
      return M.just_1()
    end

    local name = read_ident()

    if name == "pk" then
      expect("(")
      local key = read_key()
      expect(")")
      return M.pk(key)

    elseif name == "pkh" then
      expect("(")
      local key = read_key()
      expect(")")
      -- Compute hash if full pubkey given
      local hash
      if #key == 33 or #key == 65 then
        hash = crypto.hash160(key)
      elseif #key == 20 then
        hash = key
      else
        error("invalid pkh key length")
      end
      return M.pkh(hash)

    elseif name == "pk_k" then
      expect("(")
      local key = read_key()
      expect(")")
      return M.pk_k(key)

    elseif name == "pk_h" then
      expect("(")
      local key = read_key()
      expect(")")
      local hash
      if #key == 33 or #key == 65 then
        hash = crypto.hash160(key)
      elseif #key == 20 then
        hash = key
      else
        error("invalid pk_h key length")
      end
      return M.pk_h(hash)

    elseif name == "older" then
      expect("(")
      local n = read_number()
      expect(")")
      return M.older(n)

    elseif name == "after" then
      expect("(")
      local n = read_number()
      expect(")")
      return M.after(n)

    elseif name == "sha256" then
      expect("(")
      local hex = read_hex()
      expect(")")
      return M.sha256(hex_to_bin(hex))

    elseif name == "hash256" then
      expect("(")
      local hex = read_hex()
      expect(")")
      return M.hash256(hex_to_bin(hex))

    elseif name == "ripemd160" then
      expect("(")
      local hex = read_hex()
      expect(")")
      return M.ripemd160(hex_to_bin(hex))

    elseif name == "hash160" then
      expect("(")
      local hex = read_hex()
      expect(")")
      return M.hash160(hex_to_bin(hex))

    elseif name == "and_v" then
      expect("(")
      local x = parse_wrappers_and_expr()
      expect(",")
      local y = parse_wrappers_and_expr()
      expect(")")
      return M.and_v(x, y)

    elseif name == "and_b" then
      expect("(")
      local x = parse_wrappers_and_expr()
      expect(",")
      local y = parse_wrappers_and_expr()
      expect(")")
      return M.and_b(x, y)

    elseif name == "and_n" then
      expect("(")
      local x = parse_wrappers_and_expr()
      expect(",")
      local y = parse_wrappers_and_expr()
      expect(")")
      return M.and_n(x, y)

    elseif name == "or_b" then
      expect("(")
      local x = parse_wrappers_and_expr()
      expect(",")
      local y = parse_wrappers_and_expr()
      expect(")")
      return M.or_b(x, y)

    elseif name == "or_c" then
      expect("(")
      local x = parse_wrappers_and_expr()
      expect(",")
      local y = parse_wrappers_and_expr()
      expect(")")
      return M.or_c(x, y)

    elseif name == "or_d" then
      expect("(")
      local x = parse_wrappers_and_expr()
      expect(",")
      local y = parse_wrappers_and_expr()
      expect(")")
      return M.or_d(x, y)

    elseif name == "or_i" then
      expect("(")
      local x = parse_wrappers_and_expr()
      expect(",")
      local y = parse_wrappers_and_expr()
      expect(")")
      return M.or_i(x, y)

    elseif name == "andor" then
      expect("(")
      local x = parse_wrappers_and_expr()
      expect(",")
      local y = parse_wrappers_and_expr()
      expect(",")
      local z = parse_wrappers_and_expr()
      expect(")")
      return M.andor(x, y, z)

    elseif name == "thresh" then
      expect("(")
      local k = read_number()
      local subs = {}
      while true do
        expect(",")
        subs[#subs + 1] = parse_wrappers_and_expr()
        skip_ws()
        if peek() == ")" then break end
      end
      expect(")")
      return M.thresh(k, subs)

    elseif name == "multi" then
      expect("(")
      local k = read_number()
      local keys = {}
      while true do
        expect(",")
        keys[#keys + 1] = read_key()
        skip_ws()
        if peek() == ")" then break end
      end
      expect(")")
      return M.multi(k, keys)

    elseif name == "multi_a" then
      expect("(")
      local k = read_number()
      local keys = {}
      while true do
        expect(",")
        keys[#keys + 1] = read_key()
        skip_ws()
        if peek() == ")" then break end
      end
      expect(")")
      return M.multi_a(k, keys)

    -- High-level policy: and, or
    elseif name == "and" then
      expect("(")
      local x = parse_wrappers_and_expr()
      expect(",")
      local y = parse_wrappers_and_expr()
      expect(")")
      -- Compile to and_v(X, Y) with appropriate wrappers
      -- Need to wrap x as V and y as B
      if has(x.type, T.B) then
        x = M.wrap_v(x)
      end
      return M.and_v(x, y)

    elseif name == "or" then
      expect("(")
      local x = parse_wrappers_and_expr()
      expect(",")
      local y = parse_wrappers_and_expr()
      expect(")")
      -- Choose optimal or variant based on types
      -- Simple strategy: use or_d if x is Bdu
      if has(x.type, T.B) and has(x.type, T.d) and has(x.type, T.u) then
        return M.or_d(x, y)
      elseif has(x.type, T.B) and has(x.type, T.d) then
        -- Try or_i
        return M.or_i(x, y)
      else
        return M.or_i(x, y)
      end

    else
      error("unknown policy function: " .. name)
    end
  end

  local node = parse_wrappers_and_expr()
  skip_ws()
  if pos <= #policy_str then
    error("unexpected character at position " .. pos)
  end
  return node
end

--------------------------------------------------------------------------------
-- Type analysis helpers
--------------------------------------------------------------------------------

function M.type_string(t)
  local parts = {}
  if has(t, T.B) then parts[#parts + 1] = "B" end
  if has(t, T.V) then parts[#parts + 1] = "V" end
  if has(t, T.K) then parts[#parts + 1] = "K" end
  if has(t, T.W) then parts[#parts + 1] = "W" end
  if has(t, T.z) then parts[#parts + 1] = "z" end
  if has(t, T.o) then parts[#parts + 1] = "o" end
  if has(t, T.n) then parts[#parts + 1] = "n" end
  if has(t, T.d) then parts[#parts + 1] = "d" end
  if has(t, T.u) then parts[#parts + 1] = "u" end
  if has(t, T.e) then parts[#parts + 1] = "e" end
  if has(t, T.f) then parts[#parts + 1] = "f" end
  if has(t, T.s) then parts[#parts + 1] = "s" end
  if has(t, T.m) then parts[#parts + 1] = "m" end
  if has(t, T.x) then parts[#parts + 1] = "x" end
  if has(t, T.k) then parts[#parts + 1] = "k" end
  return table.concat(parts)
end

function M.is_valid_top_level(node)
  -- Top level must be B type
  return has(node.type, T.B)
end

function M.is_nonmalleable(node)
  return has(node.type, T.m)
end

function M.has_timelock_mixing(node)
  return not has(node.type, T.k)
end

return M
