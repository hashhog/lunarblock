#!/usr/bin/env luajit
-- #53 row (e): the assumeutxo activation gate compared HEIGHT while its
-- refusal message claimed "work does not exceed active chainstate".
-- Now: cumulative-WORK comparison when both sides are supplied, loud
-- truthful height proxy otherwise. FAILS BEHAVIORALLY AT PARENT in both
-- work directions (parent ignores the extra work args entirely).
package.path = "src/?.lua;src/?/init.lua;" .. package.path
local utxo_mod  = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local storage_mod = require("lunarblock.storage")

local tmpdir = os.tmpname(); os.remove(tmpdir); os.execute("mkdir -p " .. tmpdir)

local PASS, FAIL = 0, 0
local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then PASS = PASS + 1; io.write("  PASS  " .. name .. "\n")
  else FAIL = FAIL + 1; io.write("  FAIL  " .. name .. " -- " .. tostring(err) .. "\n") end
end
local function work(v) return string.rep("\0", 30) .. string.char(v) .. "\0" end

local n = 0
local function fresh_cs()
  n = n + 1
  local d = tmpdir .. "/cs" .. n
  os.execute("mkdir -p " .. d)
  local stor = storage_mod.open(d)
  local cs = utxo_mod.new_chain_state(stor, consensus.networks.regtest)
  cs:init()
  return cs
end

-- Discriminator: a gate refusal returns (false, <gate message>) BEFORE any
-- file access; passage reaches io.open and fails with "failed to open
-- snapshot" on the nonexistent path.

test("heavier-but-SHORTER snapshot base passes the gate (reaches file open)", function()
  local cs = fresh_cs()
  local ok, err = cs:load_snapshot("/nonexistent/snap.dat", nil,
    100,          -- base_height (SHORTER than active 200)
    200,          -- active_tip_height
    nil,
    work(9),      -- snapshot base work: HEAVIER
    work(4))      -- active tip work
  assert(ok == false and err:match("failed to open snapshot"),
    "heavier-but-shorter base must pass the work gate (got: " .. tostring(err) .. ")")
end)

test("taller-but-LIGHTER snapshot base is refused by WORK", function()
  local cs = fresh_cs()
  local ok, err = cs:load_snapshot("/nonexistent/snap.dat", nil,
    300,          -- base_height (TALLER than active 200)
    200,
    nil,
    work(3),      -- snapshot base work: LIGHTER
    work(4))
  assert(ok == false and err:match("work does not exceed"),
    "taller-but-lighter base must be refused by work (got: " .. tostring(err) .. ")")
end)

test("no work basis: height proxy applies with a TRUTHFUL message", function()
  local cs = fresh_cs()
  local ok, err = cs:load_snapshot("/nonexistent/snap.dat", nil,
    100, 200, nil)  -- no works supplied; 100 <= 200 -> refuse
  assert(ok == false and err:match("height proxy"),
    "height-proxy refusal must SAY it compared height (got: " .. tostring(err) .. ")")
end)

io.write(string.format("\n%d passed, %d failed\n", PASS, FAIL))
os.exit(FAIL == 0 and 0 or 1)
os.execute("rm -rf " .. tmpdir)
