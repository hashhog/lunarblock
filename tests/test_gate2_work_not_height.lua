#!/usr/bin/env luajit
-- #53 (2026-08-27): fork-descent GATE 2 must compare cumulative WORK, not
-- height. Pre-fix code: `if tip_entry.height <= active_tip_height then
-- return false` — a heavier-but-SHORTER header chain (difficulty boundary)
-- was wrongly refused; the comment above it already claimed work.
-- FAILS BEHAVIORALLY AT PARENT: the heavier-but-shorter case returned
-- false there without even attempting the descent.
package.path = "src/?.lua;src/?/init.lua;" .. package.path
local sync_mod  = require("lunarblock.sync")
local consensus = require("lunarblock.consensus")
local types     = require("lunarblock.types")

local PASS, FAIL = 0, 0
local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then PASS = PASS + 1; io.write("  PASS  " .. name .. "\n")
  else FAIL = FAIL + 1; io.write("  FAIL  " .. name .. " -- " .. tostring(err) .. "\n") end
end

local function work(v) return string.rep("\0", 30) .. string.char(v) .. "\0" end
local function h256(n) return types.hash256(string.rep(string.char(n), 32)) end

-- Minimal downloader whose gate path we can observe: we detect PASSAGE
-- through GATE 2 by whether the function proceeds into the ancestry walk
-- (which will fail loudly on our sparse fixture AFTER the gate) versus
-- refusing AT the gate (clean `false` with no walk log). To make passage
-- observable without a full chain fixture, we give the header tip a
-- missing prev entry: the walk's "missing header entry" exit also returns
-- false, but only AFTER the gate — so we instrument hc.headers with a
-- probe table that records lookups of the tip's PREV hash.
local function build(tip_work, active_work, tip_h, active_h)
  local hc = sync_mod.new_header_chain(consensus.networks.regtest, nil)
  local tip_hash, active_hash, prev_hash = h256(2), h256(3), h256(4)
  hc.header_tip_hash = tip_hash
  hc.header_tip_height = tip_h
  local probe = { walked = false }
  local real = {
    [types.hash256_hex(tip_hash)]    = { height = tip_h, total_work = tip_work,
                                         header = { prev_hash = prev_hash }, prev_hash = prev_hash },
    [types.hash256_hex(active_hash)] = { height = active_h, total_work = active_work },
  }
  hc.headers = setmetatable({}, { __index = function(_, k)
    if k == types.hash256_hex(prev_hash) then probe.walked = true end
    return real[k]
  end })
  hc.height_to_hash = {}  -- active tip NOT on linear map => fork shape
  local dl = sync_mod.new_block_downloader(hc, nil, consensus.networks.regtest)
  dl.active_tip_provider = function() return active_hash, active_h end
  return dl, probe
end

-- Discriminator on this sparse fixture: a GATE-2 refusal returns false
-- CLEANLY (pcall ok); passage proceeds into the ancestry walk, which
-- crashes on the fake header (pcall not ok). Both tests therefore fail
-- behaviorally at the parent, where the gate compared HEIGHT.

test("heavier-but-SHORTER header chain passes GATE 2 (reaches the walk)", function()
  local dl = build(work(9), work(4), 10, 20)  -- tip shorter but HEAVIER
  local ok = pcall(function() return dl:_apply_fork_aware_floor() end)
  assert(ok == false,
    "gate refused a heavier-but-shorter chain (height comparison) — the walk was never reached")
end)

test("taller-but-LIGHTER header chain is refused at GATE 2", function()
  local dl = build(work(3), work(4), 30, 20)  -- tip taller but LIGHTER
  local ok, r = pcall(function() return dl:_apply_fork_aware_floor() end)
  assert(ok == true and r == false,
    "gate admitted a taller-but-lighter chain into the walk — height must not decide")
end)

io.write(string.format("\n%d passed, %d failed\n", PASS, FAIL))
os.exit(FAIL == 0 and 0 or 1)
