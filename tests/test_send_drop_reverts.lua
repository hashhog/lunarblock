#!/usr/bin/env luajit
-- #74: dropped sends must revert caller-side state (the blockbrew-wedge
-- class). Fails behaviorally at the parent: start_sync left syncing=true
-- pinned to a peer that never received the getheaders.
package.path = "src/?.lua;src/?/init.lua;" .. package.path
local sync_mod  = require("lunarblock.sync")
local consensus = require("lunarblock.consensus")

local PASS, FAIL = 0, 0
local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then PASS = PASS + 1; io.write("  PASS  " .. name .. "\n")
  else FAIL = FAIL + 1; io.write("  FAIL  " .. name .. " -- " .. tostring(err) .. "\n") end
end

test("start_sync releases the syncing latch when the getheaders send drops", function()
  local hc = sync_mod.new_header_chain(consensus.networks.regtest, nil)
  -- minimal state so get_block_locator works
  hc.header_tip_height = 0
  local dead_peer = {
    ip = "10.0.0.9", port = 8444,
    send_message = function() return false end,  -- every send drops
  }
  hc:start_sync(dead_peer)
  assert(hc.syncing == false,
    "syncing latch must be RELEASED when the send drops (was pinned forever pre-#74)")
  assert(hc.sync_peer == nil, "sync_peer must be cleared")
end)

test("start_sync keeps the latch when the send succeeds", function()
  local hc = sync_mod.new_header_chain(consensus.networks.regtest, nil)
  hc.header_tip_height = 0
  local ok_peer = {
    ip = "10.0.0.10", port = 8444,
    send_message = function() return true end,
  }
  hc:start_sync(ok_peer)
  assert(hc.syncing == true, "successful send must keep the latch")
end)

io.write(string.format("\n%d passed, %d failed\n", PASS, FAIL))
os.exit(FAIL == 0 and 0 or 1)
