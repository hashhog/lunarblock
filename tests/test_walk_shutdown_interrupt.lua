#!/usr/bin/env luajit
-- Control: stop during gettxoutsetinfo must abort the walk, and a
-- waitfornewblock that arrives mid-walk must not pause it.
--
-- Core (kernel/coinstats.cpp ComputeUTXOStats + rpc/server.cpp
-- RpcInterruptionPoint) checks an interruption point on the cursor and
-- throws RPC_CLIENT_NOT_CONNECTED (-9) "Shutting down" once InterruptRPC
-- has run, so stop_mainnet does not wait out the walk and SIGKILL.
-- waitfornewblock is a separate RPC; it does not run inside the walk.
--
-- PRE-FIX: the walk runs every txid group to a successful result, stop()
-- only latches SIGTERM, and waitfornewblock called from the slice pump
-- does not return until the tip moves.
-- POST-FIX: stop / a latched shutdown abort with -9 before the remaining
-- groups are hashed; waitfornewblock returns a deferred long-poll and the
-- walk still covers every coin. The deferred call completes with the new
-- tip once a later slice moves it.
--
-- A 30k-output tx is still walked without a yield (interruption is between
-- txid groups). That is acceptable on mainnet.
--
-- Run from the lunarblock repo root:
--   luajit tests/test_walk_shutdown_interrupt.lua

package.path = "./src/?.lua;./lunarblock/?.lua;" .. package.path

local rpc_mod = require("lunarblock.rpc")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local types = require("lunarblock.types")
local script_mod = require("lunarblock.script")
local storage_mod = require("lunarblock.storage")
local cjson = require("cjson")
local ops = require("lunarblock.ops")
local tip_notifier = require("lunarblock.tip_notifier")

local pass, fail = 0, 0
local function check(name, cond, detail)
  if cond then
    io.write("PASS: " .. name .. "\n")
    pass = pass + 1
  else
    io.write("FAIL: " .. name .. (detail and (" -- " .. tostring(detail)) or "") .. "\n")
    fail = fail + 1
  end
end

local function txid_of(b)
  return types.hash256(string.char(b) .. string.rep("\x00", 31))
end

local function make_server(n_coins)
  local db = storage_mod.new_memory_storage()
  local cs = utxo.new_chain_state(db, consensus.networks.regtest)
  local script = script_mod.make_p2pkh_script(string.rep("\x11", 20))
  for i = 1, n_coins do
    cs.coin_view:add(txid_of(i), 0, utxo.utxo_entry(50, script, 1, i == 1))
  end
  cs.tip_hash = types.hash256(string.rep("\xab", 32))
  cs.tip_height = 2
  local server = rpc_mod.new({
    chain_state = cs,
    storage = db,
    network = consensus.networks.regtest,
  })
  server._utxo_walk_slice_groups = 1
  server._utxo_walk_slice_seconds = 0
  server.tip_notifier = tip_notifier.new()
  return server, cs
end

local function call_info(server)
  return server.methods["gettxoutsetinfo"](server, {})
end

--------------------------------------------------------------------------------
-- 1. A shutdown latched before the walk aborts without hashing.
--------------------------------------------------------------------------------

do
  ops.reset_signal_handlers()
  ops.shutting_down = true
  local server = make_server(4)
  local pumps = 0
  server.tip_pump = function() pumps = pumps + 1 end
  local ok, res = pcall(call_info, server)
  local code = (not ok and type(res) == "table") and res.code or nil
  local msg = (not ok and type(res) == "table") and res.message or (ok and "ok" or tostring(res))
  check("latched shutdown aborts gettxoutsetinfo",
    code == -9 and msg == "Shutting down",
    "code=" .. tostring(code) .. " msg=" .. tostring(msg))
  check("latched shutdown does not walk", pumps == 0, "pumps=" .. tostring(pumps))
  ops.shutting_down = false
  ops.reset_signal_handlers()
end

--------------------------------------------------------------------------------
-- 2. RPC stop during the first slice aborts the rest of the walk.
--------------------------------------------------------------------------------

do
  ops.reset_signal_handlers()
  ops.shutting_down = false
  local running = true
  ops.set_signal_handler(ops.SIGTERM, function() running = false end)
  local n = 8
  local server = make_server(n)
  local pumps = 0
  local stop_reply
  server.tip_pump = function()
    pumps = pumps + 1
    if pumps == 1 then
      stop_reply = server.methods["stop"](server, {})
    end
  end
  local ok, res = pcall(call_info, server)
  local code = (not ok and type(res) == "table") and res.code or nil
  local msg = (not ok and type(res) == "table") and res.message or (ok and "ok" or tostring(res))
  check("stop during the walk returns LunarBlock stopping",
    stop_reply == "LunarBlock stopping", tostring(stop_reply))
  check("stop during the walk aborts with Shutting down",
    code == -9 and msg == "Shutting down",
    "code=" .. tostring(code) .. " msg=" .. tostring(msg))
  check("stop does not wait for every txid group",
    pumps > 0 and pumps < n, "pumps=" .. tostring(pumps) .. " n=" .. n)
  check("SIGTERM handler ran (main loop can exit)", running == false)
  ops.shutting_down = false
  ops.reset_signal_handlers()
end

--------------------------------------------------------------------------------
-- 3. waitfornewblock mid-walk is deferred; the walk still finishes.
--------------------------------------------------------------------------------

do
  ops.reset_signal_handlers()
  ops.shutting_down = false
  local n = 6
  local server, cs = make_server(n)
  local original_hex = types.hash256_hex(cs.tip_hash)
  local new_hash = types.hash256(string.rep("\xcd", 32))
  local new_hex = types.hash256_hex(new_hash)
  local pumps = 0
  local wait_status, wait_body
  local tip_at_wait_return
  local sent = {}
  local stub = {
    send = function(_, data)
      sent[#sent + 1] = data
      return #data
    end,
    close = function() end,
  }
  server.tip_pump = function()
    pumps = pumps + 1
    if pumps == 1 then
      wait_body, wait_status = server:handle_request(
        '{"jsonrpc":"1.0","id":"w","method":"waitfornewblock","params":[0]}')
      tip_at_wait_return = types.hash256_hex(cs.tip_hash)
      local waits = server._deferred_waits
      local w = waits and waits[#waits]
      if w then w.client = stub end
    elseif pumps == 2 then
      cs.tip_hash = new_hash
      cs.tip_height = 99
      server.tip_notifier:notify()
    end
  end
  local ok, res = pcall(call_info, server)
  local decoded = ok and cjson.decode(res._raw_json) or nil
  check("waitfornewblock during the walk is deferred",
    wait_status == "deferred",
    "status=" .. tostring(wait_status) .. " body=" .. tostring(wait_body))
  check("wait returned before the tip moved",
    tip_at_wait_return == original_hex,
    tostring(tip_at_wait_return))
  check("walk still covered every coin",
    decoded ~= nil and decoded.txouts == n,
    decoded and ("txouts=" .. tostring(decoded.txouts)) or tostring(res))
  check("walk label stays the pre-walk tip",
    decoded ~= nil and decoded.bestblock == original_hex,
    decoded and decoded.bestblock)
  if server.drain_deferred_waits then server:drain_deferred_waits() end
  local completed = server._completed_waits and server._completed_waits[1]
  local sent_blob = table.concat(sent)
  check("deferred waitfornewblock completes with the new tip",
    completed ~= nil and completed.hash == new_hex and completed.height == 99
      and sent_blob:find(new_hex, 1, true) ~= nil,
    "completed=" .. tostring(completed and completed.hash)
      .. " sent=" .. tostring(#sent))
  check("walk was not stuck inside the wait (later slices ran)",
    pumps >= n, "pumps=" .. tostring(pumps))
  ops.shutting_down = false
  ops.reset_signal_handlers()
end

--------------------------------------------------------------------------------
-- 4. No shutdown: the yielding walk still matches an unpumped walk.
--------------------------------------------------------------------------------

do
  ops.reset_signal_handlers()
  ops.shutting_down = false
  local server = make_server(5)
  local pumps = 0
  server.tip_pump = function() pumps = pumps + 1 end
  local ok, res = pcall(call_info, server)
  local decoded = ok and cjson.decode(res._raw_json) or nil
  server.tip_pump = nil
  local ok2, res2 = pcall(call_info, server)
  local decoded2 = ok2 and cjson.decode(res2._raw_json) or nil
  check("clear shutdown flag does not abort a normal walk",
    decoded ~= nil and decoded.txouts == 5 and pumps >= 5,
    "pumps=" .. tostring(pumps) .. " err=" .. tostring(res))
  check("yielding walk hash matches the unpumped walk",
    decoded ~= nil and decoded2 ~= nil
      and decoded.hash_serialized_3 == decoded2.hash_serialized_3
      and decoded.hash_serialized_3 ~= string.rep("0", 64),
    tostring(decoded and decoded.hash_serialized_3))
  ops.reset_signal_handlers()
end

io.write(string.format("\n%d PASS / %d FAIL\n", pass, fail))
if fail > 0 then os.exit(1) end
