#!/usr/bin/env luajit
-- LB-10: scantxoutset / dumptxoutset / verifychain / rescanblockchain must not
-- freeze the serialized main loop or ignore SIGTERM.
--
-- Core runs these on RPC worker threads: P2P keeps being served and blocks keep
-- connecting while they run, and RpcInterruptionPoint() aborts them with
-- RPC_CLIENT_NOT_CONNECTED (-9) "Shutting down" once InterruptRPC has run.
-- lunarblock is one cooperative loop, so each handler must yield to
-- rpc.tip_pump (peers, block connect, nested RPC) between slices and poll the
-- shutdown latch, the way gettxoutsetinfo already does.
--
-- For each long RPC this file checks, by name:
--   <rpc>: peers are served while it runs     (tip_pump ran many times)
--   <rpc>: the tip advances while it runs     (a block "connected" in a pump)
--   <rpc>: the result is the pre-pump snapshot (scan is not corrupted by it)
--   <rpc>: stop mid-run aborts with -9 within a bounded number of slices
-- plus a latched shutdown never starts the work, a second long RPC is refused
-- while one runs, and dumptxoutset rollback holds block connection.
--
-- Run from the lunarblock repo root:
--   luajit tests/test_long_rpc_yield.lua

package.path = "./src/?.lua;./lunarblock/?.lua;" .. package.path

local rpc_mod = require("lunarblock.rpc")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local types = require("lunarblock.types")
local script_mod = require("lunarblock.script")
local storage_mod = require("lunarblock.storage")
local wallet_mod = require("lunarblock.wallet")
local cjson = require("cjson")
local ops = require("lunarblock.ops")

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

local N_COINS = 64
local SPK = script_mod.make_p2pkh_script(string.rep("\x11", 20))

local function txid_of(b)
  return types.hash256(string.char(b) .. string.rep("\x00", 31))
end

local function reset_ops()
  ops.reset_signal_handlers()
  ops.shutting_down = false
end

-- A node whose "main loop" is the pump: it counts peer service, and on the
-- pump numbers in `connect_at` it connects a block (tip moves, a coin is added
-- to the cache) the way a real slice would.
local function make_node()
  local db = storage_mod.new_memory_storage()
  local cs = utxo.new_chain_state(db, consensus.networks.regtest)
  for i = 1, N_COINS do
    cs.coin_view:add(txid_of(i), 0, utxo.utxo_entry(50, SPK, 1, i == 1))
  end
  cs.coin_view:flush()
  cs.tip_hash = types.hash256(string.rep("\xab", 32))
  cs.tip_height = 20
  local server = rpc_mod.new({
    chain_state = cs,
    storage = db,
    network = consensus.networks.regtest,
  })
  server._long_rpc_slice_seconds = 0   -- pump on every yield point
  server._long_rpc_check_every = 1     -- yield point on every item
  local node = {
    server = server, cs = cs, db = db,
    pumps = 0, start_height = cs.tip_height, stop_at = nil,
    stop_pumps = 0,
  }
  server.tip_pump = function()
    node.pumps = node.pumps + 1
    -- connect a block: the tip advances, a new coin appears
    cs.tip_height = cs.tip_height + 1
    cs.coin_view:add(txid_of(100 + node.pumps), 0, utxo.utxo_entry(50, SPK, 2, false))
    if node.wallet then
      -- the wallet is told about the connected block, as main.lua's
      -- on_block_connected observer does
      node.wallet:scan_block(cs, { transactions = {} }, cs.tip_height, nil)
    end
    if node.stop_at and node.pumps == node.stop_at then
      node.stop_reply = server.methods["stop"](server, {})
    end
    if node.stop_at and node.pumps > node.stop_at then
      node.stop_pumps = node.stop_pumps + 1
    end
  end
  return node
end

local function errinfo(ok, res)
  if ok then return nil, nil end
  if type(res) == "table" then return res.code, res.message end
  return nil, tostring(res)
end

local function run_case(label, setup, call, verify)
  -- 1. pumped run: peers served, tip advances, result correct
  do
    reset_ops()
    local node = make_node()
    local ctx = setup(node) or {}
    local ok, res = pcall(call, node, ctx)
    check(label .. ": call succeeds", ok, ok and "" or (type(res) == "table" and res.message or res))
    check(label .. ": peers are served while it runs", node.pumps >= 3,
      "pumps=" .. node.pumps)
    check(label .. ": the tip advances while it runs",
      node.cs.tip_height > node.start_height,
      "tip=" .. node.cs.tip_height .. " start=" .. node.start_height)
    if ok and verify then verify(node, ctx, res, label) end
  end
  -- 2. stop mid-run: aborts -9, bounded slices after the stop
  do
    reset_ops()
    local running = true
    ops.set_signal_handler(ops.SIGTERM, function() running = false end)
    local node = make_node()
    node.stop_at = 2
    local ctx = setup(node) or {}
    local ok, res = pcall(call, node, ctx)
    local code, msg = errinfo(ok, res)
    check(label .. ": stop mid-run aborts with -9 Shutting down",
      code == -9 and msg == "Shutting down",
      ok and "completed instead of aborting" or ("code=" .. tostring(code) .. " msg=" .. tostring(msg)))
    check(label .. ": stop is honoured within one slice",
      node.pumps >= 2 and node.stop_pumps <= 1,
      "pumps=" .. node.pumps .. " after_stop=" .. node.stop_pumps)
    reset_ops()
  end
  -- 3. a shutdown latched before the call never does the work
  do
    reset_ops()
    ops.shutting_down = true
    local node = make_node()
    local ctx = setup(node) or {}
    local ok, res = pcall(call, node, ctx)
    local code = errinfo(ok, res)
    check(label .. ": latched shutdown aborts before the work",
      code == -9 and node.pumps == 0,
      "code=" .. tostring(code) .. " pumps=" .. node.pumps)
    reset_ops()
  end
end

--------------------------------------------------------------------------------
-- scantxoutset
--------------------------------------------------------------------------------
do
  local spk_hex = (SPK:gsub(".", function(c) return string.format("%02x", c:byte()) end))
  run_case("scantxoutset",
    function() return {} end,
    function(node)
      return node.server.methods["scantxoutset"](node.server,
        {"start", {"raw(" .. spk_hex .. ")"}})
    end,
    function(node, _, res, label)
      local j = cjson.decode(res._raw_json)
      -- the 64 coins that existed when the scan opened its iterator; coins the
      -- pumped "blocks" added later are not in the pinned set
      check(label .. ": result is the pre-pump snapshot",
        j.success == true and j.txouts == N_COINS and #j.unspents == N_COINS
          and j.height == node.start_height,
        "txouts=" .. tostring(j.txouts) .. " unspents=" .. tostring(j.unspents and #j.unspents)
          .. " height=" .. tostring(j.height))
    end)
end

--------------------------------------------------------------------------------
-- verifychain (level 0: read-only, deterministic on a stub chain)
--------------------------------------------------------------------------------
do
  run_case("verifychain",
    function(node)
      local db = node.db
      db.get_hash_by_height = function(h) return txid_of(h + 1) end
      db.get_block = function() return { transactions = {}, header = {} } end
    end,
    function(node)
      return node.server.methods["verifychain"](node.server, {0, 0})
    end,
    function(_, _, res, label)
      check(label .. ": returns true", res == true, tostring(res))
    end)
end

--------------------------------------------------------------------------------
-- rescanblockchain (real Wallet over a stub block store)
--------------------------------------------------------------------------------
do
  run_case("rescanblockchain",
    function(node)
      local db = node.db
      local cb_in = types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), "\x01\x01", 0xFFFFFFFF)
      local function block_at(h)
        local out = types.txout(50, script_mod.make_p2pkh_script(string.rep(string.char(h + 1), 20)))
        local tx = types.transaction(1, { cb_in }, { out }, 0)
        return { header = { timestamp = 1000 + h }, transactions = { tx } }
      end
      db.get_hash_by_height = function(h) return txid_of(h + 1) end
      db.get_block = function(hash) return block_at(hash.bytes:byte(1) - 1) end
      local w = wallet_mod.new(consensus.networks.regtest, db)
      node.server.wallet = w
      node.wallet = w
      return { wallet = w }
    end,
    function(node)
      return node.server.methods["rescanblockchain"](node.server, {})
    end,
    function(node, _, res, label)
      check(label .. ": scans the whole chain as of the call",
        res.start_height == 0 and res.stop_height == node.start_height,
        "start=" .. tostring(res.start_height) .. " stop=" .. tostring(res.stop_height))
      check(label .. ": a block connected mid-rescan is not lost to the wallet",
        node.wallet.last_synced_height == node.cs.tip_height
          and node.wallet._rescan_active == false,
        "synced=" .. tostring(node.wallet.last_synced_height)
          .. " tip=" .. tostring(node.cs.tip_height))
    end)
end

--------------------------------------------------------------------------------
-- dumptxoutset
--------------------------------------------------------------------------------
do
  local paths = {}
  local expect_hash
  run_case("dumptxoutset",
    function(node)
      local path = os.tmpname()
      os.remove(path)
      paths[#paths + 1] = path
      paths[#paths + 1] = path .. ".incomplete"
      node.path = path
      if not expect_hash then
        expect_hash = select(1, node.cs:compute_utxo_hash())
      end
      return { path = path }
    end,
    function(node, ctx)
      return node.server.methods["dumptxoutset"](node.server, { ctx.path })
    end,
    function(node, _, res, label)
      check(label .. ": dump is the pre-pump snapshot",
        res.coins_written == N_COINS and res.base_height == node.start_height,
        "coins=" .. tostring(res.coins_written) .. " base_height=" .. tostring(res.base_height))
      local want = {}
      for i = 32, 1, -1 do want[#want + 1] = string.format("%02x", expect_hash:byte(i)) end
      check(label .. ": txoutset_hash names the dumped set, not the moved tip",
        res.txoutset_hash == table.concat(want),
        tostring(res.txoutset_hash))
    end)
  for _, p in ipairs(paths) do os.remove(p) end
end

--------------------------------------------------------------------------------
-- dumptxoutset rollback: block connection is held while the chain is rewound
--------------------------------------------------------------------------------
do
  reset_ops()
  local node = make_node()
  local paused_during_pump = {}
  local nested_resp
  local rolled = 0
  local cs = node.cs
  local real_dump = cs.dump_snapshot
  cs.rollback_chain_to = function(self, target, _, step)
    local list = {}
    while self.tip_height > target do
      if step then step() end
      list[#list + 1] = { hash = txid_of(self.tip_height), height = self.tip_height }
      self.tip_height = self.tip_height - 1
      rolled = rolled + 1
    end
    return list
  end
  cs.reapply_disconnected = function(self, list)
    for i = #list, 1, -1 do
      if node.server.block_submission_paused ~= true then
        error("reapply ran without connection held")
      end
      self.tip_height = list[i].height
    end
    return true
  end
  local inner = node.server.tip_pump
  node.server.tip_pump = function()
    paused_during_pump[#paused_during_pump + 1] = node.server.block_submission_paused
    if not nested_resp then
      nested_resp = node.server:handle_single_request(
        { method = "invalidateblock", params = { string.rep("00", 32) }, id = 1 })
    end
    -- pumps must not move the tip while the chain is being rewound
    local h = cs.tip_height
    inner()
    cs.tip_height = h
  end
  local path = os.tmpname(); os.remove(path)
  local ok, res = pcall(function()
    return node.server.methods["dumptxoutset"](node.server, { path, "", { rollback = 10 } })
  end)
  os.remove(path); os.remove(path .. ".incomplete")
  local all_paused = #paused_during_pump > 0
  for _, p in ipairs(paused_during_pump) do if p ~= true then all_paused = false end end
  check("dumptxoutset rollback: peers served while rewinding", #paused_during_pump >= 3,
    "pumps=" .. #paused_during_pump)
  check("dumptxoutset rollback: block connection held on every pump", all_paused)
  check("dumptxoutset rollback: a tip-moving RPC served mid-rewind is refused",
    nested_resp and nested_resp.error and nested_resp.error.code == -1
      and tostring(nested_resp.error.message):find("rollback", 1, true) ~= nil,
    nested_resp and nested_resp.error and nested_resp.error.message or "no response")
  check("dumptxoutset rollback: tip restored and hold released",
    ok and cs.tip_height == 20 and node.server.block_submission_paused == false,
    ok and ("tip=" .. cs.tip_height) or tostring(type(res) == "table" and res.message or res))
  reset_ops()
end

--------------------------------------------------------------------------------
-- the P2P connect path honours the hold (main.lua wires it to the rollback flag)
--------------------------------------------------------------------------------
do
  local sync_mod = require("lunarblock.sync")
  local hc = { height_to_hash = {}, headers = {}, header_tip_height = 0 }
  local dl = sync_mod.new_block_downloader(hc, nil, consensus.networks.regtest)
  dl.next_connect_height = 1
  -- With no header at the cursor the connect loop logs once and stamps
  -- _last_missing_log; a held call must return before it gets that far.
  dl.connect_hold = function() return true end
  local held_ok = dl:connect_pending_blocks()
  check("connect_hold: a held call does not enter the connect loop",
    held_ok == true and dl._last_missing_log == nil,
    "ok=" .. tostring(held_ok) .. " stamp=" .. tostring(dl._last_missing_log))
  dl.connect_hold = function() return false end
  dl:connect_pending_blocks()
  check("connect_hold: released, the connect loop runs again (control)",
    dl._last_missing_log ~= nil)
end

--------------------------------------------------------------------------------
-- one long RPC at a time
--------------------------------------------------------------------------------
do
  reset_ops()
  local node = make_node()
  local nested_code, nested_msg
  local inner = node.server.tip_pump
  node.server.tip_pump = function()
    inner()
    if not nested_code then
      local ok, res = pcall(node.server.methods["verifychain"], node.server, {0, 0})
      nested_code, nested_msg = errinfo(ok, res)
    end
  end
  node.db.get_hash_by_height = function(h) return txid_of(h + 1) end
  node.db.get_block = function() return { transactions = {}, header = {} } end
  local spk_hex = (SPK:gsub(".", function(c) return string.format("%02x", c:byte()) end))
  local ok = pcall(node.server.methods["scantxoutset"], node.server,
    {"start", {"raw(" .. spk_hex .. ")"}})
  check("a second long RPC during a scan is refused (-1), the first completes",
    ok and nested_code == -1 and tostring(nested_msg):find("in progress", 1, true) ~= nil,
    "ok=" .. tostring(ok) .. " code=" .. tostring(nested_code) .. " msg=" .. tostring(nested_msg))
  reset_ops()
end

io.write(string.format("\n%d PASS / %d FAIL\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
