#!/usr/bin/env luajit
-- #72 audit row (4) — the chain-sync-timeout "give the peer a chance" probe.
--
-- Reference (Bitcoin Core v31.99, net_processing.cpp:5244-5252): when an
-- outbound peer's chain-sync timeout fires, Core sends a getheaders with
-- GetLocator(m_chain_sync.m_work_header->pprev) — a REAL locator anchored
-- one block below the work header — so an honest peer at our tip still
-- answers with >= 1 header, and only sets m_sent_getheaders afterward.
--
-- lunarblock's probe sent an EMPTY locator with a zero hash_stop. Core's
-- ProcessGetHeaders treats a null locator as a hash_stop lookup; a zero
-- hash_stop resolves to nothing, so honest peers answer with NOTHING and
-- the "second chance" was a functional no-op — the timeout converted into
-- a guaranteed eviction. This test EXECUTES consider_eviction on the
-- timeout-exceeded branch, captures the getheaders actually sent, and
-- asserts its locator is non-empty. It fails behaviorally at the parent
-- commit (locator count = 0).

package.path = "src/?.lua;src/?/init.lua;" .. package.path

local peerman   = require("lunarblock.peerman")
local peer_mod  = require("lunarblock.peer")
local consensus = require("lunarblock.consensus")
local p2p       = require("lunarblock.p2p")

local PASS, FAIL = 0, 0
local function pass(name) io.write(string.format("  PASS  %s\n", name)); PASS = PASS + 1 end
local function fail(name, msg) io.write(string.format("  FAIL  %s -- %s\n", name, msg)); FAIL = FAIL + 1 end
local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end

local function make_pm()
  local tmpdir = os.tmpname(); os.remove(tmpdir); os.execute("mkdir -p " .. tmpdir)
  local net = consensus.networks.regtest
  local pm = peerman.new(net, nil, { data_dir = tmpdir })
  return pm, tmpdir
end

test("chain-sync-timeout probe sends a NON-EMPTY locator (Core net_processing.cpp:5248)", function()
  local pm = make_pm()
  pm.our_height = 500

  -- Wire the provider main.lua installs: a real locator from tip-1.
  -- hash256 objects (write_hash256 reads .bytes)
  local fake_hashes = {}
  for i = 1, 12 do fake_hashes[i] = { bytes = string.rep(string.char(i), 32) } end
  pm.locator_provider = function() return fake_hashes end

  -- Fake ESTABLISHED outbound peer capturing what it is asked to send.
  local sent = {}
  local p = {
    ip = "10.0.0.1", port = 8444, inbound = false,
    state = peer_mod.STATE.ESTABLISHED,
    send_message = function(self, cmd, payload) sent[#sent + 1] = {cmd = cmd, payload = payload} end,
  }
  pm:_init_peer_chain_sync(p)
  local ss = pm:get_peer_chain_sync(p)

  -- Behind-tip peer, timeout already exceeded, probe not yet sent.
  pm:set_peer_best_block(p, 100, string.rep("\0", 32), nil)
  ss.timeout = 1000            -- exceeded (now = 2000 below)
  ss.work_header = {height = 500}
  ss.sent_getheaders = false

  pm:consider_eviction(p, 2000)

  assert(#sent == 1, "probe getheaders was not sent (sent=" .. #sent .. ")")
  assert(sent[1].cmd == "getheaders", "expected getheaders, got " .. tostring(sent[1].cmd))
  local msg = p2p.deserialize_getheaders(sent[1].payload)
  local n = #(msg.locator_hashes or msg.block_locator_hashes or {})
  assert(n > 0, "probe locator is EMPTY — the no-op probe that guarantees eviction " ..
    "(Core sends GetLocator(work_header->pprev), net_processing.cpp:5248)")
  assert(ss.sent_getheaders == true, "sent_getheaders must latch after the probe")
end)

test("probe with NO provider skips the send instead of sending an empty locator", function()
  local pm = make_pm()
  pm.our_height = 500
  local sent = {}
  local p = {
    ip = "10.0.0.2", port = 8444, inbound = false,
    state = peer_mod.STATE.ESTABLISHED,
    send_message = function(self, cmd, payload) sent[#sent + 1] = {cmd = cmd} end,
  }
  pm:_init_peer_chain_sync(p)
  local ss = pm:get_peer_chain_sync(p)
  pm:set_peer_best_block(p, 100, string.rep("\0", 32), nil)
  ss.timeout = 1000
  ss.work_header = {height = 500}
  ss.sent_getheaders = false

  pm:consider_eviction(p, 2000)

  assert(#sent == 0, "an empty-locator getheaders must not be sent (it elicits nothing)")
end)

io.write(string.format("\n%d passed, %d failed\n", PASS, FAIL))
os.exit(FAIL == 0 and 0 or 1)
