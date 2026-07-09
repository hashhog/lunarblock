#!/usr/bin/env luajit
-- Inbound-connection eviction — lunarblock
--
-- Reference (Bitcoin Core v31.99, bitcoin-core/src):
--   net.cpp AttemptToEvictConnection (~1689): when inbound slots are full,
--   Core does NOT hard-refuse the newcomer.  It runs a protection ladder over
--   existing inbound peers (protect lowest min-ping, most-recent tx/block relay,
--   a few unique netgroups, most-recently-connected) and EVICTS the
--   longest-connected survivor to make room.  Only when every inbound peer is
--   protected is the new connection refused.
--
-- Pre-fix lunarblock (peerman.lua accept_inbound) simply client:close()'d every
-- new inbound once inbound_count >= max_inbound — hard-refuse, no eviction.
-- This test EXERCISES the real accept_inbound path (via a stubbed listen socket
-- + client) and asserts:
--   (1) full slots -> an EXISTING inbound peer is evicted, count stays == max,
--       the newcomer is admitted (its socket NOT closed);
--   (2) full slots but ALL inbound protected -> newcomer refused (socket closed),
--       count unchanged, no existing peer evicted.
--
-- Harness style mirrors tests/test_w157_feeler_anti_eclipse.lua.

package.path = "src/?.lua;src/?/init.lua;" .. package.path

local peerman   = require("lunarblock.peerman")
local peer_mod  = require("lunarblock.peer")
local consensus = require("lunarblock.consensus")
local socket    = require("socket")

-- ---------------------------------------------------------------------------
-- Test scaffolding
-- ---------------------------------------------------------------------------
local PASS, FAIL = 0, 0
local function pass(name) io.write(string.format("  PASS  %s\n", name)); PASS = PASS + 1 end
local function fail(name, msg) io.write(string.format("  FAIL  %s -- %s\n", name, msg)); FAIL = FAIL + 1 end
local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end
local function expect_eq(a, b, msg)
  if a ~= b then error((msg or "mismatch") .. ": got " .. tostring(a) ..
        ", expected " .. tostring(b), 2) end
end
local function expect_true(v, msg) if not v then error((msg or "expected true") .. ": got " .. tostring(v), 2) end end
local function expect_false(v, msg) if v then error((msg or "expected false") .. ": got " .. tostring(v), 2) end end

-- A stub TCP socket that records whether it was closed.  Enough surface for
-- Peer:disconnect (socket:close) and accept_inbound (settimeout/close).
local function make_stub_socket()
  local s = { closed = false }
  function s:close() self.closed = true end
  function s:settimeout(_) end
  function s:getpeername() return self._ip, self._port end
  return s
end

local function make_pm(max_inbound)
  local tmpdir = os.tmpname()
  os.remove(tmpdir)
  os.execute("mkdir -p " .. tmpdir)
  local net = consensus.networks.regtest
  local pm = peerman.new(net, nil, { data_dir = tmpdir, max_inbound = max_inbound,
                                     nov2transport = true })
  return pm, tmpdir
end
local function rm_dir(path)
  if path and path ~= "" and path ~= "/" then os.execute("rm -rf " .. path) end
end

-- Register a controlled inbound peer directly into the manager (bypassing the
-- socket handshake).  opts: ping, conn_time, last_recv, last_block_ann.
local function add_inbound(pm, ip, port, opts)
  opts = opts or {}
  local p = peer_mod.new(ip, port, pm.network, pm.our_height, false, nil, false, false, nil)
  p.inbound = true
  p.state = peer_mod.STATE.CONNECTED
  p.socket = make_stub_socket()
  p.min_ping_ms = opts.ping            -- nil = unmeasured
  p.conn_time = opts.conn_time or socket.gettime()
  p.last_recv = opts.last_recv or 0
  p.nonce = opts.nonce or math.random(1, 2 ^ 40)
  local key = ip .. ":" .. port
  pm.peers[key] = p
  pm.peer_list[#pm.peer_list + 1] = p
  if opts.last_block_ann then pm._peer_last_block_ann[key] = opts.last_block_ann end
  return p
end

local function count_inbound(pm)
  local n = 0
  for _, p in ipairs(pm.peer_list) do if p.inbound then n = n + 1 end end
  return n
end

-- Drive one real accept_inbound with a stubbed listen socket handing back a
-- single new client from `ip`.  Returns the stub client so callers can inspect
-- whether it was closed (refused) or kept (admitted).
local function offer_inbound(pm, ip, port)
  local client = make_stub_socket()
  client._ip, client._port = ip, port
  pm.listen_socket = {
    accept = function() return client end,
  }
  pm.network_active = true
  pm:accept_inbound()
  return client
end

-- ---------------------------------------------------------------------------
-- Test 1: full inbound -> existing peer evicted, newcomer admitted.
-- ---------------------------------------------------------------------------
test("full inbound evicts least-valuable existing peer (not the newcomer)", function()
  -- MAX=25.  The ladder can protect at most 4+4+4+4+4 = 20 peers (five rungs of
  -- 4: ping, activity, block-relay, netgroup, most-recent-conn), so with 25
  -- distinct-in-every-dimension inbound peers a victim is guaranteed to survive
  -- to the final rung — the longest-connected of the ~5 unprotected peers.
  local MAX = 25
  local pm, dir = make_pm(MAX)

  local base = socket.gettime()
  for i = 1, MAX do
    -- Distinct in every dimension so each protection rung has a clear ranking
    -- and the eviction candidate is deterministic.
    add_inbound(pm, "10." .. i .. ".0.1", 40000 + i, {
      ping = 5 + i,                  -- unique measured pings
      last_recv = base + i,          -- unique activity times
      last_block_ann = base + i,     -- unique block-relay times
      conn_time = base + i,          -- unique connect times (peer 1 oldest)
    })
  end

  expect_eq(count_inbound(pm), MAX, "precondition: inbound full")

  -- The selector must find an evictable existing inbound peer (not nil), and it
  -- must be a currently-registered inbound peer.
  local predicted = pm:select_inbound_eviction_candidate()
  expect_true(predicted ~= nil, "selector returns an eviction candidate")
  expect_true(predicted.inbound, "candidate is an inbound peer")
  local predicted_key = predicted.ip .. ":" .. predicted.port
  expect_true(pm.peers[predicted_key] == predicted, "candidate is registered")
  -- Peer:disconnect nils out peer.socket, so capture the stub now to inspect it.
  local predicted_sock = predicted.socket

  local client = offer_inbound(pm, "203.0.113.7", 51000)

  -- The predicted EXISTING inbound peer was evicted, count held at the cap, and
  -- the newcomer was admitted (its socket stays open + it is now registered).
  expect_eq(count_inbound(pm), MAX, "count stays == max after eviction+admit")
  expect_true(predicted_sock.closed, "the predicted least-valuable peer was evicted")
  expect_true(pm.peers[predicted_key] == nil, "victim removed from peers")
  expect_false(client.closed, "newcomer admitted, socket not closed")
  expect_true(pm.peers["203.0.113.7:51000"] ~= nil, "newcomer registered")

  -- Exactly one existing peer was evicted (no collateral disconnects).
  local closed = 0
  for _, p in ipairs(pm.peer_list) do
    if p.socket and p.socket.closed then closed = closed + 1 end
  end
  expect_eq(closed, 0, "no lingering closed sockets remain in peer_list")

  rm_dir(dir)
end)

-- ---------------------------------------------------------------------------
-- Test 2: full inbound but every peer protected -> newcomer refused.
-- ---------------------------------------------------------------------------
test("all inbound protected -> newcomer hard-refused, none evicted", function()
  -- With max_inbound small enough that the count never exceeds what the
  -- protection ladder can shield, select_inbound_eviction_candidate returns nil
  -- and accept_inbound must fall back to closing the NEW connection.
  --
  -- The ladder's first rung already protects the 4 lowest-ping peers; with
  -- exactly 4 inbound peers (all measured), rung 2 empties the candidate list
  -- and no victim can be chosen.
  local MAX = 4
  local pm, dir = make_pm(MAX)

  local base = socket.gettime()
  local existing = {}
  for i = 1, MAX do
    existing[i] = add_inbound(pm, "10." .. i .. ".0.1", 40000 + i, {
      ping = 5 + i,
      last_recv = base,
      last_block_ann = base,
      conn_time = base + i,
    })
  end

  expect_eq(count_inbound(pm), MAX, "precondition: inbound full")
  -- Sanity: the selector itself reports no evictable candidate.
  expect_true(pm:select_inbound_eviction_candidate() == nil,
    "all-protected -> selector returns nil")

  local client = offer_inbound(pm, "203.0.113.9", 52000)

  expect_eq(count_inbound(pm), MAX, "count unchanged (no eviction, no admit)")
  expect_true(client.closed, "newcomer hard-refused (socket closed)")
  expect_true(pm.peers["203.0.113.9:52000"] == nil, "newcomer NOT registered")
  for i = 1, MAX do
    expect_false(existing[i].socket.closed,
      "protected existing peer #" .. i .. " not evicted")
  end

  rm_dir(dir)
end)

-- ---------------------------------------------------------------------------
io.write(string.format("\n%d passed, %d failed\n", PASS, FAIL))
os.exit(FAIL == 0 and 0 or 1)
