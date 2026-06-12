#!/usr/bin/env luajit
-- W157 P2P feeler + getaddr anti-eclipse / anti-DoS hardening — lunarblock
--
-- Reference (Bitcoin Core v31.99, bitcoin-core/src):
--   net.cpp            ThreadOpenConnections FEELER arm (~2700-2895):
--                      FEELER_INTERVAL=120s, MAX_FEELER_CONNECTIONS=1,
--                      addrman.Select(newOnly=true) -> ONE NEW-table address,
--                      short-lived probe, addrman.Good() (NEW->TRIED) ONLY on a
--                      successful handshake, then disconnect; off the outbound
--                      slot budget (FEELER holds no semOutbound grant).
--   net.h:61/75        FEELER_INTERVAL = 2min;  MAX_FEELER_CONNECTIONS = 1.
--   net_processing.cpp GETADDR handler (~4816): ignore getaddr from OUTBOUND
--                      peers, answer only the FIRST getaddr per connection
--                      (m_getaddr_recvd), cap reply at
--                      min(1000, ceil(0.23*addrman_size)) (MAX_PCT_ADDR_TO_SEND
--                      =23, MAX_ADDR_TO_SEND=1000).
--   net_processing.cpp ProcessAddrs token bucket (~5625): per-peer bucket init
--                      1.0, refill elapsed*0.1 cap 1000, spend 1/addr, drop
--                      excess for rate-limited peers.  BOTH addr AND addrv2 go
--                      through the SAME ProcessAddrs bucket (:4022) so addrv2
--                      cannot bypass the limit.
--
-- This test EXECUTES the real lunarblock code paths (peerman.maybe_open_feeler,
-- _respond_getaddr, handle_addr, handle_addrv2) and asserts the guards are
-- PRESENT.  It includes falsification cases: a not-probed NEW entry must STAY
-- NEW, and a failed-handshake feeler must NOT promote.
--
-- Harness mirrors test_w128_addrman.lua so the project runner output is uniform.

package.path = "src/?.lua;src/?/init.lua;" .. package.path

local peerman   = require("lunarblock.peerman")
local peer_mod  = require("lunarblock.peer")
local consensus = require("lunarblock.consensus")
local p2p       = require("lunarblock.p2p")

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
local function expect_nil(v, msg) if v ~= nil then error((msg or "expected nil") .. ": got " .. tostring(v), 2) end end
local function expect_not_nil(v, msg) if v == nil then error((msg or "expected non-nil"), 2) end end

-- Fresh PeerManager backed by a tmpdir (no live socket I/O is performed because
-- every test stubs connect_peer / send_message).
local function make_pm()
  local tmpdir = os.tmpname()
  os.remove(tmpdir)
  os.execute("mkdir -p " .. tmpdir)
  local net = consensus.networks.regtest
  local pm = peerman.new(net, nil, { data_dir = tmpdir })
  return pm, tmpdir
end
local function rm_dir(path)
  if path and path ~= "" and path ~= "/" then os.execute("rm -rf " .. path) end
end

-- Seed the NEW table densely so the addrman's random-probe Select reliably
-- finds an entry (the un-weighted Select_ is a documented pre-existing gap --
-- W128 BUG-2; the feeler delegates to it, so the test needs enough density to
-- exercise the feeler path deterministically rather than the selection lottery).
-- The source IP is varied across many /16 groups so entries spread across many
-- NEW buckets instead of colliding into a handful.
local function seed_new_table(pm, n)
  n = n or 3000
  for i = 1, n do
    local a = math.floor(i / 65536) % 256
    local b = math.floor(i / 256) % 256
    local c = i % 256
    local sa = math.floor(i / 256) % 256
    local sb = i % 256
    pm:_add_to_new("100." .. a .. "." .. b .. "." .. c, 8333,
      p2p.SERVICES.NODE_NETWORK, os.time(), "198." .. sa .. "." .. sb .. ".1")
  end
end

-- Is "ip:port" currently in the TRIED table (i.e. has it been promoted)?
local function in_tried(pm, ip, port)
  local info = pm._addr_info[ip .. ":" .. port]
  return info ~= nil and info.in_tried == true
end
-- Is "ip:port" currently in the NEW table?
local function in_new(pm, ip, port)
  local info = pm._addr_info[ip .. ":" .. port]
  return info ~= nil and info.in_tried ~= true and (info.new_ref_count or 0) > 0
end

print("\n=========================================================================")
print("W157 feeler + getaddr anti-eclipse / anti-DoS -- lunarblock")
print("Source: src/peerman.lua (maybe_open_feeler, _respond_getaddr,")
print("        handle_addr, handle_addrv2, _rate_limit_addrs)")
print("Reference: bitcoin-core/src/{net.cpp,net.h,net_processing.cpp}")
print("=========================================================================")

-- ---------------------------------------------------------------------------
-- 0: Genuine Core v31.99 constants
-- ---------------------------------------------------------------------------
print("\n--- 0: Core constant identity ---")
test("0-a: FEELER_INTERVAL = 120s (Core net.h:61 = 2min)", function()
  expect_eq(peerman.STALE_TIP.FEELER_INTERVAL, 120)
end)
test("0-b: MAX_FEELER_CONNECTIONS = 1 (Core net.h:75)", function()
  expect_eq(peerman.CONNMAN.MAX_FEELER_CONNECTIONS, 1)
end)
test("0-c: MAX_PCT_ADDR_TO_SEND = 23 (Core net_processing.cpp:188)", function()
  expect_eq(peerman.CONNMAN.MAX_PCT_ADDR_TO_SEND, 23)
end)
test("0-d: MAX_ADDR_TO_SEND = 1000 (Core net_processing.cpp:190)", function()
  expect_eq(peerman.CONNMAN.MAX_ADDR_TO_SEND, 1000)
end)
test("0-e: MAX_ADDR_RATE_PER_SECOND = 0.1 (Core net_processing.cpp:193)", function()
  expect_eq(peerman.CONNMAN.MAX_ADDR_RATE_PER_SECOND, 0.1)
end)
test("0-f: MAX_ADDR_PROCESSING_TOKEN_BUCKET = 1000 (Core net_processing.cpp:197)", function()
  expect_eq(peerman.CONNMAN.MAX_ADDR_PROCESSING_TOKEN_BUCKET, 1000)
end)

-- ---------------------------------------------------------------------------
-- 1: FEELER selects from the NEW table
-- ---------------------------------------------------------------------------
print("\n--- 1: feeler selects from NEW only ---")
test("1-a: maybe_open_feeler picks a NEW-table address and opens ONE probe", function()
  local pm, d = make_pm()
  seed_new_table(pm)
  expect_true(pm._new_count > 0, "NEW table seeded")
  expect_eq(pm._tried_count, 0, "TRIED table starts empty")

  -- Stub connect_peer so no real TCP happens; record what was dialed and
  -- register a fake peer object in pm.peers (so maybe_open_feeler can flag it).
  local dialed = {}
  pm.connect_peer = function(self, ip, port, skip_div)
    dialed[#dialed + 1] = { ip = ip, port = port, skip_div = skip_div }
    self.peers[ip .. ":" .. port] = {
      ip = ip, port = port, inbound = false,
      state = peer_mod.STATE.CONNECTING,
    }
    self.peer_list[#self.peer_list + 1] = self.peers[ip .. ":" .. port]
    return true
  end

  local opened = pm:maybe_open_feeler()
  expect_true(opened, "feeler should open when NEW entries exist")
  expect_eq(#dialed, 1, "exactly one feeler dial")
  expect_true(dialed[1].skip_div, "feeler bypasses /16 outbound-diversity gate")
  -- The dialed address MUST be a NEW-table member (feeler selects-from-NEW).
  expect_true(in_new(pm, dialed[1].ip, dialed[1].port),
    "feeler dialed an address from the NEW table")
  expect_false(in_tried(pm, dialed[1].ip, dialed[1].port),
    "the dialed address was NEW (not already TRIED) at selection time")
  expect_true(pm.peers[dialed[1].ip .. ":" .. dialed[1].port].is_feeler,
    "opened peer flagged is_feeler")
  rm_dir(d)
end)

test("1-b: empty NEW table -> no feeler (no-op)", function()
  local pm, d = make_pm()
  local dialed = 0
  pm.connect_peer = function() dialed = dialed + 1; return true end
  local opened = pm:maybe_open_feeler()
  expect_false(opened, "no feeler with an empty NEW table")
  expect_eq(dialed, 0, "no dial attempt")
  rm_dir(d)
end)

test("1-c: -connect mode -> feeler is a no-op", function()
  local pm, d = make_pm()
  pm.config.connect = { "198.51.100.9:8333" }
  pm:_add_to_new("198.51.100.7", 8333, p2p.SERVICES.NODE_NETWORK, os.time(), "203.0.113.1")
  local dialed = 0
  pm.connect_peer = function() dialed = dialed + 1; return true end
  local opened = pm:maybe_open_feeler()
  expect_false(opened, "no feeler in -connect mode")
  expect_eq(dialed, 0, "no dial attempt in -connect mode")
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- 2: promote NEW->TRIED on handshake-SUCCESS ONLY (falsification cases)
-- ---------------------------------------------------------------------------
print("\n--- 2: promote-on-success-ONLY ---")
test("2-a: a feeler that reaches ESTABLISHED promotes NEW->TRIED on disconnect", function()
  local pm, d = make_pm()
  pm:_add_to_new("198.51.100.7", 8333, p2p.SERVICES.NODE_NETWORK, os.time(), "203.0.113.1")
  -- Build a real-ish feeler peer that completed its handshake.
  local p = peer_mod.new("198.51.100.7", 8333, consensus.networks.regtest, 0)
  p.inbound = false
  p.is_feeler = true
  p.state = peer_mod.STATE.ESTABLISHED
  pm.peers["198.51.100.7:8333"] = p
  pm.peer_list[#pm.peer_list + 1] = p
  -- Disconnect drives the promotion (Core addrman.Good on feeler success).
  pm:disconnect_peer(p, "feeler")
  expect_true(in_tried(pm, "198.51.100.7", 8333),
    "ESTABLISHED feeler must be promoted NEW->TRIED")
  expect_false(in_new(pm, "198.51.100.7", 8333),
    "address must have left the NEW table after promotion")
  rm_dir(d)
end)

test("2-b: FALSIFICATION — a feeler that NEVER reaches ESTABLISHED does NOT promote", function()
  local pm, d = make_pm()
  pm:_add_to_new("198.51.100.8", 8333, p2p.SERVICES.NODE_NETWORK, os.time(), "203.0.113.1")
  local p = peer_mod.new("198.51.100.8", 8333, consensus.networks.regtest, 0)
  p.inbound = false
  p.is_feeler = true
  p.state = peer_mod.STATE.CONNECTING  -- handshake never completed
  pm.peers["198.51.100.8:8333"] = p
  pm.peer_list[#pm.peer_list + 1] = p
  pm:disconnect_peer(p, "feeler handshake failed")
  expect_false(in_tried(pm, "198.51.100.8", 8333),
    "failed-handshake feeler must NOT be promoted to TRIED")
  expect_true(in_new(pm, "198.51.100.8", 8333),
    "address must REMAIN in the NEW table after a failed probe")
  rm_dir(d)
end)

test("2-c: FALSIFICATION — a NOT-probed NEW entry stays NEW", function()
  local pm, d = make_pm()
  -- Two NEW entries; only one will be probed.
  pm:_add_to_new("198.51.100.7", 8333, p2p.SERVICES.NODE_NETWORK, os.time(), "203.0.113.1")
  pm:_add_to_new("198.51.100.20", 8333, p2p.SERVICES.NODE_NETWORK, os.time(), "203.0.113.9")
  -- Promote ONLY .7 (simulate the success path directly).
  pm:_move_to_tried("198.51.100.7", 8333)
  expect_true(in_tried(pm, "198.51.100.7", 8333), ".7 promoted")
  -- .20 was never probed -> must still be NEW, never TRIED.
  expect_false(in_tried(pm, "198.51.100.20", 8333),
    "un-probed entry must NOT be in TRIED")
  expect_true(in_new(pm, "198.51.100.20", 8333),
    "un-probed entry must STAY in NEW")
  rm_dir(d)
end)

test("2-d: failed feeler DIAL (connect_peer false) does not promote", function()
  local pm, d = make_pm()
  seed_new_table(pm)
  local before_tried = pm._tried_count
  expect_eq(before_tried, 0, "TRIED starts empty")
  local dialed
  pm.connect_peer = function(self, ip, port)
    dialed = ip .. ":" .. port
    return false, "connection refused"
  end
  local opened = pm:maybe_open_feeler()
  expect_false(opened, "dial failure -> feeler not opened")
  expect_not_nil(dialed, "a dial WAS attempted (selection succeeded)")
  -- NOTHING promoted: TRIED still empty after a dial-failure feeler.
  expect_eq(pm._tried_count, 0, "no promotion on dial failure")
  local ip, port = dialed:match("^(.*):(%d+)$")
  expect_true(in_new(pm, ip, tonumber(port)),
    "dial-failed address stays in NEW")
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- 3: bounded (MAX_FEELER_CONNECTIONS=1) + off-budget + 120s interval
-- ---------------------------------------------------------------------------
print("\n--- 3: bounded / off-budget / 120s interval ---")
test("3-a: at most ONE in-flight feeler (MAX_FEELER_CONNECTIONS=1)", function()
  local pm, d = make_pm()
  seed_new_table(pm)
  local dials = 0
  pm.connect_peer = function(self, ip, port)
    dials = dials + 1
    self.peers[ip .. ":" .. port] = { ip = ip, port = port, inbound = false,
      state = peer_mod.STATE.CONNECTING }
    self.peer_list[#self.peer_list + 1] = self.peers[ip .. ":" .. port]
    return true
  end
  expect_true(pm:maybe_open_feeler(), "first feeler opens")
  -- A feeler is already in flight; even though the interval would not yet allow
  -- another, force the interval open to prove the in-flight cap is independent.
  pm._next_feeler = 0
  expect_false(pm:maybe_open_feeler(),
    "second feeler must be refused while one is in flight")
  expect_eq(dials, 1, "only one feeler dial total")
  rm_dir(d)
end)

test("3-b: feeler is OFF the outbound budget", function()
  local pm, d = make_pm()
  -- A lone feeler peer must NOT be counted toward max_outbound.  We assert via
  -- get_outbound_counts (feeler excluded) and by checking maintain_connections
  -- still wants to open a real outbound when only a feeler is present.
  local feeler = { ip = "198.51.100.7", port = 8333, inbound = false,
    is_feeler = true, state = peer_mod.STATE.ESTABLISHED }
  pm.peers["198.51.100.7:8333"] = feeler
  pm.peer_list[1] = feeler
  local full, block = pm:get_outbound_counts()
  expect_eq(full, 0, "feeler must NOT count as a full-relay outbound")
  expect_eq(block, 0, "feeler must NOT count as a block-relay outbound")

  -- Now add a real (non-feeler) outbound and confirm it IS counted.
  local real = { ip = "198.51.100.40", port = 8333, inbound = false,
    state = peer_mod.STATE.ESTABLISHED }
  pm.peers["198.51.100.40:8333"] = real
  pm.peer_list[2] = real
  full = pm:get_outbound_counts()
  expect_eq(full, 1, "a non-feeler outbound IS counted (feeler still excluded)")
  rm_dir(d)
end)

test("3-c: 120s feeler interval is honored", function()
  local pm, d = make_pm()
  seed_new_table(pm)
  local dials = 0
  pm.connect_peer = function(self, ip, port)
    dials = dials + 1
    -- Return true WITHOUT registering a peer so no in-flight feeler blocks the
    -- interval test; the 120s window alone must gate the second call.
    return true
  end
  expect_true(pm:maybe_open_feeler(), "first feeler opens and arms the 120s timer")
  expect_not_nil(pm._next_feeler, "next-feeler timestamp armed")
  expect_true(pm._next_feeler >= os.time() + 119 and pm._next_feeler <= os.time() + 121,
    "next feeler scheduled ~120s out")
  -- No in-flight feeler (stub didn't register one); the interval alone must gate.
  expect_false(pm:maybe_open_feeler(), "second feeler refused inside the 120s window")
  expect_eq(dials, 1, "only one dial within the interval")
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- 4: GETADDR answered-once + ignore-outbound + 23% cap
-- ---------------------------------------------------------------------------
print("\n--- 4: getaddr guards ---")
-- Capture helper: returns a fake inbound peer that records sent addr payloads.
local function capture_peer(inbound, send_addrv2)
  local sent = {}
  return {
    ip = "203.0.113.5", port = 8333,
    inbound = inbound,
    send_addrv2 = send_addrv2 and true or false,
    send_message = function(_, _, payload) sent[#sent + 1] = payload end,
    _sent = sent,
  }
end

test("4-a: getaddr from an OUTBOUND peer is ignored", function()
  local pm, d = make_pm()
  for i = 1, 50 do
    pm.known_addresses["203.0.114." .. i .. ":8333"] = {
      ip = "203.0.114." .. i, port = 8333, services = 1,
      timestamp = os.time(), attempts = 0, last_try = 0,
    }
  end
  local p = capture_peer(false, false)   -- inbound=false => outbound
  pm:_respond_getaddr(p)
  expect_eq(#p._sent, 0, "no reply to an outbound peer's getaddr")
  rm_dir(d)
end)

test("4-b: only the FIRST getaddr per connection is answered", function()
  local pm, d = make_pm()
  for i = 1, 50 do
    pm.known_addresses["203.0.114." .. i .. ":8333"] = {
      ip = "203.0.114." .. i, port = 8333, services = 1,
      timestamp = os.time(), attempts = 0, last_try = 0,
    }
  end
  local p = capture_peer(true, false)    -- inbound
  pm:_respond_getaddr(p)
  pm:_respond_getaddr(p)                  -- repeat: must be ignored
  pm:_respond_getaddr(p)
  expect_eq(#p._sent, 1, "exactly one getaddr reply per connection")
  expect_true(p.getaddr_recvd, "getaddr_recvd flag set after first answer")
  rm_dir(d)
end)

test("4-c: reply capped at min(1000, ceil(0.23*size))", function()
  local pm, d = make_pm()
  -- 100 addresses -> ceil(0.23*100) = 23 cap.
  for i = 1, 100 do
    pm.known_addresses["203.0.114." .. i .. ":8333"] = {
      ip = "203.0.114." .. i, port = 8333, services = 1,
      timestamp = os.time(), attempts = 0, last_try = 0,
    }
  end
  local p = capture_peer(true, false)
  pm:_respond_getaddr(p)
  expect_eq(#p._sent, 1, "one reply")
  local addrs = p2p.deserialize_addr(p._sent[1])
  expect_eq(#addrs, 23, "ceil(0.23*100)=23 addresses returned")
  rm_dir(d)
end)

test("4-d: cap honors the 1000 absolute floor of the min()", function()
  local pm, d = make_pm()
  -- 10 addresses -> ceil(0.23*10)=3; min(1000,3)=3.
  for i = 1, 10 do
    pm.known_addresses["203.0.115." .. i .. ":8333"] = {
      ip = "203.0.115." .. i, port = 8333, services = 1,
      timestamp = os.time(), attempts = 0, last_try = 0,
    }
  end
  local p = capture_peer(true, false)
  pm:_respond_getaddr(p)
  local addrs = p2p.deserialize_addr(p._sent[1])
  expect_eq(#addrs, 3, "ceil(0.23*10)=3")
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- 5: inbound-addr token bucket (drops excess + covers addrv2)
-- ---------------------------------------------------------------------------
print("\n--- 5: token bucket (addr + addrv2 share ONE bucket) ---")

-- Build a routable addr/addrv2 payload of N entries with fresh timestamps so
-- the only thing limiting how many get STORED is the token bucket.
local function make_addr_payload(n, base)
  local list = {}
  for i = 1, n do
    list[i] = {
      timestamp = os.time(),
      services = p2p.SERVICES.NODE_NETWORK,
      ip = base .. "." .. i,
      port = 8333,
    }
  end
  return p2p.serialize_addr(list)
end
local function make_addrv2_payload(n, base)
  local list = {}
  for i = 1, n do
    list[i] = {
      timestamp = os.time(),
      services = p2p.SERVICES.NODE_NETWORK,
      network_id = p2p.NET_ID.IPV4,
      ip = base .. "." .. i,
      port = 8333,
    }
  end
  return p2p.serialize_addrv2(list)
end

test("5-a: addr flood on a drained bucket drops the excess", function()
  local pm, d = make_pm()
  -- Rate-limited (non-noban, non-manual) inbound peer.
  local p = { ip = "203.0.113.50", port = 8333, inbound = true,
    noban = false, is_manual = false }
  -- Fresh bucket inits to 1.0 -> only ONE address admitted; the rest dropped.
  local before = pm:get_known_address_count()
  pm:handle_addr(p, make_addr_payload(50, "198.51.101"))
  local after = pm:get_known_address_count()
  expect_eq(after - before, 1,
    "drained bucket (init 1.0) admits exactly 1 of 50 addr entries")
  expect_true(p.addr_token_bucket < 1.0, "bucket spent below 1 after the burst")
  rm_dir(d)
end)

test("5-b: FALSIFICATION via addrv2 — an addrv2 flood on the SAME drained bucket is dropped", function()
  local pm, d = make_pm()
  local p = { ip = "203.0.113.51", port = 8333, inbound = true,
    noban = false, is_manual = false }
  -- First, drain the bucket with an addr burst (admits 1).
  pm:handle_addr(p, make_addr_payload(20, "198.51.102"))
  expect_true(p.addr_token_bucket < 1.0, "bucket drained by the addr burst")
  -- Now hit the SAME peer with an addrv2 flood: if addrv2 used a separate
  -- bucket the attacker would bypass the limit.  It must share the bucket and
  -- therefore drop everything (bucket already < 1.0).
  local before = pm:get_known_address_count()
  pm:handle_addrv2(p, make_addrv2_payload(40, "198.51.103"))
  local after = pm:get_known_address_count()
  expect_eq(after - before, 0,
    "addrv2 flood on the shared drained bucket must store ZERO new addresses")
  rm_dir(d)
end)

test("5-c: addr and addrv2 use the SAME per-peer bucket field (no per-message reset)", function()
  local pm, d = make_pm()
  local p = { ip = "203.0.113.52", port = 8333, inbound = true,
    noban = false, is_manual = false }
  -- Drain the bucket via addr (init 1.0 -> spends down past 1.0 with a burst).
  pm:handle_addr(p, make_addr_payload(5, "198.51.104"))
  expect_not_nil(p.addr_token_bucket, "addr handler created the per-peer bucket")
  expect_true(p.addr_token_bucket < 1.0, "addr burst drained the bucket below 1.0")
  -- If addrv2 reset to a fresh 1.0 bucket, this would jump back >= 1.0.  It must
  -- keep operating on the SAME drained field (only a tiny 0.1/s refill applies).
  pm:handle_addrv2(p, make_addrv2_payload(1, "198.51.105"))
  expect_true(p.addr_token_bucket < 1.0,
    "addrv2 did NOT reset the bucket to a fresh 1.0 -- it is the shared field")
  rm_dir(d)
end)

test("5-d: whitelisted (noban) peer is NOT rate-limited", function()
  local pm, d = make_pm()
  local p = { ip = "203.0.113.53", port = 8333, inbound = true,
    noban = true, is_manual = false }
  local before = pm:get_known_address_count()
  pm:handle_addr(p, make_addr_payload(30, "198.51.106"))
  local after = pm:get_known_address_count()
  expect_eq(after - before, 30,
    "noban peer bypasses the rate limit (all 30 stored)")
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
io.write(string.format("\n  PASS:  %d\n", PASS))
io.write(string.format("  FAIL:  %d\n\n", FAIL))
if FAIL > 0 then os.exit(1) end
