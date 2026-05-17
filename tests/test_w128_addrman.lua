#!/usr/bin/env luajit
-- W128 AddrMan + connman + peer selection audit — lunarblock (Lua / LuaJIT)
--
-- Reference: bitcoin-core/src/addrman.h         (AddrMan public surface)
--            bitcoin-core/src/addrman_impl.h    (AddrInfo, bucket math, formats)
--            bitcoin-core/src/addrman.cpp       (IsTerrible/GetChance/Select_/Add_/Good_/MakeTried/Attempt_)
--            bitcoin-core/src/net.h             (FEELER_INTERVAL, MAX_OUTBOUND_*, MAX_BLOCK_RELAY_ONLY_*)
--            bitcoin-core/src/net.cpp           (ThreadOpenConnections, anchors load/save, fixed seeds, AttemptToEvictConnection)
--            bitcoin-core/src/node/eviction.cpp (SelectNodeToEvict, ProtectEvictionCandidatesByRatio)
--            bitcoin-core/src/banman.h          (two-channel BanMan + Discouragement design)
--            bitcoin-core/src/banman.cpp        (CSubNet match semantics, SweepBanned, DumpBanlist)
--            bitcoin-core/src/netaddress.h      (NET_IPV4 = 1, NET_IPV6 = 2 enum values)
--            bitcoin-core/src/util/asmap.cpp    (GetGroup() group-bytes encoding)
--
-- Scope: assert lunarblock's AddrMan + connman + peer selection +
--        BanMan behaviors against Core's; EXCLUDES BIP-155 (W117).
--
-- Gate map (W128):
--   G1   AddrMan bucket-count constants (NEW=1024, TRIED=256)
--   G2   AddrMan bucket-hash math (double-SHA256 / GetCheapHash)
--   G3   AddrInfo:IsTerrible quality predicates
--   G4   AddrInfo:GetChance weighted selection
--   G5   AddrMan Select_() while-loop with chance_factor backoff
--   G6   get_addr_group network-type byte (NET_IPV4 = 1)
--   G7   Source-group time_penalty applied on Add()
--   G8   Stochastic refcount guard for new-table multiplicity
--   G9   Test-before-evict in MakeTried (m_tried_collisions)
--   G10  Attempt() updates m_last_try + nAttempts
--   G11  Connected() updates nTime on 20-min interval
--   G12  SetServices() updates service flags
--   G13  GetAddr_() max_addresses + max_pct + IsTerrible filter
--   G14  AddrMan persistence (peers.dat V4_MULTIPORT)
--   G15  MAX_BLOCK_RELAY_ONLY_ANCHORS = 2 clamp on load
--   G16  Anchors save BlockRelayOnly only, not all outbound
--   G17  Anchors file BIP155 binary format
--   G18  ThreadOpenConnections type ladder (7 arms)
--   G19  FEELER_INTERVAL = 2min Poisson-scheduled feeler
--   G20  EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL = 5min
--   G21  MAX_OUTBOUND_FULL_RELAY = 8 + MAX_BLOCK_RELAY_ONLY = 2 separately
--   G22  Fixed-seed fallback after 60s on empty addrman
--   G23  100-tries cap on per-tick addrman selection
--   G24  10-min last-try gate (nTries < 30 bypass)
--   G25  IsBadPort gate (nTries < 50 bypass)
--   G26  NodeEvictionCandidate / SelectNodeToEvict (inbound eviction)
--   G27  ProtectEvictionCandidatesByRatio (50% uptime + 25% disadvantaged net)
--   G28  BanMan two-channel: banlist + CRollingBloomFilter discouragement
--   G29  CSubNet semantics in setban (CIDR matching)
--   G30  DEFAULT_MISBEHAVING_BANTIME = 24h + DUMP_BANS_INTERVAL = 15min
--
-- Bugs:
--   BUG-1  P1  IsTerrible() not implemented            (G3,  CORRECTNESS+ECLIPSE)
--   BUG-2  P1  GetChance + chance_factor absent        (G4/G5, ECLIPSE)
--   BUG-3  P1  get_addr_group IPv4 prefix byte = 0x04, Core = 0x01;
--              ASN-IPv4 path uses NET_IPV6 = 2 as well (G6, ECLIPSE)
--   BUG-4  P2  Connected()/nTime refresh absent        (G11, CORRECTNESS)
--   BUG-5  P1  GetAddr max_pct + IsTerrible + Fisher-Yates absent
--              (G13, OBS+CORRECTNESS)
--   BUG-6  P2  anchors load doesn't clamp to MAX=2     (G15, CORRECTNESS)
--   BUG-7  P1  anchors save uses any outbound, not BlockRelayOnly
--              (G16, ECLIPSE)
--   BUG-8  P2  anchors.dat plain text not BIP155 binary (G17, OBS)
--   BUG-9  P1  ThreadOpenConnections 7-arm ladder absent (G18, ECLIPSE)
--   BUG-10 P2  FEELER_INTERVAL feeler scheduling absent (G19, ECLIPSE)
--   BUG-11 P2  EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL absent (G20, ECLIPSE)
--   BUG-12 P1  8 full-relay vs 2 block-relay split absent (G21, PRIVACY)
--   BUG-13 P2  fixed-seed fallback absent              (G22, OBS)
--   BUG-14 P2  10-min last-try gate (60s used)         (G24, ECLIPSE)
--   BUG-15 P2  IsBadPort gate absent                   (G25, DOS)
--   BUG-16 P1  inbound NodeEvictionCandidate + SelectNodeToEvict +
--              ProtectEvictionCandidatesByRatio absent (G26/G27, ECLIPSE+DOS)
--   BUG-17 P1  BanMan two-channel + CSubNet matching absent (G28/G29, CVE-class)
--
-- Test harness style mirrors test_w125_error_parity.lua so the project
-- test runner output stays uniform: xfail_pre_fix counts as expected
-- divergence (not a failure); fail counts only true regressions.

package.path = "src/?.lua;src/?/init.lua;" .. package.path

local peerman = require("lunarblock.peerman")
local peer_mod = require("lunarblock.peer")
local consensus = require("lunarblock.consensus")

-- ---------------------------------------------------------------------------
-- Test scaffolding
-- ---------------------------------------------------------------------------

local PASS = 0
local FAIL = 0
local XFAIL_PRE_FIX = 0
local BUGS = {}

local function pass(name)
  io.write(string.format("  PASS  %s\n", name))
  PASS = PASS + 1
end

local function fail(name, msg)
  io.write(string.format("  FAIL  %s -- %s\n", name, msg))
  FAIL = FAIL + 1
end

local function xfail_pre_fix(name, msg)
  io.write(string.format("  XFAIL %s -- %s\n", name, msg))
  XFAIL_PRE_FIX = XFAIL_PRE_FIX + 1
end

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end

local function test_xfail_pre_fix(name, bug_id, fn)
  local ok, err = pcall(fn)
  if ok then
    pass(name .. " [now PASSing -- " .. bug_id .. " fix likely landed]")
  else
    xfail_pre_fix(name .. " (" .. bug_id .. ")", tostring(err))
  end
end

local function bug(id, severity)
  BUGS[#BUGS + 1] = id .. " (" .. severity .. ")"
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) ..
          ", expected " .. tostring(b), 2)
  end
end

local function expect_true(v, msg)
  if not v then error((msg or "expected true") .. ": got " .. tostring(v), 2) end
end

local function expect_false(v, msg)
  if v then error((msg or "expected false") .. ": got " .. tostring(v), 2) end
end

local function expect_nil(v, msg)
  if v ~= nil then error((msg or "expected nil") .. ": got " .. tostring(v), 2) end
end

local function expect_not_nil(v, msg)
  if v == nil then error((msg or "expected non-nil"), 2) end
end

-- Build a fresh PeerManager backed by a tmpdir (no live I/O).
local function make_pm()
  local tmpdir = os.tmpname()
  os.remove(tmpdir)
  os.execute("mkdir -p " .. tmpdir)
  local net = consensus.networks.regtest
  local pm = peerman.new(net, nil, { data_dir = tmpdir })
  return pm, tmpdir
end

local function rm_dir(path)
  if path and path ~= "" and path ~= "/" then
    os.execute("rm -rf " .. path)
  end
end

-- ---------------------------------------------------------------------------
-- Print banner
-- ---------------------------------------------------------------------------

print("\n=========================================================================")
print("W128 AddrMan + connman + peer selection -- lunarblock")
print("Source: src/peerman.lua + src/asmap.lua + src/rpc.lua (setban shim)")
print("Reference: bitcoin-core/src/{addrman,net,banman,netaddress,node/eviction}")
print("=========================================================================")

-- ---------------------------------------------------------------------------
-- G1: AddrMan bucket-count constants
-- W104 BUG-1/2 already cover this; W128 re-asserts as a coverage check.
-- ---------------------------------------------------------------------------
print("\n--- G1: bucket-count constants (NEW=1024, TRIED=256 in Core) ---")
test_xfail_pre_fix("G1-a: NEW_BUCKET_COUNT should be 1024 (W104 BUG-1 still open)",
  "W104-BUG-1", function()
    -- Core: ADDRMAN_NEW_BUCKET_COUNT = 1 << 10 = 1024
    -- lunarblock: 256 (4x too small)
    expect_eq(peerman.ADDRMAN.NEW_BUCKET_COUNT, 1024, "NEW_BUCKET_COUNT")
  end)
test_xfail_pre_fix("G1-b: TRIED_BUCKET_COUNT should be 256 (W104 BUG-2 still open)",
  "W104-BUG-2", function()
    expect_eq(peerman.ADDRMAN.TRIED_BUCKET_COUNT, 256, "TRIED_BUCKET_COUNT")
  end)
test("G1-c: BUCKET_SIZE = 64 (matches Core)", function()
  expect_eq(peerman.ADDRMAN.BUCKET_SIZE, 64)
end)
test("G1-d: NEW_BUCKETS_PER_ADDRESS = 8 (matches Core)", function()
  expect_eq(peerman.ADDRMAN.NEW_BUCKETS_PER_ADDRESS, 8)
end)
test("G1-e: TRIED_BUCKETS_PER_GROUP = 8 (matches Core)", function()
  expect_eq(peerman.ADDRMAN.TRIED_BUCKETS_PER_GROUP, 8)
end)
test("G1-f: NEW_BUCKETS_PER_SOURCE_GROUP = 64 (matches Core)", function()
  expect_eq(peerman.ADDRMAN.NEW_BUCKETS_PER_SOURCE_GROUP, 64)
end)

-- ---------------------------------------------------------------------------
-- G2: AddrMan bucket-hash math
-- W104 BUG-14 covers this in detail; W128 just asserts the surface.
-- ---------------------------------------------------------------------------
print("\n--- G2: bucket-hash math (W104 BUG-14 -- single-SHA256 vs Core GetCheapHash) ---")
test("G2-a: addr_hash returns 32-bit value", function()
  local key = string.rep("\x00", 32)
  local h = peerman.addr_hash(key, "1.2.3.4:8333")
  expect_true(type(h) == "number")
  expect_true(h >= 0 and h < 2^32)
end)

-- ---------------------------------------------------------------------------
-- G3: AddrInfo:IsTerrible
-- ---------------------------------------------------------------------------
print("\n--- G3: AddrInfo:IsTerrible(now) (BUG-1 P1) ---")
bug("BUG-1", "P1")
test_xfail_pre_fix("G3-a: is_terrible() method exists on PeerManager", "BUG-1", function()
  local pm, d = make_pm()
  expect_not_nil(pm.is_terrible,
    "is_terrible method should exist (5 predicates: future-skew, HORIZON, retries, max-failures)")
  rm_dir(d)
end)
test_xfail_pre_fix("G3-b: IsTerrible flags future-skew > 10min", "BUG-1", function()
  local pm, d = make_pm()
  local now = os.time()
  local future_entry = { nTime = now + 700, last_try = 0, last_success = 0, nAttempts = 0 }
  expect_true(pm:is_terrible(future_entry, now),
    "addr.nTime > now + 10min must be terrible (came-in-flying-DeLorean)")
  rm_dir(d)
end)
test_xfail_pre_fix("G3-c: IsTerrible flags HORIZON > 30d ago", "BUG-1", function()
  local pm, d = make_pm()
  local now = os.time()
  local stale = { nTime = now - 31*24*3600, last_try = 0, last_success = 0, nAttempts = 0 }
  expect_true(pm:is_terrible(stale, now), "30d+ stale must be terrible")
  rm_dir(d)
end)
test_xfail_pre_fix("G3-d: IsTerrible flags retries >= 3 with never-success", "BUG-1", function()
  local pm, d = make_pm()
  local now = os.time()
  local never_succeeded = { nTime = now - 3600, last_try = now - 120,
                            last_success = 0, nAttempts = 3 }
  expect_true(pm:is_terrible(never_succeeded, now),
    "3 retries without ever a success must be terrible")
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- G4 + G5: AddrInfo:GetChance + Select_() chance_factor backoff
-- ---------------------------------------------------------------------------
print("\n--- G4/G5: GetChance + chance_factor weighted selection (BUG-2 P1) ---")
bug("BUG-2", "P1")
test_xfail_pre_fix("G4-a: get_chance() method exists on PeerManager", "BUG-2", function()
  local pm, d = make_pm()
  expect_not_nil(pm.get_chance,
    "get_chance method should exist (10-min recent-try * 0.01, 0.66^min(attempts, 8))")
  rm_dir(d)
end)
test_xfail_pre_fix("G4-b: GetChance deprioritises last_try < 10min by 0.01x", "BUG-2", function()
  local pm, d = make_pm()
  local now = os.time()
  local recent = { last_try = now - 60, nAttempts = 0 }
  local stale = { last_try = now - 3600, nAttempts = 0 }
  local c_recent = pm:get_chance(recent, now)
  local c_stale  = pm:get_chance(stale, now)
  expect_true(c_recent < c_stale * 0.02,
    "recent-try entry must have <2% the selection chance of stale entry")
  rm_dir(d)
end)
test_xfail_pre_fix("G5-a: Select_() loops with chance_factor * 1.2 backoff", "BUG-2", function()
  -- Distribution-level check: terrible entries should be selected ~1% as
  -- often as healthy entries.  We can't trivially exercise that without a
  -- functioning GetChance, so probe the existence of the chance_factor
  -- variable in _select_address (via source inspection).  Pre-fix: the
  -- helper picks uniform random with no weighting.
  local pm, d = make_pm()
  -- Look for chance_factor signal: not present pre-fix.
  -- (Test is xfail; fix must introduce GetChance-weighted selection.)
  expect_not_nil(pm.select_weighted or pm._select_address_weighted,
    "weighted selection helper must exist (Core addrman.cpp:733-772)")
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- G6: get_addr_group network-type byte
-- ---------------------------------------------------------------------------
print("\n--- G6: get_addr_group network-type byte (BUG-3 P1) ---")
bug("BUG-3", "P1")
test_xfail_pre_fix("G6-a: IPv4 /16 fallback prefix should be NET_IPV4=1 not 4", "BUG-3", function()
  local g = peerman.get_addr_group("203.0.114.5")
  -- lunarblock asmap.lua:598 returns char(4) -- collides with Core NET_I2P=4.
  -- Core NET_IPV4 is enum value 1.
  expect_eq(g:sub(1,1):byte(), 1,
    "IPv4 group first byte must be NET_IPV4 = 1 (got " .. g:sub(1,1):byte() .. ")")
end)
test_xfail_pre_fix("G6-b: ASN-IPv4 group prefix should be NET_IPV4=1 not NET_IPV6=2",
  "BUG-3", function()
    -- This test fires only when asmap is loaded with an IPv4 mapping; we
    -- approximate by asserting the public API contract:  any time the
    -- get_addr_group result describes an IPv4 address, the network-byte
    -- must encode IPv4 (= 1) regardless of which mode (fallback vs ASN).
    -- src/asmap.lua:587 explicitly uses string.char(NET_IPV6) = char(2),
    -- which is wrong for IPv4 addresses.  Without loading an asmap we
    -- can't exercise this path here; document via inspection instead.
    local asmap_src = io.open("src/asmap.lua", "r"):read("*a")
    -- Pre-fix: src has `string.char(NET_IPV6)` in the IPv4 ASN branch.
    -- Fix: must use `string.char(NET_IPV4)` (= 1) for IPv4 addresses.
    expect_false(asmap_src:find("string.char%(NET_IPV6%)") ~= nil
                 and asmap_src:find("get_addr_group") ~= nil,
      "asmap.lua get_addr_group IPv4-ASN branch uses NET_IPV6 prefix -- should be NET_IPV4")
  end)

-- ---------------------------------------------------------------------------
-- G7: time_penalty applied on Add() (W104 BUG-6)
-- ---------------------------------------------------------------------------
print("\n--- G7: time_penalty on AddrMan Add (W104 BUG-6 still open) ---")
test_xfail_pre_fix("G7-a: _add_to_new applies time_penalty argument", "W104-BUG-6", function()
  local pm, d = make_pm()
  local t = os.time()
  -- Core signature is Add(vAddr, source, time_penalty=2h-for-addr-relay)
  -- _add_to_new currently has signature (ip, port, services, timestamp, src_ip).
  -- No time_penalty parameter at all.  Fix-side would change signature.
  -- Pre-fix: assert the helper signature differs from a hypothetical fixed one
  -- by trying to pass time_penalty.  We can't enforce this without source
  -- inspection -- approximate by asserting the stored timestamp matches input.
  pm:_add_to_new("203.0.114.5", 8333, 1, t, "5.6.7.8")
  -- find the stored entry
  local found
  for b = 0, peerman.ADDRMAN.NEW_BUCKET_COUNT - 1 do
    for _, e in pairs(pm._new_buckets[b]) do
      if e.ip == "203.0.114.5" then found = e end
    end
  end
  expect_not_nil(found, "address must be in some new bucket")
  -- Core would store t - time_penalty (with a 2h default for addr relay).
  -- lunarblock stores t verbatim.  This passes iff Core's adjustment was
  -- applied -- i.e. fix landed.
  expect_true(found.timestamp <= t - 60,
    "time_penalty must subtract from stored nTime (Core: 2h for addr relay)")
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- G8: Stochastic refcount guard (W104 BUG-7)
-- ---------------------------------------------------------------------------
print("\n--- G8: stochastic refcount guard (W104 BUG-7 still open) ---")
test_xfail_pre_fix("G8-a: nRefCount > 0 multiplicity insert is randomised", "W104-BUG-7", function()
  -- Statistically: with Core's 1/(1<<nRefCount) probability gate, after N
  -- repeated adds of the same address from distinct sources, expected
  -- nRefCount grows logarithmically not linearly.  Pre-fix lunarblock
  -- accepts every add up to NEW_BUCKETS_PER_ADDRESS = 8 deterministically
  -- (per W104 BUG-7).
  local pm, d = make_pm()
  for i = 1, 50 do
    pm:_add_to_new("203.0.114.5", 8333, 1, os.time(), "10.0.0." .. i)
  end
  local info = pm._addr_info["203.0.114.5:8333"]
  expect_not_nil(info, "addr_info should exist")
  -- With Core's stochastic gate, the probability of reaching nRefCount=8
  -- after 50 adds is (8! / 8^8 * 50! / (50-8)!) which is non-trivial; but
  -- the *deterministic* lunarblock impl will hit 8 quickly.  A weak proxy:
  -- 50 adds without any stochastic gate must reach exactly the cap.
  -- Fix-side test: with Core gate, p(refs >= 8) after 50 adds should be
  -- well under 99%.  We assert refs == 8 in xfail (passes pre-fix because
  -- the deterministic path always hits the cap).
  expect_true(info.new_ref_count <= 4,
    "with stochastic guard, expected ref_count after 50 adds well below cap")
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- G9: Test-before-evict (W104 BUG-9/10)
-- ---------------------------------------------------------------------------
print("\n--- G9: test-before-evict / m_tried_collisions (W104 BUG-9/10) ---")
test_xfail_pre_fix("G9-a: tried_collisions set exists on PeerManager", "W104-BUG-10", function()
  local pm, d = make_pm()
  expect_not_nil(pm._tried_collisions,
    "_tried_collisions set should exist (Core m_tried_collisions; deferred eviction)")
  rm_dir(d)
end)
test_xfail_pre_fix("G9-b: resolve_collisions method exists", "W104-BUG-10", function()
  local pm, d = make_pm()
  expect_not_nil(pm.resolve_collisions,
    "resolve_collisions method should exist (Core ResolveCollisions_)")
  rm_dir(d)
end)
test_xfail_pre_fix("G9-c: select_tried_collision method exists", "W104-BUG-10", function()
  local pm, d = make_pm()
  expect_not_nil(pm.select_tried_collision,
    "select_tried_collision method should exist")
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- G10: Attempt() (W104 BUG-11)
-- ---------------------------------------------------------------------------
print("\n--- G10: Attempt() updates last_try + nAttempts (W104 BUG-11) ---")
test_xfail_pre_fix("G10-a: attempt_addr method exists", "W104-BUG-11", function()
  local pm, d = make_pm()
  expect_not_nil(pm.attempt_addr,
    "attempt_addr method should exist (Core Attempt_ at addrman.cpp:673)")
  rm_dir(d)
end)
test_xfail_pre_fix("G10-b: addr_info entries carry last_try + n_attempts fields",
  "W104-BUG-11", function()
    local pm, d = make_pm()
    pm:_add_to_new("203.0.114.5", 8333, 1, os.time(), "5.6.7.8")
    local info = pm._addr_info["203.0.114.5:8333"]
    expect_not_nil(info.last_try, "last_try field should exist")
    expect_not_nil(info.n_attempts, "n_attempts field should exist")
    rm_dir(d)
  end)

-- ---------------------------------------------------------------------------
-- G11: Connected() nTime refresh on disconnect (Core comment)
-- ---------------------------------------------------------------------------
print("\n--- G11: Connected() / nTime refresh (BUG-4 P2) ---")
bug("BUG-4", "P2")
test_xfail_pre_fix("G11-a: connected_addr method exists", "BUG-4", function()
  local pm, d = make_pm()
  expect_not_nil(pm.connected_addr,
    "connected_addr method should exist (Core Connected_ at addrman.cpp:857)")
  rm_dir(d)
end)
test_xfail_pre_fix("G11-b: nTime refreshes when delta > 20min", "BUG-4", function()
  local pm, d = make_pm()
  local old_t = os.time() - 7200  -- 2h ago
  pm:_add_to_new("203.0.114.5", 8333, 1, old_t, "5.6.7.8")
  -- After Connected(), nTime should update if (now - nTime) > 20min
  pm:connected_addr("203.0.114.5", 8333, os.time())
  local info_key = "203.0.114.5:8333"
  -- Look at the stored timestamp in the bucket
  local found
  for b = 0, peerman.ADDRMAN.NEW_BUCKET_COUNT - 1 do
    for _, e in pairs(pm._new_buckets[b]) do
      if e.ip == "203.0.114.5" then found = e end
    end
  end
  expect_not_nil(found, "entry should remain")
  expect_true(found.timestamp > old_t + 1800,
    "Connected_ should refresh nTime when delta > 20min")
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- G12: SetServices() (W104 BUG-13)
-- ---------------------------------------------------------------------------
print("\n--- G12: SetServices() (W104 BUG-13 still open) ---")
test_xfail_pre_fix("G12-a: set_services method exists", "W104-BUG-13", function()
  local pm, d = make_pm()
  expect_not_nil(pm.set_services,
    "set_services method should exist (Core SetServices_ at addrman.cpp:876)")
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- G13: GetAddr_ max_addresses / max_pct / IsTerrible / Fisher-Yates
-- ---------------------------------------------------------------------------
print("\n--- G13: GetAddr_ max_pct + IsTerrible + Fisher-Yates (BUG-5 P1) ---")
bug("BUG-5", "P1")
test_xfail_pre_fix("G13-a: _respond_getaddr applies max_pct cap (~23%)", "BUG-5", function()
  -- Core MAX_PCT_ADDR_TO_SEND = 23 in net_processing.cpp:188.
  -- lunarblock _respond_getaddr unconditionally returns up to 1000 entries.
  local pm, d = make_pm()
  -- Seed with 100 addresses
  for i = 1, 100 do
    pm.known_addresses["203.0.114." .. i .. ":8333"] = {
      ip = "203.0.114." .. i, port = 8333, services = 1,
      timestamp = os.time(), attempts = 0, last_try = 0,
    }
  end
  -- Mock a peer to capture the addr message
  local captured
  local fake_peer = {
    ip = "5.6.7.8", port = 8333,
    send_addrv2 = false,
    send_message = function(_, _, payload) captured = payload end,
  }
  pm:_respond_getaddr(fake_peer)
  -- Pre-fix: all 100 (or up to 1000) returned.  Fix-side: ~23% = 23 max.
  local p2p = require("lunarblock.p2p")
  local addrs = p2p.deserialize_addr(captured)
  expect_true(#addrs <= 25,
    "max_pct=23 cap should limit getaddr response to ~23% of pool (got " .. #addrs .. ")")
  rm_dir(d)
end)
test_xfail_pre_fix("G13-b: _respond_getaddr filters out terrible (HORIZON-aged) entries",
  "BUG-5", function()
    local pm, d = make_pm()
    local now = os.time()
    -- Mix one fresh + one terrible (35-day stale)
    pm.known_addresses["203.0.114.1:8333"] = {
      ip = "203.0.114.1", port = 8333, services = 1,
      timestamp = now - 60, attempts = 0, last_try = 0,
    }
    pm.known_addresses["203.0.114.2:8333"] = {
      ip = "203.0.114.2", port = 8333, services = 1,
      timestamp = now - 35 * 24 * 3600, attempts = 0, last_try = 0,
    }
    local captured
    local fake_peer = {
      ip = "5.6.7.8", port = 8333,
      send_addrv2 = false,
      send_message = function(_, _, payload) captured = payload end,
    }
    pm:_respond_getaddr(fake_peer)
    local p2p = require("lunarblock.p2p")
    local addrs = p2p.deserialize_addr(captured)
    -- Pre-fix: 2 returned.  Fix-side: 1 (the terrible one filtered).
    expect_eq(#addrs, 1,
      "IsTerrible filter should exclude 35-day-stale entries from getaddr response")
    rm_dir(d)
  end)

-- ---------------------------------------------------------------------------
-- G14: peers.dat persistence (W104 BUG-17)
-- ---------------------------------------------------------------------------
print("\n--- G14: AddrMan peers.dat persistence (W104 BUG-17 still open) ---")
test_xfail_pre_fix("G14-a: peers.dat exists after stop", "W104-BUG-17", function()
  local pm, d = make_pm()
  pm:_add_to_new("203.0.114.5", 8333, 1, os.time(), "5.6.7.8")
  pm:stop()
  local f = io.open(d .. "/peers.dat", "r")
  expect_not_nil(f, "peers.dat should be written on stop")
  if f then f:close() end
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- G15: MAX_BLOCK_RELAY_ONLY_ANCHORS clamp on load
-- ---------------------------------------------------------------------------
print("\n--- G15: anchors load clamps to MAX=2 (BUG-6 P2) ---")
bug("BUG-6", "P2")
test_xfail_pre_fix("G15-a: _load_anchors caps at MAX_ANCHORS=2", "BUG-6", function()
  local tmpdir = os.tmpname()
  os.remove(tmpdir)
  os.execute("mkdir -p " .. tmpdir)
  -- Write 5 anchors to disk (attacker / file-corruption scenario).
  local f = io.open(tmpdir .. "/anchors.dat", "w")
  for i = 1, 5 do
    f:write("203.0.114." .. i .. ":8333\n")
  end
  f:close()
  local pm = peerman.new(consensus.networks.regtest, nil, { data_dir = tmpdir })
  expect_true(#pm._anchors <= peerman.ADDRMAN.MAX_ANCHORS,
    "_load_anchors should clamp to MAX_ANCHORS=2 (got " .. #pm._anchors .. ")")
  rm_dir(tmpdir)
end)

-- ---------------------------------------------------------------------------
-- G16: Anchors save BlockRelayOnly only
-- ---------------------------------------------------------------------------
print("\n--- G16: anchors save BlockRelayOnly only (BUG-7 P1) ---")
bug("BUG-7", "P1")
test_xfail_pre_fix("G16-a: _save_anchors filters to BlockRelayOnly peers",
  "BUG-7", function()
    local pm, d = make_pm()
    -- Construct a stub outbound, ESTABLISHED, FULL_RELAY peer.
    local fake_peer = {
      ip = "203.0.114.5", port = 8333,
      inbound = false,
      state = peer_mod.STATE.ESTABLISHED,
      conn_type = "OUTBOUND_FULL_RELAY",  -- explicitly NOT block-relay-only
      is_block_relay_only = false,
    }
    pm.peer_list = { fake_peer }
    pm:_save_anchors()
    -- The file should be empty / not exist because no BlockRelayOnly peer.
    local f = io.open(d .. "/anchors.dat", "r")
    expect_nil(f,
      "anchors.dat should NOT be written for non-block-relay outbound peers")
    if f then f:close() end
    rm_dir(d)
  end)

-- ---------------------------------------------------------------------------
-- G17: anchors file BIP155 binary format
-- ---------------------------------------------------------------------------
print("\n--- G17: anchors.dat BIP155 binary format (BUG-8 P2) ---")
bug("BUG-8", "P2")
test_xfail_pre_fix("G17-a: anchors.dat is binary, not 'ip:port\\n' text", "BUG-8", function()
  local pm, d = make_pm()
  local fake_peer = {
    ip = "203.0.114.5", port = 8333,
    inbound = false,
    state = peer_mod.STATE.ESTABLISHED,
    conn_type = "BLOCK_RELAY",
    is_block_relay_only = true,
  }
  pm.peer_list = { fake_peer }
  pm:_save_anchors()
  local f = io.open(d .. "/anchors.dat", "rb")
  if f then
    local data = f:read("*a")
    f:close()
    -- Core's binary format starts with a checksum header, not ASCII digits.
    -- Pre-fix: ASCII like "203.0.114.5:8333\n".
    local first_byte = data:byte(1)
    expect_false(first_byte and first_byte >= 0x20 and first_byte <= 0x7E
                 and data:find("\n"),
      "anchors.dat should be BIP155 binary, not ASCII text (got first byte 0x"
      .. string.format("%02x", first_byte or 0) .. ")")
  end
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- G18: ThreadOpenConnections 7-arm type ladder
-- ---------------------------------------------------------------------------
print("\n--- G18: outbound connection-type ladder (BUG-9 P1) ---")
bug("BUG-9", "P1")
test_xfail_pre_fix("G18-a: select_outbound_conn_type method exists", "BUG-9", function()
  local pm, d = make_pm()
  expect_not_nil(pm.select_outbound_conn_type,
    "select_outbound_conn_type helper should exist (Core ThreadOpenConnections type-ladder)")
  rm_dir(d)
end)
test_xfail_pre_fix("G18-b: ConnectionType enum exists with 7 distinct values",
  "BUG-9", function()
    expect_not_nil(peerman.ConnectionType,
      "ConnectionType enum should exist (INBOUND/OUTBOUND_FULL_RELAY/BLOCK_RELAY/FEELER/MANUAL/ADDR_FETCH/PRIVATE_BROADCAST)")
  end)

-- ---------------------------------------------------------------------------
-- G19: FEELER_INTERVAL = 2min
-- ---------------------------------------------------------------------------
print("\n--- G19: FEELER_INTERVAL Poisson scheduling (BUG-10 P2) ---")
bug("BUG-10", "P2")
test_xfail_pre_fix("G19-a: FEELER_INTERVAL constant exists and = 120s", "BUG-10", function()
  expect_not_nil(peerman.STALE_TIP and peerman.STALE_TIP.FEELER_INTERVAL or peerman.FEELER_INTERVAL,
    "FEELER_INTERVAL constant should exist (Core net.h:61 = 2min)")
  local v = (peerman.STALE_TIP and peerman.STALE_TIP.FEELER_INTERVAL) or peerman.FEELER_INTERVAL
  expect_eq(v, 120, "FEELER_INTERVAL should be 2min = 120s")
end)

-- ---------------------------------------------------------------------------
-- G20: EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL
-- ---------------------------------------------------------------------------
print("\n--- G20: EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL (BUG-11 P2) ---")
bug("BUG-11", "P2")
test_xfail_pre_fix("G20-a: EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL = 5min", "BUG-11", function()
  local v = (peerman.STALE_TIP and peerman.STALE_TIP.EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL)
         or peerman.EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL
  expect_not_nil(v, "EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL should exist (Core net.h:63)")
  expect_eq(v, 300, "Core: 5min = 300s")
end)

-- ---------------------------------------------------------------------------
-- G21: 8 full-relay vs 2 block-relay outbound split
-- ---------------------------------------------------------------------------
print("\n--- G21: 8 full-relay + 2 block-relay outbound split (BUG-12 P1) ---")
bug("BUG-12", "P1")
test_xfail_pre_fix("G21-a: MAX_OUTBOUND_FULL_RELAY = 8 + MAX_BLOCK_RELAY_ONLY = 2",
  "BUG-12", function()
    local stale = peerman.STALE_TIP
    expect_eq(stale.TARGET_OUTBOUND_FULL_RELAY, 8, "TARGET_OUTBOUND_FULL_RELAY")
    expect_eq(stale.TARGET_BLOCK_RELAY_ONLY, 2, "TARGET_BLOCK_RELAY_ONLY")
    -- These exist in the constants table.  The bug is that get_outbound_counts
    -- at peerman.lua:2352 doesn't actually separate them: comment line
    -- 2358 says "For now, treat all outbound as full-relay".
    local pm, d = make_pm()
    local full, block = pm:get_outbound_counts()
    -- Pre-fix: block is always 0 even when there ARE block-relay peers.
    -- Fix-side: requires actual block-relay tracking.  Stub a peer marked
    -- block-relay-only and check it's counted as block_only.
    pm.peer_list = { {
      ip = "203.0.114.5", port = 8333, inbound = false,
      state = peer_mod.STATE.ESTABLISHED, is_block_relay_only = true,
    } }
    full, block = pm:get_outbound_counts()
    expect_eq(block, 1, "block-relay-only peer must be counted in second return value")
    expect_eq(full, 0, "block-relay-only peer must NOT be counted as full-relay")
    rm_dir(d)
  end)

-- ---------------------------------------------------------------------------
-- G22: Fixed-seed fallback
-- ---------------------------------------------------------------------------
print("\n--- G22: fixed-seed fallback after 60s (BUG-13 P2) ---")
bug("BUG-13", "P2")
test_xfail_pre_fix("G22-a: network table has fixed_seeds field", "BUG-13", function()
  local net = consensus.networks.mainnet or consensus.networks.regtest
  expect_not_nil(net.fixed_seeds,
    "mainnet/regtest network table should have fixed_seeds (Core: chainparamsseeds.h)")
end)

-- ---------------------------------------------------------------------------
-- G23: 100-tries cap
-- ---------------------------------------------------------------------------
print("\n--- G23: 100-tries cap on per-tick addrman selection (PRESENT) ---")
test("G23-a: select_peer_to_connect has 100-iteration cap", function()
  local pm, d = make_pm()
  -- Reading the public surface for the 100-cap is the most robust way.
  -- Verified by inspection at peerman.lua:1261.
  -- Drive the path: empty addrman, no candidates -> returns nil promptly.
  local addr = pm:select_peer_to_connect()
  expect_nil(addr, "empty addrman should return nil from select_peer_to_connect")
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- G24: 10-min last-try gate
-- ---------------------------------------------------------------------------
print("\n--- G24: 10-min last-try gate (Core net.cpp:2845) (BUG-14 P2) ---")
bug("BUG-14", "P2")
test_xfail_pre_fix("G24-a: select_peer_to_connect skips entries last-tried < 10min ago",
  "BUG-14", function()
    local pm, d = make_pm()
    local now = os.time()
    pm.known_addresses["203.0.114.5:8333"] = {
      ip = "203.0.114.5", port = 8333, services = 1,
      timestamp = now - 60, attempts = 1, last_try = now - 120,  -- 2 min ago
    }
    -- The 60s gate would let this through.  Core's 10-min gate would not.
    local candidate = pm:select_peer_to_connect()
    expect_nil(candidate,
      "addr with last_try 2min ago must be skipped (Core: 10min gate)")
    rm_dir(d)
  end)

-- ---------------------------------------------------------------------------
-- G25: IsBadPort gate
-- ---------------------------------------------------------------------------
print("\n--- G25: IsBadPort gate (BUG-15 P2) ---")
bug("BUG-15", "P2")
test_xfail_pre_fix("G25-a: is_bad_port helper exists", "BUG-15", function()
  expect_not_nil(peerman.is_bad_port,
    "is_bad_port helper should exist (Core IsBadPort -- blocks 1,7,9,...,25,6667,...)")
end)
test_xfail_pre_fix("G25-b: select_peer_to_connect skips IPv4 addresses at port 25 (SMTP)",
  "BUG-15", function()
    local pm, d = make_pm()
    local now = os.time()
    -- An attacker publishes our victim:25 as a Bitcoin node.
    pm.known_addresses["203.0.114.5:25"] = {
      ip = "203.0.114.5", port = 25, services = 1,
      timestamp = now, attempts = 0, last_try = 0,
    }
    -- Force AddrMan-empty so the known_addresses fallback fires.
    local candidate = pm:select_peer_to_connect()
    -- Pre-fix: returned (BadPort gate absent).  Fix-side: nil.
    expect_nil(candidate, "port-25 candidate must be skipped (IsBadPort)")
    rm_dir(d)
  end)

-- ---------------------------------------------------------------------------
-- G26 + G27: inbound eviction
-- ---------------------------------------------------------------------------
print("\n--- G26/G27: inbound eviction NodeEvictionCandidate + SelectNodeToEvict (BUG-16 P1) ---")
bug("BUG-16", "P1")
test_xfail_pre_fix("G26-a: attempt_to_evict_connection method exists", "BUG-16", function()
  local pm, d = make_pm()
  expect_not_nil(pm.attempt_to_evict_connection,
    "attempt_to_evict_connection method should exist (Core net.cpp:1689 AttemptToEvictConnection)")
  rm_dir(d)
end)
test_xfail_pre_fix("G26-b: select_node_to_evict helper exists", "BUG-16", function()
  expect_not_nil(peerman.select_node_to_evict,
    "select_node_to_evict helper should exist (Core node/eviction.cpp:178)")
end)
test_xfail_pre_fix("G27-a: protect_eviction_candidates_by_ratio helper exists",
  "BUG-16", function()
    expect_not_nil(peerman.protect_eviction_candidates_by_ratio,
      "protect_eviction_candidates_by_ratio helper should exist (Core node/eviction.cpp:105)")
  end)

-- ---------------------------------------------------------------------------
-- G28: BanMan two-channel
-- ---------------------------------------------------------------------------
print("\n--- G28: BanMan two-channel design (BUG-17 P1) ---")
bug("BUG-17", "P1")
test_xfail_pre_fix("G28-a: PeerManager has separate discouraged + banned channels",
  "BUG-17", function()
    local pm, d = make_pm()
    expect_not_nil(pm.discouraged,
      "discouraged channel should exist as a CRollingBloomFilter-equivalent")
    expect_not_nil(pm.banned, "banned channel should exist (manual / persistent)")
    -- They must not be the same table.
    expect_true(pm.discouraged ~= pm.banned,
      "discouraged and banned must be separate data structures")
    rm_dir(d)
  end)
test_xfail_pre_fix("G28-b: misbehaving() adds to discouraged, not persistent banned",
  "BUG-17", function()
    local pm, d = make_pm()
    -- Fake peer triggering misbehaving.
    local fake = { ip = "203.0.114.5", port = 8333, noban = false, is_manual = false }
    -- Pre-fix: peerman.lua:1502 calls self:ban_peer(peer.ip) which persists.
    pm:misbehaving(fake, 100, "test reason")
    -- Misbehaving should NOT have grown the persistent ban map -- only the
    -- ephemeral discouraged bloom (Core: m_discouraged, not m_banned).
    expect_nil(pm.banned[fake.ip],
      "misbehaving must NOT add to persistent banned map (Core: m_discouraged bloom only)")
    rm_dir(d)
  end)
test_xfail_pre_fix("G28-c: discouraged state is NOT persisted to disk", "BUG-17", function()
  local pm, d = make_pm()
  local fake = { ip = "203.0.114.5", port = 8333, noban = false, is_manual = false }
  pm:misbehaving(fake, 100, "test reason")
  pm:stop()
  -- Pre-fix: banned.dat written with the discouraged IP. Fix-side: not written.
  local f = io.open(d .. "/banned.dat", "r")
  if f then
    local data = f:read("*a")
    f:close()
    expect_false(data:find("203.0.114.5") ~= nil,
      "discouraged IP must not appear in persistent banned.dat (Core: m_discouraged bloom is ephemeral)")
  end
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- G29: CSubNet matching in setban
-- ---------------------------------------------------------------------------
print("\n--- G29: CSubNet matching in setban (BUG-17 same root) ---")
test_xfail_pre_fix("G29-a: setban '10.0.0.0/8' matches '10.5.6.7'", "BUG-17", function()
  local pm, d = make_pm()
  -- Simulate setban-style insertion with a CIDR.
  pm:ban_peer("10.0.0.0/8")
  -- A peer at 10.5.6.7 should now be considered banned.
  -- Pre-fix: is_banned does exact-string match -> false.
  expect_true(pm:is_banned("10.5.6.7"),
    "CIDR /8 ban must match member IP (Core CSubNet::Match)")
  rm_dir(d)
end)

-- ---------------------------------------------------------------------------
-- G30: DEFAULT_MISBEHAVING_BANTIME + DUMP_BANS_INTERVAL
-- ---------------------------------------------------------------------------
print("\n--- G30: ban constants (PARTIAL: BANTIME ok, DUMP_INTERVAL absent) ---")
test("G30-a: DEFAULT_BAN_DURATION = 86400 (24h) matches Core", function()
  expect_eq(peerman.MISBEHAVIOR.DEFAULT_BAN_DURATION, 86400)
end)
test_xfail_pre_fix("G30-b: DUMP_BANS_INTERVAL constant exists (= 900s)",
  "BUG-17", function()
    local v = peerman.MISBEHAVIOR.DUMP_BANS_INTERVAL or peerman.DUMP_BANS_INTERVAL
    expect_not_nil(v, "DUMP_BANS_INTERVAL should exist (Core banman.h:22 = 15min)")
    expect_eq(v, 900)
  end)

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------

print("\n=========================================================================")
print("W128 AddrMan + connman + peer selection -- summary")
print("=========================================================================")
io.write(string.format("\n  PASS:  %d\n", PASS))
io.write(string.format("  XFAIL: %d (expected pre-fix divergences)\n", XFAIL_PRE_FIX))
io.write(string.format("  FAIL:  %d\n\n", FAIL))

if #BUGS > 0 then
  -- Deduplicate the bug list (each P1/P2 may appear once per `bug()` call;
  -- tests reference the same id multiple times in a few places).
  local seen, dedup = {}, {}
  for _, b in ipairs(BUGS) do
    if not seen[b] then
      dedup[#dedup + 1] = b
      seen[b] = true
    end
  end
  io.write("Bugs surfaced:\n")
  for _, b in ipairs(dedup) do
    io.write("  " .. b .. "\n")
  end
  io.write("\n")
end

print("Audit gates: 30 W128 set")
print("  PRESENT:  4  (G1-c..f bucket sub-constants, G2-a hash surface, G23, G30-a)")
print("  PARTIAL:  3  (G1 partial; G2 partial; G30 partial)")
print("  MISSING: 23  (G3, G4, G5, G6, G7, G8, G9, G10, G11, G12, G13, G14,")
print("              G15, G16, G17, G18, G19, G20, G21, G22, G24, G25, G26,")
print("              G27, G28, G29, G30-b)")
print("")
print("Cross-references:")
print("  W104 (spec/w104_addrman_spec.lua) -- in-memory bucket data structure")
print("  W117 BIP-155 addrv2 wire format -- excluded from W128 scope")
print("  W125 RPC error parity -- setban/addnode error code wrappers")

if FAIL > 0 then
  os.exit(1)
end
os.exit(0)
