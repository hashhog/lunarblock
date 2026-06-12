-- test_addrman_persist.lua
--
-- Proof for the bucketed-addrman persistence pilot (peers.dat-equivalent).
-- Validates:
--   1. Round-trip restart-persistence: K addrs across multiple /16 source
--      groups (multiple buckets), some promoted to tried, serialize -> load
--      into a FRESH PeerManager -> counts + per-bucket/pos placement +
--      tried/new classification survive intact.
--   2. Corrupt-file safety: a truncated/garbage/wrong-version peers.dat does
--      NOT crash boot and falls back to an empty addrman.
--   3. Falsification control: a fresh PM WITHOUT a peers.dat is empty
--      (pre-impl cold-start behaviour).
--
-- Run: luajit tests/test_addrman_persist.lua   (in-process, no daemon, no slot)

package.path = "src/?.lua;./?.lua;" .. package.path

local peerman = require("lunarblock.peerman")

local pass, fail = 0, 0
local function check(cond, msg)
  if cond then
    pass = pass + 1
    print("  PASS: " .. msg)
  else
    fail = fail + 1
    print("  FAIL: " .. msg)
  end
end

local function mktmp()
  local d = "/tmp/lb_addrman_persist_" .. tostring(os.time()) .. "_" .. tostring(math.random(1, 1e9))
  os.execute("mkdir -p " .. d)
  return d
end

local NET = { p2p_port = 48341 }
local PORT = 8333

--------------------------------------------------------------------------------
-- Helper: snapshot the FULL placement (bucket -> pos -> {ip,port,classification})
--------------------------------------------------------------------------------
local function placement_of(pm)
  local p = { new = {}, tried = {} }
  for b = 0, peerman.ADDRMAN.NEW_BUCKET_COUNT - 1 do
    for pos, e in pairs(pm._new_buckets[b]) do
      p.new[b .. "/" .. pos] = e.ip .. ":" .. e.port
    end
  end
  for b = 0, peerman.ADDRMAN.TRIED_BUCKET_COUNT - 1 do
    for pos, e in pairs(pm._tried_buckets[b]) do
      p.tried[b .. "/" .. pos] = e.ip .. ":" .. e.port
    end
  end
  return p
end

local function count_keys(t)
  local n = 0
  for _ in pairs(t) do n = n + 1 end
  return n
end

--------------------------------------------------------------------------------
-- 1. FALSIFICATION CONTROL — fresh PM, no peers.dat, must be empty.
--------------------------------------------------------------------------------
print("== Falsification control: cold start (no peers.dat) is empty ==")
do
  local dir = mktmp()
  local pm = peerman.new(NET, nil, { data_dir = dir })
  local s = pm:get_addrman_stats()
  check(s.new_count == 0 and s.tried_count == 0,
    "fresh PM with no peers.dat has new_count==tried_count==0 (PRE-impl cold start)")
end

--------------------------------------------------------------------------------
-- 2. ROUND-TRIP PERSISTENCE — populate, save, load into fresh PM, compare.
--------------------------------------------------------------------------------
print("== Round-trip: populate -> save -> fresh load -> placement preserved ==")
local dir = mktmp()
local now = os.time()

local pm1 = peerman.new(NET, nil, { data_dir = dir })

-- Populate across 4 distinct /16 source groups (a = 10..13) so entries land in
-- MULTIPLE new buckets; recent timestamps so none are IsTerrible-pruned.
local expected_addrs = {}
for a = 10, 13 do
  local src = a .. ".0.0.254"          -- distinct /16 per a => distinct src group
  for d = 1, 6 do
    local ip = a .. ".0.0." .. d
    pm1:_add_to_new(ip, PORT, 1, now, src)
    expected_addrs[ip .. ":" .. PORT] = true
  end
end

-- Promote a few to tried (exercise both classifications).
local tried_addrs = { "10.0.0.1", "11.0.0.2", "12.0.0.3" }
for _, ip in ipairs(tried_addrs) do
  pm1:_move_to_tried(ip, PORT)
end

local s1 = pm1:get_addrman_stats()
print(string.format("  populated PM1: new=%d tried=%d", s1.new_count, s1.tried_count))
check(s1.tried_count == #tried_addrs, "PM1 tried_count matches promotions")
check(s1.new_count > 0, "PM1 has new entries across multiple buckets")

-- The set that PM1 ACTUALLY retains (some inputs may collide in a bucket-slot
-- and be evicted by _add_to_new — that is correct Core-faithful behaviour, not
-- a persistence loss; the round-trip must preserve exactly what PM1 holds).
local retained = {}
for ip_key in pairs(pm1._addr_info) do retained[ip_key] = true end
check(count_keys(retained) == s1.new_count + s1.tried_count,
  "PM1 _addr_info count == new_count + tried_count")

-- Confirm entries really span multiple new buckets (placement-across-buckets).
local pl1 = placement_of(pm1)
do
  local buckets_seen = {}
  for k in pairs(pl1.new) do buckets_seen[k:match("^(%d+)/")] = true end
  check(count_keys(buckets_seen) >= 2,
    "new entries occupy >= 2 distinct buckets (placement spread)")
end

-- Capture the salt before save (must survive so future inserts bucket-match).
local key1 = pm1._addrman_key

-- Save.
local ok_save = pm1:_save_addrman()
check(ok_save, "_save_addrman() wrote peers.dat")
do
  local f = io.open(dir .. "/peers.dat", "r")
  check(f ~= nil, "peers.dat exists on disk after save")
  if f then f:close() end
end

-- "Restart": a brand-new PeerManager on the same datadir loads peers.dat in its
-- constructor.
local pm2 = peerman.new(NET, nil, { data_dir = dir })
local s2 = pm2:get_addrman_stats()
print(string.format("  reloaded PM2: new=%d tried=%d", s2.new_count, s2.tried_count))

check(s2.new_count == s1.new_count, "new_count survives restart (matches)")
check(s2.tried_count == s1.tried_count, "tried_count survives restart (matches)")

-- Salt round-trips (so subsequent inserts land in the same buckets).
check(pm2._addrman_key == key1, "nKey (addrman salt) round-trips exactly")

-- Every RETAINED address (what PM1 actually held) present after restart, and
-- no extra/phantom entries appeared.
do
  local mismatch = 0
  for ip_key in pairs(retained) do
    if not pm2._addr_info[ip_key] then mismatch = mismatch + 1 end
  end
  local extra = 0
  for ip_key in pairs(pm2._addr_info) do
    if not retained[ip_key] then extra = extra + 1 end
  end
  check(mismatch == 0 and extra == 0,
    "reloaded _addr_info exactly matches PM1's retained address set")
end
do
  local wrong = 0
  for _, ip in ipairs(tried_addrs) do
    local info = pm2._addr_info[ip .. ":" .. PORT]
    if not (info and info.in_tried) then wrong = wrong + 1 end
  end
  check(wrong == 0, "all promoted addresses retain in_tried classification after restart")
end
-- And new-classified ones did NOT flip to tried.
do
  local tried_set = {}
  for _, ip in ipairs(tried_addrs) do tried_set[ip .. ":" .. PORT] = true end
  local flipped = 0
  for ip_key in pairs(expected_addrs) do
    if not tried_set[ip_key] then
      local info = pm2._addr_info[ip_key]
      if info and info.in_tried then flipped = flipped + 1 end
    end
  end
  check(flipped == 0, "new-classified addresses did NOT flip to tried on restart")
end

-- PLACEMENT preserved: identical bucket/pos maps in both tables.
local pl2 = placement_of(pm2)
do
  local same = true
  for slot, addr in pairs(pl1.new) do
    if pl2.new[slot] ~= addr then same = false break end
  end
  for slot, addr in pairs(pl2.new) do
    if pl1.new[slot] ~= addr then same = false break end
  end
  check(same and count_keys(pl1.new) == count_keys(pl2.new),
    "NEW bucket/pos placement preserved verbatim across restart")
end
do
  local same = true
  for slot, addr in pairs(pl1.tried) do
    if pl2.tried[slot] ~= addr then same = false break end
  end
  for slot, addr in pairs(pl2.tried) do
    if pl1.tried[slot] ~= addr then same = false break end
  end
  check(same and count_keys(pl1.tried) == count_keys(pl2.tried),
    "TRIED bucket/pos placement preserved verbatim across restart")
end

-- Select() returns restored addresses (functional liveness of the reloaded
-- book).  _select_address probes random (bucket,pos) slots up to 100 tries, so
-- with a sparsely-populated table it can return nil; retry a handful of times
-- to get a deterministic functional signal, and require the hit to be a
-- persisted address.
do
  local hit = nil
  for _ = 1, 50 do
    local got = pm2:_select_address()
    if got then hit = got break end
  end
  check(hit ~= nil and retained[hit.ip .. ":" .. hit.port] == true,
    "_select_address() on reloaded PM returns a persisted address")
end

--------------------------------------------------------------------------------
-- 3. CORRUPT-FILE SAFETY — must never crash boot; falls back to empty addrman.
--------------------------------------------------------------------------------
print("== Corrupt-file safety: never crash, fall back to empty ==")

local function corrupt_case(name, write_bytes)
  local d = mktmp()
  local f = assert(io.open(d .. "/peers.dat", "w"))
  f:write(write_bytes)
  f:close()
  local ok, pm = pcall(peerman.new, NET, nil, { data_dir = d })
  check(ok, name .. ": construction did NOT crash")
  if ok then
    local s = pm:get_addrman_stats()
    check(s.new_count == 0 and s.tried_count == 0,
      name .. ": fell back to empty addrman")
  end
end

corrupt_case("truncated-json", '{"version":1,"new":[{"ip":"10.0.0.1"')
corrupt_case("garbage-bytes", "\0\1\2\3not json at all\255")
corrupt_case("empty-file", "")
corrupt_case("wrong-version", '{"version":999,"nkey":"","asmap_version":"","new":[],"tried":[]}')
corrupt_case("missing-tables", '{"version":1,"nkey":"","asmap_version":""}')

-- Oversized hand-crafted file must NOT drive growth past the ceiling.
print("== Bound: oversized peers.dat capped at ceiling ==")
do
  local cjson = require("cjson")
  local d = mktmp()
  local huge = { version = 1, nkey = string.rep("ab", 32), asmap_version = "", new = {}, tried = {} }
  -- Craft far more than the ceiling of unique addresses (no bucket/pos so they
  -- take the _add_to_new fall-back path, which enforces collision/refcount caps).
  local n = peerman.ADDRMAN.PERSIST_MAX_ENTRIES + 5000
  for i = 1, n do
    local ip = (16 + (i % 200)) .. "." .. (i % 256) .. "." .. (math.floor(i / 256) % 256) .. "." .. (i % 250 + 1)
    huge.new[i] = { ip = ip, port = PORT, services = 1, timestamp = now, src_ip = "200.0.0.1" }
  end
  local f = assert(io.open(d .. "/peers.dat", "w"))
  f:write(cjson.encode(huge))
  f:close()
  local ok, pm = pcall(peerman.new, NET, nil, { data_dir = d })
  check(ok, "oversized file: construction did NOT crash")
  if ok then
    local s = pm:get_addrman_stats()
    check(s.new_count <= peerman.ADDRMAN.PERSIST_MAX_ENTRIES,
      string.format("oversized file bounded: new_count=%d <= ceiling=%d",
        s.new_count, peerman.ADDRMAN.PERSIST_MAX_ENTRIES))
  end
end

--------------------------------------------------------------------------------
print(string.format("\n==== %d passed, %d failed ====", pass, fail))
os.exit(fail == 0 and 0 or 1)
