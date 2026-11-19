-- spec/addr_routable_spec.lua
--
-- cffix-lunarblock-addr-routable: a byte-level CNetAddr::IsRoutable guards
-- every addrman / known_addresses insertion and every automatic dial.
--
-- Core: AddrManImpl::AddSingle (addrman.cpp) returns early on
-- !addr.IsRoutable(); CNetAddr::IsRoutable (netaddress.cpp) is
--   IsValid() && !(RFC1918 || RFC2544 || RFC3927 || RFC4862 || RFC6598 ||
--                  RFC5737 || RFC4193 || RFC4843 || RFC7343 || IsLocal() ||
--                  IsInternal())
-- and IsValid() rejects ::, 2001:db8::/32 (RFC3849), internal, 0.0.0.0 and
-- 255.255.255.255.  An addrv2 IPv6 entry carrying the IPv4-in-IPv6 or
-- TORv2-in-IPv6 prefix is unserialized as !IsValid() (netaddress.h
-- UnserializeV2Stream).
--
-- Before this fix `_is_routable` passed every non-dotted-quad string, so the
-- addr handler let ::1, fe80::1 and fc00::1 into addrman, and handle_addrv2
-- wrote even 10.0.0.1 and 127.0.0.1 into known_addresses before its check.

local peerman = require("lunarblock.peerman")
local p2p = require("lunarblock.p2p")

local function make_network()
  return {
    name = "regtest",
    magic_bytes = "\xfa\xbf\xb5\xda",
    port = 18444,
    default_port = 18444,
    dns_seeds = {},
    pow_target_spacing = 600,
  }
end

local dirs = {}
local function make_pm()
  local tmpdir = os.tmpname()
  os.remove(tmpdir)
  os.execute("mkdir -p " .. tmpdir)
  dirs[#dirs + 1] = tmpdir
  return peerman.new(make_network(), nil, { data_dir = tmpdir })
end

local function count(t)
  local n = 0
  for _ in pairs(t) do n = n + 1 end
  return n
end

-- 16 raw bytes for an IPv6 literal (any spelling).
local function v6(s)
  local info = peerman.parse_ip(s)
  assert(info and info.family == "ipv6", "bad ipv6 literal " .. s)
  return info.bytes
end

local function v4(s)
  local info = peerman.parse_ip(s)
  assert(info and info.family == "ipv4", "bad ipv4 literal " .. s)
  return info.bytes
end

-- IPv4-in-IPv6 (::ffff:a.b.c.d) as 16 raw bytes.
local function mapped(s)
  return string.rep("\0", 10) .. "\xff\xff" .. v4(s)
end

-- A noban peer skips the addr token bucket so every entry is processed.
local function src_peer()
  return { ip = "5.6.7.8", port = 8333, noban = true }
end

local function addr_v1(list)
  local entries = {}
  for i, s in ipairs(list) do
    local b16 = s:match("^::ffff:(%d+%.%d+%.%d+%.%d+)$")
    entries[i] = { timestamp = os.time() - 60, services = 1,
                   addr16 = b16 and mapped(b16) or v6(s), port = 8333 }
  end
  return p2p.serialize_addr(entries)
end

local function addr_v2(list)
  local entries = {}
  for i, e in ipairs(list) do
    entries[i] = { timestamp = os.time() - 60, services = 1,
                   network_id = e[1], addr_bytes = e[2], port = 8333 }
  end
  return p2p.serialize_addrv2(entries)
end

-- Every entry of the bucketed addrman (new + tried).
local function addrman_ips(pm)
  local out = {}
  for b = 0, peerman.ADDRMAN.NEW_BUCKET_COUNT - 1 do
    for _, e in pairs(pm._new_buckets[b]) do out[#out + 1] = e.ip end
  end
  for b = 0, peerman.ADDRMAN.TRIED_BUCKET_COUNT - 1 do
    for _, e in pairs(pm._tried_buckets[b]) do out[#out + 1] = e.ip end
  end
  return out
end

describe("addr routability (Core CNetAddr::IsRoutable at AddrMan::AddSingle)", function()

  teardown(function()
    for _, d in ipairs(dirs) do os.execute("rm -rf " .. d) end
  end)

  it("is_routable rejects the IPv6 special ranges Core rejects", function()
    for _, s in ipairs({
      "::", "::1", "0:0:0:0:0:0:0:1",
      "fe80::", "fe80::1", "fe80::ffff:ffff:ffff:ffff",  -- RFC4862 fe80::/64
      "fc00::", "fc00::1", "fd00::1", "fdff::1",         -- RFC4193 fc00::/7
      "fd6b:88c0:8724:edb1:8e4:3588:e546:35ca",          -- internal
      "fd87:d87e:eb43::1",                               -- TORv2-in-IPv6
      "2001:db8::", "2001:db8::1",                       -- RFC3849
      "2001:10::", "2001:1f::1",                         -- RFC4843 ORCHID
      "2001:20::", "2001:2f::1",                         -- RFC7343 ORCHIDv2
      "::ffff:10.0.0.1", "::ffff:127.0.0.1",             -- mapped IPv4
    }) do
      assert.is_false(peerman.is_routable(s), s .. " must not be routable")
    end
  end)

  it("is_routable accepts what Core accepts (no over-filtering)", function()
    for _, s in ipairs({
      "8.8.8.8", "2001::1", "2001::8888", "2a01:4f8::1",
      "fe80:1::1",          -- outside Core's RFC4862 fe80::/64
      "2001:30::1",         -- outside ORCHID/ORCHIDv2
      "2002::1",            -- RFC3964 6to4: Core does not filter it
      "64:ff9b::1",         -- RFC6052: Core does not filter it
      "ff02::1",            -- multicast: Core does not filter it
      "224.0.0.1",          -- IPv4 multicast: Core does not filter it
      "240.0.0.1",          -- Core has no 240/4 rule
      "::ffff:8.8.8.8",     -- mapped public IPv4 is that IPv4
      "abcdef.onion", "abcdef.b32.i2p",
    }) do
      assert.is_true(peerman.is_routable(s), s .. " must be routable")
    end
    assert.is_false(peerman.is_routable("255.255.255.255"))  -- INADDR_NONE
    assert.is_false(peerman.is_routable("0.0.0.0"))          -- INADDR_ANY
    assert.is_false(peerman.is_routable("not-an-ip"))
    assert.is_false(peerman.is_routable(""))
    assert.is_false(peerman.is_routable(nil))
  end)

  it("handle_addr keeps ::1, fe80::1 and fc00::1 out of known_addresses and addrman", function()
    local pm = make_pm()
    pm:handle_addr(src_peer(), addr_v1({
      "::1", "fe80::1", "fc00::1", "2001:db8::1", "2001:10::1",
      "fd6b:88c0:8724::1",
    }))
    assert.equals(0, count(pm.known_addresses))
    assert.equals(0, pm._new_count)
    assert.same({}, addrman_ips(pm))
  end)

  it("handle_addrv2 keeps 10.0.0.1 and 127.0.0.1 out of known_addresses and addrman", function()
    local pm = make_pm()
    pm:handle_addrv2(src_peer(), addr_v2({
      { p2p.NET_ID.IPV4, v4("10.0.0.1") },
      { p2p.NET_ID.IPV4, v4("127.0.0.1") },
      { p2p.NET_ID.IPV4, v4("192.168.1.1") },
    }))
    assert.equals(0, count(pm.known_addresses))
    assert.equals(0, pm._new_count)
    assert.same({}, addrman_ips(pm))
  end)

  it("handle_addrv2 keeps non-routable IPv6 and IPv4-in-IPv6 out", function()
    local pm = make_pm()
    pm:handle_addrv2(src_peer(), addr_v2({
      { p2p.NET_ID.IPV6, v6("::1") },
      { p2p.NET_ID.IPV6, v6("fe80::1") },
      { p2p.NET_ID.IPV6, v6("fc00::1") },
      -- Core: an addrv2 IPv6 entry with the IPv4-in-IPv6 prefix is !IsValid()
      { p2p.NET_ID.IPV6, mapped("8.8.8.8") },
    }))
    assert.equals(0, count(pm.known_addresses))
    assert.equals(0, pm._new_count)
  end)

  it("control: routable IPv4, IPv6 and overlay entries are still stored", function()
    local pm = make_pm()
    pm:handle_addr(src_peer(), addr_v1({ "2a01:4f8::1", "::ffff:8.8.8.8" }))
    assert.equals(2, count(pm.known_addresses))
    assert.equals(2, pm._new_count)

    local pm2 = make_pm()
    pm2:handle_addrv2(src_peer(), addr_v2({
      { p2p.NET_ID.IPV4, v4("1.2.3.4") },
      { p2p.NET_ID.IPV6, v6("2a01:4f8::2") },
      { p2p.NET_ID.TORV3, string.rep("\1", 32) },
      { p2p.NET_ID.I2P, string.rep("\2", 32) },
      { p2p.NET_ID.CJDNS, "\xfc" .. string.rep("\3", 15) },
    }))
    -- All five are remembered; only the two IP entries reach the bucketed
    -- addrman (overlay networks were never bucketed here).
    assert.equals(5, count(pm2.known_addresses))
    assert.equals(2, pm2._new_count)
  end)

  it("add_known_address and _add_to_new refuse non-routable addresses", function()
    local pm = make_pm()
    assert.is_false(pm:add_known_address("::1", 8333))
    assert.is_false(pm:add_known_address("10.0.0.1", 8333))
    assert.is_false(pm:_add_to_new("fe80::1", 8333, 1, os.time(), "5.6.7.8"))
    assert.is_false(pm:_add_to_new("127.0.0.1", 8333, 1, os.time(), "5.6.7.8"))
    assert.is_false(pm:_move_to_tried("fc00::1", 8333))
    assert.equals(0, count(pm.known_addresses))
    assert.equals(0, pm._new_count)
    assert.equals(0, pm._tried_count)
    -- control
    assert.is_true(pm:add_known_address("2a01:4f8::1", 8333))
    assert.is_true(pm:_add_to_new("2a01:4f8::1", 8333, 1, os.time(), "5.6.7.8"))
  end)

  it("select_peer_to_connect never picks a non-routable entry already in the pool", function()
    local pm = make_pm()
    -- Simulate a pool polluted before this fix (e.g. an old peers.dat).
    pm.known_addresses["fe80::1:8333"] = {
      ip = "fe80::1", port = 8333, services = 1, timestamp = os.time(),
      attempts = 0, last_try = 0,
    }
    pm.known_addresses["127.0.0.1:8333"] = {
      ip = "127.0.0.1", port = 8333, services = 1, timestamp = os.time(),
      attempts = 0, last_try = 0,
    }
    for _ = 1, 20 do
      assert.is_nil(pm:select_peer_to_connect())
    end
    -- control: a routable entry is selected
    pm.known_addresses["2a01:4f8::1:8333"] = {
      ip = "2a01:4f8::1", port = 8333, services = 1, timestamp = os.time(),
      attempts = 0, last_try = 0,
    }
    local c = pm:select_peer_to_connect()
    assert.is_not_nil(c)
    assert.equals("2a01:4f8::1", c.ip)
  end)

  it("peers.dat load drops non-routable entries stored before the gate", function()
    local pm = make_pm()
    pm:_deserialize_addrman({
      new = {
        { ip = "fe80::1", port = 8333, bucket = 1, pos = 1, services = 1, timestamp = os.time() },
        { ip = "10.0.0.1", port = 8333, bucket = 2, pos = 2, services = 1, timestamp = os.time() },
        { ip = "2a01:4f8::1", port = 8333, bucket = 3, pos = 3, services = 1, timestamp = os.time() },
      },
      tried = {
        { ip = "127.0.0.1", port = 8333, bucket = 1, pos = 1, services = 1, timestamp = os.time() },
        { ip = "1.2.3.4", port = 8333, bucket = 2, pos = 2, services = 1, timestamp = os.time() },
      },
    })
    local ips = addrman_ips(pm)
    table.sort(ips)
    assert.same({ "1.2.3.4", "2a01:4f8::1" }, ips)
    assert.equals(1, pm._new_count)
    assert.equals(1, pm._tried_count)
  end)

  it("feeler selection skips a non-routable NEW entry", function()
    local pm = make_pm()
    -- Plant a non-routable entry straight into a NEW bucket (pre-gate pool).
    pm._new_buckets[0][0] = { ip = "fc00::1", port = 8333, services = 1,
                              timestamp = os.time(), src_ip = "5.6.7.8" }
    pm._addr_info["fc00::1:8333"] = { in_tried = false, new_ref_count = 1,
                                       new_refs = { [0] = 0 } }
    pm._new_count = 1
    assert.is_nil(pm:_select_for_feeler())
  end)

  it("anchors: a non-routable anchor is neither loaded nor saved", function()
    local pm = make_pm()
    local dir = pm.data_dir
    local f = assert(io.open(dir .. "/anchors.dat", "w"))
    f:write("127.0.0.1:8333\n10.0.0.1:8333\n1.2.3.4:8333\n")
    f:close()
    pm:_load_anchors()
    assert.equals(1, #pm._anchors)
    assert.equals("1.2.3.4", pm._anchors[1].ip)

    local function peer(ip)
      return { ip = ip, port = 8333, inbound = false,
               state = require("lunarblock.peer").STATE.ESTABLISHED }
    end
    pm.peer_list = { peer("127.0.0.1"), peer("1.2.3.4") }
    pm:_save_anchors()
    local g = assert(io.open(dir .. "/anchors.dat", "r"))
    local content = g:read("*a")
    g:close()
    assert.is_nil(content:find("127.0.0.1", 1, true))
    assert.truthy(content:find("1.2.3.4:8333", 1, true))
  end)
end)
