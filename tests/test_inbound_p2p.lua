#!/usr/bin/env luajit
-- Inbound P2P readiness — CHARTER "full P2P, outbound AND inbound".
--
-- Control for QUEUES.md lunarblock item 0. Each requirement has a
-- regtest assertion that does not need mainnet:
--
--   (1) configurable bind, default 0.0.0.0 + [::], restrict via --bind
--   (2) inbound version/verack appears in getpeerinfo with inbound: true
--   (3) inbound slots are separate from outbound (flood cannot starve sync)
--   (4) half-open handshake is reaped and frees the slot
--   (5) inbound peer is served getheaders + getdata (a block) like outbound
--
-- Negative control: a TCP connect that never sends version is disconnected
-- on the handshake timeout and does not keep occupying an inbound slot.
--
-- Default bind address (report in the commit body): 0.0.0.0 and ::

package.path = "src/?.lua;src/?/init.lua;" .. package.path

local peerman   = require("lunarblock.peerman")
local p2p       = require("lunarblock.p2p")
local consensus = require("lunarblock.consensus")
local types     = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local rpc_mod   = require("lunarblock.rpc")
local main      = require("lunarblock.main")
local socket    = require("socket")

local NET = consensus.networks.regtest
local HANDSHAKE_S = 0.25

local PASS, FAIL = 0, 0
local function pass(name) io.write(string.format("  PASS  %s\n", name)); PASS = PASS + 1 end
local function fail(name, msg)
  io.write(string.format("  FAIL  %s -- %s\n", name, msg)); FAIL = FAIL + 1
end
local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end
local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) .. ", expected " .. tostring(b), 2)
  end
end
local function expect_true(v, msg)
  if not v then error((msg or "expected true") .. ": got " .. tostring(v), 2) end
end
local function expect_false(v, msg)
  if v then error((msg or "expected false") .. ": got " .. tostring(v), 2) end
end

local function mkdtemp()
  local path = os.tmpname()
  os.remove(path)
  os.execute("mkdir -p " .. path)
  return path
end
local function rmdir(path)
  if path and path ~= "" and path ~= "/" then os.execute("rm -rf " .. path) end
end

local function has_cmd(messages, cmd)
  for _, m in ipairs(messages) do
    if m.command == cmd then return m end
  end
  return nil
end

--------------------------------------------------------------------------------
-- Raw Bitcoin P2P client that dials an already-listening node (inbound).
--------------------------------------------------------------------------------
local function InboundClient()
  local c = { sock = nil, buf = "", messages = {}, closed = false }
  function c:connect(host, port)
    self.sock = assert(socket.tcp())
    self.sock:settimeout(2)
    local ok, err = self.sock:connect(host, port)
    if not ok then error("inbound connect failed: " .. tostring(err)) end
    self.sock:settimeout(0)
  end
  function c:send_msg(command, payload)
    if not self.sock then error("not connected") end
    local framed = p2p.make_message(NET.magic_bytes, command, payload or "")
    local sent, err = self.sock:send(framed)
    if not sent then error("send " .. command .. " failed: " .. tostring(err)) end
  end
  function c:send_version()
    self:send_msg("version", p2p.serialize_version({
      version = 70016,
      services = 9,
      timestamp = os.time(),
      recv_services = 0,
      recv_ip = "127.0.0.1",
      recv_port = 0,
      from_services = 9,
      from_ip = "127.0.0.1",
      from_port = 1,
      nonce = math.random(1, 2 ^ 40),
      user_agent = "/inbound-readiness:0.0.1/",
      start_height = 0,
      relay = true,
    }))
  end
  function c:drain()
    if not self.sock then return end
    local data, err, partial = self.sock:receive(65536)
    data = data or partial
    if data and #data > 0 then
      self.buf = self.buf .. data
    elseif err == "closed" then
      self.closed = true
    end
    while #self.buf >= 24 do
      local header = p2p.parse_header(self.buf:sub(1, 24))
      if not header then break end
      local total = 24 + (header.length or 0)
      if #self.buf < total then break end
      local payload = self.buf:sub(25, total)
      self.buf = self.buf:sub(total + 1)
      self.messages[#self.messages + 1] = { command = header.command, payload = payload }
    end
  end
  function c:close()
    if self.sock then self.sock:close(); self.sock = nil end
    self.closed = true
  end
  return c
end

local function make_pm(extra)
  extra = extra or {}
  local dir = extra.data_dir or mkdtemp()
  local cfg = {
    data_dir = dir,
    nov2transport = true,
    max_outbound = extra.max_outbound or 0,
    max_inbound = extra.max_inbound or 8,
    max_peers = extra.max_peers,
    bind = extra.bind,
    port = extra.port or 0,
    handshake_timeout = extra.handshake_timeout or HANDSHAKE_S,
  }
  local pm = peerman.new(NET, nil, cfg)
  return pm, dir
end

-- Always stop + rmdir, even when the assertion fails, so a leaked
-- bind on the regtest default port cannot poison later tests.
local function with_pm(extra, fn)
  local pm, dir = make_pm(extra)
  local clients = {}
  local ok, err = pcall(fn, pm, clients)
  for _, c in ipairs(clients) do pcall(function() c:close() end) end
  pcall(function() pm:stop() end)
  rmdir(dir)
  if not ok then error(err, 0) end
end

local function listen_port(pm)
  local live = pm:get_listening_binds()
  expect_true(live and #live > 0, "node is listening")
  return live[1].port
end

local function pump_until(pm, clients, cond, timeout, label)
  timeout = timeout or 3
  local deadline = socket.gettime() + timeout
  while socket.gettime() < deadline do
    pm:tick()
    if clients then
      if clients.drain then
        clients:drain()
      else
        for _, c in ipairs(clients) do c:drain() end
      end
    end
    if cond() then return true end
    socket.sleep(0.01)
  end
  error((label or "wait") .. " timeout after " .. timeout .. "s")
end

local function inbound_handshake(pm, clients)
  local client = InboundClient()
  clients[#clients + 1] = client
  client:connect("127.0.0.1", listen_port(pm))
  pump_until(pm, client, function()
    local _, _, inbound = pm:get_peer_counts()
    return inbound >= 1
  end, 2, "accept inbound")
  client:send_version()
  pump_until(pm, client, function()
    return has_cmd(client.messages, "version") ~= nil
  end, 3, "inbound version")
  client:send_msg("verack", "")
  pump_until(pm, client, function()
    return has_cmd(client.messages, "verack") ~= nil
  end, 3, "inbound verack")
  pump_until(pm, client, function()
    return #pm:get_established_peers() >= 1
  end, 3, "inbound established")
  return client
end

local function canned_header()
  return types.block_header(
    NET.genesis.version,
    types.hash256_zero(),
    types.hash256_zero(),
    NET.genesis.timestamp,
    NET.genesis.bits,
    NET.genesis.nonce)
end

local function register_serve_handlers(pm)
  local header = canned_header()
  local genesis_hash = types.hash256_from_hex(NET.genesis_hash)
  local block_bytes = serialize.serialize_block(types.block(header, {}))
  pm:register_handler("getheaders", function(peer, _payload)
    peer:send_message("headers", p2p.serialize_headers({ header }))
  end)
  pm:register_handler("getdata", function(peer, payload)
    local items = p2p.deserialize_inv(payload)
    for _, item in ipairs(items) do
      if item.type == p2p.INV_TYPE.MSG_BLOCK
          or item.type == p2p.INV_TYPE.MSG_WITNESS_BLOCK then
        peer:send_message("block", block_bytes)
      end
    end
  end)
  return genesis_hash
end

local function getpeerinfo(pm)
  local server = rpc_mod.new({ network = NET, peer_manager = pm })
  local handler = server.methods["getpeerinfo"]
  expect_true(handler, "getpeerinfo registered")
  local ok, result = pcall(handler, server, {})
  expect_true(ok, "getpeerinfo raised: " .. tostring(result))
  return result
end

print("\n=========================================================================")
print("Inbound P2P readiness — lunarblock")
print("Default bind: 0.0.0.0 and ::")
print("=========================================================================\n")

--------------------------------------------------------------------------------
-- (1) parse_bind_spec / CLI --bind / default all-interfaces
--------------------------------------------------------------------------------
print("--- (1) bind configuration ---")

test("default bind hosts are all-interfaces IPv4 and IPv6, not loopback", function()
  expect_true(type(peerman.DEFAULT_BIND_HOSTS) == "table", "DEFAULT_BIND_HOSTS exported")
  expect_eq(#peerman.DEFAULT_BIND_HOSTS, 2, "two default hosts")
  expect_eq(peerman.DEFAULT_BIND_HOSTS[1], "0.0.0.0")
  expect_eq(peerman.DEFAULT_BIND_HOSTS[2], "::")
  for _, h in ipairs(peerman.DEFAULT_BIND_HOSTS) do
    expect_false(h == "127.0.0.1", "must not default to IPv4 loopback")
    expect_false(h == "::1", "must not default to IPv6 loopback")
  end
end)

test("parses IPv4, IPv4:port, bracketed IPv6, and bare IPv6", function()
  expect_true(type(peerman.parse_bind_spec) == "function", "parse_bind_spec exported")
  local a = peerman.parse_bind_spec("0.0.0.0", 8333)
  expect_eq(a.host, "0.0.0.0"); expect_eq(a.port, 8333)
  local b = peerman.parse_bind_spec("127.0.0.1:8334", 8333)
  expect_eq(b.host, "127.0.0.1"); expect_eq(b.port, 8334)
  local c = peerman.parse_bind_spec("[::]", 8333)
  expect_eq(c.host, "::"); expect_eq(c.port, 8333)
  local d = peerman.parse_bind_spec("[::1]:18444", 8333)
  expect_eq(d.host, "::1"); expect_eq(d.port, 18444)
  local e = peerman.parse_bind_spec("::", 8333)
  expect_eq(e.host, "::"); expect_eq(e.port, 8333)
end)

test("parse_args --bind is repeatable and --maxconnections is parsed", function()
  local real_exit = os.exit
  os.exit = function(code) error("os.exit " .. tostring(code), 0) end
  local ok, result = pcall(main.parse_args, {
    "--bind=127.0.0.1",
    "--bind=[::1]",
    "--maxconnections=20",
  })
  os.exit = real_exit
  expect_true(ok, "parse_args must accept --bind (got " .. tostring(result) .. ")")
  expect_true(type(result.bind) == "table", "bind is a list")
  expect_eq(#result.bind, 2, "two --bind values")
  expect_eq(result.bind[1], "127.0.0.1")
  expect_eq(result.bind[2], "[::1]")
  expect_eq(result.maxpeers, 20, "--maxconnections aliases --maxpeers")
end)

test("parse_args default bind is unset so the listener uses 0.0.0.0 and [::]", function()
  local result = main.parse_args({})
  expect_true(result.bind == nil, "default bind is unset (nil)")
  expect_eq(result.maxpeers, 125)
end)

test("default get_bind_addresses is 0.0.0.0 and :: on the listen port", function()
  local dir = mkdtemp()
  local pm = peerman.new(NET, nil, { data_dir = dir, listen = false, port = 18444 })
  local addrs = pm:get_bind_addresses()
  expect_eq(#addrs, 2, "two default bind addresses")
  expect_eq(addrs[1].host, "0.0.0.0")
  expect_eq(addrs[1].port, 18444)
  expect_eq(addrs[2].host, "::")
  expect_eq(addrs[2].port, 18444)
  rmdir(dir)
end)

test("--bind=127.0.0.1 restricts the listener to loopback", function()
  with_pm({ bind = { "127.0.0.1" }, port = 0 }, function(pm)
    local addrs = pm:get_bind_addresses()
    expect_eq(#addrs, 1)
    expect_eq(addrs[1].host, "127.0.0.1")
    local ok, err = pm:start_listener()
    expect_true(ok, "start_listener: " .. tostring(err))
    local live = pm:get_listening_binds()
    expect_true(#live >= 1, "at least one live bind")
    for _, b in ipairs(live) do
      expect_eq(b.host, "127.0.0.1")
      expect_true(b.port > 0, "ephemeral port assigned")
    end
  end)
end)

test("default listen binds all interfaces, not loopback", function()
  with_pm({ bind = nil, port = 0 }, function(pm)
    local ok, err = pm:start_listener()
    expect_true(ok, "start_listener: " .. tostring(err))
    local live = pm:get_listening_binds()
    expect_true(#live >= 1, "at least one live bind")
    local hosts = {}
    for _, b in ipairs(live) do hosts[b.host] = true end
    expect_true(hosts["0.0.0.0"] or hosts["::"] or hosts["::0"],
      "default bind is all-interfaces (got " .. (live[1] and live[1].host or "none") .. ")")
    expect_false(hosts["127.0.0.1"], "default must not be IPv4 loopback")
    expect_false(hosts["::1"], "default must not be IPv6 loopback")
    -- Dual-stack [::] (or IPv4 0.0.0.0) must still accept IPv4 clients.
    local port = live[1].port
    local probe = socket.tcp()
    probe:settimeout(2)
    local cok, cerr = probe:connect("127.0.0.1", port)
    expect_true(cok, "IPv4 client can connect to default bind: " .. tostring(cerr))
    probe:close()
  end)
end)

--------------------------------------------------------------------------------
-- (2)(5) inbound handshake, getpeerinfo inbound:true, served block
--------------------------------------------------------------------------------
print("\n--- (2)(5) inbound handshake + getpeerinfo + serve ---")

test("inbound version/verack appears in getpeerinfo with inbound:true and is served a block", function()
  with_pm({ bind = { "127.0.0.1" }, max_inbound = 4, max_outbound = 0 }, function(pm, clients)
    local genesis_hash = register_serve_handlers(pm)
    local ok, err = pm:start_listener()
    expect_true(ok, "start_listener: " .. tostring(err))
    local client = inbound_handshake(pm, clients)

    local info = getpeerinfo(pm)
    expect_true(type(info) == "table", "getpeerinfo returns array")
    expect_true(#info >= 1, "at least one peer")
    local inbound
    for _, p in ipairs(info) do
      if p.inbound then inbound = p break end
    end
    expect_true(inbound ~= nil, "getpeerinfo has an inbound peer")
    expect_eq(inbound.inbound, true)
    expect_eq(inbound.connection_type, "inbound")
    expect_eq(inbound.subver, "/inbound-readiness:0.0.1/")

    client:send_msg("getheaders", p2p.serialize_getheaders(70016, {}, types.hash256_zero()))
    pump_until(pm, client, function()
      return has_cmd(client.messages, "headers") ~= nil
    end, 3, "served headers")
    local headers_msg = has_cmd(client.messages, "headers")
    local headers = p2p.deserialize_headers(headers_msg.payload)
    expect_true(#headers >= 1, "served at least one header")

    client:send_msg("getdata", p2p.serialize_inv({
      { type = p2p.INV_TYPE.MSG_BLOCK, hash = genesis_hash },
    }))
    pump_until(pm, client, function()
      return has_cmd(client.messages, "block") ~= nil
    end, 3, "served block")
    expect_true(has_cmd(client.messages, "block") ~= nil, "inbound peer received a block")
  end)
end)

--------------------------------------------------------------------------------
-- (4) half-open handshake reap
--------------------------------------------------------------------------------
print("\n--- (4) half-open handshake reap ---")

test("half-open inbound is reaped on handshake timeout and frees the slot", function()
  with_pm({
    bind = { "127.0.0.1" },
    max_inbound = 2,
    max_outbound = 0,
    handshake_timeout = HANDSHAKE_S,
  }, function(pm, clients)
    local ok, err = pm:start_listener()
    expect_true(ok, "start_listener: " .. tostring(err))
    local client = InboundClient()
    clients[#clients + 1] = client
    client:connect("127.0.0.1", listen_port(pm))
    pump_until(pm, client, function()
      local _, _, inbound = pm:get_peer_counts()
      return inbound == 1
    end, 2, "slot held")
    local _, _, inbound = pm:get_peer_counts()
    expect_eq(inbound, 1, "half-open holds an inbound slot")

    pump_until(pm, client, function()
      local _, _, n = pm:get_peer_counts()
      return n == 0
    end, HANDSHAKE_S + 1.5, "slot freed")
    local total, outbound, inbound2 = pm:get_peer_counts()
    expect_eq(inbound2, 0, "inbound slot freed after handshake timeout")
    expect_eq(total, 0, "no peers remain")
    expect_eq(outbound, 0)
    local info = getpeerinfo(pm)
    expect_eq(#info, 0, "getpeerinfo empty after reap")
  end)
end)

--------------------------------------------------------------------------------
-- (3) inbound flood cannot starve outbound
--------------------------------------------------------------------------------
print("\n--- (3) inbound slots separate from outbound ---")

test("inbound flood cannot starve an outbound slot", function()
  -- Tight budget: 2 inbound + 1 outbound inside a 3-connection cap.
  -- If inbound counted against the same pool as outbound, the third
  -- connect_peer would fail with "max peers reached".
  with_pm({
    bind = { "127.0.0.1" },
    max_inbound = 2,
    max_outbound = 1,
    max_peers = 3,
  }, function(pm, clients)
    local ok, err = pm:start_listener()
    expect_true(ok, "start_listener: " .. tostring(err))

    local mock = assert(socket.bind("127.0.0.1", 0))
    mock:settimeout(0)
    local _, mock_port = mock:getsockname()
    local mock_ok, mock_err = pcall(function()
      inbound_handshake(pm, clients)
      inbound_handshake(pm, clients)
      local _, _, inbound = pm:get_peer_counts()
      expect_eq(inbound, 2, "inbound full")

      local third = InboundClient()
      clients[#clients + 1] = third
      third:connect("127.0.0.1", listen_port(pm))
      for _ = 1, 20 do pm:tick(); socket.sleep(0.01) end
      local _, _, inbound_after = pm:get_peer_counts()
      expect_true(inbound_after <= 2, "inbound stays at cap (got " .. tostring(inbound_after) .. ")")

      local cok, cerr = pm:connect_peer("127.0.0.1", mock_port, true, false)
      expect_true(cok, "outbound connect must succeed while inbound is full: " .. tostring(cerr))
      local total, outbound, inbound_final = pm:get_peer_counts()
      expect_eq(outbound, 1, "outbound slot occupied")
      expect_true(inbound_final <= 2, "inbound still capped")
      expect_true(total >= 3, "total includes the reserved outbound")
    end)
    mock:close()
    if not mock_ok then error(mock_err, 0) end
  end)
end)

test("max_inbound is reserved from max_peers - max_outbound when unset", function()
  local dir = mkdtemp()
  local pm = peerman.new(NET, nil, {
    data_dir = dir,
    max_peers = 20,
    max_outbound = 8,
    nov2transport = true,
  })
  expect_eq(pm.max_inbound, 12, "Core nMaxInbound = nMaxConnections - nMaxOutbound")
  expect_eq(pm.max_outbound, 8)
  expect_eq(pm.max_peers, 20)
  rmdir(dir)
end)

--------------------------------------------------------------------------------
print("\n=========================================================================")
print(string.format("Inbound P2P readiness: %d PASS, %d FAIL", PASS, FAIL))
print("=========================================================================")
os.exit(FAIL > 0 and 1 or 0)
