-- Security: the Prometheus metrics listener must not be reachable from other
-- hosts by default, and no metrics client may stall the node's event loop.
--
-- Before the fix (main.lua, inline in the main loop):
--   * the listener bound 0.0.0.0 with no way to narrow it;
--   * an accepted client was read line by line with client:settimeout(2) and
--     no total deadline, inside the single event loop. A client sending one
--     header line every 1.5 s held the whole node (P2P, RPC, validation) for as
--     long as it kept sending.
--
-- Core has no metrics port. Its HTTP RPC server binds localhost unless told
-- otherwise (bitcoin-core/src/httpserver.cpp HTTPBindAddresses) and serves on
-- worker threads with a per-request timeout (-rpcservertimeout).
--
-- The "node" tests start a real regtest node (luajit src/main.lua) on random
-- ports, so they measure the listener the node actually opens, not a model of
-- it. The "module" tests drive lunarblock.metrics_server directly.

local socket = require("socket")

local REPO = (debug.getinfo(1, "S").source:match("@?(.*/)spec/") or "./")

local function sh_quote(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end

local function read_file(p)
  local f = io.open(p, "rb")
  if not f then return nil end
  local d = f:read("*a")
  f:close()
  return d
end

local function free_port()
  for _ = 1, 50 do
    local p = math.random(42000, 59000)
    local s = socket.tcp4()
    local ok = s:bind("0.0.0.0", p)
    s:close()
    if ok then return p end
  end
  error("no free port")
end

-- Listening sockets on `port` from /proc/net/tcp: list of hex local addresses
-- ("0100007F" = 127.0.0.1, "00000000" = 0.0.0.0).
local function listen_addrs(port)
  local out = {}
  local data = read_file("/proc/net/tcp") or ""
  for line in data:gmatch("[^\n]+") do
    local addr, hport, st = line:match("^%s*%d+:%s+(%x+):(%x+)%s+%x+:%x+%s+(%x+)")
    if addr and tonumber(hport, 16) == port and st == "0A" then
      out[#out + 1] = addr
    end
  end
  return out
end

local function wait_connect(port, secs)
  local t_end = socket.gettime() + secs
  while socket.gettime() < t_end do
    local c = socket.tcp4()
    c:settimeout(0.2)
    if c:connect("127.0.0.1", port) then
      c:close()
      return true
    end
    c:close()
    socket.sleep(0.2)
  end
  return false
end

-- Start a regtest node; returns a handle with ports, datadir and log path.
-- `timeout 90` is the backstop; stop_node() asks it to stop over RPC.
local function start_node(extra)
  math.randomseed(os.time() + math.floor(socket.gettime() * 1000) % 100000)
  local h = {
    p2p = free_port(), rpc = free_port(), metrics = free_port(),
  }
  local dir = os.tmpname()
  os.remove(dir)
  h.dir = dir .. "_lbmetrics"
  os.execute("mkdir -p " .. sh_quote(h.dir))
  h.log = h.dir .. "/node.log"
  local cmd = string.format(
    "cd %s && LD_LIBRARY_PATH=./lib timeout 90 luajit src/main.lua " ..
    "--network regtest --datadir %s --port %d --rpcport %d --metricsport %d " ..
    "--nov2transport %s > %s 2>&1 &",
    sh_quote(REPO), sh_quote(h.dir), h.p2p, h.rpc, h.metrics, extra or "",
    sh_quote(h.log))
  os.execute(cmd)
  h.up = wait_connect(h.metrics, 30)
  return h
end

local function stop_node(h)
  if not h then return end
  local cookie = read_file(h.dir .. "/regtest/.cookie")
  if cookie then
    local mime = require("mime")
    local c = socket.tcp4()
    c:settimeout(5)
    if c:connect("127.0.0.1", h.rpc) then
      local body = '{"jsonrpc":"1.0","id":1,"method":"stop","params":[]}'
      c:send("POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic " ..
        mime.b64(cookie:gsub("%s+$", "")) .. "\r\nContent-Type: application/json\r\n" ..
        "Content-Length: " .. #body .. "\r\nConnection: close\r\n\r\n" .. body)
      c:receive("*a")
    end
    c:close()
  end
  -- Wait for the process to release its ports before removing the datadir.
  local t_end = socket.gettime() + 30
  while socket.gettime() < t_end and #listen_addrs(h.rpc) > 0 do
    socket.sleep(0.2)
  end
  os.execute("rm -rf " .. sh_quote(h.dir))
end

-- Connect a dribbling client and, 0.3 s later, a well-formed probe request.
-- The dribbler sends the request line, then one header line every 1.5 s
-- (inside master's 2 s per-line timeout) for `lines` lines.
-- Returns probe latency (s, or nil if never answered), whether the dribbler
-- was dropped by the server, and when.
local function dribble_and_probe(port, lines)
  local d = socket.tcp4()
  d:settimeout(2)
  assert(d:connect("127.0.0.1", port))
  d:send("GET /metrics HTTP/1.1\r\n")
  d:settimeout(0)
  local t0 = socket.gettime()
  local next_line = t0 + 1.5
  local sent_lines = 0
  local probe, probe_sent_at, probe_latency, probe_buf = nil, nil, nil, ""
  local dribbler_closed_at = nil
  local t_end = t0 + 1.5 * lines + 6
  while socket.gettime() < t_end do
    local now = socket.gettime()
    if not probe and now - t0 >= 0.3 then
      probe = socket.tcp4()
      probe:settimeout(2)
      assert(probe:connect("127.0.0.1", port))
      probe:send("GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
      probe:settimeout(0)
      probe_sent_at = socket.gettime()
    end
    if probe and not probe_latency then
      local data, err, partial = probe:receive(4096)
      data = data or partial
      if data and #data > 0 then probe_buf = probe_buf .. data end
      if probe_buf:find("bitcoin_mempool_size", 1, true) or err == "closed" then
        if probe_buf:find("200 OK", 1, true) then
          probe_latency = socket.gettime() - probe_sent_at
        end
        probe:close()
        probe = false -- answered (or refused); stop polling
      end
    end
    if not dribbler_closed_at then
      local _, err = d:receive(4096)
      if err == "closed" then
        dribbler_closed_at = socket.gettime() - t0
      elseif sent_lines < lines and now >= next_line then
        local _, serr = d:send("X-Dribble-" .. sent_lines .. ": 1\r\n")
        if serr == "closed" then dribbler_closed_at = socket.gettime() - t0 end
        sent_lines = sent_lines + 1
        next_line = next_line + 1.5
      elseif sent_lines == lines then
        -- Done dribbling: finish the request so the old code can answer it.
        d:send("\r\n")
        sent_lines = sent_lines + 1
      end
    end
    if probe_latency and dribbler_closed_at then break end
    socket.sleep(0.01)
  end
  d:close()
  if probe then probe:close() end
  return probe_latency, dribbler_closed_at
end

describe("metrics listener (node)", function()
  local node

  lazy_setup(function() node = start_node() end)
  lazy_teardown(function() stop_node(node) end)

  it("binds the metrics listener to 127.0.0.1 by default", function()
    assert.is_true(node.up, "metrics listener never came up; log:\n" ..
      tostring(read_file(node.log)))
    local addrs = listen_addrs(node.metrics)
    assert.are.same({ "0100007F" }, addrs,
      "metrics port must listen on 127.0.0.1 only (hex 0100007F); " ..
      "00000000 is 0.0.0.0")
  end)

  it("a client dribbling header bytes does not delay a concurrent request by more than 1 s", function()
    assert.is_true(node.up, "metrics listener never came up")
    local latency, closed_at = dribble_and_probe(node.metrics, 6)
    assert.is_not_nil(latency, "probe request was never answered")
    assert.is_true(latency < 1.0, string.format(
      "probe answered after %.2f s while another client dribbled headers " ..
      "(event loop blocked)", latency))
    assert.is_not_nil(closed_at, "dribbling client was never dropped")
    assert.is_true(closed_at < 4.0, string.format(
      "dribbling client held its connection for %.2f s; total request " ..
      "deadline is ~2 s", closed_at))
  end)
end)

describe("metrics listener (node, --metricsbind)", function()
  local node

  lazy_setup(function() node = start_node("--metricsbind 0.0.0.0") end)
  lazy_teardown(function() stop_node(node) end)

  it("--metricsbind 0.0.0.0 opts in to all interfaces", function()
    assert.is_true(node.up, "metrics listener never came up with " ..
      "--metricsbind 0.0.0.0; log:\n" .. tostring(read_file(node.log)))
    assert.are.same({ "00000000" }, listen_addrs(node.metrics))
  end)
end)

describe("metrics_server module", function()
  local ok_mod, ms = pcall(require, "lunarblock.metrics_server")

  local function new_server(opts)
    assert.is_true(ok_mod, "lunarblock.metrics_server is missing: " .. tostring(ms):match("[^\n]*"))
    opts = opts or {}
    opts.port = opts.port or free_port()
    opts.render = opts.render or function() return "bitcoin_blocks_total 7\n" end
    local srv = assert(ms.new(opts))
    return srv, opts.port
  end

  local function connect(port)
    local c = socket.tcp4()
    c:settimeout(2)
    assert(c:connect("127.0.0.1", port))
    return c
  end

  it("defaults the bind address to 127.0.0.1", function()
    assert.is_true(ok_mod, "lunarblock.metrics_server is missing: " .. tostring(ms):match("[^\n]*"))
    assert.are.equal("127.0.0.1", ms.DEFAULT_BIND)
    local srv, port = new_server()
    assert.are.equal("127.0.0.1", srv.bind)
    assert.are.same({ "0100007F" }, listen_addrs(port))
    srv:close()
  end)

  it("tick() returns at once while a client has sent only part of a request", function()
    local srv, port = new_server()
    local c = connect(port)
    c:send("GET /metrics HTTP/1.1\r\nHost: x\r\n")  -- no blank line yet
    socket.sleep(0.05)
    local t0 = socket.gettime()
    for _ = 1, 20 do srv:tick() end
    local dt = socket.gettime() - t0
    assert.is_true(dt < 0.2, string.format("20 ticks took %.3f s", dt))
    assert.are.equal(1, srv:client_count())
    -- Finishing the request gets the response.
    c:send("\r\n")
    socket.sleep(0.05)
    srv:tick()
    c:settimeout(2)
    local resp = c:receive("*a")
    assert.truthy(resp:find("HTTP/1.1 200 OK", 1, true))
    assert.truthy(resp:find("bitcoin_blocks_total 7", 1, true))
    assert.are.equal(0, srv:client_count())
    c:close()
    srv:close()
  end)

  it("drops a client that misses the total request deadline", function()
    local clock = 1000
    local srv, port = new_server({ now = function() return clock end })
    local c = connect(port)
    c:send("GET /metrics HTTP/1.1\r\n")
    socket.sleep(0.05)
    srv:tick()
    assert.are.equal(1, srv:client_count())
    -- Still sending, but past the deadline counted from accept.
    clock = clock + ms.REQUEST_DEADLINE + 0.01
    c:send("X-Late: 1\r\n")
    socket.sleep(0.05)
    srv:tick()
    assert.are.equal(0, srv:client_count())
    c:settimeout(1)
    local data, err = c:receive("*a")
    assert.are.equal("", data or "")
    c:close()
    srv:close()
  end)

  it("drops a client whose request exceeds the size cap", function()
    local srv, port = new_server()
    local c = connect(port)
    c:send("GET /metrics HTTP/1.1\r\nX-Big: " .. string.rep("a", ms.MAX_REQUEST_BYTES + 100))
    socket.sleep(0.05)
    for _ = 1, 10 do srv:tick() socket.sleep(0.01) end
    assert.are.equal(0, srv:client_count())
    c:close()
    srv:close()
  end)

  it("caps concurrent clients at MAX_CLIENTS and closes the rest on accept", function()
    local srv, port = new_server()
    local held = {}
    -- Fill the slots first (the listen backlog is MAX_CLIENTS too, so the
    -- extra connections are made after those are accepted).
    for i = 1, ms.MAX_CLIENTS do held[i] = connect(port) end
    socket.sleep(0.05)
    srv:tick()
    assert.are.equal(ms.MAX_CLIENTS, srv:client_count())
    local extra = {}
    for i = 1, 3 do extra[i] = connect(port) end
    socket.sleep(0.05)
    srv:tick()
    assert.are.equal(ms.MAX_CLIENTS, srv:client_count())
    for _, c in ipairs(extra) do
      c:settimeout(1)
      local _, err = c:receive(1)
      assert.are.equal("closed", err)
      c:close()
    end
    for _, c in ipairs(held) do c:close() end
    srv:close()
  end)
end)
