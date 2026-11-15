-- Prometheus metrics listener.
--
-- Core has no metrics port; its closest analogue is the HTTP RPC server, which
-- binds to localhost unless told otherwise (httpserver.cpp HTTPBindAddresses)
-- and serves requests on worker threads with a per-request timeout
-- (-rpcservertimeout). lunarblock runs a single event loop, so this listener
-- must never block it:
--
--   * the default bind address is 127.0.0.1; --metricsbind widens it;
--   * every socket is non-blocking; tick() reads whatever bytes are already
--     there and returns at once;
--   * each request has a total deadline (REQUEST_DEADLINE seconds from accept)
--     and a header-size cap (MAX_REQUEST_BYTES); a client that misses either is
--     dropped;
--   * at most MAX_CLIENTS requests are open at once; further connections are
--     closed on accept.
--
-- Before this module the listener lived inline in main.lua, bound 0.0.0.0 and
-- read the request line by line with a 2 s per-line timeout and no total
-- deadline, so one client sending a header line every 1.5 s froze the node.

local socket = require("socket")

local M = {}

M.DEFAULT_BIND = "127.0.0.1"
M.REQUEST_DEADLINE = 2.0      -- seconds from accept to a complete request
M.MAX_REQUEST_BYTES = 8192    -- request line + headers
M.MAX_CLIENTS = 16
M.READ_CHUNK = 4096

local MetricsServer = {}
MetricsServer.__index = MetricsServer

local function build_response(body)
  return string.format(
    "HTTP/1.1 200 OK\r\n" ..
    "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n" ..
    "Content-Length: %d\r\n" ..
    "Connection: close\r\n\r\n%s",
    #body, body)
end

--- Open the listener.
-- opts.port    TCP port (required, > 0)
-- opts.bind    address to bind (default M.DEFAULT_BIND)
-- opts.render  function() -> body string (Prometheus text format)
-- opts.now     clock override for tests (default socket.gettime)
-- Returns server, or nil + error string.
function M.new(opts)
  local bind = opts.bind
  if bind == nil or bind == "" then bind = M.DEFAULT_BIND end
  local sock
  if bind:find(":", 1, true) then
    sock = socket.tcp6()
  else
    sock = socket.tcp4()
  end
  if not sock then return nil, "socket creation failed" end
  sock:setoption("reuseaddr", true)
  local ok, err = sock:bind(bind, opts.port)
  if not ok then
    sock:close()
    return nil, err
  end
  ok, err = sock:listen(M.MAX_CLIENTS)
  if not ok then
    sock:close()
    return nil, err
  end
  sock:settimeout(0)
  return setmetatable({
    socket = sock,
    bind = bind,
    port = opts.port,
    render = opts.render or function() return "" end,
    now = opts.now or socket.gettime,
    clients = {},
  }, MetricsServer)
end

function MetricsServer:client_count()
  return #self.clients
end

function MetricsServer:_accept_all()
  -- Bounded so a connect flood cannot keep one tick() busy.
  for _ = 1, 2 * M.MAX_CLIENTS do
    local c = self.socket:accept()
    if not c then return end
    if #self.clients >= M.MAX_CLIENTS then
      c:close()
    else
      c:settimeout(0)
      self.clients[#self.clients + 1] = {
        sock = c, buf = "", deadline = self:now() + M.REQUEST_DEADLINE,
      }
    end
  end
end

-- Advance one client; return true when it is finished (and closed).
function MetricsServer:_step(cl)
  if self:now() > cl.deadline then
    cl.sock:close()
    return true
  end
  if not cl.out then
    local data, err, partial = cl.sock:receive(M.READ_CHUNK)
    data = data or partial
    if data and #data > 0 then cl.buf = cl.buf .. data end
    if cl.buf:find("\r?\n\r?\n") then
      local okr, body = pcall(self.render)
      if not okr or type(body) ~= "string" then body = "" end
      cl.out = build_response(body)
      cl.sent = 0
    elseif #cl.buf > M.MAX_REQUEST_BYTES or err == "closed" then
      cl.sock:close()
      return true
    else
      return false
    end
  end
  local last, err, partial_last = cl.sock:send(cl.out, cl.sent + 1)
  cl.sent = last or partial_last or cl.sent
  if cl.sent >= #cl.out or (err and err ~= "timeout") then
    cl.sock:close()
    return true
  end
  return false
end

--- Service the listener without blocking: accept pending connections and
-- advance every open request by whatever bytes are already available.
function MetricsServer:tick()
  self:_accept_all()
  local keep = {}
  for _, cl in ipairs(self.clients) do
    if not self:_step(cl) then keep[#keep + 1] = cl end
  end
  self.clients = keep
end

function MetricsServer:close()
  for _, cl in ipairs(self.clients) do cl.sock:close() end
  self.clients = {}
  if self.socket then self.socket:close() end
  self.socket = nil
end

return M
