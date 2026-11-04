-- Security: RPC must never run unauthenticated, and no RPC input may reach a
-- shell.
--
-- Before the fix:
--   * with no --rpcpassword the server skipped the auth check entirely, so any
--     local process (or a browser page POSTing blind to 127.0.0.1) could call
--     every RPC;
--   * wallet names and backup paths were spliced into os.execute/io.popen
--     command lines ("mkdir -p '<dir>'", 'test -d "<path>"', "ls -1 '<dir>'"),
--     so a name containing a quote or $(...) ran commands as the node's user.
--
-- Reference: bitcoin-core/src/httprpc.cpp (HTTPReq_JSONRPC, RPCAuthorized,
-- CheckUserAuthorized, InitRPCAuthentication), src/rpc/request.cpp
-- (GenerateAuthCookie, DeleteAuthCookie).
--
-- The HTTP tests drive the real RPCServer:tick() over a loopback socket: the
-- client writes a whole request into the kernel buffer, tick() accepts, reads
-- and answers it, and the client then reads the reply.

local rpc = require("lunarblock.rpc")
local consensus = require("lunarblock.consensus")
local wallet_mod = require("lunarblock.wallet")
local socket = require("socket")
local cjson = require("cjson")

local function sh_quote(s) return "'" .. s:gsub("'", "'\\''") .. "'" end

local function make_tmpdir(tag)
  local p = os.tmpname()
  os.remove(p)
  p = p .. "_" .. tag
  os.execute("mkdir -p " .. sh_quote(p))
  return p
end

local function rm_rf(p)
  if p and p ~= "" and p ~= "/" then os.execute("rm -rf " .. sh_quote(p)) end
end

local function file_exists(p)
  local f = io.open(p, "rb")
  if f then f:close() return true end
  return false
end

local function read_file(p)
  local f = io.open(p, "rb")
  if not f then return nil end
  local d = f:read("*a")
  f:close()
  return d
end

local function file_mode(p)
  local h = io.popen("stat -c %a " .. sh_quote(p) .. " 2>/dev/null")
  local out = h:read("*a")
  h:close()
  return (out:gsub("%s+$", ""))
end

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function b64(s)
  local pad = (3 - #s % 3) % 3
  local p = s .. string.rep("\0", pad)
  local out = {}
  for i = 1, #p, 3 do
    local a, b, c = p:byte(i, i + 2)
    local n = a * 65536 + b * 256 + c
    for _, sh in ipairs({18, 12, 6, 0}) do
      local k = math.floor(n / 2 ^ sh) % 64
      out[#out + 1] = B64:sub(k + 1, k + 1)
    end
  end
  local r = table.concat(out)
  if pad > 0 then r = r:sub(1, -pad - 1) .. string.rep("=", pad) end
  return r
end

-- Explicit port band 19700-19799: below the kernel's ephemeral range and away
-- from the fleet's reserved bands (port 0 could land on a fleet port; see the
-- PORT SAFETY note in spec/orphan_scripts_spec.lua).
local function new_server(cfg)
  cfg = cfg or {}
  cfg.host = "127.0.0.1"
  cfg.network = consensus.networks.regtest
  for port = 19700, 19799 do
    cfg.rpcport = port
    local s = rpc.new(cfg)
    if pcall(s.start, s) then
      s._test_port = port
      return s
    end
    s:stop()
  end
  error("no free RPC test port in 19700-19799")
end

-- Send one raw HTTP request, let the server handle it, return status, raw.
local function roundtrip(server, opts)
  opts = opts or {}
  local body = opts.body or '{"jsonrpc":"1.0","id":1,"method":"uptime","params":[]}'
  local lines = {
    (opts.method or "POST") .. " " .. (opts.path or "/") .. " HTTP/1.1",
    "Host: 127.0.0.1",
    "Content-Type: " .. (opts.content_type or "application/json"),
    "Content-Length: " .. #body,
  }
  if opts.auth then lines[#lines + 1] = "Authorization: Basic " .. b64(opts.auth) end
  for _, h in ipairs(opts.headers or {}) do lines[#lines + 1] = h end
  local raw = table.concat(lines, "\r\n") .. "\r\n\r\n" .. body
  local c = socket.tcp4()
  c:settimeout(3)
  assert(c:connect("127.0.0.1", server._test_port))
  assert(c:send(raw))
  server:tick()
  local resp, _, partial = c:receive("*a")
  c:close()
  resp = resp or partial or ""
  return tonumber(resp:match("^HTTP/1%.1 (%d+)")), resp
end

local function read_cookie(dir)
  local data = read_file(dir .. "/.cookie")
  assert.is_not_nil(data, "no .cookie written in " .. dir)
  return data
end

describe("sec: RPC authentication is mandatory (Core cookie auth)", function()
  local dir, server

  before_each(function()
    dir = make_tmpdir("lbauth")
    server = new_server({cookie_dir = dir, rpcpassword = ""})
  end)

  after_each(function()
    if server then server:stop() end
    rm_rf(dir)
  end)

  it("refuses an unauthenticated POST with 401 when no --rpcpassword is set", function()
    local status = roundtrip(server, {})
    assert.equal(401, status)
  end)

  it("writes <datadir>/.cookie as __cookie__:<64 hex> with mode 0600", function()
    local data = read_cookie(dir)
    assert.is_truthy(data:match("^__cookie__:%x+$"), "cookie format: " .. data)
    assert.equal(64, #data:match(":(%x+)$"))
    assert.equal("600", file_mode(dir .. "/.cookie"))
  end)

  it("accepts the cookie credential", function()
    local status, resp = roundtrip(server, {auth = read_cookie(dir)})
    assert.equal(200, status)
    local body = cjson.decode(resp:match("\r\n\r\n(.*)$"))
    assert.is_number(body.result)
  end)

  it("answers a wrong cookie with 401 and WWW-Authenticate: Basic realm=\"jsonrpc\"", function()
    local status, resp = roundtrip(server, {auth = "__cookie__:" .. string.rep("0", 64)})
    assert.equal(401, status)
    assert.is_truthy(resp:find('WWW%-Authenticate: Basic realm="jsonrpc"'))
  end)

  it("refuses malformed Basic auth (no colon, wrong scheme)", function()
    assert.equal(401, (roundtrip(server, {auth = "nocolon"})))
    assert.equal(401, (roundtrip(server, {headers = {"Authorization: Bearer abc"}})))
  end)

  it("refuses a request carrying an Origin header with 403 even with valid credentials", function()
    local status = roundtrip(server, {auth = read_cookie(dir),
                                      headers = {"Origin: http://evil.example"}})
    assert.equal(403, status)
  end)

  it("accepts content-type text/plain with valid credentials, as Core does", function()
    -- Core ignores Content-Type; its documented curl example sends text/plain.
    -- Auth, not the content type, is what stops a cross-site form post.
    assert.equal(401, (roundtrip(server, {content_type = "text/plain;"})))
    assert.equal(200, (roundtrip(server, {auth = read_cookie(dir), content_type = "text/plain;"})))
  end)

  it("requires auth for GET /health and /wallet/<name> too", function()
    assert.equal(401, (roundtrip(server, {method = "GET", path = "/health", body = ""})))
    assert.equal(401, (roundtrip(server, {path = "/wallet/w"})))
    assert.equal(200, (roundtrip(server, {method = "GET", path = "/health", body = "",
                                          auth = read_cookie(dir)})))
  end)

  it("deletes the cookie on stop()", function()
    assert.is_true(file_exists(dir .. "/.cookie"))
    server:stop()
    server = nil
    assert.is_false(file_exists(dir .. "/.cookie"))
  end)

  it("writes a fresh cookie on every start", function()
    local first = read_cookie(dir)
    server:stop()
    server = new_server({cookie_dir = dir})
    assert.are_not.equal(first, read_cookie(dir))
  end)
end)

describe("sec: RPC password and rpcauth credentials", function()
  local server
  after_each(function() if server then server:stop() end server = nil end)

  it("--rpcpassword: right credential 200, wrong 401, none 401", function()
    server = new_server({rpcuser = "u", rpcpassword = "p"})
    assert.equal(200, (roundtrip(server, {auth = "u:p"})))
    assert.equal(401, (roundtrip(server, {auth = "u:x"})))
    assert.equal(401, (roundtrip(server, {auth = "x:p"})))
    assert.equal(401, (roundtrip(server, {})))
  end)

  it("does not keep the plaintext password on the server object", function()
    server = new_server({rpcuser = "u", rpcpassword = "s3cret-plaintext"})
    for k, v in pairs(server) do
      assert.are_not.equal("s3cret-plaintext", v, "plaintext stored in field " .. tostring(k))
    end
  end)

  it("--rpcauth user:salt$hmac (Core share/rpcauth format) authenticates", function()
    local crypto = require("lunarblock.crypto")
    local salt = "cb77f0957de88ff388cf817ddbc7273"
    local mac = crypto.hmac_sha256(salt, "hunter2")
    local hex = (mac:gsub(".", function(ch) return string.format("%02x", ch:byte()) end))
    server = new_server({rpcauth = {"alice:" .. salt .. "$" .. hex}})
    assert.equal(200, (roundtrip(server, {auth = "alice:hunter2"})))
    assert.equal(401, (roundtrip(server, {auth = "alice:hunter3"})))
  end)

  it("fails closed: no password and no cookie dir refuses every request", function()
    server = new_server({})
    assert.equal(401, (roundtrip(server, {})))
    assert.equal(401, (roundtrip(server, {auth = "lunarblock:"})))
  end)
end)

describe("sec: RPC input never reaches a shell", function()
  local dir, marker

  before_each(function()
    dir = make_tmpdir("lbshell")
    -- Relative marker name: the injected command runs in the test's cwd, and a
    -- payload without "/" passes the old wallet-name character filter.
    marker = "lb_pwned_" .. tostring(os.time()) .. "_" .. tostring(math.random(1e9))
    os.remove(marker)
  end)

  after_each(function()
    os.remove(marker)
    rm_rf(dir)
  end)

  local function rpc_with_manager()
    local mgr = wallet_mod.new_manager(dir, consensus.networks.regtest, nil)
    mgr:ensure_wallets_dir()
    local s = rpc.new({network = consensus.networks.regtest, wallet_manager = mgr,
                       datadir = dir})
    return s, mgr
  end

  it("createwallet name with a quote does not run a command", function()
    local _, mgr = rpc_with_manager()
    pcall(function() mgr:create_wallet("x'; touch " .. marker .. "; '", {blank = true}) end)
    for n in pairs(mgr.wallets) do mgr:release_lock(n) end
    assert.is_false(file_exists(marker), "shell command ran from a wallet name")
  end)

  it("restorewallet name with $(...) does not run a command", function()
    local s, mgr = rpc_with_manager()
    assert.is_not_nil(mgr:create_wallet("src", {blank = true}))
    local backup = mgr:get_wallet_path("src")
    pcall(s.methods["restorewallet"], s, {"r$(touch " .. marker .. ")", backup})
    for n in pairs(mgr.wallets) do mgr:release_lock(n) end
    assert.is_false(file_exists(marker), "shell command ran from a restorewallet name")
  end)

  it("backupwallet destination with $(...) does not run a command", function()
    local s, mgr = rpc_with_manager()
    local w = assert(mgr:create_wallet("b", {blank = true}))
    s.request_wallet = w
    pcall(s.methods["backupwallet"], s, {"$(touch " .. marker .. ")/out.json"})
    for n in pairs(mgr.wallets) do mgr:release_lock(n) end
    assert.is_false(file_exists(marker), "shell command ran from a backupwallet path")
  end)

  it("backupwallet still writes to an existing directory", function()
    local s, mgr = rpc_with_manager()
    local w = assert(mgr:create_wallet("b2", {blank = true}))
    s.request_wallet = w
    local dest = dir .. "/backup.json"
    s.methods["backupwallet"](s, {dest})
    for n in pairs(mgr.wallets) do mgr:release_lock(n) end
    assert.is_true(file_exists(dest))
  end)

  it("listwalletdir works when the datadir contains a quote", function()
    local qdir = dir .. "/it's"
    os.execute("mkdir -p " .. sh_quote(qdir))
    local mgr = wallet_mod.new_manager(qdir, consensus.networks.regtest, nil)
    mgr:ensure_wallets_dir()
    assert.is_not_nil(mgr:create_wallet("a", {blank = true}))
    local names = {}
    for _, e in ipairs(mgr:list_wallet_dir()) do names[#names + 1] = e.name end
    for n in pairs(mgr.wallets) do mgr:release_lock(n) end
    assert.same({"a"}, names)
  end)

  it("wallet names cannot traverse out of the wallets directory", function()
    local _, mgr = rpc_with_manager()
    assert.is_not_nil(mgr:create_wallet("inner", {blank = true}))
    assert.is_true(mgr:unload_wallet("inner"))
    local w = mgr:load_wallet("../wallets/inner")
    if w then mgr:release_lock("../wallets/inner") end
    assert.is_nil(w, "load_wallet followed ../ out of the wallets dir")
    assert.is_nil((mgr:create_wallet("..", {blank = true})))
    assert.is_nil((mgr:create_wallet(".", {blank = true})))
    assert.is_nil((mgr:create_wallet("a\0b", {blank = true})))
    for n in pairs(mgr.wallets) do mgr:release_lock(n) end
  end)

  it("importmnemonic refuses a wallet name that leaves the wallets directory", function()
    local s, mgr = rpc_with_manager()
    local mnem = "abandon abandon abandon abandon abandon abandon"
      .. " abandon abandon abandon abandon abandon about"
    -- <wallets_dir>/../wallet.json is <datadir>/wallet.json.
    local escaped = dir .. "/wallet.json"
    os.remove(escaped)
    for _, bad in ipairs({"..", ".", "../x", "a/b", "a\0b"}) do
      local ok, err = pcall(s.methods["importmnemonic"], s, {mnem, "", bad})
      assert.is_false(ok, "importmnemonic accepted wallet name " .. bad)
      assert.equals(rpc.ERROR.WALLET_ERROR, err.code)
      assert.is_nil(mgr.wallets[bad])
    end
    assert.is_false(file_exists(escaped),
      "importmnemonic wrote <wallets_dir>/../wallet.json")
    -- Control: a plain name is still accepted and registered, so the
    -- refusals above come from the name check, not the mnemonic or manager.
    -- (Whether the file then lands on disk is a separate, older gap:
    -- importmnemonic never creates <wallets_dir>/<name>/.)
    local res = s.methods["importmnemonic"](s, {mnem, "", "good"})
    assert.equals("good", res.wallet_name)
    assert.is_not_nil(mgr.wallets["good"])
    assert.is_false(file_exists(escaped))
  end)

  it("no os.execute or io.popen call remains in src/", function()
    local h = io.popen("ls src/*.lua")
    local hits = {}
    for path in h:lines() do
      local n = 0
      for line in io.lines(path) do
        n = n + 1
        local code = line:gsub("%-%-.*$", "")
        if code:find("os%.execute%s*%(") or code:find("io%.popen%s*%(") then
          hits[#hits + 1] = path .. ":" .. n
        end
      end
    end
    h:close()
    assert.same({}, hits)
  end)
end)

describe("sec: fsutil (shell-free filesystem helpers)", function()
  local dir
  before_each(function() dir = make_tmpdir("lbfs") end)
  after_each(function() rm_rf(dir) end)

  local function fsutil()
    local ok, m = pcall(require, "lunarblock.fsutil")
    assert.is_true(ok, "lunarblock.fsutil missing")
    return m
  end

  it("mkdir_p / is_dir / list_dir / dir_size", function()
    local fs = fsutil()
    local deep = dir .. "/a b/c'd/$(x)"
    assert.is_true((fs.mkdir_p(deep)))
    assert.is_true(fs.is_dir(deep))
    assert.is_false(fs.is_dir(dir .. "/nope"))
    local f = io.open(deep .. "/f", "wb"); f:write(string.rep("z", 1000)); f:close()
    f = io.open(dir .. "/g", "wb"); f:write("12345"); f:close()
    assert.equal(1005, fs.dir_size(dir))
    local names = {}
    for _, e in ipairs(fs.list_dir(dir)) do names[#names + 1] = e.name end
    assert.same({"a b", "g"}, names)
    assert.is_nil(fs.list_dir(dir .. "/nope"))
  end)

  it("write_file_mode creates the file 0600", function()
    local fs = fsutil()
    assert.is_true((fs.write_file_mode(dir .. "/c", "data", 384)))
    assert.equal("600", file_mode(dir .. "/c"))
    assert.equal("data", read_file(dir .. "/c"))
  end)
end)
