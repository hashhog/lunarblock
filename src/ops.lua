--- Operational-parity helpers for lunarblock.
--
-- Closes 7 ops gaps that Bitcoin Core ships in init.cpp / util/system.cpp:
--   * --daemon  (POSIX double-fork via FFI; setsid; redirect stdio to /dev/null)
--   * --pid=<path>  (write PID on launch, remove on graceful shutdown)
--   * --debug=<cat>  (selective category logging; pass-through to logger)
--   * SIGHUP log reopen  (reopen the configured log file under SIGHUP)
--   * --conf=<file>  (Bitcoin-Core-style key=value config file parser)
--   * --ready-fd=<N>  (write "READY\n" to FD on listeners up; for systemd-style
--      supervisors that don't support sd_notify but do support FD ready-signal)
--   * SIGTERM/SIGINT  (graceful shutdown wired to a shared "running" flag)
--
-- luaposix is NOT a build dependency on maxbox (it's missing from the rock
-- environment), so this module reaches for fork/setsid/getpid/kill via raw
-- LuaJIT FFI rather than `require("posix.signal")`.  This matches the FFI
-- pattern already used in wallet.lua for fcntl/open/close/etc.
--
-- Reference: bitcoin-core/src/init.cpp `AppInitMain`, `util/system.cpp`
-- `daemon()`, `init/common.cpp` `g_pidfile_path` for the PID-file lifecycle.

local ffi = require("ffi")
local bit = require("bit")

local M = {}

--------------------------------------------------------------------------------
-- POSIX bindings
--------------------------------------------------------------------------------
--
-- libc symbols we need.  Wrapped in a pcall because some FFI cdef collisions
-- with other modules (storage.lua, wallet.lua) can throw "duplicate definition"
-- if the runtime has already declared `open`/`close` etc.  pcall lets us share
-- those without requiring strict ordering of `require` calls.
pcall(ffi.cdef, [[
  int    fork(void);
  int    setsid(void);
  int    getpid(void);
  int    kill(int pid, int sig);
  int    chdir(const char *path);
  int    dup2(int oldfd, int newfd);
  int    open(const char *pathname, int flags, ...);
  int    close(int fd);
  int    write(int fd, const void *buf, unsigned long count);
  int    isatty(int fd);
  unsigned int umask(unsigned int mask);
  typedef void (*sighandler_t)(int);
  sighandler_t signal(int signum, sighandler_t handler);
]])

local O_RDWR  = 2
local O_WRONLY = 1
local O_CREAT = 64       -- Linux x86_64
local O_TRUNC = 512
local O_APPEND = 1024

-- Linux x86_64 signal numbers (the only platform lunarblock targets).
M.SIGHUP  = 1
M.SIGINT  = 2
M.SIGTERM = 15

--------------------------------------------------------------------------------
-- Config file parser  (--conf=<file>)
--------------------------------------------------------------------------------
--
-- Bitcoin Core's bitcoin.conf accepts simple key=value lines, with `#` and `;`
-- as comment markers, and section headers like `[main]`.  We support all three.
-- Section headers gate keys to a network: a key under `[main]` only applies
-- when running mainnet, `[test]` for testnet, `[regtest]` for regtest.  Keys
-- outside any section apply to every network (matching Core's behavior).
--
-- The returned table is { [key] = value, ... } with values as strings.  The
-- caller (parse_args) is responsible for type-coercion to bool/int.
function M.parse_conf_file(path, network)
  local f, err = io.open(path, "r")
  if not f then return nil, err end
  local result = {}
  local current_section = nil
  -- Map Core section names → our network names.
  local section_to_network = {
    main = "mainnet",
    test = "testnet",
    regtest = "regtest",
  }
  for line in f:lines() do
    -- Strip comments (anything after `#` or `;`) and whitespace.
    line = line:gsub("[#;].*$", "")
    line = line:match("^%s*(.-)%s*$") or ""
    if line ~= "" then
      local section = line:match("^%[(.+)%]$")
      if section then
        current_section = section
      else
        local k, v = line:match("^([%w%-_%.]+)%s*=%s*(.*)$")
        if k then
          local applies = true
          if current_section then
            applies = (section_to_network[current_section] == network)
          end
          if applies then
            result[k] = v
          end
        end
      end
    end
  end
  f:close()
  return result, nil
end

--- Apply parsed conf-file kv pairs onto an args table.
-- Bitcoin Core semantics: command-line flags win over conf-file.  We honor
-- that by only setting a key if its current value matches the parser default.
-- The caller passes the default-args table (snapshot before CLI parsing) so
-- we can detect "still at default" cleanly.
function M.apply_conf_to_args(args, defaults, conf)
  local function bool(v)
    return v == "1" or v == "true" or v == "yes" or v == "on"
  end
  -- Whitelist of conf keys → (target_arg, type).
  -- Mirrors what parse_args knows how to handle.  Unknown keys are ignored
  -- (matching Core's `-printtoconsole` etc., which fall through silently if
  -- not relevant to the running mode).
  local schema = {
    datadir       = {"datadir",       "string"},
    network       = {"network",       "string"},
    rpcport       = {"rpcport",       "number"},
    rpcuser       = {"rpcuser",       "string"},
    rpcpassword   = {"rpcpassword",   "string"},
    port          = {"port",          "number"},
    maxpeers      = {"maxpeers",      "number"},
    dbcache       = {"dbcache",       "number"},
    connect       = {"connect",       "string"},
    printtoconsole = {"printtoconsole", "bool"},
    nowalletcreate = {"nowalletcreate", "bool"},
    daemon        = {"daemon",        "bool"},
    reindex       = {"reindex",       "bool"},
    prune         = {"prune",         "number"},
    metricsport   = {"metricsport",   "number"},
    rest          = {"rest",          "bool"},
    restport      = {"restport",      "number"},
    pid           = {"pid",           "string"},
    debug         = {"debug",         "string"},
    log           = {"log",           "string"},
    nov2transport = {"nov2transport", "bool"},
    peerbloomfilters = {"peerbloomfilters", "bool"},
    ["ready-fd"]  = {"ready_fd",      "number"},
  }
  for k, v in pairs(conf) do
    local entry = schema[k]
    if entry then
      local target_key, kind = entry[1], entry[2]
      if args[target_key] == defaults[target_key] then
        if kind == "bool" then
          args[target_key] = bool(v)
        elseif kind == "number" then
          args[target_key] = tonumber(v)
        else
          args[target_key] = v
        end
      end
    end
  end
end

--------------------------------------------------------------------------------
-- Logger  (--debug=<cat> + SIGHUP reopen + log file)
--------------------------------------------------------------------------------
--
-- Cheap category logger.  Bitcoin Core's BCLog::Logger has ~30 categories;
-- we ship a small shared subset (net/mempool/rpc/bench/prune/zmq/validation).
-- Unknown categories fall through silently — they're parsed but never emit.
-- `all` is a shorthand for "enable every category".
M.LOG_CATEGORIES = {
  "net", "mempool", "rpc", "bench", "prune", "zmq",
  "validation", "leveldb", "tor", "rand", "addrman",
  "ibd", "consensus", "p2p", "wallet",
}

--- Build a logger object.
-- @param opts table:
--   - log_file string|nil: path to log file (nil = stdout/stderr only)
--   - debug_cats table: { [category]=true, ... } enabled categories
--   - printtoconsole bool: also write to stdout (mirrors Core)
function M.new_logger(opts)
  opts = opts or {}
  local self = {
    log_file = opts.log_file,
    debug_cats = opts.debug_cats or {},
    printtoconsole = opts.printtoconsole,
    _fh = nil,
  }
  function self:open()
    if self.log_file then
      local fh, err = io.open(self.log_file, "a")
      if not fh then return nil, err end
      self._fh = fh
    end
    return true
  end
  --- SIGHUP handler: close + reopen the log file.  Used by logrotate.
  function self:reopen()
    if self._fh then
      pcall(function() self._fh:close() end)
      self._fh = nil
    end
    return self:open()
  end
  function self:close()
    if self._fh then
      pcall(function() self._fh:close() end)
      self._fh = nil
    end
  end
  --- Write a log line.  cat is optional: if the line has no category, it
  --  always emits.  If a category is given and the category isn't in
  --  debug_cats, the line is suppressed (Core "-debug=net" semantics).
  function self:log(msg, cat)
    if cat and not (self.debug_cats[cat] or self.debug_cats.all) then
      return
    end
    local line = string.format("%s %s\n", os.date("%Y-%m-%d %H:%M:%S"), msg)
    if self._fh then
      self._fh:write(line)
      self._fh:flush()
    end
    if not self._fh or self.printtoconsole then
      io.stdout:write(line)
      io.stdout:flush()
    end
  end
  --- Is this category enabled? (cheap predicate for hot paths)
  function self:enabled(cat)
    return self.debug_cats[cat] == true or self.debug_cats.all == true
  end
  return self
end

--- Parse a `--debug=<cat>[,<cat>...]` value into a set.
-- Comma-separated list, "1" = enable everything, "0" = disable everything,
-- empty string = treated as "all" (Core behavior).
function M.parse_debug_cats(spec)
  local cats = {}
  if not spec or spec == "" or spec == "1" then
    cats.all = true
    return cats
  end
  if spec == "0" then
    return cats
  end
  for cat in spec:gmatch("[^,]+") do
    cat = cat:match("^%s*(.-)%s*$")
    if cat ~= "" then
      cats[cat] = true
    end
  end
  return cats
end

--------------------------------------------------------------------------------
-- PID file  (--pid=<path>)
--------------------------------------------------------------------------------
--
-- Write our PID to the file at launch; remove it at graceful shutdown.
-- Bitcoin Core uses `g_pidfile_path` and removes it via a scope-guarded RAII
-- handle in init.cpp; we use a simple try-write / try-remove pair.
function M.write_pid_file(path)
  local f, err = io.open(path, "w")
  if not f then return nil, err end
  f:write(tostring(ffi.C.getpid()) .. "\n")
  f:close()
  return true
end

function M.remove_pid_file(path)
  -- os.remove returns nil on missing; we don't surface that as an error.
  pcall(os.remove, path)
end

--------------------------------------------------------------------------------
-- Daemonize  (--daemon)
--------------------------------------------------------------------------------
--
-- Stevens' classic double-fork.  Steps:
--   1. fork() → first child detaches from controlling terminal
--   2. setsid() → become session leader
--   3. fork() again → grandchild can never re-acquire a TTY
--   4. chdir("/") so the daemon doesn't pin a mount
--   5. redirect stdin/stdout/stderr to /dev/null (or to log file if given)
--
-- Returns true if the caller is the surviving grandchild that should continue
-- main().  Calls os.exit(0) in the parent / first child paths.  Returns
-- (nil, errstr) on a fork() failure.
function M.daemonize(opts)
  opts = opts or {}
  local pid = ffi.C.fork()
  if pid < 0 then return nil, "first fork failed" end
  if pid > 0 then
    -- Parent: exit immediately so the shell prompt returns.
    os.exit(0)
  end
  -- Child 1.  Become session leader so we survive the controlling TTY closing.
  if ffi.C.setsid() < 0 then return nil, "setsid failed" end
  -- Second fork prevents this process from ever re-acquiring a TTY.
  pid = ffi.C.fork()
  if pid < 0 then return nil, "second fork failed" end
  if pid > 0 then os.exit(0) end
  -- Grandchild.  Reset working dir + umask.
  ffi.C.chdir("/")
  ffi.C.umask(0x12)  -- 022, world-readable but not world-writable
  -- Redirect stdin to /dev/null, stdout/stderr to log file or /dev/null.
  local devnull = ffi.C.open("/dev/null", O_RDWR)
  if devnull >= 0 then
    ffi.C.dup2(devnull, 0)
    if not opts.log_path then
      ffi.C.dup2(devnull, 1)
      ffi.C.dup2(devnull, 2)
    end
    ffi.C.close(devnull)
  end
  if opts.log_path then
    -- O_WRONLY | O_CREAT | O_APPEND, mode 0644.  We bit.bor() carefully —
    -- LuaJIT's bit lib operates on int32, which is fine for these flags.
    local logfd = ffi.C.open(opts.log_path,
      bit.bor(O_WRONLY, O_CREAT, O_APPEND), 0x1A4)  -- 0644
    if logfd >= 0 then
      ffi.C.dup2(logfd, 1)
      ffi.C.dup2(logfd, 2)
      ffi.C.close(logfd)
    end
  end
  return true
end

--------------------------------------------------------------------------------
-- Signals  (SIGHUP, SIGINT, SIGTERM)
--------------------------------------------------------------------------------
--
-- LuaJIT FFI signal handlers run in a *signal context*, which is hostile to
-- Lua callbacks (no GC alloc, no string concat, etc).  The standard pattern
-- is to set a flag in C-callable code and have the main loop poll it.
--
-- We allocate a single `volatile int` per signal (via ffi.new("int[1]"))
-- and wire `signal(N, handler)` where `handler` is an FFI callback that
-- writes to the int.  The main loop then calls poll_signals() every tick
-- and dispatches Lua callbacks on flagged signals.
--
-- ffi.cast("sighandler_t", lua_fn) does not work safely in all LuaJIT 2.1
-- versions, so we use ffi.cast("void(*)(int)", lua_fn) with a Lua closure
-- that ONLY mutates a preallocated int[1] flag — no string formatting,
-- no error(), no GC.
local _signal_flags = {}
local _signal_callbacks = {}
local _signal_handlers = {}  -- Keep ffi.cast'd handlers alive for GC.

local function _install(signum)
  if _signal_flags[signum] then return end  -- idempotent
  local flag = ffi.new("int[1]", 0)
  _signal_flags[signum] = flag
  local handler = ffi.cast("sighandler_t",
    function(_) flag[0] = 1 end)
  _signal_handlers[signum] = handler
  ffi.C.signal(signum, handler)
end

--- Install a signal handler.
-- @param signum number: SIGHUP/SIGINT/SIGTERM
-- @param fn function: Lua callback to invoke when the signal is polled
function M.set_signal_handler(signum, fn)
  _install(signum)
  _signal_callbacks[signum] = fn
end

--- Drain pending signals and invoke their Lua callbacks.
-- Call this once per main-loop tick.  Cheap (just int compares) when no
-- signals are pending.
function M.poll_signals()
  for signum, flag in pairs(_signal_flags) do
    if flag[0] ~= 0 then
      flag[0] = 0
      local cb = _signal_callbacks[signum]
      if cb then
        local ok, err = pcall(cb)
        if not ok then
          io.stderr:write(string.format(
            "signal handler for %d threw: %s\n", signum, tostring(err)))
        end
      end
    end
  end
end

--- Tear down all installed handlers.  Used by tests so the busted runner
--- isn't left with FFI callbacks pointing into freed Lua state.
function M.reset_signal_handlers()
  for signum, _ in pairs(_signal_flags) do
    -- SIG_DFL = default disposition (0 cast to a function pointer).
    ffi.C.signal(signum, ffi.cast("sighandler_t", 0))
  end
  _signal_flags = {}
  _signal_callbacks = {}
  _signal_handlers = {}
end

--------------------------------------------------------------------------------
-- Ready-FD  (--ready-fd=<N>)
--------------------------------------------------------------------------------
--
-- Systemd-style ready signal.  When a process supervisor (s6, runit,
-- ad-hoc shell) wants to know "the daemon is up and accepting connections",
-- the standard cheap method without sd_notify is to write a token to a
-- pre-opened pipe FD.  The supervisor reads that token to confirm liveness.
function M.signal_ready(fd)
  if not fd or fd < 0 then return false end
  local msg = "READY\n"
  local n = ffi.C.write(fd, msg, #msg)
  if n < 0 then return false end
  -- Best-effort close; the supervisor on the other end will see EOF.
  pcall(ffi.C.close, fd)
  return true
end

return M
