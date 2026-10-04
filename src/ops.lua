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
    -- FIX-64 (W119): PEM paths for optional HTTPS RPC termination.  Bare
    -- ASCII flag names (TOML `rpc-tls-cert = "..."`) and the underscore
    -- aliases stay parseable through the same path-style key handling that
    -- `ready-fd` uses.
    ["rpc-tls-cert"] = {"rpc_tls_cert", "string"},
    ["rpc-tls-key"]  = {"rpc_tls_key",  "string"},
    port          = {"port",          "number"},
    bind          = {"bind",          "string"},
    maxpeers      = {"maxpeers",      "number"},
    maxconnections = {"maxpeers",     "number"},
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
    -- Full-script-verification parity (Bitcoin Core -assumevalid).
    -- noassumevalid=1 (bool) or assumevalid=0 (string) disables the
    -- assumevalid script-skip; assumevalid=<hash> overrides the trusted block.
    -- Wired in main.lua right after network selection.
    noassumevalid = {"noassumevalid", "bool"},
    assumevalid   = {"assumevalid",   "string"},
    -- Self-address advertisement (Core -externalip / -discover); main.lua
    -- splits externalip on commas and resolves the discover default.
    externalip    = {"externalip",    "string"},
    discover      = {"discover",      "bool"},
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
-- Live category-mask mutation (the `logging` RPC).
--------------------------------------------------------------------------------
--
-- Bitcoin Core's `logging` RPC (rpc/node.cpp:218) mutates the global
-- BCLog::Logger::m_categories bitmask IN MEMORY, taking effect immediately
-- with no restart.  These helpers do the equivalent on lunarblock's live
-- logger: they mutate the SAME `logger.debug_cats` table that `logger:log`
-- and `logger:enabled` consult on EVERY record.  Nothing is snapshotted, so a
-- toggle takes effect the instant the table is mutated — this is the trap the
-- ouroboros reference (f11846a) called out: a filter that snapshots its
-- category set at construction will NOT honour a runtime toggle.  Here there
-- is no snapshot to go stale; `self:enabled(cat)` reads `debug_cats[cat]` /
-- `debug_cats.all` live.
--
-- The `all` token is stored as the `debug_cats.all` flag (already understood
-- by logger:log / logger:enabled as "every category on"), matching Core's
-- BCLog::ALL.  Enabling a single category does NOT clear `.all`; disabling
-- `all` clears the whole mask, mirroring Core's DisableCategory(ALL).

--- The live debug-category mask of the running node, or nil if no logger has
--  been installed yet (e.g. a unit-test harness that never called new_logger).
-- @return table|nil: the logger's live `debug_cats` table
function M.get_logger_categories()
  local logger = package.loaded["lunarblock.logger"]
  if logger and type(logger.debug_cats) == "table" then
    return logger.debug_cats
  end
  return nil
end

--- Is `cat` currently being debug-logged on the live logger?  Reads the SAME
--  predicate logger:enabled uses, so the answer is exactly "would this
--  category's DEBUG lines emit right now".  `all` flips every category true.
-- @param cat string
-- @return boolean
function M.category_active(cat)
  local dc = M.get_logger_categories()
  if not dc then return false end
  return dc[cat] == true or dc.all == true
end

--- Enable a single category (or every category for the `all` token) on the
--  live logger, taking effect immediately.  No-op (returns false) when no
--  logger is installed.
-- @param cat string  -- a category name, or "all"/"1"/"" for the full mask
-- @return boolean: true if a logger was present and mutated
function M.enable_category(cat)
  local dc = M.get_logger_categories()
  if not dc then return false end
  if cat == "all" or cat == "1" or cat == "" then
    dc.all = true
  else
    dc[cat] = true
  end
  return true
end

--- Disable a single category (or every category for the `all` token) on the
--  live logger.  Disabling `all` clears the WHOLE mask (Core
--  DisableCategory(ALL) parity), not just the `.all` flag.  No-op (returns
--  false) when no logger is installed.
-- @param cat string  -- a category name, or "all"/"1"/"" for the full mask
-- @return boolean: true if a logger was present and mutated
function M.disable_category(cat)
  local dc = M.get_logger_categories()
  if not dc then return false end
  if cat == "all" or cat == "1" or cat == "" then
    -- Clear every per-category flag AND the all flag: turning "all" off must
    -- leave nothing logging (Core's m_categories = NONE).
    for k in pairs(dc) do dc[k] = nil end
  else
    dc[cat] = nil
    -- If the `all` flag was on, an individual disable would be masked by it
    -- (logger:enabled returns true while .all is set).  Core has no such
    -- shadowing: DisableCategory(net) under ALL leaves every OTHER category
    -- on but net off.  Reproduce that by expanding .all into explicit
    -- per-category flags, then dropping the one being disabled.
    if dc.all then
      dc.all = nil
      for _, name in ipairs(M.LOG_CATEGORIES) do
        if name ~= cat then dc[name] = true end
      end
    end
  end
  return true
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
-- NO FFI CALLBACK IS EVER INSTALLED AS A SIGNAL HANDLER.
--
-- The previous design wired signal(N, ffi.cast("sighandler_t", lua_fn)).
-- A LuaJIT FFI callback entered while the VM is executing a compiled trace
-- aborts the process: lj_ccallback_enter() sees g->jit_base set, pushes
-- LJ_ERR_FFI_BADCBACK and calls the panic handler, which prints
--   PANIC: unprotected error in call to Lua API (bad callback)
-- and exit(1)s -- no pcall can catch it, because the panic happens before
-- the callback body runs.  A busy node is almost always inside a trace, so
-- SIGTERM (stop_mainnet, systemctl stop) aborted it without a flush: 9
-- mainnet aborts 2026-09-26..10-04, each at an operator stop.  A signal
-- delivered to a non-main thread (RocksDB, coin prefetch, script workers)
-- would also have entered the main lua_State from a foreign thread.
--
-- Instead the shutdown signals are BLOCKED and collected synchronously:
--   * block_shutdown_signals() blocks SIGHUP/SIGINT/SIGTERM in the calling
--     thread.  main() calls it before any thread exists, so every thread
--     created later (RocksDB background pool, coin_prefetch, parallel_verify
--     workers) inherits the block and the kernel keeps the signal PENDING
--     on the process instead of delivering it anywhere.
--   * poll_signals() drains pending signals with sigtimedwait(zero timeout)
--     -- a plain syscall from Lua context, no callback, no signal context --
--     and runs the Lua callbacks.  Same observable semantics as before
--     (one main-loop tick of latency), the same shape as Core, whose
--     handlers only set a flag the main thread polls.
-- Signals that arrive before the main loop polls stay pending until then
-- (Core likewise finishes the current init step before honouring shutdown).
local _sigset_ok = pcall(ffi.cdef, [[
  typedef struct { unsigned long val[16]; } lb_sigset_t;
  struct lb_sig_timespec { long tv_sec; long tv_nsec; };
]])
local function _decl(decl) pcall(ffi.cdef, decl) end
_decl("int sigemptyset(lb_sigset_t *set);")
_decl("int sigaddset(lb_sigset_t *set, int signum);")
_decl("int sigismember(const lb_sigset_t *set, int signum);")
_decl("int pthread_sigmask(int how, const lb_sigset_t *set, lb_sigset_t *old);")
_decl("int sigtimedwait(const lb_sigset_t *set, void *info, const struct lb_sig_timespec *timeout);")

local SIG_BLOCK   = 0   -- Linux
local SIG_UNBLOCK = 1

local _signal_callbacks = {}
local _blocked = {}          -- signum -> true once blocked in this thread
local _pending = {}          -- kernel-delivered, drained, not yet dispatched
local _raised = {}           -- In-process raises (M.raise_signal), pending.
local _wait_set = nil        -- lb_sigset_t of every blocked signal
local _zero_ts = nil

-- Set when SIGTERM/SIGINT is dispatched. Long RPC walks (gettxoutsetinfo)
-- poll this and abort; Core's RpcInterruptionPoint throws once InterruptRPC
-- has cleared g_rpc_running. Stays set for the rest of the process.
M.shutting_down = false

local function _thread_count()
  local n = 0
  local ok = pcall(function()
    local f = io.open("/proc/self/status", "r")
    if not f then return end
    local s = f:read("*a")
    f:close()
    n = tonumber(s:match("\nThreads:%s*(%d+)")) or 0
  end)
  return ok and n or 0
end

local function _rebuild_wait_set()
  local set = ffi.new("lb_sigset_t")
  ffi.C.sigemptyset(set)
  for signum, _ in pairs(_blocked) do ffi.C.sigaddset(set, signum) end
  _wait_set = set
  _zero_ts = _zero_ts or ffi.new("struct lb_sig_timespec", 0, 0)
end

--- Block `signums` in the calling thread so they are collected by
--- poll_signals() instead of being delivered.  Returns true on success.
--- Threads created AFTER this call inherit the block; call it before any
--- thread exists (main() does, ahead of the script-worker pool and storage).
-- @param signums table|nil: defaults to {SIGHUP, SIGINT, SIGTERM}
-- @return boolean ok, string|nil warning
function M.block_shutdown_signals(signums)
  if not _sigset_ok then return false, "sigset cdef unavailable" end
  signums = signums or { M.SIGHUP, M.SIGINT, M.SIGTERM }
  local set = ffi.new("lb_sigset_t")
  ffi.C.sigemptyset(set)
  local fresh = false
  for _, signum in ipairs(signums) do
    ffi.C.sigaddset(set, signum)
    if not _blocked[signum] then fresh = true end
  end
  if not fresh then return true end
  if ffi.C.pthread_sigmask(SIG_BLOCK, set, nil) ~= 0 then
    return false, "pthread_sigmask(SIG_BLOCK) failed"
  end
  for _, signum in ipairs(signums) do _blocked[signum] = true end
  _rebuild_wait_set()
  local threads = _thread_count()
  if threads > 1 then
    -- Threads that already exist keep the signal unblocked: a signal the
    -- kernel routes to one of them takes the default action (terminate).
    return true, string.format(
      "signals blocked with %d threads already running; a signal routed to "
      .. "one of them terminates the process without a flush", threads)
  end
  return true
end

-- Move every kernel-pending blocked signal into _pending.  Never raises.
local function _drain()
  if not _wait_set then return end
  for _ = 1, 64 do
    local signum = ffi.C.sigtimedwait(_wait_set, nil, _zero_ts)
    if signum <= 0 then break end
    _pending[signum] = true
  end
end

--- Install a signal handler.
-- @param signum number: SIGHUP/SIGINT/SIGTERM
-- @param fn function: Lua callback to invoke when the signal is polled
function M.set_signal_handler(signum, fn)
  if not _blocked[signum] then
    local ok, warn = M.block_shutdown_signals({ signum })
    if not ok then
      io.stderr:write(string.format(
        "[signal] cannot collect signal %d (%s); default disposition stays\n",
        signum, tostring(warn)))
    elseif warn then
      io.stderr:write("[signal] WARNING: " .. warn .. "\n")
    end
  end
  _signal_callbacks[signum] = fn
end

--- Raise a signal in-process, through the same path a delivered signal takes.
-- Marks the signal pending exactly as a delivered one; the next
-- poll_signals() runs the SAME Lua callback an external `kill -<signum>`
-- would.  A raise that lands before set_signal_handler stays pending until a
-- callback exists.  Used by RPC `stop` (gate 5): Core's stop ->
-- StartShutdown(), the process exits via the SIGTERM path.
-- @param signum number
function M.raise_signal(signum)
  _raised[signum] = true
end

--- Drain pending signals and invoke their Lua callbacks.
-- Call this once per main-loop tick.  One sigtimedwait syscall when nothing
-- is pending.  Never raises: a throwing callback is reported and swallowed.
function M.poll_signals()
  _drain()
  for _, signum in ipairs({ M.SIGTERM, M.SIGINT, M.SIGHUP }) do
    local cb = _signal_callbacks[signum]
    -- A signal with no callback yet stays pending (blocked early in main(),
    -- delivered during startup) and is dispatched once a handler exists.
    if cb and (_pending[signum] or _raised[signum]) then
      _pending[signum] = nil
      _raised[signum] = nil
      -- Latch before the callback so a walk's interruption point observes
      -- shutdown even if the callback only flips the main loop's `running`.
      if signum == M.SIGTERM or signum == M.SIGINT then
        M.shutting_down = true
      end
      local ok, err = pcall(cb)
      if not ok then
        pcall(io.stderr.write, io.stderr, string.format(
          "signal handler for %d threw: %s\n", signum, tostring(err)))
      end
    end
  end
end

--- True when shutdown has been requested.
-- If SIGTERM/SIGINT is pending but not yet dispatched, dispatch it first
-- (the same poll the main loop does) so a walk aborted mid-slice still
-- runs the handler that clears `running`. Common path: one sigtimedwait
-- syscall, nothing pending, return false. A raised signal with no handler
-- installed stays pending (stop before set_signal_handler) and does not latch.
-- @return boolean
function M.poll_shutdown()
  if M.shutting_down then return true end
  _drain()
  local pending = (_signal_callbacks[M.SIGTERM]
                    and (_raised[M.SIGTERM] or _pending[M.SIGTERM]))
      or (_signal_callbacks[M.SIGINT]
          and (_raised[M.SIGINT] or _pending[M.SIGINT]))
  if not pending then return false end
  M.poll_signals()
  return M.shutting_down and true or false
end

--- Tear down all installed handlers: discard pending signals and unblock.
--- Used by tests so the busted runner is left with the default dispositions.
function M.reset_signal_handlers()
  _drain()
  if _wait_set and next(_blocked) then
    ffi.C.pthread_sigmask(SIG_UNBLOCK, _wait_set, nil)
  end
  _signal_callbacks = {}
  _blocked = {}
  _pending = {}
  _raised = {}
  _wait_set = nil
  M.shutting_down = false
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
