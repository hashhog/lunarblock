-- Regression specs for two mainnet faults (QUEUES lunarblock item 0, 2026-10-04):
--
-- 1. "PANIC: unprotected error in call to Lua API (bad callback)" on every
--    busy SIGTERM.  The signal handler was an FFI callback; LuaJIT aborts in
--    lj_ccallback_enter when a callback is entered while a compiled trace
--    runs.  The fix installs NO handler: the shutdown signals are blocked and
--    collected with sigtimedwait() from poll_signals().
-- 2. Every addrv2 getaddr reply raised "serialize.lua:19: bad argument #1 to
--    'floor' (number expected, got cdata)": addrman services read off the wire
--    are uint64_t cdata, and write_varint/write_u16le only took Lua numbers.
--
-- NEGATIVE CONTROL: on fcf5dc5 the "async SIGTERM inside a compiled trace"
-- case aborts the whole busted process with the PANIC (exit 1), the /proc
-- disposition case fails (SigCgt has the bit), and the cdata/getaddr cases
-- raise the 'floor'/'char' errors.

local ffi = require("ffi")
local ops = require("lunarblock.ops")
local serialize = require("lunarblock.serialize")
local p2p = require("lunarblock.p2p")
local peerman = require("lunarblock.peerman")

pcall(ffi.cdef, "int getpid(void);")
pcall(ffi.cdef, "long syscall(long number, ...);")
local SYS_tgkill = 234   -- x86_64

-- Bit `signum` of a hex signal mask line in /proc/self/status (SigBlk/SigCgt).
local function proc_sig_bit(field, signum)
  local f = assert(io.open("/proc/self/status", "r"))
  local s = f:read("*a")
  f:close()
  local hex = assert(s:match("\n" .. field .. ":%s*(%x+)"), field)
  local mask = tonumber(hex:sub(-8), 16)   -- low 32 bits hold signals 1..32
  return math.floor(mask / 2 ^ (signum - 1)) % 2 == 1
end

-- Send `signum` to THIS process's main thread (tid == pid) from this thread.
-- Thread-directed, so a RocksDB / worker thread that a previous spec left
-- running in the busted process can never receive it.
local function tgkill_self(signum)
  local pid = ffi.C.getpid()
  return ffi.C.syscall(SYS_tgkill, ffi.cast("long", pid), ffi.cast("long", pid),
                       ffi.cast("long", signum))
end

describe("signal handling without FFI callbacks", function()
  before_each(function() ops.reset_signal_handlers() end)
  after_each(function() ops.reset_signal_handlers() end)

  it("installs no kernel handler: SIGTERM is blocked, not caught", function()
    ops.set_signal_handler(ops.SIGTERM, function() end)
    assert.is_false(proc_sig_bit("SigCgt", ops.SIGTERM),
      "a SIGTERM handler is installed (FFI callback in signal context)")
    assert.is_true(proc_sig_bit("SigBlk", ops.SIGTERM),
      "SIGTERM must be blocked so it stays pending for poll_signals")
  end)

  it("reset_signal_handlers unblocks again", function()
    ops.set_signal_handler(ops.SIGTERM, function() end)
    ops.reset_signal_handlers()
    assert.is_false(proc_sig_bit("SigBlk", ops.SIGTERM))
  end)

  it("a delivered SIGTERM runs the Lua callback from poll_signals", function()
    local fired = 0
    ops.set_signal_handler(ops.SIGTERM, function() fired = fired + 1 end)
    assert.equal(0, tonumber(tgkill_self(ops.SIGTERM)))
    assert.equal(0, fired)            -- nothing runs in signal context
    ops.poll_signals()
    assert.equal(1, fired)
    assert.is_true(ops.shutting_down)
    ops.poll_signals()
    assert.equal(1, fired)            -- consumed exactly once
  end)

  it("poll_shutdown collects a pending SIGINT and latches", function()
    local fired = false
    ops.set_signal_handler(ops.SIGINT, function() fired = true end)
    assert.is_false(ops.poll_shutdown())
    tgkill_self(ops.SIGINT)
    assert.is_true(ops.poll_shutdown())
    assert.is_true(fired)
  end)

  it("SIGHUP is dispatched but does not latch shutdown", function()
    local hups = 0
    ops.set_signal_handler(ops.SIGHUP, function() hups = hups + 1 end)
    tgkill_self(ops.SIGHUP)
    assert.is_false(ops.poll_shutdown())
    ops.poll_signals()
    assert.equal(1, hups)
    assert.is_false(ops.shutting_down)
  end)

  it("a signal blocked before its handler exists is dispatched once it does", function()
    assert.is_true((ops.block_shutdown_signals()))
    tgkill_self(ops.SIGTERM)
    ops.poll_signals()                -- no callback yet: stays pending
    assert.is_false(ops.shutting_down)
    local fired = false
    ops.set_signal_handler(ops.SIGTERM, function() fired = true end)
    ops.poll_signals()
    assert.is_true(fired)
    assert.is_true(ops.shutting_down)
  end)

  it("a throwing callback never escapes poll_signals", function()
    ops.set_signal_handler(ops.SIGTERM, function() error("boom") end)
    tgkill_self(ops.SIGTERM)
    assert.has_no.errors(function() ops.poll_signals() end)
    assert.is_true(ops.shutting_down)
  end)

  it("an async SIGTERM landing inside a compiled trace is collected, not a PANIC", function()
    -- A helper process sends a thread-directed SIGTERM to our main thread
    -- 0.3 s from now while this loop is running as a JIT trace.  On the old
    -- FFI-callback handler this aborted the whole busted process with
    -- "PANIC: unprotected error in call to Lua API (bad callback)".
    local fired = false
    ops.set_signal_handler(ops.SIGTERM, function() fired = true end)
    local pid = ffi.C.getpid()
    local cmd = string.format(
      "python3 -c 'import ctypes,time; time.sleep(0.3); "
      .. "ctypes.CDLL(None).syscall(%d, %d, %d, %d)' >/dev/null 2>&1 &",
      SYS_tgkill, pid, pid, ops.SIGTERM)
    os.execute(cmd)
    local socket = require("socket")
    local deadline = socket.gettime() + 10
    local x = 0
    while not fired and socket.gettime() < deadline do
      for i = 1, 2000000 do x = (x + i * 3) % 1000003 end   -- hot trace
      ops.poll_signals()
    end
    assert.is_true(fired, "SIGTERM was not collected within 10 s (x=" .. x .. ")")
  end)
end)

describe("serialize writers accept uint64_t cdata integers", function()
  local u64 = function(v) return ffi.new("uint64_t", v) end

  local function enc(fn, v)
    local w = serialize.buffer_writer()
    w[fn](v)
    return w.result()
  end

  it("narrow writers encode a cdata value like the equal Lua number", function()
    for _, case in ipairs({
      { "write_u8", 9 }, { "write_u16le", 0x409 }, { "write_u16be", 8333 },
      { "write_u32le", 0x20000409 }, { "write_i32le", 70016 },
    }) do
      local fn, v = case[1], case[2]
      assert.equal(enc(fn, v), enc(fn, u64(v)), fn)
    end
  end)

  it("write_varint handles every CompactSize width for cdata", function()
    for _, v in ipairs({ 0, 9, 0xFC, 0xFD, 0x409, 0xFFFF, 0x10000, 0x20000409, 0xFFFFFFFF }) do
      assert.equal(enc("write_varint", v), enc("write_varint", u64(v)), tostring(v))
    end
    -- Above 2^32: 0xFF + 8-byte LE, exact past 2^53.
    local big = ffi.new("uint64_t", 0x0123456789ABCDEFULL)
    assert.equal("\255\239\205\171\137\103\69\35\1", enc("write_varint", big))
  end)

  it("write_varint round-trips a services value read back as cdata", function()
    local w = serialize.buffer_writer()
    w.write_varint(0x409)
    local back = serialize.buffer_reader(w.result()).read_varint(false)
    assert.equal(w.result(), enc("write_varint", u64(back)))
  end)

  it("write_i64le encodes int64 cdata including negatives", function()
    assert.equal(enc("write_i64le", -1), enc("write_i64le", ffi.new("int64_t", -1)))
    assert.equal(enc("write_i64le", 5000), enc("write_i64le", ffi.new("int64_t", 5000)))
    assert.equal(string.rep("\255", 8), enc("write_i64le", ffi.new("int64_t", -1)))
  end)
end)

describe("getaddr reply with cdata services in addrman", function()
  local function make_pm()
    local tmpdir = os.tmpname()
    os.remove(tmpdir)
    os.execute("mkdir -p " .. tmpdir)
    local net = { name = "regtest", magic_bytes = "\xfa\xbf\xb5\xda", port = 18444,
                  default_port = 18444, dns_seeds = {}, pow_target_spacing = 600 }
    return peerman.new(net, nil, { data_dir = tmpdir }), tmpdir
  end

  local function fill(pm)
    -- Services exactly as the wire readers produce them (uint64_t cdata),
    -- covering the u8 (9), u16 (0x409) and u32 (0x20000409) CompactSize forms.
    local svc = { 9, 0x409, 0x20000409, 0x409, 0x409, 0x409, 0x409, 0x409, 0x409, 0x409 }
    for i, s in ipairs(svc) do
      local ip = "23.10." .. i .. ".7"
      pm.known_addresses[ip .. ":8333"] = {
        ip = ip, port = 8333, services = ffi.new("uint64_t", s),
        timestamp = os.time(), attempts = 0, last_try = 0,
      }
    end
  end

  for _, v2 in ipairs({ true, false }) do
    it((v2 and "addrv2" or "addr") .. " peer gets a reply; a getaddr payload is ignored", function()
      local pm, d = make_pm()
      fill(pm)
      local sent = {}
      local peer = { inbound = true, send_addrv2 = v2,
                     send_message = function(_, cmd, payload) sent[#sent + 1] = { cmd, payload } end }
      local handler = pm.message_handlers["getaddr"]
      assert.is_function(handler)
      assert.has_no.errors(function() handler(peer, "\0\1junk-payload") end)
      assert.equal(1, #sent)
      assert.equal(v2 and "addrv2" or "addr", sent[1][1])
      local list = v2 and p2p.deserialize_addrv2(sent[1][2]) or p2p.deserialize_addr(sent[1][2])
      assert.equal(2, #list)          -- floor(23% of 10)
      for _, a in ipairs(list) do
        local s = tonumber(a.services)
        assert.is_true(s == 9 or s == 0x409 or s == 0x20000409, tostring(s))
        assert.equal(8333, a.port)
      end
      os.execute("rm -rf " .. d)
    end)
  end
end)
