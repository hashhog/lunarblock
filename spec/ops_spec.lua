--- Tests for src/ops.lua: operational-parity helpers.
-- Covers config-file parsing, debug-category parsing, logger,
-- PID file, and signal handlers (without spawning a real daemon).

local helpers = require("spec.helpers")

describe("lunarblock.ops", function()
  local ops

  setup(function()
    ops = require("lunarblock.ops")
  end)

  --------------------------------------------------------------------------
  describe("parse_conf_file", function()
    local tmp_dir, tmp_path

    before_each(function()
      tmp_dir = helpers.tmpdir()
      tmp_path = tmp_dir .. "/lunarblock.conf"
    end)

    after_each(function()
      helpers.cleanup(tmp_dir)
    end)

    local function write_conf(content)
      local f = assert(io.open(tmp_path, "w"))
      f:write(content)
      f:close()
    end

    it("returns nil + error on missing file", function()
      local conf, err = ops.parse_conf_file("/nonexistent/path/conf", "mainnet")
      assert.is_nil(conf)
      assert.is_string(err)
    end)

    it("parses simple key=value", function()
      write_conf("rpcuser=bob\nrpcpassword=secret\nmaxpeers=42\n")
      local conf = assert(ops.parse_conf_file(tmp_path, "mainnet"))
      assert.equal("bob", conf.rpcuser)
      assert.equal("secret", conf.rpcpassword)
      assert.equal("42", conf.maxpeers)
    end)

    it("skips comments and blank lines", function()
      write_conf([[
# Top-level comment
; semicolon comment
rpcuser=alice

# blank line above + comment with leading whitespace
   ; another comment
maxpeers=10
]])
      local conf = assert(ops.parse_conf_file(tmp_path, "mainnet"))
      assert.equal("alice", conf.rpcuser)
      assert.equal("10", conf.maxpeers)
    end)

    it("strips inline comments after #", function()
      write_conf("rpcuser=bob # this is bob's account\n")
      local conf = assert(ops.parse_conf_file(tmp_path, "mainnet"))
      assert.equal("bob", conf.rpcuser)
    end)

    it("respects [main] section for mainnet", function()
      write_conf([[
rpcuser=global

[main]
maxpeers=100

[test]
maxpeers=200
]])
      local conf = assert(ops.parse_conf_file(tmp_path, "mainnet"))
      assert.equal("global", conf.rpcuser)
      assert.equal("100", conf.maxpeers)
    end)

    it("respects [test] section for testnet", function()
      write_conf([[
[main]
maxpeers=100

[test]
maxpeers=200
]])
      local conf = assert(ops.parse_conf_file(tmp_path, "testnet"))
      assert.equal("200", conf.maxpeers)
    end)

    it("respects [regtest] section for regtest", function()
      write_conf([[
[regtest]
maxpeers=8
]])
      local conf = assert(ops.parse_conf_file(tmp_path, "regtest"))
      assert.equal("8", conf.maxpeers)
    end)

    it("ignores keys from non-matching sections", function()
      write_conf([[
[test]
maxpeers=200
]])
      local conf = assert(ops.parse_conf_file(tmp_path, "mainnet"))
      assert.is_nil(conf.maxpeers)
    end)
  end)

  --------------------------------------------------------------------------
  describe("apply_conf_to_args", function()
    it("only fills in still-default args, never overrides CLI", function()
      local defaults = { rpcuser = "lunarblock", maxpeers = 125, daemon = false }
      local args     = { rpcuser = "cli_override", maxpeers = 125, daemon = false }
      ops.apply_conf_to_args(args, defaults, {
        rpcuser = "from_conf",  -- Would override the CLI value.  Should NOT.
        maxpeers = "50",        -- Currently default, should be applied.
        daemon = "1",           -- Currently default, should be applied (bool).
      })
      assert.equal("cli_override", args.rpcuser)  -- CLI wins.
      assert.equal(50, args.maxpeers)
      assert.is_true(args.daemon)
    end)

    it("coerces bool keywords correctly", function()
      local defaults = { daemon = false, rest = false, printtoconsole = false }
      local args = { daemon = false, rest = false, printtoconsole = false }
      ops.apply_conf_to_args(args, defaults, {
        daemon = "yes",
        rest = "0",
        printtoconsole = "true",
      })
      assert.is_true(args.daemon)
      assert.is_false(args.rest)
      assert.is_true(args.printtoconsole)
    end)

    it("ignores unknown keys silently", function()
      local defaults = { maxpeers = 125 }
      local args = { maxpeers = 125 }
      assert.has_no.errors(function()
        ops.apply_conf_to_args(args, defaults, {
          maxpeers = "10",
          totally_made_up_key = "ignore_me",
        })
      end)
      assert.equal(10, args.maxpeers)
    end)
  end)

  --------------------------------------------------------------------------
  describe("parse_debug_cats", function()
    it("returns all=true for nil", function()
      local cats = ops.parse_debug_cats(nil)
      assert.is_true(cats.all)
    end)

    it("returns all=true for empty string", function()
      local cats = ops.parse_debug_cats("")
      assert.is_true(cats.all)
    end)

    it("returns all=true for '1'", function()
      local cats = ops.parse_debug_cats("1")
      assert.is_true(cats.all)
    end)

    it("returns empty set for '0'", function()
      local cats = ops.parse_debug_cats("0")
      assert.is_nil(cats.all)
      assert.is_nil(cats.net)
    end)

    it("parses single category", function()
      local cats = ops.parse_debug_cats("net")
      assert.is_true(cats.net)
      assert.is_nil(cats.all)
      assert.is_nil(cats.mempool)
    end)

    it("parses comma-separated list", function()
      local cats = ops.parse_debug_cats("net,mempool,rpc")
      assert.is_true(cats.net)
      assert.is_true(cats.mempool)
      assert.is_true(cats.rpc)
      assert.is_nil(cats.bench)
    end)

    it("strips whitespace around categories", function()
      local cats = ops.parse_debug_cats(" net , mempool ")
      assert.is_true(cats.net)
      assert.is_true(cats.mempool)
    end)
  end)

  --------------------------------------------------------------------------
  describe("logger", function()
    local tmp_dir, log_path

    before_each(function()
      tmp_dir = helpers.tmpdir()
      log_path = tmp_dir .. "/test.log"
    end)

    after_each(function()
      helpers.cleanup(tmp_dir)
    end)

    it("opens and writes to a log file", function()
      local logger = ops.new_logger({ log_file = log_path, debug_cats = {} })
      assert.is_true(logger:open())
      logger:log("hello world")
      logger:close()
      local f = assert(io.open(log_path, "r"))
      local content = f:read("*a")
      f:close()
      assert.matches("hello world", content)
    end)

    it("suppresses category-tagged lines when category not enabled", function()
      local logger = ops.new_logger({ log_file = log_path, debug_cats = {} })
      assert(logger:open())
      logger:log("net stuff", "net")
      logger:close()
      local f = assert(io.open(log_path, "r"))
      local content = f:read("*a")
      f:close()
      assert.equal("", content)
    end)

    it("emits category-tagged lines when category is enabled", function()
      local logger = ops.new_logger({
        log_file = log_path,
        debug_cats = { net = true },
      })
      assert(logger:open())
      logger:log("net stuff", "net")
      logger:log("mempool stuff", "mempool")  -- not enabled
      logger:close()
      local f = assert(io.open(log_path, "r"))
      local content = f:read("*a")
      f:close()
      assert.matches("net stuff", content)
      assert.is_nil(content:find("mempool stuff"))
    end)

    it("emits everything when 'all' is enabled", function()
      local logger = ops.new_logger({
        log_file = log_path,
        debug_cats = { all = true },
      })
      assert(logger:open())
      logger:log("any cat", "anything")
      logger:close()
      local f = assert(io.open(log_path, "r"))
      local content = f:read("*a")
      f:close()
      assert.matches("any cat", content)
    end)

    it("reopens log file (SIGHUP simulation)", function()
      local logger = ops.new_logger({ log_file = log_path, debug_cats = {} })
      assert(logger:open())
      logger:log("before reopen")
      -- Simulate logrotate: rename the file.  reopen() should land us at
      -- the same path (a fresh file, since rotate moved the old one away).
      os.rename(log_path, log_path .. ".1")
      assert.is_true(logger:reopen())
      logger:log("after reopen")
      logger:close()
      local f = assert(io.open(log_path, "r"))
      local content = f:read("*a")
      f:close()
      assert.matches("after reopen", content)
      assert.is_nil(content:find("before reopen"))
      -- And the rotated file still has the pre-reopen content.
      local f2 = assert(io.open(log_path .. ".1", "r"))
      local content2 = f2:read("*a")
      f2:close()
      assert.matches("before reopen", content2)
    end)

    it("enabled() returns the right answer", function()
      local logger = ops.new_logger({
        log_file = log_path,
        debug_cats = { net = true },
      })
      assert.is_true(logger:enabled("net"))
      assert.is_false(logger:enabled("rpc"))
    end)
  end)

  --------------------------------------------------------------------------
  describe("PID file", function()
    local tmp_dir, pid_path

    before_each(function()
      tmp_dir = helpers.tmpdir()
      pid_path = tmp_dir .. "/lunarblock.pid"
    end)

    after_each(function()
      helpers.cleanup(tmp_dir)
    end)

    it("writes the current PID", function()
      assert.is_true(ops.write_pid_file(pid_path))
      local f = assert(io.open(pid_path, "r"))
      local pid = f:read("*l")
      f:close()
      assert.matches("^%d+$", pid)
      assert.is_true(tonumber(pid) > 0)
    end)

    it("removes the PID file", function()
      assert.is_true(ops.write_pid_file(pid_path))
      ops.remove_pid_file(pid_path)
      local f = io.open(pid_path, "r")
      assert.is_nil(f)
    end)

    it("remove_pid_file is idempotent on missing file", function()
      assert.has_no.errors(function()
        ops.remove_pid_file(pid_path .. ".nonexistent")
      end)
    end)

    it("returns nil + error on unwritable path", function()
      local ok, err = ops.write_pid_file("/nonexistent/dir/pid")
      assert.is_nil(ok)
      assert.is_string(err)
    end)
  end)

  --------------------------------------------------------------------------
  describe("signals", function()
    -- We exercise install + poll without ever firing a real signal — the
    -- runtime delivery mechanism is already covered by libc and the kernel.
    -- Here we test the registration table and poll_signals dispatch.
    after_each(function()
      ops.reset_signal_handlers()
    end)

    it("registers a handler without throwing", function()
      assert.has_no.errors(function()
        ops.set_signal_handler(ops.SIGHUP, function() end)
      end)
    end)

    it("poll_signals is a no-op when no signal pending", function()
      local fired = false
      ops.set_signal_handler(ops.SIGHUP, function() fired = true end)
      ops.poll_signals()
      assert.is_false(fired)
    end)

    it("exposes Linux x86_64 signal numbers", function()
      assert.equal(1, ops.SIGHUP)
      assert.equal(2, ops.SIGINT)
      assert.equal(15, ops.SIGTERM)
    end)
  end)

  --------------------------------------------------------------------------
  describe("ready signal", function()
    it("returns false on negative FD", function()
      assert.is_false(ops.signal_ready(-1))
    end)

    it("returns false on nil FD", function()
      assert.is_false(ops.signal_ready(nil))
    end)

    -- We can't exercise the success path safely here without spinning up a
    -- pipe + reader.  ffi.C.write to a closed FD would return -1 which we
    -- already cover via the negative-FD test.
  end)

  --------------------------------------------------------------------------
  describe("LOG_CATEGORIES", function()
    it("is a non-empty list of strings", function()
      assert.is_table(ops.LOG_CATEGORIES)
      assert.is_true(#ops.LOG_CATEGORIES > 0)
      for _, c in ipairs(ops.LOG_CATEGORIES) do
        assert.is_string(c)
      end
    end)
  end)
end)
