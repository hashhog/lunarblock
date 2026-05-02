#!/usr/bin/env luajit
-- LunarBlock - Bitcoin full node in Lua
-- CLI & Application Entry Point

io.stdout:setvbuf("line")
io.stderr:setvbuf("line")

local VERSION = "0.1.0"

--------------------------------------------------------------------------------
-- Minimal argument parser (no external dependency)
--------------------------------------------------------------------------------

local function default_args()
  return {
    datadir = os.getenv("HOME") .. "/.lunarblock",
    network = "mainnet",
    rpcport = nil,  -- will default from network config
    rpcuser = "lunarblock",
    rpcpassword = "",
    port = nil,  -- will default from network config
    maxpeers = 125,
    dbcache = 450,
    connect = nil,
    testnet = false,
    regtest = false,
    printtoconsole = false,
    nowalletcreate = false,
    reindex = false,
    reindex_chainstate = false,
    daemon = false,
    jitprofile = false,
    jitverbose = false,
    prune = 0,  -- 0=disabled, 1=manual only, >=550=target MB
    rest = false,  -- Enable REST API
    restport = nil,  -- REST server port (default: 8080)
    -- ZMQ notification endpoints
    zmqpubhashblock = nil,
    zmqpubhashtx = nil,
    zmqpubrawblock = nil,
    zmqpubrawtx = nil,
    zmqpubsequence = nil,
    zmqpubhwm = 1000,  -- ZMQ high water mark
    nov2transport = false,  -- Disable BIP324 v2 transport
    peerbloomfilters = false, -- BIP-35 / NODE_BLOOM: matches Core DEFAULT_PEERBLOOMFILTERS=false (net_processing.h)
    import_blocks = nil,   -- Path to framed block file for import (or "-" for stdin)
    import_utxo = nil,     -- Path to Core-format UTXO snapshot file for AssumeUTXO import
    -- Operational-parity flags (mirrors Bitcoin Core init.cpp + util/system.cpp)
    pid = nil,             -- Path to PID file (default: <datadir>/lunarblock.pid)
    debug = nil,           -- Comma-separated debug categories (e.g. "net,mempool")
    log = nil,             -- Path to log file (default: <datadir>/debug.log)
    conf = nil,            -- Path to bitcoin.conf-style config file
    ready_fd = nil,        -- File descriptor for ready-signal (systemd-style)
  }
end

local function parse_args(argv)
  -- Snapshot defaults so conf-file merge can detect "still at default" cleanly.
  local args = default_args()
  local defaults = default_args()

  local i = 1
  while i <= #argv do
    local arg = argv[i]
    if arg == "--help" or arg == "-h" then
      print("Usage: lunarblock [OPTIONS]")
      print("")
      print("A Bitcoin full node in Lua")
      print("")
      print("Options:")
      print("  -d, --datadir DIR       Data directory (default: ~/.lunarblock)")
      print("  -n, --network NET       Network: mainnet, testnet, regtest (default: mainnet)")
      print("      --rpcport PORT      RPC server port")
      print("      --rpcuser USER      RPC username (default: lunarblock)")
      print("      --rpcpassword PW    RPC password")
      print("      --port PORT         P2P listen port")
      print("      --maxpeers N        Maximum peer connections (default: 125)")
      print("      --dbcache MB        Database cache size in MB (default: 450)")
      print("      --connect IP:PORT   Connect to specific peer")
      print("      --testnet           Use testnet")
      print("      --regtest           Use regtest")
      print("      --printtoconsole    Print log to console")
      print("      --nowalletcreate    Do not create wallet on first run")
      print("      --reindex           Rebuild UTXO set from blocks")
      print("      --reindex-chainstate Rebuild chainstate (UTXO set) from on-disk blocks")
      print("      --daemon            Run as daemon")
      print("      --jitprofile        Enable JIT profiling output")
      print("      --jitverbose        Enable verbose JIT compilation logging")
      print("      --prune N           Prune mode: 0=disabled, 1=manual, >=550=target MB")
      print("      --metricsport PORT  Prometheus metrics port (default: 9332, 0 = disabled)")
      print("      --rest              Enable REST API (no auth, read-only)")
      print("      --restport PORT     REST server port (default: 8080)")
      print("      --zmqpubhashblock ENDPOINT  Publish hashblock notifications")
      print("      --zmqpubhashtx ENDPOINT     Publish hashtx notifications")
      print("      --zmqpubrawblock ENDPOINT   Publish rawblock notifications")
      print("      --zmqpubrawtx ENDPOINT      Publish rawtx notifications")
      print("      --zmqpubsequence ENDPOINT   Publish sequence notifications")
      print("      --zmqpubhwm N               ZMQ high water mark (default: 1000)")
      print("      --nov2transport             Disable BIP324 v2 encrypted transport")
      print("      --peerbloomfilters BOOL     Advertise NODE_BLOOM and service BIP-35 mempool requests (default: 0)")
      print("      --import-blocks FILE        Import blocks from framed file (or - for stdin)")
      print("      --import-utxo FILE          Import UTXO snapshot from Core dumptxoutset file (AssumeUTXO)")
      print("      --pid PATH                  Path to PID file (default: <datadir>/lunarblock.pid)")
      print("      --debug CATS                Enable debug categories (comma-separated; e.g. net,mempool,1=all)")
      print("      --log PATH                  Path to log file (default: <datadir>/debug.log)")
      print("      --conf PATH                 Path to bitcoin.conf-style config file")
      print("      --ready-fd N                Write READY token to this FD when listeners are up")
      print("      --version           Print version and exit")
      print("  -h, --help              Show this help message")
      os.exit(0)
    elseif arg == "--version" then
      print("LunarBlock v" .. VERSION)
      print("LuaJIT " .. (jit and jit.version or "unknown"))
      os.exit(0)
    elseif arg == "-d" or arg == "--datadir" then
      i = i + 1
      args.datadir = argv[i]
    elseif arg == "-n" or arg == "--network" then
      i = i + 1
      args.network = argv[i]
    elseif arg == "--rpcport" then
      i = i + 1
      args.rpcport = tonumber(argv[i])
    elseif arg == "--rpcuser" then
      i = i + 1
      args.rpcuser = argv[i]
    elseif arg == "--rpcpassword" then
      i = i + 1
      args.rpcpassword = argv[i]
    elseif arg == "--port" then
      i = i + 1
      args.port = tonumber(argv[i])
    elseif arg == "--maxpeers" then
      i = i + 1
      args.maxpeers = tonumber(argv[i])
    elseif arg == "--dbcache" then
      i = i + 1
      args.dbcache = tonumber(argv[i])
    elseif arg == "--connect" then
      i = i + 1
      args.connect = argv[i]
    elseif arg == "--testnet" then
      args.testnet = true
    elseif arg == "--regtest" then
      args.regtest = true
    elseif arg == "--printtoconsole" then
      args.printtoconsole = true
    elseif arg == "--nowalletcreate" then
      args.nowalletcreate = true
    elseif arg == "--reindex" then
      args.reindex = true
    elseif arg == "--reindex-chainstate" then
      args.reindex_chainstate = true
    elseif arg == "--daemon" then
      args.daemon = true
    elseif arg == "--jitprofile" then
      args.jitprofile = true
    elseif arg == "--jitverbose" then
      args.jitverbose = true
    elseif arg == "--nov2transport" then
      args.nov2transport = true
    elseif arg == "--peerbloomfilters" then
      i = i + 1
      local v = argv[i]
      args.peerbloomfilters = (v == "1" or v == "true" or v == "yes" or v == "on")
    elseif arg == "--import-blocks" then
      i = i + 1
      args.import_blocks = argv[i]
    elseif arg == "--import-utxo" then
      i = i + 1
      args.import_utxo = argv[i]
    elseif arg == "--prune" then
      i = i + 1
      local prune_val = tonumber(argv[i])
      if not prune_val then
        io.stderr:write("--prune requires a numeric value\n")
        os.exit(1)
      end
      if prune_val < 0 then
        io.stderr:write("--prune cannot be negative\n")
        os.exit(1)
      end
      if prune_val > 1 and prune_val < 550 then
        io.stderr:write("--prune target must be 0, 1, or at least 550 MB\n")
        os.exit(1)
      end
      args.prune = prune_val
    elseif arg == "--metricsport" then
      i = i + 1
      args.metricsport = tonumber(argv[i])
    elseif arg == "--rest" then
      args.rest = true
    elseif arg == "--restport" then
      i = i + 1
      args.restport = tonumber(argv[i])
    elseif arg == "--zmqpubhashblock" then
      i = i + 1
      args.zmqpubhashblock = argv[i]
    elseif arg == "--zmqpubhashtx" then
      i = i + 1
      args.zmqpubhashtx = argv[i]
    elseif arg == "--zmqpubrawblock" then
      i = i + 1
      args.zmqpubrawblock = argv[i]
    elseif arg == "--zmqpubrawtx" then
      i = i + 1
      args.zmqpubrawtx = argv[i]
    elseif arg == "--zmqpubsequence" then
      i = i + 1
      args.zmqpubsequence = argv[i]
    elseif arg == "--zmqpubhwm" then
      i = i + 1
      args.zmqpubhwm = tonumber(argv[i])
    elseif arg == "--pid" or arg:match("^%-%-pid=") then
      -- Accept both "--pid PATH" and "--pid=PATH" (Bitcoin Core both forms).
      local v = arg:match("^%-%-pid=(.*)$")
      if v then args.pid = v else i = i + 1; args.pid = argv[i] end
    elseif arg == "--debug" or arg:match("^%-%-debug=") then
      local v = arg:match("^%-%-debug=(.*)$")
      if v then args.debug = v else i = i + 1; args.debug = argv[i] end
    elseif arg == "--log" or arg:match("^%-%-log=") then
      local v = arg:match("^%-%-log=(.*)$")
      if v then args.log = v else i = i + 1; args.log = argv[i] end
    elseif arg == "--conf" or arg:match("^%-%-conf=") then
      local v = arg:match("^%-%-conf=(.*)$")
      if v then args.conf = v else i = i + 1; args.conf = argv[i] end
    elseif arg == "--ready-fd" or arg:match("^%-%-ready%-fd=") then
      local v = arg:match("^%-%-ready%-fd=(.*)$")
      if v then args.ready_fd = tonumber(v) else i = i + 1; args.ready_fd = tonumber(argv[i]) end
    else
      io.stderr:write("Unknown option: " .. arg .. "\n")
      os.exit(1)
    end
    i = i + 1
  end

  -- Conf-file merge.  CLI flags win; conf-file fills in remaining defaults.
  -- The network used for [section] gating is whichever the CLI selected
  -- (testnet/regtest flags applied below) — but since those flags also
  -- override `network` directly, we approximate by computing the effective
  -- network here.
  if args.conf then
    local effective_network = args.network
    if args.testnet then effective_network = "testnet" end
    if args.regtest then effective_network = "regtest" end
    local ok_ops, ops = pcall(require, "lunarblock.ops")
    if ok_ops then
      local conf, err = ops.parse_conf_file(args.conf, effective_network)
      if not conf then
        io.stderr:write(string.format(
          "Failed to read --conf=%s: %s\n", args.conf, tostring(err)))
        os.exit(1)
      end
      ops.apply_conf_to_args(args, defaults, conf)
    end
  end

  return args
end

--------------------------------------------------------------------------------
-- Block Import Mode
--------------------------------------------------------------------------------

local function run_import_blocks(args)
  local ffi = require("ffi")
  local consensus_mod = require("lunarblock.consensus")
  local storage_mod = require("lunarblock.storage")
  local utxo_mod = require("lunarblock.utxo")
  local validation = require("lunarblock.validation")
  local serialize = require("lunarblock.serialize")
  local types = require("lunarblock.types")

  -- Get network configuration
  local network = consensus_mod.networks[args.network]
  if not network then
    io.stderr:write("Unknown network: " .. args.network .. "\n")
    os.exit(1)
  end

  -- Create data directory
  local datadir = args.datadir
  if args.network ~= "mainnet" then
    datadir = datadir .. "/" .. args.network
  end
  os.execute("mkdir -p " .. datadir)

  print(string.format("import-blocks: network=%s datadir=%s source=%s",
    args.network, datadir, args.import_blocks))

  -- Initialize database
  local db = storage_mod.open(datadir .. "/chainstate", args.dbcache)

  -- Initialize chain state
  local chain_state = utxo_mod.new_chain_state(db, network)
  chain_state:init()
  local tip_height = chain_state.tip_height or 0
  print(string.format("Chain tip at height %d, starting import", tip_height))

  -- Open input file
  local input
  if args.import_blocks == "-" then
    input = io.stdin
  else
    local err
    input, err = io.open(args.import_blocks, "rb")
    if not input then
      io.stderr:write("Cannot open file: " .. tostring(err) .. "\n")
      os.exit(1)
    end
  end

  -- Use C fread for efficient binary I/O via FFI
  pcall(ffi.cdef, [[
    typedef struct { void *_opaque; } FILE;
    size_t fread(void *ptr, size_t size, size_t count, FILE *stream);
    FILE *fdopen(int fd, const char *mode);
    int fileno(FILE *stream);
    int fclose(FILE *stream);
    FILE *fopen(const char *path, const char *mode);
  ]])

  local c_file
  if args.import_blocks == "-" then
    -- Use stdin file descriptor
    c_file = ffi.C.fdopen(0, "rb")
  else
    c_file = ffi.C.fopen(args.import_blocks, "rb")
  end
  if c_file == nil then
    io.stderr:write("Cannot open file via FFI\n")
    os.exit(1)
  end

  local frame_buf = ffi.new("uint8_t[8]")
  local imported = 0
  local skipped = 0
  local start_time = os.clock()
  local last_log_time = start_time
  local last_log_count = 0

  while true do
    -- Read frame header: [4 bytes height LE] [4 bytes size LE]
    local n = ffi.C.fread(frame_buf, 1, 8, c_file)
    if n == 0 then break end
    if n ~= 8 then
      io.stderr:write(string.format("Incomplete frame header: got %d bytes\n", tonumber(n)))
      break
    end

    local frame_height = frame_buf[0] + frame_buf[1] * 256 +
                         frame_buf[2] * 65536 + frame_buf[3] * 16777216
    local frame_size = frame_buf[4] + frame_buf[5] * 256 +
                       frame_buf[6] * 65536 + frame_buf[7] * 16777216

    if frame_size == 0 or frame_size > 4 * 1024 * 1024 then
      io.stderr:write(string.format("Invalid frame size %d at height %d\n", frame_size, frame_height))
      break
    end

    -- Read block data
    local block_buf = ffi.new("uint8_t[?]", frame_size)
    n = ffi.C.fread(block_buf, 1, frame_size, c_file)
    if tonumber(n) ~= frame_size then
      io.stderr:write(string.format("Incomplete block data at height %d: got %d of %d\n",
        frame_height, tonumber(n), frame_size))
      break
    end

    -- Skip blocks we already have
    if frame_height <= tip_height then
      skipped = skipped + 1
    else
      -- Convert to Lua string for deserialization
      local block_data = ffi.string(block_buf, frame_size)

      -- Deserialize the block
      local ok, block = pcall(serialize.deserialize_block, block_data)
      if not ok then
        io.stderr:write(string.format("Error deserializing block at height %d: %s\n",
          frame_height, tostring(block)))
        os.exit(1)
      end

      -- Compute block hash
      local block_hash = validation.compute_block_hash(block.header)

      -- Connect the block to chain state (skip script validation for speed during import)
      local skip_scripts = true
      local connect_ok, connect_err = chain_state:connect_block(
        block, frame_height, block_hash, nil, nil, skip_scripts)
      if not connect_ok then
        io.stderr:write(string.format("Error connecting block at height %d: %s\n",
          frame_height, tostring(connect_err)))
        os.exit(1)
      end

      imported = imported + 1

      -- Log progress periodically
      local now = os.clock()
      if now - last_log_time >= 10 or imported % 10000 == 0 then
        local elapsed = now - start_time
        local rate = (imported - last_log_count) / math.max(now - last_log_time, 0.001)
        print(string.format("import-blocks: height=%d imported=%d skipped=%d rate=%.1f blk/s",
          frame_height, imported, skipped, rate))
        last_log_time = now
        last_log_count = imported
      end
    end
  end

  -- Cleanup
  if args.import_blocks ~= "-" then
    ffi.C.fclose(c_file)
  end

  -- Close database (flushes on close)
  db.close()

  local elapsed = os.clock() - start_time
  local rate = imported / math.max(elapsed, 0.001)
  print(string.format("import-blocks complete: imported=%d skipped=%d elapsed=%.1fs rate=%.1f blk/s",
    imported, skipped, elapsed, rate))
end

--------------------------------------------------------------------------------
-- UTXO Snapshot Import Mode (AssumeUTXO)
--
-- Replaces the legacy HDOG-FFI fast path with a pure-Lua loader that
-- accepts Bitcoin Core's dumptxoutset wire format.  See utxo.lua
-- ChainState:load_snapshot for the parser.
--------------------------------------------------------------------------------

local function run_import_utxo(args)
  local consensus_mod = require("lunarblock.consensus")
  local storage_mod = require("lunarblock.storage")
  local utxo_mod = require("lunarblock.utxo")
  local types = require("lunarblock.types")

  -- Determine data directory
  local datadir = args.datadir
  if args.network ~= "mainnet" then
    datadir = datadir .. "/" .. args.network
  end
  os.execute("mkdir -p " .. datadir)

  print(string.format("import-utxo: network=%s datadir=%s source=%s",
    args.network, datadir, args.import_utxo))

  local network = consensus_mod.networks[args.network]
  if not network then
    io.stderr:write("import-utxo FAILED: unknown network " .. tostring(args.network) .. "\n")
    os.exit(1)
  end

  -- import-blocks (line 292) opens the same RocksDB at `datadir/chainstate`,
  -- and so does the daemon path (line 656). Without the `/chainstate` here,
  -- import-utxo wrote into a sibling DB at `datadir/` whose chain_tip was
  -- invisible to a subsequent daemon start and the snapshot UTXOs were
  -- effectively orphaned. Recovered manually 2026-05-01 by `mv`-ing the
  -- RocksDB files into `chainstate/`; this prevents the same trap on the
  -- next operator-driven snapshot import.
  local db = storage_mod.open(datadir .. "/chainstate")
  local cs = utxo_mod.new_chain_state(db, network)
  cs:init()

  local t0 = os.time()
  local ok, err = cs:load_snapshot(args.import_utxo)
  local elapsed = os.time() - t0

  if not ok then
    db.close()
    io.stderr:write("import-utxo FAILED: " .. tostring(err) .. "\n")
    os.exit(1)
  end

  -- Resolve assumeutxo height for the loaded base block.
  local tip_hex = types.hash256_hex(cs.tip_hash)
  local au_data, au_height = consensus_mod.assumeutxo_for_blockhash(network, tip_hex)
  if au_height then
    cs.tip_height = au_height
    db.set_chain_tip(cs.tip_hash, au_height, true)
    if au_data and au_data.hash_serialized then
      print("import-utxo: blockhash matches assumeutxo height " .. au_height)
    end
  end

  -- Compute and display the resulting set hash.
  local set_hash, count = cs:compute_utxo_hash()
  local set_hash_hex = ""
  for i = 1, 32 do
    set_hash_hex = set_hash_hex .. string.format("%02x", set_hash:byte(i))
  end

  db.close()

  print(string.format(
    "import-utxo complete: utxos=%d block=%s set_hash=%s elapsed=%ds",
    count, tip_hex, set_hash_hex, elapsed))
end

--------------------------------------------------------------------------------
-- Module exports for testing
--------------------------------------------------------------------------------

local M = {}
M.VERSION = VERSION
M.parse_args = parse_args

--------------------------------------------------------------------------------
-- Main entry point
--------------------------------------------------------------------------------

local function main()
  local socket = require("socket")
  local args = parse_args(arg)

  -- Override network from flags
  if args.testnet then args.network = "testnet" end
  if args.regtest then args.network = "regtest" end

  -- Check for import-utxo mode
  if args.import_utxo then
    run_import_utxo(args)
    return
  end

  -- Check for import-blocks mode
  if args.import_blocks then
    run_import_blocks(args)
    return
  end

  -- Load modules
  local consensus_mod = require("lunarblock.consensus")
  local storage_mod = require("lunarblock.storage")
  local sync_mod = require("lunarblock.sync")
  local peerman_mod = require("lunarblock.peerman")
  local rpc_mod = require("lunarblock.rpc")
  local mempool_mod = require("lunarblock.mempool")
  local mempool_persist_mod = require("lunarblock.mempool_persist")
  local utxo_mod = require("lunarblock.utxo")
  local fee_mod = require("lunarblock.fee")
  local wallet_mod = require("lunarblock.wallet")
  local mining_mod = require("lunarblock.mining")
  local prune_mod = require("lunarblock.prune")
  local validation = require("lunarblock.validation")
  local p2p = require("lunarblock.p2p")
  local types = require("lunarblock.types")
  local serialize = require("lunarblock.serialize")

  -- Get network configuration
  local network = consensus_mod.networks[args.network]
  if not network then
    io.stderr:write("Unknown network: " .. args.network .. "\n")
    os.exit(1)
  end

  -- Apply default ports if not specified
  if not args.rpcport then args.rpcport = network.rpc_port end
  if not args.port then args.port = network.port end

  -- Create data directory
  local datadir = args.datadir
  if args.network ~= "mainnet" then
    datadir = datadir .. "/" .. args.network
  end
  os.execute("mkdir -p " .. args.datadir)
  os.execute("mkdir -p " .. datadir)

  print("LunarBlock v" .. VERSION .. " starting...")
  print("Network: " .. args.network)
  print("Data directory: " .. datadir)

  -- Operational helpers: daemon, PID file, logger, signals, ready-fd.
  -- Must run before storage open() because daemonize() closes inherited
  -- FDs (Bitcoin Core init.cpp does the same: AppInitMain calls
  -- DaemonizeIfRequested *before* OpenDataDirectory).
  local ops = require("lunarblock.ops")

  -- Default log path lives in datadir.  --log may override.
  local log_path = args.log or (datadir .. "/debug.log")
  -- Default PID path lives in datadir.  --pid may override.
  local pid_path = args.pid or (datadir .. "/lunarblock.pid")

  -- --daemon: detach via double-fork.  Stdout/stderr get redirected to the
  -- log file inside the grandchild — anything we print BEFORE this call goes
  -- to the controlling terminal.  We DO NOT daemonize during import-blocks
  -- or import-utxo (those modes already returned early).
  if args.daemon then
    print("Daemonizing...")
    local ok, err = ops.daemonize({ log_path = log_path })
    if not ok then
      io.stderr:write("daemonize failed: " .. tostring(err) .. "\n")
      os.exit(1)
    end
    -- We're now in the grandchild.  io.stdout/io.stderr point at log_path
    -- (or /dev/null if no log was configured) via dup2.  Reset line-buffer
    -- mode that we set at the top of the file.
    io.stdout:setvbuf("line")
    io.stderr:setvbuf("line")
  end

  -- PID file: write our PID for ops scripts (start/stop_mainnet.sh).
  -- Bitcoin Core writes this in init.cpp after fork() but before main loop.
  local pid_ok, pid_err = ops.write_pid_file(pid_path)
  if not pid_ok then
    io.stderr:write(string.format("Warning: failed to write PID file %s: %s\n",
      pid_path, tostring(pid_err)))
  else
    print("PID file: " .. pid_path)
  end

  -- Build logger.  --debug=<cat>[,<cat>] gates per-category emission.
  local debug_cats = ops.parse_debug_cats(args.debug)
  local logger = ops.new_logger({
    log_file = (args.printtoconsole and not args.daemon) and nil or log_path,
    debug_cats = debug_cats,
    printtoconsole = args.printtoconsole,
  })
  local logger_ok, logger_err = logger:open()
  if not logger_ok then
    io.stderr:write(string.format(
      "Warning: failed to open log file %s: %s\n", log_path, tostring(logger_err)))
  end
  -- Stash on package.loaded so other modules can access it without an arg
  -- threading change.  (Most lunarblock modules use io.stdout directly today;
  -- migrating them to the category logger is a separate cleanup.)
  package.loaded["lunarblock.logger"] = logger
  if args.debug then
    print("Debug categories: " .. args.debug)
  end

  -- SIGHUP → reopen log file (logrotate).
  -- SIGTERM/SIGINT → graceful shutdown via the `running` flag below.
  -- Signal handlers run in async context; the main loop polls them.
  -- The actual `running` flag is created down at line ~1207 ("local running")
  -- — we install handlers there so the closure can mutate it.

  -- Enable JIT profiling if requested
  if args.jitprofile then
    local ok, jit_p = pcall(require, "jit.p")
    if ok then
      jit_p.start("vl", datadir .. "/jit_profile.txt")
      print("JIT profiling enabled, output to " .. datadir .. "/jit_profile.txt")
    else
      print("Warning: JIT profiling not available")
    end
  end
  if args.jitverbose then
    local ok, jit_v = pcall(require, "jit.v")
    if ok then
      jit_v.on(datadir .. "/jit_verbose.txt")
      print("JIT verbose logging enabled, output to " .. datadir .. "/jit_verbose.txt")
    else
      print("Warning: JIT verbose logging not available")
    end
  end

  -- Initialize database
  io.stdout:write("Opening database...\n"); io.stdout:flush()
  local db = storage_mod.open(datadir .. "/chainstate", args.dbcache)
  io.stdout:write("Database opened.\n"); io.stdout:flush()

  -- Initialize chain state
  io.stdout:write("Initializing chain state...\n"); io.stdout:flush()
  local chain_state = utxo_mod.new_chain_state(db, network)
  chain_state:init()
  io.stdout:write(string.format("Chain state initialized: height=%d\n", chain_state.tip_height or -1)); io.stdout:flush()

  -- BUG-REPORT.md fix #3: post-restart consistency check + auto-rollback.
  -- Walk back from chain_tip up to 200 blocks; for each block, verify that
  -- its first ~5 non-coinbase transactions' inputs resolve to a UTXO in
  -- CF.UTXO or in the block's own undo data. If any block fails, roll back
  -- to the highest known-good height and let IBD re-apply.
  --
  -- This catches the post-EMFILE wedge class: a hard crash leaves
  -- chain_tip pointing at a block whose UTXO mutations didn't fully reach
  -- disk. Without this check, IBD continues from the inconsistent state
  -- and wedges thousands of blocks later when a tx finally references a
  -- lost UTXO (h=938344 on Apr 28). Skipped if --reindex-chainstate is
  -- requested (the reindex will rebuild from scratch anyway).
  if not args.reindex_chainstate and not args.reindex
      and chain_state.tip_height and chain_state.tip_height > 0 then
    io.stdout:write("Verifying chainstate consistency (last 200 blocks)...\n")
    io.stdout:flush()
    local rolled, final_h, details = chain_state:verify_chainstate_consistency(200, 5)
    if details.found_inconsistency then
      io.stdout:write(string.format(
        "[CHAINSTATE-RECOVERY] Detected inconsistency: %s\n",
        tostring(details.reason)))
      if rolled > 0 then
        io.stdout:write(string.format(
          "[CHAINSTATE-RECOVERY] Auto-rollback successful: disconnected %d block(s); new tip h=%d\n",
          rolled, final_h))
      end
      if details.undo_missing then
        io.stdout:write(
          "[CHAINSTATE-RECOVERY] WARNING: rollback was incomplete (undo data unavailable). "
          .. "If IBD re-wedges, restart with --reindex-chainstate to rebuild from on-disk blocks.\n")
      end
      io.stdout:flush()
    else
      io.stdout:write(string.format(
        "Chainstate consistency check passed (tip h=%d).\n", final_h))
      io.stdout:flush()
    end
  end

  -- Initialize header chain
  io.stdout:write("Initializing header chain...\n"); io.stdout:flush()
  local header_chain = sync_mod.new_header_chain(network, db)
  header_chain:init()
  io.stdout:write("Header chain initialized.\n"); io.stdout:flush()
  print(string.format("Chain tip: height=%d hash=%s",
    header_chain.header_tip_height,
    header_chain.header_tip_hash and types.hash256_hex(header_chain.header_tip_hash) or "none"
  ))

  -- --reindex (full): Bitcoin Core re-reads every blk*.dat file from disk
  -- and rebuilds BOTH the block index AND the chainstate (init.cpp
  -- LoadBlocksFromDisk → ActivateBestChain).  In lunarblock today, the
  -- block-body store is a RocksDB CF (CF.BLOCKS), keyed by block hash, that
  -- IS the block index — there's no separate "block.idx" to rebuild.  So
  -- --reindex effectively reduces to --reindex-chainstate (replay every
  -- block-body via connect_block).  The remaining gap is a *block-body*
  -- re-import from an external source (e.g. -loadblock=bootstrap.dat),
  -- which is a separate feature and is left as a TODO below.
  --
  -- TODO(ops): full --reindex including block-body re-import from external
  -- bootstrap.dat is not yet implemented.  Today --reindex == --reindex-
  -- chainstate.  When the import-blocks framing pipeline is wired into
  -- startup, this is where it would chain off args.reindex.
  if args.reindex and not args.reindex_chainstate then
    print("[reindex] no separate block-body store to rebuild; running --reindex-chainstate")
    args.reindex_chainstate = true
  end

  -- --reindex-chainstate: wipe CF.UTXO + CF.UNDO and replay every
  -- block-body in CF.BLOCKS via connect_block. Recovers from the
  -- chainstate-corruption wedge documented in
  -- project_lunarblock_wedge_2026_04_28.
  if args.reindex_chainstate then
    local reindex_target = header_chain.header_tip_height
    if not reindex_target or reindex_target < 1 then
      io.stderr:write("--reindex-chainstate: no header tip to replay against — abort\n")
      os.exit(1)
    end
    io.stdout:write(string.format(
      "[reindex-chainstate] starting: target_height=%d (header tip)\n",
      reindex_target))
    io.stdout:flush()
    local progress_fn = function(msg, height)
      if msg then
        io.stdout:write(string.format("[reindex-chainstate] %s\n", msg))
      else
        io.stdout:write(string.format("[reindex-chainstate] replayed %d / %d (%.1f%%)\n",
          height, reindex_target, 100 * height / reindex_target))
      end
      io.stdout:flush()
    end
    local ok, msg = chain_state:reindex_chainstate(reindex_target, progress_fn)
    if not ok then
      io.stderr:write(string.format("[reindex-chainstate] FAILED: %s\n", tostring(msg)))
      os.exit(1)
    end
    io.stdout:write(string.format("[reindex-chainstate] %s\n", tostring(msg)))
    io.stdout:write(string.format("[reindex-chainstate] resuming normal startup at h=%d\n",
      chain_state.tip_height))
    io.stdout:flush()
  end

  -- Initialize block pruner.  args.prune is the user-supplied --prune
  -- value: 0=disabled (default), 1=manual-only, >=550=automatic with
  -- target MB.  When disabled, pruner.maybe_prune is a no-op so the
  -- IBD path remains identical to the un-pruned default.
  local pruner = prune_mod.new({
    target_mb = args.prune or 0,
    storage = db,
  })
  if pruner.enabled then
    print(string.format(
      "Pruning enabled: mode=%s target=%d MB (keep newest %d blocks)",
      pruner.automatic and "automatic" or "manual",
      pruner.target_mb,
      pruner.automatic and pruner:target_blocks_to_keep() or -1))
  end

  -- Initialize block downloader for IBD
  local block_downloader = sync_mod.new_block_downloader(header_chain, db, network)
  -- Start downloading from after the current chain tip
  block_downloader.next_connect_height = chain_state.tip_height + 1
  block_downloader.next_download_height = chain_state.tip_height + 1
  -- Build assumevalid callbacks once; they close over header_chain which is
  -- updated in-place as new headers arrive, so the lookup is always current.
  local av_in_index, av_is_ancestor, av_on_best_chain =
    consensus_mod.make_assumevalid_callbacks(network, header_chain)

  -- Wire up block connection callback to update UTXO chain state.
  -- The fourth parameter (caller_batch_fn) is the BUG-REPORT.md fix #2
  -- atomic-barrier hook from sync.lua: it adds the block-body write to
  -- connect_block's atomic batch so chain_tip + UTXO + UNDO + block body
  -- all commit together. Pre-2026-04-30 the body was put separately by
  -- sync.lua AFTER the callback, leaving a window where chain_tip could
  -- advance past a block whose body was missing on disk.
  block_downloader.connect_callback = function(block, height, block_hash, caller_batch_fn)
    -- During IBD, skip fsync on every block (nosync=true). The sync.lua loop
    -- issues a sync flush every utxo_flush_interval blocks (default 200).
    -- This avoids ~5ms of fsync latency per block, giving ~200x speedup for
    -- small early blocks.

    -- Compute skip_scripts via the real ancestor-check semantic (Bitcoin Core
    -- v28.0 ConnectBlock logic).  Regtest has assumevalid=nil so skip_scripts
    -- will always be false there, preserving full script verification.
    local block_hash_hex = types.hash256_hex(block_hash)
    local best_header_work = header_chain:get_chain_work()
    local best_header_height = header_chain.header_tip_height or 0
    local skip_scripts = consensus_mod.should_skip_script_validation(
      network, height, block_hash_hex,
      av_in_index, av_is_ancestor, av_on_best_chain,
      best_header_work, best_header_height
    )

    local ok, err = chain_state:connect_block(
      block, height, block_hash, nil, nil, skip_scripts, nil, true,
      caller_batch_fn)
    if not ok then
      -- Raise an error so pcall in connect_pending_blocks catches it.
      -- Returning nil without error would cause connect_pending_blocks to
      -- believe the connection succeeded, storing the block and advancing
      -- the height while the UTXO state was never updated.
      error(string.format("Failed to connect block %d: %s", height, tostring(err)))
    end
    -- Run the prune sweep AFTER the block is connected. maybe_prune is
    -- self-throttled (PRUNE_INTERVAL_BLOCKS) and capped per-call
    -- (MAX_DELETES_PER_SWEEP), so calling it on every connected block
    -- adds at most a hash-table check on the fast path. When --prune=0
    -- this is a single early-return.
    if pruner.enabled then
      pruner:maybe_prune(height)
    end
    -- Broadcast inv to peers for newly connected blocks (skip during IBD)
    if block_downloader.ibd_complete then
      local inv_payload = p2p.serialize_inv({
        {type = p2p.INV_TYPE.MSG_BLOCK, hash = block_hash}
      })
      peer_manager:broadcast("inv", inv_payload)
    end
  end

  -- Initialize mempool
  local mempool = mempool_mod.new(chain_state, {
    max_mempool_size = 300 * 1024 * 1024,
    min_relay_fee = 1000,
  })

  -- Bitcoin Core-compatible mempool.dat (kernel/mempool_persist.cpp).
  -- Load any prior dump now; persistence on shutdown is wired into the
  -- main-loop cleanup section below.
  local mempool_dat_path = datadir .. "/mempool.dat"
  do
    local f = io.open(mempool_dat_path, "rb")
    if f then
      f:close()
      local ok, stats_or_err = mempool_persist_mod.load(mempool, mempool_dat_path)
      if ok then
        print(string.format(
          "Loaded mempool.dat: %d accepted, %d failed, %d expired, %d already there",
          stats_or_err.count or 0, stats_or_err.failed or 0,
          stats_or_err.expired or 0, stats_or_err.already_there or 0))
      else
        print("Warning: failed to load mempool.dat: " .. tostring(stats_or_err))
      end
    end
  end

  -- Initialize ZMQ notifications (if any endpoints configured)
  local zmq_notifier = nil
  if args.zmqpubhashblock or args.zmqpubhashtx or args.zmqpubrawblock or
     args.zmqpubrawtx or args.zmqpubsequence then
    local zmq_mod = require("lunarblock.zmq")
    if zmq_mod.is_available() then
      zmq_notifier = zmq_mod.new_notification_manager({
        zmqpubhashblock = args.zmqpubhashblock,
        zmqpubhashtx = args.zmqpubhashtx,
        zmqpubrawblock = args.zmqpubrawblock,
        zmqpubrawtx = args.zmqpubrawtx,
        zmqpubsequence = args.zmqpubsequence,
        zmqpubhwm = args.zmqpubhwm,
      })
      if zmq_notifier.enabled then
        print("ZMQ notifications enabled")
        -- Wire up chain state callbacks for block notifications
        chain_state.callbacks.on_block_connected = function(block_hash, block)
          local block_data = serialize.serialize_block(block)
          zmq_notifier:on_block_connected(block_hash.bytes, block_data)
        end
        chain_state.callbacks.on_block_disconnected = function(block_hash)
          zmq_notifier:on_block_disconnected(block_hash.bytes)
        end
        -- Wire up mempool callback for tx removal notifications
        mempool.callbacks.on_tx_removed = function(txid_hex, _reason)
          local txid_bytes = types.hash256_from_hex(txid_hex)
          zmq_notifier:on_tx_removed(txid_bytes.bytes)
        end
      end
    else
      print("Warning: ZMQ notifications requested but libzmq not available")
    end
  end

  -- Initialize fee estimator
  local fee_estimator = fee_mod.new(144)
  local fee_est_path = datadir .. "/fee_estimates.dat"
  if fee_estimator:load(fee_est_path) then
    print("Loaded fee estimation data from " .. fee_est_path)
  end

  -- Wire fee estimator into block-connected callback.
  -- Wrap any existing callback (e.g. ZMQ) so both fire.
  local prev_on_block_connected = chain_state.callbacks.on_block_connected
  chain_state.callbacks.on_block_connected = function(block_hash, block)
    -- Feed the fee estimator: record confirmations for tracked txs
    local height = chain_state.tip_height
    if block and block.transactions then
      for _, tx in ipairs(block.transactions) do
        local txid = validation.compute_txid(tx)
        local txid_hex = types.hash256_hex(txid)
        fee_estimator:tx_confirmed(txid_hex, height)
      end
    end
    fee_estimator:on_block(height)
    -- Call previous callback (ZMQ, etc.)
    if prev_on_block_connected then
      prev_on_block_connected(block_hash, block)
    end
  end

  -- Initialize peer manager
  local peer_manager = peerman_mod.new(network, db, {
    maxpeers = args.maxpeers,
    max_outbound = (args.maxpeers == 0) and 0 or 8,
    nov2transport = args.nov2transport,
    peerbloomfilters = args.peerbloomfilters,
    data_dir = datadir,
  })
  peer_manager.our_height = header_chain.header_tip_height

  -- Clear any stale bans from previous sessions (genesis hash was wrong,
  -- causing all peers to be banned — now fixed).
  peer_manager.banned = {}

  -- Bootstrap: connect to local Bitcoin Core directly
  local bootstrap_ok, bootstrap_err = peer_manager:connect_peer("127.0.0.1", 48332, true)
  if bootstrap_ok then
    print("Bootstrap: connected to Bitcoin Core at 127.0.0.1:48332")
  else
    print("Bootstrap: failed to connect to Bitcoin Core: " .. tostring(bootstrap_err))
  end

  -- Register P2P message handlers
  peer_manager:register_handler("headers", function(peer, payload)
    local accepted, err = header_chain:handle_headers(peer, payload)
    if err then
      print("Invalid headers from " .. peer.ip .. ": " .. err)
      peer_manager:add_ban_score(peer, 100, err)
    elseif accepted and accepted > 0 then
      print(string.format("Accepted %d headers, tip now at height %d",
        accepted, header_chain.header_tip_height))
      peer_manager.our_height = header_chain.header_tip_height
      chain_state.header_tip_height = header_chain.header_tip_height
    end
  end)

  peer_manager:register_handler("block", function(peer, payload)
    -- Process blocks both during IBD and at tip (for new blocks
    -- received via inv→getdata after IBD completes).
    local ok, err = block_downloader:handle_block(peer, payload)
    if not ok then
      print(string.format("Block download error: %s", tostring(err)))
    end
  end)

  peer_manager:register_handler("notfound", function(peer, payload)
    -- Handle notfound responses: remove blocks from inflight so they can
    -- be re-requested from different peers. Without this handler, the
    -- inflight entry lingers until timeout, delaying stall recovery.
    local items = p2p.deserialize_inv(payload)
    for _, item in ipairs(items) do
      if item.type == p2p.INV_TYPE.MSG_BLOCK or
         item.type == p2p.INV_TYPE.MSG_WITNESS_BLOCK then
        local hash_hex = types.hash256_hex(item.hash)
        block_downloader:handle_notfound(hash_hex, peer)
      end
    end
  end)

  peer_manager:register_handler("inv", function(peer, payload)
    local items = p2p.deserialize_inv(payload)
    local to_request = {}
    for _, item in ipairs(items) do
      if item.type == p2p.INV_TYPE.MSG_TX or item.type == p2p.INV_TYPE.MSG_WITNESS_TX then
        local txid_hex = types.hash256_hex(item.hash)
        if not mempool:has(txid_hex) then
          to_request[#to_request + 1] = {
            type = p2p.INV_TYPE.MSG_WITNESS_TX,
            hash = item.hash,
          }
        end
      elseif item.type == p2p.INV_TYPE.MSG_BLOCK or item.type == p2p.INV_TYPE.MSG_WITNESS_BLOCK then
        -- Request new block headers
        header_chain:start_sync(peer)
      end
    end
    if #to_request > 0 then
      peer:send_message("getdata", p2p.serialize_inv(to_request))
    end
  end)

  peer_manager:register_handler("tx", function(peer, payload)
    local ok, err = pcall(function()
      local tx = serialize.deserialize_transaction(payload)
      local accepted, reason = mempool:accept_transaction(tx)
      if accepted then
        -- Relay to other peers
        local txid = validation.compute_txid(tx)
        local inv = p2p.serialize_inv({
          {type = p2p.INV_TYPE.MSG_WITNESS_TX, hash = txid}
        })
        peer_manager:broadcast("inv", inv, function(p) return p ~= peer end)
        -- Track for fee estimation
        local txid_hex = types.hash256_hex(txid)
        local entry = mempool:get_entry(txid_hex)
        if entry then
          fee_estimator:track_tx(txid_hex, entry.fee_rate, chain_state.tip_height)
        end
        -- ZMQ notification for new transaction
        if zmq_notifier then
          zmq_notifier:on_tx_added(txid.bytes, payload)
        end
      else
        -- Log rejection if verbose
        local _ = reason
      end
    end)
    if not ok then
      peer_manager:add_ban_score(peer, 10, tostring(err))
    end
  end)

  -- BIP 35: respond to "mempool" by sending inv of every txid in our mempool.
  -- Reference: bitcoin-core/src/net_processing.cpp ProcessMessage MEMPOOL handler
  -- (the "Only process received mempool messages if we advertise NODE_BLOOM"
  -- block).  We mirror that exactly: gate on the per-peer our_services flag,
  -- disconnect the peer if they ask without us advertising NODE_BLOOM (Core's
  -- "fDisconnect = true; return;" path), then enqueue all mempool entries via
  -- the existing trickle queue so the actual sends are spread across ticks
  -- and never block the single-threaded event loop on a giant walk.
  local bit = require("bit")
  peer_manager:register_handler("mempool", function(peer, _payload)
    -- Gate: did *we* advertise NODE_BLOOM to this peer? (Core's m_our_services
    -- check.)  Without it, Core treats the request as misbehavior and drops
    -- the peer.  We follow the same policy.
    local advertised_bloom = bit.band(peer.our_services or 0,
                                      p2p.SERVICES.NODE_BLOOM) ~= 0
    if not advertised_bloom then
      peer:disconnect("mempool request with bloom filters disabled")
      return
    end

    -- Walk the mempool once and queue every entry onto this peer's trickle
    -- queue.  _process_trickle() drains MAX_INV_PER_MSG entries per tick, so
    -- even a 30k-tx mempool fans out across the next few ticks without
    -- starving the event loop.
    local trickle_state = peer_manager._peer_trickle and
                          peer_manager._peer_trickle[peer.ip .. ":" .. peer.port]
    if not trickle_state then
      -- Peer not yet established or already torn down — nothing to do.
      return
    end
    local use_wtxid = peer.wtxid_relay
    for _, entry in pairs(mempool.entries) do
      local hash = use_wtxid and entry.wtxid or entry.txid
      trickle_state.inv_queue[#trickle_state.inv_queue + 1] = {
        hash = hash,
        is_wtxid = use_wtxid,
      }
    end
    -- Force the next trickle send to fire on the next tick rather than
    -- waiting up to OUTBOUND_INTERVAL/INBOUND_INTERVAL seconds — BIP-35
    -- semantics expect a prompt response.
    trickle_state.next_send_time = 0
  end)

  -- BIP 152: Compact block message handlers
  local compact_block = require("lunarblock.compact_block")

  peer_manager:register_handler("cmpctblock", function(peer, payload)
    local ok, err = pcall(function()
      local cmpctblock = p2p.deserialize_cmpctblock(payload)
      local header_bytes = serialize.serialize_block_header(cmpctblock.header)
      local block_hash = types.hash256(header_bytes)
      print(string.format("Received compact block from %s:%d (short_ids=%d, prefilled=%d)",
        peer.ip, peer.port, #cmpctblock.short_ids, #cmpctblock.prefilled_txns))

      -- Create a partial block and try to reconstruct
      local partial = compact_block.new_partial_block()
      local init_err = partial:init(cmpctblock, mempool)
      if init_err then
        print("compact block init error: " .. init_err)
        -- Fall back to requesting full block
        return
      end

      if partial:is_complete() then
        -- All transactions available (all prefilled or from mempool)
        local blk, recon_err = partial:reconstruct()
        if blk then
          print("Compact block fully reconstructed")
          -- Serialize and pass through normal block handling
          local blk_data = serialize.serialize_block(blk)
          block_downloader:handle_block(peer, blk_data)
        else
          print("Compact block reconstruction failed: " .. (recon_err or "unknown"))
        end
      else
        -- Request missing transactions via getblocktxn
        local missing = partial:get_missing_indices()
        print(string.format("Compact block missing %d txns, sending getblocktxn", #missing))
        local req_payload = p2p.serialize_getblocktxn(block_hash, missing)
        peer:send_message("getblocktxn", req_payload)
        -- Store partial block for later completion
        peer.pending_compact = peer.pending_compact or {}
        peer.pending_compact[types.hash256_hex(block_hash)] = partial
      end
    end)
    if not ok then
      print("Error processing compact block: " .. tostring(err))
    end
  end)

  peer_manager:register_handler("blocktxn", function(peer, payload)
    local ok, err = pcall(function()
      local blocktxn = p2p.deserialize_blocktxn(payload)
      local hash_hex = types.hash256_hex(blocktxn.block_hash)
      print(string.format("Received blocktxn from %s:%d (%d txns)",
        peer.ip, peer.port, #blocktxn.transactions))

      -- Look up pending compact block
      if not peer.pending_compact or not peer.pending_compact[hash_hex] then
        print("Unexpected blocktxn (no pending compact block)")
        return
      end

      local partial = peer.pending_compact[hash_hex]
      local fill_err = partial:fill_from_blocktxn(blocktxn.transactions)
      if fill_err then
        print("blocktxn fill error: " .. fill_err)
        peer.pending_compact[hash_hex] = nil
        return
      end

      local blk, recon_err = partial:reconstruct()
      peer.pending_compact[hash_hex] = nil
      if blk then
        print("Compact block reconstructed from blocktxn")
          local blk_data = serialize.serialize_block(blk)
          block_downloader:handle_block(peer, blk_data)
      else
        print("Compact block reconstruction failed: " .. (recon_err or "unknown"))
      end
    end)
    if not ok then
      print("Error processing blocktxn: " .. tostring(err))
    end
  end)

  peer_manager:register_handler("getblocktxn", function(peer, payload)
    local ok, err = pcall(function()
      local req = p2p.deserialize_getblocktxn(payload)
      print(string.format("Received getblocktxn from %s:%d (%d indexes)",
        peer.ip, peer.port, #req.indexes))

      -- Look up the full block
      local blk = db.get_block(req.block_hash)
      if blk then
        -- Respond with the requested transactions
        local transactions = {}
        for _, index in ipairs(req.indexes) do
          local tx = blk.transactions[index + 1]  -- Convert to 1-based
          if tx then
            transactions[#transactions + 1] = tx
          end
        end
        local resp_payload = p2p.serialize_blocktxn(req.block_hash, transactions)
        peer:send_message("blocktxn", resp_payload)
      else
        print("getblocktxn: block not found")
      end
    end)
    if not ok then
      print("Error processing getblocktxn: " .. tostring(err))
    end
  end)

  peer_manager:register_handler("getdata", function(peer, payload)
    local items = p2p.deserialize_inv(payload)
    local not_found = {}
    for _, item in ipairs(items) do
      if item.type == p2p.INV_TYPE.MSG_WITNESS_TX or item.type == p2p.INV_TYPE.MSG_TX then
        local txid_hex = types.hash256_hex(item.hash)
        local entry = mempool:get_entry(txid_hex)
        if entry then
          local data = serialize.serialize_transaction(entry.tx, true)
          peer:send_message("tx", data)
        else
          not_found[#not_found + 1] = item
        end
      elseif item.type == p2p.INV_TYPE.MSG_BLOCK or item.type == p2p.INV_TYPE.MSG_WITNESS_BLOCK then
        local blk = db.get_block(item.hash)
        if blk then
          local data = serialize.serialize_block(blk)
          peer:send_message("block", data)
        else
          not_found[#not_found + 1] = item
        end
      end
    end
    if #not_found > 0 then
      peer:send_message("notfound", p2p.serialize_notfound(not_found))
    end
  end)

  -- Peer established callback: start sync
  peer_manager.callbacks.on_peer_established = function(peer)
    print(string.format("Peer established: %s:%d %s (height=%d)",
      peer.ip, peer.port, peer.user_agent or "unknown", peer.start_height))
    if not header_chain.syncing and peer.start_height > header_chain.header_tip_height then
      header_chain:start_sync(peer)
    end
  end

  -- Initialize wallet manager (multi-wallet support)
  local wallet_manager = wallet_mod.new_manager(datadir, network, db)
  wallet_manager:ensure_wallets_dir()

  -- Load or create default wallet (backward compatible)
  local wallet = nil
  local default_wallet_path = datadir .. "/wallet.json"
  if not args.nowalletcreate then
    -- Try to load existing default wallet
    if wallet_mod.exists(default_wallet_path) then
      wallet = wallet_manager:load_wallet("")
      if wallet then
        print("Loaded default wallet")
      end
    end
    -- Create new wallet if none exists
    if not wallet then
      print("Creating new wallet...")
      wallet = wallet_manager:create_wallet("", {})
      if wallet then
        print("Wallet created. First address: " .. (wallet.addresses[1] or "none"))
      end
    end
  end

  -- Initialize RPC server
  local rpc_server = rpc_mod.new({
    host = "127.0.0.1",
    rpcport = args.rpcport,
    rpcuser = args.rpcuser,
    rpcpassword = args.rpcpassword,
    chain_state = chain_state,
    mempool = mempool,
    peer_manager = peer_manager,
    storage = db,
    network = network,
    fee_estimator = fee_estimator,
    wallet = wallet,  -- Legacy single wallet (backward compat)
    wallet_manager = wallet_manager,  -- Multi-wallet manager
    datadir = args.datadir,
    mining = mining_mod,
    block_downloader = block_downloader,
    -- Pass header_chain so submitblock can compute assumevalid skip decision
    header_chain = header_chain,
    -- Pre-built assumevalid callbacks (same closures as used by connect_callback)
    av_in_index = av_in_index,
    av_is_ancestor = av_is_ancestor,
    av_on_best_chain = av_on_best_chain,
    -- Pruner: enables `pruned`, `pruneheight`, `automatic_pruning` in
    -- getblockchaininfo and gates getblock with the right error code.
    pruner = pruner,
  })
  rpc_server:start()

  -- Initialize REST server (if enabled)
  local rest_server = nil
  if args.rest then
    local rest_mod = require("lunarblock.rest")
    local rest_port = args.restport or 8080
    rest_server = rest_mod.new({
      host = "127.0.0.1",
      rest_port = rest_port,
      chain_state = chain_state,
      mempool = mempool,
      storage = db,
      network = network,
    })
    rest_server:start()
  end

  -- Initialize Prometheus metrics server
  local metrics_port = args.metricsport or 9332
  local metrics_socket = nil
  if metrics_port > 0 then
    local socket = require("socket")
    -- tcp4() not tcp(): see rpc.lua / rest.lua — reuseaddr otherwise
    -- silently fails on LuaSocket 3.0 and bind races TIME_WAIT on relaunch.
    metrics_socket = socket.tcp4()
    assert(metrics_socket:setoption("reuseaddr", true))
    local ok, err = metrics_socket:bind("0.0.0.0", metrics_port)
    if ok then
      metrics_socket:listen(16)
      metrics_socket:settimeout(0)
      print(string.format("Prometheus metrics server on port %d", metrics_port))
    else
      print(string.format("WARNING: Metrics server failed on port %d: %s", metrics_port, tostring(err)))
      metrics_socket:close()
      metrics_socket = nil
    end
  end

  -- Connect to specific peer if requested
  if args.connect then
    local ip, port_str = args.connect:match("^([^:]+):?(%d*)$")
    local connect_port = tonumber(port_str) or network.port
    peer_manager:connect_peer(ip, connect_port)
  end

  -- Start P2P listener
  local listen_ok, listen_err = peer_manager:start_listener("0.0.0.0", args.port)
  if listen_ok then
    print(string.format("P2P listening on port %d", args.port))
  else
    print(string.format("WARNING: P2P listener failed on port %d: %s", args.port, tostring(listen_err)))
  end
  print(string.format("RPC listening on port %d", args.rpcport))
  if rest_server then
    print(string.format("REST listening on port %d", args.restport or 8080))
  end

  -- Ready signal: notify supervisor that listeners are up.
  -- Bitcoin Core uses sd_notify(READY=1); we use a simple write to a
  -- pre-opened FD so any process supervisor (s6, runit, shell) can wait on it.
  if args.ready_fd then
    if ops.signal_ready(args.ready_fd) then
      print(string.format("Ready signal sent on FD %d", args.ready_fd))
    else
      io.stderr:write(string.format(
        "Warning: failed to write READY to FD %d\n", args.ready_fd))
    end
  end

  -- Signal handling (graceful shutdown + log rotation).
  -- SIGTERM/SIGINT → flip running=false; main loop exits, cleanup runs.
  -- SIGHUP        → reopen log file (logrotate compatibility).
  local running = true
  ops.set_signal_handler(ops.SIGTERM, function()
    print("[signal] SIGTERM received, shutting down")
    running = false
  end)
  ops.set_signal_handler(ops.SIGINT, function()
    print("[signal] SIGINT received, shutting down")
    running = false
  end)
  ops.set_signal_handler(ops.SIGHUP, function()
    print("[signal] SIGHUP received, reopening log file")
    local rok, rerr = logger:reopen()
    if not rok then
      io.stderr:write("log reopen failed: " .. tostring(rerr) .. "\n")
    end
  end)

  -- Main event loop
  print("Entering main loop...")
  local last_status = 0
  while running do
    -- Drain any pending POSIX signals (SIGTERM/SIGINT/SIGHUP).
    -- Cheap: just int compares when no signal is pending.
    ops.poll_signals()

    -- Process P2P
    peer_manager:tick()

    -- Schedule block downloads — both during IBD and at tip.
    -- After IBD, new blocks are discovered via inv→getheaders→headers
    -- and need to be downloaded and connected.
    if header_chain.header_tip_height > chain_state.tip_height then
      local peers = peer_manager:get_established_peers()
      if #peers > 0 then
        block_downloader:schedule_downloads(peers)
      end
    end

    -- Process RPC (pcall to prevent tick errors from crashing the server socket)
    local rpc_ok, rpc_err = pcall(function() rpc_server:tick() end)
    if not rpc_ok then
      print(string.format("RPC tick error: %s", tostring(rpc_err)))
    end

    -- Process REST
    if rest_server then
      rest_server:tick()
    end

    -- Process Prometheus metrics requests
    if metrics_socket then
      local client = metrics_socket:accept()
      if client then
        client:settimeout(2)
        -- Read and discard HTTP request
        repeat
          local line = client:receive("*l")
        until not line or line == ""
        -- Build metrics response
        local height = chain_state.tip_height or 0
        local peers = #(peer_manager:get_established_peers())
        local mp_count = mempool and mempool.tx_count or 0
        local body = string.format(
          "# HELP bitcoin_blocks_total Current block height\n" ..
          "# TYPE bitcoin_blocks_total gauge\n" ..
          "bitcoin_blocks_total %d\n" ..
          "# HELP bitcoin_peers_connected Number of connected peers\n" ..
          "# TYPE bitcoin_peers_connected gauge\n" ..
          "bitcoin_peers_connected %d\n" ..
          "# HELP bitcoin_mempool_size Mempool transaction count\n" ..
          "# TYPE bitcoin_mempool_size gauge\n" ..
          "bitcoin_mempool_size %d\n",
          height, peers, mp_count)
        local resp = string.format(
          "HTTP/1.1 200 OK\r\n" ..
          "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n" ..
          "Content-Length: %d\r\n" ..
          "Connection: close\r\n\r\n%s",
          #body, body)
        client:send(resp)
        client:close()
      end
    end

    -- Periodic status update
    local now = socket.gettime()
    if now - last_status > 60 then
      local peers = peer_manager:get_established_peers()
      print(string.format("[%s] Height: %d | Headers: %d | Peers: %d | Mempool: %d txs (%d bytes) | Pending: %d | Inflight: %d",
        os.date("%Y-%m-%d %H:%M:%S"),
        chain_state.tip_height or 0,
        header_chain.header_tip_height,
        #peers,
        mempool.tx_count,
        mempool.total_size,
        block_downloader:get_pending_count(),
        block_downloader:get_inflight_count()
      ))

      -- [DIAG] Wedge-diagnostic line: captures state that the existing
      -- status line omits but that matters when the node wedges
      -- (state R, RPC unresponsive, RSS growing). Written so future
      -- post-mortems have data on whether the wedge is GC-stall,
      -- heap-blowup, cursor-skip, or peer-starvation.
      --
      --   gc_kb            : Lua heap via collectgarbage("count") — a
      --                      jump here correlates with a GC pause; a
      --                      steady climb means a leak.
      --   rss_kb           : process RSS from /proc/self/status — if
      --                      gc_kb stays flat but rss_kb grows, the
      --                      allocation is FFI or native (not Lua heap).
      --   dl_conn_gap      : next_download_height - next_connect_height
      --                      — shows whether the scheduler is running
      --                      ahead of the connector (normal) or stuck
      --                      at the cursor (wedge).
      --   since_connect_s  : seconds since next_connect_height last
      --                      advanced — the 90 s STALL RECOVERY timer
      --                      source-of-truth. If this grows past 90
      --                      without a STALL RECOVERY line, recovery
      --                      is broken.
      local gc_kb = collectgarbage("count")
      local rss_kb = 0
      local f = io.open("/proc/self/status", "r")
      if f then
        for line in f:lines() do
          local m = line:match("^VmRSS:%s*(%d+)")
          if m then rss_kb = tonumber(m); break end
        end
        f:close()
      end
      local dl_conn_gap = (block_downloader.next_download_height or 0)
        - (block_downloader.next_connect_height or 0)
      local since_connect_s = 0
      if block_downloader.last_connect_advance and block_downloader.last_connect_advance > 0 then
        since_connect_s = now - block_downloader.last_connect_advance
      end
      print(string.format(
        "[DIAG] gc_kb=%d rss_kb=%d dl_conn_gap=%d since_connect_s=%.0f peers=%d pending=%d inflight=%d",
        math.floor(gc_kb), rss_kb, dl_conn_gap, since_connect_s,
        #peers,
        block_downloader:get_pending_count(),
        block_downloader:get_inflight_count()))

      last_status = now
    end

    -- Short sleep to avoid busy-waiting (reduced for RPC throughput)
    socket.sleep(0.001)
  end

  -- Cleanup
  print("Shutting down...")

  -- Stop JIT profiling
  if args.jitprofile then
    local ok, jit_p = pcall(require, "jit.p")
    if ok then
      jit_p.stop()
      print("JIT profile written to " .. datadir .. "/jit_profile.txt")
    end
  end
  if args.jitverbose then
    local ok, jit_v = pcall(require, "jit.v")
    if ok then
      jit_v.off()
      print("JIT verbose log written to " .. datadir .. "/jit_verbose.txt")
    end
  end

  peer_manager:stop()
  rpc_server:stop()
  if rest_server then rest_server:stop() end
  if wallet then wallet:save(wallet_path) end
  -- Persist fee estimation data
  local save_ok, save_err = fee_estimator:save(fee_est_path)
  if save_ok then
    print("Saved fee estimation data to " .. fee_est_path)
  else
    print("Warning: failed to save fee estimates: " .. tostring(save_err))
  end
  -- Persist mempool to mempool.dat (Bitcoin Core compatible).
  local dump_ok, dump_count_or_err = mempool_persist_mod.dump(mempool, mempool_dat_path)
  if dump_ok then
    print(string.format("Dumped %d mempool transactions to %s",
      dump_count_or_err or 0, mempool_dat_path))
  else
    print("Warning: failed to dump mempool: " .. tostring(dump_count_or_err))
  end
  db.close()
  -- Remove PID file (Bitcoin Core init.cpp does this in the Shutdown path).
  ops.remove_pid_file(pid_path)
  -- Close logger so the file gets fsynced before exit.
  logger:close()
  print("LunarBlock stopped.")
end

-- Export module for testing or run main if executed directly
M.main = main

-- Check if being run directly (not required as a module)
if not pcall(debug.getlocal, 4, 1) then
  -- Running as script
  -- First check for --help and --version before loading any modules
  for _, v in ipairs(arg) do
    if v == "--help" or v == "-h" then
      print("Usage: lunarblock [OPTIONS]")
      print("")
      print("A Bitcoin full node in Lua")
      print("")
      print("Options:")
      print("  -d, --datadir DIR       Data directory (default: ~/.lunarblock)")
      print("  -n, --network NET       Network: mainnet, testnet, regtest (default: mainnet)")
      print("      --rpcport PORT      RPC server port")
      print("      --rpcuser USER      RPC username (default: lunarblock)")
      print("      --rpcpassword PW    RPC password")
      print("      --port PORT         P2P listen port")
      print("      --maxpeers N        Maximum peer connections (default: 125)")
      print("      --dbcache MB        Database cache size in MB (default: 450)")
      print("      --connect IP:PORT   Connect to specific peer")
      print("      --testnet           Use testnet")
      print("      --regtest           Use regtest")
      print("      --printtoconsole    Print log to console")
      print("      --nowalletcreate    Do not create wallet on first run")
      print("      --reindex           Rebuild UTXO set from blocks")
      print("      --reindex-chainstate Rebuild chainstate (UTXO set) from on-disk blocks")
      print("      --daemon            Run as daemon")
      print("      --jitprofile        Enable JIT profiling output")
      print("      --jitverbose        Enable verbose JIT compilation logging")
      print("      --prune N           Prune mode: 0=disabled, 1=manual, >=550=target MB")
      print("      --metricsport PORT  Prometheus metrics port (default: 9332, 0 = disabled)")
      print("      --rest              Enable REST API (no auth, read-only)")
      print("      --restport PORT     REST server port (default: 8080)")
      print("      --zmqpubhashblock ENDPOINT  Publish hashblock notifications")
      print("      --zmqpubhashtx ENDPOINT     Publish hashtx notifications")
      print("      --zmqpubrawblock ENDPOINT   Publish rawblock notifications")
      print("      --zmqpubrawtx ENDPOINT      Publish rawtx notifications")
      print("      --zmqpubsequence ENDPOINT   Publish sequence notifications")
      print("      --zmqpubhwm N               ZMQ high water mark (default: 1000)")
      print("      --import-blocks FILE        Import blocks from framed file (or - for stdin)")
      print("      --import-utxo FILE          Import UTXO snapshot from Core dumptxoutset file (AssumeUTXO)")
      print("      --pid PATH                  Path to PID file (default: <datadir>/lunarblock.pid)")
      print("      --debug CATS                Enable debug categories (comma-separated; e.g. net,mempool,1=all)")
      print("      --log PATH                  Path to log file (default: <datadir>/debug.log)")
      print("      --conf PATH                 Path to bitcoin.conf-style config file")
      print("      --ready-fd N                Write READY token to this FD when listeners are up")
      print("      --version           Print version and exit")
      print("  -h, --help              Show this help message")
      os.exit(0)
    elseif v == "--version" then
      print("LunarBlock v" .. VERSION)
      print("LuaJIT " .. (jit and jit.version or "unknown"))
      os.exit(0)
    end
  end
  main()
end

return M
