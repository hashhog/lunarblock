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
    -- FIX-64 (W119): optional HTTPS/TLS termination for the RPC server.
    -- When BOTH paths are set, the JSON-RPC HTTP server wraps each accepted
    -- socket with luasec so traffic is TLS-encrypted (Core's httpserver.cpp
    -- pattern, mediated by libevent + OpenSSL).  When NEITHER is set, the
    -- server stays plaintext (backward-compat).  Mismatched (only one set) is
    -- a startup error.  Requires `luasec` (`luarocks install luasec` or
    -- `apt install lua-sec` on Debian/Ubuntu).
    rpc_tls_cert = nil,
    rpc_tls_key  = nil,
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
    asmap = nil,              -- Path to ASMap file for ASN-based IP bucketing (--asmap)
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
    peerblockfilters = false, -- BIP-157 / NODE_COMPACT_FILTERS: matches Core DEFAULT_PEERBLOCKFILTERS=false (init.cpp:993).
                              -- FIX-71 W121 BUG-2: gate plumbed but currently always false at advertisement time because
                              -- peer.lua:854 has no BIP-157 case branches (p2p.lua BIP157_P2P_DISPATCH_PRESENT=false).
                              -- When future P2P fix wave lands the dispatch + flips the flag, this CLI bit alone enables
                              -- the advertisement (assuming --blockfilterindex is also on, matching Core).
    import_blocks = nil,   -- Path to framed block file for import (or "-" for stdin)
    import_utxo = nil,     -- Path to Core-format UTXO snapshot file for AssumeUTXO import
    -- Operational-parity flags (mirrors Bitcoin Core init.cpp + util/system.cpp)
    pid = nil,             -- Path to PID file (default: <datadir>/lunarblock.pid)
    debug = nil,           -- Comma-separated debug categories (e.g. "net,mempool")
    log = nil,             -- Path to log file (default: <datadir>/debug.log)
    conf = nil,            -- Path to bitcoin.conf-style config file
    ready_fd = nil,        -- File descriptor for ready-signal (systemd-style)
    -- FIX-68 (W120 BUG-9): mempool full-RBF toggle.  Mirrors Bitcoin Core's
    -- -mempoolfullrbf, default TRUE per DEFAULT_MEMPOOL_FULL_RBF (Core v28+,
    -- policy/rbf.h).  When TRUE (default), accept_transaction skips BIP-125
    -- Rule 1 — any sufficiently-fee'd replacement is allowed, matching Core's
    -- cluster-mempool relay policy.  When FALSE, Rule 1 is enforced and
    -- non-signaling replacements are rejected with "conflicting tx does not
    -- signal RBF".  getmempoolinfo.fullrbf reads this value (honest).
    mempool_fullrbf = nil,  -- nil = take mempool.lua default; true/false override
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
      print("      --rpc-tls-cert PATH PEM cert path (enables HTTPS; requires --rpc-tls-key)")
      print("      --rpc-tls-key PATH  PEM private-key path (requires --rpc-tls-cert)")
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
      print("      --asmap PATH                Path to ASMap file for ASN-based IP bucketing")
      print("      --peerbloomfilters BOOL     Advertise NODE_BLOOM and service BIP-35 mempool requests (default: 0)")
      print("      --txindex                   Maintain a full transaction index (txid → blockhash) for getrawtransaction")
      print("      --blockfilterindex          Maintain a BIP-157/158 basic block-filter index (compact filters per block)")
      print("      --peerblockfilters BOOL     Advertise NODE_COMPACT_FILTERS service bit (default: 0; requires --blockfilterindex AND BIP-157 P2P dispatch)")
      print("      --import-blocks FILE        Import blocks from framed file (or - for stdin)")
      print("      --import-utxo FILE          Import UTXO snapshot from Core dumptxoutset file (AssumeUTXO)")
      print("      --pid PATH                  Path to PID file (default: <datadir>/lunarblock.pid)")
      print("      --debug CATS                Enable debug categories (comma-separated; e.g. net,mempool,1=all)")
      print("      --log PATH                  Path to log file (default: <datadir>/debug.log)")
      print("      --conf PATH                 Path to bitcoin.conf-style config file")
      print("      --ready-fd N                Write READY token to this FD when listeners are up")
      print("      --mempool-fullrbf BOOL      Mempool full-RBF policy (default: 1 = on, Core v28+ default)")
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
    elseif arg == "--rpc-tls-cert" or arg:match("^%-%-rpc%-tls%-cert=") then
      -- FIX-64 (W119): PEM cert path for HTTPS RPC.  Must be paired with
      -- --rpc-tls-key.  Mirrors Bitcoin Core's optional libevent+OpenSSL
      -- HTTPS termination in src/httpserver.cpp (Core's pattern is bind via
      -- evhttp_bind_socket_with_handle then wrap with SSL_CTX).  We use
      -- luasec instead; same shape: ssl.newcontext(params) + ssl.wrap(sock).
      local v = arg:match("^%-%-rpc%-tls%-cert=(.*)$")
      if v then args.rpc_tls_cert = v else i = i + 1; args.rpc_tls_cert = argv[i] end
    elseif arg == "--rpc-tls-key" or arg:match("^%-%-rpc%-tls%-key=") then
      -- FIX-64 (W119): PEM private-key path for HTTPS RPC.  Must be paired
      -- with --rpc-tls-cert.  No password-on-key support yet (Core's
      -- httpserver.cpp uses SSL_CTX_use_PrivateKey_file with PEM type and
      -- defers passphrase to the operator via SSL_CTX_set_default_passwd_cb;
      -- a follow-up can add --rpc-tls-key-passphrase if real deployments
      -- ever ship encrypted PEMs to lunarblock).
      local v = arg:match("^%-%-rpc%-tls%-key=(.*)$")
      if v then args.rpc_tls_key = v else i = i + 1; args.rpc_tls_key = argv[i] end
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
    elseif arg == "--asmap" or arg:match("^%-%-asmap=") then
      -- BUG-1 fix (W115 FIX-50): add --asmap CLI option for ASN-based bucketing.
      -- Mirrors Bitcoin Core's -asmap=<path> / -asmap (embedded) in init.cpp:540.
      local v = arg:match("^%-%-asmap=(.*)$")
      if v then
        args.asmap = v
      else
        i = i + 1
        args.asmap = argv[i]
      end
    elseif arg == "--peerbloomfilters" then
      i = i + 1
      local v = argv[i]
      args.peerbloomfilters = (v == "1" or v == "true" or v == "yes" or v == "on")
    elseif arg == "--peerblockfilters" or arg:match("^%-%-peerblockfilters=") then
      -- FIX-71 W121 BUG-2: opt-in to advertising NODE_COMPACT_FILTERS to
      -- peers.  Mirrors bitcoin-core init.cpp:993 -peerblockfilters.
      -- Setting this WITHOUT --blockfilterindex is a no-op (the gate in
      -- p2p.should_advertise_compact_filters() requires both).  Core
      -- treats the same combination as an init error; lunarblock chooses
      -- silent no-op to keep the gate simple and stay loud-error-free
      -- in the start_testnet4.sh / start_mainnet.sh paths.  Also
      -- requires p2p.BIP157_P2P_DISPATCH_PRESENT=true — currently false
      -- because peer.lua:854 has no BIP-157 case branches; the gate
      -- structurally returns false until the dispatch lands.
      local v = arg:match("^%-%-peerblockfilters=(.*)$")
      if v == nil then
        i = i + 1
        v = argv[i]
        args.peerblockfilters = (v == "1" or v == "true" or v == "yes" or v == "on")
      else
        args.peerblockfilters = (v == "1" or v == "true" or v == "yes" or v == "on")
      end
    elseif arg == "--txindex" or arg:match("^%-%-txindex=") then
      -- Pattern C0 (2026-05-06): enable inline txindex maintenance.
      -- Accepts "--txindex" (bare) or "--txindex=BOOL".  Mirrors
      -- bitcoin-core's -txindex CLI flag.  Default off; live mainnet
      -- runs unaffected unless the operator opts in on next restart.
      local v = arg:match("^%-%-txindex=(.*)$")
      if v == nil then
        args.txindex = true
      else
        args.txindex = (v == "1" or v == "true" or v == "yes" or v == "on")
      end
    elseif arg == "--blockfilterindex" or arg:match("^%-%-blockfilterindex=") then
      -- BIP-157 Phase 2 (2026-05-07): enable inline block-filter index
      -- (basic GCS filter per block) maintained atomically with
      -- chainstate.  Accepts "--blockfilterindex" (bare) or
      -- "--blockfilterindex=BOOL".  Mirrors bitcoin-core's
      -- -blockfilterindex=basic CLI flag.  Default off; live mainnet
      -- IBD path is bit-for-bit unchanged unless the operator opts in
      -- on next restart.
      local v = arg:match("^%-%-blockfilterindex=(.*)$")
      if v == nil then
        args.blockfilterindex = true
      else
        args.blockfilterindex = (v == "1" or v == "true" or v == "yes"
                                 or v == "on" or v == "basic")
      end
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
    elseif arg == "--mempool-fullrbf" or arg:match("^%-%-mempool%-fullrbf=") then
      -- FIX-68 (W120 BUG-9): mempool full-RBF toggle.  Mirrors Bitcoin Core's
      -- -mempoolfullrbf option (init.cpp adds it via SetupServerArgs).  Default
      -- TRUE per DEFAULT_MEMPOOL_FULL_RBF (Core policy/rbf.h since v28).
      -- Accepts "0/1", "true/false", "yes/no", "on/off"; passing nothing
      -- after the bare flag is treated as "1" (enable).  Wired to mempool
      -- config below — getmempoolinfo.fullrbf then reflects the actual setting.
      local v = arg:match("^%-%-mempool%-fullrbf=(.*)$")
      if v == nil then
        -- Look ahead — if next arg is a known bool literal, consume it;
        -- otherwise treat bare "--mempool-fullrbf" as enable.
        local nxt = argv[i + 1]
        if nxt == "0" or nxt == "1" or nxt == "true" or nxt == "false"
           or nxt == "yes" or nxt == "no" or nxt == "on" or nxt == "off" then
          i = i + 1
          v = nxt
        else
          v = "1"
        end
      end
      args.mempool_fullrbf = (v == "1" or v == "true" or v == "yes" or v == "on")
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
  if args.txindex then
    chain_state:set_txindex_enabled(true)
  end
  if args.blockfilterindex then
    chain_state:set_filterindex_enabled(true)
  end
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

      -- Context-free validation: check_block with height for BIP-34.
      -- Operator-controlled import path still validates structural
      -- invariants (PoW, merkle, weight, BIP-34 height, per-tx sanity)
      -- so a corrupted or malicious .dat file is caught before chainstate
      -- is modified. skip_check_block=false (default).
      local ok_chk, chk_err = pcall(validation.check_block, block,
        chain_state.network, frame_height)
      if not ok_chk then
        io.stderr:write(string.format(
          "Error validating block at height %d: %s\n",
          frame_height, tostring(chk_err)))
        os.exit(1)
      end

      -- Connect block through unified accept_block pipeline.
      -- skip_check_block=true because we already validated above.
      -- skip_scripts=true: operator import for speed; no peer-supplied data.
      -- prev_block_mtp + get_block_mtp computed inside accept_block.
      local connect_ok, connect_err = chain_state:accept_block(
        block, frame_height, block_hash, {
          skip_check_block = true,
          skip_scripts     = true,
        })
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

  -- Peek the 51-byte snapshot metadata header BEFORE loading so we can
  -- resolve the snapshot's base height from the assumeutxo table and pass
  -- it to load_snapshot as base_height.  Without this, load_snapshot's
  -- per-coin height guard (Core validation.cpp:5814-5819 "Bad snapshot data
  -- after deserializing N coins") used effective_base_height = tip_height,
  -- which is 0 immediately after connect_genesis() on a fresh datadir.
  -- Every snapshot coin from a block > 0 then failed the guard, so the load
  -- aborted with "Bad snapshot data after deserializing 0 coins" on the very
  -- first coin.  We resolve the height here (the loaded-after lookup at the
  -- bottom of this function did the same thing, just too late to help the
  -- guard) and feed it in.
  local pre_base_height = nil
  do
    local hf = io.open(args.import_utxo, "rb")
    if not hf then
      db.close()
      io.stderr:write("import-utxo FAILED: cannot open snapshot file: "
        .. tostring(args.import_utxo) .. "\n")
      os.exit(1)
    end
    local header = hf:read(51)
    hf:close()
    if not header or #header < 51 then
      db.close()
      io.stderr:write("import-utxo FAILED: cannot read snapshot header\n")
      os.exit(1)
    end
    local meta, meta_err = utxo_mod.deserialize_snapshot_metadata(header)
    if not meta then
      db.close()
      io.stderr:write("import-utxo FAILED: " .. tostring(meta_err) .. "\n")
      os.exit(1)
    end
    local base_hex = types.hash256_hex(meta.base_blockhash)
    local _au_data, _au_height =
      consensus_mod.assumeutxo_for_blockhash(network, base_hex)
    if _au_height then
      pre_base_height = _au_height
      print(string.format(
        "import-utxo: base block %s -> assumeutxo height %d",
        base_hex, _au_height))
    else
      -- No assumeutxo entry for this base block.  We still attempt the load,
      -- but warn loudly: the per-coin height guard will reject the snapshot
      -- because effective_base_height falls back to the genesis tip (0).
      io.stderr:write(string.format(
        "import-utxo WARNING: no assumeutxo entry for base block %s; "
        .. "per-coin height guard will reject coins from blocks > 0\n",
        base_hex))
    end
  end

  local t0 = os.time()
  -- Pass base_height so the per-coin height guard uses the true snapshot
  -- height instead of the fresh-datadir genesis tip (0).
  local ok, err = cs:load_snapshot(args.import_utxo, nil, pre_base_height)
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

  -- Compute and display the resulting set hash.  This is the HASH_SERIALIZED
  -- pass over the whole UTXO set (Core's coinstats.cpp HashWriter path); on
  -- the ~190M-coin mainnet snapshot it is the dominant post-load cost, so we
  -- time it on its own line for operator visibility.
  local h0 = os.time()
  local set_hash, count = cs:compute_utxo_hash()
  local hash_elapsed = os.time() - h0
  local set_hash_hex = ""
  for i = 1, 32 do
    set_hash_hex = set_hash_hex .. string.format("%02x", set_hash:byte(i))
  end

  db.close()

  print(string.format(
    "import-utxo complete: utxos=%d block=%s set_hash=%s load_elapsed=%ds hash_elapsed=%ds",
    count, tip_hex, set_hash_hex, elapsed, hash_elapsed))
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
  local crypto = require("lunarblock.crypto")
  local blockfilter_mod = require("lunarblock.blockfilter")

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
  -- Pattern C0 (2026-05-06): enable txindex if requested.  Off by default
  -- so the live mainnet IBD path (which is intentionally not restarted in
  -- this fix wave) keeps the same hot loop.  When on, connect_block writes
  -- (txid → blockhash||height_le) into CF.TX_INDEX inside the per-block
  -- atomic batch, and disconnect_block deletes those keys symmetrically.
  if args.txindex then
    chain_state:set_txindex_enabled(true)
    io.stdout:write("txindex enabled (Pattern C0).\n"); io.stdout:flush()
  end
  -- BIP-157 Phase 2 (2026-05-07): enable filter index if requested.
  -- Off by default — see set_filterindex_enabled in src/utxo.lua.  When
  -- on, connect_block builds the BIP-158 basic filter and writes the
  -- filter+height-index entries plus the filter_last_header chain into
  -- the per-block atomic batch, and disconnect_block deletes them
  -- symmetrically (with prev_header rewind via Core's CustomRemove
  -- semantics).
  if args.blockfilterindex then
    chain_state:set_filterindex_enabled(true)
    io.stdout:write("blockfilterindex enabled (BIP-157 Phase 2).\n")
    io.stdout:flush()
  end
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

  -- AssumeUTXO snapshot forward-sync: inject the snapshot base block-index.
  --
  -- After a fresh `--import-utxo`, the chainstate tip is the snapshot base
  -- (e.g. mainnet 944183) but the header chain only has genesis, because the
  -- snapshot file does not carry the base block's header.  Without a
  -- connectable base block-index the node cannot forward-sync past the base:
  -- it would have to re-download every header from genesis, and even then the
  -- post-snapshot blocks hit the 3-layer stall (chainwork below min /
  -- parent-not-found / empty MTP window) documented in
  -- sync.lua::inject_snapshot_base.
  --
  -- We detect the condition (chainstate tip is a known assumeutxo base AND the
  -- header chain sits below it) and inject a connectable base block-index from
  -- the assumeutxo entry's `header` + `chain_work` fields.  Forward-sync then
  -- starts directly from the base (Core's assumeUTXO model; mirrors nimrod's
  -- header-persist approach).  This touches ONLY the forward path — the base
  -- is only ever extended upward and never participates in reorg.
  if chain_state.tip_hash and (chain_state.tip_height or -1) > (header_chain.header_tip_height or -1) then
    local tip_hex = types.hash256_hex(chain_state.tip_hash)
    local au_data, au_height = consensus_mod.assumeutxo_for_blockhash(network, tip_hex)
    if au_data and au_height and au_data.header and au_data.chain_work then
      local hdr = au_data.header
      local base_header = types.block_header(
        hdr.version,
        types.hash256_from_hex(hdr.prev_hash),
        types.hash256_from_hex(hdr.merkle_root),
        hdr.timestamp,
        hdr.bits,
        hdr.nonce
      )
      -- Sanity: the reconstructed header must hash to the snapshot base block
      -- hash. A mismatch means the assumeutxo `header` fields are wrong; we
      -- refuse to inject a forged base block-index rather than poison the
      -- header chain.
      local computed_hex = types.hash256_hex(validation.compute_block_hash(base_header))
      if computed_hex ~= tip_hex then
        io.stderr:write(string.format(
          "[assumeutxo] WARNING: base header for height %d hashes to %s, expected %s; "
          .. "NOT injecting base block-index (header chain will sync from genesis)\n",
          au_height, computed_hex, tip_hex))
      else
        local base_work = consensus_mod.work_float_from_hex(au_data.chain_work)
        local injected, why = header_chain:inject_snapshot_base(
          au_height, chain_state.tip_hash, base_header, base_work)
        if injected then
          io.stdout:write(string.format(
            "[assumeutxo] injected snapshot base block-index: height=%d hash=%s "
            .. "chain_work=%s -> header chain forward-syncs from base\n",
            au_height, tip_hex, au_data.chain_work))
          io.stdout:flush()
          -- Keep peer_manager's advertised height in sync with the new header
          -- tip (set later from header_chain.header_tip_height, but make the
          -- intent explicit here for clarity).
          print(string.format("Header tip advanced to snapshot base: height=%d", au_height))
        else
          io.stdout:write(string.format(
            "[assumeutxo] base block-index NOT injected (%s); height=%d\n",
            tostring(why), au_height))
          io.stdout:flush()
        end
      end
    end
  end

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

    -- Wrap connect_block in pcall so we can discard partial in-memory
    -- mutations on failure. connect_block iterates through txns, calling
    -- coin_view:spend()/add() for each — those are immediate cache
    -- mutations. If a later tx in the same block fails validation
    -- (e.g. tapscript SCRIPT_SIZE), the flush at the end of connect_block
    -- never runs (so disk is consistent), but the cache is left holding
    -- spent entries and fresh adds. A retry would then see "Missing UTXO"
    -- on inputs whose UTXOs the cache thinks are spent. Calling
    -- coin_view:discard_dirty() drops every dirty cache entry; subsequent
    -- :get() calls fall back to disk and see the real (pre-attempt) state.
    --
    -- This closes the secondary symptom of the 944,186 wedge — see
    -- project_lunarblock_wedge_2026_04_28: tapscript SCRIPT_SIZE failed,
    -- then retries reported "Missing UTXO for input 1 of tx 98a09ed2..."
    -- because that input had been pre-spent in the cache during attempt 1.
    -- Route through accept_block (unified pipeline). sync.lua's
    -- connect_pending_blocks has already run validation.check_block with the
    -- correct height, so skip_check_block=true avoids a redundant pass here.
    -- accept_block will still compute prev_block_mtp and get_block_mtp
    -- correctly from storage, fixing the silent BIP-113 IsFinalTx + BIP-68
    -- time-based sequence-lock degradation that existed when connect_block
    -- was called directly with nil MTP args.
    -- accept_block can fail in two ways:
    --   (a) raise a Lua error via assert() (e.g. tapscript SCRIPT_SIZE fires
    --       inside connect_block) → pcall_ok=false, ok_or_err=error message.
    --   (b) return (nil, err_string) from a structured validation gate
    --       (e.g. connect_block: "prev_hash mismatch ...", "non-final
    --       transaction: bad-txns-nonfinal", "bad-cb-amount ...",
    --       "too-far-ahead", "bad-blk-sigops ..."). These paths return
    --       cleanly without raising. pcall_ok=true, accept_ok=nil, accept_err=string.
    -- Pre-fix, only (a) was handled — (b) silently fell through, sync.lua's
    -- pcall around connect_callback returned cb_ok=true, and
    -- connect_pending_blocks then ran `next_connect_height += 1` on a block
    -- that was NEVER connected. The local chain_state.tip_height stayed put
    -- (because connect_block bailed before its `self.tip_height = height`
    -- assignment), but next_connect_height marched past. Two heights later
    -- the scheduler attempted a block whose prev had never been applied,
    -- producing the 949207 wedge: "Missing UTXO for input 2 of tx
    -- 201efbc8..." where the missing UTXO was created in 949205, which
    -- silently dropped on a structured-error path.
    -- Both failure modes are now funnelled to the same handler: discard the
    -- partial in-memory cache mutations and raise so sync.lua's `if not
    -- cb_ok` branch fires and next_connect_height is NOT incremented.
    local pcall_ok, accept_ok, accept_err = pcall(chain_state.accept_block, chain_state,
      block, height, block_hash, {
        skip_check_block = true,    -- already validated by sync.lua above
        skip_scripts     = skip_scripts,
        nosync           = true,    -- IBD: caller-managed periodic flush
        caller_batch_fn  = caller_batch_fn,
      })
    if not pcall_ok then
      -- (a) A Lua error was raised (typically assert() inside connect_block).
      -- accept_ok is the error message in this case (pcall's 2nd return).
      -- Discard partial in-memory cache mutations from the failed attempt
      -- so a retry (or any sibling block) sees pre-attempt UTXO state.
      -- Disk is already consistent (no flush ran).
      chain_state.coin_view:discard_dirty()
      -- Re-raise so pcall in connect_pending_blocks catches it.
      error(string.format("Failed to connect block %d: %s", height, tostring(accept_ok)))
    end
    if not accept_ok then
      -- (b) Structured validation failure — accept_block returned (nil, err).
      -- Symmetric handling to the raised-error path above: drop dirty cache
      -- so retry sees clean state, then raise so sync.lua does NOT advance
      -- next_connect_height past a block whose UTXO mutations never landed.
      chain_state.coin_view:discard_dirty()
      error(string.format("Failed to connect block %d: %s", height, tostring(accept_err)))
    end
    -- Run the prune sweep AFTER the block is connected. maybe_prune is
    -- self-throttled (PRUNE_INTERVAL_BLOCKS) and capped per-call
    -- (MAX_DELETES_PER_SWEEP), so calling it on every connected block
    -- adds at most a hash-table check on the fast path. When --prune=0
    -- this is a single early-return.
    if pruner.enabled then
      pruner:maybe_prune(height)
    end
    -- Announce newly connected blocks to peers (skip during IBD).
    -- BIP-130: peers that sent `sendheaders` get a `headers` announce.
    -- BIP-152: HB peers (high_bandwidth=true) get an unsolicited cmpctblock.
    -- Everyone else gets the legacy `inv` announce.
    -- W112 BUG-5/BUG-6 fix: pass full block so announce_block can build
    -- cmpctblock payloads for HB peers (was passing only block_hash+header).
    if block_downloader.ibd_complete then
      peer_manager:announce_block(block_hash, block.header, block)
    end
  end

  -- Initialize mempool
  -- FIX-68 (W120 BUG-9): plumb --mempool-fullrbf into mempool config.  When
  -- the CLI flag was provided (true or false), it wins; otherwise the
  -- module-level default (Mempool.fullrbf = DEFAULT_MEMPOOL_FULL_RBF = true)
  -- applies.  getmempoolinfo.fullrbf then mirrors the actual relay policy.
  local mempool = mempool_mod.new(chain_state, {
    max_mempool_size = 300 * 1024 * 1024,
    min_relay_fee = 1000,
    fullrbf = args.mempool_fullrbf,  -- nil => mempool uses DEFAULT_MEMPOOL_FULL_RBF
  })

  -- Orphan tx pool (Core txorphanage parity).  Buffers up to 100 txs that
  -- arrived before their parent so we can re-evaluate them on parent
  -- arrival rather than dropping them on the floor and waiting for a
  -- re-announce.  Bounded by mempool_mod.MAX_ORPHAN_TRANSACTIONS,
  -- MAX_ORPHAN_TX_SIZE and MAX_ORPHANS_PER_PEER (see src/mempool.lua).
  local orphan_pool = mempool_mod.new_orphan_pool()

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

  -- Wire fee estimator into mempool tx-removal callback.
  -- Wrap any existing callback (e.g. ZMQ) so both fire.
  -- Mirrors Core's removeTx(hash, inBlock=false): evicted/replaced/expired txs
  -- are recorded as failures in failAvg; "confirmed" and "test-accept" are skipped
  -- (tx_confirmed() handles confirmed txs; test-accept is a dry-run).
  local prev_on_tx_removed = mempool.callbacks.on_tx_removed
  mempool.callbacks.on_tx_removed = function(txid_hex, reason)
    fee_estimator:tx_removed(txid_hex, reason)
    if prev_on_tx_removed then
      prev_on_tx_removed(txid_hex, reason)
    end
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
    -- Drain orphan pool: any orphan that named a tx in this block as a
    -- missing parent is now resolvable from the UTXO set.  Re-feed
    -- through the mempool acceptance pipeline; reject-on-persistent-fail
    -- is fine because we removed the orphan entry first.
    if orphan_pool and block and block.transactions then
      local resolved = orphan_pool:on_block_connected(block)
      for _, c in ipairs(resolved) do
        orphan_pool:remove(c.wtxid_hex)
        pcall(function() mempool:accept_transaction(c.tx) end)
      end
      -- Time-based expiry: evict orphans older than ORPHAN_TX_EXPIRE_TIME
      -- (300 s / 5 min) whose parent chain never arrived.  Called here
      -- so expiry runs at most once per block (cheap, ~100 entries).
      -- Mirrors Core's LimitOrphans() age gate (txorphanage.cpp).
      orphan_pool:expire_stale()
    end
    -- Call previous callback (ZMQ, etc.)
    if prev_on_block_connected then
      prev_on_block_connected(block_hash, block)
    end
  end

  -- Initialize peer manager
  local peer_manager = peerman_mod.new(network, db, {
    maxpeers = args.maxpeers,
    -- Core-semantic --connect: pin to ONLY the given peer, no auto-outbound
    -- fill (the block-downloader can stall on flaky DNS peers; a single
    -- reliable pinned peer avoids that).
    max_outbound = (args.connect and 0) or ((args.maxpeers == 0) and 0 or 8),
    nov2transport = args.nov2transport,
    peerbloomfilters = args.peerbloomfilters,
    -- BIP-159: when prune mode is enabled, peers see NODE_NETWORK_LIMITED
    -- in our outbound version handshake.  args.prune > 0 selects between
    -- archive-mode and limited-archive serving.
    prune_mode = (type(args.prune) == "number" and args.prune > 0),
    -- FIX-71 W121 BUG-2: NODE_COMPACT_FILTERS advertisement gate inputs.
    -- The gate function p2p.should_advertise_compact_filters() AND's
    -- three signals; the third (BIP157_P2P_DISPATCH_PRESENT) is module-
    -- level in p2p.lua and currently false because peer.lua:854 has no
    -- BIP-157 case branches.  When the future P2P fix wave lands the
    -- dispatch, no change is needed here — the module-level flag flips
    -- and the gate evaluates true (assuming the operator opted in via
    -- --peerblockfilters AND --blockfilterindex).
    peerblockfilters = args.peerblockfilters,
    blockfilterindex_enabled = args.blockfilterindex,
    data_dir = datadir,
  })
  peer_manager.our_height = header_chain.header_tip_height

  -- Load ASMap for ASN-based IP bucketing (W115 FIX-50, BUG-25 startup log).
  -- --asmap PATH: load from disk.  No --asmap: skip (plain /16//32 bucketing).
  if args.asmap then
    local ok, asmap_err = peer_manager:load_asmap(args.asmap)
    if ok then
      -- BUG-25: log ASMap health on startup after loading.
      -- asmap_health_check also emits a log line to stderr internally.
      peer_manager:asmap_health_check()
    else
      io.stderr:write(string.format(
        "[asmap] WARNING: failed to load asmap from %s: %s\n",
        args.asmap, tostring(asmap_err)))
    end
  end

  -- Clear any stale bans from previous sessions (genesis hash was wrong,
  -- causing all peers to be banned — now fixed).
  peer_manager.banned = {}

  -- Legacy dev bootstrap: connect to a local Bitcoin Core directly. The
  -- 127.0.0.1:48332 target is a stale dev default (fails everywhere else), and
  -- when --connect is given that pins the real peer below, so skip this.
  if not args.connect then
    local bootstrap_ok, bootstrap_err = peer_manager:connect_peer("127.0.0.1", 48332, true)
    if bootstrap_ok then
      print("Bootstrap: connected to Bitcoin Core at 127.0.0.1:48332")
    else
      print("Bootstrap: failed to connect to Bitcoin Core: " .. tostring(bootstrap_err))
    end
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
      local err_str = tostring(err)
      print(string.format("Block download error: %s", err_str))
      -- Bitcoin Core net_processing.cpp:4788 / MaybePunishNodeForBlock:
      -- BLOCK_MUTATED (witness malleation) and BLOCK_INVALID_HEADER both call
      -- Misbehaving(peer, 100). Deserialize failures are network noise (not
      -- necessarily the peer's fault), so we skip the ban score only for that.
      if err_str ~= "deserialize failed" then
        peer_manager:add_ban_score(peer, 100, err_str)
      end
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
      elseif item.type == p2p.INV_TYPE.MSG_WTX then
        -- BIP-339: wtxid-relay peers announce via MSG_WTX (=5); hash is wtxid.
        -- Look up by wtxid hex; if not in mempool, request via MSG_WTX getdata.
        local wtxid_hex = types.hash256_hex(item.hash)
        if not mempool:has_wtxid(wtxid_hex) then
          to_request[#to_request + 1] = {
            type = p2p.INV_TYPE.MSG_WTX,
            hash = item.hash,
          }
        end
      elseif item.type == p2p.INV_TYPE.MSG_BLOCK or item.type == p2p.INV_TYPE.MSG_WITNESS_BLOCK then
        -- Request new block headers
        header_chain:start_sync(peer)
      end
    end
    -- Core net_processing.cpp:128: MAX_GETDATA_SZ=1000 — cap each outgoing
    -- getdata to 1000 items.  An inv from a peer can carry up to 50000 entries
    -- (MAX_INV_SZ); sending them all in one getdata violates the cap and risks
    -- the remote peer dropping the oversized request.
    local i = 1
    while i <= #to_request do
      local batch = {}
      local limit = math.min(i + p2p.MAX_GETDATA_SZ - 1, #to_request)
      for j = i, limit do
        batch[#batch + 1] = to_request[j]
      end
      peer:send_message("getdata", p2p.serialize_inv(batch))
      i = i + p2p.MAX_GETDATA_SZ
    end
  end)

  -- Forward declaration so the tx handler can recurse into orphan
  -- resolution after a successful parent accept.
  local try_resolve_orphans

  peer_manager:register_handler("tx", function(peer, payload)
    local ok, err = pcall(function()
      local tx = serialize.deserialize_transaction(payload)
      local accepted, reason = mempool:accept_transaction(tx)
      if accepted then
        -- Relay to other peers via the trickle queue (Poisson delay, BIP-339
        -- correct inv type: MSG_WTX for wtxid_relay peers, MSG_TX otherwise).
        -- Do NOT call peer_manager:broadcast() here — that sends immediately to
        -- all peers with MSG_WITNESS_TX (legacy) and leaks timing/origin info.
        local txid  = validation.compute_txid(tx)
        local wtxid = validation.compute_wtxid(tx)
        -- Pass tx object so peers with bloom filters can do per-peer filtering
        -- (BIP-37 FIX-37: queue_tx_announcement now accepts optional tx arg).
        peer_manager:queue_tx_announcement(txid, wtxid, tx)
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
        -- Re-check orphan pool: any orphan that named this tx as a missing
        -- parent may now be admissible.  Iterates with cycle protection
        -- via the orphan_pool's removal on each loop.
        try_resolve_orphans(txid_hex)
      elseif reason == "missing inputs" then
        -- Buffer in orphan pool so that when the parent arrives we can
        -- re-evaluate.  Bounded; rejections are silent.
        -- Use wtxid as primary key (BIP-339 / W99 G14): two transactions
        -- with the same txid but different witnesses are distinct orphans.
        local wtxid = validation.compute_wtxid(tx)
        local wtxid_hex = types.hash256_hex(wtxid)
        local missing = mempool:missing_parents_for(tx)
        local pid = (peer and peer.ip and peer.port)
                    and (peer.ip .. ":" .. peer.port) or "anonymous"
        orphan_pool:add(tx, wtxid_hex, pid, missing)
      else
        -- Log rejection if verbose
        local _ = reason
      end
    end)
    if not ok then
      peer_manager:add_ban_score(peer, 10, tostring(err))
    end
  end)

  -- After a tx is accepted to the mempool, re-feed any orphans that
  -- listed it as a missing parent.  Worklist style with depth-bounded
  -- recursion: each accepted child is itself enqueued so transitive
  -- chains drain in one call.
  try_resolve_orphans = function(parent_txid_hex)
    local worklist = {parent_txid_hex}
    local seen = {}
    while #worklist > 0 do
      local cur = table.remove(worklist)
      if not seen[cur] then
        seen[cur] = true
        local children = orphan_pool:children_of(cur)
        for _, c in ipairs(children) do
          -- Always remove first; on persistent reject we don't want to
          -- keep retrying the same tx every time the parent re-resolves.
          -- Remove by wtxid_hex (primary key); add txid_hex to worklist
          -- so subsequent children_of() calls resolve grandchildren.
          orphan_pool:remove(c.wtxid_hex)
          local accepted = mempool:accept_transaction(c.tx)
          if accepted then
            worklist[#worklist + 1] = c.txid_hex
          end
        end
      end
    end
  end

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

  -- BIP-37 / BIP-111: bloom filter P2P dispatch (FIX-37).
  -- Reference: bitcoin-core/src/net_processing.cpp FILTERLOAD/FILTERADD/
  --            FILTERCLEAR handlers (4963-5033).
  --
  -- filterload / filteradd / filterclear are inbound messages (peer → us).
  -- When NODE_BLOOM is not in our advertised services, Core disconnects the
  -- peer immediately (fDisconnect = true).  We mirror that exactly via
  -- bloom_guard().  When NODE_BLOOM IS advertised the messages are parsed
  -- and stored in per-peer state for outbound tx INV filtering (Step 4)
  -- and merkleblock serving (Step 5 via getdata MSG_FILTERED_BLOCK below).

  local bloom = require("lunarblock.bloom")

  local function bloom_guard(peer, msg_type)
    -- bit was already required above for the mempool handler; require again is
    -- idempotent in Lua (returns cached module).
    local bit_mod = require("bit")
    local advertised_bloom = bit_mod.band(peer.our_services or 0,
                                          p2p.SERVICES.NODE_BLOOM) ~= 0
    if not advertised_bloom then
      peer:disconnect(msg_type .. " received but NODE_BLOOM not advertised (BIP-111)")
      return false
    end
    return true
  end

  peer_manager:register_handler("filterload", function(peer, payload)
    -- BIP-111: disconnect if we did not advertise NODE_BLOOM.
    if not bloom_guard(peer, "filterload") then return end

    -- Parse the filter payload (varstr(vData) || nHashFuncs || nTweak || nFlags).
    local f, err = bloom.parse_filterload(payload)
    if not f then
      -- Malformed payload — misbehave and disconnect (mirrors Core's
      -- Misbehaving(peer, "bad filterload message") path).
      peer:disconnect("filterload parse error: " .. tostring(err))
      return
    end

    -- BIP-37: reject oversized filters (IsWithinSizeConstraints).
    -- Core calls Misbehaving(peer, "too-large bloom filter") → fDisconnect.
    if not bloom.is_within_size_constraints(f) then
      peer:disconnect("filterload: filter exceeds size constraints (BIP-37)")
      return
    end

    -- Store the filter in per-peer state and enable filtered tx relay.
    peer.bloom_filter = f
    peer.relay_txes   = true
    print(string.format("[bloom] filterload from %s:%d (vdata_len=%d hash_funcs=%d tweak=%d flags=%d)",
      peer.ip, peer.port, f.vdata_len, f.n_hash_funcs, f.n_tweak, f.n_flags))
  end)

  peer_manager:register_handler("filteradd", function(peer, payload)
    -- BIP-111: disconnect if we did not advertise NODE_BLOOM.
    if not bloom_guard(peer, "filteradd") then return end

    -- Parse element (varstr, max 520 bytes per BIP-37 / MAX_SCRIPT_ELEMENT_SIZE).
    local elem, err = bloom.parse_filteradd(payload)
    if not elem then
      -- Oversized element or parse failure.  Core calls
      -- Misbehaving(peer, "bad filteradd message") → fDisconnect.
      peer:disconnect("filteradd: " .. tostring(err))
      return
    end

    -- No filter loaded yet — treat as bad (Core "else bad = true" path).
    if not peer.bloom_filter then
      peer:disconnect("filteradd received without prior filterload")
      return
    end

    -- Insert the element into the existing filter.
    bloom.insert(peer.bloom_filter, elem)
  end)

  peer_manager:register_handler("filterclear", function(peer, _payload)
    -- BIP-111: disconnect if we did not advertise NODE_BLOOM.
    if not bloom_guard(peer, "filterclear") then return end

    -- Remove the filter and restore unconditional tx relay (Core:
    -- m_bloom_filter = nullptr; m_relay_txs = true; m_bloom_filter_loaded = false).
    peer.bloom_filter = nil
    peer.relay_txes   = true
    print(string.format("[bloom] filterclear from %s:%d — filter removed, relay restored",
      peer.ip, peer.port))
  end)

  -- merkleblock is server→client (we never expect to receive it as a server).
  -- Log and drop; no disconnect (not a protocol violation per BIP-111).
  peer_manager:register_handler("merkleblock", function(peer, _payload)
    print(string.format("[bloom] unexpected merkleblock from %s:%d — ignored",
      peer.ip, peer.port))
  end)

  -- BIP 152: Compact block message handlers
  local compact_block = require("lunarblock.compact_block")

  peer_manager:register_handler("cmpctblock", function(peer, payload)
    local ok, err = pcall(function()
      local cmpctblock = p2p.deserialize_cmpctblock(payload)
      local header_bytes = serialize.serialize_block_header(cmpctblock.header)
      -- W112 BUG-1 fix: types.hash256 wraps raw bytes; we need double-SHA256
      -- of the 80-byte header to get the 32-byte block hash (crypto.hash256_type).
      local block_hash = crypto.hash256_type(header_bytes)

      -- W112 BUG-7 fix: enforce MAX_CMPCTBLOCK_DEPTH=5 — reject stale compact
      -- blocks more than 5 blocks below our current tip (Core net_processing.cpp).
      do
        local entry = header_chain:get_header(block_hash)
        local tip_h = header_chain.header_tip_height or 0
        if entry and tip_h - (entry.height or 0) > compact_block.MAX_CMPCTBLOCK_DEPTH then
          print(string.format("cmpctblock too deep (depth=%d, max=%d) — ignored",
            tip_h - entry.height, compact_block.MAX_CMPCTBLOCK_DEPTH))
          return
        end
      end

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
    -- BIP-159 peer-served-blocks gate: when prune mode is on and the
    -- pruner has actually deleted blocks below the keep window, the
    -- `db.get_block(item.hash)` call below will return nil for those
    -- hashes and we fall through to the `not_found` branch — which
    -- emits the correct `notfound` reply per Core's net_processing.cpp
    -- behaviour.  An honest peer respecting our NODE_NETWORK_LIMITED
    -- bit should not request these in the first place; the not_found
    -- reply is the per-protocol fallback for misbehaving peers.
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
      elseif item.type == p2p.INV_TYPE.MSG_FILTERED_BLOCK then
        -- BIP-37 Step 5: serve merkleblock for MSG_FILTERED_BLOCK (=3).
        -- Reference: bitcoin-core/src/net_processing.cpp:2438-2458.
        -- Only send if the peer has a bloom filter loaded (Core silently
        -- omits the response when m_bloom_filter == nullptr).
        local blk = db.get_block(item.hash)
        if blk and peer.bloom_filter then
          local ok_mb, mb_err = pcall(function()
            -- Build txid array and match flags from the block.
            local txid_strings = {}
            local v_match = {}
            local matched_tx = {}  -- 1-indexed matched transactions (for tx push)
            for tx_i, tx in ipairs(blk.transactions) do
              local tx_validation = require("lunarblock.validation")
              local txid_obj = tx_validation.compute_txid(tx)
              txid_strings[tx_i] = txid_obj.bytes
              local matched = bloom.is_relevant_and_update(peer.bloom_filter, tx)
              v_match[tx_i] = matched
              if matched then
                matched_tx[#matched_tx + 1] = tx
              end
            end
            -- Encode the 80-byte block header.
            local hdr_bytes = serialize.serialize_block_header(blk)
            -- Build and send the merkleblock message.
            local mb_payload = bloom.encode_merkle_block(hdr_bytes, txid_strings, v_match)
            peer:send_message("merkleblock", mb_payload)
            -- Push matched transactions immediately after (Core behaviour:
            -- "CMerkleBlock just contains hashes, so also push any transactions
            --  in the block the client did not see").
            for _, matched_tx_entry in ipairs(matched_tx) do
              local tx_data = serialize.serialize_transaction(matched_tx_entry, false)
              peer:send_message("tx", tx_data)
            end
          end)
          if not ok_mb then
            -- Merkleblock build failure (e.g. block has no transactions).
            -- Fall back to not_found rather than crashing the loop.
            print(string.format("[bloom] merkleblock build failed for %s:%d: %s",
              peer.ip, peer.port, tostring(mb_err)))
            not_found[#not_found + 1] = item
          end
        elseif not blk then
          not_found[#not_found + 1] = item
        end
        -- else: block found but no filter loaded → silently omit (Core behaviour)
      end
    end
    if #not_found > 0 then
      peer:send_message("notfound", p2p.serialize_notfound(not_found))
    end
  end)

  --------------------------------------------------------------------------
  -- BIP-157 compact-filter request handlers (FIX-81 — W121 BUG-1/2 closure)
  --
  -- Mirrors bitcoin-core/src/net_processing.cpp:
  --   PrepareBlockFilterRequest  (line 3262) — shared validation
  --   ProcessGetCFilters         (line 3315) — getcfilters → cfilter*
  --   ProcessGetCFHeaders        (line 3344) — getcfheaders → cfheaders
  --   ProcessGetCFCheckPt        (line 3386) — getcfcheckpt → cfcheckpt
  --
  -- Validation common to all 3:
  --   (a) filter_type != 0   → peer:disconnect (Core fDisconnect=true)
  --   (b) !NODE_COMPACT_FILTERS in our advertised services → disconnect
  --       (Core's `peer.m_our_services & NODE_COMPACT_FILTERS` check)
  --   (c) stop_hash not in active chain → disconnect
  --       (Core's LookupBlockIndex + BlockRequestAllowed)
  --   (d) start_height > stop_index.height → disconnect (cfilters/cfheaders)
  --   (e) (stop_index.height - start_height) >= max_height_diff → disconnect
  --
  -- On success: walk the active chain (height_to_hash) from start_height
  -- to stop_index.height, look up each filter via storage CF.BLOCK_FILTER,
  -- and send the response message(s).
  --
  -- We use the active-chain walk (header_chain.height_to_hash[h]) because
  -- Core's stop_index.GetAncestor(h) by definition walks back from
  -- stop_index, and BlockRequestAllowed restricts stop_hash to peers we
  -- can serve.  When stop_hash IS on the active chain (the only case
  -- where BlockRequestAllowed passes the W14_REQUEST_BLOCKS threshold),
  -- GetAncestor(h) == height_to_hash[h].  Cross-fork stop_hashes are
  -- rejected outright — matches Core's BlockRequestAllowed false path.
  --
  local function bip157_dispatch_present()
    return p2p.BIP157_P2P_DISPATCH_PRESENT
  end

  local function get_active_chain_hash(height)
    local hash_hex = header_chain.height_to_hash[height]
    if not hash_hex then return nil end
    return types.hash256_from_hex(hash_hex)
  end

  -- Resolve `stop_hash` to a height on the active chain, mirroring Core's
  -- LookupBlockIndex + active-chain check.  Returns the height or nil.
  -- Rejects unknown hashes AND known headers that are not on the active
  -- chain (cross-fork getcfilters).  The header_chain.get_header path
  -- returns an entry with a height; height_to_hash[entry.height] must
  -- equal the requested hash hex to confirm active-chain membership.
  local function resolve_stop_hash_on_active_chain(stop_hash)
    local entry = header_chain:get_header(stop_hash)
    if not entry then return nil end
    local stop_height = entry.height
    local active_hex = header_chain.height_to_hash[stop_height]
    if not active_hex then return nil end
    if active_hex ~= types.hash256_hex(stop_hash) then return nil end
    return stop_height
  end

  -- Read a filter blob directly from CF.BLOCK_FILTER (matches the inline
  -- writes done by chain_state.connect_block; see utxo.lua:2952).  The
  -- on-disk layout is {filter_hash || filter_header || varstr(filter)}.
  local function read_filter_blob(block_hash)
    local data = db.get(storage_mod.CF.BLOCK_FILTER, block_hash.bytes)
    if not data then return nil end
    local r = serialize.buffer_reader(data)
    return {
      filter_hash   = r.read_hash256(),
      filter_header = r.read_hash256(),
      filter        = r.read_varstr(),
    }
  end

  local function our_compact_filters_advertised(peer)
    local bit_mod = require("bit")
    return bit_mod.band(peer.our_services or 0,
                        p2p.SERVICES.NODE_COMPACT_FILTERS) ~= 0
  end

  peer_manager:register_handler("getcfilters", function(peer, payload)
    if not bip157_dispatch_present() then return end
    if not chain_state.filterindex_enabled then
      -- Core: !filter_index → log + return (no disconnect)
      return
    end
    local ok, req = pcall(p2p.deserialize_getcfilters, payload)
    if not ok or not req then
      peer:misbehaving(10, "malformed getcfilters")
      return
    end
    -- Validation (b): filter_type==BASIC + service advertised.
    if req.filter_type ~= p2p.FILTER_TYPE.BASIC or
       not our_compact_filters_advertised(peer) then
      peer:disconnect("getcfilters: unsupported filter_type or NODE_COMPACT_FILTERS not advertised")
      return
    end
    -- Validation (c): stop_hash on active chain.
    local stop_height = resolve_stop_hash_on_active_chain(req.stop_hash)
    if not stop_height then
      peer:disconnect("getcfilters: stop_hash not on active chain (BlockRequestAllowed)")
      return
    end
    -- Validation (d): start_height > stop_height.
    if req.start_height > stop_height then
      peer:disconnect("getcfilters: start_height > stop_height")
      return
    end
    -- Validation (e): range too large (Core: >= max).
    if stop_height - req.start_height >= p2p.MAX_GETCFILTERS_SIZE then
      peer:disconnect("getcfilters: range exceeds MAX_GETCFILTERS_SIZE")
      return
    end
    -- Walk active chain, look up each filter, send cfilter responses.
    for h = req.start_height, stop_height do
      local block_hash = get_active_chain_hash(h)
      if not block_hash then break end
      local info = read_filter_blob(block_hash)
      if not info then break end
      local out = p2p.serialize_cfilter(req.filter_type, block_hash, info.filter)
      peer:send_message("cfilter", out)
    end
  end)

  peer_manager:register_handler("getcfheaders", function(peer, payload)
    if not bip157_dispatch_present() then return end
    if not chain_state.filterindex_enabled then return end
    local ok, req = pcall(p2p.deserialize_getcfheaders, payload)
    if not ok or not req then
      peer:misbehaving(10, "malformed getcfheaders")
      return
    end
    if req.filter_type ~= p2p.FILTER_TYPE.BASIC or
       not our_compact_filters_advertised(peer) then
      peer:disconnect("getcfheaders: unsupported filter_type or NODE_COMPACT_FILTERS not advertised")
      return
    end
    local stop_height = resolve_stop_hash_on_active_chain(req.stop_hash)
    if not stop_height then
      peer:disconnect("getcfheaders: stop_hash not on active chain (BlockRequestAllowed)")
      return
    end
    if req.start_height > stop_height then
      peer:disconnect("getcfheaders: start_height > stop_height")
      return
    end
    if stop_height - req.start_height >= p2p.MAX_GETCFHEADERS_SIZE then
      peer:disconnect("getcfheaders: range exceeds MAX_GETCFHEADERS_SIZE")
      return
    end
    -- prev_header: filter_header at start_height - 1.  Genesis (h=0):
    -- prev_header = uint256() = all-zeros (BIP-157 §"Filter Headers").
    local prev_filter_header
    if req.start_height == 0 then
      prev_filter_header = types.hash256_zero()
    else
      local prev_block_hash = get_active_chain_hash(req.start_height - 1)
      if not prev_block_hash then return end
      local prev_info = read_filter_blob(prev_block_hash)
      if not prev_info then return end
      prev_filter_header = prev_info.filter_header
    end
    -- Collect filter_hashes from start_height..stop_height.
    local filter_hashes = {}
    for h = req.start_height, stop_height do
      local block_hash = get_active_chain_hash(h)
      if not block_hash then return end
      local info = read_filter_blob(block_hash)
      if not info then return end
      filter_hashes[#filter_hashes + 1] = info.filter_hash
    end
    -- stop_index.GetBlockHash() in Core: send the stop_hash itself.
    local stop_hash = get_active_chain_hash(stop_height) or req.stop_hash
    local out = p2p.serialize_cfheaders(req.filter_type, stop_hash,
                                        prev_filter_header, filter_hashes)
    peer:send_message("cfheaders", out)
  end)

  peer_manager:register_handler("getcfcheckpt", function(peer, payload)
    if not bip157_dispatch_present() then return end
    if not chain_state.filterindex_enabled then return end
    local ok, req = pcall(p2p.deserialize_getcfcheckpt, payload)
    if not ok or not req then
      peer:misbehaving(10, "malformed getcfcheckpt")
      return
    end
    if req.filter_type ~= p2p.FILTER_TYPE.BASIC or
       not our_compact_filters_advertised(peer) then
      peer:disconnect("getcfcheckpt: unsupported filter_type or NODE_COMPACT_FILTERS not advertised")
      return
    end
    local stop_height = resolve_stop_hash_on_active_chain(req.stop_hash)
    if not stop_height then
      peer:disconnect("getcfcheckpt: stop_hash not on active chain (BlockRequestAllowed)")
      return
    end
    -- Core (net_processing.cpp:3403): N = stop_index.height / CFCHECKPT_INTERVAL.
    -- For each i in [0, N): height = (i + 1) * CFCHECKPT_INTERVAL,
    -- header = filter_header at that height.
    local interval = blockfilter_mod.CFCHECKPT_INTERVAL
    local n = math.floor(stop_height / interval)
    local headers = {}
    for i = 1, n do
      local h = i * interval
      local block_hash = get_active_chain_hash(h)
      if not block_hash then return end
      local info = read_filter_blob(block_hash)
      if not info then return end
      headers[i] = info.filter_header
    end
    local stop_hash = get_active_chain_hash(stop_height) or req.stop_hash
    local out = p2p.serialize_cfcheckpt(req.filter_type, stop_hash, headers)
    peer:send_message("cfcheckpt", out)
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
    -- FIX-64 (W119): optional HTTPS termination.  When both paths are set
    -- RPCServer:start() wraps the listening socket via luasec.  When neither
    -- is set, plaintext path (backward-compat).  Mismatch is a fatal error
    -- raised inside RPCServer:start() so callers see a clear message.
    rpc_tls_cert = args.rpc_tls_cert,
    rpc_tls_key  = args.rpc_tls_key,
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
    -- Register in manual_peers BEFORE the initial connect so the tick-level
    -- _reconnect_manual_peers() keeps the pin alive after any disconnect.
    -- With max_outbound forced to 0 (Core -connect semantics) the maintain
    -- loop opens NO outbound peers, so this is the only mechanism that
    -- re-establishes the pin if it drops (e.g. a transient handshake/headers
    -- hiccup) — without it the node falls to Peers:0 permanently and the body
    -- gap never downloads.  Same entry shape the addnode RPC uses.
    local key = ip .. ":" .. connect_port
    peer_manager.manual_peers[key] = {
      ip = ip,
      port = connect_port,
      use_v2_override = nil,
      last_try = 0,
      attempts = 0,
      success_count = 0,
    }
    -- Manual, diversity-exempt, eviction-protected pin (Core -connect
    -- semantics): with max_outbound forced to 0 above, this is the ONLY peer.
    peer_manager:connect_peer(ip, connect_port, true, nil, true)
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

    -- Process P2P (pcall — defense against malformed peer payloads
    -- crashing the main loop. A bad getdata varint mismatch trips an
    -- assert in src/serialize.lua:219 read_bytes that unwinds 5 frames
    -- and aborts the entire LuaJIT process; without this pcall the RPC
    -- server dies with it. Fixes the P0 DoS finding from Phase B
    -- fleet-replay 2026-05-24, see CORE-PARITY-AUDIT/_bug-reports/
    -- lunarblock-getblockcount-fails-2026-05-24.md.
    -- Per-peer dispatch isolation in src/peer.lua is the deeper fix;
    -- this top-level pcall is the symptom-layer safety net.)
    local p2p_ok, p2p_err = pcall(function() peer_manager:tick() end)
    if not p2p_ok then
      print(string.format("P2P tick error: %s", tostring(p2p_err)))
    end

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
      print("      --rpc-tls-cert PATH PEM cert path (enables HTTPS; requires --rpc-tls-key)")
      print("      --rpc-tls-key PATH  PEM private-key path (requires --rpc-tls-cert)")
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
      print("      --mempool-fullrbf BOOL      Mempool full-RBF policy (default: 1 = on, Core v28+ default)")
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
