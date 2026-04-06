#!/usr/bin/env luajit
-- LunarBlock - Bitcoin full node in Lua
-- CLI & Application Entry Point

io.stdout:setvbuf("line")
io.stderr:setvbuf("line")

local VERSION = "0.1.0"

--------------------------------------------------------------------------------
-- Minimal argument parser (no external dependency)
--------------------------------------------------------------------------------

local function parse_args(argv)
  local args = {
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
    import_blocks = nil,   -- Path to framed block file for import (or "-" for stdin)
  }

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
      print("      --daemon            Run as daemon")
      print("      --jitprofile        Enable JIT profiling output")
      print("      --jitverbose        Enable verbose JIT compilation logging")
      print("      --prune N           Prune mode: 0=disabled, 1=manual, >=550=target MB")
      print("      --rest              Enable REST API (no auth, read-only)")
      print("      --restport PORT     REST server port (default: 8080)")
      print("      --zmqpubhashblock ENDPOINT  Publish hashblock notifications")
      print("      --zmqpubhashtx ENDPOINT     Publish hashtx notifications")
      print("      --zmqpubrawblock ENDPOINT   Publish rawblock notifications")
      print("      --zmqpubrawtx ENDPOINT      Publish rawtx notifications")
      print("      --zmqpubsequence ENDPOINT   Publish sequence notifications")
      print("      --zmqpubhwm N               ZMQ high water mark (default: 1000)")
      print("      --nov2transport             Disable BIP324 v2 encrypted transport")
      print("      --import-blocks FILE        Import blocks from framed file (or - for stdin)")
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
    elseif arg == "--daemon" then
      args.daemon = true
    elseif arg == "--jitprofile" then
      args.jitprofile = true
    elseif arg == "--jitverbose" then
      args.jitverbose = true
    elseif arg == "--nov2transport" then
      args.nov2transport = true
    elseif arg == "--import-blocks" then
      i = i + 1
      args.import_blocks = argv[i]
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
    else
      io.stderr:write("Unknown option: " .. arg .. "\n")
      os.exit(1)
    end
    i = i + 1
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
  local utxo_mod = require("lunarblock.utxo")
  local fee_mod = require("lunarblock.fee")
  local wallet_mod = require("lunarblock.wallet")
  local mining_mod = require("lunarblock.mining")
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

  -- Initialize header chain
  io.stdout:write("Initializing header chain...\n"); io.stdout:flush()
  local header_chain = sync_mod.new_header_chain(network, db)
  header_chain:init()
  io.stdout:write("Header chain initialized.\n"); io.stdout:flush()
  print(string.format("Chain tip: height=%d hash=%s",
    header_chain.header_tip_height,
    header_chain.header_tip_hash and types.hash256_hex(header_chain.header_tip_hash) or "none"
  ))

  -- Initialize block downloader for IBD
  local block_downloader = sync_mod.new_block_downloader(header_chain, db, network)
  -- Start downloading from after the current chain tip
  block_downloader.next_connect_height = chain_state.tip_height + 1
  block_downloader.next_download_height = chain_state.tip_height + 1
  -- Wire up block connection callback to update UTXO chain state
  block_downloader.connect_callback = function(block, height, block_hash)
    -- During IBD, skip fsync on every block (nosync=true). The sync.lua loop
    -- issues a sync flush every utxo_flush_interval blocks (default 2000).
    -- This avoids ~5ms of fsync latency per block, giving ~200x speedup for
    -- small early blocks.
    local ok, err = chain_state:connect_block(block, height, block_hash, nil, nil, true, nil, true)
    if not ok then
      -- Raise an error so pcall in connect_pending_blocks catches it.
      -- Returning nil without error would cause connect_pending_blocks to
      -- believe the connection succeeded, storing the block and advancing
      -- the height while the UTXO state was never updated.
      error(string.format("Failed to connect block %d: %s", height, tostring(err)))
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

  -- Initialize peer manager
  local peer_manager = peerman_mod.new(network, db, {
    maxpeers = args.maxpeers,
    max_outbound = (args.maxpeers == 0) and 0 or 8,
    nov2transport = args.nov2transport,
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

  -- Signal handling (graceful shutdown)
  local running = true

  -- Main event loop
  print("Entering main loop...")
  local last_status = 0
  while running do
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
  db.close()
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
      print("      --daemon            Run as daemon")
      print("      --jitprofile        Enable JIT profiling output")
      print("      --jitverbose        Enable verbose JIT compilation logging")
      print("      --prune N           Prune mode: 0=disabled, 1=manual, >=550=target MB")
      print("      --rest              Enable REST API (no auth, read-only)")
      print("      --restport PORT     REST server port (default: 8080)")
      print("      --zmqpubhashblock ENDPOINT  Publish hashblock notifications")
      print("      --zmqpubhashtx ENDPOINT     Publish hashtx notifications")
      print("      --zmqpubrawblock ENDPOINT   Publish rawblock notifications")
      print("      --zmqpubrawtx ENDPOINT      Publish rawtx notifications")
      print("      --zmqpubsequence ENDPOINT   Publish sequence notifications")
      print("      --zmqpubhwm N               ZMQ high water mark (default: 1000)")
      print("      --import-blocks FILE        Import blocks from framed file (or - for stdin)")
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
