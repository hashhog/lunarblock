#!/usr/bin/env luajit
-- LunarBlock - Bitcoin full node in Lua
-- CLI & Application Entry Point

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
    else
      io.stderr:write("Unknown option: " .. arg .. "\n")
      os.exit(1)
    end
    i = i + 1
  end

  return args
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
  local lfs = require("lfs")

  local args = parse_args(arg)

  -- Override network from flags
  if args.testnet then args.network = "testnet" end
  if args.regtest then args.network = "regtest" end

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
  lfs.mkdir(args.datadir)
  lfs.mkdir(datadir)

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
  print("Opening database...")
  local db = storage_mod.open(datadir .. "/chainstate", args.dbcache)

  -- Initialize chain state
  local chain_state = utxo_mod.new_chain_state(db, network)
  chain_state:init()

  -- Initialize header chain
  local header_chain = sync_mod.new_header_chain(network, db)
  header_chain:init()
  print(string.format("Chain tip: height=%d hash=%s",
    header_chain.header_tip_height,
    header_chain.header_tip_hash and types.hash256_hex(header_chain.header_tip_hash) or "none"
  ))

  -- Initialize mempool
  local mempool = mempool_mod.new(chain_state, {
    max_mempool_size = 300 * 1024 * 1024,
    min_relay_fee = 1000,
  })

  -- Initialize fee estimator
  local fee_estimator = fee_mod.new(144)

  -- Initialize peer manager
  local peer_manager = peerman_mod.new(network, db, {
    maxpeers = args.maxpeers,
    max_outbound = 8,
  })
  peer_manager.our_height = header_chain.header_tip_height

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
    end
  end)

  peer_manager:register_handler("block", function(_peer, _payload)
    -- Handle during IBD (block downloader) or normal operation
    -- Block handling is done via the block downloader for IBD
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
    for _, item in ipairs(items) do
      if item.type == p2p.INV_TYPE.MSG_WITNESS_TX or item.type == p2p.INV_TYPE.MSG_TX then
        local txid_hex = types.hash256_hex(item.hash)
        local entry = mempool:get_entry(txid_hex)
        if entry then
          local data = serialize.serialize_transaction(entry.tx, true)
          peer:send_message("tx", data)
        end
      end
    end
  end)

  -- Peer established callback: start sync
  peer_manager.callbacks.on_peer_established = function(peer)
    print(string.format("Peer established: %s:%d %s (height=%d)",
      peer.ip, peer.port, peer.user_agent, peer.start_height))
    if not header_chain.syncing and peer.start_height > header_chain.header_tip_height then
      header_chain:start_sync(peer)
    end
  end

  -- Initialize wallet
  local wallet = nil
  local wallet_path = datadir .. "/wallet.json"
  if not args.nowalletcreate then
    wallet = wallet_mod.load(wallet_path, network, db)
    if not wallet then
      print("Creating new wallet...")
      wallet = wallet_mod.create(network, db)
      wallet:save(wallet_path)
      print("Wallet created. First address: " .. wallet.addresses[1])
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
    wallet = wallet,
    mining = mining_mod,
  })
  rpc_server:start()

  -- Connect to specific peer if requested
  if args.connect then
    local ip, port_str = args.connect:match("^([^:]+):?(%d*)$")
    local connect_port = tonumber(port_str) or network.port
    peer_manager:connect_peer(ip, connect_port)
  end

  -- Start P2P listener
  peer_manager:start_listener("0.0.0.0", args.port)
  print(string.format("P2P listening on port %d", args.port))
  print(string.format("RPC listening on port %d", args.rpcport))

  -- Signal handling (graceful shutdown)
  local running = true

  -- Main event loop
  print("Entering main loop...")
  local last_status = 0
  while running do
    -- Process P2P
    peer_manager:tick()

    -- Process RPC
    rpc_server:tick()

    -- Periodic status update
    local now = socket.gettime()
    if now - last_status > 60 then
      local peers = peer_manager:get_established_peers()
      print(string.format("[%s] Height: %d | Peers: %d | Mempool: %d txs (%d bytes)",
        os.date("%Y-%m-%d %H:%M:%S"),
        header_chain.header_tip_height,
        #peers,
        mempool.tx_count,
        mempool.total_size
      ))
      last_status = now
    end

    -- Short sleep to avoid busy-waiting
    socket.sleep(0.05)
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
