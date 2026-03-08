#!/usr/bin/env luajit
-- LunarBlock - Bitcoin full node in Lua

local VERSION = "0.1.0"

-- Minimal argument parser
local function parse_args(argv)
  local args = {
    datadir = os.getenv("HOME") .. "/.lunarblock",
    network = "mainnet",
    rpcport = 8332,
    rpcuser = "lunarblock",
    rpcpassword = "",
    port = 8333,
    maxpeers = 125,
    dbcache = 450,
    testnet = false,
    regtest = false,
    printtoconsole = false,
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
      print("  -d, --datadir DIR     Data directory (default: ~/.lunarblock)")
      print("  -n, --network NET     Network: mainnet, testnet, regtest (default: mainnet)")
      print("      --rpcport PORT    RPC server port (default: 8332)")
      print("      --rpcuser USER    RPC username (default: lunarblock)")
      print("      --rpcpassword PW  RPC password")
      print("      --port PORT       P2P listen port (default: 8333)")
      print("      --maxpeers N      Maximum peer connections (default: 125)")
      print("      --dbcache MB      Database cache size in MB (default: 450)")
      print("      --testnet         Use testnet")
      print("      --regtest         Use regtest")
      print("      --printtoconsole  Print log to console")
      print("      --version         Print version and exit")
      print("  -h, --help            Show this help message")
      os.exit(0)
    elseif arg == "--version" then
      print("LunarBlock v" .. VERSION)
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
    elseif arg == "--testnet" then
      args.testnet = true
    elseif arg == "--regtest" then
      args.regtest = true
    elseif arg == "--printtoconsole" then
      args.printtoconsole = true
    else
      io.stderr:write("Unknown option: " .. arg .. "\n")
      os.exit(1)
    end
    i = i + 1
  end

  return args
end

local args = parse_args(arg)

-- Override network from flags
if args.testnet then args.network = "testnet" end
if args.regtest then args.network = "regtest" end

print("LunarBlock v" .. VERSION .. " starting...")
print("Network: " .. args.network)
print("Data directory: " .. args.datadir)
