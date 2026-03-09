-- Tests for main.lua CLI and argument parsing

describe("main module", function()
  local main

  setup(function()
    main = require("lunarblock.main")
  end)

  describe("VERSION", function()
    it("exports version string", function()
      assert.is_string(main.VERSION)
      assert.matches("^%d+%.%d+%.%d+$", main.VERSION)
    end)
  end)

  describe("parse_args", function()
    it("returns default values with empty arguments", function()
      local args = main.parse_args({})
      assert.equal("mainnet", args.network)
      assert.equal(125, args.maxpeers)
      assert.equal(450, args.dbcache)
      assert.equal("lunarblock", args.rpcuser)
      assert.equal("", args.rpcpassword)
      assert.is_false(args.testnet)
      assert.is_false(args.regtest)
      assert.is_false(args.printtoconsole)
      assert.is_false(args.nowalletcreate)
      assert.is_false(args.reindex)
      assert.is_false(args.daemon)
      assert.is_nil(args.connect)
    end)

    it("parses --testnet flag", function()
      local args = main.parse_args({"--testnet"})
      assert.is_true(args.testnet)
      assert.is_false(args.regtest)
    end)

    it("parses --regtest flag", function()
      local args = main.parse_args({"--regtest"})
      assert.is_true(args.regtest)
      assert.is_false(args.testnet)
    end)

    it("parses -n/--network option", function()
      local args = main.parse_args({"-n", "testnet"})
      assert.equal("testnet", args.network)

      args = main.parse_args({"--network", "regtest"})
      assert.equal("regtest", args.network)
    end)

    it("parses -d/--datadir option", function()
      local args = main.parse_args({"-d", "/tmp/testdata"})
      assert.equal("/tmp/testdata", args.datadir)

      args = main.parse_args({"--datadir", "/var/lib/lunarblock"})
      assert.equal("/var/lib/lunarblock", args.datadir)
    end)

    it("parses --rpcport option", function()
      local args = main.parse_args({"--rpcport", "18443"})
      assert.equal(18443, args.rpcport)
    end)

    it("parses --rpcuser option", function()
      local args = main.parse_args({"--rpcuser", "admin"})
      assert.equal("admin", args.rpcuser)
    end)

    it("parses --rpcpassword option", function()
      local args = main.parse_args({"--rpcpassword", "secret123"})
      assert.equal("secret123", args.rpcpassword)
    end)

    it("parses --port option", function()
      local args = main.parse_args({"--port", "18444"})
      assert.equal(18444, args.port)
    end)

    it("parses --maxpeers option", function()
      local args = main.parse_args({"--maxpeers", "50"})
      assert.equal(50, args.maxpeers)
    end)

    it("parses --dbcache option", function()
      local args = main.parse_args({"--dbcache", "1024"})
      assert.equal(1024, args.dbcache)
    end)

    it("parses --connect option", function()
      local args = main.parse_args({"--connect", "192.168.1.1:8333"})
      assert.equal("192.168.1.1:8333", args.connect)
    end)

    it("parses --printtoconsole flag", function()
      local args = main.parse_args({"--printtoconsole"})
      assert.is_true(args.printtoconsole)
    end)

    it("parses --nowalletcreate flag", function()
      local args = main.parse_args({"--nowalletcreate"})
      assert.is_true(args.nowalletcreate)
    end)

    it("parses --reindex flag", function()
      local args = main.parse_args({"--reindex"})
      assert.is_true(args.reindex)
    end)

    it("parses --daemon flag", function()
      local args = main.parse_args({"--daemon"})
      assert.is_true(args.daemon)
    end)

    it("handles multiple options", function()
      local args = main.parse_args({
        "--testnet",
        "--datadir", "/tmp/test",
        "--maxpeers", "25",
        "--rpcport", "18332",
        "--nowalletcreate",
        "--printtoconsole"
      })
      assert.is_true(args.testnet)
      assert.equal("/tmp/test", args.datadir)
      assert.equal(25, args.maxpeers)
      assert.equal(18332, args.rpcport)
      assert.is_true(args.nowalletcreate)
      assert.is_true(args.printtoconsole)
    end)

    it("has default datadir based on HOME", function()
      local args = main.parse_args({})
      local home = os.getenv("HOME")
      assert.equal(home .. "/.lunarblock", args.datadir)
    end)
  end)

  describe("module loading", function()
    it("all required modules can be loaded", function()
      -- Test that all modules referenced in main.lua can be loaded
      local modules = {
        "lunarblock.types",
        "lunarblock.serialize",
        "lunarblock.crypto",
        "lunarblock.address",
        "lunarblock.script",
        "lunarblock.consensus",
        "lunarblock.storage",
        "lunarblock.validation",
        "lunarblock.p2p",
        "lunarblock.peer",
        "lunarblock.peerman",
        "lunarblock.sync",
        "lunarblock.utxo",
        "lunarblock.mempool",
        "lunarblock.fee",
        "lunarblock.mining",
        "lunarblock.rpc",
        "lunarblock.wallet",
      }

      for _, mod_name in ipairs(modules) do
        local ok, mod = pcall(require, mod_name)
        assert.is_true(ok, "Failed to load module: " .. mod_name .. " - " .. tostring(mod))
        assert.is_table(mod)
      end
    end)
  end)

  describe("network data directory structure", function()
    it("mainnet uses base datadir", function()
      local args = main.parse_args({"-d", "/data", "-n", "mainnet"})
      assert.equal("mainnet", args.network)
      -- Note: actual datadir modification happens in main() not parse_args()
      assert.equal("/data", args.datadir)
    end)

    it("testnet should create subdirectory", function()
      local args = main.parse_args({"-d", "/data", "--testnet"})
      -- The --testnet flag is parsed, network override happens in main()
      assert.is_true(args.testnet)
    end)

    it("regtest should create subdirectory", function()
      local args = main.parse_args({"-d", "/data", "--regtest"})
      -- The --regtest flag is parsed, network override happens in main()
      assert.is_true(args.regtest)
    end)
  end)

  describe("exports", function()
    it("exports main function", function()
      assert.is_function(main.main)
    end)

    it("exports parse_args function", function()
      assert.is_function(main.parse_args)
    end)
  end)
end)
