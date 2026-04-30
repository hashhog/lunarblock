package = "lunarblock"
version = "scm-1"
rockspec_format = "3.0"
source = {
  url = "git+https://github.com/user/lunarblock.git"
}
description = {
  summary = "A Bitcoin full node implementation in Lua targeting LuaJIT 2.1",
  license = "MIT"
}
dependencies = {
  "lua >= 5.1",
  "luasocket >= 3.1.0",
  "lua-cjson >= 2.1.0",
}
test_dependencies = {
  "busted >= 2.1.0",
  "luacheck >= 1.1.0",
  "luafilesystem >= 1.8.0",
}
build = {
  type = "builtin",
  modules = {
    ["lunarblock.main"] = "src/main.lua",
    ["lunarblock.types"] = "src/types.lua",
    ["lunarblock.serialize"] = "src/serialize.lua",
    ["lunarblock.crypto"] = "src/crypto.lua",
    ["lunarblock.address"] = "src/address.lua",
    ["lunarblock.script"] = "src/script.lua",
    ["lunarblock.consensus"] = "src/consensus.lua",
    ["lunarblock.storage"] = "src/storage.lua",
    ["lunarblock.validation"] = "src/validation.lua",
    ["lunarblock.p2p"] = "src/p2p.lua",
    ["lunarblock.peer"] = "src/peer.lua",
    ["lunarblock.peerman"] = "src/peerman.lua",
    ["lunarblock.sync"] = "src/sync.lua",
    ["lunarblock.mempool"] = "src/mempool.lua",
    ["lunarblock.mining"] = "src/mining.lua",
    ["lunarblock.rpc"] = "src/rpc.lua",
    ["lunarblock.wallet"] = "src/wallet.lua",
    ["lunarblock.utxo"] = "src/utxo.lua",
    ["lunarblock.fee"] = "src/fee.lua",
    ["lunarblock.perf"] = "src/perf.lua",
    ["lunarblock.prune"] = "src/prune.lua",
    ["lunarblock.ops"] = "src/ops.lua",
    ["lunarblock.sha256_accel"] = {
      sources = {"csrc/sha256_accel.c"},
      libraries = {"crypto"},
      incdirs = {"/usr/include"},
      libdirs = {"/usr/lib64", "/usr/lib"},
    },
    ["lunarblock.parallel_verify"] = {
      sources = {"csrc/parallel_verify.c"},
      libraries = {"secp256k1", "pthread"},
      incdirs = {"/usr/include"},
      libdirs = {"/usr/lib64", "/usr/lib", "./lib"},
    },
  },
  install = {
    bin = {
      lunarblock = "src/main.lua"
    }
  }
}
