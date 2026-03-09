package = "lunarblock"
version = "scm-1"
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
  },
  install = {
    bin = {
      lunarblock = "src/main.lua"
    }
  }
}
