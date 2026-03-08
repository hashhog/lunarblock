package = "lunarblock"
version = "scm-1"
source = {
  url = "git://github.com/hashhog/lunarblock.git"
}
description = {
  summary = "Bitcoin full node in Lua (LuaJIT)",
  license = "MIT"
}
dependencies = {
  "lua >= 5.1",
  "luasocket",
  "cjson",
  "busted",
}
build = {
  type = "builtin",
  modules = {
    ["lunarblock"] = "src/init.lua",
  }
}
