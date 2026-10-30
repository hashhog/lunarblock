-- spec/tmp_leak_spec.lua
--
-- The txospenderindex and deep-reorg specs open a RocksDB under /tmp and used
-- to leave it there: ~4 GB/day on maxbox's RAM-backed /tmp (ops audit
-- 2026-10-25, finding 19).  Run each spec in a child busted and require that
-- no new lunarblock_txospender_* / lunarblock_deepreorg_* entry survives.

local PREFIXES = { "lunarblock_txospender_", "lunarblock_deepreorg_" }

local function snapshot()
  local set = {}
  local p = io.popen("ls -1A /tmp 2>/dev/null")
  for name in p:lines() do
    for _, pre in ipairs(PREFIXES) do
      if name:sub(1, #pre) == pre then set[name] = true end
    end
  end
  p:close()
  return set
end

local function leaked_by(spec_file)
  local before = snapshot()
  local rc = os.execute("busted --lua=luajit --helper=spec/known_red_helper.lua "
    .. "--pattern=_spec " .. spec_file .. " >/dev/null 2>&1")
  local after, leaked = snapshot(), {}
  for name in pairs(after) do
    if not before[name] then leaked[#leaked + 1] = name end
  end
  table.sort(leaked)
  return rc, leaked
end

describe("test scratch cleanup", function()
  for _, spec_file in ipairs({
    "spec/txospenderindex_spec.lua",
    "spec/deep_reorg_unbounded_spec.lua",
  }) do
    it(spec_file .. " leaves nothing in /tmp", function()
      local rc, leaked = leaked_by(spec_file)
      assert.is_true(rc == true or rc == 0, "child busted run failed")
      assert.are.same({}, leaked)
      for _, name in ipairs(leaked) do
        os.execute("rm -rf -- '/tmp/" .. name .. "'")
      end
    end)
  end
end)
