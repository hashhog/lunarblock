-- Durability model of src/storage.lua (see the "Durability model" block in
-- M.open): by default writes go to memtables only (no WAL) and durability
-- comes from atomic flushes of every column family; LUNARBLOCK_DB_WAL=1 /
-- open_opts.wal=true keeps the legacy WAL behaviour.
--
-- Crash simulation: a CHILD luajit process opens the DB, writes, and then
-- SIGKILLs itself (no close, no destructors), exactly like an OOM kill or
-- `kill -9`.  The parent then reopens the datadir and checks which state
-- survived.  What must hold in checkpoint mode:
--   * everything up to the last checkpoint(true)/sync=true write survives;
--   * writes after it are lost AS A UNIT -- a later multi-CF batch never
--     survives partially (chain_tip agrees with the UTXO/undo keys);
--   * a clean close() makes everything durable.
-- And in legacy WAL mode an unsynced write survives a process kill (the WAL
-- is in the page cache), which is the behaviour the mode switch preserves.

describe("storage durability model", function()
  local storage

  local function make_temp_dir()
    local tmpname = os.tmpname()
    os.remove(tmpname)
    os.execute("mkdir -p " .. tmpname)
    return tmpname
  end

  local function remove_dir(path)
    os.execute("rm -rf " .. path)
  end

  -- Run `body` (Lua source) in a child luajit that has `db` open on `path`
  -- with open_opts `opts_src`; the child SIGKILLs itself at the end.
  -- Returns the exit status reported by os.execute.
  local function run_child_and_crash(path, opts_src, body)
    local script = path .. "/child.lua"
    local f = assert(io.open(script, "w"))
    f:write([[
local ffi = require("ffi")
ffi.cdef("int kill(int pid, int sig); int getpid(void);")
local storage = require("lunarblock.storage")
local db = storage.open(]] .. string.format("%q", path .. "/chainstate") .. [[, 16, ]] .. opts_src .. [[)
]] .. body .. [[

io.stdout:flush()
ffi.C.kill(ffi.C.getpid(), 9)
]])
    f:close()
    return os.execute("luajit " .. script .. " >/dev/null 2>&1")
  end

  setup(function()
    storage = require("lunarblock.storage")
  end)

  it("defaults to the checkpoint (no-WAL) model and exposes checkpoint()", function()
    local path = make_temp_dir()
    local db = storage.open(path .. "/chainstate", 16)
    if os.getenv("LUNARBLOCK_DB_WAL") == "1" then
      assert.is_true(db.wal_enabled)
    else
      assert.is_false(db.wal_enabled)
    end
    assert.is_function(db.checkpoint)
    db.close()
    remove_dir(path)
  end)

  it("checkpoint mode: a crash rolls back to the last checkpoint, never to a partial batch", function()
    local path = make_temp_dir()
    run_child_and_crash(path, "{ wal = false }", [[
local CF = storage.CF
-- state 1, made durable explicitly
local b = db.batch()
b.put(CF.UTXO, "coinA", "v1")
b.put(CF.UNDO, "undo1", "u1")
b.put(CF.META, "chain_tip", "tip1")
b.write(false)
db.checkpoint(true)
-- state 2: one multi-CF batch, NOT checkpointed
local b2 = db.batch()
b2.put(CF.UTXO, "coinA", "v2")
b2.delete(CF.UTXO, "coinZ")
b2.put(CF.UNDO, "undo2", "u2")
b2.put(CF.BLOCKS, "blk2", string.rep("x", 8192))
b2.put(CF.META, "chain_tip", "tip2")
b2.write(false)
]])
    local db = storage.open(path .. "/chainstate", 16, { wal = false })
    assert.are.equal("tip1", db.get(storage.CF.META, "chain_tip"))
    assert.are.equal("v1", db.get(storage.CF.UTXO, "coinA"))
    assert.are.equal("u1", db.get(storage.CF.UNDO, "undo1"))
    assert.is_nil(db.get(storage.CF.UNDO, "undo2"))
    assert.is_nil(db.get(storage.CF.BLOCKS, "blk2"))
    db.close()
    remove_dir(path)
  end)

  it("checkpoint mode: sync=true writes are durable when they return", function()
    local path = make_temp_dir()
    run_child_and_crash(path, "{ wal = false }", [[
local CF = storage.CF
db.put(CF.META, "k_sync", "durable", true)
local b = db.batch()
b.put(CF.UTXO, "c1", "x")
b.put(CF.META, "chain_tip", "tipS")
b.write(true)
db.put(CF.META, "k_nosync", "volatile", false)
]])
    local db = storage.open(path .. "/chainstate", 16, { wal = false })
    assert.are.equal("durable", db.get(storage.CF.META, "k_sync"))
    assert.are.equal("tipS", db.get(storage.CF.META, "chain_tip"))
    assert.are.equal("x", db.get(storage.CF.UTXO, "c1"))
    assert.is_nil(db.get(storage.CF.META, "k_nosync"))
    db.close()
    remove_dir(path)
  end)

  it("checkpoint mode: a non-blocking checkpoint becomes durable once the flush finishes", function()
    local path = make_temp_dir()
    run_child_and_crash(path, "{ wal = false }", [[
local CF = storage.CF
local b = db.batch()
b.put(CF.UTXO, "c1", "y")
b.put(CF.META, "chain_tip", "tipN")
b.write(false)
db.checkpoint(false)
-- wait (bounded) for the scheduled flush to finish before crashing
local socket = require("socket")
for _ = 1, 500 do
  if db.property("rocksdb.num-running-flushes") == "0"
     and db.property("rocksdb.mem-table-flush-pending") == "0"
     and db.property("rocksdb.num-immutable-mem-table") == "0" then break end
  socket.sleep(0.01)
end
]])
    local db = storage.open(path .. "/chainstate", 16, { wal = false })
    assert.are.equal("tipN", db.get(storage.CF.META, "chain_tip"))
    assert.are.equal("y", db.get(storage.CF.UTXO, "c1"))
    db.close()
    remove_dir(path)
  end)

  it("checkpoint mode: close() makes all writes durable", function()
    local path = make_temp_dir()
    local db = storage.open(path .. "/chainstate", 16, { wal = false })
    local b = db.batch()
    b.put(storage.CF.UTXO, "c9", "z")
    b.put(storage.CF.META, "chain_tip", "tipC")
    b.write(false)
    db.close()
    local db2 = storage.open(path .. "/chainstate", 16, { wal = false })
    assert.are.equal("tipC", db2.get(storage.CF.META, "chain_tip"))
    assert.are.equal("z", db2.get(storage.CF.UTXO, "c9"))
    db2.close()
    remove_dir(path)
  end)

  it("legacy WAL mode: an unsynced write survives a process kill", function()
    local path = make_temp_dir()
    run_child_and_crash(path, "{ wal = true }", [[
local CF = storage.CF
local b = db.batch()
b.put(CF.UTXO, "cw", "wal")
b.put(CF.META, "chain_tip", "tipW")
b.write(false)
]])
    local db = storage.open(path .. "/chainstate", 16, { wal = true })
    assert.are.equal("tipW", db.get(storage.CF.META, "chain_tip"))
    assert.are.equal("wal", db.get(storage.CF.UTXO, "cw"))
    db.close()
    remove_dir(path)
  end)

  it("a datadir written in one mode opens and reads correctly in the other", function()
    local path = make_temp_dir()
    -- legacy WAL mode, crash (data only in the WAL) ...
    run_child_and_crash(path, "{ wal = true }", [[
db.put(storage.CF.META, "chain_tip", "tipX", false)
]])
    -- ... then checkpoint mode must replay that WAL on open
    local db = storage.open(path .. "/chainstate", 16, { wal = false })
    assert.are.equal("tipX", db.get(storage.CF.META, "chain_tip"))
    db.put(storage.CF.META, "chain_tip", "tipY", false)
    db.close()
    local db2 = storage.open(path .. "/chainstate", 16, { wal = true })
    assert.are.equal("tipY", db2.get(storage.CF.META, "chain_tip"))
    db2.close()
    remove_dir(path)
  end)

  it("block bodies are stored in blob files and read back byte-identical", function()
    local path = make_temp_dir()
    local db = storage.open(path .. "/chainstate", 16)
    local body = {}
    for i = 1, 20000 do body[i] = string.char(i % 251) end
    body = table.concat(body)
    db.put(storage.CF.BLOCKS, "blkhash", body)
    db.put(storage.CF.BLOCKS, "tiny", "abc")  -- below min_blob_size: stays inline
    db.flush(true)  -- memtable -> SST/blob in either durability mode
    db.close()
    local p = io.popen("ls " .. path .. "/chainstate | grep -c '\\.blob$'")
    local nblob = tonumber(p:read("*a")); p:close()
    assert.is_true(nblob >= 1, "expected at least one .blob file")
    local db2 = storage.open(path .. "/chainstate", 16)
    assert.are.equal(body, db2.get(storage.CF.BLOCKS, "blkhash"))
    assert.are.equal("abc", db2.get(storage.CF.BLOCKS, "tiny"))
    local it = db2.iterator(storage.CF.BLOCKS)
    it.seek("blkhash")
    assert.is_true(it.valid())
    assert.are.equal(body, it.value())
    it.destroy()
    db2.close()
    remove_dir(path)
  end)
end)
