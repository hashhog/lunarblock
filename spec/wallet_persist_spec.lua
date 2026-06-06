-- Regression tests for the wallet restart-persistence fix (sweep wa0fq5wtk).
--
-- Covers the four guarantees the fix must provide:
--   (1) ATOMIC + DURABLE save  — temp + fsync + rename, no torn / partial file,
--       no leftover .tmp.
--   (2) SAVE-ON-MUTATION       — a keypool advance (getnewaddress) is flushed
--       immediately, so a SIMULATED UNCLEAN restart (load from disk WITHOUT a
--       clean shutdown save) does not lose the advanced index.
--   (3) FAULT-TOLERANT LOAD    — a missing / truncated / corrupt / empty wallet
--       file MUST NOT raise; it is quarantined to .bak and (when available)
--       recovered from the crashed-save .tmp.
--   (4) last_synced_height round-trips so startup reconciles only the gap.

-- Custom loader for lunarblock modules (handles src/ directory layout).
local function setup_loader()
  local loaders = package.loaders or package.searchers
  table.insert(loaders, 2, function(module)
    local name = module:match("^lunarblock%.(.+)")
    if name then
      local filename = "src/" .. name .. ".lua"
      local f = io.open(filename)
      if f then
        f:close()
        return function() return dofile(filename) end
      end
    end
    return nil, "not found"
  end)
end

-- A deterministic, fixed 32-byte seed so from_seed() builds the same wallet
-- every time (the test asserts on derived addresses / indices).
local SEED = ("a"):rep(32)

local function read_file(path)
  local f = io.open(path, "rb")
  if not f then return nil end
  local data = f:read("*a")
  f:close()
  return data
end

local function write_file(path, data)
  local f = assert(io.open(path, "wb"))
  f:write(data)
  f:close()
end

local function file_exists(path)
  local f = io.open(path, "rb")
  if f then f:close(); return true end
  return false
end

describe("wallet restart persistence", function()
  local wallet
  local consensus
  local tmpdir
  local wpath

  setup(function()
    setup_loader()
    wallet = require("lunarblock.wallet")
    consensus = require("lunarblock.consensus")
  end)

  before_each(function()
    tmpdir = os.tmpname() .. "_wallet_persist"
    os.execute("rm -f " .. tmpdir .. "; mkdir -p " .. tmpdir)
    wpath = tmpdir .. "/wallet.json"
  end)

  after_each(function()
    if tmpdir then os.execute("rm -rf " .. tmpdir) end
  end)

  local function fresh_wallet()
    return wallet.from_seed(SEED, consensus.networks.regtest, nil)
  end

  it("saves atomically and round-trips through load", function()
    local w = fresh_wallet()
    w.last_synced_height = 12345
    local ok, err = w:save(wpath)
    assert.is_true(ok, tostring(err))

    -- No leftover temp file after a successful atomic save.
    assert.is_false(file_exists(wpath .. ".tmp"))
    assert.is_true(file_exists(wpath))

    local w2, lerr = wallet.load(wpath, consensus.networks.regtest, nil)
    assert.is_not_nil(w2, tostring(lerr))
    assert.are.equal(w.next_external_index, w2.next_external_index)
    assert.are.equal(12345, w2.last_synced_height)
    -- The remembered save path lets save-on-mutation re-flush.
    assert.are.equal(wpath, w2._save_path)
  end)

  it("flushes a keypool advance immediately (save-on-mutation)", function()
    local w = fresh_wallet()
    assert.is_true(w:save(wpath))
    local idx_before = w.next_external_index

    -- getnewaddress advances the external index. The fix flushes immediately,
    -- so the new index is on disk WITHOUT any explicit save() call.
    local addr = w:get_new_address()
    assert.is_string(addr)
    assert.are.equal(idx_before + 1, w.next_external_index)

    -- Reload straight from disk (NO clean shutdown save) — simulates an
    -- unclean restart right after handing out the address.
    local w2 = assert(wallet.load(wpath, consensus.networks.regtest, nil))
    assert.are.equal(idx_before + 1, w2.next_external_index,
      "keypool advance was lost on unclean restart")
  end)

  it("the SAME address is never re-issued across an unclean restart", function()
    -- This is the fund-loss scenario: hand out address A, crash, restart,
    -- request another address — it must NOT be A again.
    local w = fresh_wallet()
    assert.is_true(w:save(wpath))
    local addr_a = w:get_new_address()

    -- Unclean restart: reload from disk (no shutdown save).
    local w2 = assert(wallet.load(wpath, consensus.networks.regtest, nil))
    local addr_b = w2:get_new_address()

    assert.are_not.equal(addr_a, addr_b,
      "re-issued the same address after a crash → incoming funds unrecoverable")
  end)

  it("does NOT crash on a truncated / partially-written wallet file", function()
    local w = fresh_wallet()
    assert.is_true(w:save(wpath))
    local good = assert(read_file(wpath))

    -- Truncate the file to half (a torn write mid-flush).
    write_file(wpath, good:sub(1, math.max(1, math.floor(#good / 2))))

    -- Must return nil + err, NOT raise. pcall asserts the no-crash guarantee.
    local ok, ret, err = pcall(wallet.load, wpath, consensus.networks.regtest, nil)
    assert.is_true(ok, "wallet.load RAISED on a truncated file (must not crash)")
    assert.is_nil(ret)
    assert.is_not_nil(err)
    -- The corrupt file is quarantined for inspection.
    assert.is_true(file_exists(wpath .. ".bak"))
  end)

  it("does NOT crash on a garbage (non-JSON) wallet file", function()
    write_file(wpath, "this is not json at all \0\1\2 \xff")
    local ok, ret = pcall(wallet.load, wpath, consensus.networks.regtest, nil)
    assert.is_true(ok, "wallet.load RAISED on garbage (must not crash)")
    assert.is_nil(ret)
    assert.is_true(file_exists(wpath .. ".bak"))
  end)

  it("does NOT crash on an empty wallet file", function()
    write_file(wpath, "")
    local ok, ret = pcall(wallet.load, wpath, consensus.networks.regtest, nil)
    assert.is_true(ok, "wallet.load RAISED on an empty file (must not crash)")
    assert.is_nil(ret)
  end)

  it("recovers from a crashed-save .tmp when the live file is corrupt", function()
    -- Simulate: save() wrote <path>.tmp fully, then crashed before rename, AND
    -- the prior live file got truncated. The loader must recover from .tmp.
    local w = fresh_wallet()
    w.last_synced_height = 777
    -- Build a valid serialization and place it at the .tmp path.
    assert.is_true(w:save(wpath))
    local good = assert(read_file(wpath))
    write_file(wpath .. ".tmp", good)
    -- Corrupt the live file.
    write_file(wpath, "{ broken")

    local w2, lerr = wallet.load(wpath, consensus.networks.regtest, nil)
    assert.is_not_nil(w2, "did not recover from crashed-save temp file: " .. tostring(lerr))
    assert.are.equal(777, w2.last_synced_height)
    -- The recovered temp was promoted into place; the corrupt original is .bak.
    assert.is_true(file_exists(wpath .. ".bak"))
    assert.is_false(file_exists(wpath .. ".tmp"))
  end)

  it("save_if_dirty is a no-op when clean and flushes when dirty", function()
    local w = fresh_wallet()
    assert.is_true(w:save(wpath))           -- clears dirty
    assert.is_false(w._dirty)
    -- No-op: returns true, writes nothing new (file unchanged is acceptable).
    assert.is_true(w:save_if_dirty())

    w:mark_dirty()
    assert.is_true(w._dirty)
    assert.is_true(w:save_if_dirty())
    assert.is_false(w._dirty)               -- cleared after flush
  end)

  it("scan_block advances last_synced_height and marks dirty", function()
    local w = fresh_wallet()
    w:save(wpath)
    w._dirty = false
    -- An empty / irrelevant block still moves the reconciled height forward.
    local block = { transactions = {} }
    w:scan_block(nil, block, 500, nil)
    assert.are.equal(500, w.last_synced_height)
    assert.is_true(w._dirty)
    -- Height never regresses.
    w:scan_block(nil, block, 499, nil)
    assert.are.equal(500, w.last_synced_height)
  end)
end)
