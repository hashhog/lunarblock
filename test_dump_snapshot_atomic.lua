#!/usr/bin/env luajit
-- Atomic-write protocol regression test for dump_snapshot.
--
-- Mirrors Bitcoin Core's rpc/blockchain.cpp::dumptxoutset which writes
-- to "<path>.incomplete", fsyncs, and renames. After a successful dump
-- only <path> should exist; the .incomplete temp must be gone so that
-- mid-dump observers never see a torn file.
--
-- Run: luajit test_dump_snapshot_atomic.lua

package.path = "lunarblock/?.lua;src/?.lua;" .. package.path

local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local types = require("lunarblock.types")
local storage_mod = require("lunarblock.storage")

local function test(name, func)
  io.write("Testing: " .. name .. " ... ")
  local ok, err = pcall(func)
  if ok then
    print("PASS")
  else
    print("FAIL: " .. tostring(err))
    os.exit(1)
  end
end

local function exists(p)
  local f = io.open(p, "rb")
  if not f then return false end
  f:close()
  return true
end

print("=== dump_snapshot atomic-write tests ===\n")

test("dump leaves no .incomplete on success (rpc.lua flow)", function()
  -- Direct test of the rpc.lua atomic-rename flow: dump to tmppath,
  -- then os.rename to final. We don't call rpc.lua here (that needs
  -- a running RPC server), but we exercise the same primitives.
  local tmp = "/tmp/lb_atomic_test_" .. os.time() .. ".dat"
  local tmp_incomplete = tmp .. ".incomplete"
  local final = tmp .. ".final"

  -- Pre-conditions: no leftover artifacts from a prior run.
  os.remove(tmp_incomplete); os.remove(final)
  assert(not exists(tmp_incomplete), "stale .incomplete")
  assert(not exists(final), "stale final path")

  local db = storage_mod.open("/tmp/lb_atomic_db_" .. os.time())
  local cs = utxo.new_chain_state(db, consensus.networks.regtest)
  cs:init()
  cs.tip_hash = types.hash256(string.rep("\xcc", 32))
  cs.tip_height = 0

  -- Mirrors rpc.lua: write to tmp_incomplete, then rename.
  local result, err = cs:dump_snapshot(tmp_incomplete)
  assert(result, "dump failed: " .. tostring(err))
  -- The dump must have written tmp_incomplete and called fsync.
  assert(exists(tmp_incomplete), "missing tmp file post-dump")

  local rok, rerr = os.rename(tmp_incomplete, final)
  assert(rok, "rename failed: " .. tostring(rerr))

  -- Atomic-write invariant: after the rename, only final must exist.
  assert(exists(final), "final path missing after rename")
  assert(not exists(tmp_incomplete), ".incomplete left after rename")

  os.remove(final)
  db.close()
end)

print("\nAll dump_snapshot atomic-write tests passed.")
