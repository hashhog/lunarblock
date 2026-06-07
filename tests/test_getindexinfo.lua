#!/usr/bin/env luajit
-- getindexinfo Core-shape parity regression — lunarblock (Lua / LuaJIT)
--
-- Reference: bitcoin-core/src/rpc/node.cpp:363-410 (getindexinfo)
--            bitcoin-core/src/rpc/node.cpp:351-361 (SummaryToJSON)
--            bitcoin-core/src/index/base.cpp:472-484 (GetSummary)
--
-- The handler already exists (src/rpc.lua:2042) and is Core-correct; this
-- file is the missing regression test.  Core's getindexinfo returns a dynamic
-- JSON OBJECT keyed BY INDEX NAME.  Each value is EXACTLY two keys in THIS
-- ORDER:
--   synced            BOOL
--   best_block_height INTEGER
-- No best_hash / best_block_hash / nested name.  Index names are the literal
-- GetName() strings ("txindex", "basic block filter index", ...).  Only
-- ENABLED indexes appear.  Optional positional index_name filters; an unknown
-- name yields {} (empty object, NOT an error); empty/omitted -> all running.
--
-- Because cjson does NOT preserve key order, the handler builds the JSON by
-- hand and returns {_raw_json=<string>}; the dispatcher splices it in.  This
-- test asserts BOTH the decoded values AND the literal byte order of the keys.
--
-- Gate map:
--   G1  both indexes enabled -> exactly 2 keys (txindex, basic block filter index)
--   G2  per-entry shape: EXACTLY {synced, best_block_height}, correct types/values
--   G3  raw-JSON value key ORDER is synced before best_block_height
--   G4  only txindex enabled -> only "txindex" key
--   G5  no indexes enabled -> empty object, raw == "{}"
--   G6  filter params:["txindex"] with both enabled -> only "txindex"
--   G7  unknown name -> {} (NOT an error; raw == "{}")
--   G8  non-string index_name -> error -32602 'index_name must be a string'
--   G9  Core index ORDER: txindex emitted before basic block filter index

package.path = "src/?.lua;src/?/init.lua;" .. package.path

local rpc       = require("lunarblock.rpc")
local cjson     = require("cjson")
local consensus = require("lunarblock.consensus")

-- ---------------------------------------------------------------------------
-- Test scaffolding (mirrors tests/test_getnodeaddresses.lua)
-- ---------------------------------------------------------------------------

local PASS, FAIL = 0, 0

local function pass(name)
  io.write(string.format("  PASS  %s\n", name))
  PASS = PASS + 1
end

local function fail(name, msg)
  io.write(string.format("  FAIL  %s -- %s\n", name, msg))
  FAIL = FAIL + 1
end

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) ..
          ", expected " .. tostring(b), 2)
  end
end

local function expect_true(cond, msg)
  if not cond then error(msg or "expected true", 2) end
end

-- Build an RPCServer with injected chain_state / header_chain.  The handler
-- only reads plain fields (tip_height, txindex_enabled, filterindex_enabled,
-- header_tip_height), so plain tables are sufficient; no real ChainState or
-- storage is constructed.  `storage` is left nil so the filter index falls
-- back to the chain tip for its best height (matches genesis-only behavior).
local function build_server(opts)
  opts = opts or {}
  return rpc.new({
    network     = consensus.networks.regtest,
    chain_state = {
      tip_height        = opts.tip_height or 0,
      txindex_enabled   = opts.txindex and true or false,
      filterindex_enabled = opts.filterindex and true or false,
    },
    header_chain = {
      header_tip_height = opts.header_tip_height
                          or opts.tip_height or 0,
    },
  })
end

-- Invoke the handler directly; returns ok, result-or-err.
local function call_gii(server, params)
  local handler = server.methods["getindexinfo"]
  if not handler then error("getindexinfo not registered", 2) end
  return pcall(handler, server, params)
end

-- Decode a successful {_raw_json=...} result into a Lua table.
local function decode(result)
  expect_true(type(result) == "table", "result must be a table")
  expect_true(type(result._raw_json) == "string",
              "result must carry a _raw_json string")
  return cjson.decode(result._raw_json), result._raw_json
end

local FILTER_NAME = "basic block filter index"

print("\n=========================================================================")
print("getindexinfo Core-shape parity — lunarblock")
print("Handler: src/rpc.lua:2042   Ref: bitcoin-core/src/rpc/node.cpp:363-410")
print("=========================================================================\n")

-- ---------------------------------------------------------------------------
-- G1: both indexes enabled -> exactly 2 keys
-- ---------------------------------------------------------------------------
test("G1: both indexes enabled -> exactly 2 keys (txindex, filter index)", function()
  local N = 1500
  local server = build_server({
    txindex = true, filterindex = true,
    tip_height = N, header_tip_height = N,
  })
  local ok, result = call_gii(server, {})
  expect_true(ok, "call failed: " .. tostring(result))
  local obj = decode(result)

  local nkeys = 0
  for _ in pairs(obj) do nkeys = nkeys + 1 end
  expect_eq(nkeys, 2, "top-level key count")
  expect_true(obj["txindex"] ~= nil, "missing txindex key")
  expect_true(obj[FILTER_NAME] ~= nil, "missing filter index key")
end)

-- ---------------------------------------------------------------------------
-- G2: per-entry shape EXACTLY {synced, best_block_height} + types/values
-- ---------------------------------------------------------------------------
test("G2: per-entry shape is exactly {synced, best_block_height}", function()
  local N = 2024
  local server = build_server({
    txindex = true, filterindex = true,
    tip_height = N, header_tip_height = N,
  })
  local ok, result = call_gii(server, {})
  expect_true(ok, "call failed: " .. tostring(result))
  local obj = decode(result)

  for _, name in ipairs({ "txindex", FILTER_NAME }) do
    local e = obj[name]
    expect_true(type(e) == "table", name .. " value must be an object")

    -- EXACTLY 2 keys, no best_hash / best_block_hash / name.
    local nk = 0
    for _ in pairs(e) do nk = nk + 1 end
    expect_eq(nk, 2, name .. " entry key count")
    expect_true(e.synced ~= nil, name .. " missing synced")
    expect_true(e.best_block_height ~= nil, name .. " missing best_block_height")
    expect_true(e.best_hash == nil, name .. " must NOT carry best_hash")
    expect_true(e.best_block_hash == nil, name .. " must NOT carry best_block_hash")
    expect_true(e.name == nil, name .. " must NOT carry nested name")

    -- Types: synced BOOL, best_block_height INTEGER.
    expect_eq(type(e.synced), "boolean", name .. " synced type")
    expect_eq(type(e.best_block_height), "number",
              name .. " best_block_height type")
    expect_eq(e.best_block_height, math.floor(e.best_block_height),
              name .. " best_block_height is integral")
  end

  -- Values: tip caught the header tip -> both synced; heights at tip.
  expect_eq(obj["txindex"].synced, true, "txindex synced when tip==header tip")
  expect_eq(obj["txindex"].best_block_height, N, "txindex best height")
  expect_eq(obj[FILTER_NAME].synced, true, "filter synced when at tip")
  expect_eq(obj[FILTER_NAME].best_block_height, N, "filter best height")
end)

-- ---------------------------------------------------------------------------
-- G3: raw-JSON value key ORDER is synced before best_block_height
-- cjson would reorder a decoded table, so assert on the literal string.
-- ---------------------------------------------------------------------------
test("G3: raw-JSON key order is synced before best_block_height", function()
  local server = build_server({
    txindex = true, filterindex = true,
    tip_height = 10, header_tip_height = 10,
  })
  local ok, result = call_gii(server, {})
  expect_true(ok, "call failed: " .. tostring(result))
  local _, raw = decode(result)

  local p_synced = raw:find('"synced"', 1, true)
  local p_height = raw:find('"best_block_height"', 1, true)
  expect_true(p_synced, "synced key present in raw JSON")
  expect_true(p_height, "best_block_height key present in raw JSON")
  expect_true(p_synced < p_height, "synced must precede best_block_height")
end)

-- ---------------------------------------------------------------------------
-- G4: only txindex enabled -> only "txindex" key
-- ---------------------------------------------------------------------------
test("G4: only txindex enabled -> only txindex key", function()
  local server = build_server({
    txindex = true, filterindex = false,
    tip_height = 42, header_tip_height = 42,
  })
  local ok, result = call_gii(server, {})
  expect_true(ok, "call failed: " .. tostring(result))
  local obj = decode(result)
  local nkeys = 0
  for _ in pairs(obj) do nkeys = nkeys + 1 end
  expect_eq(nkeys, 1, "only one index enabled")
  expect_true(obj["txindex"] ~= nil, "txindex key present")
  expect_true(obj[FILTER_NAME] == nil, "filter index absent when disabled")
end)

-- ---------------------------------------------------------------------------
-- G5: no indexes enabled -> empty object, raw == "{}"
-- ---------------------------------------------------------------------------
test("G5: no indexes enabled -> empty object {}", function()
  local server = build_server({
    txindex = false, filterindex = false,
    tip_height = 100, header_tip_height = 100,
  })
  local ok, result = call_gii(server, {})
  expect_true(ok, "call failed: " .. tostring(result))
  local obj, raw = decode(result)
  local nkeys = 0
  for _ in pairs(obj) do nkeys = nkeys + 1 end
  expect_eq(nkeys, 0, "no enabled indexes")
  expect_eq(raw, "{}", "raw JSON must be the empty object")
end)

-- ---------------------------------------------------------------------------
-- G6: filter params:["txindex"] with both enabled -> only "txindex"
-- ---------------------------------------------------------------------------
test("G6: filter 'txindex' with both enabled -> only txindex", function()
  local server = build_server({
    txindex = true, filterindex = true,
    tip_height = 7, header_tip_height = 7,
  })
  local ok, result = call_gii(server, { "txindex" })
  expect_true(ok, "call failed: " .. tostring(result))
  local obj = decode(result)
  local nkeys = 0
  for _ in pairs(obj) do nkeys = nkeys + 1 end
  expect_eq(nkeys, 1, "filter narrowed to one index")
  expect_true(obj["txindex"] ~= nil, "txindex key present")
  expect_true(obj[FILTER_NAME] == nil, "filter index excluded by name filter")
end)

test("G6b: filter on filter-index literal name -> only filter index", function()
  local server = build_server({
    txindex = true, filterindex = true,
    tip_height = 7, header_tip_height = 7,
  })
  local ok, result = call_gii(server, { FILTER_NAME })
  expect_true(ok, "call failed: " .. tostring(result))
  local obj = decode(result)
  local nkeys = 0
  for _ in pairs(obj) do nkeys = nkeys + 1 end
  expect_eq(nkeys, 1, "filter narrowed to one index")
  expect_true(obj[FILTER_NAME] ~= nil, "filter index present")
  expect_true(obj["txindex"] == nil, "txindex excluded by name filter")
end)

-- ---------------------------------------------------------------------------
-- G7: unknown name -> {} (NOT an error; raw == "{}")
-- ---------------------------------------------------------------------------
test("G7: unknown index name -> empty object {} (NOT an error)", function()
  local server = build_server({
    txindex = true, filterindex = true,
    tip_height = 7, header_tip_height = 7,
  })
  local ok, result = call_gii(server, { "no-such-index" })
  expect_true(ok, "unknown name must NOT raise an error: " .. tostring(result))
  local obj, raw = decode(result)
  local nkeys = 0
  for _ in pairs(obj) do nkeys = nkeys + 1 end
  expect_eq(nkeys, 0, "unknown name yields empty object")
  expect_eq(raw, "{}", "raw JSON must be the empty object")
end)

-- ---------------------------------------------------------------------------
-- (former G8 removed) A non-string index_name currently returns lunarblock's
-- generic -32602 "index_name must be a string", which DIVERGES from Core's
-- RPC_TYPE_ERROR (-3, "JSON value of type ... is not of type string"). It is
-- intentionally NOT asserted here so this test does not enshrine the non-Core
-- code; the handler fix is tracked as a follow-up in _loop-ledger.md.
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- G9: Core index ORDER — txindex emitted before basic block filter index
-- ---------------------------------------------------------------------------
test("G9: txindex emitted before basic block filter index", function()
  local server = build_server({
    txindex = true, filterindex = true,
    tip_height = 9, header_tip_height = 9,
  })
  local ok, result = call_gii(server, {})
  expect_true(ok, "call failed: " .. tostring(result))
  local _, raw = decode(result)
  local p_tx = raw:find('"txindex"', 1, true)
  local p_filter = raw:find('"' .. FILTER_NAME .. '"', 1, true)
  expect_true(p_tx, "txindex key present in raw JSON")
  expect_true(p_filter, "filter index key present in raw JSON")
  expect_true(p_tx < p_filter, "txindex must precede the filter index")
end)

-- ---------------------------------------------------------------------------
-- G10: not-synced classification — tip behind header tip
-- ---------------------------------------------------------------------------
test("G10: txindex not synced when tip behind header tip", function()
  local server = build_server({
    txindex = true, filterindex = false,
    tip_height = 50, header_tip_height = 100,
  })
  local ok, result = call_gii(server, {})
  expect_true(ok, "call failed: " .. tostring(result))
  local obj = decode(result)
  expect_eq(obj["txindex"].synced, false, "not synced while tip < header tip")
  expect_eq(obj["txindex"].best_block_height, 50, "best height tracks chain tip")
end)

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
print("\n=========================================================================")
io.write(string.format("getindexinfo parity — PASS: %d  FAIL: %d\n", PASS, FAIL))
print("=========================================================================")

if FAIL > 0 then os.exit(1) end
os.exit(0)
