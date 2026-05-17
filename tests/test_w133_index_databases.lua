#!/usr/bin/env luajit
-- W133 Index databases (txindex + coinstatsindex) audit — lunarblock
--
-- Reference: bitcoin-core/src/index/base.{cpp,h}
--            bitcoin-core/src/index/txindex.{cpp,h}
--            bitcoin-core/src/index/coinstatsindex.{cpp,h}
--            bitcoin-core/src/index/disktxpos.h
--            bitcoin-core/src/index/db_key.h
--
-- Scope: assert lunarblock's txindex + coinstatsindex parity vs Core.
-- EXCLUDES blockfilterindex (covered by W121).
--
-- Gate map (W133):
--   G1   `-txindex` CLI flag accepted; default off
--   G2   `-coinstatsindex` CLI flag accepted; default off
--   G3   txindex CustomAppend value layout = CDiskTxPos
--   G4   txindex skips genesis (height==0 returns true)
--   G5   Atomic CustomAppend + WriteBatch (per-block)
--   G6   CustomRemove on disconnect (symmetrical)
--   G7   BaseIndex DB_BEST_BLOCK locator written per Commit
--   G8   BaseIndex Init() locator-based rewind
--   G9   BaseIndex Sync() background-thread catch-up
--   G10  BaseIndex BlockUntilSyncedToCurrentChain
--   G11  BaseIndex GetSummary {name, synced, best_block_*}
--   G12  `getindexinfo` RPC
--   G13  TxIndex::FindTx CDiskTxPos + OpenBlockFile + txid verify
--   G14  tx-index value carries nTxOffset for skip-block-load
--   G15  tx-index value carries height (already does; rpc ignores)
--   G16  Coinstatsindex MuHash3072 incremental + persisted DB_MUHASH
--   G17  Coinstatsindex per-block DBVal record
--   G18  Coinstatsindex LookUpStats(block_index) historical lookup
--   G19  Coinstatsindex unspendables×4 tracking
--   G20  Coinstatsindex height + hash dual-index w/ CopyHeightIndexToHashIndex
--   G21  `gettxoutsetinfo hash_type=muhash`
--   G22  `gettxoutsetinfo hash_type=none`
--   G23  `gettxoutsetinfo use_index=false` toggle (N/A pre-coinstatsindex)
--   G24  DB_BLOCK_HEIGHT key big-endian (per-index)
--   G25  DBHashKey/DBHeightKey prefix bytes distinct from BaseIndex BEST_BLOCK
--   G26  Prune-lock coordination (UpdatePruneLock per index)
--   G27  ValidationInterface role.validated gate for background chainstate
--   G28  Periodic locator flush (SYNC_LOCATOR_WRITE_INTERVAL = 30s)
--   G29  `scanblocks` RPC (uses TxIndex + BlockFilterIndex)
--   G30  Dead-code: src/txindex.lua + src/indexmanager.lua deleted-or-wired-in
--
-- Bugs (23):
--   BUG-1  P0  -coinstatsindex CLI flag absent              (G2,  OPS)
--   BUG-2  P1  tx-index value = (block_hash 32B ‖ height 4B LE), NOT CDiskTxPos (G3, CORRECTNESS)
--   BUG-3  P1  genesis-skip is side-effect of connect_genesis() short-circuit, not explicit (G4, CORRECTNESS)
--   BUG-4  P0  Pattern C0 never writes a txindex-specific locator   (G7, OPS)
--   BUG-5  P1  No locator-based rewind on restart            (G8, OPS)
--   BUG-6  P2  No background-thread sync (indexmanager.tick dead)   (G9, OPS)
--   BUG-7  P1  No BlockUntilSyncedToCurrentChain primitive   (G10, OPS)
--   BUG-8  P1  No per-index GetSummary                        (G11, OPS)
--   BUG-9  P1  `getindexinfo` RPC absent                      (G12, OPS)
--   BUG-10 P1  getrawtransaction full-block deserialise + linear scan (G13, PERF)
--   BUG-11 P2  No nTxOffset in tx-index value                (G14, SCHEMA)
--   BUG-12 P2  rpc ignores height bytes; falls back to O(N) iterator scan (G15, PERF)
--   BUG-13 P0  compute_utxo_hash full UTXO scan per gettxoutsetinfo (G16, PERF)
--   BUG-14 P1  No per-block DBVal record                      (G17, COMPLETENESS)
--   BUG-15 P1  gettxoutsetinfo <height> historical lookup unsupported (G18, RPC)
--   BUG-16 P2  No unspendables×4 tracking                     (G19, COMPLETENESS)
--   BUG-17 P1  No CopyHeightIndexToHashIndex on disconnect   (G20, REORG)
--   BUG-18 P0  gettxoutsetinfo hash_type=muhash absent       (G21, RPC)
--   BUG-19 P3  hash_type=none not supported                  (G22, RPC)
--   BUG-20 P1  No prune-lock coordination                    (G26, SAFETY)
--   BUG-21 P2  No ValidationInterface role.validated check   (G27, FUTURE)
--   BUG-22 P2  No periodic locator flush (Pattern C0 = stricter though) (G28, OPS)
--   BUG-23 P3  src/txindex.lua + src/indexmanager.lua dead code (G30, DEAD-CODE)
--
-- Test harness style mirrors test_w128_addrman.lua / test_w125_error_parity.lua
-- so the project test runner output stays uniform: xfail_pre_fix counts as
-- expected divergence (not a failure); fail counts only true regressions.

package.path = "src/?.lua;src/?/init.lua;" .. package.path

-- ---------------------------------------------------------------------------
-- Test scaffolding
-- ---------------------------------------------------------------------------

local PASS = 0
local FAIL = 0
local XFAIL_PRE_FIX = 0
local BUGS = {}

local function pass(name)
  io.write(string.format("  PASS  %s\n", name))
  PASS = PASS + 1
end

local function fail(name, msg)
  io.write(string.format("  FAIL  %s -- %s\n", name, msg))
  FAIL = FAIL + 1
end

local function xfail_pre_fix(name, msg)
  io.write(string.format("  XFAIL %s -- %s\n", name, msg))
  XFAIL_PRE_FIX = XFAIL_PRE_FIX + 1
end

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end

local function test_xfail_pre_fix(name, bug_id, fn)
  local ok, err = pcall(fn)
  if ok then
    pass(name .. " [now PASSing -- " .. bug_id .. " fix likely landed]")
  else
    xfail_pre_fix(name .. " (" .. bug_id .. ")", tostring(err))
  end
end

local function bug(id, severity)
  BUGS[#BUGS + 1] = id .. " (" .. severity .. ")"
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a)
      .. ", expected " .. tostring(b), 2)
  end
end

local function expect_true(v, msg)
  if not v then error((msg or "expected true") .. ": got " .. tostring(v), 2) end
end

local function expect_false(v, msg)
  if v then error((msg or "expected false") .. ": got " .. tostring(v), 2) end
end

local function expect_nil(v, msg)
  if v ~= nil then error((msg or "expected nil") .. ": got " .. tostring(v), 2) end
end

local function expect_not_nil(v, msg)
  if v == nil then error((msg or "expected non-nil"), 2) end
end

-- Pluck a file source for grep-style checks (used for "is dead code wired?"
-- and "does production code reference X?" probes).
local function slurp(path)
  local f = io.open(path, "r")
  if not f then return nil end
  local body = f:read("*a")
  f:close()
  return body
end

local function file_contains(path, needle)
  local body = slurp(path)
  if not body then return false end
  return body:find(needle, 1, true) ~= nil
end

-- ---------------------------------------------------------------------------
-- Banner
-- ---------------------------------------------------------------------------

print("\n=========================================================================")
print("W133 Index databases (txindex + coinstatsindex) -- lunarblock")
print("Source: src/utxo.lua (Pattern C0) + src/rpc.lua (getrawtransaction +")
print("        gettxoutsetinfo) + src/storage.lua (CF.TX_INDEX) +")
print("        src/main.lua (CLI) + src/txindex.lua + src/indexmanager.lua")
print("        (dead-code).")
print("Reference: bitcoin-core/src/index/{base,txindex,coinstatsindex,")
print("           disktxpos,db_key}.{cpp,h}")
print("=========================================================================")

-- ---------------------------------------------------------------------------
-- G1: `-txindex` CLI flag accepted; default off
-- ---------------------------------------------------------------------------

print("\n--- G1: -txindex CLI flag ---")

test("G1-a: src/main.lua parses --txindex flag (bare + =BOOL)", function()
  expect_true(file_contains("src/main.lua",
    "elseif arg == \"--txindex\""), "--txindex parser missing")
  expect_true(file_contains("src/main.lua",
    "args.txindex = (v == \"1\""), "--txindex= boolean parsing missing")
end)

test("G1-b: ChainState constructor sets txindex_enabled = false by default",
function()
  -- ChainState.new() sets txindex_enabled = false explicitly per
  -- src/utxo.lua:1569 ("self.txindex_enabled = false"). We verify the
  -- contract via source grep rather than constructing a ChainState
  -- (which would require a full storage stub including batch()).
  expect_true(file_contains("src/utxo.lua",
    "self.txindex_enabled = false"),
    "default-off contract pinned in src/utxo.lua")
end)

test("G1-c: set_txindex_enabled(enabled) coerces to boolean", function()
  -- src/utxo.lua:1614-1616 — late toggle from main.lua after CLI parse.
  expect_true(file_contains("src/utxo.lua",
    "function ChainState:set_txindex_enabled(enabled)"),
    "set_txindex_enabled method defined")
  expect_true(file_contains("src/utxo.lua",
    "self.txindex_enabled = enabled and true or false"),
    "boolean coercion in set_txindex_enabled")
end)

-- ---------------------------------------------------------------------------
-- G2: `-coinstatsindex` CLI flag accepted; default off
-- ---------------------------------------------------------------------------

print("\n--- G2: -coinstatsindex CLI flag (BUG-1 P0) ---")

test_xfail_pre_fix("G2: --coinstatsindex flag in main.lua parser (BUG-1)",
  "BUG-1", function()
    bug("BUG-1", "P0")
    expect_true(file_contains("src/main.lua", "--coinstatsindex"),
      "-coinstatsindex CLI flag missing")
  end)

-- ---------------------------------------------------------------------------
-- G3: txindex CustomAppend value layout = CDiskTxPos
-- ---------------------------------------------------------------------------

print("\n--- G3: tx-index value layout (BUG-2) ---")

test_xfail_pre_fix("G3-a: tx-index value layout = CDiskTxPos {nFile,nPos,nTxOffset}",
  "BUG-2", function()
    bug("BUG-2", "P1")
    -- The live Pattern C0 layout is `(block_hash 32B ‖ height 4B LE)` = 36B.
    -- Core's CDiskTxPos is `(nFile, nPos, nTxOffset)` with nTxOffset VARINT
    -- such that the wire size is ~6-10 bytes. Probe the live module's
    -- comment block for the canonical layout pin and assert Core schema.
    expect_true(file_contains("src/utxo.lua",
      "block_hash || height_le"), "Pattern C0 comment block exists")
    error("tx-index value layout is `(block_hash, height_LE)`, "
      .. "not Core's CDiskTxPos `(nFile, nPos, nTxOffset)`")
  end)

test("G3-b: dead-code src/txindex.lua claims file_num/block_pos/tx_offset (12B)",
function()
  -- Sanity check that the dead-code module exists and is referenced ONLY
  -- by tests. BUG-23 (G30) covers the full dead-code analysis.
  expect_true(file_contains("src/txindex.lua",
    "[file_num: 4B LE][block_pos: 4B LE][tx_offset: 4B LE]"),
    "src/txindex.lua header comment claims 12-byte layout")
end)

-- ---------------------------------------------------------------------------
-- G4: txindex skips genesis (height==0 returns true)
-- ---------------------------------------------------------------------------

print("\n--- G4: genesis-skip parity (BUG-3) ---")

test_xfail_pre_fix("G4: explicit `if block.height == 0 return true` in connect_block",
  "BUG-3", function()
    bug("BUG-3", "P1")
    -- Core's index/txindex.cpp:77 has the explicit guard. Lunarblock's
    -- Pattern C0 relies on connect_block returning early at the
    -- `genesis_hash` short-circuit (utxo.lua:2144-2151), BEFORE
    -- block_txid_bytes is even declared at line 2300. Net effect is
    -- correct today, but the contract is implicit; an explicit
    -- height==0 guard inside the txindex write block is missing.
    expect_true(file_contains("src/utxo.lua",
      "if block.height == 0 then return true end"),
      "explicit genesis-skip in txindex write block")
  end)

-- ---------------------------------------------------------------------------
-- G5: Atomic CustomAppend + WriteBatch (per-block)
-- ---------------------------------------------------------------------------

print("\n--- G5: per-block atomic batch (PRESENT) ---")

test("G5: Pattern C0 writes inside coin_view:flush atomic batch", function()
  expect_true(file_contains("src/utxo.lua",
    "self.coin_view:flush(false, function(batch)"),
    "atomic batch wrapper around per-block writes")
  expect_true(file_contains("src/utxo.lua",
    "batch.put(storage_mod.CF.TX_INDEX, block_txid_bytes[i], txindex_value)"),
    "tx-index puts inside the same batch")
end)

-- ---------------------------------------------------------------------------
-- G6: CustomRemove on disconnect (symmetrical)
-- ---------------------------------------------------------------------------

print("\n--- G6: disconnect_block symmetry (PRESENT) ---")

test("G6: disconnect_block deletes CF.TX_INDEX entries inside batch", function()
  expect_true(file_contains("src/utxo.lua",
    "batch.delete(storage_mod.CF.TX_INDEX, block_txid_bytes[i])"),
    "tx-index deletes inside disconnect batch")
end)

-- ---------------------------------------------------------------------------
-- G7: BaseIndex DB_BEST_BLOCK locator written per Commit
-- ---------------------------------------------------------------------------

print("\n--- G7: per-index locator persistence (BUG-4 P0) ---")

test_xfail_pre_fix("G7-a: production code writes a `txindex_*` locator meta key",
  "BUG-4", function()
    bug("BUG-4", "P0")
    -- Pattern C0 shares CF.META["chain_tip"] with the chainstate; there is
    -- no independent index locator. spec/txindex_spec.lua references a
    -- `txindex_height` key but the production write path doesn't.
    local main_body = slurp("src/main.lua") or ""
    local utxo_body = slurp("src/utxo.lua") or ""
    local rpc_body  = slurp("src/rpc.lua")  or ""
    local sync_body = slurp("src/sync.lua") or ""
    local prod = main_body .. utxo_body .. rpc_body .. sync_body
    expect_true(prod:find("txindex_height", 1, true) ~= nil
      or prod:find("txindex_best_block", 1, true) ~= nil
      or prod:find("txindex_locator", 1, true) ~= nil,
      "no production-code reference to a txindex-specific locator")
  end)

test_xfail_pre_fix("G7-b: BaseIndex::DB::WriteBestBlock(batch, locator) analog",
  "BUG-4", function()
    -- Core's base.cpp:90-93 has `WriteBestBlock(CDBBatch& batch, const CBlockLocator& locator)`.
    -- We probe for ANY persistence call that writes a per-index locator.
    expect_true(file_contains("src/utxo.lua", "WriteBestBlock")
      or file_contains("src/utxo.lua", "write_best_block")
      or file_contains("src/utxo.lua", "DB_BEST_BLOCK"),
      "no WriteBestBlock/write_best_block analog in production")
  end)

-- ---------------------------------------------------------------------------
-- G8: BaseIndex Init() locator-based rewind
-- ---------------------------------------------------------------------------

print("\n--- G8: init-time locator rewind (BUG-5 P1) ---")

test_xfail_pre_fix("G8: ChainState:init() reads txindex locator + rewinds to fork",
  "BUG-5", function()
    bug("BUG-5", "P1")
    -- Core's base.cpp:124-134 reads the locator and rewinds.
    local utxo_body = slurp("src/utxo.lua") or ""
    expect_true(utxo_body:find("rewind to the fork point", 1, true) ~= nil
      or utxo_body:find("rewind to fork", 1, true) ~= nil
      or utxo_body:find("locator", 1, true) ~= nil,
      "no init-time rewind-to-fork analog in ChainState:init()")
  end)

-- ---------------------------------------------------------------------------
-- G9: BaseIndex Sync() background-thread catch-up
-- ---------------------------------------------------------------------------

print("\n--- G9: background-thread sync (BUG-6 P2) ---")

test("G9-a: indexmanager.lua exists with start_building / tick methods", function()
  expect_true(file_contains("src/indexmanager.lua",
    "function manager.start_building"),
    "indexmanager.lua start_building exists")
  expect_true(file_contains("src/indexmanager.lua",
    "function manager.tick"),
    "indexmanager.lua tick exists")
end)

test_xfail_pre_fix("G9-b: indexmanager is wired into main.lua / sync.lua (BUG-6)",
  "BUG-6", function()
    bug("BUG-6", "P2")
    -- Production code never requires indexmanager.
    local main_body = slurp("src/main.lua") or ""
    local sync_body = slurp("src/sync.lua") or ""
    expect_true(main_body:find("require.*indexmanager", 1, false) ~= nil
      or sync_body:find("require.*indexmanager", 1, false) ~= nil,
      "indexmanager.lua never required by main.lua / sync.lua (dead code)")
  end)

-- ---------------------------------------------------------------------------
-- G10: BaseIndex BlockUntilSyncedToCurrentChain
-- ---------------------------------------------------------------------------

print("\n--- G10: BlockUntilSyncedToCurrentChain primitive (BUG-7 P1) ---")

test_xfail_pre_fix("G10: block_until_synced_to_current_chain primitive present",
  "BUG-7", function()
    bug("BUG-7", "P1")
    local all = (slurp("src/utxo.lua") or "")
              .. (slurp("src/rpc.lua") or "")
              .. (slurp("src/indexmanager.lua") or "")
    expect_true(all:find("block_until_synced", 1, true) ~= nil
      or all:find("BlockUntilSynced", 1, true) ~= nil
      or all:find("wait_until_synced", 1, true) ~= nil,
      "BlockUntilSyncedToCurrentChain analog absent")
  end)

-- ---------------------------------------------------------------------------
-- G11: BaseIndex GetSummary {name, synced, best_block_height, best_block_hash}
-- ---------------------------------------------------------------------------

print("\n--- G11: per-index GetSummary (BUG-8 P1) ---")

test_xfail_pre_fix("G11: get_index_summary / index:get_stats production hook",
  "BUG-8", function()
    bug("BUG-8", "P1")
    -- indexmanager.lua DOES expose get_stats, but it's dead-code.
    -- Production paths have no summary.
    local main_body = slurp("src/main.lua") or ""
    local rpc_body  = slurp("src/rpc.lua")  or ""
    local utxo_body = slurp("src/utxo.lua") or ""
    expect_true(main_body:find("get_index_summary", 1, true) ~= nil
      or rpc_body:find("get_index_summary", 1, true) ~= nil
      or utxo_body:find("get_index_summary", 1, true) ~= nil,
      "no get_index_summary production hook")
  end)

-- ---------------------------------------------------------------------------
-- G12: `getindexinfo` RPC
-- ---------------------------------------------------------------------------

print("\n--- G12: getindexinfo RPC (BUG-9 P1) ---")

test_xfail_pre_fix("G12: rpc.lua exposes self.methods[\"getindexinfo\"]",
  "BUG-9", function()
    bug("BUG-9", "P1")
    expect_true(file_contains("src/rpc.lua",
      "self.methods[\"getindexinfo\"]"),
      "getindexinfo RPC handler absent")
  end)

-- ---------------------------------------------------------------------------
-- G13: TxIndex::FindTx CDiskTxPos + OpenBlockFile + txid verify
-- ---------------------------------------------------------------------------

print("\n--- G13: FindTx O(1) seek vs full-block scan (BUG-10 P1) ---")

test_xfail_pre_fix("G13: getrawtransaction skips full-block deserialise via offset",
  "BUG-10", function()
    bug("BUG-10", "P1")
    -- The post-fix shape would not linearly scan block.transactions for
    -- the matching txid.  Today's path is rpc.lua:2143-2162 which does
    -- exactly that.
    local rpc_body = slurp("src/rpc.lua") or ""
    -- Probe: a fast FindTx would use a seek_to_tx / open_block_at_offset
    -- helper.  Absence ⇒ BUG-10 still open.
    expect_true(rpc_body:find("seek_to_tx", 1, true) ~= nil
      or rpc_body:find("open_block_at_offset", 1, true) ~= nil
      or rpc_body:find("read_tx_at_offset", 1, true) ~= nil,
      "no offset-based FindTx fast path; rpc deserialises full block")
  end)

-- ---------------------------------------------------------------------------
-- G14: tx-index value carries nTxOffset for skip-block-load
-- ---------------------------------------------------------------------------

print("\n--- G14: nTxOffset in tx-index value (BUG-11 P2) ---")

test_xfail_pre_fix("G14: tx-index value includes nTxOffset field",
  "BUG-11", function()
    bug("BUG-11", "P2")
    -- Pattern C0 value is 36 bytes (block_hash 32B + height 4B LE). The
    -- CDiskTxPos analog would add nTxOffset (4B or VARINT). Probe utxo.lua
    -- buffer width and the rpc.lua reader.
    local utxo_body = slurp("src/utxo.lua") or ""
    expect_true(utxo_body:find("ffi.new(\"uint8_t[44]", 1, true) ~= nil
      or utxo_body:find("ffi.new(\"uint8_t[40]", 1, true) ~= nil
      or utxo_body:find("nTxOffset", 1, true) ~= nil
      or utxo_body:find("tx_offset", 1, true) ~= nil,
      "tx-index value still 36 bytes; nTxOffset slot absent")
  end)

-- ---------------------------------------------------------------------------
-- G15: rpc reads the height bytes already in the tx-index value
-- ---------------------------------------------------------------------------

print("\n--- G15: rpc decodes height from tx-index value (BUG-12 P2) ---")

test_xfail_pre_fix("G15: getrawtransaction decodes height from tx_index_data[33..36]",
  "BUG-12", function()
    bug("BUG-12", "P2")
    -- The data IS stored (utxo.lua:2860-2863 packs height_LE in bytes 33..36).
    -- The RPC ignores it (rpc.lua:2354 comment claims it's "not stored"
    -- and does an O(N) iterator scan).
    local rpc_body = slurp("src/rpc.lua") or ""
    expect_true(rpc_body:find("tx_index_data:sub(33", 1, true) ~= nil
      or rpc_body:find("tx_index_data:sub(33, 36)", 1, true) ~= nil
      or rpc_body:find("read_u32le.*tx_index", 1, false) ~= nil,
      "rpc still does iterator-scan instead of reading height from value")
    -- Sanity: the misleading comment at line 2354 still says
    -- "in production, store height in tx_index" (it IS stored).
    expect_false(rpc_body:find("in production, store height in tx_index",
      1, true) ~= nil,
      "stale comment about height-not-stored still present")
  end)

-- ---------------------------------------------------------------------------
-- G16: Coinstatsindex MuHash3072 incremental + persisted DB_MUHASH
-- ---------------------------------------------------------------------------

print("\n--- G16: MuHash incremental state (BUG-13 P0) ---")

test_xfail_pre_fix("G16-a: ChainState maintains a persistent m_muhash field",
  "BUG-13", function()
    bug("BUG-13", "P0")
    local utxo_body = slurp("src/utxo.lua") or ""
    expect_true(utxo_body:find("self.muhash =", 1, true) ~= nil
      or utxo_body:find("self.m_muhash", 1, true) ~= nil
      or utxo_body:find("coinstats_muhash", 1, true) ~= nil,
      "ChainState has no m_muhash member (full UTXO scan per call)")
  end)

test_xfail_pre_fix("G16-b: DB_MUHASH meta key persisted atomically with chain_tip",
  "BUG-13", function()
    local utxo_body = slurp("src/utxo.lua") or ""
    expect_true(utxo_body:find("DB_MUHASH", 1, true) ~= nil
      or utxo_body:find("coinstats_muhash", 1, true) ~= nil
      or utxo_body:find("\"muhash\"", 1, true) ~= nil,
      "no DB_MUHASH atomically-committed key in production")
  end)

test("G16-c: compute_utxo_hash exists (the slow fallback that today powers gettxoutsetinfo)",
function()
  -- This is the FALLBACK used when coinstatsindex is absent. Present is the
  -- correct status for the slow path; absent would mean even the fallback is
  -- broken. PRESENT here proves only the fallback is wired, not the index.
  local utxo_body = slurp("src/utxo.lua") or ""
  expect_true(utxo_body:find("function ChainState:compute_utxo_hash", 1, true) ~= nil,
    "compute_utxo_hash exists as the slow fallback")
end)

-- ---------------------------------------------------------------------------
-- G17: Coinstatsindex per-block DBVal record
-- ---------------------------------------------------------------------------

print("\n--- G17: per-block DBVal record (BUG-14 P1) ---")

test_xfail_pre_fix("G17: per-block DBVal {muhash, output_count, bogo_size, ...} record",
  "BUG-14", function()
    bug("BUG-14", "P1")
    local utxo_body = slurp("src/utxo.lua") or ""
    local rpc_body  = slurp("src/rpc.lua") or ""
    local all = utxo_body .. rpc_body
    -- The 12 DBVal fields per coinstatsindex.cpp:46-83.
    -- We probe for ANY tracking of total_subsidy / total_prevout_spent_amount
    -- per block.
    expect_true(all:find("total_subsidy", 1, true) ~= nil
      or all:find("total_prevout_spent", 1, true) ~= nil
      or all:find("total_new_outputs_ex_coinbase", 1, true) ~= nil,
      "no per-block DBVal record fields tracked in production")
  end)

-- ---------------------------------------------------------------------------
-- G18: Coinstatsindex LookUpStats(block_index) historical lookup
-- ---------------------------------------------------------------------------

print("\n--- G18: historical gettxoutsetinfo <height|hash> (BUG-15 P1) ---")

test_xfail_pre_fix("G18: gettxoutsetinfo handler accepts hash_type AND height params",
  "BUG-15", function()
    bug("BUG-15", "P1")
    -- Look for the handler accepting non-discarded params.  Current
    -- signature is `function(rpc, _params)` which discards.
    local rpc_body = slurp("src/rpc.lua") or ""
    expect_false(rpc_body:find(
      "self.methods[\"gettxoutsetinfo\"] = function(rpc, _params)", 1, true) ~= nil,
      "gettxoutsetinfo signature still discards params (no height/hash_type)")
  end)

-- ---------------------------------------------------------------------------
-- G19: Coinstatsindex unspendables×4 tracking
-- ---------------------------------------------------------------------------

print("\n--- G19: unspendables×4 tracking (BUG-16 P2) ---")

test_xfail_pre_fix("G19: total_unspendables_{genesis,bip30,scripts,unclaimed_rewards}",
  "BUG-16", function()
    bug("BUG-16", "P2")
    local all = (slurp("src/utxo.lua") or "")
              .. (slurp("src/rpc.lua") or "")
    expect_true(all:find("total_unspendables_genesis", 1, true) ~= nil,
      "total_unspendables_genesis_block tracking absent")
    expect_true(all:find("total_unspendables_bip30", 1, true) ~= nil,
      "total_unspendables_bip30 tracking absent")
    expect_true(all:find("total_unspendables_scripts", 1, true) ~= nil,
      "total_unspendables_scripts tracking absent")
    expect_true(all:find("total_unspendables_unclaimed_rewards", 1, true) ~= nil,
      "total_unspendables_unclaimed_rewards tracking absent")
  end)

-- ---------------------------------------------------------------------------
-- G20: Coinstatsindex height + hash dual-index w/ CopyHeightIndexToHashIndex
-- ---------------------------------------------------------------------------

print("\n--- G20: dual-index w/ CopyHeightIndexToHashIndex on reorg (BUG-17 P1) ---")

test_xfail_pre_fix("G20: CopyHeightIndexToHashIndex preserves stale-chain entries",
  "BUG-17", function()
    bug("BUG-17", "P1")
    local utxo_body = slurp("src/utxo.lua") or ""
    expect_true(utxo_body:find("CopyHeightIndexToHashIndex", 1, true) ~= nil
      or utxo_body:find("copy_height_index_to_hash_index", 1, true) ~= nil
      or utxo_body:find("DBHashKey", 1, true) ~= nil,
      "no stale-chain hash-key preservation; reorg deletes index entries")
  end)

-- ---------------------------------------------------------------------------
-- G21: `gettxoutsetinfo hash_type=muhash`
-- ---------------------------------------------------------------------------

print("\n--- G21: hash_type=muhash (BUG-18 P0) ---")

test_xfail_pre_fix("G21-a: gettxoutsetinfo handler accepts hash_type=muhash",
  "BUG-18", function()
    bug("BUG-18", "P0")
    local rpc_body = slurp("src/rpc.lua") or ""
    -- A correct handler would parse params[1] for "muhash"/"hash_serialized_3"/"none".
    expect_true(rpc_body:find("hash_type == \"muhash\"", 1, true) ~= nil
      or rpc_body:find("hash_type=='muhash'", 1, true) ~= nil
      or rpc_body:find("params[1] == \"muhash\"", 1, true) ~= nil,
      "no hash_type=muhash branch in gettxoutsetinfo")
  end)

test_xfail_pre_fix("G21-b: gettxoutsetinfo response includes muhash field",
  "BUG-18", function()
    local rpc_body = slurp("src/rpc.lua") or ""
    expect_true(rpc_body:find("muhash =", 1, true) ~= nil
      or rpc_body:find("muhash=", 1, true) ~= nil,
      "no muhash field in gettxoutsetinfo response")
  end)

-- ---------------------------------------------------------------------------
-- G22: `gettxoutsetinfo hash_type=none`
-- ---------------------------------------------------------------------------

print("\n--- G22: hash_type=none (BUG-19 P3) ---")

test_xfail_pre_fix("G22: hash_type=none short-circuits hashing",
  "BUG-19", function()
    bug("BUG-19", "P3")
    local rpc_body = slurp("src/rpc.lua") or ""
    expect_true(rpc_body:find("hash_type == \"none\"", 1, true) ~= nil
      or rpc_body:find("hash_type=='none'", 1, true) ~= nil,
      "no hash_type=none branch in gettxoutsetinfo")
  end)

-- ---------------------------------------------------------------------------
-- G23: `gettxoutsetinfo use_index=false` toggle
-- (N/A pre-coinstatsindex — recorded as N/A, not a separate bug)
-- ---------------------------------------------------------------------------

print("\n--- G23: use_index=false toggle (N/A until coinstatsindex lands) ---")

test("G23: documented as N/A until BUG-13 (coinstatsindex) closes", function()
  -- No assertion needed; this gate is dependent on BUG-13.
  expect_true(true, "G23 is N/A until coinstatsindex incremental state exists")
end)

-- ---------------------------------------------------------------------------
-- G24: DB_BLOCK_HEIGHT key big-endian (per-index)
-- ---------------------------------------------------------------------------

print("\n--- G24: per-index BE height key ---")

test("G24-a: shared CF.HEIGHT_INDEX uses 4B BE encoding", function()
  -- storage.lua:198-205 encode_height is BE. Used by chainstate height
  -- lookups; would be the per-index analog under a Core-shaped schema.
  expect_true(file_contains("src/storage.lua",
    "local function encode_height(height)"),
    "encode_height helper present")
  expect_true(file_contains("src/storage.lua",
    "math.floor(height / 16777216) % 256"),
    "BE-msbyte first in encode_height")
end)

test_xfail_pre_fix("G24-b: per-index DBHeightKey with prefix byte ('t' = DB_BLOCK_HEIGHT)",
  "BUG-14", function()
    -- Same shape as BUG-14 (no per-block DBVal record => no DBHeightKey).
    local utxo_body = slurp("src/utxo.lua") or ""
    expect_true(utxo_body:find("DBHeightKey", 1, true) ~= nil
      or utxo_body:find("DB_BLOCK_HEIGHT", 1, true) ~= nil,
      "no per-index DBHeightKey analog")
  end)

-- ---------------------------------------------------------------------------
-- G25: DBHashKey/DBHeightKey prefix bytes distinct from BaseIndex BEST_BLOCK
-- ---------------------------------------------------------------------------

print("\n--- G25: distinct key prefix bytes ('s', 't', 'B') ---")

test_xfail_pre_fix("G25: per-index key-prefix scheme aligned with Core db_key.h",
  "BUG-14", function()
    -- See G24-b. The prefix-byte distinction is a Core db_key.h artifact;
    -- absent until coinstatsindex lands.
    local utxo_body = slurp("src/utxo.lua") or ""
    expect_true(utxo_body:find("DB_BLOCK_HASH", 1, true) ~= nil
      or utxo_body:find("DB_BEST_BLOCK", 1, true) ~= nil
      or utxo_body:find("0x73", 1, true) ~= nil,  -- 's'
      "no per-index key-prefix scheme")
  end)

-- ---------------------------------------------------------------------------
-- G26: Prune-lock coordination
-- ---------------------------------------------------------------------------

print("\n--- G26: prune-lock coordination (BUG-20 P1) ---")

test_xfail_pre_fix("G26: UpdatePruneLock(index_name, height) analog present",
  "BUG-20", function()
    bug("BUG-20", "P1")
    local all = (slurp("src/utxo.lua") or "")
              .. (slurp("src/prune.lua") or "")
              .. (slurp("src/main.lua") or "")
    expect_true(all:find("UpdatePruneLock", 1, true) ~= nil
      or all:find("update_prune_lock", 1, true) ~= nil
      or all:find("prune_lock", 1, true) ~= nil,
      "no UpdatePruneLock analog; index unaware of pruner")
  end)

-- ---------------------------------------------------------------------------
-- G27: ValidationInterface role.validated gate for background chainstate
-- ---------------------------------------------------------------------------

print("\n--- G27: role.validated chainstate gate (BUG-21 P2) ---")

test_xfail_pre_fix("G27: connect_block hook ignores role.validated == false",
  "BUG-21", function()
    bug("BUG-21", "P2")
    local utxo_body = slurp("src/utxo.lua") or ""
    expect_true(utxo_body:find("role.validated", 1, true) ~= nil
      or utxo_body:find("ChainstateRole", 1, true) ~= nil
      or utxo_body:find("background_chainstate", 1, true) ~= nil,
      "no role.validated gate; single-chainstate assumption baked in")
  end)

-- ---------------------------------------------------------------------------
-- G28: Periodic locator flush (SYNC_LOCATOR_WRITE_INTERVAL = 30s)
-- ---------------------------------------------------------------------------

print("\n--- G28: periodic locator flush (BUG-22 P2) ---")

test_xfail_pre_fix("G28: SYNC_LOCATOR_WRITE_INTERVAL or equivalent",
  "BUG-22", function()
    bug("BUG-22", "P2")
    local all = (slurp("src/utxo.lua") or "")
              .. (slurp("src/indexmanager.lua") or "")
              .. (slurp("src/sync.lua") or "")
    expect_true(all:find("SYNC_LOCATOR_WRITE_INTERVAL", 1, true) ~= nil
      or all:find("sync_locator_write_interval", 1, true) ~= nil
      or all:find("locator_flush_interval", 1, true) ~= nil,
      "no SYNC_LOCATOR_WRITE_INTERVAL analog (Pattern C0 is stricter though)")
  end)

-- ---------------------------------------------------------------------------
-- G29: `scanblocks` RPC (uses TxIndex + BlockFilterIndex)
-- ---------------------------------------------------------------------------

print("\n--- G29: scanblocks RPC (N/A — not in W133 scope) ---")

test("G29: scanblocks is W121 scope (BIP-157) — no W133 assertion", function()
  -- Recorded for completeness; tracked under W121.
  expect_true(true, "scanblocks RPC tracked under W121 BIP-157 audit")
end)

-- ---------------------------------------------------------------------------
-- G30: Dead-code (src/txindex.lua + src/indexmanager.lua) deleted-or-wired-in
-- ---------------------------------------------------------------------------

print("\n--- G30: dead-code modules (BUG-23 P3) ---")

test("G30-a: src/txindex.lua exists (262 LOC)", function()
  expect_not_nil(slurp("src/txindex.lua"), "src/txindex.lua exists")
end)

test("G30-b: src/indexmanager.lua exists (259 LOC)", function()
  expect_not_nil(slurp("src/indexmanager.lua"), "src/indexmanager.lua exists")
end)

test_xfail_pre_fix("G30-c: src/txindex.lua is required by production code",
  "BUG-23", function()
    bug("BUG-23", "P3")
    local main_body = slurp("src/main.lua") or ""
    local utxo_body = slurp("src/utxo.lua") or ""
    local rpc_body  = slurp("src/rpc.lua") or ""
    local sync_body = slurp("src/sync.lua") or ""
    local prod = main_body .. utxo_body .. rpc_body .. sync_body
    expect_true(prod:find("require(\"lunarblock.txindex\")", 1, true) ~= nil
      or prod:find("require 'lunarblock.txindex'", 1, true) ~= nil,
      "src/txindex.lua never required by production code (dead)")
  end)

test_xfail_pre_fix("G30-d: src/indexmanager.lua is required by production code",
  "BUG-23", function()
    local main_body = slurp("src/main.lua") or ""
    local utxo_body = slurp("src/utxo.lua") or ""
    local rpc_body  = slurp("src/rpc.lua") or ""
    local sync_body = slurp("src/sync.lua") or ""
    local prod = main_body .. utxo_body .. rpc_body .. sync_body
    expect_true(prod:find("require(\"lunarblock.indexmanager\")", 1, true) ~= nil
      or prod:find("require 'lunarblock.indexmanager'", 1, true) ~= nil,
      "src/indexmanager.lua never required by production code (dead)")
  end)

test("G30-e: dead-code claims a different value schema than production", function()
  -- This is a true PASS (the assertion holds): confirms the schema mismatch
  -- documented in BUG-23. The production Pattern C0 uses a 36-byte
  -- (block_hash, height_LE) value; the dead module claims a 12-byte
  -- (file_num, block_pos, tx_offset) value.
  expect_true(file_contains("src/txindex.lua",
    "[file_num: 4B LE][block_pos: 4B LE][tx_offset: 4B LE]"),
    "dead-code module documents the 12-byte schema")
  expect_true(file_contains("src/utxo.lua",
    "block_hash || height_le"),
    "production code documents the 36-byte schema")
end)

test("G30-f: stale comment at rpc.lua re txindex format is FALSE for production",
function()
  -- rpc.lua:8193 claims "lunarblock txindex stores file offsets, not block
  -- hashes" — TRUE for the dead `src/txindex.lua`, FALSE for the live
  -- Pattern C0 (which DOES store block_hash + height). Documents the
  -- documentation-vs-code drift introduced by BUG-23.
  expect_true(file_contains("src/rpc.lua",
    "lunarblock txindex stores file offsets, not block hashes"),
    "stale comment still present in rpc.lua")
end)

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------

print("\n=========================================================================")
print("W133 Index databases -- summary")
print("=========================================================================")
io.write(string.format("\n  PASS:  %d\n", PASS))
io.write(string.format("  XFAIL: %d (expected pre-fix divergences)\n", XFAIL_PRE_FIX))
io.write(string.format("  FAIL:  %d\n\n", FAIL))

if #BUGS > 0 then
  local seen, dedup = {}, {}
  for _, b in ipairs(BUGS) do
    if not seen[b] then
      dedup[#dedup + 1] = b
      seen[b] = true
    end
  end
  io.write("Bugs surfaced:\n")
  for _, b in ipairs(dedup) do
    io.write("  " .. b .. "\n")
  end
  io.write("\n")
end

print("Audit gates: 30 W133 set")
print("  PRESENT:  6  (G1-a/b/c, G5, G6, G16-c [slow fallback], G24-a, G30-a/b/e/f)")
print("  MISSING: 23  (G2, G3-a, G4, G7, G8, G9-b, G10, G11, G12, G13, G14,")
print("              G15, G16-a/b, G17, G18, G19, G20, G21-a/b, G22, G24-b, G25,")
print("              G26, G27, G28, G30-c/d)")
print("  N/A:      1  (G23 — depends on BUG-13 coinstatsindex landing)")
print("  TRACKED-ELSEWHERE: 1  (G29 — scanblocks is W121)")
print("")
print("Cross-references:")
print("  W121 BIP-157/158 compact filter index (blockfilterindex)")
print("  W120 mempool RBF (sibling persistence shape)")
print("  CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-2026-05-05.md")
print("  FIX-72 / FIX-76 / FIX-77 / FIX-80 -- adjacent persistence-shape audits")

if FAIL > 0 then
  os.exit(1)
end
os.exit(0)
