#!/usr/bin/env luajit
-- W123 Mining / GBT parity audit — lunarblock (Lua / LuaJIT)
--
-- Reference: bitcoin-core/src/node/miner.cpp
--            bitcoin-core/src/rpc/mining.cpp
--            BIP-22 / BIP-23 / BIP-141 / BIP-94
--
-- Scope: Audit lunarblock's Mining / GBT RPC stack against Bitcoin
--        Core's miner.cpp + rpc/mining.cpp for 30 standard W123 gates.
--
-- Gate map (W123):
--   G1   getblocktemplate RPC method registered
--   G2   GBT mode=template default
--   G3   GBT mode=proposal (BIP-23 §Proposals)                       [BUG-1]
--   G4   GBT enforces "segwit" rule client-side                      [BUG-2]
--   G5   GBT longpollid field                                        [BUG-3]
--   G6   GBT IBD / connection-count guard                            [BUG-4]
--   G7   GBT bits from GetNextWorkRequired (retarget)                [BUG-5]
--   G8   GBT mintime honors BIP-94 timewarp                          [BUG-6]
--   G9   GBT mtp from chain state (not os.time-3600)                 [BUG-7]
--   G10  GBT transactions[i].sigops accurate                         [BUG-8]
--   G11  GBT BIP-22 depends 1-based indexing
--   G12  GBT default_witness_commitment field
--   G13  GBT coinbasevalue field
--   G14  GBT coinbasetxn (BIP-23 optional)
--   G15  GBT coinbaseaux.flags empty obj                             [BUG-9]
--   G16  GBT rules includes "csv" always
--   G17  GBT rules includes "!segwit"/"taproot" post-segwit
--   G18  GBT signet_challenge on signet                              [BUG-10]
--   G19  GBT vbavailable per BIP-9
--   G20  GBT setClientRules strips active bits if unsupported        [BUG-11]
--   G21  getmininginfo RPC method registered
--   G22  getmininginfo.next.bits via NextEmptyBlockIndex              [BUG-12]
--   G23  getmininginfo.networkhashps populated                       [BUG-13]
--   G24  prioritisetransaction RPC                                   [BUG-14]
--   G25  getprioritisedtransactions RPC                              [BUG-14]
--   G26  submitblock RPC
--   G27  submitblock BIP-22 result strings
--   G28  submitheader RPC                                            [BUG-15]
--   G29  generatetoaddress RPC
--   G30  generatetoaddress honors maxtries (params[3])               [BUG-16]
--
-- Bugs found (16):
--   BUG-1  (P0-RPC) GBT proposal mode advertised in capabilities=["proposal"]
--                   but params[1].mode == "proposal" ignored — Core
--                   mining.cpp:730-752 vs lunarblock rpc.lua:3869.
--   BUG-2  (P1-RPC) GBT does not enforce setClientRules.contains("segwit")
--                   — Core mining.cpp:854-857 throws on missing.
--   BUG-3  (P1-RPC) longpollid field absent from template response
--                   — Core mining.cpp:1002.
--   BUG-4  (P1-RPC) GBT no IBD / connection-count guard
--                   — Core mining.cpp:766-775.
--   BUG-5  (P1-RPC) GBT bits = prev_header.bits, not GetNextWorkRequired
--                   — mining.lua:382 dead-helper-at-call-site for
--                   consensus.get_next_work_required (consensus.lua:401).
--   BUG-6  (P1-RPC) GBT mintime missing BIP-94 timewarp clause on
--                   retarget — mining.lua:442; MAX_TIMEWARP=600 declared
--                   in consensus.lua:41 but unused by mining path.
--   BUG-7  (P1-RPC) chain_state.mtp never populated; fallback
--                   `os.time() - 3600` is wrong — mining.lua:267.
--                   compute_mtp_from_storage exists at utxo.lua:3132 but
--                   the mining path doesn't call it.
--   BUG-8  (P1-RPC) GBT transactions[i].sigops hardcoded 0 — mining.lua:485.
--                   In-template sigops accounting also wrong: counts
--                   output-script sigops on the spendee instead of
--                   redeem-script / witness-program sigops on the
--                   spender (mining.lua:296-302).
--   BUG-9  (P2-RPC) coinbaseaux={flags=""} non-standard — Core emits
--                   empty obj `aux`.
--   BUG-10 (P2-RPC) No signet network params; signet_challenge never
--                   emitted.
--   BUG-11 (P2-RPC) setClientRules never parsed; rule active-bit
--                   stripping absent — Core mining.cpp:968-991.
--   BUG-12 (P2-RPC) getmininginfo.next.bits = current bits, not next
--                   — rpc.lua:7256.
--   BUG-13 (P2-RPC) getmininginfo.networkhashps hardcoded 0; Core
--                   mining.cpp:472 calls getnetworkhashps internally.
--   BUG-14 (P1-RPC) prioritisetransaction + getprioritisedtransactions
--                   both missing; mempool has no fee_delta plumbing.
--   BUG-15 (P1-RPC) submitheader RPC missing entirely.
--   BUG-16 (P2-RPC) generatetoaddress ignores params[3] maxtries.
--
-- Total: 16 actionable bugs / 30 gates / ~50 tests.
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_w123_mining_gbt.lua

package.path = "src/?.lua;./?.lua;" .. package.path

local loaders = package.loaders or package.searchers
table.insert(loaders, 2, function(module)
  local name = module:match("^lunarblock%.(.+)")
  if name then
    local filename = "src/" .. name .. ".lua"
    local f = io.open(filename)
    if f then f:close(); return function() return dofile(filename) end end
  end
  return nil, "not found"
end)

-- Read source files for source-level absence checks.
local function read_file(path)
  local f = assert(io.open(path, "r"), "cannot open " .. path)
  local s = f:read("*a"); f:close(); return s
end
local RPC_SRC     = read_file("src/rpc.lua")
local MINING_SRC  = read_file("src/mining.lua")
local MEMPOOL_SRC = read_file("src/mempool.lua")
local CONSENSUS_SRC = read_file("src/consensus.lua")

local PASS, FAIL, XFAIL_PRE_FIX = 0, 0, 0
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
  io.write(string.format("  XFAIL %s (expected pre-fix) -- %s\n", name, msg))
  XFAIL_PRE_FIX = XFAIL_PRE_FIX + 1
end

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end

-- xfail_pre_fix wrapper: test is expected to FAIL until the named bug is
-- fixed.  When the bug is fixed the wrapper still passes (it surfaces a
-- "now PASSing — bug likely fixed" message); when the bug is still open
-- the failure counts as XFAIL not FAIL (so the wave-discovery exit code
-- remains 0).
local function test_xfail_pre_fix(name, fn, bug_id)
  local ok, err = pcall(fn)
  if ok then
    pass(name .. " [now PASSing — " .. bug_id .. " fix likely landed]")
  else
    xfail_pre_fix(name .. " [" .. bug_id .. "]", tostring(err))
  end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) .. ", expected " .. tostring(b))
  end
end

local function expect_true(v, msg)
  if not v then error(msg or "expected true") end
end

local function expect_match(s, pattern, msg)
  if not s:find(pattern) then
    error((msg or "no match") .. " (pattern: " .. tostring(pattern) .. ")")
  end
end

local function expect_no_match(s, pattern, msg)
  if s:find(pattern) then
    error((msg or "unexpected match") .. " (pattern: " .. tostring(pattern) .. ")")
  end
end

local function bug(id, severity, desc)
  BUGS[#BUGS + 1] = string.format("%s (%s) %s", id, severity, desc)
end

print("\n=========================================================================")
print("W123 Mining / GBT parity audit — lunarblock")
print("Source: src/rpc.lua, src/mining.lua, src/mempool.lua, src/consensus.lua")
print("Reference: bitcoin-core/src/node/miner.cpp, src/rpc/mining.cpp")
print("=========================================================================")

-- ---------------------------------------------------------------------------
-- G1: getblocktemplate RPC method registered
-- ---------------------------------------------------------------------------
print("\n--- G1: getblocktemplate RPC method registered (PRESENT) ---")
test("G1: rpc.lua registers self.methods[\"getblocktemplate\"]", function()
  expect_match(RPC_SRC, 'self%.methods%["getblocktemplate"%]',
    "getblocktemplate handler missing")
end)

-- ---------------------------------------------------------------------------
-- G2: mode=template default (implicit)
-- ---------------------------------------------------------------------------
print("\n--- G2: mode=template default (PRESENT — implicit) ---")
test("G2: getblocktemplate handler treats absent mode as template", function()
  -- Handler always calls create_block_template; OK because absence of mode
  -- == default 'template' per BIP-22.
  expect_match(RPC_SRC, 'rpc%.mining%.create_block_template%(',
    "create_block_template not called from getblocktemplate handler")
end)

-- ---------------------------------------------------------------------------
-- G3: mode=proposal (BIP-23) — BUG-1 (P0-RPC)
-- ---------------------------------------------------------------------------
print("\n--- G3: GBT mode=proposal (BIP-23) — expect MISSING ---")
test_xfail_pre_fix("G3: rpc.lua getblocktemplate handler parses params[1].mode",
  function()
    -- Look for "proposal" string match inside the getblocktemplate handler
    -- body specifically.  Currently the only "proposal" mention is in
    -- mining.lua's `capabilities = {"proposal"}` (advertised back to client),
    -- NOT a handler-side check for params[1].mode == "proposal".
    -- Find the handler block start; check from there to "self.methods[" next.
    local start = RPC_SRC:find('self%.methods%["getblocktemplate"%]', 1, false)
    expect_true(start, "getblocktemplate handler not found")
    -- Window up to next method registration or end-of-function.
    local window_end = RPC_SRC:find('self%.methods%[', start + 40)
    local body = RPC_SRC:sub(start, window_end or (start + 4000))
    expect_match(body, 'params%[1%]%.mode',
      "params[1].mode never read in getblocktemplate handler — BIP-23 proposal mode missing")
  end, "BUG-1")

-- ---------------------------------------------------------------------------
-- G4: enforces segwit rule client-side — BUG-2 (P1-RPC)
-- ---------------------------------------------------------------------------
print("\n--- G4: GBT enforces client \"segwit\" rule — expect MISSING ---")
test_xfail_pre_fix("G4: rpc.lua getblocktemplate handler parses params[1].rules",
  function()
    local start = RPC_SRC:find('self%.methods%["getblocktemplate"%]', 1, false)
    expect_true(start, "getblocktemplate handler not found")
    local window_end = RPC_SRC:find('self%.methods%[', start + 40)
    local body = RPC_SRC:sub(start, window_end or (start + 4000))
    expect_match(body, 'params%[1%]%.rules',
      "params[1].rules never read; cannot enforce setClientRules.contains(\"segwit\")")
  end, "BUG-2")

-- ---------------------------------------------------------------------------
-- G5: longpollid field — BUG-3 (P1-RPC)
-- ---------------------------------------------------------------------------
print("\n--- G5: GBT longpollid field — expect MISSING ---")
test_xfail_pre_fix("G5: mining.lua template object has longpollid key",
  function()
    expect_match(MINING_SRC, 'longpollid',
      "longpollid not emitted in template; BIP-22 §Long Polling")
  end, "BUG-3")

-- ---------------------------------------------------------------------------
-- G6: IBD / connection-count guard — BUG-4 (P1-RPC)
-- ---------------------------------------------------------------------------
print("\n--- G6: GBT IBD / connection-count guard — expect MISSING ---")
test_xfail_pre_fix("G6: getblocktemplate handler checks IBD before returning template",
  function()
    local start = RPC_SRC:find('self%.methods%["getblocktemplate"%]', 1, false)
    expect_true(start, "getblocktemplate handler not found")
    local window_end = RPC_SRC:find('self%.methods%[', start + 40)
    local body = RPC_SRC:sub(start, window_end or (start + 4000))
    expect_true(body:find('initial.download') or body:find('IBD') or
                body:find('isInitialBlockDownload') or body:find('in_ibd'),
      "no IBD guard in getblocktemplate handler — Core mining.cpp:766-775")
  end, "BUG-4")

-- ---------------------------------------------------------------------------
-- G7: bits from GetNextWorkRequired (retarget) — BUG-5 (P1-RPC)
-- ---------------------------------------------------------------------------
print("\n--- G7: GBT bits via GetNextWorkRequired — expect PARTIAL ---")
test_xfail_pre_fix("G7: mining.lua create_block_template calls get_next_work_required",
  function()
    expect_match(MINING_SRC, 'get_next_work_required',
      "consensus.get_next_work_required helper exists (consensus.lua:401) but " ..
      "mining.lua:382 reads prev_header.bits directly — dead-helper-at-call-site")
  end, "BUG-5")

test("G7-confession: mining.lua:382 reads prev_header.bits directly", function()
  -- This is the comment that confesses BUG-5 — keep the test asserting the
  -- regression marker stays visible until the fix lands.
  expect_match(MINING_SRC, 'In a real implementation, compute next required bits',
    "BUG-5 confession comment removed without fix? mining.lua:383")
end)

-- ---------------------------------------------------------------------------
-- G8: mintime honors BIP-94 timewarp — BUG-6 (P1-RPC)
-- ---------------------------------------------------------------------------
print("\n--- G8: GBT mintime BIP-94 timewarp clause — expect PARTIAL ---")
test_xfail_pre_fix("G8: mining.lua references MAX_TIMEWARP in mintime computation",
  function()
    -- MAX_TIMEWARP = 600 declared in consensus.lua:41 but unused by mining.lua.
    expect_match(MINING_SRC, 'MAX_TIMEWARP',
      "MAX_TIMEWARP not referenced in mining path; mintime missing BIP-94 clause")
  end, "BUG-6")

test("G8: MAX_TIMEWARP constant exists in consensus.lua (dead-helper)", function()
  expect_match(CONSENSUS_SRC, 'M%.MAX_TIMEWARP%s*=%s*600',
    "MAX_TIMEWARP should be 600 per BIP-94")
end)

-- ---------------------------------------------------------------------------
-- G9: mtp from chain state — BUG-7 (P1-RPC)
-- ---------------------------------------------------------------------------
print("\n--- G9: GBT mtp from chain state (not os.time-3600 fallback) — expect MISSING ---")
test_xfail_pre_fix("G9: mining.lua does NOT use `os.time() - 3600` as MTP fallback",
  function()
    expect_no_match(MINING_SRC, 'os%.time%(%) %- 3600',
      "mining.lua:267 falls back to os.time() - 3600 when chain_state.mtp is unset — wrong MTP")
  end, "BUG-7")

test("G9: utxo.lua provides compute_mtp_from_storage helper (dead-helper-at-call-site)",
  function()
    local UTXO_SRC = read_file("src/utxo.lua")
    expect_match(UTXO_SRC, 'compute_mtp_from_storage',
      "compute_mtp_from_storage helper should exist in utxo.lua for use by mining path")
  end)

-- ---------------------------------------------------------------------------
-- G10: transactions[i].sigops accurate — BUG-8 (P1-RPC)
-- ---------------------------------------------------------------------------
print("\n--- G10: GBT transactions[i].sigops accurate — expect PARTIAL ---")
test_xfail_pre_fix("G10: mining.lua does NOT emit hardcoded sigops = 0",
  function()
    expect_no_match(MINING_SRC, 'sigops = 0,%s*%-%-',
      "mining.lua:485 emits hardcoded sigops = 0 — BIP-22 spec says clients MUST NOT assume zero")
  end, "BUG-8")

-- ---------------------------------------------------------------------------
-- G11: BIP-22 depends 1-based indexing (PRESENT)
-- ---------------------------------------------------------------------------
print("\n--- G11: GBT BIP-22 depends 1-based indexing (PRESENT) ---")
test("G11: mining.lua tx_index maps txid -> 1-based index", function()
  -- mining.lua:460-463: `for i, entry in ipairs(selected) do tx_index[..] = i end`
  expect_match(MINING_SRC, 'tx_index%[types%.hash256_hex%(entry%.txid%)%] = i',
    "BIP-22 depends 1-based indexing absent")
end)

-- ---------------------------------------------------------------------------
-- G12: default_witness_commitment (PRESENT)
-- ---------------------------------------------------------------------------
print("\n--- G12: GBT default_witness_commitment field (PRESENT) ---")
test("G12: mining.lua template emits default_witness_commitment when segwit active",
  function()
    expect_match(MINING_SRC, 'default_witness_commitment',
      "default_witness_commitment key missing from template object")
  end)

-- ---------------------------------------------------------------------------
-- G13: coinbasevalue (PRESENT)
-- ---------------------------------------------------------------------------
print("\n--- G13: GBT coinbasevalue field (PRESENT) ---")
test("G13: mining.lua template emits coinbasevalue", function()
  expect_match(MINING_SRC, 'coinbasevalue%s*=%s*coinbase_value',
    "coinbasevalue not set to coinbase_value")
end)

-- ---------------------------------------------------------------------------
-- G14: coinbasetxn (BIP-23) — PRESENT (over-emitted)
-- ---------------------------------------------------------------------------
print("\n--- G14: GBT coinbasetxn (BIP-23 optional, PARTIAL — Core only emits coinbasevalue) ---")
test("G14: mining.lua emits coinbasetxn (BIP-23 optional, allowed)", function()
  expect_match(MINING_SRC, 'coinbasetxn',
    "coinbasetxn missing from template (BIP-23 optional)")
end)

-- ---------------------------------------------------------------------------
-- G15: coinbaseaux.flags non-standard — BUG-9 (P2-RPC)
-- ---------------------------------------------------------------------------
print("\n--- G15: GBT coinbaseaux empty obj (no flags key) — expect PARTIAL ---")
test_xfail_pre_fix("G15: mining.lua coinbaseaux is empty object (no `flags` sub-key)",
  function()
    expect_no_match(MINING_SRC, 'coinbaseaux = {flags',
      "mining.lua:433 emits {flags=\"\"} sub-key; Core emits empty object")
  end, "BUG-9")

-- ---------------------------------------------------------------------------
-- G16: rules includes "csv" always (PRESENT)
-- ---------------------------------------------------------------------------
print("\n--- G16: GBT rules includes \"csv\" always (PRESENT) ---")
test("G16: mining.lua rules array starts with {\"csv\"}", function()
  expect_match(MINING_SRC, 'local rules = {"csv"}',
    "rules array doesn't start with csv")
end)

-- ---------------------------------------------------------------------------
-- G17: rules includes "!segwit"/"taproot" post-segwit (PRESENT)
-- ---------------------------------------------------------------------------
print("\n--- G17: GBT rules adds \"!segwit\"/\"taproot\" post-segwit (PRESENT) ---")
test("G17: mining.lua rules adds !segwit and taproot when segwit active", function()
  expect_match(MINING_SRC, '"!segwit"',
    "!segwit rule missing")
  expect_match(MINING_SRC, '"taproot"',
    "taproot rule missing")
end)

-- ---------------------------------------------------------------------------
-- G18: signet_challenge on signet — BUG-10 (P2-RPC)
-- ---------------------------------------------------------------------------
print("\n--- G18: GBT signet_challenge on signet — expect MISSING ---")
test_xfail_pre_fix("G18: consensus.lua has signet network params with signet_challenge",
  function()
    expect_match(CONSENSUS_SRC:lower(), 'signet',
      "no signet network params in consensus.lua")
  end, "BUG-10")

-- ---------------------------------------------------------------------------
-- G19: vbavailable per BIP-9 (PARTIAL — always empty)
-- ---------------------------------------------------------------------------
print("\n--- G19: GBT vbavailable per BIP-9 (PARTIAL — always emits {}) ---")
test("G19: mining.lua emits vbavailable", function()
  expect_match(MINING_SRC, 'vbavailable',
    "vbavailable key absent")
end)

-- ---------------------------------------------------------------------------
-- G20: setClientRules strips active bits if unsupported — BUG-11 (P2-RPC)
-- ---------------------------------------------------------------------------
print("\n--- G20: GBT setClientRules active-bit stripping — expect MISSING ---")
test_xfail_pre_fix("G20: rpc.lua getblocktemplate handler implements client-rule active-bit stripping",
  function()
    local start = RPC_SRC:find('self%.methods%["getblocktemplate"%]', 1, false)
    expect_true(start, "getblocktemplate handler not found")
    local window_end = RPC_SRC:find('self%.methods%[', start + 40)
    local body = RPC_SRC:sub(start, window_end or (start + 4000))
    expect_true(body:find('setClientRules') or body:find('client_rules') or
                body:find('strip.*bits'),
      "no client-rule active-bit stripping; pre-segwit clients get segwit templates")
  end, "BUG-11")

-- ---------------------------------------------------------------------------
-- G21: getmininginfo RPC method registered (PRESENT)
-- ---------------------------------------------------------------------------
print("\n--- G21: getmininginfo RPC method registered (PRESENT) ---")
test("G21: rpc.lua registers self.methods[\"getmininginfo\"]", function()
  expect_match(RPC_SRC, 'self%.methods%["getmininginfo"%]',
    "getmininginfo handler missing")
end)

-- ---------------------------------------------------------------------------
-- G22: getmininginfo.next.bits via NextEmptyBlockIndex — BUG-12 (P2-RPC)
-- ---------------------------------------------------------------------------
print("\n--- G22: getmininginfo.next.bits = next-block bits — expect PARTIAL ---")
test_xfail_pre_fix("G22: rpc.lua getmininginfo computes next.bits via GetNextWorkRequired",
  function()
    -- Locate getmininginfo handler.
    local start = RPC_SRC:find('self%.methods%["getmininginfo"%]', 1, false)
    expect_true(start, "getmininginfo handler not found")
    local window_end = RPC_SRC:find('self%.methods%[', start + 40)
    local body = RPC_SRC:sub(start, window_end or (start + 4000))
    expect_match(body, 'get_next_work_required',
      "getmininginfo.next.bits not computed via get_next_work_required — uses tip's bits")
  end, "BUG-12")

-- ---------------------------------------------------------------------------
-- G23: getmininginfo.networkhashps populated — BUG-13 (P2-RPC)
-- ---------------------------------------------------------------------------
print("\n--- G23: getmininginfo.networkhashps populated — expect MISSING ---")
test_xfail_pre_fix("G23: rpc.lua getmininginfo handler does NOT hardcode networkhashps = 0",
  function()
    local start = RPC_SRC:find('self%.methods%["getmininginfo"%]', 1, false)
    expect_true(start, "getmininginfo handler not found")
    local window_end = RPC_SRC:find('self%.methods%[', start + 40)
    local body = RPC_SRC:sub(start, window_end or (start + 4000))
    expect_no_match(body, 'networkhashps = 0,',
      "rpc.lua:7251 hardcodes networkhashps = 0; Core mining.cpp:472 calls getnetworkhashps")
  end, "BUG-13")

-- ---------------------------------------------------------------------------
-- G24: prioritisetransaction RPC — BUG-14 (P1-RPC)
-- ---------------------------------------------------------------------------
print("\n--- G24: prioritisetransaction RPC — expect MISSING ---")
test_xfail_pre_fix("G24: rpc.lua registers prioritisetransaction method",
  function()
    expect_match(RPC_SRC, 'self%.methods%["prioritisetransaction"%]',
      "prioritisetransaction RPC absent")
  end, "BUG-14")

test_xfail_pre_fix("G24-mempool: mempool.lua has fee_delta plumbing",
  function()
    expect_true(MEMPOOL_SRC:find('fee_delta') or MEMPOOL_SRC:find('prioritise') or
                MEMPOOL_SRC:find('modify_fee'),
      "mempool.lua has no fee_delta / prioritise / modify_fee plumbing")
  end, "BUG-14")

-- ---------------------------------------------------------------------------
-- G25: getprioritisedtransactions RPC — BUG-14 (companion)
-- ---------------------------------------------------------------------------
print("\n--- G25: getprioritisedtransactions RPC — expect MISSING ---")
test_xfail_pre_fix("G25: rpc.lua registers getprioritisedtransactions method",
  function()
    expect_match(RPC_SRC, 'self%.methods%["getprioritisedtransactions"%]',
      "getprioritisedtransactions RPC absent")
  end, "BUG-14")

-- ---------------------------------------------------------------------------
-- G26: submitblock RPC (PRESENT)
-- ---------------------------------------------------------------------------
print("\n--- G26: submitblock RPC (PRESENT) ---")
test("G26: rpc.lua registers self.methods[\"submitblock\"]", function()
  expect_match(RPC_SRC, 'self%.methods%["submitblock"%]',
    "submitblock RPC missing")
end)

-- ---------------------------------------------------------------------------
-- G27: submitblock BIP-22 result strings (PRESENT)
-- ---------------------------------------------------------------------------
print("\n--- G27: submitblock BIP-22 result strings (PRESENT) ---")
test("G27: rpc.lua has bip22_result mapper", function()
  expect_match(RPC_SRC, 'local function bip22_result',
    "bip22_result mapper missing")
  -- Check canonical short-codes are present.
  for _, k in ipairs({
    'duplicate', 'inconclusive', 'high%-hash', 'bad%-txnmrklroot',
    'bad%-witness%-merkle%-match', 'bad%-cb%-amount', 'bad%-cb%-height',
    'bad%-txns%-nonfinal', 'bad%-txns%-duplicate'
  }) do
    expect_match(RPC_SRC, '"' .. k .. '"', "BIP22 result code missing: " .. k)
  end
end)

-- ---------------------------------------------------------------------------
-- G28: submitheader RPC — BUG-15 (P1-RPC)
-- ---------------------------------------------------------------------------
print("\n--- G28: submitheader RPC — expect MISSING ---")
test_xfail_pre_fix("G28: rpc.lua registers submitheader method",
  function()
    expect_match(RPC_SRC, 'self%.methods%["submitheader"%]',
      "submitheader RPC absent — Core mining.cpp:1108-1146")
  end, "BUG-15")

-- ---------------------------------------------------------------------------
-- G29: generatetoaddress RPC (PRESENT)
-- ---------------------------------------------------------------------------
print("\n--- G29: generatetoaddress RPC (PRESENT) ---")
test("G29: rpc.lua registers self.methods[\"generatetoaddress\"]", function()
  expect_match(RPC_SRC, 'self%.methods%["generatetoaddress"%]',
    "generatetoaddress RPC missing")
end)

-- ---------------------------------------------------------------------------
-- G30: generatetoaddress honors maxtries — BUG-16 (P2-RPC)
-- ---------------------------------------------------------------------------
print("\n--- G30: generatetoaddress honors maxtries (params[3]) — expect MISSING ---")
test_xfail_pre_fix("G30: rpc.lua generatetoaddress reads params[3] as maxtries",
  function()
    local start = RPC_SRC:find('self%.methods%["generatetoaddress"%]', 1, false)
    expect_true(start, "generatetoaddress handler not found")
    local window_end = RPC_SRC:find('self%.methods%[', start + 40)
    local body = RPC_SRC:sub(start, window_end or (start + 4000))
    expect_true(body:find('params%[3%]') or body:find('maxtries'),
      "generatetoaddress does NOT read params[3]/maxtries; Core default DEFAULT_MAX_TRIES=1_000_000")
  end, "BUG-16")

-- ---------------------------------------------------------------------------
-- Source-level absence invariant — protects against drive-by stub additions.
-- Each invariant asserts the CURRENT state until the fix lands.  When a fix
-- closes a gap, flip the invariant from `expect_no_match` -> `expect_match`.
-- ---------------------------------------------------------------------------

print("\n--- Source-level invariants (drive-by stub guards) ---")
test("INV-1: mining.lua tx_index 1-based starts at i=1 (BIP-22)", function()
  -- The pattern `for i, entry in ipairs(selected) do tx_index[...] = i end`
  -- must keep `i` from `ipairs`, which is 1-based.  Switching to `i - 1` would
  -- regress to a 0-based map and the depends array would be off-by-one.
  expect_match(MINING_SRC, 'for i, entry in ipairs%(selected%)',
    "tx_index loop changed shape — BIP-22 depends indexing may have regressed")
end)

test("INV-2: ClampOptions semantics preserved (mining.lua:215-237)", function()
  expect_match(MINING_SRC, 'MINIMUM_BLOCK_RESERVED_WEIGHT',
    "MINIMUM_BLOCK_RESERVED_WEIGHT (=2000) constant removed?")
  expect_match(MINING_SRC, 'DEFAULT_BLOCK_RESERVED_WEIGHT',
    "DEFAULT_BLOCK_RESERVED_WEIGHT (=8000) constant removed?")
end)

test("INV-3: coinbase nLockTime = height - 1 (BIP-94 anti-fee-sniping)", function()
  expect_match(MINING_SRC, 'coinbase_locktime = %(height > 0%) and %(height %- 1%)',
    "coinbase_locktime calculation regressed — Core miner.cpp:196")
end)

test("INV-4: coinbase sequence MAX_SEQUENCE_NONFINAL (0xFFFFFFFE)", function()
  expect_match(MINING_SRC, 'MAX_SEQUENCE_NONFINAL%s*=%s*0xFFFFFFFE',
    "MAX_SEQUENCE_NONFINAL constant regressed — Core miner.cpp:171")
end)

test("INV-5: MAX_CONSECUTIVE_FAILURES early-exit preserved (miner.cpp:284)", function()
  expect_match(MINING_SRC, 'MAX_CONSECUTIVE_FAILURES%s*=%s*1000',
    "MAX_CONSECUTIVE_FAILURES (=1000) gate regressed")
  expect_match(MINING_SRC, 'BLOCK_FULL_ENOUGH_WEIGHT_DELTA%s*=%s*4000',
    "BLOCK_FULL_ENOUGH_WEIGHT_DELTA (=4000) gate regressed")
end)

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------

print("\n=========================================================================")
print(string.format("W123 SUMMARY: %d PASS, %d FAIL, %d XFAIL (pre-fix expected)",
  PASS, FAIL, XFAIL_PRE_FIX))
print(string.format("Status: %s",
  FAIL == 0 and "W123 audit complete — 16 bugs catalogued"
  or "UNEXPECTED FAILURES — investigate"))
print("=========================================================================")

-- Record bugs.
bug("BUG-1",  "P0-RPC", "GBT mode=proposal silently treated as new-template request")
bug("BUG-2",  "P1-RPC", "GBT does not enforce client setClientRules.contains(\"segwit\")")
bug("BUG-3",  "P1-RPC", "longpollid field missing from template response (BIP-22)")
bug("BUG-4",  "P1-RPC", "GBT no IBD / connection-count guard")
bug("BUG-5",  "P1-RPC", "GBT bits = prev_header.bits, not GetNextWorkRequired")
bug("BUG-6",  "P1-RPC", "GBT mintime missing BIP-94 timewarp clause on retarget")
bug("BUG-7",  "P1-RPC", "chain_state.mtp never populated; fallback os.time-3600 wrong")
bug("BUG-8",  "P1-RPC", "GBT transactions[i].sigops hardcoded 0")
bug("BUG-9",  "P2-RPC", "coinbaseaux={flags=\"\"} non-standard; Core emits empty obj")
bug("BUG-10", "P2-RPC", "No signet network params; signet_challenge never emitted")
bug("BUG-11", "P2-RPC", "setClientRules never parsed; rule active-bit stripping absent")
bug("BUG-12", "P2-RPC", "getmininginfo.next.bits = current bits, not next")
bug("BUG-13", "P2-RPC", "getmininginfo.networkhashps hardcoded 0")
bug("BUG-14", "P1-RPC", "prioritisetransaction + getprioritisedtransactions both missing")
bug("BUG-15", "P1-RPC", "submitheader RPC missing entirely")
bug("BUG-16", "P2-RPC", "generatetoaddress ignores params[3] maxtries")

print("\nBugs catalogued:")
for _, b in ipairs(BUGS) do print("  " .. b) end

-- Discovery-wave exit code: 0 on no UNEXPECTED failures; XFAILs are advisory.
if FAIL > 0 then os.exit(1) end
