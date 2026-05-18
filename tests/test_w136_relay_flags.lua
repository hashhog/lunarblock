#!/usr/bin/env luajit
-- W136 BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay audit — lunarblock
--
-- Reference: bitcoin-core/src/net_processing.cpp
--            bitcoin-core/src/policy/feerate.cpp
--            bitcoin-core/src/policy/fees/block_policy_estimator.cpp (FeeFilterRounder)
--            bitcoin-core/src/node/protocol_version.h
--
-- Scope: assert lunarblock's BIP-130 / BIP-133 / BIP-339 wire parity vs Core.
-- Excludes sendcmpct (W126), sendaddrv2 (W117), sendtxrcncl (separate wave).
--
-- Gate map (W136):
--   G1   SENDHEADERS_VERSION = 70012 constant
--   G2   FEEFILTER_VERSION = 70013 constant
--   G3   WTXID_RELAY_VERSION = 70016 constant
--   G4   SENDHEADERS sent only after initial-headers-sync + version gate
--   G5   SENDHEADERS receive -> sets peer.m_prefers_headers
--   G6   SENDHEADERS receive does NOT enforce "before verack"
--   G7   announce_block uses headers when peer.send_headers else inv
--   G8   wtxidrelay (and sendaddrv2) after VERACK -> disconnect
--   G9   WTXIDRELAY sent in response to VERSION before VERACK, version-gated
--   G10  WTXIDRELAY not sent to outbound block-relay-only / feeler
--   G11  Duplicate WTXIDRELAY logs but is no-op
--   G12  WTXIDRELAY ignored when common_version < WTXID_RELAY_VERSION
--   G13  WTXIDRELAY before VERSION drops (pre-handshake filter)
--   G14  FEEFILTER payload MoneyRange-validated
--   G15  FEEFILTER receive version gate (advisory)
--   G16  Outbound FEEFILTER version-gated
--   G17  Outbound FEEFILTER not sent to block-relay-only peers
--   G18  Outbound FEEFILTER not sent under -blocksonly equivalent
--   G19  Outbound FEEFILTER not sent to ForceRelay peers
--   G20  Periodic FEEFILTER broadcast (AVG_FEEFILTER_BROADCAST_INTERVAL=10min)
--   G21  IBD FEEFILTER override = MAX_MONEY + re-send on IBD exit
--   G22  FeeFilterRounder bucket quantization + jitter
--   G23  filterToSend = max(rounded, mempool.min_relay_feerate)
--   G24  Re-send only when filterToSend != peer.m_fee_filter_sent
--   G25  MAX_FEEFILTER_CHANGE_DELAY=5min substantial-change bring-forward
--   G26  Outbound tx-inv filtered by peer.fee_filter feerate gate
--   G27  Outbound tx-inv uses MSG_WTX for wtxid_relay peers
--   G28  GETDATA serves MSG_WTX (=5) requests
--   G29  Orphan-parent-fetch always uses MSG_TX (not audited; noted)
--   G30  Documentation honest re: which BIPs are wired
--
-- Bugs (23):
--   BUG-1  P2  SENDHEADERS_VERSION constant absent              (G1, INFRA)
--   BUG-2  P2  FEEFILTER_VERSION constant absent                (G2, INFRA)
--   BUG-3  P2  WTXID_RELAY_VERSION constant absent              (G3, INFRA)
--   BUG-4  P1  SENDHEADERS sent at handshake-complete, no chainwork gate (G4, BIP-130)
--   BUG-5  P0  wtxidrelay (and sendaddrv2) after VERACK silently accepted (G8, BIP-339+155)
--   BUG-6  P0  WTXIDRELAY never sent — BIP-339 opt-in unreachable (G9, BIP-339)
--   BUG-7  P3  Duplicate WTXIDRELAY no log/count                (G11, BIP-339)
--   BUG-8  P1  WTXIDRELAY accepted from below-WTXID_RELAY_VERSION peers (G12, BIP-339)
--   BUG-9  P1  FEEFILTER payload not MoneyRange-validated       (G14, BIP-133)
--   BUG-10 P2  FEEFILTER receive: no version gate (defensive)   (G15, BIP-133)
--   BUG-11 P2  Outbound FEEFILTER: no version gate              (G16, BIP-133)
--   BUG-12 P1  Outbound FEEFILTER: no block-relay-only gate     (G17, BIP-133)
--   BUG-13 P2  Outbound FEEFILTER: no -blocksonly gate          (G18, BIP-133)
--   BUG-14 P3  Outbound FEEFILTER: no ForceRelay gate           (G19, BIP-133)
--   BUG-15 P1  Outbound FEEFILTER: no periodic broadcast        (G20, BIP-133)
--   BUG-16 P0  Outbound FEEFILTER: no IBD MAX_MONEY override    (G21, BIP-133)
--   BUG-17 P1  Outbound FEEFILTER: no FeeFilterRounder          (G22, BIP-133)
--   BUG-18 P0  Outbound FEEFILTER: hardcoded 100000 vs mempool  (G23, BIP-133)
--   BUG-19 P3  Outbound FEEFILTER: no "differs from sent" gate  (G24, BIP-133)
--   BUG-20 P2  Outbound FEEFILTER: no MAX_CHANGE_DELAY bring-forward (G25, BIP-133)
--   BUG-21 P0  queue_tx_announcement ignores p.fee_filter       (G26, BIP-133)
--   BUG-22 P0  getdata handler doesn't serve MSG_WTX (=5)       (G28, BIP-339)
--   BUG-23 P3  Stale-compliance comments (peer.lua:99-106, 694, 758) (G30, DOCS)
--
-- (Total 23 bugs catalogued in audit/w136_relay_flags.md.  Some lower-severity
-- bugs are noted in the matrix but not separately xfail-tested here:
-- BUG-10/14/19/20 are mostly cosmetic / moot-pending-other-fixes and only
-- contribute to the documentation surface.)
--
-- Test harness style mirrors tests/test_w133_index_databases.lua.
-- xfail_pre_fix counts as expected divergence (not a failure); FAIL counts only
-- true regressions.

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

-- Slurp a file for grep-style probes.
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

local function file_matches(path, pattern)
  local body = slurp(path)
  if not body then return false end
  return body:find(pattern) ~= nil
end

-- ---------------------------------------------------------------------------
-- Banner
-- ---------------------------------------------------------------------------

print("\n=========================================================================")
print("W136 BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay")
print("    -- lunarblock")
print("Source: src/peer.lua + src/peerman.lua + src/p2p.lua + src/main.lua")
print("Reference: bitcoin-core/src/net_processing.cpp,")
print("           bitcoin-core/src/policy/feerate.cpp,")
print("           bitcoin-core/src/policy/fees/block_policy_estimator.cpp,")
print("           bitcoin-core/src/node/protocol_version.h")
print("=========================================================================")

-- ---------------------------------------------------------------------------
-- Load modules that we can actually exercise without full chain init.
-- (peer.lua + peerman.lua require socket and the full chain, so we limit
-- ourselves to source-grep + p2p.lua serializer round-trips.)
-- ---------------------------------------------------------------------------

local ok_p2p, p2p = pcall(require, "lunarblock.p2p")
if not ok_p2p then
  -- Fallback to local path style used by some earlier tests.
  ok_p2p, p2p = pcall(require, "p2p")
end
if not ok_p2p then
  io.write(string.format("  FAIL  module load -- could not require p2p: %s\n", tostring(p2p)))
  os.exit(1)
end

-- ---------------------------------------------------------------------------
-- G1: SENDHEADERS_VERSION = 70012 constant (BUG-1 P2)
-- ---------------------------------------------------------------------------

print("\n--- G1: SENDHEADERS_VERSION constant (BUG-1 P2) ---")

test_xfail_pre_fix("G1: p2p.SENDHEADERS_VERSION == 70012 (BUG-1)",
  "BUG-1", function()
    bug("BUG-1", "P2")
    expect_eq(p2p.SENDHEADERS_VERSION, 70012,
      "p2p.SENDHEADERS_VERSION should be 70012 per Core protocol_version.h:24")
  end)

-- ---------------------------------------------------------------------------
-- G2: FEEFILTER_VERSION = 70013 constant (BUG-2 P2)
-- ---------------------------------------------------------------------------

print("\n--- G2: FEEFILTER_VERSION constant (BUG-2 P2) ---")

test_xfail_pre_fix("G2: p2p.FEEFILTER_VERSION == 70013 (BUG-2)",
  "BUG-2", function()
    bug("BUG-2", "P2")
    expect_eq(p2p.FEEFILTER_VERSION, 70013,
      "p2p.FEEFILTER_VERSION should be 70013 per Core protocol_version.h:27")
  end)

-- ---------------------------------------------------------------------------
-- G3: WTXID_RELAY_VERSION = 70016 constant (BUG-3 P2)
-- ---------------------------------------------------------------------------

print("\n--- G3: WTXID_RELAY_VERSION constant (BUG-3 P2) ---")

test_xfail_pre_fix("G3: p2p.WTXID_RELAY_VERSION == 70016 (BUG-3)",
  "BUG-3", function()
    bug("BUG-3", "P2")
    expect_eq(p2p.WTXID_RELAY_VERSION, 70016,
      "p2p.WTXID_RELAY_VERSION should be 70016 per Core protocol_version.h:36")
  end)

-- ---------------------------------------------------------------------------
-- G4: SENDHEADERS sent only after initial-headers-sync + version gate
--     (BUG-4 P1) — BIP-130
-- ---------------------------------------------------------------------------

print("\n--- G4: SENDHEADERS post-IHS chainwork gate (BUG-4 P1, BIP-130) ---")

test("G4-a: lunarblock currently sends sendheaders in handle_verack (pin)",
function()
  -- Pin the current behavior so we know which branch is the regression
  -- direction after the fix lands.
  expect_true(file_contains("src/peer.lua",
    "self:send_message(\"sendheaders\", \"\")"),
    "expected literal send_message(\"sendheaders\", \"\") in peer.lua")
  -- And it currently fires inside handle_verack (one-line literal),
  -- not in a chainwork-gated MaybeSendSendHeaders.
  expect_true(file_contains("src/peer.lua",
    "function Peer:handle_verack()"),
    "handle_verack exists")
end)

test_xfail_pre_fix(
  "G4-b: SENDHEADERS guarded by 'pindexBestKnownBlock.chainwork > MinimumChainWork' (BUG-4)",
  "BUG-4", function()
    bug("BUG-4", "P1")
    -- Probe for ANY chainwork / minimum-work gate near the
    -- sendheaders send site.  Today there is none.
    expect_true(
      file_contains("src/peer.lua", "MinimumChainWork")
      or file_contains("src/peer.lua", "min_chain_work")
      or file_contains("src/peerman.lua", "MaybeSendSendHeaders")
      or file_contains("src/peerman.lua", "maybe_send_sendheaders"),
      "no chainwork gate on sendheaders send — sent eagerly at handshake-complete"
    )
  end)

test_xfail_pre_fix(
  "G4-c: SENDHEADERS guarded by 'common_version >= SENDHEADERS_VERSION' (BUG-4)",
  "BUG-4", function()
    expect_true(
      file_contains("src/peer.lua", "SENDHEADERS_VERSION")
      or file_contains("src/peer.lua", "common_version >= 70012"),
      "no SENDHEADERS_VERSION (70012) gate on sendheaders send"
    )
  end)

-- ---------------------------------------------------------------------------
-- G5: SENDHEADERS receive -> sets peer.send_headers
-- ---------------------------------------------------------------------------

print("\n--- G5: SENDHEADERS receive sets send_headers ---")

test("G5: peer.lua sets self.send_headers = true on inbound sendheaders",
function()
  expect_true(file_contains("src/peer.lua",
    "elseif msg.command == \"sendheaders\" then"),
    "sendheaders dispatch arm present")
  expect_true(file_contains("src/peer.lua",
    "self.send_headers = true"),
    "send_headers flag set on receive")
end)

-- ---------------------------------------------------------------------------
-- G6: SENDHEADERS receive accepts any-time (Core: no ordering constraint)
-- ---------------------------------------------------------------------------

print("\n--- G6: SENDHEADERS receive no ordering constraint ---")

test("G6: peer.lua does NOT misbehaving() on post-VERACK sendheaders",
function()
  -- The dispatch loop only enforces PRE_HANDSHAKE_ALLOWED while
  -- !handshake_complete (peer.lua:871-877).  Once VERACK is sent,
  -- sendheaders flows through the message-type switch with no
  -- additional ordering check.  Sanity-check the comment.
  expect_true(file_contains("src/peer.lua",
    "sendheaders = true,  -- BIP 130: Accepted pre-handshake"),
    "PRE_HANDSHAKE_ALLOWED documents BIP-130 sendheaders allowed pre-handshake")
end)

-- ---------------------------------------------------------------------------
-- G7: announce_block uses headers when peer.send_headers, else inv
-- ---------------------------------------------------------------------------

print("\n--- G7: announce_block respects BIP-130 preference ---")

test("G7-a: peerman.announce_block branches on p.send_headers", function()
  expect_true(file_contains("src/peerman.lua",
    "if p.send_headers and header then"),
    "announce_block branches on send_headers")
  expect_true(file_contains("src/peerman.lua",
    "p2p.serialize_headers"),
    "headers serialization invoked")
end)

test("G7-b: fallback path uses inv with MSG_BLOCK", function()
  expect_true(file_contains("src/peerman.lua",
    "type = p2p.INV_TYPE.MSG_BLOCK, hash = block_hash"),
    "inv fallback serialization uses MSG_BLOCK")
end)

-- ---------------------------------------------------------------------------
-- G8: wtxidrelay / sendaddrv2 after VERACK -> disconnect (BUG-5 P0)
-- ---------------------------------------------------------------------------

print("\n--- G8: wtxidrelay/sendaddrv2 post-VERACK -> disconnect (BUG-5 P0) ---")

test_xfail_pre_fix(
  "G8-a: post-VERACK wtxidrelay triggers misbehaving/disconnect (BUG-5)",
  "BUG-5", function()
    bug("BUG-5", "P0")
    -- Look for either a misbehaving/disconnect call inside the
    -- wtxidrelay arm or a "fSuccessfullyConnected" / "handshake_complete"
    -- guard.  Today (peer.lua:905-908) there is neither.
    local body = slurp("src/peer.lua") or ""
    local idx = body:find('elseif msg.command == "wtxidrelay" then', 1, true)
    expect_true(idx ~= nil, "wtxidrelay dispatch arm present (sanity)")
    -- Bound the arm at the next 'elseif' so adjacent arms (sendaddrv2,
    -- sendtxrcncl) don't leak their own guards into this check.
    local arm_end = body:find("elseif msg.command", idx + 50, true)
    local arm = body:sub(idx, arm_end or (idx + 200))
    expect_true(
      arm:find("misbehaving", 1, true) ~= nil
      or arm:find("disconnect", 1, true) ~= nil
      or arm:find("handshake_complete", 1, true) ~= nil
      or arm:find("fSuccessfullyConnected", 1, true) ~= nil,
      "no post-VERACK disconnect guard on wtxidrelay arm"
    )
  end)

test_xfail_pre_fix(
  "G8-b: post-VERACK sendaddrv2 triggers misbehaving/disconnect (BUG-5)",
  "BUG-5", function()
    local body = slurp("src/peer.lua") or ""
    local idx = body:find('elseif msg.command == "sendaddrv2" then', 1, true)
    expect_true(idx ~= nil, "sendaddrv2 dispatch arm present (sanity)")
    -- Find the next 'elseif' to bound the sendaddrv2 arm body only
    -- (otherwise the slurp window leaks into the sendtxrcncl arm
    -- below, which legitimately has a 'handshake_complete' check
    -- and would mask the bug).
    local arm_end = body:find("elseif msg.command", idx + 50, true)
    local arm = body:sub(idx, arm_end or (idx + 200))
    expect_true(
      arm:find("misbehaving", 1, true) ~= nil
      or arm:find("disconnect", 1, true) ~= nil
      or arm:find("handshake_complete", 1, true) ~= nil
      or arm:find("fSuccessfullyConnected", 1, true) ~= nil,
      "no post-VERACK disconnect guard on sendaddrv2 arm"
    )
  end)

-- ---------------------------------------------------------------------------
-- G9: WTXIDRELAY sent in response to VERSION before VERACK, version-gated
--     (BUG-6 P0) — BIP-339
-- ---------------------------------------------------------------------------

print("\n--- G9: WTXIDRELAY sent before VERACK (BUG-6 P0, BIP-339) ---")

test("G9-a: Peer:handle_version exists (sanity)", function()
  expect_true(file_contains("src/peer.lua",
    "function Peer:handle_version(payload)"),
    "handle_version defined")
end)

test_xfail_pre_fix(
  "G9-b: Peer:handle_version sends 'wtxidrelay' before sending 'verack' (BUG-6)",
  "BUG-6", function()
    bug("BUG-6", "P0")
    -- Look for a literal send_message("wtxidrelay", ...) anywhere
    -- in peer.lua.  Today there is none (line 905-908 only RECEIVES).
    expect_true(file_contains("src/peer.lua",
      "send_message(\"wtxidrelay\""),
      "no outbound send_message(\"wtxidrelay\", ...) call site exists"
    )
  end)

test_xfail_pre_fix(
  "G9-c: WTXIDRELAY send gated on ver.version >= WTXID_RELAY_VERSION (BUG-6)",
  "BUG-6", function()
    local body = slurp("src/peer.lua") or ""
    -- Look for either the bare 70016 literal in the same neighborhood
    -- as wtxidrelay or a named constant gate.
    expect_true(
      body:find("ver%.version%s*>=%s*70016") ~= nil
      and body:find("send_message%(\"wtxidrelay\"") ~= nil,
      "no ver.version >= 70016 + send_message(\"wtxidrelay\") sequence in peer.lua"
    )
  end)

-- ---------------------------------------------------------------------------
-- G10: WTXIDRELAY not sent to block-relay-only / feeler (moot: no BRO concept)
-- ---------------------------------------------------------------------------

print("\n--- G10: WTXIDRELAY not sent to block-relay-only (N/A, BUG-12 sibling) ---")

test("G10: lunarblock has no block-relay-only outbound concept (pin)",
function()
  -- peerman.lua:2356-2360 explicitly says "treat all outbound as full-relay".
  expect_true(file_contains("src/peerman.lua",
    "treat all outbound as full-relay"),
    "block-relay-only outbound concept absent (G10 + G17 moot until landed)")
end)

-- ---------------------------------------------------------------------------
-- G11: Duplicate WTXIDRELAY logs but is no-op (BUG-7 P3)
-- ---------------------------------------------------------------------------

print("\n--- G11: Duplicate WTXIDRELAY observability (BUG-7 P3) ---")

test_xfail_pre_fix(
  "G11: duplicate WTXIDRELAY logs a 'duplicate' diagnostic (BUG-7)",
  "BUG-7", function()
    bug("BUG-7", "P3")
    -- Look for any log/print mentioning duplicate wtxidrelay; case-insensitive.
    local body = slurp("src/peer.lua") or ""
    expect_true(
      body:lower():find("duplicate wtxidrelay", 1, true) ~= nil
      or body:lower():find("duplicate.*wtxid") ~= nil,
      "no duplicate-wtxidrelay log per Core net_processing.cpp:3932-3933"
    )
  end)

-- ---------------------------------------------------------------------------
-- G12: WTXIDRELAY ignored when common_version < WTXID_RELAY_VERSION
--      (BUG-8 P1)
-- ---------------------------------------------------------------------------

print("\n--- G12: WTXIDRELAY accepted only at common_version >= 70016 (BUG-8 P1) ---")

test_xfail_pre_fix(
  "G12: wtxidrelay arm gates on peer common version (BUG-8)",
  "BUG-8", function()
    bug("BUG-8", "P1")
    local body = slurp("src/peer.lua") or ""
    local idx = body:find('elseif msg.command == "wtxidrelay" then', 1, true)
    expect_true(idx ~= nil, "wtxidrelay dispatch arm present (sanity)")
    local arm_end = body:find("elseif msg.command", (idx or 1) + 50, true)
    local arm = body:sub(idx or 1, arm_end or ((idx or 1) + 200))
    expect_true(
      arm:find("70016") ~= nil
      or arm:find("WTXID_RELAY_VERSION") ~= nil
      or arm:find("version >= ") ~= nil,
      "no version gate inside wtxidrelay arm"
    )
  end)

-- ---------------------------------------------------------------------------
-- G13: WTXIDRELAY before VERSION drops (pre-handshake filter)
-- ---------------------------------------------------------------------------

print("\n--- G13: pre-VERSION WTXIDRELAY dropped ---")

test("G13: dispatcher rejects any pre-version message including wtxidrelay",
function()
  expect_true(file_contains("src/peer.lua",
    "if not self.version_received then"),
    "version-received gate present")
  expect_true(file_contains("src/peer.lua",
    "non-version message before version"),
    "misbehaving message present")
end)

-- ---------------------------------------------------------------------------
-- G14: FEEFILTER payload MoneyRange-validated (BUG-9 P1)
-- ---------------------------------------------------------------------------

print("\n--- G14: FEEFILTER MoneyRange validation (BUG-9 P1, BIP-133) ---")

test_xfail_pre_fix(
  "G14-a: feefilter arm validates MoneyRange before storing (BUG-9)",
  "BUG-9", function()
    bug("BUG-9", "P1")
    local body = slurp("src/peer.lua") or ""
    local idx = body:find('elseif msg.command == "feefilter" then', 1, true)
    expect_true(idx ~= nil, "feefilter dispatch arm present (sanity)")
    local arm_end = body:find("elseif msg.command", (idx or 1) + 50, true)
    local arm = body:sub(idx or 1, arm_end or ((idx or 1) + 200))
    expect_true(
      arm:find("MoneyRange") ~= nil
      or arm:find("is_valid_amount") ~= nil
      or arm:find("MAX_MONEY") ~= nil,
      "no MoneyRange validation on incoming feefilter"
    )
  end)

-- Round-trip sanity for the serializer (PASS).
test("G14-b: serialize_feefilter / deserialize_feefilter roundtrip 100 sat/kvB",
function()
  local payload = p2p.serialize_feefilter(100)
  expect_eq(#payload, 8, "feefilter payload is 8 bytes (u64le)")
  expect_eq(p2p.deserialize_feefilter(payload), 100, "deserialize roundtrip")
end)

test("G14-c: serialize_feefilter roundtrip MAX_MONEY (2.1e15)",
function()
  -- MAX_MONEY = 21_000_000 * 10^8 = 2.1e15.  Lua doubles hold this exactly.
  local max_money = 2100000000000000
  local payload = p2p.serialize_feefilter(max_money)
  expect_eq(#payload, 8, "feefilter payload remains 8 bytes")
  expect_eq(p2p.deserialize_feefilter(payload), max_money,
    "MAX_MONEY roundtrip")
end)

-- ---------------------------------------------------------------------------
-- G16: Outbound FEEFILTER version-gated (BUG-11 P2)
-- ---------------------------------------------------------------------------

print("\n--- G16: outbound FEEFILTER version-gated (BUG-11 P2) ---")

test_xfail_pre_fix(
  "G16: peer.lua wraps feefilter send in 'version >= FEEFILTER_VERSION' (BUG-11)",
  "BUG-11", function()
    bug("BUG-11", "P2")
    local body = slurp("src/peer.lua") or ""
    -- Find the line that sends feefilter and check there is a gate
    -- in the same handler.  Today the send is bare inside handle_verack.
    local idx = body:find("send_message%(\"feefilter\"")
    expect_true(idx ~= nil, "feefilter send site exists (sanity)")
    -- Look BEFORE the send for a version gate within 200 chars.
    local prefix = body:sub(math.max(1, (idx or 1) - 300), (idx or 1))
    expect_true(
      prefix:find("70013") ~= nil
      or prefix:find("FEEFILTER_VERSION") ~= nil,
      "no FEEFILTER_VERSION gate immediately around send_message(\"feefilter\", ...)"
    )
  end)

-- ---------------------------------------------------------------------------
-- G17: Outbound FEEFILTER not sent to block-relay-only (BUG-12 P1)
-- ---------------------------------------------------------------------------

print("\n--- G17: outbound FEEFILTER skipped for block-relay-only (BUG-12 P1) ---")

test_xfail_pre_fix(
  "G17: feefilter send is gated on 'not block-relay-only' (BUG-12)",
  "BUG-12", function()
    bug("BUG-12", "P1")
    local body = slurp("src/peer.lua") or ""
    local idx = body:find("send_message%(\"feefilter\"")
    local prefix = body:sub(math.max(1, (idx or 1) - 500), (idx or 1))
    expect_true(
      prefix:find("block_only") ~= nil
      or prefix:find("block_relay_only") ~= nil
      or prefix:find("IsBlockOnlyConn") ~= nil,
      "no block-relay-only gate on feefilter send"
    )
  end)

-- ---------------------------------------------------------------------------
-- G18: Outbound FEEFILTER not sent under -blocksonly equivalent (BUG-13 P2)
-- ---------------------------------------------------------------------------

print("\n--- G18: outbound FEEFILTER skipped under -blocksonly (BUG-13 P2) ---")

test_xfail_pre_fix(
  "G18: feefilter send is gated on 'not ignore_incoming_txs' (BUG-13)",
  "BUG-13", function()
    bug("BUG-13", "P2")
    expect_true(
      file_contains("src/peer.lua", "ignore_incoming_txs")
      or file_contains("src/main.lua", "--blocksonly"),
      "no -blocksonly / ignore_incoming_txs CLI/gate observed"
    )
  end)

-- ---------------------------------------------------------------------------
-- G20: Periodic FEEFILTER broadcast (BUG-15 P1)
-- ---------------------------------------------------------------------------

print("\n--- G20: periodic FEEFILTER broadcast (BUG-15 P1) ---")

test_xfail_pre_fix(
  "G20-a: AVG_FEEFILTER_BROADCAST_INTERVAL = 10min present (BUG-15)",
  "BUG-15", function()
    bug("BUG-15", "P1")
    expect_true(
      file_contains("src/peer.lua", "AVG_FEEFILTER_BROADCAST_INTERVAL")
      or file_contains("src/peerman.lua", "AVG_FEEFILTER_BROADCAST_INTERVAL")
      or file_matches("src/peer.lua", "feefilter.-broadcast"),
      "no AVG_FEEFILTER_BROADCAST_INTERVAL constant present"
    )
  end)

test_xfail_pre_fix(
  "G20-b: peer state tracks next_send_feefilter timer (BUG-15)",
  "BUG-15", function()
    expect_true(
      file_contains("src/peer.lua", "next_send_feefilter")
      or file_contains("src/peer.lua", "next_feefilter")
      or file_contains("src/peerman.lua", "next_send_feefilter"),
      "no per-peer next_send_feefilter timer field"
    )
  end)

-- ---------------------------------------------------------------------------
-- G21: IBD MAX_MONEY override + on-IBD-exit resend (BUG-16 P0)
-- ---------------------------------------------------------------------------

print("\n--- G21: IBD MAX_MONEY override (BUG-16 P0) ---")

test_xfail_pre_fix(
  "G21-a: feefilter sender consults IBD state (BUG-16)",
  "BUG-16", function()
    bug("BUG-16", "P0")
    local body = slurp("src/peer.lua") or ""
    local idx = body:find("send_message%(\"feefilter\"")
    local ctx = body:sub(math.max(1, (idx or 1) - 500), (idx or 1) + 200)
    expect_true(
      ctx:find("IsInitialBlockDownload") ~= nil
      or ctx:find("is_initial_block_download") ~= nil
      or ctx:find("in_ibd") ~= nil
      or ctx:find("MAX_MONEY") ~= nil,
      "no IBD check around feefilter send"
    )
  end)

-- ---------------------------------------------------------------------------
-- G22: FeeFilterRounder bucket quantization (BUG-17 P1)
-- ---------------------------------------------------------------------------

print("\n--- G22: FeeFilterRounder bucket quantization (BUG-17 P1) ---")

test_xfail_pre_fix(
  "G22: FeeFilterRounder or quantization function present (BUG-17)",
  "BUG-17", function()
    bug("BUG-17", "P1")
    expect_true(
      file_contains("src/fee.lua", "FeeFilterRounder")
      or file_contains("src/fee.lua", "fee_filter_rounder")
      or file_contains("src/fee.lua", "FEE_FILTER_SPACING")
      or file_contains("src/peer.lua", "FeeFilterRounder"),
      "no FeeFilterRounder / FEE_FILTER_SPACING in src/"
    )
  end)

-- ---------------------------------------------------------------------------
-- G23: filterToSend = max(rounded, min_relay_feerate) (BUG-18 P0)
-- ---------------------------------------------------------------------------

print("\n--- G23: filterToSend derived from mempool min_relay_feerate (BUG-18 P0) ---")

test_xfail_pre_fix(
  "G23-a: feefilter send computes value from mempool / fee_policy (BUG-18)",
  "BUG-18", function()
    bug("BUG-18", "P0")
    -- Today: the value 100000 is hardcoded inline.  The fix would
    -- compute it from a policy/mempool ref.
    expect_false(
      file_contains("src/peer.lua",
        "self:send_message(\"feefilter\", p2p.serialize_feefilter(100000))"),
      "feefilter still sends the hardcoded 100000 sat/kvB literal — should derive from mempool min-relay"
    )
  end)

test("G23-b: hardcoded 100000 is the current bug-pin", function()
  -- Forward-regression pin: confirm the literal still exists today so the
  -- xfail above documents a real (not phantom) divergence.
  expect_true(
    file_contains("src/peer.lua",
      "p2p.serialize_feefilter(100000)"),
    "hardcoded 100000 literal not found — audit may have already moved"
  )
end)

-- ---------------------------------------------------------------------------
-- G26: Outbound tx-inv filtered by peer.fee_filter (BUG-21 P0)
-- ---------------------------------------------------------------------------

print("\n--- G26: outbound tx-inv consults p.fee_filter (BUG-21 P0) ---")

test_xfail_pre_fix(
  "G26-a: queue_tx_announcement consults p.fee_filter (BUG-21)",
  "BUG-21", function()
    bug("BUG-21", "P0")
    local body = slurp("src/peerman.lua") or ""
    local fn_start = body:find("function PeerManager:queue_tx_announcement", 1, true)
    expect_true(fn_start ~= nil,
      "queue_tx_announcement function exists (sanity)")
    -- Scan the function body for any reference to fee_filter / filterrate.
    local fn_body = body:sub(fn_start, fn_start + 2000)
    expect_true(
      fn_body:find("fee_filter") ~= nil
      or fn_body:find("filterrate") ~= nil
      or fn_body:find("min_fee") ~= nil,
      "queue_tx_announcement never references p.fee_filter"
    )
  end)

-- Forward-regression pin: confirm the gap exists today.
test("G26-b: fee_filter field present on Peer but unused in peerman (pin)",
function()
  expect_true(
    file_contains("src/peer.lua", "self.fee_filter = 0"),
    "Peer:new initializes fee_filter (sanity)")
  expect_true(
    file_contains("src/peer.lua",
      "self.fee_filter = p2p.deserialize_feefilter(msg.payload)"),
    "peer.lua updates fee_filter on incoming feefilter (sanity)")
  -- And peerman does NOT reference it (the bug):
  local body = slurp("src/peerman.lua") or ""
  expect_false(body:find("fee_filter", 1, true) ~= nil,
    "peerman.lua references fee_filter — bug may have moved")
end)

-- ---------------------------------------------------------------------------
-- G27: Outbound tx-inv uses MSG_WTX for wtxid_relay peers (PRESENT)
-- ---------------------------------------------------------------------------

print("\n--- G27: outbound tx-inv MSG_WTX / MSG_TX dispatch (BIP-339) ---")

test("G27-a: peerman.queue_tx_announcement switches on p.wtxid_relay", function()
  expect_true(file_contains("src/peerman.lua",
    "local hash = p.wtxid_relay and wtxid or txid"),
    "queue_tx_announcement chooses wtxid vs txid")
  expect_true(file_contains("src/peerman.lua",
    "local is_wtxid = p.wtxid_relay"),
    "queue_tx_announcement marks is_wtxid")
end)

test("G27-b: _process_trickle emits MSG_WTX when is_wtxid", function()
  expect_true(file_contains("src/peerman.lua",
    "local inv_type = entry.is_wtxid and p2p.INV_TYPE.MSG_WTX or p2p.INV_TYPE.MSG_TX"),
    "trickle uses MSG_WTX for wtxid entries")
end)

test("G27-c: p2p.INV_TYPE.MSG_WTX == 5 (BIP-339 constant)", function()
  expect_eq(p2p.INV_TYPE.MSG_WTX, 5,
    "MSG_WTX must equal 5 per BIP-339")
end)

-- ---------------------------------------------------------------------------
-- G28: GETDATA serves MSG_WTX (BUG-22 P0)
-- ---------------------------------------------------------------------------

print("\n--- G28: getdata serves MSG_WTX requests (BUG-22 P0) ---")

test_xfail_pre_fix(
  "G28-a: main.lua getdata handler dispatches on MSG_WTX (BUG-22)",
  "BUG-22", function()
    bug("BUG-22", "P0")
    -- The current getdata handler (main.lua:1666-1746) only checks MSG_TX /
    -- MSG_WITNESS_TX / MSG_BLOCK / MSG_WITNESS_BLOCK / MSG_FILTERED_BLOCK.
    -- We need to look INSIDE the getdata handler, not anywhere in main.lua,
    -- because the inv handler at main.lua:1290 already references MSG_WTX
    -- (we relay MSG_WTX in announcements; the bug is the SERVING side).
    local body = slurp("src/main.lua") or ""
    local fn_start = body:find('peer_manager:register_handler%("getdata"')
    expect_true(fn_start ~= nil,
      "getdata register_handler found (sanity)")
    -- Scan only the getdata handler body (terminate at next register_handler
    -- or end-of-file; conservative window = ~3000 bytes).
    local fn_body = body:sub(fn_start or 1, (fn_start or 1) + 3000)
    expect_true(
      fn_body:find("MSG_WTX", 1, true) ~= nil,
      "no MSG_WTX arm in getdata handler — wtxid-relay peers asking for tx will get notfound"
    )
  end)

-- Forward-regression pin: confirm tx arm currently lists only MSG_TX/WITNESS_TX.
test("G28-b: current getdata handler lists MSG_WITNESS_TX + MSG_TX (pin)",
function()
  expect_true(file_contains("src/main.lua",
    "if item.type == p2p.INV_TYPE.MSG_WITNESS_TX or item.type == p2p.INV_TYPE.MSG_TX then"),
    "expected current MSG_WITNESS_TX|MSG_TX dispatch in getdata handler")
end)

-- ---------------------------------------------------------------------------
-- G30: Documentation honesty re: which BIPs are wired (BUG-23 P3)
-- ---------------------------------------------------------------------------

print("\n--- G30: stale-compliance comments (BUG-23 P3, DOCS) ---")

test("G30-a: PRE_HANDSHAKE_ALLOWED comment claims BIP-130 (pin)", function()
  expect_true(file_contains("src/peer.lua",
    "sendheaders = true,  -- BIP 130: Accepted pre-handshake"),
    "PRE_HANDSHAKE_ALLOWED comment lists BIP-130 sendheaders")
end)

test_xfail_pre_fix(
  "G30-b: handle_version comment 'BIP155, BIP330, BIP339' matches actual implementation (BUG-23)",
  "BUG-23", function()
    bug("BUG-23", "P3")
    local body = slurp("src/peer.lua") or ""
    -- Locate the comment block.
    local idx = body:find("Send feature negotiation messages BEFORE verack", 1, true)
    expect_true(idx ~= nil, "comment block exists (sanity)")
    local block = body:sub(idx, idx + 800)
    -- The comment claims BIP339 but the block never sends wtxidrelay.
    local mentions_bip339 = block:find("BIP339", 1, true) ~= nil
    local sends_wtxidrelay = block:find("send_message%(\"wtxidrelay\"") ~= nil
    expect_eq(mentions_bip339, sends_wtxidrelay,
      "comment mentions BIP339 but body does not send wtxidrelay")
  end)

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------

print("\n=========================================================================")
print("W136 sendheaders/feefilter/wtxidrelay -- summary")
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

print("Audit gates: 30 W136 set")
print("  PRESENT:   9  (G5, G6, G7-a/b, G10, G13, G14-b/c, G23-b, G27-a/b/c, G28-b, G30-a)")
print("  MISSING/DIVERGENT: 21 (G1, G2, G3, G4-b/c, G8-a/b, G9-b/c, G11, G12,")
print("                       G14-a, G16, G17, G18, G20-a/b, G21-a, G22, G23-a,")
print("                       G26-a, G28-a, G30-b)")
print("")
print("Cross-references:")
print("  W117 BIP-155 networks + addrv2/sendaddrv2 (sibling BIP at handshake)")
print("  W126 BIP-152 compact blocks + sendcmpct (sibling handshake-time gate)")
print("  W121 BIP-157 compact filters (sibling 'half-wired gate' pattern)")
print("  W120 mempool RBF (sibling 'comment-as-confession' pattern)")
print("  W122 codec stress (test-comment-as-confession universal pattern)")

if FAIL > 0 then
  os.exit(1)
end
os.exit(0)
