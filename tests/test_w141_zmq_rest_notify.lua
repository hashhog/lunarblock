#!/usr/bin/env luajit
-- W141 ZMQ + REST + Notification scripts audit — lunarblock (Lua / LuaJIT)
--
-- Reference: bitcoin-core/src/zmq/zmqnotificationinterface.cpp +
--            zmqpublishnotifier.cpp; bitcoin-core/src/rest.cpp;
--            bitcoin-core/src/init.cpp:485,498,529-530,2008-2018;
--            bitcoin-core/src/node/kernel_notifications.cpp:30-47;
--            bitcoin-core/src/wallet/wallet.cpp:1140-1163;
--            bitcoin-core/src/txmempool.cpp:263-275 (BUG-9 BLOCK-suppress);
--            bitcoin-core/src/common/system.cpp:38-65.
--
-- Scope: 30 gates spanning
--   A. ZMQ wire & topic correctness   (G1-G10)
--   B. ZMQ event fan-out               (G11-G18)
--   C. REST endpoint coverage / shape  (G19-G26)
--   D. REST format & input parsing     (G27-G28)
--   E. Notify-script flags             (G29-G30)
--
-- Bugs found (1 P0 + 6 P1 + 9 P2 + 6 P3 = 22):
--
--   BUG-1   (P2)  topic_seq per-topic vs Core per-notifier-instance (G3).
--   BUG-2   (P1)  No per-topic --zmqpub<topic>hwm (G5).
--   BUG-3   (P1)  No ZMQ_IPV6 socket option (G7).
--   BUG-4   (P2)  No unix: → ipc:// prefix normalization (G8).
--   BUG-5   (P2)  No IBD/fInitialDownload gate on UpdatedBlockTip (G11+G12).
--   BUG-6   (P1)  BlockConnected does NOT fan out hashtx/rawtx (G13).
--   BUG-7   (P1)  BlockDisconnected does NOT fan out hashtx/rawtx (G14).
--   BUG-8   (P2)  No historical-role gate (latent for assumeutxo) (G15).
--   BUG-9   (P0)  Block-removed txs fire sequence-R instead of being
--                 suppressed (G17). Wire-deviation, mis-classifies every
--                 confirmed tx as evicted.
--   BUG-10  (P2)  mempool_sequence owned by NotificationManager, not by
--                 Mempool; starts at 0 not 1; not exposed via RPC (G18).
--   BUG-11  (P2)  /rest/blockpart/ endpoint absent (G21).
--   BUG-12  (P2)  /rest/mempool/contents missing mempool_sequence query
--                 parameter + verbose+sequence mutex check (G25).
--   BUG-13  (P2)  /rest/deploymentinfo/ endpoint absent (G26).
--   BUG-14  (P2)  /rest/getutxos POST-body input absent (G27).
--   BUG-15  (P2)  /rest/spenttxouts/ endpoint absent (G28).
--   BUG-16  (P1)  --alertnotify / --blocknotify / --walletnotify /
--                 --startupnotify / --shutdownnotify all absent (G29).
--                 Cross-ref: W124 BUG-12.
--   BUG-17  (P1)  os.execute("mkdir -p " .. datadir) shell-injectable;
--                 will carry into notify-script flags (G30 latent).
--   BUG-18  (P3)  ZMQSubscriber test helper has no unsubscribe path.
--   BUG-19  (P3)  encode_le64 overflow at 2^53.
--   BUG-20  (P3)  REST always emits Connection: close.
--   BUG-21  (P3)  REST Content-Length parsing accepts 0x10 hex literal.
--   BUG-22  (P3)  ZMQ + REST fire from main thread (no thread pool).
--
-- Run from `lunarblock/`:
--   luajit tests/test_w141_zmq_rest_notify.lua
--
-- Tests are written XFAIL-pre-fix for every BUG; PASSes mean the bug is
-- still present (matches the lunarblock W### audit convention — flips to
-- PASS-with-fix-marker once a future fix wave closes the gap).

package.path = "src/?.lua;src/?/init.lua;./?.lua;" .. package.path

-- ---------------------------------------------------------------------------
-- Test framework
-- ---------------------------------------------------------------------------

local PASS, FAIL, XFAIL_PRE_FIX = 0, 0, 0

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

local function test_xfail_pre_fix(name, fn)
  local ok, err = pcall(fn)
  if ok then
    pass(name .. " [now PASSing — fix likely landed]")
  else
    xfail_pre_fix(name, tostring(err))
  end
end

local function expect_truthy(v, msg)
  if not v then
    error((msg or "expected truthy") .. ": got " .. tostring(v))
  end
end

local function expect_falsy(v, msg)
  if v then
    error((msg or "expected falsy") .. ": got " .. tostring(v))
  end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) ..
          ", expected " .. tostring(b))
  end
end

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

local function read_file(path)
  local f = io.open(path, "r")
  if not f then return nil end
  local data = f:read("*a")
  f:close()
  return data
end

local function file_contains(path, needle)
  local data = read_file(path)
  if not data then return false end
  return string.find(data, needle, 1, true) ~= nil
end

local function count_occurrences(path, needle)
  local data = read_file(path)
  if not data then return 0 end
  local n = 0
  local i = 1
  while true do
    local s = string.find(data, needle, i, true)
    if not s then break end
    n = n + 1
    i = s + #needle
  end
  return n
end

-- ---------------------------------------------------------------------------
-- Banner
-- ---------------------------------------------------------------------------

print("\n=========================================================================")
print("W141 ZMQ + REST + Notification scripts audit — lunarblock")
print("Source: src/zmq.lua, src/rest.lua, src/main.lua")
print("Reference: bitcoin-core/src/zmq/zmqnotificationinterface.cpp,")
print("           bitcoin-core/src/zmq/zmqpublishnotifier.cpp,")
print("           bitcoin-core/src/rest.cpp,")
print("           bitcoin-core/src/init.cpp + node/kernel_notifications.cpp,")
print("           bitcoin-core/src/wallet/wallet.cpp:1140-1163,")
print("           bitcoin-core/src/txmempool.cpp:263-275 (BLOCK-suppress).")
print("=========================================================================")

-- ===========================================================================
-- SECTION A — ZMQ wire & topic correctness (G1-G10)
-- ===========================================================================
print("\n=== A. ZMQ wire & topic correctness (G1-G10) ===")

-- G1: 5 topics registered
print("\n--- G1: 5 ZMQ topics registered ---")
test("G1-a: zmq.lua defines TOPIC_HASHBLOCK", function()
  expect_truthy(file_contains("src/zmq.lua", 'M.TOPIC_HASHBLOCK = "hashblock"'),
                "TOPIC_HASHBLOCK missing")
end)
test("G1-b: zmq.lua defines TOPIC_HASHTX", function()
  expect_truthy(file_contains("src/zmq.lua", 'M.TOPIC_HASHTX = "hashtx"'),
                "TOPIC_HASHTX missing")
end)
test("G1-c: zmq.lua defines TOPIC_RAWBLOCK", function()
  expect_truthy(file_contains("src/zmq.lua", 'M.TOPIC_RAWBLOCK = "rawblock"'),
                "TOPIC_RAWBLOCK missing")
end)
test("G1-d: zmq.lua defines TOPIC_RAWTX", function()
  expect_truthy(file_contains("src/zmq.lua", 'M.TOPIC_RAWTX = "rawtx"'),
                "TOPIC_RAWTX missing")
end)
test("G1-e: zmq.lua defines TOPIC_SEQUENCE", function()
  expect_truthy(file_contains("src/zmq.lua", 'M.TOPIC_SEQUENCE = "sequence"'),
                "TOPIC_SEQUENCE missing")
end)

-- G2: multipart wire format [topic, body, LE32(seq)]
print("\n--- G2: multipart wire format ---")
test("G2-a: ZMQPublisher:send sends topic, body, seq parts", function()
  expect_truthy(file_contains("src/zmq.lua", "local parts = {topic, body, seq_bytes}"),
                "send() does not assemble {topic, body, seq_bytes}")
end)
test("G2-b: seq encoded as LE32", function()
  expect_truthy(file_contains("src/zmq.lua", "local seq_bytes = encode_le32(seq)"),
                "seq not LE32-encoded")
end)
test("G2-c: SNDMORE flag set for all parts except last", function()
  expect_truthy(file_contains("src/zmq.lua",
                              "local flags = (i < #parts) and M.ZMQ_SNDMORE or 0"),
                "SNDMORE flag logic missing")
end)

-- G3: per-notifier-instance nSequence (BUG-1: per-topic instead)
print("\n--- G3: per-notifier-instance nSequence (BUG-1 P2) ---")
test("G3-a: topic_seq map exists", function()
  expect_truthy(file_contains("src/zmq.lua", "self.topic_seq = {}"),
                "topic_seq map missing")
end)
test_xfail_pre_fix("G3-b: per-notifier-instance nSequence (NOT just per-topic) (BUG-1 latent)", function()
  -- Core: each topic-notifier-INSTANCE has its own nSequence
  -- (zmqpublishnotifier.h:21). lunarblock keys by topic only — same
  -- observable when one notifier per topic, but drifts if a topic ever
  -- has two notifiers at different endpoints.
  expect_truthy(file_contains("src/zmq.lua", "notifier_seq") or
                file_contains("src/zmq.lua", "per_notifier_sequence"),
                "no per-notifier-instance sequence concept — BUG-1")
end)

-- G4: hash byte-order = display (reversed)
print("\n--- G4: hash byte-order reversal ---")
test("G4-a: reverse_bytes called in notify_hashblock", function()
  expect_truthy(file_contains("src/zmq.lua",
                              "return self:send(M.TOPIC_HASHBLOCK, reverse_bytes(block_hash))"),
                "hashblock not byte-reversed")
end)
test("G4-b: reverse_bytes called in notify_hashtx", function()
  expect_truthy(file_contains("src/zmq.lua",
                              "return self:send(M.TOPIC_HASHTX, reverse_bytes(txid))"),
                "hashtx not byte-reversed")
end)
test("G4-c: reverse_bytes called in notify_sequence", function()
  expect_truthy(file_contains("src/zmq.lua", "reverse_bytes(hash) .. string.char(label)"),
                "sequence not byte-reversed")
end)

-- G5: per-topic --zmqpub<topic>hwm (BUG-2: single global)
print("\n--- G5: per-topic SNDHWM (BUG-2 P1) ---")
test("G5-a: --zmqpubhwm global flag exists", function()
  expect_truthy(file_contains("src/main.lua", '"--zmqpubhwm"'),
                "--zmqpubhwm flag missing")
end)
test_xfail_pre_fix("G5-b: --zmqpubhashblockhwm per-topic flag (BUG-2)", function()
  expect_truthy(file_contains("src/main.lua", '"--zmqpubhashblockhwm"'),
                "--zmqpubhashblockhwm absent — BUG-2: only global --zmqpubhwm exists")
end)
test_xfail_pre_fix("G5-c: --zmqpubrawblockhwm per-topic flag (BUG-2)", function()
  expect_truthy(file_contains("src/main.lua", '"--zmqpubrawblockhwm"'),
                "--zmqpubrawblockhwm absent — BUG-2")
end)
test_xfail_pre_fix("G5-d: --zmqpubsequencehwm per-topic flag (BUG-2)", function()
  expect_truthy(file_contains("src/main.lua", '"--zmqpubsequencehwm"'),
                "--zmqpubsequencehwm absent — BUG-2")
end)

-- G6: TCP_KEEPALIVE
print("\n--- G6: ZMQ_TCP_KEEPALIVE ---")
test("G6-a: keepalive set on every socket", function()
  expect_truthy(file_contains("src/zmq.lua",
                              "zmq_setsockopt(sock, M.ZMQ_TCP_KEEPALIVE, keepalive"),
                "TCP_KEEPALIVE not set")
end)

-- G7: ZMQ_IPV6 (BUG-3: no IPv6 toggle)
print("\n--- G7: ZMQ_IPV6 (BUG-3 P1) ---")
test_xfail_pre_fix("G7-a: ZMQ_IPV6 socket option set when address is IPv6 (BUG-3)", function()
  expect_truthy(file_contains("src/zmq.lua", "ZMQ_IPV6") or
                file_contains("src/zmq.lua", "is_ipv6") or
                file_contains("src/zmq.lua", "IsZMQAddressIPV6"),
                "ZMQ_IPV6 detection / setsockopt absent — BUG-3")
end)

-- G8: unix: → ipc:// prefix normalization (BUG-4)
print("\n--- G8: unix: prefix normalization (BUG-4 P2) ---")
test_xfail_pre_fix("G8-a: unix: prefix normalized to ipc:// (BUG-4)", function()
  expect_truthy(file_contains("src/zmq.lua", '"unix:"') or
                file_contains("src/zmq.lua", "ADDR_PREFIX_UNIX") or
                file_contains("src/zmq.lua", "unix://"),
                "no unix:/ipc:// prefix normalization — BUG-4")
end)

-- G9: shared-endpoint socket reuse
print("\n--- G9: shared-endpoint socket reuse ---")
test("G9-a: endpoint_to_socket map used for socket reuse", function()
  expect_truthy(file_contains("src/zmq.lua", "local endpoint_to_socket = {}"),
                "endpoint_to_socket reuse map missing")
end)

-- G10: ZMQ_LINGER=0 on shutdown
print("\n--- G10: ZMQ_LINGER=0 on shutdown ---")
test("G10-a: linger=0 set in shutdown", function()
  expect_truthy(file_contains("src/zmq.lua",
                              "local linger = ffi.new(\"int[1]\", 0)"),
                "LINGER=0 not set on shutdown")
end)

-- ===========================================================================
-- SECTION B — ZMQ event fan-out (G11-G18)
-- ===========================================================================
print("\n=== B. ZMQ event fan-out (G11-G18) ===")

-- G11+G12: IBD gate (BUG-5)
print("\n--- G11+G12: IBD/fInitialDownload gate on UpdatedBlockTip (BUG-5 P2) ---")
test_xfail_pre_fix("G11-a: NotificationManager:on_block_connected has IBD gate (BUG-5)", function()
  -- Core: zmqnotificationinterface.cpp:153 returns when fInitialDownload.
  -- lunarblock has no such check.
  local body = read_file("src/zmq.lua")
  expect_truthy(body, "zmq.lua unreadable")
  expect_truthy(body:find("initial_block_download", 1, true) or
                body:find("fInitialDownload", 1, true) or
                body:find("is_ibd", 1, true),
                "no IBD gate on hashblock/rawblock fan-out — BUG-5")
end)
test_xfail_pre_fix("G12-a: notify only when tip changed (not on side-fork connect) (BUG-5b)", function()
  -- Core: zmqnotificationinterface.cpp:153 also returns when
  -- pindexNew == pindexFork. lunarblock has no notion.
  expect_truthy(file_contains("src/zmq.lua", "tip_changed") or
                file_contains("src/zmq.lua", "pindexNew") or
                file_contains("src/zmq.lua", "pindexFork"),
                "no 'tip-only' gate — BUG-5b")
end)

-- G13: BlockConnected hashtx/rawtx fan-out (BUG-6)
print("\n--- G13: BlockConnected fans out hashtx/rawtx for every tx (BUG-6 P1) ---")
test_xfail_pre_fix("G13-a: on_block_connected loops block.vtx to emit hashtx (BUG-6)", function()
  local body = read_file("src/zmq.lua")
  expect_truthy(body, "zmq.lua unreadable")
  -- Look at the on_block_connected body specifically — it ends at "end" before
  -- on_block_disconnected. Confirm it walks transactions.
  local start = body:find("function NotificationManager:on_block_connected", 1, true)
  local stop = body:find("function NotificationManager:on_block_disconnected", 1, true)
  expect_truthy(start and stop, "function markers missing")
  local snippet = body:sub(start, stop - 1)
  expect_truthy(snippet:find("notify_hashtx", 1, true) and
                (snippet:find("block.transactions", 1, true) or
                 snippet:find("block.vtx", 1, true) or
                 snippet:find("for _, tx in ipairs(block", 1, true)),
                "on_block_connected does NOT fan out hashtx per tx — BUG-6")
end)
test_xfail_pre_fix("G13-b: on_block_connected loops block.vtx to emit rawtx (BUG-6)", function()
  local body = read_file("src/zmq.lua")
  local start = body:find("function NotificationManager:on_block_connected", 1, true)
  local stop = body:find("function NotificationManager:on_block_disconnected", 1, true)
  local snippet = body:sub(start, stop - 1)
  expect_truthy(snippet:find("notify_rawtx", 1, true),
                "on_block_connected does NOT fan out rawtx per tx — BUG-6")
end)

-- G14: BlockDisconnected hashtx/rawtx fan-out (BUG-7)
print("\n--- G14: BlockDisconnected fans out hashtx/rawtx (BUG-7 P1) ---")
test_xfail_pre_fix("G14-a: on_block_disconnected fans out hashtx per tx (BUG-7)", function()
  local body = read_file("src/zmq.lua")
  local start = body:find("function NotificationManager:on_block_disconnected", 1, true)
  local stop = body:find("function NotificationManager:on_tx_added", 1, true)
  expect_truthy(start and stop, "function markers missing")
  local snippet = body:sub(start, stop - 1)
  expect_truthy(snippet:find("notify_hashtx", 1, true),
                "on_block_disconnected does NOT fan out hashtx per tx — BUG-7")
end)

-- G15: historical-role gate (BUG-8 latent)
print("\n--- G15: historical-role gate (BUG-8 P2, latent for assumeutxo) ---")
test_xfail_pre_fix("G15-a: historical-role / background-validation guard (BUG-8)", function()
  expect_truthy(file_contains("src/zmq.lua", "historical") or
                file_contains("src/zmq.lua", "role.historical") or
                file_contains("src/zmq.lua", "background_validation"),
                "no historical-role gate — BUG-8 latent for assumeutxo")
end)

-- G16: TransactionAddedToMempool emits both hashtx+rawtx AND sequence-A
print("\n--- G16: on_tx_added emits hashtx + rawtx + sequence-A ---")
test("G16-a: on_tx_added emits notify_hashtx", function()
  local body = read_file("src/zmq.lua")
  local start = body:find("function NotificationManager:on_tx_added", 1, true)
  local stop = body:find("function NotificationManager:on_tx_removed", 1, true)
  local snippet = body:sub(start, stop - 1)
  expect_truthy(snippet:find("notify_hashtx", 1, true), "on_tx_added does not emit hashtx")
end)
test("G16-b: on_tx_added emits notify_rawtx", function()
  local body = read_file("src/zmq.lua")
  local start = body:find("function NotificationManager:on_tx_added", 1, true)
  local stop = body:find("function NotificationManager:on_tx_removed", 1, true)
  local snippet = body:sub(start, stop - 1)
  expect_truthy(snippet:find("notify_rawtx", 1, true), "on_tx_added does not emit rawtx")
end)
test("G16-c: on_tx_added emits notify_tx_acceptance (sequence-A)", function()
  local body = read_file("src/zmq.lua")
  local start = body:find("function NotificationManager:on_tx_added", 1, true)
  local stop = body:find("function NotificationManager:on_tx_removed", 1, true)
  local snippet = body:sub(start, stop - 1)
  expect_truthy(snippet:find("notify_tx_acceptance", 1, true),
                "on_tx_added does not emit sequence-A")
end)

-- G17: BLOCK-removal suppression (BUG-9 P0)
print("\n--- G17: BLOCK-reason suppression on tx removal (BUG-9 P0) ---")
test_xfail_pre_fix("G17-a: main.lua on_tx_removed filters reason 'confirmed'/'block' (BUG-9 P0)", function()
  -- Core txmempool.cpp:269: if (reason != BLOCK) TransactionRemovedFromMempool(...)
  -- lunarblock main.lua:1116-1119 fires zmq_notifier:on_tx_removed for EVERY reason.
  -- Fix: skip when reason == "confirmed" or "block".
  local body = read_file("src/main.lua")
  expect_truthy(body, "main.lua unreadable")
  -- Look at the relevant block: ZMQ tx-removal callback.
  local s = body:find("mempool.callbacks.on_tx_removed = function(txid_hex, _reason)", 1, true)
  expect_truthy(s, "main.lua ZMQ on_tx_removed wiring not found")
  -- Match scope: callback body up to the next blank-line-terminated 'end\n'.
  local snippet = body:sub(s, s + 600)
  expect_truthy(snippet:find('if _reason ~= "confirmed"', 1, true) or
                snippet:find('if reason ~= "block"', 1, true) or
                snippet:find("reason ~= BLOCK", 1, true) or
                snippet:find("if reason and reason ~=", 1, true),
                "ZMQ on_tx_removed fires for every reason including 'confirmed' — BUG-9 P0")
end)
test_xfail_pre_fix("G17-b: zmq.lua NotificationManager:on_tx_removed accepts a reason arg (BUG-9 P0 alt)", function()
  -- Alternative fix locus: push the filter into zmq.lua so callers don't need
  -- to know the rule.
  local body = read_file("src/zmq.lua")
  expect_truthy(body, "zmq.lua unreadable")
  expect_truthy(body:find("function NotificationManager:on_tx_removed(txid, reason)", 1, true),
                "NotificationManager:on_tx_removed signature does not take reason — BUG-9 P0")
end)

-- G18: mempool_sequence owned by Mempool, not NotificationManager (BUG-10)
print("\n--- G18: mempool_sequence ownership + 1-start + RPC exposure (BUG-10 P2) ---")
test_xfail_pre_fix("G18-a: mempool.lua owns m_sequence_number (BUG-10)", function()
  -- Core: CTxMemPool::m_sequence_number — owns counter at the mempool level
  -- so callers can read it independent of ZMQ wiring.
  local body = read_file("src/mempool.lua")
  expect_truthy(body, "mempool.lua unreadable")
  expect_truthy(body:find("m_sequence_number", 1, true) or
                body:find("mempool_sequence", 1, true) or
                body:find("self.sequence_number", 1, true),
                "Mempool does not own a sequence counter — BUG-10")
end)
test_xfail_pre_fix("G18-b: mempool_sequence starts at 1 (Core parity) (BUG-10)", function()
  -- Core: CTxMemPool::m_sequence_number{1};  lunarblock: 0
  local body = read_file("src/zmq.lua")
  expect_truthy(body, "zmq.lua unreadable")
  expect_falsy(body:find("self.mempool_sequence = 0", 1, true),
               "mempool_sequence starts at 0 instead of 1 — BUG-10 off-by-one vs Core")
end)
test_xfail_pre_fix("G18-c: getmempoolinfo RPC exposes mempool_sequence field (BUG-10)", function()
  -- Core: getmempoolinfo returns the mempool sequence (top-level field) so
  -- RPC consumers can poll without ZMQ.  Tighten match: look INSIDE the
  -- getmempoolinfo result table, not anywhere in rpc.lua (vin_entry.sequence
  -- false-positive otherwise).
  local body = read_file("src/rpc.lua")
  expect_truthy(body, "rpc.lua unreadable")
  local s = body:find('self.methods%["getmempoolinfo"%]')
  expect_truthy(s, "getmempoolinfo handler not found")
  -- Look at the immediate return-table block (~next 80 lines).
  local snippet = body:sub(s, s + 4000)
  expect_truthy(snippet:find("mempool_sequence", 1, true) or
                snippet:find("sequence_number", 1, true),
                "getmempoolinfo does not expose mempool sequence — BUG-10")
end)

-- ===========================================================================
-- SECTION C — REST endpoint coverage & shape (G19-G26)
-- ===========================================================================
print("\n=== C. REST endpoint coverage & shape (G19-G26) ===")

-- G19: /rest/tx
print("\n--- G19: /rest/tx/<txid>.{bin,hex,json} ---")
test("G19-a: handle_tx defined", function()
  expect_truthy(file_contains("src/rest.lua", "function RESTServer:handle_tx"),
                "handle_tx missing")
end)
test("G19-b: /rest/tx/ route in router", function()
  expect_truthy(file_contains("src/rest.lua", '"^/rest/tx/([0-9a-fA-F]+)$"'),
                "/rest/tx/ route absent")
end)

-- G20: /rest/block + /rest/block/notxdetails
print("\n--- G20: /rest/block + /rest/block/notxdetails ---")
test("G20-a: handle_block defined", function()
  expect_truthy(file_contains("src/rest.lua", "function RESTServer:handle_block"),
                "handle_block missing")
end)
test("G20-b: /rest/block/notxdetails route", function()
  expect_truthy(file_contains("src/rest.lua",
                              '"^/rest/block/notxdetails/([0-9a-fA-F]+)$"'),
                "/rest/block/notxdetails route absent")
end)

-- G21: /rest/blockpart (BUG-11)
print("\n--- G21: /rest/blockpart/<hash>?offset=N&size=N (BUG-11 P2) ---")
test_xfail_pre_fix("G21-a: /rest/blockpart route registered (BUG-11)", function()
  expect_truthy(file_contains("src/rest.lua", "/rest/blockpart"),
                "/rest/blockpart endpoint absent — BUG-11")
end)
test_xfail_pre_fix("G21-b: handle_blockpart implemented (BUG-11)", function()
  expect_truthy(file_contains("src/rest.lua", "handle_blockpart") or
                file_contains("src/rest.lua", "handle_block_part"),
                "handle_blockpart absent — BUG-11")
end)

-- G22: /rest/blockfilter + /rest/blockfilterheaders
print("\n--- G22: /rest/blockfilter + /rest/blockfilterheaders (BIP-157) ---")
test("G22-a: handle_blockfilter defined", function()
  expect_truthy(file_contains("src/rest.lua",
                              "function RESTServer:handle_blockfilter"),
                "handle_blockfilter missing")
end)
test("G22-b: handle_blockfilterheaders defined", function()
  expect_truthy(file_contains("src/rest.lua",
                              "function RESTServer:handle_blockfilterheaders"),
                "handle_blockfilterheaders missing")
end)
test("G22-c: query-param ?count= form supported", function()
  expect_truthy(file_contains("src/rest.lua",
                              "DEFAULT_HEADERS_COUNT"),
                "?count= default fallback missing")
end)

-- G23: /rest/headers (both forms)
print("\n--- G23: /rest/headers (path + query forms) ---")
test("G23-a: handle_headers defined", function()
  expect_truthy(file_contains("src/rest.lua",
                              "function RESTServer:handle_headers"),
                "handle_headers missing")
end)
test("G23-b: path-form /rest/headers/<count>/<hash>", function()
  expect_truthy(file_contains("src/rest.lua",
                              '"^/rest/headers/(%d+)/([0-9a-fA-F]+)$"'),
                "path-form headers route missing")
end)
test("G23-c: query-form /rest/headers/<hash>?count=", function()
  expect_truthy(file_contains("src/rest.lua",
                              '"^/rest/headers/([0-9a-fA-F]+)$"'),
                "query-form headers route missing")
end)

-- G24: /rest/chaininfo
print("\n--- G24: /rest/chaininfo ---")
test("G24-a: handle_chaininfo defined", function()
  expect_truthy(file_contains("src/rest.lua",
                              "function RESTServer:handle_chaininfo"),
                "handle_chaininfo missing")
end)

-- G25: /rest/mempool/contents mempool_sequence query param (BUG-12)
print("\n--- G25: /rest/mempool/contents mempool_sequence query (BUG-12 P2) ---")
test("G25-a: handle_mempool_contents defined", function()
  expect_truthy(file_contains("src/rest.lua",
                              "function RESTServer:handle_mempool_contents"),
                "handle_mempool_contents missing")
end)
test_xfail_pre_fix("G25-b: mempool_sequence query param honoured (BUG-12)", function()
  local body = read_file("src/rest.lua")
  expect_truthy(body, "rest.lua unreadable")
  expect_truthy(body:find("mempool_sequence", 1, true),
                "mempool_sequence query param NOT parsed in mempool/contents — BUG-12")
end)
test_xfail_pre_fix("G25-c: 400 when verbose=true AND mempool_sequence=true (BUG-12)", function()
  local body = read_file("src/rest.lua")
  expect_truthy(body, "rest.lua unreadable")
  expect_truthy(body:find("Verbose results cannot contain mempool sequence", 1, true) or
                body:find("verbose_and_sequence", 1, true),
                "no mutual-exclusion check for verbose+sequence — BUG-12")
end)

-- G26: /rest/deploymentinfo (BUG-13)
print("\n--- G26: /rest/deploymentinfo[/hash] (BUG-13 P2) ---")
test_xfail_pre_fix("G26-a: /rest/deploymentinfo route registered (BUG-13)", function()
  expect_truthy(file_contains("src/rest.lua", "/rest/deploymentinfo"),
                "/rest/deploymentinfo absent — BUG-13")
end)
test_xfail_pre_fix("G26-b: handle_deploymentinfo implemented (BUG-13)", function()
  expect_truthy(file_contains("src/rest.lua", "handle_deploymentinfo") or
                file_contains("src/rest.lua", "handle_deployment_info"),
                "handle_deploymentinfo absent — BUG-13")
end)

-- ===========================================================================
-- SECTION D — REST format & input parsing (G27-G28)
-- ===========================================================================
print("\n=== D. REST format & input parsing (G27-G28) ===")

-- G27: /rest/getutxos POST body (BUG-14)
print("\n--- G27: /rest/getutxos POST-body input (BUG-14 P2) ---")
test("G27-a: handle_getutxos defined (URI-scheme path works)", function()
  expect_truthy(file_contains("src/rest.lua",
                              "function RESTServer:handle_getutxos"),
                "handle_getutxos missing entirely")
end)
test_xfail_pre_fix("G27-b: handle_getutxos honours POST body (BUG-14)", function()
  -- Core rest.cpp:912: strRequestMutable = req->ReadBody();
  -- lunarblock: only URI-scheme parsing, no body read.
  local body = read_file("src/rest.lua")
  expect_truthy(body, "rest.lua unreadable")
  -- Look at handle_getutxos body specifically.
  local s = body:find("function RESTServer:handle_getutxos", 1, true)
  local e = body:find("function RESTServer:handle_mempool_contents", 1, true)
  expect_truthy(s and e, "getutxos function bounds missing")
  local snippet = body:sub(s, e - 1)
  expect_truthy(snippet:find("body", 1, true) or
                snippet:find("ReadBody", 1, true) or
                snippet:find("post_body", 1, true),
                "handle_getutxos never reads a POST body — BUG-14")
end)
test_xfail_pre_fix("G27-c: route dispatches POST /rest/getutxos (BUG-14)", function()
  -- Core REST routing accepts both GET and POST for getutxos.
  -- lunarblock route() only accepts GET (rejects POST early at the top); the
  -- POST branch only allow-lists /payjoin.  Fix: add /rest/getutxos to the
  -- POST allow-list AND have handle_getutxos take the body arg.
  local body = read_file("src/rest.lua")
  expect_truthy(body, "rest.lua unreadable")
  expect_truthy(body:find("POST /rest/getutxos", 1, true) or
                body:find("getutxos_post", 1, true) or
                body:find('clean_post == "/rest/getutxos"', 1, true),
                "no POST /rest/getutxos route — BUG-14")
end)

-- G28: /rest/spenttxouts (BUG-15)
print("\n--- G28: /rest/spenttxouts/<hash> (BUG-15 P2) ---")
test_xfail_pre_fix("G28-a: /rest/spenttxouts route registered (BUG-15)", function()
  expect_truthy(file_contains("src/rest.lua", "/rest/spenttxouts"),
                "/rest/spenttxouts endpoint absent — BUG-15")
end)
test_xfail_pre_fix("G28-b: handle_spenttxouts implemented (BUG-15)", function()
  expect_truthy(file_contains("src/rest.lua", "handle_spenttxouts") or
                file_contains("src/rest.lua", "handle_spent_txouts"),
                "handle_spenttxouts absent — BUG-15")
end)

-- ===========================================================================
-- SECTION E — Notify-script flags (G29-G30)
-- ===========================================================================
print("\n=== E. Notify-script flags (G29-G30) ===")

-- G29: --alertnotify / --blocknotify / --walletnotify / --startupnotify /
--      --shutdownnotify (BUG-16)
print("\n--- G29: notify-script CLI flags (BUG-16 P1; cross-ref W124 BUG-12) ---")
test_xfail_pre_fix("G29-a: --alertnotify flag wired (BUG-16)", function()
  expect_truthy(file_contains("src/main.lua", '"--alertnotify"'),
                "--alertnotify absent — BUG-16")
end)
test_xfail_pre_fix("G29-b: --blocknotify flag wired (BUG-16)", function()
  expect_truthy(file_contains("src/main.lua", '"--blocknotify"'),
                "--blocknotify absent — BUG-16")
end)
test_xfail_pre_fix("G29-c: --walletnotify flag wired (BUG-16)", function()
  expect_truthy(file_contains("src/main.lua", '"--walletnotify"'),
                "--walletnotify absent — BUG-16")
end)
test_xfail_pre_fix("G29-d: --startupnotify flag wired (BUG-16)", function()
  expect_truthy(file_contains("src/main.lua", '"--startupnotify"'),
                "--startupnotify absent — BUG-16")
end)
test_xfail_pre_fix("G29-e: --shutdownnotify flag wired (BUG-16)", function()
  expect_truthy(file_contains("src/main.lua", '"--shutdownnotify"'),
                "--shutdownnotify absent — BUG-16")
end)

-- G30: shell-injection hardening (BUG-17 latent)
print("\n--- G30: shell-injection hardening (BUG-17 P1, latent) ---")
test("G30-a: os.execute(mkdir -p ..) pattern still present (documents BUG-17)", function()
  -- This is the antipattern that will recur in notify-script substitution.
  -- We assert it EXISTS today (documenting BUG-17); the fix is to switch to
  -- lfs.mkdir or an FFI mkdir(2) call AND add a shell_escape helper.
  expect_truthy(file_contains("src/main.lua", 'os.execute("mkdir -p " .. datadir)'),
                "BUG-17 antipattern unexpectedly missing (datadir mkdir was hardened?)")
end)
test_xfail_pre_fix("G30-b: shell_escape helper exists for notify-script substitution (BUG-17)", function()
  -- Core: src/util/string.cpp ShellEscape — single-quote-wrap with internal
  -- single-quote rewrite ('  ->  '"'"' ).
  local main = read_file("src/main.lua")
  local ops = read_file("src/ops.lua")
  local function has_shell_escape(body)
    if not body then return false end
    return body:find("shell_escape", 1, true) or
           body:find("ShellEscape", 1, true) or
           body:find("posix.shell_escape", 1, true)
  end
  expect_truthy(has_shell_escape(main) or has_shell_escape(ops),
                "no shell_escape helper — BUG-17 latent (will recur in notify-script %s/%w)")
end)
test_xfail_pre_fix("G30-c: SanitizeString equivalent for alertnotify %s (BUG-17)", function()
  -- Core: kernel_notifications.cpp:40 SanitizeString(strMessage) before shell.
  local main = read_file("src/main.lua")
  expect_truthy(main and (main:find("sanitize_alert_message", 1, true) or
                          main:find("SanitizeString", 1, true) or
                          main:find("safe_alert_message", 1, true)),
                "no SanitizeString equivalent — BUG-17 latent for --alertnotify")
end)

-- ===========================================================================
-- Extra: explicit cross-bug coverage
-- ===========================================================================
print("\n=== Extra: explicit cross-bug confirmations ===")

-- BUG-18: subscriber unsubscribe
print("\n--- BUG-18: ZMQSubscriber unsubscribe path ---")
test_xfail_pre_fix("BUG-18: ZMQSubscriber has unsubscribe method", function()
  expect_truthy(file_contains("src/zmq.lua", "function ZMQSubscriber:unsubscribe") or
                file_contains("src/zmq.lua", "ZMQ_UNSUBSCRIBE"),
                "ZMQSubscriber lacks unsubscribe — BUG-18")
end)

-- BUG-19: encode_le64 overflow at 2^53 — documented only; test the helper exists
print("\n--- BUG-19: encode_le64 precision (theoretical) ---")
test("BUG-19: encode_le64 helper exists (precision caveat noted)", function()
  expect_truthy(file_contains("src/zmq.lua", "local function encode_le64"),
                "encode_le64 helper missing")
end)

-- BUG-20: Connection: close always
print("\n--- BUG-20: REST Connection: close always emitted ---")
test_xfail_pre_fix("BUG-20: REST honours Connection: keep-alive", function()
  local body = read_file("src/rest.lua")
  expect_truthy(body, "rest.lua unreadable")
  expect_truthy(body:find("keep-alive", 1, true) or
                body:find("Connection: keep-alive", 1, true),
                "REST always emits Connection: close — BUG-20")
end)

-- BUG-21: Content-Length parsing accepts hex
print("\n--- BUG-21: Content-Length parsing accepts hex (theoretical) ---")
test("BUG-21: tonumber-based Content-Length parsing in place", function()
  expect_truthy(file_contains("src/rest.lua",
                              'local clen = tonumber(headers["content-length"])'),
                "Content-Length parsing logic missing — BUG-21 doc only")
end)

-- BUG-22: ZMQ + REST fire on main thread
print("\n--- BUG-22: ZMQ + REST run on main thread (no thread pool) ---")
test_xfail_pre_fix("BUG-22: notification thread pool exists", function()
  expect_truthy(file_contains("src/main.lua", "notification_thread") or
                file_contains("src/main.lua", "notify_pool") or
                file_contains("src/zmq.lua", "ZMQ_XPUB_NODROP"),
                "no notification thread pool — BUG-22")
end)

-- ===========================================================================
-- Universal-pattern reminders
-- ===========================================================================
print("\n=== Universal-pattern reminders ===")

test("UNIVERSAL: MemPoolRemovalReason::BLOCK suppression rule documented", function()
  -- BUG-9 P0 will recur fleet-wide; document the rule in the audit md.
  expect_truthy(file_contains("audit/w141_zmq_rest_notify.md",
                              "MemPoolRemovalReason::BLOCK"),
                "audit md does not document the BLOCK-suppression rule")
end)

test("UNIVERSAL: shell-injection latent class flagged for notify-script", function()
  expect_truthy(file_contains("audit/w141_zmq_rest_notify.md",
                              "shell-injection-class latent pattern") or
                file_contains("audit/w141_zmq_rest_notify.md", "BUG-17"),
                "audit md does not flag shell-injection-class for notify-script")
end)

-- ===========================================================================
-- Summary
-- ===========================================================================
print("\n=========================================================================")
print(string.format("W141 summary:  PASS=%d   FAIL=%d   XFAIL=%d   total=%d",
                    PASS, FAIL, XFAIL_PRE_FIX, PASS + FAIL + XFAIL_PRE_FIX))
print(string.format("Expected XFAIL count (pre-fix): ~30 (one per BUG/sub-claim)"))
print("Bugs: 1 P0 + 6 P1 + 9 P2 + 6 P3 = 22.")
print("=========================================================================")

if FAIL > 0 then
  os.exit(1)
else
  os.exit(0)
end
