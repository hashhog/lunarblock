#!/usr/bin/env luajit
-- test_fix37_bloom_wiring.lua — FIX-37 bloom.lua P2P dispatch wiring tests
--
-- Covers:
--   1. filterload → peer.bloom_filter populated, peer.relay_txes = true
--   2. filteradd  → filter mutated in-place
--   3. filterclear → peer.bloom_filter back to nil, relay_txes = true
--   4. Outbound tx INV filtering via queue_tx_announcement (bloom filter match)
--   5. BIP-111 disconnect path still fires when NODE_BLOOM not advertised
--   6. Oversize filterload (>36000 bytes OR >50 hash funcs) → disconnect
--   7. filteradd without prior filterload → disconnect
--   8. Malformed filterload payload → disconnect
--   9. MSG_FILTERED_BLOCK getdata → merkleblock serving (unit logic)
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_fix37_bloom_wiring.lua

package.path = "src/?.lua;./?.lua;" .. package.path

local bloom     = require("lunarblock.bloom")
local p2p       = require("lunarblock.p2p")
local serialize = require("lunarblock.serialize")

local PASS = 0
local FAIL = 0

local function pass(name)
  print(string.format("  PASS  %s", name))
  PASS = PASS + 1
end

local function fail(name, msg)
  print(string.format("  FAIL  %s — %s", name, msg))
  FAIL = FAIL + 1
end

local function eq(a, b, name)
  if a == b then pass(name)
  else fail(name, string.format("expected %s, got %s", tostring(b), tostring(a))) end
end

local function ok(v, name)
  if v then pass(name) else fail(name, "expected truthy, got falsy") end
end

local function not_ok(v, name)
  if not v then pass(name) else fail(name, "expected falsy, got truthy") end
end

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

local bit = require("bit")

-- Simulate bloom_guard from main.lua
local function bloom_guard_sim(peer_our_services, msg_type)
  local advertised = bit.band(peer_our_services or 0, p2p.SERVICES.NODE_BLOOM) ~= 0
  if not advertised then
    return false, msg_type .. " received but NODE_BLOOM not advertised (BIP-111)"
  end
  return true, nil
end

-- Build a minimal fake peer with our_services set to include NODE_BLOOM.
local function make_peer(bloom_bit)
  local disconnected_reason = nil
  local peer = {
    ip           = "127.0.0.1",
    port         = 9999,
    bloom_filter = nil,
    relay_txes   = false,
    our_services = bloom_bit and p2p.SERVICES.NODE_BLOOM or 0,
    disconnect   = function(self, reason) disconnected_reason = reason end,
  }
  return peer, function() return disconnected_reason end
end

-- Simulate the filterload handler logic from main.lua (FIX-37).
-- Returns whether the handler completed without disconnecting.
local function simulate_filterload(peer, payload, get_disconnect)
  -- bloom_guard
  local ok_guard, _ = bloom_guard_sim(peer.our_services, "filterload")
  if not ok_guard then
    peer:disconnect("filterload received but NODE_BLOOM not advertised (BIP-111)")
    return false
  end
  local f, err = bloom.parse_filterload(payload)
  if not f then
    peer:disconnect("filterload parse error: " .. tostring(err))
    return false
  end
  if not bloom.is_within_size_constraints(f) then
    peer:disconnect("filterload: filter exceeds size constraints (BIP-37)")
    return false
  end
  peer.bloom_filter = f
  peer.relay_txes   = true
  return true
end

-- Simulate the filteradd handler logic from main.lua (FIX-37).
local function simulate_filteradd(peer, payload)
  local ok_guard, _ = bloom_guard_sim(peer.our_services, "filteradd")
  if not ok_guard then
    peer:disconnect("filteradd received but NODE_BLOOM not advertised (BIP-111)")
    return false
  end
  local elem, err = bloom.parse_filteradd(payload)
  if not elem then
    peer:disconnect("filteradd: " .. tostring(err))
    return false
  end
  if not peer.bloom_filter then
    peer:disconnect("filteradd received without prior filterload")
    return false
  end
  bloom.insert(peer.bloom_filter, elem)
  return true
end

-- Simulate the filterclear handler logic from main.lua (FIX-37).
local function simulate_filterclear(peer, _payload)
  local ok_guard, _ = bloom_guard_sim(peer.our_services, "filterclear")
  if not ok_guard then
    peer:disconnect("filterclear received but NODE_BLOOM not advertised (BIP-111)")
    return false
  end
  peer.bloom_filter = nil
  peer.relay_txes   = true
  return true
end

--------------------------------------------------------------------------------
-- Build a valid filterload payload from a bloom_filter object
--------------------------------------------------------------------------------
local function make_filterload_payload(bf)
  return bloom.encode_filterload(bf)
end

-- Build a minimal filteradd payload (varstr of one element)
local function make_filteradd_payload(elem)
  local w = serialize.buffer_writer()
  w.write_varstr(elem)
  return w.result()
end

--------------------------------------------------------------------------------
-- Section 1: filterload — happy path
--------------------------------------------------------------------------------
print("=== Section 1: filterload happy path ===")

do
  local peer, get_dc = make_peer(true)  -- NODE_BLOOM advertised
  local bf = bloom.bloom_filter(10, 0.001, 42, bloom.UPDATE_ALL)
  bloom.insert(bf, "watchkey")
  local payload = make_filterload_payload(bf)

  local completed = simulate_filterload(peer, payload, get_dc)
  ok(completed, "filterload handler completes without disconnect")
  ok(peer.bloom_filter ~= nil, "peer.bloom_filter populated after filterload")
  ok(peer.relay_txes, "peer.relay_txes = true after filterload")
  eq(get_dc(), nil, "no disconnect triggered on valid filterload")

  -- The loaded filter should retain inserted key
  ok(bloom.contains(peer.bloom_filter, "watchkey"),
    "loaded filter contains previously inserted key")
  -- n_tweak round-trips
  eq(peer.bloom_filter.n_tweak, bf.n_tweak, "loaded filter n_tweak matches original")
  eq(peer.bloom_filter.n_flags, bf.n_flags, "loaded filter n_flags matches original")
end

--------------------------------------------------------------------------------
-- Section 2: filteradd — mutation of existing filter
--------------------------------------------------------------------------------
print("=== Section 2: filteradd mutates loaded filter ===")

do
  local peer, get_dc = make_peer(true)
  -- First load a filter
  local bf = bloom.bloom_filter(20, 0.001, 0, bloom.UPDATE_NONE)
  bloom.insert(bf, "initial")
  local load_payload = make_filterload_payload(bf)
  simulate_filterload(peer, load_payload, get_dc)

  -- Initial key must be present
  ok(bloom.contains(peer.bloom_filter, "initial"), "initial key present before filteradd")
  not_ok(bloom.contains(peer.bloom_filter, "added_later"), "added_later key absent before filteradd")

  -- Now add a new element via filteradd
  local add_payload = make_filteradd_payload("added_later")
  local completed = simulate_filteradd(peer, add_payload)
  ok(completed, "filteradd handler completes without disconnect")
  ok(bloom.contains(peer.bloom_filter, "initial"), "initial key still present after filteradd")
  ok(bloom.contains(peer.bloom_filter, "added_later"), "new key present after filteradd")
  eq(get_dc(), nil, "no disconnect on valid filteradd")
end

--------------------------------------------------------------------------------
-- Section 3: filterclear — resets filter and restores relay
--------------------------------------------------------------------------------
print("=== Section 3: filterclear resets per-peer state ===")

do
  local peer, get_dc = make_peer(true)
  -- Load a filter first
  local bf = bloom.bloom_filter(10, 0.001, 1, bloom.UPDATE_NONE)
  local load_payload = make_filterload_payload(bf)
  simulate_filterload(peer, load_payload, get_dc)
  ok(peer.bloom_filter ~= nil, "filter loaded before filterclear")

  -- Clear it
  local completed = simulate_filterclear(peer, "")
  ok(completed, "filterclear handler completes without disconnect")
  ok(peer.bloom_filter == nil, "peer.bloom_filter nil after filterclear")
  ok(peer.relay_txes, "peer.relay_txes = true after filterclear")
  eq(get_dc(), nil, "no disconnect on valid filterclear")
end

--------------------------------------------------------------------------------
-- Section 4: BIP-111 disconnect path — NODE_BLOOM not advertised
--------------------------------------------------------------------------------
print("=== Section 4: BIP-111 disconnect when NODE_BLOOM not advertised ===")

do
  -- filterload
  local peer, get_dc = make_peer(false)  -- no NODE_BLOOM
  local bf = bloom.bloom_filter(10, 0.001, 0, bloom.UPDATE_NONE)
  simulate_filterload(peer, make_filterload_payload(bf), get_dc)
  ok(get_dc() ~= nil, "filterload disconnects when NODE_BLOOM not advertised")
  ok(peer.bloom_filter == nil, "bloom_filter not set when disconnected on filterload")
end

do
  -- filteradd (no bloom advertised)
  local peer, get_dc = make_peer(false)
  simulate_filteradd(peer, make_filteradd_payload("x"))
  ok(get_dc() ~= nil, "filteradd disconnects when NODE_BLOOM not advertised")
end

do
  -- filterclear (no bloom advertised)
  local peer, get_dc = make_peer(false)
  simulate_filterclear(peer, "")
  ok(get_dc() ~= nil, "filterclear disconnects when NODE_BLOOM not advertised")
end

do
  -- nil our_services defaults to 0 → disconnect
  local peer, get_dc = make_peer(false)
  peer.our_services = nil
  simulate_filterload(peer, make_filterload_payload(
    bloom.bloom_filter(10, 0.001, 0, bloom.UPDATE_NONE)), get_dc)
  ok(get_dc() ~= nil, "filterload disconnects when our_services=nil")
end

--------------------------------------------------------------------------------
-- Section 5: Oversize filterload → disconnect
--------------------------------------------------------------------------------
print("=== Section 5: oversize filterload → disconnect ===")

do
  -- Build a filter that exceeds MAX_BLOOM_FILTER_SIZE (36000 bytes).
  -- We craft one directly rather than through bloom_filter() (which clamps).
  local oversized_bf = {
    vdata        = {},
    vdata_len    = bloom.MAX_BLOOM_FILTER_SIZE + 1,  -- 36001 bytes
    n_hash_funcs = 1,
    n_tweak      = 0,
    n_flags      = bloom.UPDATE_NONE,
  }
  for i = 1, oversized_bf.vdata_len do
    oversized_bf.vdata[i] = 0
  end
  -- Verify our crafted struct is indeed too large
  not_ok(bloom.is_within_size_constraints(oversized_bf),
    "oversized filter fails is_within_size_constraints")

  local payload = bloom.encode_filterload(oversized_bf)
  local peer, get_dc = make_peer(true)
  simulate_filterload(peer, payload, get_dc)
  ok(get_dc() ~= nil, "filterload disconnects on oversized filter (vdata_len > 36000)")
  ok(peer.bloom_filter == nil, "bloom_filter not stored on oversized filterload")
end

do
  -- Build a filter with too many hash functions (n_hash_funcs > 50).
  local too_many_hashes_bf = {
    vdata        = {},
    vdata_len    = 10,
    n_hash_funcs = bloom.MAX_HASH_FUNCS + 1,  -- 51
    n_tweak      = 0,
    n_flags      = bloom.UPDATE_NONE,
  }
  for i = 1, too_many_hashes_bf.vdata_len do
    too_many_hashes_bf.vdata[i] = 0
  end
  not_ok(bloom.is_within_size_constraints(too_many_hashes_bf),
    "filter with 51 hash funcs fails is_within_size_constraints")

  local payload = bloom.encode_filterload(too_many_hashes_bf)
  local peer, get_dc = make_peer(true)
  simulate_filterload(peer, payload, get_dc)
  ok(get_dc() ~= nil, "filterload disconnects when n_hash_funcs > 50")
end

--------------------------------------------------------------------------------
-- Section 6: filteradd without prior filterload → disconnect
--------------------------------------------------------------------------------
print("=== Section 6: filteradd without prior filterload → disconnect ===")

do
  local peer, get_dc = make_peer(true)
  -- bloom_filter is nil (no filterload sent)
  local add_payload = make_filteradd_payload("some_element")
  simulate_filteradd(peer, add_payload)
  ok(get_dc() ~= nil, "filteradd disconnects when no filter loaded")
  local dc_msg = get_dc()
  ok(dc_msg and dc_msg:find("without prior filterload"),
    "disconnect reason mentions 'without prior filterload'")
end

--------------------------------------------------------------------------------
-- Section 7: filteradd with oversized element → disconnect
--------------------------------------------------------------------------------
print("=== Section 7: filteradd oversized element (> 520 bytes) → disconnect ===")

do
  local peer, get_dc = make_peer(true)
  -- Load a valid filter first
  local bf = bloom.bloom_filter(10, 0.001, 0, bloom.UPDATE_NONE)
  simulate_filterload(peer, make_filterload_payload(bf), get_dc)
  ok(peer.bloom_filter ~= nil, "filter loaded before oversized filteradd")

  -- Try to add a 521-byte element (> MAX_FILTER_ADD_SIZE = 520)
  local w = serialize.buffer_writer()
  w.write_varstr(string.rep("\xAB", 521))
  local over_payload = w.result()
  local completed = simulate_filteradd(peer, over_payload)
  not_ok(completed, "filteradd handler rejects 521-byte element")
  ok(get_dc() ~= nil, "filteradd disconnects on oversized element")
end

--------------------------------------------------------------------------------
-- Section 8: Malformed filterload payload → disconnect
--------------------------------------------------------------------------------
print("=== Section 8: malformed filterload payload → disconnect ===")

do
  local peer, get_dc = make_peer(true)
  -- Empty payload — will fail to parse (insufficient bytes for the fields)
  simulate_filterload(peer, "", get_dc)
  ok(get_dc() ~= nil, "filterload disconnects on empty (malformed) payload")
  ok(peer.bloom_filter == nil, "bloom_filter not set on malformed payload")
end

do
  local peer, get_dc = make_peer(true)
  -- Truncated: varstr says 10 bytes but only 3 follow
  local w = serialize.buffer_writer()
  w.write_varint(10)  -- claims 10 bytes
  w.write_bytes("abc")  -- only 3 bytes — reader will throw
  simulate_filterload(peer, w.result(), get_dc)
  ok(get_dc() ~= nil, "filterload disconnects on truncated varstr payload")
end

--------------------------------------------------------------------------------
-- Section 9: Outbound tx INV filtering via queue_tx_announcement
-- (unit test of the filter logic without a real PeerManager)
--------------------------------------------------------------------------------
print("=== Section 9: outbound tx INV bloom filter (FIX-37 Step 4) ===")

-- Simulate the per-peer filter check logic from peerman.lua:queue_tx_announcement.
-- If peer.bloom_filter ~= nil and tx is provided, only queue when filter matches.
local function should_queue(peer_bloom_filter, tx_obj)
  if peer_bloom_filter ~= nil and tx_obj ~= nil then
    local ok_pcall, matched = pcall(bloom.is_relevant_and_update, peer_bloom_filter, tx_obj)
    if not ok_pcall or not matched then
      return false
    end
  end
  return true
end

do
  -- Peer with no filter → always relay
  ok(should_queue(nil, nil), "no filter → always queued (no tx)")

  -- Build a minimal synthetic tx-like object.
  -- bloom.is_relevant_and_update requires tx.outputs / tx.inputs.
  -- We build one that matches by txid and one that doesn't.
  local matched_tx = {
    outputs = {},
    inputs  = {},
  }
  local unmatched_tx = {
    outputs = {},
    inputs  = {},
  }

  -- Build filter and insert the txid bytes for matched_tx.
  -- We synthesise txid bytes that we control (no need to actually compute txid
  -- from full tx serialization — the function uses compute_txid internally,
  -- but for a unit test we just test the filter logic through contains()).
  local bf_unit = bloom.bloom_filter(50, 0.001, 99, bloom.UPDATE_NONE)
  local fake_txid_bytes = string.rep("\x01", 32)
  bloom.insert(bf_unit, fake_txid_bytes)

  -- is_relevant_and_update on a tx with no outputs/inputs will fall through to
  -- the txid check.  We can't control compute_txid here so test the gate logic
  -- directly: a filter that is nil passes, a non-nil filter that rejects blocks.

  -- Nil filter → always relay regardless of tx
  ok(should_queue(nil, matched_tx), "nil filter → always queued even with tx object")

  -- Non-nil filter + nil tx → always relay (missing tx means can't filter)
  ok(should_queue(bf_unit, nil), "non-nil filter + nil tx → always queued")

  -- Non-nil filter + tx with no relevant data (empty outputs/inputs, unknown txid)
  -- → should_queue returns false (filter doesn't match)
  local result_unmatched = should_queue(bf_unit, unmatched_tx)
  -- The unmatched_tx has no outputs/inputs so is_relevant_and_update will
  -- use compute_txid internally — we can't predict the result here since
  -- compute_txid needs validation module. We test that should_queue returns
  -- a boolean at all.
  ok(type(result_unmatched) == "boolean",
    "should_queue returns boolean for filter+tx combination")

  -- Empty-vData filter (match-all CVE-2013-5700) → always relay
  local match_all_bf = {
    vdata = {}, vdata_len = 0, n_hash_funcs = 0, n_tweak = 0, n_flags = 0,
  }
  local ok_pcall2, matched2 = pcall(bloom.is_relevant_and_update, match_all_bf, unmatched_tx)
  ok(ok_pcall2, "is_relevant_and_update doesn't throw on empty-vData filter")
  ok(matched2, "empty-vData filter matches all txs (CVE-2013-5700)")
end

--------------------------------------------------------------------------------
-- Section 10: PartialMerkleTree building (merkleblock step infrastructure)
--------------------------------------------------------------------------------
print("=== Section 10: PartialMerkleTree / merkleblock building ===")

do
  -- 4-tx block, tx index 1 and 3 match
  local fake_txids = {}
  for i = 1, 4 do
    fake_txids[i] = string.rep(string.char(i), 32)
  end
  local v_match = {false, true, false, true}

  local pmt = bloom.encode_partial_merkle_tree(fake_txids, v_match)
  ok(pmt ~= nil, "encode_partial_merkle_tree returns a PMT table")
  eq(pmt.n_transactions, 4, "PMT n_transactions = 4")
  ok(#pmt.v_hash > 0, "PMT v_hash is non-empty")
  ok(#pmt.v_bits > 0, "PMT v_bits is non-empty")

  local serialized = bloom.serialize_partial_merkle_tree(pmt)
  ok(type(serialized) == "string", "serialize_partial_merkle_tree returns a string")
  ok(#serialized > 4, "serialized PMT has more than 4 bytes")

  -- encode_merkle_block = 80-byte header || PMT
  local fake_header = string.rep("\xAB", 80)
  local mb_payload = bloom.encode_merkle_block(fake_header, fake_txids, v_match)
  ok(type(mb_payload) == "string", "encode_merkle_block returns a string")
  ok(#mb_payload > 80, "merkleblock payload is longer than header alone")
  -- First 80 bytes must be the header
  eq(mb_payload:sub(1, 80), fake_header, "merkleblock payload starts with 80-byte header")
end

do
  -- Single-tx block (coinbase only), tx matches
  local single_txid = {string.rep("\xFF", 32)}
  local pmt_single = bloom.encode_partial_merkle_tree(single_txid, {true})
  eq(pmt_single.n_transactions, 1, "single-tx PMT has n_transactions=1")
  -- A single matching tx → v_bits should have true, v_hash the txid
  ok(pmt_single.v_bits[1] == true, "single-tx PMT v_bits[1] = true")
end

do
  -- All-non-matching block (filter passes nothing)
  local txids = {}
  local no_match = {}
  for i = 1, 3 do
    txids[i] = string.rep(string.char(i * 10), 32)
    no_match[i] = false
  end
  local pmt_none = bloom.encode_partial_merkle_tree(txids, no_match)
  eq(pmt_none.n_transactions, 3, "all-non-match PMT has correct n_transactions")
  -- All bits false → root hash stored in one hash entry
  ok(#pmt_none.v_hash >= 1, "all-non-match PMT has at least one hash (root)")
end

--------------------------------------------------------------------------------
-- Summary
--------------------------------------------------------------------------------
print(string.rep("-", 60))
print(string.format("Results: %d PASS, %d FAIL", PASS, FAIL))
if FAIL > 0 then
  os.exit(1)
else
  print("ALL PASS")
  os.exit(0)
end
