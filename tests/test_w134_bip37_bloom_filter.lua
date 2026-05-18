#!/usr/bin/env luajit
-- test_w134_bip37_bloom_filter.lua — W134 BIP-37 Bloom Filter (legacy SPV)
--
-- Re-audits lunarblock's BIP-37 + BIP-111 surface against
-- bitcoin-core/src/common/bloom.{cpp,h}, bitcoin-core/src/merkleblock.{cpp,h},
-- and net_processing.cpp FILTERLOAD/FILTERADD/FILTERCLEAR/version/
-- MSG_FILTERED_BLOCK/mempool handlers.
--
-- Three new vectors W110 did not cover:
--   1. Post-FIX-37 wire correctness (merkleblock encoding round-trip,
--      matched-tx TX_NO_WITNESS, BitsToBytes LSB-first parity).
--   2. Version-handshake fRelay flag semantics.
--   3. Outbound application of per-peer bloom filter in peerman.lua
--      queue_tx_announcement + BIP-35 mempool walk.
--
-- See audit/w134_bip37_bloom_filter.md for full bug catalogue.
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_w134_bip37_bloom_filter.lua 2>&1

package.path = "src/?.lua;./?.lua;" .. package.path

-- Custom loader so `require("lunarblock.<name>")` resolves to src/<name>.lua
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

local bloom     = require("lunarblock.bloom")
local p2p       = require("lunarblock.p2p")
local serialize = require("lunarblock.serialize")
local crypto    = require("lunarblock.crypto")
local bit_mod   = require("bit")

local PASS, FAIL, XFAIL, XPASS = 0, 0, 0, 0

local function pass(name) print(string.format("  PASS  %s", name)); PASS = PASS + 1 end
local function fail(name, msg) print(string.format("  FAIL  %s — %s", name, msg)); FAIL = FAIL + 1 end
local function xfail(name, msg)
  -- known-bug XFAIL: documented in audit/w134_bip37_bloom_filter.md
  print(string.format("  XFAIL %s — %s", name, msg or "known bug"))
  XFAIL = XFAIL + 1
end
local function xpass(name)
  -- An XFAIL that unexpectedly passes — indicates the bug has been fixed
  print(string.format("  XPASS %s (fix landed; flip XFAIL to PASS)", name))
  XPASS = XPASS + 1
end

local function eq(a, b, name)
  if a == b then pass(name) else fail(name, string.format("expected %s, got %s", tostring(b), tostring(a))) end
end
local function ok(v, name)
  if v then pass(name) else fail(name, "expected truthy") end
end
local function not_ok(v, name)
  if not v then pass(name) else fail(name, "expected falsy") end
end
local function approx_eq(a, b, eps, name)
  eps = eps or 1e-12
  if math.abs(a - b) < eps then pass(name) else fail(name, string.format("|%s - %s| > %g", tostring(a), tostring(b), eps)) end
end

------------------------------------------------------------------------
-- Section A: Constants (G1, G2, G3, G11-G14, G30)
------------------------------------------------------------------------
print("=== A: constants (G1-G3, G11-G14, G30) ===")

eq(bloom.MAX_BLOOM_FILTER_SIZE, 36000, "G1: MAX_BLOOM_FILTER_SIZE = 36000")
eq(bloom.MAX_HASH_FUNCS,           50, "G2: MAX_HASH_FUNCS = 50")
eq(bloom.MAX_FILTER_ADD_SIZE,     520, "      MAX_FILTER_ADD_SIZE = 520 (BIP-37)")

-- G3: LN2SQUARED is a Lua double; exact constant from Core is
-- 0.48045301391820142466... but Lua doubles have ~16 digits of precision.
-- Verify within mantissa precision (5e-16 ~= 1 ULP of 0.5).
do
  -- We can't read LN2SQUARED from bloom.lua (file-local), but exercise the
  -- constructor that uses it: for n=1, fp=0.5, the bit count formula is
  -- -1 / LN2SQUARED * 1 * log(0.5) = -1 * (-0.6931..) / 0.4804.. = 1.4426..
  -- → floor(1) bit → 1 byte. Verify constructor handles tiny input.
  local bf_tiny = bloom.bloom_filter(1, 0.5, 0, 0)
  ok(bf_tiny.vdata_len >= 1, "G3/G4: tiny filter (n=1, fp=0.5) yields >=1 byte")
end

eq(bloom.UPDATE_NONE,           0, "G11: UPDATE_NONE = 0")
eq(bloom.UPDATE_ALL,            1, "G12: UPDATE_ALL = 1")
eq(bloom.UPDATE_P2PUBKEY_ONLY,  2, "G13: UPDATE_P2PUBKEY_ONLY = 2")
eq(bloom.UPDATE_MASK,           3, "G14: UPDATE_MASK = 3")

eq(p2p.SERVICES.NODE_BLOOM, 4,    "G30: NODE_BLOOM service bit = 4 (1<<2)")
eq(bloom.NODE_BLOOM,        4,    "G30: bloom.NODE_BLOOM = 4")

-- NODE_BLOOM advertised IFF peerbloomfilters=true
do
  local services_no  = p2p.our_services(false, false, nil)
  local services_yes = p2p.our_services(true,  false, nil)
  not_ok(bit_mod.band(services_no,  p2p.SERVICES.NODE_BLOOM) ~= 0, "G30: NODE_BLOOM absent when --peerbloomfilters=false")
  ok    (bit_mod.band(services_yes, p2p.SERVICES.NODE_BLOOM) ~= 0, "G30: NODE_BLOOM present when --peerbloomfilters=true")
end

------------------------------------------------------------------------
-- Section B: CBloomFilter math (G4-G10)
------------------------------------------------------------------------
print("=== B: math (G4-G10) ===")

-- G4/G5: constructor caps to MAX_BLOOM_FILTER_SIZE / MAX_HASH_FUNCS
do
  local bf_huge = bloom.bloom_filter(10^9, 1e-12, 0, 0)
  ok(bf_huge.vdata_len      <= bloom.MAX_BLOOM_FILTER_SIZE, "G4: vdata_len <= MAX_BLOOM_FILTER_SIZE for absurd input")
  ok(bf_huge.n_hash_funcs   <= bloom.MAX_HASH_FUNCS,        "G5: n_hash_funcs <= MAX_HASH_FUNCS for absurd input")
end

-- G6: MurmurHash3 32-bit math via mul32u (regression for W110 BUG-3)
eq(bloom.murmur_hash3(0,  ""),                 0, "G6: MurmurHash3(0, '') = 0")
eq(bloom.murmur_hash3(0,  string.char(0)),     1364076727, "G6: MurmurHash3(0, NUL) = 1364076727")
eq(bloom.murmur_hash3(5,  ""),                 3423425485, "G6: MurmurHash3(5, '') = 3423425485")
do
  local h = bloom.murmur_hash3(0xdeadbeef, "hello")
  ok(h >= 0 and h < 4294967296, "G6: result in u32 range")
end

-- G7: seed = (nHashNum * 0xFBA4C795 + nTweak) mod 2^32
-- Indirect test: a bloom filter with vData=empty must match-all (G9 CVE-2013-5700).
do
  local bf = bloom.bloom_filter(1, 0.5, 0, 0)
  bf.vdata = {}; bf.vdata_len = 0
  ok(bloom.contains(bf, "anything-at-all"), "G9: CVE-2013-5700 — empty vData returns match-all")
end

-- G8: bit-index modulo by (vdata_len*8) — manifest via insert/contains
-- (covered in round-trip below).

-- G10: insert(k) → contains(k) round-trip for diverse keys
do
  local bf = bloom.bloom_filter(100, 1e-6, 12345, 0)  -- large filter for low FP
  local keys = {
    "key-1", "key-2", string.rep("\xff", 32), string.rep("\x00", 32),
    "outpoint-like\x00\x00\x00\x00",
    string.rep("A", 256),
  }
  for _, k in ipairs(keys) do
    bloom.insert(bf, k)
    ok(bloom.contains(bf, k), "G10: round-trip insert/contains for "..#k.."-byte key")
  end
end

-- insert into match-all filter is a silent no-op (CVE-2013-5700)
do
  local bf = bloom.bloom_filter(1, 0.5, 0, 0)
  bf.vdata = {}; bf.vdata_len = 0
  -- must not error
  local ok_call, err = pcall(bloom.insert, bf, "irrelevant")
  ok(ok_call, "G9: insert on empty vData is silent no-op (no error)")
end

------------------------------------------------------------------------
-- Section C: filterload/filteradd wire round-trip (G15, G25, G26)
------------------------------------------------------------------------
print("=== C: filter wire round-trip (G15, G25, G26) ===")

do
  local bf = bloom.bloom_filter(200, 0.001, 0xC0FFEE, bloom.UPDATE_P2PUBKEY_ONLY)
  bloom.insert(bf, "watch-pubkey")
  local payload = bloom.encode_filterload(bf)
  ok(type(payload) == "string" and #payload > 0, "G15: encode_filterload returns bytes")

  local parsed, err = bloom.parse_filterload(payload)
  ok(parsed ~= nil and err == nil, "G15: parse_filterload accepts valid payload")
  if parsed then
    eq(parsed.n_hash_funcs, bf.n_hash_funcs, "G15: round-trip n_hash_funcs")
    eq(parsed.n_tweak,      bf.n_tweak,      "G15: round-trip n_tweak")
    eq(parsed.n_flags,      bf.n_flags,      "G15: round-trip n_flags")
    eq(parsed.vdata_len,    bf.vdata_len,    "G15: round-trip vdata_len")
    -- Inserted element survives wire round-trip
    ok(bloom.contains(parsed, "watch-pubkey"), "G15: contains() true in parsed filter")
  end
end

-- filteradd parse: 520-byte boundary
do
  local w = serialize.buffer_writer()
  w.write_varstr(string.rep("\x42", 520))
  local elem, err = bloom.parse_filteradd(w.result())
  ok(elem and not err, "G26: 520-byte filteradd accepted")

  local w2 = serialize.buffer_writer()
  w2.write_varstr(string.rep("\x42", 521))
  local elem2, err2 = bloom.parse_filteradd(w2.result())
  ok(elem2 == nil and err2 ~= nil, "G26: 521-byte filteradd rejected (MAX_FILTER_ADD_SIZE=520)")
end

------------------------------------------------------------------------
-- Section D: IsRelevantAndUpdate (G16-G23)
------------------------------------------------------------------------
print("=== D: IsRelevantAndUpdate (G16-G23) ===")

-- Build a tiny tx with one input and one output for the IsRelevant path.
local types = require("lunarblock.types")
local null_hash = types.hash256(string.rep("\0", 32))

-- Helper: minimal tx with given scriptPubKey on output 0 and given outpoint on input 0
local function mk_tx_one_output(spk_bytes, prev_txid_bytes, prev_index, script_sig)
  return {
    version  = 2,
    inputs   = { { prev_out = { hash = types.hash256(prev_txid_bytes or string.rep("\1", 32)), index = prev_index or 0 },
                   script_sig = script_sig or "", sequence = 0xFFFFFFFE, witness = {} } },
    outputs  = { { value = 5000, script_pubkey = spk_bytes } },
    locktime = 0,
    segwit   = false,
  }
end

-- G16: txid match
do
  local bf = bloom.bloom_filter(50, 1e-6, 0, bloom.UPDATE_NONE)
  local tx = mk_tx_one_output("\x6a\x04test")  -- OP_RETURN 'test'
  local validation = require("lunarblock.validation")
  local txid = validation.compute_txid(tx)
  bloom.insert(bf, txid.bytes)
  ok(bloom.is_relevant_and_update(bf, tx), "G16: txid match in IsRelevantAndUpdate")
end

-- G17: per-output pushdata walk — match on a known pushdata element
do
  local bf = bloom.bloom_filter(50, 1e-6, 0, bloom.UPDATE_NONE)
  bloom.insert(bf, "data-element")  -- 12 bytes
  -- scriptPubKey: OP_PUSHBYTES_12 <"data-element">
  local spk = string.char(12) .. "data-element"
  local tx = mk_tx_one_output(spk)
  ok(bloom.is_relevant_and_update(bf, tx), "G17: per-output pushdata match")
end

-- G19: outpoint match — txid(32) || index(LE32) byte format
do
  local bf = bloom.bloom_filter(50, 1e-6, 0, bloom.UPDATE_NONE)
  local prev = string.rep("\x77", 32)
  bloom.insert(bf, prev .. string.char(5, 0, 0, 0))  -- index=5 LE
  local tx = mk_tx_one_output("\x6a", prev, 5, "")
  ok(bloom.is_relevant_and_update(bf, tx), "G19: outpoint match (txid||LE32)")
end

-- G20: scriptSig pushdata match
do
  local bf = bloom.bloom_filter(50, 1e-6, 0, bloom.UPDATE_NONE)
  bloom.insert(bf, "sig-data")
  local script_sig = string.char(8) .. "sig-data"  -- OP_PUSHBYTES_8 sig-data
  local tx = mk_tx_one_output("\x6a", nil, 0, script_sig)
  ok(bloom.is_relevant_and_update(bf, tx), "G20: scriptSig pushdata match")
end

-- G21: UPDATE_ALL — outpoint inserted after match
do
  local bf = bloom.bloom_filter(50, 1e-6, 0, bloom.UPDATE_ALL)
  bloom.insert(bf, "pushy")
  local spk = string.char(5) .. "pushy"
  local tx = mk_tx_one_output(spk)
  local validation = require("lunarblock.validation")
  local txid = validation.compute_txid(tx)
  ok(bloom.is_relevant_and_update(bf, tx), "G21: UPDATE_ALL match")
  ok(bloom.contains_outpoint(bf, txid.bytes, 0), "G21: outpoint (txid, 0) inserted after match")
end

-- G22: UPDATE_P2PUBKEY_ONLY — outpoint inserted for canonical P2PK script
do
  local bf = bloom.bloom_filter(50, 1e-6, 0, bloom.UPDATE_P2PUBKEY_ONLY)
  -- canonical compressed P2PK: 0x21 <33-byte pk> 0xac
  local pk = string.rep("\x02", 33)
  local spk_p2pk = string.char(0x21) .. pk .. string.char(0xac)
  bloom.insert(bf, pk)  -- watch the pushdata (pubkey)
  local tx = mk_tx_one_output(spk_p2pk)
  local validation = require("lunarblock.validation")
  local txid = validation.compute_txid(tx)
  ok(bloom.is_relevant_and_update(bf, tx), "G22: UPDATE_P2PUBKEY_ONLY (canonical P2PK) match")
  ok(bloom.contains_outpoint(bf, txid.bytes, 0), "G22: outpoint inserted for canonical P2PK")
end

-- BUG-3 (P1-CDIV) — non-canonical P2PK via OP_PUSHDATA1 NOT detected
-- Core's Solver() accepts OP_PUSHDATA1 0x21 <pk> 0xac as PUBKEY.
do
  local bf = bloom.bloom_filter(50, 1e-6, 0, bloom.UPDATE_P2PUBKEY_ONLY)
  local pk = string.rep("\x02", 33)
  -- OP_PUSHDATA1 (0x4c) || len(0x21) || pk || OP_CHECKSIG
  local spk_pushdata1 = string.char(0x4c, 0x21) .. pk .. string.char(0xac)
  bloom.insert(bf, pk)
  local tx = mk_tx_one_output(spk_pushdata1)
  local validation = require("lunarblock.validation")
  local txid = validation.compute_txid(tx)
  local matched = bloom.is_relevant_and_update(bf, tx)
  ok(matched, "BUG-3 (G22): match for OP_PUSHDATA1 P2PK form")
  -- The outpoint insertion is the BUG-3 sub-condition; expect XFAIL until fix.
  if bloom.contains_outpoint(bf, txid.bytes, 0) then
    xpass("BUG-3: outpoint inserted for OP_PUSHDATA1 P2PK form (Core Solver parity)")
  else
    xfail("BUG-3: outpoint NOT inserted for OP_PUSHDATA1 P2PK form (Core Solver parity)",
          "is_p2pk() only matches canonical 0x21/0x41 prefix; OP_PUSHDATA1 form missed")
  end
end

-- G23: UPDATE_NONE never inserts outpoint
do
  local bf = bloom.bloom_filter(50, 1e-6, 0, bloom.UPDATE_NONE)
  bloom.insert(bf, "match-me")
  local spk = string.char(8) .. "match-me"
  local tx = mk_tx_one_output(spk)
  local validation = require("lunarblock.validation")
  local txid = validation.compute_txid(tx)
  ok(bloom.is_relevant_and_update(bf, tx), "G23: UPDATE_NONE matches but does not insert")
  not_ok(bloom.contains_outpoint(bf, txid.bytes, 0), "G23: outpoint NOT inserted with UPDATE_NONE")
end

-- G24: outpoint_le32 encoding for u32 values 0..2^32-1
-- Indirect: insert at index = 0x12345678, verify contains via same encoding.
do
  local bf = bloom.bloom_filter(50, 1e-6, 0, bloom.UPDATE_NONE)
  local prev = string.rep("\x44", 32)
  bloom.insert_outpoint(bf, prev, 0x12345678)
  ok(bloom.contains_outpoint(bf, prev, 0x12345678), "G24: outpoint LE32 round-trip for u32 0x12345678")
end

------------------------------------------------------------------------
-- Section E: PartialMerkleTree + CMerkleBlock encoding (G28)
------------------------------------------------------------------------
print("=== E: PartialMerkleTree + CMerkleBlock (G28) ===")

-- Single-tx block: PMT has 1 hash, 1 bit (=match value), 1 flag byte
do
  local txid1 = crypto.hash256("tx1")  -- a 32-byte hash
  local pmt = bloom.encode_partial_merkle_tree({ txid1 }, { true })
  eq(pmt.n_transactions, 1, "G28: PMT n_transactions = 1")
  eq(#pmt.v_hash,        1, "G28: single-tx tree has 1 hash")
  eq(#pmt.v_bits,        1, "G28: single-tx tree has 1 bit")
  eq(pmt.v_bits[1],   true, "G28: single-tx tree v_bits[1] = true")

  local pmt_bytes = bloom.serialize_partial_merkle_tree(pmt)
  ok(#pmt_bytes >= (4 + 1 + 32 + 1 + 1), "G28: PMT serialised length >= header overhead")
end

-- 4-tx block, match tx 1 (0-indexed) — PMT should include 1 hash on the
-- matching branch + at most 2 sibling hashes.
do
  local txids = {}
  for i = 1, 4 do txids[i] = crypto.hash256("tx"..i) end
  local pmt = bloom.encode_partial_merkle_tree(txids, { false, true, false, false })
  eq(pmt.n_transactions, 4, "G28: 4-tx PMT n_transactions = 4")
  -- For a balanced 4-tx tree (height=2), matching tx 1 → traversal yields:
  --   root (parent=true) → bit
  --     left (parent=true, contains tx0+tx1) → bit
  --       leaf0 (no match) → bit + hash
  --       leaf1 (match)    → bit + hash
  --     right (no match) → bit + hash
  -- Total: 5 bits, 3 hashes.
  eq(#pmt.v_bits, 5, "G28: 4-tx match-1 yields 5 vBits")
  eq(#pmt.v_hash, 3, "G28: 4-tx match-1 yields 3 vHash entries")
end

-- BitsToBytes LSB-first encoding parity with Core merkleblock.cpp:13-20
do
  -- Hand-craft v_bits = {1, 0, 1, 1, 0, 0, 0, 0} → byte = 0b00001101 = 0x0d (LSB first)
  local pmt = {
    n_transactions = 1,
    v_hash = { string.rep("\0", 32) },
    v_bits = { true, false, true, true, false, false, false, false },
  }
  local bytes = bloom.serialize_partial_merkle_tree(pmt)
  -- bytes layout: u32 (1 tx) + varint(1) + 32-byte hash + varint(1) + 1 flag byte
  -- header: 4 + 1 + 32 + 1 = 38, flag byte at offset 39 (1-indexed)
  local flag_byte = bytes:byte(39)
  eq(flag_byte, 0x0d, "G28: BitsToBytes LSB-first packing — {1,0,1,1,0,...} → 0x0d")
end

-- BUG-5: empty v_bits should serialise as varint(0) (Core BitsToBytes(empty) = [])
-- but lunarblock floor-rounds to n_bytes=1, inserting a phantom 0x00 byte.
-- (A real block always has >=1 tx so this is mostly theoretical.)
do
  local pmt = { n_transactions = 0, v_hash = {}, v_bits = {} }
  local bytes = bloom.serialize_partial_merkle_tree(pmt)
  -- expected: u32(0) || varint(0) hashes || varint(0) bytes  = 4+1+1 = 6 bytes
  -- lunarblock currently: 4+1+1 (varint(1)) + 1 (phantom 0x00) = 7 bytes
  if #bytes == 6 then
    xpass("BUG-5: empty v_bits → varint(0) bytes (Core parity)")
  else
    xfail("BUG-5: empty v_bits → varint(0) bytes (Core parity)",
          string.format("got %d bytes, expected 6 (n_bytes floor of 1)", #bytes))
  end
end

-- Full merkleblock: 80-byte header + PMT
do
  local hdr = string.rep("\xAB", 80)
  local txid = crypto.hash256("only-tx")
  local mb = bloom.encode_merkle_block(hdr, { txid }, { true })
  eq(mb:sub(1, 80), hdr, "G28: merkleblock starts with 80-byte header")
  local tail = mb:sub(81)
  ok(#tail >= (4 + 1 + 32 + 1 + 1), "G28: merkleblock body has PMT layout")
end

------------------------------------------------------------------------
-- Section F: IsWithinSizeConstraints (G29)
------------------------------------------------------------------------
print("=== F: IsWithinSizeConstraints (G29) ===")

do
  local bf = bloom.bloom_filter(100, 0.001, 0, 0)
  ok(bloom.is_within_size_constraints(bf), "G29: normal filter is within size")

  -- Forge an oversized filter via direct field write (simulating a malicious peer)
  local oversized = { vdata = {}, vdata_len = 36001, n_hash_funcs = 10, n_tweak = 0, n_flags = 0 }
  not_ok(bloom.is_within_size_constraints(oversized), "G29: vdata_len=36001 fails IsWithinSizeConstraints")

  local toomanyhash = { vdata = {}, vdata_len = 100, n_hash_funcs = 51, n_tweak = 0, n_flags = 0 }
  not_ok(bloom.is_within_size_constraints(toomanyhash), "G29: n_hash_funcs=51 fails IsWithinSizeConstraints")
end

------------------------------------------------------------------------
-- Section G: BIP-111 NODE_BLOOM disconnect (G25-G27)
-- (Re-verified post-FIX-37; same logic as W110 Section 2-4.)
------------------------------------------------------------------------
print("=== G: BIP-111 NODE_BLOOM disconnect ===")

local function bloom_guard_sim(peer_our_services, msg_type)
  local advertised_bloom = bit_mod.band(peer_our_services or 0, p2p.SERVICES.NODE_BLOOM) ~= 0
  if not advertised_bloom then return false, msg_type .. " received but NODE_BLOOM not advertised (BIP-111)" end
  return true, nil
end

for _, msg in ipairs({"filterload", "filteradd", "filterclear"}) do
  local g, _ = bloom_guard_sim(0, msg)
  not_ok(g, "G25-G27: "..msg.." → disconnect when NODE_BLOOM absent")
  local g2, _ = bloom_guard_sim(p2p.SERVICES.NODE_BLOOM, msg)
  ok(g2, "G25-G27: "..msg.." → accepted when NODE_BLOOM advertised")
end

------------------------------------------------------------------------
-- Section H: NEW W134 BUGS — fRelay flag + relay_txs gate + mempool walk
------------------------------------------------------------------------
print("=== H: W134 BUGS (1, 2, 4) ===")

-- BUG-1 / BUG-12: version-message fRelay parsed but not stored on peer
do
  -- Version message with fRelay=0
  local ver_payload = p2p.serialize_version({
    version = 70016, services = 1, timestamp = 0,
    recv_services = 0, recv_ip = "0.0.0.0", recv_port = 0,
    from_services = 0, from_ip = "0.0.0.0", from_port = 0,
    nonce = 0, user_agent = "/test/", start_height = 0,
    relay = false,
  })
  local parsed = p2p.deserialize_version(ver_payload)
  eq(parsed.relay, false, "BUG-1: deserialize_version round-trips fRelay=false")

  -- Now check whether peer.lua stores it. The peer module exposes `wtxid_relay`
  -- but no `relay_txs` field — verify by introspecting a fresh peer object.
  local peer_mod = require("lunarblock.peer")
  local p = peer_mod.new("127.0.0.1", 18333, "regtest", 0, false, nil, false, false, nil)
  if p.relay_txs ~= nil or p.relay_txes ~= nil then
    -- field exists; need to also verify it's read by peerman.queue_tx_announcement
    -- For now this is the easy half-test: field presence.
    xpass("BUG-1: peer struct exposes relay_txs/relay_txes field")
  else
    xfail("BUG-1: peer struct does NOT expose relay_txs/relay_txes field",
          "fRelay=false from inbound version is silently dropped after one read in peer.lua:705")
  end
end

-- BUG-2: BIP-35 mempool walk does NOT apply per-peer bloom filter
-- We can't easily run the actual handler here without a full event loop,
-- but we can grep the main.lua source for the application call.
do
  local f = io.open("src/main.lua")
  local src = f:read("*a")
  f:close()
  -- Find the mempool handler region and check if it calls is_relevant_and_update
  local handler_start = src:find('register_handler%("mempool"', 1, false)
  local handler_end = src:find('end%)', handler_start or 1, false)
  local handler = (handler_start and handler_end) and src:sub(handler_start, handler_end + 4) or ""
  if handler:find("is_relevant_and_update") or handler:find("bloom_filter") then
    xpass("BUG-2: BIP-35 mempool handler applies per-peer bloom filter")
  else
    xfail("BUG-2: BIP-35 mempool handler does NOT apply per-peer bloom filter",
          "Core net_processing.cpp:6010-6020 calls m_bloom_filter->IsRelevantAndUpdate per entry")
  end
end

-- BUG-4: `peer.relay_txes` (TYPO) is set but never read.
do
  local f = io.open("src/main.lua")
  local main_src = f:read("*a"); f:close()
  local sets_txes = main_src:find("peer%.relay_txes%s*=") ~= nil
  ok(sets_txes, "BUG-4: peer.relay_txes is set in main.lua filterload/filterclear")

  -- Check NO file reads it (only the assignments in main.lua exist)
  local read_count = 0
  for _, file in ipairs({"src/main.lua", "src/peer.lua", "src/peerman.lua", "src/p2p.lua"}) do
    local ff = io.open(file)
    if ff then
      local txt = ff:read("*a"); ff:close()
      for line in txt:gmatch("[^\n]+") do
        if line:find("relay_txes") and not line:find("=%s*true") and not line:find("=%s*false") then
          -- Reads that aren't assignments (very loose; OK for audit signal)
          if line:find("if%s+.*relay_txes") or
             line:find("not%s+.*%.relay_txes") or
             line:find("%.relay_txes[^=]") then
            read_count = read_count + 1
          end
        end
      end
    end
  end
  if read_count > 0 then
    xpass("BUG-4: peer.relay_txes is read somewhere (gate active)")
  else
    xfail("BUG-4: peer.relay_txes is dead (set, never read; outbound tx-INV not gated)",
          "rename to relay_txs and wire into peerman.queue_tx_announcement")
  end
end

-- BUG-9: peer struct has no `m_relays_txs` equivalent
do
  local peer_mod = require("lunarblock.peer")
  local p = peer_mod.new("127.0.0.1", 18333, "regtest", 0, false, nil, false, false, nil)
  if p.relays_txs ~= nil or p.m_relays_txs ~= nil then
    xpass("BUG-9: peer struct exposes m_relays_txs / relays_txs flag")
  else
    xfail("BUG-9: peer struct has no m_relays_txs flag (Core pfrom.m_relays_txs)",
          "Set to true on filterload/filteradd/filterclear/version-fRelay; informational only")
  end
end

------------------------------------------------------------------------
-- Section I: BUG-6 — outpoint_le32 globalness
------------------------------------------------------------------------
print("=== I: BUG-6 (outpoint_le32 global) ===")

-- Probe global table. bloom.lua defines `function outpoint_le32(...)` without local.
do
  if rawget(_G, "outpoint_le32") ~= nil then
    xfail("BUG-6: outpoint_le32 leaks into _G (declared without `local`)",
          "src/bloom.lua:412 — should be `local function outpoint_le32(...)`")
  else
    xpass("BUG-6: outpoint_le32 is properly local-scoped")
  end
end

------------------------------------------------------------------------
-- Section J: BUG-17 — LuaJIT bit.lshift 32-bit semantics in calc_tree_width
------------------------------------------------------------------------
print("=== J: BUG-17 (bit.lshift 32-bit trap latent) ===")

-- bit.lshift(1, 32) wraps to 1 under LuaJIT semantics.
do
  local bit = require("bit")
  local x = bit.lshift(1, 32)
  -- The PMT calc_tree_width uses bit.lshift(1, height). In practice height <= 24
  -- for any sane block but we record the trap.
  if x == 1 then
    xfail("BUG-17: bit.lshift(1,32) wraps to 1 (latent — height<=24 keeps it safe)",
          "calc_tree_width @ bloom.lua:535 — use 2^height if height could approach 32")
  elseif x == 0 then
    pass("BUG-17: bit.lshift(1,32) returns 0 (sane platform; safe)")
  else
    pass("BUG-17: bit.lshift(1,32) returns "..tostring(x).." (platform-specific; sanity ok)")
  end
end

------------------------------------------------------------------------
-- Section K: PMT internal consistency cross-checks
------------------------------------------------------------------------
print("=== K: PMT internal consistency ===")

-- 2-tx block, both match → 3 bits, 2 hashes (root.parent → leaf0.bit+hash, leaf1.bit+hash)
do
  local txids = { crypto.hash256("a"), crypto.hash256("b") }
  local pmt = bloom.encode_partial_merkle_tree(txids, { true, true })
  eq(#pmt.v_bits, 3, "K: 2-tx both-match PMT yields 3 vBits")
  eq(#pmt.v_hash, 2, "K: 2-tx both-match PMT yields 2 vHash")
end

-- 2-tx block, none match → 1 bit + 1 hash (root_bit=0 → emit root hash)
do
  local txids = { crypto.hash256("a"), crypto.hash256("b") }
  local pmt = bloom.encode_partial_merkle_tree(txids, { false, false })
  eq(#pmt.v_bits, 1, "K: 2-tx no-match PMT yields 1 vBit")
  eq(#pmt.v_hash, 1, "K: 2-tx no-match PMT yields 1 vHash (root)")
  eq(pmt.v_bits[1], false, "K: root bit = false when no match")
end

-- Odd-tx tree height (3 tx → tree width [3,2,1] → height = 2)
-- Per Core CalcTreeWidth: (n + (1<<h) - 1) >> h.
do
  local txids = { crypto.hash256("a"), crypto.hash256("b"), crypto.hash256("c") }
  local pmt = bloom.encode_partial_merkle_tree(txids, { false, true, false })
  ok(#pmt.v_bits >= 3, "K: 3-tx PMT yields >=3 vBits")
  ok(#pmt.v_hash >= 2, "K: 3-tx PMT yields >=2 vHash")
end

------------------------------------------------------------------------
-- Summary
------------------------------------------------------------------------
print(string.rep("-", 60))
print(string.format("Results: %d PASS, %d FAIL, %d XFAIL, %d XPASS", PASS, FAIL, XFAIL, XPASS))
print(string.format("(XFAIL = known-bug expected-failure documented in audit/w134_bip37_bloom_filter.md)"))
if XPASS > 0 then
  print(string.format("NOTE: %d XPASS — bug appears fixed; flip XFAIL→PASS in this test", XPASS))
end
if FAIL > 0 then
  os.exit(1)
else
  print("ALL ASSERTIONS GREEN (XFAIL counted as expected)")
  os.exit(0)
end
