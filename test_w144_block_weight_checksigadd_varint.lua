#!/usr/bin/env luajit
-- W144 regression tests: three consensus divergences patched.
--
-- Finding 8  (MED): block weight omits 80-byte header + tx-count varint.
--   check_block computed weight as a pure per-tx sum, missing
--   (80 + varint_len(nTx)) * WITNESS_SCALE_FACTOR.  A block whose Core weight
--   is in (4 000 000, 4 000 000 + 324] was wrongly accepted.
--   Fix: add the overhead after the per-tx loop in check_block.
--
-- Finding 10 (MED): OP_CHECKSIGADD not tapscript-gated.
--   Legacy and witness-v0 scripts with OP_CHECKSIGADD (0xba) were evaluated
--   rather than rejected with BAD_OPCODE.  Core interpreter.cpp:1087 requires
--   BAD_OPCODE unless sigversion == TAPSCRIPT.
--   Fix: gate added at the top of the OP_CHECKSIGADD branch, before any pop().
--
-- Finding 15 (MED): legacy tx vin-count CompactSize accepts non-canonical encoding.
--   The legacy branch of deserialize_transaction read input-count with raw
--   read_u16le / read_u32le / read_u64le, skipping the non-canonical and
--   MAX_SIZE guards that read_varint enforces.  compute_txid re-serializes
--   canonically so the wrong leaf matched the merkle root — block wrongly accepted.
--   Fix: apply the same non-canonical + MAX_SIZE checks in the legacy branch.
--
-- Run: cd lunarblock && luajit test_w144_block_weight_checksigadd_varint.lua

package.path = "./src/?.lua;./lunarblock/?.lua;" .. package.path
package.cpath = "./lib/?.so;" .. package.cpath

local validation = require("lunarblock.validation")
local serialize  = require("lunarblock.serialize")
local consensus  = require("lunarblock.consensus")
local crypto     = require("lunarblock.crypto")
local types      = require("lunarblock.types")
local script     = require("lunarblock.script")

local pass, fail = 0, 0

local function check(name, cond, detail)
  if cond then
    io.write("PASS: " .. name .. "\n")
    pass = pass + 1
  else
    io.write("FAIL: " .. name .. (detail and (" — " .. tostring(detail)) or "") .. "\n")
    fail = fail + 1
  end
end

local function check_eq(name, got, expected)
  check(name, got == expected,
    string.format("got=%s expected=%s", tostring(got), tostring(expected)))
end

-- Expect a pcall to fail, optionally matching a substring of the error.
local function check_fails(name, fn, substr)
  local ok, err = pcall(fn)
  if ok then
    io.write("FAIL: " .. name .. " — expected failure but got success\n")
    fail = fail + 1
  else
    local msg = tostring(err)
    if substr == nil or msg:find(substr, 1, true) then
      io.write("PASS: " .. name .. "\n")
      pass = pass + 1
    else
      io.write("FAIL: " .. name .. " — wrong error: " .. msg .. "\n")
      fail = fail + 1
    end
  end
end

local function check_passes(name, fn)
  local ok, err = pcall(fn)
  if ok then
    io.write("PASS: " .. name .. "\n")
    pass = pass + 1
  else
    io.write("FAIL: " .. name .. " — unexpected error: " .. tostring(err) .. "\n")
    fail = fail + 1
  end
end

--------------------------------------------------------------------------------
-- Finding 8: Block weight formula — unit test + rejection test
--
-- The fix adds (80 + varint_len(nTx)) * WITNESS_SCALE_FACTOR to total_weight
-- after the per-tx loop.  This aligns with rest.lua:462's full-block formula:
--   stripped_size * 3 + full_size
-- where serialize_block_without_witness / serialize_block include the 80-byte
-- header and the tx-count varint.
--------------------------------------------------------------------------------
print("=== Finding 8: block weight includes header + varint overhead ===")

-- Build a minimal coinbase transaction.
-- Serialized: version(4)+vin_count(1)+null_hash(32)+null_idx(4)+
--             script_len(1)+script(2)+seq(4)+vout_count(1)+
--             value(8)+spk_len(1)+spk(1)+locktime(4) = 63 bytes
-- Weight (non-witness) = 63 * 4 = 252 WU.
local function make_coinbase()
  return types.transaction(
    1,  -- version
    { types.txin(
        types.outpoint(types.hash256(string.rep("\x00", 32)), 0xFFFFFFFF),
        "\x01\x00",   -- 2-byte coinbase scriptSig (min length)
        0xFFFFFFFF
    )},
    { types.txout(5000000000, "\x51") },  -- OP_TRUE output
    0   -- locktime
  )
end

-- Build a non-coinbase transaction with a padded output script to reach a
-- specific serialized size.  The non-null prevout_hash ensures check_block
-- does not treat this as a coinbase.
-- Serialized: version(4)+vin_count(1)+hash(32)+idx(4)+
--             script_sig_len(1)+seq(4)+vout_count(1)+
--             value(8)+spk_len(varint)+spk(N)+locktime(4)
-- For large N (N > 65535): spk_len = 5 bytes.
-- Total = 59 + 5 + N = 64 + N bytes.
local function make_padded_noncoinbase(spk_size)
  -- Build output-script varint manually so we get the exact byte count
  -- before calling types.txout (which stores it as a raw string):
  local spk = string.rep("\x51", spk_size)   -- N bytes of OP_TRUE
  return types.transaction(
    1,
    { types.txin(
        types.outpoint(types.hash256(string.rep("\xaa", 32)), 0),
        "",            -- empty scriptSig
        0xFFFFFFFF
    )},
    { types.txout(1000000, spk) },
    0
  )
end

-- Helper: compute the correct merkle root for a list of transactions.
local function compute_merkle_root(txs)
  local hashes = {}
  for i, tx in ipairs(txs) do
    hashes[i] = validation.compute_txid(tx)
  end
  local root, _ = crypto.compute_merkle_root(hashes)
  return root
end

-- Helper: build a full block with a correct merkle root header.
local function make_block(txs)
  -- Compute txids so check_block can cache them and also so we can
  -- derive the merkle root.
  local merkle_root = compute_merkle_root(txs)
  local header = types.block_header(
    1,                       -- version
    types.hash256_zero(),    -- prev_hash (doesn't matter for this test)
    merkle_root,             -- merkle_root: must be correct for the check to pass
    0,                       -- timestamp
    0x207fffff,              -- bits (regtest min target, but check_pow=false so irrelevant)
    0                        -- nonce
  )
  return types.block(header, txs)
end

-- Gate 8A: Weight formula equivalence.
--   For a 1-coinbase block (nTx=1), the corrected check_block formula
--   (per_tx + (80+1)*4) must equal the full-block formula stripped*3+full.
do
  local cb = make_coinbase()
  local block = make_block({cb})

  local stripped = serialize.serialize_block_without_witness(block)
  local full     = serialize.serialize_block(block)
  local weight_ref = #stripped * 3 + #full   -- rest.lua:462 / Core formula

  local base_data  = serialize.serialize_transaction(cb, false)
  local total_data = serialize.serialize_transaction(cb, true)
  local per_tx     = #base_data * 3 + #total_data
  local overhead   = (80 + 1) * consensus.WITNESS_SCALE_FACTOR  -- nTx=1 → varint=1
  local weight_fixed = per_tx + overhead

  check_eq("8A: per-tx + overhead equals stripped*3+full (1-tx block)",
    weight_fixed, weight_ref)

  -- The overhead itself: 81 * 4 = 324 WU.
  check_eq("8A: overhead for 1-tx block = 324 WU",
    overhead, 324)
end

-- Gate 8B: Reject a block whose per-tx weight sum equals MAX_BLOCK_WEIGHT exactly.
--   Pre-fix: per-tx sum = 4 000 000 ≤ 4 000 000 → accept (wrong).
--   Post-fix: total = 4 000 000 + 324 = 4 000 324 > 4 000 000 → reject.
--
-- Block layout (2 txs, varint for nTx = 1 byte):
--   Coinbase    : 63 bytes → 252 WU
--   Non-coinbase: target_ncb_bytes bytes → target_ncb_weight WU
--   Sum         : 4 000 000 WU exactly (pre-fix would accept)
do
  local MAX_W   = consensus.MAX_BLOCK_WEIGHT  -- 4 000 000
  local WSF     = consensus.WITNESS_SCALE_FACTOR  -- 4
  -- nTx=2, varint=1 byte, overhead = (80+1)*4 = 324 WU.
  local overhead = (80 + 1) * WSF

  -- Coinbase contributes 63*4=252 WU.
  local cb     = make_coinbase()
  local cb_sz  = #serialize.serialize_transaction(cb, false)
  local cb_wt  = cb_sz * WSF  -- 252

  -- Non-coinbase must make total per-tx = MAX_W.
  -- ncb_wt = MAX_W - cb_wt = 3 999 748 WU → ncb_sz = 999 937 bytes.
  -- ncb_sz = 64 + spk_size → spk_size = 999 937 - 64 = 999 873.
  local ncb_wt_target = MAX_W - cb_wt           -- 3 999 748
  local ncb_sz_target = ncb_wt_target / WSF      -- 999 937
  local spk_size      = ncb_sz_target - 64       -- 999 873

  local ncb  = make_padded_noncoinbase(spk_size)
  local ncb_actual_sz = #serialize.serialize_transaction(ncb, false)

  -- Verify exact sizing before trusting the test.
  check_eq("8B: non-coinbase tx serializes to expected size",
    ncb_actual_sz, ncb_sz_target)

  local total_per_tx = cb_wt + ncb_actual_sz * WSF
  check_eq("8B: per-tx weight sum equals MAX_BLOCK_WEIGHT",
    total_per_tx, MAX_W)

  -- This block should be REJECTED post-fix (total = MAX_W + overhead > MAX_W).
  local block_over = make_block({cb, ncb})
  check_fails("8B: block with per-tx_sum=MAX_BLOCK_WEIGHT rejected post-fix",
    function()
      validation.check_block(block_over, consensus.networks.regtest, nil, false)
    end,
    "weight")  -- error message contains "weight"
end

-- Gate 8C: Accept a block whose TOTAL weight (per-tx + overhead) equals MAX_BLOCK_WEIGHT.
--   Per-tx sum = MAX_W - overhead = 4 000 000 - 324 = 3 999 676 WU.
--   Total = 3 999 676 + 324 = 4 000 000 = MAX_BLOCK_WEIGHT → accept.
do
  local MAX_W   = consensus.MAX_BLOCK_WEIGHT
  local WSF     = consensus.WITNESS_SCALE_FACTOR
  local overhead = (80 + 1) * WSF  -- 324

  local cb    = make_coinbase()
  local cb_sz = #serialize.serialize_transaction(cb, false)
  local cb_wt = cb_sz * WSF  -- 252

  -- ncb target weight = (MAX_W - overhead) - cb_wt = 3 999 424 WU
  -- → ncb_sz = 3 999 424 / 4 = 999 856 bytes → spk_size = 999 856 - 64 = 999 792
  local per_tx_target = MAX_W - overhead          -- 3 999 676
  local ncb_wt_target = per_tx_target - cb_wt    -- 3 999 424
  local ncb_sz_target = ncb_wt_target / WSF       -- 999 856
  local spk_size      = ncb_sz_target - 64        -- 999 792

  local ncb  = make_padded_noncoinbase(spk_size)
  local ncb_actual_sz = #serialize.serialize_transaction(ncb, false)
  check_eq("8C: non-coinbase tx serializes to expected size",
    ncb_actual_sz, ncb_sz_target)

  local total_per_tx = cb_wt + ncb_actual_sz * WSF
  check_eq("8C: per-tx weight sum = MAX_W - overhead",
    total_per_tx, per_tx_target)

  -- This block should be ACCEPTED: total = per_tx + overhead = MAX_W.
  local block_exact = make_block({cb, ncb})
  check_passes("8C: block with total_weight=MAX_BLOCK_WEIGHT accepted",
    function()
      validation.check_block(block_exact, consensus.networks.regtest, nil, false)
    end)
end

--------------------------------------------------------------------------------
-- Finding 10: OP_CHECKSIGADD (0xba) must be gated to tapscript only
--   Core interpreter.cpp:1087: return BAD_OPCODE for BASE or WITNESS_V0.
--   The gate must fire BEFORE any stack pop.
--------------------------------------------------------------------------------
print("\n=== Finding 10: OP_CHECKSIGADD tapscript gate ===")

local OP_CHECKSIGADD = string.char(script.OP.OP_CHECKSIGADD)  -- 0xba

-- Gate 10A: OP_CHECKSIGADD in legacy (BASE) script → BAD_OPCODE.
do
  local ok, err = script.execute_script(
    OP_CHECKSIGADD,
    {"sig", "\x00", string.rep("\xcc", 32)},   -- sig, num=0, 32-byte pubkey on stack
    {}  -- no flags → BASE sigversion (not is_tapscript)
  )
  check(
    "10A: OP_CHECKSIGADD in legacy (BASE) script → BAD_OPCODE",
    not ok and tostring(err):find("BAD_OPCODE", 1, true),
    "got: " .. tostring(err)
  )
end

-- Gate 10B: OP_CHECKSIGADD in witness-v0 script → BAD_OPCODE.
do
  local ok, err = script.execute_script(
    OP_CHECKSIGADD,
    {"sig", "\x00", string.rep("\xcc", 32)},
    { is_witness_v0 = true }  -- witness-v0, but not tapscript
  )
  check(
    "10B: OP_CHECKSIGADD in witness-v0 script → BAD_OPCODE",
    not ok and tostring(err):find("BAD_OPCODE", 1, true),
    "got: " .. tostring(err)
  )
end

-- Gate 10C: OP_CHECKSIGADD gate fires BEFORE stack pops (stack too small → BAD_OPCODE
--           not INVALID_STACK_OPERATION in legacy).
do
  local ok, err = script.execute_script(
    OP_CHECKSIGADD,
    {},   -- empty stack: would normally be INVALID_STACK_OPERATION if we got past gate
    {}    -- BASE: no is_tapscript
  )
  check(
    "10C: BAD_OPCODE fires before stack check in legacy (empty stack)",
    not ok and tostring(err):find("BAD_OPCODE", 1, true),
    "got: " .. tostring(err)
  )
end

-- Gate 10D: OP_CHECKSIGADD in tapscript with empty sig and 32-byte pubkey → success.
--           Empty sig → success=false → push_num(0+0=0).  No BAD_OPCODE.
do
  local n_push = "\x00"  -- CScriptNum encoding of 0 (single zero byte in minimal)
  -- Script: OP_CHECKSIGADD only.  Stack pre-loaded: sig(empty), num(0), pubkey(32 bytes).
  -- Core pops: pubkey=top, num=second, sig=third.
  local result_stack = {}
  local ok, err = script.execute_script(
    OP_CHECKSIGADD,
    {
      "",                          -- sig (empty → success=false)
      "\x00",                      -- num=0 (CScriptNum minimal encoding)
      string.rep("\xcc", 32),      -- pubkey (32-byte xonly, unknown key → forward-compat)
    },
    { is_tapscript = true }
  )
  check(
    "10D: OP_CHECKSIGADD in tapscript (empty sig, unknown 32-byte key) → no BAD_OPCODE",
    ok ~= false or (err ~= "BAD_OPCODE"),
    "got: " .. tostring(err)
  )
end

--------------------------------------------------------------------------------
-- Finding 15: Legacy tx vin-count CompactSize — non-canonical encoding check
--
-- The raw bytes for a minimal legacy transaction have:
--   version (4 bytes LE) | vin_count varint | inputs | vout_count varint |
--   outputs | locktime (4 bytes LE)
--
-- A non-canonical varint encodes a value using more bytes than necessary, e.g.
-- encoding value 1 as 0xFD 0x01 0x00 (3 bytes) instead of 0x01 (1 byte).
-- After the fix, deserialize_transaction must reject such encodings with
-- "non-canonical ReadCompactSize()".
--------------------------------------------------------------------------------
print("\n=== Finding 15: Legacy tx vin-count non-canonical varint ===")

-- Build raw bytes for a minimal legacy transaction manually.
-- version=1 | vin_count_varint | one input | vout_count=1 | one output | locktime=0
local function encode_u32le(n)
  return string.char(
    n % 256,
    math.floor(n / 256) % 256,
    math.floor(n / 65536) % 256,
    math.floor(n / 16777216) % 256
  )
end

local function encode_u64le(n)
  -- For small values (≤ 2^32) split into two u32 halves.
  local lo = n % 4294967296
  local hi = math.floor(n / 4294967296)
  return encode_u32le(lo) .. encode_u32le(hi)
end

-- Minimal single input (prevout + empty scriptSig + sequence):
-- prevout_hash(32) + prevout_index(4) + script_sig_len(1=0x00) + sequence(4)
local function minimal_input()
  return string.rep("\xaa", 32)   -- prevout_hash (non-null)
      .. encode_u32le(0)           -- prevout_index
      .. "\x00"                    -- scriptSig length = 0
      .. encode_u32le(0xFFFFFFFF) -- sequence
end

-- Minimal single output: value(8) + script_pubkey_len(1) + OP_1(1)
local function minimal_output()
  return encode_u64le(1000000)  -- 1000000 sat
      .. "\x01"                  -- script_pubkey_len = 1
      .. "\x51"                  -- OP_1
end

local tx_version   = encode_u32le(1)
local tx_input     = minimal_input()
local tx_output    = minimal_output()
local tx_locktime  = encode_u32le(0)
local tx_vout_section = "\x01" .. tx_output  -- vout_count=1 + output

-- Gate 15A: Non-canonical vin_count varint 0xFD 0x01 0x00 (value=1, non-canonical).
--   Core serialize.h:343-344: if nSizeRet < 253 after reading 0xFD → non-canonical.
do
  local raw = tx_version
           .. "\xfd\x01\x00"   -- 0xFD marker: read u16le = 1, but 1 < 253 → non-canonical
           .. tx_input          -- one input (matches the declared count of 1)
           .. tx_vout_section
           .. tx_locktime
  check_fails(
    "15A: vin_count 0xFD 0x01 0x00 (value=1, non-canonical) → error",
    function() serialize.deserialize_transaction(raw) end,
    "non-canonical"
  )
end

-- Gate 15B: Canonical vin_count 0x01 (value=1, single byte) → success.
do
  local raw = tx_version
           .. "\x01"            -- 1-byte varint for value 1 (canonical)
           .. tx_input
           .. tx_vout_section
           .. tx_locktime
  check_passes(
    "15B: vin_count 0x01 (canonical) → no error",
    function() return serialize.deserialize_transaction(raw) end
  )
end

-- Gate 15C: Non-canonical 0xFE with value < 0x10000 → error.
--   0xFE marker: read u32le. Value must be >= 0x10000, else non-canonical.
--   Use 0xFE 0xFF 0xFF 0x00 0x00 = 65535 (0xFFFF) which is < 0x10000.
do
  local raw = tx_version
           .. "\xfe\xff\xff\x00\x00"   -- 0xFE + u32le(0x0000FFFF=65535) < 0x10000 → non-canonical
           .. tx_input  -- still just one input in the blob so the loop would stop, but
                        -- the non-canonical check fires before the loop starts
           .. tx_vout_section
           .. tx_locktime
  check_fails(
    "15C: vin_count 0xFE 0x0000FFFF (value=65535, non-canonical) → error",
    function() serialize.deserialize_transaction(raw) end,
    "non-canonical"
  )
end

-- Gate 15D: Canonical 0xFE encoding → succeeds (value >= 0x10000).
--   Use 0xFE with value = 0x00010000 (65536). Reading 65536 inputs would hit
--   MAX_SIZE=33554432 limit (65536 < MAX_SIZE), so check_transaction would
--   later fail on the tx size, but deserialization itself succeeds past the
--   non-canonical check (it would fail trying to read 65536 inputs from a
--   short buffer, but the test is that we do NOT get a non-canonical error).
--   We test a canonical 0xFD encoding with value=0x0100 (256 >= 253) instead,
--   which is unambiguous and won't try to read 65536 inputs.
do
  -- Canonical 0xFD encoding for value = 256 (0x0100): 0xFD 0x00 0x01.
  -- We do NOT actually have 256 inputs in the buffer, so the deserializer
  -- will hit an EOF reading the 2nd input.  The key assertion is that we
  -- get EOF (or similar), NOT "non-canonical ReadCompactSize()".
  local raw = tx_version
           .. "\xfd\x00\x01"   -- 0xFD + u16le(0x0100 = 256): 256 >= 253 → canonical
           .. tx_input          -- only 1 input in buffer; reader will EOF on input 2
           .. tx_vout_section
           .. tx_locktime
  local ok, err = pcall(function() return serialize.deserialize_transaction(raw) end)
  -- We expect EITHER success OR a non-"non-canonical" error (EOF / read_bytes).
  check(
    "15D: vin_count 0xFD 0x0100 (value=256, canonical) → NOT non-canonical error",
    not ok == false or (tostring(err):find("non-canonical", 1, true) == nil),
    "got: " .. tostring(err)
  )
end

-- Gate 15E: MAX_SIZE exceeded (0xFF with value >= 0x100000000) → "size too large".
--   0xFF reads u64le.  The non-canonical guard fires when value < 0x100000000.
--   To reach the MAX_SIZE check we need value >= 0x100000000.
--   Any such value is far above MAX_SIZE (0x02000000 = 33554432), so we always
--   get "size too large" when we reach that check.
--   Use 0x100000000 = 4294967296: canonical (passes non-canonical check) AND
--   4294967296 > MAX_SIZE (33554432) → "size too large".
do
  local canonical_large = 0x100000000  -- 4294967296; passes non-canonical, exceeds MAX_SIZE
  local raw = tx_version
           .. "\xff"
           .. encode_u64le(canonical_large)  -- 0x100000000 → passes canonical, fails MAX_SIZE
           .. tx_input
           .. tx_vout_section
           .. tx_locktime
  check_fails(
    "15E: vin_count 0xFF with value=0x100000000 → size too large",
    function() serialize.deserialize_transaction(raw) end,
    "size too large"
  )
end

--------------------------------------------------------------------------------
print(string.format("\n%d passed, %d failed", pass, fail))
if fail > 0 then os.exit(1) end
