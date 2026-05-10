#!/usr/bin/env luajit
-- Regression test for W58-7: IsStandardTx per-output policy in mempool accept.
-- Bug: accept_transaction had no per-output script type check.  A tx with a
-- nonstandard output (e.g., truncated OP_RETURN 0x6a09deadbeef) was silently
-- accepted instead of rejected with "scriptpubkey".
-- Also tests: version gate, dust gate, and valid nulldata admission.
-- Reference: Bitcoin Core policy/policy.cpp IsStandardTx().
-- Run: luajit test_mempool_isstandard.lua

package.path = './src/?.lua;./lunarblock/?.lua;' .. package.path
package.cpath = './lib/?.so;' .. package.cpath

local types   = require("lunarblock.types")
local mempool = require("lunarblock.mempool")
local script  = require("lunarblock.script")

local pass = 0
local fail = 0

local function check(name, cond, extra)
  if cond then
    print("PASS: " .. name)
    pass = pass + 1
  else
    print("FAIL: " .. name .. (extra and (" | " .. tostring(extra)) or ""))
    fail = fail + 1
  end
end

-- ── helpers ──────────────────────────────────────────────────────────────────

local function hex_to_bytes(h)
  return (h:gsub("%x%x", function(b) return string.char(tonumber(b, 16)) end))
end

local function make_mock_chain(utxos_tbl)
  local coin_view = {
    utxos = utxos_tbl or {},
    get = function(self, txid, vout)
      return self.utxos[types.hash256_hex(txid) .. ":" .. vout]
    end,
  }
  return { coin_view = coin_view, tip_height = 700000 }
end

-- Create a P2PKH scriptPubKey for a 20-byte hash (all zeroes here).
local function p2pkh_script()
  return "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"  -- 25 bytes
end

-- Add a confirmed UTXO to the mock chain state.
local function add_utxo(cs, txid_hex, vout, value, spk)
  cs.coin_view.utxos[txid_hex .. ":" .. vout] = {
    value    = value,
    script_pubkey = spk or p2pkh_script(),
    height   = 600000,
    is_coinbase = false,
  }
end

-- Build a minimal 1-in, 1-out transaction.
local function make_tx(inp_txid, inp_vout, out_value, out_spk, version)
  local inp = types.txin(types.outpoint(inp_txid, inp_vout), "", 0xFFFFFFFE)
  local out = types.txout(out_value, out_spk)
  return types.transaction(version or 1, {inp}, {out}, 0)
end

-- ── Part 1: classify_script unit tests ───────────────────────────────────────

print("=== Part 1: classify_script (W56 fix) ===")

-- 0x6a09deadbeef  → OP_RETURN 0x09 <only 3 bytes of data follow; 9 promised>
-- Truncated push: nonstandard, NOT nulldata.
local truncated_opreturn = hex_to_bytes("6a09deadbeef")
local t1 = script.classify_script(truncated_opreturn)
check("6a09deadbeef → nonstandard (truncated push)", t1 == "nonstandard", "got: " .. t1)

-- 0x6a04deadbeef  → OP_RETURN 0x04 <deadbeef> — well-formed nulldata
local valid_opreturn = hex_to_bytes("6a04deadbeef")
local t2 = script.classify_script(valid_opreturn)
check("6a04deadbeef → nulldata (valid push)", t2 == "nulldata", "got: " .. t2)

-- Bare 0x6a  → OP_RETURN with no data — still nulldata (Core: empty push-only is fine)
local bare_opreturn = "\x6a"
local t3 = script.classify_script(bare_opreturn)
check("0x6a alone → nulldata", t3 == "nulldata", "got: " .. t3)

-- Standard P2PKH
local t4 = script.classify_script(p2pkh_script())
check("P2PKH → p2pkh", t4 == "p2pkh", "got: " .. t4)

-- ── Part 2: mempool accept rejects nonstandard output ────────────────────────

print("\n=== Part 2: mempool rejects nonstandard output (PATH B bug) ===")

do
  local base_txid = types.hash256(string.rep("\x10", 32))
  local base_txid_hex = types.hash256_hex(base_txid)
  local cs = make_mock_chain()
  add_utxo(cs, base_txid_hex, 0, 5000000)

  local mp = mempool.new(cs)

  -- Tx with a truncated OP_RETURN output — MUST be rejected with "scriptpubkey"
  local bad_tx = make_tx(base_txid, 0, 1000000, hex_to_bytes("6a09deadbeef"))
  local ok, reason = mp:accept_transaction(bad_tx)
  check("truncated OP_RETURN output → rejected", not ok, "reason: " .. tostring(reason))
  check("rejection reason is 'scriptpubkey'", reason == "scriptpubkey", "got: " .. tostring(reason))
end

-- ── Part 3: mempool admits valid nulldata output ─────────────────────────────

print("\n=== Part 3: mempool admits valid nulldata output ===")

do
  local base_txid = types.hash256(string.rep("\x11", 32))
  local base_txid_hex = types.hash256_hex(base_txid)
  local cs = make_mock_chain()
  add_utxo(cs, base_txid_hex, 0, 5000000)

  local mp = mempool.new(cs)

  -- Tx with a valid OP_RETURN output and a change output
  local inp = types.txin(types.outpoint(base_txid, 0), "", 0xFFFFFFFE)
  -- output 0: change (P2PKH, 4990000 sat — well above dust)
  local out_change = types.txout(4990000, p2pkh_script())
  -- output 1: OP_RETURN with valid push
  local out_opreturn = types.txout(0, hex_to_bytes("6a04deadbeef"))
  local tx = types.transaction(1, {inp}, {out_change, out_opreturn}, 0)

  local ok, txid_hex_or_err = mp:accept_transaction(tx)
  check("valid nulldata + change output → accepted", ok,
        "reason: " .. tostring(txid_hex_or_err))
end

-- ── Part 4: version gate ─────────────────────────────────────────────────────

print("\n=== Part 4: version gate (versions 1-3 standard) ===")

do
  local base_txid = types.hash256(string.rep("\x20", 32))
  local base_txid_hex = types.hash256_hex(base_txid)

  for _, ver in ipairs({0, 4, 100}) do
    local cs = make_mock_chain()
    add_utxo(cs, base_txid_hex, 0, 5000000)
    local mp = mempool.new(cs)
    local tx = make_tx(base_txid, 0, 4990000, p2pkh_script(), ver)
    local ok, reason = mp:accept_transaction(tx)
    check(string.format("version %d → rejected", ver), not ok,
          "reason: " .. tostring(reason))
    check(string.format("version %d rejection reason is 'version'", ver),
          reason and reason:find("^version") ~= nil,
          "got: " .. tostring(reason))
  end

  -- Versions 1, 2, 3 must be accepted
  for _, ver in ipairs({1, 2, 3}) do
    local cs = make_mock_chain()
    add_utxo(cs, base_txid_hex, 0, 5000000)
    local mp = mempool.new(cs)
    local tx = make_tx(base_txid, 0, 4990000, p2pkh_script(), ver)
    local ok, reason = mp:accept_transaction(tx)
    check(string.format("version %d → accepted", ver), ok,
          "reason: " .. tostring(reason))
  end
end

-- ── Part 5: dust gate ────────────────────────────────────────────────────────

print("\n=== Part 5: dust gate (more than 1 dust output → rejected) ===")

do
  -- P2PKH dust threshold at 3000 sat/kvB:
  -- nSize = 8+1+25 (output serialization) + 32+4+1+107+4 (input estimation) = 182
  -- threshold = floor(3000 * 182 / 1000) = 546 sat
  -- So outputs with value < 546 are dust.

  local base_txid = types.hash256(string.rep("\x30", 32))
  local base_txid_hex = types.hash256_hex(base_txid)

  -- One dust output (< 546 sat) is allowed (ephemeral dust rule)
  do
    local cs = make_mock_chain()
    add_utxo(cs, base_txid_hex, 0, 5000000)
    local mp = mempool.new(cs)
    local inp = types.txin(types.outpoint(base_txid, 0), "", 0xFFFFFFFE)
    local out_normal = types.txout(4990000, p2pkh_script())
    local out_dust   = types.txout(100, p2pkh_script())  -- 100 < 546, dust
    local tx = types.transaction(1, {inp}, {out_normal, out_dust}, 0)
    local ok, reason = mp:accept_transaction(tx)
    check("one dust output (ephemeral dust) → accepted", ok,
          "reason: " .. tostring(reason))
  end

  -- Two dust outputs → rejected with "dust"
  do
    local cs = make_mock_chain()
    add_utxo(cs, base_txid_hex, 0, 5000000)
    local mp = mempool.new(cs)
    local inp = types.txin(types.outpoint(base_txid, 0), "", 0xFFFFFFFE)
    local out_dust1 = types.txout(100, p2pkh_script())
    local out_dust2 = types.txout(100, p2pkh_script())
    local tx = types.transaction(1, {inp}, {out_dust1, out_dust2}, 0)
    local ok, reason = mp:accept_transaction(tx)
    check("two dust outputs → rejected", not ok, "reason: " .. tostring(reason))
    check("rejection reason is 'dust'", reason == "dust", "got: " .. tostring(reason))
  end
end

-- ── Part 6: CVE-2017-12842 — non-witness size >= 65 bytes ───────────────────

print("\n=== Part 6: CVE-2017-12842 tx-size-small gate ===")

-- The minimum standard non-witness tx size is 65 bytes.
-- A 1-in / 1-out tx with empty scriptSig and a 25-byte P2PKH output has:
--   4 (version) + 1 (vin count) + 41 (input: 32+4+1+0+4) +
--   1 (vout count) + 8+1+25 (output) + 4 (locktime) = 85 bytes → accepted.
-- We need to get BELOW 65.  A minimal tx: 1-in / 0-out is too degenerate
-- (fails check_transaction "no outputs").  Instead, build a tx with a
-- P2PKH output carrying a tiny (1-byte) scriptPubKey — that won't pass
-- classify_script, so craft one that will, but shrink inputs.
-- Easiest: use 0-byte scriptSig and an outpoint that still makes the
-- non-witness size < 65.  Actually the minimal valid structure we can
-- get to: 4+1+41+1+9+4 = 60 bytes → below 65, so it should be rejected.
-- Build that tx manually: 1 input (prev 32-byte hash + 4-byte index +
-- 1-byte empty scriptSig len + 4-byte sequence) = 41 bytes of input.
-- 1 output: 8-byte value + 1-byte empty scriptPubKey len = 9 bytes.
-- Total: 4+1+41+1+9+4 = 60 bytes.  Use a degenerate 1-byte nulldata output:
-- 0x6a (just OP_RETURN, valid nulldata, 1 byte) → 8+1+1 = 10 byte vout.
-- Non-witness size: 4+1+41+1+10+4 = 61 bytes < 65 → tx-size-small.
do
  local base_txid = types.hash256(string.rep("\x40", 32))
  local base_txid_hex = types.hash256_hex(base_txid)
  local cs = make_mock_chain()
  -- Provide a UTXO for our input so the tx doesn't fail on "missing inputs".
  -- The output we use: 1-byte nulldata OP_RETURN (0x6a), value 1000000.
  add_utxo(cs, base_txid_hex, 0, 1000000, "\x6a")

  local mp = mempool.new(cs)

  -- Build a tx whose non-witness serialization is < 65 bytes.
  -- Input: empty scriptSig, output: 1-byte OP_RETURN, fee = 0 (value in == value out).
  -- Non-witness: 4+1+(32+4+1+0+4)+1+(8+1+1)+4 = 4+1+41+1+10+4 = 61 bytes.
  local inp = types.txin(types.outpoint(base_txid, 0), "", 0xFFFFFFFE)
  local out = types.txout(1000000, "\x6a")
  local tx_small = types.transaction(1, {inp}, {out}, 0)

  local ok, reason = mp:accept_transaction(tx_small)
  check("non-witness size 61 → rejected with tx-size-small", not ok,
        "reason: " .. tostring(reason))
  check("rejection reason starts with 'tx-size-small'",
        reason and reason:find("^tx%-size%-small") ~= nil,
        "got: " .. tostring(reason))
end

-- A normal P2PKH tx is well above 65 bytes non-witness.
do
  local base_txid = types.hash256(string.rep("\x41", 32))
  local base_txid_hex = types.hash256_hex(base_txid)
  local cs = make_mock_chain()
  add_utxo(cs, base_txid_hex, 0, 5000000)
  local mp = mempool.new(cs)
  local tx = make_tx(base_txid, 0, 4990000, p2pkh_script())
  local ok, reason = mp:accept_transaction(tx)
  check("normal P2PKH tx (>=65 bytes non-witness) → accepted", ok,
        "reason: " .. tostring(reason))
end

-- ── Part 7: WITNESS_UNKNOWN outputs are standard ─────────────────────────────

print("\n=== Part 7: WITNESS_UNKNOWN (v2-v16 witness programs) are standard ===")

-- Bitcoin Core Solver() returns WITNESS_UNKNOWN for witness programs with
-- version != 0 that are not v1+32 Taproot.  IsStandard() accepts these
-- (only NONSTANDARD returns false).  Lunarblock must do the same.
do
  -- classify_script unit test: OP_2 <32 bytes> = v2+32 witness program.
  -- 0x52 0x20 <32 bytes> — not P2TR (that's 0x51 0x20), so WITNESS_UNKNOWN.
  local v2_32 = "\x52\x20" .. string.rep("\xab", 32)
  local st = script.classify_script(v2_32)
  check("classify_script: OP_2 <32-byte program> → witness_unknown",
        st == "witness_unknown", "got: " .. tostring(st))

  -- OP_3 <20-byte program> — v3+20
  local v3_20 = "\x53\x14" .. string.rep("\xcd", 20)
  local st2 = script.classify_script(v3_20)
  check("classify_script: OP_3 <20-byte program> → witness_unknown",
        st2 == "witness_unknown", "got: " .. tostring(st2))

  -- OP_16 <2-byte program> — v16+2 (minimum valid witness program size)
  local v16_2 = "\x60\x02\xef\xbe"
  local st3 = script.classify_script(v16_2)
  check("classify_script: OP_16 <2-byte program> → witness_unknown",
        st3 == "witness_unknown", "got: " .. tostring(st3))
end

-- Mempool must admit a tx with a WITNESS_UNKNOWN (v2+32) output.
do
  local base_txid = types.hash256(string.rep("\x50", 32))
  local base_txid_hex = types.hash256_hex(base_txid)
  local cs = make_mock_chain()
  add_utxo(cs, base_txid_hex, 0, 5000000)
  local mp = mempool.new(cs)

  -- v2+32 output (WITNESS_UNKNOWN, standard per Core)
  local v2_32_spk = "\x52\x20" .. string.rep("\xab", 32)
  local inp = types.txin(types.outpoint(base_txid, 0), "", 0xFFFFFFFE)
  local out = types.txout(4990000, v2_32_spk)
  local tx = types.transaction(1, {inp}, {out}, 0)

  local ok, reason = mp:accept_transaction(tx)
  check("v2+32 witness_unknown output → accepted by mempool", ok,
        "reason: " .. tostring(reason))
end

-- v0 with wrong program size (not 20 or 32): NONSTANDARD in Core → rejected.
do
  local base_txid = types.hash256(string.rep("\x51", 32))
  local base_txid_hex = types.hash256_hex(base_txid)
  local cs = make_mock_chain()
  add_utxo(cs, base_txid_hex, 0, 5000000)
  local mp = mempool.new(cs)

  -- OP_0 <10-byte program> — v0+10 is NONSTANDARD in Core (not 20 or 32)
  local v0_10_spk = "\x00\x0a" .. string.rep("\xbb", 10)
  local inp = types.txin(types.outpoint(base_txid, 0), "", 0xFFFFFFFE)
  local out = types.txout(4990000, v0_10_spk)
  local tx = types.transaction(1, {inp}, {out}, 0)

  local ok, reason = mp:accept_transaction(tx)
  check("v0+10-byte program (NONSTANDARD) → rejected with scriptpubkey", not ok,
        "reason: " .. tostring(reason))
  check("rejection reason is 'scriptpubkey'",
        reason == "scriptpubkey", "got: " .. tostring(reason))
end

-- ── summary ──────────────────────────────────────────────────────────────────

print(string.format("\n%d passed, %d failed", pass, fail))
if fail > 0 then
  os.exit(1)
end
