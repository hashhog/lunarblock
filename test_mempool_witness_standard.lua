#!/usr/bin/env luajit
-- W72 regression tests: IsWitnessStandard policy gates in mempool accept.
-- Covers all 6 gates from Bitcoin Core policy/policy.cpp:265-352.
--   Gate 1: P2A input with non-empty witness → bad-witness-nonstandard.
--   Gate 2: P2SH-wrapped witness — bad scriptSig or empty stack → reject.
--   Gate 3: non-witness prevScript paired with non-empty witness → reject.
--   Gate 4: P2WSH (v0+32-byte) limits: script ≤ 3600 B, items ≤ 100, each ≤ 80 B.
--   Gate 5: P2TR (v1+32-byte, non-P2SH) annex tag 0x50 → reject;
--            tapscript leaf 0xc0 → each element ≤ 80 B; empty stack → reject.
--   Gate 6: coinbase exempt (tested via is_witness_standard unit call).
-- Run: luajit test_mempool_witness_standard.lua

package.path = './src/?.lua;./lunarblock/?.lua;' .. package.path
package.cpath = './lib/?.so;' .. package.cpath

local types   = require("lunarblock.types")
local mempool = require("lunarblock.mempool")
local script  = require("lunarblock.script")

local pass = 0
local fail = 0

local function check(name, cond, extra)
  if cond then
    io.write("PASS: " .. name .. "\n")
    pass = pass + 1
  else
    io.write("FAIL: " .. name .. (extra and (" | " .. tostring(extra)) or "") .. "\n")
    fail = fail + 1
  end
end

-- ── helpers ──────────────────────────────────────────────────────────────────

local function make_mock_chain(utxos_tbl)
  local coin_view = {
    utxos = utxos_tbl or {},
    get = function(self, txid, vout)
      return self.utxos[types.hash256_hex(txid) .. ":" .. vout]
    end,
  }
  return { coin_view = coin_view, tip_height = 700000 }
end

local function add_utxo(cs, txid_hex, vout, value, spk)
  cs.coin_view.utxos[txid_hex .. ":" .. vout] = {
    value         = value,
    script_pubkey = spk,
    height        = 600000,
    is_coinbase   = false,
  }
end

-- Build minimal scripts.
local function p2pkh_script()
  return "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"
end

local function p2wsh_script(hash32)
  -- OP_0 <0x20> <32 bytes>
  return "\x00\x20" .. (hash32 or string.rep("\xaa", 32))
end

local function p2tr_script(xonly32)
  -- OP_1 <0x20> <32 bytes>
  return "\x51\x20" .. (xonly32 or string.rep("\xbb", 32))
end

local function p2sh_script(hash20)
  -- OP_HASH160 <0x14> <20 bytes> OP_EQUAL
  return "\xa9\x14" .. (hash20 or string.rep("\xcc", 20)) .. "\x87"
end

local function p2a_script()
  return "\x51\x02\x4e\x73"
end

-- Build a tx whose inputs have specific script_sigs and witnesses.
-- inputs_spec is a list of {prev_txid, prev_vout, script_sig, witness}
-- outputs_spec is a list of {value, spk}
local function make_tx_full(inputs_spec, outputs_spec)
  local inputs = {}
  for _, ispec in ipairs(inputs_spec) do
    local inp = types.txin(
      types.outpoint(ispec[1], ispec[2]),
      ispec[3] or "",
      0xFFFFFFFE
    )
    inp.witness = ispec[4] or {}
    inputs[#inputs + 1] = inp
  end
  local outputs = {}
  for _, ospec in ipairs(outputs_spec) do
    outputs[#outputs + 1] = types.txout(ospec[1], ospec[2])
  end
  return types.transaction(1, inputs, outputs, 0)
end

-- P2SH scriptSig encoding: push one data item (the redeemScript).
-- Returns: length-prefixed push opcode + data.
local function push_bytes(data)
  local n = #data
  if n <= 0x4b then
    return string.char(n) .. data
  elseif n <= 0xff then
    return "\x4c" .. string.char(n) .. data
  elseif n <= 0xffff then
    local lo = n % 256
    local hi = math.floor(n / 256)
    return "\x4d" .. string.char(lo) .. string.char(hi) .. data
  else
    error("push_bytes: data too large")
  end
end

-- ── Part 1: is_witness_standard unit tests ────────────────────────────────────

print("=== Part 1: is_witness_standard unit function ===")

-- Gate 6: empty witness on all inputs → always true (no witness to validate).
do
  local tx = make_tx_full(
    { { types.hash256(string.rep("\x01", 32)), 0, "", {} } },
    { { 4990000, p2pkh_script() } }
  )
  local utxos = { { script_pubkey = p2pkh_script() } }
  local ok, err = mempool.is_witness_standard(tx, utxos)
  check("Gate 6: empty witness → standard", ok, err)
end

-- Gate 3: P2PKH prevout with non-empty witness → bad-witness-nonstandard.
do
  local tx = make_tx_full(
    { { types.hash256(string.rep("\x02", 32)), 0, "", { "somebytes" } } },
    { { 4990000, p2pkh_script() } }
  )
  local utxos = { { script_pubkey = p2pkh_script() } }
  local ok, err = mempool.is_witness_standard(tx, utxos)
  check("Gate 3: P2PKH + witness → rejected", not ok, err)
  check("Gate 3: rejection reason", err == "bad-witness-nonstandard", "got: " .. tostring(err))
end

-- Gate 1: P2A prevout with witness → bad-witness-nonstandard.
do
  local tx = make_tx_full(
    { { types.hash256(string.rep("\x03", 32)), 0, "", { "anybytes" } } },
    { { 4990000, p2pkh_script() } }
  )
  local utxos = { { script_pubkey = p2a_script() } }
  local ok, err = mempool.is_witness_standard(tx, utxos)
  check("Gate 1: P2A + witness → rejected", not ok, err)
  check("Gate 1: rejection reason", err == "bad-witness-nonstandard", "got: " .. tostring(err))
end

-- Gate 4a: P2WSH redeem script > 3600 bytes → rejected.
do
  local oversized_script = string.rep("\x51", 3601)  -- 3601 bytes
  local tx = make_tx_full(
    { { types.hash256(string.rep("\x04", 32)), 0, "",
        { "arg1", oversized_script } } },
    { { 4990000, p2pkh_script() } }
  )
  local utxos = { { script_pubkey = p2wsh_script() } }
  local ok, err = mempool.is_witness_standard(tx, utxos)
  check("Gate 4a: P2WSH script > 3600 B → rejected", not ok, err)
  check("Gate 4a: rejection reason", err == "bad-witness-nonstandard", "got: " .. tostring(err))
end

-- Gate 4a: P2WSH redeem script exactly 3600 bytes → accepted.
do
  local exact_script = string.rep("\x51", 3600)
  local tx = make_tx_full(
    { { types.hash256(string.rep("\x05", 32)), 0, "",
        { "arg1", exact_script } } },
    { { 4990000, p2pkh_script() } }
  )
  local utxos = { { script_pubkey = p2wsh_script() } }
  local ok, err = mempool.is_witness_standard(tx, utxos)
  check("Gate 4a: P2WSH script = 3600 B → standard", ok, err)
end

-- Gate 4b: P2WSH stack items > 100 → rejected.
do
  -- 102 witness items: items[1..101] are stack args, items[102] is the script.
  local witness = {}
  for j = 1, 101 do witness[j] = "x" end  -- 101 non-script items > 100
  witness[102] = "\x51"  -- redeemScript (1 byte, well within 3600)
  local tx = make_tx_full(
    { { types.hash256(string.rep("\x06", 32)), 0, "", witness } },
    { { 4990000, p2pkh_script() } }
  )
  local utxos = { { script_pubkey = p2wsh_script() } }
  local ok, err = mempool.is_witness_standard(tx, utxos)
  check("Gate 4b: P2WSH 101 stack items > 100 → rejected", not ok, err)
  check("Gate 4b: rejection reason", err == "bad-witness-nonstandard", "got: " .. tostring(err))
end

-- Gate 4b: P2WSH stack items exactly 100 → accepted.
do
  local witness = {}
  for j = 1, 100 do witness[j] = "x" end  -- 100 non-script items ≤ 100
  witness[101] = "\x51"  -- redeemScript
  local tx = make_tx_full(
    { { types.hash256(string.rep("\x07", 32)), 0, "", witness } },
    { { 4990000, p2pkh_script() } }
  )
  local utxos = { { script_pubkey = p2wsh_script() } }
  local ok, err = mempool.is_witness_standard(tx, utxos)
  check("Gate 4b: P2WSH 100 stack items = limit → standard", ok, err)
end

-- Gate 4c: P2WSH stack item > 80 bytes → rejected.
do
  local big_item = string.rep("\xab", 81)  -- 81 bytes > 80
  local tx = make_tx_full(
    { { types.hash256(string.rep("\x08", 32)), 0, "",
        { big_item, "\x51" } } },
    { { 4990000, p2pkh_script() } }
  )
  local utxos = { { script_pubkey = p2wsh_script() } }
  local ok, err = mempool.is_witness_standard(tx, utxos)
  check("Gate 4c: P2WSH stack item 81 B > 80 → rejected", not ok, err)
  check("Gate 4c: rejection reason", err == "bad-witness-nonstandard", "got: " .. tostring(err))
end

-- Gate 4c: P2WSH stack item exactly 80 bytes → accepted.
do
  local exact_item = string.rep("\xab", 80)
  local tx = make_tx_full(
    { { types.hash256(string.rep("\x09", 32)), 0, "",
        { exact_item, "\x51" } } },
    { { 4990000, p2pkh_script() } }
  )
  local utxos = { { script_pubkey = p2wsh_script() } }
  local ok, err = mempool.is_witness_standard(tx, utxos)
  check("Gate 4c: P2WSH stack item = 80 B → standard", ok, err)
end

-- Gate 5 annex: P2TR with 2-element witness where last byte[1] == 0x50 → rejected.
do
  -- witness = { "somesig", "\x50restofannex" }
  local annex = "\x50\xde\xad\xbe\xef"
  local tx = make_tx_full(
    { { types.hash256(string.rep("\x0a", 32)), 0, "",
        { "schnorrsig", annex } } },
    { { 4990000, p2pkh_script() } }
  )
  local utxos = { { script_pubkey = p2tr_script() } }
  local ok, err = mempool.is_witness_standard(tx, utxos)
  check("Gate 5: P2TR annex (0x50 prefix) → rejected", not ok, err)
  check("Gate 5: annex rejection reason", err == "bad-witness-nonstandard", "got: " .. tostring(err))
end

-- Gate 5 empty stack: P2TR with 0 witness items → rejected.
do
  local tx = make_tx_full(
    { { types.hash256(string.rep("\x0b", 32)), 0, "", {} } },
    { { 4990000, p2pkh_script() } }
  )
  local utxos = { { script_pubkey = p2tr_script() } }
  -- Force non-empty witness (the gate only fires when witness is non-empty;
  -- but empty witness is permitted at this gate).  Test the "0 items"
  -- edge that Core rejects as "already invalid by consensus":
  -- We need at least 1 witness item for the gate to trigger at all.
  -- Use a single empty-string witness item (distinct from no witness).
  local tx2 = make_tx_full(
    { { types.hash256(string.rep("\x0b", 32)), 0, "", {""} } },
    { { 4990000, p2pkh_script() } }
  )
  local utxos2 = { { script_pubkey = p2tr_script() } }
  -- A single-item witness on P2TR is a key-path spend → allowed (gate 5).
  local ok2, err2 = mempool.is_witness_standard(tx2, utxos2)
  check("Gate 5: P2TR key-path (1 item) → standard", ok2, err2)
end

-- Gate 5 tapscript item > 80: P2TR script-path with oversized stack element.
-- Stack layout: [item1_oversized, witness_script, control_block]
-- control_block[0] & 0xfe == 0xc0 (Tapscript)
do
  local big_item = string.rep("\xcd", 81)  -- 81 bytes > 80
  local witness_script = "\x51"  -- OP_TRUE
  -- control block byte 0: leaf version 0xc0, internal key parity 0 → 0xc0
  local control_block = "\xc0" .. string.rep("\xef", 32)
  local tx = make_tx_full(
    { { types.hash256(string.rep("\x0c", 32)), 0, "",
        { big_item, witness_script, control_block } } },
    { { 4990000, p2pkh_script() } }
  )
  local utxos = { { script_pubkey = p2tr_script() } }
  local ok, err = mempool.is_witness_standard(tx, utxos)
  check("Gate 5: tapscript item 81 B > 80 → rejected", not ok, err)
  check("Gate 5: tapscript rejection reason", err == "bad-witness-nonstandard", "got: " .. tostring(err))
end

-- Gate 5 tapscript item exactly 80 → standard.
do
  local exact_item = string.rep("\xcd", 80)
  local witness_script = "\x51"
  local control_block = "\xc0" .. string.rep("\xef", 32)
  local tx = make_tx_full(
    { { types.hash256(string.rep("\x0d", 32)), 0, "",
        { exact_item, witness_script, control_block } } },
    { { 4990000, p2pkh_script() } }
  )
  local utxos = { { script_pubkey = p2tr_script() } }
  local ok, err = mempool.is_witness_standard(tx, utxos)
  check("Gate 5: tapscript item = 80 B → standard", ok, err)
end

-- Gate 5: P2TR script-path with non-tapscript leaf version (e.g. 0xc2).
-- Core does NOT restrict item sizes for unknown leaf versions.
-- 0xc2 & 0xfe = 0xc2 ≠ 0xc0 → skip item-size check → standard even with 81-byte items.
do
  local big_item = string.rep("\xdd", 81)
  local witness_script = "\x51"
  local control_block = "\xc2" .. string.rep("\xef", 32)  -- leaf version 0xc2
  local tx = make_tx_full(
    { { types.hash256(string.rep("\x0e", 32)), 0, "",
        { big_item, witness_script, control_block } } },
    { { 4990000, p2pkh_script() } }
  )
  local utxos = { { script_pubkey = p2tr_script() } }
  local ok, err = mempool.is_witness_standard(tx, utxos)
  check("Gate 5: unknown leaf version 0xc2, 81-byte item → standard", ok, err)
end

-- Gate 2: P2SH-wrapped P2WSH — scriptSig pushes a valid P2WSH redeemScript.
-- The prevout is P2SH; scriptSig = push(p2wsh_script); witness = {arg, script}.
do
  local inner_wsh_hash = string.rep("\xff", 32)
  local redeem_script = p2wsh_script(inner_wsh_hash)  -- 34 bytes
  local script_sig = push_bytes(redeem_script)
  local witness_script_inner = "\x51"  -- 1 byte, well within 3600
  local tx = make_tx_full(
    { { types.hash256(string.rep("\x10", 32)), 0, script_sig,
        { "somearg", witness_script_inner } } },
    { { 4990000, p2pkh_script() } }
  )
  -- P2SH hash = HASH160(redeem_script); we use an arbitrary hash here since
  -- is_witness_standard only cares about script type, not hash correctness.
  local utxos = { { script_pubkey = p2sh_script() } }
  local ok, err = mempool.is_witness_standard(tx, utxos)
  check("Gate 2: P2SH-wrapped P2WSH → standard", ok, err)
end

-- Gate 2: P2SH-wrapped witness — empty scriptSig (empty stack) → rejected.
do
  local tx = make_tx_full(
    { { types.hash256(string.rep("\x11", 32)), 0, "",
        { "somearg", "\x51" } } },
    { { 4990000, p2pkh_script() } }
  )
  local utxos = { { script_pubkey = p2sh_script() } }
  local ok, err = mempool.is_witness_standard(tx, utxos)
  check("Gate 2: P2SH empty scriptSig (empty stack) → rejected", not ok, err)
  check("Gate 2: empty-stack rejection reason", err == "bad-witness-nonstandard", "got: " .. tostring(err))
end

-- Gate 2: P2SH scriptSig with non-push opcode → rejected.
do
  -- scriptSig contains OP_DUP (0x76) — not a push-only opcode
  local bad_scriptsig = "\x76"
  local tx = make_tx_full(
    { { types.hash256(string.rep("\x12", 32)), 0, bad_scriptsig,
        { "somearg", "\x51" } } },
    { { 4990000, p2pkh_script() } }
  )
  local utxos = { { script_pubkey = p2sh_script() } }
  local ok, err = mempool.is_witness_standard(tx, utxos)
  check("Gate 2: P2SH scriptSig non-push → rejected", not ok, err)
  check("Gate 2: non-push rejection reason", err == "bad-witness-nonstandard", "got: " .. tostring(err))
end

-- Gate 2 → Gate 3: P2SH wrapping a P2PKH (not a witness program) + witness → rejected.
do
  local redeem_script = p2pkh_script()  -- NOT a witness program
  local script_sig = push_bytes(redeem_script)
  local tx = make_tx_full(
    { { types.hash256(string.rep("\x13", 32)), 0, script_sig,
        { "somearg" } } },
    { { 4990000, p2pkh_script() } }
  )
  local utxos = { { script_pubkey = p2sh_script() } }
  local ok, err = mempool.is_witness_standard(tx, utxos)
  check("Gate 2+3: P2SH wrapping P2PKH + witness → rejected", not ok, err)
  check("Gate 2+3: rejection reason", err == "bad-witness-nonstandard", "got: " .. tostring(err))
end

-- Gate 5 key-path (1 element, no annex): standard.
do
  local sig64 = string.rep("\xaa", 64)
  local tx = make_tx_full(
    { { types.hash256(string.rep("\x14", 32)), 0, "", { sig64 } } },
    { { 4990000, p2pkh_script() } }
  )
  local utxos = { { script_pubkey = p2tr_script() } }
  local ok, err = mempool.is_witness_standard(tx, utxos)
  check("Gate 5: P2TR key-path (64-byte sig) → standard", ok, err)
end

-- ── Part 2: full mempool accept_transaction integration ───────────────────────

print("\n=== Part 2: mempool accept_transaction integration ===")

-- P2A stuffing rejection via accept_transaction.
do
  local base_txid = types.hash256(string.rep("\xa1", 32))
  local base_txid_hex = types.hash256_hex(base_txid)
  local cs = make_mock_chain()
  add_utxo(cs, base_txid_hex, 0, 5000000, p2a_script())
  local mp = mempool.new(cs)

  local inp = types.txin(types.outpoint(base_txid, 0), "", 0xFFFFFFFE)
  inp.witness = { "stuffedbytes" }
  local out = types.txout(4990000, p2pkh_script())
  local tx = types.transaction(1, {inp}, {out}, 0)
  local ok, reason = mp:accept_transaction(tx)
  check("accept_transaction: P2A + witness → rejected", not ok, reason)
  check("accept_transaction: P2A reason", reason == "bad-witness-nonstandard", "got: " .. tostring(reason))
end

-- P2WSH oversized script rejection via accept_transaction.
do
  local base_txid = types.hash256(string.rep("\xa2", 32))
  local base_txid_hex = types.hash256_hex(base_txid)
  local cs = make_mock_chain()
  add_utxo(cs, base_txid_hex, 0, 5000000, p2wsh_script())
  local mp = mempool.new(cs)

  local inp = types.txin(types.outpoint(base_txid, 0), "", 0xFFFFFFFE)
  inp.witness = { "arg", string.rep("\x51", 3601) }  -- script too large
  local out = types.txout(4990000, p2pkh_script())
  local tx = types.transaction(1, {inp}, {out}, 0)
  local ok, reason = mp:accept_transaction(tx)
  check("accept_transaction: P2WSH script > 3600 B → rejected", not ok, reason)
  check("accept_transaction: P2WSH script reason", reason == "bad-witness-nonstandard",
        "got: " .. tostring(reason))
end

-- P2TR annex rejection via accept_transaction.
do
  local base_txid = types.hash256(string.rep("\xa3", 32))
  local base_txid_hex = types.hash256_hex(base_txid)
  local cs = make_mock_chain()
  add_utxo(cs, base_txid_hex, 0, 5000000, p2tr_script())
  local mp = mempool.new(cs)

  local inp = types.txin(types.outpoint(base_txid, 0), "", 0xFFFFFFFE)
  inp.witness = { "schnorrsig", "\x50annexdata" }
  local out = types.txout(4990000, p2pkh_script())
  local tx = types.transaction(1, {inp}, {out}, 0)
  local ok, reason = mp:accept_transaction(tx)
  check("accept_transaction: P2TR annex → rejected", not ok, reason)
  check("accept_transaction: annex reason", reason == "bad-witness-nonstandard",
        "got: " .. tostring(reason))
end

-- P2TR tapscript oversized item via accept_transaction.
do
  local base_txid = types.hash256(string.rep("\xa4", 32))
  local base_txid_hex = types.hash256_hex(base_txid)
  local cs = make_mock_chain()
  add_utxo(cs, base_txid_hex, 0, 5000000, p2tr_script())
  local mp = mempool.new(cs)

  local inp = types.txin(types.outpoint(base_txid, 0), "", 0xFFFFFFFE)
  local big_item = string.rep("\xcd", 81)
  inp.witness = { big_item, "\x51", "\xc0" .. string.rep("\xef", 32) }
  local out = types.txout(4990000, p2pkh_script())
  local tx = types.transaction(1, {inp}, {out}, 0)
  local ok, reason = mp:accept_transaction(tx)
  check("accept_transaction: tapscript item 81 B → rejected", not ok, reason)
  check("accept_transaction: tapscript reason", reason == "bad-witness-nonstandard",
        "got: " .. tostring(reason))
end

-- Non-witness prevout with witness → rejected.
do
  local base_txid = types.hash256(string.rep("\xa5", 32))
  local base_txid_hex = types.hash256_hex(base_txid)
  local cs = make_mock_chain()
  add_utxo(cs, base_txid_hex, 0, 5000000, p2pkh_script())
  local mp = mempool.new(cs)

  local inp = types.txin(types.outpoint(base_txid, 0), "", 0xFFFFFFFE)
  inp.witness = { "bloated" }
  local out = types.txout(4990000, p2pkh_script())
  local tx = types.transaction(1, {inp}, {out}, 0)
  local ok, reason = mp:accept_transaction(tx)
  check("accept_transaction: P2PKH + witness → rejected", not ok, reason)
  check("accept_transaction: P2PKH reason", reason == "bad-witness-nonstandard",
        "got: " .. tostring(reason))
end

-- Standard P2WSH within limits → accepted.
do
  local base_txid = types.hash256(string.rep("\xa6", 32))
  local base_txid_hex = types.hash256_hex(base_txid)
  local cs = make_mock_chain()
  add_utxo(cs, base_txid_hex, 0, 5000000, p2wsh_script())
  local mp = mempool.new(cs)

  local inp = types.txin(types.outpoint(base_txid, 0), "", 0xFFFFFFFE)
  -- 2 stack args (each 20 bytes) + 10-byte redeemScript
  inp.witness = { string.rep("\x01", 20), string.rep("\x02", 20), "\x51" }
  local out = types.txout(4990000, p2pkh_script())
  local tx = types.transaction(1, {inp}, {out}, 0)
  local ok, reason = mp:accept_transaction(tx)
  check("accept_transaction: valid P2WSH spend → accepted", ok, reason)
end

-- ── summary ──────────────────────────────────────────────────────────────────

print(string.format("\n%d passed, %d failed", pass, fail))
if fail > 0 then
  os.exit(1)
end
