-- Reject-reason token parity for the mempool RPC paths
-- (testmempoolaccept / sendrawtransaction).
--
-- Asserts that lunarblock emits Bitcoin Core's *bare* reject-reason tokens
-- rather than English prose, per _reason-code-parity-2026-07-08.md (Tier B).
-- Core references: consensus/tx_check.cpp, consensus/tx_verify.cpp,
-- validation.cpp, rpc/mempool.cpp:399-400.
--
-- Standalone (no busted): run with `luajit test_reason_token_parity.lua`.
package.path = "./lunarblock/?.lua;" .. package.path
package.cpath = "./lib/?.so;" .. package.cpath

local types = require("lunarblock.types")
local mempool = require("lunarblock.mempool")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local serialize = require("lunarblock.serialize")
local rpc = require("lunarblock.rpc")

-- Standard P2PKH scriptPubKey.
local P2PKH_SCRIPT = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"

local pass_count, fail_count = 0, 0
local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then
    pass_count = pass_count + 1
    print("PASS: " .. name)
  else
    fail_count = fail_count + 1
    print("FAIL: " .. name)
    print("  " .. tostring(err))
  end
end

local function assert_eq(expected, actual, msg)
  if expected ~= actual then
    error((msg or "mismatch") .. ": expected '" .. tostring(expected)
      .. "' but got '" .. tostring(actual) .. "'", 2)
  end
end

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------
local function make_tx(version, locktime)
  return types.transaction(version or 1, {}, {}, locktime or 0)
end
local function make_input(txid_hash, vout, sequence)
  return types.txin(types.outpoint(txid_hash, vout), "", sequence or 0xFFFFFFFF)
end
local function make_output(value, script)
  return types.txout(value, script or P2PKH_SCRIPT)
end

local function make_chain_state(utxos)
  local coin_view = {
    utxos = utxos or {},
    get = function(self, txid, vout)
      return self.utxos[types.hash256_hex(txid) .. ":" .. vout]
    end,
  }
  return { coin_view = coin_view, tip_height = 700000 }
end
local function add_utxo(cs, txid_hex, vout, value, height, is_coinbase)
  cs.coin_view.utxos[txid_hex .. ":" .. vout] = {
    value = value, script_pubkey = P2PKH_SCRIPT,
    height = height or 500000, is_coinbase = is_coinbase or false,
  }
end

-- Call validation.check_transaction and return the bare token it raised
-- (strips any "file:line: " prefix, exactly as accept_transaction does).
local function check_tx_token(tx)
  local ok, err = pcall(validation.check_transaction, tx)
  if ok then error("expected check_transaction to reject", 2) end
  return (tostring(err):gsub("^.-:%d+:%s*", ""))
end

print("\n=== CheckTransaction family: bare Core tokens ===\n")

test("bad-txns-vin-empty (no inputs)", function()
  local tx = make_tx(); tx.outputs[1] = make_output(50000)
  assert_eq("bad-txns-vin-empty", check_tx_token(tx))
end)

test("bad-txns-vout-empty (no outputs)", function()
  local tx = make_tx()
  tx.inputs[1] = make_input(types.hash256(string.rep("\x01", 32)), 0)
  assert_eq("bad-txns-vout-empty", check_tx_token(tx))
end)

test("bad-txns-oversize (stripped size > 1MB)", function()
  local tx = make_tx()
  tx.inputs[1] = make_input(types.hash256(string.rep("\x01", 32)), 0)
  tx.outputs[1] = make_output(50000, string.rep("\x00", 1000001))
  assert_eq("bad-txns-oversize", check_tx_token(tx))
end)

test("bad-txns-vout-negative", function()
  local tx = make_tx()
  tx.inputs[1] = make_input(types.hash256(string.rep("\x01", 32)), 0)
  tx.outputs[1] = make_output(-1)
  assert_eq("bad-txns-vout-negative", check_tx_token(tx))
end)

test("bad-txns-vout-toolarge", function()
  local tx = make_tx()
  tx.inputs[1] = make_input(types.hash256(string.rep("\x01", 32)), 0)
  tx.outputs[1] = make_output(consensus.MAX_MONEY + 1)
  assert_eq("bad-txns-vout-toolarge", check_tx_token(tx))
end)

test("bad-txns-txouttotal-toolarge", function()
  local tx = make_tx()
  tx.inputs[1] = make_input(types.hash256(string.rep("\x01", 32)), 0)
  tx.outputs[1] = make_output(consensus.MAX_MONEY)
  tx.outputs[2] = make_output(consensus.MAX_MONEY)
  assert_eq("bad-txns-txouttotal-toolarge", check_tx_token(tx))
end)

test("bad-txns-inputs-duplicate", function()
  local tx = make_tx()
  local h = types.hash256(string.rep("\x01", 32))
  tx.inputs[1] = make_input(h, 0)
  tx.inputs[2] = make_input(h, 0)
  tx.outputs[1] = make_output(50000)
  assert_eq("bad-txns-inputs-duplicate", check_tx_token(tx))
end)

test("bad-txns-prevout-null (non-coinbase null input)", function()
  local tx = make_tx()
  tx.inputs[1] = make_input(types.hash256(string.rep("\x01", 32)), 0)
  tx.inputs[2] = make_input(types.hash256(string.rep("\x00", 32)), 0)
  tx.outputs[1] = make_output(50000)
  assert_eq("bad-txns-prevout-null", check_tx_token(tx))
end)

print("\n=== accept_transaction: mempool reject tokens ===\n")

-- These tokens now surface verbatim through the pcall in accept_transaction.
test("CheckTransaction token surfaces through accept_transaction", function()
  local cs = make_chain_state()
  local mp = mempool.new(cs)
  local tx = make_tx()
  local h = types.hash256(string.rep("\x01", 32))
  tx.inputs[1] = make_input(h, 0)
  tx.inputs[2] = make_input(h, 0)  -- duplicate
  tx.outputs[1] = make_output(50000)
  local ok, err = mp:accept_transaction(tx)
  assert_eq(false, ok, "should reject")
  assert_eq("bad-txns-inputs-duplicate", err)
end)

test("non-final (mempool token, not bad-txns-nonfinal)", function()
  local cs = make_chain_state()
  local prev = types.hash256(string.rep("\x01", 32))
  add_utxo(cs, types.hash256_hex(prev), 0, 100000)
  local mp = mempool.new(cs)
  -- Height-based locktime in the future, non-final sequence.
  local tx = make_tx(1, 800000)
  tx.inputs[1] = make_input(prev, 0, 0xFFFFFFFE)
  tx.outputs[1] = make_output(90000)
  local ok, err = mp:accept_transaction(tx)
  assert_eq(false, ok, "should reject")
  assert_eq("non-final", err)
end)

test("bad-txns-premature-spend-of-coinbase", function()
  local cs = make_chain_state()
  local prev = types.hash256(string.rep("\x02", 32))
  -- coinbase only 50 blocks deep (needs 100)
  add_utxo(cs, types.hash256_hex(prev), 0, 100000, 699950, true)
  local mp = mempool.new(cs)
  local tx = make_tx()
  tx.inputs[1] = make_input(prev, 0)
  tx.outputs[1] = make_output(90000)
  local ok, err = mp:accept_transaction(tx)
  assert_eq(false, ok, "should reject")
  assert_eq("bad-txns-premature-spend-of-coinbase", err)
end)

test("bad-txns-in-belowout (outputs exceed inputs)", function()
  local cs = make_chain_state()
  local prev = types.hash256(string.rep("\x03", 32))
  add_utxo(cs, types.hash256_hex(prev), 0, 100000)
  local mp = mempool.new(cs)
  local tx = make_tx()
  tx.inputs[1] = make_input(prev, 0)
  tx.outputs[1] = make_output(200000)  -- more than the 100000 input
  local ok, err = mp:accept_transaction(tx)
  assert_eq(false, ok, "should reject")
  assert_eq("bad-txns-in-belowout", err)
end)

test("min relay fee not met", function()
  local cs = make_chain_state()
  local prev = types.hash256(string.rep("\x04", 32))
  add_utxo(cs, types.hash256_hex(prev), 0, 100000)
  local mp = mempool.new(cs)
  local tx = make_tx()
  tx.inputs[1] = make_input(prev, 0)
  tx.outputs[1] = make_output(99999)  -- 1 sat fee -> below min relay
  local ok, err = mp:accept_transaction(tx)
  assert_eq(false, ok, "should reject")
  assert_eq("min relay fee not met", err)
end)

test("accept_transaction keeps internal bad-txns-inputs-missingorspent", function()
  local cs = make_chain_state()
  local mp = mempool.new(cs)
  local tx = make_tx()
  tx.inputs[1] = make_input(types.hash256(string.rep("\x99", 32)), 0)  -- absent
  tx.outputs[1] = make_output(50000)
  local ok, err = mp:accept_transaction(tx)
  assert_eq(false, ok, "should reject")
  assert_eq("bad-txns-inputs-missingorspent", err)
end)

print("\n=== testmempoolaccept RPC: missing-inputs remap ===\n")

test("testmempoolaccept remaps missing inputs -> 'missing-inputs'", function()
  local cs = make_chain_state()
  local mp = mempool.new(cs)
  local server = rpc.new({ network = consensus.networks.mainnet, mempool = mp })

  local tx = make_tx()
  tx.inputs[1] = make_input(types.hash256(string.rep("\x99", 32)), 0)  -- absent
  tx.outputs[1] = make_output(50000)
  local hex = rpc.hex_encode(serialize.serialize_transaction(tx, true))

  local results = server.methods["testmempoolaccept"](server, { { hex } })
  assert_eq(false, results[1].allowed, "should not be allowed")
  assert_eq("missing-inputs", results[1]["reject-reason"])
end)

print("")
print(string.format("=== %d passed, %d failed ===", pass_count, fail_count))
if fail_count > 0 then os.exit(1) end
