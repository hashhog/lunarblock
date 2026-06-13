#!/usr/bin/env luajit
-- Focused functional test for the fundrawtransaction RPC — lunarblock.
--
-- fundrawtransaction is the raw-tx sibling of walletcreatefundedpsbt: it shares
-- the same coin-selection / change engine (fund_transaction_core in src/rpc.lua,
-- Core's FundTransaction()).  This test mirrors the walletcreatefundedpsbt
-- fixture in spec/wallet_signing_rpc_spec.lua: stand up a fake regtest wallet
-- with one P2WPKH UTXO, build a raw tx with 1 output and NO inputs, fund it,
-- and assert the funded tx is genuine (real selected inputs, real fee, real
-- change position, hex decodes to that tx).
--
-- Reference: bitcoin-core/src/wallet/rpc/spend.cpp fundrawtransaction:706
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_fundrawtransaction.lua 2>&1

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

local rpc        = require("lunarblock.rpc")
local types      = require("lunarblock.types")
local consensus  = require("lunarblock.consensus")
local crypto     = require("lunarblock.crypto")
local script_mod = require("lunarblock.script")
local address    = require("lunarblock.address")
local serialize  = require("lunarblock.serialize")

local bit = require("bit")

-- Test infra ---------------------------------------------------------
local PASS, FAIL = 0, 0
local function pass(n) io.write(string.format("  PASS  %s\n", n)); PASS = PASS + 1 end
local function fail(n, m) io.write(string.format("  FAIL  %s -- %s\n", n, m)); FAIL = FAIL + 1 end
local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end
local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) .. ", expected " .. tostring(b))
  end
end
local function expect_true(v, msg) if not v then error(msg or "expected true") end end

local function bin_to_hex(bin)
  local h = {}
  for i = 1, #bin do h[i] = string.format("%02x", bin:byte(i)) end
  return table.concat(h)
end

print("=== fundrawtransaction RPC functional test (lunarblock) ===\n")

-- Build a fake regtest wallet with one P2WPKH UTXO worth 1 BTC, mirroring the
-- walletcreatefundedpsbt fixture in spec/wallet_signing_rpc_spec.lua.
local function make_funded_wallet()
  local privkey = crypto.sha256("lunarblock-fundraw-test-key")
  local pubkey = crypto.pubkey_from_privkey(privkey, true)
  local pkh = crypto.hash160(pubkey)
  local spk = script_mod.make_p2wpkh_script(pkh)
  local addr = address.pubkey_to_p2wpkh(pubkey, "regtest")

  local prev_txid = types.hash256(string.rep("\x66", 32))
  local outpoint_key = prev_txid.bytes .. string.char(0, 0, 0, 0)

  return {
    network = consensus.networks.regtest,
    is_encrypted = false, is_locked = false,
    keys = {[addr] = {privkey = privkey, pubkey = pubkey, type = "p2wpkh"}},
    utxos = {
      [outpoint_key] = {
        value = 100000000, script_pubkey = spk, address = addr,
        txid = prev_txid, vout = 0, confirmations = 100,
      },
    },
    scan_utxos = function() end,
    estimate_fee_rate = function() return 1 end,
    get_change_address = function() return addr end,
  }, addr
end

-- Build a raw tx with exactly 1 output (0.5 BTC to recip) and NO inputs.
-- A zero-input tx must be serialized in witness format (marker 0x00, flag
-- 0x01) — otherwise the leading 0x00 vin-count byte is indistinguishable from
-- the segwit marker on decode.  This matches Core, which always uses witness
-- serialization for an empty-vin tx.
local function build_unfunded_raw_hex(recip_addr, btc_amount)
  local at, prog = address.decode_address(recip_addr, "regtest")
  local spk = script_mod.make_p2wpkh_script(prog)
  local sat = math.floor(btc_amount * consensus.COIN + 0.5)
  local tx = types.transaction(2, {}, {types.txout(sat, spk)}, 0)
  tx.segwit = true
  return bin_to_hex(serialize.serialize_transaction(tx, true)), sat
end

local function recip()
  local rp = crypto.sha256("lunarblock-fundraw-recipient")
  local pub = crypto.pubkey_from_privkey(rp, true)
  return address.pubkey_to_p2wpkh(pub, "regtest")
end

-- 1. Registration ----------------------------------------------------
test("fundrawtransaction is registered in the wallet RPC dispatch", function()
  local server = rpc.new({network = consensus.networks.regtest})
  expect_true(type(server.methods["fundrawtransaction"]) == "function",
    "method not registered")
end)

-- 2. Default path: fund a 1-output, no-input raw tx. -----------------
test("funds a no-input raw tx: adds inputs + change, genuine fee/changepos", function()
  local server = rpc.new({network = consensus.networks.regtest})
  local wallet = make_funded_wallet()
  server.wallet = wallet

  local recip_addr = recip()
  local out_sat = 50000000  -- 0.5 BTC
  local raw_hex = build_unfunded_raw_hex(recip_addr, 0.5)

  -- Sanity: the pre-fund tx genuinely has NO inputs.
  local pre_tx = serialize.deserialize_transaction(
    (raw_hex:gsub('..', function(cc) return string.char(tonumber(cc, 16)) end)))
  expect_eq(#pre_tx.inputs, 0, "pre-fund tx should have 0 inputs")
  expect_eq(#pre_tx.outputs, 1, "pre-fund tx should have 1 output")

  local result = server.methods["fundrawtransaction"](server, {raw_hex, {feeRate = 1}})

  -- Result shape: { hex, fee, changepos }.
  expect_true(type(result) == "table", "result not a table")
  expect_true(type(result.hex) == "string", "hex must be a string")
  expect_true(type(result.fee) == "number", "fee must be a number")
  expect_true(type(result.changepos) == "number", "changepos must be a number")

  -- Fee is positive and genuine.
  expect_true(result.fee > 0, "fee must be > 0, got " .. tostring(result.fee))

  -- Decode the returned hex back to a tx.
  local funded = serialize.deserialize_transaction(
    (result.hex:gsub('..', function(cc) return string.char(tonumber(cc, 16)) end)))

  -- Inputs were added (vin non-empty).
  expect_true(#funded.inputs >= 1, "funded tx must have >= 1 input")

  -- A change output exists (1 BTC UTXO covers 0.5 BTC + tiny fee, so change
  -- is well above dust → changepos must be valid, not -1).
  expect_true(result.changepos >= 0, "expected a change output (changepos >= 0)")
  expect_eq(#funded.outputs, 2, "funded tx should have recip + change = 2 outputs")

  -- changepos is consistent with the returned hex: the output at changepos is
  -- the change (paying the wallet's change address), the other is the recip.
  local change_out = funded.outputs[result.changepos + 1]
  expect_true(change_out ~= nil, "changepos index out of range in funded tx")

  -- Recompute the funded input/output/fee relationship from the wallet UTXO
  -- set (the only place value comes from) and assert the conservation law:
  --   sum(inputs) == sum(outputs) + fee  AND  change == inputs - outputs - fee.
  local total_in = 0
  for _, inp in ipairs(funded.inputs) do
    local vout = inp.prev_out.index
    local key = inp.prev_out.hash.bytes .. string.char(
      bit.band(vout, 0xFF),
      bit.band(bit.rshift(vout, 8), 0xFF),
      bit.band(bit.rshift(vout, 16), 0xFF),
      bit.band(bit.rshift(vout, 24), 0xFF))
    local u = wallet.utxos[key]
    expect_true(u ~= nil, "funded input references a non-wallet UTXO (fabricated?)")
    total_in = total_in + u.value
  end

  local total_out = 0
  for _, o in ipairs(funded.outputs) do total_out = total_out + o.value end

  local fee_sat = math.floor(result.fee * consensus.COIN + 0.5)
  expect_eq(total_in, total_out + fee_sat,
    "value conservation broken: sum(in) != sum(out) + fee")
  expect_eq(change_out.value, total_in - out_sat - fee_sat,
    "change != inputs - outputs - fee")

  -- The original recipient output is preserved unchanged.
  local recip_present = false
  for _, o in ipairs(funded.outputs) do
    if o.value == out_sat then recip_present = true end
  end
  expect_true(recip_present, "original 0.5 BTC recipient output was not preserved")

  print(string.format(
    "    [genuine] inputs=%d outputs=%d total_in=%d total_out=%d fee=%d change=%d changepos=%d",
    #funded.inputs, #funded.outputs, total_in, total_out, fee_sat,
    change_out.value, result.changepos))
end)

-- 3. Insufficient funds error follows Core. --------------------------
test("insufficient funds raises the wallet error", function()
  local server = rpc.new({network = consensus.networks.regtest})
  server.wallet = {
    network = consensus.networks.regtest,
    is_encrypted = false, is_locked = false,
    utxos = {}, keys = {},
    scan_utxos = function() end,
    estimate_fee_rate = function() return 1 end,
    get_change_address = function() return recip() end,
  }
  local raw_hex = build_unfunded_raw_hex(recip(), 0.5)
  local ok, err = pcall(server.methods["fundrawtransaction"], server, {raw_hex, {feeRate = 1}})
  expect_true(not ok, "expected an error on insufficient funds")
  expect_true(type(err) == "table" and err.code == rpc.ERROR.WALLET_ERROR,
    "expected WALLET_ERROR code")
end)

-- 4. Bad hexstring param is rejected. --------------------------------
test("rejects a non-string hexstring param", function()
  local server = rpc.new({network = consensus.networks.regtest})
  server.wallet = make_funded_wallet()
  local ok, err = pcall(server.methods["fundrawtransaction"], server, {})
  expect_true(not ok, "expected an error on missing hexstring")
  expect_true(type(err) == "table" and err.code == rpc.ERROR.INVALID_PARAMS,
    "expected INVALID_PARAMS code")
end)

print(string.format("\n=== fundrawtransaction SUMMARY: %d PASS / %d FAIL ===", PASS, FAIL))
os.exit(FAIL == 0 and 0 or 1)
