-- spec/pre_taproot_bip341_prevouts_spec.lua
--
-- A witness v1 32-byte spend in a block BELOW mainnet's taproot_height
-- (709632) is validated with Taproot rules, because Core's
-- GetBlockScriptFlags (validation.cpp) sets SCRIPT_VERIFY_TAPROOT for every
-- block except the listed exceptions.  BIP341's sighash commits to EVERY
-- input's spent amount and scriptPubKey (PrecomputedTransactionData::Init,
-- interpreter.cpp, always hashes all spent outputs), so connect_block must
-- hand the full spent-output vector to the script check whenever
-- verify_taproot is set -- not only when height >= taproot_height.
--
-- Pinned here, through ChainState:connect_block on mainnet params at height
-- 700000, on the serial path AND on the parallel script-check queue:
--   1. a 2-input tx whose input 1 spends OP_1 <32-byte key> with a valid
--      BIP341 key-path SIGHASH_DEFAULT signature over both prevouts is
--      accepted (Core accepts);
--   2. the same with SIGHASH_ALL|ANYONECANPAY at input index 1 is accepted,
--      and with a wrong ACP signature it is REJECTED as a script verdict --
--      never a raised internal fault;
--   3. a key-path signature that commits to the wrong amounts is rejected
--      (the fix must not make an invalid spend valid);
--   4. Core's Taproot exception block (mainnet 692261, flags P2SH|WITNESS)
--      still validates without Taproot: a garbage witness v1 spend passes.

package.path = "./src/?.lua;" .. package.path
package.cpath = "./lib/?.so;" .. package.cpath

local utxo_mod    = require("lunarblock.utxo")
local validation  = require("lunarblock.validation")
local consensus   = require("lunarblock.consensus")
local types       = require("lunarblock.types")
local crypto      = require("lunarblock.crypto")
local storage_mod = require("lunarblock.storage")
local fault       = require("lunarblock.fault")

local MAINNET = consensus.networks.mainnet
local HEIGHT = 700000
local TAPROOT_EXCEPTION_HASH =
  "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"

local function xonly_of(priv)
  return crypto.pubkey_from_privkey(priv, true):sub(2, 33)
end

local function make_coinbase(height, tag)
  return {
    version = 1, locktime = 0,
    inputs = {{
      prev_out   = { hash = types.hash256(string.rep("\0", 32)), index = 0xFFFFFFFF },
      script_sig = validation.encode_bip34_height(height) .. "/pretap/" .. tag,
      sequence   = 0xFFFFFFFF,
      witness    = {},
    }},
    outputs = {{ value = 0, script_pubkey = "\x51" }},
  }
end

-- Build the scenario: two funding coins (input 0: bare OP_TRUE; input 1:
-- P2TR key path), and a spending tx signed per `mode`:
--   "default"   SIGHASH_DEFAULT over the real prevouts
--   "acp"       SIGHASH_ALL|ANYONECANPAY (0x81) over the real prevouts
--   "acp_bad"   0x81 signature over a different message
--   "wrong_amt" SIGHASH_DEFAULT over prevouts with input 0's amount changed
--   "garbage"   a 64-byte all-0x01 "signature"
local function build(mode, tag)
  local priv = crypto.sha256("pretap-key-" .. tag)
  local program = xonly_of(priv)
  local p2tr_spk = "\x51\x20" .. program
  local fund0 = types.hash256(crypto.sha256("pretap-fund0-" .. tag))
  local fund1 = types.hash256(crypto.sha256("pretap-fund1-" .. tag))
  local coins = {
    { txid = fund0, vout = 0, value = 70000, spk = "\x51" },
    { txid = fund1, vout = 3, value = 130000, spk = p2tr_spk },
  }
  local tx = types.transaction(2, {}, {}, 0)
  tx.segwit = true
  tx.inputs[1] = types.txin(types.outpoint(fund0, 0), "", 0xFFFFFFFF)
  tx.inputs[2] = types.txin(types.outpoint(fund1, 3), "", 0xFFFFFFFE)
  tx.inputs[1].witness = {}
  tx.outputs[1] = types.txout(190000, "\x51")

  local prevouts = {
    { value = coins[1].value, script_pubkey = coins[1].spk },
    { value = coins[2].value, script_pubkey = coins[2].spk },
  }
  local hash_type = (mode == "acp" or mode == "acp_bad") and 0x81 or 0x00
  local sign_prevouts = prevouts
  if mode == "wrong_amt" then
    sign_prevouts = {
      { value = coins[1].value + 1, script_pubkey = coins[1].spk },
      prevouts[2],
    }
  end
  local sighash = assert(validation.signature_hash_taproot(
    tx, 1, hash_type, sign_prevouts, 0, nil, nil, nil, nil))
  if mode == "acp_bad" then sighash = crypto.sha256("not-the-sighash") end
  local sig
  if mode == "garbage" then
    sig = string.rep("\1", 64)
  else
    sig = assert(crypto.schnorr_sign(priv, sighash))
    assert(crypto.schnorr_verify(program, sig, sighash))
  end
  if hash_type ~= 0 then sig = sig .. string.char(hash_type) end
  tx.inputs[2].witness = { sig }

  local block = {
    header = {
      version = 0x20000000, prev_hash = types.hash256_zero(),
      merkle_root = types.hash256_zero(), timestamp = 1631000000,
      bits = 0x1d00ffff, nonce = 0,
    },
    transactions = { make_coinbase(HEIGHT, tag), tx },
  }
  return block, coins
end

local dirs = {}
local function fresh_chain(coins)
  -- os.tmpname() creates the file it names; remove it with the dir.
  local base = os.tmpname()
  local dir = base .. "_pretap"
  os.execute("mkdir -p " .. dir)
  dirs[#dirs + 1] = base
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, MAINNET)
  for _, c in ipairs(coins) do
    cs.coin_view:add(c.txid, c.vout, utxo_mod.utxo_entry(c.value, c.spk, 1, false))
  end
  return cs, stor
end

-- connect_block reports a script failure by raising (assert) or returning
-- (nil, err); either is a VERDICT.  A raise tagged [SYSTEM-FAULT] (or a
-- latched fault) means the check did not complete -- a node bug, never a
-- verdict on the block (Core: a CScriptCheck returns a ScriptError or the
-- node aborts).
-- Returns { accepted = bool, internal = bool, err = string|nil }
local function connect(mode, tag, use_parallel, block_hash)
  local block, coins = build(mode, tag)
  local cs, stor = fresh_chain(coins)
  block_hash = block_hash or types.hash256(crypto.sha256("pretap-blk-" .. tag))
  local okp, ok, err = pcall(cs.connect_block, cs, block, HEIGHT, block_hash,
    nil, nil, false, use_parallel)
  stor.close()
  local r = { accepted = false, internal = false }
  if not okp then
    r.err = tostring(ok)
  elseif ok then
    r.accepted = true
  else
    r.err = tostring(err)
  end
  r.internal = fault.is_system_fault(r.err) or fault.is_latched()
  return r
end

describe("pre-taproot-height BIP341 prevouts (connect_block, mainnet h=700000)", function()
  local had_workers

  setup(function()
    validation.set_script_check_workers(2)
    had_workers = validation.script_check_workers()
  end)

  teardown(function()
    validation.set_script_check_workers(0)
    for _, base in ipairs(dirs) do
      os.execute("rm -rf " .. base .. "_pretap")
      os.remove(base)
    end
  end)

  before_each(function()
    if fault._reset_for_tests then fault._reset_for_tests() end
  end)

  it("block flags at 700000 carry verify_taproot (Core GetBlockScriptFlags)", function()
    local f = consensus.get_block_script_flags(MAINNET, HEIGHT, nil)
    assert.is_true(f.verify_taproot)
    assert.is_true(HEIGHT < MAINNET.taproot_height)
  end)

  it("instrument: the parallel queue has script workers", function()
    assert.is_true(had_workers > 0, "no script-check workers; the parallel cases would run serial")
  end)

  for _, path in ipairs({ { "serial", false }, { "parallel", true } }) do
    local pname, par = path[1], path[2]

    local function accepted(r)
      assert.is_false(r.internal, "internal fault, not a verdict: " .. tostring(r.err))
      assert.is_true(r.accepted, r.err)
    end
    local function rejected_by_taproot(r)
      assert.is_false(r.internal, "internal fault, not a verdict: " .. tostring(r.err))
      assert.is_false(r.accepted)
      assert.is_truthy(r.err:find("TAPROOT", 1, true) or r.err:find("taproot", 1, true), r.err)
    end

    it(pname .. ": valid SIGHASH_DEFAULT key-path over both prevouts is accepted", function()
      accepted(connect("default", pname .. "-default", par))
    end)

    it(pname .. ": valid SIGHASH_ALL|ANYONECANPAY at index 1 is accepted, not an internal fault", function()
      accepted(connect("acp", pname .. "-acp", par))
    end)

    it(pname .. ": a bad ANYONECANPAY signature at index 1 is a script verdict, not an internal fault", function()
      rejected_by_taproot(connect("acp_bad", pname .. "-acpbad", par))
    end)

    it(pname .. ": a key-path signature committing to the wrong amounts is rejected", function()
      rejected_by_taproot(connect("wrong_amt", pname .. "-wrongamt", par))
    end)

    it(pname .. ": Core's Taproot exception block (692261) still validates without Taproot", function()
      local f = consensus.get_block_script_flags(MAINNET, 692261, TAPROOT_EXCEPTION_HASH)
      assert.is_falsy(f.verify_taproot)
      accepted(connect("garbage", pname .. "-exception", par,
        types.hash256_from_hex(TAPROOT_EXCEPTION_HASH)))
    end)

    it(pname .. ": negative control -- the same garbage spend in a normal block is rejected", function()
      rejected_by_taproot(connect("garbage", pname .. "-garbage", par))
    end)
  end
end)
