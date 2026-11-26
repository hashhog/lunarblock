-- spec/psweep_multisig_findanddelete_empty_sig_spec.lua
--
-- Legacy (SigVersion::BASE) FindAndDelete of an EMPTY signature
-- (item psweep-lunarblock-multisig-findanddelete-empty-sig; it also covers
-- the CONST_SCRIPTCODE count site of r3fix-lunarblock-findanddelete-empty-sig).
--
-- Core v31.1, script/interpreter.cpp:
--   * OP_CHECKMULTISIG(VERIFY), lines 1138-1150: ONE scriptCode
--     (pbegincodehash..pend) and, for EVERY signature k, empty included,
--     FindAndDelete(scriptCode, CScript() << vchSig) before any signature is
--     checked.  `CScript() << {}` is the single byte 00 (AppendDataSize(0)),
--     so an empty sig deletes every opcode-aligned OP_0 from the scriptCode
--     the other, non-empty signatures are then hashed over.
--   * FindAndDelete, lines 229-255: byte-exact, opcode-aligned matching; the
--     return value is the number of deletions, and with
--     SCRIPT_VERIFY_CONST_SCRIPTCODE (policy) found > 0 is SIG_FINDANDDELETE,
--     in CHECKSIG (lines 328-333) and CHECKMULTISIG alike.
--
-- lunarblock master (076d240) skipped the empty sig in both legacy sig
-- checkers (validation.make_sig_checker, which connect_block's serial and
-- parallel paths use, and make_collecting_sig_checker, which no caller in
-- src/ reaches today) and in validation.find_and_delete itself, so the
-- multisig sighash kept the OP_0.
-- With scriptPubKey  00 75 53 <pk1> <pk2> <pk3> <pk4> 54 ae 91
-- and scriptSig      00 00 01 01 <S>       (S: pk4 over Core's scriptCode)
--   Core:   S verifies against pk4; the next sig, 01, fails SIG_DER -> invalid.
--   master: S fails pk4 and pk3, nSigs 3 > nKeys 2, false, OP_NOT -> valid.
-- The mirror (S' over the scriptCode WITH the 00) is the opposite split:
-- Core accepts, master rejects.  Every block verdict below was replayed into
-- a pinned bitcoind v31.1 (set FAD_DUMP_DIR to dump the regtest chains).
--
-- The CONST_SCRIPTCODE count (script.lua findanddelete_count) used a Lua
-- gsub pattern: it returned 0 for an empty sig, matched inside push data
-- (not opcode-aligned), and a needle holding a NUL byte truncated the
-- pattern (an empty pattern matches at every position).

package.path = "./src/?.lua;" .. package.path
package.cpath = "./lib/?.so;" .. package.cpath

local types       = require("lunarblock.types")
local utxo_mod    = require("lunarblock.utxo")
local consensus   = require("lunarblock.consensus")
local validation  = require("lunarblock.validation")
local script      = require("lunarblock.script")
local crypto      = require("lunarblock.crypto")
local mining      = require("lunarblock.mining")
local serialize   = require("lunarblock.serialize")
local storage_mod = require("lunarblock.storage")
local mempool_mod = require("lunarblock.mempool")
local rpc_mod     = require("lunarblock.rpc")
local fault       = require("lunarblock.fault")
local cjson       = require("cjson")

local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function push(data)
  local n = #data
  if n == 0 then return "\x00" end
  if n <= 75 then return string.char(n) .. data end
  assert(n <= 255)
  return "\x4c" .. string.char(n) .. data
end

local SIGHASH_ALL = 1

-- Four deterministic keys.
local PRIV, PK = {}, {}
for i = 1, 4 do
  PRIV[i] = crypto.sha256("psweep-fad-key-" .. i)
  PK[i] = crypto.pubkey_from_privkey(PRIV[i], true)
end

local function multisig_body()
  return "\x53" .. push(PK[1]) .. push(PK[2]) .. push(PK[3]) .. push(PK[4]) .. "\x54\xae"
end

-- The item's script:  00 75 53 <pk1..pk4> 54 ae 91
local FAD_SPK  = "\x00\x75" .. multisig_body() .. "\x91"
-- Control: the same OP_0-prefixed 3-of-4 without OP_NOT (must verify).
local CTRL_SPK = "\x00\x75" .. multisig_body()

-- Sign `tx` input `idx` (0-based) with key i over `script_code` (legacy,
-- SIGHASH_ALL).  The sighash is built with sig_bytes=nil, so no
-- FindAndDelete runs inside this helper: the caller passes the exact
-- scriptCode Core hashes.
local function sign(tx, idx, script_code, i)
  local h = validation.signature_hash_legacy(tx, idx, script_code, SIGHASH_ALL, nil)
  local der = assert(crypto.ecdsa_sign(PRIV[i], h))
  return der .. string.char(SIGHASH_ALL)
end

-- scriptSig for a spend of `kind`, given the unsigned tx:
--   input1  00 00 01 01 <S>     S by pk4 over Core's scriptCode (OP_0 deleted)
--   mirror  00 00 01 01 <S'>    S' by pk4 over the scriptCode with OP_0 kept
--   ctrl    00 <s2> <s3> <s4>   valid 3-of-4 over CTRL_SPK (no empty sig)
--   ctrlbad ctrl with s4 over the wrong scriptCode: must be rejected
-- `wrap` = the P2SH redeem script (appended as the last push) or nil.
local function script_sig_for(kind, tx, idx, wrap)
  local code = wrap or (kind:sub(1, 4) == "ctrl" and CTRL_SPK or FAD_SPK)
  local ss
  if kind == "input1" then
    local S = sign(tx, idx, code:sub(2), 4)       -- leading 00 deleted, as Core
    ss = "\x00\x00\x01\x01" .. push(S)
  elseif kind == "mirror" then
    local S = sign(tx, idx, code, 4)              -- 00 kept
    ss = "\x00\x00\x01\x01" .. push(S)
  elseif kind == "ctrl" or kind == "ctrlbad" then
    local s4code = (kind == "ctrlbad") and code:sub(2) or code
    ss = "\x00" .. push(sign(tx, idx, code, 2)) .. push(sign(tx, idx, code, 3))
      .. push(sign(tx, idx, s4code, 4))
  else
    error("unknown kind " .. kind)
  end
  if wrap then ss = ss .. push(wrap) end
  return ss
end

-- P2WSH (SigVersion::WITNESS_V0): Core runs no FindAndDelete, so the
-- scriptCode is the whole witnessScript, OP_0 included.  Guards that the
-- fix stays out of segwit v0:
--   w_full  00 00 01 <S>, S by pk4 over the full witnessScript
--           -> Core: S verifies, then 01 fails SIG_DER: invalid
--   w_del   the same with S over the OP_0-deleted witnessScript
--           -> Core: S fails pk4..pk3, false, OP_NOT: valid
local P2WSH_SPK = "\x00\x20" .. crypto.sha256(FAD_SPK)
local function witness_for(kind, tx, idx, value)
  local code = (kind == "w_full") and FAD_SPK or FAD_SPK:sub(2)
  local h = validation.signature_hash_segwit_v0(tx, idx, code, value, SIGHASH_ALL, nil)
  local S = assert(crypto.ecdsa_sign(PRIV[4], h)) .. string.char(SIGHASH_ALL)
  return { "", "", "\x01", S, FAD_SPK }
end

local function spk_for(kind, p2sh)
  local base = kind:sub(1, 4) == "ctrl" and CTRL_SPK or FAD_SPK
  if p2sh then return script.make_p2sh_script(crypto.hash160(base)), base end
  return base, nil
end

--------------------------------------------------------------------------------
-- 1. validation.find_and_delete with an empty signature (Core FindAndDelete
--    with b = CScript() << {} = 00).
--------------------------------------------------------------------------------
describe("find_and_delete of an empty signature deletes opcode-aligned OP_0 (Core)", function()
  it("deletes a leading OP_0: 00 75 51 -> 75 51", function()
    assert.equal(hex("\x75\x51"), hex(validation.find_and_delete("\x00\x75\x51", "")))
  end)

  it("deletes every OP_0, consecutive ones included: 00 00 51 00 -> 51", function()
    assert.equal(hex("\x51"), hex(validation.find_and_delete("\x00\x00\x51\x00", "")))
  end)

  it("deletes the OP_0 of the item's scriptPubKey only", function()
    assert.equal(hex(FAD_SPK:sub(2)), hex(validation.find_and_delete(FAD_SPK, "")))
  end)

  -- Opcode alignment: zero bytes inside push data are not opcodes.
  it("deletes a trailing OP_0 but not the zero bytes of the push before it: 02 00 00 00 -> 02 00 00", function()
    assert.equal(hex("\x02\x00\x00"), hex(validation.find_and_delete("\x02\x00\x00\x00", "")))
  end)

  it("keeps a PUSHDATA1 of a single zero byte: 4c 01 00 unchanged", function()
    assert.equal(hex("\x4c\x01\x00"), hex(validation.find_and_delete("\x4c\x01\x00", "")))
  end)

  it("control: a script with no OP_0 is unchanged", function()
    assert.equal(hex(CTRL_SPK:sub(3)), hex(validation.find_and_delete(CTRL_SPK:sub(3), "")))
  end)

  it("control: a non-empty sig still deletes only its own push", function()
    local sig = "\x30\x01\x00\x01"
    local s = "\x00" .. push(sig) .. "\x51" .. push(sig)
    assert.equal(hex("\x00\x51"), hex(validation.find_and_delete(s, sig)))
  end)
end)

--------------------------------------------------------------------------------
-- 2. The block-path checkers, through ChainState:connect_block on mainnet
--    params at height 700000 (DERSIG, NULLDUMMY; no CONST_SCRIPTCODE, no
--    NULLFAIL), serial and on the parallel script-check queue.
--------------------------------------------------------------------------------
local MAINNET = consensus.networks.mainnet
local HEIGHT = 700000

local function make_coinbase(height, tag)
  return {
    version = 1, locktime = 0,
    inputs = {{
      prev_out   = { hash = types.hash256(string.rep("\0", 32)), index = 0xFFFFFFFF },
      script_sig = validation.encode_bip34_height(height) .. "/psfad/" .. tag,
      sequence   = 0xFFFFFFFF,
      witness    = {},
    }},
    outputs = {{ value = 0, script_pubkey = "\x51" }},
  }
end

local function build_mainnet(kind, p2sh, tag)
  local is_w = kind:sub(1, 2) == "w_"
  local spk, redeem
  if is_w then spk = P2WSH_SPK else spk, redeem = spk_for(kind, p2sh) end
  local fund = types.hash256(crypto.sha256("psfad-fund-" .. tag))
  local coins = {{ txid = fund, vout = 0, value = 100000, spk = spk }}
  local tx = types.transaction(1,
    {types.txin(types.outpoint(fund, 0), "", 0xFFFFFFFF)},
    {types.txout(90000, "\x51")}, 0)
  if is_w then
    tx.segwit = true
    tx.inputs[1].witness = witness_for(kind, tx, 0, 100000)
  else
    tx.inputs[1].script_sig = script_sig_for(kind, tx, 0, redeem)
  end
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
  local base = os.tmpname()
  local dir = base .. "_psfad"
  os.execute("mkdir -p " .. dir)
  dirs[#dirs + 1] = base
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, MAINNET)
  for _, c in ipairs(coins) do
    cs.coin_view:add(c.txid, c.vout, utxo_mod.utxo_entry(c.value, c.spk, 1, false))
  end
  return cs, stor
end

-- { accepted = bool, internal = bool, err = string|nil }
local function connect(kind, p2sh, use_parallel)
  local tag = kind .. (p2sh and "-p2sh" or "-bare") .. (use_parallel and "-par" or "-ser")
  local block, coins = build_mainnet(kind, p2sh, tag)
  local cs, stor = fresh_chain(coins)
  local bh = types.hash256(crypto.sha256("psfad-blk-" .. tag))
  local okp, ok, err = pcall(cs.connect_block, cs, block, HEIGHT, bh,
    nil, nil, false, use_parallel)
  stor.close()
  local r = { accepted = false, internal = false }
  if not okp then r.err = tostring(ok)
  elseif ok then r.accepted = true
  else r.err = tostring(err) end
  r.internal = fault.is_system_fault(r.err) or fault.is_latched()
  return r
end

describe("legacy CHECKMULTISIG empty-sig FindAndDelete in connect_block (mainnet h=700000)", function()
  local had_workers

  setup(function()
    validation.set_script_check_workers(2)
    had_workers = validation.script_check_workers()
  end)

  teardown(function()
    validation.set_script_check_workers(0)
    for _, base in ipairs(dirs) do
      os.execute("rm -rf " .. base .. "_psfad")
      os.remove(base)
    end
  end)

  before_each(function()
    if fault._reset_for_tests then fault._reset_for_tests() end
  end)

  it("block flags at 700000: DERSIG on, CONST_SCRIPTCODE and NULLFAIL off", function()
    local f = consensus.get_block_script_flags(MAINNET, HEIGHT, nil)
    assert.is_true(f.verify_dersig)
    assert.is_falsy(f.verify_const_scriptcode)
    assert.is_falsy(f.verify_nullfail)
  end)

  it("instrument: the parallel queue has script workers", function()
    assert.is_true(had_workers > 0, "no script-check workers; the parallel cases would run serial")
  end)

  local function accepted(r)
    assert.is_false(r.internal, "internal fault, not a verdict: " .. tostring(r.err))
    assert.is_true(r.accepted, r.err)
  end
  -- `reason`: the script error the rejection must carry (Core's verdict:
  -- SIG_DER for the 01 sig reached after S verifies; EVAL_FALSE, which
  -- lunarblock words "verify_script returned false", for a 3-of-4 whose
  -- result is false).
  local function rejected(r, reason)
    assert.is_false(r.internal, "internal fault, not a verdict: " .. tostring(r.err))
    assert.is_false(r.accepted, "block accepted")
    assert.is_truthy(tostring(r.err):find(reason, 1, true),
      "rejected for the wrong reason (want " .. reason .. "): " .. tostring(r.err))
  end

  for _, path in ipairs({ { "serial", false }, { "parallel", true } }) do
    local pname, par = path[1], path[2]
    for _, wrap in ipairs({ { "bare", false }, { "p2sh", true } }) do
      local wname, p2sh = wrap[1], wrap[2]
      local pre = pname .. " " .. wname .. ": "

      -- Invalid stays invalid (the bug): Core rejects, master accepted.
      it(pre .. "input 1 (S over the OP_0-deleted scriptCode) is rejected, like Core", function()
        rejected(connect("input1", p2sh, par), "SIG_DER")
      end)

      -- Valid stays valid (the mirror): Core accepts, master rejected.
      it(pre .. "mirror (S over the scriptCode with OP_0 kept) is accepted, like Core", function()
        accepted(connect("mirror", p2sh, par))
      end)

      -- Over-deletion guard: non-empty sigs must not delete the OP_0.
      it(pre .. "control: a valid 3-of-4 under an OP_0 prefix, no empty sig, is accepted", function()
        accepted(connect("ctrl", p2sh, par))
      end)

      -- Negative control: the checker really verifies (a wrong sig fails).
      it(pre .. "negative control: the 3-of-4 with one sig over the wrong scriptCode is rejected", function()
        rejected(connect("ctrlbad", p2sh, par), "verify_script returned false")
      end)
    end

    -- Segwit v0 has no FindAndDelete: the empty sig must not delete the OP_0.
    it(pname .. " p2wsh: S over the full witnessScript is rejected, like Core", function()
      rejected(connect("w_full", false, par), "SIG_DER")
    end)

    it(pname .. " p2wsh: S over the OP_0-deleted witnessScript is accepted, like Core", function()
      accepted(connect("w_del", false, par))
    end)
  end
end)

--------------------------------------------------------------------------------
-- 2b. make_collecting_sig_checker in inline mode.  connect_block does not
--     reach it today (no caller in src/ passes opts.collector; the parallel
--     queue's worker calls verify_input_script, i.e. make_sig_checker), so
--     its copy of the multisig FindAndDelete is pinned here directly, the
--     way spec/parallel_verify_spec.lua drives it.
--------------------------------------------------------------------------------
describe("make_collecting_sig_checker (inline) legacy CHECKMULTISIG empty-sig FindAndDelete", function()
  local FLAGS = consensus.get_block_script_flags(MAINNET, HEIGHT, nil)

  local function run(kind, p2sh)
    local spk, redeem = spk_for(kind, p2sh)
    local tx = types.transaction(1,
      {types.txin(types.outpoint(types.hash256(crypto.sha256("psfad-coll-" .. kind)), 0), "", 0xFFFFFFFF)},
      {types.txout(90000, "\x51")}, 0)
    local ss = script_sig_for(kind, tx, 0, redeem)
    tx.inputs[1].script_sig = ss
    local collector = {}
    local checker = validation.make_collecting_sig_checker(
      tx, 0, 100000, spk, FLAGS, collector, nil, true)
    local ok, res, err = pcall(script.verify_script, ss, spk, FLAGS, checker)
    assert.is_true(ok, "verify_script raised: " .. tostring(res))
    assert.equal(0, #collector, "inline mode must not defer")
    return res, err
  end

  for _, wrap in ipairs({ { "bare", false }, { "p2sh", true } }) do
    local wname, p2sh = wrap[1], wrap[2]

    it(wname .. ": input 1 fails (S verifies, then 01 is SIG_DER), like Core", function()
      local res, err = run("input1", p2sh)
      assert.is_falsy(res)
      assert.equal("SIG_DER", err)
    end)

    it(wname .. ": mirror verifies (S fails, OP_NOT), like Core", function()
      local res, err = run("mirror", p2sh)
      assert.is_nil(err)
      assert.is_true(res)
    end)

    it(wname .. ": control: the valid 3-of-4 under an OP_0 prefix verifies", function()
      local res, err = run("ctrl", p2sh)
      assert.is_nil(err)
      assert.is_true(res)
    end)
  end
end)

--------------------------------------------------------------------------------
-- 3. CONST_SCRIPTCODE (policy): the FindAndDelete count of an empty sig,
--    opcode-aligned and NUL-safe (Core interpreter.cpp:330-332, 1146-1148).
--------------------------------------------------------------------------------
describe("CONST_SCRIPTCODE FindAndDelete count (script.verify_script, policy flags)", function()
  local FLAGS = {
    verify_p2sh = true, verify_dersig = true, verify_strictenc = true,
    verify_low_s = true, verify_nulldummy = true, verify_const_scriptcode = true,
  }

  local function run(script_sig, spk, signer)
    local tx = types.transaction(1,
      {types.txin(types.outpoint(types.hash256(string.rep("\x33", 32)), 0), "", 0xFFFFFFFF)},
      {types.txout(1000, "\x51")}, 0)
    if signer then script_sig = signer(tx) end
    tx.inputs[1].script_sig = script_sig
    local checker = validation.make_sig_checker(tx, 0, 2000, spk, FLAGS)
    local ok, res, err = pcall(script.verify_script, script_sig, spk, FLAGS, checker)
    assert.is_true(ok, "verify_script raised: " .. tostring(res))
    return res, err
  end

  it("R32 shape: P2SH redeem 00 00 ac fails SIG_FINDANDDELETE", function()
    local redeem = "\x00\x00\xac"
    local res, err = run(push(redeem), script.make_p2sh_script(crypto.hash160(redeem)))
    assert.is_falsy(res)
    assert.equal("SIG_FINDANDDELETE", err)
  end)

  it("CHECKSIG: empty sig with an OP_0 in the scriptCode fails SIG_FINDANDDELETE", function()
    local res, err = run("\x00", "\x00\x75" .. push(PK[1]) .. "\xac\x91")
    assert.is_falsy(res)
    assert.equal("SIG_FINDANDDELETE", err)
  end)

  it("CHECKMULTISIG: the item's input 1 fails SIG_FINDANDDELETE", function()
    local res, err = run(nil, FAD_SPK, function(tx) return script_sig_for("input1", tx, 0) end)
    assert.is_falsy(res)
    assert.equal("SIG_FINDANDDELETE", err)
  end)

  -- Opcode alignment: zero bytes inside a push are not a match.
  it("control: empty sig, zero bytes only inside a push -> no SIG_FINDANDDELETE", function()
    local res, err = run("\x00", "\x02\x00\x00\x75" .. push(PK[1]) .. "\xac\x91")
    assert.is_nil(err)
    assert.is_true(res)
  end)

  -- Opcode alignment for a non-empty sig: its push sitting inside another
  -- push's data is not a match (Core: found = 0).  The blob is not DER, so
  -- the script then fails SIG_DER -- not SIG_FINDANDDELETE.
  it("a non-empty sig whose push sits inside push data is not SIG_FINDANDDELETE", function()
    local blob = string.rep("\x30", 70) .. string.char(SIGHASH_ALL)
    local inner = "\x07" .. push(blob)
    local spk = "\x4c" .. string.char(#inner) .. inner .. "\x75" .. push(PK[1]) .. "\xac"
    local _, err = run(push(blob), spk)
    assert.equal("SIG_DER", err)
  end)

  it("control: the same sig as an opcode-aligned push is SIG_FINDANDDELETE", function()
    local blob = string.rep("\x30", 70) .. string.char(SIGHASH_ALL)
    local spk = push(blob) .. "\x75" .. push(PK[1]) .. "\xac"
    local _, err = run(push(blob), spk)
    assert.equal("SIG_FINDANDDELETE", err)
  end)

  -- NUL safety: a sig holding a zero byte is compared byte-exactly.  The
  -- scriptCode holds an aligned push that agrees with the sig's push only up
  -- to the sig's NUL (a NUL truncates a Lua pattern).  Core: found = 0; the
  -- DER-valid sig then fails to verify, OP_NOT -> true.
  it("a sig holding a NUL byte is not matched by a push that differs after the NUL", function()
    local sig = "\x30\x06\x02\x01\x00\x02\x01\x01" .. string.char(SIGHASH_ALL)
    local spk = "\x09\x30\x06\x02\x01\xff\xff\xff\xff\xff\x75" .. push(PK[1]) .. "\xac\x91"
    local res, err = run(push(sig), spk)
    assert.is_nil(err)
    assert.is_true(res)
  end)

  it("control: the same NUL-holding sig as an aligned push is SIG_FINDANDDELETE", function()
    local sig = "\x30\x06\x02\x01\x00\x02\x01\x01" .. string.char(SIGHASH_ALL)
    local spk = push(sig) .. "\x75" .. push(PK[1]) .. "\xac\x91"
    local _, err = run(push(sig), spk)
    assert.equal("SIG_FINDANDDELETE", err)
  end)
end)

describe("testmempoolaccept of the R32 minimised tx (p2sh [0 0 CHECKSIG])", function()
  local R32_HEX = "0200000001c877670c3d53f7de5a8018a94494b99668c036a58788bb4ab34d1c75bdf0e0b70000000004030000acfeffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000"

  it("is refused with SIG_FINDANDDELETE (Signature is found in scriptCode), like Core", function()
    local tx = serialize.deserialize_transaction(serialize.buffer_reader(
      (R32_HEX:gsub("..", function(b) return string.char(tonumber(b, 16)) end))))
    local redeem = "\x00\x00\xac"
    local cs = {
      tip_height = 200,
      tip_hash = types.hash256_zero(),
      storage = {
        get_header = function() return nil end,
        get_hash_by_height = function() return nil end,
      },
      network = consensus.networks.regtest,
      coin_view = {
        utxos = {},
        get = function(self, txid, vout)
          return self.utxos[types.hash256_hex(txid) .. ":" .. vout]
        end,
      },
    }
    local op = tx.inputs[1].prev_out
    cs.coin_view.utxos[types.hash256_hex(op.hash) .. ":" .. op.index] =
      utxo_mod.utxo_entry(100000, script.make_p2sh_script(crypto.hash160(redeem)), 1, false)
    -- main.lua builds the node's mempool with verify_input_scripts = true.
    local mp = mempool_mod.new(cs, {verify_input_scripts = true})
    local server = rpc_mod.new({network = consensus.networks.regtest})
    server.mempool = mp
    local body = cjson.encode({method = "testmempoolaccept", params = {{R32_HEX}}, id = 1})
    local res = cjson.decode((server:handle_request(body)))
    assert.is_true(res.error == nil or res.error == cjson.null,
      "RPC error: " .. cjson.encode(res.error))
    local r = res.result[1]
    assert.is_false(r.allowed)
    assert.is_truthy(tostring(r["reject-reason"]):find("Signature is found in scriptCode", 1, true),
      "reject-reason: " .. tostring(r["reject-reason"]))
  end)
end)

--------------------------------------------------------------------------------
-- 4. Regtest: mine the outputs on the real regtest genesis, then submit a
--    block spending one.  Each case runs on a fresh chain.  With FAD_DUMP_DIR
--    set, each case's full chain (heights 1..105, one hex block per line) is
--    written to <dir>/<case>.hex for replay into bitcoind v31.1.
--------------------------------------------------------------------------------
describe("regtest submitblock: a block spending the multisig outputs", function()
  local REGTEST = consensus.networks.regtest
  local BITS = REGTEST.pow_limit_bits
  local PAY = "\x51"
  local SUBSIDY = 5000000000
  local T0 = os.time() - 7200
  local PREFIX = 104
  -- coinbase at height 1 pays FAD_SPK, 2 pays P2SH(FAD_SPK), 3 pays
  -- CTRL_SPK, 4 pays P2WSH(FAD_SPK)
  local FUND_SPK = {
    [1] = FAD_SPK,
    [2] = script.make_p2sh_script(crypto.hash160(FAD_SPK)),
    [3] = CTRL_SPK,
    [4] = P2WSH_SPK,
  }
  local prefix_blocks, prefix_hex, fund_txid = {}, {}, {}
  local path, db, cs, r

  local function mine(height, prev_hash, txs)
    -- BIP141 commitment only when a tx carries a witness.
    local commitment
    for _, t in ipairs(txs) do
      if t.segwit then
        local wtxids = {types.hash256_zero()}
        for i, u in ipairs(txs) do wtxids[i + 1] = validation.compute_wtxid(u) end
        commitment = crypto.hash256(crypto.compute_merkle_root(wtxids).bytes .. string.rep("\0", 32))
        break
      end
    end
    local cb = mining.create_coinbase_tx(height, SUBSIDY, "/psfad/", commitment,
      FUND_SPK[height] or PAY)
    local all, txids = {cb}, {validation.compute_txid(cb)}
    for i, t in ipairs(txs) do all[i + 1] = t; txids[i + 1] = validation.compute_txid(t) end
    local header = types.block_header(0x20000000, prev_hash,
      crypto.compute_merkle_root(txids), T0 + height * 60, BITS, 0)
    local block = types.block(header, all)
    assert(mining.mine_block(block, 0x7FFFFFFF), "could not mine regtest block")
    return block, validation.compute_block_hash(block.header), txids[1]
  end

  local function submit(block)
    return r.methods["submitblock"](r, {hex(serialize.serialize_block(block))})
  end

  -- kind, funding height, p2sh redeem (or nil)
  local function spend_block(kind, fund_h, redeem)
    local tx = types.transaction(1,
      {types.txin(types.outpoint(fund_txid[fund_h], 0), "", 0xFFFFFFFF)},
      {types.txout(SUBSIDY - 10000, PAY)}, 0)
    if kind:sub(1, 2) == "w_" then
      tx.segwit = true
      tx.inputs[1].witness = witness_for(kind, tx, 0, SUBSIDY)
    else
      tx.inputs[1].script_sig = script_sig_for(kind, tx, 0, redeem)
    end
    local prev = validation.compute_block_hash(prefix_blocks[PREFIX].header)
    return mine(PREFIX + 1, prev, {tx})
  end

  local function dump(name, block)
    local dir = os.getenv("FAD_DUMP_DIR")
    if not dir or dir == "" then return end
    local f = assert(io.open(dir .. "/" .. name .. ".hex", "w"))
    for h = 1, PREFIX do f:write(prefix_hex[h], "\n") end
    f:write(hex(serialize.serialize_block(block)), "\n")
    f:close()
  end

  setup(function()
    local prev = types.hash256_from_hex(REGTEST.genesis_hash)
    for h = 1, PREFIX do
      local block, bh, cbid = mine(h, prev, {})
      prefix_blocks[h] = block
      prefix_hex[h] = hex(serialize.serialize_block(block))
      if FUND_SPK[h] then fund_txid[h] = cbid end
      prev = bh
    end
  end)

  before_each(function()
    fault._reset_for_tests()
    path = (os.getenv("TMPDIR") or "/tmp") .. "/lunarblock_psfad_"
      .. os.time() .. "_" .. math.random(1e9)
    db = storage_mod.open(path)
    cs = utxo_mod.new_chain_state(db, REGTEST)
    cs:init()
    r = rpc_mod.new({ rpcport = 0, network = REGTEST })
    r.chain_state = cs
    r.storage = db
    for h = 1, PREFIX do
      local res = submit(prefix_blocks[h])
      assert(res == cjson.null or res == nil, "prefix submitblock h=" .. h .. ": " .. tostring(res))
    end
    assert.equal(PREFIX, cs.tip_height)
  end)

  after_each(function()
    fault._reset_for_tests()
    pcall(db.close)
    os.execute("rm -rf '" .. path .. "'")
  end)

  local function expect_rejected(name, block, bh)
    dump(name, block)
    local res = submit(block)
    assert.is_true(type(res) == "string", "submitblock accepted the block (Core rejects): " .. tostring(res))
    assert.equal(PREFIX, cs.tip_height)
    assert.is_true(cs:is_block_invalid(bh), "block not marked failed: " .. tostring(res))
  end
  local function expect_accepted(name, block, bh)
    dump(name, block)
    local res = submit(block)
    assert.equal(cjson.null, res, "submitblock: " .. tostring(res))
    assert.equal(PREFIX + 1, cs.tip_height)
    assert.equal(types.hash256_hex(bh), types.hash256_hex(cs.tip_hash))
  end

  it("input 1 bare: rejected, like Core", function()
    expect_rejected("fad_input1_bare", spend_block("input1", 1))
  end)

  it("input 1 p2sh: rejected, like Core", function()
    expect_rejected("fad_input1_p2sh", spend_block("input1", 2, FAD_SPK))
  end)

  it("mirror bare: accepted, like Core", function()
    expect_accepted("fad_mirror_bare", spend_block("mirror", 1))
  end)

  it("mirror p2sh: accepted, like Core", function()
    expect_accepted("fad_mirror_p2sh", spend_block("mirror", 2, FAD_SPK))
  end)

  it("control: valid 3-of-4 under an OP_0 prefix is accepted", function()
    expect_accepted("fad_ctrl", spend_block("ctrl", 3))
  end)

  it("negative control: one sig over the wrong scriptCode is rejected", function()
    expect_rejected("fad_ctrlbad", spend_block("ctrlbad", 3))
  end)

  it("p2wsh: S over the full witnessScript is rejected, like Core", function()
    expect_rejected("fad_p2wsh_full", spend_block("w_full", 4))
  end)

  it("p2wsh: S over the OP_0-deleted witnessScript is accepted, like Core", function()
    expect_accepted("fad_p2wsh_del", spend_block("w_del", 4))
  end)
end)
