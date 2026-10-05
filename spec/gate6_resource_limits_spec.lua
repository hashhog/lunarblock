-- spec/gate6_resource_limits_spec.lua
--
-- Release gate 6 (docs/RELEASE-CHECKLIST.md in the meta-repo): a SYSTEM fault
-- -- allocation failure, I/O error, a script-check worker that did not run --
-- leads to retry or halt, NEVER to a reject (verdict / ban) and NEVER to an
-- accept.  Bitcoin Core: script checks report only ScriptError values;
-- everything else is FatalError -> AbortNode (validation.cpp, node/abort.cpp):
-- no BLOCK_FAILED_VALID, no Misbehaving, no coins-cache flush, exit non-zero.
--
-- Every fault here is injected through src/fault.lua's test hooks
-- (fault.hooks is nil in production) or by replacing a crypto function in
-- this process.  Each injected test FAILS on the deployed commit (3fe8be6 +
-- hook plumbing only) and passes on the fix; the CONTROL tests (a genuinely
-- invalid input is still a verdict, a valid block still connects) pass on
-- both.

package.path = "src/?.lua;" .. package.path

local ffi = require("ffi")
local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local crypto = require("lunarblock.crypto")
local script = require("lunarblock.script")
local storage_mod = require("lunarblock.storage")
local utxo = require("lunarblock.utxo")
local sync = require("lunarblock.sync")
local fault = require("lunarblock.fault")

local REGTEST = consensus.networks.regtest

-- Feature probes: on the deployed tree (hook plumbing only) these are nil.
local function latched()
  return fault.is_latched ~= nil and fault.is_latched() or false
end
local function reset_fault()
  if fault._reset_for_tests then fault._reset_for_tests() else fault.hooks = nil end
end

local OP_TRUE_SPK = "\x51"
local PRIV = string.rep("\x01", 31) .. "\x07"
local PUB = crypto.pubkey_from_privkey(PRIV, true)

local function p2pk_spk(pub, negate)
  -- <pub> OP_CHECKSIG [OP_NOT]
  return string.char(#pub) .. pub .. "\xac" .. (negate and "\x91" or "")
end

local function coinbase(height, nonce)
  -- BIP34: height push first.
  local hb = height < 17 and string.char(0x50 + height) or string.char(1, height % 256)
  if height == 0 then hb = "\x00" end
  return types.transaction(1,
    { types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                 hb .. string.char(1, nonce or 0) .. "\x00\x00", 0xFFFFFFFF) },
    { types.txout(5000000000, OP_TRUE_SPK) }, 0)
end

local function merkle(txs)
  local hashes = {}
  for i, tx in ipairs(txs) do hashes[i] = validation.compute_txid(tx) end
  return crypto.compute_merkle_root(hashes)
end

local function mine(header)
  local target = consensus.bits_to_target(header.bits)
  for nonce = 0, 2000000 do
    header.nonce = nonce
    if consensus.hash_meets_target(validation.compute_block_hash(header).bytes, target) then
      return header
    end
  end
  error("no nonce")
end

describe("gate 6: a system fault is never a verdict (lunarblock)", function()
  local db, cs, path
  local hashes = {}
  local tip_time

  -- Funding coins seeded straight into the chainstate (non-coinbase, so no
  -- maturity wait): one per test kind.
  local FUND = {}

  local function fund(tag, spk, value)
    local txid = types.hash256(crypto.hash256("gate6-fund-" .. tag))
    cs.coin_view:add(txid, 0, utxo.utxo_entry(value or 100000000, spk, 1, false))
    FUND[tag] = { txid = txid, spk = spk, value = value or 100000000 }
  end

  local function spend_tx(tag, script_sig, out_spk)
    local f = FUND[tag]
    return types.transaction(1,
      { types.txin(types.outpoint(f.txid, 0), script_sig or "", 0xFFFFFFFF) },
      { types.txout(f.value - 1000, out_spk or OP_TRUE_SPK) }, 0)
  end

  local function sign_p2pk(tx, spk)
    local sighash = validation.signature_hash_legacy(tx, 0, spk, 1)
    local der = assert(crypto.ecdsa_sign(PRIV, sighash))
    local sig = der .. "\x01"
    return string.char(#sig) .. sig
  end

  local function make_block(txs, nonce)
    local height = cs.tip_height + 1
    local all = { coinbase(height, nonce) }
    for _, t in ipairs(txs or {}) do all[#all + 1] = t end
    tip_time = tip_time + 600
    local header = types.block_header(4, cs.tip_hash, merkle(all),
      tip_time, REGTEST.pow_limit_bits, 0)
    mine(header)
    return types.block(header, all), validation.compute_block_hash(header), height
  end

  -- The IBD connect path (main.lua connect_callback): accept_block with
  -- skip_check_block, and discard_dirty on any failure.
  local function connect(block, bh, height, use_parallel)
    local caller_batch_fn = function(batch)
      batch.put(storage_mod.CF.BLOCKS, bh.bytes, serialize.serialize_block(block))
      batch.put(storage_mod.CF.HEADERS, bh.bytes, serialize.serialize_block_header(block.header))
      local hk = string.char(math.floor(height / 16777216) % 256,
        math.floor(height / 65536) % 256, math.floor(height / 256) % 256, height % 256)
      batch.put(storage_mod.CF.HEIGHT_INDEX, hk, bh.bytes)
    end
    db.put_header(bh, block.header)
    local pc_ok, ok, err = pcall(cs.accept_block, cs, block, height, bh, {
      skip_check_block = true, skip_scripts = false, use_parallel = use_parallel,
      nosync = true, caller_batch_fn = caller_batch_fn, requested = true })
    if not pc_ok then
      cs.coin_view:discard_dirty()
      return nil, tostring(ok), true
    end
    if not ok then
      cs.coin_view:discard_dirty()
      return nil, tostring(err), false
    end
    return true
  end

  -- What the P2P layer would do with the failure: mark (verdict) / punish.
  local function judged(err)
    return sync.is_invalid_block_verdict(err), sync.should_punish_peer_for_block_error(err)
  end

  local function coin_unspent(tag)
    return cs.coin_view:get(FUND[tag].txid, 0) ~= nil
  end
  local function disk_coin_unspent(tag)
    return db.get(storage_mod.CF.UTXO, utxo.outpoint_key(FUND[tag].txid, 0)) ~= nil
  end

  before_each(function()
    reset_fault()
    validation.set_script_check_workers(0)
    path = "/tmp/lunarblock_gate6_" .. os.time() .. "_" .. math.random(1e9)
    db = storage_mod.open(path)
    cs = utxo.new_chain_state(db, REGTEST)
    cs:init()
    -- genesis + h1 with plain coinbases, connected without scripts.
    tip_time = os.time() - 100000
    local prev = types.hash256_zero()
    for h = 0, 1 do
      local all = { coinbase(h, 0) }
      tip_time = tip_time + 600
      local header = types.block_header(4, prev, merkle(all), tip_time, REGTEST.pow_limit_bits, 0)
      mine(header)
      local b = types.block(header, all)
      local bh = validation.compute_block_hash(header)
      db.put_header(bh, header); db.put_block(bh, b); db.put_height_index(h, bh)
      assert(cs:connect_block(b, h, bh, nil, nil, true))
      hashes[h], prev = bh, bh
    end
    fund("anyone", OP_TRUE_SPK)
    fund("p2pk", p2pk_spk(PUB))
    fund("p2pk_not", p2pk_spk(PUB, true))
    fund("p2pkh", script.make_p2pkh_script(crypto.hash160(PUB)))
    cs.coin_view:flush(false)
  end)

  after_each(function()
    reset_fault()
    validation.set_script_check_workers(0)
    if db then pcall(db.close) end
    os.execute("rm -rf '" .. path .. "'")
  end)

  ------------------------------------------------------------------------
  -- CONTROLS (pass on both trees)
  ------------------------------------------------------------------------

  it("CONTROL: a valid signed spend connects (serial)", function()
    local tx = spend_tx("p2pk")
    tx.inputs[1].script_sig = sign_p2pk(tx, FUND.p2pk.spk)
    local b, bh, h = make_block({ tx })
    assert.is_true(connect(b, bh, h, false))
    assert.equals(h, cs.tip_height)
    assert.is_false(coin_unspent("p2pk"))
  end)

  it("CONTROL: a genuinely bad signature is still a verdict (serial and parallel)", function()
    for _, par in ipairs({ false, true }) do
      if par then validation.set_script_check_workers(2) end
      local tx = spend_tx("p2pk")
      tx.inputs[1].script_sig = string.char(72) .. string.rep("\x30", 71) .. "\x01"
      local b, bh, h = make_block({ tx }, par and 9 or 8)
      local ok, err = connect(b, bh, h, par)
      assert.is_nil(ok)
      local verdict, punish = judged(err)
      assert.is_true(verdict, "bad signature must be a verdict: " .. tostring(err))
      assert.is_true(punish)
      assert.is_false(latched())
      assert.equals(1, cs.tip_height)
      assert.is_true(coin_unspent("p2pk"))
    end
  end)

  it("CONTROL: <validsig> <pk> CHECKSIG NOT with no fault is a script failure (verdict)", function()
    local tx = spend_tx("p2pk_not")
    tx.inputs[1].script_sig = sign_p2pk(tx, FUND.p2pk_not.spk)
    local b, bh, h = make_block({ tx })
    local ok, err = connect(b, bh, h, false)
    assert.is_nil(ok)
    assert.is_true((judged(err)))
  end)

  ------------------------------------------------------------------------
  -- Script layer: three outcomes
  ------------------------------------------------------------------------

  it("a transient allocation failure in a script check is re-run, not a verdict (serial)", function()
    local calls = 0
    fault.hooks = { script_check = function()
      calls = calls + 1
      if calls == 1 then error("not enough memory", 0) end
    end }
    local tx = spend_tx("anyone")
    local b, bh, h = make_block({ tx })
    local ok, err = connect(b, bh, h, false)
    assert.is_true(ok, "valid block rejected after a transient OOM: " .. tostring(err))
    assert.equals(h, cs.tip_height)
    assert.is_false(latched())
  end)

  it("a persistent runtime fault in a script check halts: no verdict, no punish, nothing applied", function()
    fault.hooks = { script_check = function()
      local t = nil
      return t.boom  -- "attempt to index local 't' (a nil value)"
    end }
    local tx = spend_tx("anyone")
    local b, bh, h = make_block({ tx })
    local ok, err = connect(b, bh, h, false)
    assert.is_nil(ok)
    local verdict, punish = judged(err)
    assert.is_false(verdict, "runtime fault judged as a verdict: " .. err)
    assert.is_false(punish, "runtime fault punished the peer: " .. err)
    assert.is_true(latched(), "node did not halt (AbortNode latch)")
    assert.equals(1, cs.tip_height)
    assert.is_true(coin_unspent("anyone"))
    assert.is_true(disk_coin_unspent("anyone"))
    -- The latch refuses every further connect -- as a system fault.
    fault.hooks = nil
    local b2, bh2, h2 = make_block({ spend_tx("anyone") }, 3)
    local ok2, err2 = connect(b2, bh2, h2, false)
    assert.is_nil(ok2)
    assert.is_false((judged(err2)))
  end)

  it("<validsig> <pk> CHECKSIG NOT under a secp/alloc fault: never accepted, never a verdict, never cached", function()
    local real_v, real_lax = crypto.ecdsa_verify, crypto.ecdsa_verify_lax
    local faulting = true
    local function fake(...)
      if faulting then error("not enough memory", 0) end
      return real_v(...)
    end
    local function fake_lax(...)
      if faulting then error("not enough memory", 0) end
      return real_lax(...)
    end
    crypto.ecdsa_verify, crypto.ecdsa_verify_lax = fake, fake_lax
    local ok_t, terr = pcall(function()
      local tx = spend_tx("p2pk_not")
      tx.inputs[1].script_sig = sign_p2pk(tx, FUND.p2pk_not.spk)
      local b, bh, h = make_block({ tx })
      local ok, err = connect(b, bh, h, false)
      assert.is_nil(ok, "a NOT'd CHECKSIG whose verify faulted was ACCEPTED")
      assert.equals(1, cs.tip_height)
      local verdict, punish = judged(err)
      assert.is_false(verdict, "secp/alloc fault judged as a verdict: " .. err)
      assert.is_false(punish)
      -- Not cached: with the fault gone, the same block is judged on its
      -- merits (the valid sig makes CHECKSIG NOT fail -> verdict).
      faulting = false
      reset_fault()
      local ok2, err2 = connect(b, bh, h, false)
      assert.is_nil(ok2)
      assert.is_true((judged(err2)), "after the fault clears the block must get its real verdict")
    end)
    crypto.ecdsa_verify, crypto.ecdsa_verify_lax = real_v, real_lax
    assert(ok_t, terr)
  end)

  it("parallel: a worker that faults outside the interpreter is re-run on the host, not a verdict", function()
    validation.set_script_check_workers(2)
    assert.is_true(validation.script_check_workers() >= 1, "pool did not start")
    local junk = "\xff\xff\xff\xff"   -- a tx the worker cannot deserialize
    fault.hooks = { script_jobs_built = function(cjobs, n, keep)
      keep[#keep + 1] = junk
      cjobs[0].tx_bytes = ffi.cast("const uint8_t *", junk)
      cjobs[0].tx_len = #junk
    end }
    local b, bh, h = make_block({ spend_tx("anyone"), spend_tx("p2pk") }, 4)
    b.transactions[3].inputs[1].script_sig = sign_p2pk(b.transactions[3], FUND.p2pk.spk)
    -- re-mine: the merkle root changed
    b.header.merkle_root = merkle(b.transactions); mine(b.header)
    bh = validation.compute_block_hash(b.header)
    local ok, err = connect(b, bh, h, true)
    assert.is_true(ok, "worker fault became a verdict: " .. tostring(err))
    assert.equals(h, cs.tip_height)
    assert.is_false(latched())
  end)

  it("parallel: a job no worker wrote a result for is re-run, never read as pass or fail", function()
    validation.set_script_check_workers(2)
    fault.hooks = { script_jobs_done = function(cjobs, n, failures)
      cjobs[0].result = -1        -- PV_RESULT_NOT_RUN
      cjobs[0].error[0] = 0
      return failures
    end }
    local b, bh, h = make_block({ spend_tx("anyone") }, 5)
    local ok, err = connect(b, bh, h, true)
    assert.is_true(ok, "an unrun job was judged: " .. tostring(err))
    assert.equals(h, cs.tip_height)
  end)

  it("parallel: an unrun job hiding an INVALID input is still rejected (no fail-open)", function()
    validation.set_script_check_workers(2)
    fault.hooks = { script_jobs_done = function(cjobs, n, failures)
      for i = 0, n - 1 do cjobs[i].result = -1; cjobs[i].error[0] = 0 end
      return 0
    end }
    local tx = spend_tx("p2pk")
    tx.inputs[1].script_sig = string.char(72) .. string.rep("\x30", 71) .. "\x01"
    local b, bh, h = make_block({ tx }, 6)
    local ok, err = connect(b, bh, h, true)
    assert.is_nil(ok, "an unrun job read as PASS: invalid input accepted")
    assert.is_true((judged(err)), "re-run of the unrun job must give the real verdict: " .. tostring(err))
    assert.equals(1, cs.tip_height)
  end)

  ------------------------------------------------------------------------
  -- Storage: write-before-forget, retry, halt
  ------------------------------------------------------------------------

  it("a chainstate write that fails twice halts with memory == disk (no verdict, spent coin not resurrected)", function()
    local tx = spend_tx("anyone")
    local b, bh, h = make_block({ tx })
    fault.hooks = { db_write = function() return "IO error: No space left on device" end }
    local ok, err = connect(b, bh, h, false)
    fault.hooks = nil
    assert.is_nil(ok)
    local verdict, punish = judged(err)
    assert.is_false(verdict); assert.is_false(punish)
    assert.is_true(latched(), "a failed chainstate write did not halt the node")
    assert.equals(1, cs.tip_height)
    local disk_hash, disk_h = db.get_chain_tip()
    assert.equals(1, disk_h)
    assert.equals(types.hash256_hex(hashes[1]), types.hash256_hex(disk_hash))
    assert.is_true(coin_unspent("anyone"))
  end)

  it("a single transient write failure is retried in place: the valid block connects", function()
    local n = 0
    fault.hooks = { db_write = function()
      n = n + 1
      if n == 1 then return "IO error: No space left on device" end
    end }
    local b, bh, h = make_block({ spend_tx("anyone") })
    local ok, err = connect(b, bh, h, false)
    fault.hooks = nil
    assert.is_true(ok, tostring(err))
    assert.equals(h, cs.tip_height)
    assert.is_false(coin_unspent("anyone"))
    assert.is_false(disk_coin_unspent("anyone"))
    assert.is_false(latched())
  end)

  it("a coin-DB read error is a system fault: no verdict/punish; the second on the same block halts", function()
    local tx = spend_tx("anyone")
    local b, bh, h = make_block({ tx })
    -- evict the coin from the cache so connect reads it from disk
    cs.coin_view:clear_cache()
    local key = utxo.outpoint_key(FUND.anyone.txid, 0)
    fault.hooks = { db_get = function(cf, k)
      if cf == storage_mod.CF.UTXO and k == key then
        return "Corruption: block checksum mismatch"
      end
    end }
    local ok, err = connect(b, bh, h, false)
    assert.is_nil(ok)
    local verdict, punish = judged(err)
    assert.is_false(verdict, err); assert.is_false(punish, err)
    assert.is_false(latched(), "the first fault must be retried, not halt")
    local ok2, err2 = connect(b, bh, h, false)
    assert.is_nil(ok2)
    assert.is_false((judged(err2)))
    assert.is_true(latched(), "a repeated read fault on the same block must halt")
    fault.hooks = nil
    assert.equals(1, cs.tip_height)
  end)

  it("a reorg commit that fails twice restores memory to the disk tip and halts", function()
    -- Active: h1 -> A2.  Side: h1 -> S2 -> S3 (heavier).
    local a2, a2h, h2 = make_block({}, 11)
    assert.is_true(connect(a2, a2h, h2, false))
    tip_time = tip_time - 600
    local function side(prev, height, t, nonce)
      local all = { coinbase(height, nonce) }
      local header = types.block_header(4, prev, merkle(all), t, REGTEST.pow_limit_bits, 0)
      mine(header)
      local blk = types.block(header, all)
      local hh = validation.compute_block_hash(header)
      db.put_header(hh, header); db.put_block(hh, blk)
      return blk, hh
    end
    local s2, s2h = side(hashes[1], 2, tip_time + 1, 21)
    local s3, s3h = side(s2h, 3, tip_time + 601, 22)
    fault.hooks = { db_write = function(sync_flag)
      if sync_flag then return "IO error: No space left on device" end
    end }
    local pc_ok, res, err = pcall(cs.accept_side_branch_block, cs, s3, s3h)
    fault.hooks = nil
    local e = pc_ok and err or res
    assert.is_true(not pc_ok or res == nil, "reorg reported success")
    assert.is_false(sync.is_invalid_block_verdict(e), tostring(e))
    assert.equals(2, cs.tip_height, "in-memory tip left on the uncommitted side branch")
    assert.equals(types.hash256_hex(a2h), types.hash256_hex(cs.tip_hash))
    local disk_hash, disk_h = db.get_chain_tip()
    assert.equals(2, disk_h)
    assert.equals(types.hash256_hex(a2h), types.hash256_hex(disk_hash))
    assert.is_true(latched(), "a failed reorg commit did not halt the node")
  end)

  it("a failed durability checkpoint (flush) halts the node", function()
    assert.is_true(connect(make_block({ spend_tx("anyone") })))
    fault.hooks = { db_checkpoint = function() return "IO error: No space left on device" end }
    local ok, err = pcall(db.checkpoint, true)
    fault.hooks = nil
    assert.is_false(ok)
    assert.is_false(sync.is_invalid_block_verdict(tostring(err)))
    assert.is_true(latched(), "a failed checkpoint did not halt the node")
  end)

  ------------------------------------------------------------------------
  -- Classifier table and entry points
  ------------------------------------------------------------------------

  it("classifier: wrapped system-fault strings are never verdicts or punishable", function()
    local cases = {
      "Failed to connect block 5: Script verification failed for input 1 of tx ab: not enough memory",
      "Failed to connect block 5: Parallel script verification failed: not enough memory",
      "reorg-connect-failed at height 3: Script verification failed for input 1: not enough memory",
      "Failed to connect block 7: " .. (fault.TAG or "[SYSTEM-FAULT] ") .. "RocksDB error: Corruption: bad block",
      "Failed to connect block 7: RocksDB error: Busy: lock held",
    }
    for _, c in ipairs(cases) do
      assert.is_false(sync.is_invalid_block_verdict(c), "verdict: " .. c)
      assert.is_false(sync.should_punish_peer_for_block_error(c), "punish: " .. c)
    end
    -- controls
    assert.is_true(sync.is_invalid_block_verdict(
      "Failed to connect block 5: Script verification failed for input 1 of tx ab: EVAL_FALSE"))
    assert.is_true(sync.should_punish_peer_for_block_error("bad-prevblk"))
    assert.is_true(sync.should_punish_peer_for_block_error("bad-cb-amount: coinbase pays too much"))
  end)

  it("mempool: a runtime fault in the policy script check is not a reject; the latch refuses admission", function()
    local mempool_mod = require("lunarblock.mempool")
    local mp = mempool_mod.new(cs, { verify_input_scripts = true })
    local P2WPKH = "\x00\x14" .. string.rep("\x33", 20)
    -- control: the same signed tx with no fault is admitted.
    local function sign_p2pkh(t)
      local sighash = validation.signature_hash_legacy(t, 0, FUND.p2pkh.spk, 1)
      local sig = assert(crypto.ecdsa_sign(PRIV, sighash)) .. "\x01"
      return string.char(#sig) .. sig .. string.char(#PUB) .. PUB
    end
    local ctl = spend_tx("p2pkh", nil, P2WPKH)
    ctl.inputs[1].script_sig = sign_p2pkh(ctl)
    local mp_ctl = mempool_mod.new(cs, { verify_input_scripts = true })
    local c_ok, c_acc, c_reason = pcall(mp_ctl.accept_transaction, mp_ctl, ctl)
    assert.is_true(c_ok and c_acc == true, "control tx not admitted: " .. tostring(c_acc) .. " " .. tostring(c_reason))
    local tx = spend_tx("p2pkh", nil, P2WPKH)
    tx.inputs[1].script_sig = sign_p2pkh(tx)
    local real, real_lax = crypto.ecdsa_verify, crypto.ecdsa_verify_lax
    crypto.ecdsa_verify = function() error("not enough memory", 0) end
    crypto.ecdsa_verify_lax = crypto.ecdsa_verify
    local pc_ok, acc, reason = pcall(mp.accept_transaction, mp, tx)
    crypto.ecdsa_verify, crypto.ecdsa_verify_lax = real, real_lax
    -- A raised system fault (no reject reason, nothing a peer is punished
    -- for) -- never a "mandatory-script-verify-flag-failed" reject.
    assert.is_false(pc_ok, "allocation fault in the policy script check became a tx verdict: "
      .. tostring(acc) .. " " .. tostring(reason))
    assert.is_true(fault.is_system_fault ~= nil and fault.is_system_fault(acc), tostring(acc))
    -- Latched: admission refused as a system fault, not a policy reject.
    if fault.latch then fault.latch("test") end
    local tx2 = spend_tx("anyone")
    local pc2, acc2 = pcall(mp.accept_transaction, mp, tx2)
    assert.is_false(pc2 and acc2 == true, "latched node admitted a tx")
    assert.is_false(pc2, "latched node answered with a policy reject instead of a system fault")
  end)

  it("submitblock: a system fault is JSON-RPC -25, never a BIP-22 string", function()
    local rpc_mod = require("lunarblock.rpc")
    local r = rpc_mod.new({ rpcport = 0, network = REGTEST })
    r.chain_state = cs
    r.storage = db
    local b, bh = make_block({ spend_tx("anyone") })
    fault.hooks = { script_check = function() error("not enough memory", 0) end }
    local hex = (serialize.serialize_block(b):gsub(".", function(c)
      return string.format("%02x", c:byte()) end))
    local ok, res = pcall(r.methods["submitblock"], r, { hex })
    fault.hooks = nil
    assert.is_false(ok, "submitblock returned a BIP-22 result for a system fault: " .. tostring(res))
    assert.equals("table", type(res))
    assert.equals(-25, res.code)
    assert.equals(1, cs.tip_height)
    -- Latched now: every later submitblock is -25 too.
    local ok2, res2 = pcall(r.methods["submitblock"], r, { hex })
    assert.is_false(ok2)
    assert.equals(-25, type(res2) == "table" and res2.code or nil)
  end)
end)

describe("gate 6: script-raise classification (lunarblock)", function()
  it("explicit consensus raises are SCRIPT_ERROR; runtime faults are INTERNAL", function()
    assert.is_function(fault.script_raise_handler, "no three-outcome script layer")
    -- A real consensus failure from the interpreter: OP_RETURN.
    local ok, r = xpcall(script.verify_script, fault.script_raise_handler, "", "\x6a", {}, nil)
    assert.is_false(ok)
    local internal = fault.classify_script_raise(r)
    assert.is_false(internal, "OP_RETURN classified INTERNAL")
    -- A runtime fault.
    local ok2, r2 = xpcall(function() local t; return t.x end, fault.script_raise_handler)
    assert.is_false(ok2)
    assert.is_true((fault.classify_script_raise(r2)))
    -- LUA_ERRMEM bypasses the handler.
    assert.is_true((fault.classify_script_raise("not enough memory")))
  end)
end)
