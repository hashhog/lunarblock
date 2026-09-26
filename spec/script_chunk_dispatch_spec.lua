-- spec/script_chunk_dispatch_spec.lua
--
-- Tx-grouped chunk dispatch for the script-check worker pool
-- (csrc/parallel_verify.c pv_script_chunk_len; Core CCheckQueue::Loop hands
-- each worker a contiguous batch, not one check at a time).
--
-- Properties pinned here:
--   1. PARTITION: for any batch shape and worker count the chunks are
--      contiguous, disjoint and cover [0, n) -- every input is claimed exactly
--      once; a chunk only ever cuts a tx when the chunk is that tx alone.
--   2. VERDICT: with real multi-input P2WPKH transactions, an all-valid batch
--      passes and a single bad input anywhere (mid-tx, last input of a large
--      tx, first input of a batch) fails the whole batch with the lowest
--      failing index, at 1 worker and at 8, and irrespective of tx order.

local crypto = require("lunarblock.crypto")
local script = require("lunarblock.script")
local types = require("lunarblock.types")
local validation = require("lunarblock.validation")
local consensus = require("lunarblock.consensus")

local FLAGS = {
  verify_p2sh = true, verify_witness = true, verify_dersig = true,
  verify_nulldummy = true, verify_taproot = true,
  verify_checklocktimeverify = true, verify_checksequenceverify = true,
}

-- One P2WPKH tx with `n_in` inputs, each signed with its own key.
-- Returns list of jobs (one per input). `bad` = set of input indices (1-based)
-- whose signature is replaced by a well-formed signature over the wrong hash.
local function make_tx_jobs(tag, n_in, bad)
  bad = bad or {}
  local tx = types.transaction(2, {}, {}, 0)
  tx.segwit = true
  local keys, values = {}, {}
  for i = 1, n_in do
    local priv = crypto.sha256("chunk-" .. tag .. "-" .. i)
    local pub = crypto.pubkey_from_privkey(priv, true)
    keys[i] = { priv = priv, pub = pub, pkh = crypto.hash160(pub) }
    values[i] = 10000 + i
    local prev = types.hash256(crypto.sha256("chunk-prev-" .. tag .. "-" .. i))
    tx.inputs[i] = types.txin(types.outpoint(prev, i - 1), "", 0xFFFFFFFD)
  end
  tx.outputs[1] = types.txout(5000, script.make_p2wpkh_script(string.rep("\x22", 20)))
  local cache = validation.precomputed_tx_data(tx)
  local jobs = {}
  for i = 1, n_in do
    local k = keys[i]
    local synthetic = script.make_p2pkh_script(k.pkh)
    local sh = validation.signature_hash_segwit_v0(
      tx, i - 1, synthetic, values[i], consensus.SIGHASH.ALL, cache)
    if bad[i] then sh = crypto.sha256("not-the-sighash") end
    local der = crypto.ecdsa_sign(k.priv, sh)
    tx.inputs[i].witness = { der .. string.char(consensus.SIGHASH.ALL), k.pub }
    jobs[i] = {
      tx = tx, input_index = i - 1, amount = values[i],
      script_pubkey = script.make_p2wpkh_script(k.pkh),
      flags = FLAGS, taproot_active = true,
    }
  end
  return jobs
end

-- Concatenate per-tx job lists (inputs of one tx stay consecutive, exactly as
-- connect_block queues them).
local function batch(txs)
  local out = {}
  for _, t in ipairs(txs) do
    for _, j in ipairs(t) do out[#out + 1] = j end
  end
  return out
end

local SHAPE = { 1, 2, 10, 1, 3, 60, 1, 1, 15, 4, 2, 1, 33, 1, 7 }

local function build_txs(bad_at)  -- bad_at: {tx_index = {input_index=true}}
  bad_at = bad_at or {}
  local txs = {}
  for t, n in ipairs(SHAPE) do
    txs[t] = make_tx_jobs("t" .. t, n, bad_at[t])
  end
  return txs
end

-- Global 1-based position of (tx t, input i) in batch(txs).
local function pos(txs, t, i)
  local p = 0
  for k = 1, t - 1 do p = p + #txs[k] end
  return p + i
end

describe("script-check chunk partition (pv_script_chunk_len)", function()
  local function check_partition(ids, nworkers)
    local parts = validation._script_chunk_partition(ids, nworkers)
    assert.is_not_nil(parts, "parallel_verify.so must load for this spec")
    local n = #ids
    local covered = {}
    local expect = 0
    for _, p in ipairs(parts) do
      local s, len = p[1], p[2]
      assert.equals(expect, s)             -- contiguous, disjoint
      assert.is_true(len >= 1)
      for k = s, s + len - 1 do
        assert.is_nil(covered[k]); covered[k] = true
      end
      local e = s + len                    -- one past the chunk
      if e < n and ids[e + 1] == ids[e] then
        -- The chunk cuts a tx: then the chunk must be that tx only.
        assert.equals(ids[s + 1], ids[e], "chunk cut a tx while holding another")
      end
      expect = e
    end
    assert.equals(n, expect)               -- covers [0, n)
    return parts
  end

  it("covers every index exactly once for varied shapes and worker counts", function()
    local seed = 12345
    local function rnd(m) seed = (seed * 1103515245 + 12345) % 2147483648; return seed % m end
    for trial = 1, 200 do
      local ids, t = {}, 0
      local ntx = 1 + rnd(300)
      for _ = 1, ntx do
        t = t + 1
        local k = 1 + (rnd(10) == 0 and rnd(400) or rnd(4))
        for _ = 1, k do ids[#ids + 1] = t end
      end
      for _, w in ipairs({ 1, 2, 7, 15 }) do check_partition(ids, w) end
    end
    check_partition({}, 15)
    check_partition({ 1 }, 15)
  end)

  it("hands a small tx to one worker and splits only large txs", function()
    -- 400 two-input txs: no tx may be split at all.
    local ids = {}
    for t = 1, 400 do ids[#ids + 1] = t; ids[#ids + 1] = t end
    local parts = check_partition(ids, 15)
    for _, p in ipairs(parts) do
      assert.equals(0, p[2] % 2)
    end
    -- One 1000-input tx: split, but into far fewer pieces than inputs.
    ids = {}
    for _ = 1, 1000 do ids[#ids + 1] = 1 end
    parts = check_partition(ids, 15)
    assert.is_true(#parts < 100, "1000-input tx cut into " .. #parts .. " chunks")
    assert.is_true(#parts >= 8, "1000-input tx should still spread across workers")
  end)
end)

describe("script-check verdicts under chunked dispatch", function()
  teardown(function()
    validation.set_script_check_workers(0)
    validation.parallel_verify_shutdown()
  end)

  for _, w in ipairs({ 1, 8 }) do
    describe(w .. " worker(s)", function()
      setup(function()
        assert.is_true(validation.set_script_check_workers(w))
        assert.equals(w, validation.script_check_workers())
      end)

      it("accepts an all-valid multi-input batch (every job ran)", function()
        local ok, err = validation.verify_script_checks(batch(build_txs()))
        assert.is_true(ok, tostring(err))
      end)

      it("rejects a bad input in the middle of a 10-input tx", function()
        local txs = build_txs({ [3] = { [6] = true } })
        local ok, err = validation.verify_script_checks(batch(txs))
        assert.is_false(ok)
        assert.matches("^input " .. pos(txs, 3, 6) .. ":", err)
      end)

      it("rejects a bad LAST input of the 60-input tx", function()
        local txs = build_txs({ [6] = { [60] = true } })
        local ok, err = validation.verify_script_checks(batch(txs))
        assert.is_false(ok)
        assert.matches("^input " .. pos(txs, 6, 60) .. ":", err)
      end)

      it("rejects a bad first input and reports the lowest of several", function()
        local txs = build_txs({ [1] = { [1] = true }, [13] = { [20] = true } })
        local ok, err = validation.verify_script_checks(batch(txs))
        assert.is_false(ok)
        assert.matches("^input 1:", err)
        txs = build_txs({ [9] = { [15] = true }, [13] = { [2] = true } })
        ok, err = validation.verify_script_checks(batch(txs))
        assert.is_false(ok)
        assert.matches("^input " .. pos(txs, 9, 15) .. ":", err)
      end)

      it("verdict does not depend on tx order", function()
        local txs = build_txs({ [6] = { [31] = true } })
        local rev = {}
        for k = #txs, 1, -1 do rev[#rev + 1] = txs[k] end
        local ok, err = validation.verify_script_checks(batch(rev))
        assert.is_false(ok)
        -- tx 6 of 15 is at reversed position 10.
        assert.matches("^input " .. pos(rev, 10, 31) .. ":", err)
        local good = build_txs()
        local grev = {}
        for k = #good, 1, -1 do grev[#grev + 1] = good[k] end
        assert.is_true((validation.verify_script_checks(batch(grev))))
      end)
    end)
  end
end)
