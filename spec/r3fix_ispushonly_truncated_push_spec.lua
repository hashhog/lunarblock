-- spec/r3fix_ispushonly_truncated_push_spec.lua
--
-- A scriptSig that ends mid-push (e.g. the single byte 0x4d, OP_PUSHDATA2
-- with no length) is "not push-only", never a raise
-- (item r3fix-lunarblock-ispushonly-truncated-push; R3 diff-fuzz night 1,
-- seed 739943, row R18 mempool/reason/nonstandard|rpc-error:-32603).
--
-- Core v31.1:
--   * CScript::IsPushOnly (script/script.cpp:266-281) returns false when
--     GetOp fails, so IsStandardTx refuses the tx with
--     "scriptsig-not-pushonly" (policy/policy.cpp:130-131).
--   * CScript::GetSigOpCount(scriptSig) (script/script.cpp:183-205) returns 0
--     for a P2SH spend whose scriptSig does not parse, and CountWitnessSigOps
--     only looks inside a push-only scriptSig.
--   * In a block the script fails (BAD_OPCODE, interpreter.cpp:446) and the
--     block is marked BLOCK_FAILED_VALID.
--
-- lunarblock master (84f5cfd): script.is_push_only called parse_script, which
-- assert()s on the truncated push.  testmempoolaccept answered RPC -32603,
-- and from a block spending a P2SH output the raise escaped connect_block's
-- sigop-cost pass (outside the script xpcall): the error matched no
-- sync.classify_callback_error pattern, so the block was never marked failed.

local types = require("lunarblock.types")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local script = require("lunarblock.script")
local crypto = require("lunarblock.crypto")
local mining = require("lunarblock.mining")
local serialize = require("lunarblock.serialize")
local storage_mod = require("lunarblock.storage")
local mempool_mod = require("lunarblock.mempool")
local rpc_mod = require("lunarblock.rpc")
local sync = require("lunarblock.sync")
local fault = require("lunarblock.fault")
local cjson = require("cjson")

local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

-- The minimised R18 case: one input, scriptSig = 4d, spending a bare empty
-- scriptPubKey; one P2WSH output.
local R18_HEX = "02000000010ab49e6c40c793f4af2c4cb5e7573cbd20425fa49669feecf54f1f1d16bfe69400000000014dfeffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000"

local TRUNCATED = {
  ["4d (PUSHDATA2, no length)"]        = "\x4d",
  ["4d01 (PUSHDATA2, half a length)"]  = "\x4d\x01",
  ["4d0100 (PUSHDATA2, no data)"]      = "\x4d\x01\x00",
  ["4c (PUSHDATA1, no length)"]        = "\x4c",
  ["4c05ab (PUSHDATA1, short data)"]   = "\x4c\x05\xab",
  ["4e010000 (PUSHDATA4, short len)"]  = "\x4e\x01\x00\x00",
  ["4e01000000 (PUSHDATA4, no data)"]  = "\x4e\x01\x00\x00\x00",
  ["02ab (direct push, short data)"]   = "\x02\xab",
  ["51 4d (OP_1 then truncated)"]      = "\x51\x4d",
  ["ac 4d (non-push then truncated)"]  = "\xac\x4d",
}

describe("script.is_push_only on a truncated push (Core IsPushOnly)", function()
  for name, s in pairs(TRUNCATED) do
    it("returns false, not a raise: " .. name, function()
      local ok, res = pcall(script.is_push_only, s)
      assert.is_true(ok, "is_push_only raised: " .. tostring(res))
      assert.is_false(res)
    end)
  end

  -- Controls: well-formed scripts keep their answers.
  it("well-formed push-only scripts stay push-only", function()
    assert.is_true(script.is_push_only(""))
    assert.is_true(script.is_push_only("\x00\x51\x60\x4f"))
    assert.is_true(script.is_push_only("\x02\xab\xcd"))
    assert.is_true(script.is_push_only("\x4c\x01\xab"))
    assert.is_true(script.is_push_only("\x4d\x01\x00\xab"))
    assert.is_true(script.is_push_only("\x4e\x01\x00\x00\x00\xab"))
    assert.is_true(script.is_push_only("\x4d\x00\x00"))   -- zero-length PUSHDATA2
    assert.is_true(script.is_push_only("\x50"))           -- OP_RESERVED counts as push
  end)

  it("a non-push opcode is still not push-only", function()
    assert.is_false(script.is_push_only("\x61"))
    assert.is_false(script.is_push_only("\x51\xac"))
  end)
end)

describe("P2SH sigop counting on a truncated scriptSig (Core GetSigOpCount(scriptSig))", function()
  local REDEEM = "\x51"
  local P2SH_SPK = script.make_p2sh_script(crypto.hash160(REDEEM))
  local PREV = types.hash256(string.rep("\x22", 32))

  local function tx_with_sig(sig)
    return types.transaction(2,
      {types.txin(types.outpoint(PREV, 0), sig, 0xFFFFFFFF)},
      {types.txout(1000, "\x51")}, 0)
  end
  local function prev_out() return types.txout(2000, P2SH_SPK) end

  it("extract_p2sh_redeem_script returns nil, not a raise", function()
    local ok, res = pcall(validation.extract_p2sh_redeem_script, "\x4d")
    assert.is_true(ok, "extract_p2sh_redeem_script raised: " .. tostring(res))
    assert.is_nil(res)
  end)

  -- Core returns 0 the moment GetOp fails, even when a complete push holding
  -- CHECKSIGs comes first.
  it("a complete redeem push followed by a truncated push counts 0", function()
    local sig = "\x03\xac\xac\xac" .. "\x4d"
    local ok, n = pcall(validation.get_p2sh_sigop_count, tx_with_sig(sig), prev_out)
    assert.is_true(ok, "get_p2sh_sigop_count raised: " .. tostring(n))
    assert.equal(0, n)
  end)

  it("witness sigops of a P2SH input with a truncated scriptSig are 0", function()
    local ok, n = pcall(validation.count_witness_sigops, "\x4d", P2SH_SPK, {})
    assert.is_true(ok, "count_witness_sigops raised: " .. tostring(n))
    assert.equal(0, n)
  end)

  it("get_transaction_sigop_cost does not raise", function()
    local flags = {verify_p2sh = true, verify_witness = true}
    local ok, n = pcall(validation.get_transaction_sigop_cost,
      tx_with_sig("\x4d"), prev_out, flags)
    assert.is_true(ok, "get_transaction_sigop_cost raised: " .. tostring(n))
    assert.equal(0, n)
  end)

  -- Control: a well-formed P2SH scriptSig still counts its redeem sigops.
  it("control: a well-formed P2SH scriptSig still counts its redeem sigops", function()
    assert.equal(3, validation.get_p2sh_sigop_count(
      tx_with_sig("\x03\xac\xac\xac"), prev_out))
  end)
end)

describe("testmempoolaccept of the R18 minimised tx (scriptSig 4d)", function()
  local function make_cs()
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
    return cs
  end

  it("answers scriptsig-not-pushonly like Core, not RPC -32603", function()
    local mp = mempool_mod.new(make_cs())
    local server = rpc_mod.new({network = consensus.networks.regtest})
    server.mempool = mp
    local body = cjson.encode({method = "testmempoolaccept",
      params = {{R18_HEX}}, id = 1})
    local res = cjson.decode((server:handle_request(body)))
    assert.is_true(res.error == nil or res.error == cjson.null,
      "RPC error: " .. cjson.encode(res.error))
    local r = res.result[1]
    assert.is_false(r.allowed)
    assert.equal("scriptsig-not-pushonly", r["reject-reason"])
  end)
end)

describe("a block spending a P2SH output with scriptSig 4d", function()
  local REGTEST = consensus.networks.regtest
  local BITS = REGTEST.pow_limit_bits
  local SPK = script.make_p2pkh_script(string.rep("\x44", 20))
  local REDEEM = "\x51"                                   -- OP_TRUE
  local P2SH_SPK = script.make_p2sh_script(crypto.hash160(REDEEM))
  -- 100 x (OP_0 OP_0 OP_0 OP_CHECKMULTISIG OP_DROP) OP_1: executes, and
  -- counts 2,000 accurate sigops (each CHECKMULTISIG follows OP_0, so 20).
  local EXEC_REDEEM = string.rep("\x00\x00\x00\xae\x75", 100) .. "\x51"
  local P2SH_EXEC = script.make_p2sh_script(crypto.hash160(EXEC_REDEEM))
  local N_EXEC = 11                 -- 11 x 2,000 x 4 = 88,000 > 80,000
  local T0 = os.time()
  -- heights 0..PREFIX; coinbase 1 pays P2SH(OP_TRUE), coinbases
  -- 2..1+N_EXEC pay P2SH(EXEC_REDEEM); all mature at PREFIX + 1.
  local PREFIX = 1 + N_EXEC + 100
  local path, db, cs, r, hashes, funding_txid, exec_txids

  local function subsidy(height)
    return math.floor(5000000000 / (2 ^ math.floor(height / 150)))
  end

  local function simple_block(height, prev_hash, spk)
    local cb = types.transaction(1,
      {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                  string.char(1, height % 256), 0xFFFFFFFF)},
      {types.txout(subsidy(height), spk or SPK)}, 0)
    local header = types.block_header(1, prev_hash, types.hash256_zero(),
      T0 + height, BITS, 0)
    local block = types.block(header, {cb})
    block.header.merkle_root = crypto.compute_merkle_root({validation.compute_txid(cb)})
    return block, validation.compute_block_hash(block.header), validation.compute_txid(cb)
  end

  -- Mined block at `height` holding a coinbase plus one tx that spends the
  -- height-1 P2SH coinbase output with `script_sig`.
  -- With `heavy`, a third tx follows that spends the N_EXEC P2SH(EXEC_REDEEM)
  -- coinbases: 88,000 sigop cost counted only in ConnectBlock (no legacy
  -- sigops, so the context-free CheckBlock count passes).
  local function spend_block(height, prev_hash, script_sig, heavy)
    local spend = types.transaction(2,
      {types.txin(types.outpoint(funding_txid, 0), script_sig, 0xFFFFFFFF)},
      {types.txout(subsidy(1) - 10000, SPK)}, 0)
    local txs = {spend}
    if heavy then
      local push = "\x4d" .. string.char(#EXEC_REDEEM % 256, math.floor(#EXEC_REDEEM / 256))
        .. EXEC_REDEEM
      local ins = {}
      for i = 1, N_EXEC do
        ins[i] = types.txin(types.outpoint(exec_txids[i], 0), push, 0xFFFFFFFF)
      end
      txs[2] = types.transaction(2, ins,
        {types.txout(subsidy(2) * N_EXEC - 10000, SPK)}, 0)
    end
    local wtxids, txids = {types.hash256_zero()}, {}
    for i, t in ipairs(txs) do
      wtxids[i + 1] = validation.compute_wtxid(t)
      txids[i + 1] = validation.compute_txid(t)
    end
    local witness_root = crypto.compute_merkle_root(wtxids)
    local commitment = crypto.hash256(witness_root.bytes .. string.rep("\0", 32))
    local cb = mining.create_coinbase_tx(height, subsidy(height),
      "/p2sh4d/", commitment, SPK)
    txids[1] = validation.compute_txid(cb)
    local root = crypto.compute_merkle_root(txids)
    local header = types.block_header(0x20000000, prev_hash, root,
      T0 + height + 1, BITS, 0)
    local all = {cb}
    for i, t in ipairs(txs) do all[i + 1] = t end
    local block = types.block(header, all)
    assert(mining.mine_block(block, 0x7FFFFFFF), "could not mine regtest block")
    return block, validation.compute_block_hash(block.header)
  end

  local function submit(block)
    return r.methods["submitblock"](r, {hex(serialize.serialize_block(block))})
  end

  before_each(function()
    path = (os.getenv("TMPDIR") or "/tmp") .. "/lunarblock_r3fix_pushonly_"
      .. os.time() .. "_" .. math.random(1e9)
    db = storage_mod.open(path)
    cs = utxo.new_chain_state(db, REGTEST)
    cs:init()
    hashes, exec_txids = {}, {}
    local prev = types.hash256_zero()
    for h = 0, PREFIX do
      local spk = nil
      if h == 1 then spk = P2SH_SPK elseif h >= 2 and h <= 1 + N_EXEC then spk = P2SH_EXEC end
      local block, bh, cbid = simple_block(h, prev, spk)
      if h == 1 then funding_txid = cbid end
      if h >= 2 and h <= 1 + N_EXEC then exec_txids[h - 1] = cbid end
      db.put_header(bh, block.header)
      db.put_block(bh, block)
      db.put_height_index(h, bh)
      local ok, err = cs:connect_block(block, h, bh, nil, nil, true)
      assert(ok, "prefix connect h=" .. h .. ": " .. tostring(err))
      hashes[h] = bh
      prev = bh
    end
    r = rpc_mod.new({ rpcport = 0, network = REGTEST })
    r.chain_state = cs
    r.storage = db
  end)

  after_each(function()
    fault._reset_for_tests()
    pcall(db.close)
    os.execute("rm -rf '" .. path .. "'")
  end)

  -- connect_block reports a rule failure either by raising it or by
  -- returning (nil, err); accept_block / the sync callback classify either
  -- the same way.  What must hold is that the failure is a VERDICT.
  it("connect_block fails with a classified consensus verdict", function()
    local h = PREFIX + 1
    local bad, bad_h = spend_block(h, hashes[PREFIX], "\x4d")
    local ok, res, err = pcall(cs.connect_block, cs, bad, h, bad_h)
    local failure = ok and err or res
    assert.is_false(ok and res == true, "block connected")
    assert.is_truthy(failure)
    assert.equal("consensus", sync.classify_callback_error(failure), tostring(failure))
    assert.is_true(sync.is_invalid_block_verdict(failure), tostring(failure))
  end)

  it("submitblock rejects it and marks the block failed", function()
    local bad, bad_h = spend_block(PREFIX + 1, hashes[PREFIX], "\x4d")
    local res = submit(bad)
    assert.is_true(type(res) == "string", "submitblock result: " .. tostring(res))
    assert.equal(types.hash256_hex(hashes[PREFIX]), types.hash256_hex(cs.tip_hash))
    assert.is_true(cs:is_block_invalid(bad_h),
      "block not marked failed; submitblock said: " .. tostring(res))
  end)

  -- Control (valid block stays valid): the same spend with a well-formed
  -- P2SH scriptSig (push of the OP_TRUE redeem script) connects.
  it("control: the same spend with scriptSig <OP_TRUE redeem> connects", function()
    local good, good_h = spend_block(PREFIX + 1, hashes[PREFIX],
      string.char(#REDEEM) .. REDEEM)
    assert.equal(cjson.null, submit(good))
    assert.equal(types.hash256_hex(good_h), types.hash256_hex(cs.tip_hash))
    assert.is_false(cs:is_block_invalid(good_h))
  end)

  -- Consensus ordering (Core ConnectBlock): the truncated P2SH input counts
  -- 0 sigops (GetSigOpCount(scriptSig) returns 0 when GetOp fails), so the
  -- per-tx sigop total reaches the heavy tx and fails bad-blk-sigops before
  -- the deferred script checks report the 4d input.  Master raised at the
  -- 4d input's sigop count instead (submitblock: block-script-verify-flag-
  -- failed; Core v31.1 answers bad-blk-sigops).
  it("a heavy P2SH-sigop tx after it still fails bad-blk-sigops, like Core", function()
    local h = PREFIX + 1
    local bad, bad_h = spend_block(h, hashes[PREFIX], "\x4d", true)
    assert.equal("bad-blk-sigops", submit(bad))
    assert.is_true(cs:is_block_invalid(bad_h))
  end)

  -- Control: with a well-formed P2SH scriptSig the same block fails the same
  -- way (P2SH sigop counting itself is unchanged).
  it("control: the heavy tx after a valid P2SH spend fails bad-blk-sigops", function()
    local bad, bad_h = spend_block(PREFIX + 1, hashes[PREFIX],
      string.char(#REDEEM) .. REDEEM, true)
    assert.equal("bad-blk-sigops", submit(bad))
    assert.is_true(cs:is_block_invalid(bad_h))
  end)
end)
