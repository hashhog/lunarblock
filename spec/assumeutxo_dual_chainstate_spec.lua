-- spec/assumeutxo_dual_chainstate_spec.lua
--
-- AssumeUTXO REAL dual-chainstate background validation.
--
-- This is the functional gate for the dual-chainstate pilot: it proves that
-- loadtxoutset spins up a SECOND (background) chainstate with its OWN separate
-- UTXO store, that the background chainstate REALLY re-connects every block
-- genesis -> base into that store (not a counter), that a correct-hash snapshot
-- is ACCEPTED (validated flips true), and — most importantly — that a
-- deliberately-WRONG assumed hash is REJECTED (the falsification).
--
-- Core reference: bitcoin-core/src/validation.cpp.
--   ActivateSnapshot (5588): snapshot loaded into the active chainstate.
--   AddChainstate (6170): genesis-validated chainstate demoted to a BACKGROUND
--     chainstate (m_target_blockhash = snapshot base), keeping its own coins DB.
--   MaybeValidateSnapshot (5967): at the base, compute the bg coins'
--     HASH_SERIALIZED and compare to au_data.hash_serialized. MATCH -> VALIDATED
--     + retire bg; MISMATCH -> INVALID + AbortNode.

local types      = require("lunarblock.types")
local utxo       = require("lunarblock.utxo")
local consensus  = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local storage_mod = require("lunarblock.storage")
local script     = require("lunarblock.script")
local rpc        = require("lunarblock.rpc")
local cjson      = require("cjson")

-- Seed the RNG with per-process entropy (os.time is only 1s-granular and LuaJIT
-- math.random is deterministic without a seed, so the os.time()+math.random()
-- temp-path suffixes below would repeat across runs and reuse leftover/locked
-- /tmp DB state — which could spuriously false-green the wrong-hash falsification
-- when this spec is run alongside the other AssumeUTXO specs). The table address
-- gives a value unique to this process invocation.
math.randomseed(os.time() + ((tonumber(tostring({}):match("0x(%x+)") or "0", 16) or 0) % 1000000))

-- ── helpers ──────────────────────────────────────────────────────────────────

local function make_coinbase_tx(height, value, script_pubkey)
  -- BIP34: regtest activates BIP34 at height 1, so the coinbase scriptSig must
  -- begin with the serialized height.  Encode height as a minimal push so the
  -- block connects under the active chain's BIP34 enforcement.
  local sig
  if height < 128 then
    sig = string.char(1, height)
  else
    sig = string.char(2, height % 256, math.floor(height / 256) % 256)
  end
  -- Append a per-height tag so coinbase txids are unique across blocks (BIP30).
  sig = sig .. string.char(0x4b, height % 256)
  return types.transaction(
    1,
    {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), sig, 0xFFFFFFFF)},
    {types.txout(value, script_pubkey)},
    0
  )
end

local function make_block(height, transactions, prev_hash)
  local header = types.block_header(
    1,
    prev_hash,
    types.hash256_zero(),
    os.time() + height,
    consensus.networks.regtest.pow_limit_bits,
    0
  )
  return types.block(header, transactions)
end

-- Build an active chainstate rooted at the REAL regtest genesis, then connect
-- `n` real coinbase blocks (heights 1..n) on top.  Returns (db, chain_state,
-- base_height, blocks_by_height) where blocks_by_height[h] = {block, hash}.
local function build_active_chain(n)
  local tmp = "/tmp/lb_dualcs_active_" .. os.time() .. "_" .. math.random(1000000)
  local db = storage_mod.open(tmp)
  local cs = utxo.new_chain_state(db, consensus.networks.regtest)
  cs:init()  -- connects the REAL regtest genesis at height 0

  local script_pubkey = script.make_p2pkh_script(string.rep("\x42", 20))
  local blocks = {}
  local prev = cs.tip_hash  -- real regtest genesis hash

  for h = 1, n do
    local cb = make_coinbase_tx(h, 5000000000, script_pubkey)
    local b  = make_block(h, {cb}, prev)
    local bh = validation.compute_block_hash(b.header)
    local ok, err = cs:connect_block(b, h, bh)
    assert(ok, "active connect_block failed at height " .. h .. ": " .. tostring(err))
    -- Store the block + height index so the background pass can read it back.
    db.put_block(bh, b)
    db.put_header(bh, b.header)
    db.put_height_index(h, bh)
    blocks[h] = { block = b, hash = bh }
    prev = bh
  end

  return db, cs, n, blocks
end

describe("AssumeUTXO dual-chainstate background validation", function()

  it("separate UTXO store: bg chainstate does NOT alias the active store", function()
    local db, cs = build_active_chain(3)

    local bg = utxo.new_background_validator(
      nil, consensus.networks.regtest, 3, string.rep("\x00", 32),
      function() return nil end)

    -- (a) The background chainstate's coins store is a DIFFERENT object from
    --     the active chainstate's store (proven by identity / aliasing).
    assert.is_not_equal(cs.storage, bg.storage,
      "bg storage must be a distinct object from the active store")
    assert.is_not_equal(cs.coin_view, bg.chain_state.coin_view,
      "bg coin_view must be a distinct object from the active coin_view")
    assert.is_true(bg.storage._memory,
      "bg coins store should be the in-memory backend by default")

    -- Aliasing falsification: writing to the active store must NOT appear in
    -- the bg store, and vice-versa.
    local probe_key = string.rep("\x77", 36)
    cs.storage.put(storage_mod.CF.UTXO, probe_key, "active-only")
    assert.is_nil(bg.storage.get(storage_mod.CF.UTXO, probe_key),
      "active-store write must not be visible in the separate bg store")

    bg:retire()
    db.close()
  end)

  it("bg chainstate REALLY connects genesis->base into its own store", function()
    local db, cs, base, blocks = build_active_chain(4)

    -- Independently-computed expected UTXO set at the base: the active chain's
    -- own coins (it connected the same blocks).  This is the ground truth the
    -- bg replay must reproduce — NOT empty, NOT a counter.
    local active_hash = cs:compute_utxo_hash()

    local bg = utxo.new_background_validator(
      nil, consensus.networks.regtest, base, active_hash,
      function(h)
        if blocks[h] then return blocks[h].block, blocks[h].hash end
        return nil
      end)

    local validated, err = bg:run_to_completion()
    assert.is_true(validated, "bg replay should match the active chain: " .. tostring(err))
    assert.equal(base, bg.current_height,
      "bg must have connected every block to the base height")

    db.close()
  end)

  it("ACCEPT: correct assumed hash flips the snapshot to validated", function()
    local db, cs, base, blocks = build_active_chain(4)

    -- Dump a snapshot at the base with the CORRECT serialized hash.
    local dump_path = "/tmp/lb_dualcs_accept_" .. os.time() .. "_" .. math.random(1000000) .. ".dat"
    local dump = cs:dump_snapshot(dump_path)
    assert.is_not_nil(dump)
    -- chainparams stores hash_serialized in display (big-endian) order.
    local correct_hash_hex = types.hash256_hex(types.hash256(dump.hash))

    -- Fresh ACTIVE chainstate to load the snapshot into (the snapshot becomes
    -- the active chainstate; its coins come from the file, not a replay).
    local load_db = storage_mod.open("/tmp/lb_dualcs_accept_load_"
      .. os.time() .. "_" .. math.random(1000000))
    local active = utxo.new_chain_state(load_db, consensus.networks.regtest)
    active:init()
    -- Mirror the block store so the bg pass can read genesis..base.
    for h = 1, base do
      load_db.put_block(blocks[h].hash, blocks[h].block)
      load_db.put_header(blocks[h].hash, blocks[h].block.header)
      load_db.put_height_index(h, blocks[h].hash)
    end

    local au_data = { hash_serialized = correct_hash_hex,
                      m_chain_tx_count = base + 1,
                      blockhash = types.hash256_hex(cs.tip_hash) }

    local activation, aerr = utxo.activate_snapshot_with_background(
      active, dump_path, au_data, base,
      function(h)
        local bh = load_db.get_hash_by_height(h)
        if not bh then return nil end
        return load_db.get_block(bh), bh
      end)
    assert.is_not_nil(activation, "activation failed: " .. tostring(aerr))

    -- While running (before drive), the snapshot is UNVALIDATED.
    assert.is_false(activation.snapshot:is_validated(),
      "snapshot must start UNVALIDATED (validated=false)")

    local validated, err = activation.background:run_to_completion()
    assert.is_true(validated, "background validation should accept: " .. tostring(err))
    assert.is_true(activation.snapshot:is_validated(),
      "snapshot must flip to VALIDATED after a correct-hash match")
    assert.is_false(activation.snapshot:is_invalid())

    load_db.close()
    db.close()
    os.remove(dump_path)
  end)

  it("REJECT (falsification): a wrong assumed hash marks the snapshot invalid", function()
    local db, cs, base, blocks = build_active_chain(4)

    local dump_path = "/tmp/lb_dualcs_reject_" .. os.time() .. "_" .. math.random(1000000) .. ".dat"
    local dump = cs:dump_snapshot(dump_path)
    assert.is_not_nil(dump)

    -- DELIBERATELY WRONG assumed hash (all 0xEE) — the snapshot bytes are real,
    -- but the assumeutxo commitment is corrupt.  The background re-derivation
    -- must NOT silently pass.
    local wrong_hash_hex = string.rep("ee", 32)

    local load_db = storage_mod.open("/tmp/lb_dualcs_reject_load_"
      .. os.time() .. "_" .. math.random(1000000))
    local active = utxo.new_chain_state(load_db, consensus.networks.regtest)
    active:init()
    for h = 1, base do
      load_db.put_block(blocks[h].hash, blocks[h].block)
      load_db.put_header(blocks[h].hash, blocks[h].block.header)
      load_db.put_height_index(h, blocks[h].hash)
    end

    local au_data = { hash_serialized = wrong_hash_hex,
                      m_chain_tx_count = base + 1,
                      blockhash = types.hash256_hex(cs.tip_hash) }

    local activation, aerr = utxo.activate_snapshot_with_background(
      active, dump_path, au_data, base,
      function(h)
        local bh = load_db.get_hash_by_height(h)
        if not bh then return nil end
        return load_db.get_block(bh), bh
      end)
    assert.is_not_nil(activation, "activation failed: " .. tostring(aerr))

    local validated, err = activation.background:run_to_completion()
    -- The background pass connected every block (REAL work) and then caught the
    -- mismatch — it is NOT validated and surfaced a hard error/abort condition.
    assert.is_false(validated, "wrong-hash snapshot must NOT validate")
    assert.is_not_nil(err, "a wrong-hash mismatch must surface an error")
    assert.matches("mismatch", err)
    -- Snapshot chainstate is marked INVALID (Core handle_invalid_snapshot).
    assert.is_true(activation.snapshot:is_invalid(),
      "snapshot must be marked INVALID on a hash mismatch")
    assert.is_false(activation.snapshot:is_validated())

    load_db.close()
    db.close()
    os.remove(dump_path)
  end)

  it("end-to-end via loadtxoutset RPC: validated reflected in result + getchainstates", function()
    local db, cs, base, blocks = build_active_chain(3)

    local dump_path = "/tmp/lb_dualcs_rpc_dump_" .. os.time() .. "_" .. math.random(1000000) .. ".dat"
    local dump = cs:dump_snapshot(dump_path)
    local correct_hash_hex = types.hash256_hex(types.hash256(dump.hash))

    -- Fresh node-shaped chainstate with the same blocks in its store.
    local node_db = storage_mod.open("/tmp/lb_dualcs_rpc_node_"
      .. os.time() .. "_" .. math.random(1000000))
    local node_cs = utxo.new_chain_state(node_db, consensus.networks.regtest)
    node_cs:init()
    for h = 1, base do
      node_db.put_block(blocks[h].hash, blocks[h].block)
      node_db.put_header(blocks[h].hash, blocks[h].block.header)
      node_db.put_height_index(h, blocks[h].hash)
    end

    local net = {}
    for k, v in pairs(consensus.networks.regtest) do net[k] = v end
    net.assumeutxo = {
      [base] = { hash_serialized = correct_hash_hex,
                 m_chain_tx_count = base + 1,
                 blockhash = types.hash256_hex(cs.tip_hash) },
    }

    local snap = "/tmp/lb_dualcs_rpc_" .. os.time() .. "_" .. math.random(1000000) .. ".dat"
    cs:dump_snapshot(snap)

    local server = rpc.new({ chain_state = node_cs, storage = node_db, network = net })

    -- getchainstates BEFORE the snapshot: single validated chainstate.
    local pre_raw, pre_err = server:handle_request(
      '{"method":"getchainstates","params":[],"id":1}')
    assert.is_not_nil(pre_raw, "getchainstates returned nil; err=" .. tostring(pre_err))
    local pre = cjson.decode(pre_raw)
    assert.is_true(pre.result.chainstates[1].validated)
    assert.is_nil(pre.result.chainstates[1].snapshot_blockhash)

    local lt_raw, lt_err = server:handle_request(
      '{"method":"loadtxoutset","params":["' .. snap .. '"],"id":2}')
    assert.is_not_nil(lt_raw, "loadtxoutset returned nil; err=" .. tostring(lt_err))
    local resp = cjson.decode(lt_raw)
    assert.is_true(resp.error == nil or resp.error == cjson.null,
      "loadtxoutset should succeed: " .. cjson.encode(resp.error or {}))
    assert.is_true(resp.result.validated,
      "loadtxoutset result.validated must be true after a correct-hash match")

    -- getchainstates AFTER: snapshot chainstate present + validated=true.
    local post_raw, post_err = server:handle_request(
      '{"method":"getchainstates","params":[],"id":3}')
    assert.is_not_nil(post_raw, "post getchainstates returned nil; err=" .. tostring(post_err))
    local post = cjson.decode(post_raw)
    local entry = post.result.chainstates[#post.result.chainstates]
    assert.is_not_nil(entry.snapshot_blockhash,
      "active chainstate must report snapshot_blockhash after loadtxoutset")
    assert.is_true(entry.validated,
      "getchainstates must report validated=true after the bg pass matched")

    node_db.close()
    db.close()
    os.remove(snap)
    os.remove(dump_path)
  end)

end)
