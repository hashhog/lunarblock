-- spec/dumptxoutset_rollback_spec.lua
--
-- Verifies the rollback mode added to dumptxoutset.  Mirrors
-- bitcoin-core/src/rpc/blockchain.cpp dumptxoutset rollback semantics:
--
--   1. type="" or "latest" -> dump current tip (backwards compatible).
--   2. type="rollback" with no height -> roll back to the highest
--      assumeutxo entry <= current tip, dump there, re-apply.
--   3. options.rollback = <int|hex>: roll back to that target, dump,
--      re-apply.
--
-- Builds a synthetic regtest chain via connect_block (same pattern used
-- in spec/utxo_spec.lua and spec/rpc_spec.lua invalidateblock tests).

local rpc = require("lunarblock.rpc")
local types = require("lunarblock.types")
local consensus = require("lunarblock.consensus")
local utxo = require("lunarblock.utxo")
local validation = require("lunarblock.validation")
local script = require("lunarblock.script")
local storage_mod = require("lunarblock.storage")
local cjson = require("cjson")

-- Helpers (lifted from spec/utxo_spec.lua's disconnect_block tests so this
-- file is self-contained).
local function make_coinbase_tx(height, value, script_pubkey)
  local coinbase_sig = string.char(1, height % 256)
  return types.transaction(
    1,
    {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                coinbase_sig, 0xFFFFFFFF)},
    {types.txout(value, script_pubkey)},
    0
  )
end

local function make_block(height, transactions, prev_hash)
  local header = types.block_header(
    1,
    prev_hash or types.hash256_zero(),
    types.hash256_zero(),
    os.time() + height,
    consensus.networks.regtest.pow_limit_bits,
    0
  )
  return types.block(header, transactions)
end

-- Build a chain of N coinbase-only blocks on top of a fresh chainstate.
-- Returns (db, chain_state, block_hashes_by_height).
local function build_chain(n_blocks)
  local tmp_path = "/tmp/lunarblock_dumptxoutset_rollback_"
    .. os.time() .. "_" .. math.random(1000000)
  local db = storage_mod.open(tmp_path)
  local chain_state = utxo.new_chain_state(db, consensus.networks.regtest)
  chain_state:init()

  local pubkey_hash = string.rep("\x42", 20)
  local script_pubkey = script.make_p2pkh_script(pubkey_hash)

  local hashes = {}
  local prev_hash = types.hash256_zero()
  for h = 0, n_blocks - 1 do
    local coinbase = make_coinbase_tx(h, 5000000000, script_pubkey)
    local block = make_block(h, {coinbase}, prev_hash)
    local block_hash = validation.compute_block_hash(block.header)
    db.put_header(block_hash, block.header)
    db.put_block(block_hash, block)
    db.put_height_index(h, block_hash)
    chain_state:connect_block(block, h, block_hash)
    hashes[h] = block_hash
    prev_hash = block_hash
  end

  return db, chain_state, hashes
end

describe("dumptxoutset rollback mode", function()

  describe("ChainState:rollback_chain_to / reapply_disconnected", function()
    it("disconnects then re-applies leaving tip and UTXO count unchanged",
       function()
      local db, chain_state, hashes = build_chain(4)

      local original_tip = chain_state.tip_height
      local original_hash_hex = types.hash256_hex(chain_state.tip_hash)
      local original_count = chain_state:get_utxo_stats().utxo_count

      assert.equal(3, original_tip)

      -- Roll back from height 3 to height 1.
      local disconnected, err = chain_state:rollback_chain_to(1)
      assert.is_nil(err)
      assert.is_not_nil(disconnected)
      assert.equal(2, #disconnected)  -- heights 3 and 2 disconnected
      assert.equal(1, chain_state.tip_height)
      assert.equal(types.hash256_hex(hashes[1]),
                   types.hash256_hex(chain_state.tip_hash))

      -- Each disconnected entry carries its hash and height.
      assert.equal(3, disconnected[1].height)
      assert.equal(2, disconnected[2].height)
      assert.equal(types.hash256_hex(hashes[3]),
                   types.hash256_hex(disconnected[1].hash))

      -- Re-apply.
      local ok, rerr = chain_state:reapply_disconnected(disconnected)
      assert.is_nil(rerr)
      assert.is_true(ok)
      assert.equal(original_tip, chain_state.tip_height)
      assert.equal(original_hash_hex, types.hash256_hex(chain_state.tip_hash))

      -- UTXO count should match exactly.
      chain_state.coin_view:clear_cache()
      assert.equal(original_count, chain_state:get_utxo_stats().utxo_count)

      db.close()
    end)

    it("is a no-op when target_height equals current tip", function()
      local db, chain_state = build_chain(2)
      local before = chain_state.tip_height
      local list = chain_state:rollback_chain_to(before)
      assert.is_not_nil(list)
      assert.equal(0, #list)
      assert.equal(before, chain_state.tip_height)
      db.close()
    end)

    it("rejects target above current tip", function()
      local db, chain_state = build_chain(2)
      local list, err = chain_state:rollback_chain_to(99)
      assert.is_nil(list)
      assert.matches("above current tip", err)
      db.close()
    end)

    it("rejects negative target", function()
      local db, chain_state = build_chain(2)
      local list, err = chain_state:rollback_chain_to(-1)
      assert.is_nil(list)
      assert.matches("negative", err)
      db.close()
    end)
  end)

  describe("RPC dumptxoutset positional 'rollback' type", function()
    it("rejects rollback type on regtest (no assumeutxo entries)", function()
      local db, chain_state = build_chain(2)
      local server = rpc.new({
        chain_state = chain_state,
        storage = db,
        network = consensus.networks.regtest,
      })
      local snapshot_path = "/tmp/lunarblock_dump_rollback_regtest_"
        .. os.time() .. "_" .. math.random(1000000) .. ".dat"

      local request = '{"method":"dumptxoutset","params":["'
        .. snapshot_path .. '","rollback"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.MISC_ERROR, decoded.error.code)
      assert.matches("No assumeutxo snapshots configured",
        decoded.error.message)

      os.remove(snapshot_path)
      db.close()
    end)

    it("rejects unknown snapshot type", function()
      local db, chain_state = build_chain(1)
      local server = rpc.new({
        chain_state = chain_state,
        storage = db,
        network = consensus.networks.regtest,
      })
      local snapshot_path = "/tmp/lunarblock_dump_unknown_type_"
        .. os.time() .. "_" .. math.random(1000000) .. ".dat"

      local request = '{"method":"dumptxoutset","params":["'
        .. snapshot_path .. '","junkmode"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.INVALID_PARAMS, decoded.error.code)
      assert.matches("Invalid snapshot type", decoded.error.message)

      os.remove(snapshot_path)
      db.close()
    end)

    it("type=\"\" still works (latest mode, backwards compatible)", function()
      local db, chain_state = build_chain(2)
      local original_tip = chain_state.tip_height
      local server = rpc.new({
        chain_state = chain_state,
        storage = db,
        network = consensus.networks.regtest,
      })
      local snapshot_path = "/tmp/lunarblock_dump_latest_"
        .. os.time() .. "_" .. math.random(1000000) .. ".dat"

      -- No params[2] => default "latest" path.
      local request = '{"method":"dumptxoutset","params":["'
        .. snapshot_path .. '"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(cjson.null, decoded.error)
      assert.is_not_nil(decoded.result)
      assert.equal(original_tip, decoded.result.base_height)

      -- Tip is unchanged.
      assert.equal(original_tip, chain_state.tip_height)

      os.remove(snapshot_path)
      db.close()
    end)
  end)

  describe("RPC dumptxoutset options.rollback by height", function()
    it("rolls back, dumps at target, re-applies to original tip",
       function()
      local db, chain_state, hashes = build_chain(4)
      local original_tip = chain_state.tip_height
      local original_hash_hex = types.hash256_hex(chain_state.tip_hash)

      local server = rpc.new({
        chain_state = chain_state,
        storage = db,
        network = consensus.networks.regtest,
      })
      local snapshot_path = "/tmp/lunarblock_dump_rollback_h1_"
        .. os.time() .. "_" .. math.random(1000000) .. ".dat"

      -- options.rollback = 1 -> roll back to height 1.
      local request = '{"method":"dumptxoutset","params":["'
        .. snapshot_path .. '","",{"rollback":1}],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(cjson.null, decoded.error,
        "unexpected error: " .. cjson.encode(decoded.error or {}))
      assert.is_not_nil(decoded.result)

      -- Snapshot's base_height matches the rollback target.
      assert.equal(1, decoded.result.base_height)
      assert.equal(types.hash256_hex(hashes[1]), decoded.result.base_hash)

      -- Node was restored to original tip after dump.
      assert.equal(original_tip, chain_state.tip_height)
      assert.equal(original_hash_hex, types.hash256_hex(chain_state.tip_hash))

      os.remove(snapshot_path)
      db.close()
    end)

    it("rejects rollback type when type is set to something else",
       function()
      local db, chain_state = build_chain(2)
      local server = rpc.new({
        chain_state = chain_state,
        storage = db,
        network = consensus.networks.regtest,
      })
      local snapshot_path = "/tmp/lunarblock_dump_conflict_"
        .. os.time() .. "_" .. math.random(1000000) .. ".dat"

      -- type="latest" while options.rollback is set => conflict.
      local request = '{"method":"dumptxoutset","params":["'
        .. snapshot_path .. '","latest",{"rollback":0}],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.INVALID_PARAMS, decoded.error.code)
      assert.matches("with rollback option", decoded.error.message)

      os.remove(snapshot_path)
      db.close()
    end)

    it("rejects rollback target above current tip", function()
      local db, chain_state = build_chain(2)
      local server = rpc.new({
        chain_state = chain_state,
        storage = db,
        network = consensus.networks.regtest,
      })
      local snapshot_path = "/tmp/lunarblock_dump_above_tip_"
        .. os.time() .. "_" .. math.random(1000000) .. ".dat"

      local request = '{"method":"dumptxoutset","params":["'
        .. snapshot_path .. '","",{"rollback":99}],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.MISC_ERROR, decoded.error.code)

      os.remove(snapshot_path)
      db.close()
    end)

    it("rejects malformed hex hash", function()
      local db, chain_state = build_chain(2)
      local server = rpc.new({
        chain_state = chain_state,
        storage = db,
        network = consensus.networks.regtest,
      })
      local snapshot_path = "/tmp/lunarblock_dump_bad_hash_"
        .. os.time() .. "_" .. math.random(1000000) .. ".dat"

      -- 64-char string with non-hex content.
      local bad_hash = string.rep("zz", 32)
      local request = '{"method":"dumptxoutset","params":["'
        .. snapshot_path .. '","",{"rollback":"' .. bad_hash .. '"}],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.INVALID_PARAMS, decoded.error.code)

      os.remove(snapshot_path)
      db.close()
    end)
  end)
end)
