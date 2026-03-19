local types = require("lunarblock.types")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local serialize = require("lunarblock.serialize")
local crypto = require("lunarblock.crypto")
local validation = require("lunarblock.validation")
local storage_mod = require("lunarblock.storage")
local script = require("lunarblock.script")

describe("assumeutxo", function()

  describe("snapshot metadata serialization", function()
    it("creates snapshot metadata with correct fields", function()
      local network_magic = "\xf9\xbe\xb4\xd9"
      local base_hash = types.hash256(string.rep("\xab", 32))
      local metadata = utxo.snapshot_metadata(network_magic, base_hash, 123456)

      assert.equal(utxo.SNAPSHOT_MAGIC, metadata.magic)
      assert.equal(utxo.SNAPSHOT_VERSION, metadata.version)
      assert.equal(network_magic, metadata.network_magic)
      assert.equal(base_hash.bytes, metadata.base_blockhash.bytes)
      assert.equal(123456, metadata.coins_count)
    end)

    it("round-trips snapshot metadata", function()
      local network_magic = "\xf9\xbe\xb4\xd9"
      local base_hash = types.hash256(string.rep("\xcd", 32))
      local original = utxo.snapshot_metadata(network_magic, base_hash, 9876543210)

      local serialized = utxo.serialize_snapshot_metadata(original)
      assert.equal(51, #serialized)  -- 5 + 2 + 4 + 32 + 8 = 51 bytes

      local deserialized, err = utxo.deserialize_snapshot_metadata(serialized)
      assert.is_nil(err)
      assert.is_not_nil(deserialized)

      assert.equal(original.magic, deserialized.magic)
      assert.equal(original.version, deserialized.version)
      assert.equal(original.network_magic, deserialized.network_magic)
      assert.equal(original.base_blockhash.bytes, deserialized.base_blockhash.bytes)
      assert.equal(original.coins_count, deserialized.coins_count)
    end)

    it("validates magic bytes on deserialization", function()
      local bad_data = "xxxxx" .. string.rep("\x00", 46)  -- 51 bytes with wrong magic
      local result, err = utxo.deserialize_snapshot_metadata(bad_data)

      assert.is_nil(result)
      assert.matches("invalid snapshot magic", err)
    end)

    it("rejects too-short metadata", function()
      local result, err = utxo.deserialize_snapshot_metadata("short")

      assert.is_nil(result)
      assert.matches("too short", err)
    end)

    it("rejects unsupported version", function()
      -- Create valid magic but with version = 255
      local w = serialize.buffer_writer()
      w.write_bytes(utxo.SNAPSHOT_MAGIC)
      w.write_u16le(255)  -- unsupported version
      w.write_bytes(string.rep("\x00", 44))  -- padding to 51 bytes
      local bad_data = w.result()

      local result, err = utxo.deserialize_snapshot_metadata(bad_data)

      assert.is_nil(result)
      assert.matches("unsupported snapshot version", err)
    end)
  end)

  describe("snapshot coin serialization", function()
    it("serializes and deserializes snapshot coin round-trip", function()
      local original = utxo.utxo_entry(5000000000, "\x76\xa9\x14" .. string.rep("\xab", 20) .. "\x88\xac", 100, true)
      local serialized = utxo.serialize_snapshot_coin(original)
      local reader = serialize.buffer_reader(serialized)
      local deserialized = utxo.deserialize_snapshot_coin(reader)

      assert.equal(original.value, deserialized.value)
      assert.equal(original.script_pubkey, deserialized.script_pubkey)
      assert.equal(original.height, deserialized.height)
      assert.equal(original.is_coinbase, deserialized.is_coinbase)
    end)

    it("handles non-coinbase coin", function()
      local original = utxo.utxo_entry(123456789, "\x00\x14" .. string.rep("\xcd", 20), 50000, false)
      local serialized = utxo.serialize_snapshot_coin(original)
      local reader = serialize.buffer_reader(serialized)
      local deserialized = utxo.deserialize_snapshot_coin(reader)

      assert.equal(original.value, deserialized.value)
      assert.equal(original.height, deserialized.height)
      assert.is_false(deserialized.is_coinbase)
    end)

    it("handles height 0 coinbase", function()
      local original = utxo.utxo_entry(5000000000, "script", 0, true)
      local serialized = utxo.serialize_snapshot_coin(original)
      local reader = serialize.buffer_reader(serialized)
      local deserialized = utxo.deserialize_snapshot_coin(reader)

      assert.equal(0, deserialized.height)
      assert.is_true(deserialized.is_coinbase)
    end)

    it("handles empty script", function()
      local original = utxo.utxo_entry(1000, "", 100, false)
      local serialized = utxo.serialize_snapshot_coin(original)
      local reader = serialize.buffer_reader(serialized)
      local deserialized = utxo.deserialize_snapshot_coin(reader)

      assert.equal("", deserialized.script_pubkey)
    end)
  end)

  describe("consensus assumeutxo helpers", function()
    it("returns nil for non-existent height", function()
      local result = consensus.assumeutxo_for_height(consensus.networks.mainnet, 999999)
      assert.is_nil(result)
    end)

    it("returns data for configured height", function()
      local result = consensus.assumeutxo_for_height(consensus.networks.mainnet, 840000)
      assert.is_not_nil(result)
      assert.is_not_nil(result.hash_serialized)
      assert.is_not_nil(result.m_chain_tx_count)
      assert.is_not_nil(result.blockhash)
    end)

    it("checks if height has assumeutxo", function()
      assert.is_true(consensus.has_assumeutxo(consensus.networks.mainnet, 840000))
      assert.is_false(consensus.has_assumeutxo(consensus.networks.mainnet, 123))
    end)

    it("returns empty list for networks without assumeutxo", function()
      local heights = consensus.get_assumeutxo_heights(consensus.networks.testnet)
      assert.equal(0, #heights)
    end)

    it("returns assumeutxo heights sorted", function()
      local heights = consensus.get_assumeutxo_heights(consensus.networks.mainnet)
      assert.is_true(#heights > 0)

      -- Verify sorted
      for i = 2, #heights do
        assert.is_true(heights[i] > heights[i-1])
      end
    end)

    it("finds assumeutxo by blockhash", function()
      local network = consensus.networks.mainnet
      local expected_blockhash = network.assumeutxo[840000].blockhash

      local data, height = consensus.assumeutxo_for_blockhash(network, expected_blockhash)
      assert.is_not_nil(data)
      assert.equal(840000, height)
    end)

    it("returns nil for unknown blockhash", function()
      local data = consensus.assumeutxo_for_blockhash(consensus.networks.mainnet, "0000000000000000000000000000000000000000000000000000000000000000")
      assert.is_nil(data)
    end)
  end)

  describe("streaming sha256", function()
    it("produces same result as single-shot sha256", function()
      local data = "The quick brown fox jumps over the lazy dog"
      local expected = crypto.sha256(data)

      local hasher = crypto.sha256_init()
      hasher.update(data)
      local result = hasher.final()

      assert.equal(expected, result)
    end)

    it("handles incremental updates", function()
      local data1 = "Hello, "
      local data2 = "world!"
      local expected = crypto.sha256(data1 .. data2)

      local hasher = crypto.sha256_init()
      hasher.update(data1)
      hasher.update(data2)
      local result = hasher.final()

      assert.equal(expected, result)
    end)

    it("handles many small updates", function()
      local data = "abcdefghijklmnopqrstuvwxyz"
      local expected = crypto.sha256(data)

      local hasher = crypto.sha256_init()
      for i = 1, #data do
        hasher.update(data:sub(i, i))
      end
      local result = hasher.final()

      assert.equal(expected, result)
    end)

    it("handles empty data", function()
      local expected = crypto.sha256("")

      local hasher = crypto.sha256_init()
      local result = hasher.final()

      assert.equal(expected, result)
    end)
  end)

  describe("snapshot chainstate", function()
    local db
    local tmp_path

    setup(function()
      tmp_path = "/tmp/lunarblock_snapshot_test_" .. os.time()
    end)

    before_each(function()
      db = storage_mod.open(tmp_path .. "_" .. math.random(1000000))
    end)

    after_each(function()
      if db then
        db.close()
      end
    end)

    it("creates snapshot chainstate", function()
      local snapshot_hash = types.hash256(string.rep("\xaa", 32))
      local snapshot_cs = utxo.new_snapshot_chainstate(db, consensus.networks.regtest, 100, snapshot_hash)

      assert.is_not_nil(snapshot_cs)
      assert.is_true(snapshot_cs.is_snapshot)
      assert.equal(100, snapshot_cs.snapshot_height)
      assert.equal(snapshot_hash.bytes, snapshot_cs.snapshot_hash.bytes)
      assert.is_false(snapshot_cs:is_validated())
    end)

    it("marks snapshot as validated", function()
      local snapshot_hash = types.hash256(string.rep("\xbb", 32))
      local snapshot_cs = utxo.new_snapshot_chainstate(db, consensus.networks.regtest, 200, snapshot_hash)

      assert.is_false(snapshot_cs:is_validated())
      snapshot_cs:set_validated()
      assert.is_true(snapshot_cs:is_validated())
    end)

    it("provides access to underlying chain state", function()
      local snapshot_hash = types.hash256(string.rep("\xcc", 32))
      local snapshot_cs = utxo.new_snapshot_chainstate(db, consensus.networks.regtest, 300, snapshot_hash)

      local cs = snapshot_cs:get_chain_state()
      assert.is_not_nil(cs)
      assert.is_not_nil(cs.coin_view)
    end)
  end)

  describe("loadtxoutset workflow", function()
    local db
    local chain_state
    local tmp_path
    local snapshot_file

    setup(function()
      tmp_path = "/tmp/lunarblock_loadtxoutset_test_" .. os.time()
      snapshot_file = tmp_path .. "_snapshot.dat"
    end)

    before_each(function()
      db = storage_mod.open(tmp_path .. "_" .. math.random(1000000))
      chain_state = utxo.new_chain_state(db, consensus.networks.regtest)
      chain_state:init()
    end)

    after_each(function()
      if db then
        db.close()
      end
      os.remove(snapshot_file)
    end)

    -- Helper to create a simple coinbase transaction
    local function make_coinbase_tx(height, value, script_pubkey)
      local coinbase_sig = string.char(1, height % 256)
      return types.transaction(
        1,
        {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), coinbase_sig, 0xFFFFFFFF)},
        {types.txout(value, script_pubkey)},
        0
      )
    end

    -- Helper to create a simple block
    local function make_block(height, transactions)
      local header = types.block_header(
        1,
        types.hash256_zero(),
        types.hash256_zero(),
        os.time() + height,
        consensus.networks.regtest.pow_limit_bits,
        0
      )
      return types.block(header, transactions)
    end

    it("dumps and loads empty snapshot", function()
      -- Set a dummy tip
      chain_state.tip_hash = types.hash256(string.rep("\x01", 32))
      chain_state.tip_height = 0

      -- Dump snapshot (empty UTXO set)
      local result, err = chain_state:dump_snapshot(snapshot_file)
      assert.is_nil(err)
      assert.is_not_nil(result)
      assert.equal(0, result.coins_count)

      -- Create fresh chainstate and load
      local db2 = storage_mod.open(tmp_path .. "_load_" .. math.random(1000000))
      local chain_state2 = utxo.new_chain_state(db2, consensus.networks.regtest)
      chain_state2:init()

      local ok, load_err = chain_state2:load_snapshot(snapshot_file)
      db2.close()

      assert.is_true(ok)
      assert.is_nil(load_err)
    end)

    it("dumps snapshot with UTXOs and computes hash", function()
      -- Add some blocks to create UTXOs
      local pubkey_hash = string.rep("\x42", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      for h = 0, 2 do
        local coinbase = make_coinbase_tx(h, 5000000000, script_pubkey)
        local block = make_block(h, {coinbase})
        local block_hash = validation.compute_block_hash(block.header)
        chain_state:connect_block(block, h, block_hash)
      end

      -- Dump snapshot
      local result, err = chain_state:dump_snapshot(snapshot_file)

      assert.is_nil(err)
      assert.is_not_nil(result)
      assert.equal(3, result.coins_count)
      assert.equal(32, #result.hash)  -- SHA256 hash is 32 bytes
      assert.equal(2, result.base_height)
    end)

    it("computes deterministic UTXO hash", function()
      -- Add blocks
      local pubkey_hash = string.rep("\x55", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      for h = 0, 1 do
        local coinbase = make_coinbase_tx(h, 5000000000, script_pubkey)
        local block = make_block(h, {coinbase})
        local block_hash = validation.compute_block_hash(block.header)
        chain_state:connect_block(block, h, block_hash)
      end

      -- Compute hash twice
      local hash1, count1 = chain_state:compute_utxo_hash()
      local hash2, count2 = chain_state:compute_utxo_hash()

      assert.equal(hash1, hash2)
      assert.equal(count1, count2)
      assert.equal(2, count1)
    end)

    it("rejects snapshot with wrong network magic", function()
      -- Set a tip
      chain_state.tip_hash = types.hash256(string.rep("\x01", 32))
      chain_state.tip_height = 0

      -- Dump with regtest network
      chain_state:dump_snapshot(snapshot_file)

      -- Try to load with mainnet network
      local db2 = storage_mod.open(tmp_path .. "_mainnet_" .. math.random(1000000))
      local mainnet_cs = utxo.new_chain_state(db2, consensus.networks.mainnet)
      mainnet_cs:init()

      local ok, err = mainnet_cs:load_snapshot(snapshot_file)
      db2.close()

      assert.is_false(ok)
      assert.matches("network magic mismatch", err)
    end)
  end)

  describe("background validator", function()
    local db

    setup(function()
      -- Background validator needs a storage handle
    end)

    before_each(function()
      local tmp_path = "/tmp/lunarblock_bg_validator_" .. os.time() .. "_" .. math.random(1000000)
      db = storage_mod.open(tmp_path)
    end)

    after_each(function()
      if db then
        db.close()
      end
    end)

    it("creates background validator", function()
      local target_hash = string.rep("\xaa", 32)
      local validator = utxo.new_background_validator(
        db,
        consensus.networks.regtest,
        100,  -- target height
        target_hash,
        function(h) return nil end  -- get_block stub
      )

      assert.is_not_nil(validator)
      assert.equal(100, validator.target_height)
      assert.equal(0, validator.current_height)
      assert.is_false(validator:is_complete())
    end)

    it("reports progress correctly", function()
      local validator = utxo.new_background_validator(
        db,
        consensus.networks.regtest,
        100,
        string.rep("\xbb", 32),
        function(h) return nil end
      )

      assert.equal(0, validator:progress())

      -- Simulate some progress
      validator.current_height = 50
      assert.equal(50, validator:progress())

      validator.current_height = 100
      assert.equal(100, validator:progress())
    end)

    it("handles empty chain (no blocks)", function()
      local validator = utxo.new_background_validator(
        db,
        consensus.networks.regtest,
        10,
        string.rep("\xcc", 32),
        function(h)
          -- Return nil to simulate missing block
          return nil
        end
      )

      local height, target, complete, err = validator:step()

      assert.equal(0, height)
      assert.equal(10, target)
      assert.is_false(complete)
      assert.is_not_nil(err)
      assert.matches("failed to get block", err)
    end)
  end)

end)
