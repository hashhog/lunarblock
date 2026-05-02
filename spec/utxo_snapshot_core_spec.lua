-- spec/utxo_snapshot_core_spec.lua
--
-- Verifies that lunarblock's UTXO snapshot format is byte-compatible with
-- Bitcoin Core's dumptxoutset / loadtxoutset wire format
-- (bitcoin-core/src/rpc/blockchain.cpp WriteUTXOSnapshot, src/coins.h
-- Coin::Serialize, src/compressor.h ScriptCompression / AmountCompression).
--
-- Layered tests:
--   1. Core VARINT primitive (write_corevarint / read_corevarint).
--   2. CompressAmount / DecompressAmount: known vectors + round-trip.
--   3. ScriptCompression: raw branch + recognized-type loader.
--   4. serialize_snapshot_coin: byte parity vs hand-encoded reference.
--   5. dump_snapshot / load_snapshot round-trip on a populated chainstate.
--   6. Cross-impl spot check: a hand-built Core-format file decodes
--      cleanly through load_snapshot.

local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local serialize = require("lunarblock.serialize")
local types = require("lunarblock.types")
local storage_mod = require("lunarblock.storage")
local validation = require("lunarblock.validation")
local script_mod = require("lunarblock.script")

local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function unhex(h)
  return (h:gsub("%x%x", function(c) return string.char(tonumber(c, 16)) end))
end

local function corevarint_bytes(val)
  local w = serialize.buffer_writer()
  utxo.write_corevarint(w, val)
  return w.result()
end

local function corevarint_parse(bytes)
  local r = serialize.buffer_reader(bytes)
  return tonumber(utxo.read_corevarint(r))
end

describe("Core-format UTXO snapshot", function()

  describe("Core VARINT (MSB base-128)", function()
    -- Reference vectors derived by hand from
    -- bitcoin-core/src/serialize.h:WriteVarInt.  Hex strings are the on-wire
    -- bytes a Stream& would receive.
    local cases = {
      {0,        "00"},
      {1,        "01"},
      {127,      "7f"},
      {128,      "8000"},  -- after first 7 bits exhaust, n = (n>>7) - 1 = 0,
                           -- but we still write the carry byte as 0x80.
      {255,      "807f"},
      {256,      "8100"},
      {16383,    "fe7f"},
      {16384,    "ff00"},
    }

    it("matches Core reference bytes for known values", function()
      for _, c in ipairs(cases) do
        local v, expected = c[1], c[2]
        assert.equal(expected, hex(corevarint_bytes(v)),
          string.format("write_corevarint(%d) mismatch", v))
      end
    end)

    it("round-trips through read_corevarint", function()
      for _, c in ipairs(cases) do
        local v = c[1]
        assert.equal(v, corevarint_parse(corevarint_bytes(v)))
      end
    end)

    it("round-trips a wide value range", function()
      local samples = {0, 1, 7, 127, 128, 255, 1000, 65535, 65536,
                       1000000, 2 ^ 24, 2 ^ 30, 2 ^ 32 - 1}
      for _, v in ipairs(samples) do
        local enc = corevarint_bytes(v)
        local dec = corevarint_parse(enc)
        assert.equal(v, dec,
          string.format("round-trip failed for %d -> %s", v, hex(enc)))
      end
    end)
  end)

  describe("CompressAmount / DecompressAmount", function()
    -- Reference values computed against the compressor.cpp algorithm
    -- (verified independently in Python during development).
    local known = {
      {0,                0},
      {1,                1},
      {100,              3},
      {1000000,          7},
      {5000000000,       50},
      {2100000000000000, 21000000},  -- MAX_MONEY (21M BTC)
    }

    it("matches Bitcoin Core CompressAmount for known values", function()
      for _, c in ipairs(known) do
        local v, expected = c[1], c[2]
        assert.equal(expected, tonumber(utxo.compress_amount(v)),
          string.format("CompressAmount(%s) mismatch", tostring(v)))
      end
    end)

    it("decompress(compress(x)) == x for representative amounts", function()
      local samples = {0, 1, 9, 10, 100, 1000, 12345678, 50000000,
                       5000000000, 2100000000000000}
      for _, v in ipairs(samples) do
        local c = utxo.compress_amount(v)
        local d = utxo.decompress_amount(c)
        assert.equal(v, d,
          string.format("compress/decompress round-trip failed for %s",
            tostring(v)))
      end
    end)
  end)

  describe("ScriptCompression (raw branch)", function()
    it("emits VARINT(size+6) || raw bytes for non-recognized scripts", function()
      -- Use a P2WPKH (witness v0 keyhash) script: 0x00 0x14 <20 bytes>.
      -- Length 22, expected encoding: VARINT(22+6=28)=0x1c followed by raw.
      local witness_script = "\x00\x14" .. string.rep("\x77", 20)
      local enc = utxo.compress_script(witness_script)
      -- VARINT(28) is 0x1c (single byte since 28 < 128).
      assert.equal("1c" .. hex(witness_script), hex(enc))
    end)

    it("round-trips through decompress_script (raw branch)", function()
      local witness_script = "\x51\x21" .. string.rep("\xab", 33)  -- P2PK-ish
      local enc = utxo.compress_script(witness_script)
      local r = serialize.buffer_reader(enc)
      assert.equal(witness_script, utxo.decompress_script(r))
    end)

    it("decompress_script reads recognized P2PKH type byte", function()
      -- Hand-build the compressed form: type 0x00 (Core VARINT 0x00) +
      -- 20-byte hash160.  Loader must reconstruct OP_DUP OP_HASH160 ...
      local h160 = string.rep("\x12", 20)
      local enc = "\x00" .. h160
      local r = serialize.buffer_reader(enc)
      local script_pubkey = utxo.decompress_script(r)
      assert.equal("\x76\xa9\x14" .. h160 .. "\x88\xac", script_pubkey)
    end)

    it("decompress_script reads recognized P2SH type byte", function()
      local h160 = string.rep("\x34", 20)
      local enc = "\x01" .. h160
      local r = serialize.buffer_reader(enc)
      local script_pubkey = utxo.decompress_script(r)
      assert.equal("\xa9\x14" .. h160 .. "\x87", script_pubkey)
    end)

    it("decompress_script recovers uncompressed P2PK (tag 0x04, even Y)",
       function()
      -- Generator point G:
      --   compressed   = 02 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
      --   uncompressed = 04 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
      --                     483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
      -- Y is even, so the compressed prefix is 0x02 and the on-disk type
      -- byte is 0x04 (== 0x02 + 0x02).
      local x = unhex(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
      local enc = "\x04" .. x
      local r = serialize.buffer_reader(enc)
      local script_pubkey = utxo.decompress_script(r)
      local expected_pubkey = "\x04" .. x .. unhex(
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
      assert.equal(67, #script_pubkey)
      assert.equal(string.char(0x41) .. expected_pubkey .. "\xac",
        script_pubkey)
    end)

    it("decompress_script recovers uncompressed P2PK (tag 0x05, odd Y)",
       function()
      -- 2*G:
      --   compressed   = 03 c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
      -- Y is odd, so on-disk type byte is 0x05 (== 0x02 + 0x03).
      local x = unhex(
        "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
      local enc = "\x05" .. x
      local r = serialize.buffer_reader(enc)
      local script_pubkey = utxo.decompress_script(r)
      assert.equal(67, #script_pubkey)
      assert.equal(0x41, script_pubkey:byte(1))
      assert.equal(0x04, script_pubkey:byte(2))           -- uncompressed prefix
      assert.equal(x, script_pubkey:sub(3, 34))           -- x-coord matches
      assert.equal(0xac, script_pubkey:byte(67))          -- OP_CHECKSIG
      -- Y must be odd to match the input tag.
      assert.equal(1, script_pubkey:byte(66) % 2)
    end)

    it("decompress_script falls back to OP_RETURN for invalid x-coord",
       function()
      -- All-0xFF x is not on the secp256k1 curve; secp256k1_ec_pubkey_parse
      -- must reject it.  decompress_script returns the OP_RETURN sentinel
      -- so the loader can flag the coin as unspendable.
      local enc = "\x04" .. string.rep("\xff", 32)
      local r = serialize.buffer_reader(enc)
      assert.equal("\x6a", utxo.decompress_script(r))
    end)
  end)

  describe("serialize_snapshot_coin (Core Coin::Serialize parity)", function()
    it("emits VARINT(code) || VARINT(compressed_amount) || ScriptCompression",
       function()
      local h160 = string.rep("\xee", 20)
      local script_pubkey = "\x00\x14" .. h160  -- P2WPKH (raw branch)
      local entry = utxo.utxo_entry(50000, script_pubkey, 100, false)

      -- Compute expected bytes by hand using the same primitives.
      local expected_w = serialize.buffer_writer()
      -- code = 100 * 2 + 0 = 200. Core VARINT(200) =>
      --   tmp[0]=200&0x7F=72(0x48); n=(200>>7)-1=0; tmp[1]=0|0x80=0x80
      --   write reversed: 0x80, 0x48 => "8048"
      utxo.write_corevarint(expected_w, 200)
      utxo.write_corevarint(expected_w, utxo.compress_amount(50000))
      expected_w.write_bytes(utxo.compress_script(script_pubkey))
      local expected = expected_w.result()

      local actual = utxo.serialize_snapshot_coin(entry)
      assert.equal(hex(expected), hex(actual))
    end)

    it("round-trips through deserialize_snapshot_coin", function()
      local script_pubkey = "\x6a\x04" .. "test"  -- OP_RETURN payload
      local entry = utxo.utxo_entry(123456789, script_pubkey, 7777, true)
      local enc = utxo.serialize_snapshot_coin(entry)
      local r = serialize.buffer_reader(enc)
      local back = utxo.deserialize_snapshot_coin(r)
      assert.equal(entry.value, back.value)
      assert.equal(entry.script_pubkey, back.script_pubkey)
      assert.equal(entry.height, back.height)
      assert.equal(entry.is_coinbase, back.is_coinbase)
    end)
  end)

  describe("dump_snapshot / load_snapshot Core wire format", function()
    local tmp_path
    local snapshot_file
    local db1, db2

    setup(function()
      tmp_path = "/tmp/lunarblock_corefmt_snapshot_" .. os.time()
      snapshot_file = tmp_path .. ".dat"
    end)

    after_each(function()
      if db1 then db1.close(); db1 = nil end
      if db2 then db2.close(); db2 = nil end
      os.remove(snapshot_file)
    end)

    it("produces a 51-byte Core SnapshotMetadata header", function()
      -- Build the metadata directly so we don't depend on any chainstate
      -- side-effects (e.g. genesis UTXO auto-creation in init()).  This is
      -- a pure byte-format check against SnapshotMetadata::Serialize.
      local meta = utxo.snapshot_metadata(
        consensus.networks.regtest.magic_bytes,
        types.hash256(string.rep("\xab", 32)),
        0)
      local header = utxo.serialize_snapshot_metadata(meta)
      assert.equal(51, #header)
      -- First 5 bytes are the snapshot magic.
      assert.equal(utxo.SNAPSHOT_MAGIC, header:sub(1, 5))
      -- Bytes 6..7 = version (uint16 LE) == 2.
      local version_lo = header:byte(6)
      local version_hi = header:byte(7)
      assert.equal(2, version_lo + version_hi * 256)
      -- Bytes 8..11 = network magic.
      assert.equal(consensus.networks.regtest.magic_bytes, header:sub(8, 11))
      -- Bytes 12..43 = base blockhash.
      assert.equal(string.rep("\xab", 32), header:sub(12, 43))
      -- Bytes 44..51 = coins_count (uint64 LE) == 0 for empty UTXO set.
      for i = 44, 51 do
        assert.equal(0, header:byte(i))
      end
    end)

    it("dump+load round-trip preserves UTXOs (regtest fixture)", function()
      db1 = storage_mod.open(tmp_path .. "_a_" .. math.random(1000000))
      local cs = utxo.new_chain_state(db1, consensus.networks.regtest)
      cs:init()

      -- Hand-add UTXOs instead of going through connect_block so the test
      -- is independent of the pre-existing block-height tracking failures
      -- in this repo.
      local fixtures = {
        {
          txid = types.hash256(string.rep("\x10", 32)),
          vout = 0,
          entry = utxo.utxo_entry(5000000000, "\x76\xa9\x14"
            .. string.rep("\x33", 20) .. "\x88\xac", 1, true),
        },
        {
          txid = types.hash256(string.rep("\x10", 32)),
          vout = 1,
          entry = utxo.utxo_entry(123, "\x00\x14"
            .. string.rep("\x44", 20), 2, false),
        },
        {
          txid = types.hash256(string.rep("\x20", 32)),
          vout = 7,
          entry = utxo.utxo_entry(1000000, "\xa9\x14"
            .. string.rep("\x55", 20) .. "\x87", 5, false),
        },
      }
      for _, f in ipairs(fixtures) do
        cs.coin_view:add(f.txid, f.vout, f.entry)
      end
      cs.coin_view:flush()

      cs.tip_hash = types.hash256(string.rep("\xcc", 32))
      cs.tip_height = 5

      local dump_result, dump_err = cs:dump_snapshot(snapshot_file)
      assert.is_nil(dump_err)
      -- coins_count includes the regtest genesis UTXO created by init().
      -- The exact count is implementation-defined; we only require that
      -- our explicit fixtures are present after round-trip.
      assert.is_true(dump_result.coins_count >= #fixtures)

      -- Fresh chainstate to load into.
      db2 = storage_mod.open(tmp_path .. "_b_" .. math.random(1000000))
      local cs2 = utxo.new_chain_state(db2, consensus.networks.regtest)
      cs2:init()

      local ok, load_err = cs2:load_snapshot(snapshot_file)
      assert.is_true(ok)
      assert.is_nil(load_err)

      -- Verify each UTXO came back identically.
      for _, f in ipairs(fixtures) do
        local back = cs2.coin_view:get(f.txid, f.vout)
        assert.is_not_nil(back, "UTXO missing after load")
        assert.equal(f.entry.value, back.value)
        assert.equal(f.entry.script_pubkey, back.script_pubkey)
        assert.equal(f.entry.height, back.height)
        assert.equal(f.entry.is_coinbase, back.is_coinbase)
      end

      -- Tip should be set to the snapshot base.
      assert.equal(types.hash256_hex(cs.tip_hash),
                   types.hash256_hex(cs2.tip_hash))
    end)

    it("rejects truncated metadata", function()
      local f = io.open(snapshot_file, "wb")
      f:write("utxo\xff\x02\x00")  -- magic + partial version, only 7 bytes
      f:close()

      db1 = storage_mod.open(tmp_path .. "_t_" .. math.random(1000000))
      local cs = utxo.new_chain_state(db1, consensus.networks.regtest)
      cs:init()

      local ok, err = cs:load_snapshot(snapshot_file)
      assert.is_false(ok)
      assert.is_not_nil(err)
    end)
  end)

  describe("hand-built Core-format file decodes via load_snapshot", function()
    -- Build a minimal Core-format snapshot file by hand (one txid, one
    -- coin, OP_RETURN script) and ensure load_snapshot parses it.
    local snapshot_file

    setup(function()
      snapshot_file = "/tmp/lunarblock_corefmt_handbuilt_" .. os.time()
        .. "_" .. math.random(1000000) .. ".dat"
    end)

    after_each(function()
      os.remove(snapshot_file)
    end)

    it("loads a hand-encoded one-coin snapshot", function()
      local network = consensus.networks.regtest
      local base_blockhash = types.hash256(string.rep("\xa1", 32))

      -- Hand-build the file.
      local script_pubkey = "\x6a\x05hello"  -- 7-byte OP_RETURN script
      local entry = utxo.utxo_entry(1000000, script_pubkey, 42, false)

      -- Header.
      local meta = utxo.snapshot_metadata(network.magic_bytes, base_blockhash, 1)
      local header = utxo.serialize_snapshot_metadata(meta)

      -- Body: txid (32) || CompactSize(1) || CompactSize(0) || coin
      local txid_bytes = string.rep("\x77", 32)
      local body_w = serialize.buffer_writer()
      body_w.write_bytes(txid_bytes)
      body_w.write_varint(1)  -- coins_per_txid (CompactSize)
      body_w.write_varint(0)  -- vout (CompactSize)
      body_w.write_bytes(utxo.serialize_snapshot_coin(entry))

      local f = io.open(snapshot_file, "wb")
      f:write(header)
      f:write(body_w.result())
      f:close()

      -- Load through the public API.
      local db = storage_mod.open("/tmp/lunarblock_corefmt_handbuilt_db_"
        .. os.time() .. "_" .. math.random(1000000))
      local cs = utxo.new_chain_state(db, network)
      cs:init()

      local ok, err = cs:load_snapshot(snapshot_file)
      assert.is_true(ok, err)

      -- The loaded UTXO should match what we wrote.
      local loaded = cs.coin_view:get(types.hash256(txid_bytes), 0)
      assert.is_not_nil(loaded)
      assert.equal(entry.value, loaded.value)
      assert.equal(entry.script_pubkey, loaded.script_pubkey)
      assert.equal(entry.height, loaded.height)
      assert.equal(entry.is_coinbase, loaded.is_coinbase)

      db.close()
    end)
  end)

  describe("Core-strict genesis-coinbase exclusion (dump_snapshot)", function()
    -- Bitcoin Core never inserts the genesis block's coinbase into the
    -- UTXO set (validation.cpp:2337-2343 ConnectBlock fast-path), so its
    -- dumptxoutset on a fresh chainstate emits coins_count=0 and a 51-byte
    -- file (just the metadata header).  lunarblock's connect_genesis()
    -- inserts the coinbase for "consistency"; dump_snapshot must filter
    -- it out so the wire format stays byte-identical to Core.
    local tmp_path
    local snapshot_file
    local db

    setup(function()
      tmp_path = "/tmp/lunarblock_genesis_excl_" .. os.time()
      snapshot_file = tmp_path .. ".dat"
    end)

    after_each(function()
      if db then db.close(); db = nil end
      os.remove(snapshot_file)
    end)

    it("produces a 51-byte snapshot with coins_count=0 on fresh regtest",
       function()
      db = storage_mod.open(tmp_path .. "_a_" .. math.random(1000000))
      local cs = utxo.new_chain_state(db, consensus.networks.regtest)
      cs:init()  -- adds genesis coinbase to the in-memory UTXO set

      local result, err = cs:dump_snapshot(snapshot_file)
      assert.is_nil(err)
      assert.is_not_nil(result)
      assert.equal(0, result.coins_count,
        "dump_snapshot must exclude the genesis coinbase")

      local f = io.open(snapshot_file, "rb")
      local raw = f:read("*a")
      f:close()
      assert.equal(51, #raw,
        "fresh regtest snapshot must be exactly 51 bytes (metadata only)")

      -- Sanity: parsed metadata reports zero coins.
      local meta, merr = utxo.deserialize_snapshot_metadata(raw)
      assert.is_nil(merr)
      assert.equal(0, meta.coins_count)
    end)

    it("produces a 51-byte snapshot with coins_count=0 on fresh mainnet",
       function()
      db = storage_mod.open(tmp_path .. "_b_" .. math.random(1000000))
      local cs = utxo.new_chain_state(db, consensus.networks.mainnet)
      cs:init()

      local result, err = cs:dump_snapshot(snapshot_file)
      assert.is_nil(err)
      assert.equal(0, result.coins_count)

      local f = io.open(snapshot_file, "rb")
      local raw = f:read("*a")
      f:close()
      assert.equal(51, #raw)
    end)
  end)

  describe("Core-strict assumeutxo whitelist (loadtxoutset RPC)", function()
    -- bitcoin-core/src/validation.cpp:5775-5780: after recovering the
    -- snapshot's base block height from the header index, the chainparams
    -- whitelist is consulted by HEIGHT.  If the height is not present,
    -- Core refuses with the exact string "Assumeutxo height in snapshot
    -- metadata not recognized (<H>) - refusing to load snapshot".
    local rpc_mod = require("lunarblock.rpc")
    local cjson = require("cjson")

    local tmp_path
    local snapshot_file
    local db

    setup(function()
      tmp_path = "/tmp/lunarblock_whitelist_" .. os.time()
      snapshot_file = tmp_path .. ".dat"
    end)

    after_each(function()
      if db then db.close(); db = nil end
      os.remove(snapshot_file)
    end)

    it("rejects a regtest-genesis snapshot with Core's exact error message",
       function()
      -- Build a fresh regtest chainstate and dump it.  base_blockhash
      -- will be the regtest genesis hash and base_height = 0.  Regtest
      -- has no assumeutxo entries, so the whitelist lookup must fail
      -- and Core's exact error string must surface back through the
      -- JSON-RPC envelope.
      db = storage_mod.open(tmp_path .. "_c_" .. math.random(1000000))
      local cs = utxo.new_chain_state(db, consensus.networks.regtest)
      cs:init()

      local _, derr = cs:dump_snapshot(snapshot_file)
      assert.is_nil(derr)

      local server = rpc_mod.new({
        chain_state = cs,
        storage = db,
        network = consensus.networks.regtest,
      })

      local request = cjson.encode({
        jsonrpc = "1.0",
        method  = "loadtxoutset",
        params  = { snapshot_file },
        id      = 1,
      })
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error,
        "loadtxoutset must error on a non-whitelisted base height")
      assert.equal(rpc_mod.ERROR.MISC_ERROR, decoded.error.code)
      -- Substring match against Core's exact error template.
      assert.matches(
        "Assumeutxo height in snapshot metadata not recognized %(0%)"
        .. " %- refusing to load snapshot",
        decoded.error.message)
    end)
  end)

  describe("chainparams.assumeutxo", function()
    it("contains all 4 mainnet snapshots from Bitcoin Core", function()
      local heights = consensus.get_assumeutxo_heights(
        consensus.networks.mainnet)
      assert.equal(4, #heights)
      assert.equal(840000, heights[1])
      assert.equal(880000, heights[2])
      assert.equal(910000, heights[3])
      assert.equal(935000, heights[4])
    end)

    it("uses real Core hash_serialized for height 840000", function()
      local data = consensus.assumeutxo_for_height(
        consensus.networks.mainnet, 840000)
      assert.is_not_nil(data)
      assert.equal(
        "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96",
        data.hash_serialized)
      assert.equal(991032194, data.m_chain_tx_count)
      assert.equal(
        "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
        data.blockhash)
    end)

    it("uses real Core hash_serialized for height 935000", function()
      local data = consensus.assumeutxo_for_height(
        consensus.networks.mainnet, 935000)
      assert.is_not_nil(data)
      assert.equal(
        "e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050",
        data.hash_serialized)
      assert.equal(1305397408, data.m_chain_tx_count)
    end)
  end)

  describe("loadtxoutset strict gate uses HASH_SERIALIZED (SHA256d)",
           function()
    -- bitcoin-core/src/validation.cpp:5904-5915 calls
    --   ComputeUTXOStats(CoinStatsHashType::HASH_SERIALIZED, ...)
    -- and bytewise-compares maybe_stats->hashSerialized against
    -- au_data.hash_serialized.  Per kernel/coinstats.cpp:161-163,
    -- HASH_SERIALIZED is a HashWriter, whose GetHash() returns SHA256d
    -- (hash.h:115-119).  MuHash3072 is a separate hash type
    -- (CoinStatsHashType::MUHASH) used only by gettxoutsetinfo.
    --
    -- This test pins compute_utxo_hash to the SHA256d-of-streamed-TxOutSer
    -- contract by computing the hash twice and comparing against an
    -- independently-streamed reference (no muhash module touched).
    local crypto = require("lunarblock.crypto")
    local script_mod = require("lunarblock.script")

    local tmp_path
    local db

    setup(function()
      tmp_path = "/tmp/lunarblock_strictgate_" .. os.time()
        .. "_" .. math.random(1000000)
    end)

    after_each(function()
      if db then db.close(); db = nil end
    end)

    it("compute_utxo_hash returns SHA256d of canonical TxOutSer stream",
       function()
      db = storage_mod.open(tmp_path .. "_a_" .. math.random(1000000))
      local cs = utxo.new_chain_state(db, consensus.networks.regtest)
      cs:init()

      -- Three UTXOs across two txids, with one txid containing a
      -- multi-byte vout (256) so the test catches regressions if the
      -- iterator order is ever assumed to be byte-LE rather than
      -- numeric-uint32 ascending (Core uses std::map<uint32_t, Coin>).
      local txid_a = types.hash256(string.rep("\x10", 32))
      local txid_b = types.hash256(string.rep("\x20", 32))
      local fixtures = {
        { txid = txid_a, vout = 1,
          entry = utxo.utxo_entry(50, script_mod.make_p2pkh_script(
            string.rep("\x33", 20)), 11, true) },
        { txid = txid_a, vout = 256,
          entry = utxo.utxo_entry(99, script_mod.make_p2pkh_script(
            string.rep("\x44", 20)), 12, false) },
        { txid = txid_b, vout = 0,
          entry = utxo.utxo_entry(7, script_mod.make_p2pkh_script(
            string.rep("\x55", 20)), 13, false) },
      }
      for _, f in ipairs(fixtures) do
        cs.coin_view:add(f.txid, f.vout, f.entry)
      end
      cs.coin_view:flush()

      -- Independent reference: build the canonical TxOutSer stream by
      -- hand in (txid lex-asc, vout uint32-asc) order, single-pass
      -- streaming SHA256, then SHA256-once-more for SHA256d. This is
      -- byte-equivalent to Core's HashWriter::GetHash().
      local ref = crypto.sha256_init()
      -- txid_a runs first (\x10... < \x20...), with vouts 1, 256.
      ref.update(utxo.serialize_txoutser(
        utxo.outpoint_key(txid_a, 1), fixtures[1].entry))
      ref.update(utxo.serialize_txoutser(
        utxo.outpoint_key(txid_a, 256), fixtures[2].entry))
      -- Then txid_b with vout 0.
      ref.update(utxo.serialize_txoutser(
        utxo.outpoint_key(txid_b, 0), fixtures[3].entry))
      local expected = crypto.sha256(ref.final())

      local got, count = cs:compute_utxo_hash()
      assert.equal(32, #got)
      -- Count includes regtest genesis coinbase added by cs:init() plus
      -- our 3 fixtures. We don't pin the exact count here — the byte
      -- equality is the load-bearing assertion. To keep the SHA256d
      -- reference pure, recompute fresh on a chainstate with no genesis.
      assert.is_true(count >= 3)

      -- Run on a clean chainstate without init() so the genesis coinbase
      -- doesn't perturb the streamed bytes.
      local db2 = storage_mod.open(tmp_path .. "_b_"
        .. math.random(1000000))
      local cs2 = utxo.new_chain_state(db2, consensus.networks.regtest)
      -- Skip init(); just install the fixtures.
      for _, f in ipairs(fixtures) do
        cs2.coin_view:add(f.txid, f.vout, f.entry)
      end
      cs2.coin_view:flush()
      local clean_hash, clean_count = cs2:compute_utxo_hash()
      db2.close()

      assert.equal(3, clean_count)
      assert.equal(expected, clean_hash,
        "compute_utxo_hash must equal SHA256d of canonical TxOutSer stream")
    end)

    it("does NOT equal compute_muhash for the same UTXO set", function()
      -- MuHash3072 and HASH_SERIALIZED are different functions; the
      -- 25bdd7d regression silently swapped one for the other in the
      -- strict gate. Pin that they produce different bytes so any future
      -- swap is caught by the test suite.
      db = storage_mod.open(tmp_path .. "_c_" .. math.random(1000000))
      local cs = utxo.new_chain_state(db, consensus.networks.regtest)
      cs:init()

      local txid = types.hash256(string.rep("\x77", 32))
      cs.coin_view:add(txid, 0, utxo.utxo_entry(
        21000000, script_mod.make_p2pkh_script(string.rep("\x88", 20)),
        100, true))
      cs.coin_view:flush()

      local sha_d = cs:compute_utxo_hash()
      local muhash = cs:compute_muhash()
      assert.equal(32, #sha_d)
      assert.equal(32, #muhash)
      assert.are_not.equal(sha_d, muhash,
        "HASH_SERIALIZED and MuHash3072 are distinct hash functions")
    end)

    it("load_snapshot rejects mismatched HASH_SERIALIZED expected_hash",
       function()
      -- Round-trip a snapshot, then attempt to load it with a wrong
      -- expected_hash; the strict-gate check must trigger and the error
      -- message must mention HASH_SERIALIZED, not muhash.
      local snapshot_file = tmp_path .. "_snap.dat"

      db = storage_mod.open(tmp_path .. "_d_" .. math.random(1000000))
      local cs = utxo.new_chain_state(db, consensus.networks.regtest)
      cs:init()
      cs.coin_view:add(types.hash256(string.rep("\xab", 32)), 0,
        utxo.utxo_entry(42, script_mod.make_p2pkh_script(
          string.rep("\xcd", 20)), 7, false))
      cs.coin_view:flush()
      cs.tip_hash = types.hash256(string.rep("\xee", 32))
      cs.tip_height = 1
      local _, derr = cs:dump_snapshot(snapshot_file)
      assert.is_nil(derr)

      local db2 = storage_mod.open(tmp_path .. "_e_"
        .. math.random(1000000))
      local cs2 = utxo.new_chain_state(db2, consensus.networks.regtest)
      cs2:init()
      local wrong_hash = string.rep("\x00", 32)
      local ok, err = cs2:load_snapshot(snapshot_file, wrong_hash)
      db2.close()
      os.remove(snapshot_file)

      assert.is_false(ok)
      assert.is_not_nil(err)
      assert.matches("hash_serialized", err,
        "strict-gate error must reference HASH_SERIALIZED")
    end)
  end)

  -- Suppress unused warnings
  local _ = unhex
  local _2 = validation
  local _3 = script_mod
end)
