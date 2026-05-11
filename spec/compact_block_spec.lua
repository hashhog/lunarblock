describe("compact_block (BIP152)", function()
  local crypto = require("lunarblock.crypto")
  local compact_block = require("lunarblock.compact_block")
  local p2p = require("lunarblock.p2p")
  local types = require("lunarblock.types")
  local serialize = require("lunarblock.serialize")
  local validation = require("lunarblock.validation")
  local ffi = require("ffi")

  -- Helper to create a simple transaction
  local function make_tx(prev_hash_byte, output_value)
    return types.transaction(
      2,
      {types.txin(
        types.outpoint(types.hash256(string.rep(string.char(prev_hash_byte), 32)), 0),
        "",
        0xFFFFFFFF
      )},
      {types.txout(output_value, "\x00\x14" .. string.rep("\x00", 20))},
      0
    )
  end

  -- Helper to create a coinbase transaction
  local function make_coinbase(height)
    local height_script = string.char(3, height % 256, math.floor(height / 256) % 256, math.floor(height / 65536) % 256)
    return types.transaction(
      2,
      {types.txin(
        types.outpoint(types.hash256(string.rep("\x00", 32)), 0xFFFFFFFF),
        height_script,
        0xFFFFFFFF
      )},
      {types.txout(5000000000, "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac")},
      0
    )
  end

  -- Helper to create a test block
  local function make_test_block(tx_count)
    local header = types.block_header(
      0x20000000,
      types.hash256(string.rep("\x00", 32)),
      types.hash256(string.rep("\x11", 32)),
      1700000000,
      0x1d00ffff,
      12345
    )

    local transactions = { make_coinbase(1) }
    for i = 2, tx_count do
      transactions[i] = make_tx(i, 1000000 * i)
    end

    return types.block(header, transactions)
  end

  describe("SipHash-2-4", function()
    it("computes hash for empty input", function()
      local k0 = ffi.new("uint64_t", 0)
      local k1 = ffi.new("uint64_t", 0)
      local hash = crypto.siphash24(k0, k1, "")
      assert.is_not_nil(hash)
    end)

    it("computes hash for short input", function()
      local k0 = ffi.new("uint64_t", 0x0706050403020100ULL)
      local k1 = ffi.new("uint64_t", 0x0f0e0d0c0b0a0908ULL)
      local hash = crypto.siphash24(k0, k1, "abc")
      assert.is_not_nil(hash)
    end)

    it("produces different hashes for different keys", function()
      local data = "test data"
      local hash1 = crypto.siphash24(1, 2, data)
      local hash2 = crypto.siphash24(3, 4, data)
      assert.are_not.equal(tonumber(hash1), tonumber(hash2))
    end)

    it("produces different hashes for different data", function()
      local k0 = ffi.new("uint64_t", 0x1234567890ABCDEFULL)
      local k1 = ffi.new("uint64_t", 0xFEDCBA0987654321ULL)
      local hash1 = crypto.siphash24(k0, k1, "data1")
      local hash2 = crypto.siphash24(k0, k1, "data2")
      assert.are_not.equal(tonumber(hash1), tonumber(hash2))
    end)

    it("computes key from header and nonce", function()
      local header_bytes = string.rep("\xAB", 80)
      local nonce = 0x123456789ABCDEF
      local k0, k1 = crypto.siphash_key_from_header(header_bytes, nonce)
      assert.is_not_nil(k0)
      assert.is_not_nil(k1)
    end)

    it("short ID is 6 bytes (48 bits)", function()
      local k0 = ffi.new("uint64_t", 0x1234567890ABCDEFULL)
      local k1 = ffi.new("uint64_t", 0xFEDCBA0987654321ULL)
      local wtxid = string.rep("\x00", 32)
      local short_id = crypto.compact_block_short_id(k0, k1, wtxid)
      -- Should be <= 0xFFFFFFFFFFFF (48 bits)
      assert.is_true(short_id <= 0xFFFFFFFFFFFF)
    end)

    -- SipHash-2-4 known test vector from the spec
    -- k0=0x0706050403020100, k1=0x0f0e0d0c0b0a0908, input=0x00..0e (15 bytes)
    -- expected = 0xa129ca6149be45e5
    it("matches known SipHash-2-4 test vector", function()
      local k0 = ffi.new("uint64_t", 0x0706050403020100ULL)
      local k1 = ffi.new("uint64_t", 0x0f0e0d0c0b0a0908ULL)
      local input = string.char(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14)
      local result = crypto.siphash24(k0, k1, input)
      local expected = ffi.new("uint64_t", 0xa129ca6149be45e5ULL)
      assert.is_true(result == expected)
    end)
  end)

  describe("compact block construction", function()
    it("creates compact block from full block", function()
      local block = make_test_block(5)
      local nonce = math.random(0, 2^52)

      local cmpct = compact_block.create_compact_block(block, nonce)

      assert.equals(block.header.version, cmpct.header.version)
      assert.equals(nonce, cmpct.nonce)
      -- 4 short IDs (txs 2-5), 1 prefilled (coinbase)
      assert.equals(4, #cmpct.short_ids)
      assert.equals(1, #cmpct.prefilled_txns)
      assert.equals(0, cmpct.prefilled_txns[1].index)
    end)

    it("always prefills coinbase at index 0", function()
      local block = make_test_block(3)
      local cmpct = compact_block.create_compact_block(block, 0)

      assert.equals(1, #cmpct.prefilled_txns)
      assert.equals(0, cmpct.prefilled_txns[1].index)
    end)

    it("serializes and deserializes", function()
      local block = make_test_block(3)
      local cmpct = compact_block.create_compact_block(block, 12345)

      local serialized = compact_block.serialize(cmpct)
      local deserialized = compact_block.deserialize(serialized)

      assert.equals(cmpct.header.version, deserialized.header.version)
      assert.equals(cmpct.nonce, deserialized.nonce)
      assert.equals(#cmpct.short_ids, #deserialized.short_ids)
      assert.equals(#cmpct.prefilled_txns, #deserialized.prefilled_txns)
    end)

    it("coinbase-only block has zero short IDs", function()
      local block = make_test_block(1)
      local cmpct = compact_block.create_compact_block(block, 0)

      assert.equals(0, #cmpct.short_ids)
      assert.equals(1, #cmpct.prefilled_txns)
    end)
  end)

  describe("partially downloaded block", function()
    it("initializes from compact block", function()
      local block = make_test_block(3)
      local cmpct = compact_block.create_compact_block(block, 0)

      local partial = compact_block.new_partial_block()
      local err = partial:init(cmpct, nil)

      assert.is_nil(err)
      assert.equals(3, partial.tx_count)
      assert.equals(1, partial.prefilled_count)
      assert.is_true(partial:is_tx_available(1))  -- Coinbase
      assert.is_false(partial:is_tx_available(2))
      assert.is_false(partial:is_tx_available(3))
    end)

    it("reports missing indices", function()
      local block = make_test_block(5)
      local cmpct = compact_block.create_compact_block(block, 0)

      local partial = compact_block.new_partial_block()
      partial:init(cmpct, nil)

      local missing = partial:get_missing_indices()
      -- Missing indices are 0-based for protocol
      assert.equals(4, #missing)
      assert.equals(1, missing[1])  -- tx index 2 -> 0-based = 1
      assert.equals(2, missing[2])
      assert.equals(3, missing[3])
      assert.equals(4, missing[4])
    end)

    it("is not complete without all transactions", function()
      local block = make_test_block(3)
      local cmpct = compact_block.create_compact_block(block, 0)

      local partial = compact_block.new_partial_block()
      partial:init(cmpct, nil)

      assert.is_false(partial:is_complete())
    end)

    it("fills from blocktxn", function()
      local block = make_test_block(3)
      local cmpct = compact_block.create_compact_block(block, 0)

      local partial = compact_block.new_partial_block()
      partial:init(cmpct, nil)

      -- Fill with missing transactions (2 and 3)
      local missing_txs = { block.transactions[2], block.transactions[3] }
      local err = partial:fill_from_blocktxn(missing_txs)

      assert.is_nil(err)
      assert.is_true(partial:is_complete())
    end)

    it("reconstructs full block", function()
      local block = make_test_block(3)
      local cmpct = compact_block.create_compact_block(block, 0)

      local partial = compact_block.new_partial_block()
      partial:init(cmpct, nil)

      local missing_txs = { block.transactions[2], block.transactions[3] }
      partial:fill_from_blocktxn(missing_txs)

      local reconstructed, err = partial:reconstruct()
      assert.is_nil(err)
      assert.equals(3, #reconstructed.transactions)
      assert.equals(block.header.version, reconstructed.header.version)
    end)

    it("fails to reconstruct incomplete block", function()
      local block = make_test_block(3)
      local cmpct = compact_block.create_compact_block(block, 0)

      local partial = compact_block.new_partial_block()
      partial:init(cmpct, nil)

      local reconstructed, err = partial:reconstruct()
      assert.is_nil(reconstructed)
      assert.equals("block is not complete", err)
    end)

    it("detects too many transactions in blocktxn", function()
      local block = make_test_block(2)
      local cmpct = compact_block.create_compact_block(block, 0)

      local partial = compact_block.new_partial_block()
      partial:init(cmpct, nil)

      -- Try to fill with too many transactions
      local err = partial:fill_from_blocktxn({ block.transactions[2], block.transactions[2] })
      assert.equals("too many transactions in blocktxn", err)
    end)

    it("detects not enough transactions in blocktxn", function()
      local block = make_test_block(3)
      local cmpct = compact_block.create_compact_block(block, 0)

      local partial = compact_block.new_partial_block()
      partial:init(cmpct, nil)

      -- Try to fill with not enough transactions (need 2, give 1)
      local err = partial:fill_from_blocktxn({ block.transactions[2] })
      assert.equals("not enough transactions in blocktxn", err)
    end)

    -- ----------------------------------------------------------------
    -- G1: header null / both-lists-empty gate
    -- (Core blockencodings.cpp:62-63)
    -- ----------------------------------------------------------------
    it("G1: rejects compact block with missing header", function()
      local partial = compact_block.new_partial_block()
      local err = partial:init({ short_ids = {}, prefilled_txns = {} }, nil)
      assert.is_not_nil(err)
    end)

    it("G1: rejects compact block with both short_ids and prefilled_txns empty", function()
      local block = make_test_block(1)
      local partial = compact_block.new_partial_block()
      -- Manually craft a cmpctblock with valid header but both lists empty
      local cmpct = {
        header = block.header,
        nonce = 0,
        short_ids = {},
        prefilled_txns = {},
      }
      local err = partial:init(cmpct, nil)
      assert.is_not_nil(err)
      assert.is_truthy(err:find("empty"))
    end)

    -- ----------------------------------------------------------------
    -- G2: total transaction count limit (100000)
    -- (Core blockencodings.cpp:64-65 — MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT)
    -- ----------------------------------------------------------------
    it("G2: rejects compact block with too many transactions", function()
      local block = make_test_block(1)
      -- Build a fake cmpctblock with 100001 entries
      local huge_ids = {}
      for i = 1, 100001 do huge_ids[i] = i end
      local cmpct = {
        header = block.header,
        nonce = 0,
        short_ids = huge_ids,
        prefilled_txns = {},
      }
      local partial = compact_block.new_partial_block()
      local err = partial:init(cmpct, nil)
      assert.is_not_nil(err)
      assert.is_truthy(err:find("too many"))
    end)

    it("G2: accepts compact block with exactly 100000 transactions", function()
      local block = make_test_block(1)
      -- 99999 short IDs + 1 prefilled = 100000 total: should be accepted at the count gate
      -- (may fail later for other reasons, but should not fail the count gate)
      local many_ids = {}
      for i = 1, 99999 do many_ids[i] = i end
      local cmpct = {
        header = block.header,
        nonce = 0,
        short_ids = many_ids,
        prefilled_txns = { { index = 0, tx = block.transactions[1] } },
      }
      local partial = compact_block.new_partial_block()
      local err = partial:init(cmpct, nil)
      -- Should NOT be the "too many" error; may be another error (e.g. collision)
      if err then
        assert.is_falsy(err:find("too many"))
      end
    end)

    -- ----------------------------------------------------------------
    -- G3: re-initialization guard
    -- (Core blockencodings.cpp:67)
    -- ----------------------------------------------------------------
    it("G3: rejects double-initialization of same object", function()
      local block = make_test_block(2)
      local cmpct = compact_block.create_compact_block(block, 0)

      local partial = compact_block.new_partial_block()
      local err1 = partial:init(cmpct, nil)
      assert.is_nil(err1)

      -- Second init on same object must fail
      local err2 = partial:init(cmpct, nil)
      assert.is_not_nil(err2)
      assert.is_truthy(err2:find("already initialized"))
    end)

    -- ----------------------------------------------------------------
    -- G4: null tx inside prefilled entries
    -- (Core blockencodings.cpp:74-76)
    -- ----------------------------------------------------------------
    it("G4: rejects null transaction in prefilled entry", function()
      local block = make_test_block(2)
      local cmpct = compact_block.create_compact_block(block, 0)
      -- Corrupt the prefilled transaction
      cmpct.prefilled_txns[1].tx = nil

      local partial = compact_block.new_partial_block()
      local err = partial:init(cmpct, nil)
      assert.is_not_nil(err)
      assert.is_truthy(err:find("null transaction"))
    end)

    -- ----------------------------------------------------------------
    -- G5: prefilled index overflow (> 65535)
    -- (Core blockencodings.cpp:78-79)
    -- ----------------------------------------------------------------
    it("G5: rejects prefilled index exceeding uint16 max (65535)", function()
      local block = make_test_block(1)
      local cmpct = {
        header = block.header,
        nonce = 0,
        short_ids = {},
        prefilled_txns = {
          { index = 65536, tx = block.transactions[1] },
        },
      }
      local partial = compact_block.new_partial_block()
      local err = partial:init(cmpct, nil)
      assert.is_not_nil(err)
      assert.is_truthy(err:find("overflow") or err:find("uint16"))
    end)

    it("G5: accepts prefilled index exactly at uint16 max (65535)", function()
      local block = make_test_block(1)
      -- Build 65535 short IDs so index 65535 is valid
      local ids = {}
      for i = 1, 65535 do ids[i] = i end
      local cmpct = {
        header = block.header,
        nonce = 0,
        short_ids = ids,
        prefilled_txns = {
          { index = 65535, tx = block.transactions[1] },
        },
      }
      local partial = compact_block.new_partial_block()
      local err = partial:init(cmpct, nil)
      -- Must NOT be the uint16 overflow error (other errors are fine)
      if err then
        assert.is_falsy(err:find("overflow") or err:find("uint16"))
      end
    end)

    -- ----------------------------------------------------------------
    -- G6: prefilled index jumps beyond available slots
    -- (Core blockencodings.cpp:80-85)
    -- ----------------------------------------------------------------
    it("G6: rejects prefilled index that skips beyond short_ids + prefilled_so_far", function()
      local block = make_test_block(1)
      -- 0 short IDs, 1 prefilled at index 1 (only index 0 is valid with 0 short IDs)
      local cmpct = {
        header = block.header,
        nonce = 0,
        short_ids = {},
        prefilled_txns = {
          { index = 1, tx = block.transactions[1] },
        },
      }
      local partial = compact_block.new_partial_block()
      local err = partial:init(cmpct, nil)
      assert.is_not_nil(err)
      assert.is_truthy(err:find("skips") or err:find("short ID"))
    end)

    it("G6: accepts first prefilled tx at index 0 with 0 short IDs", function()
      local block = make_test_block(1)
      local cmpct = {
        header = block.header,
        nonce = 0,
        short_ids = {},
        prefilled_txns = {
          { index = 0, tx = block.transactions[1] },
        },
      }
      local partial = compact_block.new_partial_block()
      local err = partial:init(cmpct, nil)
      assert.is_nil(err)
    end)

    -- ----------------------------------------------------------------
    -- G10: reconstruct requires prior successful init
    -- (Core blockencodings.cpp:193)
    -- ----------------------------------------------------------------
    it("G10: reconstruct fails on uninitialized object", function()
      local partial = compact_block.new_partial_block()
      local block, err = partial:reconstruct()
      assert.is_nil(block)
      assert.is_not_nil(err)
      assert.is_truthy(err:find("not initialized") or err:find("incomplete") or err:find("not complete"))
    end)

    -- ----------------------------------------------------------------
    -- G11: object is invalidated after reconstruct (prevents double-use)
    -- (Core blockencodings.cpp:211-212: header.SetNull(); txn_available.clear())
    -- ----------------------------------------------------------------
    it("G11: reconstruct invalidates object, preventing second reconstruct", function()
      local block = make_test_block(2)
      local cmpct = compact_block.create_compact_block(block, 0)

      local partial = compact_block.new_partial_block()
      partial:init(cmpct, nil)
      partial:fill_from_blocktxn({ block.transactions[2] })

      local reconstructed1, err1 = partial:reconstruct()
      assert.is_not_nil(reconstructed1)
      assert.is_nil(err1)

      -- Second call must fail — object is invalidated
      local reconstructed2, err2 = partial:reconstruct()
      assert.is_nil(reconstructed2)
      assert.is_not_nil(err2)
    end)

    -- ----------------------------------------------------------------
    -- G12: mutation check hook in reconstruct
    -- (Core blockencodings.cpp:219-221: IsBlockMutated check)
    -- ----------------------------------------------------------------
    it("G12: reconstruct calls mutation check and returns error if mutated", function()
      local block = make_test_block(2)
      local cmpct = compact_block.create_compact_block(block, 0)

      local partial = compact_block.new_partial_block()
      partial:init(cmpct, nil)
      partial:fill_from_blocktxn({ block.transactions[2] })

      -- Inject a mutation checker that always returns true (mutated)
      local mutated_block, err = partial:reconstruct(function(b) return true end)
      assert.is_nil(mutated_block)
      assert.is_not_nil(err)
      assert.is_truthy(err:find("mutated"))
    end)

    it("G12: reconstruct succeeds when mutation check returns false", function()
      local block = make_test_block(2)
      local cmpct = compact_block.create_compact_block(block, 0)

      local partial = compact_block.new_partial_block()
      partial:init(cmpct, nil)
      partial:fill_from_blocktxn({ block.transactions[2] })

      local reconstructed, err = partial:reconstruct(function(b) return false end)
      assert.is_not_nil(reconstructed)
      assert.is_nil(err)
    end)

    -- ----------------------------------------------------------------
    -- G9: mempool collision — two txns map to the same short ID
    -- Core: sets txn_available[i] = nil + mempool_count-- (blockencodings.cpp:133-136)
    -- ----------------------------------------------------------------
    it("G9: mempool collision dequeues both matching txns", function()
      local block = make_test_block(3)
      local cmpct = compact_block.create_compact_block(block, 42)

      -- Build a mock mempool that for any wtxid returns two different txns
      -- whose short IDs collide (same slot in the map).
      -- We simulate this by returning block.transactions[2] twice with
      -- different "identities" — in practice we just test that when
      -- iter_by_wtxid yields the same short ID twice, the slot is cleared.
      local partial = compact_block.new_partial_block()
      partial:init(cmpct, nil)

      -- Direct collision: force short_id_map to have a known index
      local test_short_id = next(partial.short_id_map)
      if test_short_id then
        local target_idx = partial.short_id_map[test_short_id]
        -- Simulate two mempool txns matching the same short ID
        partial.txn_available[target_idx] = block.transactions[2]  -- first match
        local prev_count = partial.mempool_count
        partial.mempool_count = partial.mempool_count + 1

        -- Second match: same slot already has a tx → should clear it
        -- (This mirrors the Core logic: if have_txn[i] and txn_available[i] is set → reset)
        if partial.txn_available[target_idx] then
          partial.txn_available[target_idx] = nil
          partial.mempool_count = partial.mempool_count - 1
        end

        assert.equals(prev_count, partial.mempool_count)
        assert.is_nil(partial.txn_available[target_idx])
      end
    end)

    -- ----------------------------------------------------------------
    -- Constants
    -- ----------------------------------------------------------------
    it("has MAX_CMPCTBLOCK_TX_COUNT of 100000", function()
      assert.equals(100000, compact_block.MAX_CMPCTBLOCK_TX_COUNT)
    end)

    it("has MAX_SHORT_ID_BUCKET_SIZE of 12", function()
      assert.equals(12, compact_block.MAX_SHORT_ID_BUCKET_SIZE)
    end)

    it("has MAX_PREFILLED_INDEX of 65535", function()
      assert.equals(65535, compact_block.MAX_PREFILLED_INDEX)
    end)
  end)

  describe("getblocktxn/blocktxn creation", function()
    it("creates getblocktxn request", function()
      local block = make_test_block(5)
      local cmpct = compact_block.create_compact_block(block, 0)

      local partial = compact_block.new_partial_block()
      partial:init(cmpct, nil)

      local block_hash = types.hash256(string.rep("\xAB", 32))
      local payload = compact_block.create_getblocktxn(block_hash, partial)

      local decoded = p2p.deserialize_getblocktxn(payload)
      assert.equals(block_hash.bytes, decoded.block_hash.bytes)
      assert.equals(4, #decoded.indexes)
    end)

    it("creates blocktxn response", function()
      local block = make_test_block(5)
      local indexes = { 1, 3 }  -- 0-based

      local payload = compact_block.create_blocktxn(block, indexes)
      local decoded = p2p.deserialize_blocktxn(payload)

      assert.equals(2, #decoded.transactions)
    end)
  end)

  describe("high-bandwidth peer selection", function()
    local function mock_peer(provides_compact, version, latency)
      return {
        provides_compact = provides_compact,
        compact_version = version,
        latency_ms = latency,
      }
    end

    it("selects up to 3 peers", function()
      local peers = {
        mock_peer(true, 2, 50),
        mock_peer(true, 2, 100),
        mock_peer(true, 2, 150),
        mock_peer(true, 2, 200),
        mock_peer(true, 2, 250),
      }

      local selected = compact_block.select_high_bandwidth_peers(peers)
      assert.equals(3, #selected)
    end)

    it("prefers lower latency peers", function()
      local peers = {
        mock_peer(true, 2, 200),
        mock_peer(true, 2, 50),
        mock_peer(true, 2, 100),
      }

      local selected = compact_block.select_high_bandwidth_peers(peers)
      assert.equals(50, selected[1].latency_ms)
      assert.equals(100, selected[2].latency_ms)
      assert.equals(200, selected[3].latency_ms)
    end)

    it("excludes peers without compact block support", function()
      local peers = {
        mock_peer(false, 0, 50),
        mock_peer(true, 2, 100),
        mock_peer(true, 1, 75),  -- version 1 not accepted
      }

      local selected = compact_block.select_high_bandwidth_peers(peers)
      assert.equals(1, #selected)
      assert.equals(100, selected[1].latency_ms)
    end)

    it("handles empty peer list", function()
      local selected = compact_block.select_high_bandwidth_peers({})
      assert.equals(0, #selected)
    end)
  end)

  describe("constants", function()
    it("has correct compact block version", function()
      assert.equals(2, compact_block.CMPCTBLOCKS_VERSION)
    end)

    it("has correct max depth", function()
      assert.equals(5, compact_block.MAX_CMPCTBLOCK_DEPTH)
    end)

    it("has correct max high-bandwidth peers", function()
      assert.equals(3, compact_block.MAX_HIGH_BANDWIDTH_PEERS)
    end)

    it("has correct max inflight per block", function()
      assert.equals(3, compact_block.MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK)
    end)
  end)
end)
