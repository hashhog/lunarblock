describe("sync", function()
  local sync
  local types
  local consensus
  local validation
  local serialize
  local crypto
  local p2p

  setup(function()
    package.path = "src/?.lua;" .. package.path
    -- Set up lunarblock.X aliases
    package.preload["lunarblock.types"] = function() return require("types") end
    package.preload["lunarblock.serialize"] = function() return require("serialize") end
    package.preload["lunarblock.crypto"] = function() return require("crypto") end
    package.preload["lunarblock.script"] = function() return require("script") end
    package.preload["lunarblock.consensus"] = function() return require("consensus") end
    package.preload["lunarblock.validation"] = function() return require("validation") end
    package.preload["lunarblock.p2p"] = function() return require("p2p") end

    types = require("types")
    serialize = require("serialize")
    consensus = require("consensus")
    validation = require("validation")
    crypto = require("crypto")
    p2p = require("p2p")
    sync = require("sync")
  end)

  -- Mock storage for testing
  local function create_mock_storage()
    local data = {
      headers = {},
      height_index = {},
      meta = {},
    }

    local storage = {
      CF = {
        META = "meta",
        HEADERS = "headers",
        HEIGHT_INDEX = "height",
      }
    }

    function storage.get(cf, key)
      if cf == "meta" then
        return data.meta[key]
      elseif cf == "headers" then
        return data.headers[key]
      elseif cf == "height" then
        return data.height_index[key]
      end
      return nil
    end

    function storage.put(cf, key, value, _sync)
      if cf == "meta" then
        data.meta[key] = value
      elseif cf == "headers" then
        data.headers[key] = value
      elseif cf == "height" then
        data.height_index[key] = value
      end
    end

    function storage.get_header(block_hash)
      local header_data = data.headers[block_hash.bytes]
      if not header_data then return nil end
      return serialize.deserialize_block_header(header_data)
    end

    function storage.put_header(block_hash, header)
      local header_data = serialize.serialize_block_header(header)
      data.headers[block_hash.bytes] = header_data
    end

    function storage.get_hash_by_height(height)
      local key = string.char(
        math.floor(height / 16777216) % 256,
        math.floor(height / 65536) % 256,
        math.floor(height / 256) % 256,
        height % 256
      )
      local hash_bytes = data.height_index[key]
      if not hash_bytes or #hash_bytes ~= 32 then return nil end
      return types.hash256(hash_bytes)
    end

    function storage.put_height_index(height, block_hash)
      local key = string.char(
        math.floor(height / 16777216) % 256,
        math.floor(height / 65536) % 256,
        math.floor(height / 256) % 256,
        height % 256
      )
      data.height_index[key] = block_hash.bytes
    end

    function storage.get_chain_tip()
      return nil, nil
    end

    function storage.set_chain_tip(_hash, _height, _sync)
    end

    return storage
  end

  -- Create a valid header extending from a parent
  local function create_valid_header(parent_hash, timestamp, bits)
    bits = bits or 0x207fffff  -- regtest difficulty
    timestamp = timestamp or os.time()
    return types.block_header(
      1,               -- version
      parent_hash,     -- prev_hash
      types.hash256_zero(),  -- merkle_root
      timestamp,
      bits,
      0                -- nonce (we'll find valid one)
    )
  end

  -- Find a valid nonce for a header (brute force for regtest difficulty)
  local function find_valid_nonce(header)
    local target = consensus.bits_to_target(header.bits)
    for nonce = 0, 1000000 do
      header.nonce = nonce
      local hash = validation.compute_block_hash(header)
      if consensus.hash_meets_target(hash.bytes, target) then
        return true
      end
    end
    return false
  end

  describe("HeaderChain initialization", function()
    it("creates a new header chain with regtest network", function()
      local storage = create_mock_storage()
      local chain = sync.new_header_chain(consensus.networks.regtest, storage)

      assert.is_not_nil(chain)
      assert.equals(-1, chain:get_tip_height())
      assert.is_nil(chain:get_tip_hash())
    end)

    it("initializes with genesis block", function()
      local storage = create_mock_storage()
      local chain = sync.new_header_chain(consensus.networks.regtest, storage)
      chain:init()

      assert.equals(0, chain:get_tip_height())
      assert.is_not_nil(chain:get_tip_hash())

      local genesis_entry = chain:get_header_at_height(0)
      assert.is_not_nil(genesis_entry)
      assert.equals(0, genesis_entry.height)
      assert.equals(consensus.networks.regtest.genesis.timestamp, genesis_entry.header.timestamp)
      assert.equals(consensus.networks.regtest.genesis.bits, genesis_entry.header.bits)
    end)

    it("stores genesis in database during init", function()
      local storage = create_mock_storage()
      local chain = sync.new_header_chain(consensus.networks.regtest, storage)
      chain:init()

      local tip_hash = chain:get_tip_hash()
      local stored_header = storage.get_header(tip_hash)
      assert.is_not_nil(stored_header)
      assert.equals(consensus.networks.regtest.genesis.timestamp, stored_header.timestamp)
    end)
  end)

  describe("accept_header", function()
    local storage, chain, genesis_hash

    before_each(function()
      storage = create_mock_storage()
      chain = sync.new_header_chain(consensus.networks.regtest, storage)
      chain:init()
      genesis_hash = chain:get_tip_hash()
    end)

    it("accepts a valid header extending the chain", function()
      local header = create_valid_header(
        genesis_hash,
        consensus.networks.regtest.genesis.timestamp + 600
      )
      assert.is_true(find_valid_nonce(header))

      local ok, err = chain:accept_header(header)
      assert.is_true(ok)
      assert.is_nil(err)
      assert.equals(1, chain:get_tip_height())
    end)

    it("rejects header with unknown parent", function()
      local unknown_parent = types.hash256(string.rep("\xff", 32))
      local header = create_valid_header(
        unknown_parent,
        os.time()
      )

      local ok, err = chain:accept_header(header)
      assert.is_false(ok)
      assert.is_truthy(err:match("unknown parent"))
    end)

    it("rejects header with insufficient proof of work", function()
      -- Create header with impossibly low target (high difficulty)
      local header = types.block_header(
        1,
        genesis_hash,
        types.hash256_zero(),
        os.time(),
        0x03000001,  -- very high difficulty
        0
      )

      local ok, err = chain:accept_header(header)
      assert.is_false(ok)
      assert.equals("insufficient proof of work", err)
    end)

    it("rejects header with timestamp not greater than MTP", function()
      -- For genesis alone, MTP is just the genesis timestamp
      -- So we need a timestamp <= genesis timestamp
      local header = create_valid_header(
        genesis_hash,
        consensus.networks.regtest.genesis.timestamp - 1  -- before MTP
      )
      assert.is_true(find_valid_nonce(header))

      local ok, err = chain:accept_header(header)
      assert.is_false(ok)
      assert.equals("timestamp not greater than median time past", err)
    end)

    it("skips already known headers", function()
      local header = create_valid_header(
        genesis_hash,
        consensus.networks.regtest.genesis.timestamp + 600
      )
      assert.is_true(find_valid_nonce(header))

      -- Accept first time
      local ok1, err1 = chain:accept_header(header)
      assert.is_true(ok1)
      assert.is_nil(err1)

      -- Accept second time - should succeed but not increase height
      local ok2, err2 = chain:accept_header(header)
      assert.is_true(ok2)
      assert.is_nil(err2)
      assert.equals(1, chain:get_tip_height())  -- still 1
    end)
  end)

  describe("block locator", function()
    local storage, chain

    before_each(function()
      storage = create_mock_storage()
      chain = sync.new_header_chain(consensus.networks.regtest, storage)
      chain:init()
    end)

    it("returns genesis hash for new chain", function()
      local locator = chain:get_block_locator()
      assert.equals(1, #locator)

      local genesis_hash = chain:get_tip_hash()
      assert.is_true(types.hash256_eq(locator[1], genesis_hash))
    end)

    it("builds exponential backoff locator for longer chain", function()
      -- Build a chain of 20 blocks
      local parent_hash = chain:get_tip_hash()
      local timestamp = consensus.networks.regtest.genesis.timestamp

      for i = 1, 20 do
        timestamp = timestamp + 600
        local header = create_valid_header(parent_hash, timestamp)
        assert.is_true(find_valid_nonce(header))
        local ok, err = chain:accept_header(header)
        assert.is_true(ok, "Failed at block " .. i .. ": " .. tostring(err))
        parent_hash = validation.compute_block_hash(header)
      end

      assert.equals(20, chain:get_tip_height())

      local locator = chain:get_block_locator()
      -- For 20 blocks: 10 individual hashes (20,19,18,17,16,15,14,13,12,11)
      -- then exponential: 9, 7, 3, 0 (step doubles after 10)
      -- Actually: after 10 hashes, step doubles each time
      assert.is_true(#locator >= 10)
      assert.is_true(#locator <= 20)

      -- First hash should be tip
      local tip_hash = chain:get_tip_hash()
      assert.is_true(types.hash256_eq(locator[1], tip_hash))

      -- Last hash should be genesis (height 0)
      local genesis_entry = chain:get_header_at_height(0)
      local genesis_hash = validation.compute_block_hash(genesis_entry.header)
      assert.is_true(types.hash256_eq(locator[#locator], genesis_hash))
    end)
  end)

  describe("get_past_timestamps", function()
    local storage, chain

    before_each(function()
      storage = create_mock_storage()
      chain = sync.new_header_chain(consensus.networks.regtest, storage)
      chain:init()
    end)

    it("returns genesis timestamp for single-block chain", function()
      local genesis_hash = chain:get_tip_hash()
      local genesis_hex = types.hash256_hex(genesis_hash)

      local timestamps = chain:get_past_timestamps(genesis_hex, 11)
      assert.equals(1, #timestamps)
      assert.equals(consensus.networks.regtest.genesis.timestamp, timestamps[1])
    end)

    it("returns correct timestamps for longer chain", function()
      local parent_hash = chain:get_tip_hash()
      local base_timestamp = consensus.networks.regtest.genesis.timestamp
      local expected_timestamps = { base_timestamp }

      -- Build 5 more blocks
      for i = 1, 5 do
        local timestamp = base_timestamp + i * 600
        local header = create_valid_header(parent_hash, timestamp)
        assert.is_true(find_valid_nonce(header))
        chain:accept_header(header)
        parent_hash = validation.compute_block_hash(header)
        table.insert(expected_timestamps, 1, timestamp)  -- prepend
      end

      local tip_hex = types.hash256_hex(parent_hash)
      local timestamps = chain:get_past_timestamps(tip_hex, 11)

      -- Should have 6 timestamps (blocks 5, 4, 3, 2, 1, 0)
      assert.equals(6, #timestamps)

      -- Timestamps should be in reverse order (newest first)
      for i, ts in ipairs(timestamps) do
        assert.equals(expected_timestamps[i], ts)
      end
    end)
  end)

  describe("process_headers batch", function()
    local storage, chain

    before_each(function()
      storage = create_mock_storage()
      chain = sync.new_header_chain(consensus.networks.regtest, storage)
      chain:init()
    end)

    it("processes batch of valid headers and updates tip", function()
      local headers = {}
      local parent_hash = chain:get_tip_hash()
      local timestamp = consensus.networks.regtest.genesis.timestamp

      for i = 1, 5 do
        timestamp = timestamp + 600
        local header = create_valid_header(parent_hash, timestamp)
        assert.is_true(find_valid_nonce(header))
        headers[i] = header
        parent_hash = validation.compute_block_hash(header)
      end

      local accepted, err = chain:process_headers(headers)
      assert.is_nil(err)
      assert.equals(5, accepted)
      assert.equals(5, chain:get_tip_height())
    end)

    it("stops processing on first invalid header", function()
      local headers = {}
      local parent_hash = chain:get_tip_hash()
      local timestamp = consensus.networks.regtest.genesis.timestamp

      -- Create 2 valid headers
      for i = 1, 2 do
        timestamp = timestamp + 600
        local header = create_valid_header(parent_hash, timestamp)
        assert.is_true(find_valid_nonce(header))
        headers[i] = header
        parent_hash = validation.compute_block_hash(header)
      end

      -- Third header has invalid PoW
      headers[3] = types.block_header(
        1,
        parent_hash,
        types.hash256_zero(),
        timestamp + 600,
        0x03000001,  -- very high difficulty
        0
      )

      -- More valid headers after
      headers[4] = create_valid_header(
        validation.compute_block_hash(headers[3]),
        timestamp + 1200
      )

      local accepted, err = chain:process_headers(headers)
      assert.equals(2, accepted)
      assert.equals("insufficient proof of work", err)
      assert.equals(2, chain:get_tip_height())
    end)
  end)

  describe("checkpoint validation", function()
    local storage, chain

    before_each(function()
      -- Create a network with a custom checkpoint
      local network = {
        name = "test",
        genesis = consensus.networks.regtest.genesis,
        pow_no_retarget = true,
        pow_allow_min_difficulty = true,
        checkpoints = {
          [1] = "0000000000000000000000000000000000000000000000000000000000001234",
        }
      }

      storage = create_mock_storage()
      chain = sync.new_header_chain(network, storage)
      chain:init()
    end)

    it("rejects header with wrong hash at checkpoint height", function()
      local genesis_hash = chain:get_tip_hash()
      local header = create_valid_header(
        genesis_hash,
        consensus.networks.regtest.genesis.timestamp + 600
      )
      assert.is_true(find_valid_nonce(header))

      -- This header won't match the checkpoint hash
      local ok, err = chain:accept_header(header)
      assert.is_false(ok)
      assert.is_truthy(err:match("checkpoint mismatch"))
    end)
  end)

  describe("work calculation", function()
    local storage, chain

    before_each(function()
      storage = create_mock_storage()
      chain = sync.new_header_chain(consensus.networks.regtest, storage)
      chain:init()
    end)

    it("calculates positive work for valid bits", function()
      local work = chain:work_for_bits(0x1d00ffff)  -- mainnet genesis difficulty
      assert.is_true(work > 0)
      assert.is_true(work < math.huge)
    end)

    it("returns higher work for lower target (higher difficulty)", function()
      local easy_work = chain:work_for_bits(0x207fffff)   -- regtest (easy)
      local hard_work = chain:work_for_bits(0x1d00ffff)   -- mainnet genesis (harder)

      assert.is_true(hard_work > easy_work)
    end)

    it("accumulates total work as chain grows", function()
      local genesis_entry = chain:get_header_at_height(0)
      local genesis_work = genesis_entry.total_work

      -- Add a block
      local parent_hash = chain:get_tip_hash()
      local header = create_valid_header(
        parent_hash,
        consensus.networks.regtest.genesis.timestamp + 600
      )
      assert.is_true(find_valid_nonce(header))
      chain:accept_header(header)

      local block1_entry = chain:get_header_at_height(1)
      assert.is_true(block1_entry.total_work > genesis_work)
    end)
  end)

  describe("sync controller", function()
    local storage, chain

    -- Mock peer
    local function create_mock_peer()
      local peer = {
        messages_sent = {}
      }

      function peer:send_message(cmd, payload)
        self.messages_sent[#self.messages_sent + 1] = {
          command = cmd,
          payload = payload
        }
      end

      return peer
    end

    before_each(function()
      storage = create_mock_storage()
      chain = sync.new_header_chain(consensus.networks.regtest, storage)
      chain:init()
    end)

    it("starts sync by sending getheaders", function()
      local peer = create_mock_peer()
      chain:start_sync(peer)

      assert.is_true(chain:is_syncing())
      assert.equals(peer, chain:get_sync_peer())
      assert.equals(1, #peer.messages_sent)
      assert.equals("getheaders", peer.messages_sent[1].command)
    end)

    it("handles empty headers response (sync complete)", function()
      local peer = create_mock_peer()
      chain:start_sync(peer)

      -- Empty headers payload
      local payload = p2p.serialize_headers({})
      local accepted = chain:handle_headers(peer, payload)

      assert.equals(0, accepted)
      assert.is_false(chain:is_syncing())
      assert.is_nil(chain:get_sync_peer())
    end)

    it("handles headers and continues if batch is full", function()
      local peer = create_mock_peer()
      chain:start_sync(peer)

      -- Create a batch of valid headers
      local headers = {}
      local parent_hash = chain:get_tip_hash()
      local timestamp = consensus.networks.regtest.genesis.timestamp

      -- Create 5 headers (in real scenario would be 2000)
      for i = 1, 5 do
        timestamp = timestamp + 600
        local header = create_valid_header(parent_hash, timestamp)
        assert.is_true(find_valid_nonce(header))
        headers[i] = header
        parent_hash = validation.compute_block_hash(header)
      end

      local payload = p2p.serialize_headers(headers)
      local accepted = chain:handle_headers(peer, payload)

      assert.equals(5, accepted)
      -- Less than 2000, so sync should be complete
      assert.is_false(chain:is_syncing())
    end)

    it("stops sync on invalid headers", function()
      local peer = create_mock_peer()
      chain:start_sync(peer)

      -- Create invalid header (bad PoW)
      local bad_header = types.block_header(
        1,
        chain:get_tip_hash(),
        types.hash256_zero(),
        os.time(),
        0x03000001,  -- impossible difficulty
        0
      )

      local payload = p2p.serialize_headers({bad_header})
      local accepted, err = chain:handle_headers(peer, payload)

      assert.equals(-1, accepted)
      assert.is_truthy(err)
    end)

    it("can stop sync manually", function()
      local peer = create_mock_peer()
      chain:start_sync(peer)

      assert.is_true(chain:is_syncing())

      chain:stop_sync()

      assert.is_false(chain:is_syncing())
      assert.is_nil(chain:get_sync_peer())
    end)
  end)

  describe("header_tip vs chain_tip separation", function()
    it("uses separate storage keys for header_tip and chain_tip", function()
      local storage = create_mock_storage()
      local chain = sync.new_header_chain(consensus.networks.regtest, storage)
      chain:init()

      -- The header_tip should be stored
      local header_tip_data = storage.get("meta", "header_tip")
      assert.is_not_nil(header_tip_data)
      assert.equals(36, #header_tip_data)  -- 32 bytes hash + 4 bytes height

      -- chain_tip should NOT be set by header sync
      local chain_tip_data = storage.get("meta", "chain_tip")
      assert.is_nil(chain_tip_data)
    end)
  end)
end)
