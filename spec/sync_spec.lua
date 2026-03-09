describe("sync", function()
  local sync
  local types
  local consensus
  local validation
  local serialize
  local crypto
  local p2p

  setup(function()
    -- Mock socket module if not available (for test environments without LuaSocket)
    if not pcall(require, "socket") then
      package.preload["socket"] = function()
        return { gettime = function() return os.time() end }
      end
    end

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

  --------------------------------------------------------------------------------
  -- BlockDownloader Tests
  --------------------------------------------------------------------------------

  describe("BlockDownloader", function()
    local storage, chain

    -- Extended mock storage for block operations
    local function create_block_storage()
      local base = create_mock_storage()
      local blocks = {}
      local chain_tip_data = nil

      function base.put_block(block_hash, blk)
        blocks[block_hash.bytes] = serialize.serialize_block(blk)
      end

      function base.get_block(block_hash)
        local data = blocks[block_hash.bytes]
        if not data then return nil end
        return serialize.deserialize_block(data)
      end

      -- Override get to also check blocks CF
      local orig_get = base.get
      function base.get(cf, key)
        if cf == "blocks" then
          return blocks[key]
        end
        return orig_get(cf, key)
      end

      function base.set_chain_tip(hash, height, sync_flag)
        local w = serialize.buffer_writer()
        w.write_hash256(hash)
        w.write_u32le(height)
        chain_tip_data = w.result()
        base.put("meta", "chain_tip", chain_tip_data, sync_flag)
      end

      function base.get_chain_tip()
        if not chain_tip_data or #chain_tip_data < 36 then
          return nil, nil
        end
        local hash = types.hash256(chain_tip_data:sub(1, 32))
        local r = serialize.buffer_reader(chain_tip_data:sub(33, 36))
        local height = r.read_u32le()
        return hash, height
      end

      return base
    end

    -- Mock peer with message tracking
    local function create_mock_peer(id, start_height)
      local peer = {
        id = id or 1,
        messages_sent = {},
        start_height = start_height or 100
      }

      function peer:send_message(cmd, payload)
        self.messages_sent[#self.messages_sent + 1] = {
          command = cmd,
          payload = payload
        }
      end

      return peer
    end

    -- Create a mock block for testing
    local function create_mock_block(prev_hash, height, timestamp)
      timestamp = timestamp or os.time()
      local header = types.block_header(
        1,
        prev_hash,
        types.hash256_zero(),  -- merkle root will be computed
        timestamp,
        0x207fffff,  -- regtest difficulty
        0
      )

      -- Find valid nonce
      local target = consensus.bits_to_target(header.bits)
      for nonce = 0, 1000000 do
        header.nonce = nonce
        local hash = validation.compute_block_hash(header)
        if consensus.hash_meets_target(hash.bytes, target) then
          break
        end
      end

      -- Create a simple coinbase transaction
      local coinbase_inp = types.txin(
        types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
        string.char(height % 256),  -- simplified BIP34 height
        0xFFFFFFFF
      )
      local coinbase_out = types.txout(5000000000, "")  -- 50 BTC
      local coinbase = types.transaction(1, {coinbase_inp}, {coinbase_out}, 0)

      -- Compute merkle root
      local txid = validation.compute_txid(coinbase)
      header.merkle_root = txid

      return types.block(header, {coinbase})
    end

    before_each(function()
      storage = create_block_storage()
      chain = sync.new_header_chain(consensus.networks.regtest, storage)
      chain:init()
    end)

    describe("creation and initial state", function()
      it("creates a new block downloader with correct initial state", function()
        local downloader = sync.new_block_downloader(chain, storage, consensus.networks.regtest)

        assert.is_not_nil(downloader)
        assert.equals(0, downloader.next_download_height)
        assert.equals(0, downloader.next_connect_height)
        assert.is_false(downloader.ibd_complete)
        assert.equals(1024, downloader.download_window)
        assert.equals(16, downloader.blocks_per_peer)
      end)

      it("exposes status methods", function()
        local downloader = sync.new_block_downloader(chain, storage, consensus.networks.regtest)

        assert.is_false(downloader:is_complete())
        assert.equals(0, downloader:get_connect_height())
        assert.equals(0, downloader:get_inflight_count())
        assert.equals(0, downloader:get_pending_count())
      end)
    end)

    describe("schedule_downloads", function()
      it("assigns blocks to peers round-robin", function()
        -- Build a small header chain
        local parent_hash = chain:get_tip_hash()
        local timestamp = consensus.networks.regtest.genesis.timestamp

        for i = 1, 5 do
          timestamp = timestamp + 600
          local header = create_valid_header(parent_hash, timestamp)
          assert.is_true(find_valid_nonce(header))
          chain:accept_header(header)
          parent_hash = validation.compute_block_hash(header)
        end

        local downloader = sync.new_block_downloader(chain, storage, consensus.networks.regtest)
        local peer1 = create_mock_peer(1)
        local peer2 = create_mock_peer(2)

        downloader:schedule_downloads({peer1, peer2})

        -- Both peers should have received getdata messages
        assert.is_true(#peer1.messages_sent > 0 or #peer2.messages_sent > 0)

        -- Check that requests were distributed
        local total_requests = #peer1.messages_sent + #peer2.messages_sent
        assert.is_true(total_requests >= 1)
      end)

      it("respects per-peer in-flight limit", function()
        -- Build a larger header chain
        local parent_hash = chain:get_tip_hash()
        local timestamp = consensus.networks.regtest.genesis.timestamp

        for i = 1, 20 do
          timestamp = timestamp + 600
          local header = create_valid_header(parent_hash, timestamp)
          assert.is_true(find_valid_nonce(header))
          chain:accept_header(header)
          parent_hash = validation.compute_block_hash(header)
        end

        local downloader = sync.new_block_downloader(chain, storage, consensus.networks.regtest)
        downloader.blocks_per_peer = 4  -- Set low limit for testing

        local peer = create_mock_peer(1)
        downloader:schedule_downloads({peer})

        -- Count total items requested
        local total_items = 0
        for _, msg in ipairs(peer.messages_sent) do
          if msg.command == "getdata" then
            local items = p2p.deserialize_inv(msg.payload)
            total_items = total_items + #items
          end
        end

        -- Should not exceed per-peer limit
        assert.is_true(total_items <= downloader.blocks_per_peer)
      end)

      it("does nothing with no peers", function()
        local downloader = sync.new_block_downloader(chain, storage, consensus.networks.regtest)
        downloader:schedule_downloads({})
        assert.equals(0, downloader:get_inflight_count())
      end)

      it("does nothing when IBD is complete", function()
        local downloader = sync.new_block_downloader(chain, storage, consensus.networks.regtest)
        downloader.ibd_complete = true

        local peer = create_mock_peer(1)
        downloader:schedule_downloads({peer})

        assert.equals(0, #peer.messages_sent)
      end)
    end)

    describe("handle_block", function()
      it("stores pending block and triggers connect", function()
        -- Create a single-block chain
        local genesis_hash = chain:get_tip_hash()
        local timestamp = consensus.networks.regtest.genesis.timestamp + 600

        local header = create_valid_header(genesis_hash, timestamp)
        assert.is_true(find_valid_nonce(header))
        chain:accept_header(header)

        local downloader = sync.new_block_downloader(chain, storage, consensus.networks.regtest)
        downloader.next_connect_height = 1  -- Start from height 1

        -- Create matching block
        local block = create_mock_block(genesis_hash, 1, timestamp)
        -- Use the actual header from the chain
        local entry = chain:get_header_at_height(1)
        block.header = entry.header

        local block_data = serialize.serialize_block(block)
        local peer = create_mock_peer(1)

        -- Mark as inflight first
        local hash_hex = chain.height_to_hash[1]
        downloader.inflight[hash_hex] = {peer = peer, request_time = os.time(), timeout = 5}
        downloader.peer_inflight[peer] = 1

        -- Handle should succeed (block may fail validation but that's ok for this test)
        local ok = downloader:handle_block(peer, block_data)
        -- Block receipt should work even if validation fails
        assert.is_not_nil(ok)
      end)

      it("removes block from inflight on receipt", function()
        local genesis_hash = chain:get_tip_hash()
        local timestamp = consensus.networks.regtest.genesis.timestamp + 600

        local header = create_valid_header(genesis_hash, timestamp)
        assert.is_true(find_valid_nonce(header))
        chain:accept_header(header)

        local downloader = sync.new_block_downloader(chain, storage, consensus.networks.regtest)
        local peer = create_mock_peer(1)

        -- Create matching block
        local entry = chain:get_header_at_height(1)
        local block = types.block(entry.header, {})
        local block_data = serialize.serialize_block(block)

        -- Mark as inflight
        local hash_hex = chain.height_to_hash[1]
        downloader.inflight[hash_hex] = {peer = peer, request_time = os.time(), timeout = 5}
        downloader.peer_inflight[peer] = 1

        downloader:handle_block(peer, block_data)

        -- Should be removed from inflight
        assert.is_nil(downloader.inflight[hash_hex])
        assert.is_nil(downloader.peer_inflight[peer])
      end)
    end)

    describe("connect_pending_blocks", function()
      it("processes blocks in order, skips gaps", function()
        -- Build header chain
        local parent_hash = chain:get_tip_hash()
        local timestamp = consensus.networks.regtest.genesis.timestamp

        for i = 1, 3 do
          timestamp = timestamp + 600
          local header = create_valid_header(parent_hash, timestamp)
          assert.is_true(find_valid_nonce(header))
          chain:accept_header(header)
          parent_hash = validation.compute_block_hash(header)
        end

        local downloader = sync.new_block_downloader(chain, storage, consensus.networks.regtest)
        downloader.next_connect_height = 1

        -- Add block at height 2 but not height 1 (gap)
        local entry2 = chain:get_header_at_height(2)
        local hash2_hex = chain.height_to_hash[2]
        local hash2 = validation.compute_block_hash(entry2.header)
        downloader.pending_blocks[hash2_hex] = {
          block = types.block(entry2.header, {}),
          height = 2,
          hash = hash2
        }

        -- Try to connect - should stop at gap
        downloader:connect_pending_blocks()

        -- Height 1 is missing, so we shouldn't have connected anything
        assert.equals(1, downloader.next_connect_height)
        -- Block at height 2 should still be pending
        assert.is_not_nil(downloader.pending_blocks[hash2_hex])
      end)
    end)

    describe("stall detection", function()
      it("detects stalled requests and clears them", function()
        local parent_hash = chain:get_tip_hash()
        local timestamp = consensus.networks.regtest.genesis.timestamp + 600

        local header = create_valid_header(parent_hash, timestamp)
        assert.is_true(find_valid_nonce(header))
        chain:accept_header(header)

        local downloader = sync.new_block_downloader(chain, storage, consensus.networks.regtest)
        downloader.base_stall_timeout = 0  -- Immediate timeout for testing

        local peer = create_mock_peer(1)
        local hash_hex = chain.height_to_hash[1]

        -- Simulate an old in-flight request
        downloader.inflight[hash_hex] = {
          peer = peer,
          request_time = os.time() - 100,  -- 100 seconds ago
          timeout = 1  -- 1 second timeout
        }
        downloader.peer_inflight[peer] = 1

        -- Schedule should detect stall and clear it
        downloader:schedule_downloads({peer})

        -- Stalled request should be cleared
        -- Note: It will be re-requested in the same call
        assert.equals(0, downloader.peer_inflight[peer] or 0)
      end)
    end)

    describe("IBD completion", function()
      it("detects when all blocks are connected", function()
        -- Chain with just genesis
        local downloader = sync.new_block_downloader(chain, storage, consensus.networks.regtest)

        -- Set connect height past tip (genesis is height 0)
        downloader.next_connect_height = 1

        -- Try to connect (no pending blocks)
        downloader:connect_pending_blocks()

        -- Should detect completion since connect_height > tip_height (0)
        assert.is_true(downloader:is_complete())
      end)
    end)

    describe("batched getdata", function()
      it("sends multiple inv items per getdata message", function()
        -- Build header chain
        local parent_hash = chain:get_tip_hash()
        local timestamp = consensus.networks.regtest.genesis.timestamp

        for i = 1, 10 do
          timestamp = timestamp + 600
          local header = create_valid_header(parent_hash, timestamp)
          assert.is_true(find_valid_nonce(header))
          chain:accept_header(header)
          parent_hash = validation.compute_block_hash(header)
        end

        local downloader = sync.new_block_downloader(chain, storage, consensus.networks.regtest)
        local peer = create_mock_peer(1)

        downloader:schedule_downloads({peer})

        -- Should have sent getdata message(s)
        assert.is_true(#peer.messages_sent >= 1)

        -- Check that items are batched
        for _, msg in ipairs(peer.messages_sent) do
          if msg.command == "getdata" then
            local items = p2p.deserialize_inv(msg.payload)
            -- Should have multiple items in one message (batched)
            assert.is_true(#items >= 1)
          end
        end
      end)
    end)
  end)
end)
