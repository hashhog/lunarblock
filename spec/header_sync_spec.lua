--- Header synchronization integration tests
-- Tests header chain initialization, validation, and sync workflows

local helpers = require("spec.helpers")

describe("header sync", function()
  local sync
  local types
  local consensus
  local validation
  local p2p
  local serialize
  local crypto

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

  -- Create a valid header extending from a parent (regtest difficulty)
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

  describe("chain initialization", function()
    it("initializes with genesis block", function()
      local storage = helpers.mock_storage()
      local chain = sync.new_header_chain(consensus.networks.regtest, storage)
      chain:init()

      assert.equals(0, chain:get_tip_height())
      assert.is_not_nil(chain:get_tip_hash())
    end)

    it("genesis header has correct regtest parameters", function()
      local storage = helpers.mock_storage()
      local chain = sync.new_header_chain(consensus.networks.regtest, storage)
      chain:init()

      local genesis_entry = chain:get_header_at_height(0)
      assert.is_not_nil(genesis_entry)
      assert.equals(0, genesis_entry.height)
      assert.equals(consensus.networks.regtest.genesis.timestamp, genesis_entry.header.timestamp)
      assert.equals(consensus.networks.regtest.genesis.bits, genesis_entry.header.bits)
    end)

    it("stores genesis in database during init", function()
      local storage = helpers.mock_storage()
      local chain = sync.new_header_chain(consensus.networks.regtest, storage)
      chain:init()

      local tip_hash = chain:get_tip_hash()
      local stored_header = storage.get_header(tip_hash)
      assert.is_not_nil(stored_header)
      assert.equals(consensus.networks.regtest.genesis.timestamp, stored_header.timestamp)
    end)
  end)

  describe("header acceptance", function()
    local storage, chain, genesis_hash

    before_each(function()
      storage = helpers.mock_storage()
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

      local ok1, _ = chain:accept_header(header)
      assert.is_true(ok1)

      -- Accept second time - should succeed but not increase height
      local ok2, _ = chain:accept_header(header)
      assert.is_true(ok2)
      assert.equals(1, chain:get_tip_height())
    end)
  end)

  describe("block locator", function()
    local storage, chain

    before_each(function()
      storage = helpers.mock_storage()
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
      -- Should have exponential backoff
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

  describe("getheaders message", function()
    local storage, chain

    before_each(function()
      storage = helpers.mock_storage()
      chain = sync.new_header_chain(consensus.networks.regtest, storage)
      chain:init()
    end)

    it("serializes getheaders with locator", function()
      local locator = chain:get_block_locator()
      local stop_hash = types.hash256_zero()

      local payload = p2p.serialize_getheaders(p2p.PROTOCOL_VERSION, locator, stop_hash)
      assert.is_not_nil(payload)
      assert.is_true(#payload > 0)
    end)
  end)

  describe("sync controller", function()
    local storage, chain

    before_each(function()
      storage = helpers.mock_storage()
      chain = sync.new_header_chain(consensus.networks.regtest, storage)
      chain:init()
    end)

    it("starts sync by sending getheaders", function()
      local peer = helpers.mock_peer()
      chain:start_sync(peer)

      assert.is_true(chain:is_syncing())
      assert.equals(peer, chain:get_sync_peer())
      assert.equals(1, #peer.sent)
      assert.equals("getheaders", peer.sent[1].command)
    end)

    it("handles empty headers response (sync complete)", function()
      local peer = helpers.mock_peer()
      chain:start_sync(peer)

      -- Empty headers payload
      local payload = p2p.serialize_headers({})
      local accepted = chain:handle_headers(peer, payload)

      assert.equals(0, accepted)
      assert.is_false(chain:is_syncing())
      assert.is_nil(chain:get_sync_peer())
    end)

    it("handles valid headers batch", function()
      local peer = helpers.mock_peer()
      chain:start_sync(peer)

      -- Create valid headers
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

      local payload = p2p.serialize_headers(headers)
      local accepted = chain:handle_headers(peer, payload)

      assert.equals(5, accepted)
      -- Less than 2000, so sync should be complete
      assert.is_false(chain:is_syncing())
    end)

    it("stops sync on invalid headers", function()
      local peer = helpers.mock_peer()
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
      local peer = helpers.mock_peer()
      chain:start_sync(peer)

      assert.is_true(chain:is_syncing())

      chain:stop_sync()

      assert.is_false(chain:is_syncing())
      assert.is_nil(chain:get_sync_peer())
    end)
  end)

  describe("work calculation", function()
    local storage, chain

    before_each(function()
      storage = helpers.mock_storage()
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

  describe("header_tip vs chain_tip separation", function()
    it("uses separate storage keys for header_tip and chain_tip", function()
      local storage = helpers.mock_storage()
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
