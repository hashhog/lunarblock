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
  -- W85: version 4 is required because regtest activates BIP65 + BIP66 from
  -- height 0 (bip65_height=0, bip66_height=0), so any block after genesis must
  -- carry nVersion >= 4 to pass the bad-version contextual check.
  local function create_valid_header(parent_hash, timestamp, bits, version)
    bits = bits or 0x207fffff  -- regtest difficulty
    timestamp = timestamp or os.time()
    version = version or 4  -- must be >= 4 on regtest (BIP65/66 active from h=0)
    return types.block_header(
      version,
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
      assert.equals("time-too-old", err)
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

    -- W85: time-too-new gate (MAX_FUTURE_BLOCK_TIME = 7200s)
    -- Bitcoin Core validation.cpp:4108-4110, chain.h:29
    it("rejects header more than 2 hours in the future (time-too-new)", function()
      local far_future = os.time() + consensus.MAX_FUTURE_BLOCK_TIME + 10
      local header = create_valid_header(genesis_hash, far_future)
      assert.is_true(find_valid_nonce(header))

      local ok, err = chain:accept_header(header)
      assert.is_false(ok)
      assert.equals("time-too-new", err)
    end)

    -- W85: boundary — exactly at MAX_FUTURE_BLOCK_TIME should still be accepted
    it("accepts header at exactly MAX_FUTURE_BLOCK_TIME boundary", function()
      local boundary = os.time() + consensus.MAX_FUTURE_BLOCK_TIME
      local header = create_valid_header(genesis_hash, boundary)
      assert.is_true(find_valid_nonce(header))

      local ok, _ = chain:accept_header(header)
      assert.is_true(ok)
    end)

    -- Helper: build a minimal test network with easy PoW and specific soft-fork heights.
    -- bv_net(bip34_h, bip66_h, bip65_h) produces a regtest-like network where only
    -- the specified heights activate BIP34/66/65.  Using large values (e.g. 999999)
    -- means those deployments stay inactive throughout the test.
    local function bv_net(bip34_h, bip66_h, bip65_h)
      return {
        name = "bvtest",
        magic_bytes = consensus.networks.regtest.magic_bytes,
        port = 18444, rpc_port = 18443,
        pubkey_address_prefix = 0x6F, script_address_prefix = 0xC4,
        wif_prefix = 0xEF, bech32_hrp = "bcrt",
        genesis = consensus.networks.regtest.genesis,
        genesis_hash = consensus.networks.regtest.genesis_hash,
        checkpoints = { [0] = consensus.networks.regtest.genesis_hash },
        bip34_height = bip34_h, bip65_height = bip65_h, bip66_height = bip66_h,
        csv_height = 999999, segwit_height = 999999, taproot_height = 999999,
        pow_limit_bits = 0x207fffff, pow_no_retarget = true,
        pow_allow_min_difficulty = false, enforce_bip94 = false,
        min_chain_work = "0000000000000000000000000000000000000000000000000000000000000000",
        assumevalid = nil, versionbits_period = 2016, versionbits_threshold = 1512,
        dns_seeds = {}, assumeutxo = {}
      }
    end

    -- Helper: mine one header at regtest easy difficulty.
    local function mine_header(version, parent_hash, timestamp, bits)
      bits = bits or 0x207fffff
      local h = types.block_header(version, parent_hash, types.hash256_zero(),
        timestamp, bits, 0)
      local target = consensus.bits_to_target(bits)
      for nonce = 0, 1000000 do
        h.nonce = nonce
        if consensus.hash_meets_target(validation.compute_block_hash(h).bytes, target) then
          return h
        end
      end
      return nil  -- should never happen with 0x207fffff
    end

    -- W85: bad-version gate — nVersion < 2 rejected after BIP34 activation.
    -- Bitcoin Core validation.cpp:4113-4118.
    -- Network: bip34 activates at height 1, bip65+66 disabled (height 999999).
    -- At height 1 (prev.height=0): v1 passes (0 < 1 → BIP34 not yet active).
    -- At height 2 (prev.height=1): v1 rejected (1 >= 1 → BIP34 active after prev).
    it("rejects nVersion < 2 after BIP34 activation (bad-version)", function()
      local net = bv_net(1, 999999, 999999)
      local st = helpers.mock_storage()
      local ch = sync.new_header_chain(net, st)
      ch:init()
      local ts = consensus.networks.regtest.genesis.timestamp

      -- h=1: v4, passes (bip34 not active yet: prev.height=0 < 1)
      local h1 = mine_header(4, ch:get_tip_hash(), ts + 600)
      local ok1, e1 = ch:accept_header(h1)
      assert.is_true(ok1, "h=1 v4 should pass: " .. tostring(e1))

      -- h=2: v1, rejected (bip34 active: prev.height=1 >= 1)
      local h2 = mine_header(1, ch:get_tip_hash(), ts + 1200)
      local ok2, e2 = ch:accept_header(h2)
      assert.is_false(ok2)
      assert.is_truthy(e2 and e2:match("bad%-version"),
        "expected bad-version, got: " .. tostring(e2))
    end)

    -- W85: bad-version gate — nVersion < 3 rejected after BIP66 (DERSIG) activation.
    -- Network: bip66 activates at height 1, bip34+65 disabled (height 999999).
    -- v2 block at height 2 is rejected (prev.height=1 >= bip66_height=1).
    it("rejects nVersion < 3 after BIP66 activation (bad-version)", function()
      local net = bv_net(999999, 1, 999999)
      local st = helpers.mock_storage()
      local ch = sync.new_header_chain(net, st)
      ch:init()
      local ts = consensus.networks.regtest.genesis.timestamp

      -- h=1: v4, passes
      local h1 = mine_header(4, ch:get_tip_hash(), ts + 600)
      assert.is_true(ch:accept_header(h1))

      -- h=2: v2, rejected
      local h2 = mine_header(2, ch:get_tip_hash(), ts + 1200)
      local ok2, e2 = ch:accept_header(h2)
      assert.is_false(ok2)
      assert.is_truthy(e2 and e2:match("bad%-version"),
        "expected bad-version, got: " .. tostring(e2))
    end)

    -- W85: bad-version gate — nVersion < 4 rejected after BIP65 (CLTV) activation.
    -- Network: bip65 activates at height 1, bip34+66 disabled.
    -- v3 block at height 2 is rejected (prev.height=1 >= bip65_height=1).
    it("rejects nVersion < 4 after BIP65 activation (bad-version)", function()
      local net = bv_net(999999, 999999, 1)
      local st = helpers.mock_storage()
      local ch = sync.new_header_chain(net, st)
      ch:init()
      local ts = consensus.networks.regtest.genesis.timestamp

      -- h=1: v4, passes
      local h1 = mine_header(4, ch:get_tip_hash(), ts + 600)
      assert.is_true(ch:accept_header(h1))

      -- h=2: v3, rejected
      local h2 = mine_header(3, ch:get_tip_hash(), ts + 1200)
      local ok2, e2 = ch:accept_header(h2)
      assert.is_false(ok2)
      assert.is_truthy(e2 and e2:match("bad%-version"),
        "expected bad-version, got: " .. tostring(e2))
    end)

    -- W85: bad-version gate — nVersion >= 4 is always accepted (no higher gate).
    it("accepts nVersion = 4 even after all soft-fork activations", function()
      local net = bv_net(1, 1, 1)  -- all active from h=1
      local st = helpers.mock_storage()
      local ch = sync.new_header_chain(net, st)
      ch:init()
      local ts = consensus.networks.regtest.genesis.timestamp

      local h1 = mine_header(4, ch:get_tip_hash(), ts + 600)
      local ok1, e1 = ch:accept_header(h1)
      assert.is_true(ok1, "v4 should always pass: " .. tostring(e1))
    end)

    -- Helper: build a minimal network for timewarp tests.
    -- pow_no_retarget=true keeps the difficulty constant (prevents bad-diffbits
    -- from firing due to the retarget calculation at height%2016).
    -- BIP34/65/66 heights are set to 999999 to isolate the timewarp gate.
    local function tw_net_make(name)
      return {
        name = name or "tw_test",
        magic_bytes = consensus.networks.regtest.magic_bytes,
        port = 18444, rpc_port = 18443,
        pubkey_address_prefix = 0x6F, script_address_prefix = 0xC4,
        wif_prefix = 0xEF, bech32_hrp = "bcrt",
        genesis = consensus.networks.regtest.genesis,
        genesis_hash = consensus.networks.regtest.genesis_hash,
        checkpoints = { [0] = consensus.networks.regtest.genesis_hash },
        bip34_height = 999999, bip65_height = 999999, bip66_height = 999999,
        csv_height = 999999, segwit_height = 999999, taproot_height = 999999,
        pow_limit_bits = 0x207fffff,
        pow_no_retarget = true,      -- constant difficulty; no retarget at h%2016
        pow_allow_min_difficulty = false,
        enforce_bip94 = true,        -- timewarp gate active
        min_chain_work = "0000000000000000000000000000000000000000000000000000000000000000",
        assumevalid = nil, versionbits_period = 2016, versionbits_threshold = 1512,
        dns_seeds = {}, assumeutxo = {}
      }
    end

    -- Helper: inject a fake ancestor at the given height into a chain's header
    -- table.  Used to set up h=2015 without mining 2015 PoW blocks.
    local function inject_chain_segment(ch, start_height, end_height, base_ts, base_bits, prev_hash)
      -- Inject heights start_height..end_height (inclusive) in descending order,
      -- patching each block's prev_hash to point to the one below it.
      local cur_prevhash = prev_hash  -- the prev-hash of start_height block
      local entries = {}
      for h = start_height, end_height do
        -- Unique bytes: combine height into a recognizable pattern
        local b = string.rep(string.char((h * 7 + 13) % 251 + 1), 32)
        local hash = types.hash256(b)
        local hex = types.hash256_hex(hash)
        entries[h] = { hash = hash, hex = hex }
        ch.headers[hex] = {
          header = {
            version = 4,
            prev_hash = cur_prevhash,
            merkle_root = types.hash256_zero(),
            timestamp = base_ts + h * 600,
            bits = base_bits, nonce = 0,
          },
          height = h, total_work = h,
        }
        ch.height_to_hash[h] = hex
        cur_prevhash = hash
      end
      return entries
    end

    -- W85: BIP94 timewarp check at height 2016 on a network with enforce_bip94=true.
    -- Bitcoin Core validation.cpp:4097-4105, consensus/consensus.h:35.
    -- We white-box inject a fake height-2015 ancestor so we can test the gate
    -- without mining 2015 real PoW blocks.
    it("rejects BIP94 timewarp attack at difficulty adjustment height (time-timewarp-attack)", function()
      local tw_net = tw_net_make("tw_test1")

      local tw_storage = helpers.mock_storage()
      local tw_storage = helpers.mock_storage()
      local tw_chain = sync.new_header_chain(tw_net, tw_storage)
      tw_chain:init()
      local base_ts = consensus.networks.regtest.genesis.timestamp

      -- Inject heights 1..2015 so the MTP window around 2015 is populated.
      -- inject_chain_segment returns the hash of each injected block.
      inject_chain_segment(tw_chain, 1, 2015, base_ts, 0x207fffff, tw_chain:get_tip_hash())

      -- The fake h=2015 block has timestamp base_ts + 2015*600.
      local prev_ts = base_ts + 2015 * 600
      local fake_h2015_hex = tw_chain.height_to_hash[2015]
      local fake_h2015_hash = types.hash256(tw_chain.headers[fake_h2015_hex].header.prev_hash.bytes)
      -- Actually get the hash of h=2015 from the injected table
      fake_h2015_hash = types.hash256(string.rep(string.char((2015 * 7 + 13) % 251 + 1), 32))

      -- Build height-2016 header with timestamp < prev_ts - MAX_TIMEWARP → rejected.
      -- The timewarp check fires because: enforce_bip94=true AND 2016%2016==0.
      local timewarp_ts = prev_ts - consensus.MAX_TIMEWARP - 1
      local tw_target = consensus.bits_to_target(0x207fffff)
      local tw_header = types.block_header(4, fake_h2015_hash, types.hash256_zero(),
        timewarp_ts, 0x207fffff, 0)
      -- Mining at regtest difficulty (0x207fffff) — nonce 0 is usually sufficient.
      for nonce = 0, 1000000 do
        tw_header.nonce = nonce
        if consensus.hash_meets_target(validation.compute_block_hash(tw_header).bytes, tw_target) then break end
      end

      local ok, err = tw_chain:accept_header(tw_header)
      assert.is_false(ok)
      assert.equals("time-timewarp-attack", err)
    end)

    -- W85: BIP94 timewarp boundary — exactly at prev_ts - MAX_TIMEWARP passes.
    -- Core condition: block.GetBlockTime() < pindexPrev->GetBlockTime() - MAX_TIMEWARP
    -- "strictly less than", so equality is accepted.
    it("accepts BIP94 timewarp boundary (equal to prev - MAX_TIMEWARP)", function()
      local tw_net = tw_net_make("tw_test2")
      local tw_storage = helpers.mock_storage()
      local tw_chain = sync.new_header_chain(tw_net, tw_storage)
      tw_chain:init()
      local base_ts = consensus.networks.regtest.genesis.timestamp

      inject_chain_segment(tw_chain, 1, 2015, base_ts, 0x207fffff, tw_chain:get_tip_hash())

      local prev_ts = base_ts + 2015 * 600
      local fake_h2015_hash = types.hash256(string.rep(string.char((2015 * 7 + 13) % 251 + 1), 32))

      -- Exactly at boundary: prev_ts - MAX_TIMEWARP (equal, not strictly less).
      local boundary_ts = prev_ts - consensus.MAX_TIMEWARP
      local tw_target = consensus.bits_to_target(0x207fffff)
      local tw_header = types.block_header(4, fake_h2015_hash, types.hash256_zero(),
        boundary_ts, 0x207fffff, 0)
      for nonce = 0, 1000000 do
        tw_header.nonce = nonce
        if consensus.hash_meets_target(validation.compute_block_hash(tw_header).bytes, tw_target) then break end
      end

      local ok, err = tw_chain:accept_header(tw_header)
      assert.is_true(ok, "boundary (equal) should pass, got: " .. tostring(err))
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
