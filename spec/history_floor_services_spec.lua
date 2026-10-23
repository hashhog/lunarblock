-- spec/history_floor_services_spec.lua
--
-- A node that bootstrapped from a UTXO snapshot holds no block bodies below
-- the snapshot base.  Bitcoin Core v31.1, measured on regtest
-- (loadtxoutset @299, bodies 1..299 never fetched, then restarted):
--
--   getblock(pre-base or base) -> -1 "Block not available (not fully downloaded)"
--   getblockchaininfo          -> pruned:false, no pruneheight
--   getchainstates             -> snapshot chainstate carries snapshot_blockhash
--                                 and validated:false
--   localservices              -> 0xc08 (WITNESS|NETWORK_LIMITED|P2P_V2): no
--                                 NODE_NETWORK, before and after a restart;
--                                 peers see the same value in `version`
--
-- Core: rpc/blockchain.cpp CheckBlockDataAvailability (~670), loadtxoutset
-- (~3432 RemoveLocalServices(NODE_NETWORK)), init.cpp:1947 (NODE_NETWORK only
-- when not pruning and no historical chainstate), init.cpp:1368 (re-added when
-- the background download completes).
--
-- These tests drive the real handlers: the version message the peer actually
-- writes to its socket, getnetworkinfo/getblock/getchainstates through
-- RPCServer:handle_request, and the loadtxoutset RPC on a real chainstate.

local bit         = require("bit")
local cjson       = require("cjson")
local types       = require("lunarblock.types")
local consensus   = require("lunarblock.consensus")
local p2p         = require("lunarblock.p2p")
local peer_module = require("lunarblock.peer")
local rpc         = require("lunarblock.rpc")
local storage_mod = require("lunarblock.storage")
local serialize   = require("lunarblock.serialize")
local utxo        = require("lunarblock.utxo")
local validation  = require("lunarblock.validation")
local script      = require("lunarblock.script")

local NETWORK = p2p.SERVICES.NODE_NETWORK
local LIMITED = p2p.SERVICES.NODE_NETWORK_LIMITED
local WITNESS = p2p.SERVICES.NODE_WITNESS

local regtest = consensus.networks.regtest

-- The process-wide "history below the snapshot base is missing" gate.  Called
-- through a guard so that, on a tree without the gate, every test still runs
-- and fails on its own assertion instead of erroring in setup.
local function set_history_incomplete(v)
  if p2p.set_history_incomplete then p2p.set_history_incomplete(v) end
end

local function call(server, method, params)
  local raw = server:handle_request(cjson.encode({
    method = method, params = params or {}, id = 1 }))
  return cjson.decode(raw)
end

-- Capture every byte the peer writes; v1 transport so the frame is
-- 24-byte header + payload.
local function capture_socket()
  local sent = {}
  local sock = setmetatable({}, {
    __index = function(_, key)
      if key == "send" then
        return function(_, data) sent[#sent + 1] = data; return #data end
      end
      if key == "receive" then
        return function() return nil, "timeout", "" end
      end
      if key == "close" then return function() end end
      if key == "settimeout" then return function() end end
    end,
  })
  return sock, sent
end

local function sent_version_services(sent)
  for _, frame in ipairs(sent) do
    if #frame >= 24 and frame:sub(5, 11) == "version" then
      return p2p.deserialize_version(frame:sub(25)).services
    end
  end
  error("no version message was sent")
end

-- Header-only regtest chain 1..n on top of the real genesis, stored the way a
-- snapshot node stores it: headers + height index, NO block bodies.
local function header_only_store(n)
  local db = storage_mod.new_memory_storage()
  local T0 = 1296688602
  local g = types.block_header(1, types.hash256_zero(), types.hash256_zero(),
    T0, regtest.pow_limit_bits, 2)
  local prev = validation.compute_block_hash(g)
  db.put_header(prev, g)
  db.put_height_index(0, prev)
  local hashes = { [0] = prev }
  for h = 1, n do
    local hdr = types.block_header(1, prev, types.hash256_zero(),
      T0 + h, regtest.pow_limit_bits, h)
    local hh = validation.compute_block_hash(hdr)
    db.put_header(hh, hdr)
    db.put_height_index(h, hh)
    hashes[h] = hh
    prev = hh
  end
  return db, hashes
end

local function put_snapshot_base(db, height)
  local w = serialize.buffer_writer()
  w.write_u32le(height)
  db.put(db.CF.META, "snapshot_base_height", w.result(), true)
end

describe("history floor: a snapshot node answers like Core", function()
  after_each(function()
    set_history_incomplete(false)
  end)

  describe("service bits", function()
    it("a genesis-synced node still advertises NODE_NETWORK (0xc09)", function()
      set_history_incomplete(false)
      assert.equal(0xc09, p2p.our_services(false, false, nil))
    end)

    it("a node missing history below its snapshot base drops NODE_NETWORK, keeps NODE_NETWORK_LIMITED (0xc08)", function()
      set_history_incomplete(true)
      local s = p2p.our_services(false, false, nil)
      assert.equal(0, bit.band(s, NETWORK))
      assert.is_true(bit.band(s, LIMITED) ~= 0)
      assert.is_true(bit.band(s, WITNESS) ~= 0)
      assert.equal(0xc08, s)
    end)

    it("a pruning node drops NODE_NETWORK too (Core init.cpp:1947)", function()
      set_history_incomplete(false)
      assert.equal(0xc08, p2p.our_services(false, true, nil))
    end)

    it("the outbound version message carries the services without NODE_NETWORK", function()
      set_history_incomplete(true)
      local p = peer_module.new("127.0.0.1", 18444, regtest, 299, false)
      local sock, sent = capture_socket()
      p.socket = sock
      p.state = peer_module.STATE.CONNECTED
      p:start_handshake()
      local services = sent_version_services(sent)
      assert.equal(0, bit.band(services, NETWORK))
      assert.is_true(bit.band(services, LIMITED) ~= 0)
    end)

    it("the inbound version reply carries the services without NODE_NETWORK", function()
      set_history_incomplete(true)
      local p = peer_module.new("127.0.0.1", 18444, regtest, 299, false)
      local sock, sent = capture_socket()
      p.socket = sock
      p.inbound = true
      p.state = peer_module.STATE.CONNECTED
      p:handle_version(p2p.serialize_version({
        version = p2p.PROTOCOL_VERSION, services = 0xc09, timestamp = os.time(),
        recv_services = 0, recv_ip = "127.0.0.1", recv_port = 18444,
        from_services = 0xc09, from_ip = "127.0.0.1", from_port = 18445,
        nonce = 42, user_agent = "/test/", start_height = 0,
      }))
      local services = sent_version_services(sent)
      assert.equal(0, bit.band(services, NETWORK))
      assert.is_true(bit.band(services, LIMITED) ~= 0)
    end)

    it("getnetworkinfo localservices is 0xc08 without NETWORK while history is missing", function()
      set_history_incomplete(true)
      local server = rpc.new({ network = regtest,
        chain_state = { tip_height = 0, tip_hash = types.hash256_zero() } })
      local r = call(server, "getnetworkinfo").result
      assert.equal("0000000000000c08", r.localservices)
      assert.same({ "WITNESS", "NETWORK_LIMITED", "P2P_V2" }, r.localservicesnames)
    end)

    it("getnetworkinfo localservices stays 0xc09 on a genesis-synced node", function()
      set_history_incomplete(false)
      local server = rpc.new({ network = regtest,
        chain_state = { tip_height = 0, tip_hash = types.hash256_zero() } })
      local r = call(server, "getnetworkinfo").result
      assert.equal("0000000000000c09", r.localservices)
      assert.same({ "NETWORK", "WITNESS", "NETWORK_LIMITED", "P2P_V2" }, r.localservicesnames)
    end)
  end)

  describe("getblock on a block in the index without a body", function()
    local db, hashes, server
    before_each(function()
      db, hashes = header_only_store(5)
      put_snapshot_base(db, 5)
      server = rpc.new({ network = regtest, storage = db,
        chain_state = { tip_height = 5, tip_hash = hashes[5] } })
    end)

    for _, verbosity in ipairs({ 0, 1, 2 }) do
      it("answers -1 'Block not available (not fully downloaded)' at verbosity " .. verbosity, function()
        local r = call(server, "getblock", { types.hash256_hex(hashes[1]), verbosity })
        assert.equal(-1, r.error.code)
        assert.equal("Block not available (not fully downloaded)", r.error.message)
      end)
    end

    it("answers the same for the snapshot base block itself", function()
      local r = call(server, "getblock", { types.hash256_hex(hashes[5]) })
      assert.equal(-1, r.error.code)
      assert.equal("Block not available (not fully downloaded)", r.error.message)
    end)

    it("still answers -5 'Block not found' for a hash that is not in the index", function()
      local r = call(server, "getblock", { string.rep("ab", 32) })
      assert.equal(-5, r.error.code)
      assert.equal("Block not found", r.error.message)
    end)

    it("getblockheader still works for the pre-base block", function()
      local r = call(server, "getblockheader", { types.hash256_hex(hashes[1]) })
      assert.is_true(r.error == nil or r.error == cjson.null)
      assert.equal(types.hash256_hex(hashes[1]), r.result.hash)
    end)

    it("keeps 'pruned data' for a block a pruning node really pruned", function()
      server.pruner = { enabled = true, prune_height = 3, automatic = false,
        target_mb = 0, is_pruned = function(_, h) return h <= 3 end }
      local r = call(server, "getblock", { types.hash256_hex(hashes[1]) })
      assert.equal(-1, r.error.code)
      assert.equal("Block not available (pruned data)", r.error.message)
    end)

    it("getblockchaininfo reports pruned:false and no pruneheight", function()
      local r = call(server, "getblockchaininfo").result
      assert.is_false(r.pruned)
      assert.is_nil(r.pruneheight)
    end)
  end)

  describe("getchainstates on an --import-utxo datadir (no in-process snapshot)", function()
    it("shows snapshot_blockhash and validated:false", function()
      local db, hashes = header_only_store(5)
      put_snapshot_base(db, 5)
      local server = rpc.new({ network = regtest, storage = db,
        chain_state = { tip_height = 5, tip_hash = hashes[5] } })
      local r = call(server, "getchainstates").result
      local active = r.chainstates[#r.chainstates]
      assert.equal(types.hash256_hex(hashes[5]), active.snapshot_blockhash)
      assert.is_false(active.validated)
    end)

    it("the --import-utxo record alone (CF.META snapshot_blockhash, no injected base height) is enough", function()
      local db, hashes = header_only_store(5)
      db.put(db.CF.META, "snapshot_blockhash", hashes[5].bytes, true)
      local server = rpc.new({ network = regtest, storage = db,
        chain_state = { tip_height = 5, tip_hash = hashes[5] } })
      local r = call(server, "getchainstates").result
      local active = r.chainstates[#r.chainstates]
      assert.equal(types.hash256_hex(hashes[5]), active.snapshot_blockhash)
      assert.is_false(active.validated)
    end)

    it("a genesis-synced datadir has no snapshot_blockhash and validated:true", function()
      local db, hashes = header_only_store(5)
      local server = rpc.new({ network = regtest, storage = db,
        chain_state = { tip_height = 5, tip_hash = hashes[5] } })
      local r = call(server, "getchainstates").result
      local active = r.chainstates[#r.chainstates]
      assert.is_nil(active.snapshot_blockhash)
      assert.is_true(active.validated)
    end)
  end)

  describe("loadtxoutset", function()
    -- Real chain of n coinbase blocks on the regtest genesis (same shape as
    -- spec/assumeutxo_dual_chainstate_spec.lua).
    local function build_active_chain(n)
      local db = storage_mod.new_memory_storage()
      local cs = utxo.new_chain_state(db, regtest)
      cs:init()
      local spk = script.make_p2pkh_script(string.rep("\x42", 20))
      local blocks = {}
      local prev = cs.tip_hash
      for h = 1, n do
        local sig = string.char(1, h) .. string.char(0x4b, h % 256)
        local cb = types.transaction(1,
          { types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), sig, 0xFFFFFFFF) },
          { types.txout(5000000000, spk) }, 0)
        local hdr = types.block_header(1, prev, types.hash256_zero(),
          os.time() + h, regtest.pow_limit_bits, 0)
        local blk = types.block(hdr, { cb })
        local bh = validation.compute_block_hash(blk.header)
        local ok, err = cs:connect_block(blk, h, bh)
        assert(ok, "connect_block failed at height " .. h .. ": " .. tostring(err))
        db.put_block(bh, blk)
        db.put_header(bh, blk.header)
        db.put_height_index(h, bh)
        blocks[h] = { block = blk, hash = bh }
        prev = bh
      end
      return db, cs, blocks
    end

    local function load_into_fresh_node(with_bodies)
      local base = 3
      local _, cs, blocks = build_active_chain(base)
      local snap = string.format("/tmp/lb_histfloor_%d_%d.dat", os.time(), math.random(1000000))
      local dump = cs:dump_snapshot(snap)
      assert.is_not_nil(dump)
      local node_db = storage_mod.new_memory_storage()
      local node_cs = utxo.new_chain_state(node_db, regtest)
      node_cs:init()
      for h = 1, base do
        if with_bodies then node_db.put_block(blocks[h].hash, blocks[h].block) end
        node_db.put_header(blocks[h].hash, blocks[h].block.header)
        node_db.put_height_index(h, blocks[h].hash)
      end
      local net = {}
      for k, v in pairs(regtest) do net[k] = v end
      net.assumeutxo = { [base] = {
        hash_serialized = types.hash256_hex(types.hash256(dump.hash)),
        m_chain_tx_count = base + 1,
        blockhash = types.hash256_hex(cs.tip_hash) } }
      local server = rpc.new({ chain_state = node_cs, storage = node_db, network = net })
      local r = call(server, "loadtxoutset", { snap })
      os.remove(snap)
      assert.is_true(r.error == nil or r.error == cjson.null,
        "loadtxoutset failed: " .. cjson.encode(r.error or {}))
      return server, blocks, node_db
    end

    it("without the historical bodies: drops NODE_NETWORK and getblock(pre-base) is 'not fully downloaded'", function()
      set_history_incomplete(false)
      local server, blocks = load_into_fresh_node(false)
      assert.equal(0, bit.band(p2p.our_services(false, false, nil), NETWORK))
      assert.equal("0000000000000c08", call(server, "getnetworkinfo").result.localservices)
      local cs = call(server, "getchainstates").result.chainstates
      assert.is_false(cs[#cs].validated)
      assert.equal(types.hash256_hex(blocks[3].hash), cs[#cs].snapshot_blockhash)
      local r = call(server, "getblock", { types.hash256_hex(blocks[1].hash) })
      assert.equal(-1, r.error.code)
      assert.equal("Block not available (not fully downloaded)", r.error.message)
    end)

    it("with every historical body local (background pass validates): keeps NODE_NETWORK", function()
      set_history_incomplete(false)
      load_into_fresh_node(true)
      assert.is_true(bit.band(p2p.our_services(false, false, nil), NETWORK) ~= 0)
    end)

    it("persists the snapshot record, so a restarted node still answers snapshot_blockhash + validated:false", function()
      set_history_incomplete(false)
      local _, blocks, node_db = load_into_fresh_node(false)
      -- A restart: no in-process SnapshotChainstate, same datadir.
      local restarted = rpc.new({ network = regtest, storage = node_db,
        chain_state = { tip_height = 3, tip_hash = blocks[3].hash } })
      local cs = call(restarted, "getchainstates").result.chainstates
      assert.equal(types.hash256_hex(blocks[3].hash), cs[#cs].snapshot_blockhash)
      assert.is_false(cs[#cs].validated)
    end)
  end)
end)
