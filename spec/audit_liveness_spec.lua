-- spec/audit_liveness_spec.lua
--
-- Fleet architecture audit 2026-10-07, lunarblock items (receipts in the
-- meta-repo: arch-concurrency-liveness-audit-2026-10-07.md, fix brief #4):
--
--   LB-1  a body that fails as received (witness stripped / bad merkle) made
--         the connect cursor SKIP the height for good.  Core: a BLOCK_MUTATED
--         body is not a verdict on the block -- punish the sender, keep the
--         height, fetch it from another peer (net_processing.cpp ProcessMessage
--         "block" -> IsBlockMutated; validation.cpp AcceptBlock /
--         InvalidBlockFound skip BLOCK_FAILED_VALID for BLOCK_MUTATED).
--   LB-6  in-flight requests were not freed when the peer disconnected
--         (Core FinalizeNode).
--   LB-12 compact-block reconstruction ran without its mutation check.
--   LB-5  the stale-tip / chain-sync eviction machinery was never fed, so
--         every outbound peer was evicted ~22 min after it connected.
--   LB-2  invalidateblock read ~headers x 10,000 headers from storage.
--   LB-3  accept_block connected a block that invalidateblock had marked.

package.path = "src/?.lua;" .. package.path

local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local crypto = require("lunarblock.crypto")
local mining = require("lunarblock.mining")
local p2p = require("lunarblock.p2p")
local sync = require("lunarblock.sync")

local REGTEST = consensus.networks.regtest
local SPK = "\x51"

local function create_storage()
  local data = { meta = {}, headers = {}, height = {}, blocks = {} }
  local s = {
    CF = { META = "meta", HEADERS = "headers", HEIGHT_INDEX = "height",
           BLOCKS = "blocks" },
    reads = 0,
  }
  function s.get(cf, key) return data[cf] and data[cf][key] end
  function s.put(cf, key, value) data[cf][key] = value end
  function s.delete(cf, key) data[cf][key] = nil end
  function s.get_header(h)
    s.reads = s.reads + 1
    local d = data.headers[h.bytes]
    return d and serialize.deserialize_block_header(d) or nil
  end
  function s.put_header(h, header)
    data.headers[h.bytes] = serialize.serialize_block_header(header)
  end
  local function hkey(height)
    return string.char(math.floor(height / 16777216) % 256,
      math.floor(height / 65536) % 256, math.floor(height / 256) % 256,
      height % 256)
  end
  function s.put_height_index(height, h) data.height[hkey(height)] = h.bytes end
  function s.get_hash_by_height(height)
    local b = data.height[hkey(height)]
    return b and types.hash256(b) or nil
  end
  function s.put_block(h, blk) data.blocks[h.bytes] = serialize.serialize_block(blk) end
  function s.get_block(h)
    local d = data.blocks[h.bytes]
    return d and serialize.deserialize_block(d) or nil
  end
  function s.batch()
    local b = {}
    function b.put(cf, k, v) data[cf] = data[cf] or {}; data[cf][k] = v end
    function b.delete(cf, k) if data[cf] then data[cf][k] = nil end end
    function b.write() return true end
    function b.destroy() end
    function b.clear() end
    function b.count() return 0 end
    return b
  end
  function s.get_chain_tip() return nil, nil end
  function s.set_chain_tip() end
  function s.iterator(cf)
    local keys = {}
    for k in pairs(data[cf] or {}) do keys[#keys + 1] = k end
    table.sort(keys)
    local i = 1
    return {
      seek_to_first = function() i = 1 end,
      valid = function() return keys[i] ~= nil end,
      key = function() return keys[i] end,
      next = function() i = i + 1 end,
      destroy = function() end,
    }
  end
  s._data = data
  return s
end

-- A fully valid coinbase-only regtest block (BIP34 height, witness
-- commitment + 32-byte reserved value, correct merkle root, mined).
local function build_block(height, prev_hash, ts, bip34_height)
  local witness_root = crypto.compute_merkle_root({ types.hash256_zero() })
  local commitment = crypto.hash256(witness_root.bytes .. string.rep("\0", 32))
  local cb = mining.create_coinbase_tx(bip34_height or height,
    5000000000, "/audit/", commitment, SPK)
  local merkle = crypto.compute_merkle_root({ validation.compute_txid(cb) })
  local header = types.block_header(0x20000000, prev_hash, merkle, ts,
    REGTEST.pow_limit_bits, 0)
  local block = types.block(header, { cb })
  assert(mining.mine_block(block, 0x7FFFFFFF), "mine")
  return block, validation.compute_block_hash(block.header)
end

-- Same header, coinbase witness stripped: header hash unchanged, body
-- malleated (Core IsBlockMutated -> bad-witness-nonce-size).
local function stripped_bytes(block)
  local cb = block.transactions[1]
  local saved_w, saved_s = cb.inputs[1].witness, cb.segwit
  cb.inputs[1].witness = {}
  cb.segwit = false
  cb._cached_witness_data = nil
  local bytes = serialize.serialize_block(block)
  cb.inputs[1].witness, cb.segwit = saved_w, saved_s
  cb._cached_witness_data = nil
  return bytes
end

local function mock_peer(id)
  local peer = { id = id, ip = "127.0.0." .. id, port = 8333, start_height = 100,
                 services = 9, messages_sent = {}, state = "established" }
  function peer:send_message(cmd, payload)
    self.messages_sent[#self.messages_sent + 1] = { command = cmd, payload = payload }
    return true
  end
  return peer
end

local function getdata_count(peer, hash_hex)
  local n = 0
  for _, m in ipairs(peer.messages_sent) do
    if m.command == "getdata" then
      for _, item in ipairs(p2p.deserialize_inv(m.payload)) do
        if types.hash256_hex(item.hash) == hash_hex then n = n + 1 end
      end
    end
  end
  return n
end

describe("LB-1 a malleated body never costs the height (Core BLOCK_MUTATED)", function()
  local storage, chain, dl, blocks, active, connected
  local N = 6

  before_each(function()
    storage = create_storage()
    chain = sync.new_header_chain(REGTEST, storage)
    chain:init()
    local prev = chain:get_tip_hash()
    local ts = REGTEST.genesis.timestamp
    blocks = {}
    for h = 1, N do
      ts = ts + 600
      local blk, bh = build_block(h, prev, ts)
      assert(chain:accept_header(blk.header))
      blocks[h] = { block = blk, hash = bh, hex = types.hash256_hex(bh),
                    bytes = serialize.serialize_block(blk) }
      prev = bh
    end
    active = { hash = chain:get_header_at_height(0) and
      validation.compute_block_hash(chain:get_header_at_height(0).header), height = 0 }
    connected = {}
    dl = sync.new_block_downloader(chain, storage, REGTEST)
    dl.next_connect_height = 1
    dl.next_download_height = 1
    dl.active_tip_provider = function() return active.hash, active.height end
    dl.connect_callback = function(block, height, hash)
      assert(block.header.prev_hash.bytes == active.hash.bytes, "prev mismatch")
      active.hash, active.height = hash, height
      connected[height] = types.hash256_hex(hash)
      return true
    end
    dl.invalid_block_callback = function() end
  end)

  local function deliver_honest(peer, from, to)
    for h = from, to do dl:handle_block(peer, blocks[h].bytes) end
  end

  it("witness-stripped h from one peer, honest h from another: the tip reaches the end", function()
    local evil, good = mock_peer(2), mock_peer(3)
    deliver_honest(good, 1, 2)
    assert.equals(2, active.height)
    local ok, err = dl:handle_block(evil, stripped_bytes(blocks[3].block))
    assert.is_false(ok)
    assert.truthy(tostring(err):find("mutated block", 1, true))
    assert.is_true(sync.should_punish_peer_for_block_error(err))
    -- nothing moved: cursor still on 3, block 3 NOT failed, nothing pending
    assert.equals(3, dl.next_connect_height)
    assert.is_false(chain:is_failed(blocks[3].hex))
    assert.is_nil(dl.pending_blocks[blocks[3].hex])
    -- honest copy is accepted (not LATE_ARRIVAL) and the chain completes
    deliver_honest(good, 3, N)
    assert.equals(N, active.height)
    assert.equals(blocks[N].hex, connected[N])
  end)

  it("a mutated copy never replaces an honest pending body", function()
    local evil, good = mock_peer(2), mock_peer(3)
    deliver_honest(good, 1, 1)
    dl:handle_block(good, blocks[3].bytes)            -- far-ahead honest, pending
    assert.truthy(dl.pending_blocks[blocks[3].hex])
    dl:handle_block(evil, stripped_bytes(blocks[3].block))
    assert.truthy(dl.pending_blocks[blocks[3].hex], "honest pending copy was evicted")
    dl:handle_block(good, blocks[2].bytes)
    assert.equals(3, active.height)
  end)

  it("the sender's in-flight request is dropped and the block is re-requested from another peer", function()
    local evil, good = mock_peer(2), mock_peer(3)
    dl.inflight[blocks[1].hex] = { peer = evil, request_time = os.time(), timeout = 60 }
    dl.peer_inflight[evil] = 1
    dl:handle_block(evil, stripped_bytes(blocks[1].block))
    assert.is_nil(dl.inflight[blocks[1].hex])
    dl:schedule_downloads({ evil, good })
    assert.equals(1, getdata_count(good, blocks[1].hex))
    assert.equals(0, getdata_count(evil, blocks[1].hex))
  end)

  it("a mutated body recovered from storage at the cursor is dropped, not skipped", function()
    local good = mock_peer(3)
    -- the stripped copy is on disk (e.g. stored before the fix)
    storage._data.blocks[blocks[1].hash.bytes] = stripped_bytes(blocks[1].block)
    dl:connect_pending_blocks()
    assert.equals(0, active.height)
    assert.equals(1, dl.next_connect_height, "cursor skipped the height")
    assert.is_false(chain:is_failed(blocks[1].hex))
    assert.is_nil(storage._data.blocks[blocks[1].hash.bytes], "bad stored copy kept")
    deliver_honest(good, 1, N)
    assert.equals(N, active.height)
  end)

  it("NEGATIVE CONTROL: a genuinely invalid body (merkle-consistent bad-cb-height) is marked failed, never connected", function()
    local evil = mock_peer(2)
    -- a different block at height 1 whose coinbase commits to height 7
    local genesis = validation.compute_block_hash(chain:get_header_at_height(0).header)
    local bad, bad_hash = build_block(1, genesis, REGTEST.genesis.timestamp + 300, 7)
    assert(chain:accept_header(bad.header))
    -- make it the cursor block (as if it were the best header at 1)
    chain.height_to_hash[1] = types.hash256_hex(bad_hash)
    local ok = dl:handle_block(evil, serialize.serialize_block(bad))
    assert.is_false(ok)
    assert.equals(0, active.height)
    assert.is_true(chain:is_failed(types.hash256_hex(bad_hash)))
  end)
end)

describe("LB-1 validation.is_block_mutated (Core IsBlockMutated)", function()
  it("flags stripped witness, changed tx, duplicate tx; passes the real block", function()
    local blk = build_block(1, types.hash256_zero(), 1296688602 + 600)
    local raw = serialize.serialize_block(blk)
    assert.is_false((validation.is_block_mutated(serialize.deserialize_block(raw), true, raw)))
    local s = stripped_bytes(blk)
    local m, why = validation.is_block_mutated(serialize.deserialize_block(s), true, s)
    assert.is_true(m); assert.equals("bad-witness-nonce-size", why)
    local b2 = serialize.deserialize_block(raw)
    b2.transactions[1].outputs[1].value = 1
    local r2 = serialize.serialize_block(b2)
    m, why = validation.is_block_mutated(b2, true, r2)
    assert.is_true(m); assert.equals("bad-txnmrklroot", why)
    -- raw route and object route agree
    m = validation.is_block_mutated(serialize.deserialize_block(s), true)
    assert.is_true(m)
  end)
end)

describe("LB-12 compact block reconstruction runs the mutation check", function()
  it("a forged (witness-stripped) prefilled coinbase does not reconstruct", function()
    local compact_block = require("lunarblock.compact_block")
    local blk = build_block(1, types.hash256_zero(), 1296688602 + 600)
    local cb = serialize.deserialize_block(stripped_bytes(blk)).transactions[1]
    local partial = compact_block.new_partial_block()
    local err = partial:init({ header = blk.header, nonce = 1, short_ids = {},
      prefilled_txns = { { index = 0, tx = cb } } }, nil)
    assert.is_nil(err)
    local out, rerr = partial:reconstruct(function(b)
      return (validation.is_block_mutated(b, true))
    end)
    assert.is_nil(out)
    assert.truthy(tostring(rerr):find("mutated", 1, true))
  end)
end)

describe("LB-6 a disconnecting peer's in-flight blocks are freed (Core FinalizeNode)", function()
  it("frees the entries and pulls the download cursor back", function()
    local storage = create_storage()
    local chain = sync.new_header_chain(REGTEST, storage)
    chain:init()
    local prev, ts = chain:get_tip_hash(), REGTEST.genesis.timestamp
    local hexes = {}
    for h = 1, 4 do
      ts = ts + 600
      local blk, bh = build_block(h, prev, ts)
      assert(chain:accept_header(blk.header))
      hexes[h] = types.hash256_hex(bh)
      prev = bh
    end
    local dl = sync.new_block_downloader(chain, storage, REGTEST)
    dl.next_connect_height, dl.next_download_height = 1, 5
    local gone, stay = mock_peer(2), mock_peer(3)
    for h = 1, 3 do dl.inflight[hexes[h]] = { peer = gone, request_time = 0, timeout = 60 } end
    dl.inflight[hexes[4]] = { peer = stay, request_time = 0, timeout = 60 }
    dl.peer_inflight[gone], dl.peer_inflight[stay] = 3, 1
    assert.equals(3, dl:on_peer_disconnected(gone))
    assert.is_nil(dl.inflight[hexes[1]])
    assert.truthy(dl.inflight[hexes[4]])
    assert.is_nil(dl.peer_inflight[gone])
    assert.equals(1, dl.next_download_height)
  end)
end)

describe("LB-5 stale-tip / chain-sync eviction is fed (Core ConsiderEviction)", function()
  local peerman = require("lunarblock.peerman")
  local socket = require("socket")
  local real_gettime
  local now

  before_each(function()
    real_gettime = socket.gettime
    now = 1000000
    socket.gettime = function() return now end
  end)
  after_each(function() socket.gettime = real_gettime end)

  local function outbound(pm, id)
    local p = { ip = "10.0.0." .. id, port = 8333, inbound = false, state = "established",
                sent = {}, disconnected = nil }
    function p:send_message(cmd) self.sent[#self.sent + 1] = cmd return true end
    pm.peers[p.ip .. ":" .. p.port] = p
    pm.peer_list[#pm.peer_list + 1] = p
    pm:_init_peer_chain_sync(p)
    return p
  end

  local function work(n) return string.rep("\0", 31) .. string.char(n) end

  it("announcing outbound peers survive 25 min; a silent one is evicted after ~22 min", function()
    local pm = peerman.new(REGTEST, nil, { max_outbound = 8, data_dir = "/nonexistent-lb-audit" })
    local evicted = {}
    pm.disconnect_peer = function(_, p, reason) evicted[p.ip] = reason end
    local tip = { h = 100 }
    pm.active_tip_info = function() return tip.h, "tip" .. tip.h, work(tip.h) end
    pm.locator_provider = function() return { types.hash256_zero() } end
    local a, b, silent = outbound(pm, 1), outbound(pm, 2), outbound(pm, 3)
    -- protection is capped (Core MAX_OUTBOUND_PEERS_TO_PROTECT); keep the
    -- announcers unprotected so the timer logic itself is what is tested
    pm._protected_outbound = 99
    for minute = 1, 25 do
      now = now + 60
      tip.h = tip.h + ((minute % 5 == 0) and 1 or 0)
      -- a and b announce every new tip (headers handler feeds this)
      pm:note_peer_best_block(a, tip.h, "tip" .. tip.h, work(tip.h))
      pm:note_peer_best_block(b, tip.h, "tip" .. tip.h, work(tip.h))
      pm._extra_peer_check_time = 0
      pm:check_for_stale_tip_and_evict_peers()
    end
    assert.is_nil(evicted[a.ip])
    assert.is_nil(evicted[b.ip])
    assert.equals("outbound peer has old chain", evicted[silent.ip])
  end)

  it("the stale-tip clock follows the active tip", function()
    local pm = peerman.new(REGTEST, nil, { max_outbound = 8, data_dir = "/nonexistent-lb-audit" })
    local tip = { h = 5 }
    pm.active_tip_info = function() return tip.h, "t" .. tip.h, work(tip.h) end
    pm:check_for_stale_tip_and_evict_peers()
    now = now + 3 * 600 + 10
    tip.h = 6
    pm:check_for_stale_tip_and_evict_peers()
    assert.is_false(pm:tip_may_be_stale())
    now = now + 3 * 600 + 10
    assert.is_true(pm:tip_may_be_stale())
  end)

  it("a peer with a block request in flight counts for TipMayBeStale and extra-peer eviction", function()
    local pm = peerman.new(REGTEST, nil, { max_outbound = 8, data_dir = "/nonexistent-lb-audit" })
    local p = outbound(pm, 1)
    pm.block_inflight_source = { inflight = { aa = { peer = p } }, peer_inflight = { [p] = 1 } }
    assert.equals(1, pm:get_blocks_in_flight_count())
    assert.is_true(pm:peer_has_block_in_flight(p))
  end)
end)

describe("LB-2 / LB-3 invalidation cost and stickiness", function()
  local utxo = require("lunarblock.utxo")
  local CS = getmetatable(utxo.new_chain_state(create_storage(), REGTEST))

  -- Active chain 0..N plus a side branch of 3 off height N-10, all headers
  -- stored; a HeaderChain over the same storage is the in-memory index.
  local function setup(N)
    local storage = create_storage()
    local chain = sync.new_header_chain(REGTEST, storage)
    chain:init()
    local g = chain:get_tip_hash()
    local hashes = { [0] = g }
    local prev, ts = g, REGTEST.genesis.timestamp
    for h = 1, N do
      ts = ts + 600
      local hdr = types.block_header(4, prev, types.hash256_zero(), ts, REGTEST.pow_limit_bits, 0)
      local target = consensus.bits_to_target(hdr.bits)
      for nonce = 0, 1000000 do
        hdr.nonce = nonce
        if consensus.hash_meets_target(validation.compute_block_hash(hdr).bytes, target) then break end
      end
      assert(chain:accept_header(hdr))
      local bh = validation.compute_block_hash(hdr)
      storage.put_header(bh, hdr)
      hashes[h] = bh
      prev = bh
    end
    local side = {}
    prev, ts = hashes[N - 10], REGTEST.genesis.timestamp + 600 * (N - 10) + 7
    for i = 1, 3 do
      ts = ts + 600
      local hdr = types.block_header(4, prev, types.hash256_zero(), ts, REGTEST.pow_limit_bits, 0)
      local target = consensus.bits_to_target(hdr.bits)
      for nonce = 0, 1000000 do
        hdr.nonce = nonce
        if consensus.hash_meets_target(validation.compute_block_hash(hdr).bytes, target) then break end
      end
      assert(chain:accept_header(hdr))
      local bh = validation.compute_block_hash(hdr)
      storage.put_header(bh, hdr)
      side[i] = bh
      prev = bh
    end
    local cs = setmetatable({ storage = storage, invalid_blocks = {},
      tip_hash = hashes[N], tip_height = N, network = REGTEST }, CS)
    cs.save_invalid_blocks = function() end
    cs.header_index = chain
    return cs, storage, hashes, side
  end

  it("invalidating a side-branch block reads O(fork) headers, not O(headers x depth)", function()
    local N = 400
    local cs, storage, hashes, side = setup(N)
    storage.reads = 0
    cs.parent_steps = 0
    assert.truthy(cs:invalidate_block(side[1]))
    -- 1 (existence) + a handful; the pre-fix walk read ~N*(N/2) = 80,000
    local work = (cs.parent_steps or 0) + storage.reads
    print("[LB-2] invalidate_block(side): header storage reads " .. storage.reads
      .. ", parent steps " .. tostring(cs.parent_steps))
    assert.is_true(work < 50, "header work: " .. work)
    assert.is_true(cs.invalid_blocks[side[2].bytes])
    assert.is_true(cs.invalid_blocks[side[3].bytes])
    assert.is_nil(cs.invalid_blocks[hashes[N].bytes])
    assert.equals(N, cs.tip_height)
  end)

  it("has_invalid_ancestor stops at the first active-chain ancestor", function()
    local N = 400
    local cs, storage, hashes, side = setup(N)
    storage.reads = 0
    cs.parent_steps = 0
    assert.is_false(cs:has_invalid_ancestor(side[3]))
    assert.is_false(cs:has_invalid_ancestor(hashes[N]))
    -- parent steps (memory or storage) + storage reads: the fork is 10 deep,
    -- so ~15 steps; walking to genesis is ~800.
    local work = (cs.parent_steps or 0) + storage.reads
    print("[LB-4] has_invalid_ancestor x2: parent steps " .. tostring(cs.parent_steps)
      .. ", header storage reads " .. storage.reads)
    assert.is_true(work < 40, "ancestor work: " .. work)
    cs.invalid_blocks[side[1].bytes] = true
    assert.is_true(cs:has_invalid_ancestor(side[3]))
  end)

  it("accept_block refuses an invalidated block and a child of one", function()
    local cs = setmetatable({ invalid_blocks = {}, tip_height = 0 }, CS)
    local bh = types.hash256(string.rep("\7", 32))
    cs.invalid_blocks[bh.bytes] = true
    local ok, err = cs:accept_block({ header = { prev_hash = types.hash256_zero() } }, 1, bh, {})
    assert.is_nil(ok); assert.equals("duplicate-invalid", err)
    local child = { header = { prev_hash = bh } }
    ok, err = cs:accept_block(child, 2, types.hash256(string.rep("\8", 32)), {})
    assert.is_nil(ok); assert.truthy(err:find("bad-prevblk", 1, true))
  end)
end)
