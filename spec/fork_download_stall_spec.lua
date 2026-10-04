-- spec/fork_download_stall_spec.lua
--
-- Gate-7 liveness: the 2026-10-04 mainnet 1-block fork at 969888
-- (winner 9c4117.., loser 0211bf2a..).  lunarblock (deployed 935f0b0) took the
-- LOSING 969888 and then sat 35+ min on
--   "[FORK-DL] heavier fork at h=969889 pending a bridging body; waiting
--    (reorg-connect-failed: side-branch block missing at height 969888)"
-- with its RPC unresponsive, until a restart.  Three defects, one test group
-- each (every group FAILS on 935f0b0):
--
--  1. accept_header wrote height_to_hash[h] for EVERY accepted header, so the
--     losing sibling's header (equal work, never the best header) overwrote the
--     winner's height slot.  The node downloaded/connected the loser, and when
--     the winner's child arrived the slot still named the loser: the fork
--     floor's same-chain fast path said "no fork" and the height-keyed download
--     walk never requested the winner's 969888 (the bridging body).
--     Core: by-height = m_best_header->GetAncestor(h) (validation.cpp:4919).
--  2. The W46 cursor re-request always picked the FIRST peer with a free slot,
--     so a peer that never delivered got the same block again and again
--     (mainnet: 18 min on one peer).  Core disconnects the staller
--     (net_processing.cpp:6094/6117) and fetches elsewhere.
--  3. accept_side_branch_block found the missing bridging body only AFTER
--     disconnecting the active tip, then rolled back -- on every main-loop
--     pass while it waited.  Core never starts toward a chain missing data
--     (FindMostWorkChain, validation.cpp:3140).

local types = require("lunarblock.types")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local serialize = require("lunarblock.serialize")
local sync = require("lunarblock.sync")
local utxo = require("lunarblock.utxo")
local script = require("lunarblock.script")
local storage_mod = require("lunarblock.storage")

local REGTEST = consensus.networks.regtest

local function hkey(height)
  return string.char(math.floor(height / 16777216) % 256,
    math.floor(height / 65536) % 256, math.floor(height / 256) % 256, height % 256)
end

-- In-memory storage: headers, height index, meta.  Blocks CF is empty (no
-- bodies on disk), which is what the fork walk sees for un-downloaded blocks.
local function mock_storage()
  local d = { headers = {}, height = {}, meta = {}, blocks = {} }
  local s = { CF = { META = "meta", HEADERS = "headers", HEIGHT_INDEX = "height", BLOCKS = "blocks" } }
  function s.get(cf, k) return d[cf] and d[cf][k] end
  function s.put(cf, k, v) d[cf][k] = v end
  function s.get_header(h)
    local raw = d.headers[h.bytes]
    return raw and serialize.deserialize_block_header(raw) or nil
  end
  function s.put_header(h, hdr) d.headers[h.bytes] = serialize.serialize_block_header(hdr) end
  function s.put_height_index(height, h) d.height[hkey(height)] = h.bytes end
  function s.get_hash_by_height(height)
    local b = d.height[hkey(height)]
    return b and types.hash256(b) or nil
  end
  function s.get_chain_tip() return nil, nil end
  function s.set_chain_tip() end
  return s
end

local ts = REGTEST.genesis.timestamp
local function mine_header(parent_hash, salt)
  ts = ts + 600
  local hdr = types.block_header(4, parent_hash, types.hash256_zero(), ts + (salt or 0), 0x207fffff, 0)
  local target = consensus.bits_to_target(hdr.bits)
  for nonce = 0, 1000000 do
    hdr.nonce = nonce
    if consensus.hash_meets_target(validation.compute_block_hash(hdr).bytes, target) then
      return hdr, validation.compute_block_hash(hdr)
    end
  end
  error("no nonce")
end

local function hex(h) return types.hash256_hex(h) end

local function mock_peer(id)
  local p = { id = id, start_height = 100, services = 9, sent = {} }
  function p:send_message(cmd, payload)
    self.sent[#self.sent + 1] = { cmd = cmd, payload = payload }
    return true
  end
  return p
end

local function asked_for(peer, hash)
  for _, m in ipairs(peer.sent) do
    if m.cmd == "getdata" and m.payload:find(hash.bytes, 1, true) then return true end
  end
  return false
end

-- prefix P1,P2 on genesis; B1 and A are siblings at height 3; B2 extends B1.
local function fork_fixture()
  local st = mock_storage()
  local hc = sync.new_header_chain(REGTEST, st)
  hc:init()
  local p1h, p1 = mine_header(hc:get_tip_hash())
  assert(hc:accept_header(p1h))
  local p2h, p2 = mine_header(p1)
  assert(hc:accept_header(p2h))
  local b1h, b1 = mine_header(p2, 1)
  local ah, a = mine_header(p2, 2)
  local b2h, b2 = mine_header(b1, 3)
  return { st = st, hc = hc, p2 = p2, b1h = b1h, b1 = b1, ah = ah, a = a, b2h = b2h, b2 = b2 }
end

describe("fork-download stall (2026-10-04, 969888)", function()

  describe("height_to_hash follows the BEST header chain only", function()
    it("a non-best sibling header does not take the best chain's height slot", function()
      local f = fork_fixture()
      assert(f.hc:accept_header(f.b1h))   -- winner first (becomes best)
      assert(f.hc:accept_header(f.ah))    -- loser: equal work, NOT best
      assert.equal(hex(f.b1), hex(f.hc.header_tip_hash))
      assert.equal(hex(f.b1), f.hc.height_to_hash[3],
        "the losing sibling's header overwrote the best chain's height slot")
      assert.equal(hex(f.b1), hex(f.st.get_hash_by_height(3)),
        "persisted height index must follow the best header chain too")
    end)

    it("a heavier child re-points its whole ancestry", function()
      local f = fork_fixture()
      assert(f.hc:accept_header(f.ah))    -- A first: best
      assert(f.hc:accept_header(f.b1h))   -- B1: equal work, not best
      assert.equal(hex(f.a), f.hc.height_to_hash[3])
      assert(f.hc:accept_header(f.b2h))   -- B2 on B1: strictly heavier
      assert.equal(hex(f.b2), hex(f.hc.header_tip_hash))
      assert.equal(hex(f.b2), f.hc.height_to_hash[4])
      assert.equal(hex(f.b1), f.hc.height_to_hash[3],
        "B2 became best but height 3 still names the losing sibling A")
      assert.equal(hex(f.p2), f.hc.height_to_hash[2])
    end)
  end)

  describe("the bridging body of a heavier fork is requested", function()
    it("mainnet order: winner hdr, loser hdr, loser connected, winner's child", function()
      local f = fork_fixture()
      assert(f.hc:accept_header(f.b1h))
      assert(f.hc:accept_header(f.ah))
      assert(f.hc:accept_header(f.b2h))
      local dl = sync.new_block_downloader(f.hc, f.st, REGTEST)
      -- active validated tip = the LOSER A at height 3 (what lunarblock connected)
      dl.active_tip_provider = function() return f.a, 3 end
      dl.next_connect_height, dl.next_download_height = 4, 4
      local peer = mock_peer(1)
      dl:schedule_downloads({ peer })
      assert.is_true(asked_for(peer, f.b1),
        "the winner's block at the fork height (the bridging body) was never requested")
      assert.is_true(asked_for(peer, f.b2))
      assert.equal(3, dl.next_connect_height, "connect cursor must walk the fork from fork_point+1")
    end)
  end)

  describe("W46 re-request rotates away from a peer that did not deliver", function()
    local function setup()
      local st = mock_storage()
      local hc = sync.new_header_chain(REGTEST, st)
      hc:init()
      local h1h, h1 = mine_header(hc:get_tip_hash())
      assert(hc:accept_header(h1h))
      local dl = sync.new_block_downloader(hc, st, REGTEST)
      dl.next_connect_height, dl.next_download_height = 1, 1
      local p1, p2 = mock_peer(1), mock_peer(2)
      dl:schedule_downloads({ p1, p2 })
      local first = asked_for(p1, h1) and p1 or p2
      local other = first == p1 and p2 or p1
      assert.is_true(asked_for(first, h1))
      p1.sent, p2.sent = {}, {}
      return dl, h1, first, other, p1, p2
    end

    it("after an in-flight timeout the block goes to ANOTHER peer", function()
      local dl, h1, first, other, p1, p2 = setup()
      local info = dl.inflight[hex(h1)]
      info.request_time = info.request_time - 10000
      dl._force_rerequest_last = {}
      dl:schedule_downloads({ p1, p2 })
      assert.is_false(asked_for(first, h1), "re-asked the peer that never delivered")
      assert.is_true(asked_for(other, h1))
    end)

    it("after notfound the block goes to ANOTHER peer", function()
      local dl, h1, first, other, p1, p2 = setup()
      dl:handle_notfound(hex(h1), first)
      dl._force_rerequest_last = {}
      dl:schedule_downloads({ p1, p2 })
      assert.is_false(asked_for(first, h1), "re-asked the peer that answered notfound")
      assert.is_true(asked_for(other, h1))
    end)

    it("with every peer tried, a new round starts (no permanent starvation)", function()
      local dl, h1, first, other, p1, p2 = setup()
      dl:handle_notfound(hex(h1), first)
      dl._force_rerequest_last = {}
      dl:schedule_downloads({ p1, p2 })
      assert.is_true(asked_for(other, h1))
      p1.sent, p2.sent = {}, {}
      dl:handle_notfound(hex(h1), other)
      dl._force_rerequest_last = {}
      dl:schedule_downloads({ p1, p2 })
      assert.is_true(asked_for(p1, h1) or asked_for(p2, h1), "block starved after all peers tried")
    end)
  end)

  describe("a missing bridging body is detected BEFORE the tip is disconnected", function()
    local db, cs, path
    local SPK = script.make_p2pkh_script(string.rep("\x42", 20))
    local function cb(height)
      return types.transaction(1, { types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
        string.char(1, height % 256), 0xFFFFFFFF) }, { types.txout(5000000000, SPK) }, 0)
    end
    local function blk(height, prev, nonce)
      local b = types.block(types.block_header(1, prev, types.hash256_zero(),
        os.time() + height + nonce * 1000000, REGTEST.pow_limit_bits, nonce), { cb(height) })
      return b, validation.compute_block_hash(b.header)
    end

    before_each(function()
      path = "/tmp/lunarblock_forkdl_" .. os.time() .. "_" .. math.random(1e9)
      db = storage_mod.open(path)
      cs = utxo.new_chain_state(db, REGTEST)
      cs:init()
    end)
    after_each(function()
      if db then db.close() end
      os.execute("rm -rf '" .. path .. "'")
    end)

    it("returns the missing-body wait WITHOUT rolling back, then reorgs once it lands", function()
      local prev = types.hash256_zero()
      local fork
      for h = 0, 1 do
        local b, bh = blk(h, prev, 0)
        db.put_header(bh, b.header); db.put_block(bh, b); db.put_height_index(h, bh)
        assert(cs:connect_block(b, h, bh, nil, nil, true))
        prev, fork = bh, bh
      end
      local a, ah = blk(2, fork, 0)                 -- active tip A at h2
      db.put_header(ah, a.header); db.put_block(ah, a); db.put_height_index(2, ah)
      assert(cs:connect_block(a, 2, ah, nil, nil, true))
      local b1, b1h = blk(2, fork, 7)               -- winner's h2: header only
      db.put_header(b1h, b1.header)
      local b2, b2h = blk(3, b1h, 7)                -- winner's h3: in hand

      local rollbacks = 0
      local real = cs.rollback_chain_to
      cs.rollback_chain_to = function(self, ...)
        rollbacks = rollbacks + 1
        return real(self, ...)
      end

      local res, err = cs:accept_side_branch_block(b2, b2h)
      assert.is_nil(res)
      assert.is_truthy(tostring(err):find("side%-branch block missing at height 2"), tostring(err))
      assert.equal(0, rollbacks, "disconnected the active tip although a bridging body was missing")
      assert.equal(hex(ah), hex(cs.tip_hash))
      assert.is_not_nil(db.get_block(b2h), "the fork body in hand must be kept on disk")

      db.put_block(b1h, b1)                         -- bridging body arrives
      local res2, err2 = cs:accept_side_branch_block(b2, b2h)
      assert.equal("connected", res2, tostring(err2))
      assert.equal(hex(b2h), hex(cs.tip_hash))
      assert.equal(3, cs.tip_height)
    end)
  end)
end)
