-- Block relay, Core parity (bitcoin-core/src/net_processing.cpp).
--
-- Repro (regtest, two bitcoinds each -connect'ing ONLY to lunarblock): blocks
-- mined on Core A reached lunarblock but never Core B. Three gaps, each of
-- which alone stalls B:
--
--   1. announce gate. Core UpdatedBlockTip announces every new tip once the
--      node is out of IBD (UpdateIBDStatus: tip recent + min chainwork,
--      latched). lunarblock gated on block_downloader.ibd_complete, which the
--      IBD-RELATCH clears the moment a new block's header arrives and only
--      re-sets after the block is connected — so it was false for EVERY block
--      connected and nothing was ever announced.
--   2. getheaders. Core always replies (an empty `headers` when there is
--      nothing to send) and serves the ACTIVE chain only. lunarblock stayed
--      silent on "nothing to send" (the requester then refuses to send another
--      getheaders for HEADERS_RESPONSE_TIME = 2 min, ignoring our invs) and
--      served headers up to its HEADER tip (the follow-up getdata for
--      not-yet-connected bodies drew `notfound`).
--   3. getdata(MSG_CMPCT_BLOCK). Core asks for the first block of a headers
--      announce as a compact block; lunarblock did not answer it at all.

local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local validation = require("lunarblock.validation")
local p2p = require("lunarblock.p2p")
local peerman = require("lunarblock.peerman")
local peer_mod = require("lunarblock.peer")
local consensus = require("lunarblock.consensus")
local sync = require("lunarblock.sync")

local T = p2p.INV_TYPE
local hex = types.hash256_hex

local function make_header(prev, ts, nonce)
  return types.block_header(0x20000000, prev or types.hash256_zero(),
    types.hash256_zero(), ts or os.time(), 0x207fffff, nonce or 0)
end

local function mock_peer(id, send_headers)
  return {
    id = id, state = peer_mod.STATE.ESTABLISHED, send_headers = send_headers,
    sent = {},
    send_message = function(self, command, payload)
      self.sent[#self.sent + 1] = { command = command, payload = payload }
    end,
  }
end

describe("block relay: announce gate (Core UpdatedBlockTip / UpdateIBDStatus)", function()
  local NOW = 1800000000
  local DAY = peerman.DEFAULT_MAX_TIP_AGE

  it("uses Core's DEFAULT_MAX_TIP_AGE of 24h", function()
    assert.equal(24 * 60 * 60, DAY)
  end)

  it("announces a recent tip and latches out of IBD", function()
    local pm = peerman.new(consensus.networks.regtest, nil, nil)
    assert.is_true(pm:should_announce_new_tip(NOW - 60, true, NOW))
    -- latched: a later old-timestamp tip (e.g. reorg to an old-time block)
    -- is still announced — Core never re-enters IBD.
    assert.is_true(pm:should_announce_new_tip(NOW - 10 * DAY, true, NOW))
  end)

  it("does not announce while the tip is older than max tip age (IBD)", function()
    local pm = peerman.new(consensus.networks.regtest, nil, nil)
    assert.is_false(pm:should_announce_new_tip(NOW - DAY - 1, true, NOW))
    assert.is_true(pm:should_announce_new_tip(NOW - DAY, true, NOW))
  end)

  it("does not announce while chainwork is below min_chain_work", function()
    local pm = peerman.new(consensus.networks.regtest, nil, nil)
    assert.is_false(pm:should_announce_new_tip(NOW, false, NOW))
    assert.is_true(pm:should_announce_new_tip(NOW, nil, NOW))  -- unknown work
  end)

  -- The master gate, block_downloader.ibd_complete, sampled at the moment a
  -- freshly announced tip block is connected. The new header has already
  -- arrived, so schedule_downloads' IBD-RELATCH has cleared the flag.
  it("announces the new tip block even though ibd_complete is relatched false", function()
    local storage = { get_header = function() return nil end }
    local hc = { header_tip_height = 5, height_to_hash = {},
      get_header_at_height = function() return nil end }
    local dl = sync.new_block_downloader(hc, storage, consensus.networks.regtest)
    dl.ibd_complete = true          -- caught up at height 4
    dl.reached_tip = true
    dl.next_connect_height = 5      -- header for block 5 just arrived
    pcall(dl.schedule_downloads, dl, { { id = 1, ip = "127.0.0.1", port = 1,
      services = 0xFFFFFFFF, state = peer_mod.STATE.ESTABLISHED,
      send_message = function() end } })
    assert.is_false(dl.ibd_complete)  -- the old gate: nothing announced

    local pm = peerman.new(consensus.networks.regtest, nil, nil)
    local p = mock_peer(1, true)
    pm.peer_list = { p }
    local hdr = make_header(nil, NOW)
    if pm:should_announce_new_tip(hdr.timestamp, true, NOW) then
      pm:announce_block(validation.compute_block_hash(hdr), hdr)
    end
    assert.equal(1, #p.sent)
    assert.equal("headers", p.sent[1].command)
  end)
end)

describe("block relay: getheaders reply (Core ProcessGetHeaders)", function()
  -- Active chain genesis..3 connected, headers known up to 5.
  local hc, hashes
  before_each(function()
    hc = { headers = {}, height_to_hash = {}, header_tip_height = 5 }
    hashes = {}
    local prev = types.hash256_zero()
    for h = 0, 5 do
      local hdr = make_header(prev, 1296688602 + h, h)
      local hh = validation.compute_block_hash(hdr)
      hashes[h] = hh
      hc.headers[hex(hh)] = { header = hdr, height = h }
      hc.height_to_hash[h] = hex(hh)
      prev = hh
    end
    function hc:get_header(hash) return self.headers[hex(hash)] end
    function hc:get_header_at_height(h)
      local k = self.height_to_hash[h]
      return k and self.headers[k] or nil
    end
  end)

  local function req(locator_heights, stop)
    local loc = {}
    for i, h in ipairs(locator_heights) do loc[i] = hashes[h] end
    return { block_locator_hashes = loc, hash_stop = stop or types.hash256_zero() }
  end

  it("replies with an EMPTY headers message when the peer is at our tip", function()
    local payload = peerman.getheaders_response(req({ 3 }), hc, 3)
    assert.is_string(payload)
    assert.equal(0, #p2p.deserialize_headers(payload))
    assert.equal("\0", payload)
  end)

  it("serves only the ACTIVE chain, not headers past the connected tip", function()
    local got = p2p.deserialize_headers(peerman.getheaders_response(req({ 0 }), hc, 3))
    assert.equal(3, #got)  -- heights 1..3, not 4..5
    assert.equal(hex(hashes[3]), hex(validation.compute_block_hash(got[3])))
  end)

  it("serves up to the header tip when it equals the active tip", function()
    local got = p2p.deserialize_headers(peerman.getheaders_response(req({ 1 }), hc, 5))
    assert.equal(4, #got)  -- 2..5
  end)

  it("honours hash_stop", function()
    local got = p2p.deserialize_headers(
      peerman.getheaders_response(req({ 0 }, hashes[2]), hc, 5))
    assert.equal(2, #got)
  end)
end)

describe("block relay: getdata(MSG_CMPCT_BLOCK) (Core ProcessGetBlockData)", function()
  local blk, bhash
  before_each(function()
    local cb = types.transaction(1,
      { types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), "\x01\x01", 0xFFFFFFFF) },
      { types.txout(5000000000, "\x51") }, 0)
    blk = types.block(make_header(nil, 1800000000), { cb })
    bhash = types.hash256(string.rep("\x42", 32))
  end)
  local function ask(depth)
    return peerman.getdata_response({ type = T.MSG_CMPCT_BLOCK, hash = bhash }, {
      get_block = function(h) if hex(h) == hex(bhash) then return blk end end,
      block_depth = function() return depth end,
    })
  end

  it("serves a cmpctblock for a block near the tip", function()
    local cmd, data, status = ask(0)
    assert.equal("served", status)
    assert.equal("cmpctblock", cmd)
    local cb = p2p.deserialize_cmpctblock(data)
    assert.equal(hex(validation.compute_block_hash(blk.header)),
      hex(validation.compute_block_hash(cb.header)))
    assert.equal(1, #cb.prefilled_txns)
  end)

  it("serves the full witness block when deeper than MAX_CMPCTBLOCK_DEPTH", function()
    local cmd, data, status = ask(6)
    assert.equal("served", status)
    assert.equal("block", cmd)
    assert.equal(serialize.serialize_block(blk), data)
  end)

  it("serves the full block when depth is unknown", function()
    local cmd, _, status = ask(nil)
    assert.equal("served", status)
    assert.equal("block", cmd)
  end)

  it("unknown block -> notfound", function()
    local _, _, status = peerman.getdata_response(
      { type = T.MSG_CMPCT_BLOCK, hash = types.hash256(string.rep("\x55", 32)) },
      { get_block = function() return nil end })
    assert.equal("notfound", status)
  end)
end)
