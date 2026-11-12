-- P2P "cmpctblock": the header is validated before any reconstruction, and
-- a peer holds at most one pending partial block, which expires.
--
-- Security finding C4 (fleet security audit, 2026-11-08): the handler built a
-- PartiallyDownloadedBlock for ANY header -- unknown parent, no proof of work
-- -- scanned the whole mempool for it, and parked the partial in
-- peer.pending_compact keyed by block hash, with no cap and no expiry.  One
-- connection grew RSS by 928 MB from 236 MB of junk cmpctblocks in 35 s.
--
-- Core (net_processing.cpp, CMPCTBLOCK):
--   * prev block unknown            -> return (ask for headers), nothing built
--   * ProcessNewBlockHeaders fails  -> MaybePunishNodeForBlock, return
--   * only then PartiallyDownloadedBlock::InitData (the mempool scan), and
--     the partial lives in the peer's single in-flight slot for that block
--     (mapBlocksInFlight), dropped when the download times out.
--
-- The handler is a closure inside main.lua's main(), so this spec slices the
-- LIVE source of the compact-block section out of src/main.lua (the same
-- technique as tx_orphan_relay_spec.lua) and runs it against a real
-- HeaderChain on regtest; only the peer manager, mempool and block
-- downloader are stubbed, and they record what they were asked to do.

local helpers = require("spec.helpers")
local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local crypto = require("lunarblock.crypto")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local p2p = require("lunarblock.p2p")
local sync = require("lunarblock.sync")
local compact_block = require("lunarblock.compact_block")

local REGTEST = consensus.networks.regtest

local function read_main()
  local f = assert(io.open("src/main.lua", "r"))
  local s = f:read("*a")
  f:close()
  return s
end

local function slice(src, start_marker, end_marker)
  local a = src:find(start_marker, 1, true)
  assert(a, "marker not found in src/main.lua: " .. start_marker)
  local b, e = src:find(end_marker, a, true)
  assert(b, "end marker not found after " .. start_marker)
  return src:sub(a, e)
end

-- Build the live cmpctblock + blocktxn handlers from main.lua's source.
local function build(chain)
  local src = read_main()
  local ban_src = slice(src, "  local HEADERS_BAN_SUBSTRINGS = {", "\n  end\n")
  local a = src:find('  local compact_block = require("lunarblock.compact_block")', 1, true)
  assert(a, "compact block section not found in src/main.lua")
  local b = src:find('peer_manager:register_handler("blocktxn"', a, true)
  assert(b, "blocktxn handler not found")
  local _, e = src:find("\n  end)\n", b, true)
  assert(e, "end of blocktxn handler not found")
  local chunk_src = ban_src .. "\n" .. src:sub(a, e)
  local chunk = assert(loadstring(chunk_src, "=main.lua:cmpctblock"))

  local rec = { bans = {}, handled = {}, sent = {}, mempool_scans = 0,
                disconnects = {} }
  local pm = { handlers = {}, our_height = 0 }
  function pm:register_handler(cmd, fn) self.handlers[cmd] = fn end
  function pm:add_ban_score(peer, score, reason)
    rec.bans[#rec.bans + 1] = { score = score, reason = reason }
  end
  function pm:disconnect_peer(peer, why)
    rec.disconnects[#rec.disconnects + 1] = why
  end
  function pm:note_peer_best_block() end

  local mempool = {}
  function mempool:iter_by_wtxid()
    rec.mempool_scans = rec.mempool_scans + 1
    return function() return nil end
  end

  local block_downloader = {}
  function block_downloader:handle_block(peer, data, opts)
    rec.handled[#rec.handled + 1] = { data = data, opts = opts }
    return true
  end

  local chain_state = { header_tip_height = 0 }
  local env = setmetatable({
    peer_manager = pm,
    header_chain = chain,
    mempool = mempool,
    block_downloader = block_downloader,
    chain_state = chain_state,
    network = REGTEST,
    p2p = p2p, serialize = serialize, crypto = crypto, types = types,
    validation = validation, consensus = consensus,
    note_peer_has_block = function() end,
  }, { __index = _G })
  setfenv(chunk, env)
  chunk()
  assert(pm.handlers.cmpctblock, "cmpctblock handler was not registered")
  assert(pm.handlers.blocktxn, "blocktxn handler was not registered")
  return pm.handlers, rec, chain_state
end

local function new_chain()
  local chain = sync.new_header_chain(REGTEST, helpers.mock_storage())
  chain:init()
  return chain
end

local function new_peer()
  local p = { ip = "10.1.2.3", port = 18444, sent = {} }
  function p:send_message(cmd, payload)
    self.sent[#self.sent + 1] = cmd
  end
  return p
end

local P2PKH = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"

local function coinbase(height, tag)
  local script_sig = string.char(1, height % 256) .. (tag or "")
  return types.transaction(1,
    { types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), script_sig,
                 0xFFFFFFFF) },
    { types.txout(5000000000, P2PKH) }, 0)
end

local function spend(n)
  local prev = types.hash256(string.rep(string.char(n % 256), 32))
  return types.transaction(1,
    { types.txin(types.outpoint(prev, 0), "", 0xFFFFFFFE) },
    { types.txout(1000 + n, P2PKH) }, 0)
end

-- A block whose header has a valid regtest PoW (or, with bad_pow, one that
-- does NOT meet its target) on top of `parent`.
local function make_block(chain, parent_hex, txs, opts)
  opts = opts or {}
  local parent = chain.headers[parent_hex]
  local height = parent and (parent.height + 1) or 1
  local all = { coinbase(height, opts.tag) }
  for _, tx in ipairs(txs or {}) do all[#all + 1] = tx end
  local txids = {}
  for i, tx in ipairs(all) do txids[i] = validation.compute_txid(tx) end
  local prev = opts.prev or types.hash256_from_hex(parent_hex)
  local ts = (parent and parent.header.timestamp or os.time()) + (opts.dt or 1)
  local header = types.block_header(4, prev, crypto.compute_merkle_root(txids),
    ts, 0x207fffff, 0)
  local target = consensus.bits_to_target(header.bits)
  for nonce = 0, 100000 do
    header.nonce = nonce
    local ok = consensus.hash_meets_target(
      validation.compute_block_hash(header).bytes, target)
    if ok ~= (opts.bad_pow == true) then break end
  end
  return types.block(header, all)
end

-- Compact form: coinbase prefilled, every other tx as a short id (so with an
-- empty mempool a block with >1 tx needs getblocktxn).
local function cmpct_payload(blk)
  return compact_block.serialize(compact_block.create_compact_block(blk, 7))
end

local function block_hex(blk)
  return types.hash256_hex(validation.compute_block_hash(blk.header))
end

local function count(t)
  local n = 0
  for _ in pairs(t or {}) do n = n + 1 end
  return n
end

describe("cmpctblock header gate and pending cap (C4)", function()
  local saved_clock
  before_each(function() saved_clock = compact_block.clock end)
  after_each(function() compact_block.clock = saved_clock end)

  it("drops a cmpctblock whose parent is unknown before touching the mempool", function()
    local chain = new_chain()
    local h, rec = build(chain)
    local peer = new_peer()
    local blk = make_block(chain, chain:get_tip_hash() and
      types.hash256_hex(chain:get_tip_hash()), { spend(1) },
      { prev = types.hash256(string.rep("\x42", 32)) })
    h.cmpctblock(peer, cmpct_payload(blk))
    assert.equals(0, count(peer.pending_compact))
    assert.equals(0, rec.mempool_scans)
    assert.equals(0, #rec.handled)
    assert.equals(0, #rec.bans)          -- Core does not punish; it asks for headers
    assert.is_nil(chain.headers[block_hex(blk)])
  end)

  it("drops and punishes a cmpctblock whose header fails proof of work", function()
    local chain = new_chain()
    local h, rec = build(chain)
    local peer = new_peer()
    local tip_hex = types.hash256_hex(chain:get_tip_hash())
    local blk = make_block(chain, tip_hex, { spend(2) }, { bad_pow = true })
    h.cmpctblock(peer, cmpct_payload(blk))
    assert.equals(0, count(peer.pending_compact))
    assert.equals(0, rec.mempool_scans)
    assert.equals(0, #rec.handled)
    assert.is_nil(chain.headers[block_hex(blk)])
    assert.equals(1, #rec.bans)          -- Core: MaybePunishNodeForBlock (invalid header)
    assert.equals(100, rec.bans[1].score)
  end)

  it("keeps at most one pending partial per peer across 100 valid distinct headers", function()
    local chain = new_chain()
    local h, rec = build(chain)
    local peer = new_peer()
    local tip_hex = types.hash256_hex(chain:get_tip_hash())
    local max_seen = 0
    for i = 1, 100 do
      -- 100 distinct siblings of the tip, each with valid PoW and one
      -- short-id tx the (empty) mempool cannot supply.
      local blk = make_block(chain, tip_hex, { spend(i) }, { tag = tostring(i), dt = i })
      h.cmpctblock(peer, cmpct_payload(blk))
      local n = count(peer.pending_compact)
      if n > max_seen then max_seen = n end
    end
    assert.is_true(max_seen <= 1, "pending_compact grew to " .. max_seen)
    assert.equals(1, count(peer.pending_compact))
  end)

  it("expires a pending partial: a blocktxn after the timeout is not reconstructed", function()
    local chain = new_chain()
    local h, rec = build(chain)
    local peer = new_peer()
    local now = 1000000
    compact_block.clock = function() return now end
    local tip_hex = types.hash256_hex(chain:get_tip_hash())
    local tx = spend(9)
    local blk = make_block(chain, tip_hex, { tx })
    h.cmpctblock(peer, cmpct_payload(blk))
    assert.equals(1, count(peer.pending_compact))

    now = now + (compact_block.PENDING_COMPACT_TIMEOUT or 600) + 1
    h.blocktxn(peer, p2p.serialize_blocktxn(
      validation.compute_block_hash(blk.header), { tx }))
    assert.equals(0, #rec.handled)
    assert.equals(0, count(peer.pending_compact))
  end)

  it("a valid compact block extending the tip still reconstructs and is handed to the block path", function()
    local chain = new_chain()
    local h, rec, cs = build(chain)
    local peer = new_peer()
    local tip_hex = types.hash256_hex(chain:get_tip_hash())
    local tx = spend(11)
    local blk = make_block(chain, tip_hex, { tx })
    local hx = block_hex(blk)
    h.cmpctblock(peer, cmpct_payload(blk))
    -- header accepted (so handle_block will not drop it as "unknown block")
    assert.is_not_nil(chain.headers[hx])
    assert.equals(1, chain.headers[hx].height)
    assert.equals(1, cs.header_tip_height)
    assert.equals(1, rec.mempool_scans)
    assert.same({ "getblocktxn" }, peer.sent)

    h.blocktxn(peer, p2p.serialize_blocktxn(
      validation.compute_block_hash(blk.header), { tx }))
    assert.equals(1, #rec.handled)
    assert.is_true(rec.handled[1].opts.via_compact)
    assert.equals(serialize.serialize_block(blk), rec.handled[1].data)
    assert.equals(0, count(peer.pending_compact))
    assert.equals(0, #rec.bans)
  end)

  it("a fully prefilled valid compact block connects without getblocktxn", function()
    local chain = new_chain()
    local h, rec = build(chain)
    local peer = new_peer()
    local tip_hex = types.hash256_hex(chain:get_tip_hash())
    local blk = make_block(chain, tip_hex, {})
    h.cmpctblock(peer, cmpct_payload(blk))
    assert.is_not_nil(chain.headers[block_hex(blk)])
    assert.equals(1, #rec.handled)
    assert.equals(serialize.serialize_block(blk), rec.handled[1].data)
    assert.equals(0, count(peer.pending_compact))
  end)
end)
