-- P2P "getblocktxn": only blocks near the tip are answered with a blocktxn,
-- and an out-of-range transaction index is misbehaviour.
--
-- Security finding H6 (fleet security audit, 2026-11-08): the handler looked
-- up and fully decoded the stored block for EVERY request, however deep, and
-- silently skipped indexes past the end of the block.  A ~60-byte request
-- therefore cost one full block decode (~27 ms on a dense mainnet block;
-- 1,000 requests stalled the node for 2.4 s) and the peer was never scored.
--
-- Core (net_processing.cpp, GETBLOCKTXN + SendBlockTransactions):
--   * no block index entry                  -> ignored
--   * pindex->nHeight >= tip - MAX_BLOCKTXN_DEPTH (10)
--                                            -> read block, send blocktxn
--   * deeper                                 -> push MSG_WITNESS_BLOCK onto
--     m_getdata_requests: the peer gets the full block through the getdata
--     path and has to download every byte we read from disk
--   * req.indexes[i] >= block.vtx.size()     -> Misbehaving("getblocktxn with
--     out-of-bounds tx indices"), no reply
--
-- The handler is a closure inside main.lua's main(), so this spec slices the
-- LIVE source of the getblocktxn handler out of src/main.lua (the technique
-- of tx_orphan_relay_spec.lua and sec_cmpctblock_header_spec.lua).  The block
-- store is stubbed and counts block decodes; the peer and peer manager record
-- what they were asked to do.

local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local validation = require("lunarblock.validation")
local p2p = require("lunarblock.p2p")
local compact_block = require("lunarblock.compact_block")

local function read_main()
  local f = assert(io.open("src/main.lua", "r"))
  local s = f:read("*a")
  f:close()
  return s
end

local P2PKH = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"

local function coinbase(height)
  return types.transaction(1,
    { types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                 string.char(1, height % 256), 0xFFFFFFFF) },
    { types.txout(5000000000, P2PKH) }, 0)
end

local function spend(n)
  local prev = types.hash256(string.rep(string.char(n % 256), 32))
  return types.transaction(1,
    { types.txin(types.outpoint(prev, 0), "", 0xFFFFFFFE) },
    { types.txout(1000 + n, P2PKH) }, 0)
end

-- A 4-tx block at `height`; the header is not mined (the handler never
-- checks PoW, it only looks the block up).
local function make_block(height)
  local txs = { coinbase(height), spend(height * 10 + 1),
                spend(height * 10 + 2), spend(height * 10 + 3) }
  local prev = types.hash256(string.rep(string.char(height % 256), 32))
  local header = types.block_header(4, prev, types.hash256_zero(),
    1700000000 + height, 0x207fffff, height)
  return types.block(header, txs)
end

-- Build the live getblocktxn handler from main.lua's source.  `tip` is the
-- active-chain height; `blocks` maps height -> block, all of them on our
-- header chain and in the block store.
local function build(tip, blocks)
  local src = read_main()
  local a = src:find('  peer_manager:register_handler("getblocktxn"', 1, true)
  assert(a, "getblocktxn handler not found in src/main.lua")
  local _, e = src:find("\n  end)\n", a, true)
  assert(e, "end of getblocktxn handler not found")
  local chunk = assert(loadstring(src:sub(a, e), "=main.lua:getblocktxn"))

  local rec = { decodes = 0, bans = {}, served_by = nil }
  local headers, stored = {}, {}
  for h, blk in pairs(blocks) do
    local hash = validation.compute_block_hash(blk.header)
    local hx = types.hash256_hex(hash)
    headers[hx] = { header = blk.header, height = h }
    stored[hx] = serialize.serialize_block(blk)
  end

  local header_chain = { headers = headers }
  function header_chain:get_header(hash)
    return self.headers[types.hash256_hex(hash)]
  end

  local db = {}
  function db.get_block(hash)
    local data = stored[types.hash256_hex(hash)]
    if not data then return nil end
    rec.decodes = rec.decodes + 1
    return serialize.deserialize_block(data)
  end

  local pm = { handlers = {} }
  function pm:register_handler(cmd, fn) self.handlers[cmd] = fn end
  function pm:misbehaving(peer, score, reason)
    rec.bans[#rec.bans + 1] = { score = score, reason = reason }
  end
  function pm:add_ban_score(peer, score, reason) self:misbehaving(peer, score, reason) end

  local serve_getdata_item = function() end
  rec.serve_getdata_item = serve_getdata_item

  local env = setmetatable({
    peer_manager = pm,
    header_chain = header_chain,
    chain_state = { tip_height = tip },
    db = db,
    p2p = p2p, serialize = serialize, types = types,
    compact_block = compact_block,
    serve_getdata_item = serve_getdata_item,
    print = function() end,
  }, { __index = _G })
  setfenv(chunk, env)
  chunk()
  assert(pm.handlers.getblocktxn, "getblocktxn handler was not registered")
  return pm.handlers.getblocktxn, rec
end

local function new_peer()
  local p = { ip = "10.1.2.3", port = 18444, sent = {}, getdata = {} }
  function p:send_message(cmd, payload)
    self.sent[#self.sent + 1] = { cmd = cmd, payload = payload }
  end
  function p:queue_getdata(items, serve)
    for _, it in ipairs(items) do
      self.getdata[#self.getdata + 1] = { item = it, serve = serve }
    end
  end
  return p
end

local function request(blk, indexes)
  return p2p.serialize_getblocktxn(validation.compute_block_hash(blk.header), indexes)
end

local function txid_hex(tx)
  return types.hash256_hex(validation.compute_txid(tx))
end

describe("getblocktxn depth limit and index bounds (H6)", function()
  local TIP = 100

  it("answers a request 11 blocks deep with the full block, without decoding it", function()
    local deep = make_block(TIP - 11)
    local handler, rec = build(TIP, { [TIP - 11] = deep })
    local peer = new_peer()
    handler(peer, request(deep, { 1 }))
    assert.equals(0, rec.decodes)               -- the block was not read for a blocktxn
    assert.equals(0, #peer.sent)                -- and no blocktxn was built
    assert.equals(1, #peer.getdata)             -- Core: m_getdata_requests.push_back
    local g = peer.getdata[1]
    assert.equals(p2p.INV_TYPE.MSG_WITNESS_BLOCK, g.item.type)
    assert.equals(types.hash256_hex(validation.compute_block_hash(deep.header)),
      types.hash256_hex(g.item.hash))
    assert.equals(rec.serve_getdata_item, g.serve)  -- served by the getdata path
    assert.equals(0, #rec.bans)                 -- Core does not punish this
  end)

  it("does not decode anything for 1,000 deep requests", function()
    local deep = make_block(TIP - 50)
    local handler, rec = build(TIP, { [TIP - 50] = deep })
    local peer = new_peer()
    local payload = request(deep, { 1, 2 })
    for _ = 1, 1000 do handler(peer, payload) end
    assert.equals(0, rec.decodes)
    assert.equals(0, #peer.sent)
    assert.equals(1000, #peer.getdata)
  end)

  it("still answers a request exactly 10 blocks deep with a blocktxn", function()
    local blk = make_block(TIP - 10)
    local handler, rec = build(TIP, { [TIP - 10] = blk })
    local peer = new_peer()
    handler(peer, request(blk, { 1, 3 }))
    assert.equals(1, rec.decodes)
    assert.equals(0, #peer.getdata)
    assert.equals(1, #peer.sent)
    assert.equals("blocktxn", peer.sent[1].cmd)
    local resp = p2p.deserialize_blocktxn(peer.sent[1].payload)
    assert.equals(2, #resp.transactions)
    assert.equals(txid_hex(blk.transactions[2]), txid_hex(resp.transactions[1]))
    assert.equals(txid_hex(blk.transactions[4]), txid_hex(resp.transactions[2]))
    assert.equals(0, #rec.bans)
  end)

  it("scores the peer for an index past the end of the block and sends nothing", function()
    local blk = make_block(TIP)
    local handler, rec = build(TIP, { [TIP] = blk })
    local peer = new_peer()
    handler(peer, request(blk, { 1, 500 }))
    assert.equals(1, #rec.bans)                 -- Core: Misbehaving
    assert.equals(100, rec.bans[1].score)
    assert.truthy(rec.bans[1].reason:find("out-of-bounds", 1, true))
    assert.equals(0, #peer.sent)                -- no partial blocktxn
  end)

  it("treats index == number of transactions as out of range", function()
    local blk = make_block(TIP - 1)
    local handler, rec = build(TIP, { [TIP - 1] = blk })
    local peer = new_peer()
    handler(peer, request(blk, { #blk.transactions }))
    assert.equals(1, #rec.bans)
    assert.equals(0, #peer.sent)
  end)

  it("ignores a request for a block it does not know", function()
    local known = make_block(TIP)
    local unknown = make_block(TIP + 7)
    local handler, rec = build(TIP, { [TIP] = known })
    local peer = new_peer()
    handler(peer, request(unknown, { 0 }))
    assert.equals(0, rec.decodes)
    assert.equals(0, #peer.sent)
    assert.equals(0, #peer.getdata)
    assert.equals(0, #rec.bans)
  end)

  -- The handler hands deep requests to serve_getdata_item, which main.lua
  -- defines after it; the spec injects a stub, so check the live scoping:
  -- the local is declared before the handler and the later definition
  -- assigns that local instead of declaring a new one.
  it("hands deep requests to the getdata server that main.lua defines later", function()
    local src = read_main()
    local h = assert(src:find('  peer_manager:register_handler("getblocktxn"', 1, true))
    local decl = src:find("\n  local serve_getdata_item\n", 1, true)
    assert.truthy(decl and decl < h, "serve_getdata_item is not declared before the handler")
    assert.is_nil(src:find("local function serve_getdata_item", 1, true))
    local def = src:find("\n  function serve_getdata_item(", 1, true)
    assert.truthy(def and def > h, "serve_getdata_item is not defined after the handler")
  end)
end)
