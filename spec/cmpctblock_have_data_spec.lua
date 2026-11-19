-- P2P "cmpctblock": a compact block for a block we already have, or one with
-- no more work than the active tip, is not reconstructed.
--
-- Finding (cfaudit lunarblock 2026-11-18, residual of C4 / lunarblock#46):
-- a resent cmpctblock for an already-known valid header (the tip, or up to
-- MAX_CMPCTBLOCK_DEPTH below it) passed the header gate, because
-- HeaderChain:accept_header returns true for a known header.  Every copy
-- then ran PartiallyDownloadedBlock init -- a full mempool scan with
-- pure-Lua SipHash per entry -- and sent a getblocktxn.  k copies against a
-- mempool of N cost k*N short-id computations.
--
-- Core (net_processing.cpp, CMPCTBLOCK), after ProcessNewBlockHeaders:
--   if (pindex->nStatus & BLOCK_HAVE_DATA) return;          // nothing to do
--   if (pindex->nChainWork <= ActiveChain().Tip()->nChainWork || nTx != 0) {
--       if (requested_block_from_this_peer) getdata(full block);
--       return;
--   }
-- Only then does PartiallyDownloadedBlock::InitData touch the mempool.
--
-- Like sec_cmpctblock_header_spec.lua this slices the LIVE compact-block
-- section of src/main.lua and runs it against a real regtest HeaderChain;
-- the peer manager, mempool, chain state and block downloader are stubs.

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

-- A mempool of n entries with random wtxids (none matches a short id).
local function stub_mempool(n)
  local entries = {}
  for i = 1, n do
    local b = {}
    for j = 1, 32 do b[j] = string.char(math.random(0, 255)) end
    entries[i] = table.concat(b)
  end
  local mp = {}
  function mp:iter_by_wtxid()
    local i = 0
    return function()
      i = i + 1
      if entries[i] then return entries[i], { dummy = i } end
      return nil
    end
  end
  return mp
end

local function build(chain, chain_state, block_downloader, mempool)
  local src = read_main()
  local ban_src = slice(src, "  local HEADERS_BAN_SUBSTRINGS = {", "\n  end\n")
  local a = src:find('  local compact_block = require("lunarblock.compact_block")', 1, true)
  assert(a, "compact block section not found in src/main.lua")
  local b = src:find('peer_manager:register_handler("blocktxn"', a, true)
  assert(b, "blocktxn handler not found")
  local _, e = src:find("\n  end)\n", b, true)
  assert(e, "end of blocktxn handler not found")
  local chunk = assert(loadstring(ban_src .. "\n" .. src:sub(a, e),
    "=main.lua:cmpctblock"))

  local pm = { handlers = {}, our_height = 0, bans = {} }
  function pm:register_handler(cmd, fn) self.handlers[cmd] = fn end
  function pm:add_ban_score(peer, score, reason)
    self.bans[#self.bans + 1] = { score = score, reason = reason }
  end
  function pm:note_peer_best_block() end

  local env = setmetatable({
    peer_manager = pm,
    header_chain = chain,
    mempool = mempool,
    block_downloader = block_downloader,
    chain_state = chain_state,
    network = REGTEST,
    p2p = p2p, serialize = serialize, crypto = crypto, types = types,
    -- no `consensus` here: main.lua has no such local, so the handler
    -- must not depend on one (it resolves to nil in the live node).
    validation = validation,
    note_peer_has_block = function() end,
  }, { __index = function(_, k) return k ~= "consensus" and _G[k] or nil end })
  setfenv(chunk, env)
  chunk()
  assert(pm.handlers.cmpctblock, "cmpctblock handler was not registered")
  return pm.handlers, pm
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

-- Valid regtest-PoW block on top of parent_hex, coinbase + txs.
local function make_block(chain, parent_hex, txs, tag)
  local parent = chain.headers[parent_hex]
  local height = parent.height + 1
  local all = { coinbase(height, tag) }
  for _, tx in ipairs(txs or {}) do all[#all + 1] = tx end
  local txids = {}
  for i, tx in ipairs(all) do txids[i] = validation.compute_txid(tx) end
  local header = types.block_header(4, types.hash256_from_hex(parent_hex),
    crypto.compute_merkle_root(txids), parent.header.timestamp + 1, 0x207fffff, 0)
  local target = consensus.bits_to_target(header.bits)
  for nonce = 0, 100000 do
    header.nonce = nonce
    if consensus.hash_meets_target(
      validation.compute_block_hash(header).bytes, target) then break end
  end
  return types.block(header, all)
end

local function block_hex(blk)
  return types.hash256_hex(validation.compute_block_hash(blk.header))
end

-- Compact form: coinbase prefilled, one short id per other tx.
local function cmpct_payload(blk)
  return compact_block.serialize(compact_block.create_compact_block(blk, 7))
end

-- Build the payload outside the counted window (create_compact_block itself
-- computes the block's short ids), then reset the counter.
local reset_counter
local function payload_for(blk)
  local p = cmpct_payload(blk)
  reset_counter()
  return p
end

local function new_peer()
  local p = { ip = "10.1.2.3", port = 18444, sent = {} }
  function p:send_message(cmd, payload)
    self.sent[#self.sent + 1] = cmd
  end
  return p
end

local function count_of(cmd, list)
  local n = 0
  for _, c in ipairs(list) do if c == cmd then n = n + 1 end end
  return n
end

local N = 200   -- mempool entries
local K = 5     -- resent copies

describe("cmpctblock for a block we have / with no more work than the tip", function()
  local real_short_id, short_id_calls
  before_each(function()
    real_short_id = crypto.compact_block_short_id
    short_id_calls = 0
    reset_counter = function() short_id_calls = 0 end
    crypto.compact_block_short_id = function(...)
      short_id_calls = short_id_calls + 1
      return real_short_id(...)
    end
  end)
  after_each(function()
    crypto.compact_block_short_id = real_short_id
  end)

  -- Chain genesis -> b1 -> ... -> b<n>, headers accepted, the active tip
  -- moved to b<n> and every body stored (as if connected).
  local function connected_chain(n)
    local storage = helpers.mock_storage()
    local chain = sync.new_header_chain(REGTEST, storage)
    chain:init()
    local blocks = {}
    local parent_hex = types.hash256_hex(chain:get_tip_hash())
    for i = 1, n do
      local blk = make_block(chain, parent_hex, { spend(i) }, "c" .. i)
      local accepted, herr = chain:process_headers({ blk.header })
      assert.is_nil(herr)
      local hash = validation.compute_block_hash(blk.header)
      storage.put(storage.CF.BLOCKS, hash.bytes, serialize.serialize_block(blk))
      blocks[i] = blk
      parent_hex = block_hex(blk)
    end
    local tip = blocks[n]
    local chain_state = {
      tip_hash = validation.compute_block_hash(tip.header),
      tip_height = n,
      header_tip_height = n,
    }
    return chain, chain_state, blocks, storage
  end

  it("a resent cmpctblock for the connected tip does no mempool scan and no getblocktxn", function()
    local chain, cs, blocks = connected_chain(1)
    local bd = { inflight = {}, pending_blocks = {} }
    function bd:handle_block() error("must not be handed a block") end
    local h = build(chain, cs, bd, stub_mempool(N))
    local peer = new_peer()
    local pl = payload_for(blocks[1])
    for _ = 1, K do h.cmpctblock(peer, pl) end
    assert.equals(0, short_id_calls)
    assert.equals(0, count_of("getblocktxn", peer.sent))
    assert.is_nil(next(peer.pending_compact or {}))
  end)

  it("a cmpctblock for a connected block 3 below the tip does no mempool scan", function()
    local chain, cs, blocks = connected_chain(4)
    local bd = { inflight = {}, pending_blocks = {} }
    function bd:handle_block() error("must not be handed a block") end
    local h = build(chain, cs, bd, stub_mempool(N))
    local peer = new_peer()
    local pl = payload_for(blocks[1])
    for _ = 1, K do h.cmpctblock(peer, pl) end
    assert.equals(0, short_id_calls)
    assert.equals(0, count_of("getblocktxn", peer.sent))
  end)

  it("a cmpctblock with no more work than the tip, requested from this peer, gets a full-block getdata", function()
    local chain, cs, blocks = connected_chain(2)
    local hx = block_hex(blocks[2])
    local peer = new_peer()
    local bd = { inflight = { [hx] = { peer = peer } }, pending_blocks = {} }
    function bd:handle_block() error("must not be handed a block") end
    local h = build(chain, cs, bd, stub_mempool(N))
    h.cmpctblock(peer, payload_for(blocks[2]))
    assert.equals(0, short_id_calls)
    assert.same({ "getdata" }, peer.sent)
    -- requested from ANOTHER peer: nothing sent to this one
    local other = new_peer()
    h.cmpctblock(other, payload_for(blocks[2]))
    assert.equals(0, short_id_calls)
    assert.same({}, other.sent)
  end)

  it("a cmpctblock for a block with more work whose body is already stored is not reconstructed", function()
    local chain, cs, blocks, storage = connected_chain(1)
    -- b2 extends the tip; its header is new but its body is already on disk
    -- (received, not yet connected).
    local b2 = make_block(chain, block_hex(blocks[1]), { spend(77) }, "x")
    storage.put(storage.CF.BLOCKS, validation.compute_block_hash(b2.header).bytes,
      serialize.serialize_block(b2))
    local bd = { inflight = {}, pending_blocks = {} }
    function bd:handle_block() error("must not be handed a block") end
    local h = build(chain, cs, bd, stub_mempool(N))
    local peer = new_peer()
    local pl = payload_for(b2)
    for _ = 1, K do h.cmpctblock(peer, pl) end
    assert.is_not_nil(chain.headers[block_hex(b2)])   -- header still accepted
    assert.equals(0, short_id_calls)
    assert.equals(0, count_of("getblocktxn", peer.sent))
  end)

  it("a cmpctblock for a block with more work held in pending_blocks is not reconstructed", function()
    local chain, cs, blocks = connected_chain(1)
    local b2 = make_block(chain, block_hex(blocks[1]), { spend(78) }, "y")
    local bd = { inflight = {}, pending_blocks = { [block_hex(b2)] = { dummy = true } } }
    function bd:handle_block() error("must not be handed a block") end
    local h = build(chain, cs, bd, stub_mempool(N))
    local peer = new_peer()
    h.cmpctblock(peer, payload_for(b2))
    assert.equals(0, short_id_calls)
    assert.equals(0, count_of("getblocktxn", peer.sent))
  end)

  it("a new block extending the tip is still reconstructed: one scan, one getblocktxn", function()
    local chain, cs, blocks = connected_chain(1)
    local b2 = make_block(chain, block_hex(blocks[1]), { spend(79) }, "z")
    local bd = { inflight = {}, pending_blocks = {} }
    function bd:handle_block() error("must not be handed a block") end
    local h = build(chain, cs, bd, stub_mempool(N))
    local peer = new_peer()
    h.cmpctblock(peer, payload_for(b2))
    assert.equals(N, short_id_calls)
    assert.same({ "getblocktxn" }, peer.sent)
    assert.is_not_nil(chain.headers[block_hex(b2)])
  end)
end)
