-- P2P "inv": a block announcement sends at most one getheaders per inv and
-- does not change the header-sync peer.
--
-- Security finding H7 (fleet security audit, 2026-11-08): every MSG_BLOCK
-- item called header_chain:start_sync(peer), so one 50,000-item inv sent
-- ~50,000 getheaders (~50 MB of locators) back at the sender and made the
-- sender the global header-sync peer (sync_peer), evicting whichever peer
-- was syncing us.
--
-- Core (net_processing.cpp, INV): block items only record the last unknown
-- hash (best_block = &inv.hash, skipped when AlreadyHaveBlock); after the loop
-- ONE MaybeSendGetHeaders(pfrom, ...), which refuses while a getheaders to
-- that peer is younger than HEADERS_RESPONSE_TIME (m_last_getheaders_timestamp,
-- cleared when connecting headers arrive).  The inv path never touches the
-- headers-sync bookkeeping of another peer.
--
-- The handler is a closure inside main.lua's main(), so this spec slices the
-- LIVE inv handler out of src/main.lua (the technique of
-- sec_cmpctblock_header_spec.lua) and runs it against a real regtest
-- HeaderChain; only the peer manager and mempool are stubbed.

local helpers = require("spec.helpers")
local types = require("lunarblock.types")
local consensus = require("lunarblock.consensus")
local p2p = require("lunarblock.p2p")
local sync = require("lunarblock.sync")

local REGTEST = consensus.networks.regtest

local function build_inv_handler(chain)
  local f = assert(io.open("src/main.lua", "r"))
  local src = f:read("*a")
  f:close()
  local a = src:find('peer_manager:register_handler("inv", function(peer, payload)', 1, true)
  assert(a, "inv handler not found in src/main.lua")
  local _, e = src:find("\n  end)\n", a, true)
  assert(e, "end of inv handler not found")
  local chunk = assert(loadstring(src:sub(a, e), "=main.lua:inv"))

  local pm = { handlers = {} }
  function pm:register_handler(cmd, fn) self.handlers[cmd] = fn end
  function pm:claim_tx_request() return true end
  local mempool = {}
  function mempool:has() return false end
  function mempool:has_wtxid() return false end

  setfenv(chunk, setmetatable({
    peer_manager = pm,
    header_chain = chain,
    mempool = mempool,
    p2p = p2p, types = types,
    note_peer_has_block = function() end,
  }, { __index = _G }))
  chunk()
  assert(pm.handlers.inv, "inv handler was not registered")
  return pm.handlers.inv
end

local function new_chain()
  local chain = sync.new_header_chain(REGTEST, helpers.mock_storage())
  chain:init()
  return chain
end

local function new_peer(ip)
  local p = { ip = ip, port = 18444, sent = {} }
  function p:send_message(cmd, payload)
    self.sent[#self.sent + 1] = cmd
    return true
  end
  return p
end

local function count(peer, cmd)
  local n = 0
  for _, c in ipairs(peer.sent) do
    if c == cmd then n = n + 1 end
  end
  return n
end

-- n distinct block hashes that are not in the header chain.
local function block_inv(n, salt)
  local items = {}
  for i = 1, n do
    items[i] = {
      type = p2p.INV_TYPE.MSG_BLOCK,
      hash = types.hash256(string.sub(string.format("%s:%d", salt or "blk", i)
        .. string.rep("\1", 32), 1, 32)),
    }
  end
  return p2p.serialize_inv(items)
end

describe("H7: block inv -> getheaders", function()
  it("a 1,000-item block inv sends at most one getheaders and leaves sync_peer unchanged", function()
    local chain = new_chain()
    local on_inv = build_inv_handler(chain)
    local syncer = new_peer("10.0.0.1")
    chain:start_sync(syncer)
    assert.equals(syncer, chain.sync_peer)

    local attacker = new_peer("10.6.6.6")
    on_inv(attacker, block_inv(1000))
    assert.is_true(count(attacker, "getheaders") <= 1,
      "sent " .. count(attacker, "getheaders") .. " getheaders for one inv")
    assert.equals(syncer, chain.sync_peer)
    assert.is_true(chain.syncing)
  end)

  it("a block inv from another peer does not take the header-sync latch", function()
    local chain = new_chain()
    local on_inv = build_inv_handler(chain)
    local syncer = new_peer("10.0.0.1")
    chain:start_sync(syncer)
    on_inv(new_peer("10.6.6.7"), block_inv(1))
    assert.equals(syncer, chain.sync_peer)
  end)

  it("one new block announcement still fetches headers (tip following)", function()
    local chain = new_chain()
    local on_inv = build_inv_handler(chain)
    local peer = new_peer("10.0.0.2")
    on_inv(peer, block_inv(1))
    assert.equals(1, count(peer, "getheaders"))
  end)

  it("an inv for a block we already have sends no getheaders", function()
    local chain = new_chain()
    local on_inv = build_inv_handler(chain)
    local peer = new_peer("10.0.0.3")
    on_inv(peer, p2p.serialize_inv({
      { type = p2p.INV_TYPE.MSG_BLOCK, hash = chain.header_tip_hash },
    }))
    assert.equals(0, count(peer, "getheaders"))
  end)

  it("repeated invs while a getheaders is in flight do not resend; a headers reply re-arms", function()
    local chain = new_chain()
    local on_inv = build_inv_handler(chain)
    local peer = new_peer("10.0.0.4")
    for i = 1, 20 do on_inv(peer, block_inv(1, "r" .. i)) end
    assert.equals(1, count(peer, "getheaders"))

    -- The peer answers (empty headers = nothing past our locator).
    chain:handle_headers(peer, p2p.serialize_headers({}))
    on_inv(peer, block_inv(1, "next"))
    assert.equals(2, count(peer, "getheaders"))
  end)

  it("the in-flight mark expires after HEADERS_RESPONSE_TIME", function()
    local chain = new_chain()
    local peer = new_peer("10.0.0.5")
    assert.is_function(chain.maybe_send_getheaders,
      "HeaderChain has no per-peer getheaders in-flight limit")
    assert.is_true(chain:maybe_send_getheaders(peer, 1000))
    assert.is_false(chain:maybe_send_getheaders(peer, 1000 + sync.HeaderChain.HEADERS_RESPONSE_TIME))
    assert.is_true(chain:maybe_send_getheaders(peer, 1001 + sync.HeaderChain.HEADERS_RESPONSE_TIME))
    assert.equals(2, count(peer, "getheaders"))
  end)
end)
