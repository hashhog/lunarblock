-- P2P "tx" handler: orphan routing (child-before-parent) and punishment.
--
-- The handler is a closure inside main.lua's main(), so it cannot be
-- required.  Instead of testing a copy of the logic, this spec EXTRACTS the
-- live source text of the handler and of try_resolve_orphans from
-- src/main.lua and runs it against a real Mempool + real OrphanPool, with
-- only the peer manager stubbed (it records bans and relays).
--
-- Core references:
--   node/txdownloadman_impl.cpp MempoolRejectedTx: TX_MISSING_INPUTS → the
--     orphanage (m_orphanage->AddTx), not the recent-rejects filter.
--   node/txdownloadman_impl.cpp MempoolAcceptedTx → AddChildrenToWorkSet:
--     a parent's arrival re-evaluates its orphaned children.
--   net_processing.cpp ProcessInvalidTx: no Misbehaving() for any tx.

local types = require("lunarblock.types")
local mempool_mod = require("lunarblock.mempool")
local serialize = require("lunarblock.serialize")
local validation = require("lunarblock.validation")
local fault = require("lunarblock.fault")

local function read_main()
  local f = assert(io.open("src/main.lua", "r"))
  local s = f:read("*a")
  f:close()
  return s
end

-- Return the source text from `start_marker` up to and including the first
-- `end_marker` after it.
local function slice(src, start_marker, end_marker)
  local a = src:find(start_marker, 1, true)
  assert(a, "marker not found in src/main.lua: " .. start_marker)
  local b, e = src:find(end_marker, a, true)
  assert(b, "end marker not found after " .. start_marker)
  return src:sub(a, e)
end

-- Build the live tx handler from main.lua's own source.
local function build_handler(mp, pool)
  local src = read_main()
  local handler_src = slice(src,
    'peer_manager:register_handler("tx", function(peer, payload)', "\n  end)\n")
  local resolver_src = slice(src,
    "  try_resolve_orphans = function(parent_txid_hex)", "\n  end\n")
  local chunk_src = "local try_resolve_orphans\n" .. handler_src .. "\n"
                    .. resolver_src
  local chunk = assert(loadstring(chunk_src, "=main.lua:tx-handler"))

  local pm = { bans = {}, relayed = {}, handlers = {} }
  function pm:register_handler(cmd, fn) self.handlers[cmd] = fn end
  function pm:add_ban_score(peer, score, reason)
    self.bans[#self.bans + 1] = { score = score, reason = reason }
  end
  function pm:queue_tx_announcement(txid, wtxid, tx)
    self.relayed[#self.relayed + 1] = types.hash256_hex(txid)
  end

  local env = setmetatable({
    peer_manager = pm,
    mempool = mp,
    mempool_mod = mempool_mod,
    orphan_pool = pool,
    validation = validation,
    types = types,
    serialize = serialize,
    fault = fault,
    fee_estimator = { track_tx = function() end },
    chain_state = mp.chain_state,
    zmq_notifier = nil,
  }, { __index = _G })
  setfenv(chunk, env)
  chunk()
  assert(pm.handlers.tx, "tx handler was not registered")
  return pm.handlers.tx, pm
end

local P2PKH = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"

local function chain_with_utxos(list)
  local utxos = {}
  for _, u in ipairs(list) do
    utxos[u[1] .. ":" .. u[2]] = {
      value = u[3], script_pubkey = P2PKH, height = 500000, is_coinbase = false,
    }
  end
  return {
    coin_view = {
      get = function(_, txid, vout)
        return utxos[types.hash256_hex(txid) .. ":" .. vout]
      end,
    },
    tip_height = 700000,
  }
end

local function spend(prev_txid, vout, value)
  return types.transaction(1,
    { types.txin(types.outpoint(prev_txid, vout), "", 0xFFFFFFFE) },
    { types.txout(value, P2PKH) }, 0)
end

local function wire(tx) return serialize.serialize_transaction(tx, true) end
local function txid_hex(tx) return types.hash256_hex(validation.compute_txid(tx)) end

local PEER = { ip = "10.0.0.1", port = 8333 }

describe("p2p tx handler (main.lua, live source)", function()
  local root = types.hash256(string.rep("\x11", 32))
  local root2 = types.hash256(string.rep("\x22", 32))
  local mp, pool, handle, pm

  before_each(function()
    mp = mempool_mod.new(chain_with_utxos({
      { types.hash256_hex(root), 0, 100000 },
      { types.hash256_hex(root2), 0, 100000 },
    }))
    pool = mempool_mod.new_orphan_pool()
    handle, pm = build_handler(mp, pool)
  end)

  it("mempool reports a missing parent with the typed missing-inputs token", function()
    local parent = spend(root, 0, 90000)
    local child = spend(validation.compute_txid(parent), 0, 80000)
    local ok, reason = mp:accept_transaction(child)
    assert.is_false(ok)
    assert.is_true(mempool_mod.is_missing_inputs(reason),
      "unexpected reject token: " .. tostring(reason))
  end)

  it("orphans a child that arrives before its parent, then accepts it when the parent arrives", function()
    local parent = spend(root, 0, 90000)
    local child = spend(validation.compute_txid(parent), 0, 80000)

    handle(PEER, wire(child))
    assert.equal(1, pool:size(), "child must be buffered in the orphan pool")
    assert.is_nil(mp:get_entry(txid_hex(child)))
    assert.equal(0, #pm.bans)

    handle(PEER, wire(parent))
    assert.is_not_nil(mp:get_entry(txid_hex(parent)), "parent accepted")
    assert.is_not_nil(mp:get_entry(txid_hex(child)),
      "child must be accepted once its parent arrives")
    assert.equal(0, pool:size())
    -- Both are relayed (Core RelayTransaction for the resolved orphan too).
    assert.equal(2, #pm.relayed)
    assert.equal(0, #pm.bans)
  end)

  it("keeps a two-parent child orphaned until the second parent arrives", function()
    local p1 = spend(root, 0, 90000)
    local p2 = spend(root2, 0, 90000)
    local child = types.transaction(1, {
      types.txin(types.outpoint(validation.compute_txid(p1), 0), "", 0xFFFFFFFE),
      types.txin(types.outpoint(validation.compute_txid(p2), 0), "", 0xFFFFFFFE),
    }, { types.txout(170000, P2PKH) }, 0)

    handle(PEER, wire(child))
    assert.equal(1, pool:size())
    handle(PEER, wire(p1))
    assert.equal(1, pool:size(), "still missing p2: must stay orphaned")
    assert.is_nil(mp:get_entry(txid_hex(child)))
    handle(PEER, wire(p2))
    assert.is_not_nil(mp:get_entry(txid_hex(child)))
    assert.equal(0, pool:size())
  end)
end)

describe("p2p tx handler never punishes the relaying peer", function()
  -- Core net_processing.cpp ProcessInvalidTx: no Misbehaving() for any
  -- TxValidationResult; an exception in ProcessMessage is only logged.
  local root = types.hash256(string.rep("\x33", 32))
  local mp, pool, handle, pm

  before_each(function()
    mp = mempool_mod.new(chain_with_utxos({ { types.hash256_hex(root), 0, 100000 } }))
    pool = mempool_mod.new_orphan_pool()
    handle, pm = build_handler(mp, pool)
  end)

  it("does not punish a peer for a tx payload that fails to deserialize", function()
    handle(PEER, "\x01\x00\x00\x00\xff")  -- truncated: the reader throws
    assert.equal(0, #pm.bans)
  end)

  it("does not punish a peer when mempool admission throws a plain error", function()
    mp.accept_transaction = function() error("internal bug in admission") end
    handle(PEER, wire(spend(root, 0, 90000)))
    assert.equal(0, #pm.bans)
  end)

  it("does not punish a peer for a system fault (control: already true on 86efc28)", function()
    mp.accept_transaction = function() fault.raise("db write failed") end
    handle(PEER, wire(spend(root, 0, 90000)))
    assert.equal(0, #pm.bans)
  end)

  it("does not punish a peer for a consensus-invalid tx (control)", function()
    -- outputs exceed inputs: bad-txns-in-belowout, a verdict, still no ban
    handle(PEER, wire(spend(root, 0, 200000)))
    assert.is_nil(mp:get_entry(txid_hex(spend(root, 0, 200000))))
    assert.equal(0, #pm.bans)
  end)
end)
