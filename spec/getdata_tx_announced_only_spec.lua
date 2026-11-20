-- getdata serves a mempool tx only to a peer it was already announced to
-- (Core PeerManagerImpl::FindTxForGetData, bitcoin-core/src/net_processing.cpp:
-- "If a tx was in the mempool prior to the last INV for this peer, permit the
-- request", via CTxMemPool::info_for_relay(id, tx_relay.m_last_inv_sequence)).
--
-- Before this fix peerman.getdata_response served any mempool tx by txid or
-- wtxid to any peer that asked, so a peer could fetch a tx the moment it
-- reached our mempool, before the Poisson trickle (_process_trickle) had
-- announced it to that peer.  That undoes the trickle's timing privacy: the
-- first node to hand out a tx is a good guess at its origin.
--
-- Now each mempool entry records the mempool sequence at insert, each peer's
-- trickle state records the sequence at its last inv round, and a tx item is
-- served only when entry.sequence < the peer's last_inv_sequence.

local types = require("lunarblock.types")
local mempool_mod = require("lunarblock.mempool")
local validation = require("lunarblock.validation")
local serialize = require("lunarblock.serialize")
local p2p = require("lunarblock.p2p")
local peerman = require("lunarblock.peerman")
local peer_mod = require("lunarblock.peer")

local T = p2p.INV_TYPE

local NET = {
  name = "regtest", magic_bytes = "\xfa\xbf\xb5\xda", port = 18444,
  default_port = 18444, dns_seeds = {},
}

local P2WPKH_A = "\x00\x14" .. string.rep("\x11", 20)
local P2WPKH_B = "\x00\x14" .. string.rep("\x22", 20)

local function mock_chain_state()
  local utxos = {}
  return {
    coin_view = {
      utxos = utxos,
      get = function(self, txid, vout)
        return self.utxos[types.hash256_hex(txid) .. ":" .. vout]
      end,
    },
    tip_height = 700000,
  }, utxos
end

-- A segwit spend of a funded P2WPKH outpoint (prev byte `b`).
local function new_tx(utxos, b)
  local prev = types.hash256(string.rep(string.char(b), 32))
  utxos[types.hash256_hex(prev) .. ":0"] =
    { value = 100000, script_pubkey = P2WPKH_A, height = 500000, is_coinbase = false }
  local tx = types.transaction(2,
    { types.txin(types.outpoint(prev, 0), "", 0xFFFFFFFD) },
    { types.txout(90000, P2WPKH_B) }, 0)
  tx.inputs[1].witness = { string.rep("\x30", 71), "\x02" .. string.rep("\x33", 32) }
  tx.segwit = true
  return tx
end

local function mock_peer(i)
  local p = {
    ip = "10.7." .. i .. ".1", port = 8333, inbound = true,
    wtxid_relay = true, state = peer_mod.STATE.ESTABLISHED, invs = {},
  }
  function p:send_message(command, payload)
    if command == "inv" then
      for _, item in ipairs(p2p.deserialize_inv(payload)) do
        self.invs[types.hash256_hex(item.hash)] = item.type
      end
    end
  end
  return p
end

describe("getdata serves only announced txs (Core FindTxForGetData)", function()
  local mp, utxos, pm, P, Q, tx, wtxid, txid

  -- Deps exactly as main.lua's serve_getdata_item builds them for `peer`.
  -- On a base without get_last_inv_sequence the key is nil and the old
  -- ungated code serves; the assertions below then fail by name.
  local function ask(peer, type_, hash)
    local seq = pm.get_last_inv_sequence and pm:get_last_inv_sequence(peer)
    return peerman.getdata_response({ type = type_, hash = hash },
      { mempool = mp, last_inv_sequence = seq and seq or 0 })
  end

  local function trickle_round(peer)
    pm._peer_trickle[peer.ip .. ":" .. peer.port].next_send_time = 0
    pm:_process_trickle()
  end

  before_each(function()
    local cs
    cs, utxos = mock_chain_state()
    mp = mempool_mod.new(cs)
    pm = peerman.new(NET, nil, { data_dir = "/nonexistent-getdata-announced" })
    pm.mempool = mp  -- as main.lua wires it
    P, Q = mock_peer(1), mock_peer(2)
    for _, p in ipairs({ P, Q }) do
      pm.peer_list[#pm.peer_list + 1] = p
      pm.peers[p.ip .. ":" .. p.port] = p
      pm:_init_peer_trickle(p)
      -- Keep the Poisson timer from firing on its own during the test.
      pm._peer_trickle[p.ip .. ":" .. p.port].next_send_time = math.huge
    end
    tx = new_tx(utxos, 0x01)
    assert.is_true((mp:accept_transaction(tx)))
    txid = validation.compute_txid(tx)
    wtxid = validation.compute_wtxid(tx)
    pm:queue_tx_announcement(txid, wtxid, tx)
  end)

  it("refuses a tx not yet trickled to the requesting peer (notfound)", function()
    assert.is_nil(P.invs[types.hash256_hex(wtxid)])  -- not announced yet
    local cmd, data, status = ask(P, T.MSG_WTX, wtxid)
    assert.equal("notfound", status)
    assert.is_nil(cmd)
    assert.is_nil(data)
  end)

  it("refuses it by txid too (MSG_TX and MSG_WITNESS_TX)", function()
    assert.equal("notfound", select(3, ask(P, T.MSG_TX, txid)))
    assert.equal("notfound", select(3, ask(P, T.MSG_WITNESS_TX, txid)))
  end)

  it("positive control: served once the trickle has announced it", function()
    trickle_round(P)
    assert.equal(T.MSG_WTX, P.invs[types.hash256_hex(wtxid)])
    local cmd, data, status = ask(P, T.MSG_WTX, wtxid)
    assert.equal("served", status)
    assert.equal("tx", cmd)
    assert.equal(serialize.serialize_transaction(tx, true), data)
    assert.equal("served", select(3, ask(P, T.MSG_TX, txid)))
  end)

  it("is per peer: announcing to P does not open it to Q", function()
    trickle_round(P)
    assert.equal("served", select(3, ask(P, T.MSG_WTX, wtxid)))
    assert.is_nil(Q.invs[types.hash256_hex(wtxid)])
    assert.equal("notfound", select(3, ask(Q, T.MSG_WTX, wtxid)))
    trickle_round(Q)
    assert.equal("served", select(3, ask(Q, T.MSG_WTX, wtxid)))
  end)

  it("a tx that arrives after the peer's last inv round waits for the next", function()
    trickle_round(P)
    local tx2 = new_tx(utxos, 0x02)
    assert.is_true((mp:accept_transaction(tx2)))
    local w2 = validation.compute_wtxid(tx2)
    assert.equal("served", select(3, ask(P, T.MSG_WTX, wtxid)))
    assert.equal("notfound", select(3, ask(P, T.MSG_WTX, w2)))
    pm:queue_tx_announcement(validation.compute_txid(tx2), w2, tx2)
    trickle_round(P)
    assert.equal("served", select(3, ask(P, T.MSG_WTX, w2)))
  end)

  it("a peer without trickle state is served no tx", function()
    trickle_round(P)
    pm:_cleanup_peer_trickle(P)
    assert.equal("notfound", select(3, ask(P, T.MSG_WTX, wtxid)))
    -- and a caller that passes no sequence at all serves nothing
    assert.equal("notfound", select(3, peerman.getdata_response(
      { type = T.MSG_WTX, hash = wtxid }, { mempool = mp })))
  end)

  it("a reorg re-admission (bypass_limits) is servable at once, as in Core", function()
    -- Core PreChecks: entry_sequence = bypass_limits ? 0 : GetSequence(), so
    -- a tx put back from a disconnected block is not hidden from peers.
    local tx3 = new_tx(utxos, 0x03)
    assert.is_true((mp:accept_transaction(tx3, true, { bypass_limits = true })))
    assert.equal("served",
      select(3, ask(P, T.MSG_WTX, validation.compute_wtxid(tx3))))
  end)

  it("a tx restored with its old sequence (package-RBF rollback) stays gated", function()
    -- The rollback in accept_package passes the evicted entry's sequence
    -- back in (opts.entry_sequence) instead of bypass_limits' 0.
    local tx4 = new_tx(utxos, 0x04)
    local seq = mp.get_sequence and mp:get_sequence() or 1
    assert.is_true((mp:accept_transaction(tx4, false,
      { bypass_limits = true, entry_sequence = seq })))
    local w4 = validation.compute_wtxid(tx4)
    assert.equal("notfound", select(3, ask(P, T.MSG_WTX, w4)))
    trickle_round(P)
    assert.equal("served", select(3, ask(P, T.MSG_WTX, w4)))
  end)

  it("a tx sent by sendrawtransaction is served after its direct inv", function()
    -- sendrawtransaction announces with an immediate inv to every peer
    -- (PeerManager:broadcast), not through the trickle.  Those peers must
    -- still be served the getdata that follows.
    local rpc = require("lunarblock.rpc")
    local consensus = require("lunarblock.consensus")
    local cjson = require("cjson")
    local tx5 = new_tx(utxos, 0x05)
    local server = rpc.new({ network = consensus.networks.regtest,
      mempool = mp, peer_manager = pm })
    local hex = rpc.hex_encode(serialize.serialize_transaction(tx5, true))
    local d = cjson.decode((server:handle_request(
      '{"method":"sendrawtransaction","params":["' .. hex .. '"],"id":1}')))
    assert.truthy(d.error == nil or d.error == cjson.null)
    local t5 = validation.compute_txid(tx5)
    assert.equal(types.hash256_hex(t5), d.result)
    assert.is_not_nil(P.invs[types.hash256_hex(t5)])  -- the direct inv
    assert.equal("served", select(3, ask(P, T.MSG_WITNESS_TX, t5)))
    assert.equal("served", select(3, ask(Q, T.MSG_WTX, validation.compute_wtxid(tx5))))
  end)

  it("a getdata does not clear unbroadcast for a tx it refused", function()
    local h = types.hash256_hex(txid)
    mp:add_unbroadcast(h)
    assert.equal("notfound", select(3, ask(P, T.MSG_WTX, wtxid)))
    assert.is_true(mp:is_unbroadcast(h))
    trickle_round(P)
    assert.equal("served", select(3, ask(P, T.MSG_WTX, wtxid)))
    assert.is_false(mp:is_unbroadcast(h))
  end)
end)
