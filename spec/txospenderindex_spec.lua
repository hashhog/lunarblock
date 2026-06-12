-- spec/txospenderindex_spec.lua
--
-- Proves the txospenderindex (spent-outpoint -> spending-tx index) and the
-- gettxspendingprevout RPC port, mirroring bitcoin-core's TxoSpenderIndex
-- (src/index/txospenderindex.{h,cpp}) + rpc/mempool.cpp::gettxspendingprevout.
--
-- Proof obligations (per the AXIS #3 design):
--   1. CONNECT: a block where tx B spends an output of tx A indexes
--      A:0 -> spending txid = B (+ confirming block hash).
--   2. invalidateblock DISCONNECT: erases A:0 (find_spender -> nil).
--   3. LIVE REORG DISCONNECT: a heavier branch that orphans B erases A:0
--      (this is the rustoshi lesson — both the invalidateblock path AND the
--      live submitblock/reorg path must undo the index; lunarblock funnels
--      both through the single unified disconnect_block, so this proves both).
--   4. FALSIFICATION: with the index DISABLED, the pre-impl does NOT answer
--      (find_spender -> nil, and gettxspendingprevout's confirmed path is
--      unavailable -> RPC_MISC_ERROR -1).
--   5. RPC error-code parity: empty outputs -> -8, negative vout -> -8,
--      strict unknown key -> -3, index unavailable -> -1.

local types = require("lunarblock.types")
local utxo = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local script = require("lunarblock.script")
local storage_mod = require("lunarblock.storage")
local rpc = require("lunarblock.rpc")

-- ── Block-building helpers (lifted from chainstate_corruption_spec). ─────────
local function make_coinbase_tx(height, value, script_pubkey)
  local coinbase_sig = string.char(1, height % 256)
  return types.transaction(
    1,
    {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                coinbase_sig, 0xFFFFFFFF)},
    {types.txout(value, script_pubkey)},
    0
  )
end

-- nonce lets two blocks at the same height (active vs side-branch) differ.
local function make_block(height, transactions, prev_hash, nonce)
  local header = types.block_header(
    1,
    prev_hash or types.hash256_zero(),
    types.hash256_zero(),
    os.time() + height + (nonce or 0) * 1000000,
    consensus.networks.regtest.pow_limit_bits,
    nonce or 0
  )
  return types.block(header, transactions)
end

-- Store + connect a tip-extending block; returns its hash.
local function connect(chain_state, db, height, txs, prev_hash, nonce)
  local block = make_block(height, txs, prev_hash, nonce)
  local block_hash = validation.compute_block_hash(block.header)
  db.put_header(block_hash, block.header)
  db.put_block(block_hash, block)
  db.put_height_index(height, block_hash)
  local ok, err = chain_state:connect_block(block, height, block_hash, nil, nil, true)
  assert(ok, "connect_block failed at height " .. height .. ": " .. tostring(err))
  return block_hash, block
end

-- Store a side-branch block (header + body only, NO height index) so
-- accept_side_branch_block can reorg onto it.
local function store_side(db, height, txs, prev_hash, nonce)
  local block = make_block(height, txs, prev_hash, nonce)
  local block_hash = validation.compute_block_hash(block.header)
  db.put_header(block_hash, block.header)
  db.put_block(block_hash, block)
  return block_hash, block
end

local PKH = string.rep("\x42", 20)
local SPK = script.make_p2pkh_script(PKH)

-- Build a matured chain of `n` coinbase-only blocks (heights 0..n-1) with the
-- txospenderindex toggled per `enabled`.  Returns db, chain_state, hashes,
-- coinbase-txid-by-height map, path.
local function build_base(n, enabled)
  local tmp_path = "/tmp/lunarblock_txospender_"
    .. os.time() .. "_" .. math.random(100000000)
  local db = storage_mod.open(tmp_path)
  local chain_state = utxo.new_chain_state(db, consensus.networks.regtest)
  chain_state:set_txospenderindex_enabled(enabled)
  chain_state:init()

  local hashes, cb_txid = {}, {}
  local prev = types.hash256_zero()
  for h = 0, n - 1 do
    local cb = make_coinbase_tx(h, 5000000000, SPK)
    cb_txid[h] = validation.compute_txid(cb)
    local bh = connect(chain_state, db, h, {cb}, prev)
    hashes[h] = bh
    prev = bh
  end
  return db, chain_state, hashes, cb_txid, tmp_path
end

describe("txospenderindex", function()

  it("CONNECT: indexes spent-outpoint -> spending tx (+ block hash)", function()
    -- 102 coinbase blocks (heights 0..101) -> h=1 coinbase is mature at h=102.
    local db, cs, hashes, cb_txid = build_base(102, true)

    -- tx A = the coinbase at h=1; its output A:0 is what B spends.
    local A_txid = cb_txid[1]

    -- Block at h=102: coinbase + tx B spending A:0.
    local coinbase = make_coinbase_tx(102, 5000000000, SPK)
    local B = types.transaction(
      1,
      {types.txin(types.outpoint(A_txid, 0), "", 0xFFFFFFFF)},
      {types.txout(4999990000, SPK)},
      0)
    local B_txid = validation.compute_txid(B)
    local bh102 = connect(cs, db, 102, {coinbase, B}, hashes[101])

    -- find_spender(A:0) -> B (+ confirming block hash bh102).
    local rec = cs:find_spender({ hash = A_txid, index = 0 })
    assert.is_not_nil(rec, "A:0 should be indexed as spent by B")
    assert.equal(types.hash256_hex(B_txid), types.hash256_hex(rec.spending_txid))
    assert.equal(types.hash256_hex(bh102), types.hash256_hex(rec.block_hash))
    -- full spending tx round-trips.
    assert.equal(B_txid.bytes,
      validation.compute_txid(
        require("lunarblock.serialize").deserialize_transaction(rec.spending_tx_bytes)).bytes)

    db.close()
  end)

  it("invalidateblock DISCONNECT erases the spend entry", function()
    local db, cs, hashes, cb_txid = build_base(102, true)
    local A_txid = cb_txid[1]
    local coinbase = make_coinbase_tx(102, 5000000000, SPK)
    local B = types.transaction(1,
      {types.txin(types.outpoint(A_txid, 0), "", 0xFFFFFFFF)},
      {types.txout(4999990000, SPK)}, 0)
    local bh102 = connect(cs, db, 102, {coinbase, B}, hashes[101])

    assert.is_not_nil(cs:find_spender({ hash = A_txid, index = 0 }),
      "precondition: A:0 indexed before invalidate")

    -- invalidate_block -> disconnect_block(invalidateblock path) -> erase.
    local ok, err = cs:invalidate_block(bh102)
    assert.is_true(ok, "invalidate_block failed: " .. tostring(err))

    assert.is_nil(cs:find_spender({ hash = A_txid, index = 0 }),
      "A:0 must be ERASED after invalidateblock disconnect")
    -- best height rewound to 101.
    assert.equal(101, cs.tip_height)

    db.close()
  end)

  it("LIVE REORG (heavier branch orphans B) erases the spend entry", function()
    local db, cs, hashes, cb_txid = build_base(102, true)
    local A_txid = cb_txid[1]

    -- Active branch: ONE block at h=102 with coinbase + B (spends A:0).
    local cb102 = make_coinbase_tx(102, 5000000000, SPK)
    local B = types.transaction(1,
      {types.txin(types.outpoint(A_txid, 0), "", 0xFFFFFFFF)},
      {types.txout(4999990000, SPK)}, 0)
    local bh102 = connect(cs, db, 102, {cb102, B}, hashes[101])
    assert.is_not_nil(cs:find_spender({ hash = A_txid, index = 0 }),
      "precondition: A:0 indexed on the active branch")
    assert.equal(102, cs.tip_height)

    -- Heavier side branch from h=101: TWO blocks (h=102', h=103') that do NOT
    -- spend A. Two same-difficulty blocks outweigh the single active block, so
    -- accept_side_branch_block triggers a LIVE reorg that orphans B.
    -- nonce=7 makes the h=102' header distinct from the active bh102.
    local cb102b = make_coinbase_tx(102, 5000000000, SPK)
    local bh102b, blk102b = store_side(db, 102, {cb102b}, hashes[101], 7)
    local cb103b = make_coinbase_tx(103, 5000000000, SPK)
    local bh103b, blk103b = store_side(db, 103, {cb103b}, bh102b, 7)

    -- Submit the heavier tip last block -> reorg fires.
    local res, rerr = cs:accept_side_branch_block(blk103b, bh103b)
    assert.equal("connected", res,
      "expected a live reorg onto the heavier branch, got " ..
      tostring(res) .. " / " .. tostring(rerr))
    assert.equal(103, cs.tip_height, "tip should be the heavier branch tip")

    -- The orphaned block B is gone from the active chain; its spend of A:0
    -- must be ERASED by the live-reorg disconnect path.
    assert.is_nil(cs:find_spender({ hash = A_txid, index = 0 }),
      "A:0 must be ERASED after the LIVE reorg orphans B")

    db.close()
  end)

  it("FALSIFICATION: disabled index does NOT answer", function()
    -- Same chain shape, but the index is DISABLED. The pre-impl behaviour:
    -- find_spender returns nil even though B really spends A on-chain.
    local db, cs, hashes, cb_txid = build_base(102, false)
    local A_txid = cb_txid[1]
    local cb102 = make_coinbase_tx(102, 5000000000, SPK)
    local B = types.transaction(1,
      {types.txin(types.outpoint(A_txid, 0), "", 0xFFFFFFFF)},
      {types.txout(4999990000, SPK)}, 0)
    connect(cs, db, 102, {cb102, B}, hashes[101])

    assert.is_nil(cs:find_spender({ hash = A_txid, index = 0 }),
      "disabled index must NOT answer (falsification)")

    db.close()
  end)
end)

describe("gettxspendingprevout RPC", function()
  -- Build an RPC server over a real chain_state + a mempool, index enabled.
  local function build_rpc(enabled)
    local mempool_mod = require("lunarblock.mempool")
    local db, cs, hashes, cb_txid = build_base(102, enabled)
    -- Connect a confirmed spend (B spends A:0) so the index has data.
    local A_txid = cb_txid[1]
    local cb102 = make_coinbase_tx(102, 5000000000, SPK)
    local B = types.transaction(1,
      {types.txin(types.outpoint(A_txid, 0), "", 0xFFFFFFFF)},
      {types.txout(4999990000, SPK)}, 0)
    local B_txid = validation.compute_txid(B)
    local bh102 = connect(cs, db, 102, {cb102, B}, hashes[101])

    local mempool = mempool_mod.new(cs, {})
    local server = rpc.new({
      chain_state = cs,
      mempool = mempool,
      storage = db,
      network = consensus.networks.regtest,
    })
    return server, cs, db, A_txid, B_txid, bh102, mempool
  end

  local cjson = require("cjson")
  -- Normalize a handle_single_request response: success carries
  -- error == cjson.null (userdata) and the array in either _raw_json_result
  -- or result._raw_json; an RPC error carries a {code,message} table.
  local function call(server, params)
    local resp = server:handle_single_request(
      { method = "gettxspendingprevout", params = params, id = 1 })
    local err = resp.error
    if err == cjson.null or err == nil then err = nil end
    local raw = resp._raw_json_result
      or (type(resp.result) == "table" and resp.result._raw_json) or nil
    local arr = raw and cjson.decode(raw) or nil
    return { err = err, arr = arr, raw = raw }
  end

  it("CONFIRMED spend: returns spendingtxid + blockhash via the index", function()
    local server, cs, db, A_txid, B_txid, bh102 = build_rpc(true)
    local A_hex = types.hash256_hex(A_txid)
    local resp = call(server, {
      { { txid = A_hex, vout = 0 } },
      { mempool_only = false },
    })
    assert.is_nil(resp.err, "unexpected RPC error: " ..
      (resp.err and resp.err.message or ""))
    assert.equal(1, #resp.arr)
    assert.equal(A_hex, resp.arr[1].txid)
    assert.equal(0, resp.arr[1].vout)
    assert.equal(types.hash256_hex(B_txid), resp.arr[1].spendingtxid)
    assert.equal(types.hash256_hex(bh102), resp.arr[1].blockhash)
    db.close()
  end)

  it("UNSPENT outpoint via index: bare {txid,vout}", function()
    local server, cs, db, A_txid = build_rpc(true)
    -- A:1 does not exist / is unspent -> bare entry, no spendingtxid/blockhash.
    local A_hex = types.hash256_hex(A_txid)
    local resp = call(server, {
      { { txid = A_hex, vout = 1 } },
      { mempool_only = false },
    })
    assert.is_nil(resp.err)
    assert.equal(A_hex, resp.arr[1].txid)
    assert.equal(1, resp.arr[1].vout)
    assert.is_nil(resp.arr[1].spendingtxid)
    assert.is_nil(resp.arr[1].blockhash)
    db.close()
  end)

  it("ERROR CODES: empty outputs -> -8", function()
    local server = build_rpc(true)
    local resp = call(server, { {} })
    assert.is_not_nil(resp.err)
    assert.equal(-8, resp.err.code)
    assert.equal("Invalid parameter, outputs are missing", resp.err.message)
  end)

  it("ERROR CODES: negative vout -> -8", function()
    local server, cs, db, A_txid = build_rpc(true)
    local resp = call(server, { { { txid = types.hash256_hex(A_txid), vout = -1 } } })
    assert.is_not_nil(resp.err)
    assert.equal(-8, resp.err.code)
    assert.equal("Invalid parameter, vout cannot be negative", resp.err.message)
    db.close()
  end)

  it("ERROR CODES: strict unknown key in options -> -3", function()
    local server, cs, db, A_txid = build_rpc(true)
    local resp = call(server, {
      { { txid = types.hash256_hex(A_txid), vout = 0 } },
      { bogus = true },
    })
    assert.is_not_nil(resp.err)
    assert.equal(-3, resp.err.code)
    db.close()
  end)

  it("ERROR CODES: index unavailable (disabled) -> -1", function()
    -- Index DISABLED, mempool_only=false, outpoint not in mempool -> Core's
    -- RPC_MISC_ERROR (-1) with the exact message.
    local server, cs, db, A_txid = build_rpc(false)
    local resp = call(server, {
      { { txid = types.hash256_hex(A_txid), vout = 0 } },
      { mempool_only = false },
    })
    assert.is_not_nil(resp.err)
    assert.equal(-1, resp.err.code)
    assert.equal(
      "Mempool lacks a relevant spend, and txospenderindex is unavailable.",
      resp.err.message)
    db.close()
  end)
end)
