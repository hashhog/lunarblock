-- spec/getorphantxs_spec.lua
--
-- Proven-teeth tests for the getorphantxs JSON-RPC method (Core v28 parity).
-- Reference: bitcoin-core/src/rpc/mempool.cpp::getorphantxs +
--            bitcoin-core/src/node/txorphanage.cpp::GetOrphanTransactions /
--            OrphanToJSON.
--
-- These FAIL if getorphantxs regresses (method-not-found, wrong shape, wrong
-- verbosity handling, or the wrong error code on an out-of-range verbosity).
--
-- Shape under test (DEFINITIVE Core shape, rpc/mempool.cpp::getorphantxs):
--   verbosity 0 (default): array of TXID hex strings (non-witness txid).
--   verbosity 1: array of {txid, wtxid, bytes, vsize, weight, from} (no expiration).
--   verbosity 2: verbosity-1 objects PLUS `hex`.
--   invalid verbosity (e.g. 3) -> RPC_INVALID_PARAMETER (-8).
--   bool verbosity arg -> rejected (allow_bool=false), NOT mapped to 0/1.

local rpc        = require("lunarblock.rpc")
local types      = require("lunarblock.types")
local consensus  = require("lunarblock.consensus")
local mempool    = require("lunarblock.mempool")
local validation = require("lunarblock.validation")
local serialize  = require("lunarblock.serialize")
local cjson      = require("cjson")

describe("getorphantxs", function()

  -- Standard P2PKH scriptPubKey.
  local P2PKH = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"

  local function random_txid()
    local b = ""
    for _ = 1, 32 do b = b .. string.char(math.random(0, 255)) end
    return types.hash256(b)
  end

  local function make_orphan()
    local parent = random_txid()
    local tx = types.transaction(
      1,
      { types.txin(types.outpoint(parent, 0), "", 0xFFFFFFFE) },
      { types.txout(50000, P2PKH) },
      0)
    local wtxid = validation.compute_wtxid(tx)
    return tx, types.hash256_hex(wtxid)
  end

  -- Build an RPC server whose orphan pool already holds `peer_map` orphans,
  -- where peer_map is a list of peer-id strings (one orphan per entry).
  -- Returns server, pool, and the ordered list of {wtxid, peer_id, tx}.
  local function server_with_orphans(peer_ids)
    local pool = mempool.new_orphan_pool()
    local inserted = {}
    for _, pid in ipairs(peer_ids) do
      local tx, w = make_orphan()
      assert.is_true(pool:add(tx, w, pid, {}))
      inserted[#inserted + 1] = { wtxid = w, peer_id = pid, tx = tx }
    end
    local server = rpc.new({
      chain_state = {
        tip_height = 700000,
        tip_hash = types.hash256(string.rep("\xab", 32)),
      },
      network = consensus.networks.mainnet,
      orphan_pool = pool,
    })
    return server, pool, inserted
  end

  local function call(server, params)
    return server.methods["getorphantxs"](server, params or {})
  end

  it("is registered (not method-not-found) and returns [] for an empty pool", function()
    local server = rpc.new({
      chain_state = { tip_height = 700000, tip_hash = types.hash256(string.rep("\xab", 32)) },
      network = consensus.networks.mainnet,
      orphan_pool = mempool.new_orphan_pool(),
    })
    assert.is_function(server.methods["getorphantxs"])
    -- Full JSON round-trip proves registration + dispatch + serialization.
    local resp = server:handle_request(
      '{"method":"getorphantxs","params":[],"id":1}')
    local decoded = cjson.decode(resp)
    assert.equal(cjson.null, decoded.error)
    -- Empty pool serializes as a JSON array, not an object.
    assert.equal("[]", resp:match('"result":(%[%])'))
  end)

  it("verbosity 0 (default): returns the array of orphan TXIDs", function()
    local server, pool, inserted = server_with_orphans({ "1.2.3.4:8333", "5.6.7.8:8333" })
    local res = call(server, {})
    assert.are_equal(2, #res)
    -- Core pushes orphan.tx->GetHash() (the NON-witness txid), NOT the wtxid.
    local want = {}
    for _, e in ipairs(inserted) do
      local tx = pool.entries[e.wtxid].tx
      want[types.hash256_hex(validation.compute_txid(tx))] = true
    end
    for _, t in ipairs(res) do
      assert.is_true(want[t], "txid " .. tostring(t) .. " is one we inserted")
      assert.are_equal(64, #t, "txid is 32-byte hex")
    end
    -- Explicit verbosity=0 matches the default.
    assert.are_same(res, call(server, { 0 }))
  end)

  it("verbosity 1: returns objects with the Core OrphanToJSON field set", function()
    local server, pool, inserted = server_with_orphans({ "9.9.9.9:8333" })
    local res = call(server, { 1 })
    assert.are_equal(1, #res)
    local o = res[1]

    -- EXACTLY the Core OrphanToJSON fields present.
    assert.is_string(o.txid)
    assert.is_string(o.wtxid)
    assert.is_number(o.bytes)
    assert.is_number(o.vsize)
    assert.is_number(o.weight)
    assert.is_table(o.from)

    -- Core has NO `expiration` field — it must not be emitted.
    assert.is_nil(o.expiration)

    -- The object carries EXACTLY {txid, wtxid, bytes, vsize, weight, from} and
    -- nothing else (no expiration, no hex at verbosity 1).
    local allowed = {
      txid = true, wtxid = true, bytes = true,
      vsize = true, weight = true, from = true,
    }
    for k in pairs(o) do
      assert.is_true(allowed[k], "unexpected field at verbosity 1: " .. tostring(k))
    end

    local entry = pool.entries[inserted[1].wtxid]
    local tx = entry.tx

    -- wtxid matches the primary key; txid matches compute_txid.
    assert.are_equal(inserted[1].wtxid, o.wtxid)
    assert.are_equal(types.hash256_hex(validation.compute_txid(tx)), o.txid)

    -- bytes / vsize / weight computed the same way getrawtransaction does.
    local weight = validation.get_tx_weight(tx)
    local bytes  = #serialize.serialize_transaction(tx, true)
    assert.are_equal(weight, o.weight)
    assert.are_equal(bytes, o.bytes)
    assert.are_equal(math.ceil(weight / consensus.WITNESS_SCALE_FACTOR), o.vsize)

    -- from = the single announcing peer id, as a 1-element array.
    assert.are_equal(1, #o.from)
    assert.are_equal("9.9.9.9:8333", o.from[1])

    -- verbosity 1 must NOT carry the verbosity-2 `hex` field.
    assert.is_nil(o.hex)
  end)

  it("verbosity 2: verbosity-1 fields PLUS hex (serialized tx)", function()
    local server, pool, inserted = server_with_orphans({ "7.7.7.7:8333" })
    local res = call(server, { 2 })
    assert.are_equal(1, #res)
    local o = res[1]
    -- Inherits all verbosity-1 fields (no expiration in Core).
    assert.is_string(o.txid)
    assert.is_string(o.wtxid)
    assert.is_number(o.bytes)
    assert.is_number(o.vsize)
    assert.is_number(o.weight)
    assert.is_table(o.from)
    assert.is_nil(o.expiration)
    -- Plus the hex of the full (witness-included) serialization.
    local tx = pool.entries[inserted[1].wtxid].tx
    assert.is_string(o.hex)
    assert.are_equal(rpc.hex_encode(serialize.serialize_transaction(tx, true)), o.hex)
  end)

  it("invalid verbosity (out of 0..2) -> RPC_INVALID_PARAMETER (-8)", function()
    local server = server_with_orphans({ "1.1.1.1:8333" })
    local ok, err = pcall(call, server, { 3 })
    assert.is_false(ok)
    assert.are_equal(rpc.ERROR.INVALID_PARAMETER, err.code)
    assert.truthy(err.message:match("Invalid verbosity value 3"))

    -- Negative is also out of range.
    local ok2, err2 = pcall(call, server, { -1 })
    assert.is_false(ok2)
    assert.are_equal(rpc.ERROR.INVALID_PARAMETER, err2.code)
  end)

  it("bool verbosity arg is rejected (allow_bool=false), not mapped to 0/1", function()
    local server = server_with_orphans({ "1.1.1.1:8333", "2.2.2.2:8333" })
    -- Core ParseVerbosity(..., allow_bool=false): a boolean must error, NOT be
    -- silently treated as 0/1. true must NOT behave like verbosity 1.
    local ok_t, err_t = pcall(call, server, { true })
    assert.is_false(ok_t, "boolean true must be rejected, not accepted as 1")
    assert.is_table(err_t)
    local ok_f, err_f = pcall(call, server, { false })
    assert.is_false(ok_f, "boolean false must be rejected, not accepted as 0")
    assert.is_table(err_f)
  end)

  it("works end-to-end through handle_request at verbosity 1", function()
    local server = server_with_orphans({ "2.2.2.2:8333" })
    local resp = server:handle_request(
      '{"method":"getorphantxs","params":[1],"id":7}')
    local decoded = cjson.decode(resp)
    assert.equal(cjson.null, decoded.error)
    assert.equal(7, decoded.id)
    assert.are_equal(1, #decoded.result)
    assert.is_string(decoded.result[1].wtxid)
    assert.is_table(decoded.result[1].from)
    assert.are_equal("2.2.2.2:8333", decoded.result[1].from[1])
  end)
end)
