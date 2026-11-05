-- testmempoolaccept must emit reject-details whenever it emits reject-reason.
--
-- Core rpc/mempool.cpp:403 sets reject-details = state.ToString(); a state
-- with no debug message prints as the bare reason token, so Core answers
-- txn-already-in-mempool / txn-already-known with
--   {"reject-reason":"txn-already-in-mempool","reject-details":"txn-already-in-mempool"}
-- lunarblock omitted the field for both.
-- Found by tools/core-regtest rows operator/testmempoolaccept/(in-mempool|confirmed):[0].reject-details.

local rpc = require("lunarblock.rpc")
local consensus = require("lunarblock.consensus")
local cjson = require("cjson")

describe("testmempoolaccept reject-details", function()
  local PREVOUT = string.rep("11", 32) .. "00000000"
  local OUT = "00e1f50500000000" .. "0151"
  local LEGACY = "01000000" .. "01" .. PREVOUT .. "00" .. "ffffffff" ..
                 "01" .. OUT .. "00000000"

  local function call(mempool)
    local server = rpc.new({network = consensus.networks.regtest})
    server.mempool = mempool
    local body = cjson.encode({method = "testmempoolaccept", params = {{LEGACY}}, id = 1})
    local res = cjson.decode((server:handle_request(body)))
    assert.is_true(res.error == nil or res.error == cjson.null, "RPC returned an error")
    return res.result[1]
  end

  it("repeats the token for a tx already in the mempool", function()
    local txid_hex
    -- Learn the txid by decoding once through the same path.
    local probe = call({entries = {}, accept_to_memory_pool = function()
      return {accepted = false, reject_reason = "x"} end})
    txid_hex = probe.txid
    local r = call({entries = {[txid_hex] = {}}})
    assert.equal("txn-already-in-mempool", r["reject-reason"])
    assert.equal("txn-already-in-mempool", r["reject-details"])
  end)

  it("repeats the token for an already-confirmed tx (txn-already-known)", function()
    local r = call({entries = {}, accept_to_memory_pool = function()
      return {accepted = false, reject_reason = "txn-already-known"} end})
    assert.equal("txn-already-known", r["reject-reason"])
    assert.equal("txn-already-known", r["reject-details"])
  end)

  it("keeps a supplied detail string", function()
    local r = call({entries = {}, accept_to_memory_pool = function()
      return {accepted = false, reject_reason = "a", reject_details = "a, because"} end})
    assert.equal("a, because", r["reject-details"])
  end)

  it("omits reject-details for missing-inputs, like Core", function()
    local r = call({entries = {}, accept_to_memory_pool = function()
      return {accepted = false, reject_reason = "bad-txns-inputs-missingorspent"} end})
    assert.equal("missing-inputs", r["reject-reason"])
    assert.is_nil(r["reject-details"])
  end)
end)
