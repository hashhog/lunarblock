-- decoderawtransaction / sendrawtransaction / testmempoolaccept must refuse
-- hex that Core's DecodeHexTx refuses (-22 "TX decode failed").
--
-- Core core_io.cpp DecodeTx only accepts a decode that consumes the WHOLE
-- input, and decoderawtransaction's `iswitness` selects which format is
-- tried (true: extended only, false: legacy only, absent: both).
-- sendrawtransaction / testmempoolaccept use DecodeHexTx's defaults
-- (extended only).
--
-- lunarblock ignored leftover bytes and ignored `iswitness`: a valid tx plus
-- one trailing 0x00 was decoded, accepted and relayed; a segwit tx with
-- iswitness=false decoded as if the flag had not been given.
-- Found by tools/core-regtest (rows operator/decoderawtransaction/
-- (segwit-iswitness-false|trailing), operator/(sendrawtransaction|
-- testmempoolaccept)/trailing).

local rpc = require("lunarblock.rpc")
local consensus = require("lunarblock.consensus")
local cjson = require("cjson")

describe("raw transaction hex is decoded strictly", function()
  local PREVOUT = string.rep("11", 32) .. "00000000"
  local OUT = "00e1f50500000000" .. "0151"
  local LEGACY = "01000000" .. "01" .. PREVOUT .. "00" .. "ffffffff" ..
                 "01" .. OUT .. "00000000"
  local SEGWIT = "02000000" .. "0001" .. "01" .. PREVOUT .. "00" .. "ffffffff" ..
                 "01" .. OUT .. "0101aa" .. "00000000"

  local function call(method, params)
    local server = rpc.new({network = consensus.networks.regtest})
    -- decode happens before any mempool use; a stub is enough to get past
    -- testmempoolaccept's "mempool available" guard.
    server.mempool = {}
    local body = cjson.encode({method = method, params = params, id = 1})
    return cjson.decode((server:handle_request(body)))
  end

  local function assert_decode_failed(res, what)
    assert.truthy(type(res.error) == "table",
      what .. ": expected -22 but the call SUCCEEDED: " .. tostring(res.result))
    assert.are.equal(-22, res.error.code, what)
    assert.truthy(res.error.message:find("TX decode failed", 1, true), what)
  end

  local function ok(res)
    return res.error == nil or res.error == cjson.null
  end

  it("decoderawtransaction accepts both valid forms", function()
    assert.truthy(ok(call("decoderawtransaction", {LEGACY})))
    assert.truthy(ok(call("decoderawtransaction", {SEGWIT})))
    assert.truthy(ok(call("decoderawtransaction", {SEGWIT, true})))
    assert.truthy(ok(call("decoderawtransaction", {LEGACY, false})))
  end)

  it("decoderawtransaction rejects trailing bytes", function()
    assert_decode_failed(call("decoderawtransaction", {LEGACY .. "00"}), "legacy+00")
    assert_decode_failed(call("decoderawtransaction", {SEGWIT .. "00"}), "segwit+00")
  end)

  it("decoderawtransaction honours iswitness=false on a segwit tx", function()
    assert_decode_failed(call("decoderawtransaction", {SEGWIT, false}),
      "segwit iswitness=false")
  end)

  it("decoderawtransaction accepts a legacy tx with iswitness=true", function()
    -- a legacy tx has no marker: extended-only decoding still parses it
    assert.truthy(ok(call("decoderawtransaction", {LEGACY, true})))
  end)

  it("sendrawtransaction rejects trailing bytes", function()
    assert_decode_failed(call("sendrawtransaction", {LEGACY .. "00"}), "legacy+00")
    assert_decode_failed(call("sendrawtransaction", {SEGWIT .. "00"}), "segwit+00")
  end)

  it("testmempoolaccept rejects trailing bytes", function()
    assert_decode_failed(call("testmempoolaccept", {{LEGACY .. "00"}}), "legacy+00")
    assert_decode_failed(call("testmempoolaccept", {{SEGWIT .. "00"}}), "segwit+00")
  end)
end)
