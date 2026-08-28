-- createrawtransaction -- `vout` must be range-checked against int32
--
-- THE DEFECT (regression pinned by this spec)
-- ------------------------------------------
-- createrawtransaction's input parser only asked "is vout negative?".  It
-- never asked "is vout too big?".  The value was then narrowed to the 32-bit
-- `vout` field of the outpoint, so anything at or above 2^32 silently WRAPPED:
--
--     vout 4294967296 (2^32)  -->  outpoint index 0
--     vout 8589934592 (2^33)  -->  outpoint index 0
--
-- Both were observed on the live mainnet node.  The RPC returned SUCCESS and a
-- perfectly well-formed transaction hex -- one that spends a COMPLETELY
-- DIFFERENT outpoint from the one the caller asked for, and index 0 of a real
-- txid is very likely a real, fundable output.  A caller that signs and
-- broadcasts what it was handed spends the wrong coin, with no error and no
-- log line anywhere.  Silent redirection of a spend is the worst shape a bug
-- can take in this RPC.
--
-- WHAT BITCOIN CORE DOES
-- ----------------------
-- Core reads the field with `find_value(o, "vout").getInt<int>()` -- `int`,
-- i.e. THIRTY-TWO bits (bitcoin-core/src/rpc/rawtransaction_util.cpp,
-- AddInputs:38-45).  univalue's `getInt<Int>`
-- (src/univalue/include/univalue.h) range-checks the parsed integer against
-- the destination type and throws `std::runtime_error("JSON integer out of
-- range")` when it does not fit; the RPC layer surfaces that as
-- RPC_MISC_ERROR (-1).
--
-- The ORDERING IS DELIBERATE AND IS UNIVALUE'S, NOT OURS: the range check
-- lives inside the *conversion*, so it fires BEFORE the handler's own
-- `if (nOutput < 0) throw ... "vout cannot be negative"` sign test ever runs.
-- That is why -1 gets the vout-specific -8 message while 2147483648 -- also
-- "not a valid vout" in any human sense -- gets the generic -1 "JSON integer
-- out of range" instead.  Matching Core here means matching that ORDER, not
-- just the two checks.
--
-- The fix therefore adds, BEFORE the existing sign test:
--     if vout < -2147483648 or vout > 2147483647 then
--       error({code = M.ERROR.MISC_ERROR, message = "JSON integer out of range"})
--     end
--
-- TEETH
-- -----
-- Cases 1-6 are all rejections, and a handler that rejected EVERY input would
-- satisfy every one of them.  The two CONTROL cases exist to make that
-- impossible: they drive the real handler to success and then DECODE the
-- returned hex with the node's own deserializer, asserting the outpoint index
-- that actually landed in the bytes.  In particular the int32-MAX control
-- (2147483647) fails loudly if the new bound is off by one in the tight
-- direction.
--
-- References:
--   bitcoin-core/src/rpc/rawtransaction_util.cpp:38-45   AddInputs
--   bitcoin-core/src/univalue/include/univalue.h         getInt<Int>
--   bitcoin-core/src/rpc/protocol.h                      RPC_MISC_ERROR = -1
--                                                        RPC_INVALID_PARAMETER = -8

local rpc = require("lunarblock.rpc")
local serialize = require("lunarblock.serialize")
local consensus = require("lunarblock.consensus")
local cjson = require("cjson")

describe("createrawtransaction vout int32 range", function()

  -- Well-formed 64-hex txid; the content is irrelevant -- createrawtransaction
  -- builds an UNSIGNED transaction and never looks the outpoint up.
  local TXID =
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

  -- A single OP_RETURN output. Deliberately data-only: it keeps the spec
  -- independent of address encoding/network, so a failure here can only mean
  -- the INPUT parser, never the output parser.
  local OUTPUTS = '{"data":"deadbeef"}'

  -- The request body is written as LITERAL JSON text so the large integers
  -- reach the handler exactly as they arrive off the wire, not via a Lua
  -- literal that some encoder might reshape.
  local function call(inputs_json, extra_json)
    local server = rpc.new({network = consensus.networks.mainnet})
    local body = '{"method":"createrawtransaction","params":[' ..
      inputs_json .. ',' .. OUTPUTS .. (extra_json or "") .. '],"id":1}'
    -- handle_request returns (body, status_override); bind the first return
    -- value explicitly so the status does not become a second argument to
    -- cjson.decode (which rejects a second argument).
    local response = server:handle_request(body)
    return cjson.decode(response)
  end

  local function call_vout(vout_json)
    return call('[{"txid":"' .. TXID .. '","vout":' .. vout_json .. '}]')
  end

  -- Assert a rejection. A SUCCESS is reported as a distinct, loud failure
  -- rather than being silently tolerated.
  local function assert_error(decoded, code, message, what)
    if type(decoded.error) ~= "table" then
      assert.truthy(false, what ..
        ": expected an error object but the call SUCCEEDED with result " ..
        tostring(decoded.result))
    end
    assert.truthy(decoded.error.code == code, what .. ": expected error code " ..
      tostring(code) .. ", got " .. tostring(decoded.error.code))
    assert.truthy(decoded.error.message == message, what ..
      ": expected message " .. string.format("%q", message) .. ", got " ..
      string.format("%q", tostring(decoded.error.message)))
  end

  -- Decode with the node's own transaction deserializer and report the
  -- outpoint index that actually reached the wire bytes.
  local function first_input_vout(hex)
    local tx = serialize.deserialize_transaction(rpc.hex_decode(hex))
    assert.truthy(#tx.inputs == 1,
      "expected exactly one input in the built tx, got " .. tostring(#tx.inputs))
    return tx.inputs[1].prev_out.index
  end

  local function assert_accepted(decoded, expected_vout, what)
    if decoded.error ~= nil and decoded.error ~= cjson.null then
      assert.truthy(false, what .. ": expected success but got error " ..
        tostring(decoded.error.code) .. " " .. tostring(decoded.error.message))
    end
    assert.truthy(type(decoded.result) == "string",
      what .. ": expected a hex string result, got " .. type(decoded.result))
    assert.truthy(#decoded.result > 0, what .. ": hex must be non-empty")
    local got = first_input_vout(decoded.result)
    assert.truthy(got == expected_vout, what ..
      ": outpoint index in the tx bytes -- expected " ..
      tostring(expected_vout) .. ", got " .. tostring(got))
  end

  describe("REGRESSION: out-of-int32 vout is -1 JSON integer out of range",
  function()

    it("rejects vout 4294967296 (2^32) -- pre-fix this WRAPPED to 0", function()
      assert_error(call_vout("4294967296"), rpc.ERROR.MISC_ERROR,
        "JSON integer out of range", "vout 2^32")
    end)

    it("rejects vout 8589934592 (2^33) -- pre-fix this ALSO wrapped to 0",
    function()
      assert_error(call_vout("8589934592"), rpc.ERROR.MISC_ERROR,
        "JSON integer out of range", "vout 2^33")
    end)

    it("rejects vout 2147483648 (int32 MAX + 1) -- the exact boundary",
    function()
      assert_error(call_vout("2147483648"), rpc.ERROR.MISC_ERROR,
        "JSON integer out of range", "vout 2147483648")
    end)

    it("rejects vout -2147483649 with the RANGE message, not the sign one",
    function()
      -- Negative AND out of int32 range. Core's range check lives inside the
      -- conversion, so it wins over "cannot be negative". Ordering assertion.
      assert_error(call_vout("-2147483649"), rpc.ERROR.MISC_ERROR,
        "JSON integer out of range", "vout -2147483649")
    end)
  end)

  describe("neighbouring guards still report Core's own codes", function()

    it("rejects vout -1 with -8 vout cannot be negative", function()
      -- In int32 range, so the range check passes and the sign test speaks.
      assert_error(call_vout("-1"), rpc.ERROR.INVALID_PARAMETER,
        "Invalid parameter, vout cannot be negative", "vout -1")
    end)

    it("rejects sequence 4294967296 with -8 sequence out of range", function()
      local decoded = call('[{"txid":"' .. TXID ..
        '","vout":0,"sequence":4294967296}]')
      assert_error(decoded, rpc.ERROR.INVALID_PARAMETER,
        "Invalid parameter, sequence number is out of range", "sequence 2^32")
    end)

    it("rejects locktime -1 with -8 locktime out of range", function()
      local decoded = call('[{"txid":"' .. TXID .. '","vout":0}]', ',-1')
      assert_error(decoded, rpc.ERROR.INVALID_PARAMETER,
        "Invalid parameter, locktime out of range", "locktime -1")
    end)
  end)

  describe("CONTROLS -- an over-tight bound must FAIL these", function()

    it("accepts vout 2147483647 (int32 MAX) and carries it into the tx bytes",
    function()
      -- Mandatory teeth: proves the new upper bound is `> 2147483647`, not
      -- `>= 2147483647` or some smaller cap.
      assert_accepted(call_vout("2147483647"), 2147483647,
        "vout 2147483647 (int32 MAX)")
    end)

    it("accepts an ordinary vout 7 and carries it into the tx bytes",
    function()
      -- Mandatory teeth: proves the handler still does its normal job, so the
      -- rejection tests above cannot be satisfied by a reject-everything stub.
      assert_accepted(call_vout("7"), 7, "vout 7 (ordinary)")
    end)
  end)
end)
