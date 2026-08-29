-- createrawtransaction must HONOUR the `version` argument, not ignore it.
--
-- THE DEFECT
-- ----------
-- Core's createrawtransaction takes a 5th argument, `version`
-- (bitcoin-core/src/rpc/rawtransaction.cpp:122). It reads it as
-- `self.Arg<uint32_t>("version")`, bounds it to
-- [TX_MIN_STANDARD_VERSION, TX_MAX_STANDARD_VERSION] = [1, 3]
-- (src/policy/policy.h:152-153) and ASSIGNS it to the transaction
-- (src/rpc/rawtransaction_util.cpp:158-161).
--
-- lunarblock passed a hardcoded 2 to types.transaction() and ignored the
-- argument. Asked for version 1, 2 or 3 it returned 02000000 every time, and
-- version 4 -- which Core rejects -- was accepted. A success reply for a
-- request that was not honoured, and not cosmetic: version 3 is TRUC
-- (BIP 431), so a caller who asked for v3 and received v2 holds a transaction
-- with different relay behaviour from the one requested, with nothing in the
-- reply saying so.
--
-- Measured 2026-08-29 by tools/rpc-arg-differential.py against a real regtest
-- Core: seven of the ten implementations behaved identically here.
--
-- THE UNSIGNED WIDTH DECIDES WHICH ERROR YOU GET
-- ---------------------------------------------
-- `version` is read as uint32, unlike the int32 used for `vout`, so
-- 2147483648 SURVIVES the conversion and reaches the DOMAIN error (-8), while
-- -1 and 4294967296 fail the CONVERSION first (-1). Both directions are
-- asserted; collapsing them would look close enough and be wrong twice.
--
-- A LUA-SPECIFIC HAZARD, asserted below: numbers here are doubles, so a
-- non-integral version must be REJECTED rather than floored -- `math.floor`
-- would turn 2.7 into a valid version 2. Core's getInt refuses it outright.
--
-- THE ASSERTIONS DECODE THE VERSION BYTES with the node's own deserializer.
-- Checking only that the call was accepted is exactly the pre-fix behaviour.

local rpc = require("lunarblock.rpc")
local serialize = require("lunarblock.serialize")
local consensus = require("lunarblock.consensus")
local cjson = require("cjson")

describe("createrawtransaction version argument", function()

  local TXID =
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
  local INPUTS = '[{"txid":"' .. TXID .. '","vout":0}]'
  local OUTPUTS = '{"data":"deadbeef"}'

  -- Literal JSON text so large integers reach the handler exactly as they
  -- arrive off the wire.
  local function call_version(version_json)
    local server = rpc.new({network = consensus.networks.mainnet})
    local tail = version_json and (',0,false,' .. version_json) or ',0,false'
    local body = '{"method":"createrawtransaction","params":[' ..
      INPUTS .. ',' .. OUTPUTS .. tail .. '],"id":1}'
    return cjson.decode((server:handle_request(body)))
  end

  local function assert_error(decoded, code, message, what)
    if type(decoded.error) ~= "table" then
      assert.truthy(false, what ..
        ": expected an error object but the call SUCCEEDED with result " ..
        tostring(decoded.result))
    end
    assert.truthy(decoded.error.code == code, what .. ": expected code " ..
      tostring(code) .. ", got " .. tostring(decoded.error.code))
    assert.truthy(decoded.error.message == message, what ..
      ": expected message " .. string.format("%q", message) .. ", got " ..
      string.format("%q", tostring(decoded.error.message)))
  end

  -- The version that actually reached the wire bytes.
  local function tx_version(decoded, what)
    if decoded.error ~= nil and decoded.error ~= cjson.null then
      assert.truthy(false, what .. ": expected success, got error " ..
        tostring(decoded.error and decoded.error.message))
    end
    return serialize.deserialize_transaction(rpc.hex_decode(decoded.result)).version
  end

  it("emits versions 1, 2 and 3 rather than forcing 2", function()
    for _, want in ipairs({1, 2, 3}) do
      local got = tx_version(call_version(tostring(want)), "version " .. want)
      assert.truthy(got == want, "asked for version " .. want ..
        ", transaction carries version " .. tostring(got))
    end
  end)

  it("rejects versions outside [1,3] with Core's domain error", function()
    for _, bad in ipairs({"0", "4", "2147483648"}) do
      assert_error(call_version(bad), -8,
        "Invalid parameter, version out of range(1~3)", "version " .. bad)
    end
  end)

  it("rejects versions outside uint32 as a CONVERSION failure, not a domain one",
    function()
      -- Paired with the test above, this pins the boundary in BOTH directions:
      -- -8 inside uint32, -1 outside it.
      for _, bad in ipairs({"-1", "-2147483649", "4294967296"}) do
        assert_error(call_version(bad), -1, "JSON integer out of range",
          "version " .. bad)
      end
    end)

  it("rejects a NON-INTEGER version instead of flooring it", function()
    -- math.floor(2.7) would be a valid version 2. Core's getInt refuses.
    assert_error(call_version("2.7"), -1, "JSON integer out of range",
      "version 2.7")
  end)

  -- CONTROLS. Without these, a handler that rejected every version would
  -- satisfy every rejection assertion above.
  it("CONTROL an absent version defaults to 2", function()
    local got = tx_version(call_version(nil), "absent version")
    assert.truthy(got == 2, "absent version produced " .. tostring(got))
  end)

  it("CONTROL an explicit null version defaults to 2", function()
    local got = tx_version(call_version("null"), "null version")
    assert.truthy(got == 2, "null version produced " .. tostring(got))
  end)
end)
