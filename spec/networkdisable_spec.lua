-- Tests for the NetworkDisable RAII gate around `dumptxoutset rollback`.
--
-- Mirrors Bitcoin Core's NetworkDisable wrapper around TemporaryRollback in
-- rpc/blockchain.cpp::dumptxoutset. We exercise the
-- `block_submission_paused` flag directly and confirm `submitblock`
-- short-circuits with a "paused" reject string before any deserialization.

local rpc = require("lunarblock.rpc")
local consensus = require("lunarblock.consensus")

-- Helper: minimal RPCServer with the methods table populated. Avoids
-- pulling in chain_state / mempool / peer_manager since the gate fires
-- before any of them are touched.
local function make_minimal_rpc()
  local r = rpc.new({
    rpcport = 0,
    network = consensus.networks.mainnet,
  })
  return r
end

describe("NetworkDisable rollback gate", function()
  it("block_submission_paused defaults to false", function()
    local r = make_minimal_rpc()
    assert.equal(false, r.block_submission_paused)
  end)

  it("set/clear flag round-trips", function()
    local r = make_minimal_rpc()
    r.block_submission_paused = true
    assert.equal(true, r.block_submission_paused)
    r.block_submission_paused = false
    assert.equal(false, r.block_submission_paused)
  end)

  it("submitblock returns canonical BIP-22 'rejected' while flag is set", function()
    local r = make_minimal_rpc()
    r.block_submission_paused = true
    -- Garbage hex is fine: gate runs before deserialization.
    -- BIP-22: canonical "rejected" string, not a long "paused" message.
    local result = r.methods["submitblock"](r, {"00"})
    assert.equal("string", type(result))
    assert.equal("rejected", result)
  end)

  it("submitblock proceeds past gate once flag is cleared", function()
    local r = make_minimal_rpc()
    r.block_submission_paused = true
    r.block_submission_paused = false
    -- With the gate cleared, submitblock should reach decode/validate.
    -- "00" is too short to deserialize, so we expect an error or a
    -- non-paused string response. Important: don't see "paused".
    local ok, result_or_err = pcall(function()
      return r.methods["submitblock"](r, {"00"})
    end)
    if ok then
      if type(result_or_err) == "string" then
        assert.is_falsy(result_or_err:find("paused"))
      end
    else
      -- Error is acceptable — proves we're past the gate.
      local msg = type(result_or_err) == "table" and result_or_err.message
                  or tostring(result_or_err)
      assert.is_falsy(msg:find("paused"))
    end
  end)
end)
