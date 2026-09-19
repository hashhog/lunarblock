-- Per-thread script-check entry point.
--
-- Loaded inside a dedicated lua_State owned by one C worker thread
-- (csrc/parallel_verify.c). A lua_State is not thread-safe; this module
-- must never be required on the host state for work, and must never call
-- back into the C job queue (that would deadlock the worker on itself).

local serialize = require("lunarblock.serialize")
local validation = require("lunarblock.validation")

local M = {}

-- connect_block pushes every input of a tx consecutively, so the same
-- interned tx_bytes string arrives N times. Deserialize + BIP143 midstate
-- once; reuse for the rest of the tx. Without this, a 1000-input
-- consolidation is 1000 deserializations of the same blob — the worker
-- analogue of the host O(N^2) prev_outputs bug that made [W77-CB] 12-25s.
local last_bytes, last_tx, last_prevouts, last_cache

--- Run one CScriptCheck-equivalent.
-- @param tx_bytes string serialized transaction (with witness)
-- @param input_index number 0-based
-- @param prev_script string scriptPubKey of the spent output
-- @param amount number satoshis
-- @param flags_bits number packed SCRIPT_VERIFY flags + TAPROOT_ACTIVE
-- @param prevouts_blob string|nil packed prevouts (taproot)
-- @return boolean, string|nil
function M.run(tx_bytes, input_index, prev_script, amount, flags_bits, prevouts_blob)
  local tx, prev_outputs, cache
  if last_bytes == tx_bytes then
    tx = last_tx
    prev_outputs = last_prevouts
    cache = last_cache
  else
    tx = serialize.deserialize_transaction(tx_bytes, true)
    prev_outputs = nil
    if prevouts_blob and #prevouts_blob > 0 then
      prev_outputs = validation.decode_prevouts(prevouts_blob)
    end
    cache = validation.precomputed_tx_data(tx, prev_outputs)
    last_bytes = tx_bytes
    last_tx = tx
    last_prevouts = prev_outputs
    last_cache = cache
  end
  local flags = validation.script_flags_from_bits(flags_bits)
  local taproot_active = validation.script_flags_taproot_active(flags_bits)
  local ok, err = validation.verify_input_script(
    tx, input_index, amount, prev_script, flags,
    { taproot_active = taproot_active, prev_outputs = prev_outputs, cache = cache })
  if ok then
    return true
  end
  return false, err or "script check failed"
end

return M
