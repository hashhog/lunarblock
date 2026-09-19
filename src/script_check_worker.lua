-- Per-thread script-check entry point.
--
-- Loaded inside a dedicated lua_State owned by one C worker thread
-- (csrc/parallel_verify.c). A lua_State is not thread-safe; this module
-- must never be required on the host state for work, and must never call
-- back into the C job queue (that would deadlock the worker on itself).

local serialize = require("lunarblock.serialize")
local validation = require("lunarblock.validation")

local M = {}

--- Run one CScriptCheck-equivalent.
-- @param tx_bytes string serialized transaction (with witness)
-- @param input_index number 0-based
-- @param prev_script string scriptPubKey of the spent output
-- @param amount number satoshis
-- @param flags_bits number packed SCRIPT_VERIFY flags + TAPROOT_ACTIVE
-- @param prevouts_blob string|nil packed prevouts (taproot)
-- @return boolean, string|nil
function M.run(tx_bytes, input_index, prev_script, amount, flags_bits, prevouts_blob)
  -- Force witness deserialization. Segwit marker is in the bytes when
  -- the host serialized with include_witness=true.
  local tx = serialize.deserialize_transaction(tx_bytes, true)
  local flags = validation.script_flags_from_bits(flags_bits)
  local taproot_active = validation.script_flags_taproot_active(flags_bits)
  local prev_outputs = nil
  if prevouts_blob and #prevouts_blob > 0 then
    prev_outputs = validation.decode_prevouts(prevouts_blob)
  end
  local ok, err = validation.verify_input_script(
    tx, input_index, amount, prev_script, flags,
    { taproot_active = taproot_active, prev_outputs = prev_outputs })
  if ok then
    return true
  end
  return false, err or "script check failed"
end

return M
