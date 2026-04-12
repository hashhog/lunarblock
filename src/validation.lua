local bit = require("bit")
local ffi = require("ffi")
local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local crypto = require("lunarblock.crypto")
local script = require("lunarblock.script")
local consensus = require("lunarblock.consensus")
local M = {}

--------------------------------------------------------------------------------
-- Parallel Verification (C Worker Pool)
--------------------------------------------------------------------------------

-- FFI declarations for parallel verification
ffi.cdef[[
  /* Input verification job */
  typedef struct {
    const uint8_t *tx_data;
    size_t tx_len;
    uint32_t input_index;
    const uint8_t *prev_script;
    size_t prev_script_len;
    int64_t amount;
    uint32_t flags;
    int result;
  } verify_job;

  /* Signature verification job (pre-computed sighash) */
  typedef struct {
    const uint8_t *pubkey;
    size_t pubkey_len;
    const uint8_t *sig_der;
    size_t sig_len;
    const uint8_t *msghash32;
    int result;
  } sig_verify_job;

  int pv_init(int num_threads);
  int pv_verify_batch(verify_job *jobs, int count);
  int pv_verify_signatures(sig_verify_job *jobs, int count);
  int pv_get_num_workers(void);
  void pv_shutdown(void);
]]

-- Parallel verification library (lazy loaded)
local pv_lib = nil
local pv_available = nil

-- Try to load the parallel verification library
local function init_parallel_verify()
  if pv_available ~= nil then
    return pv_available
  end

  local paths = {
    "./lib/parallel_verify.so",
    "lunarblock/parallel_verify",
    "./lunarblock/parallel_verify.so",
    "./parallel_verify.so",
    "parallel_verify",
  }

  for _, path in ipairs(paths) do
    local ok, lib = pcall(ffi.load, path)
    if ok then
      pv_lib = lib
      -- Initialize worker pool
      local num_workers = lib.pv_init(0)  -- Auto-detect thread count
      if num_workers > 0 then
        pv_available = true
        return true
      end
    end
  end

  pv_available = false
  return false
end

-- Threshold for using parallel verification
local PARALLEL_THRESHOLD = 16

--- Check if parallel verification is available.
-- @return boolean: true if available
function M.parallel_verify_available()
  return init_parallel_verify()
end

--- Get number of parallel verification workers.
-- @return number: number of worker threads, or 0 if not available
function M.parallel_verify_workers()
  if not init_parallel_verify() then
    return 0
  end
  return pv_lib.pv_get_num_workers()
end

--- Shutdown parallel verification workers.
-- Call this before exit to clean up resources.
function M.parallel_verify_shutdown()
  if pv_lib and pv_available then
    pv_lib.pv_shutdown()
    pv_available = false
  end
end

--- Verify a batch of signatures in parallel.
-- Each entry should have: pubkey (string), sig_der (string), sighash (string, 32 bytes)
-- @param sigs table: array of {pubkey, sig_der, sighash}
-- @return boolean, string|nil: success, error message if failed
function M.verify_signatures_parallel(sigs)
  if #sigs == 0 then
    return true
  end

  -- Fall back to single-threaded if parallel not available or batch too small
  if not init_parallel_verify() or #sigs < PARALLEL_THRESHOLD then
    for i, sig in ipairs(sigs) do
      local ok = crypto.ecdsa_verify(sig.pubkey, sig.sig_der, sig.sighash)
      if not ok then
        return false, "signature verification failed at index " .. i
      end
    end
    return true
  end

  -- Prepare FFI job array
  local jobs = ffi.new("sig_verify_job[?]", #sigs)

  -- We need to keep references to prevent GC
  local pubkey_ptrs = {}
  local sig_ptrs = {}
  local hash_ptrs = {}

  for i, sig in ipairs(sigs) do
    local j = i - 1  -- 0-indexed

    -- Allocate C buffers and copy data
    local pubkey_buf = ffi.new("uint8_t[?]", #sig.pubkey)
    ffi.copy(pubkey_buf, sig.pubkey, #sig.pubkey)
    pubkey_ptrs[i] = pubkey_buf

    local sig_buf = ffi.new("uint8_t[?]", #sig.sig_der)
    ffi.copy(sig_buf, sig.sig_der, #sig.sig_der)
    sig_ptrs[i] = sig_buf

    local hash_buf = ffi.new("uint8_t[32]")
    ffi.copy(hash_buf, sig.sighash, 32)
    hash_ptrs[i] = hash_buf

    jobs[j].pubkey = pubkey_buf
    jobs[j].pubkey_len = #sig.pubkey
    jobs[j].sig_der = sig_buf
    jobs[j].sig_len = #sig.sig_der
    jobs[j].msghash32 = hash_buf
    jobs[j].result = 0
  end

  -- Run parallel verification
  local failures = pv_lib.pv_verify_signatures(jobs, #sigs)

  if failures < 0 then
    return false, "parallel verification error"
  elseif failures > 0 then
    -- Find first failure for error message
    for i = 0, #sigs - 1 do
      if jobs[i].result ~= 1 then
        return false, "signature verification failed at index " .. (i + 1)
      end
    end
    return false, "signature verification failed"
  end

  return true
end

--------------------------------------------------------------------------------
-- Transaction Validation (Context-Free)
--------------------------------------------------------------------------------

--- Check basic transaction structure (context-free validation).
-- @param tx transaction: The transaction to check
-- @return boolean, boolean: success flag, is_coinbase flag
function M.check_transaction(tx)
  -- Must have at least one input and one output
  assert(#tx.inputs > 0, "transaction has no inputs")
  assert(#tx.outputs > 0, "transaction has no outputs")

  -- Check serialized size (use cached data if available from check_block)
  local tx_data = tx._cached_base_data or serialize.serialize_transaction(tx, false)
  assert(#tx_data >= consensus.MIN_TX_SIZE,
         "transaction size " .. #tx_data .. " below minimum " .. consensus.MIN_TX_SIZE)

  -- Check for duplicate inputs (avoid buffer_writer allocation per input)
  local seen_outpoints = {}
  for _, inp in ipairs(tx.inputs) do
    local idx = inp.prev_out.index
    local key = inp.prev_out.hash.bytes .. string.char(
      bit.band(idx, 0xFF),
      bit.band(bit.rshift(idx, 8), 0xFF),
      bit.band(bit.rshift(idx, 16), 0xFF),
      bit.band(bit.rshift(idx, 24), 0xFF)
    )
    if seen_outpoints[key] then
      error("duplicate input")
    end
    seen_outpoints[key] = true
  end

  -- Validate outputs: value >= 0, value <= MAX_MONEY, total <= MAX_MONEY
  local total_out = 0
  for i, out in ipairs(tx.outputs) do
    assert(out.value >= 0, "output " .. i .. " has negative value")
    assert(out.value <= consensus.MAX_MONEY,
           "output " .. i .. " value exceeds MAX_MONEY")
    total_out = total_out + out.value
    assert(total_out <= consensus.MAX_MONEY, "total output value exceeds MAX_MONEY")
  end

  -- Detect coinbase: single input with null hash and index 0xFFFFFFFF
  local is_coinbase = false
  local null_hash = string.rep("\0", 32)
  if #tx.inputs == 1 then
    local inp = tx.inputs[1]
    if inp.prev_out.hash.bytes == null_hash and inp.prev_out.index == 0xFFFFFFFF then
      is_coinbase = true
    end
  end

  if is_coinbase then
    -- Coinbase scriptSig must be between 2 and 100 bytes
    local sig_len = #tx.inputs[1].script_sig
    assert(sig_len >= 2, "coinbase scriptSig too short: " .. sig_len)
    assert(sig_len <= 100, "coinbase scriptSig too long: " .. sig_len)
  else
    -- Non-coinbase: no input can have null hash
    for i, inp in ipairs(tx.inputs) do
      assert(inp.prev_out.hash.bytes ~= null_hash,
             "non-coinbase input " .. i .. " has null prevout hash")
    end
  end

  return true, is_coinbase
end

--------------------------------------------------------------------------------
-- Transaction ID Computation
--------------------------------------------------------------------------------

--- Compute txid (double-SHA256 of non-witness serialization).
-- Uses cached serialization if available (set by check_block).
-- @param tx transaction: The transaction
-- @return hash256: The txid
function M.compute_txid(tx)
  if tx._cached_txid then return tx._cached_txid end
  local data = tx._cached_base_data or serialize.serialize_transaction(tx, false)
  local txid = crypto.hash256_type(data)
  tx._cached_txid = txid
  return txid
end

--- Compute wtxid (double-SHA256 of witness serialization).
-- For non-segwit transactions, wtxid == txid.
-- Uses cached serialization if available (set by check_block).
-- @param tx transaction: The transaction
-- @return hash256: The wtxid
function M.compute_wtxid(tx)
  if tx._cached_wtxid then return tx._cached_wtxid end
  local data = tx._cached_witness_data or serialize.serialize_transaction(tx, true)
  local wtxid = crypto.hash256_type(data)
  tx._cached_wtxid = wtxid
  return wtxid
end

--------------------------------------------------------------------------------
-- Transaction Weight
--------------------------------------------------------------------------------

--- Get transaction weight.
-- Weight = base_size * 3 + total_size
-- where base_size is non-witness serialization length
-- and total_size is witness serialization length.
-- @param tx transaction: The transaction
-- @return number: The weight in weight units
function M.get_tx_weight(tx)
  local base_size = #serialize.serialize_transaction(tx, false)
  local total_size = #serialize.serialize_transaction(tx, true)
  return base_size * 3 + total_size
end

--------------------------------------------------------------------------------
-- Sigops Counting
--------------------------------------------------------------------------------

--- Count signature operations in a script.
-- @param script_bytes string: The script bytes
-- @param accurate boolean: If true, use accurate counting for OP_CHECKMULTISIG
-- @return number: The sigops count
function M.count_script_sigops(script_bytes, accurate)
  -- Gracefully handle unparseable scripts (e.g. coinbase scriptSig with arbitrary data)
  local ok, ops = pcall(script.parse_script, script_bytes)
  if not ok then return 0 end
  local count = 0
  local prev_opcode = nil

  for _, op in ipairs(ops) do
    local opcode = op.opcode

    if opcode == script.OP.OP_CHECKSIG or opcode == script.OP.OP_CHECKSIGVERIFY then
      count = count + 1
    elseif opcode == script.OP.OP_CHECKMULTISIG or opcode == script.OP.OP_CHECKMULTISIGVERIFY then
      if accurate and prev_opcode and prev_opcode >= script.OP.OP_1 and prev_opcode <= script.OP.OP_16 then
        count = count + (prev_opcode - script.OP.OP_1 + 1)
      else
        count = count + consensus.MAX_PUBKEYS_PER_MULTISIG
      end
    end

    prev_opcode = opcode
  end

  return count
end

--- Get legacy sigop count for a transaction.
-- Counts sigops from scriptSig and scriptPubKey without accurate counting.
-- @param tx transaction: The transaction
-- @return number: The legacy sigops count (NOT scaled)
function M.get_legacy_sigop_count(tx)
  local count = 0
  for _, inp in ipairs(tx.inputs) do
    count = count + M.count_script_sigops(inp.script_sig, false)
  end
  for _, out in ipairs(tx.outputs) do
    count = count + M.count_script_sigops(out.script_pubkey, false)
  end
  return count
end

--- Get P2SH sigop count for a transaction.
-- For each input spending a P2SH output, extract the redeem script from
-- scriptSig and count sigops with accurate counting.
-- @param tx transaction: The transaction
-- @param get_prev_output function(inp) -> txout: Function to get previous output for input
-- @return number: The P2SH sigops count (NOT scaled)
function M.get_p2sh_sigop_count(tx, get_prev_output)
  -- Coinbase transactions don't have P2SH sigops
  local null_hash = string.rep("\0", 32)
  if #tx.inputs == 1 and
     tx.inputs[1].prev_out.hash.bytes == null_hash and
     tx.inputs[1].prev_out.index == 0xFFFFFFFF then
    return 0
  end

  local count = 0
  for _, inp in ipairs(tx.inputs) do
    local prev_out = get_prev_output(inp)
    if not prev_out then
      error("missing previous output for input")
    end

    local script_type = script.classify_script(prev_out.script_pubkey)
    if script_type == "p2sh" then
      -- Extract redeem script (last push in scriptSig)
      local redeem_script = M.extract_p2sh_redeem_script(inp.script_sig)
      if redeem_script then
        count = count + M.count_script_sigops(redeem_script, true)
      end
    end
  end
  return count
end

--- Extract the redeem script from a P2SH scriptSig.
-- The redeem script is the last push operation in the scriptSig.
-- @param script_sig string: The scriptSig bytes
-- @return string|nil: The redeem script, or nil if not found
function M.extract_p2sh_redeem_script(script_sig)
  if #script_sig == 0 then
    return nil
  end

  -- Check if scriptSig is push-only
  if not script.is_push_only(script_sig) then
    return nil
  end

  -- Parse and find the last push
  local ops = script.parse_script(script_sig)
  if #ops == 0 then
    return nil
  end

  local last_op = ops[#ops]
  -- For OP_0, data is nil but represents empty bytes
  if last_op.opcode == script.OP.OP_0 then
    return ""
  elseif last_op.opcode >= script.OP.OP_1 and last_op.opcode <= script.OP.OP_16 then
    -- Small number push (1-16) - not a valid redeem script
    return nil
  elseif last_op.data then
    return last_op.data
  end

  return nil
end

--- Count witness sigops for a single input.
-- @param script_sig string: The scriptSig
-- @param script_pubkey string: The scriptPubKey of the output being spent
-- @param witness table|nil: The witness stack
-- @return number: The witness sigops (NOT scaled - witness sigops cost 1)
function M.count_witness_sigops(script_sig, script_pubkey, witness)
  witness = witness or {}

  local witness_version, witness_program

  -- Check if scriptPubKey is a witness program directly
  local script_type, program = script.classify_script(script_pubkey)
  if script_type == "p2wpkh" then
    witness_version = 0
    witness_program = program
  elseif script_type == "p2wsh" then
    witness_version = 0
    witness_program = program
  elseif script_type == "p2tr" then
    witness_version = 1
    witness_program = program
  elseif script_type == "p2sh" then
    -- Check if it's P2SH-wrapped witness (P2SH-P2WPKH or P2SH-P2WSH)
    if script.is_push_only(script_sig) then
      local redeem_script = M.extract_p2sh_redeem_script(script_sig)
      if redeem_script then
        local inner_type, inner_program = script.classify_script(redeem_script)
        if inner_type == "p2wpkh" then
          witness_version = 0
          witness_program = inner_program
        elseif inner_type == "p2wsh" then
          witness_version = 0
          witness_program = inner_program
        end
      end
    end
  end

  if not witness_version then
    return 0
  end

  -- Count sigops based on witness version
  if witness_version == 0 then
    if #witness_program == 20 then
      -- P2WPKH: 1 sigop
      return 1
    elseif #witness_program == 32 and #witness > 0 then
      -- P2WSH: count from witness script (last witness item)
      local witness_script = witness[#witness]
      return M.count_script_sigops(witness_script, true)
    end
  end

  -- Future witness versions or invalid programs return 0
  return 0
end

--- Get total signature operation cost for a transaction.
-- This implements Bitcoin Core's GetTransactionSigOpCost:
-- - Legacy sigops (scriptSig + scriptPubKey) are multiplied by WITNESS_SCALE_FACTOR
-- - P2SH sigops are multiplied by WITNESS_SCALE_FACTOR
-- - Witness sigops cost 1 each (no scaling)
-- @param tx transaction: The transaction
-- @param get_prev_output function(inp) -> txout: Function to get previous output
-- @param flags table: Script verification flags (needs verify_p2sh, verify_witness)
-- @return number: The total sigop cost
function M.get_transaction_sigop_cost(tx, get_prev_output, flags)
  flags = flags or {}

  -- Start with legacy sigops, scaled by WITNESS_SCALE_FACTOR
  local cost = M.get_legacy_sigop_count(tx) * consensus.WITNESS_SCALE_FACTOR

  -- Coinbase check
  local null_hash = string.rep("\0", 32)
  local is_coinbase = #tx.inputs == 1 and
                      tx.inputs[1].prev_out.hash.bytes == null_hash and
                      tx.inputs[1].prev_out.index == 0xFFFFFFFF

  if is_coinbase then
    return cost
  end

  -- Add P2SH sigops if P2SH is enabled
  if flags.verify_p2sh then
    cost = cost + M.get_p2sh_sigop_count(tx, get_prev_output) * consensus.WITNESS_SCALE_FACTOR
  end

  -- Add witness sigops (no scaling) if witness is enabled
  if flags.verify_witness then
    for _, inp in ipairs(tx.inputs) do
      local prev_out = get_prev_output(inp)
      if prev_out then
        cost = cost + M.count_witness_sigops(inp.script_sig, prev_out.script_pubkey, inp.witness)
      end
    end
  end

  return cost
end

--------------------------------------------------------------------------------
-- FindAndDelete for Legacy Sighash
--------------------------------------------------------------------------------

--- Serialize data as a push operation (length prefix + data).
-- For data ≤ 75 bytes: single length byte
-- For data ≤ 255 bytes: OP_PUSHDATA1 + 1-byte length
-- For data ≤ 65535 bytes: OP_PUSHDATA2 + 2-byte length
-- @param data string: The data to serialize as a push
-- @return string: Push-encoded data
local function serialize_push_data(data)
  local len = #data
  if len <= 75 then
    return string.char(len) .. data
  elseif len <= 255 then
    return string.char(0x4c, len) .. data  -- OP_PUSHDATA1
  elseif len <= 65535 then
    local low = len % 256
    local high = math.floor(len / 256)
    return string.char(0x4d, low, high) .. data  -- OP_PUSHDATA2
  else
    -- OP_PUSHDATA4 for very large data
    local b1 = len % 256
    local b2 = math.floor(len / 256) % 256
    local b3 = math.floor(len / 65536) % 256
    local b4 = math.floor(len / 16777216) % 256
    return string.char(0x4e, b1, b2, b3, b4) .. data  -- OP_PUSHDATA4
  end
end

--- Escape special pattern characters in a string for Lua pattern matching.
-- @param str string: The string to escape
-- @return string: Escaped string safe for use in patterns
local function escape_pattern(str)
  return (str:gsub("[%(%)%.%%%+%-%*%?%[%]%^%$]", "%%%1"))
end

--- Find and delete all occurrences of a push-encoded signature from a script.
-- This is used in legacy sighash computation to remove the signature being
-- verified from the scriptCode before hashing.
-- @param script_bytes string: The script bytes
-- @param sig_bytes string: The signature bytes (without push opcode)
-- @return string: Script with signature removed
function M.find_and_delete(script_bytes, sig_bytes)
  if not sig_bytes or #sig_bytes == 0 then
    return script_bytes
  end

  -- The signature is push-encoded in the script: [push_opcode] [data]
  local push_encoded = serialize_push_data(sig_bytes)

  -- Remove all occurrences of the push-encoded signature
  local pattern = escape_pattern(push_encoded)
  local result = script_bytes:gsub(pattern, "")

  return result
end

--- Remove all OP_CODESEPARATOR (0xab) opcodes from a script.
-- Used in legacy sighash computation.
-- Must properly parse the script to avoid stripping 0xab bytes that appear
-- inside data pushes (e.g., within public key data).
-- @param script_bytes string: The script bytes
-- @return string: Script with OP_CODESEPARATOR opcodes removed
function M.remove_codeseparators(script_bytes)
  local parts = {}
  local pos = 1
  local len = #script_bytes

  while pos <= len do
    local opcode = script_bytes:byte(pos)

    if opcode == 0xab then
      -- OP_CODESEPARATOR: skip it (don't add to parts)
      pos = pos + 1
    elseif opcode >= 0x01 and opcode <= 0x4b then
      -- Direct push: opcode is the number of bytes to push
      local data_len = opcode
      local end_pos = pos + data_len
      if end_pos > len then end_pos = len end
      parts[#parts + 1] = script_bytes:sub(pos, end_pos)
      pos = end_pos + 1
    elseif opcode == 0x4c then
      -- OP_PUSHDATA1: 1-byte length follows
      if pos + 1 > len then
        parts[#parts + 1] = script_bytes:sub(pos, pos)
        pos = pos + 1
      else
        local data_len = script_bytes:byte(pos + 1)
        local end_pos = pos + 1 + data_len
        if end_pos > len then end_pos = len end
        parts[#parts + 1] = script_bytes:sub(pos, end_pos)
        pos = end_pos + 1
      end
    elseif opcode == 0x4d then
      -- OP_PUSHDATA2: 2-byte length follows (little-endian)
      if pos + 2 > len then
        parts[#parts + 1] = script_bytes:sub(pos, len)
        pos = len + 1
      else
        local data_len = script_bytes:byte(pos + 1) + script_bytes:byte(pos + 2) * 256
        local end_pos = pos + 2 + data_len
        if end_pos > len then end_pos = len end
        parts[#parts + 1] = script_bytes:sub(pos, end_pos)
        pos = end_pos + 1
      end
    elseif opcode == 0x4e then
      -- OP_PUSHDATA4: 4-byte length follows (little-endian)
      if pos + 4 > len then
        parts[#parts + 1] = script_bytes:sub(pos, len)
        pos = len + 1
      else
        local b1, b2, b3, b4 = script_bytes:byte(pos + 1, pos + 4)
        local data_len = b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
        local end_pos = pos + 4 + data_len
        if end_pos > len then end_pos = len end
        parts[#parts + 1] = script_bytes:sub(pos, end_pos)
        pos = end_pos + 1
      end
    else
      -- Regular opcode (not a push, not OP_CODESEPARATOR)
      parts[#parts + 1] = script_bytes:sub(pos, pos)
      pos = pos + 1
    end
  end

  return table.concat(parts)
end

--------------------------------------------------------------------------------
-- Signature Hash (Legacy)
--------------------------------------------------------------------------------

--- Compute signature hash for legacy (pre-segwit) transactions.
-- Implements FindAndDelete and OP_CODESEPARATOR removal per Bitcoin Core.
-- @param tx transaction: The transaction
-- @param input_index number: Index of input being signed (0-based)
-- @param script_code string: The script code to sign (should start after last OP_CODESEPARATOR)
-- @param hash_type number: The hash type
-- @param sig_bytes string|nil: Optional signature bytes to remove via FindAndDelete
-- @return string: 32-byte hash
function M.signature_hash_legacy(tx, input_index, script_code, hash_type, sig_bytes)
  local ht = bit.band(hash_type, 0x1F)
  local anyone_can_pay = bit.band(hash_type, 0x80) ~= 0

  -- Special case: SIGHASH_SINGLE with input_index > #outputs
  if ht == consensus.SIGHASH.SINGLE and input_index >= #tx.outputs then
    return string.rep("\0", 31) .. "\1"
  end

  -- Apply FindAndDelete: remove the signature from scriptCode (legacy only)
  local processed_script = script_code
  if sig_bytes and #sig_bytes > 0 then
    processed_script = M.find_and_delete(processed_script, sig_bytes)
  end

  -- Remove OP_CODESEPARATOR bytes from the scriptCode
  processed_script = M.remove_codeseparators(processed_script)

  -- Create modified transaction copy
  local modified_inputs = {}
  local modified_outputs = {}

  -- Handle inputs
  if anyone_can_pay then
    -- Only include the signing input
    modified_inputs[1] = {
      prev_out = tx.inputs[input_index + 1].prev_out,
      script_sig = processed_script,
      sequence = tx.inputs[input_index + 1].sequence
    }
  else
    for i, inp in ipairs(tx.inputs) do
      local script_to_use = ""
      local sequence = inp.sequence

      if i == input_index + 1 then
        script_to_use = processed_script
      else
        -- For SIGHASH_NONE or SIGHASH_SINGLE, zero out sequences for other inputs
        if ht == consensus.SIGHASH.NONE or ht == consensus.SIGHASH.SINGLE then
          sequence = 0
        end
      end

      modified_inputs[i] = {
        prev_out = inp.prev_out,
        script_sig = script_to_use,
        sequence = sequence
      }
    end
  end

  -- Handle outputs
  if ht == consensus.SIGHASH.NONE then
    -- No outputs
  elseif ht == consensus.SIGHASH.SINGLE then
    -- Outputs up to and including input_index
    -- Earlier outputs get value -1 and empty script
    for i = 1, input_index + 1 do
      if i < input_index + 1 then
        modified_outputs[i] = {
          value = -1,
          script_pubkey = ""
        }
      else
        modified_outputs[i] = tx.outputs[i]
      end
    end
  else
    -- SIGHASH_ALL: include all outputs
    for i, out in ipairs(tx.outputs) do
      modified_outputs[i] = out
    end
  end

  -- Build the serialization
  local w = serialize.buffer_writer()
  w.write_i32le(tx.version)

  -- Inputs
  w.write_varint(#modified_inputs)
  for _, inp in ipairs(modified_inputs) do
    w.write_hash256(inp.prev_out.hash)
    w.write_u32le(inp.prev_out.index)
    w.write_varstr(inp.script_sig)
    w.write_u32le(inp.sequence)
  end

  -- Outputs
  w.write_varint(#modified_outputs)
  for _, out in ipairs(modified_outputs) do
    w.write_i64le(out.value)
    w.write_varstr(out.script_pubkey)
  end

  w.write_u32le(tx.locktime)
  w.write_u32le(hash_type)

  return crypto.hash256(w.result())
end

--------------------------------------------------------------------------------
-- Signature Hash (SegWit v0 - BIP143)
--------------------------------------------------------------------------------

--- Compute signature hash for SegWit v0 (BIP143).
-- @param tx transaction: The transaction
-- @param input_index number: Index of input being signed (0-based)
-- @param script_code string: The script code to sign
-- @param value number: Value of the input being spent (satoshis)
-- @param hash_type number: The hash type
-- @return string: 32-byte hash
function M.signature_hash_segwit_v0(tx, input_index, script_code, value, hash_type)
  local ht = bit.band(hash_type, 0x1F)
  local anyone_can_pay = bit.band(hash_type, 0x80) ~= 0

  -- Compute hashPrevouts
  local hash_prevouts
  if anyone_can_pay then
    hash_prevouts = string.rep("\0", 32)
  else
    local w = serialize.buffer_writer()
    for _, inp in ipairs(tx.inputs) do
      w.write_hash256(inp.prev_out.hash)
      w.write_u32le(inp.prev_out.index)
    end
    hash_prevouts = crypto.hash256(w.result())
  end

  -- Compute hashSequence
  local hash_sequence
  if anyone_can_pay or ht == consensus.SIGHASH.SINGLE or ht == consensus.SIGHASH.NONE then
    hash_sequence = string.rep("\0", 32)
  else
    local w = serialize.buffer_writer()
    for _, inp in ipairs(tx.inputs) do
      w.write_u32le(inp.sequence)
    end
    hash_sequence = crypto.hash256(w.result())
  end

  -- Compute hashOutputs
  local hash_outputs
  if ht == consensus.SIGHASH.SINGLE then
    if input_index < #tx.outputs then
      local w = serialize.buffer_writer()
      local out = tx.outputs[input_index + 1]
      w.write_i64le(out.value)
      w.write_varstr(out.script_pubkey)
      hash_outputs = crypto.hash256(w.result())
    else
      hash_outputs = string.rep("\0", 32)
    end
  elseif ht == consensus.SIGHASH.NONE then
    hash_outputs = string.rep("\0", 32)
  else
    -- SIGHASH_ALL
    local w = serialize.buffer_writer()
    for _, out in ipairs(tx.outputs) do
      w.write_i64le(out.value)
      w.write_varstr(out.script_pubkey)
    end
    hash_outputs = crypto.hash256(w.result())
  end

  -- Build the preimage
  local w = serialize.buffer_writer()
  w.write_i32le(tx.version)
  w.write_bytes(hash_prevouts)
  w.write_bytes(hash_sequence)

  -- Outpoint being spent
  local inp = tx.inputs[input_index + 1]
  w.write_hash256(inp.prev_out.hash)
  w.write_u32le(inp.prev_out.index)

  -- Script code (with length prefix)
  w.write_varstr(script_code)

  -- Value being spent
  w.write_i64le(value)

  -- Sequence
  w.write_u32le(inp.sequence)

  w.write_bytes(hash_outputs)
  w.write_u32le(tx.locktime)
  w.write_u32le(hash_type)

  return crypto.hash256(w.result())
end

--------------------------------------------------------------------------------
-- BIP341 Taproot Signature Hash
--------------------------------------------------------------------------------

--- Compute taproot sighash (BIP341).
-- @param tx transaction: The transaction being verified
-- @param input_index number: 0-based index of the input being signed
-- @param hash_type number: Sighash type (0x00 = SIGHASH_DEFAULT, or standard types)
-- @param prev_outputs table: Array of {value=number, script_pubkey=string} for ALL inputs
-- @param ext_flag number: Extension flag (0 for key-path, 1 for script-path)
-- @param annex string|nil: Annex data (if present)
-- @param tapleaf_hash string|nil: 32-byte leaf hash (for script-path spending)
-- @param codesep_pos number|nil: Code separator position (default 0xFFFFFFFF)
-- @return string: 32-byte sighash
function M.signature_hash_taproot(tx, input_index, hash_type, prev_outputs,
                                   ext_flag, annex, tapleaf_hash, codesep_pos)
  ext_flag = ext_flag or 0
  codesep_pos = codesep_pos or 0xFFFFFFFF

  -- Determine effective sighash type
  local ht = hash_type
  if ht == 0x00 then
    ht = 0x01  -- SIGHASH_DEFAULT acts as SIGHASH_ALL
  end
  local output_type = bit.band(ht, 0x03)
  local anyone_can_pay = bit.band(ht, 0x80) ~= 0

  -- Build the epoch + sighash preimage using tagged hash
  local w = serialize.buffer_writer()

  -- Epoch byte (0x00)
  w.write_u8(0x00)

  -- Hash type
  w.write_u8(hash_type)

  -- Transaction data
  w.write_i32le(tx.version)
  w.write_u32le(tx.locktime)

  -- If NOT ANYONECANPAY, commit to all inputs
  if not anyone_can_pay then
    -- sha_prevouts: SHA256 of all outpoints
    local pw = serialize.buffer_writer()
    for _, inp in ipairs(tx.inputs) do
      pw.write_hash256(inp.prev_out.hash)
      pw.write_u32le(inp.prev_out.index)
    end
    w.write_bytes(crypto.sha256(pw.result()))

    -- sha_amounts: SHA256 of all prev output amounts
    local aw = serialize.buffer_writer()
    for _, po in ipairs(prev_outputs) do
      aw.write_i64le(po.value)
    end
    w.write_bytes(crypto.sha256(aw.result()))

    -- sha_scriptpubkeys: SHA256 of all prev output scriptPubKeys (with compact size prefix)
    local sw = serialize.buffer_writer()
    for _, po in ipairs(prev_outputs) do
      sw.write_varstr(po.script_pubkey)
    end
    w.write_bytes(crypto.sha256(sw.result()))

    -- sha_sequences: SHA256 of all input sequences
    local qw = serialize.buffer_writer()
    for _, inp in ipairs(tx.inputs) do
      qw.write_u32le(inp.sequence)
    end
    w.write_bytes(crypto.sha256(qw.result()))
  end

  -- If SIGHASH_ALL (output_type == 1 or 0), commit to all outputs
  if output_type ~= 0x02 and output_type ~= 0x03 then
    -- sha_outputs: SHA256 of all outputs
    local ow = serialize.buffer_writer()
    for _, out in ipairs(tx.outputs) do
      ow.write_i64le(out.value)
      ow.write_varstr(out.script_pubkey)
    end
    w.write_bytes(crypto.sha256(ow.result()))
  end

  -- Spend type: (ext_flag * 2) + annex_present
  local annex_present = annex and 1 or 0
  w.write_u8(ext_flag * 2 + annex_present)

  -- Input-specific data
  if anyone_can_pay then
    -- This input's outpoint
    local inp = tx.inputs[input_index + 1]
    w.write_hash256(inp.prev_out.hash)
    w.write_u32le(inp.prev_out.index)

    -- This input's prev output
    local po = prev_outputs[input_index + 1]
    w.write_i64le(po.value)
    w.write_varstr(po.script_pubkey)

    -- This input's sequence
    w.write_u32le(inp.sequence)
  else
    -- Just the input index
    w.write_u32le(input_index)
  end

  -- Annex hash (if present)
  if annex then
    local ah = crypto.sha256(crypto.compact_size(#annex) .. annex)
    w.write_bytes(ah)
  end

  -- Output-specific data for SIGHASH_SINGLE
  if output_type == 0x03 then
    if input_index < #tx.outputs then
      local ow = serialize.buffer_writer()
      local out = tx.outputs[input_index + 1]
      ow.write_i64le(out.value)
      ow.write_varstr(out.script_pubkey)
      w.write_bytes(crypto.sha256(ow.result()))
    else
      w.write_bytes(string.rep("\0", 32))
    end
  end

  -- Script-path extensions (ext_flag == 1)
  if ext_flag == 1 then
    assert(tapleaf_hash, "tapleaf_hash required for script-path sighash")
    w.write_bytes(tapleaf_hash)
    w.write_u8(0x00)  -- key_version
    w.write_u32le(codesep_pos)
  end

  return crypto.tagged_hash("TapSighash", w.result())
end

--------------------------------------------------------------------------------
-- Block Hash
--------------------------------------------------------------------------------

--- Compute block hash (double-SHA256 of header).
-- @param header block_header: The block header
-- @return hash256: The block hash
function M.compute_block_hash(header)
  local data = serialize.serialize_block_header(header)
  return crypto.hash256_type(data)
end

--------------------------------------------------------------------------------
-- Proof of Work
--------------------------------------------------------------------------------

--- Check if block header meets proof of work requirements.
-- @param header block_header: The block header
-- @param network table: Network configuration (optional, defaults to mainnet)
-- @return boolean: true if valid
function M.check_proof_of_work(header, network)
  network = network or consensus.networks.mainnet

  local block_hash = M.compute_block_hash(header)
  local target = consensus.bits_to_target(header.bits)

  return consensus.hash_meets_target(block_hash.bytes, target)
end

--------------------------------------------------------------------------------
-- Merkle Root
--------------------------------------------------------------------------------

--- Check if block's merkle root is correct.
-- @param block block: The full block
-- @return boolean: true if valid
function M.check_merkle_root(block)
  local tx_hashes = {}
  for i, tx in ipairs(block.transactions) do
    tx_hashes[i] = M.compute_txid(tx)
  end

  local computed_root = crypto.compute_merkle_root(tx_hashes)
  return types.hash256_eq(computed_root, block.header.merkle_root)
end

--------------------------------------------------------------------------------
-- Witness Commitment
--------------------------------------------------------------------------------

-- Witness commitment prefix: OP_RETURN (0x6a) + push 36 bytes (0x24) + marker (aa21a9ed)
local WITNESS_COMMITMENT_PREFIX = "\x6a\x24\xaa\x21\xa9\xed"

--- Check witness commitment in coinbase.
-- @param block block: The full block
-- @return boolean: true if valid or no commitment needed
function M.check_witness_commitment(block)
  if #block.transactions == 0 then
    return true
  end

  local coinbase = block.transactions[1]

  -- Find witness commitment in coinbase outputs (search from last to first)
  local commitment_hash = nil
  for i = #coinbase.outputs, 1, -1 do
    local script_pubkey = coinbase.outputs[i].script_pubkey
    if #script_pubkey >= 38 and script_pubkey:sub(1, 6) == WITNESS_COMMITMENT_PREFIX then
      commitment_hash = script_pubkey:sub(7, 38)
      break
    end
  end

  -- No commitment found - check if any transaction has witness data
  if not commitment_hash then
    for i = 2, #block.transactions do
      if block.transactions[i].segwit then
        return false  -- Has witness data but no commitment
      end
    end
    return true  -- No witness data, no commitment needed
  end

  -- Compute witness merkle root
  -- Coinbase wtxid is all zeros
  local witness_hashes = {}
  witness_hashes[1] = types.hash256_zero()
  for i = 2, #block.transactions do
    witness_hashes[i] = M.compute_wtxid(block.transactions[i])
  end
  local witness_root = crypto.compute_merkle_root(witness_hashes)

  -- Get witness nonce from coinbase (first witness item, or 32 zero bytes)
  local witness_nonce = string.rep("\0", 32)
  if coinbase.inputs[1].witness and #coinbase.inputs[1].witness >= 1 then
    witness_nonce = coinbase.inputs[1].witness[1]
    if #witness_nonce ~= 32 then
      return false  -- Invalid nonce length
    end
  end

  -- Verify: SHA256d(witness_root || witness_nonce) == commitment_hash
  local computed = crypto.hash256(witness_root.bytes .. witness_nonce)
  return computed == commitment_hash
end

--------------------------------------------------------------------------------
-- Block Header Validation
--------------------------------------------------------------------------------

--- Check block header (timestamp and PoW).
-- @param header block_header: The block header
-- @param network table: Network configuration
-- @return boolean: true if valid
function M.check_block_header(header, network)
  network = network or consensus.networks.mainnet

  -- Check timestamp not more than 2 hours in future
  local current_time = os.time()
  local max_future = 2 * 60 * 60  -- 2 hours
  assert(header.timestamp <= current_time + max_future,
         "block timestamp too far in future")

  -- Check proof of work
  assert(M.check_proof_of_work(header, network), "proof of work failed")

  return true
end

--------------------------------------------------------------------------------
-- Full Block Validation
--------------------------------------------------------------------------------

--- Check full block (context-free).
-- @param block block: The full block
-- @param network table: Network configuration
-- @param height number: Block height (optional, for BIP34 check)
-- @return boolean: true if valid
function M.check_block(block, network, height)
  network = network or consensus.networks.mainnet

  -- Check header
  M.check_block_header(block.header, network)

  -- Must have at least one transaction
  assert(#block.transactions > 0, "block has no transactions")

  -- Single-pass: check transactions, compute weight, count sigops, and cache
  -- serialized data on each tx to eliminate redundant serializations in
  -- check_merkle_root, check_witness_commitment, and connect_block.
  local total_weight = 0
  local total_sigops = 0
  for i, tx in ipairs(block.transactions) do
    -- Serialize once and cache on the tx object BEFORE check_transaction
    -- so it can reuse the cached base_data for the MIN_TX_SIZE check.
    -- This also eliminates redundant serializations in check_merkle_root,
    -- check_witness_commitment, and connect_block.
    local base_data = serialize.serialize_transaction(tx, false)
    local total_data = serialize.serialize_transaction(tx, true)
    tx._cached_base_data = base_data
    tx._cached_witness_data = total_data

    -- Pre-compute and cache txid/wtxid from the serialized data
    tx._cached_txid = crypto.hash256_type(base_data)
    tx._cached_wtxid = crypto.hash256_type(total_data)

    local _, is_cb = M.check_transaction(tx)
    if i == 1 then
      assert(is_cb, "first transaction is not coinbase")
    else
      assert(not is_cb, "transaction " .. i .. " is coinbase")
    end

    -- Weight: base_size * 3 + total_size
    total_weight = total_weight + #base_data * 3 + #total_data

    -- Legacy sigops
    for _, inp in ipairs(tx.inputs) do
      total_sigops = total_sigops + M.count_script_sigops(inp.script_sig, false)
    end
    for _, out in ipairs(tx.outputs) do
      total_sigops = total_sigops + M.count_script_sigops(out.script_pubkey, false)
    end
  end
  assert(total_weight <= consensus.MAX_BLOCK_WEIGHT,
         "block weight " .. total_weight .. " exceeds maximum " .. consensus.MAX_BLOCK_WEIGHT)
  assert(total_sigops * consensus.WITNESS_SCALE_FACTOR <= consensus.MAX_BLOCK_SIGOPS_COST,
         "sigops cost " .. (total_sigops * consensus.WITNESS_SCALE_FACTOR) ..
         " exceeds maximum " .. consensus.MAX_BLOCK_SIGOPS_COST)

  -- Verify merkle root
  assert(M.check_merkle_root(block), "merkle root mismatch")

  -- Verify witness commitment
  assert(M.check_witness_commitment(block), "witness commitment mismatch")

  -- BIP34: height in coinbase scriptSig
  if height and height >= network.bip34_height then
    local coinbase_sig = block.transactions[1].inputs[1].script_sig
    if #coinbase_sig > 0 then
      local first_byte = coinbase_sig:byte(1)
      local encoded_height
      if first_byte == 0x00 then
        -- OP_0 pushes 0
        encoded_height = 0
      elseif first_byte >= 0x51 and first_byte <= 0x60 then
        -- OP_1 through OP_16 push values 1-16
        encoded_height = first_byte - 0x50
      elseif first_byte == 0x4f then
        -- OP_1NEGATE pushes -1
        encoded_height = -1
      elseif first_byte >= 1 and first_byte <= 4 and #coinbase_sig >= first_byte + 1 then
        -- Standard BIP34: first byte is push length (1-4), followed by LE height
        encoded_height = 0
        for i = 1, first_byte do
          encoded_height = encoded_height + coinbase_sig:byte(i + 1) * (256 ^ (i - 1))
        end
      else
        error("invalid BIP34 height encoding")
      end
      assert(encoded_height == height,
             "BIP34 height mismatch: expected " .. height .. ", got " .. encoded_height)
    else
      error("empty coinbase scriptSig (BIP34 requires height)")
    end
  end

  return true
end

--------------------------------------------------------------------------------
-- BIP68 Sequence Locks
--------------------------------------------------------------------------------

--- Calculate the sequence locks for a transaction (BIP68).
-- Returns the minimum block height and minimum MTP time for the transaction
-- to be valid. These are "last invalid" values (the first valid is one more).
-- @param tx transaction: The transaction
-- @param height number: Height of the block being validated
-- @param get_utxo_height function(inp) -> number: Returns the height where each input's UTXO was confirmed
-- @param get_block_mtp function(height) -> number: Returns the MTP of the block at given height
-- @param enforce_bip68 boolean: Whether BIP68 is active at this height
-- @return number, number: min_height (last invalid), min_time (last invalid)
function M.calculate_sequence_locks(tx, height, get_utxo_height, get_block_mtp, enforce_bip68)
  -- Initialize to -1: "last invalid" semantics means -1 allows any height/time
  local min_height = -1
  local min_time = -1

  -- BIP68 only applies to version >= 2 transactions when active
  if tx.version < 2 or not enforce_bip68 then
    return min_height, min_time
  end

  for i, inp in ipairs(tx.inputs) do
    local seq = inp.sequence

    -- Check disable flag (bit 31): if set, skip this input
    if bit.band(seq, consensus.SEQUENCE_LOCKTIME_DISABLE_FLAG) == 0 then
      -- Get the height where this UTXO was confirmed
      local coin_height = get_utxo_height(inp)
      assert(coin_height, "Missing UTXO height for input " .. i)

      -- Check type flag (bit 22): time-based or height-based
      if bit.band(seq, consensus.SEQUENCE_LOCKTIME_TYPE_FLAG) ~= 0 then
        -- Time-based lock
        -- Get MTP of the block BEFORE the one containing the UTXO
        local coin_time = get_block_mtp(math.max(coin_height - 1, 0))
        -- Lock value in 512-second units, convert to seconds, apply "last invalid" adjustment
        local lock_value = bit.band(seq, consensus.SEQUENCE_LOCKTIME_MASK)
        local lock_seconds = bit.lshift(lock_value, consensus.SEQUENCE_LOCKTIME_GRANULARITY)
        min_time = math.max(min_time, coin_time + lock_seconds - 1)
      else
        -- Height-based lock
        local lock_value = bit.band(seq, consensus.SEQUENCE_LOCKTIME_MASK)
        min_height = math.max(min_height, coin_height + lock_value - 1)
      end
    end
  end

  return min_height, min_time
end

--- Check if sequence locks are satisfied for inclusion in a block (BIP68).
-- @param min_height number: Minimum height from calculate_sequence_locks
-- @param min_time number: Minimum time from calculate_sequence_locks
-- @param block_height number: Height of the block being validated
-- @param prev_block_mtp number: MTP of the previous block
-- @return boolean: true if locks are satisfied
function M.check_sequence_locks(min_height, min_time, block_height, prev_block_mtp)
  -- Using "last invalid" semantics: value must be STRICTLY LESS than threshold
  if min_height >= block_height then
    return false
  end
  if min_time >= prev_block_mtp then
    return false
  end
  return true
end

--------------------------------------------------------------------------------
-- Block Context Validation
--------------------------------------------------------------------------------

--- Check block in context of chain.
-- @param block block: The full block
-- @param header block_header: This block's header
-- @param prev_header block_header: Previous block's header
-- @param height number: Block height
-- @param network table: Network configuration
-- @param median_time number: Median time past of previous 11 blocks
-- @return boolean: true if valid
function M.check_block_context(block, header, prev_header, height, network, median_time)
  network = network or consensus.networks.mainnet

  -- Verify prev_hash matches computed hash of prev_header
  local prev_hash = M.compute_block_hash(prev_header)
  assert(types.hash256_eq(header.prev_hash, prev_hash),
         "prev_hash does not match previous block hash")

  -- Verify timestamp > median_time_past
  assert(header.timestamp > median_time,
         "block timestamp " .. header.timestamp ..
         " not greater than median time past " .. median_time)

  -- Check difficulty target bounds
  -- NOTE: Full difficulty validation is done in sync.lua's HeaderChain:accept_header()
  -- which has access to ancestor blocks via consensus.get_next_work_required().
  -- Here we only perform basic sanity checks.

  -- Verify bits is within valid range (not exceeding pow_limit)
  -- Compare as big-endian byte strings: target must be <= pow_limit
  local target = consensus.bits_to_target(header.bits)
  local pow_limit = consensus.bits_to_target(network.pow_limit_bits)
  for i = 1, 32 do
    local t = target:byte(i)
    local p = pow_limit:byte(i)
    if t > p then
      error("target exceeds proof-of-work limit")
    elseif t < p then
      break  -- target is less, which is valid
    end
  end

  return true
end

--------------------------------------------------------------------------------
-- Signature Checker
--------------------------------------------------------------------------------

--- Create a signature checker for script verification.
-- @param tx transaction: The transaction
-- @param input_index number: Index of input being verified (0-based)
-- @param prev_output_value number: Value of the previous output being spent
-- @param prev_script_pubkey string: ScriptPubKey of the previous output
-- @param flags table: Script verification flags
-- @return table: Checker with check_sig, check_locktime, check_sequence methods
function M.make_sig_checker(tx, input_index, prev_output_value, prev_script_pubkey, flags)
  flags = flags or {}
  local checker = {}

  -- Determine if this is a SegWit spend
  local is_segwit = flags.is_segwit or false

  -- Witness program hash for P2WPKH, witness script for P2WSH
  local wpkh_program = nil     -- 20-byte witness program for P2WPKH
  local wsh_script = nil       -- witness script for P2WSH

  --- Set segwit mode dynamically (called by verify_witness_program).
  -- @param segwit boolean: enable segwit sighash
  -- @param p2wpkh_program string|nil: 20-byte hash for P2WPKH
  -- @param p2wsh_witness_script string|nil: witness script for P2WSH
  function checker.set_segwit(segwit, p2wpkh_program, p2wsh_witness_script)
    is_segwit = segwit
    wpkh_program = p2wpkh_program
    wsh_script = p2wsh_witness_script
  end

  --- Get witness data from the spending transaction input.
  -- @return table: witness stack
  function checker.get_witness()
    local inp = tx.inputs[input_index + 1]
    if inp and inp.witness then
      return inp.witness
    end
    return {}
  end

  --- Check a signature against a public key.
  -- @param sig string: DER-encoded signature with hash type byte appended
  -- @param pubkey string: Public key (33 or 65 bytes)
  -- @return boolean: true if valid
  function checker.check_sig(sig, pubkey)
    if #sig == 0 then
      return false
    end

    -- Extract hash type from last byte
    local hash_type = sig:byte(#sig)
    local sig_der = sig:sub(1, -2)

    -- Determine script code
    local script_code
    if is_segwit then
      if wpkh_program then
        -- P2WPKH: synthetic P2PKH script from 20-byte program
        script_code = script.make_p2pkh_script(wpkh_program)
      elseif wsh_script then
        -- P2WSH: use the witness script
        script_code = wsh_script
      else
        -- Fallback: try classifying the scriptPubKey
        local script_type, hash = script.classify_script(prev_script_pubkey)
        if script_type == "p2wpkh" then
          script_code = script.make_p2pkh_script(hash)
        else
          script_code = flags.witness_script or prev_script_pubkey
        end
      end
    else
      -- Legacy: use the script code provided
      script_code = flags.script_code or prev_script_pubkey
    end

    -- Compute sighash
    local sighash
    if is_segwit then
      -- SegWit does NOT use FindAndDelete
      sighash = M.signature_hash_segwit_v0(tx, input_index, script_code, prev_output_value, hash_type)
    else
      -- Legacy: pass the full signature (with hash type byte) for FindAndDelete
      sighash = M.signature_hash_legacy(tx, input_index, script_code, hash_type, sig)
    end

    -- Verify ECDSA signature
    -- Use strict DER parsing when DERSIG/STRICTENC/LOW_S flags require it,
    -- otherwise use lax DER parsing for pre-BIP66 compatibility
    if flags.verify_dersig or flags.verify_strictenc or flags.verify_low_s then
      return crypto.ecdsa_verify(pubkey, sig_der, sighash)
    else
      return crypto.ecdsa_verify_lax(pubkey, sig_der, sighash)
    end
  end

  --- Check locktime (BIP65 CLTV).
  -- @param script_locktime number: Locktime value from script
  -- @return boolean: true if valid
  function checker.check_locktime(script_locktime)
    -- Fail if sequences are all 0xFFFFFFFF (transaction is final)
    if tx.inputs[input_index + 1].sequence == 0xFFFFFFFF then
      return false
    end

    -- Locktime types must match (both block height or both timestamp)
    local threshold = consensus.LOCKTIME_THRESHOLD
    local tx_locktime = tx.locktime

    -- Both must be same type
    if (script_locktime < threshold) ~= (tx_locktime < threshold) then
      return false
    end

    -- Script locktime must be <= tx locktime
    return script_locktime <= tx_locktime
  end

  --- Check sequence (BIP112 CSV).
  -- @param script_sequence number: Sequence value from script
  -- @return boolean: true if valid
  function checker.check_sequence(script_sequence)
    -- Check disable flag
    if not consensus.sequence_locks_active(script_sequence) then
      return true  -- Disabled, always passes
    end

    local inp = tx.inputs[input_index + 1]

    -- Transaction version must be >= 2
    if tx.version < 2 then
      return false
    end

    -- Input sequence must have locks active
    if not consensus.sequence_locks_active(inp.sequence) then
      return false
    end

    -- Types must match
    local script_is_time = consensus.sequence_lock_is_time_based(script_sequence)
    local input_is_time = consensus.sequence_lock_is_time_based(inp.sequence)
    if script_is_time ~= input_is_time then
      return false
    end

    -- Script sequence value must be <= input sequence value
    local script_value = consensus.sequence_lock_value(script_sequence)
    local input_value = consensus.sequence_lock_value(inp.sequence)
    return script_value <= input_value
  end

  return checker
end

--- Create a signature checker for tapscript (BIP342) script-path execution.
-- Uses Schnorr signatures and taproot sighash (BIP341).
-- @param tx transaction: The transaction
-- @param input_index number: Index of input being verified (0-based)
-- @param prev_outputs table: Array of {value, script_pubkey} for ALL inputs
-- @param tapleaf_hash string: 32-byte tapleaf hash for this script
-- @param annex string|nil: Annex data (if present)
-- @return table: Checker with check_sig, check_locktime, check_sequence methods
function M.make_tapscript_checker(tx, input_index, prev_outputs, tapleaf_hash, annex)
  local checker = {}
  local codesep_pos = 0xFFFFFFFF

  function checker.set_codesep(pos)
    codesep_pos = pos
  end

  --- Check a BIP340 Schnorr signature against an x-only public key.
  -- @param sig string: 64- or 65-byte Schnorr signature (65 if explicit hash type)
  -- @param pubkey string: 32-byte x-only public key
  -- @return boolean: true if valid
  function checker.check_sig(sig, pubkey)
    if #sig == 0 then
      return false
    end

    -- BIP342: signature must be exactly 64 or 65 bytes
    if #sig ~= 64 and #sig ~= 65 then
      return false
    end

    -- Extract hash type
    local hash_type = 0x00  -- SIGHASH_DEFAULT
    local sig_bytes = sig
    if #sig == 65 then
      hash_type = sig:byte(65)
      sig_bytes = sig:sub(1, 64)
      -- BIP341: hash_type 0x00 must not be used with 65-byte sig
      if hash_type == 0x00 then
        return false
      end
    end

    -- Compute taproot sighash for script-path (ext_flag = 1)
    local sighash = M.signature_hash_taproot(
      tx, input_index, hash_type, prev_outputs,
      1, annex, tapleaf_hash, codesep_pos
    )

    -- Verify BIP340 Schnorr signature
    return crypto.schnorr_verify(pubkey, sig_bytes, sighash)
  end

  --- Check locktime (BIP65 CLTV).
  function checker.check_locktime(script_locktime)
    if tx.inputs[input_index + 1].sequence == 0xFFFFFFFF then
      return false
    end
    local threshold = consensus.LOCKTIME_THRESHOLD
    local tx_locktime = tx.locktime
    if (script_locktime < threshold) ~= (tx_locktime < threshold) then
      return false
    end
    return script_locktime <= tx_locktime
  end

  --- Check sequence (BIP112 CSV).
  function checker.check_sequence(script_sequence)
    if not consensus.sequence_locks_active(script_sequence) then
      return true
    end
    local inp = tx.inputs[input_index + 1]
    if tx.version < 2 then
      return false
    end
    if not consensus.sequence_locks_active(inp.sequence) then
      return false
    end
    local script_is_time = consensus.sequence_lock_is_time_based(script_sequence)
    local input_is_time = consensus.sequence_lock_is_time_based(inp.sequence)
    if script_is_time ~= input_is_time then
      return false
    end
    local script_value = consensus.sequence_lock_value(script_sequence)
    local input_value = consensus.sequence_lock_value(inp.sequence)
    return script_value <= input_value
  end

  return checker
end

--------------------------------------------------------------------------------
-- Deferred-Collect Sig Checker (for parallel batch ECDSA)
--------------------------------------------------------------------------------

--- Create a "collecting" sig checker that defers ECDSA verification.
-- During script execution, instead of immediately verifying each ECDSA
-- signature, this checker records {pubkey, sig_der, sighash} into a
-- caller-supplied collector table.  After all inputs have been processed,
-- the caller batch-verifies via verify_signatures_parallel().
--
-- Script opcode logic (OP_CHECKMULTISIG counting, push-only checks, etc.)
-- still runs inside the script engine; only the final crypto step is deferred.
--
-- NOTE: For Schnorr / Taproot signatures (Schnorr is always immediate since
-- schnorr_verify is in the C extension and typically fast enough) we still
-- verify immediately.  Only ECDSA (the bottleneck for pre-taproot blocks) is
-- deferred.
--
-- @param tx transaction: The transaction being verified
-- @param input_index number: 0-based input index
-- @param prev_output_value number: Satoshi value of the prev output
-- @param prev_script_pubkey string: scriptPubKey of the prev output
-- @param flags table: Script verification flags
-- @param collector table: Array to append {pubkey, sig_der, sighash} to
-- @return table: Checker compatible with make_sig_checker interface
function M.make_collecting_sig_checker(tx, input_index, prev_output_value, prev_script_pubkey, flags, collector)
  flags = flags or {}
  local checker = {}

  local is_segwit = flags.is_segwit or false
  local wpkh_program = nil
  local wsh_script = nil

  function checker.set_segwit(segwit, p2wpkh_program, p2wsh_witness_script)
    is_segwit = segwit
    wpkh_program = p2wpkh_program
    wsh_script = p2wsh_witness_script
  end

  function checker.get_witness()
    local inp = tx.inputs[input_index + 1]
    if inp and inp.witness then
      return inp.witness
    end
    return {}
  end

  --- Deferred ECDSA check: compute sighash immediately (must happen in script
  -- execution order) but push (pubkey, sig_der, sighash) to collector instead
  -- of calling ecdsa_verify.  Returns true (optimistic) so script execution
  -- can continue; the batch verify pass at the end will catch any failures.
  function checker.check_sig(sig, pubkey)
    if #sig == 0 then
      return false
    end

    local hash_type = sig:byte(#sig)
    local sig_der = sig:sub(1, -2)

    -- Determine script code (same logic as make_sig_checker)
    local script_code
    if is_segwit then
      if wpkh_program then
        script_code = script.make_p2pkh_script(wpkh_program)
      elseif wsh_script then
        script_code = wsh_script
      else
        local script_type, hash = script.classify_script(prev_script_pubkey)
        if script_type == "p2wpkh" then
          script_code = script.make_p2pkh_script(hash)
        else
          script_code = flags.witness_script or prev_script_pubkey
        end
      end
    else
      script_code = flags.script_code or prev_script_pubkey
    end

    -- Compute sighash now (order-dependent — must run here in script execution)
    local sighash
    if is_segwit then
      sighash = M.signature_hash_segwit_v0(tx, input_index, script_code, prev_output_value, hash_type)
    else
      sighash = M.signature_hash_legacy(tx, input_index, script_code, hash_type, sig)
    end

    -- Push to collector for deferred parallel ECDSA verification
    collector[#collector + 1] = { pubkey = pubkey, sig_der = sig_der, sighash = sighash }

    -- Return true optimistically; batch verify will catch failures
    return true
  end

  function checker.check_locktime(script_locktime)
    if tx.inputs[input_index + 1].sequence == 0xFFFFFFFF then
      return false
    end
    local threshold = consensus.LOCKTIME_THRESHOLD
    local tx_locktime = tx.locktime
    if (script_locktime < threshold) ~= (tx_locktime < threshold) then
      return false
    end
    return script_locktime <= tx_locktime
  end

  function checker.check_sequence(script_sequence)
    if not consensus.sequence_locks_active(script_sequence) then
      return true
    end
    local inp = tx.inputs[input_index + 1]
    if tx.version < 2 then return false end
    if not consensus.sequence_locks_active(inp.sequence) then return false end
    local script_is_time = consensus.sequence_lock_is_time_based(script_sequence)
    local input_is_time = consensus.sequence_lock_is_time_based(inp.sequence)
    if script_is_time ~= input_is_time then return false end
    local script_value = consensus.sequence_lock_value(script_sequence)
    local input_value = consensus.sequence_lock_value(inp.sequence)
    return script_value <= input_value
  end

  return checker
end

return M
