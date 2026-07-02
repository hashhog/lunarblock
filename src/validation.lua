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

  -- Check serialized size.
  -- Upper bound (consensus): Bitcoin Core CheckTransaction checks
  --   GetSerializeSize(TX_NO_WITNESS(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
  -- i.e. stripped_size * 4 > 4_000_000, which means stripped_size > 1_000_000.
  -- Reference: bitcoin-core/src/consensus/tx_check.cpp:19.
  local tx_data = tx._cached_base_data or serialize.serialize_transaction(tx, false)
  assert(#tx_data * consensus.WITNESS_SCALE_FACTOR <= consensus.MAX_BLOCK_WEIGHT,
         "transaction stripped size " .. #tx_data .. " * 4 exceeds MAX_BLOCK_WEIGHT")

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
      -- CVE-2018-17144: duplicate inputs allow inflation in naive UTXO implementations.
      -- Core: state.Invalid(TX_CONSENSUS, "bad-txns-inputs-duplicate")
      -- tx_check.cpp:44.
      error("bad-txns-inputs-duplicate")
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
-- Equivalent to: stripped_size * (WITNESS_SCALE_FACTOR - 1) + total_size
-- Reference: bitcoin-core/src/consensus/validation.h:132-135.
-- @param tx transaction: The transaction
-- @return number: The weight in weight units
function M.get_tx_weight(tx)
  local base_size = #serialize.serialize_transaction(tx, false)
  local total_size = #serialize.serialize_transaction(tx, true)
  return base_size * 3 + total_size
end

--- Get the sigop-adjusted weight.
-- When a transaction has many sigops, its effective weight is raised to
-- sigop_cost * bytes_per_sigop so that miners are correctly compensated.
-- Reference: bitcoin-core/src/policy/policy.cpp:390-393 GetSigOpsAdjustedWeight.
--   return std::max(weight, sigop_cost * bytes_per_sigop);
-- @param weight number: raw transaction weight
-- @param sigop_cost number: total sigop cost (from get_transaction_sigop_cost)
-- @param bytes_per_sigop number: bytes per sigop policy setting (default 20)
-- @return number: adjusted weight
function M.get_sigops_adjusted_weight(weight, sigop_cost, bytes_per_sigop)
  bytes_per_sigop = bytes_per_sigop or 20
  local adjusted = sigop_cost * bytes_per_sigop
  if adjusted > weight then return adjusted end
  return weight
end

--- Get virtual transaction size (vsize).
-- vsize = ceil(sigop_adjusted_weight / WITNESS_SCALE_FACTOR)
-- Reference: bitcoin-core/src/policy/policy.cpp:395-398 GetVirtualTransactionSize:
--   return (GetSigOpsAdjustedWeight(nWeight, nSigOpCost, bytes_per_sigop)
--           + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
-- When sigop_cost=0 and bytes_per_sigop=0 this reduces to ceil(weight/4),
-- matching the no-sigop-adjustment form (policy.h:186-188).
-- @param weight number: raw transaction weight
-- @param sigop_cost number: total sigop cost (0 to disable adjustment)
-- @param bytes_per_sigop number: bytes per sigop (0 to disable adjustment)
-- @return number: virtual size in vbytes (integer, ceiling division)
function M.get_virtual_tx_size(weight, sigop_cost, bytes_per_sigop)
  sigop_cost = sigop_cost or 0
  bytes_per_sigop = bytes_per_sigop or 0
  local adj = M.get_sigops_adjusted_weight(weight, sigop_cost, bytes_per_sigop)
  -- Ceiling division: (adj + WSF - 1) / WSF
  return math.floor((adj + consensus.WITNESS_SCALE_FACTOR - 1) / consensus.WITNESS_SCALE_FACTOR)
end

--------------------------------------------------------------------------------
-- Sigops Counting
--------------------------------------------------------------------------------

--- Count signature operations in a script.
-- @param script_bytes string: The script bytes
-- @param accurate boolean: If true, use accurate counting for OP_CHECKMULTISIG
-- @return number: The sigops count
function M.count_script_sigops(script_bytes, accurate)
  -- Mirror Bitcoin Core CScript::GetSigOpCount (script/script.cpp:158-180):
  -- walk the script opcode-by-opcode and, on a malformed/truncated push (where
  -- Core's GetOp returns false), STOP and return the count accumulated SO FAR
  -- -- NOT 0.  The previous `pcall(parse_script); if not ok then return 0`
  -- undercounted any script that fails to fully parse (e.g. leading OP_CHECKSIGs
  -- before a truncated push), which let an attacker craft a block whose true
  -- (Core) sigop cost exceeds MAX_BLOCK_SIGOPS_COST pass this node's check
  -- (false-accept -> chain split).  This counts the partial prefix exactly as
  -- Core does.  Unparseable trailing bytes simply end the walk.
  local count = 0
  local prev_opcode = nil
  local pos = 1
  local len = #script_bytes
  local OP = script.OP

  while pos <= len do
    local opcode = script_bytes:byte(pos)
    pos = pos + 1

    -- Skip push data, mirroring GetOp: if the script is truncated mid-push
    -- (not enough bytes for the length prefix or the data), GetOp would return
    -- false, so we break and return what we have counted so far.
    if opcode >= 0x01 and opcode <= 0x4b then          -- direct push of N bytes
      pos = pos + opcode
      if pos - 1 > len then break end
    elseif opcode == 0x4c then                          -- OP_PUSHDATA1
      if pos > len then break end
      local data_len = script_bytes:byte(pos)
      pos = pos + 1 + data_len
      if pos - 1 > len then break end
    elseif opcode == 0x4d then                          -- OP_PUSHDATA2
      if pos + 1 > len then break end
      local data_len = script_bytes:byte(pos) + script_bytes:byte(pos + 1) * 256
      pos = pos + 2 + data_len
      if pos - 1 > len then break end
    elseif opcode == 0x4e then                          -- OP_PUSHDATA4
      if pos + 3 > len then break end
      local b1, b2, b3, b4 = script_bytes:byte(pos, pos + 3)
      local data_len = b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
      pos = pos + 4 + data_len
      if pos - 1 > len then break end
    end

    if opcode == OP.OP_CHECKSIG or opcode == OP.OP_CHECKSIGVERIFY then
      count = count + 1
    elseif opcode == OP.OP_CHECKMULTISIG or opcode == OP.OP_CHECKMULTISIGVERIFY then
      if accurate and prev_opcode and prev_opcode >= OP.OP_1 and prev_opcode <= OP.OP_16 then
        count = count + (prev_opcode - OP.OP_1 + 1)
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

-- Advance one opcode from 1-based byte position `pos` in `script`, returning
-- the 1-based position of the byte immediately after that opcode (including
-- its push payload). Mirrors CScript::GetOp's cursor advance. On a truncated
-- push it advances to len+1 (Core's GetOp returns false but still moves pc to
-- end); the caller's loop terminates either way.
local function script_get_op_end(script, pos)
  local len = #script
  if pos > len then return pos end
  local opcode = script:byte(pos)
  pos = pos + 1
  if opcode <= 0x4b then
    pos = pos + opcode
  elseif opcode == 0x4c then
    if pos > len then return len + 1 end
    pos = pos + 1 + script:byte(pos)
  elseif opcode == 0x4d then
    if pos + 1 > len then return len + 1 end
    pos = pos + 2 + script:byte(pos) + script:byte(pos + 1) * 256
  elseif opcode == 0x4e then
    if pos + 3 > len then return len + 1 end
    local b1, b2, b3, b4 = script:byte(pos, pos + 3)
    pos = pos + 4 + b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
  end
  if pos > len + 1 then pos = len + 1 end
  return pos
end

--- Find and delete all occurrences of a push-encoded signature from a script.
-- This is used in legacy sighash computation to remove the signature being
-- verified from the scriptCode before hashing.
--
-- Faithful port of Bitcoin Core FindAndDelete (interpreter.cpp:229-255):
-- non-overlapping, greedy removal of the needle, with the match cursor only
-- advancing one opcode at a time via GetOp between match windows. Implemented
-- with byte-exact comparisons (string.sub) instead of Lua string patterns —
-- the previous gsub-pattern implementation silently truncated the match at the
-- first 0x00 byte inside a DER signature (Lua patterns treat an embedded NUL
-- as a terminator), so a `02 21 00 ...` signature was only partially deleted,
-- corrupting the scriptCode and the sighash (NULLFAIL on every FindAndDelete
-- script_tests / tx_valid vector).
-- @param script_bytes string: The script bytes
-- @param sig_bytes string: The signature bytes (without push opcode)
-- @return string: Script with signature removed
function M.find_and_delete(script_bytes, sig_bytes)
  if not sig_bytes or #sig_bytes == 0 then
    return script_bytes
  end

  -- The signature is push-encoded in the script: [push_opcode] [data]
  local b = serialize_push_data(sig_bytes)
  local blen = #b
  local slen = #script_bytes
  if blen == 0 or slen < blen then
    return script_bytes
  end

  local parts = {}
  local pc = 1     -- current scan cursor (1-based)
  local pc2 = 1    -- start of the not-yet-copied run
  local found = 0

  while true do
    -- Copy the run [pc2, pc) accumulated since the last match window.
    if pc > pc2 then
      parts[#parts + 1] = script_bytes:sub(pc2, pc - 1)
    end
    -- Greedily skip every contiguous needle occurrence at pc (byte-exact;
    -- string.sub comparison handles embedded NUL bytes correctly).
    while (slen - (pc - 1)) >= blen
          and script_bytes:sub(pc, pc + blen - 1) == b do
      pc = pc + blen
      found = found + 1
    end
    pc2 = pc
    -- GetOp: advance one opcode. Terminate when the cursor reaches the end.
    if pc > slen then break end
    pc = script_get_op_end(script_bytes, pc)
  end

  if found > 0 then
    if pc2 <= slen then
      parts[#parts + 1] = script_bytes:sub(pc2, slen)
    end
    return table.concat(parts)
  end
  return script_bytes
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

  -- Special case: SIGHASH_SINGLE with input_index >= #outputs.
  -- Core (SignatureHash, interpreter.cpp:1640) returns uint256::ONE here —
  -- the legacy SIGHASH_SINGLE "bug" value. uint256::ONE has m_data[0]==0x01
  -- and the rest zero (uint256.h base_blob(uint8_t v):m_data{v}), so the raw
  -- 32-byte message hash is 0x01 followed by 31 zero bytes (LITTLE-endian),
  -- NOT 31 zeros then 0x01. Returning the reversed bytes made every
  -- out-of-range SIGHASH_SINGLE legacy signature fail to verify (NULLFAIL).
  if ht == consensus.SIGHASH.SINGLE and input_index >= #tx.outputs then
    return "\1" .. string.rep("\0", 31)
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

--- BIP-341 hash-type validity check.
-- Per Core SignatureHashSchnorr (interpreter.cpp:1516) only the values
--   {0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83}
-- are accepted; everything else makes SignatureHashSchnorr return false
-- and the surrounding Schnorr check fails. Pre-fix lunarblock omitted
-- this range check in all three Taproot checker sites (key-path schnorr
-- (×2) and tapscript checker.check_sig); a 65-byte sig whose last byte
-- was e.g. 0x04 would still compute a sighash and the verify would
-- succeed or fail depending on whether the resulting hash happened to
-- match a forged sig — i.e. lunarblock could ACCEPT a witness Core
-- REJECTS, splitting consensus on any block that lands such a sig.
function M.is_valid_taproot_hash_type(hash_type)
  return hash_type <= 0x03 or (hash_type >= 0x81 and hash_type <= 0x83)
end

--- Compute the BIP-341 sigmsg buffer (the bytes fed into TapSighash tagged
-- hash). Exposed so the bip341-vector-runner shim can validate the
-- pre-image against Bitcoin Core's BIP-341 wallet vectors before checking
-- the final hash.
--
-- Returns (msg_bytes) on success, or (nil, err_string) when Core's
-- SignatureHashSchnorr (interpreter.cpp:1483-1570) would return false:
--   * hash_type outside {0x00..0x03, 0x81..0x83}            (Core line 1516)
--   * output_type == SIGHASH_SINGLE and in_pos >= vout.size (Core line 1550)
-- Pre-W95 lunarblock would synthesize a 32-byte zero placeholder for the
-- SIGHASH_SINGLE-out-of-range branch instead of failing, exposing a real
-- consensus-split surface: a Schnorr sig forged against that placeholder
-- digest would verify in lunarblock while Core rejected the input with
-- SCRIPT_ERR_SCHNORR_SIG_HASHTYPE.
function M.signature_msg_taproot(tx, input_index, hash_type, prev_outputs,
                                  ext_flag, annex, tapleaf_hash, codesep_pos)
  ext_flag = ext_flag or 0
  codesep_pos = codesep_pos or 0xFFFFFFFF

  -- BIP-341 hash_type range gate (Core interpreter.cpp:1516). Defense-in-
  -- depth: every consensus call site pre-validates via is_valid_taproot_
  -- hash_type, but if a non-consensus caller (RPC/wallet/PSBT debug
  -- shim) ever passes a bogus byte, we must NOT return a synthesized
  -- digest — that would let policy code build a sig the consensus layer
  -- could never have produced.
  if not M.is_valid_taproot_hash_type(hash_type) then
    return nil, "TAPROOT_BAD_HASH_TYPE"
  end

  local ht = hash_type
  if ht == 0x00 then ht = 0x01 end
  local output_type = bit.band(ht, 0x03)
  local anyone_can_pay = bit.band(ht, 0x80) ~= 0

  -- Core SignatureHashSchnorr line 1550: SIGHASH_SINGLE with in_pos >=
  -- vout.size() returns false. The Schnorr CHECK then fails with
  -- SCRIPT_ERR_SCHNORR_SIG_HASHTYPE. The fail-out MUST happen before we
  -- serialize the message — otherwise a Schnorr sig forged against
  -- sha256(... || 32-zero-bytes || ...) would verify here while being
  -- inadmissible in Core.
  if output_type == 0x03 and input_index >= #tx.outputs then
    return nil, "TAPROOT_SIGHASH_SINGLE_OUT_OF_RANGE"
  end

  local w = serialize.buffer_writer()
  w.write_u8(0x00)  -- epoch
  w.write_u8(hash_type)
  w.write_i32le(tx.version)
  w.write_u32le(tx.locktime)

  if not anyone_can_pay then
    local pw = serialize.buffer_writer()
    for _, inp in ipairs(tx.inputs) do
      pw.write_hash256(inp.prev_out.hash)
      pw.write_u32le(inp.prev_out.index)
    end
    w.write_bytes(crypto.sha256(pw.result()))

    local aw = serialize.buffer_writer()
    for _, po in ipairs(prev_outputs) do
      aw.write_i64le(po.value)
    end
    w.write_bytes(crypto.sha256(aw.result()))

    local sw = serialize.buffer_writer()
    for _, po in ipairs(prev_outputs) do
      sw.write_varstr(po.script_pubkey)
    end
    w.write_bytes(crypto.sha256(sw.result()))

    local qw = serialize.buffer_writer()
    for _, inp in ipairs(tx.inputs) do
      qw.write_u32le(inp.sequence)
    end
    w.write_bytes(crypto.sha256(qw.result()))
  end

  if output_type ~= 0x02 and output_type ~= 0x03 then
    local ow = serialize.buffer_writer()
    for _, out in ipairs(tx.outputs) do
      ow.write_i64le(out.value)
      ow.write_varstr(out.script_pubkey)
    end
    w.write_bytes(crypto.sha256(ow.result()))
  end

  local annex_present = annex and 1 or 0
  w.write_u8(ext_flag * 2 + annex_present)

  if anyone_can_pay then
    local inp = tx.inputs[input_index + 1]
    w.write_hash256(inp.prev_out.hash)
    w.write_u32le(inp.prev_out.index)
    local po = prev_outputs[input_index + 1]
    w.write_i64le(po.value)
    w.write_varstr(po.script_pubkey)
    w.write_u32le(inp.sequence)
  else
    w.write_u32le(input_index)
  end

  if annex then
    local ah = crypto.sha256(crypto.compact_size(#annex) .. annex)
    w.write_bytes(ah)
  end

  if output_type == 0x03 then
    -- Out-of-range case is rejected at function entry; here input_index <
    -- #tx.outputs is invariant. Matches Core SignatureHashSchnorr line
    -- 1551-1557 (HashWriter sha_single_output << tx_to.vout[in_pos]).
    local ow = serialize.buffer_writer()
    local out = tx.outputs[input_index + 1]
    ow.write_i64le(out.value)
    ow.write_varstr(out.script_pubkey)
    w.write_bytes(crypto.sha256(ow.result()))
  end

  if ext_flag == 1 then
    assert(tapleaf_hash, "tapleaf_hash required for script-path sighash")
    w.write_bytes(tapleaf_hash)
    w.write_u8(0x00)
    w.write_u32le(codesep_pos)
  end

  return w.result()
end

--- Compute taproot sighash (BIP341).
-- @param tx transaction: The transaction being verified
-- @param input_index number: 0-based index of the input being signed
-- @param hash_type number: Sighash type (0x00 = SIGHASH_DEFAULT, or standard types)
-- @param prev_outputs table: Array of {value=number, script_pubkey=string} for ALL inputs
-- @param ext_flag number: Extension flag (0 for key-path, 1 for script-path)
-- @param annex string|nil: Annex data (if present)
-- @param tapleaf_hash string|nil: 32-byte leaf hash (for script-path spending)
-- @param codesep_pos number|nil: Code separator position (default 0xFFFFFFFF)
-- @return string|nil 32-byte sighash on success, nil + err string on
--                    failure (bad hash_type or SIGHASH_SINGLE oor-output).
function M.signature_hash_taproot(tx, input_index, hash_type, prev_outputs,
                                   ext_flag, annex, tapleaf_hash, codesep_pos)
  local msg, err = M.signature_msg_taproot(tx, input_index, hash_type, prev_outputs,
                                       ext_flag, annex, tapleaf_hash, codesep_pos)
  if not msg then return nil, err end
  return crypto.tagged_hash("TapSighash", msg)
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
-- Mirrors Bitcoin Core CheckProofOfWorkImpl / DeriveTarget (src/pow.cpp:146-171).
-- Three conditions must all hold:
--   1. bits must not encode a negative target (fNegative flag from SetCompact).
--   2. bits must not be zero or overflow (fOverflow flag from SetCompact).
--   3. target must not exceed pow_limit (would allow easier-than-minimum work).
--   4. block hash must be <= target.
-- Conditions 1-3 are gated via bits_to_target returning a zero 32-byte string
-- for negative/overflow/zero inputs; condition 3 is the explicit pow_limit check
-- added here (Core: if bnTarget > UintToArith256(pow_limit) return false).
-- @param header block_header: The block header
-- @param network table: Network configuration (optional, defaults to mainnet)
-- @return boolean: true if valid
function M.check_proof_of_work(header, network)
  network = network or consensus.networks.mainnet

  local block_hash = M.compute_block_hash(header)
  local target = consensus.bits_to_target(header.bits)

  -- Reject if target exceeds network's proof-of-work limit.
  -- Bitcoin Core DeriveTarget: if (bnTarget > UintToArith256(pow_limit)) return {};
  local pow_limit = consensus.bits_to_target(network.pow_limit_bits)
  if consensus.compare_targets(target, pow_limit) > 0 then
    return false
  end

  return consensus.hash_meets_target(block_hash.bytes, target)
end

--------------------------------------------------------------------------------
-- Merkle Root
--------------------------------------------------------------------------------

--- Check if block's merkle root is correct.
--
-- Mirrors Core CheckMerkleRoot (validation.cpp:3837-3862): computes the
-- block merkle root (with CVE-2012-2459 mutation detection) and rejects on
-- EITHER a root mismatch (bad-txnmrklroot) OR a detected duplicate-tx
-- malleation (bad-txns-duplicate, CVE-2012-2459). The mutation flag is set
-- by crypto.compute_merkle_root when any complete adjacent pair at any level
-- is bit-identical — Core treats that identically to an invalid root.
--
-- @param block block: The full block
-- @return boolean, string|nil: true if valid; false + reject reason otherwise
function M.check_merkle_root(block)
  local tx_hashes = {}
  for i, tx in ipairs(block.transactions) do
    tx_hashes[i] = M.compute_txid(tx)
  end

  local computed_root, mutated = crypto.compute_merkle_root(tx_hashes)
  if not types.hash256_eq(computed_root, block.header.merkle_root) then
    return false, "bad-txnmrklroot"
  end
  -- CVE-2012-2459: a duplicate-tx malleation reproduces the SAME root, so the
  -- mismatch check above passes; reject on the mutation flag (Core:
  -- bad-txns-duplicate).
  if mutated then
    return false, "bad-txns-duplicate"
  end
  return true
end

--------------------------------------------------------------------------------
-- Witness Commitment (BIP-141)
--------------------------------------------------------------------------------

-- Witness commitment prefix: OP_RETURN (0x6a) + push 36 bytes (0x24) + marker (aa21a9ed)
-- MINIMUM_WITNESS_COMMITMENT = 38 bytes (Core consensus/validation.h:18)
-- NO_WITNESS_COMMITMENT = -1  (Core consensus/validation.h:15)
local WITNESS_COMMITMENT_PREFIX = "\x6a\x24\xaa\x21\xa9\xed"
local MINIMUM_WITNESS_COMMITMENT = 38

--- Find the index of the last coinbase output that carries a witness commitment.
-- Mirrors Core GetWitnessCommitmentIndex (consensus/validation.h:147-165):
-- scans ALL coinbase outputs forward, keeps the last matching index.
-- Returns nil when not found (Core returns NO_WITNESS_COMMITMENT = -1).
-- @param coinbase table: The coinbase transaction
-- @return number|nil: 1-based output index, or nil
local function get_witness_commitment_index(coinbase)
  local commitpos = nil
  for i, out in ipairs(coinbase.outputs) do
    local spk = out.script_pubkey
    if #spk >= MINIMUM_WITNESS_COMMITMENT and spk:sub(1, 6) == WITNESS_COMMITMENT_PREFIX then
      commitpos = i
    end
  end
  return commitpos
end

--- Check witness malleation for a block.
-- Mirrors Core CheckWitnessMalleation (validation.cpp:3864-3916).
--
-- BUG-W77 fixes (4 bugs):
--   Bug 1: segwit-activation gating missing — callers must pass expect_witness_commitment
--   Bug 2: witness stack size check was >= 1; Core requires == 1 (BLOCK_MUTATED)
--   Bug 3: missing nonce silently defaulted to zeros; Core rejects (bad-witness-nonce-size)
--   Bug 4: unexpected-witness loop excluded coinbase; Core checks ALL txs
--
-- @param block table: The full block
-- @param expect_witness_commitment boolean: true when segwit deployment is active
--        (mirrors Core's DeploymentActiveAfter(pindexPrev, DEPLOYMENT_SEGWIT))
-- @return boolean, string|nil: true on success; false + error string on failure
function M.check_witness_malleation(block, expect_witness_commitment)
  if expect_witness_commitment then
    -- Segwit is active: look for witness commitment in coinbase.
    -- Core asserts block is non-empty + coinbase has at least one input here;
    -- those invariants are already enforced by check_block's earlier gates.
    local coinbase = block.transactions[1]
    local commitpos = get_witness_commitment_index(coinbase)

    if commitpos ~= nil then
      -- Gate 7: coinbase must have at least one input (asserted by Core).
      -- check_block / check_transaction already ensures this; guard defensively.
      if not coinbase.inputs[1] then
        return false, "bad-witness-nonce-size: coinbase has no inputs"
      end

      -- Gate 8+9: coinbase witness stack must be EXACTLY one 32-byte item.
      -- Core validation.cpp:3880:
      --   if (witness_stack.size() != 1 || witness_stack[0].size() != 32)
      --     → bad-witness-nonce-size (BLOCK_MUTATED)
      -- Bug 2 fix: was checked as >= 1 (allowed multi-item stacks).
      -- Bug 3 fix: was silently defaulting to zeros when witness absent.
      local wit = coinbase.inputs[1].witness
      if not wit or #wit ~= 1 or #wit[1] ~= 32 then
        return false, "bad-witness-nonce-size"
      end
      local witness_nonce = wit[1]

      -- Gate 10: BlockWitnessMerkleRoot — coinbase wtxid = 32 zero bytes,
      -- all other txs use their real wtxid (including witness data).
      local witness_hashes = {}
      witness_hashes[1] = types.hash256_zero()  -- coinbase wtxid = 0x000...0
      for i = 2, #block.transactions do
        witness_hashes[i] = M.compute_wtxid(block.transactions[i])
      end
      local witness_root = crypto.compute_merkle_root(witness_hashes)

      -- Gate 11: SHA256d(witness_root || witness_nonce) must equal the
      -- 32-byte commitment embedded at commitpos scriptPubKey[6..38].
      -- Core validation.cpp:3892-3898.
      local commitment_hash = coinbase.outputs[commitpos].script_pubkey:sub(7, 38)
      local computed = crypto.hash256(witness_root.bytes .. witness_nonce)
      if computed ~= commitment_hash then
        return false, "bad-witness-merkle-match"
      end

      return true
    end
    -- Fall through: commitment not found → check for unexpected witness data
    -- (same path as when segwit is NOT active).
  end

  -- Gate 12: No witness commitment present (either segwit not active, or
  -- active but no commitment output found).  Any transaction in the block
  -- that carries witness data is an error ("unexpected-witness").
  -- Core validation.cpp:3906-3913: iterates ALL vtx (including coinbase).
  -- Bug 4 fix: previous loop started at i=2, skipping the coinbase.
  for _, tx in ipairs(block.transactions) do
    if tx.segwit then
      return false, "unexpected-witness"
    end
  end

  return true
end

--- check_witness_commitment: thin wrapper kept for backward-compatibility.
-- Callers that don't have a segwit-active flag always treat commitment as
-- expected (segwit-active=true).  New call-sites must use
-- check_witness_malleation directly to pass the activation flag.
-- @param block table: The full block
-- @return boolean: true if valid or no commitment needed
function M.check_witness_commitment(block)
  local ok, _err = M.check_witness_malleation(block, true)
  return ok
end

--------------------------------------------------------------------------------
-- Block Header Validation
--------------------------------------------------------------------------------

--- Check block header (timestamp and PoW).
-- @param header block_header: The block header
-- @param network table: Network configuration
-- @return boolean: true if valid
-- @param check_pow boolean|nil: when false, SKIP the proof-of-work assert.
--   Mirrors Bitcoin Core CheckBlockHeader(block, state, params, fCheckPOW)
--   (validation.cpp:3997): "if (fCheckPOW && !CheckProofOfWork(...))". Defaults
--   to true so every existing caller (no 3rd arg) is unchanged — the live
--   IBD / reorg / RPC paths all keep full PoW enforcement. fCheckPOW=false is
--   used ONLY by the differential reject-bar harness, which re-serializes a
--   real block after a structural mutation: the new header hash no longer meets
--   the network target, so the unconditional PoW gate would short-circuit on a
--   high-hash reject BEFORE the body gate under test runs (a dead-gate). This
--   exactly parallels Core's own use of fCheckPOW=false in ContextualCheckBlock
--   /TestBlockValidity-style paths where PoW was already established upstream.
function M.check_block_header(header, network, check_pow)
  network = network or consensus.networks.mainnet
  if check_pow == nil then check_pow = true end

  -- Check proof of work (Core fCheckPOW gate) and the wall-clock future-time
  -- gate, BOTH under the check_pow flag.
  --
  -- Faithfulness note (Core structure): in Bitcoin Core, CheckBlockHeader
  -- (validation.cpp:3828-3834) is context-free and checks ONLY proof of work;
  -- the "time-too-new" 2-hour future-time gate is a CONTEXTUAL check that lives
  -- in ContextualCheckBlockHeader (validation.cpp:4108-4110, chain.h:29) because
  -- it depends on wall-clock time (NodeClock::now()), not on block bytes alone.
  -- lunarblock enforces that contextual gate on the LIVE header-acceptance path
  -- in sync.lua:1101-1107 (alongside the time-too-old MTP gate), exactly where
  -- Core does. Keeping a second wall-clock copy in this context-free function is
  -- a divergence from Core's CheckBlock structure AND makes the function
  -- non-deterministic (a synthetic block re-validated by the differential
  -- reject-bar harness with a deliberately-high "final" timestamp would trip
  -- this gate and dead-gate every inner body check, e.g. BIP30). Gating it under
  -- check_pow keeps the LIVE default IDENTICAL — every production caller omits
  -- the flag, it defaults true, and the gate stays on (and is in any case
  -- already enforced contextually in sync.lua) — while the harness's
  -- check_pow=false makes the inner body gates LIVE, mirroring Core's own
  -- fCheckPOW=false usage in the TestBlockValidity / re-validation paths where
  -- the header's contextual preconditions were established upstream.
  if check_pow then
    local current_time = os.time()
    assert(header.timestamp <= current_time + consensus.MAX_FUTURE_BLOCK_TIME,
           "time-too-new")
    assert(M.check_proof_of_work(header, network), "proof of work failed")
  end

  return true
end

--------------------------------------------------------------------------------
-- BIP-34 Height Encoding
--------------------------------------------------------------------------------

--- Build the canonical BIP-34 byte encoding for a block height.
-- Mirrors Bitcoin Core's CScript() << nHeight (script.h:433-448):
--   height == 0  → "\x00"            (OP_0, single byte)
--   1..16        → "\x51".."\x60"    (OP_1..OP_16, single byte)
--   otherwise    → length-prefixed sign-magnitude CScriptNum
-- @param height number: Block height (non-negative integer)
-- @return string: Canonical byte string
function M.encode_bip34_height(height)
  if height == 0 then
    return "\x00"  -- OP_0
  end
  if height >= 1 and height <= 16 then
    return string.char(0x50 + height)  -- OP_1..OP_16
  end
  -- CScriptNum: minimal little-endian sign-magnitude with length prefix.
  local le = {}
  local h = height
  while h > 0 do
    le[#le + 1] = h % 256
    h = math.floor(h / 256)
  end
  -- If high bit of last byte is set, append zero sign byte.
  if le[#le] >= 0x80 then
    le[#le + 1] = 0x00
  end
  -- Prepend length byte.
  local bytes = { #le }
  for _, b in ipairs(le) do
    bytes[#bytes + 1] = b
  end
  return string.char(unpack(bytes))
end

--------------------------------------------------------------------------------
-- Full Block Validation
--------------------------------------------------------------------------------

--- Check full block (context-free).
-- @param block block: The full block
-- @param network table: Network configuration
-- @param height number: Block height (optional, for BIP34 check)
-- @return boolean: true if valid
-- @param check_pow boolean|nil: forwarded to check_block_header. Defaults to
--   true (every existing positional caller passes (block, network, height) and
--   is unchanged). See check_block_header for the fCheckPOW rationale — the
--   differential reject-bar harness passes false so a structurally-mutated real
--   block reaches the body gates (merkle / sigops / weight / coinbase) instead
--   of being rejected on a high-hash header. Core: CheckBlock(block, state,
--   params, fCheckPOW, fCheckMerkleRoot) validation.cpp:4017.
function M.check_block(block, network, height, check_pow)
  network = network or consensus.networks.mainnet
  if check_pow == nil then check_pow = true end

  -- Check header
  M.check_block_header(block.header, network, check_pow)

  -- Contextual block-version floor (Core ContextualCheckBlockHeader,
  -- validation.cpp:4112-4118 "bad-version"). Reject outdated block versions
  -- once the corresponding soft fork has buried-activated, height-gated on the
  -- block's OWN height:
  --   nVersion < 2  after BIP34 (HEIGHTINCB) activation
  --   nVersion < 3  after BIP66 (DERSIG)     activation
  --   nVersion < 4  after BIP65 (CLTV)       activation
  -- Core gates each arm on DeploymentActiveAfter(pindexPrev, ...), which for a
  -- buried deployment is (pindexPrev->nHeight + 1) >= DeploymentHeight, i.e. the
  -- block's own height >= activation_height (deploymentstatus.h:17) — INCLUDING
  -- the activation height itself. This mirrors sync.lua:1283-1297 (the
  -- header-first/P2P accept_header path) so the submitblock RPC path (which
  -- routes through check_block but bypasses accept_header) enforces the SAME
  -- floor as P2P + Core. Only fires when a height is supplied (context-free
  -- callers, e.g. the side-branch stage-1 pre-check that passes nil, defer this
  -- to the height-aware connect/accept path just as the BIP-34 arm below does).
  if height ~= nil then
    if block.header.version < 2
      and network.bip34_height ~= nil
      and height >= network.bip34_height then
      error(string.format("bad-version(0x%08x)", block.header.version))
    end
    if block.header.version < 3
      and network.bip66_height ~= nil
      and height >= network.bip66_height then
      error(string.format("bad-version(0x%08x)", block.header.version))
    end
    if block.header.version < 4
      and network.bip65_height ~= nil
      and height >= network.bip65_height then
      error(string.format("bad-version(0x%08x)", block.header.version))
    end
  end

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

    -- Weight: base_size * 3 + total_size (per-transaction contribution only)
    total_weight = total_weight + #base_data * 3 + #total_data

    -- Legacy sigops
    for _, inp in ipairs(tx.inputs) do
      total_sigops = total_sigops + M.count_script_sigops(inp.script_sig, false)
    end
    for _, out in ipairs(tx.outputs) do
      total_sigops = total_sigops + M.count_script_sigops(out.script_pubkey, false)
    end
  end
  -- Core GetBlockWeight (consensus/validation.h:136) serializes the WHOLE block,
  -- which includes the 80-byte block header and the tx-count CompactSize varint.
  -- The per-tx loop above accumulates only the per-transaction weights. Add the
  -- missing overhead for header + varint so our weight matches Core exactly:
  --   missing = (80 + varint_len(nTx)) * WITNESS_SCALE_FACTOR
  -- Both stripped and full block serializations include header+varint identically,
  -- so the weight contribution is header_bytes * WITNESS_SCALE_FACTOR (not *3+1).
  -- Mirrors rest.lua:462 full-block formula: stripped_size*3 + block_size where
  -- stripped_size already includes header + varint.
  do
    local nTx = #block.transactions
    local varint_bytes
    if nTx < 0xFD then
      varint_bytes = 1
    elseif nTx <= 0xFFFF then
      varint_bytes = 3
    elseif nTx <= 0xFFFFFFFF then
      varint_bytes = 5
    else
      varint_bytes = 9
    end
    total_weight = total_weight + (80 + varint_bytes) * consensus.WITNESS_SCALE_FACTOR
  end
  assert(total_weight <= consensus.MAX_BLOCK_WEIGHT,
         "block weight " .. total_weight .. " exceeds maximum " .. consensus.MAX_BLOCK_WEIGHT)
  assert(total_sigops * consensus.WITNESS_SCALE_FACTOR <= consensus.MAX_BLOCK_SIGOPS_COST,
         "sigops cost " .. (total_sigops * consensus.WITNESS_SCALE_FACTOR) ..
         " exceeds maximum " .. consensus.MAX_BLOCK_SIGOPS_COST)

  -- Verify merkle root (+ CVE-2012-2459 duplicate-tx malleation, Core
  -- CheckMerkleRoot validation.cpp:3837-3862). check_merkle_root returns
  -- false + the Core reject reason (bad-txnmrklroot / bad-txns-duplicate).
  local merkle_ok, merkle_err = M.check_merkle_root(block)
  assert(merkle_ok, merkle_err or "merkle root mismatch")

  -- Verify witness commitment / malleation (BIP-141, ContextualCheckBlock).
  -- Segwit is active when height >= network.segwit_height.
  -- Bug 1 fix: was always called with implicit segwit_active=true; now
  -- respects the deployment activation height so pre-segwit blocks are
  -- not incorrectly rejected for lacking a witness commitment.
  -- Core: ContextualCheckBlock calls CheckWitnessMalleation with
  --   DeploymentActiveAfter(pindexPrev, DEPLOYMENT_SEGWIT).
  local segwit_active = height ~= nil and network.segwit_height ~= nil and
                        height >= network.segwit_height
  local wit_ok, wit_err = M.check_witness_malleation(block, segwit_active)
  assert(wit_ok, wit_err or "witness commitment mismatch")

  -- BIP34: coinbase scriptSig must start with the byte-exact canonical
  -- encoding of the block height.
  -- Bitcoin Core validation.cpp:4151-4159:
  --   CScript expect = CScript() << nHeight;
  --   sig.size() >= expect.size() && equal(expect, sig[:expect.size()])
  -- Error code: "bad-cb-height" (Core BlockValidationResult::BLOCK_CONSENSUS).
  -- Bug fix (W79): previous assert messages used "BIP34:" / "BIP34 height mismatch"
  -- (uppercase prefix), which were NOT matched by rpc.lua's lowercase "bip34"
  -- pattern — BIP34 violations were silently mapped to "block-script-verify-flag-
  -- failed" (first assert, caught by s:find("script")) or "rejected" (second
  -- assert).  Now both asserts embed "bad-cb-height" so the canonical-set check
  -- in classify_block_rejection() catches them immediately, matching Core's
  -- state.Invalid(BLOCK_CONSENSUS, "bad-cb-height", ...) wire code.
  if height and height >= network.bip34_height then
    local coinbase_sig = block.transactions[1].inputs[1].script_sig
    local expect = M.encode_bip34_height(height)
    local n = #expect
    if #coinbase_sig < n then
      error("bad-cb-height: coinbase scriptSig too short for height " .. height ..
            " (need " .. n .. " bytes, got " .. #coinbase_sig .. ")")
    end
    for i = 1, n do
      if coinbase_sig:byte(i) ~= expect:byte(i) then
        error("bad-cb-height: height mismatch at byte " .. i ..
              " (expected " .. string.format("0x%02x", expect:byte(i)) ..
              " got " .. string.format("0x%02x", coinbase_sig:byte(i)) ..
              ") at block height " .. height)
      end
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
-- @param snapshot_base_height number|nil: assumeUTXO snapshot base height, or
--        nil for a genesis-synced / production node.  See the BIP68 time-lock
--        relaxation note below.
-- @return number, number: min_height (last invalid), min_time (last invalid)
function M.calculate_sequence_locks(tx, height, get_utxo_height, get_block_mtp, enforce_bip68, snapshot_base_height)
  -- Initialize to -1: "last invalid" semantics means -1 allows any height/time
  local min_height = -1
  local min_time = -1

  -- BIP68 only applies to version >= 2 transactions when active.
  -- Core stores nVersion as uint32_t and compares it UNSIGNED
  -- (tx_verify.cpp:51 fEnforceBIP68 = tx.version >= 2), so a high-bit
  -- version (e.g. 0xFFFFFFFF, read here signed as -1 via read_i32le) STILL
  -- enforces BIP68. Reinterpret as unsigned 32-bit (% 2^32) before comparing,
  -- matching the connect-block gate bip68_version_active (utxo.lua:29-30).
  -- A signed `tx.version < 2` check would treat 0xFFFFFFFF as -1 (< 2) and
  -- SKIP enforcement, false-accepting a non-final tx (a chain split).
  if (tx.version % 4294967296) < 2 or not enforce_bip68 then
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
        -- Core (tx_verify.cpp:74) uses GetMedianTimePast of the block PRIOR to
        -- the coin's height, i.e. the 11-block MTP window ending at
        -- (coin_height-1) → heights [coin_height-11 .. coin_height-1].
        --
        -- SNAPSHOT-BOOTSTRAP RELAXATION: an assumeUTXO-bootstrapped node only
        -- has block headers from the snapshot base forward; the (up to 10)
        -- pre-base headers are absent by design.  For a coin created within the
        -- first 10 blocks above the base, that MTP window is *truncated* — the
        -- median is computed over fewer than 11 timestamps and is biased
        -- upward (the oldest/smallest timestamps are missing), yielding a
        -- min_time that is seconds-too-high and a FALSE BIP68 time-lock reject
        -- (observed: tx 3f0cdb03… at h948465, coin@944193, base 944183 →
        -- window dipped to 944182 which is below the base → min_time 41s high →
        -- 17s over the block MTP → false reject of a block Core accepts).
        --
        -- These snapshot-frontier coins sit at/just above the assumeUTXO base,
        -- which is below nMinimumChainWork and is effectively assumevalid, so
        -- their exact relative TIME lock is not recomputable from the
        -- forward-synced header set.  Treat such an input's time-lock as
        -- trivially satisfied (skip it).  This is gated strictly on
        -- snapshot_base_height being set AND the coin being inside the
        -- truncation zone, so genesis-synced and production nodes (where the
        -- full pre-coin header window is present) are unaffected, and only the
        -- relative-TIME lock is relaxed — the relative-HEIGHT lock below is
        -- always computed exactly from the snapshot-preserved coin height.
        --
        -- Truncation zone: window underflows the base iff
        --   (coin_height-1) - (MEDIAN_TIME_PAST_BLOCKS-1) < snapshot_base_height
        --   ⇔ coin_height <= snapshot_base_height + (MEDIAN_TIME_PAST_BLOCKS-1)
        local truncated = snapshot_base_height
          and coin_height <= snapshot_base_height + (consensus.MEDIAN_TIME_PAST_BLOCKS - 1)
        if not truncated then
          -- Get MTP of the block BEFORE the one containing the UTXO
          local coin_time = get_block_mtp(math.max(coin_height - 1, 0))
          -- Lock value in 512-second units, convert to seconds, apply "last invalid" adjustment
          local lock_value = bit.band(seq, consensus.SEQUENCE_LOCKTIME_MASK)
          local lock_seconds = bit.lshift(lock_value, consensus.SEQUENCE_LOCKTIME_GRANULARITY)
          min_time = math.max(min_time, coin_time + lock_seconds - 1)
        end
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
function M.make_sig_checker(tx, input_index, prev_output_value, prev_script_pubkey, flags, prev_outputs)
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

  -- LEGACY/SegWit-v0 OP_CODESEPARATOR sighash truncation.
  -- pbegincodehash (interpreter.cpp:422,1054): the 1-based BYTE offset of the
  -- byte right after the most-recently-EXECUTED OP_CODESEPARATOR within the
  -- currently-executing script. nil = no codesep executed yet (full
  -- scriptCode). The interpreter's execute_script resets this to nil on
  -- entry (Core resets pbegincodehash to script.begin() per EvalScript) and
  -- updates it via set_codesep when a codesep runs. check_sig slices its
  -- scriptCode at this offset for both BASE (then FindAndDelete +
  -- remove-codeseparators) and WITNESS_V0 (slice only) — see interpreter.cpp
  -- EvalChecksigPreTapscript line 326 `CScript scriptCode(pbegincodehash, pend)`.
  local codesep_byte_offset = nil
  -- The script CURRENTLY being evaluated (scriptSig, scriptPubKey, or P2SH
  -- redeem script). Core's legacy scriptCode is CScript(pbegincodehash, pend)
  -- over THIS script (interpreter.cpp:326,420-422), NOT the prevout
  -- scriptPubKey. Set by the interpreter at each execute_script entry.
  local current_script = nil

  --- Record codeseparator state. First arg is the 0-based opcode index
  -- (unused by the legacy/segwit ECDSA path; kept for API symmetry with the
  -- tapscript checker). Second arg is the 1-based byte offset of
  -- pbegincodehash within the executing script; nil resets to full scriptCode.
  -- Third arg is the currently-executing script bytes.
  function checker.set_codesep(opcode_idx, byte_offset, exec_script)
    codesep_byte_offset = byte_offset
    current_script = exec_script
  end

  -- Slice a scriptCode at the recorded pbegincodehash byte offset (Core
  -- CScript(pbegincodehash, pend)). When no codesep has executed the full
  -- script is returned unchanged.
  local function apply_codesep(sc)
    if codesep_byte_offset and codesep_byte_offset > 1 then
      return sc:sub(codesep_byte_offset)
    end
    return sc
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
  -- @param all_sigs table|nil: For OP_CHECKMULTISIG, the full list of
  --   signatures to FindAndDelete from the legacy scriptCode (Core builds one
  --   scriptCode with ALL sigs removed and reuses it for every key — see
  --   interpreter.cpp:1142-1167). nil for single OP_CHECKSIG.
  -- @return boolean: true if valid
  function checker.check_sig(sig, pubkey, all_sigs)
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
      -- Legacy: Core's scriptCode is the script CURRENTLY being evaluated
      -- (interpreter.cpp:326,420-422), not the prevout scriptPubKey. This
      -- matters when a CHECKSIG runs inside the scriptSig or a P2SH redeem
      -- script — the FindAndDelete + codeseparator handling must operate on
      -- THAT script. Fall back to flags.script_code / prev_script_pubkey only
      -- when the interpreter did not record the executing script.
      script_code = current_script or flags.script_code or prev_script_pubkey
    end

    -- OP_CODESEPARATOR truncation: scriptCode = bytes from pbegincodehash to
    -- end of the executing script (interpreter.cpp:326). Applies to BOTH the
    -- legacy and segwit-v0 sighash. For legacy the truncated subscript then
    -- goes through FindAndDelete + remove-codeseparators inside
    -- signature_hash_legacy; for segwit-v0 BIP143 the truncation is the only
    -- codesep transform (no FindAndDelete, codeseparators NOT stripped).
    script_code = apply_codesep(script_code)

    -- Compute sighash
    local sighash
    if is_segwit then
      -- SegWit does NOT use FindAndDelete
      sighash = M.signature_hash_segwit_v0(tx, input_index, script_code, prev_output_value, hash_type)
    elseif all_sigs then
      -- OP_CHECKMULTISIG (legacy): FindAndDelete EVERY signature from the
      -- scriptCode up front, then build the sighash without a further
      -- per-sig FindAndDelete (sig_bytes=nil), matching Core's single shared
      -- scriptCode.
      for _, s in ipairs(all_sigs) do
        if s and #s > 0 then
          script_code = M.find_and_delete(script_code, s)
        end
      end
      sighash = M.signature_hash_legacy(tx, input_index, script_code, hash_type, nil)
    else
      -- Legacy single CHECKSIG: pass the signature for FindAndDelete.
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

  --- BIP-341 Taproot key-path Schnorr verify.
  -- Returns true iff `sig` is a valid BIP-340 Schnorr signature by
  -- `witness_program` (the 32-byte x-only output key) over the BIP-341
  -- key-path (ext_flag=0) sighash of this transaction.
  -- @param witness_program string: 32-byte x-only output key
  -- @param sig string: 64- or 65-byte Schnorr signature (65 = sig||hash_type)
  -- @param annex string|nil: BIP-341 annex including the 0x50 prefix
  -- @return boolean: true if signature verifies, false otherwise
  function checker.check_schnorr_keypath(witness_program, sig, annex)
    if not prev_outputs then return false end
    if #sig ~= 64 and #sig ~= 65 then return false end

    local hash_type = 0x00
    local sig_bytes = sig
    if #sig == 65 then
      hash_type = string.byte(sig, 65)
      sig_bytes = string.sub(sig, 1, 64)
      -- BIP-341: explicit SIGHASH_DEFAULT byte is invalid in 65-byte form
      if hash_type == 0x00 then return false end
      -- BIP-341 hash_type range gate (Core interpreter.cpp:1516).
      if not M.is_valid_taproot_hash_type(hash_type) then return false end
    end

    local sighash = M.signature_hash_taproot(
      tx, input_index, hash_type, prev_outputs, 0, annex)
    -- Core CheckSchnorrSignature line 1737-1738: if SignatureHashSchnorr
    -- returns false, set SCRIPT_ERR_SCHNORR_SIG_HASHTYPE and fail. We
    -- mirror by returning false (the surrounding tapscript dispatcher
    -- raises SIG_SCHNORR). Pre-W95 lunarblock silently fed a 32-zero
    -- sighash to schnorr_verify here on the SIGHASH_SINGLE-out-of-range
    -- path — split surface fixed.
    if not sighash then return false end
    return crypto.schnorr_verify(witness_program, sig_bytes, sighash)
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
    -- BIP68/BIP112: Core treats CTransaction::version as uint32_t
    -- (interpreter.cpp CheckSequence: `if (txTo->version < 2)`), so the
    -- comparison is UNSIGNED. serialize.read_i32le returns a SIGNED value,
    -- so a high-bit-set version (e.g. 0xffffffff -> -1) must NOT be treated
    -- as < 2. Only a small non-negative version (0 or 1) fails the gate.
    if tx.version >= 0 and tx.version < 2 then
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
      -- BIP-341 hash_type range gate (Core interpreter.cpp:1516).
      if not M.is_valid_taproot_hash_type(hash_type) then
        return false
      end
    end

    -- Compute taproot sighash for script-path (ext_flag = 1)
    local sighash = M.signature_hash_taproot(
      tx, input_index, hash_type, prev_outputs,
      1, annex, tapleaf_hash, codesep_pos
    )
    -- Same Core parity as keypath: SIGHASH_SINGLE-OOR or bad hash_type
    -- returns nil; we surface false here so the tapscript opcode
    -- dispatcher (script.lua OP_CHECKSIG{,VERIFY,ADD}) can raise
    -- SIG_SCHNORR / CHECKSIGVERIFY instead of crashing on the nil
    -- argument inside libsecp256k1's schnorrsig_verify.
    if not sighash then return false end

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
    -- BIP68/BIP112: Core treats CTransaction::version as uint32_t
    -- (interpreter.cpp CheckSequence: `if (txTo->version < 2)`), so the
    -- comparison is UNSIGNED. serialize.read_i32le returns a SIGNED value,
    -- so a high-bit-set version (e.g. 0xffffffff -> -1) must NOT be treated
    -- as < 2. Only a small non-negative version (0 or 1) fails the gate.
    if tx.version >= 0 and tx.version < 2 then
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
-- CHECKMULTISIG inline-verify mode (2026-05-02 fix): If `inline_verify` is
-- truthy, check_sig performs ECDSA verification inline and returns the real
-- result — bypassing the collector. This is required for OP_CHECKMULTISIG /
-- OP_CHECKMULTISIGVERIFY whose `m`-of-`n` trial-and-error pairing in
-- script.lua advances `isig`/`ikey` based on the boolean returned by
-- check_sig. With deferred-collect (always-true return) the trial loop
-- silently advances on FAILED pairs and the batch pass at the end then
-- rejects the wrong (sig, pubkey) tuples — observed at h=944,184. Callers
-- in connect_block scan the relevant scripts (script.has_multisig_op +
-- extract_last_push for P2SH redeem) and set inline_verify=true when any
-- multisig opcode is reachable. Other scripts (single-sig P2WPKH/P2PKH,
-- P2TR keypath) keep the parallel speedup.
--
-- @param tx transaction: The transaction being verified
-- @param input_index number: 0-based input index
-- @param prev_output_value number: Satoshi value of the prev output
-- @param prev_script_pubkey string: scriptPubKey of the prev output
-- @param flags table: Script verification flags
-- @param collector table: Array to append {pubkey, sig_der, sighash} to
-- @param prev_outputs table|nil: Per-input prev_outputs for taproot key-path
-- @param inline_verify boolean|nil: If true, verify ECDSA inline (CHECKMULTISIG)
-- @return table: Checker compatible with make_sig_checker interface
function M.make_collecting_sig_checker(tx, input_index, prev_output_value, prev_script_pubkey, flags, collector, prev_outputs, inline_verify)
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

  -- LEGACY/SegWit-v0 OP_CODESEPARATOR sighash truncation (see the same
  -- machinery documented in make_sig_checker). Required on the block-connect
  -- path too, or a CODESEPARATOR-bearing script (legacy or P2WSH) computes
  -- the wrong sighash during block validation.
  local codesep_byte_offset = nil
  local current_script = nil
  function checker.set_codesep(opcode_idx, byte_offset, exec_script)
    codesep_byte_offset = byte_offset
    current_script = exec_script
  end
  local function apply_codesep(sc)
    if codesep_byte_offset and codesep_byte_offset > 1 then
      return sc:sub(codesep_byte_offset)
    end
    return sc
  end

  function checker.get_witness()
    local inp = tx.inputs[input_index + 1]
    if inp and inp.witness then
      return inp.witness
    end
    return {}
  end

  --- ECDSA check: in deferred mode, compute sighash and push (pubkey, sig_der,
  -- sighash) to the collector for batch verification at end-of-block.  In
  -- inline mode (CHECKMULTISIG-bearing scripts) verify immediately and
  -- return the real result so OP_CHECKMULTISIG's trial pairing works.
  function checker.check_sig(sig, pubkey, all_sigs)
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
      -- Legacy: scriptCode is the script currently being evaluated (Core
      -- interpreter.cpp:326,420-422), not the prevout scriptPubKey.
      script_code = current_script or flags.script_code or prev_script_pubkey
    end

    -- OP_CODESEPARATOR truncation (scriptCode = pbegincodehash..end).
    script_code = apply_codesep(script_code)

    -- Compute sighash now (order-dependent — must run here in script execution)
    local sighash
    if is_segwit then
      sighash = M.signature_hash_segwit_v0(tx, input_index, script_code, prev_output_value, hash_type)
    elseif all_sigs then
      -- OP_CHECKMULTISIG (legacy): FindAndDelete every signature up front
      -- (Core interpreter.cpp:1142-1167), then hash without per-sig FAD.
      for _, s in ipairs(all_sigs) do
        if s and #s > 0 then
          script_code = M.find_and_delete(script_code, s)
        end
      end
      sighash = M.signature_hash_legacy(tx, input_index, script_code, hash_type, nil)
    else
      sighash = M.signature_hash_legacy(tx, input_index, script_code, hash_type, sig)
    end

    if inline_verify then
      -- Inline ECDSA: required for OP_CHECKMULTISIG correctness. The
      -- trial-and-error pairing loop in script.lua's CHECKMULTISIG handler
      -- depends on the *real* verify result.
      if flags.verify_dersig or flags.verify_strictenc or flags.verify_low_s then
        return crypto.ecdsa_verify(pubkey, sig_der, sighash)
      else
        return crypto.ecdsa_verify_lax(pubkey, sig_der, sighash)
      end
    end

    -- Push to collector for deferred parallel ECDSA verification
    collector[#collector + 1] = { pubkey = pubkey, sig_der = sig_der, sighash = sighash }

    -- Return true optimistically; batch verify will catch failures
    return true
  end

  --- BIP-341 Taproot key-path Schnorr verify (immediate; not batched).
  -- Same semantics as make_sig_checker.check_schnorr_keypath. Schnorr
  -- verification is not deferred to the batch pass — only ECDSA is.
  function checker.check_schnorr_keypath(witness_program, sig, annex)
    if not prev_outputs then return false end
    if #sig ~= 64 and #sig ~= 65 then return false end

    local hash_type = 0x00
    local sig_bytes = sig
    if #sig == 65 then
      hash_type = string.byte(sig, 65)
      sig_bytes = string.sub(sig, 1, 64)
      if hash_type == 0x00 then return false end
      -- BIP-341 hash_type range gate (Core interpreter.cpp:1516).
      if not M.is_valid_taproot_hash_type(hash_type) then return false end
    end

    local sighash = M.signature_hash_taproot(
      tx, input_index, hash_type, prev_outputs, 0, annex)
    -- Core parity (see make_sig_checker.check_schnorr_keypath above):
    -- nil sighash means SIGHASH_SINGLE-OOR or bad hash_type; surface as
    -- verify failure so the dispatcher fails the script.
    if not sighash then return false end
    return crypto.schnorr_verify(witness_program, sig_bytes, sighash)
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
    -- Unsigned version comparison (see make_sig_checker.check_sequence):
    -- Core's CheckSequence uses uint32_t version; a high-bit-set version is
    -- never < 2. read_i32le is signed, so guard with `>= 0`.
    if tx.version >= 0 and tx.version < 2 then return false end
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
