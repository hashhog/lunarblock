local bit = require("bit")
local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local crypto = require("lunarblock.crypto")
local script = require("lunarblock.script")
local consensus = require("lunarblock.consensus")
local M = {}

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

  -- Check serialized size
  local tx_data = serialize.serialize_transaction(tx, false)
  assert(#tx_data >= consensus.MIN_TX_SIZE,
         "transaction size " .. #tx_data .. " below minimum " .. consensus.MIN_TX_SIZE)

  -- Check for duplicate inputs
  local seen_outpoints = {}
  for _, inp in ipairs(tx.inputs) do
    local w = serialize.buffer_writer()
    w.write_u32le(inp.prev_out.index)
    local key = inp.prev_out.hash.bytes .. w.result()
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
-- @param tx transaction: The transaction
-- @return hash256: The txid
function M.compute_txid(tx)
  local data = serialize.serialize_transaction(tx, false)
  return crypto.hash256_type(data)
end

--- Compute wtxid (double-SHA256 of witness serialization).
-- For non-segwit transactions, wtxid == txid.
-- @param tx transaction: The transaction
-- @return hash256: The wtxid
function M.compute_wtxid(tx)
  local data = serialize.serialize_transaction(tx, true)
  return crypto.hash256_type(data)
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
  local ops = script.parse_script(script_bytes)
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

--- Remove all OP_CODESEPARATOR (0xab) bytes from a script.
-- Used in legacy sighash computation.
-- @param script_bytes string: The script bytes
-- @return string: Script with OP_CODESEPARATOR removed
function M.remove_codeseparators(script_bytes)
  return (script_bytes:gsub("\171", ""))  -- 0xab = 171 decimal
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

  -- First transaction must be coinbase
  local _, is_coinbase = M.check_transaction(block.transactions[1])
  assert(is_coinbase, "first transaction is not coinbase")

  -- Rest must not be coinbase
  for i = 2, #block.transactions do
    local _, is_cb = M.check_transaction(block.transactions[i])
    assert(not is_cb, "transaction " .. i .. " is coinbase")
  end

  -- Compute total block weight
  local total_weight = 0
  for _, tx in ipairs(block.transactions) do
    total_weight = total_weight + M.get_tx_weight(tx)
  end
  assert(total_weight <= consensus.MAX_BLOCK_WEIGHT,
         "block weight " .. total_weight .. " exceeds maximum " .. consensus.MAX_BLOCK_WEIGHT)

  -- Count legacy sigops (scriptSig + scriptPubKey, non-accurate counting)
  local total_sigops = 0
  for _, tx in ipairs(block.transactions) do
    for _, inp in ipairs(tx.inputs) do
      total_sigops = total_sigops + M.count_script_sigops(inp.script_sig, false)
    end
    for _, out in ipairs(tx.outputs) do
      total_sigops = total_sigops + M.count_script_sigops(out.script_pubkey, false)
    end
  end
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
      -- First byte tells us how many bytes for the height
      local height_len = coinbase_sig:byte(1)
      if height_len >= 1 and height_len <= 4 and #coinbase_sig >= height_len + 1 then
        -- Read height as little-endian
        local encoded_height = 0
        for i = 1, height_len do
          encoded_height = encoded_height + coinbase_sig:byte(i + 1) * (256 ^ (i - 1))
        end
        assert(encoded_height == height,
               "BIP34 height mismatch: expected " .. height .. ", got " .. encoded_height)
      else
        error("invalid BIP34 height encoding")
      end
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

  -- Check difficulty target
  if not network.pow_no_retarget then
    -- Check if this is a retarget block
    if height % consensus.DIFFICULTY_ADJUSTMENT_INTERVAL == 0 then
      -- This is a retarget block - we need the difficulty to be recalculated
      -- The actual target calculation requires looking back 2016 blocks
      -- For now, just verify the bits field is reasonable
      assert(header.bits > 0, "invalid difficulty bits")
    else
      -- Non-retarget block: bits should match previous block
      -- (unless we allow minimum difficulty on testnet)
      if network.pow_allow_min_difficulty then
        -- Testnet special rules: if block took > 20 minutes, allow minimum difficulty
        local time_diff = header.timestamp - prev_header.timestamp
        if time_diff > 20 * 60 then
          -- Allow minimum difficulty (pow_limit_bits)
          assert(header.bits == network.pow_limit_bits or header.bits == prev_header.bits,
                 "invalid difficulty for slow testnet block")
        else
          assert(header.bits == prev_header.bits,
                 "non-retarget block has different bits")
        end
      else
        assert(header.bits == prev_header.bits,
               "non-retarget block has different bits")
      end
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
      -- For P2WPKH, construct synthetic P2PKH script from witness program
      local script_type, hash = script.classify_script(prev_script_pubkey)
      if script_type == "p2wpkh" then
        -- Synthetic P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        script_code = script.make_p2pkh_script(hash)
      else
        -- P2WSH or other: use the witness script (passed via flags)
        script_code = flags.witness_script or prev_script_pubkey
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
    return crypto.ecdsa_verify(pubkey, sig_der, sighash)
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

return M
