local bit = require("bit")
local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local crypto = require("lunarblock.crypto")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local M = {}

-- Constants
local LOCKTIME_THRESHOLD = consensus.LOCKTIME_THRESHOLD  -- 500,000,000
local SEQUENCE_FINAL = 0xFFFFFFFF

--------------------------------------------------------------------------------
-- Transaction Finality (Locktime Check)
--------------------------------------------------------------------------------

--- Check if a transaction is final for inclusion in a block.
-- A transaction is final if:
-- 1. nLockTime == 0, OR
-- 2. nLockTime < threshold (height for height-based, time for time-based), OR
-- 3. All inputs have nSequence == 0xFFFFFFFF (SEQUENCE_FINAL)
-- @param tx transaction: The transaction to check
-- @param height number: Block height for height-based locktime
-- @param mtp number: Median time past for time-based locktime
-- @return boolean: true if transaction is final
function M.is_final_tx(tx, height, mtp)
  -- nLockTime == 0 means always final
  if tx.locktime == 0 then
    return true
  end

  -- Determine if locktime is height-based or time-based
  local lock_threshold
  if tx.locktime < LOCKTIME_THRESHOLD then
    -- Height-based: compare against block height
    lock_threshold = height
  else
    -- Time-based: compare against median time past
    lock_threshold = mtp
  end

  -- If locktime is satisfied (less than threshold), tx is final
  if tx.locktime < lock_threshold then
    return true
  end

  -- Otherwise, tx is final only if all inputs have SEQUENCE_FINAL
  for _, inp in ipairs(tx.inputs) do
    if inp.sequence ~= SEQUENCE_FINAL then
      return false
    end
  end

  return true
end

--- Apply anti-fee-sniping to a wallet transaction.
-- Sets nLockTime to current height and ensures inputs have non-final sequence.
-- This prevents miners from building longer hidden chains with wallet transactions.
-- @param tx transaction: The transaction to modify
-- @param current_height number: Current blockchain height
function M.apply_anti_fee_sniping(tx, current_height)
  -- Set locktime to current height
  tx.locktime = current_height

  -- Ensure at least one input has non-final sequence so locktime is enforced
  -- Use 0xFFFFFFFE (MAX_SEQUENCE_NONFINAL) for compatibility with BIP125 RBF
  for _, inp in ipairs(tx.inputs) do
    if inp.sequence == SEQUENCE_FINAL then
      inp.sequence = SEQUENCE_FINAL - 1  -- 0xFFFFFFFE
    end
  end
end

--------------------------------------------------------------------------------
-- Hex Encoding Helpers
--------------------------------------------------------------------------------

--- Encode binary data to hexadecimal string.
-- @param data string: Binary data
-- @return string: Hex-encoded string
function M.hex_encode(data)
  local hex = {}
  for i = 1, #data do
    hex[i] = string.format("%02x", data:byte(i))
  end
  return table.concat(hex)
end

--- Decode hexadecimal string to binary data.
-- @param hex string: Hex-encoded string
-- @return string: Binary data
function M.hex_decode(hex)
  local bytes = {}
  for i = 1, #hex, 2 do
    bytes[#bytes + 1] = string.char(tonumber(hex:sub(i, i + 1), 16))
  end
  return table.concat(bytes)
end

--------------------------------------------------------------------------------
-- Coinbase Transaction Creation
--------------------------------------------------------------------------------

--- Create a coinbase transaction.
-- @param height number: Block height (for BIP34 encoding)
-- @param value number: Total coinbase value (subsidy + fees) in satoshis
-- @param coinbase_script_extra string: Extra data to include in coinbase scriptSig (optional)
-- @param witness_commitment string: 32-byte witness commitment hash (optional)
-- @param payout_script string: Script pubkey for block reward payout
-- @return transaction: The coinbase transaction
function M.create_coinbase_tx(height, value, coinbase_script_extra, witness_commitment, payout_script)
  -- Build the coinbase scriptSig: height (BIP34) + extra data
  local w = serialize.buffer_writer()

  -- Encode height as minimal push (BIP34)
  if height == 0 then
    w.write_u8(1)
    w.write_u8(0)
  else
    local h_bytes = {}
    local h = height
    while h > 0 do
      h_bytes[#h_bytes + 1] = h % 256
      h = math.floor(h / 256)
    end
    w.write_u8(#h_bytes)
    for _, b in ipairs(h_bytes) do
      w.write_u8(b)
    end
  end

  if coinbase_script_extra then
    w.write_bytes(coinbase_script_extra)
  end
  local coinbase_script_sig = w.result()

  -- Build the transaction
  local inputs = {
    types.txin(
      types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
      coinbase_script_sig,
      0xFFFFFFFF
    )
  }

  local outputs = {}
  -- Main payout output
  outputs[1] = types.txout(value, payout_script)

  -- Witness commitment output (if provided)
  if witness_commitment then
    local commitment_script = "\x6a\x24\xaa\x21\xa9\xed" .. witness_commitment
    outputs[#outputs + 1] = types.txout(0, commitment_script)
  end

  local tx = types.transaction(2, inputs, outputs, 0)

  -- Add witness nonce for segwit
  if witness_commitment then
    tx.segwit = true
    tx.inputs[1].witness = {string.rep("\0", 32)}
  end

  return tx
end

--------------------------------------------------------------------------------
-- Block Template Construction
--------------------------------------------------------------------------------

--- Create a block template for mining.
-- @param mempool table: The mempool object
-- @param chain_state table: Chain state with tip_height, tip_hash, storage
-- @param network table: Network configuration (mainnet, testnet, regtest)
-- @param payout_script string: Script pubkey for block reward
-- @param config table: Optional configuration (max_weight, max_sigops)
-- @return table, block: BIP22 template and block object
function M.create_block_template(mempool, chain_state, network, payout_script, config)
  config = config or {}
  local max_weight = config.max_weight or consensus.MAX_BLOCK_WEIGHT
  local max_sigops = config.max_sigops or consensus.MAX_BLOCK_SIGOPS_COST

  local height = chain_state.tip_height + 1
  local prev_hash = chain_state.tip_hash
  local subsidy = consensus.get_block_subsidy(height)

  -- Get median time past for locktime checks
  -- chain_state.mtp should be provided; fallback to current time - 3600 (1 hour ago)
  local mtp = chain_state.mtp or (os.time() - 3600)

  -- Select transactions from mempool ordered by ancestor fee rate
  local sorted_entries = mempool:get_sorted_entries()
  local selected = {}
  local selected_set = {}     -- txid_hex -> true
  local total_fees = 0
  local total_sigops = 0

  -- Reserve space for coinbase (estimated ~1000 weight units)
  local coinbase_weight_estimate = 1000
  local total_weight = coinbase_weight_estimate

  for _, entry in ipairs(sorted_entries) do
    local txid_hex = types.hash256_hex(entry.txid)

    -- Skip if already selected
    if selected_set[txid_hex] then goto continue end

    -- Skip transactions that are not final (locktime not satisfied)
    if not M.is_final_tx(entry.tx, height, mtp) then goto continue end

    -- Check weight limit
    if total_weight + entry.weight > max_weight then goto continue end

    -- Check sigops limit
    local tx_sigops = 0
    for _, inp in ipairs(entry.tx.inputs) do
      tx_sigops = tx_sigops + validation.count_script_sigops(inp.script_sig, true) * consensus.WITNESS_SCALE_FACTOR
    end
    for _, out in ipairs(entry.tx.outputs) do
      tx_sigops = tx_sigops + validation.count_script_sigops(out.script_pubkey, true) * consensus.WITNESS_SCALE_FACTOR
    end
    if total_sigops + tx_sigops > max_sigops then goto continue end

    -- Ensure all ancestors are already selected
    local ancestors_ok = true
    for _, inp in ipairs(entry.tx.inputs) do
      local prev_hex = types.hash256_hex(inp.prev_out.hash)
      if mempool:has(prev_hex) and not selected_set[prev_hex] then
        ancestors_ok = false
        break
      end
    end
    if not ancestors_ok then goto continue end

    -- Add to block
    selected[#selected + 1] = entry
    selected_set[txid_hex] = true
    total_fees = total_fees + entry.fee
    total_weight = total_weight + entry.weight
    total_sigops = total_sigops + tx_sigops

    ::continue::
  end

  -- Build the transaction list (coinbase first)
  local transactions = {}

  -- Compute witness commitment
  local witness_commitment = nil
  if height >= network.segwit_height then
    -- Compute witness merkle root from selected txs
    local wtx_hashes = {types.hash256_zero()}  -- coinbase wtxid placeholder
    for _, entry in ipairs(selected) do
      wtx_hashes[#wtx_hashes + 1] = entry.wtxid
    end
    local witness_root = crypto.compute_merkle_root(wtx_hashes)
    local witness_nonce = string.rep("\0", 32)
    witness_commitment = crypto.hash256(witness_root.bytes .. witness_nonce)
  end

  -- Create coinbase
  local coinbase_value = subsidy + total_fees
  local extra = "/LunarBlock/"
  local coinbase_tx = M.create_coinbase_tx(
    height, coinbase_value, extra, witness_commitment, payout_script
  )
  transactions[1] = coinbase_tx

  -- Add selected transactions
  for _, entry in ipairs(selected) do
    transactions[#transactions + 1] = entry.tx
  end

  -- Compute merkle root
  local tx_hashes = {}
  for i, tx in ipairs(transactions) do
    tx_hashes[i] = validation.compute_txid(tx)
  end
  local merkle_root = crypto.compute_merkle_root(tx_hashes)

  -- Get difficulty target
  local bits = chain_state.storage.get_header(prev_hash).bits
  -- In a real implementation, compute next required bits at retarget heights

  -- Build block header
  local header = types.block_header(
    0x20000000,  -- version with no signaling bits
    prev_hash,
    merkle_root,
    os.time(),
    bits,
    0  -- nonce starts at 0
  )

  -- Build the template response (BIP22 format)
  local template = {
    version = header.version,
    previousblockhash = types.hash256_hex(prev_hash),
    transactions = {},
    coinbaseaux = {flags = ""},
    coinbasevalue = coinbase_value,
    coinbasetxn = {
      data = M.hex_encode(serialize.serialize_transaction(coinbase_tx, true)),
    },
    target = M.hex_encode(consensus.bits_to_target(bits)),
    mintime = os.time(),
    mutable = {"time", "transactions", "prevblock"},
    noncerange = "00000000ffffffff",
    sigoplimit = consensus.MAX_BLOCK_SIGOPS_COST,
    sizelimit = consensus.MAX_BLOCK_SERIALIZED_SIZE,
    weightlimit = consensus.MAX_BLOCK_WEIGHT,
    curtime = os.time(),
    bits = string.format("%08x", bits),
    height = height,
    default_witness_commitment = witness_commitment and
      M.hex_encode("\x6a\x24\xaa\x21\xa9\xed" .. witness_commitment) or nil,
  }

  -- Add transaction data to template
  for _, entry in ipairs(selected) do
    template.transactions[#template.transactions + 1] = {
      data = M.hex_encode(serialize.serialize_transaction(entry.tx, true)),
      txid = types.hash256_hex(entry.txid),
      hash = types.hash256_hex(entry.wtxid),
      fee = entry.fee,
      sigops = 0,  -- simplified
      weight = entry.weight,
    }
  end

  -- Also return the full block object for direct mining
  local block = types.block(header, transactions)

  return template, block
end

--------------------------------------------------------------------------------
-- CPU Mining (for regtest)
--------------------------------------------------------------------------------

--- Mine a block by iterating through nonces.
-- This is a simple CPU miner suitable only for regtest.
-- @param block block: The block to mine
-- @param max_nonce number: Maximum nonce value to try (default 0xFFFFFFFF)
-- @return boolean, hash256: success flag and block hash if found
function M.mine_block(block, max_nonce)
  max_nonce = max_nonce or 0xFFFFFFFF
  local header_data = serialize.serialize_block_header(block.header)
  local target = consensus.bits_to_target(block.header.bits)

  for nonce = 0, max_nonce do
    -- Update nonce in header (last 4 bytes of 80-byte header)
    local nonce_bytes = string.char(
      bit.band(nonce, 0xFF),
      bit.band(bit.rshift(nonce, 8), 0xFF),
      bit.band(bit.rshift(nonce, 16), 0xFF),
      bit.band(bit.rshift(nonce, 24), 0xFF)
    )
    local candidate = header_data:sub(1, 76) .. nonce_bytes
    local hash = crypto.hash256(candidate)

    if consensus.hash_meets_target(hash, target) then
      block.header.nonce = nonce
      return true, types.hash256(hash)
    end
  end

  return false
end

return M
