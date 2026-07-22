local bit = require("bit")
local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local crypto = require("lunarblock.crypto")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local M = {}

-- Constants
local LOCKTIME_THRESHOLD = consensus.LOCKTIME_THRESHOLD  -- 500,000,000
local SEQUENCE_FINAL     = 0xFFFFFFFF
-- CTxIn::MAX_SEQUENCE_NONFINAL: used for coinbase inputs so that nLockTime is
-- enforced at validation time.  Core miner.cpp:171.
local MAX_SEQUENCE_NONFINAL = 0xFFFFFFFE

-- Block-assembly limits (Bitcoin Core policy/policy.h + node/miner.cpp)
-- DEFAULT_BLOCK_RESERVED_WEIGHT: weight reserved for block header + coinbase.
-- Core policy/policy.h:27.
local DEFAULT_BLOCK_RESERVED_WEIGHT  = 8000
-- MINIMUM_BLOCK_RESERVED_WEIGHT: lower bound for ClampOptions.
-- Core policy/policy.h:34.
local MINIMUM_BLOCK_RESERVED_WEIGHT  = 2000
-- MAX_CONSECUTIVE_FAILURES: give up when this many consecutive chunks failed
-- and the block is already close to full.  Core miner.cpp:284.
local MAX_CONSECUTIVE_FAILURES       = 1000
-- BLOCK_FULL_ENOUGH_WEIGHT_DELTA: "close to full" threshold.
-- Core miner.cpp:285.
local BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000

-- Median-time-past of the 11 blocks ending at tip_hash (Core GetMedianTimePast).
-- Mirrors the same helper in utxo.lua (kept local to avoid a module cycle); used
-- to clamp the mined-block timestamp to MTP+1 so the header is valid under a
-- peer's ContextualCheckBlockHeader (see create_block_template).
local function compute_mtp_from_storage(storage, tip_hash)
  if not storage or not tip_hash then
    return nil
  end
  local timestamps = {}
  local current_hash = tip_hash
  for _ = 1, 11 do
    local header = storage.get_header(current_hash)
    if not header then break end
    timestamps[#timestamps + 1] = header.timestamp
    current_hash = header.prev_hash
  end
  if #timestamps == 0 then
    return nil
  end
  table.sort(timestamps)
  local n = #timestamps
  return timestamps[math.floor(n / 2) + 1]
end

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
--
-- Key Core semantics reproduced here:
--   • coinbase input sequence = MAX_SEQUENCE_NONFINAL (0xFFFFFFFE) so that
--     nLockTime is enforced.  Core miner.cpp:171.
--   • coinbase nLockTime = height - 1 (anti-fee-sniping for regtest / miners).
--     Core miner.cpp:196.  For height == 0 we use 0 to avoid underflow.
function M.create_coinbase_tx(height, value, coinbase_script_extra, witness_commitment, payout_script)
  -- Build the coinbase scriptSig: height (BIP34) + extra data
  local w = serialize.buffer_writer()

  -- Encode height as minimal push (BIP34), byte-identical to the validator.
  -- Reuse validation.encode_bip34_height so the miner and the consensus check
  -- (validation.check_block, which does `CScript() << nHeight` per Core
  -- script.h:433-448) can never disagree.  The previous inline encoder always
  -- emitted a length-prefixed CScriptNum push, but Core / the validator use
  -- single-byte opcodes for the small cases: OP_0 (0x00) for height 0 and
  -- OP_1..OP_16 (0x51..0x60) for heights 1..16.  For height 1 the old code
  -- produced 0x01 0x01 instead of the required 0x51, so every generatetoaddress
  -- block was rejected with "bad-cb-height" (height mismatch at byte 1).
  w.write_bytes(validation.encode_bip34_height(height))

  if coinbase_script_extra then
    w.write_bytes(coinbase_script_extra)
  end
  local coinbase_script_sig = w.result()

  -- Build the transaction
  -- BUG FIX: sequence must be MAX_SEQUENCE_NONFINAL (0xFFFFFFFE) so that the
  -- coinbase locktime is enforced during block validation.
  -- Core miner.cpp:171: coinbaseTx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL
  local inputs = {
    types.txin(
      types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
      coinbase_script_sig,
      MAX_SEQUENCE_NONFINAL   -- 0xFFFFFFFE, not 0xFFFFFFFF
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

  -- BUG FIX: nLockTime = height - 1 (Core miner.cpp:196).
  -- This implements anti-fee-sniping and is enforced by validation.
  -- For height == 0 we use 0 to avoid underflow.
  local coinbase_locktime = (height > 0) and (height - 1) or 0
  local tx = types.transaction(2, inputs, outputs, coinbase_locktime)

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

--- Apply ClampOptions semantics to a config table.
-- Mirrors Core's ClampOptions() in miner.cpp:79.
-- • block_reserved_weight is clamped to [MINIMUM_BLOCK_RESERVED_WEIGHT,
--   MAX_BLOCK_WEIGHT] (defaults to DEFAULT_BLOCK_RESERVED_WEIGHT when absent).
-- • nBlockMaxWeight is clamped to [block_reserved_weight, MAX_BLOCK_WEIGHT].
-- @param config table: caller-supplied config
-- @return table: clamped config (never mutates the input table)
function M.clamp_options(config)
  config = config or {}
  local out = {}
  for k, v in pairs(config) do out[k] = v end

  -- Resolve block_reserved_weight
  local reserved = out.block_reserved_weight or DEFAULT_BLOCK_RESERVED_WEIGHT
  if reserved < MINIMUM_BLOCK_RESERVED_WEIGHT then
    reserved = MINIMUM_BLOCK_RESERVED_WEIGHT
  end
  if reserved > consensus.MAX_BLOCK_WEIGHT then
    reserved = consensus.MAX_BLOCK_WEIGHT
  end
  out.block_reserved_weight = reserved

  -- Resolve nBlockMaxWeight
  local max_w = out.max_weight or consensus.MAX_BLOCK_WEIGHT
  if max_w < reserved then max_w = reserved end
  if max_w > consensus.MAX_BLOCK_WEIGHT then max_w = consensus.MAX_BLOCK_WEIGHT end
  out.max_weight = max_w

  return out
end

--- Create a block template for mining.
-- @param mempool table: The mempool object
-- @param chain_state table: Chain state with tip_height, tip_hash, storage
-- @param network table: Network configuration (mainnet, testnet, regtest)
-- @param payout_script string: Script pubkey for block reward
-- @param config table: Optional configuration (max_weight, block_reserved_weight,
--                      max_sigops, block_min_fee_rate)
-- @param get_block_info function|nil: Optional fn(height) -> {mtp, version} for
--   BIP9 deployment state queries.  When nil, defaults to VERSIONBITS_TOP_BITS
--   (correct for all-buried-deployment networks such as mainnet today).
-- @return table, block: BIP22 template and block object
function M.create_block_template(mempool, chain_state, network, payout_script, config, get_block_info)
  -- BUG FIX: apply ClampOptions so callers cannot supply out-of-range values.
  -- Core miner.cpp:79 ClampOptions().
  config = M.clamp_options(config)

  local max_weight = config.max_weight   -- already clamped
  local max_sigops = config.max_sigops or consensus.MAX_BLOCK_SIGOPS_COST
  -- BUG FIX: reserve DEFAULT_BLOCK_RESERVED_WEIGHT (8000) for header + coinbase,
  -- not the old hard-coded 1000.  Core miner.cpp:114 resetBlock().
  local block_reserved_weight = config.block_reserved_weight  -- already clamped

  local height = chain_state.tip_height + 1
  local prev_hash = chain_state.tip_hash
  -- Pass the network's subsidy halving interval so the MINED coinbase claims
  -- the same subsidy the connect-block validator enforces. Omitting it defaults
  -- get_block_subsidy to the 210000 mainnet interval, so on regtest (150-block
  -- interval, Core kernel/chainparams.cpp:535) the template over-claimed 50 BTC
  -- at height >=150 while validation (utxo.lua:3438, which DOES pass the network
  -- interval) expected 25 -> self-mined block 150 was rejected "bad-cb-amount".
  local subsidy = consensus.get_block_subsidy(
    height, network.subsidy_halving_interval)

  -- Get median time past for locktime checks
  -- chain_state.mtp should be provided; fallback to current time - 3600 (1 hour ago)
  local mtp = chain_state.mtp or (os.time() - 3600)

  -- Select transactions from mempool ordered by ancestor fee rate
  local sorted_entries = mempool:get_sorted_entries()
  local selected = {}
  local selected_set = {}     -- txid_hex -> true
  local total_fees = 0
  local total_sigops = 0

  -- BUG FIX: start weight at block_reserved_weight (8000), which reserves
  -- space for the block header, tx count varint, and coinbase tx.
  -- Core miner.cpp:114: nBlockWeight = *Assert(m_options.block_reserved_weight)
  local total_weight = block_reserved_weight

  -- BUG FIX: implement MAX_CONSECUTIVE_FAILURES early-exit.
  -- Core miner.cpp:284-318: if nConsecutiveFailed > 1000 AND the block is
  -- within BLOCK_FULL_ENOUGH_WEIGHT_DELTA (4000) of the weight cap, stop.
  local consecutive_failed = 0

  for _, entry in ipairs(sorted_entries) do
    local txid_hex = types.hash256_hex(entry.txid)

    -- Skip if already selected
    if selected_set[txid_hex] then goto continue end

    -- Skip transactions that are not final (locktime not satisfied)
    if not M.is_final_tx(entry.tx, height, mtp) then goto continue end

    -- Compute this entry's sigops cost
    local tx_sigops = 0
    for _, inp in ipairs(entry.tx.inputs) do
      tx_sigops = tx_sigops + validation.count_script_sigops(inp.script_sig, true) * consensus.WITNESS_SCALE_FACTOR
    end
    for _, out in ipairs(entry.tx.outputs) do
      tx_sigops = tx_sigops + validation.count_script_sigops(out.script_pubkey, true) * consensus.WITNESS_SCALE_FACTOR
    end

    -- Check weight limit: >= mirrors Core's TestChunkBlockLimits (miner.cpp:241).
    -- BUG FIX: was > (off-by-one allowed weight == max_weight through).
    local weight_fits  = (total_weight + entry.weight < max_weight)
    -- Check sigops limit: >= mirrors Core miner.cpp:244.
    -- BUG FIX: was > (off-by-one allowed sigops == max_sigops through).
    local sigops_fits  = (total_sigops + tx_sigops < max_sigops)

    -- Ensure all ancestors are already selected
    local ancestors_ok = true
    for _, inp in ipairs(entry.tx.inputs) do
      local prev_hex = types.hash256_hex(inp.prev_out.hash)
      if mempool:has(prev_hex) and not selected_set[prev_hex] then
        ancestors_ok = false
        break
      end
    end

    if not weight_fits or not sigops_fits or not ancestors_ok then
      -- BUG FIX: track consecutive failures and give up early when close to
      -- full.  Core miner.cpp:313-318.
      consecutive_failed = consecutive_failed + 1
      if consecutive_failed > MAX_CONSECUTIVE_FAILURES and
         total_weight + BLOCK_FULL_ENOUGH_WEIGHT_DELTA > max_weight then
        break
      end
      goto continue
    end

    -- Chunk accepted: reset consecutive-failure counter.
    consecutive_failed = 0

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

  -- Compute block version via BIP9 state machine.
  -- Bitcoin Core miner.cpp uses VersionBitsCache::ComputeBlockVersion to set
  -- the signaling bits for any STARTED or LOCKED_IN deployments (versionbits.cpp:265-279).
  -- We pass the optional get_block_info callback; when nil, compute_block_version
  -- returns VERSIONBITS_TOP_BITS (correct for all-buried-deployment networks).
  local block_version = consensus.compute_block_version(network, height, get_block_info)

  -- Block timestamp = max(MTP + 1, current time) — Core's GetMinimumTime /
  -- UpdateTime (miner.cpp:36-47, validation UpdateTime).  Reorg-drop fix
  -- (mining-side consistency): the timestamp was previously raw os.time(),
  -- which on a fast regtest mine (many blocks in the same wall-clock second)
  -- produced blocks whose timestamp is NOT strictly greater than the
  -- median-time-past of the prior 11 blocks.  The local accept_block /
  -- connect_block path does NOT enforce the header time-too-old rule
  -- (ContextualCheckBlockHeader), so such blocks were mined + stored fine — but
  -- a PEER validating them via accept_header (which DOES enforce it) rejected
  -- the whole header chain as "time-too-old".  That silently broke ALL
  -- lunarblock-to-lunarblock header sync (the reorg proof's R3 could not feed
  -- its chain to R1), so the heavier-fork header tip never propagated and the
  -- reorg machinery never engaged.  Clamping to MTP+1 makes every mined block
  -- header-MTP-valid, exactly like Core's miner.
  local real_mtp = compute_mtp_from_storage(chain_state.storage, prev_hash)
  local block_time = os.time()
  if real_mtp and block_time <= real_mtp then
    block_time = real_mtp + 1
  end

  -- Build block header
  local header = types.block_header(
    block_version,
    prev_hash,
    merkle_root,
    block_time,
    bits,
    0  -- nonce starts at 0
  )

  -- BIP22/BIP23/BIP9 required fields:
  -- capabilities: server-side features (Core: aCaps = ["proposal"])
  local capabilities = {"proposal"}

  -- rules: enforced soft-fork rules (Core rpc/mining.cpp:954-963)
  -- "csv" is always included; "!segwit" and "taproot" once segwit is active.
  local rules = {"csv"}
  if height >= network.segwit_height then
    rules[#rules + 1] = "!segwit"
    rules[#rules + 1] = "taproot"
  end

  -- vbavailable: map of pending versionbits deployment names to bit numbers.
  -- We have no live BIP9 deployments in our state machine right now; emit empty
  -- object.  Core: result.pushKV("vbavailable", vbavailable).
  local vbavailable = {}

  -- vbrequired: bitmask of version bits the server requires miners to set.
  -- Always 0 on current mainnet/testnet/regtest per BIP9.
  -- Core: result.pushKV("vbrequired", 0).
  local vbrequired = 0

  -- Build the template response (BIP22 format)
  local template = {
    capabilities = capabilities,
    version = header.version,
    rules = rules,
    vbavailable = vbavailable,
    vbrequired = vbrequired,
    previousblockhash = types.hash256_hex(prev_hash),
    transactions = {},
    coinbaseaux = {flags = ""},
    coinbasevalue = coinbase_value,
    coinbasetxn = {
      data = M.hex_encode(serialize.serialize_transaction(coinbase_tx, true)),
    },
    target = M.hex_encode(consensus.bits_to_target(bits)),
    -- BUG FIX: mintime must be MTP+1 (GetMinimumTime), not os.time().
    -- Core miner.cpp:36-47: GetMinimumTime returns MTP+1 (adjusted for
    -- BIP94 timewarp on retarget boundaries).  BIP22 mintime field.
    mintime = mtp + 1,
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

  -- Build per-tx index map for BIP22 `depends` field.
  -- Core rpc/mining.cpp:898-923: setTxIndex maps txid → 1-based index in the
  -- non-coinbase transactions array.  Coinbase is at slot 0 (excluded from the
  -- template transactions list), so the first real tx is at 1.
  -- We replicate this: index i starts at 1 for the first selected entry.
  local tx_index = {}  -- txid_hex -> 1-based index (1 = first non-coinbase tx)
  for i, entry in ipairs(selected) do
    tx_index[types.hash256_hex(entry.txid)] = i
  end

  -- Add transaction data to template, including BIP22 `depends` array.
  for _, entry in ipairs(selected) do
    -- Compute depends: 1-based indices of in-template transactions this tx
    -- spends.  Only inputs whose prev txid maps to a selected in-template tx
    -- are included (inputs spending confirmed UTXOs have no in-template dep).
    local depends = {}
    for _, inp in ipairs(entry.tx.inputs) do
      local prev_hex = types.hash256_hex(inp.prev_out.hash)
      local dep_idx = tx_index[prev_hex]
      if dep_idx then
        depends[#depends + 1] = dep_idx
      end
    end

    template.transactions[#template.transactions + 1] = {
      data = M.hex_encode(serialize.serialize_transaction(entry.tx, true)),
      txid = types.hash256_hex(entry.txid),
      hash = types.hash256_hex(entry.wtxid),
      depends = depends,
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
