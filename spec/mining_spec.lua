local types = require("lunarblock.types")
local mining = require("lunarblock.mining")
local consensus = require("lunarblock.consensus")
local serialize = require("lunarblock.serialize")
local validation = require("lunarblock.validation")
local crypto = require("lunarblock.crypto")
local mempool_mod = require("lunarblock.mempool")

describe("mining", function()

  -- Helper to create a simple transaction
  local function make_tx(version, inputs, outputs, locktime)
    local tx = types.transaction(version or 1, inputs or {}, outputs or {}, locktime or 0)
    return tx
  end

  -- Helper to create input referencing an outpoint
  local function make_input(txid_hash, vout, sequence)
    return types.txin(
      types.outpoint(txid_hash, vout),
      "",
      sequence or 0xFFFFFFFE
    )
  end

  -- Helper to create output
  local function make_output(value, script_pubkey)
    return types.txout(value, script_pubkey or string.rep("\x00", 25))
  end

  -- Helper to create a P2PKH-style payout script
  local function make_payout_script()
    -- OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    return "\x76\xa9\x14" .. string.rep("\x01", 20) .. "\x88\xac"
  end

  -- Helper to create a mock chain state
  local function make_mock_chain_state(tip_height, tip_hash, bits)
    tip_hash = tip_hash or types.hash256(string.rep("\xab", 32))
    bits = bits or consensus.networks.regtest.pow_limit_bits
    return {
      tip_height = tip_height or 100,
      tip_hash = tip_hash,
      storage = {
        get_header = function(_, hash)
          return {
            version = 0x20000000,
            prev_hash = types.hash256_zero(),
            merkle_root = types.hash256_zero(),
            timestamp = os.time() - 600,
            bits = bits,
            nonce = 0
          }
        end
      }
    }
  end

  -- Helper to create a mock mempool
  local function make_mock_mempool(entries)
    entries = entries or {}
    local mp = {
      entries_list = entries,
      entries_map = {},
    }
    for _, entry in ipairs(entries) do
      mp.entries_map[types.hash256_hex(entry.txid)] = entry
    end
    function mp:get_sorted_entries()
      return self.entries_list
    end
    function mp:has(txid_hex)
      return self.entries_map[txid_hex] ~= nil
    end
    return mp
  end

  -- Helper to create a mempool entry
  local function make_mempool_entry(tx, fee, txid)
    txid = txid or validation.compute_txid(tx)
    local wtxid = validation.compute_wtxid(tx)
    local weight = validation.get_tx_weight(tx)
    local vsize = math.ceil(weight / 4)
    return {
      tx = tx,
      txid = txid,
      wtxid = wtxid,
      fee = fee,
      vsize = vsize,
      weight = weight,
      fee_rate = fee / vsize,
      height = 100,
      time = os.time(),
      ancestors = {},
      descendants = {},
      ancestor_count = 0,
      descendant_count = 0,
      ancestor_size = 0,
      descendant_size = 0,
      ancestor_fees = 0,
      descendant_fees = 0,
    }
  end

  describe("hex_encode", function()
    it("encodes binary to hex", function()
      assert.equal("00", mining.hex_encode("\x00"))
      assert.equal("ff", mining.hex_encode("\xff"))
      assert.equal("48656c6c6f", mining.hex_encode("Hello"))
      assert.equal("", mining.hex_encode(""))
    end)

    it("handles all byte values", function()
      local data = ""
      for i = 0, 255 do
        data = data .. string.char(i)
      end
      local hex = mining.hex_encode(data)
      assert.equal(512, #hex)
      assert.equal("00", hex:sub(1, 2))
      assert.equal("ff", hex:sub(511, 512))
    end)
  end)

  describe("hex_decode", function()
    it("decodes hex to binary", function()
      assert.equal("\x00", mining.hex_decode("00"))
      assert.equal("\xff", mining.hex_decode("ff"))
      assert.equal("Hello", mining.hex_decode("48656c6c6f"))
      assert.equal("", mining.hex_decode(""))
    end)

    it("round-trips with hex_encode", function()
      local original = string.rep("\xde\xad\xbe\xef", 8)
      local encoded = mining.hex_encode(original)
      local decoded = mining.hex_decode(encoded)
      assert.equal(original, decoded)
    end)
  end)

  describe("create_coinbase_tx", function()
    it("creates valid coinbase with correct height encoding (BIP34)", function()
      local payout_script = make_payout_script()
      local coinbase = mining.create_coinbase_tx(100, 5000000000, nil, nil, payout_script)

      -- Check structure
      assert.equal(2, coinbase.version)
      assert.equal(1, #coinbase.inputs)
      assert.equal(1, #coinbase.outputs)
      -- BUG FIX: locktime = height-1 = 99 (Core miner.cpp:196)
      assert.equal(99, coinbase.locktime)

      -- Check input is null coinbase
      local inp = coinbase.inputs[1]
      assert.equal(string.rep("\x00", 32), inp.prev_out.hash.bytes)
      assert.equal(0xFFFFFFFF, inp.prev_out.index)
      -- BUG FIX: sequence = MAX_SEQUENCE_NONFINAL (0xFFFFFFFE), not 0xFFFFFFFF
      -- Core miner.cpp:171: CTxIn::MAX_SEQUENCE_NONFINAL
      assert.equal(0xFFFFFFFE, inp.sequence)

      -- Check BIP34 height encoding in scriptSig
      local script_sig = inp.script_sig
      -- Height 100 = 0x64, which fits in 1 byte
      assert.equal(1, script_sig:byte(1))  -- 1 byte for height
      assert.equal(100, script_sig:byte(2))  -- height value
    end)

    it("encodes height 0 correctly", function()
      local coinbase = mining.create_coinbase_tx(0, 5000000000, nil, nil, make_payout_script())
      local script_sig = coinbase.inputs[1].script_sig
      assert.equal(1, script_sig:byte(1))
      assert.equal(0, script_sig:byte(2))
    end)

    it("encodes large heights correctly", function()
      -- Height 500000 = 0x07A120 (3 bytes)
      local coinbase = mining.create_coinbase_tx(500000, 5000000000, nil, nil, make_payout_script())
      local script_sig = coinbase.inputs[1].script_sig
      assert.equal(3, script_sig:byte(1))  -- 3 bytes for height
      -- Little-endian: 0x20, 0xA1, 0x07
      local encoded_height = script_sig:byte(2) +
                             script_sig:byte(3) * 256 +
                             script_sig:byte(4) * 65536
      assert.equal(500000, encoded_height)
    end)

    it("has correct value in output", function()
      local value = 625000000  -- 6.25 BTC
      local coinbase = mining.create_coinbase_tx(100, value, nil, nil, make_payout_script())
      assert.equal(value, coinbase.outputs[1].value)
    end)

    it("includes extra data in scriptSig", function()
      local extra = "/TestPool/"
      local coinbase = mining.create_coinbase_tx(100, 5000000000, extra, nil, make_payout_script())
      local script_sig = coinbase.inputs[1].script_sig
      -- Extra should appear after height encoding
      assert.truthy(script_sig:find(extra, 1, true))
    end)

    it("includes witness commitment output when provided", function()
      local witness_commitment = string.rep("\xab", 32)
      local coinbase = mining.create_coinbase_tx(100, 5000000000, nil, witness_commitment, make_payout_script())

      assert.equal(2, #coinbase.outputs)
      -- Second output should be witness commitment
      local commitment_out = coinbase.outputs[2]
      assert.equal(0, commitment_out.value)
      -- Check prefix: OP_RETURN (0x6a) + push 36 (0x24) + marker (aa21a9ed)
      assert.equal("\x6a\x24\xaa\x21\xa9\xed", commitment_out.script_pubkey:sub(1, 6))
      -- Check commitment hash
      assert.equal(witness_commitment, commitment_out.script_pubkey:sub(7, 38))
    end)

    it("sets segwit flag and witness nonce when commitment provided", function()
      local witness_commitment = string.rep("\xcd", 32)
      local coinbase = mining.create_coinbase_tx(100, 5000000000, nil, witness_commitment, make_payout_script())

      assert.is_true(coinbase.segwit)
      assert.equal(1, #coinbase.inputs[1].witness)
      assert.equal(string.rep("\x00", 32), coinbase.inputs[1].witness[1])
    end)

    it("does not set segwit without witness commitment", function()
      local coinbase = mining.create_coinbase_tx(100, 5000000000, nil, nil, make_payout_script())

      assert.is_false(coinbase.segwit)
      assert.equal(0, #coinbase.inputs[1].witness)
    end)
  end)

  describe("create_block_template", function()
    it("selects transactions ordered by fee rate", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      local network = consensus.networks.regtest

      -- Create two transactions with different fee rates
      local tx1 = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0)}, {make_output(9000)})
      local tx2 = make_tx(1, {make_input(types.hash256(string.rep("\x02", 32)), 0)}, {make_output(8000)})

      -- tx2 has higher fee (2000 vs 1000)
      local entry1 = make_mempool_entry(tx1, 1000)
      local entry2 = make_mempool_entry(tx2, 2000)

      -- Sorted by fee rate descending
      local mempool = make_mock_mempool({entry2, entry1})

      local template, block = mining.create_block_template(mempool, chain_state, network, payout_script)

      -- Block should have coinbase + 2 txs
      assert.equal(3, #block.transactions)
      -- After coinbase, higher fee tx should come first in template
      assert.equal(2, #template.transactions)
      assert.equal(types.hash256_hex(entry2.txid), template.transactions[1].txid)
    end)

    it("respects weight limit", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      local network = consensus.networks.regtest

      -- Create transactions that together exceed the weight limit
      local tx1 = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0)}, {make_output(9000)})
      local entry1 = make_mempool_entry(tx1, 1000)

      local mempool = make_mock_mempool({entry1})

      -- Set very low weight limit that can't fit the tx
      local config = {max_weight = 500}
      local template, block = mining.create_block_template(mempool, chain_state, network, payout_script, config)

      -- Block should only have coinbase
      assert.equal(1, #block.transactions)
      assert.equal(0, #template.transactions)
    end)

    it("coinbase value equals subsidy plus fees", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      local network = consensus.networks.regtest

      local tx1 = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0)}, {make_output(9000)})
      local entry1 = make_mempool_entry(tx1, 1000)

      local mempool = make_mock_mempool({entry1})

      local template, block = mining.create_block_template(mempool, chain_state, network, payout_script)

      local expected_subsidy = consensus.get_block_subsidy(101)
      local expected_value = expected_subsidy + 1000

      assert.equal(expected_value, template.coinbasevalue)
      assert.equal(expected_value, block.transactions[1].outputs[1].value)
    end)

    it("computes valid merkle root", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      local network = consensus.networks.regtest

      local tx1 = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0)}, {make_output(9000)})
      local entry1 = make_mempool_entry(tx1, 1000)

      local mempool = make_mock_mempool({entry1})

      local _, block = mining.create_block_template(mempool, chain_state, network, payout_script)

      -- Verify merkle root matches computed value
      assert.is_true(validation.check_merkle_root(block))
    end)

    it("includes witness commitment for segwit blocks", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      local network = consensus.networks.regtest  -- segwit_height = 0

      local mempool = make_mock_mempool({})

      local template, block = mining.create_block_template(mempool, chain_state, network, payout_script)

      -- Coinbase should have witness commitment
      assert.is_true(block.transactions[1].segwit)
      assert.truthy(template.default_witness_commitment)
    end)

    it("returns empty template when mempool is empty", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      local network = consensus.networks.regtest

      local mempool = make_mock_mempool({})

      local template, block = mining.create_block_template(mempool, chain_state, network, payout_script)

      assert.equal(1, #block.transactions)  -- Only coinbase
      assert.equal(0, #template.transactions)
    end)

    it("skips transactions with unselected ancestors", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      local network = consensus.networks.regtest

      -- Create parent tx
      local parent_txid = types.hash256(string.rep("\x01", 32))
      local parent_tx = make_tx(1, {make_input(types.hash256(string.rep("\xff", 32)), 0)}, {make_output(9000)})
      local parent_entry = make_mempool_entry(parent_tx, 100, parent_txid)

      -- Create child that spends parent (child has higher fee rate, will be processed first)
      local child_tx = make_tx(1, {make_input(parent_txid, 0)}, {make_output(8000)})
      local child_entry = make_mempool_entry(child_tx, 5000)

      -- Mock mempool with child listed first (higher fee rate)
      -- but parent not yet selected, so child should be skipped initially
      local entries = {child_entry, parent_entry}
      local mempool = make_mock_mempool(entries)

      local template, block = mining.create_block_template(mempool, chain_state, network, payout_script)

      -- Parent should be included (processed second, no deps)
      -- Child should be skipped (processed first, parent not yet selected)
      -- Only coinbase + parent = 2 txs total
      assert.equal(2, #block.transactions)
    end)
  end)

  describe("mine_block", function()
    it("successfully mines a regtest block (low difficulty)", function()
      local payout_script = make_payout_script()

      -- Create a simple block with regtest difficulty
      local header = types.block_header(
        0x20000000,
        types.hash256_zero(),
        types.hash256(string.rep("\xab", 32)),
        os.time(),
        consensus.networks.regtest.pow_limit_bits,
        0
      )
      local coinbase = mining.create_coinbase_tx(1, 5000000000, nil, nil, payout_script)
      local block = types.block(header, {coinbase})

      local success, hash = mining.mine_block(block)

      assert.is_true(success)
      assert.truthy(hash)
      assert.equal("hash256", hash._type)

      -- Verify the nonce was set
      assert.truthy(block.header.nonce >= 0)

      -- Verify the hash meets target
      local target = consensus.bits_to_target(block.header.bits)
      assert.is_true(consensus.hash_meets_target(hash.bytes, target))
    end)

    it("returns false when max_nonce is insufficient", function()
      local payout_script = make_payout_script()

      -- Use mainnet difficulty (very hard to find valid nonce)
      local header = types.block_header(
        0x20000000,
        types.hash256_zero(),
        types.hash256(string.rep("\xab", 32)),
        os.time(),
        consensus.networks.mainnet.pow_limit_bits,
        0
      )
      local coinbase = mining.create_coinbase_tx(1, 5000000000, nil, nil, payout_script)
      local block = types.block(header, {coinbase})

      -- Only try 10 nonces - extremely unlikely to find a valid mainnet block
      local success = mining.mine_block(block, 10)

      assert.is_false(success)
    end)

    it("mines regtest block within reasonable nonce range", function()
      local payout_script = make_payout_script()

      local header = types.block_header(
        0x20000000,
        types.hash256(string.rep("\x01", 32)),
        types.hash256(string.rep("\x02", 32)),
        os.time(),
        consensus.networks.regtest.pow_limit_bits,
        0
      )
      local coinbase = mining.create_coinbase_tx(1, 5000000000, nil, nil, payout_script)
      local block = types.block(header, {coinbase})

      -- Regtest difficulty is so low that we should find a valid nonce quickly
      local success, hash = mining.mine_block(block, 10000)

      assert.is_true(success)
      assert.truthy(hash)
    end)
  end)

  describe("BIP22 template format", function()
    it("has all required fields", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      local network = consensus.networks.regtest

      local mempool = make_mock_mempool({})

      local template, _ = mining.create_block_template(mempool, chain_state, network, payout_script)

      -- Required BIP22 fields
      assert.truthy(template.version)
      assert.truthy(template.previousblockhash)
      assert.is_table(template.transactions)
      assert.truthy(template.coinbasevalue)
      assert.truthy(template.target)
      assert.truthy(template.mintime)
      assert.is_table(template.mutable)
      assert.truthy(template.noncerange)
      assert.truthy(template.sigoplimit)
      assert.truthy(template.sizelimit)
      assert.truthy(template.curtime)
      assert.truthy(template.bits)
      assert.truthy(template.height)
    end)

    it("has valid hex-encoded target", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      local network = consensus.networks.regtest

      local mempool = make_mock_mempool({})

      local template, _ = mining.create_block_template(mempool, chain_state, network, payout_script)

      -- Target should be 64 hex chars (32 bytes)
      assert.equal(64, #template.target)
      -- Should decode successfully
      local target_bytes = mining.hex_decode(template.target)
      assert.equal(32, #target_bytes)
    end)

    it("has valid coinbase transaction data", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      local network = consensus.networks.regtest

      local mempool = make_mock_mempool({})

      local template, _ = mining.create_block_template(mempool, chain_state, network, payout_script)

      -- Coinbase data should be hex-encoded
      local coinbase_hex = template.coinbasetxn.data
      assert.truthy(coinbase_hex)
      assert.truthy(#coinbase_hex > 0)
      assert.equal(0, #coinbase_hex % 2)  -- Even number of hex chars

      -- Should decode and deserialize successfully
      local coinbase_bytes = mining.hex_decode(coinbase_hex)
      local reader = serialize.buffer_reader(coinbase_bytes)
      local coinbase_tx = serialize.deserialize_transaction(reader)
      assert.truthy(coinbase_tx)
    end)

    it("transaction entries have required fields", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      local network = consensus.networks.regtest

      local tx = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0)}, {make_output(9000)})
      local entry = make_mempool_entry(tx, 1000)
      local mempool = make_mock_mempool({entry})

      local template, _ = mining.create_block_template(mempool, chain_state, network, payout_script)

      assert.equal(1, #template.transactions)
      local tx_entry = template.transactions[1]
      assert.truthy(tx_entry.data)
      assert.truthy(tx_entry.txid)
      assert.truthy(tx_entry.hash)
      assert.truthy(tx_entry.fee)
      assert.truthy(tx_entry.weight)
    end)

    it("height is correct", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(500)
      local network = consensus.networks.regtest

      local mempool = make_mock_mempool({})

      local template, _ = mining.create_block_template(mempool, chain_state, network, payout_script)

      assert.equal(501, template.height)
    end)

    it("bits field is formatted as 8 hex chars", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      local network = consensus.networks.regtest

      local mempool = make_mock_mempool({})

      local template, _ = mining.create_block_template(mempool, chain_state, network, payout_script)

      assert.equal(8, #template.bits)
      -- Should be valid hex
      assert.truthy(template.bits:match("^%x+$"))
    end)
  end)

  describe("is_final_tx", function()
    it("returns true for locktime 0", function()
      local tx = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFE)}, {make_output(9000)}, 0)
      assert.is_true(mining.is_final_tx(tx, 100, 1700000000))
    end)

    it("returns true when height-based locktime is satisfied", function()
      -- locktime 50 < height 100, so final
      local tx = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFE)}, {make_output(9000)}, 50)
      assert.is_true(mining.is_final_tx(tx, 100, 1700000000))
    end)

    it("returns false when height-based locktime is not satisfied", function()
      -- locktime 150 > height 100, and sequence is not final
      local tx = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFE)}, {make_output(9000)}, 150)
      assert.is_false(mining.is_final_tx(tx, 100, 1700000000))
    end)

    it("returns true when time-based locktime is satisfied", function()
      -- locktime 500000001 (>= 500000000 so time-based)
      -- mtp = 600000000, locktime < mtp, so final
      local tx = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFE)}, {make_output(9000)}, 500000001)
      assert.is_true(mining.is_final_tx(tx, 100, 600000000))
    end)

    it("returns false when time-based locktime is not satisfied", function()
      -- locktime 700000000, mtp = 600000000, locktime > mtp
      local tx = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFE)}, {make_output(9000)}, 700000000)
      assert.is_false(mining.is_final_tx(tx, 100, 600000000))
    end)

    it("returns true when all inputs have SEQUENCE_FINAL even if locktime not satisfied", function()
      -- locktime 150 > height 100, but all inputs have sequence 0xFFFFFFFF
      local tx = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFF)}, {make_output(9000)}, 150)
      assert.is_true(mining.is_final_tx(tx, 100, 1700000000))
    end)

    it("returns false if any input has non-final sequence and locktime not satisfied", function()
      -- Two inputs: one final, one not final
      local inputs = {
        make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFF),
        make_input(types.hash256(string.rep("\x02", 32)), 0, 0xFFFFFFFE)
      }
      local tx = make_tx(1, inputs, {make_output(9000)}, 150)
      assert.is_false(mining.is_final_tx(tx, 100, 1700000000))
    end)

    it("handles locktime threshold boundary correctly", function()
      -- locktime exactly at threshold (500000000) is height-based
      local tx = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFE)}, {make_output(9000)}, 499999999)
      assert.is_true(mining.is_final_tx(tx, 500000000, 1700000000))

      -- locktime at threshold is time-based
      local tx2 = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFE)}, {make_output(9000)}, 500000000)
      -- With height 100 and mtp 600000000, locktime 500000000 < mtp 600000000
      assert.is_true(mining.is_final_tx(tx2, 100, 600000000))
    end)
  end)

  describe("locktime filtering in block template", function()
    it("excludes transactions with unsatisfied height-based locktime", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      chain_state.mtp = 1700000000
      local network = consensus.networks.regtest

      -- Create a tx with locktime 150 (not satisfied at height 101)
      local tx = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFE)}, {make_output(9000)}, 150)
      local entry = make_mempool_entry(tx, 1000)

      local mempool = make_mock_mempool({entry})
      local template, block = mining.create_block_template(mempool, chain_state, network, payout_script)

      -- Transaction should be excluded
      assert.equal(1, #block.transactions)  -- Only coinbase
      assert.equal(0, #template.transactions)
    end)

    it("includes transactions with satisfied height-based locktime", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      chain_state.mtp = 1700000000
      local network = consensus.networks.regtest

      -- Create a tx with locktime 50 (satisfied at height 101)
      local tx = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFE)}, {make_output(9000)}, 50)
      local entry = make_mempool_entry(tx, 1000)

      local mempool = make_mock_mempool({entry})
      local template, block = mining.create_block_template(mempool, chain_state, network, payout_script)

      -- Transaction should be included
      assert.equal(2, #block.transactions)  -- Coinbase + tx
      assert.equal(1, #template.transactions)
    end)

    it("excludes transactions with unsatisfied time-based locktime", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      chain_state.mtp = 1600000000
      local network = consensus.networks.regtest

      -- Create a tx with locktime 1700000000 (time-based, > mtp)
      local tx = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFE)}, {make_output(9000)}, 1700000000)
      local entry = make_mempool_entry(tx, 1000)

      local mempool = make_mock_mempool({entry})
      local template, block = mining.create_block_template(mempool, chain_state, network, payout_script)

      -- Transaction should be excluded
      assert.equal(1, #block.transactions)
      assert.equal(0, #template.transactions)
    end)

    it("includes transactions with SEQUENCE_FINAL despite unsatisfied locktime", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      chain_state.mtp = 1700000000
      local network = consensus.networks.regtest

      -- Create a tx with locktime 150 but all inputs have SEQUENCE_FINAL
      local tx = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFF)}, {make_output(9000)}, 150)
      local entry = make_mempool_entry(tx, 1000)

      local mempool = make_mock_mempool({entry})
      local template, block = mining.create_block_template(mempool, chain_state, network, payout_script)

      -- Transaction should be included (SEQUENCE_FINAL makes it final)
      assert.equal(2, #block.transactions)
      assert.equal(1, #template.transactions)
    end)
  end)

  describe("coinbase transaction", function()
    -- BUG FIX W87: sequence is MAX_SEQUENCE_NONFINAL (0xFFFFFFFE), not SEQUENCE_FINAL.
    -- Core miner.cpp:171: "Make sure timelock is enforced."
    it("has sequence MAX_SEQUENCE_NONFINAL (0xFFFFFFFE)", function()
      local payout_script = make_payout_script()
      local coinbase = mining.create_coinbase_tx(100, 5000000000, nil, nil, payout_script)

      assert.equal(0xFFFFFFFE, coinbase.inputs[1].sequence)
    end)

    -- BUG FIX W87: locktime = height-1 (anti-fee-sniping).
    -- Core miner.cpp:196: coinbaseTx.nLockTime = static_cast<uint32_t>(nHeight - 1)
    it("has locktime = height - 1", function()
      local payout_script = make_payout_script()
      local coinbase100 = mining.create_coinbase_tx(100, 5000000000, nil, nil, payout_script)
      assert.equal(99, coinbase100.locktime)

      local coinbase1 = mining.create_coinbase_tx(1, 5000000000, nil, nil, payout_script)
      assert.equal(0, coinbase1.locktime)

      -- height 0 edge case: no underflow
      local coinbase0 = mining.create_coinbase_tx(0, 5000000000, nil, nil, payout_script)
      assert.equal(0, coinbase0.locktime)
    end)
  end)

  describe("witness commitment", function()
    it("includes correct witness commitment format in coinbase", function()
      local witness_commitment = string.rep("\xab", 32)
      local payout_script = make_payout_script()
      local coinbase = mining.create_coinbase_tx(100, 5000000000, nil, witness_commitment, payout_script)

      -- Should have 2 outputs
      assert.equal(2, #coinbase.outputs)

      -- Second output is witness commitment
      local commitment_out = coinbase.outputs[2]
      assert.equal(0, commitment_out.value)

      -- Format: OP_RETURN (0x6a) + PUSH 36 (0x24) + marker (aa21a9ed) + 32-byte hash
      local script = commitment_out.script_pubkey
      assert.equal(38, #script)
      assert.equal(0x6a, script:byte(1))  -- OP_RETURN
      assert.equal(0x24, script:byte(2))  -- push 36 bytes
      assert.equal("\xaa\x21\xa9\xed", script:sub(3, 6))  -- marker
      assert.equal(witness_commitment, script:sub(7, 38))
    end)

    it("sets witness nonce to 32 zero bytes", function()
      local witness_commitment = string.rep("\xab", 32)
      local payout_script = make_payout_script()
      local coinbase = mining.create_coinbase_tx(100, 5000000000, nil, witness_commitment, payout_script)

      assert.is_true(coinbase.segwit)
      assert.equal(1, #coinbase.inputs[1].witness)
      assert.equal(string.rep("\0", 32), coinbase.inputs[1].witness[1])
    end)

    it("computes witness commitment correctly in block template", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      local network = consensus.networks.regtest  -- segwit enabled

      local mempool = make_mock_mempool({})
      local template, block = mining.create_block_template(mempool, chain_state, network, payout_script)

      -- Coinbase should have witness commitment
      local coinbase = block.transactions[1]
      assert.is_true(coinbase.segwit)
      assert.equal(2, #coinbase.outputs)

      -- Template should have default_witness_commitment
      assert.truthy(template.default_witness_commitment)
      -- Should be hex-encoded: 6a24aa21a9ed + 64 hex chars (32 bytes)
      assert.equal(76, #template.default_witness_commitment)  -- 38 bytes * 2
      assert.equal("6a24aa21a9ed", template.default_witness_commitment:sub(1, 12))
    end)
  end)

  describe("apply_anti_fee_sniping", function()
    it("sets locktime to current height", function()
      local tx = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFF)}, {make_output(9000)}, 0)
      assert.equal(0, tx.locktime)

      mining.apply_anti_fee_sniping(tx, 100)

      assert.equal(100, tx.locktime)
    end)

    it("sets final sequences to non-final", function()
      local tx = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFF)}, {make_output(9000)}, 0)
      assert.equal(0xFFFFFFFF, tx.inputs[1].sequence)

      mining.apply_anti_fee_sniping(tx, 100)

      assert.equal(0xFFFFFFFE, tx.inputs[1].sequence)
    end)

    it("preserves already non-final sequences", function()
      local tx = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFD)}, {make_output(9000)}, 0)

      mining.apply_anti_fee_sniping(tx, 100)

      -- Should remain unchanged since it's already non-final
      assert.equal(0xFFFFFFFD, tx.inputs[1].sequence)
    end)

    it("handles multiple inputs", function()
      local inputs = {
        make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFF),
        make_input(types.hash256(string.rep("\x02", 32)), 0, 0xFFFFFFFE),
        make_input(types.hash256(string.rep("\x03", 32)), 0, 0xFFFFFFFF)
      }
      local tx = make_tx(1, inputs, {make_output(9000)}, 0)

      mining.apply_anti_fee_sniping(tx, 500)

      assert.equal(500, tx.locktime)
      assert.equal(0xFFFFFFFE, tx.inputs[1].sequence)  -- Changed from FINAL
      assert.equal(0xFFFFFFFE, tx.inputs[2].sequence)  -- Already non-final
      assert.equal(0xFFFFFFFE, tx.inputs[3].sequence)  -- Changed from FINAL
    end)
  end)

  -- -------------------------------------------------------------------------
  -- W87 new tests: clamp_options, reserved weight, >= gates, mintime
  -- -------------------------------------------------------------------------

  describe("clamp_options (W87)", function()
    it("defaults block_reserved_weight to 8000", function()
      local out = mining.clamp_options({})
      assert.equal(8000, out.block_reserved_weight)
    end)

    it("clamps block_reserved_weight below MINIMUM up to 2000", function()
      local out = mining.clamp_options({block_reserved_weight = 100})
      assert.equal(2000, out.block_reserved_weight)
    end)

    it("clamps block_reserved_weight above MAX_BLOCK_WEIGHT", function()
      local out = mining.clamp_options({block_reserved_weight = 5000000})
      assert.equal(consensus.MAX_BLOCK_WEIGHT, out.block_reserved_weight)
    end)

    it("defaults max_weight to MAX_BLOCK_WEIGHT", function()
      local out = mining.clamp_options({})
      assert.equal(consensus.MAX_BLOCK_WEIGHT, out.max_weight)
    end)

    it("does not allow max_weight below block_reserved_weight", function()
      -- block_reserved_weight clamped to 2000, max_weight also clamped up to 2000
      local out = mining.clamp_options({block_reserved_weight = 100, max_weight = 1000})
      assert.equal(2000, out.block_reserved_weight)
      assert.equal(2000, out.max_weight)
    end)

    it("does not allow max_weight above MAX_BLOCK_WEIGHT", function()
      local out = mining.clamp_options({max_weight = 9000000})
      assert.equal(consensus.MAX_BLOCK_WEIGHT, out.max_weight)
    end)

    it("preserves valid in-range values unchanged", function()
      local out = mining.clamp_options({block_reserved_weight = 5000, max_weight = 3000000})
      assert.equal(5000, out.block_reserved_weight)
      assert.equal(3000000, out.max_weight)
    end)
  end)

  describe("block_reserved_weight gate (W87 — Bug 3)", function()
    -- The block starts at block_reserved_weight=8000, not 1000.
    -- A transaction of weight 3992001 must be excluded from a default-weight block
    -- because 8000 + 3992001 = 4000001 >= 4000000.
    it("reserves 8000 weight units for header+coinbase by default", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      local network = consensus.networks.regtest

      -- Build a tx whose weight exactly fills the remaining space minus 1
      -- available = 4000000 - 8000 = 3992000; weight 3992001 must NOT fit.
      local big_output = make_output(9000, string.rep("\x51", 3992001 / 4))  -- approx
      local tx = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0)},
                         {make_output(9000)})
      -- Force a weight manually by patching the entry weight
      local entry = make_mempool_entry(tx, 1000)
      entry.weight = 3992001

      local mempool = make_mock_mempool({entry})
      local _, block = mining.create_block_template(mempool, chain_state, network, payout_script)
      -- 8000 + 3992001 = 4000001 >= 4000000, so tx must be excluded
      assert.equal(1, #block.transactions)  -- only coinbase
    end)

    it("accepts a tx that exactly fits within the reserved space", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      local network = consensus.networks.regtest

      local tx = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0)},
                         {make_output(9000)})
      local entry = make_mempool_entry(tx, 1000)
      entry.weight = 3991999  -- 8000 + 3991999 = 3999999 < 4000000: fits

      local mempool = make_mock_mempool({entry})
      local _, block = mining.create_block_template(mempool, chain_state, network, payout_script)
      assert.equal(2, #block.transactions)  -- coinbase + tx
    end)
  end)

  describe("weight gate off-by-one (W87 — Bug 4)", function()
    -- Gate is < (i.e. total+weight < max), which mirrors Core's >=.
    -- A tx with weight == remaining exactly must NOT fit.
    it("rejects a tx whose weight exactly reaches max_weight", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      local network = consensus.networks.regtest

      local tx = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0)},
                         {make_output(9000)})
      local entry = make_mempool_entry(tx, 1000)
      -- With reserved=8000, set weight so 8000 + w == max_weight exactly
      entry.weight = consensus.MAX_BLOCK_WEIGHT - 8000  -- equals limit exactly

      local mempool = make_mock_mempool({entry})
      local _, block = mining.create_block_template(mempool, chain_state, network, payout_script)
      -- 8000 + (4000000-8000) = 4000000, which is NOT < 4000000 => excluded
      assert.equal(1, #block.transactions)
    end)
  end)

  describe("MAX_CONSECUTIVE_FAILURES early exit (W87 — Bug 5)", function()
    it("stops adding txs after 1000 consecutive failures when block is near full", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      local network = consensus.networks.regtest

      -- Fill the block close to full with one big tx
      local big_tx = make_tx(1, {make_input(types.hash256(string.rep("\x01", 32)), 0)},
                              {make_output(9000)})
      local big_entry = make_mempool_entry(big_tx, 10000)
      -- 8000 + 3991000 = 3999000: close to full (within BLOCK_FULL_ENOUGH_WEIGHT_DELTA=4000)
      big_entry.weight = 3991000

      -- Add 1001 tiny txs that each exceed the remaining space
      local entries = {big_entry}
      for i = 1, 1001 do
        local small_tx = make_tx(1,
          {make_input(types.hash256(string.rep(string.char(i % 256), 32)), 0)},
          {make_output(100)})
        local small_entry = make_mempool_entry(small_tx, 1)
        small_entry.weight = 5000  -- 3999000 + 5000 = 4004000 > 4000000, so fails
        entries[#entries + 1] = small_entry
      end

      local mempool = make_mock_mempool(entries)
      -- Should complete without hanging (the early-exit fires after 1000 failures)
      local _, block = mining.create_block_template(mempool, chain_state, network, payout_script)
      -- Big tx is included; small ones excluded because they exceed the limit
      assert.equal(2, #block.transactions)
    end)
  end)

  describe("mintime = MTP+1 (W87 — Bug 6)", function()
    it("template mintime equals mtp+1", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      local mtp_val = 1700000000
      chain_state.mtp = mtp_val
      local network = consensus.networks.regtest

      local mempool = make_mock_mempool({})
      local template, _ = mining.create_block_template(mempool, chain_state, network, payout_script)

      assert.equal(mtp_val + 1, template.mintime)
    end)
  end)

  -- -------------------------------------------------------------------------
  -- W91: compute_block_version wiring in create_block_template
  -- Bug fixed: mining.lua used hardcoded 0x20000000 (no BIP9 signaling);
  -- must call consensus.compute_block_version.
  -- -------------------------------------------------------------------------
  describe("W91 compute_block_version wiring", function()
    local function make_block_info_fn(blocks)
      return function(h) return blocks[h] end
    end

    it("uses VERSIONBITS_TOP_BITS for networks without a deployments list", function()
      -- Mainnet and regtest have no .deployments key -> version is VERSIONBITS_TOP_BITS
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(100)
      local network = consensus.networks.regtest

      local mempool = make_mock_mempool({})
      local template, _ = mining.create_block_template(mempool, chain_state, network, payout_script)

      -- For a network with no active BIP9 deployments the version must equal TOP_BITS.
      assert.equal(consensus.VERSIONBITS_TOP_BITS, template.version)
    end)

    it("signals signaling bits when a deployment is in STARTED state", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(25)

      -- Build a synthetic network with one deployment on bit 1 that will be in
      -- STARTED state at height 26 (the block being assembled).
      local period    = 10
      local threshold = 8
      local dep = {bit = 1, start_time = 1000, timeout = 9999, min_activation_height = 0}
      local test_net = {
        name                  = "regtest",
        versionbits_period    = period,
        versionbits_threshold = threshold,
        deployments           = {dep},
        pow_limit_bits        = consensus.networks.regtest.pow_limit_bits,
        segwit_height         = 0,
        taproot_height        = 0,
        bip34_height          = 1,
        pow_no_retarget       = true,
        pow_allow_min_difficulty = true,
      }

      -- Period 0 (h=0..9): MTP >= start_time -> state at end of period 0 = STARTED.
      -- Period 1 (h=10..19): blocks in this period see STARTED.
      -- Period 2 starts at h=20; blocks here also query period 1 end (h=19) = STARTED.
      local blocks = {}
      for h = 0, 25 do
        blocks[h] = {timestamp = 1000, mtp = 1000, version = 0x20000000}
      end
      local get_block_info = make_block_info_fn(blocks)

      local mempool = make_mock_mempool({})
      local template, _ = mining.create_block_template(
        mempool, chain_state, test_net, payout_script, nil, get_block_info)

      -- The version must have the deployment bit set
      local expected = bit.bor(consensus.VERSIONBITS_TOP_BITS, bit.lshift(1, dep.bit))
      assert.equal(expected, template.version)
      -- Top 3 bits must still be 001
      assert.equal(consensus.VERSIONBITS_TOP_BITS,
        bit.band(template.version, consensus.VERSIONBITS_TOP_MASK))
    end)

    it("does NOT signal when deployment is DEFINED (not yet started)", function()
      local payout_script = make_payout_script()
      local chain_state = make_mock_chain_state(5)

      local dep = {bit = 1, start_time = 9999, timeout = 99999, min_activation_height = 0}
      local test_net = {
        name                  = "regtest",
        versionbits_period    = 10,
        versionbits_threshold = 8,
        deployments           = {dep},
        pow_limit_bits        = consensus.networks.regtest.pow_limit_bits,
        segwit_height         = 0,
        taproot_height        = 0,
        bip34_height          = 1,
        pow_no_retarget       = true,
        pow_allow_min_difficulty = true,
      }

      local blocks = {}
      for h = 0, 5 do
        blocks[h] = {timestamp = 100, mtp = 100, version = 0x20000000}
      end

      local mempool = make_mock_mempool({})
      local template, _ = mining.create_block_template(
        mempool, chain_state, test_net, payout_script, nil, make_block_info_fn(blocks))

      -- DEFINED -> no signaling; version must equal TOP_BITS
      assert.equal(consensus.VERSIONBITS_TOP_BITS, template.version)
    end)
  end)

end)
