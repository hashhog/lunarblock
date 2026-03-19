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
      assert.equal(0, coinbase.locktime)

      -- Check input is null coinbase
      local inp = coinbase.inputs[1]
      assert.equal(string.rep("\x00", 32), inp.prev_out.hash.bytes)
      assert.equal(0xFFFFFFFF, inp.prev_out.index)
      assert.equal(0xFFFFFFFF, inp.sequence)

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
    it("has sequence 0xFFFFFFFF", function()
      local payout_script = make_payout_script()
      local coinbase = mining.create_coinbase_tx(100, 5000000000, nil, nil, payout_script)

      assert.equal(0xFFFFFFFF, coinbase.inputs[1].sequence)
    end)

    it("has locktime 0", function()
      local payout_script = make_payout_script()
      local coinbase = mining.create_coinbase_tx(100, 5000000000, nil, nil, payout_script)

      assert.equal(0, coinbase.locktime)
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

end)
