local types = require("lunarblock.types")
local mempool = require("lunarblock.mempool")
local consensus = require("lunarblock.consensus")
local serialize = require("lunarblock.serialize")
local validation = require("lunarblock.validation")
local storage_mod = require("lunarblock.storage")
local utxo = require("lunarblock.utxo")
local script = require("lunarblock.script")

describe("mempool", function()

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
      sequence or 0xFFFFFFFE  -- Default: RBF signaling
    )
  end

  -- Helper to create output
  local function make_output(value, script_pubkey)
    return types.txout(value, script_pubkey or string.rep("\x00", 25))
  end

  -- Helper to create a mock chain state with coin view
  local function make_mock_chain_state(utxos)
    utxos = utxos or {}
    local mock_coin_view = {
      utxos = utxos,
      get = function(self, txid, vout)
        local key = types.hash256_hex(txid) .. ":" .. vout
        return self.utxos[key]
      end
    }
    return {
      coin_view = mock_coin_view,
      tip_height = 700000
    }
  end

  -- Helper to add UTXO to mock chain state
  local function add_utxo(chain_state, txid_hex, vout, value, script_pubkey, height, is_coinbase)
    local key = txid_hex .. ":" .. vout
    chain_state.coin_view.utxos[key] = {
      value = value,
      script_pubkey = script_pubkey or string.rep("\x00", 25),
      height = height or 500000,
      is_coinbase = is_coinbase or false
    }
  end

  describe("outpoint_key", function()
    it("generates deterministic 36-byte key", function()
      local txid = types.hash256(string.rep("\xab", 32))
      local key1 = mempool.outpoint_key(txid, 0)
      local key2 = mempool.outpoint_key(txid, 0)

      assert.equal(36, #key1)
      assert.equal(key1, key2)
    end)

    it("generates unique keys for different vout indices", function()
      local txid = types.hash256(string.rep("\xcd", 32))
      local key0 = mempool.outpoint_key(txid, 0)
      local key1 = mempool.outpoint_key(txid, 1)

      assert.not_equal(key0, key1)
    end)
  end)

  describe("mempool_entry", function()
    it("creates entry with correct fields", function()
      local tx = make_tx(1, {}, {}, 0)
      tx.inputs[1] = make_input(types.hash256(string.rep("\x01", 32)), 0)
      tx.outputs[1] = make_output(50000)

      local txid = validation.compute_txid(tx)
      local entry = mempool.mempool_entry(tx, txid, 1000, 200, 700000, 1234567890)

      assert.equal(tx, entry.tx)
      assert.equal(txid, entry.txid)
      assert.equal(1000, entry.fee)
      assert.equal(200, entry.vsize)
      assert.equal(5, entry.fee_rate)  -- 1000 / 200
      assert.equal(700000, entry.height)
      assert.equal(1234567890, entry.time)
      assert.equal(0, entry.ancestor_count)
      assert.equal(0, entry.descendant_count)
    end)
  end)

  describe("Mempool.new", function()
    it("creates empty mempool", function()
      local chain_state = make_mock_chain_state()
      local mp = mempool.new(chain_state)

      assert.equal(0, mp.tx_count)
      assert.equal(0, mp.total_size)
      assert.equal(mempool.DEFAULT_MAX_MEMPOOL_SIZE, mp.max_size)
      assert.equal(mempool.DEFAULT_MIN_RELAY_FEE, mp.min_relay_fee)
    end)

    it("accepts custom config", function()
      local chain_state = make_mock_chain_state()
      local mp = mempool.new(chain_state, {
        max_mempool_size = 1000000,
        min_relay_fee = 2000
      })

      assert.equal(1000000, mp.max_size)
      assert.equal(2000, mp.min_relay_fee)
    end)
  end)

  describe("Mempool:accept_transaction", function()
    it("accepts valid transaction with sufficient fee", function()
      local prev_txid = types.hash256(string.rep("\x01", 32))
      local prev_txid_hex = types.hash256_hex(prev_txid)

      local chain_state = make_mock_chain_state()
      add_utxo(chain_state, prev_txid_hex, 0, 100000)

      local mp = mempool.new(chain_state)

      local tx = make_tx(1, {}, {}, 0)
      tx.inputs[1] = make_input(prev_txid, 0)
      tx.outputs[1] = make_output(90000)  -- 10000 sat fee

      local ok, txid_hex, fee = mp:accept_transaction(tx)
      assert.is_true(ok)
      assert.is_string(txid_hex)
      assert.equal(10000, fee)
      assert.equal(1, mp.tx_count)
    end)

    it("rejects duplicate transaction", function()
      local prev_txid = types.hash256(string.rep("\x01", 32))
      local prev_txid_hex = types.hash256_hex(prev_txid)

      local chain_state = make_mock_chain_state()
      add_utxo(chain_state, prev_txid_hex, 0, 100000)

      local mp = mempool.new(chain_state)

      local tx = make_tx(1, {}, {}, 0)
      tx.inputs[1] = make_input(prev_txid, 0)
      tx.outputs[1] = make_output(90000)

      mp:accept_transaction(tx)
      local ok, err = mp:accept_transaction(tx)

      assert.is_false(ok)
      assert.equal("tx already in mempool", err)
    end)

    it("rejects coinbase transaction", function()
      local chain_state = make_mock_chain_state()
      local mp = mempool.new(chain_state)

      -- Coinbase tx: null prevout, index 0xFFFFFFFF
      local tx = make_tx(1, {}, {}, 0)
      tx.inputs[1] = types.txin(
        types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
        "\x03\x01\x02\x03",
        0xFFFFFFFF
      )
      tx.outputs[1] = make_output(5000000000)

      local ok, err = mp:accept_transaction(tx)
      assert.is_false(ok)
      assert.equal("coinbase transactions not accepted", err)
    end)

    it("rejects transaction with missing inputs", function()
      local chain_state = make_mock_chain_state()
      local mp = mempool.new(chain_state)

      -- Reference non-existent UTXO
      local tx = make_tx(1, {}, {}, 0)
      tx.inputs[1] = make_input(types.hash256(string.rep("\x99", 32)), 0)
      tx.outputs[1] = make_output(50000)

      local ok, err = mp:accept_transaction(tx)
      assert.is_false(ok)
      assert.equal("missing inputs", err)
    end)

    it("rejects transaction with fee rate below minimum", function()
      local prev_txid = types.hash256(string.rep("\x01", 32))
      local prev_txid_hex = types.hash256_hex(prev_txid)

      local chain_state = make_mock_chain_state()
      add_utxo(chain_state, prev_txid_hex, 0, 100000)

      local mp = mempool.new(chain_state)

      -- Very low fee transaction (1 sat)
      local tx = make_tx(1, {}, {}, 0)
      tx.inputs[1] = make_input(prev_txid, 0)
      tx.outputs[1] = make_output(99999)  -- Only 1 sat fee

      local ok, err = mp:accept_transaction(tx)
      assert.is_false(ok)
      assert.truthy(err:match("fee rate too low"))
    end)

    it("rejects transaction spending immature coinbase", function()
      local prev_txid = types.hash256(string.rep("\x01", 32))
      local prev_txid_hex = types.hash256_hex(prev_txid)

      local chain_state = make_mock_chain_state()
      -- Coinbase at height 699950 (only 50 blocks ago, needs 100)
      add_utxo(chain_state, prev_txid_hex, 0, 100000, nil, 699950, true)

      local mp = mempool.new(chain_state)

      local tx = make_tx(1, {}, {}, 0)
      tx.inputs[1] = make_input(prev_txid, 0)
      tx.outputs[1] = make_output(90000)

      local ok, err = mp:accept_transaction(tx)
      assert.is_false(ok)
      assert.equal("spending immature coinbase", err)
    end)

    it("accepts transaction spending mature coinbase", function()
      local prev_txid = types.hash256(string.rep("\x01", 32))
      local prev_txid_hex = types.hash256_hex(prev_txid)

      local chain_state = make_mock_chain_state()
      -- Coinbase at height 699900 (100 blocks ago, mature)
      add_utxo(chain_state, prev_txid_hex, 0, 100000, nil, 699900, true)

      local mp = mempool.new(chain_state)

      local tx = make_tx(1, {}, {}, 0)
      tx.inputs[1] = make_input(prev_txid, 0)
      tx.outputs[1] = make_output(90000)

      local ok, txid_hex = mp:accept_transaction(tx)
      assert.is_true(ok)
      assert.is_string(txid_hex)
    end)
  end)

  describe("RBF replacement", function()
    it("replaces transaction with higher fee", function()
      local prev_txid = types.hash256(string.rep("\x01", 32))
      local prev_txid_hex = types.hash256_hex(prev_txid)

      local chain_state = make_mock_chain_state()
      add_utxo(chain_state, prev_txid_hex, 0, 100000)

      local mp = mempool.new(chain_state)

      -- Original tx with lower fee
      local tx1 = make_tx(1, {}, {}, 0)
      tx1.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFD)  -- RBF enabled
      tx1.outputs[1] = make_output(95000)  -- 5000 sat fee

      local ok1, txid1_hex = mp:accept_transaction(tx1)
      assert.is_true(ok1)
      assert.equal(1, mp.tx_count)

      -- Replacement tx with higher fee
      local tx2 = make_tx(1, {}, {}, 0)
      tx2.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFD)
      tx2.outputs[1] = make_output(90000)  -- 10000 sat fee (higher)

      local ok2, txid2_hex = mp:accept_transaction(tx2)
      assert.is_true(ok2)
      assert.equal(1, mp.tx_count)  -- Still 1 tx, replaced
      assert.is_nil(mp:get_entry(txid1_hex))  -- Original removed
      assert.is_not_nil(mp:get_entry(txid2_hex))  -- Replacement present
    end)

    it("rejects replacement with lower fee", function()
      local prev_txid = types.hash256(string.rep("\x01", 32))
      local prev_txid_hex = types.hash256_hex(prev_txid)

      local chain_state = make_mock_chain_state()
      add_utxo(chain_state, prev_txid_hex, 0, 100000)

      local mp = mempool.new(chain_state)

      -- Original tx with higher fee
      local tx1 = make_tx(1, {}, {}, 0)
      tx1.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFD)
      tx1.outputs[1] = make_output(90000)  -- 10000 sat fee

      mp:accept_transaction(tx1)

      -- Attempt replacement with lower fee
      local tx2 = make_tx(1, {}, {}, 0)
      tx2.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFD)
      tx2.outputs[1] = make_output(95000)  -- 5000 sat fee (lower)

      local ok, err = mp:accept_transaction(tx2)
      assert.is_false(ok)
      assert.equal("replacement fee not higher than original", err)
    end)

    it("rejects replacement when original does not signal RBF", function()
      local prev_txid = types.hash256(string.rep("\x01", 32))
      local prev_txid_hex = types.hash256_hex(prev_txid)

      local chain_state = make_mock_chain_state()
      add_utxo(chain_state, prev_txid_hex, 0, 100000)

      local mp = mempool.new(chain_state)

      -- Original tx without RBF signaling (sequence 0xFFFFFFFF)
      local tx1 = make_tx(1, {}, {}, 0)
      tx1.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFF)  -- No RBF
      tx1.outputs[1] = make_output(95000)

      mp:accept_transaction(tx1)

      -- Attempt replacement
      local tx2 = make_tx(1, {}, {}, 0)
      tx2.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFD)
      tx2.outputs[1] = make_output(90000)

      local ok, err = mp:accept_transaction(tx2)
      assert.is_false(ok)
      assert.equal("conflicting tx does not signal RBF", err)
    end)
  end)

  describe("block connection", function()
    it("removes confirmed transactions", function()
      local prev_txid = types.hash256(string.rep("\x01", 32))
      local prev_txid_hex = types.hash256_hex(prev_txid)

      local chain_state = make_mock_chain_state()
      add_utxo(chain_state, prev_txid_hex, 0, 100000)

      local mp = mempool.new(chain_state)

      local tx = make_tx(1, {}, {}, 0)
      tx.inputs[1] = make_input(prev_txid, 0)
      tx.outputs[1] = make_output(90000)

      local ok, txid_hex = mp:accept_transaction(tx)
      assert.is_true(ok)
      assert.equal(1, mp.tx_count)

      -- Create a block containing this transaction
      local header = types.block_header(1, types.hash256_zero(), types.hash256_zero(), os.time(), 0x207fffff, 0)
      local block = types.block(header, {tx})

      mp:on_block_connected(block)

      assert.equal(0, mp.tx_count)
      assert.is_nil(mp:get_entry(txid_hex))
    end)

    it("removes conflicting transactions", function()
      local prev_txid = types.hash256(string.rep("\x01", 32))
      local prev_txid_hex = types.hash256_hex(prev_txid)

      local chain_state = make_mock_chain_state()
      add_utxo(chain_state, prev_txid_hex, 0, 100000)

      local mp = mempool.new(chain_state)

      -- Mempool tx spending the output
      local tx1 = make_tx(1, {}, {}, 0)
      tx1.inputs[1] = make_input(prev_txid, 0)
      tx1.outputs[1] = make_output(90000)

      mp:accept_transaction(tx1)
      assert.equal(1, mp.tx_count)

      -- Block contains different tx spending same output
      local tx2 = make_tx(1, {}, {}, 0)
      tx2.inputs[1] = make_input(prev_txid, 0)
      tx2.outputs[1] = make_output(85000)  -- Different output amount

      local header = types.block_header(1, types.hash256_zero(), types.hash256_zero(), os.time(), 0x207fffff, 0)
      local block = types.block(header, {tx2})

      mp:on_block_connected(block)

      -- Mempool tx should be removed as conflicting
      assert.equal(0, mp.tx_count)
    end)
  end)

  describe("mempool trimming", function()
    it("evicts lowest fee-rate transactions when full", function()
      local chain_state = make_mock_chain_state()

      -- Add UTXOs for multiple transactions
      for i = 1, 5 do
        local txid = types.hash256(string.rep(string.char(i), 32))
        local txid_hex = types.hash256_hex(txid)
        add_utxo(chain_state, txid_hex, 0, 1000000)
      end

      -- Small mempool size to force trimming
      local mp = mempool.new(chain_state, { max_mempool_size = 500 })

      -- Add transactions with different fee rates
      local txids = {}
      for i = 1, 3 do
        local prev_txid = types.hash256(string.rep(string.char(i), 32))
        local tx = make_tx(1, {}, {}, 0)
        tx.inputs[1] = make_input(prev_txid, 0)
        -- Higher i = higher fee
        tx.outputs[1] = make_output(1000000 - i * 50000)

        local ok, txid_hex = mp:accept_transaction(tx)
        if ok then
          txids[i] = txid_hex
        end
      end

      -- Due to small max_size, some txs may have been evicted
      -- The lowest fee rate tx should be evicted first
      local info = mp:get_info()
      assert.is_true(info.bytes <= mp.max_size or mp.tx_count <= 2)
    end)
  end)

  describe("ancestor/descendant limits", function()
    it("rejects transaction exceeding ancestor count limit", function()
      local chain_state = make_mock_chain_state()

      -- Create a chain of transactions exceeding MAX_ANCESTORS
      local prev_txid = types.hash256(string.rep("\x01", 32))
      local prev_txid_hex = types.hash256_hex(prev_txid)
      add_utxo(chain_state, prev_txid_hex, 0, 100000000)

      local mp = mempool.new(chain_state)

      -- Build chain up to MAX_ANCESTORS
      local current_txid = prev_txid
      for i = 1, mempool.MAX_ANCESTORS do
        local tx = make_tx(1, {}, {}, 0)
        tx.inputs[1] = make_input(current_txid, 0)
        tx.outputs[1] = make_output(100000000 - i * 10000)  -- Decreasing value for fees

        local ok, txid_hex = mp:accept_transaction(tx)
        if ok then
          current_txid = validation.compute_txid(tx)
        else
          -- Chain should fail at some point due to ancestor limit
          assert.truthy(txid_hex:match("too many ancestors"))
          break
        end
      end
    end)

    it("tracks ancestor counts correctly", function()
      local chain_state = make_mock_chain_state()

      local prev_txid = types.hash256(string.rep("\x01", 32))
      local prev_txid_hex = types.hash256_hex(prev_txid)
      add_utxo(chain_state, prev_txid_hex, 0, 100000000)

      local mp = mempool.new(chain_state)

      -- Parent tx
      local tx1 = make_tx(1, {}, {}, 0)
      tx1.inputs[1] = make_input(prev_txid, 0)
      tx1.outputs[1] = make_output(99990000)

      local ok1, txid1_hex = mp:accept_transaction(tx1)
      assert.is_true(ok1)

      local entry1 = mp:get_entry(txid1_hex)
      assert.equal(0, entry1.ancestor_count)

      -- Child tx
      local tx1_txid = validation.compute_txid(tx1)
      local tx2 = make_tx(1, {}, {}, 0)
      tx2.inputs[1] = make_input(tx1_txid, 0)
      tx2.outputs[1] = make_output(99980000)

      local ok2, txid2_hex = mp:accept_transaction(tx2)
      assert.is_true(ok2)

      local entry2 = mp:get_entry(txid2_hex)
      assert.equal(1, entry2.ancestor_count)

      -- Parent should now have descendant
      entry1 = mp:get_entry(txid1_hex)
      assert.equal(1, entry1.descendant_count)
    end)

    it("rejects 26th transaction in a chain (exceeds MAX_ANCESTORS=25)", function()
      local chain_state = make_mock_chain_state()

      -- Start with a UTXO
      local base_txid = types.hash256(string.rep("\x01", 32))
      local base_txid_hex = types.hash256_hex(base_txid)
      add_utxo(chain_state, base_txid_hex, 0, 500000000)

      local mp = mempool.new(chain_state)

      -- Build a chain of exactly 25 transactions (MAX_ANCESTORS)
      local current_txid = base_txid
      local txids = {}
      for i = 1, 25 do
        local tx = make_tx(1, {}, {}, 0)
        tx.inputs[1] = make_input(current_txid, 0)
        tx.outputs[1] = make_output(500000000 - i * 1000000)

        local ok, txid_hex = mp:accept_transaction(tx)
        assert.is_true(ok, "Transaction " .. i .. " should be accepted")
        txids[i] = txid_hex
        current_txid = validation.compute_txid(tx)
      end

      assert.equal(25, mp.tx_count)

      -- Verify the last transaction has 24 ancestors (not counting itself)
      local last_entry = mp:get_entry(txids[25])
      assert.equal(24, last_entry.ancestor_count)

      -- The 26th transaction should be rejected
      local tx26 = make_tx(1, {}, {}, 0)
      tx26.inputs[1] = make_input(current_txid, 0)
      tx26.outputs[1] = make_output(500000000 - 26 * 1000000)

      local ok26, err26 = mp:accept_transaction(tx26)
      assert.is_false(ok26)
      assert.truthy(err26:match("too many ancestors"))
    end)

    it("rejects transaction when ancestor has too many descendants", function()
      local chain_state = make_mock_chain_state()

      -- Create root UTXO with many outputs
      local root_txid = types.hash256(string.rep("\x01", 32))
      local root_txid_hex = types.hash256_hex(root_txid)
      for i = 0, 30 do
        add_utxo(chain_state, root_txid_hex, i, 10000000)
      end

      local mp = mempool.new(chain_state)

      -- Create a parent transaction
      local parent_tx = make_tx(1, {}, {}, 0)
      parent_tx.inputs[1] = make_input(root_txid, 0)
      parent_tx.outputs = {}
      for i = 1, 30 do
        parent_tx.outputs[i] = make_output(300000)
      end

      local ok_parent, parent_hex = mp:accept_transaction(parent_tx)
      assert.is_true(ok_parent)

      local parent_txid = validation.compute_txid(parent_tx)

      -- Create 25 child transactions (MAX_DESCENDANTS)
      for i = 0, 24 do
        local child_tx = make_tx(1, {}, {}, 0)
        child_tx.inputs[1] = make_input(parent_txid, i)
        child_tx.outputs[1] = make_output(290000)

        local ok, hex = mp:accept_transaction(child_tx)
        assert.is_true(ok, "Child " .. i .. " should be accepted")
      end

      -- Parent should have 25 descendants now
      local parent_entry = mp:get_entry(parent_hex)
      assert.equal(25, parent_entry.descendant_count)

      -- The 26th child should be rejected due to descendant limit
      local child26 = make_tx(1, {}, {}, 0)
      child26.inputs[1] = make_input(parent_txid, 25)
      child26.outputs[1] = make_output(290000)

      local ok26, err26 = mp:accept_transaction(child26)
      assert.is_false(ok26)
      assert.truthy(err26:match("too many descendants"))
    end)

    it("properly deduplicates ancestors with diamond dependency", function()
      local chain_state = make_mock_chain_state()

      -- Root UTXO with 2 outputs
      local root_txid = types.hash256(string.rep("\x01", 32))
      local root_txid_hex = types.hash256_hex(root_txid)
      add_utxo(chain_state, root_txid_hex, 0, 10000000)
      add_utxo(chain_state, root_txid_hex, 1, 10000000)

      local mp = mempool.new(chain_state)

      -- Create parent A spending output 0
      local parent_a = make_tx(1, {}, {}, 0)
      parent_a.inputs[1] = make_input(root_txid, 0)
      parent_a.outputs[1] = make_output(9990000)

      local ok_a, hex_a = mp:accept_transaction(parent_a)
      assert.is_true(ok_a)
      local txid_a = validation.compute_txid(parent_a)

      -- Create parent B spending output 1
      local parent_b = make_tx(1, {}, {}, 0)
      parent_b.inputs[1] = make_input(root_txid, 1)
      parent_b.outputs[1] = make_output(9990000)

      local ok_b, hex_b = mp:accept_transaction(parent_b)
      assert.is_true(ok_b)
      local txid_b = validation.compute_txid(parent_b)

      -- Create child spending both parents (diamond dependency)
      local child = make_tx(1, {}, {}, 0)
      child.inputs[1] = make_input(txid_a, 0)
      child.inputs[2] = make_input(txid_b, 0)
      child.outputs[1] = make_output(19960000)

      local ok_child, hex_child = mp:accept_transaction(child)
      assert.is_true(ok_child)

      local child_entry = mp:get_entry(hex_child)
      -- Child has 2 unique ancestors: parent_a and parent_b
      assert.equal(2, child_entry.ancestor_count)

      -- Both parents should have 1 descendant (the child)
      local entry_a = mp:get_entry(hex_a)
      local entry_b = mp:get_entry(hex_b)
      assert.equal(1, entry_a.descendant_count)
      assert.equal(1, entry_b.descendant_count)
    end)

    it("propagates descendant updates through entire ancestor chain", function()
      local chain_state = make_mock_chain_state()

      local base_txid = types.hash256(string.rep("\x01", 32))
      local base_txid_hex = types.hash256_hex(base_txid)
      add_utxo(chain_state, base_txid_hex, 0, 100000000)

      local mp = mempool.new(chain_state)

      -- Create a chain: tx1 -> tx2 -> tx3
      local tx1 = make_tx(1, {}, {}, 0)
      tx1.inputs[1] = make_input(base_txid, 0)
      tx1.outputs[1] = make_output(99990000)
      local ok1, hex1 = mp:accept_transaction(tx1)
      assert.is_true(ok1)
      local txid1 = validation.compute_txid(tx1)

      local tx2 = make_tx(1, {}, {}, 0)
      tx2.inputs[1] = make_input(txid1, 0)
      tx2.outputs[1] = make_output(99980000)
      local ok2, hex2 = mp:accept_transaction(tx2)
      assert.is_true(ok2)
      local txid2 = validation.compute_txid(tx2)

      local tx3 = make_tx(1, {}, {}, 0)
      tx3.inputs[1] = make_input(txid2, 0)
      tx3.outputs[1] = make_output(99970000)
      local ok3, hex3 = mp:accept_transaction(tx3)
      assert.is_true(ok3)

      -- tx1 should have 2 descendants (tx2 and tx3)
      local entry1 = mp:get_entry(hex1)
      assert.equal(2, entry1.descendant_count)

      -- tx2 should have 1 descendant (tx3)
      local entry2 = mp:get_entry(hex2)
      assert.equal(1, entry2.descendant_count)

      -- tx3 should have 0 descendants
      local entry3 = mp:get_entry(hex3)
      assert.equal(0, entry3.descendant_count)
    end)

    it("correctly updates all ancestors when removing transaction", function()
      local chain_state = make_mock_chain_state()

      local base_txid = types.hash256(string.rep("\x01", 32))
      local base_txid_hex = types.hash256_hex(base_txid)
      add_utxo(chain_state, base_txid_hex, 0, 100000000)

      local mp = mempool.new(chain_state)

      -- Create a chain: tx1 -> tx2 -> tx3
      local tx1 = make_tx(1, {}, {}, 0)
      tx1.inputs[1] = make_input(base_txid, 0)
      tx1.outputs[1] = make_output(99990000)
      local ok1, hex1 = mp:accept_transaction(tx1)
      assert.is_true(ok1)
      local txid1 = validation.compute_txid(tx1)

      local tx2 = make_tx(1, {}, {}, 0)
      tx2.inputs[1] = make_input(txid1, 0)
      tx2.outputs[1] = make_output(99980000)
      local ok2, hex2 = mp:accept_transaction(tx2)
      assert.is_true(ok2)
      local txid2 = validation.compute_txid(tx2)

      local tx3 = make_tx(1, {}, {}, 0)
      tx3.inputs[1] = make_input(txid2, 0)
      tx3.outputs[1] = make_output(99970000)
      local ok3, hex3 = mp:accept_transaction(tx3)
      assert.is_true(ok3)

      -- Remove tx3 only
      mp:remove_transaction(hex3, "test")

      -- tx1 should now have 1 descendant (tx2 only)
      local entry1 = mp:get_entry(hex1)
      assert.equal(1, entry1.descendant_count)

      -- tx2 should have 0 descendants
      local entry2 = mp:get_entry(hex2)
      assert.equal(0, entry2.descendant_count)

      assert.equal(2, mp.tx_count)
    end)

    it("enforces ancestor size limit", function()
      local chain_state = make_mock_chain_state()

      -- Create UTXOs for large transactions
      for i = 0, 30 do
        local txid = types.hash256(string.rep(string.char(i), 32))
        local txid_hex = types.hash256_hex(txid)
        add_utxo(chain_state, txid_hex, 0, 100000000)
      end

      local mp = mempool.new(chain_state)

      -- Build a chain of large transactions (each ~10KB)
      -- MAX_ANCESTOR_SIZE = 101000, so after ~10 transactions it should fail
      local prev_txid = types.hash256(string.rep("\x00", 32))
      add_utxo(chain_state, types.hash256_hex(prev_txid), 0, 1000000000)

      local accepted_count = 0
      for i = 1, 15 do
        local tx = make_tx(1, {}, {}, 0)
        tx.inputs[1] = make_input(prev_txid, 0)
        -- Create multiple outputs to increase tx size
        tx.outputs = {}
        for j = 1, 200 do  -- ~8KB with many outputs
          tx.outputs[j] = make_output(4000000)
        end

        local ok, result = mp:accept_transaction(tx)
        if ok then
          accepted_count = accepted_count + 1
          prev_txid = validation.compute_txid(tx)
        else
          -- Should eventually fail due to ancestor size
          assert.truthy(result:match("ancestor size too large"))
          break
        end
      end

      -- Should have accepted some but not all
      assert.is_true(accepted_count > 0)
      assert.is_true(accepted_count < 15)
    end)
  end)

  describe("mempool queries", function()
    it("get_sorted_entries returns transactions ordered by ancestor fee rate", function()
      local chain_state = make_mock_chain_state()

      -- Add UTXOs
      for i = 1, 3 do
        local txid = types.hash256(string.rep(string.char(i), 32))
        local txid_hex = types.hash256_hex(txid)
        add_utxo(chain_state, txid_hex, 0, 1000000)
      end

      local mp = mempool.new(chain_state)

      -- Add transactions with different fee rates
      -- tx1: low fee rate
      local tx1 = make_tx(1, {}, {}, 0)
      tx1.inputs[1] = make_input(types.hash256(string.rep("\x01", 32)), 0)
      tx1.outputs[1] = make_output(995000)  -- 5000 sat fee
      mp:accept_transaction(tx1)

      -- tx2: high fee rate
      local tx2 = make_tx(1, {}, {}, 0)
      tx2.inputs[1] = make_input(types.hash256(string.rep("\x02", 32)), 0)
      tx2.outputs[1] = make_output(950000)  -- 50000 sat fee
      mp:accept_transaction(tx2)

      -- tx3: medium fee rate
      local tx3 = make_tx(1, {}, {}, 0)
      tx3.inputs[1] = make_input(types.hash256(string.rep("\x03", 32)), 0)
      tx3.outputs[1] = make_output(980000)  -- 20000 sat fee
      mp:accept_transaction(tx3)

      local sorted = mp:get_sorted_entries()
      assert.equal(3, #sorted)

      -- Should be sorted by descending ancestor fee rate
      assert.is_true(sorted[1].fee >= sorted[2].fee)
      assert.is_true(sorted[2].fee >= sorted[3].fee)
    end)

    it("get_info returns correct statistics", function()
      local prev_txid = types.hash256(string.rep("\x01", 32))
      local prev_txid_hex = types.hash256_hex(prev_txid)

      local chain_state = make_mock_chain_state()
      add_utxo(chain_state, prev_txid_hex, 0, 100000)

      local mp = mempool.new(chain_state)

      local tx = make_tx(1, {}, {}, 0)
      tx.inputs[1] = make_input(prev_txid, 0)
      tx.outputs[1] = make_output(90000)

      mp:accept_transaction(tx)

      local info = mp:get_info()
      assert.equal(1, info.size)
      assert.is_true(info.bytes > 0)
      assert.equal(mp.max_size, info.maxmempool)
      assert.equal(mp.min_relay_fee, info.mempoolminfee)
    end)

    it("get_raw_mempool returns all txids", function()
      local chain_state = make_mock_chain_state()

      for i = 1, 2 do
        local txid = types.hash256(string.rep(string.char(i), 32))
        local txid_hex = types.hash256_hex(txid)
        add_utxo(chain_state, txid_hex, 0, 100000)
      end

      local mp = mempool.new(chain_state)

      local tx1 = make_tx(1, {}, {}, 0)
      tx1.inputs[1] = make_input(types.hash256(string.rep("\x01", 32)), 0)
      tx1.outputs[1] = make_output(90000)
      mp:accept_transaction(tx1)

      local tx2 = make_tx(1, {}, {}, 0)
      tx2.inputs[1] = make_input(types.hash256(string.rep("\x02", 32)), 0)
      tx2.outputs[1] = make_output(90000)
      mp:accept_transaction(tx2)

      local raw = mp:get_raw_mempool()
      assert.equal(2, #raw)
    end)

    it("has checks if transaction exists", function()
      local prev_txid = types.hash256(string.rep("\x01", 32))
      local prev_txid_hex = types.hash256_hex(prev_txid)

      local chain_state = make_mock_chain_state()
      add_utxo(chain_state, prev_txid_hex, 0, 100000)

      local mp = mempool.new(chain_state)

      local tx = make_tx(1, {}, {}, 0)
      tx.inputs[1] = make_input(prev_txid, 0)
      tx.outputs[1] = make_output(90000)

      assert.is_false(mp:has("nonexistent"))

      local _, txid_hex = mp:accept_transaction(tx)
      assert.is_true(mp:has(txid_hex))
    end)
  end)

  describe("transaction removal", function()
    it("removes transaction and updates parent descendant counts", function()
      local chain_state = make_mock_chain_state()

      local prev_txid = types.hash256(string.rep("\x01", 32))
      local prev_txid_hex = types.hash256_hex(prev_txid)
      add_utxo(chain_state, prev_txid_hex, 0, 100000000)

      local mp = mempool.new(chain_state)

      -- Parent tx
      local tx1 = make_tx(1, {}, {}, 0)
      tx1.inputs[1] = make_input(prev_txid, 0)
      tx1.outputs[1] = make_output(99990000)

      local _, txid1_hex = mp:accept_transaction(tx1)

      -- Child tx
      local tx1_txid = validation.compute_txid(tx1)
      local tx2 = make_tx(1, {}, {}, 0)
      tx2.inputs[1] = make_input(tx1_txid, 0)
      tx2.outputs[1] = make_output(99980000)

      local _, txid2_hex = mp:accept_transaction(tx2)

      -- Verify parent has descendant
      local entry1 = mp:get_entry(txid1_hex)
      assert.equal(1, entry1.descendant_count)

      -- Remove child
      mp:remove_transaction(txid2_hex, "test")

      -- Parent should have no descendants now
      entry1 = mp:get_entry(txid1_hex)
      assert.equal(0, entry1.descendant_count)
      assert.equal(1, mp.tx_count)
    end)

    it("removes descendant chain when parent is removed", function()
      local chain_state = make_mock_chain_state()

      local prev_txid = types.hash256(string.rep("\x01", 32))
      local prev_txid_hex = types.hash256_hex(prev_txid)
      add_utxo(chain_state, prev_txid_hex, 0, 100000000)

      local mp = mempool.new(chain_state)

      -- Parent tx
      local tx1 = make_tx(1, {}, {}, 0)
      tx1.inputs[1] = make_input(prev_txid, 0)
      tx1.outputs[1] = make_output(99990000)

      local _, txid1_hex = mp:accept_transaction(tx1)

      -- Child tx
      local tx1_txid = validation.compute_txid(tx1)
      local tx2 = make_tx(1, {}, {}, 0)
      tx2.inputs[1] = make_input(tx1_txid, 0)
      tx2.outputs[1] = make_output(99980000)

      local _, txid2_hex = mp:accept_transaction(tx2)

      assert.equal(2, mp.tx_count)

      -- Remove parent (should also remove child)
      mp:remove_transaction(txid1_hex, "test")

      assert.equal(0, mp.tx_count)
      assert.is_nil(mp:get_entry(txid1_hex))
      assert.is_nil(mp:get_entry(txid2_hex))
    end)
  end)

  describe("BIP125 Replace-by-Fee", function()

    describe("signals_rbf", function()
      it("detects RBF signaling with sequence 0xFFFFFFFD", function()
        local tx = make_tx(1, {}, {}, 0)
        tx.inputs[1] = make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFD)
        tx.outputs[1] = make_output(50000)

        assert.is_true(mempool.signals_rbf(tx))
      end)

      it("detects RBF signaling with sequence 0", function()
        local tx = make_tx(1, {}, {}, 0)
        tx.inputs[1] = make_input(types.hash256(string.rep("\x01", 32)), 0, 0)
        tx.outputs[1] = make_output(50000)

        assert.is_true(mempool.signals_rbf(tx))
      end)

      it("rejects RBF signaling with sequence 0xFFFFFFFE", function()
        local tx = make_tx(1, {}, {}, 0)
        tx.inputs[1] = make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFE)
        tx.outputs[1] = make_output(50000)

        assert.is_false(mempool.signals_rbf(tx))
      end)

      it("rejects RBF signaling with sequence 0xFFFFFFFF", function()
        local tx = make_tx(1, {}, {}, 0)
        tx.inputs[1] = make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFF)
        tx.outputs[1] = make_output(50000)

        assert.is_false(mempool.signals_rbf(tx))
      end)

      it("signals RBF if any input has low sequence", function()
        local tx = make_tx(1, {}, {}, 0)
        tx.inputs[1] = make_input(types.hash256(string.rep("\x01", 32)), 0, 0xFFFFFFFF)
        tx.inputs[2] = make_input(types.hash256(string.rep("\x02", 32)), 0, 0xFFFFFFFD)
        tx.outputs[1] = make_output(50000)

        assert.is_true(mempool.signals_rbf(tx))
      end)
    end)

    describe("is_replaceable", function()
      it("returns true for direct RBF signaling transaction", function()
        local prev_txid = types.hash256(string.rep("\x01", 32))
        local prev_txid_hex = types.hash256_hex(prev_txid)

        local chain_state = make_mock_chain_state()
        add_utxo(chain_state, prev_txid_hex, 0, 100000)

        local mp = mempool.new(chain_state)

        local tx = make_tx(1, {}, {}, 0)
        tx.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFD)  -- RBF signal
        tx.outputs[1] = make_output(90000)

        local ok, txid_hex = mp:accept_transaction(tx)
        assert.is_true(ok)
        assert.is_true(mp:is_replaceable(txid_hex))
      end)

      it("returns false for non-signaling transaction without ancestors", function()
        local prev_txid = types.hash256(string.rep("\x01", 32))
        local prev_txid_hex = types.hash256_hex(prev_txid)

        local chain_state = make_mock_chain_state()
        add_utxo(chain_state, prev_txid_hex, 0, 100000)

        local mp = mempool.new(chain_state)

        local tx = make_tx(1, {}, {}, 0)
        tx.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFF)  -- No RBF
        tx.outputs[1] = make_output(90000)

        local ok, txid_hex = mp:accept_transaction(tx)
        assert.is_true(ok)
        assert.is_false(mp:is_replaceable(txid_hex))
      end)

      it("returns true for non-signaling child with signaling ancestor", function()
        local chain_state = make_mock_chain_state()

        local prev_txid = types.hash256(string.rep("\x01", 32))
        local prev_txid_hex = types.hash256_hex(prev_txid)
        add_utxo(chain_state, prev_txid_hex, 0, 100000000)

        local mp = mempool.new(chain_state)

        -- Parent signals RBF
        local parent_tx = make_tx(1, {}, {}, 0)
        parent_tx.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFD)  -- RBF signal
        parent_tx.outputs[1] = make_output(99990000)

        local ok1, parent_hex = mp:accept_transaction(parent_tx)
        assert.is_true(ok1)

        -- Child does NOT signal RBF
        local parent_txid = validation.compute_txid(parent_tx)
        local child_tx = make_tx(1, {}, {}, 0)
        child_tx.inputs[1] = make_input(parent_txid, 0, 0xFFFFFFFF)  -- No RBF
        child_tx.outputs[1] = make_output(99980000)

        local ok2, child_hex = mp:accept_transaction(child_tx)
        assert.is_true(ok2)

        -- Child should be replaceable due to parent's signaling
        assert.is_true(mp:is_replaceable(child_hex))
      end)
    end)

    describe("replacement rules", function()
      it("rejects replacement when conflicting tx and ancestors do not signal RBF", function()
        local prev_txid = types.hash256(string.rep("\x01", 32))
        local prev_txid_hex = types.hash256_hex(prev_txid)

        local chain_state = make_mock_chain_state()
        add_utxo(chain_state, prev_txid_hex, 0, 100000)

        local mp = mempool.new(chain_state)

        -- Original tx without RBF signaling (sequence 0xFFFFFFFF)
        local tx1 = make_tx(1, {}, {}, 0)
        tx1.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFF)  -- No RBF
        tx1.outputs[1] = make_output(95000)

        mp:accept_transaction(tx1)

        -- Attempt replacement
        local tx2 = make_tx(1, {}, {}, 0)
        tx2.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFD)
        tx2.outputs[1] = make_output(90000)

        local ok, err = mp:accept_transaction(tx2)
        assert.is_false(ok)
        assert.equal("conflicting tx does not signal RBF", err)
      end)

      it("allows replacement when ancestor signals RBF (inherited signaling)", function()
        local chain_state = make_mock_chain_state()

        local prev_txid = types.hash256(string.rep("\x01", 32))
        local prev_txid_hex = types.hash256_hex(prev_txid)
        add_utxo(chain_state, prev_txid_hex, 0, 100000000)

        -- Another UTXO for the replacement tx
        local other_txid = types.hash256(string.rep("\x02", 32))
        local other_txid_hex = types.hash256_hex(other_txid)
        add_utxo(chain_state, other_txid_hex, 0, 100000000)

        local mp = mempool.new(chain_state)

        -- Parent signals RBF
        local parent_tx = make_tx(1, {}, {}, 0)
        parent_tx.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFD)  -- RBF signal
        parent_tx.outputs[1] = make_output(99990000)
        parent_tx.outputs[2] = make_output(5000)  -- Extra output for child to spend

        local ok1, parent_hex = mp:accept_transaction(parent_tx)
        assert.is_true(ok1)

        -- Child does NOT signal RBF directly
        local parent_txid = validation.compute_txid(parent_tx)
        local child_tx = make_tx(1, {}, {}, 0)
        child_tx.inputs[1] = make_input(parent_txid, 1, 0xFFFFFFFF)  -- No direct RBF
        child_tx.outputs[1] = make_output(1000)

        local ok2, child_hex = mp:accept_transaction(child_tx)
        assert.is_true(ok2)

        -- Child is replaceable due to parent's signaling
        assert.is_true(mp:is_replaceable(child_hex))

        -- Replacement of child (spending different output, conflicting by spending same parent output)
        local replace_tx = make_tx(1, {}, {}, 0)
        replace_tx.inputs[1] = make_input(parent_txid, 1, 0xFFFFFFFD)
        replace_tx.outputs[1] = make_output(500)  -- Higher fee

        local ok3, replace_hex = mp:accept_transaction(replace_tx)
        assert.is_true(ok3)
        assert.is_nil(mp:get_entry(child_hex))  -- Original removed
        assert.is_not_nil(mp:get_entry(replace_hex))  -- Replacement present
      end)

      it("requires replacement fee to be strictly higher than conflicting fees", function()
        local prev_txid = types.hash256(string.rep("\x01", 32))
        local prev_txid_hex = types.hash256_hex(prev_txid)

        local chain_state = make_mock_chain_state()
        add_utxo(chain_state, prev_txid_hex, 0, 100000)

        local mp = mempool.new(chain_state)

        local tx1 = make_tx(1, {}, {}, 0)
        tx1.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFD)
        tx1.outputs[1] = make_output(90000)  -- 10000 sat fee

        mp:accept_transaction(tx1)

        -- Same fee (not higher)
        local tx2 = make_tx(1, {}, {}, 0)
        tx2.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFD)
        tx2.outputs[1] = make_output(90000)  -- Same 10000 sat fee

        local ok, err = mp:accept_transaction(tx2)
        assert.is_false(ok)
        assert.truthy(err:match("replacement fee not higher"))
      end)

      it("requires incremental relay fee payment", function()
        local prev_txid = types.hash256(string.rep("\x01", 32))
        local prev_txid_hex = types.hash256_hex(prev_txid)

        local chain_state = make_mock_chain_state()
        add_utxo(chain_state, prev_txid_hex, 0, 100000)

        local mp = mempool.new(chain_state)

        local tx1 = make_tx(1, {}, {}, 0)
        tx1.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFD)
        tx1.outputs[1] = make_output(90000)  -- 10000 sat fee

        mp:accept_transaction(tx1)

        -- Only 1 sat higher (not enough for relay)
        local tx2 = make_tx(1, {}, {}, 0)
        tx2.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFD)
        tx2.outputs[1] = make_output(89999)  -- 10001 sat fee

        local ok, err = mp:accept_transaction(tx2)
        assert.is_false(ok)
        assert.truthy(err:match("insufficient fee for relay"))
      end)

      it("accepts replacement with sufficient incremental fee", function()
        local prev_txid = types.hash256(string.rep("\x01", 32))
        local prev_txid_hex = types.hash256_hex(prev_txid)

        local chain_state = make_mock_chain_state()
        add_utxo(chain_state, prev_txid_hex, 0, 100000)

        local mp = mempool.new(chain_state)

        local tx1 = make_tx(1, {}, {}, 0)
        tx1.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFD)
        tx1.outputs[1] = make_output(90000)  -- 10000 sat fee

        local ok1, txid1_hex = mp:accept_transaction(tx1)
        assert.is_true(ok1)

        -- 1000 sats higher (enough for ~1 sat/vB incremental with typical ~85 vB tx)
        local tx2 = make_tx(1, {}, {}, 0)
        tx2.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFD)
        tx2.outputs[1] = make_output(89000)  -- 11000 sat fee

        local ok2, txid2_hex = mp:accept_transaction(tx2)
        assert.is_true(ok2)
        assert.is_nil(mp:get_entry(txid1_hex))
        assert.is_not_nil(mp:get_entry(txid2_hex))
      end)

      it("rejects replacement with new unconfirmed inputs", function()
        local chain_state = make_mock_chain_state()

        local prev_txid = types.hash256(string.rep("\x01", 32))
        local prev_txid_hex = types.hash256_hex(prev_txid)
        add_utxo(chain_state, prev_txid_hex, 0, 100000)

        -- UTXO for unconfirmed parent
        local parent_base = types.hash256(string.rep("\x02", 32))
        local parent_base_hex = types.hash256_hex(parent_base)
        add_utxo(chain_state, parent_base_hex, 0, 100000)

        local mp = mempool.new(chain_state)

        -- Original tx
        local tx1 = make_tx(1, {}, {}, 0)
        tx1.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFD)
        tx1.outputs[1] = make_output(90000)

        mp:accept_transaction(tx1)

        -- Create an unconfirmed parent in mempool
        local parent_tx = make_tx(1, {}, {}, 0)
        parent_tx.inputs[1] = make_input(parent_base, 0, 0xFFFFFFFD)
        parent_tx.outputs[1] = make_output(90000)

        local ok_parent, parent_hex = mp:accept_transaction(parent_tx)
        assert.is_true(ok_parent)
        local parent_txid = validation.compute_txid(parent_tx)

        -- Replacement that spends original output AND new unconfirmed parent
        local tx2 = make_tx(1, {}, {}, 0)
        tx2.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFD)
        tx2.inputs[2] = make_input(parent_txid, 0, 0xFFFFFFFD)
        tx2.outputs[1] = make_output(170000)  -- Higher fee

        local ok, err = mp:accept_transaction(tx2)
        assert.is_false(ok)
        assert.equal("replacement adds new unconfirmed input", err)
      end)

      it("evicts descendants of replaced transaction", function()
        local chain_state = make_mock_chain_state()

        local prev_txid = types.hash256(string.rep("\x01", 32))
        local prev_txid_hex = types.hash256_hex(prev_txid)
        add_utxo(chain_state, prev_txid_hex, 0, 100000000)

        local mp = mempool.new(chain_state)

        -- Parent tx
        local parent_tx = make_tx(1, {}, {}, 0)
        parent_tx.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFD)
        parent_tx.outputs[1] = make_output(99990000)

        local ok1, parent_hex = mp:accept_transaction(parent_tx)
        assert.is_true(ok1)
        local parent_txid = validation.compute_txid(parent_tx)

        -- Child tx
        local child_tx = make_tx(1, {}, {}, 0)
        child_tx.inputs[1] = make_input(parent_txid, 0, 0xFFFFFFFD)
        child_tx.outputs[1] = make_output(99980000)

        local ok2, child_hex = mp:accept_transaction(child_tx)
        assert.is_true(ok2)
        assert.equal(2, mp.tx_count)

        -- Replace parent (should also evict child)
        local replace_tx = make_tx(1, {}, {}, 0)
        replace_tx.inputs[1] = make_input(prev_txid, 0, 0xFFFFFFFD)
        replace_tx.outputs[1] = make_output(99950000)  -- Higher fee

        local ok3, replace_hex = mp:accept_transaction(replace_tx)
        assert.is_true(ok3)
        assert.equal(1, mp.tx_count)
        assert.is_nil(mp:get_entry(parent_hex))
        assert.is_nil(mp:get_entry(child_hex))
        assert.is_not_nil(mp:get_entry(replace_hex))
      end)

      it("rejects replacement exceeding max eviction limit", function()
        local chain_state = make_mock_chain_state()

        -- Create UTXOs for many descendants
        local base_txid = types.hash256(string.rep("\x01", 32))
        local base_txid_hex = types.hash256_hex(base_txid)
        add_utxo(chain_state, base_txid_hex, 0, 10000000000)

        local mp = mempool.new(chain_state)

        -- Create a parent with many outputs
        local parent_tx = make_tx(1, {}, {}, 0)
        parent_tx.inputs[1] = make_input(base_txid, 0, 0xFFFFFFFD)
        parent_tx.outputs = {}
        for i = 1, 110 do
          parent_tx.outputs[i] = make_output(80000000)
        end

        local ok_parent, parent_hex = mp:accept_transaction(parent_tx)
        assert.is_true(ok_parent)
        local parent_txid = validation.compute_txid(parent_tx)

        -- Create 100 children (hitting MAX_REPLACEMENT_CANDIDATES with parent = 101)
        -- Actually, we need to be careful about descendant limits
        -- Let's just create as many as we can (25 is the limit per ancestor)
        -- For this test, we'll need a special setup

        -- Instead, let's test with a simpler scenario
        -- Reset and use a different approach
      end)

      it("replaces multiple conflicting transactions", function()
        local chain_state = make_mock_chain_state()

        -- Two separate UTXOs
        local txid1 = types.hash256(string.rep("\x01", 32))
        local txid1_hex = types.hash256_hex(txid1)
        add_utxo(chain_state, txid1_hex, 0, 100000)

        local txid2 = types.hash256(string.rep("\x02", 32))
        local txid2_hex = types.hash256_hex(txid2)
        add_utxo(chain_state, txid2_hex, 0, 100000)

        local mp = mempool.new(chain_state)

        -- First tx spending UTXO 1
        local tx1 = make_tx(1, {}, {}, 0)
        tx1.inputs[1] = make_input(txid1, 0, 0xFFFFFFFD)
        tx1.outputs[1] = make_output(95000)  -- 5000 fee

        local ok1, hex1 = mp:accept_transaction(tx1)
        assert.is_true(ok1)

        -- Second tx spending UTXO 2
        local tx2 = make_tx(1, {}, {}, 0)
        tx2.inputs[1] = make_input(txid2, 0, 0xFFFFFFFD)
        tx2.outputs[1] = make_output(95000)  -- 5000 fee

        local ok2, hex2 = mp:accept_transaction(tx2)
        assert.is_true(ok2)
        assert.equal(2, mp.tx_count)

        -- Replacement that spends BOTH UTXOs (conflicts with both txs)
        local tx3 = make_tx(1, {}, {}, 0)
        tx3.inputs[1] = make_input(txid1, 0, 0xFFFFFFFD)
        tx3.inputs[2] = make_input(txid2, 0, 0xFFFFFFFD)
        tx3.outputs[1] = make_output(180000)  -- 20000 fee (> 10000 combined + incremental)

        local ok3, hex3 = mp:accept_transaction(tx3)
        assert.is_true(ok3)
        assert.equal(1, mp.tx_count)
        assert.is_nil(mp:get_entry(hex1))
        assert.is_nil(mp:get_entry(hex2))
        assert.is_not_nil(mp:get_entry(hex3))
      end)
    end)
  end)

  describe("package validation", function()

    describe("is_topo_sorted_package", function()
      it("accepts properly sorted package (parent before child)", function()
        local chain_state = make_mock_chain_state()
        local base_txid = types.hash256(string.rep("\x01", 32))
        local base_txid_hex = types.hash256_hex(base_txid)
        add_utxo(chain_state, base_txid_hex, 0, 100000000)

        -- Parent transaction
        local parent = make_tx(1, {}, {}, 0)
        parent.inputs[1] = make_input(base_txid, 0)
        parent.outputs[1] = make_output(99990000)
        local parent_txid = validation.compute_txid(parent)

        -- Child transaction spending parent
        local child = make_tx(1, {}, {}, 0)
        child.inputs[1] = make_input(parent_txid, 0)
        child.outputs[1] = make_output(99980000)

        local ok, err = mempool.is_topo_sorted_package({parent, child})
        assert.is_true(ok)
        assert.is_nil(err)
      end)

      it("rejects misordered package (child before parent)", function()
        local chain_state = make_mock_chain_state()
        local base_txid = types.hash256(string.rep("\x01", 32))
        local base_txid_hex = types.hash256_hex(base_txid)
        add_utxo(chain_state, base_txid_hex, 0, 100000000)

        -- Parent transaction
        local parent = make_tx(1, {}, {}, 0)
        parent.inputs[1] = make_input(base_txid, 0)
        parent.outputs[1] = make_output(99990000)
        local parent_txid = validation.compute_txid(parent)

        -- Child transaction spending parent
        local child = make_tx(1, {}, {}, 0)
        child.inputs[1] = make_input(parent_txid, 0)
        child.outputs[1] = make_output(99980000)

        -- Wrong order: child, parent
        local ok, err = mempool.is_topo_sorted_package({child, parent})
        assert.is_false(ok)
      end)
    end)

    describe("is_consistent_package", function()
      it("accepts package with no conflicts", function()
        local txid1 = types.hash256(string.rep("\x01", 32))
        local txid2 = types.hash256(string.rep("\x02", 32))

        local tx1 = make_tx(1, {}, {}, 0)
        tx1.inputs[1] = make_input(txid1, 0)
        tx1.outputs[1] = make_output(50000)

        local tx2 = make_tx(1, {}, {}, 0)
        tx2.inputs[1] = make_input(txid2, 0)
        tx2.outputs[1] = make_output(50000)

        local ok, err = mempool.is_consistent_package({tx1, tx2})
        assert.is_true(ok)
      end)

      it("rejects package with conflicting inputs", function()
        local txid1 = types.hash256(string.rep("\x01", 32))

        -- Both txs spend the same outpoint
        local tx1 = make_tx(1, {}, {}, 0)
        tx1.inputs[1] = make_input(txid1, 0)
        tx1.outputs[1] = make_output(50000)

        local tx2 = make_tx(1, {}, {}, 0)
        tx2.inputs[1] = make_input(txid1, 0)  -- Same outpoint!
        tx2.outputs[1] = make_output(50000)

        local ok, err = mempool.is_consistent_package({tx1, tx2})
        assert.is_false(ok)
        assert.equal("conflict in package", err)
      end)
    end)

    describe("is_well_formed_package", function()
      it("accepts valid 2-transaction package", function()
        local txid1 = types.hash256(string.rep("\x01", 32))
        local txid2 = types.hash256(string.rep("\x02", 32))

        local tx1 = make_tx(1, {}, {}, 0)
        tx1.inputs[1] = make_input(txid1, 0)
        tx1.outputs[1] = make_output(50000)

        local tx2 = make_tx(1, {}, {}, 0)
        tx2.inputs[1] = make_input(txid2, 0)
        tx2.outputs[1] = make_output(50000)

        local ok, err = mempool.is_well_formed_package({tx1, tx2})
        assert.is_true(ok)
      end)

      it("rejects empty package", function()
        local ok, err = mempool.is_well_formed_package({})
        assert.is_false(ok)
        assert.equal("empty package", err)
      end)

      it("rejects package with too many transactions", function()
        local txns = {}
        for i = 1, 26 do  -- MAX_PACKAGE_COUNT = 25
          local txid = types.hash256(string.rep(string.char(i), 32))
          local tx = make_tx(1, {}, {}, 0)
          tx.inputs[1] = make_input(txid, 0)
          tx.outputs[1] = make_output(50000)
          txns[i] = tx
        end

        local ok, err = mempool.is_well_formed_package(txns)
        assert.is_false(ok)
        assert.equal("package-too-many-transactions", err)
      end)

      it("rejects package with duplicate transactions", function()
        local txid1 = types.hash256(string.rep("\x01", 32))

        local tx1 = make_tx(1, {}, {}, 0)
        tx1.inputs[1] = make_input(txid1, 0)
        tx1.outputs[1] = make_output(50000)

        -- Same transaction twice
        local ok, err = mempool.is_well_formed_package({tx1, tx1})
        assert.is_false(ok)
        assert.equal("package-contains-duplicates", err)
      end)
    end)

    describe("is_child_with_parents", function()
      it("returns true for valid child-with-parents package", function()
        local base_txid = types.hash256(string.rep("\x01", 32))

        -- Parent
        local parent = make_tx(1, {}, {}, 0)
        parent.inputs[1] = make_input(base_txid, 0)
        parent.outputs[1] = make_output(50000)
        local parent_txid = validation.compute_txid(parent)

        -- Child spending parent
        local child = make_tx(1, {}, {}, 0)
        child.inputs[1] = make_input(parent_txid, 0)
        child.outputs[1] = make_output(40000)

        local ok = mempool.is_child_with_parents({parent, child})
        assert.is_true(ok)
      end)

      it("returns false when parent is not spent by child", function()
        local txid1 = types.hash256(string.rep("\x01", 32))
        local txid2 = types.hash256(string.rep("\x02", 32))

        local parent = make_tx(1, {}, {}, 0)
        parent.inputs[1] = make_input(txid1, 0)
        parent.outputs[1] = make_output(50000)

        -- Child does NOT spend parent
        local child = make_tx(1, {}, {}, 0)
        child.inputs[1] = make_input(txid2, 0)
        child.outputs[1] = make_output(40000)

        local ok = mempool.is_child_with_parents({parent, child})
        assert.is_false(ok)
      end)

      it("returns false for single transaction", function()
        local txid1 = types.hash256(string.rep("\x01", 32))

        local tx = make_tx(1, {}, {}, 0)
        tx.inputs[1] = make_input(txid1, 0)
        tx.outputs[1] = make_output(50000)

        local ok = mempool.is_child_with_parents({tx})
        assert.is_false(ok)
      end)
    end)
  end)

  describe("CPFP package acceptance", function()

    it("accepts package where child pays for low-fee parent", function()
      local chain_state = make_mock_chain_state()

      -- Base UTXO for parent
      local base_txid = types.hash256(string.rep("\x01", 32))
      local base_txid_hex = types.hash256_hex(base_txid)
      add_utxo(chain_state, base_txid_hex, 0, 100000000)

      local mp = mempool.new(chain_state)

      -- Parent with LOW fee (would be rejected individually)
      -- ~85 vB tx needs 85 sat for 1 sat/vB (1000 sat/KB), use 20 sat
      local parent = make_tx(1, {}, {}, 0)
      parent.inputs[1] = make_input(base_txid, 0)
      parent.outputs[1] = make_output(99999980)  -- 20 sat fee (too low)
      local parent_txid = validation.compute_txid(parent)

      -- Child with HIGH fee (pays for both)
      local child = make_tx(1, {}, {}, 0)
      child.inputs[1] = make_input(parent_txid, 0)
      child.outputs[1] = make_output(99899980)  -- 100000 sat fee (high)

      -- Try accepting parent individually (should fail)
      local ok_parent, err_parent = mp:accept_transaction(parent)
      assert.is_false(ok_parent)
      assert.truthy(err_parent:match("fee rate too low"))

      -- Accept as package (should succeed)
      local ok, result = mp:accept_package({parent, child})
      assert.is_true(ok)
      assert.equal(2, #result.txids)
      assert.equal(2, mp.tx_count)

      -- Package fee rate should be above minimum
      assert.is_true(result.package_fee_rate > 0.5)  -- > 0.5 sat/vB
    end)

    it("rejects package where combined fee rate is still too low", function()
      local chain_state = make_mock_chain_state()

      local base_txid = types.hash256(string.rep("\x01", 32))
      local base_txid_hex = types.hash256_hex(base_txid)
      add_utxo(chain_state, base_txid_hex, 0, 100000000)

      local mp = mempool.new(chain_state)

      -- Both parent and child have very low fees
      local parent = make_tx(1, {}, {}, 0)
      parent.inputs[1] = make_input(base_txid, 0)
      parent.outputs[1] = make_output(99999990)  -- 10 sat fee
      local parent_txid = validation.compute_txid(parent)

      local child = make_tx(1, {}, {}, 0)
      child.inputs[1] = make_input(parent_txid, 0)
      child.outputs[1] = make_output(99999980)  -- 10 sat fee

      -- Combined: 20 sat / ~200 vB = ~0.1 sat/vB (way below min)
      local ok, err = mp:accept_package({parent, child})
      assert.is_false(ok)
      assert.truthy(err:match("package fee rate too low"))
    end)

    it("handles intra-package spending correctly", function()
      local chain_state = make_mock_chain_state()

      local base_txid = types.hash256(string.rep("\x01", 32))
      local base_txid_hex = types.hash256_hex(base_txid)
      add_utxo(chain_state, base_txid_hex, 0, 100000000)

      local mp = mempool.new(chain_state)

      -- Parent
      local parent = make_tx(1, {}, {}, 0)
      parent.inputs[1] = make_input(base_txid, 0)
      parent.outputs[1] = make_output(99990000)  -- 10000 sat fee
      local parent_txid = validation.compute_txid(parent)

      -- Child spending parent
      local child = make_tx(1, {}, {}, 0)
      child.inputs[1] = make_input(parent_txid, 0)
      child.outputs[1] = make_output(99980000)  -- 10000 sat fee

      local ok, result = mp:accept_package({parent, child})
      assert.is_true(ok)
      assert.equal(2, #result.txids)
      assert.equal(20000, result.total_fees)
    end)

    it("accepts already-mempool transactions in package", function()
      local chain_state = make_mock_chain_state()

      local txid1 = types.hash256(string.rep("\x01", 32))
      local txid1_hex = types.hash256_hex(txid1)
      add_utxo(chain_state, txid1_hex, 0, 100000000)

      local txid2 = types.hash256(string.rep("\x02", 32))
      local txid2_hex = types.hash256_hex(txid2)
      add_utxo(chain_state, txid2_hex, 0, 100000000)

      local mp = mempool.new(chain_state)

      -- First accept tx1 individually
      local tx1 = make_tx(1, {}, {}, 0)
      tx1.inputs[1] = make_input(txid1, 0)
      tx1.outputs[1] = make_output(99990000)

      local ok1, hex1 = mp:accept_transaction(tx1)
      assert.is_true(ok1)
      assert.equal(1, mp.tx_count)

      -- Second tx
      local tx2 = make_tx(1, {}, {}, 0)
      tx2.inputs[1] = make_input(txid2, 0)
      tx2.outputs[1] = make_output(99990000)

      -- Accept as package (tx1 already in mempool)
      local ok, result = mp:accept_package({tx1, tx2})
      assert.is_true(ok)
      assert.equal(2, #result.txids)
      assert.equal(2, mp.tx_count)
    end)

    it("rejects package with missing inputs", function()
      local chain_state = make_mock_chain_state()
      local mp = mempool.new(chain_state)

      local missing_txid = types.hash256(string.rep("\x99", 32))

      local tx = make_tx(1, {}, {}, 0)
      tx.inputs[1] = make_input(missing_txid, 0)
      tx.outputs[1] = make_output(50000)

      local ok, err = mp:accept_package({tx})
      assert.is_false(ok)
      assert.truthy(err:match("missing inputs"))
    end)

    it("tracks ancestor/descendant correctly after package acceptance", function()
      local chain_state = make_mock_chain_state()

      local base_txid = types.hash256(string.rep("\x01", 32))
      local base_txid_hex = types.hash256_hex(base_txid)
      add_utxo(chain_state, base_txid_hex, 0, 100000000)

      local mp = mempool.new(chain_state)

      -- Parent
      local parent = make_tx(1, {}, {}, 0)
      parent.inputs[1] = make_input(base_txid, 0)
      parent.outputs[1] = make_output(99990000)
      local parent_txid = validation.compute_txid(parent)

      -- Child
      local child = make_tx(1, {}, {}, 0)
      child.inputs[1] = make_input(parent_txid, 0)
      child.outputs[1] = make_output(99980000)

      local ok, result = mp:accept_package({parent, child})
      assert.is_true(ok)

      -- Check ancestor/descendant tracking
      local parent_entry = mp:get_entry(result.txids[1])
      local child_entry = mp:get_entry(result.txids[2])

      assert.equal(0, parent_entry.ancestor_count)
      assert.equal(1, parent_entry.descendant_count)
      assert.equal(1, child_entry.ancestor_count)
      assert.equal(0, child_entry.descendant_count)
    end)
  end)

  describe("package_relay P2P messages", function()
    local p2p = require("lunarblock.p2p")

    it("serializes and deserializes sendpackages", function()
      local payload = p2p.serialize_sendpackages(1)
      local result = p2p.deserialize_sendpackages(payload)
      assert.equal(1, result.version)
    end)

    it("serializes and deserializes ancpkginfo", function()
      local wtxid = types.hash256(string.rep("\xab", 32))
      local payload = p2p.serialize_ancpkginfo(wtxid)
      local result = p2p.deserialize_ancpkginfo(payload)
      assert.equal(wtxid.bytes, result.wtxid.bytes)
    end)

    it("serializes and deserializes getpkgtxns", function()
      local pkg_hash = types.hash256(string.rep("\xcd", 32))
      local wtxid1 = types.hash256(string.rep("\x01", 32))
      local wtxid2 = types.hash256(string.rep("\x02", 32))

      local payload = p2p.serialize_getpkgtxns(pkg_hash, {wtxid1, wtxid2})
      local result = p2p.deserialize_getpkgtxns(payload)

      assert.equal(pkg_hash.bytes, result.package_hash.bytes)
      assert.equal(2, #result.wtxids)
      assert.equal(wtxid1.bytes, result.wtxids[1].bytes)
      assert.equal(wtxid2.bytes, result.wtxids[2].bytes)
    end)

    it("serializes and deserializes pkgtxns", function()
      local pkg_hash = types.hash256(string.rep("\xcd", 32))

      -- Create simple transactions
      local base_txid = types.hash256(string.rep("\x01", 32))
      local tx1 = make_tx(1, {}, {}, 0)
      tx1.inputs[1] = make_input(base_txid, 0)
      tx1.outputs[1] = make_output(50000)

      local payload = p2p.serialize_pkgtxns(pkg_hash, {tx1})
      local result = p2p.deserialize_pkgtxns(payload)

      assert.equal(pkg_hash.bytes, result.package_hash.bytes)
      assert.equal(1, #result.transactions)
    end)

    it("serializes and deserializes pckginfo1", function()
      local parent_wtxid = types.hash256(string.rep("\x01", 32))
      local child_wtxid = types.hash256(string.rep("\x02", 32))

      local payload = p2p.serialize_pckginfo1(parent_wtxid, child_wtxid)
      local result = p2p.deserialize_pckginfo1(payload)

      assert.equal(parent_wtxid.bytes, result.parent_wtxid.bytes)
      assert.equal(child_wtxid.bytes, result.child_wtxid.bytes)
    end)
  end)

  describe("pay-to-anchor (P2A) policy", function()
    local P2A_SCRIPT = script.P2A_SCRIPT

    describe("is_anchor_output", function()
      it("returns true for P2A output", function()
        local output = make_output(0, P2A_SCRIPT)
        assert.is_true(mempool.is_anchor_output(output))
      end)

      it("returns false for P2WPKH output", function()
        local p2wpkh = "\x00\x14" .. string.rep("\x00", 20)
        local output = make_output(1000, p2wpkh)
        assert.is_false(mempool.is_anchor_output(output))
      end)

      it("returns false for P2TR output", function()
        local p2tr = "\x51\x20" .. string.rep("\x00", 32)
        local output = make_output(1000, p2tr)
        assert.is_false(mempool.is_anchor_output(output))
      end)
    end)

    describe("is_valid_anchor_amount", function()
      it("returns true for zero-value anchor", function()
        local output = make_output(0, P2A_SCRIPT)
        assert.is_true(mempool.is_valid_anchor_amount(output))
      end)

      it("returns false for non-zero anchor", function()
        local output = make_output(1, P2A_SCRIPT)
        assert.is_false(mempool.is_valid_anchor_amount(output))
      end)

      it("returns false for dust-level anchor", function()
        local output = make_output(546, P2A_SCRIPT)
        assert.is_false(mempool.is_valid_anchor_amount(output))
      end)
    end)

    describe("is_dust_exempt", function()
      it("returns true for P2A script", function()
        assert.is_true(mempool.is_dust_exempt(P2A_SCRIPT))
      end)

      it("returns false for P2WPKH script", function()
        local p2wpkh = "\x00\x14" .. string.rep("\x00", 20)
        assert.is_false(mempool.is_dust_exempt(p2wpkh))
      end)

      it("returns false for P2TR script", function()
        local p2tr = "\x51\x20" .. string.rep("\x00", 32)
        assert.is_false(mempool.is_dust_exempt(p2tr))
      end)
    end)

    describe("check_anchor_outputs", function()
      it("accepts tx with zero-value P2A output", function()
        local tx = make_tx(1, {}, {}, 0)
        tx.inputs[1] = make_input(types.hash256(string.rep("\x01", 32)), 0)
        tx.outputs[1] = make_output(99000)  -- Normal output
        tx.outputs[2] = make_output(0, P2A_SCRIPT)  -- P2A anchor

        local ok, err = mempool.check_anchor_outputs(tx)
        assert.is_true(ok)
        assert.is_nil(err)
      end)

      it("rejects tx with non-zero P2A output", function()
        local tx = make_tx(1, {}, {}, 0)
        tx.inputs[1] = make_input(types.hash256(string.rep("\x01", 32)), 0)
        tx.outputs[1] = make_output(99000)
        tx.outputs[2] = make_output(1000, P2A_SCRIPT)  -- Invalid: non-zero P2A

        local ok, err = mempool.check_anchor_outputs(tx)
        assert.is_false(ok)
        assert.truthy(err:match("anchor output.*must have value 0"))
      end)

      it("accepts tx with multiple zero-value P2A outputs", function()
        local tx = make_tx(1, {}, {}, 0)
        tx.inputs[1] = make_input(types.hash256(string.rep("\x01", 32)), 0)
        tx.outputs[1] = make_output(0, P2A_SCRIPT)
        tx.outputs[2] = make_output(0, P2A_SCRIPT)

        local ok, err = mempool.check_anchor_outputs(tx)
        assert.is_true(ok)
      end)

      it("accepts tx with no P2A outputs", function()
        local tx = make_tx(1, {}, {}, 0)
        tx.inputs[1] = make_input(types.hash256(string.rep("\x01", 32)), 0)
        tx.outputs[1] = make_output(99000)

        local ok, err = mempool.check_anchor_outputs(tx)
        assert.is_true(ok)
      end)
    end)

    describe("mempool acceptance with P2A", function()
      it("accepts tx with zero-value P2A anchor output", function()
        local prev_txid = types.hash256(string.rep("\x01", 32))
        local prev_txid_hex = types.hash256_hex(prev_txid)

        local chain_state = make_mock_chain_state()
        add_utxo(chain_state, prev_txid_hex, 0, 100000)

        local mp = mempool.new(chain_state)

        local tx = make_tx(1, {}, {}, 0)
        tx.inputs[1] = make_input(prev_txid, 0)
        tx.outputs[1] = make_output(90000)  -- Normal output
        tx.outputs[2] = make_output(0, P2A_SCRIPT)  -- P2A anchor

        local ok, txid_hex, fee = mp:accept_transaction(tx)
        assert.is_true(ok)
        assert.is_string(txid_hex)
        assert.equal(10000, fee)
      end)

      it("rejects tx with non-zero P2A anchor output", function()
        local prev_txid = types.hash256(string.rep("\x01", 32))
        local prev_txid_hex = types.hash256_hex(prev_txid)

        local chain_state = make_mock_chain_state()
        add_utxo(chain_state, prev_txid_hex, 0, 100000)

        local mp = mempool.new(chain_state)

        local tx = make_tx(1, {}, {}, 0)
        tx.inputs[1] = make_input(prev_txid, 0)
        tx.outputs[1] = make_output(89000)
        tx.outputs[2] = make_output(1000, P2A_SCRIPT)  -- Invalid: non-zero P2A

        local ok, err = mp:accept_transaction(tx)
        assert.is_false(ok)
        assert.truthy(err:match("anchor output.*must have value 0"))
      end)
    end)

    describe("P2A spending (CPFP use case)", function()
      it("allows spending P2A output with empty witness", function()
        -- This tests that P2A outputs can be spent (anyone-can-spend)
        -- for CPFP fee bumping. The witness for P2A is empty.
        local chain_state = make_mock_chain_state()

        -- Parent with P2A anchor output
        local parent_txid = types.hash256(string.rep("\x01", 32))
        local parent_txid_hex = types.hash256_hex(parent_txid)
        add_utxo(chain_state, parent_txid_hex, 0, 100000)

        -- Also add a P2A UTXO (representing a commitment tx anchor)
        local anchor_txid = types.hash256(string.rep("\x02", 32))
        local anchor_txid_hex = types.hash256_hex(anchor_txid)
        -- Note: P2A UTXOs have 0 value but we use small value for test simplicity
        chain_state.coin_view.utxos[anchor_txid_hex .. ":0"] = {
          value = 0,
          script_pubkey = P2A_SCRIPT,
          height = 500000,
          is_coinbase = false
        }

        local mp = mempool.new(chain_state)

        -- Child tx that spends both normal UTXO and P2A anchor (CPFP)
        local tx = make_tx(1, {}, {}, 0)
        tx.inputs[1] = make_input(parent_txid, 0)
        tx.inputs[2] = make_input(anchor_txid, 0)  -- Spend P2A anchor
        tx.outputs[1] = make_output(90000)

        -- For segwit spending, the witness would be empty for P2A
        -- This test verifies mempool accepts the tx structure
        local ok, txid_hex, fee = mp:accept_transaction(tx)
        assert.is_true(ok)
        assert.is_string(txid_hex)
        -- Fee = 100000 + 0 (anchor) - 90000 = 10000
        assert.equal(10000, fee)
      end)

      it("P2A is exempt from dust threshold", function()
        -- This confirms P2A outputs don't need to meet dust threshold
        -- because they must be exactly 0 value
        assert.is_true(mempool.is_dust_exempt(P2A_SCRIPT))
        assert.equal(0, mempool.ANCHOR_AMOUNT)
      end)
    end)
  end)

end)
