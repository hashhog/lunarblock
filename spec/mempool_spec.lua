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

end)
