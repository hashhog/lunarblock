describe("validation", function()
  local validation
  local types
  local serialize
  local crypto
  local consensus
  local script

  -- Helper: convert hex string to binary
  local function hex_to_bin(hex)
    return (hex:gsub("..", function(h) return string.char(tonumber(h, 16)) end))
  end

  -- Helper: convert binary to hex string
  local function bin_to_hex(bin)
    return (bin:gsub(".", function(c) return string.format("%02x", c:byte()) end))
  end

  setup(function()
    package.path = "src/?.lua;" .. package.path
    -- Set up lunarblock.X aliases
    package.preload["lunarblock.types"] = function() return require("types") end
    package.preload["lunarblock.serialize"] = function() return require("serialize") end
    package.preload["lunarblock.crypto"] = function() return require("crypto") end
    package.preload["lunarblock.script"] = function() return require("script") end
    package.preload["lunarblock.consensus"] = function() return require("consensus") end

    types = require("types")
    serialize = require("serialize")
    consensus = require("consensus")
    script = require("script")
    validation = require("validation")
    crypto = require("lunarblock.crypto")  -- loaded via validation
  end)

  describe("check_transaction", function()
    it("accepts valid transaction", function()
      local tx = types.transaction(1, {}, {}, 0)
      -- Add input
      local prev_hash = types.hash256(string.rep("\x01", 32))
      local inp = types.txin(types.outpoint(prev_hash, 0), "\x00", 0xFFFFFFFF)
      tx.inputs[1] = inp
      -- Add output
      tx.outputs[1] = types.txout(50000, string.rep("\x00", 25))

      local success, is_coinbase = validation.check_transaction(tx)
      assert.is_true(success)
      assert.is_false(is_coinbase)
    end)

    it("rejects transaction with no inputs", function()
      local tx = types.transaction(1, {}, {}, 0)
      tx.outputs[1] = types.txout(50000, string.rep("\x00", 25))

      assert.has_error(function()
        validation.check_transaction(tx)
      end, "transaction has no inputs")
    end)

    it("rejects transaction with no outputs", function()
      local tx = types.transaction(1, {}, {}, 0)
      local prev_hash = types.hash256(string.rep("\x01", 32))
      tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "\x00", 0xFFFFFFFF)

      assert.has_error(function()
        validation.check_transaction(tx)
      end, "transaction has no outputs")
    end)

    it("detects coinbase transaction", function()
      local tx = types.transaction(1, {}, {}, 0)
      -- Coinbase input: null hash, index 0xFFFFFFFF
      local null_hash = types.hash256(string.rep("\x00", 32))
      local coinbase_input = types.txin(
        types.outpoint(null_hash, 0xFFFFFFFF),
        "\x03\x01\x02\x03",  -- Valid coinbase scriptSig (4 bytes)
        0xFFFFFFFF
      )
      tx.inputs[1] = coinbase_input
      tx.outputs[1] = types.txout(5000000000, string.rep("\x00", 25))

      local success, is_coinbase = validation.check_transaction(tx)
      assert.is_true(success)
      assert.is_true(is_coinbase)
    end)

    it("rejects duplicate inputs", function()
      local tx = types.transaction(1, {}, {}, 0)
      local prev_hash = types.hash256(string.rep("\x01", 32))
      -- Same outpoint twice
      tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "\x00", 0xFFFFFFFF)
      tx.inputs[2] = types.txin(types.outpoint(prev_hash, 0), "\x00", 0xFFFFFFFF)
      tx.outputs[1] = types.txout(50000, string.rep("\x00", 25))

      assert.has_error(function()
        validation.check_transaction(tx)
      end, "duplicate input")
    end)

    it("rejects negative output value", function()
      local tx = types.transaction(1, {}, {}, 0)
      local prev_hash = types.hash256(string.rep("\x01", 32))
      tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "\x00", 0xFFFFFFFF)
      tx.outputs[1] = types.txout(-1, string.rep("\x00", 25))

      assert.has_error(function()
        validation.check_transaction(tx)
      end)
    end)

    it("rejects output value exceeding MAX_MONEY", function()
      local tx = types.transaction(1, {}, {}, 0)
      local prev_hash = types.hash256(string.rep("\x01", 32))
      tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "\x00", 0xFFFFFFFF)
      tx.outputs[1] = types.txout(consensus.MAX_MONEY + 1, string.rep("\x00", 25))

      assert.has_error(function()
        validation.check_transaction(tx)
      end)
    end)

    it("rejects total output value exceeding MAX_MONEY", function()
      local tx = types.transaction(1, {}, {}, 0)
      local prev_hash = types.hash256(string.rep("\x01", 32))
      tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "\x00", 0xFFFFFFFF)
      -- Two outputs that together exceed MAX_MONEY
      tx.outputs[1] = types.txout(consensus.MAX_MONEY, string.rep("\x00", 25))
      tx.outputs[2] = types.txout(1, string.rep("\x00", 25))

      assert.has_error(function()
        validation.check_transaction(tx)
      end, "total output value exceeds MAX_MONEY")
    end)

    it("rejects coinbase with short scriptSig", function()
      local tx = types.transaction(1, {}, {}, 0)
      local null_hash = types.hash256(string.rep("\x00", 32))
      tx.inputs[1] = types.txin(
        types.outpoint(null_hash, 0xFFFFFFFF),
        "\x01",  -- Only 1 byte (too short)
        0xFFFFFFFF
      )
      tx.outputs[1] = types.txout(5000000000, string.rep("\x00", 25))

      assert.has_error(function()
        validation.check_transaction(tx)
      end)
    end)

    it("rejects coinbase with long scriptSig", function()
      local tx = types.transaction(1, {}, {}, 0)
      local null_hash = types.hash256(string.rep("\x00", 32))
      tx.inputs[1] = types.txin(
        types.outpoint(null_hash, 0xFFFFFFFF),
        string.rep("\x00", 101),  -- 101 bytes (too long)
        0xFFFFFFFF
      )
      tx.outputs[1] = types.txout(5000000000, string.rep("\x00", 25))

      assert.has_error(function()
        validation.check_transaction(tx)
      end)
    end)

    it("rejects non-coinbase with null prevout hash", function()
      local tx = types.transaction(1, {}, {}, 0)
      -- Two inputs, second has null hash (invalid)
      local prev_hash = types.hash256(string.rep("\x01", 32))
      local null_hash = types.hash256(string.rep("\x00", 32))
      tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "\x00", 0xFFFFFFFF)
      tx.inputs[2] = types.txin(types.outpoint(null_hash, 0), "\x00", 0xFFFFFFFF)
      tx.outputs[1] = types.txout(50000, string.rep("\x00", 25))

      assert.has_error(function()
        validation.check_transaction(tx)
      end)
    end)
  end)

  describe("compute_txid", function()
    it("computes txid for simple transaction", function()
      local tx = types.transaction(1, {}, {}, 0)
      local prev_hash = types.hash256(string.rep("\x00", 32))
      tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0xFFFFFFFF), "\x04\x01\x02\x03\x04", 0xFFFFFFFF)
      tx.outputs[1] = types.txout(5000000000, string.rep("\x76\xa9", 1) .. string.rep("\x00", 23))

      local txid = validation.compute_txid(tx)
      assert.equals("hash256", txid._type)
      assert.equals(32, #txid.bytes)
    end)

    it("returns different txid for different transactions", function()
      local tx1 = types.transaction(1, {}, {}, 0)
      local tx2 = types.transaction(2, {}, {}, 0)

      local prev_hash = types.hash256(string.rep("\x00", 32))
      tx1.inputs[1] = types.txin(types.outpoint(prev_hash, 0xFFFFFFFF), "\x04\x01\x02\x03\x04", 0xFFFFFFFF)
      tx1.outputs[1] = types.txout(5000000000, string.rep("\x00", 25))

      tx2.inputs[1] = types.txin(types.outpoint(prev_hash, 0xFFFFFFFF), "\x04\x01\x02\x03\x04", 0xFFFFFFFF)
      tx2.outputs[1] = types.txout(5000000000, string.rep("\x00", 25))

      local txid1 = validation.compute_txid(tx1)
      local txid2 = validation.compute_txid(tx2)

      assert.is_not.equals(txid1.bytes, txid2.bytes)
    end)
  end)

  describe("compute_wtxid", function()
    it("equals txid for non-segwit transaction", function()
      local tx = types.transaction(1, {}, {}, 0)
      tx.segwit = false
      local prev_hash = types.hash256(string.rep("\x00", 32))
      tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0xFFFFFFFF), "\x04\x01\x02\x03\x04", 0xFFFFFFFF)
      tx.outputs[1] = types.txout(5000000000, string.rep("\x00", 25))

      local txid = validation.compute_txid(tx)
      local wtxid = validation.compute_wtxid(tx)

      assert.equals(txid.bytes, wtxid.bytes)
    end)

    it("differs from txid for segwit transaction", function()
      local tx = types.transaction(1, {}, {}, 0)
      tx.segwit = true
      local prev_hash = types.hash256(string.rep("\x01", 32))
      local inp = types.txin(types.outpoint(prev_hash, 0), "", 0xFFFFFFFF)
      inp.witness = {"\x30\x44" .. string.rep("\x00", 68), "\x02" .. string.rep("\x00", 32)}
      tx.inputs[1] = inp
      tx.outputs[1] = types.txout(50000, string.rep("\x00", 22))

      local txid = validation.compute_txid(tx)
      local wtxid = validation.compute_wtxid(tx)

      assert.is_not.equals(txid.bytes, wtxid.bytes)
    end)
  end)

  describe("compute_block_hash", function()
    it("computes genesis block hash correctly for mainnet", function()
      local mainnet = consensus.networks.mainnet

      -- Build genesis block header
      local genesis_header = types.block_header(
        mainnet.genesis.version,
        types.hash256_zero(),  -- prev_hash
        types.hash256_from_hex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"),
        mainnet.genesis.timestamp,
        mainnet.genesis.bits,
        mainnet.genesis.nonce
      )

      local block_hash = validation.compute_block_hash(genesis_header)
      local hash_hex = types.hash256_hex(block_hash)

      assert.equals(mainnet.genesis_hash, hash_hex)
    end)

    it("computes genesis block hash correctly for regtest", function()
      local regtest = consensus.networks.regtest

      local genesis_header = types.block_header(
        regtest.genesis.version,
        types.hash256_zero(),
        types.hash256_from_hex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"),
        regtest.genesis.timestamp,
        regtest.genesis.bits,
        regtest.genesis.nonce
      )

      local block_hash = validation.compute_block_hash(genesis_header)
      local hash_hex = types.hash256_hex(block_hash)

      assert.equals(regtest.genesis_hash, hash_hex)
    end)
  end)

  describe("check_proof_of_work", function()
    it("passes for genesis block header", function()
      local mainnet = consensus.networks.mainnet

      local genesis_header = types.block_header(
        mainnet.genesis.version,
        types.hash256_zero(),
        types.hash256_from_hex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"),
        mainnet.genesis.timestamp,
        mainnet.genesis.bits,
        mainnet.genesis.nonce
      )

      assert.is_true(validation.check_proof_of_work(genesis_header, mainnet))
    end)

    it("fails with modified nonce", function()
      local mainnet = consensus.networks.mainnet

      local genesis_header = types.block_header(
        mainnet.genesis.version,
        types.hash256_zero(),
        types.hash256_from_hex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"),
        mainnet.genesis.timestamp,
        mainnet.genesis.bits,
        mainnet.genesis.nonce + 1  -- Modified nonce
      )

      assert.is_false(validation.check_proof_of_work(genesis_header, mainnet))
    end)

    it("passes for regtest with easy difficulty", function()
      local regtest = consensus.networks.regtest

      local genesis_header = types.block_header(
        regtest.genesis.version,
        types.hash256_zero(),
        types.hash256_from_hex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"),
        regtest.genesis.timestamp,
        regtest.genesis.bits,
        regtest.genesis.nonce
      )

      assert.is_true(validation.check_proof_of_work(genesis_header, regtest))
    end)
  end)

  describe("check_merkle_root", function()
    it("passes for block with correct merkle root", function()
      -- Create coinbase transaction
      local tx = types.transaction(1, {}, {}, 0)
      local null_hash = types.hash256(string.rep("\x00", 32))
      tx.inputs[1] = types.txin(
        types.outpoint(null_hash, 0xFFFFFFFF),
        "\x04\x01\x02\x03\x04",
        0xFFFFFFFF
      )
      tx.outputs[1] = types.txout(5000000000, string.rep("\x00", 25))

      -- Compute merkle root
      local txid = validation.compute_txid(tx)
      local merkle_root = crypto.compute_merkle_root({txid})

      -- Create block with correct merkle root
      local header = types.block_header(1, types.hash256_zero(), merkle_root, os.time(), 0x207fffff, 0)
      local block = types.block(header, {tx})

      assert.is_true(validation.check_merkle_root(block))
    end)

    it("fails for block with wrong merkle root", function()
      local tx = types.transaction(1, {}, {}, 0)
      local null_hash = types.hash256(string.rep("\x00", 32))
      tx.inputs[1] = types.txin(
        types.outpoint(null_hash, 0xFFFFFFFF),
        "\x04\x01\x02\x03\x04",
        0xFFFFFFFF
      )
      tx.outputs[1] = types.txout(5000000000, string.rep("\x00", 25))

      -- Use wrong merkle root
      local wrong_merkle_root = types.hash256(string.rep("\xff", 32))
      local header = types.block_header(1, types.hash256_zero(), wrong_merkle_root, os.time(), 0x207fffff, 0)
      local block = types.block(header, {tx})

      assert.is_false(validation.check_merkle_root(block))
    end)

    it("handles multiple transactions", function()
      -- Create two transactions
      local tx1 = types.transaction(1, {}, {}, 0)
      local null_hash = types.hash256(string.rep("\x00", 32))
      tx1.inputs[1] = types.txin(types.outpoint(null_hash, 0xFFFFFFFF), "\x04\x01\x02\x03\x04", 0xFFFFFFFF)
      tx1.outputs[1] = types.txout(5000000000, string.rep("\x00", 25))

      local tx2 = types.transaction(1, {}, {}, 0)
      local prev_hash = types.hash256(string.rep("\x01", 32))
      tx2.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "\x00", 0xFFFFFFFF)
      tx2.outputs[1] = types.txout(4999990000, string.rep("\x00", 25))

      -- Compute merkle root with both transactions
      local txids = {validation.compute_txid(tx1), validation.compute_txid(tx2)}
      local merkle_root = crypto.compute_merkle_root(txids)

      local header = types.block_header(1, types.hash256_zero(), merkle_root, os.time(), 0x207fffff, 0)
      local block = types.block(header, {tx1, tx2})

      assert.is_true(validation.check_merkle_root(block))
    end)
  end)

  describe("count_script_sigops", function()
    it("counts OP_CHECKSIG as 1", function()
      local p2pkh = script.make_p2pkh_script(string.rep("\x00", 20))
      local count = validation.count_script_sigops(p2pkh, false)
      assert.equals(1, count)
    end)

    it("counts OP_CHECKMULTISIG as 20 without accurate counting", function()
      -- 2-of-3 multisig
      local multisig = string.char(script.OP.OP_2) ..
                       string.char(33) .. string.rep("\x00", 33) ..
                       string.char(33) .. string.rep("\x00", 33) ..
                       string.char(33) .. string.rep("\x00", 33) ..
                       string.char(script.OP.OP_3) ..
                       string.char(script.OP.OP_CHECKMULTISIG)

      local count = validation.count_script_sigops(multisig, false)
      assert.equals(20, count)
    end)

    it("counts OP_CHECKMULTISIG accurately when enabled", function()
      -- 2-of-3 multisig
      local multisig = string.char(script.OP.OP_2) ..
                       string.char(33) .. string.rep("\x00", 33) ..
                       string.char(33) .. string.rep("\x00", 33) ..
                       string.char(33) .. string.rep("\x00", 33) ..
                       string.char(script.OP.OP_3) ..
                       string.char(script.OP.OP_CHECKMULTISIG)

      local count = validation.count_script_sigops(multisig, true)
      assert.equals(3, count)  -- Uses OP_3 as the count
    end)

    it("counts P2PKH scriptPubKey + scriptSig as 2 total", function()
      local pubkey_hash = string.rep("\x00", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      -- P2PKH scriptSig: <sig> <pubkey>
      local script_sig = string.char(71) .. string.rep("\x00", 71) ..
                         string.char(33) .. string.rep("\x00", 33)

      local pubkey_sigops = validation.count_script_sigops(script_pubkey, false)
      local sig_sigops = validation.count_script_sigops(script_sig, false)

      assert.equals(1, pubkey_sigops)  -- OP_CHECKSIG in scriptPubKey
      assert.equals(0, sig_sigops)     -- No sigops in scriptSig
    end)
  end)

  describe("get_tx_weight", function()
    it("calculates legacy tx weight as 4 * size", function()
      local tx = types.transaction(1, {}, {}, 0)
      tx.segwit = false
      local prev_hash = types.hash256(string.rep("\x01", 32))
      tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "\x00", 0xFFFFFFFF)
      tx.outputs[1] = types.txout(50000, string.rep("\x00", 25))

      local weight = validation.get_tx_weight(tx)
      local size = #serialize.serialize_transaction(tx, false)

      -- For legacy tx: base_size * 3 + total_size = size * 3 + size = size * 4
      assert.equals(size * 4, weight)
    end)

    it("calculates segwit tx weight with witness discount", function()
      local tx = types.transaction(1, {}, {}, 0)
      tx.segwit = true
      local prev_hash = types.hash256(string.rep("\x01", 32))
      local inp = types.txin(types.outpoint(prev_hash, 0), "", 0xFFFFFFFF)
      inp.witness = {string.rep("\x00", 72), string.rep("\x00", 33)}
      tx.inputs[1] = inp
      tx.outputs[1] = types.txout(50000, string.rep("\x00", 22))

      local weight = validation.get_tx_weight(tx)
      local base_size = #serialize.serialize_transaction(tx, false)
      local total_size = #serialize.serialize_transaction(tx, true)

      assert.equals(base_size * 3 + total_size, weight)
      -- Weight should be less than 4 * total_size due to witness discount
      assert.is_true(weight < total_size * 4)
    end)
  end)

  describe("make_sig_checker", function()
    describe("check_locktime", function()
      it("passes when script locktime <= tx locktime (block heights)", function()
        local tx = types.transaction(1, {}, {}, 500)  -- locktime 500
        local prev_hash = types.hash256(string.rep("\x01", 32))
        tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "\x00", 0xFFFFFFFE)
        tx.outputs[1] = types.txout(50000, string.rep("\x00", 25))

        local checker = validation.make_sig_checker(tx, 0, 50000, "", {})

        assert.is_true(checker.check_locktime(400))
        assert.is_true(checker.check_locktime(500))
      end)

      it("fails when script locktime > tx locktime", function()
        local tx = types.transaction(1, {}, {}, 500)
        local prev_hash = types.hash256(string.rep("\x01", 32))
        tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "\x00", 0xFFFFFFFE)
        tx.outputs[1] = types.txout(50000, string.rep("\x00", 25))

        local checker = validation.make_sig_checker(tx, 0, 50000, "", {})

        assert.is_false(checker.check_locktime(501))
      end)

      it("fails when sequence is 0xFFFFFFFF", function()
        local tx = types.transaction(1, {}, {}, 500)
        local prev_hash = types.hash256(string.rep("\x01", 32))
        tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "\x00", 0xFFFFFFFF)
        tx.outputs[1] = types.txout(50000, string.rep("\x00", 25))

        local checker = validation.make_sig_checker(tx, 0, 50000, "", {})

        assert.is_false(checker.check_locktime(400))
      end)

      it("fails when locktime types mismatch", function()
        -- tx locktime is block height
        local tx = types.transaction(1, {}, {}, 1000)
        local prev_hash = types.hash256(string.rep("\x01", 32))
        tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "\x00", 0xFFFFFFFE)
        tx.outputs[1] = types.txout(50000, string.rep("\x00", 25))

        local checker = validation.make_sig_checker(tx, 0, 50000, "", {})

        -- Script locktime is timestamp (>= 500000000)
        assert.is_false(checker.check_locktime(500000001))
      end)
    end)

    describe("check_sequence", function()
      it("passes when disabled flag is set", function()
        local tx = types.transaction(2, {}, {}, 0)
        local prev_hash = types.hash256(string.rep("\x01", 32))
        tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "\x00", 0x80000000)
        tx.outputs[1] = types.txout(50000, string.rep("\x00", 25))

        local checker = validation.make_sig_checker(tx, 0, 50000, "", {})

        -- Disabled sequence always passes
        assert.is_true(checker.check_sequence(0x80000000))
      end)

      it("fails when tx version < 2", function()
        local tx = types.transaction(1, {}, {}, 0)
        local prev_hash = types.hash256(string.rep("\x01", 32))
        tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "\x00", 10)
        tx.outputs[1] = types.txout(50000, string.rep("\x00", 25))

        local checker = validation.make_sig_checker(tx, 0, 50000, "", {})

        assert.is_false(checker.check_sequence(5))
      end)

      it("passes when script sequence <= input sequence (height-based)", function()
        local tx = types.transaction(2, {}, {}, 0)
        local prev_hash = types.hash256(string.rep("\x01", 32))
        tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "\x00", 100)
        tx.outputs[1] = types.txout(50000, string.rep("\x00", 25))

        local checker = validation.make_sig_checker(tx, 0, 50000, "", {})

        assert.is_true(checker.check_sequence(50))
        assert.is_true(checker.check_sequence(100))
      end)

      it("fails when script sequence > input sequence", function()
        local tx = types.transaction(2, {}, {}, 0)
        local prev_hash = types.hash256(string.rep("\x01", 32))
        tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "\x00", 100)
        tx.outputs[1] = types.txout(50000, string.rep("\x00", 25))

        local checker = validation.make_sig_checker(tx, 0, 50000, "", {})

        assert.is_false(checker.check_sequence(101))
      end)

      it("fails when sequence types mismatch", function()
        local tx = types.transaction(2, {}, {}, 0)
        local prev_hash = types.hash256(string.rep("\x01", 32))
        -- Input uses height-based sequence
        tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "\x00", 100)
        tx.outputs[1] = types.txout(50000, string.rep("\x00", 25))

        local checker = validation.make_sig_checker(tx, 0, 50000, "", {})

        -- Script uses time-based sequence
        assert.is_false(checker.check_sequence(0x00400010))
      end)
    end)
  end)

  describe("signature_hash_legacy", function()
    it("returns special hash for SIGHASH_SINGLE with no matching output", function()
      local tx = types.transaction(1, {}, {}, 0)
      local prev_hash = types.hash256(string.rep("\x01", 32))
      tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "\x00", 0xFFFFFFFF)
      tx.inputs[2] = types.txin(types.outpoint(prev_hash, 1), "\x00", 0xFFFFFFFF)
      -- Only one output
      tx.outputs[1] = types.txout(50000, string.rep("\x00", 25))

      -- SIGHASH_SINGLE for input 1 (no matching output)
      local hash = validation.signature_hash_legacy(tx, 1, "\x00", consensus.SIGHASH.SINGLE)

      local expected = string.rep("\0", 31) .. "\1"
      assert.equals(expected, hash)
    end)

    it("produces consistent hash for same inputs", function()
      local tx = types.transaction(1, {}, {}, 0)
      local prev_hash = types.hash256(string.rep("\x01", 32))
      tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "\x00", 0xFFFFFFFF)
      tx.outputs[1] = types.txout(50000, string.rep("\x00", 25))

      local script_code = script.make_p2pkh_script(string.rep("\x00", 20))

      local hash1 = validation.signature_hash_legacy(tx, 0, script_code, consensus.SIGHASH.ALL)
      local hash2 = validation.signature_hash_legacy(tx, 0, script_code, consensus.SIGHASH.ALL)

      assert.equals(hash1, hash2)
    end)
  end)

  describe("signature_hash_segwit_v0", function()
    it("produces consistent hash for same inputs", function()
      local tx = types.transaction(1, {}, {}, 0)
      tx.segwit = true
      local prev_hash = types.hash256(string.rep("\x01", 32))
      local inp = types.txin(types.outpoint(prev_hash, 0), "", 0xFFFFFFFF)
      inp.witness = {}
      tx.inputs[1] = inp
      tx.outputs[1] = types.txout(50000, script.make_p2wpkh_script(string.rep("\x00", 20)))

      local script_code = script.make_p2pkh_script(string.rep("\x00", 20))
      local value = 100000

      local hash1 = validation.signature_hash_segwit_v0(tx, 0, script_code, value, consensus.SIGHASH.ALL)
      local hash2 = validation.signature_hash_segwit_v0(tx, 0, script_code, value, consensus.SIGHASH.ALL)

      assert.equals(hash1, hash2)
      assert.equals(32, #hash1)
    end)

    it("produces different hash for different values", function()
      local tx = types.transaction(1, {}, {}, 0)
      tx.segwit = true
      local prev_hash = types.hash256(string.rep("\x01", 32))
      local inp = types.txin(types.outpoint(prev_hash, 0), "", 0xFFFFFFFF)
      inp.witness = {}
      tx.inputs[1] = inp
      tx.outputs[1] = types.txout(50000, script.make_p2wpkh_script(string.rep("\x00", 20)))

      local script_code = script.make_p2pkh_script(string.rep("\x00", 20))

      local hash1 = validation.signature_hash_segwit_v0(tx, 0, script_code, 100000, consensus.SIGHASH.ALL)
      local hash2 = validation.signature_hash_segwit_v0(tx, 0, script_code, 200000, consensus.SIGHASH.ALL)

      assert.is_not.equals(hash1, hash2)
    end)
  end)
end)
