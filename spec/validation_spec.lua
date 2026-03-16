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

  describe("find_and_delete", function()
    it("removes a simple signature from script", function()
      -- Script: <sig> <pubkey> (push-encoded)
      local sig = hex_to_bin("304402200102030405060708091011121314151617181920")
      local pubkey = hex_to_bin("0401020304050607080910111213141516171819202122232425262728293031323334353637383940")

      -- Create script with push-encoded sig and pubkey
      local script_code = string.char(#sig) .. sig .. string.char(#pubkey) .. pubkey

      -- Remove the signature
      local result = validation.find_and_delete(script_code, sig)

      -- Should only have the pubkey remaining
      local expected = string.char(#pubkey) .. pubkey
      assert.equals(expected, result)
    end)

    it("removes multiple occurrences of signature", function()
      local sig = "\x01\x02\x03"
      -- Script with sig appearing twice
      local script_code = string.char(3) .. sig .. "\xac" .. string.char(3) .. sig .. "\xac"

      local result = validation.find_and_delete(script_code, sig)

      -- Both occurrences should be removed
      assert.equals("\xac\xac", result)
    end)

    it("does nothing if signature not present", function()
      local sig = "\x01\x02\x03"
      local script_code = "\x04\x05\x06\x07\xac"

      local result = validation.find_and_delete(script_code, sig)

      assert.equals(script_code, result)
    end)

    it("handles empty signature gracefully", function()
      local script_code = "\x01\x02\x03\xac"

      local result = validation.find_and_delete(script_code, "")
      assert.equals(script_code, result)

      local result2 = validation.find_and_delete(script_code, nil)
      assert.equals(script_code, result2)
    end)
  end)

  describe("remove_codeseparators", function()
    it("removes OP_CODESEPARATOR bytes", function()
      -- Script with OP_CODESEPARATOR (0xab) mixed in
      local script_code = "\x51\xab\x52\xab\xab\x53"  -- OP_1 CODESEP OP_2 CODESEP CODESEP OP_3

      local result = validation.remove_codeseparators(script_code)

      -- All 0xab bytes should be removed
      assert.equals("\x51\x52\x53", result)
    end)

    it("handles script with no codeseparators", function()
      local script_code = "\x51\x52\x53"

      local result = validation.remove_codeseparators(script_code)

      assert.equals(script_code, result)
    end)

    it("handles empty script", function()
      local result = validation.remove_codeseparators("")
      assert.equals("", result)
    end)
  end)

  describe("sighash test vectors", function()
    -- Bitcoin Core sighash.json test vectors
    -- Format: [raw_transaction_hex, script_hex, input_index, hashType, expected_sighash_hex]

    local test_vectors = {
      -- Test vector 1
      {"907c2bc503ade11cc3b04eb2918b6f547b0630ab569273824748c87ea14b0696526c66ba740200000004ab65ababfd1f9bdd4ef073c7afc4ae00da8a66f429c917a0081ad1e1dabce28d373eab81d8628de802000000096aab5253ab52000052ad042b5f25efb33beec9f3364e8a9139e8439d9d7e26529c3c30b6c3fd89f8684cfd68ea0200000009ab53526500636a52ab599ac2fe02a526ed040000000008535300516352515164370e010000000003006300ab2ec229", "", 2, 1864164639, "31af167a6cf3f9d5f6875caa4d31704ceb0eba078d132b78dab52c3b8997317e"},
      -- Test vector 2
      {"a0aa3126041621a6dea5b800141aa696daf28408959dfb2df96095db9fa425ad3f427f2f6103000000015360290e9c6063fa26912c2e7fb6a0ad80f1c5fea1771d42f12976092e7a85a4229fdb6e890000000001abc109f6e47688ac0e4682988785744602b8c87228fcef0695085edf19088af1a9db126e93000000000665516aac536affffffff8fe53e0806e12dfd05d67ac68f4768fdbe23fc48ace22a5aa8ba04c96d58e2750300000009ac51abac63ab5153650524aa680455ce7b000000000000499e50030000000008636a00ac526563ac5051ee030000000003abacabd2b6fe000000000003516563910fb6b5", "65", 0, -1391424484, "48d6a1bd2cd9eec54eb866fc71209418a950402b5d7e52363bfb75c98e141175"},
      -- Test vector 3
      {"6e7e9d4b04ce17afa1e8546b627bb8d89a6a7fefd9d892ec8a192d79c2ceafc01694a6a7e7030000000953ac6a51006353636a33bced1544f797f08ceed02f108da22cd24c9e7809a446c61eb3895914508ac91f07053a01000000055163ab516affffffff11dc54eee8f9e4ff0bcf6b1a1a35b1cd10d63389571375501af7444073bcec3c02000000046aab53514a821f0ce3956e235f71e4c69d91abe1e93fb703bd33039ac567249ed339bf0ba0883ef300000000090063ab65000065ac654bec3cc504bcf499020000000005ab6a52abac64eb060100000000076a6a5351650053bbbc130100000000056a6aab53abd6e1380100000000026a51c4e509b8", "acab655151", 0, 479279909, "2a3d95b09237b72034b23f2d2bb29fa32a58ab5c6aa72f6aafdfa178ab1dd01c"},
      -- Test vector 4 - with OP_CODESEPARATOR in script
      {"73107cbd025c22ebc8c3e0a47b2a760739216a528de8d4dab5d45cbeb3051cebae73b01ca10200000007ab6353656a636affffffffe26816dffc670841e6a6c8c61c586da401df1261a330a6c6b3dd9f9a0789bc9e000000000800ac6552ac6aac51ffffffff0174a8f0010000000004ac52515100000000", "5163ac63635151ac", 1, 1190874345, "06e328de263a87b09beabe222a21627a6ea5c7f560030da31610c4611f4a46bc"},
      -- Test vector 5
      {"e93bbf6902be872933cb987fc26ba0f914fcfc2f6ce555258554dd9939d12032a8536c8802030000000453ac5353eabb6451e074e6fef9de211347d6a45900ea5aaf2636ef7967f565dce66fa451805c5cd10000000003525253ffffffff047dc3e6020000000007516565ac656aabec9eea010000000001633e46e600000000000015080a030000000001ab00000000", "5300ac6a53ab6a", 1, -886562767, "f03aa4fc5f97e826323d0daa03343ebf8a34ed67a1ce18631f8b88e5c992e798"},
      -- Test vector 6
      {"50818f4c01b464538b1e7e7f5ae4ed96ad23c68c830e78da9a845bc19b5c3b0b20bb82e5e9030000000763526a63655352ffffffff023b3f9c040000000008630051516a6a5163a83caf01000000000553ab65510000000000", "6aac", 0, 946795545, "746306f322de2b4b58ffe7faae83f6a72433c22f88062cdde881d4dd8a5a4e2d"},
      -- Test vector 7
      {"a93e93440250f97012d466a6cc24839f572def241c814fe6ae94442cf58ea33eb0fdd9bcc1030000000600636a0065acffffffff5dee3a6e7e5ad6310dea3e5b3ddda1a56bf8de7d3b75889fc024b5e233ec10f80300000007ac53635253ab53ffffffff0160468b04000000000800526a5300ac526a00000000", "ac00636a53", 1, 1773442520, "5c9d3a2ce9365bb72cfabbaa4579c843bb8abf200944612cf8ae4b56a908bcbd"},
      -- Test vector 8 - empty script
      {"c363a70c01ab174230bbe4afe0c3efa2d7f2feaf179431359adedccf30d1f69efe0c86ed390200000002ab51558648fe0231318b04000000000151662170000000000008ac5300006a63acac00000000", "", 0, 2146479410, "191ab180b0d753763671717d051f138d4866b7cb0d1d4811472e64de595d2c70"},
      -- Test vector 9
      {"d3b7421e011f4de0f1cea9ba7458bf3486bee722519efab711a963fa8c100970cf7488b7bb0200000003525352dcd61b300148be5d05000000000000000000", "535251536aac536a", 0, -1960128125, "29aa6d2d752d3310eba20442770ad345b7f6a35f96161ede5f07b33e92053e2a"},
      -- Test vector 10
      {"04bac8c5033460235919a9c63c42b2db884c7c8f2ed8fcd69ff683a0a2cccd9796346a04050200000003655351fcad3a2c5a7cbadeb4ec7acc9836c3f5c3e776e5c566220f7f965cf194f8ef98efb5e3530200000007526a006552526526a2f55ba5f69699ece76692552b399ba908301907c5763d28a15b08581b23179cb01eac03000000075363ab6a516351073942c2025aa98a05000000000765006aabac65abd7ffa6030000000004516a655200000000", "53ac6365ac526a", 1, 764174870, "bf5fdc314ded2372a0ad078568d76c5064bf2affbde0764c335009e56634481b"},
    }

    for i, vec in ipairs(test_vectors) do
      it("passes Bitcoin Core test vector " .. i, function()
        local raw_tx_hex = vec[1]
        local script_hex = vec[2]
        local input_index = vec[3]
        local hash_type = vec[4]
        local expected_hash_hex = vec[5]

        -- Parse transaction
        local tx_bytes = hex_to_bin(raw_tx_hex)
        local tx = serialize.deserialize_transaction(tx_bytes)

        -- Parse script
        local script_code = hex_to_bin(script_hex)

        -- Handle signed hash_type (convert from signed int32)
        if hash_type < 0 then
          hash_type = hash_type + 0x100000000  -- Convert to unsigned
        end

        -- Compute sighash (without FindAndDelete for test vectors, as they pre-process the script)
        local sighash = validation.signature_hash_legacy(tx, input_index, script_code, hash_type)

        -- Compare with expected (note: expected is in display order, sighash is in internal order)
        -- The expected hash is in display byte order (reversed from internal)
        local expected_bytes = hex_to_bin(expected_hash_hex)
        local sighash_reversed = sighash:reverse()

        assert.equals(expected_bytes, sighash_reversed,
          "Test vector " .. i .. ": expected " .. expected_hash_hex ..
          " but got " .. bin_to_hex(sighash_reversed))
      end)
    end
  end)

  describe("bip68 sequence locks", function()
    local bit = require("bit")

    -- Constants from consensus module
    local SEQUENCE_LOCKTIME_DISABLE_FLAG = 0x80000000
    local SEQUENCE_LOCKTIME_TYPE_FLAG = 0x00400000
    local SEQUENCE_LOCKTIME_MASK = 0x0000FFFF
    local SEQUENCE_LOCKTIME_GRANULARITY = 9  -- 512 seconds

    -- Helper to create a test transaction
    local function make_test_tx(version, sequences)
      local tx = types.transaction(version, {}, {}, 0)
      for i, seq in ipairs(sequences) do
        local prev_hash = types.hash256(string.rep(string.char(i), 32))
        tx.inputs[i] = types.txin(types.outpoint(prev_hash, 0), "\x00", seq)
      end
      tx.outputs[1] = types.txout(50000, string.rep("\x00", 25))
      return tx
    end

    describe("calculate_sequence_locks", function()
      it("returns -1, -1 for version 1 transactions", function()
        local tx = make_test_tx(1, {10})

        local function get_utxo_height() return 100 end
        local function get_block_mtp() return 1000000 end

        local min_height, min_time = validation.calculate_sequence_locks(
          tx, 200, get_utxo_height, get_block_mtp, true
        )

        assert.equals(-1, min_height)
        assert.equals(-1, min_time)
      end)

      it("returns -1, -1 when BIP68 not active", function()
        local tx = make_test_tx(2, {10})

        local function get_utxo_height() return 100 end
        local function get_block_mtp() return 1000000 end

        local min_height, min_time = validation.calculate_sequence_locks(
          tx, 200, get_utxo_height, get_block_mtp, false
        )

        assert.equals(-1, min_height)
        assert.equals(-1, min_time)
      end)

      it("returns -1, -1 when disable flag is set", function()
        local tx = make_test_tx(2, {bit.bor(SEQUENCE_LOCKTIME_DISABLE_FLAG, 10)})

        local function get_utxo_height() return 100 end
        local function get_block_mtp() return 1000000 end

        local min_height, min_time = validation.calculate_sequence_locks(
          tx, 200, get_utxo_height, get_block_mtp, true
        )

        assert.equals(-1, min_height)
        assert.equals(-1, min_time)
      end)

      it("calculates height-based lock correctly", function()
        -- Sequence = 10 blocks, UTXO at height 100
        -- min_height = 100 + 10 - 1 = 109 (last invalid)
        local tx = make_test_tx(2, {10})

        local function get_utxo_height() return 100 end
        local function get_block_mtp() return 1000000 end

        local min_height, min_time = validation.calculate_sequence_locks(
          tx, 200, get_utxo_height, get_block_mtp, true
        )

        assert.equals(109, min_height)
        assert.equals(-1, min_time)
      end)

      it("calculates time-based lock correctly", function()
        -- Sequence = TYPE_FLAG | 10 = time-based, 10 * 512 = 5120 seconds
        -- UTXO at height 100, MTP at height 99 = 1000000
        -- min_time = 1000000 + 5120 - 1 = 1005119 (last invalid)
        local seq = bit.bor(SEQUENCE_LOCKTIME_TYPE_FLAG, 10)
        local tx = make_test_tx(2, {seq})

        local utxo_height = 100
        local mtp_at_99 = 1000000

        local function get_utxo_height() return utxo_height end
        local function get_block_mtp(h)
          if h == 99 then return mtp_at_99 end
          return mtp_at_99  -- default
        end

        local min_height, min_time = validation.calculate_sequence_locks(
          tx, 200, get_utxo_height, get_block_mtp, true
        )

        assert.equals(-1, min_height)
        assert.equals(1000000 + 10 * 512 - 1, min_time)
      end)

      it("takes maximum across multiple inputs", function()
        -- Input 1: 10 blocks, UTXO at height 100 -> 109
        -- Input 2: 20 blocks, UTXO at height 50 -> 69
        -- Input 3: 5 blocks, UTXO at height 200 -> 204
        -- max = 204
        local tx = make_test_tx(2, {10, 20, 5})

        local heights = {100, 50, 200}
        local call_count = 0
        local function get_utxo_height(inp)
          for idx, input in ipairs(tx.inputs) do
            if input == inp then
              return heights[idx]
            end
          end
        end
        local function get_block_mtp() return 1000000 end

        local min_height, min_time = validation.calculate_sequence_locks(
          tx, 300, get_utxo_height, get_block_mtp, true
        )

        -- Input 1: 100 + 10 - 1 = 109
        -- Input 2: 50 + 20 - 1 = 69
        -- Input 3: 200 + 5 - 1 = 204
        assert.equals(204, min_height)
        assert.equals(-1, min_time)
      end)

      it("handles mixed height and time locks", function()
        -- Input 1: height-based, 10 blocks, UTXO at height 100 -> 109
        -- Input 2: time-based, 10 units (5120s), UTXO at height 50, MTP@49 = 1000000 -> 1005119
        local seq1 = 10
        local seq2 = bit.bor(SEQUENCE_LOCKTIME_TYPE_FLAG, 10)
        local tx = make_test_tx(2, {seq1, seq2})

        local heights = {100, 50}
        local function get_utxo_height(inp)
          for idx, input in ipairs(tx.inputs) do
            if input == inp then
              return heights[idx]
            end
          end
        end
        local function get_block_mtp(h)
          if h == 49 then return 1000000 end
          return 0
        end

        local min_height, min_time = validation.calculate_sequence_locks(
          tx, 300, get_utxo_height, get_block_mtp, true
        )

        assert.equals(109, min_height)
        assert.equals(1000000 + 10 * 512 - 1, min_time)
      end)

      it("handles 0xFFFFFFFF sequence (RBF opt-in, BIP68 disabled)", function()
        -- 0xFFFFFFFF has disable flag set
        local tx = make_test_tx(2, {0xFFFFFFFF})

        local function get_utxo_height() return 100 end
        local function get_block_mtp() return 1000000 end

        local min_height, min_time = validation.calculate_sequence_locks(
          tx, 200, get_utxo_height, get_block_mtp, true
        )

        assert.equals(-1, min_height)
        assert.equals(-1, min_time)
      end)

      it("handles 0xFFFFFFFE sequence (RBF opt-in, BIP68 disabled)", function()
        -- 0xFFFFFFFE has disable flag set (bit 31 = 1)
        local tx = make_test_tx(2, {0xFFFFFFFE})

        local function get_utxo_height() return 100 end
        local function get_block_mtp() return 1000000 end

        local min_height, min_time = validation.calculate_sequence_locks(
          tx, 200, get_utxo_height, get_block_mtp, true
        )

        assert.equals(-1, min_height)
        assert.equals(-1, min_time)
      end)
    end)

    describe("check_sequence_locks", function()
      it("passes when height requirement is satisfied", function()
        -- min_height = 109 (last invalid), block_height = 110
        local result = validation.check_sequence_locks(109, -1, 110, 2000000)
        assert.is_true(result)
      end)

      it("fails when height requirement is not satisfied", function()
        -- min_height = 109 (last invalid), block_height = 109
        local result = validation.check_sequence_locks(109, -1, 109, 2000000)
        assert.is_false(result)
      end)

      it("fails when height is below min_height", function()
        -- min_height = 109 (last invalid), block_height = 100
        local result = validation.check_sequence_locks(109, -1, 100, 2000000)
        assert.is_false(result)
      end)

      it("passes when time requirement is satisfied", function()
        -- min_time = 1005119 (last invalid), prev_block_mtp = 1005120
        local result = validation.check_sequence_locks(-1, 1005119, 200, 1005120)
        assert.is_true(result)
      end)

      it("fails when time requirement is not satisfied", function()
        -- min_time = 1005119 (last invalid), prev_block_mtp = 1005119
        local result = validation.check_sequence_locks(-1, 1005119, 200, 1005119)
        assert.is_false(result)
      end)

      it("fails when time is below min_time", function()
        -- min_time = 1005119 (last invalid), prev_block_mtp = 1000000
        local result = validation.check_sequence_locks(-1, 1005119, 200, 1000000)
        assert.is_false(result)
      end)

      it("passes when both requirements are satisfied", function()
        local result = validation.check_sequence_locks(109, 1005119, 200, 2000000)
        assert.is_true(result)
      end)

      it("fails when only height requirement is satisfied", function()
        local result = validation.check_sequence_locks(109, 1005119, 200, 1000000)
        assert.is_false(result)
      end)

      it("fails when only time requirement is satisfied", function()
        local result = validation.check_sequence_locks(109, 1005119, 100, 2000000)
        assert.is_false(result)
      end)

      it("passes with -1, -1 (no locks)", function()
        local result = validation.check_sequence_locks(-1, -1, 0, 0)
        assert.is_true(result)
      end)
    end)
  end)
end)
