-- test_connect_block_w93.lua
-- W93 comprehensive audit: ConnectBlock + ConnectTip + UpdateCoins gates.
--
-- Mirrors W92 (DisconnectBlock + ApplyTxInUndo) by exercising the symmetric
-- gates on the CONNECT side.  All gate refs are validation.cpp:2295-2700.
--
--   Gate 1  (Core:2339-2343)   genesis-hash short-circuit
--   Gate 2  (Core:2332-2333)   view.GetBestBlock() == hashPrevBlock
--   Gate 14 (Core:2569-2572)   bad-blk-sigops in-loop early-bail + string
--   Gate 16 (Core:coins.cpp:91) CoinView:add IsUnspendable short-circuit
--                              (symmetric to W92 disconnect-side fix)
--   Gate 17 (Core:2610-2614)   bad-cb-amount error string + value cap
--   Cousin:                    bad-txns-BIP30 + bad-txns-accumulated-fee-outofrange
--                              error-string parity (existing, regression-pinned)
--
-- Reference: bitcoin-core/src/validation.cpp:2295-2673, coins.cpp:89-130.

package.path = "./src/?.lua;" .. package.path
package.cpath = "./lib/?.so;" .. package.cpath

local utxo_mod    = require("lunarblock.utxo")
local validation  = require("lunarblock.validation")
local consensus   = require("lunarblock.consensus")
local types       = require("lunarblock.types")
local crypto      = require("lunarblock.crypto")
local serialize   = require("lunarblock.serialize")
local storage_mod = require("lunarblock.storage")

local pass, fail = 0, 0
local function check(name, cond, detail)
  if cond then
    io.write("PASS: " .. name .. "\n")
    pass = pass + 1
  else
    io.write("FAIL: " .. name .. (detail and (" -- " .. tostring(detail)) or "") .. "\n")
    fail = fail + 1
  end
end

local REGTEST = consensus.networks.regtest

local function tmpdir()
  local path = os.tmpname() .. "_w93"
  os.execute("mkdir -p " .. path)
  return path
end

local function make_coinbase(height, padding_byte, value_override, n_outputs)
  local height_enc = validation.encode_bip34_height(height)
  local pad_byte   = padding_byte or 0
  local padding    = string.rep(string.char(pad_byte), 20)
  local outs = {}
  local total_outs = n_outputs or 1
  local val = value_override or 5000000000
  for i = 1, total_outs do
    outs[i] = { value = (i == 1) and val or 0, script_pubkey = "\x51" }
  end
  return {
    version = 1, locktime = 0,
    inputs = {{
      prev_out   = { hash = types.hash256(string.rep("\0",32)), index = 0xFFFFFFFF },
      script_sig = height_enc .. "/LunarBlock/" .. padding,
      sequence   = 0xFFFFFFFF,
      witness    = {},
    }},
    outputs = outs,
  }
end

local function mine_pow(header)
  for n = 0, 0xFFFFFF do
    header.nonce = n
    local h = validation.compute_block_hash(header)
    if string.byte(h.bytes, 32) < 0x80 then return end
  end
end

local function make_block(prev_hash, height, timestamp, padding_byte, value_override, n_outputs)
  local cb = make_coinbase(height, padding_byte, value_override, n_outputs)
  local base  = serialize.serialize_transaction(cb, false)
  local total = serialize.serialize_transaction(cb, true)
  cb._cached_base_data    = base
  cb._cached_witness_data = total
  cb._cached_txid         = crypto.hash256_type(base)
  cb._cached_wtxid        = crypto.hash256_type(total)
  local merkle = crypto.compute_merkle_root({cb._cached_txid})
  local header = {
    version = 0x20000000, prev_hash = prev_hash,
    merkle_root = merkle, timestamp = timestamp,
    bits = REGTEST.pow_limit_bits, nonce = 0,
  }
  mine_pow(header)
  return { header = header, transactions = {cb} }, validation.compute_block_hash(header)
end

io.write("\n=== Gate 1: genesis-hash short-circuit ===\n")

do
  -- Build a fresh chain state without invoking connect_genesis(), then call
  -- connect_block() with the regtest genesis hash.  Core's ConnectBlock
  -- short-circuits on genesis and returns true without touching transactions.
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)

  -- Construct a synthetic genesis-mimicking block.  We don't need the actual
  -- coinbase tx bytes — Gate 1 short-circuits BEFORE iterating transactions.
  local gen_hash = types.hash256_from_hex(REGTEST.genesis_hash)
  local fake_genesis = {
    header = {
      version = 1, prev_hash = types.hash256_zero(),
      merkle_root = types.hash256_zero(),
      timestamp = REGTEST.genesis.timestamp,
      bits = REGTEST.genesis.bits, nonce = REGTEST.genesis.nonce,
    },
    transactions = {{
      version = 1, locktime = 0,
      inputs = {{
        prev_out = { hash = types.hash256_zero(), index = 0xFFFFFFFF },
        script_sig = "", sequence = 0xFFFFFFFF, witness = {},
      }},
      outputs = {{ value = 0, script_pubkey = "\x6a" }},  -- unspendable: never added
    }},
  }
  -- Use the canonical genesis hash so Gate 1 short-circuits regardless of
  -- header content (the hash is what gates).
  local ok, fees = cs:connect_block(fake_genesis, 0, gen_hash)
  check("Gate 1: connect_block on genesis hash short-circuits OK",
    ok == true, "ok=" .. tostring(ok) .. " fees=" .. tostring(fees))
  check("Gate 1: tip_hash advanced to genesis hash",
    types.hash256_eq(cs.tip_hash, gen_hash))
  check("Gate 1: tip_height = 0",
    cs.tip_height == 0)
  -- Genesis coinbase NOT in UTXO (skipped).
  local txid = validation.compute_txid(fake_genesis.transactions[1])
  check("Gate 1: genesis coinbase NOT added to UTXO (short-circuit)",
    not cs.coin_view:have(txid, 0))

  stor.close()
  os.execute("rm -rf " .. dir)
end

io.write("\n=== Gate 2: view.GetBestBlock() == hashPrevBlock ===\n")

do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:connect_genesis()
  local genesis_hash = cs.tip_hash

  -- Build a block whose prev_hash is BOGUS (not the current tip).
  -- Gate 2 must catch this and return nil + "prev_hash mismatch".
  local bogus_prev = types.hash256(string.rep("\xff", 32))
  local cb = make_coinbase(1, 0x01)
  local base = serialize.serialize_transaction(cb, false)
  local total = serialize.serialize_transaction(cb, true)
  cb._cached_base_data, cb._cached_witness_data = base, total
  cb._cached_txid  = crypto.hash256_type(base)
  cb._cached_wtxid = crypto.hash256_type(total)
  local merkle = crypto.compute_merkle_root({cb._cached_txid})
  local header = {
    version = 0x20000000, prev_hash = bogus_prev,  -- WRONG parent
    merkle_root = merkle, timestamp = 1500000001,
    bits = REGTEST.pow_limit_bits, nonce = 0,
  }
  mine_pow(header)
  local bh = validation.compute_block_hash(header)
  local blk = { header = header, transactions = {cb} }

  local ok, err = cs:connect_block(blk, 1, bh)
  check("Gate 2: bogus prev_hash → connect_block returns nil",
    ok == nil, "ok=" .. tostring(ok))
  check("Gate 2: error mentions prev_hash mismatch",
    err and string.find(err, "prev_hash mismatch", 1, true) ~= nil,
    "got: " .. tostring(err))

  stor.close()
  os.execute("rm -rf " .. dir)
end

do
  -- Negative case: correct prev_hash → Gate 2 passes silently.
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:connect_genesis()
  local genesis_hash = cs.tip_hash

  local blk, bh = make_block(genesis_hash, 1, 1500000002, 0x02)
  local ok, fees = cs:connect_block(blk, 1, bh)
  check("Gate 2: correct prev_hash → connect_block returns OK",
    ok == true, "err=" .. tostring(fees))

  stor.close()
  os.execute("rm -rf " .. dir)
end

io.write("\n=== Gate 14: bad-blk-sigops error string ===\n")

do
  -- We synthesize a block whose total sigop cost exceeds
  -- MAX_BLOCK_SIGOPS_COST (80000).  Quickest path: a coinbase with many
  -- OP_CHECKSIG opcodes in its scriptPubKey output.  legacy_sigop_count
  -- multiplies by WITNESS_SCALE_FACTOR=4, so we need >20000 CHECKSIGs.
  -- But scriptPubKey is bounded by MAX_SCRIPT_SIZE=10000.  Instead we put
  -- the CHECKSIGs into the scriptSig of the coinbase input — Core counts
  -- legacy sigops from BOTH scriptSig and scriptPubKey (script.cpp
  -- GetSigOpCount).
  --
  -- Actually simpler: build a coinbase scriptSig with 20001 OP_CHECKSIGs.
  -- coinbase scriptSig is bounded only by 100 bytes for height-encoded
  -- portion; in regtest there's no scriptSig size constraint other than
  -- 100 byte general limit.  Easier: directly test the error string by
  -- artificially bumping a fake total_sigop_cost via an internal hook.
  --
  -- Pragmatic alternative: drive the failure through script.lua's
  -- get_legacy_sigop_count by hand-crafting a coinbase output whose
  -- scriptPubKey is 9999 bytes of OP_CHECKSIG (0xac), then test that the
  -- "bad-blk-sigops" error string appears.
  --
  -- coinbase output scriptPubKey: ~9999 bytes of OP_CHECKSIG → ~9999
  -- legacy sigops *4 = ~40000 cost.  Still under the limit.  We'd need
  -- multiple outputs to exceed 80000; coinbase can have up to ~125k outs
  -- in principle but each output incurs serialization overhead.  Easiest:
  -- 3 outputs of 9999 CHECKSIG each → 29997 sigops * 4 = 119988 > 80000.
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:connect_genesis()
  local genesis_hash = cs.tip_hash

  -- Build a coinbase with 3 outputs each containing 9999 OP_CHECKSIG bytes.
  local big_script = string.rep("\xac", 9999)
  local height_enc = validation.encode_bip34_height(1)
  local cb = {
    version = 1, locktime = 0,
    inputs = {{
      prev_out   = { hash = types.hash256(string.rep("\0",32)), index = 0xFFFFFFFF },
      script_sig = height_enc .. "/LunarBlock/" .. string.rep("\x01", 20),
      sequence   = 0xFFFFFFFF, witness = {},
    }},
    outputs = {
      { value = 5000000000, script_pubkey = big_script },
      { value = 0,          script_pubkey = big_script },
      { value = 0,          script_pubkey = big_script },
    },
  }
  local base  = serialize.serialize_transaction(cb, false)
  local total = serialize.serialize_transaction(cb, true)
  cb._cached_base_data    = base
  cb._cached_witness_data = total
  cb._cached_txid         = crypto.hash256_type(base)
  cb._cached_wtxid        = crypto.hash256_type(total)
  local merkle = crypto.compute_merkle_root({cb._cached_txid})
  local header = {
    version = 0x20000000, prev_hash = genesis_hash,
    merkle_root = merkle, timestamp = 1500000003,
    bits = REGTEST.pow_limit_bits, nonce = 0,
  }
  mine_pow(header)
  local bh = validation.compute_block_hash(header)
  local blk = { header = header, transactions = {cb} }

  local ok, err = cs:connect_block(blk, 1, bh)
  check("Gate 14: sigop overflow → connect_block returns nil",
    ok == nil, "ok=" .. tostring(ok))
  check("Gate 14: error string starts with 'bad-blk-sigops'",
    err and string.find(err, "bad-blk-sigops", 1, true) ~= nil,
    "got: " .. tostring(err))

  stor.close()
  os.execute("rm -rf " .. dir)
end

io.write("\n=== Gate 16: CoinView:add IsUnspendable short-circuit ===\n")

do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  local txid = types.hash256(string.rep("\x33", 32))

  -- OP_RETURN script → must NOT be added by CoinView:add.
  local op_return = "\x6a\x04test"
  cs.coin_view:add(txid, 0, utxo_mod.utxo_entry(0, op_return, 1, false))
  check("Gate 16: CoinView:add filtered OP_RETURN entry",
    not cs.coin_view:have(txid, 0))

  -- Over-MAX_SCRIPT_SIZE script → must NOT be added.
  local oversize = string.rep("\x01", 10001)
  cs.coin_view:add(txid, 1, utxo_mod.utxo_entry(0, oversize, 1, false))
  check("Gate 16: CoinView:add filtered over-MAX_SCRIPT_SIZE entry",
    not cs.coin_view:have(txid, 1))

  -- Normal P2PKH script → MUST be added.
  local p2pkh = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"
  cs.coin_view:add(txid, 2, utxo_mod.utxo_entry(1000, p2pkh, 1, false))
  check("Gate 16: CoinView:add accepted P2PKH entry",
    cs.coin_view:have(txid, 2))

  stor.close()
  os.execute("rm -rf " .. dir)
end

io.write("\n=== Gate 17: bad-cb-amount error string ===\n")

do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:connect_genesis()
  local genesis_hash = cs.tip_hash

  -- Coinbase claims subsidy + 1 sat with no fees in the block.
  local blk, bh = make_block(genesis_hash, 1, 1500000004, 0x04, 5000000001, 1)
  local ok, err = cs:connect_block(blk, 1, bh)
  check("Gate 17: coinbase value > subsidy → connect_block returns nil",
    ok == nil, "ok=" .. tostring(ok))
  check("Gate 17: error string starts with 'bad-cb-amount'",
    err and string.find(err, "bad-cb-amount", 1, true) ~= nil,
    "got: " .. tostring(err))
  -- Format mirrors Core: "coinbase pays too much (actual=N vs limit=M)".
  check("Gate 17: error includes 'actual=' and 'limit=' tokens (Core parity)",
    err and string.find(err, "actual=", 1, true) ~= nil
        and string.find(err, "limit=",  1, true) ~= nil,
    "got: " .. tostring(err))

  stor.close()
  os.execute("rm -rf " .. dir)
end

io.write("\n=== Gate 17: coinbase value == subsidy → OK ===\n")

do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:connect_genesis()
  local genesis_hash = cs.tip_hash

  local blk, bh = make_block(genesis_hash, 1, 1500000005, 0x05, 5000000000, 1)
  local ok, fees = cs:connect_block(blk, 1, bh)
  check("Gate 17: coinbase value == subsidy → connect_block returns OK",
    ok == true, "err=" .. tostring(fees))
  check("Gate 17: fees == 0 in coinbase-only block",
    fees == 0, "fees=" .. tostring(fees))

  stor.close()
  os.execute("rm -rf " .. dir)
end

io.write("\n=== Cousin: bad-txns-BIP30 error string (regression pin) ===\n")

do
  -- Build a block whose coinbase has the same txid as a coinbase already in
  -- the UTXO set, on a network with no BIP34-bypass (regtest bip34_hash=nil).
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:connect_genesis()
  local genesis_hash = cs.tip_hash

  local blk1, bh1 = make_block(genesis_hash, 1, 1500000010, 0x10)
  assert(cs:connect_block(blk1, 1, bh1))
  local cb_txid = validation.compute_txid(blk1.transactions[1])

  -- Now produce blk2 with a DIFFERENT coinbase that nonetheless ends up at the
  -- same txid by reusing blk1's exact coinbase tx structure.  Easiest: just
  -- reuse blk1's coinbase tx object in a new block.
  local cb2 = make_coinbase(1, 0x10)  -- identical coinbase to blk1
  local base = serialize.serialize_transaction(cb2, false)
  local total = serialize.serialize_transaction(cb2, true)
  cb2._cached_base_data, cb2._cached_witness_data = base, total
  cb2._cached_txid  = crypto.hash256_type(base)
  cb2._cached_wtxid = crypto.hash256_type(total)
  check("Cousin: duplicate coinbase produces same txid",
    types.hash256_eq(cb2._cached_txid, cb_txid))

  local merkle = crypto.compute_merkle_root({cb2._cached_txid})
  local header = {
    version = 0x20000000, prev_hash = bh1,
    merkle_root = merkle, timestamp = 1500000011,
    bits = REGTEST.pow_limit_bits, nonce = 0,
  }
  mine_pow(header)
  local bh2 = validation.compute_block_hash(header)
  local blk2 = { header = header, transactions = {cb2} }

  local ok, err = cs:connect_block(blk2, 2, bh2)
  check("Cousin: duplicate coinbase → connect_block returns nil",
    ok == nil, "ok=" .. tostring(ok))
  check("Cousin: error string contains 'bad-txns-BIP30'",
    err and string.find(err, "bad-txns-BIP30", 1, true) ~= nil,
    "got: " .. tostring(err))

  stor.close()
  os.execute("rm -rf " .. dir)
end

io.write("\n=== Smoke: simple regtest block connects cleanly + tip advances ===\n")

do
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:connect_genesis()
  local genesis_hash = cs.tip_hash

  local blk1, bh1 = make_block(genesis_hash, 1, 1500000020, 0x20)
  local ok1, fees1 = cs:connect_block(blk1, 1, bh1)
  check("Smoke: block 1 connects", ok1 == true, tostring(fees1))
  check("Smoke: tip advanced to bh1", types.hash256_eq(cs.tip_hash, bh1))
  check("Smoke: height = 1", cs.tip_height == 1)
  check("Smoke: cb1 UTXO present",
    cs.coin_view:have(validation.compute_txid(blk1.transactions[1]), 0))

  local blk2, bh2 = make_block(bh1, 2, 1500000021, 0x21)
  local ok2, fees2 = cs:connect_block(blk2, 2, bh2)
  check("Smoke: block 2 connects", ok2 == true, tostring(fees2))
  check("Smoke: tip advanced to bh2", types.hash256_eq(cs.tip_hash, bh2))
  check("Smoke: height = 2", cs.tip_height == 2)

  stor.close()
  os.execute("rm -rf " .. dir)
end

io.write(string.format("\n=== %d passed, %d failed ===\n", pass, fail))
os.exit(fail > 0 and 1 or 0)
