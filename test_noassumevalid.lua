-- verify_noassumevalid.lua
--
-- PROOF that --noassumevalid FORCES full script verification and is NOT a dead
-- flag. Two composable layers, chained end-to-end:
--
--   PROOF A (flag -> gate): should_skip_script_validation() returns TRUE for a
--     block below the assumevalid checkpoint when assumevalid is configured
--     (all 6 Core ConnectBlock conditions met, via the REAL
--     make_assumevalid_callbacks), and returns FALSE the instant
--     network.assumevalid is cleared to nil (exactly what --noassumevalid does).
--
--   PROOF B (gate -> interpreter): feeding those exact skip booleans into
--     ChainState:connect_block on a block that spends a coin with a
--     DELIBERATELY-INVALID signature -> skip=true ACCEPTS the block (bad sig
--     never checked), skip=false REJECTS it with a script-verification error
--     (the interpreter ran on the input).
--
-- Chained: --noassumevalid -> assumevalid=nil -> gate returns false ->
--          connect_block runs the interpreter -> bad signature rejected.
--
-- Run: cd lunarblock && luajit verify_noassumevalid.lua

package.path = "./src/?.lua;" .. package.path
package.cpath = "./lib/?.so;" .. package.cpath

local consensus   = require("lunarblock.consensus")
local utxo_mod    = require("lunarblock.utxo")
local validation  = require("lunarblock.validation")
local types       = require("lunarblock.types")
local crypto      = require("lunarblock.crypto")
local serialize   = require("lunarblock.serialize")
local storage_mod = require("lunarblock.storage")

local pass, fail = 0, 0
local function check(name, cond, detail)
  if cond then
    io.write("PASS: " .. name .. "\n"); pass = pass + 1
  else
    io.write("FAIL: " .. name .. (detail and ("  -- " .. tostring(detail)) or "") .. "\n")
    fail = fail + 1
  end
end

--------------------------------------------------------------------------------
-- PROOF A — flag flips the skip gate
--------------------------------------------------------------------------------
io.write("=== PROOF A: --noassumevalid flips should_skip_script_validation ===\n")

-- A mainnet-shaped network with assumevalid CONFIGURED (the default state).
local AV_HASH   = string.rep("aa", 32)   -- 64-hex assumevalid block hash
local BLK_HASH  = string.rep("bb", 32)   -- 64-hex hash of the block we connect
local BLK_HEIGHT = 200000                -- well below the AV block (205000)
local AV_HEIGHT  = 205000

local net = {
  name = "mainnet-sim",
  assumevalid = AV_HASH,
  -- all-zero min chain work (64 hex chars) so Condition 5 (work >= min) passes trivially
  min_chain_work = string.rep("0", 64),
}

-- REAL header-chain shape consumed by make_assumevalid_callbacks: the AV block
-- is in the index, and the block we connect is the canonical block at its height.
local header_chain = {
  headers = { [AV_HASH] = { height = AV_HEIGHT } },
  height_to_hash = { [BLK_HEIGHT] = BLK_HASH, [AV_HEIGHT] = AV_HASH },
  header_tip_height = AV_HEIGHT,
}

local best_work = "00000000000000000000000000000000000000000000000000000000ffffffff"

local function eval_skip(network)
  local av_in_index, av_is_ancestor, av_on_best =
    consensus.make_assumevalid_callbacks(network, header_chain)
  return consensus.should_skip_script_validation(
    network, BLK_HEIGHT, BLK_HASH,
    av_in_index, av_is_ancestor, av_on_best,
    best_work, AV_HEIGHT)
end

-- (1) assumevalid configured -> skip == true (Core would skip sig checks here)
local skip_with_av, reason_with = eval_skip(net)
check("assumevalid CONFIGURED -> skip_scripts == true (would bypass interpreter)",
  skip_with_av == true, "got " .. tostring(skip_with_av) .. " / " .. tostring(reason_with))

-- (2) --noassumevalid clears network.assumevalid = nil -> skip == false
net.assumevalid = nil   -- this is precisely what main.lua does for --noassumevalid
local skip_without_av, reason_without = eval_skip(net)
check("--noassumevalid (assumevalid=nil) -> skip_scripts == false (interpreter forced)",
  skip_without_av == false, "got " .. tostring(skip_without_av) .. " / " .. tostring(reason_without))
io.write("       reason when disabled: " .. tostring(reason_without) .. "\n")

--------------------------------------------------------------------------------
-- PROOF B — the skip boolean actually gates the interpreter
--------------------------------------------------------------------------------
io.write("\n=== PROOF B: connect_block with a BAD signature, skip=true vs skip=false ===\n")

local REGTEST = consensus.networks.regtest

local function mine_pow(header)
  for n = 0, 0xFFFFFF do
    header.nonce = n
    local h = validation.compute_block_hash(header)
    if string.byte(h.bytes, 32) < 0x80 then return end
  end
end

local function tmpdir()
  local p = os.tmpname() .. "_av0"
  os.execute("mkdir -p " .. p)
  return p
end

-- The coin we plant: a P2PK output (<33-byte pubkey> OP_CHECKSIG). Spending it
-- REQUIRES a valid ECDSA signature -> a garbage signature makes CHECKSIG fail
-- iff the interpreter is invoked.
local PUBKEY = "\x02" .. string.rep("\x11", 32)          -- structurally-shaped compressed key
local P2PK   = "\x21" .. PUBKEY .. "\xac"                -- PUSH33 <pk> OP_CHECKSIG
local COIN_TXID = types.hash256(string.rep("\xcd", 32))  -- the outpoint's txid
local COIN_VALUE = 100000000                             -- 1 BTC, NON-coinbase

-- A block at height 1 that spends the planted coin with a GARBAGE signature.
local function build_block(prev_hash)
  local height_enc = validation.encode_bip34_height(1)
  local coinbase = {
    version = 1, locktime = 0,
    inputs = {{
      prev_out   = { hash = types.hash256(string.rep("\0", 32)), index = 0xFFFFFFFF },
      script_sig = height_enc .. "/av0-verify/" .. string.rep("\x01", 12),
      sequence   = 0xFFFFFFFF, witness = {},
    }},
    outputs = { { value = 0, script_pubkey = "\x51" } },  -- OP_TRUE, subsidy=0 claimed
  }
  -- Garbage "signature": 9 zero bytes pushed as the scriptSig. Not a valid
  -- ECDSA/DER signature -> OP_CHECKSIG yields false -> verify_script fails.
  local bad_sig = "\x09" .. string.rep("\x00", 9)
  local spend = {
    version = 1, locktime = 0,
    inputs = {{
      prev_out   = { hash = COIN_TXID, index = 0 },
      script_sig = bad_sig,
      sequence   = 0xFFFFFFFF, witness = {},
    }},
    outputs = { { value = COIN_VALUE - 1000, script_pubkey = "\x51" } },  -- 1000 sat fee
  }
  for _, tx in ipairs({ coinbase, spend }) do
    local base  = serialize.serialize_transaction(tx, false)
    local total = serialize.serialize_transaction(tx, true)
    tx._cached_base_data    = base
    tx._cached_witness_data = total
    tx._cached_txid         = crypto.hash256_type(base)
    tx._cached_wtxid        = crypto.hash256_type(total)
  end
  local merkle = crypto.compute_merkle_root({ coinbase._cached_txid, spend._cached_txid })
  local header = {
    version = 0x20000000, prev_hash = prev_hash,
    merkle_root = merkle, timestamp = 1600000000,
    bits = REGTEST.pow_limit_bits, nonce = 0,
  }
  mine_pow(header)
  return { header = header, transactions = { coinbase, spend } },
         validation.compute_block_hash(header)
end

-- Build a fresh, coin-seeded chainstate for one connect_block attempt.
local function fresh_state()
  local dir = tmpdir()
  local stor = storage_mod.open(dir)
  local cs = utxo_mod.new_chain_state(stor, REGTEST)
  cs:connect_genesis()
  -- Plant the spendable P2PK coin (NON-coinbase so no maturity gate).
  cs.coin_view:add(COIN_TXID, 0, utxo_mod.utxo_entry(COIN_VALUE, P2PK, 0, false))
  return cs, stor, dir, cs.tip_hash
end

-- (3) skip=true (assumevalid ON): the bad signature is NEVER checked -> accepted.
do
  local cs, stor, dir, genesis = fresh_state()
  local blk, bh = build_block(genesis)
  -- feed PROOF A's skip_with_av (true) exactly
  local ok, res = pcall(function()
    return cs:connect_block(blk, 1, bh, nil, nil, skip_with_av, false)
  end)
  check("skip_scripts=true (assumevalid ON) -> bad-sig block ACCEPTED (interpreter bypassed)",
    ok == true and res ~= nil,
    "pcall_ok=" .. tostring(ok) .. " ret=" .. tostring(res))
  stor.close(); os.execute("rm -rf " .. dir)
end

-- (4) skip=false (--noassumevalid): the interpreter runs -> bad sig REJECTED.
do
  local cs, stor, dir, genesis = fresh_state()
  local blk, bh = build_block(genesis)
  -- feed PROOF A's skip_without_av (false) exactly
  local ok, err = pcall(function()
    return cs:connect_block(blk, 1, bh, nil, nil, skip_without_av, false)
  end)
  local is_script_reject = (ok == false)
    and type(err) == "string"
    and err:find("Script verification failed", 1, true) ~= nil
  check("skip_scripts=false (--noassumevalid) -> bad-sig block REJECTED by interpreter",
    is_script_reject,
    "pcall_ok=" .. tostring(ok) .. " err=" .. tostring(err))
  io.write("       reject error: " .. tostring(err) .. "\n")
  stor.close(); os.execute("rm -rf " .. dir)
end

--------------------------------------------------------------------------------
io.write(string.format("\n==== %d passed, %d failed ====\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
