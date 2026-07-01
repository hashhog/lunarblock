-- test_submitblock_discard_dirty.lua
--
-- EFFECTIVE regression test for the submitblock UTXO-cache-poisoning bug found
-- by adversarial-fuzz wave-2 (2026-07-01): a block submitted via `submitblock`
-- that SPENDS a real coin and then FAILS a later consensus gate left that coin
-- marked spent in the in-memory coin_view (accept_block's contract is that the
-- caller must coin_view:discard_dirty() on failure — the P2P/IBD path in
-- main.lua does; the submitblock RPC path did NOT).  The next block spending
-- the same coin then false-rejected `bad-txns-inputs-missingorspent`, and the
-- next successful block's flush persisted the phantom delete to the chainstate
-- DB (permanent UTXO corruption).
--
-- Mechanism reproduced faithfully at the RPC layer:
--   1. seed regtest genesis + 101 coinbase-only blocks (h1 coinbase matures).
--   2. submitblock an INVALID block at 102 whose single tx spends the height-1
--      coinbase and then over-pays its output (bad-txns-in-belowout) — the
--      spend lands in the cache before the failure.  Expect REJECT.
--   3. submitblock a VALID block at 102 that spends the same height-1 coinbase
--      correctly.
--
-- PRE-FIX  : step 3 REJECTs bad-txns-inputs-missingorspent (test FAILS).
-- POST-FIX : step 3 ACCEPTs (result == null) (test PASSES).
--
-- Reference: bitcoin-core/src/validation.cpp ConnectTip uses a temporary
-- CCoinsViewCache that is simply discarded on ConnectBlock failure, so the
-- base CoinsTip is never mutated by a rejected block.  This test asserts the
-- lunarblock equivalent: a rejected submitblock leaves the coin_view untouched.

package.path = "./src/?.lua;" .. package.path
package.cpath = "./lib/?.so;" .. package.cpath

local utxo_mod    = require("lunarblock.utxo")
local validation  = require("lunarblock.validation")
local consensus   = require("lunarblock.consensus")
local types       = require("lunarblock.types")
local crypto      = require("lunarblock.crypto")
local serialize   = require("lunarblock.serialize")
local storage_mod = require("lunarblock.storage")
local rpc_mod     = require("lunarblock.rpc")

local REGTEST = consensus.networks.regtest

local pass, fail = 0, 0
local function check(name, cond, detail)
  if cond then
    io.write("PASS: " .. name .. "\n"); pass = pass + 1
  else
    io.write("FAIL: " .. name .. (detail and (" -- " .. tostring(detail)) or "") .. "\n"); fail = fail + 1
  end
end

local function tmpdir()
  local path = os.tmpname() .. "_sbdd"; os.execute("mkdir -p " .. path); return path
end

local function mine_pow(header)
  for n = 0, 0xFFFFFF do
    header.nonce = n
    local h = validation.compute_block_hash(header)
    if string.byte(h.bytes, 32) < 0x80 then return end
  end
end

local function make_coinbase(height)
  local height_enc = validation.encode_bip34_height(height)
  return {
    version = 1, locktime = 0,
    inputs = {{
      prev_out   = { hash = types.hash256(string.rep("\0", 32)), index = 0xFFFFFFFF },
      script_sig = height_enc .. "/discard-test/" .. string.rep("\0", 12),
      sequence   = 0xFFFFFFFF, witness = {},
    }},
    outputs = {{ value = 5000000000, script_pubkey = "\x51" }},  -- OP_TRUE
  }
end

-- Build a block from a coinbase + list of extra txs; compute merkle + PoW.
local function build_block(prev_hash, height, timestamp, extra_txs, cb_extra)
  local cb = make_coinbase(height)
  -- Perturb the coinbase scriptSig so sibling blocks at the same height differ.
  if cb_extra then cb.inputs[1].script_sig = cb.inputs[1].script_sig .. cb_extra end
  local txs = { cb }
  for _, t in ipairs(extra_txs or {}) do txs[#txs + 1] = t end
  local txids = {}
  for i, t in ipairs(txs) do txids[i] = validation.compute_txid(t) end
  local merkle = crypto.compute_merkle_root(txids)
  local header = {
    version = 0x20000000, prev_hash = prev_hash, merkle_root = merkle,
    timestamp = timestamp, bits = REGTEST.pow_limit_bits, nonce = 0,
  }
  mine_pow(header)
  return { header = header, transactions = txs },
         validation.compute_block_hash(header), txids[1]
end

-- A tx spending (prev_txid:0) paying `value` to OP_TRUE.
local function spend_tx(prev_txid, value)
  return {
    version = 1, locktime = 0,
    inputs = {{
      prev_out = { hash = prev_txid, index = 0 },
      script_sig = "", sequence = 0xFFFFFFFF, witness = {},
    }},
    outputs = {{ value = value, script_pubkey = "\x51" }},
  }
end

io.write("\n=== submitblock discard_dirty regression ===\n")

local dir = tmpdir()
local stor = storage_mod.open(dir)
local cs = utxo_mod.new_chain_state(stor, REGTEST)
cs:init()  -- connect genesis (height 0)

-- Build the RPC server bound to the chain state — the code under test.
local rpc = rpc_mod.new({ rpcport = 0, network = REGTEST, chain_state = cs, storage = stor })

-- Serialize a block to hex for submitblock.
local function block_hex(block)
  return (serialize.serialize_block(block):gsub(".", function(c)
    return string.format("%02x", string.byte(c)) end))
end

-- Seed 101 coinbase-only blocks THROUGH submitblock (stores headers/bodies so
-- the MTP time check works and the height-1 coinbase matures at height 102).
local prev = types.hash256_from_hex(REGTEST.genesis_hash)
local ts = REGTEST.genesis.timestamp + 1
local h1_cb_txid
for h = 1, 101 do
  local block, _, cb_txid = build_block(prev, h, ts)
  ts = ts + 1
  local res = rpc.methods["submitblock"](rpc, { block_hex(block) })
  assert(res == nil or type(res) ~= "string",
    "seed submitblock h=" .. h .. " rejected: " .. tostring(res))
  if h == 1 then h1_cb_txid = cb_txid end
  prev = validation.compute_block_hash(block.header)
end
check("seeded to height 101", cs.tip_height == 101, "tip=" .. tostring(cs.tip_height))
check("height-1 coinbase present after seed",
  cs.coin_view:get(h1_cb_txid, 0) ~= nil)

local tip101 = cs.tip_hash
local next_ts = ts

-- STEP 2: INVALID block @102 — spends h1 coinbase then over-pays (in-belowout).
local bad_spend  = spend_tx(h1_cb_txid, 6000000000)  -- 60 BTC out > 50 BTC in
local bad_block  = build_block(tip101, 102, next_ts, { bad_spend }, "\x01")
local bad_res = rpc.methods["submitblock"](rpc, { block_hex(bad_block) })
-- submitblock returns a BIP-22 reject string on failure (cjson.null on success).
check("invalid poisoning block is REJECTED", type(bad_res) == "string",
  "result=" .. tostring(bad_res))
check("node tip unchanged after reject (still 101)",
  types.hash256_eq(cs.tip_hash, tip101))

-- STEP 3: VALID block @102 — spends the SAME h1 coinbase correctly.
-- This is the behaviour that regressed: pre-fix the coin_view still thinks
-- h1 coinbase is spent, so this false-rejects bad-txns-inputs-missingorspent.
local good_spend = spend_tx(h1_cb_txid, 4900000000)  -- 49 BTC out <= 50 BTC in
local good_block = build_block(tip101, 102, next_ts + 1, { good_spend }, "\x02")
local good_res = rpc.methods["submitblock"](rpc, { block_hex(good_block) })

-- Bitcoin Core / all 9 sibling nodes ACCEPT this block.  submitblock returns
-- the JSON null (cjson.null) on success; anything else (a BIP-22 string) is a
-- reject.  The specific pre-fix failure string is bad-txns-inputs-missingorspent.
local accepted = (good_res == nil) or (type(good_res) ~= "string")
check("valid h1-coinbase spend ACCEPTED after prior reject (no cache poisoning)",
  accepted, "result=" .. tostring(good_res))
if not accepted then
  check("  (diagnostic) reject reason was the poisoning symptom",
    tostring(good_res):find("missingorspent") ~= nil, "reason=" .. tostring(good_res))
end
check("node tip advanced to 102 on accept", cs.tip_height == 102,
  "tip_height=" .. tostring(cs.tip_height))

os.execute("rm -rf " .. dir)

io.write(string.format("\n%d passed, %d failed\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
