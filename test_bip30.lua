#!/usr/bin/env luajit
-- BIP-30 (duplicate-coinbase prevention) regression test.
--
-- Per Core validation.cpp:2402-2476 + IsBIP30Repeat at line 6189,
-- ConnectBlock must reject any block whose tx outputs collide with
-- existing UTXOs, with two known mainnet exemption blocks
-- (h=91842, h=91880). Pre-fix lunarblock had no enforcement: a
-- malicious miner could mine a block whose coinbase txid duplicated
-- an existing UTXO and silently overwrite it (CVE-2012-1909 family).
--
-- This test:
--   1. Verifies is_bip30_exempt for each known-mainnet exemption pair
--      and rejects testnet/regtest inheritance of the exemption.
--   2. Drives a mock CoinView with one pre-existing UTXO and walks
--      the BIP-30 enforcement decision the connect_block path now
--      makes: have(check_txid, vout) on every tx output.
--   3. Verifies a duplicate triggers rejection.
--   4. Verifies a non-duplicate (fresh txid) passes.
--
-- Run: luajit test_bip30.lua

package.path = "lunarblock/?.lua;src/?.lua;" .. package.path

local utxo = require("lunarblock.utxo")
local types = require("lunarblock.types")

local pass = 0
local fail = 0

local function check(name, cond, detail)
  if cond then
    print("PASS: " .. name)
    pass = pass + 1
  else
    print("FAIL: " .. name .. (detail and (" — " .. tostring(detail)) or ""))
    fail = fail + 1
  end
end

-- Build a real block hash from its big-endian display hex
local H_91842 = types.hash256_from_hex("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")
local H_91880 = types.hash256_from_hex("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")
local H_OTHER = types.hash256_from_hex("0000000000000000000000000000000000000000000000000000000000000abc")

-- 1. is_bip30_exempt — positive cases (mainnet)
check("mainnet h=91842 with correct hash → exempt",
  utxo.is_bip30_exempt("mainnet", 91842, H_91842))
check("mainnet h=91880 with correct hash → exempt",
  utxo.is_bip30_exempt("mainnet", 91880, H_91880))

-- 2. is_bip30_exempt — negative cases (wrong hash for known height)
check("mainnet h=91842 with WRONG hash → NOT exempt",
  not utxo.is_bip30_exempt("mainnet", 91842, H_OTHER))
check("mainnet h=91880 with WRONG hash → NOT exempt",
  not utxo.is_bip30_exempt("mainnet", 91880, H_OTHER))

-- 3. is_bip30_exempt — unrelated heights are NOT exempt
check("mainnet h=100000 → NOT exempt",
  not utxo.is_bip30_exempt("mainnet", 100000, H_OTHER))
check("mainnet h=0 → NOT exempt",
  not utxo.is_bip30_exempt("mainnet", 0, H_OTHER))
check("mainnet h=227931 (BIP34 height) → NOT exempt",
  not utxo.is_bip30_exempt("mainnet", 227931, H_OTHER))

-- 4. is_bip30_exempt — testnet / regtest must NOT inherit mainnet exemption
check("testnet h=91842 with mainnet hash → NOT exempt",
  not utxo.is_bip30_exempt("testnet", 91842, H_91842))
check("testnet4 h=91842 → NOT exempt",
  not utxo.is_bip30_exempt("testnet4", 91842, H_91842))
check("regtest h=91842 → NOT exempt",
  not utxo.is_bip30_exempt("regtest", 91842, H_91842))

-- 5. nil hash defensively → not exempt
check("nil block_hash → NOT exempt",
  not utxo.is_bip30_exempt("mainnet", 91842, nil))

------------------------------------------------------------
-- Integration: drive the BIP-30 enforcement decision path
-- against a mock CoinView. Mirrors the loop in connect_block:
--   for each tx in block.transactions:
--     check_txid = compute_txid(tx)
--     for vout_idx = 0..N-1:
--       if coin_view:have(check_txid, vout_idx):
--         REJECT (BIP-30 violation)
------------------------------------------------------------

-- Build a tiny mock storage so CoinView:have only consults its cache.
-- For our purposes the disk_store can return nil for everything.
local mock_storage = {
  get = function(_cf, _key) return nil end,
  batch = function() return {put = function() end, delete = function() end, write = function() end} end,
  set_chain_tip = function() end,
}

local cv = utxo.new_coin_view(mock_storage)

-- Add a "pre-existing" UTXO at txid X, vout 0
local existing_txid = types.hash256_from_hex(
  "1111111111111111111111111111111111111111111111111111111111111111")
cv:add(existing_txid, 0, utxo.utxo_entry(50e8, "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac", 100, true))

-- 6. coin_view:have on the existing entry returns true
check("CoinView:have on existing UTXO → true",
  cv:have(existing_txid, 0) == true)

-- 7. coin_view:have on a different txid returns false
local fresh_txid = types.hash256_from_hex(
  "2222222222222222222222222222222222222222222222222222222222222222")
check("CoinView:have on fresh txid → false",
  cv:have(fresh_txid, 0) == false)

-- 8. The duplicate scenario: a "block" whose first tx has txid == existing_txid
-- with one output at vout 0 → should trigger BIP-30 rejection.
local function bip30_check(coinview, block_txs)
  for _, tx in ipairs(block_txs) do
    -- normally validation.compute_txid(tx); for the test we pass txids directly.
    local check_txid = tx.txid
    for vout_idx = 1, #tx.outputs do
      if coinview:have(check_txid, vout_idx - 1) then
        return false, "bad-txns-BIP30"
      end
    end
  end
  return true, nil
end

local dup_block = {
  { txid = existing_txid, outputs = {{value = 50e8, script_pubkey = ""}} }
}
local ok, err = bip30_check(cv, dup_block)
check("block with duplicate-coinbase txid → REJECTED with bad-txns-BIP30",
  not ok and err == "bad-txns-BIP30", tostring(err))

-- 9. The clean scenario: a block whose tx has a fresh txid
local clean_block = {
  { txid = fresh_txid, outputs = {{value = 50e8, script_pubkey = ""}} }
}
ok, err = bip30_check(cv, clean_block)
check("block with fresh txid → accepted",
  ok and err == nil, tostring(err))

-- 10. Multi-output collision: tx whose vout=1 collides but vout=0 is fresh.
do
  -- Add a UTXO at (multi_txid, 1) only — vout 0 is unused.
  local multi_txid = types.hash256_from_hex(
    "3333333333333333333333333333333333333333333333333333333333333333")
  cv:add(multi_txid, 1, utxo.utxo_entry(25e8, "", 200, false))
  local block = {
    { txid = multi_txid, outputs = {
      {value = 10e8, script_pubkey = ""},   -- vout 0: fresh
      {value = 15e8, script_pubkey = ""},   -- vout 1: collides
    }},
  }
  local ok2, err2 = bip30_check(cv, block)
  check("multi-output collision (any vout collides) → REJECTED",
    not ok2 and err2 == "bad-txns-BIP30", tostring(err2))
end

print(string.format("\n%d passed, %d failed", pass, fail))
if fail > 0 then
  os.exit(1)
end
