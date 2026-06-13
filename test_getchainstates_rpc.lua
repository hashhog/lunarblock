#!/usr/bin/env luajit
-- Targeted unit test for the getchainstates RPC handler.
-- No network, no multi-node regtest: we drive rpc.methods.getchainstates
-- directly against a mock chain_state (with a coin_view carrying a known
-- coins-tip cache budget), mock storage (with a tip header + a known
-- coins-DB block-cache size), and a mock header_chain.
--
-- Shape contract mirrors Bitcoin Core rpc/blockchain.cpp::getchainstates
-- (3462-3519) + RPCHelpForChainstate (3449-3460):
--   {
--     headers: <int>,                     -- best-header height seen so far
--     chainstates: [                       -- ordered by work, ACTIVE last
--       {
--         blocks: <int>,
--         bestblockhash: <hex>,
--         bits: <hex8>,
--         target: <hex64>,
--         difficulty: <num>,
--         verificationprogress: <num>,     -- [0..1]
--         coins_db_cache_bytes: <int>,
--         coins_tip_cache_bytes: <int>,
--         validated: true,                 -- single fully-validated chainstate
--       }                                  -- NO snapshot_blockhash key
--     ]
--   }

package.path = "lunarblock/?.lua;src/?.lua;" .. package.path

-- Mock socket so requiring p2p/peer modules (pulled in transitively) is safe.
package.preload['socket'] = function()
  return {
    tcp = function()
      return {
        setoption = function() return true end,
        bind = function() return true end,
        listen = function() return true end,
        settimeout = function() end,
        accept = function() return nil end,
        close = function() end,
        send = function() return true end,
        receive = function() return nil, "timeout" end,
      }
    end,
    gettime = function() return 0 end,
  }
end

local rpc = require("lunarblock.rpc")
local types = require("lunarblock.types")
local consensus = require("lunarblock.consensus")
local cjson = require("cjson")

local passed, failed = 0, 0
local function test(name, func)
  io.write("Testing: " .. name .. " ... ")
  local ok, err = pcall(func)
  if ok then
    passed = passed + 1
    print("PASS")
  else
    failed = failed + 1
    print("FAIL: " .. tostring(err))
  end
end

-- A concrete tip block hash (display hex) + its hash256 object.
local TIP_HEX = "0000000000000000000123456789abcdef0123456789abcdef0123456789abcd"
local tip_hash = types.hash256_from_hex(TIP_HEX)

-- Tip header carries a non-default nBits so we can prove bits/target/difficulty
-- are derived from the GENUINE tip header (not the network pow-limit fallback).
local TIP_BITS = 0x1a05db8b  -- a real-ish mainnet-style compact target

-- Known, distinct cache budgets so we can prove the handler reads the REAL
-- in-node cache configuration (not a hard-coded constant or a single shared
-- value).  coins_db (RocksDB block cache) and coins_tip (UTXO cache) differ.
local COINS_DB_BYTES  = 512 * 1024 * 1024   -- 536870912
local COINS_TIP_BYTES = 450 * 1024 * 1024   -- 471859200

local TIP_HEIGHT    = 12345
local HEADER_HEIGHT = 12400  -- best-header > block tip (still syncing headers)

local mock_storage = {
  _block_cache_bytes = COINS_DB_BYTES,
  get_header = function(hash)
    if hash and hash.bytes == tip_hash.bytes then
      return { version = 1, bits = TIP_BITS, nonce = 0, timestamp = 1700000000 }
    end
    return nil
  end,
}

local mock_chain_state = {
  tip_height = TIP_HEIGHT,
  tip_hash = tip_hash,
  coin_view = { max_cache_bytes = COINS_TIP_BYTES },
}

local mock_header_chain = { header_tip_height = HEADER_HEIGHT }

local function make_server()
  return rpc.new({
    network = consensus.networks.regtest,
    storage = mock_storage,
    chain_state = mock_chain_state,
    header_chain = mock_header_chain,
  })
end

local function decode(server)
  local result = server.methods.getchainstates(server, {})
  assert(type(result) == "table", "result should be a table")
  assert(type(result._raw_json) == "string", "result should carry _raw_json string")
  return cjson.decode(result._raw_json), result._raw_json
end

-- (existence) method is registered + dispatchable.
test("getchainstates method exists", function()
  local server = make_server()
  assert(server.methods.getchainstates ~= nil, "method not registered")
end)

-- (top-level shape) headers is an int; chainstates is a 1-element array.
test("top-level: headers int + chainstates 1-element array", function()
  local server = make_server()
  local obj = decode(server)

  assert(type(obj.headers) == "number", "headers must be a number")
  assert(obj.headers == math.floor(obj.headers), "headers must be an integer")
  -- best-header height seen so far == header_chain tip.
  assert(obj.headers == HEADER_HEIGHT,
    "headers should be best-header height " .. HEADER_HEIGHT .. ", got " .. tostring(obj.headers))

  assert(type(obj.chainstates) == "table", "chainstates must be an array")
  assert(#obj.chainstates == 1, "expected exactly 1 chainstate, got " .. #obj.chainstates)
end)

-- (entry shape) the lone chainstate entry has ALL required fields with the
-- correct types, validated==true, and NO snapshot_blockhash key.
test("entry: all required fields, correct types, validated, no snapshot key", function()
  local server = make_server()
  local obj = decode(server)
  local cs = obj.chainstates[1]

  -- blocks: int == active chainstate tip height.
  assert(type(cs.blocks) == "number" and cs.blocks == math.floor(cs.blocks),
    "blocks must be an integer")
  assert(cs.blocks == TIP_HEIGHT, "blocks should be tip height " .. TIP_HEIGHT ..
    ", got " .. tostring(cs.blocks))

  -- bestblockhash: 64-char hex == the tip hash.
  assert(type(cs.bestblockhash) == "string" and #cs.bestblockhash == 64,
    "bestblockhash must be a 64-char hex string")
  assert(cs.bestblockhash == TIP_HEX,
    "bestblockhash should equal tip hash, got " .. cs.bestblockhash)

  -- bits: 8-char hex == tip nBits ("%08x" of TIP_BITS).
  assert(type(cs.bits) == "string" and #cs.bits == 8, "bits must be 8-char hex")
  assert(cs.bits == string.format("%08x", TIP_BITS),
    "bits should be %08x of tip nBits, got " .. cs.bits)

  -- target: 64-char hex difficulty target.
  assert(type(cs.target) == "string" and #cs.target == 64,
    "target must be 64-char hex")

  -- difficulty: number > 0 (derived from the genuine tip nBits, not 1.0).
  assert(type(cs.difficulty) == "number", "difficulty must be a number")
  assert(cs.difficulty > 0, "difficulty should be > 0 for a real tip nBits")

  -- verificationprogress: number in [0,1].
  assert(type(cs.verificationprogress) == "number",
    "verificationprogress must be a number")
  assert(cs.verificationprogress >= 0 and cs.verificationprogress <= 1,
    "verificationprogress must be in [0,1], got " .. tostring(cs.verificationprogress))

  -- coins_db_cache_bytes: int == the REAL configured RocksDB block-cache size.
  assert(type(cs.coins_db_cache_bytes) == "number"
    and cs.coins_db_cache_bytes == math.floor(cs.coins_db_cache_bytes),
    "coins_db_cache_bytes must be an integer")
  assert(cs.coins_db_cache_bytes == COINS_DB_BYTES,
    "coins_db_cache_bytes should be the genuine block-cache size " .. COINS_DB_BYTES ..
    ", got " .. tostring(cs.coins_db_cache_bytes))

  -- coins_tip_cache_bytes: int == the REAL configured UTXO (coins-tip) cache.
  assert(type(cs.coins_tip_cache_bytes) == "number"
    and cs.coins_tip_cache_bytes == math.floor(cs.coins_tip_cache_bytes),
    "coins_tip_cache_bytes must be an integer")
  assert(cs.coins_tip_cache_bytes == COINS_TIP_BYTES,
    "coins_tip_cache_bytes should be the genuine UTXO cache size " .. COINS_TIP_BYTES ..
    ", got " .. tostring(cs.coins_tip_cache_bytes))

  -- validated: true (single fully-validated chainstate).
  assert(cs.validated == true, "validated must be true for the single chainstate")

  -- snapshot_blockhash: ABSENT (no AssumeUTXO snapshot active).  cjson omits
  -- absent keys, so the decoded table must not have the key at all.
  assert(cs.snapshot_blockhash == nil,
    "snapshot_blockhash must be OMITTED when no snapshot is active")
end)

-- (key order) raw JSON must emit fields in Core make_chain_data order, and the
-- top-level object must be {headers, chainstates}.
test("raw JSON key order matches Core make_chain_data", function()
  local server = make_server()
  local _, raw = decode(server)

  -- Top-level order: headers before chainstates.
  assert(raw:find('"headers"') < raw:find('"chainstates"'),
    "headers must precede chainstates")

  -- Entry order: blocks, bestblockhash, bits, target, difficulty,
  -- verificationprogress, coins_db_cache_bytes, coins_tip_cache_bytes, validated.
  local order = {
    "blocks", "bestblockhash", "bits", "target", "difficulty",
    "verificationprogress", "coins_db_cache_bytes", "coins_tip_cache_bytes",
    "validated",
  }
  local last = 0
  for _, key in ipairs(order) do
    local pos = raw:find('"' .. key .. '"', 1, true)
    assert(pos ~= nil, "missing key in raw JSON: " .. key)
    assert(pos > last, "key out of order: " .. key)
    last = pos
  end

  -- snapshot_blockhash must not appear in the raw JSON either.
  assert(raw:find('"snapshot_blockhash"', 1, true) == nil,
    "snapshot_blockhash must not appear in raw JSON")
end)

print("")
print(string.format("=== getchainstates RPC: %d passed, %d failed ===", passed, failed))
os.exit(failed == 0 and 0 or 1)
