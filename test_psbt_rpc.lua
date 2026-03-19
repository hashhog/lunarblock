#!/usr/bin/env luajit
-- Test PSBT RPC methods without network dependencies

package.path = "lunarblock/?.lua;src/?.lua;" .. package.path

-- Mock the socket module
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
      }
    end,
  }
end

-- Mock cjson
package.preload['cjson'] = function()
  local M = {}
  M.null = setmetatable({}, {__tostring = function() return "null" end})
  function M.encode(v)
    if v == M.null then return "null" end
    if type(v) == "table" then
      local parts = {}
      local is_array = #v > 0 or next(v) == nil
      if is_array then
        for _, val in ipairs(v) do
          parts[#parts + 1] = M.encode(val)
        end
        return "[" .. table.concat(parts, ",") .. "]"
      else
        for k, val in pairs(v) do
          parts[#parts + 1] = '"' .. tostring(k) .. '":' .. M.encode(val)
        end
        return "{" .. table.concat(parts, ",") .. "}"
      end
    elseif type(v) == "string" then
      return '"' .. v:gsub('"', '\\"') .. '"'
    elseif type(v) == "number" then
      return tostring(v)
    elseif type(v) == "boolean" then
      return v and "true" or "false"
    end
    return "null"
  end
  function M.decode(s)
    -- Very simple decoder for test purposes
    if s:match("^%s*%[") then
      local t = {}
      for item in s:gmatch('"([^"]+)"') do
        t[#t + 1] = item
      end
      return t
    end
    -- Parse as object for simple cases
    local t = {}
    for k, v in s:gmatch('"([^"]+)"%s*:%s*([^,}]+)') do
      v = v:gsub('^"', ''):gsub('"$', '')
      if v == "true" then t[k] = true
      elseif v == "false" then t[k] = false
      elseif v == "null" then t[k] = nil
      elseif tonumber(v) then t[k] = tonumber(v)
      else t[k] = v
      end
    end
    return t
  end
  return M
end

local rpc = require("lunarblock.rpc")
local psbt_mod = require("lunarblock.psbt")
local types = require("lunarblock.types")
local consensus = require("lunarblock.consensus")

local function test(name, func)
  io.write("Testing: " .. name .. " ... ")
  local ok, err = pcall(func)
  if ok then
    print("PASS")
  else
    print("FAIL: " .. tostring(err))
  end
end

print("=== PSBT RPC Tests ===\n")

-- Create a mock RPC server for testing
local server = rpc.new({
  network = consensus.networks.regtest,
})

test("createpsbt RPC method exists", function()
  assert(server.methods.createpsbt ~= nil, "createpsbt not found")
end)

test("decodepsbt RPC method exists", function()
  assert(server.methods.decodepsbt ~= nil, "decodepsbt not found")
end)

test("combinepsbt RPC method exists", function()
  assert(server.methods.combinepsbt ~= nil, "combinepsbt not found")
end)

test("finalizepsbt RPC method exists", function()
  assert(server.methods.finalizepsbt ~= nil, "finalizepsbt not found")
end)

test("analyzepsbt RPC method exists", function()
  assert(server.methods.analyzepsbt ~= nil, "analyzepsbt not found")
end)

test("utxoupdatepsbt RPC method exists", function()
  assert(server.methods.utxoupdatepsbt ~= nil, "utxoupdatepsbt not found")
end)

test("walletprocesspsbt RPC method exists", function()
  assert(server.methods.walletprocesspsbt ~= nil, "walletprocesspsbt not found")
end)

test("converttopsbt RPC method exists", function()
  assert(server.methods.converttopsbt ~= nil, "converttopsbt not found")
end)

test("joinpsbts RPC method exists", function()
  assert(server.methods.joinpsbts ~= nil, "joinpsbts not found")
end)

test("createpsbt creates valid PSBT", function()
  local inputs = {
    {txid = "0101010101010101010101010101010101010101010101010101010101010101", vout = 0}
  }
  local outputs = {
    {["bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3xueyj"] = 0.0005}  -- regtest address
  }

  local result = server.methods.createpsbt(server, {inputs, outputs})
  assert(type(result) == "string", "result should be base64 string")

  -- Decode and verify
  local psbt = psbt_mod.from_base64(result)
  assert(#psbt.inputs == 1, "wrong input count")
  assert(#psbt.outputs == 1, "wrong output count")
end)

test("decodepsbt decodes PSBT", function()
  -- Create a PSBT first
  local txid = types.hash256(string.rep("\x01", 32))
  local tx = types.transaction(2, {
    types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD),
  }, {types.txout(50000, "\x00\x14" .. string.rep("\x02", 20))}, 0)
  local psbt = psbt_mod.new(tx)
  local b64 = psbt_mod.to_base64(psbt)

  local decoded = server.methods.decodepsbt(server, {b64})
  assert(decoded.tx ~= nil, "no tx in decoded")
  assert(decoded.tx.version == 2, "wrong version")
  assert(#decoded.inputs == 1, "wrong input count")
end)

test("combinepsbt combines PSBTs", function()
  local txid = types.hash256(string.rep("\x05", 32))
  local tx = types.transaction(2, {
    types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD),
  }, {types.txout(50000, "\x00\x14" .. string.rep("\x06", 20))}, 0)

  local psbt1 = psbt_mod.new(tx)
  local psbt2 = psbt_mod.deserialize(psbt_mod.serialize(psbt1))

  -- Add different info to each
  psbt1.inputs[1].witness_utxo = {value = 100000, script_pubkey = "\x00\x14" .. string.rep("\x07", 20)}
  psbt2.inputs[1].sighash_type = 1

  local b64_1 = psbt_mod.to_base64(psbt1)
  local b64_2 = psbt_mod.to_base64(psbt2)

  local combined_b64 = server.methods.combinepsbt(server, {{b64_1, b64_2}})
  local combined = psbt_mod.from_base64(combined_b64)

  assert(combined.inputs[1].witness_utxo ~= nil, "missing UTXO")
  assert(combined.inputs[1].sighash_type == 1, "missing sighash")
end)

test("analyzepsbt analyzes PSBT status", function()
  local txid = types.hash256(string.rep("\x08", 32))
  local tx = types.transaction(2, {
    types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFD),
  }, {types.txout(50000, "\x00\x14" .. string.rep("\x09", 20))}, 0)
  local psbt = psbt_mod.new(tx)
  local b64 = psbt_mod.to_base64(psbt)

  local analysis = server.methods.analyzepsbt(server, {b64})
  assert(analysis.inputs ~= nil, "no inputs analysis")
  assert(#analysis.inputs == 1, "wrong input count")
  assert(analysis.next ~= nil, "no next role")
end)

test("converttopsbt converts raw transaction", function()
  -- Create a simple raw transaction hex
  local txid = types.hash256(string.rep("\x0a", 32))
  local tx = types.transaction(2, {
    types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFF),
  }, {types.txout(50000, "\x00\x14" .. string.rep("\x0b", 20))}, 0)

  local serialize = require("lunarblock.serialize")
  local raw_hex = rpc.hex_encode(serialize.serialize_transaction(tx, false))

  local result = server.methods.converttopsbt(server, {raw_hex})
  assert(type(result) == "string", "result should be base64 string")

  -- Verify it's valid PSBT
  local psbt = psbt_mod.from_base64(result)
  assert(#psbt.inputs == 1, "wrong input count")
end)

print("\n=== All RPC Tests Complete ===")
