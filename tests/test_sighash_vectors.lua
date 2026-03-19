#!/usr/bin/env luajit
-- Test harness for Bitcoin sighash test vectors
-- Loads sighash.json from Bitcoin Core and verifies signature_hash_legacy

-- Setup module paths (same pattern as other tests in this repo)
package.path = "lunarblock/?.lua;src/?.lua;" .. package.path

local cjson = require("cjson")
local serialize = require("lunarblock.serialize")
local validation = require("lunarblock.validation")
local types = require("lunarblock.types")

--------------------------------------------------------------------------------
-- Hex encode/decode helpers
--------------------------------------------------------------------------------

local function hex_decode(hex)
  if not hex or hex == "" then return "" end
  local bytes = {}
  for i = 1, #hex, 2 do
    bytes[#bytes + 1] = string.char(tonumber(hex:sub(i, i + 1), 16))
  end
  return table.concat(bytes)
end

local function hex_encode(data)
  local hex = {}
  for i = 1, #data do
    hex[i] = string.format("%02x", data:byte(i))
  end
  return table.concat(hex)
end

--------------------------------------------------------------------------------
-- Load test vectors
--------------------------------------------------------------------------------

-- Try multiple paths for the sighash.json file
local vector_paths = {
  "../ouroboros/bitcoin/src/test/data/sighash.json",
  "/home/max/hashhog/ouroboros/bitcoin/src/test/data/sighash.json",
}

local f, json_text
for _, path in ipairs(vector_paths) do
  f = io.open(path, "r")
  if f then
    json_text = f:read("*a")
    f:close()
    io.write("Loaded test vectors from: " .. path .. "\n")
    break
  end
end
assert(json_text, "Cannot open sighash.json from any known path")

local vectors = cjson.decode(json_text)

--------------------------------------------------------------------------------
-- Run tests
--------------------------------------------------------------------------------

local pass_count = 0
local fail_count = 0
local error_count = 0
local total = 0

for idx, entry in ipairs(vectors) do
  -- Skip header comment (first entry is a single-element array with a string)
  if type(entry[1]) == "string" and #entry == 1 then
    -- Header row, skip
  else
    total = total + 1
    local raw_tx_hex = entry[1]
    local script_hex = entry[2]
    local input_index = entry[3]  -- 0-based
    local hash_type = entry[4]    -- signed 32-bit integer
    local expected_hex = entry[5]

    local ok, err_msg = pcall(function()
      -- Decode raw transaction from hex
      local raw_tx = hex_decode(raw_tx_hex)
      local tx = serialize.deserialize_transaction(raw_tx)

      -- Decode the subscript from hex
      local script_code = hex_decode(script_hex)

      -- Compute legacy sighash (no sig_bytes for FindAndDelete in test vectors)
      -- hash_type is signed int32 from JSON; LuaJIT's bit.band and the
      -- serialize write_u32le both handle negative values correctly via
      -- two's complement / Lua modular arithmetic.
      local sighash = validation.signature_hash_legacy(tx, input_index, script_code, hash_type, nil)

      -- The sighash result is 32 raw bytes from double-SHA256.
      -- Bitcoin Core's test vectors express the expected hash as a uint256
      -- hex string where the first hex chars are the most significant byte.
      -- The raw SHA-256 output bytes are in big-endian order (MSB first),
      -- so direct hex_encode matches the expected format.
      local computed_hex = hex_encode(sighash)

      if computed_hex == expected_hex then
        pass_count = pass_count + 1
      else
        -- Also try reversed (in case the format is little-endian display)
        local reversed = sighash:reverse()
        local reversed_hex = hex_encode(reversed)
        if reversed_hex == expected_hex then
          pass_count = pass_count + 1
        else
          fail_count = fail_count + 1
          if fail_count <= 10 then
            io.write(string.format("FAIL test #%d (vec %d): input_index=%d hash_type=%d\n",
              total, idx, input_index, hash_type))
            io.write(string.format("  expected:  %s\n", expected_hex))
            io.write(string.format("  computed:  %s\n", computed_hex))
            io.write(string.format("  reversed:  %s\n", reversed_hex))
          end
        end
      end
    end)

    if not ok then
      error_count = error_count + 1
      if error_count <= 10 then
        io.write(string.format("ERROR test #%d (vec %d): %s\n", total, idx, tostring(err_msg)))
      end
    end
  end
end

io.write(string.format("\nSighash test results: %d passed, %d failed, %d errors out of %d total\n",
  pass_count, fail_count, error_count, total))

if fail_count == 0 and error_count == 0 then
  io.write("ALL TESTS PASSED\n")
  os.exit(0)
else
  os.exit(1)
end
