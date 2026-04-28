#!/usr/bin/env luajit
-- BIP-341 vector-runner shim for lunarblock.
-- Drives validation.signature_msg_taproot + validation.signature_hash_taproot
-- via the stdin/stdout JSON protocol described in
-- tools/bip341-vector-runner/README.md.
--
-- Input (one JSON object per line on stdin):
--   { "tx_hex": "...", "input_index": 0,
--     "spent_amounts": [12345, ...],
--     "spent_scripts": ["hex...", ...],
--     "hash_type": 0,
--     "annex_hex": null }
--
-- Output (one JSON object per line on stdout):
--   { "sig_msg": "hex...", "sig_hash": "hex..." }

io.stdout:setvbuf("line")
io.stderr:setvbuf("line")

-- Adjust package.path to find lunarblock source.
local script_dir = (arg[0] or ""):match("^(.*[/\\])") or "./"
package.path = script_dir .. "../../lunarblock/?.lua;"
            .. script_dir .. "../../src/?.lua;"
            .. "lunarblock/?.lua;src/?.lua;"
            .. package.path

local cjson      = require("cjson")
local serialize  = require("lunarblock.serialize")
local validation = require("lunarblock.validation")

local function hex_decode(h)
  if h == nil or h == cjson.null then return nil end
  local out = {}
  for i = 1, #h, 2 do
    out[#out + 1] = string.char(tonumber(h:sub(i, i + 1), 16))
  end
  return table.concat(out)
end

local function hex_encode(b)
  local t = {}
  for i = 1, #b do
    t[i] = string.format("%02x", b:byte(i))
  end
  return table.concat(t)
end

local function process_request(req)
  local tx_bytes = hex_decode(req.tx_hex)
  local tx = serialize.deserialize_transaction(tx_bytes)

  local prev_outputs = {}
  for i, amt in ipairs(req.spent_amounts) do
    prev_outputs[i] = {
      value = amt,
      script_pubkey = hex_decode(req.spent_scripts[i]),
    }
  end

  local annex = req.annex_hex and hex_decode(req.annex_hex) or nil
  local hash_type = tonumber(req.hash_type) or 0

  -- BIP-341 wallet vectors only exercise key-path (ext_flag=0).
  local sig_msg = validation.signature_msg_taproot(
    tx, req.input_index, hash_type, prev_outputs, 0, annex)
  local sig_hash = validation.signature_hash_taproot(
    tx, req.input_index, hash_type, prev_outputs, 0, annex)

  return {
    sig_msg  = hex_encode(sig_msg),
    sig_hash = hex_encode(sig_hash),
  }
end

while true do
  local line = io.read("*l")
  if not line then break end
  if #line > 0 then
    local ok, req = pcall(cjson.decode, line)
    if not ok then
      io.write(string.format('{"error":"json parse: %s"}\n', tostring(req)))
    else
      local ok2, resp = pcall(process_request, req)
      if not ok2 then
        io.write(string.format('{"error":"%s"}\n',
          tostring(resp):gsub('"', '\\"')))
      else
        io.write(cjson.encode(resp) .. "\n")
      end
    end
    io.stdout:flush()
  end
end
