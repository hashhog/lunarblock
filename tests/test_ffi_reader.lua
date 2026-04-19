#!/usr/bin/env luajit
-- W72: correctness + timing test for serialize.buffer_reader_ffi.
--
-- For each block in the corpus:
--   1. Parse with the pure-Lua buffer_reader (old path).
--   2. Parse with buffer_reader_ffi (new path).
--   3. Compare every field of every tx.
--   4. Round-trip: serialize_block(parsed) == original bytes, under both.
-- Finally, run a small perf microbench (old vs new, iterations=3 per block)
-- as a sanity signal on the expected speedup.  The authoritative perf
-- number comes from the [W72-DESER] log on a live node, not this bench.
--
-- Usage:
--   LUA_PATH="src/?.lua;;" luajit tests/test_ffi_reader.lua [corpus_path]
--   # corpus_path defaults to /tmp/w72-test-blocks.hex
--   # corpus line format: "<height> <hash_hex> <block_hex>"

package.path = "src/?.lua;./?.lua;" .. package.path

local serialize = require("lunarblock.serialize")
local perf = require("lunarblock.perf")

local function hex_decode(h)
  if #h % 2 ~= 0 then error("odd-length hex") end
  local out = {}
  for i = 1, #h, 2 do
    out[#out + 1] = string.char(tonumber(h:sub(i, i + 1), 16))
  end
  return table.concat(out)
end

local function bytes_hex(b)
  local out = {}
  for i = 1, #b do out[i] = string.format("%02x", b:byte(i)) end
  return table.concat(out)
end

local function load_corpus(path)
  local f = assert(io.open(path, "r"), "cannot open corpus " .. path)
  local entries = {}
  for line in f:lines() do
    local height_str, hash_hex, block_hex = line:match("^(%S+)%s+(%S+)%s+(%S+)$")
    if height_str then
      entries[#entries + 1] = {
        height = tonumber(height_str),
        hash_hex = hash_hex,
        block_bytes = hex_decode(block_hex),
      }
    end
  end
  f:close()
  return entries
end

local function header_eq(a, b)
  if a.version ~= b.version then return false, "version" end
  if a.prev_hash.bytes ~= b.prev_hash.bytes then return false, "prev_hash" end
  if a.merkle_root.bytes ~= b.merkle_root.bytes then return false, "merkle_root" end
  if a.timestamp ~= b.timestamp then return false, "timestamp" end
  if a.bits ~= b.bits then return false, "bits" end
  if a.nonce ~= b.nonce then return false, "nonce" end
  return true
end

local function tx_eq(a, b, tx_idx)
  if a.version ~= b.version then return false, "tx " .. tx_idx .. " version" end
  if a.locktime ~= b.locktime then return false, "tx " .. tx_idx .. " locktime" end
  if (a.segwit or false) ~= (b.segwit or false) then
    return false, "tx " .. tx_idx .. " segwit flag"
  end
  if #a.inputs ~= #b.inputs then return false, "tx " .. tx_idx .. " input count" end
  if #a.outputs ~= #b.outputs then return false, "tx " .. tx_idx .. " output count" end
  for i = 1, #a.inputs do
    local ia, ib = a.inputs[i], b.inputs[i]
    if ia.prev_out.hash.bytes ~= ib.prev_out.hash.bytes then
      return false, string.format("tx %d input %d prev_hash", tx_idx, i)
    end
    if ia.prev_out.index ~= ib.prev_out.index then
      return false, string.format("tx %d input %d prev_index", tx_idx, i)
    end
    if ia.script_sig ~= ib.script_sig then
      return false, string.format("tx %d input %d script_sig", tx_idx, i)
    end
    if ia.sequence ~= ib.sequence then
      return false, string.format("tx %d input %d sequence", tx_idx, i)
    end
    -- Witness stacks
    local wa, wb = ia.witness or {}, ib.witness or {}
    if #wa ~= #wb then
      return false, string.format("tx %d input %d witness count", tx_idx, i)
    end
    for j = 1, #wa do
      if wa[j] ~= wb[j] then
        return false, string.format("tx %d input %d witness[%d]", tx_idx, i, j)
      end
    end
  end
  for i = 1, #a.outputs do
    if a.outputs[i].value ~= b.outputs[i].value then
      return false, string.format("tx %d output %d value", tx_idx, i)
    end
    if a.outputs[i].script_pubkey ~= b.outputs[i].script_pubkey then
      return false, string.format("tx %d output %d script_pubkey", tx_idx, i)
    end
  end
  return true
end

local function block_eq(a, b)
  local ok, why = header_eq(a.header, b.header)
  if not ok then return false, "header: " .. why end
  if #a.transactions ~= #b.transactions then
    return false, "tx count"
  end
  for i = 1, #a.transactions do
    ok, why = tx_eq(a.transactions[i], b.transactions[i], i)
    if not ok then return false, why end
  end
  return true
end

local corpus_path = arg[1] or "/tmp/w72-test-blocks.hex"
local entries = load_corpus(corpus_path)
io.write(string.format("[W72-TEST] loaded %d blocks from %s\n", #entries, corpus_path))
if #entries == 0 then
  io.stderr:write("no blocks loaded; aborting\n")
  os.exit(1)
end

local total_pass = 0
local total_bytes = 0
local t_old_total, t_new_total = 0, 0

for _, e in ipairs(entries) do
  local data = e.block_bytes
  total_bytes = total_bytes + #data

  -- Parse with both readers
  local r_old = serialize.buffer_reader(data)
  local block_old = serialize.deserialize_block(r_old)
  local block_new = serialize.deserialize_block_ffi(data)

  -- Field-level comparison
  local ok, why = block_eq(block_old, block_new)
  if not ok then
    io.stderr:write(string.format("[W72-TEST] block %d MISMATCH: %s\n", e.height, why))
    os.exit(1)
  end

  -- Round-trip: re-serialize and compare to original
  local reser_old = serialize.serialize_block(block_old)
  local reser_new = serialize.serialize_block(block_new)
  if reser_old ~= data then
    io.stderr:write(string.format("[W72-TEST] block %d OLD round-trip mismatch (%d vs %d bytes)\n",
      e.height, #reser_old, #data))
    os.exit(1)
  end
  if reser_new ~= data then
    io.stderr:write(string.format("[W72-TEST] block %d NEW round-trip mismatch (%d vs %d bytes)\n",
      e.height, #reser_new, #data))
    os.exit(1)
  end

  -- Perf sample: warm JIT first, then take the MIN of N iterations
  -- (min rejects GC stalls and OS scheduler jitter; mean is polluted).
  local WARMUP, N = 5, 20
  for _ = 1, WARMUP do serialize.deserialize_block(serialize.buffer_reader(data)) end
  for _ = 1, WARMUP do serialize.deserialize_block_ffi(data) end
  collectgarbage("collect"); collectgarbage("collect")

  local old_min, new_min = math.huge, math.huge
  local old_sum, new_sum = 0, 0
  for _ = 1, N do
    local t0 = perf.now()
    serialize.deserialize_block(serialize.buffer_reader(data))
    local t1 = perf.now()
    local d = t1 - t0
    old_sum = old_sum + d
    if d < old_min then old_min = d end
  end
  for _ = 1, N do
    local t0 = perf.now()
    serialize.deserialize_block_ffi(data)
    local t1 = perf.now()
    local d = t1 - t0
    new_sum = new_sum + d
    if d < new_min then new_min = d end
  end
  t_old_total = t_old_total + old_min
  t_new_total = t_new_total + new_min

  io.write(string.format(
    "[W72-TEST] h=%d size=%6dKB txs=%4d PASS  old_min=%6.2fms new_min=%6.2fms speedup=%.2fx (old_avg=%.2f new_avg=%.2f)\n",
    e.height, #data / 1024, #block_old.transactions,
    old_min * 1000, new_min * 1000, old_min / math.max(new_min, 1e-9),
    (old_sum / N) * 1000, (new_sum / N) * 1000))
  total_pass = total_pass + 1
end

io.write("\n[W72-TEST] SUMMARY\n")
io.write(string.format("  blocks passed : %d/%d\n", total_pass, #entries))
io.write(string.format("  corpus size   : %.1f MB\n", total_bytes / 1048576))
io.write(string.format("  old total     : %.1f ms\n", t_old_total * 1000))
io.write(string.format("  new total     : %.1f ms\n", t_new_total * 1000))
io.write(string.format("  speedup       : %.2fx\n", t_old_total / math.max(t_new_total, 1e-9)))
io.write(string.format("  old throughput: %.1f MB/s\n", (total_bytes / 1048576) / t_old_total))
io.write(string.format("  new throughput: %.1f MB/s\n", (total_bytes / 1048576) / t_new_total))
io.write("\n[W72-TEST] ALL BLOCKS PASS\n")
os.exit(0)
