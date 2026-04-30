-- Bitcoin Core-compatible mempool.dat dump/load.
--
-- Format (matches bitcoin-core/src/node/mempool_persist.cpp v2):
--
--   <plaintext header>
--     u64           version              (1 = no XOR key, 2 = XOR-obfuscated)
--     compactsize   key_len = 8          (only present when version == 2)
--     bytes[8]      xor_key              (only present when version == 2)
--   <obfuscated payload> (every byte XOR'd with key[(offset_in_payload) % 8])
--     u64           tx_count
--     repeated tx_count times:
--       tx-with-witness                  (CTransaction, segwit-format if applicable)
--       i64       nTime                  (unix seconds)
--       i64       nFeeDelta              (CAmount priority delta)
--     compactsize   map_deltas_count
--     repeated map_deltas_count times:
--       bytes[32] txid                   (internal little-endian on wire)
--       i64       fee_delta
--     compactsize   unbroadcast_count
--     repeated unbroadcast_count times:
--       bytes[32] txid
--
-- Notes on byte-for-byte compatibility:
--   * uint64 reads/writes use the existing serialize.lua helpers, which
--     split into two LE u32 halves.  LuaJIT doubles can losslessly hold
--     anything below 2^53, which is far above any plausible mempool tx
--     count, fee delta or timestamp.
--   * Hashes are written as raw 32-byte buffers (the same internal LE
--     order types.hash256 uses for tx data — Core writes uint256 the
--     same way).
--   * The XOR key is freshly generated per dump; loaders read whatever
--     key is in the header.  Version 1 (no key) is also accepted on
--     load, matching Core's MEMPOOL_DUMP_VERSION_NO_XOR_KEY path.

local serialize = require("lunarblock.serialize")
local validation = require("lunarblock.validation")
local types = require("lunarblock.types")

local M = {}

M.VERSION_NO_XOR_KEY = 1
M.VERSION = 2  -- matches Core MEMPOOL_DUMP_VERSION

--- XOR a payload string with an 8-byte key, repeating the key cyclically.
-- Pure Lua loop; LuaJIT's bit.bxor is the inner op.  Hot path on dump
-- /load only — not on tx accept path.
local bit = require("bit")
local function xor_obfuscate(data, key)
  if #key ~= 8 then
    error("xor_obfuscate: key must be 8 bytes, got " .. #key)
  end
  if key == "\0\0\0\0\0\0\0\0" then
    -- Identity; matches Core's `if (!*this) return;` shortcut.
    return data
  end
  local out = {}
  local kb = { key:byte(1, 8) }
  for i = 1, #data do
    out[i] = string.char(bit.bxor(data:byte(i), kb[((i - 1) % 8) + 1]))
  end
  return table.concat(out)
end
M.xor_obfuscate = xor_obfuscate

--- Generate 8 random bytes for use as a fresh XOR key.
-- math.random is used because lunarblock is not cryptographically picky
-- about this key (Core seeds it from FastRandomContext but the file is
-- only obfuscated for opportunistic anti-AV-scanning, not security).
local function random_xor_key()
  local r = {}
  for i = 1, 8 do
    r[i] = string.char(math.random(0, 255))
  end
  return table.concat(r)
end
M.random_xor_key = random_xor_key

--- Serialize the obfuscated payload of a mempool dump.
-- @param entries  array of {tx, time, fee_delta=0}
-- @param map_deltas  optional map of txid_hex -> int64 fee delta
-- @param unbroadcast optional array of txid_hex strings
-- @return string  raw payload bytes (BEFORE obfuscation)
local function serialize_payload(entries, map_deltas, unbroadcast)
  local w = serialize.buffer_writer()
  w.write_u64le(#entries)
  for _, e in ipairs(entries) do
    -- tx-with-witness; matches Core's TX_WITH_WITNESS(*tx).
    w.write_bytes(serialize.serialize_transaction(e.tx, true))
    w.write_i64le(e.time or 0)
    w.write_i64le(e.fee_delta or 0)
  end

  -- mapDeltas: keys are sorted by Core via std::map iteration order,
  -- which on uint256 means lexicographic over the raw 32-byte
  -- little-endian buffer.  We sort the same way for stable output.
  local md_entries = {}
  if map_deltas then
    for txid_hex, delta in pairs(map_deltas) do
      md_entries[#md_entries + 1] = {
        bytes = types.hash256_from_hex(txid_hex).bytes,
        delta = delta,
      }
    end
    table.sort(md_entries, function(a, b) return a.bytes < b.bytes end)
  end
  w.write_varint(#md_entries)
  for _, e in ipairs(md_entries) do
    w.write_bytes(e.bytes)
    w.write_i64le(e.delta)
  end

  -- unbroadcast: std::set<Txid>, sorted same as map_deltas.
  local ub_bytes = {}
  if unbroadcast then
    for _, txid_hex in ipairs(unbroadcast) do
      ub_bytes[#ub_bytes + 1] = types.hash256_from_hex(txid_hex).bytes
    end
    table.sort(ub_bytes)
  end
  w.write_varint(#ub_bytes)
  for _, b in ipairs(ub_bytes) do
    w.write_bytes(b)
  end
  return w.result()
end
M.serialize_payload = serialize_payload

--- Build the fully framed (header + obfuscated payload) dump bytes.
-- @param entries  array of {tx, time, fee_delta=0}
-- @param opts     optional table:
--                   xor_key         8-byte string (default: random)
--                   version         1 or 2 (default 2)
--                   map_deltas      map txid_hex -> int64
--                   unbroadcast     array of txid_hex
-- @return string  bytes ready for io.write
function M.encode_dump(entries, opts)
  opts = opts or {}
  local version = opts.version or M.VERSION
  local payload = serialize_payload(entries, opts.map_deltas, opts.unbroadcast)
  local header_w = serialize.buffer_writer()
  header_w.write_u64le(version)
  if version == M.VERSION then
    local key = opts.xor_key or random_xor_key()
    if #key ~= 8 then
      error("encode_dump: xor_key must be 8 bytes")
    end
    header_w.write_varint(8)
    header_w.write_bytes(key)
    payload = xor_obfuscate(payload, key)
  elseif version ~= M.VERSION_NO_XOR_KEY then
    error("encode_dump: unsupported version " .. tostring(version))
  end
  return header_w.result() .. payload
end

--- Parse the fully framed dump bytes back into entries + deltas + unbroadcast.
-- @param data string: full file contents
-- @return table { entries, map_deltas, unbroadcast } or nil, err
function M.decode_dump(data)
  if type(data) ~= "string" or #data < 8 then
    return nil, "dump too small"
  end
  local r = serialize.buffer_reader(data)
  local version = r.read_u64le()
  local payload
  if version == M.VERSION_NO_XOR_KEY then
    payload = data:sub(r.position())
  elseif version == M.VERSION then
    local key_len = r.read_varint()
    if key_len ~= 8 then
      return nil, "bad key length: " .. key_len
    end
    local key = r.read_bytes(8)
    payload = xor_obfuscate(data:sub(r.position()), key)
  else
    return nil, "unknown mempool dump version " .. tostring(version)
  end

  local pr = serialize.buffer_reader(payload)
  local count = pr.read_u64le()
  local entries = {}
  for i = 1, count do
    local tx = serialize.deserialize_transaction(pr)
    local nTime = pr.read_i64le()
    local nFeeDelta = pr.read_i64le()
    entries[i] = { tx = tx, time = nTime, fee_delta = nFeeDelta }
  end

  local map_deltas = {}
  local md_count = pr.read_varint()
  for i = 1, md_count do
    local hash_bytes = pr.read_bytes(32)
    local delta = pr.read_i64le()
    map_deltas[types.hash256_hex(types.hash256(hash_bytes))] = delta
  end

  local unbroadcast = {}
  local ub_count = pr.read_varint()
  for i = 1, ub_count do
    local hash_bytes = pr.read_bytes(32)
    unbroadcast[i] = types.hash256_hex(types.hash256(hash_bytes))
  end

  return {
    entries = entries,
    map_deltas = map_deltas,
    unbroadcast = unbroadcast,
    version = version,
  }
end

--- Walk a Mempool object and pull (tx, time, fee_delta=0) tuples ready
-- for encode_dump.  Skips entries with no `tx` field defensively.
function M.snapshot(mempool)
  local entries = {}
  for _, entry in pairs(mempool.entries) do
    if entry and entry.tx then
      entries[#entries + 1] = {
        tx = entry.tx,
        time = entry.time or 0,
        fee_delta = entry.fee_delta or 0,
      }
    end
  end
  return entries
end

--- Dump a Mempool to disk in Bitcoin Core's mempool.dat format.
-- Writes to <path>.new and renames over <path>, matching Core.
-- @param mempool Mempool: source mempool
-- @param path string: destination path (e.g. <datadir>/mempool.dat)
-- @return boolean, string: ok, written_count_or_err
function M.dump(mempool, path)
  local entries = M.snapshot(mempool)
  local data = M.encode_dump(entries)
  local tmp = path .. ".new"
  local f, err = io.open(tmp, "wb")
  if not f then return false, err or "cannot open " .. tmp end
  f:write(data)
  f:close()
  local renamed, rerr = os.rename(tmp, path)
  if not renamed then
    return false, rerr or "rename failed"
  end
  return true, #entries
end

--- Load a mempool.dat file and feed each entry through accept_transaction.
-- Mirrors Core's LoadMempool: failures are tolerated, expired entries
-- (older than `expiry_seconds` from now) are skipped.  Returns a stats
-- table.
-- @param mempool Mempool: destination mempool
-- @param path string: source path
-- @param opts table: optional { now=os.time(), expiry_seconds=336*3600,
--                                use_current_time=false }
function M.load(mempool, path, opts)
  opts = opts or {}
  local f, ferr = io.open(path, "rb")
  if not f then
    return false, ferr or "no mempool dump"
  end
  local data = f:read("*a")
  f:close()
  local parsed, perr = M.decode_dump(data)
  if not parsed then
    return false, perr
  end
  local now = opts.now or os.time()
  local expiry_seconds = opts.expiry_seconds or (336 * 3600)  -- 14 days
  local stats = { count = 0, expired = 0, failed = 0, already_there = 0 }

  for _, e in ipairs(parsed.entries) do
    local nTime = opts.use_current_time and now or e.time
    if nTime < now - expiry_seconds then
      stats.expired = stats.expired + 1
    else
      local txid = validation.compute_txid(e.tx)
      local txid_hex = types.hash256_hex(txid)
      if mempool.entries[txid_hex] then
        stats.already_there = stats.already_there + 1
      else
        local ok = mempool:accept_transaction(e.tx)
        if ok then
          stats.count = stats.count + 1
          if opts.use_current_time then
            local entry = mempool.entries[txid_hex]
            if entry then entry.time = now end
          else
            local entry = mempool.entries[txid_hex]
            if entry then entry.time = nTime end
          end
        else
          stats.failed = stats.failed + 1
        end
      end
    end
  end

  return true, stats
end

return M
