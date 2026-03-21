local M = {}

-- BufferWriter: accumulates binary data for serialization
function M.buffer_writer()
  local parts = {}
  local writer = {}

  function writer.write_u8(val)
    parts[#parts + 1] = string.char(val % 256)
  end

  function writer.write_u16le(val)
    parts[#parts + 1] = string.char(val % 256, math.floor(val / 256) % 256)
  end

  function writer.write_u16be(val)
    parts[#parts + 1] = string.char(math.floor(val / 256) % 256, val % 256)
  end

  function writer.write_u32le(val)
    parts[#parts + 1] = string.char(
      val % 256,
      math.floor(val / 256) % 256,
      math.floor(val / 65536) % 256,
      math.floor(val / 16777216) % 256
    )
  end

  function writer.write_i32le(val)
    if val < 0 then val = val + 4294967296 end
    writer.write_u32le(val)
  end

  -- For 64-bit values, use two 32-bit writes (LuaJIT double precision safe up to 2^53)
  function writer.write_u64le(val)
    local low = val % 4294967296
    local high = math.floor(val / 4294967296)
    writer.write_u32le(low)
    writer.write_u32le(high)
  end

  function writer.write_i64le(val)
    -- Handle negative values: convert to unsigned representation
    -- For 64-bit, we split into two 32-bit parts
    if val < 0 then
      -- Two's complement: add 2^64
      -- Since we can't represent 2^64 directly, we handle it by adding to each part
      local low = val % 4294967296
      local high = math.floor(val / 4294967296)
      if low < 0 then
        low = low + 4294967296
        high = high - 1
      end
      if high < 0 then
        high = high + 4294967296
      end
      writer.write_u32le(low)
      writer.write_u32le(high)
    else
      writer.write_u64le(val)
    end
  end

  -- Bitcoin compact size encoding (varint)
  function writer.write_varint(val)
    if val < 0xFD then
      writer.write_u8(val)
    elseif val <= 0xFFFF then
      writer.write_u8(0xFD)
      writer.write_u16le(val)
    elseif val <= 0xFFFFFFFF then
      writer.write_u8(0xFE)
      writer.write_u32le(val)
    else
      writer.write_u8(0xFF)
      writer.write_u64le(val)
    end
  end

  function writer.write_bytes(data)
    parts[#parts + 1] = data
  end

  function writer.write_varstr(data)
    writer.write_varint(#data)
    writer.write_bytes(data)
  end

  function writer.write_hash256(h)
    writer.write_bytes(h.bytes)
  end

  function writer.result()
    return table.concat(parts)
  end

  function writer.length()
    local total = 0
    for _, p in ipairs(parts) do total = total + #p end
    return total
  end

  return writer
end

-- BufferReader: reads binary data for deserialization
function M.buffer_reader(data)
  local pos = 1
  local reader = {}

  function reader.read_u8()
    assert(pos <= #data, "read_u8: unexpected end of data")
    local val = data:byte(pos)
    pos = pos + 1
    return val
  end

  function reader.read_u16le()
    assert(pos + 1 <= #data, "read_u16le: unexpected end of data")
    local b1, b2 = data:byte(pos, pos + 1)
    pos = pos + 2
    return b1 + b2 * 256
  end

  function reader.read_u16be()
    assert(pos + 1 <= #data, "read_u16be: unexpected end of data")
    local b1, b2 = data:byte(pos, pos + 1)
    pos = pos + 2
    return b1 * 256 + b2
  end

  function reader.read_u32le()
    assert(pos + 3 <= #data, "read_u32le: unexpected end of data")
    local b1, b2, b3, b4 = data:byte(pos, pos + 3)
    pos = pos + 4
    return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
  end

  function reader.read_i32le()
    local val = reader.read_u32le()
    if val >= 2147483648 then val = val - 4294967296 end
    return val
  end

  function reader.read_u64le()
    local low = reader.read_u32le()
    local high = reader.read_u32le()
    return low + high * 4294967296
  end

  function reader.read_i64le()
    local low = reader.read_u32le()
    local high = reader.read_u32le()
    -- Check sign bit (bit 31 of high word)
    if high >= 2147483648 then
      -- Negative number: convert from two's complement
      -- Subtract 2^64 by computing -(2^64 - value)
      -- value = low + high * 2^32
      -- 2^64 - value = (2^32 - 1 - low) + (2^32 - 1 - high) * 2^32 + 1
      local comp_low = 4294967295 - low
      local comp_high = 4294967295 - high
      return -(comp_low + comp_high * 4294967296 + 1)
    else
      return low + high * 4294967296
    end
  end

  function reader.read_varint()
    local first = reader.read_u8()
    if first < 0xFD then
      return first
    elseif first == 0xFD then
      return reader.read_u16le()
    elseif first == 0xFE then
      return reader.read_u32le()
    else
      return reader.read_u64le()
    end
  end

  function reader.read_bytes(n)
    assert(pos + n - 1 <= #data, "read_bytes: unexpected end of data at pos " .. pos .. " need " .. n)
    local result = data:sub(pos, pos + n - 1)
    pos = pos + n
    return result
  end

  function reader.read_varstr()
    local len = reader.read_varint()
    return reader.read_bytes(len)
  end

  function reader.read_hash256()
    local types = require("lunarblock.types")
    return types.hash256(reader.read_bytes(32))
  end

  function reader.position()
    return pos
  end

  function reader.remaining()
    return #data - pos + 1
  end

  function reader.is_eof()
    return pos > #data
  end

  return reader
end

-- Serialize a block header to 80 bytes
function M.serialize_block_header(header)
  local w = M.buffer_writer()
  w.write_i32le(header.version)
  w.write_hash256(header.prev_hash)
  w.write_hash256(header.merkle_root)
  w.write_u32le(header.timestamp)
  w.write_u32le(header.bits)
  w.write_u32le(header.nonce)
  return w.result()
end

-- Deserialize a block header from 80 bytes
function M.deserialize_block_header(reader)
  local types = require("lunarblock.types")
  if type(reader) == "string" then
    reader = M.buffer_reader(reader)
  end
  return types.block_header(
    reader.read_i32le(),      -- version
    reader.read_hash256(),    -- prev_hash
    reader.read_hash256(),    -- merkle_root
    reader.read_u32le(),      -- timestamp
    reader.read_u32le(),      -- bits
    reader.read_u32le()       -- nonce
  )
end

-- Serialize a transaction (with optional witness)
function M.serialize_transaction(tx, include_witness)
  local w = M.buffer_writer()
  w.write_i32le(tx.version)

  local has_witness = include_witness and tx.segwit
  if has_witness then
    w.write_u8(0x00)  -- marker
    w.write_u8(0x01)  -- flag
  end

  w.write_varint(#tx.inputs)
  for _, inp in ipairs(tx.inputs) do
    w.write_hash256(inp.prev_out.hash)
    w.write_u32le(inp.prev_out.index)
    w.write_varstr(inp.script_sig)
    w.write_u32le(inp.sequence)
  end

  w.write_varint(#tx.outputs)
  for _, out in ipairs(tx.outputs) do
    w.write_i64le(out.value)
    w.write_varstr(out.script_pubkey)
  end

  if has_witness then
    for _, inp in ipairs(tx.inputs) do
      w.write_varint(#inp.witness)
      for _, item in ipairs(inp.witness) do
        w.write_varstr(item)
      end
    end
  end

  w.write_u32le(tx.locktime)
  return w.result()
end

-- Deserialize a transaction
function M.deserialize_transaction(reader)
  local types = require("lunarblock.types")
  if type(reader) == "string" then
    reader = M.buffer_reader(reader)
  end

  local version = reader.read_i32le()
  local marker = reader.read_u8()
  local segwit = false
  local input_count

  if marker == 0x00 then
    local flag = reader.read_u8()
    assert(flag == 0x01, "Invalid segwit flag: " .. flag)
    segwit = true
    input_count = reader.read_varint()
  else
    -- marker was actually the first byte of varint for input count
    if marker < 0xFD then
      input_count = marker
    elseif marker == 0xFD then
      input_count = reader.read_u16le()
    elseif marker == 0xFE then
      input_count = reader.read_u32le()
    else
      input_count = reader.read_u64le()
    end
  end

  local inputs = {}
  for i = 1, input_count do
    local prev_hash = reader.read_hash256()
    local prev_index = reader.read_u32le()
    local script_sig = reader.read_varstr()
    local sequence = reader.read_u32le()
    inputs[i] = types.txin(
      types.outpoint(prev_hash, prev_index),
      script_sig,
      sequence
    )
  end

  local output_count = reader.read_varint()
  local outputs = {}
  for i = 1, output_count do
    local value = reader.read_i64le()
    local script_pubkey = reader.read_varstr()
    outputs[i] = types.txout(value, script_pubkey)
  end

  if segwit then
    for _, inp in ipairs(inputs) do
      local stack_count = reader.read_varint()
      inp.witness = {}
      for j = 1, stack_count do
        inp.witness[j] = reader.read_varstr()
      end
    end
  end

  local locktime = reader.read_u32le()
  local tx = types.transaction(version, inputs, outputs, locktime)
  tx.segwit = segwit
  return tx
end

-- Serialize a full block
function M.serialize_block(blk)
  local w = M.buffer_writer()
  w.write_bytes(M.serialize_block_header(blk.header))
  w.write_varint(#blk.transactions)
  for _, tx in ipairs(blk.transactions) do
    w.write_bytes(M.serialize_transaction(tx, true))
  end
  return w.result()
end

-- Serialize a block without witness data (for stripped size calculation)
function M.serialize_block_without_witness(blk)
  local w = M.buffer_writer()
  w.write_bytes(M.serialize_block_header(blk.header))
  w.write_varint(#blk.transactions)
  for _, tx in ipairs(blk.transactions) do
    w.write_bytes(M.serialize_transaction(tx, false))  -- false = no witness
  end
  return w.result()
end

-- Deserialize a full block
function M.deserialize_block(reader)
  local types = require("lunarblock.types")
  if type(reader) == "string" then
    reader = M.buffer_reader(reader)
  end
  local header = M.deserialize_block_header(reader)
  local tx_count = reader.read_varint()
  local transactions = {}
  for i = 1, tx_count do
    transactions[i] = M.deserialize_transaction(reader)
  end
  return types.block(header, transactions)
end

return M
