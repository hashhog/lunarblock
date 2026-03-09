--- LuaJIT FFI test helpers for lunarblock
-- Provides hex conversion utilities, temporary directories, and mock objects
-- for testing Bitcoin consensus code.
local ffi = require("ffi")
local M = {}

--------------------------------------------------------------------------------
-- Hex Encoding/Decoding
--------------------------------------------------------------------------------

--- Convert a hex string to binary bytes.
-- @param hex string: hexadecimal string (e.g., "deadbeef")
-- @return string: binary data
function M.hex_to_bytes(hex)
  return (hex:gsub("%x%x", function(c) return string.char(tonumber(c, 16)) end))
end

--- Convert binary bytes to a hex string.
-- @param bytes string: binary data
-- @return string: hexadecimal string
function M.bytes_to_hex(bytes)
  return (bytes:gsub(".", function(c) return string.format("%02x", string.byte(c)) end))
end

--------------------------------------------------------------------------------
-- Temporary Directory Management
--------------------------------------------------------------------------------

--- Create a temporary directory for test databases.
-- @return string: path to the temporary directory
function M.tmpdir()
  local dir = os.tmpname() .. "_lunarblock_test"
  os.execute("mkdir -p " .. dir)
  return dir
end

--- Clean up a temporary directory.
-- @param dir string: path to directory to remove
function M.cleanup(dir)
  os.execute("rm -rf " .. dir)
end

--------------------------------------------------------------------------------
-- Custom Assertions
--------------------------------------------------------------------------------

--- Assert two byte strings are equal, showing hex on failure.
-- @param expected string: expected binary data
-- @param actual string: actual binary data
-- @param msg string: optional error message prefix
function M.assert_bytes_eq(expected, actual, msg)
  if expected ~= actual then
    error(string.format("%s\nExpected: %s\nActual:   %s",
      msg or "Byte mismatch",
      M.bytes_to_hex(expected),
      M.bytes_to_hex(actual)))
  end
end

--- Assert a hash256 matches expected hex value (handles endianness).
-- Bitcoin displays hashes in big-endian but stores them in little-endian.
-- @param expected_hex string: expected hash in display (big-endian) format
-- @param hash hash256: hash256 object
-- @param msg string: optional error message prefix
function M.assert_hash_eq(expected_hex, hash, msg)
  local types = require("lunarblock.types")
  local actual_hex = types.hash256_hex(hash)
  if expected_hex ~= actual_hex then
    error(string.format("%s\nExpected: %s\nActual:   %s",
      msg or "Hash mismatch", expected_hex, actual_hex))
  end
end

--------------------------------------------------------------------------------
-- Mock Objects
--------------------------------------------------------------------------------

--- Build a mock peer for integration tests.
-- Captures sent messages for later assertion.
-- @param opts table: optional configuration
--   - ip: peer IP (default "127.0.0.1")
--   - port: peer port (default 18444)
--   - user_agent: peer user agent (default "/LunarBlock:0.1.0/")
--   - start_height: peer's reported chain height (default 0)
--   - services: peer services bitmask (default 1)
-- @return table: mock peer object with send method
function M.mock_peer(opts)
  opts = opts or {}
  local peer = {
    ip = opts.ip or "127.0.0.1",
    port = opts.port or 18444,
    user_agent = opts.user_agent or "/LunarBlock:0.1.0/",
    start_height = opts.start_height or 0,
    services = opts.services or 1,
    sent = {},
  }

  --- Record a sent message.
  -- @param self table: peer object
  -- @param command string: message command
  -- @param payload string: message payload (optional)
  function peer:send_message(command, payload)
    self.sent[#self.sent + 1] = {
      command = command,
      payload = payload or ""
    }
  end

  --- Get all messages sent with a given command.
  -- @param self table: peer object
  -- @param command string: message command to filter
  -- @return table: list of matching messages
  function peer:messages_for(command)
    local results = {}
    for _, msg in ipairs(self.sent) do
      if msg.command == command then
        results[#results + 1] = msg
      end
    end
    return results
  end

  --- Clear all sent messages.
  -- @param self table: peer object
  function peer:clear_sent()
    self.sent = {}
  end

  return peer
end

--- Build a mock storage backend for testing.
-- @return table: mock storage object
function M.mock_storage()
  local data = {
    meta = {},
    headers = {},
    height_index = {},
    blocks = {},
  }

  local storage = {
    CF = {
      META = "meta",
      HEADERS = "headers",
      HEIGHT_INDEX = "height",
      BLOCKS = "blocks",
    }
  }

  function storage.get(cf, key)
    if data[cf] then
      return data[cf][key]
    end
    return nil
  end

  function storage.put(cf, key, value, sync)
    if data[cf] then
      data[cf][key] = value
    end
  end

  function storage.get_header(block_hash)
    local serialize = require("lunarblock.serialize")
    local header_data = data.headers[block_hash.bytes]
    if not header_data then return nil end
    return serialize.deserialize_block_header(header_data)
  end

  function storage.put_header(block_hash, header)
    local serialize = require("lunarblock.serialize")
    local header_data = serialize.serialize_block_header(header)
    data.headers[block_hash.bytes] = header_data
  end

  function storage.get_hash_by_height(height)
    local types = require("lunarblock.types")
    local key = string.char(
      math.floor(height / 16777216) % 256,
      math.floor(height / 65536) % 256,
      math.floor(height / 256) % 256,
      height % 256
    )
    local hash_bytes = data.height_index[key]
    if not hash_bytes or #hash_bytes ~= 32 then return nil end
    return types.hash256(hash_bytes)
  end

  function storage.put_height_index(height, block_hash)
    local key = string.char(
      math.floor(height / 16777216) % 256,
      math.floor(height / 65536) % 256,
      math.floor(height / 256) % 256,
      height % 256
    )
    data.height_index[key] = block_hash.bytes
  end

  function storage.get_chain_tip()
    return nil, nil
  end

  function storage.set_chain_tip(hash, height, sync)
  end

  function storage.put_block(block_hash, block)
    local serialize = require("lunarblock.serialize")
    data.blocks[block_hash.bytes] = serialize.serialize_block(block)
  end

  function storage.get_block(block_hash)
    local serialize = require("lunarblock.serialize")
    local block_data = data.blocks[block_hash.bytes]
    if not block_data then return nil end
    return serialize.deserialize_block(block_data)
  end

  return storage
end

--------------------------------------------------------------------------------
-- Bitcoin Core Test Vectors
--------------------------------------------------------------------------------

--- Well-known Bitcoin Core test vectors for crypto operations.
M.test_vectors = {
  -- SHA256d test vectors
  sha256d = {
    { input = "", expected = "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456" },
    { input = "abc", expected = "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358" },
  },
  -- HASH160 test vectors (known public keys)
  hash160 = {
    -- Compressed pubkey for private key = 1
    { input = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      expected = "751e76e8199196d454941c45d1b3a323f1433bd6" },
  },
  -- Genesis block header (80 bytes)
  genesis_header = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
  -- Genesis block hash (little-endian as stored)
  genesis_hash_le = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
  -- Genesis block hash (big-endian as displayed)
  genesis_hash_be = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
}

return M
