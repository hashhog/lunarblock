#!/usr/bin/env luajit
-- Targeted unit test for the getblockfrompeer RPC handler.
-- No network, no multi-node regtest: we drive rpc.methods.getblockfrompeer
-- directly against mock storage + a mock peer that captures outbound messages.
--
-- Asserts (mirrors Core rpc/blockchain.cpp::getblockfrompeer +
-- net_processing.cpp::FetchBlock):
--   (a) unknown header        -> RPC_MISC_ERROR (-1) "Block header missing"
--   (b) unknown/disconnected peer_id -> RPC_MISC_ERROR (-1) "Peer does not exist"
--   (c) success: a getdata(MSG_WITNESS_BLOCK, hash) is sent to the resolved
--       peer and the result is the empty JSON object {}.
--   (d) the peer-id convention is the 0-based peer_list index (same as
--       getpeerinfo "id" / disconnectnode nodeid).

package.path = "lunarblock/?.lua;src/?.lua;" .. package.path

-- Mock socket so requiring peer/p2p modules (pulled in transitively) is safe.
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
local p2p = require("lunarblock.p2p")

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

-- A known block hash (display hex) and its corresponding hash256 object.
local KNOWN_HEX = "00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"
local known_hash = types.hash256_from_hex(KNOWN_HEX)

-- Mock storage: only KNOWN_HEX has a header, and no block body on disk
-- (so the "already downloaded" short-circuit does not fire).
local mock_storage = {
  get_header = function(hash)
    if hash.bytes == known_hash.bytes then
      -- Minimal header stand-in; the handler only checks for non-nil.
      return { version = 1, bits = 0x1d00ffff, nonce = 0 }
    end
    return nil
  end,
  get_block = function(_hash) return nil end,
  get_hash_by_height = function(_h) return nil end,
}

-- Mock peer: captures every send_message call.
local function make_mock_peer(ip, port)
  return {
    ip = ip, port = port, sent = {},
    send_message = function(self, command, payload)
      self.sent[#self.sent + 1] = { command = command, payload = payload }
      return true
    end,
  }
end

local function make_server(peer_list)
  return rpc.new({
    network = consensus.networks.regtest,
    storage = mock_storage,
    peer_manager = peer_list and { peer_list = peer_list } or nil,
  })
end

-- (existence) the method is registered + dispatchable.
test("getblockfrompeer method exists", function()
  local server = make_server({})
  assert(server.methods.getblockfrompeer ~= nil, "method not registered")
end)

-- (a) unknown header -> RPC_MISC_ERROR "Block header missing".
test("unknown header -> 'Block header missing' (-1)", function()
  local peer = make_mock_peer("1.2.3.4", 8333)
  local server = make_server({ peer })
  local unknown_hex = string.rep("ab", 32)
  local ok, err = pcall(server.methods.getblockfrompeer, server, { unknown_hex, 0 })
  assert(not ok, "expected error, got success")
  assert(type(err) == "table", "expected structured error table, got " .. type(err))
  assert(err.code == -1, "expected code -1 (RPC_MISC_ERROR), got " .. tostring(err.code))
  assert(err.message == "Block header missing",
    "expected 'Block header missing', got " .. tostring(err.message))
  assert(#peer.sent == 0, "no getdata should be sent on header-missing")
end)

-- (b) unknown/disconnected peer_id -> RPC_MISC_ERROR "Peer does not exist".
test("unknown peer_id -> 'Peer does not exist' (-1)", function()
  -- peer_list has 1 peer (index 0 valid); request peer_id 5 (out of range).
  local peer = make_mock_peer("1.2.3.4", 8333)
  local server = make_server({ peer })
  local ok, err = pcall(server.methods.getblockfrompeer, server, { KNOWN_HEX, 5 })
  assert(not ok, "expected error, got success")
  assert(type(err) == "table", "expected structured error table")
  assert(err.code == -1, "expected code -1, got " .. tostring(err.code))
  assert(err.message == "Peer does not exist",
    "expected 'Peer does not exist', got " .. tostring(err.message))
  assert(#peer.sent == 0, "no getdata should be sent when peer not found")
end)

-- (b') no peer_manager at all -> 'Peer does not exist'.
test("no peer_manager -> 'Peer does not exist' (-1)", function()
  local server = make_server(nil)  -- peer_manager = nil
  local ok, err = pcall(server.methods.getblockfrompeer, server, { KNOWN_HEX, 0 })
  assert(not ok, "expected error")
  assert(err.code == -1 and err.message == "Peer does not exist",
    "expected 'Peer does not exist', got " .. tostring(err and err.message))
end)

-- (c) + (d) success: getdata(MSG_WITNESS_BLOCK, hash) sent to the resolved
-- peer (peer_id 0 == peer_list[1]); result is {}.
test("success -> getdata(block) sent to resolved peer, returns {}", function()
  local peer0 = make_mock_peer("10.0.0.1", 8333)
  local peer1 = make_mock_peer("10.0.0.2", 8333)
  local server = make_server({ peer0, peer1 })

  -- peer_id 1 must resolve to peer_list[2] == peer1 (0-based, getpeerinfo "id").
  local result = server.methods.getblockfrompeer(server, { KNOWN_HEX, 1 })

  -- result is the empty JSON object {}.
  assert(type(result) == "table", "result should be a table")
  assert(result._raw_json == "{}", "result should encode as empty object {}, got "
    .. tostring(result._raw_json))

  -- getdata went to peer1 (the resolved peer), NOT peer0.
  assert(#peer1.sent == 1, "expected exactly 1 message to resolved peer, got " .. #peer1.sent)
  assert(#peer0.sent == 0, "no message should go to the non-targeted peer")

  local msg = peer1.sent[1]
  assert(msg.command == "getdata", "expected 'getdata' command, got " .. tostring(msg.command))

  -- Decode the getdata payload and verify it carries our block hash with a
  -- block inv type.
  local invs = p2p.deserialize_getdata(msg.payload)
  assert(#invs == 1, "expected 1 inv item, got " .. #invs)
  local item = invs[1]
  assert(item.type == p2p.INV_TYPE.MSG_WITNESS_BLOCK
      or item.type == p2p.INV_TYPE.MSG_BLOCK,
    "expected a block inv type, got " .. tostring(item.type))
  assert(item.hash.bytes == known_hash.bytes,
    "getdata hash must equal the requested block hash")
  -- Confirm round-trip back to the display hex.
  assert(types.hash256_hex(item.hash) == KNOWN_HEX,
    "getdata hash hex mismatch: got " .. types.hash256_hex(item.hash))
end)

print("")
print(string.format("=== getblockfrompeer RPC: %d passed, %d failed ===", passed, failed))
os.exit(failed == 0 and 0 or 1)
