local rpc = require("lunarblock.rpc")
local types = require("lunarblock.types")
local consensus = require("lunarblock.consensus")
local cjson = require("cjson")

describe("rpc", function()

  describe("parse_http_request", function()
    it("parses valid POST request with JSON body", function()
      local request = "POST / HTTP/1.1\r\n" ..
        "Host: localhost:8332\r\n" ..
        "Content-Type: application/json\r\n" ..
        "Content-Length: 52\r\n" ..
        "\r\n" ..
        '{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":1}'

      local method, path, headers, body = rpc.parse_http_request(request)

      assert.equal("POST", method)
      assert.equal("/", path)
      assert.equal("application/json", headers["content-type"])
      assert.equal("52", headers["content-length"])
      assert.equal('{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":1}', body)
    end)

    it("returns nil for incomplete request", function()
      local request = "POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nshort"

      local method, err = rpc.parse_http_request(request)

      assert.is_nil(method)
      assert.equal("incomplete body", err)
    end)

    it("returns nil for missing header delimiter", function()
      local request = "POST / HTTP/1.1\r\nContent-Length: 10"

      local method, err = rpc.parse_http_request(request)

      assert.is_nil(method)
      assert.equal("incomplete request", err)
    end)

    it("handles headers case-insensitively", function()
      local request = "GET /test HTTP/1.1\r\n" ..
        "CONTENT-TYPE: text/plain\r\n" ..
        "content-length: 0\r\n" ..
        "\r\n"

      local method, path, headers = rpc.parse_http_request(request)

      assert.equal("GET", method)
      assert.equal("/test", path)
      assert.equal("text/plain", headers["content-type"])
      assert.equal("0", headers["content-length"])
    end)
  end)

  describe("build_http_response", function()
    it("builds correct HTTP format with content-length", function()
      local body = '{"result":42}'
      local response = rpc.build_http_response(200, body)

      assert.truthy(response:match("HTTP/1.1 200 OK"))
      assert.truthy(response:match("Content%-Type: application/json"))
      assert.truthy(response:match("Content%-Length: " .. #body))
      assert.truthy(response:match(body .. "$"))
    end)

    it("handles different status codes", function()
      local response400 = rpc.build_http_response(400, "{}")
      local response404 = rpc.build_http_response(404, "{}")
      local response500 = rpc.build_http_response(500, "{}")

      assert.truthy(response400:match("400 Bad Request"))
      assert.truthy(response404:match("404 Not Found"))
      assert.truthy(response500:match("500 Internal Server Error"))
    end)

    it("allows custom content type", function()
      local response = rpc.build_http_response(200, "plain text", "text/plain")

      assert.truthy(response:match("Content%-Type: text/plain"))
    end)
  end)

  describe("check_auth", function()
    it("accepts valid credentials", function()
      -- "user:pass" in base64 is "dXNlcjpwYXNz"
      local headers = {authorization = "Basic dXNlcjpwYXNz"}

      assert.is_true(rpc.check_auth(headers, "user", "pass"))
    end)

    it("rejects invalid credentials", function()
      local headers = {authorization = "Basic dXNlcjpwYXNz"}

      assert.is_false(rpc.check_auth(headers, "user", "wrong"))
    end)

    it("rejects missing authorization header", function()
      local headers = {}

      assert.is_false(rpc.check_auth(headers, "user", "pass"))
    end)

    it("rejects non-Basic auth scheme", function()
      local headers = {authorization = "Bearer sometoken"}

      assert.is_false(rpc.check_auth(headers, "user", "pass"))
    end)
  end)

  describe("base64_decode", function()
    it("decodes known test vectors", function()
      -- Standard base64 test cases
      assert.equal("hello", rpc.base64_decode("aGVsbG8="))
      assert.equal("world", rpc.base64_decode("d29ybGQ="))
      assert.equal("user:pass", rpc.base64_decode("dXNlcjpwYXNz"))
      assert.equal("test", rpc.base64_decode("dGVzdA=="))
      assert.equal("a", rpc.base64_decode("YQ=="))
      assert.equal("ab", rpc.base64_decode("YWI="))
      assert.equal("abc", rpc.base64_decode("YWJj"))
    end)

    it("handles no padding", function()
      assert.equal("abc", rpc.base64_decode("YWJj"))
    end)
  end)

  describe("hex_encode", function()
    it("encodes binary data correctly", function()
      assert.equal("00", rpc.hex_encode("\x00"))
      assert.equal("ff", rpc.hex_encode("\xff"))
      assert.equal("0102030405", rpc.hex_encode("\x01\x02\x03\x04\x05"))
      assert.equal("deadbeef", rpc.hex_encode("\xde\xad\xbe\xef"))
    end)
  end)

  describe("hex_decode", function()
    it("decodes hex strings correctly", function()
      assert.equal("\x00", rpc.hex_decode("00"))
      assert.equal("\xff", rpc.hex_decode("ff"))
      assert.equal("\x01\x02\x03\x04\x05", rpc.hex_decode("0102030405"))
      assert.equal("\xde\xad\xbe\xef", rpc.hex_decode("deadbeef"))
    end)
  end)

  describe("handle_request", function()
    local server

    before_each(function()
      server = rpc.new({
        chain_state = {
          tip_height = 700000,
          tip_hash = types.hash256(string.rep("\xab", 32))
        },
        network = consensus.networks.mainnet
      })
    end)

    it("returns result for valid JSON-RPC call", function()
      local request = '{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(700000, decoded.result)
      assert.equal(cjson.null, decoded.error)
      assert.equal(1, decoded.id)
    end)

    it("returns METHOD_NOT_FOUND for unknown method", function()
      local request = '{"method":"unknownmethod","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(cjson.null, decoded.result)
      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.METHOD_NOT_FOUND, decoded.error.code)
      assert.truthy(decoded.error.message:match("unknownmethod"))
      assert.equal(1, decoded.id)
    end)

    it("returns PARSE_ERROR for malformed JSON", function()
      local request = '{"method": broken json'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(cjson.null, decoded.result)
      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.PARSE_ERROR, decoded.error.code)
      assert.equal(cjson.null, decoded.id)
    end)

    it("preserves request id in response", function()
      local request = '{"method":"getblockcount","params":[],"id":"test-123"}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal("test-123", decoded.id)
    end)

    it("handles numeric id", function()
      local request = '{"method":"getblockcount","params":[],"id":42}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(42, decoded.id)
    end)
  end)

  describe("getblockchaininfo", function()
    it("returns expected fields", function()
      local server = rpc.new({
        chain_state = {
          tip_height = 700000,
          tip_hash = types.hash256(string.rep("\xab", 32))
        },
        network = consensus.networks.mainnet
      })

      local request = '{"method":"getblockchaininfo","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal("mainnet", decoded.result.chain)
      assert.equal(700000, decoded.result.blocks)
      assert.equal(700000, decoded.result.headers)
      assert.is_string(decoded.result.bestblockhash)
      assert.equal(64, #decoded.result.bestblockhash)
      assert.is_number(decoded.result.difficulty)
      assert.is_number(decoded.result.mediantime)
      assert.is_number(decoded.result.verificationprogress)
      assert.is_boolean(decoded.result.initialblockdownload)
      assert.is_string(decoded.result.chainwork)
      assert.is_boolean(decoded.result.pruned)
    end)

    it("works with testnet", function()
      local server = rpc.new({
        chain_state = {
          tip_height = 2000000,
          tip_hash = types.hash256(string.rep("\xcd", 32))
        },
        network = consensus.networks.testnet
      })

      local request = '{"method":"getblockchaininfo","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal("testnet", decoded.result.chain)
    end)
  end)

  describe("getblockcount", function()
    it("returns current height", function()
      local server = rpc.new({
        chain_state = {tip_height = 123456},
        network = consensus.networks.mainnet
      })

      local request = '{"method":"getblockcount","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(123456, decoded.result)
    end)

    it("returns 0 when no chain state", function()
      local server = rpc.new({network = consensus.networks.mainnet})

      local request = '{"method":"getblockcount","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(0, decoded.result)
    end)
  end)

  describe("getrawmempool", function()
    it("returns list of txids when no mempool", function()
      local server = rpc.new({network = consensus.networks.mainnet})

      local request = '{"method":"getrawmempool","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.same({}, decoded.result)
    end)

    it("returns empty object for verbose when no mempool", function()
      local server = rpc.new({network = consensus.networks.mainnet})

      local request = '{"method":"getrawmempool","params":[true],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.same({}, decoded.result)
    end)
  end)

  describe("estimatesmartfee", function()
    it("returns feerate and blocks", function()
      local server = rpc.new({network = consensus.networks.mainnet})

      local request = '{"method":"estimatesmartfee","params":[6],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_number(decoded.result.feerate)
      assert.is_number(decoded.result.blocks)
      assert.equal(6, decoded.result.blocks)
    end)

    it("uses default target when not specified", function()
      local server = rpc.new({network = consensus.networks.mainnet})

      local request = '{"method":"estimatesmartfee","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_number(decoded.result.feerate)
      assert.equal(6, decoded.result.blocks)  -- Default target
    end)
  end)

  describe("help", function()
    it("returns sorted list of methods", function()
      local server = rpc.new({network = consensus.networks.mainnet})

      local request = '{"method":"help","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      local methods = decoded.result
      assert.is_string(methods)
      assert.truthy(methods:match("getblockcount"))
      assert.truthy(methods:match("getblockchaininfo"))
      assert.truthy(methods:match("help"))

      -- Check sorted order
      local lines = {}
      for line in methods:gmatch("[^\n]+") do
        lines[#lines + 1] = line
      end
      assert.is_true(#lines > 5)

      -- Verify sorted
      for i = 2, #lines do
        assert.is_true(lines[i-1] < lines[i], "Methods should be sorted")
      end
    end)

    it("returns message for specific method", function()
      local server = rpc.new({network = consensus.networks.mainnet})

      local request = '{"method":"help","params":["getblockcount"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.truthy(decoded.result:match("getblockcount"))
    end)
  end)

  describe("validateaddress", function()
    it("validates mainnet P2PKH address", function()
      local server = rpc.new({network = consensus.networks.mainnet})

      -- Valid mainnet address
      local request = '{"method":"validateaddress","params":["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_true(decoded.result.isvalid)
      assert.equal("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", decoded.result.address)
    end)

    it("rejects invalid address", function()
      local server = rpc.new({network = consensus.networks.mainnet})

      local request = '{"method":"validateaddress","params":["invalid"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_false(decoded.result.isvalid)
    end)
  end)

  describe("getnetworkinfo", function()
    it("returns expected fields", function()
      local server = rpc.new({network = consensus.networks.mainnet})

      local request = '{"method":"getnetworkinfo","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_number(decoded.result.version)
      assert.is_string(decoded.result.subversion)
      assert.truthy(decoded.result.subversion:match("LunarBlock"))
      assert.is_number(decoded.result.protocolversion)
      assert.is_number(decoded.result.connections)
      assert.is_table(decoded.result.networks)
      assert.is_number(decoded.result.relayfee)
    end)
  end)

  describe("getconnectioncount", function()
    it("returns 0 when no peer manager", function()
      local server = rpc.new({network = consensus.networks.mainnet})

      local request = '{"method":"getconnectioncount","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(0, decoded.result)
    end)

    it("returns peer count from peer manager", function()
      local mock_peer_manager = {
        peer_list = {{}, {}, {}}  -- 3 mock peers
      }
      local server = rpc.new({
        network = consensus.networks.mainnet,
        peer_manager = mock_peer_manager
      })

      local request = '{"method":"getconnectioncount","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(3, decoded.result)
    end)
  end)

  describe("stop", function()
    it("returns shutdown message", function()
      local server = rpc.new({network = consensus.networks.mainnet})

      local request = '{"method":"stop","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_string(decoded.result)
      assert.truthy(decoded.result:match("stopping"))
    end)
  end)

  describe("RPC error codes", function()
    it("defines standard JSON-RPC error codes", function()
      assert.equal(-32700, rpc.ERROR.PARSE_ERROR)
      assert.equal(-32600, rpc.ERROR.INVALID_REQUEST)
      assert.equal(-32601, rpc.ERROR.METHOD_NOT_FOUND)
      assert.equal(-32602, rpc.ERROR.INVALID_PARAMS)
      assert.equal(-32603, rpc.ERROR.INTERNAL_ERROR)
    end)

    it("defines Bitcoin-specific error codes", function()
      assert.equal(-1, rpc.ERROR.MISC_ERROR)
      assert.equal(-26, rpc.ERROR.VERIFY_REJECTED)
      assert.equal(-22, rpc.ERROR.DESERIALIZATION_ERROR)
      assert.equal(-25, rpc.ERROR.VERIFY_ERROR)
      assert.equal(-27, rpc.ERROR.VERIFY_ALREADY_IN_CHAIN)
    end)
  end)

  describe("sendrawtransaction", function()
    local serialize = require("lunarblock.serialize")
    local validation = require("lunarblock.validation")

    -- Create a simple test transaction (non-segwit, minimal valid structure)
    local function make_test_tx(prev_hash, prev_index, value)
      prev_hash = prev_hash or string.rep("\x01", 32)
      prev_index = prev_index or 0
      value = value or 50000  -- 0.0005 BTC
      return {
        version = 2,
        inputs = {
          {
            prev_out = {
              hash = types.hash256(prev_hash),
              index = prev_index
            },
            script_sig = "\x00",  -- minimal valid scriptSig
            sequence = 0xFFFFFFFE,  -- RBF signaling
            witness = {}
          }
        },
        outputs = {
          {
            value = value,
            script_pubkey = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"  -- P2PKH
          }
        },
        locktime = 0,
        segwit = false
      }
    end

    -- Create a mock mempool
    local function make_mock_mempool(accept_result, accept_fee, entries)
      entries = entries or {}
      return {
        entries = entries,
        has = function(self, txid_hex)
          return self.entries[txid_hex] ~= nil
        end,
        accept_transaction = function(self, tx)
          if type(accept_result) == "function" then
            return accept_result(tx)
          elseif accept_result == true then
            local txid = validation.compute_txid(tx)
            local txid_hex = types.hash256_hex(txid)
            -- Add to entries to track
            self.entries[txid_hex] = {tx = tx, fee = accept_fee or 1000}
            return true, txid_hex, accept_fee or 1000
          else
            return false, accept_result or "validation failed"
          end
        end,
        remove_transaction = function(self, txid_hex, reason)
          self.entries[txid_hex] = nil
        end
      }
    end

    -- Create a mock peer manager
    local function make_mock_peer_manager()
      local pm = {
        broadcasts = {},  -- record of broadcasts
        announcements = {},  -- record of queued announcements
      }
      pm.broadcast = function(self, cmd, payload)
        self.broadcasts[#self.broadcasts + 1] = {command = cmd, payload = payload}
      end
      pm.queue_tx_announcement = function(self, txid, wtxid)
        self.announcements[#self.announcements + 1] = {txid = txid, wtxid = wtxid}
      end
      return pm
    end

    it("accepts valid transaction and returns txid", function()
      local tx = make_test_tx()
      local txid = validation.compute_txid(tx)
      local expected_txid = types.hash256_hex(txid)
      local raw = serialize.serialize_transaction(tx, false)
      local hex = rpc.hex_encode(raw)

      local mock_mempool = make_mock_mempool(true, 1000)
      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      local request = '{"method":"sendrawtransaction","params":["' .. hex .. '"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(cjson.null, decoded.error)
      assert.equal(expected_txid, decoded.result)
      assert.equal(64, #decoded.result)  -- txid is 64 hex chars
    end)

    it("broadcasts inv to peers on success", function()
      local tx = make_test_tx()
      local raw = serialize.serialize_transaction(tx, false)
      local hex = rpc.hex_encode(raw)

      local mock_mempool = make_mock_mempool(true, 1000)
      local mock_peer_manager = make_mock_peer_manager()
      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool,
        peer_manager = mock_peer_manager
      })

      local request = '{"method":"sendrawtransaction","params":["' .. hex .. '"],"id":1}'
      server:handle_request(request)

      -- Should have broadcast an inv message
      assert.equal(1, #mock_peer_manager.broadcasts)
      assert.equal("inv", mock_peer_manager.broadcasts[1].command)

      -- Should have queued trickling announcement
      assert.equal(1, #mock_peer_manager.announcements)
    end)

    it("returns DESERIALIZATION_ERROR for invalid hex", function()
      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = make_mock_mempool(true, 1000)
      })

      -- Invalid hex (not valid transaction structure)
      local request = '{"method":"sendrawtransaction","params":["deadbeef"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.DESERIALIZATION_ERROR, decoded.error.code)
      assert.truthy(decoded.error.message:match("decode"))
    end)

    it("returns DESERIALIZATION_ERROR for empty hex", function()
      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = make_mock_mempool(true, 1000)
      })

      local request = '{"method":"sendrawtransaction","params":[""],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.DESERIALIZATION_ERROR, decoded.error.code)
    end)

    it("returns VERIFY_ALREADY_IN_CHAIN when tx already in mempool", function()
      local tx = make_test_tx()
      local txid = validation.compute_txid(tx)
      local txid_hex = types.hash256_hex(txid)
      local raw = serialize.serialize_transaction(tx, false)
      local hex = rpc.hex_encode(raw)

      -- Mempool already has this transaction
      local mock_mempool = make_mock_mempool(true, 1000, {[txid_hex] = {tx = tx}})
      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      local request = '{"method":"sendrawtransaction","params":["' .. hex .. '"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.VERIFY_ALREADY_IN_CHAIN, decoded.error.code)
      assert.truthy(decoded.error.message:match("already"))
    end)

    it("returns VERIFY_ERROR for missing inputs", function()
      local tx = make_test_tx()
      local raw = serialize.serialize_transaction(tx, false)
      local hex = rpc.hex_encode(raw)

      local mock_mempool = make_mock_mempool("missing inputs")
      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      local request = '{"method":"sendrawtransaction","params":["' .. hex .. '"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.VERIFY_ERROR, decoded.error.code)
      assert.truthy(decoded.error.message:match("missing inputs"))
    end)

    it("returns VERIFY_REJECTED for insufficient fee", function()
      local tx = make_test_tx()
      local raw = serialize.serialize_transaction(tx, false)
      local hex = rpc.hex_encode(raw)

      local mock_mempool = make_mock_mempool("fee rate too low: 0.5 < 1000 sat/KB")
      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      local request = '{"method":"sendrawtransaction","params":["' .. hex .. '"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.VERIFY_REJECTED, decoded.error.code)
      assert.truthy(decoded.error.message:match("fee"))
    end)

    it("rejects transaction exceeding maxfeerate", function()
      local tx = make_test_tx()
      local raw = serialize.serialize_transaction(tx, false)
      local hex = rpc.hex_encode(raw)

      -- Very high fee (1 BTC = 100M satoshis for a ~100 vbyte tx = ~1M sat/vB)
      local mock_mempool = make_mock_mempool(true, 100000000)  -- 1 BTC fee
      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      -- maxfeerate = 0.001 BTC/kvB (very low, ~100 sat/vB)
      local request = '{"method":"sendrawtransaction","params":["' .. hex .. '", 0.001],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.MISC_ERROR, decoded.error.code)
      assert.truthy(decoded.error.message:match("exceeds maxfeerate"))
    end)

    it("accepts any fee when maxfeerate is 0", function()
      local tx = make_test_tx()
      local txid = validation.compute_txid(tx)
      local expected_txid = types.hash256_hex(txid)
      local raw = serialize.serialize_transaction(tx, false)
      local hex = rpc.hex_encode(raw)

      -- Very high fee
      local mock_mempool = make_mock_mempool(true, 100000000)
      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      -- maxfeerate = 0 means accept any fee rate
      local request = '{"method":"sendrawtransaction","params":["' .. hex .. '", 0],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(cjson.null, decoded.error)
      assert.equal(expected_txid, decoded.result)
    end)

    it("rejects maxfeerate > 1 BTC/kvB", function()
      local tx = make_test_tx()
      local raw = serialize.serialize_transaction(tx, false)
      local hex = rpc.hex_encode(raw)

      local mock_mempool = make_mock_mempool(true, 1000)
      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      -- maxfeerate = 2 BTC/kvB (unreasonably high, should reject)
      local request = '{"method":"sendrawtransaction","params":["' .. hex .. '", 2.0],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.MISC_ERROR, decoded.error.code)
      assert.truthy(decoded.error.message:match("cannot exceed"))
    end)

    it("uses default maxfeerate of 0.10 BTC/kvB", function()
      local tx = make_test_tx()
      local raw = serialize.serialize_transaction(tx, false)
      local hex = rpc.hex_encode(raw)

      -- Fee that is ~1000 sat/vB (should be well under 0.10 BTC/kvB = 10000 sat/vB)
      local mock_mempool = make_mock_mempool(true, 100000)  -- 0.001 BTC
      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      -- No maxfeerate param - should use default
      local request = '{"method":"sendrawtransaction","params":["' .. hex .. '"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(cjson.null, decoded.error)
      assert.is_string(decoded.result)
    end)

    it("removes tx from mempool if maxfeerate check fails after acceptance", function()
      local tx = make_test_tx()
      local raw = serialize.serialize_transaction(tx, false)
      local hex = rpc.hex_encode(raw)

      -- High fee that passes mempool but fails maxfeerate
      local mock_mempool = make_mock_mempool(true, 50000000)  -- 0.5 BTC
      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      local txid = validation.compute_txid(tx)
      local txid_hex = types.hash256_hex(txid)

      -- Very low maxfeerate
      local request = '{"method":"sendrawtransaction","params":["' .. hex .. '", 0.0001],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      -- Should error
      assert.is_not_nil(decoded.error)

      -- Transaction should have been removed from mempool
      assert.is_nil(mock_mempool.entries[txid_hex])
    end)

    it("requires mempool to be available", function()
      local tx = make_test_tx()
      local raw = serialize.serialize_transaction(tx, false)
      local hex = rpc.hex_encode(raw)

      local server = rpc.new({
        network = consensus.networks.mainnet
        -- No mempool!
      })

      local request = '{"method":"sendrawtransaction","params":["' .. hex .. '"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      -- Should be internal error since mempool is required
      assert.truthy(decoded.error.message:match("[Mm]empool"))
    end)
  end)

  describe("getrawtransaction", function()
    local serialize = require("lunarblock.serialize")
    local validation = require("lunarblock.validation")

    -- Create a simple test transaction (non-segwit, minimal valid structure)
    local function make_test_tx(prev_hash, prev_index, value, output_script)
      prev_hash = prev_hash or string.rep("\x01", 32)
      prev_index = prev_index or 0
      value = value or 50000  -- 0.0005 BTC
      output_script = output_script or "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"  -- P2PKH
      return {
        version = 2,
        inputs = {
          {
            prev_out = {
              hash = types.hash256(prev_hash),
              index = prev_index
            },
            script_sig = "\x00",
            sequence = 0xFFFFFFFE,
            witness = {}
          }
        },
        outputs = {
          {
            value = value,
            script_pubkey = output_script
          }
        },
        locktime = 0,
        segwit = false
      }
    end

    -- Create a mock mempool
    local function make_mock_mempool(entries)
      entries = entries or {}
      return {
        entries = entries,
        get_entry = function(self, txid_hex)
          return self.entries[txid_hex]
        end,
        has = function(self, txid_hex)
          return self.entries[txid_hex] ~= nil
        end,
      }
    end

    -- Create a mock storage
    local function make_mock_storage(blocks, tx_index)
      blocks = blocks or {}
      tx_index = tx_index or {}
      return {
        get_block = function(block_hash)
          local hash_hex = types.hash256_hex(block_hash)
          return blocks[hash_hex]
        end,
        get = function(cf, key)
          if cf == "tx_index" then
            local txid_hex = rpc.hex_encode(key)
            return tx_index[txid_hex]
          end
          return nil
        end,
      }
    end

    it("returns raw hex for mempool transaction (non-verbose)", function()
      local tx = make_test_tx()
      local txid = validation.compute_txid(tx)
      local txid_hex = types.hash256_hex(txid)
      local weight = validation.get_tx_weight(tx)
      local size = #serialize.serialize_transaction(tx, true)
      local vsize = math.ceil(weight / 4)

      local mock_mempool = make_mock_mempool({
        [txid_hex] = {
          tx = tx,
          txid = txid,
          fee = 1000,
          vsize = vsize,
          weight = weight,
          size = size,
          time = os.time(),
        }
      })

      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      local request = '{"method":"getrawtransaction","params":["' .. txid_hex .. '", false],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(cjson.null, decoded.error)
      assert.is_string(decoded.result)
      -- Should be hex-encoded transaction
      assert.truthy(decoded.result:match("^[0-9a-f]+$"))

      -- Verify it decodes back to the same transaction
      local decoded_raw = rpc.hex_decode(decoded.result)
      local decoded_tx = serialize.deserialize_transaction(decoded_raw)
      assert.equal(tx.version, decoded_tx.version)
      assert.equal(tx.locktime, decoded_tx.locktime)
    end)

    it("returns verbose output for mempool transaction", function()
      local tx = make_test_tx()
      local txid = validation.compute_txid(tx)
      local txid_hex = types.hash256_hex(txid)
      local weight = validation.get_tx_weight(tx)
      local size = #serialize.serialize_transaction(tx, true)
      local vsize = math.ceil(weight / 4)

      local mock_mempool = make_mock_mempool({
        [txid_hex] = {
          tx = tx,
          txid = txid,
          fee = 1000,
          vsize = vsize,
          weight = weight,
          size = size,
          time = os.time(),
        }
      })

      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      local request = '{"method":"getrawtransaction","params":["' .. txid_hex .. '", true],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(cjson.null, decoded.error)
      local result = decoded.result

      -- Check required fields
      assert.equal(txid_hex, result.txid)
      assert.is_string(result.hash)  -- wtxid
      assert.equal(64, #result.hash)
      assert.equal(tx.version, result.version)
      assert.is_number(result.size)
      assert.is_number(result.vsize)
      assert.is_number(result.weight)
      assert.equal(tx.locktime, result.locktime)
      assert.is_table(result.vin)
      assert.is_table(result.vout)
      assert.is_string(result.hex)

      -- Check vin
      assert.equal(1, #result.vin)
      assert.is_string(result.vin[1].txid)
      assert.is_number(result.vin[1].vout)
      assert.is_table(result.vin[1].scriptSig)
      assert.is_string(result.vin[1].scriptSig.asm)
      assert.is_string(result.vin[1].scriptSig.hex)
      assert.is_number(result.vin[1].sequence)

      -- Check vout
      assert.equal(1, #result.vout)
      assert.is_number(result.vout[1].value)
      assert.equal(0, result.vout[1].n)  -- output index
      assert.is_table(result.vout[1].scriptPubKey)
      assert.is_string(result.vout[1].scriptPubKey.type)
      assert.is_string(result.vout[1].scriptPubKey.asm)
      assert.is_string(result.vout[1].scriptPubKey.hex)

      -- Mempool transactions should not have block info
      assert.is_nil(result.blockhash)
      assert.is_nil(result.confirmations)
    end)

    it("decodes P2PKH scriptPubKey correctly", function()
      -- Create P2PKH output
      local pubkey_hash = string.rep("\xab", 20)
      local script = "\x76\xa9\x14" .. pubkey_hash .. "\x88\xac"
      local tx = make_test_tx(nil, nil, 50000, script)
      local txid = validation.compute_txid(tx)
      local txid_hex = types.hash256_hex(txid)
      local weight = validation.get_tx_weight(tx)
      local size = #serialize.serialize_transaction(tx, true)
      local vsize = math.ceil(weight / 4)

      local mock_mempool = make_mock_mempool({
        [txid_hex] = {
          tx = tx,
          txid = txid,
          fee = 1000,
          vsize = vsize,
          weight = weight,
          size = size,
          time = os.time(),
        }
      })

      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      local request = '{"method":"getrawtransaction","params":["' .. txid_hex .. '", true],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      local spk = decoded.result.vout[1].scriptPubKey
      assert.equal("pubkeyhash", spk.type)
      assert.is_string(spk.address)
      assert.truthy(spk.address:match("^1"))  -- mainnet P2PKH starts with 1
    end)

    it("decodes P2SH scriptPubKey correctly", function()
      -- Create P2SH output
      local script_hash = string.rep("\xcd", 20)
      local script = "\xa9\x14" .. script_hash .. "\x87"
      local tx = make_test_tx(nil, nil, 50000, script)
      local txid = validation.compute_txid(tx)
      local txid_hex = types.hash256_hex(txid)
      local weight = validation.get_tx_weight(tx)
      local size = #serialize.serialize_transaction(tx, true)
      local vsize = math.ceil(weight / 4)

      local mock_mempool = make_mock_mempool({
        [txid_hex] = {
          tx = tx,
          txid = txid,
          fee = 1000,
          vsize = vsize,
          weight = weight,
          size = size,
          time = os.time(),
        }
      })

      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      local request = '{"method":"getrawtransaction","params":["' .. txid_hex .. '", true],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      local spk = decoded.result.vout[1].scriptPubKey
      assert.equal("scripthash", spk.type)
      assert.is_string(spk.address)
      assert.truthy(spk.address:match("^3"))  -- mainnet P2SH starts with 3
    end)

    it("decodes P2WPKH scriptPubKey correctly", function()
      -- Create P2WPKH output
      local program = string.rep("\xef", 20)
      local script = "\x00\x14" .. program
      local tx = make_test_tx(nil, nil, 50000, script)
      local txid = validation.compute_txid(tx)
      local txid_hex = types.hash256_hex(txid)
      local weight = validation.get_tx_weight(tx)
      local size = #serialize.serialize_transaction(tx, true)
      local vsize = math.ceil(weight / 4)

      local mock_mempool = make_mock_mempool({
        [txid_hex] = {
          tx = tx,
          txid = txid,
          fee = 1000,
          vsize = vsize,
          weight = weight,
          size = size,
          time = os.time(),
        }
      })

      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      local request = '{"method":"getrawtransaction","params":["' .. txid_hex .. '", true],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      local spk = decoded.result.vout[1].scriptPubKey
      assert.equal("witness_v0_keyhash", spk.type)
      assert.is_string(spk.address)
      assert.truthy(spk.address:match("^bc1q"))  -- mainnet P2WPKH starts with bc1q
    end)

    it("decodes P2TR scriptPubKey correctly", function()
      -- Create P2TR output
      local program = string.rep("\x12", 32)
      local script = "\x51\x20" .. program
      local tx = make_test_tx(nil, nil, 50000, script)
      local txid = validation.compute_txid(tx)
      local txid_hex = types.hash256_hex(txid)
      local weight = validation.get_tx_weight(tx)
      local size = #serialize.serialize_transaction(tx, true)
      local vsize = math.ceil(weight / 4)

      local mock_mempool = make_mock_mempool({
        [txid_hex] = {
          tx = tx,
          txid = txid,
          fee = 1000,
          vsize = vsize,
          weight = weight,
          size = size,
          time = os.time(),
        }
      })

      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      local request = '{"method":"getrawtransaction","params":["' .. txid_hex .. '", true],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      local spk = decoded.result.vout[1].scriptPubKey
      assert.equal("witness_v1_taproot", spk.type)
      assert.is_string(spk.address)
      assert.truthy(spk.address:match("^bc1p"))  -- mainnet P2TR starts with bc1p
    end)

    it("returns error -5 when transaction not found", function()
      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = make_mock_mempool({})
      })

      local fake_txid = string.rep("a", 64)
      local request = '{"method":"getrawtransaction","params":["' .. fake_txid .. '"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.INVALID_ADDRESS, decoded.error.code)
      assert.truthy(decoded.error.message:match("mempool"))
    end)

    it("returns error for invalid txid format", function()
      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = make_mock_mempool({})
      })

      -- Too short
      local request = '{"method":"getrawtransaction","params":["abc"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.INVALID_PARAMS, decoded.error.code)
    end)

    it("returns error for invalid blockhash format", function()
      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = make_mock_mempool({})
      })

      local fake_txid = string.rep("a", 64)
      -- Invalid blockhash (too short)
      local request = '{"method":"getrawtransaction","params":["' .. fake_txid .. '", true, "invalid"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.INVALID_PARAMS, decoded.error.code)
    end)

    it("calculates vsize correctly (ceil(weight/4))", function()
      -- Create a segwit transaction
      local tx = {
        version = 2,
        inputs = {
          {
            prev_out = {
              hash = types.hash256(string.rep("\x01", 32)),
              index = 0
            },
            script_sig = "",  -- Empty for segwit
            sequence = 0xFFFFFFFE,
            witness = {"\x30" .. string.rep("\x00", 71), "\x02" .. string.rep("\x00", 32)}  -- mock witness
          }
        },
        outputs = {
          {
            value = 50000,
            script_pubkey = "\x00\x14" .. string.rep("\x00", 20)  -- P2WPKH
          }
        },
        locktime = 0,
        segwit = true
      }
      local txid = validation.compute_txid(tx)
      local txid_hex = types.hash256_hex(txid)
      local weight = validation.get_tx_weight(tx)
      local expected_vsize = math.ceil(weight / 4)
      local size = #serialize.serialize_transaction(tx, true)

      local mock_mempool = make_mock_mempool({
        [txid_hex] = {
          tx = tx,
          txid = txid,
          fee = 1000,
          vsize = expected_vsize,
          weight = weight,
          size = size,
          time = os.time(),
        }
      })

      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      local request = '{"method":"getrawtransaction","params":["' .. txid_hex .. '", true],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(expected_vsize, decoded.result.vsize)
      assert.equal(weight, decoded.result.weight)

      -- Verify vsize = ceil(weight / 4)
      assert.equal(math.ceil(weight / 4), decoded.result.vsize)
    end)

    it("includes witness data in txinwitness array", function()
      local witness_data = {"\x30" .. string.rep("\xab", 71), "\x02" .. string.rep("\xcd", 32)}
      local tx = {
        version = 2,
        inputs = {
          {
            prev_out = {
              hash = types.hash256(string.rep("\x01", 32)),
              index = 0
            },
            script_sig = "",
            sequence = 0xFFFFFFFE,
            witness = witness_data
          }
        },
        outputs = {
          {
            value = 50000,
            script_pubkey = "\x00\x14" .. string.rep("\x00", 20)
          }
        },
        locktime = 0,
        segwit = true
      }
      local txid = validation.compute_txid(tx)
      local txid_hex = types.hash256_hex(txid)
      local weight = validation.get_tx_weight(tx)
      local size = #serialize.serialize_transaction(tx, true)
      local vsize = math.ceil(weight / 4)

      local mock_mempool = make_mock_mempool({
        [txid_hex] = {
          tx = tx,
          txid = txid,
          fee = 1000,
          vsize = vsize,
          weight = weight,
          size = size,
          time = os.time(),
        }
      })

      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      local request = '{"method":"getrawtransaction","params":["' .. txid_hex .. '", true],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      -- Check witness data is present
      assert.is_table(decoded.result.vin[1].txinwitness)
      assert.equal(2, #decoded.result.vin[1].txinwitness)
      assert.equal(rpc.hex_encode(witness_data[1]), decoded.result.vin[1].txinwitness[1])
      assert.equal(rpc.hex_encode(witness_data[2]), decoded.result.vin[1].txinwitness[2])
    end)

    it("handles coinbase transactions correctly", function()
      local coinbase_msg = "test coinbase message"
      local tx = {
        version = 2,
        inputs = {
          {
            prev_out = {
              hash = types.hash256(string.rep("\x00", 32)),  -- null hash
              index = 0xFFFFFFFF  -- coinbase marker
            },
            script_sig = coinbase_msg,
            sequence = 0xFFFFFFFF,
            witness = {string.rep("\x00", 32)}  -- coinbase witness nonce
          }
        },
        outputs = {
          {
            value = 625000000,  -- 6.25 BTC
            script_pubkey = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"
          }
        },
        locktime = 0,
        segwit = true
      }
      local txid = validation.compute_txid(tx)
      local txid_hex = types.hash256_hex(txid)
      local weight = validation.get_tx_weight(tx)
      local size = #serialize.serialize_transaction(tx, true)
      local vsize = math.ceil(weight / 4)

      local mock_mempool = make_mock_mempool({
        [txid_hex] = {
          tx = tx,
          txid = txid,
          fee = 0,
          vsize = vsize,
          weight = weight,
          size = size,
          time = os.time(),
        }
      })

      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      local request = '{"method":"getrawtransaction","params":["' .. txid_hex .. '", true],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      -- Coinbase input should have 'coinbase' field instead of 'txid'
      assert.is_string(decoded.result.vin[1].coinbase)
      assert.equal(rpc.hex_encode(coinbase_msg), decoded.result.vin[1].coinbase)
      assert.is_nil(decoded.result.vin[1].txid)
    end)

    it("handles OP_RETURN (nulldata) outputs", function()
      -- Create OP_RETURN output
      local data = "Hello, Bitcoin!"
      local script = "\x6a" .. string.char(#data) .. data  -- OP_RETURN <push data>
      local tx = make_test_tx(nil, nil, 0, script)  -- 0 value for OP_RETURN
      local txid = validation.compute_txid(tx)
      local txid_hex = types.hash256_hex(txid)
      local weight = validation.get_tx_weight(tx)
      local size = #serialize.serialize_transaction(tx, true)
      local vsize = math.ceil(weight / 4)

      local mock_mempool = make_mock_mempool({
        [txid_hex] = {
          tx = tx,
          txid = txid,
          fee = 1000,
          vsize = vsize,
          weight = weight,
          size = size,
          time = os.time(),
        }
      })

      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      local request = '{"method":"getrawtransaction","params":["' .. txid_hex .. '", true],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      local spk = decoded.result.vout[1].scriptPubKey
      assert.equal("nulldata", spk.type)
      assert.is_nil(spk.address)  -- OP_RETURN has no address
    end)
  end)

  describe("getblockchaininfo (enhanced)", function()
    it("returns difficulty calculated from bits", function()
      -- Create a mock storage with a block header
      local mock_storage = {
        get_header = function(hash)
          return {
            version = 0x20000000,
            prev_hash = types.hash256(string.rep("\x00", 32)),
            merkle_root = types.hash256(string.rep("\xab", 32)),
            timestamp = os.time() - 60,  -- 1 minute ago
            bits = 0x1d00ffff,  -- minimum difficulty
            nonce = 0,
          }
        end,
      }

      local server = rpc.new({
        chain_state = {
          tip_height = 100,
          tip_hash = types.hash256(string.rep("\xab", 32)),
          header_tip_height = 100,
        },
        storage = mock_storage,
        network = consensus.networks.mainnet
      })

      local request = '{"method":"getblockchaininfo","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      -- At difficulty 1 (bits = 0x1d00ffff), difficulty should be ~1.0
      assert.is_number(decoded.result.difficulty)
      assert.is_true(decoded.result.difficulty >= 0.9)
      assert.is_true(decoded.result.difficulty <= 1.1)
    end)

    it("returns softforks table", function()
      local server = rpc.new({
        chain_state = {
          tip_height = 800000,
          tip_hash = types.hash256(string.rep("\xab", 32))
        },
        network = consensus.networks.mainnet
      })

      local request = '{"method":"getblockchaininfo","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      -- Should have softforks table
      assert.is_table(decoded.result.softforks)
    end)

    it("correctly identifies initial block download", function()
      -- Create a mock storage with an old block header
      local mock_storage = {
        get_header = function(hash)
          return {
            version = 0x20000000,
            prev_hash = types.hash256(string.rep("\x00", 32)),
            merkle_root = types.hash256(string.rep("\xab", 32)),
            timestamp = os.time() - (25 * 60 * 60),  -- 25 hours ago
            bits = 0x1d00ffff,
            nonce = 0,
          }
        end,
      }

      local server = rpc.new({
        chain_state = {
          tip_height = 100,
          tip_hash = types.hash256(string.rep("\xab", 32)),
        },
        storage = mock_storage,
        network = consensus.networks.mainnet
      })

      local request = '{"method":"getblockchaininfo","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_true(decoded.result.initialblockdownload)
    end)

    it("tracks separate header and block heights", function()
      local server = rpc.new({
        chain_state = {
          tip_height = 100,
          tip_hash = types.hash256(string.rep("\xab", 32)),
          header_tip_height = 150,  -- Headers are ahead
        },
        network = consensus.networks.mainnet
      })

      local request = '{"method":"getblockchaininfo","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(100, decoded.result.blocks)
      assert.equal(150, decoded.result.headers)
    end)
  end)

  describe("getblockhash (enhanced)", function()
    it("returns error for negative height", function()
      local server = rpc.new({
        chain_state = {tip_height = 100},
        storage = {
          get_hash_by_height = function(h) return types.hash256(string.rep("\xab", 32)) end
        },
        network = consensus.networks.mainnet
      })

      local request = '{"method":"getblockhash","params":[-1],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.INVALID_PARAMS, decoded.error.code)
      assert.truthy(decoded.error.message:match("out of range"))
    end)

    it("returns error for height beyond tip", function()
      local server = rpc.new({
        chain_state = {tip_height = 100},
        storage = {
          get_hash_by_height = function(h)
            if h <= 100 then
              return types.hash256(string.rep("\xab", 32))
            end
            return nil
          end
        },
        network = consensus.networks.mainnet
      })

      local request = '{"method":"getblockhash","params":[101],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.INVALID_PARAMS, decoded.error.code)
    end)

    it("returns correct hash for valid height", function()
      local expected_hash = types.hash256(string.rep("\xab", 32))
      local expected_hex = types.hash256_hex(expected_hash)

      local server = rpc.new({
        chain_state = {tip_height = 100},
        storage = {
          get_hash_by_height = function(h)
            if h == 50 then
              return expected_hash
            end
            return nil
          end
        },
        network = consensus.networks.mainnet
      })

      local request = '{"method":"getblockhash","params":[50],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(cjson.null, decoded.error)
      assert.equal(expected_hex, decoded.result)
    end)
  end)

  describe("getmempoolinfo (enhanced)", function()
    it("returns loaded field", function()
      local server = rpc.new({network = consensus.networks.mainnet})

      local request = '{"method":"getmempoolinfo","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_true(decoded.result.loaded)
    end)

    it("returns total_fee in BTC", function()
      -- Create a mock mempool with some transactions
      local mock_mempool = {
        entries = {
          ["aaaa"] = {fee = 10000},  -- 0.0001 BTC
          ["bbbb"] = {fee = 20000},  -- 0.0002 BTC
        },
        get_info = function()
          return {
            size = 2,
            bytes = 500,
            usage = 1000,
            maxmempool = 300 * 1024 * 1024,
            mempoolminfee = 1000,
          }
        end,
        min_relay_fee = 1000,
      }

      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      local request = '{"method":"getmempoolinfo","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      -- Total fee should be 30000 satoshis = 0.0003 BTC
      assert.is_number(decoded.result.total_fee)
      assert.equal(0.0003, decoded.result.total_fee)
    end)

    it("returns minrelaytxfee in BTC/kvB", function()
      local mock_mempool = {
        entries = {},
        get_info = function()
          return {
            size = 0,
            bytes = 0,
            usage = 0,
            maxmempool = 300 * 1024 * 1024,
            mempoolminfee = 1000,
          }
        end,
        min_relay_fee = 1000,  -- 1000 sat/kvB
      }

      local server = rpc.new({
        network = consensus.networks.mainnet,
        mempool = mock_mempool
      })

      local request = '{"method":"getmempoolinfo","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      -- 1000 sat/kvB = 0.00001 BTC/kvB
      assert.is_number(decoded.result.minrelaytxfee)
      assert.equal(0.00001, decoded.result.minrelaytxfee)
    end)
  end)

  describe("getblock (enhanced)", function()
    local serialize = require("lunarblock.serialize")
    local validation = require("lunarblock.validation")

    -- Create a simple test block
    local function make_test_block()
      local coinbase_tx = {
        version = 2,
        inputs = {{
          prev_out = {
            hash = types.hash256(string.rep("\x00", 32)),
            index = 0xFFFFFFFF
          },
          script_sig = "\x01\x00",  -- height 0
          sequence = 0xFFFFFFFF,
          witness = {string.rep("\x00", 32)}
        }},
        outputs = {{
          value = 5000000000,  -- 50 BTC
          script_pubkey = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"
        }},
        locktime = 0,
        segwit = true
      }

      local header = {
        version = 0x20000000,
        prev_hash = types.hash256(string.rep("\x00", 32)),
        merkle_root = types.hash256(string.rep("\xab", 32)),
        timestamp = 1700000000,
        bits = 0x1d00ffff,
        nonce = 12345,
      }

      return {
        header = header,
        transactions = {coinbase_tx}
      }
    end

    it("returns raw hex for verbosity 0", function()
      local block = make_test_block()
      local block_hash = types.hash256(string.rep("\xcd", 32))
      local block_hash_hex = types.hash256_hex(block_hash)

      local mock_storage = {
        get_block = function(hash)
          if hash.bytes == block_hash.bytes then
            return block
          end
          return nil
        end,
        iterator = function() return nil end,
      }

      local server = rpc.new({
        storage = mock_storage,
        network = consensus.networks.mainnet
      })

      local request = '{"method":"getblock","params":["' .. block_hash_hex .. '", 0],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(cjson.null, decoded.error)
      assert.is_string(decoded.result)
      -- Should be hex-encoded
      assert.truthy(decoded.result:match("^[0-9a-f]+$"))
    end)

    it("returns JSON with txids for verbosity 1", function()
      local block = make_test_block()
      local block_hash = types.hash256(string.rep("\xcd", 32))
      local block_hash_hex = types.hash256_hex(block_hash)

      local mock_storage = {
        get_block = function(hash)
          if hash.bytes == block_hash.bytes then
            return block
          end
          return nil
        end,
        get_header = function(hash) return block.header end,
        iterator = function() return nil end,
      }

      local server = rpc.new({
        storage = mock_storage,
        network = consensus.networks.mainnet
      })

      local request = '{"method":"getblock","params":["' .. block_hash_hex .. '", 1],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(cjson.null, decoded.error)
      assert.is_table(decoded.result)
      assert.equal(block_hash_hex, decoded.result.hash)
      assert.is_number(decoded.result.time)
      assert.equal(1700000000, decoded.result.time)
      assert.is_number(decoded.result.nonce)
      assert.equal(12345, decoded.result.nonce)
      assert.is_table(decoded.result.tx)
      assert.equal(1, #decoded.result.tx)
      -- tx should be just txid strings
      assert.is_string(decoded.result.tx[1])
      assert.equal(64, #decoded.result.tx[1])
    end)

    it("returns JSON with full transactions for verbosity 2", function()
      local block = make_test_block()
      local block_hash = types.hash256(string.rep("\xcd", 32))
      local block_hash_hex = types.hash256_hex(block_hash)

      local mock_storage = {
        get_block = function(hash)
          if hash.bytes == block_hash.bytes then
            return block
          end
          return nil
        end,
        get_header = function(hash) return block.header end,
        iterator = function() return nil end,
      }

      local server = rpc.new({
        storage = mock_storage,
        network = consensus.networks.mainnet
      })

      local request = '{"method":"getblock","params":["' .. block_hash_hex .. '", 2],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(cjson.null, decoded.error)
      assert.is_table(decoded.result)
      assert.is_table(decoded.result.tx)
      assert.equal(1, #decoded.result.tx)
      -- tx should be full transaction objects
      assert.is_table(decoded.result.tx[1])
      assert.is_string(decoded.result.tx[1].txid)
      assert.is_table(decoded.result.tx[1].vin)
      assert.is_table(decoded.result.tx[1].vout)
    end)

    it("calculates difficulty from bits", function()
      local block = make_test_block()
      local block_hash = types.hash256(string.rep("\xcd", 32))
      local block_hash_hex = types.hash256_hex(block_hash)

      local mock_storage = {
        get_block = function(hash)
          if hash.bytes == block_hash.bytes then
            return block
          end
          return nil
        end,
        get_header = function(hash) return block.header end,
        iterator = function() return nil end,
      }

      local server = rpc.new({
        storage = mock_storage,
        network = consensus.networks.mainnet
      })

      local request = '{"method":"getblock","params":["' .. block_hash_hex .. '", 1],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_number(decoded.result.difficulty)
      -- At minimum difficulty (0x1d00ffff), difficulty should be ~1.0
      assert.is_true(decoded.result.difficulty >= 0.9)
      assert.is_true(decoded.result.difficulty <= 1.1)
    end)

    it("returns error for invalid block hash", function()
      local server = rpc.new({
        storage = {get_block = function() return nil end},
        network = consensus.networks.mainnet
      })

      -- Invalid hash (too short)
      local request = '{"method":"getblock","params":["abc"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.INVALID_PARAMS, decoded.error.code)
    end)

    it("returns error for block not found", function()
      local mock_storage = {
        get_block = function() return nil end,
      }

      local server = rpc.new({
        storage = mock_storage,
        network = consensus.networks.mainnet
      })

      local fake_hash = string.rep("a", 64)
      local request = '{"method":"getblock","params":["' .. fake_hash .. '"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.INVALID_ADDRESS, decoded.error.code)
      assert.truthy(decoded.error.message:match("not found"))
    end)

    it("includes nTx count", function()
      local block = make_test_block()
      local block_hash = types.hash256(string.rep("\xcd", 32))
      local block_hash_hex = types.hash256_hex(block_hash)

      local mock_storage = {
        get_block = function(hash)
          if hash.bytes == block_hash.bytes then
            return block
          end
          return nil
        end,
        get_header = function(hash) return block.header end,
        iterator = function() return nil end,
      }

      local server = rpc.new({
        storage = mock_storage,
        network = consensus.networks.mainnet
      })

      local request = '{"method":"getblock","params":["' .. block_hash_hex .. '", 1],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(1, decoded.result.nTx)
    end)
  end)

  describe("batch JSON-RPC", function()
    it("processes array of requests and returns array of responses", function()
      local server = rpc.new({
        chain_state = {tip_height = 700000, tip_hash = types.hash256(string.rep("\xab", 32))},
        network = consensus.networks.mainnet
      })

      local batch_request = '[' ..
        '{"method":"getblockcount","params":[],"id":1},' ..
        '{"method":"getbestblockhash","params":[],"id":2}' ..
      ']'

      local response = server:handle_request(batch_request)
      local decoded = cjson.decode(response)

      assert.is_table(decoded)
      assert.equal(2, #decoded)

      -- Responses should be in order
      assert.equal(1, decoded[1].id)
      assert.equal(700000, decoded[1].result)
      assert.equal(cjson.null, decoded[1].error)

      assert.equal(2, decoded[2].id)
      assert.is_string(decoded[2].result)
      assert.equal(64, #decoded[2].result)
      assert.equal(cjson.null, decoded[2].error)
    end)

    it("handles mixed success and error in batch", function()
      local server = rpc.new({
        chain_state = {tip_height = 100},
        network = consensus.networks.mainnet
      })

      local batch_request = '[' ..
        '{"method":"getblockcount","params":[],"id":1},' ..
        '{"method":"unknownmethod","params":[],"id":2},' ..
        '{"method":"getconnectioncount","params":[],"id":3}' ..
      ']'

      local response = server:handle_request(batch_request)
      local decoded = cjson.decode(response)

      assert.equal(3, #decoded)

      -- First request succeeds
      assert.equal(1, decoded[1].id)
      assert.equal(100, decoded[1].result)
      assert.equal(cjson.null, decoded[1].error)

      -- Second request fails
      assert.equal(2, decoded[2].id)
      assert.equal(cjson.null, decoded[2].result)
      assert.is_not_nil(decoded[2].error)
      assert.equal(rpc.ERROR.METHOD_NOT_FOUND, decoded[2].error.code)

      -- Third request succeeds
      assert.equal(3, decoded[3].id)
      assert.equal(0, decoded[3].result)
      assert.equal(cjson.null, decoded[3].error)
    end)

    it("handles notifications (no id) in batch - no response included", function()
      local server = rpc.new({
        chain_state = {tip_height = 100},
        network = consensus.networks.mainnet
      })

      -- First request is a notification (no id), second has id
      local batch_request = '[' ..
        '{"method":"getblockcount","params":[]},' ..
        '{"method":"getblockcount","params":[],"id":2}' ..
      ']'

      local response = server:handle_request(batch_request)
      local decoded = cjson.decode(response)

      -- Only one response (for the request with id)
      assert.equal(1, #decoded)
      assert.equal(2, decoded[1].id)
      assert.equal(100, decoded[1].result)
    end)

    it("returns 204 No Content for all-notification batch", function()
      local server = rpc.new({
        chain_state = {tip_height = 100},
        network = consensus.networks.mainnet
      })

      -- All notifications (no id)
      local batch_request = '[' ..
        '{"method":"getblockcount","params":[]},' ..
        '{"method":"getconnectioncount","params":[]}' ..
      ']'

      local response, status = server:handle_request(batch_request)

      -- Should return empty body and 204 status
      assert.equal("", response)
      assert.equal(204, status)
    end)

    it("maintains request order in responses", function()
      local server = rpc.new({
        chain_state = {tip_height = 500},
        network = consensus.networks.mainnet
      })

      -- Use string IDs to verify order
      local batch_request = '[' ..
        '{"method":"getblockcount","params":[],"id":"third"},' ..
        '{"method":"getconnectioncount","params":[],"id":"first"},' ..
        '{"method":"help","params":[],"id":"second"}' ..
      ']'

      local response = server:handle_request(batch_request)
      local decoded = cjson.decode(response)

      assert.equal(3, #decoded)
      assert.equal("third", decoded[1].id)
      assert.equal("first", decoded[2].id)
      assert.equal("second", decoded[3].id)
    end)

    it("returns error for batch exceeding max size", function()
      local server = rpc.new({
        chain_state = {tip_height = 100},
        network = consensus.networks.mainnet
      })

      -- Build a batch that exceeds 1000 requests
      local requests = {}
      for i = 1, 1001 do
        requests[i] = '{"method":"getblockcount","params":[],"id":' .. i .. '}'
      end
      local batch_request = '[' .. table.concat(requests, ',') .. ']'

      local response, status = server:handle_request(batch_request)
      local decoded = cjson.decode(response)

      assert.equal(400, status)
      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.INVALID_REQUEST, decoded.error.code)
      assert.truthy(decoded.error.message:match("1000"))
    end)

    it("handles exactly max batch size", function()
      local server = rpc.new({
        chain_state = {tip_height = 100},
        network = consensus.networks.mainnet
      })

      -- Build a batch with exactly 1000 requests
      local requests = {}
      for i = 1, 1000 do
        requests[i] = '{"method":"getblockcount","params":[],"id":' .. i .. '}'
      end
      local batch_request = '[' .. table.concat(requests, ',') .. ']'

      local response, status = server:handle_request(batch_request)
      local decoded = cjson.decode(response)

      -- Should succeed
      assert.is_nil(status)  -- No status override means 200
      assert.equal(1000, #decoded)
    end)

    it("handles invalid request objects in batch", function()
      local server = rpc.new({
        chain_state = {tip_height = 100},
        network = consensus.networks.mainnet
      })

      -- Include an invalid element (string instead of object)
      local batch_request = '[' ..
        '{"method":"getblockcount","params":[],"id":1},' ..
        '"not an object",' ..
        '{"method":"getblockcount","params":[],"id":3}' ..
      ']'

      local response = server:handle_request(batch_request)
      local decoded = cjson.decode(response)

      assert.equal(3, #decoded)

      -- First succeeds
      assert.equal(1, decoded[1].id)
      assert.equal(100, decoded[1].result)

      -- Second is invalid
      assert.equal(cjson.null, decoded[2].id)
      assert.is_not_nil(decoded[2].error)
      assert.equal(rpc.ERROR.INVALID_REQUEST, decoded[2].error.code)

      -- Third succeeds
      assert.equal(3, decoded[3].id)
      assert.equal(100, decoded[3].result)
    end)

    it("handles empty batch", function()
      local server = rpc.new({
        chain_state = {tip_height = 100},
        network = consensus.networks.mainnet
      })

      local batch_request = '[]'
      local response = server:handle_request(batch_request)
      local decoded = cjson.decode(response)

      -- Empty batch returns empty array (not 204 - Bitcoin Core compatibility)
      assert.is_table(decoded)
      assert.equal(0, #decoded)
    end)

    it("handles null id correctly", function()
      local server = rpc.new({
        chain_state = {tip_height = 100},
        network = consensus.networks.mainnet
      })

      -- null id is NOT a notification - it should return a response
      local batch_request = '[' ..
        '{"method":"getblockcount","params":[],"id":null}' ..
      ']'

      local response = server:handle_request(batch_request)
      local decoded = cjson.decode(response)

      -- Should include response with null id
      assert.equal(1, #decoded)
      assert.equal(cjson.null, decoded[1].id)
      assert.equal(100, decoded[1].result)
    end)

    it("singleton notification returns 204 No Content", function()
      local server = rpc.new({
        chain_state = {tip_height = 100},
        network = consensus.networks.mainnet
      })

      -- Singleton notification (no id field)
      local request = '{"method":"getblockcount","params":[]}'
      local response, status = server:handle_request(request)

      assert.equal("", response)
      assert.equal(204, status)
    end)

    it("preserves various id types in responses", function()
      local server = rpc.new({
        chain_state = {tip_height = 100},
        network = consensus.networks.mainnet
      })

      local batch_request = '[' ..
        '{"method":"getblockcount","params":[],"id":42},' ..
        '{"method":"getblockcount","params":[],"id":"string-id"},' ..
        '{"method":"getblockcount","params":[],"id":null}' ..
      ']'

      local response = server:handle_request(batch_request)
      local decoded = cjson.decode(response)

      assert.equal(3, #decoded)
      assert.equal(42, decoded[1].id)
      assert.equal("string-id", decoded[2].id)
      assert.equal(cjson.null, decoded[3].id)
    end)
  end)

  describe("invalidateblock", function()
    local storage_mod = require("lunarblock.storage")
    local utxo = require("lunarblock.utxo")
    local validation = require("lunarblock.validation")
    local script = require("lunarblock.script")

    -- Helper to create a simple coinbase transaction
    local function make_coinbase_tx(height, value, script_pubkey)
      local coinbase_sig = string.char(1, height % 256)
      return types.transaction(
        1,
        {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), coinbase_sig, 0xFFFFFFFF)},
        {types.txout(value, script_pubkey)},
        0
      )
    end

    -- Helper to create a simple block
    local function make_block(height, transactions, prev_hash)
      local header = types.block_header(
        1,
        prev_hash or types.hash256_zero(),
        types.hash256_zero(),
        os.time() + height,
        consensus.networks.regtest.pow_limit_bits,
        0
      )
      return types.block(header, transactions)
    end

    it("rejects invalid block hash format", function()
      local server = rpc.new({
        chain_state = {tip_height = 100},
        network = consensus.networks.mainnet
      })

      local request = '{"method":"invalidateblock","params":["notahash"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.INVALID_PARAMS, decoded.error.code)
    end)

    it("returns error when chain_state is not available", function()
      local server = rpc.new({
        network = consensus.networks.mainnet
      })

      local hash = string.rep("ab", 32)
      local request = '{"method":"invalidateblock","params":["' .. hash .. '"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.MISC_ERROR, decoded.error.code)
    end)

    it("returns error for non-existent block", function()
      local tmp_path = "/tmp/lunarblock_rpc_invalidate_test_" .. os.time() .. "_" .. math.random(1000000)
      local db = storage_mod.open(tmp_path)
      local chain_state = utxo.new_chain_state(db, consensus.networks.regtest)
      chain_state:init()

      local server = rpc.new({
        chain_state = chain_state,
        storage = db,
        network = consensus.networks.regtest
      })

      local hash = string.rep("ff", 32)
      local request = '{"method":"invalidateblock","params":["' .. hash .. '"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)

      db.close()
    end)

    it("successfully invalidates a block", function()
      local tmp_path = "/tmp/lunarblock_rpc_invalidate_test2_" .. os.time() .. "_" .. math.random(1000000)
      local db = storage_mod.open(tmp_path)
      local chain_state = utxo.new_chain_state(db, consensus.networks.regtest)
      chain_state:init()

      local pubkey_hash = string.rep("\x11", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      -- Connect genesis block
      local coinbase0 = make_coinbase_tx(0, 5000000000, script_pubkey)
      local block0 = make_block(0, {coinbase0})
      local block_hash0 = validation.compute_block_hash(block0.header)
      db.put_header(block_hash0, block0.header)
      db.put_block(block_hash0, block0)
      chain_state:connect_block(block0, 0, block_hash0)

      -- Connect another block
      local coinbase1 = make_coinbase_tx(1, 5000000000, script_pubkey)
      local block1 = make_block(1, {coinbase1}, block_hash0)
      local block_hash1 = validation.compute_block_hash(block1.header)
      db.put_header(block_hash1, block1.header)
      db.put_block(block_hash1, block1)
      chain_state:connect_block(block1, 1, block_hash1)

      local server = rpc.new({
        chain_state = chain_state,
        storage = db,
        network = consensus.networks.regtest
      })

      -- Invalidate block 1
      local hash_hex = types.hash256_hex(block_hash1)
      local request = '{"method":"invalidateblock","params":["' .. hash_hex .. '"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(cjson.null, decoded.error)
      assert.equal(cjson.null, decoded.result)  -- Returns null on success

      -- Verify chain rolled back
      assert.equal(0, chain_state.tip_height)

      db.close()
    end)
  end)

  describe("reconsiderblock", function()
    local storage_mod = require("lunarblock.storage")
    local utxo = require("lunarblock.utxo")
    local validation = require("lunarblock.validation")
    local script = require("lunarblock.script")

    -- Helper to create a simple coinbase transaction
    local function make_coinbase_tx(height, value, script_pubkey)
      local coinbase_sig = string.char(1, height % 256)
      return types.transaction(
        1,
        {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), coinbase_sig, 0xFFFFFFFF)},
        {types.txout(value, script_pubkey)},
        0
      )
    end

    -- Helper to create a simple block
    local function make_block(height, transactions, prev_hash)
      local header = types.block_header(
        1,
        prev_hash or types.hash256_zero(),
        types.hash256_zero(),
        os.time() + height,
        consensus.networks.regtest.pow_limit_bits,
        0
      )
      return types.block(header, transactions)
    end

    it("rejects invalid block hash format", function()
      local server = rpc.new({
        chain_state = {tip_height = 100},
        network = consensus.networks.mainnet
      })

      local request = '{"method":"reconsiderblock","params":["short"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.INVALID_PARAMS, decoded.error.code)
    end)

    it("returns error when chain_state is not available", function()
      local server = rpc.new({
        network = consensus.networks.mainnet
      })

      local hash = string.rep("cd", 32)
      local request = '{"method":"reconsiderblock","params":["' .. hash .. '"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
      assert.equal(rpc.ERROR.MISC_ERROR, decoded.error.code)
    end)

    it("successfully reconsiders a previously invalidated block", function()
      local tmp_path = "/tmp/lunarblock_rpc_reconsider_test_" .. os.time() .. "_" .. math.random(1000000)
      local db = storage_mod.open(tmp_path)
      local chain_state = utxo.new_chain_state(db, consensus.networks.regtest)
      chain_state:init()

      local pubkey_hash = string.rep("\x22", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      -- Connect two blocks
      local coinbase0 = make_coinbase_tx(0, 5000000000, script_pubkey)
      local block0 = make_block(0, {coinbase0})
      local block_hash0 = validation.compute_block_hash(block0.header)
      db.put_header(block_hash0, block0.header)
      db.put_block(block_hash0, block0)
      chain_state:connect_block(block0, 0, block_hash0)

      local coinbase1 = make_coinbase_tx(1, 5000000000, script_pubkey)
      local block1 = make_block(1, {coinbase1}, block_hash0)
      local block_hash1 = validation.compute_block_hash(block1.header)
      db.put_header(block_hash1, block1.header)
      db.put_block(block_hash1, block1)
      chain_state:connect_block(block1, 1, block_hash1)

      -- Invalidate block 1
      chain_state:invalidate_block(block_hash1)
      assert.is_true(chain_state:is_block_invalid(block_hash1))

      local server = rpc.new({
        chain_state = chain_state,
        storage = db,
        network = consensus.networks.regtest
      })

      -- Reconsider block 1
      local hash_hex = types.hash256_hex(block_hash1)
      local request = '{"method":"reconsiderblock","params":["' .. hash_hex .. '"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(cjson.null, decoded.error)
      assert.equal(cjson.null, decoded.result)

      -- Block should no longer be invalid
      assert.is_false(chain_state:is_block_invalid(block_hash1))

      db.close()
    end)
  end)

  describe("getdeploymentinfo", function()
    it("returns non-empty deployments on regtest with segwit and taproot", function()
      local server = rpc.new({
        chain_state = {
          tip_height = 150,
          tip_hash = types.hash256(string.rep("\xab", 32)),
        },
        network = consensus.networks.regtest,
      })

      local request = '{"method":"getdeploymentinfo","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(cjson.null, decoded.error)
      local deps = decoded.result.deployments
      assert.is_table(deps)

      -- Must have segwit
      assert.is_table(deps.segwit)
      assert.equal("buried", deps.segwit.type)
      assert.is_boolean(deps.segwit.active)
      assert.is_number(deps.segwit.height)
      assert.is_number(deps.segwit.min_activation_height)

      -- Must have taproot
      assert.is_table(deps.taproot)
      assert.equal("buried", deps.taproot.type)
      assert.is_boolean(deps.taproot.active)

      -- On regtest height 0, both should be active at tip_height 150
      assert.is_true(deps.segwit.active)
      assert.is_true(deps.taproot.active)
    end)

    it("returns inactive deployments when tip is below activation height", function()
      local server = rpc.new({
        chain_state = {
          tip_height = 100,
          tip_hash = types.hash256(string.rep("\xcd", 32)),
        },
        network = consensus.networks.mainnet,
      })

      local request = '{"method":"getdeploymentinfo","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(cjson.null, decoded.error)
      local deps = decoded.result.deployments

      -- segwit activates at height 481824 on mainnet; tip is 100
      assert.is_table(deps.segwit)
      assert.is_false(deps.segwit.active)

      -- taproot activates at height 709632 on mainnet; tip is 100
      assert.is_table(deps.taproot)
      assert.is_false(deps.taproot.active)
    end)

    it("returns active deployments when tip is at or above activation height", function()
      local server = rpc.new({
        chain_state = {
          tip_height = 750000,
          tip_hash = types.hash256(string.rep("\xef", 32)),
        },
        network = consensus.networks.mainnet,
      })

      local request = '{"method":"getdeploymentinfo","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(cjson.null, decoded.error)
      local deps = decoded.result.deployments

      -- Both segwit (481824) and taproot (709632) should be active at 750000
      assert.is_true(deps.segwit.active)
      assert.is_true(deps.taproot.active)

      -- bip34, bip65, bip66, csv all active well below 750000
      assert.is_true(deps.bip34.active)
      assert.is_true(deps.bip65.active)
      assert.is_true(deps.bip66.active)
      assert.is_true(deps.csv.active)
    end)

    it("returns hash and height in result", function()
      local server = rpc.new({
        chain_state = {
          tip_height = 42,
          tip_hash = types.hash256(string.rep("\x11", 32)),
        },
        network = consensus.networks.regtest,
      })

      local request = '{"method":"getdeploymentinfo","params":[],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.equal(cjson.null, decoded.error)
      assert.is_number(decoded.result.height)
      assert.equal(42, decoded.result.height)
      assert.is_string(decoded.result.hash)
      assert.equal(64, #decoded.result.hash)
    end)

    it("errors on invalid blockhash param", function()
      local server = rpc.new({
        chain_state = {tip_height = 10},
        network = consensus.networks.regtest,
      })

      local request = '{"method":"getdeploymentinfo","params":["notahash"],"id":1}'
      local response = server:handle_request(request)
      local decoded = cjson.decode(response)

      assert.is_not_nil(decoded.error)
    end)
  end)

end)
