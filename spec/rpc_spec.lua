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

end)
