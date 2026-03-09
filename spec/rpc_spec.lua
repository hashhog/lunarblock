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
    end)
  end)

end)
