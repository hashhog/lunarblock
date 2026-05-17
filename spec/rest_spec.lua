local rest = require("lunarblock.rest")
local types = require("lunarblock.types")
local consensus = require("lunarblock.consensus")
local serialize = require("lunarblock.serialize")
local validation = require("lunarblock.validation")
local cjson = require("cjson")

describe("rest", function()

  --------------------------------------------------------------------------------
  -- Helper Functions
  --------------------------------------------------------------------------------

  local function hex_encode(data)
    local hex = {}
    for i = 1, #data do
      hex[i] = string.format("%02x", data:byte(i))
    end
    return table.concat(hex)
  end

  local function hex_decode(hex_str)
    local bytes = {}
    for i = 1, #hex_str, 2 do
      bytes[#bytes + 1] = string.char(tonumber(hex_str:sub(i, i + 1), 16))
    end
    return table.concat(bytes)
  end

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

  -- Create a simple test transaction
  local function make_test_tx(prev_hash, prev_index, value, output_script)
    prev_hash = prev_hash or string.rep("\x01", 32)
    prev_index = prev_index or 0
    value = value or 50000
    output_script = output_script or "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"
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

  -- Parse HTTP response
  local function parse_http_response(response)
    local status = tonumber(response:match("HTTP/1.1 (%d+)"))
    local content_type = response:match("[Cc]ontent%-[Tt]ype:%s*([^\r\n]+)")
    local body_start = response:find("\r\n\r\n")
    local body = body_start and response:sub(body_start + 4) or ""
    return status, content_type, body
  end

  --------------------------------------------------------------------------------
  -- REST Server Tests
  --------------------------------------------------------------------------------

  describe("new", function()
    it("creates server with default settings", function()
      local server = rest.new({})
      assert.is_not_nil(server)
      assert.equal("127.0.0.1", server.host)
      assert.equal(8080, server.port)
    end)

    it("accepts custom port", function()
      local server = rest.new({rest_port = 9090})
      assert.equal(9090, server.port)
    end)
  end)

  describe("/rest/block endpoint", function()
    it("returns 400 for invalid hash", function()
      local server = rest.new({})
      local response = server:route("GET", "/rest/block/invalid.json")
      local status = parse_http_response(response)
      assert.equal(400, status)
    end)

    it("returns 404 for block not found", function()
      local mock_storage = {
        get_block = function() return nil end,
      }
      local server = rest.new({storage = mock_storage})
      local fake_hash = string.rep("a", 64)
      local response = server:route("GET", "/rest/block/" .. fake_hash .. ".json")
      local status = parse_http_response(response)
      assert.equal(404, status)
    end)

    it("returns JSON for valid block", function()
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
        get_header = function() return block.header end,
        iterator = function() return nil end,
      }

      local server = rest.new({
        storage = mock_storage,
        network = consensus.networks.mainnet
      })

      local response = server:route("GET", "/rest/block/" .. block_hash_hex .. ".json")
      local status, content_type, body = parse_http_response(response)

      assert.equal(200, status)
      assert.truthy(content_type:match("application/json"))

      local decoded = cjson.decode(body)
      assert.equal(block_hash_hex, decoded.hash)
      assert.is_number(decoded.time)
      assert.equal(1700000000, decoded.time)
      assert.is_table(decoded.tx)
      assert.equal(1, #decoded.tx)
    end)

    it("returns raw binary for .bin format", function()
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
        get_header = function() return block.header end,
        iterator = function() return nil end,
      }

      local server = rest.new({storage = mock_storage})

      local response = server:route("GET", "/rest/block/" .. block_hash_hex .. ".bin")
      local status, content_type = parse_http_response(response)

      assert.equal(200, status)
      assert.truthy(content_type:match("octet%-stream"))
    end)

    it("returns hex for .hex format", function()
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
        get_header = function() return block.header end,
        iterator = function() return nil end,
      }

      local server = rest.new({storage = mock_storage})

      local response = server:route("GET", "/rest/block/" .. block_hash_hex .. ".hex")
      local status, content_type, body = parse_http_response(response)

      assert.equal(200, status)
      assert.truthy(content_type:match("text/plain"))
      -- Body should be hex
      assert.truthy(body:match("^[0-9a-f]+"))
    end)

    it("returns txids only for notxdetails endpoint", function()
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
        get_header = function() return block.header end,
        iterator = function() return nil end,
      }

      local server = rest.new({storage = mock_storage, network = consensus.networks.mainnet})

      local response = server:route("GET", "/rest/block/notxdetails/" .. block_hash_hex .. ".json")
      local status, _, body = parse_http_response(response)

      assert.equal(200, status)

      local decoded = cjson.decode(body)
      assert.is_table(decoded.tx)
      assert.equal(1, #decoded.tx)
      -- tx should be just txid strings, not objects
      assert.is_string(decoded.tx[1])
      assert.equal(64, #decoded.tx[1])
    end)
  end)

  describe("/rest/tx endpoint", function()
    it("returns 400 for invalid txid", function()
      local server = rest.new({})
      local response = server:route("GET", "/rest/tx/invalid.json")
      local status = parse_http_response(response)
      assert.equal(400, status)
    end)

    it("returns 404 for transaction not found", function()
      local mock_mempool = {
        get_entry = function() return nil end,
      }
      local server = rest.new({mempool = mock_mempool})
      local fake_txid = string.rep("a", 64)
      local response = server:route("GET", "/rest/tx/" .. fake_txid .. ".json")
      local status = parse_http_response(response)
      assert.equal(404, status)
    end)

    it("returns JSON for mempool transaction", function()
      local tx = make_test_tx()
      local txid = validation.compute_txid(tx)
      local txid_hex = types.hash256_hex(txid)

      local mock_mempool = {
        get_entry = function(id)
          if id == txid_hex then
            return {tx = tx}
          end
          return nil
        end,
      }

      local server = rest.new({
        mempool = mock_mempool,
        network = consensus.networks.mainnet
      })

      local response = server:route("GET", "/rest/tx/" .. txid_hex .. ".json")
      local status, content_type, body = parse_http_response(response)

      assert.equal(200, status)
      assert.truthy(content_type:match("application/json"))

      local decoded = cjson.decode(body)
      assert.equal(txid_hex, decoded.txid)
      assert.is_table(decoded.vin)
      assert.is_table(decoded.vout)
    end)

    it("returns raw hex for .hex format", function()
      local tx = make_test_tx()
      local txid = validation.compute_txid(tx)
      local txid_hex = types.hash256_hex(txid)

      local mock_mempool = {
        get_entry = function(id)
          if id == txid_hex then
            return {tx = tx}
          end
          return nil
        end,
      }

      local server = rest.new({mempool = mock_mempool})

      local response = server:route("GET", "/rest/tx/" .. txid_hex .. ".hex")
      local status, content_type, body = parse_http_response(response)

      assert.equal(200, status)
      assert.truthy(content_type:match("text/plain"))
      assert.truthy(body:match("^[0-9a-f]+"))
    end)
  end)

  describe("/rest/headers endpoint", function()
    it("returns 400 for invalid count", function()
      local server = rest.new({})
      local response = server:route("GET", "/rest/headers/invalid/" .. string.rep("a", 64) .. ".json")
      local status = parse_http_response(response)
      assert.equal(400, status)
    end)

    it("returns 400 for count out of range", function()
      local server = rest.new({})
      local response = server:route("GET", "/rest/headers/3000/" .. string.rep("a", 64) .. ".json")
      local status, _, body = parse_http_response(response)
      assert.equal(400, status)
      assert.truthy(body:match("out of acceptable range"))
    end)

    it("returns 404 for block not found", function()
      local mock_storage = {
        get_header = function() return nil end,
      }
      local server = rest.new({storage = mock_storage})
      local response = server:route("GET", "/rest/headers/5/" .. string.rep("a", 64) .. ".json")
      local status = parse_http_response(response)
      assert.equal(404, status)
    end)

    it("returns JSON headers", function()
      local block = make_test_block()
      local block_hash = types.hash256(string.rep("\xcd", 32))
      local block_hash_hex = types.hash256_hex(block_hash)

      local mock_storage = {
        get_header = function(hash)
          if hash.bytes == block_hash.bytes then
            return block.header
          end
          return nil
        end,
        iterator = function() return nil end,
      }

      local server = rest.new({storage = mock_storage})

      local response = server:route("GET", "/rest/headers/1/" .. block_hash_hex .. ".json")
      local status, content_type, body = parse_http_response(response)

      assert.equal(200, status)
      assert.truthy(content_type:match("application/json"))

      local decoded = cjson.decode(body)
      assert.is_table(decoded)
      assert.equal(1, #decoded)
      assert.is_number(decoded[1].time)
    end)
  end)

  describe("/rest/blockhashbyheight endpoint", function()
    it("returns 400 for invalid height", function()
      local server = rest.new({})
      local response = server:route("GET", "/rest/blockhashbyheight/invalid.json")
      local status = parse_http_response(response)
      assert.equal(400, status)
    end)

    it("returns 404 for height beyond tip", function()
      local mock_storage = {
        get_hash_by_height = function() return nil end,
      }
      local server = rest.new({
        storage = mock_storage,
        chain_state = {tip_height = 10}
      })
      local response = server:route("GET", "/rest/blockhashbyheight/100.json")
      local status = parse_http_response(response)
      assert.equal(404, status)
    end)

    it("returns block hash for valid height", function()
      local expected_hash = types.hash256(string.rep("\xab", 32))

      local mock_storage = {
        get_hash_by_height = function(h)
          if h == 5 then
            return expected_hash
          end
          return nil
        end,
      }

      local server = rest.new({
        storage = mock_storage,
        chain_state = {tip_height = 100}
      })

      local response = server:route("GET", "/rest/blockhashbyheight/5.json")
      local status, content_type, body = parse_http_response(response)

      assert.equal(200, status)
      assert.truthy(content_type:match("application/json"))

      local decoded = cjson.decode(body)
      assert.equal(types.hash256_hex(expected_hash), decoded.blockhash)
    end)

    it("returns hex for .hex format", function()
      local expected_hash = types.hash256(string.rep("\xab", 32))

      local mock_storage = {
        get_hash_by_height = function(h)
          if h == 5 then
            return expected_hash
          end
          return nil
        end,
      }

      local server = rest.new({
        storage = mock_storage,
        chain_state = {tip_height = 100}
      })

      local response = server:route("GET", "/rest/blockhashbyheight/5.hex")
      local status, content_type, body = parse_http_response(response)

      assert.equal(200, status)
      assert.truthy(content_type:match("text/plain"))
      assert.equal(types.hash256_hex(expected_hash), body:gsub("%s+", ""))
    end)
  end)

  describe("/rest/getutxos endpoint", function()
    it("returns 400 for empty request", function()
      local server = rest.new({storage = {}})
      local response = server:route("GET", "/rest/getutxos/.json")
      local status = parse_http_response(response)
      assert.equal(400, status)
    end)

    it("returns 400 for too many outpoints", function()
      local server = rest.new({storage = {}})
      -- Build path with 20 outpoints (max is 15)
      local outpoints = {}
      for i = 1, 20 do
        outpoints[#outpoints + 1] = string.rep("a", 64) .. "-" .. i
      end
      local response = server:route("GET", "/rest/getutxos/" .. table.concat(outpoints, "/") .. ".json")
      local status, _, body = parse_http_response(response)
      assert.equal(400, status)
      assert.truthy(body:match("max outpoints exceeded"))
    end)

    it("returns JSON with bitmap and utxos", function()
      local mock_storage = {
        get = function() return nil end,  -- No UTXOs found
      }

      local server = rest.new({
        storage = mock_storage,
        chain_state = {
          tip_height = 100,
          tip_hash = types.hash256(string.rep("\xab", 32))
        }
      })

      local txid = string.rep("a", 64)
      local response = server:route("GET", "/rest/getutxos/" .. txid .. "-0.json")
      local status, content_type, body = parse_http_response(response)

      assert.equal(200, status)
      assert.truthy(content_type:match("application/json"))

      local decoded = cjson.decode(body)
      assert.is_number(decoded.chainHeight)
      assert.is_string(decoded.chaintipHash)
      assert.is_string(decoded.bitmap)
      assert.is_table(decoded.utxos)
    end)

    it("handles checkmempool prefix", function()
      local mock_storage = {
        get = function() return nil end,
      }
      local mock_mempool = {
        entries = {},
      }

      local server = rest.new({
        storage = mock_storage,
        mempool = mock_mempool,
        chain_state = {
          tip_height = 100,
          tip_hash = types.hash256(string.rep("\xab", 32))
        }
      })

      local txid = string.rep("a", 64)
      local response = server:route("GET", "/rest/getutxos/checkmempool/" .. txid .. "-0.json")
      local status = parse_http_response(response)

      assert.equal(200, status)
    end)
  end)

  describe("/rest/mempool/contents endpoint", function()
    it("returns 404 when mempool not available", function()
      local server = rest.new({})
      local response = server:route("GET", "/rest/mempool/contents.json")
      local status = parse_http_response(response)
      assert.equal(404, status)
    end)

    it("returns JSON mempool contents", function()
      local mock_mempool = {
        entries = {
          ["aaaa"] = {
            vsize = 200,
            weight = 800,
            fee = 10000,
            time = 1700000000,
            height = 100,
            descendant_count = 1,
            descendant_size = 200,
            ancestor_count = 1,
            ancestor_size = 200,
          }
        }
      }

      local server = rest.new({mempool = mock_mempool})

      local response = server:route("GET", "/rest/mempool/contents.json")
      local status, content_type, body = parse_http_response(response)

      assert.equal(200, status)
      assert.truthy(content_type:match("application/json"))

      local decoded = cjson.decode(body)
      assert.is_table(decoded)
      assert.is_not_nil(decoded["aaaa"])
      assert.is_number(decoded["aaaa"].vsize)
    end)

    it("returns non-verbose list when verbose=false", function()
      local mock_mempool = {
        entries = {
          ["aaaa"] = {vsize = 200, weight = 800, fee = 10000, time = 1700000000, height = 100},
          ["bbbb"] = {vsize = 300, weight = 1200, fee = 20000, time = 1700000001, height = 100},
        }
      }

      local server = rest.new({mempool = mock_mempool})

      local response = server:route("GET", "/rest/mempool/contents.json?verbose=false")
      local status, _, body = parse_http_response(response)

      assert.equal(200, status)

      local decoded = cjson.decode(body)
      assert.is_table(decoded)
      -- Should be an array of txids, not objects
      assert.equal(2, #decoded)
    end)
  end)

  describe("/rest/mempool/info endpoint", function()
    it("returns 404 when mempool not available", function()
      local server = rest.new({})
      local response = server:route("GET", "/rest/mempool/info.json")
      local status = parse_http_response(response)
      assert.equal(404, status)
    end)

    it("returns JSON mempool info", function()
      local mock_mempool = {
        entries = {
          ["aaaa"] = {fee = 10000},
          ["bbbb"] = {fee = 20000},
        },
        min_relay_fee = 1000,
        get_info = function()
          return {
            size = 2,
            bytes = 500,
            usage = 1000,
            maxmempool = 300 * 1024 * 1024,
            mempoolminfee = 1000,
          }
        end,
      }

      local server = rest.new({mempool = mock_mempool})

      local response = server:route("GET", "/rest/mempool/info.json")
      local status, content_type, body = parse_http_response(response)

      assert.equal(200, status)
      assert.truthy(content_type:match("application/json"))

      local decoded = cjson.decode(body)
      assert.is_true(decoded.loaded)
      assert.equal(2, decoded.size)
      assert.is_number(decoded.total_fee)
      assert.is_number(decoded.mempoolminfee)
      assert.is_number(decoded.minrelaytxfee)
    end)
  end)

  describe("error handling", function()
    it("returns 400 for non-GET methods", function()
      local server = rest.new({})
      local response = server:route("POST", "/rest/block/abc.json")
      local status = parse_http_response(response)
      assert.equal(400, status)
    end)

    it("returns 404 for unknown paths", function()
      local server = rest.new({})
      local response = server:route("GET", "/rest/unknown")
      local status = parse_http_response(response)
      assert.equal(404, status)
    end)

    it("returns 400 for invalid format suffix", function()
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

      local server = rest.new({storage = mock_storage})

      local response = server:route("GET", "/rest/block/" .. block_hash_hex .. ".invalid")
      local status, _, body = parse_http_response(response)
      assert.equal(400, status)
      assert.truthy(body:match("format not found"))
    end)
  end)

  describe("constants", function()
    it("defines max outpoints limit", function()
      assert.equal(15, rest.MAX_GETUTXOS_OUTPOINTS)
    end)

    it("defines max headers count", function()
      assert.equal(2000, rest.MAX_HEADERS_COUNT)
    end)

    it("defines default headers count for ?count= form", function()
      assert.equal(5, rest.DEFAULT_HEADERS_COUNT)
    end)

    it("defines format types", function()
      assert.equal("json", rest.FORMAT.JSON)
      assert.equal("bin", rest.FORMAT.BIN)
      assert.equal("hex", rest.FORMAT.HEX)
    end)

    it("knows the BIP-157 basic filter type", function()
      assert.equal(0, rest.FILTER_TYPE_BY_NAME.basic)
    end)
  end)

  --------------------------------------------------------------------------------
  -- /rest/chaininfo  (REST wave 2026-05-06)
  --------------------------------------------------------------------------------

  describe("/rest/chaininfo endpoint", function()
    -- Build a minimal storage that returns a header for the configured tip.
    -- The chaininfo handler reads tip header.bits / tip header.timestamp and
    -- walks 11 ancestors via prev_hash for mediantime — we wire all of those
    -- through one closure-driven mock.
    local function make_mock(tip_height)
      local block = make_test_block()
      local tip_hash = types.hash256(string.rep("\xcd", 32))
      return {
        tip_hash = tip_hash,
        block = block,
        storage = {
          get_header = function() return block.header end,
        },
        chain_state = {
          tip_height = tip_height or 100,
          tip_hash = tip_hash,
          header_tip_height = tip_height or 100,
        },
      }
    end

    it("returns 400 for non-JSON format", function()
      local m = make_mock()
      local server = rest.new({
        storage = m.storage,
        chain_state = m.chain_state,
        network = consensus.networks.mainnet,
      })
      local response = server:route("GET", "/rest/chaininfo.bin")
      local status = parse_http_response(response)
      assert.equal(400, status)
    end)

    it("returns chaininfo JSON shape (Core parity)", function()
      local m = make_mock(100)
      local server = rest.new({
        storage = m.storage,
        chain_state = m.chain_state,
        network = consensus.networks.mainnet,
      })

      local response = server:route("GET", "/rest/chaininfo.json")
      local status, content_type, body = parse_http_response(response)

      assert.equal(200, status)
      assert.truthy(content_type:match("application/json"))

      local d = cjson.decode(body)
      -- FIX-80: Core's canonical chain name is "main", not "mainnet"
      -- (bitcoin-core/src/util/chaintype.cpp::ChainTypeToString).
      assert.equal("main",               d.chain)
      assert.equal(100,                  d.blocks)
      assert.equal(100,                  d.headers)
      assert.equal(types.hash256_hex(m.tip_hash), d.bestblockhash)
      assert.is_number(d.difficulty)
      assert.is_number(d.mediantime)
      assert.is_number(d.verificationprogress)
      assert.is_boolean(d.initialblockdownload)
      assert.is_string(d.chainwork)
      assert.equal(64, #d.chainwork)
      assert.is_string(d.bits)
      assert.equal(8,  #d.bits)
      assert.is_string(d.target)
      assert.equal(64, #d.target)
      assert.equal(false, d.pruned)
      assert.is_table(d.softforks)
      -- Mainnet has bip34/bip65/bip66/csv/segwit/taproot all defined.
      assert.equal("buried", d.softforks.bip34.type)
      assert.equal("buried", d.softforks.taproot.type)
      assert.equal(true,  d.softforks.testdummy.active)
      -- At height 100, only testdummy (height=0) is active on mainnet.
      assert.equal(false, d.softforks.bip34.active)
    end)

    it("activates buried softforks past their height", function()
      local m = make_mock(800000)  -- past taproot
      local server = rest.new({
        storage = m.storage,
        chain_state = m.chain_state,
        network = consensus.networks.mainnet,
      })

      local response = server:route("GET", "/rest/chaininfo.json")
      local status, _, body = parse_http_response(response)
      assert.equal(200, status)
      local d = cjson.decode(body)
      assert.equal(true, d.softforks.bip34.active)
      assert.equal(true, d.softforks.bip65.active)
      assert.equal(true, d.softforks.taproot.active)
    end)

    it("populates pruneheight + automatic_pruning when pruner is enabled", function()
      local m = make_mock(100)
      local server = rest.new({
        storage     = m.storage,
        chain_state = m.chain_state,
        network     = consensus.networks.mainnet,
        pruner = {
          enabled      = true,
          prune_height = 50,
          automatic    = true,
          target_mb    = 600,
        },
      })

      local response = server:route("GET", "/rest/chaininfo.json")
      local _, _, body = parse_http_response(response)
      local d = cjson.decode(body)
      assert.equal(true, d.pruned)
      -- Core: pruneheight = prune_height + 1 (first UNPRUNED block).
      assert.equal(51, d.pruneheight)
      assert.equal(true, d.automatic_pruning)
      assert.equal(600 * 1024 * 1024, d.prune_target_size)
    end)
  end)

  --------------------------------------------------------------------------------
  -- /rest/headers ?count=N  (REST wave 2026-05-06)
  --------------------------------------------------------------------------------

  describe("/rest/headers ?count= form", function()
    it("accepts ?count= query param (Core parity)", function()
      local block = make_test_block()
      local block_hash = types.hash256(string.rep("\xcd", 32))
      local block_hash_hex = types.hash256_hex(block_hash)

      local mock_storage = {
        get_header = function(hash)
          if hash.bytes == block_hash.bytes then return block.header end
          return nil
        end,
        iterator = function() return nil end,
      }

      local server = rest.new({storage = mock_storage})
      local response = server:route("GET",
        "/rest/headers/" .. block_hash_hex .. ".json?count=1")
      local status, content_type, body = parse_http_response(response)
      assert.equal(200, status)
      assert.truthy(content_type:match("application/json"))
      local d = cjson.decode(body)
      assert.equal(1, #d)
    end)

    it("defaults count=5 when ?count= omitted", function()
      local block = make_test_block()
      local block_hash = types.hash256(string.rep("\xcd", 32))
      local block_hash_hex = types.hash256_hex(block_hash)

      local mock_storage = {
        get_header = function(hash)
          if hash.bytes == block_hash.bytes then return block.header end
          return nil
        end,
        iterator = function() return nil end,
      }

      local server = rest.new({storage = mock_storage})
      local response = server:route("GET",
        "/rest/headers/" .. block_hash_hex .. ".json")
      local status, _, body = parse_http_response(response)
      assert.equal(200, status)
      local d = cjson.decode(body)
      -- We only seeded one header; loop terminates after 1 even though
      -- count defaults to 5 — confirms the route matched and didn't 404.
      assert.equal(1, #d)
    end)

    it("rejects ?count= out of range", function()
      local server = rest.new({storage = {get_header = function() return nil end}})
      local response = server:route("GET",
        "/rest/headers/" .. string.rep("a", 64) .. ".json?count=3000")
      local status, _, body = parse_http_response(response)
      assert.equal(400, status)
      assert.truthy(body:match("out of acceptable range"))
    end)
  end)

  --------------------------------------------------------------------------------
  -- /rest/blockfilter and /rest/blockfilterheaders  (REST wave 2026-05-06)
  --------------------------------------------------------------------------------

  describe("/rest/blockfilter endpoint", function()
    -- Build a fake "filter index" that satisfies the lookup contract used by
    -- rest.lua::lookup_filter().  We give one block_hash a synthetic filter.
    local function make_indexed_storage(block_hash, filter_payload, filter_header)
      local serialize_mod = require("lunarblock.serialize")
      local w = serialize_mod.buffer_writer()
      w.write_hash256(types.hash256(string.rep("\xfa", 32)))    -- filter_hash
      w.write_hash256(filter_header)                            -- filter_header
      w.write_varstr(filter_payload)                            -- filter_data
      local cf_bytes = w.result()

      return {
        get = function(cf, key)
          if cf == "block_filter" and key == block_hash.bytes then
            return cf_bytes
          end
          return nil
        end,
      }
    end

    it("returns 400 for unknown filtertype", function()
      local server = rest.new({storage = {get = function() return nil end}})
      local response = server:route("GET",
        "/rest/blockfilter/exotic/" .. string.rep("a", 64) .. ".json")
      local status, _, body = parse_http_response(response)
      assert.equal(400, status)
      assert.truthy(body:match("Unknown filtertype"))
    end)

    it("returns 404 when the filter is not indexed", function()
      local server = rest.new({storage = {get = function() return nil end}})
      local response = server:route("GET",
        "/rest/blockfilter/basic/" .. string.rep("a", 64) .. ".json")
      local status = parse_http_response(response)
      assert.equal(404, status)
    end)

    it("returns the filter as JSON for the basic filtertype", function()
      local block_hash = types.hash256(string.rep("\xab", 32))
      local payload = "\x10\x20\x30\x40"
      local fheader = types.hash256(string.rep("\xfb", 32))
      local server = rest.new({
        storage = make_indexed_storage(block_hash, payload, fheader),
      })

      local response = server:route("GET",
        "/rest/blockfilter/basic/" .. types.hash256_hex(block_hash) .. ".json")
      local status, content_type, body = parse_http_response(response)
      assert.equal(200, status)
      assert.truthy(content_type:match("application/json"))
      local d = cjson.decode(body)
      assert.equal("10203040", d.filter)
    end)
  end)

  describe("/rest/blockfilterheaders endpoint", function()
    -- Mock a height index + filter store: heights 100..104, each block_hash
    -- = "\xCC" .. 31 bytes of (counter), each filter_header = "\xFE" .. 31
    -- bytes of (counter).  Used to verify the path-form (count in URL) and
    -- query-form (?count=N) both walk forward correctly.
    local function make_filter_chain_storage(start_height, count)
      local serialize_mod = require("lunarblock.serialize")
      local hashes = {}
      local cf_filter = {}
      local cf_height = {}
      for i = 0, count - 1 do
        local h = start_height + i
        local bh = string.char(0xCC) .. string.char(i) .. string.rep("\x00", 30)
        local fh = string.char(0xFE) .. string.char(i) .. string.rep("\x00", 30)
        hashes[h] = types.hash256(bh)

        local w = serialize_mod.buffer_writer()
        w.write_hash256(types.hash256(string.rep("\xfa", 32)))
        w.write_hash256(types.hash256(fh))
        w.write_varstr("\x01\x02")
        cf_filter[bh] = w.result()

        cf_height[string.char(
          math.floor(h / 16777216) % 256,
          math.floor(h / 65536)    % 256,
          math.floor(h / 256)      % 256,
          h % 256
        )] = bh
      end

      return {
        first_hash = hashes[start_height],
        first_height = start_height,
        storage = {
          get = function(cf, key)
            if cf == "block_filter" then return cf_filter[key] end
            return nil
          end,
          get_hash_by_height = function(h) return hashes[h] end,
          iterator = function(cf)
            if cf ~= "height" then return nil end
            local keys = {}
            for k, _ in pairs(cf_height) do keys[#keys + 1] = k end
            table.sort(keys)
            local i = 0
            local it = {}
            function it.seek_to_first() i = 1 end
            function it.valid() return keys[i] ~= nil end
            function it.key() return keys[i] end
            function it.value() return cf_height[keys[i]] end
            function it.next() i = i + 1 end
            function it.destroy() end
            return it
          end,
        },
      }
    end

    it("returns 400 for unknown filtertype", function()
      local server = rest.new({storage = {get = function() return nil end}})
      local response = server:route("GET",
        "/rest/blockfilterheaders/exotic/5/" .. string.rep("a", 64) .. ".json")
      local status, _, body = parse_http_response(response)
      assert.equal(400, status)
      assert.truthy(body:match("Unknown filtertype"))
    end)

    it("returns 400 for count out of range (path form)", function()
      local server = rest.new({storage = {get = function() return nil end}})
      local response = server:route("GET",
        "/rest/blockfilterheaders/basic/3000/" .. string.rep("a", 64) .. ".json")
      local status, _, body = parse_http_response(response)
      assert.equal(400, status)
      assert.truthy(body:match("out of acceptable range"))
    end)

    it("returns N filter headers (path form)", function()
      local m = make_filter_chain_storage(100, 3)
      local server = rest.new({storage = m.storage})

      local response = server:route("GET",
        "/rest/blockfilterheaders/basic/3/" ..
        types.hash256_hex(m.first_hash) .. ".json")
      local status, content_type, body = parse_http_response(response)
      assert.equal(200, status)
      assert.truthy(content_type:match("application/json"))
      local d = cjson.decode(body)
      assert.equal(3, #d)
      for _, hex in ipairs(d) do
        assert.equal(64, #hex)
      end
    end)

    it("returns N filter headers (query-param form)", function()
      local m = make_filter_chain_storage(200, 3)
      local server = rest.new({storage = m.storage})

      local response = server:route("GET",
        "/rest/blockfilterheaders/basic/" ..
        types.hash256_hex(m.first_hash) .. ".json?count=2")
      local status, _, body = parse_http_response(response)
      assert.equal(200, status)
      local d = cjson.decode(body)
      assert.equal(2, #d)
    end)
  end)

end)
