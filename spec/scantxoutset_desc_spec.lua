-- scantxoutset unspents[].desc is Core's InferDescriptor of the coin's own
-- scriptPubKey (addr(...)#csum), not the scan-object string the caller sent
-- (rpc/blockchain.cpp scantxoutset).

local rpc = require("lunarblock.rpc")
local utxo_mod = require("lunarblock.utxo")
local storage_mod = require("lunarblock.storage")
local cjson = require("cjson")
local consensus = require("lunarblock.consensus")

local P2SH_SPK_HEX = "a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87"
local P2SH_ADDR = "2ND8PB9RrfCaAcjfjP1Y6nAgFd9zWHYX4DN"
local P2SH_DESC = "addr(2ND8PB9RrfCaAcjfjP1Y6nAgFd9zWHYX4DN)#pn0u88a8"

local function from_hex(h)
  return (h:gsub("%x%x", function(b) return string.char(tonumber(b, 16)) end))
end

local function scan(scanobject)
  local server = rpc.new({network = consensus.networks.regtest})
  local entry = utxo_mod.utxo_entry(5000, from_hex(P2SH_SPK_HEX), 1, false)
  local key = string.rep("\9", 32) .. "\0\0\0\0"
  local val = utxo_mod.serialize_utxo_entry(entry)
  local done = false
  server.storage = {
    iterator = function(cf)
      assert(cf == storage_mod.CF.UTXO)
      return {
        seek_to_first = function() end,
        valid = function() return not done end,
        key = function() return key end,
        value = function() return val end,
        next = function() done = true end,
        destroy = function() end,
      }
    end,
    get_hash_by_height = function() return nil end,
  }
  server.chain_state = {tip_height = 1}
  local body = cjson.encode({method = "scantxoutset",
                             params = {"start", {scanobject}}, id = 1})
  local resp = cjson.decode((server:handle_request(body)))
  assert.is_nil(resp.error and resp.error ~= cjson.null and resp.error or nil)
  return resp.result.unspents
end

describe("scantxoutset desc", function()
  it("raw() scan object reports the inferred addr() descriptor", function()
    local u = scan("raw(" .. P2SH_SPK_HEX .. ")")
    assert.are.equal(1, #u)
    assert.are.equal(P2SH_DESC, u[1].desc)
  end)

  it("addr() scan object reports the descriptor with its checksum", function()
    local u = scan("addr(" .. P2SH_ADDR .. ")")
    assert.are.equal(1, #u)
    assert.are.equal(P2SH_DESC, u[1].desc)
  end)
end)
