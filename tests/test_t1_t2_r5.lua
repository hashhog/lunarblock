#!/usr/bin/env luajit
-- T1/T2 R5 probe parity vs live Bitcoin Core (tools/r5-probes.d).
--
-- CONTROL: `luajit tests/test_t1_t2_r5.lua`
--
-- Encodes the remaining T1/T2 FAILs from the 2026-09-01 r5_probe sweep
-- (tools/diff-test-artifacts/r5-probe/20260901T182642Z.json lunarblock
-- T1 37/46 T2 19/41). Dispatch goes through handle_single_request so a
-- handler that raises a bare Lua error (wire -32603) or is missing
-- (wire -32601) fails these.

package.path = "src/?.lua;src/?/init.lua;./?.lua;" .. package.path

local rpc       = require("lunarblock.rpc")
local cjson     = require("cjson")
local consensus = require("lunarblock.consensus")
local types     = require("lunarblock.types")

local PSBT_A = "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA"
local PSBT_B = "cHNidP8BACkCAAAAAAGghgEAAAAAABYAFHUedugZkZbUVJQcRdGzoyPxQzvWAAAAAAAA"
local RAW_HEX = "0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000fdffffff01a086010000000000160014751e76e8199196d454941c45d1b3a323f1433bd600000000"
local WIF_PRIV1 = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
local KEY1 = "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd"
local KEY2 = "03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626"

local PASS, FAIL = 0, 0
local function pass(n) io.write(string.format("  PASS  %s\n", n)); PASS = PASS + 1 end
local function fail(n, m) io.write(string.format("  FAIL  %s -- %s\n", n, m)); FAIL = FAIL + 1 end
local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end

local function dummy_peer_manager()
  return {
    network = consensus.networks.mainnet,
    manual_peers = {},
    peers = {},
    banned = {},
    clear_expired_bans = function() end,
    get_banned_list = function() return {} end,
    connect_peer = function() return true end,
    disconnect_peer = function() end,
  }
end

local function dummy_block()
  local prev = types.hash256_zero()
  local coinbase = types.transaction(1, {
    types.txin(types.outpoint(prev, 0xffffffff), "\x04\x00", 0xffffffff),
  }, {
    types.txout(5000000000, "\x51"),
  }, 0)
  return {
    header = types.block_header(1, prev, prev, 1231006505, 0x1d00ffff, 2083236893),
    transactions = { coinbase },
  }
end

local function make_rpc(extra)
  extra = extra or {}
  local cfg = {
    network      = extra.network or consensus.networks.mainnet,
    peer_manager = extra.peer_manager or dummy_peer_manager(),
    mempool      = extra.mempool,
    storage      = extra.storage,
    chain_state  = extra.chain_state,
    mining       = extra.mining,
  }
  return rpc.new(cfg)
end

local function dispatch(server, method, params)
  local resp = server:handle_single_request({
    method = method, params = params or {}, id = 1,
  })
  if type(resp.error) == "table" and resp.error.code then
    return resp
  end
  if resp._raw_json_result then
    resp.result = cjson.decode(resp._raw_json_result)
  end
  return resp
end

local function err_of(resp)
  local e = resp.error
  if type(e) ~= "table" or e == cjson.null or e.code == nil then
    return nil, ""
  end
  return e.code, e.message or ""
end

local function expect_err(resp, code, name)
  local got, msg = err_of(resp)
  if got ~= code then
    error(string.format("%s: expected error %s, got %s (%s)",
      name or "rpc", tostring(code), tostring(got), tostring(msg)), 2)
  end
  return msg
end

local function expect_ok(resp, name)
  local got, msg = err_of(resp)
  if got ~= nil then
    error(string.format("%s: expected success, got error %s (%s)",
      name or "rpc", tostring(got), tostring(msg)), 2)
  end
  return resp.result
end

print("=== T1/T2 R5 probe parity (lunarblock) ===\n")

local DESC_NO_CSUM = "wpkh(03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd)"
local DESC_CSUM = DESC_NO_CSUM .. "#e72f49hy"
local ZERO64 = string.rep("0", 64)
local HASH11 = string.rep("11", 32)

--------------------------------------------------------------------------------
-- T1
--------------------------------------------------------------------------------
print("--- T1 ---")

test("t1 addnode invalid-command is -1 help-text family", function()
  local msg = expect_err(dispatch(make_rpc(), "addnode",
    {"192.0.2.1:8333", "notacommand"}), -1)
  assert(msg:sub(1, 7) == "addnode", "Core help-text family, got " .. msg)
end)

test("t1 listbanned success is a JSON array", function()
  local srv = make_rpc()
  local resp = dispatch(srv, "listbanned", {})
  local res = expect_ok(resp, "listbanned")
  -- Force the on-the-wire JSON type: empty Lua tables encode as {} unless
  -- tagged with empty_array_mt.
  local encoded
  if type(resp.result) == "table" and resp.result ~= cjson.null then
    encoded = cjson.encode(resp.result)
  else
    encoded = tostring(res)
  end
  assert(encoded:sub(1, 1) == "[", "listbanned must encode as array, got " .. encoded)
end)

test("t1 getblocktemplate missing-segwit-rule is -8", function()
  local msg = expect_err(dispatch(make_rpc(), "getblocktemplate", {{}}), -8)
  assert(msg:find("segwit", 1, true), "Core missing-segwit family, got " .. msg)
end)

test("t1 sendrawtransaction decode-error is -22", function()
  expect_err(dispatch(make_rpc(), "sendrawtransaction", {"deadbeef"}), -22)
end)

test("t1 testmempoolaccept decode-error is -22", function()
  expect_err(dispatch(make_rpc({
    mempool = { entries = {}, accept_to_memory_pool = function() end },
  }), "testmempoolaccept", {{"deadbeef"}}), -22)
end)

--------------------------------------------------------------------------------
-- T2
--------------------------------------------------------------------------------
print("--- T2 ---")

test("t2 decoderawtransaction nonhex is -22", function()
  local msg = expect_err(dispatch(make_rpc(), "decoderawtransaction", {"zz"}), -22)
  assert(msg:find("TX decode failed", 1, true), "got " .. msg)
end)

test("t2 validateaddress exact-invalid matches Core Base58 checksum/length", function()
  local res = expect_ok(dispatch(make_rpc(), "validateaddress", {"notanaddress"}))
  assert(res.isvalid == false, "isvalid")
  assert(res.error == "Invalid checksum or length of Base58 address (P2PKH or P2SH)",
    "got " .. tostring(res.error))
end)

test("t2 getblockstats invalid-stat is -8", function()
  local block = dummy_block()
  local bh = types.hash256_from_hex(HASH11)
  local storage = {
    get_block = function(h)
      if h and h.bytes == bh.bytes then return block end
      return nil
    end,
    get_undo = function() return nil end,
    get_header = function() return nil end,
    iterator = function() return nil end,
  }
  local msg = expect_err(dispatch(make_rpc({ storage = storage, chain_state = { tip_height = 1 } }),
    "getblockstats", {HASH11, {"bogusstat"}}), -8)
  assert(msg:find("Invalid selected statistic", 1, true), "got " .. msg)
end)

test("t2 gettxoutproof tx-not-in-block is -5", function()
  expect_err(dispatch(make_rpc({
    storage = { get_block = function() return nil end },
  }), "gettxoutproof", {{ZERO64}}), -5)
end)

test("t2 verifytxoutproof nonhex is -8 ParseHexV", function()
  local msg = expect_err(dispatch(make_rpc(), "verifytxoutproof", {"zz"}), -8)
  assert(msg == "proof must be hexadecimal string (not 'zz')", "got " .. msg)
end)

test("t2 importmempool missing file is -1", function()
  local msg = expect_err(dispatch(make_rpc(), "importmempool",
    {"/nonexistent/r5-probe-no-such-file.dat"}), -1)
  assert(msg == "Unable to import mempool file, see debug log for details.",
    "got " .. msg)
end)

test("t2 prioritisetransaction bad-txid is -8", function()
  expect_err(dispatch(make_rpc({
    mempool = { prioritise_transaction = function() end },
  }), "prioritisetransaction", {"zz", 0, 1000}), -8)
end)

test("t2 scantxoutset bogus action is -8", function()
  local msg = expect_err(dispatch(make_rpc(), "scantxoutset", {"bogus"}), -8)
  assert(msg == "Invalid action 'bogus'", "got " .. msg)
end)

test("t2 pruneblockchain string height is -3 before prune-mode gate", function()
  local msg = expect_err(dispatch(make_rpc(), "pruneblockchain", {"zz"}), -3)
  assert(msg:find("not of expected type number", 1, true), "got " .. msg)
end)

test("t2 decodescript nonhex is -8 ParseHexV", function()
  local msg = expect_err(dispatch(make_rpc(), "decodescript", {"zz"}), -8)
  assert(msg == "argument must be hexadecimal string (not 'zz')", "got " .. msg)
end)

test("t2 combinerawtransaction unknown-input is -25", function()
  local msg = expect_err(dispatch(make_rpc(), "combinerawtransaction",
    {{RAW_HEX, RAW_HEX}}), -25)
  assert(msg == "Input not found or already spent", "got " .. msg)
end)

test("t2 createpsbt canonical-exact matches Core ConstructTransaction PSBT", function()
  local inputs = {{txid = string.rep("a", 64), vout = 0}}
  local outputs = {["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"] = 0.001}
  local res = expect_ok(dispatch(make_rpc(), "createpsbt", {inputs, outputs}))
  assert(res == PSBT_A, "got " .. tostring(res))
end)

test("t2 createpsbt bad-txid is -8", function()
  local inputs = {{txid = "zz", vout = 0}}
  local outputs = {["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"] = 0.001}
  expect_err(dispatch(make_rpc(), "createpsbt", {inputs, outputs}), -8)
end)

test("t2 analyzepsbt analyze-exact matches Core next-role", function()
  local res = expect_ok(dispatch(make_rpc(), "analyzepsbt", {PSBT_A}))
  assert(type(res.inputs) == "table" and res.inputs[1], "inputs")
  assert(res.inputs[1].has_utxo == false, "has_utxo")
  assert(res.inputs[1].is_final == false, "is_final")
  assert(res.inputs[1].next == "updater", "input next")
  assert(res.next == "updater", "top next got " .. tostring(res.next))
  assert(res.inputs[1].missing == nil, "Core omits missing when only utxo is absent")
end)

test("t2 combinepsbt empty array is -8", function()
  local msg = expect_err(dispatch(make_rpc(), "combinepsbt", {{}}), -8)
  assert(msg == "Parameter 'txs' cannot be empty", "got " .. msg)
end)

test("t2 joinpsbts join-exact is a PSBT combining both txs", function()
  local res = expect_ok(dispatch(make_rpc(), "joinpsbts", {{PSBT_A, PSBT_B}}))
  assert(type(res) == "string" and res:sub(1, 7) == "cHNidP8",
    "joined PSBT, got " .. tostring(res):sub(1, 40))
end)

test("t2 descriptorprocesspsbt bad-descriptor is -5", function()
  expect_err(dispatch(make_rpc(), "descriptorprocesspsbt",
    {PSBT_A, {"nonsense(desc)"}}), -5)
end)

test("t2 descriptorprocesspsbt update-unknown-input complete false", function()
  local res = expect_ok(dispatch(make_rpc(), "descriptorprocesspsbt",
    {PSBT_A, {"wpkh(" .. WIF_PRIV1 .. ")"}}))
  assert(res.complete == false, "complete")
  assert(type(res.psbt) == "string" and res.psbt:sub(1, 7) == "cHNidP8", "psbt")
end)

test("t2 signrawtransactionwithkey bad-privkey is -5", function()
  expect_err(dispatch(make_rpc(), "signrawtransactionwithkey",
    {RAW_HEX, {"notakey"}}), -5)
end)

test("t2 submitpackage empty array is -8", function()
  local msg = expect_err(dispatch(make_rpc({
    mempool = { accept_package = function() return false, "x" end },
  }), "submitpackage", {{}}), -8)
  assert(msg:find("Array must contain between 1 and", 1, true), "got " .. msg)
end)

test("t2 submitpackage nonhex is -22", function()
  expect_err(dispatch(make_rpc({
    mempool = { accept_package = function() return false, "x" end },
  }), "submitpackage", {{"zz"}}), -22)
end)

test("t2 createmultisig invalid-pubkey is -5", function()
  local msg = expect_err(dispatch(make_rpc(), "createmultisig",
    {1, {"deadbeef"}}), -5)
  assert(msg:find("33 or 65 bytes", 1, true), "got " .. msg)
end)

test("t2 createmultisig not-enough-keys is -8", function()
  local msg = expect_err(dispatch(make_rpc(), "createmultisig",
    {3, {KEY1, KEY2}}), -8)
  assert(msg:find("not enough keys supplied", 1, true), "got " .. msg)
end)

test("t2 deriveaddresses missing-checksum is -5", function()
  local msg = expect_err(dispatch(make_rpc(), "deriveaddresses", {DESC_NO_CSUM}), -5)
  assert(msg == "Missing checksum", "got " .. msg)
end)

test("t2 deriveaddresses range on unranged is -8", function()
  local msg = expect_err(dispatch(make_rpc(), "deriveaddresses",
    {DESC_CSUM, {0, 2}}), -8)
  assert(msg == "Range should not be specified for an un-ranged descriptor",
    "got " .. msg)
end)

test("t2 getdescriptorinfo invalid-descriptor is -5", function()
  expect_err(dispatch(make_rpc(), "getdescriptorinfo", {"notadescriptor"}), -5)
end)

test("t2 getdescriptorinfo bad-checksum is -5", function()
  expect_err(dispatch(make_rpc(), "getdescriptorinfo",
    {DESC_NO_CSUM .. "#00000000"}), -5)
end)

test("t2 getdescriptorinfo success-exact-single", function()
  local res = expect_ok(dispatch(make_rpc(), "getdescriptorinfo", {DESC_NO_CSUM}))
  assert(res.descriptor == DESC_CSUM, "descriptor")
  assert(res.checksum == "e72f49hy", "checksum")
  assert(res.isrange == false, "isrange")
  assert(res.issolvable == true, "issolvable")
  assert(res.hasprivatekeys == false, "hasprivatekeys")
end)

print(string.format("\nT1/T2 R5: %d passed, %d failed\n", PASS, FAIL))
os.exit(FAIL == 0 and 0 or 1)
