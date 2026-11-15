-- getaddressinfo `labels` lists the address-book entry's label, including the
-- default "", as Core does (wallet/rpc/addresses.cpp:503-508: push
-- FindAddressBookEntry(dest)->GetLabel() when there is an entry). Core's
-- getnewaddress always writes that entry (CWallet::GetNewDestination ->
-- SetAddressBook(dest, label, RECEIVE), label from LabelFromValue, default
-- ""), so a fresh receive address reports labels [""]. lunarblock ignored the
-- getnewaddress label and emitted an empty labels list (core-regtest row
-- wallet/address/info:labels, core [""] vs node {}).

local function hex_to_bin(hex)
  return (hex:gsub('..', function(cc) return string.char(tonumber(cc, 16)) end))
end

local function setup_loader()
  local loaders = package.loaders or package.searchers
  table.insert(loaders, 2, function(module)
    local name = module:match("^lunarblock%.(.+)")
    if name then
      local filename = "src/" .. name .. ".lua"
      local f = io.open(filename)
      if f then
        f:close()
        return function() return dofile(filename) end
      end
    end
    return nil, "not found"
  end)
end

describe("getaddressinfo labels (Core address book)", function()
  local wallet, consensus, rpc, cjson
  local w, server

  setup(function()
    setup_loader()
    wallet = require("lunarblock.wallet")
    consensus = require("lunarblock.consensus")
    rpc = require("lunarblock.rpc")
    cjson = require("cjson")
  end)

  before_each(function()
    local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    w = wallet.from_seed(seed, consensus.networks.regtest, nil)
    server = rpc.new({ network = consensus.networks.regtest, wallet = w })
  end)

  local function call(method, params)
    local body = cjson.encode({ jsonrpc = "1.0", id = 1, method = method, params = params })
    local resp = server:handle_request(body)
    return cjson.decode(resp), resp
  end

  local function labels_of(addr)
    local d, resp = call("getaddressinfo", { addr })
    assert.is_true(d.error == cjson.null, resp)
    return d.result.labels, resp
  end

  it("a getnewaddress address with no label reports labels [\"\"]", function()
    local d = call("getnewaddress", {})
    local labels, resp = labels_of(d.result)
    assert.same({ "" }, labels)
    assert.is_truthy(resp:find('"labels":[""]', 1, true), resp)
  end)

  it("a getnewaddress label is reported back", function()
    local d = call("getnewaddress", { "savings" })
    assert.same({ "savings" }, (labels_of(d.result)))
    d = call("getnewaddress", { "bech", "bech32" })
    assert.same({ "bech" }, (labels_of(d.result)))
  end)

  it("a change address has no address-book entry", function()
    local addr = w:get_change_address()
    local labels = labels_of(addr)
    assert.equals(0, #labels)
  end)

  it("a keypool lookahead key that getnewaddress never handed out has no entry", function()
    -- from_seed pre-derives gap_limit external keys; Core adds an address-book
    -- entry only when GetNewDestination hands one out.
    local lookahead
    for addr, info in pairs(w.keys) do
      if info.change == 0 then lookahead = addr; break end
    end
    assert.is_string(lookahead)
    assert.equals(0, #labels_of(lookahead))
  end)

  it("rejects the reserved label \"*\" and a non-string label (LabelFromValue)", function()
    local d, resp = call("getnewaddress", { "*" })
    assert.is_table(d.error, resp)
    assert.equals(-11, d.error.code)
    assert.equals("Invalid label name", d.error.message)
    d, resp = call("getnewaddress", { 5 })
    assert.is_table(d.error, resp)
    assert.equals(-3, d.error.code)
  end)

  it("keeps a label across a save and reload", function()
    local d = call("getnewaddress", { "kept" })
    local addr = d.result
    local path = os.tmpname()
    assert.is_true((w:save(path)))
    local w2 = assert(wallet.load(path, consensus.networks.regtest, nil))
    os.remove(path)
    os.remove(path .. ".tmp")
    -- The reloaded wallet still reports it (guarded so a tree without the
    -- accessor fails on the assertion, not on a nil call).
    local got = w2.get_address_label and w2:get_address_label(addr)
    assert.equals("kept", got)
    server = rpc.new({ network = consensus.networks.regtest, wallet = w2 })
    assert.same({ "kept" }, (labels_of(addr)))
  end)
end)
