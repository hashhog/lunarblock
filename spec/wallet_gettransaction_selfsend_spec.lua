-- gettransaction.details for a send-to-self, as Core lists it.
--
-- Core CachedTxGetAmounts (wallet/receive.cpp): for a from-me transaction an
-- output that OutputIsChange is skipped outright (no "send" row, no "receive"
-- row); every other output gets a "send" row, and an output paying one of our
-- addresses also gets a "receive" row. Sending 1 BTC to a second address of the
-- same wallet therefore lists {receive +1, send -1} and NOT the change.
-- lunarblock listed the change as a receive and left out the send row.

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

describe("gettransaction details for a send-to-self", function()
  local wallet, consensus, types, crypto, script
  local w, blocks, txids

  setup(function()
    setup_loader()
    wallet = require("lunarblock.wallet")
    consensus = require("lunarblock.consensus")
    types = require("lunarblock.types")
    crypto = require("lunarblock.crypto")
    script = require("lunarblock.script")
  end)

  local function spk_of(addr)
    return "\x00\x14" .. crypto.hash160(w.keys[addr].pubkey)
  end

  local function spend(prev, vout, outs)
    local ins = {types.txin(types.outpoint(prev, vout), "", 0xFFFFFFFF)}
    local o = {}
    for i, out in ipairs(outs) do o[i] = types.txout(out[1], out[2]) end
    return types.transaction(2, ins, o, 0)
  end

  before_each(function()
    local seed = hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    w = wallet.from_seed(seed, consensus.networks.regtest, nil)
    local a1 = w:get_new_address()   -- coinbase address
    local a2 = w:get_new_address()   -- second receive address (send-to-self target)
    local chg = w:get_change_address()
    local foreign = "\x00\x14" .. string.rep("\x07", 20)

    local cb = types.transaction(1,
      {types.txin(types.outpoint(types.hash256(string.rep("\0", 32)), 0xFFFFFFFF), "\x01\x01", 0xFFFFFFFF)},
      {types.txout(5000000000, spk_of(a1))}, 0)
    local cb_id = require("lunarblock.validation").compute_txid(cb)
    -- tx1: 1 BTC to our own a2, 49 BTC change (minus 0.0001 fee)
    local selfsend = spend(cb_id, 0, {{100000000, spk_of(a2)}, {4899990000, spk_of(chg)}})
    local ss_id = require("lunarblock.validation").compute_txid(selfsend)
    -- tx2 (control): 1 BTC to a foreign script, rest to change
    local pay = spend(ss_id, 1, {{100000000, foreign}, {4799980000, spk_of(w:get_change_address())}})
    local pay_id = require("lunarblock.validation").compute_txid(pay)
    txids = {
      cb = types.hash256_hex(cb_id), ss = types.hash256_hex(ss_id), pay = types.hash256_hex(pay_id),
    }
    blocks = {
      [0] = {header = {timestamp = 1}, transactions = {}},
      [1] = {header = {timestamp = 2}, transactions = {cb}},
      [2] = {header = {timestamp = 3}, transactions = {selfsend}},
      [3] = {header = {timestamp = 4}, transactions = {pay}},
    }
    w.scanned = true
    w.storage = {
      get_hash_by_height = function(h) return types.hash256(string.char(h) .. string.rep("\0", 31)) end,
      get_block = function(hash) return blocks[hash.bytes:byte(1)] end,
    }
    w:scan_history({tip_height = 3}, nil)
  end)

  local function cats(txid_hex)
    local d = w:get_transaction_detail(txid_hex, 3).details
    local rows = {}
    for _, r in ipairs(d) do rows[#rows + 1] = r.category .. ":" .. r.amount end
    table.sort(rows)
    return rows
  end

  it("lists receive +1 and send -1 and omits the change output", function()
    assert.same({"receive:1", "send:-1"}, cats(txids.ss))
  end)

  it("gives the send row the self-paid vout, not the change vout", function()
    local d = w:get_transaction_detail(txids.ss, 3).details
    for _, r in ipairs(d) do assert.equals(0, r.vout) end
  end)

  it("a payment to a foreign address lists only the send row, change omitted", function()
    assert.same({"send:-1"}, cats(txids.pay))
  end)

  it("control: a plain coinbase receive is unchanged", function()
    local d = w:get_transaction_detail(txids.cb, 3).details
    assert.equals(1, #d)
    assert.equals(50, d[1].amount)
  end)

  it("does not change amount, fee, credit or debit (balances untouched)", function()
    local r = w:get_transaction_detail(txids.ss, 3)
    local h = w.tx_history[txids.ss]
    assert.equals(-0.0001, r.fee)
    assert.equals(0, r.amount)  -- credit - value_out: change still counts toward credit
    assert.equals(4999990000, h.credit)
    assert.equals(5000000000, h.debit)
  end)
end)
