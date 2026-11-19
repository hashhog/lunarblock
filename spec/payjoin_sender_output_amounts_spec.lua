-- BIP-78 PayJoin sender: the sender checklist a malicious receiver must not
-- get past (cffix-lunarblock-payjoin-sender-output-amounts).
--
-- Before this fix, payjoin_check_outputs compared only the multiset of output
-- SCRIPTS, never amounts; the fee cap (G13) only ran when
-- maxadditionalfeecontribution was passed, and then trusted the receiver's
-- witness_utxo values for the sender's own inputs; any http:// endpoint was
-- accepted; version / locktime / nSequence were never compared.  A receiver
-- (or anyone on-path over plaintext http) could move value out of the
-- sender's change into the payment output and the wallet re-signed the
-- proposal with SIGHASH_ALL and broadcast it.
--
-- Core has no PayJoin sender; the reference is BIP-78 "Sender's payjoin
-- proposal checklist":
--   * tx version and nLockTime unchanged; sender input nSequence unchanged;
--     no mixed nSequence introduced by receiver inputs;
--   * every sender output (all but the payment output) present with its
--     amount, except the fee output (additionalfeeoutputindex), which may
--     drop by at most maxadditionalfeecontribution, and that contribution
--     may only pay fee (contribution <= proposal fee - original fee);
--   * the pj endpoint is https, or http to a .onion host.

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

describe("payjoin sender checklist (BIP-78)", function()
  local sender, rest_mod, wallet_mod, types, consensus, crypto
  local script_mod, address_mod, validation, psbt_mod

  setup(function()
    setup_loader()
    sender      = require("lunarblock.payjoin_sender")
    rest_mod    = require("lunarblock.rest")
    wallet_mod  = require("lunarblock.wallet")
    types       = require("lunarblock.types")
    consensus   = require("lunarblock.consensus")
    crypto      = require("lunarblock.crypto")
    script_mod  = require("lunarblock.script")
    address_mod = require("lunarblock.address")
    validation  = require("lunarblock.validation")
    psbt_mod    = require("lunarblock.psbt")
  end)

  -- Regtest sender wallet with one 500,000-sat P2WPKH UTXO.  Change goes to a
  -- second key so change and payment are distinct scripts.
  local function make_sender(seed)
    local w = wallet_mod.new(consensus.networks.regtest)
    local function key(tag)
      local priv = crypto.sha256("pj-amounts-" .. seed .. tag)
      local pub = crypto.pubkey_from_privkey(priv, true)
      local addr = address_mod.pubkey_to_p2wpkh(pub, "regtest")
      w.keys[addr] = {privkey = priv, pubkey = pub, type = "p2wpkh"}
      w.addresses[#w.addresses + 1] = addr
      return addr, script_mod.make_p2wpkh_script(crypto.hash160(pub))
    end
    local addr, spk = key("-funds")
    local change_addr, change_spk = key("-change")
    w.is_locked = false
    w.is_encrypted = false
    local prev_txid = types.hash256(string.rep("\xAB", 32))
    local okey = prev_txid.bytes .. string.char(0, 0, 0, 0)
    w.utxos[okey] = {
      value = 500000, script_pubkey = spk, address = addr,
      txid = prev_txid, vout = 0, height = 1, is_coinbase = false,
      confirmations = 100,
    }
    w.confirmed_balance = 500000
    function w:get_available_utxos(_) return {{utxo = self.utxos[okey]}} end
    function w:get_new_address() return change_addr end
    function w:get_change_address() return change_addr end
    return w, change_spk
  end

  local function make_receiver(seed)
    local w = wallet_mod.new(consensus.networks.regtest)
    local priv = crypto.sha256("pj-amounts-recv-" .. seed)
    local pub = crypto.pubkey_from_privkey(priv, true)
    local addr = address_mod.pubkey_to_p2wpkh(pub, "regtest")
    local spk = script_mod.make_p2wpkh_script(crypto.hash160(pub))
    w.is_locked = false
    w.is_encrypted = false
    w.keys[addr] = {privkey = priv, pubkey = pub, type = "p2wpkh"}
    w.addresses[#w.addresses + 1] = addr
    local prev_txid = types.hash256(string.rep("\xCD", 32))
    local okey = prev_txid.bytes .. string.char(0, 0, 0, 0)
    w.utxos[okey] = {
      value = 250000, script_pubkey = spk, address = addr,
      txid = prev_txid, vout = 0, height = 1, is_coinbase = false,
      confirmations = 100,
    }
    w.confirmed_balance = 250000
    function w:get_available_utxos(_) return {{utxo = self.utxos[okey]}} end
    return w, addr, spk
  end

  -- Mock mempool: accepts everything and records WHICH tx was broadcast.
  local function make_mempool()
    local m = {accepted = {}}
    function m:accept_transaction(tx)
      self.accepted[#self.accepted + 1] = tx
      return true, types.hash256_hex(validation.compute_txid(tx))
    end
    return m
  end

  local function find_out(tx, spk)
    for i, o in ipairs(tx.outputs) do
      if o.script_pubkey == spk then return i, o end
    end
  end

  -- Run the full sender flow against a transport hook that rewrites the
  -- Original PSBT with `mutate(psbt, ctx)` and returns it as the Proposal.
  local function run(seed, mutate, opts, pj)
    local sw, change_spk = make_sender(seed)
    local _, recv_addr, recv_spk = make_receiver(seed)
    local mp = make_mempool()
    sw:set_mempool(mp)
    local called = false
    local transport = function(_, body, _)
      called = true
      local p = psbt_mod.from_base64(body)
      mutate(p, {change_spk = change_spk, pay_spk = recv_spk})
      return psbt_mod.to_base64(p), nil
    end
    opts = opts or {}
    opts.network = "regtest"
    opts.transport = transport
    opts.fee_rate = 1
    local uri = "bitcoin:" .. recv_addr .. "?amount=0.0005&pj=" ..
                (pj or "https%3A%2F%2Freceiver.example%2Fpayjoin")
    local txid, status, err = sender.send_payjoin_request(
      sw, mp, nil, uri, nil, opts)
    return {txid = txid, status = status, err = err, mp = mp,
            called = called, change_spk = change_spk, pay_spk = recv_spk}
  end

  local function shift_change_to_payment(x)
    return function(p, c)
      local ci = find_out(p.tx, c.change_spk)
      local pi = find_out(p.tx, c.pay_spk)
      p.tx.outputs[ci].value = p.tx.outputs[ci].value - x
      p.tx.outputs[pi].value = p.tx.outputs[pi].value + x
    end
  end

  -- What the broadcast tx paid back to the sender's change script.
  local function broadcast_change(r)
    local tx = r.mp.accepted[#r.mp.accepted]
    local _, o = find_out(tx, r.change_spk)
    return o and o.value
  end

  -- Wallet:create_transaction appends change after the recipients, so with
  -- one recipient the change is output index 1 (0-based, as BIP-78's
  -- additionalfeeoutputindex counts).  The control below pins that.
  local CHANGE_IDX = 1

  it("positive control: untouched proposal is accepted as payjoin", function()
    local r = run("ctl", function() end)
    assert.is_nil(r.err)
    assert.are.equal("payjoin", r.status)
    local tx = r.mp.accepted[1]
    assert.are.equal(r.change_spk, tx.outputs[CHANGE_IDX + 1].script_pubkey)
  end)

  it("positive control: FIX-65 receiver round-trip is still payjoin", function()
    local sw = make_sender("rt")
    local rw, recv_addr = make_receiver("rt")
    local srv = rest_mod.new({wallet = rw, network = consensus.networks.regtest})
    local mp = make_mempool()
    sw:set_mempool(mp)
    local transport = function(url, body, _)
      local q = {}
      for k, v in (url:match("%?(.*)$") or ""):gmatch("([^=&]+)=([^&]*)") do
        q[k] = v
      end
      local resp = srv:handle_payjoin(q, body)
      if resp:match("HTTP/1.1 (%d+)") ~= "200" then
        return nil, sender.ERR.TRANSPORT, "http " .. tostring(resp)
      end
      return resp:match("\r\n\r\n(.*)$") or "", nil
    end
    local txid, status, err = sender.send_payjoin_request(sw, mp, nil,
      "bitcoin:" .. recv_addr ..
      "?amount=0.0005&pj=https%3A%2F%2Freceiver.example%2Fpayjoin",
      nil, {network = "regtest", transport = transport, fee_rate = 1})
    assert.is_nil(err and err.message)
    assert.is_truthy(txid)
    assert.are.equal("payjoin", status)
    assert.are.equal(2, #mp.accepted[1].inputs)
  end)

  it("receiver lowers change by X and raises payment by X -> fallback", function()
    local r = run("steal", shift_change_to_payment(20000))
    assert.are.equal("fallback", r.status)
    assert.is_truthy(r.err.message:find("changed the amount of a sender output", 1, true))
    assert.are.equal(sender.ERR.SNOOP, r.err and r.err.code)
    -- What was broadcast is the Original: change intact.
    local orig_change = broadcast_change(r)
    assert.is_truthy(orig_change)
    assert.is_true(orig_change > 400000)
  end)

  it("change drop within maxadditionalfeecontribution that only moves value to the payee -> fallback", function()
    -- The fee output may only fund FEE; here the fee is unchanged and the
    -- whole contribution lands in the payment output.
    local r = run("steal-capped", shift_change_to_payment(2000), {
      maxadditionalfeecontribution = 5000, additionalfeeoutputindex = CHANGE_IDX,
    })
    assert.are.equal("fallback", r.status)
    assert.is_truthy(r.err.message:find("exceeds the fee increase", 1, true))
  end)

  it("receiver inflates the sender input's witness_utxo value to hide a change drop from G13 -> fallback", function()
    local X = 5000
    local r = run("inflate", function(p, c)
      shift_change_to_payment(X)(p, c)
      -- Lie about the sender's own input value so (in - out) looks like
      -- the fee rose by exactly X.
      p.inputs[1].witness_utxo.value = p.inputs[1].witness_utxo.value + X
    end, {maxadditionalfeecontribution = X,
          additionalfeeoutputindex = CHANGE_IDX})
    assert.are.equal("fallback", r.status)
    assert.is_truthy(r.err.message:find("exceeds the fee increase", 1, true))
    assert.are.equal(sender.ERR.FEE_EXCEEDED, r.err and r.err.code)
  end)

  it("fee output may drop by <= maxadditionalfeecontribution when it pays fee", function()
    local r = run("payfee", function(p, c)
      local ci = find_out(p.tx, c.change_spk)
      p.tx.outputs[ci].value = p.tx.outputs[ci].value - 300
    end, {maxadditionalfeecontribution = 300,
          additionalfeeoutputindex = CHANGE_IDX})
    assert.is_nil(r.err and r.err.message)
    assert.are.equal("payjoin", r.status)
  end)

  it("fee output dropping by more than maxadditionalfeecontribution -> fallback", function()
    local r = run("overfee", function(p, c)
      local ci = find_out(p.tx, c.change_spk)
      p.tx.outputs[ci].value = p.tx.outputs[ci].value - 301
    end, {maxadditionalfeecontribution = 300,
          additionalfeeoutputindex = CHANGE_IDX})
    assert.are.equal("fallback", r.status)
    assert.is_truthy(r.err.message:find("more than maxadditionalfeecontribution", 1, true))
  end)

  it("changed tx version -> fallback", function()
    local r = run("ver", function(p) p.tx.version = p.tx.version + 1 end)
    assert.are.equal("fallback", r.status)
    assert.is_truthy(r.err.message:find("changed the tx version", 1, true))
  end)

  it("changed nLockTime -> fallback", function()
    local r = run("lt", function(p) p.tx.locktime = p.tx.locktime + 1 end)
    assert.are.equal("fallback", r.status)
    assert.is_truthy(r.err.message:find("changed nLockTime", 1, true))
  end)

  it("changed sender input nSequence -> fallback", function()
    local r = run("seq", function(p)
      p.tx.inputs[1].sequence = 0xFFFFFFFE
    end)
    assert.are.equal("fallback", r.status)
    assert.is_truthy(r.err.message:find("changed a sender input's nSequence", 1, true))
  end)

  it("receiver input with a different nSequence -> fallback", function()
    local r = run("mixseq", function(p)
      local txid = types.hash256(string.rep("\xEF", 32))
      p.tx.inputs[#p.tx.inputs + 1] =
        types.txin(types.outpoint(txid, 0), "", 0xFFFFFFFE)
      local pin = psbt_mod.psbt_input()
      pin.witness_utxo = {value = 10000,
                          script_pubkey = p.inputs[1].witness_utxo.script_pubkey}
      pin.final_script_witness = {string.rep("\x01", 71), string.rep("\x02", 33)}
      p.inputs[#p.inputs + 1] = pin
    end)
    assert.are.equal("fallback", r.status)
    assert.is_truthy(r.err.message:find("mixed sequences", 1, true))
  end)

  it("http:// pj endpoint on a clearnet host is refused before any request", function()
    local r = run("http", function() end, nil,
                  "http%3A%2F%2Freceiver.example%2Fpayjoin")
    assert.is_false(r.called)
    assert.are.equal(sender.ERR.BAD_URI, r.err and r.err.code)
    assert.are.equal(0, #r.mp.accepted)
  end)

  it("http:// pj endpoint on a .onion host is allowed", function()
    local r = run("onion", function() end, nil,
      "http%3A%2F%2Fexampleonionaddressxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion%2Fpj")
    assert.is_true(r.called)
    assert.are.equal("payjoin", r.status)
  end)
end)
