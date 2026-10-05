-- Mempool time locks are evaluated against the ACTIVE chain the way Core's
-- CheckFinalTxAtTip / CalculateLockPointsAtTip / CheckSequenceLocksAtTip do:
--   * nLockTime cutoff        = tip MTP, height = tip+1
--   * confirmed coin (height H)  time lock measured from MTP(H-1) of the active chain
--   * mempool coin               height tip+1, time measured from the tip MTP
-- Pre-fix (4ab752a) mempool.lua get_block_mtp_conservative returned the TIP MTP
-- for every coin, so a matured time-type relative lock on a confirmed coin was
-- refused (non-BIP68-final) forever.
local types = require("lunarblock.types")
local mempool = require("lunarblock.mempool")

describe("mempool MTP / BIP68 (active-chain coin MTP)", function()
  local T0 = 1600000000
  local STEP = 512          -- one SEQUENCE_LOCKTIME granularity unit per block
  local TIP = 200
  local TYPE_FLAG = 0x00400000

  local function hhash(tag, h)
    return types.hash256(string.format("%-8s%024d", tag, h))
  end

  -- Build a header store: an active chain 0..TIP (timestamps T0 + STEP*h) plus,
  -- optionally, a best-HEADER fork that leaves the active chain above
  -- fork_from and that the persisted height index follows.
  local function make_chain(opts)
    opts = opts or {}
    local headers, index = {}, {}
    local function add(tag, h, prev, ts)
      local hash = hhash(tag, h)
      headers[hash.bytes] = { prev_hash = prev, timestamp = ts, bits = 0x207fffff, version = 4 }
      return hash
    end
    local prev = types.hash256_zero()
    local active = {}
    for h = 0, TIP do
      prev = add("active", h, prev, T0 + STEP * h)
      active[h] = prev
      index[h] = prev
    end
    if opts.fork_from then
      local fprev = active[opts.fork_from]
      for h = opts.fork_from + 1, TIP + 3 do
        -- fork timestamps are wildly different so a wrong-chain read shows
        fprev = add("fork", h, fprev, T0 + STEP * h + 100000)
        index[h] = fprev
      end
    end
    for _, h in ipairs(opts.drop or {}) do headers[active[h].bytes] = nil end
    local storage = {
      get_header = function(hash) return headers[hash.bytes] end,
      get_hash_by_height = function(h) return index[h] end,
    }
    return storage, active
  end

  local function mtp_of(active_heights_ts_h)
    -- MTP of active block at height h (strictly increasing timestamps,
    -- h >= 10): the median of t(h-10..h) = t(h-5).
    return T0 + STEP * (active_heights_ts_h - 5)
  end

  local P2PKH = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"

  local function make_cs(storage, active)
    local utxos = {}
    return {
      tip_height = TIP,
      tip_hash = active[TIP],
      storage = storage,
      network = { csv_height = 1 },
      coin_view = {
        utxos = utxos,
        get = function(self, txid, vout)
          return self.utxos[types.hash256_hex(txid) .. ":" .. vout]
        end,
      },
    }
  end

  local function add_coin(cs, tag, height)
    local txid = types.hash256(string.format("coin%-28s", tag))
    cs.coin_view.utxos[types.hash256_hex(txid) .. ":0"] =
      { value = 100000, script_pubkey = P2PKH, height = height, is_coinbase = false }
    return txid
  end

  local function spend(txid, vout, sequence, version, locktime, value)
    return types.transaction(version or 2,
      { types.txin(types.outpoint(txid, vout), "", sequence) },
      { types.txout(value or 90000, P2PKH) }, locktime or 0)
  end

  -- coin confirmed at 100: coin MTP = MTP(99) = T0 + 94*STEP; tip MTP = T0 + 195*STEP
  -- elapsed = 101 units.  Core: min_time = coin_mtp + L*512 - 1 < tip_mtp  <=>  L <= 101.
  local COIN_H = 100
  local ELAPSED_UNITS = (mtp_of(TIP) - mtp_of(COIN_H - 1)) / STEP

  it("sanity: the fixture's elapsed lock units are 101", function()
    assert.equal(101, ELAPSED_UNITS)
  end)

  it("ACCEPTS a matured time-type relative lock on a confirmed coin (boundary L = elapsed)", function()
    local storage, active = make_chain()
    local cs = make_cs(storage, active)
    local mp = mempool.new(cs)
    local c = add_coin(cs, "a", COIN_H)
    local ok, err = mp:accept_transaction(spend(c, 0, TYPE_FLAG + ELAPSED_UNITS))
    assert.is_true(ok, tostring(err))
  end)

  it("ACCEPTS a long-matured 1-unit time lock on a confirmed coin", function()
    local storage, active = make_chain()
    local cs = make_cs(storage, active)
    local mp = mempool.new(cs)
    local c = add_coin(cs, "b", COIN_H)
    local ok, err = mp:accept_transaction(spend(c, 0, TYPE_FLAG + 1))
    assert.is_true(ok, tostring(err))
  end)

  it("control: REJECTS the same lock one unit past maturity (L = elapsed + 1)", function()
    local storage, active = make_chain()
    local cs = make_cs(storage, active)
    local mp = mempool.new(cs)
    local c = add_coin(cs, "c", COIN_H)
    local ok, err = mp:accept_transaction(spend(c, 0, TYPE_FLAG + ELAPSED_UNITS + 1))
    assert.is_false(ok)
    assert.equal("non-BIP68-final", err)
  end)

  it("control: height lock boundary on a confirmed coin (tip+1 semantics)", function()
    local storage, active = make_chain()
    local cs = make_cs(storage, active)
    local mp = mempool.new(cs)
    -- coin at 100, next block 201: min_height = 100 + L - 1 < 201 <=> L <= 101
    local c1 = add_coin(cs, "h1", COIN_H)
    local ok1, e1 = mp:accept_transaction(spend(c1, 0, 101))
    assert.is_true(ok1, tostring(e1))
    local c2 = add_coin(cs, "h2", COIN_H)
    local ok2, e2 = mp:accept_transaction(spend(c2, 0, 102))
    assert.is_false(ok2)
    assert.equal("non-BIP68-final", e2)
  end)

  it("REJECTS a child of an unconfirmed parent with a height lock of 1 (coin height tip+1)", function()
    local storage, active = make_chain()
    local cs = make_cs(storage, active)
    local mp = mempool.new(cs)
    local c = add_coin(cs, "p", COIN_H)
    local parent = spend(c, 0, 0xFFFFFFFE, 2, 0, 95000)
    local okp, ep = mp:accept_transaction(parent)
    assert.is_true(okp, tostring(ep))
    local ptxid = require("lunarblock.validation").compute_txid(parent)
    local ok, err = mp:accept_transaction(spend(ptxid, 0, 1, 2, 0, 90000))
    assert.is_false(ok)
    assert.equal("non-BIP68-final", err)
    -- control: lock 0 on the same parent is final
    local ok0, e0 = mp:accept_transaction(spend(ptxid, 0, 0, 2, 0, 90000))
    assert.is_true(ok0, tostring(e0))
  end)

  it("REJECTS a child of an unconfirmed parent with a 1-unit time lock (measured from tip MTP)", function()
    local storage, active = make_chain()
    local cs = make_cs(storage, active)
    local mp = mempool.new(cs)
    local c = add_coin(cs, "pt", COIN_H)
    local parent = spend(c, 0, 0xFFFFFFFE, 2, 0, 95000)
    assert.is_true((mp:accept_transaction(parent)))
    local ptxid = require("lunarblock.validation").compute_txid(parent)
    local ok, err = mp:accept_transaction(spend(ptxid, 0, TYPE_FLAG + 1, 2, 0, 90000))
    assert.is_false(ok)
    assert.equal("non-BIP68-final", err)
  end)

  it("nLockTime = tip MTP - 1 is ACCEPTED; = tip MTP is REJECTED non-final (control)", function()
    local storage, active = make_chain()
    local cs = make_cs(storage, active)
    local mp = mempool.new(cs)
    local tip_mtp = mtp_of(TIP)
    local c1 = add_coin(cs, "l1", COIN_H)
    local ok1, e1 = mp:accept_transaction(spend(c1, 0, 0xFFFFFFFE, 2, tip_mtp - 1))
    assert.is_true(ok1, tostring(e1))
    local c2 = add_coin(cs, "l2", COIN_H)
    local ok2, e2 = mp:accept_transaction(spend(c2, 0, 0xFFFFFFFE, 2, tip_mtp))
    assert.is_false(ok2)
    assert.equal("non-final", e2)
  end)

  it("reads the coin MTP from the ACTIVE chain when the height index follows a header fork", function()
    -- index follows a fork above 150 whose timestamps are +100000 s; the coin at
    -- 180 is on the active chain.  Active coin MTP = MTP(179); fork MTP is ~100000 later.
    local storage, active = make_chain({ fork_from = 150 })
    local cs = make_cs(storage, active)
    local mp = mempool.new(cs)
    local units = (mtp_of(TIP) - mtp_of(179)) / STEP   -- 21
    local c = add_coin(cs, "f", 180)
    local ok, err = mp:accept_transaction(spend(c, 0, TYPE_FLAG + units))
    assert.is_true(ok, tostring(err))
    local c2 = add_coin(cs, "f2", 180)
    local ok2, err2 = mp:accept_transaction(spend(c2, 0, TYPE_FLAG + units + 1))
    assert.is_false(ok2)
    assert.equal("non-BIP68-final", err2)
  end)

  it("resolver: active-chain MTP below and above the index/active join point", function()
    local storage, active = make_chain({ fork_from = 150 })
    local cs = make_cs(storage, active)
    local f = mempool._make_active_get_block_mtp(cs, mtp_of(TIP))
    assert.equal(mtp_of(120), f(120))   -- below the join: from the index
    assert.equal(mtp_of(179), f(179))   -- above the join: from the walk
    assert.equal(mtp_of(TIP), f(TIP))
  end)

  it("FAILS CLOSED (refuses, no crash) when the coin's MTP window is not held", function()
    local storage, active = make_chain({ drop = { 92 } })   -- inside MTP(99)'s window
    local cs = make_cs(storage, active)
    local mp = mempool.new(cs)
    local c = add_coin(cs, "m", COIN_H)
    local ok, err = mp:accept_transaction(spend(c, 0, TYPE_FLAG + 1))
    assert.is_false(ok)
    assert.equal("non-BIP68-final", err)
    -- control: a height lock on the same kind of coin is unaffected
    local c2 = add_coin(cs, "m2", COIN_H)
    local ok2, e2 = mp:accept_transaction(spend(c2, 0, 1))
    assert.is_true(ok2, tostring(e2))
  end)

  it("tip MTP window not held: time-based nLockTime refused, plain tx still accepted", function()
    local storage, active = make_chain({ drop = { TIP - 4 } })
    local cs = make_cs(storage, active)
    local mp = mempool.new(cs)
    local c1 = add_coin(cs, "w1", COIN_H)
    local ok1, e1 = mp:accept_transaction(spend(c1, 0, 0xFFFFFFFE, 2, T0))
    assert.is_false(ok1)
    assert.equal("non-final", e1)
    local c2 = add_coin(cs, "w2", COIN_H)
    local ok2, e2 = mp:accept_transaction(spend(c2, 0, 0xFFFFFFFE, 2, 0))
    assert.is_true(ok2, tostring(e2))
  end)
end)
