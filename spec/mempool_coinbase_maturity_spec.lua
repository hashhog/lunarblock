-- Reorg eviction: Core MaybeUpdateMempoolForReorg -> removeForReorg
-- (filter_final_and_mature) re-checks every entry against the NEW tip.
-- Pre-fix (4ab752a) lunarblock re-added the disconnected blocks' txs but never
-- re-checked the entries already in the pool.
-- Fixture notes from the time-lock spec follow.
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

describe("mempool coinbase maturity at tip+1", function()
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


  it("coinbase maturity is judged at tip+1 (Core CheckTxInputs nSpendHeight): 100 confs at the next block ACCEPTED, 99 REJECTED", function()
    local storage, active = make_chain()
    local cs = make_cs(storage, active)
    local mp = mempool.new(cs)
    local c = add_coin(cs, "cb2", 101)     -- 201 - 101 = 100
    cs.coin_view.utxos[types.hash256_hex(c) .. ":0"].is_coinbase = true
    local ok, err = mp:accept_transaction(spend(c, 0, 0xFFFFFFFE, 2, 0, 90000))
    assert.is_true(ok, tostring(err))
    local c2 = add_coin(cs, "cb3", 102)    -- 201 - 102 = 99
    cs.coin_view.utxos[types.hash256_hex(c2) .. ":0"].is_coinbase = true
    local ok2, err2 = mp:accept_transaction(spend(c2, 0, 0xFFFFFFFE, 2, 0, 90000))
    assert.is_false(ok2)
    assert.equal("bad-txns-premature-spend-of-coinbase", err2)
  end)
end)
