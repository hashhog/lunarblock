-- Mempool:has_wtxid must be an indexed lookup, not a scan of the mempool.
--
-- The MSG_WTX inv handler (main.lua) calls has_wtxid once per announced item
-- that is not already in the mempool.  Once lunarblock started sending
-- wtxidrelay (c95cd22), every modern Core peer announces with MSG_WTX, so this
-- runs for nearly every tx announcement on mainnet.  The old implementation
-- walked self.entries and hex-encoded every entry's wtxid: ~33 ms per miss at
-- 7k entries.  At mainnet announcement rates that saturated the single-threaded
-- event loop; peers' sockets backed up to MB of unread tx traffic, the one
-- requested block sat behind it past every stall timeout, and RPC timed out
-- (mainnet stalls at 968709 and 968725 on 2026-09-26).
--
-- Core: AlreadyHaveTx -> m_mempool.exists(Wtxid) (net_processing.cpp), which is
-- an index lookup.

local types = require("lunarblock.types")
local mempool_mod = require("lunarblock.mempool")
local validation = require("lunarblock.validation")

local function mock_chain_state()
  local utxos = {}
  return {
    coin_view = {
      utxos = utxos,
      get = function(self, txid, vout)
        return self.utxos[types.hash256_hex(txid) .. ":" .. vout]
      end,
    },
    tip_height = 700000,
  }, utxos
end

local P2WPKH_A = "\x00\x14" .. string.rep("\x11", 20)
local P2WPKH_B = "\x00\x14" .. string.rep("\x22", 20)
local P2PKH = "\x76\xa9\x14" .. string.rep("\x00", 20) .. "\x88\xac"

local function setup()
  local cs, utxos = mock_chain_state()
  local prev1 = types.hash256(string.rep("\x01", 32))
  local prev2 = types.hash256(string.rep("\x02", 32))
  utxos[types.hash256_hex(prev1) .. ":0"] =
    { value = 100000, script_pubkey = P2WPKH_A, height = 500000, is_coinbase = false }
  utxos[types.hash256_hex(prev2) .. ":0"] =
    { value = 100000, script_pubkey = P2PKH, height = 500000, is_coinbase = false }
  local mp = mempool_mod.new(cs)

  local sw = types.transaction(2,
    { types.txin(types.outpoint(prev1, 0), "", 0xFFFFFFFD) },
    { types.txout(90000, P2WPKH_B) }, 0)
  sw.inputs[1].witness = { string.rep("\x30", 71), "\x02" .. string.rep("\x33", 32) }
  sw.segwit = true
  assert.is_true((mp:accept_transaction(sw)))

  local legacy = types.transaction(1,
    { types.txin(types.outpoint(prev2, 0), "", 0xFFFFFFFE) },
    { types.txout(90000, P2PKH) }, 0)
  assert.is_true((mp:accept_transaction(legacy)))

  return mp, sw, legacy
end

local function hex(h) return types.hash256_hex(h) end

-- Deterministic 32-byte string for filler entries.
local function filler_bytes(i, salt)
  local s = string.format("%08x%s", i, salt)
  return (s .. string.rep("\0", 32)):sub(1, 32)
end

describe("Mempool:has_wtxid (BIP-339 inv dedup) is an index lookup", function()
  local mp, sw, legacy
  before_each(function()
    mp, sw, legacy = setup()
  end)

  it("finds a segwit tx by its wtxid (txid ~= wtxid)", function()
    local wtxid = hex(validation.compute_wtxid(sw))
    assert.not_equal(hex(validation.compute_txid(sw)), wtxid)
    assert.is_true(mp:has_wtxid(wtxid))
  end)

  it("finds a legacy tx by its wtxid (== txid)", function()
    assert.is_true(mp:has_wtxid(hex(validation.compute_wtxid(legacy))))
  end)

  it("does not report an unknown wtxid", function()
    assert.is_false(mp:has_wtxid(string.rep("ab", 32)))
  end)

  it("does not match a segwit tx by its txid", function()
    -- A MSG_WTX inv carrying a segwit tx's TXID names a different wtxid.
    assert.is_false(mp:has_wtxid(hex(validation.compute_txid(sw))))
  end)

  it("forgets a segwit tx once it leaves the mempool", function()
    local wtxid = hex(validation.compute_wtxid(sw))
    mp:remove_transaction(hex(validation.compute_txid(sw)))
    assert.is_false(mp:has_wtxid(wtxid))
  end)

  it("does not walk the mempool on a miss (hash256_hex call count is O(1))", function()
    -- 5,000 filler segwit-shaped entries, the size of the mainnet mempool when
    -- the event loop wedged.  Inserted directly: the point is what a MISS
    -- costs, and the old scan hex-encoded every entry's wtxid.
    for i = 1, 5000 do
      local txid = types.hash256(filler_bytes(i, "t"))
      mp.entries[hex(txid)] = { wtxid = types.hash256(filler_bytes(i, "w")) }
    end
    local real = types.hash256_hex
    local calls = 0
    types.hash256_hex = function(h) calls = calls + 1; return real(h) end
    local ok, res = pcall(function()
      local miss = mp:has_wtxid(string.rep("cd", 32))
      local hit = mp:has_wtxid(real(validation.compute_wtxid(sw)))
      return { miss = miss, hit = hit }
    end)
    types.hash256_hex = real
    assert.is_true(ok, tostring(res))
    assert.is_false(res.miss)
    assert.is_true(res.hit)
    -- Old scan: ~5,000 calls for the miss alone.  Indexed: at most one
    -- re-verification per lookup path.
    assert.is_true(calls <= 4, "has_wtxid hex-encoded " .. calls .. " wtxids")
  end)
end)
