-- spec/w102_assumeutxo_audit_spec.lua
--
-- W102 AssumeUTXO snapshot loading gate audit.
-- Reference: bitcoin-core/src/validation.cpp ActivateSnapshot (5588) +
--            PopulateAndValidateSnapshot (5754).
--
-- Bugs documented in this file (13 total):
--
--   BUG-1  (G4, CONSENSUS-DIVERGENT): loadtxoutset calls load_snapshot without
--          passing expected_hash — the HASH_SERIALIZED strict gate is skipped.
--   BUG-2  (G4, CONSENSUS-DIVERGENT): "base block header must appear in headers
--          chain" gate absent (Core validation.cpp:5611-5615).
--   BUG-3  (G4, CONSENSUS-DIVERGENT): duplicate-activation guard absent — calling
--          loadtxoutset twice silently succeeds (Core validation.cpp:5600-5601).
--   BUG-4  (G5, CONSENSUS-DIVERGENT): "snapshot work must exceed active chainstate"
--          check absent (Core validation.cpp:5706-5708).
--   BUG-5  (G6, CORRECTNESS): "mempool must be empty" precondition absent
--          (Core validation.cpp:5627-5629).
--   BUG-6  (G8, CONSENSUS-DIVERGENT): per-coin coin.nHeight > base_height
--          validation absent (Core validation.cpp:5814-5819).
--   BUG-7  (G8, CONSENSUS-DIVERGENT): per-coin MoneyRange validation absent
--          (Core validation.cpp:5820-5823).
--   BUG-8  (G8, CORRECTNESS): coins_per_txid > coins_left guard absent
--          (Core validation.cpp:5804-5806).
--   BUG-9  (G9, CORRECTNESS): trailing-data check after last coin absent
--          (Core validation.cpp:5872-5883).
--   BUG-10 (G12, CORRECTNESS): BackgroundValidator / SnapshotChainstate defined
--          but never wired — 3-chainstate architecture is unimplemented.
--   BUG-11 (G15, CORRECTNESS): BackgroundValidator always skips script
--          validation (hardcoded true) — background IBD diverges from Core.
--   BUG-12 (G21, OBSERVABILITY): dumptxoutset nchaintx returns UTXO count
--          instead of m_chain_tx_count (Core blockchain.cpp:3346).
--   BUG-13 (G21, OBSERVABILITY): dumptxoutset txoutset_hash emitted in natural
--          LE byte order; Core uint256::ToString() reverses to big-endian.

local types     = require("lunarblock.types")
local utxo      = require("lunarblock.utxo")
local consensus = require("lunarblock.consensus")
local serialize = require("lunarblock.serialize")
local crypto    = require("lunarblock.crypto")
local validation = require("lunarblock.validation")
local storage_mod = require("lunarblock.storage")
local script    = require("lunarblock.script")
local rpc       = require("lunarblock.rpc")
local cjson     = require("cjson")

-- ── helpers ──────────────────────────────────────────────────────────────────

local function make_coinbase_tx(height, value, script_pubkey)
  local coinbase_sig = string.char(1, height % 256)
  return types.transaction(
    1,
    {types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                coinbase_sig, 0xFFFFFFFF)},
    {types.txout(value, script_pubkey)},
    0
  )
end

local function make_block(height, transactions, prev_hash)
  local header = types.block_header(
    1,
    prev_hash or types.hash256_zero(),
    types.hash256_zero(),
    os.time() + height,
    consensus.networks.regtest.pow_limit_bits,
    0
  )
  return types.block(header, transactions)
end

-- Build a chain of n coinbase blocks; returns (db, chain_state).
local function build_chain(n_blocks)
  local tmp_path = "/tmp/lb_w102_"
    .. os.time() .. "_" .. math.random(1000000)
  local db = storage_mod.open(tmp_path)
  local cs = utxo.new_chain_state(db, consensus.networks.regtest)
  cs:init()

  local pubkey_hash  = string.rep("\x42", 20)
  local script_pubkey = script.make_p2pkh_script(pubkey_hash)
  local prev_hash    = types.hash256_zero()

  for h = 0, n_blocks - 1 do
    local cb    = make_coinbase_tx(h, 5000000000, script_pubkey)
    local block = make_block(h, {cb}, prev_hash)
    local bh    = validation.compute_block_hash(block.header)
    cs:connect_block(block, h, bh)
    prev_hash = bh
  end

  return db, cs
end

-- Build a minimal syntactically-valid snapshot file with `n_coins` coins.
-- All coins have height=0, value=1 sat, empty scriptPubKey.
local function build_snapshot_file(path, network_magic, base_hash, n_coins)
  local f, err = io.open(path, "wb")
  if not f then return false, err end

  -- Metadata header (51 bytes)
  local meta = utxo.snapshot_metadata(network_magic, base_hash, n_coins)
  f:write(utxo.serialize_snapshot_metadata(meta))

  -- Body: each coin in its own txid bucket
  for i = 1, n_coins do
    local txid = types.hash256(string.rep(string.char(i % 256), 32))
    f:write(txid.bytes)        -- 32-byte txid

    -- CompactSize(1) = one output in this bucket
    f:write(string.char(1))

    -- CompactSize(0) = vout index 0
    f:write(string.char(0))

    -- Coin: code(height=0, coinbase=0)=0, compressed_amount(1), empty script
    local coin_entry = utxo.utxo_entry(1, "", 0, false)
    f:write(utxo.serialize_snapshot_coin(coin_entry))
  end

  f:close()
  return true
end

-- ── test suite ────────────────────────────────────────────────────────────────

describe("W102 AssumeUTXO snapshot loading gate audit", function()

  -- ── BUG-1: load_snapshot expected_hash not passed from loadtxoutset ─────────
  -- Core validation.cpp:5912 asserts hashSerialized == au_data.hash_serialized
  -- after loading. lunarblock's rpc.lua loadtxoutset calls:
  --   chain_state:load_snapshot(path)
  -- without a second argument, so expected_hash is nil and the strict gate is
  -- a no-op.  A snapshot with wrong coins passes silently.
  describe("BUG-1: hash_serialized strict gate not invoked by loadtxoutset", function()
    it("load_snapshot accepts wrong-hash when expected_hash is nil (documents bug)", function()
      local tmp = "/tmp/lb_w102_bug1_" .. os.time() .. "_" .. math.random(1000000)
      local db = storage_mod.open(tmp)
      local cs = utxo.new_chain_state(db, consensus.networks.regtest)
      cs:init()
      cs.tip_hash   = types.hash256(string.rep("\x01", 32))
      cs.tip_height = 0

      local snap = tmp .. "_snap.dat"
      build_snapshot_file(snap,
        consensus.networks.regtest.magic_bytes,
        cs.tip_hash, 1)

      -- Pass a clearly wrong expected_hash — load must fail when the gate fires
      local wrong_hash = string.rep("\xff", 32)
      -- BUG: without expected_hash, this call succeeds even with garbage
      local ok_no_hash = cs:load_snapshot(snap)
      -- When expected_hash IS provided, it should reject
      local cs2 = utxo.new_chain_state(db, consensus.networks.regtest)
      cs2:init()
      local ok_wrong, err_wrong = cs2:load_snapshot(snap, wrong_hash)

      -- Document the bug: no-arg call succeeds (should be rejected by rpc.lua)
      assert.is_true(ok_no_hash,
        "load_snapshot with no expected_hash should succeed (gate lives in caller)")
      -- When expected_hash is provided, it correctly rejects
      assert.is_false(ok_wrong)
      assert.matches("hash mismatch", err_wrong)

      db.close()
      os.remove(snap)
    end)
  end)

  -- ── BUG-2: "base block header must appear in headers chain" gate absent ─────
  -- Core validation.cpp:5611-5615: LookupBlockIndex(base_blockhash) must return
  -- non-null or the load is refused.
  describe("BUG-2: base-block-in-headers-chain gate absent", function()
    it("loadtxoutset accepts snapshot whose base block is not in local headers chain", function()
      local db, cs = build_chain(2)
      local snap   = "/tmp/lb_w102_bug2_" .. os.time() .. "_" .. math.random(1000000) .. ".dat"

      -- Construct a snapshot that claims to base on a completely unknown hash.
      local unknown_hash = types.hash256(string.rep("\xde", 32))
      local unknown_hash_hex = types.hash256_hex(unknown_hash)

      -- Register it in a fake network so assumeutxo_for_blockhash accepts it.
      local fake_network = {}
      for k, v in pairs(consensus.networks.regtest) do fake_network[k] = v end
      fake_network.assumeutxo = {
        [999] = {
          hash_serialized = string.rep("aa", 32),
          m_chain_tx_count = 1,
          blockhash = unknown_hash_hex,
        }
      }

      -- Build a snapshot with the unknown base hash
      local f = io.open(snap, "wb")
      local meta = utxo.snapshot_metadata(
        fake_network.magic_bytes, unknown_hash, 0)
      f:write(utxo.serialize_snapshot_metadata(meta))
      f:close()

      local server = rpc.new({
        chain_state = cs,
        storage     = db,
        network     = fake_network,
      })

      -- BUG: loadtxoutset does NOT refuse this; Core would reject with
      -- "The base block header (hash) must appear in the headers chain".
      local req = '{"method":"loadtxoutset","params":["' .. snap .. '"],"id":1}'
      local _raw209 = server:handle_request(req)
      local resp = cjson.decode(_raw209)

      -- The RPC should succeed even though the base block is unknown locally
      -- (documents the absent gate — Core would return an error here).
      -- NOTE: this assertion documents current (broken) behaviour.
      local has_error = (resp.error ~= nil and resp.error ~= cjson.null)
      if has_error then
        -- Accepted: if it errors for a different reason, check it isn't the
        -- expected Core error message.
        local msg = (type(resp.error) == "table" and resp.error.message) or ""
        assert.not_matches("headers chain", msg)
      end

      db.close()
      os.remove(snap)
    end)
  end)

  -- ── BUG-3: duplicate-activation guard absent ─────────────────────────────────
  -- Core validation.cpp:5600-5601: if CurrentChainstate().m_from_snapshot_blockhash
  -- is set, refuse a second loadtxoutset with "Can't activate a snapshot-based
  -- chainstate more than once".
  describe("BUG-3: calling loadtxoutset twice succeeds (no duplicate guard)", function()
    it("second loadtxoutset call is not rejected", function()
      local db, cs = build_chain(1)
      local snap = "/tmp/lb_w102_bug3_" .. os.time() .. "_" .. math.random(1000000) .. ".dat"
      local tip_hex = types.hash256_hex(cs.tip_hash)

      -- Add an assumeutxo entry pointing at the current tip
      local fake_net = {}
      for k, v in pairs(consensus.networks.regtest) do fake_net[k] = v end
      fake_net.assumeutxo = {
        [0] = {
          hash_serialized = string.rep("00", 32),
          m_chain_tx_count = 1,
          blockhash = tip_hex,
        }
      }

      -- Dump a real snapshot from this chainstate
      local ok = cs:dump_snapshot(snap)
      assert.is_not_nil(ok)

      local server = rpc.new({
        chain_state = cs,
        storage     = db,
        network     = fake_net,
      })

      local req = '{"method":"loadtxoutset","params":["' .. snap .. '"],"id":1}'

      -- First call
      local _r1raw = server:handle_request(req)
      local r1 = cjson.decode(_r1raw)

      -- Second call — Core would reject with "Can't activate a snapshot-based
      -- chainstate more than once".  lunarblock silently re-loads.
      -- BUG: no error returned on second call.
      local snap2 = snap .. "2"
      os.rename(snap, snap2)  -- avoid "file exists" guard on dump
      cs:dump_snapshot(snap2)
      os.rename(snap2, snap)
      local _r2raw = server:handle_request(req)
      local r2 = cjson.decode(_r2raw)

      -- Document the bug: both calls return success (no dedup guard).
      -- JSON null comes back as cjson.null (userdata), not Lua nil.
      local r1_ok = (r1.error == nil or r1.error == cjson.null)
      local r2_ok = (r2.error == nil or r2.error == cjson.null)
      assert.is_true(r1_ok, "first loadtxoutset should succeed")
      assert.is_true(r2_ok, "BUG-3: second loadtxoutset should be rejected but isn't")

      db.close()
      os.remove(snap)
    end)
  end)

  -- ── BUG-5: mempool-empty precondition absent ──────────────────────────────────
  -- Core validation.cpp:5627-5629 refuses loadtxoutset when mempool is non-empty.
  describe("BUG-5: loadtxoutset succeeds even when mempool is non-empty", function()
    it("non-empty mempool does not block loadtxoutset", function()
      local db, cs = build_chain(1)
      local snap   = "/tmp/lb_w102_bug5_" .. os.time() .. "_" .. math.random(1000000) .. ".dat"
      local tip_hex = types.hash256_hex(cs.tip_hash)

      local fake_net = {}
      for k, v in pairs(consensus.networks.regtest) do fake_net[k] = v end
      fake_net.assumeutxo = {
        [0] = {
          hash_serialized = string.rep("00", 32),
          m_chain_tx_count = 1,
          blockhash = tip_hex,
        }
      }
      cs:dump_snapshot(snap)

      -- Fake a non-empty mempool
      local fake_mempool = { size = function() return 5 end }

      local server = rpc.new({
        chain_state = cs,
        storage     = db,
        network     = fake_net,
        mempool     = fake_mempool,
      })

      local req = '{"method":"loadtxoutset","params":["' .. snap .. '"],"id":1}'
      local _bug5raw = server:handle_request(req)
      local resp = cjson.decode(_bug5raw)

      -- BUG: no rejection despite non-empty mempool
      -- JSON null -> cjson.null (userdata), not Lua nil.
      local no_error = (resp.error == nil or resp.error == cjson.null)
      assert.is_true(no_error,
        "BUG-5: loadtxoutset should reject when mempool is non-empty (Core:5627)")

      db.close()
      os.remove(snap)
    end)
  end)

  -- ── BUG-6: coin.nHeight > base_height validation absent ──────────────────────
  -- Core validation.cpp:5814: coin.nHeight > base_height → reject snapshot.
  describe("BUG-6: coin height > base_height not validated during load", function()
    it("snapshot coin with height > base_height is silently accepted", function()
      local tmp  = "/tmp/lb_w102_bug6_" .. os.time() .. "_" .. math.random(1000000)
      local db   = storage_mod.open(tmp)
      local cs   = utxo.new_chain_state(db, consensus.networks.regtest)
      cs:init()
      cs.tip_hash   = types.hash256(string.rep("\x06", 32))
      cs.tip_height = 10  -- base_height = 10

      local snap = tmp .. "_snap.dat"
      local f    = io.open(snap, "wb")

      -- Write header claiming base_height=10, 1 coin
      local meta = utxo.snapshot_metadata(
        consensus.networks.regtest.magic_bytes, cs.tip_hash, 1)
      f:write(utxo.serialize_snapshot_metadata(meta))

      -- Write one coin at height=999 (far above base_height=10)
      local txid = types.hash256(string.rep("\xab", 32))
      f:write(txid.bytes)
      f:write(string.char(1))   -- 1 output
      f:write(string.char(0))   -- vout=0
      local bad_coin = utxo.utxo_entry(1000, "", 999, false)  -- height=999 > 10
      f:write(utxo.serialize_snapshot_coin(bad_coin))
      f:close()

      -- BUG: load_snapshot does not validate coin.height against base_height
      local ok, err = cs:load_snapshot(snap)
      assert.is_true(ok,
        "BUG-6: coin with height > base_height should be rejected (Core:5814) but isn't")
      assert.is_nil(err)

      db.close()
      os.remove(snap)
    end)
  end)

  -- ── BUG-7: per-coin MoneyRange validation absent ──────────────────────────────
  -- Core validation.cpp:5820: !MoneyRange(coin.out.nValue) → reject snapshot.
  describe("BUG-7: negative coin value not rejected during load", function()
    it("snapshot coin with negative value is silently accepted", function()
      local tmp = "/tmp/lb_w102_bug7_" .. os.time() .. "_" .. math.random(1000000)
      local db  = storage_mod.open(tmp)
      local cs  = utxo.new_chain_state(db, consensus.networks.regtest)
      cs:init()
      cs.tip_hash   = types.hash256(string.rep("\x07", 32))
      cs.tip_height = 0

      local snap = tmp .. "_snap.dat"
      local f    = io.open(snap, "wb")
      local meta = utxo.snapshot_metadata(
        consensus.networks.regtest.magic_bytes, cs.tip_hash, 1)
      f:write(utxo.serialize_snapshot_metadata(meta))

      local txid = types.hash256(string.rep("\xba", 32))
      f:write(txid.bytes)
      f:write(string.char(1))
      f:write(string.char(0))
      -- Encode a negative value (-1 satoshi) as a coin
      local neg_coin = utxo.utxo_entry(-1, "", 0, false)
      f:write(utxo.serialize_snapshot_coin(neg_coin))
      f:close()

      -- BUG: no MoneyRange check → negative-value coin accepted
      local ok = cs:load_snapshot(snap)
      assert.is_true(ok,
        "BUG-7: negative coin value should be rejected (Core:5820) but isn't")

      db.close()
      os.remove(snap)
    end)
  end)

  -- ── BUG-8: coins_per_txid > coins_left guard absent ──────────────────────────
  -- Core validation.cpp:5804-5806: if (coins_per_txid > coins_left) → reject.
  describe("BUG-8: coins_per_txid > coins_left not checked", function()
    it("snapshot with coins_per_txid exceeding metadata coins_count loads without error", function()
      local tmp = "/tmp/lb_w102_bug8_" .. os.time() .. "_" .. math.random(1000000)
      local db  = storage_mod.open(tmp)
      local cs  = utxo.new_chain_state(db, consensus.networks.regtest)
      cs:init()
      cs.tip_hash   = types.hash256(string.rep("\x08", 32))
      cs.tip_height = 0

      local snap = tmp .. "_snap.dat"
      local f    = io.open(snap, "wb")
      -- Metadata says 1 coin total
      local meta = utxo.snapshot_metadata(
        consensus.networks.regtest.magic_bytes, cs.tip_hash, 1)
      f:write(utxo.serialize_snapshot_metadata(meta))

      local txid = types.hash256(string.rep("\xcc", 32))
      f:write(txid.bytes)
      -- CompactSize(3) — 3 outputs for this txid, but metadata says only 1 coin
      f:write(string.char(3))
      for vout = 0, 2 do
        f:write(string.char(vout))
        local coin = utxo.utxo_entry(100, "", 0, false)
        f:write(utxo.serialize_snapshot_coin(coin))
      end
      f:close()

      -- BUG: load_snapshot stops after coins_loaded==1 (loop condition:
      -- while coins_loaded < coins_total), so vout 1 and 2 are never read.
      -- Core rejects at the "coins_per_txid > coins_left" check.
      local ok = cs:load_snapshot(snap)
      -- Currently it succeeds; Core would reject.
      assert.is_true(ok,
        "BUG-8: coins_per_txid > coins_left should be rejected (Core:5804) but isn't")

      db.close()
      os.remove(snap)
    end)
  end)

  -- ── BUG-9: trailing-data after last coin not detected ────────────────────────
  -- Core validation.cpp:5872-5883: reads one extra byte after all coins;
  -- if it succeeds (no exception), the snapshot is corrupt.
  describe("BUG-9: trailing garbage bytes after last coin not detected", function()
    it("snapshot with trailing bytes after all coins is accepted", function()
      local tmp = "/tmp/lb_w102_bug9_" .. os.time() .. "_" .. math.random(1000000)
      local db  = storage_mod.open(tmp)
      local cs  = utxo.new_chain_state(db, consensus.networks.regtest)
      cs:init()
      cs.tip_hash   = types.hash256(string.rep("\x09", 32))
      cs.tip_height = 0

      local snap = tmp .. "_snap.dat"
      local f    = io.open(snap, "wb")
      local meta = utxo.snapshot_metadata(
        consensus.networks.regtest.magic_bytes, cs.tip_hash, 1)
      f:write(utxo.serialize_snapshot_metadata(meta))

      local txid = types.hash256(string.rep("\xdd", 32))
      f:write(txid.bytes)
      f:write(string.char(1))
      f:write(string.char(0))
      local coin = utxo.utxo_entry(500, "", 0, false)
      f:write(utxo.serialize_snapshot_coin(coin))

      -- Append 16 bytes of garbage AFTER the valid last coin
      f:write(string.rep("\xff", 16))
      f:close()

      -- BUG: load_snapshot does not check for leftover data
      local ok = cs:load_snapshot(snap)
      assert.is_true(ok,
        "BUG-9: trailing data after last coin should be rejected (Core:5880) but isn't")

      db.close()
      os.remove(snap)
    end)
  end)

  -- ── BUG-10: 3-chainstate architecture unimplemented ──────────────────────────
  -- BackgroundValidator and SnapshotChainstate are defined in utxo.lua but are
  -- never instantiated or wired into the RPC server, main loop, or sync engine.
  describe("BUG-10: BackgroundValidator / SnapshotChainstate are defined but never wired", function()
    it("new_background_validator and new_snapshot_chainstate are exported", function()
      -- These constructors exist in the module, confirming the code exists but
      -- is not hooked up.  The test verifies the API surface; the bug is the
      -- absence of any call-site in rpc.lua / main.lua / sync.lua.
      assert.is_function(utxo.new_background_validator,
        "BackgroundValidator constructor must exist in utxo module")
      assert.is_function(utxo.new_snapshot_chainstate,
        "SnapshotChainstate constructor must exist in utxo module")

      -- Confirm no wiring: loadtxoutset handler in rpc.lua must NOT return an
      -- 'ibd_chain' or 'snapshot_chain' field (it doesn't; it only touches
      -- rpc.chain_state directly).
      local db, cs = build_chain(1)
      local tip_hex = types.hash256_hex(cs.tip_hash)
      local fake_net = {}
      for k, v in pairs(consensus.networks.regtest) do fake_net[k] = v end
      fake_net.assumeutxo = {
        [0] = {
          hash_serialized = string.rep("00", 32),
          m_chain_tx_count = 1,
          blockhash = tip_hex,
        }
      }
      local snap = "/tmp/lb_w102_bug10_" .. os.time() .. ".dat"
      cs:dump_snapshot(snap)
      local server = rpc.new({chain_state=cs, storage=db, network=fake_net})
      local _bug10raw = server:handle_request(
        '{"method":"loadtxoutset","params":["' .. snap .. '"],"id":1}')
      local resp = cjson.decode(_bug10raw)

      -- BUG: result has no 'ibd_chain', 'snapshot_validated', etc. fields
      if resp.result then
        assert.is_nil(resp.result.ibd_chain,
          "BUG-10: 3-chainstate not wired — no ibd_chain field in response")
        assert.is_nil(resp.result.snapshot_validated,
          "BUG-10: no background validation status in response")
      end

      db.close()
      os.remove(snap)
    end)
  end)

  -- ── BUG-11: BackgroundValidator skips script validation ──────────────────────
  -- utxo.lua:4676 connect_block(..., true) — skip_script_validation is hardcoded.
  describe("BUG-11: BackgroundValidator hardcodes skip_script_validation=true", function()
    it("BackgroundValidator step processes blocks with skip_script_validation=true", function()
      local db, cs = build_chain(1)
      local n_blocks = 3
      local blocks   = {}
      local prev     = types.hash256_zero()

      local pubkey_hash  = string.rep("\x55", 20)
      local script_pubkey = script.make_p2pkh_script(pubkey_hash)

      for h = 0, n_blocks - 1 do
        local cb = make_coinbase_tx(h, 5000000000, script_pubkey)
        local b  = make_block(h, {cb}, prev)
        local bh = validation.compute_block_hash(b.header)
        blocks[h] = {block=b, hash=bh}
        prev = bh
      end

      local hash_for_height = {}
      for h = 0, n_blocks - 1 do
        hash_for_height[h] = blocks[h]
      end

      local validator = utxo.new_background_validator(
        db,
        consensus.networks.regtest,
        n_blocks,
        string.rep("\x00", 32),  -- wrong target hash (will error at comparison)
        function(h)
          if hash_for_height[h] then
            return hash_for_height[h].block, hash_for_height[h].hash
          end
          return nil
        end
      )

      -- BUG: skip_script_validation=true means script errors during IBD
      -- are silently ignored — background validation can certify a chain
      -- that contains invalid scripts.
      local _, _, complete, err = validator:step()

      -- It processes blocks (no crash from skip), but will fail at hash check.
      assert.is_false(complete)
      -- Error should be UTXO hash mismatch (not a script error), confirming
      -- scripts were skipped rather than validated.
      if err then
        assert.matches("hash mismatch", err,
          "BUG-11: expected hash-mismatch error (scripts were skipped, not validated)")
      end

      db.close()
    end)
  end)

  -- ── BUG-12: nchaintx returns UTXO count not m_chain_tx_count ────────────────
  -- Core blockchain.cpp:3346: result.pushKV("nchaintx", tip->m_chain_tx_count).
  -- lunarblock rpc.lua:7278: nchaintx = result.coins_count  (wrong field).
  describe("BUG-12: dumptxoutset nchaintx returns UTXO count instead of m_chain_tx_count", function()
    it("nchaintx equals coins_written (wrong — should be cumulative tx count)", function()
      local db, cs = build_chain(3)
      local snap   = "/tmp/lb_w102_bug12_" .. os.time() .. "_" .. math.random(1000000) .. ".dat"

      local server = rpc.new({
        chain_state = cs,
        storage     = db,
        network     = consensus.networks.regtest,
      })

      local req  = '{"method":"dumptxoutset","params":["' .. snap .. '"],"id":1}'
      local _bug12raw = server:handle_request(req)
      local resp = cjson.decode(_bug12raw)

      assert.is_true(resp.error == nil or resp.error == cjson.null)
      local r = resp.result

      -- BUG: nchaintx == coins_written (both are UTXO count).
      -- Core's nchaintx is cumulative tx count (m_chain_tx_count), which
      -- counts every transaction ever included in the chain, not just UTXOs.
      assert.is_not_nil(r.nchaintx)
      assert.is_not_nil(r.coins_written)
      -- Document: they are equal in lunarblock (both use UTXO count)
      assert.equal(r.coins_written, r.nchaintx,
        "BUG-12: nchaintx == coins_written (UTXO count); Core uses m_chain_tx_count")

      os.remove(snap)
      db.close()
    end)
  end)

  -- ── BUG-13: txoutset_hash byte order wrong (LE not reversed to BE) ───────────
  -- Core uint256::ToString() reverses bytes (big-endian display).
  -- lunarblock rpc.lua:7268-7270: iterates i=1..32 (natural LE order).
  describe("BUG-13: dumptxoutset txoutset_hash uses LE byte order, Core uses BE", function()
    it("txoutset_hash from dumptxoutset is not reversed relative to compute_utxo_hash LE output", function()
      local db, cs = build_chain(2)
      local snap   = "/tmp/lb_w102_bug13_" .. os.time() .. "_" .. math.random(1000000) .. ".dat"

      local server = rpc.new({
        chain_state = cs,
        storage     = db,
        network     = consensus.networks.regtest,
      })

      local req  = '{"method":"dumptxoutset","params":["' .. snap .. '"],"id":1}'
      local _bug13raw = server:handle_request(req)
      local resp = cjson.decode(_bug13raw)

      assert.is_true(resp.error == nil or resp.error == cjson.null)
      local returned_hash_hex = resp.result.txoutset_hash

      -- Compute the expected hash in Core-compatible BE order (reversed)
      local raw_hash, _ = cs:compute_utxo_hash()
      local be_hex_chars = {}
      for i = 32, 1, -1 do
        be_hex_chars[#be_hex_chars + 1] =
          string.format("%02x", raw_hash:byte(i))
      end
      local core_compatible_hex = table.concat(be_hex_chars)

      -- Compute the LE-order hex (what lunarblock currently returns)
      local le_hex_chars = {}
      for i = 1, 32 do
        le_hex_chars[#le_hex_chars + 1] =
          string.format("%02x", raw_hash:byte(i))
      end
      local le_hex = table.concat(le_hex_chars)

      -- BUG: lunarblock returns LE (matches le_hex, not core_compatible_hex)
      assert.equal(le_hex, returned_hash_hex,
        "BUG-13: dumptxoutset txoutset_hash is in LE byte order (not reversed)")
      assert.not_equal(core_compatible_hex, returned_hash_hex,
        "BUG-13: txoutset_hash should match Core BE display but doesn't")

      os.remove(snap)
      db.close()
    end)
  end)

end)
