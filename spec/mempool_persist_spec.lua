local types = require("lunarblock.types")
local mempool = require("lunarblock.mempool")
local mempool_persist = require("lunarblock.mempool_persist")
local serialize = require("lunarblock.serialize")
local validation = require("lunarblock.validation")
local helpers = require("spec.helpers")

describe("mempool_persist (Bitcoin Core compatible)", function()

  -- ---------------------------------------------------------------------
  -- Fixtures (mirrors mempool_spec.lua's mock helpers; we don't depend on
  -- that file at runtime, just reproduce the few helpers we need here.)
  -- ---------------------------------------------------------------------
  local function make_tx(version, inputs, outputs, locktime)
    return types.transaction(version or 1, inputs or {}, outputs or {}, locktime or 0)
  end
  local function make_input(txid_hash, vout, sequence)
    return types.txin(types.outpoint(txid_hash, vout), "",
      sequence or 0xFFFFFFFE)
  end
  local function make_output(value, script_pubkey)
    return types.txout(value, script_pubkey or string.rep("\x00", 25))
  end
  local function make_mock_chain_state(utxos)
    utxos = utxos or {}
    local mock_coin_view = {
      utxos = utxos,
      get = function(self, txid, vout)
        local key = types.hash256_hex(txid) .. ":" .. vout
        return self.utxos[key]
      end
    }
    return { coin_view = mock_coin_view, tip_height = 700000 }
  end
  local function add_utxo(chain_state, txid_hex, vout, value)
    local key = txid_hex .. ":" .. vout
    chain_state.coin_view.utxos[key] = {
      value = value,
      script_pubkey = string.rep("\x00", 25),
      height = 500000,
      is_coinbase = false,
    }
  end

  -- Build a trivial accepted tx so we have a real Mempool entry to dump.
  local function build_accepted_mempool()
    local mp_chain = make_mock_chain_state()
    local prev_txid = types.hash256(string.rep("\xaa", 32))
    add_utxo(mp_chain, types.hash256_hex(prev_txid), 0, 100000)
    local mp = mempool.new(mp_chain)

    local tx = make_tx(1, {}, {}, 0)
    tx.inputs[1] = make_input(prev_txid, 0)
    tx.outputs[1] = make_output(90000)
    local ok, txid_hex = mp:accept_transaction(tx)
    assert.is_true(ok)
    return mp, tx, txid_hex
  end

  -- ---------------------------------------------------------------------
  -- XOR helper
  -- ---------------------------------------------------------------------
  describe("xor_obfuscate", function()
    it("is a no-op on the all-zero key (matches Core's identity case)", function()
      local payload = "hello, world"
      assert.equal(payload, mempool_persist.xor_obfuscate(payload, "\0\0\0\0\0\0\0\0"))
    end)

    it("is its own inverse with any 8-byte key", function()
      local payload = "the quick brown fox jumps over the lazy dog"
      local key = "\x01\x02\x03\x04\x05\x06\x07\x08"
      local once = mempool_persist.xor_obfuscate(payload, key)
      assert.not_equal(payload, once)
      local twice = mempool_persist.xor_obfuscate(once, key)
      assert.equal(payload, twice)
    end)
  end)

  -- ---------------------------------------------------------------------
  -- Format: header bytes match Core's layout exactly.
  -- ---------------------------------------------------------------------
  describe("encode_dump header", function()
    it("starts with version u64 LE and an 8-byte key for v2", function()
      local entries = {}
      local key = "\x10\x20\x30\x40\x50\x60\x70\x80"
      local data = mempool_persist.encode_dump(entries, { xor_key = key })
      -- u64le(2) = 02 00 00 00 00 00 00 00
      assert.equal(string.char(2, 0, 0, 0, 0, 0, 0, 0), data:sub(1, 8))
      -- compactsize(8) = 0x08
      assert.equal(string.char(8), data:sub(9, 9))
      -- 8-byte key
      assert.equal(key, data:sub(10, 17))
      -- payload (count=0) is XOR'd; count u64=0 XOR'd with key cycles
      -- to a string equal to key (cycle=1 of key here).
      assert.equal(key, data:sub(18, 25))
    end)

    it("emits version 1 with no key when requested", function()
      local data = mempool_persist.encode_dump({}, { version = 1 })
      assert.equal(string.char(1, 0, 0, 0, 0, 0, 0, 0), data:sub(1, 8))
      -- Payload is unobfuscated; count=0 -> 8 bytes of zero.
      assert.equal(string.rep("\0", 8), data:sub(9, 16))
    end)
  end)

  -- ---------------------------------------------------------------------
  -- Round-trip: encode_dump -> decode_dump preserves the snapshot.
  -- ---------------------------------------------------------------------
  describe("encode_dump <-> decode_dump", function()
    it("round-trips an empty mempool", function()
      local data = mempool_persist.encode_dump({}, { xor_key = "\x55\x55\x55\x55\xaa\xaa\xaa\xaa" })
      local parsed, err = mempool_persist.decode_dump(data)
      assert.is_nil(err)
      assert.equal(0, #parsed.entries)
      assert.equal(2, parsed.version)
    end)

    it("round-trips a single-tx mempool snapshot byte-exactly", function()
      local mp, tx, txid_hex = build_accepted_mempool()
      local entries = mempool_persist.snapshot(mp)
      assert.equal(1, #entries)

      local data = mempool_persist.encode_dump(entries, {
        xor_key = "\x01\x23\x45\x67\x89\xab\xcd\xef",
      })
      local parsed, err = mempool_persist.decode_dump(data)
      assert.is_nil(err)
      assert.equal(1, #parsed.entries)

      local round = parsed.entries[1]
      assert.equal(serialize.serialize_transaction(tx, true),
                   serialize.serialize_transaction(round.tx, true))
      local round_txid = validation.compute_txid(round.tx)
      assert.equal(txid_hex, types.hash256_hex(round_txid))
    end)

    it("decodes v1 (unobfuscated) dumps", function()
      local mp = build_accepted_mempool()
      local entries = mempool_persist.snapshot(mp)
      local data = mempool_persist.encode_dump(entries, { version = 1 })
      local parsed = mempool_persist.decode_dump(data)
      assert.equal(1, parsed.version)
      assert.equal(1, #parsed.entries)
    end)

    it("round-trips map_deltas and unbroadcast sets", function()
      local txid1 = types.hash256_hex(types.hash256(string.rep("\x11", 32)))
      local txid2 = types.hash256_hex(types.hash256(string.rep("\x22", 32)))
      local data = mempool_persist.encode_dump({}, {
        map_deltas = { [txid1] = 1234, [txid2] = -5678 },
        unbroadcast = { txid1 },
        xor_key = "\x00\x01\x02\x03\x04\x05\x06\x07",
      })
      local parsed = mempool_persist.decode_dump(data)
      assert.equal(1234, parsed.map_deltas[txid1])
      assert.equal(-5678, parsed.map_deltas[txid2])
      assert.equal(1, #parsed.unbroadcast)
      assert.equal(txid1, parsed.unbroadcast[1])
    end)

    it("rejects an unknown version", function()
      local bogus = string.char(99, 0, 0, 0, 0, 0, 0, 0) .. string.rep("\0", 16)
      local parsed, err = mempool_persist.decode_dump(bogus)
      assert.is_nil(parsed)
      assert.truthy(err:match("unknown"))
    end)
  end)

  -- ---------------------------------------------------------------------
  -- File-level dump+load via Mempool helpers.
  -- ---------------------------------------------------------------------
  describe("Mempool dump + load", function()
    it("writes mempool.dat and reloads it into a fresh mempool", function()
      local mp, tx, txid_hex = build_accepted_mempool()
      local tmpdir = helpers.tmpdir()
      local path = tmpdir .. "/mempool.dat"
      finally(function() helpers.cleanup(tmpdir) end)

      local ok, written = mempool_persist.dump(mp, path)
      assert.is_true(ok)
      assert.equal(1, written)

      -- File exists.
      local f = io.open(path, "rb")
      assert.is_not_nil(f)
      local data = f:read("*a"); f:close()
      assert.is_true(#data > 0)

      -- The .new tempfile has been renamed away.
      local tmp = io.open(path .. ".new", "rb")
      assert.is_nil(tmp)

      -- Build a fresh mempool with the same UTXO so accept_transaction
      -- succeeds, then load.  We have to stand up the same coin_view
      -- the original tx referenced.
      local prev_hash_hex = types.hash256_hex(tx.inputs[1].prev_out.hash)
      local fresh_chain = make_mock_chain_state()
      add_utxo(fresh_chain, prev_hash_hex, tx.inputs[1].prev_out.index, 100000)
      local mp2 = mempool.new(fresh_chain)
      assert.equal(0, mp2.tx_count)

      local lok, stats = mempool_persist.load(mp2, path, { now = os.time() })
      assert.is_true(lok)
      assert.equal(1, stats.count)
      assert.equal(0, stats.failed)
      assert.is_not_nil(mp2:get_entry(txid_hex))
    end)

    it("load returns false when the file is missing", function()
      local mp_chain = make_mock_chain_state()
      local mp = mempool.new(mp_chain)
      local ok, err = mempool_persist.load(mp, "/nonexistent/mempool.dat")
      assert.is_false(ok)
      assert.is_string(err)
    end)

    it("load skips entries older than the expiry window", function()
      local mp, tx = build_accepted_mempool()
      local tmpdir = helpers.tmpdir()
      local path = tmpdir .. "/mempool.dat"
      finally(function() helpers.cleanup(tmpdir) end)

      -- Manually back-date the entry's `time` to 100 days ago, then dump.
      for _, entry in pairs(mp.entries) do
        entry.time = os.time() - (100 * 24 * 3600)
      end
      assert.is_true(mempool_persist.dump(mp, path))

      local prev_hash_hex = types.hash256_hex(tx.inputs[1].prev_out.hash)
      local fresh_chain = make_mock_chain_state()
      add_utxo(fresh_chain, prev_hash_hex, tx.inputs[1].prev_out.index, 100000)
      local mp2 = mempool.new(fresh_chain)

      -- Default expiry = 14 days, so 100-day-old entry must be dropped.
      local lok, stats = mempool_persist.load(mp2, path)
      assert.is_true(lok)
      assert.equal(0, stats.count)
      assert.equal(1, stats.expired)
    end)
  end)

end)
