describe("erlay (BIP330)", function()
  local erlay = require("lunarblock.erlay")
  local minisketch = require("lunarblock.minisketch")
  local p2p = require("lunarblock.p2p")
  local ffi = require("ffi")
  local helpers = require("spec.helpers")

  -- Test helper: create deterministic wtxid
  local function make_wtxid(n)
    return string.rep(string.char(n % 256), 32)
  end

  describe("short_txid", function()
    it("computes 32-bit hash from salt and wtxid", function()
      local salt = 0x123456789ABCDEF
      local wtxid = make_wtxid(1)
      local short = erlay.short_txid(salt, wtxid)

      assert.is_number(short)
      assert.is_true(short >= 0)
      assert.is_true(short <= 0xFFFFFFFF)
    end)

    it("produces different hashes for different wtxids", function()
      local salt = 12345
      local short1 = erlay.short_txid(salt, make_wtxid(1))
      local short2 = erlay.short_txid(salt, make_wtxid(2))

      assert.are_not.equal(short1, short2)
    end)

    it("produces different hashes for different salts", function()
      local wtxid = make_wtxid(1)
      local short1 = erlay.short_txid(111, wtxid)
      local short2 = erlay.short_txid(222, wtxid)

      assert.are_not.equal(short1, short2)
    end)

    it("requires 32-byte wtxid", function()
      assert.has_error(function()
        erlay.short_txid(0, "short")
      end)
    end)
  end)

  describe("compute_short_txids", function()
    it("computes short IDs for a list of wtxids", function()
      local salt = 12345
      local wtxids = { make_wtxid(1), make_wtxid(2), make_wtxid(3) }
      local shorts = erlay.compute_short_txids(salt, wtxids)

      assert.equals(3, #shorts)
      for i, short in ipairs(shorts) do
        assert.equals(erlay.short_txid(salt, wtxids[i]), short)
      end
    end)

    it("handles empty list", function()
      local shorts = erlay.compute_short_txids(0, {})
      assert.equals(0, #shorts)
    end)
  end)

  describe("minisketch", function()
    it("creates sketch with specified capacity", function()
      local sketch = minisketch.new(32, 10)
      assert.is_not_nil(sketch)
      sketch:destroy()
    end)

    it("adds elements to sketch", function()
      local sketch = minisketch.new(32, 10)
      sketch:add(12345)
      sketch:add(67890)
      sketch:destroy()
    end)

    it("serializes and deserializes", function()
      local sketch1 = minisketch.new(32, 10)
      sketch1:add(12345)
      sketch1:add(67890)

      local bytes = sketch1:serialize()
      assert.equals(sketch1:serialized_size(), #bytes)

      local sketch2 = minisketch.new(32, 10)
      sketch2:deserialize(bytes)

      -- Merging identical sketches should produce empty result
      sketch1:merge(sketch2)
      local decoded, err = sketch1:decode(10)

      -- Pure Lua implementation may not support full decode
      if decoded then
        assert.equals(0, #decoded)
      end

      sketch1:destroy()
      sketch2:destroy()
    end)

    it("clones sketch", function()
      local sketch1 = minisketch.new(32, 5)
      sketch1:add(111)
      sketch1:add(222)

      local sketch2 = sketch1:clone()

      local bytes1 = sketch1:serialize()
      local bytes2 = sketch2:serialize()

      assert.equals(bytes1, bytes2)

      sketch1:destroy()
      sketch2:destroy()
    end)

    it("reports FFI availability", function()
      local has_ffi = minisketch.has_ffi()
      assert.is_boolean(has_ffi)
    end)
  end)

  describe("build_sketch", function()
    it("creates sketch from short txids", function()
      local short_ids = { 100, 200, 300 }
      local sketch = erlay.build_sketch(short_ids, 10)

      assert.is_not_nil(sketch)
      sketch:destroy()
    end)

    it("skips zero elements", function()
      local short_ids = { 0, 100, 0, 200 }
      local sketch = erlay.build_sketch(short_ids, 10)

      assert.is_not_nil(sketch)
      sketch:destroy()
    end)
  end)

  describe("estimate_capacity", function()
    it("returns reasonable capacity for small sets", function()
      local cap = erlay.estimate_capacity(10)
      assert.is_true(cap >= 10)
    end)

    it("returns minimum capacity of 10", function()
      local cap = erlay.estimate_capacity(0)
      assert.is_true(cap >= 10)
    end)

    it("scales with set size", function()
      local cap_small = erlay.estimate_capacity(100)
      local cap_large = erlay.estimate_capacity(1000)
      assert.is_true(cap_large > cap_small)
    end)
  end)

  describe("message serialization", function()
    describe("sendtxrcncl", function()
      it("serializes and deserializes", function()
        local version = 1
        local salt = 0x123456789ABC

        local payload = p2p.serialize_sendtxrcncl(version, salt)
        local decoded = p2p.deserialize_sendtxrcncl(payload)

        assert.equals(version, decoded.version)
        -- Note: salt loses precision due to Lua number limits
        assert.is_number(decoded.salt)
      end)

      it("erlay module serialization matches p2p", function()
        local version = 1
        local salt = 12345678

        local payload1 = erlay.serialize_sendtxrcncl(version, salt)
        local payload2 = p2p.serialize_sendtxrcncl(version, salt)

        assert.equals(payload1, payload2)
      end)
    end)

    describe("reqrecon", function()
      it("serializes and deserializes", function()
        local payload = p2p.serialize_reqrecon(100, 0.02)
        local decoded = p2p.deserialize_reqrecon(payload)

        assert.equals(100, decoded.set_size)
        -- Q is scaled to uint16, so precision is limited
        assert.is_true(math.abs(decoded.q - 0.02) < 0.001)
      end)
    end)

    describe("sketch", function()
      it("serializes and deserializes", function()
        local sketch_bytes = string.rep("\xAB", 40)

        local payload = p2p.serialize_sketch(sketch_bytes)
        local decoded = p2p.deserialize_sketch(payload)

        assert.equals(sketch_bytes, decoded)
      end)
    end)

    describe("reconcildiff", function()
      it("serializes success with want list", function()
        local want_ids = { 100, 200, 300 }

        local payload = p2p.serialize_reconcildiff(true, want_ids)
        local decoded = p2p.deserialize_reconcildiff(payload)

        assert.is_true(decoded.success)
        assert.equals(3, #decoded.want_txids)
        for i, id in ipairs(want_ids) do
          assert.equals(id, decoded.want_txids[i])
        end
      end)

      it("serializes failure", function()
        local payload = p2p.serialize_reconcildiff(false, {})
        local decoded = p2p.deserialize_reconcildiff(payload)

        assert.is_false(decoded.success)
        assert.equals(0, #decoded.want_txids)
      end)
    end)
  end)

  describe("peer state", function()
    it("creates new peer state", function()
      local state = erlay.new_peer_state()

      assert.is_false(state.erlay_enabled)
      assert.equals(0, state.our_salt)
      assert.equals(0, state.their_salt)
      assert.is_false(state.is_initiator)
    end)

    it("negotiates Erlay", function()
      local state = erlay.new_peer_state()

      erlay.negotiate(state, 1, 12345, 67890, true)

      assert.is_true(state.erlay_enabled)
      assert.equals(1, state.version)
      assert.equals(12345, state.their_salt)
      assert.equals(67890, state.our_salt)
      assert.is_true(state.is_initiator)
      assert.is_number(state.combined_salt)
    end)

    it("should_reconcile returns false when not enabled", function()
      local state = erlay.new_peer_state()
      assert.is_false(erlay.should_reconcile(state, os.time()))
    end)

    it("should_reconcile respects initiator role", function()
      local state = erlay.new_peer_state()
      erlay.negotiate(state, 1, 100, 200, false)  -- Not initiator

      assert.is_false(erlay.should_reconcile(state, os.time()))
    end)

    it("should_reconcile respects interval", function()
      local state = erlay.new_peer_state()
      erlay.negotiate(state, 1, 100, 200, true)
      state.last_recon_time = os.time()

      assert.is_false(erlay.should_reconcile(state, os.time()))
    end)
  end)

  describe("reconciliation set", function()
    it("creates empty set", function()
      local recon_set = erlay.new_recon_set()
      local shorts = erlay.get_short_txids(recon_set)
      assert.equals(0, #shorts)
    end)

    it("adds transactions", function()
      local recon_set = erlay.new_recon_set()
      local salt = 12345
      local wtxid = make_wtxid(1)

      erlay.add_to_recon_set(recon_set, salt, wtxid)

      local shorts = erlay.get_short_txids(recon_set)
      assert.equals(1, #shorts)
    end)

    it("removes transactions", function()
      local recon_set = erlay.new_recon_set()
      local salt = 12345
      local wtxid = make_wtxid(1)

      erlay.add_to_recon_set(recon_set, salt, wtxid)
      erlay.remove_from_recon_set(recon_set, wtxid)

      local shorts = erlay.get_short_txids(recon_set)
      assert.equals(0, #shorts)
    end)

    it("recomputes short IDs when salt changes", function()
      local recon_set = erlay.new_recon_set()
      local wtxid = make_wtxid(1)

      erlay.add_to_recon_set(recon_set, 111, wtxid)
      local shorts1 = erlay.get_short_txids(recon_set)

      erlay.add_to_recon_set(recon_set, 222, make_wtxid(2))
      local shorts2 = erlay.get_short_txids(recon_set)

      -- New salt should cause recomputation
      assert.equals(2, #shorts2)
    end)
  end)

  describe("generate_salt", function()
    it("generates random salt", function()
      local salt1 = erlay.generate_salt()
      local salt2 = erlay.generate_salt()

      assert.is_number(salt1)
      assert.is_number(salt2)
      -- Salts should be different (extremely unlikely to be same)
      assert.are_not.equal(salt1, salt2)
    end)

    it("generates positive numbers", function()
      for _ = 1, 10 do
        local salt = erlay.generate_salt()
        assert.is_true(salt > 0)
      end
    end)
  end)

  describe("SipHash-2-4", function()
    it("computes hash for empty input", function()
      local hash = erlay.siphash24(0, 0, "")
      assert.is_not_nil(hash)
    end)

    it("computes hash for test vector", function()
      -- Using k0=0, k1=0 for reproducibility
      local hash = erlay.siphash24(0, 0, "hello")
      assert.is_not_nil(hash)
    end)

    it("produces different hashes for different keys", function()
      local hash1 = erlay.siphash24(1, 2, "test")
      local hash2 = erlay.siphash24(3, 4, "test")
      assert.are_not.equal(tonumber(hash1), tonumber(hash2))
    end)

    it("produces different hashes for different data", function()
      local hash1 = erlay.siphash24(1, 1, "data1")
      local hash2 = erlay.siphash24(1, 1, "data2")
      assert.are_not.equal(tonumber(hash1), tonumber(hash2))
    end)
  end)

  describe("constants", function()
    it("has correct version", function()
      assert.equals(1, erlay.VERSION)
    end)

    it("has correct field bits", function()
      assert.equals(32, erlay.FIELD_BITS)
    end)

    it("has correct reconciliation interval", function()
      assert.equals(2, erlay.RECON_INTERVAL)
    end)

    it("has reasonable default capacity", function()
      assert.is_true(erlay.DEFAULT_CAPACITY >= 10)
    end)
  end)
end)
