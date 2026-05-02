-- Parallel signature verification tests.
--
-- Regression test for the h=944,184 deadlock: pv_verify_signatures used to
-- post jobs onto a separate sig queue that no worker drained, so the main
-- thread blocked forever on pthread_cond_wait(work_done). This spec posts a
-- batch of valid (and a few mixed-validity) sigs and asserts that
-- verify_signatures_parallel returns within a reasonable time. Without the
-- fix, busted hangs forever here.

describe("parallel_verify", function()
  local validation
  local crypto
  local socket

  setup(function()
    package.path = "src/?.lua;" .. package.path
    validation = require("lunarblock.validation")
    crypto = require("lunarblock.crypto")
    socket = require("socket")
  end)

  -- Clean up the worker pool at the end of the suite. Without this, the 31
  -- pthread workers stay sleeping on a condition variable when LuaJIT exits;
  -- on some kernels that produces a SIGSEGV during process teardown that
  -- masks the actual test result.
  teardown(function()
    if validation and validation.parallel_verify_shutdown then
      validation.parallel_verify_shutdown()
    end
  end)

  describe("availability", function()
    it("loads the parallel_verify shared library", function()
      assert.is_true(validation.parallel_verify_available())
    end)

    it("reports a positive worker count", function()
      assert.is_true(validation.parallel_verify_workers() > 0)
    end)
  end)

  describe("verify_signatures_parallel", function()
    -- Build a batch of {pubkey, sig_der, sighash} entries large enough
    -- to trip the parallel path (PARALLEL_THRESHOLD = 16 in validation.lua).
    -- Self-check each sig with single-thread crypto.ecdsa_verify so that a
    -- failure inside verify_signatures_parallel can be attributed to the
    -- parallel pool, not a bad fixture.
    local function make_valid_sigs(n)
      local sigs = {}
      for i = 1, n do
        -- Per-i private key so each entry is distinct.
        -- %064x => 64 hex chars => 32 bytes when decoded. Anything shorter
        -- causes libsecp256k1 to read uninitialised bytes past the buffer
        -- and the sign/verify pair becomes non-deterministic.
        local seed = string.format("%064x", i)
        local privkey = (seed:gsub('..', function(cc)
          return string.char(tonumber(cc, 16))
        end))
        assert(#privkey == 32, "privkey must be 32 bytes")
        local pubkey = crypto.pubkey_from_privkey(privkey, true)
        local sighash = crypto.sha256("parallel verify test message " .. i)
        local sig_der = crypto.ecdsa_sign(privkey, sighash)
        assert(crypto.ecdsa_verify(pubkey, sig_der, sighash),
               string.format("fixture self-check failed at i=%d", i))
        sigs[i] = { pubkey = pubkey, sig_der = sig_der, sighash = sighash }
      end
      return sigs
    end

    it("returns true for an empty batch", function()
      local ok = validation.verify_signatures_parallel({})
      assert.is_true(ok)
    end)

    it("returns true for a single-threaded (under-threshold) batch", function()
      -- 8 < PARALLEL_THRESHOLD (16) => single-threaded path.
      local sigs = make_valid_sigs(8)
      local ok, err = validation.verify_signatures_parallel(sigs)
      assert.is_true(ok, tostring(err))
    end)

    it("returns true for a parallel batch of 32 valid sigs (deadlock regression)", function()
      -- 32 >= PARALLEL_THRESHOLD => parallel path. Pre-fix this hangs.
      local sigs = make_valid_sigs(32)
      local t0 = socket.gettime()
      local ok, err = validation.verify_signatures_parallel(sigs)
      local elapsed = socket.gettime() - t0
      assert.is_true(ok, tostring(err))
      -- Sanity: 32 ECDSA verifies on 31 worker threads should finish in
      -- well under 5 seconds. If we ever take longer than this, the worker
      -- pool is wedged and the deadlock has regressed.
      assert.is_true(elapsed < 5.0,
        string.format("parallel verify took %.3fs (>5s, likely wedged)", elapsed))
    end)

    it("returns false on the first invalid signature in a parallel batch", function()
      local sigs = make_valid_sigs(20)
      -- Corrupt sig at index 7: zero out the DER body so verification fails.
      sigs[7].sig_der = string.rep("\0", #sigs[7].sig_der)
      local ok, err = validation.verify_signatures_parallel(sigs)
      assert.is_false(ok)
      assert.is_string(err)
      assert.matches("signature verification failed", err)
    end)

    it("handles back-to-back batches (worker pool reuse)", function()
      -- Run several sequential batches to confirm the pool services
      -- repeated dispatches and does not lose state between calls. Pre-fix
      -- this would hang on the very first batch; post-fix all four batches
      -- complete promptly.
      for batch = 1, 4 do
        local sigs = make_valid_sigs(20)
        local ok, err = validation.verify_signatures_parallel(sigs)
        assert.is_true(ok, string.format("batch %d failed: %s", batch, tostring(err)))
      end
    end)

    it("accepts high-S signatures via lax DER + S normalization", function()
      -- Regression test for the second h=944,184 wave: after the deadlock
      -- fix landed, parallel verify still failed because the C side parsed
      -- DER with secp256k1_ecdsa_signature_parse_der (strict). Some valid
      -- mainnet sigs trip the strict parser's "silently zero R/S" edge case
      -- and others are high-S (rejected by secp256k1_ecdsa_verify post-LOW_S
      -- without normalization). Bitcoin Core uses lax DER + S normalize for
      -- this exact reason; the C side must match.
      --
      -- We can't easily mint a "strict-rejects, lax-accepts" DER from Lua,
      -- but we *can* construct a high-S signature and confirm the parallel
      -- pool accepts it. If the C verify_ecdsa skipped S normalization the
      -- batch would fail.
      local crypto2 = require("lunarblock.crypto")
      local ffi = require("ffi")
      ffi.cdef[[
        int secp256k1_ecdsa_signature_parse_der(const void *ctx, void *sig, const unsigned char *input, size_t inputlen);
        int secp256k1_ecdsa_signature_serialize_compact(const void *ctx, unsigned char *output64, const void *sig);
      ]]
      -- Library handles already loaded by crypto.lua; we reach in through it.

      -- Build 20 valid sigs, then for one of them compute the *high-S* twin.
      -- secp256k1 returns low-S; we flip S to (n - S) which is the high-S
      -- version of the same signature. The verify must still accept it once
      -- the lax parser normalizes it back.
      local sigs = make_valid_sigs(20)

      -- secp256k1 group order n (big-endian)
      local n_hex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
      local function hex2bytes(h)
        return (h:gsub('..', function(cc) return string.char(tonumber(cc, 16)) end))
      end
      local n_be = hex2bytes(n_hex)

      -- Subtract S from n (big-endian, byte-wise) to flip to high-S.
      local function sub_be(a_be, b_be)
        local out = {}
        local borrow = 0
        for i = #a_be, 1, -1 do
          local av = a_be:byte(i)
          local bv = b_be:byte(i)
          local d = av - bv - borrow
          if d < 0 then d = d + 256; borrow = 1 else borrow = 0 end
          out[i] = string.char(d)
        end
        return table.concat(out)
      end

      -- Decode our DER-encoded sig to extract R and S as 32-byte BE.
      -- We assume secp256k1 output: 0x30 LL 0x02 RL R 0x02 SL S
      local function decode_rs(der)
        local pos = 1
        assert(der:byte(pos) == 0x30); pos = pos + 1
        pos = pos + 1                                  -- seq len
        assert(der:byte(pos) == 0x02); pos = pos + 1   -- R tag
        local rlen = der:byte(pos); pos = pos + 1
        local r = der:sub(pos, pos + rlen - 1); pos = pos + rlen
        assert(der:byte(pos) == 0x02); pos = pos + 1   -- S tag
        local slen = der:byte(pos); pos = pos + 1
        local s = der:sub(pos, pos + slen - 1)
        local function pad32(x)
          while #x > 32 and x:byte(1) == 0 do x = x:sub(2) end
          return string.rep("\0", 32 - #x) .. x
        end
        return pad32(r), pad32(s)
      end

      -- Re-encode R||S(high-S) as DER (always ≤ 72 bytes).
      local function encode_der(r32, s32)
        local function trim_int(x)
          -- Strip leading zeros, then add 0x00 prefix if MSB is set
          local off = 1
          while off < #x and x:byte(off) == 0 do off = off + 1 end
          x = x:sub(off)
          if x:byte(1) >= 0x80 then x = "\0" .. x end
          return x
        end
        local rt = trim_int(r32)
        local st = trim_int(s32)
        local body = "\x02" .. string.char(#rt) .. rt
                  .. "\x02" .. string.char(#st) .. st
        return "\x30" .. string.char(#body) .. body
      end

      -- Pick sig at index 13 and rewrite it as high-S.
      local r32, s32 = decode_rs(sigs[13].sig_der)
      local high_s = sub_be(n_be, s32)
      sigs[13].sig_der = encode_der(r32, high_s)

      local ok, err = validation.verify_signatures_parallel(sigs)
      assert.is_true(ok, "high-S sig should still verify after lax+normalize: " .. tostring(err))
    end)
  end)
end)
