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
  end)
end)
