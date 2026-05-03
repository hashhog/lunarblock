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

  -- CHECKMULTISIG correctness gate (2026-05-02). Regression for the silent-
  -- pass collector: pre-fix, make_collecting_sig_checker.check_sig returned
  -- true for every (sig, pubkey) tuple, so OP_CHECKMULTISIG's m-of-n trial
  -- pairing in script.lua advanced isig on FAILED pairs and then the batch
  -- ECDSA pass at end-of-block rejected the wrong tuples. Post-fix, the
  -- inline_verify flag drives check_sig to do real ECDSA inline, mirroring
  -- make_sig_checker exactly so the trial-pairing loop sees real results.
  describe("multisig collector inline-verify", function()
    local script
    local types
    local serialize

    setup(function()
      script = require("lunarblock.script")
      types = require("lunarblock.types")
      serialize = require("lunarblock.serialize")
    end)

    -- Helper: build a synthetic m-of-n multisig redeem script and a
    -- transaction that spends a P2SH output wrapping it. Returns the tx,
    -- the redeem script, and the per-key (privkey, pubkey, sig) triples.
    local function build_multisig_tx(m, n, sign_indexes)
      local prev_hash = types.hash256(string.rep("\xab", 32))
      local tx = types.transaction(1, {}, {}, 0)
      tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "", 0xFFFFFFFF)
      tx.outputs[1] = types.txout(100000, string.rep("\x00", 22))

      -- Generate n keys.
      local keys = {}
      for i = 1, n do
        local seed = string.format("%064x", 0xC0DE0000 + i)
        local privkey = (seed:gsub('..', function(cc)
          return string.char(tonumber(cc, 16))
        end))
        local pubkey = crypto.pubkey_from_privkey(privkey, true)
        keys[i] = { privkey = privkey, pubkey = pubkey }
      end

      -- Build the m-of-n redeem script:
      -- OP_<m> <pk1> <pk2> ... <pkn> OP_<n> OP_CHECKMULTISIG
      local parts = { string.char(0x50 + m) }  -- OP_m
      for i = 1, n do
        parts[#parts + 1] = string.char(33)
        parts[#parts + 1] = keys[i].pubkey
      end
      parts[#parts + 1] = string.char(0x50 + n)  -- OP_n
      parts[#parts + 1] = string.char(0xae)      -- OP_CHECKMULTISIG
      local redeem = table.concat(parts)

      -- Compute the legacy sighash for the spend (script_code = redeem).
      local hash_type = 0x01  -- SIGHASH_ALL
      local sighash = validation.signature_hash_legacy(
        tx, 0, redeem, hash_type, "")

      -- Sign with the requested key indexes.
      for _, idx in ipairs(sign_indexes) do
        keys[idx].sig = crypto.ecdsa_sign(keys[idx].privkey, sighash) ..
                        string.char(hash_type)
      end

      return tx, redeem, keys
    end

    -- Helper: build the scriptSig for an m-of-n P2SH multisig.
    -- scriptSig = OP_0 <sig1> <sig2> ... <sigm> <redeem>
    local function build_multisig_scriptsig(sigs, redeem)
      local parts = { string.char(0x00) }  -- OP_0 (CHECKMULTISIG dummy)
      for _, s in ipairs(sigs) do
        if #s < 0x4c then
          parts[#parts + 1] = string.char(#s) .. s
        else
          parts[#parts + 1] = string.char(0x4c, #s) .. s
        end
      end
      parts[#parts + 1] = string.char(0x4c, #redeem) .. redeem
      return table.concat(parts)
    end

    it("script.has_multisig_op detects 0xae as opcode", function()
      -- 2-of-2: OP_2 <pk1> <pk2> OP_2 OP_CHECKMULTISIG
      local pk = string.rep("\x02", 33)
      local s = string.char(0x52) .. string.char(33) .. pk
                .. string.char(33) .. pk
                .. string.char(0x52, 0xae)
      assert.is_true(script.has_multisig_op(s))
      -- OP_CHECKMULTISIGVERIFY (0xaf) too
      local s2 = string.char(0x52) .. string.char(33) .. pk
                 .. string.char(33) .. pk
                 .. string.char(0x52, 0xaf)
      assert.is_true(script.has_multisig_op(s2))
    end)

    it("script.has_multisig_op ignores 0xae inside push payload", function()
      -- A 33-byte push containing 0xae bytes followed by OP_CHECKSIG.
      -- The 0xae bytes are inside the push, not opcodes.
      local payload = string.rep("\xae", 33)
      local s = string.char(33) .. payload .. string.char(0xac)  -- OP_CHECKSIG
      assert.is_false(script.has_multisig_op(s))
    end)

    it("script.has_multisig_op false for P2PKH", function()
      local p2pkh = string.char(0x76, 0xa9, 0x14) ..
                    string.rep("\x01", 20) ..
                    string.char(0x88, 0xac)
      assert.is_false(script.has_multisig_op(p2pkh))
    end)

    it("collector inline mode: 2-of-3 valid sigs verify correctly", function()
      -- Sign with keys 1 and 2 (positional match: keys 1 and 2 in the n=3
      -- pubkey list). The multisig trial loop should pair them correctly.
      local tx, redeem, keys = build_multisig_tx(2, 3, { 1, 2 })

      -- Build the spending input with collected (m=2) sigs.
      local script_sig = build_multisig_scriptsig({
        keys[1].sig, keys[2].sig
      }, redeem)
      tx.inputs[1].script_sig = script_sig

      -- Use the deferred-collect path with inline_verify gated by the
      -- has_multisig scan.  P2SH classification: the redeem is in the
      -- last push of script_sig.
      local p2sh_script = script.make_p2sh_script(crypto.hash160(redeem))
      assert.is_true(
        script.has_multisig_op(redeem),
        "redeem must trip the multisig scanner"
      )

      local flags = {
        verify_p2sh = true,
        verify_dersig = true,
        verify_strictenc = true,
      }
      local collector = {}
      local checker = validation.make_collecting_sig_checker(
        tx, 0, 100000, p2sh_script, flags, collector, nil,
        true  -- inline_verify=true (gated by has_multisig scan in connect_block)
      )

      local ok = script.verify_script(script_sig, p2sh_script, flags, checker)
      assert.is_true(ok, "valid 2-of-3 multisig must verify under inline_verify")

      -- Inline mode: nothing should be added to the collector because every
      -- check_sig verified inline.
      assert.equals(0, #collector)
    end)

    it("collector inline mode: 2-of-3 with one invalid sig fails", function()
      -- Sign with key 1 (valid) and key 4-that-doesn't-exist (we corrupt
      -- key 3's sig so it's invalid).  The trial loop should fail to pair.
      local tx, redeem, keys = build_multisig_tx(2, 3, { 1, 2 })
      -- Corrupt key 2's sig: zero out the DER body.  Trial pairing should
      -- skip past key 2 (sig invalid for any pubkey) and fail because there
      -- aren't enough valid sigs.
      keys[2].sig = string.rep("\x00", #keys[2].sig - 1) .. string.char(0x01)

      local script_sig = build_multisig_scriptsig({
        keys[1].sig, keys[2].sig
      }, redeem)
      tx.inputs[1].script_sig = script_sig

      local p2sh_script = script.make_p2sh_script(crypto.hash160(redeem))
      local flags = {
        verify_p2sh = true,
        verify_dersig = true,
        verify_strictenc = true,
        verify_nullfail = true,
      }
      local collector = {}
      local checker = validation.make_collecting_sig_checker(
        tx, 0, 100000, p2sh_script, flags, collector, nil,
        true  -- inline_verify=true
      )

      -- Pre-fix this would silently pass (collector returns true unconditionally,
      -- batch verify catches it later but with a misleading "index N" error).
      -- Post-fix, verify_script should reject it directly with NULLFAIL or
      -- a script-eval failure during the multisig trial loop.
      local ok, err = pcall(script.verify_script, script_sig, p2sh_script, flags, checker)
      assert.is_false(
        ok and err == true,
        "invalid multisig sig must be rejected (got ok=" .. tostring(ok) ..
        ", err=" .. tostring(err) .. ")"
      )
    end)

    it("collector deferred mode: single-sig P2PKH still uses parallel batch", function()
      -- P2PKH (no multisig): inline_verify=false, sig is appended to the
      -- collector for batch verification at end-of-block. This is the
      -- common-case parallel speedup path that we preserve.
      local prev_hash = types.hash256(string.rep("\xcd", 32))
      local tx = types.transaction(1, {}, {}, 0)
      tx.inputs[1] = types.txin(types.outpoint(prev_hash, 0), "", 0xFFFFFFFF)
      tx.outputs[1] = types.txout(50000, string.rep("\x00", 22))

      local privkey = (string.format("%064x", 0xBEEF42)):gsub('..',
        function(cc) return string.char(tonumber(cc, 16)) end)
      local pubkey = crypto.pubkey_from_privkey(privkey, true)
      local pkh = crypto.hash160(pubkey)
      local p2pkh = script.make_p2pkh_script(pkh)
      assert.is_false(script.has_multisig_op(p2pkh))

      -- Sign
      local hash_type = 0x01
      local sighash = validation.signature_hash_legacy(tx, 0, p2pkh, hash_type, "")
      local sig = crypto.ecdsa_sign(privkey, sighash) .. string.char(hash_type)

      -- Build scriptSig: <sig> <pubkey>
      tx.inputs[1].script_sig = string.char(#sig) .. sig ..
                                string.char(#pubkey) .. pubkey

      local flags = { verify_dersig = true, verify_strictenc = true }
      local collector = {}
      local checker = validation.make_collecting_sig_checker(
        tx, 0, 50000, p2pkh, flags, collector, nil,
        false  -- inline_verify=false: parallel speedup
      )

      local ok = script.verify_script(tx.inputs[1].script_sig, p2pkh, flags, checker)
      assert.is_true(ok, "P2PKH must verify under deferred-collect")

      -- Deferred mode: the sig should be in the collector, NOT inline-verified.
      assert.equals(1, #collector,
        "P2PKH (single check_sig) must defer 1 sig to the collector")
      assert.equals(pubkey, collector[1].pubkey)
    end)

    it("collector cross-check: inline result == single-thread result on multisig", function()
      -- Regression: replicate the OP_CHECKMULTISIG m-of-n trial-pairing on
      -- a synthetic input and verify the parallel-verify path (collecting
      -- + inline_verify) matches the single-threaded make_sig_checker path
      -- bit-for-bit.
      --
      -- Specifically tests: 2-of-3 where the wallet provides sigs in the
      -- canonical (sorted-by-pubkey-index) order. Both checkers must
      -- accept it.
      for _, signers in ipairs({ {1, 2}, {1, 3}, {2, 3} }) do
        local tx, redeem, keys = build_multisig_tx(2, 3, signers)
        local script_sig = build_multisig_scriptsig({
          keys[signers[1]].sig, keys[signers[2]].sig
        }, redeem)
        tx.inputs[1].script_sig = script_sig

        local p2sh_script = script.make_p2sh_script(crypto.hash160(redeem))
        local flags = {
          verify_p2sh = true,
          verify_dersig = true,
          verify_strictenc = true,
        }

        -- Single-threaded reference path
        local serial_checker = validation.make_sig_checker(
          tx, 0, 100000, p2sh_script, flags)
        local serial_ok = script.verify_script(
          script_sig, p2sh_script, flags, serial_checker)

        -- Parallel-verify path with inline_verify=true (CHECKMULTISIG gate)
        local collector = {}
        local parallel_checker = validation.make_collecting_sig_checker(
          tx, 0, 100000, p2sh_script, flags, collector, nil, true)
        local parallel_ok = script.verify_script(
          script_sig, p2sh_script, flags, parallel_checker)

        assert.equals(serial_ok, parallel_ok,
          string.format("signers=%d,%d: parallel(%s) != serial(%s)",
            signers[1], signers[2],
            tostring(parallel_ok), tostring(serial_ok)))
        assert.is_true(parallel_ok,
          string.format("signers=%d,%d should verify",
            signers[1], signers[2]))
      end
    end)
  end)
end)
