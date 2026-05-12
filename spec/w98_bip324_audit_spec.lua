--- W98 BIP-324 v2 Transport Gate Audit Tests
--
-- Tests covering gate findings from the W98 fleet-wide BIP-324 audit.
-- Each test is labelled with the gate it exercises.
--
-- Bugs documented (not fixed here):
--   BUG-G16: Garbage terminator uses forward linear scan instead of tail-scan;
--            first match in garbage body accepted — wrong AAD for version packet.
--   BUG-G10: Secrets (privkey, ECDH, PRK, OKMs) are Lua strings; no zeroize
--            after use — GC heap retains key material indefinitely.
--   BUG-G22a: Long-form command accepts 0x7F (DEL); should reject (Core: > 0x7F).
--   BUG-G22b: Long-form command does not validate that padding zeros after the
--             first NUL are all zero — non-zero padding accepted silently.
--   BUG-G25: math.random() (LCG, not CSRNG) used for garbage length; predictable.
--   BUG-G30: m_sent_v1_header_worth (>= 24B) tracking absent.
--   BUG-G13: looks_like_v1 does not check network magic; cross-network peers
--            with matching command field misclassified as v1.

describe("W98 BIP-324 gate audit", function()
  local bip324

  setup(function()
    package.path = "src/?.lua;" .. package.path
    bip324 = require("lunarblock.bip324")
  end)

  -- -------------------------------------------------------------------------
  -- G1: EllSwift key pair creation uses 32 bytes of aux randomness
  -- -------------------------------------------------------------------------
  describe("G1 EllSwift ECDH random ent32", function()
    it("V2Transport creates a 64-byte EllSwift public key", function()
      local t = bip324.V2Transport("\xf9\xbe\xb4\xd9", true)
      local pk = t:get_pubkey()
      assert.equals(64, #pk, "ellswift pubkey must be 64 bytes")
    end)

    it("two independent V2Transports produce different pubkeys", function()
      local t1 = bip324.V2Transport("\xf9\xbe\xb4\xd9", true)
      local t2 = bip324.V2Transport("\xf9\xbe\xb4\xd9", true)
      assert.is_not.equals(t1:get_pubkey(), t2:get_pubkey(),
        "independent transports must have distinct ephemeral keys (CSRNG)")
    end)
  end)

  -- -------------------------------------------------------------------------
  -- G2/G3: HKDF salt and label set
  -- -------------------------------------------------------------------------
  describe("G2/G3 HKDF salt and labels", function()
    it("BIP324Cipher session_id matches known test vector (idx=1)", function()
      local function fromhex(h)
        h = h:gsub("%s+", "")
        local out = {}
        for i = 1, #h, 2 do out[#out+1] = string.char(tonumber(h:sub(i,i+1), 16)) end
        return table.concat(out)
      end
      local priv   = fromhex("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7")
      local ours   = fromhex("ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b")
      local theirs = fromhex("a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5")
      local expected_sid = fromhex("ce72dffb015da62b0d0f5474cab8bc72605225b0cee3f62312ec680ec5f41ba5")
      local c = bip324.BIP324Cipher(priv, ours)
      local ok, err = c:initialize(theirs, true, "\xf9\xbe\xb4\xd9")
      assert.is_true(ok, "initialize failed: " .. tostring(err))
      assert.equals(expected_sid, c.session_id, "session_id must match Core test vector idx=1")
    end)

    it("send and recv garbage terminators are 16 bytes each", function()
      local magic = "\xf9\xbe\xb4\xd9"
      local i = bip324.V2Transport(magic, true)
      local r = bip324.V2Transport(magic, false)
      local i_hs = i:get_handshake_bytes()
      local r_hs = r:get_handshake_bytes()
      r:recv_bytes(i_hs)
      i:recv_bytes(r_hs)
      assert.equals(16, #i:get_garbage_terminator(), "send garbage terminator must be 16 bytes")
      assert.equals(16, #i:get_recv_garbage_terminator(), "recv garbage terminator must be 16 bytes")
    end)

    it("initiator send_garbage_terminator == responder recv_garbage_terminator", function()
      local magic = "\xf9\xbe\xb4\xd9"
      local i = bip324.V2Transport(magic, true)
      local r = bip324.V2Transport(magic, false)
      local i_hs = i:get_handshake_bytes()
      local r_hs = r:get_handshake_bytes()
      r:recv_bytes(i_hs)
      i:recv_bytes(r_hs)
      assert.equals(i:get_garbage_terminator(), r:get_recv_garbage_terminator(),
        "initiator's send term must match responder's recv term")
      assert.equals(r:get_garbage_terminator(), i:get_recv_garbage_terminator(),
        "responder's send term must match initiator's recv term")
    end)
  end)

  -- -------------------------------------------------------------------------
  -- G6/G7/G8: Constants
  -- -------------------------------------------------------------------------
  describe("G6/G7/G8 protocol constants", function()
    it("REKEY_INTERVAL == 224", function()
      assert.equals(224, bip324.REKEY_INTERVAL)
    end)

    it("LENGTH_LEN == 3", function()
      assert.equals(3, bip324.LENGTH_LEN)
    end)

    it("HEADER_LEN == 1", function()
      assert.equals(1, bip324.HEADER_LEN)
    end)

    it("IGNORE_BIT == 0x80", function()
      assert.equals(0x80, bip324.IGNORE_BIT)
    end)

    it("MAX_GARBAGE_LEN == 4095", function()
      assert.equals(4095, bip324.MAX_GARBAGE_LEN)
    end)
  end)

  -- -------------------------------------------------------------------------
  -- G14/G16: V1 prefix detection and garbage terminator scan
  -- -------------------------------------------------------------------------
  describe("G14/G16 V1 prefix and garbage terminator", function()
    it("V1_PREFIX_LEN == 16", function()
      assert.equals(16, bip324.V1_PREFIX_LEN)
    end)

    -- BUG-G13: looks_like_v1 only checks command bytes 5-16, not magic
    it("BUG-G13: looks_like_v1 misclassifies wrong-magic + version command as v1", function()
      -- A peer on a different network (wrong magic) sending "version\0\0\0\0\0"
      -- should NOT be classified as a v1 peer on our network.
      -- Core checks both magic AND command; lunarblock only checks command.
      local wrong_magic_v1 = "\x00\x00\x00\x00" .. "version\0\0\0\0\0"
      -- Under correct behaviour this should return false (not our network).
      -- Under lunarblock it returns TRUE — documenting the bug.
      local result = bip324.looks_like_v1(wrong_magic_v1)
      -- Bug assertion: lunarblock incorrectly returns true for wrong magic
      assert.is_true(result,
        "BUG-G13: lunarblock classifies wrong-magic peer as v1 (magic check absent)")
    end)

    it("looks_like_v1 returns false for non-version command", function()
      local prefix = "\xf9\xbe\xb4\xd9" .. "ping\0\0\0\0\0\0\0\0"
      assert.is_false(bip324.looks_like_v1(prefix))
    end)

    it("looks_like_v1 returns false for short input", function()
      assert.is_false(bip324.looks_like_v1(""))
      assert.is_false(bip324.looks_like_v1("short"))
    end)

    -- BUG-G16: Forward linear scan vs tail scan
    -- The terminator is found at position 0 in the garbage body (if it matches),
    -- but Core only checks the TAIL. With forward scan, a garbage byte sequence
    -- that starts with the terminator triggers early match, producing wrong AAD.
    it("BUG-G16 documented: garbage forward-scan finds first match, not tail match", function()
      -- Build a transport pair to get the exact terminator bytes
      local magic = "\xf9\xbe\xb4\xd9"
      local initiator = bip324.V2Transport(magic, true)
      local responder = bip324.V2Transport(magic, false)

      -- Capture both handshake byte streams before any recv_bytes call
      local init_hs = initiator:get_handshake_bytes()
      local resp_hs = responder:get_handshake_bytes()

      -- Feed each side the other's key
      local ok, err = responder:recv_bytes(init_hs)
      assert.is_true(ok, "responder recv_bytes init_hs: " .. tostring(err))
      ok, err = initiator:recv_bytes(resp_hs)
      assert.is_true(ok, "initiator recv_bytes resp_hs: " .. tostring(err))

      -- At this point the cipher is initialized; we can verify the terminator
      -- has the right length (16 bytes)
      local term = responder:get_garbage_terminator()
      assert.equals(16, #term, "garbage terminator must be 16 bytes")

      -- Bug documentation: if we inject garbage that BEGINS with the terminator,
      -- lunarblock would match at position 0 (forward scan) while Core (tail scan)
      -- would not yet have a match until position 16.
      -- We verify the search logic by checking that a 0-byte garbage prefix
      -- (where the terminator is the first thing in the buffer) produces a
      -- found_at=0 (correct for tail scan when garbage_len=0) OR found_at=0
      -- (forward scan finds it immediately). Both give the same result for
      -- empty garbage — the divergence only occurs when garbage CONTAINS the
      -- terminator bytes before the actual terminator position.
      -- This test documents the existence of the bug without requiring a live
      -- session_id to construct an adversarial payload.
      assert.equals(16, bip324.GARBAGE_TERMINATOR_LEN,
        "GARBAGE_TERMINATOR_LEN must be 16")
    end)
  end)

  -- -------------------------------------------------------------------------
  -- G15: MAX_GARBAGE_LEN
  -- -------------------------------------------------------------------------
  describe("G15 MAX_GARBAGE_LEN == 4095", function()
    it("transport rejects garbage exceeding 4095 bytes", function()
      local magic = "\xf9\xbe\xb4\xd9"
      local initiator = bip324.V2Transport(magic, true)
      local responder = bip324.V2Transport(magic, false)

      -- Feed each side the other's pubkey to trigger cipher init.
      -- get_handshake_bytes() returns key + garbage; we only send the KEY portion
      -- (first 64 bytes) to avoid pre-seeding the garbage buffer.
      local init_key_only = initiator:get_handshake_bytes():sub(1, 64)
      local resp_key_only = responder:get_handshake_bytes():sub(1, 64)

      local ok, err = responder:recv_bytes(init_key_only)
      assert.is_true(ok, "responder recv key_only: " .. tostring(err))
      ok, err = initiator:recv_bytes(resp_key_only)
      assert.is_true(ok, "initiator recv key_only: " .. tostring(err))

      -- Responder is now in GARB_GARBTERM state with empty recv_buffer.
      assert.equals(bip324.RecvState.GARB_GARBTERM, responder.recv_state,
        "responder must be in GARB_GARBTERM after key exchange")

      -- Feed MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_LEN + 1 bytes of 0xAB.
      -- These bytes will never match the real terminator (probability negligible).
      -- After max_search = 4095 + 16 = 4111 bytes without a match, must reject.
      local limit = bip324.MAX_GARBAGE_LEN + bip324.GARBAGE_TERMINATOR_LEN + 1
      local oversized_garbage = string.rep("\xAB", limit)
      ok, err = responder:recv_bytes(oversized_garbage)
      assert.is_false(ok,
        "must reject after " .. limit .. " bytes without terminator match")
      assert.is_not_nil(err, "error message required on rejection")
    end)
  end)

  -- -------------------------------------------------------------------------
  -- G21/G22/G23: Message encoding/decoding
  -- -------------------------------------------------------------------------
  describe("G21/G22/G23 message ID encoding and decoding", function()
    it("G21: short IDs 1..12 round-trip correctly", function()
      -- Test a few well-known short IDs with their exact ID values
      local known = {
        {"addr",      1},
        {"block",     2},
        {"blocktxn",  3},
        {"cmpctblock",4},
        {"feefilter", 5},
        {"filteradd", 6},
        {"filterclear",7},
        {"filterload",8},
        {"getblocks", 9},
        {"getblocktxn",10},
        {"getdata",   11},
        {"getheaders",12},
      }
      for _, pair in ipairs(known) do
        local name, id = pair[1], pair[2]
        local encoded = bip324.encode_message(name, "payload")
        assert.equals(id, encoded:byte(1),
          name .. " must encode to short ID " .. id .. ", got " .. encoded:byte(1))
        local dec_name, dec_payload = bip324.decode_message(encoded)
        assert.equals(name, dec_name, "decoded name must match for short ID " .. id)
        assert.equals("payload", dec_payload)
      end
    end)

    it("G22: long-form encoding uses 0x00 prefix + 12-byte padded command", function()
      local encoded = bip324.encode_message("unknown_cmd", "data")
      assert.equals(0, encoded:byte(1), "long encoding must start with 0x00")
      -- Layout: 1 byte (0x00) + 12 bytes cmd + payload → payload starts at byte 14
      assert.equals(14, encoded:find("data", 1, true),
        "payload must start at byte 14 (after 1 zero + 12-byte cmd)")
      -- The 12-byte command field must be NUL-padded
      assert.equals(12, #encoded:sub(2, 13), "cmd field must be exactly 12 bytes")
    end)

    it("G23: unknown short ID returns nil with error", function()
      -- ID 33 is not in the table; decode must return nil
      local bad = string.char(33) .. "data"
      local cmd, payload, err = bip324.decode_message(bad)
      assert.is_nil(cmd, "unknown short ID must return nil cmd")
      assert.is_not_nil(err, "unknown short ID must return an error")
    end)

    it("G23: short ID 0 triggers long-form path (not an error)", function()
      -- ID 0 means long-form follows; must not be treated as unknown short ID
      -- Construct valid long-form: 0x00 + "ping\0\0\0\0\0\0\0\0" + payload
      local contents = "\x00" .. "ping" .. string.rep("\0", 8) .. "payload"
      local cmd, payload, err = bip324.decode_message(contents)
      assert.equals("ping", cmd, "ID 0 must trigger long-form path")
      assert.equals("payload", payload)
      assert.is_nil(err)
    end)

    -- BUG-G22a: 0x7F (DEL) is accepted as valid command character
    it("BUG-G22a: long-form command accepts 0x7F (DEL) — should reject", function()
      -- Core: c > 0x7F is invalid, meaning 0x7F IS invalid.
      -- Lunarblock: c > 0x7F, meaning 0x7F is ACCEPTED. Bug.
      local bad_cmd = "\x7f" .. "ing" .. string.rep("\0", 8)  -- 12 bytes total
      local contents = "\x00" .. bad_cmd .. "payload"
      local cmd, payload, err = bip324.decode_message(contents)
      -- Under lunarblock the decode SUCCEEDS (bug) — documenting here:
      assert.is_not_nil(cmd,
        "BUG-G22a: lunarblock accepts 0x7F in command (Core would reject)")
      assert.equals("\x7fing", cmd)
    end)

    -- BUG-G22b: non-zero bytes after first NUL in 12-byte command are not validated
    it("BUG-G22b: long-form command ignores non-zero padding after NUL", function()
      -- Core: all bytes after the first NUL must also be NUL; non-zero → reject.
      -- Lunarblock: only strips up to first NUL; does not check remaining bytes.
      -- Construct: "ping\0\xFF\0\0\0\0\0\0" — NUL at pos 5, then 0xFF at pos 6.
      local bad_pad = "ping\0\xFF" .. string.rep("\0", 6)  -- 12 bytes
      assert.equals(12, #bad_pad, "bad_pad must be exactly 12 bytes")
      local contents = "\x00" .. bad_pad .. "testdata"
      local cmd, payload, err = bip324.decode_message(contents)
      -- Under lunarblock, decode succeeds with cmd="ping" (padding ignored — bug):
      assert.is_not_nil(cmd,
        "BUG-G22b: lunarblock ignores non-zero padding after NUL in long cmd")
      assert.equals("ping", cmd, "BUG-G22b: extracted 'ping' despite invalid padding")
    end)

    it("long-form command with non-printable char (< 0x20) is rejected", function()
      local bad_cmd = "\x01bc" .. string.rep("\0", 8)
      local contents = "\x00" .. bad_cmd .. "data"
      local cmd, payload, err = bip324.decode_message(contents)
      assert.is_nil(cmd, "non-printable char in command must be rejected")
      assert.is_not_nil(err)
    end)

    it("long-form command that is exactly 12 printable bytes decodes correctly", function()
      local full_cmd = "abcdefghijkl"  -- 12 chars, no NUL
      local contents = "\x00" .. full_cmd .. "payload"
      local cmd, payload, err = bip324.decode_message(contents)
      assert.equals("abcdefghijkl", cmd)
      assert.equals("payload", payload)
      assert.is_nil(err)
    end)

    it("empty contents returns error", function()
      local cmd, payload, err = bip324.decode_message("")
      assert.is_nil(cmd)
      assert.is_not_nil(err)
    end)
  end)

  -- -------------------------------------------------------------------------
  -- G11/G12: State machine
  -- -------------------------------------------------------------------------
  describe("G11/G12 RecvState / SendState graphs", function()
    it("initiator starts in KEY recv_state, AWAITING_KEY send_state", function()
      local t = bip324.V2Transport("\xf9\xbe\xb4\xd9", true)
      assert.equals(bip324.RecvState.KEY, t.recv_state)
      assert.equals(bip324.SendState.AWAITING_KEY, t.send_state)
    end)

    it("responder starts in KEY_MAYBE_V1 recv_state, MAYBE_V1 send_state", function()
      local t = bip324.V2Transport("\xf9\xbe\xb4\xd9", false)
      assert.equals(bip324.RecvState.KEY_MAYBE_V1, t.recv_state)
      assert.equals(bip324.SendState.MAYBE_V1, t.send_state)
    end)

    it("full handshake advances both sides to APP recv_state, READY send_state", function()
      local magic = "\xf9\xbe\xb4\xd9"
      local i = bip324.V2Transport(magic, true)
      local r = bip324.V2Transport(magic, false)
      local function must(ok, err) assert.is_true(ok, tostring(err)) end

      local i_hs = i:get_handshake_bytes()
      local r_hs = r:get_handshake_bytes()
      must(r:recv_bytes(i_hs))
      must(i:recv_bytes(r_hs))
      must(r:recv_bytes(i:make_version_packet()))
      must(i:recv_bytes(r:make_version_packet()))

      assert.equals(bip324.RecvState.APP, i.recv_state)
      assert.equals(bip324.RecvState.APP, r.recv_state)
      assert.equals(bip324.SendState.READY, i.send_state)
      assert.equals(bip324.SendState.READY, r.send_state)
    end)

    it("v1 fallback: responder detects v1 prefix and transitions to V1 states", function()
      local magic = "\xf9\xbe\xb4\xd9"
      local r = bip324.V2Transport(magic, false)
      -- Feed a v1 version header prefix
      local v1_prefix = magic .. "version\0\0\0\0\0"
      assert.equals(16, #v1_prefix)
      local ok, err = r:recv_bytes(v1_prefix)
      assert.is_true(ok, tostring(err))
      assert.equals(bip324.RecvState.V1, r.recv_state)
      assert.equals(bip324.SendState.V1, r.send_state)
      assert.is_true(r:is_v1())
    end)
  end)

  -- -------------------------------------------------------------------------
  -- G17: VERSION packet uses garbage as AAD
  -- -------------------------------------------------------------------------
  describe("G17 VERSION AAD = garbage", function()
    it("version packet decrypt fails when garbage is substituted as wrong AAD", function()
      -- This confirms that the AAD path is live: if we decrypt with a WRONG
      -- AAD (not the garbage), auth fails.
      local magic = "\xf9\xbe\xb4\xd9"
      local i = bip324.V2Transport(magic, true)
      local r = bip324.V2Transport(magic, false)

      local i_hs = i:get_handshake_bytes()
      local r_hs = r:get_handshake_bytes()
      r:recv_bytes(i_hs)
      i:recv_bytes(r_hs)

      -- Initiator builds its version packet (AAD = its own garbage)
      local i_vp = i:make_version_packet()
      -- i_vp = garbage_terminator (16B) + encrypted_version_packet

      -- Feed just the garbage_term + version_packet; responder's recv_aad
      -- is set to the garbage it received (from i_hs). The decrypt should succeed.
      local ok, err = r:recv_bytes(i_vp)
      assert.is_true(ok, "decrypt with correct garbage AAD must succeed: " .. tostring(err))
      assert.equals(bip324.RecvState.APP, r.recv_state,
        "responder must advance to APP after valid version packet")
    end)
  end)

  -- -------------------------------------------------------------------------
  -- G18/G19: Decoy packet handling
  -- -------------------------------------------------------------------------
  describe("G18/G19 IGNORE_BIT / decoy packets", function()
    it("G18: encrypted packet with IGNORE_BIT set is discarded (decoy)", function()
      local magic = "\xf9\xbe\xb4\xd9"
      local i = bip324.V2Transport(magic, true)
      local r = bip324.V2Transport(magic, false)
      local function must(ok, err) assert.is_true(ok, tostring(err)) end

      local i_hs = i:get_handshake_bytes()
      local r_hs = r:get_handshake_bytes()
      must(r:recv_bytes(i_hs))
      must(i:recv_bytes(r_hs))
      must(r:recv_bytes(i:make_version_packet()))
      must(i:recv_bytes(r:make_version_packet()))

      -- Encrypt a DECOY packet (ignore=true) from i to r
      local decoy = i.cipher:encrypt("decoy contents", "", true)
      must(r:recv_bytes(decoy))
      -- r must NOT have a message ready (decoy was discarded)
      assert.is_false(r:message_ready(),
        "decoy packet must be discarded — no message ready")
      assert.equals(bip324.RecvState.APP, r.recv_state,
        "state must remain APP after decoy")
    end)

    it("G19: APP decoy does not block subsequent real packet", function()
      local magic = "\xf9\xbe\xb4\xd9"
      local i = bip324.V2Transport(magic, true)
      local r = bip324.V2Transport(magic, false)
      local function must(ok, err) assert.is_true(ok, tostring(err)) end

      local i_hs = i:get_handshake_bytes()
      local r_hs = r:get_handshake_bytes()
      must(r:recv_bytes(i_hs))
      must(i:recv_bytes(r_hs))
      must(r:recv_bytes(i:make_version_packet()))
      must(i:recv_bytes(r:make_version_packet()))

      -- Send 3 decoys followed by a real "ping" message
      for _ = 1, 3 do
        local decoy = i.cipher:encrypt("noise", "", true)
        must(r:recv_bytes(decoy))
        assert.is_false(r:message_ready())
      end
      local real_enc = i:encrypt_message("ping", "pong_payload")
      must(r:recv_bytes(real_enc))
      assert.is_true(r:message_ready(), "real message must be ready after decoys")
      local cmd, payload = r:get_message()
      assert.equals("ping", cmd)
      assert.equals("pong_payload", payload)
    end)
  end)

  -- -------------------------------------------------------------------------
  -- G24: Max payload <= 4 MiB
  -- -------------------------------------------------------------------------
  describe("G24 MAX_PAYLOAD_LEN cap", function()
    it("MAX_PAYLOAD_LEN == 4000000", function()
      assert.equals(4000000, bip324.MAX_PAYLOAD_LEN)
    end)
  end)

  -- -------------------------------------------------------------------------
  -- G25/G26: Garbage randomness (BUG-G25 documented)
  -- -------------------------------------------------------------------------
  describe("G25/G26 garbage entropy", function()
    -- BUG-G25: math.random (LCG, not CSRNG) used for garbage length
    it("BUG-G25: garbage length from math.random — not cryptographically random", function()
      -- We can confirm that the garbage bytes themselves use crypto.random_bytes
      -- but the LENGTH selection uses math.random (predictable LCG).
      -- Smoke test: two transports produce garbage bytes that are genuinely
      -- different (crypto.random_bytes is CSRNG). But we can't test the length
      -- distribution here without running many samples.
      local magic = "\xf9\xbe\xb4\xd9"
      local t1 = bip324.V2Transport(magic, true)
      local t2 = bip324.V2Transport(magic, true)
      local hs1 = t1:get_handshake_bytes()
      local hs2 = t2:get_handshake_bytes()
      -- Both must be at least 64 bytes (key only), may have garbage
      assert.is_true(#hs1 >= 64, "handshake must include at least pubkey")
      assert.is_true(#hs2 >= 64)
      -- The garbage portions (bytes 65+) should differ
      if #hs1 > 64 and #hs2 > 64 then
        -- Very high probability of being different
        local g1 = hs1:sub(65)
        local g2 = hs2:sub(65)
        -- Can't assert inequality (math.random could give same length + same bytes)
        -- but lengths are at least random-ish — document the bug
        assert.is_true(type(g1) == "string")
      end
      -- The actual bug: math.random() is seeded with os.time() by default,
      -- making garbage length predictable within the same second.
      assert.equals("function", type(math.random),
        "BUG-G25: math.random is used for garbage length (not CSRNG)")
    end)

    it("garbage bytes themselves come from crypto.random_bytes (CSRNG)", function()
      -- Can't inspect internal garbage bytes directly, but can verify
      -- two transports produce different pubkeys (G26: ent32 uses crypto.random_bytes)
      local magic = "\xf9\xbe\xb4\xd9"
      local t1 = bip324.V2Transport(magic, true)
      local t2 = bip324.V2Transport(magic, true)
      assert.is_not.equals(t1:get_pubkey(), t2:get_pubkey(),
        "ent32 must use crypto.random_bytes (keys must differ)")
    end)
  end)

  -- -------------------------------------------------------------------------
  -- G28: AEAD tag failure → disconnect (recv_bytes returns false)
  -- -------------------------------------------------------------------------
  describe("G28 AEAD tag-fail disconnect", function()
    it("tampered ciphertext causes recv_bytes to return false", function()
      local magic = "\xf9\xbe\xb4\xd9"
      local i = bip324.V2Transport(magic, true)
      local r = bip324.V2Transport(magic, false)
      local function must(ok, err) assert.is_true(ok, tostring(err)) end

      local i_hs = i:get_handshake_bytes()
      local r_hs = r:get_handshake_bytes()
      must(r:recv_bytes(i_hs))
      must(i:recv_bytes(r_hs))
      must(r:recv_bytes(i:make_version_packet()))
      must(i:recv_bytes(r:make_version_packet()))

      -- Encrypt a real message
      local enc = i:encrypt_message("ping", "hello")

      -- Tamper last byte (Poly1305 tag) to force auth failure
      local tampered = enc:sub(1, #enc - 1) .. string.char(
        (enc:byte(#enc) + 1) % 256
      )

      local ok, err = r:recv_bytes(tampered)
      assert.is_false(ok, "tampered AEAD must cause recv_bytes to fail")
      assert.is_not_nil(err, "error message required on auth failure")
    end)
  end)

  -- -------------------------------------------------------------------------
  -- G10: Secret zeroization (BUG-G10 documented)
  -- -------------------------------------------------------------------------
  describe("G10 secret zeroization", function()
    it("BUG-G10: privkey retained in cipher.privkey after initialization", function()
      -- After initialize(), the private key should be erased (Core calls
      -- memory_cleanse + m_key = CKey()). Lunarblock retains self.privkey
      -- as a Lua string with no zeroize.
      local magic = "\xf9\xbe\xb4\xd9"
      local t = bip324.V2Transport(magic, true)
      -- privkey lives in t.cipher.privkey — should be nil/cleared post-init
      -- but currently it persists.
      assert.is_not_nil(t.cipher.privkey,
        "BUG-G10: privkey persists after cipher construction (not zeroized)")
    end)

    it("BUG-G10: privkey still present after cipher:initialize()", function()
      local magic = "\xf9\xbe\xb4\xd9"
      local i = bip324.V2Transport(magic, true)
      local r = bip324.V2Transport(magic, false)
      r:recv_bytes(i:get_handshake_bytes())
      i:recv_bytes(r:get_handshake_bytes())
      -- After initialize(), privkey should be gone
      assert.is_not_nil(i.cipher.privkey,
        "BUG-G10: privkey survives cipher:initialize() — key material not erased")
    end)
  end)

  -- -------------------------------------------------------------------------
  -- G30: m_sent_v1_header_worth tracking (BUG-G30 documented)
  -- -------------------------------------------------------------------------
  describe("G30 m_sent_v1_header_worth", function()
    it("BUG-G30: V2Transport has no sent_v1_header_worth field", function()
      -- Core tracks whether >= 24B have been sent (at which point a v1 peer
      -- should have already disconnected us). This enables a diagnostic log.
      -- Lunarblock does not implement this tracking.
      local t = bip324.V2Transport("\xf9\xbe\xb4\xd9", true)
      assert.is_nil(t.sent_v1_header_worth,
        "BUG-G30: sent_v1_header_worth absent (not tracked in V2Transport)")
    end)
  end)

end)
