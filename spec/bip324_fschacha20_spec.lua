--- Regression test for BIP324 FSChaCha20 (length cipher) continuity.
--
-- Background: prior to wave7-2026-04-14, src/bip324.lua's FSChaCha20
-- implementation derived a fresh ChaCha20 stream per packet using a nonce
-- of (packet_counter, rekey_counter). Per BIP324 and the Python reference
-- (bitcoin-core/test/functional/test_framework/crypto/chacha20.py) and
-- Core's FSChaCha20::Crypt (bitcoin-core/src/crypto/chacha20.cpp), the
-- length cipher is a *continuous* stream within a rekey period with
-- nonce=(0, rekey_counter); successive crypt() calls consume contiguous
-- keystream bytes.
--
-- The bug: packet 0 of a fresh stream happens to emit the same 3 bytes
-- under both constructions, so the v2 handshake succeeds up through the
-- first decrypted packet. Starting at packet 1, lunarblock's keystream
-- diverged from Core's and Core peers silently dropped the connection
-- after our first post-handshake message (state=version_sent → closed).
--
-- This test constructs a full symmetric v2 transport pair (initiator +
-- responder), performs the handshake, exchanges version packets, then
-- exchanges N=3 additional encrypted application messages back and forth.
-- All decrypts must succeed; the test exercises the length cipher past
-- packet 0.

describe("BIP324 FSChaCha20 length cipher (continuous stream)", function()
  local bip324
  local crypto

  setup(function()
    package.path = "src/?.lua;" .. package.path
    crypto = require("lunarblock.crypto")
    bip324 = require("lunarblock.bip324")
  end)

  it("two peers handshake and exchange multiple encrypted messages", function()
    local magic = "\xf9\xbe\xb4\xd9"
    local initiator = bip324.V2Transport(magic, true)
    local responder = bip324.V2Transport(magic, false)

    -- Simulate wire: initiator sends key+garbage, responder sends key+garbage.
    local init_bytes = initiator:get_handshake_bytes()
    local resp_bytes = responder:get_handshake_bytes()
    assert.is_true(#init_bytes >= 64)
    assert.is_true(#resp_bytes >= 64)

    -- Responder receives initiator's key+garbage (first 16 bytes are not v1).
    local ok, err = responder:recv_bytes(init_bytes)
    assert.is_true(ok, "responder recv_bytes(init_bytes) failed: " .. tostring(err))

    -- Initiator receives responder's key+garbage.
    ok, err = initiator:recv_bytes(resp_bytes)
    assert.is_true(ok, "initiator recv_bytes(resp_bytes) failed: " .. tostring(err))

    -- Both sides must now have a ready cipher; session IDs must match.
    assert.is_true(initiator.cipher.initialized)
    assert.is_true(responder.cipher.initialized)
    assert.equals(initiator:get_session_id(), responder:get_session_id())

    -- Each side sends its garbage-terminator + v2 version packet.
    local init_vp = initiator:make_version_packet()
    local resp_vp = responder:make_version_packet()

    -- Responder consumes initiator's version packet (finds garb term, decrypts
    -- first AEAD packet with AAD = initiator's garbage).
    ok, err = responder:recv_bytes(init_vp)
    assert.is_true(ok, "responder recv_bytes(init_vp) failed: " .. tostring(err))

    -- Initiator consumes responder's version packet.
    ok, err = initiator:recv_bytes(resp_vp)
    assert.is_true(ok, "initiator recv_bytes(resp_vp) failed: " .. tostring(err))

    assert.is_true(initiator:ready_to_send())
    assert.is_true(responder:ready_to_send())

    -- Now exchange N application messages in BOTH directions. Packet 0 of the
    -- length cipher was used by the v2 version packet; from packet 1 onward
    -- the pre-bug code would diverge from Core.
    local payloads = {
      string.rep("A", 32),
      string.rep("\x7f", 65),
      string.rep("\x00", 17) .. string.rep("\xff", 17),
      "final",
    }

    for i, payload in ipairs(payloads) do
      -- initiator -> responder
      local enc = initiator:encrypt_message("ping", payload)
      ok, err = responder:recv_bytes(enc)
      assert.is_true(ok, "responder recv_bytes app#" .. i .. " failed: " .. tostring(err))
      assert.is_true(responder:message_ready(), "no message ready after app#" .. i)
      local cmd, got = responder:get_message()
      assert.equals("ping", cmd)
      assert.equals(payload, got)

      -- responder -> initiator
      enc = responder:encrypt_message("pong", payload)
      ok, err = initiator:recv_bytes(enc)
      assert.is_true(ok, "initiator recv_bytes app#" .. i .. " failed: " .. tostring(err))
      assert.is_true(initiator:message_ready())
      cmd, got = initiator:get_message()
      assert.equals("pong", cmd)
      assert.equals(payload, got)
    end
  end)

  it("FSChaCha20 length cipher matches self-inverse across 10 packets", function()
    -- Two independent FSChaCha20 instances with the same key must produce the
    -- same keystream, so encrypt->decrypt round-trip works for every packet.
    -- (Smoke-level direct exercise of the length cipher.)
    -- We drive through the V2Transport's internal cipher indirectly by
    -- encrypting/decrypting many packets in sequence and requiring success;
    -- the handshake round above already covers the code path, and repeating
    -- it here catches off-by-one regressions in keystream offsetting.
    local magic = "\xf9\xbe\xb4\xd9"
    local initiator = bip324.V2Transport(magic, true)
    local responder = bip324.V2Transport(magic, false)
    local function must(ok, err) assert.is_true(ok, tostring(err)); return ok end
    -- Capture handshake bytes from BOTH sides before either recv_bytes call:
    -- recv_bytes transitions send_state past MAYBE_V1, after which
    -- get_handshake_bytes() returns "".
    local init_hs = initiator:get_handshake_bytes()
    local resp_hs = responder:get_handshake_bytes()
    must(responder:recv_bytes(init_hs))
    must(initiator:recv_bytes(resp_hs))
    must(responder:recv_bytes(initiator:make_version_packet()))
    must(initiator:recv_bytes(responder:make_version_packet()))

    for i = 1, 10 do
      local payload = string.rep(string.char((i * 7) % 256), i * 3)
      local enc = initiator:encrypt_message("inv", payload)
      local ok, err = responder:recv_bytes(enc)
      assert.is_true(ok, "packet " .. i .. " length-cipher decrypt failed: " .. tostring(err))
      assert.is_true(responder:message_ready())
      local cmd, got = responder:get_message()
      assert.equals("inv", cmd)
      assert.equals(payload, got)
    end
  end)
end)
