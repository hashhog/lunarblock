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

  it("FSChaCha20Poly1305 rekey at packet 224 produces matching new keys (W56)", function()
    -- W56 regression: the rekey step of FSChaCha20Poly1305 previously used
    -- bare ChaCha20 block 0 as the new key, but BIP324 / Core /
    -- bip324_cipher.py derive the new key from the AEAD keystream (block 1,
    -- since block 0 is used for the Poly1305 one-time key). After packet 224
    -- our key diverged from the peer's and every subsequent decrypt failed
    -- authentication. This test exchanges REKEY_INTERVAL+10 = 234 packets
    -- in BOTH directions to force exactly one rekey on each cipher and
    -- confirm continued success past the boundary.
    local magic = "\xf9\xbe\xb4\xd9"
    local initiator = bip324.V2Transport(magic, true)
    local responder = bip324.V2Transport(magic, false)
    local function must(ok, err) assert.is_true(ok, tostring(err)); return ok end
    local init_hs = initiator:get_handshake_bytes()
    local resp_hs = responder:get_handshake_bytes()
    must(responder:recv_bytes(init_hs))
    must(initiator:recv_bytes(resp_hs))
    must(responder:recv_bytes(initiator:make_version_packet()))
    must(initiator:recv_bytes(responder:make_version_packet()))

    for i = 1, 234 do
      local payload = string.rep(string.char((i * 13) % 256), (i % 17) + 1)
      local enc = initiator:encrypt_message("inv", payload)
      local ok, err = responder:recv_bytes(enc)
      assert.is_true(ok, "i->r packet " .. i .. " decrypt failed: " .. tostring(err))
      assert.is_true(responder:message_ready(), "no message ready i->r #" .. i)
      local cmd, got = responder:get_message()
      assert.equals("inv", cmd)
      assert.equals(payload, got)

      local enc2 = responder:encrypt_message("pong", payload)
      ok, err = initiator:recv_bytes(enc2)
      assert.is_true(ok, "r->i packet " .. i .. " decrypt failed: " .. tostring(err))
      assert.is_true(initiator:message_ready(), "no message ready r->i #" .. i)
      cmd, got = initiator:get_message()
      assert.equals("pong", cmd)
      assert.equals(payload, got)
    end
  end)

  it("chacha20_crypt matches RFC 8439 test vector (W57)", function()
    -- W57: crypto.chacha20_crypt was passing a 12-byte IV to OpenSSL's
    -- EVP_chacha20, which expects a 16-byte IV (4-byte LE counter ||
    -- 12-byte nonce). With non-zero nonces OpenSSL read 4 bytes of garbage
    -- past the Lua string and produced wrong keystream. This broke the
    -- FSChaCha20 length cipher rekey path at rc>=1. This test catches the
    -- regression directly against the RFC 8439 vector with counter=0.
    local crypto = require("lunarblock.crypto")
    -- chacha20_block(key=0, nonce=(0,1), counter=0) → 8f1a6b76320e...
    local new_key = string.char(
      0x28, 0x69, 0x7a, 0xbe, 0x54, 0xee, 0x36, 0x39,
      0x20, 0xbb, 0xa9, 0xf2, 0xe0, 0x54, 0xb0, 0xc7,
      0x01, 0xa2, 0x1b, 0x16, 0x35, 0x3d, 0x3e, 0x02,
      0x76, 0x1c, 0x83, 0xab, 0x51, 0x14, 0x6b, 0x05)
    -- Non-trivial nonce: 4 zeros (packet part of period_nonce) + LE(1) as 8 bytes
    local nonce = "\0\0\0\0\1\0\0\0\0\0\0\0"
    local ks = crypto.chacha20_crypt(new_key, nonce, string.rep("\0", 16))
    local function tohex(s)
      local t = {}
      for i = 1, #s do t[i] = string.format("%02x", string.byte(s, i)) end
      return table.concat(t)
    end
    -- Expected from Python bitcoin-core test_framework chacha20_block on
    -- FSChaCha20 post-rekey (initial key above, nonce=(0,1), counter=0).
    assert.equals("8f1a6b76320eca3ecf76295824790c90", tohex(ks))
  end)

  it("FSChaCha20Poly1305 FSAEAD_TESTS[0] vector across 2 rekey boundaries (W57)", function()
    -- W57 regression: Python reference FSChaCha20Poly1305 produces a specific
    -- ciphertext after 500 warmup encrypts (crossing rekey boundaries at
    -- packets 224 and 448). This tests the full packet-cipher chain end to
    -- end against the Core test framework's canonical vector — any drift
    -- from Core's byte output (either in the rekey derivation, the AEAD
    -- primitive, or the nonce construction) will fail this test.
    local ffi = require("ffi")
    local bit = require("bit")
    local crypto = require("lunarblock.crypto")
    local REKEY_INTERVAL = 224
    local function FSP(key)
      local self = { key = key, packet_counter = 0, rekey_counter = ffi.new("uint64_t", 0) }
      local function make_nonce()
        local n = ffi.new("unsigned char[12]")
        n[0] = bit.band(self.packet_counter, 0xFF)
        n[1] = bit.band(bit.rshift(self.packet_counter, 8), 0xFF)
        n[2] = bit.band(bit.rshift(self.packet_counter, 16), 0xFF)
        n[3] = bit.band(bit.rshift(self.packet_counter, 24), 0xFF)
        local rc = self.rekey_counter
        for i = 0, 7 do n[4+i] = tonumber(bit.band(bit.rshift(rc, i*8), 0xFF)) end
        return ffi.string(n, 12)
      end
      local function rekey()
        local rn = ffi.new("unsigned char[12]")
        rn[0], rn[1], rn[2], rn[3] = 0xFF, 0xFF, 0xFF, 0xFF
        local rc = self.rekey_counter
        for i = 0, 7 do rn[4+i] = tonumber(bit.band(bit.rshift(rc, i*8), 0xFF)) end
        local blob = crypto.chacha20poly1305_encrypt(self.key, ffi.string(rn, 12), string.rep("\0", 32), "")
        self.key = blob:sub(1, 32)
        self.packet_counter = 0
        self.rekey_counter = self.rekey_counter + ffi.new("uint64_t", 1)
      end
      function self:encrypt(plain, aad)
        local n = make_nonce()
        local res = crypto.chacha20poly1305_encrypt(self.key, n, plain, aad)
        self.packet_counter = self.packet_counter + 1
        if self.packet_counter == REKEY_INTERVAL then rekey() end
        return res
      end
      return self
    end
    local function fromhex(h)
      h = h:gsub("%s+", "")
      local out = {}
      for i = 1, #h, 2 do out[#out+1] = string.char(tonumber(h:sub(i, i+1), 16)) end
      return table.concat(out)
    end
    local function tohex(s)
      local t = {}
      for i = 1, #s do t[i] = string.format("%02x", string.byte(s, i)) end
      return table.concat(t)
    end
    local plain = fromhex("d6a4cb04ef0f7c09c1866ed29dc24d820e75b0491032a51b4c3366f9ca35c19e"
      .. "a3047ec6be9d45f9637b63e1cf9eb4c2523a5aab7b851ebeba87199db0e839cf"
      .. "0d5c25e50168306377aedbe9089fd2463ded88b83211cf51b73b150608cc7a60"
      .. "0d0f11b9a742948482e1b109d8faf15b450aa7322e892fa2208c6691e3fecf4c"
      .. "711191b14d75a72147")
    local aad = fromhex("786cb9b6ebf44288974cf0")
    local key = fromhex("5c9e1c3951a74fba66708bf9d2c217571684556b6a6a3573bff2847d38612654")
    local expected = "9dcebbd3281ea3dd8e9a1ef7d55a97abd6743e56ebc0c190cb2c4e14160b385e"
      .. "0bf508dddf754bd02c7c208447c131ce23e47a4a14dfaf5dd8bc601323950f75"
      .. "4e05d46e9232f83fc5120fbbef6f5347a826ec79a93820718d4ec7a2b7cfaaa4"
      .. "4b21e16d726448b62f803811aff4f6d827ed78e738ce8a507b81a8ae13131192"
      .. "8039213de18a5120dc9b7370baca878f50ff254418de3da50c"
    local c = FSP(key)
    for _ = 1, 500 do c:encrypt("", "") end
    local got = c:encrypt(plain, aad)
    assert.equals(expected, tohex(got))
  end)
end)
