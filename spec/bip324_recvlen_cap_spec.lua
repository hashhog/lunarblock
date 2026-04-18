--- Regression test for BIP324 oversize-frame rejection (W67c).
--
-- Background: the BIP324 length field is a 24-bit little-endian value,
-- so a malformed or malicious peer (or a length-cipher state desync) can
-- produce recv_len up to ~16 MiB. Bitcoin Core's net.h caps p2p messages
-- at MAX_PROTOCOL_MESSAGE_LENGTH = 4_000_000; anything larger is rejected
-- before it's buffered. Prior to W67c, lunarblock accepted whatever
-- decrypt_length returned, which let a misbehaving peer make us allocate
-- and retain ~16 MiB per connection (DoS / memory pressure, especially
-- during IBD where we're already RAM-tight on flush batches).
--
-- The fix: after decoding recv_len, reject and fail recv_bytes if the
-- value exceeds M.MAX_PAYLOAD_LEN (4 MB). recv_bytes returning false
-- propagates into Peer:recv_messages → Peer:disconnect, severing the
-- socket before the oversize payload is read.

describe("BIP324 recv_len 4 MB cap (W67c)", function()
  local bip324

  setup(function()
    package.path = "src/?.lua;" .. package.path
    bip324 = require("lunarblock.bip324")
  end)

  it("exposes MAX_PAYLOAD_LEN = 4_000_000", function()
    assert.equals(4000000, bip324.MAX_PAYLOAD_LEN)
  end)

  it("rejects a decoded recv_len above the cap", function()
    local magic = "\xf9\xbe\xb4\xd9"
    local t = bip324.V2Transport(magic, true)

    -- Jump the transport to post-handshake receive state so recv_bytes
    -- reaches the length-decrypt branch. Stub decrypt_length to return
    -- a value one byte above the cap.
    t.recv_state = bip324.RecvState.VERSION
    t.cipher.decrypt_length = function() return bip324.MAX_PAYLOAD_LEN + 1 end

    -- Feed exactly LENGTH_LEN bytes so we enter the length-decode branch
    -- but don't try to decrypt a full packet.
    local ok, err = t:recv_bytes(string.rep("\x00", bip324.LENGTH_LEN))
    assert.is_false(ok)
    assert.is_string(err)
    assert.is_truthy(err:find("oversize v2 frame", 1, true))
  end)

  it("accepts a decoded recv_len at exactly the cap", function()
    local magic = "\xf9\xbe\xb4\xd9"
    local t = bip324.V2Transport(magic, true)

    t.recv_state = bip324.RecvState.VERSION
    t.cipher.decrypt_length = function() return bip324.MAX_PAYLOAD_LEN end
    -- Stub decrypt so the packet-size path doesn't blow up waiting for
    -- 4 MB of ciphertext; we just want to prove the cap check passes at
    -- the boundary.
    t.cipher.decrypt = function() return nil, nil, "stub: not enough bytes" end

    -- Only LENGTH_LEN bytes: we'll pass the length check, then return true
    -- because #recv_buffer < packet_size (waiting for more data).
    local ok = t:recv_bytes(string.rep("\x00", bip324.LENGTH_LEN))
    assert.is_true(ok)
    assert.equals(bip324.MAX_PAYLOAD_LEN, t.recv_len)
  end)
end)
