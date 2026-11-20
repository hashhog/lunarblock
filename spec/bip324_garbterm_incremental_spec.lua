--- BIP324 garbage-terminator search must be incremental.
--
-- Background: in GARB_GARBTERM, _recv_loop rescanned the whole garbage
-- buffer from offset 0 on every call, with one string.sub (a new substring)
-- per offset.  recv_bytes runs it on every tick, even when no bytes arrived,
-- so a peer that sends 4,111 bytes without a terminator and then goes quiet
-- cost ~4,096 substring allocations per tick until the handshake timeout.
-- Core's V2Transport::ProcessReceivedGarbageBytes (bitcoin-core/src/net.cpp)
-- checks only the newest 16-byte window per received byte, so its work is
-- proportional to the bytes received, and zero when nothing arrives.

package.path = "src/?.lua;" .. package.path
package.preload["lunarblock.crypto"] = package.preload["lunarblock.crypto"]
  or function() return require("crypto") end
local bip324 = require("bip324")

describe("BIP324 garbage terminator scan is incremental", function()
  local real_sub, real_find = string.sub, string.find
  local sub_calls, find_calls

  local function hook()
    sub_calls, find_calls = 0, 0
    string.sub = function(...) sub_calls = sub_calls + 1; return real_sub(...) end
    string.find = function(...) find_calls = find_calls + 1; return real_find(...) end
  end

  local function unhook()
    string.sub, string.find = real_sub, real_find
  end

  after_each(unhook)

  local magic = "\xfa\xbf\xb5\xda" -- regtest
  local MAXG = bip324.MAX_GARBAGE_LEN
  local TLEN = bip324.GARBAGE_TERMINATOR_LEN

  -- A connected initiator/responder pair, the responder in GARB_GARBTERM with
  -- an empty buffer (only the initiator's 64-byte key has been delivered).
  local function pair()
    local initiator = bip324.V2Transport(magic, true)
    local responder = bip324.V2Transport(magic, false)
    -- Take both keys first: get_handshake_bytes returns "" once a side has
    -- left its key-waiting send state.
    local ikey = initiator:get_handshake_bytes():sub(1, 64)
    local rkey = responder:get_handshake_bytes():sub(1, 64)
    local ok, err = responder:recv_bytes(ikey)
    assert.is_true(ok, tostring(err))
    ok, err = initiator:recv_bytes(rkey)
    assert.is_true(ok, tostring(err))
    assert.is_true(initiator.cipher.initialized)
    assert.equals(bip324.RecvState.GARB_GARBTERM, responder.recv_state)
    assert.equals(0, #responder.recv_buffer)
    return initiator, responder
  end

  -- Garbage that cannot contain the terminator (every byte differs from the
  -- terminator's first byte).
  local function garbage(n, term)
    local c = term:byte(1) == 0xAB and "\xCD" or "\xAB"
    return string.rep(c, n)
  end

  it("does no string work on recv_bytes('') while holding 4111 garbage bytes", function()
    local _, responder = pair()
    local term = responder:get_recv_garbage_terminator()
    local ok, err = responder:recv_bytes(garbage(MAXG + TLEN, term))
    assert.is_true(ok, tostring(err))
    assert.equals(bip324.RecvState.GARB_GARBTERM, responder.recv_state)

    hook()
    for _ = 1, 100 do
      ok, err = responder:recv_bytes("")
      assert.is_true(ok, tostring(err))
    end
    local subs, finds = sub_calls, find_calls
    unhook()
    assert.equals(0, subs, "string.sub calls across 100 empty recv_bytes")
    assert.equals(0, finds, "string.find calls across 100 empty recv_bytes")
    assert.equals(bip324.RecvState.GARB_GARBTERM, responder.recv_state)
  end)

  it("work per byte-at-a-time delivery stays bounded (no rescan from offset 0)", function()
    local _, responder = pair()
    local term = responder:get_recv_garbage_terminator()
    local g = garbage(MAXG + TLEN, term)
    hook()
    for i = 1, #g do
      local ok, err = responder:recv_bytes(real_sub(g, i, i))
      assert.is_true(ok, tostring(err))
    end
    local subs = sub_calls
    unhook()
    -- A rescan from 0 costs ~#g^2/2 (~8.4M) substring calls; incremental
    -- work is O(1) per byte.
    assert.is_true(subs <= 2 * #g, "string.sub calls for " .. #g .. " single-byte reads: " .. subs)
  end)

  -- Handshake completes for each garbage length and delivery chunking,
  -- including a terminator split across reads, and the version packet's AAD
  -- is exactly the garbage (decrypt would fail otherwise).
  for _, glen in ipairs({0, 1, 15, 16, 17, 1000, MAXG}) do
    for _, chunk in ipairs({1, 7, 16, 100000}) do
      it(("finds the terminator: garbage=%d chunk=%d"):format(glen, chunk), function()
        local initiator, responder = pair()
        local term = responder:get_recv_garbage_terminator()
        local g = garbage(glen, term)
        initiator.garbage = g
        local term_and_version = initiator:make_version_packet()
        -- Garbage and terminator arrive in `chunk`-sized reads (so the
        -- terminator is split across reads); the version packet follows in
        -- one read.
        local stream = g .. term_and_version:sub(1, TLEN)
        for i = 1, #stream, chunk do
          local ok, err = responder:recv_bytes(stream:sub(i, i + chunk - 1))
          assert.is_true(ok, tostring(err))
        end
        assert.equals(bip324.RecvState.VERSION, responder.recv_state)
        local ok, err = responder:recv_bytes(term_and_version:sub(TLEN + 1))
        assert.is_true(ok, tostring(err))
        assert.equals(bip324.RecvState.APP, responder.recv_state)
      end)
    end
  end

  it("rejects once more than 4095 garbage bytes precede the terminator", function()
    local initiator, responder = pair()
    local term = responder:get_recv_garbage_terminator()
    local g = garbage(MAXG + 1, term)
    local ok = true
    for i = 1, #g + TLEN do
      local b = i <= #g and g:sub(i, i) or term:sub(i - #g, i - #g)
      ok = responder:recv_bytes(b)
      if not ok then break end
    end
    assert.is_false(ok)
    assert.are_not.equal(bip324.RecvState.VERSION, responder.recv_state)
  end)

  it("accepts a terminator that first appears after earlier near-matches", function()
    local initiator, responder = pair()
    local term = responder:get_recv_garbage_terminator()
    -- Garbage made of 15-byte terminator prefixes: every one is a partial
    -- match that a scan must step past without skipping the real one.
    local near = term:sub(1, 15)
    local g = string.rep(near, 20)
    initiator.garbage = g
    local term_and_version = initiator:make_version_packet()
    local stream = g .. term_and_version:sub(1, TLEN)
    for i = 1, #stream, 5 do
      local ok, err = responder:recv_bytes(stream:sub(i, i + 4))
      assert.is_true(ok, tostring(err))
    end
    assert.equals(bip324.RecvState.VERSION, responder.recv_state)
    assert.equals(g, responder.recv_aad)
    local ok, err = responder:recv_bytes(term_and_version:sub(TLEN + 1))
    assert.is_true(ok, tostring(err))
    assert.equals(bip324.RecvState.APP, responder.recv_state)
  end)
end)
