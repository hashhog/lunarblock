--- BIP324Cipher:initialize must not force a full Lua GC cycle.
--
-- Background: initialize used to end with collectgarbage("collect"), a full
-- stop-the-world collection of the whole Lua heap.  Any inbound connection
-- reaches it by sending 64 non-v1 bytes (inbound v2 is on by default), and it
-- runs on the single event loop that also serves P2P, RPC and REST, so a peer
-- could stall the node once per connection, repeatedly.  Core's
-- BIP324Cipher::Initialize (bitcoin-core/src/bip324.cpp) does constant
-- per-connection work.  The collect did not even achieve its stated goal:
-- Lua strings are immutable and the GC does not zero freed memory.

describe("BIP324 cipher initialize does no forced GC", function()
  local bip324
  local real_collectgarbage
  local calls

  setup(function()
    package.path = "src/?.lua;" .. package.path
    package.preload["lunarblock.crypto"] = function() return require("crypto") end
    bip324 = require("bip324")
  end)

  before_each(function()
    calls = {}
    real_collectgarbage = _G.collectgarbage
    _G.collectgarbage = function(opt, ...)
      calls[#calls + 1] = opt or "collect"
      return real_collectgarbage(opt, ...)
    end
  end)

  after_each(function()
    _G.collectgarbage = real_collectgarbage
  end)

  local function full_collects()
    local n = 0
    for _, opt in ipairs(calls) do
      if opt == "collect" then n = n + 1 end
    end
    return n
  end

  local magic = "\xfa\xbf\xb5\xda" -- regtest

  it("responder V2Transport completes key exchange without collectgarbage('collect')", function()
    local initiator = bip324.V2Transport(magic, true)
    local their_key = initiator:get_handshake_bytes():sub(1, 64)
    assert.equals(64, #their_key)

    local responder = bip324.V2Transport(magic, false)
    calls = {}
    local ok, err = responder:recv_bytes(their_key)
    assert.is_true(ok, tostring(err))
    -- The cipher really was initialized by those 64 bytes.
    assert.is_true(responder.cipher.initialized)
    assert.equals(bip324.RecvState.GARB_GARBTERM, responder.recv_state)
    assert.equals(0, full_collects())
  end)

  it("initiator side initialize also does not force a full collection", function()
    local responder = bip324.V2Transport(magic, false)
    local initiator = bip324.V2Transport(magic, true)
    local resp_key = responder:get_handshake_bytes():sub(1, 64)
    calls = {}
    local ok, err = initiator:recv_bytes(resp_key)
    assert.is_true(ok, tostring(err))
    assert.is_true(initiator.cipher.initialized)
    assert.equals(0, full_collects())
  end)

  it("both sides still derive matching session keys", function()
    local a = bip324.V2Transport(magic, true)
    local b = bip324.V2Transport(magic, false)
    local a_hs = a:get_handshake_bytes()
    local b_hs = b:get_handshake_bytes()
    assert.is_true((b:recv_bytes(a_hs:sub(1, 64))))
    assert.is_true((a:recv_bytes(b_hs:sub(1, 64))))
    assert.equals(a.cipher.send_garbage_terminator, b.cipher.recv_garbage_terminator)
    assert.equals(a.cipher.recv_garbage_terminator, b.cipher.send_garbage_terminator)
    assert.equals(a.cipher.session_id, b.cipher.session_id)
  end)
end)
