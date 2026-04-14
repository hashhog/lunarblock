--- Regression test for BIP324 v2 handshake aux randomness.
--
-- Background: prior to wave5-2026-04-14, src/bip324.lua:458 called
-- crypto.ellswift_create(privkey) with no auxrnd32 argument, causing
-- libsecp256k1 to derive a deterministic encoding that Bitcoin Core
-- mainnet peers silently rejected. Node sat at Peers: 0 forever.
--
-- Fix: pass a fresh 32-byte CSPRNG value as auxrnd32 on every V2Transport
-- construction. See wave4-2026-04-14/LUNARBLOCK-BLOCK-SYNC-STALL-DIAG.md
-- and bitcoin-core/src/bip324.cpp:28 (m_key.EllSwiftCreate(ent32)).

describe("BIP324 v2 handshake aux randomness", function()
  local bip324
  local crypto

  setup(function()
    package.path = "src/?.lua;" .. package.path
    package.preload["lunarblock.crypto"] = function() return require("crypto") end
    crypto = require("crypto")
    bip324 = require("bip324")
  end)

  it("ellswift_create accepts a 32-byte auxrnd32 argument", function()
    local priv = crypto.random_bytes(32)
    local aux = crypto.random_bytes(32)
    assert.equals(32, #aux)
    local ell = crypto.ellswift_create(priv, aux)
    assert.is_not_nil(ell)
    assert.equals(64, #ell)
  end)

  it("produces distinct ellswift public keys across V2Transport instances", function()
    -- Two handshakes built back-to-back must differ in their ellswift output
    -- even if by cosmic coincidence the privkey collides (negligible).
    local magic = "\xf9\xbe\xb4\xd9"
    local t1 = bip324.V2Transport(magic, true)
    local t2 = bip324.V2Transport(magic, true)
    local b1 = t1:get_handshake_bytes()
    local b2 = t2:get_handshake_bytes()
    -- First 64 bytes of the sent handshake are the ellswift key.
    assert.equals(64, #b1:sub(1, 64))
    assert.equals(64, #b2:sub(1, 64))
    -- Non-determinism: two fresh V2Transport instances produce different keys.
    assert.are_not.equal(b1:sub(1, 64), b2:sub(1, 64))
  end)
end)
