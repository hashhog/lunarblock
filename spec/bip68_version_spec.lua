-- BIP-68 version gate unsigned-compare (differential bug-hunt, 2026-06-14).
-- Reference: bitcoin-core/src/consensus/tx_verify.cpp:51 (fEnforceBIP68 = version
--            >= 2, unsigned) + primitives/transaction.h:293 (const uint32_t version).
--
-- lunarblock reads the tx version via read_i32le (signed). The BIP-68 connect-block
-- gate (utxo.lua) compared it signed, so a high-bit version (0x80000002, read as
-- -2147483646) was treated as < 2 and BIP-68 was SKIPPED -> false-accept of a tx
-- with an unmet relative timelock (a chain split). bip68_version_active reinterprets
-- as unsigned 32-bit (% 2^32). Pure function -> non-vacuity is self-evident.
local utxo = require("lunarblock.utxo")

describe("BIP-68 version gate compares unsigned (Core uint32_t)", function()
  it("a high-bit version 0x80000002 enables BIP-68", function()
    assert.is_true(utxo.bip68_version_active(-2147483646)) -- 0x80000002 read signed
    assert.is_true(utxo.bip68_version_active(-1))          -- 0xFFFFFFFF read signed
    assert.is_true(utxo.bip68_version_active(2))
    assert.is_true(utxo.bip68_version_active(3))
    assert.is_false(utxo.bip68_version_active(1))
    assert.is_false(utxo.bip68_version_active(0))
  end)
end)
