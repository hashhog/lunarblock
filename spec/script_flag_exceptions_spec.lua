-- GetBlockScriptFlags parity with Bitcoin Core (script_flag_exceptions).
--
-- Core's GetBlockScriptFlags (bitcoin-core/src/validation.cpp:2249-2289) is a
-- THREE-STEP sequence and the order is load-bearing:
--
--   step 1  BASE       flags = P2SH | WITNESS | TAPROOT, UNCONDITIONALLY, for
--                      every block (:2262).  Core has had no BIP16Height and no
--                      taprootHeight in this path since v23.
--   step 2  EXCEPTION  on a block-hash hit in script_flag_exceptions, REPLACE
--                      the entire flag set with the table's value (:2264-2267).
--                      This is an assignment, NOT an early return.
--   step 3  HEIGHT     OR the four still-height-gated soft forks on top of the
--                      step-2 result (:2268-2286): DERSIG (BIP66), CLTV (BIP65),
--                      CSV (BIP68/112/113), NULLDUMMY (BIP147, rides SegWit).
--
-- Getting step 3 to run AFTER step 2 is the whole point.  Mainnet block 692261's
-- exception value is P2SH|WITNESS; an early return yields P2SH|WITNESS alone and
-- DROPS DERSIG|CLTV|CSV|NULLDUMMY, all four active at that height.  That is a
-- FALSE-ACCEPT — the node would accept scripts Core rejects under BIP-66/65/
-- 112/147.
--
-- Exception table (bitcoin-core/src/kernel/chainparams.cpp:85-88, 210-211):
--   mainnet  170060  00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22 -> NONE
--   mainnet  692261  0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad -> P2SH|WITNESS
--   testnet3         00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105 -> NONE

describe("GetBlockScriptFlags (script_flag_exceptions)", function()
  local consensus, types

  local MAINNET_BIP16_HEX   = "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
  local MAINNET_TAPROOT_HEX = "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"
  local TESTNET3_BIP16_HEX  = "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"
  local NON_EXCEPTION_HEX   = "0000000000000000000000000000000000000000000000000000000000000001"

  local BIP16_HEIGHT   = 170060
  local TAPROOT_HEIGHT = 692261

  setup(function()
    package.path = "src/?.lua;lunarblock/?.lua;" .. package.path
    consensus = require("consensus")
    types     = require("types")
  end)

  -- Sorted "{A|B|C}" rendering so a mismatch prints the whole set.
  local function render(flags)
    local ks = {}
    for k, v in pairs(flags) do if v then ks[#ks + 1] = k end end
    table.sort(ks)
    return "{" .. table.concat(ks, "|") .. "}"
  end

  local function flags_at(net_name, height, hex)
    return consensus.get_block_script_flags(
      consensus.networks[net_name], height, hex and types.hash256_from_hex(hex) or nil)
  end

  describe("exception table", function()
    it("carries Core's two mainnet entries and one testnet3 entry", function()
      local mn = consensus.SCRIPT_FLAG_EXCEPTIONS.mainnet
      assert.is_table(mn[MAINNET_BIP16_HEX])
      assert.is_nil(next(mn[MAINNET_BIP16_HEX]))          -- SCRIPT_VERIFY_NONE
      assert.equals("{verify_p2sh|verify_witness}", render(mn[MAINNET_TAPROOT_HEX]))
      local tn = consensus.SCRIPT_FLAG_EXCEPTIONS.testnet
      assert.is_table(tn[TESTNET3_BIP16_HEX])
      assert.is_nil(next(tn[TESTNET3_BIP16_HEX]))
    end)

    it("is empty for testnet4 and regtest", function()
      assert.is_nil(next(consensus.SCRIPT_FLAG_EXCEPTIONS.testnet4))
      assert.is_nil(next(consensus.SCRIPT_FLAG_EXCEPTIONS.regtest))
    end)
  end)

  describe("the three Core-authoritative results", function()
    it("[170060] BIP16 violator -> SCRIPT_VERIFY_NONE", function()
      -- Exception value is NONE and none of the four height gates are active at
      -- 170060 (bip66=363725, bip65=388381, csv=419328, segwit=481824).
      local f = flags_at("mainnet", BIP16_HEIGHT, MAINNET_BIP16_HEX)
      assert.equals("{}", render(f))
    end)

    it("[692261] Taproot violator -> P2SH|WITNESS|DERSIG|CLTV|CSV|NULLDUMMY (TAPROOT stripped)", function()
      local f = flags_at("mainnet", TAPROOT_HEIGHT, MAINNET_TAPROOT_HEX)
      assert.is_true(f.verify_p2sh)
      assert.is_true(f.verify_witness)
      assert.is_falsy(f.verify_taproot)
      -- The four that an early-return implementation would silently drop.
      assert.is_true(f.verify_dersig)
      assert.is_true(f.verify_checklocktimeverify)
      assert.is_true(f.verify_checksequenceverify)
      assert.is_true(f.verify_nulldummy)
      assert.equals(
        "{verify_checklocktimeverify|verify_checksequenceverify|verify_dersig|"
        .. "verify_nulldummy|verify_p2sh|verify_witness}", render(f))
    end)

    it("[control @692261] a NON-exception hash KEEPS taproot", function()
      local f = flags_at("mainnet", TAPROOT_HEIGHT, NON_EXCEPTION_HEX)
      assert.is_true(f.verify_taproot)
      assert.equals(
        "{verify_checklocktimeverify|verify_checksequenceverify|verify_dersig|"
        .. "verify_nulldummy|verify_p2sh|verify_taproot|verify_witness}", render(f))
    end)

    it("[testnet3] BIP16 violator -> SCRIPT_VERIFY_NONE", function()
      assert.equals("{}", render(flags_at("testnet", 514, TESTNET3_BIP16_HEX)))
    end)
  end)

  describe("step 1: base flags are unconditional", function()
    -- Core dropped BIP16Height/taprootHeight from this path in v23; the two
    -- violating blocks are handled by the exception table, not by height.
    it("P2SH|WITNESS|TAPROOT are on at genesis", function()
      local f = flags_at("mainnet", 0, NON_EXCEPTION_HEX)
      assert.equals("{verify_p2sh|verify_taproot|verify_witness}", render(f))
    end)

    it("WITNESS is on long before segwit_height", function()
      assert.is_true(flags_at("mainnet", BIP16_HEIGHT, NON_EXCEPTION_HEX).verify_witness)
    end)

    it("TAPROOT is on long before taproot activation (709632)", function()
      assert.is_true(flags_at("mainnet", BIP16_HEIGHT, NON_EXCEPTION_HEX).verify_taproot)
      assert.is_true(flags_at("mainnet", 709631, NON_EXCEPTION_HEX).verify_taproot)
    end)
  end)

  describe("step 3: buried deployments use >= (DeploymentActiveAt)", function()
    local mn
    setup(function() mn = consensus.networks.mainnet end)

    it("DERSIG flips at bip66_height", function()
      assert.is_falsy(flags_at("mainnet", mn.bip66_height - 1, NON_EXCEPTION_HEX).verify_dersig)
      assert.is_true(flags_at("mainnet", mn.bip66_height, NON_EXCEPTION_HEX).verify_dersig)
    end)
    it("CLTV flips at bip65_height", function()
      assert.is_falsy(flags_at("mainnet", mn.bip65_height - 1, NON_EXCEPTION_HEX).verify_checklocktimeverify)
      assert.is_true(flags_at("mainnet", mn.bip65_height, NON_EXCEPTION_HEX).verify_checklocktimeverify)
    end)
    it("CSV flips at csv_height", function()
      assert.is_falsy(flags_at("mainnet", mn.csv_height - 1, NON_EXCEPTION_HEX).verify_checksequenceverify)
      assert.is_true(flags_at("mainnet", mn.csv_height, NON_EXCEPTION_HEX).verify_checksequenceverify)
    end)
    it("NULLDUMMY flips at segwit_height", function()
      assert.is_falsy(flags_at("mainnet", mn.segwit_height - 1, NON_EXCEPTION_HEX).verify_nulldummy)
      assert.is_true(flags_at("mainnet", mn.segwit_height, NON_EXCEPTION_HEX).verify_nulldummy)
    end)
  end)

  describe("byte order", function()
    -- The table is keyed by DISPLAY-order (big-endian) hex, which is what
    -- types.hash256_hex returns.  A byte-reversed key is a different block and
    -- must NOT hit — negative control against a well-meaning "endianness fix".
    local function reverse_hex(hex)
      local h = types.hash256_from_hex(hex)
      return types.hash256_hex({ bytes = h.bytes:reverse() })
    end

    it("display-order hex round-trips through hash256_from_hex/hash256_hex", function()
      assert.equals(MAINNET_TAPROOT_HEX,
        types.hash256_hex(types.hash256_from_hex(MAINNET_TAPROOT_HEX)))
    end)

    it("byte-reversed exception hash does NOT hit the table (keeps taproot)", function()
      local rev = reverse_hex(MAINNET_TAPROOT_HEX)
      assert.is_nil(consensus.SCRIPT_FLAG_EXCEPTIONS.mainnet[rev])
      local f = flags_at("mainnet", TAPROOT_HEIGHT, rev)
      assert.is_true(f.verify_taproot)
      assert.is_true(f.verify_p2sh)
    end)

    it("byte-reversed BIP16 hash does NOT hit the table", function()
      local rev = reverse_hex(MAINNET_BIP16_HEX)
      assert.is_nil(consensus.SCRIPT_FLAG_EXCEPTIONS.mainnet[rev])
      assert.is_true(flags_at("mainnet", BIP16_HEIGHT, rev).verify_p2sh)
    end)
  end)

  describe("hygiene", function()
    it("never aliases the module exception table (step 3 must not mutate it)", function()
      flags_at("mainnet", TAPROOT_HEIGHT, MAINNET_TAPROOT_HEX)
      flags_at("mainnet", BIP16_HEIGHT, MAINNET_BIP16_HEX)
      assert.equals("{verify_p2sh|verify_witness}",
        render(consensus.SCRIPT_FLAG_EXCEPTIONS.mainnet[MAINNET_TAPROOT_HEX]))
      assert.is_nil(next(consensus.SCRIPT_FLAG_EXCEPTIONS.mainnet[MAINNET_BIP16_HEX]))
    end)

    it("returns a fresh table per call", function()
      local a = flags_at("mainnet", TAPROOT_HEIGHT, NON_EXCEPTION_HEX)
      local b = flags_at("mainnet", TAPROOT_HEIGHT, NON_EXCEPTION_HEX)
      assert.is_false(rawequal(a, b))
    end)

    it("contains no STANDARD/policy flags at any height", function()
      -- NULLFAIL, CLEANSTACK, LOW_S, STRICTENC, MINIMALDATA, MINIMALIF,
      -- WITNESS_PUBKEYTYPE, CONST_SCRIPTCODE are STANDARD_SCRIPT_VERIFY_FLAGS
      -- (policy/policy.h:125) and must never appear in block validation.
      local policy = {
        "verify_nullfail", "verify_cleanstack", "verify_low_s", "verify_strictenc",
        "verify_minimaldata", "verify_minimalif", "verify_witness_pubkeytype",
        "verify_const_scriptcode", "verify_sigpushonly",
        "verify_discourage_upgradable_nops",
      }
      for _, h in ipairs({0, BIP16_HEIGHT, TAPROOT_HEIGHT, 900000}) do
        local f = flags_at("mainnet", h, NON_EXCEPTION_HEX)
        for _, name in ipairs(policy) do
          assert.is_falsy(f[name], name .. " leaked at height " .. h)
        end
      end
    end)

    it("does not cross-pollute networks without exceptions", function()
      assert.is_true(flags_at("testnet4", 1, MAINNET_BIP16_HEX).verify_p2sh)
      assert.is_true(flags_at("regtest", 1, MAINNET_BIP16_HEX).verify_taproot)
    end)

    it("tolerates a nil block hash (context-free callers)", function()
      local f = consensus.get_block_script_flags(consensus.networks.mainnet, TAPROOT_HEIGHT, nil)
      assert.is_true(f.verify_taproot)
      assert.is_true(f.verify_dersig)
    end)
  end)

  describe("sigop counting consumes the same exception-aware flags", function()
    -- Core passes the identical `flags` to GetTransactionSigOpCost
    -- (validation.cpp:2565); P2SH sigops are gated on SCRIPT_VERIFY_P2SH
    -- (consensus/tx_verify.cpp:150-152) and CountWitnessSigOps returns 0 when
    -- SCRIPT_VERIFY_WITNESS is clear (script/interpreter.cpp:2140-2142).
    local validation

    setup(function() validation = require("validation") end)

    it("[170060] counts no P2SH sigops under the NONE exception", function()
      local flags = flags_at("mainnet", BIP16_HEIGHT, MAINNET_BIP16_HEX)

      -- One input spending a P2SH output whose redeemScript holds a 2-of-3
      -- CHECKMULTISIG (20 sigops when counted accurately).
      local redeem = string.char(0x52)                        -- OP_2
        .. string.char(0x21) .. string.rep("\x02", 33)
        .. string.char(0x21) .. string.rep("\x03", 33)
        .. string.char(0x21) .. string.rep("\x02", 33)
        .. string.char(0x53)                                  -- OP_3
        .. string.char(0xae)                                  -- OP_CHECKMULTISIG
      -- redeemScript is 105 bytes, so the push needs OP_PUSHDATA1.
      local script_sig = string.char(0x4c, #redeem) .. redeem
      local p2sh_spk = string.char(0xa9, 0x14) .. string.rep("\x01", 20) .. string.char(0x87)

      local tx = {
        version = 1, locktime = 0,
        inputs = { { prev_out = { hash = { bytes = string.rep("\x11", 32) }, index = 0 },
                     script_sig = script_sig, sequence = 0xffffffff, witness = {} } },
        outputs = { { value = 1000, script_pubkey = "" } },
      }
      local function get_prev(_) return { value = 2000, script_pubkey = p2sh_spk } end

      local cost_none  = validation.get_transaction_sigop_cost(tx, get_prev, flags)
      local cost_p2sh  = validation.get_transaction_sigop_cost(tx, get_prev,
        { verify_p2sh = true, verify_witness = true })

      assert.is_falsy(flags.verify_p2sh)
      assert.is_true(cost_p2sh > cost_none)
      -- With NONE, only the (zero) legacy count remains.
      assert.equals(validation.get_legacy_sigop_count(tx) * 4, cost_none)
    end)

    it("[692261] still counts P2SH + witness sigops (exception is P2SH|WITNESS)", function()
      local flags = flags_at("mainnet", TAPROOT_HEIGHT, MAINNET_TAPROOT_HEX)
      assert.is_true(flags.verify_p2sh)
      assert.is_true(flags.verify_witness)
    end)
  end)
end)
