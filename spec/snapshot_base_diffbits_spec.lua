-- spec/snapshot_base_diffbits_spec.lua
--
-- Regression proof for the snapshot-base nBits fail-open (2026-08-09).
--
-- THE BUG.  sync.lua carried a `skip_diffbits` relaxation that DISABLED the
-- nBits-vs-REQUIRED check (Bitcoin Core ContextualCheckBlockHeader,
-- validation.cpp:4086-4089) whenever
--     snapshot_base_height is set
--     AND the network retargets
--     AND height % 2016 == 0
--     AND (height - 2016) < snapshot_base_height
-- That predicate is true at EXACTLY ONE, PUBLICLY COMPUTABLE height per base
-- (mainnet base 944183 -> height 945504).  At that height accept_header still
-- checked hash <= DECLARED target ("high-hash"), but never checked the
-- DECLARED bits against the REQUIRED bits, so any unauthenticated peer could
-- mine a difficulty-1 header there for a laptop-second of work.  The header
-- did not even need to become the tip: accept_header writes height_to_hash and
-- CF.HEIGHT_INDEX unconditionally.
--
-- THE FIX.  Delete the relaxation; resolve the one pre-base ancestor the
-- retarget needs (boundary - 2016, which lies below the base and was never
-- downloaded) from a PINNED, HASH-VERIFIED anchor in the assumeutxo entry;
-- make "unresolvable" mean REJECT everywhere.
--
-- ALL TESTS HERE ARE MAINNET-SHAPED OR TESTNET4-SHAPED.  A regtest test would
-- prove nothing: regtest sets pow_no_retarget, so consensus.lua returns
-- prev.header.bits before the retarget branch is ever reached and a completely
-- broken implementation still passes.  (The regtest no-regression guard is at
-- the bottom, explicitly labelled as a guard, not as evidence.)
--
-- Reference: bitcoin-core/src/pow.cpp GetNextWorkRequired /
--            CalculateNextWorkRequired, bitcoin-core/src/validation.cpp
--            ContextualCheckBlockHeader (:4080-4121) and ActivateSnapshot
--            (:5611-5624).

local types = require("lunarblock.types")
local sync = require("lunarblock.sync")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local utxo = require("lunarblock.utxo")
local helpers = require("spec.helpers")

--------------------------------------------------------------------------------
-- Real mainnet constants (verified 2026-08-09 against TWO independent
-- genesis-synced mainnet nodes: blockbrew RPC 8355 and haskoin RPC 8354).
--------------------------------------------------------------------------------
local MAINNET       = consensus.networks.mainnet
local BASE_HEIGHT   = 944183          -- hashhog assumeutxo snapshot base
local ANCHOR_HEIGHT = 943488          -- floor(944183/2016)*2016
local BOUNDARY      = 945504          -- first retarget boundary above the base
local PERIOD_BITS   = 0x17020684      -- nBits throughout 943488..945503
local BOUNDARY_BITS = 0x17021369      -- REAL nBits of mainnet block 945504
local ATTACK_BITS   = 0x1d00ffff      -- difficulty 1 (the free-header attack)
local ANCHOR_TS     = 1775208520      -- real time of mainnet block 943488
local PREV_TS       = 1776448209      -- real time of mainnet block 945503
local ANCHOR_HASH   = "00000000000000000000223415062538352e7e03e6720ef6a79bee4b7fa973b0"

local INTERVAL = consensus.DIFFICULTY_ADJUSTMENT_INTERVAL
local ZERO_WORK_HEX = string.rep("0", 64)

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

--- Mainnet-SHAPED synthetic network (pow_no_retarget=false,
--- pow_allow_min_difficulty=false, enforce_bip94=false) carrying a copy of the
--- real 944183 assumeutxo entry.  min_chain_work is zeroed and checkpoints are
--- emptied so the test isolates the diffbits gate.
-- @param opts table|nil: {no_anchor=bool, anchor_ts=n, anchor_bits=n,
--                         anchor_hash=str, drop_anchor_bits=bool}
local function mainnet_shaped(opts)
  opts = opts or {}
  local src = MAINNET.assumeutxo[BASE_HEIGHT]
  local anchor = nil
  if not opts.no_anchor then
    anchor = {
      blockhash = opts.anchor_hash or ANCHOR_HASH,
      timestamp = opts.anchor_ts or ANCHOR_TS,
    }
    -- NB: `cond and nil or X` silently yields X in Lua; spell it out.
    if not opts.drop_anchor_bits then
      anchor.bits = opts.anchor_bits or PERIOD_BITS
    end
  end
  return {
    name = "mainnet-shaped",
    magic_bytes = MAINNET.magic_bytes,
    port = 8333, rpc_port = 8332,
    pubkey_address_prefix = 0x00, script_address_prefix = 0x05,
    wif_prefix = 0x80, bech32_hrp = "bc",
    genesis = MAINNET.genesis,
    genesis_hash = MAINNET.genesis_hash,
    checkpoints = {},
    bip34_height = 227931, bip66_height = 363725, bip65_height = 388381,
    csv_height = 419328, segwit_height = 481824, taproot_height = 709632,
    pow_limit_bits = MAINNET.pow_limit_bits,
    pow_no_retarget = false,
    pow_allow_min_difficulty = false,
    enforce_bip94 = false,
    min_chain_work = ZERO_WORK_HEX,
    assumevalid = nil,
    versionbits_period = 2016, versionbits_threshold = 1916,
    dns_seeds = {},
    headerssync_params = MAINNET.headerssync_params,
    assumeutxo = {
      [BASE_HEIGHT] = {
        hash_serialized  = src.hash_serialized,
        m_chain_tx_count = src.m_chain_tx_count,
        blockhash        = src.blockhash,
        header           = src.header,
        chain_work       = src.chain_work,
        pre_base_ancestors = anchor and { [ANCHOR_HEIGHT] = anchor } or nil,
      },
    },
  }
end

--- Materialise the REAL mainnet 944183 header from the assumeutxo entry.
-- Its hash is the pinned base blockhash, which is what the lineage gate in
-- HeaderChain:resolve_pre_base_ancestor checks against.
local function real_base_header()
  local h = MAINNET.assumeutxo[BASE_HEIGHT].header
  return types.block_header(
    h.version,
    types.hash256_from_hex(h.prev_hash),
    types.hash256_from_hex(h.merkle_root),
    h.timestamp, h.bits, h.nonce)
end

local function put_entry(chain, header, height, index)
  local hash = validation.compute_block_hash(header)
  local hex  = types.hash256_hex(hash)
  chain.headers[hex] = { header = header, height = height,
                         total_work = consensus.work_zero() }
  if index ~= false then chain.height_to_hash[height] = hex end
  return hash, hex
end

--- Timestamp schedule: 600s spacing ending at the REAL time of 945503, so the
--- retarget arithmetic reproduces the REAL nBits of 945504.
local function ts_for(height) return PREV_TS - (945503 - height) * 600 end

--- Build a snapshot-bootstrapped HeaderChain: NO genesis, NO headers below the
--- base — exactly the shape of the live mainnet lunarblock datadir.
-- @param net table: network table
-- @param opts table|nil: {top=height, nonce_offset=n, fake_base=bool}
-- @return chain, storage, tip_hash
local function build_snapshot_chain(net, opts)
  opts = opts or {}
  local top = opts.top or 945503
  local storage = helpers.mock_storage()
  local chain = sync.new_header_chain(net, storage)
  -- Deliberately NOT chain:init() — a snapshot node's header chain roots at
  -- the base, not at genesis.

  local base_header = real_base_header()
  if opts.fake_base then
    -- Same height, DIFFERENT hash: a lineage that does not run through the
    -- pinned base and must therefore NOT get the pinned anchor.
    base_header = types.block_header(
      base_header.version, base_header.prev_hash, base_header.merkle_root,
      base_header.timestamp, base_header.bits, base_header.nonce + 1)
  end
  local prev_hash = put_entry(chain, base_header, BASE_HEIGHT)
  chain.snapshot_base_height = BASE_HEIGHT

  for h = BASE_HEIGHT + 1, top do
    local hdr = types.block_header(0x20000000, prev_hash, types.hash256_zero(),
      ts_for(h), (h >= BOUNDARY) and BOUNDARY_BITS or PERIOD_BITS,
      h + (opts.nonce_offset or 0))
    prev_hash = put_entry(chain, hdr, h)
  end

  chain.header_tip_hash = prev_hash
  chain.header_tip_height = top
  return chain, storage, prev_hash
end

local function candidate_header(prev_hash, bits, ts)
  return types.block_header(0x20000000, prev_hash, types.hash256_zero(),
    ts or (PREV_TS + 600), bits, 0)
end

-- skip_pow bypasses ONLY the folded hash<=target gate (Core's context-free
-- CheckProofOfWork) so a synthetic, unmined header can reach the CONTEXTUAL
-- gates.  min_pow_checked bypasses the MinimumChainWork anti-DoS gate.
-- Neither touches the diffbits check, which is what is under test.
local ACCEPT_OPTS = { skip_pow = true, min_pow_checked = true,
                      current_time = PREV_TS + 1200 }

--------------------------------------------------------------------------------

describe("snapshot-base diffbits (mainnet-shaped)", function()

  ------------------------------------------------------------------------------
  -- T3 — the actual vulnerability
  ------------------------------------------------------------------------------
  describe("T3: the boundary above the snapshot base", function()

    it("3a ATTACK: rejects a difficulty-1 header at the boundary (bad-diffbits)", function()
      local chain, _, tip = build_snapshot_chain(mainnet_shaped())
      local cand = candidate_header(tip, ATTACK_BITS)
      local ok, err = chain:accept_header(cand, ACCEPT_OPTS)
      -- PRE-FIX: skip_diffbits fired here and this returned true.
      assert.is_false(ok, "difficulty-1 header at the snapshot boundary must be rejected")
      assert.truthy(err and err:find("bad%-diffbits", 1, false),
        "expected bad-diffbits, got: " .. tostring(err))
      assert.truthy(err:find("0x17021369", 1, true),
        "reject must name the REQUIRED bits, got: " .. tostring(err))
    end)

    it("3b HONEST: accepts the real 945504 nBits (no false-reject, no wedge)", function()
      local chain, _, tip = build_snapshot_chain(mainnet_shaped())
      local cand = candidate_header(tip, BOUNDARY_BITS)
      local ok, err = chain:accept_header(cand, ACCEPT_OPTS)
      assert.is_true(ok,
        "honest boundary header must still be accepted (this is the wedge the "
        .. "relaxation was invented to avoid); got: " .. tostring(err))
    end)

    it("3c NO-ANCHOR: fails CLOSED — both honest and attack headers rejected", function()
      local net = mainnet_shaped({ no_anchor = true })
      for _, bits in ipairs({ ATTACK_BITS, BOUNDARY_BITS }) do
        local chain, _, tip = build_snapshot_chain(net)
        local ok, err = chain:accept_header(candidate_header(tip, bits), ACCEPT_OPTS)
        assert.is_false(ok, "must never accept when the required bits are unresolvable")
        assert.truthy(err and err:find("diffbits%-unresolvable"),
          "expected diffbits-unresolvable, got: " .. tostring(err))
        assert.truthy(err:find("missing%-ancestor:943488"),
          "reason must name the missing ancestor height, got: " .. tostring(err))
      end
    end)

    it("3d NARROWNESS: the anchor is consulted at exactly one height", function()
      -- 947520's period-first is 945504, which is AT/ABOVE the base and comes
      -- from the parent-pointer walk.  Corrupting the pinned anchor must not
      -- change the answer at all.
      local good = mainnet_shaped()
      local chain_a, _, tip_a = build_snapshot_chain(good, { top = 947519 })
      local cand_a = types.block_header(0x20000000, tip_a, types.hash256_zero(),
        ts_for(947519) + 600, BOUNDARY_BITS, 0)
      local expected_a = chain_a:calculate_next_work_required(947520, cand_a)
      assert.is_number(expected_a)

      local bad = mainnet_shaped({ anchor_ts = 1, anchor_bits = 0x1d00ffff })
      local chain_b, _, tip_b = build_snapshot_chain(bad, { top = 947519 })
      local cand_b = types.block_header(0x20000000, tip_b, types.hash256_zero(),
        ts_for(947519) + 600, BOUNDARY_BITS, 0)
      local expected_b = chain_b:calculate_next_work_required(947520, cand_b)

      assert.equals(expected_a, expected_b,
        "the second boundary must not depend on the pinned anchor at all")
    end)
  end)

  ------------------------------------------------------------------------------
  -- T4 — poison-immunity
  ------------------------------------------------------------------------------
  describe("T4: poison-immunity", function()

    it("4a: a poisoned height_to_hash[943488] does not change the required bits", function()
      local chain, _, tip = build_snapshot_chain(mainnet_shaped())

      -- Fabricate a difficulty-1 "ancestor" at 943488 and make it the entry the
      -- HEIGHT INDEX points at — the primitive an attacker gets from
      -- accept_header's unconditional height_to_hash / CF.HEIGHT_INDEX write.
      local poison = types.block_header(0x20000000, types.hash256_zero(),
        types.hash256_zero(), 1, ATTACK_BITS, 99)
      put_entry(chain, poison, ANCHOR_HEIGHT)

      local ok, err = chain:accept_header(candidate_header(tip, ATTACK_BITS), ACCEPT_OPTS)
      assert.is_false(ok, "resolution must never read the height index")
      assert.truthy(err and err:find("bad%-diffbits"), tostring(err))
      assert.truthy(err:find("0x17021369", 1, true),
        "required bits must still be the honest ones, got: " .. tostring(err))

      -- ...and the honest header must still be accepted with the index poisoned.
      local chain2, _, tip2 = build_snapshot_chain(mainnet_shaped())
      put_entry(chain2, poison, ANCHOR_HEIGHT)
      local ok2, err2 = chain2:accept_header(candidate_header(tip2, BOUNDARY_BITS), ACCEPT_OPTS)
      assert.is_true(ok2, "poisoned index must not false-reject either; got " .. tostring(err2))
    end)

    it("4b: competing forks each compute from their OWN ancestry", function()
      local net = mainnet_shaped()
      local chain, _, tip_a = build_snapshot_chain(net)

      -- Fork B: same timestamps, different nonces from 944600 up, so it shares
      -- heights with fork A but has different hashes.
      local fork_parent_hex = chain.height_to_hash[944599]
      local prev_hash = validation.compute_block_hash(chain.headers[fork_parent_hex].header)
      for h = 944600, 945503 do
        local hdr = types.block_header(0x20000000, prev_hash, types.hash256_zero(),
          ts_for(h), PERIOD_BITS, h + 7777)
        prev_hash = put_entry(chain, hdr, h, false)  -- do NOT touch height_to_hash
      end
      local tip_b = prev_hash

      -- Both forks must demand the same (honest) bits at the boundary.
      local ok_a = chain:accept_header(candidate_header(tip_a, BOUNDARY_BITS), ACCEPT_OPTS)
      assert.is_true(ok_a, "fork A honest boundary header")
      -- Admitting fork A must not change fork B's verdict.
      local ok_b, err_b = chain:accept_header(candidate_header(tip_b, BOUNDARY_BITS), ACCEPT_OPTS)
      assert.is_true(ok_b, "fork B honest boundary header; got " .. tostring(err_b))

      local ok_c, err_c = chain:accept_header(candidate_header(tip_b, ATTACK_BITS), ACCEPT_OPTS)
      assert.is_false(ok_c, "fork B difficulty-1 boundary header must still be rejected")
      assert.truthy(err_c and err_c:find("bad%-diffbits"), tostring(err_c))
    end)

    it("4c: a lineage that does not reach the PINNED base gets no anchor", function()
      local chain, _, tip = build_snapshot_chain(mainnet_shaped(), { fake_base = true })
      local ok, err = chain:accept_header(candidate_header(tip, BOUNDARY_BITS), ACCEPT_OPTS)
      assert.is_false(ok, "anchor must be gated on the base's HASH, not its height")
      assert.truthy(err and err:find("diffbits%-unresolvable"), tostring(err))
    end)
  end)

  ------------------------------------------------------------------------------
  -- T9 — boot audit of an already-poisoned datadir
  ------------------------------------------------------------------------------
  describe("T9: boot audit of the stored chain", function()

    local function seed_storage(boundary_bits)
      local net = mainnet_shaped()
      local storage = helpers.mock_storage()
      local seeder = sync.new_header_chain(net, storage)
      local base_header = real_base_header()
      local prev_hash = validation.compute_block_hash(base_header)
      storage.put_header(prev_hash, base_header)
      storage.put_height_index(BASE_HEIGHT, prev_hash)
      for h = BASE_HEIGHT + 1, BOUNDARY do
        local hdr = types.block_header(0x20000000, prev_hash, types.hash256_zero(),
          ts_for(h), (h == BOUNDARY) and boundary_bits or PERIOD_BITS, h)
        prev_hash = validation.compute_block_hash(hdr)
        storage.put_header(prev_hash, hdr)
        storage.put_height_index(h, prev_hash)
      end
      seeder:set_snapshot_base_height(BASE_HEIGHT)
      seeder:set_header_tip(prev_hash, BOUNDARY, true)
      return net, storage
    end

    it("starts silently on an honest stored chain", function()
      local net, storage = seed_storage(BOUNDARY_BITS)
      local chain = sync.new_header_chain(net, storage)
      chain:init()
      assert.is_nil(chain.snapshot_audit_error)
      assert.equals(BOUNDARY, chain.header_tip_height)
    end)

    it("refuses to start on a datadir poisoned before the fix shipped", function()
      local net, storage = seed_storage(ATTACK_BITS)
      local chain = sync.new_header_chain(net, storage)
      chain:init()
      assert.is_string(chain.snapshot_audit_error)
      assert.truthy(chain.snapshot_audit_error:find("945504", 1, true),
        chain.snapshot_audit_error)
      assert.truthy(chain.snapshot_audit_error:find("0x1d00ffff", 1, true),
        chain.snapshot_audit_error)
    end)
  end)

  ------------------------------------------------------------------------------
  -- T6 — connect-time backstop (ChainState:check_diffbits, mainnet-shaped)
  ------------------------------------------------------------------------------
  describe("T6: connect-time backstop on a snapshot-base chain", function()

    local function seeded_chain_state(net)
      local storage = helpers.mock_storage()
      local seeder = sync.new_header_chain(net, storage)
      local base_header = real_base_header()
      local prev_hash = validation.compute_block_hash(base_header)
      storage.put_header(prev_hash, base_header)
      for h = BASE_HEIGHT + 1, 945503 do
        local hdr = types.block_header(0x20000000, prev_hash, types.hash256_zero(),
          ts_for(h), PERIOD_BITS, h)
        prev_hash = validation.compute_block_hash(hdr)
        storage.put_header(prev_hash, hdr)
      end
      seeder:set_snapshot_base_height(BASE_HEIGHT)
      return utxo.new_chain_state(storage, net), prev_hash
    end

    it("ACCEPTS the honest boundary block (pre-fix this false-rejected)", function()
      local cs, tip = seeded_chain_state(mainnet_shaped())
      local ok, err = cs:check_diffbits(candidate_header(tip, BOUNDARY_BITS), BOUNDARY)
      assert.is_true(ok, "honest boundary block must connect; got " .. tostring(err))
    end)

    it("REJECTS a difficulty-1 boundary block", function()
      local cs, tip = seeded_chain_state(mainnet_shaped())
      local ok, err = cs:check_diffbits(candidate_header(tip, ATTACK_BITS), BOUNDARY)
      assert.is_false(ok)
      assert.truthy(err and err:find("bad%-diffbits"), tostring(err))
    end)

    it("fails CLOSED without the anchor", function()
      local cs, tip = seeded_chain_state(mainnet_shaped({ no_anchor = true }))
      local ok, err = cs:check_diffbits(candidate_header(tip, BOUNDARY_BITS), BOUNDARY)
      assert.is_false(ok)
      assert.truthy(err and err:find("diffbits%-unresolvable"), tostring(err))
    end)
  end)

  ------------------------------------------------------------------------------
  -- T11 — Core reject-reason ORDER (validation.cpp:4086-4118)
  ------------------------------------------------------------------------------
  describe("T11: Core order — diffbits is checked FIRST", function()
    it("reports bad-diffbits, not time-too-old, when a header breaks both", function()
      local chain, _, tip = build_snapshot_chain(mainnet_shaped())
      -- ts well below the parent's MTP => also time-too-old.
      local cand = candidate_header(tip, ATTACK_BITS, ts_for(944200))
      local ok, err = chain:accept_header(cand, ACCEPT_OPTS)
      assert.is_false(ok)
      assert.truthy(err and err:find("bad%-diffbits"),
        "Core checks nBits first (validation.cpp:4088); got: " .. tostring(err))
    end)
  end)

  ------------------------------------------------------------------------------
  -- The banlist interaction (main.lua HEADERS_BAN_SUBSTRINGS)
  ------------------------------------------------------------------------------
  it("the unresolvable reason is NOT ban-worthy", function()
    -- main.lua substring-matches "bad-diffbits" and 100-score-bans on a hit.
    -- "diffbits-unresolvable" is OUR missing data, not peer misbehaviour: if
    -- the reason string contained that token the node would 24h-ban every
    -- honest peer at the boundary and empty its addrman.
    local BAN_SUBSTRINGS = {
      "proof of work", "difficulty transition", "non-continuous header",
      "commitment", "time-too-old", "time-timewarp", "bad-diffbits", "bad-version",
    }
    local chain, _, tip = build_snapshot_chain(mainnet_shaped({ no_anchor = true }))
    local _, err = chain:accept_header(candidate_header(tip, BOUNDARY_BITS), ACCEPT_OPTS)
    for _, s in ipairs(BAN_SUBSTRINGS) do
      assert.is_falsy(err:find(s, 1, true),
        "diffbits-unresolvable must not match ban substring '" .. s .. "': " .. err)
    end
  end)
end)

--------------------------------------------------------------------------------
-- T5 — testnet4-shaped (BIP94 + min-difficulty)
--------------------------------------------------------------------------------
describe("snapshot-base diffbits (testnet4-shaped: BIP94 + min-difficulty)", function()

  local T4_POW_LIMIT  = 0x1d00ffff
  local T4_PREV_BITS  = 0x1c010000   -- much harder than the limit
  local T4_ANCHOR_BITS = 0x1c7fff00  -- different from prev; BIP94 must use THIS
  local T4_BASE       = 4020         -- 4020 % 2016 = 2004  (not aligned)
  local T4_ANCHOR_H   = 2016         -- floor(4020/2016)*2016
  local T4_BOUNDARY   = 4032
  local T4_ANCHOR_TS  = 1000000
  local T4_PREV_TS    = T4_ANCHOR_TS + consensus.TARGET_TIMESPAN  -- exact timespan

  local function t4_net(opts)
    opts = opts or {}
    return {
      name = "testnet4-shaped",
      magic_bytes = "\x1c\x16\x3f\x28",
      port = 48333, rpc_port = 48332,
      pubkey_address_prefix = 0x6F, script_address_prefix = 0xC4,
      wif_prefix = 0xEF, bech32_hrp = "tb",
      genesis = consensus.networks.regtest.genesis,
      genesis_hash = consensus.networks.regtest.genesis_hash,
      checkpoints = {},
      bip34_height = 1, bip66_height = 1, bip65_height = 1,
      csv_height = 1, segwit_height = 1, taproot_height = 1,
      pow_limit_bits = T4_POW_LIMIT,
      pow_no_retarget = false,
      pow_allow_min_difficulty = true,
      enforce_bip94 = true,
      min_chain_work = ZERO_WORK_HEX,
      assumevalid = nil,
      versionbits_period = 2016, versionbits_threshold = 1512,
      dns_seeds = {},
      headerssync_params = { commitment_period = 275, redownload_buffer_size = 7017 },
      assumeutxo = {},
      _opts = opts,
    }
  end

  --- Build a testnet4-shaped snapshot chain.  The synthetic base header's own
  --- hash is written back into the assumeutxo entry, exactly the relationship
  --- the real tables have.
  local function build_t4(opts)
    opts = opts or {}
    local base_height = opts.base or T4_BASE
    local top         = opts.top or (T4_BOUNDARY - 1)
    local body_bits   = opts.body_bits or T4_PREV_BITS
    local net = t4_net()
    local storage = helpers.mock_storage()
    local chain = sync.new_header_chain(net, storage)

    local spacing = 600
    local base_ts = (opts.base_ts or (T4_PREV_TS - (top - base_height) * spacing))
    local base_header = types.block_header(0x20000000, types.hash256_zero(),
      types.hash256_zero(), base_ts, body_bits, 1)
    local base_hash = validation.compute_block_hash(base_header)

    local anchor = nil
    if not opts.no_anchor then
      local a = {
        blockhash = string.rep("ab", 32),
        timestamp = opts.anchor_ts or T4_ANCHOR_TS,
      }
      -- NB: `cond and nil or X` silently yields X in Lua; spell it out.
      if not opts.drop_bits then a.bits = opts.anchor_bits or T4_ANCHOR_BITS end
      anchor = { [opts.anchor_height or T4_ANCHOR_H] = a }
    end
    net.assumeutxo[base_height] = {
      hash_serialized  = string.rep("cd", 32),
      m_chain_tx_count = 1,
      blockhash        = types.hash256_hex(base_hash),
      header           = { version = 0x20000000, prev_hash = string.rep("00", 32),
                           merkle_root = string.rep("00", 32), timestamp = base_ts,
                           bits = body_bits, nonce = 1 },
      chain_work       = ZERO_WORK_HEX,
      pre_base_ancestors = anchor,
    }

    local prev_hash = put_entry(chain, base_header, base_height)
    chain.snapshot_base_height = base_height
    for h = base_height + 1, top do
      local hdr = types.block_header(0x20000000, prev_hash, types.hash256_zero(),
        base_ts + (h - base_height) * spacing, body_bits, h)
      prev_hash = put_entry(chain, hdr, h)
    end
    chain.header_tip_hash = prev_hash
    chain.header_tip_height = top
    return chain, net, prev_hash, base_ts + (top - base_height) * spacing
  end

  it("5a: BIP94 retargets off the ANCHOR's nBits, not the parent's", function()
    local chain, _, tip, prev_ts = build_t4()
    local timespan = prev_ts - T4_ANCHOR_TS
    local anchor_derived = consensus.calculate_next_target(T4_PREV_BITS, timespan, T4_ANCHOR_BITS)
    local prev_derived   = consensus.calculate_next_target(T4_PREV_BITS, timespan, nil)
    assert.is_not.equals(anchor_derived, prev_derived,
      "test is vacuous unless the two candidate values differ")

    local opts = { skip_pow = true, min_pow_checked = true, current_time = prev_ts + 600 }
    local good = types.block_header(0x20000000, tip, types.hash256_zero(),
      prev_ts + 600, anchor_derived, 0)
    local ok, err = chain:accept_header(good, opts)
    assert.is_true(ok, "anchor-derived bits must be required; got " .. tostring(err))

    local chain2, _, tip2, prev_ts2 = build_t4()
    local bad = types.block_header(0x20000000, tip2, types.hash256_zero(),
      prev_ts2 + 600, prev_derived, 0)
    local ok2, err2 = chain2:accept_header(bad, opts)
    assert.is_false(ok2,
      "parent-derived bits must be rejected on a BIP94 network (pow.cpp:68-73)")
    assert.truthy(err2 and err2:find("bad%-diffbits"), tostring(err2))
  end)

  it("5b: an anchor without `bits` is refused at load", function()
    local _, net = build_t4({ drop_bits = true })
    assert.has_error(function()
      consensus.validate_assumeutxo_anchors({ t4 = net })
    end)
  end)

  it("5c: a min-difficulty walk-back below the base is UNRESOLVABLE, not a guess", function()
    -- All bits == pow_limit, so Core's walk-back loop (pow.cpp:32-35) keeps
    -- descending; on a snapshot node it runs off the bottom of the chain.
    local chain, _, tip, prev_ts = build_t4({ base = 5000, top = 5010,
                                              body_bits = T4_POW_LIMIT,
                                              base_ts = 2000000 })
    local cand = types.block_header(0x20000000, tip, types.hash256_zero(),
      prev_ts + 60, T4_POW_LIMIT, 0)   -- < 20 min => walk-back path
    local ok, err = chain:accept_header(cand,
      { skip_pow = true, min_pow_checked = true, current_time = prev_ts + 600 })
    assert.is_false(ok, "must not fall through to prev.bits")
    assert.truthy(err and err:find("diffbits%-unresolvable"), tostring(err))
  end)

  it("5d: the 20-minute rule at a non-boundary height still works", function()
    local chain, _, tip, prev_ts = build_t4({ base = 5000, top = 5010,
                                              body_bits = T4_PREV_BITS,
                                              base_ts = 2000000 })
    local cand = types.block_header(0x20000000, tip, types.hash256_zero(),
      prev_ts + 1201, T4_POW_LIMIT, 0)   -- > 20 min => min-difficulty allowed
    local ok, err = chain:accept_header(cand,
      { skip_pow = true, min_pow_checked = true, current_time = prev_ts + 2000 })
    assert.is_true(ok, "20-minute rule regression; got " .. tostring(err))
  end)
end)

--------------------------------------------------------------------------------
-- T10 — regression GUARD (explicitly not evidence: regtest has no retargeting)
--------------------------------------------------------------------------------
describe("T10 GUARD: regtest is untouched", function()
  it("pow_no_retarget short-circuits before the anchor is ever consulted", function()
    local storage = helpers.mock_storage()
    local chain = sync.new_header_chain(consensus.networks.regtest, storage)
    chain:init()
    -- Pretend this datadir was snapshot-bootstrapped at a 2016-aligned height.
    chain.snapshot_base_height = 2016

    local genesis_hex = chain.height_to_hash[0]
    local genesis = chain.headers[genesis_hex]
    local hdr = types.block_header(4, validation.compute_block_hash(genesis.header),
      types.hash256_zero(), genesis.header.timestamp + 600,
      consensus.networks.regtest.pow_limit_bits, 0)
    local ok, err = chain:accept_header(hdr, { skip_pow = true, min_pow_checked = true,
      current_time = genesis.header.timestamp + 1200 })
    assert.is_true(ok, "regtest must be unaffected; got " .. tostring(err))
    assert.is_nil(chain:audit_snapshot_boundary() ~= true and 1 or nil)
  end)

  it("required_pre_base_anchor_height is nil for pow_no_retarget networks", function()
    assert.is_nil(consensus.required_pre_base_anchor_height(consensus.networks.regtest, 299))
    assert.is_nil(consensus.required_pre_base_anchor_height(consensus.networks.regtest, 110))
    assert.equals(ANCHOR_HEIGHT,
      consensus.required_pre_base_anchor_height(MAINNET, BASE_HEIGHT))
    -- 2016-aligned base: the next boundary's period-first IS the base.
    assert.is_nil(consensus.required_pre_base_anchor_height(MAINNET, 943488))
  end)
end)
