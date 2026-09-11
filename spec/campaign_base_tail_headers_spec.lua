-- Coverage for consensus.load_campaign_assumeutxo's `base_tail_headers` band:
-- the ancestry a snapshot-bootstrapped node needs for the first retarget
-- boundary above its base, which Core gets for free (ActivateSnapshot,
-- validation.cpp:5611-5616, refuses a base that is not already in a
-- genesis-synced headers chain) and lunarblock must materialise itself.
--
-- Uses a SYNTHETIC network -- regtest params with retargeting switched back on
-- -- so the band can be two mined headers instead of two thousand real ones.
-- Base height 2017 makes the required anchor floor(2017/2016)*2016 = 2016, the
-- band's first element.

local consensus = require("lunarblock.consensus")
local types     = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local crypto    = require("lunarblock.crypto")
local sync      = require("lunarblock.sync")
local helpers   = require("spec.helpers")
local validation = require("lunarblock.validation")

local FIXTURE = "/tmp/lunarblock_campaign_base_tail_"
    .. os.time() .. "_" .. math.random(1000000) .. ".json"

local BASE_HEIGHT = 2017
local ANCHOR_HEIGHT = 2016
local EASY_BITS = 0x207fffff

local function to_hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

-- Mine a header at the easy regtest target (~1 attempt in 2 succeeds).
local function mine(prev_hash_le, timestamp, network)
  local pow_limit = consensus.bits_to_target(EASY_BITS)
  for nonce = 0, 1000 do
    local hdr = types.block_header(
      4, types.hash256(prev_hash_le), types.hash256(string.rep("\7", 32)),
      timestamp, EASY_BITS, nonce)
    local raw = serialize.serialize_block_header(hdr)
    local hash = crypto.hash256_type(raw)
    if consensus.hash_meets_target(hash.bytes, pow_limit) then
      return { raw = raw, hex = to_hex(raw), hash = hash, header = hdr }
    end
  end
  error("could not mine a header at the easy target")
end

-- The inverse of mine(): a well-formed header that does NOT meet its declared
-- target, for proving the band's proof-of-work gate actually fires.
local function mine_bad(prev_hash_le, timestamp)
  local pow_limit = consensus.bits_to_target(EASY_BITS)
  for nonce = 0, 1000 do
    local hdr = types.block_header(
      4, types.hash256(prev_hash_le), types.hash256(string.rep("\9", 32)),
      timestamp, EASY_BITS, nonce)
    local raw = serialize.serialize_block_header(hdr)
    local hash = crypto.hash256_type(raw)
    if not consensus.hash_meets_target(hash.bytes, pow_limit) then
      return { raw = raw, hex = to_hex(raw), hash = hash, header = hdr }
    end
  end
  error("could not find a header that misses the easy target")
end

local function synthetic_network()
  local net = {}
  for k, v in pairs(consensus.networks.regtest) do net[k] = v end
  net.pow_no_retarget = false   -- make the retarget branch -- and the anchor -- live
  net.pow_limit_bits = EASY_BITS
  net.assumeutxo = {}
  return net
end

local function write_fixture(entry)
  local cjson = require("cjson")
  local f = assert(io.open(FIXTURE, "w"))
  f:write(cjson.encode({ entry }))
  f:close()
end

local function load_with(entry)
  write_fixture(entry)
  local net = synthetic_network()
  local count, err = consensus.load_campaign_assumeutxo(net)
  return count, err, net
end

describe("campaign assumeutxo base_tail_headers", function()
  local anchor, base, entry

  local real_getenv

  setup(function()
    -- LuaJIT has no setenv and the loader reads the fixture path from the
    -- environment, so point os.getenv at the spec's own fixture for the
    -- duration and restore it in teardown.
    real_getenv = os.getenv
    os.getenv = function(name)
      if name == "HASHHOG_CAMPAIGN_ASSUMEUTXO" then return FIXTURE end
      return real_getenv(name)
    end
    anchor = mine(string.rep("\0", 32), 1296688602, nil)
    base   = mine(anchor.hash.bytes, 1296688603, nil)
    entry = {
      height = BASE_HEIGHT,
      blockhash = types.hash256_hex(base.hash),
      hash_serialized = string.rep("a", 64),
      m_chain_tx_count = 2,
      base_header = base.hex,
      base_tail_headers = { anchor.hex, base.hex },
    }
  end)

  teardown(function()
    if real_getenv then os.getenv = real_getenv end
    os.remove(FIXTURE)
  end)

  it("pins the required pre-base anchor out of a verified band", function()
    local count, err, net = load_with(entry)
    assert.is_nil(err)
    assert.are.equal(1, count)
    local a = net.assumeutxo[BASE_HEIGHT].pre_base_ancestors[ANCHOR_HEIGHT]
    assert.are.equal(types.hash256_hex(anchor.hash), a.blockhash)
    assert.are.equal(anchor.header.timestamp, a.timestamp)
    assert.are.equal(EASY_BITS, a.bits)
  end)

  it("refuses a band whose prev-hash linkage is broken", function()
    local broken = mine(string.rep("\3", 32), 1296688603, nil)
    local e = {}
    for k, v in pairs(entry) do e[k] = v end
    e.base_tail_headers = { anchor.hex, broken.hex }
    e.base_header = broken.hex
    e.blockhash = types.hash256_hex(broken.hash)
    local count, err = load_with(e)
    assert.is_nil(count)
    assert.is_truthy(err:find("does not link", 1, true))
  end)

  it("refuses a band containing a header that misses its own target", function()
    local bad = mine_bad(anchor.hash.bytes, 1296688603)
    local e = {}
    for k, v in pairs(entry) do e[k] = v end
    e.base_tail_headers = { anchor.hex, bad.hex }
    e.base_header = bad.hex
    e.blockhash = types.hash256_hex(bad.hash)
    local count, err = load_with(e)
    assert.is_nil(count)
    assert.is_truthy(err:find("does not satisfy proof of work", 1, true))
  end)

  it("refuses a band whose last header is not the entry blockhash", function()
    local e = {}
    for k, v in pairs(entry) do e[k] = v end
    e.blockhash = types.hash256_hex(anchor.hash)
    e.base_header = anchor.hex
    local count, err = load_with(e)
    assert.is_nil(count)
    assert.is_truthy(err:find("not the entry blockhash", 1, true))
  end)

  it("loads but does NOT pin when the band misses the anchor height", function()
    local e = {}
    for k, v in pairs(entry) do e[k] = v end
    e.base_tail_headers = { base.hex }   -- band covers only 2017
    local count, err, net = load_with(e)
    assert.is_nil(err)
    assert.are.equal(1, count)
    assert.is_nil(net.assumeutxo[BASE_HEIGHT].pre_base_ancestors)
  end)

  it("refuses a hand-pinned ancestor that contradicts the band", function()
    local e = {}
    for k, v in pairs(entry) do e[k] = v end
    e.pre_base_ancestor = {
      height = ANCHOR_HEIGHT,
      blockhash = string.rep("b", 64),
      timestamp = anchor.header.timestamp,
      bits = EASY_BITS,
    }
    local count, err = load_with(e)
    assert.is_nil(count)
    assert.is_truthy(err:find("contradicts", 1, true))
  end)

  it("keeps the verified band on the assumeutxo entry for inject to graft", function()
    local count, err, net = load_with(entry)
    assert.is_nil(err)
    assert.are.equal(1, count)
    local tails = net.assumeutxo[BASE_HEIGHT].base_tail_headers
    assert.are.equal(2, #tails)
    assert.are.equal(anchor.hex, tails[1])
    assert.are.equal(base.hex, tails[2])
  end)
end)

-- Real mainnet 91,695..91,705 headers from tools/boundary-blocks/91722.
-- Discriminator: after grafting, MTP of 91,705 is Core's 1289717179, not the
-- base timestamp 1289717980 (the 1-header truncated window).
local MAINNET_91705_TAILS = {
  "01000000cc438d9c5d934c72611af5072c5bd1bb83ab829dff1ad00532c80a0000000000e21254fce4174ac893c1df51c4409b854ac6f1fd7030114a14dc6c3856a839892e7ddf4c56720e1b3ffb21c5",
  "0100000050470615a6af7229686a190e8d9cec17026ac0cc3c547ff69a23050000000000fea86c740e0f9f688f0685867b0b8a03783ad47b1b7495102c479fd30553209b8d7fdf4c56720e1b0a31ab5b",
  "01000000aa6e87f2d13c1ca66339d7e11e79f5389fb78f92c51713f2f954070000000000c390d7ebe510b18a720e2cedcfc238656a1e8ce46765a0d188bb18cccb5360758b80df4c56720e1bbb742943",
  "01000000b993daa72dc6315d62e42c8cdc6e61f0399260982899699bab92090000000000a85d1cb4461e7e2e79c93ef55b5a117dccb2c2935c1cd58a97bd6396a1d9749a4482df4c56720e1bb1b0ff0b",
  "010000007bf85300675dd3c2caf5c4ed29e45b042d3dfce55821d1e044630000000000002a9b88886ddb46a4ccf970c0208a852f64d79df7db196a2296bc53e3eb993eaf7184df4c56720e1bd3d3b8e5",
  "010000008149f4416ecb5e045c6a4f076b84b0998a9b59f3279cb85d8e60030000000000fcee5ea416e025f1e3e1b81ac513add17991184d4bcee9bb06d65a589b4ac3bbbb85df4c56720e1bc8c2c453",
  "01000000b58804da3418d17a544f2532beefd04ed62e8f0b42acecde01e000000000000038dfdef524c5fa6341e33a4fd4754ffc746de8cf529163e6254e4c0894cac9427086df4c56720e1b2529a4fc",
  "010000005c59ab793ff54747289fd6b557fb9707a37a7bdc6f4bf4898efd030000000000d461170dd3fca470fd6bc47ac0ea27f4c132fa94d6011510533e0ec1835af90ac386df4c56720e1b558b5b2a",
  "0100000005a247fa2e7c0a127247811e061c7932d68f28d115716bf6af8f0500000000002ee69b2eb480aa32ef4044c9d875c17d95f6ea2ff9fe57c118d1e0a3e30d71de3a87df4c56720e1b4040cbe6",
  "010000006ba0089380fe8227697136f021e2fd5e78fdc894e314e9bb08680600000000006909e4120c23d6ccb7e99bee6f953f62b623eca8d553623d3adc0a9603568c941b88df4c56720e1b08be7b16",
  "010000001d7d4fc47d31894e48e5727c81d97809d9e5dbe40cbdf3659b7c030000000000aedd8dda81f069a5589bd823fac4a6f52dea9dd49b43f90b45b6d18cdd4781cadc88df4c56720e1b2f80b633",
}

describe("snapshot-base MTP window from base_tail_headers", function()
  local real_getenv

  setup(function()
    real_getenv = os.getenv
    os.getenv = function(name)
      if name == "HASHHOG_CAMPAIGN_ASSUMEUTXO" then return FIXTURE end
      return real_getenv(name)
    end
  end)

  teardown(function()
    if real_getenv then os.getenv = real_getenv end
    os.remove(FIXTURE)
  end)

  it("graft of mainnet 91,695..91,705 reports mediantime 1289717179", function()
    local chain = sync.new_header_chain(consensus.networks.mainnet, helpers.mock_storage())
    local n = chain:graft_base_tail_headers(MAINNET_91705_TAILS, 91705)
    assert.are.equal(11, n)
    local raw = helpers.hex_to_bytes(MAINNET_91705_TAILS[11])
    local hdr = serialize.deserialize_block_header(raw)
    local hash = validation.compute_block_hash(hdr)
    assert.are.equal(
      "00000000000176b6c00592ed3924b056b0ab9a8aab662476963f8877333a77b5",
      types.hash256_hex(hash))
    local timestamps = chain:get_past_timestamps(types.hash256_hex(hash), 11)
    assert.are.equal(11, #timestamps)
    assert.are.equal(1289717980, timestamps[1])  -- newest = the base itself
    assert.are.equal(1289717179, consensus.get_median_time_past(timestamps))
  end)

  it("truncated window (base only) is 1289717980, not Core's MTP", function()
    -- The pre-fix inject path: only the last header is in the index.
    local chain = sync.new_header_chain(consensus.networks.mainnet, helpers.mock_storage())
    local n = chain:graft_base_tail_headers({ MAINNET_91705_TAILS[11] }, 91705)
    assert.are.equal(1, n)
    local raw = helpers.hex_to_bytes(MAINNET_91705_TAILS[11])
    local hdr = serialize.deserialize_block_header(raw)
    local hash_hex = types.hash256_hex(validation.compute_block_hash(hdr))
    local timestamps = chain:get_past_timestamps(hash_hex, 11)
    assert.are.equal(1, #timestamps)
    assert.are.equal(1289717980, consensus.get_median_time_past(timestamps))
  end)

  it("inject grafts the band; time==MTP is rejected, time==MTP+1 accepted", function()
    -- 11 mined headers at heights 2016..2026 so the band includes the
    -- required retarget ancestor (2016) AND the BIP-113 window.
    local MTP_BASE = 2026
    local mined = {}
    local prev = string.rep("\0", 32)
    local t0 = 1296688602
    for i = 1, 11 do
      mined[i] = mine(prev, t0 + (i - 1) * 60)
      prev = mined[i].hash.bytes
    end
    local base = mined[11]
    local e = {
      height = MTP_BASE,
      blockhash = types.hash256_hex(base.hash),
      hash_serialized = string.rep("c", 64),
      m_chain_tx_count = 11,
      base_header = base.hex,
      base_tail_headers = {},
    }
    for i = 1, 11 do e.base_tail_headers[i] = mined[i].hex end

    local count, err, net = load_with(e)
    assert.is_nil(err, tostring(err))
    assert.are.equal(1, count)
    net.pow_allow_min_difficulty = false

    local chain = sync.new_header_chain(net, helpers.mock_storage())
    local ok, why = chain:inject_snapshot_base(
      MTP_BASE, base.hash, base.header, consensus.work_zero())
    assert.is_true(ok, tostring(why))
    assert.are.equal(MTP_BASE, chain.header_tip_height)

    local timestamps = chain:get_past_timestamps(types.hash256_hex(base.hash), 11)
    assert.are.equal(11, #timestamps)
    local mtp = consensus.get_median_time_past(timestamps)
    -- 11 timestamps t0, t0+60, ... t0+600; sorted median is t0+5*60.
    assert.are.equal(t0 + 5 * 60, mtp)

    local now = mtp + 100000
    local too_old = mine(base.hash.bytes, mtp)
    local acc, aerr = chain:accept_header(too_old.header, { current_time = now })
    assert.is_false(acc)
    assert.are.equal("time-too-old", aerr)

    local ok_hdr = mine(base.hash.bytes, mtp + 1)
    local acc2, aerr2 = chain:accept_header(ok_hdr.header, { current_time = now })
    assert.is_true(acc2, tostring(aerr2))
  end)
end)
