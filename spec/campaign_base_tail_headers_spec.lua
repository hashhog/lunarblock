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
      1, types.hash256(prev_hash_le), types.hash256(string.rep("\7", 32)),
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
      1, types.hash256(prev_hash_le), types.hash256(string.rep("\9", 32)),
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
end)
