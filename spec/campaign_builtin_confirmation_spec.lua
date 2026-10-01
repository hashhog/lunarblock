-- consensus.load_campaign_assumeutxo against a BUILT-IN entry at the same height.
--
-- R4 slice 910000-920000 was BLOCKED because the campaign fixture for base
-- 910,000 (minted by descending a Core clone and dumping there) carries the
-- exact commitment Core hardcodes for that height (kernel/chainparams.cpp
-- m_assumeutxo_data, mirrored in lunarblock's mainnet table), and the loader
-- refused ANY same-height entry as a "collision".
--
-- Semantics pinned here:
--   * a campaign entry whose commitment (height, blockhash, hash_serialized,
--     m_chain_tx_count) is IDENTICAL to a built-in one is a confirmation, not
--     an override: it is accepted, the built-in commitment is left untouched,
--     and the entry's verified supplemental ancestry (base header, chainwork,
--     base_mtp, base_tail_headers -> pre_base_ancestors) fills gaps the
--     built-in row lacks -- without it the 910000 row is a whitelist-only row
--     that inject_snapshot_base must refuse;
--   * ANY disagreement is still refused loudly: different hash_serialized,
--     different blockhash, different m_chain_tx_count, the built-in blockhash
--     at a different height, or supplemental data that contradicts a value the
--     built-in row already pins;
--   * a duplicate inside the campaign file itself is still refused.

local consensus = require("lunarblock.consensus")
local types     = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local crypto    = require("lunarblock.crypto")

local FIXTURE = "/tmp/lunarblock_campaign_builtin_confirm_"
    .. os.time() .. "_" .. math.random(1000000) .. ".json"

local BASE_HEIGHT = 2017
local ANCHOR_HEIGHT = 2016
local EASY_BITS = 0x207fffff
local HS = string.rep("a", 64)
local CHAINWORK = string.rep("0", 60) .. "0fff"

local function to_hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function mine(prev_hash_le, timestamp, salt)
  local pow_limit = consensus.bits_to_target(EASY_BITS)
  for nonce = 0, 1000 do
    local hdr = types.block_header(
      4, types.hash256(prev_hash_le), types.hash256(string.rep(salt or "\7", 32)),
      timestamp, EASY_BITS, nonce)
    local raw = serialize.serialize_block_header(hdr)
    local hash = crypto.hash256_type(raw)
    if consensus.hash_meets_target(hash.bytes, pow_limit) then
      return { raw = raw, hex = to_hex(raw), hash = hash, header = hdr }
    end
  end
  error("could not mine a header at the easy target")
end

local function copy(t)
  if type(t) ~= "table" then return t end
  local c = {}
  for k, v in pairs(t) do c[k] = copy(v) end
  return c
end

local function write_fixture(entries)
  local cjson = require("cjson")
  local f = assert(io.open(FIXTURE, "w"))
  f:write(cjson.encode(entries))
  f:close()
end

describe("campaign assumeutxo entry at a built-in height", function()
  local anchor, base, other, builtin, entry, real_getenv

  local function network_with(builtin_rows)
    local net = {}
    for k, v in pairs(consensus.networks.regtest) do net[k] = v end
    net.pow_no_retarget = false
    net.pow_limit_bits = EASY_BITS
    net.assumeutxo = copy(builtin_rows)
    return net
  end

  local function load_with(entries, builtin_rows)
    write_fixture(entries)
    local net = network_with(builtin_rows or { [BASE_HEIGHT] = builtin })
    local count, err = consensus.load_campaign_assumeutxo(net)
    return count, err, net
  end

  local function variant(over)
    local e = copy(entry)
    for k, v in pairs(over) do
      if v == "nil" then e[k] = nil else e[k] = v end
    end
    return e
  end

  setup(function()
    real_getenv = os.getenv
    os.getenv = function(name)
      if name == "HASHHOG_CAMPAIGN_ASSUMEUTXO" then return FIXTURE end
      return real_getenv(name)
    end
    anchor = mine(string.rep("\0", 32), 1296688602)
    base   = mine(anchor.hash.bytes, 1296688603)
    other  = mine(anchor.hash.bytes, 1296688603, "\5")
    -- A whitelist-only built-in row, the shape of lunarblock's mainnet 910000.
    builtin = {
      hash_serialized = HS,
      m_chain_tx_count = 2,
      blockhash = types.hash256_hex(base.hash),
    }
    entry = {
      height = BASE_HEIGHT,
      blockhash = types.hash256_hex(base.hash),
      hash_serialized = HS,
      m_chain_tx_count = 2,
      base_mtp = 1296688602,
      chainwork = CHAINWORK,
      base_header = base.hex,
      base_tail_headers = { anchor.hex, base.hex },
    }
  end)

  teardown(function()
    if real_getenv then os.getenv = real_getenv end
    os.remove(FIXTURE)
  end)

  it("accepts an entry identical to a built-in one and keeps the built-in commitment", function()
    local count, err, net = load_with({ entry })
    assert.is_nil(err)
    assert.are.equal(1, count)
    local row = net.assumeutxo[BASE_HEIGHT]
    assert.are.equal(HS, row.hash_serialized)
    assert.are.equal(2, row.m_chain_tx_count)
    assert.are.equal(types.hash256_hex(base.hash), row.blockhash)
  end)

  it("fills the built-in row's missing ancestry from the verified band", function()
    local _, err, net = load_with({ entry })
    assert.is_nil(err)
    local row = net.assumeutxo[BASE_HEIGHT]
    assert.is_table(row.header)
    assert.are.equal(base.header.nonce, row.header.nonce)
    assert.are.equal(CHAINWORK, row.chain_work)
    assert.are.equal(1296688602, row.base_mtp)
    assert.are.equal(2, #row.base_tail_headers)
    local a = row.pre_base_ancestors[ANCHOR_HEIGHT]
    assert.are.equal(types.hash256_hex(anchor.hash), a.blockhash)
    assert.are.equal(EASY_BITS, a.bits)
  end)

  -- Negative controls: every disagreement with the built-in is still fatal.
  it("refuses the same height with a different hash_serialized", function()
    local count, err = load_with({ variant({ hash_serialized = string.rep("b", 64) }) })
    assert.is_nil(count)
    assert.truthy(err:find("collides with existing height " .. BASE_HEIGHT, 1, true))
  end)

  it("refuses the same height with a different blockhash", function()
    local count, err = load_with({ variant({
      blockhash = types.hash256_hex(other.hash),
      base_header = other.hex,
      base_tail_headers = { anchor.hex, other.hex },
    }) })
    assert.is_nil(count)
    assert.truthy(err:find("collides with existing height " .. BASE_HEIGHT, 1, true))
  end)

  it("refuses the same height with a different m_chain_tx_count", function()
    local count, err = load_with({ variant({ m_chain_tx_count = 3 }) })
    assert.is_nil(count)
    assert.truthy(err:find("collides with existing height " .. BASE_HEIGHT, 1, true))
  end)

  it("refuses the built-in blockhash at a different height", function()
    local count, err = load_with({ variant({
      height = BASE_HEIGHT + 1,
      base_header = "nil", base_tail_headers = "nil",
    }) })
    assert.is_nil(count)
    assert.truthy(err:find("collides with existing height " .. BASE_HEIGHT, 1, true))
  end)

  it("refuses supplemental chainwork that contradicts the built-in row", function()
    local pinned = copy(builtin)
    pinned.chain_work = string.rep("0", 60) .. "0eee"
    local count, err, net = load_with({ entry }, { [BASE_HEIGHT] = pinned })
    assert.is_nil(count)
    assert.truthy(err:find("contradicts", 1, true))
    assert.are.equal(string.rep("0", 60) .. "0eee", net.assumeutxo[BASE_HEIGHT].chain_work)
  end)

  it("refuses a base_header that contradicts the built-in row's header", function()
    local pinned = copy(builtin)
    pinned.header = {
      version = 4, prev_hash = types.hash256_hex(anchor.hash),
      merkle_root = string.rep("0", 64), timestamp = 1, bits = EASY_BITS, nonce = 1,
    }
    local count, err = load_with({ entry }, { [BASE_HEIGHT] = pinned })
    assert.is_nil(count)
    assert.truthy(err:find("contradicts", 1, true))
  end)

  it("refuses a pre-base ancestor that contradicts the built-in row's pin", function()
    local pinned = copy(builtin)
    pinned.pre_base_ancestors = {
      [ANCHOR_HEIGHT] = { blockhash = string.rep("c", 64), timestamp = 5, bits = EASY_BITS },
    }
    local count, err = load_with({ entry }, { [BASE_HEIGHT] = pinned })
    assert.is_nil(count)
    assert.truthy(err:find("contradicts", 1, true))
  end)

  it("refuses a base_header that does not hash to the confirmed blockhash", function()
    local count, err, net = load_with({ variant({
      base_header = other.hex, base_tail_headers = "nil",
    }) })
    assert.is_nil(count)
    assert.truthy(err:find("hashes to", 1, true))
    assert.is_nil(net.assumeutxo[BASE_HEIGHT].header)
  end)

  it("still refuses the same entry twice in one campaign file", function()
    local count, err = load_with({ entry, copy(entry) })
    assert.is_nil(count)
    assert.truthy(err:find("duplicates", 1, true))
  end)

  -- The real R4 input, when run from inside the hashhog meta-repo checkout.
  it("loads the real soak-910000 fixture against the mainnet table", function()
    local path = "../tools/boundary-blocks/soak-910000/campaign-entry.json"
    local f = io.open(path, "rb")
    if not f then
      pending("meta-repo fixture " .. path .. " not present")
      return
    end
    local data = f:read("*a")
    f:close()
    local wf = assert(io.open(FIXTURE, "w"))
    wf:write(data)
    wf:close()
    local net = {}
    for k, v in pairs(consensus.networks.mainnet) do net[k] = v end
    net.assumeutxo = copy(consensus.networks.mainnet.assumeutxo)
    local before = copy(net.assumeutxo[910000])
    local count, err = consensus.load_campaign_assumeutxo(net)
    assert.is_nil(err)
    assert.are.equal(1, count)
    local row = net.assumeutxo[910000]
    assert.are.equal(before.hash_serialized, row.hash_serialized)
    assert.are.equal(before.blockhash, row.blockhash)
    assert.are.equal(before.m_chain_tx_count, row.m_chain_tx_count)
    local need = consensus.required_pre_base_anchor_height(net, 910000)
    assert.is_table(row.pre_base_ancestors[need])
    assert.is_true(consensus.validate_assumeutxo_anchors({ mainnet = net }))
    -- The module-level production table is not mutated by a copy's load.
    assert.is_nil(consensus.networks.mainnet.assumeutxo[910000].header)
  end)
end)
