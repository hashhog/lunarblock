-- spec/bip30_snapshot_ancestor_spec.lua
--
-- BIP30 enforcement decision (Core ConnectBlock, validation.cpp:2402-2476):
--
--   fEnforceBIP30 = !IsBIP30Repeat(*pindex);
--   pindexBIP34height = pindex->pprev->GetAncestor(BIP34Height);
--   fEnforceBIP30 = fEnforceBIP30 && (!pindexBIP34height ||
--                   !(pindexBIP34height->GetBlockHash() == BIP34Hash));
--   if (fEnforceBIP30 || pindex->nHeight >= BIP34_IMPLIES_BIP30_LIMIT) { HaveCoin scan }
--
-- On an assumeutxo-bootstrapped datadir lunarblock never holds headers below
-- the snapshot base, so the old height-index lookup of block 227,931 always
-- missed and BIP30 ran for every output of every block (fail-open into
-- per-output lookups; stricter than Core, never looser).  The ancestor is now
-- resolved through the block's own stored-header lineage to the pinned
-- snapshot base.  These tests pin:
--   * the historic exemptions (91842 / 91880, hash-checked),
--   * the BIP34-height edge (227,931 still enforces: pprev is below it),
--   * the 1,983,702 re-enforcement limit,
--   * the snapshot lineage resolution, and every fail-closed branch of it.

local types = require("lunarblock.types")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local utxo = require("lunarblock.utxo")

local MAINNET = consensus.networks.mainnet
local BIP34_HASH = types.hash256_from_hex(MAINNET.bip34_hash)
local BASE_HEIGHT = 944183  -- a real mainnet assumeutxo base (chainparams)
local H_91842 = "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"
local H_91880 = "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"

-- Core's full decision, composed from lunarblock's two helpers exactly the
-- way connect_block composes them.
local function enforce_bip30(net, height, block_hash, get_ancestor_hash)
  local enforce = not utxo.is_bip30_exempt(net.name, height, block_hash)
  if enforce and utxo.bip34_bypasses_bip30(net, height, get_ancestor_hash) then
    enforce = false
  end
  return enforce
end

local function canonical_ancestor(h)
  if h == MAINNET.bip34_height then return BIP34_HASH end
  return nil
end

local function real_base_header()
  local h = MAINNET.assumeutxo[BASE_HEIGHT].header
  return types.block_header(h.version, types.hash256_from_hex(h.prev_hash),
    types.hash256_from_hex(h.merkle_root), h.timestamp, h.bits, h.nonce)
end

-- Mock storage: stored headers by hash, optional height index, META.
local function mock_storage(headers, height_index)
  local st = { CF = { META = "meta" }, header_reads = 0 }
  function st.get_header(hash)
    st.header_reads = st.header_reads + 1
    return headers[hash.bytes]
  end
  function st.get_hash_by_height(h) return height_index and height_index[h] or nil end
  function st.get() return nil end
  function st.batch() return {} end
  return st
end

-- Build `n` synthetic descendants of `parent_header`; returns list of
-- {hash, header} from height base+1 .. base+n, and fills `headers`.
local function extend(headers, parent_header, n)
  local out = {}
  local parent_hash = validation.compute_block_hash(parent_header)
  for i = 1, n do
    local hdr = types.block_header(0x20000000, parent_hash,
      types.hash256(string.rep(string.char(i % 256), 32)),
      parent_header.timestamp + 600 * i, parent_header.bits, i)
    local hh = validation.compute_block_hash(hdr)
    headers[hh.bytes] = hdr
    out[i] = { hash = hh, header = hdr }
    parent_hash = hh
  end
  return out
end

local function snapshot_chainstate(storage, base_height)
  local cs = utxo.new_chain_state(storage, MAINNET)
  cs._snapshot_base_height = base_height or BASE_HEIGHT
  return cs
end

describe("BIP30 enforcement decision (Core ConnectBlock)", function()
  it("exempts the two IsBIP30Repeat blocks only with their exact hashes", function()
    assert.is_false(enforce_bip30(MAINNET, 91842, types.hash256_from_hex(H_91842), canonical_ancestor))
    assert.is_false(enforce_bip30(MAINNET, 91880, types.hash256_from_hex(H_91880), canonical_ancestor))
    local other = types.hash256(string.rep("\1", 32))
    assert.is_true(enforce_bip30(MAINNET, 91842, other, canonical_ancestor))
    assert.is_true(enforce_bip30(MAINNET, 91880, other, canonical_ancestor))
    -- A neighbouring height with a repeat hash is not an exemption.
    assert.is_true(enforce_bip30(MAINNET, 91843, types.hash256_from_hex(H_91842), canonical_ancestor))
  end)

  it("enforces below and AT the BIP34 height (pprev->GetAncestor is null)", function()
    local blk = types.hash256(string.rep("\2", 32))
    assert.is_true(enforce_bip30(MAINNET, 227930, blk, canonical_ancestor))
    assert.is_true(enforce_bip30(MAINNET, 227931, BIP34_HASH, canonical_ancestor))
  end)

  it("skips above the BIP34 height on the BIP34 chain, enforces off it", function()
    local blk = types.hash256(string.rep("\3", 32))
    assert.is_false(enforce_bip30(MAINNET, 227932, blk, canonical_ancestor))
    assert.is_false(enforce_bip30(MAINNET, 700000, blk, canonical_ancestor))
    assert.is_false(enforce_bip30(MAINNET, 1983701, blk, canonical_ancestor))
    local wrong = function() return types.hash256(string.rep("\4", 32)) end
    assert.is_true(enforce_bip30(MAINNET, 700000, blk, wrong))
    assert.is_true(enforce_bip30(MAINNET, 700000, blk, function() return nil end))
  end)

  it("re-enforces at and above BIP34_IMPLIES_BIP30_LIMIT (1,983,702)", function()
    local blk = types.hash256(string.rep("\5", 32))
    assert.is_true(enforce_bip30(MAINNET, 1983702, blk, canonical_ancestor))
    assert.is_true(enforce_bip30(MAINNET, 2500000, blk, canonical_ancestor))
  end)
end)

describe("ChainState:bip30_ancestor_hash", function()
  it("uses the connected-block height index when it has the height", function()
    local st = mock_storage({}, { [227931] = BIP34_HASH })
    local cs = utxo.new_chain_state(st, MAINNET)
    local got = cs:bip30_ancestor_hash(types.hash256(string.rep("\6", 32)), 500000, 227931)
    assert.is_true(types.hash256_eq(got, BIP34_HASH))
    -- ...but never for the block's own height or above (pprev ancestry only).
    assert.is_nil(cs:bip30_ancestor_hash(types.hash256(string.rep("\6", 32)), 227931, 227931))
  end)

  it("resolves the BIP34 ancestor through the pinned snapshot base lineage", function()
    local headers = {}
    local base = real_base_header()
    local kids = extend(headers, base, 5)
    local st = mock_storage(headers, nil)
    local cs = snapshot_chainstate(st)
    -- Block at base+1: its parent IS the base.
    local base_hash = validation.compute_block_hash(base)
    assert.equals(MAINNET.assumeutxo[BASE_HEIGHT].blockhash, types.hash256_hex(base_hash))
    local got = cs:bip30_ancestor_hash(base_hash, BASE_HEIGHT + 1, MAINNET.bip34_height)
    assert.is_true(types.hash256_eq(got, BIP34_HASH))
    -- Block at base+6: parent is kids[5], walks 5 stored headers to the base.
    got = cs:bip30_ancestor_hash(kids[5].hash, BASE_HEIGHT + 6, MAINNET.bip34_height)
    assert.is_true(types.hash256_eq(got, BIP34_HASH))
    -- And the decision composed as connect_block does: BIP30 skipped.
    local ga = function(h) return cs:bip30_ancestor_hash(kids[5].hash, BASE_HEIGHT + 6, h) end
    assert.is_false(enforce_bip30(MAINNET, BASE_HEIGHT + 6, types.hash256(string.rep("\7", 32)), ga))
  end)

  it("memoizes the lineage: steady state reads one header per block", function()
    local headers = {}
    local base = real_base_header()
    local kids = extend(headers, base, 50)
    local st = mock_storage(headers, nil)
    local cs = snapshot_chainstate(st)
    assert.is_not_nil(cs:bip30_ancestor_hash(kids[40].hash, BASE_HEIGHT + 41, 227931))
    local before = st.header_reads
    assert.is_not_nil(cs:bip30_ancestor_hash(kids[41].hash, BASE_HEIGHT + 42, 227931))
    assert.is_true(st.header_reads - before <= 1)
  end)

  it("fails closed when the lineage does not reach the pinned base", function()
    local headers = {}
    -- A fake 'base' with the right height but not the pinned hash.
    local fake = real_base_header()
    fake = types.block_header(fake.version, fake.prev_hash, fake.merkle_root,
      fake.timestamp, fake.bits, fake.nonce + 1)
    local kids = extend(headers, fake, 3)
    local cs = snapshot_chainstate(mock_storage(headers, nil))
    assert.is_nil(cs:bip30_ancestor_hash(kids[3].hash, BASE_HEIGHT + 4, 227931))
    local ga = function(h) return cs:bip30_ancestor_hash(kids[3].hash, BASE_HEIGHT + 4, h) end
    assert.is_true(enforce_bip30(MAINNET, BASE_HEIGHT + 4, types.hash256(string.rep("\8", 32)), ga))
  end)

  it("fails closed on a gap in the stored headers", function()
    local headers = {}
    local kids = extend(headers, real_base_header(), 4)
    headers[kids[2].hash.bytes] = nil  -- hole
    local cs = snapshot_chainstate(mock_storage(headers, nil))
    assert.is_nil(cs:bip30_ancestor_hash(kids[4].hash, BASE_HEIGHT + 5, 227931))
  end)

  it("fails closed without a snapshot base, below/at the base, or with no assumeutxo entry", function()
    local headers = {}
    local kids = extend(headers, real_base_header(), 2)
    -- No snapshot base recorded.
    local cs = utxo.new_chain_state(mock_storage(headers, nil), MAINNET)
    cs._snapshot_base_height = false
    assert.is_nil(cs:bip30_ancestor_hash(kids[2].hash, BASE_HEIGHT + 3, 227931))
    -- Base recorded but block not above it.
    cs = snapshot_chainstate(mock_storage(headers, nil))
    assert.is_nil(cs:bip30_ancestor_hash(kids[1].hash, BASE_HEIGHT, 227931))
    -- Base height with no assumeutxo entry for it.
    cs = snapshot_chainstate(mock_storage(headers, nil), BASE_HEIGHT + 1)
    assert.is_nil(cs:bip30_ancestor_hash(kids[2].hash, BASE_HEIGHT + 3, 227931))
    -- Only the BIP34 height is ever resolved from the base.
    cs = snapshot_chainstate(mock_storage(headers, nil))
    assert.is_nil(cs:bip30_ancestor_hash(kids[2].hash, BASE_HEIGHT + 3, 227930))
  end)

  it("does not apply to networks without a BIP34 hash", function()
    local net = setmetatable({ bip34_hash = false }, { __index = MAINNET })
    local headers = {}
    local kids = extend(headers, real_base_header(), 2)
    local cs = utxo.new_chain_state(mock_storage(headers, nil), net)
    cs._snapshot_base_height = BASE_HEIGHT
    assert.is_nil(cs:bip30_ancestor_hash(kids[2].hash, BASE_HEIGHT + 3, net.bip34_height))
  end)
end)
