-- Snapshot boot must not decide BIP-68 / BIP-113 / time-too-old from a partial
-- MTP window or a missing ancestor, and must backfill the pre-base header
-- chain (Core holds the full header chain before validating any block).
--
-- Real mainnet numbers (Bitcoin Core getblockheader, 2026-10-03):
--   block 932256 spends a coin created at 927979 with nSequence 0x004013c7
--   (time lock 5063 * 512 s).  Core: coin MTP = MTP(927978) = 1765804000,
--   min_time 1768396255 < prev MTP 1768398550 -> final.  A snapshot at 930000
--   holds base_tail_headers 927974..930000, so the window 927968..927978 has
--   only 5 headers: median 1765808303 -> min_time 1768400558 >= 1768398550 ->
--   FALSE reject (camlcoin hit exactly this).  lunarblock's old code instead
--   SKIPPED the time lock for every coin <= base+10 (fail-open) and returned
--   0 for a missing height (fail-open).

local types      = require("lunarblock.types")
local serialize  = require("lunarblock.serialize")
local consensus  = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local storage_mod = require("lunarblock.storage")
local utxo       = require("lunarblock.utxo")
local sync       = require("lunarblock.sync")
local crypto     = require("lunarblock.crypto")
local p2p        = require("lunarblock.p2p")

local function unhex(h)
  return (h:gsub("%x%x", function(b) return string.char(tonumber(b, 16)) end))
end

-- Raw 80-byte mainnet headers 927966..927978 (Core getblockheader <h> false).
local RAW = {
  [927966] = "004000204ba148820ae8ae424419370d27243639025fe9590c4101000000000000000000f57c7275a92fb9b654f7c6db9fce851774f32f70f05bf759ddab874b0027efdeeafa3f693ae601175a3570a6",
  [927967] = "00e0ff26cb8c74b118a48b2ab2b08bbed7b0d8ec8f4bc0c0328b01000000000000000000d0925f4e48d6b1464a4fec3c2cfcdda327a4db44b9bab9df7e2ef02b6fce06f8affc3f693ae60117848eba75",
  [927968] = "0040d5271527afa32e96e40aa83462077ad71f57edd46e12d70801000000000000000000d86ef389e4383912c696812dd30f9bbe49649ca5466a250ca09e617edd77e2f98aff3f693ae60117c3d0e67d",
  [927969] = "00604c2275d46a68ab50f7972eb3e5c2d7121a6a93b112b9563b010000000000000000009424d434c17c89aebb9fdf35e0d9fea4c944ac151e23f684e3e21e0fbd728082000140693ae601179c972b33",
  [927970] = "00a00420536dd03c2356179c3860de85d61ba09176f91446d00e00000000000000000000858da5a3a3416716d22280fc858e15f63ae335f46132cb7de766b8c57304f654a40140693ae60117065b07ec",
  [927971] = "00407b21362deed34a89d70b1460117c7bf96c6b8a6581c39988010000000000000000001f93a5b2993179f782dff30c44a9b1c48743dd4e8f1f3e44a9224aaffea194a1a70340693ae601178a07a026",
  [927972] = "00e0ff3f4b8d1d54d193eb8fb1efdc2f43055fe02aa85546c5d4000000000000000000007b72dd234a9e33fab697246f56964b24cad845977f80cc644bbfc55a01ce8b138b0540693ae601176f958fbd",
  [927973] = "000000347086fc0b3552d57b65f88909cee8c70c77b2ac654ab8010000000000000000004cb9fd96801049bf956e76469e46616332901546a94de61dd72a58fe345782d5e00740693ae60117a644a6a2",
  [927974] = "004002209143c555c0a28dbd521c97aa7e03e64c93ad992669ea00000000000000000000432180db8e60bc066319e02bc8dc77883628e0c39f27e186e8456424494e7e9ad01540693ae60117e4a986da",
  [927975] = "0000de258c3aac1daba1c1f547119026c083b9be506d0bfeea37000000000000000000008c266bcf17ebc8a9ff79d1db7b356e6828d24169725674800236440232d2d6d84f1640693ae601172f34e592",
  [927976] = "0040aa25ea9af58f5967beb933e6e70f566c5fbbf17c80ed9f8601000000000000000000efd6c731cf9c490798b13bebfdac28aa16e570e4427efa55f9a8cfb86dde71ceaf1840693ae601175a9e160f",
  [927977] = "000000346445d1e4c1a1ccb99e4ef033fee46c65cf584797e5f400000000000000000000b39c9cf6d8869991620571af2267451233d53f91eaaa8a408c34d1ddf4ba6f70471a40693ae60117275721b5",
  [927978] = "00c0052052cad98b346a025552f94313ccc6afc599a592b58c9b010000000000000000005f512e2208b459e61d540d343c7376b985f9b78430195346392dfd4255cef1d3071c40693ae601177bf79c5f",
}
local CORE_MTP_927978 = 1765804000   -- Core getblockheader(927978).mediantime
local CORE_MTP_932255 = 1768398550   -- prev MTP of block 932256
local PARTIAL_MEDIAN  = 1765808303   -- median of 927974..927978 only

local function storage_with(lo, hi)
  local st = storage_mod.new_memory_storage()
  for h = lo, hi do
    local hdr = serialize.deserialize_block_header(unhex(RAW[h]))
    local hash = validation.compute_block_hash(hdr)
    st.put_header(hash, hdr)
    st.put_height_index(h, hash)
  end
  return st
end

local function tx_932256()
  return { version = 2, inputs = { { sequence = 0x004013c7 } } }
end

local function seq_locks(st)
  return validation.calculate_sequence_locks(
    tx_932256(), 932256, function() return 927979 end,
    utxo.make_get_block_mtp(st), true, 930000)
end

describe("snapshot coin MTP (mainnet 932256, coin 927979)", function()
  it("full window: coin MTP is Core's and the block is final", function()
    local st = storage_with(927966, 927978)
    assert.are.equal(CORE_MTP_927978, utxo.make_get_block_mtp(st)(927978))
    local min_h, min_t = seq_locks(st)
    assert.are.equal(CORE_MTP_927978 + 5063 * 512 - 1, min_t)
    assert.is_true(validation.check_sequence_locks(min_h, min_t, 932256, CORE_MTP_932255))
  end)

  it("band-only window (927974..927978): refuses instead of a partial median", function()
    local st = storage_with(927974, 927978)
    local v, why = utxo.make_get_block_mtp(st)(927978)
    assert.is_nil(v)
    assert.is_truthy(tostring(why):find("missing-ancestor-header", 1, true))
    -- sanity: the value the partial window WOULD give is the false-reject one
    assert.is_true(PARTIAL_MEDIAN + 5063 * 512 - 1 >= CORE_MTP_932255)
    -- and the snapshot height does not buy a skip any more (fail-open removed)
    local ok, err = pcall(seq_locks, st)
    assert.is_false(ok)
    assert.is_truthy(tostring(err):find("missing-ancestor-header", 1, true))
  end)

  it("absent ancestor height: refuses instead of time 0", function()
    local st = storage_mod.new_memory_storage()
    local v, why = utxo.make_get_block_mtp(st)(927978)
    assert.is_nil(v)
    assert.is_truthy(tostring(why):find("no header at height 927978", 1, true))
  end)

  it("missing-ancestor is filed local: no punish, BIP22 inconclusive", function()
    local e = "Failed to connect block 932256: missing-ancestor-header: coin MTP at "
      .. "height 927978 for input 1: bad-txns-nonfinal-lookalike"
    assert.are.equal("local", sync.classify_callback_error(e))
    assert.is_false(sync.should_punish_peer_for_block_error(e))
    local rpc = require("lunarblock.rpc")
    assert.are.equal("inconclusive", rpc.classify_block_rejection(e))
  end)

  it("a short window that reaches GENESIS is legitimate", function()
    local st = storage_mod.new_memory_storage()
    local prev = types.hash256_zero()
    local last
    for i = 0, 2 do
      local hdr = types.block_header(1, prev, types.hash256(string.rep("\1", 32)),
        1000 + i * 10, 0x207fffff, i)
      local hash = validation.compute_block_hash(hdr)
      st.put_header(hash, hdr)
      prev, last = hash, hash
    end
    assert.are.equal(1010, utxo.compute_mtp_from_storage(st, last))
  end)
end)

--------------------------------------------------------------------------------
-- Pre-base header backfill on a mined regtest chain.
--------------------------------------------------------------------------------

local EASY = 0x207fffff
local function regtest_net()
  local net = {}
  for k, v in pairs(consensus.networks.regtest) do net[k] = v end
  net.assumeutxo = {}
  return net
end

local function mine_chain(genesis_hdr, n, tag)
  local target = consensus.bits_to_target(EASY)
  local out = { [0] = genesis_hdr }
  local prev = validation.compute_block_hash(genesis_hdr)
  for h = 1, n do
    local hdr
    for nonce = 0, 100000 do
      hdr = types.block_header(4, prev, types.hash256(string.rep(tag, 32)),
        genesis_hdr.timestamp + h * 600, EASY, nonce)
      if consensus.hash_meets_target(validation.compute_block_hash(hdr).bytes, target) then break end
    end
    out[h] = hdr
    prev = validation.compute_block_hash(hdr)
  end
  return out
end

local function hexof(hdr) return types.hash256_hex(validation.compute_block_hash(hdr)) end

-- A snapshot-booted chain: genesis + band ROOT..BASE (+ seeded base work).
local ROOT, BASE = 20, 30
local function snapshot_chain(chain, seed_override)
  local net = regtest_net()
  local st = storage_mod.new_memory_storage()
  local hc = sync.new_header_chain(net, st)
  hc:add_genesis()
  assert.are.equal(net.genesis_hash, hexof(chain[0]))
  local cum = consensus.work_zero()
  for h = 0, BASE do cum = consensus.work_add(cum, hc:work_for_bits(chain[h].bits)) end
  for h = ROOT, BASE do
    local hex = hexof(chain[h])
    hc.headers[hex] = { header = chain[h], height = h,
      total_work = (h == BASE) and (seed_override or cum) or consensus.work_zero() }
    hc.height_to_hash[h] = hex
    st.put_header(validation.compute_block_hash(chain[h]), chain[h])
    st.put_height_index(h, validation.compute_block_hash(chain[h]))
  end
  hc.snapshot_base_height = BASE
  hc.header_tip_hash = validation.compute_block_hash(chain[BASE])
  hc.header_tip_height = BASE
  return hc, st, cum
end

local function batch(chain, lo, hi)
  local t = {}
  for h = lo, hi do t[#t + 1] = chain[h] end
  return t
end

describe("pre-base header backfill", function()
  local chain, other
  setup(function()
    local hc0 = sync.new_header_chain(regtest_net(), storage_mod.new_memory_storage())
    hc0:add_genesis()
    local g = hc0.headers[hc0.height_to_hash[0]].header
    chain = mine_chain(g, BASE, "\7")
    other = mine_chain(g, BASE, "\8")
  end)

  it("detects the gap and requests locator=frontier, hashStop=root parent", function()
    local hc = snapshot_chain(chain)
    local gap = hc:refresh_prebase_gap()
    assert.is_not_nil(gap)
    assert.are.equal(ROOT, gap.root_height)
    assert.are.equal(hexof(chain[ROOT - 1]), gap.root_prev_hex)
    local sent
    local peer = { send_message = function(_, cmd, payload) sent = { cmd, payload }; return true end }
    assert.is_true(hc:maybe_request_prebase(peer, 1000))
    assert.are.equal("getheaders", sent[1])
    local req = p2p.deserialize_getheaders(sent[2])
    assert.are.equal(hexof(chain[0]), types.hash256_hex(req.block_locator_hashes[1]))
    assert.are.equal(hexof(chain[ROOT - 1]), types.hash256_hex(req.hash_stop))
    -- in flight: no duplicate inside the retry window
    assert.is_false(hc:maybe_request_prebase(peer, 1001))
  end)

  it("holds block connection while the gap is open", function()
    local hc = snapshot_chain(chain)
    hc:refresh_prebase_gap()
    local bd = { header_chain = hc }
    -- must return before touching any other downloader state
    assert.is_true(sync.new_block_downloader and
      getmetatable(sync.new_block_downloader(hc, storage_mod.new_memory_storage(), hc.network))
        ._connect_pending_blocks_inner(bd))
  end)

  it("links in two batches, commits headers + height index + work, releases", function()
    local hc, st, cum = snapshot_chain(chain)
    hc:refresh_prebase_gap()
    local peer = { send_message = function() return true end }
    local n1, e1 = hc:handle_headers(peer, p2p.serialize_headers(batch(chain, 1, 10)))
    assert.is_nil(e1); assert.are.equal(10, n1)
    assert.is_not_nil(hc.prebase_gap)
    assert.is_nil(hc.height_to_hash[5])          -- staged only, not committed
    local n2, e2 = hc:handle_headers(peer, p2p.serialize_headers(batch(chain, 11, 25)))
    assert.is_nil(e2); assert.are.equal(9, n2)   -- 11..19; 20+ is past hashStop
    assert.is_nil(hc.prebase_gap)
    for h = 1, ROOT - 1 do
      assert.are.equal(hexof(chain[h]), hc.height_to_hash[h])
      assert.is_not_nil(st.get_header(validation.compute_block_hash(chain[h])))
      assert.are.equal(hexof(chain[h]), types.hash256_hex(st.get_hash_by_height(h)))
    end
    assert.are.equal(0, consensus.work_compare(cum, hc.headers[hexof(chain[BASE])].total_work))
    assert.is_true(consensus.work_compare(hc.headers[hexof(chain[ROOT])].total_work,
      consensus.work_zero()) > 0)
    -- the coin-MTP lookup below the band now resolves
    assert.is_not_nil(utxo.compute_mtp_from_storage(st, validation.compute_block_hash(chain[ROOT - 1])))
    -- and a fresh refresh finds no gap
    assert.is_nil(hc:refresh_prebase_gap())
  end)

  it("a valid chain that does not hash to the band root is discarded", function()
    local hc = snapshot_chain(chain)
    hc:refresh_prebase_gap()
    local peer = { send_message = function() return true end }
    local n, err = hc:handle_headers(peer, p2p.serialize_headers(batch(other, 1, ROOT - 1)))
    assert.are.equal(-1, n)
    assert.is_truthy(err:find("not the snapshot band root parent", 1, true))
    assert.is_not_nil(hc.prebase_gap)
    assert.are.equal(0, hc.prebase_gap.frontier_height)   -- restarted at genesis
    assert.is_nil(hc.height_to_hash[1])
  end)

  it("a header missing its own target stops the frontier (ban token)", function()
    local hc = snapshot_chain(chain)
    hc:refresh_prebase_gap()
    local bad = {}
    for k, v in pairs(chain[1]) do bad[k] = v end
    local target = consensus.bits_to_target(EASY)
    for nonce = 0, 100000 do
      bad.nonce = nonce
      local hb = types.block_header(bad.version, bad.prev_hash, bad.merkle_root,
        bad.timestamp, bad.bits, nonce)
      if not consensus.hash_meets_target(validation.compute_block_hash(hb).bytes, target) then
        bad = hb; break
      end
    end
    local n, err = hc:handle_headers({ send_message = function() return true end },
      p2p.serialize_headers({ bad }))
    assert.are.equal(-1, n)
    assert.is_truthy(err:find("proof of work", 1, true))
    assert.are.equal(0, hc.prebase_gap.frontier_height)
  end)

  it("chainwork mismatch with the seeded assumeutxo work stays held (fail closed)", function()
    local hc = snapshot_chain(chain, consensus.work_add(consensus.work_zero(),
      consensus.work_from_hex(string.rep("0", 63) .. "1")))
    hc:refresh_prebase_gap()
    local n, err = hc:handle_headers({ send_message = function() return true end },
      p2p.serialize_headers(batch(chain, 1, ROOT - 1)))
    assert.is_nil(err)
    assert.is_not_nil(hc.prebase_gap)
    assert.is_truthy(hc.prebase_gap.error:find("chainwork", 1, true))
    assert.is_nil(hc.height_to_hash[1])
  end)
end)
