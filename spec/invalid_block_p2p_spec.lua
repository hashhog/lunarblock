-- spec/invalid_block_p2p_spec.lua
--
-- A block delivered over P2P that fails CONSENSUS validation must be handled
-- the way Bitcoin Core handles it:
--   * Chainstate::InvalidBlockFound / InvalidChainFound (validation.cpp):
--     mark it BLOCK_FAILED_VALID, its descendants BLOCK_FAILED_CHILD, and
--     RecalculateBestHeader so the most-work VALID header is the target.
--   * Core never re-requests a failed block, and fetches the valid competitor
--     at the same height.
--   * AcceptBlockHeader: a header on a failed parent is BLOCK_INVALID_PREV
--     ("bad-prevblk").
--   * Non-verdicts (BLOCK_MUTATED, our missing data such as
--     missing-ancestor-header, local I/O) are NOT marked: retry later.
--
-- Pre-fix (e4b11ef) the download walk re-requested the failed block on the
-- next scheduler tick: tools/p2p-invalid-block-feed.py counted 7,249 getdata
-- for one bad-cb-amount block in ~60 s.

package.path = "src/?.lua;" .. package.path

local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local p2p = require("lunarblock.p2p")
local sync = require("lunarblock.sync")

local REGTEST = consensus.networks.regtest

local function create_storage()
  local data = { meta = {}, headers = {}, height = {}, blocks = {} }
  local s = {
    CF = { META = "meta", HEADERS = "headers", HEIGHT_INDEX = "height",
           BLOCKS = "blocks" },
  }
  function s.get(cf, key) return data[cf] and data[cf][key] end
  function s.put(cf, key, value) data[cf][key] = value end
  function s.get_header(h)
    local d = data.headers[h.bytes]
    return d and serialize.deserialize_block_header(d) or nil
  end
  function s.put_header(h, header)
    data.headers[h.bytes] = serialize.serialize_block_header(header)
  end
  local function hkey(height)
    return string.char(math.floor(height / 16777216) % 256,
      math.floor(height / 65536) % 256, math.floor(height / 256) % 256,
      height % 256)
  end
  function s.put_height_index(height, h) data.height[hkey(height)] = h.bytes end
  function s.get_hash_by_height(height)
    local b = data.height[hkey(height)]
    return b and types.hash256(b) or nil
  end
  function s.put_block(h, blk) data.blocks[h.bytes] = serialize.serialize_block(blk) end
  function s.get_block(h)
    local d = data.blocks[h.bytes]
    return d and serialize.deserialize_block(d) or nil
  end
  function s.get_chain_tip() return nil, nil end
  function s.set_chain_tip() end
  return s
end

local function mine_header(parent_hash, timestamp)
  local header = types.block_header(4, parent_hash, types.hash256_zero(),
    timestamp, REGTEST.pow_limit_bits, 0)
  local target = consensus.bits_to_target(header.bits)
  for nonce = 0, 1000000 do
    header.nonce = nonce
    if consensus.hash_meets_target(validation.compute_block_hash(header).bytes, target) then
      return header
    end
  end
  error("no nonce")
end

local function hex_of(header)
  return types.hash256_hex(validation.compute_block_hash(header))
end

local function mock_peer(id)
  local peer = { id = id, ip = "127.0.0." .. id, start_height = 100,
                 services = 9, messages_sent = {} }
  function peer:send_message(cmd, payload)
    self.messages_sent[#self.messages_sent + 1] = { command = cmd, payload = payload }
    return true
  end
  return peer
end

-- How many getdata items for `hash_hex` has `peer` been sent?
local function getdata_count(peer, hash_hex)
  local n = 0
  for _, m in ipairs(peer.messages_sent) do
    if m.command == "getdata" then
      for _, item in ipairs(p2p.deserialize_inv(m.payload)) do
        if types.hash256_hex(item.hash) == hash_hex then n = n + 1 end
      end
    end
  end
  return n
end

-- A body for `header` (contents are irrelevant: check_block is stubbed; the
-- verdict comes from the connect callback, exactly as on the live node where
-- bad-cb-amount / bad-txns-nonfinal come out of ConnectBlock).
local function body(header)
  local cb = types.transaction(1,
    { types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF), "\1\1", 0xFFFFFFFF) },
    { types.txout(5000000001, "") }, 0)
  return serialize.serialize_block(types.block(header, { cb }))
end

describe("invalid block over P2P (Core InvalidBlockFound parity)", function()
  local orig_check_block, orig_is_mutated
  local storage, chain, dl, genesis_hash, t0
  local cb_err            -- error the connect callback raises for B1
  local connects          -- hash_hex -> times connect_callback ran
  local persisted         -- hashes handed to invalid_block_callback

  before_each(function()
    orig_check_block = validation.check_block
    -- The bodies here are placeholders that do not match their headers
    -- (merkle root zero).  The verdict under test comes from the connect
    -- callback, so the receipt-time mutation gate (LB-1, its own spec in
    -- audit_liveness_spec.lua) is stubbed along with check_block.
    orig_is_mutated = validation.is_block_mutated
    validation.is_block_mutated = function() return false end
    validation.check_block = function() return true end
    storage = create_storage()
    chain = sync.new_header_chain(REGTEST, storage)
    chain:init()
    genesis_hash = chain:get_tip_hash()
    t0 = REGTEST.genesis.timestamp
    dl = sync.new_block_downloader(chain, storage, REGTEST)
    dl.next_connect_height = 1
    dl.next_download_height = 1
    dl.active_tip_provider = function() return genesis_hash, 0 end
    connects, persisted = {}, {}
    dl.connect_callback = function(block, height, hash)
      local hx = types.hash256_hex(hash)
      connects[hx] = (connects[hx] or 0) + 1
      error(cb_err)
    end
    dl.invalid_block_callback = function(hashes)
      for _, h in ipairs(hashes) do persisted[types.hash256_hex(h)] = true end
    end
  end)

  after_each(function()
    validation.check_block = orig_check_block
    validation.is_block_mutated = orig_is_mutated
  end)

  it("marks a consensus-invalid block failed, never re-requests it, and fetches the competitor", function()
    cb_err = "src/main.lua:1623: Failed to connect block 1: bad-cb-amount: "
      .. "coinbase pays too much (actual=5000000001 vs limit=5000000000)"
    local b1 = mine_header(genesis_hash, t0 + 600)
    local b1_hex = hex_of(b1)
    assert.is_true(chain:accept_header(b1))
    local x = mock_peer(2)

    dl:schedule_downloads({ x })
    assert.equals(1, getdata_count(x, b1_hex))

    local ok, err = dl:handle_block(x, body(b1))
    assert.is_false(ok)
    assert.truthy(tostring(err):find("bad-cb-amount", 1, true))
    assert.equals(1, connects[b1_hex])

    -- The scheduler never asks for B1 again (pre-fix: once per tick).
    for _ = 1, 25 do dl:schedule_downloads({ x }) end
    assert.equals(1, getdata_count(x, b1_hex),
      "failed block re-requested (pre-fix hot loop)")

    -- The verdict is recorded (and handed off for persistence) ...
    assert.is_true(chain:is_failed(b1_hex))
    assert.is_true(persisted[b1_hex])
    -- ... and the header tip is back on the valid chain.
    assert.equals(0, chain.header_tip_height)
    assert.is_nil(chain.height_to_hash[1])

    -- Re-delivery (X redials and pushes it) never reaches connect again, and
    -- a re-announced header is a no-op.
    assert.is_true(dl:handle_block(x, body(b1)))
    assert.equals(1, connects[b1_hex])
    assert.is_true(chain:accept_header(b1))
    assert.equals(0, chain.header_tip_height)

    -- A header building on B1 is refused (Core BLOCK_INVALID_PREV).
    local b2x = mine_header(validation.compute_block_hash(b1), t0 + 1200)
    local ok2, err2 = chain:accept_header(b2x)
    assert.is_false(ok2)
    assert.equals("bad-prevblk", err2)

    -- The honest competitor at the same height becomes the target and is fetched.
    local h = mock_peer(3)
    local b1v = mine_header(genesis_hash, t0 + 601)
    local b1v_hex = hex_of(b1v)
    assert.is_true(chain:accept_header(b1v))
    assert.equals(1, chain.header_tip_height)
    assert.equals(b1v_hex, chain.height_to_hash[1])
    dl:schedule_downloads({ x, h })
    assert.equals(1, getdata_count(x, b1v_hex) + getdata_count(h, b1v_hex))
    assert.equals(1, getdata_count(x, b1_hex) + getdata_count(h, b1_hex))
  end)

  it("marks known descendants failed-child and moves the header tip off the branch", function()
    cb_err = "Failed to connect block 1: non-final transaction: bad-txns-nonfinal"
    local b1 = mine_header(genesis_hash, t0 + 600)
    local b2 = mine_header(validation.compute_block_hash(b1), t0 + 1200)
    assert.is_true(chain:accept_header(b1))
    assert.is_true(chain:accept_header(b2))
    assert.equals(2, chain.header_tip_height)
    local x = mock_peer(2)
    dl:schedule_downloads({ x })
    local b2_before = getdata_count(x, hex_of(b2))  -- in the first window
    dl:handle_block(x, body(b1))
    assert.is_true(chain:is_failed(hex_of(b1)))
    assert.is_true(chain:is_failed(hex_of(b2)))
    assert.is_true(persisted[hex_of(b2)])
    assert.equals(0, chain.header_tip_height)
    for _ = 1, 10 do dl:schedule_downloads({ x }) end
    assert.equals(b2_before, getdata_count(x, hex_of(b2)))
    assert.equals(1, getdata_count(x, hex_of(b1)))
    assert.is_nil(dl.inflight[hex_of(b2)], "failed descendant left in flight")
  end)

  it("does NOT mark a non-verdict (missing-ancestor-header) failure; retries after a backoff", function()
    cb_err = "Failed to connect block 1: missing-ancestor-header: no header at "
      .. "height 0 for input 0 (BIP68 time lock)"
    local b1 = mine_header(genesis_hash, t0 + 600)
    local b1_hex = hex_of(b1)
    assert.is_true(chain:accept_header(b1))
    local x = mock_peer(2)
    dl:schedule_downloads({ x })
    local ok = dl:handle_block(x, body(b1))
    assert.is_false(ok)
    assert.is_false(chain:is_failed(b1_hex))
    assert.is_nil(persisted[b1_hex])
    assert.equals(1, chain.header_tip_height)
    assert.equals(b1_hex, chain.height_to_hash[1])

    -- Not hammered on the next ticks ...
    for _ = 1, 10 do dl:schedule_downloads({ x }) end
    assert.equals(1, getdata_count(x, b1_hex))
    -- ... but still requestable once the backoff expires (no verdict).
    dl._cb_retry_after[b1_hex] = 0
    dl._force_rerequest_last = {}
    dl:schedule_downloads({ x })
    assert.equals(2, getdata_count(x, b1_hex))
  end)

  it("classifies verdicts vs non-verdicts like Core (BLOCK_MUTATED and our missing data are not verdicts)", function()
    local V = sync.is_invalid_block_verdict
    assert.is_true(V("Failed to connect block 21: bad-cb-amount: coinbase pays too much"))
    assert.is_true(V("Failed to connect block 111: non-final transaction: bad-txns-nonfinal"))
    assert.is_true(V("Script verification failed for input 0 of tx ab"))
    assert.is_true(V("Failed to connect block 111: utxo.lua:3119: BIP68 sequence locks not satisfied for tx 7b"))
    assert.is_false(V("Failed to connect block 111: missing-ancestor-header: bad-txns-nonfinal pending"))
    assert.is_false(V("merkle root mismatch"))
    assert.is_false(V("bad-txns-duplicate"))
    assert.is_false(V("witness commitment mismatch"))
    assert.is_false(V("Missing UTXO for input 1 of tx 98a0"))
    assert.is_false(V("rocksdb error: IO error: No space left on device"))
    assert.is_false(V("connect_block: prev_hash mismatch"))
    assert.is_false(V(nil))
  end)

  it("a side-branch reorg verdict marks the ancestor that failed and its descendant", function()
    -- Active chain: genesis -> A1.  Competing: genesis -> B1 -> B2x (heavier).
    local a1 = mine_header(genesis_hash, t0 + 600)
    assert.is_true(chain:accept_header(a1))
    local a1_hash = validation.compute_block_hash(a1)
    local b1 = mine_header(genesis_hash, t0 + 601)
    local b2x = mine_header(validation.compute_block_hash(b1), t0 + 1200)
    assert.is_true(chain:accept_header(b1))
    assert.is_true(chain:accept_header(b2x))
    assert.equals(2, chain.header_tip_height)
    local b1_hex, b2x_hex = hex_of(b1), hex_of(b2x)

    -- Mapping only: non-verdicts never condemn anything.
    assert.equals(b1_hex, dl:_side_branch_failed_hex(b2x_hex, nil,
      "reorg-connect-failed at height 1: bad-cb-amount: coinbase pays too much"))
    assert.is_nil(dl:_side_branch_failed_hex(b2x_hex, nil,
      "reorg-connect-failed: side-branch block missing at height 1"))
    assert.is_nil(dl:_side_branch_failed_hex(b2x_hex, nil,
      "reorg-connect-failed at height 1: missing-ancestor-header: no header at height 0"))
    assert.equals(b2x_hex, dl:_side_branch_failed_hex(b2x_hex, nil, "invalid-ancestor"))

    -- Drive it: active tip A1, B2x arrives, orchestrator reports the B1 verdict.
    dl.active_tip_provider = function() return a1_hash, 1 end
    dl.next_connect_height = 2
    dl.next_download_height = 2
    dl.side_branch_callback = function(block, hash)
      if block.header.prev_hash.bytes == a1_hash.bytes then return "extend" end
      return nil, "reorg-connect-failed at height 1: bad-cb-amount: coinbase pays too much"
    end
    local x = mock_peer(2)
    local ok, err = dl:handle_block(x, body(b2x))
    assert.is_false(ok)
    assert.truthy(tostring(err):find("bad-cb-amount", 1, true))
    assert.is_true(chain:is_failed(b1_hex))
    assert.is_true(chain:is_failed(b2x_hex))
    assert.is_true(persisted[b1_hex] and persisted[b2x_hex])
    assert.equals(1, chain.header_tip_height)
    assert.equals(hex_of(a1), chain.height_to_hash[1])
    assert.equals(2, dl.next_connect_height)
    for _ = 1, 10 do dl:schedule_downloads({ x }) end
    assert.equals(0, getdata_count(x, b1_hex) + getdata_count(x, b2x_hex))
  end)
end)

-- ChainState:accept_side_branch_block must return to the valid chain when a
-- side-branch block's connect RAISES (connect_block asserts on BIP68 sequence
-- locks and script failures) -- not only when it returns (nil, err).  Pre-fix
-- the raise escaped past abort_reorg: the reorg batch was never destroyed and
-- the in-memory tip stayed at the fork point, i.e. the valid tip that had just
-- been disconnected was lost (p2p-invalid-block-feed after/bip68
-- "tip-disturbed").
describe("side-branch reorg: a RAISED connect failure rolls back to the valid tip", function()
  local utxo = require("lunarblock.utxo")
  local script = require("lunarblock.script")
  local storage_mod = require("lunarblock.storage")
  local SPK = script.make_p2pkh_script(string.rep("\x42", 20))
  local db, cs, path

  local function coinbase(height, nonce)
    return types.transaction(1,
      { types.txin(types.outpoint(types.hash256_zero(), 0xFFFFFFFF),
                   string.char(1, height % 256, nonce or 0), 0xFFFFFFFF) },
      { types.txout(5000000000, SPK) }, 0)
  end
  local function block_at(height, prev, nonce)
    local header = types.block_header(1, prev, types.hash256_zero(),
      os.time() + height + (nonce or 0) * 1000000, REGTEST.pow_limit_bits, nonce or 0)
    return types.block(header, { coinbase(height, nonce) })
  end

  before_each(function()
    path = "/tmp/lunarblock_ibp2p_sb_" .. os.time() .. "_" .. math.random(1e9)
    db = storage_mod.open(path)
    cs = utxo.new_chain_state(db, REGTEST)
    cs:init()
  end)
  after_each(function()
    if db then db.close() end
    os.execute("rm -rf '" .. path .. "'")
  end)

  local function run(mode)
    -- Active: h0 -> h1 -> A2.  Side: h1 -> S2 -> S3 (heavier).
    local prev = types.hash256_zero()
    local hashes = {}
    for h = 0, 2 do
      local b = block_at(h, prev)
      local bh = validation.compute_block_hash(b.header)
      db.put_header(bh, b.header); db.put_block(bh, b); db.put_height_index(h, bh)
      assert(cs:connect_block(b, h, bh, nil, nil, true))
      hashes[h], prev = bh, bh
    end
    local s2 = block_at(2, hashes[1], 7)
    local s2h = validation.compute_block_hash(s2.header)
    db.put_header(s2h, s2.header); db.put_block(s2h, s2)
    local s3 = block_at(3, s2h, 7)
    local s3h = validation.compute_block_hash(s3.header)
    db.put_header(s3h, s3.header); db.put_block(s3h, s3)

    assert.is_not_nil(cs.coin_view:get(validation.compute_txid(coinbase(2)), 0), "precondition")
    -- S2's connect raises the way connect_block's BIP68 assert does.
    local real_connect = cs.connect_block
    cs.connect_block = function(self, blk, height, bh, ...)
      if bh.bytes == s2h.bytes then
        if mode == "raise" then
          error("utxo.lua:3119: BIP68 sequence locks not satisfied for tx ab "
            .. "(min_height=-1 >= 2 or min_time=9 >= 8)")
        end
        return nil, "bad-cb-amount: coinbase pays too much"
      end
      return real_connect(self, blk, height, bh, ...)
    end

    local ok, res, err = pcall(cs.accept_side_branch_block, cs, s3, s3h)
    assert.is_true(ok, "accept_side_branch_block raised: " .. tostring(res))
    assert.is_nil(res)
    assert.truthy(tostring(err):find("^reorg%-connect%-failed at height 2: "))
    assert.is_true(sync.is_invalid_block_verdict(err:match(": (.*)$")))
    -- Back on the valid tip, in memory and on disk.
    assert.equals(2, cs.tip_height)
    assert.equals(types.hash256_hex(hashes[2]), types.hash256_hex(cs.tip_hash))
    local disk_hash, disk_h = db.get_chain_tip()
    assert.equals(2, disk_h)
    assert.equals(types.hash256_hex(hashes[2]), types.hash256_hex(disk_hash))
    -- A2's coinbase is still spendable (the disconnect was rolled back).
    local a2_txid = validation.compute_txid(block_at(2, hashes[1]).transactions[1])
    assert.is_not_nil(cs.coin_view:get(a2_txid, 0),
      "disconnected tip's coinbase reads as spent after the aborted reorg")
  end

  it("connect RAISES (BIP68 assert): rolls back to the valid tip", function()
    run("raise")
  end)

  it("connect RETURNS a verdict (bad-cb-amount): coin cache matches disk again", function()
    run("return")
  end)
end)
