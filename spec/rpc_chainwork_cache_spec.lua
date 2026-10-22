-- getblockchaininfo / getblockheader must not re-walk the whole chain on every
-- call.  lunarblock serves RPC on its single main loop, so one slow call delays
-- every request queued behind it: on mainnet (2026-10-22) getblockheader(tip)
-- took 47.9 s and getblockchaininfo 46.1 s, because chainwork was re-summed
-- from the last assumeutxo base (~28k headers) and getblockheader found the
-- block's height by scanning HEIGHT_INDEX from genesis.  The fleet monitors
-- call both every 5 minutes, so the peer-count sampler's getpeerinfo sat behind
-- them and timed out at 30 s in 15 of 20 samples.
--
-- These specs drive the RPC handlers against an in-memory storage that counts
-- header reads and height-index iterator steps, and pin:
--   * chainwork values (exact, independently computed) before and after
--     caching, across a tip extension and a reorg;
--   * a repeat or tip+1 query reads O(1) headers, not O(height);
--   * getblockheader takes the height from the header index, not a scan.

local rpc = require("lunarblock.rpc")
local types = require("lunarblock.types")
local consensus = require("lunarblock.consensus")
local cjson = require("cjson")

local EASY = 0x207fffff   -- regtest powLimit: block proof = 2
local HARD = 0x1d00ffff   -- mainnet genesis bits: block proof = 0x100010001
local PROOF = { [EASY] = 2, [HARD] = 0x100010001 }

-- Exact 64-char hex of a non-negative integer below 2^53.
local function hex64(n)
  local digits = {}
  for i = 64, 1, -1 do
    local d = n % 16
    digits[i] = string.format("%x", d)
    n = (n - d) / 16
  end
  return table.concat(digits)
end

local function mkhash(tag, h)
  -- 32 distinct bytes per (branch tag, height); never all-zero.
  local s = string.format("%s%08d", tag, h)
  return types.hash256(s .. string.rep("\1", 32 - #s))
end

-- In-memory chain store with the storage methods the handlers use.
local function new_store()
  local st = {
    headers = {},       -- hash bytes -> header
    by_height = {},     -- height -> hash256
    bits_at = {},       -- height -> bits (active chain)
    header_reads = 0,
    iter_steps = 0,
  }
  st.get_header = function(hash)
    st.header_reads = st.header_reads + 1
    return st.headers[hash.bytes]
  end
  st.get_hash_by_height = function(h) return st.by_height[h] end
  st.get_block = function() return nil end
  st.iterator = function(cf)
    assert(cf == "height")
    local i = 0
    local max_h = #st.by_height
    local it = {}
    it.seek_to_first = function() i = 0 end
    it.valid = function() return i <= max_h and st.by_height[i] ~= nil end
    it.key = function() return string.char(0, math.floor(i / 65536) % 256, math.floor(i / 256) % 256, i % 256) end
    it.value = function() return st.by_height[i].bytes end
    it.next = function() st.iter_steps = st.iter_steps + 1; i = i + 1 end
    it.destroy = function() end
    return it
  end
  -- Append (or overwrite, for a reorg) the active block at height h.
  st.set = function(h, tag, bits)
    local hash = mkhash(tag, h)
    local prev = (h > 0) and st.by_height[h - 1] or types.hash256(string.rep("\0", 32))
    st.headers[hash.bytes] = {
      version = 0x20000000, prev_hash = prev,
      merkle_root = types.hash256(string.rep("\2", 32)),
      timestamp = 1700000000 + h * 600, bits = bits, nonce = h,
    }
    st.by_height[h] = hash
    st.bits_at[h] = bits
  end
  st.truncate = function(top)
    for h = top + 1, #st.by_height do st.by_height[h] = nil; st.bits_at[h] = nil end
  end
  st.expected_chainwork = function(h)
    local w = 0
    for i = 0, h do w = w + PROOF[st.bits_at[i]] end
    return hex64(w)
  end
  return st
end

-- Minimal header index (sync.HeaderChain:get_header shape): hex -> {height}.
local function new_header_chain(st)
  local hc = { headers = {} }
  function hc:get_header(hash) return self.headers[types.hash256_hex(hash)] end
  hc.index = function(h)
    hc.headers[types.hash256_hex(st.by_height[h])] = { height = h }
  end
  return hc
end

local function build_chain(n, tag)
  local st = new_store()
  local hc = new_header_chain(st)
  for h = 0, n do
    st.set(h, tag or "a", (h < n / 2) and EASY or HARD)
    hc.index(h)
  end
  return st, hc
end

local function server_for(st, hc, tip)
  return rpc.new({
    chain_state = { tip_height = tip, tip_hash = st.by_height[tip] },
    storage = st,
    header_chain = hc,
    network = consensus.networks.regtest,
  })
end

local function call(server, method, params)
  local body = server:handle_request(cjson.encode(
    { method = method, params = params or {}, id = 1 }))
  local resp = cjson.decode(body)
  if resp.error ~= nil and resp.error ~= cjson.null then
    error(method .. " errored: " .. cjson.encode(resp.error))
  end
  return resp.result
end

-- A query this cheap is what keeps getpeerinfo answerable behind the
-- monitors: the MTP walk (11) + tip header lookups + a short chainwork walk.
local MAX_WARM_HEADER_READS = 64

describe("chainwork cache (getpeerinfo starved behind slow RPCs)", function()
  local N = 3000

  it("getblockchaininfo repeat query does not re-walk the chain", function()
    local st, hc = build_chain(N)
    local server = server_for(st, hc, N)
    local first = call(server, "getblockchaininfo")
    assert.equal(st.expected_chainwork(N), first.chainwork)

    st.header_reads = 0
    local again = call(server, "getblockchaininfo")
    assert.equal(first.chainwork, again.chainwork)
    assert.is_true(st.header_reads <= MAX_WARM_HEADER_READS,
      "warm getblockchaininfo read " .. st.header_reads .. " headers")
  end)

  it("getblockchaininfo after the tip advances by one reads O(1) headers", function()
    local st, hc = build_chain(N)
    local server = server_for(st, hc, N)
    call(server, "getblockchaininfo")

    st.set(N + 1, "a", HARD); hc.index(N + 1)
    server.chain_state.tip_height = N + 1
    server.chain_state.tip_hash = st.by_height[N + 1]
    st.header_reads = 0
    local r = call(server, "getblockchaininfo")
    assert.equal(st.expected_chainwork(N + 1), r.chainwork)
    assert.is_true(st.header_reads <= MAX_WARM_HEADER_READS,
      "tip+1 getblockchaininfo read " .. st.header_reads .. " headers")
  end)

  it("getblockheader(tip) finds the height without scanning HEIGHT_INDEX", function()
    local st, hc = build_chain(N)
    local server = server_for(st, hc, N)
    local tip_hex = types.hash256_hex(st.by_height[N])
    local r = call(server, "getblockheader", { tip_hex })
    assert.equal(N, r.height)
    assert.equal(1, r.confirmations)
    assert.equal(st.expected_chainwork(N), r.chainwork)

    st.header_reads, st.iter_steps = 0, 0
    r = call(server, "getblockheader", { tip_hex })
    assert.equal(st.expected_chainwork(N), r.chainwork)
    assert.is_true(st.iter_steps <= 1,
      "getblockheader stepped the height index " .. st.iter_steps .. " times")
    assert.is_true(st.header_reads <= MAX_WARM_HEADER_READS,
      "warm getblockheader read " .. st.header_reads .. " headers")
  end)

  it("getblockheader of an older block after the tip is cached is exact and cheap", function()
    local st, hc = build_chain(N)
    local server = server_for(st, hc, N)
    call(server, "getblockchaininfo")
    for _, h in ipairs({ 0, 1, 999, 1000, 1001, 1499, 1500, 2001, N - 1 }) do
      st.header_reads = 0
      local r = call(server, "getblockheader", { types.hash256_hex(st.by_height[h]) })
      assert.equal(h, r.height)
      assert.equal(st.expected_chainwork(h), r.chainwork, "chainwork at " .. h)
      assert.is_true(st.header_reads <= 1000 + MAX_WARM_HEADER_READS,
        "getblockheader(" .. h .. ") read " .. st.header_reads .. " headers")
    end
  end)

  -- Consensus-adjacent safety: chainwork is reporting-only here, but a stale
  -- cache would report the old branch's work after a reorg.  Cache entries are
  -- keyed by block hash, which commits to the whole ancestry, so a replaced
  -- branch can never be served.
  it("a reorg below cached points reports the new branch's chainwork", function()
    local st, hc = build_chain(N)
    local server = server_for(st, hc, N)
    call(server, "getblockchaininfo")
    -- Replace everything above 1500 (crossing the 2000 checkpoint) with a
    -- branch whose blocks are all EASY, then extend it past the old tip.
    local fork = 1500
    st.truncate(fork)
    for h = fork + 1, N + 5 do st.set(h, "b", EASY); hc.index(h) end
    server.chain_state.tip_height = N + 5
    server.chain_state.tip_hash = st.by_height[N + 5]
    local r = call(server, "getblockchaininfo")
    assert.equal(st.expected_chainwork(N + 5), r.chainwork)
    r = call(server, "getblockheader", { types.hash256_hex(st.by_height[2000]) })
    assert.equal(st.expected_chainwork(2000), r.chainwork)

    -- Reorg to a SHORTER branch below the last checkpoint: tip moves down.
    st.truncate(900)
    for h = 901, 950 do st.set(h, "c", HARD); hc.index(h) end
    server.chain_state.tip_height = 950
    server.chain_state.tip_hash = st.by_height[950]
    r = call(server, "getblockchaininfo")
    assert.equal(st.expected_chainwork(950), r.chainwork)
  end)

  it("a block off the active chain is still reported with confirmations -1", function()
    local st, hc = build_chain(200)
    local server = server_for(st, hc, 200)
    -- A stale header the header index knows at height 150, not active there.
    local stale = mkhash("z", 150)
    st.headers[stale.bytes] = {
      version = 0x20000000, prev_hash = st.by_height[149],
      merkle_root = types.hash256(string.rep("\2", 32)),
      timestamp = 1700000000, bits = EASY, nonce = 7,
    }
    hc.headers[types.hash256_hex(stale)] = { height = 150 }
    local r = call(server, "getblockheader", { types.hash256_hex(stale) })
    assert.equal(-1, r.confirmations)
  end)
end)
