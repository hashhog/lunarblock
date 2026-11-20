-- REST height lookups must not scan the height index once per header.
--
-- Core's rest_headers (src/rest.cpp) looks the start block up ONCE and then
-- walks ActiveChain().Next(); rest_block / rest_filter_header do one lookup.
-- lunarblock used to find each header's height by a full HEIGHT_INDEX scan
-- from seek_to_first, once PER returned header, so
-- GET /rest/headers/2000/<hash> cost O(count x height) iterator steps on the
-- single main loop (~2000 x 970k on mainnet).
--
-- These specs build an in-memory store of 50,000 heights, wrap its
-- iterator() so every next() is counted, and assert the cost is O(count).
-- A step budget makes the wrapped iterator stop early once exceeded, so the
-- pre-fix code finishes quickly and fails on the assertion instead of
-- spending minutes scanning.

local rest = require("lunarblock.rest")
local types = require("lunarblock.types")
local storage_mod = require("lunarblock.storage")
local serialize = require("lunarblock.serialize")
local cjson = require("cjson")

local N_HEIGHTS = 50000
local START = 40000

local function be4(h)
  return string.char(math.floor(h / 16777216) % 256, math.floor(h / 65536) % 256,
                     math.floor(h / 256) % 256, h % 256)
end

local function hash_at(h)
  return types.hash256(string.rep("\xaa", 28) .. be4(h))
end

local function header_at(h)
  return {
    version = 0x20000000,
    prev_hash = h > 0 and hash_at(h - 1) or types.hash256(string.rep("\x00", 32)),
    merkle_root = types.hash256(string.rep("\xab", 32)),
    timestamp = 1700000000 + h,
    bits = 0x207fffff,
    nonce = h,  -- lets the spec check which header came back
  }
end

-- Shared fixture: built once (50k headers), reused by every case.
local db
local header_entries = {}

local function build_store()
  if db then return end
  db = storage_mod.new_memory_storage()
  for h = 0, N_HEIGHTS - 1 do
    local hh = hash_at(h)
    db.put_height_index(h, hh)
    db.put_header(hh, header_at(h))
    header_entries[hh.bytes] = { height = h }
  end
end

-- Proxy store whose height-index iterator counts steps and stops being valid
-- once `budget` steps have been taken (so a per-header scan cannot run for
-- minutes; it just yields a short/incorrect answer and a large step count).
local function counting_store(budget)
  local stats = { nexts = 0, iterators = 0 }
  local proxy = setmetatable({}, { __index = db })
  proxy.iterator = function(cf)
    local it = db.iterator(cf)
    if not it then return nil end
    stats.iterators = stats.iterators + 1
    local w = {}
    function w.seek_to_first() it.seek_to_first() end
    function w.seek(k) it.seek(k) end
    function w.valid() return stats.nexts < budget and it.valid() end
    function w.key() return it.key() end
    function w.value() return it.value() end
    function w.next() stats.nexts = stats.nexts + 1; it.next() end
    function w.destroy() it.destroy() end
    return w
  end
  return proxy, stats
end

-- Stand-in for main.lua's chain_state.header_index (sync.lua HeaderChain):
-- get_header(hash) -> {height = ...}.
local header_index = {
  get_header = function(_, hash) return header_entries[hash.bytes] end,
}

local function body_of(response)
  return response:match("\r\n\r\n(.*)$")
end

local function status_of(response)
  return tonumber(response:match("^HTTP/1%.1 (%d+)"))
end

describe("REST height lookup is O(count), not O(count x height)", function()
  setup(build_store)

  it("handle_headers 2000 from height 40000 takes no height-index scan with a header index", function()
    local store, stats = counting_store(4000)
    local server = rest.new({
      storage = store,
      chain_state = { tip_height = N_HEIGHTS - 1, header_index = header_index },
    })
    local resp = server:handle_headers("2000", types.hash256_hex(hash_at(START)), "bin")
    assert.equal(0, stats.nexts)
    assert.equal(0, stats.iterators)
    assert.equal(200, status_of(resp))
    local body = body_of(resp)
    assert.equal(2000 * 80, #body)
    -- first and last header are heights 40000 and 41999 (nonce = height)
    local r = serialize.buffer_reader(body:sub(1, 80))
    assert.equal(START, serialize.deserialize_block_header(r).nonce)
    r = serialize.buffer_reader(body:sub(1999 * 80 + 1, 2000 * 80))
    assert.equal(START + 1999, serialize.deserialize_block_header(r).nonce)
  end)

  it("handle_headers 2000 from height 40000 scans the height index at most once without a header index", function()
    -- One fallback scan reaches height 40000 in 40000 steps; per-header
    -- scans need ~2000 x 40000.  Budget = one full pass.
    local store, stats = counting_store(N_HEIGHTS)
    local server = rest.new({ storage = store, chain_state = { tip_height = N_HEIGHTS - 1 } })
    local resp = server:handle_headers("2000", types.hash256_hex(hash_at(START)), "bin")
    assert.is_true(stats.iterators <= 1, "iterators=" .. stats.iterators)
    assert.is_true(stats.nexts <= START, "nexts=" .. stats.nexts)
    assert.equal(200, status_of(resp))
    assert.equal(2000 * 80, #body_of(resp))
  end)

  it("handle_headers with count 1 returns the start header without any scan", function()
    local store, stats = counting_store(N_HEIGHTS)
    local server = rest.new({ storage = store, chain_state = { tip_height = N_HEIGHTS - 1 } })
    local resp = server:handle_headers("1", types.hash256_hex(hash_at(START)), "bin")
    assert.equal(200, status_of(resp))
    assert.equal(80, #body_of(resp))
    assert.equal(0, stats.iterators)
  end)

  it("handle_headers stops at the active tip and at a header the index does not hold", function()
    local store = counting_store(math.huge)
    local server = rest.new({
      storage = store,
      chain_state = { tip_height = N_HEIGHTS - 1, header_index = header_index },
    })
    -- 2000 requested from 49990: only 10 exist on the active chain.
    local resp = server:handle_headers("2000", types.hash256_hex(hash_at(N_HEIGHTS - 10)), "bin")
    assert.equal(10 * 80, #body_of(resp))
    -- Unknown start hash -> 404, as before.
    resp = server:handle_headers("5", string.rep("ee", 32), "bin")
    assert.equal(404, status_of(resp))
  end)

  it("handle_headers does not step forward from a stale (non-active) header", function()
    -- A header the header index places at height 40000 but that is NOT the
    -- active block there: only that header comes back (pre-fix behaviour,
    -- and Core returns nothing past a non-active block).
    local stale = types.hash256(string.rep("\xbb", 32))
    local store = counting_store(math.huge)
    local stale_header = header_at(START)
    stale_header.nonce = 777
    db.put_header(stale, stale_header)
    header_entries[stale.bytes] = { height = START }
    local server = rest.new({
      storage = store,
      chain_state = { tip_height = N_HEIGHTS - 1, header_index = header_index },
    })
    local resp = server:handle_headers("5", types.hash256_hex(stale), "bin")
    assert.equal(200, status_of(resp))
    assert.equal(80, #body_of(resp))
    header_entries[stale.bytes] = nil
  end)

  it("handle_block JSON resolves height with no height-index scan", function()
    local blk = { header = header_at(START), transactions = {} }
    local hh = hash_at(START)
    db.put_block(hh, blk)
    local store, stats = counting_store(N_HEIGHTS)
    local server = rest.new({
      storage = store,
      chain_state = { tip_height = N_HEIGHTS - 1, header_index = header_index },
    })
    local resp = server:handle_block(types.hash256_hex(hh), "json")
    assert.equal(200, status_of(resp))
    local d = cjson.decode(body_of(resp))
    assert.equal(START, d.height)
    assert.equal(N_HEIGHTS - START, d.confirmations)
    assert.equal(0, stats.nexts)
  end)

  it("blockfilterheaders resolves the start height with no height-index scan", function()
    for h = START, START + 99 do
      local w = serialize.buffer_writer()
      w.write_hash256(types.hash256(string.rep("\xfa", 32)))
      w.write_hash256(types.hash256(string.rep("\xfe", 28) .. be4(h)))
      w.write_varstr("\x01\x02")
      db.put("block_filter", hash_at(h).bytes, w.result())
    end
    local store, stats = counting_store(N_HEIGHTS)
    local server = rest.new({
      storage = store,
      chain_state = { tip_height = N_HEIGHTS - 1, header_index = header_index },
    })
    local resp = server:route("GET", "/rest/blockfilterheaders/basic/100/"
      .. types.hash256_hex(hash_at(START)) .. ".json")
    assert.equal(200, status_of(resp))
    assert.equal(100, #cjson.decode(body_of(resp)))
    assert.equal(0, stats.nexts)
  end)
end)
