--- getchaintips: every block-index leaf, not only the active tip.
--
-- Core rpc/blockchain.cpp getchaintips:
--   tips      = every block-index entry that is not on the active chain and
--               is not the pprev of another such entry, plus the active tip;
--   branchlen = height - FindFork(active chain).height;
--   status, first match wins:
--     active         on the active chain
--     invalid        BLOCK_FAILED_VALID (the block or, via the descendant
--                    marking, an ancestor failed)
--     headers-only   !HaveNumChainTxs: the block or an ancestor back to the
--                    active chain has no data
--     valid-fork     IsValid(BLOCK_VALID_SCRIPTS): connected at some point
--     valid-headers  IsValid(BLOCK_VALID_TREE)
--
-- lunarblock's block index is CF.HEADERS (hash -> 80-byte header, never
-- pruned, never deleted); bodies are CF.BLOCKS.  Heights come from the
-- in-memory HeaderChain when the header is resident there, else from the
-- parent chain.  "invalid" is ChainState.invalid_blocks / HeaderChain.failed
-- on the tip or any ancestor down to the fork (lunarblock marks descendants
-- too, as Core v31 does).  "Connected at some point" is the was-connected
-- marker disconnect_block writes (ChainState.WAS_CONNECTED_PREFIX); an
-- off-chain block that carries it once passed ConnectBlock.
--
-- Read-only: nothing here writes.
local types = require("lunarblock.types")
local storage_mod = require("lunarblock.storage")
local consensus = require("lunarblock.consensus")

local M = {}

-- Meta key prefix of the was-connected marker (written by
-- ChainState:disconnect_block).  Kept here so both sides use one name.
M.WAS_CONNECTED_PREFIX = "wasconnected:"

local ZERO32 = string.rep("\0", 32)

local HEXB = {}
for i = 0, 255 do HEXB[string.char(i)] = string.format("%02x", i) end

-- Display hex of raw (internal byte order) hash bytes.
local function hex_of(bytes)
  return (bytes:reverse():gsub(".", HEXB))
end

--- Compute the tip list.
-- @param ctx table { storage, chain_state, header_chain (optional) }
-- @return array of { height, hash (hex), branchlen, status }, highest first
function M.tips(ctx)
  local cs = ctx.chain_state
  local storage = ctx.storage
  local hc = ctx.header_chain
  local tip_hash = cs and cs.tip_hash
  local tip_height = cs and cs.tip_height or 0
  if not tip_hash then
    return { { height = tip_height, hash = hex_of(ZERO32), branchlen = 0,
               status = "active" } }
  end
  local active = { { height = tip_height, hash = hex_of(tip_hash.bytes),
                     branchlen = 0, status = "active" } }
  if not storage or not storage.iterator then
    return active
  end

  local resident = hc and hc.headers
  local h2h = hc and hc.height_to_hash

  -- Highest height F at which the header chain's height map agrees with the
  -- active chain; everything at or below F is then answered by the map in
  -- O(1) without walking the active chain from the tip.
  local F = -1
  if h2h then
    local h = math.min(tip_height, hc.header_tip_height or -1)
    while h >= 0 do
      local a = cs:active_hash_at(h)
      if a and h2h[h] == hex_of(a.bytes) then break end
      h = h - 1
    end
    F = h
  end

  local function on_active(hex, bytes, h)
    if h > tip_height or h < 0 then return false end
    if h <= F then return h2h[h] == hex end
    local a = cs:active_hash_at(h)
    return a ~= nil and a.bytes == bytes
  end

  -- Pass 1: every stored header.  Resident ones carry their height;
  -- the rest are resolved through their parents afterwards.
  local prev_of = {}     -- bytes -> prev bytes (non-active entries only)
  local height_of = {}   -- bytes -> height (non-active entries only)
  local nonres = {}      -- bytes -> prev bytes (height still unknown)
  local bits_of = {}     -- bytes -> nBits (non-active entries only)
  local iter = storage.iterator(storage_mod.CF.HEADERS)
  iter.seek_to_first()
  while iter.valid() do
    local k, v = iter.key(), iter.value()
    if #k == 32 and #v >= 36 then
      local prev = v:sub(5, 36)
      local b1, b2, b3, b4 = v:byte(73, 76)
      local hx = resident and hex_of(k)
      local e = hx and resident[hx]
      if e and e.height then
        if not on_active(hx, k, e.height) then
          prev_of[k] = prev
          height_of[k] = e.height
          bits_of[k] = ((b4 * 256 + b3) * 256 + b2) * 256 + b1
        end
      else
        nonres[k] = prev
        bits_of[k] = ((b4 * 256 + b3) * 256 + b2) * 256 + b1
      end
    end
    iter.next()
  end
  iter.destroy()

  -- Resolve the height of a header that is not resident: walk parents to
  -- one whose height is known.  nil when the ancestry is not in the index.
  local known = {}
  local function resolve_height(bytes)
    local path, n, cur, base = {}, 0, bytes, nil
    while true do
      local kh = known[cur]
      if kh ~= nil then base = kh break end
      if height_of[cur] then base = height_of[cur] break end
      local e = resident and resident[hex_of(cur)]
      if e and e.height then base = e.height break end
      local p = nonres[cur]
      if not p then
        local hdr = storage.get_header(types.hash256(cur))
        p = hdr and hdr.prev_hash.bytes
      end
      n = n + 1
      path[n] = cur
      if not p or n > 10000000 then base = false break end
      if p == ZERO32 then base = -1 break end  -- cur is the genesis block
      cur = p
    end
    -- path[i]'s parent is path[i + 1] (path[n]'s height is base + 1).
    for i = n, 1, -1 do
      if base ~= false then base = base + 1 end
      known[path[i]] = base
    end
    if base == false then return nil end
    return n > 0 and known[bytes] or base
  end

  for k, prev in pairs(nonres) do
    local h = resolve_height(k)
    if h and not on_active(hex_of(k), k, h) then
      prev_of[k] = prev
      height_of[k] = h
    end
  end

  -- An off-chain entry that is some off-chain entry's parent is not a tip
  -- (the children of an off-chain block are themselves off-chain).
  local is_parent = {}
  for _, p in pairs(prev_of) do is_parent[p] = true end

  local function is_invalid(bytes)
    if cs.invalid_blocks and cs.invalid_blocks[bytes] then return true end
    if hc and hc.is_failed and hc:is_failed(hex_of(bytes)) then return true end
    return false
  end

  local function has_data(bytes)
    return storage.get(storage_mod.CF.BLOCKS, bytes) ~= nil
  end

  local function was_connected(bytes)
    return storage.get(storage_mod.CF.META,
                       M.WAS_CONNECTED_PREFIX .. bytes) ~= nil
  end

  -- Work of the branch from `k` down to (not including) the fork at
  -- fork_h, against the active chain above fork_h.
  local function more_work_than_active(k, fork_h)
    local side = consensus.work_zero()
    local cur = k
    while cur and height_of[cur] and height_of[cur] > fork_h do
      side = consensus.work_add(side, consensus.get_block_work(bits_of[cur]))
      cur = prev_of[cur]
    end
    local act = consensus.work_zero()
    for h = fork_h + 1, tip_height do
      local a = cs:active_hash_at(h)
      local hdr = a and storage.get_header(a)
      if not hdr then return false end
      act = consensus.work_add(act, consensus.get_block_work(hdr.bits))
    end
    return consensus.work_compare(side, act) > 0
  end

  local out = { active[1] }
  for k, prev in pairs(prev_of) do
    if not is_parent[k] and k ~= tip_hash.bytes then
      -- Walk down to the active chain.
      local invalid, data = false, true
      local cur, fork_h = k, nil
      for _ = 1, 10000000 do
        if is_invalid(cur) then invalid = true end
        if data and not has_data(cur) then data = false end
        local p = prev_of[cur]
        if not p then break end  -- unreachable: cur is in prev_of
        if prev_of[p] then
          cur = p
        else
          -- p is on the active chain (or not in the index at all).
          local ph = height_of[cur] - 1
          local ok = on_active(hex_of(p), p, ph)
          if ok then fork_h = ph end
          break
        end
      end
      -- No fork on the active chain: the ancestry is not in the index, so
      -- the branch length is unknowable; leave the leaf out rather than guess.
      -- Also left out: a "valid" branch with all its data and MORE work than
      -- the active chain.  Core cannot hold one (ActivateBestChain connects
      -- it or marks it failed); lunarblock does when a side-branch connect
      -- failed without a recorded verdict (accept_side_branch_block's
      -- abort_reorg) or the branch was never activated.  Its real status is
      -- unknown to this node, so no status is invented for it.
      if fork_h and not invalid and data
          and more_work_than_active(k, fork_h) then
        fork_h = nil
      end
      if fork_h then
        local status
        if invalid then
          status = "invalid"
        elseif not data then
          status = "headers-only"
        elseif was_connected(k) then
          status = "valid-fork"
        else
          status = "valid-headers"
        end
        out[#out + 1] = { height = height_of[k], hash = hex_of(k),
                          branchlen = height_of[k] - fork_h, status = status }
      end
    end
  end

  table.sort(out, function(a, b)
    if a.height ~= b.height then return a.height > b.height end
    return a.hash < b.hash
  end)
  return out
end

M.hex_of = hex_of

return M
