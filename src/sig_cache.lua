--- sig_cache.lua: Signature verification cache for transaction validation
-- Caches successful script verifications to avoid redundant work during block validation.
--
-- W105 BUG-1 fix: key is now per-TX (not per-input).  input_index is ignored
-- in make_key; a single cache entry covers all inputs of a transaction.
-- Callers should pass the wtxid (witness txid) so that segwit witness mutation
-- produces a cache miss; the key derivation itself is agnostic to which hash
-- is supplied, so the wtxid fix lives in utxo.lua at the call sites.
--
-- W105 BUG-2 fix: a 32-byte per-process nonce (read from /dev/urandom at
-- construction time) is prepended to every key input before SHA-256.  Keys
-- from a previous process run cannot collide with the current session's keys.
-- This mirrors Core's GetRandHash() nonce in validation.cpp:2030-2035.

local crypto = require("lunarblock.crypto")

local SigCache = {}
SigCache.__index = SigCache

--- Create a new signature cache.
-- A 32-byte per-process nonce is read from /dev/urandom at construction time
-- (W105 BUG-2: no nonce in previous implementation).
-- @param max_entries number: Maximum number of entries (default 50000)
-- @return SigCache: New cache instance
function SigCache.new(max_entries)
  -- Read 32 bytes from /dev/urandom for the per-instance nonce.
  -- Pattern mirrors peerman.lua:_init_addrman (FIX-19 d870baa) and
  -- sync.lua HeadersSync construction.
  local nonce
  local f = io.open("/dev/urandom", "rb")
  if f then
    nonce = f:read(32)
    f:close()
  end
  if not nonce or #nonce ~= 32 then
    -- /dev/urandom unavailable (rare; test environments without the device).
    -- Fall back to a weak nonce derived from os.time() + os.clock().
    -- Documented limitation; production deployments should have /dev/urandom.
    nonce = tostring(os.time()) .. tostring(os.clock()) .. tostring(math.random())
  end

  return setmetatable({
    cache      = {},
    count      = 0,
    max_entries = max_entries or 50000,
    _nonce     = nonce,
  }, SigCache)
end

--- Create a cache key from verification parameters.
-- Key = SHA-256(nonce || txid_or_wtxid || flags_string).
-- input_index is intentionally ignored: the cache is keyed per-TX, not
-- per-input, matching Core's SHA256(nonce || wtxid || flags) scheme.
-- @param txid_or_wtxid string: Transaction or witness-transaction ID (32 bytes)
-- @param input_index number: (ignored) Input index — kept for API compat
-- @param flags number: Script verification flags
-- @return string: 32-byte binary cache key (SHA-256 hash)
function SigCache:make_key(txid_or_wtxid, input_index, flags)
  -- Concatenate nonce || txid_or_wtxid || flags as a decimal string.
  -- input_index is deliberately excluded (per-TX key, not per-input).
  local material = self._nonce .. txid_or_wtxid .. tostring(flags)
  return crypto.sha256(material)
end

--- Check if a verification result is cached.
-- @param txid_or_wtxid string: Transaction or witness-transaction ID (32 bytes)
-- @param input_index number: (ignored) Input index — kept for API compat
-- @param flags number: Script verification flags
-- @return boolean: True if cached (all inputs of the transaction verified OK)
function SigCache:lookup(txid_or_wtxid, input_index, flags)
  return self.cache[self:make_key(txid_or_wtxid, input_index, flags)] ~= nil
end

--- Insert a successful verification result into the cache.
-- A single insert covers all inputs of the transaction (per-TX semantics).
-- @param txid_or_wtxid string: Transaction or witness-transaction ID (32 bytes)
-- @param input_index number: (ignored) Input index — kept for API compat
-- @param flags number: Script verification flags
function SigCache:insert(txid_or_wtxid, input_index, flags)
  local key = self:make_key(txid_or_wtxid, input_index, flags)
  if self.cache[key] then return end

  -- Evict random entry if at capacity
  if self.count >= self.max_entries then
    local victim = next(self.cache)
    if victim then
      self.cache[victim] = nil
      self.count = self.count - 1
    end
  end

  self.cache[key] = true
  self.count = self.count + 1
end

--- Clear all cached entries.
-- Should be called on reorg/disconnect_block.
function SigCache:clear()
  self.cache = {}
  self.count = 0
end

--- Get current cache size.
-- @return number: Number of cached entries
function SigCache:size()
  return self.count
end

return SigCache
