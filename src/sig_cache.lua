--- sig_cache.lua: Signature verification cache for transaction validation
-- Caches successful script verifications to avoid redundant work during block validation.
--
-- CACHE GRANULARITY (per-INPUT).  The key incorporates input_index so each
-- input of a transaction has its OWN cache entry.  This is required because
-- utxo.lua inserts into the cache PER-INPUT, inside the input loop, right
-- after each input's script verifies (connect_block: sig_cache:insert after
-- the per-input verify block).  A per-TX key (input_index ignored) is UNSOUND
-- with that insertion pattern: the entry created after input 0 passes would
-- be HIT by input 1's lookup, so input 1..n-1 skip verification entirely.  A
-- crafted tx whose input 0 is valid but input 1 is invalid (e.g. the legacy
-- SIGHASH_SINGLE input_index>=n_outputs bug: a signature over the "proper"
-- SINGLE sighash that Core rejects because SignatureHash returns uint256(1))
-- then sails through — vin[0] passes, seeds the per-tx entry, vin[1]'s real
-- script check is skipped, and the block is falsely ACCEPTED → consensus fork.
-- (The prior "W105 BUG-1" per-TX key tried to mirror Core's g_scriptExecutionCache,
-- but Core inserts that per-TX entry ONCE, AFTER all inputs pass — not per-input.)
-- Callers should pass the wtxid (witness txid) so that segwit witness mutation
-- produces a cache miss.
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
-- Key = SHA-256(nonce || txid_or_wtxid || input_index || flags_string).
-- input_index IS part of the key: the cache is per-input (see file header for
-- why a per-TX key is unsound given the per-input insertion in utxo.lua).
-- @param txid_or_wtxid string: Transaction or witness-transaction ID (32 bytes)
-- @param input_index number: Input index (part of the key)
-- @param flags number: Script verification flags
-- @return string: 32-byte binary cache key (SHA-256 hash)
function SigCache:make_key(txid_or_wtxid, input_index, flags)
  -- Concatenate nonce || txid_or_wtxid || input_index || flags as a string.
  local material = self._nonce .. txid_or_wtxid ..
    tostring(input_index) .. ":" .. tostring(flags)
  return crypto.sha256(material)
end

--- Check if a verification result is cached.
-- @param txid_or_wtxid string: Transaction or witness-transaction ID (32 bytes)
-- @param input_index number: Input index (part of the key)
-- @param flags number: Script verification flags
-- @return boolean: True if this input of the transaction verified OK before
function SigCache:lookup(txid_or_wtxid, input_index, flags)
  return self.cache[self:make_key(txid_or_wtxid, input_index, flags)] ~= nil
end

--- Insert a successful verification result into the cache.
-- One insert covers a single (transaction, input) pair (per-input semantics).
-- @param txid_or_wtxid string: Transaction or witness-transaction ID (32 bytes)
-- @param input_index number: Input index (part of the key)
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
