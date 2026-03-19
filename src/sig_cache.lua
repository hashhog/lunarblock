--- sig_cache.lua: Signature verification cache for transaction validation
-- Caches successful script verifications to avoid redundant work during block validation.
-- Key is a combination of txid, input_index, and script flags.

local SigCache = {}
SigCache.__index = SigCache

--- Create a new signature cache.
-- @param max_entries number: Maximum number of entries (default 50000)
-- @return SigCache: New cache instance
function SigCache.new(max_entries)
  return setmetatable({
    cache = {},
    count = 0,
    max_entries = max_entries or 50000,
  }, SigCache)
end

--- Create a cache key from verification parameters.
-- @param txid string: Transaction ID (32 bytes)
-- @param input_index number: Input index
-- @param flags number: Script verification flags
-- @return string: Cache key
function SigCache:make_key(txid, input_index, flags)
  return txid .. ":" .. tostring(input_index) .. ":" .. tostring(flags)
end

--- Check if a verification result is cached.
-- @param txid string: Transaction ID (32 bytes)
-- @param input_index number: Input index
-- @param flags number: Script verification flags
-- @return boolean: True if cached (verification was successful)
function SigCache:lookup(txid, input_index, flags)
  return self.cache[self:make_key(txid, input_index, flags)] ~= nil
end

--- Insert a successful verification result into the cache.
-- @param txid string: Transaction ID (32 bytes)
-- @param input_index number: Input index
-- @param flags number: Script verification flags
function SigCache:insert(txid, input_index, flags)
  local key = self:make_key(txid, input_index, flags)
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
