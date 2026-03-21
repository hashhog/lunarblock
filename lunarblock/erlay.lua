--- BIP330 Erlay: Efficient transaction relay using set reconciliation.
-- Implements transaction announcement batching and minisketch-based reconciliation
-- to reduce bandwidth usage for transaction relay.
local ffi = require("ffi")
local bit = require("bit")
local crypto = require("lunarblock.crypto")
local minisketch = require("lunarblock.minisketch")
local serialize = require("lunarblock.serialize")
local M = {}

--------------------------------------------------------------------------------
-- Constants (from BIP330)
--------------------------------------------------------------------------------

-- Erlay protocol version
M.VERSION = 1

-- Default reconciliation interval in seconds
M.RECON_INTERVAL = 2

-- Field size for minisketch (32 bits for short txids)
M.FIELD_BITS = 32

-- Default sketch capacity (number of differences we can recover)
M.DEFAULT_CAPACITY = 100

-- Q-coefficient for estimating reconciliation set size
M.Q = 0.02

-- Maximum short txid value
M.MAX_SHORT_TXID = 0xFFFFFFFF

--------------------------------------------------------------------------------
-- SipHash-2-4 Implementation for Short TxIDs
--------------------------------------------------------------------------------

-- SipHash-2-4 constants
local SIPHASH_C0 = ffi.new("uint64_t", 0x736f6d6570736575ULL)
local SIPHASH_C1 = ffi.new("uint64_t", 0x646f72616e646f6dULL)
local SIPHASH_C2 = ffi.new("uint64_t", 0x6c7967656e657261ULL)
local SIPHASH_C3 = ffi.new("uint64_t", 0x7465646279746573ULL)

-- SipRound function
local function sipround(v0, v1, v2, v3)
  v0 = v0 + v1
  v1 = bit.bor(bit.lshift(v1, 13), bit.rshift(v1, 51))
  v1 = bit.bxor(v1, v0)
  v0 = bit.bor(bit.lshift(v0, 32), bit.rshift(v0, 32))

  v2 = v2 + v3
  v3 = bit.bor(bit.lshift(v3, 16), bit.rshift(v3, 48))
  v3 = bit.bxor(v3, v2)

  v0 = v0 + v3
  v3 = bit.bor(bit.lshift(v3, 21), bit.rshift(v3, 43))
  v3 = bit.bxor(v3, v0)

  v2 = v2 + v1
  v1 = bit.bor(bit.lshift(v1, 17), bit.rshift(v1, 47))
  v1 = bit.bxor(v1, v2)
  v2 = bit.bor(bit.lshift(v2, 32), bit.rshift(v2, 32))

  return v0, v1, v2, v3
end

-- Read 8 bytes as little-endian uint64
local function read_u64le(data, offset)
  local b1, b2, b3, b4, b5, b6, b7, b8 = data:byte(offset, offset + 7)
  local low = b1 + b2 * 0x100 + b3 * 0x10000 + b4 * 0x1000000
  local high = b5 + b6 * 0x100 + b7 * 0x10000 + b8 * 0x1000000
  return ffi.new("uint64_t", low) + ffi.new("uint64_t", high) * ffi.new("uint64_t", 0x100000000ULL)
end

--- SipHash-2-4 implementation for arbitrary data.
-- @param k0 cdata|number: first 64-bit key part
-- @param k1 cdata|number: second 64-bit key part
-- @param data string: data to hash
-- @return cdata: 64-bit hash result
local function siphash24(k0, k1, data)
  k0 = ffi.new("uint64_t", k0)
  k1 = ffi.new("uint64_t", k1)

  local v0 = bit.bxor(SIPHASH_C0, k0)
  local v1 = bit.bxor(SIPHASH_C1, k1)
  local v2 = bit.bxor(SIPHASH_C2, k0)
  local v3 = bit.bxor(SIPHASH_C3, k1)

  local len = #data
  local blocks = math.floor(len / 8)

  -- Process full 8-byte blocks
  for i = 0, blocks - 1 do
    local m = read_u64le(data, i * 8 + 1)
    v3 = bit.bxor(v3, m)
    v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    v0 = bit.bxor(v0, m)
  end

  -- Process remaining bytes with length encoding
  local last = ffi.new("uint64_t", len % 256) * ffi.new("uint64_t", 0x100000000000000ULL)
  local remaining = len % 8
  local offset = blocks * 8 + 1

  if remaining >= 7 then last = last + ffi.new("uint64_t", data:byte(offset + 6)) * ffi.new("uint64_t", 0x1000000000000ULL) end
  if remaining >= 6 then last = last + ffi.new("uint64_t", data:byte(offset + 5)) * ffi.new("uint64_t", 0x10000000000ULL) end
  if remaining >= 5 then last = last + ffi.new("uint64_t", data:byte(offset + 4)) * ffi.new("uint64_t", 0x100000000ULL) end
  if remaining >= 4 then last = last + ffi.new("uint64_t", data:byte(offset + 3)) * ffi.new("uint64_t", 0x1000000ULL) end
  if remaining >= 3 then last = last + ffi.new("uint64_t", data:byte(offset + 2)) * ffi.new("uint64_t", 0x10000ULL) end
  if remaining >= 2 then last = last + ffi.new("uint64_t", data:byte(offset + 1)) * ffi.new("uint64_t", 0x100ULL) end
  if remaining >= 1 then last = last + ffi.new("uint64_t", data:byte(offset)) end

  v3 = bit.bxor(v3, last)
  v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
  v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
  v0 = bit.bxor(v0, last)

  -- Finalization
  v2 = bit.bxor(v2, ffi.new("uint64_t", 0xFF))
  v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
  v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
  v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
  v0, v1, v2, v3 = sipround(v0, v1, v2, v3)

  return bit.bxor(bit.bxor(v0, v1), bit.bxor(v2, v3))
end

-- Export for use by other modules
M.siphash24 = siphash24

--- Compute a 32-bit short transaction ID for Erlay reconciliation.
-- Uses SipHash-2-4(salt, wtxid) truncated to 32 bits.
-- @param salt number|cdata: 64-bit reconciliation salt
-- @param wtxid string: 32-byte witness transaction ID
-- @return number: 32-bit short txid
function M.short_txid(salt, wtxid)
  assert(#wtxid == 32, "wtxid must be 32 bytes")

  -- Split salt into k0 and k1 (salt is single 64-bit value, use it as k0)
  local k0 = ffi.new("uint64_t", salt)
  local k1 = ffi.new("uint64_t", 0)

  local hash = siphash24(k0, k1, wtxid)

  -- Truncate to 32 bits
  return tonumber(bit.band(hash, ffi.new("uint64_t", 0xFFFFFFFFULL)))
end

--- Compute short txids for a list of wtxids.
-- @param salt number: reconciliation salt
-- @param wtxids table: list of 32-byte wtxid strings
-- @return table: list of 32-bit short txids
function M.compute_short_txids(salt, wtxids)
  local short_ids = {}
  for i, wtxid in ipairs(wtxids) do
    short_ids[i] = M.short_txid(salt, wtxid)
  end
  return short_ids
end

--------------------------------------------------------------------------------
-- Reconciliation Set Management
--------------------------------------------------------------------------------

--- Create a reconciliation set for tracking announced transactions.
-- @return table: reconciliation set object
function M.new_recon_set()
  return {
    -- Map from short_txid -> wtxid (for our transactions)
    short_to_wtxid = {},
    -- Map from wtxid -> short_txid
    wtxid_to_short = {},
    -- Salt used for this reconciliation
    salt = 0,
  }
end

--- Add a transaction to the reconciliation set.
-- @param recon_set table: reconciliation set
-- @param salt number: current salt
-- @param wtxid string: 32-byte wtxid
function M.add_to_recon_set(recon_set, salt, wtxid)
  -- Update salt if needed
  if recon_set.salt ~= salt then
    -- Salt changed, need to recompute all short txids
    local old_wtxids = {}
    for wid, _ in pairs(recon_set.wtxid_to_short) do
      old_wtxids[#old_wtxids + 1] = wid
    end
    recon_set.short_to_wtxid = {}
    recon_set.wtxid_to_short = {}
    recon_set.salt = salt
    for _, wid in ipairs(old_wtxids) do
      local short = M.short_txid(salt, wid)
      recon_set.short_to_wtxid[short] = wid
      recon_set.wtxid_to_short[wid] = short
    end
  end

  local short = M.short_txid(salt, wtxid)
  recon_set.short_to_wtxid[short] = wtxid
  recon_set.wtxid_to_short[wtxid] = short
end

--- Remove a transaction from the reconciliation set.
-- @param recon_set table: reconciliation set
-- @param wtxid string: 32-byte wtxid
function M.remove_from_recon_set(recon_set, wtxid)
  local short = recon_set.wtxid_to_short[wtxid]
  if short then
    recon_set.short_to_wtxid[short] = nil
    recon_set.wtxid_to_short[wtxid] = nil
  end
end

--- Get all short txids in the reconciliation set.
-- @param recon_set table: reconciliation set
-- @return table: list of short txids
function M.get_short_txids(recon_set)
  local result = {}
  for short, _ in pairs(recon_set.short_to_wtxid) do
    result[#result + 1] = short
  end
  return result
end

--------------------------------------------------------------------------------
-- Sketch Building and Reconciliation
--------------------------------------------------------------------------------

--- Build a minisketch from a set of short txids.
-- @param short_txids table: list of 32-bit short txids
-- @param capacity number: sketch capacity (optional)
-- @return Minisketch: sketch containing the short txids
function M.build_sketch(short_txids, capacity)
  capacity = capacity or M.DEFAULT_CAPACITY
  local sketch = minisketch.new(M.FIELD_BITS, capacity)
  for _, short_id in ipairs(short_txids) do
    if short_id ~= 0 then  -- 0 is not a valid element
      sketch:add(short_id)
    end
  end
  return sketch
end

--- Estimate the required sketch capacity based on set sizes.
-- Uses BIP330 formula: capacity = |local| + |remote|*q + sqrt(|local|)*q_factor
-- @param local_count number: size of our set
-- @param remote_count_estimate number: estimated size of remote set (optional)
-- @return number: recommended capacity
function M.estimate_capacity(local_count, remote_count_estimate)
  remote_count_estimate = remote_count_estimate or local_count
  -- Simple estimate: expect about Q% difference
  local expected_diff = math.max(local_count, remote_count_estimate) * M.Q
  -- Add safety margin
  return math.max(10, math.ceil(expected_diff * 2))
end

--- Handle sketch reconciliation.
-- Merges remote sketch with local sketch and decodes differences.
-- @param remote_sketch_bytes string: serialized remote sketch
-- @param local_txids table: list of our short txids
-- @param capacity number: sketch capacity
-- @return table|nil, table|nil: {have, want} sets, or nil on decode failure
function M.reconcile_sketches(remote_sketch_bytes, local_txids, capacity)
  capacity = capacity or M.DEFAULT_CAPACITY

  -- Build local sketch
  local local_sketch = M.build_sketch(local_txids, capacity)

  -- Create and deserialize remote sketch
  local remote_sketch = minisketch.new(M.FIELD_BITS, capacity)
  remote_sketch:deserialize(remote_sketch_bytes)

  -- Merge (XOR) to get symmetric difference
  local_sketch:merge(remote_sketch)

  -- Decode differences
  local differences, err = local_sketch:decode(capacity)

  -- Clean up
  local_sketch:destroy()
  remote_sketch:destroy()

  if not differences then
    return nil, nil, err
  end

  -- Partition differences into "have" (in our set) and "want" (not in our set)
  local local_set = {}
  for _, short in ipairs(local_txids) do
    local_set[short] = true
  end

  local have = {}  -- We have these, remote doesn't
  local want = {}  -- Remote has these, we don't

  for _, diff in ipairs(differences) do
    if local_set[diff] then
      have[#have + 1] = diff
    else
      want[#want + 1] = diff
    end
  end

  return have, want
end

--------------------------------------------------------------------------------
-- Message Serialization (BIP330)
--------------------------------------------------------------------------------

--- Serialize a SENDTXRCNCL message.
-- Sent during handshake to negotiate Erlay support.
-- @param version number: Erlay version (currently 1)
-- @param salt number: 64-bit reconciliation salt
-- @return string: serialized message payload
function M.serialize_sendtxrcncl(version, salt)
  local w = serialize.buffer_writer()
  w.write_u32le(version)
  w.write_u64le(salt)
  return w.result()
end

--- Deserialize a SENDTXRCNCL message.
-- @param data string: message payload
-- @return table: {version, salt}
function M.deserialize_sendtxrcncl(data)
  local r = serialize.buffer_reader(data)
  return {
    version = r.read_u32le(),
    salt = r.read_u64le(),
  }
end

--- Serialize a REQRECON message (request reconciliation).
-- @param set_size number: size of our reconciliation set for this peer
-- @param q number: difference coefficient (scaled by 2^16)
-- @return string: serialized message payload
function M.serialize_reqrecon(set_size, q)
  local w = serialize.buffer_writer()
  w.write_varint(set_size)
  w.write_u16le(math.floor(q * 65536))  -- Q scaled to uint16
  return w.result()
end

--- Deserialize a REQRECON message.
-- @param data string: message payload
-- @return table: {set_size, q}
function M.deserialize_reqrecon(data)
  local r = serialize.buffer_reader(data)
  return {
    set_size = r.read_varint(),
    q = r.read_u16le() / 65536,
  }
end

--- Serialize a SKETCH message.
-- @param sketch_bytes string: serialized minisketch
-- @return string: serialized message payload
function M.serialize_sketch(sketch_bytes)
  local w = serialize.buffer_writer()
  w.write_varint(#sketch_bytes)
  w.write_bytes(sketch_bytes)
  return w.result()
end

--- Deserialize a SKETCH message.
-- @param data string: message payload
-- @return string: sketch bytes
function M.deserialize_sketch(data)
  local r = serialize.buffer_reader(data)
  local len = r.read_varint()
  return r.read_bytes(len)
end

--- Serialize a RECONCILDIFF message.
-- Sent after reconciliation to request missing transactions.
-- @param success boolean: whether reconciliation succeeded
-- @param want_txids table: list of wtxids we want (only if success=true)
-- @return string: serialized message payload
function M.serialize_reconcildiff(success, want_txids)
  local w = serialize.buffer_writer()
  w.write_u8(success and 1 or 0)
  if success then
    w.write_varint(#want_txids)
    for _, wtxid in ipairs(want_txids) do
      w.write_bytes(wtxid)
    end
  end
  return w.result()
end

--- Deserialize a RECONCILDIFF message.
-- @param data string: message payload
-- @return table: {success, want_txids}
function M.deserialize_reconcildiff(data)
  local r = serialize.buffer_reader(data)
  local success = r.read_u8() == 1
  local want_txids = {}
  if success then
    local count = r.read_varint()
    for i = 1, count do
      want_txids[i] = r.read_bytes(32)
    end
  end
  return {
    success = success,
    want_txids = want_txids,
  }
end

--------------------------------------------------------------------------------
-- Peer State for Erlay
--------------------------------------------------------------------------------

--- Create Erlay state for a peer.
-- @return table: peer Erlay state
function M.new_peer_state()
  return {
    -- Whether Erlay was negotiated with this peer
    erlay_enabled = false,
    -- Our salt (sent in our SENDTXRCNCL)
    our_salt = 0,
    -- Their salt (received in their SENDTXRCNCL)
    their_salt = 0,
    -- Combined salt for this connection
    combined_salt = 0,
    -- Version negotiated
    version = 0,
    -- Whether we initiated the connection (affects reconciliation role)
    is_initiator = false,
    -- Transactions to announce via reconciliation (not yet reconciled)
    pending_recon = M.new_recon_set(),
    -- Time of last reconciliation
    last_recon_time = 0,
    -- Whether we're waiting for a reconciliation response
    recon_pending = false,
  }
end

--- Negotiate Erlay with a peer.
-- Called after receiving their SENDTXRCNCL.
-- @param state table: peer Erlay state
-- @param their_version number: their Erlay version
-- @param their_salt number: their salt
-- @param our_salt number: our salt
-- @param is_initiator boolean: whether we initiated the connection
function M.negotiate(state, their_version, their_salt, our_salt, is_initiator)
  state.erlay_enabled = true
  state.version = math.min(their_version, M.VERSION)
  state.their_salt = their_salt
  state.our_salt = our_salt
  state.is_initiator = is_initiator

  -- Combined salt: XOR of both salts, ensures both parties contribute
  state.combined_salt = bit.bxor(
    tonumber(bit.band(their_salt, 0xFFFFFFFF)),
    tonumber(bit.band(our_salt, 0xFFFFFFFF))
  )
end

--- Check if it's time to initiate reconciliation.
-- Only the outbound peer initiates reconciliation.
-- @param state table: peer Erlay state
-- @param now number: current time
-- @return boolean: true if should initiate
function M.should_reconcile(state, now)
  if not state.erlay_enabled then
    return false
  end
  if not state.is_initiator then
    return false  -- Only outbound peers initiate
  end
  if state.recon_pending then
    return false  -- Already waiting for response
  end
  if now - state.last_recon_time < M.RECON_INTERVAL then
    return false  -- Too soon
  end
  return true
end

--- Initiate reconciliation with a peer.
-- Builds a sketch and returns the serialized bytes to send.
-- @param state table: peer Erlay state
-- @param local_txids table: list of wtxids to reconcile
-- @return string: serialized sketch to send
-- @return number: capacity used
function M.initiate_reconciliation(state, local_txids)
  -- Compute short txids
  local short_ids = M.compute_short_txids(state.combined_salt, local_txids)

  -- Estimate capacity
  local capacity = M.estimate_capacity(#local_txids)

  -- Build sketch
  local sketch = M.build_sketch(short_ids, capacity)
  local sketch_bytes = sketch:serialize()
  sketch:destroy()

  state.recon_pending = true

  return sketch_bytes, capacity
end

--- Handle incoming sketch from peer.
-- @param state table: peer Erlay state
-- @param sketch_bytes string: serialized remote sketch
-- @param local_txids table: list of our wtxids
-- @param capacity number: sketch capacity
-- @return table|nil, table|nil: have (they want), want (we want), or nil on failure
function M.handle_sketch(state, sketch_bytes, local_txids, capacity)
  -- Compute our short txids
  local local_shorts = M.compute_short_txids(state.combined_salt, local_txids)

  -- Build map from short -> wtxid
  local short_to_wtxid = {}
  for i, wtxid in ipairs(local_txids) do
    short_to_wtxid[local_shorts[i]] = wtxid
  end

  -- Reconcile
  local have, want, err = M.reconcile_sketches(sketch_bytes, local_shorts, capacity)

  if not have then
    return nil, nil, err
  end

  -- Convert short txids back to wtxids for "have"
  local have_wtxids = {}
  for _, short in ipairs(have) do
    local wtxid = short_to_wtxid[short]
    if wtxid then
      have_wtxids[#have_wtxids + 1] = wtxid
    end
  end

  -- "want" contains short txids we don't have - peer needs to send us these
  return have_wtxids, want
end

--- Handle reconciliation diff response.
-- Called after receiving RECONCILDIFF from peer.
-- @param state table: peer Erlay state
-- @param success boolean: whether reconciliation succeeded
-- @param missing_short_ids table: short txids the peer wants from us
function M.handle_reconcildiff(state, success, missing_short_ids)
  state.recon_pending = false
  state.last_recon_time = os.time()
  return success, missing_short_ids
end

--- Generate a random 64-bit salt.
-- @return number: random salt (as Lua number, loses some precision)
function M.generate_salt()
  local bytes = crypto.random_bytes(8)
  local b1, b2, b3, b4, b5, b6, b7 = bytes:byte(1, 7)
  -- Only use 52 bits to stay within Lua number precision
  return b1 + b2 * 0x100 + b3 * 0x10000 + b4 * 0x1000000 +
         b5 * 0x100000000 + b6 * 0x10000000000 + b7 * 0x1000000000000
end

return M
