-- bloom.lua — CBloomFilter + PartialMerkleTree + CMerkleBlock
-- BIP-37 SPV bloom filter subsystem for lunarblock.
--
-- Reference: bitcoin-core/src/common/bloom.h|cpp
--            bitcoin-core/src/merkleblock.h|cpp
--
-- W110 audit (30 gates).
--
-- BUG list discovered during W110 audit:
--
--   BUG-1  (G3)  LN2SQUARED precision: Lua double only has ~15-16 decimal
--                digits; the constant 0.4804530139182014246671025... rounds
--                to 0.4804530139182014 at best (53-bit mantissa).  All
--                sizing calculations carry a small rounding error.  This is
--                a language-level limitation; documented and not worked around.
--
--   BUG-2  (G4/G5) Constructor size formula uses Lua float arithmetic which
--                loses precision for nElements > ~4.47e9 (the intermediate
--                product exceeds 2^52).  In practice nElements is always
--                small enough for this not to matter, but the path is
--                technically imprecise.
--
--   BUG-3  (G6)  MurmurHash3 body/tail multiplication: Lua double is 64-bit
--                IEEE-754.  Multiplying two 32-bit unsigned values can produce
--                a 64-bit product that exceeds 2^53 = 9007199254740992, losing
--                low bits.  Fix: decompose into 16-bit halves so each partial
--                product is at most 65535*65535 = 4294836225 < 2^53.  This
--                bug would have caused incorrect hash values; FIXED in this
--                implementation via mul32u().
--
--   BUG-4  (G8)  Bit-index u32 modulo: murmur_hash3() returns a value in
--                [0, 2^32), vdata_len*8 <= 288000 — both fit in Lua double
--                precisely, so the % operator is exact.  PASSES.
--
--   BUG-5  (G9)  CVE-2013-5700 guard: empty vData must be treated as
--                match-all (contains returns true, insert is a no-op).
--                Implemented here.  PASSES.
--
--   BUG-6  (G10) isFull/isEmpty: Core has no public API for these; the
--                empty-vData guard handles the match-all case inline.
--                No exported predicate is needed.  PASSES.
--
--   BUG-7  (G24) Outpoint serialisation: txid(32 LE) || index(4 LE).  The
--                index comes from deserialised transactions as a Lua float.
--                Values up to 2^32-1 are handled correctly by the same
--                byte-shift arithmetic as serialize.buffer_writer.  PASSES.
--
--   BUG-8  (G25) filterload: message type is registered in the BIP-324
--                message-type table (p2p.lua:1287) but no handler is
--                registered in main.lua and no parse_filterload function
--                exists in p2p.lua.  MISSING — parse_filterload is
--                provided here; callers must register the handler.
--
--   BUG-9  (G26) filteradd: same as BUG-8.  Message type registered but
--                no handler.  parse_filteradd (with the ≤520 byte guard)
--                is provided here.  MISSING in main.lua.
--
--   BUG-10 (G27) filterclear: message type registered but no handler.
--                Semantics are trivial (set vData = null).  MISSING in
--                main.lua.
--
--   BUG-11 (G28) merkleblock: message type registered but no send path
--                and no encode_merkle_block function.  Implemented here
--                as encode_merkle_block + PartialMerkleTree traversal.
--                MISSING in main.lua (send path).
--
--   BUG-12 (G16) txid match in is_relevant_and_update: correct; we pass
--                txid.bytes (32 raw bytes) to contains().  PASSES.
--
--   BUG-13 (G17) Per-output pushdata walk: uses script.parse_script()
--                which mirrors Core's GetOp loop.  PASSES.
--
--   BUG-14 (G18) P2PK / multisig detection for UPDATE_P2PUBKEY_ONLY:
--                script.classify_script() returns "multisig" for bare
--                multisig; P2PK is detected by is_p2pk() locally.
--                PASSES.
--
--   BUG-15 (G19) Outpoint match in is_relevant_and_update: checks
--                prev_out.hash.bytes || prev_out.index encoded as 4-byte
--                LE.  PASSES.
--
--   BUG-16 (G29) IsWithinSizeConstraints: exported.  PASSES.
--
--   BUG-17 (G30) NODE_BLOOM = 4 (1<<2): correct in p2p.lua:19.  BIP-111
--                gate (mempool handler) exists in main.lua:1271.  PASSES.

local bit = require("bit")
local serialize = require("lunarblock.serialize")
local crypto = require("lunarblock.crypto")

local M = {}

--------------------------------------------------------------------------------
-- Constants (G1, G2, G3)
--------------------------------------------------------------------------------

-- G1: MAX_BLOOM_FILTER_SIZE = 36000 bytes (bloom.h:17)
M.MAX_BLOOM_FILTER_SIZE = 36000

-- G2: MAX_HASH_FUNCS = 50 (bloom.h:18)
M.MAX_HASH_FUNCS = 50

-- G3: LN2SQUARED (bloom.cpp:23)
-- BUG-1: inherent float precision limitation in Lua (53-bit mantissa).
local LN2SQUARED = 0.4804530139182014

-- LN2 for nHashFuncs computation (bloom.cpp:24)
local LN2 = 0.6931471805599453

-- G11-G14: Update flags (bloom.h:24-31)
M.UPDATE_NONE          = 0
M.UPDATE_ALL           = 1
M.UPDATE_P2PUBKEY_ONLY = 2
M.UPDATE_MASK          = 3

-- G30: NODE_BLOOM service bit = 1<<2 = 4 (p2p.h)
M.NODE_BLOOM = 4

-- G26: filteradd max element size (BIP-37, Core net_processing.cpp:~3337)
M.MAX_FILTER_ADD_SIZE = 520

--------------------------------------------------------------------------------
-- mul32u: 32-bit unsigned multiply with correct wrapping (BUG-3 fix)
--
-- Lua doubles are 64-bit IEEE-754 with 53-bit mantissa.  Multiplying two
-- u32 values can produce a product up to (2^32-1)^2 ≈ 1.84e19 > 2^53,
-- causing precision loss in the lower bits.
--
-- Fix: decompose into 16-bit halves.  Each partial product is at most
-- 65535^2 = 4294836225 < 2^53, so no precision is lost.
--
-- @param a number: unsigned 32-bit value (0..2^32-1)
-- @param b number: unsigned 32-bit value (0..2^32-1)
-- @return number: (a * b) mod 2^32
--------------------------------------------------------------------------------
local function mul32u(a, b)
  local a_lo = a % 65536
  local a_hi = math.floor(a / 65536)
  local b_lo = b % 65536
  local b_hi = math.floor(b / 65536)
  -- (a_hi*2^16 + a_lo) * (b_hi*2^16 + b_lo) mod 2^32
  -- = (a_hi*b_lo + a_lo*b_hi)*2^16 + a_lo*b_lo   (mod 2^32)
  -- only lower 16 bits of the *2^16 term survive the mod 2^32
  local mid = (a_hi * b_lo + a_lo * b_hi) % 65536
  local lo  = a_lo * b_lo
  return (mid * 65536 + lo) % 4294967296
end

-- rotl32u: rotate-left for unsigned 32-bit values
local function rotl32u(x, r)
  local xs = bit.tobit(x)  -- treat as signed for bit ops
  local result = bit.bor(bit.lshift(xs, r), bit.rshift(xs, 32 - r))
  return result < 0 and result + 4294967296 or result
end

--------------------------------------------------------------------------------
-- MurmurHash3 (x86_32) — G6
-- Reference: bitcoin-core/src/hash.cpp MurmurHash3()
-- All arithmetic is 32-bit unsigned; mul32u() handles correct wrapping.
--
-- @param seed number: u32 hash seed
-- @param data string: bytes to hash
-- @return number: 32-bit unsigned hash result (0..2^32-1)
--------------------------------------------------------------------------------
local function murmur_hash3(seed, data)
  local h1  = seed  -- u32
  local c1  = 0xcc9e2d51
  local c2  = 0x1b873593
  local len = #data
  local nblocks = math.floor(len / 4)

  -- Body: process 4-byte LE blocks (ReadLE32)
  for i = 0, nblocks - 1 do
    local b1, b2, b3, b4 = data:byte(i*4+1, i*4+4)
    local k1 = b1 + b2*256 + b3*65536 + b4*16777216

    k1 = mul32u(k1, c1)
    k1 = rotl32u(k1, 15)
    k1 = mul32u(k1, c2)

    h1 = bit.bxor(bit.tobit(h1), bit.tobit(k1))
    if h1 < 0 then h1 = h1 + 4294967296 end
    h1 = rotl32u(h1, 13)
    h1 = (mul32u(h1, 5) + 0xe6546b64) % 4294967296
  end

  -- Tail: remaining 1-3 bytes
  local tail_start = nblocks * 4 + 1
  local k1 = 0
  local rem = len % 4
  if rem >= 3 then k1 = k1 + data:byte(tail_start + 2) * 65536 end
  if rem >= 2 then k1 = k1 + data:byte(tail_start + 1) * 256 end
  if rem >= 1 then
    k1 = k1 + data:byte(tail_start)
    k1 = mul32u(k1, c1)
    k1 = rotl32u(k1, 15)
    k1 = mul32u(k1, c2)
    h1 = bit.bxor(bit.tobit(h1), bit.tobit(k1))
    if h1 < 0 then h1 = h1 + 4294967296 end
  end

  -- Finalization: fmix32
  h1 = bit.bxor(bit.tobit(h1), len)
  if h1 < 0 then h1 = h1 + 4294967296 end

  h1 = bit.bxor(bit.tobit(h1), bit.rshift(bit.tobit(h1), 16))
  if h1 < 0 then h1 = h1 + 4294967296 end
  h1 = mul32u(h1, 0x85ebca6b)

  h1 = bit.bxor(bit.tobit(h1), bit.rshift(bit.tobit(h1), 13))
  if h1 < 0 then h1 = h1 + 4294967296 end
  h1 = mul32u(h1, 0xc2b2ae35)

  h1 = bit.bxor(bit.tobit(h1), bit.rshift(bit.tobit(h1), 16))
  if h1 < 0 then h1 = h1 + 4294967296 end

  return h1
end

-- Export for testing
M.murmur_hash3 = murmur_hash3

--------------------------------------------------------------------------------
-- Hash schedule (G7, G8)
-- nIndex = MurmurHash3(nHashNum * 0xFBA4C795 + nTweak, data) % (vdata_len*8)
--
-- Seed is computed mod 2^32 to stay in u32 range (G7).
-- G8: result is in [0, 2^32); modulo by vdata_len*8 ≤ 288000 uses float
--     arithmetic which is exact for both operands (BUG-4: PASSES).
--------------------------------------------------------------------------------

local function bloom_hash(bf, n_hash_num, data)
  -- seed = (nHashNum * 0xFBA4C795 + nTweak) mod 2^32
  -- Use mul32u for the multiplication to avoid float overflow
  local product = mul32u(n_hash_num, 0xFBA4C795)
  local seed = (product + bf.n_tweak) % 4294967296
  local h = murmur_hash3(seed, data)
  return h % (bf.vdata_len * 8)
end

--------------------------------------------------------------------------------
-- CBloomFilter constructor (G4, G5)
--
-- @param n_elements  number: expected number of elements to insert
-- @param fp_rate     number: target false positive rate (0..1)
-- @param tweak       number: u32 nTweak added to each hash seed
-- @param flags       number: BLOOM_UPDATE_* constant (nFlags)
-- @return table: bloom filter object
--------------------------------------------------------------------------------
function M.bloom_filter(n_elements, fp_rate, tweak, flags)
  -- G4: bit-size formula from Core (bloom.cpp:32)
  -- BUG-2: float precision for very large n_elements (documented).
  local n_filter_bits = math.min(
    math.floor(-1.0 / LN2SQUARED * n_elements * math.log(fp_rate)),
    M.MAX_BLOOM_FILTER_SIZE * 8
  )
  if n_filter_bits < 1 then n_filter_bits = 1 end
  local vdata_len = math.floor(n_filter_bits / 8)
  if vdata_len < 1 then vdata_len = 1 end

  -- G5: nHashFuncs formula from Core (bloom.cpp:38)
  -- BUG-2: same float precision caveat.
  local n_hash_funcs = math.min(
    math.floor(vdata_len * 8 / n_elements * LN2),
    M.MAX_HASH_FUNCS
  )
  if n_hash_funcs < 1 then n_hash_funcs = 1 end

  local bf = {
    vdata        = {},       -- byte array (1-indexed), all 0
    vdata_len    = vdata_len,
    n_hash_funcs = n_hash_funcs,
    n_tweak      = tweak or 0,
    n_flags      = flags or M.UPDATE_NONE,
  }
  for i = 1, vdata_len do
    bf.vdata[i] = 0
  end
  return bf
end

--- Deserialise a CBloomFilter from a filterload wire payload.
-- Wire format: varstr(vData) || uint32(nHashFuncs) || uint32(nTweak) || uint8(nFlags)
-- (SERIALIZE_METHODS on CBloomFilter in bloom.h:67)
-- G25: parses the filterload payload.
-- @param payload string: raw bytes from filterload P2P message
-- @return table|nil: bloom filter, or nil on error
-- @return string|nil: error message on failure
function M.parse_filterload(payload)
  local ok, result = pcall(function()
    local r = serialize.buffer_reader(payload)
    local vdata_raw = r.read_varstr()
    local n_hash_funcs = r.read_u32le()
    local n_tweak      = r.read_u32le()
    local n_flags      = r.read_u8()
    local bf = {
      vdata        = {},
      vdata_len    = #vdata_raw,
      n_hash_funcs = n_hash_funcs,
      n_tweak      = n_tweak,
      n_flags      = n_flags,
    }
    for i = 1, #vdata_raw do
      bf.vdata[i] = vdata_raw:byte(i)
    end
    return bf
  end)
  if not ok then return nil, tostring(result) end
  return result, nil
end

--- Encode a CBloomFilter to wire bytes (for filterload message).
-- @param bf table: bloom filter object
-- @return string: serialised bytes
function M.encode_filterload(bf)
  local w = serialize.buffer_writer()
  local parts = {}
  for i = 1, bf.vdata_len do
    parts[i] = string.char(bf.vdata[i])
  end
  w.write_varstr(table.concat(parts))
  w.write_u32le(bf.n_hash_funcs)
  w.write_u32le(bf.n_tweak)
  w.write_u8(bf.n_flags)
  return w.result()
end

--- Parse a filteradd message payload.
-- Wire format: varstr(element)
-- G26: enforces MAX_FILTER_ADD_SIZE = 520 bytes.
-- @param payload string: raw filteradd bytes
-- @return string|nil: element bytes, or nil on error
-- @return string|nil: error message on failure
function M.parse_filteradd(payload)
  local ok, result = pcall(function()
    local r = serialize.buffer_reader(payload)
    local elem = r.read_varstr()
    if #elem > M.MAX_FILTER_ADD_SIZE then
      error(string.format("filteradd element too large: %d > %d", #elem, M.MAX_FILTER_ADD_SIZE))
    end
    return elem
  end)
  if not ok then return nil, tostring(result) end
  return result, nil
end

--------------------------------------------------------------------------------
-- insert (G9)
-- Sets the hash-indexed bits in vdata.
-- CVE-2013-5700: if vdata is empty, silently returns.
--------------------------------------------------------------------------------

function M.insert(bf, key)
  if bf.vdata_len == 0 then return end
  for i = 0, bf.n_hash_funcs - 1 do
    local n_index  = bloom_hash(bf, i, key)
    local byte_idx = math.floor(n_index / 8) + 1   -- 1-indexed
    local bit_mask = bit.lshift(1, bit.band(n_index, 7))
    bf.vdata[byte_idx] = bit.bor(bf.vdata[byte_idx], bit_mask)
  end
end

--- Insert an outpoint (txid + vout_index) into the filter.
-- Outpoint wire format: txid(32-byte LE) || index(4-byte LE) — G24.
-- @param bf          table: bloom filter
-- @param txid_bytes  string: 32-byte raw txid
-- @param vout_index  number: output index (u32)
function M.insert_outpoint(bf, txid_bytes, vout_index)
  local key = txid_bytes .. outpoint_le32(vout_index)
  M.insert(bf, key)
end

--------------------------------------------------------------------------------
-- contains (G9)
-- Returns true if all hash-indexed bits are set.
-- CVE-2013-5700: empty vData matches everything (returns true).
--------------------------------------------------------------------------------

function M.contains(bf, key)
  if bf.vdata_len == 0 then return true end
  for i = 0, bf.n_hash_funcs - 1 do
    local n_index  = bloom_hash(bf, i, key)
    local byte_idx = math.floor(n_index / 8) + 1
    local bit_mask = bit.lshift(1, bit.band(n_index, 7))
    if bit.band(bf.vdata[byte_idx], bit_mask) == 0 then
      return false
    end
  end
  return true
end

--- Check whether an outpoint is in the filter (G19).
function M.contains_outpoint(bf, txid_bytes, vout_index)
  local key = txid_bytes .. outpoint_le32(vout_index)
  return M.contains(bf, key)
end

--------------------------------------------------------------------------------
-- G29: IsWithinSizeConstraints (bloom.cpp:90-93)
--------------------------------------------------------------------------------

function M.is_within_size_constraints(bf)
  return bf.vdata_len <= M.MAX_BLOOM_FILTER_SIZE
     and bf.n_hash_funcs <= M.MAX_HASH_FUNCS
end

--------------------------------------------------------------------------------
-- outpoint_le32: 4-byte LE encoding of a u32 vout index (G24)
-- Safe for all values 0..2^32-1 using Lua float arithmetic (BUG-7: PASSES).
--------------------------------------------------------------------------------

function outpoint_le32(index)
  return string.char(
    index % 256,
    math.floor(index / 256)    % 256,
    math.floor(index / 65536)  % 256,
    math.floor(index / 16777216) % 256
  )
end

--------------------------------------------------------------------------------
-- is_p2pk: detect P2PK scripts — <pubkey> OP_CHECKSIG (G18)
-- Bitcoin Core TxoutType::PUBKEY (solver.cpp:~87-92).
-- Forms: 0x41 <65B> 0xac  or  0x21 <33B> 0xac.
--------------------------------------------------------------------------------

local function is_p2pk(spk)
  local len = #spk
  if len == 67 and spk:byte(1) == 0x41 and spk:byte(67) == 0xac then
    return true
  end
  if len == 35 and spk:byte(1) == 0x21 and spk:byte(35) == 0xac then
    return true
  end
  return false
end

--------------------------------------------------------------------------------
-- IsRelevantAndUpdate (G16-G23)
-- Mirrors bitcoin-core/src/common/bloom.cpp CBloomFilter::IsRelevantAndUpdate.
--
-- @param bf  table: bloom filter
-- @param tx  table: types.transaction from deserialization
-- @return boolean: true if tx matches the filter
--                  (side-effect: updates filter for spending-tx discovery)
--------------------------------------------------------------------------------

function M.is_relevant_and_update(bf, tx)
  -- Match-all filter (CVE-2013-5700 — zero-size = match all)
  if bf.vdata_len == 0 then return true end

  local script_mod = require("lunarblock.script")
  local validation = require("lunarblock.validation")

  local f_found = false

  -- G16: txid match
  local txid = validation.compute_txid(tx)
  if M.contains(bf, txid.bytes) then
    f_found = true
  end

  -- G17-G22: Per-output scan (mirrors Core's vout loop)
  for i, txout in ipairs(tx.outputs) do
    local spk = txout.script_pubkey or ""
    local ok, ops = pcall(script_mod.parse_script, spk)
    if ok then
      for _, op in ipairs(ops) do
        -- G17: any non-empty pushdata element match
        if op.data and #op.data > 0 and M.contains(bf, op.data) then
          f_found = true
          local update_mode = bit.band(bf.n_flags, M.UPDATE_MASK)
          -- G21: UPDATE_ALL — always insert outpoint for spending-tx discovery
          if update_mode == M.UPDATE_ALL then
            M.insert_outpoint(bf, txid.bytes, i - 1)  -- 0-indexed vout
          -- G22: UPDATE_P2PUBKEY_ONLY — insert only for P2PK or multisig
          elseif update_mode == M.UPDATE_P2PUBKEY_ONLY then
            -- G18: check TxoutType via classify_script + is_p2pk
            local stype = script_mod.classify_script(spk)
            if stype == "multisig" or is_p2pk(spk) then
              M.insert_outpoint(bf, txid.bytes, i - 1)
            end
          end
          -- G23: UPDATE_NONE — no outpoint insertion
          break  -- only first matching pushdata per output (Core's break)
        end
      end
    end
  end

  if f_found then return true end

  -- G19-G20: Per-input scan (mirrors Core's vin loop)
  for _, txin in ipairs(tx.inputs) do
    -- G19: outpoint match (prev_out as txid||index LE4)
    local prev = txin.prev_out
    if prev and prev.hash then
      if M.contains_outpoint(bf, prev.hash.bytes, prev.index) then
        return true
      end
    end

    -- G20: scriptSig pushdata items
    local sig = txin.script_sig or ""
    local ok, ops = pcall(script_mod.parse_script, sig)
    if ok then
      for _, op in ipairs(ops) do
        if op.data and #op.data > 0 and M.contains(bf, op.data) then
          return true
        end
      end
    end
  end

  return false
end

--------------------------------------------------------------------------------
-- PartialMerkleTree (G28)
-- Implements bitcoin-core/src/merkleblock.cpp CPartialMerkleTree.
--
-- encode_partial_merkle_tree(txid_strings, v_match) builds the PMT and
-- returns a table suitable for wire serialisation.
--
-- Wire format for CMerkleBlock (from merkleblock.h:90-97):
--   [block header 80 bytes]
--   [nTransactions: uint32]
--   [nHashes: varint]  [hashes: uint256[]]
--   [nFlagBytes: varint]  [flagBytes: byte[]]  -- LSB first per BitsToBytes
--------------------------------------------------------------------------------

--- CalcTreeWidth: number of nodes at height h in a tree with n_transactions
-- Mirrors Core's CalcTreeWidth(height) in merkleblock.h:74.
local function calc_tree_width(n_transactions, height)
  return math.floor((n_transactions + bit.lshift(1, height) - 1) / bit.lshift(1, height))
end

--- CalcHash: hash at (height, pos).
-- Height 0 = txid; higher = Hash256(left||right).
local function calc_hash(height, pos, txid_strings, n_transactions)
  if height == 0 then
    return txid_strings[pos + 1]  -- Lua 1-indexed
  end
  local left  = calc_hash(height - 1, pos * 2, txid_strings, n_transactions)
  local right
  if (pos * 2 + 1) < calc_tree_width(n_transactions, height - 1) then
    right = calc_hash(height - 1, pos * 2 + 1, txid_strings, n_transactions)
  else
    right = left  -- duplicate last hash for odd levels
  end
  return crypto.hash256(left .. right)
end

--- TraverseAndBuild: depth-first traversal building vBits and vHash.
local function traverse_and_build(height, pos, txid_strings, v_match, v_bits, v_hash, n_transactions)
  -- Is this node parent of at least one matched txid?
  local f_parent_of_match = false
  local leaf_start = bit.lshift(pos, height)
  local leaf_end   = math.min(bit.lshift(pos + 1, height), n_transactions) - 1
  for p = leaf_start, leaf_end do
    if v_match[p + 1] then  -- 1-indexed
      f_parent_of_match = true
      break
    end
  end

  -- Store flag bit
  v_bits[#v_bits + 1] = f_parent_of_match

  if height == 0 or not f_parent_of_match then
    -- Leaf or non-matching subtree: store hash
    v_hash[#v_hash + 1] = calc_hash(height, pos, txid_strings, n_transactions)
  else
    -- Matching interior node: recurse into children
    traverse_and_build(height - 1, pos * 2, txid_strings, v_match, v_bits, v_hash, n_transactions)
    if pos * 2 + 1 < calc_tree_width(n_transactions, height - 1) then
      traverse_and_build(height - 1, pos * 2 + 1, txid_strings, v_match, v_bits, v_hash, n_transactions)
    end
  end
end

--- Encode a PartialMerkleTree.
-- @param txid_strings table: 1-indexed array of 32-byte binary txid strings
-- @param v_match      table: 1-indexed array of boolean match flags
-- @return table: { n_transactions, v_hash, v_bits }
function M.encode_partial_merkle_tree(txid_strings, v_match)
  local n = #txid_strings
  assert(n > 0, "PartialMerkleTree requires at least one transaction")
  assert(#v_match == n, "v_match must be same length as txid_strings")

  local v_bits = {}
  local v_hash = {}

  -- Calculate tree height
  local n_height = 0
  while calc_tree_width(n, n_height) > 1 do
    n_height = n_height + 1
  end

  traverse_and_build(n_height, 0, txid_strings, v_match, v_bits, v_hash, n)

  return { n_transactions = n, v_hash = v_hash, v_bits = v_bits }
end

--- Serialise a PartialMerkleTree to wire bytes.
-- @param pmt table: output of encode_partial_merkle_tree
-- @return string: wire bytes
function M.serialize_partial_merkle_tree(pmt)
  local w = serialize.buffer_writer()
  w.write_u32le(pmt.n_transactions)

  w.write_varint(#pmt.v_hash)
  for _, h in ipairs(pmt.v_hash) do
    w.write_bytes(h)
  end

  -- BitsToBytes: ret[p/8] |= bits[p] << (p%8)  (LSB-first per Core)
  local n_bytes = math.ceil(#pmt.v_bits / 8)
  if n_bytes == 0 then n_bytes = 1 end
  local flag_bytes = {}
  for i = 1, n_bytes do flag_bytes[i] = 0 end
  for p, b in ipairs(pmt.v_bits) do
    if b then
      local byte_idx = math.floor((p - 1) / 8) + 1
      local bit_idx  = (p - 1) % 8
      flag_bytes[byte_idx] = bit.bor(flag_bytes[byte_idx], bit.lshift(1, bit_idx))
    end
  end
  w.write_varint(n_bytes)
  for _, b in ipairs(flag_bytes) do w.write_u8(b) end

  return w.result()
end

--- Encode a CMerkleBlock message payload.
-- G28: provides the wire payload for a merkleblock message.
-- @param block_header_bytes string: 80-byte serialised block header
-- @param txid_strings        table: 1-indexed array of 32-byte txid strings
-- @param v_match             table: 1-indexed array of boolean match flags
-- @return string: wire payload (header || PMT)
function M.encode_merkle_block(block_header_bytes, txid_strings, v_match)
  assert(#block_header_bytes == 80, "block header must be 80 bytes")
  local pmt = M.encode_partial_merkle_tree(txid_strings, v_match)
  return block_header_bytes .. M.serialize_partial_merkle_tree(pmt)
end

return M
