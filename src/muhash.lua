-- src/muhash.lua
--
-- MuHash3072 set hash for the UTXO set, byte-compatible with
-- bitcoin-core/src/crypto/muhash.{h,cpp}.
--
-- Background
-- ----------
-- MuHash is a homomorphic set hash: H(S) = product_{x in S} ToNum3072(x)
-- mod p, where p = 2^3072 - 1103717 (the largest 3072-bit safe prime).
-- ToNum3072 expands a 32-byte SHA256(input) into a 3072-bit value via
-- a ChaCha20 keystream (RFC 8439, all-zero nonce, all-zero block counter)
-- so that the result is a uniformly distributed Num3072. Insert multiplies
-- into a numerator accumulator; Remove multiplies into a denominator
-- accumulator. Finalize computes (numerator / denominator) mod p, packs
-- the result as 384 little-endian bytes, and returns SHA256(packed).
--
-- Implementation
-- --------------
-- LuaJIT has no native bigint. Rather than hand-roll 48-limb 64-bit
-- arithmetic (which would mean reproducing safegcd inversion), this
-- module talks to OpenSSL libcrypto via FFI:
--
--   * BN_lebin2bn  — load 384 little-endian bytes -> BIGNUM
--   * BN_bn2lebinpad — pack BIGNUM -> 384 little-endian bytes
--   * BN_mod_mul   — modular multiplication
--   * BN_mod_inverse — modular inverse via extended Euclidean algorithm
--
-- The little-endian byte-pad endpoints match Core's Num3072::ToBytes /
-- Num3072(unsigned char[BYTE_SIZE]) which use ReadLE32/WriteLE32 (or
-- LE64) per limb — mathematically the value is just a 3072-bit integer
-- in little-endian byte order.
--
-- ChaCha20 keystream is provided by crypto.chacha20_crypt with a 12-byte
-- zero nonce; OpenSSL's EVP_chacha20 wraps a 16-byte IV (4-byte LE block
-- counter || 12-byte nonce), starting at counter 0 — identical to Core's
-- ChaCha20Aligned default state (chacha20.cpp SetKey + Keystream).
--
-- This is the slow path; correctness over speed. UTXO snapshot validation
-- runs Finalize once per snapshot import, so a single BN_mod_inverse is
-- fine. Per-coin Insert / Remove costs one BN_mod_mul each (microseconds).

local ffi = require("ffi")
local crypto = require("lunarblock.crypto")

local M = {}

--------------------------------------------------------------------------------
-- OpenSSL BIGNUM FFI bindings
--------------------------------------------------------------------------------

ffi.cdef[[
  typedef struct bignum_st BIGNUM;
  typedef struct bignum_ctx BN_CTX;

  BIGNUM *BN_new(void);
  void    BN_free(BIGNUM *a);
  BN_CTX *BN_CTX_new(void);
  void    BN_CTX_free(BN_CTX *ctx);

  /* Little-endian bytes <-> BIGNUM. Available in OpenSSL >= 1.1.0. */
  BIGNUM *BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);
  int     BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen);

  /* Big-endian (used only for setting the modulus from a hard-coded constant
     string if we ever needed to). */
  BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
  int     BN_bn2bin(const BIGNUM *a, unsigned char *to);
  int     BN_num_bits(const BIGNUM *a);

  /* (a * b) mod m */
  int BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                 const BIGNUM *m, BN_CTX *ctx);
  /* a^-1 mod n */
  BIGNUM *BN_mod_inverse(BIGNUM *r, const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);

  /* Used to construct the modulus 2^3072 - 1103717 from scratch. */
  int BN_set_bit(BIGNUM *a, int n);
  int BN_sub_word(BIGNUM *a, unsigned long w);
  int BN_set_word(BIGNUM *a, unsigned long w);
  int BN_copy(BIGNUM *to, const BIGNUM *from);
  int BN_cmp(const BIGNUM *a, const BIGNUM *b);
]]

local libcrypto = ffi.load("crypto")

--------------------------------------------------------------------------------
-- Constants
--------------------------------------------------------------------------------

-- 2^3072 - 1103717. See bitcoin-core/src/crypto/muhash.cpp MAX_PRIME_DIFF.
local MAX_PRIME_DIFF = 1103717
M.NUM3072_BYTE_SIZE = 384  -- 3072 bits
M.MUHASH_OUTPUT_SIZE = 32  -- SHA256 of finalized Num3072

-- Lazily-built modulus BIGNUM.  Wrapped in ffi.gc so it is freed when the
-- module table is collected (i.e. on process exit in practice).
local _modulus = nil
local function get_modulus()
  if _modulus then return _modulus end
  local m = libcrypto.BN_new()
  if m == nil then error("muhash: BN_new failed for modulus") end
  -- Set bit 3072 -> value 2^3072.
  if libcrypto.BN_set_bit(m, 3072) ~= 1 then
    libcrypto.BN_free(m)
    error("muhash: BN_set_bit(3072) failed")
  end
  -- Subtract MAX_PRIME_DIFF (1103717 < 2^32, fits in BN_ULONG on every platform).
  if libcrypto.BN_sub_word(m, MAX_PRIME_DIFF) ~= 1 then
    libcrypto.BN_free(m)
    error("muhash: BN_sub_word failed")
  end
  _modulus = ffi.gc(m, libcrypto.BN_free)
  return _modulus
end

--------------------------------------------------------------------------------
-- Num3072 helpers
--------------------------------------------------------------------------------

-- Allocate a fresh BIGNUM with value 1 (the multiplicative identity).
local function new_one()
  local b = libcrypto.BN_new()
  if b == nil then error("muhash: BN_new failed") end
  if libcrypto.BN_set_word(b, 1) ~= 1 then
    libcrypto.BN_free(b)
    error("muhash: BN_set_word(1) failed")
  end
  return ffi.gc(b, libcrypto.BN_free)
end

-- Build a Num3072 from raw 384-byte little-endian buffer.
local function bn_from_le_bytes(buf, len)
  local b = libcrypto.BN_lebin2bn(buf, len, nil)
  if b == nil then error("muhash: BN_lebin2bn failed") end
  return ffi.gc(b, libcrypto.BN_free)
end

-- Pack a BIGNUM into 384 little-endian bytes (Lua string).
local function bn_to_le_bytes(bn, len)
  len = len or M.NUM3072_BYTE_SIZE
  local out = ffi.new("unsigned char[?]", len)
  local n = libcrypto.BN_bn2lebinpad(bn, out, len)
  if n ~= len then
    error(string.format("muhash: BN_bn2lebinpad returned %d (expected %d)", n, len))
  end
  return ffi.string(out, len)
end

--- Map an arbitrary-length input to a Num3072.
-- Mirrors MuHash3072::ToNum3072 (muhash.cpp:536):
--     uint256 hashed_in = SHA256(in)
--     ChaCha20Aligned(hashed_in).Keystream(tmp[384])
--     Num3072 out{tmp}
-- Because Num3072(unsigned char[384]) reads via ReadLE32/64 per limb, and
-- BN_lebin2bn interprets its input as a little-endian integer, the two
-- representations are identical (the value of limb i lives at bytes
-- [i*L .. i*L + L) in both cases).
function M.to_num3072(input)
  local key = crypto.sha256(input)        -- 32 bytes
  local nonce = string.rep("\0", 12)      -- RFC 8439 zero nonce
  local zeros = string.rep("\0", M.NUM3072_BYTE_SIZE)
  local keystream = crypto.chacha20_crypt(key, nonce, zeros)  -- 384 bytes
  return bn_from_le_bytes(keystream, M.NUM3072_BYTE_SIZE)
end

-- Multiply dst <- (dst * a) mod modulus.  Allocates and frees a temp BIGNUM.
local function bn_mul_assign(dst, a)
  local m = get_modulus()
  local ctx = libcrypto.BN_CTX_new()
  if ctx == nil then error("muhash: BN_CTX_new failed") end
  local ok = libcrypto.BN_mod_mul(dst, dst, a, m, ctx)
  libcrypto.BN_CTX_free(ctx)
  if ok ~= 1 then error("muhash: BN_mod_mul failed") end
end

-- Returns a^-1 mod modulus as a fresh, gc-managed BIGNUM.
local function bn_modinv(a)
  local m = get_modulus()
  local ctx = libcrypto.BN_CTX_new()
  if ctx == nil then error("muhash: BN_CTX_new failed") end
  local r = libcrypto.BN_new()
  if r == nil then
    libcrypto.BN_CTX_free(ctx)
    error("muhash: BN_new failed")
  end
  local result = libcrypto.BN_mod_inverse(r, a, m, ctx)
  libcrypto.BN_CTX_free(ctx)
  if result == nil then
    libcrypto.BN_free(r)
    error("muhash: BN_mod_inverse failed (input not coprime to modulus)")
  end
  return ffi.gc(r, libcrypto.BN_free)
end

--------------------------------------------------------------------------------
-- MuHash3072 accumulator
--------------------------------------------------------------------------------

local MuHash3072 = {}
MuHash3072.__index = MuHash3072

--- Construct a new empty MuHash accumulator.
-- @return MuHash3072: numerator=1, denominator=1.
function M.new()
  local self = setmetatable({}, MuHash3072)
  self.numerator = new_one()
  self.denominator = new_one()
  return self
end

--- Construct a MuHash containing a single element (Core's
--  MuHash3072(span<const unsigned char> in) noexcept constructor).
-- @param input string: raw bytes.
-- @return MuHash3072.
function M.from_singleton(input)
  local self = M.new()
  -- Replace numerator with ToNum3072(input).  We can't just assign because
  -- numerator is gc-managed; instead, free the old one and reattach.
  local n = M.to_num3072(input)
  -- Detach old numerator from gc so we can free it eagerly.
  local old = self.numerator
  ffi.gc(old, nil)
  libcrypto.BN_free(old)
  self.numerator = n
  return self
end

--- Insert a single element into the set.  Multiplies ToNum3072(input)
--  into the numerator, modulo p.
-- @param input string: raw bytes.
-- @return MuHash3072: self (chainable).
function MuHash3072:insert(input)
  local x = M.to_num3072(input)
  bn_mul_assign(self.numerator, x)
  return self
end

--- Remove a single element from the set.  Multiplies ToNum3072(input)
--  into the denominator, modulo p.
-- @param input string: raw bytes.
-- @return MuHash3072: self (chainable).
function MuHash3072:remove(input)
  local x = M.to_num3072(input)
  bn_mul_assign(self.denominator, x)
  return self
end

--- Multiply this MuHash by another one, in-place (set union).
function MuHash3072:multiply(other)
  bn_mul_assign(self.numerator, other.numerator)
  bn_mul_assign(self.denominator, other.denominator)
  return self
end

--- Divide this MuHash by another, in-place (set difference).
function MuHash3072:divide(other)
  bn_mul_assign(self.numerator, other.denominator)
  bn_mul_assign(self.denominator, other.numerator)
  return self
end

--- Finalize and return the 32-byte SHA256 of the canonical Num3072 packing.
--  Does not mutate the running ratio in any way that affects future
--  Insert/Remove (Core resets the denominator to 1 in Finalize for
--  serialization purposes; we do the same to mirror behavior).
-- @return string: 32 raw bytes.
function MuHash3072:finalize()
  -- combined = numerator * denominator^-1 mod p
  local inv = bn_modinv(self.denominator)
  local m = get_modulus()
  local ctx = libcrypto.BN_CTX_new()
  if ctx == nil then error("muhash: BN_CTX_new failed") end

  local combined = libcrypto.BN_new()
  if combined == nil then
    libcrypto.BN_CTX_free(ctx)
    error("muhash: BN_new failed")
  end
  ffi.gc(combined, libcrypto.BN_free)

  if libcrypto.BN_mod_mul(combined, self.numerator, inv, m, ctx) ~= 1 then
    libcrypto.BN_CTX_free(ctx)
    error("muhash: BN_mod_mul (finalize) failed")
  end
  libcrypto.BN_CTX_free(ctx)

  -- Mirror Core's Finalize: collapse the running fraction back into the
  -- numerator and reset the denominator to 1, so the same accumulator
  -- can be Finalized again or kept Insert/Remove'd consistently.
  -- Detach old gc-managed BIGNUMs and free them, then reattach.
  local old_num = self.numerator
  ffi.gc(old_num, nil)
  libcrypto.BN_free(old_num)
  -- combined now becomes the numerator; copy because we already attached
  -- gc on combined above — easier to just transfer ownership.
  self.numerator = combined  -- keep the gc finalizer set on combined

  local old_den = self.denominator
  ffi.gc(old_den, nil)
  libcrypto.BN_free(old_den)
  self.denominator = new_one()

  -- SHA256 of canonical 384-byte LE packing.
  local packed = bn_to_le_bytes(self.numerator, M.NUM3072_BYTE_SIZE)
  return crypto.sha256(packed)
end

--- Encode the current Num3072 numerator (after mixing in the denominator
--  the way Finalize does) as Core's serialization: numerator || denominator,
--  each 384 LE bytes.  Useful for cross-impl reproduction tests.
-- @return string: 768 bytes.
function MuHash3072:serialize()
  return bn_to_le_bytes(self.numerator) .. bn_to_le_bytes(self.denominator)
end

M.MuHash3072 = MuHash3072

return M
