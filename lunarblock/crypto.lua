local ffi = require("ffi")
local types = require("lunarblock.types")
local M = {}

-- OpenSSL FFI declarations
ffi.cdef[[
  /* EVP digest interface (OpenSSL 1.1+) */
  typedef struct evp_md_st EVP_MD;
  typedef struct evp_md_ctx_st EVP_MD_CTX;

  const EVP_MD *EVP_sha256(void);
  const EVP_MD *EVP_sha512(void);
  const EVP_MD *EVP_ripemd160(void);

  EVP_MD_CTX *EVP_MD_CTX_new(void);
  void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
  int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, void *impl);
  int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
  int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
  int EVP_MD_size(const EVP_MD *md);

  /* HMAC */
  unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len,
                      const unsigned char *d, size_t n,
                      unsigned char *md, unsigned int *md_len);
]]

local libcrypto = ffi.load("crypto")

-- SHA-256: single hash
function M.sha256(data)
  local ctx = libcrypto.EVP_MD_CTX_new()
  assert(ctx ~= nil, "Failed to create EVP_MD_CTX")
  local md = ffi.new("unsigned char[32]")
  local md_len = ffi.new("unsigned int[1]")
  libcrypto.EVP_DigestInit_ex(ctx, libcrypto.EVP_sha256(), nil)
  libcrypto.EVP_DigestUpdate(ctx, data, #data)
  libcrypto.EVP_DigestFinal_ex(ctx, md, md_len)
  libcrypto.EVP_MD_CTX_free(ctx)
  return ffi.string(md, 32)
end

-- Double SHA-256: hash256 used for block hashes, txids
function M.hash256(data)
  return M.sha256(M.sha256(data))
end

-- Double SHA-256 returning a hash256 type
function M.hash256_type(data)
  return types.hash256(M.hash256(data))
end

-- RIPEMD-160
function M.ripemd160(data)
  local ctx = libcrypto.EVP_MD_CTX_new()
  assert(ctx ~= nil, "Failed to create EVP_MD_CTX")
  local md = ffi.new("unsigned char[20]")
  local md_len = ffi.new("unsigned int[1]")
  libcrypto.EVP_DigestInit_ex(ctx, libcrypto.EVP_ripemd160(), nil)
  libcrypto.EVP_DigestUpdate(ctx, data, #data)
  libcrypto.EVP_DigestFinal_ex(ctx, md, md_len)
  libcrypto.EVP_MD_CTX_free(ctx)
  return ffi.string(md, 20)
end

-- HASH160: RIPEMD160(SHA256(data)) used for addresses
function M.hash160(data)
  return M.ripemd160(M.sha256(data))
end

-- HASH160 returning a hash160 type
function M.hash160_type(data)
  return types.hash160(M.hash160(data))
end

-- HMAC-SHA512: used for BIP32 key derivation
function M.hmac_sha512(key, data)
  local md = ffi.new("unsigned char[64]")
  local md_len = ffi.new("unsigned int[1]", 64)
  local result = libcrypto.HMAC(
    libcrypto.EVP_sha512(), key, #key, data, #data, md, md_len
  )
  assert(result ~= nil, "HMAC-SHA512 failed")
  return ffi.string(md, 64)
end

-- libsecp256k1 FFI declarations
ffi.cdef[[
  typedef struct secp256k1_context_struct secp256k1_context;
  typedef struct { unsigned char data[64]; } secp256k1_pubkey;
  typedef struct { unsigned char data[64]; } secp256k1_ecdsa_signature;

  /* Context flags */
  enum {
    SECP256K1_CONTEXT_VERIFY = 0x0101,
    SECP256K1_CONTEXT_SIGN   = 0x0201,
    SECP256K1_CONTEXT_NONE   = 0x0001
  };

  /* Serialization flags */
  enum {
    SECP256K1_EC_COMPRESSED   = 0x0102,
    SECP256K1_EC_UNCOMPRESSED = 0x0002
  };

  secp256k1_context* secp256k1_context_create(unsigned int flags);
  void secp256k1_context_destroy(secp256k1_context* ctx);

  int secp256k1_ec_pubkey_parse(
    const secp256k1_context* ctx,
    secp256k1_pubkey* pubkey,
    const unsigned char* input,
    size_t inputlen
  );

  int secp256k1_ec_pubkey_serialize(
    const secp256k1_context* ctx,
    unsigned char* output,
    size_t* outputlen,
    const secp256k1_pubkey* pubkey,
    unsigned int flags
  );

  int secp256k1_ecdsa_signature_parse_der(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature* sig,
    const unsigned char* input,
    size_t inputlen
  );

  int secp256k1_ecdsa_verify(
    const secp256k1_context* ctx,
    const secp256k1_ecdsa_signature* sig,
    const unsigned char* msghash32,
    const secp256k1_pubkey* pubkey
  );

  int secp256k1_ec_pubkey_create(
    const secp256k1_context* ctx,
    secp256k1_pubkey* pubkey,
    const unsigned char* seckey
  );

  int secp256k1_ecdsa_sign(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature* sig,
    const unsigned char* msghash32,
    const unsigned char* seckey,
    void* noncefp,
    const void* ndata
  );

  int secp256k1_ecdsa_signature_serialize_der(
    const secp256k1_context* ctx,
    unsigned char* output,
    size_t* outputlen,
    const secp256k1_ecdsa_signature* sig
  );

  /* Schnorr / BIP340 (if available in your libsecp256k1 build) */
  typedef struct { unsigned char data[96]; } secp256k1_xonly_pubkey;

  int secp256k1_xonly_pubkey_parse(
    const secp256k1_context* ctx,
    secp256k1_xonly_pubkey* pubkey,
    const unsigned char* input32
  );

  int secp256k1_schnorrsig_verify(
    const secp256k1_context* ctx,
    const unsigned char* sig64,
    const unsigned char* msg,
    size_t msglen,
    const secp256k1_xonly_pubkey* pubkey
  );
]]

local libsecp256k1 = ffi.load("secp256k1")

-- Create a global secp256k1 context for verification and signing
local secp_ctx = libsecp256k1.secp256k1_context_create(
  bit.bor(0x0101, 0x0201)  -- VERIFY | SIGN
)

-- Verify an ECDSA signature (DER-encoded) against a message hash and public key
function M.ecdsa_verify(pubkey_bytes, sig_der, msg_hash32)
  local pubkey = ffi.new("secp256k1_pubkey")
  if libsecp256k1.secp256k1_ec_pubkey_parse(
    secp_ctx, pubkey, pubkey_bytes, #pubkey_bytes
  ) ~= 1 then
    return false, "invalid public key"
  end

  local sig = ffi.new("secp256k1_ecdsa_signature")
  if libsecp256k1.secp256k1_ecdsa_signature_parse_der(
    secp_ctx, sig, sig_der, #sig_der
  ) ~= 1 then
    return false, "invalid DER signature"
  end

  local result = libsecp256k1.secp256k1_ecdsa_verify(secp_ctx, sig, msg_hash32, pubkey)
  return result == 1
end

-- Create a public key from a 32-byte private key
function M.pubkey_from_privkey(privkey32, compressed)
  if compressed == nil then compressed = true end
  local pubkey = ffi.new("secp256k1_pubkey")
  if libsecp256k1.secp256k1_ec_pubkey_create(secp_ctx, pubkey, privkey32) ~= 1 then
    return nil, "invalid private key"
  end

  local flags = compressed and 0x0102 or 0x0002
  local outlen = compressed and 33 or 65
  local output = ffi.new("unsigned char[?]", outlen)
  local outputlen = ffi.new("size_t[1]", outlen)
  libsecp256k1.secp256k1_ec_pubkey_serialize(secp_ctx, output, outputlen, pubkey, flags)
  return ffi.string(output, outputlen[0])
end

-- Sign a 32-byte message hash with a 32-byte private key, return DER-encoded signature
function M.ecdsa_sign(privkey32, msg_hash32)
  local sig = ffi.new("secp256k1_ecdsa_signature")
  if libsecp256k1.secp256k1_ecdsa_sign(
    secp_ctx, sig, msg_hash32, privkey32, nil, nil
  ) ~= 1 then
    return nil, "signing failed"
  end

  local output = ffi.new("unsigned char[72]")
  local outputlen = ffi.new("size_t[1]", 72)
  libsecp256k1.secp256k1_ecdsa_signature_serialize_der(
    secp_ctx, output, outputlen, sig
  )
  return ffi.string(output, outputlen[0])
end

-- Verify a BIP340 Schnorr signature (64 bytes) against a message and x-only pubkey (32 bytes)
function M.schnorr_verify(xonly_pubkey32, sig64, msg)
  local pubkey = ffi.new("secp256k1_xonly_pubkey")
  if libsecp256k1.secp256k1_xonly_pubkey_parse(secp_ctx, pubkey, xonly_pubkey32) ~= 1 then
    return false, "invalid x-only public key"
  end
  local result = libsecp256k1.secp256k1_schnorrsig_verify(
    secp_ctx, sig64, msg, #msg, pubkey
  )
  return result == 1
end

--------------------------------------------------------------------------------
-- SipHash-2-4 (BIP152 Compact Blocks)
--------------------------------------------------------------------------------

-- SipHash-2-4 constants (initialization vectors XORed with key)
local SIPHASH_C0 = ffi.new("uint64_t", 0x736f6d6570736575ULL)
local SIPHASH_C1 = ffi.new("uint64_t", 0x646f72616e646f6dULL)
local SIPHASH_C2 = ffi.new("uint64_t", 0x6c7967656e657261ULL)
local SIPHASH_C3 = ffi.new("uint64_t", 0x7465646279746573ULL)

-- Helper: rotate left for uint64
local function rotl64(x, n)
  return bit.bor(bit.lshift(x, n), bit.rshift(x, 64 - n))
end

-- SipHash round function (SipRound)
-- Using FFI uint64_t for proper 64-bit arithmetic
local function sipround(v0, v1, v2, v3)
  v0 = v0 + v1
  v1 = bit.bor(bit.lshift(v1, 13), bit.rshift(v1, 51))  -- rotl(v1, 13)
  v1 = bit.bxor(v1, v0)
  v0 = bit.bor(bit.lshift(v0, 32), bit.rshift(v0, 32))  -- rotl(v0, 32)

  v2 = v2 + v3
  v3 = bit.bor(bit.lshift(v3, 16), bit.rshift(v3, 48))  -- rotl(v3, 16)
  v3 = bit.bxor(v3, v2)

  v0 = v0 + v3
  v3 = bit.bor(bit.lshift(v3, 21), bit.rshift(v3, 43))  -- rotl(v3, 21)
  v3 = bit.bxor(v3, v0)

  v2 = v2 + v1
  v1 = bit.bor(bit.lshift(v1, 17), bit.rshift(v1, 47))  -- rotl(v1, 17)
  v1 = bit.bxor(v1, v2)
  v2 = bit.bor(bit.lshift(v2, 32), bit.rshift(v2, 32))  -- rotl(v2, 32)

  return v0, v1, v2, v3
end

-- Read 8 bytes as little-endian uint64
local function read_u64le(data, offset)
  local b1, b2, b3, b4, b5, b6, b7, b8 = data:byte(offset, offset + 7)
  -- Use FFI for proper 64-bit arithmetic
  local low = b1 + b2 * 0x100 + b3 * 0x10000 + b4 * 0x1000000
  local high = b5 + b6 * 0x100 + b7 * 0x10000 + b8 * 0x1000000
  return ffi.new("uint64_t", low) + ffi.new("uint64_t", high) * ffi.new("uint64_t", 0x100000000ULL)
end

--- SipHash-2-4 implementation for arbitrary data.
-- @param k0 number|cdata: first 64-bit key part
-- @param k1 number|cdata: second 64-bit key part
-- @param data string: data to hash
-- @return cdata: 64-bit hash result as uint64_t
function M.siphash24(k0, k1, data)
  -- Convert keys to uint64_t
  k0 = ffi.new("uint64_t", k0)
  k1 = ffi.new("uint64_t", k1)

  -- Initialize state
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

--- Compute SipHash key from block header and nonce (BIP152).
-- Key = SHA256(header || nonce), split into k0 and k1.
-- @param header_bytes string: 80-byte serialized block header
-- @param nonce number|cdata: 64-bit nonce
-- @return cdata, cdata: k0 and k1 as uint64_t
function M.siphash_key_from_header(header_bytes, nonce)
  -- Serialize nonce as little-endian 8 bytes
  local nonce64 = ffi.new("uint64_t", nonce)
  local nonce_bytes = ffi.new("uint8_t[8]")
  for i = 0, 7 do
    nonce_bytes[i] = tonumber(bit.band(bit.rshift(nonce64, i * 8), 0xFF))
  end

  -- Compute SHA256 of header || nonce
  local key_hash = M.sha256(header_bytes .. ffi.string(nonce_bytes, 8))

  -- Split into k0 and k1 (first 16 bytes, little-endian)
  local k0 = read_u64le(key_hash, 1)
  local k1 = read_u64le(key_hash, 9)

  return k0, k1
end

--- Compute short transaction ID for BIP152 compact blocks.
-- short_txid = SipHash(wtxid) & 0xffffffffffff (first 6 bytes)
-- @param k0 cdata: first key part from siphash_key_from_header
-- @param k1 cdata: second key part from siphash_key_from_header
-- @param wtxid string: 32-byte witness transaction ID
-- @return number: 6-byte short ID as a number
function M.compact_block_short_id(k0, k1, wtxid)
  local hash = M.siphash24(k0, k1, wtxid)
  -- Return only the lower 48 bits (6 bytes)
  return tonumber(bit.band(hash, ffi.new("uint64_t", 0xFFFFFFFFFFFFULL)))
end

--------------------------------------------------------------------------------
-- Merkle Root
--------------------------------------------------------------------------------

-- Compute the merkle root from a list of transaction hashes
function M.compute_merkle_root(tx_hashes)
  if #tx_hashes == 0 then
    return types.hash256_zero()
  end
  if #tx_hashes == 1 then
    return tx_hashes[1]
  end

  local current = {}
  for _, h in ipairs(tx_hashes) do
    current[#current + 1] = h.bytes
  end

  while #current > 1 do
    local next_level = {}
    for i = 1, #current, 2 do
      local left = current[i]
      local right = current[i + 1] or current[i]  -- duplicate last if odd
      next_level[#next_level + 1] = M.hash256(left .. right)
    end
    current = next_level
  end

  return types.hash256(current[1])
end

return M
