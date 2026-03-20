local ffi = require("ffi")
local types = require("lunarblock.types")
local M = {}

-- SHA-256 hardware acceleration state
local sha256_accel_lib = nil
local sha256_hw_type = nil  -- "sha_ni", "avx2", or "generic"

-- OpenSSL FFI declarations
ffi.cdef[[
  /* EVP digest interface (OpenSSL 1.1+) */
  typedef struct evp_md_st EVP_MD;
  typedef struct evp_md_ctx_st EVP_MD_CTX;

  const EVP_MD *EVP_sha1(void);
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

  /* ChaCha20-Poly1305 AEAD (OpenSSL 1.1+) */
  typedef struct evp_cipher_st EVP_CIPHER;
  typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

  const EVP_CIPHER *EVP_chacha20_poly1305(void);
  EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
  void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
  int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

  int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                         void *impl, const unsigned char *key, const unsigned char *iv);
  int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
  int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

  int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                         void *impl, const unsigned char *key, const unsigned char *iv);
  int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
  int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

  /* ChaCha20 stream cipher */
  const EVP_CIPHER *EVP_chacha20(void);

  /* Random bytes */
  int RAND_bytes(unsigned char *buf, int num);
]]

local libcrypto = ffi.load("crypto")

-- Hardware-accelerated SHA-256 FFI declarations
ffi.cdef[[
  int sha256_accel_init(void);
  void sha256_accel(const uint8_t* data, size_t len, uint8_t out[32]);
  void sha256d_accel(const uint8_t* data, size_t len, uint8_t out[32]);
]]

-- Try to load the hardware-accelerated SHA-256 library
local function init_sha256_accel()
  if sha256_accel_lib ~= nil then
    return sha256_accel_lib
  end

  -- Try to load the .so from various locations
  local paths = {
    "./lib/sha256_accel.so",    -- Project lib directory
    "lunarblock/sha256_accel",  -- LuaRocks install path
    "./lunarblock/sha256_accel.so",
    "./sha256_accel.so",
    "sha256_accel",
  }

  for _, path in ipairs(paths) do
    local ok, lib = pcall(ffi.load, path)
    if ok then
      sha256_accel_lib = lib
      local accel_type = lib.sha256_accel_init()
      if accel_type == 1 then
        sha256_hw_type = "sha_ni"
      elseif accel_type == 2 then
        sha256_hw_type = "avx2"
      else
        sha256_hw_type = "generic"
      end
      return sha256_accel_lib
    end
  end

  -- Fallback: no acceleration available
  sha256_hw_type = "generic"
  return nil
end

-- Initialize on module load (non-fatal if not available)
pcall(init_sha256_accel)

-- OpenSSL EVP control constants
local EVP_CTRL_AEAD_SET_IVLEN = 0x09
local EVP_CTRL_AEAD_GET_TAG = 0x10
local EVP_CTRL_AEAD_SET_TAG = 0x11

-- SHA-256: single hash (uses hardware acceleration if available)
function M.sha256(data)
  if sha256_accel_lib then
    local md = ffi.new("uint8_t[32]")
    sha256_accel_lib.sha256_accel(data, #data, md)
    return ffi.string(md, 32)
  end
  -- Fallback to OpenSSL
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

-- SHA-1 (for OP_SHA1)
function M.sha1(data)
  local ctx = libcrypto.EVP_MD_CTX_new()
  assert(ctx ~= nil, "Failed to create EVP_MD_CTX")
  local md = ffi.new("unsigned char[20]")
  local md_len = ffi.new("unsigned int[1]")
  libcrypto.EVP_DigestInit_ex(ctx, libcrypto.EVP_sha1(), nil)
  libcrypto.EVP_DigestUpdate(ctx, data, #data)
  libcrypto.EVP_DigestFinal_ex(ctx, md, md_len)
  libcrypto.EVP_MD_CTX_free(ctx)
  return ffi.string(md, 20)
end

-- SHA-256 streaming hasher: for incremental hashing of large data
-- Usage: local h = crypto.sha256_init(); h.update(data1); h.update(data2); local hash = h.final()
function M.sha256_init()
  local ctx = libcrypto.EVP_MD_CTX_new()
  assert(ctx ~= nil, "Failed to create EVP_MD_CTX")
  libcrypto.EVP_DigestInit_ex(ctx, libcrypto.EVP_sha256(), nil)

  local hasher = {}

  function hasher.update(data)
    libcrypto.EVP_DigestUpdate(ctx, data, #data)
  end

  function hasher.final()
    local md = ffi.new("unsigned char[32]")
    local md_len = ffi.new("unsigned int[1]")
    libcrypto.EVP_DigestFinal_ex(ctx, md, md_len)
    libcrypto.EVP_MD_CTX_free(ctx)
    return ffi.string(md, 32)
  end

  return hasher
end

-- Double SHA-256: hash256 used for block hashes, txids (uses hardware acceleration if available)
function M.hash256(data)
  if sha256_accel_lib then
    local md = ffi.new("uint8_t[32]")
    sha256_accel_lib.sha256d_accel(data, #data, md)
    return ffi.string(md, 32)
  end
  -- Fallback to two OpenSSL calls
  return M.sha256(M.sha256(data))
end

-- Double SHA-256 returning a hash256 type
function M.hash256_type(data)
  return types.hash256(M.hash256(data))
end

-- Report which SHA-256 hardware acceleration is being used
-- Returns: "sha_ni", "avx2", or "generic"
function M.sha256_hw_info()
  if sha256_hw_type == nil then
    init_sha256_accel()
  end
  return sha256_hw_type or "generic"
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

-- HMAC-SHA256: used for BIP324 HKDF
function M.hmac_sha256(key, data)
  local md = ffi.new("unsigned char[32]")
  local md_len = ffi.new("unsigned int[1]", 32)
  local result = libcrypto.HMAC(
    libcrypto.EVP_sha256(), key, #key, data, #data, md, md_len
  )
  assert(result ~= nil, "HMAC-SHA256 failed")
  return ffi.string(md, 32)
end

-- Generate cryptographically secure random bytes
function M.random_bytes(n)
  local buf = ffi.new("unsigned char[?]", n)
  local ret = libcrypto.RAND_bytes(buf, n)
  assert(ret == 1, "RAND_bytes failed")
  return ffi.string(buf, n)
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

  int secp256k1_ecdsa_signature_parse_compact(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature* sig,
    const unsigned char* input64
  );

  int secp256k1_ecdsa_signature_normalize(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature* sigout,
    const secp256k1_ecdsa_signature* sigin
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

  /* ElligatorSwift for BIP324 */
  typedef int (*secp256k1_ellswift_xdh_hash_function)(
    unsigned char *output,
    const unsigned char *x32,
    const unsigned char *ell_a64,
    const unsigned char *ell_b64,
    void *data
  );

  extern const secp256k1_ellswift_xdh_hash_function secp256k1_ellswift_xdh_hash_function_bip324;

  int secp256k1_ellswift_create(
    const secp256k1_context *ctx,
    unsigned char *ell64,
    const unsigned char *seckey32,
    const unsigned char *auxrnd32
  );

  int secp256k1_ellswift_xdh(
    const secp256k1_context *ctx,
    unsigned char *output,
    const unsigned char *ell_a64,
    const unsigned char *ell_b64,
    const unsigned char *seckey32,
    int party,
    secp256k1_ellswift_xdh_hash_function hashfp,
    void *data
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

--- Lax DER parsing: extract R and S from a non-strict DER signature.
-- Mimics Bitcoin Core's ecdsa_signature_parse_der_lax from pubkey.cpp.
-- Extracts R and S integers, right-pads or left-truncates to 32 bytes each,
-- and feeds the resulting 64-byte compact signature to secp256k1.
-- @param sig_der string: DER-encoded signature bytes (potentially non-strict)
-- @return cdata|nil: parsed secp256k1_ecdsa_signature, or nil on failure
local function lax_der_parse(sig_der)
  local len = #sig_der
  if len < 1 then return nil end
  local pos = 1

  -- Read sequence tag
  if sig_der:byte(pos) ~= 0x30 then return nil end
  pos = pos + 1
  if pos > len then return nil end

  -- Read sequence length (skip it, we don't strictly validate)
  local lenbyte = sig_der:byte(pos)
  pos = pos + 1
  if lenbyte >= 0x80 then
    -- Long form length
    local n_lenbytes = lenbyte - 0x80
    if n_lenbytes > #sig_der - pos + 1 then return nil end
    pos = pos + n_lenbytes  -- skip the length bytes
  end

  -- Read R integer tag
  if pos > len or sig_der:byte(pos) ~= 0x02 then return nil end
  pos = pos + 1
  if pos > len then return nil end

  -- Read R length
  local rlen = sig_der:byte(pos)
  pos = pos + 1
  if rlen >= 0x80 then
    -- Long form
    local n_lenbytes = rlen - 0x80
    if n_lenbytes > len - pos + 1 then return nil end
    rlen = 0
    for ii = 1, n_lenbytes do
      rlen = rlen * 256 + sig_der:byte(pos)
      pos = pos + 1
    end
  end

  if rlen > len - pos + 1 then return nil end
  local rdata = sig_der:sub(pos, pos + rlen - 1)
  pos = pos + rlen

  -- Read S integer tag
  if pos > len or sig_der:byte(pos) ~= 0x02 then return nil end
  pos = pos + 1
  if pos > len then return nil end

  -- Read S length
  local slen = sig_der:byte(pos)
  pos = pos + 1
  if slen >= 0x80 then
    local n_lenbytes = slen - 0x80
    if n_lenbytes > len - pos + 1 then return nil end
    slen = 0
    for ii = 1, n_lenbytes do
      slen = slen * 256 + sig_der:byte(pos)
      pos = pos + 1
    end
  end

  if slen > len - pos + 1 then return nil end
  local sdata = sig_der:sub(pos, pos + slen - 1)

  -- Strip leading zeros from R and S, then pad to 32 bytes
  -- (same logic as Bitcoin Core's lax parser)
  local function to_32_bytes(data)
    -- Skip leading zero bytes
    local start = 1
    while start < #data and data:byte(start) == 0 do
      start = start + 1
    end
    data = data:sub(start)
    if #data > 32 then
      return nil  -- too large even after stripping
    end
    -- Left-pad with zeros to 32 bytes
    return string.rep("\0", 32 - #data) .. data
  end

  local r32 = to_32_bytes(rdata)
  local s32 = to_32_bytes(sdata)
  if not r32 or not s32 then return nil end

  local compact = r32 .. s32
  local sig = ffi.new("secp256k1_ecdsa_signature")
  if libsecp256k1.secp256k1_ecdsa_signature_parse_compact(
    secp_ctx, sig, compact
  ) ~= 1 then
    return nil
  end

  -- Normalize S to low-S form (secp256k1 requires this for verification)
  libsecp256k1.secp256k1_ecdsa_signature_normalize(secp_ctx, sig, sig)
  return sig
end

--- Verify ECDSA signature with lax DER parsing (pre-BIP66 compatibility).
-- Uses lax DER parsing that accepts OpenSSL-compatible non-strict DER.
-- @param pubkey_bytes string: public key bytes
-- @param sig_der string: DER-encoded signature (potentially non-strict)
-- @param msg_hash32 string: 32-byte message hash
-- @return boolean: true if signature is valid
function M.ecdsa_verify_lax(pubkey_bytes, sig_der, msg_hash32)
  local pubkey = ffi.new("secp256k1_pubkey")
  if libsecp256k1.secp256k1_ec_pubkey_parse(
    secp_ctx, pubkey, pubkey_bytes, #pubkey_bytes
  ) ~= 1 then
    return false, "invalid public key"
  end

  -- Try strict DER first (most signatures are valid strict DER)
  local sig = ffi.new("secp256k1_ecdsa_signature")
  local ok = libsecp256k1.secp256k1_ecdsa_signature_parse_der(
    secp_ctx, sig, sig_der, #sig_der
  )

  if ok ~= 1 then
    -- Strict DER failed - try lax DER parsing
    sig = lax_der_parse(sig_der)
    if not sig then
      return false, "invalid DER signature"
    end
  end

  -- Normalize S to low-S form before verification
  libsecp256k1.secp256k1_ecdsa_signature_normalize(secp_ctx, sig, sig)

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
-- ElligatorSwift (BIP324)
--------------------------------------------------------------------------------

--- Create an ElligatorSwift-encoded public key from a private key.
-- @param privkey32 string: 32-byte private key
-- @param auxrnd32 string|nil: optional 32 bytes of randomness
-- @return string|nil: 64-byte ElligatorSwift public key, or nil on error
function M.ellswift_create(privkey32, auxrnd32)
  assert(#privkey32 == 32, "private key must be 32 bytes")
  local ell64 = ffi.new("unsigned char[64]")
  local ret = libsecp256k1.secp256k1_ellswift_create(
    secp_ctx, ell64, privkey32, auxrnd32 and ffi.cast("const unsigned char*", auxrnd32) or nil
  )
  if ret ~= 1 then
    return nil, "ellswift_create failed"
  end
  return ffi.string(ell64, 64)
end

--- Perform ECDH with ElligatorSwift keys using BIP324 hash function.
-- @param our_privkey string: our 32-byte private key
-- @param our_ellswift string: our 64-byte ElligatorSwift public key
-- @param their_ellswift string: their 64-byte ElligatorSwift public key
-- @param initiator boolean: true if we initiated the connection
-- @return string|nil: 32-byte shared secret, or nil on error
function M.ellswift_ecdh(our_privkey, our_ellswift, their_ellswift, initiator)
  assert(#our_privkey == 32, "private key must be 32 bytes")
  assert(#our_ellswift == 64, "our ellswift key must be 64 bytes")
  assert(#their_ellswift == 64, "their ellswift key must be 64 bytes")

  local output = ffi.new("unsigned char[32]")
  -- party: 0 if we are party A (initiator), 1 if we are party B (responder)
  -- ell_a64 is always the initiator's key, ell_b64 is always the responder's key
  local ell_a, ell_b
  if initiator then
    ell_a = our_ellswift
    ell_b = their_ellswift
  else
    ell_a = their_ellswift
    ell_b = our_ellswift
  end

  local ret = libsecp256k1.secp256k1_ellswift_xdh(
    secp_ctx,
    output,
    ell_a,
    ell_b,
    our_privkey,
    initiator and 0 or 1,
    libsecp256k1.secp256k1_ellswift_xdh_hash_function_bip324,
    nil
  )
  if ret ~= 1 then
    return nil, "ellswift_xdh failed"
  end
  return ffi.string(output, 32)
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

--------------------------------------------------------------------------------
-- ChaCha20-Poly1305 AEAD (BIP324)
--------------------------------------------------------------------------------

--- ChaCha20 stream cipher for length encryption in BIP324.
-- @param key string: 32-byte key
-- @param nonce string: 12-byte nonce
-- @param data string: data to encrypt/decrypt (XOR with keystream)
-- @return string: encrypted/decrypted data
function M.chacha20_crypt(key, nonce, data)
  assert(#key == 32, "ChaCha20 key must be 32 bytes")
  assert(#nonce == 12, "ChaCha20 nonce must be 12 bytes")

  local ctx = libcrypto.EVP_CIPHER_CTX_new()
  assert(ctx ~= nil, "Failed to create EVP_CIPHER_CTX")

  -- Initialize ChaCha20 cipher
  if libcrypto.EVP_EncryptInit_ex(ctx, libcrypto.EVP_chacha20(), nil, key, nonce) ~= 1 then
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    error("EVP_EncryptInit_ex failed")
  end

  local outbuf = ffi.new("unsigned char[?]", #data + 16)
  local outlen = ffi.new("int[1]")

  if libcrypto.EVP_EncryptUpdate(ctx, outbuf, outlen, data, #data) ~= 1 then
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    error("EVP_EncryptUpdate failed")
  end

  local total_len = outlen[0]

  if libcrypto.EVP_EncryptFinal_ex(ctx, outbuf + total_len, outlen) ~= 1 then
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    error("EVP_EncryptFinal_ex failed")
  end
  total_len = total_len + outlen[0]

  libcrypto.EVP_CIPHER_CTX_free(ctx)
  return ffi.string(outbuf, total_len)
end

--- ChaCha20-Poly1305 AEAD encryption.
-- @param key string: 32-byte key
-- @param nonce string: 12-byte nonce
-- @param plaintext string: data to encrypt
-- @param aad string: additional authenticated data (can be empty)
-- @return string: ciphertext || 16-byte tag
function M.chacha20poly1305_encrypt(key, nonce, plaintext, aad)
  assert(#key == 32, "ChaCha20-Poly1305 key must be 32 bytes")
  assert(#nonce == 12, "ChaCha20-Poly1305 nonce must be 12 bytes")
  aad = aad or ""

  local ctx = libcrypto.EVP_CIPHER_CTX_new()
  assert(ctx ~= nil, "Failed to create EVP_CIPHER_CTX")

  -- Initialize cipher
  if libcrypto.EVP_EncryptInit_ex(ctx, libcrypto.EVP_chacha20_poly1305(), nil, nil, nil) ~= 1 then
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    error("EVP_EncryptInit_ex failed")
  end

  -- Set nonce length (12 bytes)
  if libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nil) ~= 1 then
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    error("EVP_CIPHER_CTX_ctrl (IVLEN) failed")
  end

  -- Set key and nonce
  if libcrypto.EVP_EncryptInit_ex(ctx, nil, nil, key, nonce) ~= 1 then
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    error("EVP_EncryptInit_ex (key/nonce) failed")
  end

  local outlen = ffi.new("int[1]")

  -- Process AAD (no output)
  if #aad > 0 then
    if libcrypto.EVP_EncryptUpdate(ctx, nil, outlen, aad, #aad) ~= 1 then
      libcrypto.EVP_CIPHER_CTX_free(ctx)
      error("EVP_EncryptUpdate (AAD) failed")
    end
  end

  -- Encrypt plaintext
  local ciphertext = ffi.new("unsigned char[?]", #plaintext + 16)
  if libcrypto.EVP_EncryptUpdate(ctx, ciphertext, outlen, plaintext, #plaintext) ~= 1 then
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    error("EVP_EncryptUpdate (plaintext) failed")
  end
  local cipher_len = outlen[0]

  -- Finalize
  if libcrypto.EVP_EncryptFinal_ex(ctx, ciphertext + cipher_len, outlen) ~= 1 then
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    error("EVP_EncryptFinal_ex failed")
  end
  cipher_len = cipher_len + outlen[0]

  -- Get tag
  local tag = ffi.new("unsigned char[16]")
  if libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) ~= 1 then
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    error("EVP_CIPHER_CTX_ctrl (GET_TAG) failed")
  end

  libcrypto.EVP_CIPHER_CTX_free(ctx)

  return ffi.string(ciphertext, cipher_len) .. ffi.string(tag, 16)
end

--- ChaCha20-Poly1305 AEAD decryption.
-- @param key string: 32-byte key
-- @param nonce string: 12-byte nonce
-- @param ciphertext_with_tag string: ciphertext || 16-byte tag
-- @param aad string: additional authenticated data (can be empty)
-- @return string|nil, string: plaintext on success, or nil and error message on failure
function M.chacha20poly1305_decrypt(key, nonce, ciphertext_with_tag, aad)
  assert(#key == 32, "ChaCha20-Poly1305 key must be 32 bytes")
  assert(#nonce == 12, "ChaCha20-Poly1305 nonce must be 12 bytes")
  aad = aad or ""

  if #ciphertext_with_tag < 16 then
    return nil, "ciphertext too short"
  end

  local cipher_len = #ciphertext_with_tag - 16
  local ciphertext = ciphertext_with_tag:sub(1, cipher_len)
  local tag = ciphertext_with_tag:sub(cipher_len + 1)

  local ctx = libcrypto.EVP_CIPHER_CTX_new()
  assert(ctx ~= nil, "Failed to create EVP_CIPHER_CTX")

  -- Initialize cipher
  if libcrypto.EVP_DecryptInit_ex(ctx, libcrypto.EVP_chacha20_poly1305(), nil, nil, nil) ~= 1 then
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    return nil, "EVP_DecryptInit_ex failed"
  end

  -- Set nonce length (12 bytes)
  if libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nil) ~= 1 then
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    return nil, "EVP_CIPHER_CTX_ctrl (IVLEN) failed"
  end

  -- Set key and nonce
  if libcrypto.EVP_DecryptInit_ex(ctx, nil, nil, key, nonce) ~= 1 then
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    return nil, "EVP_DecryptInit_ex (key/nonce) failed"
  end

  local outlen = ffi.new("int[1]")

  -- Process AAD (no output)
  if #aad > 0 then
    if libcrypto.EVP_DecryptUpdate(ctx, nil, outlen, aad, #aad) ~= 1 then
      libcrypto.EVP_CIPHER_CTX_free(ctx)
      return nil, "EVP_DecryptUpdate (AAD) failed"
    end
  end

  -- Decrypt ciphertext
  local plaintext = ffi.new("unsigned char[?]", cipher_len + 16)
  if libcrypto.EVP_DecryptUpdate(ctx, plaintext, outlen, ciphertext, cipher_len) ~= 1 then
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    return nil, "EVP_DecryptUpdate (ciphertext) failed"
  end
  local plain_len = outlen[0]

  -- Set expected tag
  if libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, ffi.cast("void*", tag)) ~= 1 then
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    return nil, "EVP_CIPHER_CTX_ctrl (SET_TAG) failed"
  end

  -- Finalize and verify tag
  local ret = libcrypto.EVP_DecryptFinal_ex(ctx, plaintext + plain_len, outlen)
  libcrypto.EVP_CIPHER_CTX_free(ctx)

  if ret ~= 1 then
    return nil, "authentication failed"
  end

  plain_len = plain_len + outlen[0]
  return ffi.string(plaintext, plain_len)
end

return M
