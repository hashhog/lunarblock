local ffi = require("ffi")
local bit = require("bit")
local crypto = require("lunarblock.crypto")
local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local address = require("lunarblock.address")
local script = require("lunarblock.script")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
local bip39 = require("lunarblock.bip39")
local M = {}

--------------------------------------------------------------------------------
-- AES-256-CBC Encryption via OpenSSL FFI
--------------------------------------------------------------------------------

ffi.cdef[[
  /* AES encryption via EVP interface */
  typedef struct evp_cipher_st EVP_CIPHER;
  typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

  const EVP_CIPHER *EVP_aes_256_cbc(void);
  EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
  void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);

  int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                         void *impl, const unsigned char *key, const unsigned char *iv);
  int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
  int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

  int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                         void *impl, const unsigned char *key, const unsigned char *iv);
  int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
  int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

  /* PBKDF2 for key derivation */
  int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
                        const unsigned char *salt, int saltlen, int iter,
                        const void *digest, int keylen, unsigned char *out);
  const void *EVP_sha512(void);

  /* Random bytes */
  int RAND_bytes(unsigned char *buf, int num);
]]

local libcrypto = ffi.load("crypto")

-- Encryption constants
M.CRYPTO_KEY_SIZE = 32      -- AES-256 key size
M.CRYPTO_IV_SIZE = 16       -- AES block size
M.CRYPTO_SALT_SIZE = 8      -- Salt size for key derivation
M.CRYPTO_ROUNDS = 25000     -- PBKDF2 iterations

-- At-rest encryption constants (P2-1 fix for W161 master_key plaintext P0).
-- When a wallet is not user-encrypted (no passphrase set), the master key is
-- STILL encrypted at rest with a deterministic key derived from this fixed
-- phrase. This is NOT a security boundary on its own — anyone with the source
-- can decrypt — but it ensures `cat wallet.json` never leaks the literal
-- master_key + chain_code bytes, and it makes the "no plaintext master key on
-- disk" invariant testable (see tests/test_p2_1_p2_2_wallet_security.lua).
-- Users who want a real security boundary MUST call `encryptwallet` with a
-- strong passphrase. Mirrors clearbit's f302997 model (every persisted
-- master_key is ciphertext) and the W161 audit's "Encrypted-by-default
-- wallet storage" goal.
M.AT_REST_PHRASE  = "lunarblock-wallet-at-rest-v1"
M.AT_REST_ROUNDS  = 4096    -- lighter than user PBKDF2 since this is obfuscation, not protection

--- Generate cryptographically secure random bytes.
-- @param n number: Number of bytes to generate
-- @return string: Random bytes
function M.random_bytes(n)
  local buf = ffi.new("unsigned char[?]", n)
  if libcrypto.RAND_bytes(buf, n) ~= 1 then
    -- Fallback to /dev/urandom
    local f = io.open("/dev/urandom", "rb")
    if f then
      local data = f:read(n)
      f:close()
      return data
    end
    error("Failed to generate random bytes")
  end
  return ffi.string(buf, n)
end

--- Derive a key from passphrase using PBKDF2-SHA512.
-- @param passphrase string: The passphrase
-- @param salt string: Salt bytes (8 bytes)
-- @param rounds number: Number of iterations (default CRYPTO_ROUNDS)
-- @return string: 32-byte key, string: 16-byte IV
function M.derive_key(passphrase, salt, rounds)
  rounds = rounds or M.CRYPTO_ROUNDS
  local key = ffi.new("unsigned char[32]")
  local iv = ffi.new("unsigned char[16]")
  local combined = ffi.new("unsigned char[48]")

  if libcrypto.PKCS5_PBKDF2_HMAC(
    passphrase, #passphrase,
    salt, #salt, rounds,
    libcrypto.EVP_sha512(), 48, combined
  ) ~= 1 then
    error("PBKDF2 key derivation failed")
  end

  ffi.copy(key, combined, 32)
  ffi.copy(iv, combined + 32, 16)
  return ffi.string(key, 32), ffi.string(iv, 16)
end

--- Derive the at-rest encryption key (P2-1).
-- Used for wallets that are NOT user-encrypted, so plaintext master_key never
-- hits disk. Same PBKDF2-SHA512 / AES-256-CBC primitives as user encryption,
-- with the AT_REST_PHRASE constant as the "passphrase" and the per-wallet
-- encryption_salt for binding to a specific wallet file.
-- @param salt string: Salt bytes (must match the on-disk encryption_salt)
-- @return string: 32-byte key, string: 16-byte IV
function M.derive_at_rest_key(salt)
  return M.derive_key(M.AT_REST_PHRASE, salt, M.AT_REST_ROUNDS)
end

--- Encrypt data using AES-256-CBC.
-- @param plaintext string: Data to encrypt
-- @param key string: 32-byte encryption key
-- @param iv string: 16-byte initialization vector
-- @return string: Encrypted data (with PKCS7 padding)
function M.aes_encrypt(plaintext, key, iv)
  local ctx = libcrypto.EVP_CIPHER_CTX_new()
  if ctx == nil then error("Failed to create cipher context") end

  local max_len = #plaintext + 16  -- Space for padding
  local out = ffi.new("unsigned char[?]", max_len)
  local outl = ffi.new("int[1]")
  local total_len = 0

  if libcrypto.EVP_EncryptInit_ex(ctx, libcrypto.EVP_aes_256_cbc(), nil, key, iv) ~= 1 then
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    error("Failed to initialize encryption")
  end

  if libcrypto.EVP_EncryptUpdate(ctx, out, outl, plaintext, #plaintext) ~= 1 then
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    error("Failed to encrypt data")
  end
  total_len = outl[0]

  if libcrypto.EVP_EncryptFinal_ex(ctx, out + total_len, outl) ~= 1 then
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    error("Failed to finalize encryption")
  end
  total_len = total_len + outl[0]

  libcrypto.EVP_CIPHER_CTX_free(ctx)
  return ffi.string(out, total_len)
end

--- Decrypt data using AES-256-CBC.
-- @param ciphertext string: Encrypted data
-- @param key string: 32-byte encryption key
-- @param iv string: 16-byte initialization vector
-- @return string|nil: Decrypted data, or nil on failure
-- @return string|nil: Error message on failure
function M.aes_decrypt(ciphertext, key, iv)
  local ctx = libcrypto.EVP_CIPHER_CTX_new()
  if ctx == nil then return nil, "Failed to create cipher context" end

  local out = ffi.new("unsigned char[?]", #ciphertext)
  local outl = ffi.new("int[1]")
  local total_len = 0

  if libcrypto.EVP_DecryptInit_ex(ctx, libcrypto.EVP_aes_256_cbc(), nil, key, iv) ~= 1 then
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    return nil, "Failed to initialize decryption"
  end

  if libcrypto.EVP_DecryptUpdate(ctx, out, outl, ciphertext, #ciphertext) ~= 1 then
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    return nil, "Failed to decrypt data"
  end
  total_len = outl[0]

  if libcrypto.EVP_DecryptFinal_ex(ctx, out + total_len, outl) ~= 1 then
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    return nil, "Invalid passphrase or corrupted data"
  end
  total_len = total_len + outl[0]

  libcrypto.EVP_CIPHER_CTX_free(ctx)
  return ffi.string(out, total_len)
end

--------------------------------------------------------------------------------
-- Coin Selection: Branch and Bound with Random Fallback
--------------------------------------------------------------------------------

-- Constants for coin selection
M.COST_OF_CHANGE = 148     -- vbytes for a change output + future input spend
M.MAX_BNB_TRIES = 100000   -- Maximum iterations for BnB algorithm
M.DUST_THRESHOLD = 546     -- Minimum output value (sat)

--- Calculate effective value (value minus cost to spend).
-- @param value number: UTXO value in satoshis
-- @param fee_rate number: Fee rate in sat/vB
-- @param input_vsize number: Virtual size of input (default 68 for P2WPKH)
-- @return number: Effective value
local function effective_value(value, fee_rate, input_vsize)
  input_vsize = input_vsize or 68  -- P2WPKH input
  return value - math.ceil(input_vsize * fee_rate)
end

--- Branch and Bound coin selection algorithm.
-- Searches for an exact match (no change needed).
-- Based on Murch's algorithm: https://murch.one/wp-content/uploads/2016/11/erhardt2016coinselection.pdf
-- @param utxos table: Array of {key=string, utxo={value=number, ...}}
-- @param target number: Target amount in satoshis
-- @param fee_rate number: Fee rate in sat/vB
-- @param cost_of_change number: Cost to create and spend change (default COST_OF_CHANGE * fee_rate)
-- @return table|nil: Selected UTXOs, or nil if no solution found
function M.select_coins_bnb(utxos, target, fee_rate, cost_of_change)
  cost_of_change = cost_of_change or math.ceil(M.COST_OF_CHANGE * fee_rate)

  -- Calculate effective values and filter out negative
  local candidates = {}
  for _, item in ipairs(utxos) do
    local eff_val = effective_value(item.utxo.value, fee_rate)
    if eff_val > 0 then
      candidates[#candidates + 1] = {
        key = item.key,
        utxo = item.utxo,
        effective_value = eff_val,
        value = item.utxo.value,
      }
    end
  end

  -- Sort by effective value descending
  table.sort(candidates, function(a, b) return a.effective_value > b.effective_value end)

  -- Calculate total available
  local total_available = 0
  for _, c in ipairs(candidates) do
    total_available = total_available + c.effective_value
  end

  if total_available < target then
    return nil  -- Insufficient funds
  end

  -- BnB search
  local curr_selection = {}
  local curr_value = 0
  local best_selection = nil
  local best_waste = math.huge

  local function calculate_waste(selection, sel_value)
    return sel_value - target
  end

  -- Depth-first search
  local tries = 0
  local idx = 1
  local available = total_available

  while tries < M.MAX_BNB_TRIES do
    tries = tries + 1

    -- Check if we should backtrack
    local backtrack = false
    if curr_value + available < target then
      -- Cannot reach target
      backtrack = true
    elseif curr_value > target + cost_of_change then
      -- Too much (exceeds target + change cost)
      backtrack = true
    elseif curr_value >= target and curr_value <= target + cost_of_change then
      -- Found a valid solution!
      local waste = calculate_waste(curr_selection, curr_value)
      if waste < best_waste then
        best_waste = waste
        best_selection = {}
        for _, s in ipairs(curr_selection) do
          best_selection[#best_selection + 1] = s
        end
      end
      backtrack = true
    elseif idx > #candidates then
      -- No more candidates
      backtrack = true
    end

    if backtrack then
      if #curr_selection == 0 then
        break  -- Searched everything
      end

      -- Backtrack: remove last selected item and skip it
      local last = curr_selection[#curr_selection]
      curr_selection[#curr_selection] = nil
      curr_value = curr_value - last.effective_value

      -- Restore available for items after last's index
      idx = 1
      for i, c in ipairs(candidates) do
        if c == last then
          idx = i + 1
          break
        end
      end

      -- Recalculate available
      available = 0
      for i = idx, #candidates do
        available = available + candidates[i].effective_value
      end
    else
      -- Include current candidate
      local candidate = candidates[idx]
      curr_selection[#curr_selection + 1] = candidate
      curr_value = curr_value + candidate.effective_value
      available = available - candidate.effective_value
      idx = idx + 1
    end
  end

  return best_selection
end

--- Return a cryptographically secure random integer in [1, n] (1-indexed).
-- Uses wallet.random_bytes (OpenSSL RAND_bytes) to mirror Core's FastRandomContext
-- used in KnapsackSolver / SelectCoinsSRD Fisher-Yates shuffles.
-- @param n number: Upper bound (inclusive), must be >= 1
-- @return number: Integer in [1, n]
local function csprng_intn(n)
  local bytes = M.random_bytes(4)
  local v = string.byte(bytes, 1) * 0x1000000
          + string.byte(bytes, 2) * 0x10000
          + string.byte(bytes, 3) * 0x100
          + string.byte(bytes, 4)
  return (v % n) + 1
end

--- Random selection fallback (simple largest-first with randomization).
-- Used when BnB fails to find an exact match.
-- @param utxos table: Array of {key=string, utxo={value=number, ...}}
-- @param target number: Target amount including fees
-- @return table|nil: Selected UTXOs
function M.select_coins_random(utxos, target)
  -- Shuffle the UTXOs using CSPRNG (OpenSSL RAND_bytes via csprng_intn).
  -- Core uses FastRandomContext for all coin shuffle operations (W88 fix: FIX-45).
  local shuffled = {}
  for i, item in ipairs(utxos) do
    shuffled[i] = item
  end
  for i = #shuffled, 2, -1 do
    local j = csprng_intn(i)
    shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
  end

  -- Select until we have enough
  local selected = {}
  local total = 0
  for _, item in ipairs(shuffled) do
    selected[#selected + 1] = item
    total = total + item.utxo.value
    if total >= target then
      return selected
    end
  end

  return nil  -- Insufficient funds
end

--- Knapsack coin selection (greedy with some randomization).
-- @param utxos table: Array of {key=string, utxo={value=number, ...}}
-- @param target number: Target amount including fees
-- @return table|nil: Selected UTXOs
function M.select_coins_knapsack(utxos, target)
  -- Sort by value descending
  local sorted = {}
  for i, item in ipairs(utxos) do
    sorted[i] = item
  end
  table.sort(sorted, function(a, b) return a.utxo.value > b.utxo.value end)

  -- First pass: try to find a single UTXO close to target
  for _, item in ipairs(sorted) do
    if item.utxo.value >= target and item.utxo.value < target * 2 then
      return {item}
    end
  end

  -- Second pass: greedy selection
  local selected = {}
  local total = 0
  for _, item in ipairs(sorted) do
    if total >= target then break end
    selected[#selected + 1] = item
    total = total + item.utxo.value
  end

  if total >= target then
    return selected
  end

  return nil
end

--- Combined coin selection: tries BnB first, then falls back to knapsack/random.
-- @param utxos table: Array of {key=string, utxo={value=number, ...}}
-- @param target number: Target amount (output + estimated fees)
-- @param fee_rate number: Fee rate in sat/vB
-- @return table|nil: Selected UTXOs
-- @return string: Algorithm used ("bnb", "knapsack", or "random")
function M.select_coins(utxos, target, fee_rate)
  -- Try Branch and Bound first (for changeless transactions)
  local selected = M.select_coins_bnb(utxos, target, fee_rate)
  if selected then
    return selected, "bnb"
  end

  -- Fall back to knapsack
  selected = M.select_coins_knapsack(utxos, target)
  if selected then
    return selected, "knapsack"
  end

  -- Last resort: random selection
  selected = M.select_coins_random(utxos, target)
  if selected then
    return selected, "random"
  end

  return nil, "insufficient_funds"
end

--------------------------------------------------------------------------------
-- Utility Functions
--------------------------------------------------------------------------------

function M.hex_encode(data)
  local hex = {}
  for i = 1, #data do
    hex[i] = string.format("%02x", data:byte(i))
  end
  return table.concat(hex)
end

function M.hex_decode(hex)
  local bytes = {}
  for i = 1, #hex, 2 do
    bytes[#bytes + 1] = string.char(tonumber(hex:sub(i, i + 1), 16))
  end
  return table.concat(bytes)
end

--------------------------------------------------------------------------------
-- BIP32 Extended Key
--------------------------------------------------------------------------------

-- BIP32 extended key structure
function M.extended_key(key, chain_code, depth, parent_fingerprint, child_index, is_private)
  return {
    key = key,                                          -- 32 bytes (private) or 33 bytes (compressed public)
    chain_code = chain_code,                            -- 32 bytes
    depth = depth or 0,                                 -- u8
    parent_fingerprint = parent_fingerprint or "\0\0\0\0",  -- 4 bytes
    child_index = child_index or 0,                     -- u32
    is_private = is_private,
  }
end

-- Derive master key from seed (BIP32)
function M.master_key_from_seed(seed)
  local hmac = crypto.hmac_sha512("Bitcoin seed", seed)
  local key = hmac:sub(1, 32)
  local chain_code = hmac:sub(33, 64)
  return M.extended_key(key, chain_code, 0, "\0\0\0\0", 0, true)
end

--------------------------------------------------------------------------------
-- BIP32 Child Key Derivation
--------------------------------------------------------------------------------

-- secp256k1 curve order n (as bytes, big-endian)
local SECP256K1_ORDER_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

local function hex_to_bytes(hex)
  local bytes = {}
  for i = 1, #hex, 2 do
    bytes[#bytes + 1] = tonumber(hex:sub(i, i + 1), 16)
  end
  return bytes
end

local SECP256K1_ORDER = hex_to_bytes(SECP256K1_ORDER_HEX)

-- Compare two 32-byte big-endian numbers: returns -1, 0, or 1
local function compare_be(a, b)
  for i = 1, 32 do
    local ab = a[i] or 0
    local bb = b[i] or 0
    if ab < bb then return -1 end
    if ab > bb then return 1 end
  end
  return 0
end

-- Add two 32-byte numbers modulo n (secp256k1 order)
local function add_mod_n(a_bytes, b_bytes)
  -- Convert strings to byte arrays (big-endian)
  local a = {}
  local b = {}
  for i = 1, 32 do
    a[i] = a_bytes:byte(i)
    b[i] = b_bytes:byte(i)
  end

  -- Add a + b
  local result = {}
  local carry = 0
  for i = 32, 1, -1 do
    local sum = a[i] + b[i] + carry
    result[i] = sum % 256
    carry = math.floor(sum / 256)
  end

  -- Check if result >= n, if so subtract n
  if carry > 0 or compare_be(result, SECP256K1_ORDER) >= 0 then
    -- Subtract n
    local borrow = 0
    for i = 32, 1, -1 do
      local diff = result[i] - SECP256K1_ORDER[i] - borrow
      if diff < 0 then
        diff = diff + 256
        borrow = 1
      else
        borrow = 0
      end
      result[i] = diff
    end
  end

  -- Convert back to string
  local str = {}
  for i = 1, 32 do
    str[i] = string.char(result[i])
  end
  return table.concat(str)
end

-- Check if key is valid (non-zero and less than n)
local function is_valid_key(key_bytes)
  -- Check if all zeros
  local all_zero = true
  local key = {}
  for i = 1, 32 do
    key[i] = key_bytes:byte(i)
    if key[i] ~= 0 then
      all_zero = false
    end
  end
  if all_zero then return false end

  -- Check if >= n
  if compare_be(key, SECP256K1_ORDER) >= 0 then
    return false
  end

  return true
end

-- BIP32 child key derivation
function M.derive_child(parent, index)
  local hardened = index >= 0x80000000

  if hardened then
    assert(parent.is_private, "Cannot derive hardened child from public key")
  end

  -- BIP-32 depth-byte guard (Core key.cpp:483 CExtKey::Derive /
  -- pubkey.cpp:416 CExtPubKey::Derive: `if (nDepth == 0xFF) return false;`).
  -- The depth field is a single byte; deriving from a depth-255 parent would
  -- produce a child whose serialized depth byte no longer reflects its tree
  -- position. Core refuses the derivation rather than emit a wrong depth-255
  -- child (a saturating/wrapping +1 would do exactly that).
  assert(parent.depth < 0xFF,
    "BIP-32 derivation past max depth 255 (parent already at depth 255)")

  local data
  local index_bytes = string.char(
    bit.band(bit.rshift(index, 24), 0xFF),
    bit.band(bit.rshift(index, 16), 0xFF),
    bit.band(bit.rshift(index, 8), 0xFF),
    bit.band(index, 0xFF)
  )

  if hardened then
    -- Hardened: HMAC-SHA512(Key = chain_code, Data = 0x00 || private_key || index)
    data = "\0" .. parent.key .. index_bytes
  else
    -- Normal: HMAC-SHA512(Key = chain_code, Data = public_key || index)
    local pubkey
    if parent.is_private then
      pubkey = crypto.pubkey_from_privkey(parent.key, true)
    else
      pubkey = parent.key
    end
    data = pubkey .. index_bytes
  end

  local hmac = crypto.hmac_sha512(parent.chain_code, data)
  local il = hmac:sub(1, 32)
  local ir = hmac:sub(33, 64)

  -- P2-2 FIX (W118 G6-BUG-1 2nd carry-forward / W161 BUG-18): per BIP-32
  -- §"Private parent key -> private child key", if parse256(IL) >= n OR the
  -- resulting child key is 0, the derivation is invalid and the caller MUST
  -- "proceed with the next value for i". Bitcoin Core key.cpp::CKey::Derive
  -- implements this AND requires the next i to stay in the same hardened
  -- range — incrementing from 0x7FFFFFFF (last non-hardened) to 0x80000000
  -- (first hardened) silently changes the derivation type and is forbidden.
  -- Wraparound past 0xFFFFFFFF is likewise illegal. is_valid_key() checks
  -- both parse256(IL) >= n AND IL == 0 (over-eager on IL==0 vs the spec but
  -- the differential is ~2^-256 and harmless).
  local function retry_next(reason)
    local next_index = index + 1
    if next_index > 0xFFFFFFFF then
      error("BIP-32 derivation exhausted at index " .. tostring(index) ..
            " (" .. reason .. "); no valid next index")
    end
    if bit.rshift(next_index, 31) ~= bit.rshift(index, 31) then
      error("BIP-32 derivation invalid at index " .. tostring(index) ..
            " (" .. reason .. "); cannot cross hardened boundary on retry")
    end
    return M.derive_child(parent, next_index)
  end

  -- Check that parse256(IL) is in [1, n) per BIP-32.
  if not is_valid_key(il) then
    return retry_next("parse256(IL) invalid (>= n or zero)")
  end

  local child_key
  if parent.is_private then
    -- child_key = (parse256(IL) + parent_key) mod n
    child_key = add_mod_n(il, parent.key)

    -- Check that child key is non-zero (add_mod_n already reduces mod n).
    if not is_valid_key(child_key) then
      return retry_next("child key == 0")
    end
  else
    -- For public key derivation, we'd need point addition
    -- This implementation focuses on private key derivation
    error("Public key derivation not implemented")
  end

  -- Parent fingerprint: first 4 bytes of HASH160(parent public key)
  local parent_pubkey
  if parent.is_private then
    parent_pubkey = crypto.pubkey_from_privkey(parent.key, true)
  else
    parent_pubkey = parent.key
  end
  local fingerprint = crypto.hash160(parent_pubkey):sub(1, 4)

  return M.extended_key(child_key, ir, parent.depth + 1, fingerprint, index, parent.is_private)
end

--------------------------------------------------------------------------------
-- BIP-43 purpose-code → derivation-template table (P2-3)
--
-- Before P2-3 the wallet hard-branched on `address_type == "p2wpkh"` and
-- shipped exactly two derivation helpers (`derive_bip44_key`,
-- `derive_bip84_key`).  That left BIP-49 (P2SH-P2WPKH) and BIP-86 (P2TR)
-- silently broken — setting `address_type = "p2sh-p2wpkh"` or `"p2tr"` fell
-- through to the BIP-44 + P2PKH branch and emitted the WRONG address +
-- script type for the WRONG derivation path.  See `tests/test_w118_wallet.lua`
-- G11-BUG-3 (BIP-49 + BIP-86 derivation absent).
--
-- The refactor here makes purpose-code handling table-driven so adding a
-- new BIP only requires extending `M.PURPOSE_TEMPLATES` (and the
-- corresponding address builder in `M.pubkey_to_address_for_purpose`).
-- The 3 hardcoded if/elseif sites (`unlock`, `generate_address`,
-- `import_privkey`) now consult the table; the old `derive_bip44_key` /
-- `derive_bip84_key` helpers remain as 1-line shims for callers that
-- pre-date the refactor (tests, RPC dispatch, fixture loaders).
--
-- Closes: lunarblock unfreeze plan P2-3 ("Generalize BIP-43 purpose-code
-- handling") — `CORE-PARITY-AUDIT/_lunarblock-unfreeze-plan-2026-05-26.md`.
--------------------------------------------------------------------------------

--- SLIP-0044 coin types per network.
-- Mainnet uses 0', everything else (testnet3/testnet4/regtest/signet) uses
-- 1' per SLIP-0044.  Previously every derivation hardcoded coin_type=0
-- regardless of network (`tests/test_w118_wallet.lua` G10-BUG-2: testnet
-- wallets generated the SAME keys as mainnet, violating SLIP-0044).
--
-- @param network_name string: e.g. "mainnet", "testnet", "testnet4", "regtest"
-- @return number: SLIP-0044 coin_type (0 for mainnet, 1 for testnets)
function M.coin_type_for_network(network_name)
  if network_name == "mainnet" then return 0 end
  return 1
end

--- BIP-43 purpose-code → derivation + address-type template.
--
-- Each entry is keyed by the unhardened purpose number (44/49/84/86) and
-- carries:
--   * `name`         human-readable BIP (used in errors + paths)
--   * `output_type`  Bitcoin output type produced by this BIP — one of
--                    "p2pkh" | "p2sh-p2wpkh" | "p2wpkh" | "p2tr"
--   * `address_type` legacy wallet `address_type` string for back-compat
--                    with existing `wallet.address_type` callers.  This is
--                    the value stored in `key_info.type` and serialised in
--                    `data.address_type` on disk.
--   * `bip_number`   the BIP number, for tags + tests
M.PURPOSE_TEMPLATES = {
  [44] = {
    name         = "BIP-44 legacy P2PKH",
    output_type  = "p2pkh",
    address_type = "p2pkh",
    bip_number   = 44,
  },
  [49] = {
    name         = "BIP-49 P2SH-wrapped P2WPKH",
    output_type  = "p2sh-p2wpkh",
    address_type = "p2sh-p2wpkh",
    bip_number   = 49,
  },
  [84] = {
    name         = "BIP-84 native P2WPKH",
    output_type  = "p2wpkh",
    address_type = "p2wpkh",
    bip_number   = 84,
  },
  [86] = {
    name         = "BIP-86 P2TR key-path",
    output_type  = "p2tr",
    address_type = "p2tr",
    bip_number   = 86,
  },
}

--- Core-compat RPC synonyms for address_type. Bitcoin Core's getnewaddress
-- accepts {legacy, p2sh-segwit, bech32, bech32m}; we translate those to our
-- internal {p2pkh, p2sh-p2wpkh, p2wpkh, p2tr} canonical strings so a
-- Core-compatible RPC client can drive lunarblock without changing its
-- vocabulary. Extending PURPOSE_TEMPLATES does NOT automatically extend
-- this synonym map (synonyms are an RPC-surface concern, not a
-- derivation-template concern).
M.ADDRESS_TYPE_SYNONYMS = {
  ["legacy"]      = "p2pkh",
  ["p2sh-segwit"] = "p2sh-p2wpkh",
  ["bech32"]      = "p2wpkh",
  ["bech32m"]     = "p2tr",
}

--- Reverse map: address_type string → purpose number.
-- Built lazily once on first lookup; rebuilt only if PURPOSE_TEMPLATES is
-- mutated (extending the table at runtime is supported by `M.add_purpose`).
local _address_type_to_purpose = nil
local function _build_addr_to_purpose()
  local t = {}
  for purpose, tmpl in pairs(M.PURPOSE_TEMPLATES) do
    t[tmpl.address_type] = purpose
  end
  return t
end

--- Normalise an address_type string by translating Core RPC synonyms to
-- our internal canonical form. Idempotent: canonical strings pass through.
-- @param address_type string|nil
-- @return string|nil canonical address_type
function M.canonical_address_type(address_type)
  if address_type == nil then return nil end
  return M.ADDRESS_TYPE_SYNONYMS[address_type] or address_type
end

--- Look up the purpose number for a given wallet `address_type` string.
-- Accepts both internal canonical strings (p2pkh / p2sh-p2wpkh / p2wpkh /
-- p2tr) AND Core's RPC synonyms (legacy / p2sh-segwit / bech32 / bech32m).
-- @param address_type string: canonical or Core-synonym address type
-- @return number|nil: purpose number, or nil if address_type unknown
function M.purpose_for_address_type(address_type)
  if not _address_type_to_purpose then
    _address_type_to_purpose = _build_addr_to_purpose()
  end
  local canonical = M.canonical_address_type(address_type)
  return _address_type_to_purpose[canonical]
end

--- Look up the wallet `address_type` string for a given purpose number.
-- @param purpose number: 44 | 49 | 84 | 86
-- @return string|nil: address_type, or nil if purpose unknown
function M.address_type_for_purpose(purpose)
  local tmpl = M.PURPOSE_TEMPLATES[purpose]
  if not tmpl then return nil end
  return tmpl.address_type
end

--- Register a new BIP-43 purpose-code template at runtime.
-- Future-proofing hook: extending the PURPOSE_TEMPLATES table from outside
-- this module (e.g. from a downstream plugin adding a new BIP) needs to
-- invalidate the cached reverse map.
-- @param purpose number
-- @param tmpl    table with name/output_type/address_type/bip_number
function M.add_purpose(purpose, tmpl)
  assert(type(purpose) == "number" and purpose >= 0 and purpose < 0x80000000,
    "purpose must be an unhardened uint32")
  assert(type(tmpl) == "table" and tmpl.output_type and tmpl.address_type,
    "purpose template must have output_type + address_type")
  M.PURPOSE_TEMPLATES[purpose] = tmpl
  _address_type_to_purpose = nil  -- invalidate cache
end

--- Derive a BIP-43-style HD child key: m/purpose'/coin_type'/account'/change/index
--
-- Generalises `derive_bip44_key` / `derive_bip84_key`.  Every step is
-- hardened down to `account'`; `change` and `index` are non-hardened, per
-- BIP-44 §"Path levels".
--
-- @param master    extended_key: BIP-32 master extended private key
-- @param purpose   number: BIP-43 purpose code (44/49/84/86; unhardened)
-- @param coin_type number: SLIP-0044 coin type (0 mainnet, 1 testnet)
-- @param account   number: account index (unhardened, will be hardened here)
-- @param change    number: 0 = external receive, 1 = internal change
-- @param index     number: address index within the chain
-- @return extended_key: derived child extended private key
function M.derive_for_purpose(master, purpose, coin_type, account, change, index)
  assert(M.PURPOSE_TEMPLATES[purpose],
    "unsupported BIP-43 purpose code " .. tostring(purpose) ..
    "; known purposes: " .. table.concat(M.list_purposes(), ", "))
  local p   = M.derive_child(master,    0x80000000 + purpose)    -- purpose'
  local c   = M.derive_child(p,         0x80000000 + coin_type)  -- coin_type'
  local a   = M.derive_child(c,         0x80000000 + account)    -- account'
  local chn = M.derive_child(a,         change)                  -- change
  return       M.derive_child(chn,      index)                   -- index
end

--- Enumerate registered purpose codes (sorted ascending) for error messages
-- and validation.
-- @return table: sorted array of purpose numbers (as strings, for joining)
function M.list_purposes()
  local out = {}
  for p, _ in pairs(M.PURPOSE_TEMPLATES) do out[#out + 1] = tostring(p) end
  table.sort(out, function(a, b) return tonumber(a) < tonumber(b) end)
  return out
end

--- Enumerate registered wallet `address_type` strings (sorted) for error
-- messages and the deriveaddresses / getnewaddress RPC validators.
-- @return table: sorted array of address_type strings
function M.list_address_types()
  local out = {}
  for _, tmpl in pairs(M.PURPOSE_TEMPLATES) do out[#out + 1] = tmpl.address_type end
  table.sort(out)
  return out
end

--- Derive the network-appropriate address for `pubkey` under purpose `purpose`.
--
-- BIP-44 → P2PKH (`pubkey_to_p2pkh`)
-- BIP-49 → P2SH-wrap of P2WPKH redeem script
-- BIP-84 → native P2WPKH
-- BIP-86 → P2TR key-path (tweaks internal key per BIP-341 with empty merkle root)
--
-- @param purpose      number: BIP-43 purpose code
-- @param pubkey       string: 33-byte compressed pubkey (caller's responsibility)
-- @param network_name string: "mainnet" | "testnet" | "regtest" | "signet"
-- @return string: encoded address
function M.pubkey_to_address_for_purpose(purpose, pubkey, network_name)
  local tmpl = M.PURPOSE_TEMPLATES[purpose]
  assert(tmpl, "unsupported BIP-43 purpose code " .. tostring(purpose))
  network_name = network_name or "mainnet"

  if tmpl.output_type == "p2pkh" then
    return address.pubkey_to_p2pkh(pubkey, network_name)

  elseif tmpl.output_type == "p2wpkh" then
    return address.pubkey_to_p2wpkh(pubkey, network_name)

  elseif tmpl.output_type == "p2sh-p2wpkh" then
    -- BIP-49: redeem script = OP_0 <hash160(pubkey)>, address = P2SH(redeem)
    local h = crypto.hash160(pubkey)
    local redeem = script.make_p2wpkh_script(h)
    return address.script_to_p2sh(redeem, network_name)

  elseif tmpl.output_type == "p2tr" then
    -- BIP-86 key-path: internal_xonly = pubkey[1:33] (strip parity byte),
    -- tweak = tagged_hash("TapTweak", internal_xonly), output_key = tweak_pubkey(internal, tweak).
    -- Per BIP-86 the merkle root is empty so the tweak is over just the
    -- 32-byte x-only internal key (no script-tree).
    local internal_xonly = pubkey:sub(2, 33)
    assert(#internal_xonly == 32,
      "P2TR requires a 33-byte compressed pubkey to extract the 32-byte x-only key")
    local tweak = crypto.tagged_hash("TapTweak", internal_xonly)
    local output_xonly = crypto.tweak_pubkey(internal_xonly, tweak)
    if not output_xonly then
      error("BIP-86 TapTweak failed for derived pubkey")
    end
    return address.xonly_pubkey_to_p2tr(output_xonly, network_name)

  else
    error("unhandled output_type '" .. tostring(tmpl.output_type) ..
          "' for purpose " .. tostring(purpose))
  end
end

--------------------------------------------------------------------------------
-- BIP44 / BIP84 helpers — back-compat shims around derive_for_purpose
--
-- Pre-P2-3 callers (tests + a handful of internal sites) called these
-- directly.  Keep them as 1-line shims to avoid breaking the API surface.
-- New code should call `M.derive_for_purpose` instead.
--
-- NOTE: these shims preserve the historical coin_type=0 hardcoding so they
-- byte-match the previous behaviour for mainnet callers.  Callers that
-- need network-aware coin_type should call `derive_for_purpose` with the
-- network's coin_type (see `coin_type_for_network`).
--------------------------------------------------------------------------------

-- Derive a BIP44 path: m/44'/0'/account'/change/index
function M.derive_bip44_key(master, account, change, index)
  return M.derive_for_purpose(master, 44, 0, account, change, index)
end

-- Derive a BIP84 path: m/84'/0'/account'/change/index (native segwit)
function M.derive_bip84_key(master, account, change, index)
  return M.derive_for_purpose(master, 84, 0, account, change, index)
end

-- Derive a BIP49 path: m/49'/0'/account'/change/index (P2SH-wrapped segwit)
function M.derive_bip49_key(master, account, change, index)
  return M.derive_for_purpose(master, 49, 0, account, change, index)
end

-- Derive a BIP86 path: m/86'/0'/account'/change/index (P2TR key-path)
function M.derive_bip86_key(master, account, change, index)
  return M.derive_for_purpose(master, 86, 0, account, change, index)
end

-- Parse a derivation path string like "m/44'/0'/0'/0/0"
function M.parse_path(path)
  local components = {}
  for component in path:gmatch("([^/]+)") do
    if component ~= "m" then
      local hardened = component:match("'$") or component:match("h$")
      local num_str = component:gsub("['h]$", "")
      local num = tonumber(num_str, 10)
      if num then
        if hardened then
          num = num + 0x80000000
        end
        components[#components + 1] = num
      end
    end
  end
  return components
end

-- Derive key from path
function M.derive_path(master, path)
  local components = M.parse_path(path)
  local key = master
  for _, index in ipairs(components) do
    key = M.derive_child(key, index)
  end
  return key
end

--------------------------------------------------------------------------------
-- Wallet Object
--------------------------------------------------------------------------------

local Wallet = {}
Wallet.__index = Wallet

function M.new(network, storage)
  local self = setmetatable({}, Wallet)
  self.network = network or consensus.networks.mainnet
  self.storage = storage
  self.master_key = nil
  self.encrypted_master_key = nil  -- Encrypted master key (if locked)
  self.encryption_salt = nil       -- Salt for key derivation
  self.is_encrypted = false        -- Whether wallet is encrypted
  self.is_locked = true            -- Whether wallet is locked (keys unavailable)
  self.keys = {}                   -- address -> {privkey, pubkey, path, type}
  -- IMPORTED keys (importprivkey): a registry of addresses whose private key
  -- did NOT come from the HD master key. They live in self.keys like any other
  -- key (so every scan/sign/own-script path sees them), but are ALSO recorded
  -- here, held apart from the HD keychain, so a restore-from-seed / reseed flow
  -- (which rebuilds self.keys from the master key) can re-merge them and never
  -- silently wipe them. Maps address -> {privkey, pubkey, compressed, type, label}.
  self.imported_keys = {}
  -- WATCH-ONLY descriptors (importdescriptors on a disable_private_keys wallet).
  -- Maps a classified address -> {desc, label, internal, spk_hex, kind, ts}. The
  -- wallet owns these scripts for crediting (scan_utxos / _owned_addr_for_spk
  -- consult this set alongside self.keys) but holds NO private key for them, so
  -- they are unspendable (sendtoaddress refuses). Mirrors Bitcoin Core's
  -- DescriptorScriptPubKeyMan for a watch-only descriptor wallet. Persisted in
  -- serialize() / reinstalled in M.load() so the watch set round-trips a restart.
  self.watch_addrs = {}
  -- WALLET_FLAG_DISABLE_PRIVATE_KEYS, derived purely from createwallet's
  -- disable_private_keys (Core rpc/wallet.cpp:381-383). private_keys_enabled =
  -- NOT this flag (getwalletinfo private_keys_enabled, rpc/wallet.cpp:98). Kept
  -- as an explicit field — independent of lock state / master_key presence — so
  -- a reloaded watch-only wallet can still tell it is watch-only (an unlocked
  -- keyed wallet and a watch-only wallet both have a usable key set otherwise).
  self.private_keys_enabled = true
  self.addresses = {}              -- ordered list of addresses
  self.utxos = {}                  -- outpoint_key -> {value, script_pubkey, address, txid, vout}
  -- Has this wallet ever scanned the chain for its own funds?  A wallet
  -- restored from seed / created blank derives its keys deterministically but
  -- does NOT yet know which of those scripts are funded on-chain — exactly
  -- like Bitcoin Core, where a fresh import shows balance 0 until
  -- rescanblockchain (CWallet::ScanForWalletTransactions) walks the chain.
  -- scan_utxos / scan_history leave the ledger EMPTY while this is false, so
  -- getbalance / listunspent report 0 until an explicit rescan (or a chain-
  -- mutating wallet op — generatetoaddress / sendtoaddress — which implies the
  -- wallet is live) flips it true.
  self.scanned = false
  -- How far this wallet's ledger has been reconciled against the chain. Persisted
  -- across restarts (serialize / load) so startup re-scans only the gap to the
  -- current tip rather than from genesis, and a crash mid-IBD can resume.
  -- Mirrors Bitcoin Core CWallet::m_last_block_processed_height.
  self.last_synced_height = 0
  -- Set true by any in-memory mutation that must survive an unclean restart
  -- (keypool advance, label, imported key, ScanBlock credit/debit). save_if_dirty
  -- flushes only when this is set, so the hot block-connect path is cheap.
  self._dirty = false
  -- Remembered persistence path (set by save()/load()); lets save-on-mutation
  -- re-flush without the caller re-supplying the path.
  self._save_path = nil
  self.pending_utxos = {}          -- Unconfirmed UTXOs (in mempool)
  self.spent_pending = {}          -- Outpoints spent in pending transactions
  self.transactions = {}           -- txid_hex -> {tx, height, time, fee}
  -- WALLET TRANSACTION HISTORY (listtransactions / gettransaction). Built by
  -- scan_history() from the connected chain — one entry per wallet-relevant
  -- tx, mirroring Bitcoin Core's mapWallet + CWalletTx accounting.
  self.tx_history = {}             -- txid_hex -> history entry (see scan_history)
  self.confirmed_balance = 0       -- Balance from confirmed transactions (incl. immature coinbase)
  self.spendable_balance = 0       -- Confirmed balance excluding immature coinbase
  self.immature_balance = 0        -- Sum of confirmed-but-immature coinbase values
  self.unconfirmed_balance = 0     -- Balance from unconfirmed transactions
  self.next_external_index = 0     -- BIP44 external chain index
  self.next_internal_index = 0     -- BIP44 internal (change) chain index
  self.gap_limit = 20              -- BIP44 address gap limit
  self.account = 0
  self.address_type = "p2wpkh"     -- Default address type
  self.fee_estimator = nil         -- Optional fee estimator
  self.mempool = nil               -- Optional mempool reference
  -- BIP-39 mnemonic (only present when wallet was created/imported via
  -- import_mnemonic or create_with_mnemonic). 12/15/18/21/24 ASCII words.
  -- Encrypted at rest alongside the master key when the wallet is locked.
  self.mnemonic_words = nil        -- table of words, or nil
  self.encrypted_mnemonic = nil    -- ciphertext (if encrypted + locked)
  self.bip39_passphrase = nil      -- BIP-39 passphrase used at import (NOT
                                   -- the wallet-encryption passphrase). For
                                   -- now stored in-memory only; required to
                                   -- re-derive the seed if a future caller
                                   -- wants to migrate to a different node.
  return self
end

--- Set the fee estimator for this wallet.
-- @param estimator FeeEstimator: Fee estimator instance from fee.lua
function Wallet:set_fee_estimator(estimator)
  self.fee_estimator = estimator
end

--- Set the mempool for transaction submission.
-- @param mempool Mempool: Mempool instance from mempool.lua
function Wallet:set_mempool(mempool)
  self.mempool = mempool
end

-- Create a new wallet from a random seed
function M.create(network, storage, passphrase)
  local wallet = M.new(network, storage)

  -- Generate 32 bytes of random seed using secure random
  local seed = M.random_bytes(32)

  wallet.master_key = M.master_key_from_seed(seed)
  wallet.is_locked = false

  -- Encrypt if passphrase provided
  if passphrase and #passphrase > 0 then
    wallet:encrypt(passphrase)
  else
    wallet.is_encrypted = false
  end

  -- Generate initial addresses
  wallet:generate_addresses(wallet.gap_limit)

  return wallet, seed
end

-- Restore wallet from seed
function M.from_seed(seed, network, storage, passphrase)
  local wallet = M.new(network, storage)
  wallet.master_key = M.master_key_from_seed(seed)
  wallet.is_locked = false

  -- Encrypt if passphrase provided
  if passphrase and #passphrase > 0 then
    wallet:encrypt(passphrase)
  else
    wallet.is_encrypted = false
  end

  wallet:generate_addresses(wallet.gap_limit)
  return wallet
end

--------------------------------------------------------------------------------
-- BIP-39 mnemonic import / generate
--------------------------------------------------------------------------------

--- Import a wallet from a BIP-39 mnemonic.
-- The mnemonic is validated (word membership + checksum), converted to a
-- 64-byte seed via PBKDF2-HMAC-SHA512(2048, "mnemonic"+bip39_passphrase, 64),
-- and fed into BIP-32 master_key_from_seed. The mnemonic itself is stored
-- on the wallet (encrypted at rest if a wallet-encryption passphrase is
-- set) so that getwalletmnemonic can return it for backup.
--
-- @param mnemonic       string|table: BIP-39 mnemonic (12/15/18/21/24 words)
-- @param bip39_passphrase string|nil: BIP-39 passphrase (default "").
--                                     Distinct from wallet_passphrase!
-- @param network        table|nil: network params (default mainnet)
-- @param storage        table|nil: storage backend
-- @param wallet_passphrase string|nil: AES wallet-encryption passphrase
--                                      (encrypts mnemonic + master key at rest)
-- @return Wallet|nil, string|nil: wallet on success, nil + err on failure
function M.import_mnemonic(mnemonic, bip39_passphrase, network, storage, wallet_passphrase)
  bip39_passphrase = bip39_passphrase or ""

  -- Normalise mnemonic to a list of words.
  local words
  if type(mnemonic) == "string" then
    words = {}
    for w in mnemonic:gmatch("%S+") do words[#words + 1] = w end
  elseif type(mnemonic) == "table" then
    words = mnemonic
  else
    return nil, "mnemonic must be a string or list of words"
  end

  -- Validate (word membership + checksum) BEFORE building the wallet, so a
  -- typo'd mnemonic doesn't end up persisted. The haskoin failure mode of
  -- the day was a silent bypass; we want a hard error here.
  local ok, err = bip39.validate_mnemonic(words)
  if not ok then
    return nil, err
  end

  local seed = bip39.mnemonic_to_seed(words, bip39_passphrase)
  if #seed ~= 64 then
    return nil, "bip39: unexpected seed length " .. #seed
  end

  local wallet = M.new(network, storage)
  wallet.master_key = M.master_key_from_seed(seed)
  wallet.mnemonic_words = words
  wallet.bip39_passphrase = bip39_passphrase
  wallet.is_locked = false

  if wallet_passphrase and #wallet_passphrase > 0 then
    wallet:encrypt(wallet_passphrase)
  else
    wallet.is_encrypted = false
  end

  wallet:generate_addresses(wallet.gap_limit)
  return wallet
end

--- Create a brand-new wallet with a freshly generated BIP-39 mnemonic.
-- The caller MUST back up the returned mnemonic — the wallet stores it
-- (encrypted if wallet_passphrase is set) but it is the user's job to
-- write it down off-machine. Returns the wallet AND the mnemonic words
-- so the caller can display them once at create time.
-- @param n_words           number|nil: 12/15/18/21/24 (default 24)
-- @param bip39_passphrase  string|nil: BIP-39 passphrase
-- @param network           table|nil
-- @param storage           table|nil
-- @param wallet_passphrase string|nil: AES wallet-encryption passphrase
-- @return Wallet, table:    wallet, mnemonic words
function M.create_with_mnemonic(n_words, bip39_passphrase, network, storage, wallet_passphrase)
  n_words = n_words or 24
  bip39_passphrase = bip39_passphrase or ""

  local words = bip39.generate_mnemonic(n_words)
  local wallet, err = M.import_mnemonic(words, bip39_passphrase, network, storage, wallet_passphrase)
  if not wallet then
    -- Should be impossible — we just generated the mnemonic — but propagate.
    error("create_with_mnemonic: " .. tostring(err))
  end
  return wallet, words
end

--- Get the BIP-39 mnemonic for this wallet.
-- The wallet must be unlocked. Returns nil + err if the wallet was not
-- created via import_mnemonic / create_with_mnemonic (e.g. legacy random
-- 32-byte-seed wallets predate BIP-39 wiring and have no mnemonic).
-- WARNING TO CALLERS: this leaks the wallet's master secret. Treat the
-- returned words like the on-disk wallet file: never log, never serialize,
-- only display for one-time user backup.
-- @return table|nil, string|nil: list of words, or nil + err
function Wallet:get_mnemonic()
  if self.is_locked then
    return nil, "Wallet is locked"
  end
  if not self.mnemonic_words then
    return nil, "Wallet was not created from a BIP-39 mnemonic"
  end
  return self.mnemonic_words
end

--------------------------------------------------------------------------------
-- Wallet Encryption
--------------------------------------------------------------------------------

--- Encrypt the wallet with a passphrase.
-- @param passphrase string: The encryption passphrase
function Wallet:encrypt(passphrase)
  if not self.master_key then
    error("No master key to encrypt")
  end

  -- Generate salt
  self.encryption_salt = M.random_bytes(M.CRYPTO_SALT_SIZE)

  -- Derive key from passphrase
  local key, iv = M.derive_key(passphrase, self.encryption_salt)

  -- Encrypt master key and chain code
  local plaintext = self.master_key.key .. self.master_key.chain_code
  self.encrypted_master_key = M.aes_encrypt(plaintext, key, iv)

  -- If the wallet has an associated BIP-39 mnemonic, encrypt it with the
  -- same key/IV so a stolen wallet file cannot leak the recovery phrase.
  -- Storing the mnemonic at all is a deliberate trade-off: it lets the
  -- user run getwalletmnemonic for backup, at the cost of ciphertext that
  -- decrypts to the recovery phrase under the wallet passphrase.
  if self.mnemonic_words then
    local m_plain = table.concat(self.mnemonic_words, " ")
    self.encrypted_mnemonic = M.aes_encrypt(m_plain, key, iv)
  else
    self.encrypted_mnemonic = nil
  end

  self.is_encrypted = true
  self.is_locked = false  -- Still unlocked after encryption
end

--- Lock the wallet (clear private keys from memory).
function Wallet:lock()
  if not self.is_encrypted then
    error("Cannot lock unencrypted wallet")
  end

  -- Clear private keys from memory
  if self.master_key then
    self.master_key.key = nil
    self.master_key = nil
  end

  for addr, key_info in pairs(self.keys) do
    key_info.privkey = nil
  end

  -- Clear mnemonic from memory; encrypted_mnemonic stays for re-unlock.
  self.mnemonic_words = nil
  self.bip39_passphrase = nil

  self.is_locked = true
end

--- Unlock the wallet with passphrase.
-- @param passphrase string: The encryption passphrase
-- @return boolean: true on success
-- @return string|nil: Error message on failure
function Wallet:unlock(passphrase)
  if not self.is_encrypted then
    return true  -- Not encrypted, already unlocked
  end

  if not self.encrypted_master_key or not self.encryption_salt then
    return false, "Wallet encryption data missing"
  end

  -- Derive key from passphrase
  local key, iv = M.derive_key(passphrase, self.encryption_salt)

  -- Decrypt master key
  local plaintext, err = M.aes_decrypt(self.encrypted_master_key, key, iv)
  if not plaintext then
    return false, err or "Decryption failed"
  end

  if #plaintext ~= 64 then
    return false, "Invalid decrypted key length"
  end

  -- Restore master key
  local seed_key = plaintext:sub(1, 32)
  local chain_code = plaintext:sub(33, 64)
  self.master_key = M.extended_key(seed_key, chain_code, 0, "\0\0\0\0", 0, true)

  -- Restore mnemonic if present (encrypted under same key/IV).
  if self.encrypted_mnemonic then
    local m_plain, m_err = M.aes_decrypt(self.encrypted_mnemonic, key, iv)
    if m_plain then
      local words = {}
      for w in m_plain:gmatch("%S+") do words[#words + 1] = w end
      -- Cheap sanity: 12/15/18/21/24 words. If corrupt, drop without
      -- failing unlock — the master key is the source of truth.
      if ({[12]=true,[15]=true,[18]=true,[21]=true,[24]=true})[#words] then
        self.mnemonic_words = words
      end
    else
      -- Same caveat: unlock should not fail just because the mnemonic
      -- ciphertext is unreadable.
      _ = m_err
    end
  end

  -- Regenerate private keys for all addresses.  Each key_info.type is the
  -- wallet `address_type` string that was active when the key was first
  -- generated; look up the matching BIP-43 purpose and re-derive at the
  -- network's SLIP-0044 coin_type.  Imported keys (index == -1) have no
  -- derivation path — skip them; their privkey is restored from the
  -- encrypted store directly elsewhere.
  local coin_type = M.coin_type_for_network(self.network.name)
  for _, key_info in pairs(self.keys) do
    if key_info.change ~= nil and key_info.index >= 0 then
      local purpose = M.purpose_for_address_type(key_info.type)
      if not purpose then
        -- Unknown address_type — skip rather than crash unlock; the privkey
        -- stays nil so any spend attempt fails loudly with "Private key not
        -- available".  Logging would be nice but unlock() is on the hot path.
      else
        local derived = M.derive_for_purpose(
          self.master_key, purpose, coin_type,
          self.account, key_info.change, key_info.index
        )
        key_info.privkey = derived.key
      end
    end
  end

  self.is_locked = false
  return true
end

--- Change the wallet passphrase.
-- @param old_passphrase string: Current passphrase
-- @param new_passphrase string: New passphrase
-- @return boolean: true on success
-- @return string|nil: Error message on failure
function Wallet:change_passphrase(old_passphrase, new_passphrase)
  -- Unlock with old passphrase
  local ok, err = self:unlock(old_passphrase)
  if not ok then
    return false, err
  end

  -- Re-encrypt with new passphrase
  self:encrypt(new_passphrase)
  return true
end

--------------------------------------------------------------------------------
-- Address Generation
--------------------------------------------------------------------------------

function Wallet:generate_addresses(count)
  for i = 0, count - 1 do
    self:generate_address(0, self.next_external_index + i)  -- external
    self:generate_address(1, self.next_internal_index + i)  -- internal (change)
  end
  self.next_external_index = self.next_external_index + count
  self.next_internal_index = self.next_internal_index + count
end

function Wallet:generate_address(change, index)
  -- P2-3: look up the BIP-43 purpose from the wallet's address_type and
  -- derive via the table-driven path.  This is the ONLY place that maps
  -- address_type → purpose for new-address generation; unlock() does the
  -- same lookup for existing addresses (so the two paths cannot drift).
  local purpose = M.purpose_for_address_type(self.address_type)
  if not purpose then
    error(string.format(
      "unsupported wallet.address_type %q; known types: %s (Core synonyms: %s)",
      tostring(self.address_type),
      table.concat(M.list_address_types(), ", "),
      "legacy / p2sh-segwit / bech32 / bech32m"
    ))
  end
  local coin_type = M.coin_type_for_network(self.network.name)
  -- Store the canonical address_type on the key record so unlock() (and
  -- any future code that reads key_info.type) always sees a value that's
  -- in PURPOSE_TEMPLATES, not a Core RPC synonym.
  local canonical_type = M.canonical_address_type(self.address_type)

  local key    = M.derive_for_purpose(
    self.master_key, purpose, coin_type, self.account, change, index
  )
  local pubkey = crypto.pubkey_from_privkey(key.key, true)
  local addr   = M.pubkey_to_address_for_purpose(purpose, pubkey, self.network.name)

  self.keys[addr] = {
    privkey = key.key,
    pubkey = pubkey,
    path = string.format("m/%d'/%d'/%d'/%d/%d",
      purpose, coin_type, self.account, change, index),
    type = canonical_type,
    change = change,
    index = index,
  }
  self.addresses[#self.addresses + 1] = addr
  return addr
end

function Wallet:get_new_address()
  local addr = self:generate_address(0, self.next_external_index)
  self.next_external_index = self.next_external_index + 1
  -- Keypool advance MUST survive a crash: if we hand this address out, take a
  -- payment to it, then lose the index on an unclean restart, the wallet would
  -- re-derive the SAME index for the next request and the prior payment becomes
  -- unrecoverable. Persist immediately (Core flushes the keypool on every
  -- top-up). save_if_dirty no-ops when no path is remembered (e.g. unit tests).
  self:mark_dirty()
  self:save_if_dirty()
  return addr
end

function Wallet:get_change_address()
  local addr = self:generate_address(1, self.next_internal_index)
  self.next_internal_index = self.next_internal_index + 1
  -- A change address is just as crash-sensitive as a receive address: losing
  -- the internal index on an unclean restart means the next send re-derives the
  -- same change script, so persist the advance immediately.
  self:mark_dirty()
  self:save_if_dirty()
  return addr
end

--------------------------------------------------------------------------------
-- UTXO Scanning and Balance Tracking
--------------------------------------------------------------------------------

--- Scan the UTXO set for wallet addresses (confirmed balance).
-- @param chain_state table: Optional chain state for current tip info
function Wallet:scan_utxos(chain_state)
  self.utxos = {}
  self.confirmed_balance = 0
  -- spendable_balance excludes immature coinbases; immature_balance is the sum
  -- of confirmed-but-immature coinbase values. Mirrors Bitcoin Core's split of
  -- the trusted/spendable balance vs. m_mine_immature (wallet/receive.cpp).
  self.spendable_balance = 0
  self.immature_balance = 0

  -- A wallet that has never scanned the chain (fresh restore-from-seed / blank
  -- import) reports an empty ledger until rescanblockchain runs — Core parity
  -- (CWallet::ScanForWalletTransactions). Leaving the cleared ledger in place
  -- keeps getbalance / listunspent at 0 until the wallet is explicitly rescanned
  -- or performs a chain-mutating op (which flips self.scanned true).
  if not self.scanned then
    return
  end

  if not self.storage then
    return  -- No storage, skip scan
  end

  -- Scan UTXO set for our addresses
  local storage_mod = require("lunarblock.storage")
  local utxo_mod = require("lunarblock.utxo")
  local iter = self.storage.iterator(storage_mod.CF.UTXO)
  iter.seek_to_first()

  local tip_height = chain_state and chain_state.tip_height or 0

  while iter.valid() do
    local key = iter.key()
    local data = iter.value()
    local entry = utxo_mod.deserialize_utxo_entry(data)

    -- Check if this output's scriptPubKey matches any of our addresses
    local script_type, hash_or_program = script.classify_script(entry.script_pubkey)
    local addr = nil

    if script_type == "p2wpkh" then
      local hrp = self.network.bech32_hrp or address.BECH32_HRP[self.network.name] or "bc"
      addr = address.segwit_encode(hrp, 0, hash_or_program)
    elseif script_type == "p2tr" then
      -- P2-4: discover our own P2TR coins in the confirmed UTXO set.
      addr = address.xonly_pubkey_to_p2tr(hash_or_program, self.network.name)
    elseif script_type == "p2pkh" then
      local version = self.network.pubkey_address_prefix
      addr = address.base58check_encode(version, hash_or_program)
    end

    if addr and (self.keys[addr] or self.watch_addrs[addr]) then
      -- Parse outpoint from key (32 bytes txid + 4 bytes vout)
      local txid = types.hash256(key:sub(1, 32))
      local reader = serialize.buffer_reader(key:sub(33, 36))
      local vout = reader.read_u32le()

      -- Calculate confirmations
      local confirmations = 0
      if tip_height > 0 and entry.height > 0 then
        confirmations = tip_height - entry.height + 1
      end

      self.utxos[key] = {
        value = entry.value,
        script_pubkey = entry.script_pubkey,
        address = addr,
        txid = txid,
        vout = vout,
        height = entry.height,
        is_coinbase = entry.is_coinbase,
        confirmations = confirmations,
      }
      self.confirmed_balance = self.confirmed_balance + entry.value
      -- Split into spendable vs. immature. A coinbase is spendable only once
      -- it has COINBASE_MATURITY+1 (=101) confirmations; below that it is
      -- immature and excluded from the spendable/trusted balance (Core
      -- getbalance behaviour). Non-coinbase outputs are always spendable.
      if entry.is_coinbase and confirmations < consensus.COINBASE_MATURITY + 1 then
        self.immature_balance = self.immature_balance + entry.value
      else
        self.spendable_balance = self.spendable_balance + entry.value
      end
    end

    iter.next()
  end
  iter.destroy()
end

--- Scan mempool for unconfirmed transactions affecting the wallet.
-- @param mempool table: Mempool instance
function Wallet:scan_mempool(mempool)
  if not mempool then return end

  self.pending_utxos = {}
  self.spent_pending = {}
  self.unconfirmed_balance = 0

  for txid_hex, entry in pairs(mempool.entries) do
    local tx = entry.tx

    -- Check inputs (spending our confirmed UTXOs)
    for _, inp in ipairs(tx.inputs) do
      local key = inp.prev_out.hash.bytes .. string.char(
        bit.band(inp.prev_out.index, 0xFF),
        bit.band(bit.rshift(inp.prev_out.index, 8), 0xFF),
        bit.band(bit.rshift(inp.prev_out.index, 16), 0xFF),
        bit.band(bit.rshift(inp.prev_out.index, 24), 0xFF)
      )
      if self.utxos[key] then
        -- This input spends one of our confirmed UTXOs
        self.spent_pending[key] = txid_hex
        self.unconfirmed_balance = self.unconfirmed_balance - self.utxos[key].value
      end
    end

    -- Check outputs (receiving to our addresses)
    local txid = entry.txid
    for vout_idx, out in ipairs(tx.outputs) do
      local script_type, hash_or_program = script.classify_script(out.script_pubkey)
      local addr = nil

      if script_type == "p2wpkh" then
        local hrp = self.network.bech32_hrp or address.BECH32_HRP[self.network.name] or "bc"
        addr = address.segwit_encode(hrp, 0, hash_or_program)
      elseif script_type == "p2tr" then
        -- P2-4: discover our own P2TR coins in pending mempool txs too.
        addr = address.xonly_pubkey_to_p2tr(hash_or_program, self.network.name)
      elseif script_type == "p2pkh" then
        local version = self.network.pubkey_address_prefix
        addr = address.base58check_encode(version, hash_or_program)
      end

      if addr and self.keys[addr] then
        local key = txid.bytes .. string.char(
          bit.band(vout_idx - 1, 0xFF),
          bit.band(bit.rshift(vout_idx - 1, 8), 0xFF),
          bit.band(bit.rshift(vout_idx - 1, 16), 0xFF),
          bit.band(bit.rshift(vout_idx - 1, 24), 0xFF)
        )
        self.pending_utxos[key] = {
          value = out.value,
          script_pubkey = out.script_pubkey,
          address = addr,
          txid = txid,
          vout = vout_idx - 1,
          height = 0,
          is_coinbase = false,
          confirmations = 0,
        }
        self.unconfirmed_balance = self.unconfirmed_balance + out.value
      end
    end
  end
end

--------------------------------------------------------------------------------
-- WALLET TRANSACTION HISTORY (listtransactions / gettransaction)
--
-- Mirrors Bitcoin Core's mapWallet + CWalletTx accounting (wallet/receive.cpp
-- CachedTxGetAmounts; wallet/rpc/transactions.cpp ListTransactions /
-- gettransaction). The wallet keeps no durable history ledger you can trust
-- after a disk loss, so — exactly like scan_utxos rebuilds the UTXO view by
-- walking the connected chain — scan_history rebuilds the transaction history
-- by walking every connected block in chain order and classifying each tx as a
-- wallet credit (an output paying one of our scripts) and/or a wallet debit
-- (an input spending one of our earlier outputs). A block-disconnect (reorg)
-- is handled implicitly: scan_history rebuilds from height 1..tip on every
-- call, so a rolled-back block's txs simply vanish from the rebuilt history.
--------------------------------------------------------------------------------

--- Classify a scriptPubKey to one of our wallet addresses (if any). Shared by
--- scan_utxos / scan_mempool / scan_history. Returns nil when not ours.
-- @param script_pubkey string
-- @return string|nil address
function Wallet:_owned_addr_for_spk(script_pubkey)
  if not script_pubkey then return nil end
  local script_type, hash_or_program = script.classify_script(script_pubkey)
  local addr
  if script_type == "p2wpkh" then
    local hrp = self.network.bech32_hrp or address.BECH32_HRP[self.network.name] or "bc"
    addr = address.segwit_encode(hrp, 0, hash_or_program)
  elseif script_type == "p2tr" then
    addr = address.xonly_pubkey_to_p2tr(hash_or_program, self.network.name)
  elseif script_type == "p2pkh" then
    local version = self.network.pubkey_address_prefix
    addr = address.base58check_encode(version, hash_or_program)
  end
  if addr and (self.keys[addr] or self.watch_addrs[addr]) then return addr end
  return nil
end

--- Register a watch-only descriptor's classified address into the owned-script
--- view. The wallet credits funds paid to this address (scan_utxos /
--- _owned_addr_for_spk) but holds no private key, so it cannot spend them.
--- Mirrors DescriptorScriptPubKeyMan::AddDescriptorKey for a watch-only desc.
-- @param addr string  the classified address the descriptor resolves to
-- @param info table   {desc, label, internal, spk_hex, kind, ts}
function Wallet:add_watch_descriptor(addr, info)
  self.watch_addrs[addr] = info
  local seen = false
  for _, a in ipairs(self.addresses) do
    if a == addr then seen = true; break end
  end
  if not seen then
    self.addresses[#self.addresses + 1] = addr
  end
  self:mark_dirty()
end

--- Is this address watched (watch-only descriptor) by the wallet?
-- @param addr string
-- @return boolean
function Wallet:is_watch_addr(addr)
  return self.watch_addrs[addr] ~= nil
end

--- Rebuild the wallet transaction history by walking the connected chain.
--
-- Builds self.tx_history: txid_hex -> {
--   txid, txid_hex, tx, height, blockhash (hash256), block_index, time,
--   is_coinbase,
--   credit            = sum of output value to us (satoshis),
--   debit             = sum of input value from us (satoshis),
--   fee               = debit - value_out (satoshis, only when debit>0 i.e. ours),
--   received[]        = {address, vout, amount(sat)}     -- outputs to us
--   sent[]            = {address, vout, amount(sat), fee} -- present iff debit>0
-- }
-- credit/debit/received/sent mirror Core's CachedTxGetAmounts exactly:
--   * fee is computed only when we are the sender (debit>0) as debit-value_out.
--   * "sent" entries enumerate EVERY non-change output of a from-me tx
--     (include_change=false → outputs paying our own keys are skipped).
--   * "received" entries enumerate every output paying one of our keys.
-- @param chain_state ChainState
-- @param mempool table|nil (unused for confirmed history; reserved)
function Wallet:scan_history(chain_state, mempool)
  self.tx_history = {}
  -- Same gate as scan_utxos: an unscanned wallet has no rediscovered history
  -- until rescanblockchain walks the chain (Core parity).
  if not self.scanned then return end
  if not self.storage or not chain_state then return end

  local tip_height = chain_state.tip_height or 0
  if tip_height < 0 then tip_height = 0 end

  -- outpoint_key (32-byte txid + 4-byte LE vout) -> {value, address} for every
  -- wallet-owned output seen so far. Built incrementally so a later tx's input
  -- can be recognised as spending one of our coins (chain order guarantees the
  -- creating output is processed before the spending input).
  local owned_out = {}

  local function outpoint_key(txid_bytes, vout)
    return txid_bytes .. string.char(
      bit.band(vout, 0xFF),
      bit.band(bit.rshift(vout, 8), 0xFF),
      bit.band(bit.rshift(vout, 16), 0xFF),
      bit.band(bit.rshift(vout, 24), 0xFF))
  end

  for height = 0, tip_height do
    local bhash = self.storage.get_hash_by_height(height)
    if bhash then
      local block = self.storage.get_block(bhash)
      if block and block.transactions then
        local btime = (block.header and block.header.timestamp) or 0
        for tx_index = 1, #block.transactions do
          local tx = block.transactions[tx_index]
          local txid = validation.compute_txid(tx)
          local txid_hex = types.hash256_hex(txid)

          -- Coinbase detection (validation.lua: single input, null prevout
          -- hash, index 0xFFFFFFFF).
          local is_coinbase = false
          if #tx.inputs == 1 then
            local inp = tx.inputs[1]
            if inp.prev_out and inp.prev_out.index == 0xFFFFFFFF
               and inp.prev_out.hash and inp.prev_out.hash.bytes == string.rep("\0", 32) then
              is_coinbase = true
            end
          end

          -- Debit: inputs spending our previously-seen outputs.
          local debit = 0
          if not is_coinbase then
            for _, inp in ipairs(tx.inputs) do
              if inp.prev_out and inp.prev_out.hash then
                local k = outpoint_key(inp.prev_out.hash.bytes, inp.prev_out.index)
                local owned = owned_out[k]
                if owned then debit = debit + owned.value end
              end
            end
          end

          -- Credit + record each owned output; also register owned outputs for
          -- future debit detection.
          local credit = 0
          local received = {}
          local value_out = 0
          for vout_idx = 1, #tx.outputs do
            local out = tx.outputs[vout_idx]
            value_out = value_out + out.value
            local addr = self:_owned_addr_for_spk(out.script_pubkey)
            if addr then
              local vout = vout_idx - 1
              credit = credit + out.value
              received[#received + 1] = {
                address = addr, vout = vout, amount = out.value,
              }
              owned_out[outpoint_key(txid.bytes, vout)] = {
                value = out.value, address = addr,
              }
            end
          end

          if credit > 0 or debit > 0 then
            -- Fee + sent[] only when we are the sender (debit>0). Mirrors Core
            -- CachedTxGetAmounts: nFee = nDebit - nValueOut when nDebit>0.
            local fee = 0
            local sent = {}
            if debit > 0 then
              fee = debit - value_out
              if fee < 0 then fee = 0 end
              for vout_idx = 1, #tx.outputs do
                local out = tx.outputs[vout_idx]
                -- include_change=false: skip outputs that pay back to us
                -- (change). Core's OutputIsChange excludes our own outputs from
                -- the "send" list for a from-me tx.
                if not self:_owned_addr_for_spk(out.script_pubkey) then
                  local dest_addr = self:_address_label_for_spk(out.script_pubkey)
                  sent[#sent + 1] = {
                    address = dest_addr, vout = vout_idx - 1,
                    amount = out.value, fee = fee,
                  }
                end
              end
            end

            self.tx_history[txid_hex] = {
              txid = txid,
              txid_hex = txid_hex,
              tx = tx,
              height = height,
              blockhash = bhash,
              block_index = tx_index - 1,
              time = btime,
              is_coinbase = is_coinbase,
              credit = credit,
              debit = debit,
              value_out = value_out,
              fee = fee,
              received = received,
              sent = sent,
            }
          end
        end
      end
    end
  end
end

--- Mark the wallet as having scanned the chain. Called by rescanblockchain and
--- by chain-mutating wallet ops (generatetoaddress / sendtoaddress) which imply
--- the wallet is live. Once set, scan_utxos / scan_history credit normally.
function Wallet:mark_scanned()
  self.scanned = true
  -- Persist the live flag so a reload does not regress to "balance 0 until
  -- rescan". Cheap and crash-safe.
  self:mark_dirty()
  self:save_if_dirty()
end

--- Rescan the connected chain for this wallet's own funds.
--
-- The BACKWARD counterpart of the block-connect-driven scan: walk the existing
-- chain (the chainstate UTXO set + the block history) and credit every output
-- paying a wallet-owned script into the wallet UTXO ledger + transaction
-- history, debiting spent inputs. This is the REAL wallet rescan — distinct
-- from scantxoutset, which scans the chainstate without ever touching a wallet.
--
-- Mirrors Bitcoin Core CWallet::ScanForWalletTransactions
-- (wallet/rpc/transactions.cpp::rescanblockchain): start_height defaults to 0,
-- stop_height defaults to the active tip; the range is validated
-- (0 <= start <= tip, start <= stop <= tip) and the {start_height, stop_height}
-- actually scanned is returned. lunarblock's scan_utxos walks the whole
-- chainstate UTXO set and scan_history walks 0..tip, so the range here governs
-- the Core return shape + validation; both scans are idempotent and rebuild
-- the ledger from scratch, so a from-genesis rescan never double-counts.
--
-- @param chain_state ChainState
-- @param mempool table|nil
-- @param start_height number|nil (default 0)
-- @param stop_height  number|nil (default tip)
-- @return table|nil {start_height, stop_height}, or nil + err string
function Wallet:rescan(chain_state, mempool, start_height, stop_height)
  if not chain_state then return nil, "no chain state available" end
  local tip = chain_state.tip_height or 0
  if tip < 0 then tip = 0 end

  start_height = start_height or 0
  if stop_height == nil then stop_height = tip end

  if type(start_height) ~= "number" or start_height < 0 then
    return nil, "Invalid start_height"
  end
  if start_height > tip then
    return nil, "Invalid start_height (above tip)"
  end
  if type(stop_height) ~= "number" then
    return nil, "Invalid stop_height"
  end
  if stop_height < start_height then
    return nil, "stop_height must be greater than start_height"
  end
  if stop_height > tip then stop_height = tip end

  -- This wallet now knows the chain; credit normally from here on.
  self.scanned = true

  -- Rebuild the UTXO ledger + balances from the chainstate UTXO set, and the
  -- transaction history from the connected blocks. Both rebuild from scratch.
  self:scan_utxos(chain_state)
  self:scan_history(chain_state, mempool)
  if mempool then
    self:scan_mempool(mempool)
  end

  -- A from-tip rescan has reconciled the ledger up to `stop_height`.
  self.last_synced_height = stop_height
  self:mark_dirty()

  return {start_height = start_height, stop_height = stop_height}
end

--- Is any output of this tx paid to a wallet-owned script, or does any input
--- spend one of our coins? Used by scan_block to decide whether a connected
--- block touches the wallet at all (cheap relevance filter before the heavier
--- ledger refresh). Mirrors Bitcoin Core CWallet::AddToWalletIfInvolvingMe.
function Wallet:_block_tx_is_mine(tx)
  -- Outputs paying us.
  for _, out in ipairs(tx.outputs) do
    if self:_owned_addr_for_spk(out.script_pubkey) then
      return true
    end
  end
  -- Inputs spending our coins (recognised via our current UTXO ledger).
  for _, inp in ipairs(tx.inputs) do
    if inp.prev_out and inp.prev_out.hash then
      local k = inp.prev_out.hash.bytes .. string.char(
        bit.band(inp.prev_out.index, 0xFF),
        bit.band(bit.rshift(inp.prev_out.index, 8), 0xFF),
        bit.band(bit.rshift(inp.prev_out.index, 16), 0xFF),
        bit.band(bit.rshift(inp.prev_out.index, 24), 0xFF))
      if self.utxos[k] then
        return true
      end
    end
  end
  return false
end

--- Per-block wallet hook, called from the live block-connect loop (and the
--- IBD/P2P path), NOT just the mining/RPC path. Mirrors Bitcoin Core
--- CWallet::blockConnected / ScanBlock: for each connected block, credit
--- outputs paying us and debit inputs spending our coins, then advance the
--- last-synced height so a restart resumes from here.
--
-- Implementation note: lunarblock's ledger is derived from the chainstate UTXO
-- set (scan_utxos) + connected-block history (scan_history), both idempotent
-- and cheap relative to a network round-trip. So rather than maintaining a
-- second, drift-prone incremental accounting path, scan_block re-derives the
-- ledger from the (already-updated) chainstate whenever the block is relevant.
-- The relevance filter keeps the common "block has nothing for us" case O(txs).
--
-- @param chain_state ChainState (already advanced to include this block)
-- @param block table   the just-connected block
-- @param height number  the height this block was connected at
-- @param mempool table|nil
function Wallet:scan_block(chain_state, block, height, mempool)
  if type(height) ~= "number" then
    height = (chain_state and chain_state.tip_height) or self.last_synced_height
  end

  -- A wallet that has never been scanned stays at balance 0 until an explicit
  -- rescan (Core parity); but we still track how far the chain has advanced so
  -- a later rescanblockchain / mark_scanned knows the tip. Don't credit yet.
  local relevant = false
  if self.scanned and block and block.transactions then
    for _, tx in ipairs(block.transactions) do
      if self:_block_tx_is_mine(tx) then
        relevant = true
        break
      end
    end
    if relevant then
      -- Re-derive the ledger from the updated chainstate + block history.
      self:scan_utxos(chain_state)
      self:scan_history(chain_state, mempool)
      if mempool then self:scan_mempool(mempool) end
    end
  end

  -- Always advance the reconciled height + mark dirty so the periodic flush
  -- persists progress (a relevant block changes balances; an irrelevant one
  -- still moves last_synced_height forward).
  if height and height > (self.last_synced_height or 0) then
    self.last_synced_height = height
  end
  self:mark_dirty()
  return relevant
end

--- Bring the wallet up to the chain tip on startup. Persisted last_synced_height
--- tells us how far we already reconciled; if the tip moved ahead while we were
--- down (or we crashed mid-IBD), re-derive the ledger and record the new tip.
--- Cheap no-op when already at tip. Called once from main.lua after load.
-- @param chain_state ChainState
-- @param mempool table|nil
function Wallet:reconcile_to_tip(chain_state, mempool)
  if not chain_state then return end
  local tip = chain_state.tip_height or 0
  if tip < 0 then tip = 0 end
  local from = self.last_synced_height or 0
  if from >= tip then
    -- Already reconciled; still refresh confirmations against the current tip.
    if self.scanned then self:scan_utxos(chain_state) end
    return
  end
  -- We are behind the tip: reconcile the gap. scan_utxos/scan_history rebuild
  -- the whole ledger from chainstate (idempotent), which closes the gap exactly.
  if self.scanned then
    self:scan_utxos(chain_state)
    self:scan_history(chain_state, mempool)
    if mempool then self:scan_mempool(mempool) end
  end
  self.last_synced_height = tip
  self:mark_dirty()
end

--- Best-effort destination address for an arbitrary scriptPubKey (recipient of
--- a send). Returns the encoded address, or nil for unspendable / unknown.
-- @param script_pubkey string
-- @return string|nil
function Wallet:_address_label_for_spk(script_pubkey)
  if not script_pubkey then return nil end
  local ok, script_type, hash_or_program = pcall(script.classify_script, script_pubkey)
  if not ok then return nil end
  if script_type == "p2wpkh" then
    local hrp = self.network.bech32_hrp or address.BECH32_HRP[self.network.name] or "bc"
    return address.segwit_encode(hrp, 0, hash_or_program)
  elseif script_type == "p2wsh" then
    local hrp = self.network.bech32_hrp or address.BECH32_HRP[self.network.name] or "bc"
    return address.segwit_encode(hrp, 0, hash_or_program)
  elseif script_type == "p2tr" then
    return address.xonly_pubkey_to_p2tr(hash_or_program, self.network.name)
  elseif script_type == "p2pkh" then
    return address.base58check_encode(self.network.pubkey_address_prefix, hash_or_program)
  elseif script_type == "p2sh" then
    return address.base58check_encode(self.network.script_address_prefix, hash_or_program)
  end
  return nil
end

--- Build the per-entry "transaction description" fields shared by
--- listtransactions and gettransaction (Core WalletTxToJSON), as a plain table.
-- @param h history entry
-- @param tip_height number
-- @return table
function Wallet:_tx_description(h, tip_height)
  local confirmations = 0
  if tip_height and tip_height > 0 and h.height and h.height > 0 then
    confirmations = tip_height - h.height + 1
  elseif tip_height and h.height == 0 then
    -- genesis-height coinbase (regtest height 0 is genesis; real coinbases
    -- start at height 1 so this branch is for completeness only).
    confirmations = tip_height + 1
  end
  local desc = {
    confirmations = confirmations,
    blockhash = types.hash256_hex(h.blockhash),
    blockheight = h.height,
    blockindex = h.block_index,
    blocktime = h.time,
    txid = h.txid_hex,
    time = h.time,
    timereceived = h.time,
  }
  if h.is_coinbase then desc.generated = true end
  return desc
end

--- listtransactions backing: return up to `count` recent wallet history
--- entries (most recent first), skipping `skip`, Core-shaped. Each on-chain tx
--- expands to one entry per "send" output then one per "receive" output, just
--- like Core's ListTransactions.
-- @param count number
-- @param skip number
-- @param tip_height number
-- @return table array of entries
function Wallet:get_transactions(count, skip, tip_height)
  count = count or 10
  skip = skip or 0

  -- Stable order: by (height, block_index). Core lists oldest→newest then the
  -- RPC slices the tail (most recent `count`). We collect ordered then slice.
  local ordered = {}
  for _, h in pairs(self.tx_history) do ordered[#ordered + 1] = h end
  table.sort(ordered, function(a, b)
    if a.height ~= b.height then return a.height < b.height end
    return a.block_index < b.block_index
  end)

  local entries = {}
  for _, h in ipairs(ordered) do
    local desc = self:_tx_description(h, tip_height)
    -- Sent rows first (Core emits listSent before listReceived).
    if h.debit > 0 then
      for _, s in ipairs(h.sent) do
        local e = {
          address = s.address,
          category = "send",
          amount = -(s.amount) / consensus.COIN,
          vout = s.vout,
          fee = -(s.fee) / consensus.COIN,
          abandoned = false,
        }
        for k, v in pairs(desc) do e[k] = v end
        entries[#entries + 1] = e
      end
    end
    -- Received rows.
    for _, r in ipairs(h.received) do
      local category
      if h.is_coinbase then
        if desc.confirmations < 1 then
          category = "orphan"
        elseif desc.confirmations < consensus.COINBASE_MATURITY + 1 then
          category = "immature"
        else
          category = "generate"
        end
      else
        category = "receive"
      end
      local e = {
        address = r.address,
        category = category,
        amount = r.amount / consensus.COIN,
        vout = r.vout,
        abandoned = false,
      }
      for k, v in pairs(desc) do e[k] = v end
      entries[#entries + 1] = e
    end
  end

  -- Most-recent-`count` window (Core: ListTransactions over the whole map then
  -- the RPC keeps the last `count` after `skip` from the end).
  local total = #entries
  local result = {}
  -- Slice: take entries [total-skip-count+1 .. total-skip] (1-based), clamped.
  local last = total - skip
  local first = last - count + 1
  if first < 1 then first = 1 end
  for i = first, last do
    if entries[i] then result[#result + 1] = entries[i] end
  end
  return result
end

--- gettransaction backing: return the full Core-shaped object for one txid, or
--- nil if the tx is not wallet-relevant.
-- @param txid_hex string
-- @param tip_height number
-- @return table|nil
function Wallet:get_transaction_detail(txid_hex, tip_height)
  local h = self.tx_history[txid_hex]
  if not h then return nil end

  -- amount = nNet - nFee  where nNet = credit - debit and, for a from-me tx,
  -- nFee_gettx = value_out - debit (NEGATIVE). For a pure send this reduces to
  -- credit - value_out = -(amount sent). (Core gettransaction.)
  local net = h.credit - h.debit
  local from_me = h.debit > 0
  local gettx_fee = from_me and (h.value_out - h.debit) or 0  -- negative when from-me
  local amount = (net - gettx_fee) / consensus.COIN

  local result = {
    amount = amount,
  }
  if from_me then
    result.fee = gettx_fee / consensus.COIN  -- negative (paid)
  end

  local desc = self:_tx_description(h, tip_height)
  for k, v in pairs(desc) do result[k] = v end

  -- details[] : Core calls ListTransactions(fLong=false) — send rows then
  -- receive rows, each WITHOUT the description fields.
  local details = {}
  if from_me then
    for _, s in ipairs(h.sent) do
      details[#details + 1] = {
        address = s.address,
        category = "send",
        amount = -(s.amount) / consensus.COIN,
        vout = s.vout,
        fee = -(s.fee) / consensus.COIN,
        abandoned = false,
      }
    end
  end
  for _, r in ipairs(h.received) do
    local category
    if h.is_coinbase then
      if desc.confirmations < 1 then
        category = "orphan"
      elseif desc.confirmations < consensus.COINBASE_MATURITY + 1 then
        category = "immature"
      else
        category = "generate"
      end
    else
      category = "receive"
    end
    details[#details + 1] = {
      address = r.address,
      category = category,
      amount = r.amount / consensus.COIN,
      vout = r.vout,
      abandoned = false,
    }
  end
  result.details = details

  -- hex: full witness serialization of the tx.
  local ok_hex, raw = pcall(serialize.serialize_transaction, h.tx, true)
  if ok_hex and raw then
    result.hex = M.hex_encode(raw)
  end

  return result
end

--- Get available UTXOs (confirmed and optionally unconfirmed).
-- @param include_unconfirmed boolean: Whether to include pending UTXOs (default true)
-- @param min_confirmations number: Minimum confirmations required (default 0)
-- @return table: Array of {key=string, utxo=table}
function Wallet:get_available_utxos(include_unconfirmed, min_confirmations)
  include_unconfirmed = include_unconfirmed ~= false
  min_confirmations = min_confirmations or 0

  local result = {}

  -- Add confirmed UTXOs that are not spent in pending transactions
  for key, utxo in pairs(self.utxos) do
    if not self.spent_pending[key] then
      if utxo.confirmations >= min_confirmations then
        -- Coinbase maturity (matches the node's own consensus rule, and
        -- Bitcoin Core CWallet::GetTxBlocksToMaturity / CheckTxInputs):
        -- a coinbase is spendable only once it has COINBASE_MATURITY+1 (=101)
        -- confirmations, i.e. chain depth >= 101 (tip - height >= 100). A
        -- coinbase with exactly COINBASE_MATURITY (100) confirmations is still
        -- IMMATURE and would be rejected by mempool.lua as
        -- "spending immature coinbase"; never select it here. Non-coinbase
        -- UTXOs are spendable normally.
        if utxo.is_coinbase then
          if (utxo.confirmations or 0) >= consensus.COINBASE_MATURITY + 1 then
            result[#result + 1] = {key = key, utxo = utxo}
          end
        else
          result[#result + 1] = {key = key, utxo = utxo}
        end
      end
    end
  end

  -- Add pending UTXOs if requested
  if include_unconfirmed and min_confirmations == 0 then
    for key, utxo in pairs(self.pending_utxos) do
      result[#result + 1] = {key = key, utxo = utxo}
    end
  end

  return result
end

--------------------------------------------------------------------------------
-- Transaction Creation and Signing
--------------------------------------------------------------------------------

--- Sign a P2WSH input given a witnessScript and one-or-more signing keys.
--
-- Computes the BIP-143 segwit-v0 sighash with the witnessScript as scriptCode,
-- signs once per `signKeys` entry, and returns the witness stack ready to be
-- assigned to `tx.inputs[inputIdx + 1].witness`. For a bare single-key
-- witnessScript (`<pubkey> OP_CHECKSIG`) the stack is `[sig, witnessScript]`.
-- For an M-of-N CHECKMULTISIG witnessScript the stack is
-- `[OP_0_dummy, sig_1, ..., sig_M, witnessScript]` where signatures are
-- ordered by canonical witnessScript pubkey order (Core's
-- `ProduceSignature`/`SignStep` semantics).
--
-- Reference: bitcoin-core/src/script/sign.cpp::ProduceSignature
--            BIP-143 (segwit v0 sighash + P2WSH witness layout).
--
-- @param tx            transaction
-- @param inputIdx      number: 0-based input index
-- @param witnessScript string: raw witnessScript bytes (also used as scriptCode)
-- @param value         number: prevout value in satoshis
-- @param signKeys      table: array of {privkey=string, pubkey=string}.
--                      For multisig, supply each cosigner whose key the
--                      caller controls (caller can pass <M keys for partial
--                      signing — finalization is the caller's responsibility).
-- @param hashType      number: SIGHASH byte (default SIGHASH.ALL)
-- @return table: witness stack (array of byte-strings) on success.
-- @return nil, string: error string on failure.
function M.sign_input_p2wsh(tx, inputIdx, witnessScript, value, signKeys, hashType)
  hashType = hashType or consensus.SIGHASH.ALL
  if type(witnessScript) ~= "string" or #witnessScript == 0 then
    return nil, "witnessScript must be non-empty bytes"
  end
  if type(signKeys) ~= "table" or #signKeys == 0 then
    return nil, "signKeys must be a non-empty array"
  end

  local sighash = validation.signature_hash_segwit_v0(
    tx, inputIdx, witnessScript, value, hashType)

  -- Detect M-of-N multisig.
  local m, _n, ms_pubkeys = script.parse_multisig_script(witnessScript)

  if m and ms_pubkeys then
    -- Multisig: produce signatures for each provided key, ordered by canonical
    -- witnessScript pubkey order. Stop once we have M.
    local sig_by_pk = {}
    for _, k in ipairs(signKeys) do
      if not k.privkey or not k.pubkey then
        return nil, "signKeys entry missing privkey/pubkey"
      end
      local sig, err = crypto.ecdsa_sign(k.privkey, sighash)
      if not sig then return nil, err or "signing failed" end
      sig_by_pk[k.pubkey] = sig .. string.char(hashType)
    end

    local stack = {""}  -- OP_0 dummy element (CHECKMULTISIG off-by-one)
    local collected = 0
    for _, pk in ipairs(ms_pubkeys) do
      if collected >= m then break end
      local s = sig_by_pk[pk]
      if s then
        stack[#stack + 1] = s
        collected = collected + 1
      end
    end
    if collected < m then
      return nil, string.format(
        "P2WSH multisig: have %d signatures, need %d", collected, m)
    end
    stack[#stack + 1] = witnessScript
    return stack
  end

  -- Single-key witnessScript (e.g. `<pubkey> OP_CHECKSIG`).
  local k = signKeys[1]
  if not k.privkey then
    return nil, "signKeys[1] missing privkey"
  end
  local sig, err = crypto.ecdsa_sign(k.privkey, sighash)
  if not sig then return nil, err or "signing failed" end
  return {sig .. string.char(hashType), witnessScript}
end

--------------------------------------------------------------------------------
-- BIP-86 Taproot key-path signer (P2-4)
--------------------------------------------------------------------------------

-- BIP-341 SIGHASH_DEFAULT (0x00). When this hash type is used the BIP-341
-- witness omits the trailing sighash flag byte (the wire format is a bare
-- 64-byte Schnorr signature instead of 65 bytes). All other taproot hash
-- types DO carry the trailing byte. Lunarblock defaults to SIGHASH_DEFAULT
-- — that is what BIP-86 wallets emit and what every block-explorer +
-- standard tooling expects in production.
M.SIGHASH_DEFAULT = 0x00

--- Sign a single input as a BIP-86 P2TR key-path spend.
--
-- Mirrors Core MutableTransactionSignatureCreator + CreateTaprootScriptSig
-- (script/sign.cpp + script/signingprovider.cpp) for the BIP-86 key-path
-- branch, and the rustoshi reference signer at
-- crates/wallet/src/wallet.rs::sign_p2tr_input (W27-C P0-1). Wires the
-- TapTweak + tweaked-key Schnorr signing primitives that already live in
-- src/crypto.lua (M.tagged_hash, M.taproot_tweak_seckey, M.schnorr_sign)
-- but were never composed into a signer until this fix. Closes the
-- "write-only Taproot wallets" P0 from W161 (impl-triage 2026-05-19):
-- before this fix a user could deposit to a lunarblock P2TR address but
-- could never spend, because `_sign_inputs` fell through to the legacy
-- ECDSA branch and emitted a DER-encoded sig the network rejects on a
-- v1 segwit output.
--
-- BIP-86 specifies: merkle_root is empty (key-path only, no script tree).
-- The TapTweak preimage is therefore just the 32-byte internal x-only key.
--
-- @param tx           transaction: tx being signed (segwit shape required).
-- @param input_index  number: 0-based input index being signed.
-- @param prev_outputs table: array of {value, script_pubkey} for EVERY
--                    input of `tx` (BIP-341 commits to all prevouts, not
--                    just the one being signed). Same shape consumed by
--                    validation.signature_hash_taproot.
-- @param privkey32   string: 32-byte secret key (the BIP-32 derived priv
--                    BEFORE the TapTweak — this function applies the
--                    tweak; callers must NOT pre-tweak).
-- @param hash_type   number|nil: SIGHASH byte (default M.SIGHASH_DEFAULT
--                    = 0x00, the BIP-86 default). Per BIP-341, the
--                    witness omits the trailing hash byte iff hash_type
--                    == 0x00, so callers asking for any other type get a
--                    65-byte witness item.
-- @param aux_rand32  string|nil: 32 bytes of fresh randomness. Defaults
--                    to crypto.random_bytes(32) — production Core does
--                    the same in MutableTransactionSignatureCreator via
--                    GetRandBytes. Pass an explicit zero-string only for
--                    BIP-340 vector reproduction.
-- @return string|nil 64- or 65-byte witness item on success, or
--                    nil + err on failure.
function M.sign_input_p2tr_keypath(tx, input_index, prev_outputs, privkey32, hash_type, aux_rand32)
  hash_type = hash_type or M.SIGHASH_DEFAULT
  if type(privkey32) ~= "string" or #privkey32 ~= 32 then
    return nil, "privkey32 must be a 32-byte string"
  end
  if type(prev_outputs) ~= "table" or #prev_outputs ~= #tx.inputs then
    return nil, "prev_outputs must be one entry per tx input"
  end

  -- 1. Derive the internal x-only pubkey FROM the secret key. Done before
  --    the tweak so we hash the BIP-86 preimage (the internal key — Core
  --    interpreter.cpp:1693 / BIP-86 wallet vector).
  local internal_pub33 = crypto.pubkey_from_privkey(privkey32, true)
  if not internal_pub33 or #internal_pub33 ~= 33 then
    return nil, "pubkey_from_privkey failed"
  end
  local internal_xonly = internal_pub33:sub(2, 33)
  if #internal_xonly ~= 32 then
    return nil, "internal_xonly extraction failed"
  end

  -- 2. BIP-86 TapTweak — merkle_root absent (key-path-only). Preimage is
  --    JUST the 32-byte internal key (no concatenation). Identical to the
  --    address-side derivation in pubkey_to_address_for_purpose; the two
  --    sites MUST stay in lock-step or funds burn (silently sending to a
  --    tweaked output the wallet can never reproduce on the sign side).
  local tweak = crypto.tagged_hash("TapTweak", internal_xonly)
  if not tweak or #tweak ~= 32 then
    return nil, "TapTweak hash failed"
  end

  -- 3. Apply tweak to the secret key. Uses libsecp256k1's keypair_xonly_
  --    tweak_add (the in-place mirror of pubkey-side tweak_add), which
  --    correctly handles BIP-340's even-Y normalisation (Core key.cpp
  --    SignSchnorr applies the same step transparently via Keypair).
  local tweaked_priv, terr = crypto.taproot_tweak_seckey(privkey32, tweak)
  if not tweaked_priv then
    return nil, "taproot_tweak_seckey failed: " .. tostring(terr)
  end

  -- 4. BIP-341 sighash. ext_flag=0 selects the key-path commitment shape
  --    (no tapleaf_hash / no codesep_pos).
  local sighash, sherr = validation.signature_hash_taproot(
    tx, input_index, hash_type, prev_outputs, 0, nil, nil, nil
  )
  if not sighash then
    return nil, "signature_hash_taproot failed: " .. tostring(sherr)
  end

  -- 5. Fresh aux_rand per BIP-340 §"Default Signing" — randomises the
  --    nonce, hardens against fault attacks. Pass-through allowed for
  --    deterministic vector reproduction.
  aux_rand32 = aux_rand32 or crypto.random_bytes(32)

  local sig64, signerr = crypto.schnorr_sign(tweaked_priv, sighash, aux_rand32)
  if not sig64 then
    return nil, "schnorr_sign failed: " .. tostring(signerr)
  end

  -- 6. BIP-341 wire format: hash_type byte appended ONLY if non-default.
  --    SIGHASH_DEFAULT (0x00) → 64-byte witness item.
  --    Anything else → 65 bytes (sig || hash_type).
  if hash_type == M.SIGHASH_DEFAULT then
    return sig64
  else
    return sig64 .. string.char(hash_type)
  end
end

--- Estimate fee rate for a transaction.
-- @param conf_target number: Desired confirmation target in blocks (default 6)
-- @return number: Fee rate in sat/vB
function Wallet:estimate_fee_rate(conf_target)
  conf_target = conf_target or 6

  if self.fee_estimator then
    local fee_rate = self.fee_estimator:estimate_smart_fee(conf_target)
    if fee_rate then
      return fee_rate
    end
  end

  -- Fallback: use default minimum relay fee
  return 1  -- 1 sat/vB
end

--- Create and sign a transaction.
-- @param recipients table: List of {address=string, amount=number (satoshis)}
-- @param options table: Optional settings {fee_rate=number, change_address=string, conf_target=number, include_unconfirmed=boolean, subtract_fee_from_amount=boolean}
-- @return transaction|nil: Signed transaction
-- @return number|string: Fee in satoshis, or error message
-- @return string|nil: Coin selection algorithm used
function Wallet:create_transaction(recipients, options, change_address_legacy)
  options = options or {}

  -- Handle legacy API: create_transaction(recipients, fee_rate, change_address)
  if type(options) == "number" then
    options = {fee_rate = options, change_address = change_address_legacy}
  end

  -- Check wallet is unlocked
  if self.is_encrypted and self.is_locked then
    return nil, "Wallet is locked"
  end

  -- 1. Calculate total output amount
  local total_out = 0
  for _, r in ipairs(recipients) do
    assert(r.amount > 0, "Invalid output amount")
    assert(consensus.is_valid_amount(r.amount), "Amount exceeds MAX_MONEY")
    total_out = total_out + r.amount
  end

  -- 2. Get fee rate
  local fee_rate = options.fee_rate or self:estimate_fee_rate(options.conf_target)

  -- 3. Get available UTXOs
  local include_unconfirmed = options.include_unconfirmed ~= false
  local available_utxos = self:get_available_utxos(include_unconfirmed)

  if #available_utxos == 0 then
    return nil, "No available UTXOs"
  end

  -- 4. Estimate transaction size for initial target
  -- P2WPKH input: ~68 vbytes, output: ~31 vbytes, overhead: ~11 vbytes
  local est_input_vsize = 68
  local est_output_vsize = 31
  local est_overhead = 11

  -- Initial target (output + estimated fees for minimum inputs)
  local min_inputs = 1
  local est_vsize = est_overhead + min_inputs * est_input_vsize + (#recipients + 1) * est_output_vsize
  local initial_target = total_out + math.ceil(est_vsize * fee_rate)

  -- 5. Run coin selection
  local selected, algo = M.select_coins(available_utxos, initial_target, fee_rate)
  if not selected then
    return nil, "Insufficient funds"
  end

  -- 6. Calculate actual fee with selected inputs
  local total_in = 0
  for _, item in ipairs(selected) do
    total_in = total_in + item.utxo.value
  end

  est_vsize = est_overhead + #selected * est_input_vsize + (#recipients + 1) * est_output_vsize
  local fee = math.ceil(est_vsize * fee_rate)

  -- Verify we have enough
  if total_in < total_out + fee then
    -- Try again with higher target
    initial_target = total_out + fee
    selected, algo = M.select_coins(available_utxos, initial_target, fee_rate)
    if not selected then
      return nil, "Insufficient funds"
    end
    total_in = 0
    for _, item in ipairs(selected) do
      total_in = total_in + item.utxo.value
    end
    est_vsize = est_overhead + #selected * est_input_vsize + (#recipients + 1) * est_output_vsize
    fee = math.ceil(est_vsize * fee_rate)
  end

  -- 7. Build transaction
  local inputs = {}
  for _, item in ipairs(selected) do
    inputs[#inputs + 1] = types.txin(
      types.outpoint(item.utxo.txid, item.utxo.vout),
      "",  -- Empty scriptSig for segwit
      0xFFFFFFFD  -- Signal RBF (BIP125)
    )
  end

  local outputs = {}
  for _, r in ipairs(recipients) do
    local addr_type, program = address.decode_address(r.address, self.network.name)
    local spk
    if addr_type == "p2wpkh" then
      spk = script.make_p2wpkh_script(program)
    elseif addr_type == "p2pkh" then
      spk = script.make_p2pkh_script(program)
    elseif addr_type == "p2sh" then
      spk = script.make_p2sh_script(program)
    elseif addr_type == "p2wsh" then
      spk = script.make_p2wsh_script(program)
    elseif addr_type == "p2tr" then
      spk = script.make_p2tr_script(program)
    else
      return nil, "Unsupported address type: " .. tostring(addr_type)
    end
    outputs[#outputs + 1] = types.txout(r.amount, spk)
  end

  -- Change output
  local change = total_in - total_out - fee
  if change > M.DUST_THRESHOLD then
    local change_address = options.change_address or self:get_change_address()
    local change_type, change_program = address.decode_address(change_address, self.network.name)
    local change_spk
    if change_type == "p2wpkh" then
      change_spk = script.make_p2wpkh_script(change_program)
    elseif change_type == "p2wsh" then
      change_spk = script.make_p2wsh_script(change_program)
    elseif change_type == "p2tr" then
      change_spk = script.make_p2tr_script(change_program)
    else
      change_spk = script.make_p2pkh_script(change_program)
    end
    outputs[#outputs + 1] = types.txout(change, change_spk)
  else
    fee = fee + change  -- Add dust to fee
  end

  local tx = types.transaction(2, inputs, outputs, 0)
  tx.segwit = true

  -- 8. Sign inputs.
  -- BIP-341 sighash needs the prevouts for EVERY input — pre-build the
  -- array once. Only consumed by the P2TR branch; the segwit-v0 + legacy
  -- branches commit to a single prevout each.
  local prev_outputs = {}
  for j, sel in ipairs(selected) do
    prev_outputs[j] = {
      value = sel.utxo.value,
      script_pubkey = sel.utxo.script_pubkey,
    }
  end

  for i, item in ipairs(selected) do
    local key_info = self.keys[item.utxo.address]
    if not key_info then
      return nil, "No key for address: " .. item.utxo.address
    end
    if not key_info.privkey then
      return nil, "Private key not available (wallet locked?)"
    end

    if key_info.type == "p2wpkh" then
      -- P2WPKH signing
      local pkh = crypto.hash160(key_info.pubkey)
      local script_code = script.make_p2pkh_script(pkh)
      local sighash = validation.signature_hash_segwit_v0(
        tx, i - 1, script_code, item.utxo.value, consensus.SIGHASH.ALL
      )
      local sig = crypto.ecdsa_sign(key_info.privkey, sighash)
      sig = sig .. string.char(consensus.SIGHASH.ALL)
      tx.inputs[i].witness = {sig, key_info.pubkey}
    elseif key_info.type == "p2tr" then
      -- BIP-86 key-path signing (P2-4).
      local witness_item, terr = M.sign_input_p2tr_keypath(
        tx, i - 1, prev_outputs, key_info.privkey
      )
      if not witness_item then
        return nil, "P2TR sign failed: " .. tostring(terr)
      end
      tx.inputs[i].witness = { witness_item }
      tx.inputs[i].script_sig = ""
    else
      -- Legacy P2PKH signing
      local sighash = validation.signature_hash_legacy(
        tx, i - 1, item.utxo.script_pubkey, consensus.SIGHASH.ALL
      )
      local sig = crypto.ecdsa_sign(key_info.privkey, sighash)
      sig = sig .. string.char(consensus.SIGHASH.ALL)
      -- Build scriptSig: <sig> <pubkey>
      local w = serialize.buffer_writer()
      w.write_varstr(sig)
      w.write_varstr(key_info.pubkey)
      tx.inputs[i].script_sig = w.result()
    end
  end

  return tx, fee, algo
end

--- Build lookup tables from outpoint_key -> input_value and
-- outpoint_key -> script_pubkey for every input of `tx` whose previous
-- output is in `self.utxos` or `self.pending_utxos`. Used by
-- `send_transaction` (to record absolute fee at submission time and to
-- preserve the data bumpfee needs after the rescan) and by `bump_fee`
-- (to recompute fee on the replacement and re-sign every input).
function Wallet:_lookup_input_values(tx)
  local input_values, input_scripts = {}, {}
  local all_found = true
  for _, inp in ipairs(tx.inputs) do
    local key = inp.prev_out.hash.bytes .. string.char(
      bit.band(inp.prev_out.index, 0xFF),
      bit.band(bit.rshift(inp.prev_out.index, 8), 0xFF),
      bit.band(bit.rshift(inp.prev_out.index, 16), 0xFF),
      bit.band(bit.rshift(inp.prev_out.index, 24), 0xFF)
    )
    local u = self.utxos[key] or self.pending_utxos[key]
    if u then
      input_values[key] = u.value
      input_scripts[key] = u.script_pubkey
    else
      all_found = false
    end
  end
  return input_values, all_found, input_scripts
end

--- Send a transaction to the mempool.
-- @param tx transaction: Signed transaction
-- @param meta table|nil: Optional metadata to fold into self.transactions[]
--                        — e.g. {fee=12345, replaces=<old_txid_hex>}.
--                        When `fee` is absent we recompute it from wallet UTXO
--                        input values minus tx output total (mirrors Core's
--                        CWalletTx.GetDebit - GetCredit shortcut for owned tx).
-- @return boolean: true on success
-- @return string|nil: Error message on failure
function Wallet:send_transaction(tx, meta)
  if not self.mempool then
    return false, "No mempool configured"
  end

  -- Compute fee + capture input values/scripts BEFORE accept_transaction +
  -- scan_mempool, because scan_mempool removes spent confirmed UTXOs from
  -- self.utxos. Once we come out the other side of accept the inputs may
  -- no longer be in self.utxos but rather marked in self.spent_pending.
  -- bumpfee needs both fee + input snapshot, so we always capture.
  local input_values, all_found, input_scripts = self:_lookup_input_values(tx)
  local fee = meta and meta.fee
  if not fee then
    if all_found then
      local total_in = 0
      for _, v in pairs(input_values) do total_in = total_in + v end
      local total_out = 0
      for _, o in ipairs(tx.outputs) do total_out = total_out + o.value end
      fee = total_in - total_out
      if fee < 0 then fee = 0 end
    else
      fee = 0  -- foreign inputs; we don't know
    end
  end

  local ok, err = self.mempool:accept_transaction(tx, true)
  if not ok then
    return false, err
  end

  -- Track the transaction
  local txid = validation.compute_txid(tx)
  local txid_hex = types.hash256_hex(txid)
  local entry = {
    tx = tx,
    height = 0,  -- unconfirmed
    time = os.time(),
    fee = fee,
    input_values = input_values,
    input_scripts = input_scripts,
  }
  if meta and meta.replaces then
    entry.replaces = meta.replaces
    -- Mark the conflict so a second bumpfee can refuse (Core's
    -- "Cannot bump transaction X which was already bumped by Y").
    local old = self.transactions[meta.replaces]
    if old then
      old.replaced_by = txid_hex
    end
  end
  self.transactions[txid_hex] = entry

  -- Rescan mempool to update balances
  self:scan_mempool(self.mempool)

  return true
end

--- Create and send a transaction in one step.
-- @param recipients table: List of {address=string, amount=number (satoshis)}
-- @param options table: Optional settings
-- @return transaction|nil: Sent transaction
-- @return string|nil: Error message on failure
function Wallet:send_to(recipients, options)
  local tx, result, algo = self:create_transaction(recipients, options)
  if not tx then
    return nil, result  -- result is error message
  end

  local ok, err = self:send_transaction(tx, {fee = result})
  if not ok then
    return nil, err
  end

  return tx
end

--------------------------------------------------------------------------------
-- BIP-125 fee bumping (bumpfee + psbtbumpfee)
--
-- Mirrors bitcoin-core/src/wallet/feebumper.{h,cpp}:
--   * PreconditionChecks  — owner, unconfirmed, not already replaced, BIP-125
--   * CreateRateBumpTransaction — reuse inputs, reduce change to fund the bump
--   * SignTransaction     — re-sign each input via the FIX-59 unified path
--   * CommitTransaction   — submit to mempool, mark the old tx replaced
--
-- The single Wallet:bump_fee helper returns the rebuilt transaction (signed
-- or unsigned depending on `options.sign`) so the bumpfee RPC can broadcast
-- it directly and the psbtbumpfee RPC can wrap it in a PSBT.
--------------------------------------------------------------------------------

--- Classify a scriptPubKey to one of our wallet addresses (if any).
-- @param script_pubkey string
-- @return string|nil: address, or nil if not ours
-- @return string|nil: address type ("p2wpkh"|"p2pkh"|...)
function Wallet:_address_for_script(script_pubkey)
  local script_type, hash_or_program = script.classify_script(script_pubkey)
  local addr
  if script_type == "p2wpkh" then
    local hrp = self.network.bech32_hrp or address.BECH32_HRP[self.network.name] or "bc"
    addr = address.segwit_encode(hrp, 0, hash_or_program)
  elseif script_type == "p2tr" then
    -- P2-4: recognise our own P2TR coins so bump_fee / coin reconciliation
    -- can locate the key_info for a spent taproot UTXO. hash_or_program is
    -- the 32-byte tweaked x-only key; that maps 1-1 to the bech32m address
    -- via xonly_pubkey_to_p2tr.
    addr = address.xonly_pubkey_to_p2tr(hash_or_program, self.network.name)
  elseif script_type == "p2pkh" then
    local version = self.network.pubkey_address_prefix
    addr = address.base58check_encode(version, hash_or_program)
  end
  if addr and self.keys[addr] then
    return addr, script_type
  end
  return nil
end

--- Sign every input of `tx` in place using wallet keys, mirroring the
-- create_transaction signing block (FIX-59 unified ecdsa_sign path).
-- @param tx transaction
-- @param input_utxos table: tx.inputs index (1-based) -> {value, script_pubkey, address}
-- @return boolean ok, string|nil err
-- @param tx           transaction: tx with inputs to sign
-- @param input_utxos  table: i (1-based) -> {value, script_pubkey, address}
-- @param indices      table|nil: optional 1-based-index set to restrict
--                     signing to a subset.  When nil, every input in `tx`
--                     is signed (legacy behaviour for create_transaction +
--                     bump_fee).  When non-nil only the listed indices are
--                     signed and the remaining inputs are left untouched
--                     — used by BIP-78 PayJoin receiver (FIX-65), where
--                     the sender's inputs MUST NOT be touched and the
--                     receiver only contributes its own added input(s).
function Wallet:_sign_inputs(tx, input_utxos, indices)
  local should_sign
  if indices then
    -- Build a 1-based index lookup table.  Accept either array form
    -- {3, 5} or set form {[3]=true, [5]=true}; canonicalise to set.
    local set = {}
    for k, v in pairs(indices) do
      if type(k) == "number" and v ~= false then
        if v == true then set[k] = true else set[v] = true end
      end
    end
    should_sign = function(i) return set[i] == true end
  else
    should_sign = function() return true end
  end

  -- BIP-341 requires the prev_outputs of EVERY input (not just the one
  -- being signed) for any taproot input. Pre-build the array once; the
  -- legacy + segwit-v0 paths ignore it. Used by sign_input_p2tr_keypath.
  local prev_outputs = nil
  for j = 1, #tx.inputs do
    local u = input_utxos[j]
    if u then
      prev_outputs = prev_outputs or {}
      prev_outputs[j] = { value = u.value, script_pubkey = u.script_pubkey }
    end
  end

  for i, _ in ipairs(tx.inputs) do
    if should_sign(i) then
      local utxo = input_utxos[i]
      if not utxo then
        return false, "Missing UTXO for input " .. tostring(i - 1)
      end
      local key_info = self.keys[utxo.address]
      if not key_info then
        return false, "No key for address: " .. tostring(utxo.address)
      end
      if not key_info.privkey then
        return false, "Private key not available (wallet locked?)"
      end

      if key_info.type == "p2wpkh" then
        local pkh = crypto.hash160(key_info.pubkey)
        local script_code = script.make_p2pkh_script(pkh)
        local sighash = validation.signature_hash_segwit_v0(
          tx, i - 1, script_code, utxo.value, consensus.SIGHASH.ALL
        )
        local sig = crypto.ecdsa_sign(key_info.privkey, sighash)
        sig = sig .. string.char(consensus.SIGHASH.ALL)
        tx.inputs[i].witness = {sig, key_info.pubkey}
      elseif key_info.type == "p2tr" then
        -- BIP-86 key-path spend (P2-4). The taproot signer needs the
        -- prevouts of every input, not just this one — BIP-341 commits
        -- to the whole input set unless ANYONECANPAY is in play.
        -- Wallets created post-P2-3 with address_type="p2tr" have keys
        -- tagged with type="p2tr"; legacy fallthrough to ECDSA used to
        -- silently produce DER sigs the network rejects on a v1 segwit
        -- output (the "write-only Taproot wallets" P0 from W161).
        if not prev_outputs then
          return false, "Missing prev_outputs for taproot input " .. tostring(i - 1)
        end
        local witness_item, terr = M.sign_input_p2tr_keypath(
          tx, i - 1, prev_outputs, key_info.privkey
        )
        if not witness_item then
          return false, "P2TR sign failed: " .. tostring(terr)
        end
        tx.inputs[i].witness = { witness_item }
        tx.inputs[i].script_sig = ""
      else
        local sighash = validation.signature_hash_legacy(
          tx, i - 1, utxo.script_pubkey, consensus.SIGHASH.ALL
        )
        local sig = crypto.ecdsa_sign(key_info.privkey, sighash)
        sig = sig .. string.char(consensus.SIGHASH.ALL)
        local w = serialize.buffer_writer()
        w.write_varstr(sig)
        w.write_varstr(key_info.pubkey)
        tx.inputs[i].script_sig = w.result()
      end
    end
  end
  return true
end

--- Compute virtual size of a transaction in vbytes.
-- vsize = ceil((base_size * 3 + total_size) / 4)
-- base_size  = serialization WITHOUT witness
-- total_size = serialization WITH witness
local function _compute_vsize(tx)
  local base = #serialize.serialize_transaction(tx, false)
  local total = #serialize.serialize_transaction(tx, true)
  return math.ceil((base * 3 + total) / 4)
end

--- BIP-125 fee bump (a.k.a. bumpfee / psbtbumpfee in Core).
-- Returns the rebuilt transaction and the fee accounting, or nil + errors.
--
-- @param orig_txid_hex string: hex txid (big-endian display form, as
--                              returned by sendtoaddress) of the wallet tx
--                              to bump.
-- @param options table|nil: {
--   fee_rate   = number  -- override target sat/vB
--   sign       = boolean -- when false return the unsigned tx (for PSBT path)
-- }
-- @return transaction|nil  rebuilt tx (signed if options.sign ~= false)
-- @return number|table     old_fee on success, errors-array on failure
-- @return number|nil       new_fee on success
-- @return table|nil        input_utxos {idx -> {value, script_pubkey, address}}
--                          — exposed so the psbtbumpfee path can populate
--                          witness_utxo on every PSBT input.
function Wallet:bump_fee(orig_txid_hex, options)
  options = options or {}
  local errors = {}

  -- ---- 0. Wallet unlocked + tx lookup -------------------------------------
  if self.is_encrypted and self.is_locked then
    errors[#errors + 1] = "Wallet is locked"
    return nil, errors
  end

  local entry = self.transactions[orig_txid_hex]
  if not entry then
    errors[#errors + 1] = "Invalid or non-wallet transaction id"
    return nil, errors
  end
  local orig = entry.tx

  -- ---- 1. PreconditionChecks (feebumper.cpp:23) ---------------------------
  if entry.height and entry.height > 0 then
    errors[#errors + 1] = "Transaction has been mined, or is conflicted with a mined transaction"
    return nil, errors
  end
  if entry.replaced_by then
    errors[#errors + 1] = string.format(
      "Cannot bump transaction %s which was already bumped by transaction %s",
      orig_txid_hex, entry.replaced_by)
    return nil, errors
  end

  -- BIP-125 rule 1: opt-in (any input sequence <= 0xFFFFFFFD).
  local mempool_mod = require("lunarblock.mempool")
  if not mempool_mod.signals_rbf(orig) then
    errors[#errors + 1] = "Transaction is not BIP-125 replaceable"
    return nil, errors
  end

  -- require_mine: every input must be ours (we need each input value).
  local input_utxos = {}
  for i, inp in ipairs(orig.inputs) do
    local key = inp.prev_out.hash.bytes .. string.char(
      bit.band(inp.prev_out.index, 0xFF),
      bit.band(bit.rshift(inp.prev_out.index, 8), 0xFF),
      bit.band(bit.rshift(inp.prev_out.index, 16), 0xFF),
      bit.band(bit.rshift(inp.prev_out.index, 24), 0xFF)
    )
    -- The confirmed UTXO has been removed by scan_mempool once we spent it,
    -- so look at both: spent-pending tells us it WAS ours and the value
    -- lives on entry.tx itself. Easier: walk self.keys -> need value.
    -- We stored the originating coin in self.utxos prior to send_transaction;
    -- after scan_mempool it migrates to self.spent_pending. We don't keep the
    -- value there. Use the wallet's keys + the orig tx's predecessor:
    -- iterate confirmed/pending and fall back to chain_state lookup is
    -- unavailable here, so the wallet must have witnessed the prev tx via
    -- scan_utxos OR be the sender (the typical bumpfee path: we sent it,
    -- so the original input UTXOs were in self.utxos and we recorded their
    -- values at create_transaction time). We store input values on entry
    -- to make this robust.
    local v
    local u = self.utxos[key] or self.pending_utxos[key]
    if u then
      v = u.value
    elseif entry.input_values and entry.input_values[key] then
      v = entry.input_values[key]
    end
    if not v then
      errors[#errors + 1] = "Transaction contains inputs that don't belong to this wallet"
      return nil, errors
    end

    -- Reconstruct the script_pubkey + address for signing. For an input we
    -- spent from our wallet we have the address in `keys`. We need to know
    -- which one — recover by classifying the prev outpoint's script_pubkey,
    -- which we cached on send when available.
    local script_pubkey, addr
    if entry.input_scripts and entry.input_scripts[key] then
      script_pubkey = entry.input_scripts[key]
    elseif u then
      script_pubkey = u.script_pubkey
    end
    if script_pubkey then
      addr = self:_address_for_script(script_pubkey)
    end
    if not addr then
      errors[#errors + 1] = "Transaction contains inputs that don't belong to this wallet"
      return nil, errors
    end
    input_utxos[i] = {value = v, script_pubkey = script_pubkey, address = addr}
  end

  -- ---- 2. Locate the change output ----------------------------------------
  --
  -- Core's CreateRateBumpTransaction accepts an explicit `original_change_index`
  -- but, in the common path, picks the first output whose scriptPubKey
  -- decodes to one of our addresses. We mirror that here. If no change
  -- output is present (a pure send-everything tx), bumpfee can't shrink
  -- change to fund the bump and must fail with a clear message.
  local change_index = nil
  for i, out in ipairs(orig.outputs) do
    local addr = self:_address_for_script(out.script_pubkey)
    if addr then
      change_index = i
      break
    end
  end
  if not change_index then
    errors[#errors + 1] = "Transaction does not have a change output owned by this wallet"
    return nil, errors
  end

  -- ---- 3. Compute target fee ---------------------------------------------
  local old_fee = entry.fee
  if not old_fee or old_fee <= 0 then
    -- Recompute from inputs - outputs as a safety net.
    local total_in = 0
    for i = 1, #orig.inputs do total_in = total_in + input_utxos[i].value end
    local total_out = 0
    for _, o in ipairs(orig.outputs) do total_out = total_out + o.value end
    old_fee = total_in - total_out
  end

  local orig_vsize = _compute_vsize(orig)
  local new_fee
  if options.fee_rate and options.fee_rate > 0 then
    new_fee = math.ceil(orig_vsize * options.fee_rate)
  else
    -- Default: original fee + ceil(vsize * 1 sat/vB) — mirrors EstimateFeeRate
    -- which adds wallet's WALLET_INCREMENTAL_RELAY_FEE (1 sat/vB) on top of
    -- the original feerate, applied across the same vsize.
    new_fee = old_fee + math.ceil(orig_vsize * 1)
  end

  -- BIP-125 Rule 3: new absolute fee must exceed old fee.
  if new_fee <= old_fee then
    errors[#errors + 1] = string.format(
      "New fee (%d) must exceed old fee (%d)", new_fee, old_fee)
    return nil, errors
  end

  -- ---- 4. Adjust change ---------------------------------------------------
  local delta = new_fee - old_fee
  local new_change = orig.outputs[change_index].value - delta
  if new_change <= M.DUST_THRESHOLD then
    errors[#errors + 1] = string.format(
      "Change after fee bump (%d) would be dust (<= %d); insufficient funds",
      new_change, M.DUST_THRESHOLD)
    return nil, errors
  end

  -- ---- 5. Build replacement tx -------------------------------------------
  local inputs = {}
  for _, inp in ipairs(orig.inputs) do
    -- Reuse sequence as-is (already <= 0xFFFFFFFD).
    inputs[#inputs + 1] = types.txin(
      types.outpoint(inp.prev_out.hash, inp.prev_out.index),
      "",   -- to be replaced by re-sign
      inp.sequence
    )
  end

  local outputs = {}
  for i, out in ipairs(orig.outputs) do
    if i == change_index then
      outputs[#outputs + 1] = types.txout(new_change, out.script_pubkey)
    else
      outputs[#outputs + 1] = types.txout(out.value, out.script_pubkey)
    end
  end

  local new_tx = types.transaction(orig.version, inputs, outputs, orig.locktime)
  new_tx.segwit = true

  -- ---- 6. Sign (unless caller asked for unsigned, e.g. psbtbumpfee) ------
  if options.sign ~= false then
    local ok, err = self:_sign_inputs(new_tx, input_utxos)
    if not ok then
      errors[#errors + 1] = err
      return nil, errors
    end
  end

  return new_tx, old_fee, new_fee, input_utxos
end

--------------------------------------------------------------------------------
-- Wallet Info Queries
--------------------------------------------------------------------------------

--- Get spendable (trusted) balance.
-- Excludes immature coinbase outputs (< COINBASE_MATURITY+1 = 101
-- confirmations), matching Bitcoin Core's getbalance / GetBalance, which never
-- counts immature coinbases toward the spendable balance. Falls back to the
-- raw confirmed balance only if a scan has not run yet (spendable_balance nil).
-- @return number: Spendable balance in satoshis
function Wallet:get_balance()
  return self.spendable_balance or self.confirmed_balance
end

--- Get unconfirmed balance.
-- @return number: Pending balance in satoshis (can be negative)
function Wallet:get_unconfirmed_balance()
  return self.unconfirmed_balance
end

--- Get total balance (confirmed + unconfirmed).
-- @return number: Total balance in satoshis
function Wallet:get_total_balance()
  return self.confirmed_balance + self.unconfirmed_balance
end

--- Get detailed balance breakdown.
-- @return table: {confirmed=number, unconfirmed=number, total=number, spendable=number}
function Wallet:get_balance_details()
  local spendable = 0
  local immature = 0
  for key, utxo in pairs(self.utxos) do
    if not self.spent_pending[key] then
      -- Coinbase maturity: spendable only at COINBASE_MATURITY+1 (=101)
      -- confirmations (chain depth >= 101); below that it is immature and
      -- excluded from the spendable/trusted balance (Bitcoin Core
      -- GetBalance skips immature coinbases, tracking them as m_mine_immature).
      if utxo.is_coinbase then
        if (utxo.confirmations or 0) >= consensus.COINBASE_MATURITY + 1 then
          spendable = spendable + utxo.value
        else
          immature = immature + utxo.value
        end
      else
        spendable = spendable + utxo.value
      end
    end
  end

  return {
    confirmed = self.confirmed_balance,
    unconfirmed = self.unconfirmed_balance,
    total = self.confirmed_balance + self.unconfirmed_balance,
    spendable = spendable,
    immature = immature,
  }
end

--- List unspent outputs.
-- @param include_unconfirmed boolean: Include pending UTXOs (default true)
-- @return table: Array of UTXO info
function Wallet:list_unspent(include_unconfirmed)
  include_unconfirmed = include_unconfirmed ~= false

  local result = {}

  -- Add confirmed UTXOs
  for key, utxo in pairs(self.utxos) do
    local spendable = true
    if self.spent_pending[key] then
      spendable = false
    end
    -- Immature coinbase (< COINBASE_MATURITY+1 = 101 confirmations) is not
    -- spendable: the node would reject the spend as "spending immature
    -- coinbase". Matches Bitcoin Core, which marks such outputs not spendable.
    if utxo.is_coinbase and (utxo.confirmations or 0) < consensus.COINBASE_MATURITY + 1 then
      spendable = false
    end

    result[#result + 1] = {
      txid = types.hash256_hex(utxo.txid),
      vout = utxo.vout,
      address = utxo.address,
      amount = utxo.value / consensus.COIN,
      satoshis = utxo.value,
      confirmations = utxo.confirmations or 0,
      spendable = spendable,
      safe = not self.spent_pending[key],
    }
  end

  -- Add pending UTXOs
  if include_unconfirmed then
    for key, utxo in pairs(self.pending_utxos) do
      result[#result + 1] = {
        txid = types.hash256_hex(utxo.txid),
        vout = utxo.vout,
        address = utxo.address,
        amount = utxo.value / consensus.COIN,
        satoshis = utxo.value,
        confirmations = 0,
        spendable = true,
        safe = false,
      }
    end
  end

  return result
end

--- Get all wallet addresses.
-- @return table: Array of address info
function Wallet:get_addresses()
  local result = {}
  for _, addr in ipairs(self.addresses) do
    local info = self.keys[addr]
    result[#result + 1] = {
      address = addr,
      path = info.path,
      type = info.type,
      is_change = info.change == 1,
    }
  end
  return result
end

--- Get wallet info summary.
-- @return table: Wallet status information
function Wallet:get_info()
  return {
    is_encrypted = self.is_encrypted,
    is_locked = self.is_locked,
    network = self.network.name,
    address_type = self.address_type,
    address_count = #self.addresses,
    utxo_count = 0,  -- Will be calculated
    balance = self:get_balance_details(),
    next_external_index = self.next_external_index,
    next_internal_index = self.next_internal_index,
  }
end

--------------------------------------------------------------------------------
-- WIF Export/Import
--------------------------------------------------------------------------------

-- Export private key in WIF (Wallet Import Format)
function Wallet:dump_privkey(addr)
  local info = self.keys[addr]
  if not info then return nil, "Address not in wallet" end
  -- WIF: version byte + 32-byte key + 0x01 (compressed) + checksum
  local payload = info.privkey .. "\x01"  -- compressed flag
  return address.base58check_encode(self.network.wif_prefix, payload)
end

-- Import a WIF private key.
--
-- The imported key's address-type is chosen by the wallet's current
-- `address_type` setting when the key is compressed (so an "address_type
-- = p2tr" wallet importing a compressed WIF gets a P2TR address via the
-- BIP-86 tweak path).  Uncompressed WIFs predate witness, so they always
-- map to legacy P2PKH regardless of wallet.address_type.
function Wallet:import_privkey(wif)
  local version, payload = address.base58check_decode(wif)
  assert(version == self.network.wif_prefix, "Wrong network WIF prefix")
  local compressed = (#payload == 33 and payload:byte(33) == 0x01)
  local privkey = payload:sub(1, 32)
  local pubkey = crypto.pubkey_from_privkey(privkey, compressed)

  local addr_type, addr
  if compressed then
    local purpose = M.purpose_for_address_type(self.address_type)
    if purpose then
      -- Use the canonical (post-synonym) type so the on-disk record
      -- matches what unlock() will look up later.
      addr_type = M.canonical_address_type(self.address_type)
      addr = M.pubkey_to_address_for_purpose(purpose, pubkey, self.network.name)
    else
      -- Defensive fallback: should never trigger for a wallet whose
      -- generate_address would have errored upstream.  Imported keys
      -- still need a home if the wallet was constructed with an unknown
      -- address_type and we got here anyway.
      addr_type = "p2pkh"
      addr = address.pubkey_to_p2pkh(pubkey, self.network.name)
    end
  else
    -- Uncompressed key — witness output types require compressed pubkeys.
    addr_type = "p2pkh"
    addr = address.pubkey_to_p2pkh(pubkey, self.network.name)
  end

  self.keys[addr] = {
    privkey = privkey,
    pubkey = pubkey,
    path = "imported",
    type = addr_type,
    change = 0,
    index = -1,
  }
  -- Register in the imported-key store so a later restore-from-seed / reseed
  -- (which rebuilds self.keys from the HD master key) can re-merge it and never
  -- wipe it. index == -1 / path == "imported" already excludes it from the HD
  -- re-derivation loop in unlock(); this is the durable companion record.
  self.imported_keys[addr] = {
    privkey = privkey,
    pubkey = pubkey,
    compressed = compressed,
    type = addr_type,
  }
  -- Avoid a duplicate entry in the ordered address list if re-imported.
  local already = false
  for _, a in ipairs(self.addresses) do
    if a == addr then already = true; break end
  end
  if not already then
    self.addresses[#self.addresses + 1] = addr
  end
  return addr
end

--------------------------------------------------------------------------------
-- Wallet Serialization with File Locking
--------------------------------------------------------------------------------

-- File locking via FFI (POSIX fcntl)
ffi.cdef[[
  struct flock {
    short l_type;
    short l_whence;
    long long l_start;
    long long l_len;
    int l_pid;
  };

  int open(const char *pathname, int flags, ...);
  int close(int fd);
  int fcntl(int fd, int cmd, ...);
  int ftruncate(int fd, long long length);
  long long write(int fd, const void *buf, unsigned long count);
  long long read(int fd, void *buf, unsigned long count);
  long long lseek(int fd, long long offset, int whence);
  int fsync(int fd);
  int rename(const char *oldpath, const char *newpath);
  int unlink(const char *pathname);
]]

-- fcntl constants
local F_SETLK = 6
local F_SETLKW = 7
local F_WRLCK = 1
local F_UNLCK = 2
local O_RDWR = 2
local O_RDONLY = 0
local O_CREAT = 64
local O_TRUNC = 512
-- O_DIRECTORY (Linux): require the opened path to be a directory; used to get a
-- handle for fsync()-ing the parent dir so a rename() is itself durable.
local O_DIRECTORY = 0x10000
local SEEK_SET = 0
local SEEK_END = 2

--- Acquire an exclusive lock on a file descriptor.
-- @param fd number: File descriptor
-- @return boolean: true on success
local function lock_file(fd)
  local lock = ffi.new("struct flock")
  lock.l_type = F_WRLCK
  lock.l_whence = SEEK_SET
  lock.l_start = 0
  lock.l_len = 0  -- Lock entire file
  return ffi.C.fcntl(fd, F_SETLKW, lock) == 0
end

--- Release lock on a file descriptor.
-- @param fd number: File descriptor
local function unlock_file(fd)
  local lock = ffi.new("struct flock")
  lock.l_type = F_UNLCK
  lock.l_whence = SEEK_SET
  lock.l_start = 0
  lock.l_len = 0
  ffi.C.fcntl(fd, F_SETLK, lock)
end

--- Return the directory part of a path ("/a/b/c.json" -> "/a/b"; "x" -> ".").
local function dir_of(path)
  local d = path:match("^(.*)/[^/]*$")
  if not d or d == "" then return "." end
  return d
end

--- fsync the directory containing `path` so a rename() into it is durable.
-- Mirrors Bitcoin Core's FileCommit + the directory fsync it performs after
-- a rename (src/util/fs_helpers.cpp / walletdb.cpp). Best-effort: a failure to
-- open the directory (e.g. unusual filesystem) is non-fatal — the data file
-- itself was already fsync'd, so we never lose the bytes, only the rename's
-- crash-durability guarantee.
local function fsync_dir(path)
  local dir = dir_of(path)
  local dfd = ffi.C.open(dir, bit.bor(O_RDONLY, O_DIRECTORY), 0)
  if dfd < 0 then return false end
  ffi.C.fsync(dfd)
  ffi.C.close(dfd)
  return true
end

-- Simple JSON encoding (for wallet data which has simple structure)
local function simple_json_encode(tbl)
  local parts = {"{"}
  local first = true
  for k, v in pairs(tbl) do
    if not first then parts[#parts + 1] = "," end
    first = false
    parts[#parts + 1] = string.format('"%s":', k)
    if type(v) == "string" then
      parts[#parts + 1] = string.format('"%s"', v)
    elseif type(v) == "number" then
      parts[#parts + 1] = tostring(v)
    elseif type(v) == "boolean" then
      parts[#parts + 1] = v and "true" or "false"
    elseif v == nil then
      parts[#parts + 1] = "null"
    end
  end
  parts[#parts + 1] = "}"
  return table.concat(parts)
end

-- Simple JSON decoding (for wallet data)
local function simple_json_decode(str)
  local data = {}
  -- Match key-value pairs: "key":value or "key":"value"
  for k, v in str:gmatch('"([^"]+)":%s*([^,}]+)') do
    v = v:gsub("^%s+", ""):gsub("%s+$", "")  -- trim
    if v:match('^"') then
      -- String value
      data[k] = v:match('^"(.*)"$')
    elseif v == "true" then
      data[k] = true
    elseif v == "false" then
      data[k] = false
    elseif v == "null" then
      data[k] = nil
    else
      -- Try as number
      data[k] = tonumber(v) or v
    end
  end
  return data
end

-- Try to use cjson if available, fall back to simple implementation
local function get_json()
  local ok, cjson = pcall(require, "cjson")
  if ok then
    return cjson.encode, cjson.decode
  end
  return simple_json_encode, simple_json_decode
end

--- Serialize wallet to JSON string.
-- @return string: JSON representation
function Wallet:serialize()
  local encode = get_json()
  local data = {
    version = 1,
    network = self.network.name,
    address_type = self.address_type,
    account = self.account,
    next_external_index = self.next_external_index,
    next_internal_index = self.next_internal_index,
    is_encrypted = self.is_encrypted,
    -- Persist whether the wallet has scanned the chain, so a reload does not
    -- regress a live wallet back to the "balance 0 until rescan" state.
    scanned = self.scanned and true or false,
    -- Persist how far the wallet's ledger has been reconciled against the
    -- chain. On startup main.lua reads this back and only has to re-scan the
    -- gap (last_synced_height .. tip) instead of a full from-genesis rescan,
    -- and a wallet that crashed mid-IBD knows where to resume. Mirrors
    -- Bitcoin Core's m_last_block_processed_height (CWallet) persisted in
    -- the wallet DB so a restart reconciles forward from there.
    last_synced_height = self.last_synced_height or 0,
    -- WALLET_FLAG_DISABLE_PRIVATE_KEYS, persisted so a reloaded watch-only
    -- wallet still knows it is watch-only (getwalletinfo private_keys_enabled
    -- + the -4 key-op guards key off THIS flag, not lock state / master_key
    -- presence). Default true for legacy wallet files lacking the field.
    private_keys_enabled = self.private_keys_enabled ~= false,
  }

  -- Persist WATCH-ONLY descriptors (importdescriptors on a dpk wallet). The
  -- wallet holds no private key for these scripts, so unlike HD/imported keys
  -- there is nothing to re-derive — the descriptor + its classified address +
  -- metadata IS the whole record, and it MUST round-trip the wallet file or a
  -- restart loses the watched funds (the historical wallet-fragility footgun).
  -- Symmetric with the reinstall in M.load(). Mirrors the imported_keys block.
  if self.watch_addrs and next(self.watch_addrs) ~= nil then
    local wd = {}
    for addr, info in pairs(self.watch_addrs) do
      wd[addr] = {
        desc = info.desc,
        label = info.label,
        internal = info.internal and true or false,
        spk_hex = info.spk_hex,
        kind = info.kind,
        ts = info.ts or 0,
      }
    end
    data.watch_descriptors = wd
  end

  -- Persist imported keys (importprivkey). These are NOT derivable from the HD
  -- master key, so unlike HD keys they MUST be serialized or they are lost on
  -- reload. Held apart from the HD keychain so a reseed never wipes them.
  if self.imported_keys and next(self.imported_keys) ~= nil then
    local imp = {}
    for addr, info in pairs(self.imported_keys) do
      imp[addr] = {
        privkey = M.hex_encode(info.privkey),
        compressed = info.compressed and true or false,
        type = info.type,
      }
    end
    data.imported_keys = imp
  end

  if self.is_encrypted then
    -- Store encrypted key
    data.encrypted_master_key = M.hex_encode(self.encrypted_master_key)
    data.encryption_salt = M.hex_encode(self.encryption_salt)
    -- Encrypted mnemonic (optional; only present for BIP-39 wallets).
    if self.encrypted_mnemonic then
      data.encrypted_mnemonic = M.hex_encode(self.encrypted_mnemonic)
    end
  else
    -- P2-1 FIX (W161 master_key plaintext P0): even when the wallet is NOT
    -- user-encrypted, never write the master_key + chain_code as plaintext
    -- bytes on disk. Encrypt at rest with the AT_REST_PHRASE-derived key so
    -- `cat wallet.json` cannot leak the literal master key. This is NOT a
    -- security boundary (the AT_REST_PHRASE is a public source constant) —
    -- users who need a real boundary MUST call encryptwallet with a strong
    -- passphrase. The deserializer (M.load) detects at_rest_encrypted_master
    -- and decrypts transparently.
    if self.master_key then
      local salt = M.random_bytes(M.CRYPTO_SALT_SIZE)
      local key, iv = M.derive_at_rest_key(salt)
      local plaintext = self.master_key.key .. self.master_key.chain_code
      data.at_rest_encrypted_master = M.hex_encode(M.aes_encrypt(plaintext, key, iv))
      data.at_rest_salt = M.hex_encode(salt)
      if self.mnemonic_words then
        local m_plain = table.concat(self.mnemonic_words, " ")
        data.at_rest_encrypted_mnemonic = M.hex_encode(M.aes_encrypt(m_plain, key, iv))
      end
    end
  end

  -- BIP-39 passphrase is intentionally NOT persisted. It is required to
  -- regenerate the seed externally; users must remember/back it up
  -- separately, the same way Trezor / Electrum / Sparrow do.

  return encode(data)
end

--- Save wallet to file with exclusive locking.
-- @param filepath string: Path to wallet file
-- @return boolean: true on success
-- @return string|nil: Error message on failure
function Wallet:save(filepath)
  -- Remember where we persist so save-on-mutation (mark_dirty / save_if_dirty)
  -- and the block-connect hook can re-flush without the caller re-supplying it.
  if filepath then self._save_path = filepath end
  filepath = filepath or self._save_path
  if not filepath then
    return false, "Wallet:save called with no path and no remembered path"
  end

  local data = self:serialize()

  -- ATOMIC + DURABLE write (mirror mempool_persist.dump / fee:save and Bitcoin
  -- Core walletdb.cpp): never truncate the live file in place — a crash between
  -- truncate and the final write would leave a zero-length / partial wallet that
  -- the loader would then choke on. Instead write to <path>.tmp, fsync it, then
  -- atomically rename over the destination, and fsync the parent directory so
  -- the rename itself survives a power loss.
  local tmp = filepath .. ".tmp"

  -- O_CREAT|O_TRUNC on the TEMP file only (safe: it is not the live wallet).
  -- NB: the mode arg is VARIADIC in open(2). LuaJIT passes a bare Lua number as
  -- a C double through the `...`, which the kernel then reads as garbage → the
  -- file lands with 0000 perms (unreadable even by its owner; M.exists / load
  -- via io.open then can't see it). Cast to a real C int so we get 0600.
  local fd = ffi.C.open(tmp, bit.bor(O_RDWR, O_CREAT, O_TRUNC), ffi.cast("int", 0x180))  -- 0600
  if fd < 0 then
    return false, "Cannot open temp wallet file for writing: " .. tmp
  end

  if not lock_file(fd) then
    ffi.C.close(fd)
    return false, "Cannot acquire lock on temp wallet file"
  end

  -- Write the full payload (handle partial writes from a single write() call).
  local total = #data
  local off = 0
  while off < total do
    local chunk = data:sub(off + 1)
    local n = tonumber(ffi.C.write(fd, chunk, #chunk))
    if n <= 0 then
      unlock_file(fd)
      ffi.C.close(fd)
      ffi.C.unlink(tmp)
      return false, "Failed to write wallet data"
    end
    off = off + n
  end

  -- fsync the data to stable storage BEFORE the rename, so the rename can never
  -- expose a name pointing at unflushed bytes.
  ffi.C.fsync(fd)
  unlock_file(fd)
  ffi.C.close(fd)

  -- Atomic publish: rename(2) over the destination is atomic on POSIX, so a
  -- reader either sees the old complete file or the new complete file — never a
  -- torn one.
  if ffi.C.rename(tmp, filepath) ~= 0 then
    ffi.C.unlink(tmp)
    return false, "Failed to rename temp wallet file into place"
  end

  -- Make the rename itself durable.
  fsync_dir(filepath)

  -- A successful flush clears the dirty flag.
  self._dirty = false
  return true
end

--- Mark the in-memory wallet state as changed since the last successful save.
-- Cheap; pairs with save_if_dirty() for a debounced periodic flush so the hot
-- block-connect path does not fsync on every single block.
function Wallet:mark_dirty()
  self._dirty = true
end

--- Flush to disk only if there are unsaved mutations. Returns true if a save
-- was performed (or nothing needed saving), false + err on a real failure.
-- Uses the remembered _save_path; a no-op (and success) when no path is known.
function Wallet:save_if_dirty()
  if not self._dirty then return true end
  if not self._save_path then return true end
  return self:save(self._save_path)
end

--- Read the full raw bytes of a wallet file, locking while we read.
-- Returns the raw string, or nil + err. Never raises (callers run under pcall
-- already, but this keeps the failure mode a clean nil).
local function read_wallet_raw(filepath)
  local fd = ffi.C.open(filepath, O_RDWR, 0)
  if fd < 0 then
    -- A file that exists but isn't writable still needs reading; retry RDONLY.
    fd = ffi.C.open(filepath, O_RDONLY, 0)
    if fd < 0 then
      return nil, "Wallet file not found"
    end
  end
  if not lock_file(fd) then
    ffi.C.close(fd)
    return nil, "Cannot acquire lock on wallet file"
  end
  local size = ffi.C.lseek(fd, 0, SEEK_END)
  ffi.C.lseek(fd, 0, SEEK_SET)
  if size <= 0 then
    unlock_file(fd)
    ffi.C.close(fd)
    return nil, "Wallet file is empty"
  end
  local buf = ffi.new("char[?]", size + 1)
  local bytes_read = ffi.C.read(fd, buf, size)
  unlock_file(fd)
  ffi.C.close(fd)
  if bytes_read ~= size then
    return nil, "Failed to read wallet file"
  end
  return ffi.string(buf, size)
end

--- Try to read AND decode a wallet file into a plain data table.
-- Both the read and the JSON decode run under pcall so a missing / truncated /
-- corrupt file becomes nil + err, NEVER a raised error that crashes startup.
local function try_load_data(filepath, decode)
  local raw, rerr = read_wallet_raw(filepath)
  if not raw then return nil, rerr end
  local ok, data = pcall(decode, raw)
  if not ok then
    return nil, "JSON decode failed: " .. tostring(data)
  end
  if type(data) ~= "table" then
    return nil, "wallet file did not decode to an object"
  end
  return data
end

--- Load wallet from file with locking.
-- @param filepath string: Path to wallet file
-- @param network table: Network configuration (optional, uses file value if not provided)
-- @param storage table: Storage backend (optional)
-- @param passphrase string: Passphrase for encrypted wallets (optional)
-- @return Wallet|nil: Loaded wallet
-- @return string|nil: Error message on failure
function M.load(filepath, network, storage, passphrase)
  local _, decode = get_json()

  -- FAULT-TOLERANT LOAD. A missing / corrupt / partially-written wallet file
  -- must NEVER crash node startup. Try the live file first; if it is unreadable
  -- or fails to decode, fall back to the crashed-save temp file (<path>.tmp),
  -- which may hold the freshest *complete* state if the crash happened after the
  -- temp was fully written but before the rename. Whatever we recover from, the
  -- corrupt original is quarantined to <path>.bak so the operator can inspect it
  -- and the next save() can overwrite the live name cleanly.
  local data, derr = try_load_data(filepath, decode)
  if not data then
    -- Quarantine the bad live file (best-effort).
    local bad_exists = ffi.C.open(filepath, O_RDONLY, 0)
    if bad_exists >= 0 then
      ffi.C.close(bad_exists)
      ffi.C.rename(filepath, filepath .. ".bak")
      io.stderr:write(string.format(
        "WARNING: wallet file %s unreadable (%s); moved aside to %s.bak\n",
        filepath, tostring(derr), filepath))
    end
    -- Attempt recovery from a left-over atomic-save temp file.
    local tmp = filepath .. ".tmp"
    local tdata, terr = try_load_data(tmp, decode)
    if tdata then
      io.stderr:write(string.format(
        "Recovered wallet state from crashed-save temp file %s\n", tmp))
      data = tdata
      -- Promote the recovered temp into place so subsequent reads are clean.
      ffi.C.rename(tmp, filepath)
    else
      -- Nothing recoverable. Surface a clean error; the caller (load_wallet /
      -- main.lua) must treat this as non-fatal and continue (e.g. create a
      -- fresh wallet) rather than aborting node startup.
      return nil, "wallet load failed (" .. tostring(derr) ..
        "; temp recovery: " .. tostring(terr) .. ")"
    end
  end

  -- Use network from file if not provided
  if not network and data.network then
    network = consensus.networks[data.network]
  end

  local wallet = M.new(network, storage)
  wallet.next_external_index = data.next_external_index or 0
  wallet.next_internal_index = data.next_internal_index or 0
  wallet.account = data.account or 0
  wallet.address_type = data.address_type or "p2wpkh"
  wallet.is_encrypted = data.is_encrypted or false

  if data.is_encrypted then
    -- Load encrypted key
    wallet.encrypted_master_key = M.hex_decode(data.encrypted_master_key)
    wallet.encryption_salt = M.hex_decode(data.encryption_salt)
    if data.encrypted_mnemonic then
      wallet.encrypted_mnemonic = M.hex_decode(data.encrypted_mnemonic)
    end
    wallet.is_locked = true

    -- Try to unlock if passphrase provided
    if passphrase then
      local ok, err = wallet:unlock(passphrase)
      if not ok then
        return nil, err
      end
    end
  else
    -- P2-1 FIX (W161): preferred path — at-rest encrypted master_key.
    if data.at_rest_encrypted_master and data.at_rest_salt then
      local salt = M.hex_decode(data.at_rest_salt)
      local key, iv = M.derive_at_rest_key(salt)
      local ciphertext = M.hex_decode(data.at_rest_encrypted_master)
      local plaintext, err = M.aes_decrypt(ciphertext, key, iv)
      if not plaintext or #plaintext ~= 64 then
        return nil, "at-rest decryption failed: " .. (err or "invalid length")
      end
      local seed_key = plaintext:sub(1, 32)
      local chain_code = plaintext:sub(33, 64)
      wallet.master_key = M.extended_key(seed_key, chain_code, 0, "\0\0\0\0", 0, true)
      wallet.is_locked = false
      if data.at_rest_encrypted_mnemonic then
        local m_plain = M.aes_decrypt(M.hex_decode(data.at_rest_encrypted_mnemonic), key, iv)
        if m_plain then
          local words = {}
          for w in m_plain:gmatch("%S+") do words[#words + 1] = w end
          if ({[12]=true,[15]=true,[18]=true,[21]=true,[24]=true})[#words] then
            wallet.mnemonic_words = words
          end
        end
      end
    -- Legacy back-compat path: old wallet files written before the P2-1 fix
    -- still stored master_key as plaintext. Load them, log a warning so the
    -- next save() upgrades to at-rest-encrypted, and never re-emit plaintext.
    elseif data.master_key and data.master_chain_code then
      io.stderr:write("WARNING: loading legacy plaintext master_key wallet; will be upgraded to at-rest-encrypted on next save\n")
      local seed_key = M.hex_decode(data.master_key)
      local chain_code = M.hex_decode(data.master_chain_code)
      wallet.master_key = M.extended_key(seed_key, chain_code, 0, "\0\0\0\0", 0, true)
      wallet.is_locked = false
      if data.mnemonic and type(data.mnemonic) == "string" then
        local words = {}
        for w in data.mnemonic:gmatch("%S+") do words[#words + 1] = w end
        if ({[12]=true,[15]=true,[18]=true,[21]=true,[24]=true})[#words] then
          wallet.mnemonic_words = words
        end
      end
    end
  end

  -- Regenerate addresses
  if not wallet.is_locked then
    local max_index = math.max(wallet.next_external_index, wallet.next_internal_index)
    if max_index > 0 then
      -- Reset indices to regenerate from 0
      local ext = wallet.next_external_index
      local int = wallet.next_internal_index
      wallet.next_external_index = 0
      wallet.next_internal_index = 0
      wallet:generate_addresses(ext)
      wallet.next_external_index = ext
      wallet.next_internal_index = int
    else
      wallet:generate_addresses(wallet.gap_limit)
    end
  end

  -- Re-merge imported keys AFTER HD address regeneration. They are not derivable
  -- from the master key, so the HD regen above would never recreate them — they
  -- are held apart in self.imported_keys and re-installed into self.keys here so
  -- every scan / sign / own-script path sees them. A reseed never wipes them.
  if data.imported_keys and not wallet.is_locked then
    for addr, info in pairs(data.imported_keys) do
      local privkey = M.hex_decode(info.privkey)
      local pubkey = crypto.pubkey_from_privkey(privkey, info.compressed ~= false)
      wallet.keys[addr] = {
        privkey = privkey,
        pubkey = pubkey,
        path = "imported",
        type = info.type or "p2pkh",
        change = 0,
        index = -1,
      }
      wallet.imported_keys[addr] = {
        privkey = privkey,
        pubkey = pubkey,
        compressed = info.compressed ~= false,
        type = info.type or "p2pkh",
      }
      local seen = false
      for _, a in ipairs(wallet.addresses) do
        if a == addr then seen = true; break end
      end
      if not seen then
        wallet.addresses[#wallet.addresses + 1] = addr
      end
    end
  end

  -- Restore the WALLET_FLAG_DISABLE_PRIVATE_KEYS-derived flag. Default true for
  -- legacy wallet files written before the field existed (a real keyed wallet).
  wallet.private_keys_enabled = data.private_keys_enabled ~= false

  -- Reinstall WATCH-ONLY descriptors AFTER the imported-key re-merge and BEFORE
  -- any startup rescan, so the watch set is present when the ledger is rebuilt.
  -- Symmetric with the serialize() block. A watch-only descriptor carries no
  -- private key, so there is nothing to re-derive — the persisted record IS the
  -- whole entry. This is the round-trip that keeps a reloaded watch-only wallet's
  -- funds visible (the wallet-fragility guard the watch-only family warns about).
  if data.watch_descriptors then
    for addr, info in pairs(data.watch_descriptors) do
      wallet.watch_addrs[addr] = {
        desc = info.desc,
        label = info.label,
        internal = info.internal and true or false,
        spk_hex = info.spk_hex,
        kind = info.kind,
        ts = tonumber(info.ts) or 0,
      }
      local seen = false
      for _, a in ipairs(wallet.addresses) do
        if a == addr then seen = true; break end
      end
      if not seen then
        wallet.addresses[#wallet.addresses + 1] = addr
      end
    end
  end

  -- Restore the scanned flag (a reloaded live wallet stays live).
  wallet.scanned = data.scanned and true or false

  -- Restore how far the ledger was reconciled, so startup can scan only the gap.
  wallet.last_synced_height = tonumber(data.last_synced_height) or 0

  -- Remember the path so save-on-mutation / save_if_dirty can re-flush without
  -- the caller re-supplying it.
  wallet._save_path = filepath

  return wallet
end

--- Check if wallet file exists.
-- @param filepath string: Path to wallet file
-- @return boolean: true if file exists
function M.exists(filepath)
  local f = io.open(filepath, "r")
  if f then
    f:close()
    return true
  end
  return false
end

--------------------------------------------------------------------------------
-- Wallet Manager (Multi-Wallet Support)
--------------------------------------------------------------------------------

local WalletManager = {}
WalletManager.__index = WalletManager

--- Create a new wallet manager.
-- @param datadir string: Base data directory
-- @param network table: Network configuration
-- @param storage table: Storage backend (optional)
-- @return WalletManager: New wallet manager instance
function M.new_manager(datadir, network, storage)
  local self = setmetatable({}, WalletManager)
  self.datadir = datadir
  self.wallets_dir = datadir .. "/wallets"
  self.network = network or consensus.networks.mainnet
  self.storage = storage
  self.wallets = {}       -- name -> wallet instance
  self.wallet_locks = {}  -- name -> file descriptor (for locking)
  self.default_wallet = nil  -- default wallet name
  -- Chain context, wired by main.lua after chain_state exists. Used by
  -- load_wallet to reconcile a freshly-loaded (e.g. named watch-only) wallet's
  -- ledger up to the current tip — otherwise a reloaded named wallet shows an
  -- empty ledger until an explicit rescanblockchain, because the per-block
  -- block-connect hook only feeds the DEFAULT wallet (main.lua).
  self.chain_state = nil
  self.mempool = nil
  return self
end

--- Wire the chain context so load_wallet can reconcile a loaded wallet to tip.
-- @param chain_state ChainState
-- @param mempool table|nil
function WalletManager:set_chain_context(chain_state, mempool)
  self.chain_state = chain_state
  self.mempool = mempool
end

--- Ensure wallets directory exists.
-- @return boolean: true on success
function WalletManager:ensure_wallets_dir()
  -- Try to create directory
  local ok = os.execute("mkdir -p '" .. self.wallets_dir .. "'")
  return ok == true or ok == 0
end

--- Get wallet directory path for a wallet name.
-- @param name string: Wallet name
-- @return string: Path to wallet directory
function WalletManager:get_wallet_dir(name)
  if name == "" then
    -- Default wallet is in root data directory (backward compatible)
    return self.datadir
  end
  return self.wallets_dir .. "/" .. name
end

--- Get wallet file path for a wallet name.
-- @param name string: Wallet name
-- @return string: Path to wallet.json file
function WalletManager:get_wallet_path(name)
  return self:get_wallet_dir(name) .. "/wallet.json"
end

--- Check if a wallet is loaded.
-- @param name string: Wallet name
-- @return boolean: true if wallet is loaded
function WalletManager:is_loaded(name)
  return self.wallets[name] ~= nil
end

--- Get list of loaded wallet names.
-- @return table: Array of wallet names
function WalletManager:list_wallets()
  local cjson = require("cjson")
  local names = setmetatable({}, cjson.empty_array_mt)
  for name, _ in pairs(self.wallets) do
    names[#names + 1] = name
  end
  table.sort(names)
  return names
end

--- Get a loaded wallet by name.
-- @param name string: Wallet name (empty string for default)
-- @return Wallet|nil: Wallet instance, or nil if not loaded
function WalletManager:get_wallet(name)
  return self.wallets[name]
end

--- Get default wallet (first loaded or named "").
-- @return Wallet|nil: Default wallet, or nil if no wallets loaded
function WalletManager:get_default_wallet()
  if self.default_wallet and self.wallets[self.default_wallet] then
    return self.wallets[self.default_wallet], self.default_wallet
  end
  -- Fallback: empty string wallet or first loaded
  if self.wallets[""] then
    return self.wallets[""], ""
  end
  -- Return first loaded wallet
  for name, wallet in pairs(self.wallets) do
    return wallet, name
  end
  return nil, nil
end

--- Try to acquire a file lock for a wallet.
-- @param name string: Wallet name
-- @return boolean: true if lock acquired
-- @return string|nil: Error message if failed
function WalletManager:acquire_lock(name)
  local wallet_dir = self:get_wallet_dir(name)
  local lock_path = wallet_dir .. "/.lock"

  -- Create lock file if it doesn't exist. Cast the variadic mode to a C int so
  -- it lands with real 0600 perms (a bare Lua number yields 0000 — see save()).
  local fd = ffi.C.open(lock_path, bit.bor(O_RDWR, O_CREAT), ffi.cast("int", 0x180))  -- 0600
  if fd < 0 then
    return false, "Cannot open lock file: " .. lock_path
  end

  -- Try to get exclusive lock (non-blocking)
  if not lock_file(fd) then
    ffi.C.close(fd)
    return false, "Wallet is locked by another process"
  end

  self.wallet_locks[name] = fd
  return true
end

--- Release file lock for a wallet.
-- @param name string: Wallet name
function WalletManager:release_lock(name)
  local fd = self.wallet_locks[name]
  if fd then
    unlock_file(fd)
    ffi.C.close(fd)
    self.wallet_locks[name] = nil
  end
end

--- Create a new wallet.
-- @param name string: Wallet name
-- @param options table: Options {disable_private_keys, blank, passphrase, descriptors}
-- @return Wallet|nil: New wallet, or nil on error
-- @return string|nil: Error message
function WalletManager:create_wallet(name, options)
  options = options or {}

  -- Validate name
  if name:find("[/\\:*?\"<>|]") then
    return nil, "Invalid wallet name: contains illegal characters"
  end

  -- Check if already loaded
  if self.wallets[name] then
    return nil, "Wallet \"" .. name .. "\" is already loaded"
  end

  -- Check if wallet already exists
  local wallet_path = self:get_wallet_path(name)
  if M.exists(wallet_path) then
    return nil, "Wallet \"" .. name .. "\" already exists"
  end

  -- Ensure wallets directory exists
  if name ~= "" then
    self:ensure_wallets_dir()
    local wallet_dir = self:get_wallet_dir(name)
    os.execute("mkdir -p '" .. wallet_dir .. "'")
  end

  -- Acquire lock
  local lock_ok, lock_err = self:acquire_lock(name)
  if not lock_ok then
    return nil, lock_err
  end

  -- Create wallet
  local wallet
  if options.blank or options.disable_private_keys then
    -- Create blank wallet (no keys)
    wallet = M.new(self.network, self.storage)
    wallet.is_locked = not options.disable_private_keys
  else
    -- Create with new seed
    wallet = M.create(self.network, self.storage, options.passphrase)
  end

  -- WALLET_FLAG_DISABLE_PRIVATE_KEYS (Core rpc/wallet.cpp:381-383): a watch-only
  -- wallet has private keys DISABLED. Drive getwalletinfo.private_keys_enabled +
  -- the -4 key-op guards off this explicit flag (NOT is_locked / master_key
  -- presence), and persist it so the flag survives a reload.
  wallet.private_keys_enabled = not (options.disable_private_keys == true)

  -- Save wallet
  local save_ok, save_err = wallet:save(wallet_path)
  if not save_ok then
    self:release_lock(name)
    return nil, save_err
  end

  -- Add to loaded wallets
  self.wallets[name] = wallet

  -- Set as default if first wallet
  if self.default_wallet == nil then
    self.default_wallet = name
  end

  return wallet
end

--- Load an existing wallet.
-- @param name string: Wallet name (or path for backward compat)
-- @param passphrase string: Passphrase for encrypted wallets (optional)
-- @return Wallet|nil: Loaded wallet, or nil on error
-- @return string|nil: Error message
function WalletManager:load_wallet(name, passphrase)
  -- Check if already loaded
  if self.wallets[name] then
    return nil, "Wallet \"" .. name .. "\" is already loaded"
  end

  -- Check if wallet exists
  local wallet_path = self:get_wallet_path(name)
  if not M.exists(wallet_path) then
    return nil, "Wallet file not found: " .. wallet_path
  end

  -- Acquire lock
  local lock_ok, lock_err = self:acquire_lock(name)
  if not lock_ok then
    return nil, lock_err
  end

  -- Load wallet
  local wallet, load_err = M.load(wallet_path, self.network, self.storage, passphrase)
  if not wallet then
    self:release_lock(name)
    return nil, load_err
  end

  -- Add to loaded wallets
  self.wallets[name] = wallet

  -- Set as default if first wallet
  if self.default_wallet == nil then
    self.default_wallet = name
  end

  -- Reconcile a freshly-loaded wallet to the chain tip so its ledger is rebuilt
  -- from the (persisted) owned-script + watch-only set. Named wallets are NOT
  -- fed by the per-block hook (main.lua wires it to the default wallet only), so
  -- without this a reloaded watch-only wallet shows balance 0 / empty listunspent
  -- until an explicit rescanblockchain — the restart-survival hole. Cheap no-op
  -- when not scanned or already at tip. Isolated under pcall (a reconcile hiccup
  -- must not fail the load). last_synced_height is intentionally NOT forced to 0:
  -- reconcile_to_tip rebuilds the whole ledger from chainstate idempotently.
  if self.chain_state and wallet.scanned then
    pcall(function()
      wallet:reconcile_to_tip(self.chain_state, self.mempool)
    end)
  end

  return wallet
end

--- Unload a wallet.
-- @param name string: Wallet name
-- @return boolean: true on success
-- @return string|nil: Error message
function WalletManager:unload_wallet(name)
  local wallet = self.wallets[name]
  if not wallet then
    return false, "Wallet \"" .. name .. "\" is not loaded"
  end

  -- Save wallet before unloading
  local wallet_path = self:get_wallet_path(name)
  local save_ok, save_err = wallet:save(wallet_path)
  if not save_ok then
    return false, "Failed to save wallet: " .. (save_err or "unknown error")
  end

  -- Remove from loaded wallets
  self.wallets[name] = nil

  -- Release lock
  self:release_lock(name)

  -- Update default wallet if needed
  if self.default_wallet == name then
    self.default_wallet = nil
    -- Set new default to first available
    for new_name, _ in pairs(self.wallets) do
      self.default_wallet = new_name
      break
    end
  end

  return true
end

--- List wallets in wallet directory (loaded and unloaded).
-- @return table: Array of {name=string, loaded=boolean}
function WalletManager:list_wallet_dir()
  local wallets = {}

  -- Check for default wallet in data dir
  if M.exists(self.datadir .. "/wallet.json") then
    wallets[#wallets + 1] = {
      name = "",
      loaded = self.wallets[""] ~= nil,
    }
  end

  -- Scan wallets directory
  local handle = io.popen("ls -1 '" .. self.wallets_dir .. "' 2>/dev/null")
  if handle then
    for dir in handle:lines() do
      local wallet_path = self.wallets_dir .. "/" .. dir .. "/wallet.json"
      if M.exists(wallet_path) then
        wallets[#wallets + 1] = {
          name = dir,
          loaded = self.wallets[dir] ~= nil,
        }
      end
    end
    handle:close()
  end

  return wallets
end

-- Export WalletManager class
M.WalletManager = WalletManager

return M
