local ffi = require("ffi")
local bit = require("bit")
local crypto = require("lunarblock.crypto")
local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local address = require("lunarblock.address")
local script = require("lunarblock.script")
local consensus = require("lunarblock.consensus")
local validation = require("lunarblock.validation")
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

--- Random selection fallback (simple largest-first with randomization).
-- Used when BnB fails to find an exact match.
-- @param utxos table: Array of {key=string, utxo={value=number, ...}}
-- @param target number: Target amount including fees
-- @return table|nil: Selected UTXOs
function M.select_coins_random(utxos, target)
  -- Shuffle the UTXOs
  local shuffled = {}
  for i, item in ipairs(utxos) do
    shuffled[i] = item
  end
  for i = #shuffled, 2, -1 do
    local j = math.random(1, i)
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

  -- Check that il is a valid key
  if not is_valid_key(il) then
    -- Skip this index (extremely rare)
    return M.derive_child(parent, index + 1)
  end

  local child_key
  if parent.is_private then
    -- child_key = (il + parent_key) mod n
    child_key = add_mod_n(il, parent.key)

    -- Check that child key is valid
    if not is_valid_key(child_key) then
      return M.derive_child(parent, index + 1)
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
-- BIP44/BIP84 Path Derivation
--------------------------------------------------------------------------------

-- Derive a BIP44 path: m/44'/0'/account'/change/index
function M.derive_bip44_key(master, account, change, index)
  local purpose = M.derive_child(master, 0x80000000 + 44)   -- 44'
  local coin = M.derive_child(purpose, 0x80000000 + 0)      -- 0' (Bitcoin)
  local acct = M.derive_child(coin, 0x80000000 + account)   -- account'
  local chain = M.derive_child(acct, change)                 -- 0 = external, 1 = internal
  return M.derive_child(chain, index)
end

-- Derive a BIP84 path: m/84'/0'/account'/change/index (native segwit)
function M.derive_bip84_key(master, account, change, index)
  local purpose = M.derive_child(master, 0x80000000 + 84)
  local coin = M.derive_child(purpose, 0x80000000 + 0)
  local acct = M.derive_child(coin, 0x80000000 + account)
  local chain = M.derive_child(acct, change)
  return M.derive_child(chain, index)
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
  self.addresses = {}              -- ordered list of addresses
  self.utxos = {}                  -- outpoint_key -> {value, script_pubkey, address, txid, vout}
  self.pending_utxos = {}          -- Unconfirmed UTXOs (in mempool)
  self.spent_pending = {}          -- Outpoints spent in pending transactions
  self.transactions = {}           -- txid_hex -> {tx, height, time, fee}
  self.confirmed_balance = 0       -- Balance from confirmed transactions
  self.unconfirmed_balance = 0     -- Balance from unconfirmed transactions
  self.next_external_index = 0     -- BIP44 external chain index
  self.next_internal_index = 0     -- BIP44 internal (change) chain index
  self.gap_limit = 20              -- BIP44 address gap limit
  self.account = 0
  self.address_type = "p2wpkh"     -- Default address type
  self.fee_estimator = nil         -- Optional fee estimator
  self.mempool = nil               -- Optional mempool reference
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

  -- Regenerate private keys for all addresses
  for addr, key_info in pairs(self.keys) do
    if key_info.change ~= nil and key_info.index >= 0 then
      local derived
      if key_info.type == "p2wpkh" then
        derived = M.derive_bip84_key(self.master_key, self.account, key_info.change, key_info.index)
      else
        derived = M.derive_bip44_key(self.master_key, self.account, key_info.change, key_info.index)
      end
      key_info.privkey = derived.key
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
  local key
  if self.address_type == "p2wpkh" then
    key = M.derive_bip84_key(self.master_key, self.account, change, index)
  else
    key = M.derive_bip44_key(self.master_key, self.account, change, index)
  end

  local pubkey = crypto.pubkey_from_privkey(key.key, true)
  local addr
  if self.address_type == "p2wpkh" then
    addr = address.pubkey_to_p2wpkh(pubkey, self.network.name)
  else
    addr = address.pubkey_to_p2pkh(pubkey, self.network.name)
  end

  self.keys[addr] = {
    privkey = key.key,
    pubkey = pubkey,
    path = string.format("m/%d'/%d'/%d'/%d/%d",
      self.address_type == "p2wpkh" and 84 or 44, 0, self.account, change, index),
    type = self.address_type,
    change = change,
    index = index,
  }
  self.addresses[#self.addresses + 1] = addr
  return addr
end

function Wallet:get_new_address()
  local addr = self:generate_address(0, self.next_external_index)
  self.next_external_index = self.next_external_index + 1
  return addr
end

function Wallet:get_change_address()
  local addr = self:generate_address(1, self.next_internal_index)
  self.next_internal_index = self.next_internal_index + 1
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
    elseif script_type == "p2pkh" then
      local version = self.network.pubkey_address_prefix
      addr = address.base58check_encode(version, hash_or_program)
    end

    if addr and self.keys[addr] then
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
        -- Check coinbase maturity
        if utxo.is_coinbase then
          if utxo.confirmations >= consensus.COINBASE_MATURITY then
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

  -- 8. Sign inputs
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

--- Send a transaction to the mempool.
-- @param tx transaction: Signed transaction
-- @return boolean: true on success
-- @return string|nil: Error message on failure
function Wallet:send_transaction(tx)
  if not self.mempool then
    return false, "No mempool configured"
  end

  local ok, err = self.mempool:accept_transaction(tx, true)
  if not ok then
    return false, err
  end

  -- Track the transaction
  local txid = validation.compute_txid(tx)
  self.transactions[types.hash256_hex(txid)] = {
    tx = tx,
    height = 0,  -- unconfirmed
    time = os.time(),
    fee = 0,  -- TODO: calculate from inputs - outputs
  }

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

  local ok, err = self:send_transaction(tx)
  if not ok then
    return nil, err
  end

  return tx
end

--------------------------------------------------------------------------------
-- Wallet Info Queries
--------------------------------------------------------------------------------

--- Get confirmed balance.
-- @return number: Balance in satoshis
function Wallet:get_balance()
  return self.confirmed_balance
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
  for key, utxo in pairs(self.utxos) do
    if not self.spent_pending[key] then
      -- Check coinbase maturity
      if utxo.is_coinbase then
        if utxo.confirmations >= consensus.COINBASE_MATURITY then
          spendable = spendable + utxo.value
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
    if utxo.is_coinbase and utxo.confirmations < consensus.COINBASE_MATURITY then
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

-- Import a WIF private key
function Wallet:import_privkey(wif)
  local version, payload = address.base58check_decode(wif)
  assert(version == self.network.wif_prefix, "Wrong network WIF prefix")
  local compressed = (#payload == 33 and payload:byte(33) == 0x01)
  local privkey = payload:sub(1, 32)
  local pubkey = crypto.pubkey_from_privkey(privkey, compressed)
  local addr
  if compressed and self.address_type == "p2wpkh" then
    addr = address.pubkey_to_p2wpkh(pubkey, self.network.name)
  else
    addr = address.pubkey_to_p2pkh(pubkey, self.network.name)
  end
  self.keys[addr] = {
    privkey = privkey,
    pubkey = pubkey,
    path = "imported",
    type = compressed and self.address_type or "p2pkh",
    change = 0,
    index = -1,
  }
  self.addresses[#self.addresses + 1] = addr
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
]]

-- fcntl constants
local F_SETLK = 6
local F_SETLKW = 7
local F_WRLCK = 1
local F_UNLCK = 2
local O_RDWR = 2
local O_CREAT = 64
local O_TRUNC = 512
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
  }

  if self.is_encrypted then
    -- Store encrypted key
    data.encrypted_master_key = M.hex_encode(self.encrypted_master_key)
    data.encryption_salt = M.hex_encode(self.encryption_salt)
  else
    -- Store unencrypted (for non-encrypted wallets)
    if self.master_key then
      data.master_key = M.hex_encode(self.master_key.key)
      data.master_chain_code = M.hex_encode(self.master_key.chain_code)
    end
  end

  return encode(data)
end

--- Save wallet to file with exclusive locking.
-- @param filepath string: Path to wallet file
-- @return boolean: true on success
-- @return string|nil: Error message on failure
function Wallet:save(filepath)
  local data = self:serialize()

  -- Open file with exclusive lock
  local fd = ffi.C.open(filepath, bit.bor(O_RDWR, O_CREAT, O_TRUNC), 0x180)  -- 0600
  if fd < 0 then
    return false, "Cannot open wallet file for writing"
  end

  if not lock_file(fd) then
    ffi.C.close(fd)
    return false, "Cannot acquire lock on wallet file"
  end

  -- Write data
  local written = ffi.C.write(fd, data, #data)
  if written ~= #data then
    unlock_file(fd)
    ffi.C.close(fd)
    return false, "Failed to write wallet data"
  end

  unlock_file(fd)
  ffi.C.close(fd)
  return true
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

  -- Open and lock file
  local fd = ffi.C.open(filepath, O_RDWR, 0)
  if fd < 0 then
    return nil, "Wallet file not found"
  end

  if not lock_file(fd) then
    ffi.C.close(fd)
    return nil, "Cannot acquire lock on wallet file"
  end

  -- Get file size
  local size = ffi.C.lseek(fd, 0, SEEK_END)
  ffi.C.lseek(fd, 0, SEEK_SET)

  -- Read data
  local buf = ffi.new("char[?]", size + 1)
  local bytes_read = ffi.C.read(fd, buf, size)
  unlock_file(fd)
  ffi.C.close(fd)

  if bytes_read ~= size then
    return nil, "Failed to read wallet file"
  end

  local raw = ffi.string(buf, size)
  local data = decode(raw)

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
    wallet.is_locked = true

    -- Try to unlock if passphrase provided
    if passphrase then
      local ok, err = wallet:unlock(passphrase)
      if not ok then
        return nil, err
      end
    end
  else
    -- Load unencrypted key
    if data.master_key and data.master_chain_code then
      local seed_key = M.hex_decode(data.master_key)
      local chain_code = M.hex_decode(data.master_chain_code)
      wallet.master_key = M.extended_key(seed_key, chain_code, 0, "\0\0\0\0", 0, true)
      wallet.is_locked = false
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
  return self
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
  local names = {}
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

  -- Create lock file if it doesn't exist
  local fd = ffi.C.open(lock_path, bit.bor(O_RDWR, O_CREAT), 0x180)  -- 0600
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
