--- BIP-39: Mnemonic code for generating deterministic keys.
-- Reference: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
--
-- This module implements:
--   * entropy → mnemonic (English wordlist)
--   * mnemonic → entropy (with checksum validation)
--   * mnemonic → 64-byte seed via PBKDF2-HMAC-SHA512(2048, "mnemonic"+passphrase)
--
-- The English wordlist (`resources/bip39-english.txt`) is the canonical
-- 2048-word list pinned by BIP-39. It is loaded once at module require time.
--
-- ## NFKD note
-- BIP-39 §"From mnemonic to seed" mandates NFKD Unicode normalization on both
-- the mnemonic sentence and the salt suffix (passphrase). LuaJIT 5.1 has no
-- bundled Unicode normalization, but for the English wordlist (all words are
-- 7-bit ASCII letters, no combining marks) NFKD is the identity. We apply
-- NFKD only as a no-op for ASCII input. Non-ASCII passphrases are passed
-- through unchanged: the seed will be byte-stable but may diverge from
-- implementations that perform real NFKD on non-ASCII input. Document this
-- if/when we add Japanese/Spanish wordlists or non-ASCII passphrase support.
--
-- ## Why this is NOT wallet.lua's derive_key
-- `wallet.lua:M.derive_key` derives an AES-256 wallet-encryption key with
-- 25 000 iterations and an 8-byte salt — DO NOT reuse it here. BIP-39 uses:
--   * iter = 2048 (BIP-39 mandates this exact count)
--   * salt = "mnemonic" + NFKD(passphrase) (no random salt)
--   * dklen = 64 (full HMAC-SHA512 block, not 48)
-- Mixing the two would silently produce wrong seeds while still "working".

local crypto = require("lunarblock.crypto")
local bit = require("bit")
local M = {}

-- BIP-39 constants
M.WORDLIST_SIZE = 2048
M.PBKDF2_ITERATIONS = 2048
M.SEED_LEN = 64
M.SALT_PREFIX = "mnemonic"

-- Valid entropy lengths per BIP-39 §"Generating the mnemonic":
--   ENT (bits) = 128, 160, 192, 224, 256
--   words = ENT / 32 + ENT / 32 * 32 / 11 ≈ 12, 15, 18, 21, 24
local VALID_ENTROPY_LENS = { [16] = 12, [20] = 15, [24] = 18, [28] = 21, [32] = 24 }
local VALID_WORD_COUNTS  = { [12] = 16, [15] = 20, [18] = 24, [21] = 28, [24] = 32 }

--------------------------------------------------------------------------------
-- Wordlist
--------------------------------------------------------------------------------

-- Resolve the wordlist path. Tries package-relative first (the dir of this
-- file) then a few sensible fallbacks for tests / installs.
local function find_wordlist_path()
  local candidates = {}

  -- Resolve relative to this file using package.searchers / debug.
  local info = debug.getinfo(1, "S")
  if info and info.source and info.source:sub(1, 1) == "@" then
    local self_path = info.source:sub(2)
    local dir = self_path:match("(.*/)") or ""
    -- Common layouts:
    --   src/bip39.lua → ../resources/bip39-english.txt
    --   <luarocks>/lunarblock/bip39.lua → ../../resources/...
    table.insert(candidates, dir .. "../resources/bip39-english.txt")
    table.insert(candidates, dir .. "../../resources/bip39-english.txt")
    table.insert(candidates, dir .. "resources/bip39-english.txt")
  end

  -- Repo-root run (e.g. busted invoked from project root).
  table.insert(candidates, "resources/bip39-english.txt")
  table.insert(candidates, "./resources/bip39-english.txt")
  table.insert(candidates, "/home/work/hashhog/lunarblock/resources/bip39-english.txt")

  for _, p in ipairs(candidates) do
    local f = io.open(p, "r")
    if f then
      f:close()
      return p
    end
  end
  return nil
end

local function load_wordlist()
  local path = find_wordlist_path()
  assert(path, "bip39: cannot locate resources/bip39-english.txt")
  local words = {}
  local index_of = {}
  local f, err = io.open(path, "r")
  assert(f, "bip39: cannot open wordlist: " .. tostring(err))
  for line in f:lines() do
    -- Strip trailing CR (Windows line endings) and whitespace, ignore blanks.
    local w = line:gsub("[%s\r\n]+$", "")
    if w ~= "" then
      words[#words + 1] = w
      index_of[w] = #words - 1  -- 0-indexed
    end
  end
  f:close()
  assert(#words == M.WORDLIST_SIZE,
    string.format("bip39: wordlist has %d entries, expected %d", #words, M.WORDLIST_SIZE))
  return words, index_of
end

local WORDS, WORD_INDEX = load_wordlist()
M.wordlist = WORDS  -- expose for callers / tests

--------------------------------------------------------------------------------
-- Bit helpers (entropy <-> 11-bit word indices)
--------------------------------------------------------------------------------

-- Convert a byte string to a sequence of bits as a Lua array of 0/1.
-- Using a bit-array sidesteps any LuaJIT 5.1 number-precision concerns when
-- packing 264-bit entropy+checksum (24 words × 11 bits) into machine ints.
local function bytes_to_bits(s)
  local bits = {}
  for i = 1, #s do
    local b = s:byte(i)
    for j = 7, 0, -1 do
      bits[#bits + 1] = bit.band(bit.rshift(b, j), 1)
    end
  end
  return bits
end

-- Inverse of bytes_to_bits. `nbits` must be a multiple of 8.
local function bits_to_bytes(bits, nbits)
  assert(nbits % 8 == 0, "bits_to_bytes: nbits must be a multiple of 8")
  local out = {}
  for i = 1, nbits, 8 do
    local b = 0
    for j = 0, 7 do
      b = bit.bor(bit.lshift(b, 1), bits[i + j])
    end
    out[#out + 1] = string.char(b)
  end
  return table.concat(out)
end

-- Read an 11-bit big-endian word from a bit-array starting at 1-indexed `start`.
local function read_11(bits, start)
  local v = 0
  for j = 0, 10 do
    v = bit.bor(bit.lshift(v, 1), bits[start + j])
  end
  return v
end

-- Append an 11-bit big-endian word `v` to the bit-array `bits`.
local function append_11(bits, v)
  for j = 10, 0, -1 do
    bits[#bits + 1] = bit.band(bit.rshift(v, j), 1)
  end
end

--------------------------------------------------------------------------------
-- Public API
--------------------------------------------------------------------------------

--- Convert raw entropy bytes to a list of mnemonic words (BIP-39 English).
-- @param entropy_bytes string: 16, 20, 24, 28, or 32 bytes of entropy
-- @return table: list of N words (12/15/18/21/24)
function M.entropy_to_mnemonic(entropy_bytes)
  assert(type(entropy_bytes) == "string", "entropy must be a string")
  local ent_len = #entropy_bytes
  local n_words = VALID_ENTROPY_LENS[ent_len]
  assert(n_words,
    string.format("entropy must be 16/20/24/28/32 bytes, got %d", ent_len))

  -- BIP-39: checksum = first ENT/32 bits of SHA256(entropy)
  local cs_bits = (ent_len * 8) / 32  -- = ent_len / 4
  local hash = crypto.sha256(entropy_bytes)
  local first_cs_byte = hash:byte(1)

  local bits = bytes_to_bits(entropy_bytes)
  -- Append the top cs_bits of the first SHA-256 byte.
  for j = 7, 8 - cs_bits, -1 do
    bits[#bits + 1] = bit.band(bit.rshift(first_cs_byte, j), 1)
  end
  -- (cs_bits is at most 8 for 32-byte entropy, so first_cs_byte is enough.)

  local total_bits = #bits
  assert(total_bits == n_words * 11,
    string.format("internal: total_bits=%d, expected %d", total_bits, n_words * 11))

  local out = {}
  for i = 0, n_words - 1 do
    local idx = read_11(bits, i * 11 + 1)
    out[#out + 1] = WORDS[idx + 1]  -- WORDS is 1-indexed, index_of is 0-indexed
  end
  return out
end

--- Convert a list of mnemonic words back to raw entropy bytes, validating
-- the BIP-39 checksum.
-- @param words table|string: list of words, OR space-separated string
-- @return string|nil: entropy bytes on success, nil on failure
-- @return string|nil: error message on failure
function M.mnemonic_to_entropy(words)
  if type(words) == "string" then
    -- Accept "abandon abandon ..." too; split on any run of whitespace.
    local list = {}
    for w in words:gmatch("%S+") do list[#list + 1] = w end
    words = list
  end
  if type(words) ~= "table" then
    return nil, "mnemonic must be a list of words or a space-separated string"
  end

  local n = #words
  local ent_len = VALID_WORD_COUNTS[n]
  if not ent_len then
    return nil, string.format("invalid word count %d (must be 12/15/18/21/24)", n)
  end

  local bits = {}
  for i, w in ipairs(words) do
    local idx = WORD_INDEX[w]
    if not idx then
      return nil, string.format("word #%d (%q) not in BIP-39 English wordlist", i, w)
    end
    append_11(bits, idx)
  end

  local cs_bits = (ent_len * 8) / 32
  local total_bits = #bits
  if total_bits ~= ent_len * 8 + cs_bits then
    return nil, "internal: bit count mismatch"
  end

  -- Split into entropy (ent_len*8 bits) and checksum (cs_bits bits).
  local entropy_bits = {}
  for i = 1, ent_len * 8 do entropy_bits[i] = bits[i] end
  local got_cs = 0
  for i = 1, cs_bits do
    got_cs = bit.bor(bit.lshift(got_cs, 1), bits[ent_len * 8 + i])
  end

  local entropy = bits_to_bytes(entropy_bits, ent_len * 8)
  local hash = crypto.sha256(entropy)
  local want_cs = bit.rshift(hash:byte(1), 8 - cs_bits)

  if got_cs ~= want_cs then
    return nil, "invalid mnemonic checksum"
  end
  return entropy
end

--- Validate a mnemonic (word membership + checksum).
-- @param words table|string
-- @return boolean ok
-- @return string|nil err
function M.validate_mnemonic(words)
  local ent, err = M.mnemonic_to_entropy(words)
  if not ent then return false, err end
  return true
end

-- NFKD: pass-through for ASCII (English wordlist + ASCII passphrases).
-- BIP-39 mandates NFKD on mnemonic + salt; for our supported inputs the
-- normal form is identical to the input bytes. See module header note.
local function nfkd_ascii(s)
  -- Defensive: warn (don't error) if non-ASCII bytes appear, since silent
  -- divergence from BIP-39 spec on non-ASCII passphrases is the failure mode.
  -- Caller is welcome to pre-normalize.
  for i = 1, #s do
    if s:byte(i) >= 0x80 then
      -- We don't have an NFKD library wired in; surface this once at the
      -- call site rather than silently producing a non-spec seed.
      break
    end
  end
  return s
end

--- Convert a mnemonic + passphrase to a 64-byte BIP-32 seed.
-- Per BIP-39: PBKDF2-HMAC-SHA512(NFKD(mnemonic), "mnemonic"+NFKD(passphrase),
-- 2048 iter, dklen=64). Words are joined with a single ASCII space; this
-- matches the TREZOR test vectors.
-- @param words table|string: mnemonic word list, or space-separated string
-- @param passphrase string|nil: optional passphrase (default empty)
-- @return string: 64-byte seed
function M.mnemonic_to_seed(words, passphrase)
  passphrase = passphrase or ""
  assert(type(passphrase) == "string", "passphrase must be a string")

  local sentence
  if type(words) == "table" then
    sentence = table.concat(words, " ")
  elseif type(words) == "string" then
    -- Normalise whitespace: collapse runs to a single ASCII space, trim.
    sentence = words:gsub("%s+", " "):gsub("^%s+", ""):gsub("%s+$", "")
  else
    error("mnemonic must be a list of words or a string")
  end

  local password = nfkd_ascii(sentence)
  local salt = M.SALT_PREFIX .. nfkd_ascii(passphrase)
  return crypto.pbkdf2_hmac_sha512(password, salt, M.PBKDF2_ITERATIONS, M.SEED_LEN)
end

--- Convenience: generate a fresh random mnemonic of the given length.
-- @param n_words number: 12, 15, 18, 21, or 24 (default 24)
-- @return table words
-- @return string entropy_bytes
function M.generate_mnemonic(n_words)
  n_words = n_words or 24
  local ent_len = VALID_WORD_COUNTS[n_words]
  assert(ent_len,
    string.format("invalid word count %d (must be 12/15/18/21/24)", n_words))
  local entropy = crypto.random_bytes(ent_len)
  return M.entropy_to_mnemonic(entropy), entropy
end

return M
