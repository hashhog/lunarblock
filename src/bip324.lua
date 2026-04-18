-- BIP324 v2 Encrypted P2P Transport
-- Implements ElligatorSwift key exchange, HKDF-SHA256 key derivation,
-- forward-secure ChaCha20-Poly1305 AEAD, and the v2 message encoding.

local ffi = require("ffi")
local bit = require("bit")
local crypto = require("lunarblock.crypto")
local M = {}

--------------------------------------------------------------------------------
-- Constants
--------------------------------------------------------------------------------

M.ELLSWIFT_SIZE = 64           -- ElligatorSwift public key size
M.SESSION_ID_LEN = 32          -- Session ID length
M.GARBAGE_TERMINATOR_LEN = 16  -- Garbage terminator length
M.MAX_GARBAGE_LEN = 4095       -- Maximum garbage length
M.REKEY_INTERVAL = 224         -- Packets before rekeying
M.LENGTH_LEN = 3               -- Encrypted length field size
M.HEADER_LEN = 1               -- Encrypted header size
M.TAG_LEN = 16                 -- Poly1305 tag size
M.EXPANSION = M.LENGTH_LEN + M.HEADER_LEN + M.TAG_LEN  -- Total overhead (20 bytes)

-- Header flags
M.IGNORE_BIT = 0x80            -- Decoy packet flag

--------------------------------------------------------------------------------
-- Short Message Type IDs (BIP324)
--------------------------------------------------------------------------------

-- Maps 1-byte ID to message type string
-- ID 0 means 12-byte string encoding follows
M.MESSAGE_IDS = {
  [0] = "",            -- Long encoding follows
  [1] = "addr",
  [2] = "block",
  [3] = "blocktxn",
  [4] = "cmpctblock",
  [5] = "feefilter",
  [6] = "filteradd",
  [7] = "filterclear",
  [8] = "filterload",
  [9] = "getblocks",
  [10] = "getblocktxn",
  [11] = "getdata",
  [12] = "getheaders",
  [13] = "headers",
  [14] = "inv",
  [15] = "mempool",
  [16] = "merkleblock",
  [17] = "notfound",
  [18] = "ping",
  [19] = "pong",
  [20] = "sendcmpct",
  [21] = "tx",
  [22] = "getcfilters",
  [23] = "cfilter",
  [24] = "getcfheaders",
  [25] = "cfheaders",
  [26] = "getcfcheckpt",
  [27] = "cfcheckpt",
  [28] = "addrv2",
  -- 29-32 reserved
}

-- Reverse map: message type string to 1-byte ID
M.MESSAGE_MAP = {}
for id, name in pairs(M.MESSAGE_IDS) do
  if name ~= "" then
    M.MESSAGE_MAP[name] = id
  end
end

--------------------------------------------------------------------------------
-- HKDF-SHA256 (RFC 5869) with fixed output length of 32 bytes
--------------------------------------------------------------------------------

--- HKDF-SHA256 extract phase.
-- @param salt string: salt value
-- @param ikm string: input keying material
-- @return string: 32-byte pseudorandom key (PRK)
local function hkdf_extract(salt, ikm)
  return crypto.hmac_sha256(salt, ikm)
end

--- HKDF-SHA256 expand phase with 32-byte output.
-- @param prk string: pseudorandom key from extract
-- @param info string: context info string
-- @return string: 32-byte output keying material
local function hkdf_expand32(prk, info)
  -- Single round expansion: output = HMAC(PRK, info || 0x01)
  return crypto.hmac_sha256(prk, info .. "\x01")
end

--------------------------------------------------------------------------------
-- Forward-Secure ChaCha20 (FSChaCha20) for length encryption
--------------------------------------------------------------------------------

--- Create a forward-secure ChaCha20 cipher for length encryption.
-- Rekeys every REKEY_INTERVAL packets.
-- Per BIP324, this is a *continuous* stream cipher: within one rekey period
-- the keystream bytes produced across successive crypt() calls are contiguous
-- blocks of a single ChaCha20 stream with nonce=(0, rekey_counter), NOT a
-- fresh stream-per-packet. See bitcoin-core/src/crypto/chacha20.cpp
-- (FSChaCha20::Crypt) and BIP324 Python reference FSChaCha20. Previously we
-- derived a fresh stream per packet keyed by (packet_counter, rekey_counter),
-- which decrypts packet 0 correctly but corrupts packet 1 onward — Core peers
-- close the connection after our first post-handshake message is sent.
-- @param key string: 32-byte key
-- @param rekey_interval number: packets between rekeys
-- @return table: cipher object
local function FSChaCha20(key, rekey_interval)
  local self = {
    key = key,
    rekey_interval = rekey_interval,
    packet_counter = 0,
    rekey_counter = ffi.new("uint64_t", 0),
    keystream = "",  -- pre-generated keystream for the current rekey period
  }

  -- Build rekey-period nonce (12 bytes: 4-byte zero + 8-byte LE rekey counter)
  local function period_nonce()
    local nonce = ffi.new("unsigned char[12]")
    local rc = self.rekey_counter
    for i = 0, 7 do
      nonce[4 + i] = tonumber(bit.band(bit.rshift(rc, i * 8), 0xFF))
    end
    return ffi.string(nonce, 12)
  end

  -- Generate the full keystream for this rekey period up front:
  -- REKEY_INTERVAL * LENGTH_LEN bytes for packet length crypts, then 32 bytes
  -- of keystream that becomes the next-period key. One chacha20_crypt call
  -- produces the contiguous stream that matches Core's block-counter-driven
  -- incremental keystream.
  local function refill_keystream()
    local zeros = string.rep("\0", self.rekey_interval * M.LENGTH_LEN + 32)
    self.keystream = crypto.chacha20_crypt(self.key, period_nonce(), zeros)
  end

  refill_keystream()

  -- Encrypt/decrypt (same operation for stream cipher)
  function self:crypt(data)
    local n = #data
    local off = self.packet_counter * M.LENGTH_LEN
    local ks = self.keystream:sub(off + 1, off + n)
    local out = ffi.new("unsigned char[?]", n)
    for i = 0, n - 1 do
      out[i] = bit.bxor(data:byte(i + 1), ks:byte(i + 1))
    end
    local result = ffi.string(out, n)
    self.packet_counter = self.packet_counter + 1
    if self.packet_counter == self.rekey_interval then
      -- New key = last 32 bytes of current period's keystream (continuation
      -- of the same stream, as Core does via m_chacha20.Keystream(new_key)).
      self.key = self.keystream:sub(self.rekey_interval * M.LENGTH_LEN + 1,
                                    self.rekey_interval * M.LENGTH_LEN + 32)
      self.packet_counter = 0
      self.rekey_counter = self.rekey_counter + ffi.new("uint64_t", 1)
      refill_keystream()
    end
    return result
  end

  return self
end

--------------------------------------------------------------------------------
-- Forward-Secure ChaCha20-Poly1305 (FSChaCha20Poly1305) for packet encryption
--------------------------------------------------------------------------------

--- Create a forward-secure ChaCha20-Poly1305 AEAD cipher.
-- Rekeys every REKEY_INTERVAL packets.
-- @param key string: 32-byte key
-- @param rekey_interval number: packets between rekeys
-- @return table: cipher object
local function FSChaCha20Poly1305(key, rekey_interval)
  local self = {
    key = key,
    rekey_interval = rekey_interval,
    packet_counter = 0,
    rekey_counter = ffi.new("uint64_t", 0),
  }

  -- Build nonce from counters (12 bytes: 4-byte packet counter + 8-byte rekey counter)
  local function make_nonce()
    local nonce = ffi.new("unsigned char[12]")
    -- Little-endian packet counter (4 bytes)
    nonce[0] = bit.band(self.packet_counter, 0xFF)
    nonce[1] = bit.band(bit.rshift(self.packet_counter, 8), 0xFF)
    nonce[2] = bit.band(bit.rshift(self.packet_counter, 16), 0xFF)
    nonce[3] = bit.band(bit.rshift(self.packet_counter, 24), 0xFF)
    -- Little-endian rekey counter (8 bytes)
    local rc = self.rekey_counter
    for i = 0, 7 do
      nonce[4 + i] = tonumber(bit.band(bit.rshift(rc, i * 8), 0xFF))
    end
    return ffi.string(nonce, 12)
  end

  -- Rekey using the AEAD keystream.
  -- Per BIP324, the new key is derived from 32 bytes of ChaCha20 keystream
  -- under nonce=(0xFFFFFFFF, rekey_counter) starting at BLOCK 1 (block 0 is
  -- reserved for the Poly1305 one-time key). Core does this via
  -- AEADChaCha20Poly1305::Keystream (Seek(nonce, 1); Keystream(...)), and the
  -- Python reference does it via `aead_chacha20_poly1305_encrypt(key, nonce,
  -- b"", b"\x00"*32)[:32]` — the AEAD encrypt naturally skips block 0.
  -- Bug fixed in W56: the previous implementation called bare ChaCha20 and
  -- took block 0 output as the new key, so after packet_counter reached
  -- rekey_interval (224) our key diverged from the peer's and every
  -- subsequent AEAD decrypt failed with authentication failed. This showed
  -- up in the V2DIAG logs as p_rc=1 p_ctr=0 on every block-sized APP packet.
  local function rekey()
    local rekey_nonce = ffi.new("unsigned char[12]")
    rekey_nonce[0], rekey_nonce[1], rekey_nonce[2], rekey_nonce[3] = 0xFF, 0xFF, 0xFF, 0xFF
    local rc = self.rekey_counter
    for i = 0, 7 do
      rekey_nonce[4 + i] = tonumber(bit.band(bit.rshift(rc, i * 8), 0xFF))
    end
    local rekey_blob = crypto.chacha20poly1305_encrypt(
      self.key, ffi.string(rekey_nonce, 12), string.rep("\0", 32), "")
    self.key = rekey_blob:sub(1, 32)
    self.packet_counter = 0
    self.rekey_counter = self.rekey_counter + ffi.new("uint64_t", 1)
  end

  -- Encrypt plaintext with AAD, returns ciphertext || tag
  function self:encrypt(header, contents, aad)
    local nonce = make_nonce()
    local plaintext = header .. contents
    local result = crypto.chacha20poly1305_encrypt(self.key, nonce, plaintext, aad)
    self.packet_counter = self.packet_counter + 1
    if self.packet_counter == self.rekey_interval then
      rekey()
    end
    return result
  end

  -- Decrypt ciphertext with AAD, returns header, contents or nil on auth failure
  function self:decrypt(ciphertext_with_tag, aad)
    local nonce = make_nonce()
    local plaintext, err = crypto.chacha20poly1305_decrypt(self.key, nonce, ciphertext_with_tag, aad)
    self.packet_counter = self.packet_counter + 1
    if self.packet_counter == self.rekey_interval then
      rekey()
    end
    if not plaintext then
      return nil, nil, err
    end
    local header = plaintext:sub(1, 1)
    local contents = plaintext:sub(2)
    return header, contents
  end

  return self
end

--------------------------------------------------------------------------------
-- BIP324 Cipher
--------------------------------------------------------------------------------

--- Create a BIP324 cipher for encrypting/decrypting v2 P2P messages.
-- @param privkey string: our 32-byte private key
-- @param our_ellswift string: our 64-byte ElligatorSwift public key
-- @return table: cipher object (not yet initialized)
function M.BIP324Cipher(privkey, our_ellswift)
  local self = {
    privkey = privkey,
    our_ellswift = our_ellswift,
    session_id = nil,
    send_garbage_terminator = nil,
    recv_garbage_terminator = nil,
    send_l_cipher = nil,
    send_p_cipher = nil,
    recv_l_cipher = nil,
    recv_p_cipher = nil,
    initialized = false,
  }

  --- Initialize the cipher after receiving the peer's public key.
  -- @param their_ellswift string: peer's 64-byte ElligatorSwift public key
  -- @param initiator boolean: true if we initiated the connection
  -- @param magic_bytes string: 4-byte network magic
  function self:initialize(their_ellswift, initiator, magic_bytes)
    -- Compute ECDH shared secret using BIP324 hash function
    local ecdh_secret = crypto.ellswift_ecdh(
      self.privkey, self.our_ellswift, their_ellswift, initiator
    )
    if not ecdh_secret then
      return false, "ECDH failed"
    end

    -- HKDF salt: "bitcoin_v2_shared_secret" + network magic
    local salt = "bitcoin_v2_shared_secret" .. magic_bytes

    -- Extract PRK from shared secret
    local prk = hkdf_extract(salt, ecdh_secret)

    -- Derive keys
    local initiator_l = hkdf_expand32(prk, "initiator_L")
    local initiator_p = hkdf_expand32(prk, "initiator_P")
    local responder_l = hkdf_expand32(prk, "responder_L")
    local responder_p = hkdf_expand32(prk, "responder_P")
    local garbage_terms = hkdf_expand32(prk, "garbage_terminators")
    self.session_id = hkdf_expand32(prk, "session_id")

    -- Assign keys based on role
    if initiator then
      self.send_l_cipher = FSChaCha20(initiator_l, M.REKEY_INTERVAL)
      self.send_p_cipher = FSChaCha20Poly1305(initiator_p, M.REKEY_INTERVAL)
      self.recv_l_cipher = FSChaCha20(responder_l, M.REKEY_INTERVAL)
      self.recv_p_cipher = FSChaCha20Poly1305(responder_p, M.REKEY_INTERVAL)
      self.send_garbage_terminator = garbage_terms:sub(1, 16)
      self.recv_garbage_terminator = garbage_terms:sub(17, 32)
    else
      self.send_l_cipher = FSChaCha20(responder_l, M.REKEY_INTERVAL)
      self.send_p_cipher = FSChaCha20Poly1305(responder_p, M.REKEY_INTERVAL)
      self.recv_l_cipher = FSChaCha20(initiator_l, M.REKEY_INTERVAL)
      self.recv_p_cipher = FSChaCha20Poly1305(initiator_p, M.REKEY_INTERVAL)
      self.send_garbage_terminator = garbage_terms:sub(17, 32)
      self.recv_garbage_terminator = garbage_terms:sub(1, 16)
    end

    self.initialized = true
    return true
  end

  --- Encrypt a packet.
  -- @param contents string: packet contents (message type + payload)
  -- @param aad string: additional authenticated data (empty for normal packets)
  -- @param ignore boolean: set IGNORE_BIT flag (decoy packet)
  -- @return string: encrypted packet (3-byte length + encrypted payload + tag)
  function self:encrypt(contents, aad, ignore)
    assert(self.initialized, "cipher not initialized")
    aad = aad or ""
    ignore = ignore or false

    -- Encrypt length (3 bytes)
    local len_bytes = string.char(
      bit.band(#contents, 0xFF),
      bit.band(bit.rshift(#contents, 8), 0xFF),
      bit.band(bit.rshift(#contents, 16), 0xFF)
    )
    local enc_len = self.send_l_cipher:crypt(len_bytes)

    -- Build header byte
    local header = string.char(ignore and M.IGNORE_BIT or 0)

    -- Encrypt header + contents with AEAD
    local enc_payload = self.send_p_cipher:encrypt(header, contents, aad)

    return enc_len .. enc_payload
  end

  --- Decrypt the length field from an encrypted packet.
  -- @param enc_len string: 3-byte encrypted length
  -- @return number: decrypted length
  function self:decrypt_length(enc_len)
    assert(self.initialized, "cipher not initialized")
    assert(#enc_len == 3, "encrypted length must be 3 bytes")

    local len_bytes = self.recv_l_cipher:crypt(enc_len)
    return len_bytes:byte(1) +
           len_bytes:byte(2) * 256 +
           len_bytes:byte(3) * 65536
  end

  --- Decrypt a packet (after length has been decrypted).
  -- @param enc_payload string: encrypted payload (after 3-byte length)
  -- @param aad string: additional authenticated data
  -- @return string|nil, boolean: contents and ignore flag, or nil on auth failure
  function self:decrypt(enc_payload, aad)
    assert(self.initialized, "cipher not initialized")
    aad = aad or ""

    local header, contents, err = self.recv_p_cipher:decrypt(enc_payload, aad)
    if not header then
      return nil, false, err
    end

    local ignore = bit.band(header:byte(1), M.IGNORE_BIT) == M.IGNORE_BIT
    return contents, ignore
  end

  return self
end

--------------------------------------------------------------------------------
-- Message Encoding/Decoding
--------------------------------------------------------------------------------

--- Encode a message type and payload for v2 transport.
-- @param msg_type string: message type (e.g., "ping", "version")
-- @param payload string: message payload
-- @return string: encoded contents (1 or 13 bytes type prefix + payload)
function M.encode_message(msg_type, payload)
  payload = payload or ""
  local short_id = M.MESSAGE_MAP[msg_type]
  if short_id then
    -- Short encoding: 1-byte ID + payload
    return string.char(short_id) .. payload
  else
    -- Long encoding: 0x00 + 12-byte null-padded command + payload
    local cmd = msg_type:sub(1, 12)
    cmd = cmd .. string.rep("\0", 12 - #cmd)
    return "\0" .. cmd .. payload
  end
end

--- Decode message type and payload from v2 transport contents.
-- @param contents string: decrypted packet contents
-- @return string|nil, string: message type and payload, or nil on error
function M.decode_message(contents)
  if #contents == 0 then
    return nil, nil, "empty contents"
  end

  local first_byte = contents:byte(1)
  if first_byte ~= 0 then
    -- Short encoding
    local msg_type = M.MESSAGE_IDS[first_byte]
    if not msg_type or msg_type == "" then
      return nil, nil, "unknown short message ID: " .. first_byte
    end
    return msg_type, contents:sub(2)
  else
    -- Long encoding: 12-byte null-padded command
    if #contents < 13 then
      return nil, nil, "long encoding too short"
    end
    local cmd = contents:sub(2, 13)
    -- Find end of command (first null or end of 12 bytes)
    local cmd_end = cmd:find("\0")
    if cmd_end then
      cmd = cmd:sub(1, cmd_end - 1)
    end
    -- Validate command characters (printable ASCII)
    for i = 1, #cmd do
      local c = cmd:byte(i)
      if c < 0x20 or c > 0x7F then
        return nil, nil, "invalid command character"
      end
    end
    return cmd, contents:sub(14)
  end
end

--------------------------------------------------------------------------------
-- V2Transport State Machine
--------------------------------------------------------------------------------

-- Receive states
M.RecvState = {
  KEY_MAYBE_V1 = 1,    -- Responder: waiting to distinguish v1 from v2
  KEY = 2,             -- Receiving peer's ElligatorSwift key
  GARB_GARBTERM = 3,   -- Receiving garbage and garbage terminator
  VERSION = 4,         -- Receiving version packet
  APP = 5,             -- Receiving application packets
  APP_READY = 6,       -- Application packet ready for retrieval
  V1 = 7,              -- Fallback to v1 transport
}

-- Send states
M.SendState = {
  MAYBE_V1 = 1,        -- Responder: not sending until v1/v2 determined
  AWAITING_KEY = 2,    -- Initiator: sent key, waiting for peer's key
  READY = 3,           -- Ready to send encrypted packets
  V1 = 4,              -- Fallback to v1 transport
}

--- Create a V2Transport for encrypted P2P communication.
-- @param magic_bytes string: 4-byte network magic
-- @param initiator boolean: true if we initiated the connection
-- @return table: transport object
function M.V2Transport(magic_bytes, initiator, peer_ip, peer_port)
  -- Generate ephemeral key pair
  -- BIP324: pass 32 bytes of aux randomness to ellswift_create (matches Bitcoin
  -- Core's m_key.EllSwiftCreate(ent32); see bitcoin-core/src/bip324.cpp:28).
  -- Without auxrnd32, libsecp256k1 derives a deterministic encoding that Core
  -- peers silently reject — see wave4-2026-04-14/LUNARBLOCK-BLOCK-SYNC-STALL-DIAG.md.
  local privkey = crypto.random_bytes(32)
  local auxrnd32 = crypto.random_bytes(32)
  local our_ellswift = crypto.ellswift_create(privkey, auxrnd32)
  if not our_ellswift then
    error("failed to create ElligatorSwift key")
  end

  -- Generate random garbage (0 to 4095 bytes)
  local garbage_len = math.random(0, M.MAX_GARBAGE_LEN)
  local garbage = garbage_len > 0 and crypto.random_bytes(garbage_len) or ""

  local self = {
    magic_bytes = magic_bytes,
    initiator = initiator,
    cipher = M.BIP324Cipher(privkey, our_ellswift),
    garbage = garbage,

    -- Receive state
    recv_state = initiator and M.RecvState.KEY or M.RecvState.KEY_MAYBE_V1,
    recv_buffer = "",
    recv_len = 0,         -- Decrypted length for current packet
    recv_aad = "",        -- AAD for next packet (garbage during handshake)
    recv_decode_buffer = "",  -- Decrypted packet ready for retrieval

    -- Send state
    send_state = initiator and M.SendState.AWAITING_KEY or M.SendState.MAYBE_V1,
    send_buffer = "",

    -- For v1 detection
    v1_detected = false,
    v1_prefix = "",       -- First 16 bytes received (for v1 detection)

    -- W60: peer label for diagnostic logging (decrypt_failed lines)
    peer_label = string.format("%s:%s",
      tostring(peer_ip or "?"), tostring(peer_port or "?")),
  }

  --- Get our ElligatorSwift public key for sending during handshake.
  -- @return string: 64-byte public key
  function self:get_pubkey()
    return self.cipher.our_ellswift
  end

  --- Get bytes to send for the handshake (key + garbage).
  -- @return string: bytes to send
  function self:get_handshake_bytes()
    if self.send_state == M.SendState.AWAITING_KEY or
       self.send_state == M.SendState.MAYBE_V1 then
      -- Return key + garbage (already prepared)
      return self.cipher.our_ellswift .. self.garbage
    end
    return ""
  end

  --- Get the garbage terminator to send after handshake.
  -- @return string: 16-byte garbage terminator
  function self:get_garbage_terminator()
    return self.cipher.send_garbage_terminator
  end

  --- Get the expected garbage terminator to receive.
  -- @return string: 16-byte garbage terminator
  function self:get_recv_garbage_terminator()
    return self.cipher.recv_garbage_terminator
  end

  --- Get session ID (after initialization).
  -- @return string: 32-byte session ID
  function self:get_session_id()
    return self.cipher.session_id
  end

  --- Check if the first 16 bytes look like a v1 message.
  -- V1 prefix: magic (4 bytes) + "version" + null padding
  -- @param data string: first 16 bytes received
  -- @return boolean: true if this looks like v1
  local function looks_like_v1(data)
    if #data < 16 then return false end
    -- Check if bytes 5-16 match "version\0\0\0\0\0"
    local expected_cmd = "version\0\0\0\0\0"
    return data:sub(5, 16) == expected_cmd
  end

  --- Process received bytes.
  -- @param data string: received bytes
  -- @return boolean: true if successful, false on error
  -- @return string|nil: error message on failure
  function self:recv_bytes(data)
    self.recv_buffer = self.recv_buffer .. data

    while true do
      if self.recv_state == M.RecvState.KEY_MAYBE_V1 then
        -- Need 16 bytes to distinguish v1 from v2
        if #self.recv_buffer < 16 then
          return true
        end
        local prefix = self.recv_buffer:sub(1, 16)
        if looks_like_v1(prefix) then
          -- V1 connection detected
          self.recv_state = M.RecvState.V1
          self.send_state = M.SendState.V1
          self.v1_detected = true
          self.v1_prefix = prefix
          return true
        end
        -- V2 connection, transition to KEY state
        self.recv_state = M.RecvState.KEY
        self.send_state = M.SendState.AWAITING_KEY
        -- Continue processing
      elseif self.recv_state == M.RecvState.KEY then
        -- For initiator: check for v1 fallback before waiting for full 64 bytes
        if self.initiator and #self.recv_buffer >= 16 and looks_like_v1(self.recv_buffer:sub(1, 16)) then
          self.recv_state = M.RecvState.V1
          self.send_state = M.SendState.V1
          self.v1_detected = true
          self.v1_prefix = self.recv_buffer:sub(1, 16)
          self.recv_buffer = self.recv_buffer:sub(17)
          return true
        end
        -- Need 64 bytes for peer's ElligatorSwift key
        if #self.recv_buffer < M.ELLSWIFT_SIZE then
          return true
        end
        local their_ellswift = self.recv_buffer:sub(1, M.ELLSWIFT_SIZE)
        self.recv_buffer = self.recv_buffer:sub(M.ELLSWIFT_SIZE + 1)

        -- Initialize cipher with peer's key
        local ok, err = self.cipher:initialize(their_ellswift, self.initiator, self.magic_bytes)
        if not ok then
          io.stderr:write(string.format("[%s] V2DIAG bip324 cipher_init_failed err=%s their_ells8=%s\n",
            os.date("!%Y-%m-%dT%H:%M:%SZ"), tostring(err or "?"),
            (their_ellswift:sub(1,8):gsub(".", function(c) return string.format("%02x", c:byte()) end))))
          io.stderr:flush()
          return false, "cipher initialization failed: " .. (err or "unknown")
        end
        io.stderr:write(string.format("[%s] V2DIAG bip324 KEY->GARB_GARBTERM init=%s their_ells8=%s recv_term8=%s\n",
          os.date("!%Y-%m-%dT%H:%M:%SZ"), tostring(self.initiator),
          (their_ellswift:sub(1,8):gsub(".", function(c) return string.format("%02x", c:byte()) end)),
          (self.cipher.recv_garbage_terminator:sub(1,8):gsub(".", function(c) return string.format("%02x", c:byte()) end))))
        io.stderr:flush()

        -- Transition to garbage phase
        self.recv_state = M.RecvState.GARB_GARBTERM
        self.send_state = M.SendState.READY
        -- Continue processing
      elseif self.recv_state == M.RecvState.GARB_GARBTERM then
        -- Look for garbage terminator in received data
        local term = self.cipher.recv_garbage_terminator
        local max_search = M.MAX_GARBAGE_LEN + M.GARBAGE_TERMINATOR_LEN

        -- Search for terminator (last 16 bytes of any position)
        if #self.recv_buffer < M.GARBAGE_TERMINATOR_LEN then
          return true
        end

        local found_at = nil
        for i = 0, math.min(#self.recv_buffer - M.GARBAGE_TERMINATOR_LEN, M.MAX_GARBAGE_LEN) do
          if self.recv_buffer:sub(i + 1, i + M.GARBAGE_TERMINATOR_LEN) == term then
            found_at = i
            break
          end
        end

        if found_at then
          -- Store garbage as AAD for version packet
          self.recv_aad = self.recv_buffer:sub(1, found_at)
          self.recv_buffer = self.recv_buffer:sub(found_at + M.GARBAGE_TERMINATOR_LEN + 1)
          self.recv_state = M.RecvState.VERSION
          io.stderr:write(string.format("[%s] V2DIAG bip324 GARB_GARBTERM->VERSION garb_len=%d\n",
            os.date("!%Y-%m-%dT%H:%M:%SZ"), found_at))
          io.stderr:flush()
          -- Continue processing
        elseif #self.recv_buffer > max_search then
          io.stderr:write(string.format("[%s] V2DIAG bip324 garbage_term_not_found buflen=%d max=%d\n",
            os.date("!%Y-%m-%dT%H:%M:%SZ"), #self.recv_buffer, max_search))
          io.stderr:flush()
          return false, "garbage terminator not found"
        else
          return true
        end
      elseif self.recv_state == M.RecvState.VERSION or self.recv_state == M.RecvState.APP then
        -- Receive encrypted packet
        -- First, decrypt length (3 bytes)
        if #self.recv_buffer < M.LENGTH_LEN then
          return true
        end

        if self.recv_len == 0 then
          local enc_len = self.recv_buffer:sub(1, M.LENGTH_LEN)
          self.recv_len = self.cipher:decrypt_length(enc_len)
        end

        -- Check if we have the full packet
        local packet_size = M.LENGTH_LEN + M.HEADER_LEN + self.recv_len + M.TAG_LEN
        if #self.recv_buffer < packet_size then
          return true
        end

        -- Decrypt packet
        local enc_payload = self.recv_buffer:sub(M.LENGTH_LEN + 1, packet_size)
        -- W54: capture cipher state BEFORE decrypt so a failed auth lets us
        -- compare our nonce vs what the peer used. recv_p_cipher.packet_counter
        -- is the counter that was used for this specific decrypt attempt (the
        -- counter is incremented inside :decrypt() AFTER the call).
        local _pre_p = self.cipher.recv_p_cipher
        local _pre_l = self.cipher.recv_l_cipher
        local _p_ctr = _pre_p and _pre_p.packet_counter or -1
        local _p_rc  = _pre_p and tonumber(_pre_p.rekey_counter) or -1
        local _l_ctr = _pre_l and _pre_l.packet_counter or -1
        local contents, ignore, err = self.cipher:decrypt(enc_payload, self.recv_aad)
        if not contents then
          local function hex8(s)
            if not s or #s == 0 then return "" end
            local n = math.min(8, #s)
            local out = ""
            for i = 1, n do out = out .. string.format("%02x", s:byte(i)) end
            return out
          end
          io.stderr:write(string.format(
            "[%s] V2DIAG bip324 decrypt_failed peer=%s state=%s plen=%d aad_len=%d "
              .. "p_ctr=%d p_rc=%d l_ctr=%d ct8=%s tag8=%s err=%s\n",
            os.date("!%Y-%m-%dT%H:%M:%SZ"), self.peer_label,
            tostring(self.recv_state), self.recv_len,
            #self.recv_aad, _p_ctr, _p_rc, _l_ctr,
            hex8(enc_payload),
            hex8(enc_payload:sub(#enc_payload - 7)),
            tostring(err or "?")))
          io.stderr:flush()
          return false, "decryption failed: " .. (err or "unknown")
        end

        self.recv_buffer = self.recv_buffer:sub(packet_size + 1)
        self.recv_len = 0
        self.recv_aad = ""  -- Clear AAD after first packet in state

        if ignore then
          -- Decoy packet, ignore and continue
          -- W54: log decoy decrypts so the failure-before-first-real-APP
          -- hypothesis can be tested. If we see "decoy_in state=VERSION"
          -- followed by APP decrypt_failed, the bug is downstream of decoy.
          io.stderr:write(string.format(
            "[%s] V2DIAG bip324 decoy_decrypt state=%s plen=%d aad_len=%d\n",
            os.date("!%Y-%m-%dT%H:%M:%SZ"), tostring(self.recv_state),
            self.recv_len, 0))  -- aad already cleared above
          io.stderr:flush()
        else
          if self.recv_state == M.RecvState.VERSION then
            -- Version packet received, transition to APP
            -- (contents are currently ignored per BIP324)
            io.stderr:write(string.format(
              "[%s] V2DIAG bip324 VERSION->APP contents_len=%d\n",
              os.date("!%Y-%m-%dT%H:%M:%SZ"), #contents))
            io.stderr:flush()
            self.recv_state = M.RecvState.APP
          else
            -- Application packet, make available
            self.recv_decode_buffer = contents
            self.recv_state = M.RecvState.APP_READY
            return true
          end
        end
      elseif self.recv_state == M.RecvState.APP_READY then
        -- Packet ready, don't process more until retrieved
        return true
      elseif self.recv_state == M.RecvState.V1 then
        -- V1 mode, caller handles v1 processing
        return true
      else
        return false, "invalid receive state"
      end
    end
  end

  --- Check if a message is ready for retrieval.
  -- @return boolean: true if message is ready
  function self:message_ready()
    return self.recv_state == M.RecvState.APP_READY
  end

  --- Get the received message.
  -- @return string, string: message type and payload
  function self:get_message()
    assert(self.recv_state == M.RecvState.APP_READY, "no message ready")
    local contents = self.recv_decode_buffer
    self.recv_decode_buffer = ""
    self.recv_state = M.RecvState.APP
    return M.decode_message(contents)
  end

  --- Check if cipher is initialized and ready for sending.
  -- @return boolean: true if ready
  function self:ready_to_send()
    return self.send_state == M.SendState.READY and self.cipher.initialized
  end

  --- Encrypt a message for sending.
  -- @param msg_type string: message type
  -- @param payload string: message payload
  -- @return string: encrypted packet bytes
  function self:encrypt_message(msg_type, payload)
    assert(self:ready_to_send(), "not ready to send")
    local contents = M.encode_message(msg_type, payload)
    return self.cipher:encrypt(contents, "", false)
  end

  --- Create the version packet to send after handshake.
  -- @return string: encrypted version packet + garbage terminator
  function self:make_version_packet()
    assert(self.cipher.initialized, "cipher not initialized")
    -- Version packet has empty contents (per BIP324)
    local version_packet = self.cipher:encrypt("", self.garbage, false)
    return self.cipher.send_garbage_terminator .. version_packet
  end

  --- Check if this is a v1 connection.
  -- @return boolean: true if v1 detected
  function self:is_v1()
    return self.v1_detected
  end

  --- Get v1 prefix bytes (for v1 fallback handling).
  -- @return string: first 16 bytes received
  function self:get_v1_prefix()
    return self.v1_prefix .. self.recv_buffer
  end

  return self
end

return M
