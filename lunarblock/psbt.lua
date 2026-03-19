--- BIP174/BIP370 Partially Signed Bitcoin Transaction (PSBT) support
-- Implements creation, serialization, signing, combining, and finalization.

local serialize = require("lunarblock.serialize")
local types = require("lunarblock.types")
local validation = require("lunarblock.validation")
local crypto = require("lunarblock.crypto")
local script = require("lunarblock.script")
local consensus = require("lunarblock.consensus")
local M = {}

--------------------------------------------------------------------------------
-- Constants (BIP174)
--------------------------------------------------------------------------------

-- Magic bytes: "psbt" + 0xff
M.MAGIC = "psbt\xff"

-- Global key types
M.GLOBAL_UNSIGNED_TX = 0x00
M.GLOBAL_XPUB = 0x01
M.GLOBAL_VERSION = 0xFB
M.GLOBAL_PROPRIETARY = 0xFC

-- Input key types
M.IN_NON_WITNESS_UTXO = 0x00
M.IN_WITNESS_UTXO = 0x01
M.IN_PARTIAL_SIG = 0x02
M.IN_SIGHASH_TYPE = 0x03
M.IN_REDEEM_SCRIPT = 0x04
M.IN_WITNESS_SCRIPT = 0x05
M.IN_BIP32_DERIVATION = 0x06
M.IN_FINAL_SCRIPTSIG = 0x07
M.IN_FINAL_SCRIPTWITNESS = 0x08
M.IN_PROPRIETARY = 0xFC

-- Output key types
M.OUT_REDEEM_SCRIPT = 0x00
M.OUT_WITNESS_SCRIPT = 0x01
M.OUT_BIP32_DERIVATION = 0x02
M.OUT_PROPRIETARY = 0xFC

-- Separator byte (end of map)
M.SEPARATOR = 0x00

-- PSBT version (v0 for BIP174)
M.VERSION = 0

-- Role names
M.ROLE = {
  CREATOR = "creator",
  UPDATER = "updater",
  SIGNER = "signer",
  COMBINER = "combiner",
  FINALIZER = "finalizer",
  EXTRACTOR = "extractor",
}

--------------------------------------------------------------------------------
-- PSBT Data Model
--------------------------------------------------------------------------------

--- Create a new empty PSBT input metadata.
-- @return table: PSBT input structure
function M.psbt_input()
  return {
    non_witness_utxo = nil,       -- Full previous transaction (for legacy inputs)
    witness_utxo = nil,           -- {value=number, script_pubkey=string} for segwit
    partial_sigs = {},            -- pubkey_hex -> signature (DER + sighash byte)
    sighash_type = nil,           -- Sighash type for this input
    redeem_script = nil,          -- P2SH redeem script
    witness_script = nil,         -- P2WSH witness script
    bip32_derivations = {},       -- pubkey_hex -> {fingerprint, path_array}
    final_script_sig = nil,       -- Final scriptSig
    final_script_witness = nil,   -- Final witness stack (array of strings)
    unknown = {},                 -- key_hex -> value (unknown fields)
  }
end

--- Create a new empty PSBT output metadata.
-- @return table: PSBT output structure
function M.psbt_output()
  return {
    redeem_script = nil,          -- P2SH redeem script
    witness_script = nil,         -- P2WSH witness script
    bip32_derivations = {},       -- pubkey_hex -> {fingerprint, path_array}
    unknown = {},                 -- key_hex -> value (unknown fields)
  }
end

--- Create a new PSBT from an unsigned transaction.
-- @param tx transaction: Unsigned transaction (inputs must have empty scriptSig/witness)
-- @return table: PSBT structure
function M.new(tx)
  -- Validate that tx has no signatures
  for _, inp in ipairs(tx.inputs) do
    if #inp.script_sig > 0 or (inp.witness and #inp.witness > 0) then
      error("Transaction must be unsigned for PSBT creation")
    end
  end

  local psbt = {
    version = M.VERSION,
    tx = tx,                      -- Unsigned transaction
    xpubs = {},                   -- {xpub_bytes -> {fingerprint, path_array}}
    inputs = {},                  -- Array of psbt_input
    outputs = {},                 -- Array of psbt_output
    unknown = {},                 -- Global unknown fields
  }

  -- Initialize input/output arrays
  for _ = 1, #tx.inputs do
    psbt.inputs[#psbt.inputs + 1] = M.psbt_input()
  end
  for _ = 1, #tx.outputs do
    psbt.outputs[#psbt.outputs + 1] = M.psbt_output()
  end

  return psbt
end

--------------------------------------------------------------------------------
-- Hex Utilities
--------------------------------------------------------------------------------

local function hex_encode(data)
  local hex = {}
  for i = 1, #data do
    hex[i] = string.format("%02x", data:byte(i))
  end
  return table.concat(hex)
end

local function hex_decode(hex)
  local bytes = {}
  for i = 1, #hex, 2 do
    bytes[#bytes + 1] = string.char(tonumber(hex:sub(i, i + 1), 16))
  end
  return table.concat(bytes)
end

M.hex_encode = hex_encode
M.hex_decode = hex_decode

--------------------------------------------------------------------------------
-- Base64 Encoding/Decoding
--------------------------------------------------------------------------------

local b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

function M.base64_encode(data)
  local result = {}
  local pad = (3 - #data % 3) % 3
  data = data .. string.rep("\0", pad)

  for i = 1, #data, 3 do
    local b1, b2, b3 = data:byte(i, i + 2)
    local n = b1 * 65536 + b2 * 256 + b3
    result[#result + 1] = b64_chars:sub(math.floor(n / 262144) % 64 + 1, math.floor(n / 262144) % 64 + 1)
    result[#result + 1] = b64_chars:sub(math.floor(n / 4096) % 64 + 1, math.floor(n / 4096) % 64 + 1)
    result[#result + 1] = b64_chars:sub(math.floor(n / 64) % 64 + 1, math.floor(n / 64) % 64 + 1)
    result[#result + 1] = b64_chars:sub(n % 64 + 1, n % 64 + 1)
  end

  if pad > 0 then
    for i = 1, pad do
      result[#result - i + 1] = "="
    end
  end

  return table.concat(result)
end

function M.base64_decode(data)
  local lookup = {}
  for i = 1, #b64_chars do
    lookup[b64_chars:sub(i, i)] = i - 1
  end

  data = data:gsub("[^%w%+/=]", "")
  local result = {}

  for i = 1, #data, 4 do
    local a = lookup[data:sub(i, i)] or 0
    local b = lookup[data:sub(i+1, i+1)] or 0
    local c = lookup[data:sub(i+2, i+2)] or 0
    local d = lookup[data:sub(i+3, i+3)] or 0
    local n = a * 262144 + b * 4096 + c * 64 + d
    result[#result + 1] = string.char(
      math.floor(n / 65536) % 256,
      math.floor(n / 256) % 256,
      n % 256
    )
  end

  local s = table.concat(result)
  local pad = data:match("(=*)$")
  if pad and #pad > 0 then
    s = s:sub(1, -(#pad + 1))
  end
  return s
end

--------------------------------------------------------------------------------
-- Serialization Helpers
--------------------------------------------------------------------------------

--- Write a key-value pair to a buffer writer.
-- Format: <compact_size key_len><key><compact_size value_len><value>
-- @param w buffer_writer: Writer to append to
-- @param key string: Key bytes
-- @param value string: Value bytes
local function write_kv(w, key, value)
  w.write_varint(#key)
  w.write_bytes(key)
  w.write_varint(#value)
  w.write_bytes(value)
end

--- Write key type as key.
-- @param w buffer_writer: Writer to append to
-- @param key_type number: Single byte key type
-- @param value string: Value bytes
local function write_typed_kv(w, key_type, value)
  write_kv(w, string.char(key_type), value)
end

--- Serialize a transaction without scriptSig and witness.
-- @param tx transaction: Transaction to serialize
-- @return string: Serialized unsigned transaction
local function serialize_unsigned_tx(tx)
  local w = serialize.buffer_writer()
  w.write_i32le(tx.version)

  w.write_varint(#tx.inputs)
  for _, inp in ipairs(tx.inputs) do
    w.write_hash256(inp.prev_out.hash)
    w.write_u32le(inp.prev_out.index)
    w.write_varint(0)  -- Empty scriptSig
    w.write_u32le(inp.sequence)
  end

  w.write_varint(#tx.outputs)
  for _, out in ipairs(tx.outputs) do
    w.write_i64le(out.value)
    w.write_varstr(out.script_pubkey)
  end

  w.write_u32le(tx.locktime)
  return w.result()
end

--------------------------------------------------------------------------------
-- PSBT Serialization (BIP174 Binary Format)
--------------------------------------------------------------------------------

--- Serialize a PSBT to binary format.
-- @param psbt table: PSBT structure
-- @return string: Binary PSBT data
function M.serialize(psbt)
  local w = serialize.buffer_writer()

  -- Magic bytes
  w.write_bytes(M.MAGIC)

  -- Global map
  -- Key 0x00: unsigned tx (required)
  local unsigned_tx = serialize_unsigned_tx(psbt.tx)
  write_typed_kv(w, M.GLOBAL_UNSIGNED_TX, unsigned_tx)

  -- Key 0x01: xpubs (optional)
  for xpub_bytes, derivation in pairs(psbt.xpubs) do
    local key = string.char(M.GLOBAL_XPUB) .. xpub_bytes
    -- Value: fingerprint (4 bytes) + path (4 bytes each)
    local vw = serialize.buffer_writer()
    vw.write_bytes(derivation.fingerprint)
    for _, idx in ipairs(derivation.path) do
      vw.write_u32le(idx)
    end
    write_kv(w, key, vw.result())
  end

  -- Key 0xFB: version (optional, only for v0+)
  if psbt.version and psbt.version > 0 then
    local vw = serialize.buffer_writer()
    vw.write_u32le(psbt.version)
    write_typed_kv(w, M.GLOBAL_VERSION, vw.result())
  end

  -- Unknown global fields
  for key_hex, value in pairs(psbt.unknown) do
    write_kv(w, hex_decode(key_hex), value)
  end

  -- Separator
  w.write_u8(M.SEPARATOR)

  -- Input maps
  for _, inp in ipairs(psbt.inputs) do
    -- Key 0x00: non-witness UTXO
    if inp.non_witness_utxo then
      local tx_data = serialize.serialize_transaction(inp.non_witness_utxo, false)
      write_typed_kv(w, M.IN_NON_WITNESS_UTXO, tx_data)
    end

    -- Key 0x01: witness UTXO
    if inp.witness_utxo then
      local vw = serialize.buffer_writer()
      vw.write_i64le(inp.witness_utxo.value)
      vw.write_varstr(inp.witness_utxo.script_pubkey)
      write_typed_kv(w, M.IN_WITNESS_UTXO, vw.result())
    end

    -- Key 0x02: partial signatures
    for pubkey_hex, sig in pairs(inp.partial_sigs) do
      local pubkey = hex_decode(pubkey_hex)
      local key = string.char(M.IN_PARTIAL_SIG) .. pubkey
      write_kv(w, key, sig)
    end

    -- Key 0x03: sighash type
    if inp.sighash_type then
      local vw = serialize.buffer_writer()
      vw.write_u32le(inp.sighash_type)
      write_typed_kv(w, M.IN_SIGHASH_TYPE, vw.result())
    end

    -- Key 0x04: redeem script
    if inp.redeem_script then
      write_typed_kv(w, M.IN_REDEEM_SCRIPT, inp.redeem_script)
    end

    -- Key 0x05: witness script
    if inp.witness_script then
      write_typed_kv(w, M.IN_WITNESS_SCRIPT, inp.witness_script)
    end

    -- Key 0x06: BIP32 derivation paths
    for pubkey_hex, derivation in pairs(inp.bip32_derivations) do
      local pubkey = hex_decode(pubkey_hex)
      local key = string.char(M.IN_BIP32_DERIVATION) .. pubkey
      local vw = serialize.buffer_writer()
      vw.write_bytes(derivation.fingerprint)
      for _, idx in ipairs(derivation.path) do
        vw.write_u32le(idx)
      end
      write_kv(w, key, vw.result())
    end

    -- Key 0x07: final scriptSig
    if inp.final_script_sig then
      write_typed_kv(w, M.IN_FINAL_SCRIPTSIG, inp.final_script_sig)
    end

    -- Key 0x08: final scriptWitness
    if inp.final_script_witness then
      local vw = serialize.buffer_writer()
      vw.write_varint(#inp.final_script_witness)
      for _, item in ipairs(inp.final_script_witness) do
        vw.write_varstr(item)
      end
      write_typed_kv(w, M.IN_FINAL_SCRIPTWITNESS, vw.result())
    end

    -- Unknown input fields
    for key_hex, value in pairs(inp.unknown) do
      write_kv(w, hex_decode(key_hex), value)
    end

    -- Separator
    w.write_u8(M.SEPARATOR)
  end

  -- Output maps
  for _, out in ipairs(psbt.outputs) do
    -- Key 0x00: redeem script
    if out.redeem_script then
      write_typed_kv(w, M.OUT_REDEEM_SCRIPT, out.redeem_script)
    end

    -- Key 0x01: witness script
    if out.witness_script then
      write_typed_kv(w, M.OUT_WITNESS_SCRIPT, out.witness_script)
    end

    -- Key 0x02: BIP32 derivation paths
    for pubkey_hex, derivation in pairs(out.bip32_derivations) do
      local pubkey = hex_decode(pubkey_hex)
      local key = string.char(M.OUT_BIP32_DERIVATION) .. pubkey
      local vw = serialize.buffer_writer()
      vw.write_bytes(derivation.fingerprint)
      for _, idx in ipairs(derivation.path) do
        vw.write_u32le(idx)
      end
      write_kv(w, key, vw.result())
    end

    -- Unknown output fields
    for key_hex, value in pairs(out.unknown) do
      write_kv(w, hex_decode(key_hex), value)
    end

    -- Separator
    w.write_u8(M.SEPARATOR)
  end

  return w.result()
end

--------------------------------------------------------------------------------
-- PSBT Deserialization
--------------------------------------------------------------------------------

--- Parse a key-value map from reader until separator.
-- @param r buffer_reader: Reader
-- @return table: Array of {key=string, value=string}
local function read_map(r)
  local entries = {}
  while true do
    local key_len = r.read_varint()
    if key_len == 0 then
      break  -- Separator found
    end
    local key = r.read_bytes(key_len)
    local value_len = r.read_varint()
    local value = r.read_bytes(value_len)
    entries[#entries + 1] = {key = key, value = value}
  end
  return entries
end

--- Deserialize a PSBT from binary data.
-- @param data string: Binary PSBT data
-- @return table: PSBT structure
function M.deserialize(data)
  local r = serialize.buffer_reader(data)

  -- Check magic bytes
  local magic = r.read_bytes(5)
  if magic ~= M.MAGIC then
    error("Invalid PSBT magic bytes")
  end

  local psbt = {
    version = 0,
    tx = nil,
    xpubs = {},
    inputs = {},
    outputs = {},
    unknown = {},
  }

  -- Parse global map
  local global_map = read_map(r)
  for _, entry in ipairs(global_map) do
    local key_type = entry.key:byte(1)

    if key_type == M.GLOBAL_UNSIGNED_TX then
      assert(#entry.key == 1, "Invalid unsigned tx key")
      psbt.tx = serialize.deserialize_transaction(entry.value)
      -- Verify it's unsigned
      for _, inp in ipairs(psbt.tx.inputs) do
        if #inp.script_sig > 0 or (inp.witness and #inp.witness > 0) then
          error("PSBT transaction must be unsigned")
        end
      end

    elseif key_type == M.GLOBAL_XPUB then
      local xpub_bytes = entry.key:sub(2)
      local vr = serialize.buffer_reader(entry.value)
      local fingerprint = vr.read_bytes(4)
      local path = {}
      while vr.remaining() >= 4 do
        path[#path + 1] = vr.read_u32le()
      end
      psbt.xpubs[xpub_bytes] = {fingerprint = fingerprint, path = path}

    elseif key_type == M.GLOBAL_VERSION then
      assert(#entry.key == 1, "Invalid version key")
      local vr = serialize.buffer_reader(entry.value)
      psbt.version = vr.read_u32le()

    else
      -- Unknown field
      psbt.unknown[hex_encode(entry.key)] = entry.value
    end
  end

  if not psbt.tx then
    error("PSBT missing unsigned transaction")
  end

  -- Initialize input/output arrays
  for _ = 1, #psbt.tx.inputs do
    psbt.inputs[#psbt.inputs + 1] = M.psbt_input()
  end
  for _ = 1, #psbt.tx.outputs do
    psbt.outputs[#psbt.outputs + 1] = M.psbt_output()
  end

  -- Parse input maps
  for i = 1, #psbt.tx.inputs do
    local inp = psbt.inputs[i]
    local input_map = read_map(r)

    for _, entry in ipairs(input_map) do
      local key_type = entry.key:byte(1)

      if key_type == M.IN_NON_WITNESS_UTXO then
        assert(#entry.key == 1, "Invalid non-witness UTXO key")
        inp.non_witness_utxo = serialize.deserialize_transaction(entry.value)

      elseif key_type == M.IN_WITNESS_UTXO then
        assert(#entry.key == 1, "Invalid witness UTXO key")
        local vr = serialize.buffer_reader(entry.value)
        inp.witness_utxo = {
          value = vr.read_i64le(),
          script_pubkey = vr.read_varstr(),
        }

      elseif key_type == M.IN_PARTIAL_SIG then
        local pubkey = entry.key:sub(2)
        inp.partial_sigs[hex_encode(pubkey)] = entry.value

      elseif key_type == M.IN_SIGHASH_TYPE then
        assert(#entry.key == 1, "Invalid sighash type key")
        local vr = serialize.buffer_reader(entry.value)
        inp.sighash_type = vr.read_u32le()

      elseif key_type == M.IN_REDEEM_SCRIPT then
        assert(#entry.key == 1, "Invalid redeem script key")
        inp.redeem_script = entry.value

      elseif key_type == M.IN_WITNESS_SCRIPT then
        assert(#entry.key == 1, "Invalid witness script key")
        inp.witness_script = entry.value

      elseif key_type == M.IN_BIP32_DERIVATION then
        local pubkey = entry.key:sub(2)
        local vr = serialize.buffer_reader(entry.value)
        local fingerprint = vr.read_bytes(4)
        local path = {}
        while vr.remaining() >= 4 do
          path[#path + 1] = vr.read_u32le()
        end
        inp.bip32_derivations[hex_encode(pubkey)] = {fingerprint = fingerprint, path = path}

      elseif key_type == M.IN_FINAL_SCRIPTSIG then
        assert(#entry.key == 1, "Invalid final scriptSig key")
        inp.final_script_sig = entry.value

      elseif key_type == M.IN_FINAL_SCRIPTWITNESS then
        assert(#entry.key == 1, "Invalid final scriptWitness key")
        local vr = serialize.buffer_reader(entry.value)
        local count = vr.read_varint()
        inp.final_script_witness = {}
        for j = 1, count do
          inp.final_script_witness[j] = vr.read_varstr()
        end

      else
        inp.unknown[hex_encode(entry.key)] = entry.value
      end
    end
  end

  -- Parse output maps
  for i = 1, #psbt.tx.outputs do
    local out = psbt.outputs[i]
    local output_map = read_map(r)

    for _, entry in ipairs(output_map) do
      local key_type = entry.key:byte(1)

      if key_type == M.OUT_REDEEM_SCRIPT then
        assert(#entry.key == 1, "Invalid redeem script key")
        out.redeem_script = entry.value

      elseif key_type == M.OUT_WITNESS_SCRIPT then
        assert(#entry.key == 1, "Invalid witness script key")
        out.witness_script = entry.value

      elseif key_type == M.OUT_BIP32_DERIVATION then
        local pubkey = entry.key:sub(2)
        local vr = serialize.buffer_reader(entry.value)
        local fingerprint = vr.read_bytes(4)
        local path = {}
        while vr.remaining() >= 4 do
          path[#path + 1] = vr.read_u32le()
        end
        out.bip32_derivations[hex_encode(pubkey)] = {fingerprint = fingerprint, path = path}

      else
        out.unknown[hex_encode(entry.key)] = entry.value
      end
    end
  end

  return psbt
end

--- Deserialize a base64-encoded PSBT.
-- @param b64 string: Base64 PSBT string
-- @return table: PSBT structure
function M.from_base64(b64)
  return M.deserialize(M.base64_decode(b64))
end

--- Serialize a PSBT to base64.
-- @param psbt table: PSBT structure
-- @return string: Base64 PSBT string
function M.to_base64(psbt)
  return M.base64_encode(M.serialize(psbt))
end

--------------------------------------------------------------------------------
-- PSBT Operations: Update
--------------------------------------------------------------------------------

--- Add UTXO information to a PSBT input.
-- @param psbt table: PSBT structure
-- @param input_index number: Input index (0-based)
-- @param utxo table: UTXO data {value, script_pubkey} or full transaction
-- @param is_witness boolean: If true, use witness_utxo; otherwise non_witness_utxo
function M.update_input_utxo(psbt, input_index, utxo, is_witness)
  local inp = psbt.inputs[input_index + 1]
  if not inp then
    error("Invalid input index")
  end

  if is_witness then
    inp.witness_utxo = {
      value = utxo.value,
      script_pubkey = utxo.script_pubkey,
    }
  else
    inp.non_witness_utxo = utxo
  end
end

--- Add redeem script to a PSBT input (for P2SH).
-- @param psbt table: PSBT structure
-- @param input_index number: Input index (0-based)
-- @param redeem_script string: Redeem script bytes
function M.update_input_redeem_script(psbt, input_index, redeem_script)
  local inp = psbt.inputs[input_index + 1]
  if not inp then
    error("Invalid input index")
  end
  inp.redeem_script = redeem_script
end

--- Add witness script to a PSBT input (for P2WSH).
-- @param psbt table: PSBT structure
-- @param input_index number: Input index (0-based)
-- @param witness_script string: Witness script bytes
function M.update_input_witness_script(psbt, input_index, witness_script)
  local inp = psbt.inputs[input_index + 1]
  if not inp then
    error("Invalid input index")
  end
  inp.witness_script = witness_script
end

--- Add BIP32 derivation path to a PSBT input.
-- @param psbt table: PSBT structure
-- @param input_index number: Input index (0-based)
-- @param pubkey string: Public key bytes (33 bytes compressed)
-- @param fingerprint string: Master key fingerprint (4 bytes)
-- @param path table: Array of path indices (with hardened bit set where needed)
function M.update_input_bip32(psbt, input_index, pubkey, fingerprint, path)
  local inp = psbt.inputs[input_index + 1]
  if not inp then
    error("Invalid input index")
  end
  inp.bip32_derivations[hex_encode(pubkey)] = {
    fingerprint = fingerprint,
    path = path,
  }
end

--------------------------------------------------------------------------------
-- PSBT Operations: Sign
--------------------------------------------------------------------------------

--- Check if a PSBT input is already signed (has final scripts).
-- @param input table: PSBT input
-- @return boolean: true if input is signed/finalized
function M.input_is_signed(input)
  return input.final_script_sig ~= nil or input.final_script_witness ~= nil
end

--- Sign a PSBT input with a private key.
-- @param psbt table: PSBT structure
-- @param input_index number: Input index (0-based)
-- @param privkey string: 32-byte private key
-- @param pubkey string: 33-byte compressed public key (optional, derived if nil)
-- @param sighash_type number: Sighash type (default SIGHASH_ALL)
-- @return boolean: true if signature was added
function M.sign_input(psbt, input_index, privkey, pubkey, sighash_type)
  sighash_type = sighash_type or consensus.SIGHASH.ALL

  local inp = psbt.inputs[input_index + 1]
  if not inp then
    error("Invalid input index")
  end

  -- Skip if already finalized
  if M.input_is_signed(inp) then
    return false
  end

  -- Get public key
  if not pubkey then
    pubkey = crypto.pubkey_from_privkey(privkey, true)
  end

  -- Get UTXO information
  local utxo_value, script_pubkey
  if inp.witness_utxo then
    utxo_value = inp.witness_utxo.value
    script_pubkey = inp.witness_utxo.script_pubkey
  elseif inp.non_witness_utxo then
    local tx_input = psbt.tx.inputs[input_index + 1]
    local prev_out = inp.non_witness_utxo.outputs[tx_input.prev_out.index + 1]
    utxo_value = prev_out.value
    script_pubkey = prev_out.script_pubkey
  else
    error("Missing UTXO information for input " .. input_index)
  end

  -- Determine script type and compute signature hash
  local script_type = script.classify_script(script_pubkey)
  local sighash, script_code

  if script_type == "p2wpkh" then
    -- Native P2WPKH
    local pkh = crypto.hash160(pubkey)
    script_code = script.make_p2pkh_script(pkh)
    sighash = validation.signature_hash_segwit_v0(
      psbt.tx, input_index, script_code, utxo_value, sighash_type
    )
  elseif script_type == "p2pkh" then
    -- Legacy P2PKH
    script_code = script_pubkey
    sighash = validation.signature_hash_legacy(
      psbt.tx, input_index, script_code, sighash_type
    )
  elseif script_type == "p2sh" and inp.redeem_script then
    -- P2SH - check if it wraps segwit
    local redeem_type = script.classify_script(inp.redeem_script)
    if redeem_type == "p2wpkh" then
      -- P2SH-P2WPKH
      local pkh = crypto.hash160(pubkey)
      script_code = script.make_p2pkh_script(pkh)
      sighash = validation.signature_hash_segwit_v0(
        psbt.tx, input_index, script_code, utxo_value, sighash_type
      )
    else
      -- Pure P2SH
      script_code = inp.redeem_script
      sighash = validation.signature_hash_legacy(
        psbt.tx, input_index, script_code, sighash_type
      )
    end
  elseif script_type == "p2wsh" and inp.witness_script then
    -- P2WSH
    script_code = inp.witness_script
    sighash = validation.signature_hash_segwit_v0(
      psbt.tx, input_index, script_code, utxo_value, sighash_type
    )
  else
    -- Unsupported script type
    return false
  end

  -- Sign
  local sig = crypto.ecdsa_sign(privkey, sighash)
  sig = sig .. string.char(sighash_type)

  -- Add partial signature
  inp.partial_sigs[hex_encode(pubkey)] = sig
  inp.sighash_type = sighash_type

  return true
end

--------------------------------------------------------------------------------
-- PSBT Operations: Combine
--------------------------------------------------------------------------------

--- Combine multiple PSBTs with the same underlying transaction.
-- @param psbts table: Array of PSBT structures
-- @return table: Combined PSBT
function M.combine(psbts)
  if #psbts == 0 then
    error("No PSBTs to combine")
  end

  -- Use first PSBT as base
  local result = M.deserialize(M.serialize(psbts[1]))  -- Deep copy

  -- Get base txid for validation
  local base_txid = types.hash256_hex(validation.compute_txid(result.tx))

  -- Merge additional PSBTs
  for i = 2, #psbts do
    local p = psbts[i]

    -- Verify same underlying transaction
    local txid = types.hash256_hex(validation.compute_txid(p.tx))
    if txid ~= base_txid then
      error("Cannot combine PSBTs with different transactions")
    end

    -- Merge global xpubs
    for xpub, deriv in pairs(p.xpubs) do
      if not result.xpubs[xpub] then
        result.xpubs[xpub] = deriv
      end
    end

    -- Merge global unknown
    for k, v in pairs(p.unknown) do
      if not result.unknown[k] then
        result.unknown[k] = v
      end
    end

    -- Merge inputs
    for j, inp in ipairs(p.inputs) do
      local res_inp = result.inputs[j]

      -- Merge UTXOs (prefer non-nil)
      if not res_inp.non_witness_utxo and inp.non_witness_utxo then
        res_inp.non_witness_utxo = inp.non_witness_utxo
      end
      if not res_inp.witness_utxo and inp.witness_utxo then
        res_inp.witness_utxo = inp.witness_utxo
      end

      -- Merge partial sigs
      for pk, sig in pairs(inp.partial_sigs) do
        if not res_inp.partial_sigs[pk] then
          res_inp.partial_sigs[pk] = sig
        end
      end

      -- Merge scripts
      if not res_inp.redeem_script and inp.redeem_script then
        res_inp.redeem_script = inp.redeem_script
      end
      if not res_inp.witness_script and inp.witness_script then
        res_inp.witness_script = inp.witness_script
      end

      -- Merge BIP32 derivations
      for pk, deriv in pairs(inp.bip32_derivations) do
        if not res_inp.bip32_derivations[pk] then
          res_inp.bip32_derivations[pk] = deriv
        end
      end

      -- Merge final scripts
      if not res_inp.final_script_sig and inp.final_script_sig then
        res_inp.final_script_sig = inp.final_script_sig
      end
      if not res_inp.final_script_witness and inp.final_script_witness then
        res_inp.final_script_witness = inp.final_script_witness
      end

      -- Merge unknown
      for k, v in pairs(inp.unknown) do
        if not res_inp.unknown[k] then
          res_inp.unknown[k] = v
        end
      end
    end

    -- Merge outputs
    for j, out in ipairs(p.outputs) do
      local res_out = result.outputs[j]

      if not res_out.redeem_script and out.redeem_script then
        res_out.redeem_script = out.redeem_script
      end
      if not res_out.witness_script and out.witness_script then
        res_out.witness_script = out.witness_script
      end

      for pk, deriv in pairs(out.bip32_derivations) do
        if not res_out.bip32_derivations[pk] then
          res_out.bip32_derivations[pk] = deriv
        end
      end

      for k, v in pairs(out.unknown) do
        if not res_out.unknown[k] then
          res_out.unknown[k] = v
        end
      end
    end
  end

  return result
end

--------------------------------------------------------------------------------
-- PSBT Operations: Finalize
--------------------------------------------------------------------------------

--- Finalize a PSBT input by constructing final scriptSig/witness.
-- @param psbt table: PSBT structure
-- @param input_index number: Input index (0-based)
-- @return boolean: true if finalization succeeded
function M.finalize_input(psbt, input_index)
  local inp = psbt.inputs[input_index + 1]
  if not inp then
    error("Invalid input index")
  end

  -- Already finalized?
  if M.input_is_signed(inp) then
    return true
  end

  -- Get script type
  local script_pubkey
  if inp.witness_utxo then
    script_pubkey = inp.witness_utxo.script_pubkey
  elseif inp.non_witness_utxo then
    local tx_input = psbt.tx.inputs[input_index + 1]
    local prev_out = inp.non_witness_utxo.outputs[tx_input.prev_out.index + 1]
    script_pubkey = prev_out.script_pubkey
  else
    return false  -- No UTXO info
  end

  local script_type = script.classify_script(script_pubkey)

  -- Check for at least one signature
  local pubkey_hex, sig
  for pk, s in pairs(inp.partial_sigs) do
    pubkey_hex = pk
    sig = s
    break
  end

  if not sig then
    return false  -- No signatures available
  end

  local pubkey = hex_decode(pubkey_hex)

  if script_type == "p2wpkh" then
    -- Native P2WPKH: witness = [sig, pubkey]
    inp.final_script_witness = {sig, pubkey}
    inp.final_script_sig = ""

  elseif script_type == "p2pkh" then
    -- Legacy P2PKH: scriptSig = <sig> <pubkey>
    local w = serialize.buffer_writer()
    w.write_varstr(sig)
    w.write_varstr(pubkey)
    inp.final_script_sig = w.result()

  elseif script_type == "p2sh" and inp.redeem_script then
    local redeem_type = script.classify_script(inp.redeem_script)

    if redeem_type == "p2wpkh" then
      -- P2SH-P2WPKH: scriptSig = <push redeem_script>, witness = [sig, pubkey]
      local w = serialize.buffer_writer()
      w.write_varstr(inp.redeem_script)
      inp.final_script_sig = w.result()
      inp.final_script_witness = {sig, pubkey}
    else
      -- Pure P2SH: scriptSig = <sig> <pubkey> <redeem_script>
      local w = serialize.buffer_writer()
      w.write_varstr(sig)
      w.write_varstr(pubkey)
      w.write_varstr(inp.redeem_script)
      inp.final_script_sig = w.result()
    end

  elseif script_type == "p2wsh" and inp.witness_script then
    -- P2WSH: witness = [sig, pubkey, witness_script] (simplified for single-sig)
    -- Note: Multi-sig would need different handling
    inp.final_script_witness = {sig, pubkey, inp.witness_script}
    inp.final_script_sig = ""

  else
    return false  -- Unsupported type
  end

  -- Clear non-final fields
  inp.partial_sigs = {}
  inp.bip32_derivations = {}

  return true
end

--- Finalize all inputs in a PSBT.
-- @param psbt table: PSBT structure
-- @return boolean: true if all inputs finalized successfully
function M.finalize(psbt)
  local all_success = true
  for i = 0, #psbt.inputs - 1 do
    if not M.finalize_input(psbt, i) then
      all_success = false
    end
  end
  return all_success
end

--------------------------------------------------------------------------------
-- PSBT Operations: Extract
--------------------------------------------------------------------------------

--- Extract the final signed transaction from a finalized PSBT.
-- @param psbt table: PSBT structure (must be fully finalized)
-- @return transaction: Signed transaction ready for broadcast
function M.extract(psbt)
  -- Create a copy of the transaction
  local tx_data = serialize.serialize_transaction(psbt.tx, true)
  local tx = serialize.deserialize_transaction(tx_data)

  -- Apply final scripts
  for i, inp in ipairs(psbt.inputs) do
    if not M.input_is_signed(inp) then
      error("Input " .. (i - 1) .. " is not finalized")
    end

    tx.inputs[i].script_sig = inp.final_script_sig or ""

    if inp.final_script_witness then
      tx.inputs[i].witness = inp.final_script_witness
      tx.segwit = true
    end
  end

  return tx
end

--------------------------------------------------------------------------------
-- PSBT Utility Functions
--------------------------------------------------------------------------------

--- Get number of signatures needed vs available for an input.
-- @param psbt table: PSBT structure
-- @param input_index number: Input index (0-based)
-- @return number, number: signatures_have, signatures_needed
function M.get_signature_status(psbt, input_index)
  local inp = psbt.inputs[input_index + 1]
  if not inp then
    return 0, 0
  end

  -- Count available signatures
  local have = 0
  for _ in pairs(inp.partial_sigs) do
    have = have + 1
  end

  -- Already finalized counts as complete
  if M.input_is_signed(inp) then
    return 1, 1
  end

  -- For now, assume single-sig (need 1)
  -- TODO: Parse multisig scripts to determine actual threshold
  return have, 1
end

--- Check if a PSBT is complete (all inputs finalized).
-- @param psbt table: PSBT structure
-- @return boolean: true if complete
function M.is_complete(psbt)
  for _, inp in ipairs(psbt.inputs) do
    if not M.input_is_signed(inp) then
      return false
    end
  end
  return true
end

--- Count unsigned inputs in a PSBT.
-- @param psbt table: PSBT structure
-- @return number: Number of inputs without final scripts
function M.count_unsigned(psbt)
  local count = 0
  for _, inp in ipairs(psbt.inputs) do
    if not M.input_is_signed(inp) then
      count = count + 1
    end
  end
  return count
end

--- Decode a PSBT to a human-readable table for RPC.
-- @param psbt table: PSBT structure
-- @return table: Decoded PSBT info
function M.decode(psbt)
  local result = {
    tx = {
      txid = types.hash256_hex(validation.compute_txid(psbt.tx)),
      version = psbt.tx.version,
      locktime = psbt.tx.locktime,
      vin = {},
      vout = {},
    },
    global_xpubs = {},
    inputs = {},
    outputs = {},
    fee = nil,
  }

  -- Decode transaction
  for i, inp in ipairs(psbt.tx.inputs) do
    result.tx.vin[i] = {
      txid = types.hash256_hex(inp.prev_out.hash),
      vout = inp.prev_out.index,
      sequence = inp.sequence,
    }
  end

  for i, out in ipairs(psbt.tx.outputs) do
    result.tx.vout[i] = {
      value = out.value / consensus.COIN,
      n = i - 1,
      scriptPubKey = {
        hex = hex_encode(out.script_pubkey),
      },
    }
  end

  -- Decode global xpubs
  for xpub, deriv in pairs(psbt.xpubs) do
    result.global_xpubs[#result.global_xpubs + 1] = {
      xpub = hex_encode(xpub),
      master_fingerprint = hex_encode(deriv.fingerprint),
      path = deriv.path,
    }
  end

  -- Calculate fee if possible
  local total_in = 0
  local has_all_utxos = true
  for i, inp in ipairs(psbt.inputs) do
    if inp.witness_utxo then
      total_in = total_in + inp.witness_utxo.value
    elseif inp.non_witness_utxo then
      local tx_input = psbt.tx.inputs[i]
      local prev_out = inp.non_witness_utxo.outputs[tx_input.prev_out.index + 1]
      if prev_out then
        total_in = total_in + prev_out.value
      else
        has_all_utxos = false
      end
    else
      has_all_utxos = false
    end
  end

  if has_all_utxos then
    local total_out = 0
    for _, out in ipairs(psbt.tx.outputs) do
      total_out = total_out + out.value
    end
    result.fee = (total_in - total_out) / consensus.COIN
  end

  -- Decode inputs
  for i, inp in ipairs(psbt.inputs) do
    local input_info = {
      has_utxo = inp.witness_utxo ~= nil or inp.non_witness_utxo ~= nil,
      is_final = M.input_is_signed(inp),
      partial_signatures = {},
      sighash = inp.sighash_type,
      bip32_derivs = {},
    }

    if inp.witness_utxo then
      input_info.witness_utxo = {
        amount = inp.witness_utxo.value / consensus.COIN,
        scriptPubKey = {hex = hex_encode(inp.witness_utxo.script_pubkey)},
      }
    end

    if inp.non_witness_utxo then
      input_info.non_witness_utxo = {
        txid = types.hash256_hex(validation.compute_txid(inp.non_witness_utxo)),
      }
    end

    for pk, sig in pairs(inp.partial_sigs) do
      input_info.partial_signatures[pk] = hex_encode(sig)
    end

    if inp.redeem_script then
      input_info.redeem_script = {hex = hex_encode(inp.redeem_script)}
    end

    if inp.witness_script then
      input_info.witness_script = {hex = hex_encode(inp.witness_script)}
    end

    if inp.final_script_sig then
      input_info.final_scriptSig = {hex = hex_encode(inp.final_script_sig)}
    end

    if inp.final_script_witness then
      input_info.final_scriptwitness = {}
      for j, wit in ipairs(inp.final_script_witness) do
        input_info.final_scriptwitness[j] = hex_encode(wit)
      end
    end

    for pk, deriv in pairs(inp.bip32_derivations) do
      input_info.bip32_derivs[#input_info.bip32_derivs + 1] = {
        pubkey = pk,
        master_fingerprint = hex_encode(deriv.fingerprint),
        path = deriv.path,
      }
    end

    result.inputs[i] = input_info
  end

  -- Decode outputs
  for i, out in ipairs(psbt.outputs) do
    local output_info = {
      bip32_derivs = {},
    }

    if out.redeem_script then
      output_info.redeem_script = {hex = hex_encode(out.redeem_script)}
    end

    if out.witness_script then
      output_info.witness_script = {hex = hex_encode(out.witness_script)}
    end

    for pk, deriv in pairs(out.bip32_derivations) do
      output_info.bip32_derivs[#output_info.bip32_derivs + 1] = {
        pubkey = pk,
        master_fingerprint = hex_encode(deriv.fingerprint),
        path = deriv.path,
      }
    end

    result.outputs[i] = output_info
  end

  return result
end

return M
