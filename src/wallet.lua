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
  self.keys = {}                   -- address -> {privkey, pubkey, path, type}
  self.addresses = {}              -- ordered list of addresses
  self.utxos = {}                  -- outpoint_key -> {value, script_pubkey, address, txid, vout}
  self.transactions = {}           -- txid_hex -> {tx, height, time, fee}
  self.balance = 0
  self.next_external_index = 0     -- BIP44 external chain index
  self.next_internal_index = 0     -- BIP44 internal (change) chain index
  self.gap_limit = 20              -- BIP44 address gap limit
  self.account = 0
  self.address_type = "p2wpkh"     -- Default address type
  return self
end

-- Create a new wallet from a random seed
function M.create(network, storage)
  local wallet = M.new(network, storage)

  -- Generate 32 bytes of random seed using /dev/urandom
  local f = io.open("/dev/urandom", "rb")
  local seed
  if f then
    seed = f:read(32)
    f:close()
  else
    -- Fallback to Lua random (NOT cryptographically secure)
    math.randomseed(os.time() + os.clock() * 1000000)
    local seed_bytes = {}
    for i = 1, 32 do
      seed_bytes[i] = string.char(math.random(0, 255))
    end
    seed = table.concat(seed_bytes)
  end

  wallet.master_key = M.master_key_from_seed(seed)

  -- Generate initial addresses
  wallet:generate_addresses(wallet.gap_limit)

  return wallet, seed
end

-- Restore wallet from seed
function M.from_seed(seed, network, storage)
  local wallet = M.new(network, storage)
  wallet.master_key = M.master_key_from_seed(seed)
  wallet:generate_addresses(wallet.gap_limit)
  return wallet
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
-- UTXO Scanning
--------------------------------------------------------------------------------

function Wallet:scan_utxos(chain_state)
  self.utxos = {}
  self.balance = 0

  if not self.storage then
    return  -- No storage, skip scan
  end

  -- Scan UTXO set for our addresses
  local storage_mod = require("lunarblock.storage")
  local utxo_mod = require("lunarblock.utxo")
  local iter = self.storage.iterator(storage_mod.CF.UTXO)
  iter.seek_to_first()

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

      self.utxos[key] = {
        value = entry.value,
        script_pubkey = entry.script_pubkey,
        address = addr,
        txid = txid,
        vout = vout,
        height = entry.height,
        is_coinbase = entry.is_coinbase,
      }
      self.balance = self.balance + entry.value
    end

    iter.next()
  end
  iter.destroy()
end

--------------------------------------------------------------------------------
-- Transaction Creation and Signing
--------------------------------------------------------------------------------

function Wallet:create_transaction(recipients, fee_rate, change_address)
  -- recipients: list of {address=string, amount=number (satoshis)}
  -- fee_rate: sat/vB
  -- Returns: signed transaction, fee

  -- 1. Calculate total output amount
  local total_out = 0
  for _, r in ipairs(recipients) do
    assert(r.amount > 0, "Invalid output amount")
    assert(consensus.is_valid_amount(r.amount), "Amount exceeds MAX_MONEY")
    total_out = total_out + r.amount
  end

  -- 2. Select inputs (simple: largest first)
  local selected = {}
  local total_in = 0
  local sorted_utxos = {}
  for key, utxo in pairs(self.utxos) do
    sorted_utxos[#sorted_utxos + 1] = {key = key, utxo = utxo}
  end
  table.sort(sorted_utxos, function(a, b) return a.utxo.value > b.utxo.value end)

  -- Estimate transaction size for fee calculation
  -- P2WPKH input: ~68 vbytes, output: ~31 vbytes, overhead: ~11 vbytes
  local est_input_vsize = 68
  local est_output_vsize = 31
  local est_overhead = 11

  for _, item in ipairs(sorted_utxos) do
    selected[#selected + 1] = item
    total_in = total_in + item.utxo.value

    -- Estimate fee with current selection
    local est_vsize = est_overhead + #selected * est_input_vsize
      + (#recipients + 1) * est_output_vsize  -- +1 for change
    local est_fee = math.ceil(est_vsize * fee_rate)

    if total_in >= total_out + est_fee then
      break
    end
  end

  -- 3. Calculate actual fee
  local est_vsize = est_overhead + #selected * est_input_vsize
    + (#recipients + 1) * est_output_vsize
  local fee = math.ceil(est_vsize * fee_rate)

  if total_in < total_out + fee then
    return nil, "Insufficient funds"
  end

  -- 4. Build transaction
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
  if change > 546 then  -- Dust threshold
    change_address = change_address or self:get_change_address()
    local change_type, change_program = address.decode_address(change_address, self.network.name)
    local change_spk
    if change_type == "p2wpkh" then
      change_spk = script.make_p2wpkh_script(change_program)
    else
      change_spk = script.make_p2pkh_script(change_program)
    end
    outputs[#outputs + 1] = types.txout(change, change_spk)
  else
    fee = fee + change  -- Add dust to fee
  end

  local tx = types.transaction(2, inputs, outputs, 0)
  tx.segwit = true

  -- 5. Sign inputs
  for i, item in ipairs(selected) do
    local key_info = self.keys[item.utxo.address]
    assert(key_info, "No key for address: " .. item.utxo.address)

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

  return tx, fee
end

--------------------------------------------------------------------------------
-- Wallet Info Queries
--------------------------------------------------------------------------------

function Wallet:get_balance()
  return self.balance
end

function Wallet:list_unspent()
  local result = {}
  for _, utxo in pairs(self.utxos) do
    result[#result + 1] = {
      txid = types.hash256_hex(utxo.txid),
      vout = utxo.vout,
      address = utxo.address,
      amount = utxo.value / consensus.COIN,
      satoshis = utxo.value,
      confirmations = 0,  -- would need chain state
    }
  end
  return result
end

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
-- Wallet Serialization
--------------------------------------------------------------------------------

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

function Wallet:serialize()
  local encode = get_json()
  local data = {
    master_key = M.hex_encode(self.master_key.key),
    master_chain_code = M.hex_encode(self.master_key.chain_code),
    next_external_index = self.next_external_index,
    next_internal_index = self.next_internal_index,
    account = self.account,
    address_type = self.address_type,
    network = self.network.name,
  }
  return encode(data)
end

function Wallet:save(filepath)
  local data = self:serialize()
  local f = io.open(filepath, "w")
  assert(f, "Cannot open wallet file for writing")
  f:write(data)
  f:close()
end

function M.load(filepath, network, storage)
  local _, decode = get_json()
  local f = io.open(filepath, "r")
  if not f then return nil, "Wallet file not found" end
  local raw = f:read("*a")
  f:close()
  local data = decode(raw)

  -- Use network from file if not provided
  if not network and data.network then
    network = consensus.networks[data.network]
  end

  local wallet = M.new(network, storage)
  local seed_key = M.hex_decode(data.master_key)
  local chain_code = M.hex_decode(data.master_chain_code)
  wallet.master_key = M.extended_key(seed_key, chain_code, 0, "\0\0\0\0", 0, true)
  wallet.next_external_index = data.next_external_index or 0
  wallet.next_internal_index = data.next_internal_index or 0
  wallet.account = data.account or 0
  wallet.address_type = data.address_type or "p2wpkh"

  -- Regenerate all addresses
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

  return wallet
end

return M
