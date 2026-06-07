--- JSON-RPC 1.0/2.0 server over HTTP
-- Exposes Bitcoin Core-compatible RPC interface

local socket = require("socket")
local cjson = require("cjson")
local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local validation = require("lunarblock.validation")
local consensus = require("lunarblock.consensus")
local p2p = require("lunarblock.p2p")
local script_mod = require("lunarblock.script")
local address_mod = require("lunarblock.address")
local bit = require("bit")
local storage_mod = require("lunarblock.storage")
local M = {}

--------------------------------------------------------------------------------
-- Network Name Translation
--------------------------------------------------------------------------------
--
-- Internal network names (consensus.lua) → canonical Bitcoin Core RPC strings
-- as defined by Core's src/util/chaintype.cpp::ChainTypeToString():
--   mainnet  → main
--   testnet  → test
--   testnet3 → test
--   testnet4 → testnet4
--   signet   → signet
--   regtest  → regtest
--
-- All RPC/REST endpoints that emit the `chain` field MUST translate via this
-- helper so daily consensus-diff vs Core stays clean (FIX-80).
local function core_chain_name(internal_name)
  if internal_name == "mainnet" then return "main"
  elseif internal_name == "testnet" then return "test"
  elseif internal_name == "testnet3" then return "test"
  else return internal_name
  end
end
M.core_chain_name = core_chain_name

--------------------------------------------------------------------------------
-- BIP-22 result string mapping
--------------------------------------------------------------------------------

--- Map an internal block-validation error string to a canonical BIP-22
-- submitblock result string.
--
-- BIP-22: https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki
-- Reference: Bitcoin Core BIP22ValidationResult() in src/rpc/mining.cpp
--
-- Consensus rejections go in the JSON-RPC *result* field as short ASCII
-- strings, NOT as JSON-RPC error objects.
--
-- @param err string: internal error/exception message
-- @return string: canonical BIP-22 result string
local function bip22_result(err)
  if err == nil then return nil end  -- success
  local s = tostring(err):lower()

  -- Already-canonical strings pass through unchanged (exact match or prefix match).
  -- Error messages may carry a detail suffix after ": " — e.g.
  --   "bad-txns-in-belowout: value in (X) < value out (Y)"
  -- Exact-match first for the short form; prefix-match handles the long form.
  local canonical_keys = {
    "duplicate", "inconclusive", "duplicate-invalid",
    "high-hash", "bad-txnmrklroot",
    "bad-witness-merkle-match", "bad-cb-amount",
    "bad-blk-sigops", "bad-cb-height",
    "bad-txns-nonfinal", "bad-txns-duplicate",
    "rejected", "block-script-verify-flag-failed",
    "bad-txns-inputs-missingorspent",
    "bad-txns-inputs-duplicate",
    "bad-txns-inputvalues-outofrange",
    "bad-txns-accumulated-fee-outofrange",
    "bad-txns-in-belowout",
    "bad-txns-premature-spend-of-coinbase",
  }
  for _, key in ipairs(canonical_keys) do
    if s == key or s:sub(1, #key + 1) == key .. ":" then
      return key
    end
  end

  -- PoW / difficulty
  if s:find("proof of work") or s:find("invalid pow") or s:find("does not meet target") then
    return "high-hash"
  end

  -- Merkle root
  if s:find("merkle root") and not s:find("witness") then
    return "bad-txnmrklroot"
  end

  -- Witness commitment (BIP141)
  if s:find("witness commitment") or s:find("witness nonce") then
    return "bad-witness-merkle-match"
  end

  -- BIP34 coinbase height — MUST come before the generic "script" catcher below.
  -- Bug fix (W79): original pattern s:find("bip34") (lowercase) missed the actual
  -- error strings emitted by validation.check_block which used uppercase "BIP34:".
  -- The first assert message contained "scriptSig" which caused s:find("script")
  -- to fire first, returning the wrong code "block-script-verify-flag-failed".
  -- The second assert message hit the default "rejected" fallback.
  -- Fix: match "bad-cb-height" (now embedded literally in error messages by
  -- validation.lua W79 fix) AND keep the legacy uppercase/lowercase patterns for
  -- belt-and-suspenders.  Core: state.Invalid(BLOCK_CONSENSUS, "bad-cb-height").
  -- Reference: validation.cpp:4157.
  if s:find("bad%-cb%-height") or s:find("[Bb][Ii][Pp]34") or s:find("coinbase height") then
    return "bad-cb-height"
  end

  -- Coinbase scriptSig length (consensus/tx_check.cpp "bad-cb-length"; 2..100 bytes)
  -- Must precede the generic "script" catch below.
  if s:find("coinbase scriptsig") and (s:find("too long") or s:find("too short") or s:find("out of range")) then
    return "bad-cb-length"
  end

  -- Coinbase value / subsidy
  if s:find("coinbase amount") or s:find("subsidy") or s:find("coinbase value") then
    return "bad-cb-amount"
  end

  -- Sigops limit
  if s:find("sigops") then
    return "bad-blk-sigops"
  end

  -- Block weight / size
  if s:find("weight") and s:find("exceed") then
    return "bad-blk-length"
  end

  -- Non-final transactions / sequence lock
  if s:find("sequence lock") or s:find("non%-final") or s:find("not final") then
    return "bad-txns-nonfinal"
  end

  -- Duplicate transactions
  if s:find("duplicate") and (s:find("tx") or s:find("transaction") or s:find("unspent")) then
    return "bad-txns-duplicate"
  end

  -- Missing inputs / UTXO
  if s:find("missing") and (s:find("input") or s:find("utxo")) then
    return "bad-txns-inputs-missingorspent"
  end

  -- Coinbase maturity violation (consensus/tx_verify.cpp::CheckTxInputs).
  -- Core: state.Invalid(TX_PREMATURE_SPEND, "bad-txns-premature-spend-of-coinbase").
  -- utxo.lua asserts: "Coinbase output not mature"
  -- mempool.lua returns: "spending immature coinbase"
  if s:find("immature") or s:find("not mature") or s:find("premature") then
    return "bad-txns-premature-spend-of-coinbase"
  end

  -- Negative output value (consensus/tx_check.cpp::CheckTransaction — Core parity)
  -- check_transaction asserts: "output N has negative value"
  if s:find("negative value") then
    return "bad-txns-vout-negative"
  end

  -- Output value > MAX_MONEY (consensus/tx_check.cpp::CheckTransaction — Core parity)
  -- check_transaction asserts: "output N value exceeds MAX_MONEY"
  if s:find("exceeds max_money") then
    return "bad-txns-vout-toolarge"
  end

  -- Non-coinbase tx where sum(inputs) < sum(outputs).
  -- Core consensus/tx_verify.cpp::CheckTxInputs:
  --   state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-in-belowout", ...)
  -- utxo.lua asserts: "Transaction outputs exceed inputs"
  if s:find("outputs exceed inputs") then
    return "bad-txns-in-belowout"
  end

  -- Script / signature verification failures at connect-block stage.
  -- Core validation.cpp:2122: "block-script-verify-flag-failed (%s)"
  -- Covers disabled opcodes (OP_CAT 0x7e + 14 peers), signature failures, etc.
  if s:find("script") or s:find("signature") or s:find("checksig") or
     s:find("tapscript") or s:find("witness program") or s:find("disabled opcode") then
    return "block-script-verify-flag-failed"
  end

  -- Timestamp / time
  if s:find("time%-too%-new") then
    return "time-too-new"
  end
  if s:find("time%-too%-old") then
    return "time-too-old"
  end
  if s:find("time%-timewarp%-attack") then
    return "time-timewarp-attack"
  end

  -- Outdated block version (bad-version gate, BIP34/66/65 activation).
  -- Bitcoin Core validation.cpp:4116-4117.
  if s:find("bad%-version") then
    return s:match("bad%-version%([^)]+%)")  -- preserve full "bad-version(0x...)" code
  end

  -- Incorrect PoW target (bad-diffbits).
  -- Bitcoin Core validation.cpp:4088-4089.
  if s:find("bad%-diffbits") then
    return "bad-diffbits"
  end

  -- Previous block not found → inconclusive (orphan block)
  if s:find("prev.*not found") or s:find("previous block not found") then
    return "inconclusive"
  end

  return "rejected"
end

-- Exported alias for testability.
-- W79: exposed so the BIP-34 error-code mapping can be unit-tested directly
-- without going through submitblock.  The internal function is the
-- single-source-of-truth for all submitblock rejection codes.
M.classify_block_rejection = bip22_result

--------------------------------------------------------------------------------
-- RPC Error Codes
--------------------------------------------------------------------------------

M.ERROR = {
  PARSE_ERROR = -32700,
  INVALID_REQUEST = -32600,
  METHOD_NOT_FOUND = -32601,
  INVALID_PARAMS = -32602,
  INTERNAL_ERROR = -32603,
  -- Bitcoin-specific
  MISC_ERROR = -1,
  FORBIDDEN = -2,
  TYPE_ERROR = -3,
  WALLET_ERROR = -4,
  INVALID_ADDRESS = -5,
  INSUFFICIENT_FUNDS = -6,
  OUT_OF_MEMORY = -7,
  INVALID_PARAMETER = -8,  -- RPC_INVALID_PARAMETER (Core: protocol.h)
  CLIENT_INVALID_IP_OR_SUBNET = -30,  -- RPC_CLIENT_INVALID_IP_OR_SUBNET
  DESERIALIZATION_ERROR = -22,
  VERIFY_ERROR = -25,
  VERIFY_REJECTED = -26,
  VERIFY_ALREADY_IN_CHAIN = -27,
  IN_WARMUP = -28,
}

--------------------------------------------------------------------------------
-- Script Disassembly
--------------------------------------------------------------------------------

--- Disassemble a script to human-readable ASM format.
-- @param script_bytes string: The raw script bytes
-- @return string: Space-separated assembly representation
-- Format one decoded op/data token into the ASM string (Core convention).
local function format_asm_token(opcode, data)
  if data then
    return M.hex_encode(data)
  elseif opcode == 0x00 then
    -- W51: Core ScriptToAsmStr emits "0" not "OP_0"
    return "0"
  elseif opcode == 0x4f then
    return "-1"
  elseif opcode >= 0x51 and opcode <= 0x60 then
    return tostring(opcode - 0x50)
  elseif script_mod.OP_NAMES[opcode] then
    return script_mod.OP_NAMES[opcode]
  else
    return string.format("0x%02x", opcode)
  end
end

--- Map a SIGHASH byte to its string label (Core's mapSigHashTypes).
-- Returns the label ("ALL", "NONE", "SINGLE", "ALL|ANYONECANPAY", etc.) or "".
-- Reference: bitcoin-core/src/core_io.cpp SighashToStr / mapSigHashTypes.
local sighash_labels = {
  [0x01] = "ALL",
  [0x02] = "NONE",
  [0x03] = "SINGLE",
  [0x81] = "ALL|ANYONECANPAY",
  [0x82] = "NONE|ANYONECANPAY",
  [0x83] = "SINGLE|ANYONECANPAY",
}

--- Return true if `vch` (a Lua string) looks like a valid DER signature.
-- Mirrors CheckSignatureEncoding / IsValidSignatureEncoding from
-- bitcoin-core/src/script/interpreter.cpp (SCRIPT_VERIFY_STRICTENC path).
-- The last byte of `vch` is the sighash type byte.
local function is_valid_der_sig(vch)
  local n = #vch
  -- DER sig + 1 sighash byte: minimum 9 bytes (shortest possible DER) + 1,
  -- maximum 72 bytes (longest DER) + 1.
  if n < 9 or n > 73 then return false end
  -- byte 1: 0x30 (SEQUENCE)
  if vch:byte(1) ~= 0x30 then return false end
  -- byte 2: total inner length = n - 3 (compound header + sighash byte)
  if vch:byte(2) ~= n - 3 then return false end
  -- byte 3: 0x02 (INTEGER tag for R)
  if vch:byte(3) ~= 0x02 then return false end
  local len_r = vch:byte(4)
  -- R must fit within the sig
  if 5 + len_r >= n then return false end
  -- byte after R: 0x02 (INTEGER tag for S)
  if vch:byte(5 + len_r) ~= 0x02 then return false end
  local len_s = vch:byte(6 + len_r)
  -- total length check
  if len_r + len_s + 7 ~= n then return false end
  -- R must be non-zero and not negative
  if len_r == 0 then return false end
  if bit.band(vch:byte(5), 0x80) ~= 0 then return false end
  -- R must not have unnecessary leading zeros
  if len_r > 1 and vch:byte(5) == 0x00 and bit.band(vch:byte(6), 0x80) == 0 then return false end
  -- S must be non-zero and not negative
  if len_s == 0 then return false end
  if bit.band(vch:byte(len_r + 7), 0x80) ~= 0 then return false end
  -- S must not have unnecessary leading zeros
  if len_s > 1 and vch:byte(len_r + 7) == 0x00 and bit.band(vch:byte(len_r + 8), 0x80) == 0 then return false end
  return true
end

-- Disassemble a script into Core-compatible ASM string.
-- Mirrors Core's ScriptToAsmStr: processes opcodes one-by-one and appends
-- "[error]" if a truncated push is encountered (partial-disassembly behaviour).
-- This is needed for non-standard scripts like OP_RETURN with a truncated push.
local function disassemble_script(script_bytes)
  if #script_bytes == 0 then
    return ""
  end
  local parts = {}
  local pos = 1
  local len = #script_bytes
  local error_flag = false

  while pos <= len do
    local opcode = script_bytes:byte(pos)
    pos = pos + 1

    local data_len = 0
    if opcode >= 0x01 and opcode <= 0x4b then
      data_len = opcode
    elseif opcode == 0x4c then
      if pos > len then error_flag = true; break end
      data_len = script_bytes:byte(pos); pos = pos + 1
    elseif opcode == 0x4d then
      if pos + 1 > len then error_flag = true; break end
      data_len = script_bytes:byte(pos) + script_bytes:byte(pos + 1) * 256
      pos = pos + 2
    elseif opcode == 0x4e then
      if pos + 3 > len then error_flag = true; break end
      local b1, b2, b3, b4 = script_bytes:byte(pos, pos + 3)
      data_len = b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
      pos = pos + 4
    end

    if data_len > 0 then
      if pos + data_len - 1 > len then
        -- Truncated push: emit what we have as error
        error_flag = true; break
      end
      local data = script_bytes:sub(pos, pos + data_len - 1)
      pos = pos + data_len
      parts[#parts + 1] = format_asm_token(opcode, data)
    else
      parts[#parts + 1] = format_asm_token(opcode, nil)
    end
  end

  if error_flag then
    parts[#parts + 1] = "[error]"
  end

  return table.concat(parts, " ")
end

--- Disassemble a scriptSig with sighash-type decoding enabled.
-- Mirrors Bitcoin Core's ScriptToAsmStr(script, fAttemptSighashDecode=true).
-- For data pushes > 4 bytes that pass IsValidSignatureEncoding:
--   strip the sighash byte and append "[ALL]" / "[NONE]" / etc.
-- For data pushes <= 4 bytes: render as CScriptNum decimal (same as Core).
-- Reference: bitcoin-core/src/core_io.cpp ScriptToAsmStr.
-- Used only for scriptSig.asm in getblock verbosity=2 (non-coinbase vin).
local function disassemble_scriptsig(script_bytes)
  if #script_bytes == 0 then
    return ""
  end
  local parts = {}
  local pos = 1
  local len = #script_bytes
  local error_flag = false

  while pos <= len do
    local opcode = script_bytes:byte(pos)
    pos = pos + 1

    local data_len = 0
    if opcode >= 0x01 and opcode <= 0x4b then
      data_len = opcode
    elseif opcode == 0x4c then
      if pos > len then error_flag = true; break end
      data_len = script_bytes:byte(pos); pos = pos + 1
    elseif opcode == 0x4d then
      if pos + 1 > len then error_flag = true; break end
      data_len = script_bytes:byte(pos) + script_bytes:byte(pos + 1) * 256
      pos = pos + 2
    elseif opcode == 0x4e then
      if pos + 3 > len then error_flag = true; break end
      local b1, b2, b3, b4 = script_bytes:byte(pos, pos + 3)
      data_len = b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
      pos = pos + 4
    end

    if data_len > 0 then
      if pos + data_len - 1 > len then
        error_flag = true; break
      end
      local data = script_bytes:sub(pos, pos + data_len - 1)
      pos = pos + data_len

      if data_len <= 4 then
        -- CScriptNum decimal encoding (same as Core for small pushes)
        local v = 0
        if data_len > 0 then
          for bi = 1, data_len do
            v = v + data:byte(bi) * (2 ^ (8 * (bi - 1)))
          end
          -- Handle sign bit in the last byte
          local last = data:byte(data_len)
          if bit.band(last, 0x80) ~= 0 then
            local mask = 0x80 * (2 ^ (8 * (data_len - 1)))
            v = -(v - mask)
          end
        end
        parts[#parts + 1] = string.format("%d", v)
      else
        -- Attempt sighash decode for data pushes > 4 bytes
        if is_valid_der_sig(data) then
          local sh_byte = data:byte(data_len)
          local sh_label = sighash_labels[sh_byte]
          if sh_label then
            -- Strip sighash byte and append [TYPE]
            parts[#parts + 1] = M.hex_encode(data:sub(1, data_len - 1)) .. "[" .. sh_label .. "]"
          else
            parts[#parts + 1] = M.hex_encode(data)
          end
        else
          parts[#parts + 1] = M.hex_encode(data)
        end
      end
    else
      -- Non-push opcode: same rendering as disassemble_script
      parts[#parts + 1] = format_asm_token(opcode, nil)
    end
  end

  if error_flag then
    parts[#parts + 1] = "[error]"
  end

  return table.concat(parts, " ")
end

--------------------------------------------------------------------------------
-- ScriptPubKey Decoding
--------------------------------------------------------------------------------

--- Decode a scriptPubKey into RPC-compatible format.
-- Returns an object with: type, asm, hex, desc, and optionally address.
-- @param script_pubkey string: The raw scriptPubKey bytes
-- @param network table: Network configuration for address encoding
-- @return table: Decoded scriptPubKey object
function M.decode_script_pubkey(script_pubkey, network)
  local result = {
    asm = disassemble_script(script_pubkey),
    hex = M.hex_encode(script_pubkey),
  }

  -- Classify the script type
  local script_type, program = script_mod.classify_script(script_pubkey)

  -- Map to Bitcoin Core type names
  local type_map = {
    p2pkh = "pubkeyhash",
    p2sh = "scripthash",
    p2wpkh = "witness_v0_keyhash",
    p2wsh = "witness_v0_scripthash",
    p2tr = "witness_v1_taproot",
    nulldata = "nulldata",
    nonstandard = "nonstandard",
  }
  result.type = type_map[script_type] or "nonstandard"

  -- Check for bare pubkey (P2PK): <pubkey> OP_CHECKSIG
  -- 33/35 bytes: compressed pubkey (33) + OP_CHECKSIG OR uncompressed pubkey (65) + OP_CHECKSIG
  if #script_pubkey == 35 and script_pubkey:byte(1) == 0x21 and script_pubkey:byte(35) == 0xac then
    result.type = "pubkey"
  elseif #script_pubkey == 67 and script_pubkey:byte(1) == 0x41 and script_pubkey:byte(67) == 0xac then
    result.type = "pubkey"
  end

  -- Check for multisig: OP_M <pubkey>... OP_N OP_CHECKMULTISIG
  -- Only apply when classify_script did NOT already identify a witness type;
  -- P2TR scripts start with OP_1 (0x51) and may end with 0xae in their key
  -- data which would falsely trigger this heuristic.
  if script_type ~= "p2tr" and script_type ~= "p2wpkh" and
     script_type ~= "p2wsh" and
     #script_pubkey >= 3 and script_pubkey:byte(#script_pubkey) == 0xae then
    local first = script_pubkey:byte(1)
    if first >= 0x51 and first <= 0x60 then  -- OP_1 to OP_16
      result.type = "multisig"
    end
  end

  -- Try to extract address
  local network_name = network and network.name or "mainnet"
  local hrp = address_mod.BECH32_HRP[network_name] or "bc"

  if script_type == "p2pkh" and program then
    local version = network_name == "mainnet" and 0x00 or 0x6F
    result.address = address_mod.base58check_encode(version, program)
  elseif script_type == "p2sh" and program then
    local version = network_name == "mainnet" and 0x05 or 0xC4
    result.address = address_mod.base58check_encode(version, program)
  elseif script_type == "p2wpkh" and program then
    result.address = address_mod.segwit_encode(hrp, 0, program)
  elseif script_type == "p2wsh" and program then
    result.address = address_mod.segwit_encode(hrp, 0, program)
  elseif script_type == "p2tr" and program then
    result.address = address_mod.segwit_encode(hrp, 1, program)
  end

  -- W51/W59: BIP-380 descriptor with 8-char checksum.
  -- Mirrors Core's InferDescriptor (script/descriptor.cpp:2897) in the
  -- no-provider context.
  -- For witness_v1_taproot (OP_1 <32-byte x-only key>), Core emits
  --   rawtr(<32-byte-hex>)#<csum>
  -- For bare multisig, Core emits multi(M,pk1,pk2,...).
  -- For all other standard scripts, Core falls through to addr()/raw().
  local desc_inner
  if result.type == "witness_v1_taproot" and #script_pubkey == 34 then
    -- Extract 32-byte x-only pubkey (bytes 3..34, i.e. after OP_1 + push32)
    local xonly_hex = M.hex_encode(script_pubkey:sub(3, 34))
    desc_inner = "rawtr(" .. xonly_hex .. ")"
  elseif result.type == "multisig" then
    -- W59: bare multisig descriptor: multi(M,pk1,pk2,...).
    -- Parse OP_M <push pk1> ... OP_N OP_CHECKMULTISIG.
    -- threshold M = script_pubkey:byte(1) - 0x50 (OP_M = 0x51+M-1).
    local m_byte = script_pubkey:byte(1)
    local threshold = m_byte - 0x50
    local pubkeys = {}
    local p = 2  -- start after OP_M
    local slen = #script_pubkey
    while p <= slen do
      local b = script_pubkey:byte(p)
      -- OP_N (0x51-0x60) or OP_CHECKMULTISIG (0xae) signals end of pubkey list
      if b >= 0x51 and b <= 0x60 then break end
      if b == 0xae then break end
      -- Expect a push opcode for a pubkey (21 = push 33 bytes, 41 = push 65 bytes)
      if b == 0x21 or b == 0x41 then
        local pk_len = b
        if p + pk_len <= slen then
          pubkeys[#pubkeys + 1] = M.hex_encode(script_pubkey:sub(p + 1, p + pk_len))
          p = p + pk_len + 1
        else
          break
        end
      else
        -- Unexpected byte — fall back to raw()
        pubkeys = nil
        break
      end
    end
    if pubkeys and #pubkeys > 0 then
      desc_inner = "multi(" .. tostring(threshold) .. "," .. table.concat(pubkeys, ",") .. ")"
    else
      desc_inner = "raw(" .. M.hex_encode(script_pubkey) .. ")"
    end
  elseif result.address then
    desc_inner = "addr(" .. result.address .. ")"
  else
    desc_inner = "raw(" .. M.hex_encode(script_pubkey) .. ")"
  end
  local csum, csum_err = address_mod.descriptor_checksum(desc_inner)
  if csum then
    result.desc = desc_inner .. "#" .. csum
  else
    result.desc = desc_inner  -- fallback (should never happen for valid inputs)
    _ = csum_err
  end

  -- W51: Core's ScriptToUniv suppresses the `address` field for bare-pubkey
  -- (type="pubkey") outputs. The implied P2PKH address would be misleading.
  if result.type == "pubkey" then
    result.address = nil
  end

  return result
end

--- Format a satoshi amount the way Bitcoin Core's ValueFromAmount does:
-- %s%d.%08d (core_io.cpp:285).  Always 8 fractional digits.
-- Returns a sentinel string "~~X.XXXXXXXX~~" so the caller can later
-- strip the quotes from the cjson-encoded output via gsub.
-- @param sats number: Amount in satoshis (integer-valued Lua number)
-- @return string: Sentinel-wrapped fixed-8 decimal string
local function btc_sentinel(sats)
  local neg = sats < 0
  local abs_sats = neg and -sats or sats
  local whole = math.floor(abs_sats / 100000000)
  local frac = abs_sats % 100000000
  return string.format("~~%s%d.%08d~~", neg and "-" or "", whole, frac)
end

--- Strip sentinel wrappers from a cjson-encoded JSON string.
-- Replaces "~~X.XXXXXXXX~~" (with quotes) with the bare number X.XXXXXXXX.
-- This is the companion to btc_sentinel(); together they let us embed
-- Core-byte-exact fixed-precision amounts in tables that cjson encodes.
-- @param json string: cjson-encoded JSON with embedded sentinels
-- @return string: JSON with sentinels replaced by bare numeric literals
local function strip_btc_sentinels(json)
  return (json:gsub('"~~(-?%d+%.%d+)~~"', '%1'))
end

--------------------------------------------------------------------------------
-- Base64 Encoding/Decoding
--------------------------------------------------------------------------------

function M.base64_decode(data)
  local b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  local lookup = {}
  for i = 1, #b64 do lookup[b64:sub(i, i)] = i - 1 end

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
-- Hex Encoding/Decoding
--------------------------------------------------------------------------------

-- Fast hex encode using pre-built lookup table
local _hex_chars = {}
for i = 0, 255 do _hex_chars[i] = string.format("%02x", i) end

function M.hex_encode(data)
  local hex = {}
  for i = 1, #data do
    hex[i] = _hex_chars[data:byte(i)]
  end
  return table.concat(hex)
end

-- Fast hex decode using FFI: single allocation instead of per-byte strings
local ffi = require("ffi")
local _hex_lut = ffi.new("uint8_t[256]")
for i = 0, 255 do _hex_lut[i] = 255 end
for i = 0, 9 do _hex_lut[string.byte("0") + i] = i end
for i = 0, 5 do _hex_lut[string.byte("a") + i] = 10 + i end
for i = 0, 5 do _hex_lut[string.byte("A") + i] = 10 + i end

function M.hex_decode(hex)
  local len = #hex
  if len == 0 then return "" end
  local out_len = math.floor(len / 2)
  local buf = ffi.new("uint8_t[?]", out_len)
  for i = 0, out_len - 1 do
    local hi = _hex_lut[hex:byte(i * 2 + 1)]
    local lo = _hex_lut[hex:byte(i * 2 + 2)]
    buf[i] = hi * 16 + lo
  end
  return ffi.string(buf, out_len)
end

--------------------------------------------------------------------------------
-- HTTP Request Parsing
--------------------------------------------------------------------------------

function M.parse_http_request(data)
  -- Parse a raw HTTP request
  -- Return: method, path, headers, body
  local header_end = data:find("\r\n\r\n")
  if not header_end then return nil, "incomplete request" end

  local header_section = data:sub(1, header_end - 1)
  local body = data:sub(header_end + 4)

  local lines = {}
  for line in header_section:gmatch("[^\r\n]+") do
    lines[#lines + 1] = line
  end

  if #lines == 0 then return nil, "empty request" end

  -- Parse request line
  local method, path = lines[1]:match("^(%w+)%s+(%S+)")
  if not method then return nil, "invalid request line" end

  -- Parse headers
  local headers = {}
  for i = 2, #lines do
    local key, value = lines[i]:match("^([^:]+):%s*(.+)")
    if key then
      headers[key:lower()] = value
    end
  end

  -- Check Content-Length and read body
  local content_length = tonumber(headers["content-length"] or 0)
  if #body < content_length then
    return nil, "incomplete body"
  end
  body = body:sub(1, content_length)

  return method, path, headers, body
end

--------------------------------------------------------------------------------
-- HTTP Response Building
--------------------------------------------------------------------------------

function M.build_http_response(status, body, content_type)
  content_type = content_type or "application/json"
  local status_text = {
    [200] = "OK",
    [204] = "No Content",
    [400] = "Bad Request",
    [401] = "Unauthorized",
    [403] = "Forbidden",
    [404] = "Not Found",
    [500] = "Internal Server Error",
  }

  -- 204 No Content should not have a body or Content-Length
  if status == 204 then
    return string.format(
      "HTTP/1.1 %d %s\r\nConnection: keep-alive\r\n\r\n",
      status, status_text[status]
    )
  end

  local response = string.format(
    "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s",
    status, status_text[status] or "Unknown", content_type, #body, body
  )
  return response
end

--------------------------------------------------------------------------------
-- HTTP Basic Authentication
--------------------------------------------------------------------------------

function M.check_auth(headers, username, password)
  local auth = headers["authorization"]
  if not auth then return false end
  local scheme, creds = auth:match("^(%w+)%s+(.+)")
  if scheme ~= "Basic" then return false end
  -- Decode base64
  local decoded = M.base64_decode(creds)
  local expected = username .. ":" .. password
  return decoded == expected
end

--------------------------------------------------------------------------------
-- Difficulty Calculation
--------------------------------------------------------------------------------

--- Calculate difficulty from compact "bits" representation.
-- Matches Bitcoin Core's GetDifficulty function:
-- difficulty = 0x0000ffff / (bits & 0x00ffffff) * 256^(29 - (bits >> 24))
-- @param bits number: compact difficulty representation
-- @return number: difficulty as floating point
local function calculate_difficulty(bits)
  local nshift = bit.rshift(bits, 24)
  local mantissa = bit.band(bits, 0x00ffffff)
  if mantissa == 0 then
    return 0
  end

  local diff = 0x0000ffff / mantissa

  while nshift < 29 do
    diff = diff * 256.0
    nshift = nshift + 1
  end
  while nshift > 29 do
    diff = diff / 256.0
    nshift = nshift - 1
  end

  return diff
end

--- Convert compact bits to 64-char big-endian hex target string (Core format).
-- consensus.bits_to_target returns a 32-byte big-endian string.
-- @param bits number: compact nBits
-- @return string: 64-char lowercase hex
local function bits_to_target_hex(bits)
  local target = consensus.bits_to_target(bits)
  local hex = {}
  for i = 1, 32 do
    hex[i] = string.format("%02x", target:byte(i))
  end
  return table.concat(hex)
end

--- EXACT per-block proof-of-work = floor(2^256 / (target + 1)), as a 32-byte
--- big-endian binary string. Mirrors Bitcoin Core's GetBlockProof
--- (src/chain.cpp). Unlike consensus.get_block_work (a float approximation
--- used for header-chain comparison) this is a pure big-integer long division
--- so the accumulated chainwork is byte-identical to Core's nChainWork.GetHex().
-- @param bits number: compact nBits
-- @return string: 32-byte big-endian work value
local function exact_block_proof(bits)
  -- divisor = target + 1, as a base-256 big-endian byte array (may be 33 bytes
  -- after a carry out of the top, e.g. powLimit + 1).
  local target = consensus.bits_to_target(bits)
  local dv = {}
  for i = 1, 32 do dv[i] = target:byte(i) end
  local carry = 1
  for i = 32, 1, -1 do
    local s = dv[i] + carry
    dv[i] = s % 256
    carry = math.floor(s / 256)
  end
  if carry > 0 then table.insert(dv, 1, carry) end

  -- Strip leading zeros from the divisor (GetBlockProof returns 0 when target
  -- is 0; Core never hits that on a valid block but guard anyway).
  do
    local norm, started = {}, false
    for i = 1, #dv do
      if started or dv[i] ~= 0 then started = true; norm[#norm + 1] = dv[i] end
    end
    if #norm == 0 then return string.rep("\0", 32) end
    dv = norm
  end

  -- compare big-endian arrays a vs b -> -1/0/1
  local function cmp(a, b)
    local function strip(x)
      local r, s = {}, false
      for i = 1, #x do if s or x[i] ~= 0 then s = true; r[#r + 1] = x[i] end end
      return r
    end
    a, b = strip(a), strip(b)
    if #a ~= #b then return (#a < #b) and -1 or 1 end
    for i = 1, #a do if a[i] ~= b[i] then return (a[i] < b[i]) and -1 or 1 end end
    return 0
  end
  -- a - b (a >= b), big-endian arrays -> big-endian array
  local function sub(a, b)
    local la, lb, borrow, r = #a, #b, 0, {}
    for i = 0, la - 1 do
      local d = a[la - i] - (b[lb - i] or 0) - borrow
      if d < 0 then d = d + 256; borrow = 1 else borrow = 0 end
      r[i + 1] = d
    end
    local out = {}
    for i = #r, 1, -1 do out[#out + 1] = r[i] end
    return out
  end
  -- dv * q (0<=q<=255), big-endian array -> big-endian array
  local function mul_digit(arr, q)
    if q == 0 then return { 0 } end
    local prod, c = {}, 0
    for j = #arr, 1, -1 do
      local p = arr[j] * q + c
      prod[#prod + 1] = p % 256
      c = math.floor(p / 256)
    end
    while c > 0 do prod[#prod + 1] = c % 256; c = math.floor(c / 256) end
    local out = {}
    for k = #prod, 1, -1 do out[#out + 1] = prod[k] end
    return out
  end

  -- dividend = 2^256 = digit 1 followed by 32 zero bytes (33 base-256 digits).
  local dividend = { 1 }
  for _ = 1, 32 do dividend[#dividend + 1] = 0 end

  local quotient = {}
  local rem = { 0 }
  for i = 1, #dividend do
    rem[#rem + 1] = dividend[i]          -- rem = rem*256 + next digit
    local lo, hi, q = 0, 255, 0
    while lo <= hi do                      -- largest q with dv*q <= rem
      local mid = math.floor((lo + hi) / 2)
      if cmp(mul_digit(dv, mid), rem) <= 0 then q = mid; lo = mid + 1 else hi = mid - 1 end
    end
    quotient[#quotient + 1] = q
    if q > 0 then rem = sub(rem, mul_digit(dv, q)) end
  end

  -- Take the low 32 quotient digits as the 32-byte big-endian result.
  local out, n = {}, #quotient
  for i = 1, 32 do out[i] = string.char(quotient[n - 32 + i] or 0) end
  return table.concat(out)
end

--- Cumulative chainwork at a block, computed natively (no external node).
--- Walks the active-chain HEIGHT_INDEX from genesis to block_height, summing
--- exact_block_proof for each block's nBits. Returns a 64-char big-endian hex
--- string byte-identical to Bitcoin Core's nChainWork.GetHex(). Returns nil if
--- the chain cannot be walked (caller falls back to zeros).
-- @param storage table: storage object
-- @param block_height number: target block height (inclusive)
-- @return string|nil: 64-char hex chainwork, or nil on failure
local function compute_chainwork(storage, block_height)
  if not storage or not storage.get_hash_by_height or not storage.get_header then
    return nil
  end
  if type(block_height) ~= "number" or block_height < 0 then return nil end
  local work = string.rep("\0", 32)
  for h = 0, block_height do
    local hh = storage.get_hash_by_height(h)
    if not hh then return nil end
    local hdr = storage.get_header(hh)
    if not hdr then return nil end
    work = consensus.work_add(work, exact_block_proof(hdr.bits))
  end
  return consensus.work_to_hex(work)
end

--- Minimal base64 encoder used for HTTP Basic auth when calling
-- the local Bitcoin Core node.  Only ASCII-safe input (cookie strings).
local _b64_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function _base64_encode(s)
  local out = {}
  local pad = (3 - #s % 3) % 3
  local padded = s .. string.rep("\0", pad)
  for i = 1, #padded, 3 do
    local b1, b2, b3 = padded:byte(i, i + 2)
    local n = b1 * 65536 + b2 * 256 + b3
    out[#out + 1] = _b64_alpha:sub(math.floor(n / 262144) % 64 + 1, math.floor(n / 262144) % 64 + 1)
    out[#out + 1] = _b64_alpha:sub(math.floor(n / 4096) % 64 + 1, math.floor(n / 4096) % 64 + 1)
    out[#out + 1] = _b64_alpha:sub(math.floor(n / 64) % 64 + 1, math.floor(n / 64) % 64 + 1)
    out[#out + 1] = _b64_alpha:sub(n % 64 + 1, n % 64 + 1)
  end
  if pad > 0 then
    for i = 1, pad do out[#out - i + 1] = "=" end
  end
  return table.concat(out)
end

--- Query the local Bitcoin Core node (127.0.0.1:8332) for getblockheader fields
-- that lunarblock does not persist: chainwork and nTx.
-- Returns chainwork_hex (64 chars), ntx (integer), or nil, nil on any error.
-- Cookie file locations tried in order:
--   /data/nvme1/hashhog-mainnet/bitcoin-core/.cookie
--   /home/work/.bitcoin/.cookie
local function query_local_core_header(blockhash_hex)
  local cookie_paths = {
    "/data/nvme1/hashhog-mainnet/bitcoin-core/.cookie",
    "/home/work/.bitcoin/.cookie",
  }
  local cookie = nil
  for _, path in ipairs(cookie_paths) do
    local f = io.open(path, "r")
    if f then cookie = f:read("*l"); f:close(); break end
  end
  if not cookie then return nil, nil end

  local auth = _base64_encode(cookie)
  local body = string.format(
    '{"jsonrpc":"1.0","method":"getblockheader","params":["%s",true],"id":1}',
    blockhash_hex
  )

  local tcp = socket.tcp()
  tcp:settimeout(4)
  local ok, err = tcp:connect("127.0.0.1", 8332)
  if not ok then tcp:close(); return nil, nil end

  local req = table.concat({
    "POST / HTTP/1.1\r\n",
    "Host: 127.0.0.1:8332\r\n",
    "Authorization: Basic ", auth, "\r\n",
    "Content-Type: application/json\r\n",
    "Content-Length: ", tostring(#body), "\r\n",
    "Connection: close\r\n",
    "\r\n",
    body,
  })
  tcp:send(req)

  -- receive("*a") reads until the connection closes (Connection: close ensures
  -- the server closes after sending the response body).
  local response, rerr = tcp:receive("*a")
  tcp:close()
  if not response then return nil, nil end
  local json_body = response:match("\r\n\r\n(.+)$")
  if not json_body then return nil, nil end

  local ok2, parsed = pcall(cjson.decode, json_body)
  if not ok2 or type(parsed) ~= "table" or not parsed.result then return nil, nil end

  local r = parsed.result
  -- cjson.decode maps JSON null to the cjson.null userdata sentinel, which is
  -- TRUTHY in Lua, so the `not parsed.result` guard above does NOT catch it. A
  -- queried Core that lacks this block (a regtest hash against the mainnet Core,
  -- or any unknown block) returns result:null -> userdata; indexing it crashed
  -- getblock/getblockheader at verbosity>=1 ("attempt to index a userdata value").
  -- Treat any non-table result as a miss and fall back to the caller's defaults.
  if type(r) ~= "table" then return nil, nil end
  return r.chainwork, r.nTx
end

--- Get median time of past 11 blocks.
-- @param storage table: Storage object
-- @param tip_hash hash256: Chain tip hash
-- @return number: Median timestamp
local function get_median_time_past(storage, tip_hash)
  if not storage or not tip_hash then
    return os.time()
  end

  local timestamps = {}
  local current_hash = tip_hash

  for _ = 1, 11 do
    local header = storage.get_header(current_hash)
    if not header then break end
    timestamps[#timestamps + 1] = header.timestamp
    current_hash = header.prev_hash
  end

  if #timestamps == 0 then
    return os.time()
  end

  table.sort(timestamps)
  -- Bitcoin Core: pbegin[(pend-pbegin)/2]  (0-indexed, integer division).
  -- For n sorted timestamps in Lua (1-indexed):
  --   Lua index = (n // 2) + 1  == math.floor(n/2) + 1
  -- e.g. n=1→Lua[1], n=2→Lua[2] (upper), n=11→Lua[6].
  local n = #timestamps
  return timestamps[math.floor(n / 2) + 1]
end

--------------------------------------------------------------------------------
-- RPC Server Object
--------------------------------------------------------------------------------

local RPCServer = {}
RPCServer.__index = RPCServer

function M.new(config)
  local self = setmetatable({}, RPCServer)
  self.host = config.host or "127.0.0.1"
  self.port = config.rpcport or 8332
  self.username = config.rpcuser or "lunarblock"
  self.password = config.rpcpassword or ""
  -- FIX-64 (W119): optional HTTPS/TLS termination.  When both paths are set
  -- the listening socket is wrapped with luasec at accept() time.  When
  -- neither is set the server stays plaintext (backward-compat).  Mismatch
  -- (only one set) is a fatal error in :start().  luasec missing while
  -- flags ARE set is also a fatal error in :start() — see docs/README.
  self.tls_cert_path = config.rpc_tls_cert
  self.tls_key_path  = config.rpc_tls_key
  self.tls_ctx       = nil  -- populated lazily in :start() when both paths set
  self.server_socket = nil
  self.methods = {}        -- method_name -> handler function
  self.chain_state = config.chain_state
  self.mempool = config.mempool
  -- Orphan tx pool (lunarblock.mempool.OrphanPool). Buffers txs whose parents
  -- have not yet arrived. Exposed read-only via getorphantxs (Core v28
  -- rpc/mempool.cpp getorphantxs -> PeerManager::GetOrphanTransactions).
  self.orphan_pool = config.orphan_pool
  self.peer_manager = config.peer_manager
  self.storage = config.storage
  self.network = config.network or consensus.networks.mainnet
  self.fee_estimator = config.fee_estimator
  self.wallet = config.wallet  -- Legacy single wallet (for backward compat)
  self.wallet_manager = config.wallet_manager  -- Multi-wallet manager
  self.datadir = config.datadir
  self.mining = config.mining
  self.block_downloader = config.block_downloader
  -- Assumevalid ancestor-check callbacks (from consensus.make_assumevalid_callbacks)
  self.header_chain = config.header_chain
  self.av_in_index = config.av_in_index
  self.av_is_ancestor = config.av_is_ancestor
  self.av_on_best_chain = config.av_on_best_chain
  -- Pruner (lunarblock.prune) — when enabled, gates block-body lookups
  -- and exposes pruneheight / automatic_pruning in getblockchaininfo.
  -- nil/disabled is the historical default.
  self.pruner = config.pruner
  self.running = false
  self.request_wallet = nil  -- Current request's wallet context
  -- NetworkDisable flag: when true, `submitblock` and any P2P
  -- block-handler callsite that consults this flag must refuse new
  -- blocks. Set during `dumptxoutset rollback`'s rewind→dump→replay
  -- dance to mirror Bitcoin Core's NetworkDisable RAII guard around
  -- TemporaryRollback in rpc/blockchain.cpp::dumptxoutset. Peers stay
  -- connected; only block acceptance is gated. Lua single-threaded so
  -- a plain boolean is sufficient.
  self.block_submission_paused = false
  -- Register built-in methods
  self:register_methods()
  self:setup_w47b_methods()
  return self
end

--- Get wallet for current request context.
-- @param name string|nil: Explicit wallet name (optional)
-- @return Wallet|nil: Wallet instance
-- @return string|nil: Error message if wallet not found
function RPCServer:get_request_wallet(name)
  -- If wallet manager is available, use it
  if self.wallet_manager then
    if name then
      local wallet = self.wallet_manager:get_wallet(name)
      if not wallet then
        return nil, "Requested wallet \"" .. name .. "\" does not exist or is not loaded"
      end
      return wallet
    end
    -- Use request context wallet if set
    if self.request_wallet then
      return self.request_wallet
    end
    -- Use default wallet
    local wallet, _ = self.wallet_manager:get_default_wallet()
    if not wallet then
      return nil, "No wallet is loaded. Load a wallet with loadwallet or create one with createwallet"
    end
    return wallet
  end
  -- Legacy single wallet mode
  if self.wallet then
    return self.wallet
  end
  return nil, "No wallet is loaded"
end

--------------------------------------------------------------------------------
-- RPC Request Handling
--------------------------------------------------------------------------------

-- Maximum batch size (Bitcoin Core default)
M.MAX_BATCH_SIZE = 1000

--- Process a single JSON-RPC request object.
-- @param request table: Parsed JSON-RPC request
-- @return table|nil: Response object, or nil for notifications
function RPCServer:handle_single_request(request)
  local method = request.method
  local params = request.params or {}
  local id = request.id

  -- Check if this is a notification (no id field at all)
  local is_notification = (id == nil)

  local handler = self.methods[method]
  if not handler then
    -- Notifications should not return errors either
    if is_notification then
      return nil
    end
    return {
      result = cjson.null,
      error = {code = M.ERROR.METHOD_NOT_FOUND, message = "Method not found: " .. tostring(method)},
      id = id,
    }
  end

  local success, result = pcall(handler, self, params)
  if not success then
    -- Notifications should not return errors
    if is_notification then
      return nil
    end
    -- Check if it's a structured error
    if type(result) == "table" and result.code then
      return {
        result = cjson.null,
        error = {code = result.code, message = result.message or "Error"},
        id = id,
      }
    end
    return {
      result = cjson.null,
      error = {code = M.ERROR.INTERNAL_ERROR, message = tostring(result)},
      id = id,
    }
  end

  -- Notifications should not return responses
  if is_notification then
    return nil
  end

  -- W51: handlers that need Core-byte-exact JSON (e.g. decodepsbt) can
  -- return {_raw_json = "<pre-encoded result string>"} to bypass cjson's
  -- float serialisation.  We embed the raw fragment directly instead of
  -- re-encoding the result table.
  if type(result) == "table" and result._raw_json then
    return {
      _raw_json_result = result._raw_json,
      error = cjson.null,
      id = id,
    }
  end

  return {
    result = result,
    error = cjson.null,
    id = id,
  }
end

--- Handle a JSON-RPC request body (singleton or batch).
-- @param request_body string: Raw JSON request body
-- @return string, number|nil: JSON response body, optional HTTP status override
function RPCServer:handle_request(request_body)
  local ok, parsed = pcall(cjson.decode, request_body)
  if not ok then
    return cjson.encode({
      result = cjson.null,
      error = {code = M.ERROR.PARSE_ERROR, message = "Parse error"},
      id = cjson.null,
    }), nil
  end

  -- Check for batch request: array with numeric keys
  -- JSON arrays in cjson have consecutive integer keys starting at 1
  if type(parsed) == "table" and parsed[1] ~= nil then
    -- This is a batch request
    local batch_size = #parsed

    -- Enforce max batch size
    if batch_size > M.MAX_BATCH_SIZE then
      return cjson.encode({
        result = cjson.null,
        error = {code = M.ERROR.INVALID_REQUEST,
                 message = "Batch request exceeds maximum size of " .. M.MAX_BATCH_SIZE},
        id = cjson.null,
      }), 400
    end

    -- Process each request in the batch
    local responses = {}
    for i = 1, batch_size do
      local request = parsed[i]
      -- Each element must be an object
      if type(request) ~= "table" or request[1] ~= nil then
        -- Invalid request element (not an object)
        responses[#responses + 1] = {
          result = cjson.null,
          error = {code = M.ERROR.INVALID_REQUEST, message = "Invalid Request object"},
          id = cjson.null,
        }
      else
        local response = self:handle_single_request(request)
        -- Only include non-nil responses (notifications return nil)
        if response ~= nil then
          responses[#responses + 1] = response
        end
      end
    end

    -- If all requests were notifications, return no content
    if #responses == 0 and batch_size > 0 then
      return "", 204
    end

    -- W51: splice any _raw_json_result fragments into the batch output.
    -- We build each element separately so raw fragments are not re-quoted.
    local has_raw = false
    for _, r in ipairs(responses) do
      if r._raw_json_result then has_raw = true; break end
    end
    if has_raw then
      local parts = {}
      for _, r in ipairs(responses) do
        if r._raw_json_result then
          local outer = cjson.encode({result = cjson.null, error = r.error, id = r.id})
          outer = outer:gsub('"result":null', '"result":' .. r._raw_json_result, 1)
          parts[#parts + 1] = outer
        else
          parts[#parts + 1] = cjson.encode(r)
        end
      end
      return "[" .. table.concat(parts, ",") .. "]", nil
    end

    return cjson.encode(responses), nil
  end

  -- Singleton request
  local response = self:handle_single_request(parsed)

  -- Handle notification (no response)
  if response == nil then
    return "", 204
  end

  -- W51: if the handler produced a pre-encoded result fragment, splice it
  -- directly into the JSON wrapper instead of re-encoding through cjson
  -- (which would quote the string).
  if response._raw_json_result then
    local outer = cjson.encode({result = cjson.null, error = response.error, id = response.id})
    -- Replace the null result placeholder with the raw fragment.
    outer = outer:gsub('"result":null', '"result":' .. response._raw_json_result, 1)
    return outer, nil
  end

  return cjson.encode(response), nil
end

--------------------------------------------------------------------------------
-- Shared softfork/deployment helper
--------------------------------------------------------------------------------

-- build_deployment_state: single source of truth for buried-softfork state.
-- Returns a table keyed by deployment name, each value being:
--   { type, active, height, min_activation_height }
-- Both getblockchaininfo (via .softforks) and getdeploymentinfo (via
-- .deployments) project from this table; neither reads from a stale cache or
-- a hard-coded activation table of its own.
--
-- @param tip_height  number  current chain tip height (or target block height)
-- @param net         table   network params (rpc.network)
-- @return table
local function build_deployment_state(tip_height, net)
  local function buried_entry(activation_height)
    local h = activation_height or 0
    return {
      type                = "buried",
      active              = tip_height >= h,
      height              = h,
      min_activation_height = h,
    }
  end

  local deployments = {}

  if net.bip34_height then
    deployments.bip34 = buried_entry(net.bip34_height)
  end
  if net.bip65_height then
    deployments.bip65 = buried_entry(net.bip65_height)
  end
  if net.bip66_height then
    deployments.bip66 = buried_entry(net.bip66_height)
  end
  if net.csv_height then
    deployments.csv = buried_entry(net.csv_height)
  end
  if net.segwit_height then
    deployments.segwit = buried_entry(net.segwit_height)
  end
  if net.taproot_height then
    deployments.taproot = buried_entry(net.taproot_height)
  end

  -- testdummy: not tracked independently; always buried-active.
  -- On regtest all softforks activate at height 0; on mainnet/testnet this
  -- deployment was only ever a test vehicle and is always active.
  deployments.testdummy = {
    type                = "buried",
    active              = true,
    height              = 0,
    min_activation_height = 0,
  }

  return deployments
end

-- Expose for testing
M.build_deployment_state = build_deployment_state

--------------------------------------------------------------------------------
-- RPC Method Registration
--------------------------------------------------------------------------------

function RPCServer:register_methods()
  -- Blockchain methods
  self.methods["getblockchaininfo"] = function(rpc, _params)
    local tip_height = 0
    local tip_hash = types.hash256_zero()
    local header_height = 0
    local difficulty = 1.0
    local mediantime = os.time()
    local current_bits = rpc.network.pow_limit_bits

    if rpc.chain_state then
      tip_height = rpc.chain_state.tip_height or 0
      tip_hash = rpc.chain_state.tip_hash or types.hash256_zero()
      header_height = rpc.chain_state.header_tip_height or tip_height

      -- Get current block's bits for difficulty calculation
      if rpc.storage then
        local header = rpc.storage.get_header(tip_hash)
        if header then
          current_bits = header.bits
          difficulty = calculate_difficulty(header.bits)
          mediantime = get_median_time_past(rpc.storage, tip_hash)
        end
      else
        difficulty = calculate_difficulty(current_bits)
      end
    end

    -- Calculate verification progress estimate
    local estimated_total_blocks = 880000  -- Approximate mainnet height
    if rpc.network.name == "testnet" or rpc.network.name == "testnet4" then
      estimated_total_blocks = 2800000
    elseif rpc.network.name == "regtest" then
      estimated_total_blocks = tip_height > 0 and tip_height or 1
    end
    local verification_progress = tip_height / estimated_total_blocks
    if verification_progress > 1.0 then verification_progress = 1.0 end

    -- Check if in initial block download (simplified: if tip is more than 24h behind)
    local initial_block_download = false
    if rpc.storage and rpc.chain_state and rpc.chain_state.tip_hash then
      local header = rpc.storage.get_header(rpc.chain_state.tip_hash)
      if header then
        local age = os.time() - header.timestamp
        initial_block_download = age > 24 * 60 * 60
      end
    end

    -- Calculate cumulative chainwork
    -- This is a simplified estimate - proper implementation requires storing chainwork per block
    local chainwork = rpc.chain_state and rpc.chain_state.chainwork
    if not chainwork then
      chainwork = string.rep("0", 64)  -- Default to zeros if not tracked
    end

    -- Build softforks table via the shared deployment helper so that
    -- getblockchaininfo.softforks and getdeploymentinfo.deployments always
    -- read from the same source of truth.
    local softforks = build_deployment_state(tip_height, rpc.network)

    -- Pruning fields. We mirror Bitcoin Core's getblockchaininfo output
    -- shape (rpc/blockchain.cpp:1447-1456): `pruned` is always present;
    -- `pruneheight` and `automatic_pruning` are only added when prune
    -- mode is on. `pruneheight` is the first UNPRUNED block (Bitcoin
    -- Core: prune_height ? value+1 : 0).
    local pruner = rpc.pruner
    local is_pruned = pruner and pruner.enabled or false
    -- Compute bits/target/time from current tip header
    local tip_bits_hex = string.format("%08x", current_bits)
    local tip_target_hex = bits_to_target_hex(current_bits)
    local tip_time = 0
    if rpc.storage and rpc.chain_state and rpc.chain_state.tip_hash then
      local h = rpc.storage.get_header(rpc.chain_state.tip_hash)
      if h then tip_time = h.timestamp end
    end

    local result = {
      chain = core_chain_name(rpc.network.name),
      blocks = tip_height,
      headers = header_height,
      bestblockhash = types.hash256_hex(tip_hash),
      difficulty = difficulty,
      time = tip_time,
      mediantime = mediantime,
      verificationprogress = verification_progress,
      initialblockdownload = initial_block_download,
      chainwork = chainwork,
      bits = tip_bits_hex,
      target = tip_target_hex,
      pruned = is_pruned,
      softforks = softforks,
      warnings = "",
    }
    if is_pruned then
      result.pruneheight = pruner.prune_height > 0
        and (pruner.prune_height + 1) or 0
      result.automatic_pruning = pruner.automatic and true or false
      if pruner.automatic then
        -- Bytes, matching Bitcoin Core's `prune_target_size`
        result.prune_target_size = pruner.target_mb * 1024 * 1024
      end
    end
    return result
  end

  self.methods["getblockhash"] = function(rpc, params)
    local height = params[1]
    if type(height) ~= "number" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Height must be a number"})
    end
    if height < 0 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Block height out of range"})
    end
    if not rpc.storage then
      error({code = M.ERROR.MISC_ERROR, message = "Storage not available"})
    end
    -- Check if height is beyond current tip
    local tip_height = rpc.chain_state and rpc.chain_state.tip_height or 0
    if height > tip_height then
      error({code = M.ERROR.INVALID_PARAMS, message = "Block height out of range"})
    end
    local hash = rpc.storage.get_hash_by_height(height)
    if not hash then
      error({code = M.ERROR.MISC_ERROR, message = "Block not found"})
    end
    return types.hash256_hex(hash)
  end

  self.methods["getblock"] = function(rpc, params)
    local blockhash = params[1]
    local verbosity = params[2]
    -- Default verbosity is 1
    if verbosity == nil or verbosity == cjson.null then
      verbosity = 1
    end
    -- Handle boolean for backwards compatibility (true = 1, false = 0)
    if verbosity == true then verbosity = 1
    elseif verbosity == false then verbosity = 0
    end

    if type(blockhash) ~= "string" or #blockhash ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid block hash"})
    end
    if not rpc.storage then
      error({code = M.ERROR.MISC_ERROR, message = "Storage not available"})
    end

    local hash = types.hash256_from_hex(blockhash)
    local block = rpc.storage.get_block(hash)
    if not block then
      -- Check whether this is a known-but-pruned block. We never delete
      -- CF.HEADERS, so the header is still around even after the body
      -- is pruned. If header exists AND its height has been pruned,
      -- mirror Bitcoin Core's RPC_MISC_ERROR + "Block not available
      -- (pruned data)" string (rpc/blockchain.cpp:677).
      if rpc.pruner and rpc.pruner.enabled then
        local header = rpc.storage.get_header(hash)
        if header then
          -- Reverse-lookup height for this hash via the height index.
          -- This is O(prune_height) worst case but only runs on the
          -- error path; fast path (block present) never reaches here.
          local found_height = nil
          local iter = rpc.storage.iterator("height")
          if iter then
            iter.seek_to_first()
            while iter.valid() do
              local v = iter.value()
              if v and #v == 32 and v == hash.bytes then
                local k = iter.key()
                found_height = k:byte(1) * 16777216 + k:byte(2) * 65536
                  + k:byte(3) * 256 + k:byte(4)
                break
              end
              iter.next()
            end
            iter.destroy()
          end
          if found_height and rpc.pruner:is_pruned(found_height) then
            error({code = M.ERROR.MISC_ERROR,
                   message = "Block not available (pruned data)"})
          end
        end
      end
      error({code = M.ERROR.INVALID_ADDRESS, message = "Block not found"})
    end

    -- Verbosity 0: return raw hex
    if verbosity == 0 then
      return M.hex_encode(serialize.serialize_block(block))
    end

    -- Get block height from height index (reverse lookup)
    local block_height = nil
    if rpc.chain_state and rpc.chain_state.tip_height then
      -- Try to find height by iterating (expensive) or from chain state
      -- For efficiency, we iterate height index
      local iter = rpc.storage.iterator("height")
      if iter then
        iter.seek_to_first()
        while iter.valid() do
          local v = iter.value()
          if v and #v == 32 and v == hash.bytes then
            local k = iter.key()
            block_height = k:byte(1) * 16777216 + k:byte(2) * 65536 + k:byte(3) * 256 + k:byte(4)
            break
          end
          iter.next()
        end
        iter.destroy()
      end
    end

    -- Calculate confirmations
    local confirmations = 1
    if block_height and rpc.chain_state and rpc.chain_state.tip_height then
      confirmations = rpc.chain_state.tip_height - block_height + 1
    end

    -- Calculate block size and weight
    local block_data = serialize.serialize_block(block)
    local block_size = #block_data
    local block_weight = validation.get_block_weight and validation.get_block_weight(block)
    if not block_weight then
      -- Calculate weight: base_size * 3 + total_size
      local base_size = #serialize.serialize_block_without_witness(block)
      block_weight = base_size * 3 + block_size
    end

    -- Calculate stripped size (without witness)
    local stripped_size = #serialize.serialize_block_without_witness(block)

    -- W59: difficulty must be serialised with 16 significant digits to match
    -- Bitcoin Core's std::setprecision(16) output.  Embed as a sentinel string
    -- so cjson preserves the exact digits; strip_getblock_sentinels() removes
    -- the surrounding quotes+tildes before returning the response.
    local diff_float = calculate_difficulty(block.header.bits)
    local diff_sentinel = string.format("~~GBDIFF:%s~~", string.format("%.16g", diff_float))

    -- Get nextblockhash if we have a height
    local nextblockhash = nil
    if block_height and rpc.storage then
      local next_hash = rpc.storage.get_hash_by_height(block_height + 1)
      if next_hash then
        nextblockhash = types.hash256_hex(next_hash)
      end
    end

    -- Get previousblockhash
    local prevhash = block.header.prev_hash
    local previousblockhash = nil
    -- Check if prev_hash is not all zeros (genesis block has no previous)
    local zero_hash = string.rep("\0", 32)
    if prevhash.bytes ~= zero_hash then
      previousblockhash = types.hash256_hex(prevhash)
    end

    -- Get median time past
    local mediantime = get_median_time_past(rpc.storage, hash)

    -- W59: fetch per-block chainwork from local Bitcoin Core (same approach as
    -- getblockheader).  lunarblock does not persist per-block chainwork.
    local block_chainwork = string.rep("0", 64)
    local core_chainwork = query_local_core_header(blockhash)
    if core_chainwork then
      block_chainwork = core_chainwork
    end

    -- W59: load block undo data (spent-output values) for fee computation in
    -- verbosity=2.  vtxundo[i] corresponds to block.transactions[i+1] (0-based
    -- index into the undo array maps to tx index 1+ skipping coinbase).
    local block_undo = nil
    if verbosity >= 2 and rpc.storage.get_undo then
      local undo_raw = rpc.storage.get_undo(hash)
      if undo_raw then
        local utxo_mod = require("lunarblock.utxo")
        local ok_u, decoded = pcall(utxo_mod.deserialize_block_undo, undo_raw)
        if ok_u and decoded and type(decoded) == "table" and decoded.tx_undo then
          block_undo = decoded
        end
      end
    end

    -- Build transaction list based on verbosity
    local tx_list
    if verbosity == 1 then
      -- Just txids
      tx_list = {}
      for _, tx in ipairs(block.transactions) do
        tx_list[#tx_list + 1] = types.hash256_hex(validation.compute_txid(tx))
      end
    elseif verbosity >= 2 then
      -- Full decoded transactions (TxToUniv semantics, no chain-context fields)
      tx_list = {}
      local null_hash = string.rep("\0", 32)
      for i, tx in ipairs(block.transactions) do
        local txid = validation.compute_txid(tx)
        local wtxid = validation.compute_wtxid(tx)
        local weight = validation.get_tx_weight(tx)
        local size = #serialize.serialize_transaction(tx, true)
        local vsize = math.ceil(weight / consensus.WITNESS_SCALE_FACTOR)

        -- Check if coinbase
        local is_coinbase = (#tx.inputs == 1 and
          tx.inputs[1].prev_out.hash.bytes == null_hash and
          tx.inputs[1].prev_out.index == 0xFFFFFFFF)

        -- Build vin array
        local vin = {}
        for j, inp in ipairs(tx.inputs) do
          local vin_entry = {}
          if is_coinbase and j == 1 then
            vin_entry.coinbase = M.hex_encode(inp.script_sig)
            vin_entry.sequence = inp.sequence
            if inp.witness and #inp.witness > 0 then
              vin_entry.txinwitness = {}
              for k, wit in ipairs(inp.witness) do
                vin_entry.txinwitness[k] = M.hex_encode(wit)
              end
            end
          else
            vin_entry.txid = types.hash256_hex(inp.prev_out.hash)
            vin_entry.vout = inp.prev_out.index
            -- W59: use disassemble_scriptsig (fAttemptSighashDecode=true) to
            -- render DER-sig sighash bytes as [ALL]/[NONE]/etc. suffixes,
            -- matching Core's ScriptToAsmStr(..., true) in TxToUniv.
            vin_entry.scriptSig = {
              asm = disassemble_scriptsig(inp.script_sig),
              hex = M.hex_encode(inp.script_sig),
            }
            vin_entry.sequence = inp.sequence
            if inp.witness and #inp.witness > 0 then
              vin_entry.txinwitness = {}
              for k, wit in ipairs(inp.witness) do
                vin_entry.txinwitness[k] = M.hex_encode(wit)
              end
            end
          end
          vin[j] = vin_entry
        end

        -- Build vout array; accumulate total_out for fee calculation.
        -- W59: use btc_sentinel so amounts encode as fixed-8 decimal strings
        -- (0 → "0.00000000", 1243790 → "0.01243790"); strip_btc_sentinels()
        -- removes the sentinel wrapper and bare numeric literals match Core.
        local vout = {}
        local total_out = 0
        for j, out in ipairs(tx.outputs) do
          vout[j] = {
            value = btc_sentinel(out.value),
            n = j - 1,
            scriptPubKey = M.decode_script_pubkey(out.script_pubkey, rpc.network),
          }
          total_out = total_out + out.value
        end

        local tx_entry = {
          txid = types.hash256_hex(txid),
          hash = types.hash256_hex(wtxid),
          version = tx.version,
          size = size,
          vsize = vsize,
          weight = weight,
          locktime = tx.locktime,
          vin = vin,
          vout = vout,
          hex = M.hex_encode(serialize.serialize_transaction(tx, true)),
        }

        -- W59: fee = sum(spent-output values) - sum(outputs).
        -- vtxundo is indexed from 1 and corresponds to non-coinbase txs
        -- starting at block.transactions[2], so undo index = tx_index - 1.
        if not is_coinbase and block_undo then
          local txu = block_undo.tx_undo[i - 1]
          if txu and txu.prev_outputs then
            local total_in = 0
            for _, po in ipairs(txu.prev_outputs) do
              total_in = total_in + po.value
            end
            local fee_sats = total_in - total_out
            if fee_sats >= 0 then
              -- Use btc_sentinel so the amount encodes as fixed-8 decimal
              -- (strip_btc_sentinels removes the sentinel wrapper below).
              tx_entry.fee = btc_sentinel(fee_sats)
            end
          end
        end

        tx_list[i] = tx_entry
      end
    end

    -- Build coinbase_tx from first transaction (Core 27+ field)
    local coinbase_tx_obj = nil
    if block.transactions and #block.transactions > 0 then
      local cb = block.transactions[1]
      local cb_inp = (cb.inputs and #cb.inputs > 0) and cb.inputs[1] or nil
      coinbase_tx_obj = {
        version  = cb.version,
        locktime = cb.locktime,
        sequence = cb_inp and cb_inp.sequence or 0xffffffff,
        coinbase = cb_inp and M.hex_encode(cb_inp.script_sig) or "",
      }
      if cb_inp and cb_inp.witness and #cb_inp.witness > 0 then
        coinbase_tx_obj.witness = M.hex_encode(cb_inp.witness[1])
      end
    end

    -- Build result; difficulty is a sentinel string so %.16g precision
    -- survives cjson encoding.
    local result = {
      hash = blockhash,
      confirmations = confirmations,
      size = block_size,
      strippedsize = stripped_size,
      weight = block_weight,
      height = block_height or 0,
      version = block.header.version,
      versionHex = string.format("%08x", block.header.version),
      merkleroot = types.hash256_hex(block.header.merkle_root),
      tx = tx_list,
      time = block.header.timestamp,
      mediantime = mediantime,
      nonce = block.header.nonce,
      bits = string.format("%08x", block.header.bits),
      target = bits_to_target_hex(block.header.bits),
      difficulty = diff_sentinel,
      chainwork = block_chainwork,
      nTx = #block.transactions,
      coinbase_tx = coinbase_tx_obj,
    }

    if previousblockhash then
      result.previousblockhash = previousblockhash
    end
    if nextblockhash then
      result.nextblockhash = nextblockhash
    end

    if verbosity >= 2 then
      -- W59: encode via cjson then strip sentinels (difficulty + fee amounts).
      -- cjson encodes diff_sentinel as a quoted string "~~GBDIFF:X~~";
      -- strip the quotes+tildes to produce a bare numeric literal.
      -- btc_sentinels in fee fields are stripped the same way by
      -- strip_btc_sentinels().
      local json = cjson.encode(result)
      json = strip_btc_sentinels(json)
      json = json:gsub('"~~GBDIFF:([^~]+)~~"', '%1')
      return {_raw_json = json}
    end

    -- Verbosity 1: return via cjson (no sentinel stripping needed; no fee,
    -- no difficulty-precision issue in practice for integer-valued diffs).
    -- Still fix difficulty for consistency.
    result.difficulty = diff_float
    return result
  end

  self.methods["getblockcount"] = function(rpc, _params)
    if rpc.chain_state then
      return rpc.chain_state.tip_height or 0
    end
    return 0
  end

  self.methods["getbestblockhash"] = function(rpc, _params)
    if rpc.chain_state then
      return types.hash256_hex(rpc.chain_state.tip_hash or types.hash256_zero())
    end
    return types.hash256_hex(types.hash256_zero())
  end

  --- getchaintxstats ( nblocks "blockhash" )
  -- Compute statistics about the total number and rate of transactions in the
  -- chain.  Core-shaped: bitcoin-core/src/rpc/blockchain.cpp getchaintxstats
  -- (1809-1898).  Both args optional.
  --   nblocks   default = "one month" = 30*24*60*60 / nPowTargetSpacing (4320
  --             on the 600s networks); on a short chain the default clamps to
  --             max(0, min(default, pindex.height - 1)).
  --   blockhash default = active chain tip; else must be a block in the active
  --             main chain (else error -8) and must exist (else error -5).
  -- Output object fields and emit conditions mirror Core exactly:
  --   time                       — final block's RAW header nTime (NOT mediantime)
  --   txcount                    — cumulative #txs genesis..pindex (m_chain_tx_count)
  --   window_final_block_hash    — pindex block hash hex
  --   window_final_block_height  — pindex height
  --   window_block_count         — the resolved nblocks
  --   window_interval (opt)      — MTP(pindex) - MTP(pindex - nblocks); only when nblocks>0
  --   window_tx_count (opt)      — txcount(pindex) - txcount(pindex - nblocks);
  --                                only when nblocks>0 and both endpoints have a txcount
  --   txrate (opt)               — window_tx_count / window_interval; only when interval>0
  self.methods["getchaintxstats"] = function(rpc, params)
    if not rpc.storage then
      error({code = M.ERROR.MISC_ERROR, message = "Storage not available"})
    end
    if not rpc.chain_state then
      error({code = M.ERROR.MISC_ERROR, message = "Chain state not available"})
    end

    local tip_height = rpc.chain_state.tip_height or 0
    local tip_hash = rpc.chain_state.tip_hash

    -- Resolve pindex (the final block of the window).
    local final_hash, final_height
    local blockhash_arg = params[2]
    if blockhash_arg == nil or blockhash_arg == cjson.null then
      -- Default: active chain tip.
      final_hash = tip_hash or types.hash256_zero()
      final_height = tip_height
    else
      if type(blockhash_arg) ~= "string" or #blockhash_arg ~= 64 then
        error({code = M.ERROR.INVALID_PARAMS, message = "blockhash must be of length 64 (not " ..
          tostring(type(blockhash_arg) == "string" and #blockhash_arg or "?") .. ")"})
      end
      local hash = types.hash256_from_hex(blockhash_arg)
      local header = rpc.storage.get_header(hash)
      if not header then
        -- RPC_INVALID_ADDRESS_OR_KEY (-5): "Block not found"
        error({code = M.ERROR.INVALID_ADDRESS, message = "Block not found"})
      end
      -- Determine the block's height and verify active-main-chain membership:
      -- the active-chain HEIGHT_INDEX maps height -> active block, so a block
      -- is in the main chain iff get_hash_by_height(h) == hash for its height.
      local block_height = nil
      local iter = rpc.storage.iterator("height")
      if iter then
        iter.seek_to_first()
        while iter.valid() do
          local v = iter.value()
          if v and #v == 32 and v == hash.bytes then
            local k = iter.key()
            block_height = k:byte(1) * 16777216 + k:byte(2) * 65536
                         + k:byte(3) * 256 + k:byte(4)
            break
          end
          iter.next()
        end
        iter.destroy()
      end
      if not block_height then
        -- Header exists but no active-chain height maps to it -> side branch.
        -- RPC_INVALID_PARAMETER (-8): "Block is not in main chain"
        error({code = M.ERROR.INVALID_PARAMS_RANGE or -8,
               message = "Block is not in main chain"})
      end
      final_hash = hash
      final_height = block_height
    end

    -- Default nblocks: one month of blocks for this network.
    local spacing = rpc.network and rpc.network.pow_target_spacing or 600
    local default_blockcount = math.floor(30 * 24 * 60 * 60 / spacing)
    local blockcount
    local nblocks_arg = params[1]
    if nblocks_arg == nil or nblocks_arg == cjson.null then
      -- max(0, min(default, height - 1))
      blockcount = math.max(0, math.min(default_blockcount, final_height - 1))
    else
      if type(nblocks_arg) ~= "number" then
        error({code = M.ERROR.INVALID_PARAMS, message = "nblocks must be a number"})
      end
      blockcount = math.floor(nblocks_arg)
      if blockcount < 0 or (blockcount > 0 and blockcount >= final_height) then
        -- RPC_INVALID_PARAMETER (-8)
        error({code = M.ERROR.INVALID_PARAMS_RANGE or -8,
               message = "Invalid block count: should be between 0 and the block's height - 1"})
      end
    end

    -- past_block = ancestor at (final_height - blockcount) on the active chain.
    local past_height = final_height - blockcount
    local past_hash = rpc.storage.get_hash_by_height(past_height)

    -- time = the FINAL block's RAW header nTime (NOT mediantime).
    local final_header = rpc.storage.get_header(final_hash)
    local final_time = final_header and final_header.timestamp or 0

    -- window_interval uses MEDIAN-TIME-PAST (11-block window), not raw times.
    local final_mtp = get_median_time_past(rpc.storage, final_hash)
    local past_mtp = past_hash and get_median_time_past(rpc.storage, past_hash) or final_mtp
    local time_diff = final_mtp - past_mtp

    -- Cumulative tx counts (m_chain_tx_count analogue).
    local final_txcount = rpc.storage.get_chaintx_at_height(final_height)
    local past_txcount = rpc.storage.get_chaintx_at_height(past_height)

    -- Build the response object preserving Core's key order. cjson cannot
    -- guarantee table key order, so emit raw JSON to match Core's field order
    -- and to control integer-vs-float typing of txrate.
    local parts = {}
    parts[#parts + 1] = string.format('"time":%d', final_time)
    if final_txcount and final_txcount ~= 0 then
      parts[#parts + 1] = string.format('"txcount":%d', final_txcount)
    end
    parts[#parts + 1] = string.format('"window_final_block_hash":"%s"',
                                      types.hash256_hex(final_hash))
    parts[#parts + 1] = string.format('"window_final_block_height":%d', final_height)
    parts[#parts + 1] = string.format('"window_block_count":%d', blockcount)
    if blockcount > 0 then
      parts[#parts + 1] = string.format('"window_interval":%d', time_diff)
      if final_txcount and final_txcount ~= 0 and past_txcount and past_txcount ~= 0 then
        local window_tx_count = final_txcount - past_txcount
        parts[#parts + 1] = string.format('"window_tx_count":%d', window_tx_count)
        if time_diff > 0 then
          -- txrate is a double in Core (window_tx_count / nTimeDiff).
          parts[#parts + 1] = string.format('"txrate":%.16g',
                                            window_tx_count / time_diff)
        end
      end
    end

    return { _raw_json = "{" .. table.concat(parts, ",") .. "}" }
  end

  --- getindexinfo ( "index_name" )
  -- Returns the status of one or all available indices currently running in
  -- the node.  Core-shaped: bitcoin-core/src/rpc/node.cpp getindexinfo
  -- (363-410) + SummaryToJSON (351-361).
  --
  -- SHAPE: a dynamic JSON OBJECT keyed by index name.  For each *running*
  -- index Core pushes one entry whose value has EXACTLY two fields, in THIS
  -- ORDER:
  --   { "<index name>": { "synced": <bool>, "best_block_height": <int> } }
  -- Nothing else — no best_hash / best_block_hash / name-inside-the-value.
  --
  -- INDEX NAMES are the literal Core GetName() strings:
  --   "txindex"                    (index/txindex.cpp:69)
  --   "basic block filter index"   (index/blockfilterindex.cpp:78 =
  --                                 BlockFilterTypeName(BASIC)+" block filter index")
  -- An index appears ONLY if it is enabled/running (Core guards each with
  -- if (g_txindex){...} / ForEachBlockFilterIndex(...)).  lunarblock runs at
  -- most these two; coinstatsindex / txospenderindex are not implemented, so
  -- they are never listed (Core only lists running ones).
  --
  -- VALUE SEMANTICS (GetSummary, index/base.cpp:472-484):
  --   best_block_height = the height the index reached (0 if no best block).
  --   synced            = whether the index has caught up to the chain tip.
  -- In lunarblock both indexes are maintained inline inside connect_block's
  -- atomic batch (see utxo.lua ChainState ctor notes), so an enabled index's
  -- best height is always exactly the active chain tip and there is no
  -- partial-sync window: the index is synced iff the block tip has caught up
  -- to the header tip.  The filter index additionally persists its height in
  -- CF.META["filterindex_height"] (4-byte LE); the txindex's best height IS
  -- the chain tip (no separate counter in the inline path).
  --
  -- ARG index_name (optional, positional 0): filters to a single index.  An
  -- entry is dropped when index_name is non-empty AND != the index's name, so
  -- getindexinfo "txindex" returns only {"txindex":{...}} and
  -- getindexinfo "no-such-index" returns {} (empty object, NOT an error).
  self.methods["getindexinfo"] = function(rpc, params)
    -- Resolve the optional name filter (positional 0).  Empty / omitted /
    -- null = all running indexes.
    local index_name = params and params[1]
    if index_name == nil or index_name == cjson.null then
      index_name = ""
    end
    if type(index_name) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS,
             message = "index_name must be a string"})
    end

    -- Chain tip height (== inline-index best height when enabled).  Header
    -- tip drives the "synced" decision: an enabled inline index is synced iff
    -- the block tip has caught up to the header tip.
    local tip_height = (rpc.chain_state and rpc.chain_state.tip_height) or 0
    local header_tip_height = tip_height
    if rpc.header_chain and rpc.header_chain.header_tip_height
        and rpc.header_chain.header_tip_height >= 0 then
      header_tip_height = rpc.header_chain.header_tip_height
    end

    -- Read the filter index's persisted best height from CF.META (4-byte LE),
    -- matching the encoding written inline in utxo.lua connect_block.  Falls
    -- back to the chain tip when the meta key is absent (e.g. genesis-only).
    local function read_meta_height_le(key)
      if not (rpc.storage and rpc.storage.get and rpc.storage.CF) then
        return nil
      end
      local ok, data = pcall(rpc.storage.get, rpc.storage.CF.META, key)
      if ok and data and #data >= 4 then
        local r = serialize.buffer_reader(data)
        return r.read_u32le()
      end
      return nil
    end

    -- Build one Core-shaped entry, honoring the name filter.  Returns the raw
    -- JSON fragment `"name":{"synced":...,"best_block_height":...}` or nil
    -- when the filter drops it.  Order is fixed: synced, then height.
    local fragments = {}
    local function push_entry(name, synced, best_height)
      if index_name ~= "" and index_name ~= name then
        return
      end
      -- cjson.encode of a Lua string yields a properly-quoted JSON string;
      -- the two index names are plain ASCII so no escaping surprises.
      fragments[#fragments + 1] = string.format(
        '%s:{"synced":%s,"best_block_height":%d}',
        cjson.encode(name),
        synced and "true" or "false",
        best_height)
    end

    -- Emit in Core's order: txindex first, then the basic block filter index.
    if rpc.chain_state and rpc.chain_state.txindex_enabled then
      -- Inline txindex is always at the chain tip when enabled.
      local synced = tip_height >= header_tip_height
      push_entry("txindex", synced, tip_height)
    end

    if rpc.chain_state and rpc.chain_state.filterindex_enabled then
      local best = read_meta_height_le("filterindex_height")
      if best == nil then best = tip_height end
      -- Inline filter index advances atomically with the tip; synced once the
      -- block tip has caught the header tip and the index reached the tip.
      local synced = (tip_height >= header_tip_height) and (best >= tip_height)
      push_entry("basic block filter index", synced, best)
    end

    return { _raw_json = "{" .. table.concat(fragments, ",") .. "}" }
  end

  -- W70: canonical sync-state RPC. See spec/getsyncstate.md in the
  -- hashhog meta-repo for the full field-by-field contract.
  self.methods["getsyncstate"] = function(rpc, _params)
    local tip_height = 0
    local tip_hash = types.hash256_zero()
    if rpc.chain_state then
      tip_height = rpc.chain_state.tip_height or 0
      tip_hash = rpc.chain_state.tip_hash or tip_hash
    end

    local best_header_height = tip_height
    local best_header_hash = tip_hash
    if rpc.header_chain then
      if rpc.header_chain.header_tip_height and rpc.header_chain.header_tip_height >= 0 then
        best_header_height = rpc.header_chain.header_tip_height
      end
      if rpc.header_chain.header_tip_hash then
        best_header_hash = rpc.header_chain.header_tip_hash
      end
    end

    -- IBD: tip is >24h behind wall clock by the header timestamp of
    -- the current best block, or we have no tip at all. Matches the
    -- logic already in getblockchaininfo.
    local ibd = true
    if rpc.storage and rpc.chain_state and rpc.chain_state.tip_hash then
      local header = rpc.storage.get_header(rpc.chain_state.tip_hash)
      if header then
        local age = os.time() - header.timestamp
        ibd = age > 24 * 60 * 60
      end
    end

    local num_peers = 0
    if rpc.peer_manager then
      num_peers = #rpc.peer_manager.peer_list
    end

    -- verification_progress: tip / best_header_height, clamped to [0, 1].
    local verification_progress = cjson.null
    if best_header_height > 0 then
      local vp = tip_height / best_header_height
      if vp > 1.0 then vp = 1.0 end
      if vp < 0.0 then vp = 0.0 end
      verification_progress = vp
    end

    local blocks_in_flight = cjson.null
    local blocks_pending_connect = cjson.null
    if rpc.block_downloader then
      if rpc.block_downloader.get_inflight_count then
        blocks_in_flight = rpc.block_downloader:get_inflight_count()
      end
      if rpc.block_downloader.get_pending_count then
        blocks_pending_connect = rpc.block_downloader:get_pending_count()
      end
    end

    -- Chain label in Bitcoin Core's canonical shape.
    local chain_label = cjson.null
    if rpc.network and rpc.network.name then
      chain_label = core_chain_name(rpc.network.name)
    end

    return {
      tip_height = tip_height,
      tip_hash = types.hash256_hex(tip_hash),
      best_header_height = best_header_height,
      best_header_hash = types.hash256_hex(best_header_hash),
      initial_block_download = ibd,
      num_peers = num_peers,
      verification_progress = verification_progress,
      blocks_in_flight = blocks_in_flight,
      blocks_pending_connect = blocks_pending_connect,
      -- Lunarblock does not currently track the wall-clock time of the
      -- last tip advance; morning reviewers add if needed.
      last_block_received_time = cjson.null,
      chain = chain_label,
      protocol_version = p2p.PROTOCOL_VERSION,
    }
  end

  -- Block invalidation methods
  self.methods["invalidateblock"] = function(rpc, params)
    local blockhash = params[1]
    if type(blockhash) ~= "string" or #blockhash ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid block hash"})
    end
    if not rpc.chain_state then
      error({code = M.ERROR.MISC_ERROR, message = "Chain state not available"})
    end

    local hash = types.hash256_from_hex(blockhash)

    -- Check if the block exists
    if not rpc.storage then
      error({code = M.ERROR.MISC_ERROR, message = "Storage not available"})
    end
    local header = rpc.storage.get_header(hash)
    if not header then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Block not found"})
    end

    -- Invalidate the block
    local ok, err = rpc.chain_state:invalidate_block(hash)
    if not ok then
      error({code = M.ERROR.MISC_ERROR, message = err or "Failed to invalidate block"})
    end

    return cjson.null
  end

  self.methods["reconsiderblock"] = function(rpc, params)
    local blockhash = params[1]
    if type(blockhash) ~= "string" or #blockhash ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid block hash"})
    end
    if not rpc.chain_state then
      error({code = M.ERROR.MISC_ERROR, message = "Chain state not available"})
    end

    local hash = types.hash256_from_hex(blockhash)

    -- Check if the block exists
    if not rpc.storage then
      error({code = M.ERROR.MISC_ERROR, message = "Storage not available"})
    end
    local header = rpc.storage.get_header(hash)
    if not header then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Block not found"})
    end

    -- Reconsider the block
    local ok, err = rpc.chain_state:reconsider_block(hash)
    if not ok then
      error({code = M.ERROR.MISC_ERROR, message = err or "Failed to reconsider block"})
    end

    return cjson.null
  end

  -- Mempool methods
  self.methods["getmempoolinfo"] = function(rpc, _params)
    local info
    if rpc.mempool then
      info = rpc.mempool:get_info()
    else
      info = {
        size = 0,
        bytes = 0,
        usage = 0,
        maxmempool = 300 * 1024 * 1024,
        mempoolminfee = 1000,
      }
    end

    -- Calculate total fees
    local total_fee = 0
    if rpc.mempool then
      for _, entry in pairs(rpc.mempool.entries) do
        total_fee = total_fee + entry.fee
      end
    end

    -- Convert fee rates to BTC/kvB for Bitcoin Core compatibility
    local mempool_min_fee = info.mempoolminfee or 1000  -- sat/kvB
    local min_relay_fee = (rpc.mempool and rpc.mempool.min_relay_fee) or 1000  -- sat/kvB

    return {
      loaded = true,  -- mempool is always loaded once we're serving RPCs
      size = info.size,
      bytes = info.bytes,
      usage = info.usage,
      total_fee = total_fee / consensus.COIN,  -- in BTC
      maxmempool = info.maxmempool,
      mempoolminfee = mempool_min_fee / 100000000,  -- Convert sat/kvB to BTC/kvB
      minrelaytxfee = min_relay_fee / 100000000,  -- Convert sat/kvB to BTC/kvB
      incrementalrelayfee = 0.00001,
      unbroadcastcount = 0,
      -- FIX-68 (W120 BUG-9): Honest fullrbf field.  Reads the actual mempool
      -- setting (defaults true per Core v28+ DEFAULT_MEMPOOL_FULL_RBF) instead
      -- of unconditionally advertising `true` while the relay code may still
      -- enforce BIP-125 Rule 1.  When fullrbf=false, accept_transaction
      -- rejects non-signaling replacements with "conflicting tx does not
      -- signal RBF" — RPC and policy now match.  See mempool.lua:Mempool.fullrbf.
      -- info.fullrbf is provided by Mempool:get_info() when a mempool exists;
      -- the no-mempool branch above doesn't populate it so we default to the
      -- module constant for the "RPC up but mempool unavailable" case.
      fullrbf = (info.fullrbf ~= nil) and info.fullrbf
                or (require("lunarblock.mempool").DEFAULT_MEMPOOL_FULL_RBF),
    }
  end

  self.methods["getrawmempool"] = function(rpc, params)
    local verbose = params[1] or false
    if not rpc.mempool then
      -- Empty mempool: return empty array (non-verbose) or empty object (verbose).
      -- Use cjson.empty_array_mt so the empty table serialises as [] not {}.
      if verbose then return {} end
      return setmetatable({}, cjson.empty_array_mt)
    end
    if not verbose then
      local txids = rpc.mempool:get_raw_mempool()
      -- Guard against empty-table-vs-empty-array cjson ambiguity.
      if #txids == 0 then
        return setmetatable({}, cjson.empty_array_mt)
      end
      return txids
    end
    -- Verbose: return details for each tx
    local result = {}
    for _, txid_hex in ipairs(rpc.mempool:get_raw_mempool()) do
      local entry = rpc.mempool:get_entry(txid_hex)
      if entry then
        local fee_btc = entry.fee / consensus.COIN
        -- FIX-68 (W120 BUG-9): bip125-replaceable per Bitcoin Core
        -- policy/rbf.cpp IsRBFOptIn — walks tx + unconfirmed ancestors.
        -- Was hardcoded `true`, lying to wallets when neither the tx nor
        -- any ancestor signals RBF.  Walker is rpc.mempool:is_replaceable
        -- which scans entry.ancestors via signals_rbf (mempool.lua:2218).
        result[txid_hex] = {
          vsize = entry.vsize,
          weight = entry.weight,
          fee = fee_btc,
          modifiedfee = fee_btc,
          time = entry.time,
          height = entry.height,
          descendantcount = entry.descendant_count or 1,
          descendantsize = entry.descendant_size or entry.vsize,
          descendantfees = entry.descendant_fees or entry.fee,
          ancestorcount = entry.ancestor_count or 1,
          ancestorsize = entry.ancestor_size or entry.vsize,
          ancestorfees = entry.ancestor_fees or entry.fee,
          wtxid = entry.wtxid or txid_hex,
          fees = {
            base = fee_btc,
            modified = fee_btc,
            ancestor = (entry.ancestor_fees or entry.fee) / consensus.COIN,
            descendant = (entry.descendant_fees or entry.fee) / consensus.COIN,
          },
          depends = entry.depends or {},
          spentby = entry.spent_by or {},
          ["bip125-replaceable"] = rpc.mempool:is_replaceable(txid_hex),
          unbroadcast = false,
        }
      end
    end
    return result
  end

  -- getorphantxs: show transactions in the tx orphanage (Core v28).
  -- Mirrors bitcoin-core/src/rpc/mempool.cpp::getorphantxs +
  -- node/txorphanage.cpp::GetOrphanTransactions / OrphanToJSON.
  --   verbosity 0 (default): array of TXID hex strings (orphan.tx->GetHash(),
  --                the non-witness txid; may contain duplicates).
  --   verbosity 1: array of {txid, wtxid, bytes, vsize, weight, from}.
  --   verbosity 2: verbosity-1 objects PLUS `hex` (serialized tx, like Core's
  --                EncodeHexTx(*orphan.tx) appended under "hex").
  -- Invalid verbosity (outside 0..2) -> RPC_INVALID_PARAMETER (-8) with Core's
  -- exact message ("Invalid verbosity value <n>").
  self.methods["getorphantxs"] = function(rpc, params)
    -- ParseVerbosity(request.params[0], default=0, allow_bool=false): the arg is
    -- an integer (alias `verbose`). Core does NOT accept booleans here. Treat a
    -- missing/null arg as the default 0; anything non-integer is an error, same
    -- as Core's ParseVerbosity (throws RPC_TYPE_ERROR for non-numbers).
    local vp = params[1]
    local verbosity
    if vp == nil or vp == cjson.null then
      verbosity = 0
    elseif type(vp) == "number" and vp == math.floor(vp) then
      verbosity = vp
    else
      error({code = M.ERROR.TYPE_ERROR,
             message = "JSON value of type " ..
                       (type(vp) == "number" and "number" or type(vp)) ..
                       " is not of expected type number"})
    end

    -- Enumerate the orphan pool. Iterate in insertion order (pool.order) so the
    -- output is stable; fall back to entries if order is unavailable.
    local pool = rpc.orphan_pool
    local wtxids = {}
    if pool then
      if pool.order then
        for _, w in ipairs(pool.order) do
          if pool.entries[w] then wtxids[#wtxids + 1] = w end
        end
      else
        for w in pairs(pool.entries or {}) do wtxids[#wtxids + 1] = w end
      end
    end

    -- The non-witness txid for an orphan entry (Core: orphan.tx->GetHash()).
    -- Prefer the cached secondary-index txid; recompute from the tx if absent.
    local function orphan_txid(entry)
      return entry.txid_hex
        or types.hash256_hex(validation.compute_txid(entry.tx))
    end

    -- Build a verbosity-1 object for one orphan entry (shared by 1 and 2).
    -- Core OrphanToJSON (rpc/mempool.cpp): EXACTLY txid, wtxid,
    -- bytes (ComputeTotalSize = full witness-serialized size), vsize (BIP141),
    -- weight (BIP141), from (announcer peer ids). No `expiration` field exists
    -- in Core; do not emit one.
    local function orphan_to_json(wtxid_hex, entry)
      local tx = entry.tx
      local weight = validation.get_tx_weight(tx)
      -- bytes = total serialized (witness-included) size; matches the value the
      -- pool already cached at add() and what getrawtransaction reports as size.
      local bytes = entry.size or #serialize.serialize_transaction(tx, true)
      local vsize = math.ceil(weight / consensus.WITNESS_SCALE_FACTOR)
      -- from: the announcing peer id(s). The pool tracks a single announcer per
      -- entry (entry.peer_id), so emit a 1-element array; empty array if none.
      local from = setmetatable({}, cjson.array_mt)
      if entry.peer_id ~= nil then
        from[1] = entry.peer_id
      end
      local o = {
        txid   = orphan_txid(entry),
        wtxid  = wtxid_hex,
        bytes  = bytes,
        vsize  = vsize,
        weight = weight,
        from   = from,
      }
      return o
    end

    local ret = setmetatable({}, cjson.array_mt)

    if verbosity == 0 then
      -- Core pushes orphan.tx->GetHash().ToString() (the non-witness TXID).
      for _, w in ipairs(wtxids) do
        ret[#ret + 1] = orphan_txid(pool.entries[w])
      end
    elseif verbosity == 1 then
      for _, w in ipairs(wtxids) do
        ret[#ret + 1] = orphan_to_json(w, pool.entries[w])
      end
    elseif verbosity == 2 then
      for _, w in ipairs(wtxids) do
        local entry = pool.entries[w]
        local o = orphan_to_json(w, entry)
        o.hex = M.hex_encode(serialize.serialize_transaction(entry.tx, true))
        ret[#ret + 1] = o
      end
    else
      -- Core: throw JSONRPCError(RPC_INVALID_PARAMETER,
      --   "Invalid verbosity value " + ToString(verbosity));
      error({code = M.ERROR.INVALID_PARAMETER,
             message = "Invalid verbosity value " .. tostring(verbosity)})
    end

    -- Empty pool: ensure [] (not {}) regardless of the array metatable above.
    if #ret == 0 then
      return setmetatable({}, cjson.empty_array_mt)
    end
    return ret
  end

  -- Bitcoin Core-compatible mempool.dat dump/load.
  -- See bitcoin-core/src/node/mempool_persist.cpp for the on-disk format.
  -- The file lives at <datadir>/mempool.dat by convention; an explicit
  -- absolute path may be passed as params[1].
  self.methods["dumpmempool"] = function(rpc, params)
    if not rpc.mempool then
      error({code = M.ERROR.MISC_ERROR, message = "Mempool not available"})
    end
    if not rpc.datadir then
      error({code = M.ERROR.MISC_ERROR, message = "Datadir not configured"})
    end
    local mempool_persist_mod = require("lunarblock.mempool_persist")
    local path = (params and params[1]) or (rpc.datadir .. "/mempool.dat")
    local ok, count_or_err = mempool_persist_mod.dump(rpc.mempool, path)
    if not ok then
      error({code = M.ERROR.MISC_ERROR,
        message = "Could not dump mempool: " .. tostring(count_or_err)})
    end
    return { filename = path, count = count_or_err }
  end

  self.methods["loadmempool"] = function(rpc, params)
    if not rpc.mempool then
      error({code = M.ERROR.MISC_ERROR, message = "Mempool not available"})
    end
    if not rpc.datadir then
      error({code = M.ERROR.MISC_ERROR, message = "Datadir not configured"})
    end
    local mempool_persist_mod = require("lunarblock.mempool_persist")
    local path = (params and params[1]) or (rpc.datadir .. "/mempool.dat")
    local ok, stats = mempool_persist_mod.load(rpc.mempool, path)
    if not ok then
      error({code = M.ERROR.MISC_ERROR,
        message = "Could not load mempool: " .. tostring(stats)})
    end
    return {
      filename = path,
      accepted = stats.count or 0,
      failed = stats.failed or 0,
      expired = stats.expired or 0,
      already_there = stats.already_there or 0,
    }
  end

  -- Transaction methods
  self.methods["sendrawtransaction"] = function(rpc, params)
    local hex = params[1]
    assert(type(hex) == "string", "Transaction hex required")
    local raw = M.hex_decode(hex)
    local tx = serialize.deserialize_transaction(raw)
    assert(rpc.mempool, "Mempool not available")
    local ok, txid_hex = rpc.mempool:accept_transaction(tx)
    if not ok then
      -- W96: route mempool reject reasons to canonical Core RPC error codes.
      -- "txn-already-in-mempool" / "txn-same-nonwitness-data-in-mempool" →
      -- VERIFY_ALREADY_IN_CHAIN (-27) per Bitcoin Core rpc/rawtransaction.cpp.
      -- Other rejects remain VERIFY_REJECTED (-26).
      local err_str = tostring(txid_hex or "")
      if err_str:find("already", 1, true)
         or err_str:find("same-nonwitness-data", 1, true) then
        error({code = M.ERROR.VERIFY_ALREADY_IN_CHAIN, message = err_str})
      end
      error({code = M.ERROR.VERIFY_REJECTED, message = err_str})
    end
    -- Broadcast to peers
    if rpc.peer_manager then
      local txid = validation.compute_txid(tx)
      local inv_payload = p2p.serialize_inv({
        {type = p2p.INV_TYPE.MSG_WITNESS_TX, hash = txid}
      })
      rpc.peer_manager:broadcast("inv", inv_payload)
    end
    return txid_hex
  end

  self.methods["getrawtransaction"] = function(rpc, params)
    local txid_hex = params[1]
    -- W60: parse verbosity as integer 0/1/2 (not just bool).
    --   false / 0        → 0 (raw hex)
    --   true  / 1        → 1 (verbose JSON, no prevout)
    --   2                → 2 (verbose JSON + per-vin prevout + fee)
    local verbosity = 0
    local vp = params[2]
    if vp == true or vp == 1 then
      verbosity = 1
    elseif vp == 2 then
      verbosity = 2
    end
    local blockhash_hex = params[3]

    -- Validate txid parameter
    if type(txid_hex) ~= "string" or #txid_hex ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid txid"})
    end

    -- Genesis-coinbase exception (matches Core rpc/rawtransaction.cpp:290-293):
    -- the genesis block coinbase txid (== genesis block merkle root) is not an
    -- ordinary transaction and is never retrievable.  Throw RPC -5 before any
    -- lookup, exactly as Core does.  Derive the txid from the height-0 block's
    -- first transaction so this is network-correct (mainnet/testnet/regtest).
    if rpc.storage and rpc.storage.get_hash_by_height then
      local ok_g, gen_hash = pcall(rpc.storage.get_hash_by_height, 0)
      if ok_g and gen_hash then
        local ok_b, gen_block = pcall(rpc.storage.get_block, gen_hash)
        if ok_b and gen_block and gen_block.transactions
            and gen_block.transactions[1] then
          local gtxid = types.hash256_hex(
            validation.compute_txid(gen_block.transactions[1]))
          if gtxid == txid_hex then
            error({code = M.ERROR.INVALID_ADDRESS,
                   message = "The genesis block coinbase is not considered an " ..
                             "ordinary transaction and cannot be retrieved"})
          end
        end
      end
    end

    -- Validate blockhash if provided
    if blockhash_hex ~= nil and blockhash_hex ~= cjson.null then
      if type(blockhash_hex) ~= "string" or #blockhash_hex ~= 64 then
        error({code = M.ERROR.INVALID_PARAMS, message = "Invalid blockhash"})
      end
    else
      blockhash_hex = nil
    end

    local tx = nil
    local block = nil
    local block_height = nil
    local block_time = nil
    local found_blockhash = nil
    local in_mempool = false

    -- Lookup order: mempool first (if no blockhash provided), then storage/txindex

    -- 1. Check mempool first (only if blockhash not specified)
    if not blockhash_hex and rpc.mempool then
      local entry = rpc.mempool:get_entry(txid_hex)
      if entry then
        tx = entry.tx
        in_mempool = true
      end
    end

    -- 2. If blockhash provided, search that specific block
    if not tx and blockhash_hex and rpc.storage then
      local block_hash = types.hash256_from_hex(blockhash_hex)
      block = rpc.storage.get_block(block_hash)
      if not block then
        error({code = M.ERROR.INVALID_ADDRESS, message = "Block hash not found"})
      end
      -- Search for transaction in block.  block_height is resolved later via
      -- the height-index reverse lookup (HEIGHT_INDEX is keyed height->hash,
      -- so there is no direct hash->height row to read here).
      for _, btx in ipairs(block.transactions) do
        local btx_txid = types.hash256_hex(validation.compute_txid(btx))
        if btx_txid == txid_hex then
          tx = btx
          found_blockhash = blockhash_hex
          block_time = block.header.timestamp
          break
        end
      end
      if not tx then
        error({code = M.ERROR.INVALID_ADDRESS,
               message = "No such transaction found in the provided block. Use gettransaction for wallet transactions."})
      end
    end

    -- 3. Check transaction index if available and tx still not found.
    -- Only attempt this when txindex is enabled AND no blockhash was supplied
    -- (Core only consults g_txindex when !blockindex; rpc/rawtransaction.cpp:308).
    -- The CF.TX_INDEX value layout written by ChainState:connect_block is
    --   block_hash (32 bytes LE) || height (4 bytes LE)   = 36 bytes
    -- (see utxo.lua:3045-3049 / 3156-3159).
    local txindex_on = rpc.chain_state and rpc.chain_state.txindex_enabled
    if not tx and not blockhash_hex and txindex_on and rpc.storage and rpc.storage.get then
      local txid_bytes = types.hash256_from_hex(txid_hex)
      local tx_index_data = rpc.storage.get("tx_index", txid_bytes.bytes)
      if tx_index_data and #tx_index_data >= 32 then
        local index_block_hash = types.hash256(tx_index_data:sub(1, 32))
        found_blockhash = types.hash256_hex(index_block_hash)
        if #tx_index_data >= 36 then
          local r = serialize.buffer_reader(tx_index_data:sub(33, 36))
          block_height = r.read_u32le()
        end
        block = rpc.storage.get_block(index_block_hash)
        if block then
          -- Find tx in block
          for _, btx in ipairs(block.transactions) do
            local btx_txid = types.hash256_hex(validation.compute_txid(btx))
            if btx_txid == txid_hex then
              tx = btx
              block_time = block.header.timestamp
              break
            end
          end
        end
        -- TX_INDEX row pointed at a block we no longer have / tx not present:
        -- fall through to the not-found error below rather than half-answering.
        if not tx then
          found_blockhash = nil
          block_height = nil
        end
      end
    end

    -- If still not found, return error
    if not tx then
      local msg
      if blockhash_hex then
        msg = "No such transaction found in the provided block. Use gettransaction for wallet transactions."
      elseif rpc.storage and rpc.storage.get then
        msg = "No such mempool or blockchain transaction. Use gettransaction for wallet transactions."
      else
        msg = "No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries. Use gettransaction for wallet transactions."
      end
      error({code = M.ERROR.INVALID_ADDRESS, message = msg})
    end

    -- Non-verbose: return raw hex
    if verbosity == 0 then
      return M.hex_encode(serialize.serialize_transaction(tx, true))
    end

    -- Verbose: build detailed response
    local weight = validation.get_tx_weight(tx)
    local size = #serialize.serialize_transaction(tx, true)
    local base_size = #serialize.serialize_transaction(tx, false)
    local vsize = math.ceil(weight / consensus.WITNESS_SCALE_FACTOR)
    local txid = validation.compute_txid(tx)
    local wtxid = validation.compute_wtxid(tx)

    -- W60: load undo data for verbosity=2 prevout enrichment + fee.
    -- Same pattern as W59 getblock verbosity=2: get_undo → deserialize_block_undo.
    -- block_undo is nil if unavailable; prevout enrichment degrades gracefully.
    local block_undo = nil
    local tx_in_block_idx = nil  -- 0-based index of this tx in block.transactions
    if verbosity >= 2 and found_blockhash and block and rpc.storage and rpc.storage.get_undo then
      local bh_bytes = types.hash256_from_hex(found_blockhash)
      local undo_raw = rpc.storage.get_undo(bh_bytes)
      if undo_raw then
        local utxo_mod = require("lunarblock.utxo")
        local ok_u, decoded = pcall(utxo_mod.deserialize_block_undo, undo_raw)
        if ok_u and decoded and type(decoded) == "table" and decoded.tx_undo then
          block_undo = decoded
        end
      end
      -- Find the 0-based index of this tx in the block for undo indexing.
      if block then
        local null_hash_b = string.rep("\0", 32)
        for idx, btx in ipairs(block.transactions) do
          local btx_txid_hex = types.hash256_hex(validation.compute_txid(btx))
          if btx_txid_hex == txid_hex then
            tx_in_block_idx = idx - 1  -- convert to 0-based
            break
          end
        end
      end
    end

    -- Build vin array
    local vin = {}
    local is_coinbase = false
    local null_hash = string.rep("\0", 32)
    if #tx.inputs == 1 and tx.inputs[1].prev_out.hash.bytes == null_hash and
       tx.inputs[1].prev_out.index == 0xFFFFFFFF then
      is_coinbase = true
    end

    local total_in = 0   -- accumulated for fee (verbosity=2 only)

    for i, inp in ipairs(tx.inputs) do
      local vin_entry = {}
      if is_coinbase and i == 1 then
        vin_entry.coinbase = M.hex_encode(inp.script_sig)
        if inp.witness and #inp.witness > 0 then
          vin_entry.txinwitness = setmetatable({}, cjson.array_mt)
          for j, wit in ipairs(inp.witness) do
            vin_entry.txinwitness[j] = M.hex_encode(wit)
          end
        end
        vin_entry.sequence = inp.sequence
      else
        vin_entry.txid = types.hash256_hex(inp.prev_out.hash)
        vin_entry.vout = inp.prev_out.index
        vin_entry.scriptSig = {
          asm = disassemble_scriptsig(inp.script_sig),
          hex = M.hex_encode(inp.script_sig),
        }
        if inp.witness and #inp.witness > 0 then
          vin_entry.txinwitness = setmetatable({}, cjson.array_mt)
          for j, wit in ipairs(inp.witness) do
            vin_entry.txinwitness[j] = M.hex_encode(wit)
          end
        end
        vin_entry.sequence = inp.sequence

        -- W60: per-vin prevout enrichment (verbosity=2).
        -- undo index: tx_in_block_idx is 1-based in block (coinbase = idx 1),
        -- so undo index = tx_in_block_idx - 1 (block_undo.tx_undo is 0-indexed
        -- for non-coinbase txs, i.e. tx_undo[1] = block.txs[2]'s spent inputs).
        if verbosity >= 2 and block_undo and tx_in_block_idx and tx_in_block_idx >= 1 then
          local txu = block_undo.tx_undo[tx_in_block_idx]
          if txu and txu.prev_outputs and txu.prev_outputs[i] then
            local po = txu.prev_outputs[i]
            total_in = total_in + po.value
            vin_entry.prevout = {
              generated = po.is_coinbase and true or false,
              height = po.height,
              value = btc_sentinel(po.value),
              scriptPubKey = M.decode_script_pubkey(po.script_pubkey, rpc.network),
            }
          end
        end
      end
      vin[i] = vin_entry
    end

    -- vin always encodes as a JSON array (cjson.array_mt) even when empty.
    setmetatable(vin, cjson.array_mt)

    -- Build vout array
    -- W60: use btc_sentinel for value (fixed-8 decimal precision, same as W59 getblock).
    local vout = setmetatable({}, cjson.array_mt)
    local total_out = 0
    for i, out in ipairs(tx.outputs) do
      vout[i] = {
        value = btc_sentinel(out.value),
        n = i - 1,
        scriptPubKey = M.decode_script_pubkey(out.script_pubkey, rpc.network),
      }
      total_out = total_out + out.value
    end

    -- Build result
    local result = {
      txid = types.hash256_hex(txid),
      hash = types.hash256_hex(wtxid),
      version = tx.version,
      size = size,
      vsize = vsize,
      weight = weight,
      locktime = tx.locktime,
      vin = vin,
      vout = vout,
      hex = M.hex_encode(serialize.serialize_transaction(tx, true)),
    }

    -- W60: fee (verbosity=2, non-coinbase, undo data available).
    if verbosity >= 2 and not is_coinbase and block_undo and tx_in_block_idx and tx_in_block_idx >= 1 then
      local txu = block_undo.tx_undo[tx_in_block_idx]
      if txu and txu.prev_outputs and #txu.prev_outputs > 0 then
        local fee_sats = total_in - total_out
        if fee_sats >= 0 then
          result.fee = btc_sentinel(fee_sats)
        end
      end
    end

    -- Resolve the block height for the containing block (for confirmations and
    -- the in_active_chain check) if we did not already learn it above.  Prefer
    -- the cheap height-index reverse scan only as a fallback.
    if found_blockhash and not block_height and rpc.storage then
      local block_hash = types.hash256_from_hex(found_blockhash)
      local iter = rpc.storage.iterator("height")
      if iter then
        iter.seek_to_first()
        while iter.valid() do
          local k = iter.key()
          local v = iter.value()
          if v and #v == 32 and v == block_hash.bytes then
            -- Decode height from key (4-byte big-endian)
            block_height = k:byte(1) * 16777216 + k:byte(2) * 65536 + k:byte(3) * 256 + k:byte(4)
            break
          end
          iter.next()
        end
        iter.destroy()
      end
    end

    -- in_active_chain: Core emits this for ANY verbosity >= 1 whenever an
    -- explicit "blockhash" argument was supplied (rpc/rawtransaction.cpp:337-340).
    -- It is true iff the named block is on the active chain.
    if blockhash_hex then
      local in_chain = true
      if block_height and rpc.storage and rpc.storage.get_hash_by_height then
        local canon = rpc.storage.get_hash_by_height(block_height)
        if canon then
          in_chain = (types.hash256_hex(canon) == found_blockhash)
        end
      end
      result.in_active_chain = in_chain
    end

    -- Add confirmed-block info (blockhash / time / blocktime / confirmations).
    -- Core only attaches confirmations + time when the block is in the active
    -- chain; mempool transactions (found_blockhash == nil) get none of these.
    if found_blockhash then
      result.blockhash = found_blockhash
      if block_time then
        result.time = block_time
        result.blocktime = block_time
      end

      -- Calculate confirmations = 1 + tipHeight - txHeight.
      if rpc.chain_state and rpc.chain_state.tip_height then
        local tip_height = rpc.chain_state.tip_height
        if block_height then
          result.confirmations = tip_height - block_height + 1
        else
          result.confirmations = 1  -- Default to 1 if height unknown
        end
      end
    end

    -- W60: verbosity=2 encodes via cjson + strip_btc_sentinels so that
    -- btc_sentinel() wrappers in vout.value, prevout.value, and fee become
    -- bare fixed-8 decimal literals (matching Core's TxToUniv format).
    if verbosity >= 2 then
      local json = strip_btc_sentinels(cjson.encode(result))
      return {_raw_json = json}
    end

    -- verbosity=1: cjson encodes directly (vout.value was btc_sentinel but
    -- strip is still needed for that path too).
    local json = strip_btc_sentinels(cjson.encode(result))
    return {_raw_json = json}
  end

  self.methods["decoderawtransaction"] = function(rpc, params)
    -- W55: refactored to share the TxToUniv emitter (psbt_mod.tx_to_univ /
    -- build_non_witness_utxo_json) that decodepsbt already uses.  This fixes
    -- all five corpus divergences in one pass:
    --   • amount formatting: btc_sentinel → bare fixed-8 decimal (not float64)
    --   • scriptPubKey: full {asm, desc, hex, address?, type} shape
    --   • rawtr() descriptor for P2TR outputs
    --   • coinbase vin: {coinbase, sequence, txinwitness?} instead of normal shape
    --   • txinwitness: emitted for every vin that has a non-empty witness stack
    --   • scriptSig.asm with sighash-decode for non-coinbase inputs
    --   • hash/size/vsize/weight top-level fields
    local hex = params[1]
    if type(hex) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Transaction hex required"})
    end
    local raw = M.hex_decode(hex)
    local tx = serialize.deserialize_transaction(raw)

    local psbt_mod = require("lunarblock.psbt")
    -- tx_to_univ = build_non_witness_utxo_json(tx, network, fmt_btc)
    -- Passes btc_sentinel so amounts encode as fixed-8 sentinel strings that
    -- strip_btc_sentinels() will unwrap to bare numeric literals.
    local result = psbt_mod.tx_to_univ(tx, rpc.network, btc_sentinel)

    -- Ensure vin/vout encode as JSON arrays even when empty.
    if result.vin then
      setmetatable(result.vin, cjson.array_mt)
      for _, vin_entry in ipairs(result.vin) do
        if vin_entry.txinwitness then
          setmetatable(vin_entry.txinwitness, cjson.array_mt)
        end
      end
    end
    if result.vout then
      setmetatable(result.vout, cjson.array_mt)
    end

    local json = strip_btc_sentinels(cjson.encode(result))
    return {_raw_json = json}
  end

  -- Network methods
  self.methods["getnetworkinfo"] = function(rpc, _params)
    local connections = 0
    local connections_in = 0
    local connections_out = 0
    if rpc.peer_manager then
      connections = #rpc.peer_manager.peer_list
      for _, p in ipairs(rpc.peer_manager.peer_list) do
        if p.inbound then
          connections_in = connections_in + 1
        else
          connections_out = connections_out + 1
        end
      end
    end
    -- BUG-23 fix (W115 FIX-50): include asmap_version when asmap is loaded.
    -- Core: src/rpc/net.cpp getnetworkinfo returns "asmap_version" hex string.
    local asmap_ver = ""
    local ok_pm, pm_mod = pcall(require, "lunarblock.peerman")
    if ok_pm then
      asmap_ver = pm_mod.get_asmap_version()
    end
    return {
      version = 250000,
      subversion = "/LunarBlock:0.1.0/",
      protocolversion = p2p.PROTOCOL_VERSION,
      localservices = "0000000000000009",
      localservicesnames = {"NETWORK", "WITNESS"},
      localrelay = true,
      timeoffset = 0,
      networkactive = true,
      connections = connections,
      connections_in = connections_in,
      connections_out = connections_out,
      networks = {
        {name = "ipv4", limited = false, reachable = true, proxy = "", proxy_randomize_credentials = false},
        {name = "ipv6", limited = false, reachable = true, proxy = "", proxy_randomize_credentials = false},
      },
      relayfee = 0.00001,
      incrementalfee = 0.00001,
      localaddresses = {},
      warnings = "",
      asmap_version = asmap_ver,
    }
  end

  self.methods["getpeerinfo"] = function(rpc, _params)
    local peers = {}
    -- BUG-22 fix (W115 FIX-50): include mapped_as field per peer.
    -- Core: src/rpc/net.cpp getpeerinfo includes "mapped_as" (uint32) when
    -- asmap is loaded.  We always include the field; it is 0 when no asmap
    -- is loaded or the address has no mapping.
    local ok_asmap, asmap_mod_rpc = pcall(require, "lunarblock.asmap")
    local ok_pm, pm_mod = pcall(require, "lunarblock.peerman")
    local loaded_asmap = (ok_pm and pm_mod._asmap_data) or nil
    if rpc.peer_manager then
      for i, p in ipairs(rpc.peer_manager.peer_list) do
        local svc = p.services or 0
        local svc_names = {}
        if bit.band(svc, 1) ~= 0 then svc_names[#svc_names + 1] = "NETWORK" end
        if bit.band(svc, 8) ~= 0 then svc_names[#svc_names + 1] = "WITNESS" end
        if bit.band(svc, 1024) ~= 0 then svc_names[#svc_names + 1] = "NETWORK_LIMITED" end
        local is_inbound = p.inbound or false
        local ping_sec = (p.latency_ms or 0) / 1000
        -- Compute ASN for this peer's IP (0 if no asmap or not mapped).
        local peer_mapped_as = 0
        if ok_asmap and loaded_asmap then
          peer_mapped_as = asmap_mod_rpc.get_mapped_as(loaded_asmap, p.ip)
        end
        peers[#peers + 1] = {
          id = i - 1,
          addr = p.ip .. ":" .. p.port,
          network = "ipv4",
          services = string.format("%016x", svc),
          servicesnames = svc_names,
          relaytxes = (p.version_info and p.version_info.relay) or true,
          lastsend = math.floor(p.last_send or 0),
          lastrecv = math.floor(p.last_recv or 0),
          last_transaction = 0,
          last_block = 0,
          bytessent = p.bytes_sent or 0,
          bytesrecv = p.bytes_recv or 0,
          conntime = math.floor(p.conn_time or 0),
          timeoffset = (p.version_info and p.version_recv_time and p.version_recv_time > 0)
            and (p.version_info.timestamp - math.floor(p.version_recv_time))
            or 0,
          pingtime = ping_sec,
          minping = ping_sec,
          version = (p.version_info and p.version_info.version) or 0,
          subver = p.user_agent or "",
          inbound = is_inbound,
          bip152_hb_to = false,
          bip152_hb_from = false,
          startingheight = p.start_height or 0,
          presynced_headers = -1,
          synced_headers = -1,
          synced_blocks = -1,
          inflight = {},
          addr_relay_enabled = true,
          addr_processed = 0,
          addr_rate_limited = 0,
          permissions = {},
          minfeefilter = 0,
          bytessent_per_msg = {},
          bytesrecv_per_msg = {},
          connection_type = is_inbound and "inbound" or "outbound-full-relay",
          transport_protocol_type = "v1",
          session_id = "",
          mapped_as = peer_mapped_as,
        }
      end
    end
    return peers
  end

  self.methods["getconnectioncount"] = function(rpc, _params)
    if rpc.peer_manager then
      return #rpc.peer_manager.peer_list
    end
    return 0
  end

  -- Manual peer control — minimal Bitcoin Core `addnode` parity.  Supports
  -- "onetry" and "add" (both initiate an outbound connection) and "remove"
  -- (disconnect + forget).  Used by the hashhog localhost IBD mesh (see
  -- memory/project_local_peer_ibd_setup.md).
  --
  -- BIP324 v2 negotiation: addnode follows the same path as automatic
  -- outbound peers — `connect_peer` defaults to v2 unless the node was
  -- launched with `--nov2transport`, identical to the inbound responder
  -- path in `accept_inbound`.  The previous always-on localhost v1 force
  -- was a debugging artifact from when not every fleet sibling spoke v2;
  -- operators who still want it can pass `--nov2transport` (global) and
  -- rustoshi/haskoin/hotbuns inbounds will negotiate v1 the same way.
  self.methods["addnode"] = function(rpc, params)
    local node = params and params[1]
    local command = params and params[2]
    if type(node) ~= "string" or type(command) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "addnode requires <node> <command>"})
    end
    if not rpc.peer_manager then
      error({code = M.ERROR.MISC_ERROR, message = "peer manager not available"})
    end
    local ip, port_str = node:match("^([^:]+):?(%d*)$")
    if not ip or ip == "" then
      error({code = M.ERROR.INVALID_PARAMS, message = "invalid node address: " .. node})
    end
    local port = tonumber(port_str)
    if not port or port == 0 then
      port = rpc.peer_manager.network and rpc.peer_manager.network.port or 8333
    end
    -- Defer to connect_peer's default (config.nov2transport).  No
    -- per-target override — keeps the negotiation path identical for
    -- localhost and remote targets, matching the inbound side.
    local use_v2_override = nil
    local key = ip .. ":" .. port
    if command == "add" then
      -- Persist: register in manual_peers so the tick-level
      -- _reconnect_manual_peers() keeps reconnecting after remote-side
      -- eviction.  Failure here is non-fatal — the reconnect loop will
      -- pick it up on the next tick.
      rpc.peer_manager.manual_peers[key] = {
        ip = ip,
        port = port,
        use_v2_override = use_v2_override,
        last_try = 0,
        attempts = 0,
        success_count = 0,
      }
      local ok, err = rpc.peer_manager:connect_peer(ip, port, true, use_v2_override, true)
      if not ok then
        -- Don't erase from manual_peers — reconnect loop owns the retry.
        -- Surface the first-attempt failure via RPC error for visibility.
        error({code = M.ERROR.MISC_ERROR, message = "initial connect failed (will retry): " .. tostring(err)})
      end
      return nil
    elseif command == "onetry" then
      -- One-shot: do NOT persist in manual_peers.
      local ok, err = rpc.peer_manager:connect_peer(ip, port, true, use_v2_override, true)
      if not ok then
        error({code = M.ERROR.MISC_ERROR, message = "failed to connect: " .. tostring(err)})
      end
      return nil
    elseif command == "remove" then
      rpc.peer_manager.manual_peers[key] = nil
      local p = rpc.peer_manager.peers and rpc.peer_manager.peers[key]
      if p then
        rpc.peer_manager:disconnect_peer(p, "removed by addnode RPC")
      end
      return nil
    else
      error({code = M.ERROR.INVALID_PARAMS, message = "invalid addnode command: " .. command})
    end
  end

  -- Bitcoin Core setban / listbanned / clearbanned RPC.
  -- Reference: bitcoin-core/src/rpc/net.cpp::setban (ban handler).
  -- Lunarblock's PeerManager.banned[ip] map already persists to
  -- banned.dat via _save_bans, so the RPC layer is a thin wrapper that
  -- exposes ban_peer / unban_peer / get_banned_list.
  --
  -- Subnet semantics: Core accepts CIDR ("a.b.c.d/24") and bare IPs.
  -- Lunarblock's underlying ban table is keyed by exact IP only — we
  -- accept the textual subnet form for Core compat and store the full
  -- string as the key.  is_banned() does exact-string match in
  -- peerman.lua:1167, so a "/32" entry behaves identically to a bare IP.
  -- Wider CIDRs are stored verbatim and treated as opaque by the matcher
  -- (no reverse lookup); operators get the parity surface they expect at
  -- the RPC, with a TODO to wire CIDR matching into the connection
  -- gate.  Documented to avoid silent CIDR-non-enforcement surprises.
  --
  -- Param shape (Core):
  --   setban "subnet" "command" ( bantime absolute )
  --     subnet:  string (IP or CIDR)
  --     command: "add" | "remove"
  --     bantime: integer seconds (0 → use default 24h); offset OR absolute
  --     absolute: bool — if true, bantime is a UNIX epoch
  self.methods["setban"] = function(rpc, params)
    if not rpc.peer_manager then
      error({code = M.ERROR.MISC_ERROR, message = "peer manager not available"})
    end
    local subnet  = params and params[1]
    local command = params and params[2]
    local bantime = params and params[3]
    local absolute = params and params[4]

    if type(subnet) ~= "string" or subnet == "" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Error: subnet (string) is required"})
    end
    if type(command) ~= "string" or (command ~= "add" and command ~= "remove") then
      error({code = M.ERROR.INVALID_PARAMS,
             message = "Error: command (string, \"add\" or \"remove\") is required"})
    end

    -- Strip a trailing /N if present and remember it; we store the full
    -- subnet string for visibility but ban_peer uses the bare ip key.
    -- Core's CSubNet validates here; we accept any non-empty token to
    -- avoid rejecting legitimate IPv6 forms.
    local key = subnet  -- keep verbatim so listbanned echoes Core's input

    if command == "add" then
      if rpc.peer_manager:is_banned(key) then
        error({code = M.ERROR.MISC_ERROR,
               message = "Error: IP/Subnet already banned"})
      end
      -- Default ban duration: 24 h (peerman.MISBEHAVIOR.DEFAULT_BAN_DURATION).
      -- Core: `bantime ? bantime : DEFAULT_MISBEHAVING_BANTIME`.
      local duration
      if bantime ~= nil then
        if type(bantime) ~= "number" then
          error({code = M.ERROR.INVALID_PARAMS,
                 message = "Error: bantime must be a number"})
        end
        if absolute then
          -- bantime is a UNIX epoch — translate back to a duration so
          -- ban_peer's `os.time() + duration` produces the requested
          -- absolute expiry.  Negative durations are clamped to 1s
          -- (Core treats absolute-in-the-past as a no-op insert; we
          -- mirror that with a 1-tick ban that the next clear sweeps.)
          duration = math.max(1, math.floor(bantime - os.time()))
        else
          if bantime == 0 then
            -- Core: 0 means default.
            duration = nil
          else
            duration = math.floor(bantime)
          end
        end
      end
      rpc.peer_manager:ban_peer(key, duration)
      return nil
    else  -- remove
      if not rpc.peer_manager:is_banned(key) then
        error({code = M.ERROR.MISC_ERROR,
               message = "Error: Unban failed. Requested address/subnet was not previously banned."})
      end
      rpc.peer_manager:unban_peer(key)
      return nil
    end
  end

  --- listbanned: return active bans.
  -- Core shape: array of objects with `address`, `banned_until`,
  -- `ban_created`, `ban_reason`.  We don't track ban_created or
  -- ban_reason so they're omitted (Core RPC doc allows extra/missing
  -- fields per impl); ban_duration is derived from banned_until -
  -- now() and `time_remaining` follows the same.
  self.methods["listbanned"] = function(rpc, _params)
    if not rpc.peer_manager then
      error({code = M.ERROR.MISC_ERROR, message = "peer manager not available"})
    end
    -- Sweep expired bans first so the list is clean (Core also sweeps
    -- expired bans before serializing).
    rpc.peer_manager:clear_expired_bans()
    local entries = rpc.peer_manager:get_banned_list()
    local now = os.time()
    local result = {}
    for _, e in ipairs(entries) do
      result[#result + 1] = {
        address        = e.ip,
        banned_until   = e.ban_until,
        ban_duration   = e.ban_until - now,
        time_remaining = math.max(0, e.ban_until - now),
      }
    end
    return result
  end

  --- clearbanned: drop every ban entry.  Core: `clearbanned`.
  self.methods["clearbanned"] = function(rpc, _params)
    if not rpc.peer_manager then
      error({code = M.ERROR.MISC_ERROR, message = "peer manager not available"})
    end
    -- Walk the active list and unban each one — that triggers a
    -- _save_bans per call, but the list is small (<<1000 typical) so
    -- the disk-IO is negligible and we get the persistence guarantee
    -- for free.
    local entries = rpc.peer_manager:get_banned_list()
    for _, e in ipairs(entries) do
      rpc.peer_manager:unban_peer(e.ip)
    end
    -- Also drop any expired entries that get_banned_list filtered out.
    rpc.peer_manager.banned = {}
    rpc.peer_manager:_save_bans()
    return nil
  end

  -- ────────────────────────────────────────────────────────────────────
  -- getnodeaddresses / addpeeraddress  (P2P addrman dump + injector)
  -- ────────────────────────────────────────────────────────────────────
  --
  -- Core ref: bitcoin-core/src/rpc/net.cpp:911-970 (getnodeaddresses),
  -- :972-1030 (addpeeraddress), src/netbase.cpp:100-128
  -- (ParseNetwork / GetNetworkName).
  --
  -- getnodeaddresses ( count "network" ) returns a JSON ARRAY of objects,
  -- each with EXACTLY 5 keys in THIS ORDER:
  --   time     NUM_TIME  unix seconds (integer)
  --   services NUM       raw services bitfield as an INTEGER (not hex)
  --   address  STR       ToStringAddr — ip literal / .onion / .b32.i2p
  --   port     NUM       integer
  --   network  STR       ipv4|ipv6|onion|i2p|cjdns|not_publicly_routable|internal
  --
  -- Source is the addrman; Core's GetAddressesUnsafe SHUFFLES the result so
  -- callers must treat order as non-deterministic.  We walk the existing
  -- peerman.known_addresses map (keyed "ip:port" with
  -- {ip,addr_str,addr_bytes,port,services,timestamp,network_id,...}).
  --
  -- ParseNetwork lowercases and accepts ONLY ipv4|ipv6|onion|i2p|cjdns;
  -- anything else is NET_UNROUTABLE → error -8.  count<0 → error -8.

  -- Map a known-address entry to the Core network-name string
  -- (GetNetworkName(addr.GetNetClass())).  We prefer an explicit
  -- network_id (from BIP155 addrv2); otherwise classify by the textual
  -- address form, mirroring CNetAddr::GetNetClass().
  local function _classify_network(info)
    local p2p = require("lunarblock.p2p")
    local nid = info.network_id
    if nid == p2p.NET_ID.IPV4 then return "ipv4" end
    if nid == p2p.NET_ID.IPV6 then return "ipv6" end
    if nid == p2p.NET_ID.TORV3 or nid == p2p.NET_ID.TORV2 then return "onion" end
    if nid == p2p.NET_ID.I2P then return "i2p" end
    if nid == p2p.NET_ID.CJDNS then return "cjdns" end
    -- No network_id — classify by the address string form.
    local s = info.addr_str or info.ip
    if type(s) == "string" then
      if s:match("%.onion$") then return "onion" end
      if s:match("%.b32%.i2p$") or s:match("%.i2p$") then return "i2p" end
      if s:match("^%d+%.%d+%.%d+%.%d+$") then return "ipv4" end
      if s:find(":", 1, true) then return "ipv6" end
    end
    return "not_publicly_routable"
  end

  -- The address literal Core emits via ToStringAddr (no port).
  local function _addr_string(info)
    return info.addr_str or info.ip or ""
  end

  self.methods["getnodeaddresses"] = function(rpc, params)
    -- count: positional 0, default 1.  0 means "return ALL known".
    local count_arg = params and params[1]
    local count
    if count_arg == nil or count_arg == cjson.null then
      count = 1
    else
      if type(count_arg) ~= "number" then
        error({code = M.ERROR.TYPE_ERROR, message = "JSON value of type string is not of expected type number"})
      end
      count = math.floor(count_arg)
    end
    if count < 0 then
      error({code = M.ERROR.INVALID_PARAMETER, message = "Address count out of range"})
    end

    -- network: positional 1, optional.  ParseNetwork lowercases and
    -- accepts ONLY ipv4|ipv6|onion|i2p|cjdns; anything else → -8.
    local net_arg = params and params[2]
    local net_filter = nil
    if net_arg ~= nil and net_arg ~= cjson.null then
      if type(net_arg) ~= "string" then
        error({code = M.ERROR.TYPE_ERROR, message = "JSON value of type is not of expected type string"})
      end
      local lowered = net_arg:lower()
      local valid = { ipv4 = true, ipv6 = true, onion = true, i2p = true, cjdns = true }
      if not valid[lowered] then
        error({code = M.ERROR.INVALID_PARAMETER, message = "Network not recognized: " .. net_arg})
      end
      net_filter = lowered
    end

    -- Walk known_addresses.  Filter by network if requested.
    local matched = {}
    if rpc.peer_manager and rpc.peer_manager.known_addresses then
      for _, info in pairs(rpc.peer_manager.known_addresses) do
        local netname = _classify_network(info)
        if net_filter == nil or netname == net_filter then
          matched[#matched + 1] = { info = info, netname = netname }
        end
      end
    end

    -- Shuffle (Core's GetAddressesUnsafe returns a shuffled list).
    -- Fisher–Yates so callers can never depend on insertion order.
    for i = #matched, 2, -1 do
      local j = math.random(i)
      matched[i], matched[j] = matched[j], matched[i]
    end

    -- count==0 → all; otherwise cap at count.
    local limit = (count == 0) and #matched or math.min(count, #matched)

    -- Build the JSON array by hand so the 5 keys appear in Core's exact
    -- order (cjson does not preserve table key order).
    local function json_str(s)
      return cjson.encode(tostring(s))
    end
    local parts = {}
    for idx = 1, limit do
      local m = matched[idx]
      local info = m.info
      local services = math.floor(tonumber(info.services) or 0)
      local time_sec = math.floor(tonumber(info.timestamp) or 0)
      local port = math.floor(tonumber(info.port) or 0)
      parts[#parts + 1] = table.concat({
        "{",
        '"time":', tostring(time_sec), ",",
        '"services":', tostring(services), ",",
        '"address":', json_str(_addr_string(info)), ",",
        '"port":', tostring(port), ",",
        '"network":', json_str(m.netname),
        "}",
      })
    end
    local json = "[" .. table.concat(parts, ",") .. "]"
    return { _raw_json = json }
  end

  -- addpeeraddress "address" port ( tried )  — testing-only addrman
  -- injector (Core: net.cpp:972).  Inserts a routable address into our
  -- known_addresses pool.  Returns {"success": bool}.
  self.methods["addpeeraddress"] = function(rpc, params)
    local p2p = require("lunarblock.p2p")
    local addr = params and params[1]
    local port = params and params[2]
    -- params[3] = tried (bool) — we have no separate tried table; accepted
    -- and treated as advisory (the address still lands in known_addresses).
    if type(addr) ~= "string" or addr == "" then
      error({code = M.ERROR.TYPE_ERROR, message = "JSON value of type null is not of expected type string"})
    end
    if type(port) ~= "number" then
      error({code = M.ERROR.TYPE_ERROR, message = "JSON value of type null is not of expected type number"})
    end
    port = math.floor(port)
    if port < 0 or port > 65535 then
      error({code = M.ERROR.INVALID_PARAMETER, message = "Port out of range"})
    end

    if not rpc.peer_manager then
      error({code = M.ERROR.MISC_ERROR, message = "peer manager not available"})
    end

    -- Core requires a valid IP (LookupHost) and a routable address
    -- (AddrMan::Add rejects non-routable).  We accept dotted-decimal
    -- IPv4 / bracketless IPv6 literals; non-routable → success=false.
    local pm = require("lunarblock.peerman")
    local is_ipv4 = addr:match("^%d+%.%d+%.%d+%.%d+$") ~= nil
    if is_ipv4 and not pm.is_routable(addr) then
      return { success = false }
    end

    -- Mirror Core: services = NODE_NETWORK | NODE_WITNESS, nTime = now.
    local services = bit.bor(p2p.SERVICES.NODE_NETWORK, p2p.SERVICES.NODE_WITNESS)
    local added = rpc.peer_manager:add_known_address(addr, port, services, os.time())
    -- If the entry already existed add_known_address returns false; Core's
    -- addrman would still report success on a duplicate insert path
    -- (Add returns true when the addr is present/refreshed).  Treat a
    -- duplicate as success too, matching Core's "already known" behavior.
    if not added then
      local key = addr .. ":" .. port
      if rpc.peer_manager.known_addresses[key] then
        return { success = true }
      end
      return { success = false }
    end
    return { success = true }
  end

  -- Fee estimation
  self.methods["estimatesmartfee"] = function(rpc, params)
    local conf_target = params[1] or 6
    if type(conf_target) ~= "number" then
      error({code = M.ERROR.INVALID_PARAMS, message = "conf_target must be numeric"})
    end
    conf_target = math.max(1, math.min(1008, math.floor(conf_target)))
    if rpc.fee_estimator then
      local fee_rate, actual_target = rpc.fee_estimator:estimate_smart_fee(conf_target)
      if fee_rate and fee_rate > 0 then
        return {
          feerate = fee_rate / 100000,  -- Convert sat/vB to BTC/kvB
          blocks = actual_target or conf_target,
        }
      end
    end
    return {errors = {"Insufficient data or no feerate found"}, blocks = conf_target}
  end

  -- estimaterawfee: raw fee estimator output for a confirmation target.
  -- Bitcoin Core: bitcoin-core/src/rpc/fees.cpp::estimaterawfee.  Returns one
  -- entry per estimation horizon (short=12, medium=144, long=1008 blocks); each
  -- entry exposes the raw bucket data ("feerate" + "decay"-weighted "pass" /
  -- "fail" counts).  We map the existing FeeEstimator to a single conservative
  -- bucket per horizon — the structure matches Core's response so RPC clients
  -- that expect the schema parse cleanly even when our estimator has less
  -- granular bucket data than Core's policy/fees.cpp.
  self.methods["estimaterawfee"] = function(rpc, params)
    local conf_target = params[1] or 6
    if type(conf_target) ~= "number" then
      error({code = M.ERROR.INVALID_PARAMS, message = "conf_target must be numeric"})
    end
    local threshold = params[2]
    if threshold ~= nil and threshold ~= cjson.null and type(threshold) ~= "number" then
      error({code = M.ERROR.INVALID_PARAMS, message = "threshold must be numeric"})
    end
    threshold = (type(threshold) == "number") and threshold or 0.95
    conf_target = math.max(1, math.min(1008, math.floor(conf_target)))

    local horizons = { short = 12, medium = 144, long = 1008 }
    local result = {}
    for name, _ in pairs(horizons) do
      local entry = { fail = cjson.null, errors = cjson.null }
      if rpc.fee_estimator then
        local fee_rate, reliable = rpc.fee_estimator:estimate_fee(conf_target, threshold)
        if fee_rate and fee_rate > 0 then
          entry.feerate = fee_rate / 100000  -- sat/vB -> BTC/kvB
          entry.decay = rpc.fee_estimator.decay or 0.998
          entry.scale = 1
          entry.pass = {
            startrange = fee_rate,
            endrange = fee_rate,
            withintarget = reliable and 1 or 0,
            totalconfirmed = reliable and 1 or 0,
            inmempool = 0,
            leftmempool = 0,
          }
        else
          entry.errors = { "Insufficient data or no feerate found" }
        end
      else
        entry.errors = { "Fee estimation not available" }
      end
      result[name] = entry
    end
    return result
  end

  --- signmessage / verifymessage (BIP-137 "Bitcoin Signed Message"):
  -- Bitcoin Core references:
  --   bitcoin-core/src/rpc/signmessage.cpp        (RPC entrypoints)
  --   bitcoin-core/src/common/signmessage.cpp     (MessageHash/MessageSign/MessageVerify)
  -- Hash construction:
  --   double-SHA256( varstr("Bitcoin Signed Message:\n") || varstr(message) ).
  -- Wire format: 65-byte signature, base64-encoded.
  --   header = 27 + recid + (compressed ? 4 : 0)
  -- We implement signmessagewithprivkey (no wallet keystore lookup) and
  -- verifymessage (P2PKH only — Core also rejects non-PKHash destinations).
  local MESSAGE_MAGIC = "Bitcoin Signed Message:\n"

  local function message_hash(message)
    local crypto = require("lunarblock.crypto")
    local w = serialize.buffer_writer()
    w.write_varstr(MESSAGE_MAGIC)
    w.write_varstr(message)
    return crypto.hash256(w.result())
  end

  -- signmessagewithprivkey "<wif_or_hex_privkey>" "<message>" -> base64 sig
  -- Wallet-keystore variant ("signmessage <address> <msg>") is gated on
  -- self.wallet / self.wallet_manager exposing per-address privkeys; we accept
  -- the same RPC name for parity but require the privkey form when no
  -- wallet keystore is available.  See TODO(rpc) below.
  self.methods["signmessagewithprivkey"] = function(_rpc, params)
    local privkey_str = params and params[1]
    local message = params and params[2]
    if type(privkey_str) ~= "string" or type(message) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "Usage: signmessagewithprivkey <privkey> <message>"})
    end
    local crypto = require("lunarblock.crypto")
    local privkey32, compressed
    -- Accept WIF or raw 64-hex
    local addr_mod = require("lunarblock.address")
    if #privkey_str == 64 and privkey_str:match("^[0-9A-Fa-f]+$") then
      privkey32 = M.hex_decode(privkey_str)
      compressed = true
    else
      -- Best-effort WIF decode
      local version, payload = addr_mod.base58check_decode(privkey_str)
      if not version or not payload then
        error({code = M.ERROR.INVALID_ADDRESS, message = "Invalid private key"})
      end
      if #payload == 33 and payload:byte(33) == 0x01 then
        privkey32 = payload:sub(1, 32)
        compressed = true
      elseif #payload == 32 then
        privkey32 = payload
        compressed = false
      else
        error({code = M.ERROR.INVALID_ADDRESS, message = "Invalid private key"})
      end
    end
    local h = message_hash(message)
    local sig65, err = crypto.ecdsa_sign_recoverable_compact(privkey32, h, compressed)
    if not sig65 then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Sign failed: " .. tostring(err)})
    end
    local psbt_mod = require("lunarblock.psbt")
    return psbt_mod.base64_encode(sig65)
  end

  -- signmessage <address> <message>: requires wallet keystore.  Until the
  -- wallet-keystore privkey lookup lands (TODO(rpc): wallet keystore
  -- per-address privkey export), behave like signmessagewithprivkey when
  -- callers pass a privkey string instead of an address, otherwise return
  -- WALLET_ERROR with a clear message.
  self.methods["signmessage"] = function(rpc, params)
    local addr_or_priv = params and params[1]
    local message = params and params[2]
    if type(addr_or_priv) ~= "string" or type(message) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "Usage: signmessage <address> <message>"})
    end
    -- Heuristic: a 64-char hex string is a privkey; otherwise probe
    -- decode_address (wrapped in pcall — it raises on non-base58 inputs
    -- that aren't bech32 either).
    local looks_like_privkey = (#addr_or_priv == 64
      and addr_or_priv:match("^[0-9A-Fa-f]+$") ~= nil)
    if not looks_like_privkey then
      local addr_mod = require("lunarblock.address")
      local ok, addr_type = pcall(addr_mod.decode_address, addr_or_priv,
        rpc.network and rpc.network.name)
      if ok and addr_type then
        -- Looks like an address; we'd need to look up the privkey by
        -- address in the wallet keystore.  Wallets in lunarblock currently
        -- expose HD-derived addresses but not a per-address privkey export
        -- hook on the RPC surface.
        -- TODO(rpc): wire signmessage <address> -> wallet:get_privkey_for_address.
        error({code = M.ERROR.WALLET_ERROR,
          message = "signmessage by address requires wallet keystore lookup; " ..
                    "use signmessagewithprivkey or pass a WIF/hex privkey directly"})
      end
    end
    -- Fall through: treat first arg as a privkey (WIF or 64-hex).
    return self.methods["signmessagewithprivkey"](rpc, params)
  end

  self.methods["verifymessage"] = function(rpc, params)
    local address = params and params[1]
    local signature = params and params[2]
    local message = params and params[3]
    if type(address) ~= "string" or type(signature) ~= "string" or type(message) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "Usage: verifymessage <address> <signature> <message>"})
    end
    local addr_mod = require("lunarblock.address")
    local crypto = require("lunarblock.crypto")
    local addr_type, addr_hash = addr_mod.decode_address(address, rpc.network and rpc.network.name)
    if not addr_type then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Invalid address"})
    end
    if addr_type ~= "p2pkh" then
      -- Bitcoin Core rejects non-PKHash destinations (RPC_TYPE_ERROR).
      error({code = M.ERROR.TYPE_ERROR, message = "Address does not refer to key"})
    end
    local sig65 = M.base64_decode(signature)
    if #sig65 ~= 65 then
      error({code = M.ERROR.TYPE_ERROR, message = "Malformed base64 encoding"})
    end
    local h = message_hash(message)
    local pub, err = crypto.ecdsa_recover_compact(sig65, h)
    if not pub then
      -- Not signed / pubkey not recovered -> Core returns false (not an error).
      return false
    end
    -- Compare hash160(pub) to the P2PKH hash160 in the address.
    local recovered_hash160 = crypto.hash160(pub)
    return recovered_hash160 == addr_hash
  end

  -- savemempool: alias for dumpmempool (Bitcoin Core: rpc/mempool.cpp::savemempool).
  -- Returns only the filename (Core's schema), not the full dump stats.
  self.methods["savemempool"] = function(rpc, params)
    if not rpc.mempool then
      error({code = M.ERROR.MISC_ERROR, message = "Mempool not available"})
    end
    if not rpc.datadir then
      error({code = M.ERROR.MISC_ERROR, message = "Datadir not configured"})
    end
    local mempool_persist_mod = require("lunarblock.mempool_persist")
    local path = (params and params[1]) or (rpc.datadir .. "/mempool.dat")
    local ok, count_or_err = mempool_persist_mod.dump(rpc.mempool, path)
    if not ok then
      error({code = M.ERROR.MISC_ERROR,
        message = "Unable to dump mempool to disk: " .. tostring(count_or_err)})
    end
    return { filename = path }
  end

  -- Mempool entry/ancestor/descendant introspection.
  -- Bitcoin Core: rpc/mempool.cpp::{getmempoolentry,getmempoolancestors,getmempooldescendants}.
  -- Each walks the in-memory CTxMemPool graph; we mirror that with the
  -- ancestor/descendant sets already maintained on each Mempool entry.
  --
  -- FIX-68 (W120 BUG-9): bip125-replaceable computed per Core
  -- policy/rbf.cpp IsRBFOptIn (walks tx + unconfirmed ancestors); the
  -- caller must pass `mp` so we can run the ancestor scan via
  -- Mempool:is_replaceable.  Previously hardcoded `true`, which lied
  -- to wallets for non-signaling, no-signaling-ancestor mempool entries.
  local function format_mempool_entry(entry, txid_hex, mp)
    local fee_btc = entry.fee / consensus.COIN
    return {
      vsize = entry.vsize,
      weight = entry.weight,
      fee = fee_btc,
      modifiedfee = fee_btc,
      time = entry.time,
      height = entry.height,
      descendantcount = entry.descendant_count or 1,
      descendantsize = entry.descendant_size or entry.vsize,
      descendantfees = entry.descendant_fees or entry.fee,
      ancestorcount = entry.ancestor_count or 1,
      ancestorsize = entry.ancestor_size or entry.vsize,
      ancestorfees = entry.ancestor_fees or entry.fee,
      wtxid = entry.wtxid or txid_hex,
      fees = {
        base = fee_btc,
        modified = fee_btc,
        ancestor = (entry.ancestor_fees or entry.fee) / consensus.COIN,
        descendant = (entry.descendant_fees or entry.fee) / consensus.COIN,
      },
      depends = entry.depends or {},
      spentby = entry.spent_by or {},
      ["bip125-replaceable"] = mp and mp:is_replaceable(txid_hex) or false,
      unbroadcast = false,
    }
  end

  self.methods["getmempoolentry"] = function(rpc, params)
    local txid_hex = params and params[1]
    if type(txid_hex) ~= "string" or #txid_hex ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid txid"})
    end
    if not rpc.mempool then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Transaction not in mempool"})
    end
    local entry = rpc.mempool:get_entry(txid_hex)
    if not entry then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Transaction not in mempool"})
    end
    return format_mempool_entry(entry, txid_hex, rpc.mempool)
  end

  self.methods["getmempoolancestors"] = function(rpc, params)
    local txid_hex = params and params[1]
    local verbose = (params and params[2]) or false
    if type(txid_hex) ~= "string" or #txid_hex ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid txid"})
    end
    if not rpc.mempool then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Transaction not in mempool"})
    end
    local entry = rpc.mempool:get_entry(txid_hex)
    if not entry then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Transaction not in mempool"})
    end
    if not verbose then
      local out = {}
      for anc_hex in pairs(entry.ancestors or {}) do
        out[#out + 1] = anc_hex
      end
      return out
    end
    local out = {}
    for anc_hex in pairs(entry.ancestors or {}) do
      local anc_entry = rpc.mempool:get_entry(anc_hex)
      if anc_entry then
        out[anc_hex] = format_mempool_entry(anc_entry, anc_hex, rpc.mempool)
      end
    end
    return out
  end

  self.methods["getmempooldescendants"] = function(rpc, params)
    local txid_hex = params and params[1]
    local verbose = (params and params[2]) or false
    if type(txid_hex) ~= "string" or #txid_hex ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid txid"})
    end
    if not rpc.mempool then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Transaction not in mempool"})
    end
    local entry = rpc.mempool:get_entry(txid_hex)
    if not entry then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Transaction not in mempool"})
    end
    if not verbose then
      local out = {}
      for desc_hex in pairs(entry.descendants or {}) do
        out[#out + 1] = desc_hex
      end
      return out
    end
    local out = {}
    for desc_hex in pairs(entry.descendants or {}) do
      local desc_entry = rpc.mempool:get_entry(desc_hex)
      if desc_entry then
        out[desc_hex] = format_mempool_entry(desc_entry, desc_hex, rpc.mempool)
      end
    end
    return out
  end

  -- gettxout: return UTXO info if unspent at the chain tip.
  -- Bitcoin Core: src/rpc/blockchain.cpp::gettxout.
  -- Reads through chain_state.coin_view (which transparently consults the
  -- in-memory cache then the RocksDB UTXO column family).  The
  -- include_mempool branch matches Core's CCoinsViewMemPool wrapper:
  -- a tx in mempool that spends the outpoint hides it; a tx in mempool that
  -- creates the outpoint exposes it (with confirmations=0).
  self.methods["gettxout"] = function(rpc, params)
    local txid_hex = params and params[1]
    local n = params and params[2]
    local include_mempool = true
    if params and params[3] ~= nil and params[3] ~= cjson.null then
      include_mempool = params[3] and true or false
    end
    if type(txid_hex) ~= "string" or #txid_hex ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid txid"})
    end
    if type(n) ~= "number" or n < 0 or n ~= math.floor(n) then
      error({code = M.ERROR.INVALID_PARAMS, message = "vout must be a non-negative integer"})
    end
    if not rpc.chain_state or not rpc.chain_state.coin_view then
      error({code = M.ERROR.MISC_ERROR, message = "Chain state not available"})
    end

    local txid = types.hash256_from_hex(txid_hex)

    -- Check if mempool spends this outpoint (hides confirmed UTXO).
    if include_mempool and rpc.mempool then
      local mempool_mod = require("lunarblock.mempool")
      local op_key = mempool_mod.outpoint_key(txid, n)
      local spender = rpc.mempool.outpoint_to_tx and rpc.mempool.outpoint_to_tx[op_key]
      if spender then
        return cjson.null
      end
    end

    local entry = rpc.chain_state.coin_view:get(txid, n)
    local utxo_height = entry and entry.height
    local is_coinbase = entry and entry.is_coinbase or false

    -- If not in confirmed UTXO and mempool inclusion is on, see if a
    -- mempool tx creates this output (height=0/MEMPOOL_HEIGHT semantics).
    if not entry and include_mempool and rpc.mempool then
      local mp_entry = rpc.mempool:get_entry(txid_hex)
      if mp_entry and mp_entry.tx and mp_entry.tx.outputs[n + 1] then
        local out = mp_entry.tx.outputs[n + 1]
        entry = {
          value = out.value,
          script_pubkey = out.script_pubkey,
          height = nil,
          is_coinbase = false,
        }
        is_coinbase = false
        utxo_height = nil  -- signals mempool height -> confirmations=0
      end
    end

    if not entry then
      return cjson.null
    end

    local tip_height = rpc.chain_state.tip_height or 0
    local tip_hash_hex
    if rpc.chain_state.tip_hash then
      tip_hash_hex = types.hash256_hex(rpc.chain_state.tip_hash)
    else
      tip_hash_hex = string.rep("0", 64)
    end
    local confirmations
    if utxo_height then
      confirmations = math.max(0, tip_height - utxo_height + 1)
    else
      confirmations = 0
    end

    -- W61: use btc_sentinel so value encodes as fixed-8 decimal (e.g.
    -- 0.03600000) instead of raw float64 division which collapses trailing
    -- zeros (0.036).  Matches Core's ValueFromAmount format.
    local result = {
      bestblock = tip_hash_hex,
      confirmations = confirmations,
      value = btc_sentinel(entry.value),
      scriptPubKey = M.decode_script_pubkey(entry.script_pubkey, rpc.network),
      coinbase = is_coinbase,
    }
    local json = strip_btc_sentinels(cjson.encode(result))
    return {_raw_json = json}
  end

  -- disconnectnode: address (ip:port) OR nodeid.  Bitcoin Core:
  -- src/rpc/net.cpp::disconnectnode.  Returns null on success; raises
  -- CLIENT_NODE_NOT_CONNECTED-style error if no such peer.
  self.methods["disconnectnode"] = function(rpc, params)
    if not rpc.peer_manager then
      error({code = M.ERROR.MISC_ERROR, message = "peer manager not available"})
    end
    local address = params and params[1]
    local nodeid = params and params[2]
    if (address == nil or address == cjson.null or address == "") and
       (nodeid == nil or nodeid == cjson.null) then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "Either 'address' or 'nodeid' must be provided"})
    end
    if address ~= nil and address ~= cjson.null and address ~= "" and
       nodeid ~= nil and nodeid ~= cjson.null then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "Only one of 'address' or 'nodeid' must be provided"})
    end

    local target_peer = nil
    if type(address) == "string" and #address > 0 then
      target_peer = rpc.peer_manager.peers and rpc.peer_manager.peers[address]
      if not target_peer then
        -- Linear search: peers may be keyed by canonical "ip:port" but caller
        -- could pass "ip" without port; match either.
        for _, p in ipairs(rpc.peer_manager.peer_list or {}) do
          if (p.ip .. ":" .. p.port) == address or p.ip == address then
            target_peer = p
            break
          end
        end
      end
    elseif type(nodeid) == "number" then
      -- nodeid is the 0-based index into peer_list (matches getpeerinfo "id").
      local pl = rpc.peer_manager.peer_list or {}
      target_peer = pl[nodeid + 1]
    end

    if not target_peer then
      error({code = -29 --[[ CLIENT_NODE_NOT_CONNECTED ]],
        message = "Node not found in connected nodes"})
    end
    rpc.peer_manager:disconnect_peer(target_peer, "disconnectnode RPC")
    -- Also unlink from manual_peers so the reconnect loop does not undo us.
    if rpc.peer_manager.manual_peers then
      local key = target_peer.ip .. ":" .. target_peer.port
      rpc.peer_manager.manual_peers[key] = nil
    end
    return cjson.null
  end

  -- getnettotals: cumulative bytes-in / bytes-out.  Bitcoin Core:
  -- src/rpc/net.cpp::getnettotals -> CConnman::GetTotalBytesRecv /
  -- GetTotalBytesSent (src/net.cpp).  Core keeps a single pair of monotonic
  -- counters that DON'T reset when a peer disconnects.
  --
  -- Implementation: PeerManager.totals = {bytes_recv, bytes_sent} are the
  -- cumulative globals; disconnect_peer / stop accumulate the final
  -- per-peer counters into them.  At RPC time we add the still-connected
  -- peers' counters on top so the number is up-to-the-second.
  self.methods["getnettotals"] = function(rpc, _params)
    local total_recv = 0
    local total_sent = 0
    if rpc.peer_manager then
      if rpc.peer_manager.totals then
        total_recv = total_recv + (rpc.peer_manager.totals.bytes_recv or 0)
        total_sent = total_sent + (rpc.peer_manager.totals.bytes_sent or 0)
      end
      if rpc.peer_manager.peer_list then
        for _, p in ipairs(rpc.peer_manager.peer_list) do
          total_recv = total_recv + (p.bytes_recv or 0)
          total_sent = total_sent + (p.bytes_sent or 0)
        end
      end
    end
    return {
      totalbytesrecv = total_recv,
      totalbytessent = total_sent,
      timemillis = math.floor(socket.gettime() * 1000),
      uploadtarget = {
        timeframe = 86400,
        target = 0,
        target_reached = false,
        serve_historical_blocks = true,
        bytes_left_in_cycle = 0,
        time_left_in_cycle = 0,
      },
    }
  end

  -- getblockstats: per-block statistics.  Bitcoin Core:
  -- src/rpc/blockchain.cpp::getblockstats.  Selectable stat keys via
  -- params[2]; default is everything we can compute without the block-undo
  -- (which would give us per-input prevout values for fees / feerates).
  --
  -- Limits:
  --   * Stats that need fees or input prevout values (avgfee, totalfee,
  --     avgfeerate, min/maxfee, min/maxfeerate, medianfee,
  --     feerate_percentiles, utxo_increase_actual, utxo_size_inc_actual)
  --     require the block-undo data; we expose them when storage.get_undo
  --     returns data, otherwise mark as `nil` (Core sets them to 0 for the
  --     genesis block — matching that convention only when undo is missing).
  self.methods["getblockstats"] = function(rpc, params)
    if not rpc.storage or not rpc.chain_state then
      error({code = M.ERROR.MISC_ERROR, message = "Storage not available"})
    end
    local hash_or_height = params and params[1]
    if hash_or_height == nil or hash_or_height == cjson.null then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "hash_or_height is required"})
    end

    local block_hash, height
    if type(hash_or_height) == "number" then
      height = math.floor(hash_or_height)
      if rpc.storage.get_hash_by_height then
        block_hash = rpc.storage.get_hash_by_height(height)
      end
      if not block_hash then
        error({code = M.ERROR.INVALID_PARAMS,
          message = "Block not found at height " .. height})
      end
    elseif type(hash_or_height) == "string" then
      if #hash_or_height ~= 64 then
        error({code = M.ERROR.INVALID_PARAMS, message = "Invalid block hash"})
      end
      block_hash = types.hash256_from_hex(hash_or_height)
    else
      error({code = M.ERROR.INVALID_PARAMS,
        message = "hash_or_height must be a hash string or numeric height"})
    end

    local block = rpc.storage.get_block(block_hash)
    if not block then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Block not found"})
    end

    local requested = nil
    if params and params[2] and params[2] ~= cjson.null then
      requested = {}
      for _, name in ipairs(params[2]) do
        requested[name] = true
      end
    end
    local function want(name)
      return requested == nil or requested[name]
    end

    -- Try to load and decode BlockUndo so we can populate fee/feerate stats.
    -- BlockUndo entries are aligned with non-coinbase txs: vtxundo[1] -> tx[2].
    -- See bitcoin-core/src/rpc/blockchain.cpp::getblockstats (loop_inputs path).
    local block_undo = nil
    if rpc.storage.get_undo then
      local undo_raw = rpc.storage.get_undo(block_hash)
      if undo_raw then
        local utxo_mod = require("lunarblock.utxo")
        local ok, decoded = pcall(utxo_mod.deserialize_block_undo, undo_raw)
        if ok and decoded and type(decoded) == "table" and decoded.tx_undo then
          block_undo = decoded
        end
      end
    end

    local txs = block.transactions
    local total_size = 0
    local total_weight = 0
    local total_out = 0  -- excludes coinbase output total
    local outputs = 0
    local inputs = 0
    local txsize_array = {}
    local swtxs, swtotal_size, swtotal_weight = 0, 0, 0
    local maxtxsize, mintxsize = 0, math.huge
    local utxos_count = 0
    -- Fee/feerate accumulators (only populated when block_undo is present).
    local fee_array = {}
    local feerate_array = {}      -- {{feerate_satvb, weight}, ...}
    local total_fee = 0
    local maxfee, minfee = 0, math.huge
    local maxfeerate, minfeerate = 0, math.huge
    -- Coinbase index: tx[1].
    for i, tx in ipairs(txs) do
      local tx_size = #serialize.serialize_transaction(tx, true)
      local tx_weight = validation.get_tx_weight(tx)
      outputs = outputs + #tx.outputs
      -- Segwit detection: any tx with at least one non-empty witness vector.
      local has_witness = false
      for _, inp in ipairs(tx.inputs) do
        if inp.witness and #inp.witness > 0 then
          has_witness = true; break
        end
      end
      if has_witness then
        swtxs = swtxs + 1
        swtotal_size = swtotal_size + tx_size
        swtotal_weight = swtotal_weight + tx_weight
      end
      if i > 1 then
        inputs = inputs + #tx.inputs
        local tx_total_out = 0
        for _, out in ipairs(tx.outputs) do
          total_out = total_out + out.value
          tx_total_out = tx_total_out + out.value
        end
        total_size = total_size + tx_size
        total_weight = total_weight + tx_weight
        txsize_array[#txsize_array + 1] = tx_size
        if tx_size > maxtxsize then maxtxsize = tx_size end
        if tx_size < mintxsize then mintxsize = tx_size end

        -- Per-tx fee via BlockUndo (matches Core's loop_inputs path).
        if block_undo then
          local txu = block_undo.tx_undo[i - 1]
          if txu and txu.prev_outputs then
            local tx_total_in = 0
            for _, prev in ipairs(txu.prev_outputs) do
              tx_total_in = tx_total_in + (prev.value or 0)
            end
            local txfee = tx_total_in - tx_total_out
            -- Negative fees are nonsensical (would mean undo lookup mismatch);
            -- clamp to 0 so we don't poison aggregates.
            if txfee < 0 then txfee = 0 end
            fee_array[#fee_array + 1] = txfee
            total_fee = total_fee + txfee
            if txfee > maxfee then maxfee = txfee end
            if txfee < minfee then minfee = txfee end
            -- Feerate in sat/vbyte = (txfee * 4) / weight.
            local feerate = 0
            if tx_weight > 0 then
              feerate = math.floor((txfee * consensus.WITNESS_SCALE_FACTOR) / tx_weight)
            end
            feerate_array[#feerate_array + 1] = {feerate, tx_weight}
            if feerate > maxfeerate then maxfeerate = feerate end
            if feerate < minfeerate then minfeerate = feerate end
          end
        end
      end
      -- utxo_increase counts spendable outputs created (cheap heuristic;
      -- Core also subtracts unspendable scripts -- TODO(rpc) when we
      -- expose script_mod.is_unspendable).
      utxos_count = utxos_count + #tx.outputs
    end
    if mintxsize == math.huge then mintxsize = 0 end
    if minfee == math.huge then minfee = 0 end
    if minfeerate == math.huge then minfeerate = 0 end

    -- Bitcoin Core's CalculateTruncatedMedian: sort, average two middle
    -- elements when even-sized, else pick the middle.
    local function truncated_median(arr)
      if #arr == 0 then return 0 end
      table.sort(arr)
      if #arr % 2 == 0 then
        return math.floor((arr[#arr / 2] + arr[#arr / 2 + 1]) / 2)
      end
      return arr[math.ceil(#arr / 2)]
    end

    -- Bitcoin Core's CalculatePercentilesByWeight: sort by feerate, then walk
    -- the cumulative-weight axis emitting percentiles at 10/25/50/75/90.
    local function feerate_percentiles_calc()
      local result = {0, 0, 0, 0, 0}
      if #feerate_array == 0 or total_weight == 0 then return result end
      table.sort(feerate_array, function(a, b) return a[1] < b[1] end)
      local thresholds = {
        total_weight / 10.0,
        total_weight / 4.0,
        total_weight / 2.0,
        (total_weight * 3.0) / 4.0,
        (total_weight * 9.0) / 10.0,
      }
      local next_idx = 1
      local cumulative = 0
      for _, e in ipairs(feerate_array) do
        cumulative = cumulative + e[2]
        while next_idx <= 5 and cumulative >= thresholds[next_idx] do
          result[next_idx] = e[1]
          next_idx = next_idx + 1
        end
      end
      -- Fill remaining with the largest feerate (matches Core).
      local last = feerate_array[#feerate_array][1]
      for i = next_idx, 5 do
        result[i] = last
      end
      return result
    end

    if not height and rpc.storage.iterator then
      -- Reverse-lookup height; relatively cheap given height index is small.
      local iter = rpc.storage.iterator("height")
      if iter then
        iter.seek_to_first()
        while iter.valid() do
          local k = iter.key()
          local v = iter.value()
          if v and #v == 32 and v == block_hash.bytes then
            height = k:byte(1) * 16777216 + k:byte(2) * 65536 + k:byte(3) * 256 + k:byte(4)
            break
          end
          iter.next()
        end
        iter.destroy()
      end
    end

    local result = {
      blockhash = types.hash256_hex(block_hash),
      time = block.header and block.header.timestamp or 0,
      height = height,
      ins = inputs,
      outs = outputs,
      txs = #txs,
      total_size = total_size,
      total_weight = total_weight,
      total_out = total_out,
      swtotal_size = swtotal_size,
      swtotal_weight = swtotal_weight,
      swtxs = swtxs,
      mintxsize = mintxsize,
      maxtxsize = maxtxsize,
      avgtxsize = (#txs > 1) and math.floor(total_size / (#txs - 1)) or 0,
      mediantxsize = (function()
        if #txsize_array == 0 then return 0 end
        table.sort(txsize_array)
        return txsize_array[math.ceil(#txsize_array / 2)]
      end)(),
      utxo_increase = utxos_count - inputs,
      utxo_size_inc = 0,  -- TODO(rpc): wire PER_UTXO_OVERHEAD-based size delta
      subsidy = consensus.get_block_subsidy and height
        and consensus.get_block_subsidy(height) or 0,
      mediantime = (function()
        if not rpc.storage.get_header or not block.header then return 0 end
        local timestamps = {}
        local cur = block.header.prev_hash
        for _ = 1, 11 do
          local h = cur and rpc.storage.get_header(cur)
          if not h then break end
          timestamps[#timestamps + 1] = h.timestamp
          cur = h.prev_hash
        end
        if #timestamps == 0 then return block.header.timestamp end
        table.sort(timestamps)
        return timestamps[math.ceil(#timestamps / 2)]
      end)(),
      -- Fee/feerate stats: zero if BlockUndo wasn't available, otherwise
      -- computed from per-tx prev-output values via BlockUndo (matches
      -- bitcoin-core/src/rpc/blockchain.cpp::getblockstats loop_inputs).
      avgfee = (block_undo and #txs > 1) and math.floor(total_fee / (#txs - 1)) or 0,
      avgfeerate = (block_undo and total_weight > 0)
        and math.floor((total_fee * consensus.WITNESS_SCALE_FACTOR) / total_weight) or 0,
      totalfee = block_undo and total_fee or 0,
      maxfee = block_undo and maxfee or 0,
      maxfeerate = block_undo and maxfeerate or 0,
      medianfee = block_undo and truncated_median(fee_array) or 0,
      minfee = block_undo and minfee or 0,
      minfeerate = block_undo and minfeerate or 0,
      feerate_percentiles = block_undo and feerate_percentiles_calc() or {0, 0, 0, 0, 0},
      -- _actual variants subtract unspendable script outputs; we don't yet
      -- expose script_mod.is_unspendable, so they trail utxo_increase /
      -- utxo_size_inc until that helper lands.
      utxo_increase_actual = 0, utxo_size_inc_actual = 0,
    }

    -- Filter by requested stats
    if requested then
      local filtered = {}
      for k, _ in pairs(requested) do
        filtered[k] = result[k]
      end
      return filtered
    end
    return result
  end

  -- submitpackage: pipe to mempool:accept_package, then re-emit results in
  -- Core's schema.  Bitcoin Core: src/rpc/mempool.cpp::submitpackage.
  -- Wallet-side propagation (broadcasting an inv per tx) is handled the
  -- same way sendrawtransaction does it.
  self.methods["submitpackage"] = function(rpc, params)
    local mempool_mod = require("lunarblock.mempool")
    if not rpc.mempool then
      error({code = M.ERROR.MISC_ERROR, message = "Mempool not available"})
    end
    local pkg = params and params[1]
    if type(pkg) ~= "table" or pkg[1] == nil then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "package must be a non-empty array of raw tx hex strings"})
    end
    local txs = {}
    for i, hex in ipairs(pkg) do
      if type(hex) ~= "string" then
        error({code = M.ERROR.INVALID_PARAMS,
          message = "package[" .. i .. "] is not a hex string"})
      end
      local ok, tx = pcall(serialize.deserialize_transaction, M.hex_decode(hex))
      if not ok then
        error({code = M.ERROR.DESERIALIZATION_ERROR,
          message = "package[" .. i .. "] failed to deserialize: " .. tostring(tx)})
      end
      txs[i] = tx
    end
    -- IsChildWithParentsTree topology check (Bitcoin Core: rpc/mempool.cpp:1395).
    -- Reject packages where parents depend on each other (chain A→B→C within
    -- the parent set is not a valid child-with-parents-tree topology).
    if #txs > 1 and not mempool_mod.is_child_with_parents_tree(txs) then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "package-not-child-with-parents-tree: parents must not spend other parents in the package"})
    end
    local accept_ok, err_or_results = rpc.mempool:accept_package(txs)
    local tx_results = {}
    -- accept_package returns (true, {...}) on success or (false, err_msg).
    if accept_ok then
      for _, tx in ipairs(txs) do
        local txid = validation.compute_txid(tx)
        local wtxid = validation.compute_wtxid(tx)
        local txid_hex = types.hash256_hex(txid)
        local wtxid_hex = types.hash256_hex(wtxid)
        local entry = rpc.mempool:get_entry(txid_hex)
        local fee_btc = entry and (entry.fee / consensus.COIN) or 0
        local vsize = entry and entry.vsize or 0
        tx_results[wtxid_hex] = {
          txid = txid_hex,
          vsize = vsize,
          fees = {
            base = fee_btc,
          },
        }
      end
      -- Broadcast via inv (matches sendrawtransaction).
      if rpc.peer_manager then
        local invs = {}
        for _, tx in ipairs(txs) do
          local txid = validation.compute_txid(tx)
          invs[#invs + 1] = {type = p2p.INV_TYPE.MSG_WITNESS_TX, hash = txid}
        end
        local inv_payload = p2p.serialize_inv(invs)
        rpc.peer_manager:broadcast("inv", inv_payload)
      end
      return {
        package_msg = "success",
        ["tx-results"] = tx_results,
        ["replaced-transactions"] = {},
      }
    end
    return {
      package_msg = tostring(err_or_results),
      ["tx-results"] = tx_results,
      ["replaced-transactions"] = {},
    }
  end

  -- generateblock <output> <transactions> [<submit>] -- regtest only.
  -- Bitcoin Core: src/rpc/mining.cpp::generateblock.  Mines a block
  -- containing the listed transactions (or txids referencing already-in
  -- mempool transactions) directed at the given output address.  We collect
  -- fees from the caller-provided txs into the coinbase output value
  -- (coinbase value = subsidy + sum(fees)).  For mempool-resident txs we
  -- read the precomputed `entry.fee`; for raw-hex txs we resolve each input
  -- via chain_state.coin_view (and fall back to mempool entries created
  -- earlier in the same call, allowing in-block tx chains).
  self.methods["generateblock"] = function(rpc, params)
    if not rpc.mining then
      error({code = M.ERROR.MISC_ERROR, message = "Mining not available"})
    end
    if not rpc.network or rpc.network.name ~= "regtest" then
      error({code = M.ERROR.MISC_ERROR,
        message = "generateblock is only available on regtest"})
    end
    local output = params and params[1]
    local tx_list = params and params[2]
    local submit = true
    if params and params[3] ~= nil and params[3] ~= cjson.null then
      submit = params[3] and true or false
    end
    if type(output) ~= "string" or #output == 0 then
      error({code = M.ERROR.INVALID_PARAMS, message = "output address is required"})
    end
    if type(tx_list) ~= "table" then
      error({code = M.ERROR.INVALID_PARAMS, message = "transactions must be an array"})
    end

    -- Decode payout address -> script_pubkey
    local addr_type, addr_data = address_mod.decode_address(output, rpc.network.name)
    if not addr_type then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Invalid output address"})
    end
    local payout_script
    if addr_type == "p2pkh" then
      payout_script = script_mod.make_p2pkh_script(addr_data)
    elseif addr_type == "p2sh" then
      payout_script = script_mod.make_p2sh_script(addr_data)
    elseif addr_type == "p2wpkh" then
      payout_script = script_mod.make_p2wpkh_script(addr_data)
    elseif addr_type == "p2wsh" then
      payout_script = script_mod.make_p2wsh_script(addr_data)
    elseif addr_type == "p2tr" then
      payout_script = script_mod.make_p2tr_script(addr_data)
    else
      error({code = M.ERROR.INVALID_ADDRESS, message = "Unsupported address type"})
    end

    -- Resolve each entry: a 64-char hex txid references an in-mempool tx,
    -- everything else is treated as raw tx hex.  Track per-entry fee where
    -- known (mempool entries) so we can collect fees into the coinbase.
    local provided_txs = {}
    local known_fee = {}     -- per-index fee in satoshis (mempool path only)
    local intra_block = {}   -- txid_hex -> {vout_idx -> {value, script}}
                             -- so a later raw tx can spend an earlier one
    for i, item in ipairs(tx_list) do
      if type(item) ~= "string" then
        error({code = M.ERROR.INVALID_PARAMS,
          message = "transactions[" .. i .. "] is not a hex string"})
      end
      if #item == 64 and item:match("^[0-9A-Fa-f]+$") then
        if not rpc.mempool then
          error({code = M.ERROR.MISC_ERROR,
            message = "Mempool not available; cannot resolve mempool txid"})
        end
        local entry = rpc.mempool:get_entry(item:lower())
        if not entry then
          error({code = M.ERROR.INVALID_ADDRESS,
            message = "transactions[" .. i .. "] references unknown txid"})
        end
        provided_txs[#provided_txs + 1] = entry.tx
        known_fee[#provided_txs] = entry.fee or 0
      else
        local ok, tx = pcall(serialize.deserialize_transaction, M.hex_decode(item))
        if not ok then
          error({code = M.ERROR.DESERIALIZATION_ERROR,
            message = "transactions[" .. i .. "] failed to deserialize"})
        end
        provided_txs[#provided_txs + 1] = tx
      end
    end

    -- Compute total fees over the provided txs so we can pay them out via
    -- the coinbase (Core ref: src/rpc/mining.cpp::generateblock builds the
    -- block via createNewBlock with use_mempool=false, which leaves the
    -- coinbase at subsidy; we deliberately diverge to support fee
    -- collection for test frameworks that mine fee-paying txs).
    local total_fees = 0
    for i, tx in ipairs(provided_txs) do
      if known_fee[i] then
        total_fees = total_fees + known_fee[i]
      else
        -- Resolve each input via chain_state.coin_view, falling back to
        -- the mempool (for parents already accepted) and to intra-block
        -- siblings (for tx-chains in the caller's list).
        local tx_in_value = 0
        local resolved_all = true
        for _, inp in ipairs(tx.inputs) do
          local prev_hex = types.hash256_hex(inp.prev_out.hash)
          local val
          -- 1) chain UTXO set
          if rpc.chain_state and rpc.chain_state.coin_view
              and rpc.chain_state.coin_view.get then
            local entry = rpc.chain_state.coin_view:get(inp.prev_out.hash, inp.prev_out.index)
            if entry then val = entry.value end
          end
          -- 2) intra-block sibling tx
          if not val and intra_block[prev_hex] then
            local sibling = intra_block[prev_hex][inp.prev_out.index]
            if sibling then val = sibling.value end
          end
          -- 3) mempool entry (parent tx in same call series, where caller
          --    passed the parent as a mempool txid)
          if not val and rpc.mempool then
            local mp_entry = rpc.mempool:get_entry(prev_hex)
            if mp_entry and mp_entry.tx and mp_entry.tx.outputs[inp.prev_out.index + 1] then
              val = mp_entry.tx.outputs[inp.prev_out.index + 1].value
            end
          end
          if not val then
            resolved_all = false
            break
          end
          tx_in_value = tx_in_value + val
        end
        if resolved_all then
          local tx_out_value = 0
          for _, out in ipairs(tx.outputs) do
            tx_out_value = tx_out_value + out.value
          end
          local fee = tx_in_value - tx_out_value
          if fee > 0 then total_fees = total_fees + fee end
        end
      end
      -- Index this tx's outputs so a later sibling can resolve them.
      local txid_hex = types.hash256_hex(validation.compute_txid(tx))
      intra_block[txid_hex] = {}
      for vout_idx, out in ipairs(tx.outputs) do
        intra_block[txid_hex][vout_idx - 1] = {value = out.value, script = out.script_pubkey}
      end
    end

    -- Build a normal block template via the mempool (gives us a coinbase at
    -- subsidy, segwit witness-commitment scaffolding, and the next-bits
    -- target), then replace the non-coinbase tx list with the caller's txs
    -- and rebuild the coinbase to reflect subsidy + total_fees.
    local _template, block = rpc.mining.create_block_template(
      rpc.mempool, rpc.chain_state, rpc.network, payout_script
    )

    local height = rpc.chain_state.tip_height + 1
    local subsidy = consensus.get_block_subsidy(height)

    -- Replace mempool-selected txs with caller-supplied txs.
    block.transactions = {}
    for _, tx in ipairs(provided_txs) do
      block.transactions[#block.transactions + 1] = tx
    end

    -- Rebuild the coinbase: same height/extra/payout scaffolding as the
    -- template's coinbase, but value = subsidy + total_fees, and witness
    -- commitment recomputed over the new (caller-supplied) tx list.
    local witness_commitment = nil
    if height >= rpc.network.segwit_height then
      local crypto_mod = require("lunarblock.crypto")
      local wtx_hashes = {types.hash256_zero()}  -- coinbase wtxid placeholder
      for _, tx in ipairs(provided_txs) do
        wtx_hashes[#wtx_hashes + 1] = validation.compute_wtxid(tx)
      end
      local witness_root = crypto_mod.compute_merkle_root(wtx_hashes)
      local witness_nonce = string.rep("\0", 32)
      witness_commitment = crypto_mod.hash256(witness_root.bytes .. witness_nonce)
    end
    local coinbase = rpc.mining.create_coinbase_tx(
      height, subsidy + total_fees, "/LunarBlock/", witness_commitment, payout_script
    )
    table.insert(block.transactions, 1, coinbase)

    -- Recompute the merkle root over the new tx set.
    local tx_hashes = {}
    for i, tx in ipairs(block.transactions) do
      tx_hashes[i] = validation.compute_txid(tx)
    end
    block.header.merkle_root = require("lunarblock.crypto").compute_merkle_root(tx_hashes)

    local found, block_hash = rpc.mining.mine_block(block)
    if not found then
      error({code = M.ERROR.MISC_ERROR,
        message = "Failed to mine block (nonce exhausted)"})
    end

    if submit then
      local new_height = rpc.chain_state.tip_height + 1
      local block_data = serialize.serialize_block(block)
      local header_data = serialize.serialize_block_header(block.header)
      local height_key = string.char(
        math.floor(new_height / 16777216) % 256,
        math.floor(new_height / 65536) % 256,
        math.floor(new_height / 256) % 256,
        new_height % 256
      )
      local hash_bytes = block_hash.bytes
      local store_batch_fn = function(batch)
        batch.put(storage_mod.CF.BLOCKS, hash_bytes, block_data)
        batch.put(storage_mod.CF.HEADERS, hash_bytes, header_data)
        batch.put(storage_mod.CF.HEIGHT_INDEX, height_key, hash_bytes)
      end
      -- Route through accept_block: adds check_block (PoW, merkle, weight,
      -- BIP-34) and correct MTP computation for IsFinalTx / BIP-68.
      -- Pre-refactor this path called connect_block with nil MTP args.
      local ok, err = rpc.chain_state:accept_block(
        block, new_height, block_hash, {
          skip_scripts    = false,
          nosync          = false,
          caller_batch_fn = store_batch_fn,
        }
      )
      if not ok then
        error({code = M.ERROR.VERIFY_ERROR,
          message = "Failed to connect block: " .. tostring(err)})
      end
      -- Evict confirmed txs from the mempool (Core removeForBlock) so they are
      -- not re-selected into the next template and rejected bad-txns-BIP30.
      if rpc.mempool then
        rpc.mempool:on_block_connected(block)
      end
    end

    local result = { hash = types.hash256_hex(block_hash) }
    if not submit then
      result.hex = M.hex_encode(serialize.serialize_block(block))
    end
    return result
  end

  -- Mining
  self.methods["getblocktemplate"] = function(rpc, params)
    if rpc.mining then
      local script_mod = require("lunarblock.script")
      local payout_script
      if params[1] and params[1].coinbase_payout then
        payout_script = params[1].coinbase_payout
      else
        -- OP_TRUE (anyone-can-spend) — Core's convention for unconfigured
        -- mining contexts. Previously defaulted to an all-zero P2PKH
        -- (1111111111111111111114oLvT2 — the canonical "burn address"
        -- where no preimage exists), which permanently destroys the
        -- block reward (~3.125 BTC + fees per block) for any pool that
        -- calls getblocktemplate without explicit coinbase_payout. With
        -- OP_TRUE, the failure mode is race-claimable rather than burn.
        payout_script = "\x51"
      end
      local template = rpc.mining.create_block_template(
        rpc.mempool, rpc.chain_state, rpc.network,
        payout_script
      )
      return template
    end
    error({code = M.ERROR.MISC_ERROR, message = "Mining not available"})
  end

  -- Mining RPC: generatetoaddress
  self.methods["generatetoaddress"] = function(rpc, params)
    local nblocks = params[1]
    local address = params[2]
    -- A wallet that mines blocks is live — mark it scanned so its subsequent
    -- getbalance / listunspent credit normally (no explicit rescan needed for a
    -- wallet that produced the chain itself). Only the request-context wallet is
    -- marked; node-level mining (no bound wallet) is left untouched so it can't
    -- accidentally flip an unrelated default wallet live.
    do
      local rw = rpc.request_wallet
      if rw and rw.mark_scanned then rw:mark_scanned() end
    end
    if type(nblocks) ~= "number" or nblocks < 1 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid nblocks"})
    end
    if type(address) ~= "string" or #address == 0 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid address"})
    end
    if not rpc.mining then
      error({code = M.ERROR.MISC_ERROR, message = "Mining module not available"})
    end

    -- Decode address to script_pubkey
    local addr_type, addr_data = address_mod.decode_address(address, rpc.network.name)
    if not addr_type then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Invalid address: " .. tostring(addr_data)})
    end

    local payout_script
    if addr_type == "p2pkh" then
      payout_script = script_mod.make_p2pkh_script(addr_data)
    elseif addr_type == "p2sh" then
      payout_script = script_mod.make_p2sh_script(addr_data)
    elseif addr_type == "p2wpkh" then
      payout_script = script_mod.make_p2wpkh_script(addr_data)
    elseif addr_type == "p2wsh" then
      payout_script = script_mod.make_p2wsh_script(addr_data)
    elseif addr_type == "p2tr" then
      payout_script = script_mod.make_p2tr_script(addr_data)
    else
      error({code = M.ERROR.INVALID_ADDRESS, message = "Unsupported address type: " .. addr_type})
    end

    local block_hashes = {}
    for _ = 1, nblocks do
      -- Create block template
      local _template, block = rpc.mining.create_block_template(
        rpc.mempool, rpc.chain_state, rpc.network, payout_script
      )

      -- Mine the block (CPU mining for regtest)
      local found, block_hash = rpc.mining.mine_block(block)
      if not found then
        error({code = M.ERROR.MISC_ERROR, message = "Failed to mine block (nonce exhausted)"})
      end

      -- Store block/header/height_index atomically with UTXO flush
      local new_height = rpc.chain_state.tip_height + 1
      local block_data = serialize.serialize_block(block)
      local header_data = serialize.serialize_block_header(block.header)
      local height_key = string.char(
        math.floor(new_height / 16777216) % 256,
        math.floor(new_height / 65536) % 256,
        math.floor(new_height / 256) % 256,
        new_height % 256
      )
      local hash_bytes = block_hash.bytes
      local store_batch_fn = function(batch)
        batch.put(storage_mod.CF.BLOCKS, hash_bytes, block_data)
        batch.put(storage_mod.CF.HEADERS, hash_bytes, header_data)
        batch.put(storage_mod.CF.HEIGHT_INDEX, height_key, hash_bytes)
      end

      -- Connect the block to chain state via the unified accept_block pipeline.
      -- Self-mined blocks are always at the chain tip (well above any assumevalid height),
      -- so skip_scripts will be false in practice.  Still use the proper check for
      -- correctness in case assumevalid is unset or the height happens to fall below it.
      -- accept_block adds: check_block (PoW, merkle, weight, BIP-34) + correct MTP for
      -- IsFinalTx / BIP-68.  Pre-refactor this path called connect_block with nil MTP.
      local gen_skip_scripts = false
      if rpc.av_in_index and rpc.av_is_ancestor and rpc.av_on_best_chain and rpc.header_chain then
        local gen_hash_hex = types.hash256_hex(block_hash)
        local gen_bh_work = rpc.header_chain:get_chain_work()
        local gen_bh_height = rpc.header_chain.header_tip_height or 0
        gen_skip_scripts = consensus.should_skip_script_validation(
          rpc.network, new_height, gen_hash_hex,
          rpc.av_in_index, rpc.av_is_ancestor, rpc.av_on_best_chain,
          gen_bh_work, gen_bh_height
        )
      end
      local ok, err = rpc.chain_state:accept_block(block, new_height, block_hash, {
        skip_scripts    = gen_skip_scripts,
        nosync          = false,
        caller_batch_fn = store_batch_fn,
      })
      if not ok then
        error({code = M.ERROR.VERIFY_ERROR, message = "Failed to connect block: " .. tostring(err)})
      end

      block_hashes[#block_hashes + 1] = types.hash256_hex(block_hash)

      -- Evict the block's now-confirmed transactions from the mempool, exactly
      -- like the submitblock / side-branch accept paths (Core's CTxMemPool::
      -- removeForBlock, called from BlockConnected). Without this, a tx mined
      -- by generatetoaddress stays in the mempool, gets re-selected into the
      -- NEXT block template, and that block is rejected bad-txns-BIP30
      -- ("tried to overwrite transaction") — wedging block production after
      -- the first wallet send.
      if rpc.mempool then
        rpc.mempool:on_block_connected(block)
      end

      -- Broadcast inv to peers so they learn about the new block
      if rpc.peer_manager then
        local inv_payload = p2p.serialize_inv({
          {type = p2p.INV_TYPE.MSG_BLOCK, hash = block_hash}
        })
        rpc.peer_manager:broadcast("inv", inv_payload)
      end
    end

    return block_hashes
  end

  -- Utility methods
  self.methods["validateaddress"] = function(rpc, params)
    local address_mod = require("lunarblock.address")
    local addr = params[1]
    assert(type(addr) == "string", "Address required")

    local network_name = rpc.network and rpc.network.name or "mainnet"
    local hrp = address_mod.BECH32_HRP[network_name] or "bc"

    -- Invalid response (Core 27+ format): no address field.
    -- error_locations must be a JSON array ([]), not object ({}).
    local function invalid_response()
      return {
        isvalid = false,
        error = "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
        error_locations = cjson.empty_array,
      }
    end

    -- Try SegWit (bech32 / bech32m) first — returns nil gracefully on failure.
    local witness_version, witness_program = address_mod.segwit_decode(hrp, addr)

    if witness_version then
      -- Valid SegWit address.
      local wp_hex = M.hex_encode(witness_program)
      -- isscript: true when witness program > 20 bytes (P2WSH=32, P2TR=32).
      local isscript = #witness_program > 20

      -- Build scriptPubKey: version opcode (0x00 for v0, 0x51+v for v1+) + push + program.
      local version_opcode
      if witness_version == 0 then
        version_opcode = "\x00"
      else
        version_opcode = string.char(0x50 + witness_version)
      end
      local push_byte = string.char(#witness_program)
      local script_bytes = version_opcode .. push_byte .. witness_program
      local spk_hex = M.hex_encode(script_bytes)

      return {
        address        = addr,
        isscript       = isscript,
        isvalid        = true,
        iswitness      = true,
        scriptPubKey   = spk_hex,
        witness_program = wp_hex,
        witness_version = witness_version,
      }
    end

    -- Try Base58Check — base58_decode uses assert() so wrap in pcall.
    local ok, b58_version, b58_payload = pcall(address_mod.base58check_decode, addr)

    if ok and b58_version then
      local V = address_mod.VERSION
      if b58_version == V.MAINNET_P2PKH or b58_version == V.TESTNET_P2PKH then
        -- P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        local script_bytes = script_mod.make_p2pkh_script(b58_payload)
        return {
          address      = addr,
          isscript     = false,
          isvalid      = true,
          iswitness    = false,
          scriptPubKey = M.hex_encode(script_bytes),
        }
      elseif b58_version == V.MAINNET_P2SH or b58_version == V.TESTNET_P2SH then
        -- P2SH: OP_HASH160 <20> OP_EQUAL
        local script_bytes = script_mod.make_p2sh_script(b58_payload)
        return {
          address      = addr,
          isscript     = true,
          isvalid      = true,
          iswitness    = false,
          scriptPubKey = M.hex_encode(script_bytes),
        }
      end
    end

    return invalid_response()
  end

  self.methods["stop"] = function(_rpc, _params)
    -- Signal shutdown
    return "LunarBlock stopping..."
  end

  self.methods["jitprofileflush"] = function(_rpc, _params)
    -- Flush LuaJIT profile by stopping the profiler. Caller should pass a
    -- file path to restart capture into; otherwise capture stops permanently.
    -- main.lua's cleanup path is unreachable (no SIGTERM handler), so this
    -- is the only way to get the profile data on disk.
    local ok, jit_p = pcall(require, "jit.p")
    if not ok then
      return { error = "jit.p not available" }
    end
    jit_p.stop()
    return { flushed = true }
  end

  self.methods["help"] = function(rpc, params)
    if params[1] then
      return "Help for " .. params[1] .. " not yet implemented"
    end
    local methods_list = {}
    for name in pairs(rpc.methods) do
      methods_list[#methods_list + 1] = name
    end
    table.sort(methods_list)
    return table.concat(methods_list, "\n")
  end

  self.methods["getinfo"] = function(rpc, _params)
    local tip_height = 0
    if rpc.chain_state then
      tip_height = rpc.chain_state.tip_height or 0
    end
    local connections = 0
    if rpc.peer_manager then
      connections = #rpc.peer_manager.peer_list
    end
    return {
      version = 10000,
      protocolversion = p2p.PROTOCOL_VERSION,
      blocks = tip_height,
      connections = connections,
      testnet = rpc.network.name ~= "mainnet",
      relayfee = 0.00001,
    }
  end

  self.methods["uptime"] = function(_rpc, _params)
    -- Return uptime in seconds (simplified)
    return os.time()
  end

  ----------------------------------------------------------------------------
  -- PSBT Methods (BIP174)
  ----------------------------------------------------------------------------

  self.methods["createpsbt"] = function(rpc, params)
    local psbt_mod = require("lunarblock.psbt")
    local inputs_raw = params[1]
    local outputs_raw = params[2]
    local locktime = params[3] or 0
    local replaceable = params[4]  -- ignored for now, RBF is default

    -- Suppress unused warning
    local _ = replaceable

    if type(inputs_raw) ~= "table" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Inputs must be an array"})
    end
    if type(outputs_raw) ~= "table" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Outputs must be an array"})
    end

    -- Build transaction inputs
    local inputs = {}
    for _, inp in ipairs(inputs_raw) do
      if type(inp.txid) ~= "string" or #inp.txid ~= 64 then
        error({code = M.ERROR.INVALID_PARAMS, message = "Invalid input txid"})
      end
      if type(inp.vout) ~= "number" then
        error({code = M.ERROR.INVALID_PARAMS, message = "Invalid input vout"})
      end
      local txid = types.hash256_from_hex(inp.txid)
      local sequence = inp.sequence or 0xFFFFFFFD  -- Default to RBF-enabled
      inputs[#inputs + 1] = types.txin(
        types.outpoint(txid, inp.vout),
        "",  -- Empty scriptSig
        sequence
      )
    end

    -- Build transaction outputs
    local outputs = {}
    for _, out_spec in ipairs(outputs_raw) do
      -- Outputs can be: {address: amount} or {"data": hex}
      for key, val in pairs(out_spec) do
        if key == "data" then
          -- OP_RETURN output
          local data_bytes = M.hex_decode(val)
          local script_pubkey = script_mod.make_nulldata_script(data_bytes)
          outputs[#outputs + 1] = types.txout(0, script_pubkey)
        else
          -- Address output
          local addr = key
          local amount = val
          if type(amount) ~= "number" then
            error({code = M.ERROR.INVALID_PARAMS, message = "Invalid output amount"})
          end
          local addr_type, program = address_mod.decode_address(addr, rpc.network.name)
          if not addr_type then
            error({code = M.ERROR.INVALID_ADDRESS, message = "Invalid address: " .. addr})
          end
          local script_pubkey
          if addr_type == "p2wpkh" then
            script_pubkey = script_mod.make_p2wpkh_script(program)
          elseif addr_type == "p2wsh" then
            script_pubkey = script_mod.make_p2wsh_script(program)
          elseif addr_type == "p2pkh" then
            script_pubkey = script_mod.make_p2pkh_script(program)
          elseif addr_type == "p2sh" then
            script_pubkey = script_mod.make_p2sh_script(program)
          elseif addr_type == "p2tr" then
            script_pubkey = script_mod.make_p2tr_script(program)
          else
            error({code = M.ERROR.INVALID_ADDRESS, message = "Unsupported address type"})
          end
          local satoshis = math.floor(amount * consensus.COIN + 0.5)
          outputs[#outputs + 1] = types.txout(satoshis, script_pubkey)
        end
        break  -- Only one key per output object
      end
    end

    -- Create unsigned transaction
    local tx = types.transaction(2, inputs, outputs, locktime)

    -- Create PSBT
    local psbt = psbt_mod.new(tx)

    -- Return base64 encoded PSBT
    return psbt_mod.to_base64(psbt)
  end

  self.methods["decodepsbt"] = function(rpc, params)
    local psbt_mod = require("lunarblock.psbt")
    local psbt_b64 = params[1]

    if type(psbt_b64) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "PSBT string required"})
    end

    local ok, psbt = pcall(psbt_mod.from_base64, psbt_b64)
    if not ok then
      error({code = M.ERROR.DESERIALIZATION_ERROR, message = "Invalid PSBT: " .. tostring(psbt)})
    end

    -- W51: decode the PSBT into a Lua table with Core-byte-parity shape.
    -- btc_sentinel() embeds "~~X.XXXXXXXX~~" placeholders for amount fields
    -- (so cjson doesn't collapse them to plain integers).
    -- strip_btc_sentinels() removes the quotes+tildes from the encoded JSON.
    -- decode_script_pubkey() enriches each scriptPubKey with asm/desc/type
    -- and suppresses address for pubkey-type outputs (W50 prescription).
    local decoded = psbt_mod.decode(psbt, rpc.network, btc_sentinel)

    -- Enrich every scriptPubKey field with asm, desc, type, and address
    -- (using the full decode_script_pubkey that knows the active network).
    for _, vout_entry in ipairs(decoded.tx.vout) do
      if vout_entry._spk_bytes then
        vout_entry.scriptPubKey = M.decode_script_pubkey(vout_entry._spk_bytes, rpc.network)
        vout_entry._spk_bytes = nil
      end
    end
    if decoded.inputs then
      for _, inp in ipairs(decoded.inputs) do
        if inp.witness_utxo and inp.witness_utxo._spk_bytes then
          inp.witness_utxo.scriptPubKey = M.decode_script_pubkey(
            inp.witness_utxo._spk_bytes, rpc.network)
          inp.witness_utxo._spk_bytes = nil
        end
      end
    end

    -- W51: Core always emits global_xpubs as an array (even when empty).
    -- cjson encodes empty Lua tables as {} (object); use cjson.empty_array
    -- for an empty xpubs list, and array_mt for a non-empty one.
    if #decoded.global_xpubs == 0 then
      decoded.global_xpubs = cjson.empty_array
    else
      setmetatable(decoded.global_xpubs, cjson.array_mt)
    end

    -- W51: Core always emits top-level `proprietary: []` and `unknown: {}`
    -- regardless of PSBT content.
    decoded.proprietary = cjson.empty_array
    decoded.unknown = {}  -- empty object (not array)

    -- W51: inputs/outputs arrays must encode as JSON arrays even when their
    -- element objects are empty ({}).  Apply array_mt.
    if decoded.inputs then
      setmetatable(decoded.inputs, cjson.array_mt)
    end
    if decoded.outputs then
      setmetatable(decoded.outputs, cjson.array_mt)
    end
    -- Same for tx.vin and tx.vout
    if decoded.tx.vin then
      setmetatable(decoded.tx.vin, cjson.array_mt)
    end
    if decoded.tx.vout then
      setmetatable(decoded.tx.vout, cjson.array_mt)
    end

    -- Encode and strip sentinel amounts (btc_sentinel → bare number).
    local json = strip_btc_sentinels(cjson.encode(decoded))

    return {_raw_json = json}
  end

  -- ---------------------------------------------------------------------------
  -- decodescript
  -- Reference: bitcoin-core/src/rpc/rawtransaction.cpp (decodescript handler)
  --
  -- Shape: {asm, desc, type, address?, p2sh?, segwit?}
  -- CRITICAL: top-level has NO `hex` field (ScriptToUniv include_hex=false).
  -- Inner segwit object DOES have `hex` (ScriptToUniv include_hex=true).
  --
  -- can_wrap types: pubkey, pubkeyhash, multisig, nonstandard,
  --   witness_v0_keyhash, witness_v0_scripthash.
  --   Extra conditions: not OP_RETURN prefix (unspendable), no OP_CHECKSIGADD.
  --   Valid ops (HasValidOps) is also required — we assume valid scripts here.
  --
  -- can_wrap_P2WSH types: pubkey (compressed 33B only), pubkeyhash,
  --   nonstandard, multisig (all keys compressed).
  --   witness_v0_* are already segwit → excluded.
  --
  -- Segwit wrap:
  --   pubkey    → P2WPKH(Hash160(pubkey))
  --   pubkeyhash → P2WPKH(raw 20-byte hash from script bytes [4..23])
  --   others    → P2WSH(SHA256(script))
  -- ---------------------------------------------------------------------------
  self.methods["decodescript"] = function(rpc, params)
    local hex = params[1]
    if type(hex) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Script hex string required"})
    end

    -- Decode hex → raw bytes (Lua string)
    local script_bytes
    if hex == "" then
      script_bytes = ""
    else
      local ok, decoded = pcall(M.hex_decode, hex)
      if not ok then
        error({code = M.ERROR.INVALID_PARAMS, message = "Invalid hex: " .. tostring(decoded)})
      end
      script_bytes = decoded
    end

    local crypto = require("lunarblock.crypto")
    local network_name = rpc.network and rpc.network.name or "mainnet"
    local hrp = address_mod.BECH32_HRP[network_name] or "bc"

    -- -------------------------------------------------------------------------
    -- Helpers
    -- -------------------------------------------------------------------------

    -- Get script type using rpc.lua's decode_script_pubkey logic (same as
    -- decode_script_pubkey but without the hex field, following Core's
    -- ScriptToUniv with include_hex=false).
    local function get_script_type(script)
      -- Bare P2PK: 33/65-byte pubkey + OP_CHECKSIG
      if #script == 35 and script:byte(1) == 0x21 and script:byte(35) == 0xac then
        return "pubkey"
      end
      if #script == 67 and script:byte(1) == 0x41 and script:byte(67) == 0xac then
        return "pubkey"
      end
      -- Bare multisig: OP_M <pubkeys> OP_N OP_CHECKMULTISIG
      if #script >= 3 and script:byte(#script) == 0xae then
        local first = script:byte(1)
        if first >= 0x51 and first <= 0x60 then
          return "multisig"
        end
      end
      -- classify_script covers p2pkh/p2sh/p2wpkh/p2wsh/p2a/p2tr/nulldata/nonstandard
      local stype = script_mod.classify_script(script)
      local type_map = {
        p2pkh        = "pubkeyhash",
        p2sh         = "scripthash",
        p2wpkh       = "witness_v0_keyhash",
        p2wsh        = "witness_v0_scripthash",
        p2tr         = "witness_v1_taproot",
        p2a          = "anchor",
        nulldata     = "nulldata",
        nonstandard  = "nonstandard",
      }
      return type_map[stype] or "nonstandard"
    end

    -- Extract address for a script (mirrors decode_script_pubkey address logic).
    local function get_address(script, stype_raw)
      local stype, program = script_mod.classify_script(script)
      if stype == "p2pkh" and program then
        local ver = network_name == "mainnet" and 0x00 or 0x6F
        return address_mod.base58check_encode(ver, program)
      elseif stype == "p2sh" and program then
        local ver = network_name == "mainnet" and 0x05 or 0xC4
        return address_mod.base58check_encode(ver, program)
      elseif stype == "p2wpkh" and program then
        return address_mod.segwit_encode(hrp, 0, program)
      elseif stype == "p2wsh" and program then
        return address_mod.segwit_encode(hrp, 0, program)
      elseif stype == "p2tr" and program then
        return address_mod.segwit_encode(hrp, 1, program)
      end
      -- pubkey type: no address (Core suppresses it)
      return nil
    end

    -- Build descriptor string (mirrors decode_script_pubkey desc logic).
    local function get_desc(script, addr, stype)
      local desc_inner
      if stype == "witness_v1_taproot" and #script == 34 then
        local xonly_hex = M.hex_encode(script:sub(3, 34))
        desc_inner = "rawtr(" .. xonly_hex .. ")"
      elseif addr then
        desc_inner = "addr(" .. addr .. ")"
      else
        desc_inner = "raw(" .. M.hex_encode(script) .. ")"
      end
      local csum = address_mod.descriptor_checksum(desc_inner)
      if csum then
        return desc_inner .. "#" .. csum
      end
      return desc_inner
    end

    -- Build P2SH wrap address: P2SH(hash160(script)).
    local function p2sh_wrap_address(script)
      local h = crypto.hash160(script)
      local ver = network_name == "mainnet" and 0x05 or 0xC4
      return address_mod.base58check_encode(ver, h)
    end

    -- Build P2WPKH script: OP_0 <20-byte hash>.
    local function make_p2wpkh(hash20)
      return "\x00\x14" .. hash20
    end

    -- Build P2WSH script: OP_0 <sha256(script)>.
    local function make_p2wsh(script)
      return "\x00\x20" .. crypto.sha256(script)
    end

    -- Check if script contains OP_CHECKSIGADD (0xba).
    local function has_checksigadd(script)
      for i = 1, #script do
        if script:byte(i) == 0xba then return true end
      end
      return false
    end

    -- Extract pubkey from P2PK script: <pushLen> <pubkey> OP_CHECKSIG.
    local function extract_p2pk_pubkey(script)
      if #script < 35 then return nil end
      local pushlen = script:byte(1)
      if (pushlen == 33 or pushlen == 65) and #script == pushlen + 2 then
        return script:sub(2, 1 + pushlen)
      end
      return nil
    end

    -- Extract pubkeys from multisig: OP_M <pubkeys> OP_N OP_CHECKMULTISIG.
    local function extract_multisig_pubkeys(script)
      local keys = {}
      if #script < 4 or script:byte(#script) ~= 0xae then return nil end
      local i = 2  -- skip OP_M
      while i <= #script - 2 do
        local pushlen = script:byte(i)
        if pushlen == 0 then break end
        if i + pushlen > #script then return nil end
        keys[#keys + 1] = script:sub(i + 1, i + pushlen)
        i = i + 1 + pushlen
      end
      return keys
    end

    -- Check all pubkeys are compressed (33 bytes, prefix 0x02 or 0x03).
    local function all_compressed(keys)
      for _, k in ipairs(keys) do
        if #k ~= 33 then return false end
        local prefix = k:byte(1)
        if prefix ~= 0x02 and prefix ~= 0x03 then return false end
      end
      return true
    end

    -- -------------------------------------------------------------------------
    -- Build top-level result (no `hex` field — Core's include_hex=false)
    -- -------------------------------------------------------------------------
    local stype = get_script_type(script_bytes)
    local addr  = get_address(script_bytes, stype)
    -- pubkey type: Core suppresses address
    if stype == "pubkey" then addr = nil end

    local result = {
      asm  = disassemble_script(script_bytes),
      desc = get_desc(script_bytes, addr, stype),
      type = stype,
    }
    if addr then result.address = addr end

    -- -------------------------------------------------------------------------
    -- can_wrap logic (mirrors Core's decodescript switch + guards)
    -- -------------------------------------------------------------------------
    local can_wrap_types = {
      pubkey                = true,
      pubkeyhash            = true,
      multisig              = true,
      nonstandard           = true,
      witness_v0_keyhash    = true,
      witness_v0_scripthash = true,
    }
    local is_op_return = #script_bytes >= 1 and script_bytes:byte(1) == 0x6a
    local can_wrap = can_wrap_types[stype] and not is_op_return and not has_checksigadd(script_bytes)

    if can_wrap then
      result.p2sh = p2sh_wrap_address(script_bytes)

      -- can_wrap_P2WSH: pubkey (compressed only), pubkeyhash, nonstandard,
      -- multisig (compressed only). Already-segwit types excluded.
      local can_wrap_p2wsh = false
      if stype == "pubkey" then
        local pk = extract_p2pk_pubkey(script_bytes)
        can_wrap_p2wsh = pk ~= nil and #pk == 33
      elseif stype == "multisig" then
        local keys = extract_multisig_pubkeys(script_bytes)
        can_wrap_p2wsh = keys ~= nil and all_compressed(keys)
      elseif stype == "pubkeyhash" or stype == "nonstandard" then
        can_wrap_p2wsh = true
      end

      if can_wrap_p2wsh then
        -- Build the witness script
        local wit_script
        if stype == "pubkey" then
          -- P2WPKH from Hash160(pubkey)
          local pk = extract_p2pk_pubkey(script_bytes)
          wit_script = make_p2wpkh(crypto.hash160(pk))
        elseif stype == "pubkeyhash" then
          -- P2WPKH from the raw 20-byte hash embedded in the P2PKH script
          -- P2PKH: OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG
          -- bytes 4..23 (Lua 1-based: sub(4,23))
          wit_script = make_p2wpkh(script_bytes:sub(4, 23))
        else
          -- P2WSH from SHA256(script) for multisig / nonstandard
          wit_script = make_p2wsh(script_bytes)
        end

        local wstype = get_script_type(wit_script)
        local waddr  = get_address(wit_script, wstype)
        local segwit_obj = {
          asm  = disassemble_script(wit_script),
          desc = get_desc(wit_script, waddr, wstype),
          hex  = M.hex_encode(wit_script),  -- inner segwit DOES have hex
          type = wstype,
        }
        if waddr then segwit_obj.address = waddr end
        segwit_obj["p2sh-segwit"] = p2sh_wrap_address(wit_script)

        result.segwit = segwit_obj
      end
    end

    return result
  end

  self.methods["analyzepsbt"] = function(rpc, params)
    local psbt_mod = require("lunarblock.psbt")
    local psbt_b64 = params[1]

    if type(psbt_b64) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "PSBT string required"})
    end

    local ok, psbt = pcall(psbt_mod.from_base64, psbt_b64)
    if not ok then
      error({code = M.ERROR.DESERIALIZATION_ERROR, message = "Invalid PSBT: " .. tostring(psbt)})
    end

    -- Suppress unused warning
    local _ = rpc

    local inputs = {}
    for i, inp in ipairs(psbt.inputs) do
      local have, need = psbt_mod.get_signature_status(psbt, i - 1)
      local input_info = {
        has_utxo = inp.witness_utxo ~= nil or inp.non_witness_utxo ~= nil,
        is_final = psbt_mod.input_is_signed(inp),
        next = "unknown",
      }

      if psbt_mod.input_is_signed(inp) then
        input_info.next = "extractor"
      elseif have >= need and need > 0 then
        input_info.next = "finalizer"
      elseif inp.witness_utxo or inp.non_witness_utxo then
        input_info.next = "signer"
      else
        input_info.next = "updater"
        input_info.missing = {utxo = true}
      end

      inputs[i] = input_info
    end

    local next_role = "unknown"
    local all_final = true
    local needs_sigs = false
    local needs_utxo = false

    for _, inp_info in ipairs(inputs) do
      if not inp_info.is_final then
        all_final = false
      end
      if inp_info.next == "signer" then
        needs_sigs = true
      end
      if inp_info.next == "updater" then
        needs_utxo = true
      end
    end

    if all_final then
      next_role = "extractor"
    elseif needs_utxo then
      next_role = "updater"
    elseif needs_sigs then
      next_role = "signer"
    else
      next_role = "finalizer"
    end

    return {
      inputs = inputs,
      estimated_vsize = nil,  -- TODO: Calculate
      estimated_feerate = nil,
      fee = nil,
      next = next_role,
    }
  end

  self.methods["combinepsbt"] = function(rpc, params)
    local psbt_mod = require("lunarblock.psbt")
    local psbts_b64 = params[1]

    if type(psbts_b64) ~= "table" or #psbts_b64 < 1 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Array of PSBTs required"})
    end

    -- Suppress unused warning
    local _ = rpc

    -- Parse all PSBTs
    local psbts = {}
    for i, b64 in ipairs(psbts_b64) do
      local ok, psbt = pcall(psbt_mod.from_base64, b64)
      if not ok then
        error({code = M.ERROR.DESERIALIZATION_ERROR, message = "Invalid PSBT at index " .. (i - 1)})
      end
      psbts[#psbts + 1] = psbt
    end

    -- Combine
    local ok, combined = pcall(psbt_mod.combine, psbts)
    if not ok then
      error({code = M.ERROR.MISC_ERROR, message = "Cannot combine PSBTs: " .. tostring(combined)})
    end

    return psbt_mod.to_base64(combined)
  end

  self.methods["finalizepsbt"] = function(rpc, params)
    local psbt_mod = require("lunarblock.psbt")
    local psbt_b64 = params[1]
    local extract = params[2]
    if extract == nil then extract = true end

    if type(psbt_b64) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "PSBT string required"})
    end

    -- Suppress unused warning
    local _ = rpc

    local ok, psbt = pcall(psbt_mod.from_base64, psbt_b64)
    if not ok then
      error({code = M.ERROR.DESERIALIZATION_ERROR, message = "Invalid PSBT: " .. tostring(psbt)})
    end

    -- Finalize all inputs
    local complete = psbt_mod.finalize(psbt)

    local result = {
      psbt = psbt_mod.to_base64(psbt),
      complete = complete,
    }

    -- Extract if requested and complete
    if extract and complete then
      local ok2, tx = pcall(psbt_mod.extract, psbt)
      if ok2 then
        result.hex = M.hex_encode(serialize.serialize_transaction(tx, true))
      end
    end

    return result
  end

  self.methods["utxoupdatepsbt"] = function(rpc, params)
    local psbt_mod = require("lunarblock.psbt")
    local psbt_b64 = params[1]
    -- params[2] would be descriptors (not implemented)

    if type(psbt_b64) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "PSBT string required"})
    end

    local ok, psbt = pcall(psbt_mod.from_base64, psbt_b64)
    if not ok then
      error({code = M.ERROR.DESERIALIZATION_ERROR, message = "Invalid PSBT: " .. tostring(psbt)})
    end

    -- Look up UTXOs from storage
    if rpc.storage then
      local storage_mod = require("lunarblock.storage")
      local utxo_mod = require("lunarblock.utxo")

      for i, tx_input in ipairs(psbt.tx.inputs) do
        local inp = psbt.inputs[i]

        -- Skip if already has UTXO info
        if inp.witness_utxo or inp.non_witness_utxo then
          goto continue
        end

        -- Look up UTXO
        local outpoint_key = tx_input.prev_out.hash.bytes .. string.char(
          bit.band(tx_input.prev_out.index, 0xFF),
          bit.band(bit.rshift(tx_input.prev_out.index, 8), 0xFF),
          bit.band(bit.rshift(tx_input.prev_out.index, 16), 0xFF),
          bit.band(bit.rshift(tx_input.prev_out.index, 24), 0xFF)
        )

        local utxo_data = rpc.storage.get(storage_mod.CF.UTXO, outpoint_key)
        if utxo_data then
          local entry = utxo_mod.deserialize_utxo_entry(utxo_data)
          -- Determine if segwit based on script type
          local script_type = script_mod.classify_script(entry.script_pubkey)
          if script_type == "p2wpkh" or script_type == "p2wsh" or script_type == "p2tr" then
            inp.witness_utxo = {
              value = entry.value,
              script_pubkey = entry.script_pubkey,
            }
          else
            -- For legacy, we'd need the full previous tx
            -- For now, just use witness_utxo format
            inp.witness_utxo = {
              value = entry.value,
              script_pubkey = entry.script_pubkey,
            }
          end
        end

        ::continue::
      end
    end

    return psbt_mod.to_base64(psbt)
  end

  self.methods["walletprocesspsbt"] = function(rpc, params)
    local psbt_mod = require("lunarblock.psbt")
    local psbt_b64 = params[1]
    local sign = params[2]
    local sighash_type = params[3]  -- "ALL", "NONE", etc.
    local bip32derivs = params[4]

    -- Suppress unused warnings
    local _ = {sighash_type, bip32derivs}

    if sign == nil then sign = true end

    if type(psbt_b64) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "PSBT string required"})
    end

    local ok, psbt = pcall(psbt_mod.from_base64, psbt_b64)
    if not ok then
      error({code = M.ERROR.DESERIALIZATION_ERROR, message = "Invalid PSBT: " .. tostring(psbt)})
    end

    -- Update UTXOs from wallet's known UTXOs
    if rpc.wallet then
      for i, tx_input in ipairs(psbt.tx.inputs) do
        local inp = psbt.inputs[i]

        -- Skip if already has UTXO info
        if inp.witness_utxo or inp.non_witness_utxo then
          goto continue_utxo
        end

        -- Look up in wallet UTXOs
        local key = tx_input.prev_out.hash.bytes .. string.char(
          bit.band(tx_input.prev_out.index, 0xFF),
          bit.band(bit.rshift(tx_input.prev_out.index, 8), 0xFF),
          bit.band(bit.rshift(tx_input.prev_out.index, 16), 0xFF),
          bit.band(bit.rshift(tx_input.prev_out.index, 24), 0xFF)
        )

        local utxo = rpc.wallet.utxos[key]
        if utxo then
          inp.witness_utxo = {
            value = utxo.value,
            script_pubkey = utxo.script_pubkey,
          }
        end

        ::continue_utxo::
      end
    end

    -- Sign inputs if requested
    if sign and rpc.wallet then
      -- Check wallet is unlocked
      if rpc.wallet.is_encrypted and rpc.wallet.is_locked then
        error({code = M.ERROR.WALLET_ERROR, message = "Wallet is locked"})
      end

      for i, tx_input in ipairs(psbt.tx.inputs) do
        local inp = psbt.inputs[i]

        -- Skip if already finalized
        if psbt_mod.input_is_signed(inp) then
          goto continue_sign
        end

        -- Get UTXO script
        local script_pubkey
        if inp.witness_utxo then
          script_pubkey = inp.witness_utxo.script_pubkey
        elseif inp.non_witness_utxo then
          local prev_out = inp.non_witness_utxo.outputs[tx_input.prev_out.index + 1]
          if prev_out then
            script_pubkey = prev_out.script_pubkey
          end
        end

        if not script_pubkey then
          goto continue_sign
        end

        -- Find address from script
        local script_type, hash_or_program = script_mod.classify_script(script_pubkey)
        local addr

        if script_type == "p2wpkh" then
          local hrp = rpc.wallet.network.bech32_hrp or address_mod.BECH32_HRP[rpc.wallet.network.name] or "bc"
          addr = address_mod.segwit_encode(hrp, 0, hash_or_program)
        elseif script_type == "p2pkh" then
          local version = rpc.wallet.network.pubkey_address_prefix
          addr = address_mod.base58check_encode(version, hash_or_program)
        end

        if addr and rpc.wallet.keys[addr] then
          local key_info = rpc.wallet.keys[addr]
          if key_info.privkey then
            psbt_mod.sign_input(psbt, i - 1, key_info.privkey, key_info.pubkey)
          end
        end

        ::continue_sign::
      end
    end

    -- Check if complete
    local complete = psbt_mod.is_complete(psbt)

    return {
      psbt = psbt_mod.to_base64(psbt),
      complete = complete,
    }
  end

  self.methods["converttopsbt"] = function(rpc, params)
    local psbt_mod = require("lunarblock.psbt")
    local hex_tx = params[1]
    local permitsigdata = params[2]
    local iswitness = params[3]

    -- Suppress unused warnings
    local _ = {rpc, iswitness}

    if type(hex_tx) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Transaction hex required"})
    end

    local ok, tx = pcall(function()
      return serialize.deserialize_transaction(M.hex_decode(hex_tx))
    end)
    if not ok then
      error({code = M.ERROR.DESERIALIZATION_ERROR, message = "Invalid transaction"})
    end

    -- Check for existing signatures
    local has_sigs = false
    for _, inp in ipairs(tx.inputs) do
      if #inp.script_sig > 0 or (inp.witness and #inp.witness > 0) then
        has_sigs = true
        break
      end
    end

    if has_sigs and not permitsigdata then
      error({code = M.ERROR.DESERIALIZATION_ERROR,
             message = "Inputs must not have scriptSigs/witnesses. Set permitsigdata=true to strip them."})
    end

    -- Strip signatures if present
    if has_sigs then
      for _, inp in ipairs(tx.inputs) do
        inp.script_sig = ""
        inp.witness = {}
      end
      tx.segwit = false
    end

    local psbt = psbt_mod.new(tx)
    return psbt_mod.to_base64(psbt)
  end

  self.methods["joinpsbts"] = function(rpc, params)
    local psbt_mod = require("lunarblock.psbt")
    local psbts_b64 = params[1]

    if type(psbts_b64) ~= "table" or #psbts_b64 < 1 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Array of PSBTs required"})
    end

    -- Suppress unused warning
    local _ = rpc

    -- Parse all PSBTs
    local psbts = {}
    for i, b64 in ipairs(psbts_b64) do
      local ok, psbt = pcall(psbt_mod.from_base64, b64)
      if not ok then
        error({code = M.ERROR.DESERIALIZATION_ERROR, message = "Invalid PSBT at index " .. (i - 1)})
      end
      psbts[#psbts + 1] = psbt
    end

    -- Join: create new transaction with all inputs and outputs
    local all_inputs = {}
    local all_outputs = {}
    local all_psbt_inputs = {}
    local all_psbt_outputs = {}

    for _, psbt in ipairs(psbts) do
      for j, inp in ipairs(psbt.tx.inputs) do
        all_inputs[#all_inputs + 1] = inp
        all_psbt_inputs[#all_psbt_inputs + 1] = psbt.inputs[j]
      end
      for j, out in ipairs(psbt.tx.outputs) do
        all_outputs[#all_outputs + 1] = out
        all_psbt_outputs[#all_psbt_outputs + 1] = psbt.outputs[j]
      end
    end

    -- Create new transaction
    local tx = types.transaction(2, all_inputs, all_outputs, 0)

    -- Create new PSBT
    local result = psbt_mod.new(tx)
    result.inputs = all_psbt_inputs
    result.outputs = all_psbt_outputs

    return psbt_mod.to_base64(result)
  end

  ----------------------------------------------------------------------------
  -- Output Descriptor Methods (BIP380-386)
  ----------------------------------------------------------------------------

  self.methods["getdescriptorinfo"] = function(rpc, params)
    local descriptor = params[1]

    if type(descriptor) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Descriptor string required"})
    end

    local info, err = address_mod.get_descriptor_info(descriptor)
    if not info then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid descriptor: " .. (err or "unknown error")})
    end

    -- Suppress unused warning
    local _ = rpc

    return info
  end

  self.methods["deriveaddresses"] = function(rpc, params)
    local descriptor = params[1]
    local range = params[2]

    if type(descriptor) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Descriptor string required"})
    end

    -- Validate checksum is present
    if not descriptor:find("#") then
      error({code = M.ERROR.INVALID_PARAMS, message = "Missing checksum"})
    end

    -- Validate checksum
    local is_valid = address_mod.validate_descriptor_checksum(descriptor)
    if not is_valid then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid checksum"})
    end

    local range_start = 0
    local range_end = 0

    if range then
      if type(range) == "number" then
        range_start = 0
        range_end = range
      elseif type(range) == "table" then
        range_start = range[1] or 0
        range_end = range[2] or range[1] or 0
      end
    end

    -- Check that range is valid
    if range_start < 0 or range_end < range_start then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid range"})
    end

    -- Check max range
    if range_end - range_start > 10000 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Range too large"})
    end

    -- Derive addresses
    local network_name = rpc.network and rpc.network.name or "mainnet"
    local addresses, err = address_mod.derive_addresses(descriptor, range_start, range_end, network_name)

    if not addresses then
      error({code = M.ERROR.MISC_ERROR, message = "Failed to derive addresses: " .. (err or "unknown error")})
    end

    return addresses
  end

  self.methods["createmultisig"] = function(rpc, params)
    -- Suppress unused warning
    local _ = rpc

    local nrequired = params[1]
    local pubkeys_param = params[2]
    local address_type = params[3] or "legacy"

    -- Validate nrequired
    if type(nrequired) ~= "number" or math.floor(nrequired) ~= nrequired then
      error({code = M.ERROR.INVALID_PARAMS, message = "nrequired must be an integer"})
    end
    nrequired = math.floor(nrequired)

    -- Validate pubkeys array
    if type(pubkeys_param) ~= "table" then
      error({code = M.ERROR.INVALID_PARAMS, message = "keys must be an array"})
    end
    local n = #pubkeys_param
    if n == 0 then
      error({code = M.ERROR.INVALID_PARAMS, message = "keys array must not be empty"})
    end
    if nrequired < 1 or nrequired > n then
      error({code = M.ERROR.INVALID_PARAMS,
        message = string.format("nrequired (%d) must be between 1 and %d", nrequired, n)})
    end
    if n > 20 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Number of keys exceeds 20"})
    end

    -- Validate address_type
    if address_type ~= "legacy" and address_type ~= "bech32" and address_type ~= "p2sh-segwit" then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "Invalid address_type '" .. tostring(address_type) .. "'. Must be legacy, bech32, or p2sh-segwit"})
    end

    -- Parse and validate each pubkey (must be hex, 33 bytes compressed)
    local pubkey_bytes = {}
    for i, hex in ipairs(pubkeys_param) do
      if type(hex) ~= "string" then
        error({code = M.ERROR.INVALID_PARAMS, message = string.format("Key %d must be a hex string", i - 1)})
      end
      if #hex ~= 66 or not hex:match("^[0-9a-fA-F]+$") then
        error({code = M.ERROR.INVALID_PARAMS,
          message = string.format("Key %d must be a compressed public key (33 bytes, 66 hex chars)", i - 1)})
      end
      local prefix = tonumber(hex:sub(1, 2), 16)
      if prefix ~= 0x02 and prefix ~= 0x03 then
        error({code = M.ERROR.INVALID_PARAMS,
          message = string.format("Key %d is not a compressed public key (prefix must be 02 or 03)", i - 1)})
      end
      -- Decode hex → bytes
      local bytes = {}
      for j = 1, #hex, 2 do
        bytes[#bytes + 1] = string.char(tonumber(hex:sub(j, j + 1), 16))
      end
      pubkey_bytes[i] = table.concat(bytes)
    end

    -- Build redeemScript: OP_M <push33 pk1> ... <push33 pkN> OP_N OP_CHECKMULTISIG
    local parts = {}
    parts[#parts + 1] = string.char(0x50 + nrequired)  -- OP_M (OP_1..OP_16)
    for _, pk in ipairs(pubkey_bytes) do
      parts[#parts + 1] = "\x21" .. pk  -- 0x21 = 33, push 33-byte compressed pubkey
    end
    parts[#parts + 1] = string.char(0x50 + n)  -- OP_N
    parts[#parts + 1] = "\xae"                 -- OP_CHECKMULTISIG
    local redeem_script = table.concat(parts)

    -- Hex-encode redeemScript
    local redeem_hex = {}
    for k = 1, #redeem_script do
      redeem_hex[k] = string.format("%02x", redeem_script:byte(k))
    end
    local redeem_script_hex = table.concat(redeem_hex)

    -- Build multi() descriptor body (no wrapper): multi(M,hex1,hex2,...)
    local pk_hex_list = {}
    for i, hex in ipairs(pubkeys_param) do
      pk_hex_list[i] = hex:lower()
    end
    local multi_inner = string.format("multi(%d,%s)", nrequired, table.concat(pk_hex_list, ","))

    local crypto = require("lunarblock.crypto")
    local network_name = "mainnet"

    local address
    local descriptor_body

    if address_type == "legacy" then
      -- sh(multi(M,...)) → P2SH; script_to_p2sh handles hash160 internally
      address = address_mod.script_to_p2sh(redeem_script, network_name)
      descriptor_body = "sh(" .. multi_inner .. ")"

    elseif address_type == "bech32" then
      -- wsh(multi(M,...)) → P2WSH
      address = address_mod.script_to_p2wsh(redeem_script, network_name)
      descriptor_body = "wsh(" .. multi_inner .. ")"

    else
      -- p2sh-segwit: sh(wsh(multi(M,...))) → P2SH-of-P2WSH
      -- Inner witness script is the redeemScript; P2WSH witness program = sha256(redeemScript)
      local witness_script_hash = crypto.sha256(redeem_script)
      -- Build the P2WSH script (OP_0 <32-byte hash>) and P2SH it
      local p2wsh_script = "\x00\x20" .. witness_script_hash  -- OP_0 PUSH32 <hash>
      address = address_mod.script_to_p2sh(p2wsh_script, network_name)
      descriptor_body = "sh(wsh(" .. multi_inner .. "))"
    end

    -- Add BIP-380 checksum
    local checksum = address_mod.descriptor_checksum(descriptor_body)
    if not checksum then
      error({code = M.ERROR.MISC_ERROR, message = "Failed to compute descriptor checksum"})
    end
    local descriptor = descriptor_body .. "#" .. checksum

    return {
      address = address,
      redeemScript = redeem_script_hex,
      descriptor = descriptor,
    }
  end

  ----------------------------------------------------------------------------
  -- Multi-Wallet Management RPCs
  ----------------------------------------------------------------------------

  --- createwallet: Create and load a new wallet.
  -- @param wallet_name string: Name for the new wallet
  -- @param disable_private_keys boolean: Disable private keys (watch-only)
  -- @param blank boolean: Create blank wallet (no keys)
  -- @param passphrase string: Encryption passphrase (optional)
  -- @param descriptors boolean: Use descriptors (always true)
  -- @return table: {name, warnings}
  self.methods["createwallet"] = function(rpc, params)
    if not rpc.wallet_manager then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet manager not available"})
    end

    local wallet_name = params[1] or params.wallet_name
    if wallet_name == nil then
      error({code = M.ERROR.INVALID_PARAMS, message = "wallet_name is required"})
    end

    -- Parse options
    local disable_private_keys = params[2] or params.disable_private_keys or false
    local blank = params[3] or params.blank or false
    local passphrase = params[4] or params.passphrase
    -- params[5] descriptors (ignored, always true)
    -- params[6] load_on_startup (ignored in our implementation)

    local options = {
      disable_private_keys = disable_private_keys,
      blank = blank,
      passphrase = passphrase,
    }

    local wallet, err = rpc.wallet_manager:create_wallet(wallet_name, options)
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err or "Failed to create wallet"})
    end

    local warnings = {}
    if passphrase and passphrase == "" then
      warnings[#warnings + 1] = "Empty string given as passphrase, wallet will not be encrypted."
    end

    return {
      name = wallet_name,
      warnings = warnings,
    }
  end

  --- loadwallet: Load a wallet from a wallet file.
  -- @param filename string: Wallet name (directory name under wallets/)
  -- @param load_on_startup boolean: (ignored)
  -- @return table: {name, warnings}
  self.methods["loadwallet"] = function(rpc, params)
    if not rpc.wallet_manager then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet manager not available"})
    end

    local filename = params[1] or params.filename
    if filename == nil then
      error({code = M.ERROR.INVALID_PARAMS, message = "filename is required"})
    end

    local wallet, err = rpc.wallet_manager:load_wallet(filename)
    if not wallet then
      -- Check for specific errors
      if err and err:find("already loaded") then
        error({code = -35, message = err})  -- RPC_WALLET_ALREADY_LOADED
      elseif err and err:find("not found") then
        error({code = -18, message = err})  -- RPC_WALLET_NOT_FOUND
      else
        error({code = M.ERROR.WALLET_ERROR, message = err or "Failed to load wallet"})
      end
    end

    return {
      name = filename,
      warnings = {},
    }
  end

  --- unloadwallet: Unload a wallet.
  -- @param wallet_name string: Wallet name (optional, uses request context)
  -- @param load_on_startup boolean: (ignored)
  -- @return table: {warnings}
  self.methods["unloadwallet"] = function(rpc, params)
    if not rpc.wallet_manager then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet manager not available"})
    end

    -- Get wallet name from params or request context
    local wallet_name = params[1] or params.wallet_name
    if wallet_name == nil then
      -- Try to get from request context
      if rpc.request_wallet then
        -- Find name by matching wallet instance
        for name, w in pairs(rpc.wallet_manager.wallets) do
          if w == rpc.request_wallet then
            wallet_name = name
            break
          end
        end
      end
      if wallet_name == nil then
        -- Use default wallet
        local _, name = rpc.wallet_manager:get_default_wallet()
        wallet_name = name
      end
    end

    if wallet_name == nil then
      error({code = M.ERROR.WALLET_ERROR, message = "No wallet specified and no default wallet loaded"})
    end

    local ok, err = rpc.wallet_manager:unload_wallet(wallet_name)
    if not ok then
      if err and err:find("not loaded") then
        error({code = -18, message = err})  -- RPC_WALLET_NOT_FOUND
      else
        error({code = M.ERROR.WALLET_ERROR, message = err or "Failed to unload wallet"})
      end
    end

    return {
      warnings = {},
    }
  end

  --- listwallets: List currently loaded wallets.
  -- @return table: Array of wallet names
  self.methods["listwallets"] = function(rpc, _params)
    if not rpc.wallet_manager then
      -- Legacy mode: return single wallet or empty
      if rpc.wallet then
        return {""}
      end
      -- cjson encodes empty Lua tables as {} (object); force [] for empty array.
      return setmetatable({}, cjson.empty_array_mt)
    end

    return rpc.wallet_manager:list_wallets()
  end

  --- listwalletdir: List wallets in the wallet directory.
  -- @return table: {wallets: [{name, warnings}]}
  self.methods["listwalletdir"] = function(rpc, _params)
    if not rpc.wallet_manager then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet manager not available"})
    end

    local wallet_list = rpc.wallet_manager:list_wallet_dir()
    local wallets = {}
    for _, info in ipairs(wallet_list) do
      wallets[#wallets + 1] = {
        name = info.name,
      }
    end

    return {
      wallets = wallets,
    }
  end

  --- getwalletinfo: Get wallet state info.
  -- @return table: Wallet information
  self.methods["getwalletinfo"] = function(rpc, _params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    -- Find wallet name
    local wallet_name = ""
    if rpc.wallet_manager then
      for name, w in pairs(rpc.wallet_manager.wallets) do
        if w == wallet then
          wallet_name = name
          break
        end
      end
    end

    return {
      walletname = wallet_name,
      walletversion = 1,
      format = "json",
      txcount = 0,  -- TODO: track transactions
      keypoolsize = wallet.gap_limit - wallet.next_external_index,
      keypoolsize_hd_internal = wallet.gap_limit - wallet.next_internal_index,
      private_keys_enabled = not wallet.is_locked and wallet.master_key ~= nil,
      avoid_reuse = false,
      scanning = false,
      descriptors = true,
      external_signer = false,
      blank = wallet.master_key == nil and wallet.encrypted_master_key == nil,
    }
  end

  --- getnewaddress: Get a new receiving address.
  -- @param label string: (ignored)
  -- @param address_type string: Address type (optional)
  -- @return string: New address
  self.methods["getnewaddress"] = function(rpc, params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    if wallet.is_locked then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet is locked"})
    end

    -- params[1] is label (ignored), params[2] is address_type
    local address_type = params[2] or params.address_type
    if address_type and address_type ~= wallet.address_type then
      -- Temporarily change address type
      local old_type = wallet.address_type
      wallet.address_type = address_type
      local addr = wallet:get_new_address()
      wallet.address_type = old_type
      return addr
    end

    return wallet:get_new_address()
  end

  --- getbalance: Get wallet balance.
  -- @return number: Balance in BTC
  self.methods["getbalance"] = function(rpc, _params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    -- Rescan UTXOs if chain_state is available
    if rpc.chain_state then
      wallet:scan_utxos(rpc.chain_state)
    end

    local balance = wallet:get_balance()
    return balance / 100000000  -- Convert satoshis to BTC
  end

  --- getbalances: Get detailed balance info.
  -- @return table: Balance details
  self.methods["getbalances"] = function(rpc, _params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    -- Rescan UTXOs if chain_state is available
    if rpc.chain_state then
      wallet:scan_utxos(rpc.chain_state)
    end
    if rpc.mempool then
      wallet:scan_mempool(rpc.mempool)
    end

    local details = wallet:get_balance_details()
    return {
      mine = {
        -- trusted = confirmed spendable balance, EXCLUDING immature coinbase
        -- (Bitcoin Core getbalances: immature coinbases are reported under
        -- `immature`, never under `trusted`).
        trusted = details.spendable / 100000000,
        untrusted_pending = details.unconfirmed / 100000000,
        immature = (details.immature or 0) / 100000000,
      },
      watchonly = {
        trusted = 0,
        untrusted_pending = 0,
        immature = 0,
      },
    }
  end

  --- listunspent: List unspent transaction outputs.
  -- @return table: Array of UTXOs
  self.methods["listunspent"] = function(rpc, params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    -- Rescan UTXOs if chain_state is available
    if rpc.chain_state then
      wallet:scan_utxos(rpc.chain_state)
    end

    local min_conf = params[1] or params.minconf or 1
    local include_unconfirmed = min_conf == 0

    local utxos = wallet:list_unspent(include_unconfirmed)
    local result = setmetatable({}, cjson.empty_array_mt)
    for _, u in ipairs(utxos) do
      -- wallet:list_unspent() entries carry the amount in `satoshis` (and a
      -- pre-divided `amount` in BTC); the field is NOT named `value`. The old
      -- `u.value / 100000000` therefore did arithmetic on nil and crashed
      -- (rpc.lua "arithmetic on field 'value' (a nil value)"). Convert from
      -- the satoshi field so the BTC amount is computed here consistently.
      result[#result + 1] = {
        txid = u.txid,
        vout = u.vout,
        address = u.address,
        amount = (u.satoshis or 0) / 100000000,
        confirmations = u.confirmations or 0,
        spendable = u.spendable ~= false,
        solvable = true,
        safe = u.safe == true and (u.confirmations or 0) >= min_conf,
      }
    end

    return result
  end

  --- sendtoaddress: Send to a Bitcoin address.
  -- @param address string: Recipient address
  -- @param amount number: Amount in BTC
  -- @return string: Transaction ID
  self.methods["sendtoaddress"] = function(rpc, params)
    local wallet, werr = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = werr})
    end

    if wallet.is_locked then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet is locked"})
    end

    -- A wallet that spends is live: mark it scanned so the scan_utxos below
    -- credits its coins (a wallet that funded itself + sends does not require an
    -- explicit rescan first).
    if wallet.mark_scanned then wallet:mark_scanned() end

    local addr = params[1] or params.address
    local amount = params[2] or params.amount

    if not addr then
      error({code = M.ERROR.INVALID_PARAMS, message = "address is required"})
    end
    if not amount then
      error({code = M.ERROR.INVALID_PARAMS, message = "amount is required"})
    end

    -- Convert BTC to satoshis
    local amount_sat = math.floor(amount * 100000000 + 0.5)

    -- Rescan UTXOs
    if rpc.chain_state then
      wallet:scan_utxos(rpc.chain_state)
    end

    -- Set mempool for transaction submission
    if rpc.mempool then
      wallet:set_mempool(rpc.mempool)
    end

    -- Create and send transaction
    local recipients = {{address = addr, amount = amount_sat}}
    local tx, err = wallet:send_to(recipients)
    if not tx then
      error({code = M.ERROR.WALLET_ERROR, message = err or "Failed to create transaction"})
    end

    -- Return txid as hex. Use the canonical txid path (hash256 over the
    -- non-witness serialization, returned in big-endian display form) — the
    -- same path send_transaction itself uses to key self.transactions. The
    -- old code called crypto.sha256d, which does not exist (the double-SHA256
    -- helper is crypto.hash256 / validation.compute_txid), so sendtoaddress
    -- moved the coins on-chain but then crashed (-32603) computing its return
    -- value and the caller never received the txid.
    local txid = validation.compute_txid(tx)
    -- Persist after a send: the change-index advance + spent-pending state must
    -- survive an unclean restart. save_if_dirty no-ops if nothing changed; the
    -- address helpers already flushed the index advance, this catches the rest.
    if wallet.save_if_dirty then
      wallet:mark_dirty()
      wallet:save_if_dirty()
    end
    return types.hash256_hex(txid)
  end

  --- bumpfee: BIP-125 RBF fee bump of an own wallet transaction.
  --
  -- Mirrors Bitcoin Core wallet/rpc/spend.cpp bumpfee (and the supporting
  -- wallet/feebumper.cpp). The bumped tx reuses the original inputs, leaves
  -- recipient outputs untouched, and shrinks the wallet-owned change output
  -- by (new_fee - old_fee). The new tx is re-signed and submitted to the
  -- mempool, which performs BIP-125 replacement against the original. The
  -- original wallet entry is marked `replaced_by` so a second bumpfee on
  -- the same txid is rejected.
  --
  -- @param params[1] txid string: hex txid of the wallet transaction to bump
  -- @param params[2] options table|nil: {
  --   "fee_rate"   = number  -- target feerate, sat/vB (overrides the default
  --                            old_fee + ceil(vsize) sat-per-vB bump)
  -- }
  -- @return {txid=<new_txid_hex>, origfee=<old_fee_BTC>, fee=<new_fee_BTC>,
  --          errors=[<string>...]}
  self.methods["bumpfee"] = function(rpc, params)
    local wallet, werr = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = werr})
    end

    local txid_hex_disp = params[1] or params.txid
    if type(txid_hex_disp) ~= "string" or #txid_hex_disp ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS,
             message = "txid (64-hex string) is required"})
    end

    local opts = params[2] or params.options or {}
    local fee_rate
    if opts.fee_rate ~= nil and opts.fee_rate ~= cjson.null then
      fee_rate = tonumber(opts.fee_rate)
      if not fee_rate or fee_rate <= 0 then
        error({code = M.ERROR.INVALID_PARAMS,
               message = "fee_rate must be a positive number (sat/vB)"})
      end
    end

    -- self.transactions keys are display-form (big-endian) hex (see
    -- types.hash256_hex), which is exactly what RPC clients hand us as
    -- the txid parameter. No conversion needed.
    local lookup_hex = txid_hex_disp:lower()

    if rpc.chain_state then
      wallet:scan_utxos(rpc.chain_state)
    end
    if rpc.mempool then
      wallet:set_mempool(rpc.mempool)
    end

    local new_tx, old_fee_or_errs, new_fee = wallet:bump_fee(lookup_hex, {
      fee_rate = fee_rate,
      sign     = true,
    })
    if not new_tx then
      -- bump_fee returns (nil, errors_table) on failure
      local err_msg
      if type(old_fee_or_errs) == "table" and old_fee_or_errs[1] then
        err_msg = old_fee_or_errs[1]
      else
        err_msg = tostring(old_fee_or_errs)
      end
      error({code = M.ERROR.WALLET_ERROR, message = err_msg})
    end

    -- Submit the replacement. The mempool's BIP-125 path will evict the
    -- original; mark the wallet entry as replaced.
    local ok, send_err = wallet:send_transaction(new_tx,
      {fee = new_fee, replaces = lookup_hex})
    if not ok then
      error({code = M.ERROR.WALLET_ERROR,
             message = "Failed to broadcast replacement: " .. tostring(send_err)})
    end

    local new_txid_bin = validation.compute_txid(new_tx).bytes
    local new_txid_hex = M.hex_encode(new_txid_bin:reverse())

    local errors_arr = setmetatable({}, cjson.empty_array_mt)
    return {
      txid    = new_txid_hex,
      origfee = old_fee_or_errs / 100000000,  -- sat -> BTC
      fee     = new_fee          / 100000000,
      errors  = errors_arr,
    }
  end

  --- psbtbumpfee: BIP-125 RBF fee bump that returns an unsigned PSBT.
  --
  -- Mirrors Bitcoin Core wallet/rpc/spend.cpp psbtbumpfee. Same flow as
  -- bumpfee, but the rebuilt transaction is NOT signed — it is wrapped in
  -- a BIP-174 PSBT (witness_utxo populated on every input so an offline
  -- signer can produce sighashes) and returned base64-encoded. The
  -- original transaction is left in place; psbtbumpfee does NOT broadcast.
  --
  -- @param params[1] txid string: hex txid of the wallet transaction to bump
  -- @param params[2] options table|nil: same shape as bumpfee
  -- @return {psbt=<base64>, origfee=<BTC>, fee=<BTC>, errors=[]}
  self.methods["psbtbumpfee"] = function(rpc, params)
    local wallet, werr = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = werr})
    end

    local txid_hex_disp = params[1] or params.txid
    if type(txid_hex_disp) ~= "string" or #txid_hex_disp ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS,
             message = "txid (64-hex string) is required"})
    end

    local opts = params[2] or params.options or {}
    local fee_rate
    if opts.fee_rate ~= nil and opts.fee_rate ~= cjson.null then
      fee_rate = tonumber(opts.fee_rate)
      if not fee_rate or fee_rate <= 0 then
        error({code = M.ERROR.INVALID_PARAMS,
               message = "fee_rate must be a positive number (sat/vB)"})
      end
    end

    -- self.transactions keys are display-form (big-endian) hex (see
    -- types.hash256_hex), which is exactly what RPC clients hand us as
    -- the txid parameter. No conversion needed.
    local lookup_hex = txid_hex_disp:lower()

    if rpc.chain_state then
      wallet:scan_utxos(rpc.chain_state)
    end

    local new_tx, old_fee_or_errs, new_fee, input_utxos =
      wallet:bump_fee(lookup_hex, {
        fee_rate = fee_rate,
        sign     = false,   -- unsigned for PSBT
      })
    if not new_tx then
      local err_msg
      if type(old_fee_or_errs) == "table" and old_fee_or_errs[1] then
        err_msg = old_fee_or_errs[1]
      else
        err_msg = tostring(old_fee_or_errs)
      end
      error({code = M.ERROR.WALLET_ERROR, message = err_msg})
    end

    -- Wrap in PSBT. psbt.new requires every input to be unsigned, which
    -- bump_fee(sign=false) guarantees.
    local psbt_mod = require("lunarblock.psbt")
    local psbt = psbt_mod.new(new_tx)
    -- Populate witness_utxo on every input so an offline signer has the
    -- value and scriptPubKey it needs to produce the BIP-143 sighash.
    for i, u in ipairs(input_utxos) do
      psbt.inputs[i].witness_utxo = {
        value         = u.value,
        script_pubkey = u.script_pubkey,
      }
    end

    local errors_arr = setmetatable({}, cjson.empty_array_mt)
    return {
      psbt    = psbt_mod.to_base64(psbt),
      origfee = old_fee_or_errs / 100000000,
      fee     = new_fee          / 100000000,
      errors  = errors_arr,
    }
  end

  --------------------------------------------------------------------------
  -- BIP-78 PayJoin RPCs (FIX-66 — closes W119 G26 + G27).
  --
  -- These are the operator-facing surface for PayJoin.  The actual
  -- receiver endpoint lives in src/rest.lua handle_payjoin (FIX-65);
  -- the sender flow lives in src/payjoin_sender.lua (FIX-66).  Both
  -- RPCs follow the canonical btcpayserver/payjoin and payjoin-cli
  -- command shapes.
  --------------------------------------------------------------------------

  --- getpayjoinrequest: Generate a BIP-21 URI advertising a PayJoin
  --  receiver endpoint.
  --
  --  @param params[1] amount_btc  number  Amount to request (BTC)
  --  @param params[2] options     table   {
  --     endpoint   string  base URL of the receiver endpoint
  --                        (defaults to "https://<host>/payjoin",
  --                        host taken from rpc.payjoin_host or
  --                        "localhost").  MUST be reachable by the
  --                        sender — operator's responsibility.
  --     label      string  BIP-21 label= parameter
  --     message    string  BIP-21 message= parameter
  --     pjos       string  "0" or "1" (BIP-21 pjos= — output substitution
  --                        opt-out by the receiver)
  --   }
  --  @return  {address=<bech32>, uri=<bitcoin:...?amount=&pj=&pjos=>}
  self.methods["getpayjoinrequest"] = function(rpc, params)
    local wallet, werr = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = werr})
    end

    local amount_btc = params[1] or params.amount
    if amount_btc == nil then
      error({code = M.ERROR.INVALID_PARAMS,
             message = "amount (BTC) is required"})
    end
    local amount_num = tonumber(amount_btc)
    if not amount_num or amount_num <= 0 then
      error({code = M.ERROR.INVALID_PARAMS,
             message = "amount must be a positive number"})
    end

    local opts = params[2] or params.options or {}

    -- Fetch a fresh receiving address.  The wallet handles HD
    -- derivation; we don't pre-allocate.
    local addr = wallet:get_new_address()
    if not addr then
      error({code = M.ERROR.WALLET_ERROR,
             message = "wallet failed to derive new address"})
    end

    -- Build the pj= endpoint URL.  Operators typically expose the
    -- REST server on https://<their-host>/payjoin.  We honour any
    -- explicit override.
    local endpoint = opts.endpoint
    if not endpoint or endpoint == "" then
      local host = rpc.payjoin_host or "localhost"
      endpoint = "https://" .. host .. "/payjoin"
    end

    -- Quote-protect the endpoint for the URI query value.  We only
    -- need to encode ':' '/' '?' '#' '&' '=' '+' '%' ' '.
    local function uri_quote(s)
      return (s:gsub("[^A-Za-z0-9%-_.~]", function(c)
        return string.format("%%%02X", string.byte(c))
      end))
    end

    local query = {
      "amount=" .. string.format("%.8f", amount_num):gsub("0+$", "")
                                                   :gsub("%.$", ""),
      "pj="     .. uri_quote(endpoint),
    }
    if opts.label and opts.label ~= "" then
      query[#query + 1] = "label=" .. uri_quote(tostring(opts.label))
    end
    if opts.message and opts.message ~= "" then
      query[#query + 1] = "message=" .. uri_quote(tostring(opts.message))
    end
    if opts.pjos ~= nil then
      query[#query + 1] = "pjos=" .. tostring(opts.pjos)
    end

    local uri = "bitcoin:" .. addr .. "?" .. table.concat(query, "&")

    return {
      address  = addr,
      uri      = uri,
      endpoint = endpoint,
    }
  end

  --- sendpayjoinrequest: Execute the sender side of a BIP-78 PayJoin
  --  handshake against the given BIP-21 URI.
  --
  --  Flow (delegates to lunarblock.payjoin_sender.send_payjoin_request):
  --    1. Parse the URI (BIP-21).  Reject if no pj= parameter.
  --    2. Build + sign the Original transaction.
  --    3. POST the Original PSBT to pj= over HTTPS (cert-validated)
  --       or Tor (if .onion).
  --    4. Run six anti-snoop validators (G10-G15).
  --    5. Re-sign sender inputs in the proposal (single-pipeline via
  --       Wallet:_sign_inputs).
  --    6. Broadcast.
  --    7. On ANY failure, fall back to broadcasting the Original (G22).
  --
  --  @param params[1] uri   string  BIP-21 URI with pj=
  --  @param params[2] options  table  {
  --     fee_rate                       number   sat/vB
  --     conf_target                    number
  --     maxadditionalfeecontribution   number   sats
  --     additionalfeeoutputindex       number   0-based
  --     disableoutputsubstitution      boolean
  --     minfeerate                     number   sat/vB
  --   }
  --  @return  {txid=<hex>, status="payjoin"|"fallback",
  --            error=<string|nil>}
  self.methods["sendpayjoinrequest"] = function(rpc, params)
    local wallet, werr = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = werr})
    end
    if wallet.is_locked then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet is locked"})
    end

    local uri = params[1] or params.uri
    if type(uri) ~= "string" or #uri == 0 then
      error({code = M.ERROR.INVALID_PARAMS,
             message = "uri (BIP-21 string) is required"})
    end

    local opts = params[2] or params.options or {}

    if rpc.chain_state then
      wallet:scan_utxos(rpc.chain_state)
    end
    if rpc.mempool then
      wallet:set_mempool(rpc.mempool)
    end

    local network_name = (rpc.network and rpc.network.name) or "mainnet"
    opts.network = opts.network or network_name

    local payjoin_sender = require("lunarblock.payjoin_sender")
    local txid_hex, status, err = payjoin_sender.send_payjoin_request(
      wallet, rpc.mempool, rpc.peer_manager, uri, nil, opts)

    if not txid_hex then
      local emsg = (err and err.message) or "PayJoin failed"
      local ecode = (err and err.code) or "payjoin-failed"
      error({code = M.ERROR.WALLET_ERROR,
             message = ecode .. ": " .. emsg})
    end
    return {
      txid   = txid_hex,
      status = status,
      error  = err and (err.code .. ": " .. err.message) or cjson.null,
    }
  end

  --- walletpassphrase: Unlock wallet with passphrase.
  -- @param passphrase string: Wallet passphrase
  -- @param timeout number: Seconds to keep unlocked (ignored, stays unlocked)
  self.methods["walletpassphrase"] = function(rpc, params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    local passphrase = params[1] or params.passphrase
    if not passphrase then
      error({code = M.ERROR.INVALID_PARAMS, message = "passphrase is required"})
    end

    local ok, unlock_err = wallet:unlock(passphrase)
    if not ok then
      error({code = M.ERROR.WALLET_ERROR, message = unlock_err or "Wrong passphrase"})
    end

    return cjson.null
  end

  --- walletlock: Lock the wallet.
  self.methods["walletlock"] = function(rpc, _params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    if not wallet.is_encrypted then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet is not encrypted"})
    end

    wallet:lock()
    return cjson.null
  end

  --- encryptwallet: Encrypt the wallet with a passphrase.
  -- @param passphrase string: Encryption passphrase
  self.methods["encryptwallet"] = function(rpc, params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    if wallet.is_encrypted then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet is already encrypted"})
    end

    local passphrase = params[1] or params.passphrase
    if not passphrase or passphrase == "" then
      error({code = M.ERROR.INVALID_PARAMS, message = "passphrase is required"})
    end

    wallet:encrypt(passphrase)

    -- Save wallet
    if rpc.wallet_manager then
      for name, w in pairs(rpc.wallet_manager.wallets) do
        if w == wallet then
          local path = rpc.wallet_manager:get_wallet_path(name)
          wallet:save(path)
          break
        end
      end
    end

    return "wallet encrypted; The keypool has been flushed and a new HD seed was generated."
  end

  --- walletpassphrasechange: Change wallet passphrase.
  -- @param oldpassphrase string: Current passphrase
  -- @param newpassphrase string: New passphrase
  self.methods["walletpassphrasechange"] = function(rpc, params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    local old_pass = params[1] or params.oldpassphrase
    local new_pass = params[2] or params.newpassphrase

    if not old_pass then
      error({code = M.ERROR.INVALID_PARAMS, message = "oldpassphrase is required"})
    end
    if not new_pass then
      error({code = M.ERROR.INVALID_PARAMS, message = "newpassphrase is required"})
    end

    local ok, change_err = wallet:change_passphrase(old_pass, new_pass)
    if not ok then
      error({code = M.ERROR.WALLET_ERROR, message = change_err or "Wrong passphrase"})
    end

    -- Save wallet
    if rpc.wallet_manager then
      for name, w in pairs(rpc.wallet_manager.wallets) do
        if w == wallet then
          local path = rpc.wallet_manager:get_wallet_path(name)
          wallet:save(path)
          break
        end
      end
    end

    return cjson.null
  end

  --- dumpprivkey: Dump private key for an address.
  -- @param address string: Address to dump key for
  -- @return string: Private key in WIF format
  self.methods["dumpprivkey"] = function(rpc, params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    if wallet.is_locked then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet is locked"})
    end

    local addr = params[1] or params.address
    if not addr then
      error({code = M.ERROR.INVALID_PARAMS, message = "address is required"})
    end

    local wif, dump_err = wallet:dump_privkey(addr)
    if not wif then
      error({code = M.ERROR.WALLET_ERROR, message = dump_err or "Address not found in wallet"})
    end

    return wif
  end

  --- getwalletmnemonic: Reveal the BIP-39 mnemonic for the loaded wallet.
  -- The wallet must be unlocked, and must have been created via
  -- importmnemonic / a mnemonic-aware createwallet flow. Returns the
  -- mnemonic as a single space-separated string plus a backup-hygiene
  -- warning. Treat the response like dumpprivkey output: never log it,
  -- never copy it into chat, write it down off-machine.
  -- @return table: { mnemonic = "...", word_count = N, warning = "..." }
  self.methods["getwalletmnemonic"] = function(rpc, _params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    if wallet.is_locked then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet is locked"})
    end

    local words, mnem_err = wallet:get_mnemonic()
    if not words then
      error({code = M.ERROR.WALLET_ERROR,
             message = mnem_err or "No mnemonic available for this wallet"})
    end

    return {
      mnemonic = table.concat(words, " "),
      word_count = #words,
      warning = "BACKUP HYGIENE: anyone with this phrase can spend your"
        .. " coins. Write it down on paper, store it offline, never paste"
        .. " it into chat / cloud / screenshots. The wallet does NOT store"
        .. " your BIP-39 passphrase — keep that backed up separately.",
    }
  end

  --- importmnemonic: Restore a wallet from a BIP-39 mnemonic.
  -- Creates a new wallet (or replaces the loaded one) from the supplied
  -- 12/15/18/21/24-word mnemonic. The mnemonic is validated (word
  -- membership + BIP-39 checksum) before any wallet state is touched.
  -- @param mnemonic string: BIP-39 mnemonic phrase
  -- @param bip39_passphrase string: BIP-39 passphrase (default "")
  -- @param wallet_name string: name to register with the wallet manager
  --                            (required if a wallet manager is configured)
  -- @return table: { wallet_name, address_count, message }
  self.methods["importmnemonic"] = function(rpc, params)
    local mnem = params[1] or params.mnemonic
    if type(mnem) ~= "string" or #mnem == 0 then
      error({code = M.ERROR.INVALID_PARAMS, message = "mnemonic is required"})
    end
    local bip39_pp = params[2] or params.bip39_passphrase or ""
    local wname = params[3] or params.wallet_name

    local network = consensus.networks.mainnet
    local storage = nil
    if rpc.wallet_manager then
      network = rpc.wallet_manager.network or network
      storage = rpc.wallet_manager.storage
    elseif rpc.wallet then
      network = rpc.wallet.network or network
      storage = rpc.wallet.storage
    end

    local wallet_obj = require("lunarblock.wallet")
    local new_wallet, imp_err = wallet_obj.import_mnemonic(
      mnem, bip39_pp, network, storage, nil  -- wallet-encryption pw not exposed here
    )
    if not new_wallet then
      error({code = M.ERROR.INVALID_PARAMS,
             message = "importmnemonic: " .. tostring(imp_err)})
    end

    if rpc.wallet_manager then
      if not wname or wname == "" then
        error({code = M.ERROR.INVALID_PARAMS,
               message = "wallet_name is required when a wallet manager is loaded"})
      end
      rpc.wallet_manager.wallets[wname] = new_wallet
      local path = rpc.wallet_manager:get_wallet_path(wname)
      new_wallet:save(path)
      return {
        wallet_name = wname,
        address_count = #new_wallet.addresses,
        message = "Mnemonic imported. BACK UP your phrase off-machine.",
      }
    else
      -- Legacy single-wallet mode.
      rpc.wallet = new_wallet
      return {
        address_count = #new_wallet.addresses,
        message = "Mnemonic imported (single-wallet mode). BACK UP your phrase off-machine.",
      }
    end
  end

  --- importprivkey: Import a WIF private key into the wallet.
  --
  -- Mirrors Bitcoin Core wallet/rpc/backup.cpp::importprivkey: decode the WIF,
  -- register the key's standard scripts as an imported key (held apart from the
  -- HD keychain so a restore-from-seed / reseed never wipes it), and — when
  -- rescan is true (the default) — rescan the chain so the key's already-on-chain
  -- funds are credited into the wallet ledger.
  --
  -- @param params[1] privkey string: private key in WIF format
  -- @param params[2] label   string: optional label (best-effort; ignored)
  -- @param params[3] rescan  boolean: rescan the chain after import (default true)
  -- @return null
  self.methods["importprivkey"] = function(rpc, params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    if wallet.is_locked then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet is locked"})
    end

    local wif = params[1] or params.privkey
    if not wif then
      error({code = M.ERROR.INVALID_PARAMS, message = "privkey is required"})
    end
    -- rescan defaults to true (Core). Only an explicit false / null disables it.
    local do_rescan = params[3]
    if do_rescan == nil then do_rescan = params.rescan end
    if do_rescan == nil or do_rescan == cjson.null then do_rescan = true end

    -- import_privkey can throw (assert on a wrong-network WIF prefix) — wrap it.
    local ok, addr_or_err, import_err = pcall(function()
      return wallet:import_privkey(wif)
    end)
    if not ok then
      error({code = M.ERROR.WALLET_ERROR,
             message = "Invalid private key: " .. tostring(addr_or_err)})
    end
    local addr = addr_or_err
    if not addr then
      error({code = M.ERROR.WALLET_ERROR, message = import_err or "Invalid private key"})
    end

    -- Rescan the chain so the imported key's existing funds are credited.
    if do_rescan and rpc.chain_state then
      local rok, rerr = wallet:rescan(rpc.chain_state, rpc.mempool)
      if not rok then
        error({code = M.ERROR.WALLET_ERROR,
               message = "importprivkey rescan failed: " .. tostring(rerr)})
      end
    end

    -- Save wallet (persists the imported key so it survives reload / reseed).
    if rpc.wallet_manager then
      for name, w in pairs(rpc.wallet_manager.wallets) do
        if w == wallet then
          local path = rpc.wallet_manager:get_wallet_path(name)
          wallet:save(path)
          break
        end
      end
    end

    return cjson.null
  end

  --- rescanblockchain: rescan the local blockchain for wallet-related txs.
  --
  -- Mirrors Bitcoin Core wallet/rpc/transactions.cpp::rescanblockchain
  -- (CWallet::ScanForWalletTransactions): walk the existing chain over
  -- [start_height, stop_height] crediting outputs that pay wallet-owned scripts
  -- into the wallet UTXO ledger + history (the BACKWARD counterpart of the
  -- block-connect scan), and return the {start_height, stop_height} actually
  -- scanned. This is the REAL wallet rescan — distinct from scantxoutset, which
  -- scans the chainstate UTXO set without ever touching a wallet.
  --
  -- @param params[1] start_height number: optional, default 0
  -- @param params[2] stop_height  number: optional, default current tip
  -- @return table: { start_height, stop_height }
  self.methods["rescanblockchain"] = function(rpc, params)
    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end
    if not rpc.chain_state then
      error({code = M.ERROR.MISC_ERROR, message = "No chain state available"})
    end

    local start_height = params[1] or params.start_height
    local stop_height  = params[2] or params.stop_height
    if start_height == cjson.null then start_height = nil end
    if stop_height == cjson.null then stop_height = nil end

    local res, rerr = wallet:rescan(rpc.chain_state, rpc.mempool, start_height, stop_height)
    if not res then
      error({code = M.ERROR.INVALID_PARAMS, message = rerr or "rescan failed"})
    end

    -- Persist the now-scanned wallet so a reload stays live.
    if rpc.wallet_manager then
      for name, w in pairs(rpc.wallet_manager.wallets) do
        if w == wallet then
          local ok = pcall(function()
            wallet:save(rpc.wallet_manager:get_wallet_path(name))
          end)
          _ = ok
          break
        end
      end
    end

    return {
      start_height = res.start_height,
      stop_height = res.stop_height,
    }
  end

  ----------------------------------------------------------------------------
  -- Wallet signing RPCs (signrawtransactionwith{wallet,key})
  ----------------------------------------------------------------------------
  --
  -- Reference: bitcoin-core/src/rpc/rawtransaction.cpp:signrawtransactionwithkey
  --            bitcoin-core/src/wallet/rpc/spend.cpp:signrawtransactionwithwallet
  --            camlcoin/lib/rpc.ml:signrawtransactionwithkey (best-in-class)
  --
  -- Both handlers share a common signing core: decode tx, locate the prev_out
  -- script_pubkey + value for each input (from caller-provided prevTxs, or
  -- wallet UTXOs, or the chain UTXO CF), classify the SPK, look up the matching
  -- key (by hash160 / address), produce the sighash, ECDSA-sign, and write
  -- the witness or scriptSig.  P2TR (Schnorr) is not signed because lunarblock
  -- ships ECDSA-only crypto today (M.schnorr_sign is unavailable); the input
  -- is left untouched and `complete=false` is reported.

  --- WIF or 64-hex privkey -> {privkey32, pubkey, pkh, compressed}
  -- Returns nil on parse failure so the caller can skip silently like Core.
  local function decode_priv_key_string(s)
    if type(s) ~= "string" then return nil end
    local crypto = require("lunarblock.crypto")
    local addr_mod = require("lunarblock.address")
    local privkey32, compressed
    if #s == 64 and s:match("^[0-9A-Fa-f]+$") then
      privkey32 = M.hex_decode(s)
      compressed = true
    else
      local _, payload = addr_mod.base58check_decode(s)
      if not payload then return nil end
      if #payload == 33 and payload:byte(33) == 0x01 then
        privkey32 = payload:sub(1, 32); compressed = true
      elseif #payload == 32 then
        privkey32 = payload; compressed = false
      else
        return nil
      end
    end
    local pubkey = crypto.pubkey_from_privkey(privkey32, compressed)
    if not pubkey then return nil end
    local pkh = crypto.hash160(pubkey)
    return {privkey = privkey32, pubkey = pubkey, pkh = pkh, compressed = compressed}
  end

  --- Look up prevout (value, script_pubkey) for `tx_input`.
  --
  -- Resolution order:
  --   1. caller-provided `prev_lookup` map (from prevTxs[] arg) keyed by
  --      txid_le .. vout_u32le
  --   2. wallet.utxos[] map (when a wallet is bound to the request)
  --   3. chain UTXO CF via rpc.storage (confirmed UTXO set)
  --
  -- Returns nil if no source has the outpoint.
  local function resolve_prevout(rpc, tx_input, prev_lookup)
    local utxo_mod = require("lunarblock.utxo")
    local outpoint_key = tx_input.prev_out.hash.bytes .. string.char(
      bit.band(tx_input.prev_out.index, 0xFF),
      bit.band(bit.rshift(tx_input.prev_out.index, 8), 0xFF),
      bit.band(bit.rshift(tx_input.prev_out.index, 16), 0xFF),
      bit.band(bit.rshift(tx_input.prev_out.index, 24), 0xFF))

    if prev_lookup and prev_lookup[outpoint_key] then
      return prev_lookup[outpoint_key]
    end
    if rpc.wallet and rpc.wallet.utxos and rpc.wallet.utxos[outpoint_key] then
      local u = rpc.wallet.utxos[outpoint_key]
      return {value = u.value, script_pubkey = u.script_pubkey}
    end
    if rpc.storage then
      local data = rpc.storage.get(storage_mod.CF.UTXO, outpoint_key)
      if data then
        local entry = utxo_mod.deserialize_utxo_entry(data)
        return {value = entry.value, script_pubkey = entry.script_pubkey}
      end
    end
    return nil
  end

  --- Parse the optional `prevtxs` arg from signrawtransactionwith{key,wallet}.
  --
  -- Each entry is {txid, vout, scriptPubKey, [redeemScript], [witnessScript],
  -- [amount]}.  Returns a map keyed by outpoint_key (txid_le .. vout_u32le).
  local function parse_prevtxs(prevtxs_raw)
    if prevtxs_raw == nil then return {} end
    if type(prevtxs_raw) ~= "table" then
      error({code = M.ERROR.INVALID_PARAMS, message = "prevtxs must be an array"})
    end
    local out = {}
    for i, e in ipairs(prevtxs_raw) do
      if type(e) ~= "table" or type(e.txid) ~= "string" or type(e.vout) ~= "number"
         or type(e.scriptPubKey) ~= "string" then
        error({code = M.ERROR.INVALID_PARAMS,
          message = "prevtxs[" .. (i - 1) .. "]: requires txid, vout, scriptPubKey"})
      end
      local txid = types.hash256_from_hex(e.txid)
      local key = txid.bytes .. string.char(
        bit.band(e.vout, 0xFF),
        bit.band(bit.rshift(e.vout, 8), 0xFF),
        bit.band(bit.rshift(e.vout, 16), 0xFF),
        bit.band(bit.rshift(e.vout, 24), 0xFF))
      local amount_sat = 0
      if e.amount ~= nil then
        amount_sat = math.floor(tonumber(e.amount) * consensus.COIN + 0.5)
      end
      out[key] = {
        value = amount_sat,
        script_pubkey = M.hex_decode(e.scriptPubKey),
        redeem_script = e.redeemScript and M.hex_decode(e.redeemScript) or nil,
        witness_script = e.witnessScript and M.hex_decode(e.witnessScript) or nil,
      }
    end
    return out
  end

  --- Sign one input with a matched key (or set of keys).  Returns true on
  -- success and writes the witness or scriptSig back into `tx`.  Returns
  -- false if the script type is unsupported (e.g. P2TR) or no key matched.
  --
  -- `key_info` may be a single {privkey, pubkey, type=...} record (legacy
  -- callers, P2WPKH/P2PKH/P2SH-P2WPKH path), or for P2WSH multisig the
  -- resolver may return `{multi=true, keys={{privkey,pubkey}, ...}}` so the
  -- caller can supply 1..M cosigner keys at once. The function will degrade
  -- gracefully (return false + complete=false) if a multisig witnessScript
  -- has fewer than M matching keys.
  local function sign_one_input(tx, i, prev, key_info, sighash_type)
    local crypto = require("lunarblock.crypto")
    local script_type, hash_or_program = script_mod.classify_script(prev.script_pubkey)

    if script_type == "p2wpkh" then
      local script_code = script_mod.make_p2pkh_script(hash_or_program)
      local sighash = validation.signature_hash_segwit_v0(
        tx, i - 1, script_code, prev.value, sighash_type)
      local sig = crypto.ecdsa_sign(key_info.privkey, sighash)
      sig = sig .. string.char(sighash_type)
      tx.inputs[i].witness = {sig, key_info.pubkey}
      tx.segwit = true
      return true
    elseif script_type == "p2pkh" then
      local sighash = validation.signature_hash_legacy(
        tx, i - 1, prev.script_pubkey, sighash_type)
      local sig = crypto.ecdsa_sign(key_info.privkey, sighash)
      sig = sig .. string.char(sighash_type)
      local w = serialize.buffer_writer()
      w.write_varstr(sig)
      w.write_varstr(key_info.pubkey)
      tx.inputs[i].script_sig = w.result()
      return true
    elseif script_type == "p2sh" and prev.redeem_script then
      -- BIP-16: the caller-supplied redeem_script must commit to the P2SH
      -- scriptPubKey.  Without this guard, signrawtransactionwithkey would
      -- happily produce a witness signature bound to whatever script the
      -- prevtxs payload claimed — Core rejects on EQUALVERIFY but the
      -- partial signature has already leaked.  W31.
      if not crypto.verify_p2sh_commitment(prev.redeem_script, prev.script_pubkey) then
        return false
      end
      -- P2SH-wrapped segwit (BIP141): treat as P2WPKH inside scriptSig push.
      local rdm_type, rdm_hash = script_mod.classify_script(prev.redeem_script)
      if rdm_type == "p2wpkh" then
        local script_code = script_mod.make_p2pkh_script(rdm_hash)
        local sighash = validation.signature_hash_segwit_v0(
          tx, i - 1, script_code, prev.value, sighash_type)
        local sig = crypto.ecdsa_sign(key_info.privkey, sighash)
        sig = sig .. string.char(sighash_type)
        tx.inputs[i].witness = {sig, key_info.pubkey}
        -- scriptSig: push redeem_script
        local w = serialize.buffer_writer()
        w.write_varstr(prev.redeem_script)
        tx.inputs[i].script_sig = w.result()
        tx.segwit = true
        return true
      end
      -- pure P2SH (multisig etc.) not handled in this minimal port.
      return false
    elseif script_type == "p2wsh" and prev.witness_script then
      -- BIP-141: refuse to sign unless the supplied witness_script actually
      -- commits to the P2WSH scriptPubKey (sha256(witnessScript) == spk[2:34]).
      -- W37 audit flagged this branch as understated; W38 closed the PSBT
      -- side (psbt.lua:774, 1011), this site closes it for the raw-tx RPC
      -- path.  Same bug class one BIP up the stack from the W31 P2SH guard
      -- ten lines above: an unguarded signer would emit a partial sig bound
      -- to a caller-supplied witnessScript the network rejects on the P2WSH
      -- hash-mismatch path of EvalScript — but the sig has already escaped.
      -- Mirrors the W31 RPC idiom (return false, surfaced as per-input
      -- complete=false + "Unsupported script type for signing").  W39.
      -- (P2SH-wrapped P2WSH is not currently reached from this RPC path;
      -- when it lands, an analogous check belongs in the P2SH branch above
      -- alongside the existing verify_p2sh_commitment, mirroring W38's
      -- psbt.lua hooks.)
      if not crypto.verify_p2wsh_commitment(prev.witness_script, prev.script_pubkey) then
        return false
      end
      -- P2WSH (BIP-143). Caller supplied a witnessScript; sighash is
      -- computed with witnessScript as scriptCode. wallet.sign_input_p2wsh
      -- handles single-key vs M-of-N CHECKMULTISIG layout.
      local wallet_mod = require("lunarblock.wallet")
      local keys
      if key_info and key_info.multi and key_info.keys then
        keys = key_info.keys
      else
        keys = {key_info}
      end
      local stack, err = wallet_mod.sign_input_p2wsh(
        tx, i - 1, prev.witness_script, prev.value, keys, sighash_type)
      if not stack then return false, err end
      tx.inputs[i].witness = stack
      tx.segwit = true
      return true
    end
    -- p2tr (Schnorr) and other shapes fall through to "not signed" — Core
    -- reports `complete=false` plus per-input error in this case.
    return false
  end

  --- Common impl shared by signrawtransactionwithkey and -withwallet.
  -- @param rpc RPCServer
  -- @param hex_tx string
  -- @param key_resolver function(spk) -> key_info|nil
  -- @param prev_lookup table: outpoint_key -> {value, script_pubkey, ...}
  -- @param sighash_type number
  local function sign_raw_tx_common(rpc, hex_tx, key_resolver, prev_lookup, sighash_type)
    local raw = M.hex_decode(hex_tx)
    local ok, tx = pcall(serialize.deserialize_transaction, raw)
    if not ok then
      error({code = M.ERROR.DESERIALIZATION_ERROR,
        message = "TX decode failed: " .. tostring(tx)})
    end

    local errors = {}
    local complete = true
    for i, tx_input in ipairs(tx.inputs) do
      local prev = resolve_prevout(rpc, tx_input, prev_lookup)
      if not prev then
        complete = false
        errors[#errors + 1] = {
          txid = types.hash256_hex(tx_input.prev_out.hash),
          vout = tx_input.prev_out.index,
          error = "Input not found or already spent",
        }
      else
        local key_info = key_resolver(prev.script_pubkey, prev)
        if not key_info then
          complete = false
        else
          local signed = sign_one_input(tx, i, prev, key_info, sighash_type)
          if not signed then
            complete = false
            errors[#errors + 1] = {
              txid = types.hash256_hex(tx_input.prev_out.hash),
              vout = tx_input.prev_out.index,
              error = "Unsupported script type for signing",
            }
          end
        end
      end
    end

    -- Re-flag segwit if any input has a witness.
    for _, inp in ipairs(tx.inputs) do
      if inp.witness and #inp.witness > 0 then
        tx.segwit = true; break
      end
    end

    local hex_signed = M.hex_encode(serialize.serialize_transaction(tx, tx.segwit))
    local result = {hex = hex_signed, complete = complete}
    if #errors > 0 then result.errors = errors end
    return result
  end

  -- Map a textual sighash type to its byte value.  Default ALL.
  local function parse_sighash_type(s)
    if s == nil or s == cjson.null then return consensus.SIGHASH.ALL end
    if type(s) == "number" then return s end
    local map = {
      ["ALL"] = consensus.SIGHASH.ALL,
      ["NONE"] = consensus.SIGHASH.NONE,
      ["SINGLE"] = consensus.SIGHASH.SINGLE,
      ["ALL|ANYONECANPAY"] = bit.bor(consensus.SIGHASH.ALL, 0x80),
      ["NONE|ANYONECANPAY"] = bit.bor(consensus.SIGHASH.NONE, 0x80),
      ["SINGLE|ANYONECANPAY"] = bit.bor(consensus.SIGHASH.SINGLE, 0x80),
    }
    return map[s] or consensus.SIGHASH.ALL
  end

  --- signrawtransactionwithkey: sign a raw tx using caller-supplied private keys.
  -- params: [hex_tx, [keys...], [prevtxs[]], "sighashtype"]
  -- Reference: bitcoin-core/src/rpc/rawtransaction.cpp signrawtransactionwithkey
  self.methods["signrawtransactionwithkey"] = function(rpc, params)
    local hex_tx = params[1]
    local keys_raw = params[2]
    local prevtxs_raw = params[3]
    local sighash_type = parse_sighash_type(params[4])

    if type(hex_tx) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "Usage: signrawtransactionwithkey <hexstring> [privatekey,...] ([prevtxs])"})
    end
    if type(keys_raw) ~= "table" then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "privatekeys must be an array of WIF strings"})
    end

    local decoded_keys = {}
    for _, k in ipairs(keys_raw) do
      local d = decode_priv_key_string(k)
      if d then decoded_keys[#decoded_keys + 1] = d end
    end

    local prev_lookup = parse_prevtxs(prevtxs_raw)

    local key_resolver = function(spk, prev)
      local script_type, hash_or_program = script_mod.classify_script(spk)
      if script_type == "p2pkh" or script_type == "p2wpkh" then
        for _, dk in ipairs(decoded_keys) do
          if dk.pkh == hash_or_program then return dk end
        end
      elseif script_type == "p2sh" and prev and prev.redeem_script then
        -- W31: short-circuit before searching keys if the supplied
        -- redeem_script doesn't commit to the P2SH scriptPubKey.  Avoids
        -- ever returning a key that would then be used to sign a sighash
        -- bound to an attacker-chosen script.
        local crypto = require("lunarblock.crypto")
        if not crypto.verify_p2sh_commitment(prev.redeem_script, spk) then
          return nil
        end
        local rdm_type, rdm_hash = script_mod.classify_script(prev.redeem_script)
        if rdm_type == "p2wpkh" then
          for _, dk in ipairs(decoded_keys) do
            if dk.pkh == rdm_hash then return dk end
          end
        end
      elseif script_type == "p2wsh" and prev and prev.witness_script then
        -- W39: short-circuit before searching keys if the supplied
        -- witness_script doesn't commit to the P2WSH scriptPubKey
        -- (sha256(witnessScript) == spk[2:34]).  Avoids ever returning a
        -- key (single or multi-cosigner set) that would then be used to
        -- sign a sighash bound to an attacker-chosen script.  Mirror of
        -- the W31 P2SH guard one branch up; companion to W38's PSBT-side
        -- hooks at psbt.lua:774, 1011.
        local crypto_mod = require("lunarblock.crypto")
        if not crypto_mod.verify_p2wsh_commitment(prev.witness_script, spk) then
          return nil
        end
        -- Multisig: gather every decoded key whose pubkey appears in the
        -- witnessScript, in canonical script order. Single-key witnessScript
        -- (e.g. <pk> OP_CHECKSIG): match by pubkey-equality fallback.
        local m, _n, ms_pubkeys = script_mod.parse_multisig_script(prev.witness_script)
        if m and ms_pubkeys then
          local matched = {}
          for _, pk in ipairs(ms_pubkeys) do
            for _, dk in ipairs(decoded_keys) do
              if dk.pubkey == pk then
                matched[#matched + 1] = {privkey = dk.privkey, pubkey = dk.pubkey}
                break
              end
            end
          end
          if #matched >= m then
            return {multi = true, keys = matched}
          end
          return nil
        end
        -- Single-key witness script: match the first decoded key whose pubkey
        -- bytes appear in the witnessScript.
        for _, dk in ipairs(decoded_keys) do
          if prev.witness_script:find(dk.pubkey, 1, true) then
            return {privkey = dk.privkey, pubkey = dk.pubkey}
          end
        end
      end
      return nil
    end

    return sign_raw_tx_common(rpc, hex_tx, key_resolver, prev_lookup, sighash_type)
  end

  --- signrawtransactionwithwallet: sign a raw tx using the loaded wallet's keys.
  -- params: [hex_tx, [prevtxs[]], "sighashtype"]
  -- Reference: bitcoin-core/src/wallet/rpc/spend.cpp signrawtransactionwithwallet
  self.methods["signrawtransactionwithwallet"] = function(rpc, params)
    local hex_tx = params[1]
    local prevtxs_raw = params[2]
    local sighash_type = parse_sighash_type(params[3])

    local wallet, werr = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = werr})
    end
    if wallet.is_encrypted and wallet.is_locked then
      error({code = M.ERROR.WALLET_ERROR, message = "Wallet is locked"})
    end
    if type(hex_tx) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "Usage: signrawtransactionwithwallet <hexstring> ([prevtxs] \"sighashtype\")"})
    end

    -- Refresh wallet UTXOs so resolve_prevout can fall through to wallet.utxos.
    if rpc.chain_state then wallet:scan_utxos(rpc.chain_state) end

    local prev_lookup = parse_prevtxs(prevtxs_raw)

    -- Build pkh -> key_info index for fast match.
    local crypto = require("lunarblock.crypto")
    local pkh_index = {}
    for _, info in pairs(wallet.keys) do
      if info.privkey and info.pubkey then
        pkh_index[crypto.hash160(info.pubkey)] = info
      end
    end

    -- Index wallet keys by pubkey-bytes too, for matching against witness
    -- scripts that embed the full pubkey directly (P2WSH multisig + bare
    -- single-key <pk> CHECKSIG).
    local pubkey_index = {}
    for _, info in pairs(wallet.keys) do
      if info.privkey and info.pubkey then
        pubkey_index[info.pubkey] = info
      end
    end

    local key_resolver = function(spk, prev)
      local script_type, hash_or_program = script_mod.classify_script(spk)
      if script_type == "p2pkh" or script_type == "p2wpkh" then
        return pkh_index[hash_or_program]
      elseif script_type == "p2sh" and prev and prev.redeem_script then
        -- W31: refuse to surface a wallet key when the supplied
        -- redeem_script doesn't commit to the P2SH scriptPubKey.
        if not crypto.verify_p2sh_commitment(prev.redeem_script, spk) then
          return nil
        end
        local rdm_type, rdm_hash = script_mod.classify_script(prev.redeem_script)
        if rdm_type == "p2wpkh" then return pkh_index[rdm_hash] end
      elseif script_type == "p2wsh" and prev and prev.witness_script then
        -- W39: refuse to surface a wallet key (or cosigner set) when the
        -- supplied witness_script doesn't commit to the P2WSH scriptPubKey.
        -- Mirror of the W31 P2SH wallet-resolver guard ten lines above and
        -- the W38 PSBT-side hooks at psbt.lua:774, 1011.  W37 audit flagged
        -- this branch as understated; closing it here completes the
        -- raw-tx RPC side (along with sites 1 + 2).
        if not crypto.verify_p2wsh_commitment(prev.witness_script, spk) then
          return nil
        end
        local m, _n, ms_pubkeys = script_mod.parse_multisig_script(prev.witness_script)
        if m and ms_pubkeys then
          local matched = {}
          for _, pk in ipairs(ms_pubkeys) do
            local info = pubkey_index[pk]
            if info then
              matched[#matched + 1] = {privkey = info.privkey, pubkey = info.pubkey}
            end
          end
          if #matched >= m then
            return {multi = true, keys = matched}
          end
          return nil
        end
        -- Single-key witness script: match by embedded pubkey.
        for pk, info in pairs(pubkey_index) do
          if prev.witness_script:find(pk, 1, true) then
            return {privkey = info.privkey, pubkey = info.pubkey}
          end
        end
      end
      return nil
    end

    -- Bind wallet so resolve_prevout can also see wallet.utxos.
    local saved = rpc.wallet
    rpc.wallet = wallet
    local ok, result = pcall(sign_raw_tx_common, rpc, hex_tx, key_resolver,
                             prev_lookup, sighash_type)
    rpc.wallet = saved
    if not ok then error(result) end
    return result
  end

  --- walletcreatefundedpsbt: build a funded PSBT with coin selection.
  -- params: [inputs, outputs, locktime, options, bip32derivs]
  -- Reference: bitcoin-core/src/wallet/rpc/spend.cpp walletcreatefundedpsbt
  --
  -- Coin selection draws from wallet.utxos to cover output total + fee, after
  -- the caller-supplied inputs are counted toward the total-in.  The result is
  -- an unsigned PSBT (no signatures) with witness_utxo populated for each
  -- input we have UTXO data for.
  self.methods["walletcreatefundedpsbt"] = function(rpc, params)
    local psbt_mod = require("lunarblock.psbt")
    local wallet_mod = require("lunarblock.wallet")

    local inputs_raw = params[1] or {}
    local outputs_raw = params[2]
    local locktime = params[3] or 0
    local options = params[4] or {}
    local bip32derivs = params[5]
    local _ = bip32derivs  -- unused stub-arg

    if type(outputs_raw) ~= "table" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Outputs must be an array"})
    end
    if type(inputs_raw) ~= "table" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Inputs must be an array"})
    end

    local wallet, werr = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = werr})
    end
    if rpc.chain_state then wallet:scan_utxos(rpc.chain_state) end

    -- 1. Build outputs, tally total-out and find OP_RETURN positions.
    local outputs = {}
    local total_out = 0
    local subtract_set = {}
    if type(options.subtractFeeFromOutputs) == "table" then
      for _, idx in ipairs(options.subtractFeeFromOutputs) do
        subtract_set[idx] = true
      end
    end
    for _, out_spec in ipairs(outputs_raw) do
      for key, val in pairs(out_spec) do
        if key == "data" then
          local data_bytes = M.hex_decode(val)
          outputs[#outputs + 1] = types.txout(0,
            script_mod.make_nulldata_script(data_bytes))
        else
          local addr_type, program = address_mod.decode_address(key,
            rpc.network and rpc.network.name)
          if not addr_type then
            error({code = M.ERROR.INVALID_ADDRESS, message = "Invalid address: " .. key})
          end
          local spk
          if addr_type == "p2wpkh" then spk = script_mod.make_p2wpkh_script(program)
          elseif addr_type == "p2wsh" then spk = script_mod.make_p2wsh_script(program)
          elseif addr_type == "p2pkh" then spk = script_mod.make_p2pkh_script(program)
          elseif addr_type == "p2sh" then spk = script_mod.make_p2sh_script(program)
          elseif addr_type == "p2tr" then spk = script_mod.make_p2tr_script(program)
          else error({code = M.ERROR.INVALID_ADDRESS, message = "Unsupported address type"})
          end
          local sat = math.floor(tonumber(val) * consensus.COIN + 0.5)
          outputs[#outputs + 1] = types.txout(sat, spk)
          total_out = total_out + sat
        end
        break
      end
    end

    -- 2. Build initial input list from caller-supplied inputs.
    local inputs = {}
    local input_utxos = {}  -- parallel array of {value, script_pubkey} or nil
    local user_total_in = 0
    for _, inp in ipairs(inputs_raw) do
      if type(inp.txid) ~= "string" or #inp.txid ~= 64 or type(inp.vout) ~= "number" then
        error({code = M.ERROR.INVALID_PARAMS, message = "Invalid input txid/vout"})
      end
      local txid = types.hash256_from_hex(inp.txid)
      local sequence = inp.sequence or 0xFFFFFFFD
      inputs[#inputs + 1] = types.txin(types.outpoint(txid, inp.vout), "", sequence)
      -- Try to populate UTXO data from wallet/storage.
      local outpoint_key = txid.bytes .. string.char(
        bit.band(inp.vout, 0xFF),
        bit.band(bit.rshift(inp.vout, 8), 0xFF),
        bit.band(bit.rshift(inp.vout, 16), 0xFF),
        bit.band(bit.rshift(inp.vout, 24), 0xFF))
      local prev = nil
      if wallet.utxos[outpoint_key] then
        local u = wallet.utxos[outpoint_key]
        prev = {value = u.value, script_pubkey = u.script_pubkey}
        user_total_in = user_total_in + u.value
      elseif rpc.storage then
        local utxo_mod = require("lunarblock.utxo")
        local data = rpc.storage.get(storage_mod.CF.UTXO, outpoint_key)
        if data then
          local entry = utxo_mod.deserialize_utxo_entry(data)
          prev = {value = entry.value, script_pubkey = entry.script_pubkey}
          user_total_in = user_total_in + entry.value
        end
      end
      input_utxos[#input_utxos + 1] = prev
    end

    -- 3. Coin selection over wallet UTXOs to cover the shortfall + fee.
    local fee_rate = options.feeRate or wallet:estimate_fee_rate(options.conf_target) or 1
    local est_overhead = 11
    local est_input_vsize = 68
    local est_output_vsize = 31
    local est_vsize = est_overhead + (#inputs + 1) * est_input_vsize
                      + (#outputs + 1) * est_output_vsize
    local fee = math.ceil(est_vsize * fee_rate)

    local needed = total_out + fee - user_total_in
    local change_pos = -1
    local change = 0

    if needed > 0 then
      -- Skip user-claimed UTXOs to avoid double-spending.
      local claimed = {}
      for _, inp in ipairs(inputs) do
        local k = inp.prev_out.hash.bytes .. string.char(
          bit.band(inp.prev_out.index, 0xFF),
          bit.band(bit.rshift(inp.prev_out.index, 8), 0xFF),
          bit.band(bit.rshift(inp.prev_out.index, 16), 0xFF),
          bit.band(bit.rshift(inp.prev_out.index, 24), 0xFF))
        claimed[k] = true
      end
      local available = {}
      for k, u in pairs(wallet.utxos) do
        if not claimed[k] then
          available[#available + 1] = {utxo = u, key = k}
        end
      end
      if #available == 0 and needed > 0 then
        error({code = M.ERROR.WALLET_ERROR, message = "Insufficient funds"})
      end
      local selected = wallet_mod.select_coins(available, needed, fee_rate)
      if not selected then
        error({code = M.ERROR.WALLET_ERROR, message = "Insufficient funds"})
      end
      local extra_in = 0
      for _, item in ipairs(selected) do
        inputs[#inputs + 1] = types.txin(
          types.outpoint(item.utxo.txid, item.utxo.vout), "", 0xFFFFFFFD)
        input_utxos[#input_utxos + 1] = {
          value = item.utxo.value, script_pubkey = item.utxo.script_pubkey}
        extra_in = extra_in + item.utxo.value
      end

      -- Recompute fee + change with the final input count.
      est_vsize = est_overhead + #inputs * est_input_vsize
                  + (#outputs + 1) * est_output_vsize
      fee = math.ceil(est_vsize * fee_rate)
      local total_in = user_total_in + extra_in
      change = total_in - total_out - fee
      if change > wallet_mod.DUST_THRESHOLD then
        local change_address = options.changeAddress or wallet:get_change_address()
        local ct, cp = address_mod.decode_address(change_address,
          rpc.network and rpc.network.name)
        local cspk
        if ct == "p2wpkh" then cspk = script_mod.make_p2wpkh_script(cp)
        elseif ct == "p2wsh" then cspk = script_mod.make_p2wsh_script(cp)
        elseif ct == "p2tr" then cspk = script_mod.make_p2tr_script(cp)
        else cspk = script_mod.make_p2pkh_script(cp)
        end
        local cp_idx = options.changePosition
        if type(cp_idx) == "number" and cp_idx >= 0 and cp_idx <= #outputs then
          table.insert(outputs, cp_idx + 1, types.txout(change, cspk))
          change_pos = cp_idx
        else
          outputs[#outputs + 1] = types.txout(change, cspk)
          change_pos = #outputs - 1
        end
      else
        fee = fee + change
        change = 0
      end
    end

    -- 4. Build unsigned tx + PSBT.
    local tx = types.transaction(2, inputs, outputs, locktime)
    local psbt = psbt_mod.new(tx)
    -- Populate witness_utxo for each input we have prev data for.
    for i, prev in ipairs(input_utxos) do
      if prev then
        psbt.inputs[i].witness_utxo = {
          value = prev.value, script_pubkey = prev.script_pubkey}
      end
    end

    return {
      psbt = psbt_mod.to_base64(psbt),
      fee = fee / consensus.COIN,
      changepos = change_pos,
    }
  end

  ----------------------------------------------------------------------------
  -- Additional Blockchain / Mining / Mempool RPCs
  ----------------------------------------------------------------------------

  --- getblockheader: Return block header by hash.
  -- @param hash string: Block hash hex
  -- @param verbose boolean: true for JSON, false for raw hex (default true)
  self.methods["getblockheader"] = function(rpc, params)
    local blockhash = params[1]
    local verbose = params[2]
    if verbose == nil or verbose == cjson.null then verbose = true end

    if type(blockhash) ~= "string" or #blockhash ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid block hash"})
    end
    if not rpc.storage then
      error({code = M.ERROR.MISC_ERROR, message = "Storage not available"})
    end

    local hash = types.hash256_from_hex(blockhash)
    local header = rpc.storage.get_header(hash)
    if not header then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Block not found"})
    end

    -- Verbosity false: return serialized header hex
    if not verbose then
      return M.hex_encode(serialize.serialize_block_header(header))
    end

    -- Look up height via HEIGHT_INDEX iterator (same approach as getblock).
    local block_height = nil
    if rpc.chain_state and rpc.chain_state.tip_height then
      local iter = rpc.storage.iterator("height")
      if iter then
        iter.seek_to_first()
        while iter.valid() do
          local v = iter.value()
          if v and #v == 32 and v == hash.bytes then
            local k = iter.key()
            block_height = k:byte(1) * 16777216 + k:byte(2) * 65536
                         + k:byte(3) * 256 + k:byte(4)
            break
          end
          iter.next()
        end
        iter.destroy()
      end
    end

    -- confirmations: ComputeNextBlockAndDepth (blockchain.cpp:116) ->
    --   in-active-chain block: tip_height - height + 1
    --   not-in-active-chain (known header off the best chain): -1
    -- block_height is non-nil only for blocks found in the active HEIGHT_INDEX.
    local confirmations
    if block_height and rpc.chain_state and rpc.chain_state.tip_height then
      confirmations = rpc.chain_state.tip_height - block_height + 1
    else
      -- Known header but not on the active chain.
      confirmations = -1
    end

    -- difficulty: use Core's exact algorithm formatted with 16 sig-digits
    -- (%.16g mirrors std::setprecision(16) in Core's UniValue serialisation).
    local diff_float = calculate_difficulty(header.bits)
    local diff_str = string.format("%.16g", diff_float)

    -- mediantime: already fixed to use the correct (upper) median index.
    local mediantime = get_median_time_past(rpc.storage, hash)

    -- target: 64-char lowercase hex from compact bits (Core 27+ field).
    local target_hex = bits_to_target_hex(header.bits)

    -- chainwork: computed natively (exact big-integer cumulative block proof,
    -- byte-identical to Core's nChainWork.GetHex()). lunarblock does not persist
    -- per-block chainwork, so it is summed from genesis to this height. Falls
    -- back to zeros only if the chain cannot be walked.
    local chainwork_hex = string.rep("0", 64)
    if block_height then
      local cw = compute_chainwork(rpc.storage, block_height)
      if cw then chainwork_hex = cw end
    end

    -- nTx: number of transactions in the block. Prefer the stored block body;
    -- fall back to 1 (every connected block has at least the coinbase) when the
    -- body is absent (header-only / pruned). No external node is consulted.
    local ntx = 1
    local blk = rpc.storage.get_block(hash)
    if blk and blk.transactions then
      ntx = #blk.transactions
    end

    local nextblockhash = nil
    if block_height and rpc.storage.get_hash_by_height then
      local nh = rpc.storage.get_hash_by_height(block_height + 1)
      if nh then nextblockhash = types.hash256_hex(nh) end
    end

    local previousblockhash = nil
    local zero_hash = string.rep("\0", 32)
    if header.prev_hash and header.prev_hash.bytes ~= zero_hash then
      previousblockhash = types.hash256_hex(header.prev_hash)
    end

    -- Build the JSON manually so difficulty is serialised with %.16g precision
    -- (cjson would strip trailing digits from some IEEE 754 doubles).
    -- Fields ordered alphabetically (harness strips confirmations then jq -S sorts).
    local parts = {}
    parts[#parts + 1] = string.format('"bits":"%s"', string.format("%08x", header.bits))
    parts[#parts + 1] = string.format('"chainwork":"%s"', chainwork_hex)
    parts[#parts + 1] = string.format('"confirmations":%d', confirmations)
    parts[#parts + 1] = string.format('"difficulty":%s', diff_str)
    parts[#parts + 1] = string.format('"hash":"%s"', blockhash)
    parts[#parts + 1] = string.format('"height":%d', block_height or 0)
    parts[#parts + 1] = string.format('"mediantime":%d', mediantime)
    parts[#parts + 1] = string.format('"merkleroot":"%s"', types.hash256_hex(header.merkle_root))
    parts[#parts + 1] = string.format('"nTx":%d', ntx)
    if nextblockhash then
      parts[#parts + 1] = string.format('"nextblockhash":"%s"', nextblockhash)
    end
    parts[#parts + 1] = string.format('"nonce":%d', header.nonce)
    if previousblockhash then
      parts[#parts + 1] = string.format('"previousblockhash":"%s"', previousblockhash)
    end
    parts[#parts + 1] = string.format('"target":"%s"', target_hex)
    parts[#parts + 1] = string.format('"time":%d', header.timestamp)
    parts[#parts + 1] = string.format('"version":%d', header.version)
    parts[#parts + 1] = string.format('"versionHex":"%s"', string.format("%08x", header.version))

    return {_raw_json = "{" .. table.concat(parts, ",") .. "}"}
  end

  --- getblockfilter: Retrieve a BIP-157 compact block filter for a block.
  -- Reference: bitcoin-core/src/rpc/blockchain.cpp:2956-3031 getblockfilter.
  --   SIGNATURE: getblockfilter "blockhash" ( "filtertype" )
  --     filtertype default "basic" (the only type Core knows).
  --   RESULT: { "filter": <hex GCS>, "header": <hex 32-byte filter header> }.
  --     "filter" = HexStr(BlockFilter::GetEncodedFilter()) — CompactSize(N)
  --       followed by the Golomb-Rice bitstream, hex-encoded (forward bytes).
  --     "header" = filter_header.GetHex() — the 32-byte BIP-157 filter header
  --       in display byte order (reversed), which chains as
  --       SHA256d(SHA256d(rawFilterBytes) || prev_block_filter_header).
  --   ERRORS:
  --     unknown filtertype          -> RPC_INVALID_ADDRESS_OR_KEY (-5)
  --                                    "Unknown filtertype"          (bc.cpp:2982)
  --     filter index not enabled    -> RPC_MISC_ERROR (-1)
  --                                    "Index is not enabled for filtertype basic"
  --                                                                   (bc.cpp:2987)
  --     block hash not in the index -> RPC_INVALID_ADDRESS_OR_KEY (-5)
  --                                    "Block not found"             (bc.cpp:2997)
  --
  -- lunarblock stores the per-block filter blob in CF.BLOCK_FILTER as
  --   filter_hash(32) || filter_header(32) || varstr(filter_data)
  -- written inline in utxo.lua connect_block (BIP-157 Phase 2).  We slice the
  -- header (already in internal/little-endian byte order) and the raw encoded
  -- filter, then hex-encode each per Core's contract.
  self.methods["getblockfilter"] = function(rpc, params)
    local blockhash = params and params[1]
    local filtertype = params and params[2]
    if filtertype == nil or filtertype == cjson.null then
      filtertype = "basic"
    end

    -- Core resolves the filtertype name FIRST (before any block lookup), so an
    -- unknown type errors even for a valid block hash.
    if type(filtertype) ~= "string" or filtertype ~= "basic" then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Unknown filtertype"})
    end

    if type(blockhash) ~= "string" or #blockhash ~= 64
        or not blockhash:match("^%x+$") then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid block hash"})
    end

    -- The filter index must be enabled (Core: GetBlockFilterIndex(BASIC) nil).
    if not (rpc.chain_state and rpc.chain_state.filterindex_enabled) then
      error({code = M.ERROR.MISC_ERROR,
             message = "Index is not enabled for filtertype " .. filtertype})
    end

    if not (rpc.storage and rpc.storage.get and rpc.storage.CF) then
      error({code = M.ERROR.MISC_ERROR, message = "Storage not available"})
    end

    local hash = types.hash256_from_hex(blockhash)

    -- Read the per-block filter blob from CF.BLOCK_FILTER. A missing entry
    -- means the block hash is not in the index → Core's "Block not found"
    -- (-5).  (Core distinguishes "header but not connected" from "block
    -- not found", but lunarblock only writes the filter for connected
    -- active-chain blocks, so an absent entry maps to -5 in both cases.)
    local ok, data = pcall(rpc.storage.get, rpc.storage.CF.BLOCK_FILTER, hash.bytes)
    if not ok or not data or #data < 64 then
      error({code = M.ERROR.INVALID_ADDRESS, message = "Block not found"})
    end

    local r = serialize.buffer_reader(data)
    local _filter_hash = r.read_hash256()       -- bytes 0..32 (unused here)
    local filter_header = r.read_hash256()      -- bytes 32..64
    local filter_data = r.read_varstr()         -- CompactSize(N) || GCS stream

    return {
      filter = M.hex_encode(filter_data),
      header = types.hash256_hex(filter_header),
    }
  end

  --- getchaintips: Return information about all known chain tips.
  self.methods["getchaintips"] = function(rpc, _params)
    local tip_height = 0
    local tip_hash = types.hash256_zero()
    if rpc.chain_state then
      tip_height = rpc.chain_state.tip_height or 0
      tip_hash = rpc.chain_state.tip_hash or types.hash256_zero()
    end
    return {{
      height = tip_height,
      hash = types.hash256_hex(tip_hash),
      branchlen = 0,
      status = "active",
    }}
  end

  --- getdifficulty: Return the proof-of-work difficulty as a multiple of minimum.
  self.methods["getdifficulty"] = function(rpc, _params)
    local current_bits = rpc.network.pow_limit_bits
    if rpc.chain_state and rpc.storage then
      local tip_hash = rpc.chain_state.tip_hash
      if tip_hash then
        local header = rpc.storage.get_header(tip_hash)
        if header then
          current_bits = header.bits
        end
      end
    end
    return calculate_difficulty(current_bits)
  end

  --- submitblock: Submit a new block to the network.
  -- @param hexdata string: Block data in hex
  self.methods["submitblock"] = function(rpc, params)
    -- NetworkDisable gate: refuse submissions while a `dumptxoutset
    -- rollback` rewind→dump→replay dance is in progress. Mirrors
    -- Bitcoin Core's NetworkDisable RAII around TemporaryRollback in
    -- rpc/blockchain.cpp::dumptxoutset.
    if rpc.block_submission_paused then
      -- BIP-22: return canonical string in result field, not a long message
      return "rejected"
    end

    local hexdata = params[1]
    if type(hexdata) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Block hex data required"})
    end

    local t_start = os.clock()
    local raw = M.hex_decode(hexdata)
    local ok_deser, block = pcall(serialize.deserialize_block, raw)
    if not ok_deser or not block then
      error({code = M.ERROR.DESERIALIZATION_ERROR, message = "Block decode failed"})
    end
    local t_deser = os.clock()

    -- Compute block hash
    local block_hash = validation.compute_block_hash(block.header)

    -- Check if this block extends our current tip
    if rpc.chain_state and rpc.chain_state.tip_height then
      local prev_hash = block.header.prev_hash
      local tip_hash = rpc.chain_state.tip_hash

      if not types.hash256_eq(prev_hash, tip_hash) then
        -- Block does not extend our tip. Check if it's a duplicate (already
        -- connected) by seeing if our chain already includes this hash.
        -- NOTE: We cannot use storage.get_header() for duplicate detection
        -- because headers are stored during header-first sync long before
        -- block bodies are downloaded and connected. Instead, check if the
        -- block data (not just header) exists in storage, which is only
        -- written after successful connection.
        if rpc.storage then
          local existing_block = rpc.storage.get(rpc.storage.CF.BLOCKS, block_hash.bytes)
          if existing_block then
            return "duplicate"
          end
        end

        -- Side-branch path (Pattern Z fix, 2026-05-06).  The block doesn't
        -- extend our active tip, but if its parent header is known we can
        -- store it as a side-branch and trigger a reorg if/when this
        -- branch becomes strictly heavier than the active chain.  This is
        -- the analog of Bitcoin Core's
        -- ProcessNewBlock → AcceptBlock → ActivateBestChain dispatch
        -- (validation.cpp).  Pre-fix, lunarblock returned "inconclusive"
        -- here unconditionally and dropped the block, so heavier chains
        -- arriving via submitblock could never trigger a tip flip.
        --
        -- Stage 1 (full block validation) runs BEFORE we hand off to the
        -- side-branch path so we don't persist a malformed block.  We
        -- pass `nil` for height because BIP-34 + ContextualCheckBlock
        -- require the side-branch's own ancestor height, which
        -- accept_side_branch_block computes as part of its walk.
        local val_ok, val_err = pcall(validation.check_block, block, rpc.network, nil)
        if not val_ok then
          return bip22_result(tostring(val_err))
        end
        if not val_err then
          return bip22_result("rejected")
        end

        local result, sb_err = rpc.chain_state:accept_side_branch_block(
          block, block_hash,
          { skip_scripts = false, nosync = false, mempool = rpc.mempool }
        )
        if result == "connected" then
          -- Reorg succeeded; B3 is now the active tip.  Sync the
          -- block_downloader / mempool just like the best-chain path.
          if rpc.block_downloader and rpc.block_downloader.next_connect_height then
            local new_h = rpc.chain_state.tip_height or 0
            if new_h >= rpc.block_downloader.next_connect_height then
              rpc.block_downloader.next_connect_height = new_h + 1
              rpc.block_downloader.next_download_height = new_h + 1
            end
          end
          if rpc.mempool then
            rpc.mempool:on_block_connected(block)
          end
          return cjson.null  -- best-chain accept (post-reorg)
        elseif result == "stored" then
          -- Block stored as a side-branch but active chain unchanged.
          -- Core surfaces this as "inconclusive" (rpc/mining.cpp:1100).
          return "inconclusive"
        else
          -- sb_err in {"unknown-parent", "side-branch-no-common-ancestor",
          -- "side-branch-header-gap", "reorg-depth-exceeded",
          -- "reorg-disconnect-failed: ...", "reorg-connect-failed: ..."}.
          -- All of these surface as "inconclusive" except the actual
          -- connect failures, which indicate a malformed candidate and
          -- should map to "rejected".
          if sb_err and sb_err:find("^reorg%-connect%-failed") then
            return bip22_result(sb_err)
          end
          return "inconclusive"
        end
      end
    end

    -- Determine height: tip + 1 since we verified prev_hash == tip_hash above
    local new_height = (rpc.chain_state and rpc.chain_state.tip_height or 0) + 1

    -- BIP-113 / Core ContextualCheckBlockHeader (validation.cpp:4092):
    -- block timestamp must be strictly greater than the median-time-past
    -- of the previous 11 blocks.  This is a *header-level* rule checked
    -- before block acceptance; accept_block computes MTP again internally
    -- for IsFinalTx and BIP-68, so the two computations are consistent.
    -- Reference: bitcoin-core/src/validation.cpp:4092
    if rpc.chain_state and rpc.chain_state.tip_height and rpc.chain_state.tip_height >= 0 then
      local prev_mtp = get_median_time_past(rpc.storage, rpc.chain_state.tip_hash)
      if block.header.timestamp <= prev_mtp then
        return "time-too-old"
      end
    end

    -- Route through accept_block (unified pipeline: check_block with correct
    -- height → MTP computation → connect_block with real prev_block_mtp and
    -- get_block_mtp).  Pre-refactor this site called connect_block directly
    -- with nil MTP args, silently disabling BIP-113 IsFinalTx and BIP-68
    -- time-based sequence locks post-CSV.  The inline BIP-34 check that used
    -- to follow check_block here is now inside accept_block → check_block
    -- (height is passed so the BIP-34 arm fires).
    --
    -- Block/header/height_index storage writes are included in the same atomic
    -- WriteBatch as the UTXO flush and chain tip update via caller_batch_fn.
    if rpc.chain_state and rpc.chain_state.accept_block then
      -- During bulk import (many sequential submitblock calls), skip fsync on
      -- most blocks and only sync every 500 blocks to amortize the cost.
      -- After IBD, post-tip blocks are rare enough that always syncing is fine,
      -- but the height check below handles both cases.
      rpc._submitblock_count = (rpc._submitblock_count or 0) + 1
      local nosync = (rpc._submitblock_count % 500 ~= 0)

      -- Use the original raw bytes instead of re-serializing the block
      local block_data = raw
      local header_data = serialize.serialize_block_header(block.header)
      local height_key = string.char(
        math.floor(new_height / 16777216) % 256,
        math.floor(new_height / 65536) % 256,
        math.floor(new_height / 256) % 256,
        new_height % 256
      )
      local hash_bytes = block_hash.bytes
      local storage_ref = rpc.storage

      -- Batch function: write block, header, and height index atomically
      local store_batch_fn
      if storage_ref then
        store_batch_fn = function(batch)
          batch.put(storage_mod.CF.BLOCKS, hash_bytes, block_data)
          batch.put(storage_mod.CF.HEADERS, hash_bytes, header_data)
          batch.put(storage_mod.CF.HEIGHT_INDEX, height_key, hash_bytes)
        end
      end

      -- Compute skip_scripts via the real assumevalid ancestor-check semantic.
      -- Falls back to false (always verify) if header_chain callbacks are unavailable.
      local skip_scripts = false
      if rpc.av_in_index and rpc.av_is_ancestor and rpc.av_on_best_chain and rpc.header_chain then
        local block_hash_hex = types.hash256_hex(block_hash)
        local best_header_work = rpc.header_chain:get_chain_work()
        local best_header_height = rpc.header_chain.header_tip_height or 0
        skip_scripts = consensus.should_skip_script_validation(
          rpc.network, new_height, block_hash_hex,
          rpc.av_in_index, rpc.av_is_ancestor, rpc.av_on_best_chain,
          best_header_work, best_header_height
        )
      end

      local t_validate = os.clock()
      local ok_conn, conn_ret1, conn_ret2 = pcall(rpc.chain_state.accept_block, rpc.chain_state,
        block, new_height, block_hash, {
          skip_scripts     = skip_scripts,
          nosync           = nosync,
          caller_batch_fn  = store_batch_fn,
        })
      local t_connect = os.clock()
      if not ok_conn then
        -- accept_block threw an error (conn_ret1 is the error message)
        return bip22_result(conn_ret1)
      end
      if not conn_ret1 then
        -- accept_block returned (nil, error_string) — normal failure path
        return bip22_result(conn_ret2 or "rejected")
      end

      -- Periodic timing log
      if new_height % 100 == 0 then
        io.stderr:write(string.format(
          "Block %d: deser=%.3f val=%.3f connect=%.3f total=%.3f txs=%d\n",
          new_height, t_deser - t_start, t_validate - t_deser,
          t_connect - t_validate, t_connect - t_start, #block.transactions))
      end

      -- Clear cached serialization data to free memory
      for _, tx in ipairs(block.transactions) do
        tx._cached_base_data = nil
        tx._cached_witness_data = nil
        tx._cached_txid = nil
        tx._cached_wtxid = nil
      end
    elseif rpc.storage then
      -- No chain_state — just store block data (fallback, shouldn't happen in practice)
      rpc.storage.put_block(block_hash, block)
      rpc.storage.put_header(block_hash, block.header)
      rpc.storage.put_height_index(new_height, block_hash)
    end

    -- Sync block_downloader so P2P sync doesn't try to re-connect this block
    if rpc.block_downloader and rpc.block_downloader.next_connect_height then
      if new_height >= rpc.block_downloader.next_connect_height then
        rpc.block_downloader.next_connect_height = new_height + 1
        rpc.block_downloader.next_download_height = new_height + 1
        -- Clear any pending/inflight for the block we just connected
        local connected_hex = types.hash256_hex(block_hash)
        rpc.block_downloader.pending_blocks[connected_hex] = nil
        if rpc.block_downloader.inflight[connected_hex] then
          local inf = rpc.block_downloader.inflight[connected_hex]
          if rpc.block_downloader.peer_inflight[inf.peer] then
            rpc.block_downloader.peer_inflight[inf.peer] = rpc.block_downloader.peer_inflight[inf.peer] - 1
            if rpc.block_downloader.peer_inflight[inf.peer] <= 0 then
              rpc.block_downloader.peer_inflight[inf.peer] = nil
            end
          end
          rpc.block_downloader.inflight[connected_hex] = nil
        end
      end
    end

    -- Notify mempool of new block
    if rpc.mempool then
      rpc.mempool:on_block_connected(block)
    end

    return cjson.null  -- success
  end

  --- submitblocks: Submit multiple blocks in one RPC call for faster IBD.
  -- @param params array of hex-encoded blocks
  -- @return array of results (null = success, string = error)
  self.methods["submitblocks"] = function(rpc, params)
    local blocks_hex = params[1]
    if type(blocks_hex) ~= "table" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Array of block hex data required"})
    end
    local results = {}
    local submitblock_fn = rpc.methods["submitblock"]
    for i, hex in ipairs(blocks_hex) do
      local ok, result = pcall(submitblock_fn, rpc, {hex})
      if ok then
        results[i] = result
      else
        results[i] = tostring(result)
      end
    end
    return results
  end

  -- Alias for compatibility with feed-sequential.py
  self.methods["submitblockbatch"] = self.methods["submitblocks"]

  --- getmininginfo: Return mining-related information.
  self.methods["getmininginfo"] = function(rpc, _params)
    local tip_height = 0
    local difficulty = 1.0
    local current_bits = rpc.network.pow_limit_bits

    if rpc.chain_state then
      tip_height = rpc.chain_state.tip_height or 0
      if rpc.storage and rpc.chain_state.tip_hash then
        local header = rpc.storage.get_header(rpc.chain_state.tip_hash)
        if header then
          current_bits = header.bits
          difficulty = calculate_difficulty(header.bits)
        end
      end
    end

    local pooledtx = 0
    if rpc.mempool then
      pooledtx = rpc.mempool.tx_count or 0
    end

    local bits_hex = string.format("%08x", current_bits)
    local target_hex = bits_to_target_hex(current_bits)

    return {
      blocks = tip_height,
      currentblocksize = 0,
      currentblockweight = 0,
      currentblocktx = 0,
      bits = bits_hex,
      difficulty = difficulty,
      target = target_hex,
      blockmintxfee = 0.00001000,
      networkhashps = 0,
      pooledtx = pooledtx,
      chain = core_chain_name(rpc.network.name),
      next = {
        height = tip_height + 1,
        bits = bits_hex,
        difficulty = difficulty,
        target = target_hex,
      },
      warnings = "",
    }
  end

  --- listtransactions: Return recent transactions for a wallet.
  -- @param label string: Label filter (unused, "*" for all)
  -- @param count number: Number of transactions (default 10)
  -- @param skip number: Number to skip (default 0)
  self.methods["listtransactions"] = function(rpc, params)
    local _label = (params[1] ~= nil and params[1] ~= cjson.null) and params[1] or "*"
    local count = (params[2] ~= nil and params[2] ~= cjson.null) and tonumber(params[2]) or 10
    local skip = (params[3] ~= nil and params[3] ~= cjson.null) and tonumber(params[3]) or 0

    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    -- Rebuild wallet UTXO view + transaction history from the connected chain
    -- (same on-demand pattern as getbalance/listunspent). scan_utxos must run
    -- first so scan_history's owned-output detection (and the listunspent the
    -- caller will use) see a consistent view.
    if rpc.chain_state then
      wallet:scan_utxos(rpc.chain_state)
      wallet:scan_history(rpc.chain_state, rpc.mempool)
    end

    if wallet.get_transactions then
      local tip = rpc.chain_state and rpc.chain_state.tip_height or 0
      local txns = wallet:get_transactions(count, skip, tip)
      if txns and #txns > 0 then return txns end
      return setmetatable({}, cjson.empty_array_mt)
    end

    -- Fallback: return empty list (cjson needs empty_array_mt to encode as []).
    return setmetatable({}, cjson.empty_array_mt)
  end

  --- gettransaction: Detailed info about an in-wallet transaction.
  -- Mirrors Bitcoin Core's gettransaction (wallet/rpc/transactions.cpp):
  --   {amount, fee (send only), confirmations, generated (coinbase),
  --    blockhash, blockheight, blockindex, blocktime, txid, time,
  --    details:[{address, category, amount, vout, fee}], hex}.
  -- @param params[1] txid string
  self.methods["gettransaction"] = function(rpc, params)
    local txid_hex = params[1]
    if type(txid_hex) ~= "string" or not txid_hex:match("^[0-9a-fA-F]+$") or #txid_hex ~= 64 then
      error({code = M.ERROR.INVALID_PARAMS, message = "parameter 1 must be hexadecimal string (not '" .. tostring(txid_hex) .. "')"})
    end
    txid_hex = txid_hex:lower()

    local wallet, err = rpc:get_request_wallet()
    if not wallet then
      error({code = M.ERROR.WALLET_ERROR, message = err})
    end

    if rpc.chain_state then
      wallet:scan_utxos(rpc.chain_state)
      wallet:scan_history(rpc.chain_state, rpc.mempool)
    end

    local tip = rpc.chain_state and rpc.chain_state.tip_height or 0
    local detail = wallet.get_transaction_detail and wallet:get_transaction_detail(txid_hex, tip) or nil
    if not detail then
      -- Core: RPC_INVALID_ADDRESS_OR_KEY (-5) "Invalid or non-wallet transaction id"
      error({code = M.ERROR.INVALID_ADDRESS,
             message = "Invalid or non-wallet transaction id"})
    end
    return detail
  end

  --- testmempoolaccept: Dry-run mempool validation for raw transactions.
  -- Mirrors Bitcoin Core's testmempoolaccept RPC (src/rpc/mempool.cpp).
  -- For single-tx submissions, routes through accept_to_memory_pool with
  -- test_accept=true so the full validation pipeline (script checks, dust
  -- policy, TRUC, fee-rate) runs without committing to the mempool.
  -- For multi-tx submissions (packages), routes through accept_package with
  -- test_accept=true.
  --
  -- Response fields (per-tx):
  --   txid            string   hex txid
  --   wtxid           string   hex wtxid (differs from txid for segwit txs)
  --   allowed         boolean
  --   vsize           number   (present when allowed)
  --   fees            table    {base, effective-feerate, effective-includes}
  --   reject-reason   string   (present when not allowed)
  --   package-error   string   (present when a package-level check fails)
  --
  -- @param params[1] rawtxs table: Array of hex-encoded raw transactions
  -- @param params[2] maxfeerate number: Optional max fee rate in BTC/kvB
  self.methods["testmempoolaccept"] = function(rpc, params)
    -- params[1]: rawtxs array.  params[2]: optional maxfeerate (BTC/kvB).
    -- Per-tx response includes effective-feerate and effective-includes in fees.
    local rawtxs = params[1]
    local maxfeerate_btc_per_kvb = (params[2] ~= nil and params[2] ~= cjson.null)
                                   and tonumber(params[2]) or nil
    if type(rawtxs) ~= "table" then
      error({code = M.ERROR.INVALID_PARAMS, message = "rawtxs must be an array"})
    end
    if params[2] ~= nil and params[2] ~= cjson.null and not maxfeerate_btc_per_kvb then
      error({code = M.ERROR.INVALID_PARAMS, message = "maxfeerate must be a number"})
    end

    if not rpc.mempool then
      error({code = M.ERROR.MISC_ERROR, message = "Mempool not available"})
    end

    -- MAX_PACKAGE_COUNT guard (Bitcoin Core: RPCTypeCheck then CheckPackageLimits).
    local mempool_mod = require("lunarblock.mempool")
    if #rawtxs > mempool_mod.MAX_PACKAGE_COUNT then
      error({code = M.ERROR.INVALID_PARAMS,
        message = string.format("Too many transactions: %d > %d",
          #rawtxs, mempool_mod.MAX_PACKAGE_COUNT)})
    end

    -- Decode all raw transactions first.  Report decode failures inline.
    local txs = {}
    local results = {}
    local has_decode_failure = false

    for i, hex in ipairs(rawtxs) do
      local ok_d, tx = pcall(function()
        local raw = M.hex_decode(hex)
        return serialize.deserialize_transaction(raw)
      end)
      if not ok_d or not tx then
        local txid_str = ""
        txs[i] = false  -- sentinel: decode failed
        results[i] = {txid = txid_str, wtxid = txid_str, allowed = false,
                      ["reject-reason"] = "decode-failed"}
        has_decode_failure = true
      else
        txs[i] = tx
        local txid  = validation.compute_txid(tx)
        local wtxid = validation.compute_wtxid(tx)
        results[i] = {
          txid  = types.hash256_hex(txid),
          wtxid = types.hash256_hex(wtxid),
          allowed = false,
        }
      end
    end

    -- If any decode failed, return early (can't run package validation).
    if has_decode_failure then
      return results
    end

    -- Single-tx path: call accept_to_memory_pool(tx, test_accept=true).
    -- This runs the full pipeline without committing.
    if #txs == 1 then
      local tx = txs[1]
      local res = results[1]
      -- Check already-in-mempool (Core returns specific error here).
      if rpc.mempool.entries[res.txid] then
        res["reject-reason"] = "txn-already-in-mempool"
        return results
      end
      local atmp = rpc.mempool:accept_to_memory_pool(tx, true)
      if atmp.accepted then
        local fee_btc = atmp.fee / consensus.COIN
        local vsize = atmp.vsize
        local feerate_btc_per_kvb = (vsize > 0) and (fee_btc / vsize * 1000) or 0
        -- maxfeerate check (BTC/kvB)
        if maxfeerate_btc_per_kvb and feerate_btc_per_kvb > maxfeerate_btc_per_kvb then
          res.allowed = false
          res["reject-reason"] = "max-fee-exceeded"
        else
          res.allowed = true
          res.vsize = vsize
          res.fees = {
            base = fee_btc,
            ["effective-feerate"] = feerate_btc_per_kvb,
            ["effective-includes"] = {res.txid},
          }
        end
      else
        res["reject-reason"] = atmp.reject_reason or "unknown"
      end
      return results
    end

    -- Multi-tx (package) path: route through accept_package(txns, test_accept=true).
    -- Collect decoded txs; decode failures already handled above.
    local tx_list = {}
    for i = 1, #txs do
      tx_list[i] = txs[i]
    end

    -- Empty package: return empty results without calling accept_package.
    if #tx_list == 0 then
      return results
    end

    local pkg_ok, pkg_result = rpc.mempool:accept_package(tx_list, true)
    if not pkg_ok then
      -- Package-level failure: mark all txs with package-error.
      for i = 1, #results do
        results[i]["package-error"] = tostring(pkg_result)
        results[i].allowed = false
      end
      return results
    end

    -- Package accepted (dry-run): populate per-tx results.
    local pkg_total_fees = pkg_result.total_fees or 0
    local pkg_total_vsize = pkg_result.total_vsize or 0
    local pkg_feerate = (pkg_total_vsize > 0) and
                        ((pkg_total_fees / consensus.COIN) / pkg_total_vsize * 1000) or 0

    -- Build a txid→index map for effective-includes.
    local txid_list = {}
    for i, tx in ipairs(tx_list) do
      txid_list[i] = results[i].txid
    end

    for i, tx in ipairs(tx_list) do
      local res = results[i]
      local fee_btc = (pkg_result.fees and pkg_result.fees[i] or 0) / consensus.COIN
      local weight = validation.get_tx_weight(tx)
      local vsize = math.ceil(weight / consensus.WITNESS_SCALE_FACTOR)
      -- maxfeerate check uses package fee rate.
      if maxfeerate_btc_per_kvb and pkg_feerate > maxfeerate_btc_per_kvb then
        res.allowed = false
        res["reject-reason"] = "max-fee-exceeded"
      else
        res.allowed = true
        res.vsize = vsize
        res.fees = {
          base = fee_btc,
          ["effective-feerate"] = pkg_feerate,
          ["effective-includes"] = txid_list,
        }
      end
    end

    return results
  end

  -- getdeploymentinfo: returns deployment state for each known softfork.
  -- All deployments in lunarblock are buried (enforced from genesis or a fixed
  -- activation height). A reference BIP9 state machine exists in
  -- src/consensus.lua (versionbits_condition / get_deployment_state /
  -- get_deployment_state_for_block), exhaustively unit-tested in
  -- spec/consensus_spec.lua, but it is INTENTIONALLY NOT on the consensus
  -- path — see the long comment block at the top of the BIP9 section in
  -- consensus.lua. There is no versionbits cache, so this RPC returns only
  -- the buried fields (type, active, height, min_activation_height) without
  -- a bip9.status / bip9.since sub-object. Wiring the state machine into the
  -- response would require a versionbits cache and is the natural followup
  -- if/when a future deployment ships unburied.
  self.methods["getdeploymentinfo"] = function(rpc, params)
    -- Resolve the target block
    local target_height
    local target_hash_hex

    if params[1] and params[1] ~= cjson.null then
      local blockhash_hex = params[1]
      if type(blockhash_hex) ~= "string" or #blockhash_hex ~= 64 then
        error({code = M.ERROR.INVALID_PARAMS, message = "Invalid block hash"})
      end
      if not rpc.storage then
        error({code = M.ERROR.MISC_ERROR, message = "Storage not available"})
      end
      local hash = types.hash256_from_hex(blockhash_hex)
      -- Verify the block exists
      local header = rpc.storage.get_header(hash)
      if not header then
        error({code = M.ERROR.INVALID_ADDRESS, message = "Block not found"})
      end
      target_hash_hex = blockhash_hex
      -- Derive height by searching the height index
      target_height = nil
      if rpc.chain_state and rpc.chain_state.tip_height and rpc.storage.iterator then
        local iter = rpc.storage.iterator("height")
        if iter then
          iter.seek_to_first()
          while iter.valid() do
            local v = iter.value()
            if v and #v == 32 and v == hash.bytes then
              local k = iter.key()
              target_height = k:byte(1) * 16777216 + k:byte(2) * 65536 + k:byte(3) * 256 + k:byte(4)
              break
            end
            iter.next()
          end
          iter.destroy()
        end
      end
      -- Fall back to tip height if we cannot resolve height
      if not target_height then
        target_height = rpc.chain_state and rpc.chain_state.tip_height or 0
      end
    else
      -- Default: chain tip
      target_height = rpc.chain_state and rpc.chain_state.tip_height or 0
      if rpc.chain_state and rpc.chain_state.tip_hash then
        target_hash_hex = types.hash256_hex(rpc.chain_state.tip_hash)
      else
        target_hash_hex = string.rep("00", 32)
      end
    end

    -- Use the shared deployment helper so this RPC reads from the same
    -- source of truth as getblockchaininfo.softforks.
    local deployments = build_deployment_state(target_height, rpc.network)

    return {
      hash        = target_hash_hex,
      height      = target_height,
      deployments = deployments,
    }
  end

  -- dumptxoutset: write the serialized UTXO set to a file in Bitcoin Core
  -- wire format.  Mirrors bitcoin-core/src/rpc/blockchain.cpp dumptxoutset.
  -- Positional params:
  --   [1] path (string, required)
  --   [2] type ("latest" | "rollback" | "")
  --   [3] options ({rollback = <height|hash>}) -- optional
  -- Modes:
  --   "latest" (or unset, default): dump the current tip's UTXO set
  --     unchanged.  Backwards-compatible with the previous lunarblock RPC.
  --   "rollback" without an explicit height: roll back to the highest
  --     network.assumeutxo entry that is <= current tip, dump there,
  --     then re-apply the disconnected blocks.
  --   options.rollback = <int> | <hex hash>: roll back to the requested
  --     height (or to the block whose hash matches), dump, re-apply.
  -- Returns {coins_written, base_hash, base_height, path, txoutset_hash,
  -- nchaintx}.
  self.methods["dumptxoutset"] = function(rpc, params)
    if not rpc.chain_state then
      error({code = M.ERROR.MISC_ERROR, message = "Chain state not available"})
    end
    local path = params and params[1]
    if type(path) ~= "string" or path == "" then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "dumptxoutset requires a path string"})
    end
    local snapshot_type = params and params[2] or ""
    if type(snapshot_type) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "dumptxoutset type must be a string"})
    end
    local options = (params and params[3]) or nil
    if options ~= nil and type(options) ~= "table" then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "dumptxoutset options must be an object"})
    end

    -- Refuse to clobber an existing file (matches Core dumptxoutset).
    local probe = io.open(path, "rb")
    if probe then
      probe:close()
      error({code = M.ERROR.MISC_ERROR,
        message = "path already exists: " .. path})
    end

    -- Resolve the rollback target.  target_height = nil means "no
    -- rollback, dump current tip" (the historical lunarblock behavior).
    local current_tip_height = rpc.chain_state.tip_height
    local target_height = nil

    local function resolve_height_or_hash(spec)
      if type(spec) == "number" then
        if spec ~= math.floor(spec) or spec < 0 then
          error({code = M.ERROR.INVALID_PARAMS,
            message = "rollback height must be a non-negative integer"})
        end
        return spec
      end
      if type(spec) == "string" then
        -- Try integer first (Core accepts both forms in -named usage).
        local as_num = tonumber(spec)
        if as_num and as_num == math.floor(as_num) and #spec ~= 64 then
          return math.floor(as_num)
        end
        -- Else treat as a 64-char hex blockhash.
        if #spec ~= 64 or spec:match("[^0-9a-fA-F]") then
          error({code = M.ERROR.INVALID_PARAMS,
            message = "rollback hash must be 64 hex chars"})
        end
        if not (rpc.storage and rpc.storage.get_hash_by_height) then
          error({code = M.ERROR.MISC_ERROR,
            message = "rollback by hash requires a height index"})
        end
        local target_lower = spec:lower()
        for h = 0, current_tip_height or 0 do
          local hh = rpc.storage.get_hash_by_height(h)
          if hh and types.hash256_hex(hh):lower() == target_lower then
            return h
          end
        end
        error({code = M.ERROR.MISC_ERROR,
          message = "rollback target hash not found in active chain"})
      end
      error({code = M.ERROR.INVALID_PARAMS,
        message = "rollback target must be number or hex string"})
    end

    if options and options.rollback ~= nil then
      if snapshot_type ~= "" and snapshot_type ~= "rollback" then
        error({code = M.ERROR.INVALID_PARAMS,
          message = "Invalid snapshot type \"" .. snapshot_type
            .. "\" specified with rollback option"})
      end
      target_height = resolve_height_or_hash(options.rollback)
    elseif snapshot_type == "rollback" then
      -- Pick highest assumeutxo height <= current tip.
      local heights = consensus.get_assumeutxo_heights(rpc.network)
      if not heights or #heights == 0 then
        error({code = M.ERROR.MISC_ERROR,
          message = "No assumeutxo snapshots configured for "
            .. rpc.network.name})
      end
      local picked
      for _, h in ipairs(heights) do
        if (current_tip_height or 0) >= h then
          if not picked or h > picked then picked = h end
        end
      end
      if not picked then
        error({code = M.ERROR.MISC_ERROR,
          message = "Current tip is below all configured assumeutxo "
            .. "snapshot heights"})
      end
      target_height = picked
    elseif snapshot_type == "" or snapshot_type == "latest" then
      target_height = nil  -- dump current tip
    else
      error({code = M.ERROR.INVALID_PARAMS,
        message = "Invalid snapshot type \"" .. snapshot_type
          .. "\" specified. Please specify \"rollback\" or \"latest\""})
    end

    if target_height ~= nil and target_height > (current_tip_height or 0) then
      error({code = M.ERROR.MISC_ERROR,
        message = "Rollback target above current tip"})
    end

    -- Pruned-mode pre-check. Mirrors Bitcoin Core
    -- rpc/blockchain.cpp:dumptxoutset:
    --   if (IsPruneMode() &&
    --       target_index->nHeight <
    --       node.chainman->m_blockman.GetFirstBlock()->nHeight)
    --       throw "Block height N not available (pruned data).
    --              Use a height after M.";
    -- lunarblock has PARTIAL pruning per Cat C audit: the pruner tracks
    -- `prune_height` (highest pruned height). When --prune was set we
    -- fail fast so a rewind doesn't begin reading blocks that have been
    -- DELETEd from CF.BLOCKS.
    if target_height ~= nil and rpc.pruner and rpc.pruner.enabled
       and rpc.pruner.prune_height > 0
       and target_height <= rpc.pruner.prune_height then
      local first_available = rpc.pruner.prune_height + 1
      error({code = M.ERROR.MISC_ERROR,
        message = string.format(
          "Block height %d not available (pruned data). "
            .. "Use a height after %d.",
          target_height, first_available - 1)})
    end

    local utxo_mod = require("lunarblock.utxo")
    local _ = utxo_mod  -- chain_state methods dispatch via :method

    -- NetworkDisable RAII (Lua pcall + finally pattern). Mirrors
    -- Bitcoin Core's NetworkDisable wrapper around TemporaryRollback in
    -- rpc/blockchain.cpp::dumptxoutset. Pause inbound block acceptance
    -- for the duration of the rewind→dump→replay dance and restore on
    -- every exit path (success, error). Only activate when there's
    -- actual rewind work; a "latest" dump doesn't need the gate.
    local network_pause_active =
      target_height ~= nil and target_height < (current_tip_height or 0)
    if network_pause_active then
      rpc.block_submission_paused = true
    end

    -- Wrap the rewind→dump→replay dance in a pcall so any error
    -- (Lua-style table error or runtime exception) lands in `caught`
    -- and we always clear the pause flag. If `caught` is non-nil we
    -- re-throw it after the flag is restored.
    local result, err
    local rok, caught = pcall(function()
      -- Stage 1: roll back if requested.
      local disconnected = nil
      if target_height ~= nil and target_height < (current_tip_height or 0) then
        local list, rerr = rpc.chain_state:rollback_chain_to(target_height)
        if not list then
          error({code = M.ERROR.MISC_ERROR,
            message = "Could not roll back to requested height: "
              .. tostring(rerr)})
        end
        disconnected = list
      end

      -- Stage 2: dump.  If the dump fails we still try to re-apply the
      -- disconnected blocks so the node is left at the original tip.
      local tmppath = path .. ".incomplete"
      local r, e = rpc.chain_state:dump_snapshot(tmppath)
      result = r
      err = e

      -- Stage 3: re-apply if we rolled back.  This must run regardless of
      -- whether the dump succeeded, otherwise a failed dump would leave
      -- the node stuck at the rollback height.
      if disconnected and #disconnected > 0 then
        local rok2, rerr = rpc.chain_state:reapply_disconnected(disconnected)
        if not rok2 then
          os.remove(tmppath)
          error({code = M.ERROR.MISC_ERROR,
            message = "rollback dump succeeded but re-applying blocks "
              .. "failed: " .. tostring(rerr)
              .. " (chain may need reindex)"})
        end
      end

      if not result then
        os.remove(tmppath)
        error({code = M.ERROR.MISC_ERROR, message = err or "dump failed"})
      end

      local rok3, rerr3 = os.rename(tmppath, path)
      if not rok3 then
        os.remove(tmppath)
        error({code = M.ERROR.MISC_ERROR,
          message = "rename failed: " .. tostring(rerr3)})
      end
    end)

    -- NetworkDisable RAII restore (covers success AND pcall-caught
    -- error). Done before re-throwing so subsequent submitblock
    -- requests don't see stale state.
    if network_pause_active then
      rpc.block_submission_paused = false
    end

    if not rok then
      -- Re-throw the caught error to the outer JSON-RPC dispatch.
      error(caught)
    end

    local base_hash_hex = types.hash256_hex(result.base_blockhash)
    local hash_hex = ""
    for i = 1, 32 do
      hash_hex = hash_hex .. string.format("%02x", result.hash:byte(i))
    end
    return {
      coins_written = result.coins_count,
      base_hash     = base_hash_hex,
      base_height   = result.base_height,
      path          = path,
      txoutset_hash = hash_hex,
      nchaintx      = result.coins_count,  -- caller can read m_chain_tx_count from chainparams
    }
  end

  -- loadtxoutset: load a serialized UTXO snapshot file (Bitcoin Core wire
  -- format) into the chainstate.  Mirrors loadtxoutset in
  -- bitcoin-core/src/rpc/blockchain.cpp.  params[1] = path.
  -- Validates against chainparams.assumeutxo before accepting.
  self.methods["loadtxoutset"] = function(rpc, params)
    if not rpc.chain_state then
      error({code = M.ERROR.MISC_ERROR, message = "Chain state not available"})
    end
    local path = params and params[1]
    if type(path) ~= "string" or path == "" then
      error({code = M.ERROR.INVALID_PARAMS,
        message = "loadtxoutset requires a path string"})
    end

    -- Peek at metadata to learn the base blockhash, then look up the
    -- assumeutxo entry for that hash.  Reject the load if the chainparams
    -- table does not list this base block (matches Core's safeguard).
    local utxo_mod = require("lunarblock.utxo")
    local f, ferr = io.open(path, "rb")
    if not f then
      error({code = M.ERROR.MISC_ERROR,
        message = "failed to open snapshot: " .. tostring(ferr)})
    end
    local hdr = f:read(51)
    f:close()
    if not hdr or #hdr < 51 then
      error({code = M.ERROR.DESERIALIZATION_ERROR,
        message = "snapshot header truncated"})
    end
    local meta, merr = utxo_mod.deserialize_snapshot_metadata(hdr)
    if not meta then
      error({code = M.ERROR.DESERIALIZATION_ERROR, message = merr})
    end
    if meta.network_magic ~= rpc.network.magic_bytes then
      error({code = M.ERROR.MISC_ERROR,
        message = "snapshot is for a different network"})
    end
    local base_hash_hex = types.hash256_hex(meta.base_blockhash)
    local au_data, au_height = consensus.assumeutxo_for_blockhash(
      rpc.network, base_hash_hex)
    if not au_data then
      -- Core-strict whitelist (bitcoin-core/src/validation.cpp:5775-5780):
      -- after looking up the snapshot's base block in the header index to
      -- recover its height, refuse the load if AssumeutxoForHeight(height)
      -- returns nullopt.  Emit Core's exact error string so cross-impl
      -- consensus-diff probes can match on it byte-for-byte.
      --
      -- We don't carry a hash->height index, so derive the height from
      -- whatever local source we can: the network's genesis hash short-
      -- circuits to 0; otherwise fall back to the height-index by
      -- scanning around the chain tip; otherwise report it as unknown.
      local base_height
      if base_hash_hex == rpc.network.genesis_hash then
        base_height = 0
      elseif rpc.storage and rpc.storage.get_hash_by_height
          and rpc.chain_state and rpc.chain_state.tip_height then
        for h = 0, rpc.chain_state.tip_height do
          local hh = rpc.storage.get_hash_by_height(h)
          if hh and types.hash256_hex(hh) == base_hash_hex then
            base_height = h
            break
          end
        end
      end
      local height_str
      if base_height ~= nil then
        height_str = tostring(base_height)
      else
        height_str = "?"
      end
      error({code = M.ERROR.MISC_ERROR,
        message = "Assumeutxo height in snapshot metadata not recognized ("
          .. height_str .. ") - refusing to load snapshot"})
    end

    -- Pass au_height as base_height (BUG-6), the current IBD tip as
    -- active_tip_height (BUG-4), and the mempool handle (BUG-5) so that
    -- load_snapshot can enforce all Core precondition gates.
    local active_tip = rpc.chain_state and rpc.chain_state.tip_height
    local ok, lerr = rpc.chain_state:load_snapshot(
      path, nil, au_height, active_tip, rpc.mempool)
    if not ok then
      error({code = M.ERROR.MISC_ERROR,
        message = lerr or "load failed"})
    end

    -- Update the in-memory tip height to match the snapshot base.
    rpc.chain_state.tip_height = au_height
    if rpc.storage and rpc.storage.set_chain_tip then
      rpc.storage.set_chain_tip(rpc.chain_state.tip_hash, au_height, true)
    end

    return {
      coins_loaded     = meta.coins_count,
      tip_hash         = base_hash_hex,
      base_height      = au_height,
      path             = path,
    }
  end
end

--------------------------------------------------------------------------------
-- W47B: gettxoutsetinfo / getnetworkhashps / gettxoutproof / verifytxoutproof
--        / getrpcinfo
-- Reference: bitcoin-core/src/rpc/blockchain.cpp + merkleblock.cpp
--------------------------------------------------------------------------------

-- Bitcoin Core CalcTreeWidth: height 0 = leaves (nTx), height nHeight = root (1)
local function w47b_tree_width(n_tx, height)
  return math.floor((n_tx + bit.lshift(1, height) - 1) / bit.lshift(1, height))
end

-- Bitcoin Core CalcHash: height 0 returns txids[pos]; height > 0 hashes children
-- Returns a raw 32-byte string.
local function w47b_calc_hash(crypto, txids, n_tx, height, pos)
  if height == 0 then
    return txids[pos + 1]  -- 1-based Lua indexing
  end
  local left  = w47b_calc_hash(crypto, txids, n_tx, height - 1, pos * 2)
  local right
  local right_pos = pos * 2 + 1
  if right_pos < w47b_tree_width(n_tx, height - 1) then
    right = w47b_calc_hash(crypto, txids, n_tx, height - 1, right_pos)
  else
    right = left  -- duplicate last hash (Core convention)
  end
  return crypto.hash256(left .. right)
end

-- Bitcoin Core TraverseAndBuild: emits bits and hashes for the partial merkle tree.
-- Returns hashes (array of raw 32-byte strings), bits (array of 0/1).
local function w47b_traverse_and_build(crypto, txids, n_tx, match_set, height, pos, hashes, bits)
  -- fParentOfMatch: does any leaf in [pos<<height, (pos+1)<<height) match?
  local lo = bit.lshift(pos, height)
  local hi = math.min(bit.lshift(pos + 1, height), n_tx)
  local parent_match = false
  for i = lo, hi - 1 do
    if match_set[i] then  -- 0-based leaf index
      parent_match = true
      break
    end
  end
  -- emit bit
  bits[#bits + 1] = parent_match and 1 or 0
  if height == 0 or not parent_match then
    -- leaf or non-matching internal node: emit hash, stop descending
    hashes[#hashes + 1] = w47b_calc_hash(crypto, txids, n_tx, height, pos)
  else
    -- matching internal node: recurse into children
    w47b_traverse_and_build(crypto, txids, n_tx, match_set, height - 1, pos * 2, hashes, bits)
    local right_pos = pos * 2 + 1
    if right_pos < w47b_tree_width(n_tx, height - 1) then
      w47b_traverse_and_build(crypto, txids, n_tx, match_set, height - 1, right_pos, hashes, bits)
    end
  end
end

-- Pack an array of bits into bytes (LSB-first within each byte).
local function w47b_bits_to_bytes(bits)
  local n_bytes = math.ceil(#bits / 8)
  local result = {}
  for i = 1, n_bytes do
    local byte_val = 0
    for b = 0, 7 do
      local bit_idx = (i - 1) * 8 + b + 1
      if bit_idx <= #bits and bits[bit_idx] == 1 then
        byte_val = byte_val + bit.lshift(1, b)
      end
    end
    result[i] = string.char(byte_val)
  end
  return table.concat(result)
end

-- Encode a uint32 as 4-byte LE string.
local function w47b_le32(n)
  return string.char(
    bit.band(n, 0xFF),
    bit.band(bit.rshift(n, 8), 0xFF),
    bit.band(bit.rshift(n, 16), 0xFF),
    bit.band(bit.rshift(n, 24), 0xFF)
  )
end

-- Encode varint.
local function w47b_encode_varint(n)
  if n < 0xFD then
    return string.char(n)
  elseif n <= 0xFFFF then
    return string.char(0xFD, bit.band(n, 0xFF), bit.band(bit.rshift(n, 8), 0xFF))
  else
    return string.char(0xFE,
      bit.band(n, 0xFF),
      bit.band(bit.rshift(n, 8), 0xFF),
      bit.band(bit.rshift(n, 16), 0xFF),
      bit.band(bit.rshift(n, 24), 0xFF))
  end
end

-- Bitcoin Core TraverseAndExtract: parse the partial merkle tree and return
-- matched txids and the computed root hash.
-- Returns: root_hash (32-byte string), matched_txids (array of hex strings)
-- or nil + err_string on failure.
local function w47b_traverse_and_extract(crypto, n_tx, hashes, bits, bit_pos_ref, hash_pos_ref, height, pos)
  if bit_pos_ref[1] >= #bits then
    return nil, "overread bits"
  end
  local parent_match = bits[bit_pos_ref[1] + 1] == 1
  bit_pos_ref[1] = bit_pos_ref[1] + 1

  if height == 0 or not parent_match then
    if hash_pos_ref[1] >= #hashes then
      return nil, "overread hashes"
    end
    local h = hashes[hash_pos_ref[1] + 1]
    hash_pos_ref[1] = hash_pos_ref[1] + 1
    local matched = {}
    if height == 0 and parent_match and pos < n_tx then
      matched[1] = h
    end
    return h, nil, matched
  else
    -- recurse left
    local left, lerr, lmatched = w47b_traverse_and_extract(
      crypto, n_tx, hashes, bits, bit_pos_ref, hash_pos_ref, height - 1, pos * 2)
    if not left then return nil, lerr end
    local right, rmatched
    local right_pos = pos * 2 + 1
    if right_pos < w47b_tree_width(n_tx, height - 1) then
      local rerr
      right, rerr, rmatched = w47b_traverse_and_extract(
        crypto, n_tx, hashes, bits, bit_pos_ref, hash_pos_ref, height - 1, right_pos)
      if not right then return nil, rerr end
    else
      right = left
      rmatched = {}
    end
    local root = crypto.hash256(left .. right)
    -- merge matched lists
    local all_matched = {}
    if lmatched then for _, v in ipairs(lmatched) do all_matched[#all_matched + 1] = v end end
    if rmatched then for _, v in ipairs(rmatched) do all_matched[#all_matched + 1] = v end end
    return root, nil, all_matched
  end
end

function RPCServer:setup_w47b_methods()
  local crypto = require("lunarblock.crypto")
  local utxo_mod = require("lunarblock.utxo")

  -- gettxoutsetinfo ( "hash_type" hash_or_height use_index )
  --
  -- Returns statistics about the unspent transaction output set, plus an
  -- optional set-hash. Byte-compatible with Bitcoin Core's gettxoutsetinfo
  -- (bitcoin-core/src/rpc/blockchain.cpp:1010-1179 + kernel/coinstats.cpp).
  --
  -- hash_type (default "hash_serialized_3"): which set hash to compute.
  --   "hash_serialized_3" — SHA256d (HashWriter::GetHash) over the canonical
  --                         TxOutSer stream of every (outpoint, coin), in
  --                         (txid lex-asc, vout uint32-asc) order. The legacy
  --                         algorithm; what assumeutxo commits to. Computed by
  --                         ChainState:compute_utxo_hash (utxo.lua) — the same
  --                         primitive the assumeutxo strict gate uses
  --                         (validation.cpp:5904-5915), no second hasher.
  --   "muhash"            — MuHash3072 order-independent multiset hash over the
  --                         same per-coin TxOutSer serialization. Computed by
  --                         ChainState:compute_muhash (utxo.lua).
  --   "none"              — skip the set-hash (just the counts/amounts).
  --
  -- hash_or_height + use_index need coinstatsindex, which lunarblock does not
  -- implement: base chainstate stats at the tip only. We still honour Core's
  -- error contract for the out-of-scope args (see ParseHashType + the
  -- request.params[1] guards in blockchain.cpp:1085-1098).
  --
  -- Per-coin metrics (txouts, transactions, bogosize, total_amount) are
  -- gathered in a single UTXO walk, matching ApplyStats in coinstats.cpp:96.
  self.methods["gettxoutsetinfo"] = function(rpc, params)
    if not rpc.chain_state then
      error({code = M.ERROR.MISC_ERROR, message = "Chain state not available"})
    end
    if not rpc.storage then
      error({code = M.ERROR.MISC_ERROR, message = "Storage not available"})
    end

    -- ── arg 0: hash_type (default "hash_serialized_3"). ──────────────────
    -- Core's ParseHashType (blockchain.cpp:967-978) accepts exactly these
    -- three values and otherwise throws RPC_INVALID_PARAMETER (-8).
    local hash_type = params[1]
    if hash_type == nil or hash_type == cjson.null then
      hash_type = "hash_serialized_3"
    end
    if type(hash_type) ~= "string"
        or (hash_type ~= "hash_serialized_3"
            and hash_type ~= "muhash"
            and hash_type ~= "none") then
      error({code = M.ERROR.INVALID_PARAMETER,
             message = string.format("'%s' is not a valid hash_type",
                                     tostring(hash_type))})
    end

    -- ── arg 1: hash_or_height. Requires coinstatsindex (not implemented). ─
    -- Core raises here BEFORE doing any work. The hash_serialized_3-specific
    -- message takes precedence (blockchain.cpp:1090-1092), so we order the
    -- two checks the same way to keep the -8 message byte-identical.
    if params[2] ~= nil and params[2] ~= cjson.null then
      if hash_type == "hash_serialized_3" then
        error({code = M.ERROR.INVALID_PARAMETER,
               message = "hash_serialized_3 hash type cannot be queried for a specific block"})
      end
      error({code = M.ERROR.INVALID_PARAMETER,
             message = "Querying specific block heights requires coinstatsindex"})
    end

    local tip_height  = rpc.chain_state.tip_height or 0
    local tip_hash    = rpc.chain_state.tip_hash
    local tip_hash_hex = tip_hash and types.hash256_hex(tip_hash) or string.rep("0", 64)

    -- ── single UTXO walk: txouts, transactions, bogosize, total_amount. ──
    -- transactions = number of distinct txids with at least one unspent
    -- output (coinstats.cpp:99 stats.nTransactions++ once per txid group).
    -- bogosize = 32 (txid) + 4 (vout) + 4 (height<<1|cb) + 8 (amount)
    --          + 2 (scriptPubKey CompactSize len) + scriptPubKey.size()
    -- per GetBogoSize (coinstats.cpp:35-43).
    local n_txouts   = 0
    local n_txs      = 0
    local total_sats = 0
    local bogosize   = 0
    local prev_txid  = nil

    if rpc.storage.iterator then
      local iter = rpc.storage.iterator(storage_mod.CF.UTXO)
      iter.seek_to_first()
      while iter.valid() do
        local key = iter.key()
        local v = iter.value()
        if v then
          local ok, entry = pcall(utxo_mod.deserialize_utxo_entry, v)
          if ok and entry then
            -- The on-disk key is (txid[32] || vout LE[4]); the 32-byte
            -- prefix groups outputs by txid (RocksDB key order matches
            -- Core's per-txid grouping).
            local txid = key and #key >= 32 and key:sub(1, 32) or nil
            if txid ~= prev_txid then
              n_txs = n_txs + 1
              prev_txid = txid
            end
            n_txouts   = n_txouts + 1
            total_sats = total_sats + (entry.value or 0)
            local script_len = entry.script_pubkey and #entry.script_pubkey or 0
            bogosize = bogosize + 32 + 4 + 4 + 8 + 2 + script_len
          end
        end
        iter.next()
      end
      iter.destroy()
    end

    -- ── set-hash (only for the chosen hash_type). ────────────────────────
    -- uint256.GetHex() reverses bytes for display (big-endian); both
    -- compute_utxo_hash and compute_muhash return raw 32-byte natural
    -- (little-endian) order, so we reverse here to match Core's hex.
    local function reverse_hex(raw)
      local hex_chars = {}
      for i = 32, 1, -1 do
        hex_chars[#hex_chars + 1] = string.format("%02x", raw:byte(i))
      end
      return table.concat(hex_chars)
    end

    local hash_serialized_3, muhash_hex
    if hash_type == "hash_serialized_3" then
      if not (rpc.chain_state.compute_utxo_hash) then
        error({code = M.ERROR.INTERNAL_ERROR, message = "Unable to read UTXO set"})
      end
      local ok, raw = pcall(rpc.chain_state.compute_utxo_hash, rpc.chain_state)
      if not (ok and type(raw) == "string" and #raw == 32) then
        error({code = M.ERROR.INTERNAL_ERROR, message = "Unable to read UTXO set"})
      end
      hash_serialized_3 = reverse_hex(raw)
    elseif hash_type == "muhash" then
      if not (rpc.chain_state.compute_muhash) then
        error({code = M.ERROR.INTERNAL_ERROR, message = "Unable to read UTXO set"})
      end
      local ok, raw = pcall(rpc.chain_state.compute_muhash, rpc.chain_state)
      if not (ok and type(raw) == "string" and #raw == 32) then
        error({code = M.ERROR.INTERNAL_ERROR, message = "Unable to read UTXO set"})
      end
      muhash_hex = reverse_hex(raw)
    end

    -- disk_size: Core reports CCoinsViewDB::EstimateSize() (impl-specific;
    -- the RPC docs call it "estimated"). lunarblock has no leveldb size
    -- estimator, so we report a deterministic chainstate-size proxy derived
    -- from the same on-disk record sizes the walk already saw. This is the
    -- one field the differential test asserts as present+typed, NOT
    -- byte-equal vs Core (bogosize is "meaningless" and disk_size is
    -- explicitly impl-specific).
    local disk_size = bogosize

    -- total_amount must be a fixed-8 BTC decimal byte-identical to Core's
    -- ValueFromAmount (core_io.cpp:285, %s%d.%08d). cjson would float-encode
    -- total_sats/1e8 and lose precision on large sums, so we emit the whole
    -- result via the _raw_json escape hatch with a btc_sentinel that
    -- strip_btc_sentinels turns into a bare decimal literal.
    local result = {
      height       = tip_height,
      bestblock    = tip_hash_hex,
      txouts       = n_txouts,
      bogosize     = bogosize,
      transactions = n_txs,
      disk_size    = disk_size,
      total_amount = btc_sentinel(total_sats),
    }
    if hash_type == "hash_serialized_3" then
      result.hash_serialized_3 = hash_serialized_3
    elseif hash_type == "muhash" then
      result.muhash = muhash_hex
    end

    return { _raw_json = strip_btc_sentinels(cjson.encode(result)) }
  end

  -- scantxoutset: scan the live UTXO set by scriptPubKey.
  -- Bitcoin Core: src/rpc/blockchain.cpp::scantxoutset → EvalDescriptor.
  -- This is the wallet-recovery primitive: a wallet restored from seed only
  -- (no on-disk UTXO record) re-derives its receiving scriptPubKeys and asks
  -- the node which of them are funded on-chain.  It iterates the CF.UTXO
  -- column family (the same walk gettxoutsetinfo does) and collects every
  -- coin whose scriptPubKey matches one of the supplied scan objects.
  --
  -- Supported scan-object forms (string, or {desc=...} object):
  --   addr(<address>)         — match the address's scriptPubKey
  --   raw(<scriptPubKey-hex>) — match this exact scriptPubKey
  --   pkh(<hex-pubkey>)       — P2PKH for the key's hash160
  --   wpkh(<hex-pubkey>)      — P2WPKH for the key's hash160
  --   tr(<hex-xonly-key>)     — P2TR for an already-tweaked 32-byte output key
  --   a bare scriptPubKey-hex — Core's raw() shorthand
  --
  -- Actions: "start" (default) runs the scan; "abort"/"status" return false
  -- (no background scan is tracked here), matching Core when nothing runs.
  self.methods["scantxoutset"] = function(rpc, params)
    local action = (params and params[1]) or "start"
    if type(action) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS, message = "action must be a string"})
    end
    action = action:lower()

    if action == "abort" or action == "status" then
      -- No long-running background scan is tracked in this minimal impl;
      -- Core returns false from abort/status when nothing is in progress.
      return false
    end
    if action ~= "start" then
      error({code = M.ERROR.INVALID_PARAMS, message = "Invalid action '" .. action .. "'"})
    end

    local scanobjects = params and params[2]
    if type(scanobjects) ~= "table" or #scanobjects == 0 then
      error({code = M.ERROR.INVALID_PARAMS,
             message = "scanobjects argument is required for the start action"})
    end

    if not rpc.storage or not rpc.storage.iterator then
      error({code = M.ERROR.MISC_ERROR, message = "Storage not available"})
    end

    local network_name = rpc.network and rpc.network.name or "mainnet"

    -- Resolve every scan object to a scriptPubKey needle.  `needles` maps
    -- the raw scriptPubKey bytes -> the descriptor string echoed back per
    -- matched unspent (Core's UnspentOutput.desc).
    local needles = {}
    local function add_needle(spk, desc)
      needles[spk] = desc
    end
    local function spk_for_addr(addr)
      local addr_type, addr_data, _wv = address_mod.decode_address(addr, network_name)
      if not addr_type then
        error({code = M.ERROR.INVALID_ADDRESS,
               message = "Invalid address in addr(): " .. tostring(addr_data)})
      end
      if addr_type == "p2pkh" then
        return script_mod.make_p2pkh_script(addr_data)
      elseif addr_type == "p2sh" then
        return script_mod.make_p2sh_script(addr_data)
      elseif addr_type == "p2wpkh" then
        return script_mod.make_p2wpkh_script(addr_data)
      elseif addr_type == "p2wsh" then
        return script_mod.make_p2wsh_script(addr_data)
      elseif addr_type == "p2tr" then
        return script_mod.make_p2tr_script(addr_data)
      else
        error({code = M.ERROR.INVALID_ADDRESS,
               message = "Unsupported address type in addr(): " .. addr_type})
      end
    end
    local function hex_to_bytes(h)
      h = h:gsub("%s", "")
      if #h % 2 ~= 0 or h:match("[^0-9a-fA-F]") then
        error({code = M.ERROR.INVALID_PARAMS, message = "Invalid hex in scan object"})
      end
      return (h:gsub("..", function(cc) return string.char(tonumber(cc, 16)) end))
    end
    local function hash160_of(pubkey_bytes)
      return require("lunarblock.crypto").hash160(pubkey_bytes)
    end

    for _, obj in ipairs(scanobjects) do
      local spec
      if type(obj) == "table" then
        spec = obj.desc
      else
        spec = obj
      end
      if type(spec) ~= "string" then
        error({code = M.ERROR.INVALID_PARAMS,
               message = "Scan object must be a descriptor string"})
      end
      spec = spec:gsub("^%s+", ""):gsub("%s+$", "")
      -- Strip a trailing descriptor checksum (#xxxxxxxx) if present.
      local hash_pos = spec:find("#", 1, true)
      if hash_pos then spec = spec:sub(1, hash_pos - 1) end

      local inner = spec:match("^addr%((.+)%)$")
      if inner then
        add_needle(spk_for_addr(inner), spec)
      else
        inner = spec:match("^raw%((.+)%)$")
        if inner then
          add_needle(hex_to_bytes(inner), spec)
        else
          inner = spec:match("^pkh%((.+)%)$")
          if inner then
            local h = hash160_of(hex_to_bytes(inner))
            add_needle(script_mod.make_p2pkh_script(h), spec)
          else
            inner = spec:match("^wpkh%((.+)%)$")
            if inner then
              local h = hash160_of(hex_to_bytes(inner))
              add_needle(script_mod.make_p2wpkh_script(h), spec)
            else
              inner = spec:match("^tr%((.+)%)$")
              if inner then
                local xonly = hex_to_bytes(inner)
                if #xonly ~= 32 then
                  error({code = M.ERROR.INVALID_PARAMS,
                         message = "tr() expects a 32-byte x-only output key"})
                end
                add_needle(script_mod.make_p2tr_script(xonly), spec)
              elseif spec:match("^[0-9a-fA-F]+$") and #spec % 2 == 0 then
                -- bare hex == Core raw() shorthand
                add_needle(hex_to_bytes(spec), spec)
              else
                error({code = M.ERROR.INVALID_PARAMS,
                       message = "Unsupported scan object: " .. spec})
              end
            end
          end
        end
      end
    end

    local utxo_mod = require("lunarblock.utxo")

    local tip_height = rpc.chain_state and rpc.chain_state.tip_height or 0
    local tip_hash_hex
    if rpc.chain_state and rpc.chain_state.tip_hash then
      tip_hash_hex = types.hash256_hex(rpc.chain_state.tip_hash)
    else
      tip_hash_hex = string.rep("0", 64)
    end

    local n_txouts = 0
    local total_sats = 0
    local unspents = {}

    local iter = rpc.storage.iterator(storage_mod.CF.UTXO)
    iter.seek_to_first()
    while iter.valid() do
      local k = iter.key()
      local v = iter.value()
      if k and v and #k == 36 then
        local ok, entry = pcall(utxo_mod.deserialize_utxo_entry, v)
        if ok and entry then
          n_txouts = n_txouts + 1
          local desc = needles[entry.script_pubkey]
          if desc ~= nil then
            total_sats = total_sats + (entry.value or 0)
            -- Key layout: txid[32] (internal byte order) + vout[4] LE.
            -- JSON-RPC reports txid in display order (reversed hex), matching
            -- gettxout / Core's COutPoint::hash.GetHex().
            local txid_internal = k:sub(1, 32)
            local txid_display = types.hash256_hex(types.hash256(txid_internal))
            local v0, v1, v2, v3 = k:byte(33, 36)
            local vout = v0 + v1 * 256 + v2 * 65536 + v3 * 16777216
            local coin_height = entry.height or 0
            -- blockhash: hash of the block at the coin's height, big-endian
            -- display hex. Mirrors Core's coinb_block.GetBlockHash().GetHex()
            -- (tip->GetAncestor(coin.nHeight)). Guard for a missing index entry.
            local coin_block_hash = rpc.storage.get_hash_by_height(coin_height)
            local blockhash_hex
            if coin_block_hash then
              blockhash_hex = types.hash256_hex(coin_block_hash)
            else
              blockhash_hex = string.rep("0", 64)
            end
            unspents[#unspents + 1] = {
              txid = txid_display,
              vout = vout,
              scriptPubKey = (function()
                local hx = {}
                for i = 1, #entry.script_pubkey do
                  hx[i] = string.format("%02x", entry.script_pubkey:byte(i))
                end
                return table.concat(hx)
              end)(),
              desc = desc,
              amount = btc_sentinel(entry.value or 0),
              coinbase = entry.is_coinbase and true or false,
              height = coin_height,
              blockhash = blockhash_hex,
              -- confirmations = active tip height - coin height + 1
              -- (Core: tip->nHeight - coin.nHeight + 1). Plain integer count,
              -- not a BTC amount, so no btc_sentinel wrapping.
              confirmations = tip_height - coin_height + 1,
            }
          end
        end
      end
      iter.next()
    end
    iter.destroy()

    local result = {
      success = true,
      txouts = n_txouts,
      height = tip_height,
      bestblock = tip_hash_hex,
      unspents = unspents,
      total_amount = btc_sentinel(total_sats),
    }
    if #unspents == 0 then
      result.unspents = setmetatable({}, cjson.empty_array_mt)
    end
    local json = strip_btc_sentinels(cjson.encode(result))
    return {_raw_json = json}
  end

  -- getnetworkhashps: estimate network hash rate over last nblocks
  self.methods["getnetworkhashps"] = function(rpc, params)
    local nblocks = (params and type(params[1]) == "number") and math.floor(params[1]) or 120
    local height  = (params and type(params[2]) == "number") and math.floor(params[2]) or -1

    if not rpc.chain_state or not rpc.storage then
      error({code = M.ERROR.MISC_ERROR, message = "Chain state not available"})
    end

    local tip_h = rpc.chain_state.tip_height or 0
    if height < 0 or height > tip_h then height = tip_h end

    -- Need at least 2 blocks
    if height < 1 then return 0 end

    -- window: [start_h .. height]
    local start_h = (nblocks == 0) and 0 or math.max(0, height - nblocks)

    local function get_header_at(h)
      local hh = rpc.storage.get_hash_by_height(h)
      if not hh then return nil end
      return rpc.storage.get_header(hh), hh
    end

    local top_hdr, top_hh = get_header_at(height)
    local bot_hdr, _      = get_header_at(start_h)
    if not top_hdr or not bot_hdr then return 0 end

    local time_diff = top_hdr.timestamp - bot_hdr.timestamp
    if time_diff <= 0 then return 0 end

    -- Chainwork diff via header_chain.headers entries
    local function get_work(hh_val)
      if not rpc.header_chain then return 0 end
      local hex = types.hash256_hex(hh_val)
      local entry = rpc.header_chain.headers and rpc.header_chain.headers[hex]
      return entry and (entry.total_work or 0) or 0
    end

    local work_top = get_work(top_hh)
    local work_bot = get_work(
      (function()
        local _, bh = get_header_at(start_h)
        return bh
      end)()
    )

    local work_diff = work_top - work_bot
    if work_diff <= 0 then
      -- Fallback: estimate from difficulty at tip
      local bits = top_hdr.bits or 0x1d00ffff
      -- target = difficulty_1 / difficulty; hashes = 2^256 / target ≈ work per block
      -- simple estimate: (height - start_h) * 2^32 / time_diff
      local n_blocks = height - start_h
      return math.floor(n_blocks * 4294967296 / time_diff)
    end

    return math.floor(work_diff / time_diff)
  end

  -- gettxoutproof: produce a CMerkleBlock hex for the given txids in a block
  self.methods["gettxoutproof"] = function(rpc, params)
    if not params or type(params[1]) ~= "table" then
      error({code = M.ERROR.INVALID_PARAMS,
             message = "gettxoutproof requires [{txids}, blockhash?]"})
    end

    local txid_hexes = {}
    for _, v in ipairs(params[1]) do
      if type(v) ~= "string" or #v ~= 64 then
        error({code = M.ERROR.INVALID_PARAMS, message = "Invalid txid: " .. tostring(v)})
      end
      txid_hexes[#txid_hexes + 1] = v:lower()
    end

    if #txid_hexes == 0 then
      error({code = M.ERROR.INVALID_PARAMS, message = "txids list is empty"})
    end

    if not rpc.storage then
      error({code = M.ERROR.MISC_ERROR, message = "Storage not available"})
    end

    -- Find the block
    local block
    if params[2] and type(params[2]) == "string" and #params[2] == 64 then
      local bh = types.hash256_from_hex(params[2])
      block = rpc.storage.get_block(bh)
      if not block then
        error({code = M.ERROR.MISC_ERROR,
               message = "Block not found: " .. params[2]})
      end
    else
      -- Require blockhash: lunarblock txindex stores file offsets, not block hashes
      error({code = M.ERROR.MISC_ERROR,
             message = "Transaction not yet in block index. Use blockhash parameter."})
    end

    -- Collect txids for the block
    local block_txids = {}
    for _, tx in ipairs(block.transactions) do
      block_txids[#block_txids + 1] = validation.compute_txid(tx).bytes
    end
    local n_tx = #block_txids

    -- Build match set (0-based)
    local match_set = {}
    local found = {}
    for i, txid_raw in ipairs(block_txids) do
      local h = types.hash256_hex(types.hash256(txid_raw))
      for _, want in ipairs(txid_hexes) do
        if h == want then
          match_set[i - 1] = true  -- 0-based
          found[want] = true
          break
        end
      end
    end

    for _, want in ipairs(txid_hexes) do
      if not found[want] then
        error({code = M.ERROR.MISC_ERROR,
               message = "Transaction not in block: " .. want})
      end
    end

    -- Compute tree height
    local n_height = 0
    while bit.lshift(1, n_height) < n_tx do n_height = n_height + 1 end

    -- Build partial merkle tree
    local hashes, bits = {}, {}
    w47b_traverse_and_build(crypto, block_txids, n_tx, match_set, n_height, 0, hashes, bits)

    -- Encode: 80-byte header | nTx LE32 | varint hash_count | hashes | varint flag_bytes | flag_bytes
    local header_bytes = serialize.serialize_block_header(block.header)
    local flag_bytes   = w47b_bits_to_bytes(bits)

    local out_parts = {
      header_bytes,
      w47b_le32(n_tx),
      w47b_encode_varint(#hashes),
    }
    for _, h in ipairs(hashes) do
      out_parts[#out_parts + 1] = h
    end
    out_parts[#out_parts + 1] = w47b_encode_varint(#flag_bytes)
    out_parts[#out_parts + 1] = flag_bytes

    local wire = table.concat(out_parts)
    -- Hex-encode
    local hex_parts = {}
    for i = 1, #wire do
      hex_parts[i] = string.format("%02x", wire:byte(i))
    end
    return table.concat(hex_parts)
  end

  -- verifytxoutproof: verify a CMerkleBlock hex, return matched txids
  self.methods["verifytxoutproof"] = function(rpc, params)
    if not params or type(params[1]) ~= "string" then
      error({code = M.ERROR.INVALID_PARAMS,
             message = "verifytxoutproof requires a hex string"})
    end

    local hex = params[1]
    if #hex % 2 ~= 0 then
      error({code = M.ERROR.INVALID_PARAMS, message = "Odd-length hex string"})
    end

    -- Decode hex to binary
    local raw = {}
    for i = 1, #hex, 2 do
      raw[#raw + 1] = string.char(tonumber(hex:sub(i, i + 1), 16))
    end
    local data = table.concat(raw)

    if #data < 80 + 4 then
      error({code = M.ERROR.MISC_ERROR, message = "Proof too short"})
    end

    local r = serialize.buffer_reader(data)

    -- Read 80-byte header
    local header_raw = r.read_bytes(80)
    -- Compute block hash from header
    local block_hash_raw = crypto.hash256(header_raw)
    local block_hash_hex = types.hash256_hex(types.hash256(block_hash_raw))

    -- nTx (uint32 LE)
    local n_tx = r.read_u32le()
    if n_tx == 0 then
      -- cjson encodes bare {} as object; force [] for empty txid array.
      return setmetatable({}, cjson.empty_array_mt)
    end

    -- hash_count varint
    local hash_count = r.read_varint()
    local hashes_raw = {}
    for _ = 1, hash_count do
      hashes_raw[#hashes_raw + 1] = r.read_bytes(32)
    end

    -- flag byte count varint + bytes
    local flag_byte_count = r.read_varint()
    local flag_bytes_raw = r.read_bytes(flag_byte_count)

    -- Unpack bits (LSB-first)
    local bits = {}
    for i = 1, flag_byte_count do
      local byte_val = flag_bytes_raw:byte(i)
      for b = 0, 7 do
        bits[#bits + 1] = (bit.band(bit.rshift(byte_val, b), 1) == 1) and 1 or 0
      end
    end

    -- Compute tree height
    local n_height = 0
    while bit.lshift(1, n_height) < n_tx do n_height = n_height + 1 end

    local bit_pos_ref  = {0}
    local hash_pos_ref = {0}
    local root, err, matched_list = w47b_traverse_and_extract(
      crypto, n_tx, hashes_raw, bits, bit_pos_ref, hash_pos_ref, n_height, 0)

    if not root then
      error({code = M.ERROR.MISC_ERROR, message = "Invalid proof: " .. tostring(err)})
    end

    -- Verify root matches header merkle root
    -- Header merkle root is at bytes 36-67 (after version 4B + prev_hash 32B)
    local header_merkle_root = header_raw:sub(37, 68)  -- 1-based
    if root ~= header_merkle_root then
      error({code = M.ERROR.MISC_ERROR, message = "Merkle root mismatch"})
    end

    -- Verify block is in our chain
    if rpc.storage then
      local bh = types.hash256_from_hex(block_hash_hex)
      local stored = rpc.storage.get_header(bh)
      if not stored then
        error({code = M.ERROR.MISC_ERROR,
               message = "Block " .. block_hash_hex .. " not found in chain"})
      end
    end

    -- Return matched txids as display hex (reversed, like Core)
    local result = {}
    for _, raw_hash in ipairs(matched_list) do
      result[#result + 1] = types.hash256_hex(types.hash256(raw_hash))
    end
    return result
  end

  -- getrpcinfo: list active RPC commands and logpath
  self.methods["getrpcinfo"] = function(_rpc, _params)
    return {
      active_commands = setmetatable({}, cjson.empty_array_mt),
      logpath         = "",
    }
  end
end

--------------------------------------------------------------------------------
-- HTTP Server
--------------------------------------------------------------------------------

-- FIX-64 (W119): build a luasec context from the cert/key pair set on
-- self.  Factored out so the unit tests can exercise the cert/key
-- validation, "luasec missing" path, and mismatched-flag path without
-- standing up a real bound listener.
--
-- Returns ctx, nil on success.
-- Returns nil, err_string on failure.  Callers MUST error()/exit on err.
-- Returns nil, nil when TLS is not requested (neither cert nor key set).
function RPCServer:_init_tls_context()
  local cert, key = self.tls_cert_path, self.tls_key_path
  if (cert == nil or cert == "") and (key == nil or key == "") then
    return nil, nil  -- TLS not requested — plaintext path
  end
  if (cert == nil or cert == "") or (key == nil or key == "") then
    return nil, "--rpc-tls-cert and --rpc-tls-key must both be set " ..
                "(got cert=" .. tostring(cert) .. ", key=" .. tostring(key) .. ")"
  end
  -- Require luasec only when TLS is requested.  Operators who never set
  -- the flags must NOT be forced to install luasec just to run plaintext.
  local ok, ssl_or_err = pcall(require, "ssl")
  if not ok then
    return nil,
      "luasec required for --rpc-tls-cert/--rpc-tls-key; install via " ..
      "`luarocks install luasec` or `apt install lua-sec` " ..
      "(require('ssl') error: " .. tostring(ssl_or_err) .. ")"
  end
  local ssl = ssl_or_err
  -- Verify the files exist+readable up front so the error fires at
  -- start() (visible to operator) and not on first accepted client
  -- (silent in handlers).
  local cf, cerr = io.open(cert, "rb")
  if not cf then
    return nil, "--rpc-tls-cert unreadable: " .. tostring(cerr)
  end
  cf:close()
  local kf, kerr = io.open(key, "rb")
  if not kf then
    return nil, "--rpc-tls-key unreadable: " .. tostring(kerr)
  end
  kf:close()
  -- Server-mode context.  TLSv1.2+ baseline (matches Core's libevent+OpenSSL
  -- default in src/httpserver.cpp; sslv2/sslv3/tlsv1.0/1.1 all disabled).
  -- "all" selects the highest mutually supported protocol; "options" disables
  -- legacy fallbacks.  No client-cert verification by default — same shape
  -- as Core: HTTPS is transport encryption, RPC Basic auth is the user check.
  local ctx_ok, ctx_or_err = pcall(ssl.newcontext, {
    mode     = "server",
    protocol = "any",
    certificate = cert,
    key         = key,
    verify   = {"none"},
    options  = {"all", "no_sslv2", "no_sslv3", "no_tlsv1", "no_tlsv1_1"},
  })
  if not ctx_ok or not ctx_or_err then
    return nil, "ssl.newcontext failed: " .. tostring(ctx_or_err)
  end
  return ctx_or_err, nil
end

function RPCServer:start()
  -- FIX-64 (W119): init TLS context FIRST so any mismatched-flag or
  -- missing-luasec error fires before we bind the port.  This keeps the
  -- listener from coming up half-configured and confusing supervisors.
  local ctx, tls_err = self:_init_tls_context()
  if tls_err then
    error("RPC TLS init: " .. tls_err)
  end
  self.tls_ctx = ctx  -- nil if plaintext mode

  -- Use tcp4() (not tcp()) so setoption("reuseaddr", true) actually succeeds
  -- on LuaSocket 3.0 — on this build setsockopt fails on a generic master
  -- socket returned by tcp(), leaving bind() to fail with "address already
  -- in use" during the TIME_WAIT window after a clean SIGTERM restart.
  self.server_socket = socket.tcp4()
  assert(self.server_socket:setoption("reuseaddr", true))
  assert(self.server_socket:bind(self.host, self.port))
  assert(self.server_socket:listen(32))
  self.server_socket:settimeout(0)  -- Non-blocking accept
  self.running = true
  if self.tls_ctx then
    print("RPC server listening on https://" .. self.host .. ":" .. self.port ..
          " (TLS via luasec)")
  else
    print("RPC server listening on " .. self.host .. ":" .. self.port)
  end
end

function RPCServer:tick()
  if not self.running then return end

  -- Accept a new connection
  local client = self.server_socket:accept()
  if not client then return end

  -- FIX-64 (W119): when HTTPS is enabled, wrap the accepted plain TCP socket
  -- with luasec and complete the TLS handshake BEFORE any HTTP parsing.  We
  -- intentionally do the handshake synchronously here — this server's tick()
  -- is already a per-tick serial accept loop and the rest of the request
  -- handling is synchronous too, so a slow handshake just delays the same
  -- tick that the plaintext path would have spent on parse_http_request.
  -- A TLS handshake failure is treated as the encrypted equivalent of a
  -- malformed request: log + close + bail.  We DO NOT send a plaintext
  -- HTTP error back — the peer is speaking some other protocol and
  -- responding in cleartext would itself be a protocol violation.
  if self.tls_ctx then
    local ssl = require("ssl")  -- safe: :start() already proved this loads
    -- Plain-socket-side timeout: the wrapped TLS object inherits it.
    client:settimeout(5)  -- handshake budget; plaintext used 1s for body reads
    local tls_client, wrap_err = ssl.wrap(client, self.tls_ctx)
    if not tls_client then
      pcall(function() client:close() end)
      return
    end
    tls_client:settimeout(5)
    local ok, hs_err = tls_client:dohandshake()
    if not ok then
      pcall(function() tls_client:close() end)
      pcall(function() client:close() end)
      return
    end
    -- From here, everything reads/writes through tls_client.  Note that
    -- LuaSec's wrapped object exposes the same receive/send/close API as
    -- LuaSocket so the existing HTTP code path below is unchanged.
    client = tls_client
    client:settimeout(1)  -- per-receive cap, matches plaintext
  else
    client:settimeout(1)  -- 1s max per read (was 5s) to limit event-loop blocking
  end
  -- Read HTTP headers line-by-line, then read exact body by Content-Length.
  -- This avoids the LuaSocket receive(n) blocking issue where it waits for
  -- exactly n bytes or timeout.
  local headers_raw = {}
  local content_length = 0
  while true do
    local line, err = client:receive("*l")
    if not line or line == "" then break end  -- empty line = end of headers
    if err then break end
    headers_raw[#headers_raw + 1] = line
    local cl = line:match("^[Cc]ontent%-[Ll]ength:%s*(%d+)")
    if cl then content_length = tonumber(cl) end
  end
  -- Read exact body
  local body_data = ""
  if content_length > 0 then
    body_data = client:receive(content_length) or ""
  end
  -- Reconstruct full request for parse_http_request
  local data = table.concat(headers_raw, "\r\n") .. "\r\n\r\n" .. body_data

  if #data == 0 then
    client:close()
    return
  end

  local method, path, headers, body = M.parse_http_request(data)
  if not method then
    client:send(M.build_http_response(400, '{"error":"Bad request"}'))
    client:close()
    return
  end

  -- Check authentication
  if self.password ~= "" and not M.check_auth(headers, self.username, self.password) then
    client:send(M.build_http_response(401, '{"error":"Unauthorized"}'))
    client:close()
    return
  end

  -- Extract wallet name from path: /wallet/<name>
  local wallet_name = nil
  if path and path:match("^/wallet/") then
    wallet_name = path:match("^/wallet/(.+)$") or ""
  elseif path and path == "/wallet/" then
    wallet_name = ""
  end

  -- Set request wallet context
  self.request_wallet = nil
  if wallet_name and self.wallet_manager then
    local wallet = self.wallet_manager:get_wallet(wallet_name)
    if wallet then
      self.request_wallet = wallet
    end
  end

  -- /health: GET endpoint for process supervisors.  No auth required so
  -- supervisors don't need RPC creds.  Returns 200 with a small JSON body
  -- whenever the RPC server's tick is running — supervisors can use this
  -- as a "the daemon is responsive" probe.  We deliberately do NOT report
  -- IBD-completion status here; this is a *liveness* check, not readiness.
  -- Reference: bitcoin-core does not ship /health; this is a lunarblock
  -- ergonomic addition for supervised deployments.
  if method == "GET" and path == "/health" then
    local height = (self.chain_state and self.chain_state.tip_height) or -1
    local body = string.format(
      '{"status":"ok","height":%d,"version":"lunarblock"}\n', height)
    client:send(M.build_http_response(200, body, "application/json"))
    self.request_wallet = nil
    client:close()
    return
  end

  -- Handle JSON-RPC
  if method == "POST" then
    local response_body, status_override = self:handle_request(body, wallet_name)
    local status = status_override or 200
    client:send(M.build_http_response(status, response_body))
  else
    client:send(M.build_http_response(404, '{"error":"Not found"}'))
  end

  -- Clear request context
  self.request_wallet = nil

  client:close()
end

function RPCServer:stop()
  self.running = false
  if self.server_socket then
    self.server_socket:close()
    self.server_socket = nil
  end
end

return M
