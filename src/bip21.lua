-- BIP-21 URI parser ("bitcoin:" payment URIs).
--
-- Spec: https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
--
--   bitcoin:<address>[?<query>]
--   query := <key>=<value>(&<key>=<value>)*
--   key   := lower-case ASCII letters, digits, and '-'
--   value := percent-encoded UTF-8
--
-- Recognised parameters (case-insensitive keys per BIP-21 §"reserved
-- keywords"):
--   amount     — BTC as a decimal string. Converted to satoshis (integer).
--   label      — UTF-8 label for the recipient (percent-decoded).
--   message    — UTF-8 message (percent-decoded).
--   lightning  — BOLT-11 invoice (BIP-21 extension, unified QR / BTCPay).
--   pj         — BIP-78 PayJoin endpoint URL.
--   pjos       — BIP-78 PayJoin output-substitution opt-out. '0' means
--                "receiver MUST NOT substitute outputs".
--
-- Unknown `req-X` parameters are FATAL (BIP-21 §"req-" rule):
--   > variables which are prefixed with a req- are considered required.
--   > If a client does not implement any variables which are prefixed with
--   > req-, it MUST consider the entire URI invalid.
--
-- Unknown non-req parameters are stashed in `extras` and ignored.
--
-- Returns a table on success:
--   { address   = string,           -- the part between "bitcoin:" and "?"
--     scheme    = "bitcoin",
--     addr_type = "p2pkh" | "p2sh" | "p2wpkh" | "p2wsh" | "p2tr" | ...,
--     amount    = integer | nil,    -- satoshis
--     label     = string  | nil,
--     message   = string  | nil,
--     lightning = string  | nil,
--     pj        = string  | nil,
--     pjos      = string  | nil,    -- "0" or "1" or any future value
--     extras    = { [lowercased-key] = decoded-value },
--   }
--
-- Returns `{ err = "<reason>" }` on failure. Callers should pattern-match
-- on the `err` field; the return value is always a table.

local address = require("lunarblock.address")
local M = {}

-- --------------------------------------------------------------------- --
-- Percent decoding                                                       --
-- --------------------------------------------------------------------- --
-- BIP-21 inherits RFC-3986 percent-encoding semantics. We decode %XX
-- back to a raw byte (UTF-8 safe — the result is just bytes). We also
-- accept '+' as a space *only inside the query string* (this matches
-- application/x-www-form-urlencoded, which most wallets follow when
-- generating BIP-21 URIs via QR codes); BIP-21 itself doesn't require
-- this but rejecting it would surprise users.
local function from_hex_digit(c)
  if c >= 48 and c <= 57 then return c - 48 end       -- 0-9
  if c >= 65 and c <= 70 then return c - 65 + 10 end  -- A-F
  if c >= 97 and c <= 102 then return c - 97 + 10 end -- a-f
  return nil
end

local function percent_decode(s, decode_plus_as_space)
  local out = {}
  local i = 1
  local n = #s
  while i <= n do
    local c = s:byte(i)
    if c == 37 then  -- '%'
      if i + 2 > n then return nil, "truncated percent-escape" end
      local h1 = from_hex_digit(s:byte(i + 1))
      local h2 = from_hex_digit(s:byte(i + 2))
      if not h1 or not h2 then
        return nil, "invalid percent-escape"
      end
      out[#out + 1] = string.char(h1 * 16 + h2)
      i = i + 3
    elseif c == 43 and decode_plus_as_space then  -- '+'
      out[#out + 1] = " "
      i = i + 1
    else
      out[#out + 1] = string.char(c)
      i = i + 1
    end
  end
  return table.concat(out)
end

-- --------------------------------------------------------------------- --
-- Amount parsing                                                         --
-- --------------------------------------------------------------------- --
-- BIP-21: "amount" is a decimal BTC value. We convert it to an integer
-- number of satoshis without using floating-point arithmetic (LuaJIT
-- doubles handle 21,000,000.00000000 BTC fine but we'd rather not rely
-- on that — a parser that's exact for every legal value is cheap).
local SATS_PER_BTC = 100000000

local function parse_amount_to_sats(amount_str)
  if type(amount_str) ~= "string" or amount_str == "" then
    return nil, "empty amount"
  end
  -- Reject scientific notation / leading '+' / signs.  BIP-21 amount
  -- grammar is digits + optional decimal point + digits.
  if amount_str:find("[^0-9.]") then
    return nil, "amount contains non-digit characters"
  end
  -- At most one '.'.  (string.find with plain=true takes a literal
  -- string, NOT a Lua pattern — so we pass "." not "%.".)
  local first_dot = amount_str:find(".", 1, true)
  if first_dot then
    if amount_str:find(".", first_dot + 1, true) then
      return nil, "amount has multiple decimal points"
    end
  end

  local int_part, frac_part
  if first_dot then
    int_part  = amount_str:sub(1, first_dot - 1)
    frac_part = amount_str:sub(first_dot + 1)
  else
    int_part  = amount_str
    frac_part = ""
  end

  -- "" before the dot ("." or ".5") is allowed and treated as zero;
  -- "" after the dot ("5.") is also allowed.  But "" with no digits
  -- anywhere (just "." or "") is not.
  if int_part == "" and frac_part == "" then
    return nil, "amount has no digits"
  end
  if int_part == "" then int_part = "0" end

  if #frac_part > 8 then
    return nil, "amount has more than 8 decimal places (sub-satoshi)"
  end
  -- Right-pad to exactly 8 digits to convert to satoshis.
  frac_part = frac_part .. string.rep("0", 8 - #frac_part)

  local int_sats = tonumber(int_part)
  local frac_sats = tonumber(frac_part)
  if not int_sats or not frac_sats then
    return nil, "amount could not be parsed as decimal"
  end
  -- 21e6 BTC = 2.1e15 sats fits comfortably in a Lua double's 53-bit
  -- mantissa, so multiplication is exact.
  local sats = int_sats * SATS_PER_BTC + frac_sats
  -- Guard: BIP-21 doesn't cap amount but a payment for more than the
  -- total supply is almost certainly a bug; we accept it (let the
  -- wallet refuse), but ensure no overflow into something nonsensical.
  if sats < 0 then return nil, "amount is negative" end
  return sats
end

-- --------------------------------------------------------------------- --
-- Public parser                                                          --
-- --------------------------------------------------------------------- --
-- M.parse(input, network)
--   input   — string (entire URI, including "bitcoin:" prefix)
--   network — "mainnet" | "testnet" | "regtest" (defaults to "mainnet")
function M.parse(input, network)
  if type(input) ~= "string" then
    return { err = "input is not a string" }
  end
  network = network or "mainnet"

  -- BIP-21 scheme is case-insensitive per RFC-3986 §3.1.
  local lower = input:lower()
  if lower:sub(1, 8) ~= "bitcoin:" then
    return { err = "missing 'bitcoin:' scheme" }
  end

  -- Slice the body using the lower-cased prefix length, but operate on
  -- the original-case body — addresses are case-sensitive (Base58 is
  -- case-sensitive; bech32 is lower-case but tolerates upper for QR).
  local body = input:sub(9)
  if body == "" then
    return { err = "empty body after 'bitcoin:'" }
  end

  -- Split address and query string at the first '?'.
  local q_idx = body:find("?", 1, true)
  local addr_part, query_part
  if q_idx then
    addr_part  = body:sub(1, q_idx - 1)
    query_part = body:sub(q_idx + 1)
  else
    addr_part  = body
    query_part = nil
  end

  if addr_part == "" then
    return { err = "missing address" }
  end

  -- Address: must percent-decode FIRST (some implementations percent-
  -- encode common Base58 characters — rare but legal).  We do NOT
  -- treat '+' as space in the address segment.
  local decoded_addr, dec_err = percent_decode(addr_part, false)
  if not decoded_addr then
    return { err = "address: " .. dec_err }
  end

  -- Validate against our address layer.  decode_address can raise on
  -- non-Base58 input via the base58_decode assert; wrap in pcall.
  local ok, addr_type, payload_or_err = pcall(address.decode_address,
                                              decoded_addr, network)
  if not ok then
    return { err = "address is not valid for network " .. network }
  end
  if not addr_type then
    return { err = "address is not valid for network " .. network }
  end

  -- address.decode_address accepts EITHER network's Base58 version byte
  -- regardless of the `network` arg (it only filters bech32 via HRP).
  -- BIP-21 callers expect a network-correct check, so we enforce it
  -- here for Base58 types by re-decoding and comparing the version byte
  -- against the expected one for `network`.
  if addr_type == "p2pkh" or addr_type == "p2sh" then
    local v_ok, ver = pcall(address.base58check_decode, decoded_addr)
    if not v_ok or not ver then
      return { err = "address is not valid for network " .. network }
    end
    local expect_p2pkh = (network == "mainnet")
                          and address.VERSION.MAINNET_P2PKH
                          or  address.VERSION.TESTNET_P2PKH
    local expect_p2sh  = (network == "mainnet")
                          and address.VERSION.MAINNET_P2SH
                          or  address.VERSION.TESTNET_P2SH
    if ver ~= expect_p2pkh and ver ~= expect_p2sh then
      return { err = "address is not valid for network " .. network }
    end
  end

  local result = {
    scheme    = "bitcoin",
    address   = decoded_addr,
    addr_type = addr_type,
    network   = network,
    extras    = {},
  }

  if not query_part then return result end

  -- Walk the query string.  We iterate manually rather than splitting
  -- on '&' because '&' inside a percent-encoded value would be %26,
  -- but we still want to be robust to a trailing '&'.
  local known = {
    amount    = true,
    label     = true,
    message   = true,
    lightning = true,
    pj        = true,
    pjos      = true,
  }

  local cursor = 1
  local qlen = #query_part
  while cursor <= qlen do
    local amp = query_part:find("&", cursor, true)
    local pair
    if amp then
      pair = query_part:sub(cursor, amp - 1)
      cursor = amp + 1
    else
      pair = query_part:sub(cursor)
      cursor = qlen + 1
    end
    if pair == "" then
      -- Empty segment (consecutive '&&' or trailing '&'); skip.
    else
      local eq = pair:find("=", 1, true)
      local raw_key, raw_value
      if eq then
        raw_key   = pair:sub(1, eq - 1)
        raw_value = pair:sub(eq + 1)
      else
        raw_key   = pair
        raw_value = ""
      end
      -- Keys are case-insensitive per BIP-21.  We do NOT percent-decode
      -- keys: BIP-21 doesn't allow percent-encoding inside the key.
      -- '+' inside a key is also illegal.
      local key = raw_key:lower()
      if key == "" then
        return { err = "empty key in query string" }
      end
      if key:find("[^a-z0-9%-]") then
        return { err = "invalid character in key '" .. raw_key .. "'" }
      end

      local value, verr = percent_decode(raw_value, true)
      if not value then
        return { err = "value of '" .. key .. "': " .. verr }
      end

      if known[key] then
        if key == "amount" then
          local sats, aerr = parse_amount_to_sats(value)
          if not sats then
            return { err = "amount: " .. aerr }
          end
          result.amount = sats
          result.amount_btc = value  -- keep the raw decimal too
        else
          result[key] = value
        end
      else
        -- BIP-21 §"req-": unknown required → reject.
        if key:sub(1, 4) == "req-" then
          return { err = "unsupported required parameter: " .. key }
        end
        -- Otherwise: stash and continue.
        result.extras[key] = value
      end
    end
  end

  return result
end

-- Convenience: returns the parsed table on success and (nil, err) on
-- failure.  Lets callers use the canonical Lua "value, err" idiom.
function M.parse_or_err(input, network)
  local r = M.parse(input, network)
  if r.err then return nil, r.err end
  return r
end

return M
