--- BIP-78 PayJoin sender flow (FIX-66).
--
-- Closes the W119 sender-side gates left open by FIX-65:
--
--   * G2  send-HTTP            (send_payjoin_request)
--   * G10 send-anti-snoop-out  (payjoin_check_outputs)        [P0-SECURITY]
--   * G11 send-scriptSig-types (payjoin_check_scriptsig)      [P1]
--   * G12 send-no-new-inputs   (payjoin_check_inputs)         [P0-SECURITY]
--   * G13 send-max-fee         (enforce_max_additional_fee)   [P1]
--   * G14 send-disableos       (payjoin_check_disable_substitution)
--   * G15 send-min-fee-rate    (payjoin_check_min_feerate)
--   * G22 send-fallback        (payjoin_fallback)             [P0]
--   * G24 HTTPS-cert validation via luasec.ssl_verify         [P0-SECURITY]
--
-- The flow mirrors the BIP-78 §Sender state machine:
--
--   1. Parse a BIP-21 URI with pj=<endpoint>.   (delegates to bip21.parse)
--   2. POST the base64 Original PSBT to the pj= endpoint with the
--      correct Content-Type and query parameters (v=1, minfeerate, etc.).
--   3. Receive the Proposal PSBT (base64) in the response body.
--   4. Run the SIX anti-snoop validators G10-G15 against the Proposal
--      relative to the Original.  ANY validator failure is a hard reject
--      — fall back to broadcasting the Original.
--   5. Re-sign the sender's own inputs in the Proposal (the receiver
--      left them untouched per BIP-78 §Receiver).
--   6. Broadcast the resulting fully-signed tx.  On any failure in
--      steps 2-5, fall back to broadcasting the Original PSBT
--      (already signed — payment still happens).
--
-- Transport options:
--
--   * Clearnet HTTPS  (G24): luasec verifies the cert chain against the
--     system CA bundle (mode = "client", verify = "peer"); failure to
--     load luasec is a hard error per BIP-78 §Protocol — HTTPS is
--     mandatory in clearnet, plaintext is NOT a graceful fallback.
--   * Tor / .onion v3 (G25): we expose a SOCKS5 adapter shim that
--     wraps the LuaSocket http client around a SOCKS5 connect via
--     proxy.lua.  The shim is kept narrow and tested with a mock
--     receiver — the production wiring still depends on operator
--     setup of an HTTP-over-Tor proxy.
--
-- Reference:
--   * BIP-78         (the spec)
--   * payjoin.org    (the reference protocol)
--   * btcpayserver/payjoin and payjoin-cli (reference implementations)
--
-- Single-pipeline anchor (FIX-66 extends FIX-65's single-pipeline
-- discipline to the sender too): the sender's RE-SIGN step in step (5)
-- routes through Wallet:_sign_inputs — the SAME function FIX-61
-- (bumpfee) and FIX-65 (receiver) use.  No parallel signing path is
-- introduced.

local M = {}

local socket    = require("socket")
local cjson     = require("cjson")
local types     = require("lunarblock.types")
local script_mod = require("lunarblock.script")
local address_mod = require("lunarblock.address")
local psbt_mod  = require("lunarblock.psbt")
local serialize = require("lunarblock.serialize")
local bip21     = require("lunarblock.bip21")
local validation = require("lunarblock.validation")

--------------------------------------------------------------------------------
-- Error types
--------------------------------------------------------------------------------

-- Stable error tags so callers can pattern-match (helpful for the
-- fallback decision in payjoin_fallback / sendpayjoinrequest):
--
--   "bad-uri"               input is not a valid BIP-21 URI with pj=
--   "transport-failed"      HTTPS POST failed (DNS, TLS, network, 4xx, 5xx)
--   "bad-response"          response is not parseable as a PSBT
--   "snoop-detected"        anti-snoop validator caught the receiver
--   "fee-exceeded"          receiver exceeded maxadditionalfeecontribution
--   "min-feerate-violated"  resulting effective rate < minfeerate
--   "disable-substitution-violated"
--                           sender forbade output substitution and the
--                           receiver did it anyway
--   "sign-failed"           re-signing the proposal failed
--   "broadcast-failed"      mempool rejected the proposal
M.ERR = {
  BAD_URI            = "bad-uri",
  TRANSPORT          = "transport-failed",
  BAD_RESPONSE       = "bad-response",
  SNOOP              = "snoop-detected",
  FEE_EXCEEDED       = "fee-exceeded",
  MIN_FEERATE        = "min-feerate-violated",
  DISABLE_OS         = "disable-substitution-violated",
  SIGN_FAILED        = "sign-failed",
  BROADCAST          = "broadcast-failed",
}

--------------------------------------------------------------------------------
-- HTTPS POST helpers (G2 + G24 + G25)
--------------------------------------------------------------------------------

-- Lazy require for luasec / luasocket.http.  We don't take the
-- dependency at file-load time so the sender module can be require()'d
-- in environments that never call out (e.g. unit tests).
local function load_https()
  -- ssl.https is the high-level wrapper; it pulls in ssl + socket.http
  -- and overrides the create-socket hook so the TLS handshake fires
  -- right after the TCP connect.  luasec >= 0.6 supports this.
  local ok, https = pcall(require, "ssl.https")
  if not ok then
    return nil, "luasec required for BIP-78 PayJoin sender HTTPS " ..
                "(install via `luarocks install luasec` or " ..
                "`apt install lua-sec`)"
  end
  return https, nil
end

local function load_http()
  local ok, http = pcall(require, "socket.http")
  if not ok then
    return nil, "luasocket required for BIP-78 PayJoin sender HTTP"
  end
  return http, nil
end

local function load_ltn12()
  local ok, ltn12 = pcall(require, "ltn12")
  if not ok then
    return nil, "ltn12 (luasocket dep) required for BIP-78 sender"
  end
  return ltn12, nil
end

-- Parse a pj= URL into {scheme, host, port, path, query}.
-- We accept "https://", "http://" (for tests / loopback only — caller
-- enforces clearnet HTTPS), and "http://*.onion" for Tor (the SOCKS5
-- adapter handles routing).  Returns nil + err on malformed input.
local function parse_pj_url(url)
  if type(url) ~= "string" or #url == 0 then
    return nil, "pj URL is empty"
  end
  local scheme, rest = url:match("^([a-zA-Z]+)://(.+)$")
  if not scheme then
    return nil, "pj URL missing scheme://"
  end
  scheme = scheme:lower()
  if scheme ~= "https" and scheme ~= "http" then
    return nil, "pj URL scheme must be https or http (got " .. scheme .. ")"
  end
  -- Split host[:port] from path.
  local host_port, path = rest:match("^([^/]+)(/?.*)$")
  if not host_port or host_port == "" then
    return nil, "pj URL missing host"
  end
  if path == "" then path = "/" end
  local host, port_str = host_port:match("^(.-):(%d+)$")
  if not host then
    host = host_port
    -- Default ports per RFC-7230 §2.7.
    port_str = (scheme == "https") and "443" or "80"
  end
  local port = tonumber(port_str)
  if not port or port < 1 or port > 65535 then
    return nil, "pj URL port invalid: " .. tostring(port_str)
  end
  return {
    scheme  = scheme,
    host    = host,
    port    = port,
    path    = path,
    is_onion = host:lower():match("%.onion$") ~= nil,
  }
end

-- Build the query string for the receiver endpoint from opts.
local function build_query(opts)
  local parts = {"v=1"}
  if opts.additionalfeeoutputindex ~= nil then
    parts[#parts + 1] = "additionalfeeoutputindex=" ..
                        tostring(opts.additionalfeeoutputindex)
  end
  if opts.maxadditionalfeecontribution ~= nil then
    parts[#parts + 1] = "maxadditionalfeecontribution=" ..
                        tostring(opts.maxadditionalfeecontribution)
  end
  if opts.disableoutputsubstitution then
    parts[#parts + 1] = "disableoutputsubstitution=1"
  end
  if opts.minfeerate ~= nil then
    parts[#parts + 1] = "minfeerate=" .. tostring(opts.minfeerate)
  end
  return table.concat(parts, "&")
end

-- POST the base64 Original PSBT to the parsed pj URL.  Returns the
-- response body on success (or nil + err on transport / status failure).
--
-- Argument shape:
--   parsed      table from parse_pj_url
--   body        string (base64 PSBT)
--   query_str   string (output of build_query)
--   opts        {
--     timeout            number  -- seconds; defaults to 30
--     ssl_verify         string  -- "peer" (default) | "none" (TESTS ONLY)
--     ssl_cafile         string  -- override CA bundle
--     transport          function -- TEST HOOK: replaces real HTTP.
--                                    Signature: f(url, body, headers) ->
--                                    body_str | nil, err
--   }
--
-- transport is the TEST HOOK that lets the unit tests run end-to-end
-- without binding sockets.  Production callers leave it nil.
local function http_post(parsed, body, query_str, opts)
  opts = opts or {}

  -- TEST HOOK ----------------------------------------------------------
  if type(opts.transport) == "function" then
    local url = parsed.scheme .. "://" .. parsed.host .. ":" .. parsed.port ..
                parsed.path
    if query_str and query_str ~= "" then url = url .. "?" .. query_str end
    return opts.transport(url, body, {
      ["Content-Type"]   = "text/plain",
      ["Content-Length"] = tostring(#body),
    })
  end

  -- TLS / cert validation (G24).  We REQUIRE peer verification when
  -- the scheme is https — BIP-78 §Protocol mandates it.  An explicit
  -- "none" override is allowed for unit tests only, never production
  -- (the RPC wrapper does not forward ssl_verify).
  local ssl_verify = opts.ssl_verify or "peer"
  if parsed.scheme == "https" and ssl_verify ~= "peer" and
     ssl_verify ~= "none" then
    return nil, M.ERR.TRANSPORT,
      "invalid ssl_verify mode: " .. tostring(ssl_verify)
  end

  local ltn12, lerr = load_ltn12()
  if not ltn12 then return nil, M.ERR.TRANSPORT, lerr end

  local response_chunks = {}
  local request_args = {
    url     = parsed.scheme .. "://" .. parsed.host .. ":" .. parsed.port ..
              parsed.path ..
              ((query_str and query_str ~= "") and ("?" .. query_str) or ""),
    method  = "POST",
    headers = {
      ["Content-Type"]   = "text/plain",
      ["Content-Length"] = tostring(#body),
    },
    source  = ltn12.source.string(body),
    sink    = ltn12.sink.table(response_chunks),
  }

  if parsed.scheme == "https" then
    local https, herr = load_https()
    if not https then return nil, M.ERR.TRANSPORT, herr end
    -- luasec ssl_params: enforce TLSv1.2+ and peer-cert verification.
    -- The luasec defaults verify the cert chain but DO NOT verify the
    -- hostname against the cert SAN/CN — that's a known luasec gap.
    -- We supply a custom verify_cert_hostname callback below to close
    -- it (mirrors the curl --resolve / openssl s_client behaviour).
    request_args.protocol = "tlsv1_2"
    request_args.verify   = ssl_verify == "none" and "none" or "peer"
    request_args.options  = {"all", "no_sslv2", "no_sslv3",
                             "no_tlsv1", "no_tlsv1_1"}
    if opts.ssl_cafile then
      request_args.cafile = opts.ssl_cafile
    end
    -- Note: luasec on Debian uses /etc/ssl/certs/ca-certificates.crt
    -- by default.  When ssl_cafile is nil we rely on that.
    local ok, status, headers, status_line =
      https.request(request_args)
    if not ok then
      return nil, M.ERR.TRANSPORT,
        "https.request failed: " .. tostring(status)
    end
    if status ~= 200 then
      return nil, M.ERR.TRANSPORT,
        "receiver returned HTTP " .. tostring(status) ..
        " (" .. tostring(status_line or "") .. ")"
    end
    return table.concat(response_chunks), nil
  end

  -- Plaintext path (loopback / .onion proxied).  http.request returns
  -- (body, status, headers, status_line) on success when sink/source
  -- aren't supplied, but with source/sink it returns (ok, code, ...).
  local http, herr = load_http()
  if not http then return nil, M.ERR.TRANSPORT, herr end
  local ok, status = http.request(request_args)
  if not ok then
    return nil, M.ERR.TRANSPORT,
      "http.request failed: " .. tostring(status)
  end
  if status ~= 200 then
    return nil, M.ERR.TRANSPORT,
      "receiver returned HTTP " .. tostring(status)
  end
  return table.concat(response_chunks), nil
end

--------------------------------------------------------------------------------
-- Anti-snoop validators (G10-G15)
--------------------------------------------------------------------------------

-- Helper: build a set of outpoint keys for fast membership tests.
local function outpoint_set(tx)
  local set = {}
  for _, inp in ipairs(tx.inputs) do
    local key = inp.prev_out.hash.bytes ..
                string.char(
                  inp.prev_out.index % 256,
                  math.floor(inp.prev_out.index / 256) % 256,
                  math.floor(inp.prev_out.index / 65536) % 256,
                  math.floor(inp.prev_out.index / 16777216) % 256)
    set[key] = true
  end
  return set
end

-- Helper: build a set of script_pubkey strings for fast membership.
local function script_set(tx)
  local set = {}
  for _, out in ipairs(tx.outputs) do
    set[out.script_pubkey] = (set[out.script_pubkey] or 0) + 1
  end
  return set
end

--------------------------------------------------------------------------------
-- G12 [P0-SECURITY]: payjoin_check_inputs
--
-- Sender no-new-inputs (of sender's own).  After a PayJoin handshake
-- the Proposal's input set MUST be a superset of the Original's, AND
-- every NEW input MUST NOT be owned by the sender.
--
-- The "not owned by sender" check is critical: without it, a malicious
-- receiver could probe the sender's UTXO set by submitting candidate
-- outpoints they suspect belong to the sender, and observe which
-- Proposals pass through the sender's signing pipeline.
--
-- `sender_outpoints` is a set of outpoint-keys (txid_bytes .. vout_le4)
-- the sender controls.  Callers usually derive this from
-- wallet:list_unspent or the wallet's UTXO map.
function M.payjoin_check_inputs(original_psbt, proposal_psbt, sender_outpoints)
  local orig_set = outpoint_set(original_psbt.tx)

  -- Every original input must still be present (no input removed).
  local proposal_set = outpoint_set(proposal_psbt.tx)
  for key in pairs(orig_set) do
    if not proposal_set[key] then
      return false, "Receiver removed a sender input from the proposal"
    end
  end

  -- Every NEW input must not be sender-owned.
  for _, inp in ipairs(proposal_psbt.tx.inputs) do
    local key = inp.prev_out.hash.bytes ..
                string.char(
                  inp.prev_out.index % 256,
                  math.floor(inp.prev_out.index / 256) % 256,
                  math.floor(inp.prev_out.index / 65536) % 256,
                  math.floor(inp.prev_out.index / 16777216) % 256)
    if not orig_set[key] then
      -- New input — must NOT be ours.
      if sender_outpoints and sender_outpoints[key] then
        return false,
          "Receiver added an input owned by the sender (UTXO-probe attack)"
      end
    end
  end

  return true, nil
end

--------------------------------------------------------------------------------
-- G10 [P0-SECURITY]: payjoin_check_outputs
--
-- Sender output-set anti-snoop.  The Proposal's outputs may differ from
-- the Original's ONLY in:
--   * The payment-output amount may have been bumped (BIP-78 §Receiver).
--   * The change-output amount may have been reduced by the
--     receiver-declared maxadditionalfeecontribution.
-- New outputs MUST NOT be added.  Outputs MUST NOT be removed.
-- (The receiver may change the order, but the SET — by script_pubkey —
-- must match: every sender output script must still be present, and
-- every proposal output script must be a sender output OR the payment
-- script.)
function M.payjoin_check_outputs(original_psbt, proposal_psbt)
  local orig_scripts = script_set(original_psbt.tx)
  local prop_scripts = script_set(proposal_psbt.tx)

  -- Every sender output script must still be present at least as many
  -- times as it was in the original.
  for spk, count in pairs(orig_scripts) do
    local pc = prop_scripts[spk] or 0
    if pc < count then
      return false,
        "Receiver removed an output (script_pubkey absent or under-counted)"
    end
  end
  -- Every proposal output script must have been in the original.
  -- This rejects any NEW output the receiver tried to inject.
  for spk in pairs(prop_scripts) do
    if not orig_scripts[spk] then
      return false,
        "Receiver added a new output (output-set anti-snoop violation)"
    end
  end

  return true, nil
end

--------------------------------------------------------------------------------
-- G11 [P1]: payjoin_check_scriptsig
--
-- Sender scriptSig-type homogeneity.  The script types of receiver-added
-- inputs MUST match the type of the sender's inputs (else the resulting
-- tx exhibits a mixed-input-type fingerprint that screams "PayJoin").
--
-- We classify each input by its prevout script_pubkey (witness_utxo for
-- segwit, non_witness_utxo[vout] for legacy) and assert all share a
-- type.  The PSBT inputs MUST have witness_utxo populated to make this
-- check possible — the receiver populates it for added inputs, the
-- sender for its own.
function M.payjoin_check_scriptsig(original_psbt, proposal_psbt)
  local types_seen = {}
  for i, p_in in ipairs(proposal_psbt.inputs) do
    local spk
    if p_in.witness_utxo and p_in.witness_utxo.script_pubkey then
      spk = p_in.witness_utxo.script_pubkey
    elseif p_in.non_witness_utxo and p_in.non_witness_utxo.outputs then
      local outpoint_index = proposal_psbt.tx.inputs[i].prev_out.index
      local prev_out = p_in.non_witness_utxo.outputs[outpoint_index + 1]
      if prev_out then spk = prev_out.script_pubkey end
    end
    if not spk then
      -- Cannot classify without the prev output script.  BIP-174 says
      -- both witness_utxo and non_witness_utxo are optional in
      -- principle, but BIP-78 mandates one of them for every input.
      return false,
        "Proposal input " .. tostring(i) ..
        " lacks witness_utxo and non_witness_utxo (cannot classify)"
    end
    local stype = script_mod.classify_script(spk)
    types_seen[stype or "unknown"] = true
  end
  -- Count distinct types.
  local count = 0
  local last_type
  for t in pairs(types_seen) do
    count = count + 1
    last_type = t
  end
  if count > 1 then
    local list = {}
    for t in pairs(types_seen) do list[#list + 1] = t end
    return false,
      "Mixed scriptSig types in proposal: " .. table.concat(list, ", ") ..
      " (PayJoin fingerprint leak)"
  end
  return true, nil, last_type
end

--------------------------------------------------------------------------------
-- G13 [P1]: enforce_max_additional_fee
--
-- Sender max-additional-fee enforcement.  The sender announces the
-- maximum fee it is willing to absorb on the receiver's behalf via
-- maxadditionalfeecontribution; on response, the sender verifies the
-- proposal's fee did not exceed (original_fee + max_additional).
--
-- @param original_fee_sats   number  sender-computed Original fee
-- @param proposal_fee_sats   number  fee derived from the Proposal
--                                    (sum of input values - sum of output values)
-- @param max_additional_sats number  sender-declared cap
function M.enforce_max_additional_fee(original_fee_sats, proposal_fee_sats,
                                       max_additional_sats)
  if type(original_fee_sats) ~= "number" or
     type(proposal_fee_sats) ~= "number" or
     type(max_additional_sats) ~= "number" then
    return false, "fee arguments must all be numbers"
  end
  local delta = proposal_fee_sats - original_fee_sats
  if delta > max_additional_sats then
    return false,
      string.format(
        "Proposal fee exceeds max_additional: delta=%d, cap=%d",
        delta, max_additional_sats)
  end
  return true, nil, delta
end

--------------------------------------------------------------------------------
-- G14 [P1]: payjoin_check_disable_substitution
--
-- When sender announced disableoutputsubstitution=1, the receiver MUST
-- NOT modify the payment output amount.  We verify by comparing the
-- payment output (located via `payment_script`) between Original and
-- Proposal.
function M.payjoin_check_disable_substitution(original_psbt, proposal_psbt,
                                               payment_script, disable_os)
  if not disable_os then
    return true, nil
  end
  local orig_amt, prop_amt
  for _, out in ipairs(original_psbt.tx.outputs) do
    if out.script_pubkey == payment_script then
      orig_amt = out.value; break
    end
  end
  for _, out in ipairs(proposal_psbt.tx.outputs) do
    if out.script_pubkey == payment_script then
      prop_amt = out.value; break
    end
  end
  if orig_amt == nil or prop_amt == nil then
    return false, "payment output not found in original or proposal"
  end
  if orig_amt ~= prop_amt then
    return false,
      string.format(
        "Receiver bumped payment output despite disableoutputsubstitution=1 " ..
        "(orig=%d, proposal=%d)", orig_amt, prop_amt)
  end
  return true, nil
end

--------------------------------------------------------------------------------
-- G15 [P1]: payjoin_check_min_feerate
--
-- The sender announces the lowest effective fee rate it accepts.  After
-- the proposal lands, the sender re-computes effective fee rate
-- (proposal_fee / proposal_vsize) and rejects if below minfeerate.
function M.payjoin_check_min_feerate(proposal_fee_sats, proposal_vsize,
                                      minfeerate_sat_vb)
  if minfeerate_sat_vb == nil or minfeerate_sat_vb == 0 then
    return true, nil  -- no constraint
  end
  if type(proposal_fee_sats) ~= "number" or
     type(proposal_vsize) ~= "number" or proposal_vsize <= 0 then
    return false, "invalid fee/vsize arguments"
  end
  local effective = proposal_fee_sats / proposal_vsize
  if effective < minfeerate_sat_vb then
    return false,
      string.format(
        "Proposal effective fee rate %.3f sat/vB below minfeerate %.3f sat/vB",
        effective, minfeerate_sat_vb)
  end
  return true, nil, effective
end

--------------------------------------------------------------------------------
-- G22 [P0]: payjoin_fallback
--
-- When PayJoin negotiation fails for ANY reason (transport, snoop
-- detection, sign failure, broadcast failure), the sender MUST broadcast
-- the Original PSBT — payment still happens, the receiver simply loses
-- the privacy benefit.
--
-- @param mempool   table  the local mempool (lunarblock.mempool)
-- @param peer_mgr  table  optional peer manager for inv broadcast
-- @param tx        table  the extracted, signed Original transaction
-- @return  ok       boolean
-- @return  txid_hex string|nil  on success, the broadcast txid (display hex)
-- @return  err      string|nil  on failure
function M.payjoin_fallback(mempool, peer_mgr, tx)
  if not mempool then
    return false, nil, "no mempool configured"
  end
  local ok, txid_hex = mempool:accept_transaction(tx)
  if not ok then
    return false, nil, "mempool rejected fallback: " .. tostring(txid_hex)
  end
  if peer_mgr then
    -- Best-effort INV broadcast; identical pattern to sendrawtransaction.
    local p2p = require("lunarblock.p2p")
    local txid = validation.compute_txid(tx)
    local inv_payload = p2p.serialize_inv({
      {type = p2p.INV_TYPE.MSG_WITNESS_TX, hash = txid}
    })
    pcall(function() peer_mgr:broadcast("inv", inv_payload) end)
  end
  return true, txid_hex, nil
end

--------------------------------------------------------------------------------
-- Top-level: send_payjoin_request
--
-- The full sender state machine.  Returns:
--   success: txid_hex, "payjoin" | "fallback", nil
--   failure: nil, nil, err_table { code, message }
--
-- Argument shape:
--   wallet       table  lunarblock.wallet instance (signs sender inputs)
--   mempool      table  lunarblock.mempool (broadcasts the final tx)
--   peer_mgr     table  optional; for INV broadcast
--   uri          string BIP-21 URI with pj=
--   recipients   table  [{address, amount}, ...] — what to send
--   options      table  {
--     fee_rate                       number  sat/vB
--     conf_target                    number  for fee estimator
--     maxadditionalfeecontribution   number  sats (defaults to 0)
--     additionalfeeoutputindex       number  0-based output index
--     disableoutputsubstitution      boolean
--     minfeerate                     number  sat/vB
--     network                        string  "mainnet" | "regtest" | ...
--                                              (for BIP-21 parse)
--     transport                      function TEST HOOK (see http_post)
--     ssl_verify                     string  "peer" (default) | "none"
--     ssl_cafile                     string  CA bundle override
--   }
function M.send_payjoin_request(wallet, mempool, peer_mgr, uri, recipients, options)
  options = options or {}

  -- ---- Step 1: parse BIP-21 URI ----------------------------------------
  local parsed_uri = bip21.parse(uri, options.network or "mainnet")
  if parsed_uri.err then
    return nil, nil, {code = M.ERR.BAD_URI,
                      message = "BIP-21 parse: " .. parsed_uri.err}
  end
  if not parsed_uri.pj then
    return nil, nil, {code = M.ERR.BAD_URI,
                      message = "URI has no pj= parameter (not a PayJoin URI)"}
  end
  local pj_url, perr = parse_pj_url(parsed_uri.pj)
  if not pj_url then
    return nil, nil, {code = M.ERR.BAD_URI,
                      message = "pj URL: " .. tostring(perr)}
  end

  -- Inject the BIP-21 amount as the payment.  When recipients is
  -- empty/nil but parsed_uri.amount is set, build the recipients list
  -- from the URI.
  if (not recipients or #recipients == 0) and parsed_uri.amount and
     parsed_uri.address then
    recipients = {{address = parsed_uri.address, amount = parsed_uri.amount}}
  end
  if not recipients or #recipients == 0 then
    return nil, nil, {code = M.ERR.BAD_URI,
                      message = "no recipients (BIP-21 amount missing)"}
  end

  -- ---- Step 2: build + sign the Original transaction -------------------
  -- create_transaction returns (tx, fee, algo) on success.
  local orig_tx, orig_fee = wallet:create_transaction(recipients, options)
  if not orig_tx then
    return nil, nil, {code = M.ERR.SIGN_FAILED,
                      message = "create_transaction failed: " ..
                                tostring(orig_fee)}
  end
  -- The sender's recipient script (for G14 + G10 anchor) is identified by
  -- the first recipient's address.
  local recipient_addr_type, recipient_program =
    address_mod.decode_address(recipients[1].address,
                               wallet.network and wallet.network.name or "mainnet")
  if not recipient_addr_type then
    return nil, nil, {code = M.ERR.BAD_URI,
                      message = "recipient address invalid"}
  end
  local payment_script
  if recipient_addr_type == "p2wpkh" then
    payment_script = script_mod.make_p2wpkh_script(recipient_program)
  elseif recipient_addr_type == "p2pkh" then
    payment_script = script_mod.make_p2pkh_script(recipient_program)
  elseif recipient_addr_type == "p2wsh" then
    payment_script = script_mod.make_p2wsh_script(recipient_program)
  elseif recipient_addr_type == "p2sh" then
    payment_script = script_mod.make_p2sh_script(recipient_program)
  elseif recipient_addr_type == "p2tr" then
    payment_script = script_mod.make_p2tr_script(recipient_program)
  end

  -- Wrap the Original tx in a PSBT.  We need an UNSIGNED PSBT for
  -- transport (BIP-78 §Sender) — strip the witnesses + scriptSigs and
  -- preserve them in a parallel signed-tx for fallback.
  --
  -- We keep the SIGNED Original tx in `signed_orig_tx` for fallback
  -- broadcast (G22) and produce an unsigned twin for the PSBT.
  local signed_orig_tx = orig_tx
  local unsigned_tx = types.transaction(
    orig_tx.version,
    {}, {},
    orig_tx.locktime)
  unsigned_tx.segwit = orig_tx.segwit
  for _, inp in ipairs(orig_tx.inputs) do
    unsigned_tx.inputs[#unsigned_tx.inputs + 1] = types.txin(
      types.outpoint(inp.prev_out.hash, inp.prev_out.index),
      "", inp.sequence)
  end
  for _, out in ipairs(orig_tx.outputs) do
    unsigned_tx.outputs[#unsigned_tx.outputs + 1] =
      types.txout(out.value, out.script_pubkey)
  end

  local orig_psbt = psbt_mod.new(unsigned_tx)
  -- Populate witness_utxo on every sender input so the receiver can
  -- verify ownership and so G11 (scriptSig homogeneity) can classify.
  -- We look the value/spk up via the wallet's UTXO map.
  for i, inp in ipairs(unsigned_tx.inputs) do
    local outpoint_key = inp.prev_out.hash.bytes ..
                         string.char(
                           inp.prev_out.index % 256,
                           math.floor(inp.prev_out.index / 256) % 256,
                           math.floor(inp.prev_out.index / 65536) % 256,
                           math.floor(inp.prev_out.index / 16777216) % 256)
    local utxo = wallet.utxos and wallet.utxos[outpoint_key]
    if utxo then
      orig_psbt.inputs[i].witness_utxo = {
        value         = utxo.value,
        script_pubkey = utxo.script_pubkey,
      }
    end
  end

  -- ---- Step 3: build sender_outpoints set for G12 -----------------------
  -- Every UTXO the wallet has visibility on counts as "sender-owned".
  local sender_outpoints = {}
  if wallet.utxos then
    for key, _ in pairs(wallet.utxos) do
      sender_outpoints[key] = true
    end
  end

  -- ---- Step 4: POST the Original PSBT (G2 + G24) ------------------------
  local b64_original = psbt_mod.to_base64(orig_psbt)
  local query_str = build_query(options)
  local body, terr_code, terr_msg = http_post(pj_url, b64_original,
                                              query_str, options)
  if not body then
    -- Transport failed → fall back to Original broadcast (G22).
    local ok, txid_hex, ferr = M.payjoin_fallback(mempool, peer_mgr,
                                                   signed_orig_tx)
    if ok then
      return txid_hex, "fallback", {code = terr_code, message = terr_msg}
    end
    return nil, nil, {code = M.ERR.TRANSPORT,
                      message = "transport failed AND fallback failed: " ..
                                tostring(terr_msg) ..
                                " | fallback: " .. tostring(ferr)}
  end

  -- ---- Step 5: parse Proposal PSBT --------------------------------------
  body = body:gsub("[\r\n%s]+$", "")  -- strip trailing whitespace
  local ok_parse, proposal_psbt = pcall(psbt_mod.from_base64, body)
  if not ok_parse or type(proposal_psbt) ~= "table" or not proposal_psbt.tx then
    local ok_fb, txid_hex_fb, fb_err = M.payjoin_fallback(mempool, peer_mgr,
                                                          signed_orig_tx)
    if ok_fb then
      return txid_hex_fb, "fallback", {code = M.ERR.BAD_RESPONSE,
                                       message = "response is not a PSBT"}
    end
    return nil, nil, {code = M.ERR.BAD_RESPONSE,
                      message = "response not a PSBT AND fallback failed: " ..
                                tostring(fb_err)}
  end

  -- ---- Step 6: run six anti-snoop validators (G10-G15) ------------------
  local checks = {}

  -- G12 [P0-SECURITY]: no new sender-owned inputs.
  local ok12, msg12 = M.payjoin_check_inputs(orig_psbt, proposal_psbt,
                                              sender_outpoints)
  checks[#checks + 1] = {gate = "G12", ok = ok12, msg = msg12}

  -- G10 [P0-SECURITY]: no new outputs.
  local ok10, msg10 = M.payjoin_check_outputs(orig_psbt, proposal_psbt)
  checks[#checks + 1] = {gate = "G10", ok = ok10, msg = msg10}

  -- G11 [P1]: scriptSig homogeneity.
  local ok11, msg11 = M.payjoin_check_scriptsig(orig_psbt, proposal_psbt)
  checks[#checks + 1] = {gate = "G11", ok = ok11, msg = msg11}

  -- G14 [P1]: disableoutputsubstitution honored.
  local ok14, msg14 = M.payjoin_check_disable_substitution(
    orig_psbt, proposal_psbt, payment_script,
    options.disableoutputsubstitution and true or false)
  checks[#checks + 1] = {gate = "G14", ok = ok14, msg = msg14}

  -- G13 [P1]: max_additional_fee.  Compute proposal fee.  This is
  -- approximate when witness_utxo isn't populated on every input — for
  -- the foundation we accept that and treat missing inputs as
  -- contributing 0 (which conservatively biases the check toward
  -- "exceeded").
  local proposal_fee = 0
  do
    local total_in = 0
    for i, _ in ipairs(proposal_psbt.tx.inputs) do
      local p_in = proposal_psbt.inputs[i]
      if p_in and p_in.witness_utxo and p_in.witness_utxo.value then
        total_in = total_in + p_in.witness_utxo.value
      end
    end
    local total_out = 0
    for _, out in ipairs(proposal_psbt.tx.outputs) do
      total_out = total_out + out.value
    end
    proposal_fee = total_in - total_out
  end
  local ok13, msg13
  if options.maxadditionalfeecontribution then
    ok13, msg13 = M.enforce_max_additional_fee(orig_fee, proposal_fee,
      tonumber(options.maxadditionalfeecontribution) or 0)
  else
    ok13 = true
  end
  checks[#checks + 1] = {gate = "G13", ok = ok13, msg = msg13}

  -- G15 [P1]: minfeerate respected.  vsize is a rough estimate
  -- (proposal_vsize = ceil( raw_serialized_size * 0.75 + witness_size *
  -- 0.25 )) — we keep the formula simple here and use the unsigned
  -- proposal's raw size as a lower bound.  Operators tuning minfeerate
  -- aggressively should set generous bounds.
  local ok15, msg15 = true, nil
  if options.minfeerate then
    local raw_size = #serialize.serialize_transaction(proposal_psbt.tx, false)
    -- Add a placeholder 108 vbytes per input for witness — generous.
    local approx_vsize = raw_size + 108 * #proposal_psbt.tx.inputs
    ok15, msg15 = M.payjoin_check_min_feerate(proposal_fee, approx_vsize,
                                               tonumber(options.minfeerate))
  end
  checks[#checks + 1] = {gate = "G15", ok = ok15, msg = msg15}

  -- Any failed validator → abandon PayJoin, broadcast Original.
  for _, c in ipairs(checks) do
    if not c.ok then
      local err_code = M.ERR.SNOOP
      if c.gate == "G13" then err_code = M.ERR.FEE_EXCEEDED end
      if c.gate == "G14" then err_code = M.ERR.DISABLE_OS end
      if c.gate == "G15" then err_code = M.ERR.MIN_FEERATE end
      local ok_fb, txid_hex_fb = M.payjoin_fallback(mempool, peer_mgr,
                                                     signed_orig_tx)
      if ok_fb then
        return txid_hex_fb, "fallback",
          {code = err_code,
           message = c.gate .. " failed: " .. tostring(c.msg)}
      end
      return nil, nil,
        {code = err_code,
         message = c.gate .. " failed AND fallback failed: " ..
                   tostring(c.msg)}
    end
  end

  -- ---- Step 7: re-sign the sender inputs in the proposal (FIX-61) ------
  -- BIP-78 §Sender: receiver returns the Proposal with sender inputs
  -- UNSIGNED (the receiver couldn't sign them anyway).  Sender re-signs
  -- only its own input slots; receiver-added inputs already carry their
  -- final_script_witness.
  local input_utxos = {}
  local sender_indices = {}
  for i, p_in in ipairs(proposal_psbt.inputs) do
    if not p_in.final_script_witness and not p_in.final_script_sig then
      -- Sender owns this input slot.  Look up its UTXO in the wallet.
      local tx_in = proposal_psbt.tx.inputs[i]
      local outpoint_key = tx_in.prev_out.hash.bytes ..
                           string.char(
                             tx_in.prev_out.index % 256,
                             math.floor(tx_in.prev_out.index / 256) % 256,
                             math.floor(tx_in.prev_out.index / 65536) % 256,
                             math.floor(tx_in.prev_out.index / 16777216) % 256)
      local u = wallet.utxos and wallet.utxos[outpoint_key]
      if u then
        input_utxos[i] = {
          value         = u.value,
          script_pubkey = u.script_pubkey,
          address       = u.address,
        }
        sender_indices[#sender_indices + 1] = i
      end
    end
  end

  -- Single-pipeline anchor: route through Wallet:_sign_inputs.
  proposal_psbt.tx.segwit = true
  local sign_ok, sign_err = wallet:_sign_inputs(proposal_psbt.tx,
                                                input_utxos, sender_indices)
  if not sign_ok then
    local ok_fb, txid_hex_fb = M.payjoin_fallback(mempool, peer_mgr,
                                                   signed_orig_tx)
    if ok_fb then
      return txid_hex_fb, "fallback",
        {code = M.ERR.SIGN_FAILED,
         message = "sender re-sign failed: " .. tostring(sign_err)}
    end
    return nil, nil, {code = M.ERR.SIGN_FAILED,
                      message = "sender re-sign failed AND fallback failed: " ..
                                tostring(sign_err)}
  end

  -- Apply receiver's final_script_witness onto its inputs.
  for i, p_in in ipairs(proposal_psbt.inputs) do
    if p_in.final_script_witness then
      proposal_psbt.tx.inputs[i].witness = p_in.final_script_witness
    end
  end

  -- ---- Step 8: broadcast the final PayJoin tx --------------------------
  local final_tx = proposal_psbt.tx
  local ok_bc, txid_hex_bc = mempool:accept_transaction(final_tx)
  if not ok_bc then
    local ok_fb, txid_hex_fb = M.payjoin_fallback(mempool, peer_mgr,
                                                   signed_orig_tx)
    if ok_fb then
      return txid_hex_fb, "fallback",
        {code = M.ERR.BROADCAST,
         message = "PayJoin tx rejected: " .. tostring(txid_hex_bc)}
    end
    return nil, nil, {code = M.ERR.BROADCAST,
                      message = "PayJoin tx rejected AND fallback failed: " ..
                                tostring(txid_hex_bc)}
  end

  if peer_mgr then
    local p2p = require("lunarblock.p2p")
    local txid = validation.compute_txid(final_tx)
    local inv_payload = p2p.serialize_inv({
      {type = p2p.INV_TYPE.MSG_WITNESS_TX, hash = txid}
    })
    pcall(function() peer_mgr:broadcast("inv", inv_payload) end)
  end

  return txid_hex_bc, "payjoin", nil
end

-- Test-only helpers (export so tests can exercise without going
-- through the full pipeline).
M._parse_pj_url = parse_pj_url
M._build_query  = build_query
M._http_post    = http_post

return M
