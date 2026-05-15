#!/usr/bin/env luajit
-- W119 BIP-78 PayJoin audit — lunarblock (Lua / LuaJIT)
--
-- Scope: BIP-78 (PayJoin / "P2EP" Pay-to-EndPoint) — a sender-receiver
-- interactive transaction protocol where the receiver contributes their
-- own inputs to the payment, breaking the common-input heuristic. Not in
-- Bitcoin Core (consensus has no notion of PayJoin), but established in
-- the wider ecosystem via the BIP itself, payjoin.org, and the
-- btcpayserver/payjoin reference implementation.
--
--   30-gate plan
--   ============
--   G1   recv-HTTP            G16  query-params
--   G2   send-HTTP            G17  4-error-codes (unavailable/not-enough-money/
--   G3   TLS-onion                  version-unsupported/original-psbt-rejected)
--   G4   OrigPSBT-deser       G18  recv-TTL
--   G5   recv-validate        G19  recv-no-double-receive
--   G6   fee-output-id        G20  recv-UTXO-anti-fp
--   G7   recv-add-inputs      G21  v=1-header
--   G8   recv-modify-output   G22  send-fallback-broadcast
--   G9   recv-fee-adj         G23  recv-Content-Type "text/plain; charset=utf-8"
--   G10  send-anti-snoop-out  G24  HTTPS-cert validation (clearnet)
--   G11  send-scriptSig-types G25  Tor-onion routing
--   G12  send-no-new-inputs   G26  getpayjoinrequest RPC
--   G13  send-max-fee         G27  sendpayjoinrequest RPC
--   G14  send-disableos       G28  BIP-21 pj= URI parameter
--   G15  send-min-fee-rate    G29  BIP-21 pjos= URI parameter
--                             G30  recv-replay (same-pubkey-double-spend)
--
-- Usage:
--   cd /home/work/hashhog/lunarblock
--   luajit tests/test_w119_payjoin.lua 2>&1
--
-- Expected outcome: lunarblock has no PayJoin implementation. Every gate
-- is recorded as a MISSING bug. The test suite passes as long as the
-- count of FAILs equals the count of BUG entries (i.e. only the
-- bug-confirmation tests fail).

package.path = "src/?.lua;./?.lua;" .. package.path

-- Module loader (mirrors test_w118_wallet.lua) -----------------------
local loaders = package.loaders or package.searchers
table.insert(loaders, 2, function(module)
  local name = module:match("^lunarblock%.(.+)")
  if name then
    local filename = "src/" .. name .. ".lua"
    local f = io.open(filename)
    if f then f:close(); return function() return dofile(filename) end end
  end
  return nil, "not found"
end)

-- Lightweight requires — we mostly source-search rather than exercise
-- runtime APIs, since none of those APIs exist for PayJoin.
local address  -- BIP-21 URI parser would live here (or src/address.lua).
local wallet   -- send/recv flows.
local psbt     -- OrigPSBT round-trip.
local rpc      -- getpayjoinrequest / sendpayjoinrequest dispatch.
local rest     -- HTTP server (would host the receiver endpoint).
local _ok
_ok, address = pcall(require, "lunarblock.address")
_ok, wallet  = pcall(require, "lunarblock.wallet")
_ok, psbt    = pcall(require, "lunarblock.psbt")
_ok, rpc     = pcall(require, "lunarblock.rpc")
_ok, rest    = pcall(require, "lunarblock.rest")

-- ------------------------------------------------------------------ --
-- Source slurper (cached) — gates read the live source so the audit  --
-- moves to PARTIAL/PASS the day someone wires PayJoin.                --
-- ------------------------------------------------------------------ --
local SRC_CACHE = {}
local function source_of(path)
  if SRC_CACHE[path] ~= nil then return SRC_CACHE[path] end
  local f = io.open(path, "r")
  if not f then SRC_CACHE[path] = ""; return "" end
  local s = f:read("*a") or ""
  f:close()
  SRC_CACHE[path] = s
  return s
end

local SRC_FILES = {
  "src/wallet.lua", "src/rpc.lua", "src/psbt.lua", "src/rest.lua",
  "src/main.lua", "src/address.lua", "src/p2p.lua", "src/peerman.lua",
  "src/proxy.lua", "src/bip21.lua",  -- FIX-62: BIP-21 URI parser landed.
}

local function any_source_matches(pattern)
  for _, p in ipairs(SRC_FILES) do
    local s = source_of(p)
    if s:find(pattern) then return true, p end
  end
  return false, nil
end

-- PayJoin-context-sensitive search: returns true only if `pattern`
-- occurs WITHIN ~200 chars of a "payjoin"/"BIP-78" marker, OR if the
-- pattern is a clearly PayJoin-specific token. Used for keywords that
-- overlap with generic Bitcoin terminology (minfeerate, unavailable).
local function any_payjoin_context_matches(pattern)
  for _, p in ipairs(SRC_FILES) do
    local s = source_of(p)
    -- Slice the source into windows around each "payjoin"/"bip78"/"BIP-78"
    -- anchor and search only there.
    local lower = s:lower()
    local idx = 1
    while true do
      local a, b = lower:find("payjoin", idx, true)
      if not a then
        a, b = lower:find("bip%-?78", idx)
        if not a then
          a, b = lower:find("bip78", idx, true)
        end
      end
      if not a then break end
      local lo = math.max(1, a - 200)
      local hi = math.min(#s, b + 200)
      if s:sub(lo, hi):find(pattern) then return true, p end
      idx = b + 1
    end
  end
  return false, nil
end

-- ------------------------------------------------------------------ --
-- Harness                                                              --
-- ------------------------------------------------------------------ --
local PASS, FAIL, SKIP = 0, 0, 0
local BUGS = {}

local function pass(name) io.write(string.format("  PASS  %s\n", name)); PASS = PASS + 1 end
local function fail(name, msg) io.write(string.format("  FAIL  %s -- %s\n", name, msg)); FAIL = FAIL + 1 end
local function skip(name, why) io.write(string.format("  SKIP  %s -- %s\n", name, why)); SKIP = SKIP + 1 end

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then pass(name) else fail(name, tostring(err)) end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) .. ", expected " .. tostring(b))
  end
end
local function expect_true(v, msg) if not v then error(msg or "expected true") end end
local function expect_nil(v, msg) if v ~= nil then error((msg or "expected nil") .. ", got " .. tostring(v)) end end

local function bug(id, severity, desc)
  BUGS[#BUGS + 1] = string.format("%s (%s)  %s", id, severity, desc)
end

print("=== W119 lunarblock BIP-78 PayJoin Audit ===\n")

-- =================================================================== --
-- G1-G3: HTTP / TLS transport                                          --
-- =================================================================== --
print("--- G1-G3: HTTP / TLS / Tor transport ---")

-- G1: receiver HTTP endpoint
test("G1: receiver HTTP endpoint absent (G1-BUG-1)", function()
  local hit = any_source_matches("payjoin")
  expect_eq(hit, false, "no payjoin sources at all")
  local rpc_src = source_of("src/rpc.lua")
  expect_nil(rpc_src:find('self%.methods%["getpayjoinrequest"%]'),
             "no getpayjoinrequest RPC")
  local rest_src = source_of("src/rest.lua")
  expect_nil(rest_src:find("payjoin"), "no payjoin handler on REST server")
  bug("G1-BUG-1", "P0",
      "Receiver HTTP endpoint absent. BIP-78 §Receiver requires POST handler " ..
      "accepting Original PSBT body. lunarblock has src/rest.lua HTTP server " ..
      "but no /payjoin route; src/rpc.lua has 101 RPC methods, none for " ..
      "payjoin. Wallet cannot receive PayJoin payments at all.")
end)

-- G2: sender HTTP client
test("G2: sender HTTP client absent (G2-BUG-2)", function()
  local has, _ = any_source_matches("payjoin")
  expect_eq(has, false, "no payjoin sources")
  -- Confirm no http POST helper that targets a pj endpoint either.
  local has_pj, _ = any_source_matches("pj=")
  expect_eq(has_pj, false, "no pj= URI parameter handling")
  bug("G2-BUG-2", "P0",
      "Sender HTTP client absent. BIP-78 §Sender: sender POSTs the Original " ..
      "PSBT to the receiver's pj= endpoint. lunarblock has no outbound HTTP " ..
      "client whatsoever (no luasec/luasocket-based POST in src/). " ..
      "Cannot initiate PayJoin payments.")
end)

-- G3: TLS / .onion endpoint support
test("G3: TLS-onion endpoint support absent (G3-BUG-3)", function()
  local proxy_src = source_of("src/proxy.lua")
  -- proxy.lua exists for Tor P2P (W117 FIX-58) but isn't wired for HTTP.
  expect_nil(proxy_src:find("payjoin"), "no payjoin in proxy.lua")
  expect_nil(proxy_src:find("https"), "no https client wrapper")
  bug("G3-BUG-3", "P0",
      "TLS / .onion endpoint support absent. BIP-78 mandates either HTTPS " ..
      "(with cert validation) for clearnet OR a .onion v3 hidden service. " ..
      "lunarblock's src/proxy.lua wires SOCKS5 for the BIP-155 P2P path only " ..
      "(W117 FIX-58); no HTTPS client and no PayJoin-over-Tor adapter.")
end)

-- =================================================================== --
-- G4-G9: Receiver-side PSBT manipulation                               --
-- =================================================================== --
print("\n--- G4-G9: Receiver-side PSBT manipulation ---")

-- G4: Original PSBT deserialization on the receiver side
test("G4: receiver-side Original PSBT deserialize absent (G4-BUG-4)", function()
  -- psbt.deserialize EXISTS and is correct for BIP-174 (tested in W118).
  -- The gap is that nothing CALLS it from a payjoin context.
  expect_true(type(psbt) == "table" and type(psbt.deserialize) == "function",
              "psbt.deserialize exists in BIP-174 form")
  local has, _ = any_source_matches("original.psbt")
  expect_eq(has, false, "no 'original psbt' string in any source")
  bug("G4-BUG-4", "P0",
      "Original PSBT deserialization is unwired for PayJoin. psbt.deserialize " ..
      "exists and is BIP-174-correct (W118 verified), but there is no " ..
      "receiver entry point that decodes a sender-submitted Original PSBT, " ..
      "let alone the BIP-78-specific constraints (no unknown fields, " ..
      "non-witness/witness_utxo present, all-inputs finalized policy).")
end)

-- G5: receiver-side PSBT validation (BIP-78 §Receiver checklist)
test("G5: receiver-side BIP-78 validation absent (G5-BUG-5)", function()
  -- Required checks per BIP-78 §Receiver checks:
  --   1. all inputs have witness_utxo or non_witness_utxo
  --   2. all inputs are finalized (signed)
  --   3. mixed input types prohibited (P2WPKH+P2PKH, etc.)
  --   4. no unknown fields with implicit-required semantics
  local has, _ = any_source_matches("original.psbt.reject")
  expect_eq(has, false, "no PayJoin original-psbt-rejected validator")
  bug("G5-BUG-5", "P0",
      "Receiver-side BIP-78 validation absent. BIP-78 §Receiver checks " ..
      "require: all-inputs-finalized, witness/non-witness UTXO present, " ..
      "homogeneous scriptSig types across inputs, no unknown-required " ..
      "fields. None of these exist. The 'original-psbt-rejected' error code " ..
      "cannot be emitted.")
end)

-- G6: receiver identifying the fee output ("additionalfeeoutputindex")
test("G6: fee-output identification logic absent (G6-BUG-6)", function()
  local has, _ = any_source_matches("additionalfeeoutputindex")
  expect_eq(has, false, "additionalfeeoutputindex parameter absent")
  bug("G6-BUG-6", "P1",
      "Fee-output identification logic absent. BIP-78 §Receiver: sender " ..
      "specifies additionalfeeoutputindex=N pointing at the change output " ..
      "the receiver may deduct fees from. lunarblock has no parser for " ..
      "this URL parameter and no concept of 'which output is the change " ..
      "vs. payment output' in a PayJoin context.")
end)

-- G7: receiver adding inputs to the proposal
test("G7: receiver-input contribution path absent (G7-BUG-7)", function()
  local has, _ = any_source_matches("contribute.input")
  expect_eq(has, false, "no contribute_input helper")
  local has2, _ = any_source_matches("payjoin_add_input")
  expect_eq(has2, false, "no payjoin_add_input")
  bug("G7-BUG-7", "P0",
      "Receiver-input contribution path absent. The whole point of BIP-78 " ..
      "is the receiver adds at least one of their own inputs (defeating the " ..
      "common-input-ownership heuristic). lunarblock's wallet coin-selection " ..
      "is written for unilateral sends only; there is no path for the wallet " ..
      "to enumerate its UTXOs against a sender-supplied PSBT and append " ..
      "inputs.")
end)

-- G8: receiver modifying output amounts (anti-snoop)
test("G8: receiver output-modification path absent (G8-BUG-8)", function()
  local has, _ = any_source_matches("payjoin_modify_output")
  expect_eq(has, false, "no payjoin_modify_output")
  bug("G8-BUG-8", "P1",
      "Receiver output-modification path absent. BIP-78 §Receiver allows " ..
      "(and recommends, to avoid amount-based fingerprinting) increasing " ..
      "the payment output by the contributed-input amount. lunarblock has " ..
      "no output-mutating helper that respects disableoutputsubstitution=0.")
end)

-- G9: receiver fee adjustment (using maxadditionalfeecontribution)
test("G9: receiver fee adjustment absent (G9-BUG-9)", function()
  local has, _ = any_source_matches("maxadditionalfeecontribution")
  expect_eq(has, false, "maxadditionalfeecontribution not parsed")
  bug("G9-BUG-9", "P0",
      "Receiver fee adjustment absent. BIP-78 §Receiver fee bumping: " ..
      "receiver may consume up to maxadditionalfeecontribution from the " ..
      "additionalfeeoutputindex output to cover the new size with their " ..
      "added inputs. lunarblock cannot read either parameter, so it cannot " ..
      "produce a valid PayJoin response even if everything else were wired.")
end)

-- =================================================================== --
-- G10-G15: Sender-side anti-snoop logic                                --
-- =================================================================== --
print("\n--- G10-G15: Sender-side anti-snoop checks ---")

-- G10: sender output-set anti-snoop (no new outputs added)
test("G10: sender output-set anti-snoop check absent (G10-BUG-10)", function()
  local has, _ = any_source_matches("payjoin_check_outputs")
  expect_eq(has, false, "no sender output-set verifier")
  bug("G10-BUG-10", "P0-SECURITY",
      "Sender output-set anti-snoop check absent. BIP-78 §Sender mandates " ..
      "that the sender verify the receiver did NOT introduce new outputs " ..
      "(only the payment + change may change in amount). Without this " ..
      "check the receiver can probe the sender's wallet by adding " ..
      "throwaway outputs and watching which proposals are signed. " ..
      "lunarblock has no PayJoin response validator at all.")
end)

-- G11: sender scriptSig-type homogeneity check
test("G11: sender scriptSig-type homogeneity check absent (G11-BUG-11)", function()
  local has, _ = any_source_matches("payjoin_check_scriptsig")
  expect_eq(has, false, "no scriptSig-type uniformity check")
  bug("G11-BUG-11", "P1",
      "Sender scriptSig-type homogeneity check absent. BIP-78 §Sender: " ..
      "receiver-added inputs MUST share the scriptSig type of the sender's " ..
      "inputs (else the resulting tx leaks PayJoin participation via " ..
      "mixed-input-type fingerprint). lunarblock has no such validator.")
end)

-- G12: sender must reject responses that added new sender-owned inputs
test("G12: sender no-new-inputs check absent (G12-BUG-12)", function()
  local has, _ = any_source_matches("payjoin_check_inputs")
  expect_eq(has, false, "no sender input-set verifier")
  bug("G12-BUG-12", "P0-SECURITY",
      "Sender no-new-inputs (of sender's own) check absent. BIP-78 §Sender " ..
      "mandates verifying the response only adds inputs the sender does NOT " ..
      "control (else the receiver can probe sender UTXOs by attempting to " ..
      "'add' addresses they suspect belong to the sender and observing " ..
      "which proposals get signed). lunarblock has no such validator.")
end)

-- G13: sender max-additional-fee check
test("G13: sender max-fee enforcement absent (G13-BUG-13)", function()
  local has, _ = any_source_matches("maxadditionalfee")
  expect_eq(has, false, "no max-fee enforcement on sender side")
  bug("G13-BUG-13", "P1",
      "Sender max-additional-fee enforcement absent. Sender announces the " ..
      "max fee it will absorb via maxadditionalfeecontribution; on response " ..
      "the sender must verify the receiver did not exceed it. lunarblock " ..
      "has no PayJoin sender flow, so no enforcement.")
end)

-- G14: disableoutputsubstitution honoring
test("G14: disableoutputsubstitution support absent (G14-BUG-14)", function()
  local has, _ = any_source_matches("disableoutputsubstitution")
  expect_eq(has, false, "disableoutputsubstitution not implemented")
  bug("G14-BUG-14", "P1",
      "disableoutputsubstitution parameter not supported. BIP-78 §Sender: " ..
      "when set, the receiver MUST NOT modify the payment-output amount. " ..
      "lunarblock has no parser for it nor any receiver-side respect.")
end)

-- G15: sender min-fee-rate enforcement
test("G15: sender minfeerate enforcement absent (G15-BUG-15)", function()
  -- 'minfeerate' is a generic Bitcoin term too (it appears in rpc.lua
  -- getblockstats around line 3319). The PayJoin meaning only exists
  -- inside a payjoin-tagged context, so we search PayJoin-locally.
  local has, _ = any_payjoin_context_matches("minfeerate")
  expect_eq(has, false, "minfeerate parameter not used in any PayJoin context")
  bug("G15-BUG-15", "P1",
      "Sender minfeerate enforcement absent. Sender may declare a minimum " ..
      "absolute fee-rate the response must meet; lunarblock has no parser " ..
      "and no enforcement. (Note: 'minfeerate' appears in rpc.lua " ..
      "getblockstats as block-stats output, unrelated to BIP-78.)")
end)

-- =================================================================== --
-- G16-G21: Wire format and error semantics                             --
-- =================================================================== --
print("\n--- G16-G21: Wire format and error semantics ---")

-- G16: URL query-parameter parser (additionalfeeoutputindex etc.)
test("G16: PayJoin query-parameter parser absent (G16-BUG-16)", function()
  -- rest.lua HAS a generic query parser (line 185), but no payjoin-specific
  -- handling.  Confirm both: parser exists, payjoin keys never appear.
  local rest_src = source_of("src/rest.lua")
  expect_true(rest_src:find("parse_query") ~= nil, "rest.lua has generic parse_query")
  expect_nil(rest_src:find("additionalfeeoutputindex"),
             "additionalfeeoutputindex never named in REST module")
  bug("G16-BUG-16", "P1",
      "PayJoin-specific query-parameter parser absent. src/rest.lua line 185 " ..
      "parses generic ?k=v query strings, but the five PayJoin keys (v, " ..
      "additionalfeeoutputindex, maxadditionalfeecontribution, " ..
      "disableoutputsubstitution, minfeerate) are never recognised by name " ..
      "and never validated for type / range.")
end)

-- G17: four BIP-78 error codes
test("G17: BIP-78 error code emission absent (G17-BUG-17)", function()
  -- "unavailable" is a generic English word that appears in unrelated
  -- comments / log strings (recovery log in main.lua, wallet-lock
  -- comment in wallet.lua, etc.). Restrict every code lookup to a
  -- PayJoin-tagged context so we don't false-positive on prose.
  local missing = {}
  for _, code in ipairs({"unavailable", "not%-enough%-money",
                         "version%-unsupported", "original%-psbt%-rejected"}) do
    local hit, _ = any_payjoin_context_matches(code)
    if not hit then table.insert(missing, code) end
  end
  expect_eq(#missing, 4, "all four BIP-78 error codes are missing in PayJoin context")
  bug("G17-BUG-17", "P0",
      "All four BIP-78 error codes (unavailable, not-enough-money, " ..
      "version-unsupported, original-psbt-rejected) absent. The protocol " ..
      "requires a stable error vocabulary so clients can branch correctly. " ..
      "lunarblock has no path that emits any of them. (Note: 'unavailable' " ..
      "appears in unrelated log strings and comments — not as a PayJoin " ..
      "error.)")
end)

-- G18: receiver-side proposal TTL / expiry
test("G18: receiver proposal TTL absent (G18-BUG-18)", function()
  local has, _ = any_source_matches("payjoin_ttl")
  expect_eq(has, false, "no proposal expiry tracking")
  bug("G18-BUG-18", "P1",
      "Receiver-side proposal TTL absent. payjoin.org reference recommends " ..
      "expiring open proposals after a short window (minutes) to limit " ..
      "double-receive probing. lunarblock has no PayJoin proposal store, " ..
      "so no TTL.")
end)

-- G19: receiver must reject re-submission of the same Original PSBT
test("G19: receiver double-receive guard absent (G19-BUG-19)", function()
  local has, _ = any_source_matches("payjoin_seen")
  expect_eq(has, false, "no seen-OriginalPSBT cache")
  bug("G19-BUG-19", "P0-SECURITY",
      "Receiver double-receive guard absent. If a sender can re-submit the " ..
      "same Original PSBT and receive different proposals, the receiver " ..
      "leaks UTXO information (sender learns which receiver UTXOs are " ..
      "available across attempts). BIP-78 §Receiver requires de-dup; " ..
      "lunarblock has no proposal store.")
end)

-- G20: receiver UTXO-probe / anti-fingerprinting (require sender to broadcast
-- the Original tx if the proposal is abandoned)
test("G20: receiver anti-UTXO-probe guard absent (G20-BUG-20)", function()
  local has, _ = any_source_matches("payjoin_probe")
  expect_eq(has, false, "no UTXO-probe guard")
  bug("G20-BUG-20", "P0-SECURITY",
      "Receiver anti-UTXO-probe guard absent. BIP-78 §Receiver explicitly " ..
      "warns that without rate-limiting / forced-broadcast, an attacker " ..
      "with many addresses can map the receiver's UTXO set in O(N) probes. " ..
      "Defence (per payjoin.org): require sender to broadcast Original " ..
      "first OR track per-IP attempt counts. lunarblock has neither.")
end)

-- G21: v=1 version header
test("G21: v=1 version header check absent (G21-BUG-21)", function()
  local has, _ = any_source_matches("payjoin.*v=1")
  expect_eq(has, false, "no v=1 handler")
  bug("G21-BUG-21", "P1",
      "v=1 PayJoin version header check absent. BIP-78: receiver MUST emit " ..
      "version-unsupported if the sender's v query parameter is not 1. " ..
      "lunarblock has neither the parser nor the error path.")
end)

-- =================================================================== --
-- G22-G25: Sender fallback / transport details                         --
-- =================================================================== --
print("\n--- G22-G25: Transport details ---")

-- G22: sender fallback (broadcast Original PSBT if PayJoin negotiation fails)
test("G22: sender fallback broadcast absent (G22-BUG-22)", function()
  local has, _ = any_source_matches("payjoin_fallback")
  expect_eq(has, false, "no PayJoin fallback")
  bug("G22-BUG-22", "P0",
      "Sender fallback-broadcast path absent. BIP-78 §Sender: if PayJoin " ..
      "negotiation fails for any reason, the sender MUST broadcast the " ..
      "Original PSBT (already signed) so payment still happens. " ..
      "lunarblock has no PayJoin sender flow at all.")
end)

-- G23: receiver Content-Type "text/plain; charset=utf-8"
test("G23: receiver Content-Type assertion absent (G23-BUG-23)", function()
  local has, _ = any_source_matches("text/plain.*charset=utf-8")
  expect_eq(has, false, "Content-Type not declared anywhere")
  bug("G23-BUG-23", "P2",
      "Receiver Content-Type 'text/plain; charset=utf-8' assertion absent. " ..
      "BIP-78 mandates this exact content type on response. lunarblock has " ..
      "no PayJoin response path, so the wire-level requirement cannot be " ..
      "met.")
end)

-- G24: HTTPS cert validation on the sender side (clearnet)
test("G24: HTTPS cert validation absent (G24-BUG-24)", function()
  local has, _ = any_source_matches("ssl_verify")
  expect_eq(has, false, "no TLS / luasec / openssl bindings")
  bug("G24-BUG-24", "P0-SECURITY",
      "HTTPS cert validation absent on sender side. BIP-78 §Sender clearnet: " ..
      "MUST use HTTPS with full cert validation (no skip, no pinning " ..
      "bypass). lunarblock has no TLS client (no luasec, no openssl FFI), " ..
      "so a clearnet sender flow could only be implemented in plaintext — " ..
      "a complete privacy/integrity failure.")
end)

-- G25: Tor / .onion v3 routing for sender
test("G25: Tor / .onion v3 sender routing absent (G25-BUG-25)", function()
  -- proxy.lua has SOCKS5 for P2P (W117 FIX-58) but no application-layer
  -- HTTP-over-Tor adapter.
  local proxy_src = source_of("src/proxy.lua")
  expect_true(proxy_src:find("socks5") ~= nil or proxy_src:find("SOCKS5") ~= nil,
              "SOCKS5 exists for P2P (W117)")
  expect_nil(proxy_src:find("payjoin"), "but not wired for HTTP/PayJoin")
  bug("G25-BUG-25", "P1",
      "Tor / .onion v3 PayJoin routing absent. src/proxy.lua wires SOCKS5 " ..
      "for the P2P path (W117 FIX-58) but exposes no HTTP-over-SOCKS adapter, " ..
      "so a PayJoin sender cannot reach a receiver hidden service. The " ..
      "anti-snoop guarantees of BIP-78 specifically lean on Tor for " ..
      "metadata privacy.")
end)

-- =================================================================== --
-- G26-G29: RPC + URI surface                                           --
-- =================================================================== --
print("\n--- G26-G29: RPC + URI surface ---")

-- G26: getpayjoinrequest RPC
test("G26: getpayjoinrequest RPC absent (G26-BUG-26)", function()
  local rpc_src = source_of("src/rpc.lua")
  expect_nil(rpc_src:find('self%.methods%["getpayjoinrequest"%]'),
             "no getpayjoinrequest RPC method")
  bug("G26-BUG-26", "P1",
      "getpayjoinrequest RPC absent. Wallet integrators expect an RPC that " ..
      "spawns a PayJoin receiver endpoint and returns the bitcoin: BIP-21 " ..
      "URI with pj=<endpoint>. Without it, GUI/CLI users cannot generate a " ..
      "payment request that opts into PayJoin.")
end)

-- G27: sendpayjoinrequest RPC
test("G27: sendpayjoinrequest RPC absent (G27-BUG-27)", function()
  local rpc_src = source_of("src/rpc.lua")
  expect_nil(rpc_src:find('self%.methods%["sendpayjoinrequest"%]'),
             "no sendpayjoinrequest RPC method")
  -- Confirm the wallet RPC set we DO have is unchanged (no surprise wiring).
  expect_true(rpc_src:find('self%.methods%["sendtoaddress"%]') ~= nil,
              "sendtoaddress still wired (acknowledge baseline)")
  bug("G27-BUG-27", "P1",
      "sendpayjoinrequest RPC absent. Sender flow needs an RPC accepting a " ..
      "BIP-21 URI with pj=, executing the PayJoin handshake, and returning " ..
      "the broadcast txid (with automatic fallback to the Original PSBT). " ..
      "lunarblock has sendtoaddress but no PayJoin-aware variant.")
end)

-- G28: BIP-21 pj= URI parameter — FIX-62 LANDED.
-- The BIP-21 parser lives in src/bip21.lua and recognises pj= as the
-- PayJoin endpoint indicator.  The audit assertion has been flipped:
-- we now confirm the parser exists AND that bip21.parse() returns a
-- table whose `pj` field captures the URL.  Note: this only closes the
-- URI-layer half of BIP-78 — the actual PayJoin client/server flow
-- (G1-G27, G30) remains MISSING; FIX-62 deliberately scopes to BIP-21.
test("G28: BIP-21 pj= URI parameter now supported (FIX-62)", function()
  local has21, _ = any_source_matches("bitcoin:")
  expect_true(has21, "BIP-21 'bitcoin:' URI parser source must be present")
  local ok, bip21 = pcall(require, "lunarblock.bip21")
  expect_true(ok and type(bip21) == "table",
              "lunarblock.bip21 must be require-able")
  expect_true(type(bip21.parse) == "function",
              "bip21.parse must exist")
  local uri = bip21.parse(
    "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" ..
    "?pj=https%3A%2F%2Fexample.com%2Fpayjoin", "mainnet")
  expect_true(type(uri) == "table" and not uri.err,
              "bip21.parse must accept pj= without error")
  expect_eq(uri.pj, "https://example.com/payjoin",
            "pj= URL must be captured (percent-decoded)")
end)

-- G29: BIP-21 pjos= URI parameter — FIX-62 LANDED.
test("G29: BIP-21 pjos= URI parameter now supported (FIX-62)", function()
  local ok, bip21 = pcall(require, "lunarblock.bip21")
  expect_true(ok and type(bip21) == "table", "lunarblock.bip21 require-able")
  local uri = bip21.parse(
    "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" ..
    "?pj=https%3A%2F%2Fx.example%2Fpj&pjos=0", "mainnet")
  expect_true(type(uri) == "table" and not uri.err,
              "bip21.parse must accept pjos= without error")
  expect_eq(uri.pjos, "0", "pjos=0 must be captured")
end)

-- =================================================================== --
-- G30: replay / same-pubkey double-spend safety                        --
-- =================================================================== --
print("\n--- G30: replay / same-pubkey double-spend ---")

-- G30: receiver replay protection (proposal MUST conflict-spend with Original
-- on at least one input, OR receiver tracks proposal lifetimes to avoid
-- accepting two proposals that double-spend each other's contributed inputs).
test("G30: receiver replay / double-spend protection absent (G30-BUG-30)", function()
  local has, _ = any_source_matches("payjoin_replay")
  expect_eq(has, false, "no replay guard")
  bug("G30-BUG-30", "P0-SECURITY",
      "Receiver replay / same-pubkey double-spend protection absent. " ..
      "Without a record of which UTXOs the receiver has already committed " ..
      "to a (possibly-still-broadcasting) PayJoin proposal, the receiver " ..
      "can be tricked into double-spending its own inputs across two " ..
      "concurrent senders. Mitigation per payjoin.org: lock contributed " ..
      "UTXOs while a proposal is open AND verify each new proposal " ..
      "conflict-spends with the corresponding Original PSBT. lunarblock " ..
      "has neither, because it has no proposal lifecycle at all.")
end)

-- =================================================================== --
-- Summary                                                              --
-- =================================================================== --
print(string.format("\n=== W119 SUMMARY: %d PASS / %d FAIL / %d SKIP ===", PASS, FAIL, SKIP))
print(string.format("Bugs documented: %d", #BUGS))
print("\n--- Bug List ---")
for _, b in ipairs(BUGS) do print("  " .. b) end

-- 28 of 30 gates are MISSING-confirmation tests (asserting absence).
-- G28+G29 were flipped by FIX-62 (BIP-21 URI parser landed) and now
-- assert PRESENCE. If a MISSING-gate test FAILS it means an
-- expectation about absence broke — which would be GOOD NEWS (someone
-- shipped more of PayJoin), but the surface change must be reviewed.
if FAIL > 0 then
  print(string.format(
    "\nUNEXPECTED FAILURES: %d -- review whether PayJoin landed " ..
    "or a search pattern needs updating.", FAIL))
  os.exit(1)
else
  print("\nAll 30 gates passed: 28 absence-confirmed, 2 presence-confirmed " ..
        "(G28+G29 closed by FIX-62 BIP-21). PayJoin remains MOSTLY MISSING; " ..
        "1 spec behind (BIP-78), not 2.")
  os.exit(0)
end
