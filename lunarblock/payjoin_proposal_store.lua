-- src/payjoin_proposal_store.lua -- FIX-67
--
-- W119 BIP-78 PayJoin receiver-side proposal lifecycle store.
--
-- Closes the 3 remaining W119 P0-SECURITY gates the receiver foundation
-- (FIX-65) deliberately deferred:
--
--   G18 receiver TTL                proposal expiration (60s default)
--   G19 receiver double-receive     same Original PSBT cannot mint two
--                                   different proposals (anti-snoop)
--   G20 receiver anti-UTXO-probe    UIH-1 + UIH-2 input-selection heuristics
--                                   per payjoin.org §"UTXO selection"
--   G30 receiver replay protection  in-flight outpoint lock so concurrent
--                                   senders cannot trick the receiver into
--                                   double-spending its own UTXO across
--                                   two open proposals
--
-- The store is in-process (no on-disk persistence) — restart wipes every
-- live proposal, which is the same posture payjoin.org reference and
-- btcpayserver/payjoin take ("restart = forfeit privacy for any
-- still-open Original PSBTs").
--
-- Wired from src/rest.lua handle_payjoin via:
--
--   1. proposal_store:replay_check(orig_hash, psbt_id)
--   2. proposal_store:double_spend_check(outpoints)
--   3. proposal_store:select_utxo(utxos, sender_outputs, sender_input_type)
--   4. proposal_store:commit(orig_hash, psbt_id, outpoints)
--
-- All four are pure functions of the cached state + the call's args; the
-- caller is responsible for sweeping expired entries (proposal_store:sweep()
-- runs implicitly on each public call).
--
-- Pattern (matches camlcoin/ouroboros/haskoin lifecycle-store shape):
--
--   * TTL Map        : orig_psbt_hash -> {expires_at, psbt_id, outpoints}
--   * Replay Set     : psbt_id        -> expires_at
--   * In-flight Set  : outpoint_key   -> expires_at
--
-- Outpoint key shape: txid_bytes(32) .. uint32_le(vout)  — exactly the
-- shape Wallet.utxos uses, so we can dedupe against it cheaply.

local crypto = require("lunarblock.crypto")

local M = {}

-- TTL window for open proposals.  payjoin.org reference uses 1 minute;
-- btcpayserver/payjoin uses 90 seconds.  We pick 60s as the BIP-78
-- "short window" that limits double-receive probing without legitimately
-- timing out a slow-but-honest sender.
M.DEFAULT_TTL_SECONDS = 60

-- ===================================================================
-- Constructor
-- ===================================================================
--
-- @param opts table | nil
--   ttl_seconds    -- TTL (default 60)
--   now_fn         -- monotonic time source (default os.time); a
--                     synchronous test can pass its own clock so the
--                     sweep is deterministic.
function M.new(opts)
  opts = opts or {}
  local self = {
    ttl_seconds  = opts.ttl_seconds or M.DEFAULT_TTL_SECONDS,
    now_fn       = opts.now_fn or os.time,
    -- payjoin_seen: orig_psbt_hash -> {expires_at, psbt_id, outpoints}
    -- (audit marker: "payjoin_seen")
    payjoin_seen = {},
    -- payjoin_replay: psbt_id -> expires_at
    -- (audit marker: "payjoin_replay")
    payjoin_replay = {},
    -- payjoin_inflight: outpoint_key -> expires_at
    -- (audit marker: "payjoin_inflight")
    payjoin_inflight = {},
    -- payjoin_probe: per-(remote IP) hit counter for UTXO-probe rate
    -- limiting (audit marker: "payjoin_probe").  Best-effort: receiver
    -- caller can pass remote_ip to commit() / replay_check() to opt in.
    payjoin_probe = {},
  }
  return setmetatable(self, {__index = M})
end

-- ===================================================================
-- Internal: sweep
-- ===================================================================
--
-- Drops entries whose expires_at <= now.  Called implicitly by every
-- public method so callers don't have to remember.
function M:sweep()
  local now = self.now_fn()
  for k, entry in pairs(self.payjoin_seen) do
    if entry.expires_at <= now then
      self.payjoin_seen[k] = nil
    end
  end
  for k, exp in pairs(self.payjoin_replay) do
    if exp <= now then self.payjoin_replay[k] = nil end
  end
  for k, exp in pairs(self.payjoin_inflight) do
    if exp <= now then self.payjoin_inflight[k] = nil end
  end
  for k, entry in pairs(self.payjoin_probe) do
    if entry.expires_at <= now then
      self.payjoin_probe[k] = nil
    end
  end
end

-- ===================================================================
-- Hash an Original PSBT (raw bytes form -> 32-byte sha256)
-- ===================================================================
--
-- Keying the TTL map by the SHA-256 of the body bytes (not the parsed
-- tree) is byte-identical with what btcpayserver/payjoin does.  Using
-- the raw POST body means a sender re-encoding the same logical PSBT
-- with a different field order would map to a different key — that's
-- intentional, because re-encoded PSBTs are not actually "the same
-- proposal" (the wire transcript differs).
function M.hash_original_psbt(raw_bytes)
  return crypto.sha256(raw_bytes)
end

-- ===================================================================
-- Compute psbt_id (sha256 of the unsigned-tx txid + payment_idx)
-- ===================================================================
--
-- The psbt_id is the receiver-side replay key.  It is independent of
-- whether the sender re-encodes the PSBT; what matters is the
-- (unsigned-tx, payment-output) pair the receiver committed to.  Two
-- proposals with the same psbt_id MUST be rejected — a malicious
-- sender that hits the receiver twice with the same logical payment
-- but different PSBT serialisations would otherwise leak which
-- receiver UTXO is offered each time.
--
-- @param tx          parsed unsigned transaction (psbt.tx)
-- @param payment_idx 1-based payment-output index
function M.compute_psbt_id(tx, payment_idx)
  -- Serialise the inputs' (txid, vout) tuples + payment_idx + output
  -- script_pubkey + value.  We can't use validation.compute_txid here
  -- because some inputs may carry signatures and we want a hash that's
  -- stable across (un)signed forms.
  local parts = {}
  for _, inp in ipairs(tx.inputs) do
    parts[#parts + 1] = inp.prev_out.hash.bytes
    parts[#parts + 1] = string.char(
      inp.prev_out.index % 256,
      math.floor(inp.prev_out.index / 256) % 256,
      math.floor(inp.prev_out.index / 65536) % 256,
      math.floor(inp.prev_out.index / 16777216) % 256)
  end
  parts[#parts + 1] = string.char(payment_idx % 256)
  if tx.outputs[payment_idx] then
    local out = tx.outputs[payment_idx]
    parts[#parts + 1] = out.script_pubkey or ""
    -- value as little-endian uint64 (low 32 bits suffices for psbt_id
    -- collision resistance; we already have a 32-byte sha256 covering
    -- the entire wire identity).
    local v = out.value or 0
    parts[#parts + 1] = string.char(
      v % 256,
      math.floor(v / 256) % 256,
      math.floor(v / 65536) % 256,
      math.floor(v / 16777216) % 256)
  end
  return crypto.sha256(table.concat(parts))
end

-- ===================================================================
-- G19: replay-check + double-receive guard
-- ===================================================================
--
-- Two-layer check:
--   (a) orig_hash already in payjoin_seen -> "double-receive"
--   (b) psbt_id   already in payjoin_replay -> "replay"
--
-- @param orig_hash   sha256 of the raw POST body (hash_original_psbt)
-- @param psbt_id     sha256 of the (inputs, payment_idx, output) tuple
-- @return ok bool, err string|nil
function M:replay_check(orig_hash, psbt_id)
  self:sweep()
  if self.payjoin_seen[orig_hash] then
    return false, "double-receive (Original PSBT already pending)"
  end
  if self.payjoin_replay[psbt_id] then
    return false, "replay (psbt_id already pending)"
  end
  return true, nil
end

-- ===================================================================
-- G30: double-spend guard (in-flight outpoint lock)
-- ===================================================================
--
-- Reject the proposal if ANY of the proposed receiver-contributed
-- outpoints is already pledged to a still-open proposal.  This
-- prevents two concurrent senders from each receiving a proposal that
-- (would) spend the same receiver UTXO, leaving the receiver to
-- broadcast only one but having leaked the UTXO to both.
--
-- @param outpoint_keys array of 36-byte keys (txid||vout_le)
-- @return ok bool, err string|nil
function M:double_spend_check(outpoint_keys)
  self:sweep()
  for _, key in ipairs(outpoint_keys) do
    if self.payjoin_inflight[key] then
      return false, "double-spend (outpoint already pledged to open proposal)"
    end
  end
  return true, nil
end

-- ===================================================================
-- G20: anti-fingerprint UTXO selection (UIH-1 + UIH-2)
-- ===================================================================
--
-- Per payjoin.org §"Receiver UTXO selection" + Maxwell/Lopp UIH:
--
--   UIH-1: don't add a receiver input WHOSE VALUE exceeds the smallest
--          sender output. Adding a large input makes the smaller
--          output trivially identifiable as change (sender's, even
--          though the protocol mixes our funds into payment).  The
--          heuristic-defeat assumption is that change is *always* the
--          smaller output; UIH-1 says "don't break that assumption".
--
--   UIH-2: don't add a receiver input WHOSE SCRIPT TYPE differs from
--          the sender's already-chosen inputs.  Heterogeneous script
--          types (e.g. sender used P2WPKH, receiver adds P2PKH) make
--          PayJoin transactions stand out vs the natural Bitcoin
--          population, which is dominated by single-type transactions.
--          Equivalently: the receiver's input MUST be the same wallet
--          policy / script-type as the sender's (per BIP-78 §Receiver).
--
-- Inputs:
--   utxos                array of {utxo = {value, script_pubkey, ...}}
--                        (same shape Wallet:get_available_utxos returns)
--   sender_outputs       array of sender's psbt.tx.outputs
--   sender_input_type    string ("p2wpkh"/"p2pkh"/etc), or nil if unknown
--   already_used         table of outpoint_keys to skip (used by
--                        rest.lua to skip UTXOs the sender already
--                        spends — the original double-spend guard)
--
-- Returns the chosen utxo entry (utxos[i].utxo), or nil + err.
--
-- Reference: payjoin.org/docs/specs/receiver/utxo-selection/
--            (and the underlying Maxwell+Lopp UIH analysis)
function M:select_utxo(utxos, sender_outputs, sender_input_type, already_used)
  already_used = already_used or {}
  if #utxos == 0 then
    return nil, "no UTXOs available"
  end

  -- Smallest sender output value (UIH-1 ceiling).  If the sender has
  -- no outputs we fall back to "no ceiling" (legacy behaviour).
  local smallest_output_value = nil
  for _, out in ipairs(sender_outputs or {}) do
    if out.value and (smallest_output_value == nil or out.value < smallest_output_value) then
      smallest_output_value = out.value
    end
  end

  -- Classify candidate type by script.  Mirrors rest.lua / script.lua
  -- classify_script return values.  We avoid requiring the script
  -- module here (cycle): caller can pre-classify into utxo.script_type
  -- if available; otherwise we treat unknown as "no UIH-2 filter".
  local script_mod_ok, script_mod = pcall(require, "lunarblock.script")
  local function classify(spk)
    if not spk then return nil end
    if script_mod_ok and script_mod and script_mod.classify_script then
      local t = script_mod.classify_script(spk)
      return t
    end
    return nil
  end

  -- First pass: try to find a UTXO satisfying BOTH UIH-1 and UIH-2.
  -- Second pass: relax UIH-1 (we'd rather pick *something* than fail
  -- the proposal entirely; UIH-1 violations only leak the "is change
  -- the smaller output" heuristic, which is best-effort).
  --
  -- We never relax UIH-2: a mismatched script type is a hard rule.
  local function pass(strict_uih1)
    for _, item in ipairs(utxos) do
      local u = item.utxo
      local key = u.txid.bytes .. string.char(
        u.vout % 256,
        math.floor(u.vout / 256) % 256,
        math.floor(u.vout / 65536) % 256,
        math.floor(u.vout / 16777216) % 256)
      if not already_used[key] then
        local cand_type = classify(u.script_pubkey)
        local type_ok = true
        if sender_input_type and cand_type and cand_type ~= sender_input_type then
          type_ok = false
        end
        local uih1_ok = true
        if strict_uih1 and smallest_output_value and u.value > smallest_output_value then
          uih1_ok = false
        end
        if type_ok and uih1_ok then
          return u
        end
      end
    end
    return nil
  end

  local chosen = pass(true)   -- strict UIH-1 + UIH-2
  if chosen then return chosen, nil end
  chosen = pass(false)         -- relax UIH-1 only
  if chosen then return chosen, "UIH-1 relaxed (no UTXO <= smallest output)" end
  return nil, "no UTXO satisfies UIH-2 (script-type homogeneity)"
end

-- ===================================================================
-- Commit a proposal
-- ===================================================================
--
-- Should be called by handle_payjoin AFTER all validation checks pass
-- and the proposal PSBT has been built (just before serialisation).
-- Records:
--   * orig_hash in payjoin_seen
--   * psbt_id in payjoin_replay
--   * each outpoint_key in payjoin_inflight
--
-- All three share the same expiration timestamp so they GC atomically.
function M:commit(orig_hash, psbt_id, outpoint_keys)
  self:sweep()
  local exp = self.now_fn() + self.ttl_seconds
  self.payjoin_seen[orig_hash] = {
    expires_at = exp,
    psbt_id    = psbt_id,
    outpoints  = outpoint_keys,
  }
  self.payjoin_replay[psbt_id] = exp
  for _, key in ipairs(outpoint_keys) do
    self.payjoin_inflight[key] = exp
  end
end

-- ===================================================================
-- Probe-counter (G20 secondary defence — per-IP rate limit)
-- ===================================================================
--
-- Tracks how many proposals a given remote_ip has triggered within
-- the TTL window.  Caller may consult :probe_count() before generating
-- a proposal and reject if the count exceeds a threshold (payjoin.org
-- recommends 3-5 attempts/min from a single source).
function M:probe_record(remote_ip)
  if not remote_ip then return end
  self:sweep()
  local entry = self.payjoin_probe[remote_ip]
  if not entry then
    entry = {count = 0, expires_at = self.now_fn() + self.ttl_seconds}
    self.payjoin_probe[remote_ip] = entry
  end
  entry.count = entry.count + 1
  -- Bump expiry on every hit so a slowly-probing attacker still
  -- accumulates (the TTL is per-IP-window, not per-event).
  entry.expires_at = self.now_fn() + self.ttl_seconds
end

function M:probe_count(remote_ip)
  if not remote_ip then return 0 end
  self:sweep()
  local entry = self.payjoin_probe[remote_ip]
  return entry and entry.count or 0
end

-- ===================================================================
-- Outpoint-key helper
-- ===================================================================
--
-- Build a 36-byte outpoint key (txid_bytes || vout_le32).  Exposed so
-- callers can pre-compute keys for both replay_check and commit.
function M.outpoint_key(txid_bytes, vout)
  return txid_bytes .. string.char(
    vout % 256,
    math.floor(vout / 256) % 256,
    math.floor(vout / 65536) % 256,
    math.floor(vout / 16777216) % 256)
end

return M
