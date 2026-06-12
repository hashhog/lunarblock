local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local validation = require("lunarblock.validation")
local consensus = require("lunarblock.consensus")
local script_mod = require("lunarblock.script")
local mining = require("lunarblock.mining")
local M = {}

--- Compute median-time-past for the current chain tip.
-- Reads the last 11 block headers via chain_state.storage and returns their
-- median timestamp.  Used for BIP-113 IsFinalTx and BIP-68 SequenceLocks at
-- mempool accept time.  Returns os.time() as a fallback when storage is absent.
-- Reference: Bitcoin Core CBlockIndex::GetMedianTimePast (chain.h).
local function get_tip_mtp(chain_state)
  local storage = chain_state and chain_state.storage
  local tip_hash = chain_state and chain_state.tip_hash
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
  if #timestamps == 0 then return os.time() end
  table.sort(timestamps)
  -- Bitcoin Core: pbegin[(pend-pbegin)/2] (0-indexed, integer division picks
  -- upper-middle for even n).  Lua 1-indexed: floor(n/2)+1.
  -- math.ceil(n/2) is wrong for even n (picks lower-middle).
  local n = #timestamps
  return timestamps[math.floor(n / 2) + 1]
end

-- Cluster mempool: union-find for tracking transaction clusters
local uf_parent = {}
local uf_rank = {}

local function uf_find(x)
  if x == nil then return nil end
  -- Path-compression walk.  If a parent entry was removed (uf_parent[x] == nil
  -- but x itself is non-nil) the node became an orphan root; re-anchor it.
  while uf_parent[x] ~= nil and uf_parent[x] ~= x do
    local grandparent = uf_parent[uf_parent[x]]
    if grandparent ~= nil then
      uf_parent[x] = grandparent  -- path compression
    end
    x = uf_parent[x]
  end
  -- Re-root an orphaned node so future calls are O(1).
  if uf_parent[x] == nil then
    uf_parent[x] = x
    uf_rank[x] = uf_rank[x] or 0
  end
  return x
end

local function uf_union(a, b)
  a, b = uf_find(a), uf_find(b)
  if a == b then return end
  if (uf_rank[a] or 0) < (uf_rank[b] or 0) then a, b = b, a end
  uf_parent[b] = a
  if (uf_rank[a] or 0) == (uf_rank[b] or 0) then uf_rank[a] = (uf_rank[a] or 0) + 1 end
end

-- Cluster count limit: max transactions in a single cluster.
-- Bitcoin Core policy/policy.h:72 DEFAULT_CLUSTER_LIMIT = 64.
local MAX_CLUSTER_COUNT = 64
-- Cluster vsize limit: max total virtual bytes in a single cluster.
-- Bitcoin Core policy/policy.h:74 DEFAULT_CLUSTER_SIZE_LIMIT_KVB = 101
-- → 101 * 1000 = 101,000 vbytes.  Core enforces in vbytes (weight/4).
local MAX_CLUSTER_VSIZE = 101000

local function get_cluster_size(root)
  local count = 0
  for txid, _ in pairs(uf_parent) do
    if uf_find(txid) == root then count = count + 1 end
  end
  return count
end

-- Sum the vsize of all in-mempool transactions in the cluster rooted at `root`.
-- `entries` must be the mempool's current entries table so that removed
-- transactions are not counted (union-find nodes linger until explicitly nil'd,
-- but entries are removed immediately).
local function get_cluster_vsize(root, entries)
  local vsize_total = 0
  for txid, _ in pairs(uf_parent) do
    if uf_find(txid) == root then
      local e = entries and entries[txid]
      if e then
        vsize_total = vsize_total + (e.vsize or 0)
      end
    end
  end
  return vsize_total
end

local function get_cluster_txids(root)
  local txids = {}
  for txid, _ in pairs(uf_parent) do
    if uf_find(txid) == root then txids[#txids + 1] = txid end
  end
  return txids
end

local function linearize_cluster(txids, entries)
  -- Greedy chunk algorithm: repeatedly extract highest-feerate prefix
  local remaining = {}
  for _, txid in ipairs(txids) do remaining[txid] = true end
  local result = {}
  while next(remaining) do
    local best_txid, best_rate = nil, -1
    for txid in pairs(remaining) do
      local e = entries[txid]
      if e then
        local rate = (e.fee or 0) / math.max(e.size or 1, 1)
        if rate > best_rate then best_rate = rate; best_txid = txid end
      end
    end
    if not best_txid then break end
    result[#result + 1] = best_txid
    remaining[best_txid] = nil
  end
  return result
end

local function interpolate_fee(diagram, size)
  for i = 2, #diagram do
    if diagram[i].size >= size then
      local prev = diagram[i-1]
      local curr = diagram[i]
      local frac = (size - prev.size) / math.max(curr.size - prev.size, 1)
      return prev.fee + frac * (curr.fee - prev.fee)
    end
  end
  return diagram[#diagram] and diagram[#diagram].fee or 0
end

local function build_feerate_diagram(linearization, entries)
  local diagram = {{size = 0, fee = 0}}
  local cum_size, cum_fee = 0, 0
  for _, txid in ipairs(linearization) do
    local e = entries[txid]
    if e then
      cum_size = cum_size + (e.size or 0)
      cum_fee = cum_fee + (e.fee or 0)
      diagram[#diagram + 1] = {size = cum_size, fee = cum_fee}
    end
  end
  return diagram
end

local function compare_diagrams(old_diag, new_diag)
  -- Returns true if new is strictly better (fee >= at every size, > at least once)
  local dominated = true
  local strictly_better = false
  local oi, ni = 1, 1
  while oi <= #old_diag or ni <= #new_diag do
    local os_val = old_diag[oi] and old_diag[oi].size or math.huge
    local ns = new_diag[ni] and new_diag[ni].size or math.huge
    local check_size = math.min(os_val, ns)
    if check_size == math.huge then break end
    -- Interpolate fees at check_size for both diagrams
    local old_fee = interpolate_fee(old_diag, check_size)
    local new_fee = interpolate_fee(new_diag, check_size)
    if new_fee < old_fee then dominated = false; break end
    if new_fee > old_fee then strictly_better = true end
    if os_val <= ns then oi = oi + 1 end
    if ns <= os_val then ni = ni + 1 end
  end
  return dominated and strictly_better
end

-- Export cluster mempool utilities for external use
M.uf_parent = uf_parent
M.uf_rank = uf_rank
M.uf_find = uf_find
M.uf_union = uf_union
-- Cluster limits (policy/policy.h:72-74, kernel/mempool_limits.h:20-22)
M.MAX_CLUSTER_COUNT = MAX_CLUSTER_COUNT
M.MAX_CLUSTER_VSIZE = MAX_CLUSTER_VSIZE
-- Keep legacy alias so external callers that read MAX_CLUSTER_SIZE still get
-- the transaction-COUNT limit (not 101 kvB).
M.MAX_CLUSTER_SIZE = MAX_CLUSTER_COUNT
M.get_cluster_size = get_cluster_size
M.get_cluster_vsize = get_cluster_vsize
M.get_cluster_txids = get_cluster_txids
M.linearize_cluster = linearize_cluster
M.build_feerate_diagram = build_feerate_diagram
M.compare_diagrams = compare_diagrams
M.interpolate_fee = interpolate_fee

--------------------------------------------------------------------------------
-- Mempool Policy Constants
--------------------------------------------------------------------------------

-- DEFAULT_MAX_MEMPOOL_SIZE_MB = 300, but Core uses metric MB (1,000,000 bytes),
-- not binary MiB (1,048,576 bytes).  Reference: kernel/mempool_options.h:19.
M.DEFAULT_MAX_MEMPOOL_SIZE = 300 * 1000 * 1000  -- 300 MB (metric, not MiB)
-- DEFAULT_MIN_RELAY_TX_FEE = 100 sat/kvB (Bitcoin Core policy/policy.h:70).
-- This is the absolute relay floor enforced at the admission gate (see
-- Mempool:add at "fee rate too low" below).  Core lowered the historical
-- 1000 sat/kvB default to 100 sat/kvB; lunarblock now matches.  Every fee
-- DISPLAY (getmempoolinfo/getnetworkinfo/...) reads this same constant via
-- self.min_relay_fee so the displayed minrelaytxfee can never diverge from
-- the value the node actually enforces.
M.DEFAULT_MIN_RELAY_FEE = 100     -- 100 sat/kvB (policy/policy.h:70)
M.DEFAULT_MAX_TX_FEE = 1000000    -- 0.01 BTC max fee (policy, not consensus)
-- DEFAULT_BYTES_PER_SIGOP: each sigop "costs" this many virtual bytes.
-- When a tx has many sigops, its effective vsize is raised to
--   ceil(max(weight, sigop_cost * DEFAULT_BYTES_PER_SIGOP) / 4)
-- so that sigop-heavy txs cannot pay a too-low fee rate.
-- Reference: bitcoin-core/src/policy/policy.h:50, policy.cpp:390-398.
M.DEFAULT_BYTES_PER_SIGOP = 20
-- Ancestor/descendant limits (policy/policy.h:76-78, kernel/mempool_limits.h:24-26).
-- In Bitcoin Core 28+ (cluster mempool) these are deprecated for policy
-- enforcement and replaced by cluster limits, but are retained here for
-- belt-and-suspenders relay protection and wallet coin-selection.
M.MAX_ANCESTORS = 25              -- DEFAULT_ANCESTOR_LIMIT (policy/policy.h:76)
M.MAX_DESCENDANTS = 25            -- DEFAULT_DESCENDANT_LIMIT (policy/policy.h:78)
M.MAX_ANCESTOR_SIZE = 101000      -- 101 kvB in vbytes (kernel/mempool_limits.h:22)
M.MAX_DESCENDANT_SIZE = 101000    -- 101 kvB in vbytes (kernel/mempool_limits.h:22)
-- Extra descendant exception: one single-ancestor child tx ≤ this size may
-- exceed the descendant count limit by 1 (policy/policy.h:90).
M.EXTRA_DESCENDANT_TX_SIZE_LIMIT = 10000  -- EXTRA_DESCENDANT_TX_SIZE_LIMIT
M.REPLACEMENT_MIN_FEE_BUMP = 1000 -- Minimum fee increase for RBF (sat/KB)

-- IsStandardTx weight cap (Bitcoin Core policy/policy.h:38).
-- Transactions whose weight exceeds this are non-standard and must not
-- be relayed.  Block consensus still allows them (MAX_BLOCK_WEIGHT =
-- 4_000_000), but a node treats them as non-standard at relay time.
M.MAX_STANDARD_TX_WEIGHT = 400000

-- Maximum sigop cost for a standard transaction (Bitcoin Core policy/policy.h:44).
-- = MAX_BLOCK_SIGOPS_COST / 5 = 80000 / 5 = 16000.
-- Transactions whose total sigop cost (legacy*4 + P2SH*4 + witness*1) exceeds
-- this value are rejected at relay with "bad-txns-too-many-sigops".
-- Reference: bitcoin-core/src/validation.cpp:941-943.
M.MAX_STANDARD_TX_SIGOPS_COST = 16000

-- CVE-2017-12842 minimum non-witness size (Bitcoin Core policy/policy.h:40).
-- Transactions whose non-witness serialization is < 65 bytes can be used
-- to construct inner-merkle-node collisions in SPV proofs.  Core rejects
-- them at relay (validation.cpp:812-814, PreChecks).
M.MIN_STANDARD_TX_NONWITNESS_SIZE = 65

-- IsStandardTx version range (Bitcoin Core policy/policy.h TX_MIN/MAX_STANDARD_VERSION).
-- Versions 1-3 are standard; 0 and >3 are rejected at relay.
M.TX_MIN_STANDARD_VERSION = 1
M.TX_MAX_STANDARD_VERSION = 3

-- Maximum scriptSig size for a standard input (Bitcoin Core policy/policy.h:62).
M.MAX_STANDARD_SCRIPTSIG_SIZE = 1650

-- W96: permit_bare_multisig policy flag (Core policy/policy.cpp:152-154
-- + kernel/mempool_options.h DEFAULT_PERMIT_BAREMULTISIG).
-- Core flipped this default from true → false in v28 (commit 8ee7773d).
-- When false, IsStandardTx rejects bare-multisig outputs with reason
-- "bare-multisig" even if 1 <= m <= n <= 3.
M.PERMIT_BARE_MULTISIG = false

-- W96: legacy (non-witness) sigops cap per transaction (BIP-54 +
-- Core policy.h MAX_TX_LEGACY_SIGOPS).  Enforced by ValidateInputsStandardness
-- via CheckSigopsBIP54 at relay time.  Reference:
-- bitcoin-core/src/policy/policy.cpp:170-194 + policy.h MAX_TX_LEGACY_SIGOPS=2500.
M.MAX_TX_LEGACY_SIGOPS = 2500

-- W96: P2SH redeemScript sigops cap (Core policy.h MAX_P2SH_SIGOPS = 15).
-- Enforced by ValidateInputsStandardness on TxoutType::SCRIPTHASH inputs
-- at relay time.  policy.cpp:255-257.
M.MAX_P2SH_SIGOPS = 15

-- Dust relay fee rate used for GetDustThreshold (Core policy/policy.h:68).
-- Units: satoshis per kilobyte.  Default: 3000 sat/kvB.
M.DUST_RELAY_FEE_RATE = 3000

-- DEFAULT_BLOCK_MIN_TX_FEE = 1 sat/kvB (Bitcoin Core policy/policy.h:36).
-- This is the BLOCK-assembly minimum feerate (getmininginfo.blockmintxfee),
-- a SEPARATE policy knob from the relay floor (DEFAULT_MIN_RELAY_FEE). It must
-- NOT be coupled to the relay floor: blockmintxfee renders as 0.00000001 BTC/kvB
-- while the relay floor renders as 0.00000100 BTC/kvB.
M.DEFAULT_BLOCK_MIN_TX_FEE = 1

-- Maximum datacarrier (OP_RETURN) script size in bytes (policy/policy.h:84).
-- Default = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR = 100000 bytes.
M.MAX_OP_RETURN_RELAY = 100000

-- BIP125 RBF Constants
M.MAX_BIP125_RBF_SEQUENCE = 0xFFFFFFFD  -- Sequence number signaling RBF
M.MAX_REPLACEMENT_CANDIDATES = 100       -- Max transactions that can be evicted by RBF
-- DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB (policy/policy.h:48).
-- Used in RBF Rule #4 and as the TrimToSize bump increment.
-- Previously wrong: 1000 (10× too high).  Core is 100 sat/kvB.
M.INCREMENTAL_RELAY_FEE = 100            -- 100 sat/kvB (policy/policy.h:48)

-- FIX-68 (W120 BUG-9): full-RBF default.  Bitcoin Core v28+ defaults
-- DEFAULT_MEMPOOL_FULL_RBF = true (src/policy/rbf.h since the cluster-mempool
-- branch removed Rule 1 / SignalsOptInRBF from ReplacementChecks) and
-- src/rpc/mempool.cpp:1058 hardcodes the JSON field to true.  The W120 audit
-- found lunarblock advertised fullrbf=true while still enforcing Rule 1 —
-- this constant exposes the toggle so accept_transaction can skip Rule 1
-- when fullrbf is enabled, and getmempoolinfo reads the actual setting.
-- Operator can flip to false via --mempool-fullrbf=0 / mempool config
-- `fullrbf = false` for legacy strict-opt-in policy.
M.DEFAULT_MEMPOOL_FULL_RBF = true

-- Rolling minimum fee half-life in seconds (txmempool.h:212).
-- The rolling minimum fee decays by half every ROLLING_FEE_HALFLIFE seconds.
-- When the pool is < 1/4 full, halflife is divided by 4 (faster decay).
-- When the pool is < 1/2 full, halflife is divided by 2.
-- Reference: Bitcoin Core txmempool.h:212 ROLLING_FEE_HALFLIFE = 60*60*12.
M.ROLLING_FEE_HALFLIFE = 43200           -- 12 hours in seconds (txmempool.h:212)

-- Mempool expiry: transactions older than this many seconds are removed.
-- Reference: kernel/mempool_options.h:23 DEFAULT_MEMPOOL_EXPIRY_HOURS = 336.
M.DEFAULT_MEMPOOL_EXPIRY = 336 * 3600    -- 336 hours = 14 days in seconds

-- Package Relay Constants (BIP 331)
M.MAX_PACKAGE_COUNT = 25                 -- Max transactions in a package
M.MAX_PACKAGE_WEIGHT = 404000            -- Max total weight (101KB vsize)
M.MAX_PACKAGE_VSIZE = 101000             -- Max total vsize (weight / 4)

-- Pay-to-Anchor (P2A) Constants
M.ANCHOR_AMOUNT = 0                      -- P2A outputs must have zero value

-- BIP-431 TRUC (Topologically Restricted Until Confirmation) v3 Policy
-- Reference: bitcoin-core/src/policy/truc_policy.h
-- A transaction with version=3 is treated as TRUC.
M.TRUC_VERSION = 3
-- TRUC allows at most 1 unconfirmed parent: ancestor set size ≤ 2.
M.TRUC_ANCESTOR_LIMIT = 2      -- Core truc_policy.h:27
-- TRUC allows at most 1 child: descendant set size ≤ 2.
M.TRUC_DESCENDANT_LIMIT = 2    -- Core truc_policy.h:25
-- Maximum sigop-adjusted vsize for any TRUC transaction.
M.TRUC_MAX_VSIZE = 10000       -- Core truc_policy.h:30
-- Maximum sigop-adjusted vsize for a TRUC child (has unconfirmed parent).
M.TRUC_CHILD_MAX_VSIZE = 1000  -- Core truc_policy.h:33

-- IsWitnessStandard limits (Bitcoin Core policy/policy.h).
-- P2WSH redeem script size limit (Core policy/policy.h:56).
M.MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600
-- P2WSH stack item count limit, excluding the redeem script itself (policy.h:58).
M.MAX_STANDARD_P2WSH_STACK_ITEMS = 100
-- P2WSH stack item size limit per element (policy.h:60).
M.MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80
-- Tapscript (leaf version 0xc0) stack item size limit (policy.h:62).
M.MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80
-- Annex tag: witness stack element starting with 0x50 is an annex (BIP 341).
M.ANNEX_TAG = 0x50
-- Taproot leaf version mask (BIP 341).
M.TAPROOT_LEAF_MASK = 0xfe
-- Tapscript leaf version (BIP 342).
M.TAPROOT_LEAF_TAPSCRIPT = 0xc0

--------------------------------------------------------------------------------
-- BIP-431 TRUC (v3) Policy — SingleTRUCChecks
-- Reference: bitcoin-core/src/policy/truc_policy.cpp:171-261
--------------------------------------------------------------------------------

--- Check BIP-431 TRUC policy for a single transaction entering the mempool.
--
-- Must be called for every transaction (TRUC and non-TRUC alike).
-- Enforces the following 6 gates:
--   Gate 1: Non-TRUC tx must not spend a TRUC (v=3) unconfirmed parent.
--            Core truc_policy.cpp:180-184.
--   Gate 2: TRUC tx must not spend a non-TRUC unconfirmed parent.
--            Core truc_policy.cpp:185-190.
--   Gate 3: TRUC tx sigop-adjusted vsize must be ≤ TRUC_MAX_VSIZE (10000).
--            Core truc_policy.cpp:200-204.
--   Gate 4: TRUC tx ancestor count (incl. self) must be ≤ TRUC_ANCESTOR_LIMIT (2).
--            Core truc_policy.cpp:207-211.
--   Gate 5: If TRUC tx has an unconfirmed parent, its vsize must be
--            ≤ TRUC_CHILD_MAX_VSIZE (1000).
--            Core truc_policy.cpp:223-227.
--   Gate 6: TRUC parent's descendant count (incl. new child) must be
--            ≤ TRUC_DESCENDANT_LIMIT (2). Returns sibling txid_hex when
--            sibling eviction is applicable (parent has exactly 1 existing
--            child with ancestor_count=1), otherwise nil.
--            Core truc_policy.cpp:229-258.
--
-- @param entries    table: mempool entries (txid_hex -> entry)
-- @param tx         table: the transaction being accepted
-- @param direct_parents table: txid_hex -> entry of in-mempool direct parents
-- @param vsize      number: sigop-adjusted virtual size of tx
-- @param conflicts  table: txid_hex -> true, set of direct RBF conflicts
--
-- @return ok, err_string, sibling_txid_hex
--   ok=true means all checks passed (sibling_txid_hex is nil).
--   ok=false, err set, sibling_txid_hex set → sibling eviction may be tried.
--   ok=false, err set, sibling_txid_hex nil → hard reject.
function M.single_truc_checks(entries, tx, direct_parents, vsize, conflicts)
  conflicts = conflicts or {}

  -- Gates 1+2: TRUC/non-TRUC inheritance check (applies to all txs).
  -- Core truc_policy.cpp:178-191.
  for parent_hex, parent_entry in pairs(direct_parents) do
    local parent_ver = parent_entry.tx.version
    if tx.version ~= M.TRUC_VERSION and parent_ver == M.TRUC_VERSION then
      -- Gate 1: non-TRUC spending TRUC parent.
      return false,
        string.format("non-version=3 tx cannot spend from version=3 tx %s",
          parent_hex:sub(1, 16)),
        nil
    elseif tx.version == M.TRUC_VERSION and parent_ver ~= M.TRUC_VERSION then
      -- Gate 2: TRUC spending non-TRUC parent.
      return false,
        string.format("version=3 tx cannot spend from non-version=3 tx %s",
          parent_hex:sub(1, 16)),
        nil
    end
  end

  -- Remaining gates only apply to TRUC transactions.
  -- Core truc_policy.cpp:198.
  if tx.version ~= M.TRUC_VERSION then
    return true, nil, nil
  end

  -- Gate 3: TRUC tx vsize limit.
  -- Core truc_policy.cpp:200-204.
  if vsize > M.TRUC_MAX_VSIZE then
    return false,
      string.format("version=3 tx is too big: %d > %d virtual bytes",
        vsize, M.TRUC_MAX_VSIZE),
      nil
  end

  -- Count direct parents (= unconfirmed ancestors at depth 1).
  local parent_count = 0
  local first_parent_hex = nil
  local first_parent_entry = nil
  for parent_hex, parent_entry in pairs(direct_parents) do
    parent_count = parent_count + 1
    first_parent_hex = parent_hex
    first_parent_entry = parent_entry
  end

  -- Gate 4: TRUC ancestor count (self + all in-mempool ancestors) ≤ 2.
  -- With TRUC_ANCESTOR_LIMIT=2, at most 1 unconfirmed parent is allowed.
  -- Core truc_policy.cpp:207-211 (mempool_parents.size() + 1 > TRUC_ANCESTOR_LIMIT).
  if parent_count + 1 > M.TRUC_ANCESTOR_LIMIT then
    return false,
      "tx would have too many ancestors (version=3 allows at most 1 unconfirmed parent)",
      nil
  end

  -- Additionally, if the parent itself has ancestors, the total chain exceeds 2.
  -- Core truc_policy.cpp:214-220: GetAncestorCount(mempool_parents[0]) + 1 > limit.
  if first_parent_entry then
    -- ancestor_count on the entry excludes self (set in accept_transaction step 8).
    -- ancestor_count + 1 (the parent itself) + 1 (ptx) > TRUC_ANCESTOR_LIMIT.
    local parent_anc_depth = first_parent_entry.ancestor_count + 1  -- parent incl. itself
    if parent_anc_depth + 1 > M.TRUC_ANCESTOR_LIMIT then
      return false,
        "tx would have too many ancestors (version=3 parent is not a top-level tx)",
        nil
    end
  end

  -- Remaining gates only apply when the tx has an unconfirmed parent.
  if parent_count == 0 then
    return true, nil, nil
  end

  -- Gate 5: TRUC child vsize limit (tx has unconfirmed TRUC parent).
  -- Core truc_policy.cpp:223-227.
  if vsize > M.TRUC_CHILD_MAX_VSIZE then
    return false,
      string.format("version=3 child tx is too big: %d > %d virtual bytes",
        vsize, M.TRUC_CHILD_MAX_VSIZE),
      nil
  end

  -- Gate 6: TRUC parent's descendant count must not exceed TRUC_DESCENDANT_LIMIT.
  -- The parent currently has `descendant_count` descendants (excluding self).
  -- Adding ptx would make it descendant_count+1 descendants (excl. self), or
  -- descendant_count+2 including self → compare parent.descendant_count+1+1 > limit.
  -- Core truc_policy.cpp:243: pool.GetDescendantCount(parent_entry) + 1 > TRUC_DESCENDANT_LIMIT.
  -- GetDescendantCount includes the entry itself, so it equals descendant_count+1.
  -- Core truc_policy.cpp:243: (descendant_count+1) + 1 > 2  → descendant_count > 0.
  local parent_desc_count_with_self = first_parent_entry.descendant_count + 1
  if parent_desc_count_with_self + 1 > M.TRUC_DESCENDANT_LIMIT then
    -- Sibling eviction: applicable when parent has exactly 1 existing child
    -- (GetDescendantCount == 2, i.e. descendant_count_with_self == 2) AND that
    -- child itself has no children (GetAncestorCount(**begin) == 2, meaning the
    -- child has exactly 1 ancestor = the parent).
    -- Core truc_policy.cpp:249-257.
    local sibling_txid_hex = nil
    if parent_desc_count_with_self == 2 then
      -- Exactly one existing child. Find it.
      for desc_hex in pairs(first_parent_entry.descendants) do
        local desc_entry = entries[desc_hex]
        if desc_entry then
          -- Check the sibling is not itself being replaced (direct conflict).
          local will_be_replaced = conflicts[desc_hex]
          -- Core checks GetAncestorCount == 2 (parent+self, no further ancestors).
          -- Our ancestor_count excludes self, so ancestor_count+1 == 2 → ancestor_count == 1.
          if not will_be_replaced and desc_entry.ancestor_count == 1 then
            sibling_txid_hex = desc_hex
          end
        end
      end
    end

    local err = string.format(
      "version=3 tx %s would exceed descendant count limit",
      first_parent_hex:sub(1, 16))
    return false, err, sibling_txid_hex
  end

  return true, nil, nil
end

--------------------------------------------------------------------------------
-- IsWitnessStandard (Bitcoin Core policy/policy.cpp:265-352)
--------------------------------------------------------------------------------

--- Check whether the witness data for each input of a transaction is standard.
-- This enforces the 6 policy gates from Bitcoin Core IsWitnessStandard():
--   Gate 1: P2A input with non-empty witness → reject (bad-witness-nonstandard).
--   Gate 2: P2SH-wrapped witness — extract redeemScript; fail if parse fails or
--            stack is empty (mirrors EvalScript with SCRIPT_VERIFY_NONE).
--   Gate 3: non-witness prevScript paired with non-empty witness → reject.
--   Gate 4: P2WSH (v0, 32-byte program) limits:
--            redeem script ≤ 3600 B; stack items ≤ 100; each item ≤ 80 B.
--   Gate 5: P2TR (v1, 32-byte program, non-P2SH-wrapped):
--            annex (0x50 prefix) → reject; tapscript leaf (0xc0) → each element ≤ 80 B;
--            empty stack → reject.
--   Gate 6: coinbase is exempt (checked by caller — coinbase is skipped before this).
--
-- @param tx      transaction: the transaction to check.
-- @param utxos   table[i] = {script_pubkey=string, ...}: resolved prevouts keyed 1..#tx.inputs.
--                A nil entry means the input was missing — caller must not call this function
--                when inputs are missing (we skip nil entries for safety).
-- @return boolean, string: true if standard; false + reason string if not.
-- Reference: Bitcoin Core policy/policy.cpp:265-352.

--- W96: ValidateInputsStandardness — relay-time input-standardness gate.
--
-- Mirrors Bitcoin Core's `ValidateInputsStandardness` (policy/policy.cpp:214-263).
-- For each non-witness input, classifies the prev scriptPubKey and rejects:
--   • Unknown / non-standard scriptPubKey ("bad-txns-nonstandard-inputs").
--   • Unknown segwit version (WITNESS_UNKNOWN) — relay-time gate to keep
--     forward-compat segwit versions reserved.
--   • P2SH redeem-script sigop count > MAX_P2SH_SIGOPS (15).
--
-- Also runs CheckSigopsBIP54 (policy.cpp:170-194) to cap total non-witness
-- sigops at MAX_TX_LEGACY_SIGOPS (2500) — this is BIP-54 standardness, not
-- consensus.
--
-- Coinbase is exempt — caller must not call this for coinbase.
--
-- @param tx     transaction: the transaction
-- @param utxos  table[i] = resolved {script_pubkey, ...} for each input 1..N
-- @return ok, reason
function M.validate_inputs_standardness(tx, utxos)
  -- Gate A (BIP-54): cap legacy non-witness sigops per tx.
  -- Core CheckSigopsBIP54 (policy.cpp:170-194).  Counts scriptSig sigops
  -- (fAccurate=true) + prev scriptPubKey sigops (which counts both bare
  -- and P2SH-redeem sigops via GetSigOpCount(scriptSig)).
  do
    local sigops = 0
    for i, inp in ipairs(tx.inputs) do
      local utxo = utxos[i]
      if utxo then
        local ss = inp.script_sig or ""
        local prev = utxo.script_pubkey or ""
        -- scriptSig accurate sigop count (fAccurate=true).
        sigops = sigops + (validation.count_script_sigops(ss, true) or 0)
        -- prev scriptPubKey: bare CHECKSIG sigops + P2SH-redeem sigops.
        sigops = sigops + (validation.count_script_sigops(prev, false) or 0)
        if script_mod.classify_script(prev) == "p2sh" then
          local redeem = validation.extract_p2sh_redeem_script(ss)
          if redeem then
            sigops = sigops + (validation.count_script_sigops(redeem, true) or 0)
          end
        end
        if sigops > M.MAX_TX_LEGACY_SIGOPS then
          return false,
            "bad-txns-nonstandard-inputs: non-witness sigops exceed bip54 limit"
        end
      end
    end
  end

  -- Gate B: per-input prev scriptPubKey type + P2SH redeem-sigops cap.
  for i, inp in ipairs(tx.inputs) do
    local utxo = utxos[i]
    if utxo then
      local prev = utxo.script_pubkey or ""
      local script_type = script_mod.classify_script(prev)
      if script_type == "nonstandard" then
        return false,
          string.format("bad-txns-nonstandard-inputs: input %d script unknown", i - 1)
      elseif script_type == "witness_unknown" then
        return false,
          string.format("bad-txns-nonstandard-inputs: input %d witness program is undefined", i - 1)
      elseif script_type == "p2sh" then
        local ss = inp.script_sig or ""
        local redeem = validation.extract_p2sh_redeem_script(ss)
        if not redeem or #redeem == 0 then
          -- empty scriptSig → either malformed or missing redeem; mirror Core
          -- distinction by checking whether scriptSig is push-only.
          if #ss == 0 or not script_mod.is_push_only(ss) then
            return false, string.format(
              "bad-txns-nonstandard-inputs: p2sh scriptsig malformed (input %d)", i - 1)
          end
          return false, string.format(
            "bad-txns-nonstandard-inputs: input %d P2SH redeemscript missing", i - 1)
        end
        local sigop_count = validation.count_script_sigops(redeem, true) or 0
        if sigop_count > M.MAX_P2SH_SIGOPS then
          return false, string.format(
            "bad-txns-nonstandard-inputs: p2sh redeemscript sigops exceed limit (input %d: %d > %d)",
            i - 1, sigop_count, M.MAX_P2SH_SIGOPS)
        end
      end
    end
  end

  return true, nil
end

function M.is_witness_standard(tx, utxos)
  for i, inp in ipairs(tx.inputs) do
    -- Skip inputs with no witness data (Core: "We don't care if witness for
    -- this input is empty, since it must not be bloated.")
    local witness = inp.witness  -- array of byte-strings, or nil
    if witness and #witness > 0 then
      local utxo = utxos[i]
      if not utxo then
        -- Missing UTXO: cannot evaluate. Treat as non-standard for safety.
        return false, "bad-witness-nonstandard"
      end

      local prev_script = utxo.script_pubkey
      local script_type = script_mod.classify_script(prev_script)

      -- Gate 1: P2A input with any witness → reject (witness stuffing).
      -- Reference: Core policy.cpp:283-285.
      if script_type == "p2a" then
        return false, "bad-witness-nonstandard"
      end

      local is_p2sh = (script_type == "p2sh")
      if is_p2sh then
        -- Gate 2: P2SH-wrapped witness path.
        -- Extract the redeemScript from the scriptSig push stack.
        -- Core does EvalScript(stack, scriptSig, SCRIPT_VERIFY_NONE, ...).
        -- We replicate the push-execution: parse the scriptSig as push-only
        -- and collect the pushed data items onto a stack, then take the top.
        -- Reference: Core policy.cpp:288-298.
        local script_sig = inp.script_sig or ""
        local stack = {}
        local ok_parse, ops = pcall(script_mod.parse_script, script_sig)
        if not ok_parse then
          return false, "bad-witness-nonstandard"
        end
        for _, op in ipairs(ops) do
          if op.data then
            -- push opcode: push data onto stack
            stack[#stack + 1] = op.data
          elseif op.opcode == 0x00 then
            -- OP_0: push empty byte vector
            stack[#stack + 1] = ""
          elseif op.opcode >= 0x51 and op.opcode <= 0x60 then
            -- OP_1..OP_16: push minimal encoding of 1..16
            local n = op.opcode - 0x50
            stack[#stack + 1] = string.char(n)
          elseif op.opcode == 0x4f then
            -- OP_1NEGATE: push minimal encoding of -1
            stack[#stack + 1] = "\x81"
          else
            -- Non-push opcode: EvalScript with SCRIPT_VERIFY_NONE would
            -- execute it, but for our purposes (extracting the redeemScript)
            -- we treat non-pushes as a failure (Core's EvalScript would
            -- not fail on NOPs etc., but Core also checks IsPushOnly later;
            -- the key invariant is: if EvalScript fails → return false).
            return false, "bad-witness-nonstandard"
          end
        end
        if #stack == 0 then
          return false, "bad-witness-nonstandard"
        end
        -- The redeemScript is the top stack element.
        prev_script = stack[#stack]
      end

      -- Gate 3: non-witness prevScript with non-empty witness → reject.
      -- Reference: Core policy.cpp:304-306 ("Non-witness program must not be
      -- associated with any witness").
      local wit_version, wit_program = script_mod.is_witness_program(prev_script)
      if not wit_version then
        return false, "bad-witness-nonstandard"
      end

      -- Gate 4: P2WSH (v0, 32-byte program) limits.
      -- Reference: Core policy.cpp:308-319.
      if wit_version == 0 and #wit_program == 32 then
        -- The last witness stack element is the serialized witness script.
        local ws = witness[#witness]
        if #ws > M.MAX_STANDARD_P2WSH_SCRIPT_SIZE then
          return false, "bad-witness-nonstandard"
        end
        local n_stack = #witness - 1  -- stack items excluding the script
        if n_stack > M.MAX_STANDARD_P2WSH_STACK_ITEMS then
          return false, "bad-witness-nonstandard"
        end
        for j = 1, n_stack do
          if #witness[j] > M.MAX_STANDARD_P2WSH_STACK_ITEM_SIZE then
            return false, "bad-witness-nonstandard"
          end
        end
      end

      -- Gate 5: P2TR (v1, 32-byte program, NOT P2SH-wrapped).
      -- Reference: Core policy.cpp:321-349.
      if wit_version == 1 and #wit_program == 32 and not is_p2sh then
        local stack = witness  -- array 1..N

        -- Annex detection: if ≥2 elements and last element starts with 0x50.
        if #stack >= 2 and #stack[#stack] >= 1
           and stack[#stack]:byte(1) == M.ANNEX_TAG then
          -- Annexes are nonstandard (BIP 341; no semantics defined yet).
          return false, "bad-witness-nonstandard"
        end

        if #stack >= 2 then
          -- Script-path spend.
          -- Peel the control block (last element of stack after removing annex).
          local control_block = stack[#stack]
          -- stack without last element for item-size check:
          local n_items = #stack - 2  -- items before script and control block
          if #control_block == 0 then
            return false, "bad-witness-nonstandard"
          end
          -- Check leaf version: (control_block[0] & TAPROOT_LEAF_MASK).
          if bit.band(control_block:byte(1), M.TAPROOT_LEAF_MASK)
             == M.TAPROOT_LEAF_TAPSCRIPT then
            -- Tapscript: every remaining stack element must be ≤ 80 bytes.
            for j = 1, n_items do
              if #stack[j] > M.MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE then
                return false, "bad-witness-nonstandard"
              end
            end
          end
        elseif #stack == 1 then
          -- Key-path spend: no policy limits beyond annex (already checked).
          -- (no-op)
        else
          -- 0 stack elements: already invalid by consensus; reject as nonstandard.
          -- Reference: Core policy.cpp:345-348.
          return false, "bad-witness-nonstandard"
        end
      end
    end  -- if witness non-empty
  end
  return true
end

--------------------------------------------------------------------------------
-- BIP125 RBF Signaling
--------------------------------------------------------------------------------

--- Check if a transaction signals opt-in RBF (BIP125).
-- A transaction signals RBF if any input has nSequence <= MAX_BIP125_RBF_SEQUENCE.
-- @param tx transaction: The transaction to check
-- @return boolean: True if the transaction signals RBF
function M.signals_rbf(tx)
  for _, inp in ipairs(tx.inputs) do
    if inp.sequence <= M.MAX_BIP125_RBF_SEQUENCE then
      return true
    end
  end
  return false
end

--------------------------------------------------------------------------------
-- Pay-to-Anchor (P2A) Policy
--------------------------------------------------------------------------------

--- Check if an output is a Pay-to-Anchor (P2A) output.
-- P2A outputs are anyone-can-spend outputs designed for anchor outputs in
-- Lightning commitment transactions. They allow CPFP fee bumping.
-- @param output txout: The transaction output to check
-- @return boolean: True if this is a P2A output
function M.is_anchor_output(output)
  return script_mod.is_pay_to_anchor(output.script_pubkey)
end

--- Check if a P2A (anchor) output has valid amount (must be 0).
-- Per policy, anchor outputs must have exactly 0 value to be relayed.
-- This prevents dust accumulation while allowing CPFP.
-- @param output txout: The transaction output to check
-- @return boolean: True if the anchor output has valid (zero) value
function M.is_valid_anchor_amount(output)
  return output.value == M.ANCHOR_AMOUNT
end

--- Check if a transaction's outputs comply with P2A policy.
-- All P2A outputs in a transaction must have zero value.
-- @param tx transaction: The transaction to check
-- @return boolean, string: True if valid, or false and error message
function M.check_anchor_outputs(tx)
  for i, out in ipairs(tx.outputs) do
    if M.is_anchor_output(out) then
      if not M.is_valid_anchor_amount(out) then
        return false, string.format("anchor output %d must have value 0, got %d", i, out.value)
      end
    end
  end
  return true
end

--- Check if a scriptPubKey is exempt from dust threshold.
-- P2A outputs are exempt from dust because they must be 0 value.
-- @param script_pubkey string: The scriptPubKey to check
-- @return boolean: True if exempt from dust threshold
function M.is_dust_exempt(script_pubkey)
  return script_mod.is_pay_to_anchor(script_pubkey)
end

--------------------------------------------------------------------------------
-- Outpoint Key Helper
--------------------------------------------------------------------------------

--- Generate a 36-byte key for outpoint lookups.
-- @param txid_hash256 hash256: The transaction id
-- @param vout_index number: The output index
-- @return string: 36-byte binary key
function M.outpoint_key(txid_hash256, vout_index)
  local w = serialize.buffer_writer()
  w.write_hash256(txid_hash256)
  w.write_u32le(vout_index)
  return w.result()
end

--------------------------------------------------------------------------------
-- Mempool Entry
--------------------------------------------------------------------------------

--- Create a mempool entry for a transaction.
-- @param tx transaction: The transaction
-- @param txid hash256: The transaction id
-- @param fee number: Fee in satoshis
-- @param vsize number: Virtual size
-- @param height number: Block height when added
-- @param time number: Unix timestamp when added (optional)
-- @return table: Mempool entry
function M.mempool_entry(tx, txid, fee, vsize, height, time)
  return {
    tx = tx,
    txid = txid,               -- hash256
    wtxid = validation.compute_wtxid(tx),
    fee = fee,                  -- satoshis (base fee, never mutated)
    -- Core CTxMemPoolEntry::m_modified_fee — starts at nFee, bumped by
    -- prioritisetransaction.  GetModifiedFee() returns this.  Kept in sync by
    -- Mempool:prioritise_transaction; also reconciled from map_deltas on
    -- block-connect / re-entry so a prior delta carries over.
    modified_fee = fee,         -- satoshis (base + accumulated priority delta)
    vsize = vsize,              -- virtual size (weight / 4)
    weight = validation.get_tx_weight(tx),
    size = #serialize.serialize_transaction(tx, true),
    fee_rate = fee / vsize,     -- sat/vB
    height = height,            -- block height when added
    time = time or os.time(),   -- unix timestamp when added
    ancestors = {},             -- set of txid_hex -> true
    descendants = {},           -- set of txid_hex -> true
    ancestor_count = 0,
    descendant_count = 0,
    ancestor_size = 0,
    descendant_size = 0,
    ancestor_fees = 0,
    descendant_fees = 0,
    spends_from = {},           -- outpoint_key -> txid_hex of parent in mempool
  }
end

--------------------------------------------------------------------------------
-- Mempool Object
--------------------------------------------------------------------------------

local Mempool = {}
Mempool.__index = Mempool

--- Create a new mempool.
-- @param chain_state table: The chain state (with coin_view and tip_height)
-- @param config table: Optional configuration
-- @return Mempool: New mempool instance
function M.new(chain_state, config)
  local self = setmetatable({}, Mempool)
  self.chain_state = chain_state
  self.max_size = (config and config.max_mempool_size) or M.DEFAULT_MAX_MEMPOOL_SIZE
  self.min_relay_fee = (config and config.min_relay_fee) or M.DEFAULT_MIN_RELAY_FEE
  self.expiry = (config and config.expiry) or M.DEFAULT_MEMPOOL_EXPIRY
  -- FIX-68 (W120 BUG-9): full-RBF mode (Bitcoin Core v28+ default).
  -- When true (default), accept_transaction skips BIP-125 Rule 1
  -- (opt-in signaling) — any confirmed-feeable replacement is allowed.
  -- When false (legacy), Rule 1 is enforced: every direct conflict must
  -- signal RBF (sequence <= MAX_BIP125_RBF_SEQUENCE) directly or via an
  -- unconfirmed ancestor.  Set via config.fullrbf or main.lua's
  -- --mempool-fullrbf CLI flag.  Mirrors Core's m_pool.m_opts.full_rbf
  -- (validation.cpp ReplacementChecks) and DEFAULT_MEMPOOL_FULL_RBF.
  if config ~= nil and config.fullrbf ~= nil then
    self.fullrbf = config.fullrbf and true or false
  else
    self.fullrbf = M.DEFAULT_MEMPOOL_FULL_RBF
  end
  self.entries = {}            -- txid_hex -> MempoolEntry
  -- map_deltas: user-set fee-priority deltas, keyed by display-order txid_hex
  -- (same key space as self.entries and the persist layer).  Mirrors Core's
  -- CTxMemPool::mapDeltas (std::map<Txid, CAmount>).  A delta may exist for a
  -- txid NOT currently in self.entries (Core keeps it so the tx is prioritised
  -- if it later arrives); an accumulated delta of 0 erases the key entirely.
  -- Populated by prioritise_transaction and survives restart via mempool.dat
  -- (mempool_persist.lua).  Reference: bitcoin-core/src/txmempool.{h,cpp}.
  self.map_deltas = {}         -- txid_hex -> int64 fee delta (satoshis, signed)
  self.outpoint_to_tx = {}    -- outpoint_key -> txid_hex (tracks which tx spends each output)
  self.total_size = 0          -- Current memory usage estimate
  self.tx_count = 0
  -- W96: PolicyScriptChecks/ConsensusScriptChecks gate.
  -- When true, accept_transaction runs script-verify for each input prev script
  -- before adding the tx to the mempool (Core validation.cpp:1135-1157 +
  -- 1158-1190).  Default OFF to preserve backward compatibility with existing
  -- test fixtures that use mock scripts.  Production callers (peer_manager,
  -- sendrawtransaction handler) should pass {verify_input_scripts=true} to
  -- match Core's relay behaviour.
  self.verify_input_scripts = (config and config.verify_input_scripts) == true
  -- Optional caller-supplied max feerate cap (Core ATMPArgs::m_client_maxfeerate,
  -- validation.cpp:1368-1371).  When set, the modified-feerate must not exceed
  -- this value; otherwise the tx is rejected with "max-fee-exceeded".  Units:
  -- satoshis per virtual kilobyte (sat/kvB).
  self.client_max_feerate_kvb = (config and config.client_max_feerate_kvb) or nil
  -- Rolling minimum fee state (txmempool.h:195-197, txmempool.cpp:829-859).
  -- Tracks the minimum feerate that can enter the mempool after evictions.
  -- Decays exponentially over time (ROLLING_FEE_HALFLIFE = 43200s).
  -- Bumped by TrimToSize (track_package_removed) when txs are evicted.
  -- Decay is enabled only after a block has been connected
  -- (block_since_last_rolling_fee_bump, txmempool.cpp:427).
  self.rolling_minimum_fee_rate = 0.0   -- sat/kvB, double precision
  self.last_rolling_fee_update = os.time()
  self.block_since_last_rolling_fee_bump = false
  -- Optional notification callbacks (for ZMQ, etc.)
  self.callbacks = {
    on_tx_removed = nil,  -- function(txid, reason)
  }
  return self
end

--------------------------------------------------------------------------------
-- Transaction Acceptance
--------------------------------------------------------------------------------

--- Accept a transaction into the mempool.
-- @param tx transaction: The transaction to accept
-- @param allow_rbf boolean: Whether to allow RBF replacement (default true)
-- @param opts table|nil: optional admission options.
--   opts.package_member (boolean): when true this tx is being admitted as a
--     member of a package whose AGGREGATE feerate already met the relay floor
--     (CPFP semantics). In that case we skip ONLY the two per-tx fee-floor
--     gates (absolute min-relay-fee + rolling-min-fee) so a low-fee parent
--     bailed out by a high-fee child still enters; EVERY other PreCheck
--     (standardness, dust, sigops, sequence locks, TRUC, PolicyScriptChecks)
--     still runs. Mirrors Core's AcceptMultipleTransactions, which runs full
--     PreChecks per member but applies the relay-fee floor at package level.
-- @return boolean, string, number: success, txid_hex or error message, fee
function Mempool:accept_transaction(tx, allow_rbf, opts)
  if allow_rbf == nil then allow_rbf = true end
  local package_member = opts and opts.package_member == true
  local txid = validation.compute_txid(tx)
  local txid_hex = types.hash256_hex(txid)

  -- 1. Check if we already have this transaction.
  -- Core distinguishes two cases (validation.cpp:823-830):
  --   (a) exact wtxid match → "txn-already-in-mempool"
  --   (b) same txid, different witness → "txn-same-nonwitness-data-in-mempool"
  -- We mirror that distinction so callers (RPC, P2P) can route accordingly.
  local existing = self.entries[txid_hex]
  if existing then
    local incoming_wtxid = validation.compute_wtxid(tx)
    local existing_wtxid_hex = existing.wtxid and types.hash256_hex(existing.wtxid) or nil
    local incoming_wtxid_hex = types.hash256_hex(incoming_wtxid)
    if existing_wtxid_hex == incoming_wtxid_hex then
      return false, "txn-already-in-mempool"
    else
      return false, "txn-same-nonwitness-data-in-mempool"
    end
  end

  -- 2. Basic structure validation
  local pcall_ok, check_ok, is_coinbase = pcall(validation.check_transaction, tx)
  if not pcall_ok then
    return false, "invalid transaction structure"
  end
  if not check_ok then
    return false, "invalid transaction structure"
  end
  if is_coinbase then
    return false, "coinbase transactions not accepted"
  end

  -- 2b. IsStandardTx: version range (Bitcoin Core policy/policy.cpp:102-105).
  -- Versions outside [1, 3] are rejected with reason "version".
  if tx.version < M.TX_MIN_STANDARD_VERSION or tx.version > M.TX_MAX_STANDARD_VERSION then
    return false, string.format("version: tx version %d not in [%d, %d]",
      tx.version, M.TX_MIN_STANDARD_VERSION, M.TX_MAX_STANDARD_VERSION)
  end

  -- 2b2. IsStandardTx weight cap (relay policy, not consensus).
  -- Bitcoin Core: policy/policy.cpp:111-115 — txs with weight greater
  -- than MAX_STANDARD_TX_WEIGHT (400_000) are rejected at relay with
  -- reason "tx-size".  Consensus still allows up to MAX_BLOCK_WEIGHT.
  local tx_weight_check = validation.get_tx_weight(tx)
  if tx_weight_check > M.MAX_STANDARD_TX_WEIGHT then
    return false, string.format("tx-size: weight %d exceeds %d",
      tx_weight_check, M.MAX_STANDARD_TX_WEIGHT)
  end

  -- 2b2b. CVE-2017-12842: non-witness serialized size must be >= 65 bytes.
  -- Bitcoin Core validation.cpp:812-814 (PreChecks, outside IsStandardTx):
  --   if (::GetSerializeSize(TX_NO_WITNESS(tx)) < MIN_STANDARD_TX_NONWITNESS_SIZE)
  --     return state.Invalid(…, "tx-size-small");
  -- MIN_STANDARD_TX_NONWITNESS_SIZE = 65 (policy/policy.h:40).
  -- A 64-byte base transaction can be crafted to collide with an internal
  -- merkle node hash, allowing SPV fraud proofs.  This gate closes that
  -- attack at relay time.
  local nonwitness_size = #serialize.serialize_transaction(tx, false)
  if nonwitness_size < M.MIN_STANDARD_TX_NONWITNESS_SIZE then
    return false, string.format("tx-size-small: non-witness size %d < %d",
      nonwitness_size, M.MIN_STANDARD_TX_NONWITNESS_SIZE)
  end

  -- 2b3. IsStandardTx per-input scriptSig checks (Bitcoin Core policy/policy.cpp:117-134).
  -- Each scriptSig must be (a) push-only and (b) at most MAX_STANDARD_SCRIPTSIG_SIZE bytes.
  for _, inp in ipairs(tx.inputs) do
    local ss = inp.script_sig or ""
    if #ss > M.MAX_STANDARD_SCRIPTSIG_SIZE then
      return false, string.format("scriptsig-size: %d > %d", #ss, M.MAX_STANDARD_SCRIPTSIG_SIZE)
    end
    if #ss > 0 and not script_mod.is_push_only(ss) then
      return false, "scriptsig-not-pushonly"
    end
  end

  -- 2b4. IsStandardTx per-output scriptPubKey check (Bitcoin Core policy/policy.cpp:139-155).
  -- Each output must be a standard script type; nonstandard outputs are rejected with
  -- reason "scriptpubkey".  OP_RETURN (nulldata) outputs are additionally size-limited
  -- to MAX_OP_RETURN_RELAY bytes total across all OP_RETURN outputs in the tx.
  -- "witness_unknown" outputs (v2-v16 with 2-40 byte programs) are accepted as
  -- standard per Bitcoin Core Solver() WITNESS_UNKNOWN + IsStandard() which only
  -- rejects TxoutType::NONSTANDARD, not WITNESS_UNKNOWN (policy.cpp:80-98).
  -- Reference: Bitcoin Core IsStandard() + IsStandardTx() loop, policy.cpp:80-155.
  local datacarrier_bytes_left = M.MAX_OP_RETURN_RELAY
  for _, out in ipairs(tx.outputs) do
    local script_type, type_meta = script_mod.classify_script(out.script_pubkey)
    if script_type == "nonstandard" then
      return false, "scriptpubkey"
    end
    if script_type == "nulldata" then
      local script_size = #out.script_pubkey
      if script_size > datacarrier_bytes_left then
        return false, "datacarrier"
      end
      datacarrier_bytes_left = datacarrier_bytes_left - script_size
    elseif script_type == "multisig" then
      -- W96: IsStandard rejects bare multisig with n > 3 (Core script/solver
      -- IsStandard, policy.cpp:140-141 via Solver TxoutType::MULTISIG).
      -- Reason string "scriptpubkey" matches Core (it falls through the same
      -- IsStandard() == false path).
      -- Additionally, if permit_bare_multisig is false, reject any bare
      -- multisig with reason "bare-multisig" (Core policy.cpp:152-154).
      -- We expose the policy flag via M.PERMIT_BARE_MULTISIG (default false
      -- to match Core's `-permitbaremultisig=0` since v28).
      local m, n = 0, 0
      if type(type_meta) == "string" then
        local m_s, n_s = type_meta:match("^(%d+)_(%d+)$")
        m = tonumber(m_s or "") or 0
        n = tonumber(n_s or "") or 0
      end
      if n < 1 or n > 3 or m < 1 or m > n then
        return false, "scriptpubkey"
      end
      if not M.PERMIT_BARE_MULTISIG then
        return false, "bare-multisig"
      end
    end
  end

  -- 2b5. Dust check (Bitcoin Core policy/policy.cpp:158-162).
  -- An output is dust if its value is below GetDustThreshold for its script type.
  -- IsUnspendable outputs (OP_RETURN) have a threshold of 0 (always allowed at value 0+).
  -- Bitcoin Core now allows exactly 1 dust output (MAX_DUST_OUTPUTS_PER_TX=1) to
  -- support ephemeral anchors; more than 1 dust output is rejected with "dust".
  -- Reference: Bitcoin Core GetDustThreshold() + GetDust() + IsStandardTx(), policy.cpp:27-162.
  local dust_count = 0
  for _, out in ipairs(tx.outputs) do
    local spk = out.script_pubkey
    -- IsUnspendable: starts with OP_RETURN (0x6a), threshold = 0 (dust_threshold = 0)
    local is_unspendable = (#spk >= 1 and spk:byte(1) == 0x6a)
    if not is_unspendable then
      -- Compute GetDustThreshold: nSize = serialized output size + estimated input size.
      -- Witness programs get the 75% segwit discount on the input witness portion.
      local nSize = 8 + 1 + #spk  -- value(8) + compactsize(1) + script bytes
      local script_type = script_mod.classify_script(spk)
      local is_witness = (script_type == "p2wpkh" or script_type == "p2wsh"
                          or script_type == "p2tr" or script_type == "p2a")
      if is_witness then
        -- 32(prev_hash) + 4(prev_index) + 1(script_sig_len) + (107/4)(witness) + 4(sequence)
        -- W96 fix: 107/4 = 26 (integer division), not 27.  Bitcoin Core
        -- policy.cpp:58 uses `(107 / WITNESS_SCALE_FACTOR)` which is C++ int
        -- division → 26.  Previously lunarblock added 27, computing dust
        -- thresholds 1 byte too large (~0.3% over-strict relay).
        nSize = nSize + 32 + 4 + 1 + 26 + 4  -- = 67 (Core uses 98 for P2WPKH total)
      else
        -- 32(prev_hash) + 4(prev_index) + 1(script_sig_len) + 107(script_sig) + 4(sequence)
        nSize = nSize + 32 + 4 + 1 + 107 + 4  -- = 148 (Core uses 182 for P2PKH total)
      end
      -- W96 fix: Core CFeeRate::GetFee uses EvaluateFeeUp (CEIL division), not
      -- floor.  For the default 3000 sat/kvB this happens to be a no-op
      -- (3000*nSize % 1000 == 0), but for any other configured dust rate the
      -- two diverge.  Use ceil for parity.  policy/feerate.cpp:20-26 +
      -- util/feefrac.h:202-218 (EvaluateFee<false> = round-up).
      local dust_threshold = math.ceil(M.DUST_RELAY_FEE_RATE * nSize / 1000)
      if out.value < dust_threshold then
        dust_count = dust_count + 1
      end
    end
  end
  -- MAX_DUST_OUTPUTS_PER_TX = 1: allow at most one dust output (ephemeral dust).
  if dust_count > 1 then
    return false, "dust"
  end
  -- NOTE: a single dust output is allowed HERE (the IsStandardTx gate), but is
  -- still subject to the ephemeral-dust 0-fee gate enforced AFTER the fee is
  -- known (step 5b2 below, Core PreCheckEphemeralTx).  dust_count remains in
  -- scope for that check.

  -- 2c. BIP-113 IsFinalTx: nLockTime must be satisfied at the next block.
  -- Reference: Bitcoin Core CheckFinalTxAtTip() (validation.cpp ~line 819).
  -- nextHeight = tipHeight + 1; lockTimeCutoff = MTP of current tip (BIP-113).
  local tip_height = self.chain_state.tip_height
  local tip_mtp = get_tip_mtp(self.chain_state)
  local next_height = tip_height + 1
  if not mining.is_final_tx(tx, next_height, tip_mtp) then
    return false, "bad-txns-nonfinal"
  end

  -- 3. Check all inputs exist (in UTXO set or mempool)
  local input_total = 0
  local missing_inputs = false
  local conflicts = {}  -- existing mempool txs that spend the same outputs
  -- Per-input UTXO heights for BIP-68 sequence lock checks (step 3b).
  -- Mempool-parent inputs use synthetic height tipHeight+1 (Core convention).
  local input_heights = {}  -- indexed 1..#tx.inputs
  -- Resolved prevouts for IsWitnessStandard (step 3c).
  local resolved_utxos = {}  -- indexed 1..#tx.inputs

  for i, inp in ipairs(tx.inputs) do
    local outpoint_key = M.outpoint_key(inp.prev_out.hash, inp.prev_out.index)

    -- Check if another mempool tx already spends this output
    local existing_spender = self.outpoint_to_tx[outpoint_key]
    if existing_spender then
      if allow_rbf then
        conflicts[existing_spender] = true
      else
        return false, "conflict with existing mempool tx"
      end
    end

    -- Look up UTXO from chain state
    local utxo = self.chain_state.coin_view:get(inp.prev_out.hash, inp.prev_out.index)
    local is_mempool_parent = false

    -- If not in UTXO set, check if it's an output of a mempool tx
    if not utxo then
      local prev_txid_hex = types.hash256_hex(inp.prev_out.hash)
      local parent_entry = self.entries[prev_txid_hex]
      if parent_entry and inp.prev_out.index < #parent_entry.tx.outputs then
        local out = parent_entry.tx.outputs[inp.prev_out.index + 1]
        utxo = {
          value = out.value,
          script_pubkey = out.script_pubkey,
          height = parent_entry.height,
          is_coinbase = false,
        }
        is_mempool_parent = true
      else
        missing_inputs = true
      end
    end

    if utxo then
      resolved_utxos[i] = utxo
      input_total = input_total + utxo.value
      -- Coinbase maturity
      if utxo.is_coinbase then
        if tip_height - utxo.height < consensus.COINBASE_MATURITY then
          return false, "spending immature coinbase"
        end
      end
      -- Save per-input UTXO height for BIP-68 sequence lock check.
      -- Mempool parents use synthetic height tipHeight+1 per Core convention.
      input_heights[i] = is_mempool_parent and (next_height) or utxo.height
    else
      input_heights[i] = 0
    end
  end

  if missing_inputs then
    -- W96: Core distinguishes two missing-inputs cases (validation.cpp:858-867):
    --   (a) any output of THIS tx is already in the coins cache → "txn-already-known"
    --       (we likely already accepted this tx into a block)
    --   (b) otherwise → "bad-txns-inputs-missingorspent" (real orphan)
    -- We approximate (a) by probing the coin_view for THIS tx's outputs.
    -- Reference: bitcoin-core/src/validation.cpp:858-867.
    local txid_bytes_hash = txid  -- hash256 type
    if self.chain_state.coin_view and self.chain_state.coin_view.get then
      for out_idx = 0, #tx.outputs - 1 do
        local own = self.chain_state.coin_view:get(txid_bytes_hash, out_idx)
        if own then
          return false, "txn-already-known"
        end
      end
    end
    return false, "bad-txns-inputs-missingorspent"
  end

  -- 3c. IsWitnessStandard (Bitcoin Core policy/policy.cpp:265-352).
  -- Enforces witness policy gates for each input: P2A stuffing rejection,
  -- P2SH-wrapped witness redeemScript extraction, non-witness/witness pairing,
  -- P2WSH size/count limits, P2TR annex and tapscript item-size limits.
  -- Coinbase exempt — guaranteed non-coinbase by step 2 above.
  local wit_ok, wit_err = M.is_witness_standard(tx, resolved_utxos)
  if not wit_ok then
    return false, wit_err
  end

  -- 3c2. W96: ValidateInputsStandardness (Core policy/policy.cpp:214-263).
  -- For each non-witness input, classify the prev scriptPubKey and reject:
  --   • NONSTANDARD prev scriptPubKey (with input index).
  --   • WITNESS_UNKNOWN (forward-compat segwit version with no relay support).
  --   • P2SH redeem-script with > MAX_P2SH_SIGOPS (15) sigops.
  -- Also runs CheckSigopsBIP54 to cap total non-witness sigops at
  -- MAX_TX_LEGACY_SIGOPS (2500) — a separate BIP-54 standardness gate.
  do
    local inp_std_ok, inp_std_err = M.validate_inputs_standardness(tx, resolved_utxos)
    if not inp_std_ok then
      return false, inp_std_err
    end
  end

  -- 3d. Sigop cost gate (Bitcoin Core validation.cpp:908,941-943).
  -- GetTransactionSigOpCost with STANDARD_SCRIPT_VERIFY_FLAGS (P2SH+witness).
  -- Transactions whose total sigop cost exceeds MAX_STANDARD_TX_SIGOPS_COST
  -- (16000 = MAX_BLOCK_SIGOPS_COST/5) are rejected with "bad-txns-too-many-sigops".
  -- We also save tx_sigop_cost for vsize adjustment in step 6.
  -- Reference: bitcoin-core/src/validation.cpp:908+941-943.
  local tx_sigop_cost
  do
    local inp_to_resolved = {}
    for i, inp in ipairs(tx.inputs) do
      inp_to_resolved[inp] = resolved_utxos[i]
    end
    local function get_prev_for_sigops(inp)
      return inp_to_resolved[inp]
    end
    local sigop_flags = { verify_p2sh = true, verify_witness = true }
    tx_sigop_cost = validation.get_transaction_sigop_cost(tx, get_prev_for_sigops, sigop_flags)
    if tx_sigop_cost > M.MAX_STANDARD_TX_SIGOPS_COST then
      return false, string.format("bad-txns-too-many-sigops: sigop cost %d > %d",
        tx_sigop_cost, M.MAX_STANDARD_TX_SIGOPS_COST)
    end
  end

  -- 4. Check P2A (anchor) output policy
  local anchor_ok, anchor_err = M.check_anchor_outputs(tx)
  if not anchor_ok then
    return false, anchor_err
  end

  -- 5. Calculate fee
  local output_total = 0
  for _, out in ipairs(tx.outputs) do
    output_total = output_total + out.value
  end
  local fee = input_total - output_total
  if fee < 0 then
    return false, "outputs exceed inputs"
  end

  -- 5b2. Ephemeral-dust 0-fee gate (Bitcoin Core PreCheckEphemeralTx,
  -- policy/ephemeral_policy.cpp:23-31, called from validation.cpp PreChecks
  -- ~line 934-939 when require_standard is set).  The IsStandardTx gate above
  -- permits up to MAX_DUST_OUTPUTS_PER_TX (=1) dust outputs to support
  -- ephemeral anchors, but Core ADDITIONALLY requires that a tx carrying ANY
  -- dust output pay ZERO fee — "we never want to give incentives to mine this
  -- transaction alone".  A fee-paying tx with a dust output is rejected with
  -- reason "dust" / "tx with dust output must be 0-fee".  Without this gate a
  -- fee-paying single-dust tx was accepted by lunarblock that BOTH strict and
  -- default Core reject (genuine relay-policy hole).  dust_count was computed
  -- in step 2b5 above (GetDust); reuse it here now that the fee is known.
  -- Reference: bitcoin-core/src/policy/ephemeral_policy.cpp:23-31.
  if dust_count > 0 and fee ~= 0 then
    return false, "dust: tx with dust output must be 0-fee"
  end

  -- 5b. BIP-68 SequenceLocks: per-input relative locktimes (CSV).
  -- Reference: Bitcoin Core CheckSequenceLocksAtTip() (validation.cpp ~line 887).
  -- Only enforced when CSV is active (tip_height >= csv_height) and tx.version >= 2.
  local csv_height = (self.chain_state.network and self.chain_state.network.csv_height) or 419328
  if tx.version >= 2 and tip_height >= csv_height then
    local enforce_bip68 = true
    -- get_utxo_height(inp): returns the height the UTXO was confirmed (or synthetic).
    -- get_block_mtp(h): returns the MTP of block at height h; we use tip_mtp
    --   conservatively for all heights (may false-reject time-locked txs near the
    --   boundary but never false-admits).
    local function get_utxo_height_for_seq(inp)
      for j, inp2 in ipairs(tx.inputs) do
        if inp2 == inp then
          return input_heights[j] or (next_height)
        end
      end
      return next_height
    end
    local function get_block_mtp_conservative(_h)
      return tip_mtp
    end
    local min_h, min_t = validation.calculate_sequence_locks(
      tx, next_height, get_utxo_height_for_seq, get_block_mtp_conservative, enforce_bip68)
    if not validation.check_sequence_locks(min_h, min_t, next_height, tip_mtp) then
      return false, "non-BIP68-final"
    end
  end

  -- 6. Check fee rate using sigop-adjusted vsize.
  -- Bitcoin Core computes vsize = GetVirtualTransactionSize(tx, sigop_cost, bytes_per_sigop)
  -- = ceil(max(weight, sigop_cost * bytes_per_sigop) / WITNESS_SCALE_FACTOR).
  -- This ensures sigop-heavy transactions pay proportionally higher fees.
  -- Reference: bitcoin-core/src/policy/policy.cpp:395-403 + policy.h:182-188.
  local weight = validation.get_tx_weight(tx)
  local vsize = validation.get_virtual_tx_size(weight, tx_sigop_cost, M.DEFAULT_BYTES_PER_SIGOP)
  local fee_rate_per_kb = fee * 1000 / vsize
  -- Package members bypass the per-tx absolute relay-fee floor: the package
  -- aggregate feerate was already validated by accept_package, so a low-fee
  -- parent paid for by a high-fee child must still enter (CPFP). All the
  -- standardness/script gates above still ran.
  if (not package_member) and fee_rate_per_kb < self.min_relay_fee then
    return false, string.format("fee rate too low: %.2f < %d sat/KB",
      fee_rate_per_kb, self.min_relay_fee)
  end

  -- 6b. Rolling minimum fee gate (Bitcoin Core validation.cpp:703-705).
  -- After TrimToSize evicts transactions, a rolling minimum fee is bumped so
  -- those evicted transactions cannot immediately re-enter the mempool.
  -- GetMinFee() decays over time (half-life = ROLLING_FEE_HALFLIFE) after
  -- each block is connected, approaching zero when the pool is well below max.
  -- Reference: CTxMemPool::GetMinFee (txmempool.cpp:829-851);
  --             validation.cpp:703-705 (CheckFeeRate).
  if not package_member then
    local min_fee_rate_kvb = self:get_min_fee()  -- sat/kvB
    if min_fee_rate_kvb > 0 then
      -- fee_rate_per_kb is in sat/kvB (fee*1000/vsize = sat*1000/(virtual-bytes) = sat/kvB)
      if fee_rate_per_kb < min_fee_rate_kvb then
        return false, string.format(
          "mempool min fee not met: %.2f < %.2f sat/kvB",
          fee_rate_per_kb, min_fee_rate_kvb)
      end
    end
  end

  -- 7. Handle RBF conflicts (BIP125)
  local all_conflicts = {}  -- All txs to be evicted (conflicts + descendants)
  if next(conflicts) then
    -- BIP125 Rule #1: All conflicting transactions must be replaceable
    -- (signal RBF directly or have an ancestor that does).
    --
    -- FIX-68 (W120 BUG-9): Skip Rule 1 when fullrbf is enabled.  Bitcoin
    -- Core v28+ removed SignalsOptInRBF from src/validation.cpp
    -- ReplacementChecks (cluster-mempool branch) — fullrbf default-on means
    -- replacement acceptance no longer gates on opt-in signaling.  We keep
    -- the check available behind self.fullrbf=false for operators who want
    -- legacy strict-opt-in policy; getmempoolinfo.fullrbf reflects the
    -- actual setting (no longer lies).  See policy/rbf.h
    -- DEFAULT_MEMPOOL_FULL_RBF=true.
    if not self.fullrbf then
      for conflict_txid_hex in pairs(conflicts) do
        if not self:is_replaceable(conflict_txid_hex) then
          return false, "conflicting tx does not signal RBF"
        end
      end
    end

    -- Collect all descendants of conflicting transactions
    local conflict_descendants = {}  -- All descendants to be evicted
    for conflict_txid_hex in pairs(conflicts) do
      all_conflicts[conflict_txid_hex] = true
      local conflict_entry = self.entries[conflict_txid_hex]
      if conflict_entry then
        for desc_hex in pairs(conflict_entry.descendants) do
          conflict_descendants[desc_hex] = true
        end
      end
    end
    for desc_hex in pairs(conflict_descendants) do
      all_conflicts[desc_hex] = true
    end

    -- BIP125 Rule #5: Don't evict more than MAX_REPLACEMENT_CANDIDATES transactions
    local eviction_count = 0
    for _ in pairs(all_conflicts) do
      eviction_count = eviction_count + 1
    end
    if eviction_count > M.MAX_REPLACEMENT_CANDIDATES then
      return false, string.format("too many potential replacements: %d > %d",
        eviction_count, M.MAX_REPLACEMENT_CANDIDATES)
    end

    -- EntriesAndTxidsDisjoint (rbf.cpp:85-98): the replacement tx's in-mempool
    -- ancestors must not overlap with the direct conflict set.  This prevents
    -- a replacement from being a descendant of one of the transactions it is
    -- trying to evict (cyclic replacement).  Ancestors are collected here,
    -- before conflicts are removed from the mempool, so the check is valid.
    do
      local repl_ancestors = {}
      for _, inp in ipairs(tx.inputs) do
        local prev_hex = types.hash256_hex(inp.prev_out.hash)
        local parent = self.entries[prev_hex]
        if parent then
          repl_ancestors[prev_hex] = true
          for anc_hex in pairs(parent.ancestors) do
            repl_ancestors[anc_hex] = true
          end
        end
      end
      for anc_hex in pairs(repl_ancestors) do
        if conflicts[anc_hex] then
          return false, string.format(
            "replacement tx %s spends conflicting transaction %s",
            types.hash256_hex(validation.compute_txid(tx)), anc_hex)
        end
      end
    end

    -- BIP125 Rule #3: Replacement fees must be >= original fees (rbf.cpp:109).
    -- Equal fees satisfy Rule #3; Rule #4 then enforces the incremental relay
    -- fee.  Core uses strict less-than here, not less-than-or-equal.
    local conflicting_fees = 0
    for conflict_hex in pairs(all_conflicts) do
      local entry = self.entries[conflict_hex]
      if entry then
        conflicting_fees = conflicting_fees + entry.fee
      end
    end
    if fee < conflicting_fees then
      return false, string.format("replacement fee not higher than conflicting txs: %d < %d",
        fee, conflicting_fees)
    end

    -- BIP125 Rule #4: New tx must pay for its own bandwidth (incremental relay fee)
    -- Additional fee must be >= incremental_relay_fee * new_tx_vsize
    local additional_fee = fee - conflicting_fees
    local required_additional = math.ceil(M.INCREMENTAL_RELAY_FEE * vsize / 1000)
    if additional_fee < required_additional then
      return false, string.format("insufficient fee for relay: additional %d < required %d",
        additional_fee, required_additional)
    end

    -- Rule #8 (cluster-mempool): ImprovesFeerateDiagram (Core rbf.cpp:127-140).
    -- After Rules 3 and 4 pass, verify the replacement strictly improves the
    -- feerate diagram of every affected cluster.  We build the "old" diagram
    -- from the current mempool state of all clusters that contain a conflicting
    -- tx, then the "new" diagram with those conflicts removed and the
    -- replacement tx added, and require compare_diagrams(old, new) == true.
    do
      -- Collect the set of all txids in the same clusters as the conflicts.
      local affected_txids = {}
      for conflict_hex in pairs(all_conflicts) do
        local root = uf_find(conflict_hex)
        for txid_iter, _ in pairs(uf_parent) do
          if uf_find(txid_iter) == root and self.entries[txid_iter] then
            affected_txids[txid_iter] = true
          end
        end
      end

      -- Build the old diagram from the affected cluster entries.
      local old_cluster_txids = {}
      for txid_iter in pairs(affected_txids) do
        old_cluster_txids[#old_cluster_txids + 1] = txid_iter
      end
      local old_lin = linearize_cluster(old_cluster_txids, self.entries)
      local old_diag = build_feerate_diagram(old_lin, self.entries)

      -- Build a synthetic entries table: remove all_conflicts, add replacement.
      local new_entries = {}
      for txid_iter, e in pairs(self.entries) do
        if affected_txids[txid_iter] and not all_conflicts[txid_iter] then
          new_entries[txid_iter] = e
        end
      end
      -- Synthetic entry for the replacement tx (not yet in the mempool).
      new_entries[txid_hex] = { fee = fee, size = vsize, vsize = vsize }

      -- Build new cluster txid list: old affected minus conflicts, plus replacement.
      local new_cluster_txids = {}
      for txid_iter in pairs(new_entries) do
        -- Include only affected-cluster txids plus the replacement itself.
        if affected_txids[txid_iter] or txid_iter == txid_hex then
          new_cluster_txids[#new_cluster_txids + 1] = txid_iter
        end
      end
      local new_lin = linearize_cluster(new_cluster_txids, new_entries)
      local new_diag = build_feerate_diagram(new_lin, new_entries)

      if not compare_diagrams(old_diag, new_diag) then
        return false, "insufficient feerate: does not improve feerate diagram"
      end
    end

    -- BIP125 Rule #2: The replacement may only include an unconfirmed input if
    -- that specific outpoint (txid:vout) was already an input of one of the
    -- conflicting transactions.  We collect all (txid, vout) outpoints that
    -- appear in any conflicting tx and use that as the allowed set.
    -- Reference: BIP 125 rule 2; old Core src/validation.cpp HasNoNewUnconfirmed.
    local conflict_input_outpoints = {}  -- "txhex:vout" → true
    for conflict_hex in pairs(conflicts) do   -- only direct conflicts, not descendants
      local ce = self.entries[conflict_hex]
      if ce then
        for _, inp in ipairs(ce.tx.inputs) do
          local k = types.hash256_hex(inp.prev_out.hash) .. ":" .. inp.prev_out.index
          conflict_input_outpoints[k] = true
        end
      end
    end

    -- Check each input of the replacement tx
    for _, inp in ipairs(tx.inputs) do
      local prev_hex = types.hash256_hex(inp.prev_out.hash)
      local prev_entry = self.entries[prev_hex]
      if prev_entry then
        -- This input spends an unconfirmed mempool UTXO.
        local outpoint_key = prev_hex .. ":" .. inp.prev_out.index
        if not conflict_input_outpoints[outpoint_key] then
          return false, "replacement adds new unconfirmed input"
        end
      end
    end

    -- All checks passed, remove conflicting transactions and their descendants
    for conflict_hex in pairs(all_conflicts) do
      -- Only remove if still in mempool (descendants may have been removed already)
      if self.entries[conflict_hex] then
        self:remove_transaction(conflict_hex, "replaced")
      end
    end
  end

  -- 8. Compute ancestors (with proper deduplication) and check limits
  -- Build the full set of unique in-mempool ancestors
  local ancestors = {}  -- txid_hex -> true (set of all ancestors)
  local direct_parents = {}  -- txid_hex -> entry (direct parents only)

  for _, inp in ipairs(tx.inputs) do
    local prev_hex = types.hash256_hex(inp.prev_out.hash)
    local parent = self.entries[prev_hex]
    if parent then
      direct_parents[prev_hex] = parent
      ancestors[prev_hex] = true
      -- Include all of parent's ancestors (properly deduped via set)
      for anc_hex in pairs(parent.ancestors) do
        ancestors[anc_hex] = true
      end
    end
  end

  -- Count unique ancestors and sum their sizes/fees
  local ancestor_count = 1  -- include self
  local ancestor_size = vsize  -- include self
  local ancestor_fees = fee  -- include self

  for anc_hex in pairs(ancestors) do
    local anc_entry = self.entries[anc_hex]
    if anc_entry then
      ancestor_count = ancestor_count + 1
      ancestor_size = ancestor_size + anc_entry.vsize
      ancestor_fees = ancestor_fees + anc_entry.fee
    end
  end

  if ancestor_count > M.MAX_ANCESTORS then
    return false, "too many ancestors: " .. ancestor_count
  end
  if ancestor_size > M.MAX_ANCESTOR_SIZE then
    return false, "ancestor size too large: " .. ancestor_size
  end

  -- 8b. Check descendant limits for ALL ancestors
  -- Adding this transaction would add 1 to descendant_count and vsize to descendant_size
  -- for every ancestor (including direct parents)
  for anc_hex in pairs(ancestors) do
    local anc_entry = self.entries[anc_hex]
    if anc_entry then
      local new_desc_count = anc_entry.descendant_count + 1
      local new_desc_size = anc_entry.descendant_size + vsize
      if new_desc_count > M.MAX_DESCENDANTS then
        return false, "too many descendants for ancestor " .. anc_hex:sub(1, 16)
      end
      if new_desc_size > M.MAX_DESCENDANT_SIZE then
        return false, "descendant size too large for ancestor " .. anc_hex:sub(1, 16)
      end
    end
  end

  -- 8c. BIP-431 TRUC (v3) policy checks.
  -- Reference: bitcoin-core/src/policy/truc_policy.cpp:171-261 (SingleTRUCChecks).
  -- Must be called for every tx (TRUC and non-TRUC) to enforce inheritance gates.
  -- The `conflicts` set (direct RBF conflicts) is forwarded so Gate 6 can detect
  -- sibling-eviction eligibility (the existing child is about to be replaced).
  do
    local truc_conflicts = {}
    for conflict_hex in pairs(conflicts) do
      truc_conflicts[conflict_hex] = true
    end
    local truc_ok, truc_err, sibling_hex =
      M.single_truc_checks(self.entries, tx, direct_parents, vsize, truc_conflicts)
    if not truc_ok then
      if sibling_hex then
        -- Sibling eviction: attempt to evict the existing TRUC child and retry.
        -- This mirrors Core's behaviour: the caller removes the sibling under RBF
        -- rules and re-attempts acceptance.  Here we evict the sibling and
        -- re-run the gate, then continue if it now passes.
        -- Reference: Core validation.cpp AcceptSingleTransaction sibling-eviction path.
        self:remove_transaction(sibling_hex, "truc-sibling-eviction")
        local retry_ok, retry_err, _ =
          M.single_truc_checks(self.entries, tx, direct_parents, vsize, truc_conflicts)
        if not retry_ok then
          return false, retry_err or truc_err
        end
        -- Sibling evicted and gate now passes; fall through.
      else
        return false, truc_err
      end
    end
  end

  -- 8d. W96: client_max_feerate gate (Core validation.cpp:1368-1371).
  -- When the caller (e.g. RPC sendrawtransaction with `maxfeerate`) supplied
  -- a maximum feerate, abort if this tx's modified feerate exceeds it.  Units
  -- match the gate above (sat/kvB).  This is per-Mempool config, evaluated
  -- against the freshly-computed fee_rate_per_kb.
  if self.client_max_feerate_kvb
     and fee_rate_per_kb > self.client_max_feerate_kvb then
    return false, string.format(
      "max-fee-exceeded: feerate %.2f > %.2f sat/kvB",
      fee_rate_per_kb, self.client_max_feerate_kvb)
  end

  -- 8e. W96: PolicyScriptChecks (Core validation.cpp:1135-1157).
  -- Run input-script verification against STANDARD_SCRIPT_VERIFY_FLAGS so that
  -- bad signatures, malformed scripts, and policy violations are caught at
  -- relay time and not just at block-connect time.  This is the equivalent of
  -- Core's CheckInputScripts call with cacheSigStore=true, cacheFullScriptStore=
  -- false — the policy pass.  Gated by self.verify_input_scripts so existing
  -- test fixtures (which use mock scripts) keep passing.
  --
  -- Coverage:
  --   • Legacy + P2SH: full verify_script with verify_p2sh + verify_dersig +
  --     verify_nulldummy + verify_checklocktimeverify + verify_checksequenceverify
  --     + verify_low_s + verify_strictenc + verify_minimaldata.
  --   • Witness paths (P2WPKH/P2WSH/P2TR): require the full segwit/taproot
  --     verifier stack used by ConnectBlock.  Building that here is non-trivial
  --     and would duplicate ~400 lines from utxo.lua; we leave witness
  --     verification to block-connect for now and only verify the non-witness
  --     side at relay.  This is policy-only (consensus rules are still
  --     enforced at block-connect), but does mean signature-bad witness txs
  --     can sit in the mempool until they get mined and rejected.  TODO:
  --     factor utxo.lua's per-input verifier into a reusable helper and call
  --     it here.
  if self.verify_input_scripts then
    local script_flags = {
      verify_p2sh = true,
      verify_dersig = true,
      verify_strictenc = true,
      verify_low_s = true,
      verify_nulldummy = true,
      verify_sigpushonly = true,
      verify_minimaldata = true,
      verify_discourage_upgradable_nops = true,
      verify_cleanstack = true,
      verify_checklocktimeverify = true,
      verify_checksequenceverify = true,
      verify_witness = true,
      verify_nullfail = true,
      verify_witness_pubkeytype = true,
      verify_const_scriptcode = true,
    }
    for i, inp in ipairs(tx.inputs) do
      local utxo = resolved_utxos[i]
      if utxo and validation.make_sig_checker then
        local script_type = script_mod.classify_script(utxo.script_pubkey)
        -- Only verify non-witness paths here.  Witness paths require the
        -- per-witness execution machinery in utxo.lua (~400 lines); they are
        -- still validated at block-connect.  This is policy-only — consensus
        -- rules continue to be enforced at block validation.
        local is_witness_path = (script_type == "p2wpkh"
                                  or script_type == "p2wsh"
                                  or script_type == "p2tr"
                                  or script_type == "p2a")
        if not is_witness_path then
          local ok_c, checker = pcall(validation.make_sig_checker,
            tx, i - 1, utxo.value, utxo.script_pubkey, script_flags, nil)
          if ok_c then
            -- verify_script returns:
            --   (true)            on success
            --   (false)           on script eval returning empty/false stack
            --   (nil, err_string) on hard script error
            -- We need to handle all three.  pcall adds a leading bool for the
            -- pcall outcome itself, so successful pcall + true = pass.
            local ok_p, r1, r2 = pcall(script_mod.verify_script,
              inp.script_sig or "", utxo.script_pubkey, script_flags, checker)
            if not ok_p then
              return false, string.format(
                "mandatory-script-verify-flag-failed (input %d: %s)",
                i - 1, tostring(r1))
            end
            if r1 == nil or r1 == false then
              return false, string.format(
                "mandatory-script-verify-flag-failed (input %d: %s)",
                i - 1, tostring(r2 or "script eval"))
            end
          end
        end
      end
    end
  end

  -- 9. Add to mempool
  local entry = M.mempool_entry(tx, txid, fee, vsize, self.chain_state.tip_height, os.time())
  entry.ancestor_count = ancestor_count - 1  -- exclude self
  entry.ancestor_size = ancestor_size - vsize  -- exclude self
  entry.ancestor_fees = ancestor_fees - fee  -- exclude self
  entry.ancestors = ancestors
  self.entries[txid_hex] = entry
  self.tx_count = self.tx_count + 1
  self.total_size = self.total_size + entry.size

  -- If a priority delta was set for this txid before it entered the mempool
  -- (e.g. prioritisetransaction on a not-yet-arrived tx, or a delta restored
  -- from mempool.dat), apply it to the entry's modified fee now.  Mirrors
  -- Core CTxMemPool::addUnchecked → ApplyDelta + UpdateModifiedFee
  -- (txmempool.cpp:1014-1023).
  local pending_delta = self.map_deltas[txid_hex]
  if pending_delta and pending_delta ~= 0 then
    entry.modified_fee = entry.fee + pending_delta
  end

  -- Track outpoint spending and parent relationships
  for _, inp in ipairs(tx.inputs) do
    local outpoint_key = M.outpoint_key(inp.prev_out.hash, inp.prev_out.index)
    self.outpoint_to_tx[outpoint_key] = txid_hex

    local prev_hex = types.hash256_hex(inp.prev_out.hash)
    if direct_parents[prev_hex] then
      entry.spends_from[outpoint_key] = prev_hex
    end
  end

  -- Update ALL ancestors with descendant info (not just direct parents)
  -- Each ancestor gets this new tx added as a descendant
  for anc_hex in pairs(ancestors) do
    local anc_entry = self.entries[anc_hex]
    if anc_entry then
      anc_entry.descendants[txid_hex] = true
      anc_entry.descendant_count = anc_entry.descendant_count + 1
      anc_entry.descendant_size = anc_entry.descendant_size + vsize
      anc_entry.descendant_fees = anc_entry.descendant_fees + fee
    end
  end

  -- Cluster mempool: register in union-find and merge with parent clusters
  uf_parent[txid_hex] = txid_hex
  uf_rank[txid_hex] = 0
  for parent_hex in pairs(direct_parents) do
    uf_union(txid_hex, parent_hex)
  end
  -- Check cluster limits (Bitcoin Core policy/policy.h:72-74,
  -- kernel/mempool_limits.h:20-22, txmempool.cpp:1072-1079).
  -- Two independent gates mirror Core's TxGraph::IsOversized() check:
  --   (a) cluster transaction COUNT must not exceed DEFAULT_CLUSTER_LIMIT (64)
  --   (b) cluster total vsize must not exceed DEFAULT_CLUSTER_SIZE_LIMIT_KVB*1000 (101000)
  local cluster_root = uf_find(txid_hex)
  local cluster_count = get_cluster_size(cluster_root)
  if cluster_count > MAX_CLUSTER_COUNT then
    -- Undo: remove the entry we just added
    self:remove_transaction(txid_hex, "cluster-limit")
    return false, "cluster size exceeds count limit of " .. MAX_CLUSTER_COUNT
  end
  local cluster_vsize = get_cluster_vsize(cluster_root, self.entries)
  if cluster_vsize > MAX_CLUSTER_VSIZE then
    -- Undo: remove the entry we just added
    self:remove_transaction(txid_hex, "cluster-limit")
    return false, "cluster vsize " .. cluster_vsize .. " exceeds limit of " .. MAX_CLUSTER_VSIZE
  end

  -- 9. Evict low-fee and expired transactions if mempool exceeds limits.
  -- Core's LimitMempoolSize (validation.cpp:271-276) calls Expire() then
  -- TrimToSize().  We mirror that order: first expire old txs, then trim
  -- by size so that the freshest high-feerate txs survive.
  self:expire()
  self:trim()

  return true, txid_hex, fee
end

--- AcceptToMemoryPool — main entry point matching Bitcoin Core's AcceptToMemoryPool.
-- Validates and adds a transaction to the mempool with full RBF support.
--
-- When `test_accept` is true (Core's `m_test_accept`, validation.cpp:1388),
-- we run the FULL acceptance pipeline (PreChecks + Policy/ConsensusScriptChecks)
-- but roll back any state changes so the mempool is unchanged.  The previous
-- shim short-circuited and returned `accepted=true` for any non-duplicate tx,
-- which silently accepted invalid txs (missing inputs, oversize, dust, etc.).
-- Reference: bitcoin-core/src/validation.cpp:1386-1391.
--
-- @param tx transaction: The transaction to validate and add
-- @param test_accept boolean: When true, validate only without adding (default false)
-- @return table: Result with fields: accepted, txid, fee, vsize, reject_reason
function Mempool:accept_to_memory_pool(tx, test_accept)
  if test_accept then
    -- W96 fix: run full validation, then roll back if accepted.  This mirrors
    -- Core's behaviour where m_test_accept causes early-return after
    -- PolicyScriptChecks/ConsensusScriptChecks pass but before FinalizeSubpackage.
    -- We can't easily reproduce Core's changeset model in pure Lua, so we
    -- accept via accept_transaction (which adds the entry) and then immediately
    -- remove it.  Any side-effect on the rolling-fee state would be incorrect
    -- but the test_accept path is not supposed to affect mempool state, so we
    -- also snapshot/restore the rolling-fee fields.
    local saved_rolling = self.rolling_minimum_fee_rate
    local saved_last_update = self.last_rolling_fee_update
    local saved_since_bump = self.block_since_last_rolling_fee_bump

    local ok, txid_hex_or_err, fee = self:accept_transaction(tx)
    if ok then
      -- Snapshot vsize before we wipe the entry.
      local entry = self.entries[txid_hex_or_err]
      local vsize = (entry and entry.vsize) or 0
      -- Roll back: drop the entry without bumping rolling-fee state.
      self:remove_transaction(txid_hex_or_err, "test-accept")
      -- Restore rolling-fee state so test_accept is side-effect-free.
      self.rolling_minimum_fee_rate = saved_rolling
      self.last_rolling_fee_update = saved_last_update
      self.block_since_last_rolling_fee_bump = saved_since_bump
      return {
        accepted = true,
        txid = txid_hex_or_err,
        fee = fee or 0,
        vsize = vsize,
        reject_reason = nil,
      }
    else
      -- Restore rolling-fee state in case any rejection path mutated it.
      self.rolling_minimum_fee_rate = saved_rolling
      self.last_rolling_fee_update = saved_last_update
      self.block_since_last_rolling_fee_bump = saved_since_bump
      return {
        accepted = false,
        txid = nil,
        fee = 0,
        vsize = 0,
        reject_reason = txid_hex_or_err,
      }
    end
  end

  local ok, txid_hex_or_err, fee = self:accept_transaction(tx)
  if ok then
    local entry = self.entries[txid_hex_or_err]
    return {
      accepted = true,
      txid = txid_hex_or_err,
      fee = fee or (entry and entry.fee) or 0,
      vsize = (entry and entry.vsize) or 0,
      reject_reason = nil,
    }
  else
    return {
      accepted = false,
      txid = nil,
      fee = 0,
      vsize = 0,
      reject_reason = txid_hex_or_err,
    }
  end
end

--------------------------------------------------------------------------------
-- Transaction Removal
--------------------------------------------------------------------------------

--- Remove a transaction from the mempool.
-- @param txid_hex string: Transaction id as hex string
-- @param reason string: Reason for removal (for logging)
function Mempool:remove_transaction(txid_hex, reason)
  local entry = self.entries[txid_hex]
  if not entry then return end

  -- Remove descendants first (recursive)
  -- Copy the table to avoid modification during iteration
  local desc_list = {}
  for desc_hex in pairs(entry.descendants) do
    desc_list[#desc_list + 1] = desc_hex
  end
  for _, desc_hex in ipairs(desc_list) do
    self:remove_transaction(desc_hex, reason)
  end

  -- Clean up outpoint tracking
  for _, inp in ipairs(entry.tx.inputs) do
    local outpoint_key = M.outpoint_key(inp.prev_out.hash, inp.prev_out.index)
    self.outpoint_to_tx[outpoint_key] = nil
  end

  -- Update ALL ancestors (not just direct parents)
  -- Remove this tx from their descendants set and decrement counts
  for anc_hex in pairs(entry.ancestors) do
    local anc_entry = self.entries[anc_hex]
    if anc_entry then
      anc_entry.descendants[txid_hex] = nil
      anc_entry.descendant_count = anc_entry.descendant_count - 1
      anc_entry.descendant_size = anc_entry.descendant_size - entry.vsize
      anc_entry.descendant_fees = anc_entry.descendant_fees - entry.fee
    end
  end

  self.total_size = self.total_size - entry.size
  self.tx_count = self.tx_count - 1
  self.entries[txid_hex] = nil

  -- Cluster mempool: remove from union-find
  uf_parent[txid_hex] = nil
  uf_rank[txid_hex] = nil

  -- Invoke callback if registered (for ZMQ notifications, etc.)
  -- Note: txid_hex is the hex string; callers needing bytes should convert
  if self.callbacks.on_tx_removed then
    self.callbacks.on_tx_removed(txid_hex, reason)
  end
end

--------------------------------------------------------------------------------
-- Block Connection
--------------------------------------------------------------------------------

--- Handle block connection (remove confirmed transactions).
-- Also resets the rolling fee decay clock: after a block is connected,
-- the rolling minimum fee is eligible to decay toward zero (Bitcoin Core
-- txmempool.cpp:426-427: lastRollingFeeUpdate=GetTime(),
-- blockSinceLastRollingFeeBump=true).
-- @param block block: The connected block
function Mempool:on_block_connected(block)
  for _, tx in ipairs(block.transactions) do
    local txid = validation.compute_txid(tx)
    local txid_hex = types.hash256_hex(txid)
    if self.entries[txid_hex] then
      self:remove_transaction(txid_hex, "confirmed")
    end
    -- A confirmed tx's priority delta is dropped (Core removeForBlock →
    -- ClearPrioritisation, txmempool.cpp:420) so it isn't re-applied to a
    -- future tx that reuses the txid.  Other removal reasons (REPLACED,
    -- EXPIRY, SIZELIMIT, REORG) deliberately preserve the delta.
    self:clear_prioritisation(txid_hex)
    -- Also remove conflicting transactions
    for _, inp in ipairs(tx.inputs) do
      local outpoint_key = M.outpoint_key(inp.prev_out.hash, inp.prev_out.index)
      local conflict = self.outpoint_to_tx[outpoint_key]
      if conflict and conflict ~= txid_hex then
        self:remove_transaction(conflict, "conflict")
        -- removeConflicts → ClearPrioritisation (txmempool.cpp:398).
        self:clear_prioritisation(conflict)
      end
    end
  end
  -- Reset rolling fee decay clock (txmempool.cpp:426-427).
  -- block_since_last_rolling_fee_bump=true enables get_min_fee() to
  -- decay the rolling minimum fee toward zero over time.
  self.last_rolling_fee_update = os.time()
  self.block_since_last_rolling_fee_bump = true
end

--------------------------------------------------------------------------------
-- Block Disconnection (reorg refill)
--------------------------------------------------------------------------------

--- Handle block disconnection during a reorg: re-add the block's
-- non-coinbase transactions to the mempool, best-effort.
--
-- This is the lunarblock analog of Bitcoin Core's
-- `MaybeUpdateMempoolForReorg` (validation.cpp), invoked from
-- `Chainstate::DisconnectTip`.  When a block is disconnected during a
-- reorg the txs it contained leave the chain — to avoid silently
-- dropping them we try to re-admit each one to the mempool.  The full
-- `accept_transaction` pipeline runs against the new tip's UTXO state
-- (BIP-113 IsFinalTx, BIP-68 SequenceLocks, standardness, conflicts
-- against new-chain UTXOs), so a tx that's no longer valid against the
-- post-reorg chain is correctly rejected here.  Coinbase txs are
-- skipped — coinbase outputs were unspent at disconnect (the undo
-- restored them) and coinbase is a non-standard mempool entry by
-- definition (`accept_transaction` rejects `is_coinbase`).
--
-- Reference: bitcoin-core/src/validation.cpp DisconnectTip +
-- MaybeUpdateMempoolForReorg.  Camlcoin parity: lib/sync.ml:2354-2363.
--
-- @param block block: The disconnected block
function Mempool:block_disconnected(block)
  if not block or not block.transactions then return end
  -- Skip transactions[1] (coinbase): coinbase has no inputs to admit
  -- and accept_transaction explicitly rejects coinbase txs.
  for i = 2, #block.transactions do
    local tx = block.transactions[i]
    -- Best-effort: ignore failures (tx may now conflict with the new
    -- chain, exceed mempool size, etc.).  Core's removeForReorg has
    -- the same swallow-and-continue policy.
    pcall(function()
      self:accept_transaction(tx)
    end)
  end
end

--------------------------------------------------------------------------------
-- Mempool Trimming
--------------------------------------------------------------------------------

--- Track the feerate of a removed package for the rolling minimum fee.
-- Called from trim_to_size() after evicting a transaction or cluster.
-- Bumps rolling_minimum_fee_rate if the evicted rate is higher.
-- Also clears block_since_last_rolling_fee_bump so the decay clock restarts.
-- Reference: Bitcoin Core CTxMemPool::trackPackageRemoved (txmempool.cpp:853-859).
-- @param rate_sat_kvb number: feerate in sat/kvB of the removed package
function Mempool:track_package_removed(rate_sat_kvb)
  if rate_sat_kvb > self.rolling_minimum_fee_rate then
    self.rolling_minimum_fee_rate = rate_sat_kvb
    self.block_since_last_rolling_fee_bump = false
  end
end

--- Get the current minimum fee rate required to enter the mempool.
-- Implements the exponential rolling decay from Bitcoin Core's GetMinFee().
-- The decay is only active after a block has been connected
-- (block_since_last_rolling_fee_bump == true).  While the pool is shrinking,
-- the minimum decays toward zero (floor: INCREMENTAL_RELAY_FEE / 2).
--
-- Halflife adjustments (txmempool.cpp:836-841):
--   - pool < 1/4 full → halflife / 4  (fast decay)
--   - pool < 1/2 full → halflife / 2
--   - otherwise       → full ROLLING_FEE_HALFLIFE
--
-- Returns the rolling minimum fee rate in sat/kvB; at least
-- INCREMENTAL_RELAY_FEE sat/kvB when non-zero, else 0.
--
-- Reference: Bitcoin Core CTxMemPool::GetMinFee (txmempool.cpp:829-851).
-- @return number: minimum feerate in sat/kvB
function Mempool:get_min_fee()
  -- If no block has been connected since the last bump, do not decay.
  -- Core: if (!blockSinceLastRollingFeeBump || rollingMinimumFeeRate == 0)
  --        return CFeeRate(llround(rollingMinimumFeeRate));
  if not self.block_since_last_rolling_fee_bump or self.rolling_minimum_fee_rate == 0 then
    return self.rolling_minimum_fee_rate
  end

  local now = os.time()
  if now > self.last_rolling_fee_update + 10 then
    local halflife = M.ROLLING_FEE_HALFLIFE
    -- Adjust halflife based on current pool occupancy (txmempool.cpp:837-841).
    if self.total_size < self.max_size / 4 then
      halflife = halflife / 4
    elseif self.total_size < self.max_size / 2 then
      halflife = halflife / 2
    end

    local dt = now - self.last_rolling_fee_update
    self.rolling_minimum_fee_rate =
      self.rolling_minimum_fee_rate / math.pow(2.0, dt / halflife)
    self.last_rolling_fee_update = now

    -- Floor: once below INCREMENTAL_RELAY_FEE/2, zero it out.
    -- Core: if (rollingMinimumFeeRate < incremental_relay_feerate.GetFeePerK() / 2) → 0
    if self.rolling_minimum_fee_rate < M.INCREMENTAL_RELAY_FEE / 2 then
      self.rolling_minimum_fee_rate = 0
      return 0
    end
  end

  -- Return max(rolling_minimum_fee_rate, INCREMENTAL_RELAY_FEE).
  -- Core: return std::max(CFeeRate(llround(rollingMinimumFeeRate)), incremental_relay_feerate)
  return math.max(self.rolling_minimum_fee_rate, M.INCREMENTAL_RELAY_FEE)
end

--- Expire transactions older than the configured expiry time.
-- Removes all mempool entries whose time < (now - expiry), plus all their
-- descendants.  Returns the count of transactions removed.
-- Reference: Bitcoin Core CTxMemPool::Expire (txmempool.cpp:811-827).
-- @param cutoff_time number: optional Unix timestamp; defaults to now - self.expiry
-- @return number: count of txs removed (including descendants)
function Mempool:expire(cutoff_time)
  cutoff_time = cutoff_time or (os.time() - self.expiry)
  -- Collect all entries that are directly expired.
  local expired = {}
  for txid_hex, entry in pairs(self.entries) do
    if entry.time < cutoff_time then
      expired[txid_hex] = true
    end
  end
  if not next(expired) then return 0 end

  -- Expand to include all descendants (CalculateDescendants equivalent).
  -- We do a worklist expansion: for each expired tx, add its descendants.
  local to_remove = {}
  local worklist = {}
  for txid_hex in pairs(expired) do
    worklist[#worklist + 1] = txid_hex
  end
  local visited = {}
  while #worklist > 0 do
    local hex = table.remove(worklist)
    if not visited[hex] then
      visited[hex] = true
      to_remove[#to_remove + 1] = hex
      local entry = self.entries[hex]
      if entry then
        for desc_hex in pairs(entry.descendants) do
          if not visited[desc_hex] then
            worklist[#worklist + 1] = desc_hex
          end
        end
      end
    end
  end

  -- Remove in order (remove_transaction handles cascading removal, but
  -- some txs in to_remove may already be gone; nil-check is cheap).
  local n = 0
  for _, txid_hex in ipairs(to_remove) do
    if self.entries[txid_hex] then
      self:remove_transaction(txid_hex, "expiry")
      n = n + 1
    end
  end
  return n
end

--- Evict low-fee transactions when mempool exceeds max size.
-- Implements Bitcoin Core CTxMemPool::TrimToSize (txmempool.cpp:861-911).
--
-- Three gates compared to the old trim():
--   Gate 1: loop condition — DynamicMemoryUsage() > sizelimit (Core:868).
--   Gate 2: after each eviction, call track_package_removed(evicted_feerate +
--            INCREMENTAL_RELAY_FEE) to bump the rolling minimum fee so newly
--            evicted txs cannot immediately re-enter (Core:877-878).
--   Gate 3: select the worst (lowest feerate) entry as eviction candidate,
--            using (fee+desc_fees)/(vsize+desc_size) as the descendant feerate
--            proxy (closest analog to Core's GetWorstMainChunk cluster sort).
function Mempool:trim()
  while self.total_size > self.max_size do
    -- Find the entry with the lowest descendant fee rate
    -- (total fee of this tx + descendants) / (total size of this tx + descendants)
    local worst_hex = nil
    local worst_rate = math.huge
    for hex, entry in pairs(self.entries) do
      -- Guard against zero-size (should not happen but prevents /0)
      local total_vsize = entry.vsize + entry.descendant_size
      if total_vsize > 0 then
        -- FIX-72 (mirrors rustoshi trim_to_size + get_modified_fee, mempool.rs
        -- :3061-3097 / :3372): the lowest-feerate eviction pick must consult
        -- the entry's MODIFIED fee (base + prioritisetransaction delta), not the
        -- raw base fee — Core's TrimToSize evicts by GetWorstMainChunk over the
        -- modified-fee ordering (txmempool.cpp:861-911).  So an operator-
        -- prioritised low-base-fee tx is protected from eviction in place.
        -- No-descendant case: the entry's own modified fee drives the rate.
        -- Multi-descendant case keeps raw descendant_fees aggregation (delta
        -- propagation across the cluster is the W106 G8 follow-up, not built
        -- here).  Un-prioritised entries (modified_fee == fee) pick identically.
        local own_fee = entry.modified_fee or entry.fee
        local rate = (own_fee + entry.descendant_fees) / total_vsize
        if rate < worst_rate then
          worst_rate = rate
          worst_hex = hex
        end
      end
    end
    if not worst_hex then break end

    -- Gate 2: bump rolling minimum fee before removing.
    -- evicted_rate is in sat/vB; convert to sat/kvB for the rolling tracker.
    -- Add INCREMENTAL_RELAY_FEE so evicted txs cannot immediately re-enter.
    -- Reference: txmempool.cpp:877-878 (removed += incremental_relay_feerate;
    --             trackPackageRemoved(removed)).
    local evicted_rate_kvb = math.floor(worst_rate * 1000)  -- sat/vB -> sat/kvB
    self:track_package_removed(evicted_rate_kvb + M.INCREMENTAL_RELAY_FEE)

    self:remove_transaction(worst_hex, "evicted")
  end
end

--------------------------------------------------------------------------------
-- Mempool Queries
--------------------------------------------------------------------------------

--- Get all entries sorted by ancestor fee rate for block template construction.
-- Higher ancestor fee rate = better candidate for inclusion.
--
-- FIX-72 (mirrors rustoshi get_sorted_for_mining, mempool.rs:2379-2404): the
-- entry's OWN fee contribution to its mining rank is its modified fee
-- (base + prioritisetransaction delta = entry.modified_fee, kept in sync by
-- prioritise_transaction / accept_transaction), NOT the raw base fee.  Core
-- (txmempool.cpp:636-643 UpdateModifiedFee + the mining selector reading
-- GetModifiedFee) ranks an operator-prioritised tx by its modified fee in
-- place, so a low-base-fee tx bumped above its peers surfaces ahead of them.
--
-- For a tx with no further in-mempool ancestors the rank is purely its own
-- modified feerate.  For a multi-ancestor tx the ancestor aggregation still
-- folds in raw ancestor_fees — delta propagation across the ancestor set is an
-- ACCEPTED separate follow-up (rustoshi W106 G8), deliberately NOT built here.
-- Un-prioritised txs (delta 0 ⇒ modified_fee == fee) sort byte-identically to
-- the prior base-fee behaviour.
-- @return table: Array of mempool entries sorted by ancestor fee rate (descending)
function Mempool:get_sorted_entries()
  local sorted = {}
  for _, entry in pairs(self.entries) do
    sorted[#sorted + 1] = entry
  end
  local function mining_rate(e)
    -- Multi-ancestor: keep raw ancestor aggregation (W106 G8 deferred).
    if e.ancestor_count and e.ancestor_count > 1 then
      return (e.fee + e.ancestor_fees) / (e.vsize + e.ancestor_size)
    end
    -- No further ancestors: rank by this entry's own modified fee.
    local mfee = e.modified_fee or e.fee
    return (mfee + e.ancestor_fees) / (e.vsize + e.ancestor_size)
  end
  table.sort(sorted, function(a, b)
    return mining_rate(a) > mining_rate(b)
  end)
  return sorted
end

--- Get mempool statistics.
-- mempoolminfee returns the effective minimum feerate in sat/kvB:
-- max(min_relay_fee, get_min_fee()) — the rolling minimum includes the
-- post-trim bump and decays over time (Bitcoin Core getmempoolinfo field).
-- @return table: Mempool info
function Mempool:get_info()
  local rolling_min = self:get_min_fee()  -- sat/kvB, may be 0
  local effective_min = math.max(self.min_relay_fee, rolling_min)
  return {
    size = self.tx_count,
    bytes = self.total_size,
    usage = self.total_size,
    maxmempool = self.max_size,
    mempoolminfee = effective_min,
    -- FIX-68 (W120 BUG-9): Honest fullrbf reporting — reflects the actual
    -- mempool setting, not a hardcoded `true`.  Operator can toggle via
    -- --mempool-fullrbf=0 / config.fullrbf=false.  Bitcoin Core v28+ hardcodes
    -- `true` in src/rpc/mempool.cpp:1058 because cluster-mempool removed
    -- Rule 1 entirely; lunarblock retains the toggle for backward-compat
    -- with operators who want strict opt-in.  See M.DEFAULT_MEMPOOL_FULL_RBF.
    fullrbf = self.fullrbf,
  }
end

-- FIX-68 (W120 BUG-9): BIP-125 "bip125-replaceable" walker for any tx.
--
-- Bitcoin Core's policy/rbf.cpp IsRBFOptIn(tx, pool) — used by rpc/mempool.cpp
-- (entryToJSON) and rpc/rawtransaction.cpp — first checks the tx itself,
-- and if it doesn't signal, walks its in-mempool ancestors.  Lunarblock's
-- existing Mempool:is_replaceable(txid_hex) does the right walk for mempool
-- entries; this helper extends the contract to also accept a raw tx for the
-- "is this incoming tx replaceable?" path and matches Core's 3-state semantics
-- collapsed to bool (REPLACEABLE_BIP125 => true; UNKNOWN/FINAL => false).
--
-- For txs in the mempool, this is identical to is_replaceable.
-- For txs not in the mempool, we still inspect direct ancestors via the
-- mempool entries (Core's IsRBFOptInEmptyMempool returns UNKNOWN here, but
-- we mirror the wallet-side hint: walk any unconfirmed parents we know
-- about so the RPC field still reflects the actual replaceability state.)
--
-- Reference: bitcoin-core/src/policy/rbf.cpp:24-50.
function Mempool:bip125_replaceable_tx(tx)
  -- 1. Tx itself signals?
  if M.signals_rbf(tx) then return true end
  -- 2. Any unconfirmed ancestor signals?  Walk via prev_out → mempool entry.
  --    Use a BFS over the unconfirmed ancestor graph so we cover transitive
  --    parents, not just direct ones (matches CalculateMemPoolAncestors).
  local seen = {}
  local stack = {}
  for _, inp in ipairs(tx.inputs) do
    local prev_hex = types.hash256_hex(inp.prev_out.hash)
    if not seen[prev_hex] then
      seen[prev_hex] = true
      stack[#stack + 1] = prev_hex
    end
  end
  while #stack > 0 do
    local hex = table.remove(stack)
    local entry = self.entries[hex]
    if entry then
      if M.signals_rbf(entry.tx) then return true end
      for _, inp in ipairs(entry.tx.inputs) do
        local prev_hex = types.hash256_hex(inp.prev_out.hash)
        if not seen[prev_hex] then
          seen[prev_hex] = true
          stack[#stack + 1] = prev_hex
        end
      end
    end
  end
  return false
end

--- Get all transaction ids in the mempool.
-- @return table: Array of txid hex strings
function Mempool:get_raw_mempool()
  local txids = {}
  for hex in pairs(self.entries) do
    txids[#txids + 1] = hex
  end
  return txids
end

--- Get a specific mempool entry.
-- @param txid_hex string: Transaction id as hex string
-- @return table: Mempool entry or nil
function Mempool:get_entry(txid_hex)
  return self.entries[txid_hex]
end

--- Check if a transaction is in the mempool.
-- @param txid_hex string: Transaction id as hex string
-- @return boolean: True if transaction is in mempool
function Mempool:has(txid_hex)
  return self.entries[txid_hex] ~= nil
end

--------------------------------------------------------------------------------
-- Prioritisation (mapDeltas) — prioritisetransaction / getprioritisedtransactions
--
-- Mirrors Bitcoin Core's CTxMemPool::{PrioritiseTransaction, ApplyDelta,
-- ClearPrioritisation, GetPrioritisedTransactions} (txmempool.cpp:630-687) and
-- CTxMemPoolEntry::GetModifiedFee (kernel/mempool_entry.h:120).  A delta is a
-- signed satoshi amount added to a tx's base fee when ranking it for mining;
-- the fee is not actually paid.  Keys are display-order txid_hex, identical to
-- the keys used by self.entries and the mempool.dat persist layer.
--------------------------------------------------------------------------------

-- int64 bounds, used to clamp accumulated deltas the way Core's
-- SaturatingAdd<int64_t> does (util/overflow.h).  Satoshi-scale deltas are far
-- inside LuaJIT's 2^53 exact-integer range, so the double arithmetic below is
-- lossless in practice; the clamp only matters for pathological inputs.
local INT64_MAX = 9223372036854775807
local INT64_MIN = -9223372036854775808

local function saturating_add_i64(a, b)
  local sum = a + b
  if sum > INT64_MAX then return INT64_MAX end
  if sum < INT64_MIN then return INT64_MIN end
  return sum
end

--- Apply a fee-priority delta for a transaction (Core PrioritiseTransaction).
-- Accumulates ONTO any existing delta (saturating int64 add).  When the
-- resulting accumulated delta becomes 0 the key is erased from map_deltas
-- (Core txmempool.cpp:644-646).  When the tx is currently in the mempool, the
-- entry's modified fee is updated in lockstep so getmempoolentry / mining see
-- the new ranking immediately (Core UpdateModifiedFee, txmempool.cpp:640).
-- The delta is stored even for a txid NOT in the mempool, so it applies if the
-- tx later arrives.
-- @param txid_hex string: display-order txid hex (64 chars)
-- @param delta_sats number: satoshis to add (may be negative)
function Mempool:prioritise_transaction(txid_hex, delta_sats)
  delta_sats = delta_sats or 0
  local current = self.map_deltas[txid_hex] or 0
  local new_delta = saturating_add_i64(current, delta_sats)
  -- Update the in-mempool entry's modified fee (if present) by the increment
  -- applied this call, exactly like Core's it->UpdateModifiedFee(nFeeDelta).
  local entry = self.entries[txid_hex]
  if entry then
    entry.modified_fee = saturating_add_i64(entry.modified_fee or entry.fee, delta_sats)
  end
  if new_delta == 0 then
    self.map_deltas[txid_hex] = nil
  else
    self.map_deltas[txid_hex] = new_delta
  end
end

--- Return entry.fee + map_deltas[txid] (Core CTxMemPoolEntry::GetModifiedFee).
-- Accepts either a display-order txid_hex (string) or a mempool entry table.
-- For a txid not in the mempool, returns the bare stored delta (0 if none).
-- @param txid_or_entry string|table
-- @return number: modified fee in satoshis
function Mempool:get_modified_fee(txid_or_entry)
  local entry, txid_hex
  if type(txid_or_entry) == "string" then
    txid_hex = txid_or_entry
    entry = self.entries[txid_hex]
  else
    entry = txid_or_entry
    txid_hex = entry and entry.txid and types.hash256_hex(entry.txid) or nil
  end
  local base = entry and entry.fee or 0
  local delta = (txid_hex and self.map_deltas[txid_hex]) or 0
  return base + delta
end

--- Drop a txid's stored delta (Core ClearPrioritisation, txmempool.cpp:667).
-- Called when a tx confirms in / is conflicted out by a block so its delta is
-- not re-applied to an unrelated future tx that reuses the txid.
-- @param txid_hex string
function Mempool:clear_prioritisation(txid_hex)
  self.map_deltas[txid_hex] = nil
end

--- Per-tx delta info for getprioritisedtransactions (Core GetPrioritisedTransactions).
-- @return array of { txid_hex, fee_delta, in_mempool, modified_fee|nil }
function Mempool:get_prioritised_transactions()
  local result = {}
  for txid_hex, delta in pairs(self.map_deltas) do
    local entry = self.entries[txid_hex]
    local in_mempool = entry ~= nil
    result[#result + 1] = {
      txid_hex = txid_hex,
      fee_delta = delta,
      in_mempool = in_mempool,
      -- Only meaningful when in mempool (Core sets modified_fee only then).
      modified_fee = in_mempool and (entry.fee + delta) or nil,
    }
  end
  return result
end

--- Check if a transaction is in the mempool by wtxid.
-- Used by the MSG_WTX inv handler (BIP-339): the hash in a MSG_WTX inv is
-- the wtxid, not the txid.  For non-segwit txs wtxid == txid so has()
-- suffices; for segwit we must scan the wtxid field of each entry.
-- @param wtxid_hex string: Witness transaction id as hex string
-- @return boolean: True if transaction is in mempool
function Mempool:has_wtxid(wtxid_hex)
  -- Fast path: for non-segwit txs txid == wtxid, so check txid index first.
  if self.entries[wtxid_hex] then return true end
  -- Slow path: scan for segwit transactions whose wtxid matches.
  for _, entry in pairs(self.entries) do
    if entry.wtxid then
      local entry_wtxid_hex = types.hash256_hex(entry.wtxid)
      if entry_wtxid_hex == wtxid_hex then return true end
    end
  end
  return false
end

--- Iterate over all mempool transactions yielding (wtxid_bytes, tx) pairs.
-- Used by compact_block.lua PartiallyDownloadedBlock:init to match short IDs
-- against mempool transactions (BIP-152 step 4).  W112 BUG-4 fix: this method
-- was absent, causing compact_block.lua to silently skip mempool lookup and
-- always fall back to getblocktxn round-trips.
--
-- Returns a stateful iterator suitable for "for wtxid, tx in mempool:iter_by_wtxid() do".
-- @return function, table, nil: standard Lua iterator triple
function Mempool:iter_by_wtxid()
  local _validation = nil  -- lazy-require to avoid circular dependency
  local entries = self.entries
  -- Collect txid keys once so we get a stable iteration.
  local keys = {}
  for k in pairs(entries) do keys[#keys + 1] = k end
  local idx = 0
  return function()
    idx = idx + 1
    local entry = entries[keys[idx]]
    if entry == nil then return nil end
    if entry.wtxid then
      return entry.wtxid.bytes, entry.tx
    else
      -- Non-segwit: wtxid == txid; compute on demand.
      if not _validation then _validation = require("lunarblock.validation") end
      local wtxid = _validation.compute_wtxid(entry.tx)
      return wtxid.bytes, entry.tx
    end
  end
end

--- Check descendant limits for a potential new child transaction.
-- @param parent_txid_hex string: Parent transaction id
-- @param child_vsize number: Virtual size of the potential child
-- @return boolean: True if limits would be satisfied
function Mempool:check_descendant_limits(parent_txid_hex, child_vsize)
  local parent = self.entries[parent_txid_hex]
  if not parent then return true end  -- Parent not in mempool

  local new_desc_count = parent.descendant_count + 1
  local new_desc_size = parent.descendant_size + child_vsize

  if new_desc_count > M.MAX_DESCENDANTS then
    return false
  end
  if new_desc_size > M.MAX_DESCENDANT_SIZE then
    return false
  end
  return true
end

--- Check if a mempool transaction is replaceable (BIP125).
-- A transaction is replaceable if it or any of its unconfirmed ancestors signal RBF.
-- @param txid_hex string: Transaction id as hex string
-- @return boolean: True if transaction is replaceable
function Mempool:is_replaceable(txid_hex)
  local entry = self.entries[txid_hex]
  if not entry then return false end

  -- Check if the transaction itself signals RBF
  if M.signals_rbf(entry.tx) then
    return true
  end

  -- Check if any ancestor signals RBF
  for anc_hex in pairs(entry.ancestors) do
    local anc_entry = self.entries[anc_hex]
    if anc_entry and M.signals_rbf(anc_entry.tx) then
      return true
    end
  end

  return false
end

--------------------------------------------------------------------------------
-- Package Validation (BIP 331)
--------------------------------------------------------------------------------

--- Check if a package is topologically sorted (parents before children).
-- @param txns table: Array of transactions
-- @return boolean, string|nil: success, error message
function M.is_topo_sorted_package(txns)
  -- Build a set of txids that appear later in the package
  local later_txids = {}
  for _, tx in ipairs(txns) do
    local txid = validation.compute_txid(tx)
    local txid_hex = types.hash256_hex(txid)
    later_txids[txid_hex] = true
  end

  -- Check each transaction's inputs
  for _, tx in ipairs(txns) do
    local txid = validation.compute_txid(tx)
    local txid_hex = types.hash256_hex(txid)

    for _, inp in ipairs(tx.inputs) do
      local prev_hex = types.hash256_hex(inp.prev_out.hash)
      -- If the parent appears later in the package, order is wrong
      if later_txids[prev_hex] then
        return false, "package not topologically sorted"
      end
    end

    -- Remove this tx from later_txids as we process it
    later_txids[txid_hex] = nil
  end

  return true
end

--- Check if package transactions have conflicting inputs.
-- @param txns table: Array of transactions
-- @return boolean, string|nil: success, error message
function M.is_consistent_package(txns)
  local inputs_seen = {}  -- outpoint_key -> true

  for _, tx in ipairs(txns) do
    -- Empty vin is not allowed (unconfirmed tx requirement)
    if #tx.inputs == 0 then
      return false, "transaction has no inputs"
    end

    for _, inp in ipairs(tx.inputs) do
      local outpoint_key = M.outpoint_key(inp.prev_out.hash, inp.prev_out.index)
      if inputs_seen[outpoint_key] then
        return false, "conflict in package"
      end
    end

    -- Add all inputs from this tx at once
    for _, inp in ipairs(tx.inputs) do
      local outpoint_key = M.outpoint_key(inp.prev_out.hash, inp.prev_out.index)
      inputs_seen[outpoint_key] = true
    end
  end

  return true
end

--- Check if a package is well-formed (context-free checks).
-- @param txns table: Array of transactions
-- @return boolean, string|nil: success, error message
function M.is_well_formed_package(txns)
  -- Check package count
  if #txns > M.MAX_PACKAGE_COUNT then
    return false, "package-too-many-transactions"
  end

  if #txns == 0 then
    return false, "empty package"
  end

  -- Check for duplicate transactions and compute total weight
  local seen_txids = {}
  local total_weight = 0

  for _, tx in ipairs(txns) do
    local txid = validation.compute_txid(tx)
    local txid_hex = types.hash256_hex(txid)

    if seen_txids[txid_hex] then
      return false, "package-contains-duplicates"
    end
    seen_txids[txid_hex] = true

    total_weight = total_weight + validation.get_tx_weight(tx)
  end

  -- Check total weight (only if > 1 tx, otherwise individual tx check applies)
  if #txns > 1 and total_weight > M.MAX_PACKAGE_WEIGHT then
    return false, "package-too-large"
  end

  -- Check topological sorting
  local ok, err = M.is_topo_sorted_package(txns)
  if not ok then
    return false, "package-not-sorted"
  end

  -- Check for conflicts (no tx spends same input as another)
  ok, err = M.is_consistent_package(txns)
  if not ok then
    return false, err
  end

  return true
end

--- Check if a package is child-with-parents (last tx spends outputs of all others).
-- @param txns table: Array of transactions (sorted, child last)
-- @return boolean: true if package is child-with-parents topology
function M.is_child_with_parents(txns)
  if #txns < 2 then
    return false
  end

  -- The child is the last transaction
  local child = txns[#txns]

  -- Collect the txids of all inputs of the child
  local input_txids = {}
  for _, inp in ipairs(child.inputs) do
    local prev_hex = types.hash256_hex(inp.prev_out.hash)
    input_txids[prev_hex] = true
  end

  -- Every parent (all but the last tx) must be an input of the child
  for i = 1, #txns - 1 do
    local parent = txns[i]
    local parent_txid = validation.compute_txid(parent)
    local parent_hex = types.hash256_hex(parent_txid)
    if not input_txids[parent_hex] then
      return false
    end
  end

  return true
end

--- Check if a package is child-with-parents *tree* topology.
-- Extends is_child_with_parents by additionally verifying that no parent
-- depends on another parent in the same package.  Mirrors Core's
-- IsChildWithParentsTree (policy/packages.cpp).
-- @param txns table: Array of transactions (sorted, child last)
-- @return boolean: true iff is_child_with_parents AND no parent spends another parent
function M.is_child_with_parents_tree(txns)
  if not M.is_child_with_parents(txns) then
    return false
  end

  -- Build set of parent txids (all but the last tx)
  local parent_txids = {}
  for i = 1, #txns - 1 do
    local parent = txns[i]
    local parent_txid = validation.compute_txid(parent)
    local parent_hex = types.hash256_hex(parent_txid)
    parent_txids[parent_hex] = true
  end

  -- Each parent must not spend an output of another parent
  for i = 1, #txns - 1 do
    local parent = txns[i]
    for _, inp in ipairs(parent.inputs) do
      local prev_hex = types.hash256_hex(inp.prev_out.hash)
      if parent_txids[prev_hex] then
        return false
      end
    end
  end

  return true
end

--- Calculate package fee rate.
-- @param txns table: Array of transactions
-- @param fees table: Array of fees for each transaction (parallel to txns)
-- @return number: Package fee rate in sat/vB
function M.calculate_package_fee_rate(txns, fees)
  local total_fees = 0
  local total_vsize = 0

  for i, tx in ipairs(txns) do
    total_fees = total_fees + fees[i]
    local weight = validation.get_tx_weight(tx)
    total_vsize = total_vsize + math.ceil(weight / consensus.WITNESS_SCALE_FACTOR)
  end

  if total_vsize == 0 then
    return 0
  end

  return total_fees / total_vsize
end

--- Compute package hash (SHA256 of sorted concatenated wtxids).
-- @param txns table: Array of transactions
-- @return string: 32-byte package hash
function M.compute_package_hash(txns)
  local crypto = require("lunarblock.crypto")

  -- Collect wtxids
  local wtxids = {}
  for _, tx in ipairs(txns) do
    local wtxid = validation.compute_wtxid(tx)
    wtxids[#wtxids + 1] = wtxid.bytes
  end

  -- Sort wtxids (comparing as big-endian numbers, but stored little-endian)
  -- Bitcoin Core compares in reverse byte order (most significant byte first)
  table.sort(wtxids, function(a, b)
    -- Compare bytes from end to start (reverse order for little-endian)
    for i = 32, 1, -1 do
      local ba = a:byte(i)
      local bb = b:byte(i)
      if ba ~= bb then
        return ba < bb
      end
    end
    return false  -- Equal
  end)

  -- Hash the concatenated wtxids
  return crypto.sha256(table.concat(wtxids))
end

--- Accept a package of transactions into the mempool.
-- Implements CPFP: a child with high fee can pay for low-fee parents.
-- @param txns table: Array of transactions (topologically sorted, parents first)
-- @param test_accept boolean: When true, run full validation but skip mempool insertion
--   (mirrors Core's m_test_accept — no state is mutated when this flag is set).
-- @return boolean, table|string: success, {txid_hexes, package_fee_rate} or error message
function Mempool:accept_package(txns, test_accept)
  -- 1. Well-formed package check
  local ok, err = M.is_well_formed_package(txns)
  if not ok then
    return false, err
  end

  -- 2. Basic validation for each transaction
  for i, tx in ipairs(txns) do
    local pcall_ok, check_ok, is_coinbase = pcall(validation.check_transaction, tx)
    if not pcall_ok or not check_ok then
      return false, "invalid transaction at index " .. i
    end
    if is_coinbase then
      return false, "coinbase transactions not accepted"
    end
    -- IsStandardTx weight cap applies to each tx individually within a
    -- package (Bitcoin Core: policy/policy.cpp:111-115).
    local tx_weight_pkg = validation.get_tx_weight(tx)
    if tx_weight_pkg > M.MAX_STANDARD_TX_WEIGHT then
      return false, string.format("tx-size: weight %d exceeds %d at index %d",
        tx_weight_pkg, M.MAX_STANDARD_TX_WEIGHT, i)
    end
  end

  -- 3. Build map of package txids for intra-package dependency resolution
  local package_txid_to_idx = {}  -- txid_hex -> index in txns
  local package_txid_to_tx = {}   -- txid_hex -> tx
  for i, tx in ipairs(txns) do
    local txid = validation.compute_txid(tx)
    local txid_hex = types.hash256_hex(txid)
    package_txid_to_idx[txid_hex] = i
    package_txid_to_tx[txid_hex] = tx
  end

  -- 4. Calculate fees for each transaction
  local fees = {}
  local total_fees = 0
  local total_vsize = 0

  for i, tx in ipairs(txns) do
    local input_total = 0
    local missing_inputs = false

    for _, inp in ipairs(tx.inputs) do
      local outpoint_key = M.outpoint_key(inp.prev_out.hash, inp.prev_out.index)
      local prev_hex = types.hash256_hex(inp.prev_out.hash)

      -- Check for conflicts with existing mempool transactions
      local existing_spender = self.outpoint_to_tx[outpoint_key]
      if existing_spender and not package_txid_to_idx[existing_spender] then
        return false, "conflict with existing mempool tx"
      end

      -- Look up UTXO (chain state, mempool, or intra-package)
      local utxo = self.chain_state.coin_view:get(inp.prev_out.hash, inp.prev_out.index)

      if not utxo then
        -- Check mempool parent
        local parent_entry = self.entries[prev_hex]
        if parent_entry and inp.prev_out.index < #parent_entry.tx.outputs then
          local out = parent_entry.tx.outputs[inp.prev_out.index + 1]
          utxo = {
            value = out.value,
            script_pubkey = out.script_pubkey,
            height = parent_entry.height,
            is_coinbase = false,
          }
        end
      end

      if not utxo then
        -- Check intra-package parent
        local parent_tx = package_txid_to_tx[prev_hex]
        if parent_tx and inp.prev_out.index < #parent_tx.outputs then
          local out = parent_tx.outputs[inp.prev_out.index + 1]
          utxo = {
            value = out.value,
            script_pubkey = out.script_pubkey,
            height = self.chain_state.tip_height,
            is_coinbase = false,
          }
        end
      end

      if not utxo then
        missing_inputs = true
        break
      end

      input_total = input_total + utxo.value

      -- Coinbase maturity check
      if utxo.is_coinbase then
        if self.chain_state.tip_height - utxo.height < consensus.COINBASE_MATURITY then
          return false, "spending immature coinbase"
        end
      end
    end

    if missing_inputs then
      return false, "missing inputs for transaction at index " .. i
    end

    -- Calculate output total
    local output_total = 0
    for _, out in ipairs(tx.outputs) do
      output_total = output_total + out.value
    end

    local fee = input_total - output_total
    if fee < 0 then
      return false, "outputs exceed inputs at index " .. i
    end

    fees[i] = fee
    total_fees = total_fees + fee

    local weight = validation.get_tx_weight(tx)
    local vsize = math.ceil(weight / consensus.WITNESS_SCALE_FACTOR)
    total_vsize = total_vsize + vsize
  end

  -- 5. Calculate package fee rate (sat/vB)
  local package_fee_rate = total_fees / total_vsize
  local package_fee_rate_per_kb = package_fee_rate * 1000

  -- 6. Check package fee rate meets minimum relay fee
  if package_fee_rate_per_kb < self.min_relay_fee then
    return false, string.format("package fee rate too low: %.2f < %d sat/KB",
      package_fee_rate_per_kb, self.min_relay_fee)
  end

  -- 7. Accept each transaction into the mempool by routing it through the
  --    SAME single-tx admission pipeline (accept_transaction) the P2P/RPC
  --    single-tx path uses.  This is the DoS fix: the previous inline loop
  --    inserted entries directly into self.entries after running only
  --    check_transaction + a per-tx weight cap, silently bypassing every
  --    other PreCheck — IsStandardTx (version/dust/scriptSig/scriptPubKey),
  --    IsWitnessStandard, ValidateInputsStandardness, sigop cap, anchor
  --    policy, BIP-68 sequence locks, TRUC inheritance, and PolicyScriptChecks
  --    (input-script verification).  An attacker could smuggle non-standard /
  --    invalid-script / TRUC-violating txs into the mempool (and thus into
  --    relay) by wrapping them in a submitpackage call.  Core runs full
  --    PreChecks for every package member (validation.cpp
  --    AcceptMultipleTransactionsInternal:1447-1449 + PolicyScriptChecks:1538);
  --    we now do the same.  Members are admitted in package (topological)
  --    order so an intra-package parent is already in self.entries by the time
  --    its child resolves its inputs.  The per-tx fee-floor gates are bypassed
  --    via {package_member=true} because the package aggregate feerate was
  --    already validated in step 6 (CPFP semantics); all other gates run.
  local accepted_txids = {}
  -- Track which members WE inserted (for test_accept rollback and for undo on
  -- a mid-package rejection).  Reverse order on undo so children come out
  -- before parents.
  local inserted = {}

  local function undo_inserted()
    for k = #inserted, 1, -1 do
      self:remove_transaction(inserted[k], "package-rollback")
    end
  end

  for i, tx in ipairs(txns) do
    local txid = validation.compute_txid(tx)
    local txid_hex = types.hash256_hex(txid)

    -- Skip if already in mempool (Core: already-in-mempool members are not
    -- re-validated; they count as part of the package).
    if self.entries[txid_hex] then
      accepted_txids[#accepted_txids + 1] = txid_hex
    else
      -- allow_rbf=false: a package member that conflicts with an existing
      -- mempool tx is a package error, not a silent RBF (matches the original
      -- step-4 "conflict with existing mempool tx" reject).  package_member
      -- bypasses ONLY the per-tx fee floor.
      local ok_add, txid_or_err = self:accept_transaction(tx, false,
        { package_member = true })
      if not ok_add then
        -- Roll back any members we already inserted so the package is atomic.
        undo_inserted()
        return false, string.format("%s (package tx at index %d)",
          tostring(txid_or_err), i)
      end
      inserted[#inserted + 1] = txid_or_err
      accepted_txids[#accepted_txids + 1] = txid_or_err
    end
  end

  -- 8. test_accept (dry-run): roll back everything we inserted so the mempool
  --    is left unchanged, mirroring Core's m_test_accept early-return after
  --    the checks pass.  Snapshot/restore the rolling-fee state so the dry-run
  --    is fully side-effect-free.  accept_transaction already ran expire()/
  --    trim() per member on the real path, so no extra trim is needed here.
  if test_accept then
    local saved_rolling = self.rolling_minimum_fee_rate
    local saved_last_update = self.last_rolling_fee_update
    local saved_since_bump = self.block_since_last_rolling_fee_bump
    undo_inserted()
    self.rolling_minimum_fee_rate = saved_rolling
    self.last_rolling_fee_update = saved_last_update
    self.block_since_last_rolling_fee_bump = saved_since_bump
  end

  return true, {
    txids = accepted_txids,
    fees = fees,
    package_fee_rate = package_fee_rate,
    total_fees = total_fees,
    total_vsize = total_vsize,
  }
end

--- Compute the set of missing-parent txids for `tx` against the current
-- chain + mempool. Helper used by the orphan-pool wiring on the
-- "missing inputs" reject path so the orphan-pool entry knows which
-- parent arrivals should re-trigger evaluation.  Returns a set
-- {parent_txid_hex=true} or an empty table.
function Mempool:missing_parents_for(tx)
  local missing = {}
  if not tx or not tx.inputs then return missing end
  for _, inp in ipairs(tx.inputs) do
    local utxo = self.chain_state.coin_view:get(inp.prev_out.hash, inp.prev_out.index)
    if not utxo then
      local prev_txid_hex = types.hash256_hex(inp.prev_out.hash)
      local parent_entry = self.entries[prev_txid_hex]
      if not (parent_entry and inp.prev_out.index < #parent_entry.tx.outputs) then
        missing[prev_txid_hex] = true
      end
    end
  end
  return missing
end

--------------------------------------------------------------------------------
-- Orphan transaction pool (BIP-37 / Core txorphanage parity, simplified).
--
-- A transaction whose parent is not yet in the UTXO set or mempool is
-- "orphan": it cannot be validated until its missing parent arrives.  Core
-- buffers up to MAX_ORPHAN_TRANSACTIONS=100 such txs in
-- bitcoin-core/src/node/txorphanage.cpp; on parent-tx arrival the children
-- are re-checked.  We mirror the headline limits — total cap, per-tx size
-- cap, per-peer cap, oldest-first eviction — without the Core 31.99
-- "latency-score" / wtxid-announcer multi-peer bookkeeping.
--
-- The pool is intentionally a separate object (not a Mempool method): it
-- has independent lifetimes (Mempool tracks accepted txs; OrphanPool tracks
-- rejected-with-missing-parent ones), independent eviction, and the only
-- bridge is `attempt_resolve_for_tx` which the p2p tx-handler calls on
-- accept of a parent.  Keeping the surfaces separate avoids touching the
-- 1400-line accept_transaction pipeline and keeps the live-fragility blast
-- radius minimal.
--
-- Memory bounds (Core parity):
--   MAX_ORPHAN_TRANSACTIONS = 100   (bitcoin-core/src/node/txorphanage.cpp)
--   MAX_ORPHAN_TX_SIZE      = 100000 bytes / tx  (per-tx serialized cap;
--                              maps to Core's MAX_STANDARD_TX_WEIGHT/4)
--   MAX_ORPHANS_PER_PEER    = 100   (per-peer cap; in Core a peer's share
--                              is implicitly bounded by the global cap +
--                              reservation logic — we use a flat 100 to
--                              keep the bookkeeping simple)
--   ORPHAN_TX_EXPIRE_TIME   = 300 seconds (5 min) — stale orphans whose
--                              parent chain never arrived are evicted by
--                              expire_stale().  Mirror of the constant used
--                              in Core before the weight-based rewrite
--                              (txorphanage.cpp, Core PR #22503).
--------------------------------------------------------------------------------

M.MAX_ORPHAN_TRANSACTIONS = 100
M.MAX_ORPHAN_TX_SIZE      = 100000
M.MAX_ORPHANS_PER_PEER    = 100
M.ORPHAN_TX_EXPIRE_TIME   = 300  -- seconds; Core txorphanage.h (pre-weight-rewrite)

local OrphanPool = {}
OrphanPool.__index = OrphanPool
M.OrphanPool = OrphanPool

--- Create a new orphan tx pool.
-- @param config table|nil: optional {max_orphans, max_per_peer, max_tx_size}
-- @return OrphanPool
function M.new_orphan_pool(config)
  local self = setmetatable({}, OrphanPool)
  self.max_orphans  = (config and config.max_orphans)  or M.MAX_ORPHAN_TRANSACTIONS
  self.max_per_peer = (config and config.max_per_peer) or M.MAX_ORPHANS_PER_PEER
  self.max_tx_size  = (config and config.max_tx_size)  or M.MAX_ORPHAN_TX_SIZE

  -- Primary storage keyed by wtxid_hex (BIP-339 / Core txorphanage.cpp).
  -- Secondary txid→wtxid index allows O(1) child lookup: missing_parents
  -- carries txid_hex values (from input prevout hashes), so we need to
  -- map those back to the wtxid primary key.
  self.entries      = {}  -- wtxid_hex -> {tx, txid_hex, peer_id, time, size, missing_parents={txid_hex=true,...}}
  self.txid_to_wtxid = {} -- txid_hex  -> wtxid_hex  (secondary index for dedup + child resolution)
  self.count   = 0
  -- Per-peer announcement counts (peer_id -> count).
  self.by_peer = {}
  -- Insertion order list for oldest-first eviction.  We accept the O(n)
  -- shift on eviction because n <= max_orphans (100 by default).
  self.order   = {}    -- ordered list of wtxid_hex
  return self
end

--- Try to add an orphan transaction.
-- Caller must have already determined the tx has missing inputs and the
-- missing-parent txid set.
-- Primary key is wtxid_hex (BIP-339): two txids with the same txid but
-- different witnesses are distinct orphans.  A secondary txid→wtxid map
-- enables O(1) dedup by txid and child-resolution lookups.
-- @param tx table: the orphan transaction
-- @param wtxid_hex string: hex-encoded wtxid of the orphan (primary key)
-- @param peer_id any: peer-keyed identifier (e.g. "ip:port" or numeric id)
-- @param missing_parents table|nil: set of {parent_txid_hex=true} (optional)
-- @return boolean, string|nil: true on accept; false + reason on reject
function OrphanPool:add(tx, wtxid_hex, peer_id, missing_parents)
  if type(tx) ~= "table" or type(wtxid_hex) ~= "string" then
    return false, "bad-orphan-args"
  end
  if self.entries[wtxid_hex] then
    return false, "already-have-orphan"
  end
  -- Compute txid for the secondary index (needed for child resolution via
  -- missing_parents which carries txid_hex values from input prevouts).
  local ok_txid, txid_raw = pcall(validation.compute_txid, tx)
  local txid_hex = (ok_txid and txid_raw) and types.hash256_hex(txid_raw) or wtxid_hex
  -- Reject if a different witness variant of the same txid is already present
  -- (txid-malleation: same inputs/outputs, different witness).
  if self.txid_to_wtxid[txid_hex] then
    return false, "already-have-orphan"
  end

  -- Per-tx size cap. We use the witness-included serialization since that
  -- is what the wire delivered and what Core's MAX_STANDARD_TX_WEIGHT/4
  -- bound effectively constrains.
  local ok_ser, ser = pcall(serialize.serialize_transaction, tx, true)
  if not ok_ser or type(ser) ~= "string" then
    return false, "bad-orphan-serialize"
  end
  local size = #ser
  if size > self.max_tx_size then
    return false, "orphan-too-large"
  end

  -- Per-peer cap.  Reject the new orphan rather than evicting from the
  -- offending peer — Core does symmetric eviction but a flat reject is
  -- safer for our simpler model and a misbehaving peer just gets its 101st
  -- orphan dropped on the floor.
  local pid = peer_id or "anonymous"
  if (self.by_peer[pid] or 0) >= self.max_per_peer then
    return false, "orphan-per-peer-cap"
  end

  -- Global cap: evict oldest first to make room.
  while self.count >= self.max_orphans do
    if not self:_evict_oldest() then break end
  end
  if self.count >= self.max_orphans then
    -- Defensive: should not happen unless eviction is broken.
    return false, "orphan-cap-evict-failed"
  end

  self.entries[wtxid_hex] = {
    tx              = tx,
    txid_hex        = txid_hex,
    peer_id         = pid,
    time            = os.time(),
    size            = size,
    missing_parents = missing_parents or {},
  }
  self.txid_to_wtxid[txid_hex] = wtxid_hex
  self.count = self.count + 1
  self.by_peer[pid] = (self.by_peer[pid] or 0) + 1
  self.order[#self.order + 1] = wtxid_hex
  return true
end

--- Evict the oldest orphan. Returns true if one was evicted.
function OrphanPool:_evict_oldest()
  local victim_wtxid = self.order[1]
  if not victim_wtxid then return false end
  -- Shift order list (O(n) but n <= 100).
  table.remove(self.order, 1)
  return self:_remove_internal(victim_wtxid) ~= nil
end

--- Internal removal (does not touch self.order — caller must).
-- @param wtxid_hex string: primary key
-- @return entry|nil
function OrphanPool:_remove_internal(wtxid_hex)
  local entry = self.entries[wtxid_hex]
  if not entry then return nil end
  self.entries[wtxid_hex] = nil
  -- Remove secondary txid→wtxid index entry.
  if entry.txid_hex then
    self.txid_to_wtxid[entry.txid_hex] = nil
  end
  self.count = self.count - 1
  local pid = entry.peer_id
  if pid then
    local n = (self.by_peer[pid] or 1) - 1
    if n <= 0 then
      self.by_peer[pid] = nil
    else
      self.by_peer[pid] = n
    end
  end
  return entry
end

--- Public: remove an orphan by wtxid_hex (primary key).
function OrphanPool:remove(wtxid_hex)
  if not self.entries[wtxid_hex] then return false end
  for i, w in ipairs(self.order) do
    if w == wtxid_hex then
      table.remove(self.order, i)
      break
    end
  end
  self:_remove_internal(wtxid_hex)
  return true
end

--- Test if the pool already has this orphan (by wtxid_hex, primary key).
function OrphanPool:has(wtxid_hex)
  return self.entries[wtxid_hex] ~= nil
end

--- Test if the pool already has an orphan with this txid_hex (secondary index).
function OrphanPool:has_by_txid(txid_hex)
  return self.txid_to_wtxid[txid_hex] ~= nil
end

--- Number of orphans currently held.
function OrphanPool:size()
  return self.count
end

--- Drop all orphans contributed by `peer_id` (e.g. on disconnect).
-- @return integer: number of orphans removed.
function OrphanPool:remove_for_peer(peer_id)
  if not peer_id or not self.by_peer[peer_id] then return 0 end
  local removed = 0
  -- Walk entries; keep order list rebuild simple (n <= 100).
  local kept = {}
  for _, wtxid_hex in ipairs(self.order) do
    local e = self.entries[wtxid_hex]
    if e and e.peer_id == peer_id then
      self:_remove_internal(wtxid_hex)
      removed = removed + 1
    else
      kept[#kept + 1] = wtxid_hex
    end
  end
  self.order = kept
  return removed
end

--- Evict orphans that have been sitting in the pool for longer than
-- ORPHAN_TX_EXPIRE_TIME seconds (default 300 s / 5 min).  Mirrors
-- Core's LimitOrphans() time-gate: orphans whose parent chain never
-- arrived within the expiry window are almost certainly for dead tx
-- chains and waste memory / inflate the available capacity for genuine
-- orphans.
--
-- @param now number|nil: current UNIX timestamp (os.time() if omitted)
-- @return integer: number of orphans evicted
function OrphanPool:expire_stale(now)
  now = now or os.time()
  local cutoff = now - (self.expire_time or M.ORPHAN_TX_EXPIRE_TIME)
  local evicted = 0
  -- Walk insertion order; collect the stale ones first to avoid
  -- mutating self.order while iterating it.
  local stale = {}
  for _, wtxid_hex in ipairs(self.order) do
    local e = self.entries[wtxid_hex]
    if e and e.time <= cutoff then
      stale[#stale + 1] = wtxid_hex
    end
  end
  for _, wtxid_hex in ipairs(stale) do
    if self:remove(wtxid_hex) then
      evicted = evicted + 1
    end
  end
  return evicted
end

--- A new tx (`parent_txid_hex`) has just been accepted to the chain or
-- mempool — find any orphans that listed it as a missing parent and
-- return them in insertion order.  Caller is expected to re-feed them
-- through `mempool:accept_transaction(...)` and remove them from the
-- pool with `pool:remove(wtxid_hex)` on either acceptance or persistent
-- rejection.
--
-- @param parent_txid_hex string: txid (not wtxid) of the newly-accepted parent
-- @return list of {tx, wtxid_hex, txid_hex, peer_id} entries
function OrphanPool:children_of(parent_txid_hex)
  local out = {}
  for _, wtxid_hex in ipairs(self.order) do
    local e = self.entries[wtxid_hex]
    if e and e.missing_parents[parent_txid_hex] then
      out[#out + 1] = {
        tx        = e.tx,
        wtxid_hex = wtxid_hex,
        txid_hex  = e.txid_hex,
        peer_id   = e.peer_id,
      }
    end
  end
  return out
end

--- On block connected: drop any orphan that names a tx in this block as
-- one of its missing parents (the parent is now spendable from the UTXO
-- set, so the orphan is either resolvable or no longer interesting).
-- The caller is responsible for re-feeding resolvable ones through
-- accept_transaction; this function only cleans the buffer.
-- @param block block: connected block
-- @return list of removed orphan entries (for caller's re-feed loop)
function OrphanPool:on_block_connected(block)
  if not block or not block.transactions then return {} end
  local resolved = {}
  for _, tx in ipairs(block.transactions) do
    local txid = validation.compute_txid(tx)
    local parent_hex = types.hash256_hex(txid)
    local children = self:children_of(parent_hex)
    for _, c in ipairs(children) do
      resolved[#resolved + 1] = c
    end
  end
  return resolved
end

return M
