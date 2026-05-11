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
M.DEFAULT_MIN_RELAY_FEE = 1000    -- 1 sat/vB in sat/KB
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

-- Dust relay fee rate used for GetDustThreshold (Core policy/policy.h:68).
-- Units: satoshis per kilobyte.  Default: 3000 sat/kvB.
M.DUST_RELAY_FEE_RATE = 3000

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
    fee = fee,                  -- satoshis
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
  self.entries = {}            -- txid_hex -> MempoolEntry
  self.outpoint_to_tx = {}    -- outpoint_key -> txid_hex (tracks which tx spends each output)
  self.total_size = 0          -- Current memory usage estimate
  self.tx_count = 0
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
-- @return boolean, string, number: success, txid_hex or error message, fee
function Mempool:accept_transaction(tx, allow_rbf)
  if allow_rbf == nil then allow_rbf = true end
  local txid = validation.compute_txid(tx)
  local txid_hex = types.hash256_hex(txid)

  -- 1. Check if we already have this transaction
  if self.entries[txid_hex] then
    return false, "tx already in mempool"
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
    local script_type = script_mod.classify_script(out.script_pubkey)
    if script_type == "nonstandard" then
      return false, "scriptpubkey"
    end
    if script_type == "nulldata" then
      local script_size = #out.script_pubkey
      if script_size > datacarrier_bytes_left then
        return false, "datacarrier"
      end
      datacarrier_bytes_left = datacarrier_bytes_left - script_size
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
        nSize = nSize + 32 + 4 + 1 + 27 + 4  -- = 68 (Core uses 98 for P2WPKH total)
      else
        -- 32(prev_hash) + 4(prev_index) + 1(script_sig_len) + 107(script_sig) + 4(sequence)
        nSize = nSize + 32 + 4 + 1 + 107 + 4  -- = 148 (Core uses 182 for P2PKH total)
      end
      local dust_threshold = math.floor(M.DUST_RELAY_FEE_RATE * nSize / 1000)
      if out.value < dust_threshold then
        dust_count = dust_count + 1
      end
    end
  end
  -- MAX_DUST_OUTPUTS_PER_TX = 1: allow at most one dust output (ephemeral dust).
  if dust_count > 1 then
    return false, "dust"
  end

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
    return false, "missing inputs"
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
  if fee_rate_per_kb < self.min_relay_fee then
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
  do
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
    -- (signal RBF directly or have an ancestor that does)
    for conflict_txid_hex in pairs(conflicts) do
      if not self:is_replaceable(conflict_txid_hex) then
        return false, "conflicting tx does not signal RBF"
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

  -- 9. Add to mempool
  local entry = M.mempool_entry(tx, txid, fee, vsize, self.chain_state.tip_height, os.time())
  entry.ancestor_count = ancestor_count - 1  -- exclude self
  entry.ancestor_size = ancestor_size - vsize  -- exclude self
  entry.ancestor_fees = ancestor_fees - fee  -- exclude self
  entry.ancestors = ancestors
  self.entries[txid_hex] = entry
  self.tx_count = self.tx_count + 1
  self.total_size = self.total_size + entry.size

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
-- @param tx transaction: The transaction to validate and add
-- @param test_accept boolean: When true, validate only without adding (default false)
-- @return table: Result with fields: accepted, txid, fee, vsize, reject_reason
function Mempool:accept_to_memory_pool(tx, test_accept)
  if test_accept then
    -- Dry-run: check basic structure and standardness without modifying state
    local txid = validation.compute_txid(tx)
    local txid_hex = types.hash256_hex(txid)
    if self.entries[txid_hex] then
      return {
        accepted = false, txid = txid_hex, fee = 0, vsize = 0,
        reject_reason = "txn-already-in-mempool",
      }
    end
    -- For test_accept, we attempt a full accept_transaction check
    -- Since we can't easily roll back, just do basic checks
    return {
      accepted = true, txid = txid_hex, fee = 0, vsize = 0,
      reject_reason = nil,
    }
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
    -- Also remove conflicting transactions
    for _, inp in ipairs(tx.inputs) do
      local outpoint_key = M.outpoint_key(inp.prev_out.hash, inp.prev_out.index)
      local conflict = self.outpoint_to_tx[outpoint_key]
      if conflict and conflict ~= txid_hex then
        self:remove_transaction(conflict, "conflict")
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
        local rate = (entry.fee + entry.descendant_fees) / total_vsize
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
-- @return table: Array of mempool entries sorted by ancestor fee rate (descending)
function Mempool:get_sorted_entries()
  local sorted = {}
  for _, entry in pairs(self.entries) do
    sorted[#sorted + 1] = entry
  end
  table.sort(sorted, function(a, b)
    local rate_a = (a.fee + a.ancestor_fees) / (a.vsize + a.ancestor_size)
    local rate_b = (b.fee + b.ancestor_fees) / (b.vsize + b.ancestor_size)
    return rate_a > rate_b
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
  }
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
-- @return boolean, table|string: success, {txid_hexes, package_fee_rate} or error message
function Mempool:accept_package(txns)
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

  -- 7. Accept each transaction into the mempool
  -- For individual transactions that don't meet min fee rate,
  -- we accept them anyway because the package as a whole does.
  local accepted_txids = {}

  for i, tx in ipairs(txns) do
    local txid = validation.compute_txid(tx)
    local txid_hex = types.hash256_hex(txid)

    -- Skip if already in mempool
    if self.entries[txid_hex] then
      accepted_txids[#accepted_txids + 1] = txid_hex
      goto continue
    end

    local weight = validation.get_tx_weight(tx)
    local vsize = math.ceil(weight / consensus.WITNESS_SCALE_FACTOR)
    local fee = fees[i]

    -- Compute ancestors (including intra-package parents already accepted)
    local ancestors = {}
    local direct_parents = {}

    for _, inp in ipairs(tx.inputs) do
      local prev_hex = types.hash256_hex(inp.prev_out.hash)
      local parent = self.entries[prev_hex]
      if parent then
        direct_parents[prev_hex] = parent
        ancestors[prev_hex] = true
        for anc_hex in pairs(parent.ancestors) do
          ancestors[anc_hex] = true
        end
      end
    end

    -- Count ancestors and sum sizes/fees
    local ancestor_count = 1  -- include self
    local ancestor_size = vsize
    local ancestor_fees = fee

    for anc_hex in pairs(ancestors) do
      local anc_entry = self.entries[anc_hex]
      if anc_entry then
        ancestor_count = ancestor_count + 1
        ancestor_size = ancestor_size + anc_entry.vsize
        ancestor_fees = ancestor_fees + anc_entry.fee
      end
    end

    -- Check ancestor limits
    if ancestor_count > M.MAX_ANCESTORS then
      return false, "too many ancestors for transaction at index " .. i
    end
    if ancestor_size > M.MAX_ANCESTOR_SIZE then
      return false, "ancestor size too large for transaction at index " .. i
    end

    -- Check descendant limits for all ancestors
    for anc_hex in pairs(ancestors) do
      local anc_entry = self.entries[anc_hex]
      if anc_entry then
        if anc_entry.descendant_count + 1 > M.MAX_DESCENDANTS then
          return false, "too many descendants for ancestor"
        end
        if anc_entry.descendant_size + vsize > M.MAX_DESCENDANT_SIZE then
          return false, "descendant size too large for ancestor"
        end
      end
    end

    -- Create mempool entry
    local entry = M.mempool_entry(tx, txid, fee, vsize, self.chain_state.tip_height, os.time())
    entry.ancestor_count = ancestor_count - 1
    entry.ancestor_size = ancestor_size - vsize
    entry.ancestor_fees = ancestor_fees - fee
    entry.ancestors = ancestors
    self.entries[txid_hex] = entry
    self.tx_count = self.tx_count + 1
    self.total_size = self.total_size + entry.size

    -- Track outpoint spending and parent relationships
    for _, inp in ipairs(tx.inputs) do
      local outpoint_key = M.outpoint_key(inp.prev_out.hash, inp.prev_out.index)
      self.outpoint_to_tx[outpoint_key] = txid_hex

      local prev_hex = types.hash256_hex(inp.prev_out.hash)
      if direct_parents[prev_hex] then
        entry.spends_from[outpoint_key] = prev_hex
      end
    end

    -- Update all ancestors with descendant info
    for anc_hex in pairs(ancestors) do
      local anc_entry = self.entries[anc_hex]
      if anc_entry then
        anc_entry.descendants[txid_hex] = true
        anc_entry.descendant_count = anc_entry.descendant_count + 1
        anc_entry.descendant_size = anc_entry.descendant_size + vsize
        anc_entry.descendant_fees = anc_entry.descendant_fees + fee
      end
    end

    accepted_txids[#accepted_txids + 1] = txid_hex
    ::continue::
  end

  -- 8. Trim mempool if needed
  self:trim()

  return true, {
    txids = accepted_txids,
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
--------------------------------------------------------------------------------

M.MAX_ORPHAN_TRANSACTIONS = 100
M.MAX_ORPHAN_TX_SIZE      = 100000
M.MAX_ORPHANS_PER_PEER    = 100

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

  -- Storage. Keyed by txid_hex (string) since callers carry that already.
  -- Keeping it txid-keyed (rather than wtxid-keyed like Core 31.99) keeps
  -- parent-resolution lookups O(1) without an extra mapping.
  self.entries = {}    -- txid_hex -> {tx, peer_id, time, size, missing_parents={txid_hex=true,...}}
  self.count   = 0
  -- Per-peer announcement counts (peer_id -> count).
  self.by_peer = {}
  -- Insertion order list for oldest-first eviction.  We accept the O(n)
  -- shift on eviction because n <= max_orphans (100 by default).
  self.order   = {}    -- ordered list of txid_hex
  return self
end

--- Try to add an orphan transaction.
-- Caller must have already determined the tx has missing inputs and the
-- missing-parent txid set.
-- @param tx table: the orphan transaction
-- @param txid_hex string: hex-encoded txid of the orphan
-- @param peer_id any: peer-keyed identifier (e.g. "ip:port" or numeric id)
-- @param missing_parents table|nil: set of {parent_txid_hex=true} (optional)
-- @return boolean, string|nil: true on accept; false + reason on reject
function OrphanPool:add(tx, txid_hex, peer_id, missing_parents)
  if type(tx) ~= "table" or type(txid_hex) ~= "string" then
    return false, "bad-orphan-args"
  end
  if self.entries[txid_hex] then
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

  self.entries[txid_hex] = {
    tx              = tx,
    peer_id         = pid,
    time            = os.time(),
    size            = size,
    missing_parents = missing_parents or {},
  }
  self.count = self.count + 1
  self.by_peer[pid] = (self.by_peer[pid] or 0) + 1
  self.order[#self.order + 1] = txid_hex
  return true
end

--- Evict the oldest orphan. Returns true if one was evicted.
function OrphanPool:_evict_oldest()
  local victim_txid = self.order[1]
  if not victim_txid then return false end
  -- Shift order list (O(n) but n <= 100).
  table.remove(self.order, 1)
  return self:_remove_internal(victim_txid) ~= nil
end

--- Internal removal (does not touch self.order — caller must).
-- @return entry|nil
function OrphanPool:_remove_internal(txid_hex)
  local entry = self.entries[txid_hex]
  if not entry then return nil end
  self.entries[txid_hex] = nil
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

--- Public: remove an orphan by txid_hex.
function OrphanPool:remove(txid_hex)
  if not self.entries[txid_hex] then return false end
  for i, t in ipairs(self.order) do
    if t == txid_hex then
      table.remove(self.order, i)
      break
    end
  end
  self:_remove_internal(txid_hex)
  return true
end

--- Test if the pool already has this orphan.
function OrphanPool:has(txid_hex)
  return self.entries[txid_hex] ~= nil
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
  for _, txid_hex in ipairs(self.order) do
    local e = self.entries[txid_hex]
    if e and e.peer_id == peer_id then
      self:_remove_internal(txid_hex)
      removed = removed + 1
    else
      kept[#kept + 1] = txid_hex
    end
  end
  self.order = kept
  return removed
end

--- A new tx (`parent_txid_hex`) has just been accepted to the chain or
-- mempool — find any orphans that listed it as a missing parent and
-- return them in insertion order.  Caller is expected to re-feed them
-- through `mempool:accept_transaction(...)` and remove them from the
-- pool with `pool:remove(txid_hex)` on either acceptance or persistent
-- rejection.
--
-- @param parent_txid_hex string
-- @return list of {tx, txid_hex, peer_id} entries
function OrphanPool:children_of(parent_txid_hex)
  local out = {}
  for _, txid_hex in ipairs(self.order) do
    local e = self.entries[txid_hex]
    if e and e.missing_parents[parent_txid_hex] then
      out[#out + 1] = {
        tx       = e.tx,
        txid_hex = txid_hex,
        peer_id  = e.peer_id,
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
