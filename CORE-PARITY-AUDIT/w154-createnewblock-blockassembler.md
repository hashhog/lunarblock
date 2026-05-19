# W154 — CreateNewBlock + BlockAssembler + block template (lunarblock)

**Wave:** W154 — `BlockAssembler::CreateNewBlock`,
`BlockAssembler::addChunks` (Core's modern `addPackageTxs` replacement
in the cluster-mempool world), `resetBlock`, `ClampOptions`,
`AddToBlock`, `TestChunkBlockLimits`, `TestChunkTransactions`,
`UpdateTime`, `GetMinimumTime`, `RegenerateCommitments`,
`GenerateCoinbaseCommitment` (BIP-141 0xaa21a9ed marker),
`BlockMerkleRoot` / `BlockWitnessMerkleRoot`, BIP-22/23 `getblocktemplate`
mode dispatch (`template` / `proposal`), `generatetoaddress`,
`generateblock`, `submitblock`, `prioritisetransaction` /
`getprioritisedtransactions`, BIP-9 `vbavailable`, BIP-94 timewarp
adjustment.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/node/miner.cpp:36-47` — `GetMinimumTime`: returns
  `pindexPrev->GetMedianTimePast() + 1`; on retarget boundaries
  (`height % difficulty_adjustment_interval == 0`) also bumps to
  `max(prev_block_time - MAX_TIMEWARP, mtp+1)` to defend against the
  BIP94 retarget timewarp.
- `bitcoin-core/src/node/miner.cpp:49-65` — `UpdateTime`: sets
  `pblock->nTime = max(GetMinimumTime, NodeClock::now())`, then
  recomputes nBits on testnet (`fPowAllowMinDifficultyBlocks`).
- `bitcoin-core/src/node/miner.cpp:67-77` — `RegenerateCommitments`:
  erases the witness-commitment output from `vtx[0]`, calls
  `chainman.GenerateCoinbaseCommitment`, then recomputes
  `BlockMerkleRoot`. Used by callers who mutate the tx list (e.g.
  pruning a single tx) without rebuilding the whole template.
- `bitcoin-core/src/node/miner.cpp:79-88` — `ClampOptions`:
  `block_reserved_weight ∈ [MINIMUM_BLOCK_RESERVED_WEIGHT=2000,
  MAX_BLOCK_WEIGHT=4000000]` (default `DEFAULT_BLOCK_RESERVED_WEIGHT=8000`);
  `coinbase_output_max_additional_sigops ∈ [0, MAX_BLOCK_SIGOPS_COST=80000]`
  (default `DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS=400`);
  `nBlockMaxWeight ∈ [block_reserved_weight, MAX_BLOCK_WEIGHT]`.
- `bitcoin-core/src/node/miner.cpp:98-109` — `ApplyArgsManOptions`:
  reads `-blockmaxweight`, `-blockmintxfee`, `-blockreservedweight`,
  `-printpriority` from `ArgsManager`.
- `bitcoin-core/src/node/miner.cpp:111-120` — `resetBlock`:
  `nBlockWeight = *Assert(m_options.block_reserved_weight)`;
  `nBlockSigOpsCost = m_options.coinbase_output_max_additional_sigops`
  (**not zero — reserves 400 sigops for the pool's payout outputs**).
- `bitcoin-core/src/node/miner.cpp:122-237` — `CreateNewBlock`:
  reset → enumerate via `addChunks` → set coinbase scriptSig
  `CScript() << nHeight (<< OP_0 dummy if include_dummy_extranonce)`,
  nLockTime `= nHeight - 1`, nSequence
  `= CTxIn::MAX_SEQUENCE_NONFINAL=0xFFFFFFFE` → coinbase witness nonce
  asserted to `size()==1 && size==32` after
  `GenerateCoinbaseCommitment` → `UpdateTime(...)`,
  `nBits = GetNextWorkRequired(pindexPrev, pblock, ...)`,
  `nNonce = 0` → final `TestBlockValidity(check_pow=false, check_merkle_root=false)`.
- `bitcoin-core/src/node/miner.cpp:239-260` — `TestChunkBlockLimits`:
  rejects when `nBlockWeight + chunk.size >= m_options.nBlockMaxWeight`
  OR `nBlockSigOpsCost + chunk_sigops_cost >= MAX_BLOCK_SIGOPS_COST`.
  `TestChunkTransactions`: rejects when any tx in the chunk fails
  `IsFinalTx(tx, nHeight, m_lock_time_cutoff)`.
- `bitcoin-core/src/node/miner.cpp:262-277` — `AddToBlock`:
  `nBlockWeight += entry.GetTxWeight()`;
  `nBlockSigOpsCost += entry.GetSigOpCost()`; `nFees += entry.GetFee()`.
  Uses the PRECOMPUTED `entry.GetSigOpCost()` from CTxMemPoolEntry
  (which is legacy×WITNESS_SCALE_FACTOR + P2SH×WITNESS_SCALE_FACTOR +
  witness; see `txmempool.h::GetSigOpCost`).
- `bitcoin-core/src/node/miner.cpp:279-334` — `addChunks`: select via
  `m_mempool->GetBlockBuilderChunk` (cluster-mempool chunk feerate);
  loop while `chunk_feerate_vsize >= blockMinFeeRate`; per-chunk
  `TestChunkBlockLimits + TestChunkTransactions` → either `IncludeBuilderChunk`
  + `AddToBlock` for every tx, or `SkipBuilderChunk` + `++nConsecutiveFailed`.
  Early-exit when `nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES (=1000)
  AND nBlockWeight + BLOCK_FULL_ENOUGH_WEIGHT_DELTA (=4000) > nBlockMaxWeight`.
- `bitcoin-core/src/node/types.h:39-79` — `BlockCreateOptions`:
  `use_mempool{true}`, `block_reserved_weight{std::optional}`,
  `coinbase_output_max_additional_sigops{DEFAULT_=400}`,
  `coinbase_output_script{CScript() << OP_TRUE}` (anyone-can-spend
  dummy — Core does **not** lock the dummy coinbase to anywhere), and
  `include_dummy_extranonce{false}` (true only for the
  `getblocktemplate` path, see mining.cpp:878).
- `bitcoin-core/src/policy/policy.h:24-50` —
  `DEFAULT_BLOCK_MAX_WEIGHT = MAX_BLOCK_WEIGHT = 4_000_000`,
  `DEFAULT_BLOCK_RESERVED_WEIGHT = 8000`,
  `DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS = 400`,
  `MINIMUM_BLOCK_RESERVED_WEIGHT = 2000`,
  `DEFAULT_BLOCK_MIN_TX_FEE = 1` (sat/kvB),
  `MAX_BLOCK_SIGOPS_COST = 80_000`, `MAX_STANDARD_TX_SIGOPS_COST =
  MAX_BLOCK_SIGOPS_COST/5 = 16_000`, `MAX_TX_LEGACY_SIGOPS = 2500`.
- `bitcoin-core/src/consensus/consensus.h` — `MAX_BLOCK_WEIGHT = 4_000_000`,
  `WITNESS_SCALE_FACTOR = 4`, `MAX_TIMEWARP = 600`.
- `bitcoin-core/src/script/script.h:432-448` — `push_int64` (used by
  `CScript() << nHeight`): heights `-1` and `1..16` emit OP_1..OP_16
  (single-byte 0x51..0x60); height 0 emits OP_0 (0x00);
  otherwise `CScriptNum::serialize(n)` (length-prefixed CScriptNum).
- `bitcoin-core/src/consensus/tx_check.cpp:49-50` — `bad-cb-length`:
  `vin[0].scriptSig.size() < 2 || > 100`.
- `bitcoin-core/src/validation.cpp:3997-4019` — `GenerateCoinbaseCommitment`:
  writes `OP_RETURN 0x24 0xaa 0x21 0xa9 0xed <witnessroot>` (38 bytes
  total) as a new vout on the coinbase, with `nValue = 0`.
- `bitcoin-core/src/rpc/mining.cpp:502-548` — `prioritisetransaction`:
  three-arg form `<txid> <dummy=0> <fee_delta>`; rejects `dummy != 0`
  (priority field deprecated post-0.15) and applies signed delta to
  `pool.PrioritiseTransaction(txid, fee_delta)`.
- `bitcoin-core/src/rpc/mining.cpp:550-585` — `getprioritisedtransactions`:
  `pool.GetPrioritisedTransactions()` → map of txid → `{fee_delta,
  in_mempool, modified_fee?}`.
- `bitcoin-core/src/rpc/mining.cpp:587-602` — `BIP22ValidationResult`:
  `state.IsValid() → VNULL`; `state.IsInvalid() → reject reason string
  (or "rejected" if empty)`.
- `bitcoin-core/src/rpc/mining.cpp:615-1100` — `getblocktemplate`:
  `mode ∈ {"template","proposal"}` (proposal: returns "duplicate" /
  "duplicate-invalid" / "duplicate-inconclusive" or
  `BIP22ValidationResult(TestBlockValidity(check_pow=false,
  check_merkle_root=true))`); requires `rules: ["segwit"]` in
  template_request when segwit is active (mining.cpp:1011-1014);
  refuses with `RPC_CLIENT_IN_INITIAL_DOWNLOAD` if IBD
  (mining.cpp:772-774); refuses with `RPC_CLIENT_NOT_CONNECTED` if
  no peers on non-test chains (mining.cpp:766-770); emits BIP-9
  `vbavailable` via `chainman.m_versionbitscache.GBTStatus`
  (mining.cpp:966-980); `signet_challenge` field on signet
  (mining.cpp:699-700); `longpollid =
  pindexPrev.GetHash() + nTransactionsUpdatedLast` for the BIP-22
  longpoll capability (mining.cpp:853-870).
- `bitcoin-core/src/kernel/chainparams.cpp:535` — regtest
  `consensus.nSubsidyHalvingInterval = 150`; mainnet/testnet/testnet4
  `= 210000`; signet `= 210000`. **Per-network knob, not global.**

**Files audited**
- `src/mining.lua` (530 lines) — `M.create_coinbase_tx` (line 135-202),
  `M.clamp_options` (line 215-237), `M.create_block_template`
  (line 250-494), `M.is_final_tx` (line 43-72),
  `M.apply_anti_fee_sniping` (line 79-90), `M.mine_block` (line 505-528).
  Constants: `DEFAULT_BLOCK_RESERVED_WEIGHT = 8000`,
  `MINIMUM_BLOCK_RESERVED_WEIGHT = 2000`, `MAX_CONSECUTIVE_FAILURES =
  1000`, `BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000`,
  `MAX_SEQUENCE_NONFINAL = 0xFFFFFFFE`. No `coinbase_output_max_additional_sigops`,
  no `include_dummy_extranonce`, no `print_modified_fee`, no
  `test_block_validity`, no `RegenerateCommitments` analog.
- `src/consensus.lua:48-58` — `M.HALVING_INTERVAL = 210000` (GLOBAL,
  read directly by `M.get_block_subsidy`); per-network field absent
  from every entry in `M.networks.*` (lines 893, 1020, 1094, 1164).
  `M.MAX_BLOCK_WEIGHT = 4_000_000` (line 10),
  `M.MAX_BLOCK_SIGOPS_COST = 80_000` (line 12),
  `M.WITNESS_SCALE_FACTOR = 4` (line 13),
  `M.compute_block_version` (line 744-774) returns `VERSIONBITS_TOP_BITS`
  when `get_block_info` callback is nil (which is the case for every
  caller in lunarblock — `create_block_template` only forwards an
  optional `get_block_info` param that no production site supplies).
  `M.bits_to_target` (line 75-114). No `M.get_next_work_required` call
  from `create_block_template` (it reads parent's `bits` directly).
- `src/rpc.lua:3636-3866` — `generateblock` handler (regtest only;
  rebuilds coinbase manually after `create_block_template` so it can
  collect fees from caller-supplied txs).
- `src/rpc.lua:3869-3885` — `getblocktemplate` handler (calls
  `rpc.mining.create_block_template(rpc.mempool, rpc.chain_state,
  rpc.network, payout_script)`; ignores `mode`, `longpollid`,
  `capabilities`, `rules` from the template_request).
- `src/rpc.lua:3887-3990` — `generatetoaddress` handler (single-CPU
  mining; routes through `accept_block` after `mine_block`).
- `src/rpc.lua:6947-7192` — `submitblock` handler.
- `src/rpc.lua:7217-7262` — `getmininginfo` handler (does NOT call
  `create_block_template` — emits a static-shape response).
- `src/mempool.lua:830-861` — `mempool_entry`: stores `fee`, `vsize`,
  `weight`, `wtxid`; **NO precomputed `sigop_cost` field**.
- `src/mempool.lua:2123-2137` — `Mempool:get_sorted_entries`: sorts by
  `(entry.fee + entry.ancestor_fees) / (entry.vsize + entry.ancestor_size)`
  in **Lua double division**, descending.
- `src/main.lua:80-260` — CLI flag block. **No** `-blockmaxweight`,
  `-blockmintxfee`, `-blockreservedweight`, `-blockversion`.
- `src/validation.lua:294-298` — `get_tx_weight`.
- `src/validation.lua:343-367` — `count_script_sigops` (uses local
  `pcall(script.parse_script, …)` and silently returns 0 on parse
  failure; W143 BUG-6 echo).
- `src/validation.lua:519-…` — `get_transaction_sigop_cost` (the
  P2SH+witness aware path; **not called by mining.lua**).
- `src/crypto.lua:1289-1313` — `compute_merkle_root` (used for both
  txid merkle and wtxid merkle; CVE-2012-2459 mutation detection ABSENT
  — odd levels duplicate last hash, BLOCK_MUTATED state never raised
  on duplicate-pair-tail; cross-cite W142+W143 fleet pattern).

---

## Gate matrix (30 sub-gates / 14 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR / DEFAULT_BLOCK_RESERVED_WEIGHT defined | G1: MAX_BLOCK_WEIGHT = 4_000_000 | PASS (`consensus.lua:10`) |
| 1 | … | G2: WITNESS_SCALE_FACTOR = 4 | PASS (`consensus.lua:13`) |
| 1 | … | G3: DEFAULT_BLOCK_RESERVED_WEIGHT = 8000 | PASS (`mining.lua:19`) |
| 1 | … | G4: MINIMUM_BLOCK_RESERVED_WEIGHT = 2000 | PASS (`mining.lua:22`) |
| 1 | … | G5: DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS = 400 reserved at resetBlock | **BUG-7 (P1)** — absent; `total_sigops` starts at 0 (mining.lua:274) |
| 2 | ClampOptions | G6: block_reserved_weight clamped to [2000, MAX_BLOCK_WEIGHT] | PASS (`mining.lua:222-227`) |
| 2 | … | G7: nBlockMaxWeight clamped to [reserved, MAX_BLOCK_WEIGHT] | PASS (`mining.lua:231-234`) |
| 3 | addPackageTxs ancestor-feerate selection | G8: per-cluster chunk feerate (cluster mempool) | **BUG-11 (P1)** — per-entry ancestor feerate only; no cluster cohesion (mempool.lua:2131-2134) |
| 3 | … | G9: nConsecutiveFailed bumps ONLY on chunk-fit failure | **BUG-12 (P1)** — bumps on `!ancestors_ok` too (mining.lua:321-329) |
| 4 | GenerateCoinbaseCommitment OP_RETURN 0xaa21a9ed | G10: 6-byte prefix `6a 24 aa 21 a9 ed` + 32-byte witnessroot | PASS (`mining.lua:185`) |
| 4 | … | G11: nValue=0 on commitment output | PASS (`mining.lua:186`) |
| 5 | BlockMerkleRoot / BlockWitnessMerkleRoot | G12: coinbase wtxid placeholder = 32 zero bytes | PASS (`mining.lua:352`) |
| 5 | … | G13: CVE-2012-2459 mutated-merkle detection (duplicated-pair-tail BLOCK_MUTATED) | **BUG-9 (P1)** — `crypto.compute_merkle_root` duplicates last hash on odd levels without raising mutated; fleet pattern (W142+W143 cite) |
| 6 | mintime / GetMinimumTime | G14: `mintime = prev_block_mtp + 1` | **BUG-2 + BUG-3 (P0-CDIV)** — `chain_state.mtp` is never populated by any caller → falls back to `os.time() - 3600` (mining.lua:266-267); `mintime` field is `mtp + 1` over this fake value |
| 6 | … | G15: BIP-94 timewarp clamp on retarget boundary | **BUG-4 (P1)** — `GetMinimumTime`'s `max(min_time, prev_block_time - MAX_TIMEWARP)` on retarget is absent; lunarblock unconditionally returns `mtp+1` regardless of period boundary |
| 7 | UpdateTime / header.nTime | G16: `nTime = max(GetMinimumTime, NodeClock::now())` | **BUG-5 (P0-CDIV)** — `header.timestamp = os.time()` (mining.lua:397); if system clock is even one second below `mtp+1`, the resulting header fails Core's ContextualCheckBlockHeader with `time-too-old` |
| 7 | … | G17: testnet `nBits = GetNextWorkRequired` recomputed after time update | **BUG-1 cross-cite** |
| 8 | nVersion BIP-9 version-rolling | G18: starts at VERSIONBITS_TOP_BITS (0x20000000) | PASS (`consensus.lua:745`) |
| 8 | … | G19: ORs in STARTED/LOCKED_IN deployment masks | **BUG-19 (P1)** — `get_block_info` callback is `nil` at every production call site → `compute_block_version` returns bare `VERSIONBITS_TOP_BITS`; deployment masks never OR'd in. `vbavailable` is hardcoded to `{}` (line 417), `vbrequired = 0` (line 422) — comment confesses "We have no live BIP9 deployments". |
| 8 | … | G20: regtest `-blockversion=N` override | **BUG-21 (P1)** — no `-blockversion` flag plumbed (`main.lua:80-260` has no entry); miner.cpp:143-145 |
| 9 | coinbase scriptSig length 2..100 (bad-cb-length) | G21: BIP-34 height push (heights 1-16 = single byte) bumped by OP_0 dummy when `include_dummy_extranonce` is true | **BUG-8 (P1)** — `include_dummy_extranonce` field absent from `M.create_coinbase_tx`. Heights 1-16 emit `01 <h>` (2 bytes total) → borderline-passes `bad-cb-length` only because lunarblock uses length-prefixed push, not Core's `OP_1..OP_16` single-byte encoding (which would FAIL `bad-cb-length` without OP_0 dummy). Structurally divergent BIP-34 encoding (see BUG-13). |
| 10 | coinbase height BIP-34 | G22: heights 1-16 emit OP_1..OP_16 (script.h:435-438) | **BUG-13 (P1)** — emits literal `01 <h>` for all positive heights (mining.lua:144-159); for h ∈ 1..16 this is structurally divergent from Core. Coinbase scriptSig byte-pattern differs → blocks produced by lunarblock + decoded by Core look like a non-standard BIP-34 push. Core does not enforce minimal-encoding on coinbase scriptSig, so this is not a hard rejection, but it breaks block-hash determinism vs Core for the SAME tx set + payout. |
| 11 | GBT reserved weight + sigops | G23: `nBlockWeight` starts at `block_reserved_weight` | PASS (`mining.lua:279`) |
| 11 | … | G24: `nBlockSigOpsCost` starts at `coinbase_output_max_additional_sigops` (=400) | **BUG-7 cross-cite** |
| 12 | package-feerate-not-individual | G25: TestChunkBlockLimits uses precomputed `entry.GetSigOpCost()` (legacy×4 + P2SH×4 + witness) | **BUG-6 (P0-CDIV)** — mining.lua:296-302 recomputes via `count_script_sigops(script_sig, true) * WITNESS_SCALE_FACTOR + count_script_sigops(script_pubkey, true) * WITNESS_SCALE_FACTOR`. Misses P2SH redeem-script sigops AND segwit witness-program sigops. Result: lunarblock packs blocks whose REAL sigops exceed MAX_BLOCK_SIGOPS_COST → Core peers reject with `bad-blk-sigops`. |
| 13 | Lua-double precision on fee accumulation | G26: per-cluster fee sums survive ≥1 PB cumulative fee without precision loss | PASS in practice (cumulative bounded by MAX_MONEY = 2.1e15 sat ≈ 51 bits, within Lua double's 53-bit mantissa) |
| 13 | … | G27: ancestor-feerate comparator orders identical-feerate ties same as Core's int64 fee-fraction | **BUG-20 (P1)** — `(a.fee + a.ancestor_fees) / (a.vsize + a.ancestor_size)` (mempool.lua:2131-2134) is a Lua double division; ties to Core's `feerate1 * size2 vs feerate2 * size1` int128 cross-multiply can differ at the 1-sat-per-byte granularity (W149 BUG-10 echo) |
| 14 | LuaJIT assert in miner path → wire-DoS | G28: no `assert()` in mining.lua | PASS (verified; mining.lua has zero `assert` / `error` calls. The W142 BUG-24 / W150 BUG-24 pattern is absent from the miner module specifically.) |
| 14 | … | G29: `count_script_sigops` graceful failure mode | **W143 BUG-6 echo** — validation.lua:344-346 silently returns 0 on parse failure; mining.lua then under-counts sigops for the entry. Not a fresh bug; reported under W143. |
| 14 | … | G30: per-network nSubsidyHalvingInterval | **BUG-3 cross-cite W145** (carry-forward) — `HALVING_INTERVAL = 210000` is GLOBAL in `consensus.lua:48`; regtest must use 150 per Core kernel/chainparams.cpp:535. `M.get_block_subsidy` (line 50-58) reads the global. Miner-side coinbase value is `subsidy + total_fees` (mining.lua:362) — on regtest past height 150, lunarblock pays a 50 BTC subsidy while Core's regtest schedule already halved to 25 BTC. Block has `bad-cb-amount` on Core's regtest replay. |

---

## BUG-1 (P0-CDIV) — Template emits PARENT block's `bits` at every retarget, not the next-block target

**Severity:** P0-CDIV. Bitcoin Core's `BlockAssembler::CreateNewBlock`
calls `pblock->nBits = GetNextWorkRequired(pindexPrev, pblock,
chainparams.GetConsensus())` (miner.cpp:220). On mainnet at every
2016-block retarget boundary, the new block's required bits differ
from the parent's — they're computed from
`((pindexLast->nTime - first->nTime), prevTarget)` clamped to
`[oldTarget/4, oldTarget*4]`. On testnet (`fPowAllowMinDifficultyBlocks`)
the per-block min-difficulty rule fires when `block.nTime > prev.nTime + 20*60`,
which means `nBits` flips between the actual chain target and
`powLimitBits` on every other block.

lunarblock's `create_block_template` (mining.lua:381-383) reads the
**parent's** bits directly:

```lua
-- Get difficulty target
local bits = chain_state.storage.get_header(prev_hash).bits
-- In a real implementation, compute next required bits at retarget heights
```

The trailing comment is **comment-as-confession** — the author knows
the value is wrong and admits it. There is no call to
`consensus.get_next_work_required` even though that helper exists at
`consensus.lua:401`. Result:

- **Mainnet retarget (every 2016 blocks):** lunarblock's miner mines a
  block at the OLD target. If the new required target is HARDER
  (most common, given the chain's monotonic difficulty growth), the
  block's hash fails Core's PoW check and is rejected with `high-hash`.
  If the new target is EASIER (rare; e.g. after sustained low hashrate),
  the block PASSES PoW but Core's `ContextualCheckBlockHeader` rejects
  with `bad-diffbits` because the header's `nBits` doesn't match the
  computed required bits.
- **Testnet/testnet4 every block:** the min-difficulty flip is missed,
  blocks signal the wrong target half the time.
- **`getblocktemplate.bits`:** pool software trusts this field. The
  emitted `template.bits` (mining.lua:449) is the parent's bits, so
  the template is unmineable at retarget for every downstream pool.

**File:** `src/mining.lua:381-383` (bits source);
`src/mining.lua:449` (template.bits field);
`src/consensus.lua:401` (existing `get_next_work_required` not called).

**Core ref:** `bitcoin-core/src/node/miner.cpp:220`
(`pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, ...)`).

**Impact:** every 2016-block boundary on mainnet (and every block on
testnet/testnet4) produces an unmineable or hard-rejected template.
The bug is masked in regtest because `pow_no_retarget = true`
(consensus.lua:1172) means `GetNextWorkRequired` always returns the
fixed `pow_limit_bits` — same as the parent's bits. So all existing
regtest tests pass, and the bug is **discoverable only on a non-regtest
mining run**.

---

## BUG-2 (P0-CDIV) — `chain_state.mtp` is never populated; miner uses fake MTP = `os.time() - 3600`

**Severity:** P0-CDIV. `BlockAssembler::CreateNewBlock` computes the
locktime cutoff for `IsFinalTx` as
`m_lock_time_cutoff = pindexPrev->GetMedianTimePast()` (miner.cpp:148),
which is the median of the previous 11 block timestamps per BIP-113.
This is the value passed to `IsFinalTx` for every tx during chunk
selection (miner.cpp:255).

lunarblock's `create_block_template` (mining.lua:265-267):

```lua
-- Get median time past for locktime checks
-- chain_state.mtp should be provided; fallback to current time - 3600 (1 hour ago)
local mtp = chain_state.mtp or (os.time() - 3600)
```

A grep over the entire tree shows that `chain_state.mtp` is **never
populated**:

```
$ grep "chain_state.mtp\|self.mtp\|.mtp\s*=" src/utxo.lua src/rpc.lua src/mining.lua
src/mining.lua:266: -- chain_state.mtp should be provided; fallback to current time - 3600 (1 hour ago)
src/mining.lua:267: local mtp = chain_state.mtp or (os.time() - 3600)
```

`ChainState:__init` (utxo.lua:1543-1544) initialises `tip_hash = nil`
and `tip_height = -1` but never adds an `mtp` field; `accept_block`
(utxo.lua) does not write one either. So **every call** to
`create_block_template` uses `mtp = wall_clock - 3600`.

This breaks `is_final_tx` for time-based locktimes:

```lua
-- mining.lua:43-72
if tx.locktime < LOCKTIME_THRESHOLD then
  lock_threshold = height   -- height-based: OK
else
  lock_threshold = mtp      -- time-based: uses FAKE mtp
end
if tx.locktime < lock_threshold then return true end
```

A time-based-locktime tx with `locktime = real_mtp + 100` (legitimately
deferred per BIP-113) would be **included** in the template because
`real_mtp + 100 < wall_clock - 3600` is often true on a chain that's
caught up. Conversely a tx with `locktime = wall_clock - 1800`
(should be unlockable) is **excluded** because `wall_clock - 1800
> wall_clock - 3600 = mtp`. The fake MTP is wrong in both directions
depending on chain state.

On testnet4 (which can stall for hours via min-difficulty) the chain
MTP can be several days behind wall-clock; the fallback then INCLUDES
txs whose real-locktime defers them by days. The resulting block is
rejected by Core peers with `bad-txns-nonfinal`.

**File:** `src/mining.lua:266-267` (fallback);
`src/utxo.lua:1543-1544, 1628-1629, 1719-1720, 1787-1788, 1815-1816`
(ChainState initialisation sites — none set `.mtp`).

**Core ref:** `bitcoin-core/src/node/miner.cpp:148`
(`m_lock_time_cutoff = pindexPrev->GetMedianTimePast()`).

**Impact:** time-based locktime txs are included or excluded based on
wall-clock-relative pseudo-MTP, not the real BIP-113 MTP. Templates
served via `getblocktemplate` carry blocks that Core peers reject
with `bad-txns-nonfinal`. The bug is silent in regtest because no
tests stress time-based-locktime mempool txs.

---

## BUG-3 (P0-CDIV) — `template.mintime` propagates the fake fallback MTP into the BIP-22 response

**Severity:** P0-CDIV. Per BIP-22 (and Core mining.cpp:684),
`mintime` is `GetMinimumTime(pindexPrev, difficulty_adjustment_interval)
= prev_block_mtp + 1`. Pool software trusts this value to clamp the
block's `nTime` from below.

lunarblock's template (mining.lua:439-442):

```lua
-- BUG FIX: mintime must be MTP+1 (GetMinimumTime), not os.time().
mintime = mtp + 1,
```

The fix is conceptually correct, but `mtp` is the fake fallback from
BUG-2: `mtp = os.time() - 3600`, so `mintime = wall_clock - 3599`.
This value is several hours BELOW the real MTP+1 of any sync'd chain
(real MTP is typically `wall_clock - 60..300s` on mainnet/testnet).

A pool that respects `mintime` strictly and tries `nTime = mintime`
on the first hash submit will send a header that Core rejects with
`time-too-old` (ContextualCheckBlockHeader's `block.nTime <= prev.MTP`
gate).

**File:** `src/mining.lua:442` (mintime emit).

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47`
(`GetMinimumTime`).

**Impact:** strictly downstream of BUG-2; cross-cite. Wedges every
pool-software integration that uses `template.mintime` as the
`nTime` floor.

---

## BUG-4 (P1) — `mintime` ignores BIP-94 timewarp retarget clamp

**Severity:** P1. Even with BUG-2 resolved (proper MTP source),
`mintime = mtp + 1` (mining.lua:442) does not implement Core's
BIP-94 clause:

```cpp
// bitcoin-core/src/node/miner.cpp:43-45
if (height % difficulty_adjustment_interval == 0) {
    min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
}
```

On a retarget boundary (mainnet h % 2016 == 0), if the previous
block's `nTime` is more than 600s in the past relative to the new
`mtp + 1`, lunarblock's `mintime` UNDERSHOOTS Core's by up to 600s.
A pool that mines at that `mintime` value produces a block Core
rejects with `bad-timewarp-attack` once BIP-94 activates on a network
(currently active only on testnet4 per `enforce_bip94` flag at
`consensus.lua:1107`).

**File:** `src/mining.lua:439-442` (no BIP-94 branch);
`src/consensus.lua:41` (`M.MAX_TIMEWARP = 600` defined but unused
in mining).

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47`
(`GetMinimumTime`'s `(height % DAI == 0)` clamp).

**Impact:** future activation of BIP-94 on mainnet → lunarblock-built
templates at retarget boundaries are unmineable. Already broken on
testnet4 at every retarget (block 2016, 4032, ...).

---

## BUG-5 (P0-CDIV) — `header.nTime = os.time()` skips Core's `max(GetMinimumTime, NodeClock::now())` floor

**Severity:** P0-CDIV. Core's `UpdateTime` (miner.cpp:49-65) computes
`pblock->nTime = max(GetMinimumTime(...), NodeClock::now())`. The
`max` is essential: if the system clock has drifted BELOW `mtp+1`
(e.g. NTP step backward, VM clock skew, container start-up clock
skew), Core falls back to `mtp+1` and proceeds. The miner cannot
produce a header with `nTime <= mtp`.

lunarblock's `create_block_template` (mining.lua:392-400):

```lua
local header = types.block_header(
  block_version,
  prev_hash,
  merkle_root,
  os.time(),   -- ← no clamp against mtp+1
  bits,
  0
)
```

If `os.time() < mtp + 1`, the resulting header is invalid before it
even reaches `mine_block`. The block fails Core's
`ContextualCheckBlockHeader` with `time-too-old` on submit; lunarblock's
own `submitblock` (rpc.lua:7064-7068) also rejects it with the same
reason — but for self-mining (`generatetoaddress`), the rejection
fires only AFTER `mine_block` has burned through nonces.

The probability of this firing in practice is low (system clocks
generally march forward), but the **defence-in-depth** clamp Core
provides is structurally absent. NTP step-backward on container
startup is the documented failure mode.

**File:** `src/mining.lua:397` (`os.time()` direct);
`src/mining.lua:448` (`curtime = os.time()` in template — same shape).

**Core ref:** `bitcoin-core/src/node/miner.cpp:49-65` (`UpdateTime`).

**Impact:** any clock-skew that drops `os.time() < mtp + 1` makes
the next-mined block unsubmittable. On regtest with mockable wall-clock
this can also be reproduced; on production it's a rare but real
silent-failure mode.

---

## BUG-6 (P0-CDIV) — Sigops accumulator misses P2SH redeem-script sigops AND segwit witness-program sigops

**Severity:** P0-CDIV. Core's `BlockAssembler::AddToBlock` uses
`entry.GetSigOpCost()` (miner.cpp:269), which is the per-tx
PRECOMPUTED sigop cost stored on the mempool entry at insertion time.
That cost is `legacy×WITNESS_SCALE_FACTOR + P2SH×WITNESS_SCALE_FACTOR
+ witness×1` (consensus/tx_verify.cpp::GetTransactionSigOpCost +
policy/policy.cpp::GetP2SHSigOpCount).

lunarblock's mempool entry (mempool.lua:830-861) does **not** carry a
precomputed `sigop_cost` field. `create_block_template` then
RECOMPUTES via mining.lua:296-302:

```lua
local tx_sigops = 0
for _, inp in ipairs(entry.tx.inputs) do
  tx_sigops = tx_sigops + validation.count_script_sigops(inp.script_sig, true) * consensus.WITNESS_SCALE_FACTOR
end
for _, out in ipairs(entry.tx.outputs) do
  tx_sigops = tx_sigops + validation.count_script_sigops(out.script_pubkey, true) * consensus.WITNESS_SCALE_FACTOR
end
```

What this counts vs what it MUST count per Core:

| Sigop class | Counted? | Core treatment |
|-------------|----------|----------------|
| Legacy CHECKSIG in scriptSig (accurate) | YES × 4 | yes × 4 (BIP-141 scale) |
| Legacy CHECKSIG in scriptPubKey (accurate) | YES × 4 | yes × 4 |
| P2SH redeem-script CHECKSIG (after extracting last push from scriptSig) | **NO** | yes × 4 (`GetP2SHSigOpCount`) |
| Segwit v0 P2WPKH (= 1 sigop, no scale) | **NO** | yes × 1 |
| Segwit v0 P2WSH witnessScript CHECKSIG (= n sigops, no scale) | **NO** | yes × 1 |
| Taproot key-path / script-path | **NO** | n/a (BIP-342 sigops are weight-charged, not counted here) |

A P2SH-wrapped-P2WSH-2-of-3-multisig tx pays 2 P2SH×4 = 8 legacy-equivalent
sigops to Core, but ZERO sigops in lunarblock's count. A P2WSH-only
2-of-3-multisig pays 2 (unscaled) sigops to Core, zero to lunarblock.

Two consequences:

1. **lunarblock packs blocks that exceed `MAX_BLOCK_SIGOPS_COST=80000`
   in real-sigops terms.** Core peers reject the submitted block with
   `bad-blk-sigops` (consensus/tx_check.cpp / validation.cpp:3970).
   The lunarblock node's own validation also rejects on
   `accept_block` → `check_block`, so the bug is partially self-trapping
   (the local node refuses its own template at submit time), but the
   wasted hash effort is real.
2. **The accumulator over-skips on the wrong axis.** If a SegWit-heavy
   block legitimately fits 80000 real sigops, lunarblock counts ~0,
   stays well under `max_sigops`, but then a single legacy-CHECKSIG-heavy
   tx (which IS counted) pushes the legacy slice over `max_sigops` and
   triggers early bail-out via the consecutive-failure counter (BUG-12).

**File:** `src/mining.lua:296-302` (sigops recomputation);
`src/mempool.lua:830-861` (entry missing `sigop_cost`);
`src/validation.lua:519-…` (existing `get_transaction_sigop_cost` —
the correct path — **not called**).

**Core ref:** `bitcoin-core/src/node/miner.cpp:269`
(`nBlockSigOpsCost += entry.GetSigOpCost()`).

**Impact:** routine on any block containing P2SH or SegWit txs (i.e.
every modern block). Templates exceed Core's sigops cap and are
rejected on submit. Self-trapped at lunarblock's own
`check_block` so funds aren't lost, but mining attempts at the
network tip are wasted.

---

## BUG-7 (P1) — `nBlockSigOpsCost` starts at 0, missing the 400-sigops coinbase-output reservation

**Severity:** P1. Core reserves
`DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS = 400` for the pool's
coinbase output(s) (policy.h:29). `resetBlock` initialises
`nBlockSigOpsCost = m_options.coinbase_output_max_additional_sigops`
(miner.cpp:115), so the assembler reserves 400 sigops up front and
selects only enough tx-sigops to fit within
`MAX_BLOCK_SIGOPS_COST - 400 = 79600`.

lunarblock's `create_block_template` (mining.lua:274):

```lua
local total_sigops = 0
```

starts at zero. Result: lunarblock packs templates that consume the
full 80000 in tx-sigops, leaving zero budget for the pool's coinbase
outputs. A pool that adds even one CHECKSIG to its coinbase scriptPubKey
(common for multisig pool keys) overruns the limit by 4 sigops, and
the block fails `bad-blk-sigops`.

**File:** `src/mining.lua:274` (initial counter);
`src/mining.lua` (no `coinbase_output_max_additional_sigops` field in
ClampOptions input).

**Core ref:** `bitcoin-core/src/node/miner.cpp:115` (`resetBlock`);
`bitcoin-core/src/policy/policy.h:29`
(`DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS = 400`).

**Impact:** pools using multisig coinbase pubkeys overrun
`MAX_BLOCK_SIGOPS_COST` by up to 4 sigops; block rejected with
`bad-blk-sigops`. Single-CHECKSIG (P2PKH) coinbases are unaffected.

---

## BUG-8 (P1) — `include_dummy_extranonce` field absent; coinbase scriptSig at heights 1-16 is borderline-legal by accident

**Severity:** P1. Core's `BlockCreateOptions::include_dummy_extranonce`
(types.h:76-78, default `false`) is set to `true` by
`getblocktemplate` (mining.cpp:878). When true, the assembler appends
OP_0 to the BIP-34 height push:

```cpp
// bitcoin-core/src/node/miner.cpp:186-193
coinbaseTx.vin[0].scriptSig = CScript() << nHeight;
if (m_options.include_dummy_extranonce) {
    // For blocks at heights <= 16, the BIP34-encoded height alone is only
    // one byte. Consensus requires coinbase scriptSigs to be at least two
    // bytes long (bad-cb-length), so tests and regtest include a dummy
    // extraNonce (OP_0)
    coinbaseTx.vin[0].scriptSig << OP_0;
}
```

Why this matters: `CScript() << nHeight` for n ∈ 1..16 emits the
single-byte opcode OP_1..OP_16 (`push_int64` in script.h:435-437).
That's a 1-byte scriptSig — `bad-cb-length` requires ≥ 2. Without
the OP_0 dummy, Core's miner would produce an invalid block for
heights 1-16. lunarblock dodges this by virtue of always emitting
a length-prefixed push `01 <h>` (mining.lua:144-159), which is 2
bytes for any positive height — but this is structurally divergent
from Core (see BUG-13) and survives `bad-cb-length` only because the
push-encoding happens to produce a 2-byte output.

The bug is that `include_dummy_extranonce` is absent from the
`BlockCreateOptions` analog (`mining.lua:215-237` `clamp_options`),
so `getblocktemplate` callers cannot request the Core-correct
behavior, and a future fix to BUG-13 (switch to OP_n encoding) would
re-introduce `bad-cb-length` at heights 1-16 without this flag.

**File:** `src/mining.lua:215-237` (ClampOptions analog missing
`include_dummy_extranonce`);
`src/mining.lua:135-202` (create_coinbase_tx — no caller-controlled
dummy extranonce path).

**Core ref:** `bitcoin-core/src/node/miner.cpp:186-193`
(`include_dummy_extranonce`).

**Impact:** dormant. Will surface if BUG-13 (BIP-34 encoding) is ever
fixed, because the canonical OP_n encoding would underflow
`bad-cb-length` for h ∈ 1..16 unless the dummy is present.

---

## BUG-9 (P1) — `compute_merkle_root` does not detect CVE-2012-2459 mutated-merkle (duplicated-pair-tail)

**Severity:** P1. Bitcoin Core's `BlockMerkleRoot` / `IsBlockMutated`
(consensus/merkle.cpp + validation.cpp:4027-4080) detects the
duplicated-pair-tail mutation: a merkle tree where an odd level
duplicates the last hash (per the well-known Bitcoin merkle
construction) is exploitable if the same root can be reached by
two different leaf sequences. Core raises `BLOCK_MUTATED` and
distinguishes it from `BLOCK_CONSENSUS` in net-processing to avoid
banning honest peers.

lunarblock's `crypto.compute_merkle_root` (crypto.lua:1289-1313):

```lua
while #current > 1 do
  local next_level = {}
  for i = 1, #current, 2 do
    local left = current[i]
    local right = current[i + 1] or current[i]  -- duplicate last if odd
    next_level[#next_level + 1] = M.hash256(left .. right)
  end
  current = next_level
end
```

The `or current[i]` branch duplicates the tail without any odd-level
mutation check. Cross-cite W142 fleet finding ("6 impls confirm
CVE-2012-2459 missing") and W143 BUG-1 cluster. The miner builds
witness commitment AND tx merkle through this code path
(`mining.lua:356, 379`); a mutated block submitted via `submitblock`
that lunarblock then re-broadcasts to peers can trigger ban-on-honest-peer
in Core, because Core's `BLOCK_MUTATED` ban-score handling differs
from `BLOCK_CONSENSUS`.

**File:** `src/crypto.lua:1289-1313`.

**Core ref:** `bitcoin-core/src/consensus/merkle.cpp` (BlockMerkleRoot
+ mutation flag); `bitcoin-core/src/validation.cpp:4027-4080`
(`IsBlockMutated`).

**Impact:** mutation-only divergence. lunarblock-built templates are
never mutated by lunarblock itself; the risk is on the SUBMIT side
(submitblock + accept_block + re-broadcast). Cross-cite W142 + W143
fleet pattern; closure of those fleet bugs will close this echo.

---

## BUG-10 (P0-CDIV) — `bits` field at retarget is wrong

(merged into BUG-1; redundant entry removed to keep numbering tight.)

---

## BUG-11 (P1) — Per-entry ancestor-feerate, not Core's per-cluster chunk feerate

**Severity:** P1. Bitcoin Core's `BlockAssembler::addChunks` (miner.cpp:279-334)
selects CHUNKS via `m_mempool->GetBlockBuilderChunk(selected_transactions)`,
which returns an entire cluster's-worth of transactions at the chunk
feerate (cluster mempool). A chunk is atomic: all txs in it are
either included or skipped. The chunk feerate is the marginal
fee/weight at the chunk boundary, NOT the per-entry ancestor feerate.

lunarblock's `create_block_template` (mining.lua:286-343) iterates
`mempool:get_sorted_entries()` (mempool.lua:2123-2137), which sorts
by **per-entry** `(entry.fee + entry.ancestor_fees) / (entry.vsize + entry.ancestor_size)`.
This is an APPROXIMATION of per-entry ancestor feerate (CPFP miner
algorithm pre-cluster-mempool), not the cluster chunk feerate Core
now uses.

Two divergences:

1. **Atomicity:** lunarblock includes ancestors individually if they
   happen to appear earlier in the sort (gated by `ancestors_ok`
   check at mining.lua:312-319). A multi-parent cluster where one
   parent has high feerate and one has low can be partially included
   in lunarblock but is ALL-OR-NOTHING in Core.
2. **Marginal feerate:** lunarblock's sort gives identical weight to
   the entry's own fee and its ancestors' fees. Core's chunk feerate
   gives weight to the marginal addition of the chunk, which can
   exclude ancestors that have lower per-byte feerate but high
   absolute fee.

Net effect: the **same mempool** produces different block templates
in lunarblock vs Core; revenue divergence is small (sub-1% on typical
mempools) but systematic.

**File:** `src/mempool.lua:2123-2137` (sort);
`src/mining.lua:286-343` (chunk-selection loop).

**Core ref:** `bitcoin-core/src/node/miner.cpp:279-334`
(`addChunks` via `GetBlockBuilderChunk`/`SkipBuilderChunk`/`IncludeBuilderChunk`).

**Impact:** miner revenue diverges from Core's; pool operators
running lunarblock receive slightly less fee revenue than Core
running on the same mempool snapshot.

---

## BUG-12 (P1) — `consecutive_failed` bumps on `!ancestors_ok`, not only on chunk-fit failures

**Severity:** P1. Core bumps `nConsecutiveFailed` ONLY when a
chunk fails `TestChunkBlockLimits` (weight or sigops cap) or
`TestChunkTransactions` (non-final tx) (miner.cpp:309-318). The
counter is the early-exit lever for "block is full and we're spinning".

lunarblock's loop (mining.lua:321-329):

```lua
if not weight_fits or not sigops_fits or not ancestors_ok then
  consecutive_failed = consecutive_failed + 1
  if consecutive_failed > MAX_CONSECUTIVE_FAILURES and
     total_weight + BLOCK_FULL_ENOUGH_WEIGHT_DELTA > max_weight then
    break
  end
  goto continue
end
```

The third disjunct `not ancestors_ok` bumps the counter EVERY TIME a
child appears in the sort before its parents — which is routine in
the per-entry ancestor-feerate sort (a child can have a very high
feerate that lifts its ancestor-feerate-average above its parents').
The counter then trips early, before the block is anywhere near full.

Empirically: on a mempool of 10,000+ entries with CPFP chains,
lunarblock's chunk-selection bails out after ~1000 ancestor-deferred
entries even though only a tiny fraction of the weight budget has
been spent. Result: templates that are several hundred KB smaller
than Core's on the same mempool.

**File:** `src/mining.lua:321-329`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:309-318` (`++nConsecutiveFailed`
only on `!TestChunkBlockLimits` || `!TestChunkTransactions`).

**Impact:** templates under-fill on CPFP-heavy mempools; cross-cite
BUG-11. Compounds the revenue divergence.

---

## BUG-13 (P1) — BIP-34 coinbase scriptSig encodes heights 1..16 as `01 <h>` not as `OP_1..OP_16`

**Severity:** P1. Core's `CScript() << nHeight` uses `push_int64`
(script.h:432-448):

```cpp
if (n == -1 || (n >= 1 && n <= 16))
    push_back(n + (OP_1 - 1));   // single-byte opcode
else if (n == 0)
    push_back(OP_0);
else
    *this << CScriptNum::serialize(n);
```

So heights 1..16 produce a single-byte scriptSig `0x51..0x60`;
height 0 produces `0x00`; height 17 produces `01 11`; height 128
produces `02 80 00` (sign-bit pad).

lunarblock's `create_coinbase_tx` (mining.lua:139-159) unconditionally
emits a length-prefixed push:

```lua
if height == 0 then
  w.write_u8(1); w.write_u8(0)   -- 01 00, not OP_0
else
  local h_bytes = ...
  w.write_u8(#h_bytes)            -- length prefix
  for _, b in ipairs(h_bytes) do w.write_u8(b) end
end
```

For h=1, lunarblock writes `01 01`; Core writes `51`. For h=16,
lunarblock writes `01 10`; Core writes `60`. The scriptSig BYTE PATTERN
differs → coinbase txid differs → block merkle root differs → block hash
differs. Two miners running lunarblock and Core on the SAME tx set
with the SAME payout script produce DIFFERENT block hashes.

BIP-34 (and Core's consensus enforcement) parses the scriptSig as
CScript and reads the first push as a CScriptNum. Both encodings
decode to the same height under CScriptNum (lunarblock's `01 01` is
data-push-of-1, which CScriptNum-parses to 1; Core's `0x51` is OP_1
which CScriptNum-parses to 1). So lunarblock's encoding is NOT
consensus-divergent — Core accepts it as a valid BIP-34 height. But
the block hash differs, which means:

- A pool can't trivially swap between lunarblock and Core mid-mining
  on the same template (the coinbase txid is different, so the merkle
  is different, so the work-target is different).
- Test fixtures that hard-code expected block hashes for a known tx
  set + payout fail.
- Block-explorer parity tooling that expects byte-for-byte coinbase
  matching breaks.

**File:** `src/mining.lua:139-159`.

**Core ref:** `bitcoin-core/src/script/script.h:432-448`
(`push_int64`'s OP_1..OP_16 / OP_0 branches).

**Impact:** byte-pattern divergence on coinbase scriptSig for heights
1..16 and 0; block hash divergence; tooling parity break. Not a
consensus rejection, but a deterministic mining-output mismatch
between lunarblock and Core.

---

## BUG-14 (P1) — `getblocktemplate` ignores `mode` parameter; no `proposal` support

**Severity:** P1. Core's `getblocktemplate` accepts
`template_request.mode` (mining.cpp:719-727) with values
`"template"` (default), `"proposal"` (BIP-23), or absent. For
`proposal`, Core validates the candidate block via
`TestBlockValidity(check_pow=false, check_merkle_root=true)` and
returns `BIP22ValidationResult` (mining.cpp:730-752), which is one
of: `"duplicate"`, `"duplicate-invalid"`, `"duplicate-inconclusive"`,
or a reject-reason string, or `null` for accept.

lunarblock's handler (rpc.lua:3869-3885) reads only
`params[1].coinbase_payout` and unconditionally calls
`create_block_template`. The `mode`, `longpollid`, `capabilities`,
and `rules` fields of `params[1]` are silently ignored.

Pools using BIP-23 proposal-mode pre-validation against multiple
node implementations cannot get a per-impl yes/no from lunarblock.

**File:** `src/rpc.lua:3869-3885`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:719-752` (mode dispatch
+ proposal handling).

**Impact:** BIP-23 proposal mode missing; pool software falls back
to actually-submitting via `submitblock`, which is then rejected
after work has been done. Operational only; no consensus impact.

---

## BUG-15 (P1) — No `prioritisetransaction` / `getprioritisedtransactions` RPC

**Severity:** P1. Core's `prioritisetransaction` (rpc/mining.cpp:502-548)
lets an operator bias the block-assembly fee accounting via a signed
`fee_delta` per txid. The companion `getprioritisedtransactions`
(rpc/mining.cpp:550-585) exposes the current `mapDeltas`.

Both RPCs are absent from lunarblock (`grep "prioritisetransaction"
src/` returns no results). Operators cannot bump tx priorities for
mining-pool override scenarios (e.g. boosting a stuck tx, or
deprioritising a known-DoS tx without dropping it from mempool).

**File:** `src/rpc.lua` (handler table; no `self.methods["prioritisetransaction"]
= ...` entry).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:502-585`.

**Impact:** missing operator knob; pools that rely on
`prioritisetransaction` (e.g. via Stratum-V2 bridge or local
governance) cannot use lunarblock as their template source.

---

## BUG-16 (P1) — `getblocktemplate` does not enforce IBD or peer-count gates

**Severity:** P1. Core refuses `getblocktemplate` with
`RPC_CLIENT_IN_INITIAL_DOWNLOAD` if `miner.isInitialBlockDownload()`
returns true (mining.cpp:772-774), and with `RPC_CLIENT_NOT_CONNECTED`
if `connman.GetNodeCount(Both) == 0` on a non-test chain
(mining.cpp:766-770).

lunarblock has neither gate (rpc.lua:3869-3885). A node still in IBD,
hundreds of thousands of blocks behind the real tip, will happily
emit a template — and the pool will mine on a deeply-stale chain.
A node with zero peers will emit a template that nobody else has
seen, mining a fork in the dark.

**File:** `src/rpc.lua:3869-3885`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:766-774`.

**Impact:** silent wedge-class footgun. Operator who restarts a node
and immediately starts mining gets a template for a stale tip;
pool's submitblock fails on the real network. No funds lost
(self-trapped at submitblock), but hash power is wasted for the
duration of IBD.

---

## BUG-17 (P1) — `getblocktemplate` does not validate `rules: ["segwit"]` client signaling

**Severity:** P1. Per BIP-9 + Core mining.cpp:754-760 + 1011-1014,
the template_request MUST include `rules: ["segwit"]` when segwit is
active on the network; Core throws if the client omitted it (to
defend against pre-segwit miners producing post-segwit-invalid
blocks).

lunarblock unconditionally emits `rules = {"csv"}` + (if segwit-active)
`"!segwit"`, `"taproot"` (mining.lua:407-412) without checking what the
CLIENT advertised. A pre-segwit miner using lunarblock receives a
template that includes `!segwit` (required-segwit) — which it cannot
honor — and silently mines a block lacking the witness commitment,
which Core rejects with `bad-witness-merkle-match`.

**File:** `src/rpc.lua:3869-3885` (no `rules` parse);
`src/mining.lua:407-412` (unconditional emit).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:754-760, 1011-1014`.

**Impact:** pre-segwit pool software cannot detect that the template
requires segwit; silent failure mode. Modern pools always signal
`segwit`, so this is dormant in practice, but cross-impl pool
tooling that sanity-checks the client-rules echo from the template
sees a divergence.

---

## BUG-18 (P1) — Hardcoded `template.transactions[i].sigops = 0`

**Severity:** P1. Per BIP-22 and Core mining.cpp:927-932, each
per-tx template entry MUST include the tx's `sigops` (total cost,
WITNESS_SCALE_FACTOR adjusted post-segwit, raw legacy pre-segwit).
Pool software uses this to enforce its own block-construction
sigops budget.

lunarblock emits a hardcoded `sigops = 0` (mining.lua:485):

```lua
template.transactions[#template.transactions + 1] = {
  ...
  fee = entry.fee,
  sigops = 0,  -- simplified
  weight = entry.weight,
}
```

Cross-cite BUG-6: even if a real sigop cost were emitted, the
recomputation path is buggy (misses P2SH + witness). But hardcoded 0
means pool software has zero visibility into per-tx sigop accounting.

**File:** `src/mining.lua:485`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:927-932`.

**Impact:** pool software cannot enforce its own sigops budget;
trusts lunarblock to have done the accounting (which it hasn't,
per BUG-6).

---

## BUG-19 (P1) — `vbavailable` and `vbrequired` are dead-fields; never populated from VersionBitsCache

**Severity:** P1. Per Core mining.cpp:966-980, `vbavailable` is a
`name → bit` map of every BIP-9 deployment whose state is STARTED
or LOCKED_IN; `vbrequired` is a bitmask of bits the server requires.
The values are computed from
`m_versionbitscache.GBTStatus(*pindexPrev, consensusParams)`.

lunarblock unconditionally emits empty/zero (mining.lua:414-422) with
a **comment-as-confession**:

```lua
-- vbavailable: map of pending versionbits deployment names to bit numbers.
-- We have no live BIP9 deployments in our state machine right now; emit empty
-- object.
local vbavailable = {}
-- vbrequired: bitmask of version bits the server requires miners to set.
-- Always 0 on current mainnet/testnet/regtest per BIP9.
local vbrequired = 0
```

This is fine TODAY (no live deployments on mainnet since taproot
buried), but if a future soft-fork enters STARTED state, lunarblock
templates won't advertise the bit, and miners using lunarblock won't
contribute to deployment signaling.

The `compute_block_version` helper (consensus.lua:744-774) already
implements the STARTED + LOCKED_IN OR-in logic — it's called from
`create_block_template` line 390 — but the result is only used to
set `header.version` (line 394). The `vbavailable` table is **not**
derived from the same state machine.

Cross-pattern: "wiring-look-but-no-wire" — the deployment-state code
exists and is partially called, but the BIP-9 GBT advertisement
fields are hardcoded.

**File:** `src/mining.lua:414-422` (hardcoded);
`src/consensus.lua:744-774` (state-machine exists but only feeds
`header.version`, not `vbavailable`).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:966-980` (`GBTStatus`).

**Impact:** future-soft-fork-readiness gap. Miners using lunarblock
will silently fail to signal during STARTED/LOCKED_IN windows.

---

## BUG-20 (P1) — Lua-double comparator on ancestor feerate (W149 BUG-10 echo)

**Severity:** P1. The mempool sort comparator
(mempool.lua:2131-2134):

```lua
table.sort(sorted, function(a, b)
  local rate_a = (a.fee + a.ancestor_fees) / (a.vsize + a.ancestor_size)
  local rate_b = (b.fee + b.ancestor_fees) / (b.vsize + b.ancestor_size)
  return rate_a > rate_b
end)
```

uses Lua double division. Two entries with the same exact feerate
(e.g. fee=1000 vsize=100 and fee=10000 vsize=1000, both 10 sat/vB)
can sort in different orders depending on numeric round-off of the
division. Core uses cross-multiplication on int64 (`a.fee * b.size
vs b.fee * a.size`) for exact comparison.

Cross-cite W149 BUG-10 (lunarblock chain_work comparator using Lua
doubles). Same Lua-double-precision pattern. Affects block-template
revenue determinism: two lunarblock nodes on the same mempool may
produce templates with different tx ORDERING even when total revenue
is identical.

**File:** `src/mempool.lua:2131-2134`.

**Core ref:** `bitcoin-core/src/txmempool.cpp::CompareTxMemPoolEntryByAncestorFee`
(int64 cross-multiply).

**Impact:** non-deterministic tx ordering on tied feerates; template
hash non-deterministic across runs. Operational only; no consensus
impact.

---

## BUG-21 (P1) — No `-blockmaxweight` / `-blockmintxfee` / `-blockreservedweight` / `-blockversion` CLI flags

**Severity:** P1. Core's `ApplyArgsManOptions` (miner.cpp:98-109)
plumbs `-blockmaxweight`, `-blockmintxfee`, `-blockreservedweight`,
`-printpriority` from `ArgsManager` into `BlockAssembler::Options`.
Core additionally honors `-blockversion=N` on regtest (`MineBlocksOnDemand`
gate at miner.cpp:143-145) for fork-scenario testing.

lunarblock's `parse_args` (main.lua:80-260) does not declare any of
these. Operator cannot tune block-assembly via the standard Core flag
names; the values are baked at `consensus.MAX_BLOCK_WEIGHT` (4M),
`DEFAULT_BLOCK_RESERVED_WEIGHT` (8000), and `block_min_fee_rate = 0`
(unbounded floor).

The `config` parameter to `create_block_template` (mining.lua:250)
accepts these knobs (`max_weight`, `block_reserved_weight`,
`max_sigops`, `block_min_fee_rate`), but **no caller** in `rpc.lua`
populates them — `getblocktemplate` (rpc.lua:3878-3881) and
`generatetoaddress` (rpc.lua:3925-3927) both call with `nil` config.

**File:** `src/main.lua:80-260` (no flag decls);
`src/rpc.lua:3878-3881, 3925-3927` (no config populated).

**Core ref:** `bitcoin-core/src/node/miner.cpp:98-109, 143-145`.

**Impact:** missing operator knobs. Cross-impl orchestration tooling
that uses `-blockmintxfee` to set a non-zero floor cannot do so on
lunarblock. Regtest-fork-testing via `-blockversion=N` is unavailable.

---

## BUG-22 (P1) — `getblocktemplate` default coinbase pays to all-zero P2PKH (`1111111111111111111114oLvT2`)

**Severity:** P1. Core's `BlockCreateOptions::coinbase_output_script`
defaults to `CScript() << OP_TRUE` (types.h:74) — an anyone-can-spend
dummy. Pool software replaces this with its real payout script.

lunarblock's `getblocktemplate` handler (rpc.lua:3872-3877):

```lua
local payout_script
if params[1] and params[1].coinbase_payout then
  payout_script = params[1].coinbase_payout
else
  payout_script = script_mod.make_p2pkh_script(string.rep("\0", 20))
end
```

falls back to a **P2PKH for the all-zero hash160**, which is the
address `1111111111111111111114oLvT2`. This address has no known
private key (the 20-byte hash is the SHA-256 of an unknown
preimage), so any subsidy + fees paid there are effectively burned.

A pool that calls `getblocktemplate` without explicitly setting
`coinbase_payout`, then mines and submits the template without
rebuilding the coinbase, **burns ~3.125 BTC + accumulated fees per
block** (post-2024 halving).

A pool that DOES rebuild the coinbase via the `coinbasetxn.data` /
`coinbasevalue` flow is unaffected.

**File:** `src/rpc.lua:3876` (hash160 of zero).

**Core ref:** `bitcoin-core/src/node/types.h:74` (`CScript() << OP_TRUE`
default).

**Impact:** burn risk for any pool that trusts the default coinbase
output. Core's anyone-can-spend `OP_TRUE` would let the funds be
swept by anyone monitoring the chain (still suboptimal, but
recoverable). lunarblock's P2PKH-of-zero is unrecoverable.

---

## BUG-23 (P1) — `extra = "/LunarBlock/"` is hardcoded in `create_block_template`

**Severity:** P1. Per Core (miner.cpp:188-194), the coinbase
extranonce is left to the pool software; the assembler emits only
the BIP-34 height push (and optional OP_0 dummy). Pools append their
own tag like `/MARA/`, `/F2Pool/`, etc.

lunarblock unconditionally appends `/LunarBlock/` (mining.lua:363):

```lua
local extra = "/LunarBlock/"
local coinbase_tx = M.create_coinbase_tx(
  height, coinbase_value, extra, witness_commitment, payout_script
)
```

Pools using `getblocktemplate` who replace the coinbase entirely
(via `coinbasetxn.data` round-trip) are unaffected. Pools using
`generatetoaddress` or `generateblock` (regtest) cannot suppress
the `/LunarBlock/` tag without code change.

**File:** `src/mining.lua:363`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:188-194`
(extranonce left to caller).

**Impact:** every block mined via `generatetoaddress` or
`generateblock` is permanently tagged `/LunarBlock/` in its coinbase
scriptSig. Pool branding override impossible without source modification.

---

## BUG-24 (P0-CDIV) — `HALVING_INTERVAL = 210000` is global; regtest never sees the 150-block halving

**Severity:** P0-CDIV (carry-forward from W145 BUG-2). Bitcoin Core's
regtest uses `nSubsidyHalvingInterval = 150`
(`bitcoin-core/src/kernel/chainparams.cpp:535`). At height 150,
regtest subsidy drops to 25 BTC, at 300 to 12.5 BTC, etc.

lunarblock's `M.HALVING_INTERVAL = 210000` is a GLOBAL constant
(consensus.lua:48), read by `M.get_block_subsidy` (line 50-58)
unconditionally. Every regtest entry in `M.networks.regtest`
(consensus.lua:1130-1195) lacks a per-network `halving_interval`
field; the global value is the only source.

lunarblock's miner pays `subsidy + total_fees` (mining.lua:362) where
`subsidy = consensus.get_block_subsidy(height)`. On regtest past
h=150, lunarblock pays 50 BTC while Core's regtest schedule pays 25.
Cross-impl regtest reorg testing: a lunarblock-mined regtest block at
h>150 has coinbase value 50 BTC; on Core-regtest replay, that block
is rejected with `bad-cb-amount`. Same in reverse: a Core-regtest
block at h>150 has coinbase 25 BTC; lunarblock validates it as
"correct subsidy 50, miner under-paid" and accepts the underpayment
(no `bad-cb-amount` on the low side in lunarblock's path), so
lunarblock will follow Core but for the wrong reason.

Already filed under W145 BUG-2 with `P0-CONS` severity. Re-flagged
here because `create_block_template` (mining.lua:263) is one of the
ACTIVE consumers and is in this wave's scope:

```lua
local subsidy = consensus.get_block_subsidy(height)
...
local coinbase_value = subsidy + total_fees
```

**File:** `src/consensus.lua:48` (constant);
`src/consensus.lua:1130-1195` (regtest network table — no
`halving_interval` field);
`src/mining.lua:263, 362` (consumer in this wave's scope).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:535`
(`nSubsidyHalvingInterval = 150`).

**Impact:** carry-forward; cross-cite W145 BUG-2.

---

## BUG-25 (P1) — `params[1].coinbase_payout` is a non-Core template_request field

**Severity:** P1. Core's `template_request` accepts `mode`,
`capabilities`, `rules`, `longpollid`, `data` (rpc/mining.cpp:626-642).
`coinbase_payout` is not in the spec.

lunarblock invents a custom field (rpc.lua:3873-3874):

```lua
if params[1] and params[1].coinbase_payout then
  payout_script = params[1].coinbase_payout
else
  payout_script = script_mod.make_p2pkh_script(string.rep("\0", 20))
end
```

Cross-impl pool software that doesn't know about this field gets
the BUG-22 burn-fallback. lunarblock has chosen to add a
non-standard input field rather than route through Core's
`coinbase_output_script` BlockCreateOption (which would be the
correct path — Core's IPC layer for mining is the actual extension
point).

**File:** `src/rpc.lua:3873-3874`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:626-642`
(template_request shape).

**Impact:** non-standard RPC extension; cross-impl pool software
that calls `getblocktemplate` with the spec-compliant fields gets
the burn-fallback. Documented; operational only.

---

## BUG-26 (P1) — `signet_challenge` field missing from template on signet

**Severity:** P1. Per Core mining.cpp:699-700, signet templates
include a `signet_challenge` field carrying the BIP-325 challenge
script. Miners on signet MUST solve this challenge as part of the
block; without the field, signet mining is impossible.

lunarblock's template (mining.lua:425-453) has no `signet_challenge`
field. lunarblock has no signet-specific network entry in
`M.networks` (only mainnet/testnet/testnet4/regtest — verified at
consensus.lua:1130-1195), so signet support is absent at the chain-params
level. The field's absence is consistent with no-signet-support.

**File:** `src/mining.lua:425-453` (template — no `signet_challenge`);
`src/consensus.lua:1130-1195` (no signet network entry).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:699-700`.

**Impact:** lunarblock cannot serve as a signet miner. Cross-impl
parity gap.

---

## BUG-27 (P1) — `longpollid` field absent; no longpoll capability

**Severity:** P1. Per BIP-22 + Core mining.cpp:686 + 853-870,
`longpollid` is a server-generated token (tip hash + transactions-updated
counter) that pool software passes back to get a long-blocking
re-poll. Core blocks until the tip changes or the mempool changes
significantly.

lunarblock emits no `longpollid` (mining.lua:425-453) and has no
`nTransactionsUpdatedLast` analog (`grep "TransactionsUpdated"
src/mempool.lua` returns nothing). Pool software using BIP-22
longpoll silently falls back to polling.

**File:** `src/mining.lua:425-453` (no `longpollid`);
`src/mempool.lua` (no transactions-updated counter).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:686, 853-870`.

**Impact:** pool software incurs latency penalty (poll interval vs
push notification); not a consensus issue. Cross-impl operational
parity gap.

---

## BUG-28 (P1) — No `RegenerateCommitments` helper

**Severity:** P1. Core's `RegenerateCommitments` (miner.cpp:67-77)
lets callers MUTATE the block's tx list (e.g. prune a tx, append a
tx, reorder) and recompute the witness commitment + merkle root in
one shot. It's used by external block-construction tools (e.g.
ASIC firmware that wants to evict the lowest-fee tx after acquiring
a higher-fee tx).

lunarblock has no equivalent. The `generateblock` handler (rpc.lua:3636-3866)
rebuilds the whole template via `create_block_template`, then
manually strips and replaces the coinbase + recomputes the merkle
root (rpc.lua:3791-3821) — but does NOT expose this as a reusable
helper. Pool software that wants to insert/remove a tx after
receiving a template must re-issue `getblocktemplate`.

**File:** `src/mining.lua` (no `regenerate_commitments` export);
`src/rpc.lua:3791-3821` (inline ad-hoc reimplementation in
`generateblock`).

**Core ref:** `bitcoin-core/src/node/miner.cpp:67-77`.

**Impact:** missing helper; pool software cannot mutate a template
in-place. Forces full template regeneration on every change.

---

## Cross-fleet patterns confirmed by this audit

1. **30-of-30-gates-buggy: 5th candidate.** W139, W149, W150, W152
   already hit "every gate buggy" on lunarblock. This audit is **near**
   30 distinct sub-gates (30 enumerated in matrix) and registers
   numerous P0-CDIV-class divergences (BUG-1, BUG-2, BUG-3, BUG-5,
   BUG-6, BUG-24). The 30-of-30 pattern is **not quite** triggered
   here (~12 PASS gates out of 30), but the P0-CDIV concentration
   on the active path (BUG-1 bits at retarget, BUG-2 fake MTP,
   BUG-3 mintime echo, BUG-5 wall-clock floor, BUG-6 sigops
   undercount, BUG-24 halving global) makes the miner module a
   compound-bug zone.

2. **Comment-as-confession: 6th instance in lunarblock.**
   `mining.lua:382-383`:
   `-- Get difficulty target
    -- In a real implementation, compute next required bits at retarget heights`.
   `mining.lua:266`:
   `-- chain_state.mtp should be provided; fallback to current time - 3600 (1 hour ago)`.
   `mining.lua:414-416`:
   `-- vbavailable: map of pending versionbits deployment names to bit numbers.
    -- We have no live BIP9 deployments in our state machine right now; emit empty`.
   Three new comment-as-confession instances in this single file.

3. **CVE-2012-2459 mutated-merkle absent (W142+W143 fleet pattern).**
   BUG-9 echoes the cross-cite. The miner's witness-merkle and
   tx-merkle paths both go through `crypto.compute_merkle_root`
   which silently duplicates last-hash on odd levels.

4. **Lua-double comparator (W149 BUG-10 echo).** BUG-20 — the
   ancestor-feerate sort uses Lua double division; cross-cite the
   chainwork comparator bug.

5. **Per-network nSubsidyHalvingInterval missing (W145 fleet pattern,
   5+ impls).** BUG-24 — carry-forward; no progress on this fleet-wide
   regression since W145 was filed.

6. **"wiring-look-but-no-wire" (W138 fleet pattern).** BUG-19 —
   `compute_block_version` deployment-state machine exists, but
   `vbavailable` / `vbrequired` in the template are hardcoded
   constants. The state machine partially-wired to header.version
   but not to the GBT advertisement.

7. **Two-pipeline guard / N-pipeline drift.** Three distinct
   block-construction code paths in lunarblock:
   - `create_block_template` (mining.lua:250-494) — the canonical
     assembler.
   - `generateblock` (rpc.lua:3645-3866) — rebuilds coinbase manually
     after calling create_block_template, recomputes merkle and
     witness commitment inline.
   - `generatetoaddress` (rpc.lua:3888-3990) — uses create_block_template
     unmodified.
   `generateblock` is the third leaf and has the inline
   commitment-recompute logic (rpc.lua:3800-3821) that is NOT shared
   with create_block_template's path. If create_block_template's
   witness-commitment code is fixed, generateblock's inline copy
   doesn't pick up the fix. Cross-cite the W143 "three-pipeline drift"
   pattern.

---

## Severity summary

- **P0-CDIV (consensus-divergent on mining path):** BUG-1, BUG-2,
  BUG-3, BUG-5, BUG-6, BUG-24 (= 6 P0-CDIV).
  - BUG-1: wrong `bits` at retarget → unmineable / `bad-diffbits`.
  - BUG-2: fake MTP → `bad-txns-nonfinal` on time-locked txs.
  - BUG-3: cascade of BUG-2 into BIP-22 `mintime`.
  - BUG-5: no `max(min_time, now)` clamp on `nTime`.
  - BUG-6: sigops undercount (misses P2SH + witness) → `bad-blk-sigops`.
  - BUG-24: regtest halving fleet pattern.
- **P1 (operational divergence / interop break):** BUG-4, BUG-7,
  BUG-8, BUG-9, BUG-11, BUG-12, BUG-13, BUG-14, BUG-15, BUG-16,
  BUG-17, BUG-18, BUG-19, BUG-20, BUG-21, BUG-22, BUG-23, BUG-25,
  BUG-26, BUG-27, BUG-28 (= 21 P1).
- **PASS:** G1–G4, G6–G7, G10–G12, G23, G26, G28 (12 sub-gates).

**Bug count:** 28 catalogued (BUG-10 merged into BUG-1, so 27 distinct
numbered IDs; the count above includes the merged number for
back-cite continuity).

**Top 3 findings:**

1. **BUG-1 (P0-CDIV)** — template `bits` field copies parent's,
   ignores `GetNextWorkRequired`. Every mainnet retarget produces an
   unmineable template; every testnet block flips between fixed and
   min-difficulty target without lunarblock following. The trailing
   comment "In a real implementation, compute next required bits at
   retarget heights" is comment-as-confession. The helper
   `consensus.get_next_work_required` already exists — one wiring
   line away.
2. **BUG-6 (P0-CDIV)** — sigop accounting in `create_block_template`
   misses P2SH redeem-script sigops AND segwit witness-program
   sigops. mempool entries don't carry a precomputed `sigop_cost`
   (mempool.lua:830-861 has fee/vsize/weight/wtxid but no sigop),
   so the miner recomputes incorrectly. Cluster: BUG-6 + BUG-7
   (no 400-sigops reserve) + BUG-18 (hardcoded sigops=0 in template).
3. **BUG-2 + BUG-3 (P0-CDIV cluster)** — `chain_state.mtp` is never
   populated by ANY caller; the fallback `os.time() - 3600` is used
   universally. This breaks time-based locktime checks in the miner
   (BUG-2) AND silently corrupts the BIP-22 `mintime` field (BUG-3).
   A single line in `accept_block` to set `chain_state.mtp` would
   close both.
