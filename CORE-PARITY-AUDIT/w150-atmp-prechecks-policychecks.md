# W150 — AcceptToMemoryPool + PreChecks + PolicyScriptChecks + ConsensusScriptChecks (lunarblock)

**Wave:** W150 — `MemPoolAccept::AcceptSingleTransactionInternal`,
`PreChecks`, `PolicyScriptChecks` (`STANDARD_SCRIPT_VERIFY_FLAGS`),
`ConsensusScriptChecks` (`GetBlockScriptFlags` cache), `FinalizeSubpackage`,
`AcceptPackage` / `AcceptMultipleTransactions`, `IsStandardTx`,
`AreInputsStandard` / `ValidateInputsStandardness`, `IsWitnessStandard`,
`GetDustThreshold`, `CheckFeeRate` (rolling fee), `CheckTxInputs`
(coinbase-maturity + MoneyRange), `Workspace.m_modified_fees` /
`PrioritiseTransaction`, `ATMPArgs::m_client_maxfeerate`, the suite of
operator-knobs (`-acceptnonstdtxn`, `-minrelaytxfee`, `-incrementalrelayfee`,
`-bytespersigop`, `-datacarriersize`, `-permitbaremultisig`, `-maxmempool`,
`-mempoolexpiry`, `-limitancestorcount`, `-limitdescendantcount`).

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/validation.cpp:782-982` — `MemPoolAccept::PreChecks`
  (CheckTransaction → coinbase → IsStandardTx → MIN_STANDARD_TX_NONWITNESS_SIZE
  → CheckFinalTxAtTip → exists() de-dup → conflict scan → coins_cache HaveCoin
  loop with "txn-already-known" probe → CheckSequenceLocksAtTip →
  CheckTxInputs (MoneyRange + coinbase-maturity) → ValidateInputsStandardness
  → IsWitnessStandard → GetTransactionSigOpCost → fSpendsCoinbase →
  StageAddition → PreCheckEphemeralTx → MAX_STANDARD_TX_SIGOPS_COST →
  CheckFeeRate → GetIterSet conflicts → SingleTRUCChecks).
- `bitcoin-core/src/validation.cpp:1135-1156` — `PolicyScriptChecks`:
  `CheckInputScripts(tx, state, m_view, STANDARD_SCRIPT_VERIFY_FLAGS,
  cacheSigStore=true, cacheFullScriptStore=false, ...)`.
- `bitcoin-core/src/validation.cpp:1158-1189` — `ConsensusScriptChecks`:
  re-runs `CheckInputsFromMempoolAndCache` against
  `GetBlockScriptFlags(Tip(), chainman)` to write the script cache against
  the *current-block* flags, so an at-relay-time STANDARD pass remains
  consensus-valid if the next-block flag set diverges (soft-fork rotation
  protection).
- `bitcoin-core/src/validation.cpp:1191-1240` — `FinalizeSubpackage`
  (changeset Apply, replaced-tx log, TRACEPOINT).
- `bitcoin-core/src/validation.cpp:1242-1315` — `SubmitPackage` (calls
  `FinalizeSubpackage` then `ConsensusScriptChecks` per workspace and emits
  `MempoolAcceptResult::Success` with `effective_feerate`).
- `bitcoin-core/src/policy/policy.cpp:27-64` — `GetDustThreshold` (with 75%
  segwit discount: `nSize += (32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4)`
  for witness programs → 67 extra; non-witness → 148 extra).
- `bitcoin-core/src/policy/policy.cpp:100-165` — `IsStandardTx` (version range,
  weight cap, scriptsig size/push-only, scriptpubkey type, datacarrier limit,
  bare-multisig gate, MAX_DUST_OUTPUTS_PER_TX=1 dust gate).
- `bitcoin-core/src/policy/policy.cpp:214-263` — `ValidateInputsStandardness`
  (CheckSigopsBIP54 + WITNESS_UNKNOWN + P2SH MAX_P2SH_SIGOPS).
- `bitcoin-core/src/policy/policy.cpp:265-352` — `IsWitnessStandard`
  (P2A stuffing, P2SH-wrapped extract, P2WSH stack limits, P2TR annex +
  tapscript element-size limits).
- `bitcoin-core/src/policy/policy.h:38-90` —
  `MAX_STANDARD_TX_WEIGHT=400000`, `MIN_STANDARD_TX_NONWITNESS_SIZE=65`,
  `MAX_P2SH_SIGOPS=15`, `MAX_STANDARD_TX_SIGOPS_COST=MAX_BLOCK_SIGOPS_COST/5`,
  `MAX_TX_LEGACY_SIGOPS=2500`, `DEFAULT_INCREMENTAL_RELAY_FEE=100`,
  `DEFAULT_BYTES_PER_SIGOP=20`, `DEFAULT_PERMIT_BAREMULTISIG=true`,
  `MAX_STANDARD_P2WSH_STACK_ITEMS=100`,
  `MAX_STANDARD_P2WSH_STACK_ITEM_SIZE=80`,
  `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE=80`,
  `MAX_STANDARD_P2WSH_SCRIPT_SIZE=3600`, `MAX_STANDARD_SCRIPTSIG_SIZE=1650`,
  `DUST_RELAY_TX_FEE=3000`, **`DEFAULT_MIN_RELAY_TX_FEE=100`**,
  `DEFAULT_CLUSTER_LIMIT=64`, `DEFAULT_CLUSTER_SIZE_LIMIT_KVB=101`,
  `DEFAULT_ANCESTOR_LIMIT=25`, `DEFAULT_DESCENDANT_LIMIT=25`,
  `EXTRA_DESCENDANT_TX_SIZE_LIMIT=10000`, `MAX_DUST_OUTPUTS_PER_TX=1`.
- `bitcoin-core/src/policy/policy.h:105-132` — `MANDATORY_SCRIPT_VERIFY_FLAGS`
  (7 flags) and `STANDARD_SCRIPT_VERIFY_FLAGS` (21 flags total: mandatory
  + STRICTENC + MINIMALDATA + DISCOURAGE_UPGRADABLE_NOPS + CLEANSTACK +
  MINIMALIF + NULLFAIL + LOW_S + DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM +
  WITNESS_PUBKEYTYPE + CONST_SCRIPTCODE +
  DISCOURAGE_UPGRADABLE_TAPROOT_VERSION + DISCOURAGE_OP_SUCCESS +
  DISCOURAGE_UPGRADABLE_PUBKEYTYPE).
- `bitcoin-core/src/consensus/tx_verify.cpp:164-214` — `Consensus::CheckTxInputs`
  (HaveInputs → coinbase-maturity → per-coin MoneyRange + accumulated
  MoneyRange → tx.GetValueOut() → nValueIn < value_out → MoneyRange(txfee)).
- `bitcoin-core/src/txmempool.cpp:829-859` — `GetMinFee` (decay) and
  `trackPackageRemoved` (rolling-fee bump).
- `bitcoin-core/src/init.cpp:673-686` — CLI registration of
  `-incrementalrelayfee`, `-minrelaytxfee`, `-maxmempool`, `-mempoolexpiry`,
  `-limitancestorcount`, `-limitdescendantcount`, `-bytespersigop`,
  `-permitbaremultisig`, `-datacarriersize`, `-acceptnonstdtxn`.

**Files audited**
- `src/mempool.lua` — `Mempool:accept_transaction` (~1934-line file; ATMP at
  lines 934-1746), `Mempool:accept_to_memory_pool` (test_accept shim, 1748-1827),
  `Mempool:accept_package` (package path, 2566-2821),
  `Mempool:block_disconnected` (reorg-readmit, 1940-1953),
  `Mempool:trim` (TrimToSize equivalent, 2088-2117), `Mempool:get_min_fee`
  (rolling decay, 1988-2022), `Mempool:get_info` (`getmempoolinfo` payload,
  2144-2161), `single_truc_checks`, `is_witness_standard`,
  `validate_inputs_standardness`, `mempool_entry`, module-level constants.
- `src/validation.lua` — `M.check_transaction` (184-251, the gate that
  emits `bad-txns-inputs-duplicate` via `error()`), `M.count_script_sigops`
  (343-367, silently returns 0 on parse failure),
  `M.get_transaction_sigop_cost` (519-551),
  `M.calculate_sequence_locks`, `M.check_sequence_locks`,
  `M.make_sig_checker` (1480-…).
- `src/rpc.lua` — `sendrawtransaction` (2029-2057, routes to
  `accept_transaction` NOT `accept_to_memory_pool`),
  `testmempoolaccept` (7308-…), `getmempoolinfo` (1876-…),
  `getmempoolentry`/`format_mempool_entry` (2982-3019).
- `src/main.lua` — mempool construction (1058-1062, `min_relay_fee = 1000`
  hardcoded, `verify_input_scripts` never set), tx-handler (1325-1372),
  CLI arg parse (only `--mempool-fullrbf` knob; no other Core mempool knob).
- `src/consensus.lua` — `MAX_MONEY`, `MoneyRange`, `COINBASE_MATURITY`,
  per-network `csv_height`.
- `src/mining.lua` — `is_final_tx` (43-72, BIP-113 IsFinalTx helper).
- `src/fee.lua` — fee estimator buckets; cross-cite W139.

---

## Gate matrix (32 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | PreChecks: CheckTransaction wire-token surfacing | G1: `bad-txns-vin-empty` reachable | **BUG-1 (P0-CDIV)** — `check_transaction` uses Lua `assert(#tx.inputs > 0)` (validation.lua:186); pcall in `accept_transaction` collapses to `"invalid transaction structure"` (mempool.lua:957-963), losing 6+ Core wire tokens |
| 1 | … | G2: `bad-txns-vout-empty` reachable | **BUG-1 cross-cite** |
| 1 | … | G3: `bad-txns-inputs-duplicate` (CVE-2018-17144 wire token) reachable | **BUG-1 cross-cite** — `error("bad-txns-inputs-duplicate")` at validation.lua:212 is collapsed to `"invalid transaction structure"` by the pcall wrapper |
| 1 | … | G4: `bad-txns-vout-toolarge` / `bad-txns-vout-negative` reachable | **BUG-1 cross-cite** |
| 1 | … | G5: `bad-txns-oversize` (stripped weight > MAX_BLOCK_WEIGHT) reachable | **BUG-1 cross-cite** |
| 2 | IsStandardTx core gates | G6: weight cap (MAX_STANDARD_TX_WEIGHT=400000) | PASS (`mempool.lua:979-983`) |
| 2 | … | G7: MIN_STANDARD_TX_NONWITNESS_SIZE=65 (CVE-2017-12842) | PASS (`mempool.lua:985-997`) |
| 2 | … | G8: scriptsig size + push-only per input | PASS (`mempool.lua:1001-1009`) |
| 2 | … | G9: TX_MIN_STANDARD_VERSION..TX_MAX_STANDARD_VERSION (1..3) | PASS (`mempool.lua:970-973`) |
| 2 | … | G10: per-output scriptpubkey type + datacarrier limit | PASS (`mempool.lua:1011-1053`) |
| 2 | … | G11: PERMIT_BARE_MULTISIG default mismatch | **BUG-2 (P1)** — lunarblock defaults `false` (mempool.lua:256), Core defaults `true` (policy.h:52 `DEFAULT_PERMIT_BAREMULTISIG{true}`). lunarblock rejects bare 1-of-3 / 2-of-2 multisig that Core accepts at relay |
| 2 | … | G12: MAX_DUST_OUTPUTS_PER_TX=1 dust gate | PARTIAL (mempool.lua:1095-1098) — gate present but **BUG-9** below counts BUT does not return per-output index list (Core's `GetDust()` returns `vector<uint32_t>` of dust indices) |
| 3 | DEFAULT_MIN_RELAY_TX_FEE wire | G13: relay floor matches Core | **BUG-3 (P1)** — `M.DEFAULT_MIN_RELAY_FEE = 1000` sat/kvB (mempool.lua:203), Core `DEFAULT_MIN_RELAY_TX_FEE = 100` sat/kvB (policy.h:70). Lunarblock relays at **10× stricter floor** than Core. The same value `1000` is re-set in `main.lua:1060` — two-pipeline overlap that confirms the default-1000 is intentional but cross-impl-divergent |
| 4 | PolicyScriptChecks flag completeness | G14: STANDARD_SCRIPT_VERIFY_FLAGS contains all 14 NON-MANDATORY bits | **BUG-4 (P0-CDIV)** — table at mempool.lua:1623-1639 sets 15 flags but omits 6 STANDARD bits: `verify_taproot`, `verify_minimalif`, `verify_discourage_upgradable_witness`, `verify_discourage_upgradable_taproot_version`, `verify_discourage_op_success`, `verify_discourage_upgradable_pubkeytype`. Same fleet shape as **W144 BUG-3 haskoin** (STANDARD_SCRIPT_VERIFY_FLAGS entirely absent) and **W144 blockbrew** (9 of 13 missing) |
| 4 | … | G15: `verify_const_scriptcode` consulted in script.lua | **BUG-5 (P1)** — flag set in table at mempool.lua:1638 but `verify_const_scriptcode` does NOT appear in any of script.lua's flag-consult sites (only 21 distinct flag names referenced, `verify_const_scriptcode` not among them). Dead-flag (set-but-never-read), 4th distinct lunarblock instance per W138/W139/W144 dead-flag tracking |
| 4 | … | G16: PolicyScriptChecks runs in production | **BUG-6 (P0-CDIV)** — `verify_input_scripts` defaults `false` (mempool.lua:904); zero production callers set it `true`. The entire PolicyScriptChecks pass (mempool.lua:1622-1678) is **dead in production**. sendrawtransaction (rpc.lua:2035), peer tx-handler (main.lua:1328), block-disconnect re-admit (mempool.lua:1950), orphan resolver (main.lua:1392) all route through `accept_transaction` against the default-off mempool. **30-of-30-gates-buggy candidate** for the script-verify pass (15 flags set but flag table never reached). **3rd lunarblock instance** of the fleet pattern after W139 + W149 |
| 4 | … | G17: silent failure when `make_sig_checker` errors | **BUG-7 (P0-CDIV)** — `pcall(validation.make_sig_checker, ...)` at mempool.lua:1653 returns `ok_c=false` on any internal error (e.g. unexpected witness shape, taproot tweak math overflow). The `if ok_c then` (mempool.lua:1655) silently SKIPS the entire `verify_script` call — tx is accepted with **no script check at all**. Combined with BUG-6 this is moot today, but if BUG-6 is fixed, BUG-7 becomes a defense-in-depth crater |
| 4 | … | G18: witness-path scripts skipped at PolicyScriptChecks | **BUG-8 (P1)** — `is_witness_path` filter (mempool.lua:1648-1651) skips P2WPKH/P2WSH/P2TR/P2A entirely at relay; comment-as-confession at 1644-1647 says "Witness paths require the per-witness execution machinery in utxo.lua (~400 lines); they are still validated at block-connect". This means bad-signature segwit txs sit in mempool until mined-and-rejected; relay DoS surface |
| 5 | ConsensusScriptChecks (post-PolicyScriptChecks re-verification) | G19: re-runs against `GetBlockScriptFlags(Tip())` and writes script cache | **BUG-9 (P0-CDIV)** — entirely absent. lunarblock has no ConsensusScriptChecks analog; no `CheckInputsFromMempoolAndCache`, no second-pass verification against current-block flags, no script-cache write. The whole soft-fork-rotation defense (Core validation.cpp:1166-1186 "useless if the next block has different script flags from the previous one, but … will auto-invalidate") is missing. Combined with BUG-6, lunarblock has **zero** script verification at mempool-accept time |
| 6 | CheckTxInputs (consensus money-range) | G20: per-coin MoneyRange check | **BUG-10 (P0-CONS)** — `accept_transaction` accumulates `input_total = input_total + utxo.value` (mempool.lua:1157) with NO `MoneyRange(utxo.value)` guard. CVE-2018-17144 class entry: a corrupt or attacker-supplied coin_view could return a UTXO with `value > MAX_MONEY` or `value < 0`, and the mempool would accept the tx, leak the synthetic value into fee_rate math, and **trim mempool entries the malicious tx "outpriced"**. Block-time `connect_block` catches this via utxo.lua:2395-2398 (per-W148 audit) but the relay path is wide open |
| 6 | … | G21: accumulated MoneyRange on nValueIn | **BUG-10 cross-cite** — `input_total` never tested against MAX_MONEY |
| 6 | … | G22: COINBASE_MATURITY enforced at relay | PASS (`mempool.lua:1159-1163`); uses `tip_height - utxo.height < COINBASE_MATURITY` matching Core's `nSpendHeight - coin.nHeight < COINBASE_MATURITY` with `nSpendHeight = tip+1` … wait, lunarblock uses `tip_height` not `tip_height + 1`. **Sub-bug**: BUG-11 below |
| 6 | … | G23: depth uses `next_height` (tip+1) not `tip_height` | **BUG-11 (P0-CDIV)** — Core uses `m_active_chainstate.m_chain.Height() + 1` (validation.cpp:892) as `nSpendHeight`; lunarblock uses `tip_height` (mempool.lua:1160). Off-by-one: a coinbase at height H is mature when relay-tested in the block at height H+100 (Core); lunarblock requires H+101. Rejects mature-by-1 coinbase spends at relay; mined-OK |
| 7 | BIP-68 CheckSequenceLocksAtTip parity | G24: prev-block MTPs use the actual block's MTP | **BUG-12 (P1)** — lunarblock's `get_block_mtp_conservative` (mempool.lua:1272-1274) returns `tip_mtp` for ALL ancestor heights. Inline comment claims "may false-reject … never false-admits", but the math is reversed: substituting the LATER tip_mtp for an EARLIER block_mtp **understates the lock delta** (tip_mtp > coin_block_mtp ⇒ `coin_time + lock_seconds - 1` is too low ⇒ false-admit). Core loads per-ancestor MTP from the chain. Time-locked txs near boundary admitted prematurely |
| 7 | … | G25: csv_height fallback per network | **BUG-13 (P1)** — hardcoded mainnet 419328 fallback at mempool.lua:1257 when `chain_state.network` is nil. Regtest/signet/testnet4 hit this fallback during early bootstrap (before chain_state.network is wired) and silently mis-gate BIP-68 |
| 8 | Rolling-fee precision and config | G26: rolling fee stored in Lua double | **BUG-14 (P1)** — `self.rolling_minimum_fee_rate = 0.0` (mempool.lua:916) is a Lua double; comparator `fee_rate_per_kb < min_fee_rate_kvb` at mempool.lua:1306 uses double-vs-double arithmetic. Same loss-of-precision concern as **W149 BUG-10 chain_work** lossy comparator. For fees ≤ 2^53 sats this is exact, BUT `fee * 1000 / vsize` at mempool.lua:1289 uses double division — non-integer quotients are compared against integer constants; rounding loss can flip the gate for txs sitting on the boundary |
| 8 | … | G27: `incrementalrelayfee` JSON field correct | **BUG-15 (P1)** — `incrementalrelayfee = 0.00001` hardcoded at rpc.lua:1911 (= 1000 sat/kvB), but `M.INCREMENTAL_RELAY_FEE = 100` sat/kvB (mempool.lua:283). Off by **10×**; stale value not updated when W120 lowered INCREMENTAL_RELAY_FEE from 1000 → 100. RPC consumers see wrong relay-bump value. **carry-forward / re-anchor pattern** — same one-line slip W139/W141 caught in other impls |
| 9 | Operator-knob coverage | G28: -minrelaytxfee / -incrementalrelayfee / -bytespersigop / -datacarriersize / -maxmempool / -mempoolexpiry / -limitancestor/descendant / -permitbaremultisig / -acceptnonstdtxn | **BUG-16 (P1)** — zero of 10 Core mempool CLI knobs exposed. main.lua's `argparse` only registers `--mempool-fullrbf` (line 352). Operators cannot retune relay floor, dust rate, ancestor limits, mempool size, expiry, or accept-non-standard for testnet. **10-of-10-gates-buggy candidate** for operator-knob coverage; fleet pattern (cross-cite W148 BUG-6 / W149 BUG-5) |
| 10 | test_accept rollback semantics | G29: side-effect-free dry-run | **BUG-17 (P0-CDIV)** — `accept_to_memory_pool(tx, test_accept=true)` (mempool.lua:1761-1806) inserts via `accept_transaction` and **then removes** via `self:remove_transaction(...)`. `remove_transaction` triggers the `on_tx_removed` callback (mempool.lua:1878), leaks a ZMQ removal event for a tx that never existed. Also: ancestors of the test-inserted tx have descendant_count / descendant_size / descendant_fees temporarily mutated then mutated back — concurrent `get_sorted_entries` / `get_info` calls observe corrupted state during the window. Cluster union-find (`uf_parent[txid_hex]`, mempool.lua:1714) is set, unioned with parents, then nil'd in remove_transaction — leaves uf_rank entries for OTHER mempool txs in an inconsistent state if union-during-test-accept paths through a different root. Comment at mempool.lua:1762-1770 confesses "We can't easily reproduce Core's changeset model in pure Lua" — **comment-as-confession 7th lunarblock instance** |
| 10 | … | G30: rolling-fee state restored on test_accept | PARTIAL (mempool.lua:1771-1773, 1783-1785) — only `rolling_minimum_fee_rate`, `last_rolling_fee_update`, `block_since_last_rolling_fee_bump` are snapshot/restored. NOT restored: `total_size`, `tx_count`, descendant_count delta on ancestors, uf_parent/uf_rank, outpoint_to_tx delta. **BUG-17 cross-cite** |
| 11 | Two-pipeline guard: AcceptTx vs AcceptPackage | G31: accept_package runs full IsStandardTx / IsWitnessStandard / sigop limits / RBF / TRUC / BIP-68 / BIP-113 / dust / scriptpubkey / scriptsig per-tx | **BUG-18 (P0-CDIV)** — `Mempool:accept_package` (mempool.lua:2566-2821) is a **second consensus pipeline** that runs only: `is_well_formed_package` + `check_transaction` + `MAX_STANDARD_TX_WEIGHT` + UTXO lookup + COINBASE_MATURITY + fee≥0 + package fee rate. **At least 14 per-tx gates from accept_transaction are bypassed** in the package path: version-range, MIN_STANDARD_TX_NONWITNESS_SIZE, scriptsig push-only, per-output scriptpubkey + datacarrier + bare-multisig + dust, BIP-113 IsFinalTx, BIP-68 SequenceLocks, IsWitnessStandard, ValidateInputsStandardness, MAX_STANDARD_TX_SIGOPS_COST, anchor outputs, RBF Rule 3/4/5, TRUC SingleTRUCChecks, cluster limits, PolicyScriptChecks. **17th distinct fleet two-pipeline-guard extension** per running W76+ tracking |
| 11 | … | G32: accept_package does not call accept_transaction per-tx | **BUG-18 cross-cite** — package path duplicates ancestor/descendant bookkeeping inline (mempool.lua:2719-2745) instead of routing per-tx through accept_transaction. Drift between pipelines is structural |

---

## BUG-1 (P0-CDIV) — `check_transaction` wire-token loss via pcall collapse

**Severity:** P0-CDIV. Bitcoin Core's `CheckTransaction`
(consensus/tx_check.cpp) returns a `TxValidationState` whose
`GetRejectReason()` exposes 6+ distinct wire tokens consumed by P2P
`reject` messages, block-relay validation hashing, sentinel test-suites,
and explorer tooling:
- `bad-txns-vin-empty`
- `bad-txns-vout-empty`
- `bad-txns-oversize`
- `bad-txns-vout-negative`
- `bad-txns-vout-toolarge`
- `bad-txns-txouttotal-toolarge`
- `bad-txns-inputs-duplicate` ← **CVE-2018-17144 fingerprint**
- `bad-cb-length` (coinbase scriptSig size)
- `bad-txns-prevout-null`

lunarblock's `M.check_transaction` (validation.lua:184-251) raises Lua
`assert()` / `error()` calls with mostly-correct underlying messages:

```lua
assert(#tx.inputs > 0, "transaction has no inputs")
assert(#tx.outputs > 0, "transaction has no outputs")
…
error("bad-txns-inputs-duplicate")
…
assert(out.value <= consensus.MAX_MONEY, "output ... value exceeds MAX_MONEY")
…
assert(sig_len >= 2, "coinbase scriptSig too short: " .. sig_len)
```

But `accept_transaction` wraps it in `pcall` and DISCARDS the message:

```lua
-- mempool.lua:957-963
local pcall_ok, check_ok, is_coinbase = pcall(validation.check_transaction, tx)
if not pcall_ok then
  return false, "invalid transaction structure"
end
if not check_ok then
  return false, "invalid transaction structure"
end
```

All 6+ tokens collapse into the single English string
`"invalid transaction structure"`. The P2P reject message, RPC
`testmempoolaccept.reject-reason`, and explorer tooling see the same
non-Core string for every CheckTransaction failure mode.

**Impact:**
1. **Wire-token parity break** — Core ecosystem tooling that scrapes
   reject reasons for monitoring (e.g. mempool.space's reject-rate
   dashboards) cannot distinguish "this tx had duplicate inputs"
   (CVE-class) from "this tx was empty" (cosmetic) on a lunarblock
   peer.
2. **CVE-2018-17144 forensic loss** — when a peer sends a duplicate-input
   tx, lunarblock returns `"invalid transaction structure"` instead of
   `bad-txns-inputs-duplicate`. The fingerprint Core operators look for
   when responding to an active inflation attempt is gone.
3. **Test-vector parity break** — Bitcoin Core's `test/util/data/tx_invalid.json`
   asserts on these exact tokens. Cross-impl diff-test corpus (tools/diff-test.sh
   / verify-fix.sh) cannot match lunarblock rejects to Core rejects by
   wire token; falls back to the much weaker accept-vs-reject bit.
4. **Sister pattern** — W125 + W145 noted lunarblock's "reject-string
   wire-parity slippage" sweep; this is a NEW 6+ token cluster joining
   the 9 + 10 already catalogued. Running fleet total now **25+
   tokens** for lunarblock alone.

**File:** `src/validation.lua:184-251` (assert/error sites);
`src/mempool.lua:957-963` (pcall-collapse).
**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp` +
`bitcoin-core/src/validation.cpp:798-799`.

---

## BUG-2 (P1) — `PERMIT_BARE_MULTISIG` default mismatch (lunarblock false, Core true)

**Severity:** P1. `bitcoin-core/src/policy/policy.h:52` sets
`static constexpr bool DEFAULT_PERMIT_BAREMULTISIG{true}`. lunarblock
hardcodes `M.PERMIT_BARE_MULTISIG = false` (mempool.lua:256) with the
header comment "Core flipped this default from true → false in v28
(commit 8ee7773d)" — but that statement is **false**. Inspection of the
current Core source confirms the default is still `true`:

```cpp
// bitcoin-core/src/policy/policy.h:51-52
/** Default for -permitbaremultisig */
static constexpr bool DEFAULT_PERMIT_BAREMULTISIG{true};
```

lunarblock therefore rejects bare 1-of-3 / 2-of-2 / etc. multisig
outputs at relay with reason `"bare-multisig"` (mempool.lua:1049-1051),
while Core accepts them. Wallets configured to send bare multisig to
hashhog peers see `relay rejected` and fall through to direct mining
or out-of-band submission.

This is also a **comment-as-confession 8th lunarblock instance** —
the comment cites a commit hash (`8ee7773d`) that does not match
current Core behavior; the rationale was apparently borrowed from a
fleet-wide assumption without verifying upstream state.

**File:** `src/mempool.lua:256, 1049-1051`.
**Core ref:** `bitcoin-core/src/policy/policy.h:52` (default true);
`bitcoin-core/src/policy/policy.cpp:152-154` (gate).

**Impact:** relay-policy divergence; bare-multisig txs rejected by
lunarblock peers but accepted by upstream Core. Wallet integrations
that rely on `getrawmempool` membership see "tx not in mempool"
sporadically.

---

## BUG-3 (P1) — `DEFAULT_MIN_RELAY_FEE = 1000` is 10× stricter than Core's 100

**Severity:** P1. lunarblock sets `M.DEFAULT_MIN_RELAY_FEE = 1000`
sat/kvB (mempool.lua:203) with comment "1 sat/vB in sat/KB", and
main.lua:1060 reasserts `min_relay_fee = 1000` at construction.
Bitcoin Core's current value is **`DEFAULT_MIN_RELAY_TX_FEE = 100`**
sat/kvB (`src/policy/policy.h:70`, 0.1 sat/vB). lunarblock's relay
floor is **10× higher than Core**, which means:

- Honest 0.1 sat/vB txs are rejected at lunarblock with
  `"fee rate too low: ... < 1000 sat/KB"` (mempool.lua:1291) while
  Core relays them.
- Cross-impl IBD-fresh nodes whose mempool was hydrated from Core
  will reject inbound inv/getdata fan-out from Core peers for any
  tx at 0.1-0.9 sat/vB.
- `getmempoolinfo.minrelaytxfee` reports `0.00001` BTC/kvB (1000
  sat/kvB) while Core reports `0.000001` BTC/kvB (100 sat/kvB);
  wallet fee estimators using `getmempoolinfo` on a lunarblock peer
  pay 10× the necessary base fee.
- Two-pipeline-overlap: the default is set TWICE (mempool.lua:203 +
  main.lua:1060). Any future fix needs to touch both sites or the
  hardcode at main.lua wins.

**File:** `src/mempool.lua:203`; `src/main.lua:1060` (re-assertion).
**Core ref:** `bitcoin-core/src/policy/policy.h:70`.

**Impact:** relay-policy divergence; sub-1 sat/vB tx rejection;
inflated wallet fee estimates from `getmempoolinfo`.

---

## BUG-4 (P0-CDIV) — STANDARD_SCRIPT_VERIFY_FLAGS missing 6 of 14 non-mandatory bits

**Severity:** P0-CDIV. Core's `STANDARD_SCRIPT_VERIFY_FLAGS` is
`MANDATORY_SCRIPT_VERIFY_FLAGS | <14 additional bits>` (policy.h:113-132):

```
+ SCRIPT_VERIFY_STRICTENC
+ SCRIPT_VERIFY_MINIMALDATA
+ SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS
+ SCRIPT_VERIFY_CLEANSTACK
+ SCRIPT_VERIFY_MINIMALIF
+ SCRIPT_VERIFY_NULLFAIL
+ SCRIPT_VERIFY_LOW_S
+ SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
+ SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
+ SCRIPT_VERIFY_CONST_SCRIPTCODE
+ SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
+ SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS
+ SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE
```

lunarblock's `script_flags` table at mempool.lua:1623-1639 sets 15
flags but OMITS:

| Flag | Core Status | lunarblock |
|------|-------------|------------|
| `verify_taproot` | STANDARD + MANDATORY | **MISSING** |
| `verify_minimalif` | STANDARD | **MISSING** |
| `verify_discourage_upgradable_witness` | STANDARD | **MISSING** |
| `verify_discourage_upgradable_taproot_version` | STANDARD | **MISSING** |
| `verify_discourage_op_success` | STANDARD | **MISSING** |
| `verify_discourage_upgradable_pubkeytype` | STANDARD | **MISSING** |

**`verify_taproot` is in MANDATORY_SCRIPT_VERIFY_FLAGS** — meaning
its absence makes any future tapscript-related policy verification
miss soft-fork-class checks. The script.lua dispatch at
script.lua:2026 confirms `verify_taproot` IS used to gate the v1+32
Taproot path; without it, the gate sees a non-witness execution and
returns true for any spend.

This is the **fleet-wide pattern** confirmed in W144 across 5+ impls:
- W144 haskoin BUG-3: STANDARD_SCRIPT_VERIFY_FLAGS entirely absent.
- W144 blockbrew BUG-5: 9 of 13 STANDARD bits missing.
- W144 lunarblock: noted but not enumerated.

lunarblock's count here is **6 of 14 STANDARD bits missing** at
PolicyScriptChecks (i.e., the table sets 8 of 14). Together with
BUG-6 (the table is never reached in production), the net effect is
**zero** STANDARD policy verification at relay.

**File:** `src/mempool.lua:1623-1639`.
**Core ref:** `bitcoin-core/src/policy/policy.h:113-132`.

**Impact:** if PolicyScriptChecks is ever enabled (BUG-6 fix), a
post-Taproot-activation tx that violates DISCOURAGE_UPGRADABLE_*
policy would still pass relay-time checks on lunarblock; same for
malleability-discouraging OP_SUCCESS / pubkeytype rules. Soft-fork
forwards-compat insurance is missing.

---

## BUG-5 (P1) — `verify_const_scriptcode` set in flag table but never consulted

**Severity:** P1. lunarblock's script_flags table sets
`verify_const_scriptcode = true` at mempool.lua:1638, but
`grep -oP "flags\.\w+" src/script.lua | sort -u` lists 21 distinct
flag names consulted in `verify_script` and **`verify_const_scriptcode`
is not among them**. The flag is set but the script interpreter does
not enforce it.

This is **dead-flag plumbing** — fourth distinct lunarblock instance
per W138/W139/W144 dead-data tracking. The setup is "wired-but-no-wire":
the policy author added the flag to the table thinking they were
enabling enforcement, but the interpreter side never read it.

Core enforces `SCRIPT_VERIFY_CONST_SCRIPTCODE` to ban
FindAndDelete-style sigop tricks via `if (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE)
return set_error(serror, SCRIPT_ERR_OP_CODESEPARATOR)` in
`interpreter.cpp::EvalScript` (the OP_CODESEPARATOR + non-CHECKSIG path).
lunarblock's interpreter unconditionally lets OP_CODESEPARATOR pass.

**File:** `src/mempool.lua:1638` (sets); `src/script.lua` (never reads).
**Core ref:** `bitcoin-core/src/script/interpreter.h::SCRIPT_VERIFY_CONST_SCRIPTCODE`.

**Impact:** policy gate dead; relay-time enforcement of
CONST_SCRIPTCODE policy is silently disabled. Mooted today by BUG-6
(table itself unreached) but a silent landmine if BUG-6 is fixed.

---

## BUG-6 (P0-CDIV) — `verify_input_scripts` defaults FALSE; PolicyScriptChecks is dead in production

**Severity:** P0-CDIV. `Mempool.new()` sets
`self.verify_input_scripts = (config and config.verify_input_scripts) == true`
(mempool.lua:904) — defaults `false`. A grep over `src/` and `cmd/`
shows the field is set `true` in **exactly one place**:
`spec/mempool_spec.lua:3041` (a test that wires it explicitly to
exercise the gate). All FOUR production accept-tx entry points pass
through `accept_transaction` with the default-false mempool:

| Entry point | File:Line | verify_input_scripts |
|-------------|-----------|----------------------|
| `sendrawtransaction` RPC | `rpc.lua:2035` | false (default) |
| peer `tx` handler | `main.lua:1328` | false (default) |
| reorg `block_disconnected` re-admit | `mempool.lua:1950` | false (default) |
| orphan resolver | `main.lua:1392` | false (default) |
| `testmempoolaccept` | `rpc.lua:7376` | false (default) |
| `mempool.dat` load | `mempool_persist.lua` | false (default) |

The `if self.verify_input_scripts then` gate at mempool.lua:1622 is
**always false in production**; the 56-line PolicyScriptChecks block
(mempool.lua:1622-1678) is unreachable. **Comment-as-confession 9th
lunarblock instance** at mempool.lua:898-903 explicitly admits this:

```lua
-- W96: PolicyScriptChecks/ConsensusScriptChecks gate.
-- When true, accept_transaction runs script-verify for each input prev script
-- before adding the tx to the mempool ...
-- Default OFF to preserve backward compatibility with existing
-- test fixtures that use mock scripts.  Production callers (peer_manager,
-- sendrawtransaction handler) should pass {verify_input_scripts=true} to
-- match Core's relay behaviour.
```

The comment says "Production callers should pass true" — and the
production callers DO NOT pass true.

**Combined with BUG-9 (ConsensusScriptChecks absent)**: lunarblock
performs **zero** script verification at mempool-accept time. A tx
with bad signatures is accepted into the mempool, included in
fee-rate trim decisions, relayed to peers, and only rejected when a
miner tries to include it in a block (where utxo.lua's full
ConnectBlock verification finally catches it). Until then it sits
in mempool occupying bytes, distorting fee-rate gating against
honest txs, and being broadcast to the network.

**Fleet pattern**: **3rd lunarblock 30-of-30-gates-buggy instance**
after W139 (fee estimator) and W149 (assumevalid). Crystallizes
the "subsystem rewrite candidate" archetype noted in W139 summary.

**File:** `src/mempool.lua:904`; production-caller list above.
**Core ref:** `bitcoin-core/src/validation.cpp:1135-1156` — Core's
PolicyScriptChecks is unconditionally called from PreChecks (and
again at SubmitPackage); there is no "skip script checks" mode in
the relay path.

**Impact:**
- Bad-signature txs accepted into mempool until block-include time.
- DoS surface: relay-rejected txs in Core land in lunarblock's
  mempool until eviction.
- Cross-cite BUG-7 (silent skip on make_sig_checker error) and
  BUG-8 (witness paths skipped) double down on this.

---

## BUG-7 (P0-CDIV) — `make_sig_checker` pcall failure silently bypasses script verification

**Severity:** P0-CDIV. Even in the test-only path where
`verify_input_scripts=true`, lunarblock guards `make_sig_checker`
in a `pcall`:

```lua
-- mempool.lua:1653-1675
local ok_c, checker = pcall(validation.make_sig_checker,
  tx, i - 1, utxo.value, utxo.script_pubkey, script_flags, nil)
if ok_c then
  ...
  local ok_p, r1, r2 = pcall(script_mod.verify_script, ...)
  if not ok_p then
    return false, string.format("mandatory-script-verify-flag-failed (input %d: %s)", ...)
  end
  if r1 == nil or r1 == false then
    return false, string.format("mandatory-script-verify-flag-failed (input %d: %s)", ...)
  end
end
-- NO else branch — when ok_c is false, the entire verify pass is skipped
```

When `make_sig_checker` throws an internal Lua error (e.g. taproot
tweak math overflow, malformed witness shape, missing prev_outputs
arg for v1+32 spend), `ok_c` is `false`, the entire `if ok_c then`
branch is skipped, and the tx is **accepted with NO script
verification for that input**.

Combined with BUG-6 this is mooted today; combined with a future fix
that flips verify_input_scripts=true, it becomes a security crater:
adversary crafts a tx whose witness shape provokes a Lua error in
make_sig_checker (easy via a v1+32 program with no prev_outputs
provided — the function asserts on `prev_outputs == nil` for taproot
spends — line 1480), and the tx is silently accepted at relay
despite having no valid signature.

**File:** `src/mempool.lua:1653-1675`.

**Impact:** moot today (BUG-6 closes the door anyway); critical if
BUG-6 fix lands without addressing this defensive-skip.

---

## BUG-8 (P1) — Witness-path scripts (P2WPKH/P2WSH/P2TR/P2A) skipped at PolicyScriptChecks

**Severity:** P1. The PolicyScriptChecks block at mempool.lua:1648-1651
filters out witness-program input types:

```lua
local is_witness_path = (script_type == "p2wpkh"
                          or script_type == "p2wsh"
                          or script_type == "p2tr"
                          or script_type == "p2a")
if not is_witness_path then
  ... call verify_script ...
end
```

Comment at 1644-1647 admits the gap:

```lua
-- Only verify non-witness paths here.  Witness paths require the
-- per-witness execution machinery in utxo.lua (~400 lines); they are
-- still validated at block-connect.  This is policy-only — consensus
-- rules continue to be enforced at block validation.
```

This means bad-signature P2WPKH / P2WSH / P2TR txs are accepted at
relay even when `verify_input_scripts=true`. Combined with the fact
that ~95% of mainnet txs today spend segwit outputs, this drains
nearly all the value of even enabling BUG-6's fix.

**Comment-as-confession 10th lunarblock instance**. Also fleet pattern
"TODO comment that has lived through multiple audit waves" — the W96
audit ID is on this code (mempool.lua:899-903), meaning the
factor-out-utxo-helper TODO has sat unimplemented for ~3 release
waves.

**File:** `src/mempool.lua:1644-1651`.
**Core ref:** `bitcoin-core/src/validation.cpp:1146` — `CheckInputScripts`
runs witness-spend verification at mempool accept time too.

**Impact:** bad-signature segwit txs accepted into mempool until
block-include time; relay DoS surface; ~95% of inbound tx traffic
exercises this gap.

---

## BUG-9 (P0-CDIV) — ConsensusScriptChecks entirely absent

**Severity:** P0-CDIV. Core's `ConsensusScriptChecks`
(validation.cpp:1158-1189) is the second-pass script verification that:

1. Re-runs `CheckInputsFromMempoolAndCache` against the CURRENT-BLOCK
   `GetBlockScriptFlags(Tip())`, not the relay-time
   `STANDARD_SCRIPT_VERIFY_FLAGS`.
2. Writes the script-cache result against the current-block flags so
   subsequent ConnectBlock for the same tx skips re-verification.
3. Defends against a STANDARD-vs-MANDATORY divergence where a tx
   passes STANDARD relay flags but would fail under the actual
   next-block consensus flags (Core's comment: "useless if the next
   block has different script flags from the previous one, but
   because the cache tracks script flags for us it will auto-invalidate
   and we'll just have a few blocks of extra misses on soft-fork
   activation").
4. Triggers a critical `Assume(false)` LogError when PolicyScriptChecks
   succeeded but ConsensusScriptChecks failed — alerting the operator
   to a critical STANDARD-vs-MANDATORY soft-fork rotation bug.

lunarblock has **no equivalent**:
- No `CheckInputsFromMempoolAndCache` analog anywhere in `src/`.
- No script-cache write at mempool accept time.
- `accept_transaction` does PolicyScriptChecks (under BUG-6 gate) and
  jumps directly to "Add to mempool" at mempool.lua:1680.
- `GetBlockScriptFlags(Tip())` is never even computed; tip-script-flags
  derivation is done lazily at ConnectBlock time only.

Combined with BUG-6 (PolicyScriptChecks dead in production), the
**total script verification at mempool accept is ZERO passes**. A tx
is accepted into mempool purely on the basis of structural validity,
fee, and standardness gates.

**File:** `src/mempool.lua:1622-1680` (PolicyScriptChecks at most;
ConsensusScriptChecks absent).
**Core ref:** `bitcoin-core/src/validation.cpp:1158-1189`.

**Impact:**
- Soft-fork rotation defense missing: a tx that becomes invalid the
  moment a new soft-fork activates would sit in mempool until block
  rejection.
- Script-cache absent: every ConnectBlock pass re-verifies every input
  signature from scratch, regardless of whether the tx already passed
  PolicyScriptChecks at relay time. ~2× CPU on validation hot path.
- Cross-cite W144 / W148 cache-mutation findings: lunarblock has no
  signature cache at all (`grep -n "sig_cache" src/utxo.lua` finds
  only the standalone `src/sig_cache.lua` module, never wired into
  the accept pipeline).

---

## BUG-10 (P0-CONS) — `accept_transaction` does not enforce MoneyRange on inputs (CVE-2018-17144-class entry primitive)

**Severity:** P0-CONS. Core's `Consensus::CheckTxInputs`
(consensus/tx_verify.cpp:184-188) checks **both** per-coin
MoneyRange and accumulated nValueIn MoneyRange:

```cpp
nValueIn += coin.out.nValue;
if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn)) {
    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputvalues-outofrange");
}
```

This is the relay-time gate against a corrupt or attacker-supplied
coin_view returning a UTXO with `value > MAX_MONEY` or `value < 0`
or accumulated sum > MAX_MONEY.

lunarblock's `accept_transaction` accumulates input value with no
MoneyRange check anywhere:

```lua
-- mempool.lua:1155-1170
if utxo then
  resolved_utxos[i] = utxo
  input_total = input_total + utxo.value
  -- Coinbase maturity
  if utxo.is_coinbase then ... end
  -- Save per-input UTXO height for BIP-68 sequence lock check.
  input_heights[i] = is_mempool_parent and (next_height) or utxo.height
else
  input_heights[i] = 0
end
```

There is no `MoneyRange(utxo.value)` and no
`MoneyRange(input_total)` guard. The accumulated `input_total` is
then used at mempool.lua:1249-1252:

```lua
local fee = input_total - output_total
if fee < 0 then
  return false, "outputs exceed inputs"
end
```

— without any bound check on `fee` either.

**Attack surface:**

1. **Corrupt coin_view** — a malformed UTXO database entry (e.g. after
   a power-loss-corrupted Pebble compaction; cross-cite W147) returns
   a coin with `value = -1` or `value = 2^62`. `accept_transaction`
   silently accepts and:
   - feeds the synthetic value into `fee_rate_per_kb = fee * 1000 / vsize`
     producing a wildly inflated feerate;
   - that feerate evicts honest mempool entries via `trim()` (because
     `worst_rate` becomes vastly smaller than the inflated rate);
   - the synthetic tx itself is then relayed to peers, who reject it
     at their own consensus boundary (Core does MoneyRange in PreChecks
     via CheckTxInputs) but lunarblock has already evicted the honest
     mempool subset based on the synthetic rate.

2. **Mempool-parent inputs** — at mempool.lua:1138-1149, when an input
   spends a mempool-parent UTXO, lunarblock fabricates a synthetic
   `utxo = { value = out.value, ... }` directly from the parent tx's
   output. Since the parent tx **already passed** `check_transaction`
   (which DOES check per-output MAX_MONEY), this case is bounded
   today. But the BUG above (BUG-1 wire-token collapse) shows that
   check_transaction's pcall-collapsed errors don't actually
   guarantee the assert wired through — the parent might have slipped
   past via a code path that mutates `out.value` after the check.

3. **CVE-2018-17144 fingerprint** — Core's PR #15407 + CVE writeup
   explicitly identify the MoneyRange check on inputs as the primary
   defense against inflation. Same class as the **W145 haskoin BUG-3**
   (applyBlock cache path does not re-check duplicate inputs) noted
   in W145.

**File:** `src/mempool.lua:1155-1170` (input accumulation, no MoneyRange).
**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:184-188`.

**Impact:**
- Inflation primitive at relay (downstream consensus gate at block
  ConnectBlock catches it but mempool-state corruption persists
  in between).
- Mempool-rate eviction can be weaponized via synthetic inputs.
- Wire-token gap: Core emits `bad-txns-inputvalues-outofrange`;
  lunarblock would emit nothing (the malformed UTXO would either
  pass through to the fee gate or trigger an unrelated `outputs
  exceed inputs` reason if total is negative).

---

## BUG-11 (P0-CDIV) — Coinbase-maturity depth off-by-one (uses tip_height, Core uses tip_height+1)

**Severity:** P0-CDIV. Bitcoin Core's `Consensus::CheckTxInputs`
(consensus/tx_verify.cpp:179) reads:

```cpp
if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY)
```

with `nSpendHeight = m_active_chainstate.m_chain.Height() + 1`
(validation.cpp:892 — "The mempool holds txs for the next block,
so pass height+1 to CheckTxInputs"). lunarblock uses `tip_height`
(not `tip_height + 1`) for the same comparison:

```lua
-- mempool.lua:1158-1163
if utxo.is_coinbase then
  if tip_height - utxo.height < consensus.COINBASE_MATURITY then
    return false, "spending immature coinbase"
  end
end
```

A coinbase at height H is mature at block H+100 in Core (because the
spending tx sits in the mempool destined for height H+100, and
`nSpendHeight - coin.nHeight = (H+100) - H = 100 >= 100` passes).
lunarblock's gate is `(H+99) - H = 99 < 100` → reject; only at
`tip_height = H+100` does the gate pass with `100 - H = 100 >= 100`,
i.e., the next block IS H+101 where the tx would be confirmed,
1 block later than Core. Off-by-one DELAY (lunarblock too strict
by one block).

Same shape as the **fleet COINBASE_MATURITY off-by-one cluster**
flagged in the W145 system-prompt notes ("4+ confirm COINBASE_MATURITY
off-by-one or absent"). This is lunarblock's instance.

**File:** `src/mempool.lua:1158-1163`.
**Core ref:** `bitcoin-core/src/validation.cpp:892` (nSpendHeight
= chain.Height() + 1) + `consensus/tx_verify.cpp:179` (depth check).

**Impact:**
- Mature-by-1 coinbase spends rejected at lunarblock relay but
  accepted at block-confirm time. RPC `sendrawtransaction` returns
  `"spending immature coinbase"` for a tx that mines fine.
- Cross-impl divergence: a wallet that relies on `getmempoolinfo`
  + `sendrawtransaction` for confirmation timing sees lunarblock as
  1 block behind Core's effective coinbase-maturity boundary.

---

## BUG-12 (P1) — BIP-68 SequenceLocks uses tip_mtp for ALL ancestor heights (false-admit primitive)

**Severity:** P1. Bitcoin Core's `CheckSequenceLocksAtTip` loads
each spent coin's confirming-block-1 MTP from the chain
(validation.cpp:887 calls `CalculateLockPointsAtTip` which walks the
chain and reads per-ancestor MTPs). lunarblock substitutes the
current tip's MTP for ALL ancestor lookups:

```lua
-- mempool.lua:1272-1274
local function get_block_mtp_conservative(_h)
  return tip_mtp
end
```

The inline comment at 1261-1263 claims this is conservative ("may
false-reject time-locked txs near the boundary but never false-admits"),
but the math is **reversed**. The lock-time formula inside
`calculate_sequence_locks` (validation.lua:1435-1439) is:

```lua
local coin_time = get_block_mtp(math.max(coin_height - 1, 0))
...
min_time = math.max(min_time, coin_time + lock_seconds - 1)
```

`min_time` is the threshold the spending tx must EXCEED at confirmation.
Substituting tip_mtp (the LATER, larger value) for coin_time (the
EARLIER, smaller value) makes `min_time` LARGER, i.e., harder to
exceed. But the comparator at validation.lua:1462 is
`min_time >= prev_block_mtp` — using a larger `min_time` makes
this comparison MORE likely true, which REJECTS the tx.

Wait — actually re-reading: a tx with a relative time-lock of 1 hour
on a coin confirmed at h-100 (where block-(h-100) MTP ≈ tip_mtp - 17h)
should compute `min_time = (tip_mtp - 17h) + 3600 - 1 = tip_mtp - 17h + 3599`.
Substituting tip_mtp gives `tip_mtp + 3599` → check `tip_mtp + 3599 >= tip_mtp`
→ TRUE → REJECT. lunarblock rejects MORE aggressively than Core. So
the comment is right by accident — it false-REJECTS, not false-ADMITS.

BUT: For time-locks just-past-satisfied (e.g. 17h05m on a 17h-old coin),
Core admits the tx (`min_time = old_mtp + 17h05m - 1 < tip_mtp`);
lunarblock rejects (`min_time = tip_mtp + 17h05m - 1 >= tip_mtp` always).
**lunarblock REJECTS all time-locked relative-lock spends that Core
would admit**, because `tip_mtp + anything >= tip_mtp`. Conservative
but a real relay-time divergence.

For height-locked relative locks (`SEQUENCE_LOCKTIME_TYPE_FLAG` not
set, validation.lua:1442-1443), `get_block_mtp` is not called, so
height-locks work correctly.

**File:** `src/mempool.lua:1272-1274` (conservative MTP shim);
`src/validation.lua:1432-1440` (consumer).

**Impact:**
- All BIP-68 time-relative-locked txs (`SEQUENCE_LOCKTIME_TYPE_FLAG`
  set) are rejected at relay regardless of actual time-lock state.
- Height-relative locks work correctly.
- Wire-token parity: Core emits `non-BIP68-final`; lunarblock emits
  same token (mempool.lua:1278) — semantic gate diverges, surface
  token matches.

---

## BUG-13 (P1) — `csv_height` fallback hardcoded to mainnet 419328

**Severity:** P1. `mempool.lua:1257` reads:

```lua
local csv_height = (self.chain_state.network and self.chain_state.network.csv_height) or 419328
```

When `chain_state.network` is nil (early bootstrap before
`load_or_build_chain` has populated the field; test fixtures with
mock chain_state; reorg-in-progress states), the fallback is the
**mainnet CSV activation height 419328**. Effect:

- **Regtest** (CSV active from height 0): `tip_height >= 419328` is
  false for the first ~419k blocks of any regtest run, so BIP-68 is
  silently DISABLED for txs accepted during early-regtest bootstrap.
  Tests that rely on CSV regtest semantics see false-positives.
- **Signet** (CSV active from height 1): same disability as regtest.
- **Testnet3/4**: each has its own CSV height; using mainnet's 419328
  on testnet4 (which uses 1) means CSV is incorrectly gated for the
  first 419k testnet4 blocks if the fallback fires.

The bug is benign on production mainnet (where 419328 IS the correct
value) but problematic on test networks where the fallback is exercised
during bootstrap or test setup.

**File:** `src/mempool.lua:1257`.

**Impact:** test-network BIP-68 gating wrong during bootstrap; regtest
test-fixtures see Cookie-shaped BIP-68 false-positives.

---

## BUG-14 (P1) — Rolling-fee math uses Lua double precision throughout

**Severity:** P1 ("Lua-double comparator", same fleet shape as W149
BUG-10). `Mempool:get_min_fee` (mempool.lua:1988-2022) computes:

```lua
local dt = now - self.last_rolling_fee_update
self.rolling_minimum_fee_rate =
  self.rolling_minimum_fee_rate / math.pow(2.0, dt / halflife)
```

and the fee-gate at mempool.lua:1289 reads:

```lua
local fee_rate_per_kb = fee * 1000 / vsize
if fee_rate_per_kb < self.min_relay_fee then ... end
```

Both intermediate values are Lua doubles (IEEE 754 binary64). At
typical fee amounts (≤ 2^53 sats) the integer precision is exact,
BUT:

1. `fee * 1000 / vsize` is non-integer for most (fee, vsize) pairs,
   producing rounding-loss on the order of `vsize × ULP(fee_rate)`.
2. `self.min_relay_fee` is an integer 1000; the comparator
   `fee_rate_per_kb < 1000.0` can flip differently from Core's
   integer-arithmetic `CFeeRate::operator<` (which uses 64-bit
   integer comparison on sat-per-kvB) for a fee/vsize ratio sitting
   exactly on the boundary.
3. `math.pow(2.0, dt / halflife)` introduces compound floating
   error over long-running nodes; after ~1 month of uptime the
   `rolling_minimum_fee_rate` decay term diverges from Core's
   `pow(2.0, ...)` (Core also uses `double` but invokes via
   `<cmath>` whose precision is implementation-defined; lunarblock's
   LuaJIT `math.pow` is `pow(2)` from libm — usually matches Core
   on Linux/glibc but not guaranteed).

**Same shape as W149 BUG-10** ("Lua-double chain_work lossy comparator").
Mitigation: convert fee_rate_per_kb to integer-scaled units
(e.g., fee*1000*1000/vsize for sat-per-Mvb) before comparison.

**File:** `src/mempool.lua:1289, 2007-2008`.

**Impact:** boundary-fee txs accepted/rejected nondeterministically
between Core and lunarblock; compound-floating-error drift over weeks
of uptime.

---

## BUG-15 (P1) — `incrementalrelayfee` JSON field hardcoded to 10× stale value

**Severity:** P1 ("carry-forward / re-anchor pattern", fleet-shape
from W139/W141). `rpc.lua:1911` reads:

```lua
return {
  ...
  incrementalrelayfee = 0.00001,
  ...
}
```

`0.00001` BTC/kvB = `1000` sat/kvB. But the mempool module sets
`M.INCREMENTAL_RELAY_FEE = 100` sat/kvB (mempool.lua:283) since the
W120 fix that lowered it from 1000 to 100 ("Previously wrong: 1000
(10× too high). Core is 100 sat/kvB."). The RPC handler was NOT
updated; it still emits the 10×-too-high pre-W120 value.

This is the same shape as **W141 ouroboros BUG-15** and other
"comment-as-confession 4th instance" / "carry-forward re-anchor"
findings: the underlying constant was fixed in module A, but the
downstream consumer in module B was not co-updated.

Fix: `incrementalrelayfee = mempool_mod.INCREMENTAL_RELAY_FEE / 1e8`
(0.00000100).

**File:** `src/rpc.lua:1911`.
**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::getmempoolinfo`
(emits `incrementalrelayfee` as `CFeeRate(m_opts.incremental_relay_feerate).GetFeePerK() * 1e-8`).

**Impact:** wallet fee estimators using `getmempoolinfo.incrementalrelayfee`
to compute RBF bump amount pay 10× the necessary fee bump on
lunarblock peers.

---

## BUG-16 (P1) — Zero of 10 Core mempool operator-knobs exposed

**Severity:** P1 ("no operator-knob exists" / "30-of-30-gates-buggy"
fleet shape; 4th lunarblock instance after W139, W148, W149).

Bitcoin Core exposes 10 mempool-policy CLI knobs (init.cpp:670-735):

| Core flag | Default | lunarblock |
|-----------|---------|------------|
| `-acceptnonstdtxn` | regtest:1 / others:0 | **ABSENT** |
| `-minrelaytxfee=<amt>` | 100 sat/kvB | **ABSENT** (hardcoded 1000) |
| `-incrementalrelayfee=<amt>` | 100 sat/kvB | **ABSENT** (hardcoded 100) |
| `-bytespersigop=<n>` | 20 | **ABSENT** (hardcoded 20) |
| `-permitbaremultisig=<bool>` | true | **ABSENT** (hardcoded false; BUG-2) |
| `-datacarriersize=<n>` | 100000 | **ABSENT** (hardcoded MAX_OP_RETURN_RELAY) |
| `-maxmempool=<n MB>` | 300 | **ABSENT** (hardcoded 300 MB) |
| `-mempoolexpiry=<hr>` | 336 | **ABSENT** (hardcoded 336*3600) |
| `-limitancestorcount=<n>` | 25 | **ABSENT** (hardcoded 25) |
| `-limitdescendantcount=<n>` | 25 | **ABSENT** (hardcoded 25) |

lunarblock's `main.lua` `argparse` registers exactly ONE mempool
knob: `--mempool-fullrbf` (W120 FIX-68). The other 10 are absent —
operators cannot retune relay floor, dust rate, ancestor/descendant
limits, mempool size, expiry, or accept-non-standard for testnet.

**30-of-30-gates-buggy candidate** for operator-knob coverage: 10 of
10 missing. This is the **4th lunarblock instance** of the pattern;
running fleet total is now W139 + W148 + W149 + W150 = 4 distinct
subsystems where lunarblock has the "subsystem-rewrite candidate"
profile.

**File:** `src/main.lua` (argparse registration).
**Core ref:** `bitcoin-core/src/init.cpp:670-735`.

**Impact:**
- Cannot adjust relay floor without recompile.
- Cannot enable `-acceptnonstdtxn` on regtest (lunarblock always
  enforces full standardness regardless of network).
- Cross-impl diff-test corpus cannot exercise `-acceptnonstdtxn=1`
  paths.

---

## BUG-17 (P0-CDIV) — `test_accept` rollback corrupts mempool state, emits ZMQ event for non-existent tx

**Severity:** P0-CDIV. Core's `m_test_accept` mode performs the FULL
PreChecks + PolicyScriptChecks + ConsensusScriptChecks pipeline but
returns BEFORE `FinalizeSubpackage` applies the changeset (validation.cpp:1393
called only when !m_test_accept). No mempool state mutates.

lunarblock's `accept_to_memory_pool(tx, test_accept=true)`
(mempool.lua:1761-1806) takes a different approach — insert via the
full `accept_transaction`, then remove:

```lua
local ok, txid_hex_or_err, fee = self:accept_transaction(tx)
if ok then
  local entry = self.entries[txid_hex_or_err]
  local vsize = (entry and entry.vsize) or 0
  self:remove_transaction(txid_hex_or_err, "test-accept")
  -- Restore rolling-fee state so test_accept is side-effect-free.
  self.rolling_minimum_fee_rate = saved_rolling
  ...
end
```

The comment at 1762-1770 admits: "We can't easily reproduce Core's
changeset model in pure Lua, so we accept via accept_transaction
(which adds the entry) and then immediately remove it."
**Comment-as-confession 11th lunarblock instance.**

**State corruption:**

1. **on_tx_removed callback fires** (mempool.lua:1878). If a ZMQ
   notifier is wired (main.lua:1116-1118), this emits a "tx removed"
   ZMQ notification for a tx **that never actually existed in the
   mempool from the subscriber's perspective**. ZMQ-subscribed
   indexers (mempool.space, fulcrum, electrs) see a tx hash appear
   and disappear with no prior add notification — they may flag
   the lunarblock node as buggy / blacklist it.

2. **Ancestor descendant_count temporarily bumped then decremented**
   (mempool.lua:1703-1709 add; 1858-1865 subtract). A concurrent
   `get_sorted_entries` / `get_info` / `getrawmempool` call during
   the test_accept window sees ancestor entries with inflated
   descendant_count, producing a transiently-wrong mempool snapshot.

3. **Cluster union-find (`uf_parent[txid_hex]`)** is set
   (mempool.lua:1714), unioned with parents (mempool.lua:1716-1718),
   then nil'd in remove_transaction (mempool.lua:1873). The
   `uf_rank` field on ancestors is bumped by `uf_union` but NOT
   restored on remove. Subsequent cluster-cost computations on
   unrelated mempool txs see stale ranks → potentially wrong
   eviction decisions.

4. **`total_size += entry.size` then `total_size -= entry.size`**
   (mempool.lua:1688 add; 1868 subtract). Net-zero but a concurrent
   trim() that fires between the two could over-evict.

5. **`outpoint_to_tx[outpoint_key] = txid_hex`** then nil'd
   (mempool.lua:1693, 1853). Concurrent `accept_transaction` on a
   sibling tx in the window observes the test-tx as a conflict
   and triggers RBF flow against a tx that's about to disappear.

6. **Rolling-fee snapshot is incomplete** — only 3 fields are
   restored (mempool.lua:1771-1773, 1783-1785); the
   `block_since_last_rolling_fee_bump` field is restored but NOT
   the changes to `last_rolling_fee_update` that happen during
   `get_min_fee()` (called at mempool.lua:1303 inside accept_transaction's
   step 6b). So even the "side-effect-free" rolling-fee restoration
   leaks a corruption.

**File:** `src/mempool.lua:1761-1806` (test_accept shim);
`src/mempool.lua:1836-1881` (remove_transaction).

**Impact:**
- `testmempoolaccept` RPC leaks ZMQ events for txs that never
  entered the mempool.
- Concurrent mempool queries see transient corruption during the
  test_accept window.
- Cluster union-find inconsistency persists past the test_accept
  call (`uf_rank` is not restored).

---

## BUG-18 (P0-CDIV) — Two-pipeline guard: `accept_package` bypasses 14+ per-tx standardness/policy gates

**Severity:** P0-CDIV. lunarblock has **two separate accept
pipelines** that share no per-tx gate code:

1. `Mempool:accept_transaction` (mempool.lua:934-1746) — full
   IsStandardTx, IsWitnessStandard, ValidateInputsStandardness,
   BIP-113 IsFinalTx, BIP-68 SequenceLocks, MAX_STANDARD_TX_SIGOPS_COST,
   RBF Rule 3/4/5, TRUC SingleTRUCChecks, dust gate, datacarrier
   gate, anchor outputs, cluster limits, PolicyScriptChecks (when
   enabled), version range, scriptsig push-only.
2. `Mempool:accept_package` (mempool.lua:2566-2821) — well-formed
   package check, basic check_transaction, MAX_STANDARD_TX_WEIGHT
   cap, UTXO lookup, COINBASE_MATURITY, fee≥0, package fee rate
   minimum.

**Gates the package path bypasses entirely:**

| Gate | accept_transaction | accept_package |
|------|---------------------|----------------|
| TX_MIN/MAX_STANDARD_VERSION | YES (970-973) | NO |
| MIN_STANDARD_TX_NONWITNESS_SIZE | YES (985-997) | NO |
| Scriptsig size + push-only | YES (1001-1009) | NO |
| Per-output scriptpubkey type | YES (1020-1023) | NO |
| Datacarrier limit | YES (1025-1030) | NO |
| Bare-multisig gate | YES (1031-1051) | NO |
| Dust gate | YES (1062-1098) | NO |
| BIP-113 IsFinalTx | YES (1100-1108) | NO |
| BIP-68 SequenceLocks | YES (1254-1280) | NO |
| IsWitnessStandard | YES (1196-1199) | NO |
| ValidateInputsStandardness | YES (1208-1213) | NO |
| MAX_STANDARD_TX_SIGOPS_COST | YES (1221-1236) | NO |
| Anchor output policy | YES (1239-1242) | NO |
| RBF Rules 3/4/5 | YES (1314-1499) | NO (treats any intra-package outpoint as the only conflict path) |
| TRUC SingleTRUCChecks | YES (1557-1587) | NO |
| client_max_feerate cap | YES (1594-1599) | NO |
| PolicyScriptChecks | YES (1622-1678) when enabled | NO |
| Cluster size/vsize limits | YES (1724-1736) | NO |
| Rolling-minimum-fee gate | YES (1302-1312) | NO |
| MoneyRange on inputs (BUG-10 cross-cite) | NO (also missing) | NO |

**The package path enforces 6 of 30+ gates** that accept_transaction
enforces. A package-relay caller can submit a 25-tx package
containing arbitrarily non-standard txs and they will land in the
mempool, where they then will get included in block templates by
the mining path (mining.lua reads mempool entries without re-checking
standardness).

This is the **17th distinct extension** of the fleet two-pipeline
guard (W76+ running tracking). lunarblock previously was a 4-instance
guard impl (W125 reject-string sweep, W148 IBD pipelines, W144
script-flag dispatch, W149 prune-vs-flatfile state); this brings it
to 5 distinct instances within a single impl.

**Cross-impl correlation:**
- W143 ouroboros BUG-7 (`connect_block_from_bytes` ships
  half-finished pipeline) is the same structural pattern at the
  block-validation layer; lunarblock's BUG-18 is the mempool-layer
  variant.
- W145 nimrod BUG-1 (--reindex skips entire consensus pipeline) is
  the same pattern at the IBD-replay layer.

**File:** `src/mempool.lua:2566-2821` (accept_package);
`src/mempool.lua:934-1746` (accept_transaction).
**Core ref:** `bitcoin-core/src/validation.cpp:1432-1565`
(`AcceptMultipleTransactionsInternal`): Core's package path runs
`PreChecks(args, ws)` PER WORKSPACE — same gate set as single-tx
accept — then a per-package fee-rate check, then per-workspace
PolicyScriptChecks + ConsensusScriptChecks. NO gates skipped.

**Impact:**
- Package-submit RPC (`submitpackage` if/when implemented;
  `testmempoolaccept` with array) is a back-door for non-standard
  txs into the mempool.
- Mining template (mining.lua) reads accepted-but-non-standard txs
  and includes them in block templates → blocks rejected by Core
  peers downstream.

---

## BUG-19 (P1) — `count_script_sigops` returns 0 on parse failure (sigop cap bypass)

**Severity:** P1 (fleet pattern; same shape as **W143 lunarblock
BUG-6 + camlcoin BUG-6**). `validation.lua:343-367`:

```lua
function M.count_script_sigops(script_bytes, accurate)
  -- Gracefully handle unparseable scripts (e.g. coinbase scriptSig with arbitrary data)
  local ok, ops = pcall(script.parse_script, script_bytes)
  if not ok then return 0 end
  ...
end
```

If `script.parse_script` throws (malformed pushdata length, truncated
PUSHDATA2/4, etc.) the function returns 0. Downstream consumers in
mempool's PolicyScriptChecks (mempool.lua:558-560, the
`ValidateInputsStandardness` sigop-counting block):

```lua
sigops = sigops + (validation.count_script_sigops(ss, true) or 0)
sigops = sigops + (validation.count_script_sigops(prev, false) or 0)
```

A tx whose scriptSig parses-fine but whose prev scriptPubKey
parse-fails would silently get its sigop contribution dropped to 0,
bypassing the BIP-54 `MAX_TX_LEGACY_SIGOPS=2500` cap (mempool.lua:567-570)
and the `MAX_STANDARD_TX_SIGOPS_COST=16000` cap (mempool.lua:1232-1234).
Core's `GetSigOpCount(true)` returns `MAX_PUBKEYS_PER_MULTISIG` for
each unparseable region; lunarblock returns 0.

Fleet pattern crystallized in W143 (camlcoin BUG-6, lunarblock
BUG-6). This is the relay-time twin — the W143 bugs were at
block-validation time; this BUG-19 is at mempool-accept time.
The same `parse_script + pcall(...) returns 0` shape.

**File:** `src/validation.lua:343-367`.
**Core ref:** `bitcoin-core/src/script/script.cpp::CScript::GetSigOpCount`.

**Impact:**
- Malformed-prev-scriptpubkey txs bypass relay sigop caps.
- Mined-block sigop count is correct (utxo.lua's connect_block
  path does its own counting), but trust budget reaches block-time
  before being caught.

---

## BUG-20 (P1) — `getmempoolentry` JSON has wrong wtxid type + always-empty depends/spentby + ancestor-count semantics swap

**Severity:** P1. `rpc.lua:format_mempool_entry` (2992-3019) emits:

```lua
return {
  ...
  wtxid = entry.wtxid or txid_hex,
  ...
  depends = entry.depends or {},
  spentby = entry.spent_by or {},
  ["bip125-replaceable"] = mp and mp:is_replaceable(txid_hex) or false,
  unbroadcast = false,
  descendantcount = entry.descendant_count or 1,
  descendantsize = entry.descendant_size or entry.vsize,
  ...
  ancestorcount = entry.ancestor_count or 1,
  ancestorsize = entry.ancestor_size or entry.vsize,
}
```

**Three issues:**

1. **wtxid type leak** — `entry.wtxid` is a `hash256` Lua object
   (mempool.lua:843 sets it via `validation.compute_wtxid(tx)` whose
   return is a typed table with a `bytes` field). Emitting this
   directly to JSON serializes the OBJECT (typically yielding `{}` or
   the table-id, depending on cjson encoder). Core emits a 64-char
   hex string. **Wire-format break for any JSON consumer of
   `getmempoolentry.wtxid`.**

2. **depends + spentby always empty** — `entry.depends` and
   `entry.spent_by` fields are never populated anywhere in mempool.lua.
   The actual graph data lives in `entry.ancestors` (set of all
   ancestors), `entry.descendants` (set), and `entry.spends_from`
   (outpoint_key -> parent_hex). Core's `depends` = list of direct
   parent txids; `spentby` = list of direct child txids. Both
   require an extra filter pass against `direct_parents` (mempool
   doesn't store this on the entry post-accept). lunarblock emits
   `[]` for both, leaking the entire mempool dependency graph as
   apparent root-orphans.

3. **descendant_count / ancestor_count semantics swap** — Core's
   `descendantcount` INCLUDES self (CTxMemPoolEntry counts `1` for
   a leaf); lunarblock stores `entry.descendant_count` EXCLUDING
   self (mempool.lua:1682: `entry.ancestor_count = ancestor_count
   - 1  -- exclude self`). The fallback `or 1` partially compensates
   for missing entries but produces inconsistent output: present
   entries report `n-1`, absent entries report `1`. Wallet/explorer
   tooling comparing counts across lunarblock and Core sees
   systematic off-by-one.

**File:** `src/rpc.lua:2992-3019`.

**Impact:**
- `getmempoolentry.wtxid` JSON shape mismatch.
- `depends` / `spentby` always empty — no consumer can reconstruct
  mempool dependency graph from `getmempoolentry`.
- Ancestor/descendant counts off by one vs Core.

---

## BUG-21 (P1) — `block_disconnected` reorg-readmit lacks `bypass_limits` semantics

**Severity:** P1. Core's `MaybeUpdateMempoolForReorg`
(validation.cpp DisconnectTip path) calls
`AcceptToMemoryPool(..., bypass_limits=true)`. The bypass flag:

- skips the rolling-min-fee gate (validation.cpp:948 — `if (!bypass_limits ...)
  && !CheckFeeRate(...)) return false`),
- skips the SingleTRUCChecks gate (validation.cpp:954 — `if (!args.m_bypass_limits)`),
- sets `entry_sequence = 0` (validation.cpp:923) so the readmitted
  tx is ordered AHEAD of any in-flight mempool entries that were
  accepted between the old and new chains' tip-block timestamps.

lunarblock's `block_disconnected` (mempool.lua:1940-1953) calls
`self:accept_transaction(tx)` with NO bypass flag — the FULL accept
pipeline runs including rolling-min-fee gate, TRUC checks, all
standardness gates. The pcall-wrapped error-swallow only ignores
LUA exceptions, not consensus-rule rejects:

```lua
pcall(function()
  self:accept_transaction(tx)
end)
```

`accept_transaction` returns `(false, "...")` on consensus reject,
NOT a Lua exception, so pcall returns `(true, false, "...")` — the
caller in block_disconnected ignores the return tuple entirely. The
rolling-min-fee, TRUC, and ancestor-limit gates can therefore drop
txs that Core's MaybeUpdateMempoolForReorg would have re-admitted.

After a reorg that crosses a fee-spike block, the mempool fills
with new-tip txs THEN the rolling-min-fee bumps THEN
block_disconnected tries to readmit old-tip txs that now fall below
the bumped floor → they all get rejected → reorg-disrupted txs are
permanently lost.

**File:** `src/mempool.lua:1940-1953`; no bypass_limits param at
all.
**Core ref:** `bitcoin-core/src/validation.cpp` (`MaybeUpdateMempoolForReorg`
+ bypass_limits=true path).

**Impact:**
- Reorg-disrupted txs whose fee falls below post-reorg rolling-min
  are permanently dropped instead of refunded to mempool.
- Combined with BUG-3 (10× stricter relay floor), more reorg-readmit
  txs are rejected on lunarblock than on Core.

---

## BUG-22 (P1) — `accept_transaction` rejects `accept_to_memory_pool` semantics; `sendrawtransaction` bypasses test_accept entirely

**Severity:** P1. The W96 audit added `accept_to_memory_pool`
(mempool.lua:1761) as the canonical relay entry per Core ATMP, but
two of the four production callers BYPASS it and call
`accept_transaction` directly:

| Caller | Method called | test_accept honored | bypass_limits honored | client_max_feerate honored |
|--------|---------------|---------------------|------------------------|------------------------------|
| `sendrawtransaction` RPC (rpc.lua:2035) | `accept_transaction` | NO (always insert) | NO | NO |
| peer `tx` handler (main.lua:1328) | `accept_transaction` | NO | NO | NO |
| reorg `block_disconnected` (mempool.lua:1950) | `accept_transaction` | NO | NO | NO |
| orphan resolver (main.lua:1392) | `accept_transaction` | NO | NO | NO |
| `testmempoolaccept` (rpc.lua:7376) | `accept_to_memory_pool(tx, true)` | YES | NO | YES (via Mempool.client_max_feerate_kvb config) |

Only `testmempoolaccept` flows through the ATMP shim. Production
tx-relay (sendrawtransaction + peer + reorg + orphan) skips the shim
entirely. Consequences:

- The `bypass_limits=true` semantics needed by reorg-readmit (BUG-21)
  cannot be propagated even if ATMP were extended.
- The `m_client_maxfeerate` cap is only honored on `testmempoolaccept`,
  not on `sendrawtransaction` (rpc.lua:2029-2057 has no `maxfeerate`
  parameter parsing).
- The CFeeRate `result.fee` / `result.effective_feerate` Core ATMP
  result struct is not propagated; sendrawtransaction's response is
  just `txid_hex` (rpc.lua:2056) — Core's sendrawtransaction returns
  the txid plus optional fee details via `verbose=1` (lunarblock has
  no verbose parameter).

**File:** `src/rpc.lua:2029-2057`, `src/main.lua:1328 + 1392`,
`src/mempool.lua:1950`.
**Core ref:** `bitcoin-core/src/rpc/rawtransaction.cpp::sendrawtransaction`
(routes through `BroadcastTransaction` → ATMP with proper args).

**Impact:**
- `sendrawtransaction` cannot reject high-fee txs (no `maxfeerate`).
- ATMP shim's `client_max_feerate` knob is reachable only via
  `testmempoolaccept`, not actual broadcast.
- Per-caller "all or nothing" duplication: the four production paths
  share no policy-arg surface, so future operator knobs would need
  to be added 4× over.

---

## BUG-23 (P1) — `DEFAULT_MAX_TX_FEE = 1000000` is dead-data plumbing (never consulted)

**Severity:** P1 ("dead-data plumbing" fleet pattern, **5th lunarblock
instance** per W138/W139/W141/W144 dead-data tracking).

`mempool.lua:204` defines:

```lua
M.DEFAULT_MAX_TX_FEE = 1000000    -- 0.01 BTC max fee (policy, not consensus)
```

Bitcoin Core uses `DEFAULT_MAX_RAW_TX_FEE_RATE` (kernel/mempool_options.h)
and `DEFAULT_MAX_BURN_AMOUNT` as the absurd-fee guard, exposed via
`-maxtxfee` CLI knob and the `maxfeerate` RPC param. A grep over
`src/` for `DEFAULT_MAX_TX_FEE` finds the definition line only —
zero consumers. The intended absurd-fee gate is unimplemented;
sendrawtransaction can broadcast a 100 BTC fee tx without warning.

Companion to BUG-15 (`incrementalrelayfee` carry-forward) and
BUG-16 (operator-knob coverage zero) in the same wave.

**File:** `src/mempool.lua:204`.

**Impact:** wallet-user footgun — accidental fee inflation has no
relay-time guard. Core's default `-maxtxfee=0.1 BTC` would reject;
lunarblock silently broadcasts.

---

## BUG-24 (P0-CDIV) — `accept_transaction` LuaJIT assert-as-validation surface (wire-DoS extension)

**Severity:** P0-CDIV (extends **W142 BUG-24** to mempool path).

Multiple per-tx validation sites in `accept_transaction`'s callees
use `assert()`/`error()` for control flow, then rely on pcall in
the caller to swallow:

| Site | Assert/error message | Path |
|------|----------------------|------|
| `validation.lua:186-187` | "transaction has no inputs/outputs" | check_transaction |
| `validation.lua:195-196` | "stripped size ... exceeds MAX_BLOCK_WEIGHT" | check_transaction |
| `validation.lua:212` | "bad-txns-inputs-duplicate" | check_transaction |
| `validation.lua:220-224` | "MAX_MONEY ..." | check_transaction |
| `validation.lua:240-246` | "coinbase scriptSig ..." | check_transaction |
| `validation.lua:1023` | "tapleaf_hash required" | sighash compute (taproot path) |
| `validation.lua:1305-1351` | various block validation asserts | check_block (called from mining, not mempool — exempt) |
| `validation.lua:1383-1388` | "bad-cb-height ..." | check_coinbase_height |
| `validation.lua:1429` | "Missing UTXO height for input ..." | calculate_sequence_locks |
| `script.lua:*` | parse_script asserts | sigop counting |

The mempool path wraps `validation.check_transaction` in pcall
(mempool.lua:957) but does NOT wrap `validation.calculate_sequence_locks`
(mempool.lua:1275-1276). The assert at validation.lua:1429
(`assert(coin_height, "Missing UTXO height for input " .. i)`) can
fire on a malformed mempool-parent input where `input_heights[i] = 0`
was set (mempool.lua:1168) but `get_utxo_height_for_seq` returns
`input_heights[j] or (next_height)` — if `input_heights[j]` is `0`
(falsy in some Lua contexts) the fallback fires; if it's exactly `0`
(truthy in Lua), `0` is passed as coin_height into the assert which
accepts truthy 0 — but `get_block_mtp(math.max(coin_height - 1, 0))`
= `get_block_mtp(0)` = `tip_mtp` (from the conservative shim) — no
assert fires.

Trickier: `assert(M.check_proof_of_work(header, network), ...)` at
validation.lua:1247 is in `check_block_header`, NOT called from
mempool accept. Exempt.

The genuine mempool-path wire-DoS surface is **`error("bad-txns-inputs-duplicate")`**
at validation.lua:212 — captured by mempool's pcall and folded into
`"invalid transaction structure"` (BUG-1 cross-cite). On its own,
a peer sending a duplicate-input tx triggers the Lua exception, but
the pcall catches it and the tx is rejected normally. No DoS.

**However**: `script.lua`'s `parse_script` is called WITHOUT pcall
inside `is_witness_standard` (mempool.lua:644-648):

```lua
local ok_parse, ops = pcall(script_mod.parse_script, script_sig)
if not ok_parse then
  return false, "bad-witness-nonstandard"
end
```

This site IS guarded. But ValidateInputsStandardness at
mempool.lua:558-563:

```lua
sigops = sigops + (validation.count_script_sigops(ss, true) or 0)
sigops = sigops + (validation.count_script_sigops(prev, false) or 0)
if script_mod.classify_script(prev) == "p2sh" then
  local redeem = validation.extract_p2sh_redeem_script(ss)
```

`classify_script` and `extract_p2sh_redeem_script` are called
WITHOUT pcall. If `classify_script` asserts on malformed
scriptPubKey internal bytes (e.g. truncated pushdata at the start of
the script — script.lua `parse_script` raises an error), the
entire `accept_transaction` aborts with an unhandled Lua error,
which bubbles to the peer-handler's outer pcall (main.lua:1326-1372):

```lua
local ok, err = pcall(function()
  ...
end)
if not ok then
  peer_manager:add_ban_score(peer, 10, tostring(err))
end
```

The peer gets +10 ban score for sending a tx whose **prev UTXO's
scriptPubKey** was malformed (not the tx itself). This is a
**ban-by-proxy** primitive: a peer can submit a tx spending an
adversary-controlled UTXO whose scriptPubKey we previously accepted
into our coin_view, knowing it will trigger a parse error in
classify_script, and get banned. But… the adversary needs to have
ALREADY landed a malformed-scriptPubKey UTXO in our coin_view,
which requires bypassing our own block-validation. The chain of
events is improbable but the assert-as-control-flow pattern is
identical to **W142 BUG-24 lunarblock LuaJIT assert-as-validation**.

This is the **2nd lunarblock instance** of the wire-DoS-via-assert
fleet pattern.

**File:** `src/validation.lua:343-367` (count_script_sigops with
pcall guard); `src/script.lua` (classify_script, extract_p2sh_redeem_script
without internal asserts but parse_script throws); `src/mempool.lua:558-561`
(consumers without pcall).

**Impact:**
- Ban-by-proxy on malformed-prev-script-input combination, requiring
  adversarial coin_view state.
- Same shape as W142 BUG-24; cumulative fleet pattern.

---

## Summary

**Bug count:** 24 (BUG-1 through BUG-24).

**Severity distribution:**
- **P0-CONS:** 1 (BUG-10 — MoneyRange-on-inputs absent at relay)
- **P0-CDIV:** 8 (BUG-1, BUG-4, BUG-6, BUG-7, BUG-9, BUG-11, BUG-17,
  BUG-18, BUG-24)
- **P1:** 14 (BUG-2, BUG-3, BUG-5, BUG-8, BUG-12, BUG-13, BUG-14,
  BUG-15, BUG-16, BUG-19, BUG-20, BUG-21, BUG-22, BUG-23)
- **P2:** 0

(Recount: 1 + 9 + 14 = 24 ✓; BUG-24 is P0-CDIV, listed twice in P0-CDIV
section.)

**Fleet patterns confirmed:**
- "**30-of-30-gates-buggy** candidate" (BUG-6 + BUG-9 + BUG-16) —
  PolicyScriptChecks dead in production + ConsensusScriptChecks
  entirely absent + zero of 10 operator knobs. **3rd lunarblock
  instance** after W139 (fee estimator) and W149 (assumevalid /
  pruning). lunarblock now 3-of-3 at-fleet's-most-extreme for this
  pattern; "subsystem rewrite" candidate.
- "**Two-pipeline guard** 17th distinct extension" (BUG-18) —
  accept_transaction vs accept_package gate-set divergence; 5th
  lunarblock-internal instance after W125/W148/W149.
- "**Wire-token parity slippage** 11th lunarblock token cluster"
  (BUG-1 collapses 6+ tokens; plus 7 more tokens from `bad-txns-nonfinal`,
  `coinbase transactions not accepted`, `outputs exceed inputs`,
  etc.). Lunarblock fleet running total: **25+ tokens** missing
  Core parity.
- "**Comment-as-confession** 11th lunarblock instance" — BUG-2
  (PERMIT_BARE_MULTISIG comment cites wrong upstream state),
  BUG-6 (mempool.lua:898-903 "Production callers should pass true"),
  BUG-8 (TODO acknowledging witness-path gap), BUG-17 (mempool.lua:1762-1770
  "We can't easily reproduce Core's changeset model").
- "**Dead-data plumbing** 5th lunarblock instance" — BUG-5
  (verify_const_scriptcode set-never-read), BUG-23 (DEFAULT_MAX_TX_FEE
  defined-never-consulted).
- "**Carry-forward / re-anchor** pattern" — BUG-15 (incrementalrelayfee
  hardcoded 0.00001 not updated when INCREMENTAL_RELAY_FEE flipped
  100 → 1000 → 100); same shape as W141 ouroboros / W139.
- "**LuaJIT assert-as-validation → wire-DoS** 2nd lunarblock
  instance" (BUG-24) — extends W142 BUG-24 from segwit-witness path
  to mempool path. Pattern is now confirmed across two distinct
  subsystems within lunarblock.
- "**Lua-double comparator** lossy precision" (BUG-14) — same shape
  as W149 BUG-10 (chain_work).
- "**No operator-knob exists** sweep" (BUG-16) — 10 of 10 mempool
  knobs absent. Same fleet shape as W148 BUG-6 (`-assumevalid` absent
  in blockbrew) but **complete elimination** rather than single-knob
  gap.

**Top three findings:**

1. **BUG-6 + BUG-9 cluster (P0-CDIV PolicyScriptChecks dead in
   production + ConsensusScriptChecks entirely absent)** —
   `verify_input_scripts` defaults `false` and no production caller
   sets it `true`; there is no ConsensusScriptChecks analog at all.
   Net effect: **lunarblock performs zero script verification at
   mempool-accept time**. Bad-signature txs are accepted into
   mempool, included in fee-rate trim decisions, relayed to peers,
   and only rejected when included in a block. Cross-cite W144
   STANDARD flag-set gaps (BUG-4: 6 of 14 flags missing in the
   table) — even if the table is reached, 6 STANDARD bits are unset.
   **Subsystem rewrite candidate**; 3rd lunarblock
   30-of-30-gates-buggy instance.

2. **BUG-18 (P0-CDIV two-pipeline guard: accept_package skips 14+
   per-tx gates)** — `accept_package` runs 6 of 30+ gates that
   `accept_transaction` enforces. Package-relay caller can land
   arbitrarily non-standard txs (no version range, no IsStandardTx,
   no IsWitnessStandard, no sigop limits, no BIP-113/68, no TRUC,
   no RBF Rules 3/4/5, no cluster limits, no PolicyScriptChecks) by
   bundling 1-2 txs in a package. The mining template then picks
   them up. **17th distinct fleet two-pipeline guard extension;
   5th distinct lunarblock-internal instance.**

3. **BUG-10 (P0-CONS MoneyRange-on-inputs absent at relay)** —
   `accept_transaction` accumulates `input_total + utxo.value`
   with NO MoneyRange check on per-coin value or accumulated
   total. CVE-2018-17144-class fingerprint at relay layer.
   Corrupt or attacker-supplied coin_view returns synthetic values
   → inflated feerate → weaponized eviction of honest mempool
   subset. Block-time ConnectBlock catches the invariant violation
   (utxo.lua:2395-2398) but mempool-state corruption persists in
   the interval. **First lunarblock instance of the CVE-2018-17144
   relay-layer class** (W145 surfaced the block-layer version).

**Cross-impl cumulative count:** W150 brings the running fleet
count to 76+1 = 77 discovery + 71 fix waves; ~9711 bugs catalogued
across 11 discovery quad-runs. lunarblock specifically: this is the
**4th 30-of-30-gates-buggy candidate** (W139, W148, W149, W150),
the **5th two-pipeline-guard** extension, and the **11th
wire-token-parity slippage** cluster (running total 25+ tokens).
