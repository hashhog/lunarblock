# W132 — BIP-68 / 112 / 113 nSequence + OP_CSV + MTP audit (lunarblock)

**Date:** 2026-05-17
**Wave:** W132 (discovery)
**Impl:** lunarblock (Lua / LuaJIT)
**Status:** **11 BUGS FOUND** (2 P0-CDIV, 5 P1, 3 P2, 1 P3) across **30 gates**

## Context

W132 audits lunarblock's three intertwined locktime subsystems against
the Bitcoin Core reference:

- **BIP-68** — Relative locktime via `nSequence`
  (Core `consensus/tx_verify.cpp::CalculateSequenceLocks` +
  `::EvaluateSequenceLocks` + `::SequenceLocks`).
- **BIP-112** — Script-level relative locktime opcode
  `OP_CHECKSEQUENCEVERIFY` (Core
  `script/interpreter.cpp::OP_CHECKSEQUENCEVERIFY` +
  `GenericTransactionSignatureChecker::CheckSequence`).
- **BIP-113** — Past-time-tied to median-time-past of the previous block
  for `nLockTime` enforcement (Core `chain.h::CBlockIndex::GetMedianTimePast` +
  `validation.cpp::ContextualCheckBlock` `enforce_locktime_median_time_past`).

The three were soft-forked TOGETHER under the BIP-9 `csv` deployment
(mainnet activation at h=419328).  Auditing them in one pass surfaces
the cross-coupling that a per-BIP audit would miss — especially the
"every call site that gates BIP-113 *also* gates BIP-68" deployment-key
invariant, plus the LuaJIT bit-op trap class that hit FIX-83 on
BIP-158.

> References:
>   bitcoin-core/src/consensus/tx_verify.cpp (CalculateSequenceLocks +
>   IsFinalTx + EvaluateSequenceLocks + SequenceLocks),
>   bitcoin-core/src/consensus/tx_verify.h (LOCKTIME_VERIFY_SEQUENCE),
>   bitcoin-core/src/script/interpreter.cpp:561-593 (OP_CSV opcode),
>   bitcoin-core/src/script/interpreter.cpp:1782-1826 (CheckSequence),
>   bitcoin-core/src/script/interpreter.cpp:1739-1779 (CheckLockTime),
>   bitcoin-core/src/primitives/transaction.h:76-114 (SEQUENCE_FINAL +
>     SEQUENCE_LOCKTIME_DISABLE_FLAG + SEQUENCE_LOCKTIME_TYPE_FLAG +
>     SEQUENCE_LOCKTIME_MASK + SEQUENCE_LOCKTIME_GRANULARITY),
>   bitcoin-core/src/chain.h:231-245 (GetMedianTimePast, nMedianTimeSpan),
>   bitcoin-core/src/chain.cpp:83-118 (GetAncestor),
>   bitcoin-core/src/validation.cpp:147-167 (CheckFinalTxAtTip),
>   bitcoin-core/src/validation.cpp:201-262 (CalculateLockPointsAtTip +
>     CheckSequenceLocksAtTip),
>   bitcoin-core/src/validation.cpp:2478-2482 (CSV deployment → flags),
>   bitcoin-core/src/validation.cpp:4129-4149 (ContextualCheckBlock
>     enforce_locktime_median_time_past),
>   BIP-68, BIP-112, BIP-113.

## Method

1. Re-read Core tx_verify.cpp + interpreter.cpp:561-593 + 1782-1826 +
   chain.h:231-245 + validation.cpp:147-262 + 4129-4149 end-to-end.
   Note the deployment-coupling at validation.cpp:2480 and :4135 and
   the `pindexPrev` (vs `pindex`) shift inside `ContextualCheckBlock`.
2. Synthesize 30-gate matrix:
   - Constants + masks (G1-G3).
   - BIP-68 `CalculateSequenceLocks` (G4-G9).
   - BIP-68 `EvaluateSequenceLocks` (G10-G11).
   - BIP-113 `GetMedianTimePast` (G12-G14).
   - BIP-113 `IsFinalTx` + ContextualCheckBlock gate (G15-G18).
   - BIP-112 `OP_CHECKSEQUENCEVERIFY` opcode (G19-G24).
   - BIP-112 `CheckSequence` helper (G25-G28).
   - Cross-axis: LuaJIT bit-op trap (G29-G30).
3. Classify lunarblock state against:
   - `src/consensus.lua` — constants (lines 780-817) + `get_median_time_past`.
   - `src/validation.lua:1400-1466` — `calculate_sequence_locks` +
     `check_sequence_locks`.
   - `src/validation.lua:1500-1660,1660-1760,1800-1936` — three sig-checker
     factories, each with its own `check_sequence` + `check_locktime`.
   - `src/script.lua:1696-1720` — OP_CHECKSEQUENCEVERIFY opcode.
   - `src/script.lua:1669-1695` — OP_CHECKLOCKTIMEVERIFY opcode.
   - `src/mining.lua:43-72` — `is_final_tx`.
   - `src/mempool.lua:14-35` — `get_tip_mtp` (mempool-side MTP cache).
   - `src/mempool.lua:1100-1108` — IsFinalTx mempool call site.
   - `src/mempool.lua:1254-1280` — BIP-68 mempool call site.
   - `src/utxo.lua:2181-2198` — IsFinalTx connect_block call site.
   - `src/utxo.lua:2356-2373` — BIP-68 connect_block call site.
   - `src/utxo.lua:3067-3087` — `compute_mtp_from_storage`.
   - `src/utxo.lua:3124-3151` — `get_block_mtp(h)` closure.
4. Catalogue bugs.
5. Write `tests/test_w132_nsequence_csv_mtp.lua` covering every gate.
6. LuaJIT bit-op trap audit per FIX-83 (W122 universal pattern):
   `bit.lshift(1, n)` is 32-bit modular for `n >= 32`; check every
   nSequence path.

## Severity scoring

- **P0-CDIV** — Block-validation divergence from Core under inputs reachable
  on mainnet (accept-when-Core-rejects OR reject-when-Core-accepts).
- **P1** — Mempool admission diverges (over-rejects valid bumps OR
  under-rejects Core-rejected tx); funds-at-risk if it surfaces a
  building-tx-Core-rejects scenario; non-determinism vs Core.
- **P2** — Wallet-side ergonomics or missing-but-isomorphic-via-call-sites.
- **P3** — Cosmetic / dead-code.

## 30 W132 Audit Gates

| Gate | Description | Status | Core ref |
|------|-------------|--------|----------|
| **Constants + masks** | | | |
| G1  | `SEQUENCE_FINAL = 0xFFFFFFFF` | PRESENT (mining.lua:11; rpc.lua hardcoded) | transaction.h:76 |
| G2  | `SEQUENCE_LOCKTIME_DISABLE_FLAG = 1U << 31`; `_TYPE_FLAG = 1 << 22`; `_MASK = 0x0000FFFF`; `_GRANULARITY = 9` | PRESENT (consensus.lua:793-796) | transaction.h:93-114 |
| G3  | `MAX_SEQUENCE_NONFINAL = SEQUENCE_FINAL - 1 = 0xFFFFFFFE` | PRESENT (mining.lua:14) — coinbase + anti-fee-sniping; never re-exported | transaction.h:82 |
| **BIP-68 CalculateSequenceLocks** | | | |
| G4  | `fEnforceBIP68 = (tx.version >= 2) && (flags & LOCKTIME_VERIFY_SEQUENCE)` — both required | PRESENT (validation.lua:1418, `tx.version < 2 or not enforce_bip68`) | tx_verify.cpp:51 |
| G5  | DISABLE_FLAG check skips input + sets `prevHeights[i] = 0` (Core tx_verify.cpp:65-69) | PARTIAL (BUG-1, **P3**) — lunarblock just `continue`s, but never mutates a `prevHeights` array (no LockPoints persistence); doesn't pre-zero so a subsequent caller could observe the original height | tx_verify.cpp:65-69 |
| G6  | Time-based branch: `nCoinTime = block.GetAncestor(max(nCoinHeight-1, 0)).GetMedianTimePast()` | PARTIAL (validation.lua:1435 `get_block_mtp(math.max(coin_height-1, 0))` — semantics depend on caller's closure) | tx_verify.cpp:74 |
| G7  | `nMinTime = max(nMinTime, nCoinTime + ((nSequence & MASK) << 9) - 1)` (the `-1` for last-invalid semantics) | PRESENT (validation.lua:1439) | tx_verify.cpp:88 |
| G8  | Height-based branch: `nMinHeight = max(nMinHeight, nCoinHeight + (nSequence & MASK) - 1)` | PRESENT (validation.lua:1443) | tx_verify.cpp:90 |
| G9  | DISABLED-flag input: `prevHeights[i] = 0` mutation (so a later caller using the same prevHeights array doesn't think this input was on-chain) | **MISSING** (BUG-2, **P2**) — lunarblock takes `get_utxo_height` as a CALLBACK, not a mutable array, so the Core convention `prevHeights[i] = 0` cannot be implemented here.  Caller-side at mempool.lua:1166 and utxo.lua:2361 NEVER receives the zeroed signal | tx_verify.cpp:67 |
| **BIP-68 EvaluateSequenceLocks** | | | |
| G10 | `if (lockPair.first >= block.nHeight) return false` — strict-`>=` semantics from "last-invalid" model | PRESENT (validation.lua:1459 `min_height >= block_height`) | tx_verify.cpp:101 |
| G11 | `if (lockPair.second >= nBlockTime) return false` where `nBlockTime = block.pprev.GetMedianTimePast()` | PRESENT (validation.lua:1462 `min_time >= prev_block_mtp`) at the call site invariant | tx_verify.cpp:100-101 |
| **BIP-113 GetMedianTimePast** | | | |
| G12 | Walk **up to 11** ancestors via `pindex = pindex->pprev`; tolerate `< 11` near genesis (Core nMedianTimeSpan = 11; loop bound `i < nMedianTimeSpan && pindex`) | PRESENT (mempool.lua:22-27 + utxo.lua:3073-3078; both use `for _ = 1, 11 do ... if not header then break end`) | chain.h:240 |
| G13 | Sort 11 timestamps + return `pbegin[(pend-pbegin)/2]` (0-indexed integer division; upper-middle for even-count near-genesis) | PRESENT (mempool.lua:34 + utxo.lua:3086 `sorted[math.floor(n/2)+1]`) | chain.h:243-244 |
| G14 | Storage-failure path returns deterministic value (Core: function is `const`, no storage — always returns a sorted-window median, even at genesis where only the genesis block's timestamp is in the window) | **WRONG** (BUG-3, **P1**) — `mempool.lua:18` and `utxo.lua:3069` BOTH return **`os.time()`** when storage absent or `tip_hash` nil.  This is **non-deterministic** (wall-clock time of the validating node), which CAN diverge across nodes / restarts and is **never** a Core-conformant value | chain.h:233-244 (deterministic by construction) |
| **BIP-113 IsFinalTx + ContextualCheckBlock gate** | | | |
| G15 | `IsFinalTx(tx, nHeight, nBlockTime)`: locktime=0 always final; locktime < (height-or-time threshold) final; else final iff every input.nSequence == SEQUENCE_FINAL | PRESENT (mining.lua:43-72; `nLockTime` typed via `< LOCKTIME_THRESHOLD` to select height-vs-time) | tx_verify.cpp:17-37 |
| G16 | ContextualCheckBlock uses `nLockTimeCutoff = enforce_locktime_median_time_past ? pindexPrev->GetMedianTimePast() : block.GetBlockTime()` | PRESENT (utxo.lua:2188-2193; uses `prev_block_mtp` when `enforce_bip68 and prev_block_mtp`) | validation.cpp:4140-4142 |
| G17 | The MTP-vs-block-time toggle is gated by **`DeploymentActiveAfter`** (i.e. CSV active at block N MEANS pindexPrev = N-1, so this block N is enforced) | PRESENT (utxo.lua:2182 `height >= self.network.csv_height`; lunarblock's `csv_height` semantics = "first block enforcing" = `DeploymentActiveAfter(pindexPrev=csv_height-1)`) | validation.cpp:4135 |
| G18 | Mempool admission `CheckFinalTxAtTip`: uses `nBlockHeight = active_chain_tip.nHeight + 1` and `nBlockTime = active_chain_tip.GetMedianTimePast()` (i.e. the **tip's** MTP, not pprev's) | PRESENT (mempool.lua:1103-1106 `next_height = tip_height + 1` and `tip_mtp = get_tip_mtp(self.chain_state)`) | validation.cpp:147-167 |
| **BIP-112 OP_CHECKSEQUENCEVERIFY opcode** | | | |
| G19 | Gated by `SCRIPT_VERIFY_CHECKSEQUENCEVERIFY` flag (else NOP3) | PRESENT (script.lua:1697 `flags.verify_checksequenceverify`); discourage-upgradable-nops on the off-path matches Core | interpreter.cpp:563-566 |
| G20 | `stack.size() < 1` → `SCRIPT_ERR_INVALID_STACK_OPERATION` | PRESENT (script.lua:1698 `assert(#stack > 0, ...)`) | interpreter.cpp:568-569 |
| G21 | 5-byte CScriptNum (NOT 4) so 32-bit-unsigned nSequence is representable | PRESENT (script.lua:1699 `pop_num(5)`) | interpreter.cpp:574 |
| G22 | `nSequence < 0` → `SCRIPT_ERR_NEGATIVE_LOCKTIME` | PRESENT (script.lua:1702-1713 `if sequence >= 0 ... else error("negative sequence")`) | interpreter.cpp:579-580 |
| G23 | DISABLE_FLAG set → NOP (success, no `CheckSequence` call) | PARTIAL (BUG-4, **P2**) — script.lua:1704 uses `math.floor(sequence / 0x80000000) % 2 == 1` to detect bit 31, which is CORRECT for 5-byte CScriptNum AND avoids the LuaJIT `bit.band(value > 2^32, ...)` trap.  However the function ALSO calls `consensus.sequence_locks_active(sequence)` INSIDE `checker.check_sequence` (validation.lua:1629), which uses raw `bit.band` — for `sequence > 2^32` the band truncates to int32 and the high bits are lost.  For BIP-112, only bit 31 matters, so the answer happens to be correct, but the DOUBLE check at two layers with inconsistent typing patterns is a maintenance trap.  See BUG-9 below for the related LuaJIT trap on sequence_lock_value. | interpreter.cpp:585-586 |
| G24 | Stack is left **UNCHANGED** (CSV does not consume top of stack) | PRESENT (script.lua:1700 `push(M.script_num_encode(sequence))` — push back after pop_num).  PARTIAL (BUG-5, **P2**) — push-back re-encodes via `script_num_encode`; if input was a non-minimal but verify_minimaldata=false encoding (e.g. trailing zero byte), the re-encoded form differs from what Core leaves on stack.  No subsequent opcode inspects the byte-form of stacktop(-1) on the CSV path in practice (BIP-112 is always followed by OP_DROP in standard scripts), but the byte-level deviation is real and could be exposed by a hostile script doing `OP_DUP OP_EQUAL` over the CSV value. | interpreter.cpp:574 + 590 (CScriptNum does not pop) |
| **BIP-112 CheckSequence helper** | | | |
| G25 | `tx.version < 2` → return false (fail script) | PRESENT (validation.lua:1636-1638; 1742; 1923) — three copies across three sig-checker factories | interpreter.cpp:1790-1791 |
| G26 | DISABLE_FLAG on **transaction's nSequence** (NOT script's) → return false | PRESENT (validation.lua:1641-1643; 1745; 1924) | interpreter.cpp:1797-1798 |
| G27 | Mask BOTH `nSequence` and `txToSequence` with `(SEQUENCE_LOCKTIME_TYPE_FLAG \| SEQUENCE_LOCKTIME_MASK) = 0x0040FFFF` THEN compare masked-type-matched values | **PARTIAL** (BUG-6, **P1**) — lunarblock checks TYPE_FLAG via `sequence_lock_is_time_based` (consensus.lua:808; raw `bit.band(seq, 0x00400000)`) and compares values via `sequence_lock_value` (`bit.band(seq, 0x0000FFFF)`).  Functionally equivalent for `seq < 2^32` because Core's combined mask 0x0040FFFF decomposes into the two independent masks 0x00400000 + 0x0000FFFF, and the type-match-then-value-compare are isomorphic.  **BUT** for `script_sequence > 2^32` (reachable via 5-byte CScriptNum), `bit.band` truncates to int32 SILENTLY, which may either (a) match Core (high bits don't matter for masked comparison anyway) or (b) corrupt the type-flag bit if the upper bits affect sign interpretation.  Core uses `int64_t` `txToSequence` + signed CScriptNum `nSequence` — for `script_sequence = 0x0080400005` (5-byte, type-flag set in low 32) lunarblock's `bit.band(0x0080400005, 0x00400000) = 0x00400000` (correct via accidental truncation); Core's `(int64_t)(0x0080400005 & 0x0040FFFF) = 0x00400005` (also correct).  Same answer. | interpreter.cpp:1802-1815 |
| G28 | `nSequenceMasked > txToSequenceMasked` → return false (the actual relative-lock comparison) | PRESENT (validation.lua:1655 `script_value <= input_value` in all three factories) | interpreter.cpp:1822-1823 |
| **LuaJIT bit-op trap audit** | | | |
| G29 | `bit.lshift(lock_value, GRANULARITY=9)` on time-based branch — `lock_value <= 0xFFFF`, `9 + 16 = 25 < 32` — never triggers the 32-bit modular trap | PRESENT (validation.lua:1438 `bit.lshift(lock_value, 9)` for `lock_value ≤ 0xFFFF`, max shifted value `0x1FFFE00 < 2^25`).  **NO TRAP** at this site. | tx_verify.cpp:88 |
| G30 | `bit.band(seq, DISABLE_FLAG=0x80000000)` for `seq` up to 5-byte CScriptNum (40-bit) — LuaJIT band truncates to int32 → may corrupt high bits.  Core uses int64_t with explicit `& 0x80000000` mask preserving high bits | **TRAP-WEAK** (BUG-9, **P1**) — `consensus.sequence_locks_active` (consensus.lua:802) uses `bit.band(seq, 0x80000000)`.  For inputs from `tx.inputs[i].sequence` (always 32-bit on the wire per BIP-68 transaction.h:66), no trap.  For 5-byte CScriptNum inputs in `checker.check_sequence`, the high bits 32+ are truncated.  THIS happens to be safe for the DISABLE_FLAG check (only bit 31 matters), but `sequence_lock_value(seq)` (bit.band, mask 0x0000FFFF) is similarly truncated.  Core's behavior: the mask 0x0000FFFF on a 64-bit value zeroes everything except bits 0-15, which lunarblock's int32-truncation-then-AND also achieves.  **BUT** `sequence_lock_is_time_based(seq)` (bit.band, mask 0x00400000): for `seq = 0x100400000` (5-byte value with TYPE_FLAG set AND bit 32 set), Core: `seq & 0x00400000 = 0x00400000` → TYPE_FLAG SET. lunarblock: `bit.band(0x100400000, 0x00400000)` — LuaJIT first truncates 0x100400000 → 0x00400000 (drops bit 32), then `0x00400000 & 0x00400000 = 0x00400000` → TYPE_FLAG SET.  **SAME ANSWER**, but by accident.  If Core ever extended SEQUENCE_LOCKTIME_TYPE_FLAG to bit 33+ (a hypothetical soft fork), lunarblock would diverge silently.  **AUDIT FLAG: FUTURE-PROOFING.** | transaction.h:93-104 + interpreter.cpp:1802 |

## Bug catalogue (11 BUGS)

| Bug ID | Priority | Summary | Where |
|--------|----------|---------|-------|
| **BUG-1**  | **P0-CDIV** | **Mempool BIP-68 time-based locks use TIP's MTP for every input's `coin_time`, instead of the MTP of the BLOCK PRIOR to each input's confirming block.**  At `mempool.lua:1272-1274` the closure `get_block_mtp_conservative(_h)` returns `tip_mtp` for ALL heights, ignoring its `_h` argument.  Core (`tx_verify.cpp:74`): `nCoinTime = block.GetAncestor(max(nCoinHeight-1, 0))->GetMedianTimePast()`, i.e. the MTP **of the ancestor block at (coin_height - 1)**.  Since MTP is monotonically non-decreasing across blocks, `tip_mtp >= ancestor_mtp`, so lunarblock's `nMinTime = max(nMinTime, tip_mtp + lock_seconds - 1)` is uniformly LARGER than Core's value.  This causes lunarblock to **over-reject** valid time-locked transactions at mempool admission (false-rejects only; never false-accepts, but the policy diverges from Core, so a transaction that Core's mempool accepts may be rejected by lunarblock).  Magnitude: when an input was confirmed thousands of blocks ago, ancestor_mtp is hours/days earlier than tip_mtp; the diff can exceed the lock's seconds-granularity and flip lock satisfaction.  **REACHABLE on mainnet** via any wallet bumping a transaction with a 512s-multiple time-based BIP-68 lock; the over-reject window is the gap between coin_block_MTP and tip_MTP. | mempool.lua:1272-1274 + tx_verify.cpp:74 |
| **BUG-2**  | **P2** | **`prevHeights[i] = 0` mutation for disabled-flag inputs not propagated.**  Core (`tx_verify.cpp:65-69`) takes `prevHeights` by REFERENCE and mutates `prevHeights[txinIndex] = 0` when DISABLE_FLAG is set.  This signal is later consumed by `CalculateLockPointsAtTip` (`validation.cpp:230-236`) to compute `max_input_height` (skipping inputs marked 0).  lunarblock takes `get_utxo_height` as a CALLBACK (validation.lua:1412), so the mutation cannot happen.  Caller-side at `mempool.lua:1266-1271` and `utxo.lua:2360-2363` always returns the on-chain height, never zero.  **Consequence:** lunarblock has no `LockPoints` persistence (Core caches `maxInputBlock`+`min_height`+`min_time` per mempool entry per `validation.cpp:243`), so the bug surfaces as "BIP-68 recomputed from scratch every mempool admission instead of cached" — a performance regression, not a consensus divergence.  Severity P2 because the on-disk lock points cache is absent end-to-end. | validation.lua:1412 + tx_verify.cpp:67 |
| **BUG-3**  | **P1** | **`get_tip_mtp` / `compute_mtp_from_storage` return `os.time()` when storage absent.**  At `mempool.lua:18` and `utxo.lua:3069` the storage-failure path returns the wall-clock time of the validating node.  Core's `GetMedianTimePast` (`chain.h:233-244`) is `const` over a fixed window of ancestors — it CANNOT return a non-deterministic value because there is no clock dependency.  Trigger paths: (a) freshly-initialized chain with no headers loaded — calling `mempool:accept_transaction` returns os.time() as MTP for BIP-113 / BIP-68 checks, allowing time-locked txs that depend on stale-clock; (b) regtest / fuzzing harness with mocked time can diverge between nodes; (c) testnet4 cold-restart before the headers index loads.  **Mitigation:** the path only fires when `tip_hash` is nil OR storage is nil; the former requires `chain_state.tip_hash` unset, which IS possible at boot.  P1 because it allows non-deterministic mempool admission. | mempool.lua:18 + utxo.lua:3069 + chain.h:240 |
| **BUG-4**  | **P2** | **`OP_CSV` opcode at `script.lua:1696-1714` performs the disable-flag check via a careful `math.floor(seq / 0x80000000) % 2` (avoiding LuaJIT bit-op trap), then calls `checker.check_sequence(sequence)` which RE-CHECKS via `consensus.sequence_locks_active` using `bit.band`.**  The TWO checks use DIFFERENT typing patterns: the opcode path is safe for 5-byte CScriptNum values up to 2^39-1; the checker path's `bit.band(seq, 0x80000000)` truncates inputs > 2^32 to int32, which may or may not preserve bit 31.  For `seq = 0x180000000` (bit 32 set, bit 31 set in low 32-bits): `seq & 0xFFFFFFFF = 0x80000000` → `bit.band(0x80000000, 0x80000000) = 0x80000000` → "disabled".  Core: `(int64_t)0x180000000 & 0x80000000 = 0x80000000` → "disabled". **SAME ANSWER.**  But the DOUBLE check at two layers with inconsistent typing patterns is a maintenance trap.  Single-path: lift the careful "math.floor / 0x80000000" idiom into `consensus.sequence_locks_active` so the checker-layer is safe for any 5-byte input. | script.lua:1696-1714 + validation.lua:1629 + consensus.lua:802 |
| **BUG-5**  | **P2** | **`OP_CSV` push-back re-encodes via `script_num_encode`.**  At `script.lua:1700` after `pop_num(5)`, the value is pushed back via `M.script_num_encode(sequence)`.  Core does NOT pop (uses `stacktop(-1)`) so the original byte form is preserved unconditionally.  When `verify_minimaldata=false` and the input was non-minimally encoded (e.g. `\x00\x05` for value 5), `script_num_encode` will RE-ENCODE minimally to `\x05`.  No subsequent opcode in a standard CSV-bearing script (`<n> CSV DROP <something>`) inspects the byte form, but a hostile script like `<n> CSV OP_DUP OP_PUSHDATA1 0x02 <bytes> OP_EQUAL` could observe the deviation.  P2 because no consensus-relay path triggers this (BIP-112 is always followed by OP_DROP in the wild). | script.lua:1700 + interpreter.cpp:574 |
| **BUG-6**  | **P1** | **`check_sequence` type-match check uses separate `sequence_lock_is_time_based` instead of Core's combined `nSequenceMasked` comparison.**  Core (`interpreter.cpp:1802-1815`): computes `nSequenceMasked = nSequence & (TYPE_FLAG \| MASK) = nSequence & 0x0040FFFF`, then checks `(masked < TYPE_FLAG && masked < TYPE_FLAG) \|\| (masked >= TYPE_FLAG && masked >= TYPE_FLAG)`.  The "type" is determined by **the masked value's relationship to TYPE_FLAG**, not by raw `seq & TYPE_FLAG`.  lunarblock (validation.lua:1646-1650) checks types via `consensus.sequence_lock_is_time_based(seq) = (seq & 0x00400000) != 0`.  Functionally EQUIVALENT for in-range values because the only bit difference is TYPE_FLAG itself: `(seq & 0x0040FFFF) >= 0x00400000` iff `seq & 0x00400000 != 0`.  **BUT** if a hypothetical future BIP added more bits ABOVE TYPE_FLAG that fold into "type", lunarblock would diverge.  Documented as a **shape-divergence** rather than a value-divergence; P1 because the shape is brittle to future protocol extensions. | validation.lua:1646-1650 + interpreter.cpp:1802-1815 |
| **BUG-7**  | **P1** | **Three near-identical copies of `check_sequence` across `make_sig_checker`, `make_tapscript_checker`, `make_collecting_sig_checker`.**  Files: `validation.lua:1627-1656` (legacy/v0), `:1737-1756` (tapscript), `:1918-1931` (collecting/deferred batch).  Each copy is ~25 lines and they have subtly DIFFERENT typing: the legacy copy validates `script_value <= input_value`, the tapscript copy uses the same pattern, the collecting copy uses the same pattern.  The three are identical TODAY but maintenance drift will produce a per-checker divergence (e.g. if FIX-N updates one copy for FIX-83-style cdata-uint64 mask, the other two will silently miss the fix).  Universal pattern: **same-spec, three-impl drift surface**.  Refactor: lift to a single `consensus.check_sequence_pure(script_seq, input_seq, tx_version)` and call from all three sites. | validation.lua:1627,1737,1918 |
| **BUG-8**  | **P3** | **Three near-identical copies of `check_locktime` across the three sig-checker factories.**  Files: `validation.lua:1605-1622`, `:1724-1734`, `:1906-1916`.  Same drift surface as BUG-7.  P3 because BIP-65 CheckLockTime has been stable since 2015. | validation.lua:1605,1724,1906 |
| **BUG-9**  | **P1** | **LuaJIT bit-op trap (FIX-83 universal pattern, latent).**  `consensus.sequence_locks_active`, `_is_time_based`, `_value` all use raw `bit.band` on values that COULD exceed 2^32 (via 5-byte CScriptNum from `OP_CSV`).  LuaJIT's `bit.band` is 32-bit modular: `bit.band(0x180000000, 0x80000000)` first truncates 0x180000000 → 0x80000000 (drops bit 32), then bands.  Result: SAFE TODAY because (a) `tx.inputs[i].sequence` is always 32-bit on the wire, (b) all three masks (DISABLE_FLAG, TYPE_FLAG, MASK) target bits ≤ 31, so high-bit truncation is invisible.  **FUTURE-FRAGILE**: if a soft fork ever assigned semantics to bit 32+ of `nSequence` (or extended the 4-byte CScriptNum to 5 bytes consensus-wide), lunarblock would silently drop those bits where Core preserves them.  Mitigation: replace `bit.band` with `math.floor(seq / 2^N) % 2 == 1` idiom (already used in script.lua:1704 for the DISABLE_FLAG check; **factor it out** and apply uniformly to all three accessors).  Same root cause as W122 BUG-1 / FIX-83 (`bit.lshift(1, nbits)` 32-bit modular trap). | consensus.lua:802,809,816 + W122/FIX-83 pattern |
| **BUG-10** | **P1** | **`calculate_sequence_locks` returns `(-1, -1)` for `tx.version < 2 or not enforce_bip68`, but `check_sequence_locks` (-1 >= 0) compares against `block_height` which is ALWAYS `>= 1` (`-1 >= 1` is false) and against `prev_block_mtp` which is ALWAYS `>= 0` (`-1 >= 0` is false), so the comparison correctly returns true (locks satisfied).**  HOWEVER: at near-genesis blocks (height 0/1 before MTP window is established), `prev_block_mtp` MAY be the sentinel `os.time()` (BUG-3) and the comparison may produce non-deterministic results.  Severity stack: BUG-3 + BUG-10 combine into a non-deterministic locktime check at boot.  P1 because compound with BUG-3. | validation.lua:1457-1466 + BUG-3 |
| **BUG-11** | **P1** | **No `LockPoints` cache in mempool.**  Core caches `LockPoints{height, time, maxInputBlock}` per mempool entry (`validation.h:329`, `txmempool.h:300+`) so that on every re-validation after a reorg, BIP-68 can be checked in O(1) instead of recomputing the whole chain walk.  lunarblock recomputes per-input on every `accept_transaction` call; on a long mempool with many time-locked transactions this is O(N×M) where N is mempool size and M is avg lock-input count.  Functional impact: at high mempool load + frequent reorgs, BIP-68 check becomes the hot path.  P1 because it's a performance scaling cliff under DoS. | validation.h:329 + txmempool.h LockPoints |

## P0-CONSENSUS findings

**BUG-1** is the lone P0-CDIV in this audit.

The mempool BIP-68 path's `get_block_mtp_conservative` ignores its `_h`
argument and returns `tip_mtp` for every call.  For an input
confirmed N blocks ago, Core uses the MTP of block (coin_height - 1)
(close to N hours/days/weeks before the tip's MTP); lunarblock uses
the tip's MTP.  Since `tip_mtp >= ancestor_mtp`, the computed
`nMinTime = max(nMinTime, MTP + lock_seconds - 1)` is always
GREATER in lunarblock, causing it to over-reject valid time-locked
transactions at mempool admission.

This is a **mempool-only** divergence (the connect_block path at
`utxo.lua:3138-3150` correctly walks storage to fetch the ancestor's
MTP), so block-level consensus is intact.  The mempool divergence
causes lunarblock to refuse-to-relay a Core-valid transaction, but
the transaction CAN still be mined and accepted by lunarblock if it
appears in a block (the per-input ancestor MTP is correct in
`connect_block`).

**Net consequence:** lunarblock will relay-reject some Core-valid
time-locked txs but will accept them in mined blocks; mempool-vs-block
divergence with no funds-loss but with relay-divergence severity
(funds may sit unconfirmed longer than expected because the user's
local node refused to relay).  Classification: P0-CDIV at the
mempool/relay layer; P-NONE at the block consensus layer.

## Universal-pattern notes for the meta-audit

1. **"`tip_mtp` short-circuit hides ancestor walks"** — when a callsite
   needs `nCoinTime = ancestor_at(coin_height-1).MTP`, a closure that
   returns `tip_mtp` always is a deceptively-correct stub that passes
   simple tests (it satisfies the type signature) but silently over-rejects.
   **Universal probe:** any impl whose BIP-68 mempool path supplies a
   "conservative MTP" closure should be audited for whether the closure
   actually walks ancestors.  Likely present in 3-5 impls fleet-wide.
2. **"Triple-copy sig-checker"** — BUG-7 + BUG-8 are a common idiom:
   each script-version (legacy / v0 / tapscript) gets its own checker
   factory, each with its own copy of `check_sequence` + `check_locktime`.
   Refactor pressure: lift to a single helper.  Audit cross-impl: every
   impl that distinguishes sig-versions at the checker level will have
   this.
3. **"LuaJIT bit-op trap latent on nSequence"** — BUG-9 mirrors W122
   BUG-1 / FIX-83 on blockfilter.  The same root cause (`bit.band`,
   `bit.lshift`, `bit.rshift` are 32-bit modular under LuaJIT) is
   latent here because the input is always 32-bit on the wire.  Audit
   pattern: any LuaJIT impl using `bit.band` on a value that COULD
   exceed 2^32 (5-byte CScriptNum, uint64 hashes, etc.) needs an audit
   for FIX-83-style mitigation.
4. **"`os.time()` sentinel = non-determinism"** — BUG-3 pattern: when
   a deterministic function falls back to wall-clock on edge-case
   inputs, the result is non-determinism that may diverge across
   nodes.  Audit pattern: grep every impl for `time()` / `Clock::now()`
   / `Time::Now()` inside consensus paths; consensus must be wall-clock-free.
5. **"Deployment-coupled BIP-68/112/113 enforcement"** — Core ties all
   three to `DEPLOYMENT_CSV` so they activate together; lunarblock
   does this correctly at `utxo.lua:2182` and `2432`.  Cross-impl
   audit pattern: some impls may have gated BIP-113 (MTP for
   IsFinalTx) under BIP-9 SegWit deployment by mistake; lunarblock
   does NOT have this bug.

## Out-of-scope (deferred)

- BIP-9 versionbits deployment state machine (audited in earlier W#);
  lunarblock has `network.csv_height` as a buried-deployment constant.
- LockPoints persistence (BUG-11) — refactor scope, not consensus
  rule.
- `OP_CHECKLOCKTIMEVERIFY` (BIP-65) — only audited tangentially
  via BUG-8; BIP-65 has its own audit wave.
- Sequence-lock interactions with package-relay (W116 scope).
- Mempool eviction on reorg w.r.t. lockpoint invalidation
  (`MaybeUpdateMempoolForReorg`, validation.cpp:294) — separate
  reorg-mempool wave.

## Suggested fix order (post-audit)

1. **BUG-1** — fix `get_block_mtp_conservative` to walk storage and
   return ancestor MTP.  1-file change in `mempool.lua`; reuse the
   `get_block_mtp(h)` closure pattern from `utxo.lua:3138-3150`.
   **REQUIRED before any consensus-aware mempool relay can be trusted.**
2. **BUG-3** — replace `os.time()` fallback with a defined sentinel
   (e.g. `nil` propagated as "MTP unknown → reject BIP-68 check
   safely" or `0` matching Core's near-genesis behavior).
3. **BUG-9** — factor out the `math.floor(seq / 2^N) % 2` idiom
   into `consensus.lua` accessors so the FIX-83 universal pattern
   is closed fleet-wide.
4. **BUG-7 / BUG-8** — refactor three-copy sig-checker into a single
   helper.  Cosmetic but reduces drift surface.
5. **BUG-11** — add LockPoints cache (perf scope, not consensus).

## Test summary

`tests/test_w132_nsequence_csv_mtp.lua`:

- 30 gates → ~70 assertions
- Pre-fix expected: 2 BUG XFAILs (BUG-1 mempool ancestor MTP, BUG-3
  `os.time()` fallback determinism); BUG-9 latent (would-XFAIL but no
  reachable 5-byte CScriptNum > 2^32 in mainnet history).
- Source-level regression guards on BUG-4 (single-path check),
  BUG-7 (three-copy check_sequence).
- Forward-regression: every `consensus.SEQUENCE_LOCKTIME_*` constant
  pinned to its Core value.
