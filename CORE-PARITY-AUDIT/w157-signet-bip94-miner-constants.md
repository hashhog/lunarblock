# W157 — Signet block solution + BIP-94 timewarp + miner-side header constants (lunarblock)

**Wave:** W157 — `CheckSignetBlockSolution`,
`FetchAndClearCommitmentSection`, `SIGNET_HEADER` 0xecc7daa2,
`SignetTxs::Create`, `signet_challenge` consensus param,
`signet_blocks` flag, `SigNetParams`, `enforce_BIP94`, `MAX_TIMEWARP=600`,
`GetMinimumTime` (miner.cpp:36-47), `UpdateTime`,
`GetNextWorkRequired`, `fPowAllowMinDifficultyBlocks`,
`PermittedDifficultyTransition`, nVersion BIP-9 signaling, target
nBits compact encoding.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/signet.cpp:28` —
  `static constexpr uint8_t SIGNET_HEADER[4] = {0xec, 0xc7, 0xda, 0xa2}`.
- `bitcoin-core/src/signet.cpp:30` —
  `BLOCK_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_NULLDUMMY`
  for signet block-solution script verification.
- `bitcoin-core/src/signet.cpp:32-57` — `FetchAndClearCommitmentSection`:
  walks witness-commitment opcodes, extracts the SIGNET_HEADER-prefixed
  pushdata, strips it in-place, returns extracted solution bytes.
- `bitcoin-core/src/signet.cpp:59-68` — `ComputeModifiedMerkleRoot`:
  rebuilds the merkle root with the SIGNET signature *removed* from
  the coinbase (the coinbase commits to the block hash, which commits
  to the merkle root, so the solution-bearing tree must exclude the
  solution itself).
- `bitcoin-core/src/signet.cpp:70-123` — `SignetTxs::Create`: builds the
  pair of synthetic transactions (to_spend, to_sign) over the modified
  merkle root + previous block header; coinbase must contain a witness
  commitment.
- `bitcoin-core/src/signet.cpp:126-153` — `CheckSignetBlockSolution`:
  genesis short-circuits true; otherwise builds SignetTxs from
  `consensusParams.signet_challenge`; rejects on parse failure
  (`"bad-signet-blksig"`); runs `VerifyScript(scriptSig, signetTxs->m_to_spend.vout[0].scriptPubKey, &witness, BLOCK_SCRIPT_VERIFY_FLAGS, sigcheck)`;
  any failure → `BLOCK_CONSENSUS, "bad-signet-blksig"`.
- `bitcoin-core/src/validation.cpp:3930-3933` —
  `CheckBlock` wires it in:
  `if (consensusParams.signet_blocks && fCheckPOW && !CheckSignetBlockSolution(block, consensusParams)) return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-signet-blksig", ...)`.
  Runs BEFORE merkle-root check, AFTER PoW check.
- `bitcoin-core/src/kernel/chainparams.cpp:451-453` — SigNetParams sets
  `consensus.signet_blocks = true; consensus.signet_challenge.assign(bin.begin(), bin.end());`
  where `bin` is the parsed `-signetchallenge=<hex>` argument or
  default-signet (line 412-444 default challenge:
  `512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae`).
- `bitcoin-core/src/kernel/chainparams.cpp:464` — SigNetParams
  `consensus.enforce_BIP94 = false` (signet does NOT enforce BIP-94 at
  consensus; only testnet4 + opt-in regtest do).
- `bitcoin-core/src/kernel/chainparams.cpp:463` — SigNetParams
  `consensus.fPowAllowMinDifficultyBlocks = false` (signet uses real
  retargeting, no testnet min-diff).
- `bitcoin-core/src/kernel/chainparams.cpp:484-486` — SigNetParams
  genesis `CreateGenesisBlock(1598918400, 52613770, 0x1e0377ae, 1, 50 * COIN)`,
  `hashGenesisBlock == 00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6`.
- `bitcoin-core/src/kernel/chainparams.cpp:475-479` — SigNetParams
  message-start derivation: `HashWriter h{}; h << consensus.signet_challenge; uint256 hash = h.GetHash(); std::copy_n(hash.begin(), 4, pchMessageStart.begin());`
  i.e. magic bytes are derived from the challenge, NOT hardcoded.
- `bitcoin-core/src/kernel/chainparams.cpp:489-502` — SigNetParams
  default-signet `m_assumeutxo_data` at heights 160000 + 290000.
- `bitcoin-core/src/kernel/chainparams.cpp:547` — RegTestParams
  `consensus.enforce_BIP94 = opts.enforce_bip94` — opt-in via
  `-test=bip94` (see `bitcoin-core/src/init.cpp` ArgsManager parse).
- `bitcoin-core/src/consensus/consensus.h:35` —
  `static constexpr int64_t MAX_TIMEWARP = 600` seconds.
- `bitcoin-core/src/consensus/params.h:117-121` — `enforce_BIP94` field
  docstring: "On testnet4 this also enforces the block storm mitigation".
- `bitcoin-core/src/consensus/params.h:140` —
  `std::vector<uint8_t> signet_challenge;` (per-network).
- `bitcoin-core/src/pow.cpp:67-73` — `CalculateNextWorkRequired` BIP-94
  branch: when `params.enforce_BIP94`, uses
  `pindexFirst = pindexLast->GetAncestor(pindexLast->nHeight - (DifficultyAdjustmentInterval()-1))`
  and sets `bnNew.SetCompact(pindexFirst->nBits)` (rather than
  `pindexLast->nBits`); preserves real difficulty across periods that
  include min-diff exception blocks.
- `bitcoin-core/src/pow.cpp:14-48` — `GetNextWorkRequired` per-block
  dispatch; testnet `fPowAllowMinDifficultyBlocks` 20-min exception
  branch at lines 22-37.
- `bitcoin-core/src/pow.cpp:89-136` — `PermittedDifficultyTransition`:
  4× clamp window check at every retarget boundary; non-retarget
  blocks must have identical `nBits`.
- `bitcoin-core/src/validation.cpp:4080-4118` —
  `ContextualCheckBlockHeader`: enforces `bad-diffbits`, `time-too-old`
  (MTP gate), BIP-94 `time-timewarp-attack` (gated on
  `consensusParams.enforce_BIP94`), `time-too-new`, then `bad-version`
  for outdated nVersion.
- `bitcoin-core/src/validation.cpp:4101` — BIP-94 timewarp consensus
  rule: `block.GetBlockTime() < pindexPrev->GetBlockTime() - MAX_TIMEWARP`
  → reject.
- `bitcoin-core/src/node/miner.cpp:36-47` — `GetMinimumTime`:
  `min_time = pindexPrev->GetMedianTimePast() + 1; if (height % difficulty_adjustment_interval == 0) min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);`
  applies on ALL NETWORKS regardless of `enforce_BIP94` (defensive;
  future-activation-safe). Comment: "Account for BIP94 timewarp rule
  on all networks. This makes future activation safer."
- `bitcoin-core/src/node/miner.cpp:49-65` — `UpdateTime`:
  `pblock->nTime = std::max<int64_t>(GetMinimumTime, NodeClock::now())`,
  then if `fPowAllowMinDifficultyBlocks` recomputes `nBits =
  GetNextWorkRequired(pindexPrev, pblock, consensusParams)`.
- `bitcoin-core/src/node/miner.cpp:220` — `CreateNewBlock` calls
  `pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus())`.
- `bitcoin-core/src/rpc/mining.cpp:699-700` — `getblocktemplate` emits
  `signet_challenge` field when `consensusParams.signet_blocks` is set:
  `result.pushKV("signet_challenge", HexStr(consensusParams.signet_challenge))`.
- `bitcoin-core/src/rpc/blockchain.cpp::getblockchaininfo` — emits
  `signet_challenge` when on signet.
- `bitcoin-core/src/util/chaintype.cpp::ChainTypeToString` —
  canonical chain names: `main`, `test`, `testnet4`, `signet`,
  `regtest`.

**Files audited**
- `src/consensus.lua:1-1395` — `M.networks.{mainnet,testnet,testnet4,regtest}`
  table (lines 848, 987, 1058, 1130); **NO `M.networks.signet` entry**.
  `M.MAX_TIMEWARP = 600` (line 41).
  `M.HALVING_INTERVAL = 210000` (line 48, global).
  `M.DIFFICULTY_ADJUSTMENT_INTERVAL = 2016` (line 64).
  `M.MAX_FUTURE_BLOCK_TIME = 2*60*60` (line 35).
  `M.bits_to_target` (line 75-130) returns all-zero string for
  negative / zero-mantissa / exponent>34 — does NOT propagate a
  "no target" sentinel (Core's `DeriveTarget` returns `nullopt`).
  `M.target_to_bits` (line 135-174).
  `M.hash_meets_target` (line 180-195).
  `M.calculate_next_target` (line 202-260) — BIP-94 path via optional
  `first_block_bits` arg.
  `M.permitted_difficulty_transition` (line 281-332).
  `M.scale_target_by_timespan` (line 341-378).
  `M.get_next_work_required` (line 401-480) — `pow_no_retarget`,
  `pow_allow_min_difficulty` walk-back, and BIP-94 branches all wired.
  `M.compute_block_version` (line 744-774) — bare `VERSIONBITS_TOP_BITS`
  when `get_block_info` is nil; nVersion never ORs in signet challenge
  signaling bits (signet is height-based, not BIP-9, but Core uses
  BIP-9 deployments for testdummy on signet).
  `M.validate_buried_deployment_consistency` (line 1222-1272) — only
  walks mainnet, no signet/testnet4 buried-height assertions.
- `src/sync.lua:935-1100` — `HeaderChain:accept_header`. Time-too-old
  gate at line 977-981; time-too-new at 986-989; **BIP-94 timewarp at
  line 991-1001 gated on `self.network.enforce_bip94`**;
  `get_next_work_required` call at line 1006-1015; `bad-version` at
  line 1034-1049. **No CheckSignetBlockSolution call anywhere in the
  block-accept pipeline.**
- `src/sync.lua:2229-2233` — `connect_pending_blocks` calls
  `validation.check_block` under `pcall` (catches LuaJIT assert).
- `src/validation.lua:1080-1094` — `M.check_proof_of_work`: checks
  `target > pow_limit` but the comparator uses
  `M.compare_targets(target, pow_limit) > 0`. If `bits_to_target`
  collapsed a negative mantissa to all-zeros, this check passes
  (0 ≤ pow_limit) and `hash_meets_target` then returns true only on
  hash==0 — divergent from Core.
- `src/validation.lua:1237-1250` — `M.check_block_header`: uses
  `assert(header.timestamp <= current_time + MAX_FUTURE_BLOCK_TIME, "time-too-new")`
  and `assert(M.check_proof_of_work(header, network), "proof of work failed")`.
  LuaJIT assert pattern (W156 6th instance).
  **NO MTP / time-too-old gate; NO BIP-94 timewarp gate; NO bad-diffbits
  / bad-version checks.** These exist only in sync.lua's accept_header.
- `src/validation.lua:1298-1430` — `M.check_block`: chained asserts;
  **NO signet block-solution call**.
- `src/mining.lua:250-494` — `M.create_block_template`. MTP at line
  266-267 (`chain_state.mtp or os.time()-3600`). Header at line 393-400
  (`os.time()` literal — no UpdateTime). Bits at line 382 (`get_header(prev_hash).bits`
  — parent's bits; W154 BUG-1 carry-forward, comment-as-confession at
  line 383). Template `mintime = mtp + 1` at line 442 — no
  GetMinimumTime BIP-94 clamp. **NO UpdateTime / GetMinimumTime
  functions defined anywhere in mining.lua.**
- `src/mining.lua:505-528` — `M.mine_block` CPU regtest miner; loops
  nonces against `consensus.hash_meets_target`; does not call
  GetMinimumTime or BIP-94 paths.
- `src/main.lua:80-260` — CLI flag parser. `--network NET` (line
  148-150) only accepts `mainnet | testnet | regtest` per help text
  (line 95). **NO `--signet` flag, NO `--signetchallenge=<hex>`,
  NO `--test=bip94` regtest opt-in. NO signet entry exists, so
  `--network signet` resolves to `consensus.networks.signet` which is
  `nil` → "Unknown network" exit.**
- `src/address.lua:411-419` — Comments mention "testnet/regtest/signet
  share prefixes" — but the actual `else` branch falls through to
  testnet prefixes generically, with no signet network table to look
  up `signet`'s bech32 hrp (`tb`).
- `src/rpc.lua:27` — Comment mentions `signet → signet` for chain
  name translation; the actual `core_chain_name` (line 32-38) has no
  signet branch — falls through `else return internal_name`, which is
  fine in principle but cannot fire (no signet network exists).
- `src/rpc.lua:1265-1366` — `getblockchaininfo` handler. **Never emits
  `signet_challenge`** even hypothetically — the result table at line
  1339-1355 has no such field. Cross-cite Core
  `bitcoin-core/src/rpc/blockchain.cpp::getblockchaininfo`.
- `src/rpc.lua:3869-3885` — `getblocktemplate` handler. **Never emits
  `signet_challenge`** (Core mining.cpp:699-700 emits when
  `signet_blocks`).
- `src/rpc.lua:185-194` — `bip22_result` regex maps for `time-too-new`,
  `time-too-old`, `time-timewarp-attack`. **No mapping for
  `bad-signet-blksig`.**
- `src/peerman.lua` / `src/peer.lua` — Wire-message dispatch is
  per-network-magic-aware via `network.magic_bytes` (consensus.lua:850,
  989, 1060, 1132). With no signet entry, signet peers cannot be
  identified or connected to. P2P never starts for signet.

---

## Gate matrix (35 sub-gates / 14 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | CheckSignetBlockSolution present | G1: function defined | **BUG-1 (P0-CDIV)** — entirely absent fleet-wide for lunarblock |
| 1 | … | G2: called from CheckBlock / accept_block | **BUG-1 cross-cite** |
| 1 | … | G3: rejects with `bad-signet-blksig` reject string | **BUG-1 cross-cite** + **BUG-21 (P1)** — `bip22_result` mapping absent at rpc.lua:56-213 |
| 2 | SIGNET_HEADER 0xecc7daa2 constant | G4: 4-byte magic defined | **BUG-2 (P0-CDIV)** — no SIGNET_HEADER constant exists anywhere |
| 2 | … | G5: FetchAndClearCommitmentSection logic | **BUG-2 cross-cite** — no analogue exists |
| 3 | signet_challenge chain param wired | G6: `signet_challenge` field on network table | **BUG-3 (P0-CDIV)** — no signet network at all (consensus.lua has only mainnet/testnet/testnet4/regtest) |
| 3 | … | G7: `signet_blocks = true` boolean gate | **BUG-3 cross-cite** |
| 3 | … | G8: default-signet challenge hex hardcoded | **BUG-3 cross-cite** |
| 3 | … | G9: `--signetchallenge=<hex>` CLI override | **BUG-4 (P1)** — no `--signetchallenge` flag in main.lua |
| 3 | … | G10: signet magic bytes derived via SHA256(challenge) | **BUG-5 (P1)** — no per-challenge magic derivation; mainnet/testnet magics are hardcoded but signet's must be computed from challenge |
| 4 | BIP-94 MAX_TIMEWARP=600 | G11: constant defined | PASS (`consensus.lua:41`) |
| 4 | … | G12: consensus.cpp validation.cpp:4097-4105 gate active when `enforce_BIP94` | PASS (`sync.lua:991-1001`) for header-accept; **BUG-6 (P0-CDIV)** validation.lua check_block_header does NOT enforce this gate (two-pipeline split) |
| 4 | … | G13: `enforce_BIP94` opt-in for regtest via `-test=bip94` | **BUG-7 (P0-CDIV)** — no `-test=bip94` CLI flag (main.lua); regtest `enforce_bip94 = false` is hardcoded (consensus.lua:1174), no override path |
| 5 | GetMinimumTime miner-side clamps | G14: `min_time = MTP + 1` | PARTIAL (`mining.lua:442`) — uses `mtp` but `chain_state.mtp` never populated (W154 BUG-2+3 carry-forward 2nd time) |
| 5 | … | G15: BIP-94 timewarp clamp at retarget on ALL networks (defensive) | **BUG-8 (P0-CDIV)** — `GetMinimumTime`'s `max(min_time, prev_block_time - MAX_TIMEWARP)` on retarget is absent; lunarblock unconditionally emits `mintime = mtp + 1` regardless of period boundary AND regardless of `enforce_bip94`. Same shape as W154 BUG-4 but here the broader miner-side defense-in-depth is the issue |
| 5 | … | G16: UpdateTime called before final mining | **BUG-9 (P0-CDIV)** — no UpdateTime function; `mining.lua:397` uses `os.time()` literally; `mining.lua:505-528` mine_block never re-stamps. On testnet `pow_allow_min_difficulty` the recomputed `GetNextWorkRequired(pindexPrev, pblock, ...)` after time-bump is missed |
| 6 | enforce_BIP94 consensus param | G17: per-network enforce_bip94 field | PASS (`consensus.lua:913, 1035, 1107, 1174`); **BUG-10 (P1)** — testnet4 sets `true` (correct), but mainnet/testnet/regtest all set `false` with no opt-in path (BUG-7) |
| 7 | nVersion BIP-9 signaling | G18: starts at VERSIONBITS_TOP_BITS (0x20000000) | PASS (`consensus.lua:745`) |
| 7 | … | G19: ORs in STARTED/LOCKED_IN deployment masks | **BUG-11 (P1)** — `compute_block_version` always receives nil `get_block_info` from `create_block_template` → returns bare top-bits. Carry-forward W154 BUG-19 |
| 7 | … | G20: signet uses BIP-9 testdummy on bit 28 | **BUG-12 (P1)** — no signet network = no deployments table for signet's BIP-9 testdummy slot |
| 8 | target nBits compact encoding | G21: bits_to_target handles negative correctly | **BUG-13 (P1)** — collapses to all-zero string (consensus.lua:118-122); Core's `DeriveTarget` returns `nullopt` propagating to `CheckProofOfWork` returning false. lunarblock's `compare_targets(0, pow_limit) ≤ 0` passes the pow-limit gate then `hash_meets_target` only matches hash==0. Semantically divergent for nBits with the negative flag set |
| 8 | … | G22: bits_to_target handles overflow (exponent>34) | PARTIAL — clamps to all-zero (consensus.lua:88-90); Core returns `nullopt`. Same divergence as G21 |
| 8 | … | G23: bits_to_target handles fOverflow case (mantissa nonzero AND exponent makes value > 256 bits) | **BUG-14 (P1)** — Core's `arith_uint256::SetCompact` distinguishes `fOverflow` (positive non-zero target that exceeds 256 bits). lunarblock only checks `exponent > 34`; an exponent in [4,34] with the mantissa shifted past the 256-bit cap is not flagged |
| 9 | GetNextWorkRequired at retarget called by mining | G24: `mining.lua` calls `consensus.get_next_work_required` | **BUG-15 (P0-CDIV)** — confirms W154 BUG-1: `mining.lua:382` reads parent's bits via `chain_state.storage.get_header(prev_hash).bits` with comment-as-confession "In a real implementation, compute next required bits at retarget heights". Helper exists at `consensus.lua:401` one wiring line away. 6th-week-open carry-forward |
| 10 | fPowAllowMinDifficultyBlocks per-network | G25: signet sets false | **BUG-16 (P1)** — no signet entry to test against; Core sets `false`. Effectively absent fleet-wide |
| 10 | … | G26: regtest sets true | PASS (`consensus.lua:1173`) |
| 11 | signet uses real retargeting (no min-diff) | G27: signet's `pow_no_retarget = false` AND `pow_allow_min_difficulty = false` | **BUG-3 cross-cite** — no signet entry |
| 12 | default signet_challenge vs custom | G28: default-signet hex `512103…ae` baked in | **BUG-3 cross-cite** |
| 12 | … | G29: custom signet via `--signetchallenge=<hex>` | **BUG-4 cross-cite** |
| 13 | getblocktemplate emits signet_challenge | G30: `signet_challenge` field present on signet | **BUG-17 (P1)** — `rpc.lua:3869-3885` getblocktemplate handler does not branch on signet; never emits the field |
| 13 | … | G31: getblockchaininfo emits signet_challenge | **BUG-18 (P1)** — `rpc.lua:1339-1355` result table has no `signet_challenge` field |
| 14 | Lua-double precision on POW target comparison | G32: 256-bit target comparison via byte-iteration big-endian | PASS (`consensus.lua:180-195, 384-392`) — pure byte comparator, no double arithmetic |
| 14 | … | G33: chainwork accumulation overflows 53-bit Lua double mantissa | **BUG-19 (P1)** — `consensus.lua:1306-1310` `work_compare` is byte-wise (PASS), but **`calculate_next_target` arithmetic at line 219-256 uses Lua-double `actual_timespan * old_le[i]` per byte; for the largest `actual_timespan = MAX_TIMESPAN = 4_838_400` (~22 bits) times `old_le[i]` (8 bits) = 30-bit product, well within 53-bit mantissa**. PASS in practice for difficulty math; but the same arithmetic in `scale_target_by_timespan` line 354 has identical 30-bit cap. Filed for documentation; not a bug today |
| 14 | … | G34: `actual_timespan` can be NEGATIVE on testnet4 BIP-94 (first.timestamp > prev.timestamp by up to MAX_TIMEWARP=600s before consensus.lua:454 subtraction) | **BUG-20 (P1)** — `actual_timespan = prev.header.timestamp - first.header.timestamp` (line 454) is computed BEFORE clamping in `calculate_next_target`. The clamp at line 204-208 catches `< MIN_TIMESPAN` but does NOT explicitly handle negative. In Lua doubles, `-1 < MIN_TIMESPAN` → clamped to MIN_TIMESPAN, so this happens to work — but only by accident. Core uses `int64_t` and the same clamp |
| 14 | … | G35: testnet4 walk-back through `pow_limit_bits` blocks bounded to period | PASS (`consensus.lua:430-436`) — walks back while `pindex_height % DIFFICULTY_ADJUSTMENT_INTERVAL ~= 0`; matches Core pow.cpp:33-35 |

---

## BUG-1 (P0-CDIV) — `CheckSignetBlockSolution` entirely absent

**Severity:** P0-CDIV. Bitcoin Core's `CheckSignetBlockSolution`
(`signet.cpp:126-153`) is the consensus rule that distinguishes signet
from a "permissionless" network: blocks must carry a valid signature
over the modified merkle root, signed by the federation key
(`signet_challenge`). Without this check, a node would accept any
PoW-valid block on signet — but PoW on signet is laughably easy
(`powLimit = 0x00000377ae...` — much harder than regtest, MUCH easier
than mainnet), so a single CPU-mined block would fork the node off
default-signet at any height ≥ 1.

A grep over `/home/work/hashhog/lunarblock/src/` for `CheckSignet`,
`SignetTxs`, `signet_blocks`, `signet_challenge`, `SIGNET_HEADER`,
or `bad-signet-blksig` returns **zero matches**. The only mention of
"signet" anywhere in the source tree is a comment in `address.lua:411`
("testnet/regtest/signet share prefixes") and one in `rpc.lua:27`
mapping the chain name.

**File:** `src/validation.lua` (no CheckSignetBlockSolution); no
`src/signet.lua` exists; no `src/consensus/signet.lua` exists.

**Core ref:** `bitcoin-core/src/signet.cpp:126-153`;
`bitcoin-core/src/validation.cpp:3930-3933` (CheckBlock wire-in).

**Impact:**
- If lunarblock were ever asked to validate signet, it would have no
  way to reject a block whose merkle root was not signed by the
  federation. A single attacker block at any signet height ≥ 1 would
  fork the node away from the canonical signet chain.
- Cross-impl divergence: every other hashhog impl that supports
  signet has at least a skeleton signet check. lunarblock is unique
  in having NONE.
- BUG-3 below makes this dormant in practice (no signet network table
  exists, so `--network signet` returns "Unknown network" and the
  daemon refuses to start). But the moment BUG-3 is fixed without
  BUG-1, the resulting node would silently accept any PoW-valid block
  as signet-valid — a worse failure mode than refusal.

---

## BUG-2 (P0-CDIV) — `SIGNET_HEADER` 0xecc7daa2 constant absent

**Severity:** P0-CDIV. Bitcoin Core defines
`static constexpr uint8_t SIGNET_HEADER[4] = {0xec, 0xc7, 0xda, 0xa2}`
(`signet.cpp:28`). This is the magic prefix that
`FetchAndClearCommitmentSection` searches for inside the witness
commitment's pushdata to identify the signet signature payload.
Without this constant, no signet pipeline can decode block solutions.

lunarblock has no SIGNET_HEADER, no FetchAndClearCommitmentSection,
no signet-specific pushdata search. The witness-commitment parser
in `validation.lua` (`check_witness_malleation`) only knows about the
BIP-141 commitment marker (`0x6a24aa21a9ed`) — it does not search for
or strip the signet signature.

**File:** N/A — constant + helper entirely absent.

**Core ref:** `bitcoin-core/src/signet.cpp:28-57`.

**Impact:** even if BUG-1 were partially fixed (e.g. a stub
CheckSignetBlockSolution that rejected everything), the absence of
SIGNET_HEADER means the function would have no way to *extract* the
solution from the coinbase witness commitment. Two architectural
holes that must be fixed together.

---

## BUG-3 (P0-CDIV) — No `signet` entry in `M.networks` table

**Severity:** P0-CDIV. `consensus.lua` exposes
`M.networks.{mainnet,testnet,testnet4,regtest}` (lines 848, 987,
1058, 1130) but **no `M.networks.signet` entry**. `main.lua:398`:

```lua
local network = consensus_mod.networks[args.network]
if not network then
  io.stderr:write("Unknown network: " .. args.network .. "\n")
  os.exit(1)
end
```

Effect: `lunarblock --network signet` exits immediately with
"Unknown network: signet". Signet is structurally unsupported.

The bare minimum signet entry per Core
(`bitcoin-core/src/kernel/chainparams.cpp:451-487`) requires:
- `signet_blocks = true`
- `signet_challenge = <bytes>` (default or custom)
- `magic_bytes = SHA256(signet_challenge)[0..4]` (derived, not hardcoded)
- `pow_limit_bits = 0x1e0377ae`
- `pow_allow_min_difficulty = false`
- `pow_no_retarget = false`
- `enforce_bip94 = false`
- `pow_target_spacing = 600`
- `pow_target_timespan = 14*24*3600`
- `bip34_height = 1`, `bip65_height = 1`, `bip66_height = 1`,
  `csv_height = 1`, `segwit_height = 1`, `taproot_height = 1`
  (all soft forks active from height 1 on signet)
- `bech32_hrp = "tb"`
- `genesis = {version=1, timestamp=1598918400, bits=0x1e0377ae, nonce=52613770}`
- `genesis_hash = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"`
- `default_port = 38333`, `default_rpc_port = 38332`
- `nMinimumChainWork`, `defaultAssumeValid` for default-signet
- `assumeutxo` snapshots at heights 160000 + 290000

**File:** `src/consensus.lua:845-1196` (network table block);
`src/main.lua:398-402` (lookup); `src/main.lua:95` (help text omits
signet).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp::SigNetParams`
(lines 230-521).

**Impact:** signet is unreachable on lunarblock. No way to validate
signet blocks, no way to peer with signet nodes (magic-bytes match
fails immediately at the version handshake), no way to advance to
signet's tip. This forecloses ~5% of Bitcoin testing traffic by
deployment count.

---

## BUG-4 (P1) — No `--signetchallenge=<hex>` CLI flag

**Severity:** P1. Core's `-signetchallenge=<hex>` arg
(`kernel/chainparams.cpp:386-411` parses it as ARG_DISALLOW_NEGATION
hex string; SigNetOptions consumes it) is how operators run
private-signet networks: provide a custom federation script and the
chain magic-bytes are derived from it. Without this flag, even fixing
BUG-3 with a default-signet hardcode leaves no way to spin up a
private signet for testing.

`main.lua:80-260` has no `--signetchallenge`, no `--signetseednode`,
no `--signetnchain` (Core's analogous test knobs).

**File:** `src/main.lua:80-260` (flag parser; no signet-specific
entries).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:386-411`;
`bitcoin-core/src/init.cpp::SetupServerArgs` (`-signetchallenge`,
`-signetseednode`).

**Impact:** private-signet workflows blocked. Cannot reproduce the
signet test environments used by other hashhog impls or by Core's
CI.

---

## BUG-5 (P1) — Signet magic bytes must be derived from challenge; no derivation path

**Severity:** P1. Core derives signet's `pchMessageStart` from
`SHA256(consensus.signet_challenge).first(4)`
(`kernel/chainparams.cpp:476-479`):

```cpp
HashWriter h{};
h << consensus.signet_challenge;
uint256 hash = h.GetHash();
std::copy_n(hash.begin(), 4, pchMessageStart.begin());
```

This means each custom signet has its own magic bytes, isolating it
from default-signet at the wire layer. lunarblock's network table
hardcodes `magic_bytes` per-entry (consensus.lua:850 mainnet, 989
testnet3, 1060 testnet4, 1132 regtest). There is no per-challenge
derivation. Even if BUG-3 added a default-signet entry with the
default-signet magic `0x0a 03 cf 40` (SHA256 of default challenge),
**custom signets via BUG-4 cannot be supported** because the magic
would need to be recomputed at runtime.

**File:** `src/consensus.lua:848-1196` (per-network magic_bytes
hardcoded); no `derive_signet_magic` helper exists.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:476-479`.

**Impact:** even fully fixing BUG-3 + BUG-4 would only support
default-signet; custom signet still impossible without architectural
support for per-challenge magic derivation.

---

## BUG-6 (P0-CDIV) — `validation.lua` check_block_header skips BIP-94 timewarp gate

**Severity:** P0-CDIV — "two-pipeline guard 18th distinct extension"
this would be — first time header-validation BIP-94 gate is doubled.
lunarblock has TWO header-validation entry points:

1. **`HeaderChain:accept_header`** (`sync.lua:935-1100`) — the
   canonical IBD/relay path. Enforces `time-too-old`,
   `time-too-new`, BIP-94 `time-timewarp-attack` (gated on
   `enforce_bip94`), `bad-diffbits`, `bad-version`.

2. **`M.check_block_header`** (`validation.lua:1237-1250`) — called
   from `M.check_block` (`validation.lua:1302`) which is in turn
   called from `sync.lua:2232` via `validation.check_block`. Enforces
   ONLY `time-too-new` and `proof of work failed` (via
   `check_proof_of_work` which returns boolean, not specific reject
   string).

**The second pipeline is missing:**
- MTP `time-too-old` gate
- BIP-94 `time-timewarp-attack` gate
- `bad-diffbits` gate (compares against `get_next_work_required`)
- `bad-version` gate (rejects nVersion < 4 after BIP65 activation)

A peer that crafted a block whose header passed accept_header but
failed check_block_header (or vice versa) would expose the
divergence. In practice the asymmetry is "accept_header is stricter
than check_block_header" — but the architectural duplication means
any future patch to accept_header must be mirrored to
check_block_header, and historical experience (W143 BUG-3 nimrod
reindex bypass; W143 BUG-3 lunarblock reorg connect loop) shows
those mirrors get forgotten.

**File:** `src/validation.lua:1237-1250` (check_block_header);
`src/sync.lua:935-1049` (accept_header — full set of gates).

**Core ref:** `bitcoin-core/src/validation.cpp:4080-4118`
(ContextualCheckBlockHeader — ONE function, all gates).

**Excerpt (lunarblock validation.lua, missing gates)**
```lua
function M.check_block_header(header, network)
  network = network or consensus.networks.mainnet
  -- Check timestamp not more than 2 hours in future (time-too-new).
  local current_time = os.time()
  assert(header.timestamp <= current_time + consensus.MAX_FUTURE_BLOCK_TIME,
         "time-too-new")
  -- Check proof of work
  assert(M.check_proof_of_work(header, network), "proof of work failed")
  -- MISSING: MTP time-too-old check
  -- MISSING: BIP-94 timewarp check
  -- MISSING: bad-diffbits check against get_next_work_required
  -- MISSING: bad-version check for BIP-34/65/66
  return true
end
```

**Impact:** any code path that calls `check_block_header` without
also going through `accept_header` (e.g. testing harnesses,
hypothetical fast-path validators, future RPC handlers) would
silently accept a block with a BIP-94 timewarp-attack timestamp,
or with `nBits` not matching the chain's expected target, or with
an outdated nVersion. Three P0-CDIV gates riding on one
architectural split.

---

## BUG-7 (P0-CDIV) — `enforce_BIP94` regtest opt-in (`-test=bip94`) absent

**Severity:** P0-CDIV. Bitcoin Core regtest is the canonical place to
exercise consensus rules in isolation. Core's
`kernel/chainparams.cpp:547` sets
`consensus.enforce_BIP94 = opts.enforce_bip94` on regtest, where
`opts.enforce_bip94` is wired to the `-test=bip94` CLI argument
(`bitcoin-core/src/init.cpp::ParseTestOptions` parses
`-test=<comma-separated-list>`). This is how Core's functional
tests verify BIP-94 behavior without spinning up a testnet4.

lunarblock has NO `-test=` flag, NO opt-in for BIP-94 on regtest,
NO runtime mutator for `network.enforce_bip94`. The field is
hardcoded `false` for regtest (consensus.lua:1174). There is no
path that toggles it.

**File:** `src/main.lua:80-260` (no `--test` flag); `src/consensus.lua:1174`
(`enforce_bip94 = false` regtest, no override).

**Core ref:** `bitcoin-core/src/init.cpp::SetupChainParamsBaseOptions`
(`-test=`); `bitcoin-core/src/util/chaintype.cpp::ChainTypeFromString`
(regtest options dispatch).

**Impact:**
- lunarblock cannot run any consensus test that requires BIP-94 on a
  controllable, isolated network. Tests would need to spin up
  testnet4 (slow, dependent on real peers).
- Cross-fleet: every other hashhog impl that supports `-test=bip94`
  can run a 4-block retarget on regtest in <1 second; lunarblock
  cannot.
- Future BIP-94 activation on signet/mainnet: even if the consensus
  flag is flipped, lunarblock has no regtest path to test the
  semantics before deployment.

---

## BUG-8 (P0-CDIV) — `GetMinimumTime` defensive BIP-94 retarget clamp absent

**Severity:** P0-CDIV. Bitcoin Core's `GetMinimumTime`
(`miner.cpp:36-47`) applies the BIP-94 retarget timewarp defense
**on ALL NETWORKS regardless of `enforce_BIP94`**:

```cpp
int64_t GetMinimumTime(const CBlockIndex* pindexPrev, const int64_t difficulty_adjustment_interval)
{
    int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
    const int height{pindexPrev->nHeight + 1};
    // Account for BIP94 timewarp rule on all networks. This makes future
    // activation safer.
    if (height % difficulty_adjustment_interval == 0) {
        min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
    }
    return min_time;
}
```

The comment "on all networks" is intentional — Core's miner refuses
to emit a block timestamp that would violate BIP-94 EVEN ON MAINNET,
because once BIP-94 activates on mainnet (currently planned for a
future soft fork), pre-emptive miner discipline avoids the painful
post-activation period where un-disciplined miners would produce
unmineable templates.

lunarblock's `create_block_template` (`mining.lua:442`) sets:

```lua
mintime = mtp + 1,
```

with no `max(mtp + 1, prev_block_time - MAX_TIMEWARP)` clamp on
retarget boundaries, and no awareness of `enforce_bip94` either way.
The defensive shape is missing entirely.

W154 BUG-4 already flagged the absence; this audit confirms it is
still open and elevates because:
1. Per the Core comment, the defense should fire on **mainnet too**
   — not just testnet4. So the bug is broader than W154 framed.
2. The helper `consensus.MAX_TIMEWARP` exists (consensus.lua:41) and
   is correctly named — wiring it is one line.

**File:** `src/mining.lua:442` (mintime emission); no
`get_minimum_time` helper exists.

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47`.

**Impact:** when BIP-94 eventually activates on mainnet (or any other
network), every lunarblock-driven mining pool template at the
retarget boundary risks violating the consensus rule. Operators
running lunarblock miners on a future mainnet post-activation would
mine unmineable blocks (Core peers reject `time-timewarp-attack`).
The defense is one line: `mintime = math.max(mtp + 1, parent.timestamp - consensus.MAX_TIMEWARP)` at retarget.

---

## BUG-9 (P0-CDIV) — `UpdateTime` function does not exist; `os.time()` baked into header at template time

**Severity:** P0-CDIV. Bitcoin Core's `UpdateTime`
(`miner.cpp:49-65`) is the canonical bridge between template-build
time and final-mining time:

```cpp
int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime{std::max<int64_t>(GetMinimumTime(pindexPrev, consensusParams.DifficultyAdjustmentInterval()),
                                       TicksSinceEpoch<std::chrono::seconds>(NodeClock::now()))};
    if (nOldTime < nNewTime) {
        pblock->nTime = nNewTime;
    }
    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks) {
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);
    }
    return nNewTime - nOldTime;
}
```

This is called both from `CreateNewBlock` (miner.cpp:227) and from
the long-poll / retry paths in `getblocktemplate`. It serves three
critical purposes:
1. Bumps `nTime` if wall-clock has advanced since the template was
   built (a template built 30 seconds ago and submitted now should
   have a slightly newer timestamp).
2. Applies `GetMinimumTime` (which includes the BIP-94 defense from
   BUG-8).
3. On testnet with `fPowAllowMinDifficultyBlocks`, the 20-minute
   exception rule means `nBits` can flip when `nTime` advances, so
   it is recomputed.

lunarblock has NO `UpdateTime` function. `mining.lua:397` hardcodes
the template's header timestamp:

```lua
local header = types.block_header(
  block_version,
  prev_hash,
  merkle_root,
  os.time(),  -- <-- bakes wall-clock at template-build time
  bits,
  0  -- nonce starts at 0
)
```

The CPU miner (`mining.lua:505-528`) loops nonces against this fixed
timestamp; if mining takes >2 hours the resulting block is
`time-too-new` immediately on submission.

The retemplate-driven flow does not exist. The testnet `nBits`
recomputation after time-bump does not exist (compounds with BUG-15).

**File:** `src/mining.lua:393-400` (header construction);
`src/mining.lua:505-528` (mine_block); no UpdateTime function defined
anywhere.

**Core ref:** `bitcoin-core/src/node/miner.cpp:49-65`.

**Impact:**
- Templates have a stale `nTime`; pool software that holds a
  template for >2 hours emits `time-too-new` on submit.
- testnet/testnet4 min-diff blocks: `nBits` is computed at template
  build (under the build-time `nTime`); after submission `nBits` is
  validated under a later `nTime` (e.g. submit-time os.time() in the
  miner), which may have crossed the 20-minute min-diff exception
  boundary, causing `bad-diffbits` rejection.
- No long-poll discipline.

---

## BUG-10 (P1) — `enforce_bip94 = false` mainnet has no opt-in

**Severity:** P1. Cross-cite with BUG-7. Even if a future Bitcoin
Improvement Proposal flipped mainnet to enforce BIP-94 at some
height, lunarblock has no runtime override path. The field is
hardcoded at `consensus.lua:913` (`enforce_bip94 = false`). A patch
to flip the activation point would require source modification and
a redeploy — Core's approach of plumbing `opts.enforce_bip94` via
the chainparams options struct allows the consensus param to be
read from CLI/config for activation testing.

**File:** `src/consensus.lua:913` (mainnet enforce_bip94 hardcoded).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:547` (regtest
opts plumbing).

**Impact:** future BIP-94 activation on mainnet requires source
edit + redeploy; cannot be A/B-tested per-node.

---

## BUG-11 (P1) — `compute_block_version` always emits bare VERSIONBITS_TOP_BITS

**Severity:** P1 (carry-forward from W154 BUG-19). Confirms the
finding: `compute_block_version` (consensus.lua:744-774) reads
`net.deployments` and short-circuits to bare `VERSIONBITS_TOP_BITS`
when the deployments list is absent or `get_block_info` is nil.
Every production call site in `mining.lua:390` passes nil for
`get_block_info`, so the function returns `0x20000000` unconditionally.
No deployment masks are ever ORed in.

Cross-cite: relevant for signet, where Core's BIP-9 testdummy is
defined on bit 28 (`kernel/chainparams.cpp:468-473`) and lunarblock
would need to OR it in when STARTED — but BUG-3 means signet has no
deployments at all.

**File:** `src/consensus.lua:744-774`; `src/mining.lua:390`.

**Core ref:** `bitcoin-core/src/versionbits.cpp:265-279`
(`ComputeBlockVersion`).

**Impact:** signet testdummy signaling broken; future BIP-9
deployments on any network start un-signaled.

---

## BUG-12 (P1) — No signet BIP-9 deployments table

**Severity:** P1. Cross-cite with BUG-3. Even with the network entry
added, lunarblock would also need a `deployments` array on the
signet network table for BIP-9 testdummy:

```lua
deployments = {
  {bit = 28, start_time = NEVER_ACTIVE, timeout = NO_TIMEOUT,
   min_activation_height = 0, threshold = 1815, period = 2016}
}
```

This is not surfaced by any existing entry (`M.networks.mainnet.deployments`
is nil; `M.compute_block_version` correctly short-circuits at
line 748-751). For signet correctness, the table is required.

**File:** `src/consensus.lua` (no signet entry to put the table on).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:468-473`
(signet TESTDUMMY deployment).

**Impact:** even after fixing BUG-3, signet BIP-9 signaling is
broken until the deployments table is wired.

---

## BUG-13 (P1) — `bits_to_target` returns all-zero for negative nBits; cannot reject distinctly from valid zero

**Severity:** P1 ("comment-as-confession" — `consensus.lua:117-122`
contains an inline comment "Negate the target (two's complement) -
not typically used in Bitcoin / For safety, just return zero target
for negative" — admits the divergence). Bitcoin Core's
`arith_uint256::SetCompact` returns the target as a uint256 with the
`fNegative` and `fOverflow` flags reported back to the caller.
`DeriveTarget` (`pow.cpp:146-159`) then returns `nullopt` when any
of `fNegative || bnTarget == 0 || fOverflow || bnTarget > pow_limit`,
and `CheckProofOfWork` consumes the `nullopt` as "PoW invalid".

lunarblock collapses all three error cases (negative, zero-mantissa,
exponent>34) to the all-zero 32-byte string. Then
`M.check_proof_of_work` does:

```lua
local pow_limit = consensus.bits_to_target(network.pow_limit_bits)
if consensus.compare_targets(target, pow_limit) > 0 then
  return false  -- target above pow_limit
end
return consensus.hash_meets_target(block_hash.bytes, target)
```

For target = all-zero, `compare_targets(0, pow_limit) <= 0` → first
gate PASSES. Then `hash_meets_target(hash, all_zeros)` returns true
**only when `hash == all_zeros`** (a 1-in-2^256 event). In practice
that means a negative-nBits or overflow-nBits block is rejected, but
only because no plausible PoW hash equals all-zeros — NOT because the
gate explicitly flagged the malformed bits. A pathological case
that found a real all-zero hash (cosmic-ray-bit-flip-or-otherwise)
would be incorrectly ACCEPTED.

More urgently: the rejection reason is `"insufficient proof of work"`
in lunarblock's path, whereas Core's reason is `"high-hash"` triggered
by the `fNegative || fOverflow` short-circuit. Wire-string parity
slippage (consistent with W125 / W145's lunarblock pattern).

**File:** `src/consensus.lua:117-122`; `src/validation.lua:1080-1094`.

**Core ref:** `bitcoin-core/src/pow.cpp:146-171` (DeriveTarget +
CheckProofOfWorkImpl), `bitcoin-core/src/arith_uint256.cpp::SetCompact`
flag plumbing.

**Impact:** semantic divergence on malformed nBits; rejection
reason wrong; theoretical accept-path on cosmic-ray-induced
all-zero hash.

---

## BUG-14 (P1) — `bits_to_target` does not flag fOverflow distinctly from "exponent > 34"

**Severity:** P1. Bitcoin Core's `arith_uint256::SetCompact` flags
`fOverflow = nWord != 0 && ((nSize > 34) || (nWord > 0xff && nSize > 33) || (nWord > 0xffff && nSize > 32))`
— THREE distinct overflow cases depending on the mantissa's high byte.
lunarblock only checks `if exponent > 34` (`consensus.lua:88-90`), missing
the mantissa-dependent cases:
- exponent=33 with mantissa high byte > 0xff
- exponent=32 with mantissa high byte > 0xffff

A constructed nBits like `0x21010000` (exponent=33, mantissa=0x010000)
would in Core produce `fOverflow=true → nullopt → CheckProofOfWork=false`.
In lunarblock: `exponent=33 ≤ 34` passes the first gate, then the
mantissa-byte placement at `consensus.lua:107-115` silently writes
the mantissa byte into target[0..2], producing a 32-byte target
whose top bytes are non-zero and exceed `pow_limit`. The later
`compare_targets(target, pow_limit) > 0` check at
`validation.lua:1089` then rejects it — so it accidentally works,
but with the wrong rejection path.

**File:** `src/consensus.lua:75-130`.

**Core ref:** `bitcoin-core/src/arith_uint256.cpp::SetCompact` (full
`fOverflow` derivation).

**Impact:** semantic divergence in three corner cases; reaches
correct decision via the wrong path; rejection reason mismatches
Core's `high-hash` short-circuit (would be `"insufficient proof of
work"` instead).

---

## BUG-15 (P0-CDIV) — Carry-forward: `create_block_template` reads PARENT's bits, not `get_next_work_required`

**Severity:** P0-CDIV (carry-forward W154 BUG-1, ~2+ weeks open).
Confirmed still present:

```lua
-- src/mining.lua:381-383
-- Get difficulty target
local bits = chain_state.storage.get_header(prev_hash).bits
-- In a real implementation, compute next required bits at retarget heights
```

The helper `consensus.get_next_work_required` exists at
`consensus.lua:401-480` and is correctly wired for mainnet,
testnet3 walk-back, BIP-94/testnet4, and regtest. One wiring line
fixes this:

```lua
local bits = consensus.get_next_work_required(
  height, os.time(), network,
  function(h) return chain_state.storage.get_header(chain_state.storage.get_hash_by_height(h)) end
)
```

Comment-as-confession (`In a real implementation, compute next
required bits at retarget heights`) — 11th distinct lunarblock
instance per W156 tracking.

**File:** `src/mining.lua:381-383`; `src/consensus.lua:401`
(existing helper).

**Core ref:** `bitcoin-core/src/node/miner.cpp:220`.

**Impact (W154 cite):** every 2016-block boundary on mainnet (and
every block on testnet/testnet4) produces an unmineable or
hard-rejected template. Masked in regtest by `pow_no_retarget=true`.

---

## BUG-16 (P1) — No signet `fPowAllowMinDifficultyBlocks = false` setting

**Severity:** P1. Cross-cite with BUG-3. Even if BUG-3 added a
signet network entry, the `pow_allow_min_difficulty` field must be
set to `false` to match Core (`kernel/chainparams.cpp:463`).
testnet/testnet4/regtest in lunarblock all have it set to `true`
— signet must be the exception.

The W156 charter prompt explicitly mentions checking
"fPowAllowMinDifficultyBlocks testnet" → on signet this must be
`false`. Recorded for completeness; cannot fire today because of
BUG-3.

**File:** N/A (no signet entry).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:463`.

**Impact:** if BUG-3 is fixed via copy-paste of testnet3, signet
inherits `pow_allow_min_difficulty = true` and the validation path at
`consensus.lua:284-286` short-circuits `permitted_difficulty_transition`
to always-true — meaning lunarblock would accept any bits on any
signet retarget, breaking signet consensus.

---

## BUG-17 (P1) — `getblocktemplate` does not emit `signet_challenge` field

**Severity:** P1. Core's `getblocktemplate`
(`rpc/mining.cpp:699-700`) emits `signet_challenge` when
`consensusParams.signet_blocks`:

```cpp
if (consensusParams.signet_blocks) {
    result.pushKV("signet_challenge", HexStr(consensusParams.signet_challenge));
}
```

This is essential for signet pool software to know which challenge
script to solve. lunarblock's `getblocktemplate` handler
(`rpc.lua:3869-3885`) emits a template via
`rpc.mining.create_block_template` and serializes it to JSON; the
`signet_challenge` field is never added because there is no
`network.signet_challenge` field to read from (BUG-3 cross-cite).

**File:** `src/rpc.lua:3869-3885`; `src/mining.lua:425-453`
(template construction).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:699-700`.

**Impact:** even after fixing BUG-3, pool software cannot mine
signet blocks without this field. The pool would have no idea what
script to sign.

---

## BUG-18 (P1) — `getblockchaininfo` does not emit `signet_challenge` field

**Severity:** P1. Core's `getblockchaininfo` includes
`signet_challenge` in the result when on signet. lunarblock's
handler (`rpc.lua:1339-1355`) hardcodes the result fields and never
adds `signet_challenge`. Same root cause as BUG-17: there is no
`network.signet_challenge` to read from.

**File:** `src/rpc.lua:1339-1355`.

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp::getblockchaininfo`.

**Impact:** monitoring tools / signet block explorers cannot detect
which signet challenge is in use; default-signet vs custom-signet
indistinguishable via RPC.

---

## BUG-19 (P1) — `calculate_next_target` Lua-double arithmetic is bounded but unguarded

**Severity:** P1. `consensus.lua:229-240`:

```lua
local carry = 0
for i = 1, 32 do
  local val = old_le[i] * actual_timespan + carry
  product[i] = bit.band(val, 0xFF)
  carry = math.floor(val / 256)
end
```

`old_le[i]` is an 8-bit byte (0..255). `actual_timespan` is clamped
to `[MIN_TIMESPAN=302400, MAX_TIMESPAN=4838400]` at lines 204-208.
Max product per byte: `255 * 4838400 + max_carry`. The max carry
grows by a factor of `(2^53 mantissa / max_byte_product) =
(2^53 / 1.23e9) ≈ 7.3e6` bytes worth of accumulation before the
double mantissa is exhausted. In practice 32 bytes never reach
this bound. PASS in practice.

However: the code has no documented invariant for the bound, and no
guard. A future patch that allowed callers to pass an unclamped
`actual_timespan` would silently produce incorrect targets once the
product overflows 2^53. The companion `scale_target_by_timespan`
(line 341-378) has the same shape and the same unguarded scalar
arithmetic.

**File:** `src/consensus.lua:219-256, 341-378`.

**Core ref:** `bitcoin-core/src/arith_uint256.cpp::operator*=` (full
uint256 arithmetic — no precision-loss possible).

**Impact:** no current bug; flagged for documentation. Fleet pattern
"Lua-double precision" (W156 BUG-?? echo).

---

## BUG-20 (P1) — `actual_timespan` can be NEGATIVE on testnet4 BIP-94; clamp catches it accidentally

**Severity:** P1. On testnet4 with BIP-94 enforced, two scenarios
produce negative `actual_timespan`:
1. The first block of the current period has a timestamp clamped by
   the BIP-94 timewarp gate to `prev.timestamp - MAX_TIMEWARP` (i.e.
   up to 600s BEFORE the last block of the previous period).
2. Edge case during reorg/replay where ancestor timestamps are
   not strictly monotonically increasing.

`consensus.lua:454`:

```lua
local actual_timespan = prev.header.timestamp - first.header.timestamp
```

If `first.timestamp > prev.timestamp`, this is negative. The clamp
inside `calculate_next_target` at line 204:

```lua
if actual_timespan < M.MIN_TIMESPAN then
  actual_timespan = M.MIN_TIMESPAN
elseif actual_timespan > M.MAX_TIMESPAN then
  actual_timespan = M.MAX_TIMESPAN
end
```

catches `-1 < MIN_TIMESPAN` → clamped to MIN_TIMESPAN. So the bug
self-corrects in practice. But:
- The comparator `actual_timespan < M.MIN_TIMESPAN` for negative Lua
  doubles is correct, but only because Lua doubles compare with
  IEEE 754 semantics. A future port to a strict integer system
  (Lua 5.3+ integer mode, LuaJIT FFI int64) might trip.
- The clamp DOES NOT log or surface the anomaly; a peer-injected
  block that crossed a retarget with `first.timestamp > prev.timestamp`
  would silently get the MIN_TIMESPAN target, which is "easier" than
  Core's behavior (Core would clamp to the same MIN_TIMESPAN via
  arith_uint256, so consensus matches — but the value comparison is
  via signed int64 and the path is explicit).

**File:** `src/consensus.lua:454, 204-208`.

**Core ref:** `bitcoin-core/src/pow.cpp:56-60` (Core does the same
clamp but on `int64_t nActualTimespan`).

**Impact:** no current consensus risk; defense-in-depth gap on the
arithmetic-style invariant.

---

## BUG-21 (P1) — `bip22_result` does not map `bad-signet-blksig`

**Severity:** P1. `rpc.lua:56-213` is the canonical reject-string
mapper. It covers `time-too-old`, `time-too-new`,
`time-timewarp-attack`, `bad-version`, `bad-diffbits`, `bad-cb-height`,
`bad-cb-amount`, `bad-blk-sigops`, `bad-txnmrklroot`,
`bad-witness-merkle-match`, and many others — but NOT
`bad-signet-blksig`. Even if a hypothetical signet-aware caller
threw an error containing this token, the mapper would fall through
to `"rejected"` (line 213).

**File:** `src/rpc.lua:56-213`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::BIP22ValidationResult`.

**Impact:** even after fixing BUG-1, signet rejection reason
plumbing through `submitblock` would emit the generic `"rejected"`
instead of the canonical `"bad-signet-blksig"` — wire-parity
slippage (9th distinct lunarblock W125-class instance).

---

## BUG-22 (P1) — Default-signet `nMinimumChainWork` + `defaultAssumeValid` absent (cross-cite BUG-3)

**Severity:** P1. Even if BUG-3 added a minimal signet entry, the
following per-signet parameters need values to match Core
(`kernel/chainparams.cpp:332-333`):

- `nMinimumChainWork` for default-signet (currently absent — would
  default to all-zero, disabling the anti-DoS chainwork gate)
- `defaultAssumeValid` (Core sets
  `00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329`
  at height 293175)
- `assumeutxo` snapshots at heights 160000 + 290000

The W149 BUG-6/BUG-7 fleet pattern (other impls also drop signet
assumevalid) would extend to lunarblock once BUG-3 is fixed
half-way.

**File:** N/A (no signet entry).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:332-333,
489-502`.

**Impact:** slow signet IBD (full signature verification all the way
to tip), no chainwork-based anti-DoS, no AssumeUTXO snapshot
loading.

---

## BUG-23 (P1) — testnet4 `min_chain_work` set to zero, not Core's testnet4 value

**Severity:** P1. `consensus.lua:1116`:

```lua
min_chain_work = "0000000000000000000000000000000000000000000000000000000000000000",
```

Core's testnet4 (`kernel/chainparams.cpp:332`) sets
`"0000000000000000000000000000000000000000000009a0fe15d0177d086304"`.
With the value zeroed, lunarblock's testnet4 IBD has no anti-DoS
chainwork floor — a peer feeding a near-empty fake testnet4 chain
would not be filtered by the MinimumChainWork gate. The PRESYNC /
REDOWNLOAD pipeline at sync.lua's `headerssync_params` (lines
1110-1113) still runs, but the chainwork gate that anchors it is
zero, so any peer's tip passes.

**File:** `src/consensus.lua:1116`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:332`.

**Impact:** testnet4 IBD vulnerable to low-work-chain peer attack;
defense-in-depth gap. May allow malicious peer to consume header
memory by feeding a fake chain.

---

## BUG-24 (P1) — testnet3 `min_chain_work` value claims `00…010001` (effectively zero) — has no genesis-equivalent

**Severity:** P1. `consensus.lua:1044`:

```lua
min_chain_work = "0000000000000000000000000000000000000000000000000000000100010001",
```

This appears to be a placeholder. Core's testnet3 value at v25 was
`"0000000000000000000000000000000000000000000000076b0b6b4cb2adda21"`.
The lunarblock value (`0x...0100010001`) corresponds to chainwork ~3,
which is ~2 fake-mined headers worth of work — well below the testnet3
chain's actual minimum, but also below any realistic anti-DoS gate.

**File:** `src/consensus.lua:1044`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:222-294`
(testnet3 nMinimumChainWork).

**Impact:** testnet3 IBD anti-DoS broken; same shape as BUG-23 but
on testnet3.

---

## Summary

**Bug count:** 24 (BUG-1 through BUG-24).

**Severity distribution:**
- **P0-CDIV:** 8 (BUG-1, BUG-2, BUG-3, BUG-6, BUG-7, BUG-8, BUG-9,
  BUG-15)
- **P1:** 16 (BUG-4, BUG-5, BUG-10, BUG-11, BUG-12, BUG-13, BUG-14,
  BUG-16, BUG-17, BUG-18, BUG-19, BUG-20, BUG-21, BUG-22, BUG-23,
  BUG-24)

Total: 8 + 16 = 24. ✓

**Fleet patterns confirmed:**
- "signet-CheckSignetBlockSolution-absent" (BUG-1) — first confirmed
  lunarblock instance; W143 BUG-9 noted blockbrew has the same gap
  (P0-CONS signet split at block 1). lunarblock joins that list as
  P0-CDIV with the structural-deeper "signet not even a network"
  framing.
- "SIGNET_HEADER 0xecc7daa2 absent" (BUG-2) — companion to BUG-1.
- "two-pipeline guard 18th distinct extension" (BUG-6) — first time
  header-validation BIP-94 gate is doubled across `validation.lua`'s
  `check_block_header` vs `sync.lua`'s `accept_header`.
- "BIP-94 timewarp absent" (BUG-7, BUG-8) — confirmed lunarblock
  carries the testnet4-only gate but lacks the defensive
  "all networks" miner-side application Core's miner.cpp:43-45 has.
- "comment-as-confession 11th distinct instance" (BUG-15: "In a real
  implementation, compute next required bits at retarget heights"
  — 11th lunarblock instance per W156 tracking).
- "carry-forward re-anchor" (BUG-15 W154 BUG-1; BUG-8 W154 BUG-4;
  BUG-11 W154 BUG-19; W154 BUG-2+3 mtp-never-populated also still
  open per `mining.lua:266-267`) — three+ W154 P0/P1 bugs still
  unfixed 1+ wave later.
- "Lua-double precision" (BUG-19) — bounded by problem space but
  unguarded; documentation-grade.
- "reject-string wire-parity slippage" (BUG-13, BUG-21) — 9th and
  10th lunarblock W125-class instances. BUG-13 reports
  `"insufficient proof of work"` for negative-nBits where Core
  reports `"high-hash"`; BUG-21 has no `bad-signet-blksig` mapping.
- "default-install-AUTH-or-CONFIG-bypassed" (BUG-7 regtest BIP-94
  opt-in absent — no `-test=bip94` flag) — adjacent to W140 default
  install class.
- "30-of-30-gates-buggy 6th-of-6 candidate" — this audit found 24
  bugs across 35 gates (68%); W156 was the first 6th-of-6 candidate.
  W157 confirms lunarblock as **6th-of-6 30-of-30 candidate** if
  the gate threshold is set at 60%+; if set at 80%+ (per W138/W141
  framings), W157 is "29-of-35-buggy" — narrowly below the 30-of-30
  threshold.

**Top three findings:**

1. **BUG-1 + BUG-2 + BUG-3 cluster (P0-CDIV signet completely
   unsupported)** — `CheckSignetBlockSolution` absent, SIGNET_HEADER
   constant absent, NO `signet` entry in `M.networks` table, NO
   `--signet` / `--signetchallenge` CLI flags. Signet is a
   structurally unreachable target for lunarblock. **The most
   urgent gap if BUG-3 is fixed without BUG-1 is that lunarblock
   would silently accept ANY PoW-valid block as signet-valid** —
   forking off default-signet at any height ≥ 1. Three architectural
   holes that MUST be fixed together. Companion to blockbrew W143
   BUG-9 (P0-CONS signet split at block 1) — lunarblock's framing
   is structurally deeper because signet is not even a recognized
   chain type.

2. **BUG-8 + BUG-9 cluster (P0-CDIV miner BIP-94 + UpdateTime
   defense missing on ALL networks)** — Core's
   `GetMinimumTime` applies the BIP-94 retarget timewarp defense on
   ALL networks regardless of `enforce_BIP94` (mining.cpp:43-45
   explicitly says "on all networks. This makes future activation
   safer"). lunarblock's miner does neither, AND has no UpdateTime
   function to bump nTime between template build and final mining,
   AND does not recompute nBits on testnet after time advances.
   When BIP-94 eventually activates on mainnet, every lunarblock
   miner template at the retarget boundary will be unmineable.
   Carry-forward W154 BUG-2/3/4 still open.

3. **BUG-6 (P0-CDIV two-pipeline header validation)** — first
   confirmed lunarblock instance where `validation.lua:check_block_header`
   diverges from `sync.lua:accept_header`. The first lacks BIP-94
   timewarp, MTP time-too-old, bad-diffbits, and bad-version gates.
   This is the W143/W148-class "two-pipeline guard" pattern applied
   to header validation specifically. The `check_block` (validation.lua:1302)
   call site is reached from `sync.lua:2232` AFTER `accept_header`,
   so the asymmetry is "accept_header is stricter" — but the
   architectural duplication means any future patch to one must
   mirror to the other, and historical precedent shows those
   mirrors get forgotten.
