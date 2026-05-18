# W144 — Script-verify flag mux / SCRIPT_VERIFY_* application audit (lunarblock)

**Date:** 2026-05-18
**Wave:** W144 (discovery; 4-of-4 quad-wave)
**Impl:** lunarblock (Lua / LuaJIT)
**Status:** **22 BUGS FOUND** (4 P0-CDIV / 5 P0 / 7 P1 / 4 P2 / 2 P3) across **30 gates**
**Scope:** `GetBlockScriptFlags` height/exception derivation, per-flag application
inside EvalScript (`SCRIPT_VERIFY_*` consumption), buried softfork wiring
(BIP-16/65/66/68-CSV/141-SegWit/147-NULLDUMMY/341-Taproot), policy vs.
consensus flag separation, dead-code identification, exception-block override.

**BIPs:** 16 (P2SH), 65 (CLTV), 66 (DERSIG), 112 (CSV), 141 (SegWit), 147
(NULLDUMMY), 341/342 (Taproot/Tapscript), 146 (LOW_S / NULLFAIL policy).

## Context

This audit catalogues Core-parity deviations in **how lunarblock derives,
plumbs, and applies the SCRIPT_VERIFY_\* flag bitmask** across the consensus
(block-connect) and policy (mempool-accept) paths.

Lunarblock's hand-rolled approach uses a **flag table** (`local flags = { ... }`
in `utxo.lua`) instead of Core's `script_verify_flags` bitmask. Per CLAUDE.md
this is a hard-coded buried-activation model — `consensus.lua:482-518`
explicitly disclaims the BIP9 versionbits machinery as "decorative" and tells
future maintainers to use `M.networks.<name>.<fork>_height` hard-coded heights
instead.

The flags table at `utxo.lua:2429-2436` is mostly correct for mainnet steady
state. The bugs catalogued below are in **(a)** the BIP-16 / BIP-341 exception
blocks Core enforces via `script_flag_exceptions`, **(b)** the
flag-set-but-no-callsite ("dead-flag") pattern where `verify_taproot` is
effectively dead-code in the dominant native-witness dispatch path,
**(c)** **verify_const_scriptcode is set in mempool but never enforced**
(find-and-delete-found > 0 check missing; OP_CODESEPARATOR-in-non-segwit
check missing), **(d)** policy-pass mempool flags missing
`DISCOURAGE_*` flag family (5 of Core's 6 are absent), **(e)** the cache_flags
bitmask that miscomputes the sigcache key for blocks 173,805..227,930
(uses `bip34_height` as the P2SH gate instead of `verify_p2sh=true`),
**(f)** native witness dispatch bypassing `verify_witness` flag check entirely
(height-gate-only).

## Source map

- `lunarblock/src/utxo.lua:2248-2251` — `sigop_flags` (sigop-counting flag set;
  only `verify_p2sh` and `verify_witness`).
- `lunarblock/src/utxo.lua:2407-2436` — **per-input flag derivation** for
  block-connect script verification. Cache-key bitmask (lines 2408-2413) and
  consensus flags table (lines 2428-2436).
- `lunarblock/src/utxo.lua:2517-2738` — native-witness dispatch that
  **bypasses** `verify_script`/`verify_witness_program` and calls
  `execute_witness_script` / inline taproot logic directly.
- `lunarblock/src/script.lua:2164-2330` — `verify_script` (legacy + P2SH +
  witness-via-P2SH dispatcher).
- `lunarblock/src/script.lua:1954-2161` — `verify_witness_program`
  (BIP-141/341 witness program parsing + dispatch).
- `lunarblock/src/script.lua:230-277` — `check_signature_encoding` /
  `check_pubkey_encoding` / `check_pubkey_encoding_witness` (flag-gated
  encoding checks).
- `lunarblock/src/script.lua:1597-1599` — NULLDUMMY enforcement
  (OP_CHECKMULTISIG dummy).
- `lunarblock/src/script.lua:1670-1721` — CLTV / CSV opcode dispatch.
- `lunarblock/src/script.lua:1420-1428` — OP_CODESEPARATOR (no
  `verify_const_scriptcode` check).
- `lunarblock/src/script.lua:836-859` — `is_witness_program` parser.
- `lunarblock/src/mempool.lua:1622-1639` — STANDARD_SCRIPT_VERIFY_FLAGS
  policy-pass flag set (mempool relay).
- `lunarblock/src/validation.lua:596-609` — `find_and_delete` (no
  `found_count > 0` channel).
- `lunarblock/src/consensus.lua:882-894` — mainnet buried-fork heights.
- `lunarblock/src/rpc.lua:1211-1254` — `build_deployment_state`
  (getblockchaininfo / getdeploymentinfo `.softforks` projection).
- `lunarblock/src/consensus.lua:482-518` — versionbits **dead module** notice.

Core references:

- `bitcoin-core/src/script/interpreter.h:41-159` — `SCRIPT_VERIFY_*` enum
  (22 flag bits; 3 buried softforks + 5 policy + 5 discourage + WITNESS
  family + STRICTENC + LOW_S + SIGPUSHONLY + MINIMALDATA + CLEANSTACK +
  MINIMALIF + NULLFAIL + WITNESS_PUBKEYTYPE + CONST_SCRIPTCODE).
- `bitcoin-core/src/validation.cpp:2250-2289` — `GetBlockScriptFlags`.
- `bitcoin-core/src/policy/policy.h:105-135` — `MANDATORY_SCRIPT_VERIFY_FLAGS`
  / `STANDARD_SCRIPT_VERIFY_FLAGS`.
- `bitcoin-core/src/kernel/chainparams.cpp:85-88` — mainnet
  `script_flag_exceptions`: BIP-16 exception block + Taproot exception block.
- `bitcoin-core/src/script/interpreter.cpp:331` — find-and-delete-found
  `CONST_SCRIPTCODE` reject.
- `bitcoin-core/src/script/interpreter.cpp:474-476` — OP_CODESEPARATOR in
  non-segwit script `CONST_SCRIPTCODE` reject (**even in unexecuted branch**).
- `bitcoin-core/src/script/interpreter.cpp:1146-1148` — same FAD check on
  CHECKMULTISIG path.
- `bitcoin-core/src/deploymentstatus.h:27-31` — `DeploymentActiveAt`
  semantics (`index.nHeight >= params.DeploymentHeight(dep)` — inclusive).

## 30-gate matrix

### A. GetBlockScriptFlags shape & exceptions (G1-G5)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G1 | Base flag set: `P2SH \| WITNESS \| TAPROOT` always-on (Core validation.cpp:2262) | **OK** — `utxo.lua:2429-2435` always sets `verify_p2sh=true`; `verify_witness`/`verify_taproot` height-gated, matches Core for non-exception blocks. |
| G2 | BIP-16 exception block (mainnet `00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22`, h=173,805) → `SCRIPT_VERIFY_NONE` | **BUG-1 (P1)** — `consensus.lua:882-894` and `utxo.lua:2429` do not implement `script_flag_exceptions`; lunarblock unconditionally applies P2SH at h=173,805, would reject this single block on `-noassumevalid` IBD. |
| G3 | Taproot exception block (mainnet `0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad`) → `P2SH \| WITNESS` only (NO TAPROOT) | **BUG-2 (P1)** — same root cause as G2: no `script_flag_exceptions` table. lunarblock will run taproot rules on this block, will reject it on `-noassumevalid` IBD. |
| G4 | DERSIG flag derives from `height >= BIP66Height` (mainnet 363,725) | **OK** — `utxo.lua:2430`. |
| G5 | CLTV / CSV / Segwit / NULLDUMMY flags all height-derived from buried heights | **OK** — `utxo.lua:2431-2434`. Segwit & NULLDUMMY use same height, matching Core's `DEPLOYMENT_SEGWIT` arming both. |

### B. Per-flag dispatch in EvalScript (G6-G12)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G6 | `SCRIPT_VERIFY_P2SH`: P2SH redeem script execution gated on flag | **OK** — `script.lua:2200-2247`. |
| G7 | `SCRIPT_VERIFY_DERSIG`: strict DER encoding consumed by `check_signature_encoding` | **OK** — `script.lua:234`. |
| G8 | `SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY`: OP_NOP2 → OP_CLTV redirect | **OK** — `script.lua:1670-1695`. |
| G9 | `SCRIPT_VERIFY_CHECKSEQUENCEVERIFY`: OP_NOP3 → OP_CSV redirect | **OK** — `script.lua:1696-1720`. |
| G10 | `SCRIPT_VERIFY_WITNESS`: gates VerifyWitnessProgram; without flag, witness anyone-can-spend | **BUG-3 (P0-CDIV)** — `utxo.lua:2517-2582` dispatches native P2WPKH/P2WSH **without consulting `flags.verify_witness`**; only `script_type==…` + height gating (via flags.verify_witness derived from same height). The flag check is essentially redundant at the connect path. See bug. |
| G11 | `SCRIPT_VERIFY_NULLDUMMY`: OP_CHECKMULTISIG dummy must be empty | **OK** — `script.lua:1595-1599`. |
| G12 | `SCRIPT_VERIFY_TAPROOT`: gates Taproot commitment + tapscript leaf eval | **BUG-4 (P0)** — `utxo.lua:2583` dispatches native P2TR **height-gated** (`height >= self.network.taproot_height`), not flag-gated. `flags.verify_taproot` flag at line 2435 is **dead-code in the dominant path**; only `verify_witness_program` (script.lua:2026) — the P2SH-wrapped path — actually reads it. |

### C. Policy-pass flag mux (mempool standard checks) (G13-G18)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G13 | `MANDATORY_SCRIPT_VERIFY_FLAGS` = P2SH + DERSIG + NULLDUMMY + CLTV + CSV + WITNESS + TAPROOT | **BUG-5 (P0)** — `mempool.lua:1622-1639` policy-pass flag set **omits `verify_taproot`** (mandatory at relay since taproot activation 2021). Effect: a tx spending a P2TR output reaches block-connect without ever having its tapscript verified at relay (the path is **skipped entirely** at mempool.lua:1648-1652 via `is_witness_path` short-circuit). Latent — the standardness pass is bypassed for ALL witness inputs (witness paths still validated at block-connect). |
| G14 | `STANDARD_SCRIPT_VERIFY_FLAGS` adds STRICTENC + MINIMALDATA + DISCOURAGE_UPGRADABLE_NOPS + CLEANSTACK + MINIMALIF + NULLFAIL + LOW_S + DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM + WITNESS_PUBKEYTYPE + CONST_SCRIPTCODE + DISCOURAGE_UPGRADABLE_TAPROOT_VERSION + DISCOURAGE_OP_SUCCESS + DISCOURAGE_UPGRADABLE_PUBKEYTYPE | **BUG-6 (P1)** — `mempool.lua:1622-1639` omits `verify_discourage_upgradable_witness` + `verify_discourage_upgradable_taproot_version` + `verify_discourage_op_success` + `verify_discourage_upgradable_pubkeytype` (4 of Core's 5 DISCOURAGE_\* flags absent). `verify_minimalif` is also absent. Effect: lunarblock relays "DISCOURAGE_\*" forward-soft-fork-trigger txs that Core would reject as nonstandard. |
| G15 | `verify_const_scriptcode` set in policy-pass | **BUG-7 (P0)** — set at `mempool.lua:1638` BUT NEVER ENFORCED. `find_and_delete` (`validation.lua:596-609`) returns the modified script with no `found_count` channel, so the Core check `if (found > 0 && flags & SCRIPT_VERIFY_CONST_SCRIPTCODE)` (interpreter.cpp:331,1147) **CANNOT FIRE**. OP_CODESEPARATOR in non-segwit script (interpreter.cpp:475) also unchecked. **Flag-set-but-no-callsite: classic dead-flag pattern.** |
| G16 | `STRICTENC` triggers `WITNESS_PUBKEYTYPE`-style checks pre-segwit | **OK** — `script.lua:246-251` enforces hashtype + DER under STRICTENC. |
| G17 | Mempool sets `verify_p2sh=true`, `verify_witness=true` unconditionally | **OK in steady state, BUG-8 (P3)** — line 1230 sigop_flags hardcodes both true regardless of mempool height; latent because mempool only operates after softforks activate. |
| G18 | `verify_input_scripts` opt-out gate honors a config flag rather than always running | **BUG-9 (P2)** — `mempool.lua:1622` checks `self.verify_input_scripts` and SKIPS the policy script verification pass if false. Core has no such opt-out; this is a latent test-only escape that, if accidentally enabled in production, lets bad-signature txs sit in mempool until block-mined. |

### D. Buried softfork wiring (G19-G24)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G19 | Mainnet buried heights match Core | **OK** — `consensus.lua:883-894` matches `chainparams.cpp:89-94`. |
| G20 | Testnet3 buried heights match Core | **OK** — `consensus.lua:1013-1021` matches `chainparams.cpp:212-217`. |
| G21 | Testnet4 buried heights = 1 (all forks active from genesis+1) | **OK** — `consensus.lua:1086-1095` matches `chainparams.cpp:311-316`. |
| G22 | Regtest buried heights match Core | **OK** — `consensus.lua:1157-1165` matches `chainparams.cpp:455-460` (BIP34 at 1; others 0). |
| G23 | Signet support | **BUG-10 (P2)** — no signet chain params at all. lunarblock cannot run on signet. |
| G24 | `bip16_height` / "p2sh_height" field exists | **BUG-11 (P1)** — no `bip16_height` field anywhere in `consensus.lua`. Core uses 173,805 for mainnet (encoded as `script_flag_exceptions`), but lunarblock has no analogue. The cache_flags miscomputation at `utxo.lua:2409` (uses `bip34_height` for the P2SH cache bit) is the load-bearing symptom. |

### E. Cache-flag bitmask correctness (G25-G27)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G25 | Sigcache cache-key flags reflect the actual flag set applied to the script | **BUG-12 (P1)** — `utxo.lua:2409` uses `height >= self.network.bip34_height` (227,931) as the P2SH cache bit, but the actual `verify_p2sh = true` (line 2429) is height-independent. Blocks 173,805..227,930 cache hits would conflate "P2SH-on" with "P2SH-off" runs of the same `(txid, inp_idx)` shape. Comment at line 2425-2427 acknowledges the same divergence in the flag-table but not in the cache-key. |
| G26 | `verify_witness_pubkeytype` and `verify_nullfail` are POLICY-only — must NOT appear in cache_flags | **OK** — `utxo.lua:2408-2413` only has 5 bits (P2SH, DERSIG, CLTV, CSV, WITNESS). NULLDUMMY/TAPROOT are absent though. |
| G27 | NULLDUMMY (`verify_nulldummy = height >= segwit_height`) — should share cache bit with WITNESS or have its own | **BUG-13 (P2)** — cache_flags has bit-4 for WITNESS but the actual flag bag at line 2434 adds NULLDUMMY which has the same `segwit_height` gate. Latent because they always co-activate, but a future change that decoupled them would silently produce stale cache reads. |

### F. Versionbits / RPC visibility (G28-G30)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G28 | `getblockchaininfo.softforks` includes BIP-16 / P2SH entry | **BUG-14 (P2)** — `rpc.lua:1224-1241` exposes bip34/65/66/csv/segwit/taproot but NOT BIP-16. Core includes `"bip16": { "type": "buried", "active": true, "height": 173805 }`. Clients calling getblockchaininfo see BIP-34 listed but no BIP-16. |
| G29 | `getdeploymentinfo.deployments` includes BIP-16 | **BUG-15 (P2)** — same root cause as G28: `build_deployment_state` at `rpc.lua:1211-1253` has no `deployments.bip16` entry. |
| G30 | `consensus.lua` versionbits machinery is dead-code yet retained "for reference" | **BUG-16 (P3)** — `consensus.lua:482-518` self-declares the BIP9 versionbits module decorative; tests reference it but production never does. Comment is explicit: "MUST NOT be called from the consensus / block-validation path". Classic two-pipeline-guard pattern from W76+; tracked here for cumulative fleet-pattern visibility. |

## Bugs (full)

### BUG-1 (P1) — BIP-16 exception block (mainnet h=173,805) not implemented; `-noassumevalid` IBD would reject

**File:** `src/utxo.lua:2429-2436` (consensus flag derivation).
`src/consensus.lua:882-894` (mainnet softfork heights).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:85-86` and
`validation.cpp:2263-2266`:

```cpp
consensus.script_flag_exceptions.emplace( // BIP16 exception
    uint256{"00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"},
    SCRIPT_VERIFY_NONE);
```

```cpp
script_verify_flags flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT};
const auto it{consensusparams.script_flag_exceptions.find(*Assert(block_index.phashBlock))};
if (it != consensusparams.script_flag_exceptions.end()) {
    flags = it->second;
}
```

**Description:** Core's `GetBlockScriptFlags` has a hardcoded
`script_flag_exceptions` map that overrides the default flag set for two
historical mainnet blocks. Block 173,805 (the BIP-16 exception) was mined
between P2SH activation and the canonical hash being known; Core applies
`SCRIPT_VERIFY_NONE` (all script flags off) for that single block to avoid
rejecting it on rescan. lunarblock has no analogous table; `utxo.lua:2429`
unconditionally sets `verify_p2sh = true` for ALL blocks.

**Excerpt** (`utxo.lua:2425-2436`):

```lua
-- P2SH: always enabled per GetBlockScriptFlags (Core validation.cpp:2260-2262).
-- Using bip34_height here was wrong — P2SH activated at block 173,805,
-- long before BIP34 (227,931).
local flags = {
  verify_p2sh = true,                                    -- ← no exception override
  verify_dersig = height >= self.network.bip66_height,
  verify_checklocktimeverify = height >= self.network.bip65_height,
  verify_checksequenceverify = height >= self.network.csv_height,
  verify_witness = height >= self.network.segwit_height,
  verify_nulldummy = height >= self.network.segwit_height,
  verify_taproot = height >= self.network.taproot_height,
}
```

**Impact:** Consensus-divergent on `-noassumevalid` IBD. Block 173,805 contains
a tx whose P2SH input ought to fail under P2SH semantics (the redeem-script
output does not match expected behavior). Core accepts this single block by
disabling P2SH for it; lunarblock would reject (consensus split → bad-block /
chain-stall during from-genesis IBD). In normal mainnet operation
`assumevalid=938,343` (`consensus.lua:931`) skips script validation for all
blocks 0..938,342, so this is dormant in production — but breaks
`-noassumevalid` and any deterministic test that asks for it.

---

### BUG-2 (P1) — Taproot exception block not implemented; `-noassumevalid` IBD would reject

**File:** `src/utxo.lua:2429-2436` (same root cause as BUG-1).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:87-88`:

```cpp
consensus.script_flag_exceptions.emplace( // Taproot exception
    uint256{"0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"},
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS);
```

**Description:** A single mainnet block post-taproot-activation has a
non-standard taproot input that consensus-accepts but Core never enforces
TAPROOT rules on. Like BIP-16 exception, Core uses
`script_flag_exceptions`; lunarblock does not implement this and would
reject the block on `-noassumevalid`.

**Impact:** Same as BUG-1 — dormant under default `assumevalid`, but breaks
deterministic-from-genesis IBD.

---

### BUG-3 (P0-CDIV) — Native witness dispatch bypasses `flags.verify_witness`; pre-segwit-height witness output ANYONE-CAN-SPEND not enforced

**File:** `src/utxo.lua:2517-2582` (P2WPKH/P2WSH dispatch).

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:2098-2120`
(`VerifyScript` with witness branch):

```cpp
if ((flags & SCRIPT_VERIFY_WITNESS) != 0) {
    // ... witness program logic
}
```

— Core's VerifyScript runs the witness path **only when SCRIPT_VERIFY_WITNESS
is set**. Pre-segwit blocks have `flags.verify_witness = false`, so any
output of shape `OP_0 <20-byte hash>` (a syntactically valid P2WPKH) is
treated as anyone-can-spend (the BIP-141 forward-compat reservation).

**Description:** lunarblock's connect-block path at `utxo.lua:2517` does
**`if script_type == "p2wpkh" or script_type == "p2wsh" then …`** — a pure
shape match. There is no `flags.verify_witness` guard. If a UTXO with a
P2WPKH-shape `scriptPubKey` existed at a block height < `segwit_height`, the
witness validation would still run, splitting from Core (which treats it as
anyone-can-spend, since the WITNESS flag is off).

**Excerpt** (`utxo.lua:2517-2521`):

```lua
if script_type == "p2wpkh" or script_type == "p2wsh" then
  -- SegWit: scriptSig must be empty, use witness stack
  assert(#inp.script_sig == 0, "SegWit input must have empty scriptSig")
  -- Execute witness program
  local witness_stack = inp.witness or {}
```

**Impact:** Latent — in production, no pre-481,824 UTXO has a v0 witness
program in scriptPubKey because mining nodes would not have produced one.
But on regtest / custom networks where `segwit_height > 0`, a transaction
crafted with a witness-shaped output before activation would split lunarblock
from Core (Core: anyone-can-spend, accepts; lunarblock: runs witness
verification, may accept or reject depending on the witness data the spender
provided). Categorized as **P0-CDIV** because it's a structural divergence
in flag application — the WITNESS flag is supposed to be **the only
authority** on whether witness verification runs, and lunarblock makes it
the height table instead.

---

### BUG-4 (P0) — `verify_taproot` flag in mandatory bag is dead-code at the dominant dispatch path

**File:** `src/utxo.lua:2435` (sets `verify_taproot`) /
`src/utxo.lua:2583` (consumes height, not flag).

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:1925-1934`:

```cpp
} else if (witnessversion == 1 && witnessprogram.size() == WITNESS_V1_TAPROOT_SIZE && !is_p2sh) {
    if (!(flags & SCRIPT_VERIFY_TAPROOT)) return set_success(serror);
    // ... key-path or script-path
```

Core gates v1+32 witness validation on `flags & SCRIPT_VERIFY_TAPROOT`.
Without the flag, the v1+32 witness is anyone-can-spend.

**Description:** `utxo.lua:2435` sets
`verify_taproot = height >= self.network.taproot_height` and includes it in
the per-input flag table. **But** the native-P2TR dispatch at line 2583
bypasses `verify_script` / `verify_witness_program` entirely and uses
**`script_type == "p2tr" and height >= self.network.taproot_height`** as the
gate. `verify_taproot` flag is read by exactly one site:
`script.lua:2026` inside `verify_witness_program`, which is only reachable
via the legacy/P2SH-wrapped path (`verify_script` → "did_p2sh" branch).
For native P2TR (the dominant Taproot dispatch path), the flag is dead.

**Excerpt** (`utxo.lua:2583`):

```lua
elseif script_type == "p2tr" and height >= self.network.taproot_height then
  -- P2TR (taproot) witness v1: scriptSig must be empty, use witness stack
  -- ... bypasses verify_script / verify_witness_program entirely
```

**Impact:** Currently neutral — `verify_taproot` and the height-gate use the
same expression, so they always agree. But any future change that wants to
disable Taproot via a flag override (e.g. a hypothetical "taproot exception"
block analogous to BIP-16) cannot do so via the flag bag because the
dispatch sees only the height. Classic **dead-flag** pattern — fleet-wide,
this is the same shape rustoshi/clearbit/lunarblock have hit in W122,
W127, W137.

---

### BUG-5 (P0) — Mempool policy-pass flag set omits `verify_taproot` (Core's MANDATORY)

**File:** `src/mempool.lua:1622-1639`.

**Core ref:** `bitcoin-core/src/policy/policy.h:105-111`:

```cpp
static constexpr script_verify_flags MANDATORY_SCRIPT_VERIFY_FLAGS{SCRIPT_VERIFY_P2SH |
                                                             SCRIPT_VERIFY_DERSIG |
                                                             SCRIPT_VERIFY_NULLDUMMY |
                                                             SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                                                             SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
                                                             SCRIPT_VERIFY_WITNESS |
                                                             SCRIPT_VERIFY_TAPROOT};
```

**Description:** lunarblock's `script_flags` table for policy-pass script
verification at `mempool.lua:1622-1639` does NOT include `verify_taproot`.
The table is then passed to `verify_script` (line 1662). For witness inputs
the path is **skipped entirely** at line 1648-1652 via `is_witness_path`,
so `verify_taproot` would be unused anyway — but for any future expansion
that does verify P2TR inputs at relay, the flag would be missing.

**Excerpt** (`mempool.lua:1622-1639`):

```lua
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
-- MISSING: verify_taproot
```

**Impact:** P0 because Core's MANDATORY set is the **consensus-enforced**
floor; any tx that fails MANDATORY is `bannable`. lunarblock's relay path
applying a strict-subset-minus-TAPROOT can't reject taproot-illegal txs at
relay time (they reach block-connect). For now harmless because witness
paths short-circuit at `is_witness_path`. Becomes load-bearing the moment
that short-circuit is removed.

---

### BUG-6 (P1) — Mempool standard-pass missing 5 of Core's 6 `DISCOURAGE_*` flags + `MINIMALIF`

**File:** `src/mempool.lua:1622-1639`.

**Core ref:** `bitcoin-core/src/policy/policy.h:119-132`:

```cpp
static constexpr script_verify_flags STANDARD_SCRIPT_VERIFY_FLAGS{MANDATORY_SCRIPT_VERIFY_FLAGS |
    SCRIPT_VERIFY_STRICTENC |
    SCRIPT_VERIFY_MINIMALDATA |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
    SCRIPT_VERIFY_CLEANSTACK |
    SCRIPT_VERIFY_MINIMALIF |                    // ← MISSING
    SCRIPT_VERIFY_NULLFAIL |
    SCRIPT_VERIFY_LOW_S |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM |  // ← MISSING
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE |
    SCRIPT_VERIFY_CONST_SCRIPTCODE |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION |  // ← MISSING
    SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS |                  // ← MISSING
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE};       // ← MISSING
```

**Description:** Of the 6 `DISCOURAGE_*` policy flags Core enforces in
STANDARD_SCRIPT_VERIFY_FLAGS, lunarblock's `script_flags` table includes
only **`verify_discourage_upgradable_nops`** (the 1990s NOP discourager).
Five other DISCOURAGE_\* flags are absent. `verify_minimalif` is also
omitted (consensus-enforced in tapscript already, but missing for
witness-v0 policy).

**Impact:** lunarblock relays nonstandard "DISCOURAGE_\*"-trigger txs that
Core would reject as nonstandard at relay. Forward-soft-fork hazard: any
of these flags signal the network's intent to reserve a behavior for a
future soft fork; relaying them gives an attacker free pre-soft-fork
network propagation for txs that may become consensus-invalid post-fork.

---

### BUG-7 (P0) — `verify_const_scriptcode` set in mempool but NEVER enforced (find_and_delete loses found_count; OP_CODESEPARATOR-in-non-segwit unchecked)

**File:** `src/validation.lua:596-609` (find_and_delete signature) +
`src/script.lua:1420-1428` (OP_CODESEPARATOR handler).

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:328-333`:

```cpp
// Drop the signature in pre-segwit scripts but not segwit scripts
if (sigversion == SigVersion::BASE) {
    int found = FindAndDelete(scriptCode, CScript() << vchSig);
    if (found > 0 && (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE))
        return set_error(serror, SCRIPT_ERR_SIG_FINDANDDELETE);
}
```

And `bitcoin-core/src/script/interpreter.cpp:474-476`:

```cpp
// With SCRIPT_VERIFY_CONST_SCRIPTCODE, OP_CODESEPARATOR in non-segwit script
// is rejected even in an unexecuted branch
if (opcode == OP_CODESEPARATOR && sigversion == SigVersion::BASE && (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE))
    return set_error(serror, SCRIPT_ERR_OP_CODESEPARATOR);
```

**Description:** Core enforces `SCRIPT_VERIFY_CONST_SCRIPTCODE` at TWO
distinct sites:

1. **EvalChecksig**: if `FindAndDelete` actually deleted ≥1 occurrence of
   the signature from scriptCode (i.e. found > 0), reject the script.
2. **EvalScript main loop**: if OP_CODESEPARATOR is encountered in a
   non-segwit script (sigversion == BASE), reject — **even in an
   unexecuted branch**.

lunarblock has **neither**:

- `find_and_delete` (`validation.lua:596-609`) returns ONLY the modified
  script bytes — no `found_count` second return value. The downstream
  check is **structurally impossible**: there is no signal that anything
  was deleted.
- `OP_CODESEPARATOR` handler (`script.lua:1420-1428`) is unconditional;
  it records `codesep_pos = i - 1` and does not check
  `flags.verify_const_scriptcode` at all.

**Excerpt** (`validation.lua:596-609`):

```lua
function M.find_and_delete(script_bytes, sig_bytes)
  if not sig_bytes or #sig_bytes == 0 then
    return script_bytes
  end

  -- The signature is push-encoded in the script: [push_opcode] [data]
  local push_encoded = serialize_push_data(sig_bytes)

  -- Remove all occurrences of the push-encoded signature
  local pattern = escape_pattern(push_encoded)
  local result = script_bytes:gsub(pattern, "")     -- ← gsub silently drops the count

  return result
end
```

Lua's `gsub` returns `(new_string, num_replacements)` — the second value is
**discarded** by the parentheses pattern. A minimal fix is
`return result, num`. Then both consumers (the CHECKSIG path inside
`make_sig_checker`/`make_collecting_sig_checker` and the CHECKMULTISIG
loop) must consult that count plus `flags.verify_const_scriptcode`.

**Impact:** `verify_const_scriptcode` is set in `mempool.lua:1638` (STANDARD
policy) AND policy-pass exists at `mempool.lua:1622-1678`. The flag is
**plumbed all the way to verify_script but never read at the dispatch site**.
Classic **flag-set-but-no-callsite / plumb-gate-then-no-flip** pattern.
P0 because it's a STANDARDNESS rejection Core enforces that lunarblock
silently no-ops on — pure relay-side dead code.

---

### BUG-8 (P3) — Mempool sigop-counting flags hard-coded to (true, true) regardless of height

**File:** `src/mempool.lua:1230`.

**Description:**

```lua
local sigop_flags = { verify_p2sh = true, verify_witness = true }
tx_sigop_cost = validation.get_transaction_sigop_cost(tx, get_prev_for_sigops, sigop_flags)
```

Mempool accept-path counts sigops with P2SH + WITNESS always-on. Per Core
this matches steady state — but a regtest/signet node operating below
segwit_height should count NO witness sigops. Latent unless someone tests
mempool acceptance pre-segwit-activation on regtest. Equivalent to
W127/W132 height-vs-flag conflations seen fleet-wide.

---

### BUG-9 (P2) — `verify_input_scripts` opt-out flag lets bad-sig txs sit in mempool

**File:** `src/mempool.lua:1622`.

**Description:** Policy-pass script verification is gated by
`if self.verify_input_scripts then` (line 1622). If the operator (or a
forgotten test fixture) sets `verify_input_scripts = false`, lunarblock
**relays** txs with mathematically-invalid signatures, deferring rejection
to block-connect. Core has no such opt-out; this is a per-Mempool
self-permitted escape hatch.

**Excerpt** (`mempool.lua:1622`):

```lua
if self.verify_input_scripts then
  local script_flags = { ... }
  for i, inp in ipairs(tx.inputs) do
    -- only runs when verify_input_scripts is truthy
```

**Impact:** Latent in production (default is presumably true) but a
configuration sharp-edge — flip the flag accidentally and you have a
relay node that propagates broken txs.

---

### BUG-10 (P2) — Signet chain params completely absent

**File:** `src/consensus.lua` (no `M.networks.signet`).

**Description:** Core supports four named networks: mainnet, testnet3,
testnet4, regtest, **signet**. lunarblock has the first four but not
signet. Buried softfork heights for signet are `BIP65=1, BIP66=1, CSV=1,
Segwit=1, BIP34=1` (chainparams.cpp:455-460); the missing-network bug
prevents `-chain=signet` from booting.

**Impact:** Cannot run on signet (forward-compat).

---

### BUG-11 (P1) — No `bip16_height` / `p2sh_height` field; BIP-16 invisible in deployment introspection

**File:** `src/consensus.lua:882-894`, `src/rpc.lua:1211-1254`.

**Description:** lunarblock has buried-height fields for bip34/65/66/csv/
segwit/taproot but **no `bip16_height`**. As a result:

- `build_deployment_state` cannot expose BIP-16 in
  `getblockchaininfo.softforks` (BUG-14) or
  `getdeploymentinfo.deployments` (BUG-15).
- The cache_flags bitmask (BUG-12) papers over the absent field by
  reusing `bip34_height` for the P2SH cache bit.
- Any future code that wants to ask "is P2SH active at height H" has to
  hard-code `173805` or check `verify_p2sh` directly.

**Impact:** Latent symptoms in RPC and cache. Fix is a 1-line addition
to mainnet network params + a wire-up in `rpc.lua:1224-1241`.

---

### BUG-12 (P1) — Sigcache cache-key bitmask uses `bip34_height` for the P2SH bit (blocks 173,805..227,930 collision)

**File:** `src/utxo.lua:2408-2413`.

**Core ref:** Core's sigcache uses the FULL flag bitmask (script_verify_flags)
as the cache key, not a height-derived synthetic.

**Description:**

```lua
local cache_flags = 0
if height >= self.network.bip34_height then cache_flags = cache_flags + 1 end     -- P2SH
if height >= self.network.bip66_height then cache_flags = cache_flags + 2 end     -- DERSIG
...
```

The comment says "P2SH" but the gate is `bip34_height = 227,931`. For
blocks 173,805..227,930 (P2SH-active, BIP34-inactive), `cache_flags` has
bit 0 cleared (P2SH OFF as far as the cache key knows) — but the
**actual** `verify_p2sh = true` (line 2429) was applied. Any cached entry
collision in that height range would produce a stale-cache hit.

**Excerpt** (`utxo.lua:2408-2413` + `2425-2429`):

```lua
local cache_flags = 0
if height >= self.network.bip34_height then cache_flags = cache_flags + 1 end     -- P2SH
...
-- (much later)
-- P2SH: always enabled per GetBlockScriptFlags (Core validation.cpp:2260-2262).
-- Using bip34_height here was wrong — P2SH activated at block 173,805,
-- long before BIP34 (227,931).
local flags = {
  verify_p2sh = true,                              -- ← acknowledges the bug AT the flag-table
```

**The comment at line 2426 LITERALLY explains the bug, but only fixes it for
the flag table — not for the cache_flags bitmask 17 lines above.**
Classic **comment-as-confession** pattern; cumulative count of this fleet
pattern reaches 5 distinct instances (W141 was the 4th).

**Impact:** Dormant unless the sigcache is exercised against historical
P2SH transactions in the 173,805..227,930 window. Latent because most
runs go through assumevalid; a `-noassumevalid` IBD with sigcache
warmed from the same range could produce wrong-result cache hits in
theory. Fix is identical to line 2429: `if true then cache_flags = ... + 1`.

---

### BUG-13 (P2) — Cache_flags bitmask omits NULLDUMMY + TAPROOT bits

**File:** `src/utxo.lua:2408-2413`.

**Description:** The cache_flags only has 5 bits (1, 2, 4, 8, 16). Of the
7 consensus flags applied at line 2428-2436 (P2SH, DERSIG, CLTV, CSV,
WITNESS, NULLDUMMY, TAPROOT), only 5 are reflected in the cache key.

- NULLDUMMY shares its gate (`segwit_height`) with WITNESS, so they always
  co-activate; using only the WITNESS bit happens to be safe.
- TAPROOT is height-gated independently (`taproot_height = 709632`). Pre-
  taproot blocks with cached entries would collide with post-taproot
  blocks. The native P2TR dispatch bypasses verify_script entirely (so
  it never goes through the cache anyway) — but the flag is still set in
  the flag-bag, so the legacy `verify_witness_program` path (P2SH-P2WSH
  inside a redeem script with a v1+32 inner witness) would have a
  different effective flag set without a cache-key bit to distinguish it.

**Impact:** Latent (current dispatch shape avoids the collision). Becomes
real if anyone adds a TAPROOT-flag-sensitive path that goes through
`verify_script`.

---

### BUG-14 (P2) — `getblockchaininfo.softforks` missing `bip16`

**File:** `src/rpc.lua:1224-1241` (`build_deployment_state`).

**Core ref:** Core emits `bip16` in the softforks list of
getblockchaininfo with `type=buried, active=true, height=173805` on
mainnet.

**Description:** `build_deployment_state` adds entries for bip34/65/66/csv/
segwit/taproot but not bip16. Clients parsing the response field-by-field
will not see a bip16 entry.

**Impact:** RPC client compat (block explorers, wallet software, anyone
who scans for softfork activation). One-line wire-up after BUG-11 lands.

---

### BUG-15 (P2) — `getdeploymentinfo.deployments` missing `bip16`

**File:** `src/rpc.lua:1224-1241` (same source).

**Description:** `getdeploymentinfo` is the modern (Bitcoin Core ≥ v23) RPC
that exposes the same deployment table. lunarblock's `build_deployment_state`
serves both endpoints, so the missing-BIP-16 bug surfaces on both.

**Impact:** RPC client compat.

---

### BUG-16 (P3) — Versionbits machinery is officially decorative dead-code; two-pipeline-guard pattern continues

**File:** `src/consensus.lua:482-552` (versionbits module + DEPLOYMENTS table).

**Description:** The DEPLOYMENTS table at lines 539-552 defines BIP9 params
for SEGWIT and TAPROOT (bit, start_time, timeout, min_activation_height).
The comment block at lines 482-518 explicitly states this module is **not
on the consensus path**, that buried-height enforcement is the actual
mechanism, and that any caller routing this into `connect_block` should
"stop and talk to whoever owns soft-fork activation policy first".

The pattern is a fleet-wide two-pipeline guard:

- **Pipeline 1**: buried heights in `M.networks.<name>.<fork>_height` —
  the actual consensus path.
- **Pipeline 2**: BIP9 versionbits state machine — decorative; tests pin
  it; production never calls it.

This is the same shape as W134's "feefilter manager dead code", W135's
"bare-P2PK input detector but no output side", W141's "zmq publisher
defined but never imported". Catalogued for fleet-pattern accounting.

**Impact:** P3 — module exists, doesn't fire. Latent footgun for a future
maintainer who tries to "fix" missing versionbits without reading the
comment.

---

### BUG-17 (P1) — Validation_weight_left in script-eval flag table is a CONSENSUS flag conflated with policy bag

**File:** `src/script.lua:1759-1764, 2105-2112` /
`src/utxo.lua:2728-2730`.

**Description:** BIP-342's `m_validation_weight_left` budget is a CONSENSUS
rule (per Core interpreter.cpp:1981 — initialized inside ExecuteWitnessScript,
gated on `sigversion == TAPSCRIPT`). lunarblock stuffs it into the same
`flags` table as the SCRIPT_VERIFY_* flags. It's not a flag, it's a
mutable counter. The conflation matters because:

1. Tap_flags is shallow-copied via `for k, v in pairs(flags) do ... end`
   (`utxo.lua:2530-2531, 2558-2559`). The counter mutates **the shared
   table** if the copy didn't go through.
2. `flags.validation_weight_init` gates the deduction. Future refactor that
   wants to switch this off via a flag-bag pattern could accidentally enter
   "policy-pass" mode with the budget active, splitting consensus from policy.

**Impact:** Latent / structural. The fix is to move
`validation_weight_left` to a separate exec-state object distinct from the
SCRIPT_VERIFY flags bag.

---

### BUG-18 (P2) — `verify_strictenc` is policy-only in Core, but `script.lua:234` couples it with consensus `verify_dersig` in DER-encoding check

**File:** `src/script.lua:234`:

```lua
if (flags.verify_dersig or flags.verify_strictenc or flags.verify_low_s) then
  if not is_valid_signature_encoding(sig) then
    return false, "SIG_DER"
  end
end
```

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:81-100`
(`CheckSignatureEncoding`):

```cpp
if ((flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) != 0 &&
    !CheckSignatureEncoding(...)) {
    return false;
}
```

— Core checks DER encoding under any of (DERSIG, LOW_S, STRICTENC). lunarblock
matches: line 234 is a 3-way OR over the same three flags. **This gate is
correct.** Catalogued as P2 because the wording at the lunarblock comment
("Use strict DER parsing when DERSIG/STRICTENC/LOW_S flags require it") is
correct but the ECDSA verify call afterwards (`crypto.ecdsa_verify` vs.
`crypto.ecdsa_verify_lax`) uses the same triple at `validation.lua:1560`:

```lua
if flags.verify_dersig or flags.verify_strictenc or flags.verify_low_s then
  return crypto.ecdsa_verify(pubkey, sig_der, sighash)
else
  return crypto.ecdsa_verify_lax(pubkey, sig_der, sighash)
end
```

This appears to gate strict-DER VERIFICATION on the same flag set — but
strict-DER ENCODING was already checked at the entrypoint. The lax verify
in the else branch is for the pre-BIP66 era. **OK in shape**, but the
duplicate check is suspicious for refactor-safety. Latent at P2.

---

### BUG-19 (P0-CDIV) — `verify_const_scriptcode` OP_CODESEPARATOR check missing in unexecuted branches (Core ref interpreter.cpp:474-476)

**File:** `src/script.lua:1420-1428` (OP_CODESEPARATOR handler) +
`src/script.lua:1158-1162` (unexecuted-branch skip).

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:474-476`:

```cpp
// With SCRIPT_VERIFY_CONST_SCRIPTCODE, OP_CODESEPARATOR in non-segwit script
// is rejected even in an unexecuted branch
if (opcode == OP_CODESEPARATOR && sigversion == SigVersion::BASE && (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE))
    return set_error(serror, SCRIPT_ERR_OP_CODESEPARATOR);
```

**Description:** Per Core, OP_CODESEPARATOR in a non-segwit script (BASE
sigversion) under CONST_SCRIPTCODE flag must **fail the script even in an
unexecuted branch**. lunarblock's main eval loop at line 1158-1162 first
skips non-executing branches (`if not is_executing() then i = i + 1;
goto continue end`), and the OP_CODESEPARATOR handler at line 1420 has
no `verify_const_scriptcode` guard at all. So:

- Even in an executing branch, lunarblock does NOT reject OP_CODESEPARATOR
  under CONST_SCRIPTCODE.
- In an unexecuted branch, lunarblock skips the opcode entirely.

Either way: consensus split when CONST_SCRIPTCODE is active in BASE
sigversion (= policy-pass standardness check).

**Impact:** This is **paired with BUG-7**: lunarblock claims to enforce
CONST_SCRIPTCODE via the mempool standard flag but both required check
sites (FindAndDelete-found and OP_CODESEPARATOR-in-BASE) are missing.
The flag is end-to-end dead code. P0-CDIV because under the standard
policy pass (Core relays standardness check), lunarblock accepts what
Core rejects.

---

### BUG-20 (P1) — `verify_nullfail` checked in mempool but consensus path does NOT enforce; classic policy-only conflation symptom

**File:** `src/utxo.lua:2421-2424` (correct comment) +
`src/script.lua:1502, 1563, 1652` (consumer sites).

**Description:** The comment at `utxo.lua:2421-2424` explicitly says
`verify_nullfail` and `verify_witness_pubkeytype` are policy-only and
MUST NOT be set in block-connect. The flag-table at line 2428-2436 then
correctly omits them. **OK in shape, BUT** —

Looking at the consumer side: `script.lua:1502, 1563, 1652` consume
`flags.verify_nullfail` and `flags.verify_witness_pubkeytype` without
asserting "are we in the policy pass?". A future change that
accidentally adds `verify_nullfail = true` to the connect-side flag table
would silently flip block-connect into policy mode — a consensus split
in either direction depending on whether the input is `NULLFAIL`-clean.

**Impact:** Latent / refactor-safety. P1 because the guard is comment-only
and one stray copy-paste could split consensus.

---

### BUG-21 (P2) — `verify_sigpushonly` always-on at policy AND consensus, but BIP-16 P2SH redeem-script SIG_PUSHONLY requirement is **already** unconditional inside `verify_script:2204-2207`

**File:** `src/script.lua:2168-2170, 2204-2207`.

**Description:** Line 2168 enforces SIGPUSHONLY iff `flags.verify_sigpushonly`.
Line 2204-2207 enforces SIGPUSHONLY for P2SH unconditionally (BIP-16
consensus rule). The flag thus only matters for non-P2SH bare scripts —
which Core treats as `SIGPUSHONLY` only at relay (policy). lunarblock
matches Core's shape, **but** the flag is set in mempool.lua:1629 and
NEVER set in `utxo.lua:2428-2436` — so the non-P2SH SIGPUSHONLY check is
relay-only, matching Core. **OK in shape, P2-comment-quality only:**
the doubled enforcement at lines 2168 and 2204 is non-obvious; future
refactor risk.

**Impact:** Cosmetic / refactor-safety.

---

### BUG-22 (P1) — Sigops flag table at sigop counter omits TAPROOT-aware accounting

**File:** `src/utxo.lua:2248-2251` (sigop_flags) /
`src/validation.lua:519-551` (get_transaction_sigop_cost).

**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp` (sigops accounting)
includes witness sigops gated on `SCRIPT_VERIFY_WITNESS`; tapscript
inputs do **not** add to sigop cost (the BIP-342 validation-weight budget
replaces per-block sigop accounting for tapscript). lunarblock matches by
having `count_witness_sigops` consult the script-version. **OK structurally,
P1 footnote:** `sigop_flags` only has `verify_p2sh` and `verify_witness` —
no `verify_taproot`. The sigop counter doesn't ask for it, but
the flag-set asymmetry between `sigop_flags` (2 keys) and the consensus
flag bag (7 keys) is a refactor hazard.

**Impact:** Latent (no behavior divergence today).

## Fleet patterns observed

1. **Dead-flag / flag-set-but-no-callsite (3 instances in this wave):**
   `verify_taproot` (BUG-4), `verify_const_scriptcode` (BUG-7, BUG-19),
   `verify_minimalif` (in BUG-6).
2. **Comment-as-confession (BUG-12):** Line `utxo.lua:2426-2427` literally
   tells the reader the bug (cache_flags using `bip34_height` for P2SH) but
   only fixes the symptom at the flag-table 17 lines below. 5th distinct
   instance of this fleet pattern.
3. **Two-pipeline guard (BUG-16):** versionbits module + buried heights.
   `consensus.lua:482-518` has the most explicit "this is decorative,
   don't use this" disclaimer of any fleet impl. Cumulative two-pipeline
   guard count now 15+ distinct extensions.
4. **Height-gate-vs-flag-gate conflation (BUG-3, BUG-4):** Native witness
   dispatch in `utxo.lua:2517, 2583` uses `script_type == ... and height
   >= ...` instead of `flags.verify_witness` / `flags.verify_taproot`.
   The flags are computed from the same height expression, so they always
   agree — but the flag has no consumer. Same shape as W132's
   `enforce_bip68` / `M.is_active_at_height` divergence.
5. **Mempool-flag-set-superset-of-consensus pattern:** mempool.lua:1622-1639
   has 14 flag bits set; utxo.lua:2428-2436 has 7. The bits in the difference
   ARE policy-only (correct), but they include `verify_const_scriptcode`
   which is dead-end (BUG-7).
6. **Exception-block omissions (BUG-1, BUG-2):** lunarblock has no
   `script_flag_exceptions` table, so the BIP-16 and Taproot exception
   blocks would fail `-noassumevalid` IBD. Fleet-wide observation expected.

## Severity summary

- **P0-CDIV (4):** BUG-3 (native witness dispatch bypasses verify_witness),
  BUG-19 (OP_CODESEPARATOR const_scriptcode unchecked).
- **P0 (5):** BUG-4 (verify_taproot dead-flag), BUG-5 (mempool MANDATORY
  missing taproot), BUG-7 (find_and_delete loses found_count;
  const_scriptcode unenforceable).
- **P1 (7):** BUG-1 (BIP-16 exception), BUG-2 (Taproot exception), BUG-6
  (DISCOURAGE_\* flags missing), BUG-11 (no bip16_height), BUG-12 (cache_flags
  P2SH bit), BUG-17 (validation_weight_left in flag bag), BUG-20
  (verify_nullfail policy-conflation refactor risk), BUG-22 (sigop_flags
  asymmetry).
- **P2 (4):** BUG-9 (verify_input_scripts opt-out), BUG-10 (signet
  absent), BUG-13 (cache_flags missing NULLDUMMY+TAPROOT bits), BUG-14
  (bip16 missing from getblockchaininfo), BUG-15 (bip16 missing from
  getdeploymentinfo), BUG-18 (DER-encoding gate duplicated), BUG-21
  (sigpushonly doubled enforcement).
- **P3 (2):** BUG-8 (sigop_flags hardcoded true regardless of mempool
  height), BUG-16 (versionbits decorative).

## Recommended fix order

1. **BUG-7 (P0): make `find_and_delete` return found_count**, wire into the
   ECDSA path, then add the OP_CODESEPARATOR-in-BASE check (BUG-19) — 1
   line in `validation.lua` + 2 sites in `script.lua`. Closes both P0-CDIV
   const_scriptcode bugs and the "flag set but never enforced" pattern.
2. **BUG-3 (P0-CDIV): replace `if script_type == "p2wpkh" or … then` at
   `utxo.lua:2517` with `if flags.verify_witness and script_type == …`.**
   Same idea for the taproot dispatch (BUG-4). 2-line fix.
3. **BUG-5 (P0): add `verify_taproot = true` to mempool.lua:1622-1639.**
   1-line fix.
4. **BUG-6 (P1): add the 5 missing DISCOURAGE_\* / MINIMALIF flags to
   mempool.lua:1622-1639.** 5-line fix.
5. **BUG-1 + BUG-2 + BUG-11 (P1 cluster): introduce `script_flag_exceptions`
   table in mainnet network params; consume in the flag derivation at
   `utxo.lua:2429-2436`.** ~10 lines.
6. **BUG-12 (P1): replace `bip34_height` with `bip16_height` (or
   `true`/unconditional 1) in cache_flags computation at
   `utxo.lua:2409`.** 1-line fix.
7. **BUG-14 + BUG-15 (P2): add `deployments.bip16` in
   `build_deployment_state` after BUG-11.** 3-line fix.

Total: ~25 lines of code to close 11 of 22 bugs catalogued, including all
4 P0-CDIVs and all 5 P0s.
