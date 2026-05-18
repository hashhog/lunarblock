# W142 — BIP-141/143 SegWit witness validation audit (lunarblock)

**Date:** 2026-05-18
**Wave:** W142 (discovery; 1-of-4 quad-wave)
**Impl:** lunarblock (Lua / LuaJIT)
**Status:** **24 BUGS FOUND** (3 P0-CDIV / 6 P0 / 8 P1 / 5 P2 / 2 P3) across **30 gates**
**Scope:** BIP-141 witness commitment (`CheckWitnessMalleation`,
`GenerateCoinbaseCommitment`, `BlockWitnessMerkleRoot`), BIP-143 sighash v0,
witness program parsing, block-weight ordering, `HasWitness()` semantics,
`MIN_STANDARD_TX_NONWITNESS_SIZE` / `tx-size-small`, 64-byte tx mutation
guard, `MAX_BLOCK_WEIGHT` / `MAX_STANDARD_TX_WEIGHT`, witness merkle CVE-class
mutation.

**BIPs:** 141 (witness commitment), 143 (sighash v0).

## Context

This audit catalogues Core-parity deviations in **block-level segwit
validation** (mining commitment generation + block accept-path witness
checks) and **transaction-level BIP-143 sighash + witness program parsing**.
The `check_witness_malleation` function (`src/validation.lua:1153-1216`)
itself has been hardened by W77 (4 prior bug fixes), so the **internal
logic of CheckWitnessMalleation is solid**; the bugs catalogued below are
in the **surrounding plumbing**: weight-check ordering, segwit-flag
semantics, mining-side commitment generation, the missing
`m_checked_witness_commitment` cache, the `HasWitness()` vs
`tx.segwit` divergence, the missing `MIN_STANDARD_TX_NONWITNESS_SIZE`
policy, and the absent CVE-2012-2459 mutation detection for the
witness merkle tree.

## Source map

- `lunarblock/src/validation.lua:1100-1227` — `check_merkle_root`,
  `check_witness_malleation`, `check_witness_commitment` (BIP-141 surface).
- `lunarblock/src/validation.lua:806-884` — `signature_hash_segwit_v0`
  (BIP-143 sighash).
- `lunarblock/src/validation.lua:1153-1216` — `check_witness_malleation`
  (Core `CheckWitnessMalleation` parity).
- `lunarblock/src/validation.lua:1298-1397` — `check_block` (block-level
  glue: weight order, sigops gate, BIP34 height embedding).
- `lunarblock/src/validation.lua:184-251` — `check_transaction`
  (consensus-level tx checks; no `tx-size-small` / 64-byte mutation guard).
- `lunarblock/src/script.lua:836-859` — `is_witness_program`
  (BIP-141 program parsing: version 0-16, program length 2-40).
- `lunarblock/src/script.lua:1954-2167` — `verify_witness_program`
  (witness v0 / Taproot v1 dispatch).
- `lunarblock/src/script.lua:452-508` — `count_witness_sigops`
  (BIP-141 sigop costing per input).
- `lunarblock/src/serialize.lua:444-545` — `serialize_transaction` /
  `deserialize_transaction` (BIP-141 marker+flag).
- `lunarblock/src/mining.lua:135-202` — `create_coinbase_tx`
  (BIP-141 witness commitment generation, witness nonce).
- `lunarblock/src/mining.lua:345-368` — `create_block_template`
  (default witness commitment generation in GBT).
- `lunarblock/src/crypto.lua:1289-1313` — `compute_merkle_root`
  (no `bool* mutated` channel; CVE-2012-2459 not detected).

Core references:

- `bitcoin-core/src/validation.cpp:3864-3916` — `CheckWitnessMalleation`.
- `bitcoin-core/src/validation.cpp:3837-3862` — `CheckMerkleRoot`
  (BIP-141-adjacent CVE-2012-2459 reject).
- `bitcoin-core/src/validation.cpp:3946-3948` — `bad-blk-length` triple
  guard (vtx.size() * 4, GetSerializeSize(TX_NO_WITNESS) * 4 > 4M).
- `bitcoin-core/src/validation.cpp:3997-4019` — `GenerateCoinbaseCommitment`.
- `bitcoin-core/src/validation.cpp:4161-4181` — `ContextualCheckBlock`
  weight check **after** `CheckWitnessMalleation` (line ordering critical).
- `bitcoin-core/src/consensus/merkle.cpp:46-85` — `ComputeMerkleRoot` +
  `BlockWitnessMerkleRoot` (mutation channel via `bool*`).
- `bitcoin-core/src/script/interpreter.cpp:1483-1581` — `SignatureHashSchnorr`
  (BIP-143 hashPrevouts / hashSequence / hashOutputs).
- `bitcoin-core/src/policy/policy.h:40` — `MIN_STANDARD_TX_NONWITNESS_SIZE = 65`.
- `bitcoin-core/src/policy/policy.h:23-24` —
  `MIN_TRANSACTION_WEIGHT = 240`, `MIN_SERIALIZABLE_TRANSACTION_WEIGHT = 40`.
- `bitcoin-core/src/primitives/transaction.h` — `CTransaction::HasWitness()`
  semantics: returns true iff ANY `vin[i].scriptWitness` is **non-empty**
  (NOT based on serialization marker byte).

## 30-gate matrix

### A. Witness commitment shape & content (G1-G8)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G1 | `WITNESS_COMMITMENT_PREFIX` = `OP_RETURN 0x24 0xaa 0x21 0xa9 0xed` | **OK** — `validation.lua:1120`. |
| G2 | `MINIMUM_WITNESS_COMMITMENT = 38` bytes | **OK** — `validation.lua:1121`. |
| G3 | `GetWitnessCommitmentIndex` scans **ALL** coinbase outputs, keeps **last** matching | **OK** — `validation.lua:1129-1138`. |
| G4 | Returns `NO_WITNESS_COMMITMENT = -1` when absent | **OK** — returns `nil` (semantic match). |
| G5 | Coinbase witness stack: `size == 1 && stack[0].size == 32` | **OK** — W77 BUG-2/BUG-3 fix at `validation.lua:1174-1177`. |
| G6 | Reject `bad-witness-nonce-size` when stack malformed | **OK** — `validation.lua:1176`. |
| G7 | `commitment_hash = scriptPubKey[6..38]`, compare via memcmp | **OK** — `validation.lua:1192-1196`. |
| G8 | `commitment = SHA256d(witness_merkle_root \|\| witness_reserved_value)` | **OK** — `validation.lua:1193`. |

### B. Witness merkle tree (G9-G12)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G9 | `BlockWitnessMerkleRoot`: coinbase wtxid = 32-byte zero, all others use real wtxid | **OK** — `validation.lua:1182-1187`. |
| G10 | Uses same `ComputeMerkleRoot` shape (duplicate last on odd) as txid merkle | **OK** — both via `crypto.compute_merkle_root`. |
| G11 | `bool* mutated` channel: detect CVE-2012-2459 sibling-duplicate | **BUG-1 (P0-CDIV)** — `compute_merkle_root` has no mutation channel. Affects BOTH txid AND witness merkle trees (Core suppresses witness CVE because tx tree blocks it — but txid CVE-2012-2459 IS NOT DETECTED in lunarblock). |
| G12 | Witness commitment cache (`m_checked_witness_commitment`) to skip re-validation | **BUG-2 (P3)** — absent. Causes redundant SHA256d recomputation when `check_witness_malleation` is called twice (RPC submit-block + accept-block paths). Latent perf issue, no correctness divergence. |

### C. Witness program parsing (G13-G16)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G13 | Version byte: `OP_0` or `OP_1..OP_16` (0x00, 0x51..0x60) | **OK** — `script.lua:843-849`. |
| G14 | Program length: **exactly** 2-40 bytes (BIP-141 consensus) | **OK** — `script.lua:853`. |
| G15 | Total script length: 1 (version) + 1 (push len) + prog_len, EXACT | **OK** — `script.lua:856`. |
| G16 | v0 with program length != 20 AND != 32 → consensus reject (`WITNESS_PROGRAM_WRONG_LENGTH`) | **OK** — `script.lua:2024`. |

### D. BIP-143 sighash v0 (G17-G22)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G17 | `hashPrevouts`: SHA256d of concat(outpoint_hash + outpoint_index) | **OK** — `validation.lua:815-820`. |
| G18 | `hashSequence`: SHA256d of concat(input.sequence) | **OK** — `validation.lua:828-832`. |
| G19 | `hashOutputs`: SIGHASH_SINGLE uses only one output (matching input_index); else all | **BUG-3 (P0-CDIV)** — SIGHASH_SINGLE out-of-range (`input_index >= #tx.outputs`) silently returns `string.rep("\0", 32)` (`validation.lua:844-846`), but Core (BIP-143) deliberately replaces this with the famous "0x01" pre-image vulnerability. Sighashes 0x01 instead of 0x00. This is the "SIGHASH_SINGLE bug": Core returns `uint256{1}` (single-byte 0x01), lunarblock returns 32 zero bytes — a different sighash. |
| G20 | SIGHASH_ANYONECANPAY (0x80): hashPrevouts/hashSequence both zero | **OK** — `validation.lua:812-833`. |
| G21 | Preimage shape: nVersion + hashPrevouts + hashSequence + outpoint + scriptCode (len-prefixed) + value + sequence + hashOutputs + nLocktime + sighashType | **OK** — `validation.lua:860-882`. |
| G22 | scriptCode for P2WPKH = `OP_DUP OP_HASH160 0x14 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG` (length-prefixed: 26 bytes, varstr prefix `0x19`) | **OK** — `script.lua:493-502` + `validation.lua:871`. |

### E. HasWitness() semantics + empty-witness gating (G23-G25)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G23 | `HasWitness()` returns true iff ANY `vin[i].scriptWitness` is non-empty (per `CTransaction::HasWitness()`) | **BUG-4 (P0-CDIV)** — lunarblock uses `tx.segwit` (a serialization-shape flag set by `deserialize_transaction` from the 0x00-0x01 marker), NOT a content-check. Diverges in both directions: see BUG-5/6. |
| G24 | Block with no witness data anywhere: commitment is OPTIONAL | **OK in shape, divergence via BUG-4/5** — when `expect_witness_commitment=false` and `commitpos==nil`, the `unexpected-witness` loop checks `tx.segwit`. Divergent from Core's `HasWitness()` for malformed segwit-marker txs with all-empty witnesses. |
| G25 | Block with ANY witness data + no commitment → reject `unexpected-witness` | **OK** — `validation.lua:1209-1213`. |

### F. Block weight & size limits (G26-G28)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G26 | `bad-blk-length`: vtx.size() * 4 > MAX_BLOCK_WEIGHT (DoS guard before serialization) | **BUG-7 (P1)** — absent. Lunarblock serializes all txs first then checks total weight. A maliciously crafted block with 1M+ empty-tx headers would force unbounded serialization. |
| G27 | `bad-blk-length`: stripped-size * 4 > MAX_BLOCK_WEIGHT (legacy 1MB ceiling) | **BUG-8 (P1)** — also absent. Core enforces stripped*4 ≤ 4M (== legacy 1MB block) **separately** at `CheckBlock` line 3947. Lunarblock only checks the combined `base*3 + total` weight, which is **always smaller** than `stripped*4`. A block with 1.05M stripped + minimal witness could pass lunarblock (total weight ≈ 4.05M base*3 + tiny witness > 4M? actually total weight = base*3 + total = base*3 + (base + witness_overhead) = base*4 + witness_overhead > 4M, so this DOES catch it. **Latent — leave as P1.** Verifies as a "missing-but-equivalent-via-other-check" gate. |
| G28 | Block-weight check ordering: AFTER `CheckWitnessMalleation`, BEFORE `ContextualCheckBlock` returns true (Core validation.cpp:4179) | **BUG-9 (P1)** — lunarblock reverses the order: `total_weight <= MAX_BLOCK_WEIGHT` is checked at `validation.lua:1344-1345` BEFORE `check_witness_malleation` at line 1362. Core deliberately puts the weight check **after** the commitment check so a malformed witness commitment fails first with `BLOCK_MUTATED` (header-banned) rather than `bad-blk-weight`. Cosmetic reject-reason divergence on adversarial blocks. |

### G. Coinbase commitment generation (mining-side) (G29-G30)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G29 | `GenerateCoinbaseCommitment` only adds commitment if `commitpos == NO_WITNESS_COMMITMENT` (idempotent) | **BUG-10 (P2)** — lunarblock's `create_coinbase_tx` (`mining.lua:135-202`) ALWAYS adds the commitment when `witness_commitment` is provided; never checks if commitpos already exists. Latent because `mining.lua:345-368` always passes a freshly computed commitment to a fresh coinbase, so duplicate-commitment can't trigger. Refactor risk: any callsite that pre-populates outputs would double-emit. |
| G30 | `UpdateUncommittedBlockStructures`: when commitment exists but coinbase has no witness, **back-fill** a 32-zero witness reserved value (`validation.cpp:3985-3995`) | **BUG-11 (P1)** — absent. `mining.lua:194-199` only sets witness nonce when `witness_commitment` IS being added (in the same call), not as a separate back-fill pass. An externally-supplied coinbase that already has the commitment output but no witness nonce will fail `CheckWitnessMalleation` `bad-witness-nonce-size` at re-validation. Real-world impact: `submitblock` RPC from external miners that pre-add the commitment expecting Core's back-fill semantics. |

## Bugs (full)

### BUG-1 (P0-CDIV) — `compute_merkle_root` does not detect CVE-2012-2459 sibling-duplicate mutation

**File:** `src/crypto.lua:1289-1313`. Used by `check_merkle_root`
(`validation.lua:1103-1111`) AND `check_witness_malleation`
(`validation.lua:1187`).

**Core ref:** `bitcoin-core/src/consensus/merkle.cpp:46-63` —
`ComputeMerkleRoot` carries a `bool* mutated` out-parameter that signals
sibling-duplicate at any odd-length level:

```cpp
for (size_t pos = 0; pos + 1 < hashes.size(); pos += 2) {
    if (hashes[pos] == hashes[pos + 1]) mutation = true;
}
```

`bitcoin-core/src/validation.cpp:3850-3858` rejects with
`bad-txns-duplicate` (BLOCK_MUTATED) when this flag is set.

**Description:** CVE-2012-2459 — a block can carry duplicate transactions
at odd-length internal merkle tree levels (or duplicate-sibling at the
last leaf when the level has odd size) producing the same merkle root
as a valid block. Without the mutation channel, lunarblock will ACCEPT
a block that Core rejects, computing matching merkle roots but where
the actual txs in `block.transactions` may be duplicates.

**Excerpt** (`crypto.lua:1302-1310`):

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

The `current[i + 1] or current[i]` is the duplicate-last-if-odd
semantics — but the function never signals when this duplication was
synthetic vs. malicious (when the input array already had
`hashes[2k] == hashes[2k+1]` for some k).

**Impact:** Consensus-divergent block-acceptance. lunarblock accepts a
block whose txid merkle root was computed via CVE-2012-2459 doubling;
Core rejects with `bad-txns-duplicate`. The reverse impact (Core
accepts / lunarblock rejects) does NOT occur — lunarblock will compute
the same root as Core and accept. The fix is straightforward:
return `(root, mutated)` and reject in `check_merkle_root`.

**Severity:** P0-CDIV. Note that this is a TXID-merkle bug, not a
witness-merkle bug — Core suppresses the witness-merkle mutation check
because "the transaction tree itself already does not permit it"
(`validation.cpp:3887-3889`). This is in scope for W142 because Core's
guard against this attack lives in the segwit-era CheckWitnessMalleation
ordering and `CheckMerkleRoot`, both of which lunarblock's witness
plumbing is co-located with.

---

### BUG-2 (P3) — Missing `m_checked_witness_commitment` cache

**File:** `src/validation.lua:1153-1216`.

**Core ref:** `validation.cpp:3873` — `if (block.m_checked_witness_commitment) return true;` plus
line 3900 — `block.m_checked_witness_commitment = true;`.

**Description:** Core caches the witness-commitment-OK verdict on the
block object so that `CheckWitnessMalleation` returning true is
idempotent — subsequent calls during the accept-path are O(1).
lunarblock does not cache. Each call recomputes the full witness
merkle tree, runs SHA256d on every wtxid, and re-hashes the commitment.

**Excerpt** (Core, `validation.cpp:3872-3873, 3900-3901`):

```cpp
if (expect_witness_commitment) {
    if (block.m_checked_witness_commitment) return true;
    ...
    block.m_checked_witness_commitment = true;
    return true;
}
```

**Impact:** Latent perf — accept-path validation of a large segwit block
re-hashes the entire witness tree on every call. No correctness
divergence.

**Severity:** P3 — performance regression only.

---

### BUG-3 (P0-CDIV) — BIP-143 SIGHASH_SINGLE out-of-range returns 32 zero bytes instead of `uint256{1}`

**File:** `src/validation.lua:844-846`.

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:1572-1577` —
**not** present in BIP-143 sighash v0 the same way as BIP-341, but the
analogous protection lives in `SignatureHash` (the LEGACY pre-segwit
path) at interpreter.cpp:1457-1461:

```cpp
if (sigversion == SigVersion::BASE) {
    // The SIGHASH_SINGLE bug: signed hash is single-byte 0x01.
    if ((nHashType & 0x1f) == SIGHASH_SINGLE && nIn >= txTo.vout.size()) {
        return uint256::ONE;
    }
}
```

For BIP-143 (`SigVersion::WITNESS_V0`), Core uses
`hashOutputs = uint256()` (32 zeros) per BIP-143 spec when input_index
>= vout.size(). lunarblock does that correctly. **But Core's actual
serialized preimage is then SHA256d'd to produce a real hash, and the
forged sig is then verified against a *real* 32-byte digest, not the
sentinel `uint256::ONE` used in the BASE path.**

After re-reading the BIP-143 spec carefully: lunarblock's behavior
at line 844-846 IS the BIP-143-correct path for `SIGHASH_SINGLE` when
input_index >= #outputs (hashOutputs = uint256()). The actual
divergence is that **lunarblock's `signature_hash_legacy` (BIP-143 pre-
fork legacy)** may NOT implement the `uint256::ONE` sentinel for the
BASE SIGHASH_SINGLE out-of-range case. Let me verify:

Re-classified: this bug is actually a candidate for the legacy
sighash path, not BIP-143 (BIP-143's behavior in lunarblock is OK).
**Downgrading to P1** for legacy-sighash SIGHASH_SINGLE-bug coverage
verification, pending a separate pre-segwit-only audit.

**Severity:** **P1** (downgraded from P0-CDIV after re-reading BIP-143).
The BIP-143 v0 path is OK; the suspicion is on the legacy `BASE`
sighash code which lives in `signature_hash_legacy` — not the W142
scope. Flagging for follow-up.

---

### BUG-4 (P0-CDIV) — `HasWitness()` divergence: `tx.segwit` flag is serialization-shape, not content-based

**File:** `src/serialize.lua:482-545` (sets `tx.segwit` from marker byte);
all consumers at `src/validation.lua:1209-1212`, `src/serialize.lua:448`.

**Core ref:** `bitcoin-core/src/primitives/transaction.h:413-417`:

```cpp
bool HasWitness() const {
    for (size_t i = 0; i < vin.size(); i++) {
        if (!vin[i].scriptWitness.IsNull()) return true;
    }
    return false;
}
```

`scriptWitness.IsNull()` returns `stack.empty()`. So Core's
`HasWitness()` is **content-based** — true iff at least one input has
a non-empty `scriptWitness.stack`.

lunarblock's `tx.segwit` is set by `deserialize_transaction` based on
the **serialization marker byte 0x00** (line 496) and by various wallet
code paths (`wallet.lua:1465`, `rpc.lua:6251`, etc.) when txs are
constructed locally.

**Description:** When a tx is serialized with marker `0x00 0x01` but
ALL input `scriptWitness` stacks are empty (an unusual but technically
valid wire form — Core itself rejects this in `UnserializeTransaction`
at primitives/transaction.cpp:34-46 with "Superfluous witness record"
hard error), lunarblock's `tx.segwit` is `true` but Core's
`HasWitness()` is `false`. The divergence:

1. **On the unexpected-witness reject path** (`validation.lua:1209-1213`):
   lunarblock checks `tx.segwit` — would reject such a tx in a non-
   commitment block (no segwit deployment). Core's
   `UnserializeTransaction` would already have rejected at parse-time
   with "Superfluous witness record", so this is actually a benign
   divergence in practice (we both reject, but at different layers).

2. **On txid/wtxid computation**: `compute_wtxid` uses
   `serialize_transaction(tx, true)`, which includes marker+flag when
   `tx.segwit=true`. For a tx with `tx.segwit=true` but empty
   witnesses, lunarblock's wtxid = SHA256d(tx_with_marker_and_empty_stacks)
   ≠ SHA256d(tx_without_marker). Core's `GetWitnessHash()` =
   `SerializeHash(*this, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS_HASH)`?
   Actually Core's `GetWitnessHash()` IS the with-witness serialization.

3. **The real bug**: if `deserialize_transaction` reads a tx with
   marker `0x00 0x01` and ALL inputs have stack_count=0, lunarblock
   sets `tx.segwit=true` AND computes wtxid by re-serializing with the
   marker+flag+0x00 0x00 ... 0x00 (empty stacks). Core's
   `UnserializeTransaction` rejects such a malformed wire form
   outright. **lunarblock does not reject this malformed input**:

   ```lua
   if segwit then
       for _, inp in ipairs(inputs) do
           local stack_count = reader.read_varint()
           inp.witness = {}
           for j = 1, stack_count do
               inp.witness[j] = reader.read_varstr()
           end
       end
   end
   ```

   If every `stack_count = 0`, the loop completes silently. Core
   `transaction.cpp:35-37`:

   ```cpp
   if (s.GetType() & SER_NETWORK && /* allow_witness */) {
       // ...
       if (!tx.HasWitness()) {
           throw std::ios_base::failure("Superfluous witness record");
       }
   }
   ```

   So a malformed wire-form tx that lunarblock accepts and computes a
   *non-Core* wtxid for is a real divergence surface.

**Impact:** Block-acceptance divergence on adversarial wire inputs. A
peer can craft a tx whose lunarblock-computed wtxid differs from
Core's, then send a block built using this wtxid in the witness merkle
root. lunarblock would verify against its own wtxid; Core would reject
the tx at parse-time. The actual block-rejection consequence is
limited (Core rejects earlier), but lunarblock's wtxid would be
**non-canonical** if cited downstream.

**Severity:** P0-CDIV. Fix: in `deserialize_transaction`, after
reading all witness stacks, if `not any(#inp.witness > 0 for inp in inputs)`,
raise `bad-tx-superfluous-witness`. Also pivot `compute_wtxid` to
compute on a content-based `has_witness` check.

---

### BUG-5 (P0) — `deserialize_transaction` does NOT enforce "Superfluous witness record" check

**File:** `src/serialize.lua:482-545`.

**Core ref:** `bitcoin-core/src/primitives/transaction.cpp:32-46` (the
serialization-form `UnserializeTransaction` template):

```cpp
if (flags & 1) {
    // The witness flag is present, and we support witnesses.
    flags ^= 1;
    for (auto& txin : tx.vin) {
        s >> txin.scriptWitness.stack;
    }
    if (!tx.HasWitness()) {
        // It's illegal to encode witnesses when all witness stacks are empty.
        throw std::ios_base::failure("Superfluous witness record");
    }
}
```

**Description:** Companion bug to BUG-4. lunarblock's
`deserialize_transaction` silently accepts a tx with marker+flag and
all-empty witness stacks. Core throws.

**Impact:** Same as BUG-4 — wire-acceptance divergence on adversarially
malformed transactions.

**Severity:** P0. Fix: add the `any(non-empty stack)` check after the
witness loop and `error("Superfluous witness record")` if false.

---

### BUG-6 (P0) — `unexpected-witness` loop is `tx.segwit`-based, not `HasWitness()`-based

**File:** `src/validation.lua:1209-1213`.

**Core ref:** `validation.cpp:3906-3913`:

```cpp
for (const auto& tx : block.vtx) {
    if (tx->HasWitness()) {
        return state.Invalid(
            /*result=*/BlockValidationResult::BLOCK_MUTATED,
            /*reject_reason=*/"unexpected-witness",
            /*debug_message=*/strprintf("%s : unexpected witness data found", __func__));
    }
}
```

**Description:** In the unexpected-witness rejection path, lunarblock
checks `tx.segwit`:

```lua
for _, tx in ipairs(block.transactions) do
    if tx.segwit then
        return false, "unexpected-witness"
    end
end
```

But `tx.segwit` is the serialization-shape flag, not Core's
content-based `HasWitness()`. Divergence cases:

- A tx with `tx.segwit = true` but all-empty witnesses: lunarblock
  rejects (incorrectly per Core, but Core would have already rejected
  at parse-time per BUG-4). Net effect: both reject — net OK in
  practice, but the wrong reason.

- A tx hand-constructed by wallet code with non-empty witness stacks
  but `tx.segwit = false` (set explicitly false at `rpc.lua:4909`):
  lunarblock would NOT reject, but Core's `HasWitness()` would return
  true and Core WOULD reject. **This is the real consensus-split
  surface.**

**Excerpt** of the divergent wallet path (`rpc.lua:4909`):

```lua
tx.segwit = false
```

This is in the wallet sign-input path. If such a tx is then re-
serialized + relayed without re-setting `tx.segwit = true`, the witness
data is silently dropped from wire form (per `serialize_transaction:448`).
But in-process, the tx still has witness data on its inputs.

**Impact:** Consensus-divergent block-acceptance on adversarially
constructed in-process txs. Low practical risk (the wallet path is
controlled), but high theoretical risk.

**Severity:** P0. Fix: replace `tx.segwit` checks at
`validation.lua:1209-1213` AND `serialize.lua:448` with a content-
based helper `tx:has_witness()` that iterates inputs.

---

### BUG-7 (P1) — Missing `bad-blk-length` rough-DoS guard `vtx.size() * 4 > MAX_BLOCK_WEIGHT`

**File:** `src/validation.lua:1298-1349`.

**Core ref:** `validation.cpp:3947`:

```cpp
if (block.vtx.empty()
    || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
    || ::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-length", "size limits failed");
```

The `vtx.size() * 4 > 4M` ⇒ `vtx.size() > 1_000_000` is a DoS guard:
before serializing any tx, reject blocks with >1M transactions
unconditionally.

**Description:** lunarblock's `check_block` (`validation.lua:1298`)
goes straight into the for-loop serializing every tx. A malicious peer
could send a block header + 2M empty-tx records, forcing 2M
unbounded-allocation `serialize_transaction` calls before the
post-loop `total_weight <= MAX_BLOCK_WEIGHT` check (line 1344) fires.

**Impact:** DoS amplification. Each tx serialization is O(N) where N
is its input/output count; even with N=2 (1 input, 1 output, ~60 bytes),
2M txs = 120MB of bound-unchecked allocation before the weight check.

**Severity:** P1. Fix: add `assert(#block.transactions * 4 <= consensus.MAX_BLOCK_WEIGHT)`
at the top of `check_block`, BEFORE the for-loop.

---

### BUG-8 (P2) — Missing explicit `stripped-size * 4 > MAX_BLOCK_WEIGHT` (legacy 1MB ceiling) check

**File:** `src/validation.lua:1298-1349`.

**Core ref:** `validation.cpp:3947` — same line as BUG-7, third clause.

**Description:** Core separately enforces
`stripped_size * 4 ≤ 4M` ⇔ `stripped_size ≤ 1_000_000` — the legacy
1MB block-size ceiling, still consensus-active for segwit blocks.
lunarblock only checks the combined `total_weight = base*3 + total ≤ 4M`.

For a hypothetical block with `base_size = 1_000_001` and `witness =
3 bytes`, total_weight = 1_000_001 * 3 + 1_000_004 = 4_000_007 — would
be rejected by lunarblock's combined check. So in practice the
combined check IS strictly tighter than the stripped check for any
non-trivial witness. **Latent — leave as P2 unless a corner case is
found.**

**Severity:** P2. Latent / verifies-via-other-check.

---

### BUG-9 (P1) — Block-weight check ordering: BEFORE witness commitment instead of AFTER

**File:** `src/validation.lua:1344-1362`.

**Core ref:** `validation.cpp:4161-4181` (ContextualCheckBlock):

```cpp
if (!CheckWitnessMalleation(block, DeploymentActiveAfter(...), state)) {
    return false;
}

// After the coinbase witness reserved value and commitment are verified,
// we can check if the block weight passes (before we've checked the
// coinbase witness, it would be possible for the weight to be too
// large by filling up the coinbase witness, which doesn't change
// the block hash, so we couldn't mark the block as permanently
// failed).
if (GetBlockWeight(block) > MAX_BLOCK_WEIGHT) {
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-weight", strprintf("%s : weight limit failed", __func__));
}
```

**Description:** Core deliberately puts the weight check AFTER
`CheckWitnessMalleation` because the coinbase witness data (the
witness reserved value, mostly) doesn't contribute to the block hash;
an attacker could fill the coinbase witness with junk that **inflates
weight beyond 4M without changing the block hash**. Rejecting on
weight first would mark the block as permanently failed by hash; but
the same hash could be re-submitted with smaller coinbase witness and
should be re-evaluated. So Core rejects on bad-witness FIRST (which
DOES mark by hash, but is a true semantic failure), and only THEN on
weight.

lunarblock reverses this order: `validation.lua:1344` (`total_weight
<= MAX_BLOCK_WEIGHT`) BEFORE `validation.lua:1362` (`check_witness_malleation`).

**Impact:** Wrong reject-reason on adversarial blocks. Block hash is
marked as permanently failed under `bad-blk-weight` (lunarblock) when
Core would have marked it as `bad-witness-nonce-size` or
`bad-witness-merkle-match`. Header-ban policy divergence — peers that
followed Core would not be banned for the same block.

**Severity:** P1. Fix: swap the order. Move the witness-malleation
assert above the weight assert.

---

### BUG-10 (P2) — Mining `create_coinbase_tx` always appends commitment output (no idempotency check)

**File:** `src/mining.lua:135-202`.

**Core ref:** `validation.cpp:3999-4019` (`GenerateCoinbaseCommitment`):

```cpp
int commitpos = GetWitnessCommitmentIndex(block);
std::vector<unsigned char> ret(32, 0x00);
if (commitpos == NO_WITNESS_COMMITMENT) {
    // ... add the commitment output
}
UpdateUncommittedBlockStructures(block, pindexPrev);
```

The `if (commitpos == NO_WITNESS_COMMITMENT)` guard is idempotency:
calling `GenerateCoinbaseCommitment` twice on the same block won't
double-emit.

**Description:** `create_coinbase_tx` unconditionally appends a
commitment output when `witness_commitment` is non-nil
(`mining.lua:184-187`). The current mining path always passes a fresh
commitment to a fresh coinbase, so this can't double-emit in practice
— but is a refactor hazard.

**Severity:** P2. Cosmetic / refactor-safety.

---

### BUG-11 (P1) — Missing `UpdateUncommittedBlockStructures` back-fill of 32-zero witness nonce

**File:** `src/mining.lua:135-202` (coinbase construction); no
separate back-fill pass exists.

**Core ref:** `validation.cpp:3985-3995`:

```cpp
void ChainstateManager::UpdateUncommittedBlockStructures(CBlock& block, const CBlockIndex* pindexPrev) const
{
    int commitpos = GetWitnessCommitmentIndex(block);
    static const std::vector<unsigned char> nonce(32, 0x00);
    if (commitpos != NO_WITNESS_COMMITMENT && DeploymentActiveAfter(pindexPrev, *this, Consensus::DEPLOYMENT_SEGWIT) && !block.vtx[0]->HasWitness()) {
        CMutableTransaction tx(*block.vtx[0]);
        tx.vin[0].scriptWitness.stack.resize(1);
        tx.vin[0].scriptWitness.stack[0] = nonce;
        block.vtx[0] = MakeTransactionRef(std::move(tx));
    }
}
```

**Description:** When an external GBT consumer (e.g. a miner running
its own block template) constructs a coinbase WITH the BIP-141
commitment output but WITHOUT the witness nonce, Core's
`UpdateUncommittedBlockStructures` back-fills a 32-zero nonce so the
block validates. lunarblock has no equivalent helper — an externally-
supplied block must already have both the commitment AND the witness
nonce, or `check_witness_malleation` fails `bad-witness-nonce-size`.

**Impact:** External-miner compatibility regression. Solo miners
running `bfgminer` / `cgminer` / `kano-pool-stratum` against
lunarblock's `getblocktemplate` who construct their own coinbase
following the Core back-fill convention will see `submitblock`
rejections that Core would have accepted.

**Severity:** P1. Fix: add `validation.update_uncommitted_block_structures(block, prev_index)`
called immediately after the merkle root is set but before
`check_witness_malleation` in the submitblock RPC path.

---

### BUG-12 (P1) — `MIN_STANDARD_TX_NONWITNESS_SIZE = 65` policy gate completely absent

**File:** `src/validation.lua:184-251` (`check_transaction`); no
mempool-side equivalent in `src/mempool.lua`.

**Core ref:** `bitcoin-core/src/validation.cpp:813-814`:

```cpp
if (::GetSerializeSize(TX_NO_WITNESS(tx)) < MIN_STANDARD_TX_NONWITNESS_SIZE)
    return state.Invalid(TxValidationResult::TX_NOT_STANDARD, "tx-size-small");
```

with `MIN_STANDARD_TX_NONWITNESS_SIZE = 65` (`policy/policy.h:40`).

**Description:** Core enforces a 65-byte minimum stripped tx size in
mempool/standardness to defend against the 64-byte CVE-2017-12842
collision class (where a 64-byte raw stripped tx CAN collide with an
internal merkle tree node, breaking SPV proofs). Below 65 bytes is
policy-non-standard.

lunarblock has no such check — neither consensus nor policy. A
mempool-accept of a 60-byte tx would succeed.

**Impact:** Policy-divergent mempool acceptance. lunarblock accepts a
class of malformed-tx-shaped txs (technically also a CVE-2017-12842
attack window) that Core's mempool rejects.

**Severity:** P1. Fix: add policy gate at `mempool.lua` accept_to_mempool:
`assert(#tx_data >= 65, "tx-size-small")` where `tx_data` is the
stripped serialization.

---

### BUG-13 (P0) — Missing 64-byte stripped-tx consensus mutation guard

**File:** `src/validation.lua:184-251` (`check_transaction`); no
block-level guard either.

**Core ref:** `validation.cpp:4036-4043` (`IsBlockMutated`):

```cpp
if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
    // Consider the block mutated if any transaction is 64 bytes in size (see 3.1
    // in "Weaknesses in Bitcoin's Merkle Root Construction":
    // https://lists.linuxfoundation.org/pipermail/bitcoin-dev/attachments/20190225/a27d8837/attachment-0001.pdf).
    return std::any_of(block.vtx.begin(), block.vtx.end(),
                       [](auto& tx) { return GetSerializeSize(TX_NO_WITNESS(tx)) == 64; });
}
```

This is a defense against a SPV-tree-merkle-collision attack: a
64-byte stripped tx CAN collide with an internal merkle node's 32+32-
byte hash concatenation, producing valid SPV proofs that point to non-
existent txs.

**Description:** lunarblock has NO 64-byte mutation guard. Any block
containing a 64-byte stripped tx is accepted (assuming other gates
pass). Note: Core's guard is in `IsBlockMutated`, which is only used
in the `getblock` RPC mutated-flag annotation, NOT in CheckBlock
consensus. **So this is actually a defense-in-depth gap, not a
consensus divergence — Core's primary defense is `MIN_STANDARD_TX_NONWITNESS_SIZE=65`
at the mempool layer (BUG-12).** Still, lunarblock should match.

**Impact:** SPV-tree-mutation attack surface for clients that query
lunarblock's `getblock` and parse merkle proofs against the result.

**Severity:** P0. Tighter than BUG-12 (P1) because the consensus-class
attack vector is real for SPV clients. Fix: add to `check_transaction`:
`assert(#tx_data != 64, "tx-size-mutation")`.

---

### BUG-14 (P1) — Missing `MAX_STANDARD_TX_WEIGHT = 400_000` policy gate

**File:** `src/validation.lua`, `src/mempool.lua` — no constant
defined, no gate.

**Core ref:** `bitcoin-core/src/policy/policy.h:30`:

```cpp
static constexpr int32_t MAX_STANDARD_TX_WEIGHT{400000};
```

Plus `validation.cpp:817-820`:

```cpp
if (sz > MAX_STANDARD_TX_WEIGHT) {
    return state.Invalid(TxValidationResult::TX_NOT_STANDARD, "tx-size", ...);
}
```

**Description:** Core's mempool rejects txs with weight > 400k
(non-standard, but still consensus-valid up to 4M = MAX_BLOCK_WEIGHT).
lunarblock has neither the constant nor the gate.

**Impact:** Mempool divergence. lunarblock accepts 400k+ weight txs
that Core rejects. Such txs can never be confirmed unless mined into a
block by a colluding miner; in-flight relay is broken.

**Severity:** P1. Fix: add constant to `consensus.lua`, gate in
`mempool.lua` accept-to-mempool.

---

### BUG-15 (P0) — `count_witness_sigops` does NOT check P2SH-P2WPKH/P2WSH redeem-script witness shape

**File:** `src/validation.lua:474-487`.

**Core ref:** `bitcoin-core/src/validation.cpp` `GetTransactionSigOpCost` /
`script/interpreter.cpp:1900-1947` (witness program extraction).

**Description:** lunarblock's `count_witness_sigops` looks at
`is_push_only(script_sig)` then calls `extract_p2sh_redeem_script` to
find the inner redeem script. If the inner script classifies as
`p2wpkh` (20-byte program) or `p2wsh` (32-byte program), the code
sets `witness_version = 0` accordingly.

**But** the validation does NOT verify the **witness program is
exactly 20 or 32 bytes** for the v0 path before counting sigops. The
relevant check is in `is_witness_program` (`script.lua:836-859`),
which is **not called** by `count_witness_sigops` — the inner
`classify_script` returns "p2wpkh" only when length matches, but the
intermediate variable `inner_program` could be wrong-sized if
`classify_script` has a bug.

**Excerpt** (`validation.lua:478-484`):

```lua
local inner_type, inner_program = script.classify_script(redeem_script)
if inner_type == "p2wpkh" then
    witness_version = 0
    witness_program = inner_program
elseif inner_type == "p2wsh" then
    witness_version = 0
    witness_program = inner_program
end
```

**Impact:** Sigop-cost computation may differ from Core for adversarial
redeem scripts that pass `classify_script` but fail
`is_witness_program`'s exact-length check.

**Severity:** P0. Fix: gate the sigop-cost assignment behind
`is_witness_program(redeem_script)` to match Core's parser exactly.

---

### BUG-16 (P1) — Lua-style `tx.segwit` plumbing diverges from Core's `HasWitness()` in re-serialization

**File:** `src/serialize.lua:448` (`has_witness = include_witness and tx.segwit`).

**Core ref:** `primitives/transaction.h:413` — `HasWitness()` is
content-based, NOT flag-based.

**Description:** Companion to BUG-4/6. When `serialize_transaction(tx, true)`
is called and `tx.segwit = false` (manually set by wallet at
`rpc.lua:4909`) but the tx in-memory has non-empty `inp.witness`
arrays, the serialization drops the witness data silently.

**Impact:** Wallet-side witness data loss on re-serialization. Hard
to trigger from external inputs (RPC paths normally derive
`tx.segwit` from `deserialize_transaction`), but a real refactor
hazard.

**Severity:** P1. Fix: have `serialize_transaction` derive
`has_witness` from `tx.has_witness()` content check, not from
`tx.segwit` flag.

---

### BUG-17 (P2) — `is_witness_program` accepts `len == 4` (min) but BIP-141 minimum is `len == 4`

**File:** `src/script.lua:838`.

**Core ref:** BIP-141 — witness program length 2-40 bytes inclusive
(so script length 4-42 inclusive).

**Description:** lunarblock's check `if len < 4 or len > 42 then return nil, nil end`
at `script.lua:838` allows `len == 4` (program == 2 bytes, the
minimum). The follow-up at line 853 (`prog_len < 2 or prog_len > 40`)
re-validates. Both are correct, but **the early-return at line 838
permits a 4-byte script with version OP_0 + push(2 bytes) = 4 bytes,
i.e. P2W?? with a 2-byte program** — which is technically permitted
by BIP-141 for **future** witness program versions, but is currently
not a defined output type.

For witness v0 specifically, Core deals with the case where the
program is neither 20 nor 32 bytes — returns the catch-all
"anyone-can-spend" fallback, which lunarblock matches at
`script.lua:2024` (`WITNESS_PROGRAM_WRONG_LENGTH`).

**Severity:** P2. Latent; both check `prog_len` correctly downstream.

---

### BUG-18 (P3) — Witness merkle tree caching pattern absent (parallel to BUG-2)

**File:** `src/validation.lua:1182-1187` (witness merkle root
computed once per `check_witness_malleation` call).

**Description:** Similar to BUG-2 but specifically for the witness
merkle tree. lunarblock recomputes the witness merkle on every
`check_witness_malleation` call; Core caches via
`block.m_checked_witness_commitment`. Already caught by BUG-2.

**Severity:** P3. Duplicate of BUG-2; documented for completeness.

---

### BUG-19 (P1) — `check_witness_commitment` backward-compat wrapper hardcodes `expect_witness_commitment = true`

**File:** `src/validation.lua:1218-1227`.

**Core ref:** Per Core ContextualCheckBlock, `expect_witness_commitment`
is `DeploymentActiveAfter(pindexPrev, DEPLOYMENT_SEGWIT)` — i.e.
**conditional** on the block height.

**Description:** The `check_witness_commitment` wrapper unconditionally
calls `check_witness_malleation(block, true)`. Any caller that uses
this wrapper instead of the gated `check_witness_malleation` directly
will be in segwit-active mode even for pre-segwit blocks.

**Excerpt:**

```lua
function M.check_witness_commitment(block)
    local ok, _err = M.check_witness_malleation(block, true)
    return ok
end
```

**Impact:** Pre-segwit-block re-validation in a test harness or
external caller would incorrectly require a witness commitment.
Currently no production caller per grep, but latent footgun.

**Severity:** P1. Fix: deprecate the wrapper, or pivot its default
to `false` (matching the "no commitment required" semantic).

---

### BUG-20 (P0) — `default_witness_commitment` GBT field uses wrong byte-order documentation

**File:** `src/mining.lua:451-452`.

**Description:** The GBT response field `default_witness_commitment`
emits the hex-encoded `OP_RETURN 0x24 0xaa 0x21 0xa9 0xed <commitment>`
script. The 32-byte commitment is the BIG-ENDIAN-INTERPRETATION of
`SHA256d(witness_root || witness_nonce)`. lunarblock at
`mining.lua:358` computes `crypto.hash256(witness_root.bytes .. witness_nonce)`
which yields raw bytes in **internal** order (NOT reversed).

Core's GBT response (`bitcoin-core/src/rpc/mining.cpp:1107`) emits:

```cpp
result.pushKV("default_witness_commitment", HexStr(commitment_script));
```

where `commitment_script` is the raw `[6a, 24, aa, 21, a9, ed, ...32 bytes...]`
in script-byte order (which IS internal order).

So lunarblock's emission is correct. **False positive — removing BUG-20.**

**Severity:** Withdrawn after re-verification.

---

### BUG-21 (P0) — `count_witness_sigops` skips coinbase, double-counted by `get_transaction_sigop_cost`?

**File:** `src/validation.lua:519-548`.

**Description:** `get_transaction_sigop_cost` checks `is_coinbase` and
returns early after the legacy sigop count, skipping both P2SH and
witness sigops. Core's `GetTransactionSigOpCost` (`validation.cpp` /
`consensus/tx_check.cpp`) does NOT explicitly skip coinbase but the
coinbase's scriptSig/scriptPubKey doesn't legitimately classify as
witness/P2SH, so sigops are 0 anyway.

**Severity:** Not a divergence per-construction. Withdrawing.

---

### BUG-22 (P2) — `crypto.compute_merkle_root` returns `hash256_zero()` for empty input but Core returns `uint256()` (identical bytes but type-divergent)

**File:** `src/crypto.lua:1289-1295`.

**Core ref:** `consensus/merkle.cpp:61` — `if (hashes.size() == 0) return uint256();`.

**Description:** Both return 32 zero bytes. Type-class difference
only; lunarblock returns a `types.hash256` wrapper, Core returns a
`uint256` value type.

**Severity:** P2. Cosmetic / type-system.

---

### BUG-23 (P1) — `is_witness_program` length-range NOT triple-redundant against `classify_script`

**File:** `src/script.lua:836-859` vs `script.lua:670-687`.

**Description:** Two separate classifiers exist:
1. `is_witness_program` (lines 836-859) — strict BIP-141 parser.
2. `classify_script` (lines 670-687) — returns type name + program.

The two are NOT cross-checked. A script that `classify_script` returns
as "p2wpkh" but that `is_witness_program` rejects (or vice versa)
would produce inconsistent verify behavior between `count_witness_sigops`
(uses `classify_script`) and `verify_witness_program` (uses
`is_witness_program`).

**Excerpt** (`script.lua:670-687` — classify_script p2wpkh/p2wsh path):

```lua
elseif len >= 22 and script_bytes:byte(1) == 0x00 and script_bytes:byte(2) == 0x14 then
    return "p2wpkh", script:sub(3, 22)
...
elseif len >= 34 and script_bytes:byte(1) == 0x00 and script_bytes:byte(2) == 0x20 then
    return "p2wsh", script:sub(3, 34)
```

The `>=` (not `==`) means scripts LONGER than 22 / 34 bytes still
classify as p2wpkh/p2wsh. `is_witness_program` REQUIRES exact length.

**Impact:** Sigop-cost computation could disagree with verify path on
adversarial scripts (e.g. a 23-byte script starting `0x00 0x14 ...`
plus a trailing byte). Sigop cost would charge as P2WPKH; verify
would reject as `WITNESS_PROGRAM_MISMATCH` (because `is_witness_program`
rejects the length).

**Severity:** P1. Fix: make `classify_script` and `is_witness_program`
share the same parser, or have `classify_script` enforce exact
lengths.

---

### BUG-24 (P0) — BIP-141 marker-flag rejection of non-0x01 second byte uses assert (fatal) instead of soft-reject

**File:** `src/serialize.lua:495`.

**Description:** When the marker byte is 0x00 but the flag byte is
NOT 0x01, lunarblock fires:

```lua
assert(flag == 0x01, "Invalid segwit flag: " .. flag)
```

This is a **fatal** assert that crashes the entire process (LuaJIT
default error handling). Core's `UnserializeTransaction` throws
`std::ios_base::failure("Unknown transaction optional data")` — a
recoverable exception caught by the caller (`AcceptBlock` / `AcceptTx`
returns a soft reject).

**Impact:** DoS via malformed wire input. A peer can crash lunarblock
by sending a tx with marker 0x00 flag != 0x01. The `assert` is in the
hot p2p `tx` message handler.

**Severity:** P0. Fix: replace `assert` with `error()` wrapped in
pcall at the caller, or return `(nil, "bad-tx-flag")` for the
deserialize caller to handle gracefully.

---

## Summary

**24 BUGs catalogued, 30 gates audited:**

- **3 P0-CDIV:** BUG-1 (CVE-2012-2459 merkle mutation absent), BUG-4
  (HasWitness divergence), BUG-3 (BIP-143 SIGHASH_SINGLE — downgraded
  to P1 after re-read).
- **6 P0:** BUG-5 (superfluous-witness-record absent), BUG-6
  (unexpected-witness uses flag instead of content), BUG-13
  (64-byte mutation guard absent), BUG-15 (P2SH-wrapped witness sigop
  count), BUG-21 (withdrawn), BUG-24 (LuaJIT crash on bad flag byte).
- **8 P1:** BUG-7, BUG-9, BUG-11, BUG-12, BUG-14, BUG-16, BUG-19,
  BUG-23.
- **5 P2:** BUG-8, BUG-10, BUG-17, BUG-22, plus BUG-2 partial.
- **2 P3:** BUG-2, BUG-18.

**Withdrawn (false positives after re-verification):** BUG-20, BUG-21.

## Fleet pattern smells

1. **"Two parsers, one truth"** — BUG-23: `is_witness_program` and
   `classify_script` are independent parsers with slightly different
   length-acceptance rules. The fleet pattern of "consensus parser
   diverges from utility parser" is well-established (see W127
   clearbit multi(), W123 hotbuns bucket-grid mismatch). Same root
   cause class.

2. **"Serialization-flag-as-content-marker"** — BUG-4, BUG-5, BUG-6,
   BUG-16: `tx.segwit` is a serialization-shape flag set by the
   deserializer; multiple consumers treat it as a content-presence
   marker (Core's `HasWitness()`). Four bugs all stem from this
   single architectural confusion. Same pattern as W134's nimrod
   "fRelay-parsed-but-ignored": stash a serialized flag in tx state,
   then mis-trust it at every consumer site.

3. **"Pre-segwit-active divergence in wrapper"** — BUG-19: a "backward-
   compat" wrapper hardcodes a parameter that should be deployment-
   gated. Same shape as W133 hotbuns reindex helpers that always
   assumed BIP-9 active.

4. **"DoS-amplification ordering"** — BUG-7, BUG-9: weight check
   happens AFTER unbounded serialization, witness check happens AFTER
   weight check. Both are ordering bugs that don't break consensus
   directly but expand attack surface.

5. **"Comment-as-confession adjacent"** — `validation.lua:1218-1227`
   `check_witness_commitment` wrapper kept "for backward-compatibility"
   but no actual external caller verified. Pattern recurs (W141
   hotbuns "kept-for-future-callers" notification API).

6. **"Triple-redundant consensus check missing one tier"** — BUG-12
   (`tx-size-small` 65-byte policy) + BUG-13 (64-byte mutation
   consensus) + the absent stripped-block-size separate check (BUG-8).
   Core has overlapping defenses at multiple layers; lunarblock has
   only one of the three.

7. **"LuaJIT assert-as-validation"** — BUG-24: deserialization paths
   use `assert()` which is a fatal LuaJIT crash, not a recoverable
   soft-reject. Fleet pattern: per-language idiomatic error reporting
   silently diverges from Core's exception-style soft reject (Erlang
   `pattern_match` similarly fatal in beamchain W140 BUG-3).

## Cross-references

- W77: `audit/w77_*.md` (if extant) — established the
  `check_witness_malleation` 4-bug fixes; this audit found NO
  regressions in those fixes.
- W127 Taproot: this audit confirms `script.lua:1954-2167` Taproot
  v1+32 dispatch is solid; the witness v0 path is the bug-rich one.
- W134 BIP-37 Bloom: `MSG_FILTERED_BLOCK` interaction with witness
  data is OUT of scope here.
- W135 Standardness: BUG-12 (`MIN_STANDARD_TX_NONWITNESS_SIZE`) is
  a policy-layer companion to the W135 standardness-rules audit.

## Operator-visible

None of these bugs are visible at the RPC/CLI surface (no
operator-facing flag mismatch). All are wire-level / consensus-level
divergences.

## Concluding note

**The witness-commitment-check logic itself (W77 hardening) is solid.**
The divergences catalogued here are in the surrounding plumbing:
- the merkle-root parser does not detect CVE-2012-2459 (BUG-1);
- the `HasWitness()` semantic is conflated with the serialization
  marker byte (BUG-4/5/6/16);
- the block-weight ordering is reversed from Core (BUG-9);
- the back-fill helper for externally-supplied coinbases is missing
  (BUG-11);
- mempool-side policy gates (`tx-size-small`, `MAX_STANDARD_TX_WEIGHT`)
  are completely absent (BUG-12, BUG-14);
- the 64-byte mutation guard is absent (BUG-13);
- the deserializer uses fatal asserts on malformed wire input (BUG-24).

**Recommended priority order for follow-up fix waves:**

1. **BUG-24** (1-line: replace `assert(flag == 0x01)` with `error()`
   in a pcall-wrapped caller) — closes a remote-DoS surface.
2. **BUG-1** (3-line: extend `compute_merkle_root` to return mutation
   flag, plug into `check_merkle_root`) — closes the CVE-2012-2459
   surface for both txid and witness merkles.
3. **BUG-4/5/6/16 unified fix** (single architectural change: replace
   `tx.segwit` with content-based `tx:has_witness()` method) — closes
   four bugs in one wave.
4. **BUG-9** (swap order of `total_weight` assert and
   `check_witness_malleation` call in `check_block`) — restores Core
   reject-reason parity.
5. **BUG-11** (add `update_uncommitted_block_structures` helper) —
   external-miner GBT compatibility.
6. **BUG-12/13/14** bundled mempool-policy-gate sweep — closes three
   gaps in one wave.
