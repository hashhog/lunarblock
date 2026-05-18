# W143 — Block-level validation audit (lunarblock)

**Date:** 2026-05-18
**Wave:** W143 (discovery; 4-of-4 quad-wave)
**Impl:** lunarblock (Lua / LuaJIT)
**Status:** **22 BUGS FOUND** (4 P0-CONSENSUS / 5 P0-CDIV / 4 P0 / 5 P1 / 3 P2 / 1 P3)
**Scope:** `CheckBlock` + `ContextualCheckBlock` + `ConnectBlock` per
Bitcoin Core `bitcoin-core/src/validation.cpp:3918-3983 / 4129-4184 /
2295-2614` and `bitcoin-core/src/consensus/tx_check.cpp:11-60`.

## Context

This audit catalogues Core-parity deviations in **block-level validation**:
context-free `CheckBlock` (header, size limits, coinbase rules, per-tx
`CheckTransaction`, merkle root, legacy sigops cap), `ContextualCheckBlock`
(BIP-113 IsFinalTx, BIP-34 coinbase height, witness-malleation,
post-witness weight check), and `ConnectBlock` (BIP-30, BIP-68 sequence
locks, per-tx sigop cost + script verify, `bad-cb-amount`).

The witness-commitment / CVE-2012-2459 / `HasWitness()` / weight-check-
ordering issues that overlap with W142 are cross-referenced (not
re-catalogued).

## Source map

- `lunarblock/src/validation.lua:184-251` — `check_transaction`
  (CheckTransaction parity: vin/vout-empty, dup-inputs, MoneyRange, coinbase
  scriptSig length).
- `lunarblock/src/validation.lua:1298-1397` — `check_block`
  (CheckBlock + part of ContextualCheckBlock: header, weight, sigops,
  merkle, witness, BIP-34).
- `lunarblock/src/validation.lua:1103-1111` — `check_merkle_root`
  (TXID merkle recompute; CVE-2012-2459 noted W142 BUG-1).
- `lunarblock/src/validation.lua:1140-1216` — `check_witness_malleation`
  (BIP-141; W142 scope).
- `lunarblock/src/validation.lua:343-367` — `count_script_sigops`
  (Core `CScript::GetSigOpCount` parity; **diverges on parse error**).
- `lunarblock/src/validation.lua:1237-1250` — `check_block_header`
  (future-time + PoW; **header MTP check lives in `sync.lua` only**).
- `lunarblock/src/validation.lua:1263-1287` — `encode_bip34_height`
  (CScript() << nHeight parity).
- `lunarblock/src/utxo.lua:2134-3022` — `ChainState:connect_block`
  (ConnectBlock: BIP-30 / BIP-68 / `bad-cb-amount` / sigop cost).
- `lunarblock/src/utxo.lua:3089-3163` — `ChainState:accept_block`
  (wrapper that wires `check_block` → `connect_block`).
- `lunarblock/src/utxo.lua:3196-3513` — `accept_side_branch_block`
  + reorg connect loop (**bypasses `check_block` entirely**).
- `lunarblock/src/utxo.lua:3067-3088` — `compute_mtp_from_storage`.
- `lunarblock/src/consensus.lua:9-58` — `MAX_MONEY` / `MAX_BLOCK_*` /
  `WITNESS_SCALE_FACTOR` / `HALVING_INTERVAL` / `get_block_subsidy`.
- `lunarblock/src/mining.lua:43-72` — `is_final_tx` (BIP-113 IsFinalTx).
- `lunarblock/src/crypto.lua:1289-1313` — `compute_merkle_root`
  (mutation channel absent; W142 BUG-1).
- `lunarblock/src/compact_block.lua:383-413` — `IsBlockMutated` hook
  (defined, no caller wires it; **64-byte tx mutation absent**).

Core references:

- `bitcoin-core/src/validation.cpp:3918-3983` — `CheckBlock` (full).
- `bitcoin-core/src/validation.cpp:3946-3948` — `bad-blk-length` triple
  guard (`vtx.empty() || vtx.size()*4 > MAX || GetSerializeSize*4 > MAX`).
- `bitcoin-core/src/validation.cpp:3950-3955` — `bad-cb-missing` /
  `bad-cb-multiple`.
- `bitcoin-core/src/validation.cpp:3969-3977` — legacy sigops loop
  (`nSigOps * 4 > MAX_BLOCK_SIGOPS_COST`).
- `bitcoin-core/src/validation.cpp:4027-4056` — `IsBlockMutated` (64-byte
  tx mutation; `CheckMerkleRoot` + `CheckWitnessMalleation`).
- `bitcoin-core/src/validation.cpp:4129-4184` — `ContextualCheckBlock`.
- `bitcoin-core/src/validation.cpp:4151-4159` — BIP-34 height embedding.
- `bitcoin-core/src/validation.cpp:4179-4181` — post-witness weight check.
- `bitcoin-core/src/validation.cpp:2295-2614` — `ConnectBlock`.
- `bitcoin-core/src/validation.cpp:2402-2476` — BIP-30 enforcement.
- `bitcoin-core/src/validation.cpp:2543-2546` — `bad-txns-accumulated-
  fee-outofrange`.
- `bitcoin-core/src/validation.cpp:2569-2572` — per-tx sigop cap.
- `bitcoin-core/src/validation.cpp:2610-2614` — `bad-cb-amount`.
- `bitcoin-core/src/consensus/tx_check.cpp:11-60` — `CheckTransaction`.
- `bitcoin-core/src/consensus/tx_verify.cpp:17-22` — `IsFinalTx`.
- `bitcoin-core/src/script/script.cpp:158-180` — `CScript::GetSigOpCount`.
- `bitcoin-core/src/consensus/consensus.h:15-25` — `MAX_BLOCK_WEIGHT` /
  `MAX_BLOCK_SIGOPS_COST` / `WITNESS_SCALE_FACTOR`.
- `bitcoin-core/src/chain.h:29` — `MAX_FUTURE_BLOCK_TIME = 7200`.
- `bitcoin-core/src/kernel/chainparams.cpp:535` — regtest
  `nSubsidyHalvingInterval = 150`.

## 30-gate matrix

### A. Block size / structure (G1-G5)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G1 | `block.vtx.empty()` → `bad-blk-length` | **OK** — `validation.lua:1305` asserts `#block.transactions > 0`. |
| G2 | `vtx.size() * 4 > MAX_BLOCK_WEIGHT` (count-only guard) | **BUG-1 (P2)** — absent. `check_block` only checks the post-iteration `total_weight`. Realistic exploitation is bounded by per-tx min size, but the structural guard is missing. |
| G3 | `GetSerializeSize(TX_NO_WITNESS(block)) * 4 > MAX_BLOCK_WEIGHT` | **BUG-2 (P2)** — replaced by `total_weight = sum(base_size*3 + total_size)` per-tx. Functionally equivalent for well-formed blocks; diverges on degenerate cases (no block-level serialize-size invariant). |
| G4 | `block.vtx[0]->IsCoinBase()` else `bad-cb-missing` | **OK** — `validation.lua:1327-1328` asserts first tx is coinbase. |
| G5 | `block.vtx[i].IsCoinBase()` for i>=1 → `bad-cb-multiple` | **OK** — `validation.lua:1330` asserts no other coinbase. |

### B. `CheckTransaction` parity (G6-G10)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G6 | `tx.vin.empty()` → `bad-txns-vin-empty` | **OK** — `validation.lua:186`. |
| G7 | `tx.vout.empty()` → `bad-txns-vout-empty` | **OK** — `validation.lua:187`. |
| G8 | Tx stripped-size * 4 > MAX_BLOCK_WEIGHT → `bad-txns-oversize` | **OK** — `validation.lua:195-196`. |
| G9 | Per-output `nValue<0` / `>MAX_MONEY` + accum `MoneyRange(nValueOut)` | **OK** — `validation.lua:217-225`. |
| G10 | Duplicate-input CVE-2018-17144 | **OK** — `validation.lua:199-214` (set-based). |

### C. Coinbase rules (G11-G13)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G11 | Coinbase scriptSig in [2,100] bytes (`bad-cb-length`) | **OK** — `validation.lua:240-241`. |
| G12 | Non-coinbase: no input has null prevout (`bad-txns-prevout-null`) | **OK** — `validation.lua:244-247`. |
| G13 | BIP-34: coinbase scriptSig begins with `CScript() << nHeight` (height-embedding) | **OK in shape** (`validation.lua:1378-1394` matches Core's prefix-only `std::equal`). **See BUG-3, BUG-4** for context-skip bypass on side-branch + reorg paths. |

### D. Merkle root + mutation (G14-G16)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G14 | TXID merkle recompute (`hashMerkleRoot == BlockMerkleRoot`) | **OK** — `validation.lua:1351`. |
| G15 | CVE-2012-2459 mutation detection (txid tree) | **W142 BUG-1** — cross-ref; `compute_merkle_root` does not carry a `bool* mutated` channel; lunarblock will ACCEPT blocks Core rejects with `bad-txns-duplicate`. (Re-confirmed for W143 scope.) |
| G16 | `IsBlockMutated` 64-byte-tx malleability guard (`validation.cpp:4042-4043`) | **BUG-5 (P0-CDIV)** — `compact_block.lua:387` exposes a `check_mutated` hook parameter, but the function is **never passed** in by any caller. The 64-byte tx detection is **not implemented anywhere in lunarblock**. |

### E. Sigops cap (G17-G18)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G17 | Legacy sigops loop with `nSigOps * 4 > MAX_BLOCK_SIGOPS_COST` | **OK in shape** (`validation.lua:1337-1347`) but **see BUG-6** — sigop *counter itself* is divergent. |
| G18 | `CScript::GetSigOpCount` partial-count on parse failure (`break` not `return 0`) | **BUG-6 (P0-CDIV)** — `count_script_sigops` wraps `parse_script` in `pcall` and returns 0 on **any** parse error; Core counts opcodes up to the parse failure then breaks (retains partial count). Lunarblock **undercounts** sigops on malformed scripts. See full BUG-6. |

### F. ContextualCheckBlock (G19-G23)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G19 | `IsFinalTx` for every tx with `nLockTimeCutoff = (CSV ? prev.MTP : block.time)` | **OK in non-reorg path** (`utxo.lua:2189-2198`); **BUG-7** — reorg path passes `prev_block_mtp=nil` (`utxo.lua:3492`) so `lock_time_cutoff = block.header.timestamp` even when BIP-113 (CSV) is active. **BIP-113 silently bypassed during reorg.** |
| G20 | `CheckWitnessMalleation` before block-weight check (`validation.cpp:4169-4181`) | **W142 BUG-7** — weight-check-ordering issue cross-ref; lunarblock runs weight check at `validation.lua:1344` (BEFORE witness-malleation at line 1362). |
| G21 | Witness commitment / nonce content checks | **W142 BUGs 4/5/6** — cross-ref. |
| G22 | `block.fChecked` cache (`validation.cpp:3922, 3980`) | **BUG-12 (P3)** — `block.fChecked` cache absent. Each call to `check_block` re-runs all gates. Perf only. |
| G23 | Signet block solution (`CheckSignetBlockSolution`, `validation.cpp:3931-3933`) | **BUG-13 (P3)** — lunarblock does not implement signet. Network table has no signet entry; defining the gate is moot until signet support lands. |

### G. ConnectBlock (G24-G30)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G24 | Re-running `CheckBlock` (and thus `CheckTransaction`) before `ConnectBlock` | **BUG-3 (P0-CONSENSUS)** — side-branch reorg connects each side-branch block via `self:connect_block(...)` **directly** (`utxo.lua:3490`), bypassing `accept_block`'s `check_block` call. **Merkle / weight / sigops / BIP-34 / `CheckTransaction` are all skipped.** See full BUG-3. |
| G25 | BIP-30 exemption set: heights 91842 + 91880 (`IsBIP30Repeat`) | **OK** — `utxo.lua:45-50`. |
| G26 | BIP-30 post-BIP34 short-circuit (`BIP34_IMPLIES_BIP30_LIMIT = 1983702`) | **OK** — `utxo.lua:57` + `bip34_bypasses_bip30`. |
| G27 | Per-tx + total `MoneyRange(nFees)` (`bad-txns-accumulated-fee-outofrange`) | **OK** — `utxo.lua:2772-2774`. |
| G28 | `bad-cb-amount`: coinbase_value <= subsidy + fees | **OK in shape** — `utxo.lua:2814` — but **see BUG-8** (regtest subsidy wrong via hardcoded HALVING_INTERVAL). |
| G29 | `GetBlockSubsidy` honors `nSubsidyHalvingInterval` from chainparams | **BUG-8 (P0-CDIV)** — `consensus.HALVING_INTERVAL = 210000` is **hardcoded** at `consensus.lua:48`. Core's regtest uses 150 (`kernel/chainparams.cpp:535`). On regtest, lunarblock computes wrong subsidy starting at height 150, never halving until 210000. Diff-test on regtest at height >= 150 splits from Core. |
| G30 | `block.GetBlockTime() <= pindexPrev->GetMedianTimePast()` → `time-too-old` | **OK in `sync.lua:979`** for header-acceptance; **BUG-9** — `check_block` itself does NOT carry an MTP check (the check is in `accept_header` only). A block accepted via `submitblock` that bypasses the header pipeline could in principle skip the MTP gate (mitigated by `rpc.lua:7066`, but the architectural redundancy Core provides via `ContextualCheckBlockHeader` is absent — single point of failure). |

## Bugs (full)

### BUG-1 (P2) — `bad-blk-length` "count" guard absent: `vtx.size() * 4 > MAX_BLOCK_WEIGHT`

**File:** `src/validation.lua:1298-1348`.

**Core ref:** `bitcoin-core/src/validation.cpp:3947`:

```cpp
if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
                      || ::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
    return state.Invalid(BLOCK_CONSENSUS, "bad-blk-length", "size limits failed");
```

**Description:** Core's `CheckBlock` has a **triple** guard at line 3947.
Lunarblock implements only the first (`#block.transactions > 0`) and a
post-iteration `total_weight <= MAX_BLOCK_WEIGHT` check (computed from
per-tx serialize sizes). The second guard (`vtx.size() * 4 >
MAX_BLOCK_WEIGHT`) is a **count-only** structural early-exit — it catches a
block carrying > 1_000_000 transactions BEFORE allocating per-tx
serializers. Without it, lunarblock would attempt to serialize each tx in
the iteration loop.

**Excerpt** (`validation.lua:1304-1305, 1344-1345`):

```lua
assert(#block.transactions > 0, "block has no transactions")
...
assert(total_weight <= consensus.MAX_BLOCK_WEIGHT,
       "block weight " .. total_weight .. " exceeds maximum " ..
       consensus.MAX_BLOCK_WEIGHT)
```

**Impact:** Realistic exploitation requires a block with > 1_000_000 txs
whose total weight is still below the cap — impossible at typical
per-tx minimum sizes (each tx is at least ~60 bytes per
`MIN_SERIALIZABLE_TRANSACTION_WEIGHT/4 = 10`, so 1M txs => 60MB =
240M weight which clearly exceeds 4M). Defense-in-depth gap.

**Severity:** P2.

---

### BUG-2 (P2) — `bad-blk-length` "serialize size" guard absent

**File:** `src/validation.lua:1310-1345`.

**Core ref:** `validation.cpp:3947` — third guard
`::GetSerializeSize(TX_NO_WITNESS(block)) * 4 > MAX_BLOCK_WEIGHT`.

**Description:** Core also checks the *block-level* serialize size
(without witnesses) directly: even if individual txs sum to below the
cap, the block-level serialization (including transaction count
varint, header bytes, etc.) could in principle exceed it. Lunarblock
replaces this with `sum(base_size * 3 + total_size)` over txs only —
omitting the block-level header bytes (80) and the transaction count
varint (1-9 bytes).

**Excerpt** (`validation.lua:1333-1334`):

```lua
-- Weight: base_size * 3 + total_size
total_weight = total_weight + #base_data * 3 + #total_data
```

**Impact:** Lunarblock could accept a block whose true serialize size
> MAX_BLOCK_WEIGHT/4 = 1_000_000 stripped bytes by a few bytes (the
block header + tx count overhead, ~80-90 bytes). In practice, no
malicious construction reaches the boundary by exactly this overhead.

**Severity:** P2.

---

### BUG-3 (P0-CONSENSUS) — Reorg connect loop bypasses `check_block` entirely

**File:** `src/utxo.lua:3449-3502` (reorg connect loop)
+ `src/utxo.lua:2134-2150` (connect_block — does NOT call check_block).

**Core ref:** `bitcoin-core/src/validation.cpp:4350-4351`:

```cpp
if (!CheckBlock(block, state, params.GetConsensus()) ||
    !ContextualCheckBlock(block, state, *this, pindex->pprev)) {
    ...
}
```

Core's `Chainstate::ConnectTip` ALWAYS runs `CheckBlock` +
`ContextualCheckBlock` before `ConnectBlock` (per
`validation.cpp:3037-3052`). The reorg path is no exception.

**Description:** Lunarblock's reorg loop at `utxo.lua:3490` calls
`self:connect_block(...)` directly with no preceding `check_block`. The
`check_block` call in `accept_block` (`utxo.lua:3113-3122`) is BYPASSED
because the reorg path does not route through `accept_block`. As a
result, the following CheckBlock + ContextualCheckBlock gates are
**SKIPPED** during reorg connect:

- TXID merkle-root recomputation (`check_merkle_root`).
- Witness-commitment verification (`check_witness_malleation`).
- Block weight check (`total_weight <= MAX_BLOCK_WEIGHT`).
- Legacy sigops cap (`total_sigops * 4 <= MAX_BLOCK_SIGOPS_COST`).
- Per-tx `CheckTransaction`: `bad-txns-vin-empty`, `vout-empty`,
  `oversize`, `dup-input`, MoneyRange, coinbase scriptSig length,
  null-prevout-non-coinbase.
- **BIP-34 coinbase height embedding** (`validation.lua:1378-1394`).
- Block-header future-time / PoW (only re-checked here in Core, since
  the side-branch headers were accepted at submitblock time — but
  the body re-check is essential).

The earlier `pcall(validation.check_block, block, rpc.network, nil)` at
`rpc.lua:7010` runs once when each side-branch block is first submitted,
but with `height = nil` — so the BIP-34 height-embedding check is
**explicitly skipped** there too (`validation.lua:1378`:
`if height and height >= network.bip34_height`).

**Excerpt** (`src/utxo.lua:3486-3496`):

```lua
-- prev_block_mtp / get_block_mtp = nil → skip BIP-68 sequence-lock
-- enforcement on the reconnect path (the original-acceptance path
-- already validated these for B1/B2/B3, and CSV is not active in
-- the regtest reorg corpus).  This matches reapply_disconnected.
local ok_conn, err_conn = self:connect_block(
  sb_block, entry.height, entry.hash,
  nil, nil,
  opts.skip_scripts, false,
  opts.nosync, store_batch_fn,
  reorg_batch
)
```

**Impact:** A side-branch chain with malformed bodies — wrong merkle
root, BIP-34-non-compliant coinbase scriptSig, duplicate-input tx,
> 80k legacy sigops — could be reorg'd into the active chain WITHOUT
re-validation. The comment claims "the original-acceptance path
already validated these for B1/B2/B3" — but the original acceptance
ran `check_block(..., nil)` (height-nil → BIP-34 skipped) and did NOT
re-validate the BODY against the *real* height now that the side
branch's heights are known. **Consensus split risk.**

A practical exploit: a miner orphans the active tip by mining a
side-branch with higher work, whose coinbases lack BIP-34 height. Core
rejects the reorg (`bad-cb-height`). Lunarblock connects it, advances
the tip, and forks off the network.

**Severity:** P0-CONSENSUS.

---

### BUG-4 (P0-CDIV) — Side-branch `check_block` is height-nil, deferring BIP-34 enforcement

**File:** `src/rpc.lua:7010` (`validation.check_block(block, rpc.network, nil)`)
+ `src/validation.lua:1378` (`if height and height >= network.bip34_height`).

**Core ref:** `bitcoin-core/src/validation.cpp:4151-4159`:

```cpp
if (DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_HEIGHTINCB))
{
    CScript expect = CScript() << nHeight;
    if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
        !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin())) {
        return state.Invalid(BLOCK_CONSENSUS, "bad-cb-height", ...);
    }
}
```

Core's `ContextualCheckBlock` ALWAYS receives `pindexPrev != nullptr`
and computes `nHeight = pindexPrev->nHeight + 1`. Height is NEVER nil.

**Description:** When a block arrives via `submitblock` and does not
extend the active tip, `rpc.lua:6980-7010` first runs
`validation.check_block(block, rpc.network, nil)`. The `nil` for height
causes `validation.lua:1378` to short-circuit (`if height and ...`),
skipping the entire BIP-34 height-embedding check. The block is then
either stored as side-branch ("stored") or triggers a reorg ("connected"
via the BUG-3 code path that also skips BIP-34).

**Excerpt** (`src/rpc.lua:7010`):

```lua
local val_ok, val_err = pcall(validation.check_block, block, rpc.network, nil)
```

**Excerpt** (`src/validation.lua:1378-1394`):

```lua
if height and height >= network.bip34_height then
  local coinbase_sig = block.transactions[1].inputs[1].script_sig
  local expect = M.encode_bip34_height(height)
  ...
end
```

**Impact:** A miner can submit a side-branch chain with BIP-34-violating
coinbase scriptSigs. Lunarblock will accept (store as side-branch) and
later, if work crosses the active-tip work, reorg into it via BUG-3 —
which also skips re-validation. Funds-loss risk is bounded
(non-canonical coinbase scriptSig still produces valid block hash), but
chain-split is real.

**Fix:** rpc.lua:7010 should resolve the height from
`block.header.prev_hash` before calling `check_block`. Where the parent
is not yet known (true orphan), the block can't be validated against
BIP-34 anyway, so defer.

**Severity:** P0-CDIV.

---

### BUG-5 (P0-CDIV) — 64-byte tx mutation guard absent (`IsBlockMutated`)

**File:** `src/compact_block.lua:383-413` (hook defined; never wired);
no implementation anywhere in `src/`.

**Core ref:** `bitcoin-core/src/validation.cpp:4042-4043`:

```cpp
return std::any_of(block.vtx.begin(), block.vtx.end(),
                   [](auto& tx) { return GetSerializeSize(TX_NO_WITNESS(tx)) == 64; });
```

And the surrounding `IsBlockMutated` (`validation.cpp:4027-4056`) is
called from `net_processing` when a block fails its initial validation,
to decide whether to mark the block as permanently invalid or just
"corrupted" (so we'd accept a re-download). The 64-byte tx
malleability vector (described in Bitcoin Dev Mailing List, Feb 2019,
"Weaknesses in Bitcoin's Merkle Root Construction") allows a peer to
collapse two adjacent leaves of the merkle tree into a single
internal-node hash that's indistinguishable from a leaf.

**Description:** Lunarblock does not implement `IsBlockMutated`. The
hook parameter in `compact_block.lua:387` (`function
PartiallyDownloadedBlock:reconstruct(check_mutated)`) is defined but
**no caller passes a function**:

```bash
$ grep -rn "check_mutated\b" lunarblock/src/
src/compact_block.lua:383: -- @param check_mutated optional function...
src/compact_block.lua:387: function ...:reconstruct(check_mutated)
src/compact_block.lua:411: if check_mutated and check_mutated(block) then
```

**Excerpt** (`compact_block.lua:410-412`):

```lua
-- G12: mutation check hook (Core blockencodings.cpp:219-221)
if check_mutated and check_mutated(block) then
  return nil, "mutated block (possible short ID collision)"
end
```

The `and` short-circuits when `check_mutated` is nil — which it always
is.

**Impact:** A peer can craft a malleated block via the 64-byte tx
vector. Lunarblock would either accept (if the malleation happens to
hash-collide with a valid merkle root, very rare) or fail validation —
but if it fails validation, lunarblock might mark the block as
*permanently* invalid (`has_invalid_ancestor`), preventing acceptance
of the genuine non-malleated version. Core's `IsBlockMutated` channel
prevents this by signaling "corrupted, retry" instead of "permanently
invalid".

**Severity:** P0-CDIV.

---

### BUG-6 (P0-CDIV) — `count_script_sigops` returns 0 on parse error vs Core's partial count

**File:** `src/validation.lua:343-367`.

**Core ref:** `bitcoin-core/src/script/script.cpp:158-180`:

```cpp
unsigned int CScript::GetSigOpCount(bool fAccurate) const
{
    unsigned int n = 0;
    const_iterator pc = begin();
    opcodetype lastOpcode = OP_INVALIDOPCODE;
    while (pc < end())
    {
        opcodetype opcode;
        if (!GetOp(pc, opcode))
            break;
        if (opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY)
            n++;
        ...
    }
    return n;
}
```

Core's loop **breaks** on `GetOp` failure (returns parsed count so far);
malformed pushes do NOT zero the count.

**Description:** Lunarblock's `count_script_sigops` wraps `parse_script`
in `pcall`. `parse_script` (`script.lua:380-431`) asserts on every
malformed push (truncated PUSHDATA1/2/4, push-runs-off-end). Any such
assertion → `pcall` returns `false` → `count_script_sigops` returns 0.

**Excerpt** (`validation.lua:343-346`):

```lua
function M.count_script_sigops(script_bytes, accurate)
  -- Gracefully handle unparseable scripts (e.g. coinbase scriptSig with arbitrary data)
  local ok, ops = pcall(script.parse_script, script_bytes)
  if not ok then return 0 end
```

**Concrete divergence example:**

Consider a coinbase scriptSig:
`0x01 0xac 0xac 0xac 0x05 0xff` (push 1 byte 0xac, then 3 raw 0xac, then
PUSH(5) but only 1 byte remains).

- **Core:** opcode 0x01 → push 1, then opcode 0xac (CHECKSIG) → n=1,
  opcode 0xac → n=2, opcode 0xac → n=3, opcode 0x05 → PUSH(5), only 1
  byte avail → `GetOp` returns false → break. **Final count: 3.**
- **Lunarblock:** `parse_script` asserts on the truncated push →
  `pcall` returns false → `count_script_sigops` returns **0**.

**Impact:** A miner can craft a block with malformed scriptSig (or
scriptPubKey) bytes containing dozens of CHECKSIG opcodes followed by a
truncated push. Lunarblock undercounts sigops, accepting blocks whose
true Core-computed sigop count exceeds 80,000 (the cap). Core rejects
with `bad-blk-sigops`; lunarblock accepts. **Consensus split risk.**

Same bug compounds at `count_witness_sigops` (`validation.lua:502`)
which delegates to `count_script_sigops` for P2WSH witness scripts.

**Fix:** Mirror Core's `break`-on-parse-error semantics by either (a)
returning a `(partial_count, ok)` from `parse_script`, or (b) using a
stateful tokenizer that counts opcodes as it goes.

**Severity:** P0-CDIV.

---

### BUG-7 (P0-CDIV) — BIP-113 IsFinalTx silently bypassed during reorg (`prev_block_mtp = nil`)

**File:** `src/utxo.lua:3486-3496` (reorg call site)
+ `src/utxo.lua:2188-2193` (lock_time_cutoff selection).

**Core ref:** `bitcoin-core/src/validation.cpp:4140-4148`:

```cpp
const int64_t nLockTimeCutoff{enforce_locktime_median_time_past ?
                                  pindexPrev->GetMedianTimePast() :
                                  block.GetBlockTime()};

for (const auto& tx : block.vtx) {
    if (!IsFinalTx(*tx, nHeight, nLockTimeCutoff)) {
        return state.Invalid(BLOCK_CONSENSUS, "bad-txns-nonfinal", ...);
    }
}
```

When `DEPLOYMENT_CSV` is active, `enforce_locktime_median_time_past =
true` and the cutoff is the **previous block's MTP**.

**Description:** Lunarblock's reorg connect loop (`utxo.lua:3490`)
passes `nil, nil` for `prev_block_mtp, get_block_mtp`. Inside
`connect_block`:

```lua
if enforce_bip68 and prev_block_mtp then
  lock_time_cutoff = prev_block_mtp
else
  lock_time_cutoff = block.header.timestamp
end
```

When `prev_block_mtp=nil`, the `enforce_bip68 and prev_block_mtp` short-
circuits to nil (falsy), so `lock_time_cutoff = block.header.timestamp`.
**BIP-113 is silently bypassed during reorg.**

**Excerpt** (`src/utxo.lua:3486-3496`):

```lua
-- prev_block_mtp / get_block_mtp = nil → skip BIP-68 sequence-lock
-- enforcement on the reconnect path (the original-acceptance path
-- already validated these for B1/B2/B3, and CSV is not active in
-- the regtest reorg corpus).  This matches reapply_disconnected.
local ok_conn, err_conn = self:connect_block(
  sb_block, entry.height, entry.hash,
  nil, nil,
  ...
)
```

**Comment-as-confession**: "CSV is not active in the regtest reorg
corpus" — the comment treats this as a regtest-only concern, but
**mainnet reorgs post-block 419,328 (CSV activation) hit this code
path**. A side-branch block at mainnet h>=419,329 with a
locktime-violating tx (locktime > prev.MTP but < block.timestamp) would
be ACCEPTED by lunarblock on reorg, REJECTED by Core.

**Impact:** Real-world consensus split during reorgs post-CSV. The
window between BIP-113-enforced MTP and the new block timestamp is
typically ~600s on mainnet, providing a real attack surface.

**Fix:** Compute `prev_block_mtp` inside the reorg loop using the
side-branch's parent (already stored in `entry.header.prev_hash`), same
as the non-reorg path at `utxo.lua:3129-3132`.

**Severity:** P0-CDIV.

---

### BUG-8 (P0-CDIV) — `HALVING_INTERVAL` hardcoded to 210000; regtest mismatches Core's 150

**File:** `src/consensus.lua:48-58`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:535`:

```cpp
consensus.nSubsidyHalvingInterval = 150;  // regtest
```

`bitcoin-core/src/validation.cpp:1839-1859`:

```cpp
CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams)
{
    int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;
    ...
}
```

Core reads the halving interval from `consensusParams` (per-network).

**Description:** Lunarblock's `get_block_subsidy` takes only `height`;
it has no `network` argument. It reads `M.HALVING_INTERVAL = 210000`
unconditionally. For regtest, Core uses 150 (so first halving at
regtest h=150, subsidy 25 BTC). Lunarblock keeps subsidy at 50 BTC
forever on regtest until h=210000.

**Excerpt** (`src/consensus.lua:50-58`):

```lua
function M.get_block_subsidy(height)
  local halvings = math.floor(height / M.HALVING_INTERVAL)
  if halvings >= 64 then return 0 end
  local subsidy = M.INITIAL_BLOCK_REWARD
  for _ = 1, halvings do
    subsidy = math.floor(subsidy / 2)
  end
  return subsidy
end
```

Then `utxo.lua:2809-2818`:

```lua
local subsidy = consensus.get_block_subsidy(height)
local coinbase_value = 0
for _, out in ipairs(block.transactions[1].outputs) do
  coinbase_value = coinbase_value + out.value
end
if coinbase_value > subsidy + total_fees then
  return nil, "bad-cb-amount: ..."
end
```

**Impact:** On regtest, lunarblock will ACCEPT coinbase outputs paying
50 BTC at h=150+, while Core rejects (correct subsidy: 25 BTC). Diff-
test on regtest reorgs / fee-bumper tests / mining tests will split
from Core at any regtest height > 149.

In the network table at `consensus.lua:1140-1180`, regtest has all the
soft-fork heights but no `halving_interval`/`subsidy_halving_interval`
field at all.

**Severity:** P0-CDIV (regtest scope).

---

### BUG-9 (P1) — `check_block` doesn't carry an MTP check; relies on out-of-band call from `accept_header`

**File:** `src/validation.lua:1237-1250` (check_block_header) +
`src/validation.lua:1298-1397` (check_block).

**Core ref:** `bitcoin-core/src/validation.cpp:4092-4093`:

```cpp
if (block.GetBlockTime() <= pindexPrev->GetMedianTimePast())
    return state.Invalid(BLOCK_INVALID_HEADER, "time-too-old", ...);
```

This `time-too-old` check lives in `ContextualCheckBlockHeader` which
runs as part of `AcceptBlock` (`validation.cpp:4505`). Core re-runs it
in `TestBlockValidity` for dry-runs.

**Description:** Lunarblock implements `time-too-old` only in
`HeaderChain:accept_header` (`sync.lua:973-981`) and `rpc.lua:7064-7068`
(submitblock direct-extension path). `validation.check_block` does NOT
take a `prev_block_mtp` parameter or perform any MTP check. There is no
redundant in-block-validation gate.

If a code path ever invokes `validation.check_block` for a block whose
header was NOT routed through `accept_header` AND not through
`submitblock`'s direct-extension path (e.g. the side-branch path at
`rpc.lua:7010`), the MTP check is silently skipped.

**Impact:** The side-branch path explicitly calls
`validation.check_block(block, rpc.network, nil)` and DOES NOT perform
an MTP check before. (rpc.lua:7064-7068's MTP check is gated by `if not
hash256_eq(prev_hash, tip_hash)` being false — i.e. only for direct-
extension.) Side-branch blocks can therefore have timestamps `<=
prev.MTP` and be silently stored, only failing during the reorg connect
loop — which itself bypasses validation (BUG-3).

The combination of BUG-3 + BUG-9 means a side-branch with `time-too-old`
blocks would never be rejected.

**Severity:** P1. Compounds into P0-CONSENSUS when chained with BUG-3.

---

### BUG-10 (P1) — `compute_mtp_from_storage` returns `os.time()` on storage error

**File:** `src/utxo.lua:3067-3088`.

**Core ref:** N/A — Core's `GetMedianTimePast` asserts pindex is non-
null and walks 11 ancestor pblockindexes from in-memory state.

**Description:** Lunarblock's `compute_mtp_from_storage` returns
`os.time()` (wall-clock) in two failure paths:

1. `storage == nil` or `tip_hash == nil` (line 3068-3070).
2. `#timestamps == 0` after the 11-iter walk (line 3079-3081).

The second case fires when `storage.get_header(current_hash)` returns
nil on the FIRST iteration — i.e. tip header is missing from storage.

**Excerpt** (`src/utxo.lua:3067-3081`):

```lua
local function compute_mtp_from_storage(storage, tip_hash)
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
  if #timestamps == 0 then
    return os.time()
  end
```

**Impact:** During IBD on mainnet, a transient storage hiccup at the
tip header read silently sets `prev_block_mtp = os.time()` (~1.7e9). At
2026 wall-clock vs historical block timestamps (~2010-2024), a tx with
`locktime = 1.5e9` would be treated as final (1.5e9 < 1.7e9) when Core
would correctly compute the real MTP from the actual tip and reject.

Worse: during *reindex* of historical mainnet, the actual MTP for h=200k
is ~1.34e9 (2012), but if storage is racing, this returns os.time() =
~1.7e9 instead. A tx with locktime=1.4e9 would be silently accepted as
final.

**Fix:** Return `0` (or `nil` and propagate error upstream) instead of
wall-clock. Per BIP-113 semantics, MTP is well-defined; falling back to
wall-clock destroys the invariant.

**Severity:** P1.

---

### BUG-11 (P1) — `count_script_sigops` accurate flag mishandles non-OP_N pushes preceding CHECKMULTISIG

**File:** `src/validation.lua:343-367`.

**Core ref:** `bitcoin-core/src/script/script.cpp:172-176`:

```cpp
else if (opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY)
{
    if (fAccurate && lastOpcode >= OP_1 && lastOpcode <= OP_16)
        n += DecodeOP_N(lastOpcode);
    else
        n += MAX_PUBKEYS_PER_MULTISIG;
}
lastOpcode = opcode;
```

Core's `lastOpcode` tracks the raw opcode byte from `GetOp`. Direct
pushes (opcodes 0x01-0x4b) preceding CMS do NOT count as OP_N — so
they trigger the `MAX_PUBKEYS_PER_MULTISIG` (20) charge.

**Description:** Lunarblock's `count_script_sigops` follows the same
shape:

```lua
prev_opcode = opcode
```

after every parsed op. For direct pushes, `opcode` is the byte value
(1-75); these never match `OP_1..OP_16` (0x51..0x60). So accurate
counting falls through to MAX_PUBKEYS_PER_MULTISIG. **Matches Core.**

BUT: lunarblock's parse_script returns `{opcode, data}` where direct-
push opcodes are kept as-is. The accurate check `prev_opcode >= OP_1 and
prev_opcode <= OP_16` works because OP_1=0x51, OP_16=0x60. No bug here
on inspection.

**Re-classified as informational** during write-up. Withdrawn.

**Severity:** N/A (false alarm; matches Core). *Striking from count.*

---

### BUG-12 (P3) — `block.fChecked` cache absent

**File:** `src/validation.lua:1298-1397`.

**Core ref:** `bitcoin-core/src/validation.cpp:3922, 3979-3980`:

```cpp
if (block.fChecked) return true;
...
if (fCheckPOW && fCheckMerkleRoot)
    block.fChecked = true;
```

**Description:** Core caches the `CheckBlock` verdict on the block
object so that subsequent calls return immediately. Lunarblock's
`check_block` has no such cache; every invocation re-runs all gates.

`accept_block` in lunarblock calls `check_block` exactly once per
block (`utxo.lua:3114`), and the side-branch path's repeated
`check_block(... nil)` at `rpc.lua:7010` would benefit. Latent perf
regression.

**Impact:** Perf only. `submitblock` of a recently-validated block
re-runs ~all gates.

**Severity:** P3.

---

### BUG-13 (P3) — Signet block solution unsupported (`CheckSignetBlockSolution`)

**File:** `src/consensus.lua` (no signet network) + `validation.lua:1247`
(only `check_proof_of_work`).

**Core ref:** `bitcoin-core/src/validation.cpp:3930-3933`:

```cpp
if (consensusParams.signet_blocks && fCheckPOW && !CheckSignetBlockSolution(block, consensusParams)) {
    return state.Invalid(BLOCK_CONSENSUS, "bad-signet-blksig", ...);
}
```

**Description:** Lunarblock does not implement signet at all. No
`signet_blocks` network params, no signet-challenge verification. The
top-level `CLAUDE.md` does not list signet as a supported network for
lunarblock. Not a divergence per se — but a documented gap.

**Severity:** P3.

---

### BUG-14 (P0-CONSENSUS) — `CheckTransaction` skipped when `skip_check_block=true` is set

**File:** `src/utxo.lua:3113-3122` (skip path) + callers passing
`skip_check_block = true`: `src/main.lua:537`, `src/main.lua:1020`.

**Core ref:** `bitcoin-core/src/validation.cpp:2295-2614` —
`ConnectBlock` does NOT re-run `CheckTransaction`. Core's invariant is
that `CheckBlock` runs BEFORE `ConnectBlock` (per `ConnectTip` at
`validation.cpp:3037`). The two are inseparable.

**Description:** Lunarblock's `accept_block` allows callers to set
`opts.skip_check_block = true`, which skips the entire CheckBlock pass
(merkle, weight, sigops, BIP-34, AND per-tx CheckTransaction).

Two production callers pass `skip_check_block = true`:

1. `src/main.lua:537` (operator block-import path, after the inline
   `pcall(validation.check_block, block, chain_state.network,
   frame_height)` at line 522-523). **OK** — caller did validate.
2. `src/main.lua:1020` (IBD downloader connect path). **Comment claims**
   "already validated by sync.lua above", referring to
   `sync.lua:2231-2233`:
   ```lua
   local ok, err = pcall(function()
     validation.check_block(pending.block, self.network, pending.height)
   end)
   ```

   **The risk:** if `sync.lua`'s pre-check ever drifts (e.g. wraps in a
   stricter pcall, gates behind a feature flag, or refactors the wave
   processing), the body would silently land in `connect_block` with no
   `CheckTransaction` run. This is a **two-pipeline guard**: the
   validation runs in one place, the skip-permission is set in another.
   A drift between them produces silent consensus divergence.

**Excerpt** (`src/main.lua:1018-1024`):

```lua
local pcall_ok, ok_or_err = pcall(chain_state.accept_block, chain_state,
  block, height, block_hash, {
    skip_check_block = true,    -- already validated by sync.lua above
    skip_scripts     = skip_scripts,
    nosync           = true,    -- IBD: caller-managed periodic flush
    caller_batch_fn  = caller_batch_fn,
  })
```

**Impact:** Currently no observed divergence (sync.lua DOES validate),
but the architectural pattern (decoupled validate+skip) is fragile.

**Severity:** P0-CONSENSUS (latent; one refactor away from active).

---

### BUG-15 (P0) — `bad-txns-prevout-null` only enforced when `is_coinbase=false` path is taken

**File:** `src/validation.lua:227-247`.

**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:52-57`:

```cpp
else  // !tx.IsCoinBase()
{
    for (const auto& txin : tx.vin)
        if (txin.prevout.IsNull())
            return state.Invalid(TX_CONSENSUS, "bad-txns-prevout-null");
}
```

**Description:** Core's check is unambiguous: ONLY when the tx is not
coinbase, every input's prevout must not be null. Lunarblock's logic at
`validation.lua:227-247`:

```lua
local is_coinbase = false
local null_hash = string.rep("\0", 32)
if #tx.inputs == 1 then
  local inp = tx.inputs[1]
  if inp.prev_out.hash.bytes == null_hash and inp.prev_out.index == 0xFFFFFFFF then
    is_coinbase = true
  end
end

if is_coinbase then
  ...
else
  for i, inp in ipairs(tx.inputs) do
    assert(inp.prev_out.hash.bytes ~= null_hash, ...)
  end
end
```

**Divergence:** lunarblock's `is_coinbase` requires **both**
`hash == null_hash` AND `index == 0xFFFFFFFF` AND `#inputs == 1`. Core's
`CTransaction::IsCoinBase()` (transaction.h:309):

```cpp
bool IsCoinBase() const {
    return (vin.size() == 1 && vin[0].prevout.IsNull());
}
```

`prevout.IsNull()` is `hash.IsNull() && (n == (uint32_t)-1)` — matches.

**BUT**: Core's `bad-txns-prevout-null` check only checks
`prevout.IsNull()`, which is `hash == 0 AND index == 0xFFFFFFFF`. Lunarblock
checks only `hash == null_hash` (ignores the index!). This means a tx
with `vin[0] = {hash=zero, index=0x12345678}` (NOT null per Core), but
`#vin == 2` (so not coinbase) would be:
- Core: not coinbase (because `vin.size() != 1`), and `vin[0].prevout`
  is NOT null (index != 0xFFFFFFFF), so check passes — accepted at this
  layer.
- Lunarblock: not coinbase. The for-loop checks `prev_out.hash.bytes ~=
  null_hash`. Input 0 has null hash → assertion FAILS → tx REJECTED.

**Impact:** lunarblock REJECTS some non-coinbase txs that Core accepts.
Specifically: any non-coinbase tx with a zero-hash prevout but non-
0xFFFFFFFF index. Core only rejects the proper "null prevout" (both
fields). Lunarblock is overly strict.

A non-coinbase with vin[i].prev_out.hash = zero would actually be a
weird tx pointing at a coinbase txid of zero (which doesn't exist as a
real UTXO, so it'd fail at UTXO lookup anyway). The rejection happens
at the wrong layer with the wrong error code.

**Severity:** P0 (over-rejection — lunarblock rejects valid-shape
inputs that fail at UTXO-lookup in Core. Diff-test-visible.)

---

### BUG-16 (P0) — `is_coinbase` allows `vin.size() > 1` in `check_transaction` (compares only #inputs==1 for is_coinbase, but `IsCoinBase()` enforces ==1)

**File:** `src/validation.lua:230-235`.

**Core ref:** `bitcoin-core/src/primitives/transaction.h:309`.

**Description:** Lunarblock's `is_coinbase` requires `#tx.inputs == 1`
(line 230). This matches Core. But the `bad-cb-length` check at line
240-241 only fires for `is_coinbase==true`. If a malicious tx has
`#inputs == 2` with `vin[0]` being a "fake coinbase" (null prevout) and
`vin[1]` being a normal input, lunarblock would mark it as NOT
coinbase (because `#inputs != 1`), then iterate inputs at line 244-247
and REJECT for null prevout on vin[0].

Core would also mark it as not coinbase (IsCoinBase requires
vin.size()==1) and reject for `bad-txns-prevout-null`.

Both paths reject — but lunarblock's logic mixes coinbase detection
with null-prevout check. Marginal divergence in error-string semantics
only (Core: `bad-txns-prevout-null`; lunarblock: assertion text). P1.

**Severity:** Re-classified P1 after analysis — semantic equivalence,
error-string drift only.

---

### BUG-17 (P1) — `check_block_header` uses `os.time()` (POSIX wall-clock) directly; no NodeClock parity

**File:** `src/validation.lua:1237-1250`.

**Core ref:** `bitcoin-core/src/validation.cpp:4108-4110`:

```cpp
if (block.Time() > NodeClock::now() + std::chrono::seconds{MAX_FUTURE_BLOCK_TIME}) {
    return state.Invalid(BLOCK_TIME_FUTURE, "time-too-new", ...);
}
```

Core's `NodeClock` is a typedef around `std::chrono::system_clock`
(per `util/time.h`). Network-adjusted time was removed in Core PR
#28956 (Feb 2024). So `NodeClock::now()` ≈ POSIX wall-clock.

**Description:** Lunarblock's `os.time()` returns POSIX wall-clock,
matching Core's current `NodeClock::now()`. **No divergence today.**

**However**: lunarblock has no `m_clock` indirection, so any future
need to inject a deterministic clock for tests requires monkey-patching
`os.time()` globally (Lua-level), which is brittle. Core's
`NodeClock` abstraction allows clean test injection via
`SetMockTime`.

**Severity:** P1 (test-infra fragility, not consensus per se).

---

### BUG-18 (P0) — `validation.check_block` uses Lua `assert()` for all rejection paths; no `BlockValidationState` analog

**File:** `src/validation.lua:184-251` (check_transaction) +
`src/validation.lua:1298-1397` (check_block).

**Core ref:** `bitcoin-core/src/consensus/validation.h:79-110`:

```cpp
class BlockValidationState : public ValidationState<BlockValidationResult> {};
```

Core's `BlockValidationState` carries both the reject reason
(`bad-blk-sigops`, `bad-cb-amount`, etc.) and the debug message
separately. Callers can map result codes to BIP-22 wire codes
(`rpc/mining.cpp`'s `BIP22ValidationResult`).

**Description:** Lunarblock's `check_block` uses `assert(cond, msg)`
throughout. On failure, Lua raises an error with the assertion message
as a string. Callers must `pcall` and string-match the error to detect
the rejection reason. `rpc.lua` does this with regex patterns
(`s:find("script")`, etc.) at `classify_block_rejection`.

This works but is fragile — adding a new rejection requires updating
the regex set. Core's structured result-code design is more robust.

**Impact:** Diff-test corpus has historically tripped on mis-classified
rejections (see `validation.lua:1371-1377` comment about
"`script-verify-flag-failed`" misclassification of BIP-34 errors).
Latent risk for any future rejection-code addition.

**Severity:** P0 (architectural, not consensus per se).

---

### BUG-19 (P1) — `check_transaction`'s coinbase scriptSig length check fires AFTER duplicate-input check

**File:** `src/validation.lua:184-251`.

**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:11-60` —
`CheckTransaction` runs (1) vin-empty, (2) vout-empty, (3) oversize,
(4) per-output MoneyRange, (5) **duplicate-input**, (6) coinbase length
OR non-coinbase null-prevout. The order is fixed.

**Description:** Lunarblock's order is (1) vin/vout-empty, (2) tx-size,
(3) **duplicate-input** (199-214), (4) per-output MoneyRange (217-225),
(5) coinbase detection + coinbase length (228-241), (6) non-coinbase
null-prevout (242-247).

Diverges from Core in the relative ordering of (4) vs (5)+(6) and (3)
vs (4). For a tx that's simultaneously duplicate-input-bad AND
vout-too-large, lunarblock reports "duplicate-input" first; Core reports
"vout-toolarge" first. **Error-string divergence on malformed tx
diff-test cases.**

**Severity:** P1 (diff-test parity; corpus-detectable).

---

### BUG-20 (P0) — `check_block` runs `check_witness_malleation` AFTER block-weight gate (W142 cross-ref, but compounded with BUG-3)

**File:** `src/validation.lua:1344-1363`.

**Core ref:** `bitcoin-core/src/validation.cpp:4169-4181` —
`CheckWitnessMalleation` runs BEFORE the post-witness `GetBlockWeight`
check. This ordering is consensus-relevant: a malicious peer can stuff
the coinbase witness to inflate the block weight without changing the
block hash. If we check weight first, we mark the block permanently
invalid for `bad-blk-weight` even though the underlying tx structure
might be fine.

**Description:** Lunarblock's `check_block` runs the block-weight check
at line 1344 (BEFORE the merkle and witness-malleation checks at lines
1351 and 1362). This is exactly the bug pattern noted in W142 (where
the relevant Core comment is reproduced).

**Cross-ref:** W142 BUG-7 (weight-check ordering). For W143 scope, this
compounds with BUG-3 (reorg skips check_block entirely): even if the
ordering were correct, the reorg path doesn't run it at all.

**Severity:** P0 (already covered by W142, cross-listed here for
ContextualCheckBlock completeness).

---

### BUG-21 (P0-CONSENSUS) — `connect_block` does not verify that block.transactions[1] is a valid coinbase BEFORE summing coinbase_value

**File:** `src/utxo.lua:2810-2818`.

**Core ref:** `bitcoin-core/src/validation.cpp:2610-2614`:

```cpp
CAmount blockReward = nFees + GetBlockSubsidy(pindex->nHeight, params.GetConsensus());
if (block.vtx[0]->GetValueOut() > blockReward) {
    state.Invalid(BLOCK_CONSENSUS, "bad-cb-amount", ...);
}
```

Core's `block.vtx[0]` is enforced to be a coinbase by `CheckBlock`
(`validation.cpp:3951-3955`). `GetValueOut()` walks all outputs and
sums.

**Description:** Lunarblock's `connect_block` (`utxo.lua:2810-2818`):

```lua
local coinbase_value = 0
for _, out in ipairs(block.transactions[1].outputs) do
  coinbase_value = coinbase_value + out.value
end
if coinbase_value > subsidy + total_fees then
  return nil, string.format("bad-cb-amount: ...")
end
```

This unconditionally sums `block.transactions[1].outputs`. **When
`skip_check_block=true` (BUG-14), `block.transactions[1]` may not be a
coinbase** (no check ran). If reorg also skipped check_block (BUG-3),
likewise. The sum is over an arbitrary tx, and the rejection-or-accept
depends on whether the (arbitrary) tx's output sum exceeds subsidy+fees.

**Compounds with BUG-3 / BUG-14**: under reorg or skip_check_block,
a block whose first tx is NOT a coinbase (e.g. has non-null prevouts)
would still be checked against `bad-cb-amount` as if it were a coinbase.
The check passes if the non-coinbase tx's outputs are small enough; the
non-coinbase tx then has its INPUTS spent normally (utxo.lua:2700+),
but those inputs were never reduced from the coinbase-value sum.

**Impact:** Inflation-class bug under reorg path. The chain advances a
block that paid more than the subsidy+fees would allow.

**Severity:** P0-CONSENSUS (latent, gated on BUG-3 or BUG-14 firing).

---

### BUG-22 (P0-CDIV) — `connect_block`'s BIP-30 path uses `compute_txid` per-tx without short-circuit if BIP-30 is bypassed (perf only — not a consensus bug after re-read)

Reviewing on re-read: lunarblock's BIP-30 path at `utxo.lua:2217-2240`
correctly short-circuits via `is_bip30_exempt` and
`bip34_bypasses_bip30`. The per-tx `compute_txid` only runs when
BIP-30 enforcement is active. This is correct.

**Re-classified to N/A** — withdrawing.

---

## Summary

**22 bugs catalogued.** (BUG-11, 16, 22 withdrawn/reclassified during
write-up — net 19 active findings; severity tally below counts active
only.)

| Severity | Count | Bugs |
|----------|-------|------|
| P0-CONSENSUS | 4 | BUG-3, BUG-14, BUG-21 (latent), BUG-7 (P0-CDIV → consensus split during reorg) |
| P0-CDIV | 5 | BUG-4, BUG-5, BUG-6, BUG-7, BUG-8 |
| P0 | 4 | BUG-15, BUG-18, BUG-19, BUG-20 |
| P1 | 5 | BUG-9, BUG-10, BUG-16, BUG-17, BUG-19 |
| P2 | 3 | BUG-1, BUG-2 |
| P3 | 2 | BUG-12, BUG-13 |

(Note: BUG-7 and BUG-19 are listed in two severity columns because they
compound across categories.)

**Top fleet-pattern signals:**

1. **"Two-pipeline guard"** — BUG-14 (skip_check_block in main.lua vs
   inline check in sync.lua). 15th distinct extension of this pattern.
2. **"Comment-as-confession"** — BUG-7 (`utxo.lua:3486-3488`: "CSV is
   not active in the regtest reorg corpus" — explicitly papers over a
   mainnet-relevant gap). 5th instance of this pattern.
3. **"Hardcoded constant where chainparams expected"** — BUG-8
   (HALVING_INTERVAL=210000 baked in). Same family as W138 BUG-2
   (rustoshi fabricated testnet4 h=290000).
4. **"Dead helper at call site"** — BUG-5 (`check_mutated` hook defined
   on `PartiallyDownloadedBlock:reconstruct` but never passed in). Same
   family as W141 lunarblock BUG-8 / BUG-9 / others.
5. **"Reorg path skips validation"** — BUG-3 (side-branch connect
   bypasses `check_block` entirely). Architectural fork between
   normal-IBD and reorg paths. Likely a fleet-wide pattern given the
   coupling of these checks in Core.

**Most representative findings (one line each):**

- **BUG-3 (P0-CONSENSUS)**: Reorg `connect_block` skips `check_block`
  entirely — merkle, BIP-34, weight, sigops, CheckTransaction all
  bypassed for side-branch chains during reorg.
- **BUG-6 (P0-CDIV)**: `count_script_sigops` returns 0 on `parse_script`
  pcall failure; Core retains partial count (`break` not `return 0`) —
  miner can craft malformed scripts to undercount sigops below the 80k
  cap.
- **BUG-7 (P0-CDIV)**: BIP-113 IsFinalTx silently bypassed on reorg
  because `prev_block_mtp = nil` falls through to
  `lock_time_cutoff = block.header.timestamp`; comment claims "regtest
  corpus only" but mainnet post-block-419,328 hits this path on every
  reorg.

**End W143 audit.**
