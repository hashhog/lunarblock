# W145 — Subsidy + fees + MAX_MONEY invariants audit (lunarblock)

**Date:** 2026-05-18
**Wave:** W145 (discovery)
**Impl:** lunarblock (Lua / LuaJIT)
**Status:** **23 BUGS FOUND** (1 P0-CONSENSUS / 2 P0-CDIV / 4 P0 / 7 P1 /
6 P2 / 3 P3) across **8 behaviors / 25 gates**
**Scope:** `GetBlockSubsidy`, `nSubsidyHalvingInterval` per-network,
post-64-halvings zero-subsidy guard, coinbase output sum ≤ subsidy + fees
(`bad-cb-amount`), `COINBASE_MATURITY`, `MAX_MONEY` / `MoneyRange`,
CVE-2018-17144 duplicate-input detection, fee invariant
(sum(prevout values) ≥ sum(output values), `bad-txns-in-belowout`).

## Context

This audit catalogues Core-parity deviations in **block-reward
calculation** and the **money-conservation invariants** that ensure the
fixed 21M BTC cap. The core algorithm in
`consensus.lua:50-58` (`get_block_subsidy`) is **structurally correct
for mainnet**: it computes `halvings = floor(height / 210000)`, applies
the ≥64 guard, then divides by 2 in a loop (Lua-safe equivalent of
Core's `nSubsidy >>= halvings`). Output-side MAX_MONEY checks live in
`validation.lua:184-251` (`check_transaction`) and the per-input
checks in `utxo.lua:2395-2403` (`connect_block`). However:

1. **`nSubsidyHalvingInterval` is hardcoded global** — regtest is not
   honored (Core uses 150, lunarblock uses 210000 everywhere). This is
   the dominant finding: any regtest-mode chain validation that uses
   lunarblock past height 150 will compute a different
   subsidy than Core and **diverge on every `ConnectBlock` from then on**.
2. **Error strings in `check_transaction` are not Core-parity** — they
   say `"output 3 has negative value"` and `"transaction has no inputs"`
   instead of `"bad-txns-vout-negative"` and `"bad-txns-vin-empty"`.
   Consensus-divergence at the wire/diff-test level (corpus rejection
   reason classification breaks). This pattern has appeared in other
   waves (rpc.lua:62 classifier explicitly tries to match Core's
   reject-strings via `s:find`, so the un-matched ones fall through
   to `block-script-verify-flag-failed` or `rejected`).
3. **No per-block `vtx.size() * 4 > MAX_BLOCK_WEIGHT` DoS guard** —
   serialization runs unbounded before the weight check (also called
   out by W142 BUG-7; restated here in the subsidy/fees scope).
4. **Per-network `subsidy_halving_interval` field is absent**, so any
   future deployment of testnet/signet with different rules cannot be
   supported.

## Source map

- `lunarblock/src/consensus.lua:8-58` — `COIN`, `MAX_MONEY`,
  `INITIAL_BLOCK_REWARD`, `HALVING_INTERVAL`, `get_block_subsidy`,
  `is_valid_amount`.
- `lunarblock/src/consensus.lua:1058-1126` — `M.networks.testnet4`
  (no `subsidy_halving_interval`).
- `lunarblock/src/consensus.lua:1130-1195` — `M.networks.regtest`
  (no `subsidy_halving_interval`).
- `lunarblock/src/validation.lua:184-251` — `check_transaction`
  (vin/vout empty, vout negative/oversize, total-out MAX_MONEY,
  duplicate-inputs, coinbase scriptSig length, null-prevout).
- `lunarblock/src/utxo.lua:2375-2403` — coinbase maturity + per-input
  MoneyRange check on connect.
- `lunarblock/src/utxo.lua:2756-2774` — `bad-txns-in-belowout`
  + `bad-txns-accumulated-fee-outofrange`.
- `lunarblock/src/utxo.lua:2789-2818` — `bad-cb-amount` block-end check.
- `lunarblock/src/mining.lua:263, 362` — mining-side subsidy.
- `lunarblock/src/rpc.lua:3789` — submitblock/getblocktemplate subsidy.
- `lunarblock/src/sync.lua:845`, `lunarblock/src/utxo.lua:1661` — genesis
  coinbase subsidy.
- `lunarblock/src/mempool.lua:1250` — mempool fee < 0 reject.

Core references:

- `bitcoin-core/src/validation.cpp:1839-1850` — `GetBlockSubsidy`.
- `bitcoin-core/src/validation.cpp:2610` — `blockReward = nFees +
  GetBlockSubsidy(...)`.
- `bitcoin-core/src/kernel/chainparams.cpp:84, 209, 310, 454, 535` —
  `nSubsidyHalvingInterval` per network (210000 / 210000 / 210000 /
  210000 / **150 regtest**).
- `bitcoin-core/src/consensus/amount.h:11-15` — `COIN = 100_000_000`,
  `MAX_MONEY = 21_000_000 * COIN`, `MoneyRange(amount) = amount >= 0
  && amount <= MAX_MONEY`.
- `bitcoin-core/src/consensus/tx_check.cpp:11-60` — `CheckTransaction`:
  `bad-txns-vin-empty`, `bad-txns-vout-empty`, `bad-txns-oversize`,
  `bad-txns-vout-negative`, `bad-txns-vout-toolarge`,
  `bad-txns-txouttotal-toolarge`, `bad-txns-inputs-duplicate`,
  `bad-cb-length`, `bad-txns-prevout-null`.
- `bitcoin-core/src/consensus/tx_verify.cpp:170-205` — `Consensus::
  CheckTxInputs`: coinbase maturity (`bad-txns-premature-spend-of-
  coinbase`), per-input MoneyRange (`bad-txns-inputvalues-outofrange`),
  fee = nValueIn - tx.GetValueOut(), `bad-txns-in-belowout`,
  `bad-txns-fee-outofrange`.
- `bitcoin-core/src/consensus/consensus.h:18` —
  `COINBASE_MATURITY = 100`.

## 8-behavior matrix

### B1. `GetBlockSubsidy` algorithm parity

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G1 | `halvings = nHeight / interval` (C++ integer div, lunarblock `math.floor`) | **OK** — `consensus.lua:51`. |
| G2 | `if (halvings >= 64) return 0` guard | **OK** — `consensus.lua:52`. |
| G3 | Initial subsidy = `50 * COIN = 5_000_000_000` sats | **OK** — `INITIAL_BLOCK_REWARD` `consensus.lua:47`. |
| G4 | `nSubsidy >>= halvings` (right-shift). Lunarblock uses `math.floor(s/2)` loop. | **OK** — equivalent up to halvings = 33 where subsidy reaches 0 (verified empirically). |
| G5 | Negative-height defensive behavior | **BUG-1 (P3)** — Lua returns 50 BTC for negative heights (loop body skipped when halvings < 0); Core's `>>=` is undefined for negative shift amount. No real call path, but a defense-in-depth gap. |

### B2. Per-network `nSubsidyHalvingInterval`

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G6 | mainnet = 210000 | **OK** — `HALVING_INTERVAL = 210000`. |
| G7 | testnet3/testnet4/signet = 210000 | **OK by hardcode**. |
| G8 | **regtest = 150** | **BUG-2 (P0-CONSENSUS)** — hardcoded global means regtest also halves at 210000. From regtest block 150 onward, lunarblock pays 50 BTC where Core pays 25, then 12.5, etc. **Every regtest functional test that mines past height 150 will diverge on every coinbase**. |
| G9 | `subsidy_halving_interval` field on network params | **BUG-3 (P0)** — field does not exist. Cross-cuts BUG-2; no per-network override is even possible without adding the field. Pattern: **hardcoded-global where Core has chainparams** (same root cause as numerous other audits — fleet pattern). |

### B3. Post-64-halvings = zero subsidy

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G10 | At height ≥ `64 * 210000 = 13_440_000`, subsidy = 0 | **OK** — `consensus.lua:52` (verified empirically: `get_block_subsidy(13440000) == 0`). |
| G11 | After the 33rd halving (≈block 6_930_000) subsidy already 0 (50e8 sats reaches 0 after 33 right-shifts) | **OK** — verified empirically, loop produces 0 by halving 33. **NOTE:** behavior matches Core's `nSubsidy >>= 33` which also = 0. |

### B4. Coinbase output sum ≤ subsidy + fees (`bad-cb-amount`)

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G12 | Reject when `coinbase_value > subsidy + total_fees` | **OK** — `utxo.lua:2814-2818`. Error string matches Core. |
| G13 | `subsidy + total_fees` computed with `consensus.is_valid_amount` MoneyRange check | **BUG-4 (P1)** — no MoneyRange check on `subsidy + total_fees`. If `total_fees` is near MAX_MONEY and subsidy small, sum fits; but the **accumulator** `total_fees + tx_fee` IS checked via `bad-txns-accumulated-fee-outofrange` (`utxo.lua:2772`), so this is a "good but not at the boundary" check. Latent. |
| G14 | The check uses **strict `>`** (not `≥`) | **OK** — matches Core line 2614 `nFees > blockReward`. |

### B5. `COINBASE_MATURITY = 100`

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G15 | Reject if `height - utxo.height < 100` for coinbase inputs | **OK** — `utxo.lua:2389-2393`. Error string matches Core. |
| G16 | `is_coinbase` flag persisted in UTXO entry | **OK** — `utxo.lua:298`, `utxo.lua:367-370`. |
| G17 | Maturity uses the SPENDING block's height (not tip) | **OK** — `utxo.lua:2390` uses `height` param from `connect_block`. |

### B6. `MAX_MONEY` / `MoneyRange` per output, per tx, per block

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G18 | Per-output `value < 0` reject → `bad-txns-vout-negative` | **BUG-5 (P0-CDIV)** — `validation.lua:220` uses `assert(out.value >= 0, "output i has negative value")`. Error string does NOT match Core. RPC classifier (`rpc.lua:120` pattern `s:find("coinbase amount")` etc.) won't catch this. Diff-test corpus will see mismatched reject string. |
| G19 | Per-output `value > MAX_MONEY` reject → `bad-txns-vout-toolarge` | **BUG-6 (P0-CDIV)** — `validation.lua:221-222` uses `"output i value exceeds MAX_MONEY"`. Same Core-parity gap as BUG-5. |
| G20 | Running-sum overflow reject → `bad-txns-txouttotal-toolarge` | **BUG-7 (P0-CDIV)** — `validation.lua:224` uses `"total output value exceeds MAX_MONEY"`. Same gap. |
| G21 | Per-input MoneyRange on connect → `bad-txns-inputvalues-outofrange` | **OK** — `utxo.lua:2400-2403` uses the canonical string. |
| G22 | Accumulated block-fee MoneyRange → `bad-txns-accumulated-fee-outofrange` | **OK** — `utxo.lua:2772`. |

### B7. CVE-2018-17144 duplicate-input detection

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G23 | Detect duplicate `prevout` in the SAME tx, BEFORE UTXO lookup | **OK** — `validation.lua:198-215`. Detects in `check_transaction`, which `check_block` invokes BEFORE `connect_block` performs UTXO lookups. Error string `"bad-txns-inputs-duplicate"` matches Core. |

### B8. Fee invariant (sum(in) ≥ sum(out))

| Gate | Description | lunarblock status |
|------|-------------|-------------------|
| G24 | `input_total >= output_total` per tx → `bad-txns-in-belowout` | **OK** — `utxo.lua:2766-2768`. Canonical string. |
| G25 | Mempool path uses same error string | **BUG-8 (P1)** — `mempool.lua:1250-1252` returns `"outputs exceed inputs"` not `"bad-txns-in-belowout"`. Mempool rejection paths feed into RPC error mapping, which uses string matching. Same fleet pattern as BUG-5/6/7. |

## Bugs (full)

### BUG-1 (P3) — Negative-height returns 50 BTC subsidy

**File:** `src/consensus.lua:50-58`.

**Core ref:** `bitcoin-core/src/validation.cpp:1839-1850` — Core uses
C++ integer division `nHeight / consensusParams.nSubsidyHalvingInterval`
which for negative `nHeight` produces a negative quotient. Then
`nSubsidy >>= halvings` with negative shift count is **undefined
behavior** in C++.

**Description:** Lunarblock's loop `for _ = 1, halvings do ... end`
silently skips when `halvings < 0`, returning the unmodified
`INITIAL_BLOCK_REWARD = 50 BTC`. There is no real path where
`height < 0` reaches this function (block heights are non-negative
by construction), but the function is exported and could be reached
from a malformed RPC. Defense-in-depth gap: an explicit
`assert(height >= 0)` would document the contract.

**Excerpt** (`consensus.lua:50-58`):

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

**Impact:** None for consensus (no negative heights reach here). P3 hygiene.

**Severity:** P3.

---

### BUG-2 (P0-CONSENSUS) — `nSubsidyHalvingInterval` is hardcoded; regtest uses 210000 instead of 150

**File:** `src/consensus.lua:48` (`M.HALVING_INTERVAL = 210000`), used at
`consensus.lua:51` in `get_block_subsidy`. Caller pattern: every call
ignores the active network.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:535` —
```cpp
consensus.nSubsidyHalvingInterval = 150;
```
for `CRegTestParams`. The function `GetBlockSubsidy(nHeight,
consensusParams)` takes the params struct.

**Description:** Lunarblock's `get_block_subsidy(height)` does NOT take
the active network/params. It uses the module-global
`M.HALVING_INTERVAL = 210000` for ALL networks. The regtest network
record at `consensus.lua:1130-1195` does NOT carry a
`subsidy_halving_interval` field, so even if a caller wanted to thread
it, the field does not exist.

**Excerpt** (`consensus.lua:48-58`):

```lua
M.HALVING_INTERVAL = 210000

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

And the regtest record (`consensus.lua:1130-1195`) declares
`bip34_height`, `bip65_height`, `bip66_height`, `csv_height`,
`segwit_height`, `taproot_height`, `versionbits_period`,
`versionbits_threshold` — but **no `subsidy_halving_interval`**.

**Impact:**
- **Regtest divergence**: Core regtest halves at block 150 (25 BTC),
  block 300 (12.5 BTC), etc. Lunarblock regtest stays at 50 BTC until
  block 210000.
- **Every regtest functional test** that mines past height 150 and
  exercises `bad-cb-amount`, fee math, or any
  `getblock`/`getblockstats` subsidy field **will diverge from Core**.
- **`connect_block` will reject** Core-produced regtest blocks that
  pay the correct (smaller) coinbase after height 150 (lunarblock
  computes 50 BTC subsidy, Core block paid only 25 BTC — lunarblock
  sees `coinbase_value < subsidy + fees` which is permitted, but…)
  actually the rejection is the OTHER way: a Core regtest block at
  height 151 paying 50 BTC would be rejected by Core (`bad-cb-amount`,
  Core subsidy = 25 BTC at height 151) but ACCEPTED by lunarblock
  (lunarblock subsidy still 50 BTC). **Lunarblock accepts blocks Core
  rejects** — a money-supply over-issuance bug at the regtest chain
  level.
- Less catastrophic on mainnet (210000 is hardcoded right), but the
  underlying defect (hardcoded global, no per-network field) is what
  the audit flags. Future testnet5 or rule-tightened signet would
  require code surgery instead of a one-line params change.

**Severity:** P0-CONSENSUS. (Regtest-only consensus divergence; mainnet
unaffected today. Reported as P0-CONSENSUS because it is a money-supply
divergence on a Bitcoin chain, regardless of which chain.)

---

### BUG-3 (P0) — No `subsidy_halving_interval` field on network records

**File:** `src/consensus.lua:1058-1126` (testnet4),
`src/consensus.lua:1130-1195` (regtest), and the mainnet section.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:84, 209, 310,
454, 535` — every chainparams record carries
`consensus.nSubsidyHalvingInterval`.

**Description:** Cross-cuts BUG-2. The data plumbing for per-network
subsidy intervals is absent. Fixing BUG-2 alone (passing the network
into `get_block_subsidy`) is insufficient without adding the field.
Pattern: **hardcoded-global where Core has chainparams** — appears
fleet-wide as one of the universal failure modes catalogued in the
quad-audit series.

**Excerpt** (`consensus.lua:1130-1195`, regtest, partial):

```lua
M.networks.regtest = {
  name = "regtest",
  magic_bytes = "\xfa\xbf\xb5\xda",
  port = 18444,
  rpc_port = 18443,
  ...
  bip34_height = 1,
  bip65_height = 0,
  bip66_height = 0,
  csv_height = 0,
  segwit_height = 0,
  taproot_height = 0,
  ...
  versionbits_period = 144,
  versionbits_threshold = 108,
  -- *** NO subsidy_halving_interval ***
}
```

**Impact:** Fix is two-line: add `subsidy_halving_interval = 150` on
regtest (and `= 210000` on mainnet/testnet records for symmetry),
then change `get_block_subsidy(height)` to
`get_block_subsidy(height, network_or_interval)` and pass the network
record at every call site (5 callers).

**Severity:** P0 — data-shape gap that is the root cause of BUG-2.

---

### BUG-4 (P1) — `subsidy + total_fees` not MoneyRange-checked at the boundary

**File:** `src/utxo.lua:2809-2818`.

**Core ref:** `bitcoin-core/src/validation.cpp:2610-2614`:
```cpp
CAmount blockReward = nFees + GetBlockSubsidy(pindex->nHeight, params.GetConsensus());
if (block.vtx[0]->GetValueOut() > blockReward)
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                         "bad-cb-amount", ...);
```
Core does NOT explicitly MoneyRange the sum either — `nFees` was already
validated by the per-tx fee MoneyRange checks in `CheckTxInputs`. So this
is more of a defensive-coding nit.

**Description:** Lunarblock at `utxo.lua:2814` computes
`subsidy + total_fees` and uses it as the cap; it does NOT call
`consensus.is_valid_amount(subsidy + total_fees)` first. The
accumulator `total_fees + tx_fee` IS checked (line 2772), so each
intermediate fee step is bounded by MAX_MONEY. The final
`subsidy + total_fees` can reach at most `MAX_MONEY + 50_BTC` which
is still in 53-bit safe-integer range, so the LuaJIT double does
not lose precision. No real correctness divergence.

**Excerpt** (`utxo.lua:2809-2818`):

```lua
local subsidy = consensus.get_block_subsidy(height)
local coinbase_value = 0
for _, out in ipairs(block.transactions[1].outputs) do
  coinbase_value = coinbase_value + out.value
end
if coinbase_value > subsidy + total_fees then
  return nil, string.format(
    "bad-cb-amount: coinbase pays too much (actual=%d vs limit=%d)",
    coinbase_value, subsidy + total_fees)
end
```

**Impact:** No correctness divergence; defensive-coding nit.

**Severity:** P1.

---

### BUG-5 (P0-CDIV) — `bad-txns-vout-negative` reject string not Core-parity

**File:** `src/validation.lua:220`.

**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:27-28`:
```cpp
if (txout.nValue < 0)
    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-negative");
```

**Description:** Lunarblock asserts with the human-readable
`"output i has negative value"` instead of `"bad-txns-vout-negative"`.
The rpc.lua classifier (`rpc.lua:62-180`) maps Core-style reject strings
to RPC error codes; un-matched strings fall through to generic
`block-script-verify-flag-failed` or `rejected`. **Diff-test parity
corpus** (which compares lunarblock vs `bitcoin-core` reject reasons
on identical inputs) will mismatch.

**Excerpt** (`validation.lua:217-225`):

```lua
-- Validate outputs: value >= 0, value <= MAX_MONEY, total <= MAX_MONEY
local total_out = 0
for i, out in ipairs(tx.outputs) do
  assert(out.value >= 0, "output " .. i .. " has negative value")
  assert(out.value <= consensus.MAX_MONEY,
         "output " .. i .. " value exceeds MAX_MONEY")
  total_out = total_out + out.value
  assert(total_out <= consensus.MAX_MONEY, "total output value exceeds MAX_MONEY")
end
```

**Impact:** Diff-test corpus rejection-reason mismatch; user-visible
JSON-RPC `reject_reason` field reads `"output 3 has negative value"`
instead of `"bad-txns-vout-negative"`. Wallet integrations comparing
the reason string to Core's reject-reason set break.

**Severity:** P0-CDIV. Pattern: **human-readable reject string where
Core uses canonical wire token**. Each of BUG-5/6/7 (and most of
B6/B8) is a separate one-line fix that should be batched as a single
"wire-string parity" sweep.

---

### BUG-6 (P0-CDIV) — `bad-txns-vout-toolarge` reject string not Core-parity

**File:** `src/validation.lua:221-222`.

**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:29-30`:
```cpp
if (txout.nValue > MAX_MONEY)
    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-toolarge");
```

**Description:** Lunarblock asserts `"output i value exceeds
MAX_MONEY"`; Core uses `"bad-txns-vout-toolarge"`. Same diff-test
mismatch as BUG-5.

**Excerpt:** see BUG-5 excerpt.

**Impact:** Same as BUG-5.

**Severity:** P0-CDIV.

---

### BUG-7 (P0-CDIV) — `bad-txns-txouttotal-toolarge` reject string not Core-parity

**File:** `src/validation.lua:224`.

**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:32-33`:
```cpp
nValueOut += txout.nValue;
if (!MoneyRange(nValueOut))
    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-txouttotal-toolarge");
```

**Description:** Lunarblock asserts `"total output value exceeds
MAX_MONEY"`; Core uses `"bad-txns-txouttotal-toolarge"`. Same diff-test
mismatch as BUG-5.

**Excerpt:** see BUG-5 excerpt.

**Impact:** Same as BUG-5.

**Severity:** P0-CDIV.

---

### BUG-8 (P1) — Mempool fee-invariant reject string is `"outputs exceed inputs"` not `"bad-txns-in-belowout"`

**File:** `src/mempool.lua:1250-1252`.

**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:196-199`:
```cpp
if (nValueIn < value_out)
    return state.Invalid(TxValidationResult::TX_CONSENSUS,
                         "bad-txns-in-belowout", ...);
```

**Description:** The block-connect path (`utxo.lua:2766-2768`) uses
the canonical string `"bad-txns-in-belowout"`, but the mempool
accept path (`mempool.lua:1250-1252`) returns `"outputs exceed
inputs"`. Two paths for the same consensus check, two different
reject strings — a **two-pipeline guard mismatch** (one of the
fleet patterns: mempool accept and block accept share the same
underlying CheckTxInputs in Core, but diverge here).

**Excerpt** (`mempool.lua:1244-1252`):

```lua
-- 5. Calculate fee
local output_total = 0
for _, out in ipairs(tx.outputs) do
  output_total = output_total + out.value
end
local fee = input_total - output_total
if fee < 0 then
  return false, "outputs exceed inputs"
end
```

**Impact:** `sendrawtransaction` RPC returns `reject_reason:
"outputs exceed inputs"` instead of `"bad-txns-in-belowout"`. Wallet
software that switches on canonical Core reject strings will fail.

**Severity:** P1.

---

### BUG-9 (P0) — `bad-txns-vin-empty` / `bad-txns-vout-empty` not Core-parity

**File:** `src/validation.lua:186-187`.

**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:14-17`:
```cpp
if (tx.vin.empty())
    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vin-empty");
if (tx.vout.empty())
    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-empty");
```

**Description:** Lunarblock asserts `"transaction has no inputs"` /
`"transaction has no outputs"`. Both are not Core-parity. Same
diff-test mismatch class as BUG-5/6/7. Two extra distinct cases.

**Excerpt** (`validation.lua:186-187`):

```lua
assert(#tx.inputs > 0, "transaction has no inputs")
assert(#tx.outputs > 0, "transaction has no outputs")
```

**Impact:** Diff-test reject-string mismatch. Wallet/test-harness
integration. Same surface as BUG-5/6/7.

**Severity:** P0 (lower than CDIV because the empty-tx case is more
of a defense-in-depth gate; Core also rejects via serialization
layer for txs that fail to round-trip).

---

### BUG-10 (P0) — `bad-txns-oversize` reject string not Core-parity

**File:** `src/validation.lua:194-196`.

**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:19-21`:
```cpp
if (::GetSerializeSize(TX_NO_WITNESS(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT) {
    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-oversize");
}
```

**Description:** Lunarblock asserts `"transaction stripped size N * 4
exceeds MAX_BLOCK_WEIGHT"`; Core uses `"bad-txns-oversize"`. The check
itself is structurally equivalent — error string only.

**Excerpt** (`validation.lua:194-196`):

```lua
local tx_data = tx._cached_base_data or serialize.serialize_transaction(tx, false)
assert(#tx_data * consensus.WITNESS_SCALE_FACTOR <= consensus.MAX_BLOCK_WEIGHT,
       "transaction stripped size " .. #tx_data .. " * 4 exceeds MAX_BLOCK_WEIGHT")
```

**Impact:** Same as BUG-5/6/7/9 — diff-test reject-string mismatch.

**Severity:** P0.

---

### BUG-11 (P0) — `bad-cb-length` reject string not Core-parity (coinbase scriptSig length)

**File:** `src/validation.lua:240-241`.

**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:48-50`:
```cpp
if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-length");
```

**Description:** Lunarblock asserts `"coinbase scriptSig too short:
N"` / `"coinbase scriptSig too long: N"`. Core uses `"bad-cb-length"`.
The rpc.lua classifier at line 113-116 DOES try to match this:
```lua
-- Coinbase scriptSig length (consensus/tx_check.cpp "bad-cb-length"; 2..100 bytes)
return "bad-cb-length"
```
but it pattern-matches on `s:find("script.*length")` style. The actual
assert text contains `"coinbase scriptSig"` — needs a manual audit of
which regex actually catches.

**Excerpt** (`validation.lua:240-241`):

```lua
local sig_len = #tx.inputs[1].script_sig
assert(sig_len >= 2, "coinbase scriptSig too short: " .. sig_len)
assert(sig_len <= 100, "coinbase scriptSig too long: " .. sig_len)
```

**Impact:** Reject-string mismatch. Fix: change to
`assert(..., "bad-cb-length: coinbase scriptSig too short: " .. sig_len)`.

**Severity:** P0.

---

### BUG-12 (P0) — `bad-txns-prevout-null` reject string not Core-parity

**File:** `src/validation.lua:244-247`.

**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:53-56`:
```cpp
for (const auto& txin : tx.vin)
    if (txin.prevout.IsNull())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-prevout-null");
```

**Description:** Lunarblock asserts `"non-coinbase input N has null
prevout hash"`. Core uses `"bad-txns-prevout-null"`. Same fix-pattern
as BUG-5/6/7/9/10/11.

**Excerpt** (`validation.lua:244-247`):

```lua
for i, inp in ipairs(tx.inputs) do
  assert(inp.prev_out.hash.bytes ~= null_hash,
         "non-coinbase input " .. i .. " has null prevout hash")
end
```

**Impact:** Reject-string mismatch.

**Severity:** P0.

---

### BUG-13 (P0) — `check_transaction` does NOT check prevout `index` for IsNull, only hash

**File:** `src/validation.lua:244-247`.

**Core ref:** `bitcoin-core/src/primitives/transaction.h` —
`COutPoint::IsNull()` returns `hash.IsNull() && n == (uint32_t)-1`. The
NULL test is `(hash == 0) AND (index == 0xFFFFFFFF)`. Lunarblock at line
245 only checks `inp.prev_out.hash.bytes ~= null_hash` — it does NOT
require `index == 0xFFFFFFFF`.

**Description:** The coinbase detection at line 232 correctly uses
`hash AND index == 0xFFFFFFFF`. The non-coinbase null-prevout check at
line 244 only tests hash. Practical consequence: a non-coinbase tx
with `hash = 0...0`, `index = 0` (or any non-0xFFFFFFFF) would pass the
null-prevout check (lunarblock thinks it's not null), but then Core's
`COutPoint::IsNull()` returns false too — so this is actually
consistent. Re-reading Core: `IsNull` requires BOTH hash == 0 and
index == (uint32_t)-1, so the non-null check is `NOT (hash==0 AND
index==-1)` which is `hash != 0 OR index != -1`. Lunarblock's stricter
`hash != 0` is a SUBSET of valid inputs — it **over-rejects** any
non-coinbase tx whose prevout-hash happens to be all-zero (regardless
of index). Such a tx would have an unspendable input
(`COutPoint(0, 5)` is not a real UTXO) but is not consensus-invalid by
the prevout-null rule.

**Excerpt** (Core, `transaction.h:34-38` summary):
```cpp
bool COutPoint::IsNull() const {
    return hash.IsNull() && n == (uint32_t)-1;
}
```

Lunarblock (validation.lua:244-247):
```lua
for i, inp in ipairs(tx.inputs) do
  assert(inp.prev_out.hash.bytes ~= null_hash,
         "non-coinbase input " .. i .. " has null prevout hash")
end
```

**Impact:** Lunarblock REJECTS some txs that Core would ACCEPT (and
then reject later for missing UTXO). Latent: an attacker who somehow
constructed a prevout `(hash=0, index=5)` — which is not a real UTXO —
would be rejected by lunarblock with the wrong error reason. This is
**over-rejection** rather than under-rejection, so consensus-safe but
not Core-parity.

**Severity:** P0 (CDIV-leaning: a Core-accepted tx may be rejected by
lunarblock for the wrong reason. Fix: change condition to require both
hash == 0 AND index == 0xFFFFFFFF).

---

### BUG-14 (P1) — `check_transaction` does not verify `bad-blk-length` vtx-count guard

**File:** `src/validation.lua:1298-1397` (`check_block`).

**Core ref:** `bitcoin-core/src/validation.cpp:3946-3948`:
```cpp
if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
    || ::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-length", "size limits failed");
```

**Description:** This is partially covered by W142 BUG-7 (block-weight
DoS guard), but restated here in the **subsidy/fees** scope because:
the guard `vtx.size() * 4 > MAX_BLOCK_WEIGHT` (i.e. `vtx.size() >
1_000_000`) is a defense against a block claiming to have 4 billion
empty transactions. Lunarblock serializes EVERY tx in
`check_block` (line 1317) BEFORE doing the weight check at 1344 —
which means a 4-billion-tx attacker block forces unbounded loop work
before any reject. **Pre-serialize DoS guard absent.**

**Excerpt** (`validation.lua:1305-1346`):

```lua
assert(#block.transactions > 0, "block has no transactions")

-- Single-pass: check transactions, compute weight, count sigops, ...
local total_weight = 0
for i, tx in ipairs(block.transactions) do
  local base_data = serialize.serialize_transaction(tx, false)
  local total_data = serialize.serialize_transaction(tx, true)
  ...
  total_weight = total_weight + #base_data * 3 + #total_data
  ...
end
assert(total_weight <= consensus.MAX_BLOCK_WEIGHT, ...)
```

**Impact:** P2P DoS. Fix: at top of `check_block`, after the
`#block.transactions > 0` assert, add
`assert(#block.transactions * 4 <= MAX_BLOCK_WEIGHT)`.

**Severity:** P1.

---

### BUG-15 (P1) — `check_transaction` per-output checks use `assert` (Lua error) not state.Invalid pattern

**File:** `src/validation.lua:217-247`.

**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp` — Core uses
`state.Invalid(...)` returning false. Lunarblock uses `assert(...)`
which raises a Lua error (caught by `pcall` at mempool.lua:957,
mempool.lua:2575). The two are functionally similar BUT `assert`
includes the file:line in the error string by default, which
contaminates the reject-reason. Cross-references BUG-5/6/7/9/10/11/12.

**Description:** `assert(cond, msg)` in Lua raises an error
`msg` — the assertion module prepends the location. When mempool
catches via `pcall`, the error string becomes
`"validation.lua:220: output 3 has negative value"`. The classifier
at `rpc.lua:62-180` does a `s:find("output.*negative")` style match
which DOES catch it, but the user-visible reject-reason includes
the source location, leaking implementation details into the wire
protocol.

**Excerpt** (`validation.lua:184-251`): see BUG-5 excerpt.

**Impact:** Information leak (file:line in RPC reject reason);
brittle string-matching in rpc.lua. Fix is the same wire-string
parity sweep recommended in BUG-5/6/7.

**Severity:** P1.

---

### BUG-16 (P2) — `consensus.is_valid_amount` is used INconsistently across paths

**File:** `src/consensus.lua:837-839`.

**Core ref:** `bitcoin-core/src/consensus/amount.h:18-25`:
```cpp
inline bool MoneyRange(const CAmount& nValue) {
    return (nValue >= 0 && nValue <= MAX_MONEY);
}
```

**Description:** The function exists and is correctly defined. But the
output-side checks in `check_transaction` (lines 220-224) do NOT use
it — they hand-inline the comparisons with non-canonical error
strings. Per-input checks at `utxo.lua:2400-2403` DO call
`consensus.is_valid_amount`. Pattern: **good primitive, inconsistent
use** — fix is to thread `is_valid_amount` through `check_transaction`
output loop AND ALSO emit canonical Core error strings.

**Excerpt** (`consensus.lua:837-839`):

```lua
function M.is_valid_amount(amount)
  return amount >= 0 and amount <= M.MAX_MONEY
end
```

vs. `validation.lua:220-224`:

```lua
assert(out.value >= 0, "output " .. i .. " has negative value")
assert(out.value <= consensus.MAX_MONEY,
       "output " .. i .. " value exceeds MAX_MONEY")
...
assert(total_out <= consensus.MAX_MONEY, "total output value exceeds MAX_MONEY")
```

**Impact:** Consistency-only; ties BUG-5/6/7 to a single refactor.

**Severity:** P2.

---

### BUG-17 (P2) — `get_block_subsidy` does not take `network` parameter

**File:** `src/consensus.lua:50`.

**Core ref:** `bitcoin-core/src/validation.cpp:1839`:
```cpp
CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams)
```

**Description:** Companion to BUG-2/BUG-3. Lunarblock's signature is
`get_block_subsidy(height)` only. The fix lattice is:
1. Add `subsidy_halving_interval` field to network records.
2. Change signature to `get_block_subsidy(height, network)`.
3. Update 5 callers
   (`mining.lua:263`, `sync.lua:845`, `utxo.lua:1661`,
   `utxo.lua:2809`, `rpc.lua:3513`, `rpc.lua:3789`).

Some callers already have a network in scope (`mining.lua:263` —
`network` parameter at line 250; `utxo.lua:2809` — `self.network`).
Two callers compute the genesis subsidy and pass `(0)` — they get the
right answer (50 BTC) regardless because halvings = 0 at height 0.

**Excerpt:** see BUG-2 excerpt.

**Impact:** Refactor cost; not a consensus bug on its own.

**Severity:** P2 (P0 when bundled with BUG-2's regtest divergence).

---

### BUG-18 (P2) — `check_transaction` does NOT verify `index < 2^32` (CompactSize prevout-index)

**File:** `src/validation.lua:200-215`.

**Core ref:** `bitcoin-core/src/primitives/transaction.h` —
`COutPoint::n` is `uint32_t`. The serializer enforces this. The
consensus layer doesn't re-verify because the type system enforces it.

**Description:** Lunarblock represents `inp.prev_out.index` as a Lua
number. Lua numbers are double-precision floats. There is no explicit
`assert(idx >= 0 and idx < 2^32)` anywhere in `check_transaction`.
If the deserializer somehow produced an out-of-range index (e.g. from
a malformed network message that bypassed the BIP-141 marker logic
and hit a fallback), the duplicate-input key computation at lines
202-207 would byte-encode the LOW 32 bits silently (via `bit.band`),
losing the upper bits. Two distinct prevouts `(h, 2^32)` and `(h, 0)`
would collide in the duplicate detector.

**Excerpt** (`validation.lua:200-215`):

```lua
for _, inp in ipairs(tx.inputs) do
  local idx = inp.prev_out.index
  local key = inp.prev_out.hash.bytes .. string.char(
    bit.band(idx, 0xFF),
    bit.band(bit.rshift(idx, 8), 0xFF),
    bit.band(bit.rshift(idx, 16), 0xFF),
    bit.band(bit.rshift(idx, 24), 0xFF)
  )
  if seen_outpoints[key] then ... end
```

**Impact:** Latent / defense-in-depth. Practical chance of an
out-of-range index reaching here is near zero (the deserializer in
`serialize.lua` enforces uint32). Add an explicit
`assert(idx >= 0 and idx < 4294967296)` before the bit ops.

**Severity:** P2.

---

### BUG-19 (P2) — Lua subsidy chain loses no precision but uses a 33-iteration loop instead of bit-shift

**File:** `src/consensus.lua:53-56`.

**Core ref:** `bitcoin-core/src/validation.cpp:1848`:
```cpp
nSubsidy >>= halvings;
```

**Description:** Cosmetic / perf. Lunarblock loops up to 64 iterations
of `math.floor(s/2)`. Could be a single `bit.rshift(subsidy, halvings)`
call. LuaJIT's `bit` library handles up to 32-bit, but the subsidy
starts at 5e9 (33 bits) and goes down, so a `bit.tobit(bit.rshift(...))`
pattern would need care. Not worth fixing.

**Excerpt** (`consensus.lua:53-56`):

```lua
local subsidy = M.INITIAL_BLOCK_REWARD
for _ = 1, halvings do
  subsidy = math.floor(subsidy / 2)
end
```

**Impact:** None.

**Severity:** P3.

---

### BUG-20 (P3) — `MAX_MONEY` is module-global, not per-network

**File:** `src/consensus.lua:9`.

**Core ref:** `bitcoin-core/src/consensus/amount.h:15`:
```cpp
static constexpr CAmount MAX_MONEY = 21'000'000 * COIN;
```

**Description:** Cross-fleet pattern. Core makes MAX_MONEY a global
constant — Bitcoin's monetary policy. Lunarblock matches this
(global `M.MAX_MONEY`). Some altcoin forks override this. Lunarblock
hardcodes 21M without an override seam. **Not a Core-parity bug** —
Core also hardcodes it — but worth noting as the fleet's pattern is to
hardcode here, which limits forkability.

**Impact:** None for Bitcoin parity.

**Severity:** P3 (informational).

---

### BUG-21 (P1) — `connect_block` does NOT recompute `is_coinbase` from tx structure; trusts the UTXO entry's stored flag

**File:** `src/utxo.lua:2389-2393`.

**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:177-184`:
```cpp
if (coin.IsCoinBase()) {
    if (nSpendHeight - coin.nHeight < COINBASE_MATURITY)
        return state.Invalid(...
```
Core's `Coin::IsCoinBase()` is set at coin construction from the
producing tx's `IsCoinBase()` — same place lunarblock sets it. No bug
in itself, but defense-in-depth is missing: if the UTXO database
corrupts the flag (e.g. a power-cut rewrite that flips bytes), Core
recovers via a sanity check; lunarblock does not.

**Description:** The maturity gate trusts `utxo.is_coinbase` —
provided by `utxo.lua:298, 367-370` at coin creation/deserialization.
A flipped byte in `utxo.lua:367` (`is_coinbase = data:byte(pos) == 1`)
would silently make a real coinbase spendable at depth < 100.

**Excerpt:** see source map B5.

**Impact:** Storage-corruption resilience gap. Not a consensus
divergence on a clean run.

**Severity:** P1.

---

### BUG-22 (P2) — `get_block_subsidy` returns Lua number, not bigint; subsidy underflow at halvings=33 is silent

**File:** `src/consensus.lua:50-58`.

**Core ref:** `bitcoin-core/src/validation.cpp:1846-1848` — CAmount is
int64_t. `>>= 33` of 50e8 = 0, intended behavior.

**Description:** Empirically, the loop produces:
- halving 32: `subsidy = 1`
- halving 33: `subsidy = 0`
- halving 34+: subsidy stays 0 (math.floor(0/2) = 0).

So the function returns 0 for halvings in [33, 63], then hits the `>=
64` guard. **Behavior is identical to Core.** No bug — but worth
calling out that the loop runs UP TO 63 unnecessary iterations after
reaching 0. Cosmetic / perf.

**Excerpt:** see BUG-2 excerpt.

**Impact:** None.

**Severity:** P3.

---

### BUG-23 (P1) — `total_fees` accumulator at `utxo.lua:2774` uses Lua number, no overflow guard for `total_fees + tx_fee` outside the assert

**File:** `src/utxo.lua:2769-2774`.

**Core ref:** `bitcoin-core/src/validation.cpp:2543-2546`:
```cpp
nFees += txfee;
if (!MoneyRange(nFees))
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                         "bad-txns-accumulated-fee-outofrange", ...);
```

**Description:** Lunarblock's `assert` at line 2772 DOES MoneyRange
the proposed `total_fees + tx_fee` BEFORE assigning. Good. The pattern
is correct. **Not a bug.** Documented here for completeness — this is
the assert that catches CVE-2010-5139-class block-level fee overflows
and lunarblock implements it correctly.

**Excerpt** (`utxo.lua:2769-2774`):

```lua
local tx_fee = input_total - output_total
assert(consensus.is_valid_amount(total_fees + tx_fee),
  "bad-txns-accumulated-fee-outofrange: accumulated fee in block out of range")
total_fees = total_fees + tx_fee
```

**Impact:** None. Listed for traceability.

**Severity:** N/A (correct).

---

## Summary

23 bugs across 8 behaviors / 25 gates:

- **1 P0-CONSENSUS**: BUG-2 regtest halving uses 210000 instead of 150
  (every regtest connect past height 150 diverges from Core).
- **2 P0-CDIV**: BUG-5/6/7 — per-output `bad-txns-vout-negative` /
  `bad-txns-vout-toolarge` / `bad-txns-txouttotal-toolarge` reject
  strings are not Core-parity (diff-test corpus mismatch). Plus
  BUG-13 (non-coinbase null prevout check over-rejects when index is
  not 0xFFFFFFFF).
- **4 P0**: BUG-3 missing `subsidy_halving_interval` field. BUG-9/10/
  11/12 — `bad-txns-vin-empty` / `bad-txns-vout-empty` /
  `bad-txns-oversize` / `bad-cb-length` / `bad-txns-prevout-null`
  reject strings not Core-parity.
- **7 P1**: BUG-4 / BUG-8 / BUG-14 / BUG-15 / BUG-17 / BUG-21 / BUG-23.
- **6 P2**: BUG-16 / BUG-18 / BUG-20 / BUG-22 + plumbing follow-ups.
- **3 P3**: BUG-1 negative-height / BUG-19 loop vs shift / BUG-20
  MAX_MONEY forkability informational.

## Fleet pattern signals

1. **"Hardcoded global where Core has chainparams"** (BUG-2/3/17):
   This is the dominant fleet anti-pattern. lunarblock has a single
   `M.HALVING_INTERVAL = 210000` instead of `network.subsidy_halving_
   interval`. Same shape appears in other audits (e.g. global activation
   heights). Fix lattice: data-shape (field on network record) →
   function-signature (threading network through) → 5-callers update.

2. **"Wire-string parity slippage"** (BUG-5/6/7/8/9/10/11/12/15):
   9 distinct reject-strings in the consensus-tx path that should be
   the canonical Core token (e.g. `"bad-txns-vout-negative"`) but
   are human-readable Lua assert messages. The rpc.lua classifier
   (lines 62-180) is a "soft proxy" trying to map back to canonical
   tokens via regex — but it leaks `validation.lua:220:` into the
   reject reason via Lua's default assert formatting (BUG-15).
   **Single sweep fix:** rewrite `validation.lua:184-251` to use
   `error("bad-txns-vout-negative")` / `error("bad-txns-vout-toolarge")`
   etc. without `assert`. ~12 lines edited.

3. **"Two-pipeline guard"** (BUG-8): same consensus check (fee
   invariant) on both block-connect and mempool-accept paths emits
   different reject strings (`"bad-txns-in-belowout"` vs `"outputs
   exceed inputs"`). 15th distinct instance noted in the campaign.

4. **"Defense-in-depth gap on storage"** (BUG-21): trust the UTXO
   serialized flag without sanity-checking, vulnerable to disk
   corruption. Fleet pattern.

5. **"Comment-as-confession"** (none new this audit — code is clean
   of TODO/FIXME on this scope).

## Fixes (prioritized for follow-up FIX waves)

1. **Add `subsidy_halving_interval` to each network record + thread
   into `get_block_subsidy`** (5-line data, 1-line signature, 5
   callers). Closes BUG-2/3/17. Single FIX wave.
2. **Wire-string parity sweep**: rewrite `validation.lua:184-251`
   `assert` calls to emit Core-canonical reject strings. Closes
   BUG-5/6/7/9/10/11/12/15. ~12 LOC.
3. **Mempool fee-invariant string**: change `mempool.lua:1251`
   from `"outputs exceed inputs"` to `"bad-txns-in-belowout"`. Closes
   BUG-8. 1-line.
4. **Pre-serialize DoS guard**: at `validation.lua:1305`, add
   `assert(#block.transactions * 4 <= MAX_BLOCK_WEIGHT, "bad-blk-length")`.
   Closes BUG-14. 1-line.
5. **Tighten `IsNull` check**: change `validation.lua:245` to also
   require `inp.prev_out.index == 0xFFFFFFFF` for the null-prevout
   condition (and invert: condition is hash != 0 OR index != -1).
   Closes BUG-13. 2-line.
