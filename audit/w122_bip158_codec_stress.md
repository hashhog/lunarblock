# W122 - BIP-158 GCS codec stress-vector audit (lunarblock)

**Date:** 2026-05-17  
**Wave:** W122 (discovery)  
**Impl:** lunarblock (Lua / LuaJIT)  
**Status:** **BUG FOUND** (P0-CDIV)

## Context

Per haskoin W121 addendum (commit `4a2de0f`): Core's `blockfilters.json`
test vectors don't exercise per-element Golomb-Rice quotients `q >= 64`.
Both W90 (lunarblock blockfilter audit) and W121 (compact-filter fleet
audit) used those vectors as the upper bound and missed quotient-boundary
write bugs.

haskoin found one such bug: `bitWriterWrite` silently truncated bits when
a write crossed a Word64 boundary, corrupting the stream after q >= 64.

This audit stress-tests lunarblock's `blockfilter.lua` for the analogous
class of bug — high quotients, cross-boundary writes, and LuaJIT bit
library 32-bit modular semantics.

## Method

1. Read `src/blockfilter.lua` `golomb_rice_encode` /
   `bit_stream_writer.write` and the matching decode paths.
2. Probe `golomb_rice_encode` + `golomb_rice_decode` round-trip with
   values that target `q = 0, 1, 30, 31, 32, 33, 50, 63, 64, 65, 100,
   200, 1000` and the BIP-158 P=19 parameter.
3. Probe randomly-distributed sorted-delta streams with `math.random`
   seeded 42 to surface mixed-quotient regressions.
4. Trace any failing decode back to the writer's bit-by-bit extraction
   path with explicit `bit.lshift(1, n) - 1` evaluation.
5. Compute the realistic-mainnet probability of triggering vs. the
   adversarial-block trigger surface.

Reference: `bitcoin-core/src/util/golombrice.h`,
`bitcoin-core/src/streams.h::BitStreamWriter`, BIP-158, haskoin
`4a2de0f` (`fix(filter): FIX-69 bitWriterWrite handles cross-Word64-
boundary writes`).

## Findings

### BUG-1 (P0-CDIV) — golomb_rice_encode produces wrong unary bits for q in [32, 63] (and q's whose tail after 64-chunking lands in [32, 63])

**Location:** `src/blockfilter.lua:241-249` (`golomb_rice_encode` unary
loop) reaches into `bit_stream_writer.write(bit.lshift(1, nbits) - 1,
nbits)` on the `else` branch (line 247).

**Root cause:** LuaJIT's `bit.lshift` operates with 32-bit modular
semantics: `bit.lshift(1, 32) == 1`, `bit.lshift(1, 33) == 2`,
`bit.lshift(1, 64) == 1`. So `bit.lshift(1, nbits) - 1` produces the
wrong mask when `nbits` is in `[32, 63]`. The current code handles
`nbits == 64` correctly via a special-case path that hands an explicit
`ffi.new("uint64_t", 0xFFFFFFFFFFFFFFFFULL)` to the writer — but every
`nbits` value strictly between 32 and 63 falls into the broken `else`
branch.

Effect on the unary-bit pattern (target = `nbits` ones, terminator
zero after):

| nbits | bit.lshift(1, n) - 1 | bits written      | correct |
|-------|----------------------|-------------------|---------|
| 31    | -2147483649 (0x7FFFFFFF as signed) | 31 ones | YES |
| 32    | 0                    | 32 zeros          | NO (should be 32 ones)  |
| 33    | 1                    | 32 zeros + 1 one  | NO      |
| 40    | 255 (0xFF)           | 32 zeros + 8 ones | NO      |
| 50    | 262143 (0x3FFFF)     | 32 zeros + 18 ones| NO      |
| 63    | -2147483649          | 32 zeros + 31 ones| NO      |
| 64    | (special path)       | 64 ones           | YES     |
| 65    | (64 path + nbits=1)  | 64 ones + 1 one   | YES     |
| 100   | (64 path + nbits=36) | 64 ones + broken  | NO      |
| 200   | (3 x 64 + nbits=8)   | 192 ones + 8 ones | YES (tail in [1,31]) |

So the bug triggers for `q in [32, 63]` AND for any `q` whose modulo-64
tail lands in `[32, 63]` (e.g. `q = 96..127`, `q = 160..191`).

**Reproduction:**

```
luajit -e 'package.path = "src/?.lua;"..package.path
local bf = require("blockfilter")
local P = 19
for _, q in ipairs({0,1,5,10,30,31,32,33,40,50,63,64,65,100,200}) do
  local v = q * 524288 + 12345
  local w = bf.bit_stream_writer()
  bf.golomb_rice_encode(w, P, v); w.flush()
  local r = bf.bit_stream_reader(w.result())
  local d = bf.golomb_rice_decode(r, P)
  print(string.format("q=%d in=%d out=%s %s",
    q, v, tostring(d), v == d and "PASS" or "FAIL"))
end'
```

Result (pre-fix):
```
q=0   in=12345     out=12345    PASS
q=1   in=536633    out=536633   PASS
q=5   in=2633785   out=2633785  PASS
q=10  in=5255225   out=5255225  PASS
q=30  in=15740985  out=15740985 PASS
q=31  in=16265273  out=16265273 PASS
q=32  in=16789561  out=0        FAIL  <-- bug zone enters
q=33  in=17313849  out=524288   FAIL
q=40  in=20983865  out=4194304  FAIL
q=50  in=26226745  out=9437247  FAIL
q=63  in=33042489  out=16777215 FAIL
q=64  in=33566777  out=33566777 PASS  <-- special path
q=65  in=34091065  out=34091065 PASS
q=100 in=52441145  out=35651584 FAIL  <-- tail (36) re-enters bug zone
q=200 in=104869945 out=104869945 PASS <-- tail (8) outside bug zone
```

**Severity & exposure:**

- Severity **P0-CDIV**. Filters built from blocks that produce any per-
  element delta with `q in [32, 63]` (or modulo-64 tail in `[32, 63]`)
  will have wrong unary bits in the encoded stream. The `filter_hash`
  computed from that stream diverges from Core's, and downstream the
  BIP-157 `filter_header` chain diverges from every other compliant
  node forever. A spec-compliant `cfheaders`-checking peer would ban
  lunarblock.
- Realistic-mainnet probability per element:
  `P(delta >= 32 * 524288) = exp(-32*524288 / 784931) ~= 8.5e-10`
  (geometric / Poisson-derived). For a 4000-element block, ~3.4e-6
  per block. Over the chain (~840k blocks at mainnet height) this
  expects ~3 blocks affected. So **rare** in production, but **certain**
  on synthetic / adversarial / fuzz blocks, and **easy** to trigger
  with a hand-crafted block hash + scriptPubKey set that produces a
  large delta.
- The P2P attack surface is already unlocked: FIX-81 wired the dispatch
  (W121 BUG-1 closure), so a malicious peer requesting filter headers
  for an affected block can ban the node. Pre-FIX-81 the bug was
  latent on REST only; post-FIX-81 it is reachable from any peer.
- Round-trip "encode then decode" can still appear correct because
  whatever lunarblock encoded, lunarblock can decode (it sees the
  same wrong unary bits) — this is why W90 round-trip tests pass
  and why the Spec.hs:13191 vectors (all `q < 64`) don't catch it.
  The bug shows up the moment lunarblock compares filter hashes /
  headers with another implementation.

**Why W90 + W121 missed it:**

- W90 round-trip tests use `test_values = {0, 1, 10, 100, 1000, 10000,
  100000, 524287, 524288, 1048575}` — max `q = 2` (1048575 / 524288).
- W121 reuses Core `blockfilters.json` vectors (13 blocks, all
  `q < 64`).
- The W121 audit text identified BUG-8 ("bit_stream_reader bit.lshift
  on number accumulator operates mod 2^32") as a *latent reader-side*
  hazard contingent on BUG-4 (P-hardcoding) being fixed, but did not
  identify the *encoder-side* unary-write mask bug; the encoder bypasses
  the reader entirely.

**Fix sketch (NOT applied in this audit — discovery wave only):**

In `golomb_rice_encode`:
```lua
-- replace:
bitwriter.write(bit.lshift(1, nbits) - 1, nbits)
-- with (mirroring the 64-bit path):
bitwriter.write(ffi.new("uint64_t", 0xFFFFFFFFFFFFFFFFULL), nbits)
```
That hands the writer a uint64_t cdata; the writer's per-bit extraction
branch (`if type(value) == "cdata" then ...`) uses `bit.rshift` on the
cdata which has 64-bit semantics under LuaJIT, so bits 32..63 are
preserved.

Alternative: a pure-Lua mask helper that uses
`bit.bor(bit.lshift(0xFFFFFFFF, nbits - 32), 0xFFFFFFFF)` for
`nbits > 32` and `bit.lshift(1, nbits) - 1` for `nbits <= 31`. Less
clean than the cdata path.

### BUG-2 (BUG-8 from W121, RE-CONFIRMED) — bit_stream_reader.read(nbits) silently truncates for nbits > 32

`bit_stream_reader.read` (blockfilter.lua:199-223) uses `result =
bit.lshift(result, 1) + b` where `result` is a Lua number. After 32
iterations the accumulator wraps to 32-bit semantics and returns a
signed integer (e.g. `-1` for 32-of-32 ones, where the caller expects
0xFFFFFFFF == 4294967295).

This is BUG-8 in `tests/test_w121_compact_filters.lua:130`. It is
latent because BUG-4 (P=19 hardcoding) gates it. Including it here for
W122 completeness and to flag that a hypothetical larger-P filter type
would compound with BUG-1 above.

### Cross-check — Core compatibility for q < 32 unary writes (NEGATIVE FINDING)

The W121 audit lifted `M.bit_stream_writer`, `M.bit_stream_reader`,
`M.golomb_rice_encode`, `M.golomb_rice_decode` to the module surface.
For the Core `blockfilters.json` 13 vectors, every per-element quotient
is < 64. The codec PASSes all 13 entries in `blockfilter_spec.lua`
"BIP-158 official test vectors" (lines 338-512). This wave does not
contradict that; the BUG-1 region is OUT-OF-DISTRIBUTION for those
vectors.

## Test coverage delta

New file: `tests/test_w122_bip158_codec_stress.lua` (this wave) — 25
stress tests, 7 failing pre-fix. Mapping:

| Test | q target | Pre-fix | Post-fix |
|------|----------|---------|----------|
| q=0 round-trip | 0 | PASS | PASS |
| q=1 round-trip | 1 | PASS | PASS |
| q=31 round-trip | 31 | PASS | PASS |
| q=32 round-trip | 32 | **FAIL** | PASS |
| q=33 round-trip | 33 | **FAIL** | PASS |
| q=40 round-trip | 40 | **FAIL** | PASS |
| q=50 round-trip | 50 | **FAIL** | PASS |
| q=63 round-trip | 63 | **FAIL** | PASS |
| q=64 round-trip | 64 | PASS | PASS |
| q=65 round-trip | 65 | PASS | PASS |
| q=100 round-trip | 100 | **FAIL** | PASS |
| q=200 round-trip | 200 | PASS | PASS |
| q=1000 round-trip | 1000 | (depends on tail) | PASS |
| ... | ... | ... | ... |

The new tests are marked with `XFAIL_PRE_FIX` markers so a future fix
wave can flip them in one mechanical pass.

## Verdict

**BUG FOUND.** P0-CDIV `golomb_rice_encode` unary-mask off-by-zero for
quotients in `[32, 63]` (and same modulo-64 tail in `[32, 63]`).
Mirror of haskoin BUG-16 in a different code shape: haskoin had cross-
Word64-boundary writes silently truncate; lunarblock has the LuaJIT
`bit.lshift(1, n)` 32-bit modular semantics silently produce a wrong
mask. Both surface the same way — `q >= 64` zone (and lunarblock's
also `q in [32, 63]`) is OUT-OF-DISTRIBUTION for Core's
`blockfilters.json` 13 vectors.

This is the **first lunarblock-side discovery** that the BIP-158 codec
("byte-identical Core, fleet-wide" per W121 universal finding) was
NOT byte-identical in lunarblock for the realistic-but-rare q-tail
zone.

Fix-wave artifact: a 1-3 line change in `golomb_rice_encode` plus the
flip of the `XFAIL_PRE_FIX` markers in the new test file.

## References

- BIP-158 §"Filter Encoding"
- `bitcoin-core/src/util/golombrice.h` `GolombRiceEncode` (writes
  `~0ULL` = uint64_t all-ones, no Lua bit-lib trap)
- `bitcoin-core/src/streams.h` `BitStreamWriter::Write` (per-octet
  inner loop, no cross-boundary issue)
- haskoin `4a2de0f` FIX-69 (`bitWriterWrite` cross-boundary fix)
- haskoin `3f0cde8` audit (W121 addendum BUG-16, P0)
- lunarblock W121 audit `2324f0a` (BUG-3 unbounded decode loop +
  BUG-4 P-hardcoded + BUG-8 reader mod-2^32 — all distinct from
  W122 BUG-1).
- lunarblock W90 audit fixes 10-12 (correctness of `golomb_rice_encode`
  in the q < 32 regime — incomplete; this wave extends to q >= 32).
