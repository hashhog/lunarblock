# W131 — Descriptors + Miniscript (BIP-380 / BIP-385 / BIP-379) — lunarblock

Date: 2026-05-17
Wave: W131 (Descriptors + Miniscript)
Impl: lunarblock (Lua / LuaJIT)
Scope: BIP-380 output descriptors, BIP-385 raw script descriptors (`raw()` and
`rawtr()`), BIP-389 multipath descriptors, BIP-379 Miniscript.

References:
- bitcoin-core/src/script/descriptor.cpp (3006 LOC)
- bitcoin-core/src/script/miniscript.cpp + miniscript.h (3139 LOC combined)
- bitcoin-core/src/test/descriptor_tests.cpp (1337 LOC)
- bitcoin-core/src/test/miniscript_tests.cpp
- test/functional/test_framework/descriptors.py (golden Python implementation
  of `descsum_create` / `descsum_check` used to cross-check below)

Lunarblock surface:
- `src/address.lua` — `descriptor_checksum`, `validate_descriptor_checksum`,
  `parse_descriptor`, `descriptor_to_script`, `derive_address`,
  `derive_addresses`, `get_descriptor_info`, `parse_key_expression`,
  `derive_child`, `derive_path` (BIP-32 CKD).
- `src/miniscript.lua` — Type system (B/V/K/W + properties), Fragment enum,
  node constructors, `to_script` compiler, `from_policy` (policy → MS),
  `satisfy` (witness production), type analysis helpers.
- RPC wiring (`src/rpc.lua`): `getdescriptorinfo`, `deriveaddresses`,
  bare `multi()` / `rawtr()` inference at decode_script_pubkey.

NOT present in lunarblock:
- BIP-389 multipath `<0;1>/*` parsing.
- BIP-381 MuSig2 `musig(...)` aggregation primitive.
- TR script-tree compilation (lunarblock stores `tree` field as the raw text
  but `descriptor_to_script` IGNORES it — see BUG-12).
- Miniscript-from-script decoder (`FromScript`).
- Miniscript-from-string parser (`FromString`).
- Miniscript as descriptor inner (`wsh(<miniscript>)`, `tr(K,{<miniscript>})`).
- `MiniscriptContext` distinction between P2WSH and TAPSCRIPT.
- `combo()` 4-script expansion (Core: returns 4 scriptPubKeys per index; we
  return only P2PKH).
- `descsum_check` with relaxed/no-checksum: see Method/API gap below.

## 30-gate audit matrix

Legend: PASS = correct vs Core. BUG = divergence vs Core. MISSING = feature
absent. PARTIAL = present but incomplete.

| # | Gate | Status | Notes |
|---|------|--------|-------|
| G1 | BIP-380 checksum polynomial (PolyMod) constants | PASS | `0xf5dee51989`, `0xa9fdca3312`, `0x1bab10e32d`, `0x3706b1677a`, `0x644d626ffd` — match Core. Uses 40-bit XOR helper to work around LuaJIT 32-bit `bit.bxor`. |
| G2 | BIP-380 INPUT_CHARSET | PASS | Identical 96-char alphabet to Core `descriptor.cpp:121-124`. |
| G3 | BIP-380 CHECKSUM_CHARSET (bech32) | PASS | `qpzry9x8gf2tvdw0s3jn54khce6mua7l` matches Core. |
| G4 | Golden cross-check vs Python ref | PASS | 5/5 fixtures match `descsum_create` output exactly (raw/pk/pkh/wpkh + BIP-32 origin). See test G4. |
| G5 | Checksum length boundary detection (`#cksum` must be 8 chars) | PARTIAL | `validate_descriptor_checksum` correctly rejects length ≠ 8. `parse_descriptor` rejects mismatch but does not distinguish "wrong length" vs "wrong content" — Core emits `Expected 8 character checksum, not N characters` for length mismatch which is a separate error path. BUG-1. |
| G6 | Multiple `#` symbols rejected | PASS | Lunarblock rejects `desc##cksum` (the second `#` becomes part of checksum, fails 8-char check). Behaves correctly. |
| G7 | `pk(K)`, `pkh(K)`, `wpkh(K)`, `combo(K)` at top level | PARTIAL | Parse + script generation work for compressed pubkey. `combo()` ONLY emits P2PKH; Core expands to 4 scripts (P2PK, P2PKH, P2WPKH, P2SH-P2WPKH) per index. BUG-2. |
| G8 | `wpkh(K)` rejects uncompressed pubkey | BUG | Lunarblock accepts a 65-byte uncompressed key into `wpkh()` and silently HASH160s it (`0014b5bd...`). Core rejects: `Uncompressed key are not allowed`. BUG-3. |
| G9 | `sh(...)` only at top level, `wsh(...)` only at top level or in sh | BUG | Lunarblock allows `sh(sh(...))`, `wsh(wsh(...))`, `sh(addr(...))`, `wsh(wpkh(...))`. Core enforces context: `Can only have sh() at top level`, `Can only have wsh() at top level or inside sh()`, `Can only have wpkh() at top level or inside sh()`. BUG-4. |
| G10 | `addr(ADDR)` accepts only at top level | BUG | Lunarblock parses `sh(addr(...))` as `sh` whose inner is `addr`. Core: `Can only have addr() at top level`. BUG-5. |
| G11 | `raw(HEX)` and `rawtr(XONLY)` only at top level | PARTIAL | Both work at top level; `rawtr` strictly requires 64-hex (32-byte) — implemented. But `raw()` and `rawtr()` allowed inside `sh()`/`wsh()` because parser is recursive without context check. BUG-6 (paired with G9/G10). |
| G12 | `multi(k, ...)` 1 ≤ k ≤ n, n ≤ 20 (P2WSH) / n ≤ 999 (multi_a / Tapscript) | BUG | Lunarblock allows multi(0, ...) (k=0 has no `nrequired` enforcement at descriptor layer) and allows 17+ keys at top level without rejecting (Core caps `multi()` to 20 keys; bare `multi()` is non-standard above 3-of-3). Lunarblock returns the parsed result with `threshold=3, #keys=2` for `multi(3, pk, pk)` and validates only at `descriptor_to_script` opcode push (which silently emits OP_3 OP_2 OP_CHECKMULTISIG → INVALID). BUG-7. |
| G13 | `sortedmulti` lex-sorts pubkey bytes | PASS | `descriptor_to_script` invokes `table.sort(pubkeys)` which is lex-order on strings. Cross-checked: declared (pk1=03…, pk2=02…) → script bytes have pk2 first. PASS. |
| G14 | `tr(K)` requires x-only (32-byte) internal key | BUG | Lunarblock accepts 33-byte compressed key in `tr()` and strips the prefix byte. Core (`ParsePubkeyInner` in `P2TR` context) REJECTS non-x-only keys. BUG-8. |
| G15 | `tr(K, TREE)` script-tree compilation | MISSING | Lunarblock stores `tree` as RAW STRING and IGNORES it at `descriptor_to_script` (returns key-path-only output). Two different `tr(K)` and `tr(K, pk(K'))` descriptors yield IDENTICAL P2TR addresses — script-path commits LOST. BUG-9. |
| G16 | `rawtr(XONLY)` no taproot tweak (BIP-385) | PASS | `descriptor_to_script` for `rawtr` emits `OP_1 <32-byte hex>` literally without tweaking. Matches Core. |
| G17 | Range expansion `/0/*` for non-extended keys ERRORS | BUG | Lunarblock parses `wpkh(<raw-pubkey>/0/*)` (raw 33-byte hex, no xpub/xprv) and `derive_addresses` happily returns 4 IDENTICAL addresses (the raw pubkey can't be derived from). Core: `Key path that ends with /*: cannot be extended`. BUG-10. |
| G18 | Hardened-from-xpub gives clear error at derivation | PASS | Lunarblock's `derive_path` propagates the `crypto.ec_pubkey_tweak_add` failure, returning nil with `hardened derivation requires private key`. PASS. |
| G19 | `get_descriptor_info` reports `hasprivatekeys` correctly | BUG | Lunarblock hardcodes `hasprivatekeys = false` even when WIF / xprv / combination is present. Core: `bool has_private_keys` true iff any sub-key has a private key. BUG-11. |
| G20 | `get_descriptor_info` reports `issolvable` correctly | PASS | Reports `false` for `addr()` and `raw()`, `true` for everything else. Matches Core (no `provider` access to private keys is required). |
| G21 | BIP-389 multipath `<0;1>/*` parses to N descriptors | MISSING | Lunarblock rejects `<0;1>` with `invalid path element: <0;1>`. Core supports it since v24.0 (BIP-389). BUG-12. |
| G22 | Origin path `[fingerprint/path]` accepts both `h` and `'` for hardened | PASS | `parse_key_expression` accepts both `h` and `'`. Both map to `index + 0x80000000`. Matches Core. |
| G23 | Origin fingerprint must be 8 hex chars | PASS | `parse_key_expression` rejects `[deadbee/...]` (7 hex) and `[deadbeef0/...]` (9 hex). Matches Core. |
| G24 | Miniscript fragment type system (B/V/K/W/zonduefmsxk) | BUG | Most types correct, but: (a) THRESH `compute_type` requires ALL subs to be `Bdu` — Core requires subs[0]=`Bdu`, subs[1..n-1]=`Wdu`. Lunarblock effectively rejects every valid `thresh()` with wrapped sub-expressions. (b) THRESH `e` property: Core requires `all_e && num_s == n_subs`; lunarblock has `all_e && num_s >= n - k` (LOOSER). BUG-13 / BUG-14. |
| G25 | `older(n)` time-vs-height type bit (`g` vs `h`) | BUG | Lunarblock decides `older(n)` height-vs-time by `n >= 500_000_000` (LOCKTIME_THRESHOLD). Core decides by `n & SEQUENCE_LOCKTIME_TYPE_FLAG` (bit 22 = `0x400000`). For n in `[400000, 0x3fffff]` lunarblock incorrectly classifies as relative-height; for n with bit 22 set but `< 500M` lunarblock misclassifies. BUG-15. |
| G26 | `d:` wrapper has `u` property under Tapscript context | BUG | Per Core comment `miniscript.cpp:125`: `d:` is `u` under Tapscript but NOT under P2WSH (MINIMALIF is a policy rule, not consensus). Lunarblock's `WRAP_D` never adds `u` regardless of context. Lunarblock has no `MiniscriptContext` distinction at all. BUG-16. |
| G27 | `from_policy` → miniscript compilation | PARTIAL | Works for many cases, but: (a) `or(...)` strategy is hardcoded heuristic (`or_d` if x is Bdu else `or_i`); Core compiler considers all variants and picks by cost. (b) `and(...)` only emits `and_v` and never `and_b`. Best-effort, NOT a true compiler. PARTIAL. |
| G28 | `wsh(<miniscript>)` parses as descriptor | MISSING | Lunarblock's `parse_descriptor` recognises only a fixed name list (pk, pkh, wpkh, sh, wsh, multi, sortedmulti, tr, addr, raw, combo, rawtr). `wsh(or_d(pk(K1),and_v(v:pk(K2),older(100))))` returns `invalid wsh inner: invalid descriptor format`. Cannot use miniscript inside any descriptor. BUG-17. |
| G29 | Miniscript-from-script decoder (`FromScript`) | MISSING | No `from_script` / `FromScript` function exported. `InferScript` analog absent. Cannot round-trip script→miniscript. BUG-18. |
| G30 | `musig(...)` BIP-381 MuSig2 primitive in descriptors | MISSING | Lunarblock has no `musig()` parser. Core supports it via `MuSigPubkeyProvider` since v28. BUG-19. |

## Cumulative findings

PASS: 11 (G1, G2, G3, G4, G6, G13, G16, G18, G20, G22, G23)
PARTIAL: 5 (G5, G7, G11, G12 — split, G27)
BUG: 14 (G8, G9, G10, G11, G12, G14, G15, G17, G19, G21, G24, G25, G26, G28)
MISSING: ≥4 features (multipath, musig, tr-tree, miniscript-as-descriptor, ms-from-script, combo expansion)

Total **19 distinct BUGs catalogued** (some gates cover multiple). Distribution
by severity:

- **P0 (consensus-divergent script bytes)**: BUG-9 (tr-tree ignored → wrong
  output key on every script-path tr descriptor), BUG-3 (wpkh accepts
  uncompressed → wrong scriptPubKey), BUG-7 (multi k=0 / k>n → builds invalid
  script silently), BUG-15 (older() type misclassification → can mis-validate
  timelock-mixing rule).
- **P1 (correctness / spec-violation, no consensus impact)**: BUG-4, BUG-5,
  BUG-6 (context enforcement), BUG-8 (tr-key compressed), BUG-10 (range on raw
  key), BUG-13 (thresh Bdu/Wdu), BUG-14 (thresh `e` looser), BUG-16
  (Tapscript `d:u`), BUG-17 (no miniscript in descriptor).
- **P2 (missing feature)**: BUG-12 multipath, BUG-18 from_script, BUG-19
  musig, BUG-2 combo-expansion, BUG-11 hasprivatekeys, BUG-1 length-error
  granularity.

## Top 5 findings

1. **BUG-9 P0 tr() script-tree is silently dropped on output script.**
   `descriptor_to_script` line 1196-1209 only applies the TapTweak with an
   empty merkle root (`crypto.tagged_hash("TapTweak", xonly)`). The tree text
   stored in `desc.tree` is never parsed and never folded into the tweak. Two
   descriptors that differ ONLY by tree (e.g. `tr(K)` vs `tr(K,pk(K'))`)
   produce IDENTICAL P2TR addresses. **Real-world impact**: any wallet that
   imports a script-path descriptor and tries to derive a receive address
   would receive funds at the key-path-only address, and the script-path
   commitment would never be visible on-chain — funds locked to the wrong
   output. This is the single highest-severity finding.

2. **BUG-3 P0 wpkh() accepts uncompressed pubkey.** `parse_descriptor`
   accepts the 65-byte uncompressed-pubkey hex inside `wpkh()` and
   `descriptor_to_script` happily HASH160s the 65 bytes. The resulting
   P2WPKH output is illegal per BIP-141 (must be from a compressed key for
   v0 witness program) and Core REJECTS this descriptor. lunarblock would
   produce an address that Core nodes would reject as nonstandard.

3. **BUG-13 / BUG-14 P1 THRESH type computation rejects every valid `thresh`
   with wrapped subs.** `compute_type` line 528 requires every sub to be
   `Bdu`. Per BIP-379 and Core `miniscript.cpp:237`, only `subs[0]` must be
   `Bdu`; `subs[1..n-1]` must be `Wdu`. The only way to satisfy lunarblock's
   constraint is to have every sub be base `B` — but then the compiled
   script is not a valid miniscript. Practical effect: `thresh(2, pk(A),
   s:pk(B), s:pk(C))` (the canonical k-of-n form) raises
   `thresh requires Bdu subexpressions` on construction. Compounded by
   BUG-14: even if the type check passed, the `e` property bit would be
   computed too leniently (Core: `all_e && num_s == n_subs`; lunarblock:
   `all_e && num_s >= n - k`).

4. **BUG-17 + BUG-18 P1 Miniscript is not wired into descriptors at all.**
   `parse_descriptor` recognises only the fixed name list; the miniscript
   module has no `from_string` parser nor `from_script` decoder. So
   `wsh(<miniscript>)` and `tr(K,{<miniscript>})` (the entire BIP-379
   delivery channel for miniscript on chain) are unparsable. The miniscript
   module is effectively an orphan library that can compose ms ASTs and
   serialize them to script, but cannot be invoked through the descriptor
   surface. **Pattern flagged for cross-impl audit**: "orphan miniscript"
   may show up elsewhere.

5. **BUG-15 P0 OLDER() type bit uses LOCKTIME_THRESHOLD instead of
   SEQUENCE_LOCKTIME_TYPE_FLAG.** `compute_type` line 193: `if node.k >=
   LOCKTIME_THRESHOLD then T.g else T.h`. Core (`miniscript.cpp:92-93`)
   uses `k & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG` (bit 22 = `0x400000`).
   The wrong bit selection mis-classifies `older(n)` as relative-height
   when it should be relative-time for n with bit 22 set, and vice versa.
   This affects the timelock-mixing `k` property propagation (BIP-379
   §"timelock mixing"); a tree with a misclassified older() may falsely
   PASS or FAIL `is_valid_top_level` per timelock-mixing rules.

## Universal patterns

Six patterns to watch for across the W131 fleet audit:

- **"orphan miniscript" pattern**: miniscript module exists but is not
  reachable from `parse_descriptor`. Test: does
  `parse_descriptor("wsh(or_d(pk(K),and_v(v:pk(K),older(100))))")` parse?
- **"tree silently dropped" pattern**: `tr(K, TREE)` produces the same
  address as `tr(K)`. Test: assert two `tr()` outputs with different trees
  produce DIFFERENT P2TR addresses.
- **"combo only emits one script" pattern**: `combo(K)` returns just P2PKH
  instead of 4. Test: derive script range from `combo()` and assert 4
  scriptPubKeys returned per index, not 1.
- **"tr accepts compressed pubkey" pattern**: silently strips the prefix
  byte. Test: `tr(03<32-byte hex>)` should ERROR, not silently re-interpret.
- **"thresh type confusion" pattern**: requires Bdu for all subs instead
  of `Bdu, Wdu, Wdu, …`. Test: `thresh(2, pk, s:pk, s:pk)` should compile.
- **"older() bit-22 vs 500M" pattern**: classifies time-vs-height by wrong
  threshold. Test: `older(0x400000)` should be relative-TIME (g), not
  relative-height (h).

## Out of scope

- Miniscript SATISFY logic correctness (witness production / size). Lunarblock
  has `M.satisfy` but cross-checking against Core's `produce_input` requires
  ~1000 vector lines and is beyond a 30-gate scope.
- BIP-32 derivation edge cases (already covered W118).
- Wallet integration (already covered W118).
- PSBT signing of descriptor-derived inputs (already covered W118/wave 53).
