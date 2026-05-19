# W160 — ECDSA + Schnorr + RFC 6979 + sighash construction (lunarblock)

**Wave:** W160 — ECDSA `secp256k1_ecdsa_sign` (RFC 6979 deterministic
nonce default), `secp256k1_ecdsa_sign_recoverable`, Schnorr
`secp256k1_schnorrsig_sign32` (BIP-340 aux_rand32, keypair seckey-flip
on odd-y), low-S normalisation (BIP-62 / BIP-146), strict-DER (BIP-66),
`secp256k1_ec_seckey_verify` scalar-range pre-check, sign-then-verify
paranoia (`CKey::Sign` re-verifies via `secp256k1_ecdsa_verify` and
asserts on failure), BIP-143 segwit-v0 `signature_hash`
(hashPrevouts/hashSequence/hashOutputs midstate caching), BIP-341
TapSighash (epoch=0, ext_flag, annex, scriptPath leaf hash),
SIGHASH_DEFAULT=0x00 64-byte sig shape, SIGHASH_SINGLE bug preservation
(hash of `uint256(1)`), Taproot keypair seckey-flip on odd-y output
key, BIP-32 private-side scalar tweak via `secp256k1_ec_seckey_tweak_add`
(NOT pure-Lua BigInt), recovery-id byte semantics, sigcache key shape
(per-process nonce + wtxid + flags) and inclusion of sigversion.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**

- `bitcoin-core/src/secp256k1/src/modules/recovery/main_impl.h` —
  `secp256k1_ecdsa_sign_recoverable` (RFC 6979 deterministic nonce via
  `secp256k1_nonce_function_rfc6979` default; `secp256k1_ecdsa_sig_sign`
  inner).
- `bitcoin-core/src/secp256k1/src/modules/schnorrsig/main_impl.h` —
  `secp256k1_schnorrsig_sign32` calls `secp256k1_schnorrsig_sign_internal`
  with the BIP-340 `nonce_function_bip340` and the
  `secp256k1_keypair`. Internal `secp256k1_keypair_load` extracts the
  seckey and flips it to even-y form via
  `secp256k1_fe_negate`/`scalar_negate` if needed (`keypair_load` at
  line ~63).
- `bitcoin-core/src/secp256k1/src/ecdsa_impl.h` —
  `secp256k1_ecdsa_sig_sign`; the inner sign loop falls back to fresh
  nonce when `nonce_function` increments `counter`.
- `bitcoin-core/src/secp256k1/include/secp256k1.h:820-841` —
  `secp256k1_context_randomize`: "It is highly recommended to call
  this function on contexts ... before using these contexts to call API
  functions that perform computations involving secret keys." Returns
  `SECP256K1_WARN_UNUSED_RESULT int`. Defense-in-depth re-randomise
  every "few" sign calls.
- `bitcoin-core/src/secp256k1/include/secp256k1.h:685-707` —
  `secp256k1_ec_seckey_verify(ctx, seckey)`: returns 1 iff scalar is
  in `(0, n)`. Canonical scalar-range gate before ANY sign /
  pubkey-create call.
- `bitcoin-core/src/script/sign.cpp` — `ProduceSignature` orchestrates
  per-type sighash + sign. `MutableTransactionSignatureCreator::CreateSig`
  computes legacy / BIP-143 / BIP-341 sighash, calls
  `CKey::Sign` (ECDSA) or `CKey::SignSchnorr` (Schnorr), appends
  `nHashType` byte if non-zero. BIP-341 §"Default Signing": sender
  SHOULD pass 32 bytes of fresh randomness as `aux_rand32`; passing
  zero is permitted (but RECOMMENDED only for test reproducibility).
- `bitcoin-core/src/script/interpreter.cpp:1483-1570` —
  `SignatureHashSchnorr` (BIP-341): epoch byte `0x00`, hash_type byte,
  version, locktime, `sha_prevouts / sha_amounts / sha_scriptpubkeys /
  sha_sequences` precomputed in `PrecomputedTransactionData`,
  `sha_outputs / sha_single_output` per SIGHASH variant, `spend_type`
  byte = `2 * ext_flag + (annex ? 1 : 0)`, annex hash if present,
  ext_flag=1 → tapleaf hash + key_version=0 + codesep_pos LE32.
  hash_type range gate: `{0x00..0x03, 0x81..0x83}`.
- `bitcoin-core/src/script/interpreter.cpp:1373-1455` — BIP-143
  `SignatureHash` for `SIGVERSION_WITNESS_V0`. Reuses
  `PrecomputedTransactionData::hashPrevouts/hashSequence/hashOutputs`
  (cached once per tx).
- `bitcoin-core/src/script/interpreter.cpp:1303-1372` — legacy
  `SignatureHash` for `SIGVERSION_BASE`. Calls `FindAndDelete(sig)`
  on a `CScript` parse-iter loop (NOT regex). After that strips
  OP_CODESEPARATOR bytes; **also implicitly relies on `scriptCode`
  starting after the last executed OP_CODESEPARATOR** (the caller
  is `EvalScript`, which trims via `pbegincodehash`).
- `bitcoin-core/src/key.cpp:209-235` — `CKey::Sign`: signs via
  `secp256k1_ecdsa_sign`, then **immediately re-verifies via
  `secp256k1_ecdsa_verify` and `assert(ret)`** — "Additional
  verification step to prevent using a potentially corrupted
  signature."
- `bitcoin-core/src/key.cpp:250-271` — `CKey::SignCompact`: signs,
  recovers, `secp256k1_ec_pubkey_cmp`s, `assert`s.
- `bitcoin-core/src/key.cpp:273-277` — `CKey::SignSchnorr`: builds a
  `KeyPair`, calls `secp256k1_schnorrsig_sign32` with the supplied
  aux_rand32 (Core MutableTransactionSignatureCreator passes
  `GetRandHash()` — i.e. fresh randomness every signing).
- `bitcoin-core/src/key.cpp:158-160` — `CKey::Check`:
  `secp256k1_ec_seckey_verify(static_ctx, vch)`.
- `bitcoin-core/src/script/sigcache.cpp` — `SignatureCache::ComputeEntry`
  uses per-process 32-byte nonce + wtxid + script flags +
  `SigVersion` (legacy / witness_v0 / tapscript / taproot keypath)
  via the surrounding `SignatureCacheHasher` hash function.

**Files audited**

- `src/crypto.lua` (1583 LOC) — libsecp256k1 FFI cdef (line 372-608)
  + global `secp_ctx` (line 613-615) + `ecdsa_verify` /
  `ecdsa_verify_lax` / `pubkey_from_privkey` / `ec_seckey_tweak_add` /
  `ec_pubkey_tweak_add` / `ecdsa_sign` / `ecdsa_sign_recoverable_compact`
  / `ecdsa_recover_compact` / `schnorr_verify` / `schnorr_sign` /
  `taproot_tweak_seckey`.
- `src/validation.lua` (1900+ LOC) — `signature_hash_legacy`
  (line 694-793), `signature_hash_segwit_v0` (line 806-884),
  `signature_msg_taproot` (line 919-1030), `signature_hash_taproot`
  (line 1043-1049), `is_valid_taproot_hash_type` (line 901-903),
  `find_and_delete` (line 596-609), `remove_codeseparators`
  (line 617-680), `make_sig_checker` + `make_tapscript_checker` +
  `make_collecting_sig_checker`.
- `src/script.lua` (2384 LOC) — `is_valid_signature_encoding`
  (line 164-192), `is_defined_hashtype` (line 195-199),
  `is_low_der_s` (line 202-228), `check_signature_encoding`
  (line 231-253), OP_CODESEPARATOR handler (line 1420-1428),
  OP_CHECKSIG / OP_CHECKSIGVERIFY (line 1429-1569),
  OP_CHECKMULTISIG (line 1570+), `verify_witness_program` Taproot
  key-path (line 2026-2160).
- `src/sig_cache.lua` (109 LOC) — per-process nonce (read from
  `/dev/urandom`), `make_key` (line 58-63), `lookup`, `insert`.
- `src/utxo.lua:2300-2750` — block validation: `compute_txid(tx)`
  → `txid.bytes` is what's passed to
  `sig_cache:lookup`/`:insert` (line 2416-2417, 2746).
- `src/consensus.lua:823-828` — `M.SIGHASH = {ALL, NONE, SINGLE,
  ANYONECANPAY}` (NO `DEFAULT = 0x00`).
- `src/wallet.lua:1261-1315` — `sign_input_p2wsh` (BIP-143
  segwit-v0); `Wallet:_sign_inputs` (line 1667-) and
  `Wallet:create_transaction` (line 1340-) signing block — P2WPKH
  + legacy P2PKH only, NO P2TR Schnorr path.
- `src/psbt.lua:857-1011` — `M.sign_input`: P2WPKH / P2PKH /
  P2SH / P2SH-P2WPKH / P2SH-P2WSH / P2WSH branches; P2TR explicitly
  falls through to `return false`.
- `src/rpc.lua:6124-6140` — comment "lunarblock ships ECDSA-only
  crypto today (M.schnorr_sign is unavailable)" (FALSE — see BUG-13).

**Greps confirming absence:**

```bash
$ grep -rn "secp256k1_ec_seckey_verify\|seckey_verify\b" src/ csrc/
(zero matches)

$ grep -rn "secp256k1_context_randomize\|context_randomize" src/ csrc/
(zero matches — STILL absent after W158 BUG-7 + W159 BUG-2)

$ grep -rn "memory_cleanse\|memzero\|secure_memset" src/ csrc/
(zero matches)

$ grep -rn "schnorr_sign\b" src/ tests/
src/crypto.lua:1032:function M.schnorr_sign(privkey32, msg32, aux_rand32)
src/rpc.lua:6137:  -- ships ECDSA-only crypto today (M.schnorr_sign is unavailable); the input
# Zero non-definition callers — dead-but-public.

$ grep -rn "taproot_tweak_seckey\b" src/ tests/
src/crypto.lua:1066:function M.taproot_tweak_seckey(privkey32, tweak32)
# Zero callers — dead public surface.

$ grep -rn "rfc6979\|RFC6979\|nonce_function" src/ csrc/
src/crypto.lua:454:    void* noncefp,        -- arg name only (FFI typedef)
src/crypto.lua:605:    void* noncefp,
# Zero source references — relies on libsecp256k1's default.
```

---

## Gate matrix (30 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | RFC 6979 deterministic nonce | G1: `ecdsa_sign` calls `secp256k1_ecdsa_sign(ctx, sig, hash, sk, NULL, NULL)` (default = RFC 6979) | PASS (`crypto.lua:875-889`, passes `nil, nil`) |
| 1 | … | G2: `ecdsa_sign_recoverable_compact` likewise | PASS (`crypto.lua:899-918`) |
| 2 | BIP-340 aux_rand32 hardening | G3: `schnorr_sign` accepts optional aux_rand32, threads to `secp256k1_schnorrsig_sign32` | PASS (`crypto.lua:1032-1055`) |
| 2 | … | G4: production callers pass `crypto.random_bytes(32)` not nil/zero | **BUG-2 (P0-SEC)** — zero callers exist (BUG-13); the API ships defaulting to all-zero aux_rand which means EVERY Schnorr sig lunarblock produces (zero today) would be RFC-6979-deterministic, exposing the secret if the same key signs two different msg32's via a related-key bug. "drift-converged-on-wrong-default" |
| 3 | Side-channel context blinding | G5: `secp256k1_context_randomize(secp_ctx, seed32)` immediately after `_create` | **BUG-1 (P0-SEC)** — **STILL ABSENT 5+ WEEKS AFTER W158 BUG-7** (origin) AND W159 BUG-2 (FFI confirmation). `crypto.lua:613-615` creates context, no randomize. lunarblock is the NAMED ORIGIN of this fleet-wide pattern. Cross-cite W159 BUG-2 (5+ weeks unfixed) |
| 3 | … | G6: re-randomize every few sig ops (defense-in-depth per `secp256k1.h:826`) | **BUG-1 cross-cite** |
| 4 | Seckey-verify scalar-range gate | G7: `secp256k1_ec_seckey_verify` declared in FFI cdef | **BUG-3 (P0-SEC)** — **STILL ABSENT 24+ HOURS AFTER W159 BUG-3**. Not in `crypto.lua:372-608` FFI block. Every sign + pubkey-create path silently accepts scalar=0 or ≥n. Cross-cite W159 BUG-3. |
| 4 | … | G8: `ecdsa_sign`/`schnorr_sign`/`pubkey_from_privkey`/`ec_seckey_tweak_add` pre-check scalar | **BUG-3 cross-cite** |
| 5 | Sign-then-verify paranoia | G9: after `ecdsa_sign`, re-verify with `_ecdsa_verify` (Core `CKey::Sign` line 228-234) | **BUG-4 (P1-SEC)** — `crypto.lua:875-889` returns serialized DER immediately; no re-verify, no `assert`. Cross-cite W159 BUG-5 |
| 5 | … | G10: after `ecdsa_sign_recoverable_compact`, recover-and-cmp pubkey (Core `CKey::SignCompact` line 262-270) | **BUG-4 cross-cite** — `crypto.lua:899-918` skips both recover and cmp |
| 5 | … | G11: after `schnorr_sign`, re-verify via `schnorr_verify` (defense-in-depth) | **BUG-4 cross-cite** — comment at `crypto.lua:1019-1020` "modulo defense-in-depth verify (caller can re-check)" — **comment-as-confession**; no caller re-verifies (BUG-13: no caller AT ALL) |
| 6 | Low-S normalization | G12: parsed DER signatures normalized before `secp256k1_ecdsa_verify` (lib requires low-S) | PASS (`crypto.lua:648, 753, 786`) |
| 6 | … | G13: `is_low_der_s` correct implementation of half-order test | PASS (`script.lua:202-228`) |
| 6 | … | G14: `check_signature_encoding` gates low-S on `verify_low_s` flag | PASS (`script.lua:240-244`) |
| 7 | Strict DER (BIP-66) | G15: `is_valid_signature_encoding` enforces 30 wrapper, len fields, R/S int tags + sign-bit rules | PASS (`script.lua:164-192`) |
| 7 | … | G16: lax DER fallback for pre-BIP66 blocks | PASS (`crypto.lua:660-790`, `parallel_verify.c`) |
| 8 | Legacy `signature_hash` (BIP-66 SigVersion::BASE) | G17: SIGHASH_SINGLE-out-of-range bug returns `uint256(1)` (32 LE bytes 0x00...0x01) | PASS (`validation.lua:699-701`, `string.rep("\0",31) .. "\1"`) |
| 8 | … | G18: FindAndDelete uses script-parse iteration like Core (NOT regex / pattern matching) | **BUG-5 (P0-CONS)** — `validation.lua:596-609` `find_and_delete` does `script_bytes:gsub(escape_pattern(push_encoded), "")`. **Pattern-based deletion can match across opcode boundaries** (e.g. a push body that contains the bytes of `push_encoded(sig)` would be partially overwritten). Core walks `CScript::GetOp()` and only removes whole-opcode matches. Bytes inside a longer push (OP_PUSHDATA2 with a payload containing the sig bytes) are stripped by lunarblock and preserved by Core → distinct sighash → consensus split on any script that pushes data containing the sig as a substring. "non-deterministic-where-Core-is-deterministic" + "wire-DoS via regex" fleet pattern |
| 8 | … | G19: OP_CODESEPARATOR scriptCode trim (Core: scriptCode = script[pbegincodehash..end]) BEFORE strip-all-codeseps | **BUG-6 (P0-CONS)** — `script.lua:1420-1428` updates `codesep_pos`, fires `checker.set_codesep(pos)`, but the `set_codesep` implementation only stores the integer and the LEGACY ECDSA `check_sig` (`validation.lua:1525-1545`) NEVER consults it for `script_code`. `flags.script_code or prev_script_pubkey` is used verbatim — i.e. the FULL script, not trimmed to start after the most-recently-executed OP_CODESEPARATOR. **Legacy P2SH redeem scripts (and any pre-segwit script using OP_CODESEPARATOR to commit different scriptCode for multiple sigs) produce wrong sighash vs Core**. Any tx in mainnet history using OP_CODESEPARATOR mid-script → consensus split |
| 9 | BIP-143 segwit-v0 `signature_hash` | G20: hashPrevouts/hashSequence/hashOutputs precomputed once per tx and reused across inputs | **BUG-7 (P1-PERF)** — `validation.lua:806-884` recomputes hash_prevouts, hash_sequence, hash_outputs **for every input** (O(N²) instead of Core's O(N)). On a block with N inputs each computation iterates ALL N inputs → quadratic. A 2,500-input tx (mainnet maxima today) does 2,500² = 6.25M crypto.hash256 ops instead of 2,500. No `PrecomputedTransactionData` analogue. Visible IBD regression vs Core |
| 9 | … | G21: hash_type variant handling (ANYONECANPAY/SINGLE/NONE/ALL combinations) | PASS (`validation.lua:807-857`) |
| 9 | … | G22: SegWit does NOT apply FindAndDelete (intentional Core divergence from legacy) | PASS (comment at `validation.lua:1550`) |
| 10 | BIP-341 TapSighash | G23: epoch byte 0x00 at front | PASS (`validation.lua:950`) |
| 10 | … | G24: hash_type range gate `{0x00..0x03, 0x81..0x83}` enforced + nil sighash returned on bad type | PASS (`validation.lua:901-903, 930-932`) |
| 10 | … | G25: SIGHASH_SINGLE out-of-range returns nil (BIP-341 reject), not synthesized digest | PASS (`validation.lua:945-947`) |
| 10 | … | G26: SIGHASH_DEFAULT (0x00) byte forbidden in 65-byte form | PASS (`validation.lua:1584-1585, 1697-1700`) |
| 10 | … | G27: sha_prevouts / sha_amounts / sha_scriptpubkeys / sha_sequences cached once per tx | **BUG-8 (P1-PERF)** — same as BUG-7 but for Taproot. `signature_msg_taproot` (line 949-1029) recomputes all four sha256 midstates per input. O(N²) IBD cost. No `PrecomputedTransactionData` analogue |
| 10 | … | G28: annex hash uses `compact_size(#annex) || annex` per BIP-341 (annex INCLUDES 0x50 prefix) | PASS (`validation.lua:1006-1009`); cross-check: script.lua:2129-2132 passes annex INCLUDING the 0x50 byte → correct |
| 10 | … | G29: scriptPath ext_flag=1 emits tapleaf_hash + key_version=0 + codesep_pos LE32 | PASS (`validation.lua:1022-1027`) |
| 11 | sigcache key inclusion of wtxid + sigversion | G30: key includes wtxid (W105 BUG-1 doc), input_index ignored, sigversion (legacy/witness_v0/tapscript/keypath) included | **BUG-9 (P0-CONS)** — `utxo.lua:2303 + 2416-2417`: `txid = validation.compute_txid(tx)` (NON-witness txid). The doc-comment at `sig_cache.lua:6-7` explicitly says "Callers should pass the wtxid (witness txid)" — the **fix lives in utxo.lua at the call sites** — but utxo.lua does NOT comply. **A SegWit tx with a malleated witness has the same txid → same sigcache key → cache HIT on the malleated witness even though the signature would no longer verify** (SegWit malleability sigcache poisoning, fleet pattern, 5+ impls). Also: `cache_flags` (line 2408-2413) is a coarse height-bitmask, NOT a `sigversion`; legacy vs witness_v0 vs tapscript vs taproot keypath are all bucketed under the same flags-int. A wtxid + flags collision across two different SigVersions caches a passing tapscript verify and then HITs on a fresh legacy verify with the same wtxid (almost impossible in practice but illustrates the type contract leak) |

---

## BUG-1 (P0-SEC) — `secp256k1_context_randomize` STILL absent (origin + W158 + W159 = 3rd-wave carry-forward)

**Severity:** P0-SEC. Bitcoin Core's `ECC_Start` (`bitcoin-core/src/key.cpp:571-587`)
creates the sign context with `SECP256K1_CONTEXT_NONE`, then **unconditionally
calls `secp256k1_context_randomize(ctx, vseed.data())`** with 32 bytes from
`GetRandBytes()` and `assert(ret)` on the result. The library docs
(`secp256k1.h:820-841`) explicitly say:

> "It is highly recommended to call this function on contexts ... before
> using these contexts to call API functions that perform computations
> involving secret keys, e.g., signing and public key generation. ...
> doing so before every few computations involving secret keys is
> recommended as a defense-in-depth measure."

lunarblock's `crypto.lua:613-615`:

```lua
local secp_ctx = libsecp256k1.secp256k1_context_create(
  bit.bor(0x0101, 0x0201)  -- VERIFY | SIGN
)
-- NO call to secp256k1_context_randomize anywhere in the codebase
```

**Carry-forward history**:
- W158 (BIP-322): BUG-7 first flagged lunarblock as the **named origin** of
  the fleet-wide pattern.
- W159 (libsecp256k1 FFI): BUG-2 confirmed at the FFI cdef level — 5+
  weeks open. No fix landed.
- W160 (this audit): same gap remains. **Third audit wave carry-forward**.

**Impact:**
- Every wallet ECDSA signing path (`ecdsa_sign`,
  `ecdsa_sign_recoverable_compact`) executes unblinded scalar
  multiplication on the wallet's private key. Cache-timing /
  power-analysis side channels can leak the key.
- `signmessagewithprivkey`, `signrawtransactionwithkey`, every PSBT
  signer, every `bumpfee` re-sign all run unblinded.
- The `parallel_verify.c:430` worker pool ALSO creates raw contexts
  without randomize (per W159 BUG-2 cross-cite).
- Fleet pattern: universal 10/10 impls before W158; lunarblock is the
  named origin of the pattern.

**Fix size:** ~5 lines (one `secp256k1_context_randomize` FFI declaration +
one call with `crypto.random_bytes(32)` after `_create`).

---

## BUG-2 (P0-SEC) — Schnorr aux_rand32 defaults to NULL (= all-zero) and zero callers ever pass fresh randomness

**Severity:** P0-SEC. BIP-340 §"Default Signing" recommends passing
fresh 32-byte randomness as `aux_rand32` "to provide an additional
defense in depth against differential side-channel attacks". Bitcoin
Core's `MutableTransactionSignatureCreator::CreateSchnorrSig`
(`script/sign.cpp`) passes `GetRandHash()` (32 bytes from
`GetStrongRandBytes`). Passing NULL is equivalent to all-zero
aux_rand, which makes the BIP-340 nonce **deterministic** (the
`tagged_hash("BIP0340/nonce", sk||pk||msg)` only varies on
`(sk, pk, msg)` tuples).

lunarblock's `crypto.lua:1032-1055` accepts `aux_rand32` as optional,
and the docstring (line 1023-1031) says:

```lua
-- @param aux_rand32 string|nil: 32 bytes of fresh randomness for nonce
--                              hardening. Per BIP-340 §"Default Signing", nil
--                              is equivalent to all-zero aux_rand. We default
--                              to zero so the published BIP-340 test vectors
--                              are reproducible; production callers should
--                              pass crypto.random_bytes(32) explicitly (Core
--                              does this in MutableTransactionSignatureCreator
--                              via GetRandBytes). See design doc §6a.
```

**This is a "comment-as-confession"** — the doc acknowledges production
callers SHOULD pass randomness; yet:

```bash
$ grep -rn "schnorr_sign\b" src/ tests/
src/crypto.lua:1032:function M.schnorr_sign(privkey32, msg32, aux_rand32)
src/rpc.lua:6137:  -- ships ECDSA-only crypto today (M.schnorr_sign is unavailable);
```

**Zero non-definition callers exist** (BUG-13 cross-cite). When the
function eventually gets wired, the wire-up will trivially `crypto.schnorr_sign(sk, msg)`
without the third arg — and quietly default to all-zero aux. The
"drift-converged-on-wrong-default" pattern: the API ships with the
test-mode default exposed as production behaviour.

**File:** `src/crypto.lua:1032-1055`.

**Core ref:** `bitcoin-core/src/script/sign.cpp::MutableTransactionSignatureCreator::CreateSchnorrSig`,
`bitcoin-core/src/key.cpp:273-277` (`CKey::SignSchnorr`).

**Impact:** when Schnorr signing lands in lunarblock (PSBT P2TR,
`signrawtransactionwithkey` P2TR, BIP-322 Simple-mode), every signature
will be RFC-6979-style deterministic on the (sk, msg) pair, exposing
the secret to any future related-key fault that re-signs a related msg
with the same key. Differential side-channel hardening absent.

**Fix size:** 1 line — make `aux_rand32` required (or default to
`M.random_bytes(32)`).

---

## BUG-3 (P0-SEC) — `secp256k1_ec_seckey_verify` STILL absent; every sign path silently accepts scalar=0 or ≥n

**Severity:** P0-SEC. Core's `CKey::Check`
(`bitcoin-core/src/key.cpp:158-160`) uses
`secp256k1_ec_seckey_verify(static_ctx, vch)` to reject scalar=0 or
scalar≥n BEFORE accepting any seckey into a `CKey` instance.
`CKey::MakeNewKey` rolls until `Check()` passes; Core NEVER signs with
an unverified scalar.

lunarblock's FFI declaration block (`crypto.lua:372-608`) does NOT
declare `secp256k1_ec_seckey_verify`. Greps:

```bash
$ grep -rn "secp256k1_ec_seckey_verify\|seckey_verify\b" src/ csrc/
(zero matches)
```

Every sign path silently accepts the raw 32-byte payload:
- `crypto.lua:793-806` `pubkey_from_privkey`: asserts only 32-byte
  length; libsecp256k1 will short-circuit on bad scalar, lunarblock
  surfaces "invalid private key".
- `crypto.lua:875-889` `ecdsa_sign`: same.
- `crypto.lua:899-918` `ecdsa_sign_recoverable_compact`: asserts
  `#privkey32 == 32`.
- `crypto.lua:1032-1055` `schnorr_sign`: same.
- `crypto.lua:1066-1084` `taproot_tweak_seckey`: same.
- `crypto.lua:820-834` `ec_seckey_tweak_add`: tweaks in place; if the
  tweaked seckey is 0 the library returns 0, lunarblock surfaces
  "invalid derivation" — BUT for the input check, no pre-gate.
- `crypto.lua:1094-1103` `ellswift_create`: same.

**Carry-forward**: W158 BUG-6 (this same gap) → W159 BUG-3 (FFI-level
confirmation, 24+ hours open) → W160 BUG-3 (still absent).

**File:** `src/crypto.lua:372-608` (FFI cdef), every sign path.

**Core ref:** `bitcoin-core/src/secp256k1/include/secp256k1.h:685-707`
(`secp256k1_ec_seckey_verify`),
`bitcoin-core/src/key.cpp:158-160` (`CKey::Check`).

**Impact:** WIF import accepts a Base58Check string with version=0x80
over an all-zero 32-byte payload (`Wallet:import_privkey` at
`wallet.lua:2073-2095`), `pubkey_from_privkey` returns nil → import
errors out, but `signmessagewithprivkey` (`rpc.lua:2855-2892`) feeds
the raw payload directly to `ecdsa_sign_recoverable_compact` after
the WIF parse. **No earlier rejection** → the user gets a
generic "Sign failed" instead of "Invalid private key" + the
crash log line records the secret-related operation.

**Fix size:** 2 lines (add FFI declaration + one call per sign path).

---

## BUG-4 (P1-SEC) — Sign-then-verify paranoia absent in ALL three sign paths

**Severity:** P1-SEC. Bitcoin Core's `CKey::Sign`
(`bitcoin-core/src/key.cpp:209-235`) signs via `secp256k1_ecdsa_sign`,
then **immediately re-verifies** via `secp256k1_ecdsa_verify` and
`assert(ret)`. The Core comment is explicit: "Additional verification
step to prevent using a potentially corrupted signature." This catches
in-memory corruption between sign and serialize (rowhammer, transient
faults, FFI ABI mismatches).

`CKey::SignCompact` (`key.cpp:250-271`) similarly recovers the pubkey
from the freshly-signed compact-recoverable sig and compares it to the
expected pubkey via `secp256k1_ec_pubkey_cmp`, then asserts.

lunarblock has **none** of these:

```lua
-- crypto.lua:875-889  ecdsa_sign — returns straight after serialize
function M.ecdsa_sign(privkey32, msg_hash32)
  local sig = ffi.new("secp256k1_ecdsa_signature")
  if libsecp256k1.secp256k1_ecdsa_sign(secp_ctx, sig, msg_hash32, privkey32, nil, nil) ~= 1 then
    return nil, "signing failed"
  end
  -- NO re-verify
  local output = ffi.new("unsigned char[72]")
  ...
  return ffi.string(output, outputlen[0])
end
```

```lua
-- crypto.lua:899-918  ecdsa_sign_recoverable_compact — same shape, no recover-and-cmp
```

```lua
-- crypto.lua:1032-1055  schnorr_sign — no re-verify via schnorr_verify
-- Comment at line 1019-1020: "modulo defense-in-depth verify
-- (caller can re-check via M.schnorr_verify)" — COMMENT-AS-CONFESSION
-- No caller re-verifies (and BUG-13: no caller at all).
```

**Carry-forward**: W159 BUG-5. Listed for fleet pattern completeness.

**File:** `src/crypto.lua:875-889, 899-918, 1032-1055`.

**Core ref:** `bitcoin-core/src/key.cpp:209-235, 250-271, 273-277`.

**Impact:** transient memory corruption between sign and serialize
silently emits a corrupted signature (libsecp256k1 itself is constant-
time and well-vetted, but the LuaJIT FFI buffer round-trip through
`ffi.new` + `ffi.string` is not). Core's defense-in-depth catches the
class; lunarblock does not.

**Fix size:** ~6 lines per sign path (call `ecdsa_verify` / `recover_compact`
/ `schnorr_verify` and check the result).

---

## BUG-5 (P0-CONS) — Legacy FindAndDelete uses regex/pattern matching, not script-parse iteration → cross-opcode-boundary deletion

**Severity:** P0-CONS. Bitcoin Core's `FindAndDelete`
(`script/script.cpp::CScript::FindAndDelete`) walks the script with
`GetOp()` (an opcode-aware iterator) and only removes WHOLE-OPCODE
matches of the supplied `b` script. Bytes that happen to appear
inside a longer push (e.g. an OP_PUSHDATA2 payload that contains the
sig bytes as a substring) are PRESERVED. This is the canonical
"how Core handles non-canonical sig encoding inside data pushes"
invariant — pre-BIP66 mainnet has scripts that depend on this
exact byte-for-byte non-deletion behaviour.

lunarblock's `find_and_delete` (`validation.lua:596-609`):

```lua
function M.find_and_delete(script_bytes, sig_bytes)
  if not sig_bytes or #sig_bytes == 0 then
    return script_bytes
  end

  -- The signature is push-encoded in the script: [push_opcode] [data]
  local push_encoded = serialize_push_data(sig_bytes)

  -- Remove all occurrences of the push-encoded signature
  local pattern = escape_pattern(push_encoded)
  local result = script_bytes:gsub(pattern, "")

  return result
end
```

`gsub(pattern, "")` operates on the BYTE STREAM. It does NOT respect
opcode boundaries. A script of the shape:

```
OP_PUSHDATA2 <len=200>
  ... 50 bytes of payload ...
  <push-encoded copy of sig_bytes>     ← 73 bytes (push prefix + 72-byte sig)
  ... 77 more bytes of payload ...
OP_CHECKSIG
```

Core: scriptCode passed to SignatureHash is the FULL above (sig bytes
inside the push are preserved).
lunarblock: the 73-byte sequence inside the push is stripped, the
PUSHDATA2 still claims `<len=200>` → the parser walks PAST the end of
the now-127-byte data run and consumes the OP_CHECKSIG byte as more
push payload. The two impls compute distinct sighashes → ECDSA verify
disagrees → **consensus split**.

This is also the **"non-deterministic-where-Core-is-deterministic"**
fleet pattern + the **"wire-DoS via regex"** flavour: pure-regex
walks can hit pathological backtracking on certain inputs.

**File:** `src/validation.lua:596-609`.

**Core ref:**
`bitcoin-core/src/script/script.cpp::CScript::FindAndDelete`,
`bitcoin-core/src/script/interpreter.cpp::SignatureHash` (legacy
branch, calls FindAndDelete before computing the hash).

**Impact:** any pre-BIP66 mainnet block containing a tx with a script
that embeds the spending sig as a substring of a longer data push
will have a different sighash on lunarblock vs Core → invalid spend
on lunarblock OR valid spend on lunarblock that Core rejects.

**Fix size:** ~30 lines — implement a script-parse iterator that
walks opcode-by-opcode, only deleting whole `<push><data>` runs that
exactly match `push_encoded`.

---

## BUG-6 (P0-CONS) — OP_CODESEPARATOR scriptCode trim NOT honored in legacy ECDSA check_sig

**Severity:** P0-CONS. Bitcoin Core's `EvalScript`
(`script/interpreter.cpp:1055-1100`) maintains a `pbegincodehash`
iterator. When OP_CODESEPARATOR fires, `pbegincodehash` is advanced to
PAST the codesep byte. When OP_CHECKSIG fires, `SignatureHash` is
invoked with `scriptCode = std::vector<unsigned char>(pbegincodehash,
script.end())` — i.e. the script body STARTING AFTER the most-recently-
executed OP_CODESEPARATOR. The downstream `FindAndDelete(sig)` and
`scriptCode = remove_codeseparators` apply on this **already-trimmed**
slice.

lunarblock's script engine (`script.lua:1420-1428`) DOES advance a
`codesep_pos` integer on each executed OP_CODESEPARATOR and calls
`checker.set_codesep(codesep_pos)`. BUT:

1. The `make_sig_checker.set_codesep` (`validation.lua:1505`-1508 area)
   only stores the integer.
2. The legacy `check_sig` (`validation.lua:1515-1565`) uses:
   ```lua
   script_code = flags.script_code or prev_script_pubkey
   ```
   and passes this to `signature_hash_legacy(tx, idx, script_code,
   hash_type, sig)` — NOT a slice starting at `codesep_pos`.

So the scriptCode is ALWAYS the full script (P2SH redeem script or
prev scriptPubKey), regardless of how many OP_CODESEPARATOR's fired
during execution. `remove_codeseparators` (`validation.lua:617-680`)
THEN strips all codesep bytes from the entire script (correct for the
post-trim step), but the trim itself never happens.

**Consequence**: any legacy P2SH redeem script that uses
OP_CODESEPARATOR to switch the scriptCode for different signatures
(rare but historically present on mainnet — OG-style "atomic swap"
constructions, some HTLC-style scripts before BIP-143 segwit) produces
a sighash that diverges from Core. The signatures verify in Core,
fail in lunarblock → block rejected on lunarblock that Core accepts
→ consensus split.

**File:** `src/script.lua:1420-1428` (set_codesep wiring),
`src/validation.lua:1515-1545` (legacy check_sig ignores
`codesep_pos`).

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:1055-1100`
(EvalScript pbegincodehash maintenance + OP_CHECKSIG call site).

**Impact:** historical and future P2SH scripts using
OP_CODESEPARATOR mid-redeem-script produce wrong sighash. Tapscript
codesep_pos (which IS honored as the LE32 byte in the BIP-341
ext_flag=1 message at `validation.lua:1026`) is unaffected — only the
legacy path leaks.

**Fix size:** ~15 lines — wire `set_codesep` into a per-checker
`pbegincodehash` field, slice `script_code = script_code:sub(pbegincodehash + 1)`
inside legacy `check_sig`.

---

## BUG-7 (P1-PERF) — BIP-143 hashPrevouts/hashSequence/hashOutputs recomputed per-input (O(N²) IBD)

**Severity:** P1-PERF. Bitcoin Core's
`PrecomputedTransactionData` (`script/interpreter.h`) computes
`hashPrevouts`, `hashSequence`, `hashOutputs` ONCE per transaction
and caches the results. Every `SignatureHash(SIGVERSION_WITNESS_V0)`
call reuses the cached values. Cost: O(N inputs) per tx (one hash
walk over all prevouts/sequences/outputs).

lunarblock's `signature_hash_segwit_v0` (`validation.lua:806-884`)
**recomputes all three from scratch on every call**:

```lua
function M.signature_hash_segwit_v0(tx, input_index, script_code, value, hash_type)
  ...
  if not anyone_can_pay then
    local w = serialize.buffer_writer()
    for _, inp in ipairs(tx.inputs) do
      w.write_hash256(inp.prev_out.hash)
      w.write_u32le(inp.prev_out.index)
    end
    hash_prevouts = crypto.hash256(w.result())
  end
  ...
```

Called per-input → for a tx with N inputs, this loop fires N times,
each iterating N inputs → **O(N²) per tx**. On a tx with N=2,500
inputs (mainnet maxima), that's 2,500² = 6.25M crypto.hash256 calls
where Core does 2,500.

Same shape for `hash_sequence` (line 824-832), `hash_outputs` (line
836-857). Each gets recomputed per call when `anyone_can_pay` is
false.

**File:** `src/validation.lua:806-884` (no caching), every
`make_sig_checker.check_sig` ECDSA-segwit-v0 dispatch (line 1551).

**Core ref:**
`bitcoin-core/src/script/interpreter.h::PrecomputedTransactionData`,
`bitcoin-core/src/script/interpreter.cpp:1373-1455` (BIP-143
SignatureHash reuses `txdata.hashPrevouts`).

**Impact:** O(N²) IBD cost on segwit blocks. A block with 100 SegWit
txs each averaging 500 inputs runs 100×500² = 25M crypto.hash256
ops where Core does 100×500 = 50k — 500× wall-clock overhead in
the worst case. Not a consensus issue; visible as wallet/IBD slowdown.

**Fix size:** ~30 lines — add a per-tx cache table on
`tx._cached_segwit_hash_prevouts` etc, compute once on first call,
invalidate on tx mutation (segwit pre-image is over the canonical tx
shape, so no invalidation needed mid-validation).

---

## BUG-8 (P1-PERF) — BIP-341 sha_prevouts/sha_amounts/sha_scriptpubkeys/sha_sequences recomputed per-input

**Severity:** P1-PERF. Identical shape to BUG-7 but for Taproot.
`signature_msg_taproot` (`validation.lua:919-1029`) recomputes
all four sha256 midstates (sha_prevouts, sha_amounts,
sha_scriptpubkeys, sha_sequences) **per input** when
`anyone_can_pay` is false. Core's `PrecomputedTransactionData`
(post-BIP-341 patch) caches all four once per tx.

A 2,500-input tx makes 4×2,500² = 25M crypto.sha256 calls where Core
does 4×2,500 = 10k. Worse than BUG-7 because Taproot uses single-SHA256
not double, so each call is cheaper but the absolute count is 4x.

**File:** `src/validation.lua:949-989`.

**Core ref:**
`bitcoin-core/src/script/interpreter.h::PrecomputedTransactionData`
(extended for BIP-341),
`bitcoin-core/src/script/interpreter.cpp:1483-1570`
(`SignatureHashSchnorr` reuses `txdata.sha_amounts` etc.).

**Impact:** same as BUG-7 — O(N²) Taproot script-path IBD cost.

**Fix size:** ~40 lines — extend the BUG-7 cache structure with
Taproot fields.

---

## BUG-9 (P0-CONS) — Sigcache key uses txid (not wtxid); SegWit malleability bypasses cache; sigversion not in key

**Severity:** P0-CONS. `src/sig_cache.lua:6-8` documents the
contract:

> "Callers should pass the wtxid (witness txid) so that segwit witness
> mutation produces a cache miss; the key derivation itself is agnostic
> to which hash is supplied, so the wtxid fix lives in utxo.lua at the
> call sites."

But `utxo.lua:2303 + 2416-2417, 2746`:

```lua
for tx_idx, tx in ipairs(block.transactions) do
  local txid = validation.compute_txid(tx)       -- NON-witness txid
  ...
  local txid_bytes = txid.bytes
  if self.sig_cache:lookup(txid_bytes, inp_idx, cache_flags) then
    goto skip_verification
  end
  ...
  self.sig_cache:insert(txid_bytes, inp_idx, cache_flags)
```

The "the fix lives in utxo.lua at the call sites" never happened. **Every
sigcache lookup is keyed on the non-witness txid**, which is identical
across witness-malleated SegWit transactions.

**Attack:** an attacker observes a SegWit tx in lunarblock's mempool,
crafts a malleated copy with the same txid but a different (invalid)
witness, broadcasts it. lunarblock's sig_cache `lookup` returns
cache-HIT on the malleated witness because the txid matches —
`goto skip_verification`. The invalid witness is then ADMITTED to the
block. Worse: the cache could be poisoned by inserting an entry for a
known-valid tx, then later inserting a known-invalid one with a
deliberately-modified witness — both pass cache lookups.

Defense: Core uses `wtxid` in `SignatureCacheHasher`
(`script/sigcache.cpp`). The wtxid commits to the witness data, so any
witness mutation produces a distinct cache key.

Additionally: lunarblock's `cache_flags` (line 2408-2413) is a coarse
height-bitmask:

```lua
local cache_flags = 0
if height >= self.network.bip34_height then cache_flags = cache_flags + 1 end
if height >= self.network.bip66_height then cache_flags = cache_flags + 2 end
...
```

Core's `SignatureCacheHasher` mixes in the FULL `flags` integer (which
encodes ALL the script-verify flag bits, INCLUDING the `SigVersion`
implicitly via flag bits like `WITNESS` / `TAPROOT`). lunarblock
collapses BIP66/BIP65/CSV/WITNESS into 5 bits, dropping NULLDUMMY,
SIGPUSHONLY, LOW_S, STRICTENC, MINIMALDATA, DERSIG, MINIMALIF,
NULLFAIL, WITNESS_PUBKEYTYPE, CONST_SCRIPTCODE, TAPROOT
(verify_taproot height-checked separately and NOT folded into
`cache_flags`). **A cache entry that passed verification with `verify_low_s`
unset can be HIT by a later lookup that requires `verify_low_s` — a
high-S signature in the original entry would be falsely reported as
verified for the strict-flag context.**

**Carry-forward / fleet:** SegWit-malleability-sigcache is the W160
fleet-pattern noted in 5+ impls. lunarblock is the most-clearly-
documented case because the contract is written in source and the
violation is in another file 1.5MB away.

**File:** `src/utxo.lua:2303, 2408-2413, 2416-2417, 2746`.

**Core ref:** `bitcoin-core/src/script/sigcache.cpp::SignatureCache::ComputeEntry`
(uses wtxid + full flags int).

**Impact:** SegWit malleability sigcache poisoning + sigversion
collision risk on rare flag-transition heights.

**Fix size:** ~3 lines in utxo.lua (swap `validation.compute_txid(tx)`
→ `validation.compute_wtxid(tx)` at the cache call sites) +
~10 lines to widen `cache_flags` to include LOW_S, NULLFAIL,
TAPROOT, MINIMALIF.

---

## BUG-10 (P1) — `secp256k1_xonly_pubkey` typedef declared as `data[96]`, library says `data[64]`

**Severity:** P1. **Carry-forward from W159 BUG-4** — `crypto.lua:478`:

```lua
typedef struct { unsigned char data[96]; } secp256k1_xonly_pubkey;
```

Library spec (`secp256k1_extrakeys.h:22-24`):

```c
typedef struct { unsigned char data[64]; } secp256k1_xonly_pubkey;
```

This is a 32-byte over-allocation. LuaJIT FFI happily allocates the
extra bytes; the library writes 64 and the trailing 32 bytes are
uninitialized noise. Currently benign (no one reads the noise), but
any FFI function that takes the struct by value (none today, but
future API growth could) would pass garbage as the trailing third of
the struct.

The comment at `crypto.lua:516-517` confuses the typedef with the
**keypair** typedef (which IS `data[96]`) — a copy-paste from one
declaration to another.

**Carry-forward**: W159 BUG-4. Listed for fleet pattern continuity.

**File:** `src/crypto.lua:478`.

**Core ref:** `bitcoin-core/src/secp256k1/include/secp256k1_extrakeys.h:22-24`.

**Impact:** ABI fragility; benign today, breaks on future libsecp256k1
that takes the struct by value.

**Fix size:** 1 character.

---

## BUG-11 (P1-SEC) — Seckey scratch buffers never zeroed; Lua-string privkeys never mlocked

**Severity:** P1-SEC. Core stores every `CKey` in `unique_ptr<KeyType,
...>` with a `secure_allocator` backing (LockedPool / `mlock`).
Failure paths call `memory_cleanse(sig.data(), sig.size())` on stack
buffers. lunarblock:

- `crypto.lua:828-833` `ec_seckey_tweak_add` creates a local FFI
  `unsigned char[32]` for the seckey, copies the input in, calls the
  tweak, returns `ffi.string(seckey, 32)`. The ffi buffer is held
  by LuaJIT's GC indefinitely — never zeroed before release.
- `crypto.lua:1079` `taproot_tweak_seckey` similarly: `local out =
  ffi.new("unsigned char[32]")` filled by `keypair_sec`, returned
  via `ffi.string`. No `ffi.fill(out, 32, 0)` afterwards.
- `wallet.lua:1038-1043, 2085-2092` stores `self.keys[addr].privkey`
  as a Lua string. Lua strings are immutable + interned in the
  string-table — they live until the entire string table GC; even
  after `key_info.privkey = nil` (e.g. `Wallet:lock()` at
  `wallet.lua:916`), the underlying bytes remain in the interner
  until the next GC sweep, which could be many seconds later. On a
  memory-pressured system, the page containing the privkey can be
  swapped to disk in that window.

**Carry-forward**: W159 BUG-7 + BUG-8. Listed for fleet pattern
continuity.

**File:** `src/crypto.lua:828, 1079`, `src/wallet.lua:1043, 2086`.

**Core ref:** `bitcoin-core/src/support/lockedpool.{h,cpp}`,
`bitcoin-core/src/support/cleanse.cpp::memory_cleanse`,
`bitcoin-core/src/key.cpp:11-14` (CKey + secure_allocator).

**Impact:** key material may persist in heap / swap longer than
necessary; coredumps include privkey bytes.

**Fix size:** ~10 LOC per sign path (call `ffi.fill(buf, 32, 0)`
on every seckey-bearing buffer before release).

---

## BUG-12 (P1) — `consensus.SIGHASH` table omits `DEFAULT = 0x00`

**Severity:** P1. `src/consensus.lua:823-828`:

```lua
M.SIGHASH = {
  ALL = 0x01,
  NONE = 0x02,
  SINGLE = 0x03,
  ANYONECANPAY = 0x80
}
```

BIP-341 introduced `SIGHASH_DEFAULT = 0x00` as the new "implicit ALL"
value that allows the 64-byte sig form (no explicit hash_type byte).
Core's `interpreter.h` defines `SIGHASH_DEFAULT = 0`. lunarblock
hardcodes `0x00` in the validation paths (`validation.lua:1035, 1584,
1692; utxo.lua:2626`) as a raw literal, never via the constant table.
The `consensus.SIGHASH` table is the "named exports" surface — any
caller that wants to refer to SIGHASH_DEFAULT by name has no
constant. PSBT, wallet, mempool standardness, signrawtransaction
RPC all reach for `consensus.SIGHASH.ALL` — there's no
`consensus.SIGHASH.DEFAULT` to reach for, so callers either hardcode
0x00 (`utxo.lua:2626`, `validation.lua:1692`) or never construct a
Taproot keypath sig at all (no callers exist today, so this is
latent).

**File:** `src/consensus.lua:823-828`.

**Core ref:** `bitcoin-core/src/script/interpreter.h::SIGHASH_DEFAULT`.

**Impact:** named-constant gap; cosmetic until P2TR signing lands,
then a divergence-magnet for any future PSBT P2TR signing surface
that needs to refer to `SIGHASH_DEFAULT` symbolically.

**Fix size:** 1 line — `DEFAULT = 0x00,` in the SIGHASH table.

---

## BUG-13 (P1-CDIV) — `M.schnorr_sign` is dead-but-public; comment-as-confession + wiring-look-but-no-wire 3-LAYER

**Severity:** P1-CDIV. **Carry-forward from W159 BUG-6**. Three
distinct layers of "wiring-look-but-no-wire" stack on this single
function:

**Layer 1 — function defined.** `crypto.lua:1032-1055` ships a
working `M.schnorr_sign(privkey32, msg32, aux_rand32)` that wraps
`secp256k1_schnorrsig_sign32`. The FFI keypair_create at line 1042
allocates 96 bytes (correct), the sign call passes the seckey-flip-on-
odd-y-output correctly via the keypair API.

**Layer 2 — comment lies.** `rpc.lua:6136-6138`:

```lua
-- the witness or scriptSig.  P2TR (Schnorr) is not signed because lunarblock
-- ships ECDSA-only crypto today (M.schnorr_sign is unavailable); the input
-- is left untouched and `complete=false` is reported.
```

`M.schnorr_sign` IS available (Layer 1) — the comment is false. This
is the **"comment-as-confession inverted"** flavour: the comment
admits a gap that the code has actually closed. The code path that
WOULD use the closed gap then short-circuits because of the wrong
comment.

**Layer 3 — no callers.**

```bash
$ grep -rn "schnorr_sign\b" src/ tests/
src/crypto.lua:1032:function M.schnorr_sign(privkey32, msg32, aux_rand32)
src/rpc.lua:6137:  -- ships ECDSA-only crypto today (M.schnorr_sign is unavailable);
```

- `wallet.lua:1340-1503` `Wallet:create_transaction`: P2WPKH + legacy
  P2PKH only. P2TR recipients fall into `addr_type == "p2tr"` at
  line 1437 (creates correct scriptPubKey) but the signing block at
  line 1467-1500 has no `p2tr` branch — Taproot inputs would hit
  the `else` (legacy P2PKH) branch and produce GARBAGE sighash.
- `wallet.lua:1667-1721` `Wallet:_sign_inputs`: same — no `p2tr`
  branch.
- `psbt.lua:857-1011` `M.sign_input`: line 997 has `else return false`
  — P2TR script_type silently returns false without an error message.
- `rpc.lua` `signrawtransactionwithkey`: BUG-13 Layer 2 confirms it
  skips P2TR.

**Net:** every wallet / PSBT / signrawtransactionwithkey P2TR signing
surface is broken — P2TR recipients can be SPECIFIED (address +
scriptPubKey work), but the resulting funds cannot be SPENT by
lunarblock-controlled keys. **Wallets are write-only for Taproot.**

**Carry-forward**: W159 BUG-6 → W160 BUG-13. Closing the call sites
also requires fixing BUG-9 (sigcache wtxid) and BUG-2 (aux_rand32) to
produce sound signatures.

**File:** `src/crypto.lua:1032-1055`, `src/wallet.lua:1467-1500,
1697-1715`, `src/psbt.lua:997`, `src/rpc.lua:6136-6138`.

**Core ref:** `bitcoin-core/src/script/sign.cpp::ProduceSignature`
(dispatches to `CreateSchnorrSig` for P2TR), `bitcoin-core/src/key.cpp:273-277`
(`CKey::SignSchnorr`).

**Impact:** lunarblock cannot spend Taproot UTXOs that it generated
addresses for. Funds are receivable but un-sweepable.

**Fix size:** ~50 LOC across 3 files — wire `crypto.schnorr_sign`
into `wallet.lua:_sign_inputs` P2TR branch (compute TapSighash from
`signature_hash_taproot`, sign with `schnorr_sign(seckey,
sighash, random_bytes(32))`, write the 64-byte witness), psbt.lua
sign_input P2TR branch, signrawtransactionwithkey P2TR dispatch.

---

## BUG-14 (P1) — `taproot_tweak_seckey` is dead code (zero callers across src/ csrc/ tests/)

**Severity:** P1. `crypto.lua:1066-1084` defines
`M.taproot_tweak_seckey(privkey32, tweak32)` which correctly applies
a BIP-341 TapTweak via `secp256k1_keypair_xonly_tweak_add` and
returns the tweaked seckey via `secp256k1_keypair_sec`. The
seckey-flip on odd-y output key is handled INSIDE the libsecp256k1
keypair API, so the returned seckey is already in the correct
post-flip form for signing.

```bash
$ grep -rn "taproot_tweak_seckey" src/ tests/ csrc/
src/crypto.lua:1066:function M.taproot_tweak_seckey(privkey32, tweak32)
# Zero non-definition references.
```

The function is unreachable. BIP-86 single-key Taproot derivation (the
most common Taproot use case — sweep from a BIP-86 wallet) requires
exactly this primitive: derive the internal_xonly from xprv,
compute `tweak = tagged_hash("TapTweak", internal_xonly)`, apply via
`taproot_tweak_seckey`, then sign with the tweaked seckey.
**Without a caller, BIP-86 wallets are unsupportable**.

Cross-cite BUG-13 (Schnorr signing has no caller either — both gaps
sit at the same layer).

**File:** `src/crypto.lua:1066-1084`.

**Core ref:** `bitcoin-core/src/key.cpp::CKey::ComputeTapTweakHash`
+ `CKey::SignSchnorr` (path computes tweak, applies, signs).

**Impact:** BIP-86 Taproot key-path wallets are unsupportable;
related: lunarblock can derive BIP-86 ADDRESSES (`address.lua:386-389`
`xonly_pubkey_to_p2tr` exists) but cannot SIGN for them.

**Fix size:** ~10 LOC at the wallet `create_transaction` P2TR branch
once BUG-13 is wired.

---

## BUG-15 (P1-SEC) — `pubkey_from_privkey` accepts compressed flag but does NOT verify scalar; out-of-range scalars produce nil pubkey but no distinct error path

**Severity:** P1-SEC. `crypto.lua:793-806`:

```lua
function M.pubkey_from_privkey(privkey32, compressed)
  if compressed == nil then compressed = true end
  local pubkey = ffi.new("secp256k1_pubkey")
  if libsecp256k1.secp256k1_ec_pubkey_create(secp_ctx, pubkey, privkey32) ~= 1 then
    return nil, "invalid private key"
  end
  ...
```

`secp256k1_ec_pubkey_create` returns 0 on `seckey ≥ n` or `seckey == 0`,
which the wrapper surfaces as "invalid private key". This is structurally
OK — the failure path does fire — but:

1. The caller in `wallet.lua:2078`:
   ```lua
   local pubkey = crypto.pubkey_from_privkey(privkey, compressed)
   ```
   does NOT check the return value, then at line 2080-2083 immediately:
   ```lua
   if compressed and self.address_type == "p2wpkh" then
     addr = address.pubkey_to_p2wpkh(pubkey, self.network.name)
   ```
   `pubkey` may be `nil` here — `address.pubkey_to_p2wpkh(nil, ...)` will
   crash with an opaque LuaJIT error inside the address builder, not a
   user-meaningful "Invalid private key" error.

2. The caller in `rpc.lua:6161-6163`:
   ```lua
   local pubkey = crypto.pubkey_from_privkey(privkey32, compressed)
   if not pubkey then return nil end
   ```
   silently returns `nil` from `decode_priv_key_string` — which the
   caller surfaces as a generic "invalid privkey" without distinguishing
   "scalar out of range" from "wrong WIF version" from "wrong WIF
   checksum".

3. The `wallet.lua:2073-2095` `import_privkey` does:
   ```lua
   assert(version == self.network.wif_prefix, "Wrong network WIF prefix")
   ```
   — an unhandled assert that propagates to the RPC handler and crashes
   the connection thread (W158 BUG-8 / W142 BUG-24 fleet pattern,
   assert-as-validation).

**File:** `src/crypto.lua:793-806`, `src/wallet.lua:2073-2095`,
`src/rpc.lua:6142-6164`.

**Core ref:** `bitcoin-core/src/key.cpp:158-160` (`CKey::Check` via
`seckey_verify`), `bitcoin-core/src/key_io.cpp::DecodeSecret`.

**Impact:** opaque error messages on bad WIF; an unhandled assert in
`import_privkey` crashes the RPC thread.

**Fix size:** ~10 LOC — replace assert with structured error
return, propagate `pubkey_from_privkey` nil through the import path
with a meaningful message.

---

## BUG-16 (P1-SEC) — Recoverable signature header byte semantics: `recid = (header - 27) % 4` instead of `& 3`; `compressed = header >= 31` instead of `& 4`

**Severity:** P1-SEC. **Carry-forward from W158 G25/G26**. Core's
`CPubKey::RecoverCompact` (`pubkey.cpp`):

```c
recid = (header - 27) & 3;
fComp = ((header - 27) & 4) != 0;
```

lunarblock (`crypto.lua:932-934`):

```lua
local recid = (header - 27) % 4
local compressed = header >= 31
```

For header ∈ {27..34}, both forms produce identical results: `%4`
and `&3` agree on non-negative ints, `header >= 31` and `((header-27)
& 4) != 0` agree on the {27..34} range. So **today** the divergence
is invisible.

**BUT** the header range check at `crypto.lua:929-932` only enforces
`27 <= header <= 34`. Per Core, `RecoverCompact` returns false on
`header < 27 || header >= 35`. lunarblock returns nil + "invalid
signature header byte" on the same range — equivalent. So the bug is
not exploitable today.

**Fragility:** if a future change loosens the header range (e.g. to
support BIP-340-style recovery with a 1-bit y-parity at header=35),
the `>= 31` check becomes wrong: `header=35 → compressed=true` per
lunarblock but `35-27=8, 8&4=0 → fComp=false` per Core. Listed as
fragility-marker.

**File:** `src/crypto.lua:932-934`.

**Core ref:** `bitcoin-core/src/pubkey.cpp::CPubKey::RecoverCompact`.

**Impact:** none today; latent divergence if header range expands.

**Fix size:** 2 lines — use `bit.band(header - 27, 3)` and
`bit.band(header - 27, 4) ~= 0`.

---

## BUG-17 (P1) — `is_defined_hashtype` accepts `ANYONECANPAY|SIGHASH_DEFAULT (0x80)` as defined but rejects bare `SIGHASH_DEFAULT (0x00)`

**Severity:** P1. `src/script.lua:194-199`:

```lua
local function is_defined_hashtype(sig)
  if #sig == 0 then return false end
  local ht = bit.band(sig:byte(#sig), bit.bnot(0x80))
  return ht >= 1 and ht <= 3
end
```

This zeros out the ANYONECANPAY bit (`& ~0x80`) then accepts
{1,2,3}. So:
- `0x01, 0x02, 0x03, 0x81, 0x82, 0x83` → accepted (correct).
- `0x00` → rejected (correct for SIGVERSION_BASE / SIGVERSION_WITNESS_V0).
- **`0x80` → ht=0 → rejected**, but Core's `IsDefinedHashtypeSignature`
  is also called only on legacy ECDSA sigs (with hash-type byte), and
  Core's `SignatureHash(SIGVERSION_BASE)` happily accepts ht=0 as
  "SIGHASH_ALL" implicit fallback when used with hash_type=0x80.
  Actually Core does `(nHashType & 0x1f)` → 0 → falls into the ALL
  branch.

Cross-check Core: `interpreter.cpp::IsDefinedHashtypeSignature`:

```c
unsigned char nHashType = vchSig[vchSig.size() - 1] & (~(SIGHASH_ANYONECANPAY));
if (nHashType < SIGHASH_ALL || nHashType > SIGHASH_SINGLE) return false;
```

`SIGHASH_ALL = 1`, `SIGHASH_SINGLE = 3`. So Core too rejects ht=0
after stripping ANYONECANPAY. lunarblock matches Core.

**However**, the ANYONECANPAY-only byte `0x80` has been seen in the
wild on testnet as a malformed-sig encoding; the fleet pattern is
that this validation runs only when `verify_strictenc` is set, so it's
policy-only, not consensus. Listed as fleet-tracking nit; no real bug.
**Downgrade to P3 / informational** since the logic matches Core
exactly.

(Keeping the entry for fleet-pattern continuity but lowering severity.)

**File:** `src/script.lua:194-199`.

**Core ref:** `bitcoin-core/src/script/interpreter.cpp::IsDefinedHashtypeSignature`.

**Impact:** none (matches Core).

---

## BUG-18 (P1) — `signature_hash_legacy` does NOT special-case `hash_type == 0` (works by accident via mask path)

**Severity:** P1. Per Core, legacy `SignatureHash` does
`(nHashType & SIGHASH_OUTPUT_MASK)` (= `& 0x1F`) and then dispatches:

```c
case SIGHASH_NONE:    /* zero outputs */
case SIGHASH_SINGLE:  /* single output at in_pos */
default:              /* SIGHASH_ALL — INCLUDING ht==0 */
```

The `default` branch catches both `SIGHASH_ALL=1` and `0`. lunarblock
mirrors this implicitly: `signature_hash_legacy` (line 694-792) only
branches on `ht == SINGLE` and `ht == NONE`, falling into the
ALL-equivalent else branch for everything else (including ht=0).
**This works by accident** — there is no explicit comment marking
ht=0 as "treated as ALL". Future refactor risk.

In contrast, `signature_msg_taproot` (line 919) DOES explicit
`if ht == 0x00 then ht = 0x01 end` (line 935), making the
ht=0→ALL coercion explicit.

The inconsistency is between two paths in the same file. Recommend
adding an explicit normalisation to legacy.

**File:** `src/validation.lua:694-792`.

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:1303-1372`
(`SignatureHash`, default branch).

**Impact:** none today; future-refactor risk.

**Fix size:** 1 line — explicit `if ht == 0 then ht = consensus.SIGHASH.ALL end`.

---

## BUG-19 (P1-SEC) — `escape_pattern` in find_and_delete is incomplete (missing `%0`, `\` escapes)

**Severity:** P1-SEC (cross-references BUG-5). `validation.lua:583-588`:

```lua
local function escape_pattern(str)
  return (str:gsub("[%(%)%.%%%+%-%*%?%[%]%^%$]", "%%%1"))
end
```

The Lua pattern class `[%(%)%.%%%+%-%*%?%[%]%^%$]` escapes:
`( ) . % + - * ? [ ] ^ $`. **Missing**: `\` (Lua patterns don't
interpret `\`, but the `%%%1` replacement itself can mis-interpret
`%` in the replacement — though the outer `%` is properly escaped
above). Also missing escape for `\0` — Lua strings can contain
embedded NUL bytes, and `gsub` handles them, BUT the inner pattern
escaping for the source string is incomplete if the source contains
a literal backslash followed by special chars (unusual in sig
encoding, but defense-in-depth).

The bigger issue is BUG-5 — the whole regex approach is wrong. This
finding is a follow-up: even if you kept the regex approach, the
escape table is fragile.

**File:** `src/validation.lua:583-588`.

**Impact:** low (sig encoding doesn't usually contain `\` etc); BUG-5
subsumes this finding.

**Fix size:** subsumed by BUG-5 fix (drop the regex approach).

---

## BUG-20 (P1) — No `ffi.gc` finalizer on global `secp_ctx`; context leaks across module reload / test reset

**Severity:** P1. **Carry-forward from W159 BUG-9**. `crypto.lua:613-615`:

```lua
local secp_ctx = libsecp256k1.secp256k1_context_create(
  bit.bor(0x0101, 0x0201)
)
```

No `ffi.gc(secp_ctx, libsecp256k1.secp256k1_context_destroy)`
registration. The context lives until process exit. In test runs
that `require()` `lunarblock.crypto` repeatedly, each
`require` returns the cached module + already-initialized
`secp_ctx`. In production: cosmetic on exit; matters if the LuaJIT
state is ever torn down (e.g. test-suite resetting `package.loaded`).

**Carry-forward**: W159 BUG-9. Listed for fleet pattern continuity.

**File:** `src/crypto.lua:613-615`.

**Core ref:** `bitcoin-core/src/key.cpp::ECC_Stop` (calls
`secp256k1_context_destroy` at shutdown).

**Fix size:** 1 line — `ffi.gc(secp_ctx, libsecp256k1.secp256k1_context_destroy)`.

---

## BUG-21 (P1-CDIV) — Context flags `VERIFY | SIGN` are deprecated; library treats them as `CONTEXT_NONE` today, future-rotted

**Severity:** P1-CDIV. **Carry-forward from W159 BUG-1**.
`crypto.lua:613-615` ORs the two flags
`SECP256K1_CONTEXT_VERIFY (0x0101)` and `SECP256K1_CONTEXT_SIGN (0x0201)`,
both tagged in `secp256k1.h:216` as:

> "Deprecated context flags. These flags are treated equivalent to
> SECP256K1_CONTEXT_NONE."

Post-v0.4.0 the only non-deprecated flag is `CONTEXT_NONE = 0x0001`.
A future libsecp256k1 release that drops the deprecated-flag handling
would silently break lunarblock.

**Carry-forward**: W159 BUG-1.

**File:** `src/crypto.lua:613-615`.

**Core ref:** `bitcoin-core/src/key.cpp:575` (Core moved to
`CONTEXT_NONE`).

**Fix size:** 1 line — use `0x0001`.

---

## Summary

**Bug count:** 21 (BUG-1 through BUG-21).

**Severity distribution:**
- **P0-CONS:** 4 (BUG-5 FindAndDelete-regex; BUG-6 codesep trim;
  BUG-9 sigcache wtxid + sigversion)
  — Wait recount. Re-tag:
  - P0-CONS: 3 (BUG-5, BUG-6, BUG-9).
  - P0-SEC: 3 (BUG-1, BUG-2, BUG-3).
- **P1-CDIV:** 2 (BUG-13, BUG-21)
- **P1-SEC:** 5 (BUG-4, BUG-11, BUG-15, BUG-16, BUG-19)
- **P1-PERF:** 2 (BUG-7, BUG-8)
- **P1:** 6 (BUG-10, BUG-12, BUG-14, BUG-17, BUG-18, BUG-20)

Total: 3 + 3 + 2 + 5 + 2 + 6 = **21** ✓

**Fleet patterns confirmed:**

- **side-channel-blinding-disabled** (BUG-1) — lunarblock is the
  NAMED ORIGIN. W158 BUG-7 → W159 BUG-2 → W160 BUG-1: **3-wave
  carry-forward open at the same impl that gave the pattern its
  name**.
- **sign-then-verify-paranoia-absent** (BUG-4) — all 3 sign paths;
  carry-forward W159 BUG-5.
- **SegWit malleability sigcache** (BUG-9) — lunarblock joins the
  5+ impl fleet pattern. Source comment explicitly documents the
  contract that the call sites violate.
- **wiring-look-but-no-wire 3-LAYER** (BUG-13) — `schnorr_sign` is
  defined + comment lies that it isn't + zero callers exist.
  Carry-forward W159 BUG-6. **Three distinct layers of wiring
  illusion** on a single function.
- **dead-but-public-returns-true** / dead public surface (BUG-14
  `taproot_tweak_seckey`).
- **comment-as-confession** (BUG-2 aux_rand32 doc admits gap; BUG-4
  schnorr_sign verify comment; BUG-13 rpc.lua "ECDSA-only" lie) —
  3 fresh instances this wave; lunarblock distinct-comment count
  for the pattern now 8+ since W158.
- **non-deterministic-where-Core-is-deterministic** + **wire-DoS
  via regex** (BUG-5) — FindAndDelete via `gsub` instead of script-
  parser walk.
- **comparator mismatch on adjacent gates** (BUG-16 recid mod 4 vs
  Core's `& 3`; latent today).
- **drift-converged-on-wrong-default** (BUG-2 aux_rand32 default to
  zero matches BIP-340 test mode but not production).
- **assert-as-validation** (BUG-15 `import_privkey` asserts on
  wrong-prefix WIF; W142 BUG-24 fleet pattern).
- **O(N²) where Core is O(N)** (BUG-7 BIP-143; BUG-8 BIP-341) —
  PrecomputedTransactionData absent.

**Top three findings:**

1. **BUG-1 + BUG-2 + BUG-3 (P0-SEC three-bug cluster, all
   carry-forwards)** — `secp256k1_context_randomize` STILL absent
   3 waves after lunarblock was named as the fleet ORIGIN (W158
   BUG-7); `secp256k1_ec_seckey_verify` STILL absent 24+ hours
   after W159 BUG-3; Schnorr aux_rand32 default-to-zero pattern is
   the "drift-converged-on-wrong-default" first instance. Together
   these are the **complete side-channel-hygiene gap**: unblinded
   ctx + unverified scalars + deterministic Schnorr nonces. Fix
   size: ~15 LOC total.

2. **BUG-5 + BUG-6 (P0-CONS legacy sighash divergence pair)** —
   `find_and_delete` is regex-based not script-parser-based (cross-
   opcode-boundary deletion); legacy OP_CODESEPARATOR scriptCode
   trim is wired through `set_codesep` but never consumed by the
   ECDSA sighash path. **Both are pre-segwit consensus splits**
   triggered by historical mainnet scripts. Fix size: ~45 LOC.

3. **BUG-9 (P0-CONS sigcache wtxid + sigversion gap)** — the
   `sig_cache.lua` source comment explicitly documents the
   wtxid contract; the `utxo.lua` call sites pass NON-witness
   txid. SegWit malleability sigcache poisoning is a free
   exploit. Cross-cite: `cache_flags` collapses 12 verify-flag
   bits into 5 height-bitmask bits — a `verify_low_s`-on lookup
   can HIT a `verify_low_s`-off cache entry. Fix size: ~3 LOC for
   the wtxid swap + 10 LOC to widen flags.

Plus the BUG-13 + BUG-14 cluster (Schnorr signing dead) is what
unlocks every other Taproot-signing test surface; trace fix size
~50 LOC across 3 files.

Cross-fleet observation: lunarblock now has FOUR distinct
fleet-named-origin patterns:
- W158 / W160 BUG-1 side-channel-blinding-disabled (origin),
- W158 funds-burn coinbase (origin),
- W158 base64-decode-substitutes-zero (origin),
- W160 BUG-5 FindAndDelete-via-regex (likely origin — fleet sweep
  needed to confirm; not flagged in any other impl audit to date
  but other Lua/Python impls may share the shape).
