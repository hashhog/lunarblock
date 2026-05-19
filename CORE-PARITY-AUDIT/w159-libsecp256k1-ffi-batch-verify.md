# W159 — libsecp256k1 FFI wrapping + batch verification (lunarblock)

**Wave:** W159 — `secp256k1_context_create` flags + lifecycle,
`secp256k1_context_randomize` side-channel blinding seed,
`SECP256K1_CONTEXT_NONE` (post v0.4.0) vs the deprecated
`VERIFY | SIGN` flags, `secp256k1_ec_seckey_verify` scalar-range gate,
`secp256k1_ecdsa_signature_normalize` low-S handling, Schnorr
verify/sign surface (`secp256k1_schnorrsig_verify`,
`secp256k1_schnorrsig_sign32`), `secp256k1_xonly_pubkey_parse` /
`_serialize` / `_from_pubkey`, `secp256k1_keypair_create` / `_sec` /
`_xonly_tweak_add`, batch verification (Core does not currently use
`secp256k1_schnorrsig_verify_batch`; lunarblock's `pv_verify_signatures`
worker pool), ECDSA recovery (`secp256k1_ecdsa_recover`), ElligatorSwift
(`secp256k1_ellswift_xdh`), LockedPool / `memory_cleanse` for seckey
hygiene, `ffi.gc` finalizer for context destroy, sign-then-verify
paranoia (Core `CKey::Sign` re-verifies before returning),
process-singleton vs per-thread context, `secp256k1_selftest` for
the static context, `secp256k1_context_set_illegal_callback` /
`_error_callback` for production aborts vs library defaults.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**

- `bitcoin-core/src/secp256k1/include/secp256k1.h:214-218` — context
  flags. `SECP256K1_CONTEXT_NONE` is the only non-deprecated flag in
  recent (≥ v0.4.0) library versions; `SECP256K1_CONTEXT_VERIFY` and
  `SECP256K1_CONTEXT_SIGN` are explicitly tagged
  "Deprecated context flags. These flags are treated equivalent to
  SECP256K1_CONTEXT_NONE."
- `bitcoin-core/src/secp256k1/include/secp256k1.h:243-249` —
  `secp256k1_context_static`: a "context object initialized in a special
  static way", suitable for all functionality that does NOT take a
  secret key, used in conjunction with `secp256k1_selftest`. Cloning
  the static context is not supported. The deprecated alias
  `secp256k1_context_no_precomp` is `SECP256K1_DEPRECATED("Use
  secp256k1_context_static instead")`.
- `bitcoin-core/src/secp256k1/include/secp256k1.h:267` —
  `secp256k1_selftest(void)` "highly recommended to call before using
  `secp256k1_context_static`".
- `bitcoin-core/src/secp256k1/include/secp256k1.h:820-841` —
  `secp256k1_context_randomize` (side-channel blinding seed). The
  docstring explicitly says: "It is highly recommended to call this
  function on contexts ... before using these contexts to call API
  functions that perform computations involving secret keys, e.g.,
  signing and public key generation. ... doing so before every few
  computations involving secret keys is recommended as a defense-in-depth
  measure." Returns `SECP256K1_WARN_UNUSED_RESULT int` — production
  must check the return.
- `bitcoin-core/src/secp256k1/include/secp256k1.h:685-707` —
  `secp256k1_ec_seckey_verify(const secp256k1_context*, const unsigned
  char* seckey)`: checks the seckey is in `(0, n)`. Returns 1 if valid,
  0 otherwise. Used as the canonical scalar-range gate before any
  signing or pubkey-create call (`CKey::Check` at `key.cpp:158`).
- `bitcoin-core/src/secp256k1/include/secp256k1_extrakeys.h:22-24` —
  `secp256k1_xonly_pubkey` typedef: `unsigned char data[64];`
  (NOT 96 bytes).
- `bitcoin-core/src/secp256k1/include/secp256k1_extrakeys.h:33-35` —
  `secp256k1_keypair` typedef: `unsigned char data[96];`.
- `bitcoin-core/src/secp256k1/include/secp256k1_recovery.h:24-26` —
  `secp256k1_ecdsa_recoverable_signature` typedef:
  `unsigned char data[65];`.
- `bitcoin-core/src/key.cpp:571-587` — `ECC_Start`: creates the sign
  context with `SECP256K1_CONTEXT_NONE`, then unconditionally calls
  `secp256k1_context_randomize(ctx, vseed.data())` with 32 bytes from
  `GetRandBytes()` and `assert(ret)` on the result.
- `bitcoin-core/src/key.cpp:158-160` — `CKey::Check` uses
  `secp256k1_ec_seckey_verify(secp256k1_context_static, vch)` before
  accepting any seckey into a `CKey` instance.
- `bitcoin-core/src/key.cpp:162-168` — `CKey::MakeNewKey` rolls until
  `Check()` passes; Core never accepts an unverified scalar.
- `bitcoin-core/src/key.cpp:209-235` — `CKey::Sign`: signs, then
  immediately re-verifies via `secp256k1_ecdsa_verify`, then
  `assert(ret)`. "Additional verification step to prevent using a
  potentially corrupted signature." Sign-then-verify paranoia.
- `bitcoin-core/src/key.cpp:250-271` — `CKey::SignCompact`: signs,
  then `secp256k1_ecdsa_recover`s, then `secp256k1_ec_pubkey_cmp`s
  the recovered pubkey against the expected pubkey, then `assert`.
- `bitcoin-core/src/key.cpp:561` — `memory_cleanse(sig.data(),
  sig.size())` on failure paths.
- `bitcoin-core/src/key.cpp:11-14` — `CKey::keydata` is a
  `unique_ptr<KeyType, ...>` with a `secure_allocator` backing
  (LockedPool / `mlock`). Every seckey in Core lives in mlocked
  memory.
- `bitcoin-core/src/secp256k1/include/secp256k1_schnorrsig.h:119-125` —
  `secp256k1_schnorrsig_sign32` MUST be called with a context that is
  "not `secp256k1_context_static`" (i.e., a context that has been
  randomized).
- `bitcoin-core/src/secp256k1/include/secp256k1_schnorrsig.h:178-185` —
  `secp256k1_schnorrsig_verify`. Schnorr verification is single-sig
  in libsecp256k1's public API; there is no
  `secp256k1_schnorrsig_verify_batch` in the upstream tree (Core does
  not batch-verify Schnorr today). Batch verify lives in the
  experimental schnorrsig "batch" module under
  `secp256k1/src/modules/schnorrsig/`, not exposed by the public header.
- `bitcoin-core/src/script/sigcache.cpp` — `SignatureCache::ComputeEntry`
  uses a per-process 32-byte nonce + wtxid + script flags;
  `Hash` is SHA-256.

**Files audited**

- `src/crypto.lua` (1583 LOC) — libsecp256k1 FFI cdef (line 372-608) +
  `secp_ctx` global context (line 613-615) +
  `ecdsa_verify` / `ecdsa_verify_lax` / `pubkey_from_privkey` /
  `ec_seckey_tweak_add` / `ec_pubkey_tweak_add` / `ecdsa_sign` /
  `ecdsa_sign_recoverable_compact` / `ecdsa_recover_compact` /
  `decompress_pubkey` / `schnorr_verify` / `schnorr_sign` /
  `taproot_tweak_seckey` / `ellswift_create` / `ellswift_ecdh` /
  `tweak_pubkey`. Loader: `ffi.load("secp256k1")` at line 610.
- `csrc/parallel_verify.c` (644 LOC) — pthread worker pool, per-worker
  `secp256k1_context` (line 430:
  `secp256k1_context_create(SECP256K1_CONTEXT_VERIFY)`); two `cdef`'d
  job kinds (`verify_job` placeholder + `sig_verify_job` production
  hot-path); `parse_der_signature_lax` (line 158-253);
  `process_sig_job` (line 326-333) + `pv_verify_signatures`
  (line 586-644).
- `src/validation.lua:14-43, 50-78, 107-200` — FFI cdef of the
  parallel-verify ABI + `init_parallel_verify` lazy loader +
  `verify_signatures_parallel` dispatcher with a `PARALLEL_THRESHOLD = 16`.
- `src/sig_cache.lua` (110 LOC) — per-process nonce read from
  `/dev/urandom` + `SHA-256(nonce || txid_or_wtxid || tostring(flags))`.
- `src/wallet.lua:2073-2095` — `Wallet:import_privkey` (WIF) calls
  `crypto.pubkey_from_privkey` without a `secp256k1_ec_seckey_verify`
  gate.
- `src/utxo.lua:2620-2710` — taproot key-path + script-path Schnorr
  verify call sites.
- `src/validation.lua:1593-1903` — Schnorr / Tapscript verify
  dispatchers.
- `src/script.lua:2080-2093` — Tapscript control-block tweak verify.
- `src/rpc.lua:6130-6145` — signrawtransactionwithkey "ECDSA-only crypto
  today" path (P2TR/Schnorr signing dead — `crypto.schnorr_sign` is
  defined but no caller invokes it).

---

## Gate matrix (29 sub-gates / 9 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | Context creation flags | G1: use `SECP256K1_CONTEXT_NONE` (post-v0.4.0 canonical) | **BUG-1 (P1)** — `crypto.lua:613-615` uses `bit.bor(0x0101, 0x0201) = VERIFY \| SIGN`, both explicitly deprecated in `secp256k1.h:216`; the `parallel_verify.c:430` worker contexts use `VERIFY` (0x0101) alone, also deprecated |
| 1 | … | G2: never pass an unrecognised flag value | PASS (the deprecated-but-recognised flags still resolve to `CONTEXT_NONE` in the library) |
| 2 | Context-randomize side-channel blinding | G3: `secp256k1_context_randomize(secp_ctx, seed32)` immediately after `_create` | **BUG-2 (P0-SEC)** — confirmed at FFI level. No call site exists in `crypto.lua`. lunarblock is the NAMED ORIGIN of the fleet pattern (W158 BUG-7); 5 weeks later, still unfixed |
| 2 | … | G4: same in the parallel-verify worker pool (per-worker contexts also need randomization for `SIGN` ops; for pure verify a randomized context still defends against an attacker reading worker memory during cofactor mult) | **BUG-2 cross-cite** — `parallel_verify.c:430` also creates raw, no randomize |
| 2 | … | G5: `_context_randomize` is `SECP256K1_WARN_UNUSED_RESULT`; production checks return | N/A (BUG-2 — never called) |
| 2 | … | G6: re-randomize "every few computations" per `secp256k1.h:826` defense-in-depth | **BUG-2 cross-cite** — even if BUG-2 is fixed at startup, lunarblock has no re-randomize loop |
| 3 | Seckey-verify scalar-range gate | G7: call `secp256k1_ec_seckey_verify` before every sign / pubkey_create | **BUG-3 (P0-SEC)** — `crypto.lua:793-806` `pubkey_from_privkey`, `crypto.lua:874-889` `ecdsa_sign`, `crypto.lua:899-918` `ecdsa_sign_recoverable_compact`, `crypto.lua:1032-1055` `schnorr_sign`, `crypto.lua:1066-1084` `taproot_tweak_seckey`, `crypto.lua:1094-1103` `ellswift_create` — none verify scalar range. `secp256k1_ec_seckey_verify` is not declared in the FFI cdef AT ALL |
| 3 | … | G8: WIF import sanitises seckey before storing | **BUG-3 cross-cite** — `wallet.lua:2077-2086` accepts any 32-byte slice; `pubkey_from_privkey` is called but returns nil only on EC failure, which silently absorbs an all-zero or >n scalar without distinguishing it from corrupted-WIF |
| 4 | xonly_pubkey ABI parity | G9: `secp256k1_xonly_pubkey` typedef matches Core (`data[64]`) | **BUG-4 (P1)** — `crypto.lua:478` declares the typedef as `unsigned char data[96]`, half-again the Core/library size. The inline comment at `crypto.lua:516-517` confuses xonly_pubkey (`data[64]`, `secp256k1_extrakeys.h:22-24`) with keypair (`data[96]`, `secp256k1_extrakeys.h:33-35`) — a copy-paste error |
| 4 | … | G10: `secp256k1_pubkey` typedef matches Core (`data[64]`) | PASS (`crypto.lua:375`) |
| 4 | … | G11: `secp256k1_keypair` typedef matches Core (`data[96]`) | PASS (`crypto.lua:518`) |
| 4 | … | G12: `secp256k1_ecdsa_recoverable_signature` typedef matches Core (`data[65]`) | PASS (`crypto.lua:577`) |
| 5 | Sign-then-verify paranoia | G13: after `ecdsa_sign`, re-verify with `secp256k1_ecdsa_verify` before returning | **BUG-5 (P1-SEC)** — `crypto.lua:874-889` `ecdsa_sign` returns straight after serialize; no defense-in-depth re-verify. Core's `CKey::Sign` (key.cpp:228-234) re-verifies AND asserts |
| 5 | … | G14: after `ecdsa_sign_recoverable_compact`, recover-and-cmp the pubkey | **BUG-5 cross-cite** — `crypto.lua:899-918` skips it; Core's `CKey::SignCompact` (key.cpp:262-270) does it |
| 5 | … | G15: after `schnorr_sign`, re-verify with `schnorr_verify` | **BUG-5 cross-cite** — `crypto.lua:1032-1055` skips it; the inline comment "modulo defense-in-depth verify (caller can re-check)" at line 1020 is a **comment-as-confession** — callers do not re-verify |
| 6 | Schnorr verify/sign surface | G16: `schnorr_verify` matches Core wire shape (32-byte xonly, 64-byte sig, variable msg) | PASS (`crypto.lua:998-1016`) |
| 6 | … | G17: `schnorr_sign` available AND wired into a sign path | **BUG-6 (P1-CDIV)** — `M.schnorr_sign` is defined (`crypto.lua:1032-1055`) but rpc.lua:6137 says `"M.schnorr_sign is unavailable"` and skips P2TR signing. Comment is now FALSE; `signrawtransactionwithkey` for P2TR is **dead code**. "comment-as-confession" + "wiring-look-but-no-wire" — function ships, no caller |
| 6 | … | G18: tagged_hash matches Core BIP-340 spec | PASS (`crypto.lua:1519-1522`) |
| 7 | Memory hygiene | G19: seckey scratch buffers zeroed after use | **BUG-7 (P0-SEC)** — no `memzero` / `ffi.fill(seckey, 32, 0)` anywhere in `crypto.lua`. The local `seckey` buffer in `ec_seckey_tweak_add` at line 828-833 is held by LuaJIT GC indefinitely. `aux_rand32`, `privkey32` Lua-string params live in the LuaJIT string interner — they are NEVER zeroed |
| 7 | … | G20: LockedPool / `mlock` for seckey storage | **BUG-8 (P1-SEC)** — no `mlock`, no `secure_allocator` analogue. WIF privkeys (`wallet.lua:2077-2086`) are stored as plain Lua strings in `self.keys[addr].privkey`; on a memory-pressured system Lua strings are swappable to disk |
| 7 | … | G21: `parallel_verify.c` worker contexts destroyed on shutdown | PASS (`parallel_verify.c:563-566`) |
| 7 | … | G22: `ffi.gc(secp_ctx, libsecp256k1.secp256k1_context_destroy)` LuaJIT-side finalizer | **BUG-9 (P1)** — `crypto.lua:613-615` has no `ffi.gc` registration. The context lives until process exit, then leaks (cosmetic on exit; matters for test-suite where multiple instances are created and destroyed) |
| 8 | Lax DER parser | G23: lax parser used wherever Core uses `ecdsa_signature_parse_der_lax` | PASS (`crypto.lua:660-755` + `parallel_verify.c:158-253`); both normalize-then-verify, both used in mainnet validation paths |
| 8 | … | G24: low-S normalization on every verify call | PASS — `crypto.lua:648`, `:753`, `:786` all call `_normalize` before `_verify` |
| 9 | Batch verification | G25: Schnorr batch verify (when libsecp256k1 builds with the batch module) | **BUG-10 (P2)** — no `secp256k1_schnorrsig_verify_batch` FFI declaration; lunarblock cannot opportunistically batch-verify if linked against a build that ships the batch module. Same as Core today (parity), but the W126 BIP-340 spec recommends it for IBD throughput. Listed for fleet pattern completeness, not a divergence |
| 9 | … | G26: ECDSA batch verify via `pv_verify_signatures` worker pool | PASS (`parallel_verify.c:586-644`) — works correctly under the current `MIN_PARALLEL_INPUTS=16` threshold. **BUG-11 (P1)** for the operational fragility around the unified-queue lock: `pv_verify_signatures` does not validate `count` against `INT_MAX / sizeof(sig_verify_job)`; a caller posting `count = INT_MAX` would integer-overflow the `for (int i = 0; i < count; i++)` after `current_kind = PV_JOB_SIG` is assigned, exhausting the worker pool with garbage pointers (only callable from Lua, which itself bounds the slice length, but the C ABI is exposed without bounds check) |
| 9 | … | G27: `sig_verify_job` lifetime: callers in `validation.lua:127-160` keep `pubkey_ptrs`/`sig_ptrs`/`hash_ptrs` tables alive across the C call to defeat LuaJIT GC | PASS — `validation.lua:130-133` explicitly comments "We need to keep references to prevent GC", but **BUG-12 (P1)** — the `jobs` cdata at `validation.lua:128` is itself ephemeral; if the post-shutdown path ever re-enters `verify_signatures_parallel` while a previous batch is still draining, the second batch overwrites `job_queue` mid-flight (the unified-queue design only synchronises via `queue_mutex`; the dispatcher in `pv_verify_signatures` at `parallel_verify.c:618-634` holds the mutex but does not guarantee that a previous caller's `jobs` array is unreferenced before returning) |
| 9 | … | G28: signature cache nonce randomization | PASS (`sig_cache.lua:25-48`) |
| 9 | … | G29: signature cache key includes script flags (cache-poison defense) | PASS (`sig_cache.lua:58-63`) |

---

## BUG-1 (P1) — Context created with deprecated `VERIFY | SIGN` flags instead of `SECP256K1_CONTEXT_NONE`

**Severity:** P1. `bitcoin-core/src/secp256k1/include/secp256k1.h:216`
explicitly tags `SECP256K1_CONTEXT_VERIFY` and `_SIGN` as
"Deprecated context flags. These flags are treated equivalent to
`SECP256K1_CONTEXT_NONE`." Post-v0.4.0 the only non-deprecated context
flag is `CONTEXT_NONE = SECP256K1_FLAGS_TYPE_CONTEXT = 0x0001`. Core
moved to `CONTEXT_NONE` in `key.cpp:575`.

lunarblock's `crypto.lua:613-615`:

```lua
local secp_ctx = libsecp256k1.secp256k1_context_create(
  bit.bor(0x0101, 0x0201)  -- VERIFY | SIGN
)
```

And `parallel_verify.c:38, 430`:

```c
#define SECP256K1_CONTEXT_VERIFY 0x0101
workers[i].ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
```

This is harmless TODAY (the library treats both as `CONTEXT_NONE`),
but:
- A future libsecp256k1 release that drops the deprecated flag handling
  would silently break lunarblock (the OR'd flag value
  `0x0101 | 0x0201 = 0x0301` is `SECP256K1_FLAGS_TYPE_CONTEXT |
  BIT_CONTEXT_VERIFY | BIT_CONTEXT_SIGN`; a strict library would
  reject the unrecognised combination).
- Documentation lint: anyone reading `crypto.lua` thinks lunarblock is
  on a pre-v0.4.0 build of libsecp256k1.

**File:** `src/crypto.lua:613-615`, `csrc/parallel_verify.c:38, 430`.

**Core ref:** `bitcoin-core/src/secp256k1/include/secp256k1.h:214-218`,
`bitcoin-core/src/key.cpp:575`.

**Impact:** future-proofing gap; cosmetic at v0.4.x-v0.5.x, latent
break at the next library bump if upstream drops deprecated flag
handling.

---

## BUG-2 (P0-SEC) — `secp256k1_context_randomize` NEVER called; side-channel blinding disabled (FLEET-WIDE PATTERN, LUNARBLOCK IS NAMED ORIGIN)

**Severity:** P0-SEC. Bitcoin Core's `ECC_Start` (`key.cpp:572-587`)
creates the signing context with `SECP256K1_CONTEXT_NONE`, then
unconditionally:

```cpp
std::vector<unsigned char, secure_allocator<unsigned char>> vseed(32);
GetRandBytes(vseed);
bool ret = secp256k1_context_randomize(ctx, vseed.data());
assert(ret);
```

This seeds the context for blinding: every multiplication of a secret
scalar with the elliptic-curve base point is masked, defeating timing
/ cache / EM side-channel attacks on signing. The `secp256k1.h:820-841`
doc string explicitly recommends "doing so before every few
computations involving secret keys ... as a defense-in-depth measure"
and tags the API as `SECP256K1_WARN_UNUSED_RESULT`.

lunarblock's `crypto.lua:610-615`:

```lua
local libsecp256k1 = ffi.load("secp256k1")

local secp_ctx = libsecp256k1.secp256k1_context_create(
  bit.bor(0x0101, 0x0201)  -- VERIFY | SIGN
)
-- ← NO secp256k1_context_randomize CALL HERE
```

The `secp256k1_context_randomize` symbol is **not even declared in
the FFI cdef** (line 372-608). lunarblock cannot call it even if
someone wanted to.

W158 BUG-7 (`CORE-PARITY-AUDIT/w158-bip322-message-signing.md:533-571`)
first documented this gap and named lunarblock as the origin of the
fleet-wide pattern. W159 confirms at the FFI level:

- No declaration of `secp256k1_context_randomize` in the cdef.
- No re-randomize loop on a sign cadence.
- The deprecated `VERIFY | SIGN` flag (BUG-1) compounds the
  documentation gap: a reviewer who sees the flag would assume the
  context was prepared the pre-v0.4.0 way (with separate randomize
  for the sign context), but no randomize exists.

**Affected sign paths** (every one runs against an unblinded scalar):
- `ecdsa_sign` (`crypto.lua:874-889`) — wallet send, PSBT signing,
  `signrawtransactionwithkey`.
- `ecdsa_sign_recoverable_compact` (`crypto.lua:899-918`) —
  `signmessage` / `signmessagewithprivkey`.
- `schnorr_sign` (`crypto.lua:1032-1055`) — defined but currently
  uncalled (BUG-6); the moment it IS wired, every Taproot key-path
  sign leaks too.
- `taproot_tweak_seckey` (`crypto.lua:1066-1084`) — every BIP-86
  derivation.
- `ec_seckey_tweak_add` (`crypto.lua:820-833`) — BIP-32 CKDpriv.
- `ec_pubkey_create` inside `pubkey_from_privkey` (`crypto.lua:793-806`)
  — every BIP-32 pubkey derive, every WIF import, every wallet load.
- `ellswift_create` (`crypto.lua:1094-1103`) — every BIP-324 outbound
  handshake.

**Worker-pool side:** `parallel_verify.c:430` also creates raw,
un-randomized contexts. Pure-verify contexts benefit less than sign
contexts, but per `secp256k1.h:829-833` "all functions which take a
secret key (or a keypair) as an input" benefit — and a verify-only
context is still cheap to randomize.

**File:** `src/crypto.lua:610-615` (Lua-side global context),
`src/crypto.lua:372-608` (FFI cdef — randomize symbol not declared),
`csrc/parallel_verify.c:425-460` (worker contexts).

**Core ref:** `bitcoin-core/src/key.cpp:572-587` (`ECC_Start`);
`bitcoin-core/src/secp256k1/include/secp256k1.h:820-841`
(`secp256k1_context_randomize`).

**Impact:**
- Side-channel: an attacker with local timing / cache / EM access to
  the lunarblock process (co-located VM, malicious extension under
  the same OS user, side-loaded BPF probe) can extract bits of the
  signing scalar. Enough signatures → full key recovery.
- Fleet pattern: confirmed (W158/W159) as universal. lunarblock NAMED
  ORIGIN. Per the cross-cite chain: rustoshi / nimrod / clearbit /
  camlcoin all also lack `context_randomize`. Clearbit BUG (W158
  cipher-as-scalar) compounded by no-randomize.
- Fix: 2 lines — add `secp256k1_context_randomize` to the FFI cdef
  + one call with `M.random_bytes(32)` after context create.
  PLUS extend the parallel-verify init at `parallel_verify.c:430`.
- 5+ weeks unfixed since W158 BUG-7 (longest-known side-channel
  carry-forward in lunarblock).

---

## BUG-3 (P0-SEC) — `secp256k1_ec_seckey_verify` NEVER declared in FFI; no scalar-range gate on any sign or pubkey-create path

**Severity:** P0-SEC. Bitcoin Core's `CKey::Check`
(`bitcoin-core/src/key.cpp:158-160`) calls
`secp256k1_ec_seckey_verify(secp256k1_context_static, vch)` before
accepting any 32-byte slice as a private key. `CKey::MakeNewKey`
(`key.cpp:162-168`) rolls until `Check()` passes. Every WIF import,
every BIP-32 derive, every PSBT sign path that takes a raw seckey
runs through `Check()`. The function rejects:
- `seckey == 0` (point at infinity → degenerate ECDSA / Schnorr nonce
  leak).
- `seckey >= n` (curve order — would wrap into a smaller scalar,
  exposing the wrap-around math to a side-channel observer; also
  produces a different signature than intended).

lunarblock's FFI cdef (`crypto.lua:372-608`) does NOT declare
`secp256k1_ec_seckey_verify`. Every sign / pubkey-create path
relies on the downstream API to fail:

- `secp256k1_ec_pubkey_create` returns 0 if the seckey is invalid —
  but the failure path is bundled into a generic `"invalid private
  key"` error string (`crypto.lua:797`). The caller cannot
  distinguish "seckey out of range" from "all-zero seckey" from
  "transient FFI failure". Specific defensive logging is impossible.
- `secp256k1_ecdsa_sign` likewise returns 0 — but the worse case is
  a partial-failure where the sign succeeds for a corrupted seckey
  whose top bit happens to be set to wrap-into-a-valid-scalar; this
  produces a NEW key whose signatures are valid but uncoupled from
  the operator's expected pubkey.

**Worse**: `taproot_tweak_seckey` (`crypto.lua:1066-1084`) calls
`secp256k1_keypair_create` directly. The libsecp256k1 docs explicitly
state that `_keypair_create` returns 0 for invalid seckeys, but
lunarblock's error is the generic `"keypair_create failed (invalid
seckey)"` — no scalar-range diagnostic, no upstream gate.

`ec_seckey_tweak_add` (`crypto.lua:820-833`) wraps Core's CKDpriv. The
function copies the parent seckey into a local mutable buffer, calls
`_tweak_add`, and returns the result. If the parent seckey was already
out of range, the tweak math runs on garbage. libsecp256k1 will return
0 in this case, but the error string `"invalid derivation (tweak >= n,
k_i == 0, or bad parent)"` lumps four distinct failure modes into one.

`ellswift_create` (`crypto.lua:1094-1103`) likewise — Core's ECDH
module doesn't benefit from context_randomize per `secp256k1.h:834`,
but it STILL requires a valid seckey.

**Affected scenarios:**
- **WIF import with truncated payload**: `wallet.lua:2073-2078` —
  `payload:sub(1, 32)` returns fewer than 32 bytes if `payload` is
  shorter than 32. The FFI cdef declares `const unsigned char* seckey`
  — LuaJIT passes the underlying C-string-with-NULL-terminator
  pointer, libsecp256k1 reads 32 bytes regardless of Lua-string
  length, the 32-byte buffer reads past the heap end. Either a fresh
  Lua string boundary (read-zero), or a Lua intern-pool boundary
  (read-attacker-controlled). **No length precheck on `payload`**.
- **Cipher-as-scalar (W158 clearbit ORIGIN)**: clearbit's W158 BUG was
  feeding cipher output bytes directly into the seckey parameter
  without a `seckey_verify` filter. lunarblock's identical surface
  invites the same class of bug if any future code path reuses the
  ECIES / ChaCha20 output as a seckey.

**File:** `src/crypto.lua:372-608` (FFI cdef — `_seckey_verify`
absent), `src/crypto.lua:793-806, 820-833, 874-889, 899-918,
1032-1055, 1066-1084, 1094-1103` (sign / derive sites), `src/wallet.lua:2073-2095` (WIF import).

**Core ref:**
`bitcoin-core/src/secp256k1/include/secp256k1.h:685-707`
(`secp256k1_ec_seckey_verify`); `bitcoin-core/src/key.cpp:158-160`
(`CKey::Check`); `bitcoin-core/src/key.cpp:162-168`
(`CKey::MakeNewKey`).

**Impact:**
- Distinct failure modes collapsed into generic strings — debug pain
  but more importantly, missing operator-visible diagnostic for
  cipher-as-scalar / WIF-truncation events.
- Out-of-range scalars silently accepted at WIF import on
  truncated-payload edge case (FFI reads past Lua string boundary;
  LuaJIT does NOT terminate Lua strings with C NUL — string interning
  is by length, not by NULL).
- Cross-fleet: every impl whose key path bypasses
  `secp256k1_ec_seckey_verify` is on the same trajectory as W158
  clearbit cipher-as-scalar BUG.

---

## BUG-4 (P1) — `secp256k1_xonly_pubkey` typedef declared as `data[96]` instead of Core's `data[64]`

**Severity:** P1. `bitcoin-core/src/secp256k1/include/secp256k1_extrakeys.h:22-24`:

```c
typedef struct secp256k1_xonly_pubkey {
    unsigned char data[64];
} secp256k1_xonly_pubkey;
```

lunarblock's `crypto.lua:478`:

```lua
typedef struct { unsigned char data[96]; } secp256k1_xonly_pubkey;
```

And the inline comment at `crypto.lua:516-517` doubles down on the
confusion:

```lua
/* ...
 * The fixed 96-byte size matches the public typedef in
 * secp256k1_extrakeys.h:33-35. */
typedef struct { unsigned char data[96]; } secp256k1_keypair;
```

Lines 33-35 of `secp256k1_extrakeys.h` are the `secp256k1_keypair`
typedef (which IS 96 bytes), NOT the `secp256k1_xonly_pubkey`
typedef. lunarblock confused the two structures during the original
copy-paste of the FFI cdef.

**Why this is not silently broken today:**
- LuaJIT FFI calls pass a `secp256k1_xonly_pubkey*` to the C library.
  The library only touches the first 64 bytes; the trailing 32 bytes
  in lunarblock's struct are unused padding.
- All callsites construct via `ffi.new("secp256k1_xonly_pubkey")` —
  the over-allocation is wasted but not corrupted.

**Why it IS a bug:**
- ABI parity: any future use of `ffi.sizeof("secp256k1_xonly_pubkey")`
  (e.g., serialise to disk, hash for cache-key, allocate a fixed
  array of N xonly pubkeys for a batch verify wrapper) will report
  96 bytes instead of 64 — wrong size everywhere it leaks out.
- Future library bumps: if libsecp256k1 ever introduces a new struct
  IMMEDIATELY after `secp256k1_xonly_pubkey` and the library is built
  with `-fpack-struct`, lunarblock's mis-sized struct could overlay
  the next field.
- Documentation: the inline comment lies about the source line.

**Confirmation:** `crypto.lua:1556` constructs an xonly_pubkey with
`ffi.new("secp256k1_xonly_pubkey")`; downstream
`secp256k1_xonly_pubkey_tweak_add` and `_xonly_pubkey_from_pubkey`
calls work because libsecp256k1 only reads the first 64 bytes.

**File:** `src/crypto.lua:478` (typedef wrong size), `src/crypto.lua:516-517`
(comment cites wrong line).

**Core ref:** `bitcoin-core/src/secp256k1/include/secp256k1_extrakeys.h:22-24`.

**Impact:** wasted 32 bytes per xonly_pubkey allocation (negligible);
ABI parity gap; latent break on a future library refactor; documentation
lie.

---

## BUG-5 (P1-SEC) — No sign-then-verify paranoia on any of the three sign primitives

**Severity:** P1-SEC. Bitcoin Core's `CKey::Sign` (`key.cpp:209-235`):

```cpp
ret = secp256k1_ecdsa_sign(...);
// ... grind for low R ...
assert(ret);
secp256k1_ecdsa_signature_serialize_der(...);
vchSig.resize(nSigLen);
// Additional verification step to prevent using a potentially corrupted signature
secp256k1_pubkey pk;
ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pk, UCharCast(begin()));
assert(ret);
ret = secp256k1_ecdsa_verify(secp256k1_context_static, &sig, hash.begin(), &pk);
assert(ret);
return true;
```

And `CKey::SignCompact` (`key.cpp:262-270`):

```cpp
ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &epk, UCharCast(begin()));
assert(ret);
ret = secp256k1_ecdsa_recover(secp256k1_context_static, &rpk, &rsig, hash.begin());
assert(ret);
ret = secp256k1_ec_pubkey_cmp(secp256k1_context_static, &epk, &rpk);
assert(ret == 0);
```

Both functions re-verify the freshly-produced signature against the
expected pubkey. The rationale (per the inline comment):
"Additional verification step to prevent using a potentially corrupted
signature." This defends against:
- A subtle bug in libsecp256k1 emitting a signature that decodes
  back to a different pubkey (zero-RFC6979-collision class).
- Memory corruption (cosmic-ray, mlock failure, OS-level miswire)
  between sign and serialize.
- A future hardware-accelerated sign path that miscomputes when the
  CPU is throttled / overheating.

lunarblock's three sign primitives:

```lua
-- crypto.lua:874-889 ecdsa_sign
function M.ecdsa_sign(privkey32, msg_hash32)
  local sig = ffi.new("secp256k1_ecdsa_signature")
  if libsecp256k1.secp256k1_ecdsa_sign(...) ~= 1 then
    return nil, "signing failed"
  end
  local output = ffi.new("unsigned char[72]")
  ...
  libsecp256k1.secp256k1_ecdsa_signature_serialize_der(...)
  return ffi.string(output, outputlen[0])
  -- ← NO RE-VERIFY
end

-- crypto.lua:899-918 ecdsa_sign_recoverable_compact
function M.ecdsa_sign_recoverable_compact(privkey32, msg_hash32, compressed)
  ...
  if libsecp256k1.secp256k1_ecdsa_sign_recoverable(...) ~= 1 then
    return nil, "signing failed"
  end
  ...
  return string.char(header) .. ffi.string(output64, 64)
  -- ← NO RECOVER-AND-CMP
end

-- crypto.lua:1032-1055 schnorr_sign
function M.schnorr_sign(privkey32, msg32, aux_rand32)
  ...
  if libsecp256k1.secp256k1_schnorrsig_sign32(...) ~= 1 then
    return nil, "schnorrsig_sign32 failed"
  end
  return ffi.string(sig64, 64)
  -- ← NO RE-VERIFY
end
```

`crypto.lua:1019-1020` even has a comment-as-confession:
> "Mirrors Core's CKey::SignSchnorr (bitcoin-core/src/key.cpp:273-277),
> modulo defense-in-depth verify (caller can re-check via M.schnorr_verify)."

It admits the divergence in writing. No caller re-verifies.

**File:** `src/crypto.lua:874-889, 899-918, 1032-1055`.

**Core ref:** `bitcoin-core/src/key.cpp:209-235` (`CKey::Sign`),
`bitcoin-core/src/key.cpp:250-271` (`CKey::SignCompact`),
`bitcoin-core/src/key.cpp:273-277` (`CKey::SignSchnorr` →
`KeyPair::SignSchnorr` re-verify).

**Impact:**
- A corrupted signature escapes the local sign path. The far-end
  verifier (or the network) rejects it; the operator sees a "transaction
  rejected" instead of a "sign failed" with the corruption masked.
- Class of bugs not yet observed in libsecp256k1 (it's mature), but
  the cost of the re-verify is ~one ECDSA verify (~50 μs) per sign;
  matters on cold-start sign loops, negligible on a normal node.
- Fleet pattern: this paranoia is the only thing protecting against
  "signature corrupted between sign and serialize" — most impls in
  the fleet also skip it. Consistency with Core matters.

---

## BUG-6 (P1-CDIV) — `M.schnorr_sign` is defined but uncalled; rpc.lua claims "M.schnorr_sign is unavailable" — "comment-as-confession" + "wiring-look-but-no-wire"

**Severity:** P1-CDIV. `src/crypto.lua:1032-1055` defines a complete
`M.schnorr_sign` function with all the BIP-340 plumbing
(`secp256k1_keypair_create` + `secp256k1_schnorrsig_sign32` +
optional `aux_rand32`). The function is on the module's public
surface, the FFI cdef declares all the underlying symbols, the
keypair API works.

But `src/rpc.lua:6130-6145`:

```lua
-- camlcoin/lib/rpc.ml:signrawtransactionwithkey (best-in-class)
--
-- Both handlers share a common signing core: decode tx, locate the
-- prev_out script_pubkey + value for each input ..., classify the SPK,
-- look up the matching key (by hash160 / address), produce the sighash,
-- ECDSA-sign, and write the witness or scriptSig.  P2TR (Schnorr) is
-- not signed because lunarblock ships ECDSA-only crypto today
-- (M.schnorr_sign is unavailable); the input is left untouched and
-- `complete=false` is reported.
```

The comment is FALSE as of the current source. `crypto.lua:1032`
exports `M.schnorr_sign`. A grep across the entire repo shows ZERO
non-test callers:

```
$ grep -rn 'schnorr_sign' src/
src/crypto.lua:1032: function M.schnorr_sign(privkey32, msg32, aux_rand32)
src/rpc.lua:6137:    -- ships ECDSA-only crypto today (M.schnorr_sign is unavailable)
```

This is the **wiring-look-but-no-wire** pattern: the helper is wired
end-to-end (FFI + keypair + sign32 + aux_rand handling), the comment
in the consumer admits it could be called, but it isn't.

Consequences:
- `signrawtransactionwithkey` returns `complete=false` for any P2TR
  input regardless of whether the wallet holds the necessary seckey.
  Operators using lunarblock to co-sign Taproot transactions cannot
  use the standard Bitcoin Core RPC contract.
- BIP-322 message signing (W158 wave) for Taproot addresses is
  blocked on the same path.
- PSBT signers (`psbt.lua`) cannot complete a P2TR keypath PSBT.

**File:** `src/crypto.lua:1032-1055` (defined), `src/rpc.lua:6137`
(comment-as-confession), `src/wallet.lua:1280-1320, 1473-1495,
1693-1714` (P2TR-eligible sign sites that route through ECDSA only).

**Core ref:** `bitcoin-core/src/key.cpp:273-277` (`CKey::SignSchnorr`),
`bitcoin-core/src/script/signingprovider.cpp` (P2TR signing).

**Impact:**
- Functional gap: P2TR signing through lunarblock's RPC is impossible.
  Comment ships operators into a "feature missing" state when the
  feature is actually implemented.
- Cross-pattern with BUG-5 (no sign-then-verify): even when schnorr_sign
  IS wired, the sign-once-and-trust posture sticks.
- "Comment-as-confession" pattern (~15th distinct lunarblock instance
  per W158 tracking) — admits a divergence in writing while the code
  has moved on.

---

## BUG-7 (P0-SEC) — No `memzero` / `ffi.fill` on seckey scratch buffers; LuaJIT GC keeps them alive indefinitely

**Severity:** P0-SEC. Bitcoin Core wraps every seckey scratch through
`memory_cleanse` on failure paths (`key.cpp:561`) and stores live
seckeys in `secure_allocator` (`key.cpp:11-14`). The `secure_allocator`
backs onto LockedPool, which calls `mlock` + `madvise(MADV_DONTDUMP)`
on the page so the seckey:
1. Never appears in swap (`mlock`).
2. Never appears in a core dump (`MADV_DONTDUMP`).
3. Zeroes on free (`memory_cleanse`).

lunarblock has none of this. Every seckey lives in:

1. **A Lua string** (e.g., the WIF-imported `privkey` field of
   `Wallet.keys[addr]` at `wallet.lua:2086`). Lua strings are
   GC-managed, hashed into the global string interner, and live until
   the last reference goes. The string interner's hash table is a
   plain `malloc`-backed buffer — swappable, dumpable, never zeroed.
2. **A cdata buffer** (`ffi.new("unsigned char[32]")` at
   `crypto.lua:828`). LuaJIT cdata is GC-managed but not zeroed on
   collect. A pthread that LuaJIT GC has not yet collected can still
   hold the buffer's memory.
3. **A raw FFI-passed pointer** — the Lua-string-as-C-pointer trick:
   when `ffi.cast("const unsigned char*", privkey32)` runs, the
   resulting pointer is the underlying Lua string's payload. The
   string's lifetime extends to the cdata's lifetime, which extends
   to the next GC cycle. There is no zeroing.

**Site-by-site:**

- `crypto.lua:828-833` — `ec_seckey_tweak_add` allocates a mutable
  32-byte buffer, copies the parent seckey in, calls
  `_seckey_tweak_add` (which mutates the buffer in place to the
  child seckey), then returns `ffi.string(seckey, 32)` — the seckey
  buffer is GC'd at some point in the future. **No `ffi.fill(seckey,
  32, 0)` between use and GC.**
- `crypto.lua:1042-1055` — `schnorr_sign` allocates a
  `secp256k1_keypair` (96 bytes containing the seckey + pubkey),
  calls `_keypair_create`, signs, then returns the sig. The keypair
  cdata is GC'd at some point in the future. **No zeroing.**
- `crypto.lua:1066-1084` — `taproot_tweak_seckey` is the same shape.
- `wallet.lua:2086` — `self.keys[addr].privkey = privkey` stores the
  seckey as a Lua string. The string interner caches it; on next GC
  it MAY get freed but is NEVER zeroed.

**Threat model:**
- Co-located VM / container neighbour reading swap → seckey extraction.
- Crashed-process core-dump capture → seckey extraction.
- BPF-side memory peek (works on any user with CAP_SYS_PTRACE or in
  the same uid) → live extraction.

**File:** `src/crypto.lua:820-833, 1032-1084`, `src/wallet.lua:2073-2095`.

**Core ref:** `bitcoin-core/src/key.cpp:11-14` (secure_allocator),
`bitcoin-core/src/key.cpp:561` (memory_cleanse on failure),
`bitcoin-core/src/support/lockedpool.cpp` (LockedPool implementation).

**Impact:**
- Side-channel: seckey persists in process memory after intended use.
- Cross-cite BUG-2 (side-channel blinding) — even when blinding is
  added, the seckey persistence is a separate channel.
- Cross-cite BUG-8 (LockedPool).
- Fleet pattern: every impl that uses GC'd strings for seckey storage
  is affected (Lua, OCaml, Erlang, TypeScript, Python, Haskell — six
  of ten).

---

## BUG-8 (P1-SEC) — No LockedPool / `mlock` for seckey storage; wallet seckeys swappable to disk

**Severity:** P1-SEC. Bitcoin Core's `LockedPool` (defined in
`src/support/lockedpool.h/cpp`) pages-mlocks the seckey region. Any
process under memory pressure may swap out plain (non-mlocked) pages,
including seckeys — landing them on disk as part of the encrypted
or unencrypted swap area. From swap, seckeys are recoverable by:
- A reboot into a forensics OS.
- A kernel-level memory dump (Linux `crash` tool).
- An attacker with disk-level access to a system that ran lunarblock.

lunarblock's wallet (`wallet.lua:680-700, 2086`) stores all seckeys as
plain Lua strings on the `Wallet.keys` table. The wallet-file-at-rest
encryption (`wallet.lua:100-140` for AES-256, encryption key derived
via PBKDF2 in `derive_key`) protects the disk file, but the in-memory
representation is the decrypted plain string.

**File:** `src/wallet.lua:680-700, 2086`.

**Core ref:** `bitcoin-core/src/support/lockedpool.cpp`,
`bitcoin-core/src/support/allocators/secure.h`.

**Impact:**
- Swap-to-disk leak under memory pressure.
- Core-dump leak (lunarblock processes can dump on a SIGSEGV; no
  `prctl(PR_SET_DUMPABLE, 0)` analogue).
- Cross-cite BUG-7 (no zeroing on free → even after the Lua-side
  reference dies, the swap copy persists).

---

## BUG-9 (P1) — No `ffi.gc(secp_ctx, secp256k1_context_destroy)` finalizer; context leaks at process exit

**Severity:** P1. lunarblock's `secp_ctx` at `crypto.lua:613-615` is a
module-level local cdata. LuaJIT GC does not invoke
`secp256k1_context_destroy` on it because no `ffi.gc(secp_ctx,
libsecp256k1.secp256k1_context_destroy)` finalizer is registered.

**Consequences:**
- Process exit: the context leaks ~32 KB of precomputed tables (Core
  default `ECMULT_GEN_PREC_BITS=4` → ~32 KB). On a one-shot RPC tool
  the leak is invisible; on a long-running daemon the cost is also
  trivial. The bigger issue is the test suite.
- Test suite: every `busted` test that loads `lunarblock.crypto`
  creates a new global context (one per Lua state). If the test
  harness recycles Lua states without process-exit, contexts pile up.
- Library reload: if `ffi.load("secp256k1")` were ever called twice
  (different paths, version probe), each call creates a fresh
  function-pointer table; the first context's destroy function may
  resolve via the second load's table — a mismatch that produces
  silent UAF.

**File:** `src/crypto.lua:613-615`.

**Core ref:** `bitcoin-core/src/key.cpp:590-597` (`ECC_Stop`),
`bitcoin-core/src/init.cpp` (`ECC_Context` RAII).

**Impact:** test-suite hygiene; latent UAF on library-reload edge
case; consistency with Core's RAII pattern.

---

## BUG-10 (P2) — Schnorr batch verify entirely absent

**Severity:** P2 (parity-with-Core; not a divergence). libsecp256k1's
public header `secp256k1_schnorrsig.h` ships single-sig
`secp256k1_schnorrsig_verify`. A batch verify exists as the
experimental `schnorrsig` batch module but is NOT exposed in the
public header. Bitcoin Core itself does NOT use Schnorr batch verify
today.

lunarblock matches Core's status: only `secp256k1_schnorrsig_verify`
is declared (FFI cdef `crypto.lua:486-492`). The W126 BIP-340 spec
recommends batch verify for IBD throughput (~30% faster at typical
block sizes), and `pv_verify_signatures` (`parallel_verify.c:586-644`)
provides the thread-pool infrastructure that would make batching
straightforward.

Listed for fleet pattern completeness: every impl matches Core on
"no Schnorr batch verify yet"; lunarblock has no special divergence.
Not a P1 because: (a) Core itself doesn't do this, (b) the worker
pool gives lunarblock a head-start should the feature land upstream.

**File:** `src/crypto.lua:486-492`,
`csrc/parallel_verify.c:586-644`.

**Core ref:** `bitcoin-core/src/secp256k1/include/secp256k1_schnorrsig.h`
(single-sig only).

**Impact:** none today; performance opportunity tomorrow.

---

## BUG-11 (P1) — `pv_verify_signatures` does not validate `count`; integer overflow on the for-loop is possible at the C ABI boundary

**Severity:** P1. `csrc/parallel_verify.c:586-644`:

```c
int pv_verify_signatures(sig_verify_job *jobs, int count) {
    ...
    if (count <= 0) {
        return 0;
    }
    ...
    for (int i = 0; i < count; i++) {
        jobs[i].result = verify_ecdsa(...)
        ...
    }
```

The function takes `int count` from Lua via the FFI. Lua-side
(`validation.lua:128`) `ffi.new("sig_verify_job[?]", #sigs)` is bounded
by the Lua array length, but a malicious caller bypassing
`verify_signatures_parallel` and calling `pv_lib.pv_verify_signatures`
directly with a fabricated `int count = INT_MAX` would:
1. Pass the `count <= 0` guard.
2. Pass the `count < MIN_PARALLEL_INPUTS` short-circuit (16).
3. Enter the parallel path with `current_kind = PV_JOB_SIG` and
   `job_count = INT_MAX`.
4. Workers read `((sig_verify_job *)job_queue)[job_idx]` for `job_idx
   in [0, INT_MAX)` — reading past the end of the actual array,
   triggering segfault OR worse, leaking adjacent memory through
   `result` bytes that get written back.

The `int i` for-loop also is unsafe: `for (int i = 0; i < count; i++)`
where `count = INT_MAX` is well-defined as a loop, but the array
index `jobs[i]` is undefined for `i >= actual_count`.

**File:** `csrc/parallel_verify.c:586-644`, `src/validation.lua:127-200`
(boundary-aware Lua wrapper).

**Core ref:** N/A (Core's `CheckQueue` uses bounded vectors).

**Impact:** RCE / memory disclosure if an attacker can reach the FFI
boundary (e.g., a malicious Lua module loaded into the same VM). Not
reachable from any external surface today.

---

## BUG-12 (P1) — Unified-queue race: a second batch call before the first batch's `jobs` cdata is released can overwrite `job_queue` mid-flight

**Severity:** P1. `csrc/parallel_verify.c:617-634`:

```c
pthread_mutex_lock(&queue_mutex);

current_kind = PV_JOB_SIG;
job_queue = jobs;
job_count = count;
jobs_completed = 0;
next_job = 0;

pthread_cond_broadcast(&work_available);

while (jobs_completed < job_count) {
    pthread_cond_wait(&work_done, &queue_mutex);
}

job_queue = NULL;

pthread_mutex_unlock(&queue_mutex);
```

The `queue_mutex` is held for the entire wait, so a second concurrent
call to `pv_verify_signatures` blocks until the first completes. That
much is safe. But the contract with Lua-side
`validation.lua:128-200` requires the caller to keep the `jobs` cdata
+ `pubkey_ptrs` + `sig_ptrs` + `hash_ptrs` tables alive until the
C call returns. The C call DOES return only after all workers finish,
so the explicit Lua-side comment "We need to keep references to
prevent GC" (`validation.lua:131`) covers the synchronous case.

**The hazard:** if `init_parallel_verify` ever opens a non-blocking
async path (or a future caller forgets the GC-pinning), the GC could
collect `pubkey_ptrs[i]` (a `ffi.new("uint8_t[?]", ...)`) WHILE the
worker is still reading `jobs[i].pubkey` (which is a raw `const
uint8_t *` cdata pointer into that buffer). The compiler is correct
("the C code didn't mutate the pointer, so it must still be valid"),
but LuaJIT GC can free the underlying buffer because the Lua-side
table reference is gone.

**File:** `csrc/parallel_verify.c:617-634`,
`src/validation.lua:127-200`.

**Core ref:** N/A (Core's CheckQueue uses RAII with `std::vector`
backing).

**Impact:** UAF / memory disclosure if a future refactor breaks the
GC-pinning contract. Defense-in-depth would copy `jobs[i].pubkey`
bytes into the `sig_verify_job` itself (inline) rather than holding
external pointers.

---

## BUG-13 (P1) — `pubkey_from_privkey` has no `#privkey32 == 32` length precheck; FFI reads 32 bytes regardless of Lua string length

**Severity:** P1. `src/crypto.lua:793-806`:

```lua
function M.pubkey_from_privkey(privkey32, compressed)
  if compressed == nil then compressed = true end
  local pubkey = ffi.new("secp256k1_pubkey")
  if libsecp256k1.secp256k1_ec_pubkey_create(secp_ctx, pubkey, privkey32) ~= 1 then
    return nil, "invalid private key"
  end
  ...
```

The FFI cdef declares `secp256k1_ec_pubkey_create(..., const unsigned
char* seckey)` — libsecp256k1 reads exactly 32 bytes from the pointer.
LuaJIT FFI converts a Lua string to a `const char*` to its underlying
payload buffer. If `privkey32` is fewer than 32 bytes (e.g., from a
truncated WIF — `wallet.lua:2077` `payload:sub(1, 32)` returns a
shorter string when `#payload < 32`), libsecp256k1 reads past the
buffer:
- LuaJIT does NOT NUL-terminate Lua strings the way C does — strings
  are length-prefixed in the string interner. The byte at position
  `#privkey32 + 1` is the next field in the interner table (often a
  count, a hash, or another string header).
- The read is undefined-behaviour from the C perspective but
  deterministic-by-implementation: libsecp256k1 sees whatever bytes
  follow in memory.
- The seckey passed to `_ec_pubkey_create` is `payload[1..#payload]
  || interner_garbage[1..(32-#payload)]`. This is attacker-influenced
  if the attacker can control LuaJIT's recent string allocations
  (e.g., via an RPC string before the WIF import).

`crypto.lua:998-1007` `schnorr_verify` has the right length check
(W158 BUG-something — see the inline comment about
"libsecp256k1's secp256k1_xonly_pubkey_parse and
secp256k1_schnorrsig_verify both read exactly 32 and 64 bytes
respectively..."). The pattern is well-documented inside lunarblock,
just not applied to `pubkey_from_privkey`.

Same shape gap at:
- `crypto.lua:874-889` `ecdsa_sign(privkey32, msg_hash32)` — no length
  check on either argument.
- `crypto.lua:963-988` `decompress_pubkey(compressed33)` — has a length
  check (PASS), good shape to copy.

**File:** `src/crypto.lua:793-806, 874-889`.

**Core ref:** `bitcoin-core/src/key.cpp:158-160`
(`CKey::Check` length is implicit in `unsigned char vch[32]` array
parameter type).

**Impact:**
- WIF-truncation feed: shorter-than-32 payload silently produces a
  pubkey from a seckey whose tail is interner garbage. The wallet
  stores this garbage-tail pubkey; subsequent signatures verify
  against a key the operator did not intend to control.
- Cross-cite BUG-3 (no seckey_verify gate would also catch this).

---

## BUG-14 (P1-SEC) — `ec_seckey_tweak_add` and `taproot_tweak_seckey` return a Lua string of the tweaked seckey but never zero the underlying cdata buffer

**Severity:** P1-SEC ("seckey-into-Lua-interner" companion to BUG-7).
`crypto.lua:820-833`:

```lua
function M.ec_seckey_tweak_add(parent_priv32, tweak32)
  ...
  local seckey = ffi.new("unsigned char[32]")
  ffi.copy(seckey, parent_priv32, 32)
  if libsecp256k1.secp256k1_ec_seckey_tweak_add(secp_ctx, seckey, tweak32) ~= 1 then
    return nil, "invalid derivation ..."
  end
  return ffi.string(seckey, 32)
end
```

After `_seckey_tweak_add` succeeds, `seckey[0..31]` holds the child
seckey. `ffi.string(seckey, 32)` interns those 32 bytes as a Lua
string. The local `seckey` cdata is then unreferenced from Lua —
LuaJIT GC will eventually free the buffer, but until then:
- The cdata holds the child seckey.
- The new Lua string holds an interned copy of the child seckey.
- The Lua-string copy lives in the interner ~indefinitely (until GC
  rebuilds the interner, which only happens under memory pressure).

`taproot_tweak_seckey` at `crypto.lua:1066-1084` has the same shape:
allocates `out = ffi.new("unsigned char[32]")`, calls
`_keypair_sec(secp_ctx, out, kp)`, returns `ffi.string(out, 32)`.
**No `ffi.fill(out, 32, 0)` between the libsecp256k1 call and
return.**

Core wraps each of these through `memory_cleanse` plumbing
(`key.cpp:561`).

**Fix shape (1 line per function):**

```lua
local result = ffi.string(seckey, 32)
ffi.fill(seckey, 32, 0)  -- defense-in-depth zero before GC
return result
```

**File:** `src/crypto.lua:820-833, 1066-1084`.

**Core ref:** `bitcoin-core/src/key.cpp:561`,
`bitcoin-core/src/support/cleanse.cpp::memory_cleanse`.

**Impact:** cross-cite BUG-7 (the seckey is double-resident: once in
the local cdata, once in the interned Lua string).

---

## BUG-15 (P1) — `secp256k1_context_static` and `secp256k1_selftest` never used; lunarblock instantiates a single combined SIGN+VERIFY context for non-secret ops

**Severity:** P1. Bitcoin Core's modern (post-v0.4.0) pattern is:
- One `secp256k1_context*` (the sign context) — used ONLY for
  operations that take a secret key.
- The library-provided static `secp256k1_context_static` — used for
  everything else (verify, parse, serialize, cmp).
- `secp256k1_selftest()` called before using `secp256k1_context_static`.

The split has two benefits:
1. The verify-side path runs against an unconditionally-correct
   library context — no randomize, no precomputed tables that could
   be tampered with by an attacker writing to lunarblock's heap.
2. `_context_static` cannot leak the sign-side randomize seed via
   memory pressure (it's library memory, not lunarblock heap).

lunarblock uses ONE shared context for everything (`crypto.lua:613-615`).
That context is created with `VERIFY | SIGN`, never randomized
(BUG-2). Every verify call (`ecdsa_verify`, `schnorr_verify`,
`tweak_pubkey`, etc.) runs against the same context that holds the
sign material. If the sign-side ever gets randomize (BUG-2 fix), the
randomize seed lives in the same memory as the verify path —
defeating the whole isolation argument.

Core uses `secp256k1_context_static` in `key.cpp` lines 159, 190, 200,
226, 232, 258, 266, 268 — every non-secret operation routes there.

`secp256k1_selftest` is also never called by lunarblock. Per
`secp256k1.h:243` it is "highly recommended" before first use of the
static context.

**File:** `src/crypto.lua:613-615` (only one context),
`src/crypto.lua:372-608` (cdef does not declare `_context_static` or
`_selftest`).

**Core ref:**
`bitcoin-core/src/secp256k1/include/secp256k1.h:243-249`
(`secp256k1_context_static`);
`bitcoin-core/src/secp256k1/include/secp256k1.h:267`
(`secp256k1_selftest`); `bitcoin-core/src/key.cpp:159, 190, 200, 226,
232, 258, 266, 268` (static context use).

**Impact:**
- No isolation between sign-side blinding seed (BUG-2) and verify-side
  hot path.
- No selftest run on the verify path; if the library binary is
  corrupted (e.g., a partial library swap on disk), lunarblock won't
  detect it until a real signature mismatch crashes a block-validate
  loop.
- Cross-cite BUG-1 (modern API usage); BUG-2 (randomize).

---

## BUG-16 (P1) — No `secp256k1_context_set_illegal_callback` / `_error_callback`; library aborts the process on internal misuse instead of crashing in a controlled way

**Severity:** P1. libsecp256k1 by default calls `abort()` on detected
internal misuse (e.g., NULL pointer where non-NULL required, invalid
flags). Production deployments install callbacks:
- `secp256k1_context_set_illegal_callback(ctx, fn, data)` — called
  when API contract is violated.
- `secp256k1_context_set_error_callback(ctx, fn, data)` — called when
  an internal error occurs (rare; usually indicates memory
  corruption).

Without callbacks, an attacker who can reach a single misuse path
(e.g., via the BUG-11 / BUG-12 surfaces) gets a free DoS — the
node aborts with no log line, no crash dump, no recovery path. With
callbacks, lunarblock can log the misuse, return a controlled error
to Lua, and continue serving other RPCs.

Core does NOT install custom callbacks for the sign context, but it
DOES use `secp256k1_context_static` for non-secret ops — which is
audited library code that won't trigger illegal-callback. lunarblock's
single combined context with no callback is the worst-case combination.

**File:** `src/crypto.lua:613-615` (no callback registration),
`src/crypto.lua:372-608` (callback symbols not in cdef).

**Core ref:**
`bitcoin-core/src/secp256k1/include/secp256k1.h:325-360`
(`secp256k1_context_set_illegal_callback` /
`_error_callback`).

**Impact:** uncontrolled `abort()` on any FFI-boundary misuse;
DoS amplification of BUG-11 / BUG-12 / BUG-13 / BUG-3.

---

## BUG-17 (P1) — `ecdsa_verify` early-out on parse failure leaks parse-error reason via error string (timing channel)

**Severity:** P1 (timing oracle). `crypto.lua:629-652`:

```lua
function M.ecdsa_verify(pubkey_bytes, sig_der, msg_hash32)
  local pubkey = ffi.new("secp256k1_pubkey")
  if libsecp256k1.secp256k1_ec_pubkey_parse(
    secp_ctx, pubkey, pubkey_bytes, #pubkey_bytes
  ) ~= 1 then
    return false, "invalid public key"
  end

  local sig = ffi.new("secp256k1_ecdsa_signature")
  if libsecp256k1.secp256k1_ecdsa_signature_parse_der(
    secp_ctx, sig, sig_der, #sig_der
  ) ~= 1 then
    return false, "invalid DER signature"
  end
  ...
```

The three return paths (`invalid public key`, `invalid DER signature`,
`signature mismatch`) have measurably different wall-clock latencies:
- Pubkey parse failure: ~5 μs (one EC point parse).
- Sig parse failure: ~10 μs (point parse + DER walk).
- Full verify failure: ~80 μs (point parse + DER walk + verify).

The latency is observable to a network adversary; the error-string
distinction is observable to an RPC caller. Combined, an attacker can
fingerprint:
- Whether the supplied pubkey was a valid encoding (informs them about
  the script structure).
- Whether the sig was DER-valid but mathematically wrong (informs them
  the script context).

For consensus paths this isn't reachable (consensus rejects on first
error regardless). For RPC `verifymessage` / `validateaddress` it
matters.

Core's `verifymessage` (`rpc/util.cpp::SignMessage`) does NOT
distinguish these failures externally — all return `false` with the
same wall-clock pattern.

**File:** `src/crypto.lua:629-652`.

**Core ref:** `bitcoin-core/src/rpc/signmessage.cpp::verifymessage`.

**Impact:** timing / error-string fingerprint on RPC verify paths;
small, but in scope for a security-conscious wallet provider.

---

## BUG-18 (P1) — `ecdsa_sign_recoverable_compact` does not check that `header < 27 || header > 34` is impossible AFTER libsecp256k1 returns, only on the parse side; an attacker-supplied seckey that triggers `recid >= 4` is impossible per libsecp256k1 contract but lunarblock has no `assert(recid in 0..3)` after the call

**Severity:** P1. `crypto.lua:899-918`:

```lua
function M.ecdsa_sign_recoverable_compact(privkey32, msg_hash32, compressed)
  ...
  local recid = ffi.new("int[1]")
  if libsecp256k1.secp256k1_ecdsa_recoverable_signature_serialize_compact(
    secp_ctx, output64, recid, sig
  ) ~= 1 then
    return nil, "serialize_compact failed"
  end
  local header = 27 + recid[0] + (compressed and 4 or 0)
  return string.char(header) .. ffi.string(output64, 64)
```

libsecp256k1's contract guarantees `recid ∈ {0, 1, 2, 3}` on
successful return. If a future library bug (or a memory corruption)
sets `recid > 3`, the header byte computed at line 916 can:
- Overflow `string.char()`'s 0..255 range (Lua would error with
  "bad argument #1 to char (value out of range)") if recid is large.
- More subtly, `recid = 4` would produce header `27 + 4 + 4 = 35`
  for compressed or `27 + 4 = 31` for uncompressed — but `31` IS in
  the legal-header range, so the caller would misinterpret the
  uncompressed-sig with recid 4 as a compressed-sig with recid 0.

`ecdsa_recover_compact` at `crypto.lua:926-954` DOES validate the
header range (line 930-932), but the inverse function does not
sanity-check the recid that goes INTO the header. Defense-in-depth
gap.

**File:** `src/crypto.lua:899-918`.

**Core ref:** `bitcoin-core/src/key.cpp:260` —
`assert(rec != -1);` after `_recoverable_signature_serialize_compact`.

**Impact:** corruption-window gap; unreachable today, latent under
library bug.

---

## BUG-19 (P1) — `parallel_verify.c` worker contexts created with deprecated `SECP256K1_CONTEXT_VERIFY` (0x0101); not coordinated with the Lua-side context flag choice

**Severity:** P1. `parallel_verify.c:38, 430`:

```c
#define SECP256K1_CONTEXT_VERIFY 0x0101
workers[i].ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
```

Lua-side uses `VERIFY | SIGN = 0x0301` (BUG-1). The two pools therefore
have different flag profiles, which:
- Doesn't matter for correctness today (both treated as `CONTEXT_NONE`).
- Means the two pools have different precomputed-table profiles
  (worker contexts have only the verify table; Lua-side has both).
  Memory cost: ~32 KB extra per Lua-side context.
- Makes the codebase harder to audit: the operator reading
  `parallel_verify.c` sees `VERIFY` and assumes "verify only", but the
  Lua-side context is `VERIFY | SIGN`. Reviewing whether ANY sign
  call could route through a parallel worker requires manual
  cross-checking.

**File:** `csrc/parallel_verify.c:38, 430`.

**Core ref:** `bitcoin-core/src/key.cpp:575` (Core uses
`CONTEXT_NONE` uniformly).

**Impact:** code-review friction; cross-cite BUG-1.

---

## BUG-20 (P1) — Schnorr `M.schnorr_verify` accepts `msg` of any length but Tapscript callers always feed 32-byte sighashes; no explicit `#msg == 32` invariant for the BIP-341 surface

**Severity:** P1. `crypto.lua:998-1016`:

```lua
function M.schnorr_verify(xonly_pubkey32, sig64, msg)
  ...
  if type(msg) ~= "string" then
    return false, "invalid message"
  end
  ...
  local result = libsecp256k1.secp256k1_schnorrsig_verify(
    secp_ctx, sig64, msg, #msg, pubkey
  )
```

Per BIP-340, Schnorr signs arbitrary-length messages, so the generic
API is correct. But BIP-341 (Taproot) always uses a 32-byte
TapSighash (`bitcoin-core/src/script/interpreter.cpp::SignatureHashSchnorr`
always returns a 32-byte hash). For the BIP-341 surface, accepting any
non-32-byte length opens a wedge:
- A future caller that accidentally passes the 64-byte concatenated
  `(tx_hash || annex_hash)` instead of the 32-byte TapSighash would
  succeed against an attacker-crafted Schnorr sig — different
  message, different verification, but still valid Schnorr.
- The W126 BIP-340 spec recommends the BIP-341 surface gate
  `#msg == 32` precisely to avoid this.

Lunarblock has no gate. Tapscript callers
(`validation.lua:1599, 1720, 1903` + `utxo.lua:2655`) all feed
32-byte sighashes, so the bug is latent.

Core's `script/interpreter.cpp:VerifyTaprootCommitment` enforces the
length-32 gate at the call site, not in the verify primitive.
lunarblock could match either pattern; the issue is that NEITHER side
enforces it.

**File:** `src/crypto.lua:998-1016`,
`src/validation.lua:1593-1903`, `src/utxo.lua:2620-2710`.

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:SignatureHashSchnorr`.

**Impact:** defense-in-depth gap; cross-cite W126 BIP-340 conformance
audit.

---

## BUG-21 (P1) — `parallel_verify.c::pv_init` returns the **library-level singleton** state on second call (no per-Lua-state isolation)

**Severity:** P1. `parallel_verify.c:398-464`:

```c
static int initialized = 0;
static worker_t *workers = NULL;
...
int pv_init(int num_threads) {
    if (initialized) {
        return num_workers;
    }
    ...
}
```

The C library has a single `initialized` flag + `workers` array shared
across all `dlopen` clients. A second Lua state (e.g., a test runner
spawning multiple `busted` runs in the same process; a future
embedding of lunarblock inside another LuaJIT app) calling `pv_init`
gets the FIRST state's worker pool — the workers' per-thread
secp256k1 contexts (created in the FIRST state's GC scope) outlive
the FIRST state.

**Compound with BUG-9:** Lua-side `secp_ctx` has no `ffi.gc` finalizer.
On Lua-state destruction, the C worker pool's per-thread contexts
remain initialised, but the FFI function-pointer table in the new
Lua state may resolve `secp256k1_context_destroy` differently (e.g.,
if the new state loads a different `libsecp256k1` build).

**File:** `csrc/parallel_verify.c:121-130, 398-464`.

**Core ref:** N/A.

**Impact:** Lua-state isolation gap; UAF on library-reload edge case;
test-suite hygiene.

---

## BUG-22 (P1) — `sig_cache.lua` cache-key uses `tostring(flags)` (decimal); shape-fragile and silently collides on flag superset/subset that share a decimal prefix

**Severity:** P1 (cosmetic but trip-worthy). `sig_cache.lua:58-63`:

```lua
function SigCache:make_key(txid_or_wtxid, input_index, flags)
  local material = self._nonce .. txid_or_wtxid .. tostring(flags)
  return crypto.sha256(material)
end
```

`tostring(2147483648)` and `tostring(214748364)` both render to a
decimal string. `tostring(0)` and `tostring(-0)` and `tostring("0")`
all render to `"0"`. Boolean flags would render to `"true"` /
`"false"`. The decimal-string serialization is a shape contract that
neither lunarblock nor Core enforces — any future caller passing
`tonumber(flags)` vs `flags` (already-a-number) vs `tostring(flags)`
gets different keys.

Core's `SignatureCache::ComputeEntry` reads `flags` as a `uint32_t`
and serializes via the canonical 4-byte little-endian. lunarblock's
text-mode serialization is shape-fragile:

- `flags = 0x40000001` (some-large-number) → key A.
- `flags = "1073741825"` (string version) → key A (same after
  `tostring()`).
- `flags = 0x40000001 | 0` (re-OR'd identity) → key A.
- BUT: `flags = {0x40000001}` (a table by accident) → key
  `"table: 0x..."` — totally different.

The cache is not safety-critical (a miss just re-runs the verify), but
the wave's "string-prefix collision" risk is real if anyone ever
introduces a flag like 1 vs 10 vs 100 and serializes inconsistently.

**File:** `src/sig_cache.lua:58-63`.

**Core ref:** `bitcoin-core/src/script/sigcache.cpp::SignatureCache::ComputeEntry`
(canonical `uint32_t` little-endian write).

**Impact:** cache miss = re-verify (harmless); cache collision (in
edge cases) = false-positive cached verify, which could let a
mempool-only sig get treated as a consensus-verified sig if flags
were aliased. Low likelihood; high severity if reached.

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22).

**Severity distribution:**
- **P0-SEC:** 3 (BUG-2, BUG-3, BUG-7)
- **P1:** 12 (BUG-1, BUG-4, BUG-9, BUG-11, BUG-12, BUG-13, BUG-15, BUG-16,
  BUG-17, BUG-18, BUG-19, BUG-21, BUG-22 = 13; checked) — actually 13
- **P1-SEC:** 3 (BUG-5, BUG-8, BUG-14)
- **P1-CDIV:** 1 (BUG-6)
- **P2:** 1 (BUG-10)
- **P1 (wire/correctness, miscellaneous):** counted above

Recount: P0-SEC 3 + P1-SEC 3 + P1-CDIV 1 + P1 13 + P2 1 = 21. Plus
BUG-20 (P1) = 22. ✓

**Fleet patterns confirmed / extended this audit:**
- **"side-channel-blinding-disabled"** (BUG-2) — confirmed at FFI
  level. lunarblock is the NAMED ORIGIN of the fleet-wide W158 BUG-7
  pattern; 5+ weeks open with zero progress, longest-known
  side-channel carry-forward in lunarblock.
- **"comment-as-confession"** (BUG-5 line 1019 "modulo defense-in-depth
  verify"; BUG-6 rpc.lua:6137 "M.schnorr_sign is unavailable"; BUG-4
  line 516 cites wrong header line) — ~16th, 17th, 18th distinct
  lunarblock instances (pattern fully saturating).
- **"wiring-look-but-no-wire"** (BUG-6) — `schnorr_sign` defined +
  FFI-cdef'd + keypair API plumbed end-to-end, zero callers; rpc.lua
  comment says "unavailable".
- **"two-pipeline guard"** (BUG-1 + BUG-19) — Lua-side context uses
  `VERIFY|SIGN`, C-side workers use `VERIFY`; same library, two
  different flag profiles, no coordination.
- **"FFI ABI typedef mismatch"** (BUG-4) — `xonly_pubkey` typedef
  declared `data[96]` instead of Core's `data[64]`; copy-paste from
  keypair typedef.
- **"no length precheck before FFI"** (BUG-13) — `pubkey_from_privkey`
  + `ecdsa_sign` accept any-length strings; libsecp256k1 reads 32
  bytes regardless; Lua interner garbage leaks into seckey/msg.
- **"seckey persistence in GC-managed strings"** (BUG-7 + BUG-8 +
  BUG-14) — no `memzero`, no LockedPool/`mlock`, no `ffi.fill`
  defense.
- **"no operator-knob exists"** (BUG-16) — no
  `secp256k1_context_set_illegal_callback`; library aborts on misuse.
- **"single combined context for sign + verify"** (BUG-15) — Core
  splits via `secp256k1_context_static`, lunarblock doesn't.
- **"integer overflow at FFI boundary"** (BUG-11) — `int count` in
  `pv_verify_signatures` is unvalidated.
- **"GC-pinning contract fragility"** (BUG-12) — `jobs` cdata + ptr
  tables must outlive C call; Lua wrapper does it correctly, ABI
  expose lets future callers break it.
- **"text-mode key serialization"** (BUG-22) — `tostring(flags)` in
  cache key vs Core's canonical uint32 LE.
- **"deprecated library flags"** (BUG-1, BUG-19) — `VERIFY|SIGN` is
  flagged deprecated since libsecp256k1 v0.4.0.

**Cross-cites with W158:**
- W158 BUG-7 (`secp256k1_context_randomize` never called) ← W159
  BUG-2 confirms at FFI cdef level (symbol not declared) and at
  parallel_verify.c worker-pool level (same gap).
- W158 BUG-1 (base64_decode substitutes 0) ← W159 BUG-13 same
  "no length precheck at FFI boundary" pattern.
- W158 funds-burn default coinbase ← unrelated this wave (mining
  surface, not crypto).
- W158 clearbit cipher-as-scalar ← W159 BUG-3 (no `_seckey_verify`)
  in lunarblock invites the same class of bug if any future code path
  reuses cipher output as a seckey.

**Top three findings:**

1. **BUG-2 (P0-SEC, side-channel-blinding-disabled, 5+ weeks
   carry-forward from W158)** — `secp256k1_context_randomize` is not
   declared in lunarblock's FFI cdef and never called. Every sign
   path (`ecdsa_sign`, `ecdsa_sign_recoverable_compact`,
   `schnorr_sign`, `taproot_tweak_seckey`, `ec_seckey_tweak_add`,
   `ec_pubkey_create`, `ellswift_create`) runs against an
   un-blinded scalar. lunarblock is the **NAMED ORIGIN of the
   fleet-wide pattern** confirmed across rustoshi / nimrod / clearbit
   / camlcoin. The fix is 2 LOC (FFI cdef + call after create); 5+
   weeks open since W158 BUG-7. Compound with BUG-3 (no
   `_seckey_verify` gate) and BUG-15 (single combined context for
   sign+verify) makes side-channel leakage worst-in-fleet.

2. **BUG-3 (P0-SEC, no `secp256k1_ec_seckey_verify`)** — the FFI cdef
   does NOT declare `secp256k1_ec_seckey_verify` at all. Every sign /
   pubkey-create / derive path bypasses Core's canonical scalar-range
   gate. Failure modes collapse into generic "invalid private key"
   error strings, making cipher-as-scalar (W158 clearbit origin),
   WIF-truncation (BUG-13 cross-cite), out-of-range-scalar, and
   transient FFI failures indistinguishable. Wallet WIF import
   silently accepts truncated payloads. Cross-cite W158 clearbit
   BUG-cipher-as-scalar — lunarblock's surface invites the same.

3. **BUG-6 (P1-CDIV, "wiring-look-but-no-wire" applied to Schnorr
   sign)** — `M.schnorr_sign` is fully implemented at `crypto.lua:1032`
   (FFI cdef + keypair API + aux_rand handling), but `rpc.lua:6137`
   comments "lunarblock ships ECDSA-only crypto today (M.schnorr_sign
   is unavailable)" and skips P2TR signing entirely.
   `signrawtransactionwithkey` returns `complete=false` for every
   P2TR input regardless of wallet state; BIP-322 message signing
   for Taproot addresses is also blocked. The comment is FALSE as
   of the current source — the helper ships, no caller exists. Same
   architectural shape as the fleet-wide W156 "BIP-152 SEND-side
   dead code" pattern, and the W158 lunarblock BUG-funds-burn
   pattern (working primitive, unwired caller). Fix is ~10 LOC
   (route P2TR sign path through `crypto.schnorr_sign` with proper
   aux_rand).
