# W161 — BIP-32 / BIP-39 / BIP-43 / BIP-44 / BIP-49 / BIP-84 / BIP-86 HD wallet derivation + seed mnemonic (lunarblock)

**Wave:** W161 — `CExtKey::SetSeed`, `CExtKey::Derive`, `CExtKey::Neuter`,
`CExtKey::Encode`, `CExtPubKey::Decode`, `BIP32Hash`, `CKey::Derive`,
`CPubKey::Derive`, `DescriptorScriptPubKeyMan::TopUp`, `LegacyScriptPubKeyMan`,
BIP-39 mnemonic generation + entropy↔words + PBKDF2-HMAC-SHA512(salt="mnemonic"+passphrase,
iter=2048, dklen=64), BIP-43 purpose, BIP-44/49/84/86 `m/<purpose>'/<coin_type>'/<account>'/<change>/<index>`
paths with per-network `coin_type`, xprv/xpub 78-byte serialization with
per-network version bytes (`0x0488ADE4`/`0x0488B21E` mainnet, `0x04358394`/
`0x043587CF` testnet, `0x049D7878`/`0x049D7CB2` ypub/yprv, `0x04B2430C`/
`0x04B24746` zprv/zpub), parent-fingerprint = HASH160(parent_pubkey)[:4],
depth byte (u8 overflow at 256), BIP-86 TapTweak with EMPTY merkle root,
NFKD UAX#15 normalization on mnemonic + passphrase, master generation
HMAC-SHA512(key="Bitcoin seed", data=seed).

**Scope:** discovery only — no production code changes.

## Bitcoin Core references — READ FIRST

- `bitcoin-core/src/key.cpp::CKey::Derive` (CKDpriv via libsecp256k1
  `secp256k1_ec_seckey_tweak_add`).
- `bitcoin-core/src/key.cpp::CExtKey::SetSeed` (master generation: HMAC-SHA512
  with key="Bitcoin seed"; calls `CKey::Set` which invokes
  `secp256k1_ec_seckey_verify`; returns false on IL == 0 or IL >= n; caller
  MUST retry with a fresh seed per BIP-32 §"Master key generation").
- `bitcoin-core/src/key.cpp::CExtKey::Encode` (78-byte serialization:
  version(4) + depth(1) + parent_fingerprint(4) + child_number(4) +
  chain_code(32) + key(33) where key = 0x00 || privkey32 or compressed pubkey).
- `bitcoin-core/src/pubkey.cpp::CExtPubKey::Decode` (78-byte deserialization).
- `bitcoin-core/src/pubkey.cpp::CPubKey::Derive` (CKDpub via libsecp256k1
  `secp256k1_ec_pubkey_tweak_add` + serialise-compressed).
- `bitcoin-core/src/wallet/scriptpubkeyman.cpp::DescriptorScriptPubKeyMan::TopUp`
  (BIP-44/49/84/86 path expansion + gap limit).
- `bitcoin-core/src/script/descriptor.cpp` (BIP-44/49/84/86 descriptor
  templates: `pkh($extKey/$path)`, `sh(wpkh($extKey/$path))`,
  `wpkh($extKey/$path)`, `tr($extKey/$path)`).
- `bitcoin-core/src/wallet/walletutil.cpp::GetDefaultPurposeFromAddressType`
  (default descriptor purposes per address type).
- `bitcoin-core/src/key.cpp::CKey::Sign` etc. — wallet init also calls
  `secp256k1_context_randomize` once per process (key.cpp:33 `static_random_init`).
- BIP-32: `https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki`
  ("Master key generation": IL must be < n AND non-zero, else "the master key
  is invalid; in that case proceed with the next attempt at I" — implicit
  caller retry).
- BIP-39: `https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki`
  ("To create a binary seed from the mnemonic, we use the PBKDF2 function with
  a mnemonic sentence (in UTF-8 NFKD) used as the password and the string
  'mnemonic' + passphrase (also in UTF-8 NFKD) used as the salt. The iteration
  count is set to 2048 and HMAC-SHA512 is used as the pseudo-random
  function. The length of the derived key is 512 bits (= 64 bytes).").
- BIP-43: `https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki`
  (purpose field reserves hardened indices).
- BIP-44: `https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki`
  (`m/44'/coin_type'/account'/change/address_index`; coin_type=0' for
  mainnet, 1' for testnet/regtest/signet).
- BIP-49: `https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki`
  (P2SH-P2WPKH derivation `m/49'/coin_type'/account'/...` + ypub/yprv
  version bytes).
- BIP-84: `https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki`
  (native P2WPKH `m/84'/coin_type'/account'/...` + zpub/zprv).
- BIP-86: `https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki`
  (BIP-340 key-path-only P2TR `m/86'/coin_type'/account'/...`; tweak
  must use EMPTY merkle root).

## Files audited

- `src/bip39.lua` — `WORDLIST_SIZE`, `PBKDF2_ITERATIONS`,
  `SALT_PREFIX="mnemonic"`, `entropy_to_mnemonic`, `mnemonic_to_entropy`,
  `validate_mnemonic`, `nfkd_ascii`, `mnemonic_to_seed`, `generate_mnemonic`,
  wordlist loader (`resources/bip39-english.txt`).
- `src/wallet.lua:432-665` — `extended_key()` constructor,
  `master_key_from_seed()`, `add_mod_n()` (pure-Lua BigInt), `is_valid_key()`
  (pure-Lua), `derive_child()` (uses pure-Lua add, NOT libsecp's
  `ec_seckey_tweak_add`), `derive_bip44_key`, `derive_bip84_key` (no
  BIP-49 / BIP-86), `parse_path`, `derive_path`.
- `src/wallet.lua:670-1050` — `Wallet.new`, `Wallet:generate_address`,
  `create()` (raw 32-byte random seed, NO BIP-39), `from_seed()`,
  `import_mnemonic()`, `create_with_mnemonic()`, `get_mnemonic()`,
  `encrypt()`, `lock()`, `unlock()`.
- `src/wallet.lua:2208-2400` — `Wallet:serialize` / `M.load`
  (plaintext master_key + plaintext mnemonic on disk when unencrypted).
- `src/wallet.lua:2400-2700` — `WalletManager:create_wallet`
  (always calls `M.create()` — never invokes BIP-39).
- `src/address.lua:761-810, 841-930` — `parse_key_expression`
  (decodes xpub/xprv version bytes), `derive_child` (uses libsecp's
  `ec_seckey_tweak_add` — DIVERGENT from wallet.lua), `derive_path`.
- `src/crypto.lua:372-872` — libsecp256k1 FFI cdef (NO
  `secp256k1_context_randomize`, NO `secp256k1_ec_seckey_verify`),
  `ec_seckey_tweak_add`, `ec_pubkey_tweak_add`, `pubkey_from_privkey`,
  `pbkdf2_hmac_sha512`, `random_bytes`, `hmac_sha512`.
- `src/rpc.lua:5174-6085` — `createwallet`, `loadwallet`, `getwalletmnemonic`,
  `importmnemonic`.
- `resources/bip39-english.txt` — 2048-word English wordlist.

---

## Gate matrix (40 sub-gates / 11 behaviours)

| #  | Behaviour                              | Sub-gate                                                            | Verdict |
|----|----------------------------------------|---------------------------------------------------------------------|---------|
| 1  | BIP-32 master generation               | G1: HMAC-SHA512(key="Bitcoin seed", data=seed)                      | PASS (`wallet.lua:450`) |
| 1  | …                                      | G2: IL >= n -> reject + caller retries with new seed                | **BUG-1 (P0-FUNDS)** — no check; an IL≥n produces a silently-invalid master, which later fails CKD with an opaque "invalid key" |
| 1  | …                                      | G3: IL == 0 -> reject                                               | **BUG-1 cross-cite** |
| 1  | …                                      | G4: depth = 0, parent_fingerprint = "\0\0\0\0", child_index = 0    | PASS (`wallet.lua:453`) |
| 1  | …                                      | G5: master generation seed must be 16–64 bytes (BIP-32 spec)        | **BUG-2 (P1)** — accepts any seed length; `M.create` hands raw 32-byte random; `M.from_seed` accepts whatever caller passes |
| 2  | BIP-32 CKDpriv                         | G6: child_priv = (parse256(IL) + parent_priv) mod n via libsecp     | **BUG-3 (P0-CDIV)** "two-pipeline-within-impl 2nd carry-forward" — `wallet.lua:591` uses pure-Lua `add_mod_n`; `address.lua:882` uses libsecp's `ec_seckey_tweak_add`. Two CKD pipelines coexist with divergent semantics for the same operation |
| 2  | …                                      | G7: IL >= n -> caller MUST retry next index                         | PARTIAL — `address.lua` returns error (correct); `wallet.lua:583` calls `is_valid_key(il)` which only checks `il >= SECP256K1_ORDER` (no IL=0 check on tweak alone — IL=0 + non-zero parent is valid; this is fine) but retry uses `index + 1` (`wallet.lua:585`) without checking that incremented index doesn't cross hardened boundary (BIP-32 advances to "next i" which Core implements as `++i` and validates it stays in range; lunarblock can leap from non-hardened `0x7FFFFFFF` to hardened `0x80000000`) |
| 2  | …                                      | G8: child_priv == 0 -> caller MUST retry next index                 | PASS — `is_valid_key(child_key)` at `wallet.lua:594` |
| 2  | …                                      | G9: pure-Lua add_mod_n implements modular addition correctly        | PARTIAL — basic add+conditional-subtract is implemented (`wallet.lua:485-525`); no constant-time guarantee, no protection against single-bit faults; libsecp provides hardened arithmetic via `_fe_safegcd_inv`/`_scalar_add` — gap |
| 3  | BIP-32 CKDpub                          | G10: child_pub = parent_pub + parse256(IL)*G via libsecp            | **BUG-4 (P0-FUNDS)** — `wallet.lua:600` `error("Public key derivation not implemented")`. Watch-only wallets (xpub-only) cannot derive ANY child address — same architectural gap as W118 G6-BUG-1 (pre-FIX-59) that was supposedly closed in address.lua. wallet.lua never got the same fix |
| 3  | …                                      | G11: IL >= n on pub path -> retry next index                        | N/A (G10 absent) |
| 3  | …                                      | G12: child_pub == infinity -> retry next index                      | N/A (G10 absent) |
| 4  | BIP-32 hardened derivation             | G13: hardened requires private key                                  | PASS (`wallet.lua:552-554`) |
| 4  | …                                      | G14: hardened data = 0x00 \|\| privkey32 \|\| ser32(index)          | PASS (`wallet.lua:566`) |
| 4  | …                                      | G15: index >= 2^31 marker for hardened                              | PASS (`wallet.lua:550`) |
| 5  | BIP-32 chain code propagation          | G16: child_chain_code = IR                                          | PASS (`wallet.lua:580, 612`) |
| 5  | …                                      | G17: parent_fingerprint = HASH160(parent_pubkey)[:4]                | PASS (`wallet.lua:610`) |
| 5  | …                                      | G18: depth byte = parent.depth + 1 (saturates / errors at 256)      | **BUG-5 (P1)** — `wallet.lua:612` increments depth as Lua number; serializer would silently overflow u8. Same shape as blockbrew W161 "depth-byte-overflow" finding |
| 6  | xprv/xpub 78-byte serialization        | G19: extended-key encoder exists                                    | **BUG-6 (P0-FEAT)** — NO encoder anywhere in the codebase. `grep -n "to_xprv\|serialize_extended\|to_base58.*xprv" src/*.lua` returns zero results. The wallet can construct an internal `extended_key{}` table but cannot emit a standards-compliant xprv/xpub string. Downstream impact: `getmasterxprv` / `getxpub` / PSBT global_xpubs are all impossible at the wallet RPC layer |
| 6  | …                                      | G20: xprv/xpub decoder exists                                       | PARTIAL — `address.lua:761-810` decodes xpub/xprv version bytes (mainnet+testnet only); ypub/yprv/zpub/zprv (BIP-49/84) NOT recognised (`xpub_versions = {0x0488B21E, 0x043587CF}` only) |
| 6  | …                                      | G21: per-network version bytes (mainnet/testnet/signet/regtest)     | **BUG-7 (P1)** — only mainnet+testnet version bytes are recognised; signet uses Core's testnet version bytes `0x043587CF`/`0x04358394` per BIP-32 §"Serialization format" but lunarblock has no signet network mapping at all in the decoder |
| 7  | BIP-39 wordlist + entropy<->words      | G22: 2048-word English wordlist loaded                              | PASS (`bip39.lua:99-100`) |
| 7  | …                                      | G23: valid entropy lengths 16/20/24/28/32 bytes (128/160/192/224/256 bits) | PASS (`bip39.lua:43-44`) |
| 7  | …                                      | G24: checksum = first ENT/32 bits of SHA256(entropy)                | PASS (`bip39.lua:170-178, 224-244`) |
| 7  | …                                      | G25: validate_mnemonic detects bad checksum                         | PASS (`bip39.lua:242-244, 252-256`) |
| 8  | BIP-39 mnemonic→seed PBKDF2            | G26: PBKDF2-HMAC-SHA512                                             | PASS (`bip39.lua:298` → `crypto.pbkdf2_hmac_sha512`) |
| 8  | …                                      | G27: iter = 2048                                                    | PASS (`bip39.lua:36`) |
| 8  | …                                      | G28: salt = "mnemonic" + NFKD(passphrase)                           | **BUG-8 (P0-CDIV)** "NFKD asymmetric / silent-degrade" — `bip39.lua:261-273` `nfkd_ascii` is a no-op for ASCII AND for non-ASCII (the loop breaks on first non-ASCII byte but returns the unchanged string). Comment-as-confession at line 17-20 admits "the seed will be byte-stable but may diverge from implementations that perform real NFKD on non-ASCII input". Non-ASCII passphrases (e.g. a Japanese passphrase from Trezor BIP-39) silently produce a wrong seed — wallet derives addresses no one sent funds to |
| 8  | …                                      | G29: dklen = 64                                                     | PASS (`bip39.lua:37, 298`) |
| 9  | BIP-39 mnemonic generation             | G30: random_bytes uses CSPRNG                                       | PASS (`bip39.lua:310` → `crypto.random_bytes` → `RAND_bytes`) |
| 9  | …                                      | G31: createwallet RPC offers mnemonic backup                        | **BUG-9 (P0-FUNDS)** "mnemonic-bypass-on-createwallet" — `rpc.lua:5181` calls `wallet_manager:create_wallet` which (line 2569) calls `M.create()` which (line 727) takes a **raw 32-byte CSPRNG seed**, never invokes `bip39.generate_mnemonic`. Result: `createwallet` returns SUCCESS but the wallet has NO mnemonic. Backup is impossible via `getwalletmnemonic` (returns "No mnemonic available for this wallet"). Operators see "Wallet created" + warnings, write down nothing, lose coins on disk loss. Same shape as clearbit W161 "BIP-39 module wired but bypassed on createwallet path" |
| 10 | BIP-43/44/49/84/86 paths               | G32: BIP-44 path `m/44'/coin_type'/account'/change/index`           | **BUG-10 (P0-CDIV)** "coin_type=0 hardcoded" — `wallet.lua:622` `M.derive_child(purpose, 0x80000000 + 0)`. Testnet/regtest/signet wallets derive at mainnet path. Same shape as camlcoin W161 "coin_type=0 hardcoded" + rustoshi W161 "network-strip on key parse" — BIP-44 mandates coin_type=1' for testnet/regtest/signet |
| 10 | …                                      | G33: BIP-49 P2SH-P2WPKH path `m/49'/coin_type'/...`                 | **BUG-11 (P0-FEAT)** — `derive_bip49_key` does not exist. Lunarblock wallet cannot produce nested-segwit addresses at all (still in wide use by hardware wallets) |
| 10 | …                                      | G34: BIP-84 native P2WPKH path `m/84'/coin_type'/...`               | PARTIAL — `derive_bip84_key` exists (`wallet.lua:629-635`) but coin_type=0 hardcoded (G32 BUG-10) |
| 10 | …                                      | G35: BIP-86 P2TR path `m/86'/coin_type'/...`                        | **BUG-12 (P0-FEAT)** — `derive_bip86_key` does not exist. Lunarblock wallet cannot derive Taproot key-path-only outputs. Even though `address.lua:1198-1207` knows how to apply TapTweak, no wallet path reaches it. Combined with W160 BUG-13 "3-layer wiring-look-but-no-wire write-only Taproot wallet" — Taproot is now 0-of-3 layers |
| 11 | Operational hygiene                    | G36: secp256k1_context_randomize once per process (side-channel)    | **BUG-13 (P0-SEC)** — `crypto.lua:372-608` FFI cdef does NOT declare `secp256k1_context_randomize`. Confirms the W159 BUG-2 + W158 + W160 carry-forward at architectural level (5+ weeks open in lunarblock). Core calls this once at init (`key.cpp::static_random_init`) to blind point operations against timing/EM side-channels. lunarblock's CKD + sign run with NO randomized context. Fleet-wide pattern: ≥10/10 |
| 11 | …                                      | G37: master_key + mnemonic NEVER stored plaintext on disk           | **BUG-14 (P0-FUNDS)** "master_key plaintext on disk" — `wallet.lua:2232-2234` for unencrypted wallets, `data.master_key = M.hex_encode(self.master_key.key)` writes 32-byte raw privkey hex to JSON. Line 2239 mnemonic-as-plaintext. Same shape as clearbit W161 BUG-5. Operator who set "no passphrase" loses everything on disk theft / backup leak / `cat wallet.json` to screen-share |
| 11 | …                                      | G38: bip39_passphrase NEVER stored long-term                        | PARTIAL — `wallet.lua:811` stores `wallet.bip39_passphrase = bip39_passphrase` in MEMORY in plaintext for the life of the process; serialize() correctly omits it (line 2243 comment). But the in-memory plaintext is reachable via core-dump or any process inspection — Core's `CExtKey::SetSeed` never retains the BIP-39 passphrase after seed generation |
| 11 | …                                      | G39: zeroize private key memory on lock                             | **BUG-15 (P1)** "memory hygiene: no zeroize" — `wallet.lua:909-913` `self.master_key.key = nil` does NOT zero the underlying string; LuaJIT strings are interned, the byte data persists until GC. Similarly `key_info.privkey = nil`. Core uses `memory_cleanse` (Core util.h). On a fork+exec or core dump the prior key value is still in memory |
| 11 | …                                      | G40: sign-then-verify paranoia on critical signatures               | **BUG-16 (P1)** — `crypto.lua:874-918` `ecdsa_sign` / `ecdsa_sign_recoverable_compact` do NOT verify their own output before returning. Core's `CKey::Sign` (key.cpp:303-318) calls `Verify(hash, vchSig)` after signing as a sanity check against fault injection / glitched signing hardware. Fleet-wide pattern: 5+ impls |

---

## BUG-1 (P0-FUNDS) — `master_key_from_seed` accepts invalid IL (>= n or zero)

**Severity:** P0-FUNDS. BIP-32 §"Master key generation" mandates:

> 4. Split I into two 32-byte sequences, IL and IR.
> 5. Use parse256(IL) as master secret key, and IR as master chain code.
> 6. In case IL is 0 or ≥ n, the master key is invalid, and one should proceed
>    with the next value for I.

Bitcoin Core's `CExtKey::SetSeed` (`key.cpp:355-371`) hashes the seed, then
calls `CKey::Set(...)`, which calls `secp256k1_ec_seckey_verify` and returns
`false` if the secret is invalid. The caller (descriptor / wallet init) MUST
detect this and either error out or re-randomize the seed.

lunarblock's `wallet.lua:449-454`:

```lua
function M.master_key_from_seed(seed)
  local hmac = crypto.hmac_sha512("Bitcoin seed", seed)
  local key = hmac:sub(1, 32)
  local chain_code = hmac:sub(33, 64)
  return M.extended_key(key, chain_code, 0, "\0\0\0\0", 0, true)
end
```

No `is_valid_key(key)` check. No call to `crypto.ec_seckey_tweak_add` /
`secp256k1_ec_seckey_verify`. The downstream first CKD call will fail with
"Invalid private key" deep inside `address.lua::derive_child` for a seed
that triggers IL>=n — the operator sees a cryptic error long after the
wallet has been "created" and even SAVED to disk (`wallet:save` runs in
`createwallet` before any derivation happens).

Probability of IL>=n is roughly 2^-128 per seed, so this is operationally
unlikely on a 32-byte CSPRNG seed but cataclysmic when it happens (the
wallet's persisted master_key is unusable; recovering requires picking a
different seed and re-IBD). For a 16-byte seed (`M.from_seed` accepts any
length per G5/BUG-2) the probability rises (still small but no longer
academic).

**File:** `src/wallet.lua:449-454`.

**Core ref:** `bitcoin-core/src/key.cpp::CExtKey::SetSeed`,
`secp256k1_ec_seckey_verify`.

**Impact:** silently saves a broken wallet to disk; operator-visible
failure on first derivation, with no clean recovery path.

---

## BUG-2 (P1) — `from_seed` / `master_key_from_seed` accept any seed length

**Severity:** P1. BIP-32 §"Master key generation" requires a seed of 128–512
bits (16–64 bytes). lunarblock's `master_key_from_seed` is a thin wrapper
over `crypto.hmac_sha512` which accepts a `string` of any length, including
zero-length. `M.from_seed` (`wallet.lua:746-760`) does no length check.

A caller passing a single-byte seed produces a deterministic-but-low-entropy
master key. A caller passing a 128-byte seed (e.g. by mistake) produces a
master key whose first half is HMAC(seed[0..63]) — still deterministic but
diverges from any compatible wallet that obeys the 64-byte cap.

**File:** `src/wallet.lua:449-454, 746-760`.

**Core ref:** `bitcoin-core/src/key.cpp::CExtKey::SetSeed` (no explicit
length cap but contract calls it from `MakeKeyData` etc. which always pass
64 bytes).

**Impact:** weak-seed acceptance; cross-impl divergence on >64-byte seeds.

---

## BUG-3 (P0-CDIV) — Two CKD pipelines coexist with divergent semantics (`wallet.lua` pure-Lua add vs `address.lua` libsecp)

**Severity:** P0-CDIV ("two-pipeline-within-impl 2nd carry-forward of W118
G6-BUG-1"). FIX-59 (per `tests/test_fix59_bip32_ckd.lua` header)
explicitly closed `address.derive_child` by routing through libsecp's
`secp256k1_ec_seckey_tweak_add`. But **`wallet.lua` was not migrated**.
Two `derive_child` functions now coexist:

| Path                          | Backing arithmetic                          | Used by                                  |
|-------------------------------|---------------------------------------------|------------------------------------------|
| `address.lua:841::derive_child` | libsecp `ec_seckey_tweak_add` (correct)    | descriptor / PSBT / RPC descriptor flow  |
| `wallet.lua:549::derive_child`  | pure-Lua `add_mod_n` (`wallet.lua:485-525`) | `derive_bip44_key`, `derive_bip84_key`, `Wallet:generate_address`, `Wallet:unlock` re-derivation |

The pure-Lua `add_mod_n` is a hand-rolled 32-byte big-endian add with a
single conditional subtract of `SECP256K1_ORDER` when `result >= n`. This
is functionally correct for naive addition-mod-n, but:

1. **Not constant-time.** Branch-on-data subtract leaks via timing / EM
   sidechannel. Core's libsecp arithmetic is constant-time.
2. **No protection against fault injection / single-bit flips.** libsecp
   has internal sanity checks; pure-Lua does not.
3. **Drift risk.** Any future bug fix to one path must be replicated in
   the other. The whole point of FIX-59 was to retire the bespoke
   arithmetic.

Test coverage is asymmetric — `tests/test_fix59_bip32_ckd.lua` exercises
ONLY `address.derive_child`. `wallet.derive_child` has no equivalent
test-vector run (the only wallet-level BIP-32 test in the repo is
`tests/test_w111_wallet.lua` which derives a couple of indices and checks
they're nonzero — not the BIP-32 test vectors).

**File:** `src/wallet.lua:485-525, 528-546, 549-613`.

**Core ref:** `bitcoin-core/src/key.cpp::CKey::Derive` (single libsecp
path).

**Impact:** silent divergence between BIP-44/84 wallet derivation and
descriptor derivation; sidechannel exposure for the wallet path; risk of
future drift that an isolated FIX never catches.

---

## BUG-4 (P0-FUNDS) — `wallet.lua::derive_child` errors out on public-key derivation

**Severity:** P0-FUNDS. `wallet.lua:600`:

```lua
else
  -- For public key derivation, we'd need point addition
  -- This implementation focuses on private key derivation
  error("Public key derivation not implemented")
end
```

This is the **exact** failure W118 G6-BUG-1 documented for `address.lua`,
which was closed by FIX-59. Same code shape persists in wallet.lua. Any
watch-only wallet (`disable_private_keys=true` per createwallet, OR an
xpub-only descriptor) cannot derive child addresses — `Wallet:generate_address`
calls `derive_bip84_key` which calls `derive_child`, which calls
`pubkey_from_privkey(parent.key, true)` to compute the child pubkey BUT
only after the privkey-side `add_mod_n` succeeds.

`Wallet.is_private` is the gate; for a watch-only wallet, `parent.is_private`
is false, the `else` branch runs, and the wallet is dead.

The fix lives one module over in `crypto.ec_pubkey_tweak_add` (already
declared and wrapping libsecp). The wallet just never calls it.

**File:** `src/wallet.lua:597-601`.

**Core ref:** `bitcoin-core/src/pubkey.cpp::CPubKey::Derive`.

**Impact:** watch-only wallets are completely broken at the wallet RPC
layer; combined with BUG-11+BUG-12 (no BIP-49/86) and BUG-6 (no xpub
encoder), lunarblock cannot serve as a hardware-wallet companion.

---

## BUG-5 (P1) — Depth byte u8 overflow not guarded

**Severity:** P1 ("depth-byte-overflow" — fleet-wide pattern, blockbrew W161
named origin). `wallet.lua:612`:

```lua
return M.extended_key(child_key, ir, parent.depth + 1, fingerprint, index, parent.is_private)
```

Depth is propagated as a Lua number (double). The xpub/xprv 78-byte
serialization specifies depth as a u8 — values 256+ would silently truncate
on serialize (if a serializer existed, which it doesn't; see BUG-6). The
in-memory `extended_key.depth` is now a value the xpub format cannot
represent. A caller that hand-rolls serialization (e.g. PSBT global_xpubs
in `src/psbt.lua:297-301` for the path field) would emit a depth byte that
does NOT match the path length, breaking any consumer that re-derives.

**File:** `src/wallet.lua:441, 612`.

**Core ref:** `bitcoin-core/src/key.cpp::CExtKey::Encode`
(`obj[4] = nDepth;` — u8 narrowing-conversion).

**Impact:** silent corruption past 255 derivation steps; latent because no
sensible BIP-32 path exceeds 5 or so levels, but the type contract leaks.

---

## BUG-6 (P0-FEAT) — No xprv/xpub 78-byte serializer

**Severity:** P0-FEAT. Bitcoin Core's `CExtKey::Encode` /
`CExtPubKey::Encode` produce the 78-byte standard serialization:

```
version(4) || depth(1) || parent_fingerprint(4) || child_number(4) ||
chain_code(32) || key(33)   // key = 0x00||privkey32 (xprv) or compressed pubkey (xpub)
```

This is base58check-encoded to produce the "xprv"/"xpub" strings users
back up.

lunarblock has a **decoder** (`address.lua:761-810` for descriptor parsing)
but **NO encoder**. Searching for `to_xprv`, `serialize_extended_key`,
`encode_xpub`, or the version bytes inside any `..` / `string.char` call
that emits 4 then 1 then 4 bytes returns zero matches.

Concrete impact:
- **No `getmasterxprv` / `getxpub` RPC.** Lunarblock cannot tell the
  operator their own xpub. PSBT `xpubs` map (`psbt.lua:131, 297-301`)
  is built from decoded xpubs but never populated from a wallet-side
  encode call.
- **No descriptor export.** A descriptor like
  `wpkh(xpub.../84'/0'/0'/0/*)` cannot be auto-generated from a loaded
  wallet because the xpub string doesn't exist.
- **No multisig setup.** Multisig participants exchange xpubs; lunarblock
  cannot offer or accept its own.
- **Hardware-wallet companion: dead.** Trezor/Ledger flows exchange
  ypub/zpub/xpub strings.

**File:** none — the function does not exist.

**Core ref:** `bitcoin-core/src/key.cpp::CExtKey::Encode`,
`bitcoin-core/src/pubkey.cpp::CExtPubKey::Encode`.

**Impact:** lunarblock wallets cannot interoperate with any standard
backup/restore tool, hardware wallet, or multisig coordinator. This is
a missing-feature parity gap of similar scope to BUG-11/12 (BIP-49/86).

---

## BUG-7 (P1) — Extended-key decoder recognises mainnet+testnet ONLY (no signet, no ypub/zpub/yprv/zprv)

**Severity:** P1. `address.lua:774-775`:

```lua
local xpub_versions = {0x0488B21E, 0x043587CF}  -- mainnet, testnet
local xprv_versions = {0x0488ADE4, 0x04358394}  -- mainnet, testnet
```

This misses:
- **Signet** (uses Core's testnet version bytes — would actually decode
  but lunarblock has no signet handling downstream, so a signet xpub
  silently maps to testnet semantics in `parse_key_expression`).
- **BIP-49 ypub** `0x049D7CB2` / yprv `0x049D7878` (P2SH-P2WPKH).
- **BIP-84 zpub** `0x04B24746` / zprv `0x04B2430C` (P2WPKH).
- **BIP-49 upub / vpub / zpub testnet variants.**

A descriptor like `wpkh(zpub6ru...)` fails parse → `parse_descriptor`
errors → wallet can't import a Trezor / Ledger / Sparrow / Electrum
P2WPKH watch-only setup.

**File:** `src/address.lua:774-775`.

**Core ref:** `bitcoin-core/src/chainparams.cpp::base58Prefixes[EXT_PUBLIC_KEY]`
(per-network).

**Impact:** cannot import zpub/ypub from external wallets; lunarblock-as-
descriptor-target is fenced to legacy xpub format.

---

## BUG-8 (P0-CDIV) — NFKD silent-degrade on non-ASCII passphrases ("NFKD asymmetric")

**Severity:** P0-CDIV. BIP-39 §"From mnemonic to seed" mandates UTF-8
NFKD normalization on BOTH the mnemonic sentence AND the
`"mnemonic"+passphrase` salt. NFKD is required because Unicode allows
multiple canonical encodings of the same logical character
(precomposed vs combining); without normalization, two seemingly-identical
passphrases produce different seeds.

lunarblock's `nfkd_ascii` (`bip39.lua:261-273`):

```lua
local function nfkd_ascii(s)
  for i = 1, #s do
    if s:byte(i) >= 0x80 then
      -- We don't have an NFKD library wired in; surface this once at the
      -- call site rather than silently producing a non-spec seed.
      break
    end
  end
  return s
end
```

This is a **silent NO-OP for non-ASCII input** — the loop breaks but the
unchanged `s` is returned. Comment-as-confession at file header lines
17-20:

> Non-ASCII passphrases are passed through unchanged: the seed will be
> byte-stable but may diverge from implementations that perform real NFKD
> on non-ASCII input.

This is **the exact wording Core's `key.cpp` would never accept**. A user
with a Trezor backup that uses a Japanese passphrase (NFKD-normalised by
Trezor) imports the mnemonic into lunarblock → wrong seed → wrong
addresses → **no funds shown**, even though the mnemonic+passphrase pair
is "correct".

Same shape as blockbrew W161 BUG "NFKD-asymmetric" and the broader
"silent-degrade-on-edge-input" fleet pattern.

**File:** `src/bip39.lua:261-273, 296-297`.

**Core ref:** `bitcoin-core/src/wallet/scriptpubkeyman.cpp` (Core does
NOT support BIP-39 natively; wallet-side BIP-39 implementations like
Trezor/Sparrow apply NFKD via ICU / libunistring).

**Impact:** silent funds loss on non-ASCII passphrase import; wallet
appears to work, addresses do not match any external state.

---

## BUG-9 (P0-FUNDS) — `createwallet` RPC bypasses BIP-39 entirely (mnemonic-bypass-on-create)

**Severity:** P0-FUNDS ("mnemonic-bypass-on-createwallet" — clearbit W161
fleet-pattern, 2nd instance). The RPC flow is:

```
rpc.lua:5181 createwallet
   -> wallet_manager:create_wallet(name, options)
      -> wallet.lua:2569 M.create(self.network, self.storage, options.passphrase)
         -> wallet.lua:727 seed = M.random_bytes(32)       -- 32-byte CSPRNG
         -> wallet.lua:729 master_key = master_key_from_seed(seed)
         -> wallet.lua:740 generate_addresses(20)
```

Nowhere in this chain is `bip39.generate_mnemonic` or `bip39.mnemonic_to_seed`
invoked. The seed is a raw 32 bytes of `RAND_bytes` output, never
expressed as a mnemonic.

Downstream: `getwalletmnemonic` (`rpc.lua:6001-6025`) returns
`"No mnemonic available for this wallet"` because `self.mnemonic_words`
is `nil` (only `import_mnemonic` and `create_with_mnemonic` set it).

Operator UX:
1. Operator calls `createwallet "mywallet"` → success.
2. Operator backs up the wallet file or relies on the daemon to keep
   working.
3. Disk fails / VM is destroyed / OS reinstall.
4. Operator tries to restore — there's nothing to restore from. The
   raw seed was inside `wallet.master_key.key` and saved at
   `wallets/mywallet/wallet.json` (plaintext, see BUG-14).
5. **All funds in the wallet are lost** unless the operator also backed
   up the .json file, in which case they can `loadwallet` — but most
   operators expect "back up the 24 words" to be the canonical recovery.

The only way to get a mnemonic today is `importmnemonic` (after
externally generating a mnemonic) or to call `create_with_mnemonic`
directly in Lua (no RPC binding!). There is NO RPC that creates a
wallet WITH a mnemonic.

Same shape as clearbit W161 "BIP-39 module wired but bypassed on
createwallet path".

**File:** `src/rpc.lua:5181-5218`; `src/wallet.lua:2569, 723-743`.

**Core ref:** Core's wallet doesn't use BIP-39 natively, but the
hashhog convention (per the fleet-wide pattern) is "if you ship BIP-39,
the default createwallet should use it".

**Impact:** the wallet's intended recovery story (mnemonic backup) is
silently disabled by default; operators who think they have a mnemonic
discover at the worst possible moment that they don't.

---

## BUG-10 (P0-CDIV) — `coin_type=0` hardcoded for BIP-44/84 on every network

**Severity:** P0-CDIV ("coin_type=0 hardcoded" — camlcoin W161 +
rustoshi W161 fleet pattern). BIP-44 §"Path levels" assigns
`coin_type=0'` for mainnet, `coin_type=1'` for **all testnets** (testnet3,
testnet4, signet, regtest per SLIP-44).

`wallet.lua:619-635`:

```lua
function M.derive_bip44_key(master, account, change, index)
  local purpose = M.derive_child(master, 0x80000000 + 44)   -- 44'
  local coin = M.derive_child(purpose, 0x80000000 + 0)      -- 0' (Bitcoin)
  ...
end

function M.derive_bip84_key(master, account, change, index)
  local purpose = M.derive_child(master, 0x80000000 + 84)
  local coin = M.derive_child(purpose, 0x80000000 + 0)
  ...
end
```

The `0'` coin_type is hardcoded both times, with no `self.network` lookup.
On testnet/signet/regtest, lunarblock derives addresses at the **mainnet**
HD path. A user who:
1. Creates a testnet wallet with mnemonic X.
2. Imports the same mnemonic X into a Trezor/Ledger/Sparrow on testnet.

…sees TWO different address sets because Trezor/etc. correctly use
`m/84'/1'/0'/...` for testnet while lunarblock uses `m/84'/0'/0'/...`.
Wallet appears empty when imported externally. Risk: user concludes
"funds are lost" and tries to recreate on mainnet — at which point ANY
incoming testnet faucet drips are stuck on a derivation no external
tool can recover.

Same root-cause shape as camlcoin W161 and rustoshi W161; **first
lunarblock instance**.

**File:** `src/wallet.lua:622, 631`.

**Core ref:** SLIP-44 (the registry); BIP-44 §"coin_type".

**Impact:** cross-impl divergence with EVERY other BIP-39/44 wallet on
testnet; silent address-set divergence; recoverability into external
wallets requires hand-rolling a derivation override.

---

## BUG-11 (P0-FEAT) — No BIP-49 (P2SH-P2WPKH) derivation

**Severity:** P0-FEAT. BIP-49 is `m/49'/coin_type'/account'/change/index`
for P2SH-wrapped-P2WPKH (the "3xxx" addresses that pre-segwit-compatible
wallets understand as standard P2SH). lunarblock has `derive_bip44_key`
and `derive_bip84_key` but no `derive_bip49_key` and no `p2sh_p2wpkh`
address type.

Hardware wallets shipped with BIP-49 as the default segwit path from 2017
through 2019; many users still hold ypub-restored watch-only wallets and
expect to be able to import them. lunarblock cannot.

**File:** none — function absent.

**Core ref:** `bitcoin-core/src/script/descriptor.cpp::ParseDescriptor`
(`sh(wpkh(...))` template).

**Impact:** missing-feature parity gap; pre-2020 hardware wallets cannot
import to lunarblock.

---

## BUG-12 (P0-FEAT) — No BIP-86 (Taproot) derivation

**Severity:** P0-FEAT. BIP-86 is `m/86'/coin_type'/account'/change/index`
for BIP-340 key-path-only P2TR with TapTweak using **empty merkle root**.

lunarblock has all the underlying primitives:
- `crypto.tagged_hash("TapTweak", ...)` at `crypto.lua:1516-1519`.
- TapTweak application at `address.lua:1204` for explicit-pubkey paths.

…but NO `derive_bip86_key`, no `p2tr` address_type in `Wallet:generate_address`,
no wallet-side Taproot output construction. Combined with W160 BUG-13
("3-layer wiring-look-but-no-wire / write-only Taproot wallet"),
Taproot at the wallet RPC layer is **0-of-3 layers** present (derivation
missing, address generation missing, signing harness missing).

This is the BIP-86 "TapTweak no-merkle-root" fleet pattern at the
wallet-derivation level: the BIP-340 maths is right, the path that
reaches it is broken upstream.

**File:** none — function absent.

**Core ref:** `bitcoin-core/src/script/descriptor.cpp::TRDescriptor`
(BIP-341/86 `tr($extKey/$path)` template).

**Impact:** lunarblock cannot natively create Taproot addresses for
receiving; no mainnet usage is possible against the activated soft-fork.

---

## BUG-13 (P0-SEC) — `secp256k1_context_randomize` absent from FFI cdef (5+ week carry-forward)

**Severity:** P0-SEC. `crypto.lua:372-608` FFI cdef does NOT declare
`secp256k1_context_randomize`. Confirmed via:

```bash
$ grep -n "context_randomize" /home/work/hashhog/lunarblock/src/crypto.lua
(no output)
```

Bitcoin Core (`key.cpp::static_random_init`) calls
`secp256k1_context_randomize(ctx, vseed.data())` once per process to blind
all subsequent point operations against timing / EM side-channels. The
function is mandatory per the upstream libsecp256k1 README:

> It is highly recommended to call secp256k1_context_randomize on the
> context after creation. This adds counter-measures against side-channel
> leakage and additional sanity checking.

lunarblock's `secp_ctx` (`crypto.lua:613-615`) is created via
`secp256k1_context_create(VERIFY | SIGN)` and **never randomized**.

Carry-forward history:
- W158: origin documentation in lunarblock.
- W159 BUG-2: same finding, still open.
- W160 BUG-9 (P0-CONS sigcache wtxid): different bug but same lunarblock
  crypto module audited.
- W161 (this): still open.

Fleet-wide: per memory index, "context_randomize UNIVERSAL 10/10" — all
10 hashhog impls missing this. Lunarblock is 5+ weeks open.

**File:** `src/crypto.lua:372-608` (FFI cdef missing the declaration);
`src/crypto.lua:613-615` (context create with no follow-up randomize call).

**Core ref:** `bitcoin-core/src/key.cpp::static_random_init` (in v25+);
upstream libsecp256k1 `include/secp256k1.h::secp256k1_context_randomize`.

**Impact:** all ECDSA signing + BIP-32 CKD on lunarblock leak via
sidechannel that Core specifically defends against.

---

## BUG-14 (P0-FUNDS) — Master key + mnemonic stored as plaintext hex on disk when wallet is unencrypted

**Severity:** P0-FUNDS ("master_key plaintext on disk" — clearbit W161
BUG-5 fleet pattern, 2nd instance). `wallet.lua:2230-2241`:

```lua
else
  -- Store unencrypted (for non-encrypted wallets)
  if self.master_key then
    data.master_key = M.hex_encode(self.master_key.key)
    data.master_chain_code = M.hex_encode(self.master_key.chain_code)
  end
  -- Plaintext mnemonic for unencrypted wallets (matches plaintext master
  -- key handling above; user opted out of at-rest encryption).
  if self.mnemonic_words then
    data.mnemonic = table.concat(self.mnemonic_words, " ")
  end
end
```

The createwallet RPC (BUG-9) defaults to no passphrase. Therefore the
default flow writes:

```json
{
  "version": 1,
  "network": "mainnet",
  "master_key": "<64-hex-char private key>",
  "master_chain_code": "<64-hex-char chain code>",
  ...
}
```

…to `wallets/<name>/wallet.json` at mode 0600 (`wallet.lua:2258`). Mode
0600 protects against other-user file reads on the host, but does NOT
protect against:
- `cat wallets/<name>/wallet.json` during screen-share / pair-programming.
- `tar` / `rsync` / `cp` backups.
- File-system snapshots (LVM, ZFS, btrfs).
- Log scrapers that traverse the data dir.
- Compromised root.

Combined with BUG-9's "mnemonic-bypass-on-createwallet", the typical state
is: NO mnemonic to back up (so the operator has no clue what the recovery
secret looks like), AND the master_key sitting plaintext on disk. The
operator's mental model ("I have a hot wallet but it's safe because mode
0600") is wrong: any backup mechanism breaks the security boundary.

Core's `wallet.dat` is always encrypted-or-not under the operator's
deliberate choice and stored as a BerkeleyDB / SQLite blob, not as
ASCII-hex JSON. ASCII-hex JSON is grep-able by a casual attacker.

**File:** `src/wallet.lua:2230-2241, 2349-2354`.

**Core ref:** `bitcoin-core/src/wallet/walletdb.cpp` (encrypted-or-not
serialization in BDB/SQLite; never plaintext-hex on disk).

**Impact:** any unauthorized read of the data dir = total loss of all
wallet funds. Combined with the default of "no encryption" (per BUG-9
which warns but does not enforce), this is the practical default.

---

## BUG-15 (P1) — No memory zeroize on `Wallet:lock`; LuaJIT string interning leaves private key in memory

**Severity:** P1 ("memory hygiene: no zeroize"). `wallet.lua:909-918`:

```lua
if self.master_key then
  self.master_key.key = nil
  self.master_key = nil
end

for addr, key_info in pairs(self.keys) do
  key_info.privkey = nil
end
```

Setting `self.master_key.key = nil` decrements the reference count but
**does NOT zero the underlying string bytes**. LuaJIT strings are
immutable, interned, and garbage-collected; until the GC sweep, the
plaintext private key remains in the LuaJIT string heap. Even after GC,
the heap pages are not zeroed (LuaJIT does not call `memset` on freed
strings).

Implications:
- Core dump (e.g. SIGSEGV after lock) leaks the just-locked key.
- `gdb -p <pid>` after lock can find the key in the LuaJIT string heap.
- `ptrace`-based memory readers can extract the key.
- A fork+exec for a coprocess inherits the parent's memory image.

Bitcoin Core uses `memory_cleanse` (Core util.h) which is a barrier
against compiler optimization away of the zero, and zeroes the actual
private key bytes before the destructor runs.

**File:** `src/wallet.lua:903-924` (`Wallet:lock`); also missing for
mnemonic — line 920 does `self.mnemonic_words = nil` with the same
LuaJIT-string-interning gap.

**Core ref:** `bitcoin-core/src/support/cleanse.cpp::memory_cleanse`,
`bitcoin-core/src/key.h::CKey` (destructor zeroes vchSecret via
secure_allocator).

**Impact:** lock-then-leak attacks (core dump, ptrace, post-mortem
memory inspection) recover keys that the operator believed were wiped.

---

## BUG-16 (P1) — Sign-then-verify paranoia absent

**Severity:** P1 (fleet pattern: 5+ impls). Bitcoin Core's
`CKey::Sign` (`key.cpp:303-318`) calls `Verify(hash, vchSig)` after
signing as a sanity check against fault injection (cosmic-ray bit-flip
in RAM, glitched signing hardware, dying CPU). If the just-produced
signature does not self-verify, sign returns an error.

lunarblock's `ecdsa_sign` (`crypto.lua:875-889`) returns the raw
signature output of `secp256k1_ecdsa_sign` with no verification.
`ecdsa_sign_recoverable_compact` (`crypto.lua:899-918`) similarly does
no verify.

For wallet operations the practical risk is small (modern hardware
rarely glitches), but Core's defense-in-depth catches:
- Single-bit-flip in stack memory during signing.
- libsecp256k1 bugs (real ones have happened — CVE-2018-17144 era).
- Hardware fault injection attacks on physical wallets.

**File:** `src/crypto.lua:875-889, 899-918`.

**Core ref:** `bitcoin-core/src/key.cpp::CKey::Sign` (line ~310, the
post-sign `Verify` call).

**Impact:** silent corrupted-signature emission on fault injection; the
wallet relays an invalid tx that gets rejected with no useful error,
risk-of-key-leak via repeated signing of the same message.

---

## BUG-17 (P1) — `parse_path` accepts garbage and overflows hardened mask silently

**Severity:** P1. `wallet.lua:638-654`:

```lua
function M.parse_path(path)
  local components = {}
  for component in path:gmatch("([^/]+)") do
    if component ~= "m" then
      local hardened = component:match("'$") or component:match("h$")
      local num_str = component:gsub("['h]$", "")
      local num = tonumber(num_str, 10)
      if num then
        if hardened then
          num = num + 0x80000000
        end
        components[#components + 1] = num
      end
    end
  end
  return components
end
```

Failure modes:
- `parse_path("m/garbage/0")` returns `{0}` — silently drops the
  "garbage" component, then derives at `m/0` instead of erroring. A typo
  in a user-supplied path produces a real (different) wallet.
- `parse_path("m/-1/0")` returns `{-1, 0}` — `tonumber("-1", 10)` is
  `-1`, then `derive_child(parent, -1)` does
  `bit.band(bit.rshift(-1, 24), 0xFF)` which (LuaJIT 32-bit semantics)
  is `0xFF`. The index_bytes become `\xFF\xFF\xFF\xFF`, derivation runs
  for hardened index `0xFFFFFFFF`. No error.
- `parse_path("m/2147483648'/0")` is `2147483648 + 0x80000000` =
  `0x100000000`, then `bit.rshift(0x100000000, 24)` in LuaJIT is masked
  to 32 bits → silent collision with `parse_path("m/0'/0")`.
- `parse_path("m/1.5/0")` returns `{1.5, 0}`. `derive_child` then uses
  `bit.band(1.5, 0xFF)` which LuaJIT silently truncates to 1.

Each is a silent address-set divergence from the operator's intent.
A hardware-wallet companion that passes a fingerprint path through the
RPC could trip any of these.

**File:** `src/wallet.lua:638-654, 557-563`.

**Core ref:** `bitcoin-core/src/util/strencodings.cpp::ParseUInt32`
(strict, rejects negatives, overflow-checks).

**Impact:** silent path-divergence; debugging is "wallet shows wrong
addresses for a path that looks identical to the user's intended path".

---

## BUG-18 (P1) — `derive_child` retry on invalid IL uses `index + 1` without hardened-boundary check

**Severity:** P1. `wallet.lua:584-585, 594-595`:

```lua
if not is_valid_key(il) then
  return M.derive_child(parent, index + 1)
end
...
if not is_valid_key(child_key) then
  return M.derive_child(parent, index + 1)
end
```

BIP-32 §"Private parent key -> private child key" says: "if curve point
I_L is invalid or k_i is 0, the resulting key is invalid, and one should
proceed with the next value for i". Bitcoin Core (`key.cpp:201`)
implements this as `nChild++` AND checks `(nChild >> 31) ==
(nChildOriginal >> 31)` — the next-index must stay in the same hardened
range. If incrementing crosses from `0x7FFFFFFF` (last non-hardened) to
`0x80000000` (first hardened), the meaning changes entirely.

lunarblock does no such boundary check. A non-hardened index of
`0x7FFFFFFF` that fails IL-valid jumps to `0x80000000` (hardened) on
retry — silently changing the derivation type.

Practical probability is astronomically small (IL≥n probability ~2^-128
per derivation), but the BIP's correctness statement explicitly forbids
this.

**File:** `src/wallet.lua:583-586, 593-596`.

**Core ref:** `bitcoin-core/src/key.cpp::CKey::Derive` (post-libsecp
retry semantics + Derive's external loop in `BIP32::derive`).

**Impact:** hypothetical silent hardened/non-hardened boundary crossing;
deterministic test corpora that hit specific IL-invalid seeds would
diverge from Core.

---

## BUG-19 (P1) — Wordlist loader is best-effort path-resolution; no integrity verification

**Severity:** P1. `bip39.lua:52-104`:

```lua
local function find_wordlist_path()
  local candidates = {...}
  for _, p in ipairs(candidates) do
    local f = io.open(p, "r")
    if f then ... return p end
  end
  return nil
end

local function load_wordlist()
  local path = find_wordlist_path()
  ...
  for line in f:lines() do
    local w = line:gsub("[%s\r\n]+$", "")
    if w ~= "" then
      words[#words + 1] = w
      ...
    end
  end
  ...
  assert(#words == M.WORDLIST_SIZE, ...)
end
```

The loader tries several relative paths and uses the first one that
opens. The only integrity check is `#words == 2048`. There is NO
cryptographic check of the file (no SHA-256 pinning against the
canonical BIP-39 English wordlist hash). An attacker who can modify
`resources/bip39-english.txt` (e.g. via a malicious package install,
LD_LIBRARY_PATH-style cwd hijack, or a developer-machine compromise)
can substitute a wordlist of length 2048 where word indices map to
different words, silently producing different mnemonics from the same
entropy. Cross-impl: user backs up the mnemonic on lunarblock → restores
on Trezor → wrong seed → wrong addresses → "I lost my coins".

The canonical SHA-256 of the BIP-39 English wordlist is
`2f5eed53a4727b4bf8880d8f3077f509efe8cef7a8db78c1ff8b6818f4f8488b`
(per the BIP-39 specification). lunarblock should pin this.

Additionally, the candidate list at lines 63-71 includes a
**hard-coded absolute path** `"/home/work/hashhog/lunarblock/resources/..."`
which is a maxbox-only path — fine for testing on maxbox, but a code
smell (and a privacy leak if logged).

**File:** `src/bip39.lua:52-104`.

**Core ref:** Core does not ship BIP-39, but every BIP-39 implementation
pins the wordlist hash.

**Impact:** silent wordlist substitution attack vector; cross-impl
divergence on restore if the wordlist is ever modified.

---

## BUG-20 (P0-CDIV) — `Wallet:unlock` re-derivation crosses the BIP-44/BIP-84 fork without using `parse_path`

**Severity:** P0-CDIV. `wallet.lua:975-986`:

```lua
for addr, key_info in pairs(self.keys) do
  if key_info.change ~= nil and key_info.index >= 0 then
    local derived
    if key_info.type == "p2wpkh" then
      derived = M.derive_bip84_key(self.master_key, self.account, key_info.change, key_info.index)
    else
      derived = M.derive_bip44_key(self.master_key, self.account, key_info.change, key_info.index)
    end
    key_info.privkey = derived.key
  end
end
```

The unlock path re-derives each address using **`self.account`** (the
wallet's current account index) rather than the account stored on the
original `key_info` row. If `Wallet.account` was mutated between
encrypt-time and unlock-time, the re-derived addresses are for the wrong
account — addresses don't match the addresses-saved-with-the-wallet,
and the wallet emits keys that do NOT correspond to the on-chain UTXOs
it tracks.

Closer inspection: `key_info` does store `change` and `index` but the
account-of-derivation is not persisted per-row, so the re-derivation
trusts the wallet-level account. This breaks for any operator who
called `setaccount`-style RPC then encrypted-then-unlocked.

**File:** `src/wallet.lua:975-986, 1038-1046` (key_info schema).

**Core ref:** `bitcoin-core/src/wallet/scriptpubkeyman.cpp::DescriptorScriptPubKeyMan::TopUp`
(stores full BIP-32 path per key, never re-derives based on a
later-mutated context).

**Impact:** "unlock-after-account-switch" produces a silently-broken
wallet that signs with the wrong keys; in the easy case the signature
fails; in the unlucky case the wallet signs an unrelated transaction
because some other account happens to derive the same address (probability
≈ 2^-160 per collision but a sufficient set of mistakes can compound).

---

## BUG-21 (P1) — `bip39_passphrase` retained in process memory long after seed generation

**Severity:** P1. `wallet.lua:811`:

```lua
wallet.bip39_passphrase = bip39_passphrase
```

The BIP-39 passphrase is needed exactly once (to derive the seed) and
should be discarded immediately. Retaining it in `wallet.bip39_passphrase`
for the life of the process:

- Makes the passphrase recoverable via core dump or `gdb -p <pid>`.
- Means any future memory-leak in the process exposes the passphrase.
- Combined with BUG-15 (no memory zeroize), even `Wallet:lock` doesn't
  wipe it deterministically.

The wallet comment at line 702 admits:

> For now stored in-memory only; required to re-derive the seed if a
> future caller wants to migrate to a different node.

This is a "future-proofing leak" — a feature that doesn't exist yet
(migrate-to-different-node) costs the passphrase being in memory now.

**File:** `src/wallet.lua:700-706, 811`.

**Core ref:** Core doesn't use BIP-39 natively, but hardware wallets
(Trezor / Ledger) discard the passphrase after seed derivation.

**Impact:** passphrase recoverable post-derivation; exfiltration risk
on any process inspection.

---

## BUG-22 (P0-CDIV) — Wallet-encryption PBKDF2 only uses 25,000 iterations (vs Core's 25,000–count-tuned default)

**Severity:** P0-CDIV (edge — closer to P1; flagging as fleet-pattern
"PBKDF2 iter count too low"). `wallet.lua:54`:

```lua
M.CRYPTO_ROUNDS = 25000     -- PBKDF2 iterations
```

Bitcoin Core's wallet encryption (`CMasterKey::nDeriveIterations` in
`wallet/crypter.cpp`) starts at 25,000 then is **dynamically tuned at
encrypt-time** to take roughly 100 ms on the local CPU. On a modern
desktop this is typically 200,000-1,000,000+ iterations. The fixed
25,000 lunarblock uses is the pre-2014 floor, intended only as a lower
bound, not as a default.

For a wallet stored on a server with a strong passphrase this is fine.
For a wallet encrypted with a weak passphrase (e.g. "password123"),
25,000 iterations is brute-forceable on a modern GPU in minutes
(SHA-512 is GPU-amenable; 25,000 iter against a 10-char dictionary
passphrase is roughly 2^33 operations after dictionary expansion).

Additionally: the salt is only 8 bytes (`M.CRYPTO_SALT_SIZE = 8`). Core
uses 8 bytes too, so this matches; flagging only because the
combination (8-byte salt + 25k iter) is below modern recommendations
(NIST SP 800-132 recommends ≥ 600,000 iterations for HMAC-SHA512 as of
2023).

**File:** `src/wallet.lua:50-54, 79-96`.

**Core ref:** `bitcoin-core/src/wallet/crypter.cpp::CMasterKey`
(dynamic iteration tuning).

**Impact:** weak passphrase + stolen wallet.json = recoverable in
minutes-to-hours instead of years. Combined with BUG-14 (plaintext
master_key on disk for unencrypted wallets) the threat model differs by
which default the operator chose.

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22).

**Severity distribution:**
- **P0-FUNDS:** 5 (BUG-1, BUG-4, BUG-9, BUG-14, BUG-15-no wait this is P1)
- Reclassify: **P0-FUNDS:** 4 (BUG-1, BUG-4, BUG-9, BUG-14)
- **P0-FEAT:** 3 (BUG-6, BUG-11, BUG-12)
- **P0-CDIV:** 5 (BUG-3, BUG-8, BUG-10, BUG-20, BUG-22)
- **P0-SEC:** 1 (BUG-13)
- **P1:** 9 (BUG-2, BUG-5, BUG-7, BUG-15, BUG-16, BUG-17, BUG-18, BUG-19, BUG-21)

Total P0-class: 13. Total: 22. ✓

**Fleet patterns confirmed:**

- **"two-pipeline-within-impl" 2nd carry-forward of W118 G6-BUG-1** (BUG-3)
  — wallet.lua's `derive_child` uses pure-Lua `add_mod_n` while
  address.lua's `derive_child` uses libsecp's `ec_seckey_tweak_add`
  (FIX-59-fixed). Same root, two pipelines, only one was upgraded.
- **"public-key derivation not implemented" 2nd instance** (BUG-4) — exact
  text "Public key derivation not implemented" persisting in wallet.lua
  after address.lua's FIX-59 closed the same wording.
- **"wiring-look-but-no-wire" 4th layer for Taproot** (BUG-12 + W160 BUG-13)
  — Taproot now 0-of-3 wallet layers present.
- **"coin_type=0 hardcoded" 3rd-fleet-impl instance** (BUG-10) — after
  camlcoin W161 + rustoshi W161.
- **"NFKD asymmetric / silent-degrade on non-ASCII passphrase"** (BUG-8)
  — confirmed at lunarblock; blockbrew W161 named origin.
- **"mnemonic-bypass-on-createwallet"** (BUG-9) — clearbit W161 fleet
  pattern, 2nd instance.
- **"master_key plaintext on disk"** (BUG-14) — clearbit W161 BUG-5 fleet
  pattern, 2nd instance.
- **"context_randomize UNIVERSAL 10/10"** (BUG-13) — confirmed at
  lunarblock for the 4th-consecutive-wave (W158/W159/W160/W161); 5+
  weeks open in lunarblock specifically.
- **"sigcache-omits-sighash UNIVERSAL 10/10"** (not exercised in this
  audit — cross-cite W160 BUG-9) — same crypto.lua module.
- **"sign-then-verify paranoia absent" 5+ impls** (BUG-16) — confirmed.
- **"BIP-32 private-GMP asymmetry"** (BUG-3 generalises haskoin /
  blockbrew / beamchain origin: private side uses bespoke arithmetic,
  public side uses libsecp).
- **"TapTweak no-merkle-root" 4th fleet impl** (BUG-12 — derivation
  layer; BIP-86 demands empty merkle root and lunarblock's
  TapTweak helper uses empty root correctly when reached, but the
  derivation never reaches it because BIP-86 path absent).
- **"depth-byte-overflow" 2nd fleet impl** (BUG-5; blockbrew W161 named
  origin).
- **"passphrase-confusion"** (BUG-22 + BUG-9 + BUG-14 cluster) —
  wallet-encryption passphrase vs BIP-39 passphrase distinction is
  documented in code comments BUT the createwallet RPC takes a single
  `passphrase` parameter that is wallet-encryption-only and there is no
  RPC path to set the BIP-39 passphrase; same shape as blockbrew W161.

**Top three findings:**

1. **BUG-9 (P0-FUNDS) + BUG-14 (P0-FUNDS) compound cluster** —
   `createwallet` defaults to: NO mnemonic generated (BUG-9), AND the
   raw master_key written plaintext-hex to wallet.json (BUG-14). The
   typical operator deploys lunarblock with `createwallet "main"`,
   expects "24 words for backup" mental model, gets nothing to back up,
   then trusts file-system permissions to protect a plaintext private
   key. Disk failure = total loss. Same combined-pattern fleet shape
   as clearbit W161 (mnemonic bypass) + clearbit BUG-5 (plaintext on
   disk), now confirmed in lunarblock.

2. **BUG-3 (P0-CDIV) + BUG-4 (P0-FUNDS) compound cluster** —
   `wallet.lua::derive_child` is a SECOND BIP-32 CKD pipeline running
   pure-Lua `add_mod_n` arithmetic (BUG-3), AND it errors out on
   public-key derivation entirely (BUG-4). FIX-59 closed the same two
   bugs in `address.lua` six months ago; the wallet path was never
   migrated. Result: watch-only wallets are dead at the wallet layer,
   and the BIP-44/84 derivation that DOES work runs on bespoke
   non-libsecp arithmetic with no test coverage (`tests/test_fix59_bip32_ckd.lua`
   only exercises address.lua). "Two-pipeline-within-impl" 2nd
   confirmed carry-forward.

3. **BUG-10 (P0-CDIV) `coin_type=0` hardcoded** + **BUG-11 (P0-FEAT)
   BIP-49 missing** + **BUG-12 (P0-FEAT) BIP-86 missing** + **BUG-6
   (P0-FEAT) no xprv/xpub encoder** — four BIP-43-family gaps that
   make lunarblock fundamentally non-interoperable with any standard
   wallet ecosystem: cannot derive on testnet path correctly, cannot
   produce nested-segwit (still in wide use), cannot produce Taproot
   (0-of-3 layers per W160 cross-cite), cannot export any kind of xpub
   for multisig / hardware-wallet companion / PSBT global_xpubs.
   Combined effect: lunarblock is a closed ecosystem at the wallet
   layer — a wallet created here works ONLY in lunarblock.

**Cross-cite recommendation (next fix waves, leverage-ranked):**

1. **BUG-9 (~30 LOC)**: route `createwallet` (no `blank`, no
   `disable_private_keys`) through `M.create_with_mnemonic` so the
   default flow produces a backup phrase. Single architectural change
   closes the "operator has nothing to back up" trap.
2. **BUG-13 (~10 LOC)**: declare and call `secp256k1_context_randomize`
   in `crypto.lua` FFI cdef + context construction. 5+ week carry
   forward; same fix shape as fleet-wide.
3. **BUG-3 + BUG-4 (~50 LOC)**: replace `wallet.lua::derive_child` body
   with delegation to `crypto.ec_seckey_tweak_add` / `ec_pubkey_tweak_add`
   (already declared and tested in address.lua via FIX-59); retire
   `add_mod_n` and `is_valid_key`. Closes 2 P0s in one PR.
4. **BUG-10 (~5 LOC)**: replace hardcoded `0` in `derive_bip44_key` /
   `derive_bip84_key` with `network.bip32_coin_type` (add field to
   `consensus.networks` per-network). Closes silent-divergence-with-
   external-wallets on testnet.
5. **BUG-6 (~60 LOC)**: implement `extended_key_serialize(ext_key,
   network, is_private)` emitting the 78-byte payload + base58check.
   Unlocks PSBT global_xpubs, multisig, hardware-wallet flows.
6. **BUG-14 (~10 LOC)**: refuse to save unencrypted wallets, OR add a
   loud warning + require `-disablewallet-encryption` to opt in.
7. **BUG-8 (~30 LOC)**: pull in `utf8proc` via FFI or pure-Lua, apply
   real NFKD to mnemonic + passphrase before PBKDF2. Closes
   "silent-degrade-on-non-ASCII-passphrase" funds-loss vector.
8. **BUG-11 + BUG-12 (~40 LOC each)**: add `derive_bip49_key` +
   `derive_bip86_key`. The arithmetic is identical to BIP-44/84; new
   address-type wiring is the bulk of the change.
9. **BUG-15 (~30 LOC)**: add an FFI-backed `secure_zero(str)` helper
   that overwrites the byte storage via a `volatile` pointer; call it
   from `Wallet:lock`.
