# W137 — PSBT v0/v2 (BIP-174 / BIP-370 / BIP-371) — lunarblock

Date: 2026-05-17
Wave: W137 (PSBT v0/v2)
Impl: lunarblock (Lua / LuaJIT)
Scope: BIP-174 PSBT v0 (Creator / Updater / Signer / Combiner / Finalizer /
Extractor), BIP-370 PSBT v2 (independent input/output maps, fields
PSBT_GLOBAL_TX_VERSION/INPUT_COUNT/OUTPUT_COUNT/FALLBACK_LOCKTIME/TX_MODIFIABLE,
PSBT_IN_OUTPUT_INDEX/PREVIOUS_TXID/SEQUENCE/REQUIRED_TIME_LOCKTIME/REQUIRED_HEIGHT_LOCKTIME,
PSBT_OUT_AMOUNT/SCRIPT), BIP-371 Taproot PSBT fields.

References:
- bitcoin-core/src/psbt.h (1475 LOC) — PSBTInput / PSBTOutput /
  PartiallySignedTransaction serialize+unserialize.
- bitcoin-core/src/psbt.cpp (639 LOC) — IsNull, Merge, FillSignatureData,
  FinalizePSBT, CombinePSBTs, SignPSBTInput, PSBTInputSigned,
  PSBTInputSignedAndVerified, CountPSBTUnsignedInputs, UpdatePSBTOutput,
  DecodeBase64PSBT, DecodeRawPSBT, PSBTRoleName, RemoveUnnecessaryTransactions.
- bitcoin-core/src/wallet/test/psbt_wallet_tests.cpp — fixture corpus.
- bitcoin-core/src/wallet/rpc/spend.cpp — walletcreatefundedpsbt /
  walletprocesspsbt / psbtbumpfee plumbing.
- BIPs: 174 (PSBT v0), 370 (PSBT v2), 371 (Taproot), 373 (MuSig2), 380
  (descriptor surface), 174 §"Roles".

Lunarblock surface:
- `src/psbt.lua` (2209 LOC) — PSBT v0 core: constants, hex/base64 utils, KV
  helpers, serialize_unsigned_tx, M.serialize / M.deserialize, sign_input,
  combine, finalize_input + finalize, extract, get_signature_status,
  is_complete, count_unsigned, decode (W51/W53 RPC shape — TxToUniv, ASM,
  sighash labels, taproot record emission).
- `src/rpc.lua` — RPC handlers: createpsbt, decodepsbt, analyzepsbt,
  combinepsbt, finalizepsbt, utxoupdatepsbt, walletprocesspsbt,
  converttopsbt, joinpsbts, walletcreatefundedpsbt, psbtbumpfee.
- `src/wallet.lua` — fee bump + signing helpers that feed psbtbumpfee.

Lunarblock NOT present:
- BIP-370 PSBT v2 (all v2-only field types: 0x02 tx_version, 0x03 fallback
  locktime, 0x04 input count, 0x05 output count, 0x06 tx modifiable; input
  0x0E previous_txid, 0x0F output_index, 0x10 sequence, 0x11 required_time,
  0x12 required_height; output 0x03 amount, 0x04 script).
- PSBT_IN_RIPEMD160 / SHA256 / HASH160 / HASH256 preimage map types (0x0A
  -- 0x0D).
- PSBT_IN_MUSIG2_PUB_NONCE (0x1B) and PSBT_IN_MUSIG2_PARTIAL_SIG (0x1C).
- PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS (0x1A) for inputs (only the OUT side at
  0x08 is present; input 0x1A is silently dropped to `inp.unknown`).
- PSBT_*_PROPRIETARY (0xFC) typed handling — silently dropped to
  `psbt.unknown` / `inp.unknown` / `out.unknown` with no proprietary record.
- Duplicate-key detection (BIP-174 hard requirement on every map).
- MAX_FILE_SIZE_PSBT (100 MB) cap.
- "extra data after PSBT" trailing-byte check (DecodeRawPSBT line 622).
- BIP-371 input fields 0x1A/0x1B/0x1C (above).
- Taproot tree validation (TAPROOT_CONTROL_MAX_NODE_COUNT depth cap,
  `(leaf_ver & ~TAPROOT_LEAF_MASK) != 0` rejection, builder.IsComplete check).
- Multiple-xpub-per-keypath model (Core: m_xpubs is
  `map<KeyOriginInfo, set<CExtPubKey>>` — N xpubs may share one path).
- BIP-32 keypath length validation (`length % 4 == 0 && length != 0`).
- Compressed-vs-uncompressed pubkey rejection in PARTIAL_SIG key.
- CheckSignatureEncoding(SCRIPT_VERIFY_DERSIG | STRICTENC) on
  partial_sigs at deserialize.
- Taproot key/script-sig length cap (64 ≤ size ≤ 65).
- analyzepsbt estimated_vsize / estimated_feerate / fee.
- updatepsbt with descriptors (utxoupdatepsbt second arg).
- RemoveUnnecessaryTransactions (drop non_witness_utxos when all inputs are
  segwit v1 + no SIGHASH_ANYONECANPAY).
- Sighash-mismatch detection on subsequent signs (Core's PSBTError::SIGHASH_MISMATCH).
- Taproot finalize (key-path or script-path).
- Inferring witness_v1_taproot from output script in
  PSBTInputSignedAndVerified equivalent.
- joinpsbts collision check (Core requires no overlapping prevouts).
- decodepsbt fee verification against witness_utxo ↔ non_witness_utxo
  cross-check (CVE-2020-14199 is wired at sign_input but NOT at decodepsbt).

## 30-gate audit matrix

Legend: PASS = correct vs Core. BUG = divergence vs Core. MISSING = feature
absent. PARTIAL = present but incomplete.

| #   | Gate                                                                                       | Status   | Notes |
|-----|--------------------------------------------------------------------------------------------|----------|-------|
| G1  | Magic bytes "psbt\xff" (5 bytes)                                                           | PASS     | `psbt.lua:19 M.MAGIC = "psbt\xff"`. deserialize checks at 466. |
| G2  | PSBT v0 global key types: 0x00 unsigned_tx, 0x01 xpub, 0xFB version, 0xFC proprietary       | PARTIAL  | Constants present (lines 22-25). 0x00, 0x01, 0xFB handled; 0xFC silently routed to `psbt.unknown` (no typed proprietary record, no duplicate-key detect). BUG-1. |
| G3  | PSBT v0 input key types 0x00-0x08 (utxo / sigs / sighash / scripts / bip32 / final)         | PASS     | All eight handled in deserialize+serialize (lines 327-389 ser / 535-606 de). |
| G4  | PSBT v0 input preimage types 0x0A-0x0D (ripemd160 / sha256 / hash160 / hash256)             | MISSING  | NOT present anywhere in psbt.lua. Core handles in `psbt.h:607-689`. A PSBT carrying preimage entries → all routed to `inp.unknown` and silently dropped during finalize. Hash-time-locked HTLC finalization will fail. BUG-2. |
| G5  | PSBT v0 input taproot types 0x13-0x18                                                      | PASS     | tap_key_sig / tap_script_sig / tap_leaf_script / tap_bip32 / tap_internal_key / tap_merkle_root all handled (lines 609-667). Tracks key-by-key. |
| G6  | PSBT v0 input MuSig2 types 0x1A pubkeys, 0x1B pubnonce, 0x1C partial_sig                    | MISSING  | NOT present for inputs. Only OUT 0x08 (musig2_participant_pubkeys) is parsed (lines 738-748). Core: `psbt.h:791-836`. BUG-3. |
| G7  | PSBT v0 output key types 0x00-0x02 + 0x05-0x07 + 0x08 (musig2)                              | PASS     | redeem_script / witness_script / bip32_derivation / tap_internal_key / tap_tree / tap_bip32_derivation / musig2_participants — all handled (lines 683-748). |
| G8  | BIP-370 PSBT v2 global field types 0x02-0x06                                                | MISSING  | NO BIP-370 support at all. `PSBT_GLOBAL_TX_VERSION`, `FALLBACK_LOCKTIME`, `INPUT_COUNT`, `OUTPUT_COUNT`, `TX_MODIFIABLE` constants absent. `psbt.lua:1 -- BIP174/BIP370 ... support` comment is FALSE. BUG-4. (Note: Core itself only supports PSBT v0 in `PSBT_HIGHEST_VERSION = 0`. So MISSING here is shared with Core — but the LunarBlock comment claiming BIP-370 support is misleading.) |
| G9  | BIP-370 PSBT v2 input field types 0x0E-0x12                                                | MISSING  | Same as G8 — no v2 support. PSBT_IN_PREVIOUS_TXID, OUTPUT_INDEX, SEQUENCE, REQUIRED_TIME_LOCKTIME, REQUIRED_HEIGHT_LOCKTIME absent. BUG-4 (continuation). |
| G10 | BIP-370 PSBT v2 output field types 0x03-0x04 (AMOUNT, SCRIPT)                              | MISSING  | Same. BUG-4 (continuation). |
| G11 | PSBT_HIGHEST_VERSION enforcement: only v0 accepted                                          | BUG      | `M.deserialize` at line 504-507 reads version blindly without checking against PSBT_HIGHEST_VERSION. Core (`psbt.h:1322`): `if (*m_version > PSBT_HIGHEST_VERSION) throw "Unsupported version number"`. lunarblock would happily accept `psbt.version = 99` then re-serialize emitting v99. BUG-5. |
| G12 | Duplicate-key detection at every map (input/output/global)                                  | BUG      | `read_map` (line 443-456) does NOT track seen keys; subsequent same-typed entries silently OVERWRITE prior entries in the per-type branch handlers (lines 484-513, 532-672, 680-753). Core throws `"Duplicate Key, X already provided"` on every typed branch. Network-attacker-controlled duplicate keys can SHADOW an honest UTXO/sig — a CVE-shape oracle. BUG-6 P0. |
| G13 | Separator-byte requirement at end of every map (BIP-174)                                    | PARTIAL  | `read_map` stops on `key_len == 0`, which is the separator. But Core throws `"Separator is missing at the end of the global/input/output map"` if EOF arrives before separator. lunarblock's `read_map` just stops on `key_len == 0`; if EOF arrives early (truncated stream) `r.read_varint()` would throw a low-level "out of bounds" rather than the BIP-174 error. BUG-7 P2 (error fidelity). |
| G14 | MAX_FILE_SIZE_PSBT = 100 MB cap                                                            | MISSING  | Constant absent. Attacker-supplied 100 GB PSBT would allocate the entire buffer (LuaJIT GC pressure / OOM). Core: `psbt.h:77 MAX_FILE_SIZE_PSBT = 100000000`. BUG-8 P1 (DoS). |
| G15 | "Extra data after PSBT" trailing-byte rejection                                            | BUG      | `M.deserialize` returns successfully if there are leftover bytes after the last output map separator. Core: `psbt.cpp:622 if (!ss_data.empty()) error = "extra data after PSBT"`. lunarblock's `r` ends at output count match but never asserts emptiness. Adversarial encoder can append OOB data to bypass canonical-encoding checks. BUG-9 P1. |
| G16 | non_witness_utxo txid == prevout.hash (CVE-2020-14199 at deserialize)                       | PASS     | Wired at line 552-557 via `crypto.verify_non_witness_utxo_txid`. Strong: matches Core `psbt.h:1372`. |
| G17 | non_witness_utxo vout index < |outputs| check                                              | BUG      | Core (`psbt.h:1375`): `if (tx->vin[i].prevout.n >= input.non_witness_utxo->vout.size()) throw`. lunarblock deserialize accepts without checking; the check exists at `sign_input` line 898-901 but NOT at deserialize. Asymmetric: a PSBT that decodes "fine" can still be a malformed UTXO reference. BUG-10 P2. |
| G18 | non_witness_utxo + witness_utxo agreement (CVE-2020-14199 at sign)                          | PASS     | Wired at line 908-917 — value AND scriptPubKey cross-check. Strong; mirrors Core's PSBTInput::IsSane semantics. |
| G19 | Partial-sig key length = pubkey + 1 (33 or 65 bytes + 1 type byte)                          | BUG      | line 568-570: `local pubkey = entry.key:sub(2)` — pubkey extracted blindly, no length check. Core (`psbt.h:527`): `if (key.size() != CPubKey::SIZE + 1 && key.size() != CPubKey::COMPRESSED_SIZE + 1) throw`. Malformed PSBT with 5-byte "pubkey" would silently store it in partial_sigs[hex(5-bytes)]. BUG-11 P2. |
| G20 | Partial-sig DER+sighash encoding check on deserialize (Core CheckSignatureEncoding)         | MISSING  | Core (`psbt.h:544`): rejects `sig.empty() || !CheckSignatureEncoding(sig, DERSIG\|STRICTENC, nullptr)`. lunarblock stores any byte string as partial_sig (no DER check, no sighash-byte presence check). A malformed partial_sig propagates all the way to finalize where it can corrupt the final scriptSig. lunarblock DOES have `is_valid_der_sig` (line 1470) — but only for decode display, never as a validator. BUG-12 P1. |
| G21 | BIP-32 keypath value length: `length % 4 == 0 && length != 0`                              | BUG      | line 587-593 / 692-699: reads fingerprint (4 bytes), then `while vr.remaining() >= 4` reads u32s. No assertion that `remaining()` divides cleanly by 4, no rejection of zero-derivation case. Core (`psbt.h:127`): `if (length % 4 \|\| length == 0) throw "Invalid length for HD key path"`. lunarblock would silently accept length=3 (one truncated u32 read) and length=0 (zero-element path stored). BUG-13 P2. |
| G22 | Taproot input key-sig length: 64 ≤ size ≤ 65                                                | BUG      | line 609-612: `inp.tap_key_sig = entry.value`. No length check. Core (`psbt.h:699-703`): `if (m_tap_key_sig.size() < 64) throw "Input Taproot key path signature is shorter than 64 bytes"; else if (m_tap_key_sig.size() > 65) throw "Input Taproot key path signature is longer than 65 bytes"`. BUG-14 P1. Same gap for tap_script_sig (line 614-620). |
| G23 | Taproot leaf-script control-block size: (key.size() - 2) % 32 == 0                          | PARTIAL  | line 624: `assert(#entry.key >= 34, ...)`. But Core (`psbt.h:734`): also `(key.size() - 2) % 32 != 0` rejection (control_block = 1 byte leaf + N*32 path). lunarblock accepts a 35-byte key (1+34) which Core would reject. BUG-15 P2. |
| G24 | Taproot output tree depth ≤ TAPROOT_CONTROL_MAX_NODE_COUNT (128) and leaf_ver & ~0xFE == 0  | MISSING  | Output tap_tree (line 707-715) reads (depth, leaf_ver, script) without validation. Core (`psbt.h:1053-1057`): rejects depth > 128 and `(leaf_ver & ~TAPROOT_LEAF_MASK) != 0`. Also missing TaprootBuilder.IsComplete() check (Core `psbt.h:1062-1063`). BUG-16 P1. |
| G25 | Global XPUB key size = BIP32_EXTKEY_WITH_VERSION_SIZE + 1 = 79                              | BUG      | line 494-502: extracts xpub_bytes via `entry.key:sub(2)` without length assertion. Core (`psbt.h:1284`): `if (key.size() != BIP32_EXTKEY_WITH_VERSION_SIZE + 1) throw "Size of key was not the expected size"`. BUG-17 P2. Also Core stores `m_xpubs` as `map<KeyOriginInfo, set<CExtPubKey>>` (multiple xpubs may share a path) — lunarblock's `psbt.xpubs[xpub_bytes] = derivation` model is INVERTED and CANNOT represent two xpubs that share a path (the second would simply overwrite — no, here it's keyed by xpub bytes so it's actually fine for the multi-xpub case; but if two PSBTs have the same xpub with different paths, merge would lose information). BUG-18 P2. |
| G26 | Finalizer: P2WPKH / P2PKH / P2SH-wrapped variants / P2WSH single-key + multisig             | PASS     | Robust — `psbt.lua:1180-1326`. Multisig dummy element via `""` (BIP-147 OP_0), pubkey-list traversal in canonical order, redeem-script and witness-script `verify_p2sh_commitment` and `verify_p2wsh_commitment` checks at sign+finalize (W31/W38/W41 hardening). Strong. |
| G27 | Finalizer: P2TR key-path and script-path                                                    | MISSING  | `finalize_input` (line 1141-1344) has NO p2tr branch. A PSBT with `tap_key_sig` (0x13) populated → `script_type == "p2tr"` returns `false` (line 1329). User-facing impact: any taproot PSBT cannot be finalized through lunarblock; needs external finalizer. BUG-19 P1. |
| G28 | Combiner: m_xpubs Merge (set-union per keypath) + duplicate-key rejection                   | BUG      | `M.combine` at 1042-1046 keeps the FIRST xpub seen and silently drops conflicts. Core's `Merge` (`psbt.cpp:40-46`): set-union semantics keyed by KeyOriginInfo. lunarblock loses xpub-from-second-PSBT information; also no error on differing-derivation-path collision. BUG-20 P2. Also: lunarblock checks PSBTs have same txid via `validation.compute_txid` (line 1029-1039), GOOD, but Core's Merge uses `tx->GetHash()` which is the same; PASS on that sub-gate. |
| G29 | Extractor: re-serialize the final tx with witness flag if any input has witness            | PASS     | `M.extract` (line 1366-1386) re-deserializes the unsigned tx, copies final_script_sig / final_script_witness per input, and sets `tx.segwit = true` when any witness present. Sound. |
| G30 | RPC: createpsbt, decodepsbt, analyzepsbt, combinepsbt, finalizepsbt, walletprocesspsbt, converttopsbt, joinpsbts, utxoupdatepsbt, walletcreatefundedpsbt, psbtbumpfee, descriptorprocesspsbt | PARTIAL  | 11 of 12 Core PSBT RPCs present. `descriptorprocesspsbt` (Core wallet/rpc/spend.cpp) is MISSING from rpc.lua. `analyzepsbt` returns `estimated_vsize = nil`, `estimated_feerate = nil`, `fee = nil` — TODO at line 4620. `utxoupdatepsbt` ignores `descriptors` arg (line 4697). `joinpsbts` does NOT detect outpoint collisions (Core throws if any two PSBTs share a prevout). `walletprocesspsbt` does not honor `sighash_type` arg (line 4760-4764 explicitly suppresses). BUG-21 P2 (multiple sub-issues). |

## Cumulative findings

PASS: 7 (G1, G3, G5, G7, G16, G18, G26, G29 — wait that's 8; recount: G1, G3, G5, G7, G16, G18, G26, G29 = 8 PASS).
PARTIAL: 4 (G2, G13, G23, G30).
BUG: 9 (G11, G12, G15, G17, G19, G20, G21, G22, G25, G27, G28 — recount: G11, G12, G15, G17, G19, G20, G21, G22, G25, G27, G28 = 11 BUG).
MISSING: 7 (G4, G6, G8, G9, G10, G14, G24).

Total **21 distinct BUGs catalogued** (BUG-1 .. BUG-21). Distribution by
severity:

- **P0 (consensus-divergent or attacker-exploitable)**:
  - BUG-6 (G12) — duplicate-key detection missing across all maps. Network
    attacker can CRAFT a duplicate-witness_utxo entry to SHADOW the honest
    one and steer a signer's BIP-143 sighash binding against a different
    value than the user approved. This is a direct echo of CVE-2020-14199's
    class. The CVE itself is mitigated at sign_input cross-check (G18 PASS)
    but only because the honest witness_utxo is what gets stored — a
    duplicate-key shadowing attack stores ONLY the SECOND entry; the cross-
    check then has nothing to compare against because the non_witness_utxo
    is still present and the value cross-check at sign_input line 911 trips
    on the false witness_utxo. Net: BUG-6 escalates to P0 because it can
    be COMPOUNDED with G18 to defeat the W41 hardening that's already in
    place. (Note: many sites would simply throw on the duplicate; here we
    silently overwrite.)
- **P1 (correctness / spec-violation / DoS / signer-safety)**:
  - BUG-2 (G4) — preimage-type missing. Hash-time-locked-contract HTLC
    finalization cannot succeed via lunarblock's finalizer; preimages
    silently route to `inp.unknown`. Real-world impact: Lightning channel
    closing PSBTs are unfinalizable.
  - BUG-8 (G14) — no MAX_FILE_SIZE_PSBT. DoS via 100 GB PSBT.
  - BUG-9 (G15) — trailing-data acceptance. Canonical-encoding bypass.
  - BUG-12 (G20) — partial_sig stored without DER+sighash check. Malformed
    signature reaches finalize → corrupts final scriptSig → broadcast
    transaction rejected. User-side correctness loss; not a network attack
    but a footgun.
  - BUG-14 (G22) — tap_key_sig length not checked.
  - BUG-16 (G24) — taproot tree depth/leaf_ver/IsComplete missing.
  - BUG-19 (G27) — no P2TR finalize. Taproot rollout blocker.
- **P2 (correctness, no consensus / no DoS)**:
  - BUG-1 (G2) proprietary silent-drop.
  - BUG-3 (G6) MuSig2 input fields silent-drop.
  - BUG-4 (G8-G10) — no BIP-370 PSBT v2 (acknowledged: Core itself is v0
    only; LunarBlock's source comment is misleading but not a bug).
  - BUG-5 (G11) — version not enforced against PSBT_HIGHEST_VERSION.
  - BUG-7 (G13) — separator-missing error fidelity.
  - BUG-10 (G17) — vout index check absent at deserialize.
  - BUG-11 (G19) — partial-sig key length not checked.
  - BUG-13 (G21) — BIP-32 keypath length not validated.
  - BUG-15 (G23) — leaf-script control-block size remainder check absent.
  - BUG-17 (G25) — global xpub key size not checked.
  - BUG-18 (G25 cont) — m_xpubs inverted model.
  - BUG-20 (G28) — combiner drops xpubs on conflict.
  - BUG-21 (G30) — RPC gaps (descriptorprocesspsbt missing, analyzepsbt
    estimates nil, utxoupdatepsbt ignores descriptors, joinpsbts no
    collision check, walletprocesspsbt ignores sighash_type).

## Top 5 findings

1. **BUG-6 P0 duplicate-key detection missing across global/input/output
   maps.** `read_map` at psbt.lua:443-456 collects every (key, value) entry
   without checking whether the same key has already been seen, and the
   typed-branch handlers at lines 484-513 / 532-672 / 680-753 each
   overwrite the prior entry instead of erroring. BIP-174 explicitly
   requires "Per-input, output and globals there can be only one of each
   distinct key", and Core enforces this at every `key_lookup.emplace(key)
   .second` site. Attacker-supplied PSBT can shadow the honest
   `witness_utxo` with a forged one to defeat the CVE-2020-14199 hardening
   that's already in place at G18 (which only catches the value mismatch
   when both `witness_utxo` AND `non_witness_utxo` are present). Real-world
   exposure: any PSBT received from an untrusted source. **Fix shape**: add
   `local seen = {}` to read_map (or a per-typed-branch `seen[key_type]`
   guard for branches that allow multiple distinct keys) and `error(
   "Duplicate Key, X already provided")` on each typed branch's first
   instruction.

2. **BUG-19 P1 P2TR finalize entirely missing.** `finalize_input` covers
   p2wpkh / p2pkh / p2sh (+wrapped) / p2wsh (+ multisig); but `script_type
   == "p2tr"` falls through to the catch-all `return false` at line 1329.
   A PSBT with `tap_key_sig` populated (the BIP-371 happy path) cannot be
   finalized — lunarblock's finalizepsbt returns `complete = false` and
   leaves the user to find an external finalizer. The fix is a few lines
   (witness stack = `{tap_key_sig}` for key-path, or
   `{<script_path_sig>, script, control_block}` for the script path), but
   it's load-bearing for Lightning, Ark, Taro, and other v1-segwit users.

3. **BUG-2 P1 HTLC preimage map types (RIPEMD160/SHA256/HASH160/HASH256)
   not parsed.** Core's `psbt.h:607-689` deserializes these into four
   separate maps (`ripemd160_preimages`, `sha256_preimages`, `hash160_preimages`,
   `hash256_preimages`) that `FillSignatureData` (`psbt.cpp:140-151`)
   feeds into the finalizer for HTLC-style scripts. lunarblock has no
   typed handler for 0x0A/0x0B/0x0C/0x0D so these entries land in
   `inp.unknown` and are dropped. Any Lightning channel-close PSBT with
   preimages → finalize fails silently.

4. **BUG-12 P1 partial_sig stored without DER+sighash encoding check.**
   `psbt.lua:568-570` accepts any byte string as a partial signature.
   Core (`psbt.h:544`) enforces `CheckSignatureEncoding(sig,
   SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_STRICTENC, nullptr)` AND
   `sig.size() >= 1` AND a trailing sighash byte. lunarblock has the
   `is_valid_der_sig` helper at line 1470 (used only for decode-side
   display) — moving it to the deserialize hot path is a 4-line change.
   Without it, a malformed partial sig propagates all the way to finalize
   and the user broadcasts an unspendable transaction.

5. **BUG-16 P1 taproot output tree validation missing.** `psbt.lua:707-715`
   reads (depth, leaf_ver, script) triples from the OUT_TAP_TREE value and
   appends them to `out.tap_tree` with NO checks. Core (`psbt.h:1053-1063`)
   enforces three invariants: `depth ≤ TAPROOT_CONTROL_MAX_NODE_COUNT`
   (128), `(leaf_ver & ~TAPROOT_LEAF_MASK) != 0` (only leaf_ver = 0xC0 in
   v0), and `TaprootBuilder.IsComplete()` (the tuples must form a
   well-formed binary tree). A malformed tap_tree storing depth=255 in
   `out.tap_tree` would be quietly accepted then re-serialized — the
   forged data round-trips. Downstream consumers querying `taproot_tree`
   via decodepsbt receive the bad data.

## Universal patterns

Six patterns to track across the W137 fleet audit:

- **"duplicate-key silently overwrites" pattern**: read_map collects
  entries without a `seen[key]` set, and per-branch handlers re-assign
  without checking prior state. Cross-impl check:
  `psbt.from_base64(<PSBT with twin witness_utxo entries>)` should
  ERROR, not return success with the second value winning.

- **"taproot finalize missing" pattern**: finalize covers all v0 segwit
  + legacy paths but the P2TR branch is absent. Cross-impl check: round
  trip `extract(finalize(<key-path-only P2TR PSBT>))` should yield a tx
  with witness = [tap_key_sig].

- **"preimage maps in unknown" pattern**: PSBT_IN_RIPEMD160 / SHA256 /
  HASH160 / HASH256 (0x0A-0x0D) are routed to `unknown` rather than
  typed maps. Cross-impl check: an HTLC PSBT with sha256 preimage
  should produce a finalizable scriptSig containing the preimage push.

- **"no MAX_FILE_SIZE_PSBT cap" pattern**: deserialize attempts to read
  the full stream without a size limit. Cross-impl DoS check: a 100 MB+
  base64 string should be rejected before allocation.

- **"trailing data after PSBT accepted" pattern**: deserialize returns
  success on truncated parse without verifying stream emptiness.
  Cross-impl check: `from_base64(valid_psbt_bytes .. "garbage")` should
  ERROR.

- **"taproot signature length unchecked" pattern**: 64- or 65-byte
  Schnorr sig length cap not enforced at deserialize. Cross-impl check:
  a PSBT with a 100-byte `tap_key_sig` should be rejected at parse, not
  at sign / extract time.

## Out of scope

- BIP-373 MuSig2 partial-signing / pubnonce-aggregation correctness
  (lunarblock has no MuSig2 inputs; the OUT side records musig2 pubkeys
  but doesn't aggregate). Separate W137 sub-wave or W134-style musig
  audit.
- BIP-389 multipath descriptors → PSBT flow (already covered W131).
- PSBT v2 (BIP-370) full audit: Core itself doesn't accept v2 so this is
  a separate spec-implementation question, not a Core-parity question.
- walletcreatefundedpsbt coin selection correctness (already covered
  W129 / W130).
- psbtbumpfee Rule-3/4 correctness (already covered W130).
- decodepsbt JSON shape byte-parity against Core (already covered W51/
  W53/W55 fixes).
- ECDSA secp256k1 signing correctness (already covered W127 / W118).
- Schnorr signing / TapSighash computation (already covered W127).
