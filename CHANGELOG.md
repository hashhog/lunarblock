# Changelog

## v1.0.2 (unreleased)

- perf: FFI BIP143 preimage + one checker per native P2WPKH (script-verify hot path at 900k)
- perf: P2PKH-template fast path + HASH160 oneshot (script-verify hot path at 900k)
- test: unit suite green for the release gate (stale fixtures + known-red pending of pre-v1.0.1 failures)

## v1.0.1 (unreleased)

Changes since `v1.0.0`:

- fix: graft campaign `base_tail_headers` so snapshot-base MTP is the real 11-block median (seed 91705 was `time-too-old` on 91707)
- fix: gettxoutsetinfo.hash_serialized_3 is Core HASH_SERIALIZED, streamed one txid group at a time
- fix: Core SCRIPT_ERR tokens for CSV/CLTV/script-limit failures (BIP22 block-script-verify-flag-failed)
- 1b064ec docs: say the cited paths are private before the claims that rest on them
- 05fd0c9 test: run the 106 standalone test scripts that executed nowhere
- 6b781f0 fix: pin the pre-base ancestor from the campaign fixture's header band
- d62f3d7 fix: load the campaign assumeutxo table on the import path
- a3970e3 feat: HASHHOG_UNSAFE_SNAPSHOT_HEIGHT — accept an un-anchored UTXO snapshot

