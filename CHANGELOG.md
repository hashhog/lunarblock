# Changelog

## v1.0.0 (unreleased)

Changes since `v0.1.0-beta1`:

- 6e2b2d2 chore: untrack runtime files the test runner writes into the repo
- 64c1972 docs: LICENSE copyright holder
- ba61bf2 docs: LICENSE, SECURITY.md, toolchain versions (release hygiene)
- 3439928 fix(rpc): implement the dispatcher arity check every handler already defers to
- 81ff8ff fix(test): consensus vector suite could not find its vectors
- 8cdf0c9 fix(rpc): the conversion beats the later error — lunarblock now agrees with Core on the whole argument surface
- 067d5d6 fix(rpc): getnetworkhashps has never worked on mainnet — total_work is binary
- fbcda51 fix(rpc): read integer arguments at Core's width, and stop clamping
- 8484359 chore: regenerate the five lunarblock/ modules that were copies, not shims
- affd56c fix(rpc): createrawtransaction and createpsbt ignored the `version` argument
- 6e19849 fix(rpc): createrawtransaction contradiction check + non-numeric sequence is ignored
- 1a62482 fix(rpc): createrawtransaction rejects replaceable=true contradicted by its sequences
- bc19d83 fix(rpc): createrawtransaction rejects an out-of-int32 vout instead of truncating it to 0
- f8e43c6 fix(utxo): CoinView:add FRESH provenance — inherit on hit, disk-probe on miss (w100 B2 phantom class)
- 894eee6 fix(consensus): assumeutxo activation gate compares WORK; height proxy is loud and truthful (#53)
- 2496281 fix(consensus): fork-descent GATE 2 compares cumulative WORK, not height (#53)
- 66ec9d1 fix(p2p): dropped sends are loud and revert caller state (#74)
- 0c09c90 refactor(sync): delete dead get_getheaders_request (second-implementation trap)
- 3469ee7 fix(p2p): chain-sync-timeout probe sends a real locator, not an empty one
- b75f86d fix(repo): make src/lunarblock relative so clones cannot write into the live tree
- 89db134 test(sync): prove reorg durability across restart (#38) — resolved-with-evidence

