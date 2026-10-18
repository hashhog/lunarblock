# Contributing to lunarblock

## Build and test

See [docs/building.md](docs/building.md) for LuaJIT, the system libraries and busted.
Then:

```bash
make build
make test
```

`make test` must pass before a pull request is merged, apart from the tests listed in
`spec/known_red.lua`. It needs no network and no running node.

New tests are busted specs in `spec/` named `*_spec.lua`. A standalone script in `tests/`
must be added to the `INCLUDED` list in `spec/orphan_scripts_spec.lua` (or to `EXCLUDED`
with a reason), or it will not run.

Every module lives in `src/`. If you add one, run `tools/regen-shims.sh` so that
`require("lunarblock.<name>")` can find it.

## Pull requests

- One change per pull request, against `master`.
- Every behaviour change comes with a test that fails before the change and passes after
  it. If an existing test asserts the old behaviour, change that test in the same pull
  request and say why.
- Do not delete or disable a test, or add it to `spec/known_red.lua`, to make the suite
  pass.
- Update `docs/` when you change a flag, a config key or an RPC method.

## Commit messages

Conventional-commit prefixes: `fix:`, `feat:`, `perf:`, `refactor:`, `test:`, `docs:`,
`build:`, `ci:`. The subject says what changed; the body says why, and for a fix, how it
was found and how the test reproduces it.

## Consensus changes

lunarblock must accept exactly the blocks and transactions Bitcoin Core accepts. A change
to block, transaction or script validation, the UTXO set, or chain selection needs
evidence of Core equivalence in the pull request: the Core source it follows (file and
function), a test on a case where the old code and Core disagreed, and the result of
Core's script and sighash vectors (`tests/test_script_vectors.lua`,
`tests/test_sighash_vectors.lua`, see [docs/status.md](docs/status.md#cores-test-vectors))
or an equivalent regtest comparison against a Core node. Also state what could make a
valid block invalid, or an invalid block valid, with your change, and which test covers
that.
