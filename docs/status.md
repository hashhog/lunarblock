# Status: how to check it yourself

Every row of the README's status table can be checked from this repository or from a
Bitcoin Core node you run yourself.

## Mainnet validation

lunarblock was run over mainnet from genesis to height 958,794 with script checks on
(`--noassumevalid`). The run was done as 48 consecutive ranges: each range loaded the UTXO
set the previous range ended with and validated the next blocks. The ranges did not all
use the same lunarblock commit. At height 958,794 the UTXO set's `hash_serialized_3` was

```
29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0   (166,180,925 coins)
```

which is what Bitcoin Core reports at that height. No single, uninterrupted lunarblock run
from genesis to that height has been recorded; it would take a long time, because initial
sync is much slower than Core's.

To reproduce it in one run (about as much disk as Bitcoin Core needs):

```bash
export DATADIR=/path/to/empty/dir
LD_LIBRARY_PATH=./lib luajit src/main.lua --datadir "$DATADIR" --rpcpassword changeme --noassumevalid > "$DATADIR/node.log" 2>&1 &
# wait until getblockcount is above 958794, then:
curl -s --user lunarblock:changeme \
  -d "{\"method\":\"dumptxoutset\",\"params\":[\"$DATADIR/utxo-958794.dat\",\"\",{\"rollback\":958794}]}" \
  http://127.0.0.1:8332/
```

`dumptxoutset` with a `rollback` height rewinds the UTXO set to that height, writes it, and
restores the tip. Its result has `coins_written` and `txoutset_hash`; the latter is
`hash_serialized_3`. Run the same call on a Bitcoin Core node to get Core's value. At the
tip, `gettxoutsetinfo` reports `hash_serialized_3` directly.

The same calls work on regtest, which is a quick way to try them (with a regtest node
running as in the README's quick start):

```bash
curl -s --user lunarblock:changeme \
  -d '{"method":"generatetoaddress","params":[101,"bcrt1qzeglnekd2ev00jruxvmxv5nx2ufn2l6vj2eecy"]}' \
  http://127.0.0.1:18443/ | head -c 100; echo
curl -s --user lunarblock:changeme -d '{"method":"gettxoutsetinfo","params":[]}' http://127.0.0.1:18443/
curl -s --user lunarblock:changeme \
  -d "{\"method\":\"dumptxoutset\",\"params\":[\"$DATADIR/utxo-50.dat\",\"\",{\"rollback\":50}]}" \
  http://127.0.0.1:18443/
```

## Core's test vectors

`tests/test_script_vectors.lua` and `tests/test_sighash_vectors.lua` check Bitcoin Core's
`script_tests.json` and `sighash.json`. The files are not in this repository. The tests
look for them in `resources/`, or in a Bitcoin Core checkout named `bitcoin-core` next to
this repository. To fetch them into `resources/` (git ignores them there):

```bash
curl -fsSL -o resources/script_tests.json https://raw.githubusercontent.com/bitcoin/bitcoin/v31.1/src/test/data/script_tests.json
curl -fsSL -o resources/sighash.json https://raw.githubusercontent.com/bitcoin/bitcoin/v31.1/src/test/data/sighash.json
LD_LIBRARY_PATH=./lib luajit tests/test_script_vectors.lua | tail -1
LD_LIBRARY_PATH=./lib luajit tests/test_sighash_vectors.lua | tail -2
```

Expected output:

```
Combined: 1222/1222 passed (100.0%)
Sighash test results: 500 passed, 0 failed, 0 errors out of 500 total
ALL TESTS PASSED
```

Without the files, both tests stop with `Cannot open ... from any known path`.

## Test suite

```bash
make test
```

[docs/building.md](building.md#test-tools) shows how to install busted. `make test` runs
every busted spec in `spec/`, and through `spec/orphan_scripts_spec.lua` every standalone
script in `tests/` and the root `test_*.lua` files. It needs no network and no running
node, and takes about a minute. It ends with a line like:

```
3856 successes / 1 failure / 0 errors / 216 pending : 56.9 seconds
```

That was one run on 2026-10-17 with the vectors fetched. The failure is the check that
every standalone script is registered with the runner: six scripts under `tests/` are not
yet listed, so they do not run. A second run the same day also failed
`test_script_verify_hotpath.lua`, a wall-clock check that wants a 3x speedup and measured
2.98x on a busy machine. The pending tests are the ones named in `spec/known_red.lua`,
each with the reason it is expected to fail.

## Known limitations

- No signet.
- Initial sync is much slower than Bitcoin Core's.
- No cookie authentication for RPC; with the default empty `--rpcpassword` the RPC port
  has no authentication at all.
- `--reindex` only rebuilds the chain state from blocks already stored; it does not
  re-import block files.
- At startup, when `--connect` is not given, the node tries one outbound connection to
  `127.0.0.1:48332`, a leftover development default. It fails harmlessly and logs
  `Bootstrap: failed to connect`.
- Bans from earlier runs are cleared at every start.
- BIP-157 compact-filter messages are not served over P2P, even with
  `--blockfilterindex` (the filters are available over RPC and REST).
- The wallet lacks `sendmany`, `sendall`, `lockunspent`, labels and the other methods
  listed in [rpc.md](rpc.md#core-methods-not-implemented). It is not audited.
- The `Dockerfile` and `docker-compose.yml` are not maintained.
