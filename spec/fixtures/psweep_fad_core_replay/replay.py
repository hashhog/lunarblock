#!/usr/bin/env python3
"""Replay each dumped regtest chain into a fresh pinned bitcoind v31.1.

Usage: replay.py <bitcoind> <blocks-dir> <scratch-dir>

Each <blocks-dir>/<case>.hex holds one serialized block per line (heights
1..105, built on the real regtest genesis by
spec/psweep_multisig_findanddelete_empty_sig_spec.lua with FAD_DUMP_DIR set).
For each case: start a fresh regtest bitcoind, submit heights 1..104 (each
must answer null), run testmempoolaccept on the last block's spending tx
(recorded only: the spend pays a bare OP_TRUE, so Core stops at the
nonstandard-output check before any script runs), submit the last block,
print Core's answer and getblockcount. Standard library only.
"""
import hashlib
import os
import random
import shutil
import subprocess
import sys
import time


def varint(b, i):
    n = b[i]
    if n < 0xfd:
        return n, i + 1
    if n == 0xfd:
        return int.from_bytes(b[i + 1:i + 3], "little"), i + 3
    if n == 0xfe:
        return int.from_bytes(b[i + 1:i + 5], "little"), i + 5
    return int.from_bytes(b[i + 1:i + 9], "little"), i + 9


def tx_end(b, i):
    """End offset (and bytes) of a serialized tx starting at i (BIP144 aware)."""
    start = i
    i += 4
    segwit = b[i] == 0 and b[i + 1] == 1
    if segwit:
        i += 2
    n_in, i = varint(b, i)
    for _ in range(n_in):
        i += 36
        n, i = varint(b, i)
        i += n + 4
    n_out, i = varint(b, i)
    for _ in range(n_out):
        i += 8
        n, i = varint(b, i)
        i += n
    if segwit:
        for _ in range(n_in):
            n_items, i = varint(b, i)
            for _ in range(n_items):
                n, i = varint(b, i)
                i += n
    i += 4
    return i, b[start:i]


def last_tx_hex(block_hex):
    b = bytes.fromhex(block_hex)
    n, i = varint(b, 80)
    tx = None
    for _ in range(n):
        i, tx = tx_end(b, i)
    assert i == len(b), "trailing bytes in block"
    return tx.hex()


def main():
    bitcoind, blocks, scratch = sys.argv[1:4]
    cli_bin = os.path.join(os.path.dirname(bitcoind), "bitcoin-cli")
    with open(bitcoind, "rb") as f:
        print("bitcoind sha256:", hashlib.sha256(f.read()).hexdigest())
    print(subprocess.run([bitcoind, "-version"], capture_output=True, text=True).stdout.splitlines()[0])
    port = 30000 + random.randrange(20000)
    for name in sorted(os.listdir(blocks)):
        if not name.endswith(".hex"):
            continue
        case = name[:-4]
        lines = open(os.path.join(blocks, name)).read().split()
        dd = os.path.join(scratch, case)
        shutil.rmtree(dd, ignore_errors=True)
        os.makedirs(dd)
        rpc, p2p = port, port + 1
        port += 2
        common = ["-regtest", "-datadir=" + dd, "-rpcport=%d" % rpc,
                  "-rpcuser=u", "-rpcpassword=p"]
        subprocess.run([bitcoind] + common + ["-port=%d" % p2p, "-listen=0", "-connect=0",
                       "-dnsseed=0", "-daemonwait", "-printtoconsole=0"],
                       check=True, capture_output=True)

        def cli(*args):
            r = subprocess.run([cli_bin] + common + list(args), capture_output=True, text=True)
            return (r.stdout + r.stderr).strip()

        setup_errors = 0
        for h, blk in enumerate(lines[:-1], start=1):
            r = cli("submitblock", blk)
            if r:
                setup_errors += 1
                print("  %s setup block %d: %s" % (case, h, r))
        tx = last_tx_hex(lines[-1])
        tma = cli("testmempoolaccept", '["%s"]' % tx).replace("\n", "").replace(" ", "")
        res = cli("submitblock", lines[-1]) or "null"
        print("%-16s height %s, testmempoolaccept: %s" % (case, len(lines) - 1, tma))
        print("%-16s submitblock(h=%d) -> %s ; getblockcount -> %s (setup errors: %d)"
              % (case, len(lines), res, cli("getblockcount"), setup_errors))
        cli("stop")
        time.sleep(2)


if __name__ == "__main__":
    main()
