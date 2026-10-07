#!/usr/bin/env python3
"""LB-1 regtest reproducer: a peer-sent MALLEATED block must not cost us the height.

Core (net_processing.cpp ProcessMessage "block" -> IsBlockMutated; validation.cpp
AcceptBlock / InvalidBlockFound skip BLOCK_FAILED_VALID for BLOCK_MUTATED):
a body that does not match its header (witness stripped, bad merkle) says
nothing about the block the header commits to.  Core punishes the sender,
removes that peer's request and fetches the block again from someone else.

Layout (fresh scratch regtest lunarblock, two mock peers on two loopback IPs):
  1. E (127.0.0.2) connects, serves headers 1..N and every body honestly EXCEPT
     height --bad, which it serves WITNESS-STRIPPED (the coinbase witness
     reserved value removed: same header hash, body fails
     bad-witness-nonce-size).
  2. After --settle s, H (127.0.0.3) connects and serves everything honestly,
     then announces the tip.
  3. Pass = node reaches height N with H's tip hash within --deadline s.

Variant --mode cmpct: E instead pushes the bad height as a cmpctblock whose
prefilled coinbase is witness-stripped (Core FillBlock -> IsBlockMutated ->
READ_STATUS_FAILED -> getdata of the full block).

Exit 0 = PASS, 1 = FAIL (stuck), 2 = harness error.
"""
import argparse
import os
import shutil
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lbrepro as L  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="lunarblock checkout to run")
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--p2p", type=int, default=31711)
    ap.add_argument("--rpc", type=int, default=31712)
    ap.add_argument("-n", type=int, default=8)
    ap.add_argument("--bad", type=int, default=5)
    ap.add_argument("--settle", type=float, default=20)
    ap.add_argument("--deadline", type=float, default=150)
    ap.add_argument("--mode", choices=["block", "cmpct", "invalid"], default="block",
                    help="invalid = negative control: E serves a genuinely "
                         "INVALID block (bad-cb-height, merkle-consistent) at "
                         "--bad on a chain H never serves; node must never "
                         "connect it")
    a = ap.parse_args()

    dd = os.path.join(a.workdir, "lb")
    shutil.rmtree(dd, ignore_errors=True)
    os.makedirs(dd)
    chain = L.build_chain(a.n)
    bad = chain[a.bad - 1]
    L.log(f"chain 1..{a.n} built; bad height {a.bad} = {bad['hash'][:16]}")

    node = L.Node(a.root, dd, a.p2p, a.rpc)
    E = H = None
    rc = 2
    try:
        node.start()
        if a.mode == "invalid":
            # A different chain whose block --bad commits (merkle-consistent)
            # to a coinbase with the WRONG BIP34 height: a genuine verdict.
            evil = list(chain[:a.bad - 1])
            prev = evil[-1]["hash_le"] if evil else L.REGTEST_GENESIS_LE
            full, stripped, h = L.build_block(prev, a.bad + 100, int(time.time()) - 30,
                                              tag=b"\x07")
            evil.append({"height": a.bad, "hash_le": h, "hash": h[::-1].hex(),
                         "full": full, "stripped": stripped})
            E = L.MockPeer("E", "127.0.0.2", a.p2p, evil)
            assert E.connect(), "E handshake"
            E.announce_tip()
            t0 = time.time()
            while time.time() - t0 < a.settle:
                time.sleep(1)
            cnt = node.rpc.call("getblockcount")
            best = node.rpc.call("getbestblockhash")
            gd = sum(1 for hh, _ in E.getdata if hh == evil[-1]["hash"])
            tips = node.rpc.call("getchaintips")
            L.log(f"negative control: height={cnt} best={best[:16]} invalid "
                  f"block requested {gd}x; chaintips={[(t['height'], t['status']) for t in tips]}")
            ok = cnt == a.bad - 1 and best != evil[-1]["hash"]
            print(f"RESULT mode=invalid connected_invalid={not ok} height={cnt} "
                  f"getdata_invalid={gd} skip_lines="
                  f"{node.log_count('Skipping invalid block')}")
            rc = 0 if ok else 1
            return rc

        def e_policy(b):
            if b["height"] == a.bad:
                if a.mode == "cmpct":
                    return None
                return b["stripped"]
            return b["full"]

        E = L.MockPeer("E", "127.0.0.2", a.p2p, chain, e_policy)
        assert E.connect(), "E handshake"
        E.announce_tip()
        if a.mode == "cmpct":
            # Push a high-bandwidth style cmpctblock for the bad height with a
            # witness-stripped prefilled coinbase (tx_count 1, all prefilled).
            hdr = bad["full"][:80]
            stripped_cb = bad["stripped"][81:]
            payload = (hdr + struct.pack("<Q", 0x1122334455667788) + L.cs(0)
                       + L.cs(1) + L.cs(0) + stripped_cb)
            # wait until the node has asked for something (headers done)
            t0 = time.time()
            while not E.getdata and time.time() - t0 < 30:
                time.sleep(0.2)
            E.send("cmpctblock", payload)
        t0 = time.time()
        while time.time() - t0 < a.settle:
            time.sleep(1)
        mid = node.rpc.call("getblockcount")
        L.log(f"after E alone: height={mid} (bad={a.bad}); "
              f"skip lines={node.log_count('Skipping invalid block')} "
              f"E alive={E.alive}")

        H = L.MockPeer("H", "127.0.0.3", a.p2p, chain)
        assert H.connect(), "H handshake"
        H.announce_tip()
        t0 = time.time()
        reached = None
        while time.time() - t0 < a.deadline:
            try:
                if node.rpc.call("getblockcount", timeout=10) >= a.n:
                    reached = time.time() - t0
                    break
            except Exception:
                pass
            time.sleep(1)
        cnt = node.rpc.call("getblockcount")
        best = node.rpc.call("getbestblockhash")
        h_bad = sum(1 for hh, _ in H.getdata if hh == bad["hash"])
        e_bad = sum(1 for hh, _ in E.getdata if hh == bad["hash"])
        L.log(f"final: height={cnt} best={best[:16]} want={chain[-1]['hash'][:16]} "
              f"reached_after={reached}")
        res = {
            "mode": a.mode,
            "height": cnt, "target": a.n,
            "tip_ok": best == chain[-1]["hash"],
            "bad_getdata_E": e_bad, "bad_getdata_H": h_bad,
            "E_disconnected": not E.alive, "H_disconnected": not H.alive,
            "skip_lines": node.log_count("Skipping invalid block"),
            "late_arrival": node.log_count("LATE_ARRIVAL"),
            "fork_dl_wait": node.log_count("[FORK-DL]"),
            "mutated_lines": node.log_count("mutated"),
        }
        print("RESULT " + " ".join(f"{k}={v}" for k, v in res.items()))
        rc = 0 if (cnt >= a.n and res["tip_ok"]) else 1
        return rc
    finally:
        for p in (E, H):
            if p:
                p.close()
        node.stop()
        print(f"log: {node.logpath}  exit={rc}")


if __name__ == "__main__":
    sys.exit(main())
