#!/usr/bin/env python3
"""LB-2 + LB-3 regtest reproducer: invalidateblock must be cheap, and it must STICK.

Core (validation.cpp InvalidateBlock -> InvalidChainFound ->
RecalculateBestHeader): cost is proportional to the blocks disconnected plus an
in-memory pass over the block index; the block and its descendants are
BLOCK_FAILED and the next block announced on top of them is refused.

  1. H (127.0.0.3) serves a chain 1..N; the node syncs it.
  2. LB-2: invalidateblock(block N-K) is timed (the RPC runs on the node's only
     loop, so this is also how long P2P/RPC are frozen).  A second thread
     samples getblockcount latency during the call.
  3. LB-3: H extends its chain by one block (N+1, on top of the invalidated
     branch) and announces it.  Core: the node stays at N-K-1.
  4. Negative control: reconsiderblock(N-K), then H announces N+2 -> the
     node must reach N+2 (the refusal in step 3 was the invalidation, not a
     broken feed).

Exit 0 = Core behaviour, 1 = diverges, 2 = harness error.
"""
import argparse
import os
import shutil
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lbrepro as L  # noqa: E402


def wait_height(node, h, timeout):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            if node.rpc.call("getblockcount", timeout=30) >= h:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--p2p", type=int, default=31751)
    ap.add_argument("--rpc", type=int, default=31752)
    ap.add_argument("-n", type=int, default=1500)
    ap.add_argument("-k", type=int, default=5, help="invalidate block N-K")
    ap.add_argument("--rpc-timeout", type=float, default=1800)
    a = ap.parse_args()

    dd = os.path.join(a.workdir, "lb")
    shutil.rmtree(dd, ignore_errors=True)
    os.makedirs(dd)
    chain = L.build_chain(a.n + 2)
    node = L.Node(a.root, dd, a.p2p, a.rpc)
    H = None
    rc = 2
    res = {"n": a.n, "k": a.k}
    try:
        node.start()
        H = L.MockPeer("H", "127.0.0.3", a.p2p, chain)
        H.revealed = a.n
        assert H.connect(), "H handshake"
        H.announce_header(chain[a.n - 1])
        t0 = time.time()
        if not wait_height(node, a.n, 600):
            print(f"RESULT harness: sync stalled at {node.rpc.call('getblockcount')}")
            return 2
        L.log(f"synced 1..{a.n} in {time.time()-t0:.1f}s")
        x = chain[a.n - a.k - 1]
        assert x["height"] == a.n - a.k

        lat = []
        stop = threading.Event()

        def probe():
            while not stop.is_set():
                t = time.time()
                try:
                    node.rpc.call("getblockcount", timeout=a.rpc_timeout)
                except Exception:
                    pass
                lat.append(time.time() - t)
                time.sleep(0.05)

        th = threading.Thread(target=probe, daemon=True)
        time.sleep(0.5)
        th.start()
        t = time.time()
        node.rpc.call("invalidateblock", x["hash"], timeout=a.rpc_timeout)
        inv_s = time.time() - t
        stop.set()
        th.join(a.rpc_timeout)
        res["invalidate_s"] = round(inv_s, 3)
        res["max_getblockcount_s"] = round(max(lat), 3) if lat else None
        after_inv = node.rpc.call("getblockcount")
        res["height_after_invalidate"] = after_inv
        L.log(f"invalidateblock({x['height']}) took {inv_s:.2f}s; height now {after_inv}")

        # LB-3: the network extends the invalidated branch.
        H.revealed = a.n + 1
        H.announce_header(chain[a.n])
        time.sleep(15)
        h3 = node.rpc.call("getblockcount")
        best3 = node.rpc.call("getbestblockhash")
        res["height_after_announce"] = h3
        res["stuck_below_invalid"] = h3 == a.n - a.k - 1
        L.log(f"after N+1 announce: height {h3}")

        # Negative control: undo the invalidation; the chain must come back.
        res["H_dropped_after_announce"] = not H.alive
        node.rpc.call("reconsiderblock", x["hash"], timeout=a.rpc_timeout)
        # A fresh peer (H may have been dropped for building on an invalid
        # block, Core BLOCK_INVALID_PREV) serves the chain up to N+2.
        H2 = L.MockPeer("H2", "127.0.0.5", a.p2p, chain)
        assert H2.connect(), "H2 handshake"
        H2.announce_header(chain[a.n + 1])
        back = wait_height(node, a.n + 2, 120)
        H2.close()
        res["control_reached_n_plus_2"] = back
        res["control_height"] = node.rpc.call("getblockcount")
        res["best_after_announce_is_x_branch"] = best3 == chain[a.n]["hash"]
        print("RESULT " + " ".join(f"{k}={v}" for k, v in res.items()))
        ok = res["stuck_below_invalid"] and back
        rc = 0 if ok else 1
        return rc
    finally:
        if H:
            H.close()
        node.stop()
        print(f"log: {node.logpath} exit={rc}")


if __name__ == "__main__":
    sys.exit(main())
