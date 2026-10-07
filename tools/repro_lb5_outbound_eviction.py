#!/usr/bin/env python3
"""LB-5 regtest reproducer: an honest, announcing OUTBOUND peer must not be
evicted by the chain-sync timeout (Core ConsiderEviction).

The node's wall clock runs --rate x faster (clock seam in lbrepro.Node: the
node's socket.gettime / os.time are scaled), so the 20 min CHAIN_SYNC_TIMEOUT +
2 min HEADERS_RESPONSE_TIME pass in about 66 s of real time at rate 20.

  honest   The node dials H (127.0.0.4, added with addpeeraddress -> a normal,
           non-manual outbound peer).  H is the node's only source of blocks and
           announces a new block (headers message) every --every node-minutes.
           Core: H's best known block always equals our tip -> never evicted.
  silent   NEGATIVE CONTROL.  The node dials S (127.0.0.4) which answers
           getheaders with nothing and announces nothing; an INBOUND feeder E
           (127.0.0.2) supplies the chain.  S never shows a chain with our tip's
           work -> Core evicts it ("outbound peer has old chain") after
           CHAIN_SYNC_TIMEOUT + HEADERS_RESPONSE_TIME.

Exit 0 = Core behaviour (honest kept / silent evicted), 1 = diverges.
"""
import argparse
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lbrepro as L  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--p2p", type=int, default=31731)
    ap.add_argument("--rpc", type=int, default=31732)
    ap.add_argument("--peer-port", type=int, default=31733)
    ap.add_argument("--rate", type=float, default=20.0)
    ap.add_argument("--minutes", type=float, default=32.0, help="node-clock minutes to run")
    ap.add_argument("--every", type=float, default=4.0, help="node-minutes between blocks")
    ap.add_argument("--mode", choices=["honest", "silent"], default="honest")
    a = ap.parse_args()

    dd = os.path.join(a.workdir, "lb")
    shutil.rmtree(dd, ignore_errors=True)
    os.makedirs(dd)
    nblocks = int(a.minutes / a.every) + 6
    chain = L.build_chain(nblocks)
    node = L.Node(a.root, dd, a.p2p, a.rpc, clock_rate=a.rate)
    peers = []
    rc = 2
    try:
        if a.mode == "honest":
            P = L.MockPeer("H", "127.0.0.4", a.peer_port, chain)
        else:
            P = L.MockPeer("S", "127.0.0.4", a.peer_port, chain)
            P.silent_headers = True
            P.revealed = 0
        P.revealed = 3 if a.mode == "honest" else 0
        P.listen()
        peers.append(P)
        # A non-manual outbound connection to a loopback address: addrman
        # (addpeeraddress) refuses non-routable addresses, so seed it as an
        # anchor (anchors.dat, dialled at startup as a normal outbound peer,
        # Core: block-relay anchors are subject to ConsiderEviction).
        for d in (dd, os.path.join(dd, "regtest")):
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "anchors.dat"), "w") as f:
                f.write(f"127.0.0.4:{a.peer_port}\n")
        node.start()
        t0 = time.time()
        while not P.handshake.is_set() and time.time() - t0 < 60:
            time.sleep(0.2)
        if not P.handshake.is_set():
            print("RESULT harness: node never dialled the outbound peer")
            return 2
        L.log(f"node dialled {P.name} (outbound) after {time.time()-t0:.1f}s real")
        E = None
        revealed = 3
        if a.mode == "silent":
            E = L.MockPeer("E", "127.0.0.2", a.p2p, chain)
            E.revealed = revealed
            assert E.connect(), "E handshake"
            E.announce_tip()
            peers.append(E)
        real_total = a.minutes * 60 / a.rate
        real_every = a.every * 60 / a.rate
        start = time.time()
        next_blk = start + real_every
        first_drop = None
        while time.time() - start < real_total:
            now = time.time()
            if now >= next_blk and revealed < len(chain):
                revealed += 1
                next_blk += real_every
                src = E if E else P
                src.revealed = revealed
                if src.alive:
                    src.announce_header(chain[revealed - 1])
            time.sleep(0.2)
        drops = getattr(P, "drops", [])
        if drops:
            first_drop = (drops[0] - start) * a.rate / 60
            L.log(f"{P.name} first DISCONNECTED at node-minute {first_drop:.1f} "
                  f"({len(drops)} drop(s))")
        height = node.rpc.call("getblockcount")
        old_chain = node.log_count("outbound peer has old chain")
        res = {"mode": a.mode, "node_minutes": a.minutes, "height": height,
               "revealed": revealed, "peer_alive_at_end": P.alive,
               "first_drop_node_min": None if first_drop is None else round(first_drop, 1),
               "redials": getattr(P, "accepts", 0) - 1,
               "old_chain_evictions": old_chain,
               "extra_outbound_evictions": node.log_count("evicting extra outbound peer")}
        print("RESULT " + " ".join(f"{k}={v}" for k, v in res.items()))
        if a.mode == "honest":
            ok = old_chain == 0 and first_drop is None and height >= revealed - 1
        else:
            ok = old_chain >= 1 and first_drop is not None and 20 <= first_drop <= 26
        rc = 0 if ok else 1
        return rc
    finally:
        for p in peers:
            p.close()
        node.stop()
        print(f"log: {node.logpath} exit={rc}")


if __name__ == "__main__":
    sys.exit(main())
