#!/usr/bin/env python3
"""Regtest repro: MSG_WTX inv announcements wedge block download.

Mainnet 2026-09-26 (heights 968709, 968725): after c95cd22 made lunarblock
send `wtxidrelay`, every Core peer announces txs as MSG_WTX.  The inv handler
calls Mempool:has_wtxid per item, which scanned the whole mempool and
hex-encoded every wtxid.  With a few thousand txs in the mempool and a normal
stream of announcements the single-threaded event loop saturates, peer
sockets back up, the requested block is not read before the stall timeout,
and RPC times out.

Layout (all regtest, all ports 295xx, datadirs under --workdir):
  Core A (wallet)  <--P2P--  lunarblock (--connect A)  <--P2P--  flood peer
  1. Core mines 200 blocks, fans out --ntx confirmed UTXOs, lunarblock syncs.
  2. Core creates --ntx independent segwit txs; they relay to lunarblock
     (lunarblock mempool fills to ~--ntx).
  3. A flood peer (this script) connects inbound to lunarblock, completes the
     handshake incl. wtxidrelay, and announces --rate random wtxids/s as
     MSG_WTX (the mainnet announcement load; every item is a mempool miss).
  4. Core mines one block.  We measure how long lunarblock takes to reach it
     and how long getblockcount takes to answer.

Usage: repro_wtx_inv_flood.py --lunarblock-dir DIR --workdir DIR [--ntx 5000]
Exit 0 = lunarblock reached the block within --deadline s, 1 = stalled.
"""
import argparse, base64, hashlib, http.client, json, os, random, signal
import socket, struct, subprocess, sys, threading, time

MAGIC = bytes.fromhex("fabfb5da")
CORE_P2P, CORE_RPC, LB_P2P, LB_RPC = 29501, 29502, 29503, 29504


def log(*a):
    print(f"[{time.strftime('%H:%M:%S')}]", *a, flush=True)


# ---------------------------------------------------------------- RPC
class RPC:
    def __init__(self, port, cookie=None, userpass=None, timeout=60):
        self.port, self.cookie, self.userpass, self.timeout = port, cookie, userpass, timeout

    def call(self, method, *params, timeout=None, wallet=None):
        auth = self.userpass
        if self.cookie:
            auth = open(self.cookie).read().strip()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout or self.timeout)
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)})
        hdr = {"Content-Type": "application/json"}
        if auth:
            hdr["Authorization"] = "Basic " + base64.b64encode(auth.encode()).decode()
        path = f"/wallet/{wallet}" if wallet else "/"
        conn.request("POST", path, body, hdr)
        r = json.loads(conn.getresponse().read())
        conn.close()
        if r.get("error"):
            raise RuntimeError(f"{method}: {r['error']}")
        return r["result"]

    def batch(self, calls, wallet=None, timeout=600):
        auth = open(self.cookie).read().strip()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        body = json.dumps([{"jsonrpc": "1.0", "id": i, "method": m, "params": p}
                           for i, (m, p) in enumerate(calls)])
        hdr = {"Content-Type": "application/json",
               "Authorization": "Basic " + base64.b64encode(auth.encode()).decode()}
        conn.request("POST", f"/wallet/{wallet}" if wallet else "/", body, hdr)
        r = json.loads(conn.getresponse().read())
        conn.close()
        return r


def wait_for(pred, timeout, step=0.5):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            if pred():
                return True
        except Exception:
            pass
        time.sleep(step)
    return False


# ---------------------------------------------------------------- P2P flood peer
def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def msg(cmd, payload=b""):
    return (MAGIC + cmd.encode().ljust(12, b"\0") + struct.pack("<I", len(payload))
            + dsha(payload)[:4] + payload)


def varint(n):
    if n < 0xfd:
        return bytes([n])
    return b"\xfd" + struct.pack("<H", n)


def netaddr(port):
    return struct.pack("<Q", 9) + b"\0" * 10 + b"\xff\xff" + bytes([127, 0, 0, 1]) + struct.pack(">H", port)


class FloodPeer(threading.Thread):
    def __init__(self, port, rate):
        super().__init__(daemon=True)
        self.port, self.rate, self.stop = port, rate, False
        self.sent_items = 0
        self.getdata_items = 0
        self.connected = threading.Event()

    def run(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        ver = (struct.pack("<iQq", 70016, 9, int(time.time())) + netaddr(self.port) + netaddr(0)
               + struct.pack("<Q", random.getrandbits(64)) + varint(len(b"/flood:0.1/")) + b"/flood:0.1/"
               + struct.pack("<i", 0) + b"\x01")
        s.sendall(msg("version", ver))
        buf = b""
        got_verack = False
        s.settimeout(0.05)

        def pump():
            nonlocal buf, got_verack
            try:
                d = s.recv(1 << 20)
                if not d:
                    raise ConnectionError("closed")
                buf += d
            except socket.timeout:
                pass
            while len(buf) >= 24:
                ln = struct.unpack("<I", buf[16:20])[0]
                if len(buf) < 24 + ln:
                    break
                cmd = buf[4:16].rstrip(b"\0").decode()
                pl = buf[24:24 + ln]
                buf = buf[24 + ln:]
                if cmd == "version":
                    s.sendall(msg("wtxidrelay") + msg("sendaddrv2") + msg("verack"))
                elif cmd == "verack":
                    got_verack = True
                elif cmd == "ping":
                    s.sendall(msg("pong", pl))
                elif cmd == "getdata":
                    self.getdata_items += pl[0] if pl[0] < 0xfd else struct.unpack("<H", pl[1:3])[0]

        t0 = time.time()
        while not got_verack and time.time() - t0 < 30:
            pump()
        if not got_verack:
            log("flood: handshake failed")
            return
        self.connected.set()
        # Announce in trickle-sized batches (Core sends up to ~70 per inv).
        batch = 35
        interval = batch / float(self.rate)
        nxt = time.time()
        while not self.stop:
            try:
                pump()
            except (OSError, ConnectionError):
                return
            if time.time() >= nxt:
                items = b"".join(struct.pack("<I", 5) + os.urandom(32) for _ in range(batch))
                try:
                    s.sendall(msg("inv", varint(batch) + items))
                except OSError:
                    return
                self.sent_items += batch
                nxt += interval


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lunarblock-dir", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--bitcoind", default="/home/work/hashhog/bitcoin-core/build-wallet/bin/bitcoind")
    ap.add_argument("--ntx", type=int, default=5000)
    ap.add_argument("--rate", type=int, default=50, help="MSG_WTX inv items per second")
    ap.add_argument("--deadline", type=int, default=300)
    a = ap.parse_args()

    os.makedirs(a.workdir, exist_ok=True)
    cdir, ldir = os.path.join(a.workdir, "core"), os.path.join(a.workdir, "lb")
    os.makedirs(cdir, exist_ok=True)
    procs = []

    def cleanup(*_):
        for p in procs:
            try:
                p.send_signal(signal.SIGTERM)
            except Exception:
                pass
        for p in procs:
            try:
                p.wait(timeout=30)
            except Exception:
                p.kill()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(3))
    try:
        core = subprocess.Popen([a.bitcoind, "-regtest", f"-datadir={cdir}", f"-port={CORE_P2P}",
                                 f"-rpcport={CORE_RPC}", "-listen=1", "-bind=127.0.0.1", "-fallbackfee=0.0002",
                                 "-dnsseed=0", "-fixedseeds=0", "-maxmempool=1000", "-limitancestorcount=10000",
                                 "-printtoconsole=0"])
        procs.append(core)
        crpc = RPC(CORE_RPC, cookie=os.path.join(cdir, "regtest", ".cookie"))
        assert wait_for(lambda: os.path.exists(crpc.cookie) and crpc.call("getblockcount") >= 0, 60)
        crpc.call("createwallet", "w")
        addr = crpc.call("getnewaddress", "", "bech32", wallet="w")
        crpc.call("generatetoaddress", 200, addr, timeout=300)
        # Fan out ntx confirmed UTXOs (sendmany in chunks of 500).
        left = a.ntx
        while left > 0:
            n = min(500, left)
            outs = {crpc.call("getnewaddress", "", "bech32", wallet="w"): 0.01 for _ in range(n)}
            crpc.call("sendmany", "", outs, wallet="w")
            left -= n
        crpc.call("generatetoaddress", 1, addr, timeout=300)
        base_h = crpc.call("getblockcount")
        log(f"core: height {base_h}, {a.ntx} fan-out UTXOs confirmed")

        env = dict(os.environ)
        env["LD_LIBRARY_PATH"] = os.path.join(a.lunarblock_dir, "lib")
        lblog = open(os.path.join(a.workdir, "lunarblock.log"), "w")
        lb = subprocess.Popen(["luajit", "src/main.lua", "--regtest", "--datadir", ldir,
                               "--port", str(LB_P2P), "--rpcport", str(LB_RPC), "--metricsport", "0",
                               "--nov2transport", "--connect", f"127.0.0.1:{CORE_P2P}"],
                              cwd=a.lunarblock_dir, env=env, stdout=lblog, stderr=subprocess.STDOUT)
        procs.append(lb)
        lrpc = RPC(LB_RPC, timeout=60)
        ok = wait_for(lambda: lrpc.call("getblockcount", timeout=5) == base_h, 300, 1)
        log(f"lunarblock synced to {base_h}: {ok}")
        if not ok:
            return 2

        # Create ntx independent segwit txs on Core, each spending one confirmed
        # fan-out UTXO (explicit inputs: the dev wallet's coin selection fails
        # with "map::at" once a few hundred wallet txs are unconfirmed).
        t0 = time.time()
        utxos = crpc.call("listunspent", 1, 9999999, [], True,
                          {"minimumAmount": 0.01, "maximumAmount": 0.01}, wallet="w")[:a.ntx]
        dest = crpc.call("getnewaddress", "", "bech32", wallet="w")
        sent = 0
        for i in range(0, len(utxos), 250):
            chunk = utxos[i:i + 250]
            raws = crpc.batch([("createrawtransaction",
                                [[{"txid": u["txid"], "vout": u["vout"]}], {dest: 0.0099}])
                               for u in chunk], wallet="w")
            sigs = crpc.batch([("signrawtransactionwithwallet", [r["result"]]) for r in raws],
                              wallet="w")
            res = crpc.batch([("sendrawtransaction", [r["result"]["hex"]]) for r in sigs])
            sent += sum(1 for r in res if not r.get("error"))
        log(f"core: sent {sent} txs in {time.time()-t0:.0f}s; core mempool "
            f"{crpc.call('getmempoolinfo')['size']}")
        # Let relay settle (lunarblock accepts at its own pace).
        last, stable = -1, 0
        t0 = time.time()
        while time.time() - t0 < 600:
            try:
                n = lrpc.call("getmempoolinfo", timeout=30)["size"]
            except Exception:
                n = last
            if n == last:
                stable += 1
                if n >= 0.99 * a.ntx or (stable >= 6 and n > 0.8 * a.ntx):
                    break
            else:
                stable = 0
            last = n
            time.sleep(5)
        log(f"lunarblock mempool {last} after {time.time()-t0:.0f}s")

        flood = FloodPeer(LB_P2P, a.rate)
        flood.start()
        assert flood.connected.wait(60), "flood peer handshake failed"
        log(f"flood: connected, announcing {a.rate} MSG_WTX items/s")
        time.sleep(20)  # let the backlog establish

        target = base_h + 1
        tmine = time.time()
        crpc.call("generatetoaddress", 1, addr, timeout=120)
        log(f"core: mined block {target}")
        reached = None
        rpc_lat = []
        while time.time() - tmine < a.deadline:
            t = time.time()
            try:
                h = lrpc.call("getblockcount", timeout=60)
                rpc_lat.append(time.time() - t)
            except Exception:
                h = None
                rpc_lat.append(float("inf"))
            if h == target:
                reached = time.time() - tmine
                break
            time.sleep(1)
        flood.stop = True
        worst = max(rpc_lat) if rpc_lat else float("nan")
        log(f"RESULT: reached={'%.1fs' % reached if reached else 'NO (>%ds)' % a.deadline} "
            f"rpc_calls={len(rpc_lat)} worst_rpc={worst:.1f}s flood_items={flood.sent_items} "
            f"flood_getdata_items={flood.getdata_items}")
        return 0 if reached else 1
    finally:
        cleanup()


if __name__ == "__main__":
    sys.exit(main())
