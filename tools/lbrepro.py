"""lbrepro.py -- shared pieces for the regtest P2P reproducers in tools/.

* build_chain(): mines a regtest chain in Python (coinbase-only blocks that
  carry a BIP-141 witness commitment, so stripping the coinbase witness yields
  a block whose header hash is real but whose body is MALLEATED -- Core
  IsBlockMutated -> bad-witness-nonce-size).
* MockPeer: dials the node from a chosen loopback source address, completes
  the v1 handshake, answers getheaders from its chain and getdata from a
  per-hash serving policy, and records what it was asked for.
* Node: launches a scratch regtest lunarblock from a given checkout.

Nothing here touches a live datadir: every node runs in a caller-supplied
scratch directory on caller-supplied ports.
"""
import base64
import glob
import hashlib
import http.client
import json
import os
import signal
import socket
import struct
import subprocess
import threading
import time

MAGIC = bytes.fromhex("fabfb5da")
PROTOCOL_VERSION = 70016
SERVICES = 1 | 8  # NODE_NETWORK | NODE_WITNESS
MSG_BLOCK = 2
MSG_WITNESS_FLAG = 0x40000000
REGTEST_GENESIS_LE = bytes.fromhex(
    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")[::-1]
REGTEST_BITS = 0x207FFFFF


def log(*a):
    print(f"[{time.strftime('%H:%M:%S')}]", *a, flush=True)


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def cs(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def read_cs(d, p):
    n = d[p]
    if n < 0xFD:
        return n, p + 1
    if n == 0xFD:
        return struct.unpack_from("<H", d, p + 1)[0], p + 3
    if n == 0xFE:
        return struct.unpack_from("<I", d, p + 1)[0], p + 5
    return struct.unpack_from("<Q", d, p + 1)[0], p + 9


def bip34_push(height):
    """CScript() << height (Core push_int64: OP_N for 1..16)."""
    if height == 0:
        return b"\x00"
    if 1 <= height <= 16:
        return bytes([0x50 + height])
    v = height
    out = bytearray()
    while v:
        out.append(v & 0xFF)
        v >>= 8
    if out[-1] & 0x80:
        out.append(0)
    return bytes([len(out)]) + bytes(out)


def build_block(prev_le, height, ntime, tag=b"\x00"):
    """Return (full_block_bytes, stripped_block_bytes, hash_le)."""
    script_sig = bip34_push(height) + b"\x01" + tag[:1]
    nonce32 = b"\x00" * 32
    # coinbase-only block: witness root = merkle([0*32]) = 0*32
    commitment = sha256d(b"\x00" * 32 + nonce32)
    outs = [
        (50 * 100_000_000 >> (height // 150), b"\x51"),          # OP_TRUE
        (0, b"\x6a\x24\xaa\x21\xa9\xed" + commitment),
    ]
    vin = (b"\x00" * 32 + b"\xff\xff\xff\xff" + cs(len(script_sig)) + script_sig
           + b"\xff\xff\xff\xff")
    vout = b"".join(struct.pack("<q", v) + cs(len(s)) + s for v, s in outs)
    base = struct.pack("<i", 2) + cs(1) + vin + cs(len(outs)) + vout + b"\x00" * 4
    wit = struct.pack("<i", 2) + b"\x00\x01" + cs(1) + vin + cs(len(outs)) + vout \
        + cs(1) + cs(32) + nonce32 + b"\x00" * 4
    merkle = sha256d(base)
    hdr_wo_nonce = struct.pack("<i", 0x20000000) + prev_le + merkle + struct.pack(
        "<II", ntime, REGTEST_BITS)
    target = (0x7FFFFF) << (8 * (0x20 - 3))
    nonce = 0
    while True:
        hdr = hdr_wo_nonce + struct.pack("<I", nonce)
        h = sha256d(hdr)
        if int.from_bytes(h, "little") <= target:
            break
        nonce += 1
    return hdr + cs(1) + wit, hdr + cs(1) + base, h


def build_chain(n, start_time=None, tag=b"\x00", prev_le=REGTEST_GENESIS_LE,
                start_height=1):
    """n blocks on top of prev_le. Returns list of dicts (height, hash_le,
    full, stripped)."""
    t = start_time or (int(time.time()) - 600 * (n + 1))
    out = []
    for i in range(n):
        height = start_height + i
        full, stripped, h = build_block(prev_le, height, t + 60 * i, tag)
        out.append({"height": height, "hash_le": h, "hash": h[::-1].hex(),
                    "full": full, "stripped": stripped})
        prev_le = h
    return out


def msg(cmd, payload=b""):
    return (MAGIC + cmd.encode().ljust(12, b"\x00") + struct.pack("<I", len(payload))
            + sha256d(payload)[:4] + payload)


def version_payload(start_height):
    p = struct.pack("<iQq", PROTOCOL_VERSION, SERVICES, int(time.time()))
    p += struct.pack("<Q", SERVICES) + b"\x00" * 16 + struct.pack(">H", 0)
    p += struct.pack("<Q", SERVICES) + b"\x00" * 16 + struct.pack(">H", 0)
    p += struct.pack("<Q", int.from_bytes(os.urandom(8), "little"))
    ua = b"/lbrepro:0.1/"
    p += cs(len(ua)) + ua + struct.pack("<i", start_height) + b"\x01"
    return p


class MockPeer:
    """policy(hash_le) -> bytes to send as `block`, or None to stay silent."""

    def __init__(self, name, local_ip, port, chain, policy=None):
        self.name, self.local_ip, self.port = name, local_ip, port
        self.chain = chain                      # list of block dicts (best chain)
        self.by_hash = {b["hash_le"]: b for b in chain}
        self.policy = policy or (lambda b: b["full"])
        self.sock = None
        self.alive = False
        self.handshake = threading.Event()
        self.getdata = []                       # [(hash_hex, t)]
        self.served = []                        # [(hash_hex, kind)]
        self.disconnected_at = None
        self.lock = threading.Lock()
        self.revealed = len(chain)              # chain[:revealed] is served
        self.silent_headers = False             # answer getheaders with 0
        self.version_sent = False
        self.lsock = None

    def listen(self):
        """Outbound-from-the-node mode: listen on (local_ip, port); accept the
        node's dial in the background."""
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind((self.local_ip, self.port))
        ls.listen(4)
        self.lsock = ls

        def acc():
            try:
                while True:
                    s, _ = ls.accept()
                    if self.alive:
                        s.close()
                        continue
                    self.sock, self.alive = s, True
                    self.disconnected_at = None
                    self.handshake.clear()
                    self.version_sent = False
                    self.accepts = getattr(self, "accepts", 0) + 1
                    threading.Thread(target=self._reader, daemon=True).start()
            except OSError:
                pass
        threading.Thread(target=acc, daemon=True).start()

    def announce_header(self, b):
        return self.send("headers", cs(1) + b["full"][:80] + b"\x00")

    def connect(self, start_height=None):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.local_ip, 0))
        s.settimeout(10)
        s.connect(("127.0.0.1", self.port))
        s.settimeout(None)
        self.sock, self.alive = s, True
        threading.Thread(target=self._reader, daemon=True).start()
        self.send("version", version_payload(
            start_height if start_height is not None else len(self.chain)))
        return self.handshake.wait(15)

    def send(self, cmd, payload=b""):
        try:
            with self.lock:
                self.sock.sendall(msg(cmd, payload))
            return True
        except OSError:
            self.alive = False
            return False

    def announce_tip(self):
        tip = self.chain[-1]["hash_le"]
        return self.send("inv", cs(1) + struct.pack("<I", MSG_BLOCK) + tip)

    def close(self):
        self.alive = False
        if self.lsock is not None:
            try:
                self.lsock.close()
            except Exception:
                pass
        try:
            self.sock.close()
        except Exception:
            pass

    def _recv(self, n):
        buf = b""
        while len(buf) < n:
            c = self.sock.recv(n - len(buf))
            if not c:
                raise ConnectionError("eof")
            buf += c
        return buf

    def _headers_after(self, locator):
        idx = {b["hash_le"]: i for i, b in enumerate(self.chain)}
        start = 0
        for h in locator:
            if h in idx:
                start = idx[h] + 1
                break
            if h == REGTEST_GENESIS_LE or h == self.chain[0]["full"][4:36]:
                start = 0
                break
        if self.silent_headers:
            return cs(0)
        items = self.chain[start:min(start + 2000, self.revealed)]
        return cs(len(items)) + b"".join(b["full"][:80] + b"\x00" for b in items)

    def _reader(self):
        try:
            while self.alive:
                hdr = self._recv(24)
                cmd = hdr[4:16].rstrip(b"\x00").decode()
                ln = struct.unpack("<I", hdr[16:20])[0]
                pl = self._recv(ln) if ln else b""
                self._dispatch(cmd, pl)
        except Exception:
            pass
        finally:
            if self.alive or self.disconnected_at is None:
                self.disconnected_at = time.time()
            if self.alive:
                self.drops = getattr(self, "drops", []) + [time.time()]
            self.alive = False

    def _dispatch(self, cmd, pl):
        if cmd == "version":
            if not self.version_sent and self.lsock is not None:
                self.version_sent = True
                self.send("version", version_payload(self.revealed))
            self.send("verack")
        elif cmd == "verack":
            self.handshake.set()
        elif cmd == "ping":
            self.send("pong", pl[:8])
        elif cmd == "getheaders":
            p = 4
            n, p = read_cs(pl, p)
            loc = [pl[p + 32 * i:p + 32 * (i + 1)] for i in range(n)]
            self.send("headers", self._headers_after(loc))
        elif cmd == "getdata":
            n, p = read_cs(pl, 0)
            for _ in range(n):
                t = struct.unpack_from("<I", pl, p)[0]
                h = pl[p + 4:p + 36]
                p += 36
                if (t & ~MSG_WITNESS_FLAG) != MSG_BLOCK:
                    continue
                self.getdata.append((h[::-1].hex(), time.time()))
                b = self.by_hash.get(h)
                if b is None:
                    continue
                if self.revealed <= 0 or b["height"] > self.chain[self.revealed - 1]["height"]:
                    continue
                data = self.policy(b)
                if data is None:
                    continue
                self.served.append((b["hash"], "full" if data == b["full"] else "other"))
                self.send("block", data)


class RPC:
    def __init__(self, port, datadir):
        self.port, self.datadir = port, datadir

    def auth(self):
        for c in [os.path.join(self.datadir, ".cookie")] + sorted(
                glob.glob(os.path.join(self.datadir, "**", ".cookie"), recursive=True)):
            if os.path.exists(c):
                return open(c).read().strip()
        return None

    def call(self, method, *params, timeout=60):
        a = self.auth()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        hdr = {"Content-Type": "application/json"}
        if a:
            hdr["Authorization"] = "Basic " + base64.b64encode(a.encode()).decode()
        conn.request("POST", "/", json.dumps(
            {"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}), hdr)
        r = json.loads(conn.getresponse().read())
        conn.close()
        if r.get("error"):
            raise RuntimeError(f"{method}: {r['error']}")
        return r["result"]


def port_free(p):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", p))
        return True
    except OSError:
        return False
    finally:
        s.close()


class Node:
    def __init__(self, root, datadir, p2p, rpc, extra=None, logname="node.log",
                 clock_rate=None):
        self.root, self.datadir, self.p2p, self.rpcport = root, datadir, p2p, rpc
        self.clock_rate = clock_rate
        self.extra = extra or []
        self.logpath = os.path.join(datadir, logname)
        self.proc = None
        self.rpc = RPC(rpc, datadir)

    def start(self, timeout=90):
        for p in (self.p2p, self.rpcport):
            if not port_free(p):
                raise SystemExit(f"ABORT: port {p} busy")
        os.makedirs(self.datadir, exist_ok=True)
        env = dict(os.environ)
        env["LUA_PATH"] = f"{self.root}/?.lua;{self.root}/?/init.lua;" + env.get("LUA_PATH", ";;")
        pre = []
        if self.clock_rate:
            # Clock seam: wall time (socket.gettime / os.time) runs clock_rate x
            # faster inside the node.  Nothing in the node's timers can tell.
            pre = ["-e", (
                "local s=require('socket'); local real=s.gettime; local t0=real(); "
                f"local K={float(self.clock_rate)}; "
                "s.gettime=function() return t0+(real()-t0)*K end; "
                "local ot=os.time; os.time=function(t) if t then return ot(t) end "
                "return math.floor(s.gettime()) end")]
        cmd = ["luajit"] + pre + ["src/main.lua", "--network", "regtest",
               "--datadir", self.datadir,
               "--port", str(self.p2p), "--rpcport", str(self.rpcport),
               "--bind", f"127.0.0.1:{self.p2p}", "--nov2transport", "--metricsport", "0",
               "--nowalletcreate"] + self.extra
        self.logf = open(self.logpath, "a")
        self.proc = subprocess.Popen(cmd, cwd=self.root, stdout=self.logf,
                                     stderr=subprocess.STDOUT, env=env,
                                     preexec_fn=os.setsid)
        t0 = time.time()
        while time.time() - t0 < timeout:
            if self.proc.poll() is not None:
                raise RuntimeError(f"node exited rc={self.proc.returncode}; see {self.logpath}")
            try:
                self.rpc.call("getblockcount", timeout=5)
                return True
            except Exception:
                time.sleep(0.5)
        raise RuntimeError("node RPC never came up")

    def stop(self):
        if not self.proc:
            return
        try:
            self.rpc.call("stop", timeout=5)
        except Exception:
            pass
        try:
            self.proc.wait(20)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.proc.wait(10)
        self.proc = None

    def log_count(self, needle):
        try:
            with open(self.logpath, errors="replace") as f:
                return sum(1 for line in f if needle in line)
        except OSError:
            return 0
