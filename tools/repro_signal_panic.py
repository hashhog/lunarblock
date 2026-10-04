#!/usr/bin/env python3
"""Regtest repro: SIGTERM aborts lunarblock with a LuaJIT 'bad callback' PANIC,
and an addrv2 getaddr reply raises on a cdata services field.

Mainnet 2026-09-26..10-04: every operator stop (stop_mainnet.sh, systemctl
stop) of a busy node printed
    PANIC: unprotected error in call to Lua API (bad callback)
and exited 1 without a flush.  The SIGTERM handler was an FFI callback; a
callback entered while the VM runs a compiled trace aborts in
lj_ccallback_enter.  Separately, 1,076 inbound getaddr requests raised
`serialize.lua:19: bad argument #1 to 'floor' (number expected, got cdata)`.

Layout (regtest, scratch datadirs under --workdir, ports --base-port..+3):
  Core (wallet) <--P2P-- lunarblock (--connect Core) <--P2P-- python peers

Scenarios (each runs --trials times, counts PANIC lines and exit codes):
  sync     fresh datadir, SIGTERM 1-6 s into the block download
  walk     synced datadir copy, SIGTERM while gettxoutsetinfo is walking
  busy     synced datadir copy, SIGTERM while RPC getblock calls keep the
           loop hot
  idle     synced datadir copy, SIGTERM with nothing to do (control)
  getaddr  8 inbound peers each add one addr (services 0x409); a 9th sends
           sendaddrv2 + getaddr WITH a junk payload; expect an addrv2 reply
           and no 'handler "getaddr" raised' line

Usage: repro_signal_panic.py --lunarblock-dir DIR --workdir DIR
           [--scenarios sync,walk,busy,idle,getaddr] [--trials 5]
Exit 0 = no PANIC, every stop exited 0, getaddr answered; 1 otherwise.
"""
import argparse, base64, hashlib, http.client, json, os, random, shutil, signal
import socket, struct, subprocess, sys, threading, time

MAGIC = bytes.fromhex("fabfb5da")


def log(*a):
    print(f"[{time.strftime('%H:%M:%S')}]", *a, flush=True)


class RPC:
    def __init__(self, port, cookie=None, timeout=300):
        self.port, self.cookie, self.timeout = port, cookie, timeout

    def call(self, method, *params, timeout=None, wallet=None):
        hdr = {"Content-Type": "application/json"}
        if self.cookie:
            auth = open(self.cookie).read().strip()
            hdr["Authorization"] = "Basic " + base64.b64encode(auth.encode()).decode()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout or self.timeout)
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)})
        conn.request("POST", f"/wallet/{wallet}" if wallet else "/", body, hdr)
        r = json.loads(conn.getresponse().read())
        conn.close()
        if r.get("error"):
            raise RuntimeError(f"{method}: {r['error']}")
        return r["result"]


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


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def msg(cmd, payload=b""):
    return (MAGIC + cmd.encode().ljust(12, b"\0") + struct.pack("<I", len(payload))
            + dsha(payload)[:4] + payload)


def netaddr(port):
    return struct.pack("<Q", 9) + b"\0" * 10 + b"\xff\xff" + bytes([127, 0, 0, 1]) + struct.pack(">H", port)


class MiniPeer:
    """Inbound test peer: version/verack handshake, optional sendaddrv2."""

    def __init__(self, port, addrv2=False):
        try:
            self.s = socket.create_connection(("127.0.0.1", port), timeout=10)
        except ConnectionRefusedError:   # listener may be [::] only
            self.s = socket.create_connection(("::1", port), timeout=10)
        self.buf = b""
        self.msgs = []
        ua = b"/repro:0.1/"
        ver = (struct.pack("<iQq", 70016, 0x409, int(time.time())) + netaddr(port) + netaddr(0)
               + struct.pack("<Q", random.getrandbits(64)) + bytes([len(ua)]) + ua
               + struct.pack("<i", 0) + b"\x00")
        self.s.sendall(msg("version", ver))
        got_version = got_verack = False
        t0 = time.time()
        while not (got_version and got_verack) and time.time() - t0 < 20:
            for cmd, pl in self.pump(0.2):
                if cmd == "version":
                    got_version = True
                    self.s.sendall((msg("sendaddrv2") if addrv2 else b"") + msg("verack"))
                elif cmd == "verack":
                    got_verack = True
        if not (got_version and got_verack):
            raise RuntimeError("handshake failed")

    def pump(self, wait):
        out = []
        self.s.settimeout(wait)
        try:
            d = self.s.recv(1 << 20)
            if not d:
                raise ConnectionError("closed by lunarblock")
            self.buf += d
        except socket.timeout:
            pass
        while len(self.buf) >= 24:
            ln = struct.unpack("<I", self.buf[16:20])[0]
            if len(self.buf) < 24 + ln:
                break
            cmd = self.buf[4:16].rstrip(b"\0").decode()
            pl = self.buf[24:24 + ln]
            self.buf = self.buf[24 + ln:]
            if cmd == "ping":
                self.s.sendall(msg("pong", pl))
            out.append((cmd, pl))
            self.msgs.append(cmd)
        return out

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


class Run:
    def __init__(self, a):
        self.a = a
        self.cp, self.cr, self.lp, self.lr = (a.base_port + i for i in range(4))
        self.cdir = os.path.join(a.workdir, "core")
        self.template = os.path.join(a.workdir, "lb-template")
        self.procs = []
        self.lb_procs = []
        self.rows = []

    def start_core(self):
        os.makedirs(self.cdir, exist_ok=True)
        core = subprocess.Popen([self.a.bitcoind, "-regtest", f"-datadir={self.cdir}", f"-port={self.cp}",
                                 f"-rpcport={self.cr}", "-listen=1", "-bind=127.0.0.1", "-fallbackfee=0.0002",
                                 "-dnsseed=0", "-fixedseeds=0", "-printtoconsole=0"])
        self.procs.append(core)
        self.crpc = RPC(self.cr, cookie=os.path.join(self.cdir, "regtest", ".cookie"))
        assert wait_for(lambda: os.path.exists(self.crpc.cookie) and self.crpc.call("getblockcount") >= 0, 60)
        if self.crpc.call("getblockcount") < self.a.blocks:
            try:
                self.crpc.call("createwallet", "w")
            except RuntimeError:
                self.crpc.call("loadwallet", "w")
            addr = self.crpc.call("getnewaddress", "", "bech32", wallet="w")
            self.crpc.call("generatetoaddress", self.a.blocks - 1, addr, timeout=1800)
            # Fan out UTXOs so a gettxoutsetinfo walk has work to do.
            for _ in range(self.a.fanout // 500):
                outs = {self.crpc.call("getnewaddress", "", "bech32", wallet="w"): 0.001 for _ in range(500)}
                self.crpc.call("sendmany", "", outs, wallet="w")
            self.crpc.call("generatetoaddress", 1, addr, timeout=120)
        self.tip = self.crpc.call("getblockcount")
        log(f"core: height {self.tip}")

    def start_lb(self, datadir, logname):
        env = dict(os.environ)
        env["LD_LIBRARY_PATH"] = os.path.join(self.a.lunarblock_dir, "lib")
        lf = open(os.path.join(self.a.workdir, logname), "w")
        p = subprocess.Popen(["luajit", "src/main.lua", "--regtest", "--datadir", datadir,
                              "--port", str(self.lp), "--rpcport", str(self.lr), "--metricsport", "0",
                              "--nov2transport", "--nowalletcreate",
                              "--connect", f"127.0.0.1:{self.cp}"],
                             cwd=self.a.lunarblock_dir, env=env, stdout=lf, stderr=subprocess.STDOUT)
        self.lb_procs.append(p)
        return p, os.path.join(self.a.workdir, logname)

    def wait_main_loop(self, logpath, p, timeout=180):
        def ready():
            if p.poll() is not None:
                raise RuntimeError("exited early")
            return "Entering main loop" in open(logpath, errors="replace").read()
        return wait_for(ready, timeout, 0.2)

    def stop(self, p, logpath, scenario, trial, note=""):
        t0 = time.time()
        p.send_signal(signal.SIGTERM)
        try:
            rc = p.wait(timeout=self.a.grace)
        except subprocess.TimeoutExpired:
            p.kill()
            rc = "KILLED(grace)"
        dt = time.time() - t0
        text = open(logpath, errors="replace").read()
        panics = text.count("PANIC: unprotected")
        clean = "[signal] SIGTERM received" in text
        row = dict(scenario=scenario, trial=trial, rc=rc, secs=round(dt, 1), panics=panics,
                   sigterm_logged=clean, note=note)
        self.rows.append(row)
        log(f"{scenario} #{trial}: rc={rc} stop={dt:.1f}s PANIC={panics} sigterm_logged={clean} {note}")
        return row

    def make_template(self):
        if os.path.isdir(self.template) and os.path.exists(self.template + ".synced"):
            return
        shutil.rmtree(self.template, ignore_errors=True)
        p, lp = self.start_lb(self.template, "template.log")
        lrpc = RPC(self.lr, timeout=30)
        def synced():
            if p.poll() is not None:
                raise SystemExit(f"template node exited rc={p.returncode}; see {lp}")
            return lrpc.call("getblockcount", timeout=10) == self.tip
        ok = wait_for(synced, 1800, 2)
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(timeout=self.a.grace)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
        if not ok:
            raise RuntimeError("template sync did not reach Core's tip")
        open(self.template + ".synced", "w").close()
        log("template synced")

    def copy_template(self, name):
        d = os.path.join(self.a.workdir, name)
        shutil.rmtree(d, ignore_errors=True)
        shutil.copytree(self.template, d)
        return d

    # ---------------------------------------------------------------- scenarios
    def sc_sync(self, i):
        d = os.path.join(self.a.workdir, f"sync-{i}")
        shutil.rmtree(d, ignore_errors=True)
        p, lp = self.start_lb(d, f"sync-{i}.log")
        if not self.wait_main_loop(lp, p):
            p.kill(); return
        delay = random.uniform(1, 6)
        time.sleep(delay)
        conn = open(lp, errors="replace").read().count("Connected block")
        self.stop(p, lp, "sync", i, f"delay={delay:.1f}s")

    def sc_walk(self, i):
        d = self.copy_template(f"walk-{i}")
        p, lp = self.start_lb(d, f"walk-{i}.log")
        if not self.wait_main_loop(lp, p):
            p.kill(); return
        lrpc = RPC(self.lr, timeout=120)
        st = {"done": 0, "durations": [], "inflight": False, "stop": False}

        def walker():
            # Back-to-back walks so one is almost always in flight at SIGTERM.
            while not st["stop"]:
                st["inflight"] = True
                t = time.time()
                try:
                    lrpc.call("gettxoutsetinfo", timeout=120)
                    st["durations"].append(time.time() - t)
                    st["done"] += 1
                except Exception:
                    st["inflight"] = False
                    return
                st["inflight"] = False
        th = threading.Thread(target=walker, daemon=True)
        th.start()
        delay = random.uniform(1.0, 3.0)
        time.sleep(delay)
        walking = st["inflight"]
        st["stop"] = True
        dur = (sum(st["durations"]) / len(st["durations"])) if st["durations"] else float("nan")
        self.stop(p, lp, "walk", i, f"delay={delay:.1f}s walk_in_flight={walking} "
                  f"walks_done={st['done']} walk_avg={dur:.2f}s")
        th.join(5)

    def sc_busy(self, i):
        d = self.copy_template(f"busy-{i}")
        p, lp = self.start_lb(d, f"busy-{i}.log")
        if not self.wait_main_loop(lp, p):
            p.kill(); return
        lrpc = RPC(self.lr, timeout=10)
        stop = threading.Event()

        def hammer():
            while not stop.is_set():
                try:
                    h = random.randint(0, self.tip)
                    lrpc.call("getblock", lrpc.call("getblockhash", h), 2)
                except Exception:
                    time.sleep(0.05)
        ths = [threading.Thread(target=hammer, daemon=True) for _ in range(2)]
        for t in ths:
            t.start()
        delay = random.uniform(1, 3)
        time.sleep(delay)
        self.stop(p, lp, "busy", i, f"delay={delay:.1f}s")
        stop.set()

    def sc_idle(self, i):
        d = self.copy_template(f"idle-{i}")
        p, lp = self.start_lb(d, f"idle-{i}.log")
        if not self.wait_main_loop(lp, p):
            p.kill(); return
        time.sleep(random.uniform(2, 4))
        self.stop(p, lp, "idle", i)

    def sc_getaddr(self, i):
        d = self.copy_template(f"getaddr-{i}")
        p, lp = self.start_lb(d, f"getaddr-{i}.log")
        if not self.wait_main_loop(lp, p):
            p.kill(); return
        feeders = []
        now = int(time.time())
        for k in range(8):
            mp = MiniPeer(self.lp)
            ip = bytes([23, 10 + i, 20 + k, 7])
            entry = (struct.pack("<I", now) + struct.pack("<Q", 0x409) + b"\0" * 10 + b"\xff\xff" + ip
                     + struct.pack(">H", 8333))
            mp.s.sendall(msg("addr", b"\x01" + entry))
            mp.pump(0.3)
            feeders.append(mp)
        time.sleep(1.0)
        asker = MiniPeer(self.lp, addrv2=True)
        asker.s.sendall(msg("getaddr", b"\x00\x01junk-payload"))
        reply, closed = None, False
        t0 = time.time()
        while time.time() - t0 < 8 and reply is None:
            try:
                for cmd, pl in asker.pump(0.3):
                    if cmd in ("addr", "addrv2"):
                        reply = (cmd, pl[0] if pl else 0)
            except (ConnectionError, OSError):
                closed = True
                break
        for mp in feeders + [asker]:
            mp.close()
        raised = open(lp, errors="replace").read().count('handler "getaddr" raised')
        row = self.stop(p, lp, "getaddr", i,
                        f"reply={reply} closed={closed} getaddr_raised={raised}")
        row["getaddr_ok"] = reply is not None and raised == 0

    def run(self):
        self.start_core()
        scen = self.a.scenarios.split(",")
        if any(s != "sync" for s in scen):
            self.make_template()
        for s in scen:
            for i in range(1, self.a.trials + 1):
                getattr(self, "sc_" + s)(i)
        bad = [r for r in self.rows if r["panics"] or r["rc"] != 0 or r.get("getaddr_ok") is False]
        log(f"SUMMARY: {len(self.rows)} stops, {sum(r['panics'] for r in self.rows)} PANIC, "
            f"{sum(1 for r in self.rows if r['rc'] != 0)} non-zero exits, "
            f"{sum(1 for r in self.rows if r.get('getaddr_ok') is False)} failed getaddr")
        with open(os.path.join(self.a.workdir, "rows.json"), "w") as f:
            json.dump(self.rows, f, indent=1)
        return 1 if bad else 0

    def cleanup(self):
        for p in self.lb_procs:          # never leave a node holding the ports
            if p.poll() is None:
                p.kill()
                p.wait()
        for p in self.procs:
            try:
                p.send_signal(signal.SIGTERM)
                p.wait(timeout=60)
            except Exception:
                p.kill()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lunarblock-dir", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--bitcoind", default="/home/work/hashhog/bitcoin-core/build-wallet/bin/bitcoind")
    ap.add_argument("--scenarios", default="sync,walk,busy,idle,getaddr")
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--blocks", type=int, default=1500)
    ap.add_argument("--fanout", type=int, default=20000)
    ap.add_argument("--grace", type=int, default=120)
    ap.add_argument("--base-port", type=int, default=37410)
    ap.add_argument("--seed", type=int, default=4242)
    a = ap.parse_args()
    random.seed(a.seed)
    os.makedirs(a.workdir, exist_ok=True)
    r = Run(a)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(3))
    try:
        return r.run()
    finally:
        r.cleanup()


if __name__ == "__main__":
    sys.exit(main())
