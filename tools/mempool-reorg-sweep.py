#!/usr/bin/env python3
"""Regtest sweep: lunarblock vs Bitcoin Core v31.1 mempool reorg refill.

Mines on bitcoind, submits the same blocks and raw transactions to both
nodes, then compares invalidate / reconsider / submitblock, getrawmempool,
and getblocktemplate tx order and BIP-22 depends. Does not dial any peer.
"""

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from decimal import Decimal

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BITCOIND = os.environ.get(
    "BITCOIND", "/tmp/bitcoincore/bitcoin-31.1/bin/bitcoind")
BITCOIN_CLI = os.environ.get(
    "BITCOIN_CLI", "/tmp/bitcoincore/bitcoin-31.1/bin/bitcoin-cli")
LUAJIT = os.environ.get("LUAJIT", "luajit")

USER = "sweep"
PASS = "sweep"
CORE_RPC = 18743
LB_RPC = 18745
CORE_DIR = "/tmp/lb-sweep-core"
LB_DIR = "/tmp/lb-sweep-lb"

MISMATCHES = []
MATCHED = []


def note_match(label):
    MATCHED.append(label)
    print("MATCH", label, flush=True)


def note_mismatch(label, core, lunar):
    MISMATCHES.append((label, core, lunar))
    print("MISMATCH", label, flush=True)
    print("  core: ", json.dumps(core, sort_keys=True)[:2000], flush=True)
    print("  lunar:", json.dumps(lunar, sort_keys=True)[:2000], flush=True)


class RPC:
    def __init__(self, url):
        self.url = url

    def call(self, method, params=None):
        body = json.dumps({
            "jsonrpc": "1.0", "id": "sweep",
            "method": method, "params": params or [],
        }).encode()
        req = urllib.request.Request(self.url, data=body)
        token = __import__("base64").b64encode(
            f"{USER}:{PASS}".encode()).decode()
        req.add_header("Authorization", "Basic " + token)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            payload = exc.read().decode()
            try:
                out = json.loads(payload)
            except json.JSONDecodeError:
                raise RuntimeError(f"{method} HTTP {exc.code}: {payload}") from exc
            err = out.get("error")
            raise RuntimeError(f"{method}: {err}") from exc
        try:
            out = json.loads(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            preview = raw.decode("latin-1")[:400]
            raise RuntimeError(
                f"{method}: response is not UTF-8 JSON ({exc}); preview {preview!r}"
            ) from exc
        if out.get("error"):
            raise RuntimeError(f"{method}: {out['error']}")
        return out.get("result")


def log_tail(path, n=30):
    try:
        with open(path, errors="replace") as fh:
            lines = fh.readlines()
    except OSError as exc:
        return f"(no log {path}: {exc})"
    return "".join(lines[-n:])


def wait_rpc(rpc, seconds=60, proc=None, log_path=None):
    deadline = time.time() + seconds
    last = None
    while time.time() < deadline:
        if proc is not None and proc.poll() is not None:
            tail = log_tail(log_path) if log_path else ""
            raise RuntimeError(
                f"process exited {proc.returncode} before RPC was up\n{tail}")
        try:
            rpc.call("getblockcount")
            return
        except Exception as exc:  # noqa: BLE001 — startup race
            last = exc
            time.sleep(0.3)
    tail = log_tail(log_path) if log_path else ""
    raise RuntimeError(f"RPC not up: {last}\n{tail}")


def bcli(datadir, *args, wallet=None):
    cmd = [BITCOIN_CLI, "-regtest", f"-datadir={datadir}",
           f"-rpcport={CORE_RPC}", f"-rpcuser={USER}", f"-rpcpassword={PASS}"]
    if wallet:
        cmd.append(f"-rpcwallet={wallet}")
    cmd.extend(args)
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"bitcoin-cli {' '.join(args)} failed: {proc.stderr.strip() or proc.stdout}")
    return proc.stdout.strip()


def sats_to_btc(sats):
    return format(Decimal(sats) / Decimal(100000000), "f")


def start_pair(tag):
    core_dir = f"{CORE_DIR}-{tag}"
    lb_dir = f"{LB_DIR}-{tag}"
    shutil.rmtree(core_dir, ignore_errors=True)
    shutil.rmtree(lb_dir, ignore_errors=True)
    os.makedirs(core_dir, exist_ok=True)
    os.makedirs(lb_dir, exist_ok=True)
    core_log = open(f"{core_dir}/bitcoind.log", "w")
    lb_log = open(f"{lb_dir}/lunarblock.log", "w")
    core = subprocess.Popen(
        [BITCOIND, "-regtest", f"-datadir={core_dir}",
         f"-rpcport={CORE_RPC}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
         f"-rpcuser={USER}", f"-rpcpassword={PASS}",
         "-listen=0", "-dnsseed=0", "-connect=0", "-txindex=0"],
        stdout=core_log, stderr=subprocess.STDOUT)
    env = os.environ.copy()
    env["LUA_PATH"] = f"{ROOT}/?.lua;{ROOT}/?/init.lua;;"
    lib = os.path.join(ROOT, "lib")
    env["LD_LIBRARY_PATH"] = lib + os.pathsep + env.get("LD_LIBRARY_PATH", "")
    lunar = subprocess.Popen(
        [LUAJIT, os.path.join(ROOT, "src/main.lua"),
         "--regtest", "--datadir", lb_dir,
         "--port", "18746", "--rpcport", str(LB_RPC),
         "--rpcuser", USER, "--rpcpassword", PASS,
         "--bind", "127.0.0.1:18746", "--metricsport", "0",
         "--nov2transport", "--nowalletcreate", "--printtoconsole"],
        stdout=lb_log, stderr=subprocess.STDOUT, cwd=ROOT, env=env)
    core_rpc = RPC(f"http://127.0.0.1:{CORE_RPC}")
    lb_rpc = RPC(f"http://127.0.0.1:{LB_RPC}")
    try:
        wait_rpc(core_rpc, proc=core, log_path=f"{core_dir}/bitcoind.log")
        wait_rpc(lb_rpc, seconds=90, proc=lunar, log_path=f"{lb_dir}/lunarblock.log")
    except Exception:
        stop(core, lunar)
        raise
    bcli(core_dir, "createwallet", tag)
    return core, lunar, core_rpc, lb_rpc, core_dir, tag


def stop(core, lunar):
    if lunar and lunar.poll() is None:
        lunar.terminate()
    if core and core.poll() is None:
        try:
            subprocess.run(
                [BITCOIN_CLI, "-regtest", f"-rpcport={CORE_RPC}",
                 f"-rpcuser={USER}", f"-rpcpassword={PASS}", "stop"],
                text=True, capture_output=True, timeout=20)
        except Exception:
            core.terminate()
    if lunar:
        try:
            lunar.wait(timeout=15)
        except subprocess.TimeoutExpired:
            lunar.kill()
    if core:
        try:
            core.wait(timeout=20)
        except subprocess.TimeoutExpired:
            core.kill()


def sync_chain(core_rpc, lb_rpc):
    tip = core_rpc.call("getblockcount")
    for h in range(1, tip + 1):
        blkhash = core_rpc.call("getblockhash", [h])
        raw = core_rpc.call("getblock", [blkhash, 0])
        result = lb_rpc.call("submitblock", [raw])
        if result not in (None, "duplicate"):
            raise RuntimeError(f"submitblock h={h} -> {result}")
    c_tip = core_rpc.call("getbestblockhash")
    l_tip = lb_rpc.call("getbestblockhash")
    if c_tip != l_tip:
        raise RuntimeError(f"tips diverged after sync {c_tip} vs {l_tip}")
    note_match(f"synced tip height {tip} hash {c_tip}")
    return tip


def send_both(core_rpc, lb_rpc, hex_tx):
    c_txid = core_rpc.call("sendrawtransaction", [hex_tx])
    l_txid = lb_rpc.call("sendrawtransaction", [hex_tx])
    if c_txid != l_txid:
        raise RuntimeError(f"sendrawtransaction txid {c_txid} vs {l_txid}")
    return c_txid


def make_spend(datadir, txid, vout, value_sats, fee_sats, address, wallet):
    out_sats = value_sats - fee_sats
    if out_sats <= 0:
        raise RuntimeError("fee exceeds input")
    raw = bcli(
        datadir, "createrawtransaction",
        json.dumps([{"txid": txid, "vout": vout}]),
        json.dumps({address: sats_to_btc(out_sats)}),
        wallet=wallet)
    signed = json.loads(bcli(
        datadir, "signrawtransactionwithwallet", raw, wallet=wallet))
    if not signed.get("complete"):
        raise RuntimeError(f"sign failed: {signed}")
    return signed["hex"]


def gbt(rpc):
    return rpc.call("getblocktemplate", [{"rules": ["segwit"]}])


def cmp_gbt(label, core_rpc, lb_rpc):
    c = gbt(core_rpc)
    l = gbt(lb_rpc)
    ct = c.get("transactions") or []
    lt = l.get("transactions") or []
    c_order = [t.get("txid") for t in ct]
    l_order = [t.get("txid") for t in lt]
    if c_order == l_order:
        note_match(f"{label} gbt tx order ({len(c_order)} txs)")
    else:
        note_mismatch(f"{label} gbt tx order", c_order, l_order)
    c_dep = [t.get("depends") for t in ct]
    l_dep = [t.get("depends") for t in lt]
    # Coinbase is not in the list; depends are 1-based into this list.
    if c_dep == l_dep:
        note_match(f"{label} gbt depends {c_dep}")
    else:
        note_mismatch(f"{label} gbt depends", c_dep, l_dep)
    n = min(len(ct), len(lt))
    for i in range(n):
        for field in ("fee", "weight"):
            if ct[i].get(field) != lt[i].get(field):
                note_mismatch(
                    f"{label} gbt tx[{i}] {field} txid={c_order[i] if i < len(c_order) else '?'}",
                    ct[i].get(field), lt[i].get(field))
    return c_order, c_dep


def norm_list(value):
    if value is None:
        return []
    if isinstance(value, dict) and not value:
        return []
    return value


def cmp_mempool(label, core_rpc, lb_rpc, expect_txids=None):
    c_ids = sorted(core_rpc.call("getrawmempool", [False]) or [])
    l_ids = sorted(lb_rpc.call("getrawmempool", [False]) or [])
    if c_ids == l_ids:
        note_match(f"{label} getrawmempool set {c_ids}")
    else:
        note_mismatch(f"{label} getrawmempool set", c_ids, l_ids)
    if expect_txids is not None:
        exp = sorted(expect_txids)
        if c_ids != exp:
            note_mismatch(f"{label} core mempool vs expected", c_ids, exp)
        else:
            note_match(f"{label} core mempool matches expected roles")
    try:
        c_v = core_rpc.call("getrawmempool", [True]) or {}
        l_v = lb_rpc.call("getrawmempool", [True]) or {}
    except RuntimeError as exc:
        note_mismatch(f"{label} getrawmempool verbose", "valid JSON object", str(exc))
        return c_ids
    skip = {"time"}
    for txid in sorted(set(c_v) | set(l_v)):
        cv = c_v.get(txid)
        lv = l_v.get(txid)
        if cv is None or lv is None:
            continue
        fields = sorted((set(cv) | set(lv)) - skip)
        for field in fields:
            a = cv.get(field, "<missing>")
            b = lv.get(field, "<missing>")
            if field in ("depends", "spentby"):
                a = norm_list(a)
                b = norm_list(b)
            if a != b:
                note_mismatch(f"{label} getrawmempool[{txid[:12]}] {field}", a, b)
    return c_ids


def cmp_result(label, core_val, lunar_val):
    if core_val == lunar_val:
        note_match(f"{label} {core_val!r}")
    else:
        note_mismatch(label, core_val, lunar_val)


def cmp_tip(label, core_rpc, lb_rpc):
    ch = core_rpc.call("getblockcount")
    lh = lb_rpc.call("getblockcount")
    c_hash = core_rpc.call("getbestblockhash")
    l_hash = lb_rpc.call("getbestblockhash")
    if ch == lh and c_hash == l_hash:
        note_match(f"{label} tip h={ch} {c_hash}")
    else:
        note_mismatch(f"{label} tip", {"height": ch, "hash": c_hash},
                      {"height": lh, "hash": l_hash})


def scenario_cpfp():
    print("\n=== low-feerate parent + high-feerate child ===")
    core, lunar, core_rpc, lb_rpc, core_dir, wallet = start_pair("cpfp")
    try:
        addr = bcli(core_dir, "getnewaddress", "", "bech32", wallet=wallet)
        bcli(core_dir, "generatetoaddress", "101", addr, wallet=wallet)
        sync_chain(core_rpc, lb_rpc)
        utxos = json.loads(bcli(
            core_dir, "listunspent", "100", "9999999", wallet=wallet))
        utxo = next(u for u in utxos if Decimal(str(u["amount"])) >= Decimal("1"))
        value = int((Decimal(str(utxo["amount"])) * Decimal(100000000)).to_integral_value())
        # ~2 sat/vB on a p2wpkh spend: above min relay, well below the child.
        parent_fee = 220
        parent_hex = make_spend(
            core_dir, utxo["txid"], utxo["vout"], value, parent_fee, addr, wallet)
        parent = send_both(core_rpc, lb_rpc, parent_hex)
        # Child spends the parent's only output.
        child_value = value - parent_fee
        child_fee = 200000
        child_hex = make_spend(
            core_dir, parent, 0, child_value, child_fee, addr, wallet)
        child = send_both(core_rpc, lb_rpc, child_hex)
        print(f"parent {parent} fee {parent_fee}; child {child} fee {child_fee}")
        cmp_mempool("cpfp mempool", core_rpc, lb_rpc, [parent, child])
        cmp_gbt("cpfp before mine", core_rpc, lb_rpc)

        mined = json.loads(bcli(
            core_dir, "generatetoaddress", "1", addr, wallet=wallet))[0]
        blk = core_rpc.call("getblock", [mined, 1])
        txids = blk["tx"]
        if parent not in txids or child not in txids:
            raise RuntimeError(f"block did not include parent+child: {txids}")
        raw = core_rpc.call("getblock", [mined, 0])
        sb = lb_rpc.call("submitblock", [raw])
        cmp_result("submitblock mined cpfp block", None, sb)
        cmp_tip("after cpfp mine", core_rpc, lb_rpc)

        c_inv = core_rpc.call("invalidateblock", [mined])
        l_inv = lb_rpc.call("invalidateblock", [mined])
        cmp_result("invalidateblock result", c_inv, l_inv)
        cmp_tip("after invalidate cpfp", core_rpc, lb_rpc)
        cmp_mempool("after invalidate cpfp", core_rpc, lb_rpc, [parent, child])
        cmp_gbt("after invalidate cpfp", core_rpc, lb_rpc)

        c_sub = core_rpc.call("submitblock", [raw])
        l_sub = lb_rpc.call("submitblock", [raw])
        cmp_result("submitblock of invalidated block", c_sub, l_sub)
        cmp_tip("after resubmit invalidated", core_rpc, lb_rpc)

        c_re = core_rpc.call("reconsiderblock", [mined])
        l_re = lb_rpc.call("reconsiderblock", [mined])
        cmp_result("reconsiderblock result", c_re, l_re)
        cmp_tip("after reconsider", core_rpc, lb_rpc)
        cmp_mempool("after reconsider", core_rpc, lb_rpc)
    finally:
        stop(core, lunar)


def scenario_cluster():
    print("\n=== parent + 64 in-pool children ===")
    core, lunar, core_rpc, lb_rpc, core_dir, wallet = start_pair("cluster")
    try:
        addr = bcli(core_dir, "getnewaddress", "", "bech32", wallet=wallet)
        bcli(core_dir, "generatetoaddress", "101", addr, wallet=wallet)
        sync_chain(core_rpc, lb_rpc)
        utxos = json.loads(bcli(
            core_dir, "listunspent", "100", "9999999", wallet=wallet))
        utxo = next(u for u in utxos if Decimal(str(u["amount"])) >= Decimal("1"))
        value = int((Decimal(str(utxo["amount"])) * Decimal(100000000)).to_integral_value())
        n = 64
        parent_fee = 10000
        each = (value - parent_fee) // n
        # One address per output: createrawtransaction's output map cannot
        # repeat a key, and each child must spend a distinct vout.
        addrs = [
            bcli(core_dir, "getnewaddress", "", "bech32", wallet=wallet)
            for _ in range(n)
        ]
        rem = (value - parent_fee) - each * n
        outputs = {
            addrs[i]: sats_to_btc(each + (rem if i == 0 else 0))
            for i in range(n)
        }
        raw = bcli(
            core_dir, "createrawtransaction",
            json.dumps([{"txid": utxo["txid"], "vout": utxo["vout"]}]),
            json.dumps(outputs),
            wallet=wallet)
        signed = json.loads(bcli(
            core_dir, "signrawtransactionwithwallet", raw, wallet=wallet))
        if not signed.get("complete"):
            raise RuntimeError(f"parent sign failed: {signed}")
        parent = send_both(core_rpc, lb_rpc, signed["hex"])
        mined = json.loads(bcli(
            core_dir, "generatetoaddress", "1", addr, wallet=wallet))[0]
        blk = core_rpc.call("getblock", [mined, 1])
        if parent not in blk["tx"]:
            raise RuntimeError("parent was not mined")
        raw_blk = core_rpc.call("getblock", [mined, 0])
        sb = lb_rpc.call("submitblock", [raw_blk])
        if sb not in (None, "duplicate"):
            raise RuntimeError(f"submit parent block -> {sb}")
        cmp_tip("parent confirmed", core_rpc, lb_rpc)

        # vout 0 carries the remainder; fees stay well under the output value.
        children = []
        for i in range(n):
            fee = (i + 1) * 1000  # i=0 is the lowest feerate
            out_value = (each + rem) if i == 0 else each
            hex_tx = make_spend(
                core_dir, parent, i, out_value, fee, addr, wallet)
            children.append(send_both(core_rpc, lb_rpc, hex_tx))
        print(f"parent {parent}")
        print(f"lowest-fee child {children[0]} highest-fee child {children[-1]}")
        cmp_mempool("64 children before invalidate", core_rpc, lb_rpc, children)

        c_inv = core_rpc.call("invalidateblock", [mined])
        l_inv = lb_rpc.call("invalidateblock", [mined])
        cmp_result("invalidateblock parent-block result", c_inv, l_inv)
        cmp_tip("after invalidate parent block", core_rpc, lb_rpc)
        # Core Trim keeps the parent and the 63 highest-feerate children.
        kept = [parent] + children[1:]
        cmp_mempool("64-child refill", core_rpc, lb_rpc, kept)
        cmp_gbt("64-child refill", core_rpc, lb_rpc)

        c_sub = core_rpc.call("submitblock", [raw_blk])
        l_sub = lb_rpc.call("submitblock", [raw_blk])
        cmp_result("submitblock invalidated parent block", c_sub, l_sub)
    finally:
        stop(core, lunar)


def main():
    scenario_cpfp()
    scenario_cluster()
    print("\n=== summary ===")
    print(f"matched {len(MATCHED)}")
    print(f"mismatches {len(MISMATCHES)}")
    for label, core, lunar in MISMATCHES:
        print(f"- {label}")
        print(f"    core:  {json.dumps(core, sort_keys=True)[:500]}")
        print(f"    lunar: {json.dumps(lunar, sort_keys=True)[:500]}")
    return 1 if MISMATCHES else 0


if __name__ == "__main__":
    sys.exit(main())
