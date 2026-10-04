"""End-to-end smoke test of the capture engines (no admin needed for `poll`).

Starts NetGuard AI headless in a throw-away data directory, waits a few seconds,
connects to the dashboard WebSocket with the generated token and prints what the
engine actually captured. Exit code 0 only when live traffic reached the state.

    python tools/smoke_capture.py            # auto: etw if elevated, else poll
    python tools/smoke_capture.py --engine etw   (run from an administrator shell)
"""
import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


async def read_state(port: int, token: str, wait: float) -> dict:
    import websockets
    deadline = time.time() + wait
    last = {}
    async with websockets.connect(f"ws://localhost:{port}", open_timeout=5) as ws:
        await ws.send(json.dumps({"cmd": "auth", "token": token}))
        while time.time() < deadline:
            try:
                msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=2))
            except asyncio.TimeoutError:
                continue
            if msg.get("type") == "state":
                last = msg
    return last


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", default="", choices=["", "etw", "poll", "npcap"])
    ap.add_argument("--port", type=int, default=8791)
    ap.add_argument("--seconds", type=float, default=10.0)
    ap.add_argument("--exe", default="", help="test a packaged NetGuardAI.exe instead of the source tree")
    ap.add_argument("--out", default="", help="also write the report to this file (elevated runs have no console to read)")
    args = ap.parse_args()
    if args.out:
        import io
        _buf = io.StringIO()
        _orig_print = print
        def _tee(*a, **k):
            _orig_print(*a, **k)
            _orig_print(*a, **{**k, "file": _buf})
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(_buf.getvalue())
        globals()["print"] = _tee

    data_dir = tempfile.mkdtemp(prefix="netguard_smoke_")
    env = dict(os.environ, NETGUARD_DATA_DIR=data_dir, PYTHONUTF8="1")
    if args.engine:
        env["NETGUARD_CAPTURE_ENGINE"] = args.engine
    launcher = [args.exe] if args.exe else [sys.executable, os.path.join(ROOT, "netguard.py")]
    proc = subprocess.Popen(launcher + ["--headless", "--no-block", "--port", str(args.port)],
                            cwd=os.path.dirname(args.exe) if args.exe else ROOT, env=env,
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        token_file = os.path.join(data_dir, ".netguard_token")
        for _ in range(60):
            if os.path.exists(token_file) and os.path.getsize(token_file) > 0:
                break
            if proc.poll() is not None:
                print(proc.stdout.read().decode("utf-8", "replace")[-3000:])
                print("FAIL: NetGuard exited early")
                return 2
            time.sleep(0.25)
        token = open(token_file, encoding="utf-8").read().strip()
        time.sleep(2)
        # generate a little real traffic so there is something to see
        for url in ("https://www.cloudflare.com/cdn-cgi/trace", "https://example.com/"):
            try:
                urllib.request.urlopen(url, timeout=5).read(200)
            except Exception:
                pass
        state = asyncio.run(read_state(args.port, token, args.seconds))
        pkts = state.get("recent_packets") or []
        remote = sorted({p.get("src") for p in pkts} | {p.get("dst") for p in pkts})
        print(f"moteur            : {state.get('capture_engine')}  {state.get('capture_capabilities')}")
        print(f"admin             : {state.get('is_admin')}   erreur capture: {state.get('capture_error') or '-'}")
        print(f"paquets/flux vus  : {state.get('packets_total')}   entrées récentes: {len(pkts)}")
        print(f"IP distinctes     : {len(remote)}")
        with_proc = [p for p in pkts if p.get('process')]
        with_size = [p for p in pkts if p.get('size') not in ('0B', '', None)]
        print(f"avec processus    : {len(with_proc)}   avec octets: {len(with_size)}")
        for p in pkts[:6]:
            print(f"   {p.get('t')} {p.get('src')}:{p.get('sport')} -> {p.get('dst')}:{p.get('dport')} "
                  f"{p.get('proto')} {p.get('size')} [{p.get('process')}] {p.get('location')}")
        ok = bool(pkts) and not state.get("capture_error")
        print("RESULT:", "OK" if ok else "FAIL")
        return 0 if ok else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
