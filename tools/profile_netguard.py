"""
profile_netguard — repeatable performance profiler for netguard.py.

Measures three phases:
  1. Cold startup time (import netguard + scapy etc.)
  2. Synthetic packet throughput (analyze_packet at peak rate, mock pkts)
  3. Steady-state memory after the throughput run

NetGuard's main() requires admin (raw sockets). We never call it; we
profile only the engine functions in isolation. This is enough to surface
hot loops in detect_port_scan / is_in_bad_range / etc.

Outputs (in ``tools/_profile_out/``):
    netguard_startup.prof
    netguard_pstats_top30.txt
    netguard_throughput.txt
    netguard_summary.txt
"""
from __future__ import annotations

import cProfile
import io
import pstats
import sys
import time
import tracemalloc
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT_DIR = Path(__file__).resolve().parent / "_profile_out"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def measure_startup() -> tuple[float, int, Path]:
    """cProfile + tracemalloc over `import netguard`.

    NetGuard's module-level code can spawn background threads that touch
    the network (threat feeds, GeoIP, OTX). To keep the profile bounded
    and offline, we monkey-patch `urllib.request.urlopen` to raise so
    those tasks bail out fast. We measure import time only — main() is
    out of scope (requires admin / scapy raw sockets).

    Note: scapy.arch.windows enumerates all network interfaces at import
    time via WMI / Npcap, which can take 20-30 s on a fresh process.
    That cost is captured in the profile and cannot be avoided without
    refactoring netguard to lazy-import scapy.
    """
    sys.path.insert(0, str(REPO))
    for k in list(sys.modules):
        if k.startswith("netguard"):
            del sys.modules[k]

    # Block network I/O at import time.
    import urllib.request as _urlreq

    def _no_net(*_a, **_kw):
        raise _urlreq.URLError("offline (profiler)")

    _urlreq.urlopen = _no_net  # type: ignore[assignment]

    tracemalloc.start()
    pr = cProfile.Profile()
    pr.enable()
    t0 = time.perf_counter()
    import netguard  # noqa: F401
    elapsed = time.perf_counter() - t0
    pr.disable()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    prof = OUT_DIR / "netguard_startup.prof"
    pr.dump_stats(str(prof))
    return elapsed, peak // 1024, prof


def measure_throughput(n: int = 5000) -> dict[str, float]:
    """Hammer analyze_packet with synthetic scapy packets; report events/sec.

    Requires `scapy.all` to import successfully. On Windows that pulls
    `scapy.arch.windows` which enumerates NICs (~20-30 s on cold cache).
    If that import hangs, throughput cannot be measured here — we still
    report cold startup numbers from measure_startup().
    """
    sys.path.insert(0, str(REPO))
    import netguard
    from scapy.all import IP, TCP, UDP

    ips = [f"203.0.113.{i % 250 + 1}" for i in range(n)]
    pkts = []
    for i, ip in enumerate(ips):
        if i % 3 == 0:
            pkts.append(IP(src=ip, dst="10.0.0.1") /
                        TCP(sport=40000 + i % 5000, dport=80 + i % 1024, flags="S"))
        else:
            pkts.append(IP(src=ip, dst="10.0.0.1") /
                        UDP(sport=40000 + i % 5000, dport=53 + i % 100))

    for pkt in pkts[:200]:
        try:
            netguard.analyze_packet(pkt)
        except Exception:
            pass

    t0 = time.perf_counter()
    for pkt in pkts:
        try:
            netguard.analyze_packet(pkt)
        except Exception:
            pass
    elapsed = time.perf_counter() - t0
    return {"packets": float(n), "elapsed_s": elapsed,
            "pkts_per_sec": n / elapsed if elapsed else 0.0}


def measure_microbench() -> dict[str, float]:
    """Targeted microbenchmarks of hot helpers that don't need scapy.all.

    Picks the per-packet helpers that show up in static analysis as
    O(n) over the bad-range / whitelist tables, plus the tracker
    blocklist suffix scan. These run scapy-free so they work even if
    `scapy.all` hangs at import.
    """
    import importlib
    sys.path.insert(0, str(REPO))

    # Re-import sandbox (no scapy needed for the tracker tests).
    if "argus_sandbox" in sys.modules:
        del sys.modules["argus_sandbox"]
    sb = importlib.import_module("argus_sandbox")

    # 1. tracker is_tracker on 1000 hostnames
    interceptor = sb.TrackerInterceptor(mode="normal")
    hosts = [f"host{i}.example.com" for i in range(1000)]
    t0 = time.perf_counter()
    for h in hosts:
        interceptor.is_tracker(h)
    is_tracker_per_call_us = (time.perf_counter() - t0) / len(hosts) * 1_000_000

    # 2. is_third_party
    t0 = time.perf_counter()
    for h in hosts:
        interceptor.is_third_party(h, "rbcroyalbank.com")
    is_third_party_per_call_us = (time.perf_counter() - t0) / len(hosts) * 1_000_000

    # 3. blocklist size
    blocklist = sb.get_tracker_blocklist()
    blocklist_size = len(blocklist)

    return {
        "is_tracker_us_per_call":      is_tracker_per_call_us,
        "is_third_party_us_per_call":  is_third_party_per_call_us,
        "blocklist_size":              float(blocklist_size),
    }


def write_pstats(prof_path: Path, txt_path: Path, top_n: int = 30) -> None:
    buf = io.StringIO()
    s = pstats.Stats(str(prof_path), stream=buf)
    s.sort_stats("cumulative").print_stats(top_n)
    txt_path.write_text(buf.getvalue(), encoding="utf-8")


def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="Profile NetGuard.")
    p.add_argument("--skip-startup", action="store_true",
                   help="Skip cold-startup test (useful when scapy hangs)")
    p.add_argument("--skip-throughput", action="store_true",
                   help="Skip synthetic packet test (needs scapy.all)")
    args = p.parse_args()

    print(f"Profile output: {OUT_DIR}")
    print()

    elapsed = -1.0
    peak_kb = 0
    prof = None

    if not args.skip_startup:
        print("[1/3] Cold startup…")
        try:
            elapsed, peak_kb, prof = measure_startup()
            write_pstats(prof, OUT_DIR / "netguard_pstats_top30.txt")
            print(f"  startup: {elapsed:.2f}s  peak {peak_kb/1024:.1f}MB")
        except Exception as e:
            print(f"  startup: FAILED — {e}")

    print("[2/3] Microbench (sandbox helpers, scapy-free)…")
    try:
        mb = measure_microbench()
        for k, v in mb.items():
            print(f"  {k}: {v:.3f}")
    except Exception as e:
        mb = {"error": str(e)}
        print(f"  microbench: FAILED — {e}")

    thr: dict[str, float] | dict[str, str]
    if not args.skip_throughput:
        print("[3/3] Synthetic packet throughput (5000 packets)…")
        try:
            thr = measure_throughput(5000)
            print(f"  throughput: {thr['pkts_per_sec']:.0f} pkts/s")
        except Exception as e:
            thr = {"error": str(e)}
            print(f"  throughput: SKIPPED — {e}")
    else:
        thr = {"skipped": "yes"}
        print("[3/3] Throughput: skipped (--skip-throughput)")

    summary = (
        f"NetGuard performance profile\n"
        f"  Cold startup:   {elapsed:.2f} s, peak {peak_kb/1024:.1f} MB\n"
        f"  Microbench:     {mb}\n"
        f"  Throughput:     {thr}\n"
        f"  Profile:        {prof}\n"
    )
    (OUT_DIR / "netguard_summary.txt").write_text(summary, encoding="utf-8")
    (OUT_DIR / "netguard_throughput.txt").write_text(
        "\n".join(f"{k}: {v}" for k, v in {**mb, **thr}.items()) + "\n",
        encoding="utf-8",
    )
    print()
    print(summary)


if __name__ == "__main__":
    main()
