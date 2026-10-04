"""
profile_argus — repeatable performance profiler for argus_pyqt.

Runs cProfile + tracemalloc over the import + setup phases of
``argus_pyqt`` without actually opening a GUI window. Designed to run
headless on Windows / Linux without a display server: ``QApplication.exec``
is monkey-patched to a no-op so we measure only startup + window
construction, not the event loop.

Outputs (in ``tools/_profile_out/``):
    argus_startup.prof     — cProfile binary (open with snakeviz / tuna)
    argus_per_module.txt   — per-module import time table
    argus_tracemalloc.txt  — top 30 allocation lines (lineno granularity)
    argus_summary.txt      — human-readable summary numbers

Usage:
    python tools/profile_argus.py
    python tools/profile_argus.py --quick   (skips heavy startup)
"""
from __future__ import annotations

import argparse
import cProfile
import importlib
import io
import pstats
import sys
import time
import tracemalloc
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT_DIR = Path(__file__).resolve().parent / "_profile_out"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def _stub_qapplication_exec() -> None:
    """Patch QApplication.exec so window.show() returns control immediately.

    Without this, importing argus_pyqt and calling main() would block on
    the Qt event loop. We want the cumulative profile of startup, not
    the event loop's idle ticks.
    """
    from PyQt6.QtWidgets import QApplication

    QApplication.exec = lambda self=None: 0          # type: ignore[assignment]
    QApplication.exec_ = lambda self=None: 0         # type: ignore[assignment]


def measure_per_module_imports() -> dict[str, float]:
    """Time each Argus module import in isolation (cold each time)."""
    targets = [
        "argus_sandbox",
        "argus_surveillance",
        "argus_arbiter",
        "argus_2fa",
        "argus_vault",
        "argus_mythos_bus",
        "argus_mythos_gateway",
        "argus_vault_client",
        "argus_vault_gateway",
        "argus_vault_domains",
        "argus_i18n",
        "argus_onboarding",
    ]
    results: dict[str, float] = {}
    sys.path.insert(0, str(REPO))
    for name in targets:
        # Unload if previously imported so we measure cold.
        for k in list(sys.modules):
            if k == name or k.startswith(name + "."):
                del sys.modules[k]
        t0 = time.perf_counter()
        try:
            importlib.import_module(name)
            elapsed = time.perf_counter() - t0
        except Exception as e:
            elapsed = -1.0
            results[name + " (error)"] = -1.0
            print(f"  {name}: IMPORT FAILED — {e}")
            continue
        results[name] = elapsed
    return results


def profile_startup(prof_path: Path) -> tuple[float, int]:
    """Profile sys.path setup → argus_pyqt.main() with QApplication.exec stubbed.

    Returns (elapsed_seconds, peak_kb).
    """
    sys.path.insert(0, str(REPO))
    tracemalloc.start()

    pr = cProfile.Profile()
    pr.enable()
    t0 = time.perf_counter()

    # Pre-stub Qt before importing argus_pyqt — but main() won't be reached
    # without it being importable. Trick: patch lazily once Qt loads.
    import PyQt6.QtWidgets  # noqa: F401  (force load)
    _stub_qapplication_exec()

    # Now import + invoke main(). main() calls QApplication(...).exec()
    # at the very end which is now a no-op.
    import argus_pyqt
    try:
        argus_pyqt.main()
    except SystemExit:
        # main() ends with sys.exit(app.exec()); our stubbed exec returns
        # 0 so SystemExit(0) is raised — that's the success path.
        pass
    except Exception as e:
        print(f"  startup: failed with {type(e).__name__}: {e}")

    elapsed = time.perf_counter() - t0
    pr.disable()
    pr.dump_stats(str(prof_path))

    snapshot = tracemalloc.take_snapshot()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Top 30 allocation lines.
    top = snapshot.statistics("lineno")[:30]
    with open(OUT_DIR / "argus_tracemalloc.txt", "w", encoding="utf-8") as f:
        f.write(f"Peak traced memory: {peak/1024:.1f} KB\n")
        f.write("Top 30 allocation lines (lineno granularity):\n\n")
        for s in top:
            f.write(f"{s.size/1024:10.1f} KB  {s.count:8d} allocs  {s.traceback}\n")

    return elapsed, peak // 1024


def write_pstats(prof_path: Path, txt_path: Path, top_n: int = 30) -> None:
    buf = io.StringIO()
    s = pstats.Stats(str(prof_path), stream=buf)
    s.sort_stats("cumulative").print_stats(top_n)
    txt_path.write_text(buf.getvalue(), encoding="utf-8")


def main() -> None:
    p = argparse.ArgumentParser(description="Profile argus_pyqt startup.")
    p.add_argument("--quick", action="store_true",
                   help="Skip per-module import test")
    args = p.parse_args()

    print(f"Profile output: {OUT_DIR}")
    print(f"Repo:           {REPO}")
    print()

    if not args.quick:
        print("[1/2] Per-module import times (cold each)…")
        per_mod = measure_per_module_imports()
        with open(OUT_DIR / "argus_per_module.txt", "w", encoding="utf-8") as f:
            f.write(f"{'Module':<40} {'Time (ms)':>12}\n")
            f.write("-" * 54 + "\n")
            for name, secs in sorted(per_mod.items(), key=lambda x: -x[1]):
                f.write(f"{name:<40} {secs * 1000:>12.1f}\n")
        for name, secs in sorted(per_mod.items(), key=lambda x: -x[1])[:5]:
            print(f"  {name:<32} {secs * 1000:>8.1f} ms")
        print()

    print("[2/2] Full startup profile (QApplication.exec stubbed)…")
    prof = OUT_DIR / "argus_startup.prof"
    elapsed, peak_kb = profile_startup(prof)
    write_pstats(prof, OUT_DIR / "argus_pstats_top30.txt")

    summary = (
        f"Argus startup profile\n"
        f"  Elapsed:     {elapsed:.2f} s\n"
        f"  Peak memory: {peak_kb/1024:.1f} MB\n"
        f"  Profile:     {prof}\n"
    )
    (OUT_DIR / "argus_summary.txt").write_text(summary, encoding="utf-8")
    print(summary)


if __name__ == "__main__":
    main()
