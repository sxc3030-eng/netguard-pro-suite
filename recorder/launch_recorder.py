"""NetGuard Suite — Session Recorder launcher

Spawns recorder.py in headless mode (WebSocket service on port 8860),
waits for the port to come up, then opens recorder_viewer.html in a
pywebview window. Closing the window kills the recorder subprocess
cleanly.
"""
from __future__ import annotations

import atexit
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PORT = 8860
VIEWER_URL = (HERE / "recorder_viewer.html").resolve().as_uri()


def _is_port_up(port: int, timeout: float = 0.4) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()


def _kill_orphan(port: int) -> None:
    """Free the port from a previous orphan run before starting fresh."""
    if os.name != "nt":
        return
    try:
        out = subprocess.check_output(
            ["netstat", "-aon"], encoding="utf-8", errors="ignore", timeout=5
        )
    except (subprocess.SubprocessError, OSError):
        return
    needle = f":{port} "
    for line in out.splitlines():
        if needle in line and "LISTENING" in line:
            parts = line.split()
            if parts:
                pid = parts[-1]
                if pid.isdigit():
                    print(f"[*] Killing orphan PID {pid} on port {port}…")
                    subprocess.call(["taskkill", "/F", "/PID", pid],
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)


def main() -> int:
    _kill_orphan(PORT)

    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_CONSOLE

    print("[*] Starting RecordAgent (headless)…")
    proc = subprocess.Popen(
        [sys.executable, str(HERE / "recorder.py"), "--headless"],
        cwd=str(HERE),
        creationflags=creationflags,
    )

    @atexit.register
    def _kill():
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()

    print("[*] Waiting for ws://localhost:%d …" % PORT)
    for _ in range(40):
        if _is_port_up(PORT):
            break
        time.sleep(0.25)
    else:
        print("[!] RecordAgent did not respond in time. Closing.")
        proc.terminate()
        return 1

    print("[OK] Service up. Opening viewer.")
    try:
        import webview  # pywebview
    except ImportError:
        # Fallback: open in default browser if pywebview is missing.
        import webbrowser
        webbrowser.open(VIEWER_URL)
        try:
            proc.wait()
        except KeyboardInterrupt:
            pass
        return 0

    win = webview.create_window(
        "NetGuard Suite — Session Recorder",
        VIEWER_URL,
        width=1200,
        height=780,
        background_color="#0f0f13",
    )
    try:
        webview.start()
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
