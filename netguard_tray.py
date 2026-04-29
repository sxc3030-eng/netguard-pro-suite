r"""
NetGuard Pro — Mode Fantôme (System Tray).

Ghost Mode : NetGuard runs silent in background, sleeps unless an anomaly
arrives, lives only as a tray icon. Click → opens dashboard or Argus.
Icon color = live status:
  🟢 green  — protection active, network clean
  🟡 amber  — protection active, recent anomalies (>0 threats in last 60s)
  🔴 red    — protection stopped (backend not running)

Auto-start: optional toggle that registers in HKCU\Run so the tray
launches at Windows boot. Backend then runs unattended without any
visible window.

Run:    python netguard_tray.py
Or:     LANCER_NETGUARD_GHOST.bat (auto-elevation if Npcap admin-only)
"""
import json
import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

try:
    import pystray
    from pystray import MenuItem as item
    from PIL import Image, ImageDraw
except ImportError:
    print("Installation des dépendances tray (pystray + pillow)...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pystray", "pillow"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    import pystray
    from pystray import MenuItem as item
    from PIL import Image, ImageDraw

# ── Paths ────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent
DASHBOARD  = SCRIPT_DIR / "netguard_dashboard.html"
MAP_FILE   = SCRIPT_DIR / "netguard_map.html"
BACKEND    = SCRIPT_DIR / "netguard.py"
ARGUS      = SCRIPT_DIR / "argus_pyqt.py"
TOKEN_FILE = SCRIPT_DIR / ".netguard_token"

# ── Colors per status ────────────────────────────────────────────────────
COLOR_OK    = (61, 255, 180)   # green — backend up, no recent threats
COLOR_WARN  = (255, 179, 71)   # amber — backend up, recent anomalies
COLOR_DOWN  = (255, 77, 106)   # red   — backend off

# ── Icon factory ─────────────────────────────────────────────────────────
def create_icon(color):
    """64×64 NetGuard icon with the chosen accent color."""
    img = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle([2, 2, 62, 62], radius=12, fill=(15, 15, 19))
    r, g, b = color
    draw.line([12, 12, 52, 52], fill=(r, g, b, 255), width=5)
    draw.line([52, 12, 32, 32], fill=(r, g, b, 200), width=4)
    draw.line([32, 32, 12, 52], fill=(r, g, b, 200), width=4)
    draw.ellipse([28, 28, 36, 36], fill=(180, 125, 255, 255))
    return img

# ── Globals ─────────────────────────────────────────────────────────────
_backend_process = None       # Popen handle if WE started it
_recent_threats_count = 0     # threats observed in last poll
_last_threats_seen = 0        # snapshot — for delta detection
_alerted_threat_ids = set()   # avoid re-notifying the same threat
_tray_icon = None             # set in main()


# ── Backend status / control ────────────────────────────────────────────
def is_running():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        ok = s.connect_ex(('localhost', 8765)) == 0
        s.close()
        return ok
    except Exception:
        return False


def _spawn_backend():
    """Start netguard.py in background (no console window)."""
    global _backend_process
    if is_running():
        return
    try:
        _backend_process = subprocess.Popen(
            [sys.executable, str(BACKEND)],
            cwd=str(SCRIPT_DIR),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        print(f"[TRAY] Backend launch failed: {e}", file=sys.stderr)


def _stop_backend():
    global _backend_process
    if _backend_process and _backend_process.poll() is None:
        _backend_process.terminate()
        try:
            _backend_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _backend_process.kill()
    _backend_process = None


# ── WS poll for threats (anomaly detection on the tray icon) ────────────
def _poll_threats():
    """Quick WS poll: open ws://localhost:8765, send auth, ask for state,
    return (threats_count, latest_critical). Returns (0, None) on any failure."""
    if not is_running():
        return 0, None
    try:
        from websockets.sync.client import connect  # websockets >= 12 sync API
    except ImportError:
        try:
            import asyncio
            import websockets
            return _poll_threats_async()
        except Exception:
            return 0, None
    try:
        token = TOKEN_FILE.read_text(encoding="utf-8").strip() if TOKEN_FILE.exists() else ""
        with connect("ws://localhost:8765", open_timeout=1, close_timeout=1) as ws:
            ws.send(json.dumps({"cmd": "auth", "token": token}))
            ack = json.loads(ws.recv(timeout=1))
            if ack.get("type") != "auth_ok":
                return 0, None
            state = json.loads(ws.recv(timeout=1))
            threats = state.get("threats", []) if isinstance(state, dict) else []
            return len(threats), (threats[0] if threats else None)
    except Exception:
        return 0, None


def _poll_threats_async():
    """Fallback async poll if websockets sync API is unavailable."""
    import asyncio
    import websockets
    async def _go():
        token = TOKEN_FILE.read_text(encoding="utf-8").strip() if TOKEN_FILE.exists() else ""
        try:
            async with websockets.connect("ws://localhost:8765", open_timeout=1, close_timeout=1) as ws:
                await ws.send(json.dumps({"cmd": "auth", "token": token}))
                ack = json.loads(await asyncio.wait_for(ws.recv(), timeout=1))
                if ack.get("type") != "auth_ok":
                    return 0, None
                state = json.loads(await asyncio.wait_for(ws.recv(), timeout=1))
                threats = state.get("threats", []) if isinstance(state, dict) else []
                return len(threats), (threats[0] if threats else None)
        except Exception:
            return 0, None
    try:
        return asyncio.run(_go())
    except Exception:
        return 0, None


# ── Icon update + notifications ─────────────────────────────────────────
def _icon_for_status():
    if not is_running():
        return create_icon(COLOR_DOWN), "NetGuard — 🔴 Arrêté"
    if _recent_threats_count > 0:
        return create_icon(COLOR_WARN), f"NetGuard — 🟡 {_recent_threats_count} menace(s) récente(s)"
    return create_icon(COLOR_OK), "NetGuard — 🟢 Surveillance active"


def update_icon():
    if _tray_icon is None:
        return
    img, title = _icon_for_status()
    _tray_icon.icon = img
    _tray_icon.title = title


def notify_threat(threat: dict):
    """Show a Windows balloon notification for a new critical threat."""
    if _tray_icon is None or not threat:
        return
    sev = (threat.get("severity") or "").lower()
    if sev not in ("critical", "high"):
        return
    msg = f"{threat.get('type','?')} — {threat.get('src_ip','?')}\n{threat.get('description','')[:120]}"
    try:
        _tray_icon.notify(msg, title="NetGuard — Menace détectée")
    except Exception:
        pass


# ── Periodic poller ─────────────────────────────────────────────────────
def _polling_loop():
    global _recent_threats_count, _last_threats_seen
    while True:
        try:
            count, latest = _poll_threats()
            _recent_threats_count = count
            # Notify on NEW threats only (not on every poll)
            if latest:
                tid = latest.get("id")
                if tid and tid not in _alerted_threat_ids:
                    _alerted_threat_ids.add(tid)
                    if len(_alerted_threat_ids) > 200:
                        _alerted_threat_ids.clear()  # bound memory
                    notify_threat(latest)
            update_icon()
        except Exception as e:
            print(f"[TRAY] poll error: {e}", file=sys.stderr)
        time.sleep(8)  # poll every 8 seconds


# ── Auto-start at Windows boot (HKCU\Run) ───────────────────────────────
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "NetGuardTray"


def is_autostart_enabled() -> bool:
    if os.name != "nt":
        return False
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            val, _ = winreg.QueryValueEx(k, RUN_NAME)
            return bool(val)
    except Exception:
        return False


def toggle_autostart(icon=None, item=None):
    if os.name != "nt":
        return
    import winreg
    enabled = is_autostart_enabled()
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        if enabled:
            try:
                winreg.DeleteValue(k, RUN_NAME)
            except FileNotFoundError:
                pass
        else:
            cmd = f'"{sys.executable}" "{__file__}"'
            winreg.SetValueEx(k, RUN_NAME, 0, winreg.REG_SZ, cmd)
    update_icon()


# ── Menu actions ────────────────────────────────────────────────────────
def open_dashboard(icon, item):
    webbrowser.open(DASHBOARD.as_uri())


def open_map(icon, item):
    webbrowser.open(MAP_FILE.as_uri())


def open_argus(icon, item):
    """Launch Argus (PyQt6 browser shell) — ensures backend is running first."""
    if not is_running():
        _spawn_backend()
        time.sleep(2)  # give backend time to bind WS port
    if ARGUS.exists():
        subprocess.Popen(
            [sys.executable, str(ARGUS)],
            cwd=str(SCRIPT_DIR),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )


def start_backend(icon, item):
    _spawn_backend()
    update_icon()


def stop_backend(icon, item):
    _stop_backend()
    update_icon()


def restart_backend(icon, item):
    _stop_backend()
    time.sleep(1)
    _spawn_backend()
    update_icon()


def quit_tray(icon, item):
    if _backend_process is not None:
        # Don't kill the backend — it stays running (Ghost Mode philosophy:
        # tray quits, surveillance continues until explicitly stopped).
        pass
    icon.stop()


# ── Main ────────────────────────────────────────────────────────────────
def main():
    global _tray_icon

    # Auto-launch backend at tray start (Ghost Mode core behavior)
    if not is_running():
        _spawn_backend()
        # Wait a moment for the WS port to come up
        for _ in range(10):
            if is_running():
                break
            time.sleep(0.3)

    img, title = _icon_for_status()

    autostart_label = "✓ Démarrage automatique au boot" if is_autostart_enabled() else "Activer démarrage au boot"

    menu = pystray.Menu(
        item('📊 Dashboard',           open_dashboard, default=True),
        item('🌍 Carte mondiale',      open_map),
        item('🦅 Argus (workbench)',   open_argus),
        pystray.Menu.SEPARATOR,
        item('▶ Démarrer surveillance',  start_backend),
        item('■ Arrêter surveillance',   stop_backend),
        item('↺ Redémarrer',             restart_backend),
        pystray.Menu.SEPARATOR,
        item(lambda i: ("✓ " if is_autostart_enabled() else "  ") + "Démarrage au boot Windows", toggle_autostart),
        pystray.Menu.SEPARATOR,
        item('✕ Quitter tray (surveillance reste active)', quit_tray),
    )

    _tray_icon = pystray.Icon(
        name="NetGuardPro",
        icon=img,
        title=title,
        menu=menu,
    )

    # Background poller — updates icon color + sends balloon notifications
    threading.Thread(target=_polling_loop, daemon=True).start()

    print("NetGuard Pro — Mode Fantôme actif (icône système)")
    _tray_icon.run()


if __name__ == "__main__":
    main()
