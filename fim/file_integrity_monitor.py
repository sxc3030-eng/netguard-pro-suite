"""
SentinelOS — File Integrity Monitor (FIM) v1.0
Monitors critical system files for unauthorized changes.
Detects additions, modifications, and deletions.

Port: 8840
Architecture:
    FIM Agent
        +-- Baseline Creator — hashes critical files
        +-- Change Detector — periodic comparison
        +-- Whitelist — known good changes (Windows Update, etc.)
        +-- WebSocket Server — serves state to Cortex
        +-- Alert Publisher — publishes fim.* events
"""

import os
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import json
import time
import asyncio
import logging
import threading
import hashlib
from datetime import datetime
from pathlib import Path
from collections import defaultdict

import websockets

FIMDIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(FIMDIR)
sys.path.insert(0, BASE_DIR)

VERSION = "1.0.0"
WS_PORT = 8840
IS_WINDOWS = sys.platform == "win32"

LOG_DIR = os.path.join(FIMDIR, "logs")
DATA_DIR = os.path.join(FIMDIR, "data")
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [FIM] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(LOG_DIR, "fim.log"), encoding="utf-8"),
    ],
)
logger = logging.getLogger("SentinelOS.FIM")

# ===========================================================================
# MONITORED PATHS
# ===========================================================================

# Critical directories to monitor (OS-adaptive)
if IS_WINDOWS:
    MONITOR_PATHS = [
        {"path": os.path.expandvars(r"%SYSTEMROOT%\System32\drivers\etc"), "label": "Hosts & Network Config", "recursive": False},
        {"path": os.path.expandvars(r"%SYSTEMROOT%\System32\config"), "label": "Registry Hives", "recursive": False},
        {"path": os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"), "label": "Startup Programs", "recursive": True},
        {"path": os.path.expanduser(r"~\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"), "label": "User Startup", "recursive": True},
        {"path": os.path.join(BASE_DIR, "sentinel"), "label": "SentinelOS Core", "recursive": False},
        {"path": os.path.join(BASE_DIR, "netguard.py"), "label": "NetGuard Agent", "recursive": False, "single_file": True},
    ]
else:
    # Linux / macOS
    MONITOR_PATHS = [
        {"path": "/etc/hosts", "label": "Hosts File", "recursive": False, "single_file": True},
        {"path": "/etc/passwd", "label": "Users (passwd)", "recursive": False, "single_file": True},
        {"path": "/etc/shadow", "label": "Password Hashes (shadow)", "recursive": False, "single_file": True},
        {"path": "/etc/sudoers", "label": "Sudoers Config", "recursive": False, "single_file": True},
        {"path": "/etc/ssh", "label": "SSH Config", "recursive": False},
        {"path": "/etc/crontab", "label": "Crontab", "recursive": False, "single_file": True},
        {"path": "/etc/cron.d", "label": "Cron Jobs", "recursive": True},
        {"path": "/etc/systemd/system", "label": "Systemd Services", "recursive": False},
        {"path": os.path.expanduser("~/.ssh"), "label": "User SSH Keys", "recursive": False},
        {"path": os.path.expanduser("~/.bashrc"), "label": "Bashrc", "recursive": False, "single_file": True},
        {"path": os.path.expanduser("~/.profile"), "label": "Profile", "recursive": False, "single_file": True},
        # Monitor our own sentinel directory for tampering
        {"path": os.path.join(BASE_DIR, "sentinel"), "label": "SentinelOS Core", "recursive": False},
        {"path": os.path.join(BASE_DIR, "netguard.py"), "label": "NetGuard Agent", "recursive": False, "single_file": True},
    ]

# File extensions to monitor (skip large/binary files)
MONITOR_EXTENSIONS = {
    ".py", ".sh", ".bash", ".zsh",
    ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".exe", ".dll", ".sys", ".so", ".dylib",
    ".ini", ".cfg", ".conf",
    ".reg", ".hosts", ".txt", ".json", ".xml", ".yaml", ".yml",
    ".html", ".htm",
    ".service", ".timer", ".socket",  # systemd
    "",  # Files without extension (passwd, shadow, hosts, crontab, etc.)
}

# Max file size to hash (skip large files)
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

# Whitelist patterns (temp files, caches, etc.)
WHITELIST_PATTERNS = [
    "__pycache__",
    ".pyc",
    ".log",
    ".tmp",
    ".cache",
    "Thumbs.db",
    "desktop.ini",
    ".swp",
    ".swo",
    "~",
]


# ===========================================================================
# BASELINE MANAGER
# ===========================================================================

_HMAC_KEY_FILE = os.path.join(DATA_DIR, ".fim_hmac_key")


def _get_hmac_key() -> bytes:
    """Load or generate the FIM baseline HMAC key. File chmod 0600."""
    try:
        if os.path.exists(_HMAC_KEY_FILE):
            with open(_HMAC_KEY_FILE, "rb") as f:
                key = f.read().strip()
            if len(key) >= 32:
                return key
    except OSError:
        pass
    import secrets as _s
    key = _s.token_bytes(32)
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(_HMAC_KEY_FILE, "wb") as f:
            f.write(key)
        try:
            os.chmod(_HMAC_KEY_FILE, 0o600)
        except OSError:
            pass
        logger.info(f"[Baseline] HMAC key generated -> {_HMAC_KEY_FILE}")
    except OSError as e:
        logger.error(f"[Baseline] Cannot persist HMAC key: {e}")
    return key


def _compute_baseline_hmac(data: dict, key: bytes) -> str:
    """HMAC-SHA256 over a canonical JSON dump of the baseline dict."""
    import hmac
    payload = json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


class BaselineManager:
    """Creates and manages file hash baselines (HMAC-signed against tampering)."""

    def __init__(self):
        self.baseline: dict[str, dict] = {}  # path -> {hash, size, mtime}
        self.baseline_file = os.path.join(DATA_DIR, "baseline.json")
        self._load_baseline()

    def _load_baseline(self):
        """Load baseline from disk and verify its HMAC."""
        try:
            if not os.path.exists(self.baseline_file):
                return
            with open(self.baseline_file, "r", encoding="utf-8") as f:
                envelope = json.load(f)
            # New signed format: {"_hmac": "...", "data": {...}}
            if isinstance(envelope, dict) and "_hmac" in envelope and "data" in envelope:
                key = _get_hmac_key()
                expected = _compute_baseline_hmac(envelope["data"], key)
                import hmac as _hmac
                if not _hmac.compare_digest(envelope["_hmac"], expected):
                    logger.error("[Baseline] HMAC INVALID — possible tampering. Discarding baseline; rerun create_baseline.")
                    self.baseline = {}
                    return
                self.baseline = envelope["data"]
                logger.info(f"[Baseline] Loaded {len(self.baseline)} file hashes (HMAC OK)")
                return
            # Legacy plaintext format (no signature) — accept once, warn user to rebuild
            if isinstance(envelope, dict):
                logger.warning("[Baseline] Legacy unsigned format detected. Rebuild baseline to enable HMAC protection.")
                self.baseline = envelope
                logger.info(f"[Baseline] Loaded {len(self.baseline)} file hashes (UNSIGNED — rebuild recommended)")
        except Exception as e:
            logger.warning(f"[Baseline] Load error: {e}")

    def save_baseline(self):
        """Save baseline to disk with HMAC-SHA256 envelope (0600)."""
        try:
            key = _get_hmac_key()
            envelope = {
                "_hmac": _compute_baseline_hmac(self.baseline, key),
                "_format": "hmac-sha256-v1",
                "data": self.baseline,
            }
            tmp = self.baseline_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(envelope, f, indent=1)
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, self.baseline_file)
            logger.info(f"[Baseline] Saved {len(self.baseline)} file hashes (HMAC signed)")
        except Exception as e:
            logger.error(f"[Baseline] Save error: {e}")

    def create_baseline(self) -> int:
        """Scan all monitored paths and create hash baseline. Returns count."""
        count = 0
        for monitor in MONITOR_PATHS:
            path = monitor["path"]
            if monitor.get("single_file"):
                if os.path.isfile(path):
                    info = self._hash_file(path)
                    if info:
                        self.baseline[path] = info
                        count += 1
                continue

            if not os.path.isdir(path):
                logger.warning(f"[Baseline] Path not found: {path}")
                continue

            try:
                if monitor.get("recursive", False):
                    for root, dirs, files in os.walk(path):
                        for fname in files:
                            fpath = os.path.join(root, fname)
                            if self._should_monitor(fpath):
                                info = self._hash_file(fpath)
                                if info:
                                    self.baseline[fpath] = info
                                    count += 1
                else:
                    for fname in os.listdir(path):
                        fpath = os.path.join(path, fname)
                        if os.path.isfile(fpath) and self._should_monitor(fpath):
                            info = self._hash_file(fpath)
                            if info:
                                self.baseline[fpath] = info
                                count += 1
            except PermissionError:
                logger.warning(f"[Baseline] Permission denied: {path}")
            except Exception as e:
                logger.error(f"[Baseline] Error scanning {path}: {e}")

        self.save_baseline()
        logger.info(f"[Baseline] Created baseline: {count} files")
        return count

    def _hash_file(self, filepath: str) -> dict | None:
        """Compute SHA256 hash of a file."""
        try:
            size = os.path.getsize(filepath)
            if size > MAX_FILE_SIZE:
                return None
            mtime = os.path.getmtime(filepath)
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return {
                "hash": sha256.hexdigest(),
                "size": size,
                "mtime": mtime,
            }
        except (PermissionError, OSError):
            return None

    def _should_monitor(self, filepath: str) -> bool:
        """Check if a file should be monitored."""
        # Skip whitelisted patterns
        for pattern in WHITELIST_PATTERNS:
            if pattern in filepath:
                return False
        # Check extension
        ext = os.path.splitext(filepath)[1].lower()
        # Allow files without extension (Linux: passwd, shadow, hosts, etc.)
        if ext == "" and "" in MONITOR_EXTENSIONS:
            return True
        if ext and ext not in MONITOR_EXTENSIONS:
            return False
        return True


# ===========================================================================
# CHANGE DETECTOR
# ===========================================================================

class ChangeDetector:
    """Detects changes compared to the baseline."""

    def __init__(self, baseline_mgr: BaselineManager):
        self.baseline = baseline_mgr
        self.changes: list[dict] = []
        self.alerts: list[dict] = []
        self._max_alerts = 500

    def scan_changes(self) -> list:
        """Scan monitored files and detect changes since baseline. Returns new alerts."""
        new_alerts = []
        current_files = set()

        for monitor in MONITOR_PATHS:
            path = monitor["path"]
            label = monitor.get("label", path)

            if monitor.get("single_file"):
                if os.path.isfile(path):
                    current_files.add(path)
                    alert = self._check_file(path, label)
                    if alert:
                        new_alerts.append(alert)
                continue

            if not os.path.isdir(path):
                continue

            try:
                if monitor.get("recursive", False):
                    for root, dirs, files in os.walk(path):
                        for fname in files:
                            fpath = os.path.join(root, fname)
                            if self.baseline._should_monitor(fpath):
                                current_files.add(fpath)
                                alert = self._check_file(fpath, label)
                                if alert:
                                    new_alerts.append(alert)
                else:
                    for fname in os.listdir(path):
                        fpath = os.path.join(path, fname)
                        if os.path.isfile(fpath) and self.baseline._should_monitor(fpath):
                            current_files.add(fpath)
                            alert = self._check_file(fpath, label)
                            if alert:
                                new_alerts.append(alert)
            except (PermissionError, OSError):
                pass

        # Check for deleted files
        for bpath in list(self.baseline.baseline.keys()):
            if bpath not in current_files and not os.path.exists(bpath):
                alert = {
                    "type": "file_deleted",
                    "path": bpath,
                    "filename": os.path.basename(bpath),
                    "severity": "critical",
                    "ts": time.time(),
                    "message": f"File DELETED: {os.path.basename(bpath)}",
                }
                new_alerts.append(alert)

        # Store alerts
        for a in new_alerts:
            self.alerts.append(a)
        if len(self.alerts) > self._max_alerts:
            self.alerts = self.alerts[-self._max_alerts:]

        return new_alerts

    def _check_file(self, filepath: str, label: str) -> dict | None:
        """Check a single file against baseline."""
        baseline_info = self.baseline.baseline.get(filepath)

        if not baseline_info:
            # New file — not in baseline
            new_info = self.baseline._hash_file(filepath)
            if new_info:
                # Add to baseline
                self.baseline.baseline[filepath] = new_info
                return {
                    "type": "file_added",
                    "path": filepath,
                    "filename": os.path.basename(filepath),
                    "label": label,
                    "severity": "warning",
                    "ts": time.time(),
                    "message": f"New file: {os.path.basename(filepath)} in {label}",
                }
            return None

        # Existing file — check if modified
        try:
            current_mtime = os.path.getmtime(filepath)
            if current_mtime == baseline_info.get("mtime", 0):
                return None  # Not modified

            # mtime changed — verify hash
            current_info = self.baseline._hash_file(filepath)
            if not current_info:
                return None

            if current_info["hash"] != baseline_info["hash"]:
                # File was MODIFIED
                old_hash = baseline_info["hash"][:12]
                new_hash = current_info["hash"][:12]
                # Update baseline
                self.baseline.baseline[filepath] = current_info
                return {
                    "type": "file_modified",
                    "path": filepath,
                    "filename": os.path.basename(filepath),
                    "label": label,
                    "old_hash": old_hash,
                    "new_hash": new_hash,
                    "old_size": baseline_info.get("size", 0),
                    "new_size": current_info["size"],
                    "severity": "warning",
                    "ts": time.time(),
                    "message": f"File MODIFIED: {os.path.basename(filepath)} ({old_hash}->{new_hash})",
                }
            else:
                # Hash same, just mtime changed (benign)
                self.baseline.baseline[filepath]["mtime"] = current_mtime
                return None
        except (PermissionError, OSError):
            return None


# ===========================================================================
# FIM ENGINE
# ===========================================================================

class FIMEngine:
    """File Integrity Monitor engine."""

    def __init__(self):
        self.baseline_mgr = BaselineManager()
        self.detector = ChangeDetector(self.baseline_mgr)
        self._running = True
        self._scan_interval = 30  # seconds
        self._last_scan = 0
        self.timeline: list[dict] = []
        self._initialized = False

    def start(self):
        """Initialize baseline and start monitoring."""
        # Create baseline if none exists
        if not self.baseline_mgr.baseline:
            logger.info("[FIM] No baseline found, creating initial baseline...")
            count = self.baseline_mgr.create_baseline()
            logger.info(f"[FIM] Baseline created: {count} files")
        else:
            logger.info(f"[FIM] Using existing baseline: {len(self.baseline_mgr.baseline)} files")

        self._initialized = True

        # Start monitoring loop
        t = threading.Thread(target=self._monitor_loop, daemon=True)
        t.start()
        logger.info("[FIM] Monitoring started")

    def _monitor_loop(self):
        """Periodic scan loop."""
        while self._running:
            if time.time() - self._last_scan > self._scan_interval:
                alerts = self.detector.scan_changes()
                self._last_scan = time.time()

                for alert in alerts:
                    self.timeline.append({
                        "ts": alert["ts"],
                        "source": "fim",
                        "channel": f"fim.{alert['type']}",
                        "severity": alert["severity"],
                        "data": {"message": alert["message"], "file": alert.get("filename", "")},
                    })

                if len(self.timeline) > 200:
                    self.timeline = self.timeline[-200:]

                if alerts:
                    logger.info(f"[FIM] Scan found {len(alerts)} change(s)")

            time.sleep(5)

    def rebuild_baseline(self) -> int:
        """Rebuild the entire baseline from scratch."""
        self.baseline_mgr.baseline.clear()
        count = self.baseline_mgr.create_baseline()
        self.detector.alerts.clear()
        return count

    def get_state(self) -> dict:
        return {
            "type": "state",
            "version": VERSION,
            "ts": time.time(),
            "initialized": self._initialized,
            "baseline_files": len(self.baseline_mgr.baseline),
            "alerts_count": len(self.detector.alerts),
            "recent_alerts": self.detector.alerts[-20:],
            "last_scan": self._last_scan,
            "scan_interval": self._scan_interval,
            "monitored_paths": [
                {"path": m["path"], "label": m.get("label", ""), "exists": os.path.exists(m["path"])}
                for m in MONITOR_PATHS
            ],
            "timeline": self.timeline[-30:],
            "changes_detected": sum(1 for a in self.detector.alerts if a["type"] == "file_modified"),
            "files_added": sum(1 for a in self.detector.alerts if a["type"] == "file_added"),
            "files_deleted": sum(1 for a in self.detector.alerts if a["type"] == "file_deleted"),
        }

    def stop(self):
        self._running = False
        self.baseline_mgr.save_baseline()


# ===========================================================================
# WEBSOCKET SERVER
# ===========================================================================

_engine = FIMEngine()
_ws_clients = set()


async def handle_ws(websocket, path=None):
    _ws_clients.add(websocket)
    try:
        async for message in websocket:
            try:
                msg = json.loads(message)
                cmd = msg.get("cmd", "")
                if cmd == "get_state":
                    await websocket.send(json.dumps(_engine.get_state(), default=str))
                elif cmd == "rebuild_baseline":
                    count = _engine.rebuild_baseline()
                    await websocket.send(json.dumps({"type": "baseline_rebuilt", "count": count}))
                elif cmd == "get_alerts":
                    limit = msg.get("limit", 50)
                    await websocket.send(json.dumps({
                        "type": "alerts",
                        "alerts": _engine.detector.alerts[-limit:],
                    }, default=str))
            except json.JSONDecodeError:
                pass
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        _ws_clients.discard(websocket)


async def broadcast_loop():
    while True:
        if _ws_clients:
            try:
                state = json.dumps(_engine.get_state(), default=str)
                await asyncio.gather(
                    *[c.send(state) for c in _ws_clients.copy()],
                    return_exceptions=True,
                )
            except Exception:
                pass
        await asyncio.sleep(10)


def main():
    logger.info("=" * 50)
    logger.info(f"  SentinelOS File Integrity Monitor v{VERSION}")
    logger.info(f"  WebSocket port: {WS_PORT}")
    logger.info("=" * 50)

    _engine.start()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def run():
        server = await websockets.serve(handle_ws, "localhost", WS_PORT)
        logger.info(f"[FIM] WebSocket server on ws://localhost:{WS_PORT}")
        asyncio.create_task(broadcast_loop())
        await asyncio.Future()

    try:
        loop.run_until_complete(run())
    except KeyboardInterrupt:
        pass
    finally:
        _engine.stop()
        logger.info("[FIM] Shutdown.")


if __name__ == "__main__":
    main()
