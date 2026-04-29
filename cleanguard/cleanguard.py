#!/usr/bin/env python3
"""
CleanGuard Pro v1.0.0 — Nettoyeur Système + Antivirus/Antimalware
Partie du pack NetGuard Pro
"""

import asyncio
import hashlib
import json
import math
import os
import platform
import shutil
import signal
import struct
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import threading
import time
import glob as globmod
import webbrowser

# Fix pythonw (no console) — redirect None stdout/stderr to devnull
if sys.stdout is None:
    sys.stdout = open(os.devnull, 'w')
if sys.stderr is None:
    sys.stderr = open(os.devnull, 'w')
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# --- Platform check ------------------------------------------------------
IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    try:
        import winreg
    except ImportError:
        winreg = None
else:
    winreg = None

try:
    import psutil
except ImportError:
    psutil = None

try:
    import websockets
except ImportError:
    print("[!] websockets manquant: pip install websockets")
    sys.exit(1)

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

# --- Paths ---------------------------------------------------------------
BASE_DIR = Path(__file__).parent.resolve()
SETTINGS_FILE = BASE_DIR / "cleanguard_settings.json"
QUARANTINE_DIR = BASE_DIR / "quarantine"
SIGNATURES_DIR = BASE_DIR / "signatures"
LOGS_DIR = BASE_DIR / "logs"

for d in [QUARANTINE_DIR, SIGNATURES_DIR, LOGS_DIR]:
    d.mkdir(exist_ok=True)

# --- Version -------------------------------------------------------------
VERSION = "1.0.0"

# --- Config --------------------------------------------------------------
@dataclass
class Config:
    ws_port: int = 8810
    realtime_protection: bool = False
    auto_quarantine: bool = True
    scan_archives: bool = True
    max_file_size_mb: int = 500
    heuristic_enabled: bool = True
    entropy_threshold: float = 7.2
    scan_hidden_files: bool = True
    exclusions: list = field(default_factory=list)
    scheduled_scan: str = ""  # cron expression
    scan_on_startup: bool = False
    theme: str = "dark"
    language: str = "fr"
    last_scan: str = ""
    last_clean: str = ""
    signatures_updated: str = ""

CFG = Config()

def load_settings():
    global CFG
    if SETTINGS_FILE.exists():
        try:
            data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            for k, v in data.items():
                if hasattr(CFG, k):
                    setattr(CFG, k, v)
        except Exception:
            pass

def save_settings():
    try:
        SETTINGS_FILE.write_text(json.dumps(asdict(CFG), indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        print(f"[!] Erreur sauvegarde settings: {e}")

# --- EICAR test signature -----------------------------------------------
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_PATTERN = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"

# --- Known malware hashes (SHA256) — bootstrap set ----------------------
KNOWN_MALWARE_HASHES = {
    EICAR_SHA256,  # EICAR test file
    # Common test hashes — real signatures loaded from file
}

# --- Suspicious PE imports -----------------------------------------------
# Only truly malicious API combos — removed common legitimate APIs
SUSPICIOUS_IMPORTS = [
    b"WriteProcessMemory",       # injection
    b"CreateRemoteThread",       # injection
    b"NtUnmapViewOfSection",     # process hollowing
    b"QueueUserAPC",             # APC injection
    b"RtlCreateUserThread",      # undoc injection
    b"NtWriteVirtualMemory",     # undoc injection
    b"NtCreateThreadEx",         # undoc injection
    b"IsDebuggerPresent",        # anti-debug
    b"CheckRemoteDebuggerPresent",
]
# NOTE: removed LoadLibraryA, GetProcAddress, VirtualAlloc, ShellExecute,
# RegSetValueEx, InternetOpen, GetTickCount — too common in legit software

# --- Dangerous extensions (for realtime only) ---------------------------
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe",
    ".wsf", ".wsh", ".ps1", ".hta", ".sct",
}
# NOTE: removed .js .jse .msi .msp .inf .reg .lnk .dll .sys .drv
# — too many legit files have these extensions

# --- Truly suspicious double extensions ----------------------------------
DOUBLE_EXT_PATTERNS = [
    ".jpg.exe", ".png.exe", ".pdf.exe", ".doc.exe", ".mp3.exe",
    ".mp4.exe", ".avi.exe", ".txt.exe", ".zip.exe", ".rar.exe",
    ".pdf.scr", ".doc.scr", ".jpg.scr", ".pdf.bat", ".doc.bat",
    ".pdf.vbs", ".doc.vbs", ".pdf.cmd",
]
# NOTE: removed .docm .xlsm .pptm — these are legitimate Office formats

# --- Whitelisted paths — never flag files from these locations ----------
WHITELIST_PATHS = [
    "\\program files\\",
    "\\program files (x86)\\",
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
    "\\microsoft\\",
    "\\windowsapps\\",
    "\\python3",
    "\\python\\",
    "\\nodejs\\",
    "\\git\\",
    "\\vscode\\",
    "\\visual studio\\",
    "\\jetbrains\\",
    "\\steam\\",
    "\\epic games\\",
    "\\nvidia\\",
    "\\amd\\",
    "\\intel\\",
]

# --- Cleaning targets ---------------------------------------------------
HOME = Path.home()

def expand_paths(paths):
    """Expand ~ and env vars, return existing paths"""
    result = []
    for p in paths:
        expanded = Path(os.path.expandvars(os.path.expanduser(p)))
        if "*" in str(expanded):
            result.extend(Path(x) for x in globmod.glob(str(expanded)) if Path(x).exists())
        elif expanded.exists():
            result.append(expanded)
    return result

CLEAN_TARGETS = {
    "windows_temp": {
        "label": "Fichiers temporaires Windows",
        "icon": "🗑",
        "paths": [
            os.environ.get("TEMP", ""),
            os.environ.get("TMP", ""),
            "C:/Windows/Temp",
        ],
    },
    "prefetch": {
        "label": "Windows Prefetch",
        "icon": "⚡",
        "paths": ["C:/Windows/Prefetch"],
    },
    "user_temp": {
        "label": "Fichiers temporaires utilisateur",
        "icon": "📁",
        "paths": [
            str(HOME / "AppData/Local/Temp"),
            str(HOME / "AppData/Local/CrashDumps"),
            str(HOME / "AppData/Local/D3DSCache"),
        ],
    },
    "browser_chrome": {
        "label": "Cache Google Chrome",
        "icon": "🌐",
        "paths": [
            str(HOME / "AppData/Local/Google/Chrome/User Data/Default/Cache"),
            str(HOME / "AppData/Local/Google/Chrome/User Data/Default/Code Cache"),
            str(HOME / "AppData/Local/Google/Chrome/User Data/Default/GPUCache"),
            str(HOME / "AppData/Local/Google/Chrome/User Data/Default/Service Worker/CacheStorage"),
        ],
    },
    "browser_edge": {
        "label": "Cache Microsoft Edge",
        "icon": "🌐",
        "paths": [
            str(HOME / "AppData/Local/Microsoft/Edge/User Data/Default/Cache"),
            str(HOME / "AppData/Local/Microsoft/Edge/User Data/Default/Code Cache"),
            str(HOME / "AppData/Local/Microsoft/Edge/User Data/Default/GPUCache"),
        ],
    },
    "browser_firefox": {
        "label": "Cache Mozilla Firefox",
        "icon": "🦊",
        "paths": [
            str(HOME / "AppData/Local/Mozilla/Firefox/Profiles/*/cache2"),
        ],
    },
    "recycle_bin": {
        "label": "Corbeille",
        "icon": "🗑",
        "paths": [],  # handled specially via Windows API
    },
    "windows_logs": {
        "label": "Logs Windows",
        "icon": "📝",
        "paths": [
            "C:/Windows/Logs/CBS",
            "C:/Windows/Debug",
        ],
    },
    "thumbnails": {
        "label": "Miniatures (thumbnails)",
        "icon": "🖼",
        "paths": [
            str(HOME / "AppData/Local/Microsoft/Windows/Explorer/thumbcache_*"),
        ],
    },
    "windows_update": {
        "label": "Cache Windows Update",
        "icon": "🔄",
        "paths": [
            "C:/Windows/SoftwareDistribution/Download",
        ],
    },
    "recent_docs": {
        "label": "Documents récents",
        "icon": "📄",
        "paths": [
            str(HOME / "AppData/Roaming/Microsoft/Windows/Recent"),
        ],
    },
}

# --- Activity Timeline ---------------------------------------------------
TIMELINE = deque(maxlen=200)

def timeline_add(icon, text, category="info"):
    """Add an event to the activity timeline"""
    TIMELINE.appendleft({
        "time": datetime.now().isoformat(),
        "icon": icon,
        "text": text,
        "category": category,  # info, scan, clean, threat, system
    })

# --- Scan state ----------------------------------------------------------
class ScanState:
    def __init__(self):
        self.lock = threading.Lock()
        self.active = False
        self.scan_type = ""  # quick, full, custom
        self.paused = False
        self.stop_requested = False
        self.files_scanned = 0
        self.files_total = 0
        self.current_file = ""
        self.threats_found = []
        self.start_time = 0
        self.speed = 0  # files/sec
        self.progress = 0  # 0-100

SCAN = ScanState()

# --- Cleaning state -----------------------------------------------------
class CleanState:
    def __init__(self):
        self.lock = threading.Lock()
        self.results = {}  # category -> {files: int, size: int, items: [...]}
        self.total_files = 0
        self.total_size = 0
        self.scanning = False
        self.cleaning = False

CLEAN = CleanState()

# --- Cache Layer (TTL-based) ---------------------------------------------
class CachedValue:
    __slots__ = ("value", "ts", "ttl")
    def __init__(self, ttl=10):
        self.value = None
        self.ts = 0
        self.ttl = ttl
    def get(self):
        if time.time() - self.ts < self.ttl:
            return self.value
        return None
    def set(self, val):
        self.value = val
        self.ts = time.time()
        return val
    def invalidate(self):
        self.ts = 0

CACHE_DISK = CachedValue(ttl=15)
CACHE_STARTUP = CachedValue(ttl=30)
CACHE_QUARANTINE = CachedValue(ttl=5)
CACHE_HEALTH = CachedValue(ttl=5)

# --- Quarantine ----------------------------------------------------------
QUARANTINE_DB = QUARANTINE_DIR / "quarantine.json"

def load_quarantine():
    cached = CACHE_QUARANTINE.get()
    if cached is not None:
        return cached
    if QUARANTINE_DB.exists():
        try:
            data = json.loads(QUARANTINE_DB.read_text(encoding="utf-8"))
            return CACHE_QUARANTINE.set(data)
        except Exception:
            pass
    return CACHE_QUARANTINE.set([])

def save_quarantine(entries):
    QUARANTINE_DB.write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")
    CACHE_QUARANTINE.set(entries)

# --- Scan History --------------------------------------------------------
HISTORY_FILE = LOGS_DIR / "scan_history.json"

def load_history():
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return []

def save_history(entries):
    # Keep last 100
    HISTORY_FILE.write_text(json.dumps(entries[-100:], indent=2, ensure_ascii=False), encoding="utf-8")

def add_history_entry(scan_type, files_scanned, threats, duration, cleaned_size=0):
    entries = load_history()
    entries.append({
        "date": datetime.now().isoformat(),
        "type": scan_type,
        "files_scanned": files_scanned,
        "threats_found": len(threats),
        "threats": threats[:20],
        "duration_seconds": round(duration, 1),
        "cleaned_size": cleaned_size,
    })
    save_history(entries)

# --- Signature loading --------------------------------------------------
CUSTOM_SIGS_FILE = SIGNATURES_DIR / "custom_hashes.txt"

def load_custom_signatures():
    """Load additional hash signatures from file"""
    if CUSTOM_SIGS_FILE.exists():
        try:
            for line in CUSTOM_SIGS_FILE.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and len(line) == 64:
                    KNOWN_MALWARE_HASHES.add(line.lower())
        except Exception:
            pass

# --- YARA-like pattern rules --------------------------------------------
BINARY_RULES = [
    {
        "name": "Ransomware.CryptoIndicator",
        "severity": "critical",
        "patterns": [b"YOUR FILES HAVE BEEN ENCRYPTED", b"pay bitcoin", b"decrypt your files",
                     b"ATTENTION! All your files", b"bitcoin wallet", b"ransom"],
        "min_matches": 3,  # need 3+ matches to be sure (2 had false positives)
        "file_types": [".exe", ".dll", ".hta"],
    },
    {
        "name": "Trojan.Keylogger",
        "severity": "high",
        "patterns": [b"GetAsyncKeyState", b"SetWindowsHookExA", b"keylog",
                     b"GetForegroundWindow", b"GetWindowText"],
        "min_matches": 3,  # need 3+ — some legit tools use 1-2 of these
        "file_types": [".exe", ".dll"],
    },
    {
        "name": "PUP.Miner",
        "severity": "medium",
        "patterns": [b"stratum+tcp://", b"xmrig", b"minerd", b"coinhive", b"cryptonight"],
        "min_matches": 1,  # any one of these is very specific to crypto miners
        "file_types": None,
    },
    {
        "name": "Trojan.Persistence",
        "severity": "medium",
        "patterns": [b"CurrentVersion\\Run", b"CurrentVersion\\RunOnce",
                     b"schtasks /create", b"reg add"],
        "min_matches": 3,  # raised — installers legitimately use 1-2 of these
        "file_types": [".scr", ".pif"],  # only truly suspicious types
    },
    {
        "name": "Obfuscated.PowerShell",
        "severity": "high",
        "patterns": [b"-enc ", b"FromBase64String", b"IEX(", b"Invoke-Expression",
                     b"-WindowStyle Hidden", b"bypass"],
        "min_matches": 3,  # raised — legit scripts may use 1-2 of these
        "file_types": [".ps1", ".bat", ".cmd"],
    },
    {
        "name": "Suspicious.Macro",
        "severity": "medium",
        "patterns": [b"Auto_Open", b"AutoOpen", b"Document_Open", b"Shell(",
                     b"WScript.Shell", b"Powershell", b"cmd /c"],
        "min_matches": 2,
        "file_types": [".docm", ".xlsm", ".pptm", ".doc", ".xls"],
    },
]

# =======================================================================
# SYSTEM CLEANER
# =======================================================================

def get_dir_size(path: Path) -> tuple:
    """Return (file_count, total_bytes, file_list) for a directory"""
    total_size = 0
    file_count = 0
    items = []
    try:
        for entry in os.scandir(str(path)):
            try:
                if entry.is_file(follow_symlinks=False):
                    size = entry.stat().st_size
                    total_size += size
                    file_count += 1
                    items.append({"path": entry.path, "size": size, "name": entry.name})
                elif entry.is_dir(follow_symlinks=False):
                    c, s, sub = get_dir_size(Path(entry.path))
                    total_size += s
                    file_count += c
                    items.extend(sub)
            except (PermissionError, OSError):
                pass
    except (PermissionError, OSError):
        pass
    return file_count, total_size, items

def scan_clean_targets():
    """Scan all cleaning categories, return results"""
    with CLEAN.lock:
        CLEAN.scanning = True
        CLEAN.results = {}
        CLEAN.total_files = 0
        CLEAN.total_size = 0

    results = {}
    for key, target in CLEAN_TARGETS.items():
        paths = expand_paths(target["paths"])
        cat_files = 0
        cat_size = 0
        cat_items = []

        for p in paths:
            try:
                count, size, items = get_dir_size(p)
                cat_files += count
                cat_size += size
                cat_items.extend(items[:50])  # Cap items for UI
            except Exception:
                pass

        # Special: recycle bin size estimation
        if key == "recycle_bin" and IS_WINDOWS:
            try:
                import ctypes
                from ctypes import wintypes
                class SHQUERYRBINFO(ctypes.Structure):
                    _fields_ = [("cbSize", wintypes.DWORD),
                                ("i64Size", ctypes.c_longlong),
                                ("i64NumItems", ctypes.c_longlong)]
                info = SHQUERYRBINFO()
                info.cbSize = ctypes.sizeof(SHQUERYRBINFO)
                result = ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info))
                if result == 0:
                    cat_size = info.i64Size
                    cat_files = info.i64NumItems
            except Exception:
                pass

        results[key] = {
            "label": target["label"],
            "icon": target["icon"],
            "files": cat_files,
            "size": cat_size,
            "items": cat_items[:30],
        }

    with CLEAN.lock:
        CLEAN.results = results
        CLEAN.total_files = sum(r["files"] for r in results.values())
        CLEAN.total_size = sum(r["size"] for r in results.values())
        CLEAN.scanning = False

    timeline_add("🔍", f"Scan terminé: {CLEAN.total_files} fichiers trouvés ({format_size(CLEAN.total_size)})", "scan")
    return results

# --- Browser detection & close -------------------------------------------
BROWSER_PROCESSES = {
    "browser_chrome":  ["chrome.exe", "GoogleCrashHandler.exe"],
    "browser_edge":    ["msedge.exe"],
    "browser_firefox": ["firefox.exe"],
}

def get_running_browsers(category: str) -> list:
    """Check if browser processes are running for a given category"""
    if not psutil:
        return []
    proc_names = BROWSER_PROCESSES.get(category, [])
    if not proc_names:
        return []
    running = []
    for proc in psutil.process_iter(["name"]):
        try:
            if proc.info["name"] and proc.info["name"].lower() in [n.lower() for n in proc_names]:
                running.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return running

def close_browser(category: str) -> dict:
    """Gracefully close browser processes for a category"""
    procs = get_running_browsers(category)
    if not procs:
        return {"closed": 0, "browser": category}
    closed = 0
    for proc in procs:
        try:
            proc.terminate()  # graceful SIGTERM
            closed += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    # Wait up to 3s for graceful close
    if procs:
        gone, alive = psutil.wait_procs(procs, timeout=3)
        for p in alive:
            try:
                p.kill()  # force kill if still alive
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    time.sleep(0.5)  # brief wait for file locks to release
    browser_name = {"browser_chrome": "Chrome", "browser_edge": "Edge", "browser_firefox": "Firefox"}.get(category, category)
    timeline_add("🌐", f"{browser_name} fermé ({closed} processus) pour nettoyage cache", "clean")
    return {"closed": closed, "browser": category}


def clean_category(category: str, force_close_browser: bool = False) -> dict:
    """Clean files in a specific category"""
    target = CLEAN_TARGETS.get(category)
    if not target:
        return {"error": "Catégorie inconnue"}

    if category == "recycle_bin":
        return clean_recycle_bin()

    # Browser cache: check if browser is running
    if category in BROWSER_PROCESSES:
        running = get_running_browsers(category)
        if running and not force_close_browser:
            browser_name = {"browser_chrome": "Chrome", "browser_edge": "Edge", "browser_firefox": "Firefox"}.get(category, category)
            return {
                "category": category,
                "cleaned_files": 0,
                "cleaned_size": 0,
                "errors": 0,
                "browser_running": True,
                "browser_name": browser_name,
                "pid_count": len(running),
            }
        elif running and force_close_browser:
            close_browser(category)

    paths = expand_paths(target["paths"])
    cleaned_files = 0
    cleaned_size = 0
    errors = 0

    for p in paths:
        try:
            for entry in os.scandir(str(p)):
                try:
                    if entry.is_file(follow_symlinks=False):
                        size = entry.stat().st_size
                        os.unlink(entry.path)
                        cleaned_files += 1
                        cleaned_size += size
                    elif entry.is_dir(follow_symlinks=False):
                        size = sum(f.stat().st_size for f in Path(entry.path).rglob("*") if f.is_file())
                        shutil.rmtree(entry.path, ignore_errors=True)
                        cleaned_files += 1
                        cleaned_size += size
                except (PermissionError, OSError):
                    errors += 1
        except (PermissionError, OSError):
            errors += 1

    return {
        "category": category,
        "cleaned_files": cleaned_files,
        "cleaned_size": cleaned_size,
        "errors": errors,
    }

def clean_recycle_bin() -> dict:
    """Empty the recycle bin"""
    if IS_WINDOWS:
        try:
            import ctypes
            # SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND
            ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x7)
            return {"category": "recycle_bin", "cleaned_files": 1, "cleaned_size": 0, "errors": 0}
        except Exception as e:
            return {"category": "recycle_bin", "cleaned_files": 0, "cleaned_size": 0, "errors": 1}
    return {"category": "recycle_bin", "cleaned_files": 0, "cleaned_size": 0, "errors": 0}

def clean_all() -> dict:
    """Clean all categories"""
    total_files = 0
    total_size = 0
    total_errors = 0
    details = []

    for category in CLEAN_TARGETS:
        result = clean_category(category)
        total_files += result.get("cleaned_files", 0)
        total_size += result.get("cleaned_size", 0)
        total_errors += result.get("errors", 0)
        details.append(result)

    CFG.last_clean = datetime.now().isoformat()
    save_settings()

    add_history_entry("clean", total_files, [], 0, total_size)
    timeline_add("🧹", f"Nettoyage complet: {total_files} fichiers supprimés ({format_size(total_size)})", "clean")

    return {
        "total_files": total_files,
        "total_size": total_size,
        "total_errors": total_errors,
        "details": details,
    }

# =======================================================================
# REGISTRY CLEANER (Windows only)
# =======================================================================

def scan_registry() -> list:
    """Scan Windows registry for orphaned entries"""
    if not IS_WINDOWS or winreg is None:
        return []

    issues = []

    # Check uninstall keys for invalid paths
    uninstall_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    for hive, path in uninstall_paths:
        try:
            key = winreg.OpenKey(hive, path)
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name)
                    try:
                        install_loc, _ = winreg.QueryValueEx(subkey, "InstallLocation")
                        if install_loc and not Path(install_loc).exists():
                            issues.append({
                                "type": "orphaned_uninstall",
                                "key": f"{path}\\{subkey_name}",
                                "value": install_loc,
                                "description": f"Programme désinstallé: chemin introuvable",
                            })
                    except FileNotFoundError:
                        pass
                    winreg.CloseKey(subkey)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass

    # Check Run keys for invalid executables
    run_paths = [
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ]

    for hive, path in run_paths:
        try:
            key = winreg.OpenKey(hive, path)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    # Extract executable path from command line
                    exe_path = value.strip('"').split('"')[0].split(" ")[0]
                    if exe_path and not Path(exe_path).exists() and not shutil.which(exe_path):
                        issues.append({
                            "type": "orphaned_startup",
                            "key": f"{path}\\{name}",
                            "value": value,
                            "description": f"Programme démarrage: exécutable introuvable",
                        })
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass

    # Check file associations for invalid handlers
    try:
        key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, "")
        i = 0
        checked = 0
        while checked < 200:
            try:
                subkey_name = winreg.EnumKey(key, i)
                if subkey_name.startswith("."):
                    try:
                        ext_key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, subkey_name)
                        handler, _ = winreg.QueryValueEx(ext_key, "")
                        if handler:
                            try:
                                handler_key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, handler)
                                winreg.CloseKey(handler_key)
                            except FileNotFoundError:
                                issues.append({
                                    "type": "orphaned_extension",
                                    "key": f"HKCR\\{subkey_name}",
                                    "value": handler,
                                    "description": f"Association fichier orpheline: {subkey_name} -> {handler}",
                                })
                        winreg.CloseKey(ext_key)
                    except (FileNotFoundError, OSError):
                        pass
                    checked += 1
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except Exception:
        pass

    return issues

def clean_registry_entry(entry: dict) -> bool:
    """Remove a specific registry entry — SAFE MODE: only removes clearly orphaned entries"""
    if not IS_WINDOWS or winreg is None:
        return False
    # Registry cleaning is inherently risky — we only remove startup entries
    # that point to non-existent executables
    if entry.get("type") == "orphaned_startup":
        try:
            parts = entry["key"].rsplit("\\", 1)
            path = parts[0]
            name = parts[1]
            hive = winreg.HKEY_CURRENT_USER if "HKCU" in path or "CurrentUser" in path else winreg.HKEY_LOCAL_MACHINE
            key = winreg.OpenKey(hive, path.split("\\", 1)[-1] if "\\" in path else path,
                                0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, name)
            winreg.CloseKey(key)
            return True
        except Exception:
            return False
    return False

# =======================================================================
# STARTUP MANAGER
# =======================================================================

def get_startup_programs() -> list:
    """Get list of programs that run at startup (cached)"""
    cached = CACHE_STARTUP.get()
    if cached is not None:
        return cached
    programs = []

    if not IS_WINDOWS or winreg is None:
        return CACHE_STARTUP.set(programs)

    # Registry Run keys
    run_keys = [
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Utilisateur"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Système"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Système (32-bit)"),
    ]

    for hive, path, scope in run_keys:
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    # Extract exe path
                    exe_path = value.strip('"').split('"')[0].split(" ")[0]
                    exists = Path(exe_path).exists() if exe_path else False
                    programs.append({
                        "name": name,
                        "command": value,
                        "path": exe_path,
                        "scope": scope,
                        "enabled": True,
                        "exists": exists,
                        "source": "registry",
                        "hive": "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM",
                        "reg_path": path,
                    })
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass

    # Startup folder
    startup_dirs = [
        (HOME / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup", "Utilisateur"),
        (Path("C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup"), "Système"),
    ]

    for startup_dir, scope in startup_dirs:
        if startup_dir.exists():
            for f in startup_dir.iterdir():
                if f.suffix.lower() in (".lnk", ".bat", ".cmd", ".exe", ".url"):
                    programs.append({
                        "name": f.stem,
                        "command": str(f),
                        "path": str(f),
                        "scope": scope,
                        "enabled": True,
                        "exists": True,
                        "source": "folder",
                        "folder": str(startup_dir),
                    })

    return CACHE_STARTUP.set(programs)

def toggle_startup_program(name: str, hive: str, reg_path: str, enabled: bool) -> bool:
    """Enable/disable a startup registry entry by moving to/from a disabled subkey"""
    if not IS_WINDOWS or winreg is None:
        return False

    hive_key = winreg.HKEY_CURRENT_USER if hive == "HKCU" else winreg.HKEY_LOCAL_MACHINE
    disabled_path = reg_path.replace("\\Run", "\\Run_disabled_by_CleanGuard")

    try:
        if not enabled:
            # Move from Run to disabled
            src = winreg.OpenKey(hive_key, reg_path, 0, winreg.KEY_READ)
            value, vtype = winreg.QueryValueEx(src, name)
            winreg.CloseKey(src)

            # Create disabled key if needed
            try:
                dst = winreg.OpenKey(hive_key, disabled_path, 0, winreg.KEY_SET_VALUE)
            except FileNotFoundError:
                dst = winreg.CreateKey(hive_key, disabled_path)
            winreg.SetValueEx(dst, name, 0, vtype, value)
            winreg.CloseKey(dst)

            # Delete from original
            src = winreg.OpenKey(hive_key, reg_path, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(src, name)
            winreg.CloseKey(src)
        else:
            # Move from disabled to Run
            src = winreg.OpenKey(hive_key, disabled_path, 0, winreg.KEY_READ)
            value, vtype = winreg.QueryValueEx(src, name)
            winreg.CloseKey(src)

            dst = winreg.OpenKey(hive_key, reg_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(dst, name, 0, vtype, value)
            winreg.CloseKey(dst)

            src = winreg.OpenKey(hive_key, disabled_path, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(src, name)
            winreg.CloseKey(src)

        return True
    except Exception as e:
        print(f"[!] Toggle startup error: {e}")
        return False

# =======================================================================
# DISK ANALYZER
# =======================================================================

def get_disk_info() -> list:
    """Get disk partition info (cached)"""
    cached = CACHE_DISK.get()
    if cached is not None:
        return cached
    disks = []
    if psutil:
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent,
                })
            except Exception:
                pass
    else:
        # Fallback
        for drive in "CDEFGHIJ":
            p = Path(f"{drive}:/")
            if p.exists():
                try:
                    total, used, free = shutil.disk_usage(str(p))
                    disks.append({
                        "device": f"{drive}:",
                        "mountpoint": f"{drive}:\\",
                        "fstype": "?",
                        "total": total,
                        "used": used,
                        "free": free,
                        "percent": round(used * 100 / total, 1),
                    })
                except Exception:
                    pass
    return CACHE_DISK.set(disks)

def analyze_directory(path: str, depth: int = 1) -> list:
    """Analyze directory sizes for treemap"""
    results = []
    p = Path(path)
    if not p.exists():
        return results

    try:
        for entry in os.scandir(str(p)):
            try:
                if entry.is_dir(follow_symlinks=False):
                    total = 0
                    count = 0
                    try:
                        for f in Path(entry.path).rglob("*"):
                            if f.is_file():
                                total += f.stat().st_size
                                count += 1
                    except (PermissionError, OSError):
                        pass
                    results.append({
                        "name": entry.name,
                        "path": entry.path,
                        "size": total,
                        "files": count,
                        "type": "dir",
                    })
                elif entry.is_file(follow_symlinks=False):
                    results.append({
                        "name": entry.name,
                        "path": entry.path,
                        "size": entry.stat().st_size,
                        "type": "file",
                    })
            except (PermissionError, OSError):
                pass
    except (PermissionError, OSError):
        pass

    results.sort(key=lambda x: x["size"], reverse=True)
    return results[:50]

def find_large_files(path: str = None, min_size_mb: int = 100, limit: int = 50) -> list:
    """Find largest files on disk"""
    min_size = min_size_mb * 1024 * 1024
    search_path = Path(path) if path else HOME
    results = []

    try:
        for f in search_path.rglob("*"):
            try:
                if f.is_file() and f.stat().st_size >= min_size:
                    results.append({
                        "path": str(f),
                        "name": f.name,
                        "size": f.stat().st_size,
                        "ext": f.suffix.lower(),
                        "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                    })
            except (PermissionError, OSError):
                pass
    except (PermissionError, OSError):
        pass

    results.sort(key=lambda x: x["size"], reverse=True)
    return results[:limit]

# =======================================================================
# DUPLICATE FINDER
# =======================================================================

def find_duplicates(path: str = None, min_size_kb: int = 100) -> list:
    """Find duplicate files by SHA256 hash"""
    min_size = min_size_kb * 1024
    search_path = Path(path) if path else HOME
    size_groups = defaultdict(list)

    # Step 1: Group by file size
    try:
        for f in search_path.rglob("*"):
            try:
                if f.is_file():
                    size = f.stat().st_size
                    if size >= min_size:
                        size_groups[size].append(f)
            except (PermissionError, OSError):
                pass
    except (PermissionError, OSError):
        pass

    # Step 2: Hash files with same size
    duplicates = []
    for size, files in size_groups.items():
        if len(files) < 2:
            continue
        hash_groups = defaultdict(list)
        for f in files:
            try:
                # nosec B324 - MD5 is used as a non-cryptographic content fingerprint
                # for duplicate-file detection. Collision resistance is not required;
                # we already pre-bucket by file size to bound the search space.
                h = hashlib.md5(usedforsecurity=False)
                with open(f, "rb") as fh:
                    for chunk in iter(lambda: fh.read(8192), b""):
                        h.update(chunk)
                hash_groups[h.hexdigest()].append(f)
            except Exception:
                pass

        for hash_val, dup_files in hash_groups.items():
            if len(dup_files) >= 2:
                duplicates.append({
                    "hash": hash_val,
                    "size": size,
                    "count": len(dup_files),
                    "files": [str(f) for f in dup_files],
                })

    duplicates.sort(key=lambda x: x["size"] * x["count"], reverse=True)
    return duplicates[:30]

# =======================================================================
# ANTIVIRUS ENGINE
# =======================================================================

def compute_entropy(data: bytes) -> float:
    """Shannon entropy of binary data (0-8)"""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def check_pe_file(filepath: Path) -> list:
    """Analyze PE file for suspicious characteristics"""
    findings = []
    try:
        with open(filepath, "rb") as f:
            header = f.read(2)
            if header != b"MZ":
                return findings
            data = header + f.read(min(filepath.stat().st_size, 2 * 1024 * 1024))  # Read up to 2MB

        # Entropy check
        entropy = compute_entropy(data)
        if entropy > CFG.entropy_threshold:
            findings.append({
                "type": "heuristic",
                "name": "Suspicious.HighEntropy",
                "severity": "medium",
                "detail": f"Entropie élevée ({entropy:.2f}/8.0) — fichier probablement packé ou chiffré",
            })

        # Size check (very small PE = dropper)
        if len(data) < 10240 and b"MZ" in data[:2]:
            findings.append({
                "type": "heuristic",
                "name": "Suspicious.SmallPE",
                "severity": "low",
                "detail": f"PE très petit ({len(data)} bytes) — possible dropper",
            })

        # Suspicious imports check — only flag injection-level APIs
        suspicious_count = 0
        found_imports = []
        for imp in SUSPICIOUS_IMPORTS:
            if imp in data:
                suspicious_count += 1
                found_imports.append(imp.decode(errors="ignore"))

        if suspicious_count >= 4:
            findings.append({
                "type": "heuristic",
                "name": "Suspicious.APIImports",
                "severity": "high",
                "detail": f"{suspicious_count} imports suspects: {', '.join(found_imports[:5])}",
            })
        elif suspicious_count >= 3:
            findings.append({
                "type": "heuristic",
                "name": "Suspicious.APIImports",
                "severity": "medium",
                "detail": f"{suspicious_count} imports suspects: {', '.join(found_imports[:5])}",
            })
        # NOTE: threshold raised from 2->3 to avoid flagging legitimate software

        # PE analysis with pefile
        if HAS_PEFILE:
            try:
                pe = pefile.PE(data=data, fast_load=True)
                # Check for no imports (suspicious)
                if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT") or len(pe.DIRECTORY_ENTRY_IMPORT) == 0:
                    findings.append({
                        "type": "heuristic",
                        "name": "Suspicious.NoImports",
                        "severity": "medium",
                        "detail": "PE sans table d'imports — probable shellcode ou packer",
                    })
                # Check for packed sections
                for section in pe.sections:
                    name = section.Name.rstrip(b"\x00").decode(errors="ignore")
                    if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
                        findings.append({
                            "type": "heuristic",
                            "name": "Suspicious.PackedSection",
                            "severity": "low",
                            "detail": f"Section '{name}' vide sur disque mais allouée en mémoire — packed",
                        })
                pe.close()
            except Exception:
                pass

    except Exception:
        pass

    return findings

def check_binary_rules(filepath: Path, data: bytes, data_lower: bytes = None) -> list:
    """Check file against YARA-like binary rules"""
    findings = []
    ext = filepath.suffix.lower()
    # Pre-compute lowercase once instead of per-rule
    if data_lower is None:
        data_lower = data.lower()

    for rule in BINARY_RULES:
        if rule["file_types"] and ext not in rule["file_types"]:
            continue
        matches = sum(1 for p in rule["patterns"] if p.lower() in data_lower)
        if matches >= rule["min_matches"]:
            findings.append({
                "type": "pattern",
                "name": rule["name"],
                "severity": rule["severity"],
                "detail": f"Pattern détecté: {matches}/{len(rule['patterns'])} correspondances",
            })

    return findings

def scan_file(filepath: Path) -> list:
    """Scan a single file for threats — optimized single-read"""
    findings = []

    try:
        stat = filepath.stat()
        size = stat.st_size

        # Skip too large or empty files
        if size > CFG.max_file_size_mb * 1024 * 1024 or size == 0:
            return findings

        # Skip whitelisted paths (Program Files, Windows, etc.)
        path_lower = str(filepath).lower()
        if any(wp in path_lower for wp in WHITELIST_PATHS):
            return findings

        ext = filepath.suffix.lower()
        name_lower = filepath.name.lower()

        # Double extension check (fast, no I/O)
        for pattern in DOUBLE_EXT_PATTERNS:
            if name_lower.endswith(pattern):
                findings.append({
                    "type": "heuristic",
                    "name": "Suspicious.DoubleExtension",
                    "severity": "high",
                    "detail": f"Double extension suspecte: {filepath.name}",
                })
                break

        # -- Single file read for all checks ------------------------------
        read_size = min(size, 2 * 1024 * 1024)  # Cap at 2MB for analysis
        need_deep = ext in (".exe", ".scr", ".pif", ".com")

        try:
            sha256 = hashlib.sha256()
            data = b""
            with open(filepath, "rb") as f:
                # Read first chunk for analysis + hash
                data = f.read(read_size)
                sha256.update(data)
                # Continue hashing rest of file if larger
                if size > read_size:
                    for chunk in iter(lambda: f.read(65536), b""):
                        sha256.update(chunk)

            file_hash = sha256.hexdigest()

            # Hash check
            if file_hash in KNOWN_MALWARE_HASHES:
                findings.append({
                    "type": "signature",
                    "name": "Malware.KnownHash",
                    "severity": "critical",
                    "detail": f"Hash SHA256 correspondant à un malware connu",
                    "hash": file_hash,
                })

            # EICAR pattern check (in first 256 bytes)
            if EICAR_PATTERN in data[:256]:
                findings.append({
                    "type": "signature",
                    "name": "EICAR.TestFile",
                    "severity": "critical",
                    "detail": "Fichier test antivirus EICAR détecté",
                })

            # PE analysis for executables (reuses data already in memory)
            if ext in (".exe", ".dll", ".scr", ".sys", ".drv", ".ocx", ".cpl") and data[:2] == b"MZ":
                findings.extend(check_pe_file(filepath))

            # Binary pattern rules (reuses data, pre-compute lowercase once)
            if need_deep and data:
                data_lower = data.lower()
                findings.extend(check_binary_rules(filepath, data, data_lower))

        except (PermissionError, OSError):
            pass

    except (PermissionError, OSError):
        pass

    return findings

def get_scan_paths(scan_type: str, custom_path: str = None) -> list:
    """Get list of paths to scan based on scan type"""
    if scan_type == "custom" and custom_path:
        return [Path(custom_path)]

    paths = []
    if scan_type == "quick":
        paths = [
            Path(os.environ.get("TEMP", "")),
            HOME / "Downloads",
            HOME / "Desktop",
            HOME / "AppData/Local/Temp",
            HOME / "AppData/Roaming",
            Path("C:/Windows/System32") if IS_WINDOWS else Path("/usr/bin"),
        ]
        # Add startup locations
        paths.append(HOME / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup")
    elif scan_type == "full":
        # All drives
        if IS_WINDOWS:
            for drive in "CDEFGHIJ":
                p = Path(f"{drive}:/")
                if p.exists():
                    paths.append(p)
        else:
            paths = [Path("/")]

    return [p for p in paths if p.exists()]

def count_files_in_paths(paths: list) -> int:
    """Fast estimate of total files — sample-based, not full enumeration"""
    total = 0
    for p in paths:
        try:
            # Quick count: only enumerate top 2 levels for estimation
            count = 0
            dirs = 0
            for entry in os.scandir(str(p)):
                if entry.is_file(follow_symlinks=False):
                    count += 1
                elif entry.is_dir(follow_symlinks=False):
                    dirs += 1
                    try:
                        sub = sum(1 for _ in os.scandir(entry.path))
                        count += sub * 3  # rough estimate: each subdir ~3x its direct entries
                    except (PermissionError, OSError):
                        count += 50  # default estimate per inaccessible dir
            total += max(count, dirs * 100)  # at least 100 files per directory
        except (PermissionError, OSError):
            total += 5000  # default estimate
    return max(total, 1)

def run_scan(scan_type: str, custom_path: str = None, ws_broadcast=None):
    """Run antivirus scan in background thread"""
    with SCAN.lock:
        if SCAN.active:
            return
        SCAN.active = True
        SCAN.scan_type = scan_type
        SCAN.paused = False
        SCAN.stop_requested = False
        SCAN.files_scanned = 0
        SCAN.files_total = 0
        SCAN.current_file = ""
        SCAN.threats_found = []
        SCAN.start_time = time.time()
        SCAN.progress = 0

    scan_labels = {"quick": "rapide", "full": "complet", "custom": "personnalisé"}
    timeline_add("🔍", f"Scan antivirus {scan_labels.get(scan_type, scan_type)} démarré", "scan")

    paths = get_scan_paths(scan_type, custom_path)
    if not paths:
        with SCAN.lock:
            SCAN.active = False
        return

    # Quick estimate
    SCAN.files_total = count_files_in_paths(paths) if scan_type != "full" else 100000

    try:
        for scan_path in paths:
            if SCAN.stop_requested:
                break
            try:
                for filepath in scan_path.rglob("*"):
                    if SCAN.stop_requested:
                        break
                    while SCAN.paused:
                        time.sleep(0.2)
                        if SCAN.stop_requested:
                            break

                    if not filepath.is_file():
                        continue

                    # Skip exclusions
                    fp_str = str(filepath)
                    if any(excl in fp_str for excl in CFG.exclusions):
                        continue

                    # Skip our own quarantine
                    if str(QUARANTINE_DIR) in fp_str:
                        continue

                    SCAN.current_file = fp_str
                    SCAN.files_scanned += 1

                    # Update progress
                    elapsed = time.time() - SCAN.start_time
                    SCAN.speed = SCAN.files_scanned / max(elapsed, 0.1)
                    if SCAN.files_total > 0:
                        SCAN.progress = min(99, int(SCAN.files_scanned * 100 / SCAN.files_total))

                    # Scan the file
                    threats = scan_file(filepath)
                    if threats:
                        for t in threats:
                            t["file"] = fp_str
                            t["size"] = filepath.stat().st_size
                            t["date"] = datetime.now().isoformat()
                        SCAN.threats_found.extend(threats)

                        # Log each threat to timeline
                        for t in threats:
                            sev_icon = "🔴" if t["severity"] == "critical" else "🟠" if t["severity"] == "high" else "🟡"
                            timeline_add(sev_icon, f"{t['name']} — {filepath.name}", "threat")

                        # Auto-quarantine critical threats
                        if CFG.auto_quarantine:
                            for t in threats:
                                if t["severity"] in ("critical", "high"):
                                    quarantine_file(filepath, t["name"])

            except (PermissionError, OSError):
                pass

    finally:
        duration = time.time() - SCAN.start_time
        SCAN.progress = 100
        SCAN.active = False
        SCAN.current_file = ""
        CFG.last_scan = datetime.now().isoformat()
        save_settings()

        add_history_entry(
            scan_type,
            SCAN.files_scanned,
            [{"name": t["name"], "file": t["file"], "severity": t["severity"]} for t in SCAN.threats_found],
            duration,
        )
        timeline_add("✅", f"Scan terminé: {SCAN.files_scanned} fichiers, {len(SCAN.threats_found)} menaces en {int(duration)}s", "scan")

# --- Process Scanner -----------------------------------------------------

def scan_processes() -> list:
    """Scan running processes for suspicious indicators"""
    if not psutil:
        return [{"error": "psutil non installé — pip install psutil"}]

    suspicious = []
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "cpu_percent", "memory_info", "status"]):
        try:
            info = proc.info
            exe = info.get("exe") or ""
            name = info.get("name") or ""
            cmdline = " ".join(info.get("cmdline") or [])
            findings = []

            # Check if executable exists
            if exe and not Path(exe).exists():
                findings.append("Exécutable introuvable")

            # Check for suspicious names
            sus_names = ["svchost", "csrss", "lsass", "services", "explorer"]
            name_lower = name.lower().replace(".exe", "")
            if name_lower in sus_names and exe:
                expected = "C:\\Windows\\System32\\"
                if not exe.lower().startswith(expected.lower()):
                    findings.append(f"Nom système mais chemin inhabituel: {exe}")

            # Check for hidden/obfuscated commands
            if cmdline:
                if "powershell" in cmdline.lower() and ("-enc" in cmdline.lower() or "base64" in cmdline.lower()):
                    findings.append("PowerShell avec commande encodée")
                if "cmd /c" in cmdline.lower() and "http" in cmdline.lower():
                    findings.append("CMD avec téléchargement réseau")

            # Very high CPU
            cpu = info.get("cpu_percent", 0)
            if cpu and cpu > 80:
                findings.append(f"Utilisation CPU très élevée: {cpu}%")

            if findings:
                mem = info.get("memory_info")
                suspicious.append({
                    "pid": info["pid"],
                    "name": name,
                    "exe": exe,
                    "cpu": cpu,
                    "memory": mem.rss if mem else 0,
                    "findings": findings,
                    "cmdline": cmdline[:200],
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return suspicious

# =======================================================================
# QUARANTINE
# =======================================================================

def quarantine_file(filepath: Path, threat_name: str) -> bool:
    """Move file to quarantine"""
    try:
        filepath = Path(filepath)
        if not filepath.exists():
            return False

        # Generate quarantine filename
        q_name = f"{int(time.time())}_{filepath.name}.quarantined"
        q_path = QUARANTINE_DIR / q_name

        # Move file
        shutil.move(str(filepath), str(q_path))

        # Record in quarantine DB
        entries = load_quarantine()
        entries.append({
            "original_path": str(filepath),
            "quarantine_path": str(q_path),
            "quarantine_name": q_name,
            "threat_name": threat_name,
            "date": datetime.now().isoformat(),
            "size": q_path.stat().st_size,
        })
        save_quarantine(entries)
        timeline_add("🔒", f"Quarantaine: {filepath.name} ({threat_name})", "threat")
        return True
    except Exception as e:
        print(f"[!] Quarantine error: {e}")
        return False

def restore_from_quarantine(q_name: str) -> bool:
    """Restore file from quarantine to original location"""
    entries = load_quarantine()
    for entry in entries:
        if entry["quarantine_name"] == q_name:
            q_path = Path(entry["quarantine_path"])
            orig_path = Path(entry["original_path"])
            if q_path.exists():
                try:
                    orig_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(q_path), str(orig_path))
                    entries.remove(entry)
                    save_quarantine(entries)
                    return True
                except Exception:
                    return False
    return False

def delete_from_quarantine(q_name: str) -> bool:
    """Permanently delete a quarantined file"""
    entries = load_quarantine()
    for entry in entries:
        if entry["quarantine_name"] == q_name:
            q_path = Path(entry["quarantine_path"])
            if q_path.exists():
                try:
                    os.unlink(str(q_path))
                except Exception:
                    pass
            entries.remove(entry)
            save_quarantine(entries)
            return True
    return False

# =======================================================================
# REAL-TIME PROTECTION (watchdog)
# =======================================================================

class RealtimeHandler(FileSystemEventHandler if HAS_WATCHDOG else object):
    def __init__(self, engine):
        if HAS_WATCHDOG:
            super().__init__()
        self.engine = engine

    def on_created(self, event):
        if event.is_directory:
            return
        filepath = Path(event.src_path)
        # Only scan executable and suspicious files
        if filepath.suffix.lower() in DANGEROUS_EXTENSIONS:
            threading.Thread(target=self._check_file, args=(filepath,), daemon=True).start()

    def on_modified(self, event):
        if event.is_directory:
            return
        filepath = Path(event.src_path)
        if filepath.suffix.lower() in DANGEROUS_EXTENSIONS:
            threading.Thread(target=self._check_file, args=(filepath,), daemon=True).start()

    def _check_file(self, filepath):
        time.sleep(0.5)  # Wait for file write to complete
        if not filepath.exists():
            return
        threats = scan_file(filepath)
        if threats:
            critical = [t for t in threats if t["severity"] in ("critical", "high")]
            if critical and CFG.auto_quarantine:
                quarantine_file(filepath, critical[0]["name"])
            # Broadcast alert
            if self.engine:
                alert = {
                    "type": "realtime_alert",
                    "file": str(filepath),
                    "threats": threats,
                    "quarantined": bool(critical and CFG.auto_quarantine),
                    "time": datetime.now().isoformat(),
                }
                asyncio.run_coroutine_threadsafe(
                    self.engine.broadcast(alert),
                    self.engine.loop
                )

REALTIME_OBSERVER = None

def start_realtime_protection(engine=None):
    global REALTIME_OBSERVER
    if not HAS_WATCHDOG:
        print("[!] watchdog non installé — protection temps réel indisponible")
        return False
    if REALTIME_OBSERVER:
        return True  # Already running

    handler = RealtimeHandler(engine)
    REALTIME_OBSERVER = Observer()

    watch_paths = [
        str(HOME / "Downloads"),
        str(HOME / "Desktop"),
        str(HOME / "Documents"),
        os.environ.get("TEMP", ""),
        str(HOME / "AppData/Local/Temp"),
    ]

    for wp in watch_paths:
        if wp and Path(wp).exists():
            try:
                REALTIME_OBSERVER.schedule(handler, wp, recursive=False)
            except Exception:
                pass

    REALTIME_OBSERVER.start()
    CFG.realtime_protection = True
    save_settings()
    timeline_add("🛡", "Protection temps réel activée", "system")
    return True

def stop_realtime_protection():
    global REALTIME_OBSERVER
    if REALTIME_OBSERVER:
        REALTIME_OBSERVER.stop()
        REALTIME_OBSERVER.join(timeout=5)
        REALTIME_OBSERVER = None
    CFG.realtime_protection = False
    save_settings()
    timeline_add("⚠", "Protection temps réel désactivée", "system")

# =======================================================================
# SYSTEM INFO
# =======================================================================

def get_system_info() -> dict:
    """Get system information"""
    info = {
        "os": f"{platform.system()} {platform.release()}",
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "hostname": platform.node(),
        "python": platform.python_version(),
        "cpu": "N/A",
        "cpu_count": os.cpu_count() or 0,
        "ram_total": 0,
        "ram_used": 0,
        "ram_percent": 0,
        "uptime": 0,
    }

    if psutil:
        try:
            mem = psutil.virtual_memory()
            info["ram_total"] = mem.total
            info["ram_used"] = mem.used
            info["ram_percent"] = mem.percent
            info["cpu"] = platform.processor() or "N/A"
            info["cpu_percent"] = psutil.cpu_percent(interval=0.1)
            info["uptime"] = int(time.time() - psutil.boot_time())
        except Exception:
            pass

    return info

# =======================================================================
# HEALTH SCORE
# =======================================================================

def compute_health_score() -> dict:
    """Compute system health score 0-100 (cached)"""
    cached = CACHE_HEALTH.get()
    if cached is not None:
        return cached
    score = 100
    factors = []

    # Disk space (max -20)
    disks = get_disk_info()
    for d in disks:
        if d["percent"] > 90:
            score -= 20
            factors.append({"label": f"Disque {d['device']} presque plein ({d['percent']}%)", "impact": -20})
        elif d["percent"] > 80:
            score -= 10
            factors.append({"label": f"Disque {d['device']} utilisé à {d['percent']}%", "impact": -10})

    # Temp files (max -15)
    if CLEAN.total_size > 2 * 1024 * 1024 * 1024:  # > 2GB
        score -= 15
        factors.append({"label": "Plus de 2 Go de fichiers temporaires", "impact": -15})
    elif CLEAN.total_size > 500 * 1024 * 1024:  # > 500MB
        score -= 5
        factors.append({"label": "Fichiers temporaires à nettoyer", "impact": -5})

    # Threats (max -30)
    if SCAN.threats_found:
        critical = sum(1 for t in SCAN.threats_found if t.get("severity") == "critical")
        high = sum(1 for t in SCAN.threats_found if t.get("severity") == "high")
        if critical:
            score -= 30
            factors.append({"label": f"{critical} menace(s) critique(s) détectée(s)", "impact": -30})
        elif high:
            score -= 20
            factors.append({"label": f"{high} menace(s) élevée(s) détectée(s)", "impact": -20})

    # Last scan age (max -15)
    if CFG.last_scan:
        try:
            last = datetime.fromisoformat(CFG.last_scan)
            days = (datetime.now() - last).days
            if days > 30:
                score -= 15
                factors.append({"label": f"Dernier scan il y a {days} jours", "impact": -15})
            elif days > 7:
                score -= 5
                factors.append({"label": f"Dernier scan il y a {days} jours", "impact": -5})
        except Exception:
            score -= 10
            factors.append({"label": "Aucun scan effectué", "impact": -10})
    else:
        score -= 10
        factors.append({"label": "Aucun scan effectué", "impact": -10})

    # Real-time protection (max -10)
    if not CFG.realtime_protection:
        score -= 10
        factors.append({"label": "Protection temps réel désactivée", "impact": -10})

    # Startup programs (max -5)
    startup = get_startup_programs()
    if len(startup) > 15:
        score -= 5
        factors.append({"label": f"{len(startup)} programmes au démarrage", "impact": -5})

    score = max(0, min(100, score))
    result = {
        "score": score,
        "grade": "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F",
        "factors": factors,
    }
    return CACHE_HEALTH.set(result)

# =======================================================================
# WEBSOCKET SERVER
# =======================================================================

class CleanGuardEngine:
    def __init__(self):
        self.clients = set()
        self.loop = None
        self.state_task = None

    async def broadcast(self, data):
        if not self.clients:
            return
        msg = json.dumps(data, default=str)
        disconnected = set()
        for ws in self.clients:
            try:
                await ws.send(msg)
            except Exception:
                disconnected.add(ws)
        self.clients -= disconnected

    def build_state(self) -> dict:
        """Build full state message (uses cached data for speed)"""
        health = compute_health_score()   # cached 5s
        quarantine = load_quarantine()    # cached 5s
        disks = get_disk_info()           # cached 15s

        return {
            "type": "state",
            "version": VERSION,
            "ts": time.time(),
            # Health
            "health_score": health["score"],
            "health_grade": health["grade"],
            "health_factors": health["factors"],
            # Cleaning
            "clean_scanning": CLEAN.scanning,
            "clean_cleaning": CLEAN.cleaning,
            "clean_results": CLEAN.results,
            "clean_total_files": CLEAN.total_files,
            "clean_total_size": CLEAN.total_size,
            # Scan
            "scan_active": SCAN.active,
            "scan_type": SCAN.scan_type,
            "scan_paused": SCAN.paused,
            "scan_progress": SCAN.progress,
            "scan_files_scanned": SCAN.files_scanned,
            "scan_files_total": SCAN.files_total,
            "scan_current_file": SCAN.current_file,
            "scan_speed": round(SCAN.speed),
            "scan_threats": SCAN.threats_found[-20:],
            "scan_threats_count": len(SCAN.threats_found),
            # Quarantine
            "quarantine": quarantine,
            "quarantine_count": len(quarantine),
            # Realtime
            "realtime_protection": CFG.realtime_protection,
            # System
            "disks": disks,
            # Config
            "last_scan": CFG.last_scan,
            "last_clean": CFG.last_clean,
            "heuristic_enabled": CFG.heuristic_enabled,
            "auto_quarantine": CFG.auto_quarantine,
            # Timeline
            "timeline": list(TIMELINE)[:30],
        }

    async def broadcast_state(self):
        """Periodically broadcast state — faster when scan/clean active"""
        while True:
            try:
                state = await asyncio.to_thread(self.build_state)
                await self.broadcast(state)
            except Exception as e:
                print(f"[!] Broadcast error: {e}")
            # Fast updates during active operations, slow when idle
            interval = 1 if (SCAN.active or CLEAN.scanning or CLEAN.cleaning) else 4
            await asyncio.sleep(interval)

    async def handle_command(self, ws, data):
        """Handle a WebSocket command — non-blocking"""
        cmd = data.get("cmd", "")

        if cmd == "get_state":
            state = await asyncio.to_thread(self.build_state)
            await ws.send(json.dumps(state, default=str))

        elif cmd == "get_system_info":
            info = await asyncio.to_thread(get_system_info)
            await ws.send(json.dumps({"type": "system_info", **info}, default=str))

        # -- Cleaning commands --------------------------------------------
        elif cmd == "scan_temp":
            threading.Thread(target=self._scan_clean, daemon=True).start()
            await ws.send(json.dumps({"type": "ack", "cmd": "scan_temp"}))

        elif cmd == "clean_all":
            threading.Thread(target=self._clean_all, daemon=True).start()
            await ws.send(json.dumps({"type": "ack", "cmd": "clean_all"}))

        elif cmd == "clean_category":
            cat = data.get("category", "")
            force = data.get("force_close_browser", False)
            result = await asyncio.to_thread(clean_category, cat, force)
            CACHE_HEALTH.invalidate()
            await ws.send(json.dumps({"type": "clean_result", **result}, default=str))

        # -- Registry -----------------------------------------------------
        elif cmd == "scan_registry":
            issues = await asyncio.to_thread(scan_registry)
            await ws.send(json.dumps({"type": "registry_results", "issues": issues}))

        elif cmd == "clean_registry":
            def _clean_reg():
                issues = scan_registry()
                cleaned = 0
                for issue in issues:
                    if clean_registry_entry(issue):
                        cleaned += 1
                return cleaned, len(issues)
            cleaned, total = await asyncio.to_thread(_clean_reg)
            await ws.send(json.dumps({"type": "registry_cleaned", "cleaned": cleaned, "total": total}))

        # -- Startup ------------------------------------------------------
        elif cmd == "get_startup_programs":
            programs = await asyncio.to_thread(get_startup_programs)
            await ws.send(json.dumps({"type": "startup_programs", "programs": programs}))

        elif cmd == "toggle_startup":
            name = data.get("name", "")
            hive = data.get("hive", "HKCU")
            reg_path = data.get("reg_path", "")
            enabled = data.get("enabled", True)
            result = await asyncio.to_thread(toggle_startup_program, name, hive, reg_path, enabled)
            CACHE_STARTUP.invalidate()
            await ws.send(json.dumps({"type": "startup_toggled", "success": result, "name": name}))

        # -- Antivirus ----------------------------------------------------
        elif cmd in ("quick_scan", "full_scan", "custom_scan"):
            scan_type = cmd.replace("_scan", "")
            custom_path = data.get("path", "")
            threading.Thread(target=run_scan, args=(scan_type, custom_path), daemon=True).start()
            await ws.send(json.dumps({"type": "ack", "cmd": cmd}))

        elif cmd == "stop_scan":
            SCAN.stop_requested = True
            await ws.send(json.dumps({"type": "ack", "cmd": "stop_scan"}))

        elif cmd == "pause_scan":
            SCAN.paused = True
            await ws.send(json.dumps({"type": "ack", "cmd": "pause_scan"}))

        elif cmd == "resume_scan":
            SCAN.paused = False
            await ws.send(json.dumps({"type": "ack", "cmd": "resume_scan"}))

        elif cmd == "scan_processes":
            results = await asyncio.to_thread(scan_processes)
            await ws.send(json.dumps({"type": "process_scan", "processes": results}, default=str))

        # -- Quarantine ---------------------------------------------------
        elif cmd == "get_quarantine":
            entries = load_quarantine()
            await ws.send(json.dumps({"type": "quarantine_list", "entries": entries}))

        elif cmd == "quarantine_restore":
            q_name = data.get("name", "")
            result = await asyncio.to_thread(restore_from_quarantine, q_name)
            await ws.send(json.dumps({"type": "quarantine_action", "action": "restore", "success": result}))

        elif cmd == "quarantine_delete":
            q_name = data.get("name", "")
            result = await asyncio.to_thread(delete_from_quarantine, q_name)
            await ws.send(json.dumps({"type": "quarantine_action", "action": "delete", "success": result}))

        # -- Disk ---------------------------------------------------------
        elif cmd == "analyze_disk":
            path = data.get("path", str(HOME))
            results = await asyncio.to_thread(analyze_directory, path)
            await ws.send(json.dumps({"type": "disk_analysis", "path": path, "items": results}, default=str))

        elif cmd == "get_large_files":
            path = data.get("path")
            min_mb = data.get("min_size_mb", 100)
            results = await asyncio.to_thread(find_large_files, path, min_mb)
            await ws.send(json.dumps({"type": "large_files", "files": results}, default=str))

        elif cmd == "scan_duplicates":
            path = data.get("path", str(HOME))
            threading.Thread(target=self._scan_duplicates, args=(path,), daemon=True).start()
            await ws.send(json.dumps({"type": "ack", "cmd": "scan_duplicates"}))

        # -- Real-time protection -----------------------------------------
        elif cmd == "toggle_realtime":
            if CFG.realtime_protection:
                stop_realtime_protection()
            else:
                start_realtime_protection(self)
            await ws.send(json.dumps({"type": "realtime_status", "enabled": CFG.realtime_protection}))

        # -- History ------------------------------------------------------
        elif cmd == "get_scan_history":
            history = load_history()
            await ws.send(json.dumps({"type": "scan_history", "entries": history}))

        # -- Settings -----------------------------------------------------
        elif cmd == "get_settings":
            await ws.send(json.dumps({"type": "settings", **asdict(CFG)}))

        elif cmd == "save_settings":
            settings = data.get("settings", {})
            for k, v in settings.items():
                if hasattr(CFG, k):
                    setattr(CFG, k, v)
            save_settings()
            await ws.send(json.dumps({"type": "settings_saved"}))

        else:
            await ws.send(json.dumps({"type": "error", "message": f"Commande inconnue: {cmd}"}))

    def _scan_clean(self):
        """Background scan clean targets"""
        scan_clean_targets()

    def _clean_all(self):
        """Background clean all"""
        with CLEAN.lock:
            CLEAN.cleaning = True
        clean_all()
        with CLEAN.lock:
            CLEAN.cleaning = False
        CACHE_HEALTH.invalidate()
        CACHE_DISK.invalidate()
        # Re-scan to update
        scan_clean_targets()

    def _scan_duplicates(self, path):
        """Background duplicate scan"""
        results = find_duplicates(path)
        asyncio.run_coroutine_threadsafe(
            self.broadcast({"type": "duplicate_results", "duplicates": results}),
            self.loop
        )

ENGINE = CleanGuardEngine()

# =======================================================================
# PYWEBVIEW JS BRIDGE API
# =======================================================================

try:
    import webview
    HAS_WEBVIEW = True
except ImportError:
    HAS_WEBVIEW = False

try:
    sys.path.insert(0, str(BASE_DIR.parent))
    from startup_utils import is_startup_enabled, toggle_startup as toggle_startup_reg, get_all_startup_states, minimize_to_tray
    HAS_STARTUP_UTILS = True
except ImportError:
    HAS_STARTUP_UTILS = False

class CleanGuardAPI:
    """API exposed to JavaScript via pywebview.api — instant calls, no WebSocket"""

    def __init__(self):
        self._window = None
        self._stop_broadcast = False

    def set_window(self, window):
        self._window = window

    # -- State ------------------------------------------------------------
    def get_state(self):
        return json.loads(json.dumps(ENGINE.build_state(), default=str))

    def get_system_info(self):
        return json.loads(json.dumps(get_system_info(), default=str))

    # -- Cleaning ---------------------------------------------------------
    def scan_temp(self):
        threading.Thread(target=ENGINE._scan_clean, daemon=True).start()
        return {"type": "ack", "cmd": "scan_temp"}

    def clean_all(self):
        threading.Thread(target=ENGINE._clean_all, daemon=True).start()
        return {"type": "ack", "cmd": "clean_all"}

    def clean_category(self, category, force_close_browser=False):
        result = clean_category(category, force_close_browser)
        CACHE_HEALTH.invalidate()
        return result

    # -- Registry ---------------------------------------------------------
    def scan_registry(self):
        return {"type": "registry_results", "issues": scan_registry()}

    def clean_registry(self):
        issues = scan_registry()
        cleaned = sum(1 for issue in issues if clean_registry_entry(issue))
        return {"type": "registry_cleaned", "cleaned": cleaned, "total": len(issues)}

    # -- Startup ----------------------------------------------------------
    def get_startup_programs(self):
        return {"type": "startup_programs", "programs": get_startup_programs()}

    def toggle_startup(self, name, hive="HKCU", reg_path="", enabled=True):
        result = toggle_startup_program(name, hive, reg_path, enabled)
        CACHE_STARTUP.invalidate()
        return {"type": "startup_toggled", "success": result, "name": name}

    # -- Antivirus --------------------------------------------------------
    def quick_scan(self):
        threading.Thread(target=run_scan, args=("quick",), daemon=True).start()
        return {"type": "ack", "cmd": "quick_scan"}

    def full_scan(self):
        threading.Thread(target=run_scan, args=("full",), daemon=True).start()
        return {"type": "ack", "cmd": "full_scan"}

    def custom_scan(self, path):
        threading.Thread(target=run_scan, args=("custom", path), daemon=True).start()
        return {"type": "ack", "cmd": "custom_scan"}

    def stop_scan(self):
        SCAN.stop_requested = True
        return {"type": "ack", "cmd": "stop_scan"}

    def pause_scan(self):
        SCAN.paused = True
        return {"type": "ack", "cmd": "pause_scan"}

    def resume_scan(self):
        SCAN.paused = False
        return {"type": "ack", "cmd": "resume_scan"}

    def scan_processes(self):
        return {"type": "process_scan", "processes": json.loads(json.dumps(scan_processes(), default=str))}

    # -- Quarantine -------------------------------------------------------
    def get_quarantine(self):
        return {"type": "quarantine_list", "entries": load_quarantine()}

    def quarantine_restore(self, name):
        result = restore_from_quarantine(name)
        return {"type": "quarantine_action", "action": "restore", "success": result}

    def quarantine_delete(self, name):
        result = delete_from_quarantine(name)
        return {"type": "quarantine_action", "action": "delete", "success": result}

    # -- Disk -------------------------------------------------------------
    def analyze_disk(self, path=None):
        path = path or str(HOME)
        results = analyze_directory(path)
        return json.loads(json.dumps({"type": "disk_analysis", "path": path, "items": results}, default=str))

    def get_large_files(self, path=None, min_size_mb=100):
        results = find_large_files(path, min_size_mb)
        return json.loads(json.dumps({"type": "large_files", "files": results}, default=str))

    def scan_duplicates(self, path=None):
        path = path or str(HOME)
        def _do():
            results = find_duplicates(path)
            if self._window:
                self._window.evaluate_js(f"handleMsg({json.dumps({'type': 'duplicate_results', 'duplicates': results}, default=str)})")
        threading.Thread(target=_do, daemon=True).start()
        return {"type": "ack", "cmd": "scan_duplicates"}

    # -- Real-time --------------------------------------------------------
    def toggle_realtime(self):
        if CFG.realtime_protection:
            stop_realtime_protection()
        else:
            start_realtime_protection(ENGINE)
        return {"type": "realtime_status", "enabled": CFG.realtime_protection}

    # -- History ----------------------------------------------------------
    def get_scan_history(self):
        return {"type": "scan_history", "entries": load_history()}

    # -- Settings ---------------------------------------------------------
    def get_settings(self):
        return {"type": "settings", **asdict(CFG)}

    def save_settings(self, settings):
        for k, v in settings.items():
            if hasattr(CFG, k):
                setattr(CFG, k, v)
        save_settings()
        return {"type": "settings_saved"}

    # -- Startup & Tray ------------------------------------------------
    def get_startup_state(self):
        if not HAS_STARTUP_UTILS:
            return {"enabled": False, "available": False}
        return {"enabled": is_startup_enabled("CleanGuard Pro"), "available": True}

    def toggle_startup_boot(self):
        if not HAS_STARTUP_UTILS:
            return {"enabled": False, "available": False}
        bat_path = str(BASE_DIR.parent / "LANCER_CLEANGUARD.bat")
        new_state = toggle_startup_reg("CleanGuard Pro", bat_path)
        return {"enabled": new_state, "available": True}

    def minimize_to_tray_action(self):
        if not HAS_STARTUP_UTILS or not self._window:
            return {"success": False}
        def _on_quit():
            if self._window:
                self._window.destroy()
        minimize_to_tray(self._window, "CleanGuard Pro", on_quit=_on_quit)
        return {"success": True}

    def get_all_startup_states(self):
        if not HAS_STARTUP_UTILS:
            return {}
        return get_all_startup_states()


def _pywebview_state_broadcast(api):
    """Background thread: push state to pywebview window periodically"""
    while not api._stop_broadcast:
        try:
            if api._window:
                state = ENGINE.build_state()
                js_data = json.dumps(state, default=str)
                api._window.evaluate_js(f"handleMsg({js_data})")
        except Exception:
            pass
        interval = 1 if (SCAN.active or CLEAN.scanning or CLEAN.cleaning) else 4
        time.sleep(interval)


# =======================================================================
# WEBSOCKET FALLBACK (when pywebview not available)
# =======================================================================

async def ws_handler(websocket):
    """WebSocket connection handler — fallback mode"""
    ENGINE.clients.add(websocket)
    remote = websocket.remote_address
    print(f"[+] Client connecté: {remote}")
    try:
        state = await asyncio.to_thread(ENGINE.build_state)
        await websocket.send(json.dumps(state, default=str))

        async for message in websocket:
            try:
                data = json.loads(message)
                await ENGINE.handle_command(websocket, data)
            except json.JSONDecodeError:
                await websocket.send(json.dumps({"type": "error", "message": "JSON invalide"}))
            except Exception as e:
                await websocket.send(json.dumps({"type": "error", "message": str(e)}))
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        ENGINE.clients.discard(websocket)
        print(f"[-] Client déconnecté: {remote}")

# =======================================================================
# MAIN
# =======================================================================

def format_size(size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(size) < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def main_webview():
    """Launch with pywebview — native window, direct API calls"""
    load_settings()
    load_custom_signatures()

    print(f"""
+======================================================+
|        CleanGuard Pro v{VERSION}                        |
|        Nettoyeur Système + Antivirus                 |
+======================================================+
|  Mode    : Fenêtre native (pywebview)                |
|  Protection: {'ON ' if CFG.realtime_protection else 'OFF'}                                    |
+======================================================+
    """)

    timeline_add("🚀", "CleanGuard Pro démarré", "system")

    # Initial scan of temp files
    threading.Thread(target=scan_clean_targets, daemon=True).start()

    # Start realtime protection if configured
    if CFG.realtime_protection:
        start_realtime_protection(ENGINE)

    api = CleanGuardAPI()
    dashboard_path = str(BASE_DIR / "cleanguard_dashboard.html")

    window = webview.create_window(
        f"CleanGuard Pro v{VERSION}",
        dashboard_path,
        js_api=api,
        width=1280,
        height=820,
        min_size=(900, 600),
        background_color="#0f0f13",
    )
    api.set_window(window)

    def on_loaded():
        print("[v] Dashboard chargé dans la fenêtre native")
        # Start periodic state push
        threading.Thread(target=_pywebview_state_broadcast, args=(api,), daemon=True).start()

    window.events.loaded += on_loaded

    try:
        webview.start(debug=False)
    finally:
        api._stop_broadcast = True
        stop_realtime_protection()
        save_settings()
        print("[*] CleanGuard Pro fermé.")


async def main_async():
    """Fallback: WebSocket mode when pywebview is not available"""
    load_settings()
    load_custom_signatures()

    ENGINE.loop = asyncio.get_event_loop()
    timeline_add("🚀", "CleanGuard Pro démarré (mode WebSocket)", "system")

    threading.Thread(target=scan_clean_targets, daemon=True).start()

    if CFG.realtime_protection:
        start_realtime_protection(ENGINE)

    ENGINE.state_task = asyncio.create_task(ENGINE.broadcast_state())

    port = CFG.ws_port
    print(f"""
+======================================================+
|        CleanGuard Pro v{VERSION}                        |
|        Nettoyeur Système + Antivirus                 |
+======================================================+
|  Mode    : WebSocket (fallback)                      |
|  WebSocket : ws://localhost:{port}                    |
|  Dashboard : cleanguard_dashboard.html               |
|  Protection: {'ON ' if CFG.realtime_protection else 'OFF'}                                    |
+======================================================+
    """)

    try:
        async with websockets.serve(ws_handler, "localhost", port):
            print(f"[v] Serveur WebSocket démarré sur le port {port}")
            await asyncio.Future()
    except Exception as e:
        for fallback in range(port + 1, port + 5):
            try:
                async with websockets.serve(ws_handler, "localhost", fallback):
                    print(f"[v] Serveur WebSocket démarré sur le port {fallback} (fallback)")
                    CFG.ws_port = fallback
                    save_settings()
                    await asyncio.Future()
            except Exception:
                continue
        print(f"[✗] Impossible de démarrer le serveur WebSocket: {e}")


def main():
    headless = "--headless" in sys.argv
    if headless:
        sys.argv.remove("--headless")

    if not headless and HAS_WEBVIEW:
        print("[*] pywebview détecté — lancement en mode fenêtre native")
        main_webview()
    else:
        print("[*] Mode " + ("headless (Cortex)" if headless else "WebSocket"))
        try:
            asyncio.run(main_async())
        except KeyboardInterrupt:
            print("\n[*] Arrêt de CleanGuard Pro...")
            stop_realtime_protection()
            save_settings()

if __name__ == "__main__":
    main()
