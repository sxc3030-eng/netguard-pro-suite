"""NetGuard AI — where resources are read from and where data is written.

Store / MSIX installs live under ``C:\\Program Files\\WindowsApps\\...`` which is
read-only, and a PyInstaller ``--onefile`` build extracts to a temp dir that
disappears at exit. Before this module every data file (settings, token,
pcap captures, reports, backups, log) was written next to ``netguard.py``,
so a packaged build crashed at import (``PermissionError`` on the log file)
or silently lost its settings on every launch.

Rules
-----
* ``RESOURCE_DIR`` — HTML dashboards, icons, bundled GeoIP DB (read-only).
* ``DATA_DIR``     — everything NetGuard writes.
    1. ``NETGUARD_DATA_DIR`` environment variable, when set (tests, portable use)
    2. the source directory, when running from source and it is writable
       (unchanged behaviour for development installs)
    3. ``%LOCALAPPDATA%\\NetGuard AI`` (Windows) or ``$XDG_DATA_HOME/NetGuard AI``
       otherwise — always for frozen / Store builds.
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_FROZEN = bool(getattr(sys, "frozen", False))

RESOURCE_DIR: str = getattr(sys, "_MEIPASS", None) or _HERE


def _default_data_dir() -> str:
    env = os.environ.get("NETGUARD_DATA_DIR")
    if env:
        return os.path.abspath(env)
    low = _HERE.lower()
    protected = "windowsapps" in low or "program files" in low
    if not _FROZEN and not protected and os.access(_HERE, os.W_OK):
        return _HERE
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "NetGuard AI")


DATA_DIR: str = _default_data_dir()


def data_path(*parts: str) -> str:
    return os.path.join(DATA_DIR, *parts)


def resource_path(*parts: str) -> str:
    return os.path.join(RESOURCE_DIR, *parts)


def ensure_data_dirs() -> str:
    """Create DATA_DIR and its standard sub-folders. Returns DATA_DIR."""
    for sub in ("", "captures", "reports", "backups", "logs", "geoip"):
        try:
            os.makedirs(os.path.join(DATA_DIR, sub) if sub else DATA_DIR, exist_ok=True)
        except OSError:
            pass
    return DATA_DIR


def is_frozen() -> bool:
    return _FROZEN


def is_store_build() -> bool:
    """True when running from a Microsoft Store / MSIX package.

    The Store handles purchase and updates: the homemade licence manager and the
    GitHub self-updater must step aside there (certification policies 10.8 / 11).
    Detection: exe under WindowsApps, or NETGUARD_STORE_BUILD=1 (CI / tests).
    """
    if os.environ.get("NETGUARD_STORE_BUILD", "").strip() in ("1", "true", "yes"):
        return True
    exe = (sys.executable or "").lower()
    return "\\windowsapps\\" in exe or "/windowsapps/" in exe


def self_command() -> list[str]:
    """How to relaunch THIS program (frozen exe vs. python script).

    ``[sys.executable, "netguard.py"]`` is wrong in a frozen build: ``sys.executable``
    is the application exe itself, which would then receive a stray argument.
    """
    if _FROZEN:
        return [sys.executable]
    return [sys.executable, os.path.join(_HERE, "netguard.py")]
