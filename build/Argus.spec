# -*- mode: python ; coding: utf-8 -*-
#
# Argus PyInstaller spec — one-folder bundle.
#
# Why one-folder and not one-file?
#   QtWebEngine ships a separate `QtWebEngineProcess.exe` helper that
#   Chromium spawns for the GPU + sandbox processes. With `--onefile`,
#   PyInstaller extracts the bundle to a temp dir at startup, but
#   QtWebEngine resolves the helper path *before* re-exec, so it
#   either fails to find the helper or ends up running a stale copy
#   on subsequent launches. One-folder side-steps the entire problem
#   and is the officially recommended bundle mode for Qt WebEngine.
#
# How to invoke this spec:
#   pyinstaller --clean --workpath build/build --distpath build/dist build/Argus.spec
#
# Output:
#   build/dist/Argus/Argus.exe   (Windows)
#   build/dist/Argus/Argus       (Linux/macOS — no console)
#
# Code signing:
#   This spec does NOT sign the binary. Run `signtool` separately —
#   see docs/AUTHENTICODE.md for the recommended Trusted Signing flow.
#
# Hidden imports:
#   Argus performs lazy `from argus_<x> import ...` calls at runtime
#   inside try/except blocks that gracefully degrade when a module is
#   absent. PyInstaller's static analyser cannot follow these guarded
#   imports, so we list each Wave-2 / Wave-3 module explicitly.

import os
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_data_files

block_cipher = None

# ── Resolve repo root ────────────────────────────────────────────────
# The spec lives in <repo>/build/, so repo root is one level up.
# `SPECPATH` is injected by PyInstaller and points to this file's dir.
REPO_ROOT = Path(SPECPATH).parent
BRANDING_DIR = REPO_ROOT / "branding" / "argus"
SANDBOX_DIR = REPO_ROOT / "argus_data" / "sandbox"

# ── Collect QtWebEngine bundle (binaries + data + hidden imports) ────
# This pulls in QtWebEngineProcess.exe, ICU data, locale .pak files,
# the resources subfolder, and every transitive Qt module.
qtwe_datas, qtwe_binaries, qtwe_hiddenimports = collect_all("PyQt6.QtWebEngineCore")

# Pillow plugin auto-detection — Argus uses Pillow for icon rendering.
# `collect_all` would over-include; we just need the data files (codec
# loaders are picked up by PyInstaller's normal scan of `Pillow`).
pil_datas = collect_data_files("PIL")

# ── Bundled data files ───────────────────────────────────────────────
# Format: (source path on host, destination path inside the bundle)
# Destination paths are relative to the bundle root (sys._MEIPASS).
datas = []

# All branding assets (icons, splash, wordmarks, i18n strings JSONs).
# We deliberately drop Python helpers (_canvas_icon.py, _generate_argus.py)
# and Markdown notes — those are dev-time tools, not runtime data.
_BRANDING_RUNTIME_EXTS = {".ico", ".png", ".svg", ".json"}
if BRANDING_DIR.is_dir():
    for entry in BRANDING_DIR.iterdir():
        if entry.is_file() and entry.suffix.lower() in _BRANDING_RUNTIME_EXTS:
            datas.append((str(entry), "branding/argus"))

# Default tracker blocklist seed for the sandbox
trackers_file = SANDBOX_DIR / "trackers_blocklist.txt"
if trackers_file.is_file():
    datas.append((str(trackers_file), "argus_data/sandbox"))

# Bundled licence + readme so the dist folder is self-describing
for top_level in ("README.md", "LICENSE", "SECURITY.md"):
    p = REPO_ROOT / top_level
    if p.is_file():
        datas.append((str(p), "."))

# Merge in QtWebEngine + Pillow data
datas += qtwe_datas + pil_datas

# ── Hidden imports (gracefully-degrading runtime imports) ────────────
hidden_argus_modules = [
    "argus_vault",
    "argus_vault_gateway",
    "argus_vault_client",
    "argus_sandbox",
    "argus_surveillance",
    "argus_arbiter",
    "argus_2fa",
    "argus_vault_domains",
    "argus_onboarding",
    "argus_i18n",
    "argus_mythos_bus",
    "argus_mythos_gateway",
    "config",
]

# Qt modules that PyInstaller usually finds, but we list them defensively
hidden_qt_modules = [
    "PyQt6.sip",
    "PyQt6.QtCore",
    "PyQt6.QtGui",
    "PyQt6.QtWidgets",
    "PyQt6.QtNetwork",
    "PyQt6.QtPrintSupport",
    "PyQt6.QtWebEngineCore",
    "PyQt6.QtWebEngineWidgets",
    "PyQt6.QtWebChannel",
]

# Stdlib + 3rd-party imports that Argus uses inside threads / callbacks
hidden_misc = [
    "json",
    "hashlib",
    "secrets",
    "urllib.request",
    "urllib.error",
    "urllib.parse",
    "cryptography",
    "cryptography.hazmat.primitives",
    "cryptography.hazmat.primitives.kdf.pbkdf2",
    "cryptography.hazmat.primitives.ciphers.aead",
    "cryptography.hazmat.backends",
    "PIL.Image",
    "PIL.ImageDraw",
    "PIL.ImageFont",
]

hiddenimports = hidden_argus_modules + hidden_qt_modules + hidden_misc + qtwe_hiddenimports


# ── Analysis ─────────────────────────────────────────────────────────
a = Analysis(
    [str(REPO_ROOT / "argus_pyqt.py")],
    pathex=[str(REPO_ROOT)],
    binaries=qtwe_binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Argus does not use these — excluding shrinks the bundle by ~80 MB.
        "PyQt6.QtBluetooth",
        "PyQt6.QtDBus",
        "PyQt6.QtDesigner",
        "PyQt6.QtHelp",
        "PyQt6.QtLocation",
        "PyQt6.QtMultimedia",
        "PyQt6.QtMultimediaWidgets",
        "PyQt6.QtNfc",
        "PyQt6.QtOpenGL",
        "PyQt6.QtPositioning",
        "PyQt6.QtQml",
        "PyQt6.QtQuick",
        "PyQt6.QtQuick3D",
        "PyQt6.QtQuickWidgets",
        "PyQt6.QtRemoteObjects",
        "PyQt6.QtSensors",
        "PyQt6.QtSerialPort",
        "PyQt6.QtSql",
        "PyQt6.QtSvg",
        "PyQt6.QtSvgWidgets",
        "PyQt6.QtTest",
        "PyQt6.QtTextToSpeech",
        "PyQt6.QtXml",
        # Test / dev frameworks must never end up in the prod bundle.
        "pytest",
        "pytest_qt",
        "pytest_mock",
        "bandit",
        "pip_audit",
    ],
    noarchive=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)


# ── EXE (no console) ─────────────────────────────────────────────────
icon_path = BRANDING_DIR / "argus_normal.ico"
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Argus",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,            # UPX corrupts QtWebEngine binaries on Windows.
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(icon_path) if icon_path.is_file() else None,
)


# ── COLLECT (one-folder layout) ──────────────────────────────────────
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="Argus",
)
