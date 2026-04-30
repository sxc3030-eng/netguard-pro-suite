# Copyright (C) 2026 NetGuard Pro Suite contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version. See the LICENSE file in the
# repository root for the full GPL v3 text, or
# <https://www.gnu.org/licenses/gpl-3.0.html>.
"""
Argus 2.0 — Real PyQt6 + QtWebEngine cybersecurity browser.

Layout:
  Top   : transparent live network feed (2 lines, color-coded, animated)
  Tabs  : bookmark-style strip just under feed (multi-tab, click to switch, × to close)
  Mid   : QStackedWidget with one QWebEngineView per tab (real Chromium, sandboxed)
          + optional right-side AI side panel (Ctrl+J)
  Bot   : 3-row dock — HTTPS / Engine+Search+Star / Settings+Favs+F12+NewTab
  Float : mode badge top-center (Normal / Privé / Coffre)
  F12   : Chromium DevTools panel slide-up, resizable

Persistence:
  Sessions (cookies, localStorage) survive restarts via persistent profile path
  → log into Google/Microsoft once, stays signed in next launch.
  Favorites stored in argus_data/favorites.json.
  AI conversation history in argus_data/ai_history.json (gitignored, last 50 msgs).

Run:  python argus_pyqt.py   (or LANCER_ARGUS_2.bat)
"""
import json
import os
import platform
import subprocess
import sys
import threading
import urllib.error
import urllib.request
import webbrowser
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlparse

# Module-level Argus version constant (used by About dialog + version banner +
# Help > About menu). Bump this when shipping a new release.
ARGUS_VERSION = "3.0.0"

from PyQt6.QtCore import (
    Qt, QUrl, QSize, pyqtSignal, QObject, QTimer,
    QPropertyAnimation, QEasingCurve,
)
from PyQt6.QtGui import QShortcut, QKeySequence, QIcon, QPixmap, QTextCursor
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QComboBox, QPushButton, QLabel, QStackedWidget, QFrame,
    QSizePolicy, QScrollArea, QMenu, QDialog, QCheckBox, QFormLayout,
    QDialogButtonBox, QGroupBox, QTextBrowser, QTextEdit, QTabWidget,
    QFileDialog, QMessageBox, QSplashScreen, QListWidget, QListWidgetItem,
    QPlainTextEdit, QHeaderView, QTableWidget, QTableWidgetItem, QMenuBar,
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import (
    QWebEnginePage, QWebEngineProfile, QWebEngineUrlRequestInterceptor,
    QWebEngineSettings, QWebEngineScript,
)
from PyQt6.QtPrintSupport import QPrintDialog, QPrinter

# ── Wave 2 module imports — graceful degradation if missing ──────────────
# Each import is wrapped so a missing module disables only that feature.
# Flags are inspected at runtime by the UI to skip wiring + show toasts.

try:
    from argus_sandbox import (
        make_normal_profile, make_private_profile, make_vault_profile,
        install_anti_skimmer_script, randomize_user_agent,
    )
    HAVE_SANDBOX = True
except ImportError:
    HAVE_SANDBOX = False
    make_normal_profile = make_private_profile = make_vault_profile = None
    install_anti_skimmer_script = randomize_user_agent = None

try:
    from argus_surveillance import (
        surveil_init, surveil_log_event, surveil_query, surveil_stats,
    )
    HAVE_SURVEILLANCE = True
except ImportError:
    HAVE_SURVEILLANCE = False
    def surveil_init(*_a, **_kw):  # type: ignore[no-redef]
        return None
    def surveil_log_event(*_a, **_kw):  # type: ignore[no-redef]
        return None
    def surveil_query(*_a, **_kw):  # type: ignore[no-redef]
        return []
    def surveil_stats(*_a, **_kw):  # type: ignore[no-redef]
        return {}

try:
    from argus_arbiter import (
        arbiter_init, arbiter_decide, arbiter_decide_async, Decision, ActionType,
    )
    HAVE_ARBITER = True
except ImportError:
    HAVE_ARBITER = False
    Decision = None  # type: ignore[assignment,misc]
    ActionType = str  # type: ignore[assignment,misc]
    def arbiter_init(*_a, **_kw):  # type: ignore[no-redef]
        return None
    def arbiter_decide(*_a, **_kw):  # type: ignore[no-redef]
        return None
    def arbiter_decide_async(*_a, **_kw):  # type: ignore[no-redef]
        # Synchronously invoke the callback with a None-ish allow so the UI
        # doesn't hang when arbiter is missing.
        cb = _kw.get("callback")
        if cb is None and len(_a) >= 3:
            cb = _a[2]
        if callable(cb):
            try:
                cb(None)
            except Exception:
                pass

try:
    from argus_vault_domains import is_vault_domain, VaultMatch
    HAVE_VAULT_DOMAINS = True
except ImportError:
    HAVE_VAULT_DOMAINS = False
    VaultMatch = None  # type: ignore[assignment,misc]
    def is_vault_domain(_url):  # type: ignore[no-redef]
        return None

try:
    from argus_2fa import (
        two_fa_is_setup, two_fa_setup_wizard, two_fa_challenge,
        two_fa_required_for,
    )
    HAVE_2FA = True
except ImportError:
    HAVE_2FA = False
    def two_fa_is_setup(*_a, **_kw):  # type: ignore[no-redef]
        return False
    def two_fa_setup_wizard(*_a, **_kw):  # type: ignore[no-redef]
        return False
    def two_fa_challenge(*_a, **_kw):  # type: ignore[no-redef]
        return False
    def two_fa_required_for(*_a, **_kw):  # type: ignore[no-redef]
        return False

try:
    from argus_onboarding import (
        is_first_run, mark_first_run_complete, show_first_run_dialog,
    )
    HAVE_ONBOARDING = True
except ImportError:
    HAVE_ONBOARDING = False
    def is_first_run(*_a, **_kw):  # type: ignore[no-redef]
        return False
    def mark_first_run_complete(*_a, **_kw):  # type: ignore[no-redef]
        return None
    def show_first_run_dialog(*_a, **_kw):  # type: ignore[no-redef]
        return None

try:
    from config import (
        get_secret, get_required_secret, store_secret, list_known_secrets,
        CANONICAL_SECRETS,
    )
    HAVE_CONFIG = True
except ImportError:
    HAVE_CONFIG = False
    CANONICAL_SECRETS = {}  # type: ignore[assignment]
    def get_secret(_n, fallback=None):  # type: ignore[no-redef]
        return os.environ.get(_n, fallback)
    def get_required_secret(_n, hint=""):  # type: ignore[no-redef]
        v = os.environ.get(_n)
        if not v:
            raise RuntimeError(f"Required secret {_n!r} not set")
        return v
    def store_secret(*_a, **_kw):  # type: ignore[no-redef]
        raise RuntimeError("config module not available; cannot store secrets")
    def list_known_secrets():  # type: ignore[no-redef]
        return []

# Vault management — used by Settings > Vault tab to list secrets metadata,
# rotate masterkey, etc. Module shipped in argus_vault.py; graceful fallback.
try:
    from argus_vault import (
        vault_list, vault_get, vault_delete, vault_rotate_masterkey,
        vault_exists,
    )
    HAVE_VAULT = True
except ImportError:
    HAVE_VAULT = False
    def vault_list():  # type: ignore[no-redef]
        return []
    def vault_get(_k, passphrase=None):  # type: ignore[no-redef]
        return None
    def vault_delete(_k):  # type: ignore[no-redef]
        return False
    def vault_rotate_masterkey(*_a, **_kw):  # type: ignore[no-redef]
        raise RuntimeError("argus_vault module not available")
    def vault_exists():  # type: ignore[no-redef]
        return False

# Audit chain verification (vault gateway) — Vault tab "Verify chain" button.
try:
    from argus_vault_gateway import gateway_audit_chain_verify
    HAVE_VAULT_GATEWAY = True
except ImportError:
    HAVE_VAULT_GATEWAY = False
    def gateway_audit_chain_verify():  # type: ignore[no-redef]
        return False

# Mythos bus presence flag (used in About dialog diagnostics).
try:
    import argus_mythos_bus  # noqa: F401
    HAVE_MYTHOS = True
except ImportError:
    HAVE_MYTHOS = False

# Sandbox download routing helper presence flag (About dialog diagnostics).
try:
    import argus_sandbox  # noqa: F401
    HAVE_SANDBOX_MOD = True
except ImportError:
    HAVE_SANDBOX_MOD = False

# Update checker — wired by another agent. Wrap in try/except so this file
# stays runnable even if the module hasn't landed yet.
try:
    from argus_updater import check_for_update as _argus_check_for_update
    HAVE_UPDATER = True
except ImportError:
    HAVE_UPDATER = False
    def _argus_check_for_update(*_a, **_kw):  # type: ignore[no-redef]
        return None

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "argus_data"
CACHE_DIR = ROOT / "argus_cache"
FAVS_FILE = DATA_DIR / "favorites.json"
SETTINGS_FILE = DATA_DIR / "settings.json"
AI_HISTORY_FILE = DATA_DIR / "ai_history.json"
VAULT_AUTO_SWITCH_FILE = DATA_DIR / "vault_auto_switch.json"
DOWNLOADS_SANDBOX_DIR = DATA_DIR / "downloads_sandbox"

# Help URLs for "Open URL" button next to API-Keys settings entries.
SECRET_HELP_URLS: dict[str, str] = {
    "ANTHROPIC_API_KEY":   "https://console.anthropic.com/settings/keys",
    "OPENAI_API_KEY":      "https://platform.openai.com/api-keys",
    "GOOGLE_API_KEY":      "https://aistudio.google.com/app/apikey",
    "OLLAMA_BASE_URL":     "https://ollama.com/download",
    "VIRUSTOTAL_API_KEY":  "https://www.virustotal.com/gui/my-apikey",
    "ABUSEIPDB_API_KEY":   "https://www.abuseipdb.com/account/api",
    "MAXMIND_LICENSE_KEY": "https://www.maxmind.com/en/accounts/current/license-key",
    "MAXMIND_ACCOUNT_ID":  "https://www.maxmind.com/en/account",
    "DISCORD_WEBHOOK_URL": "https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks",
    "TELEGRAM_BOT_TOKEN":  "https://core.telegram.org/bots#botfather",
    "TELEGRAM_CHAT_ID":    "https://core.telegram.org/bots/api#getupdates",
}

# Local AI backend (netguard_ai_server.py — DEFAULT_PORT = 8770)
AI_SERVER_HOST = "127.0.0.1"
AI_SERVER_PORT = 8770
AI_SERVER_BASE = f"http://{AI_SERVER_HOST}:{AI_SERVER_PORT}"
AI_HISTORY_MAX = 50          # cap conversation lines persisted
AI_PAGE_TEXT_MAX = 4096      # chars of page.toPlainText() included as context
AI_PAGE_TEXT_TIMEOUT_MS = 2000  # 2s, then send without page text

DEFAULT_SETTINGS = {
    "show_live_feed":   True,
    "show_favs":        True,
    "show_url_top":     True,
    "show_url_bottom":  True,
    "show_search_row":  True,
    "theme":            "Cyber Dark",
    "ai_panel_open":    False,
}

# Quick-action prefills for the AI side panel.
AI_QUICK_ACTIONS = [
    ("Résume",       "Résume cette page"),
    ("Failles",      "Trouve les failles de sécurité de cette page"),
    ("Explique",     "Explique ce code / JS"),
    ("Architecture", "Génère une architecture pour cette page"),
]

# Provider display labels (fallback if /api/providers is unreachable).
# The backend (netguard_ai_server.py) ships with anthropic / openai / google.
# UI labels follow the user-facing brief: Claude / GPT / Gemini.
AI_PROVIDER_FALLBACK = [
    ("anthropic", "Claude"),
    ("openai",    "GPT"),
    ("google",    "Gemini"),
]

SEARCH_ENGINES = [
    ("DuckDuckGo",  "https://duckduckgo.com/?q={q}"),
    ("Google",      "https://www.google.com/search?q={q}"),
    ("Brave",       "https://search.brave.com/search?q={q}"),
    ("Startpage",   "https://www.startpage.com/do/search?query={q}"),
    ("Bing",        "https://www.bing.com/search?q={q}"),
    ("Yahoo",       "https://search.yahoo.com/search?p={q}"),
    ("Kagi",        "https://kagi.com/search?q={q}"),
    ("Phind (dev)", "https://www.phind.com/search?q={q}"),
    ("Perplexity",  "https://www.perplexity.ai/?q={q}"),
]

DEFAULT_FAVORITES = [
    {"url": "https://gmail.com",                     "title": "Gmail",   "label": "G"},
    {"url": "https://github.com",                    "title": "GitHub",  "label": "⌘"},
    {"url": "https://outlook.live.com",              "title": "Outlook", "label": "📧"},
    {"url": "https://reddit.com",                    "title": "Reddit",  "label": "R"},
    {"url": "https://youtube.com",                   "title": "YouTube", "label": "▶"},
    {"url": "https://x.com",                         "title": "X",       "label": "𝕏"},
    {"url": "https://chatgpt.com",                   "title": "ChatGPT", "label": "🤖"},
    {"url": "https://developer.mozilla.org",         "title": "MDN",     "label": "M"},
]

MODES = [
    {"id": "normal",  "icon": "⚪", "text": "NORMAL",  "color": "#9aa0ad"},
    {"id": "private", "icon": "🟦", "text": "PRIVÉ",   "color": "#4d9fff"},
    {"id": "vault",   "icon": "🟡", "text": "COFFRE",  "color": "#d4af37"},
]


# ── Theme palette → QSS (full app stylesheets, applied via app.setStyleSheet) ──
def _build_theme(bg: str, surface: str, fg: str, accent: str,
                 border: str = "rgba(255,255,255,0.10)",
                 muted: str = "#9aa0ad",
                 font_family: str = "'Outfit','Segoe UI',sans-serif") -> str:
    """Compose a full app-wide QSS using a 4-color palette.

    Used for every theme so widgets that don't have an explicit Argus rule
    (QTabBar, QScrollBar, QDockWidget, generic QLineEdit/QPushButton) still
    inherit a coherent look.
    """
    return f"""
* {{ font-family: {font_family}; }}
QMainWindow, QWidget#root {{ background: {bg}; color: {fg}; }}
QWidget {{ color: {fg}; }}

/* Live feed (top transparent bar) */
QWidget#liveFeed {{
    background: {surface};
    border-bottom: 1px solid {border};
}}
QLabel.feedRow {{
    color: {fg};
    font-family: 'Geist Mono','Consolas',monospace;
    font-size: 11px;
    background: transparent;
}}
QLabel.feedRow[kind="ok"]   {{ color: #3dffb4; }}
QLabel.feedRow[kind="warn"] {{ color: #ffb347; }}
QLabel.feedRow[kind="bad"]  {{ color: #ff4d6a; }}
QLabel.feedRow[kind="info"] {{ color: {accent}; }}

/* Tab bar */
QFrame#tabBar {{ background: {surface}; border-bottom: 1px solid {border}; }}
QPushButton.tab {{
    background: {bg};
    color: {muted};
    border: 1px solid {border};
    border-bottom: 2px solid transparent;
    border-radius: 6px 6px 0 0;
    padding: 4px 8px 4px 10px;
    margin: 4px 1px 0 1px;
    font-size: 11px;
    text-align: left;
    min-width: 100px; max-width: 220px;
}}
QPushButton.tab:hover {{ background: {surface}; color: {fg}; }}
QPushButton.tab[active="true"] {{
    background: {surface};
    color: {accent};
    border-bottom-color: {accent};
}}
QPushButton.tabClose {{
    background: transparent;
    color: {muted};
    border: none;
    padding: 0;
    min-width: 16px; max-width: 16px;
    min-height: 16px; max-height: 16px;
    font-size: 14px;
    border-radius: 8px;
    margin-left: 4px;
}}
QPushButton.tabClose:hover {{ background: #ff4d6a; color: white; }}
QPushButton#newTabBtn {{
    background: transparent;
    color: {muted};
    border: 1px dashed {border};
    border-radius: 5px;
    margin: 4px 4px 0 4px;
    min-width: 28px; max-width: 28px;
    font-size: 14px;
    padding: 4px;
}}
QPushButton#newTabBtn:hover {{ color: {accent}; border-color: {accent}; border-style: solid; }}

/* Generic QTabBar (for any future QTabWidget) */
QTabBar::tab {{
    background: {bg};
    color: {muted};
    border: 1px solid {border};
    padding: 6px 12px;
}}
QTabBar::tab:selected {{ background: {surface}; color: {accent}; }}
QTabBar::tab:hover {{ color: {fg}; }}

/* Mode toggle button */
QPushButton#modeBtn {{
    background: transparent;
    border: 1px solid {border};
    border-radius: 6px;
    padding: 4px 12px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.06em;
    color: {muted};
    font-family: 'Geist Mono','Consolas',monospace;
}}
QPushButton#modeBtn:hover {{ color: {accent}; border-color: {accent}; background: {surface}; }}
QPushButton#modeBtn[mode="private"] {{ color: {accent}; border-color: {accent}; }}
QPushButton#modeBtn[mode="vault"]   {{ color: #d4af37; border-color: #d4af37; }}

/* NetGuard status button */
QPushButton#ngBtn {{
    background: transparent;
    border: 1px solid {border};
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    color: {muted};
    font-family: 'Geist Mono','Consolas',monospace;
    font-weight: 600;
}}
QPushButton#ngBtn:hover {{ color: {accent}; border-color: {accent}; background: {surface}; }}
QPushButton#ngBtn[status="up"]   {{ color: #3dffb4; border-color: rgba(61,255,180,0.5); }}
QPushButton#ngBtn[status="down"] {{ color: #ff4d6a; border-color: rgba(255,77,106,0.5); }}
QPushButton#ngBtn[status="warn"] {{ color: #ffb347; border-color: rgba(255,179,71,0.5); }}

/* AI toggle button */
QPushButton#aiBtn {{
    background: transparent;
    border: 1px solid {border};
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 13px;
    color: {muted};
}}
QPushButton#aiBtn:hover {{ color: {accent}; border-color: {accent}; background: {surface}; }}
QPushButton#aiBtn[open="true"] {{ color: {accent}; border-color: {accent}; background: {surface}; }}

/* Bottom dock */
QFrame#dock {{ background: {surface}; border-top: 1px solid {border}; }}
QFrame.dockRow {{ background: transparent; border-top: 1px solid {border}; }}
QFrame.dockRow[first="true"] {{ border-top: none; }}

QLabel.lock {{ font-size: 13px; color: #3dffb4; }}
QLabel.lock[level="warn"] {{ color: #ffb347; }}
QLabel.lock[level="bad"]  {{ color: #ff4d6a; }}
QLabel#urlDisplay {{
    font-family: 'Geist Mono','Consolas',monospace;
    font-size: 12px;
    color: {fg};
    padding: 4px 8px;
    background: transparent;
}}
QLabel#urlDisplay:hover {{ background: {surface}; border-radius: 4px; }}

QComboBox#engineSelect {{
    background: {surface};
    border: 1px solid {border};
    color: {fg};
    padding: 6px 10px;
    border-radius: 6px;
    font-size: 12px;
    min-width: 130px;
}}
QComboBox#engineSelect:focus {{ border-color: {accent}; }}
QComboBox#engineSelect QAbstractItemView {{
    background: {surface};
    color: {fg};
    selection-background-color: {bg};
    border: 1px solid {border};
}}

/* Generic QComboBox (theme combo, AI provider combo) */
QComboBox {{
    background: {surface};
    border: 1px solid {border};
    color: {fg};
    padding: 5px 10px;
    border-radius: 5px;
    font-size: 12px;
}}
QComboBox:focus {{ border-color: {accent}; }}
QComboBox QAbstractItemView {{
    background: {surface};
    color: {fg};
    selection-background-color: {bg};
    border: 1px solid {border};
}}

QLineEdit#searchBar {{
    background: {surface};
    border: 1px solid {border};
    color: {fg};
    padding: 7px 14px;
    border-radius: 6px;
    font-size: 13px;
    font-family: 'Geist Mono','Consolas',monospace;
}}
QLineEdit#searchBar:focus {{ border-color: {accent}; background: {bg}; }}

/* Generic QLineEdit / QTextEdit */
QLineEdit, QTextEdit {{
    background: {surface};
    border: 1px solid {border};
    color: {fg};
    padding: 5px 8px;
    border-radius: 5px;
    selection-background-color: {accent};
    selection-color: {bg};
}}
QLineEdit:focus, QTextEdit:focus {{ border-color: {accent}; }}

QPushButton.dockBtn {{
    background: transparent;
    color: {muted};
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 13px;
    min-width: 32px;
}}
QPushButton.dockBtn:hover {{ color: {accent}; background: {surface}; border-color: {border}; }}
QPushButton.dockBtn[primary="true"] {{ color: {accent}; }}
QPushButton#starBtn {{ font-size: 16px; color: #ffb347; }}
QPushButton#starBtn[saved="true"] {{ color: #ffd700; }}

/* Generic QPushButton (covers buttons not pinned to a class) */
QPushButton {{
    background: {surface};
    border: 1px solid {border};
    color: {fg};
    padding: 6px 14px;
    border-radius: 5px;
    font-size: 12px;
}}
QPushButton:hover  {{ border-color: {accent}; color: {accent}; }}
QPushButton:disabled {{ color: {muted}; border-color: {border}; }}

QFrame#favsBar {{
    background: {surface};
    border: 1px solid {border};
    border-radius: 8px;
    padding: 2px 4px;
}}
QPushButton.fav {{
    background: {bg};
    color: {muted};
    border: 1px solid transparent;
    border-radius: 5px;
    min-width: 26px; max-width: 26px;
    min-height: 26px; max-height: 26px;
    font-size: 11px;
    margin: 0 1px;
}}
QPushButton.fav:hover {{ color: {accent}; border-color: {accent}; }}
QPushButton.fav[broken="true"] {{ color: #ff4d6a; border: 1px dashed #ff4d6a; }}

QWidget#root[mode="vault"]   {{ border: 2px solid #d4af37; }}
QWidget#root[mode="private"] {{ border: 1px solid {accent}; }}

/* Top URL strip */
QFrame#topUrlStrip {{
    background: {surface};
    border-bottom: 1px solid {border};
}}
QLabel#topUrlText {{
    color: {fg};
    font-family: 'Geist Mono','Consolas',monospace;
    font-size: 11px;
    background: transparent;
    padding: 2px 8px;
}}

/* Spinner */
QLabel#spinner, QLabel#topSpinner {{
    color: {accent};
    font-size: 14px;
    background: transparent;
    padding: 0 4px;
    min-width: 16px;
}}

/* AI side panel */
QFrame#aiPanel {{
    background: {surface};
    border-left: 1px solid {border};
}}
QFrame#aiPanelHeader {{
    background: {bg};
    border-bottom: 1px solid {border};
}}
QLabel#aiPanelTitle {{
    color: {fg};
    font-size: 13px;
    font-weight: 600;
    padding: 0 4px;
}}
QTextBrowser#aiHistory {{
    background: {bg};
    border: none;
    color: {fg};
    padding: 6px;
    font-size: 12px;
    selection-background-color: {accent};
    selection-color: {bg};
}}
QTextEdit#aiInput {{
    background: {bg};
    border: 1px solid {border};
    color: {fg};
    padding: 6px 8px;
    border-radius: 5px;
    font-size: 12px;
}}
QTextEdit#aiInput:focus {{ border-color: {accent}; }}
QPushButton#aiSendBtn {{
    background: {accent};
    color: {bg};
    border: 1px solid {accent};
    border-radius: 5px;
    padding: 6px 14px;
    font-weight: 600;
}}
QPushButton#aiSendBtn:hover {{ opacity: 0.9; }}
QPushButton#aiSendBtn:disabled {{ background: {muted}; border-color: {muted}; }}
QPushButton.aiQuick {{
    background: {bg};
    color: {muted};
    border: 1px solid {border};
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 11px;
}}
QPushButton.aiQuick:hover {{ color: {accent}; border-color: {accent}; }}
QPushButton#aiClearBtn {{
    background: transparent;
    color: {muted};
    border: 1px solid {border};
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 11px;
}}
QPushButton#aiClearBtn:hover {{ color: #ff4d6a; border-color: #ff4d6a; }}

/* Settings dialog */
QDialog#settingsDialog {{
    background: {surface};
    color: {fg};
}}
QDialog#settingsDialog QGroupBox {{
    border: 1px solid {border};
    border-radius: 6px;
    margin-top: 14px;
    padding: 10px 6px 6px 6px;
    color: {accent};
    font-weight: 600;
    font-size: 12px;
}}
QDialog#settingsDialog QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    background: {surface};
}}
QDialog#settingsDialog QCheckBox {{
    color: {fg};
    font-size: 12px;
    padding: 4px 6px;
    spacing: 8px;
}}
QDialog#settingsDialog QCheckBox::indicator {{
    width: 14px; height: 14px;
    border: 1px solid {accent};
    border-radius: 3px;
    background: {bg};
}}
QDialog#settingsDialog QCheckBox::indicator:checked {{
    background: {accent};
    border-color: {accent};
}}
QDialog#settingsDialog QPushButton {{
    background: {bg};
    border: 1px solid {border};
    color: {fg};
    padding: 6px 14px;
    border-radius: 5px;
    font-size: 12px;
}}
QDialog#settingsDialog QPushButton:hover {{ border-color: {accent}; color: {accent}; }}
QDialog#settingsDialog QPushButton:default {{ background: {accent}; color: {bg}; border-color: {accent}; }}
QDialog#settingsDialog QLabel {{ color: {fg}; }}

/* QScrollBar */
QScrollBar:vertical {{
    background: {bg};
    width: 10px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {border};
    border-radius: 5px;
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{ background: {accent}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ background: {bg}; height: 10px; margin: 0; }}
QScrollBar::handle:horizontal {{ background: {border}; border-radius: 5px; min-width: 24px; }}
QScrollBar::handle:horizontal:hover {{ background: {accent}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

/* QDockWidget (defensive — Argus uses custom dock, but cover the standard one) */
QDockWidget {{ color: {fg}; titlebar-close-icon: none; titlebar-normal-icon: none; }}
QDockWidget::title {{ background: {surface}; padding: 4px 8px; }}

QMenu {{ background: {surface}; color: {fg}; border: 1px solid {border}; }}
QMenu::item:selected {{ background: {accent}; color: {bg}; }}
QToolTip {{ background: {bg}; color: {fg}; border: 1px solid {border}; padding: 4px 6px; }}
"""


THEMES: dict[str, str] = {
    "Cyber Dark":  _build_theme(bg="#0a0e14", surface="#141821", fg="#e6edf3",
                                accent="#4d9fff"),
    "Pro Dark":    _build_theme(bg="#1a1a1f", surface="#25252d", fg="#d4d4dc",
                                accent="#8b8b9d"),
    "Light Pro":   _build_theme(bg="#fafafa", surface="#ffffff", fg="#1a1a1f",
                                accent="#2563eb",
                                border="#e5e7eb", muted="#6b7280"),
    "Hacker Green":_build_theme(bg="#000800", surface="#001a05", fg="#00ff41",
                                accent="#00ff41",
                                border="#003311", muted="#008822",
                                font_family="'Consolas',monospace"),
    "Bank Vault":  _build_theme(bg="#1a1410", surface="#2a2018", fg="#d4af37",
                                accent="#b8860b",
                                border="#3a2e22", muted="#8a7050"),
    "Pastel":      _build_theme(bg="#f5f0e8", surface="#faf6f0", fg="#2d3033",
                                accent="#c9a96e",
                                border="#e0d5c4", muted="#857a6a"),
    # ── 6 new themes (community-favorite palettes) ──
    "Tokyo Night":     _build_theme(bg="#1a1b26", surface="#24283b", fg="#a9b1d6",
                                    accent="#7aa2f7"),
    "Catppuccin Mocha":_build_theme(bg="#1e1e2e", surface="#313244", fg="#cdd6f4",
                                    accent="#cba6f7"),
    "Dracula":         _build_theme(bg="#282a36", surface="#44475a", fg="#f8f8f2",
                                    accent="#bd93f9"),
    "Solarized Dark":  _build_theme(bg="#002b36", surface="#073642", fg="#839496",
                                    accent="#268bd2"),
    "Gruvbox Dark":    _build_theme(bg="#282828", surface="#3c3836", fg="#ebdbb2",
                                    accent="#fabd2f"),
    "Nord":            _build_theme(bg="#2e3440", surface="#3b4252", fg="#d8dee9",
                                    accent="#88c0d0"),
}

DEFAULT_THEME = "Cyber Dark"


THEME_QSS = r"""
* { font-family: 'Outfit', 'Segoe UI', sans-serif; }
QMainWindow, QWidget#root { background: #0a0e14; }

/* ── Live feed (top, transparent) ── */
QWidget#liveFeed {
    background: rgba(15, 18, 22, 180);
    border-bottom: 1px solid rgba(255,255,255,0.06);
}
QLabel.feedRow {
    color: #e8eaf0;
    font-family: 'Geist Mono', 'Consolas', monospace;
    font-size: 11px;
    background: transparent;
}
QLabel.feedRow[kind="ok"]   { color: #3dffb4; }
QLabel.feedRow[kind="warn"] { color: #ffb347; }
QLabel.feedRow[kind="bad"]  { color: #ff4d6a; }
QLabel.feedRow[kind="info"] { color: #4d9fff; }

/* ── Tab bar (just below feed) ── */
QFrame#tabBar {
    background: #0e1219;
    border-bottom: 1px solid rgba(255,255,255,0.06);
}
QPushButton.tab {
    background: #14181f;
    color: #9aa0ad;
    border: 1px solid rgba(255,255,255,0.04);
    border-bottom: 2px solid transparent;
    border-radius: 6px 6px 0 0;
    padding: 4px 8px 4px 10px;
    margin: 4px 1px 0 1px;
    font-size: 11px;
    text-align: left;
    min-width: 100px; max-width: 220px;
}
QPushButton.tab:hover { background: #1a1f28; color: #e8eaf0; }
QPushButton.tab[active="true"] {
    background: #1a1f28;
    color: #4d9fff;
    border-bottom-color: #4d9fff;
}
QPushButton.tab[mode="private"][active="true"] { color: #4d9fff; border-bottom-color: #4d9fff; }
QPushButton.tab[mode="vault"][active="true"]   { color: #d4af37; border-bottom-color: #d4af37; }
QPushButton.tabClose {
    background: transparent;
    color: #5a5f6c;
    border: none;
    padding: 0;
    min-width: 16px; max-width: 16px;
    min-height: 16px; max-height: 16px;
    font-size: 14px;
    border-radius: 8px;
    margin-left: 4px;
}
QPushButton.tabClose:hover { background: #ff4d6a; color: white; }
QPushButton#newTabBtn {
    background: transparent;
    color: #5a5f6c;
    border: 1px dashed rgba(255,255,255,0.1);
    border-radius: 5px;
    margin: 4px 4px 0 4px;
    min-width: 28px; max-width: 28px;
    font-size: 14px;
    padding: 4px;
}
QPushButton#newTabBtn:hover { color: #4d9fff; border-color: #4d9fff; border-style: solid; }

/* ── Mode toggle button (in dock row 3, before NetGuard) ── */
QPushButton#modeBtn {
    background: transparent;
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 6px;
    padding: 4px 12px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.06em;
    color: #9aa0ad;
    font-family: 'Geist Mono', 'Consolas', monospace;
}
QPushButton#modeBtn:hover { color: #4d9fff; border-color: #4d9fff; background: #1a1f28; }
QPushButton#modeBtn[mode="private"] { color: #4d9fff; border-color: #4d9fff; }
QPushButton#modeBtn[mode="vault"]   { color: #d4af37; border-color: #d4af37;
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #2a1f08, stop:1 #1a1409); }

/* ── NetGuard status button (in dock row 3, where F12 used to be) ── */
QPushButton#ngBtn {
    background: transparent;
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    color: #9aa0ad;
    font-family: 'Geist Mono', 'Consolas', monospace;
    font-weight: 600;
}
QPushButton#ngBtn:hover { color: #4d9fff; border-color: #4d9fff; background: #1a1f28; }
QPushButton#ngBtn[status="up"]   { color: #3dffb4; border-color: rgba(61,255,180,0.5); }
QPushButton#ngBtn[status="down"] { color: #ff4d6a; border-color: rgba(255,77,106,0.5); }
QPushButton#ngBtn[status="warn"] { color: #ffb347; border-color: rgba(255,179,71,0.5); }

/* ── Bottom dock ── */
QFrame#dock { background: #14181f; border-top: 1px solid rgba(255,255,255,0.06); }
QFrame.dockRow { background: transparent; border-top: 1px solid rgba(255,255,255,0.04); }
QFrame.dockRow[first="true"] { border-top: none; }

QLabel.lock { font-size: 13px; color: #3dffb4; }
QLabel.lock[level="warn"] { color: #ffb347; }
QLabel.lock[level="bad"]  { color: #ff4d6a; }
QLabel#urlDisplay {
    font-family: 'Geist Mono', 'Consolas', monospace;
    font-size: 12px;
    color: #e8eaf0;
    padding: 4px 8px;
    background: transparent;
}
QLabel#urlDisplay:hover { background: #1a1f28; border-radius: 4px; }

QComboBox#engineSelect {
    background: #1a1f28;
    border: 1px solid rgba(255,255,255,0.12);
    color: #e8eaf0;
    padding: 6px 10px;
    border-radius: 6px;
    font-size: 12px;
    min-width: 130px;
}
QComboBox#engineSelect:focus { border-color: #4d9fff; }
QComboBox#engineSelect QAbstractItemView {
    background: #1a1f28;
    color: #e8eaf0;
    selection-background-color: #232934;
    border: 1px solid rgba(255,255,255,0.12);
}

QLineEdit#searchBar {
    background: #1a1f28;
    border: 1px solid rgba(255,255,255,0.12);
    color: #e8eaf0;
    padding: 7px 14px;
    border-radius: 6px;
    font-size: 13px;
    font-family: 'Geist Mono', 'Consolas', monospace;
}
QLineEdit#searchBar:focus { border-color: #4d9fff; background: #14181f; }

QPushButton.dockBtn {
    background: transparent;
    color: #9aa0ad;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 13px;
    min-width: 32px;
}
QPushButton.dockBtn:hover { color: #4d9fff; background: #1a1f28; border-color: rgba(255,255,255,0.12); }
QPushButton.dockBtn[primary="true"] { color: #4d9fff; }
QPushButton#starBtn { font-size: 16px; color: #ffb347; }
QPushButton#starBtn[saved="true"] { color: #ffd700; }
QPushButton#f12Btn {
    font-family: 'Geist Mono', 'Consolas', monospace;
    font-size: 10px;
    font-weight: 600;
    padding: 6px 12px;
}

QFrame#favsBar {
    background: #1a1f28;
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 8px;
    padding: 2px 4px;
}
QPushButton.fav {
    background: #232934;
    color: #9aa0ad;
    border: 1px solid transparent;
    border-radius: 5px;
    min-width: 26px; max-width: 26px;
    min-height: 26px; max-height: 26px;
    font-size: 11px;
    margin: 0 1px;
}
QPushButton.fav:hover { color: #4d9fff; border-color: #4d9fff; }
QPushButton.fav[broken="true"] { color: #ff4d6a; border: 1px dashed #ff4d6a; opacity: 0.6; }

QWidget#root[mode="vault"]   { border: 2px solid #d4af37; }
QWidget#root[mode="private"] { border: 1px solid #4d9fff; }

/* ── Top URL strip (just above tab bar, optional) ── */
QFrame#topUrlStrip {
    background: rgba(15, 18, 22, 200);
    border-bottom: 1px solid rgba(255,255,255,0.04);
}
QLabel#topUrlText {
    color: #c8ccd6;
    font-family: 'Geist Mono', 'Consolas', monospace;
    font-size: 11px;
    background: transparent;
    padding: 2px 8px;
}

/* ── Spinner (loading indicator, right of URL bars) ── */
QLabel#spinner, QLabel#topSpinner {
    color: #4d9fff;
    font-size: 14px;
    background: transparent;
    padding: 0 4px;
    min-width: 16px;
}

/* ── Settings dialog ── */
QDialog#settingsDialog {
    background: #14181f;
    color: #e8eaf0;
}
QDialog#settingsDialog QGroupBox {
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 6px;
    margin-top: 14px;
    padding: 10px 6px 6px 6px;
    color: #4d9fff;
    font-weight: 600;
    font-size: 12px;
}
QDialog#settingsDialog QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    background: #14181f;
}
QDialog#settingsDialog QCheckBox {
    color: #c8ccd6;
    font-size: 12px;
    padding: 4px 6px;
    spacing: 8px;
}
QDialog#settingsDialog QCheckBox::indicator {
    width: 14px; height: 14px;
    border: 1px solid #4d9fff;
    border-radius: 3px;
    background: #1a1f28;
}
QDialog#settingsDialog QCheckBox::indicator:checked {
    background: #4d9fff;
    border-color: #4d9fff;
}
QDialog#settingsDialog QPushButton {
    background: #1a1f28;
    border: 1px solid rgba(255,255,255,0.12);
    color: #e8eaf0;
    padding: 6px 14px;
    border-radius: 5px;
    font-size: 12px;
}
QDialog#settingsDialog QPushButton:hover { border-color: #4d9fff; color: #4d9fff; }
QDialog#settingsDialog QPushButton:default { background: #4d9fff; color: white; border-color: #4d9fff; }

"""


# ── Theme application ────────────────────────────────────────────────────
def apply_theme(name: str) -> str:
    """Apply a named theme stylesheet to the active QApplication.

    Returns the resolved theme name (falls back to the default if `name` is
    unknown). Safe to call before windows are constructed.
    """
    if name not in THEMES:
        name = DEFAULT_THEME
    app = QApplication.instance()
    if app is not None:
        app.setStyleSheet(THEMES[name])
    return name


# ── AI conversation history ──────────────────────────────────────────────
class AIHistoryManager:
    """Persisted AI chat history (last AI_HISTORY_MAX messages)."""
    def __init__(self, path: Path):
        self.path = path
        self.messages: list[dict] = []
        self._load()

    def _load(self):
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                # Tolerate corrupt entries silently — keep only well-shaped ones.
                self.messages = [
                    m for m in data
                    if isinstance(m, dict) and m.get("role") in ("user", "assistant", "error")
                    and isinstance(m.get("content"), str)
                ]
        except (OSError, json.JSONDecodeError):
            self.messages = []

    def _save(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(
                json.dumps(self.messages[-AI_HISTORY_MAX:], indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError:
            pass

    def append(self, role: str, content: str):
        if role not in ("user", "assistant", "error"):
            return
        self.messages.append({"role": role, "content": content,
                              "ts": datetime.now().isoformat()})
        # Cap to the last AI_HISTORY_MAX entries (in-memory + on disk).
        if len(self.messages) > AI_HISTORY_MAX:
            self.messages = self.messages[-AI_HISTORY_MAX:]
        self._save()

    def clear(self):
        self.messages = []
        self._save()

    def for_api(self) -> list[dict]:
        """Return the conversation in the shape /api/chat expects."""
        return [
            {"role": m["role"], "content": m["content"]}
            for m in self.messages
            if m["role"] in ("user", "assistant")
        ]


# ── AI HTTP worker (background thread) ───────────────────────────────────
class AIChatWorker(QObject):
    """Posts a chat message to netguard_ai_server on a background thread.

    Emits `done(reply)` on success or `failed(error)` on any failure. Kept
    intentionally minimal — no streaming, the backend doesn't expose SSE.
    """
    done = pyqtSignal(str, dict)   # (reply_text, raw_result_dict)
    failed = pyqtSignal(str)       # error string

    def __init__(self, messages: list[dict], lang: str = "fr",
                 timeout: float = 60.0, parent=None):
        super().__init__(parent)
        self.messages = messages
        self.lang = lang
        self.timeout = timeout
        self._thread: threading.Thread | None = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        body = json.dumps({
            "messages": self.messages,
            "lang": self.lang,
            "agent_mode": False,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{AI_SERVER_BASE}/api/chat",
            data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.URLError as e:
            self.failed.emit(f"Backend unreachable — démarre netguard_ai_server.py ({e.reason})")
            return
        except (TimeoutError, OSError) as e:
            self.failed.emit(f"Backend unreachable — démarre netguard_ai_server.py ({e})")
            return
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            self.failed.emit("Réponse invalide du backend (JSON parse error)")
            return
        if not data.get("ok", False):
            self.failed.emit(f"Backend error: {data.get('error', 'unknown')} — {data.get('reply', '')[:200]}")
            return
        self.done.emit(data.get("reply", ""), data)


# ── Persistence ──────────────────────────────────────────────────────────
class SettingsManager:
    """Layout/UX preferences persisted between sessions."""
    def __init__(self, path: Path):
        self.path = path
        self.data = dict(DEFAULT_SETTINGS)
        self._load()

    def _load(self):
        if not self.path.exists():
            self._save()
            return
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                self.data.update(loaded)
        except Exception:
            pass

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8")

    def get(self, key: str, default=None):
        return self.data.get(key, default if default is not None else DEFAULT_SETTINGS.get(key))

    def set(self, key: str, value):
        self.data[key] = value
        self._save()


class Spinner(QLabel):
    """Tiny braille animation, started on page-load, stopped on finished."""
    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    def __init__(self, name: str = "spinner"):
        super().__init__()
        self.setObjectName(name)
        self.frame = 0
        self.setText("")
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.setFixedWidth(20)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)

    def _tick(self):
        self.frame = (self.frame + 1) % len(self.FRAMES)
        self.setText(self.FRAMES[self.frame])

    def start(self):
        if not self.timer.isActive():
            self.timer.start(85)

    def stop(self):
        self.timer.stop()
        self.setText("")


class FavoritesManager:
    def __init__(self, path: Path):
        self.path = path
        self.favorites: list[dict] = []
        self._load()

    def _load(self):
        if not self.path.exists():
            self.favorites = list(DEFAULT_FAVORITES)
            self._save()
            return
        try:
            self.favorites = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            self.favorites = list(DEFAULT_FAVORITES)

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.favorites, indent=2, ensure_ascii=False), encoding="utf-8")

    def add(self, url: str, title: str = "") -> bool:
        if any(f["url"] == url for f in self.favorites):
            return False
        # Use first letter of title or domain as label
        label = "★"
        if title:
            label = title[0].upper()
        elif url:
            try:
                from urllib.parse import urlparse
                host = urlparse(url).netloc.lstrip("www.")
                label = host[0].upper() if host else "★"
            except Exception:
                pass
        self.favorites.append({
            "url": url,
            "title": title or url,
            "label": label,
            "added": datetime.now().isoformat(),
            "broken": False,
        })
        self._save()
        return True

    def remove(self, url: str) -> bool:
        before = len(self.favorites)
        self.favorites = [f for f in self.favorites if f["url"] != url]
        if len(self.favorites) < before:
            self._save()
            return True
        return False

    def has(self, url: str) -> bool:
        return any(f["url"] == url for f in self.favorites)

    def mark_broken(self, url: str, broken: bool = True):
        for f in self.favorites:
            if f["url"] == url:
                f["broken"] = broken
                self._save()
                return


# ── Settings dialog ──────────────────────────────────────────────────────
class SettingsDialog(QDialog):
    def __init__(self, settings_mgr: SettingsManager, parent=None):
        super().__init__(parent)
        self.settings_mgr = settings_mgr
        self.setObjectName("settingsDialog")
        self.setWindowTitle("Argus — Paramètres")
        self.resize(560, 580)

        # Capture original theme so Cancel can revert live-preview changes.
        self._original_theme = settings_mgr.get("theme") or DEFAULT_THEME
        if self._original_theme not in THEMES:
            self._original_theme = DEFAULT_THEME

        # Track API-keys edits so we know what to flush on Apply.
        # Map name -> (line_edit, "Show" toggle widget). Filled by _build_keys_tab.
        self._keys_widgets: dict[str, tuple] = {}

        v = QVBoxLayout(self)
        v.setSpacing(10)
        v.setContentsMargins(10, 10, 10, 10)

        # Tabbed layout — Display / API Keys / Vault
        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_display_tab(), "Affichage")
        self._tabs.addTab(self._build_keys_tab(),    "API Keys")
        self._tabs.addTab(self._build_vault_tab(),   "Vault")
        v.addWidget(self._tabs, 1)

        # Buttons
        btns = QHBoxLayout()
        btns.addStretch(1)
        cancel = QPushButton("Annuler")
        cancel.clicked.connect(self._cancel)
        ok = QPushButton("Appliquer")
        ok.setDefault(True)
        ok.clicked.connect(self._apply)
        btns.addWidget(cancel)
        btns.addWidget(ok)
        v.addLayout(btns)

    # ── Display tab (existing section, just moved into a tab) ──────────
    def _build_display_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setSpacing(10)

        title = QLabel("Apparence et affichage")
        title.setStyleSheet("font-size:15px; font-weight:600; margin-bottom:6px;")
        v.addWidget(title)

        # Group: Theme (NEW — always at top)
        gb_theme = QGroupBox("Thème")
        gl_theme = QVBoxLayout(gb_theme)
        theme_row = QHBoxLayout()
        theme_row.addWidget(QLabel("Style global :"))
        self.theme_combo = QComboBox()
        for name in sorted(THEMES.keys(), key=str.lower):
            self.theme_combo.addItem(name)
        # Restore current selection.
        current_theme = self.settings_mgr.get("theme") or DEFAULT_THEME
        if current_theme in THEMES:
            self.theme_combo.setCurrentText(current_theme)
        # Live preview — apply on selection change.
        self.theme_combo.currentTextChanged.connect(self._on_theme_preview)
        theme_row.addWidget(self.theme_combo, 1)
        gl_theme.addLayout(theme_row)
        hint = QLabel("Aperçu en direct. « Annuler » restaure le thème précédent.")
        hint.setStyleSheet("font-size: 11px; color: #9aa0ad;")
        gl_theme.addWidget(hint)
        v.addWidget(gb_theme)

        # Group: Top
        gb_top = QGroupBox("Haut de la fenêtre")
        gl_top = QVBoxLayout(gb_top)
        self.cb_feed = QCheckBox("Live feed (lignes de code / requêtes réseau)")
        self.cb_feed.setChecked(self.settings_mgr.get("show_live_feed"))
        self.cb_url_top = QCheckBox("Barre URL en haut (juste au-dessus des onglets)")
        self.cb_url_top.setChecked(self.settings_mgr.get("show_url_top"))
        gl_top.addWidget(self.cb_feed)
        gl_top.addWidget(self.cb_url_top)
        v.addWidget(gb_top)

        # Group: Bottom
        gb_bot = QGroupBox("Bas de la fenêtre (dock)")
        gl_bot = QVBoxLayout(gb_bot)
        self.cb_url_bottom = QCheckBox("Barre URL + cadenas")
        self.cb_url_bottom.setChecked(self.settings_mgr.get("show_url_bottom"))
        self.cb_search = QCheckBox("Barre de recherche (moteur + champ)")
        self.cb_search.setChecked(self.settings_mgr.get("show_search_row"))
        self.cb_favs = QCheckBox("Favoris + boutons (mode, NetGuard, +tab)")
        self.cb_favs.setChecked(self.settings_mgr.get("show_favs"))
        gl_bot.addWidget(self.cb_url_bottom)
        gl_bot.addWidget(self.cb_search)
        gl_bot.addWidget(self.cb_favs)
        v.addWidget(gb_bot)

        v.addStretch(1)
        return w

    # ── API Keys tab ───────────────────────────────────────────────────
    def _build_keys_tab(self) -> QWidget:
        outer = QWidget()
        ov = QVBoxLayout(outer)
        ov.setSpacing(8)
        ov.setContentsMargins(2, 2, 2, 2)

        if not HAVE_CONFIG:
            warn = QLabel(
                "Module ``config`` indisponible — les clés API ne peuvent pas "
                "être stockées dans le coffre. Définis-les via .env ou "
                "variables d'environnement OS, puis redémarre Argus."
            )
            warn.setWordWrap(True)
            warn.setStyleSheet("color: #ff9e7a; font-size: 12px; padding: 12px;")
            ov.addWidget(warn)
            ov.addStretch(1)
            return outer

        # Header — short hint + .env migration button
        hdr = QHBoxLayout()
        lbl = QLabel(
            "Stocke les clés API et webhooks utilisés par Argus. Les valeurs "
            "saisies vont dans le coffre chiffré (DPAPI sous Windows)."
        )
        lbl.setWordWrap(True)
        lbl.setStyleSheet("font-size: 12px; color: #9aa0ad;")
        hdr.addWidget(lbl, 1)
        ov.addLayout(hdr)

        migrate_row = QHBoxLayout()
        migrate_row.addStretch(1)
        migrate_btn = QPushButton("Migrer depuis .env")
        migrate_btn.setToolTip(
            "Lit le fichier .env du repo, propose de copier ces secrets dans le coffre."
        )
        migrate_btn.clicked.connect(self._migrate_from_env)
        migrate_row.addWidget(migrate_btn)
        ov.addLayout(migrate_row)

        # Scrollable list of canonical secrets
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        body = QWidget()
        bv = QVBoxLayout(body)
        bv.setSpacing(8)
        bv.setContentsMargins(2, 2, 2, 2)

        for name, description in CANONICAL_SECRETS.items():
            bv.addWidget(self._build_secret_row(name, description))

        bv.addStretch(1)
        scroll.setWidget(body)
        ov.addWidget(scroll, 1)
        return outer

    def _build_secret_row(self, name: str, description: str) -> QFrame:
        row = QFrame()
        row.setStyleSheet(
            "QFrame { border: 1px solid rgba(255,255,255,0.06); "
            "border-radius: 6px; padding: 6px; }"
        )
        rv = QVBoxLayout(row)
        rv.setSpacing(4)
        rv.setContentsMargins(8, 6, 8, 6)

        head = QHBoxLayout()
        title = QLabel(f"<b>{name}</b>")
        title.setStyleSheet("font-family: 'Geist Mono','Consolas',monospace; font-size: 12px;")
        head.addWidget(title, 1)
        if name in SECRET_HELP_URLS:
            link = QPushButton("Open URL")
            link.setToolTip(SECRET_HELP_URLS[name])
            link.clicked.connect(
                lambda _=False, u=SECRET_HELP_URLS[name]: webbrowser.open(u)
            )
            head.addWidget(link)
        rv.addLayout(head)

        desc = QLabel(description)
        desc.setStyleSheet("color: #9aa0ad; font-size: 11px;")
        desc.setWordWrap(True)
        rv.addWidget(desc)

        # Resolve current value (mask if present).
        try:
            current_val = get_secret(name) or ""
        except Exception:
            current_val = ""
        edit = QLineEdit()
        edit.setEchoMode(QLineEdit.EchoMode.Password)
        if current_val:
            edit.setPlaceholderText("•" * 12)
        else:
            edit.setPlaceholderText("(not set)")

        controls = QHBoxLayout()
        controls.setSpacing(6)
        controls.addWidget(edit, 1)

        show_btn = QPushButton("Show")
        show_btn.setCheckable(True)
        show_btn.setToolTip("Afficher la valeur en clair temporairement.")

        def _on_show_toggled(checked: bool, le=edit, btn=show_btn, n=name):
            if checked:
                # Reveal: prefer the current input, fall back to the stored val.
                if not le.text():
                    try:
                        v = get_secret(n) or ""
                    except Exception:
                        v = ""
                    if v:
                        le.setText(v)
                le.setEchoMode(QLineEdit.EchoMode.Normal)
                btn.setText("Hide")
            else:
                le.setEchoMode(QLineEdit.EchoMode.Password)
                btn.setText("Show")

        show_btn.toggled.connect(_on_show_toggled)
        controls.addWidget(show_btn)

        save_btn = QPushButton("Save")
        save_btn.setDefault(False)
        save_btn.clicked.connect(
            lambda _=False, n=name, le=edit: self._save_one_secret(n, le)
        )
        controls.addWidget(save_btn)
        rv.addLayout(controls)

        self._keys_widgets[name] = (edit, show_btn)
        return row

    def _save_one_secret(self, name: str, line_edit: QLineEdit):
        value = line_edit.text().strip()
        if not value:
            QMessageBox.information(
                self, "Argus — clé vide",
                f"Saisis une valeur pour {name} avant de sauvegarder.",
            )
            return
        try:
            store_secret(name, value, owner="user")
        except Exception as e:
            QMessageBox.critical(
                self, "Argus — coffre",
                f"Impossible de stocker {name} :\n{e}",
            )
            return
        # Mask again on success.
        line_edit.clear()
        line_edit.setEchoMode(QLineEdit.EchoMode.Password)
        line_edit.setPlaceholderText("•" * 12)
        QMessageBox.information(
            self, "Argus — coffre",
            f"{name} a été stocké dans le coffre chiffré.",
        )

    def _migrate_from_env(self):
        env_path = ROOT / ".env"
        if not env_path.exists():
            QMessageBox.information(
                self, "Argus — .env",
                f"Aucun fichier .env trouvé à {env_path}.",
            )
            return
        # Parse .env (KEY=VALUE per line, ignore comments / blanks).
        candidates: dict[str, str] = {}
        try:
            for raw in env_path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k and v and k in CANONICAL_SECRETS:
                    candidates[k] = v
        except OSError as e:
            QMessageBox.warning(
                self, "Argus — .env",
                f"Lecture de .env a échoué : {e}",
            )
            return
        if not candidates:
            QMessageBox.information(
                self, "Argus — .env",
                "Aucune clé canonique trouvée dans .env.",
            )
            return
        names = "\n".join(f"  • {k}" for k in candidates)
        ans = QMessageBox.question(
            self, "Argus — migrer .env vers coffre",
            f"Copier {len(candidates)} clé(s) de .env vers le coffre chiffré ?\n\n"
            f"{names}\n\n"
            "Le fichier .env n'est PAS modifié — tu pourras le supprimer manuellement après.",
        )
        if ans != QMessageBox.StandardButton.Yes:
            return
        ok_count = 0
        errors: list[str] = []
        for name, value in candidates.items():
            try:
                store_secret(name, value, owner="env-migration")
                ok_count += 1
            except Exception as e:
                errors.append(f"{name}: {e}")
        msg = f"{ok_count} secret(s) migrés."
        if errors:
            msg += "\n\nErreurs :\n" + "\n".join(errors)
        QMessageBox.information(self, "Argus — migration", msg)

    # ── Vault tab ──────────────────────────────────────────────────────
    def _build_vault_tab(self) -> QWidget:
        outer = QWidget()
        ov = QVBoxLayout(outer)
        ov.setSpacing(8)

        if not HAVE_VAULT:
            warn = QLabel(
                "Module ``argus_vault`` indisponible — gestion du coffre désactivée."
            )
            warn.setWordWrap(True)
            warn.setStyleSheet("color: #ff9e7a; font-size: 12px; padding: 12px;")
            ov.addWidget(warn)
            ov.addStretch(1)
            return outer

        hdr = QLabel(
            "Liste des secrets stockés dans le coffre chiffré. "
            "Les valeurs ne sont jamais affichées, sauf bouton « View » "
            "(confirmation requise)."
        )
        hdr.setWordWrap(True)
        hdr.setStyleSheet("font-size: 12px; color: #9aa0ad;")
        ov.addWidget(hdr)

        # Table: Name / Owner / Created / Actions
        self._vault_table = QTableWidget()
        self._vault_table.setColumnCount(4)
        self._vault_table.setHorizontalHeaderLabels(
            ["Nom", "Owner", "Créé", "Actions"]
        )
        self._vault_table.verticalHeader().setVisible(False)
        self._vault_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._vault_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        try:
            hh = self._vault_table.horizontalHeader()
            hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            hh.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            hh.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        except Exception:
            pass
        ov.addWidget(self._vault_table, 1)
        self._reload_vault_table()

        # Bottom action row
        actions = QHBoxLayout()
        refresh_btn = QPushButton("Rafraîchir")
        refresh_btn.clicked.connect(self._reload_vault_table)
        rotate_btn = QPushButton("Rotate masterkey")
        rotate_btn.setToolTip("Génère une nouvelle clé maître + ré-encrypte tous les secrets.")
        rotate_btn.clicked.connect(self._rotate_masterkey)
        verify_btn = QPushButton("Verify audit chain")
        verify_btn.setToolTip("Vérifie la chaîne d'audit du Vault Gateway (HMAC).")
        verify_btn.clicked.connect(self._verify_audit_chain)
        actions.addWidget(refresh_btn)
        actions.addStretch(1)
        actions.addWidget(verify_btn)
        actions.addWidget(rotate_btn)
        ov.addLayout(actions)
        return outer

    def _reload_vault_table(self):
        """Re-populate the vault table from vault_list() metadata."""
        try:
            entries = vault_list() or []
        except Exception as e:
            entries = []
            QMessageBox.warning(self, "Argus — coffre",
                                f"vault_list() a échoué : {e}")
        self._vault_table.setRowCount(len(entries))
        for r, entry in enumerate(entries):
            name = entry.get("name", "")
            owner = entry.get("owner", "") or "—"
            created = entry.get("created_at", "") or "—"
            self._vault_table.setItem(r, 0, QTableWidgetItem(name))
            self._vault_table.setItem(r, 1, QTableWidgetItem(owner))
            self._vault_table.setItem(r, 2, QTableWidgetItem(created))

            # Actions cell — view / delete
            cell = QWidget()
            cl = QHBoxLayout(cell)
            cl.setContentsMargins(2, 2, 2, 2)
            cl.setSpacing(4)
            view_btn = QPushButton("View")
            view_btn.setToolTip("Affiche la valeur après confirmation.")
            view_btn.clicked.connect(
                lambda _=False, n=name: self._vault_view_value(n)
            )
            del_btn = QPushButton("Delete")
            del_btn.clicked.connect(
                lambda _=False, n=name: self._vault_delete_value(n)
            )
            cl.addWidget(view_btn)
            cl.addWidget(del_btn)
            cl.addStretch(1)
            self._vault_table.setCellWidget(r, 3, cell)

    def _vault_view_value(self, name: str):
        ans = QMessageBox.warning(
            self, "Argus — coffre",
            f"Afficher la valeur de {name} en clair ?\n"
            "La valeur restera affichée 30 secondes.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if ans != QMessageBox.StandardButton.Yes:
            return
        try:
            val = vault_get(name) or ""
        except Exception as e:
            QMessageBox.critical(self, "Argus — coffre",
                                 f"vault_get a échoué : {e}")
            return
        if not val:
            QMessageBox.information(self, "Argus — coffre",
                                    f"{name} : (valeur vide ou indisponible)")
            return
        # Use a non-modal info box that auto-closes.
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setWindowTitle(f"Argus — {name}")
        msg.setText(f"<pre>{val}</pre>")
        QTimer.singleShot(30000, msg.close)
        msg.exec()

    def _vault_delete_value(self, name: str):
        ans = QMessageBox.question(
            self, "Argus — coffre",
            f"Supprimer définitivement {name} du coffre ?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if ans != QMessageBox.StandardButton.Yes:
            return
        try:
            vault_delete(name)
        except Exception as e:
            QMessageBox.critical(self, "Argus — coffre",
                                 f"vault_delete a échoué : {e}")
            return
        self._reload_vault_table()

    def _rotate_masterkey(self):
        # 2FA gate when available.
        if HAVE_2FA:
            try:
                if two_fa_is_setup() and not two_fa_challenge():
                    QMessageBox.warning(self, "Argus — 2FA",
                                        "Échec 2FA — rotation annulée.")
                    return
            except Exception:
                pass
        ans = QMessageBox.question(
            self, "Argus — coffre",
            "Générer une nouvelle clé maître et ré-encrypter tous les secrets ?\n"
            "Cette opération peut être longue selon le nombre de secrets.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if ans != QMessageBox.StandardButton.Yes:
            return
        try:
            vault_rotate_masterkey()
        except Exception as e:
            QMessageBox.critical(self, "Argus — coffre",
                                 f"Rotation a échoué : {e}")
            return
        QMessageBox.information(self, "Argus — coffre",
                                "Clé maître régénérée. Tous les secrets ont été ré-encryptés.")
        self._reload_vault_table()

    def _verify_audit_chain(self):
        if not HAVE_VAULT_GATEWAY:
            QMessageBox.information(
                self, "Argus — gateway",
                "Vault Gateway non disponible — démarre le gateway pour vérifier la chaîne d'audit."
            )
            return
        try:
            ok = bool(gateway_audit_chain_verify())
        except Exception as e:
            QMessageBox.critical(self, "Argus — gateway",
                                 f"Vérification a échoué : {e}")
            return
        if ok:
            QMessageBox.information(self, "Argus — gateway",
                                    "Chaîne d'audit valide ✓")
        else:
            QMessageBox.warning(self, "Argus — gateway",
                                "Chaîne d'audit invalide ou interrompue ✗")

    def _on_theme_preview(self, name: str):
        """Live preview — apply immediately. _cancel reverts."""
        apply_theme(name)

    def _cancel(self):
        # Revert live-preview theme change.
        apply_theme(self._original_theme)
        self.reject()

    def reject(self):
        # Triggered by Esc or window-close-X — revert theme too.
        apply_theme(self._original_theme)
        super().reject()

    def _apply(self):
        new_theme = self.theme_combo.currentText()
        if new_theme not in THEMES:
            new_theme = DEFAULT_THEME
        self.settings_mgr.set("theme", new_theme)
        apply_theme(new_theme)  # ensure persisted choice is applied
        self.settings_mgr.set("show_live_feed", self.cb_feed.isChecked())
        self.settings_mgr.set("show_url_top",   self.cb_url_top.isChecked())
        self.settings_mgr.set("show_url_bottom",self.cb_url_bottom.isChecked())
        self.settings_mgr.set("show_search_row",self.cb_search.isChecked())
        self.settings_mgr.set("show_favs",      self.cb_favs.isChecked())
        # Note: API keys are saved on their per-row Save button — Apply
        # only persists display preferences. We don't auto-save the keys
        # tab to avoid surprising the user with a flush of partial values.
        self.accept()


# ── Live feed ────────────────────────────────────────────────────────────
class FeedSignal(QObject):
    new_request = pyqtSignal(str, str)


class RequestInterceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self, signal: FeedSignal):
        super().__init__()
        self.signal = signal

    def interceptRequest(self, info):
        try:
            url = info.requestUrl().toString()
            method = bytes(info.requestMethod()).decode("ascii", errors="replace")
            self.signal.new_request.emit(method, url)
        except Exception:
            pass


class LiveFeed(QFrame):
    # Emits when the user clicks the version badge — wired by ArgusBrowser
    # to open the About dialog.
    version_clicked = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setObjectName("liveFeed")
        self.setFixedHeight(46)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        # Outer horizontal: rows column on the left, version badge on the right.
        outer = QHBoxLayout(self)
        outer.setContentsMargins(14, 4, 10, 4)
        outer.setSpacing(8)
        rows_col = QVBoxLayout()
        rows_col.setContentsMargins(0, 0, 0, 0)
        rows_col.setSpacing(2)
        outer.addLayout(rows_col, 1)
        # Version badge — clickable, opens About.
        self.version_badge = QPushButton(f"Argus v{ARGUS_VERSION}")
        self.version_badge.setFlat(True)
        self.version_badge.setCursor(Qt.CursorShape.PointingHandCursor)
        self.version_badge.setToolTip("À propos d'Argus")
        self.version_badge.setStyleSheet(
            "QPushButton { background: transparent; color: #9aa0ad; "
            "border: 1px solid rgba(255,255,255,0.10); border-radius: 4px; "
            "padding: 2px 8px; font-size: 10px; "
            "font-family: 'Geist Mono','Consolas',monospace; }"
            "QPushButton:hover { color: #4d9fff; border-color: #4d9fff; }"
        )
        self.version_badge.clicked.connect(self.version_clicked.emit)
        outer.addWidget(self.version_badge, 0, Qt.AlignmentFlag.AlignTop)
        self.layout_box = rows_col
        self.rows: list[QLabel] = []

    def set_update_available(self, available: bool, info: dict | None = None):
        """Mark the version badge to indicate an update is available."""
        if available:
            ver = (info or {}).get("latest", "")
            tip = f"Mise à jour disponible : {ver}" if ver else "Mise à jour disponible"
            self.version_badge.setText(f"Argus v{ARGUS_VERSION} ↑")
            self.version_badge.setToolTip(tip)
            self.version_badge.setStyleSheet(
                "QPushButton { background: rgba(61,255,180,0.10); color: #3dffb4; "
                "border: 1px solid #3dffb4; border-radius: 4px; "
                "padding: 2px 8px; font-size: 10px; "
                "font-family: 'Geist Mono','Consolas',monospace; }"
                "QPushButton:hover { color: #0a0e14; background: #3dffb4; }"
            )

    def push(self, kind: str, method: str, url: str, status: str = "—", time: str = ""):
        display_url = url
        if display_url.startswith(("https://", "http://")):
            display_url = display_url.split("://", 1)[1]
        if len(display_url) > 80:
            display_url = display_url[:77] + "…"
        icon = {"ok": "✓", "warn": "⚠", "bad": "✗", "info": "⏵"}.get(kind, "·")
        text = f"{icon}  {method:<5}  {display_url:<60}  {status:>6}  {time}"
        row = QLabel(text)
        row.setProperty("class", "feedRow")
        row.setProperty("kind", kind)
        row.setStyleSheet("")
        self.layout_box.insertWidget(0, row)
        self.rows.insert(0, row)
        while len(self.rows) > 2:
            old = self.rows.pop()
            self.layout_box.removeWidget(old)
            old.deleteLater()


# ── Tab bar (custom, bookmark-style) ─────────────────────────────────────
class TabBar(QFrame):
    tab_clicked = pyqtSignal(int)
    tab_close_requested = pyqtSignal(int)
    new_tab_requested = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setObjectName("tabBar")
        self.setFixedHeight(36)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        h = QHBoxLayout(self)
        h.setContentsMargins(8, 0, 8, 0)
        h.setSpacing(0)
        self.tabs_layout = QHBoxLayout()
        self.tabs_layout.setSpacing(0)
        self.tabs_layout.setContentsMargins(0, 0, 0, 0)
        h.addLayout(self.tabs_layout)
        self.new_btn = QPushButton("+")
        self.new_btn.setObjectName("newTabBtn")
        self.new_btn.setToolTip("Nouveau tab (Ctrl+T)")
        self.new_btn.clicked.connect(self.new_tab_requested.emit)
        h.addWidget(self.new_btn)
        h.addStretch(1)
        self.tab_buttons: list[QPushButton] = []
        self.close_buttons: list[QPushButton] = []
        self.tab_widgets: list[QWidget] = []  # container holding btn+close

    def add_tab(self, idx: int, title: str = "Loading…", mode: str = "normal"):
        wrapper = QFrame()
        w_layout = QHBoxLayout(wrapper)
        w_layout.setContentsMargins(0, 0, 0, 0)
        w_layout.setSpacing(0)
        btn = QPushButton(self._truncate(title))
        btn.setProperty("class", "tab")
        btn.setProperty("active", False)
        btn.setProperty("mode", mode)
        btn.clicked.connect(lambda _, i=idx: self.tab_clicked.emit(self.tab_buttons.index(btn)))
        close = QPushButton("×")
        close.setProperty("class", "tabClose")
        close.clicked.connect(lambda _, i=idx: self.tab_close_requested.emit(self.tab_buttons.index(btn)))
        w_layout.addWidget(btn)
        w_layout.addWidget(close)
        self.tab_buttons.append(btn)
        self.close_buttons.append(close)
        self.tab_widgets.append(wrapper)
        self.tabs_layout.addWidget(wrapper)
        return btn

    def remove_tab(self, idx: int):
        if 0 <= idx < len(self.tab_buttons):
            self.tabs_layout.removeWidget(self.tab_widgets[idx])
            self.tab_widgets[idx].deleteLater()
            self.tab_buttons.pop(idx)
            self.close_buttons.pop(idx)
            self.tab_widgets.pop(idx)

    def update_tab(self, idx: int, title: str = None, mode: str = None):
        if 0 <= idx < len(self.tab_buttons):
            btn = self.tab_buttons[idx]
            if title is not None:
                btn.setText(self._truncate(title))
                btn.setToolTip(title)
            if mode is not None:
                btn.setProperty("mode", mode)
                btn.style().unpolish(btn); btn.style().polish(btn)

    def set_active(self, idx: int):
        for i, btn in enumerate(self.tab_buttons):
            btn.setProperty("active", i == idx)
            btn.style().unpolish(btn); btn.style().polish(btn)

    @staticmethod
    def _truncate(title: str, n: int = 22) -> str:
        if not title:
            return "Loading…"
        return title if len(title) <= n else title[:n - 1] + "…"


# ── AI side panel (right collapsible) ────────────────────────────────────
class AIPanel(QFrame):
    """Right-side collapsible AI assistant panel.

    Width animates 0 ↔ 380px (200ms OutCubic). Sends chat to
    netguard_ai_server.py at AI_SERVER_BASE/api/chat. Conversation persisted
    to argus_data/ai_history.json (last AI_HISTORY_MAX messages).

    Page context (URL + first 4096 chars of QWebEnginePage.toPlainText) is
    attached to each user message via a system-style note so the model can
    reason about whatever the user is currently looking at.
    """
    EXPANDED_WIDTH = 380
    ANIM_MS = 200

    # Signal: emits when the user clicks Send and we need the current page text.
    # The browser provides the page; the panel only sees a callable + url.
    page_text_requested = pyqtSignal()

    def __init__(self, history_mgr: AIHistoryManager, parent=None):
        super().__init__(parent)
        self.setObjectName("aiPanel")
        self.history = history_mgr
        self.is_open = False
        self._worker: AIChatWorker | None = None
        self._pending_user_msg: str | None = None
        # Provided by the browser owner via set_page_provider().
        self._page_provider: callable | None = None

        self.setFixedWidth(0)
        self.setMinimumWidth(0)
        self.setMaximumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)

        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        # Header — provider combo + Clear
        header = QFrame()
        header.setObjectName("aiPanelHeader")
        header.setFixedHeight(40)
        h = QHBoxLayout(header)
        h.setContentsMargins(8, 4, 8, 4)
        h.setSpacing(6)
        title = QLabel("AI")
        title.setObjectName("aiPanelTitle")
        self.provider_combo = QComboBox()
        for _name, label in AI_PROVIDER_FALLBACK:
            self.provider_combo.addItem(label)
        self.provider_combo.setToolTip(
            "Provider actif. Le choix réel se règle via netguard_ai_settings.json (clés API)."
        )
        clear_btn = QPushButton("Clear")
        clear_btn.setObjectName("aiClearBtn")
        clear_btn.setToolTip("Vider la conversation")
        clear_btn.clicked.connect(self._clear_conversation)
        h.addWidget(title)
        h.addWidget(self.provider_combo, 1)
        h.addWidget(clear_btn)
        v.addWidget(header)

        # Conversation history (HTML rendered into QTextBrowser)
        self.history_view = QTextBrowser()
        self.history_view.setObjectName("aiHistory")
        self.history_view.setOpenExternalLinks(False)
        v.addWidget(self.history_view, 1)

        # Bottom — input + send + quick actions
        bottom = QFrame()
        bottom.setObjectName("aiPanelBottom")
        b = QVBoxLayout(bottom)
        b.setContentsMargins(8, 6, 8, 8)
        b.setSpacing(6)

        # Input row: QTextEdit (3-line height) + Send button
        input_row = QHBoxLayout()
        input_row.setSpacing(6)
        self.input = QTextEdit()
        self.input.setObjectName("aiInput")
        self.input.setPlaceholderText("Pose une question…  (Ctrl+Enter pour envoyer)")
        # ~3 lines @ 12pt ≈ 60px
        self.input.setFixedHeight(60)
        self.input.setAcceptRichText(False)
        self.input.installEventFilter(self)
        self.send_btn = QPushButton("Send")
        self.send_btn.setObjectName("aiSendBtn")
        self.send_btn.clicked.connect(self._send_clicked)
        input_row.addWidget(self.input, 1)
        input_row.addWidget(self.send_btn)
        b.addLayout(input_row)

        # Quick actions
        qa_row = QHBoxLayout()
        qa_row.setSpacing(4)
        for label, prefill in AI_QUICK_ACTIONS:
            btn = QPushButton(label)
            btn.setProperty("class", "aiQuick")
            btn.setToolTip(prefill)
            btn.clicked.connect(lambda _=False, p=prefill: self._prefill(p))
            qa_row.addWidget(btn)
        qa_row.addStretch(1)
        b.addLayout(qa_row)

        v.addWidget(bottom)

        # Animator
        self._anim = QPropertyAnimation(self, b"maximumWidth")
        self._anim.setDuration(self.ANIM_MS)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim2 = QPropertyAnimation(self, b"minimumWidth")
        self._anim2.setDuration(self.ANIM_MS)
        self._anim2.setEasingCurve(QEasingCurve.Type.OutCubic)

        # Restore saved conversation
        self._render_history()

    # ── Page-text bridge (browser provides current QWebEngineView) ──
    def set_page_provider(self, fn):
        """Register a callable returning (url, view) for the current tab."""
        self._page_provider = fn

    # ── UX behaviour ────────────────────────────────────────────────
    def eventFilter(self, obj, event):
        if obj is self.input and event.type() == event.Type.KeyPress:
            mods = event.modifiers()
            if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) \
                    and (mods & Qt.KeyboardModifier.ControlModifier):
                self._send_clicked()
                return True
        return super().eventFilter(obj, event)

    def toggle(self):
        if self.is_open:
            self.collapse()
        else:
            self.expand()

    def expand(self):
        if self.is_open:
            return
        self.is_open = True
        self._animate_to(self.EXPANDED_WIDTH)
        # Focus input for immediate typing
        QTimer.singleShot(self.ANIM_MS + 30, lambda: self.input.setFocus())

    def collapse(self):
        if not self.is_open:
            return
        self.is_open = False
        self._animate_to(0)

    def _animate_to(self, target: int):
        for anim, prop_get in (
            (self._anim, self.maximumWidth),
            (self._anim2, self.minimumWidth),
        ):
            anim.stop()
            anim.setStartValue(prop_get())
            anim.setEndValue(target)
            anim.start()

    def _prefill(self, text: str):
        self.input.setPlainText(text)
        self.input.setFocus()
        cursor = self.input.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.input.setTextCursor(cursor)

    def _clear_conversation(self):
        self.history.clear()
        self._render_history()

    # ── Send ────────────────────────────────────────────────────────
    def _send_clicked(self):
        text = self.input.toPlainText().strip()
        if not text or self._worker is not None:
            return
        # Capture page text asynchronously (callable returns view; we call toPlainText with a 2s timeout fallback).
        self._pending_user_msg = text
        self.input.clear()
        # Append user msg immediately
        self.history.append("user", text)
        self._render_history()
        self.send_btn.setEnabled(False)
        # Show typing indicator
        self._set_typing(True)
        # Try to get page text; fall back to URL only if it doesn't return in time.
        url, view = self._current_page_info()
        if view is not None:
            received = {"done": False}

            def on_text(plain_text: str):
                if received["done"]:
                    return
                received["done"] = True
                ctx_text = (plain_text or "")[:AI_PAGE_TEXT_MAX]
                self._send_to_backend(text, url, ctx_text)

            try:
                view.page().toPlainText(on_text)
            except Exception:
                received["done"] = True
                self._send_to_backend(text, url, "")
                return

            def fallback():
                if received["done"]:
                    return
                received["done"] = True
                self._send_to_backend(text, url, "")

            QTimer.singleShot(AI_PAGE_TEXT_TIMEOUT_MS, fallback)
        else:
            self._send_to_backend(text, url, "")

    def _current_page_info(self):
        if self._page_provider is None:
            return ("", None)
        try:
            return self._page_provider()
        except Exception:
            return ("", None)

    def _send_to_backend(self, user_msg: str, url: str, page_text: str):
        # Build the message list: full saved conversation, plus a context-augmented
        # version of the *latest* user msg. We only mutate the last entry in `for_api()`
        # so prior turns stay untouched.
        msgs = self.history.for_api()
        if msgs and msgs[-1]["role"] == "user":
            ctx_block = self._format_ctx(url, page_text)
            msgs[-1] = {"role": "user", "content": f"{ctx_block}{user_msg}"}
        # Lang from system locale would be better; default to French for this build.
        worker = AIChatWorker(messages=msgs, lang="fr")
        worker.done.connect(self._on_worker_done)
        worker.failed.connect(self._on_worker_failed)
        self._worker = worker
        worker.start()

    @staticmethod
    def _format_ctx(url: str, page_text: str) -> str:
        if not url and not page_text:
            return ""
        parts = ["[Page context]"]
        if url:
            parts.append(f"URL: {url}")
        if page_text:
            parts.append("Content (first 4096 chars):")
            parts.append(page_text)
        parts.append("[/Page context]\n\n")
        return "\n".join(parts)

    def _on_worker_done(self, reply: str, _raw: dict):
        self._worker = None
        self._set_typing(False)
        self.send_btn.setEnabled(True)
        if not reply:
            reply = "(Réponse vide)"
        self.history.append("assistant", reply)
        self._render_history()

    def _on_worker_failed(self, error: str):
        self._worker = None
        self._set_typing(False)
        self.send_btn.setEnabled(True)
        self.history.append("error", error)
        self._render_history()

    # ── Rendering ───────────────────────────────────────────────────
    def _set_typing(self, on: bool):
        # Re-render with optional trailing typing bubble.
        self._typing = on
        self._render_history()

    def _render_history(self):
        """Render the conversation as HTML bubbles into the QTextBrowser."""
        html_parts = [
            "<style>",
            "body { background: transparent; margin: 0; padding: 4px; }",
            ".row-u { text-align: right; margin: 6px 0; }",
            ".row-a { text-align: left;  margin: 6px 0; }",
            ".bubble-u { display: inline-block; max-width: 88%; padding: 8px 10px; "
            "border-radius: 10px 10px 2px 10px; background: #4d9fff; color: #ffffff; "
            "white-space: pre-wrap; text-align: left; }",
            ".bubble-a { display: inline-block; max-width: 88%; padding: 8px 10px; "
            "border-radius: 10px 10px 10px 2px; background: #1c2128; color: #e6edf3; "
            "white-space: pre-wrap; }",
            ".bubble-e { display: inline-block; max-width: 88%; padding: 8px 10px; "
            "border-radius: 8px; background: #3a1419; color: #ff9da6; "
            "border: 1px solid #ff4d6a; white-space: pre-wrap; }",
            ".retry { display: inline-block; margin-left: 8px; padding: 2px 8px; "
            "border: 1px solid #ff4d6a; border-radius: 4px; color: #ff4d6a; "
            "text-decoration: none; font-size: 11px; }",
            ".typing { display: inline-block; padding: 6px 10px; border-radius: 10px; "
            "background: #1c2128; color: #9aa0ad; }",
            "</style>",
        ]
        for m in self.history.messages:
            content = m.get("content", "")
            # Escape HTML — user content is untrusted page text in some cases.
            safe = (content
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;"))
            if m["role"] == "user":
                html_parts.append(f'<div class="row-u"><span class="bubble-u">{safe}</span></div>')
            elif m["role"] == "assistant":
                html_parts.append(f'<div class="row-a"><span class="bubble-a">{safe}</span></div>')
            else:  # error
                html_parts.append(
                    f'<div class="row-a"><span class="bubble-e">{safe}'
                    f'<a href="argus://retry" class="retry">Retry</a></span></div>'
                )
        if getattr(self, "_typing", False):
            html_parts.append('<div class="row-a"><span class="typing">…</span></div>')

        self.history_view.setHtml("\n".join(html_parts))
        # Auto-scroll to bottom
        scrollbar = self.history_view.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        # Wire retry link clicks (anchorClicked emits QUrl)
        try:
            self.history_view.anchorClicked.disconnect()
        except TypeError:
            pass
        self.history_view.anchorClicked.connect(self._on_anchor_clicked)

    def _on_anchor_clicked(self, url):
        # Only handle our internal "argus://retry" pseudo-link.
        if url.toString() != "argus://retry":
            return
        # Find the last user message and resend it
        for m in reversed(self.history.messages):
            if m["role"] == "user":
                self._prefill(m["content"])
                self._send_clicked()
                return


# ── Vault auto-switch banner ─────────────────────────────────────────────
class VaultBanner(QFrame):
    """Non-modal banner shown when the user navigates to a known banking /
    payment / brokerage domain while NOT already in vault mode.

    Appears at the top of the tab content area. Three actions:
        * Switch to Vault — invokes the parent's mode-switch with a vault
          target.
        * Not now — hide the banner for this navigation only.
        * Always — persist the host to ``vault_auto_switch.json`` so future
          visits trigger an automatic switch (still respecting 2FA).
    """
    switch_requested = pyqtSignal(str)   # institution_name
    always_requested = pyqtSignal(str)   # host
    dismissed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("vaultBanner")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(
            "QFrame#vaultBanner { background: #d4af37; border-bottom: 1px solid #b8860b; }"
            "QFrame#vaultBanner QLabel { color: #1a1410; font-weight: 600; "
            "font-size: 12px; padding: 6px 10px; }"
            "QFrame#vaultBanner QPushButton.bannerPrimary { "
            "background: #1a1410; color: #d4af37; border: 1px solid #1a1410; "
            "border-radius: 4px; padding: 4px 12px; font-size: 11px; font-weight: 600; }"
            "QFrame#vaultBanner QPushButton.bannerPrimary:hover { background: #2a2018; }"
            "QFrame#vaultBanner QPushButton.bannerSecondary { "
            "background: transparent; color: #1a1410; border: 1px solid #1a1410; "
            "border-radius: 4px; padding: 4px 10px; font-size: 11px; }"
            "QFrame#vaultBanner QPushButton.bannerSecondary:hover { background: rgba(0,0,0,0.06); }"
            "QFrame#vaultBanner QPushButton.bannerLink { "
            "background: transparent; color: #1a1410; border: none; "
            "padding: 4px 6px; font-size: 11px; text-decoration: underline; }"
        )
        self.setFixedHeight(38)
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 0, 8, 0)
        h.setSpacing(6)
        self._label = QLabel("Banking detected")
        h.addWidget(self._label, 1)
        self._switch_btn = QPushButton("Switch to Vault")
        self._switch_btn.setProperty("class", "bannerPrimary")
        self._switch_btn.clicked.connect(self._emit_switch)
        h.addWidget(self._switch_btn)
        self._notnow_btn = QPushButton("Not now")
        self._notnow_btn.setProperty("class", "bannerSecondary")
        self._notnow_btn.clicked.connect(self._emit_dismiss)
        h.addWidget(self._notnow_btn)
        self._always_btn = QPushButton("Always")
        self._always_btn.setProperty("class", "bannerLink")
        self._always_btn.clicked.connect(self._emit_always)
        h.addWidget(self._always_btn)
        self._institution = ""
        self._host = ""
        self.hide()

    def show_for(self, institution_name: str, host: str):
        self._institution = institution_name or "this institution"
        self._host = host or ""
        self._label.setText(
            f"  Banking detected: {self._institution}. "
            f"Switch to Vault mode for stricter protection?"
        )
        self.show()

    def _emit_switch(self):
        self.switch_requested.emit(self._institution)
        self.hide()

    def _emit_dismiss(self):
        self.hide()
        self.dismissed.emit()

    def _emit_always(self):
        if self._host:
            self.always_requested.emit(self._host)
        self.hide()


# ── Form-submit JS bridge (Wave 2 task #7) ───────────────────────────────
# A small JS payload installed into every page profile that intercepts
# form.submit events, stops propagation, then notifies the host via a
# location.hash sentinel that Python polls. Python decides via arbiter
# whether to allow the submit — if allowed, JS replays the submission.
#
# This is the lowest-friction integration that doesn't require QWebChannel
# (which adds a runtime dependency on qtwebchannel.js being injected first).
# For V1 we ship logging only, with arbiter check kept best-effort: JS
# pauses the submit, records context, calls Python, and Python decides
# whether to release. If anything goes wrong the form proceeds (fail-open)
# because blocking real banking submits via JS edge-cases would be worse
# than the alternative.
FORM_SUBMIT_INTERCEPT_JS = r"""
(function () {
  if (window.__argusFormHookInstalled) return;
  window.__argusFormHookInstalled = true;

  function summarize(form) {
    var fields = form.elements ? form.elements.length : 0;
    var hasPwd = false, hasCC = false;
    try {
      for (var i = 0; i < form.elements.length; i++) {
        var el = form.elements[i];
        var t = (el.type || '').toLowerCase();
        var n = (el.name || '').toLowerCase();
        if (t === 'password') hasPwd = true;
        if (n.indexOf('card') !== -1 || n.indexOf('cc') !== -1 ||
            n.indexOf('cvv') !== -1 || /\bccnum\b/.test(n)) hasCC = true;
      }
    } catch (e) {}
    return {
      action_url: form.action || window.location.href,
      method: (form.method || 'GET').toUpperCase(),
      fields_count: fields,
      has_password: hasPwd,
      has_cc: hasCC,
      origin: window.location.href
    };
  }

  document.addEventListener('submit', function (ev) {
    try {
      var form = ev.target;
      if (!form || !form.tagName || form.tagName.toLowerCase() !== 'form') return;
      var info = summarize(form);
      // Best-effort beacon to host. Python polls runJavaScript for these.
      window.__argusLastFormSubmit = info;
      // Surface a short text marker the host can grep without a full RTT.
      var beacon = '__ARGUS_FORM_SUBMIT__:' + JSON.stringify(info);
      try { console.log(beacon); } catch (e) {}
    } catch (e) { /* swallow */ }
  }, true);
})();
"""


# ── Custom QWebEnginePage that intercepts new-window + injects download hook ──
class ArgusWebPage(QWebEnginePage):
    """QWebEnginePage subclass that:

    * Routes window.open / target=_blank into a new tab in our custom
      TabBar instead of spawning an unmanaged QWebEngineView.
    * Forwards JavaScript console messages so the host can grep for the
      ``__ARGUS_FORM_SUBMIT__`` beacon emitted by FORM_SUBMIT_INTERCEPT_JS
      and route the event to surveillance + arbiter.

    The browser owner registers itself via :meth:`set_owner` so the page
    can call back without holding a hard ref to the QMainWindow.
    """
    def __init__(self, profile, parent=None):
        super().__init__(profile, parent)
        self._owner = None

    def set_owner(self, owner):
        self._owner = owner

    def javaScriptConsoleMessage(self, level, message, line, source_id):
        # Forward the form-submit beacon to the host owner.
        try:
            if message and message.startswith("__ARGUS_FORM_SUBMIT__:"):
                payload = message.split(":", 1)[1]
                if self._owner is not None and hasattr(self._owner, "_on_form_submit_beacon"):
                    self._owner._on_form_submit_beacon(payload)
        except Exception:
            pass
        # Default behaviour (no-op in PyQt6 base).
        try:
            super().javaScriptConsoleMessage(level, message, line, source_id)
        except Exception:
            pass

    def createWindow(self, _wintype):
        # Open in a new tab inside our window. Returning None lets Qt
        # silently drop popups (the desired behaviour when no owner).
        if self._owner is not None and hasattr(self._owner, "_open_new_tab"):
            self._owner._open_new_tab("about:blank")
            view = self._owner._current_view()
            if view is not None:
                return view.page()
        return None


# ── Quick switcher (Ctrl+K) ──────────────────────────────────────────────
class QuickSwitcherDialog(QDialog):
    """VS Code style command palette + tab/history/bookmark fuzzy finder.

    Sources are aggregated lazily via a callable injected by ArgusBrowser
    so this widget stays decoupled from the browser internals.
    """

    def __init__(self, sources_provider, on_activate, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Argus — Quick Switcher")
        self.setObjectName("quickSwitcher")
        self.setModal(True)
        self.resize(600, 400)
        self._sources_provider = sources_provider
        self._on_activate = on_activate
        self._items: list[dict] = []

        v = QVBoxLayout(self)
        v.setContentsMargins(10, 10, 10, 10)
        v.setSpacing(6)

        self.input = QLineEdit()
        self.input.setPlaceholderText("Tabs / History / Bookmarks / Commands…")
        self.input.textChanged.connect(self._refilter)
        self.input.returnPressed.connect(self._activate_current)
        v.addWidget(self.input)

        self.list = QListWidget()
        self.list.setUniformItemSizes(True)
        self.list.itemActivated.connect(lambda _i: self._activate_current())
        self.list.itemDoubleClicked.connect(lambda _i: self._activate_current())
        v.addWidget(self.list, 1)

        # Populate lazily so opening is fast even with big history.
        QTimer.singleShot(0, self._reload_items)
        self.input.setFocus()

    def keyPressEvent(self, event):  # type: ignore[override]
        # Esc closes; Up/Down navigate the list even from the input field.
        if event.key() == Qt.Key.Key_Escape:
            self.reject()
            return
        if event.key() in (Qt.Key.Key_Down, Qt.Key.Key_Up):
            row = self.list.currentRow()
            n = self.list.count()
            if n > 0:
                if event.key() == Qt.Key.Key_Down:
                    self.list.setCurrentRow(min(row + 1, n - 1))
                else:
                    self.list.setCurrentRow(max(row - 1, 0))
            return
        super().keyPressEvent(event)

    def _reload_items(self):
        try:
            self._items = list(self._sources_provider())
        except Exception:
            self._items = []
        self._refilter(self.input.text())

    @staticmethod
    def _fuzzy_score(needle: str, hay: str) -> int:
        """Naive case-insensitive subsequence score; -1 means no match."""
        if not needle:
            return 0
        needle = needle.lower()
        hay_low = hay.lower()
        # Prefer prefix matches.
        if hay_low.startswith(needle):
            return 1000 - len(hay_low)
        if needle in hay_low:
            return 500 - hay_low.index(needle)
        # Subsequence fallback.
        i = 0
        for ch in hay_low:
            if ch == needle[i]:
                i += 1
                if i == len(needle):
                    return 100
        return -1

    def _refilter(self, text: str):
        self.list.clear()
        text = (text or "").strip()
        scored: list[tuple[int, dict]] = []
        for it in self._items:
            label = it.get("label", "")
            score = self._fuzzy_score(text, label)
            if score >= 0:
                scored.append((score, it))
        scored.sort(key=lambda x: -x[0])
        for _s, it in scored[:60]:
            icon = it.get("icon", "•")
            label = it.get("label", "")
            row = QListWidgetItem(f"{icon}  {label}")
            row.setData(Qt.ItemDataRole.UserRole, it)
            self.list.addItem(row)
        if self.list.count() > 0:
            self.list.setCurrentRow(0)

    def _activate_current(self):
        row = self.list.currentItem()
        if row is None and self.list.count() > 0:
            row = self.list.item(0)
        if row is None:
            return
        item = row.data(Qt.ItemDataRole.UserRole)
        try:
            self._on_activate(item)
        finally:
            self.accept()


# ── About dialog ─────────────────────────────────────────────────────────
class AboutDialog(QDialog):
    """Help > About — shows version, license, modules detected, diagnostics."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("À propos d'Argus")
        self.resize(480, 540)
        v = QVBoxLayout(self)
        v.setContentsMargins(20, 20, 20, 16)
        v.setSpacing(8)

        # Logo
        try:
            logo_path = ROOT / "branding" / "argus" / "argus_v2_256.png"
            if not logo_path.exists():
                logo_path = ROOT / "branding" / "argus" / "argus_normal.png"
            if logo_path.exists():
                pix = QPixmap(str(logo_path))
                if not pix.isNull():
                    logo = QLabel()
                    logo.setPixmap(pix.scaled(96, 96,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation))
                    logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
                    v.addWidget(logo)
        except Exception:
            pass

        title = QLabel(f"<b style='font-size:18px;'>Argus v{ARGUS_VERSION}</b>")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v.addWidget(title)

        tagline = QLabel("Cybersecurity browser & workbench — l'œil aux 100 yeux.")
        tagline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tagline.setStyleSheet("color:#9aa0ad; font-size:12px;")
        v.addWidget(tagline)

        info_lines = [
            "Licence : <b>GPL v3</b> — voir LICENSE",
            'Repo : <a href="https://github.com/sxc3030-eng/netguard-pro-suite">'
            'github.com/sxc3030-eng/netguard-pro-suite</a>',
        ]
        info = QLabel("<br>".join(info_lines))
        info.setOpenExternalLinks(True)
        info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info.setStyleSheet("font-size:12px; padding:4px;")
        v.addWidget(info)

        # Modules detected
        modules = [
            ("Sandbox",      HAVE_SANDBOX),
            ("Surveillance", HAVE_SURVEILLANCE),
            ("Arbiter",      HAVE_ARBITER),
            ("Vault",        HAVE_VAULT),
            ("Vault domains",HAVE_VAULT_DOMAINS),
            ("Vault gateway",HAVE_VAULT_GATEWAY),
            ("2FA",          HAVE_2FA),
            ("Onboarding",   HAVE_ONBOARDING),
            ("Config",       HAVE_CONFIG),
            ("Mythos bus",   HAVE_MYTHOS),
            ("Updater",      HAVE_UPDATER),
        ]
        mod_text = "<b>Modules détectés :</b><br>" + "<br>".join(
            f"&nbsp;&nbsp;{'✓' if ok else '✗'} {n}" for n, ok in modules
        )
        mod_label = QLabel(mod_text)
        mod_label.setStyleSheet("font-size:11px; padding:6px;")
        v.addWidget(mod_label)

        v.addStretch(1)

        btns = QHBoxLayout()
        copy_btn = QPushButton("Copier diagnostic")
        copy_btn.clicked.connect(self._copy_diag)
        ok_btn = QPushButton("Fermer")
        ok_btn.setDefault(True)
        ok_btn.clicked.connect(self.accept)
        btns.addWidget(copy_btn)
        btns.addStretch(1)
        btns.addWidget(ok_btn)
        v.addLayout(btns)

    def _copy_diag(self):
        try:
            from PyQt6.QtCore import QT_VERSION_STR
        except Exception:
            QT_VERSION_STR = "?"
        modules = {
            "Sandbox":       HAVE_SANDBOX,
            "Surveillance":  HAVE_SURVEILLANCE,
            "Arbiter":       HAVE_ARBITER,
            "Vault":         HAVE_VAULT,
            "Vault domains": HAVE_VAULT_DOMAINS,
            "Vault gateway": HAVE_VAULT_GATEWAY,
            "2FA":           HAVE_2FA,
            "Onboarding":    HAVE_ONBOARDING,
            "Config":        HAVE_CONFIG,
            "Mythos bus":    HAVE_MYTHOS,
            "Updater":       HAVE_UPDATER,
        }
        diag = (
            f"Argus v{ARGUS_VERSION}\n"
            f"Python   : {platform.python_version()}\n"
            f"Platform : {platform.system()} {platform.release()} ({platform.machine()})\n"
            f"PyQt6/Qt : {QT_VERSION_STR}\n"
            f"Modules  :\n"
            + "\n".join(f"  {'+' if v else '-'} {k}" for k, v in modules.items())
        )
        try:
            cb = QApplication.clipboard()
            cb.setText(diag)
            QMessageBox.information(self, "Diagnostic", "Copié dans le presse-papier.")
        except Exception:
            QMessageBox.warning(self, "Diagnostic",
                                "Échec de la copie. Voici le contenu :\n\n" + diag)


# ── Reader mode overlay ──────────────────────────────────────────────────
class ReaderModeOverlay(QFrame):
    """F9 reader mode — strips chrome, shows article in serif font.

    Content is extracted from the current page via simple JS (article tag,
    main tag, or fallback to body innerText).
    """

    summary_requested = pyqtSignal(str)  # emits raw text → AI summarize
    closed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("readerOverlay")
        self.setStyleSheet("""
            QFrame#readerOverlay {
                background: rgba(20, 24, 33, 0.98);
            }
            QFrame#readerInner {
                background: #1a1f28;
                border: 1px solid rgba(255,255,255,0.08);
                border-radius: 10px;
            }
            QPushButton#readerClose {
                background: transparent;
                color: #9aa0ad;
                border: 1px solid rgba(255,255,255,0.12);
                border-radius: 5px;
                padding: 4px 10px;
                font-size: 12px;
            }
            QPushButton#readerClose:hover { color: #ff4d6a; border-color: #ff4d6a; }
            QPushButton#readerSummary {
                background: #4d9fff;
                color: #0a0e14;
                border: 1px solid #4d9fff;
                border-radius: 5px;
                padding: 4px 12px;
                font-size: 12px;
                font-weight: 600;
            }
            QTextBrowser#readerBody {
                background: transparent;
                color: #e6edf3;
                border: none;
                font-family: 'Georgia','Cambria','Times New Roman',serif;
                font-size: 16px;
                padding: 24px 32px;
            }
            QLabel#readerTitle {
                color: #e6edf3;
                font-family: 'Georgia',serif;
                font-size: 22px;
                font-weight: 700;
                padding: 4px 8px;
            }
        """)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(40, 40, 40, 40)

        inner = QFrame()
        inner.setObjectName("readerInner")
        # Constrain to readable width.
        inner.setMaximumWidth(820)
        iv = QVBoxLayout(inner)
        iv.setContentsMargins(0, 0, 0, 0)
        iv.setSpacing(0)

        bar = QFrame()
        bv = QHBoxLayout(bar)
        bv.setContentsMargins(12, 10, 12, 10)
        self.title_lbl = QLabel("Reader mode")
        self.title_lbl.setObjectName("readerTitle")
        bv.addWidget(self.title_lbl, 1)
        self.summary_btn = QPushButton("📝 Résume")
        self.summary_btn.setObjectName("readerSummary")
        self.summary_btn.setToolTip("Demande un résumé IA de cet article (Ctrl+J)")
        self.summary_btn.clicked.connect(self._emit_summary)
        bv.addWidget(self.summary_btn)
        close_btn = QPushButton("Fermer")
        close_btn.setObjectName("readerClose")
        close_btn.clicked.connect(self.closed.emit)
        bv.addWidget(close_btn)
        iv.addWidget(bar)

        self.body = QTextBrowser()
        self.body.setObjectName("readerBody")
        self.body.setOpenExternalLinks(True)
        iv.addWidget(self.body, 1)

        wrap = QHBoxLayout()
        wrap.addStretch(1)
        wrap.addWidget(inner, 1)
        wrap.addStretch(1)
        outer.addLayout(wrap, 1)

    def show_content(self, title: str, text: str):
        self.title_lbl.setText(title or "Reader mode")
        # QTextBrowser handles plain text + paragraphs nicely.
        self.body.setPlainText(text or "(Pas de contenu extrait.)")
        self.show()
        self.raise_()

    def _emit_summary(self):
        text = self.body.toPlainText()
        if text:
            self.summary_requested.emit(text[:6000])


# ── Code sandbox QPlainTextEdit fallback (when Monaco HTML missing) ──────
class CodeSandboxFallback(QWidget):
    """Minimal QPlainTextEdit + Run button — used when monaco_sandbox.html
    is missing or QWebEngine fails to load it. Runs JS via QWebEngineView
    eval, no Pyodide."""

    def __init__(self, parent=None):
        super().__init__(parent)
        v = QVBoxLayout(self)
        v.setContentsMargins(8, 8, 8, 8)
        v.setSpacing(6)

        toolbar = QHBoxLayout()
        run_btn = QPushButton("Run JS")
        run_btn.clicked.connect(self._run)
        clear_btn = QPushButton("Clear output")
        clear_btn.clicked.connect(lambda: self.output.clear())
        toolbar.addWidget(QLabel("Code Sandbox (fallback)"))
        toolbar.addStretch(1)
        toolbar.addWidget(run_btn)
        toolbar.addWidget(clear_btn)
        v.addLayout(toolbar)

        self.editor = QPlainTextEdit()
        self.editor.setPlaceholderText("// JS code here. Click Run JS.")
        self.editor.setStyleSheet("font-family: 'Geist Mono','Consolas',monospace;")
        self.editor.setPlainText(
            "// Argus Code Sandbox (fallback mode).\n"
            "console.log('Hello from Argus!');\n"
            "1 + 1\n"
        )
        v.addWidget(self.editor, 2)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("font-family: 'Geist Mono','Consolas',monospace; background: #050709;")
        v.addWidget(self.output, 1)

        # Hidden web view used as JS evaluator.
        self._eval_view = QWebEngineView()
        self._eval_view.setVisible(False)
        self._eval_view.setHtml("<html><body><script>console.log('eval-ready');</script></body></html>")

    def _run(self):
        code = self.editor.toPlainText()
        # Wrap in IIFE that captures console.log, returns the result string.
        wrapper = (
            "(function(){var _o=[];var _e=console.log;console.log=function(){"
            "_o.push(Array.prototype.map.call(arguments,function(a){"
            "try{return typeof a==='object'?JSON.stringify(a):String(a);}catch(e){return String(a);}"
            "}).join(' '));};try{var r=eval(" + json.dumps(code) + ");console.log=_e;"
            "return _o.join('\\n')+(r!==undefined?'\\n→ '+String(r):'');"
            "}catch(e){console.log=_e;return 'ERROR: '+String(e);}})()"
        )
        try:
            self._eval_view.page().runJavaScript(wrapper, self._on_result)
        except Exception as e:
            self.output.appendPlainText(f"[failed to eval] {e}")

    def _on_result(self, result):
        self.output.appendPlainText(str(result if result is not None else ""))


# ── Main window ──────────────────────────────────────────────────────────
class ArgusBrowser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Argus 2.0 — NetGuard Cybersecurity Browser")

        # Adapt to actual usable area (excludes Windows taskbar / macOS dock /
        # Linux WM panels). Without this the window can extend past the
        # taskbar and clip the bottom dock row.
        try:
            screen = QApplication.primaryScreen()
            avail = screen.availableGeometry() if screen is not None else None
        except Exception:
            avail = None
        if avail is not None and avail.width() > 0 and avail.height() > 0:
            target_w = min(1400, max(960, avail.width() - 40))
            target_h = min(900, max(640, avail.height() - 40))
            self.resize(target_w, target_h)
            self.move(
                avail.x() + (avail.width() - target_w) // 2,
                avail.y() + (avail.height() - target_h) // 2,
            )
        else:
            self.resize(1400, 900)

        self.mode_idx = 0
        # Track current mode by name (separate from the cycling index so vault
        # can be entered/exited without forcing private as an intermediate).
        self.current_mode: str = "normal"
        self.dev_tools_view = None
        self.dev_tools_container = None
        self.tab_pages: list[QWebEngineView] = []
        # Per-tab profile reference so we know which profile a download
        # came from (and can route the download to the right sandbox path).
        self.tab_profiles: list[QWebEngineProfile] = []
        self.favs_mgr = FavoritesManager(FAVS_FILE)
        self.settings_mgr = SettingsManager(SETTINGS_FILE)
        self.ai_history_mgr = AIHistoryManager(AI_HISTORY_FILE)

        # Vault auto-switch — set of hosts the user has whitelisted with
        # "Always". Persisted as JSON in argus_data/vault_auto_switch.json.
        self._vault_always_hosts: set[str] = self._load_vault_always()
        # Track which navigation we already showed a banner for (so the
        # banner doesn't flap during in-page redirects).
        self._banner_shown_host: str = ""

        # Apply persisted theme BEFORE building UI so widgets pick it up.
        apply_theme(self.settings_mgr.get("theme") or DEFAULT_THEME)

        # ── Surveillance / arbiter init (best-effort) ──
        if HAVE_SURVEILLANCE:
            try:
                surveil_init()
            except Exception:
                pass
        if HAVE_ARBITER:
            try:
                arbiter_init("balanced")
            except Exception:
                pass

        # ── Profile (persistent — sessions survive restart) ──
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        DOWNLOADS_SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
        # Default ("normal") profile. Either built via argus_sandbox (preferred,
        # ships randomized UA + anti-skimmer hardening) or a plain persistent
        # profile if the sandbox module is missing.
        if HAVE_SANDBOX:
            try:
                self.profile = make_normal_profile()
                self.profile.setParent(self)
            except Exception:
                self.profile = QWebEngineProfile("argus-default", self)
                self._configure_basic_profile(
                    self.profile,
                    storage=str(DATA_DIR / "normal"),
                    cache=str(CACHE_DIR / "normal"),
                )
        else:
            self.profile = QWebEngineProfile("argus-default", self)
            self._configure_basic_profile(
                self.profile,
                storage=str(DATA_DIR / "normal"),
                cache=str(CACHE_DIR / "normal"),
            )
        # Anti-skimmer hardening + form-submit hook installed on the default
        # profile (re-applied per-profile in _build_profile_for_mode).
        self._install_profile_scripts(self.profile)
        self._wire_profile_downloads(self.profile)

        self.feed_signal = FeedSignal()
        self.feed_signal.new_request.connect(self._on_request)
        self.interceptor = RequestInterceptor(self.feed_signal)
        self.profile.setUrlRequestInterceptor(self.interceptor)

        # Cached pristine private/vault profiles. Built lazily on first use
        # so cold start stays fast (vault profile randomizes UA which is OK
        # to defer).
        self._mode_profiles: dict[str, QWebEngineProfile] = {"normal": self.profile}

        # ── Layout ──
        root = QWidget()
        root.setObjectName("root")
        self.root = root
        self.setCentralWidget(root)
        v = QVBoxLayout(root)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        # Menu bar — File / Help (kept minimal so we don't shadow the existing
        # dock-driven UI, but lets users discover About + new actions).
        self._build_menu_bar()

        self.feed = LiveFeed()
        self.feed.version_clicked.connect(self._open_about)
        v.addWidget(self.feed)

        # Top URL strip (optional) — shows current URL + a spinner on the right
        self.top_url_strip = QFrame()
        self.top_url_strip.setObjectName("topUrlStrip")
        self.top_url_strip.setFixedHeight(26)
        tu_layout = QHBoxLayout(self.top_url_strip)
        tu_layout.setContentsMargins(14, 2, 8, 2)
        tu_layout.setSpacing(6)
        self.top_url_text = QLabel("https://duckduckgo.com")
        self.top_url_text.setObjectName("topUrlText")
        self.top_url_text.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.top_spinner = Spinner("topSpinner")
        tu_layout.addWidget(self.top_url_text, 1)
        tu_layout.addWidget(self.top_spinner)
        v.addWidget(self.top_url_strip)

        self.tab_bar = TabBar()
        self.tab_bar.tab_clicked.connect(self._on_tab_clicked)
        self.tab_bar.tab_close_requested.connect(self._on_tab_close)
        self.tab_bar.new_tab_requested.connect(lambda: self._open_new_tab("https://duckduckgo.com"))
        v.addWidget(self.tab_bar)

        # Main area = vault banner + pages_stack + AI side panel
        # The banner stacks above the page area (but below the tab bar) so
        # users see it without it hijacking focus.
        main_area = QWidget()
        ma_layout = QHBoxLayout(main_area)
        ma_layout.setContentsMargins(0, 0, 0, 0)
        ma_layout.setSpacing(0)
        page_column = QWidget()
        page_v = QVBoxLayout(page_column)
        page_v.setContentsMargins(0, 0, 0, 0)
        page_v.setSpacing(0)
        self.vault_banner = VaultBanner(parent=page_column)
        self.vault_banner.switch_requested.connect(self._on_banner_switch)
        self.vault_banner.always_requested.connect(self._on_banner_always)
        page_v.addWidget(self.vault_banner)
        self.pages_stack = QStackedWidget()
        page_v.addWidget(self.pages_stack, 1)
        ma_layout.addWidget(page_column, 1)
        self.ai_panel = AIPanel(self.ai_history_mgr)
        self.ai_panel.set_page_provider(self._current_page_info_for_ai)
        ma_layout.addWidget(self.ai_panel)
        v.addWidget(main_area, 1)

        self.dev_tools_container = QWidget()
        self.dev_tools_container.setVisible(False)
        self.dev_tools_container.setMinimumHeight(200)
        QVBoxLayout(self.dev_tools_container).setContentsMargins(0, 0, 0, 0)
        v.addWidget(self.dev_tools_container)

        v.addWidget(self._build_dock())

        self._build_overlays()
        # Theme is applied app-wide via apply_theme() — no per-window stylesheet.
        self._apply_mode()

        # First tab
        self._open_new_tab("https://duckduckgo.com")

        # Apply persisted display settings
        self._apply_display_settings()

        # Hotkeys
        QShortcut(QKeySequence("F12"), self, activated=self._toggle_devtools)
        QShortcut(QKeySequence("Ctrl+L"), self, activated=lambda: self.search.setFocus())
        QShortcut(QKeySequence("Ctrl+R"), self, activated=lambda: self._current_page() and self._current_page().reload())
        QShortcut(QKeySequence("F5"), self, activated=lambda: self._current_page() and self._current_page().reload())
        QShortcut(QKeySequence("Alt+Left"), self, activated=lambda: self._current_page() and self._current_page().back())
        QShortcut(QKeySequence("Alt+Right"), self, activated=lambda: self._current_page() and self._current_page().forward())
        QShortcut(QKeySequence("Ctrl+T"), self, activated=lambda: self._open_new_tab("https://duckduckgo.com"))
        QShortcut(QKeySequence("Ctrl+W"), self, activated=lambda: self._on_tab_close(self.pages_stack.currentIndex()))
        QShortcut(QKeySequence("Ctrl+D"), self, activated=self._toggle_favorite_current)
        QShortcut(QKeySequence("Ctrl+,"), self, activated=self._open_settings)
        QShortcut(QKeySequence("Ctrl+J"), self, activated=self._toggle_ai_panel)
        QShortcut(QKeySequence("Ctrl+P"), self, activated=self._print_current_page)
        # New hotkeys (V3 polish pass)
        QShortcut(QKeySequence("Ctrl+K"), self, activated=self._open_quick_switcher)
        QShortcut(QKeySequence("F9"), self, activated=self._toggle_reader_mode)
        QShortcut(QKeySequence("Ctrl+Shift+N"), self, activated=self._open_code_sandbox_tab)

        # Reader mode overlay (lazily shown). Parented to the page column so
        # it covers content but not the dock / tab bar.
        self.reader_overlay = ReaderModeOverlay(parent=root)
        self.reader_overlay.hide()
        self.reader_overlay.closed.connect(self._close_reader_mode)
        self.reader_overlay.summary_requested.connect(self._summarize_in_ai_panel)

        # Restore AI panel state (persisted across sessions)
        if bool(self.settings_mgr.get("ai_panel_open")):
            QTimer.singleShot(50, self.ai_panel.expand)

        # Background update check (best-effort, non-blocking via QTimer).
        if HAVE_UPDATER:
            QTimer.singleShot(2500, self._check_for_update_async)

    # ── Build helpers ─────────────────────────────────────────
    def _build_dock(self) -> QFrame:
        dock = QFrame()
        dock.setObjectName("dock")
        dock.setFixedHeight(120)
        v = QVBoxLayout(dock)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        # Row 1 — HTTPS / URL
        row1 = QFrame()
        row1.setProperty("class", "dockRow")
        row1.setProperty("first", True)
        h1 = QHBoxLayout(row1)
        h1.setContentsMargins(14, 6, 14, 6)
        self.lock_label = QLabel("🔒")
        self.lock_label.setProperty("class", "lock")
        self.url_display = QLabel("https://duckduckgo.com")
        self.url_display.setObjectName("urlDisplay")
        self.url_display.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        info_btn = QPushButton("ⓘ")
        info_btn.setProperty("class", "dockBtn")
        info_btn.setToolTip("Cert details / JA3 / IP server")
        # Spinner — animates while a page is loading, sits on the right of the URL bar
        self.bottom_spinner = Spinner("spinner")
        gear_btn = QPushButton("⚙")
        gear_btn.setProperty("class", "dockBtn")
        gear_btn.setToolTip("Page settings")
        h1.addWidget(self.lock_label)
        h1.addWidget(self.url_display, 1)
        h1.addWidget(self.bottom_spinner)
        h1.addWidget(info_btn)
        h1.addWidget(gear_btn)
        self.row_https = row1

        # Row 2 — Engine + Search + ★ favorite button
        row2 = QFrame()
        row2.setProperty("class", "dockRow")
        h2 = QHBoxLayout(row2)
        h2.setContentsMargins(14, 6, 14, 6)
        h2.setSpacing(8)
        self.engine = QComboBox()
        self.engine.setObjectName("engineSelect")
        for name, _ in SEARCH_ENGINES:
            self.engine.addItem(name)
        self.search = QLineEdit()
        self.search.setObjectName("searchBar")
        self.search.setPlaceholderText("Recherche, URL, IP, ou >commande   (Ctrl+L)")
        self.search.returnPressed.connect(self._on_search)
        # NEW: star button to add current page to favorites
        self.star_btn = QPushButton("☆")
        self.star_btn.setObjectName("starBtn")
        self.star_btn.setProperty("class", "dockBtn")
        self.star_btn.setToolTip("Ajouter aux favoris (Ctrl+D)")
        self.star_btn.clicked.connect(self._toggle_favorite_current)
        h2.addWidget(self.engine)
        h2.addWidget(self.search, 1)
        h2.addWidget(self.star_btn)
        self.row_search = row2

        # Row 3 — Settings + Favs (dynamic) + F12 + New Tab
        row3 = QFrame()
        row3.setProperty("class", "dockRow")
        h3 = QHBoxLayout(row3)
        h3.setContentsMargins(14, 6, 14, 6)
        h3.setSpacing(6)
        settings_btn = QPushButton("⚙")
        settings_btn.setProperty("class", "dockBtn")
        settings_btn.setToolTip("Settings (Ctrl+,)")
        settings_btn.clicked.connect(self._open_settings)

        self.favs_bar = QFrame()
        self.favs_bar.setObjectName("favsBar")
        self.favs_layout = QHBoxLayout(self.favs_bar)
        self.favs_layout.setContentsMargins(4, 2, 4, 2)
        self.favs_layout.setSpacing(2)
        self.favs_bar.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self._render_favs()

        # Mode toggle button (Normal / Privé / Coffre) — moved from floating top-center to here
        self.mode_btn = QPushButton(f"{MODES[0]['icon']}  {MODES[0]['text']}")
        self.mode_btn.setObjectName("modeBtn")
        self.mode_btn.setProperty("mode", "normal")
        self.mode_btn.setToolTip("Click pour changer mode (Normal / Privé / Coffre)")
        self.mode_btn.clicked.connect(self._cycle_mode)

        # NetGuard backend status button (replaces the F12 button — F12 key still works)
        self.ng_btn = QPushButton("🛡  NetGuard")
        self.ng_btn.setObjectName("ngBtn")
        self.ng_btn.setProperty("status", "down")
        self.ng_btn.setToolTip("Backend NetGuard — click pour lancer / voir état")
        self.ng_btn.clicked.connect(self._toggle_netguard)

        # vinom-snip launcher (✂) — sibling repo at ../vinom-snip/
        self.snip_btn = QPushButton("✂")
        self.snip_btn.setObjectName("ngBtn")  # reuse ngBtn style for visual match
        self.snip_btn.setToolTip("Lancer vinom-snip (capture+annotation)")
        self.snip_btn.clicked.connect(self._launch_vinom_snip)

        # AI side panel toggle (Ctrl+J)
        self.ai_btn = QPushButton("🤖")
        self.ai_btn.setObjectName("aiBtn")
        self.ai_btn.setProperty("open", False)
        self.ai_btn.setToolTip("Panneau IA (Ctrl+J)")
        self.ai_btn.clicked.connect(self._toggle_ai_panel)

        new_tab_btn = QPushButton("+")
        new_tab_btn.setProperty("class", "dockBtn")
        new_tab_btn.setProperty("primary", True)
        new_tab_btn.setToolTip("Nouveau tab (Ctrl+T)")
        new_tab_btn.clicked.connect(lambda: self._open_new_tab("https://duckduckgo.com"))

        h3.addWidget(settings_btn)
        h3.addWidget(self.favs_bar, 1)
        h3.addWidget(self.mode_btn)
        h3.addWidget(self.ng_btn)
        h3.addWidget(self.snip_btn)
        h3.addWidget(self.ai_btn)
        h3.addWidget(new_tab_btn)
        self.row_actions = row3

        v.addWidget(row1); v.addWidget(row2); v.addWidget(row3)
        return dock

    def _render_favs(self):
        # Clear existing
        while self.favs_layout.count():
            it = self.favs_layout.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
        # Add favorites
        for fav in self.favs_mgr.favorites:
            b = QPushButton(fav.get("label", "★"))
            b.setProperty("class", "fav")
            b.setProperty("broken", fav.get("broken", False))
            b.setToolTip(f"{fav.get('title', '')} — {fav['url']}\nRight-click: remove")
            url = fav["url"]
            b.clicked.connect(lambda _, u=url: self._navigate(u))
            b.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            b.customContextMenuRequested.connect(lambda _pos, u=url, btn=b: self._fav_context_menu(u, btn))
            self.favs_layout.addWidget(b)
        self.favs_layout.addStretch(1)

    def _fav_context_menu(self, url: str, btn: QPushButton):
        m = QMenu(self)
        rem = m.addAction("Supprimer ce favori")
        rem.triggered.connect(lambda: (self.favs_mgr.remove(url), self._render_favs(), self._update_star_btn()))
        m.exec(btn.mapToGlobal(btn.rect().bottomLeft()))

    def _build_overlays(self):
        # Periodic NetGuard health check (NetGuard + mode buttons live in dock row 3)
        self.ng_check_timer = QTimer(self)
        self.ng_check_timer.timeout.connect(self._check_netguard_status)
        self.ng_check_timer.start(5000)  # every 5s
        QTimer.singleShot(500, self._check_netguard_status)  # initial check soon after start

    # ── Tab management ────────────────────────────────────────
    def _open_new_tab(self, url: str = "about:blank"):
        # Tabs are bound to the current mode's profile so privé/coffre
        # switching is observable per-tab. Switching mode replaces a tab's
        # view with a fresh one bound to the target profile (see _set_mode).
        profile = self._mode_profile_for(self.current_mode)
        view = self._create_view_for_profile(profile)
        view.setUrl(QUrl(url))
        self.tab_pages.append(view)
        self.tab_profiles.append(profile)
        idx = self.pages_stack.addWidget(view)
        self.tab_bar.add_tab(idx, "Loading…", mode=self.current_mode)
        self._switch_to_tab(len(self.tab_pages) - 1)

    def _create_view_for_profile(self, profile: QWebEngineProfile) -> QWebEngineView:
        """Build a QWebEngineView wired to ``profile`` and our hooks.

        Uses :class:`ArgusWebPage` so console-message form-submit beacons
        and createWindow popup intercepts route back to this owner.
        """
        view = QWebEngineView()
        page = ArgusWebPage(profile, view)
        page.set_owner(self)
        view.setPage(page)
        view.urlChanged.connect(lambda u, v=view: self._on_view_url_changed(v, u))
        view.titleChanged.connect(lambda t, v=view: self._on_view_title_changed(v, t))
        view.loadStarted.connect(lambda v=view: self._on_load_started(v))
        view.loadFinished.connect(lambda _ok, v=view: self._on_load_finished(v))
        return view

    def _on_tab_clicked(self, idx: int):
        if 0 <= idx < len(self.tab_pages):
            self._switch_to_tab(idx)

    def _on_tab_close(self, idx: int):
        if not (0 <= idx < len(self.tab_pages)):
            return
        view = self.tab_pages.pop(idx)
        if 0 <= idx < len(self.tab_profiles):
            self.tab_profiles.pop(idx)
        self.pages_stack.removeWidget(view)
        view.deleteLater()
        self.tab_bar.remove_tab(idx)
        if not self.tab_pages:
            self._open_new_tab("https://duckduckgo.com")
        else:
            new_idx = min(idx, len(self.tab_pages) - 1)
            self._switch_to_tab(new_idx)

    def _switch_to_tab(self, idx: int):
        if not (0 <= idx < len(self.tab_pages)):
            return
        self.pages_stack.setCurrentIndex(idx)
        self.tab_bar.set_active(idx)
        view = self.tab_pages[idx]
        self._sync_url_display(view.url().toString())
        # Sync spinner state (tab still loading?)
        try:
            loading = view.page().isLoading() if hasattr(view.page(), "isLoading") else False
        except Exception:
            loading = False
        self._set_spinning(loading)

    def _current_view(self) -> QWebEngineView | None:
        idx = self.pages_stack.currentIndex()
        if 0 <= idx < len(self.tab_pages):
            return self.tab_pages[idx]
        return None

    def _current_page(self) -> QWebEngineView | None:
        return self._current_view()

    # ── Event handlers ────────────────────────────────────────
    def _on_view_url_changed(self, view: QWebEngineView, url: QUrl):
        url_str = url.toString()
        if view is self._current_view():
            self._sync_url_display(url_str)
            # Surveillance hook: log every navigation in the active tab.
            if HAVE_SURVEILLANCE and url_str and not url_str.startswith("about:"):
                try:
                    surveil_log_event("navigation", {"url": url_str, "mode": self.current_mode})
                except Exception:
                    pass
            # Auto-vault detection on navigation.
            self._maybe_show_vault_banner(url_str)

    def _on_view_title_changed(self, view: QWebEngineView, title: str):
        try:
            idx = self.tab_pages.index(view)
            self.tab_bar.update_tab(idx, title=title or "Loading…")
        except ValueError:
            pass
        if view is self._current_view() and title:
            self.setWindowTitle(f"Argus — {title}")

    def _sync_url_display(self, url_str: str):
        self.url_display.setText(url_str)
        if hasattr(self, "top_url_text"):
            self.top_url_text.setText(url_str)
        if url_str.startswith("https://"):
            self.lock_label.setText("🔒")
            self.lock_label.setProperty("level", "ok")
        elif url_str.startswith("http://"):
            self.lock_label.setText("⚠")
            self.lock_label.setProperty("level", "warn")
        else:
            self.lock_label.setText("·")
            self.lock_label.setProperty("level", "ok")
        self.lock_label.style().unpolish(self.lock_label)
        self.lock_label.style().polish(self.lock_label)
        self._update_star_btn()

    def _on_load_started(self, view):
        if view is self._current_view():
            self._set_spinning(True)

    def _on_load_finished(self, view):
        if view is self._current_view():
            self._set_spinning(False)

    def _set_spinning(self, on: bool):
        if not hasattr(self, "bottom_spinner"):
            return
        if on:
            self.bottom_spinner.start()
            if hasattr(self, "top_spinner"):
                self.top_spinner.start()
        else:
            self.bottom_spinner.stop()
            if hasattr(self, "top_spinner"):
                self.top_spinner.stop()

    def _on_request(self, method: str, url: str):
        kind = "info"
        if url.startswith("https://"):
            kind = "ok"
        elif url.startswith("http://"):
            kind = "warn"
        bad_keywords = ["tracker", "doubleclick", "facebook.com/tr", "google-analytics"]
        if any(k in url for k in bad_keywords):
            kind = "warn"
        self.feed.push(kind, method, url, "—", "")

    def _on_search(self):
        q = self.search.text().strip()
        if not q:
            return
        if q.startswith(("http://", "https://")):
            self._navigate(q)
        elif "." in q and " " not in q and not q.startswith(">"):
            self._navigate("https://" + q)
        else:
            engine_idx = self.engine.currentIndex()
            template = SEARCH_ENGINES[engine_idx][1]
            self._navigate(template.format(q=quote(q)))
        self.search.clear()

    def _navigate(self, url: str):
        view = self._current_view()
        if view:
            view.setUrl(QUrl(url))
        else:
            self._open_new_tab(url)

    # ── Favorites ─────────────────────────────────────────────
    def _toggle_favorite_current(self):
        view = self._current_view()
        if not view:
            return
        url = view.url().toString()
        if not url or url.startswith("about:"):
            return
        if self.favs_mgr.has(url):
            self.favs_mgr.remove(url)
        else:
            self.favs_mgr.add(url, view.title() or url)
        self._render_favs()
        self._update_star_btn()

    def _update_star_btn(self):
        view = self._current_view()
        if not view:
            return
        url = view.url().toString()
        saved = self.favs_mgr.has(url)
        self.star_btn.setText("★" if saved else "☆")
        self.star_btn.setProperty("saved", saved)
        self.star_btn.style().unpolish(self.star_btn)
        self.star_btn.style().polish(self.star_btn)

    # ── DevTools / Mode ───────────────────────────────────────
    def _toggle_devtools(self):
        if not self.dev_tools_container.isVisible():
            view = self._current_view()
            if view is None:
                return
            if self.dev_tools_view is None:
                self.dev_tools_view = QWebEngineView()
                page = QWebEnginePage(self.profile, self.dev_tools_view)
                self.dev_tools_view.setPage(page)
                self.dev_tools_container.layout().addWidget(self.dev_tools_view)
            view.page().setDevToolsPage(self.dev_tools_view.page())
            self.dev_tools_container.setVisible(True)
        else:
            self.dev_tools_container.setVisible(False)

    def _cycle_mode(self):
        # Move forward through normal -> private -> vault -> normal …
        next_idx = (self.mode_idx + 1) % len(MODES)
        target_id = MODES[next_idx]["id"]
        self._set_mode(target_id, source="cycle")

    def _set_mode(self, target_id: str, source: str = "user"):
        """Switch to ``target_id`` (one of normal/private/vault) with full
        confirmation + 2FA gating + profile swap on the active tab.

        ``source`` is recorded in surveillance for auditability.
        """
        old_id = self.current_mode
        if old_id == target_id:
            return

        # ── Confirmation ─────────────────────────────────────
        # Switching INTO vault is a privileged action — confirm + 2FA.
        if target_id == "vault":
            if not self._enter_vault_mode_gate():
                # Aborted (2FA refused, arbiter blocked, etc.). Stay put.
                return
        elif target_id == "private":
            ans = QMessageBox.question(
                self, "Argus — mode Privé",
                "Activer le mode Privé ?\n\n"
                "Le tab actif sera rechargé dans un profil éphémère "
                "(cookies + cache effacés à la fermeture).",
            )
            if ans != QMessageBox.StandardButton.Yes:
                return
        elif target_id == "normal" and old_id in ("private", "vault"):
            # Going back to normal — informational confirm.
            ans = QMessageBox.question(
                self, "Argus — retour mode Normal",
                "Retourner en mode Normal ?\n\n"
                "Le tab actif sera rechargé dans le profil persistant.",
            )
            if ans != QMessageBox.StandardButton.Yes:
                return

        # ── Apply ────────────────────────────────────────────
        self.current_mode = target_id
        try:
            self.mode_idx = next(i for i, m in enumerate(MODES) if m["id"] == target_id)
        except StopIteration:
            self.mode_idx = 0

        # Surveillance audit trail.
        if HAVE_SURVEILLANCE:
            try:
                surveil_log_event("mode_switch", {
                    "from": old_id, "to": target_id, "source": source,
                })
            except Exception:
                pass

        # Recreate the active tab's view bound to the new profile so
        # new requests use the right cookie jar / cache. Keep URL.
        idx = self.pages_stack.currentIndex()
        if 0 <= idx < len(self.tab_pages):
            old_view = self.tab_pages[idx]
            current_url = old_view.url().toString() or "about:blank"
            new_profile = self._mode_profile_for(target_id, current_url=current_url)
            new_view = self._create_view_for_profile(new_profile)
            new_view.setUrl(QUrl(current_url))
            # Swap into the stack at the same index.
            self.pages_stack.removeWidget(old_view)
            self.pages_stack.insertWidget(idx, new_view)
            self.tab_pages[idx] = new_view
            if 0 <= idx < len(self.tab_profiles):
                self.tab_profiles[idx] = new_profile
            else:
                self.tab_profiles.append(new_profile)
            old_view.deleteLater()
            self.pages_stack.setCurrentIndex(idx)
            self.tab_bar.set_active(idx)

        self._apply_mode()
        self._set_live_feed_arbiter_decision(
            "info", f"Mode → {target_id.upper()}", reason=f"source={source}"
        )

    def _apply_mode(self):
        """Apply visual chrome (button + window border + window icon) for current_mode.

        Does NOT recreate tabs — that's done in _set_mode. Safe to call
        from __init__ before any tabs exist.
        """
        m = MODES[self.mode_idx]
        if hasattr(self, "mode_btn"):
            self.mode_btn.setText(f"{m['icon']}  {m['text']}")
            self.mode_btn.setProperty("mode", m["id"])
            self.mode_btn.style().unpolish(self.mode_btn); self.mode_btn.style().polish(self.mode_btn)
        self.root.setProperty("mode", m["id"])
        self.root.style().unpolish(self.root); self.root.style().polish(self.root)
        # Update active tab's mode for the bar
        idx = self.pages_stack.currentIndex()
        if idx >= 0:
            self.tab_bar.update_tab(idx, mode=m["id"])

        # Mode-specific window icon — iris colour tracks active mode
        # (blue Normal / deep-blue Privé / gold Coffre).
        _icon_map = {
            "normal":  "argus_normal.ico",
            "private": "argus_private.ico",
            "vault":   "argus_vault.ico",
        }
        _icon_file = (
            Path(__file__).resolve().parent / "branding" / "argus"
            / _icon_map.get(self.current_mode, "argus_normal.ico")
        )
        if _icon_file.exists():
            self.setWindowIcon(QIcon(str(_icon_file)))

    def _enter_vault_mode_gate(self) -> bool:
        """Privileged-mode gate. Returns True if user passes all checks.

        Sequence:
            1. Show TOTP setup wizard if not already configured.
            2. Run TOTP challenge.
            3. Ask the arbiter to bless the action (advisory).
        """
        if HAVE_2FA:
            try:
                if not two_fa_is_setup():
                    QMessageBox.information(
                        self, "Argus — mode Coffre",
                        "Le mode Coffre nécessite un second facteur (TOTP). "
                        "On va d'abord configurer un nouveau secret.",
                    )
                    try:
                        ok = bool(two_fa_setup_wizard(self))
                    except Exception as e:
                        QMessageBox.critical(self, "Argus — 2FA",
                                             f"Échec configuration 2FA :\n{e}")
                        return False
                    if not ok:
                        return False
                try:
                    challenge_ok = bool(two_fa_challenge(self))
                except Exception as e:
                    QMessageBox.critical(self, "Argus — 2FA",
                                         f"Échec challenge 2FA :\n{e}")
                    return False
                if not challenge_ok:
                    QMessageBox.warning(self, "Argus — 2FA",
                                        "Code TOTP refusé. Mode Coffre annulé.")
                    return False
            except Exception:
                # Defensive: if 2FA is broken, don't silently downgrade
                # security. Refuse to enter vault mode.
                QMessageBox.critical(self, "Argus — 2FA",
                                     "Erreur 2FA imprévue. Mode Coffre annulé.")
                return False
        else:
            # Module missing — surface a degraded warning but allow entry
            # (the brief asks for graceful degradation).
            QMessageBox.warning(
                self, "Argus — 2FA indisponible",
                "Le module argus_2fa est manquant. Le mode Coffre sera "
                "activé sans second facteur.",
            )

        # Arbiter advisory check on vault entry.
        if HAVE_ARBITER:
            try:
                view = self._current_view()
                cur = view.url().toString() if view is not None else ""
                decision = arbiter_decide("vault_mode_entry",
                                           {"current_url": cur},
                                           mode=self.current_mode)
                if decision is not None and getattr(decision, "verdict", "allow") == "block":
                    QMessageBox.critical(
                        self, "Argus — bloqué",
                        f"L'arbitre Argus a bloqué l'entrée Coffre :\n"
                        f"{getattr(decision, 'reason', 'unspecified')}",
                    )
                    return False
            except Exception:
                # Best-effort: arbiter failure shouldn't block legitimate
                # vault entry.
                pass
        return True

    # ── Settings dialog ───────────────────────────────────────
    def _open_settings(self):
        # Dialog inherits the active app-wide theme; no per-widget stylesheet override.
        dlg = SettingsDialog(self.settings_mgr, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._apply_display_settings()
        # Either way, ensure the active theme is the persisted one
        # (covers both Save and Cancel paths).
        apply_theme(self.settings_mgr.get("theme") or DEFAULT_THEME)

    # ── AI panel ──────────────────────────────────────────────
    def _toggle_ai_panel(self):
        if self.ai_panel.is_open:
            self.ai_panel.collapse()
        else:
            self.ai_panel.expand()
        # Reflect state in the dock button + persist preference.
        self.ai_btn.setProperty("open", self.ai_panel.is_open)
        self.ai_btn.style().unpolish(self.ai_btn)
        self.ai_btn.style().polish(self.ai_btn)
        self.settings_mgr.set("ai_panel_open", self.ai_panel.is_open)

    def _current_page_info_for_ai(self) -> tuple[str, "QWebEngineView | None"]:
        """Provide (url, view) for AIPanel context capture."""
        view = self._current_view()
        if view is None:
            return ("", None)
        return (view.url().toString(), view)

    def _apply_display_settings(self):
        s = self.settings_mgr
        if hasattr(self, "feed"):
            self.feed.setVisible(s.get("show_live_feed"))
        if hasattr(self, "top_url_strip"):
            self.top_url_strip.setVisible(s.get("show_url_top"))
        if hasattr(self, "row_https"):
            self.row_https.setVisible(s.get("show_url_bottom"))
        if hasattr(self, "row_search"):
            self.row_search.setVisible(s.get("show_search_row"))
        if hasattr(self, "row_actions"):
            self.row_actions.setVisible(s.get("show_favs"))

    # ── NetGuard backend control ──────────────────────────────
    def _check_netguard_status(self):
        """Ping the NetGuard WS port to know if backend is up."""
        import socket
        status = "down"
        try:
            sock = socket.create_connection(("127.0.0.1", 8765), timeout=0.5)
            sock.close()
            status = "up"
        except (OSError, ConnectionRefusedError):
            status = "down"
        if hasattr(self, "ng_btn"):
            self.ng_btn.setProperty("status", status)
            label = {"up": "🛡  NetGuard ✓", "down": "🛡  NetGuard ✗", "warn": "🛡  NetGuard ⚠"}.get(status, "🛡  NetGuard")
            self.ng_btn.setText(label)
            self.ng_btn.style().unpolish(self.ng_btn)
            self.ng_btn.style().polish(self.ng_btn)

    def _toggle_netguard(self):
        """If NetGuard is down, launch netguard.py + ai_server.py in background."""
        import socket
        import subprocess
        try:
            sock = socket.create_connection(("127.0.0.1", 8765), timeout=0.3)
            sock.close()
            # Already running — just inform user via the live feed
            self.feed.push("info", "NG", "NetGuard backend already running on :8765",
                          "OK", "")
            return
        except OSError:
            pass
        # Not running — launch
        try:
            subprocess.Popen(
                [sys.executable, str(ROOT / "netguard.py")],
                cwd=str(ROOT), creationflags=getattr(subprocess, "DETACHED_PROCESS", 0),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            self.feed.push("info", "NG", "Lancement NetGuard backend…", "STARTING", "")
            QTimer.singleShot(2000, self._check_netguard_status)
        except Exception as e:
            self.feed.push("bad", "NG", f"Échec lancement NetGuard: {e}", "FAIL", "")

    # ── Profile builders / mode profile cache ─────────────────
    def _configure_basic_profile(self, profile: QWebEngineProfile,
                                 storage: str, cache: str,
                                 cookie_policy: QWebEngineProfile.PersistentCookiesPolicy =
                                 QWebEngineProfile.PersistentCookiesPolicy.AllowPersistentCookies):
        """Plain configuration used when argus_sandbox is unavailable."""
        Path(storage).mkdir(parents=True, exist_ok=True)
        Path(cache).mkdir(parents=True, exist_ok=True)
        profile.setPersistentStoragePath(storage)
        profile.setCachePath(cache)
        profile.setPersistentCookiesPolicy(cookie_policy)
        s = profile.settings()
        s.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        s.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)

    def _install_profile_scripts(self, profile: QWebEngineProfile):
        """Inject form-submit interceptor + (optionally) anti-skimmer JS
        into ``profile``. Idempotent — re-installing replaces by name."""
        # Form-submit interceptor — always installed.
        try:
            scripts = profile.scripts()
            existing = scripts.findScript("argus_form_intercept")
            if not existing.isNull():
                scripts.remove(existing)
            s = QWebEngineScript()
            s.setName("argus_form_intercept")
            s.setSourceCode(FORM_SUBMIT_INTERCEPT_JS)
            s.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentReady)
            s.setRunsOnSubFrames(True)
            s.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
            scripts.insert(s)
        except Exception:
            pass
        # Anti-skimmer hardening from sandbox module (best-effort).
        if HAVE_SANDBOX and install_anti_skimmer_script is not None:
            try:
                install_anti_skimmer_script(profile)
            except Exception:
                pass

    def _wire_profile_downloads(self, profile: QWebEngineProfile):
        """Connect the profile's downloadRequested signal exactly once.

        Keeps a per-profile attribute ``_argus_dl_wired`` so we don't double-
        connect when the same profile is re-handed to multiple tabs.
        """
        if getattr(profile, "_argus_dl_wired", False):
            return
        try:
            profile.downloadRequested.connect(self._on_download_requested)
            try:
                setattr(profile, "_argus_dl_wired", True)
            except Exception:
                pass
        except Exception:
            pass

    def _mode_profile_for(self, mode_id: str,
                          current_url: str = "") -> QWebEngineProfile:
        """Resolve (and lazily build) the profile for a given mode.

        Vault profiles are scoped to the institution domain when possible
        so cookies don't leak between banks; private profiles are off-the-
        record (in-memory only).
        """
        # Normal is the persistent profile created in __init__.
        if mode_id == "normal":
            return self._mode_profiles["normal"]

        # Private — one shared off-the-record profile is enough.
        if mode_id == "private":
            cached = self._mode_profiles.get("private")
            if cached is not None:
                return cached
            if HAVE_SANDBOX and make_private_profile is not None:
                try:
                    p = make_private_profile()
                    p.setParent(self)
                except Exception:
                    p = QWebEngineProfile(self)  # off-the-record (no name)
            else:
                p = QWebEngineProfile(self)  # off-the-record (no storage)
            self._install_profile_scripts(p)
            self._wire_profile_downloads(p)
            self._mode_profiles["private"] = p
            return p

        # Vault — try to scope to the institution if we can detect one.
        if mode_id == "vault":
            allowed = self._domain_for_vault(current_url)
            cache_key = f"vault::{allowed or '*'}"
            cached = self._mode_profiles.get(cache_key)
            if cached is not None:
                return cached
            if HAVE_SANDBOX and make_vault_profile is not None:
                try:
                    if allowed:
                        try:
                            p = make_vault_profile(allowed_domain=allowed)
                        except TypeError:
                            # Older sandbox signature without allowed_domain.
                            p = make_vault_profile()
                    else:
                        p = make_vault_profile()
                    p.setParent(self)
                except Exception:
                    p = QWebEngineProfile(self)
            else:
                # No sandbox — fall back to a fresh off-the-record profile so
                # the user at least gets isolation from "normal" cookies.
                p = QWebEngineProfile(self)
            self._install_profile_scripts(p)
            self._wire_profile_downloads(p)
            self._mode_profiles[cache_key] = p
            return p

        # Unknown mode — return normal as a safe default.
        return self._mode_profiles["normal"]

    @staticmethod
    def _domain_for_vault(url: str) -> str:
        try:
            host = urlparse(url).netloc.lower()
            if host.startswith("www."):
                host = host[4:]
            # Take the eTLD+1 if obvious (banking domains rarely have
            # multi-level public suffixes — keep it simple for V1).
            return host or ""
        except Exception:
            return ""

    # ── Vault auto-switch banner ──────────────────────────────
    def _load_vault_always(self) -> set[str]:
        if not VAULT_AUTO_SWITCH_FILE.exists():
            return set()
        try:
            data = json.loads(VAULT_AUTO_SWITCH_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return set()
        if not isinstance(data, dict):
            return set()
        hosts = data.get("hosts")
        if isinstance(hosts, list):
            return {str(h).lower() for h in hosts if isinstance(h, str)}
        return set()

    def _save_vault_always(self):
        try:
            VAULT_AUTO_SWITCH_FILE.parent.mkdir(parents=True, exist_ok=True)
            VAULT_AUTO_SWITCH_FILE.write_text(
                json.dumps({"hosts": sorted(self._vault_always_hosts)},
                           indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError:
            pass

    def _maybe_show_vault_banner(self, url_str: str):
        if not url_str or self.current_mode == "vault":
            self.vault_banner.hide()
            return
        if not HAVE_VAULT_DOMAINS:
            return
        try:
            match = is_vault_domain(url_str)
        except Exception:
            match = None
        if match is None:
            self._banner_shown_host = ""
            self.vault_banner.hide()
            return
        host = self._domain_for_vault(url_str)
        # Auto-switch path (user previously clicked "Always" for this host).
        if host and host in self._vault_always_hosts:
            # Only auto-trigger once per host per nav.
            if self._banner_shown_host != host:
                self._banner_shown_host = host
                # Defer one tick so the URL change finishes settling first.
                QTimer.singleShot(0, lambda: self._set_mode("vault", source="auto"))
            return
        # Otherwise show the banner.
        if self._banner_shown_host == host:
            return
        self._banner_shown_host = host
        institution = getattr(match, "institution_name",
                              getattr(match, "name", str(match)))
        self.vault_banner.show_for(institution, host)

    def _on_banner_switch(self, _institution: str):
        self._set_mode("vault", source="banner")

    def _on_banner_always(self, host: str):
        if not host:
            return
        self._vault_always_hosts.add(host.lower())
        self._save_vault_always()
        if HAVE_SURVEILLANCE:
            try:
                surveil_log_event("vault_always_added", {"host": host.lower()})
            except Exception:
                pass
        self._set_mode("vault", source="banner-always")

    # ── Download sandbox ──────────────────────────────────────
    def _on_download_requested(self, dl_request):
        """Per-profile downloadRequested handler.

        Routes the heuristic+arbiter decision through ``arbiter_decide_async``
        and updates UI on the GUI thread by funnelling the callback through
        QTimer.singleShot.
        """
        try:
            # Filename / origin metadata for the heuristic.
            try:
                url = dl_request.url().toString()
            except Exception:
                url = ""
            try:
                filename = dl_request.downloadFileName() or ""
            except Exception:
                filename = ""
            try:
                origin_url = dl_request.page().url().toString()
            except Exception:
                origin_url = ""
            ext = ""
            if filename and "." in filename:
                ext = "." + filename.rsplit(".", 1)[-1].lower()

            ctx = {
                "url": url, "filename": filename, "ext": ext,
                "origin_url": origin_url, "mode": self.current_mode,
            }
        except Exception:
            return

        # Always log the download attempt to surveillance.
        if HAVE_SURVEILLANCE:
            try:
                surveil_log_event("download", ctx)
            except Exception:
                pass

        # If arbiter is unavailable, default-allow with a note in the feed.
        if not HAVE_ARBITER:
            self._handle_dl_decision_main(None, dl_request, ctx)
            return

        # Hand off to arbiter on a background thread.
        def _cb(decision):
            # Marshall to GUI thread.
            QTimer.singleShot(0, lambda d=decision: self._handle_dl_decision_main(d, dl_request, ctx))
        try:
            arbiter_decide_async("download", ctx, _cb, mode=self.current_mode)
        except Exception:
            self._handle_dl_decision_main(None, dl_request, ctx)

    def _handle_dl_decision_main(self, decision, dl_request, ctx: dict):
        verdict = "allow"
        reason = "no arbiter"
        if decision is not None:
            verdict = getattr(decision, "verdict", "allow") or "allow"
            reason = getattr(decision, "reason", "") or ""

        filename = ctx.get("filename") or "download.bin"
        sandbox_path = self._sandbox_target_path(filename)

        if verdict == "allow":
            # Save into the sandbox folder by default — never user's Downloads.
            try:
                dl_request.setDownloadDirectory(str(DOWNLOADS_SANDBOX_DIR))
                # PyQt6 also exposes setDownloadFileName on QWebEngineDownloadRequest.
                try:
                    dl_request.setDownloadFileName(sandbox_path.name)
                except Exception:
                    pass
                dl_request.accept()
            except Exception as e:
                self._set_live_feed_arbiter_decision(
                    "bad", f"Download failed: {e}", reason="dl-accept-failed",
                )
                return
            self._set_live_feed_arbiter_decision(
                "ok", f"Allowed: download {filename}", reason=reason or "ok",
            )
            return

        if verdict == "warn":
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Warning)
            box.setWindowTitle("Argus — téléchargement risqué")
            box.setText(
                f"Argus signale un risque pour le téléchargement :\n\n"
                f"  • Fichier : {filename}\n"
                f"  • Source  : {ctx.get('origin_url', '')}\n\n"
                f"Raison : {reason}"
            )
            cont = box.addButton("Continuer (sandbox)", QMessageBox.ButtonRole.AcceptRole)
            cancel = box.addButton("Annuler", QMessageBox.ButtonRole.RejectRole)
            box.setDefaultButton(cancel)
            box.exec()
            if box.clickedButton() is cont:
                try:
                    dl_request.setDownloadDirectory(str(DOWNLOADS_SANDBOX_DIR))
                    try:
                        dl_request.setDownloadFileName(sandbox_path.name)
                    except Exception:
                        pass
                    dl_request.accept()
                except Exception:
                    return
                self._set_live_feed_arbiter_decision(
                    "warn", f"User-overrode warn: {filename}", reason=reason,
                )
            else:
                try:
                    dl_request.cancel()
                except Exception:
                    pass
                self._set_live_feed_arbiter_decision(
                    "warn", f"Cancelled (warn): {filename}", reason=reason,
                )
            return

        # block
        try:
            dl_request.cancel()
        except Exception:
            pass
        QMessageBox.critical(
            self, "Argus — téléchargement bloqué",
            f"Argus a bloqué le téléchargement :\n\n"
            f"  • Fichier : {filename}\n\n"
            f"Raison : {reason}",
        )
        self._set_live_feed_arbiter_decision(
            "bad", f"Blocked: download {filename}", reason=reason,
        )

    @staticmethod
    def _sandbox_target_path(filename: str) -> Path:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe = "".join(c for c in filename if c.isalnum() or c in ("-", "_", ".")) or "download.bin"
        return DOWNLOADS_SANDBOX_DIR / f"{ts}_{safe}"

    # ── Print (Ctrl+P) ────────────────────────────────────────
    def _print_current_page(self):
        view = self._current_view()
        if view is None:
            return
        printer = QPrinter()
        dlg = QPrintDialog(printer, self)
        dlg.setWindowTitle("Argus — Imprimer")
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        page = view.page()
        try:
            page.print(printer, lambda success: None)
        except Exception as e:
            QMessageBox.warning(
                self, "Argus — impression",
                f"Échec de l'impression :\n{e}",
            )

    # ── Form-submit JS bridge → Python ────────────────────────
    def _on_form_submit_beacon(self, payload: str):
        """Receive the JSON payload from FORM_SUBMIT_INTERCEPT_JS.

        V1 scope: surveillance logging + arbiter advisory check (the
        decision does NOT prevent the submit — JS already let the form
        proceed by the time the console log fires). Future: replace the
        passive console-log bridge with a synchronous QWebChannel that
        can pause the submit pending arbiter verdict.
        """
        try:
            data = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            return
        if not isinstance(data, dict):
            return
        ctx = {
            "action_url":   data.get("action_url", ""),
            "method":       data.get("method", ""),
            "fields_count": int(data.get("fields_count") or 0),
            "has_password": bool(data.get("has_password")),
            "has_cc":       bool(data.get("has_cc")),
            "origin":       data.get("origin", ""),
            "mode":         self.current_mode,
        }
        if HAVE_SURVEILLANCE:
            try:
                surveil_log_event("form_submit", ctx)
            except Exception:
                pass
        # Advisory arbiter call — purely for the live feed.
        if HAVE_ARBITER:
            def _cb(decision):
                if decision is None:
                    return
                verdict = getattr(decision, "verdict", "allow") or "allow"
                reason = getattr(decision, "reason", "") or ""
                kind = {"allow": "ok", "warn": "warn", "block": "bad"}.get(verdict, "info")
                action = ctx.get("action_url", "")
                short = action[:60] + "…" if len(action) > 60 else action
                QTimer.singleShot(0, lambda: self._set_live_feed_arbiter_decision(
                    kind, f"form_submit → {short}", reason=f"{verdict}: {reason}",
                ))
            try:
                arbiter_decide_async("form_submit", ctx, _cb, mode=self.current_mode)
            except Exception:
                pass

    # ── Live feed surveillance widget extension ──────────────
    def _set_live_feed_arbiter_decision(self, kind: str, label: str,
                                        reason: str = ""):
        """Surface arbiter / surveillance highlights in the live feed.

        ``kind`` ∈ {ok, warn, bad, info}. The existing LiveFeed.push API
        is reused so the visual style stays consistent with HTTP rows.
        """
        if not hasattr(self, "feed"):
            return
        icon = {"ok": "✓", "warn": "⚠", "bad": "✗", "info": "ⓘ"}.get(kind, "·")
        # Method column reused as a category tag for arbiter rows.
        category = "GUARD"
        line = f"{icon} {label}"
        try:
            self.feed.push(kind, category, line, reason or "—", "")
        except Exception:
            pass

    # ── Overlay positioning ───────────────────────────────────
    # ── Menu bar ──────────────────────────────────────────────
    def _build_menu_bar(self):
        try:
            mb = self.menuBar()
            mb.clear()
            file_menu = mb.addMenu("&Fichier")
            act_new_tab = file_menu.addAction("Nouveau tab\tCtrl+T")
            act_new_tab.triggered.connect(
                lambda: self._open_new_tab("https://duckduckgo.com")
            )
            act_new_sandbox = file_menu.addAction("Nouveau Code Sandbox\tCtrl+Shift+N")
            act_new_sandbox.triggered.connect(self._open_code_sandbox_tab)
            file_menu.addSeparator()
            act_settings = file_menu.addAction("Paramètres…\tCtrl+,")
            act_settings.triggered.connect(self._open_settings)
            file_menu.addSeparator()
            act_quit = file_menu.addAction("Quitter")
            act_quit.triggered.connect(self.close)

            view_menu = mb.addMenu("&Affichage")
            act_quick = view_menu.addAction("Quick Switcher…\tCtrl+K")
            act_quick.triggered.connect(self._open_quick_switcher)
            act_reader = view_menu.addAction("Mode Lecture\tF9")
            act_reader.triggered.connect(self._toggle_reader_mode)
            act_ai = view_menu.addAction("Panneau IA\tCtrl+J")
            act_ai.triggered.connect(self._toggle_ai_panel)

            tools_menu = mb.addMenu("&Outils")
            act_snip = tools_menu.addAction("Lancer vinom-snip")
            act_snip.triggered.connect(self._launch_vinom_snip)
            act_sandbox_tab = tools_menu.addAction("Code Sandbox (nouveau tab)")
            act_sandbox_tab.triggered.connect(self._open_code_sandbox_tab)

            help_menu = mb.addMenu("&Aide")
            act_about = help_menu.addAction("À propos d'Argus")
            act_about.triggered.connect(self._open_about)
        except Exception:
            # Menu bar is decorative — never crash startup over it.
            pass

    # ── About / version banner ────────────────────────────────
    def _open_about(self):
        try:
            dlg = AboutDialog(self)
            dlg.exec()
        except Exception as e:
            QMessageBox.information(self, "Argus", f"v{ARGUS_VERSION}\n\n{e}")

    def _check_for_update_async(self):
        """Best-effort update check; updates the version badge if newer is found."""
        if not HAVE_UPDATER:
            return

        def _worker():
            try:
                info = _argus_check_for_update(current=ARGUS_VERSION)
            except Exception:
                info = None

            def _apply():
                if info and isinstance(info, dict) and info.get("update_available"):
                    try:
                        self.feed.set_update_available(True, info)
                    except Exception:
                        pass

            try:
                QTimer.singleShot(0, _apply)
            except Exception:
                pass

        threading.Thread(target=_worker, daemon=True).start()

    # ── vinom-snip launcher ───────────────────────────────────
    def _launch_vinom_snip(self):
        """Try a few entrypoints in ../vinom-snip/. Show a toast in the live
        feed on success or failure. Logs to surveillance."""
        snip_root = ROOT.parent / "vinom-snip"
        candidates: list[list[str]] = []
        # Pre-built C# .exe (real product wins) takes precedence if present.
        for exe_rel in (
            "src/VinomSnip.App/bin/Release/net8.0-windows10.0.19041.0/win-x64/VinomSnip.exe",
            "src/VinomSnip.App/bin/Debug/net8.0-windows10.0.19041.0/win-x64/VinomSnip.exe",
            "VinomSnip.exe",
            "src/VinomSnip.App/bin/Release/VinomSnip.exe",
            "src/VinomSnip.App/bin/Debug/VinomSnip.exe",
        ):
            full = snip_root / exe_rel
            if full.exists():
                candidates.append([str(full)])
        # Python entry points (kept for Python-port future-proofing).
        for py_rel in ("__main__.py", "main.py", "vinom_snip.py", "src/main.py"):
            full = snip_root / py_rel
            if full.exists():
                candidates.append([sys.executable, str(full)])
        # `dotnet run` against the csproj as last resort.
        csproj = snip_root / "src" / "VinomSnip.App" / "VinomSnip.App.csproj"
        if csproj.exists():
            candidates.append(["dotnet", "run", "--project", str(csproj)])

        if not candidates:
            self.feed.push("warn", "snip",
                           "vinom-snip not installed at ../vinom-snip/",
                           "404", "")
            return

        cmd = candidates[0]
        try:
            subprocess.Popen(
                cmd,
                cwd=str(snip_root),
                creationflags=getattr(subprocess, "DETACHED_PROCESS", 0),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            self.feed.push("info", "snip",
                           f"Lancé : {Path(cmd[0]).name}", "OK", "")
            try:
                surveil_log_event("user_action", {"type": "snip_launched",
                                                  "cmd": cmd[0]})
            except Exception:
                pass
        except Exception as e:
            self.feed.push("bad", "snip", f"Échec lancement: {e}", "FAIL", "")

    # ── Quick switcher (Ctrl+K) ───────────────────────────────
    def _open_quick_switcher(self):
        try:
            dlg = QuickSwitcherDialog(
                sources_provider=self._collect_quick_switcher_items,
                on_activate=self._activate_quick_switcher_item,
                parent=self,
            )
            dlg.exec()
        except Exception as e:
            self.feed.push("bad", "qs", f"Quick switcher error: {e}", "ERR", "")

    def _collect_quick_switcher_items(self) -> list[dict]:
        items: list[dict] = []
        # Open tabs
        try:
            for i, view in enumerate(self.tab_pages):
                title = view.title() or view.url().toString() or f"Tab {i+1}"
                items.append({
                    "kind": "tab",
                    "icon": "📑",
                    "label": f"Tab — {title}",
                    "tab_index": i,
                })
        except Exception:
            pass
        # Bookmarks
        try:
            for fav in self.favs_mgr.favorites:
                title = fav.get("title") or fav.get("url", "")
                items.append({
                    "kind": "bookmark",
                    "icon": "★",
                    "label": f"Bookmark — {title}",
                    "url": fav.get("url", ""),
                })
        except Exception:
            pass
        # History (last 50)
        if HAVE_SURVEILLANCE:
            try:
                events = surveil_query(event_types=["navigation"], limit=50) or []
                seen = set()
                for ev in reversed(events):  # newest first
                    payload = ev.get("payload", {}) if isinstance(ev, dict) else {}
                    url = payload.get("url") or ev.get("url") or ""
                    if not url or url in seen:
                        continue
                    seen.add(url)
                    items.append({
                        "kind": "history",
                        "icon": "🕓",
                        "label": f"History — {url}",
                        "url": url,
                    })
                    if len(seen) >= 50:
                        break
            except Exception:
                pass
        # Commands
        commands = [
            ("Nouveau tab",          "cmd_new_tab"),
            ("Toggle AI Panel",      "cmd_toggle_ai"),
            ("Ouvrir Settings",      "cmd_settings"),
            ("Cycle Mode",           "cmd_cycle_mode"),
            ("Lancer vinom-snip",    "cmd_snip"),
            ("Code Sandbox",         "cmd_sandbox"),
            ("Mode Lecture",         "cmd_reader"),
            ("À propos d'Argus",     "cmd_about"),
            ("Toggle DevTools (F12)","cmd_devtools"),
            ("Toggle NetGuard",      "cmd_ng"),
        ]
        for label, cmd_id in commands:
            items.append({
                "kind": "command",
                "icon": "⚡",
                "label": f"Cmd — {label}",
                "cmd": cmd_id,
            })
        return items

    def _activate_quick_switcher_item(self, item: dict):
        if not isinstance(item, dict):
            return
        kind = item.get("kind")
        if kind == "tab":
            idx = item.get("tab_index")
            if isinstance(idx, int) and 0 <= idx < len(self.tab_pages):
                self._switch_to_tab(idx)
        elif kind in ("bookmark", "history"):
            url = item.get("url")
            if url:
                self._open_new_tab(url)
        elif kind == "command":
            cmd = item.get("cmd")
            if cmd == "cmd_new_tab":
                self._open_new_tab("https://duckduckgo.com")
            elif cmd == "cmd_toggle_ai":
                self._toggle_ai_panel()
            elif cmd == "cmd_settings":
                self._open_settings()
            elif cmd == "cmd_cycle_mode":
                self._cycle_mode()
            elif cmd == "cmd_snip":
                self._launch_vinom_snip()
            elif cmd == "cmd_sandbox":
                self._open_code_sandbox_tab()
            elif cmd == "cmd_reader":
                self._toggle_reader_mode()
            elif cmd == "cmd_about":
                self._open_about()
            elif cmd == "cmd_devtools":
                self._toggle_devtools()
            elif cmd == "cmd_ng":
                self._toggle_netguard()

    # ── Code sandbox tab ─────────────────────────────────────
    def _open_code_sandbox_tab(self):
        """Open a new tab pointing at branding/argus/monaco_sandbox.html.

        Falls back to a QPlainTextEdit-based JS-only sandbox if the HTML is
        missing or QWebEngine cannot resolve the file URL.
        """
        html_path = ROOT / "branding" / "argus" / "monaco_sandbox.html"
        if html_path.exists():
            try:
                file_url = QUrl.fromLocalFile(str(html_path)).toString()
                self._open_new_tab(file_url)
                self.feed.push("info", "sandbox",
                               "Code Sandbox loaded (Monaco)", "OK", "")
                return
            except Exception:
                pass
        # Fallback — embed CodeSandboxFallback in a new QWidget tab.
        # We don't fully integrate this widget into the QStackedWidget tab
        # system (that would need refactor) — instead show as modal-less
        # secondary window so the feature still works on V1.
        try:
            wnd = QMainWindow(self)
            wnd.setWindowTitle("Argus — Code Sandbox (fallback)")
            wnd.resize(900, 640)
            wnd.setCentralWidget(CodeSandboxFallback())
            wnd.show()
            self.feed.push("warn", "sandbox",
                           "Monaco HTML missing — fallback editor shown",
                           "WARN", "")
        except Exception as e:
            self.feed.push("bad", "sandbox", f"Sandbox failed: {e}", "ERR", "")

    # ── Reader mode (F9) ─────────────────────────────────────
    def _toggle_reader_mode(self):
        if self.reader_overlay.isVisible():
            self._close_reader_mode()
            return
        view = self._current_view()
        if view is None:
            return
        # Inject a JS extractor — falls back to body innerText if no <article>.
        js = (
            "(function(){var n=document.querySelector('article')||"
            "document.querySelector('main')||document.body;"
            "var t=(document.title||'')+'';var c=(n?n.innerText:'')+'';"
            "return JSON.stringify({title:t,text:c});})()"
        )
        try:
            view.page().runJavaScript(js, self._on_reader_extracted)
        except Exception:
            self._on_reader_extracted("")

    def _on_reader_extracted(self, payload):
        title = ""
        text = ""
        try:
            if isinstance(payload, str) and payload:
                data = json.loads(payload)
                title = (data.get("title") or "").strip()
                text = (data.get("text") or "").strip()
        except Exception:
            pass
        if not text:
            view = self._current_view()
            text = "(Aucun contenu extrait pour cette page.)"
            if view is not None:
                title = title or view.title() or view.url().toString()
        # Position overlay over the page column area.
        try:
            self.reader_overlay.setGeometry(self.root.rect())
        except Exception:
            pass
        self.reader_overlay.show_content(title, text)
        try:
            surveil_log_event("user_action", {"type": "reader_mode_open",
                                              "title": title})
        except Exception:
            pass

    def _close_reader_mode(self):
        self.reader_overlay.hide()

    def _summarize_in_ai_panel(self, text: str):
        """Pre-fill the AI panel with a summary request and send."""
        try:
            if not self.ai_panel.is_open:
                self._toggle_ai_panel()
            # Prefill the input + click send programmatically.
            preset = (
                "Résume cet article en 5-7 points clés :\n\n"
                + (text or "")[:6000]
            )
            self.ai_panel.input.setPlainText(preset)
            QTimer.singleShot(80, self.ai_panel._send_clicked)
        except Exception as e:
            self.feed.push("bad", "ai", f"Summary failed: {e}", "ERR", "")

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._reposition_overlays()
        # Keep the reader overlay covering the root area.
        try:
            if hasattr(self, "reader_overlay") and self.reader_overlay.isVisible():
                self.reader_overlay.setGeometry(self.root.rect())
        except Exception:
            pass

    def _reposition_overlays(self):
        # Mode + NetGuard buttons now live in the dock — no floating overlays to position.
        pass


def main():
    # Windows: unique AppUserModelID so the taskbar groups Argus correctly
    # and shows the .ico instead of falling back to the python.exe icon.
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "Argus.Cybersec.Workbench.1"
            )
        except Exception:
            pass

    app = QApplication(sys.argv)
    app.setApplicationName("Argus")
    app.setApplicationDisplayName("Argus — Cybersecurity Workbench")
    app.setOrganizationName("NetGuard")
    app.setStyle("Fusion")

    # App-wide icon (taskbar / Alt-Tab / window title bar). Picked up by every
    # window unless overridden. Mode-specific icon is set per-window in
    # ArgusBrowser._apply_mode so it tracks the active mode live.
    _argus_root = Path(__file__).resolve().parent
    _argus_default_ico = _argus_root / "branding" / "argus" / "argus_normal.ico"
    if _argus_default_ico.exists():
        app.setWindowIcon(QIcon(str(_argus_default_ico)))

    # Apply persisted theme as early as possible (before window construction)
    # so any splash / dialog inherits the right palette from frame 1.
    try:
        prelim = SettingsManager(SETTINGS_FILE)
        apply_theme(prelim.get("theme") or DEFAULT_THEME)
    except Exception:
        apply_theme(DEFAULT_THEME)

    # ── Splash screen — show 1.5s while heavy modules import ──
    splash = None
    try:
        splash_path = _argus_root / "branding" / "argus" / "argus_splash.png"
        if splash_path.exists():
            pix = QPixmap(str(splash_path))
            if not pix.isNull():
                # Scale down if image is huge — keep splash readable on 1080p.
                if pix.width() > 720 or pix.height() > 480:
                    pix = pix.scaled(720, 480,
                                     Qt.AspectRatioMode.KeepAspectRatio,
                                     Qt.TransformationMode.SmoothTransformation)
                splash = QSplashScreen(pix, Qt.WindowType.WindowStaysOnTopHint)
                splash.showMessage(
                    f"Argus v{ARGUS_VERSION}",
                    Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignHCenter,
                    Qt.GlobalColor.white,
                )
                splash.show()
                app.processEvents()
    except Exception:
        splash = None

    win = ArgusBrowser()
    win.show()

    # Splash stays on top for ~1.5s, then closes. If splash failed to load
    # we just continue with no-op.
    if splash is not None:
        QTimer.singleShot(1500, lambda: splash.finish(win))

    # First-run onboarding — the dialog is responsible for calling
    # mark_first_run_complete() when the user clicks Get Started.
    if HAVE_ONBOARDING:
        try:
            if is_first_run():
                # Show shortly after the main window paints so the dialog
                # has somewhere to anchor + the user sees Argus' chrome.
                QTimer.singleShot(150, lambda: show_first_run_dialog(parent=win))
        except Exception:
            pass

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
