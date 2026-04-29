"""
Argus 2.0 — Real PyQt6 + QtWebEngine cybersecurity browser.

Layout:
  Top   : transparent live network feed (2 lines, color-coded, animated)
  Tabs  : bookmark-style strip just under feed (multi-tab, click to switch, × to close)
  Mid   : QStackedWidget with one QWebEngineView per tab (real Chromium, sandboxed)
  Bot   : 3-row dock — HTTPS / Engine+Search+Star / Settings+Favs+F12+NewTab
  Float : mode badge top-center (Normal / Privé / Coffre)
  F12   : Chromium DevTools panel slide-up, resizable

Persistence:
  Sessions (cookies, localStorage) survive restarts via persistent profile path
  → log into Google/Microsoft once, stays signed in next launch.
  Favorites stored in argus_data/favorites.json.

Run:  python argus_pyqt.py   (or LANCER_ARGUS_2.bat)
"""
import json
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from PyQt6.QtCore import Qt, QUrl, QSize, pyqtSignal, QObject, QTimer
from PyQt6.QtGui import QShortcut, QKeySequence, QIcon, QPixmap
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QComboBox, QPushButton, QLabel, QStackedWidget, QFrame,
    QSizePolicy, QScrollArea, QMenu,
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import (
    QWebEnginePage, QWebEngineProfile, QWebEngineUrlRequestInterceptor,
    QWebEngineSettings,
)

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "argus_data"
CACHE_DIR = ROOT / "argus_cache"
FAVS_FILE = DATA_DIR / "favorites.json"

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
"""


# ── Persistence ──────────────────────────────────────────────────────────
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
    def __init__(self):
        super().__init__()
        self.setObjectName("liveFeed")
        self.setFixedHeight(46)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 4, 14, 4)
        layout.setSpacing(2)
        self.layout_box = layout
        self.rows: list[QLabel] = []

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


# ── Main window ──────────────────────────────────────────────────────────
class ArgusBrowser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Argus 2.0 — NetGuard Cybersecurity Browser")
        self.resize(1400, 900)

        self.mode_idx = 0
        self.dev_tools_view = None
        self.dev_tools_container = None
        self.tab_pages: list[QWebEngineView] = []
        self.favs_mgr = FavoritesManager(FAVS_FILE)

        # ── Profile (persistent — sessions survive restart) ──
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self.profile = QWebEngineProfile("argus-default", self)
        self.profile.setPersistentStoragePath(str(DATA_DIR / "normal"))
        self.profile.setCachePath(str(CACHE_DIR / "normal"))
        self.profile.setPersistentCookiesPolicy(
            QWebEngineProfile.PersistentCookiesPolicy.AllowPersistentCookies
        )
        self.profile.settings().setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        self.profile.settings().setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)
        self.feed_signal = FeedSignal()
        self.feed_signal.new_request.connect(self._on_request)
        self.interceptor = RequestInterceptor(self.feed_signal)
        self.profile.setUrlRequestInterceptor(self.interceptor)

        # ── Layout ──
        root = QWidget()
        root.setObjectName("root")
        self.root = root
        self.setCentralWidget(root)
        v = QVBoxLayout(root)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        self.feed = LiveFeed()
        v.addWidget(self.feed)

        self.tab_bar = TabBar()
        self.tab_bar.tab_clicked.connect(self._on_tab_clicked)
        self.tab_bar.tab_close_requested.connect(self._on_tab_close)
        self.tab_bar.new_tab_requested.connect(lambda: self._open_new_tab("https://duckduckgo.com"))
        v.addWidget(self.tab_bar)

        self.pages_stack = QStackedWidget()
        v.addWidget(self.pages_stack, 1)

        self.dev_tools_container = QWidget()
        self.dev_tools_container.setVisible(False)
        self.dev_tools_container.setMinimumHeight(200)
        QVBoxLayout(self.dev_tools_container).setContentsMargins(0, 0, 0, 0)
        v.addWidget(self.dev_tools_container)

        v.addWidget(self._build_dock())

        self._build_overlays()
        self.setStyleSheet(THEME_QSS)
        self._apply_mode()

        # First tab
        self._open_new_tab("https://duckduckgo.com")

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
        gear_btn = QPushButton("⚙")
        gear_btn.setProperty("class", "dockBtn")
        gear_btn.setToolTip("Page settings")
        h1.addWidget(self.lock_label)
        h1.addWidget(self.url_display, 1)
        h1.addWidget(info_btn)
        h1.addWidget(gear_btn)

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

        # Row 3 — Settings + Favs (dynamic) + F12 + New Tab
        row3 = QFrame()
        row3.setProperty("class", "dockRow")
        h3 = QHBoxLayout(row3)
        h3.setContentsMargins(14, 6, 14, 6)
        h3.setSpacing(6)
        settings_btn = QPushButton("⚙")
        settings_btn.setProperty("class", "dockBtn")
        settings_btn.setToolTip("Settings (Ctrl+,)")

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

        new_tab_btn = QPushButton("+")
        new_tab_btn.setProperty("class", "dockBtn")
        new_tab_btn.setProperty("primary", True)
        new_tab_btn.setToolTip("Nouveau tab (Ctrl+T)")
        new_tab_btn.clicked.connect(lambda: self._open_new_tab("https://duckduckgo.com"))

        h3.addWidget(settings_btn)
        h3.addWidget(self.favs_bar, 1)
        h3.addWidget(self.mode_btn)
        h3.addWidget(self.ng_btn)
        h3.addWidget(new_tab_btn)

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
        view = QWebEngineView()
        page = QWebEnginePage(self.profile, view)
        view.setPage(page)
        view.urlChanged.connect(lambda u, v=view: self._on_view_url_changed(v, u))
        view.titleChanged.connect(lambda t, v=view: self._on_view_title_changed(v, t))
        view.setUrl(QUrl(url))
        self.tab_pages.append(view)
        idx = self.pages_stack.addWidget(view)
        self.tab_bar.add_tab(idx, "Loading…")
        self._switch_to_tab(len(self.tab_pages) - 1)

    def _on_tab_clicked(self, idx: int):
        if 0 <= idx < len(self.tab_pages):
            self._switch_to_tab(idx)

    def _on_tab_close(self, idx: int):
        if not (0 <= idx < len(self.tab_pages)):
            return
        view = self.tab_pages.pop(idx)
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

    def _current_view(self) -> QWebEngineView | None:
        idx = self.pages_stack.currentIndex()
        if 0 <= idx < len(self.tab_pages):
            return self.tab_pages[idx]
        return None

    def _current_page(self) -> QWebEngineView | None:
        return self._current_view()

    # ── Event handlers ────────────────────────────────────────
    def _on_view_url_changed(self, view: QWebEngineView, url: QUrl):
        if view is self._current_view():
            self._sync_url_display(url.toString())

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
        self.mode_idx = (self.mode_idx + 1) % len(MODES)
        self._apply_mode()

    def _apply_mode(self):
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

    # ── Overlay positioning ───────────────────────────────────
    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._reposition_overlays()

    def _reposition_overlays(self):
        # Mode + NetGuard buttons now live in the dock — no floating overlays to position.
        pass


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Argus")
    app.setOrganizationName("NetGuard")
    app.setStyle("Fusion")
    win = ArgusBrowser()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
