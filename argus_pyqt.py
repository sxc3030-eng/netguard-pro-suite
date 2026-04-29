"""
Argus 2.0 — Real PyQt6 + QtWebEngine browser shell.

Layout (validated from argus_ui_mockup.html):
  Top    : transparent live network feed (2 lines, color-coded, animated)
  Middle : QWebEngineView (real Chromium, sandboxed per-process)
  Bottom : 3-row dock (HTTPS / Search+Engine / Settings+Favs+Tabs)
  Float  : tab pill (top-right), mode badge (top-center)
  F12    : Chromium DevTools panel slide-up, resizable

Run:
    python argus_pyqt.py
or double-click LANCER_ARGUS.bat (after restart)
"""
import sys
from pathlib import Path

from PyQt6.QtCore import Qt, QUrl, QTimer, pyqtSignal, QObject, QSize
from PyQt6.QtGui import QAction, QShortcut, QKeySequence, QFont
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QComboBox, QPushButton, QLabel, QStackedWidget, QFrame,
    QToolButton, QSizePolicy, QSplitter, QGraphicsOpacityEffect, QStyle,
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import (
    QWebEnginePage, QWebEngineProfile, QWebEngineUrlRequestInterceptor,
    QWebEngineSettings,
)

ROOT = Path(__file__).resolve().parent

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

MODES = [
    {"id": "normal",  "icon": "⚪", "text": "NORMAL",  "color": "#9aa0ad"},
    {"id": "private", "icon": "🟦", "text": "PRIVÉ",   "color": "#4d9fff"},
    {"id": "vault",   "icon": "🟡", "text": "COFFRE",  "color": "#d4af37"},
]

# Status code → live-feed type
def _status_kind(status: int, blocked: bool = False) -> str:
    if blocked:
        return "bad"
    if status >= 500: return "bad"
    if status >= 400: return "warn"
    if status >= 300: return "warn"
    if status >= 200: return "ok"
    return "info"


THEME_QSS = r"""
* { font-family: 'Outfit', 'Segoe UI', sans-serif; }

QMainWindow, QWidget#root {
    background: #0a0e14;
}

/* ── Live feed (top, transparent) ── */
QWidget#liveFeed {
    background: rgba(15, 18, 22, 180);
    border-bottom: 1px solid rgba(255,255,255,0.06);
}
QLabel.feedRow {
    color: #e8eaf0;
    font-family: 'Geist Mono', 'Consolas', monospace;
    font-size: 11px;
    padding: 1px 0;
    background: transparent;
}
QLabel.feedRow[kind="ok"]   { color: #3dffb4; }
QLabel.feedRow[kind="warn"] { color: #ffb347; }
QLabel.feedRow[kind="bad"]  { color: #ff4d6a; }
QLabel.feedRow[kind="info"] { color: #4d9fff; }

/* ── Mode badge ── */
QLabel#modeBadge {
    background: #1a1f28;
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 13px;
    padding: 4px 12px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.06em;
    color: #9aa0ad;
    font-family: 'Geist Mono', 'Consolas', monospace;
}
QLabel#modeBadge[mode="private"] { color: #4d9fff; border-color: #4d9fff; }
QLabel#modeBadge[mode="vault"]   { color: #d4af37; border-color: #d4af37;
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #2a1f08, stop:1 #1a1409); }

/* ── Floating tabs ── */
QFrame#floatTabs {
    background: #1a1f28;
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 22px;
    padding: 3px 5px;
}
QPushButton.ftab {
    background: transparent;
    color: #9aa0ad;
    border: 1px solid transparent;
    border-radius: 16px;
    padding: 5px 12px;
    font-size: 11px;
}
QPushButton.ftab:hover { background: #232934; color: #e8eaf0; }
QPushButton.ftab[active="true"] {
    background: rgba(77,159,255,0.20);
    color: #4d9fff;
    border-color: rgba(77,159,255,0.4);
}
QPushButton.ftab[mode="private"] { color: #4d9fff; border-color: rgba(77,159,255,0.5); }
QPushButton.ftab[mode="vault"]   { color: #d4af37; border-color: #d4af37; }

/* ── Bottom dock ── */
QFrame#dock {
    background: #14181f;
    border-top: 1px solid rgba(255,255,255,0.06);
}
QFrame.dockRow {
    background: transparent;
    border-top: 1px solid rgba(255,255,255,0.04);
}
QFrame.dockRow[first="true"] { border-top: none; }

QLabel.lock     { font-size: 13px; color: #3dffb4; }
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
QComboBox#engineSelect::drop-down { border: none; width: 18px; }
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
QPushButton.dockBtn:hover {
    color: #4d9fff;
    background: #1a1f28;
    border-color: rgba(255,255,255,0.12);
}
QPushButton.dockBtn[primary="true"] { color: #4d9fff; }
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
    min-width: 24px;
    max-width: 24px;
    min-height: 24px;
    max-height: 24px;
    font-size: 11px;
    margin: 0 1px;
}
QPushButton.fav:hover { color: #4d9fff; border-color: #4d9fff; }

/* ── Vault/private window border ── */
QWidget#root[mode="vault"] {
    border: 2px solid #d4af37;
}
QWidget#root[mode="private"] {
    border: 1px solid #4d9fff;
}
"""


class FeedSignal(QObject):
    """Bridge the URL request interceptor (worker thread) to UI thread."""
    new_request = pyqtSignal(str, str)  # method, url


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
    """Top transparent feed, max 2 visible rows, oldest fades."""
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

    def push(self, kind: str, method: str, url: str, status: str = "", time: str = ""):
        # Truncate URL for display
        display_url = url
        if len(display_url) > 80:
            display_url = display_url[:77] + "…"
        # Strip protocol prefix for cleaner look
        if display_url.startswith(("https://", "http://")):
            display_url = display_url.split("://", 1)[1]
        icon = {"ok": "✓", "warn": "⚠", "bad": "✗", "info": "⏵"}.get(kind, "·")
        text = f"{icon}  {method:<5}  {display_url:<60}  {status:>6}  {time}"
        row = QLabel(text)
        row.setProperty("class", "feedRow")
        row.setProperty("kind", kind)
        row.setStyleSheet("")  # trigger style refresh
        # Insert at top
        self.layout_box.insertWidget(0, row)
        self.rows.insert(0, row)
        # Trim to last 2 rows
        while len(self.rows) > 2:
            old = self.rows.pop()
            self.layout_box.removeWidget(old)
            old.deleteLater()


class ArgusBrowser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Argus 2.0 — NetGuard Cybersecurity Browser")
        self.resize(1400, 900)

        self.mode_idx = 0  # 0=normal 1=private 2=vault
        self.dev_tools_view = None

        # ── Profile + interceptor ──
        self.profile = QWebEngineProfile.defaultProfile()
        self.profile.settings().setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        self.profile.settings().setAttribute(QWebEngineSettings.WebAttribute.ScreenCaptureEnabled, False)
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

        # Top live feed
        self.feed = LiveFeed()
        v.addWidget(self.feed)

        # Web view (real Chromium)
        self.web = QWebEngineView()
        self.web.setUrl(QUrl("https://duckduckgo.com"))
        self.web.urlChanged.connect(self._on_url_changed)
        self.web.titleChanged.connect(self._on_title_changed)
        v.addWidget(self.web, 1)

        # F12 dev tools placeholder (created lazily)
        self.dev_tools_container = QWidget()
        self.dev_tools_container.setVisible(False)
        self.dev_tools_container.setMinimumHeight(200)
        dt_layout = QVBoxLayout(self.dev_tools_container)
        dt_layout.setContentsMargins(0, 0, 0, 0)
        v.addWidget(self.dev_tools_container)

        # Bottom dock (3 rows)
        v.addWidget(self._build_dock())

        # Floating overlays (mode badge, tab bar)
        self._build_overlays()

        # Apply theme
        self.setStyleSheet(THEME_QSS)
        self._apply_mode()

        # Hotkeys
        QShortcut(QKeySequence("F12"), self, activated=self._toggle_devtools)
        QShortcut(QKeySequence("Ctrl+L"), self, activated=lambda: self.search.setFocus())
        QShortcut(QKeySequence("Ctrl+R"), self, activated=self.web.reload)
        QShortcut(QKeySequence("F5"), self, activated=self.web.reload)
        QShortcut(QKeySequence("Alt+Left"), self, activated=self.web.back)
        QShortcut(QKeySequence("Alt+Right"), self, activated=self.web.forward)

    # ── Build helpers ────────────────────────────────────────
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

        # Row 2 — Search
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
        h2.addWidget(self.engine)
        h2.addWidget(self.search, 1)

        # Row 3 — Settings / Favs / F12 / +Tab
        row3 = QFrame()
        row3.setProperty("class", "dockRow")
        h3 = QHBoxLayout(row3)
        h3.setContentsMargins(14, 6, 14, 6)
        h3.setSpacing(6)
        settings_btn = QPushButton("⚙")
        settings_btn.setProperty("class", "dockBtn")
        settings_btn.setToolTip("Settings (Ctrl+,)")

        favs_bar = QFrame()
        favs_bar.setObjectName("favsBar")
        favs_layout = QHBoxLayout(favs_bar)
        favs_layout.setContentsMargins(4, 2, 4, 2)
        favs_layout.setSpacing(2)
        for label, url in [
            ("G", "https://gmail.com"),
            ("⌘", "https://github.com"),
            ("R", "https://reddit.com"),
            ("▶", "https://youtube.com"),
            ("𝕏", "https://x.com"),
            ("D", "https://discord.com"),
            ("🤖", "https://chatgpt.com"),
            ("M", "https://developer.mozilla.org"),
        ]:
            b = QPushButton(label)
            b.setProperty("class", "fav")
            b.setToolTip(url)
            b.clicked.connect(lambda _, u=url: self.web.setUrl(QUrl(u)))
            favs_layout.addWidget(b)
        favs_layout.addStretch(1)
        favs_bar.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        self.f12_btn = QPushButton("F12")
        self.f12_btn.setObjectName("f12Btn")
        self.f12_btn.setProperty("class", "dockBtn")
        self.f12_btn.setToolTip("DevTools (F12)")
        self.f12_btn.clicked.connect(self._toggle_devtools)

        new_tab_btn = QPushButton("+")
        new_tab_btn.setProperty("class", "dockBtn")
        new_tab_btn.setProperty("primary", True)
        new_tab_btn.setToolTip("Nouveau tab (Ctrl+T)")
        new_tab_btn.clicked.connect(lambda: self.web.setUrl(QUrl("about:blank")))

        h3.addWidget(settings_btn)
        h3.addWidget(favs_bar, 1)
        h3.addWidget(self.f12_btn)
        h3.addWidget(new_tab_btn)

        v.addWidget(row1)
        v.addWidget(row2)
        v.addWidget(row3)
        return dock

    def _build_overlays(self):
        # Mode badge (floating top-center)
        self.mode_badge = QLabel(f"{MODES[0]['icon']}  {MODES[0]['text']}", self)
        self.mode_badge.setObjectName("modeBadge")
        self.mode_badge.setProperty("mode", "normal")
        self.mode_badge.setCursor(Qt.CursorShape.PointingHandCursor)
        self.mode_badge.setToolTip("Click pour changer mode (Normal / Privé / Coffre)")
        self.mode_badge.mousePressEvent = lambda e: self._cycle_mode()
        self.mode_badge.adjustSize()

        # Floating tabs (top-right)
        self.float_tabs = QFrame(self)
        self.float_tabs.setObjectName("floatTabs")
        ft = QHBoxLayout(self.float_tabs)
        ft.setContentsMargins(5, 3, 5, 3)
        ft.setSpacing(3)
        active_tab = QPushButton("📊  Argus")
        active_tab.setProperty("class", "ftab")
        active_tab.setProperty("active", True)
        plus_tab = QPushButton("+")
        plus_tab.setProperty("class", "ftab")
        ft.addWidget(active_tab)
        ft.addWidget(plus_tab)
        self.float_tabs.adjustSize()

    # ── Event handlers ────────────────────────────────────────
    def _on_url_changed(self, url: QUrl):
        url_str = url.toString()
        self.url_display.setText(url_str)
        # Update lock indicator
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

    def _on_title_changed(self, title: str):
        if title:
            self.setWindowTitle(f"Argus — {title}")

    def _on_request(self, method: str, url: str):
        # Quick heuristic for kind
        kind = "info"
        if url.startswith("https://"):
            kind = "ok"
        elif url.startswith("http://"):
            kind = "warn"
        elif url.startswith("ws"):
            kind = "info"
        # Tracker / known-bad heuristic (very rough V1)
        bad_keywords = ["tracker", "doubleclick", "facebook.com/tr", "google-analytics"]
        if any(k in url for k in bad_keywords):
            kind = "warn"
        self.feed.push(kind, method, url, "—", "")

    def _on_search(self):
        q = self.search.text().strip()
        if not q:
            return
        # Detect URL
        if q.startswith(("http://", "https://")):
            self.web.setUrl(QUrl(q))
        elif "." in q and " " not in q and not q.startswith(">"):
            # looks like domain
            self.web.setUrl(QUrl("https://" + q))
        else:
            engine_idx = self.engine.currentIndex()
            template = SEARCH_ENGINES[engine_idx][1]
            from urllib.parse import quote
            self.web.setUrl(QUrl(template.format(q=quote(q))))
        self.search.clear()

    def _toggle_devtools(self):
        if not self.dev_tools_container.isVisible():
            if self.dev_tools_view is None:
                # Create dev tools view lazily
                self.dev_tools_view = QWebEngineView()
                page = QWebEnginePage(self.profile, self.dev_tools_view)
                self.dev_tools_view.setPage(page)
                self.web.page().setDevToolsPage(page)
                self.dev_tools_container.layout().addWidget(self.dev_tools_view)
            self.dev_tools_container.setVisible(True)
            self.f12_btn.setProperty("primary", True)
        else:
            self.dev_tools_container.setVisible(False)
            self.f12_btn.setProperty("primary", False)
        self.f12_btn.style().unpolish(self.f12_btn)
        self.f12_btn.style().polish(self.f12_btn)

    def _cycle_mode(self):
        self.mode_idx = (self.mode_idx + 1) % len(MODES)
        self._apply_mode()

    def _apply_mode(self):
        m = MODES[self.mode_idx]
        self.mode_badge.setText(f"{m['icon']}  {m['text']}")
        self.mode_badge.setProperty("mode", m["id"])
        self.root.setProperty("mode", m["id"])
        for w in (self.mode_badge, self.root):
            w.style().unpolish(w)
            w.style().polish(w)
        self.mode_badge.adjustSize()
        self._reposition_overlays()

    # ── Position overlays on resize ────────────────────────────
    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._reposition_overlays()

    def _reposition_overlays(self):
        if not hasattr(self, "mode_badge"):
            return
        # Mode badge — top center, just below feed
        bw = self.mode_badge.width()
        self.mode_badge.move((self.width() - bw) // 2, 54)
        # Float tabs — top right
        self.float_tabs.adjustSize()
        ftw = self.float_tabs.width()
        self.float_tabs.move(self.width() - ftw - 14, 54)
        self.mode_badge.raise_()
        self.float_tabs.raise_()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Argus")
    app.setOrganizationName("NetGuard")

    # Force consistent style (avoid native Windows widgets clashing with our QSS)
    app.setStyle("Fusion")

    win = ArgusBrowser()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
