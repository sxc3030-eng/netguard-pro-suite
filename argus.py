"""
Argus — NetGuard Cybersecurity Workbench
"Voit tout absolument tout" — invisible auth, minimal chrome, unified browser
for the entire NetGuard Pro Suite (NetGuard / Sentinel / CleanGuard / MailShield / VPNGuard).

Architecture:
- pywebview window (WebView2 on Windows, WebKit on macOS/Linux) — same engine
  used by NetGuard's dashboard mode, no Edge/Chrome Tracking-Prevention issues.
- Each NetGuard Suite page loads in its own iframe within the Argus shell.
- The WS auth token is read from .netguard_token at startup and passed to
  every iframe URL as ?ng_token=… — no prompts, no localStorage drama.
- Tab bar, URL bar (with IP shortcut), reload/back/forward, always-on-top,
  Ctrl+1..9 hotkeys to jump tabs, Ctrl+R reload, Ctrl+L focus URL.

Run:
    python argus.py
or double-click LANCER_ARGUS.bat
"""
import json
import os
import sys
import webbrowser
from pathlib import Path

try:
    import webview
except ImportError:
    print("ERROR: pywebview not installed. Install with: pip install pywebview")
    sys.exit(1)

ROOT = Path(__file__).resolve().parent
TOKEN_FILE = ROOT / ".netguard_token"

# Module pages exposed by Argus. Order = tab order. Items with needs_token=True
# get the WS auth token appended to their URL as ?ng_token=… so they connect
# without prompting the user.
PAGES = [
    {"id": "dashboard",    "label": "Dashboard",   "icon": "📊", "path": "netguard_dashboard.html",       "needs_token": True},
    {"id": "map",          "label": "Carte",       "icon": "🌐", "path": "netguard_map.html",             "needs_token": True},
    {"id": "panels",       "label": "Panels",      "icon": "📋", "path": "netguard_panels.html",          "needs_token": True},
    {"id": "network",      "label": "Réseau",      "icon": "🔌", "path": "netguard_network.html",         "needs_token": True},
    {"id": "history",      "label": "Histoire",    "icon": "📜", "path": "netguard_history.html",         "needs_token": True},
    {"id": "ai",           "label": "AI",          "icon": "🤖", "path": "netguard_ai.html",              "needs_token": False},
    {"id": "sentinel",     "label": "Sentinel",    "icon": "🛡", "path": "sentinel/sentinel_dashboard.html",   "needs_token": False},
    {"id": "sentinel-map", "label": "Sentinel Map","icon": "🗺", "path": "sentinel/sentinel_map.html",         "needs_token": False},
    {"id": "cleanguard",   "label": "CleanGuard",  "icon": "🧹", "path": "cleanguard/cleanguard_dashboard.html","needs_token": False},
    {"id": "mailshield",   "label": "MailShield",  "icon": "📧", "path": "mailshield/mailshield_dashboard.html","needs_token": False},
    {"id": "vpnguard",     "label": "VPNGuard",    "icon": "🔐", "path": "vpnguard/vpnguard_dashboard.html",    "needs_token": False},
]


class ArgusAPI:
    """Methods callable from JS via window.pywebview.api.*"""

    def __init__(self):
        self.window = None
        self._on_top = False

    def get_token(self) -> str:
        try:
            return TOKEN_FILE.read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    def get_pages(self) -> list:
        token = self.get_token()
        out = []
        for p in PAGES:
            full = ROOT / p["path"]
            url = full.as_uri() if full.exists() else ""
            if url and p.get("needs_token") and token:
                url = f"{url}?ng_token={token}"
            out.append({**p, "url": url, "exists": bool(url)})
        return out

    def open_external(self, url: str):
        try:
            webbrowser.open(url)
        except Exception:
            pass

    def set_on_top(self, state: bool):
        self._on_top = bool(state)
        try:
            if self.window is not None:
                self.window.on_top = self._on_top
        except Exception:
            pass


def _shell_html() -> str:
    return r"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><title>Argus — NetGuard Cybersecurity Workbench</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Geist',sans-serif;background:#0a0e14;color:#eaeaea;overflow:hidden}
.shell{display:flex;flex-direction:column;height:100%}
.topbar{display:flex;background:linear-gradient(180deg,#16161d,#0e0e14);border-bottom:1px solid #2d2d39;padding:8px 14px;align-items:center;gap:10px;flex-shrink:0;height:54px;-webkit-app-region:drag}
.topbar > *{-webkit-app-region:no-drag}
.brand{display:flex;align-items:center;gap:8px;font-weight:700;color:#4d9fff;font-size:14px;letter-spacing:.08em;font-family:'Geist Mono',monospace;user-select:none}
.brand .eye{display:inline-block;width:9px;height:9px;border-radius:50%;background:radial-gradient(circle at 30% 30%,#3dffb4 0%,#4d9fff 60%,#1a3a6e 100%);box-shadow:0 0 10px #4d9fff}
.tabbar{display:flex;gap:3px;flex:1;overflow-x:auto;align-items:center}
.tabbar::-webkit-scrollbar{height:0}
.tab{display:flex;align-items:center;gap:5px;padding:6px 10px;background:transparent;border:1px solid transparent;border-radius:5px;color:#888;cursor:pointer;font:inherit;font-size:11.5px;white-space:nowrap;transition:.12s;font-family:inherit}
.tab:hover{color:#ddd;background:#1c1c26}
.tab.active{background:linear-gradient(135deg,#1a3a6e44,#2a1a4d44);border-color:#4d9fff;color:#4d9fff;font-weight:600}
.tab.missing{opacity:.32;cursor:not-allowed}
.tab.missing:hover{background:transparent}
.url-input{background:#1c1c26;border:1px solid #2d2d39;color:#bbb;padding:6px 10px;border-radius:5px;width:240px;font:inherit;font-size:11px;font-family:'Geist Mono',monospace}
.url-input:focus{outline:none;border-color:#4d9fff;color:#fff;background:#0e0e14}
.btn-icon{background:transparent;border:1px solid transparent;color:#888;width:28px;height:28px;border-radius:5px;cursor:pointer;font-size:13px;font:inherit;display:flex;align-items:center;justify-content:center;transition:.12s}
.btn-icon:hover{color:#4d9fff;border-color:#2d2d39;background:#1c1c26}
.btn-icon.active{color:#3dffb4}
.frame-host{flex:1;background:#0a0e14;position:relative}
iframe{position:absolute;inset:0;width:100%;height:100%;border:0;background:#0a0e14;display:none}
iframe.active{display:block}
.welcome{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;flex-direction:column;color:#666;gap:14px;font-size:13px}
.welcome .logo{font-size:54px;color:#4d9fff;font-weight:200;letter-spacing:.18em;font-family:'Geist Mono',monospace;text-shadow:0 0 24px rgba(77,159,255,.3)}
.welcome .sub{color:#777;font-size:10px;letter-spacing:.12em;text-transform:uppercase}
.welcome .sub2{color:#555;font-size:10px;font-family:'Geist Mono',monospace}
.token-status{position:absolute;bottom:12px;right:12px;font-size:10px;color:#666;font-family:'Geist Mono',monospace;background:rgba(20,20,30,.85);padding:4px 8px;border-radius:4px;pointer-events:none;border:1px solid #2d2d39}
.token-status.ok{color:#3dffb4;border-color:#3dffb433}
.token-status.warn{color:#ff4d6a;border-color:#ff4d6a33}
.kbd-hint{position:absolute;bottom:12px;left:12px;font-size:9px;color:#444;font-family:'Geist Mono',monospace;letter-spacing:.05em}
</style></head><body>
<div class="shell">
  <div class="topbar">
    <div class="brand"><span class="eye"></span><span>ARGUS</span></div>
    <div class="tabbar" id="tabbar"></div>
    <input id="url-input" class="url-input" placeholder="IP, domaine ou URL  (Ctrl+L)" spellcheck="false">
    <button class="btn-icon" onclick="reloadActive()" title="Recharger (F5 / Ctrl+R)">⟳</button>
    <button class="btn-icon" onclick="goBack()" title="Retour">◀</button>
    <button class="btn-icon" onclick="goFwd()" title="Suivant">▶</button>
    <button class="btn-icon" id="ontop-btn" onclick="toggleTop()" title="Toujours au-dessus">📌</button>
  </div>
  <div class="frame-host" id="frame-host">
    <div class="welcome" id="welcome">
      <div class="logo">ARGUS</div>
      <div class="sub">Cybersecurity Workbench</div>
      <div class="sub2">Chargement des modules…</div>
    </div>
    <div class="kbd-hint">Ctrl+1..9 = tab · Ctrl+R = reload · Ctrl+L = url</div>
    <div class="token-status" id="token-status">…</div>
  </div>
</div>
<script>
let pages = [];
let activeId = null;
let alwaysOnTop = false;

async function init() {
  if (!window.pywebview || !window.pywebview.api) {
    setStatus('pywebview API absente', 'warn');
    return;
  }
  try {
    pages = await window.pywebview.api.get_pages();
  } catch (e) {
    setStatus('get_pages() failed: ' + e.message, 'warn');
    return;
  }
  renderTabs();
  const tok = await window.pywebview.api.get_token();
  if (tok && tok.length >= 32) {
    setStatus('AUTH ✓ ' + tok.substring(0, 6) + '…', 'ok');
  } else {
    setStatus('TOKEN ABSENT — démarre NetGuard', 'warn');
  }
  // Auto-open the first available tab (typically Dashboard)
  const first = pages.find(p => p.exists);
  if (first) showPage(first.id);
}

function setStatus(text, kind) {
  const el = document.getElementById('token-status');
  el.textContent = text;
  el.classList.remove('ok', 'warn');
  if (kind) el.classList.add(kind);
}

function renderTabs() {
  const bar = document.getElementById('tabbar');
  bar.innerHTML = '';
  pages.forEach(p => {
    const btn = document.createElement('button');
    btn.className = 'tab' + (p.exists ? '' : ' missing');
    btn.dataset.id = p.id;
    if (p.exists) {
      btn.addEventListener('click', () => showPage(p.id));
    } else {
      btn.disabled = true;
      btn.title = 'Page non trouvée: ' + p.path;
    }
    const ic = document.createElement('span'); ic.textContent = p.icon; btn.appendChild(ic);
    const lb = document.createElement('span'); lb.textContent = p.label; btn.appendChild(lb);
    bar.appendChild(btn);
  });
}

function showPage(id) {
  const page = pages.find(p => p.id === id);
  if (!page || !page.exists) return;
  activeId = id;
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.id === id));
  let iframe = document.getElementById('frame-' + id);
  if (!iframe) {
    iframe = document.createElement('iframe');
    iframe.id = 'frame-' + id;
    iframe.src = page.url;
    document.getElementById('frame-host').appendChild(iframe);
  }
  document.querySelectorAll('iframe').forEach(f => f.classList.remove('active'));
  iframe.classList.add('active');
  const w = document.getElementById('welcome'); if (w) w.style.display = 'none';
}

function reloadActive() {
  if (!activeId) return;
  const f = document.getElementById('frame-' + activeId);
  if (f) f.src = f.src;
}

function goBack() {
  if (!activeId) return;
  const f = document.getElementById('frame-' + activeId);
  try { f && f.contentWindow.history.back(); } catch (e) {}
}

function goFwd() {
  if (!activeId) return;
  const f = document.getElementById('frame-' + activeId);
  try { f && f.contentWindow.history.forward(); } catch (e) {}
}

function toggleTop() {
  alwaysOnTop = !alwaysOnTop;
  document.getElementById('ontop-btn').classList.toggle('active', alwaysOnTop);
  if (window.pywebview && window.pywebview.api && window.pywebview.api.set_on_top) {
    window.pywebview.api.set_on_top(alwaysOnTop);
  }
}

document.getElementById('url-input').addEventListener('keydown', e => {
  if (e.key !== 'Enter') return;
  const v = e.target.value.trim();
  if (!v) return;
  const isIP = /^[0-9.]+$/.test(v) || /^[0-9a-fA-F:]+$/.test(v);
  if (isIP) {
    showPage('map');
    setTimeout(() => {
      const f = document.getElementById('frame-map');
      try { f && f.contentWindow.showIPPanel && f.contentWindow.showIPPanel(v); } catch (e) {}
    }, 350);
    e.target.value = '';
    return;
  }
  if (v.startsWith('http')) {
    window.pywebview && window.pywebview.api && window.pywebview.api.open_external(v);
    e.target.value = '';
  }
});

document.addEventListener('keydown', e => {
  if (e.ctrlKey || e.metaKey) {
    if (e.key >= '1' && e.key <= '9') {
      const idx = parseInt(e.key) - 1;
      const avail = pages.filter(p => p.exists);
      if (avail[idx]) { showPage(avail[idx].id); e.preventDefault(); }
    } else if (e.key.toLowerCase() === 'r') { reloadActive(); e.preventDefault(); }
    else if (e.key.toLowerCase() === 'l') { document.getElementById('url-input').focus(); e.preventDefault(); }
  } else if (e.key === 'F5') { reloadActive(); e.preventDefault(); }
});

window.addEventListener('pywebviewready', init);
window.addEventListener('DOMContentLoaded', () => {
  setTimeout(() => { if (!pages.length) init(); }, 600);
});
</script></body></html>
"""


def main():
    api = ArgusAPI()
    if not TOKEN_FILE.exists():
        print(f"WARN: {TOKEN_FILE} not found. Start NetGuard first to generate the auth token.")

    win = webview.create_window(
        "Argus — NetGuard Cybersecurity Workbench",
        html=_shell_html(),
        js_api=api,
        width=1400,
        height=900,
        background_color="#0a0e14",
        text_select=True,
        confirm_close=False,
    )
    api.window = win
    webview.start(debug=False)


if __name__ == "__main__":
    main()
