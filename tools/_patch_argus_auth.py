"""One-shot patcher: add Argus URL-param auth fallback to NetGuard dashboards.

Each HTML's getNgToken() currently checks localStorage first (which Edge can
block via Tracking Prevention). Argus passes the token as ?ng_token=… on
the iframe URL, so we make every getNgToken() check the URL FIRST.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTMLS = [
    "netguard_dashboard.html",
    "netguard_map.html",
    "netguard_panels.html",
    "netguard_history.html",
    "netguard_network.html",
]

OLD = "function getNgToken() {\n  let t = localStorage.getItem('ng_ws_token') || '';"

NEW = """function getNgToken() {
  // Argus shell injects the token as ?ng_token=… on the iframe URL — pick that up first.
  try {
    const _argusTok = new URLSearchParams(window.location.search).get('ng_token');
    if (_argusTok && _argusTok.length >= 32) {
      try { localStorage.setItem('ng_ws_token', _argusTok); } catch(_) {}
      return _argusTok;
    }
  } catch(_) {}
  let t = '';
  try { t = localStorage.getItem('ng_ws_token') || ''; } catch(_) {}"""


def main() -> int:
    patched = 0
    skipped = 0
    for name in HTMLS:
        p = ROOT / name
        if not p.exists():
            print(f"  - {name:30}  MISSING")
            continue
        text = p.read_text(encoding="utf-8")
        if "_argusTok" in text:
            print(f"  ~ {name:30}  already patched, skipping")
            skipped += 1
            continue
        if OLD not in text:
            print(f"  ! {name:30}  pattern not found — manual review needed")
            continue
        new_text = text.replace(OLD, NEW, 1)
        p.write_text(new_text, encoding="utf-8")
        print(f"  + {name:30}  patched")
        patched += 1
    print(f"\nDone: {patched} patched, {skipped} already up-to-date")
    return 0 if (patched + skipped) == len(HTMLS) else 1


if __name__ == "__main__":
    sys.exit(main())
