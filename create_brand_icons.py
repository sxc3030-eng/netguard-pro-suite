"""NetGuard Pro Suite — Unified Brand Icon Generator (v2, canvas-design)

Wraps `branding/_generate_brand.py:render_logo_png` to emit multi-size .ico
files for every module in the suite. The branding/ directory holds the
canonical design (SVG + 1024x1024 hero + 6-up variants) — this script just
slices that design into the icon sizes Windows wants.

Run: python create_brand_icons.py
Requires: pip install Pillow numpy
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BRANDING = ROOT / "branding"
SENTINEL_ICONS = ROOT / "sentinel" / "icons"
SIZES = [16, 24, 32, 48, 64, 128, 256]
PREVIEW = 512

if str(BRANDING) not in sys.path:
    sys.path.insert(0, str(BRANDING))
import _generate_brand as brand  # type: ignore


MODULES = [
    {"path": ROOT / "netguard_icon.ico",            "letter": "N"},
    {"path": ROOT / "netguard_ai_icon.ico",         "letter": "AI"},
    {"path": SENTINEL_ICONS / "netguard.ico",       "letter": "N"},
    {"path": SENTINEL_ICONS / "sentinel.ico",       "letter": "S"},
    {"path": ROOT / "sentinel" / "SentinelOS.ico",  "letter": "S"},
    {"path": SENTINEL_ICONS / "cleanguard.ico",     "letter": "C"},
    {"path": SENTINEL_ICONS / "fim.ico",            "letter": "F"},
    {"path": SENTINEL_ICONS / "honeypot.ico",       "letter": "H"},
    {"path": SENTINEL_ICONS / "mailshield.ico",     "letter": "M"},
    {"path": SENTINEL_ICONS / "recorder.ico",       "letter": "R"},
    {"path": SENTINEL_ICONS / "strikeback.ico",     "letter": "S"},
    {"path": SENTINEL_ICONS / "vpnguard.ico",       "letter": "V"},
]


def _build_ico(out_path: Path, letter: str) -> None:
    images = [brand.render_logo_png(s, letter=letter, transparent_bg=True) for s in SIZES]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    images[-1].save(
        out_path,
        format="ICO",
        sizes=[(s, s) for s in SIZES],
        append_images=images[:-1],
    )
    print(f"[OK] {out_path.relative_to(ROOT)}  ({letter})")


def main() -> None:
    print(f"[NetGuard Brand v2] generating {len(MODULES)} icons via canvas-design …")
    for m in MODULES:
        _build_ico(m["path"], m["letter"])

    preview_master = ROOT / "netguard_icon.png"
    brand.render_logo_png(PREVIEW, letter="N", transparent_bg=True).save(preview_master)
    print(f"[OK] {preview_master.relative_to(ROOT)}  (preview {PREVIEW}x{PREVIEW})")

    preview_ai = ROOT / "netguard_ai_icon.png"
    brand.render_logo_png(PREVIEW, letter="AI", transparent_bg=True).save(preview_ai)
    print(f"[OK] {preview_ai.relative_to(ROOT)}  (preview {PREVIEW}x{PREVIEW})")


if __name__ == "__main__":
    main()
