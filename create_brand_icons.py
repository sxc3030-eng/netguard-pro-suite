"""NetGuard Pro Suite — Unified Brand Icon Generator (v3, distinct modules)

Wraps `branding/modules/_generate_modules.py:render_module_icon` to emit
multi-size .ico files for every module in the suite. Each module has its
own bespoke metaphor (envelope for MailShield, eye for Sentinel, lightning
for StrikeBack, etc.) while sharing the same shield silhouette + tri-color
gradient brand DNA.

Run: python create_brand_icons.py
Requires: pip install Pillow numpy
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BRANDING = ROOT / "branding"
MODULES_DIR = BRANDING / "modules"
SENTINEL_ICONS = ROOT / "sentinel" / "icons"
SIZES = [16, 24, 32, 48, 64, 128, 256]
PREVIEW = 512

# Make both branding/ and branding/modules/ importable.
for p in (BRANDING, MODULES_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import _generate_modules as mods  # type: ignore


# ICO output path → module slug from branding/modules registry.
ICONS = [
    {"path": ROOT / "netguard_icon.ico",                "slug": "netguard"},
    {"path": ROOT / "netguard_ai_icon.ico",             "slug": "netguard-ai"},
    {"path": SENTINEL_ICONS / "netguard.ico",           "slug": "netguard-tray"},
    {"path": SENTINEL_ICONS / "sentinel.ico",           "slug": "sentinel-os"},
    {"path": ROOT / "sentinel" / "SentinelOS.ico",      "slug": "sentinel-os"},
    {"path": SENTINEL_ICONS / "siem.ico",               "slug": "siem"},
    {"path": SENTINEL_ICONS / "sandbox.ico",            "slug": "sandbox"},
    {"path": SENTINEL_ICONS / "cleanguard.ico",         "slug": "cleanguard"},
    {"path": SENTINEL_ICONS / "fim.ico",                "slug": "fim"},
    {"path": SENTINEL_ICONS / "honeypot.ico",           "slug": "honeypot"},
    {"path": SENTINEL_ICONS / "mailshield.ico",         "slug": "mailshield"},
    {"path": SENTINEL_ICONS / "recorder.ico",           "slug": "recorder"},
    {"path": SENTINEL_ICONS / "strikeback.ico",         "slug": "strikeback"},
    {"path": SENTINEL_ICONS / "vpnguard.ico",           "slug": "vpnguard"},
]


def _build_ico(out_path: Path, slug: str) -> None:
    images = [mods.render_module_icon(slug, s) for s in SIZES]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    images[-1].save(
        out_path,
        format="ICO",
        sizes=[(s, s) for s in SIZES],
        append_images=images[:-1],
    )
    print(f"[OK] {out_path.relative_to(ROOT)}  ({slug})")


def main() -> None:
    print(f"[NetGuard Brand v3] generating {len(ICONS)} distinct icons via canvas-design …")
    for entry in ICONS:
        _build_ico(entry["path"], entry["slug"])

    # Preview renders for the README / marketing surfaces.
    preview_master = ROOT / "netguard_icon.png"
    mods.render_module_icon("netguard", PREVIEW).save(preview_master)
    print(f"[OK] {preview_master.relative_to(ROOT)}  (preview {PREVIEW}x{PREVIEW})")

    preview_ai = ROOT / "netguard_ai_icon.png"
    mods.render_module_icon("netguard-ai", PREVIEW).save(preview_ai)
    print(f"[OK] {preview_ai.relative_to(ROOT)}  (preview {PREVIEW}x{PREVIEW})")


if __name__ == "__main__":
    main()
