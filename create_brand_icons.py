"""NetGuard Pro Suite — Unified Brand Icon Generator

Produces all module icons from a single master template so the suite stays
visually consistent. Each icon is a hexagonal tactical shield with a subtle
network mesh background, a bold center letter/symbol, and a module-specific
accent color.

Run: python create_brand_icons.py
Requires: pip install Pillow
"""
from __future__ import annotations

import math
import os
import random
from pathlib import Path
from typing import Sequence

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parent
SENTINEL_ICONS = ROOT / "sentinel" / "icons"
SIZES = [16, 24, 32, 48, 64, 128, 256]
MASTER = 512

BG = (12, 12, 18, 255)
SHIELD_FILL = (16, 18, 28, 255)

GRADIENT_BLUE_PURPLE = [(45, 217, 255), (77, 159, 255), (180, 125, 255)]
GRADIENT_AI = [(77, 159, 255), (180, 125, 255), (61, 255, 180)]
GRADIENT_RED_AMBER = [(255, 77, 106), (255, 179, 71), (255, 209, 61)]


def _find_font(size: int, bold: bool = True) -> ImageFont.FreeTypeFont:
    candidates = []
    if bold:
        candidates += [
            r"C:\Windows\Fonts\segoeuib.ttf",
            r"C:\Windows\Fonts\arialbd.ttf",
            r"C:\Windows\Fonts\seguibl.ttf",
        ]
    candidates += [
        r"C:\Windows\Fonts\segoeui.ttf",
        r"C:\Windows\Fonts\arial.ttf",
    ]
    for path in candidates:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    return ImageFont.load_default()


def _shield_polygon(size: int) -> list[tuple[float, float]]:
    """Hexagonal tactical shield — flat top, sloped sides, rounded point."""
    s = size / 200
    return [
        (62 * s, 22 * s),
        (138 * s, 22 * s),
        (170 * s, 46 * s),
        (174 * s, 90 * s),
        (162 * s, 130 * s),
        (140 * s, 158 * s),
        (100 * s, 182 * s),
        (60 * s, 158 * s),
        (38 * s, 130 * s),
        (26 * s, 90 * s),
        (30 * s, 46 * s),
    ]


def _gradient_color(stops: Sequence[tuple[int, int, int]], t: float) -> tuple[int, int, int]:
    if t <= 0:
        return stops[0]
    if t >= 1:
        return stops[-1]
    seg = t * (len(stops) - 1)
    i = int(seg)
    local = seg - i
    a = stops[i]
    b = stops[min(i + 1, len(stops) - 1)]
    return (
        int(a[0] + local * (b[0] - a[0])),
        int(a[1] + local * (b[1] - a[1])),
        int(a[2] + local * (b[2] - a[2])),
    )


def _stroke_polygon_gradient(draw: ImageDraw.ImageDraw,
                             pts: list[tuple[float, float]],
                             stops: Sequence[tuple[int, int, int]],
                             width: int) -> None:
    closed = pts + [pts[0]]
    n = len(closed) - 1
    for i in range(n):
        t = i / max(n - 1, 1)
        col = _gradient_color(stops, t) + (255,)
        draw.line([closed[i], closed[i + 1]], fill=col, width=width)
    for p in pts:
        col = _gradient_color(stops, pts.index(p) / max(len(pts) - 1, 1)) + (255,)
        r = max(1, width // 2)
        draw.ellipse([p[0] - r, p[1] - r, p[0] + r, p[1] + r], fill=col)


def _draw_mesh(img: Image.Image, size: int, rng: random.Random,
               accent: tuple[int, int, int]) -> None:
    if size < 48:
        return
    layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    s = size / 200
    margin = max(8, int(46 * s))
    y_lo = margin + max(2, int(8 * s))
    y_hi = size - margin - max(2, int(8 * s))
    if y_hi <= y_lo or size - margin <= margin:
        return
    nodes = []
    for _ in range(7):
        x = rng.randint(margin, size - margin)
        y = rng.randint(y_lo, y_hi)
        nodes.append((x, y))
    line_color = accent + (60,)
    for i, a in enumerate(nodes):
        for b in nodes[i + 1:]:
            dx, dy = a[0] - b[0], a[1] - b[1]
            if dx * dx + dy * dy < (60 * s) ** 2:
                d.line([a, b], fill=line_color, width=max(1, int(s)))
    for n in nodes:
        r = max(2, int(2.5 * s))
        d.ellipse([n[0] - r, n[1] - r, n[0] + r, n[1] + r], fill=accent + (180,))
    if size >= 64:
        layer = layer.filter(ImageFilter.GaussianBlur(radius=max(1, size / 200)))
    img.alpha_composite(layer)


def _draw_glow(img: Image.Image, size: int, center: tuple[int, int],
               accent: tuple[int, int, int]) -> None:
    if size < 32:
        return
    glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(glow)
    cx, cy = center
    r = int(size * 0.32)
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=accent + (90,))
    glow = glow.filter(ImageFilter.GaussianBlur(radius=size / 8))
    img.alpha_composite(glow)


def _sparkle_polygon(cx: float, cy: float, r: float) -> list[tuple[float, float]]:
    """4-point sparkle/diamond star with concave sides."""
    inner = r * 0.22
    return [
        (cx, cy - r),
        (cx + inner, cy - inner),
        (cx + r, cy),
        (cx + inner, cy + inner),
        (cx, cy + r),
        (cx - inner, cy + inner),
        (cx - r, cy),
        (cx - inner, cy - inner),
    ]


def _bolt_polygon(cx: float, cy: float, r: float) -> list[tuple[float, float]]:
    """Lightning bolt outline centered on (cx, cy) with half-height r."""
    return [
        (cx + r * 0.10, cy - r),
        (cx - r * 0.55, cy + r * 0.05),
        (cx - r * 0.05, cy + r * 0.05),
        (cx - r * 0.20, cy + r),
        (cx + r * 0.55, cy - r * 0.10),
        (cx + r * 0.05, cy - r * 0.10),
        (cx + r * 0.45, cy - r),
    ]


def _draw_shape(img: Image.Image, size: int, shape: str,
                accent: tuple[int, int, int]) -> None:
    cx, cy = size / 2, size * 0.50
    r = size * 0.30
    layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    if shape == "sparkle":
        pts = _sparkle_polygon(cx, cy, r)
    elif shape == "bolt":
        pts = _bolt_polygon(cx, cy, r)
    else:
        return
    if size >= 32:
        shadow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        ds = ImageDraw.Draw(shadow)
        ds.polygon(pts, fill=accent + (160,))
        shadow = shadow.filter(ImageFilter.GaussianBlur(radius=size / 22))
        layer.alpha_composite(shadow)
    d.polygon(pts, fill=(255, 255, 255, 255))
    if size >= 48:
        ImageDraw.Draw(layer).polygon(pts, outline=accent + (255,), width=max(1, int(size / 90)))
    img.alpha_composite(layer)


def _draw_letter(img: Image.Image, size: int, text: str,
                 accent: tuple[int, int, int]) -> None:
    if text == "✦":
        return _draw_shape(img, size, "sparkle", accent)
    if text == "⚡":
        return _draw_shape(img, size, "bolt", accent)
    if size < 24 and len(text) > 1:
        text = text[0]
    font_size = int(size * (0.58 if len(text) == 1 else 0.40))
    font = _find_font(font_size, bold=True)
    layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    try:
        bbox = d.textbbox((0, 0), text, font=font)
        tw = bbox[2] - bbox[0]
        th = bbox[3] - bbox[1]
        tx = (size - tw) / 2 - bbox[0]
        ty = (size - th) / 2 - bbox[1] - size * 0.04
    except AttributeError:
        tw, th = font.getsize(text)
        tx = (size - tw) / 2
        ty = (size - th) / 2 - size * 0.04
    if size >= 32:
        shadow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        ds = ImageDraw.Draw(shadow)
        ds.text((tx, ty + size * 0.02), text, font=font, fill=accent + (120,))
        shadow = shadow.filter(ImageFilter.GaussianBlur(radius=size / 28))
        layer.alpha_composite(shadow)
    d.text((tx, ty), text, font=font, fill=(255, 255, 255, 255))
    img.alpha_composite(layer)


def _draw_scan_dot(img: Image.Image, size: int) -> None:
    if size < 32:
        return
    d = ImageDraw.Draw(img)
    s = size / 200
    cx, cy = int(100 * s), int(14 * s)
    r = max(2, int(3 * s))
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(61, 255, 180, 255))


def _render_master(size: int, letter: str,
                   border_stops: Sequence[tuple[int, int, int]],
                   accent: tuple[int, int, int],
                   seed: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    pad = max(0, int(size * 0.015))
    d.ellipse([pad, pad, size - 1 - pad, size - 1 - pad], fill=BG)

    poly = _shield_polygon(size)
    d.polygon(poly, fill=SHIELD_FILL)

    rng = random.Random(seed)
    _draw_mesh(img, size, rng, accent)
    _draw_glow(img, size, (size // 2, int(size * 0.50)), accent)

    border_w = max(2, int(size * 0.022))
    _stroke_polygon_gradient(ImageDraw.Draw(img), poly, border_stops, border_w)

    inner = [(p[0] + (size / 2 - p[0]) * 0.06, p[1] + (size / 2 - p[1]) * 0.06) for p in poly]
    inner_w = max(1, int(size * 0.008))
    _stroke_polygon_gradient(ImageDraw.Draw(img), inner, border_stops, inner_w)

    _draw_letter(img, size, letter, accent)
    _draw_scan_dot(img, size)
    return img


def _save_ico(out_path: Path, letter: str,
              border_stops: Sequence[tuple[int, int, int]] = GRADIENT_BLUE_PURPLE,
              accent: tuple[int, int, int] = (77, 159, 255),
              seed: int | None = None) -> None:
    seed = seed if seed is not None else hash(out_path.name) & 0xFFFF
    images = [_render_master(s, letter, border_stops, accent, seed) for s in SIZES]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    images[-1].save(
        out_path,
        format="ICO",
        sizes=[(s, s) for s in SIZES],
        append_images=images[:-1],
    )
    print(f"[OK] {out_path.relative_to(ROOT)}")


MODULES = [
    {"path": ROOT / "netguard_icon.ico",                 "letter": "N", "accent": (77, 159, 255), "stops": GRADIENT_BLUE_PURPLE},
    {"path": ROOT / "netguard_ai_icon.ico",              "letter": "✦", "accent": (180, 125, 255), "stops": GRADIENT_AI},
    {"path": SENTINEL_ICONS / "netguard.ico",            "letter": "N", "accent": (77, 159, 255), "stops": GRADIENT_BLUE_PURPLE},
    {"path": SENTINEL_ICONS / "sentinel.ico",            "letter": "S", "accent": (45, 217, 255), "stops": GRADIENT_BLUE_PURPLE},
    {"path": ROOT / "sentinel" / "SentinelOS.ico",       "letter": "S", "accent": (45, 217, 255), "stops": GRADIENT_BLUE_PURPLE},
    {"path": SENTINEL_ICONS / "cleanguard.ico",          "letter": "C", "accent": (61, 255, 180), "stops": [(61,255,180),(45,217,255),(77,159,255)]},
    {"path": SENTINEL_ICONS / "fim.ico",                 "letter": "F", "accent": (255, 179, 71), "stops": [(255,179,71),(180,125,255),(77,159,255)]},
    {"path": SENTINEL_ICONS / "honeypot.ico",            "letter": "H", "accent": (255, 209, 61), "stops": [(255,209,61),(255,179,71),(180,125,255)]},
    {"path": SENTINEL_ICONS / "mailshield.ico",          "letter": "M", "accent": (77, 159, 255), "stops": GRADIENT_BLUE_PURPLE},
    {"path": SENTINEL_ICONS / "recorder.ico",            "letter": "R", "accent": (255, 77, 106), "stops": [(255,77,106),(180,125,255),(77,159,255)]},
    {"path": SENTINEL_ICONS / "strikeback.ico",          "letter": "⚡", "accent": (255, 179, 71), "stops": GRADIENT_RED_AMBER},
    {"path": SENTINEL_ICONS / "vpnguard.ico",            "letter": "V", "accent": (180, 125, 255), "stops": [(180,125,255),(77,159,255),(45,217,255)]},
]


def main() -> None:
    print(f"[NetGuard Brand] generating {len(MODULES)} icons …")
    for m in MODULES:
        _save_ico(m["path"], m["letter"], m["stops"], m["accent"])

    png_master = ROOT / "netguard_icon.png"
    img = _render_master(MASTER, "N", GRADIENT_BLUE_PURPLE, (77, 159, 255), seed=42)
    img.save(png_master)
    print(f"[OK] {png_master.relative_to(ROOT)} (preview {MASTER}x{MASTER})")

    png_ai = ROOT / "netguard_ai_icon.png"
    img_ai = _render_master(MASTER, "✦", GRADIENT_AI, (180, 125, 255), seed=7)
    img_ai.save(png_ai)
    print(f"[OK] {png_ai.relative_to(ROOT)} (preview {MASTER}x{MASTER})")


if __name__ == "__main__":
    main()
