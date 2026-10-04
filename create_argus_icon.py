"""Argus — Logo / Icon Generator (.png + .ico)

Generates `argus_icon.png` (256x256) and `argus_icon.ico` (multi-size) by
rendering the same composition as `argus_logo.svg`: an outer ring of small
"eyes" (the 100 yeux of Argus Panoptes) around a central panoptic eye, on
the dark NetGuard-family background.

Requires: pip install Pillow
"""
from __future__ import annotations

import math
import os
from PIL import Image, ImageDraw, ImageFilter


# Brand palette (matches netguard_logo.svg)
BG          = (15, 15, 19, 255)          # #0f0f13
BLUE        = (77, 159, 255)             # #4d9fff
PURPLE      = (180, 125, 255)            # #b47dff
GREEN       = (61, 255, 180)             # #3dffb4
GRID        = (77, 159, 255, 16)         # subtle grid


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def gradient_color(t: float):
    """Blue → purple → green along t in [0, 1]."""
    if t < 0.5:
        return lerp(BLUE, PURPLE, t * 2)
    return lerp(PURPLE, GREEN, (t - 0.5) * 2)


def draw_argus(size: int) -> Image.Image:
    """Render Argus logo at the given square size."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = size / 200.0  # scale factor: SVG is 200x200

    # Background circle
    d.ellipse([8 * s, 8 * s, 192 * s, 192 * s], fill=BG)

    # Outer glow ring
    ring = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    rd = ImageDraw.Draw(ring)
    rd.ellipse([12 * s, 12 * s, 188 * s, 188 * s],
               outline=BLUE + (110,), width=max(1, int(s)))
    ring = ring.filter(ImageFilter.GaussianBlur(radius=1.5 * s))
    img = Image.alpha_composite(img, ring)
    d = ImageDraw.Draw(img)

    # Tech grid
    for y in (60, 100, 140):
        d.line([(20 * s, y * s), (180 * s, y * s)], fill=GRID, width=1)
    for x in (60, 100, 140):
        d.line([(x * s, 20 * s), (x * s, 180 * s)], fill=GRID, width=1)

    # Outer ring of 24 eyes (r=78 from center)
    cx, cy = 100 * s, 100 * s
    for i in range(24):
        ang = -math.pi / 2 + i * (2 * math.pi / 24)
        ex = cx + 78 * s * math.cos(ang)
        ey = cy + 78 * s * math.sin(ang)
        col = gradient_color(i / 24)
        r = max(1, int(2.0 * s)) if i % 2 == 0 else max(1, int(1.6 * s))
        d.ellipse([ex - r, ey - r, ex + r, ey + r], fill=col + (220,))

    # Inner ring of 16 eyes (r=58)
    for i in range(16):
        ang = -math.pi / 2 + i * (2 * math.pi / 16)
        ex = cx + 58 * s * math.cos(ang)
        ey = cy + 58 * s * math.sin(ang)
        col = gradient_color((i + 4) / 24)  # phase shift
        r = max(1, int(1.5 * s))
        d.ellipse([ex - r, ey - r, ex + r, ey + r], fill=col + (180,))

    # Central panoptic eye — almond shape
    almond = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    ad = ImageDraw.Draw(almond)
    # Build an almond by drawing two arcs as a quadratic-Bezier-ish polygon
    n = 64
    upper = []
    lower = []
    for i in range(n + 1):
        t = i / n
        x = 60 * s + t * 80 * s
        # Symmetric parabolic-like curves
        bow = math.sin(t * math.pi) * 30 * s
        upper.append((x, cy - bow))
        lower.append((x, cy + bow))
    poly = upper + list(reversed(lower))
    ad.polygon(poly, outline=BLUE, fill=None)
    # Stroke thickness via redraw
    for off in range(-1, 2):
        for off2 in range(-1, 2):
            stroke = [(p[0] + off * s, p[1] + off2 * s) for p in poly]
            ad.polygon(stroke, outline=BLUE, fill=None)
    almond = almond.filter(ImageFilter.GaussianBlur(radius=1.2 * s))
    img = Image.alpha_composite(img, almond)
    d = ImageDraw.Draw(img)
    # Re-draw clean outline
    d.line(upper, fill=BLUE, width=max(2, int(2.5 * s)))
    d.line(lower, fill=PURPLE, width=max(2, int(2.5 * s)))

    # Iris (radial gradient effect via concentric circles)
    iris_r = 18 * s
    for i in range(int(iris_r), 0, -1):
        t = i / iris_r
        col = lerp(GREEN, PURPLE, t)
        a = int(255 * (1 - t * 0.3))
        d.ellipse([cx - i, cy - i, cx + i, cy + i], fill=col + (a,))

    # Iris radial detail (8 short rays)
    for i in range(8):
        ang = i * (math.pi / 4)
        x1 = cx + 9 * s * math.cos(ang)
        y1 = cy + 9 * s * math.sin(ang)
        x2 = cx + 14 * s * math.cos(ang)
        y2 = cy + 14 * s * math.sin(ang)
        d.line([(x1, y1), (x2, y2)], fill=BG[:3] + (160,), width=max(1, int(s)))

    # Pupil
    pr = 7 * s
    d.ellipse([cx - pr, cy - pr, cx + pr, cy + pr], fill=(10, 10, 15, 255))

    # Pupil highlight
    hr = 2.2 * s
    hx, hy = cx + 3 * s, cy - 3 * s
    d.ellipse([hx - hr, hy - hr, hx + hr, hy + hr], fill=(255, 255, 255, 220))
    sr = 0.9 * s
    sx, sy = cx - 3 * s, cy + 3 * s
    d.ellipse([sx - sr, sy - sr, sx + sr, sy + sr], fill=GREEN + (180,))

    # Scanning arc (subtle dashed)
    arc_layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    al = ImageDraw.Draw(arc_layer)
    al.arc([28 * s, 28 * s, 172 * s, 172 * s],
           start=-90, end=0, fill=GREEN + (130,), width=max(1, int(s)))
    arc_layer = arc_layer.filter(ImageFilter.GaussianBlur(radius=0.6 * s))
    img = Image.alpha_composite(img, arc_layer)

    return img


def main():
    here = os.path.dirname(os.path.abspath(__file__))

    # PNG (high-res for marketing)
    png_path = os.path.join(here, "argus_icon.png")
    big = draw_argus(512)
    big.save(png_path, "PNG")
    print(f"  OK {png_path}  ({big.size[0]}x{big.size[1]})")

    # Profile / social
    profile_path = os.path.join(here, "argus_profile.png")
    big.resize((400, 400), Image.LANCZOS).save(profile_path, "PNG")
    print(f"  OK {profile_path}  (400x400)")

    # ICO (multi-size for Windows). PIL packs sizes from a single high-res
    # base image — we render at 256 once and let PIL downscale.
    ico_path = os.path.join(here, "argus_icon.ico")
    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    base = draw_argus(256)
    base.save(ico_path, format="ICO", sizes=sizes)
    print(f"  OK {ico_path}  (sizes: {[s[0] for s in sizes]})")

    print("\n  Argus icon assets generated.")


if __name__ == "__main__":
    main()
