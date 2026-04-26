"""
NetGuard Pro - Module Icon Generator
====================================

Generates 13 per-module icons that share the master shield silhouette and
color system but each carries its own pictorial metaphor instead of a swapped
letter.

Cohesion rules (non-negotiable):
  * Same shield silhouette as netguard_logo.svg (pentagonal, single point).
  * Same body fill, same outer ring gradient (violet -> blue -> cyan).
  * Same halo, same inner containment ring, same scan-line treatment.
  * One accent shift permitted per module (e.g. mint -> amber for HoneyPot,
    cyan -> red for StrikeBack), but never the dominant ring stops.

Output:
  modules/<slug>.svg      -- vector source per module (13 files, viewBox 0 0 100 100)
  modules/<slug>.png      -- 512x512 hero render per module (13 files)
  modules/_overview.png   -- 13-up grid + 32-px favicon strip
  modules/README.md       -- per-module rationale (separate file)

Run:
  cd D:/ComfyUI-Intel/netguard-pro-suite/branding/modules
  python _generate_modules.py
"""

from __future__ import annotations

import math
import os
import sys
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

# ---------------------------------------------------------------------------
# Import the master brand pipeline.
# We re-use shield geometry, color tokens, and the body/ring/halo composition
# so every module inherits the same silhouette and palette.
#
# Resolution order:
#   1. branding/_generate_brand.py  (source on disk, normal import)
#   2. branding/__pycache__/_generate_brand.cpython-XYZ.pyc  (cached bytecode)
# This indirection means modules/ keeps working even if the brand source is
# transiently missing (e.g. between regenerations).
# ---------------------------------------------------------------------------
HERE = Path(__file__).resolve().parent
BRAND_DIR = HERE.parent
sys.path.insert(0, str(BRAND_DIR))

try:
    from _generate_brand import (  # type: ignore  # noqa: E402
        NAVY_DEEP, NAVY_MID, INDIGO_DEEP,
        VIOLET, BLUE, CYAN, CYAN_BRIGHT, ACTIVE_GREEN,
        shield_path_units, lerp,
    )
except ModuleNotFoundError:
    import importlib.util as _ilu
    _pyc = next(
        iter((BRAND_DIR / "__pycache__").glob("_generate_brand.*.pyc")),
        None,
    )
    if _pyc is None:
        raise RuntimeError(
            "Cannot find _generate_brand.py or its .pyc. "
            "Run from a checkout where branding/_generate_brand.py exists."
        )
    _spec = _ilu.spec_from_file_location("_generate_brand", str(_pyc))
    _gb = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_gb)  # type: ignore[union-attr]
    NAVY_DEEP    = _gb.NAVY_DEEP
    NAVY_MID     = _gb.NAVY_MID
    INDIGO_DEEP  = _gb.INDIGO_DEEP
    VIOLET       = _gb.VIOLET
    BLUE         = _gb.BLUE
    CYAN         = _gb.CYAN
    CYAN_BRIGHT  = _gb.CYAN_BRIGHT
    ACTIVE_GREEN = _gb.ACTIVE_GREEN
    shield_path_units = _gb.shield_path_units
    lerp = _gb.lerp


# ---------------------------------------------------------------------------
# Module registry. Order = grid order. Each entry binds a slug to a
# human name, the metaphor we draw, and an optional accent shift.
# ---------------------------------------------------------------------------

MODULES = [
    # slug,            name,                   tagline,                          accent
    ("netguard",       "NetGuard Pro",         "Master suite",                   None),
    ("netguard-tray",  "NetGuard Tray",        "System-tray launcher",           None),
    ("netguard-ai",    "AI Assistant",         "On-device intelligence",         "violet"),
    ("mailshield",     "MailShield Pro",       "Mail threat barrier",            None),
    ("cleanguard",     "CleanGuard Pro",       "System hygiene",                 "mint"),
    ("sandbox",        "Sandbox Analyzer",     "Containment & detonation",       None),
    ("sentinel-os",    "SentinelOS",           "Watchtower / radar",             None),
    ("siem",           "SIEM Monitor",         "Event timeline",                 "mint"),
    ("vpnguard",       "VPN Guard Pro",        "Encrypted tunnel",               "violet"),
    ("recorder",       "Session Recorder",     "Capture & evidence",             "red"),
    ("honeypot",       "HoneyPot Agent",       "Lure & decoy",                   "amber"),
    ("fim",            "File Integrity",       "Hash signature watch",           None),
    ("strikeback",     "StrikeBack",           "RedTeam toolkit",                "red"),
]


# ---------------------------------------------------------------------------
# Accent palette shifts. One change per module max. These re-tint the inner
# detail (scan-line, glyph nodes) without disturbing the ring gradient, so
# the suite still reads as one family.
# ---------------------------------------------------------------------------
ACCENTS = {
    None:     {"pulse": ACTIVE_GREEN, "glyph": CYAN_BRIGHT},
    "mint":   {"pulse": ACTIVE_GREEN, "glyph": (140, 250, 200)},
    "violet": {"pulse": (180, 140, 255), "glyph": (190, 160, 255)},
    "amber":  {"pulse": (255, 192, 92),  "glyph": (255, 210, 130)},
    "red":    {"pulse": (255, 92, 92),   "glyph": (255, 140, 140)},
}


# ---------------------------------------------------------------------------
# Shared base: render the suite-wide chassis (halo, body, mesh, ring,
# inner ring) -- everything except the center metaphor + scan-line. Every
# module starts from this. Lifted from render_logo_png so the family reads
# as cohesive at a glance.
# ---------------------------------------------------------------------------

def render_chassis(size: int, accent: str | None = None,
                   show_mesh: bool = True) -> tuple[Image.Image, Image.Image, int]:
    """Render the shared shield chassis. Returns (canvas, body_mask, SS)."""

    SS = 4 if size >= 64 else 6
    W, H = size * SS, size * SS

    canvas = Image.new("RGBA", (W, H), (0, 0, 0, 0))

    body_pts_units = shield_path_units(inset=0.0)

    def to_px(p):
        return (p[0] / 100.0 * W, p[1] / 100.0 * H)

    body_pts = [to_px(p) for p in body_pts_units]

    # ---- 1. Outer halo ----
    if size >= 48:
        halo = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        ImageDraw.Draw(halo).polygon(
            [to_px(p) for p in shield_path_units(inset=-2.0)],
            fill=BLUE + (60,),
        )
        halo = halo.filter(ImageFilter.GaussianBlur(radius=W * 0.04))
        canvas = Image.alpha_composite(canvas, halo)

    # ---- 2. Body fill (radial dark gradient) ----
    body_mask = Image.new("L", (W, H), 0)
    ImageDraw.Draw(body_mask).polygon(body_pts, fill=255)

    cx_g, cy_g = 0.42 * W, 0.38 * H
    max_r = math.hypot(W, H) * 0.55
    yy, xx = np.mgrid[0:H, 0:W].astype(np.float32)
    dist = np.clip(np.hypot(xx - cx_g, yy - cy_g) / max_r, 0.0, 1.0)
    t1 = np.clip(dist / 0.5, 0.0, 1.0)
    t2 = np.clip((dist - 0.5) / 0.5, 0.0, 1.0)
    out = np.zeros((H, W, 3), dtype=np.float32)
    for ch in range(3):
        first = INDIGO_DEEP[ch] + (NAVY_MID[ch] - INDIGO_DEEP[ch]) * t1
        second = NAVY_MID[ch] + (NAVY_DEEP[ch] - NAVY_MID[ch]) * t2
        out[..., ch] = np.where(dist < 0.5, first, second)
    out = np.clip(out, 0, 255).astype(np.uint8)
    grad_arr = np.concatenate(
        [out, np.full((H, W, 1), 255, dtype=np.uint8)], axis=-1
    )
    grad = Image.fromarray(grad_arr, "RGBA")
    body_layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    body_layer.paste(grad, (0, 0), body_mask)
    canvas = Image.alpha_composite(canvas, body_layer)

    # ---- 3. Triangular mesh, clipped to body (large sizes only) ----
    if show_mesh and size >= 96:
        mesh = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        md = ImageDraw.Draw(mesh)
        spacing = W * 0.058
        line_w = max(1, int(SS * 0.6))
        for angle_deg in (0, 60, -60):
            a = math.radians(angle_deg)
            dx = math.cos(a + math.pi / 2)
            dy = math.sin(a + math.pi / 2)
            n = int(W * 1.5 / spacing)
            for i in range(-n, n + 1):
                ox, oy = dx * i * spacing, dy * i * spacing
                cxl, cyl = W / 2 + ox, H / 2 + oy
                length = W * 1.5
                md.line(
                    [(cxl + math.cos(a) * length, cyl + math.sin(a) * length),
                     (cxl - math.cos(a) * length, cyl - math.sin(a) * length)],
                    fill=CYAN_BRIGHT + (40,), width=line_w,
                )
        clipped = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        clipped.paste(mesh, (0, 0), body_mask)
        canvas = Image.alpha_composite(canvas, clipped)

    # ---- 4. Outer ring gradient ----
    ring_layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    rd = ImageDraw.Draw(ring_layer)

    def color_for_point(px_unit, py_unit):
        h = max(0.0, min(1.0, (px_unit - 18) / (82 - 18)))
        v = max(0.0, min(1.0, (py_unit - 11) / (88 - 11)))
        if h < 0.5:
            top_c = lerp(VIOLET, BLUE, h / 0.5)
        else:
            top_c = lerp(BLUE, CYAN, (h - 0.5) / 0.5)
        deep = lerp(BLUE, (28, 90, 200), 0.35)
        return lerp(top_c, deep, v ** 1.4 * 0.55)

    if size <= 32:
        stroke_w_outer = max(3, int(W * 0.045))
    elif size <= 96:
        stroke_w_outer = max(3, int(W * 0.030))
    else:
        stroke_w_outer = max(3, int(W * 0.022))

    perim = body_pts_units
    for i in range(1, len(perim)):
        x0, y0 = perim[i - 1]
        x1, y1 = perim[i]
        c = color_for_point((x0 + x1) / 2, (y0 + y1) / 2)
        rd.line([to_px((x0, y0)), to_px((x1, y1))],
                fill=c + (255,), width=stroke_w_outer)
    rd.line([to_px(perim[-1]), to_px(perim[0])],
            fill=color_for_point((perim[-1][0] + perim[0][0]) / 2,
                                 (perim[-1][1] + perim[0][1]) / 2) + (255,),
            width=stroke_w_outer)

    glow = ring_layer.filter(ImageFilter.GaussianBlur(radius=W * 0.012))
    canvas = Image.alpha_composite(canvas, Image.eval(glow, lambda v: int(v * 0.55)))
    canvas = Image.alpha_composite(canvas, ring_layer)

    # ---- 5. Inner thin containment ring ----
    if size >= 64:
        inner_pts = [to_px(p) for p in shield_path_units(inset=4.0)]
        ilay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        idl = ImageDraw.Draw(ilay)
        stroke_w_inner = max(1, int(W * 0.006))
        for i in range(1, len(inner_pts)):
            idl.line([inner_pts[i - 1], inner_pts[i]],
                     fill=CYAN_BRIGHT + (140,), width=stroke_w_inner)
        idl.line([inner_pts[-1], inner_pts[0]],
                 fill=CYAN_BRIGHT + (140,), width=stroke_w_inner)
        canvas = Image.alpha_composite(canvas, ilay)

    return canvas, body_mask, SS


def add_sheen(canvas: Image.Image, body_mask: Image.Image,
              size: int) -> Image.Image:
    """Specular bloom upper-left, clipped to body. Same as master."""
    if size < 64:
        return canvas
    W, H = canvas.size
    spec = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    spd = ImageDraw.Draw(spec)
    cx_s, cy_s = int(0.36 * W), int(0.24 * H)
    r1, r2 = int(W * 0.30), int(W * 0.18)
    spd.ellipse([cx_s - r1, cy_s - r1, cx_s + r1, cy_s + r1],
                fill=(255, 255, 255, 28))
    spd.ellipse([cx_s - r2, cy_s - r2, cx_s + r2, cy_s + r2],
                fill=(255, 255, 255, 55))
    spec = spec.filter(ImageFilter.GaussianBlur(radius=W * 0.05))
    clip = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    clip.paste(spec, (0, 0), body_mask)
    return Image.alpha_composite(canvas, clip)


# ---------------------------------------------------------------------------
# Per-module metaphor drawers. Each takes (draw, W, H, SS, accent) and paints
# its glyph in the shield's optical center (cx=50%, cy=53% in unit space,
# pulled up slightly because the rounded crown shifts perceived center).
#
# Each glyph is drawn in a 0..100 unit-space and scaled to (W, H), to keep
# the same visual weight across module sizes.
#
# Convention:
#   - The "core" glyph color is warm white (245,248,255).
#   - Secondary detail uses the accent's `glyph` color.
#   - All glyphs are bounded to a 50x44 cell centered at (50, 50) in unit
#     space so they sit comfortably inside the inner containment ring.
# ---------------------------------------------------------------------------

WHITE = (245, 248, 255)


def _u2px(W, H):
    """Return helper closure converting (x_units, y_units) -> pixels."""
    return lambda x, y: (x / 100.0 * W, y / 100.0 * H)


def _stroke_w(SS, weight: float = 1.0) -> int:
    """Pixel stroke width for a glyph line, scaled to supersample factor."""
    return max(1, int(SS * 1.6 * weight))


# --- 1. NETGUARD: stylized "N" monogram (master keeps the letter). --------
def draw_netguard(draw, W, H, SS, accent):
    """The master mark keeps the N monogram, drawn at the same optical center
    used in the brand generator."""
    # Use Segoe UI Black to match the master.
    font_path = "C:/Windows/Fonts/seguibl.ttf"
    if not os.path.exists(font_path):
        font_path = "C:/Windows/Fonts/arialbd.ttf"
    target_letter_px = int(H * 0.42)
    font = ImageFont.truetype(font_path, target_letter_px)
    bbox = draw.textbbox((0, 0), "N", font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    tx = (W - tw) / 2 - bbox[0]
    ty = (H - th) / 2 - bbox[1] + H * 0.025
    # Soft luminous backdrop
    glow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(glow).text((tx, ty), "N", font=font, fill=CYAN + (90,))
    glow = glow.filter(ImageFilter.GaussianBlur(radius=W * 0.018))
    return [glow, _text_layer(W, H, "N", font, tx, ty, WHITE)]


# --- 2. NETGUARD-TRAY: condensed mini-shield stamp -----------------------
def draw_netguard_tray(draw, W, H, SS, accent):
    """A solid mini-shield stamped into the master shield, with a single
    bold 'N' centered. Designed for system-tray rendering: at 16/24/32 px
    the inset shield reads as a strong filled silhouette and the N stays
    legible. No mesh / no dot clutter — pure tray ergonomics."""
    p = _u2px(W, H)
    # Inset shield silhouette filled with bright cyan-tinted white
    inner = shield_path_units(inset=14.0)
    pts = [p(*pt) for pt in inner]
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    # Soft cyan halo behind the inset shield to read as a luminous stamp
    halo = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(halo).polygon(
        [p(*pt) for pt in shield_path_units(inset=11.5)],
        fill=CYAN + (110,),
    )
    halo = halo.filter(ImageFilter.GaussianBlur(radius=W * 0.025))
    # Solid filled inset shield
    ld.polygon(pts, fill=(245, 248, 255, 248))
    # Thin cyan keyline for refinement
    for i in range(len(pts)):
        ld.line([pts[i], pts[(i + 1) % len(pts)]],
                fill=CYAN_BRIGHT + (200,), width=max(1, _stroke_w(SS, 0.6)))
    # Centered "N" in dark navy so it reads as a stamped logotype
    font_path = "C:/Windows/Fonts/seguibl.ttf"
    if not os.path.exists(font_path):
        font_path = "C:/Windows/Fonts/arialbd.ttf"
    target_letter_px = int(H * 0.30)
    font = ImageFont.truetype(font_path, target_letter_px)
    bbox = ld.textbbox((0, 0), "N", font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    tx = (W - tw) / 2 - bbox[0]
    ty = (H - th) / 2 - bbox[1] + H * 0.03
    ld.text((tx, ty), "N", font=font, fill=(20, 28, 56, 255))
    return [halo, layer]


# --- 3. NETGUARD-AI: 4-point sparkle / spark ----------------------------
def draw_netguard_ai(draw, W, H, SS, accent):
    """Two 4-pointed sparkles — large central, small upper-right satellite.
    Reads as 'AI / generative spark' across product surfaces (Figma, Linear,
    Notion, ChatGPT)."""
    p = _u2px(W, H)
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)

    def sparkle(cx_u, cy_u, r_u, fill, glow=True):
        # 4-point star using a diamond + small rounded body
        cx, cy = p(cx_u, cy_u)
        rx = r_u / 100.0 * W
        ry = r_u / 100.0 * H
        # Cross-shape: vertical diamond + horizontal diamond superimposed
        v_pts = [(cx, cy - ry), (cx + rx * 0.28, cy),
                 (cx, cy + ry), (cx - rx * 0.28, cy)]
        h_pts = [(cx - rx, cy), (cx, cy - ry * 0.28),
                 (cx + rx, cy), (cx, cy + ry * 0.28)]
        if glow:
            glow_l = Image.new("RGBA", (W, H), (0, 0, 0, 0))
            gd = ImageDraw.Draw(glow_l)
            gd.polygon(v_pts, fill=fill + (180,))
            gd.polygon(h_pts, fill=fill + (180,))
            glow_l = glow_l.filter(ImageFilter.GaussianBlur(radius=W * 0.02))
            yield glow_l
        ld.polygon(v_pts, fill=WHITE + (255,))
        ld.polygon(h_pts, fill=WHITE + (255,))

    glows = list(sparkle(50, 53, 18, accent["glyph"]))
    glows += list(sparkle(70, 32, 7, accent["glyph"]))
    glows += list(sparkle(34, 70, 5, accent["glyph"]))
    return glows + [layer]


# --- 4. MAILSHIELD: envelope flap inset in the shield's heart ------------
def draw_mailshield(draw, W, H, SS, accent):
    """An envelope drawn in clean linework. The triangular flap echoes the
    shield's bottom point — the metaphor is 'mail, but defended'."""
    p = _u2px(W, H)
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    sw = _stroke_w(SS, 1.4)
    # Envelope body
    rect = [p(30, 38), p(70, 38), p(70, 64), p(30, 64)]
    ld.polygon(rect, fill=None, outline=WHITE + (255,))
    # Hand-draw rectangle outline with proper stroke width
    ld.line([rect[0], rect[1]], fill=WHITE + (255,), width=sw)
    ld.line([rect[1], rect[2]], fill=WHITE + (255,), width=sw)
    ld.line([rect[2], rect[3]], fill=WHITE + (255,), width=sw)
    ld.line([rect[3], rect[0]], fill=WHITE + (255,), width=sw)
    # Flap V (apex at center)
    apex = p(50, 53)
    ld.line([rect[0], apex], fill=WHITE + (255,), width=sw)
    ld.line([rect[1], apex], fill=WHITE + (255,), width=sw)
    # Tiny seal dot where flap meets body — accent color
    sx, sy = apex
    rd = max(2, int(W * 0.014))
    ld.ellipse([sx - rd, sy - rd, sx + rd, sy + rd],
               fill=accent["glyph"] + (255,))
    return [layer]


# --- 5. CLEANGUARD: stylized broom sweep + sparkle bursts ---------------
def draw_cleanguard(draw, W, H, SS, accent):
    """A diagonal broom-sweep with a fan of bristles and three mint
    sparkles trailing the sweep direction. Heavier handle and larger
    sparkles than v1 so the metaphor reads at thumb-nail scale."""
    p = _u2px(W, H)
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    sw_thick = _stroke_w(SS, 1.9)
    sw_bristle = _stroke_w(SS, 1.6)
    # Broom handle: thicker rod, top-left to lower-right
    handle_top = p(33, 30)
    handle_bot = p(60, 60)
    ld.line([handle_top, handle_bot], fill=WHITE + (255,), width=sw_thick)
    # Brush ferrule (band where bristles attach) — small filled rect
    fx, fy = handle_bot
    band_pts = [
        (fx - W * 0.025, fy - W * 0.025),
        (fx + W * 0.060, fy + W * 0.005),
        (fx + W * 0.045, fy + W * 0.030),
        (fx - W * 0.035, fy + W * 0.005),
    ]
    ld.polygon(band_pts, fill=WHITE + (240,))
    # Bristles: a fan of 6 short lines splaying out and down
    for ang_deg in (45, 60, 78, 96, 112, 128):
        a = math.radians(ang_deg)
        L = W * 0.13
        ex = fx + math.cos(a) * L
        ey = fy + math.sin(a) * L
        ld.line([(fx + W * 0.005, fy + W * 0.018), (ex, ey)],
                fill=WHITE + (235,), width=sw_bristle)
    # Three trailing 4-point sparkles, larger and brighter
    for cx_u, cy_u, r_u in ((28, 64, 4.0), (35, 75, 3.0), (44, 80, 2.2)):
        cx, cy = p(cx_u, cy_u)
        rx = r_u / 100.0 * W
        v_pts = [(cx, cy - rx * 1.4), (cx + rx * 0.32, cy),
                 (cx, cy + rx * 1.4), (cx - rx * 0.32, cy)]
        h_pts = [(cx - rx * 1.4, cy), (cx, cy - rx * 0.32),
                 (cx + rx * 1.4, cy), (cx, cy + rx * 0.32)]
        # Soft glow under each sparkle
        glow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        gd = ImageDraw.Draw(glow)
        gd.polygon(v_pts, fill=accent["glyph"] + (180,))
        gd.polygon(h_pts, fill=accent["glyph"] + (180,))
        glow = glow.filter(ImageFilter.GaussianBlur(radius=W * 0.012))
        layer = Image.alpha_composite(layer, glow)
        ld = ImageDraw.Draw(layer)
        ld.polygon(v_pts, fill=accent["glyph"] + (255,))
        ld.polygon(h_pts, fill=accent["glyph"] + (255,))
    return [layer]


# --- 6. SANDBOX: isometric translucent containment cube ------------------
def draw_sandbox(draw, W, H, SS, accent):
    """A wireframe isometric cube — the universal 'containment / detonate
    here' icon used by every sandbox vendor (Cuckoo, Joe, ANY.RUN)."""
    p = _u2px(W, H)
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    sw = _stroke_w(SS, 1.2)
    # Isometric cube vertices in unit space
    # Top face (rhombus): centered at (50, 38)
    top_back  = p(50, 28)
    top_left  = p(34, 38)
    top_right = p(66, 38)
    top_front = p(50, 48)
    # Bottom front (only 3 visible verts of bottom face)
    bot_left  = p(34, 60)
    bot_right = p(66, 60)
    bot_front = p(50, 70)
    # Top face outline
    for a, b in ((top_back, top_left), (top_left, top_front),
                 (top_front, top_right), (top_right, top_back)):
        ld.line([a, b], fill=WHITE + (235,), width=sw)
    # Vertical edges (left/front/right)
    ld.line([top_left, bot_left], fill=WHITE + (235,), width=sw)
    ld.line([top_front, bot_front], fill=WHITE + (255,), width=sw)
    ld.line([top_right, bot_right], fill=WHITE + (235,), width=sw)
    # Bottom front edges
    ld.line([bot_left, bot_front], fill=WHITE + (235,), width=sw)
    ld.line([bot_front, bot_right], fill=WHITE + (235,), width=sw)
    # Tiny accent dot in cube center — "the suspect sample"
    cx, cy = p(50, 49)
    r = max(2, int(W * 0.018))
    ld.ellipse([cx - r, cy - r, cx + r, cy + r], fill=accent["glyph"] + (235,))
    return [layer]


# --- 7. SENTINEL-OS: radar sweep eye -------------------------------------
def draw_sentinel_os(draw, W, H, SS, accent):
    """A radar dial with a sweeping wedge. The wedge is the watchtower
    metaphor without literal architecture — works at every scale."""
    p = _u2px(W, H)
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    sw = _stroke_w(SS, 1.0)
    cx_u, cy_u = 50, 53
    cx, cy = p(cx_u, cy_u)
    # Concentric arcs (3 rings)
    for r_u in (8, 13, 18):
        r = r_u / 100.0 * W
        ld.ellipse([cx - r, cy - r, cx + r, cy + r],
                   outline=WHITE + (200,), width=sw)
    # Cross-hair
    ld.line([(cx - 18 / 100.0 * W, cy), (cx + 18 / 100.0 * W, cy)],
            fill=WHITE + (140,), width=max(1, sw - 1))
    ld.line([(cx, cy - 18 / 100.0 * W), (cx, cy + 18 / 100.0 * W)],
            fill=WHITE + (140,), width=max(1, sw - 1))
    # Sweep wedge: filled triangular sector from center to upper-right
    sweep_r = 18 / 100.0 * W
    a0 = math.radians(-90)        # 12 o'clock
    a1 = math.radians(-30)        # ~2 o'clock
    wedge_pts = [(cx, cy)]
    for k in range(20):
        t = k / 19
        a = a0 + (a1 - a0) * t
        wedge_pts.append((cx + math.cos(a) * sweep_r,
                          cy + math.sin(a) * sweep_r))
    wd = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(wd).polygon(wedge_pts, fill=accent["glyph"] + (170,))
    wd = wd.filter(ImageFilter.GaussianBlur(radius=W * 0.005))
    # Bright leading-edge line of the sweep
    ld.line([(cx, cy),
             (cx + math.cos(a1) * sweep_r, cy + math.sin(a1) * sweep_r)],
            fill=accent["glyph"] + (255,), width=sw)
    # Center dot
    r = max(2, int(W * 0.012))
    ld.ellipse([cx - r, cy - r, cx + r, cy + r], fill=WHITE + (255,))
    return [wd, layer]


# --- 8. SIEM: heartbeat / event timeline pulse ---------------------------
def draw_siem(draw, W, H, SS, accent):
    """An ECG-style pulse line crossing the shield. The exact visual a SOC
    analyst lives in — fits the 'timeline of events' role of SIEM."""
    p = _u2px(W, H)
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    sw = _stroke_w(SS, 1.4)
    base_y = 53
    # Polyline pattern: flat-flat-up-down-up-flat
    pulse = [
        (24, base_y), (36, base_y),
        (40, base_y - 12), (44, base_y + 14),
        (48, base_y - 6),  (52, base_y),
        (60, base_y), (64, base_y - 8),
        (68, base_y + 4), (76, base_y),
    ]
    pts = [p(*pt) for pt in pulse]
    for i in range(1, len(pts)):
        ld.line([pts[i - 1], pts[i]], fill=accent["glyph"] + (255,), width=sw)
    # Two end dots (suggest "begin / end of trace")
    for px, py in (pts[0], pts[-1]):
        r = max(2, int(W * 0.018))
        ld.ellipse([px - r, py - r, px + r, py + r], fill=WHITE + (255,))
    return [layer]


# --- 9. VPNGUARD: tunnel + chain link ------------------------------------
def draw_vpnguard(draw, W, H, SS, accent):
    """A horizontal tunnel arch with a centered chain-link inside. Reads as
    'enclosed passage with a locked link' — i.e. encrypted tunnel."""
    p = _u2px(W, H)
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    sw = _stroke_w(SS, 1.3)
    # Tunnel: a tall rounded arch
    # Outer arch
    outer_box = [p(28, 36)[0], p(28, 36)[1], p(72, 70)[0], p(72, 70)[1]]
    ld.arc(outer_box, start=180, end=0, fill=WHITE + (220,), width=sw)
    ld.line([p(28, 53), p(28, 70)], fill=WHITE + (220,), width=sw)
    ld.line([p(72, 53), p(72, 70)], fill=WHITE + (220,), width=sw)
    ld.line([p(28, 70), p(72, 70)], fill=WHITE + (220,), width=sw)
    # Inner arch — depth cue
    inner_box = [p(36, 44)[0], p(36, 44)[1], p(64, 70)[0], p(64, 70)[1]]
    ld.arc(inner_box, start=180, end=0, fill=WHITE + (140,), width=max(1, sw - 1))
    ld.line([p(36, 57), p(36, 70)], fill=WHITE + (140,), width=max(1, sw - 1))
    ld.line([p(64, 57), p(64, 70)], fill=WHITE + (140,), width=max(1, sw - 1))
    # Chain-link (two interlocked rings) centered in tunnel mouth
    link_r = W * 0.045
    cx1, cy1 = p(46, 56)
    cx2, cy2 = p(54, 56)
    ld.ellipse([cx1 - link_r, cy1 - link_r, cx1 + link_r, cy1 + link_r],
               outline=accent["glyph"] + (255,), width=sw)
    ld.ellipse([cx2 - link_r, cy2 - link_r, cx2 + link_r, cy2 + link_r],
               outline=accent["glyph"] + (255,), width=sw)
    return [layer]


# --- 10. RECORDER: red record dot + concentric ring ----------------------
def draw_recorder(draw, W, H, SS, accent):
    """The universal red record dot with a concentric capture-ring around
    it. Anyone who has ever clicked 'record' will recognize this in one
    glance."""
    p = _u2px(W, H)
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    sw = _stroke_w(SS, 1.3)
    cx, cy = p(50, 53)
    # Outer capture ring
    r_outer = W * 0.18
    ld.ellipse([cx - r_outer, cy - r_outer, cx + r_outer, cy + r_outer],
               outline=WHITE + (200,), width=sw)
    # Solid red record dot, slightly glowing
    r_dot = W * 0.10
    glow_l = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow_l)
    gd.ellipse([cx - r_dot * 1.6, cy - r_dot * 1.6,
                cx + r_dot * 1.6, cy + r_dot * 1.6],
               fill=accent["pulse"] + (140,))
    glow_l = glow_l.filter(ImageFilter.GaussianBlur(radius=W * 0.02))
    ld.ellipse([cx - r_dot, cy - r_dot, cx + r_dot, cy + r_dot],
               fill=accent["pulse"] + (255,))
    # Tiny inner highlight
    rh = r_dot * 0.45
    ld.ellipse([cx - rh - W * 0.02, cy - rh - W * 0.02,
                cx - W * 0.02, cy - W * 0.02],
               fill=(255, 220, 220, 200))
    return [glow_l, layer]


# --- 11. HONEYPOT: hexagonal honeycomb cell + drip ----------------------
def draw_honeypot(draw, W, H, SS, accent):
    """A single hexagonal honeycomb cell with a stylized drop hanging below.
    Cleaner than a literal jar, scales to 16px, instantly says 'honey =
    bait'."""
    p = _u2px(W, H)
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    sw = _stroke_w(SS, 1.3)
    # Hexagonal honeycomb cell, flat-top
    cx_u, cy_u = 50, 47
    r_u = 14
    hex_pts = []
    for i in range(6):
        a = math.radians(60 * i + 30)  # flat-top
        hex_pts.append(p(cx_u + r_u * math.cos(a), cy_u + r_u * math.sin(a)))
    # Filled amber center — fuller saturation so it doesn't read as muddy
    # against the indigo body.
    fill_l = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    fd = ImageDraw.Draw(fill_l)
    fd.polygon(hex_pts, fill=accent["glyph"] + (200,))
    # Inner amber-glow on the hex face for "honey luminance"
    bloom = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    bd = ImageDraw.Draw(bloom)
    bd.polygon(hex_pts, fill=accent["pulse"] + (130,))
    bloom = bloom.filter(ImageFilter.GaussianBlur(radius=W * 0.025))
    # Subtle inner echo hex (hint of comb structure)
    inner_hex = []
    for i in range(6):
        a = math.radians(60 * i + 30)
        inner_hex.append(p(cx_u + (r_u * 0.55) * math.cos(a),
                           cy_u + (r_u * 0.55) * math.sin(a)))
    fd.polygon(inner_hex, fill=accent["pulse"] + (90,))
    # Hex outline (warm amber)
    for i in range(6):
        ld.line([hex_pts[i], hex_pts[(i + 1) % 6]],
                fill=accent["glyph"] + (255,), width=sw)
    # Honey drop hanging from bottom vertex
    drop_top = p(cx_u, cy_u + r_u + 1)
    drop_mid = p(cx_u, cy_u + r_u + 12)
    drop_btm = p(cx_u, cy_u + r_u + 18)
    drop_l = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    dd = ImageDraw.Draw(drop_l)
    # Tear-shape: triangle on top, half-circle on bottom
    drop_pts = [drop_top,
                (drop_top[0] - W * 0.04, drop_mid[1]),
                (drop_top[0] + W * 0.04, drop_mid[1])]
    dd.polygon(drop_pts, fill=accent["glyph"] + (235,))
    rb = W * 0.04
    dd.ellipse([drop_mid[0] - rb, drop_mid[1] - rb,
                drop_mid[0] + rb, drop_btm[1]],
               fill=accent["glyph"] + (235,))
    # Tiny gloss highlight on drop
    dd.ellipse([drop_mid[0] - rb * 0.3, drop_mid[1] + rb * 0.2,
                drop_mid[0] + rb * 0.1, drop_mid[1] + rb * 0.6],
               fill=(255, 245, 200, 255))
    return [bloom, fill_l, drop_l, layer]


# --- 12. FIM: document with a hash signature wave -----------------------
def draw_fim(draw, W, H, SS, accent):
    """A document silhouette with a folded corner and a hash 'signature'
    wave running across it. Communicates 'file + integrity = unchanged
    fingerprint'."""
    p = _u2px(W, H)
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    sw = _stroke_w(SS, 1.3)
    # Document body with folded top-right corner
    corner_in_x, corner_in_y = 64, 38
    fold_size = 8
    doc_pts = [p(34, 32), p(corner_in_x - fold_size, 32),
               p(corner_in_x, corner_in_y),
               p(66, 70), p(34, 70)]
    # Subtle fill
    fill_l = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(fill_l).polygon(doc_pts, fill=(20, 28, 56, 220))
    # Outline
    for i in range(len(doc_pts)):
        ld.line([doc_pts[i], doc_pts[(i + 1) % len(doc_pts)]],
                fill=WHITE + (235,), width=sw)
    # Folded corner triangle
    fold_pts = [p(corner_in_x - fold_size, 32),
                p(corner_in_x - fold_size, 32 + fold_size),
                p(corner_in_x, corner_in_y)]
    ld.line([fold_pts[0], fold_pts[1]], fill=WHITE + (200,), width=sw)
    ld.line([fold_pts[1], fold_pts[2]], fill=WHITE + (200,), width=sw)
    # Hash "signature" — sine-like wave drawn as polyline. Thicker and
    # backed by a soft cyan glow so the integrity-fingerprint reads
    # immediately even in the overview thumbnail.
    sig_y = 58
    sig_pts = []
    for k in range(60):
        t = k / 59
        x = 38 + 24 * t
        y = sig_y + 5.0 * math.sin(t * math.pi * 4.0)
        sig_pts.append(p(x, y))
    sw_sig = _stroke_w(SS, 1.8)
    glow_l = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow_l)
    for i in range(1, len(sig_pts)):
        gd.line([sig_pts[i - 1], sig_pts[i]],
                fill=accent["glyph"] + (200,), width=sw_sig + 2)
    glow_l = glow_l.filter(ImageFilter.GaussianBlur(radius=W * 0.010))
    for i in range(1, len(sig_pts)):
        ld.line([sig_pts[i - 1], sig_pts[i]],
                fill=accent["glyph"] + (255,), width=sw_sig)
    # Two short text-line bars above the wave to suggest 'file content'
    for y_u in (44, 49):
        ld.line([p(40, y_u), p(60, y_u)],
                fill=WHITE + (160,), width=max(1, sw - 1))
    return [fill_l, glow_l, layer]


# --- 13. STRIKEBACK: lightning bolt + crosshair reticle ------------------
def draw_strikeback(draw, W, H, SS, accent):
    """A targeting reticle with a lightning bolt striking through. Red-team
    aggression in a single glance — 'we can hit back, here is the target'.
    The bolt is rendered as a single closed polygon with a soft red bloom
    underneath for a glowing-strike feel."""
    p = _u2px(W, H)
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    sw = _stroke_w(SS, 1.2)
    cx, cy = p(50, 53)
    # Reticle: 2 concentric rings + 4 cardinal tick marks
    r_outer = W * 0.18
    r_inner = W * 0.10
    ld.ellipse([cx - r_outer, cy - r_outer, cx + r_outer, cy + r_outer],
               outline=WHITE + (220,), width=sw)
    ld.ellipse([cx - r_inner, cy - r_inner, cx + r_inner, cy + r_inner],
               outline=WHITE + (180,), width=max(1, sw - 1))
    tick_in = r_outer + W * 0.012
    tick_out = r_outer + W * 0.05
    for ang_deg in (0, 90, 180, 270):
        a = math.radians(ang_deg)
        ld.line([(cx + math.cos(a) * tick_in, cy + math.sin(a) * tick_in),
                 (cx + math.cos(a) * tick_out, cy + math.sin(a) * tick_out)],
                fill=WHITE + (220,), width=sw)
    # Lightning bolt: a single closed polygon shaped like a clean Z.
    # Path walks: top-right -> outer top -> mid-left dip -> mid-right kick
    #            -> bottom point -> mirror back up.
    bolt = [
        p(58.5, 33.0),   # outer top
        p(63.0, 35.5),
        p(53.0, 50.5),
        p(60.5, 50.5),
        p(62.5, 53.0),
        p(48.0, 73.5),   # outer bottom point
        p(43.0, 71.5),
        p(50.5, 56.5),
        p(43.5, 56.5),
        p(41.5, 53.5),
    ]
    glow_l = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(glow_l).polygon(bolt, fill=accent["pulse"] + (160,))
    glow_l = glow_l.filter(ImageFilter.GaussianBlur(radius=W * 0.018))
    ld.polygon(bolt, fill=accent["pulse"] + (255,),
               outline=(255, 255, 255, 235))
    return [glow_l, layer]


# ---------------------------------------------------------------------------
# Glyph dispatcher
# ---------------------------------------------------------------------------

GLYPH_DRAWERS = {
    "netguard":      draw_netguard,
    "netguard-tray": draw_netguard_tray,
    "netguard-ai":   draw_netguard_ai,
    "mailshield":    draw_mailshield,
    "cleanguard":    draw_cleanguard,
    "sandbox":       draw_sandbox,
    "sentinel-os":   draw_sentinel_os,
    "siem":          draw_siem,
    "vpnguard":      draw_vpnguard,
    "recorder":      draw_recorder,
    "honeypot":      draw_honeypot,
    "fim":           draw_fim,
    "strikeback":    draw_strikeback,
}


def _text_layer(W, H, text, font, x, y, color):
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(layer).text((x, y), text, font=font, fill=color + (255,))
    return layer


# ---------------------------------------------------------------------------
# Public API: render_module_icon
# ---------------------------------------------------------------------------

def _accent_for(slug: str) -> dict:
    for s, _, _, a in MODULES:
        if s == slug:
            return ACCENTS[a]
    return ACCENTS[None]


def render_module_icon(slug: str, size: int) -> Image.Image:
    """Render a module icon at `size` x `size` with transparent background.

    The chassis (silhouette, body, ring, halo, mesh, inner ring, sheen) is
    identical across modules. Only the center metaphor + scan-line accent
    change. Same LOD ladder as the master.
    """
    if slug not in GLYPH_DRAWERS:
        raise KeyError(f"Unknown module slug: {slug}")
    accent = _accent_for(slug)

    # Tray icon: special-case — strip mesh and inner ring so the silhouette
    # carries at 16/24px without clutter (it's literally a tray-bar mark).
    show_mesh = slug != "netguard-tray"

    canvas, body_mask, SS = render_chassis(size, show_mesh=show_mesh)
    W, H = canvas.size
    draw = ImageDraw.Draw(canvas)

    # Module-specific scan-line color (every module shows a faint scan line
    # at >= 96px for family cohesion, but it picks up the module's accent).
    if size >= 96:
        scan_layer = _draw_scan_line(W, H, SS, accent["pulse"])
        canvas = Image.alpha_composite(canvas, scan_layer)

    # Glyph
    glyph_layers = GLYPH_DRAWERS[slug](draw, W, H, SS, accent)
    for g in glyph_layers:
        canvas = Image.alpha_composite(canvas, g)

    # Top sheen bloom
    canvas = add_sheen(canvas, body_mask, size)

    return canvas.resize((size, size), Image.LANCZOS)


def _draw_scan_line(W, H, SS, pulse_color):
    """Module-tinted version of the scan line. Same geometry as the master."""
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    sd = ImageDraw.Draw(layer)
    inner_pts = shield_path_units(inset=4.0)
    target_y_units = 35.5
    xs = []
    for i in range(1, len(inner_pts)):
        x0, y0 = inner_pts[i - 1]
        x1, y1 = inner_pts[i]
        if (y0 - target_y_units) * (y1 - target_y_units) < 0:
            t = (target_y_units - y0) / (y1 - y0)
            xs.append(x0 + t * (x1 - x0))
    if len(xs) < 2:
        return layer
    scan_y = target_y_units / 100 * H
    x_left = min(xs) / 100 * W
    x_right = max(xs) / 100 * W
    n_seg = 60
    for k in range(n_seg):
        t0, t1 = k / n_seg, (k + 1) / n_seg
        x0_seg = x_left + (x_right - x_left) * t0 + W * 0.005
        x1_seg = x_left + (x_right - x_left) * t1 - W * 0.005
        mid_t = (t0 + t1) / 2
        curve = 1 - 4 * (mid_t - 0.5) ** 2
        a = int(180 - 100 * curve)
        sd.line([(x0_seg, scan_y), (x1_seg, scan_y)],
                fill=pulse_color + (a,), width=max(1, int(SS * 0.7)))
    node_r = max(2, int(W * 0.009))
    for nx in (x_left, x_right):
        sd.ellipse([nx - node_r * 3, scan_y - node_r * 3,
                    nx + node_r * 3, scan_y + node_r * 3],
                   fill=pulse_color + (60,))
        sd.ellipse([nx - node_r * 1.6, scan_y - node_r * 1.6,
                    nx + node_r * 1.6, scan_y + node_r * 1.6],
                   fill=pulse_color + (180,))
        sd.ellipse([nx - node_r, scan_y - node_r, nx + node_r, scan_y + node_r],
                   fill=(235, 255, 245, 255))
    return layer


# ---------------------------------------------------------------------------
# SVG export per module. Produces the shield chassis (matched to master) plus
# a slug-specific <g id="glyph"> block. Geometry is hand-crafted in unit space
# so the SVG is human-editable.
# ---------------------------------------------------------------------------

def _svg_chassis_prefix(accent_pulse):
    """Open <svg> + defs + halo + body + mesh + ring + inner ring."""
    body_pts = shield_path_units(inset=0.0)
    inner_pts = shield_path_units(inset=4.0)

    def path_d(points):
        d = f"M {points[0][0]:.3f} {points[0][1]:.3f} "
        for x, y in points[1:]:
            d += f"L {x:.3f} {y:.3f} "
        return d + "Z"

    body_d = path_d(body_pts)
    inner_d = path_d(inner_pts)

    # Scan line endpoints
    scan_y_units = 35.5
    xs = []
    for i in range(1, len(inner_pts)):
        x0, y0 = inner_pts[i - 1]
        x1, y1 = inner_pts[i]
        if (y0 - scan_y_units) * (y1 - scan_y_units) < 0:
            t = (scan_y_units - y0) / (y1 - y0)
            xs.append(x0 + t * (x1 - x0))
    x_left = min(xs) if xs else 25
    x_right = max(xs) if xs else 75

    pr, pg, pb = accent_pulse

    return body_d, inner_d, x_left, x_right, scan_y_units, (pr, pg, pb)


def render_module_svg(slug: str) -> str:
    accent = _accent_for(slug)
    body_d, inner_d, x_left, x_right, scan_y, pulse_rgb = _svg_chassis_prefix(
        accent["pulse"])
    glyph_svg = _svg_glyph_for(slug, accent)

    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="1024" height="1024">
  <defs>
    <radialGradient id="bodyGrad" cx="42%" cy="38%" r="65%">
      <stop offset="0%"  stop-color="rgb({INDIGO_DEEP[0]},{INDIGO_DEEP[1]},{INDIGO_DEEP[2]})"/>
      <stop offset="55%" stop-color="rgb({NAVY_MID[0]},{NAVY_MID[1]},{NAVY_MID[2]})"/>
      <stop offset="100%" stop-color="rgb({NAVY_DEEP[0]},{NAVY_DEEP[1]},{NAVY_DEEP[2]})"/>
    </radialGradient>
    <linearGradient id="ringGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%"   stop-color="rgb({VIOLET[0]},{VIOLET[1]},{VIOLET[2]})"/>
      <stop offset="50%"  stop-color="rgb({BLUE[0]},{BLUE[1]},{BLUE[2]})"/>
      <stop offset="100%" stop-color="rgb({CYAN[0]},{CYAN[1]},{CYAN[2]})"/>
    </linearGradient>
    <filter id="softGlow" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="0.6"/>
    </filter>
    <filter id="ringHalo" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="1.2"/>
    </filter>
    <clipPath id="shieldClip"><path d="{body_d}"/></clipPath>
  </defs>

  <!-- halo -->
  <path d="{body_d}" fill="rgb({BLUE[0]},{BLUE[1]},{BLUE[2]})" fill-opacity="0.25"
        filter="url(#ringHalo)" transform="scale(1.04) translate(-2 -2.1)"/>
  <!-- body -->
  <path d="{body_d}" fill="url(#bodyGrad)"/>
  <!-- ring -->
  <path d="{body_d}" fill="none" stroke="url(#ringGrad)" stroke-width="2.2"
        filter="url(#softGlow)" stroke-linejoin="round"/>
  <path d="{body_d}" fill="none" stroke="url(#ringGrad)" stroke-width="2.2"
        stroke-linejoin="round"/>
  <!-- inner ring -->
  <path d="{inner_d}" fill="none" stroke="rgb({CYAN_BRIGHT[0]},{CYAN_BRIGHT[1]},{CYAN_BRIGHT[2]})"
        stroke-width="0.55" stroke-opacity="0.55" stroke-linejoin="round"/>
  <!-- scan line -->
  <g>
    <line x1="{x_left + 0.5:.2f}" y1="{scan_y}" x2="{x_right - 0.5:.2f}" y2="{scan_y}"
          stroke="rgb({pulse_rgb[0]},{pulse_rgb[1]},{pulse_rgb[2]})"
          stroke-width="0.42" stroke-opacity="0.85"/>
    <circle cx="{x_left:.2f}" cy="{scan_y}" r="1.2"
            fill="rgb({pulse_rgb[0]},{pulse_rgb[1]},{pulse_rgb[2]})" fill-opacity="0.4"/>
    <circle cx="{x_left:.2f}" cy="{scan_y}" r="0.55" fill="white"/>
    <circle cx="{x_right:.2f}" cy="{scan_y}" r="1.2"
            fill="rgb({pulse_rgb[0]},{pulse_rgb[1]},{pulse_rgb[2]})" fill-opacity="0.4"/>
    <circle cx="{x_right:.2f}" cy="{scan_y}" r="0.55" fill="white"/>
  </g>

  <!-- module glyph -->
  <g id="glyph">
{glyph_svg}
  </g>

  <!-- top sheen -->
  <g clip-path="url(#shieldClip)">
    <rect x="0" y="0" width="100" height="48" fill="white" fill-opacity="0.05"/>
  </g>
</svg>
"""


def _rgb(c):
    return f"rgb({c[0]},{c[1]},{c[2]})"


def _svg_glyph_for(slug: str, accent: dict) -> str:
    g = accent["glyph"]
    p = accent["pulse"]
    if slug == "netguard":
        return ('    <text x="50" y="68" font-family="\'Segoe UI\',\'Helvetica Neue\',Arial,sans-serif"'
                ' font-weight="900" font-size="42" text-anchor="middle"'
                ' fill="rgb(245,248,255)">N</text>')
    if slug == "netguard-tray":
        # inset sub-shield with cyan keyline + centered N
        inner = shield_path_units(inset=14.0)
        d = "M " + " L ".join(f"{x:.2f} {y:.2f}" for x, y in inner) + " Z"
        return (f'    <path d="{d}" fill="rgb(245,248,255)" fill-opacity="0.97"'
                f' stroke="{_rgb(CYAN_BRIGHT)}" stroke-opacity="0.78" stroke-width="0.9"/>\n'
                f'    <text x="50" y="63" font-family="\'Segoe UI\',\'Helvetica Neue\',Arial,sans-serif"'
                f' font-weight="900" font-size="30" text-anchor="middle"'
                f' fill="rgb(20,28,56)">N</text>')
    if slug == "netguard-ai":
        def sparkle(cx, cy, r):
            return (f'<polygon points="{cx},{cy - r * 1.4} {cx + r * 0.3},{cy} '
                    f'{cx},{cy + r * 1.4} {cx - r * 0.3},{cy}" fill="rgb(245,248,255)"/>'
                    f'<polygon points="{cx - r * 1.4},{cy} {cx},{cy - r * 0.3} '
                    f'{cx + r * 1.4},{cy} {cx},{cy + r * 0.3}" fill="rgb(245,248,255)"/>')
        return (f'    {sparkle(50, 53, 18)}\n'
                f'    {sparkle(70, 32, 7)}\n'
                f'    {sparkle(34, 70, 5)}')
    if slug == "mailshield":
        return (f'    <rect x="30" y="38" width="40" height="26" fill="none"'
                f' stroke="rgb(245,248,255)" stroke-width="1.6" stroke-linejoin="round"/>\n'
                f'    <polyline points="30,38 50,53 70,38" fill="none"'
                f' stroke="rgb(245,248,255)" stroke-width="1.6" stroke-linejoin="round"/>\n'
                f'    <circle cx="50" cy="53" r="1.6" fill="{_rgb(g)}"/>')
    if slug == "cleanguard":
        return (
            '    <line x1="34" y1="30" x2="58" y2="60" stroke="rgb(245,248,255)" stroke-width="1.5" stroke-linecap="round"/>\n'
            '    <g stroke="rgb(245,248,255)" stroke-width="1.5" stroke-linecap="round">\n'
            '      <line x1="58" y1="60" x2="66" y2="65"/>\n'
            '      <line x1="58" y1="60" x2="64" y2="70"/>\n'
            '      <line x1="58" y1="60" x2="58" y2="73"/>\n'
            '      <line x1="58" y1="60" x2="51" y2="71"/>\n'
            '      <line x1="58" y1="60" x2="46" y2="68"/>\n'
            '    </g>\n'
            f'    <g fill="{_rgb(g)}">\n'
            '      <polygon points="28,62 28.7,65 31.4,65 28.7,67 28,70 27.3,67 24.6,65 27.3,65"/>\n'
            '      <polygon points="35,73 35.5,75 37.4,75 35.5,77 35,79 34.5,77 32.6,75 34.5,75"/>\n'
            '      <polygon points="44,77 44.4,78.5 45.8,78.5 44.4,80 44,81.5 43.6,80 42.2,78.5 43.6,78.5"/>\n'
            '    </g>'
        )
    if slug == "sandbox":
        return (
            '    <g fill="none" stroke="rgb(245,248,255)" stroke-width="1.4" stroke-linejoin="round">\n'
            '      <polygon points="50,28 66,38 50,48 34,38"/>\n'
            '      <line x1="34" y1="38" x2="34" y2="60"/>\n'
            '      <line x1="50" y1="48" x2="50" y2="70"/>\n'
            '      <line x1="66" y1="38" x2="66" y2="60"/>\n'
            '      <line x1="34" y1="60" x2="50" y2="70"/>\n'
            '      <line x1="50" y1="70" x2="66" y2="60"/>\n'
            '    </g>\n'
            f'    <circle cx="50" cy="49" r="2" fill="{_rgb(g)}"/>'
        )
    if slug == "sentinel-os":
        return (
            '    <g fill="none" stroke="rgb(245,248,255)" stroke-width="1.0">\n'
            '      <circle cx="50" cy="53" r="8"/>\n'
            '      <circle cx="50" cy="53" r="13"/>\n'
            '      <circle cx="50" cy="53" r="18"/>\n'
            '      <line x1="32" y1="53" x2="68" y2="53" stroke-opacity="0.55"/>\n'
            '      <line x1="50" y1="35" x2="50" y2="71" stroke-opacity="0.55"/>\n'
            '    </g>\n'
            f'    <path d="M 50 53 L 50 35 A 18 18 0 0 1 65.6 44 Z" fill="{_rgb(g)}" fill-opacity="0.45"/>\n'
            f'    <line x1="50" y1="53" x2="65.6" y2="44" stroke="{_rgb(g)}" stroke-width="1.2"/>\n'
            '    <circle cx="50" cy="53" r="1.5" fill="rgb(245,248,255)"/>'
        )
    if slug == "siem":
        return (
            f'    <polyline points="24,53 36,53 40,41 44,67 48,47 52,53 60,53 64,45 68,57 76,53" '
            f'fill="none" stroke="{_rgb(g)}" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round"/>\n'
            '    <circle cx="24" cy="53" r="1.8" fill="rgb(245,248,255)"/>\n'
            '    <circle cx="76" cy="53" r="1.8" fill="rgb(245,248,255)"/>'
        )
    if slug == "vpnguard":
        return (
            '    <g fill="none" stroke="rgb(245,248,255)" stroke-width="1.5" stroke-linecap="round">\n'
            '      <path d="M 28 53 A 22 22 0 0 1 72 53"/>\n'
            '      <line x1="28" y1="53" x2="28" y2="70"/>\n'
            '      <line x1="72" y1="53" x2="72" y2="70"/>\n'
            '      <line x1="28" y1="70" x2="72" y2="70"/>\n'
            '    </g>\n'
            '    <g fill="none" stroke="rgb(245,248,255)" stroke-opacity="0.55" stroke-width="1.1">\n'
            '      <path d="M 36 57 A 14 14 0 0 1 64 57"/>\n'
            '      <line x1="36" y1="57" x2="36" y2="70"/>\n'
            '      <line x1="64" y1="57" x2="64" y2="70"/>\n'
            '    </g>\n'
            f'    <circle cx="46" cy="56" r="4.5" fill="none" stroke="{_rgb(g)}" stroke-width="1.5"/>\n'
            f'    <circle cx="54" cy="56" r="4.5" fill="none" stroke="{_rgb(g)}" stroke-width="1.5"/>'
        )
    if slug == "recorder":
        return (
            '    <circle cx="50" cy="53" r="18" fill="none" stroke="rgb(245,248,255)" stroke-width="1.4"/>\n'
            f'    <circle cx="50" cy="53" r="10" fill="{_rgb(p)}"/>\n'
            '    <circle cx="46" cy="49" r="3" fill="rgb(255,220,220)" fill-opacity="0.7"/>'
        )
    if slug == "honeypot":
        # Hex flat-top
        pts = []
        for i in range(6):
            a = math.radians(60 * i + 30)
            pts.append((50 + 14 * math.cos(a), 47 + 14 * math.sin(a)))
        hex_d = " ".join(f"{x:.2f},{y:.2f}" for x, y in pts)
        # inner echo hex (comb hint)
        inner = []
        for i in range(6):
            a = math.radians(60 * i + 30)
            inner.append((50 + 14 * 0.55 * math.cos(a),
                          47 + 14 * 0.55 * math.sin(a)))
        inner_d = " ".join(f"{x:.2f},{y:.2f}" for x, y in inner)
        return (
            f'    <polygon points="{hex_d}" fill="{_rgb(g)}" fill-opacity="0.78"'
            f' stroke="{_rgb(g)}" stroke-width="1.5" stroke-linejoin="round"/>\n'
            f'    <polygon points="{inner_d}" fill="{_rgb(p)}" fill-opacity="0.35"/>\n'
            f'    <path d="M 50 62 L 46 70 A 4 4 0 1 0 54 70 Z" fill="{_rgb(g)}"/>\n'
            '    <ellipse cx="49" cy="71" rx="1.2" ry="2" fill="rgb(255,245,200)" fill-opacity="0.85"/>'
        )
    if slug == "fim":
        # document with fold + sig wave
        sig = []
        for k in range(28):
            t = k / 27
            x = 38 + 24 * t
            y = 56 + 4.5 * math.sin(t * math.pi * 4.0)
            sig.append((x, y))
        sig_d = " ".join(f"{x:.2f},{y:.2f}" for x, y in sig)
        return (
            '    <path d="M 34 32 L 56 32 L 64 40 L 64 70 L 34 70 Z" fill="rgb(20,28,56)" fill-opacity="0.86" stroke="rgb(245,248,255)" stroke-width="1.5" stroke-linejoin="round"/>\n'
            '    <polyline points="56,32 56,40 64,40" fill="none" stroke="rgb(245,248,255)" stroke-opacity="0.65" stroke-width="1.4"/>\n'
            '    <line x1="40" y1="44" x2="60" y2="44" stroke="rgb(245,248,255)" stroke-opacity="0.55" stroke-width="1.0"/>\n'
            '    <line x1="40" y1="48" x2="60" y2="48" stroke="rgb(245,248,255)" stroke-opacity="0.55" stroke-width="1.0"/>\n'
            f'    <polyline points="{sig_d}" fill="none" stroke="{_rgb(g)}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>'
        )
    if slug == "strikeback":
        bolt = "58.5,33 63,35.5 53,50.5 60.5,50.5 62.5,53 48,73.5 43,71.5 50.5,56.5 43.5,56.5 41.5,53.5"
        return (
            '    <g fill="none" stroke="rgb(245,248,255)" stroke-width="1.4">\n'
            '      <circle cx="50" cy="53" r="18"/>\n'
            '      <circle cx="50" cy="53" r="10" stroke-opacity="0.7"/>\n'
            '      <line x1="50" y1="33" x2="50" y2="29"/>\n'
            '      <line x1="50" y1="73" x2="50" y2="77"/>\n'
            '      <line x1="30" y1="53" x2="26" y2="53"/>\n'
            '      <line x1="70" y1="53" x2="74" y2="53"/>\n'
            '    </g>\n'
            f'    <polygon points="{bolt}" fill="{_rgb(p)}" stroke="rgb(245,248,255)" stroke-width="0.5" stroke-linejoin="round"/>'
        )
    return ""


# ---------------------------------------------------------------------------
# Overview grid: 13 modules at hero size + a 32-px favicon strip below.
# ---------------------------------------------------------------------------

def render_overview() -> Image.Image:
    cell = 280
    pad = 32
    label_h = 78

    # Layout: 5 columns x 3 rows (last row has 3 cells -> 2 empty)
    cols, rows = 5, 3
    grid_W = pad + cols * cell + (cols - 1) * pad + pad
    grid_H = pad + rows * (cell + label_h) + (rows - 1) * pad + pad

    header_h = 130
    strip_h = 200

    W = grid_W
    H = header_h + grid_H + strip_h

    bg = (15, 15, 19, 255)
    canvas = Image.new("RGBA", (W, H), bg)

    # Subtle dot lattice
    dots = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    dd = ImageDraw.Draw(dots)
    for y in range(0, H, 28):
        for x in range(0, W, 28):
            dd.point((x, y), fill=(255, 255, 255, 14))
    canvas = Image.alpha_composite(canvas, dots)

    draw = ImageDraw.Draw(canvas)

    head_font = ImageFont.truetype("C:/Windows/Fonts/seguibl.ttf", 30)
    sub_font = ImageFont.truetype("C:/Windows/Fonts/segoeuil.ttf", 14)
    label_font = ImageFont.truetype("C:/Windows/Fonts/seguibl.ttf", 17)
    cap_font = ImageFont.truetype("C:/Windows/Fonts/segoeuil.ttf", 12)
    scale_label_font = ImageFont.truetype("C:/Windows/Fonts/segoeuil.ttf", 11)

    # Header
    draw.text((pad, 38), "NetGuard Pro Suite",
              font=head_font, fill=(245, 248, 255, 255))
    draw.text((pad, 80),
              "Module marks  /  shared shield, distinct metaphor  /  13-up overview",
              font=sub_font, fill=(150, 158, 178, 255))
    meta = "v1.0  -  module sheet"
    mb = draw.textbbox((0, 0), meta, font=sub_font)
    draw.text((W - pad - (mb[2] - mb[0]), 80),
              meta, font=sub_font, fill=(100, 108, 130, 255))
    draw.line([(pad, header_h - 8), (W - pad, header_h - 8)],
              fill=(255, 255, 255, 30), width=1)

    # Modules grid
    inner_size = cell - 60   # padding inside each cell card
    for i, (slug, name, _, _) in enumerate(MODULES):
        col = i % cols
        row = i // cols
        x0 = pad + col * (cell + pad)
        y0 = header_h + pad + row * (cell + label_h + pad)

        card = Image.new("RGBA", (cell, cell + label_h), (11, 12, 17, 255))
        cb = ImageDraw.Draw(card)
        cb.rectangle([0, 0, cell - 1, cell + label_h - 1],
                     outline=(255, 255, 255, 18), width=1)
        cb.line([(20, cell - 2), (cell - 20, cell - 2)],
                fill=(255, 255, 255, 22), width=1)
        canvas.paste(card, (x0, y0), card)

        icon = render_module_icon(slug, inner_size)
        canvas.alpha_composite(icon, (x0 + (cell - inner_size) // 2,
                                      y0 + (cell - inner_size) // 2 - 4))

        lb = draw.textbbox((0, 0), name, font=label_font)
        lw = lb[2] - lb[0]
        draw.text((x0 + (cell - lw) / 2, y0 + cell + 6),
                  name, font=label_font, fill=(245, 248, 255, 255))
        cap = slug
        cb_b = draw.textbbox((0, 0), cap, font=cap_font)
        cw = cb_b[2] - cb_b[0]
        draw.text((x0 + (cell - cw) / 2, y0 + cell + 32),
                  cap, font=cap_font, fill=(120, 128, 148, 255))

    # 32px favicon strip
    strip_y = header_h + grid_H
    draw.line([(pad, strip_y), (W - pad, strip_y)],
              fill=(255, 255, 255, 30), width=1)
    draw.text((pad, strip_y + 24), "Favicon legibility @ 32 px",
              font=head_font, fill=(245, 248, 255, 255))
    draw.text((pad, strip_y + 64),
              "every module rendered at 32x32 — silhouette + glyph survive",
              font=sub_font, fill=(150, 158, 178, 255))

    cursor_x = pad
    base_y = strip_y + 110
    cell_w_small = (W - 2 * pad) // len(MODULES)
    for slug, _, _, _ in MODULES:
        sample = render_module_icon(slug, 32)
        cx = cursor_x + (cell_w_small - 32) // 2
        canvas.alpha_composite(sample, (cx, base_y + 8))
        # mini label
        lb = draw.textbbox((0, 0), slug, font=scale_label_font)
        lw = lb[2] - lb[0]
        # Truncate
        s = slug if lw < cell_w_small - 6 else slug.split("-")[-1]
        lb = draw.textbbox((0, 0), s, font=scale_label_font)
        lw = lb[2] - lb[0]
        draw.text((cursor_x + (cell_w_small - lw) // 2, base_y + 50),
                  s, font=scale_label_font, fill=(120, 128, 148, 255))
        cursor_x += cell_w_small

    return canvas


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    out_dir = HERE
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[modules] writing to {out_dir}")

    # 1. SVG sources
    print("[1/3] writing 13 SVG sources...")
    for slug, name, _, _ in MODULES:
        svg = render_module_svg(slug)
        (out_dir / f"{slug}.svg").write_text(svg, encoding="utf-8")
        print(f"       {slug}.svg")

    # 2. Hero PNGs
    print("[2/3] rendering 13 hero PNGs at 512x512...")
    for slug, name, _, _ in MODULES:
        img = render_module_icon(slug, 512)
        img.save(out_dir / f"{slug}.png", "PNG", optimize=True)
        print(f"       {slug}.png")

    # 3. Overview grid
    print("[3/3] rendering overview grid...")
    grid = render_overview()
    grid.save(out_dir / "_overview.png", "PNG", optimize=True)
    print(f"       _overview.png")

    print("[modules] done.")


if __name__ == "__main__":
    main()
