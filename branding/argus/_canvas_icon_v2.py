"""
Argus icon v2 — Accrocheur + Securitaire.

Iterates the Hieratic Cipher design toward a cybersecurity product mark:
- Shield silhouette as primary frame (immediate "security" cue)
- Brighter, higher-contrast scanning iris (camera lens energy)
- Mint scan-line crossing the iris (sci-fi UI scanner)
- Gold armed-tick at top of shield (premium / armed signal)
- Tightened 12-satellite-eyes ring (kept subtle for the Argus mythology)
- Subtle pixel-grid behind iris (data being scanned)

Render at 4× supersample, downsample LANCZOS for crisp 16/32/48 favicons.
"""
from __future__ import annotations
import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

HERE = Path(__file__).resolve().parent

# Palette
BG_DEEP = (10, 14, 20, 255)
BG_INNER = (16, 24, 36, 255)
BLUE = (77, 159, 255, 255)
BLUE_BRIGHT = (120, 195, 255, 255)
BLUE_DEEP = (28, 70, 145, 255)
PURPLE = (180, 125, 255, 255)
PURPLE_DEEP = (95, 60, 165, 255)
GOLD = (212, 175, 55, 255)
GOLD_BRIGHT = (240, 205, 90, 255)
MINT = (61, 255, 180, 255)
MINT_GLOW = (130, 255, 200, 255)
WHITE_GLINT = (245, 250, 255, 255)
INK = (4, 7, 12, 255)

SUPER = 4
FINAL = 1024
W = FINAL * SUPER
CX, CY = W // 2, W // 2


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(4))


def shield_path(cx: int, cy: int, w: int, h: int) -> list:
    """Heater shield silhouette — flat top with rounded corners, pointed bottom.
    Returns a closed polyline of points."""
    half_w = w // 2
    top_y = cy - h // 2
    bottom_y = cy + h // 2
    # Curve from top-left around to bottom-tip and back
    pts = []
    # Top edge — flat with slight curve
    n_top = 24
    for i in range(n_top + 1):
        t = i / n_top
        x = cx - half_w + t * w
        # mild downward curve at edges, flat in middle
        sag = 0.06 * h * (math.sin(t * math.pi))
        pts.append((x, top_y + sag * 0.0))  # actually flat
    # Right side — gentle outward curve down to ~70% and then taper to point
    n_side = 36
    for i in range(1, n_side + 1):
        t = i / n_side
        # ease-in to vertical, then curve toward bottom-center
        if t < 0.55:
            # gentle outward bulge
            tt = t / 0.55
            x = cx + half_w - 0.04 * half_w * math.sin(tt * math.pi)
            y = top_y + tt * (h * 0.55)
        else:
            tt = (t - 0.55) / 0.45
            # taper from full half_w to 0
            curve = math.sin(tt * math.pi / 2)
            x = cx + half_w * (1 - curve)
            y = top_y + h * 0.55 + tt * h * 0.45
        pts.append((x, y))
    # Bottom point reached. Mirror left side.
    for (x, y) in reversed(pts[len(pts) - n_side:]):
        pts.append((2 * cx - x, y))
    # Top-left → close
    pts.append((cx - half_w, top_y))
    return pts


def stroked_shield(img: Image.Image, cx: int, cy: int, w: int, h: int) -> None:
    """Filled shield with gradient stroke, drop shadow, and inner highlight."""
    # Drop shadow on a separate blurred layer
    shadow = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    sd = ImageDraw.Draw(shadow)
    sd.polygon(shield_path(cx + W // 200, cy + W // 200, w, h),
               fill=(0, 0, 0, 180))
    shadow = shadow.filter(ImageFilter.GaussianBlur(radius=W // 60))
    img.alpha_composite(shadow)

    # Filled shield
    fill_layer = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    fd = ImageDraw.Draw(fill_layer)
    fd.polygon(shield_path(cx, cy, w, h), fill=(14, 22, 38, 255))
    img.alpha_composite(fill_layer)

    # Gradient stroke — paint multiple strokes with shrinking offsets
    stroke_layers = 14
    for i in range(stroke_layers):
        t = i / (stroke_layers - 1)
        offset_w = w - i * (W // 350)
        offset_h = h - i * (W // 350)
        col = lerp(PURPLE, BLUE, t)
        sl = Image.new("RGBA", (W, W), (0, 0, 0, 0))
        sd = ImageDraw.Draw(sl)
        sd.polygon(shield_path(cx, cy, offset_w, offset_h),
                   outline=col, width=W // 600)
        img.alpha_composite(sl)


def draw_pixel_grid(img: Image.Image, cx: int, cy: int, r: int) -> None:
    """Subtle horizontal pixel-grid behind iris (data-being-scanned cue)."""
    layer = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    spacing = W // 80
    line_w = max(1, W // 1200)
    # Horizontal scanlines
    for y in range(cy - r, cy + r, spacing):
        d.line([(cx - r, y), (cx + r, y)], fill=(*BLUE[:3], 35), width=line_w)
    # Clip to circle
    mask = Image.new("L", (W, W), 0)
    md = ImageDraw.Draw(mask)
    md.ellipse([cx - r, cy - r, cx + r, cy + r], fill=255)
    layer.putalpha(Image.eval(mask, lambda v: int(v * 0.5)))  # halve alpha for subtlety
    img.alpha_composite(layer)


def draw_satellite_eye(d: ImageDraw.ImageDraw, cx: int, cy: int, r: int) -> None:
    """Small almond eye, blue iris + black pupil + glint."""
    h = int(r * 0.5)
    d.ellipse([cx - r, cy - h, cx + r, cy + h], fill=(20, 30, 50, 255))
    ir = int(r * 0.7)
    ih = int(h * 0.85)
    d.ellipse([cx - ir, cy - ih, cx + ir, cy + ih], fill=BLUE_DEEP)
    ir2 = int(r * 0.48)
    ih2 = int(h * 0.65)
    d.ellipse([cx - ir2, cy - ih2, cx + ir2, cy + ih2], fill=BLUE)
    pr = max(2, int(r * 0.2))
    d.ellipse([cx - pr, cy - pr, cx + pr, cy + pr], fill=INK)
    cr = max(1, int(r * 0.08))
    d.ellipse([cx - pr - cr // 2, cy - pr,
               cx - pr + cr, cy - pr + cr * 2], fill=WHITE_GLINT)


def draw_scanning_iris(img: Image.Image, cx: int, cy: int, R: int) -> None:
    """Bright scanning eye — high contrast iris + concentric scan rings + scan tick."""
    draw = ImageDraw.Draw(img, "RGBA")

    # Outer halo bloom
    halo = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    hd = ImageDraw.Draw(halo)
    for i in range(10, 0, -1):
        rr = R + i * (W // 240)
        a = max(0, 70 - i * 7)
        hd.ellipse([cx - rr, cy - rr, cx + rr, cy + rr], fill=(*BLUE[:3], a))
    halo = halo.filter(ImageFilter.GaussianBlur(radius=W // 60))
    img.alpha_composite(halo)

    # Pixel grid behind iris (subtle)
    draw_pixel_grid(img, cx, cy, R)

    # Iris outer rim — purple→blue gradient (concentric thin strokes)
    rim_layers = 22
    for i in range(rim_layers):
        t = i / (rim_layers - 1)
        rr = int(R - i * (W // 800))
        col = lerp(PURPLE_DEEP, BLUE_BRIGHT, t)
        draw.ellipse([cx - rr, cy - rr, cx + rr, cy + rr],
                     outline=col, width=W // 500)

    # Iris fill — bright blue
    R_inner = int(R * 0.78)
    draw.ellipse([cx - R_inner, cy - R_inner, cx + R_inner, cy + R_inner],
                 fill=BLUE_DEEP)

    # Concentric scan rings inside iris (sci-fi scanner feel)
    rings = 6
    for i in range(rings):
        t = (i + 1) / (rings + 1)
        rr = int(R_inner * (1 - t))
        col = (*BLUE_BRIGHT[:3], 90 - i * 10)
        draw.ellipse([cx - rr, cy - rr, cx + rr, cy + rr],
                     outline=col, width=max(1, W // 1200))

    # Bright iris core
    R_core = int(R * 0.55)
    glow = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    for i in range(8, 0, -1):
        rr = R_core + i * (W // 600)
        a = max(0, 90 - i * 10)
        gd.ellipse([cx - rr, cy - rr, cx + rr, cy + rr],
                   fill=(*BLUE_BRIGHT[:3], a))
    glow = glow.filter(ImageFilter.GaussianBlur(radius=W // 200))
    img.alpha_composite(glow)
    draw.ellipse([cx - R_core, cy - R_core, cx + R_core, cy + R_core],
                 fill=BLUE_BRIGHT)

    # Pupil — true ink, slight inner shadow ring
    P = int(R * 0.245)
    draw.ellipse([cx - P, cy - P, cx + P, cy + P], fill=INK)
    # Inner ring around pupil — mint hint
    draw.ellipse([cx - P, cy - P, cx + P, cy + P],
                 outline=lerp(BLUE_BRIGHT, MINT, 0.3), width=W // 600)

    # Catchlight — top-left, two-dot pattern (signature)
    cl_x = cx - int(P * 0.42)
    cl_y = cy - int(P * 0.45)
    cl_r = int(P * 0.34)
    draw.ellipse([cl_x - cl_r, cl_y - cl_r, cl_x + cl_r, cl_y + cl_r],
                 fill=WHITE_GLINT)
    cl2_r = int(cl_r * 0.42)
    cl2_x = cl_x + int(P * 0.5)
    cl2_y = cl_y + int(P * 0.45)
    draw.ellipse([cl2_x - cl2_r, cl2_y - cl2_r, cl2_x + cl2_r, cl2_y + cl2_r],
                 fill=(*WHITE_GLINT[:3], 200))


def draw_scan_tick_strong(img: Image.Image, cx: int, cy: int, R: int) -> None:
    """Mint horizontal scan-line — VERY visible. Cuts through the iris like a sensor sweep."""
    # Outer glow first (wide blurred layer)
    glow = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    half = int(R * 1.25)
    glow_w = W // 80
    gd.rectangle([cx - half, cy - glow_w // 2,
                  cx + half, cy + glow_w // 2], fill=(*MINT[:3], 180))
    glow = glow.filter(ImageFilter.GaussianBlur(radius=W // 200))
    img.alpha_composite(glow)

    # Crisp bright core line
    layer = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    sw = max(6, W // 200)
    d.line([(cx - half, cy), (cx + half, cy)], fill=MINT_GLOW, width=sw)
    # Inner brightest line
    sw2 = max(2, W // 500)
    d.line([(cx - half, cy), (cx + half, cy)],
           fill=(255, 255, 255, 220), width=sw2)
    img.alpha_composite(layer)

    # Thin marker ticks at the line's ends (premium UI scanner detail)
    tick_layer = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    td = ImageDraw.Draw(tick_layer)
    tick_h = W // 90
    tick_w = max(3, W // 350)
    for end_x in (cx - half, cx + half):
        td.line([(end_x, cy - tick_h), (end_x, cy + tick_h)],
                fill=MINT, width=tick_w)
    img.alpha_composite(tick_layer)


def draw_armed_dot(img: Image.Image, cx: int, top_y: int) -> None:
    """Single gold dot at top center — minimal 'armed' signal."""
    layer = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    y0 = top_y + W // 40
    dot_r = max(4, W // 180)
    # Outer glow
    glow = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.ellipse([cx - dot_r * 3, y0 - dot_r * 3,
                cx + dot_r * 3, y0 + dot_r * 3], fill=(*GOLD[:3], 90))
    glow = glow.filter(ImageFilter.GaussianBlur(radius=W // 200))
    img.alpha_composite(glow)
    # Solid dot
    d.ellipse([cx - dot_r, y0 - dot_r, cx + dot_r, y0 + dot_r], fill=GOLD_BRIGHT)
    img.alpha_composite(layer)


def make_full_v2() -> Image.Image:
    img = Image.new("RGBA", (W, W), BG_DEEP)

    # Background radial lift
    bg_layer = Image.new("RGBA", (W, W), BG_DEEP)
    bd = ImageDraw.Draw(bg_layer)
    for i in range(30, 0, -1):
        t = i / 30
        rr = int((1 - t) * W * 0.5)
        c = lerp(BG_DEEP, BG_INNER, (1 - t) * 0.5)
        bd.ellipse([CX - rr, CY - rr, CX + rr, CY + rr], fill=c)
    bg_layer = bg_layer.filter(ImageFilter.GaussianBlur(radius=W // 30))
    img.paste(bg_layer, (0, 0))

    # Shield silhouette (the main containment frame)
    shield_w = int(W * 0.82)
    shield_h = int(W * 0.92)
    stroked_shield(img, CX, CY + int(W * 0.02), shield_w, shield_h)

    # Armed dot at top (minimal gold signal)
    draw_armed_dot(img, CX, CY - shield_h // 2 + int(W * 0.025))

    # 12 satellite eyes — small, tight to center, partial ring (top arc only)
    sat_r = int(W * 0.024)
    sat_radius = int(W * 0.36)
    n_sats = 12
    for i in range(n_sats):
        ang = math.radians(-90 + i * (360 / n_sats))
        sx = CX + sat_radius * math.cos(ang)
        sy = CY + sat_radius * math.sin(ang)
        # Skip the bottom 2 to leave room for shield point
        if i in (5, 6, 7):  # bottom region
            continue
        d = ImageDraw.Draw(img, "RGBA")
        draw_satellite_eye(d, int(sx), int(sy), sat_r)

    # Central scanning iris (the focal point)
    R_main = int(W * 0.21)
    draw_scanning_iris(img, CX, CY, R_main)

    # Mint scan-tick across iris
    draw_scan_tick_strong(img, CX, CY, R_main)

    return img


def make_simple_v2() -> Image.Image:
    """Simplified favicon-friendly: shield + iris + pupil + scan-tick. No satellites."""
    img = Image.new("RGBA", (W, W), BG_DEEP)
    bg_layer = Image.new("RGBA", (W, W), BG_DEEP)
    bd = ImageDraw.Draw(bg_layer)
    for i in range(20, 0, -1):
        t = i / 20
        rr = int((1 - t) * W * 0.5)
        c = lerp(BG_DEEP, BG_INNER, (1 - t) * 0.5)
        bd.ellipse([CX - rr, CY - rr, CX + rr, CY + rr], fill=c)
    bg_layer = bg_layer.filter(ImageFilter.GaussianBlur(radius=W // 30))
    img.paste(bg_layer, (0, 0))

    # Bold shield
    shield_w = int(W * 0.88)
    shield_h = int(W * 0.95)
    stroked_shield(img, CX, CY + int(W * 0.015), shield_w, shield_h)

    # Bigger iris for legibility
    R = int(W * 0.30)
    draw = ImageDraw.Draw(img, "RGBA")
    # Halo
    halo = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    hd = ImageDraw.Draw(halo)
    for i in range(8, 0, -1):
        rr = R + i * (W // 200)
        a = max(0, 80 - i * 10)
        hd.ellipse([CX - rr, CY - rr, CX + rr, CY + rr], fill=(*BLUE[:3], a))
    halo = halo.filter(ImageFilter.GaussianBlur(radius=W // 60))
    img.alpha_composite(halo)

    # Iris rim
    rim_layers = 8
    for i in range(rim_layers):
        t = i / (rim_layers - 1)
        rr = int(R - i * (W // 350))
        col = lerp(PURPLE, BLUE_BRIGHT, t)
        draw.ellipse([CX - rr, CY - rr, CX + rr, CY + rr],
                     outline=col, width=W // 220)

    # Bright iris fill
    R2 = int(R * 0.78)
    draw.ellipse([CX - R2, CY - R2, CX + R2, CY + R2], fill=BLUE_BRIGHT)

    # Pupil
    P = int(W * 0.092)
    draw.ellipse([CX - P, CY - P, CX + P, CY + P], fill=INK)

    # Catchlight
    cl = int(P * 0.4)
    clx = CX - int(P * 0.4)
    cly = CY - int(P * 0.45)
    draw.ellipse([clx - cl, cly - cl, clx + cl, cly + cl], fill=WHITE_GLINT)

    # Mint scan-tick (visible at small sizes)
    layer = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    half = int(R * 1.15)
    sw = max(4, W // 280)
    ld.line([(CX - half, CY), (CX + half, CY)], fill=MINT, width=sw)
    layer = layer.filter(ImageFilter.GaussianBlur(radius=W // 800))
    img.alpha_composite(layer)

    return img


def downsample(img, size):
    return img.resize((size, size), Image.Resampling.LANCZOS)


def main():
    print("Rendering Argus icon v2 (Accrocheur + Securitaire)...")
    full = make_full_v2()
    simple = make_simple_v2()

    # Save downsampled raster outputs
    for size in (1024, 512, 256):
        downsample(full, size).save(HERE / f"argus_v2_{size}.png", optimize=True)
    for size in (64, 48, 32, 16):
        downsample(simple, size).save(HERE / f"argus_v2_simple_{size}.png", optimize=True)

    # Multi-res .ico via Pillow's built-in (uses base + sizes list)
    base = downsample(full, 256)
    base.save(HERE / "argus_v2.ico", format="ICO",
              sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])

    # Promote v2 to the canonical icon files used by the app
    downsample(full, 1024).save(HERE / "argus_normal.png", optimize=True)
    downsample(full, 1024).save(HERE / "argus_canvas_icon.png", optimize=True)
    base.save(HERE / "argus_normal.ico", format="ICO",
              sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])

    print("Done.")
    for f in sorted(HERE.glob("argus_v2*")):
        print(f"  {f.name}: {f.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
