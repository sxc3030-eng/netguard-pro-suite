"""
NetGuard Pro - Master Brand Generator
=====================================

Generates the complete branding asset set:
  branding/netguard_logo.svg            -- vector source of truth
  branding/netguard_logo_master.png     -- 1024x1024 hero render
  branding/netguard_logo_variants.png   -- 6-up grid (N S C F M V)

Design system rationale lives in branding/README.md.

The logo is a 5-vertex shield (rounded crown, single point at base) with a
double-stroked outline forming a thin "containment ring," a centered
lettermark in Segoe UI Black, and a horizontal scan-line that crosses the
shield with a small luminous node where it intersects the inner stroke.

Built by hand-crafting an SVG string (kept under tight control) and then
rasterizing through PIL with manual high-quality path rendering for the PNGs
so we don't rely on cairosvg.
"""

from __future__ import annotations

import math
import os
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parent
ROOT.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# 1. Brand tokens
# ---------------------------------------------------------------------------

# Primary palette (Cloudflare/SentinelOne-tier saturation, not neon)
NAVY_DEEP    = (8,  10, 22)         # canvas core / shield body interior
NAVY_MID     = (16, 21, 46)         # mid-fill
INDIGO_DEEP  = (28, 28, 78)         # dark accent
VIOLET       = (122,  80, 240)      # purple stop
BLUE         = (52, 120, 246)       # blue stop
CYAN         = (52, 210, 246)       # cyan stop
CYAN_BRIGHT  = (110, 240, 255)      # accent highlight
ACTIVE_GREEN = (52, 230, 168)       # "monitoring" mint, not lime

# Variant accents (per module)
VARIANT_LETTERS = ["N", "S", "C", "F", "M", "V"]
VARIANT_NAMES = {
    "N": "NetGuard",
    "S": "Sentinel",
    "C": "CleanGuard",
    "F": "FIM",
    "M": "MailShield",
    "V": "VPNGuard",
}


# ---------------------------------------------------------------------------
# 2. Geometry of the shield
# ---------------------------------------------------------------------------
#
# A "modern" shield: rounded crown, single tapered point. We define it as a
# parametric path in a 0..100 unit-square coordinate system so we can scale
# to any output size. Designed to read at 16x16 and 1024x1024.
#
#   crown:  flat across top, rounded shoulders
#   waist:  slight outward bow at mid
#   point:  single vertex at bottom-center
#
# Path is defined as a list of "cubic" segments approximating the silhouette.
# We then sample it densely for PIL polygon fills, and emit it as SVG.

def shield_path_units(inset: float = 0.0) -> list[tuple[float, float]]:
    """Return polygon points sampling the shield silhouette in 0-100 space.

    `inset` shrinks the shield uniformly toward its visual center (50, 54),
    so we can draw concentric rings.
    """
    # Master control points (top-center origin convention)
    cx = 50.0
    # Shield bounding box in 100x100 -- pulled in vertically for breathing
    # room so the bottom point is never clipped.
    top_y       = 12.0
    shoulder_y  = 12.0
    waist_y     = 47.0
    bottom_y    = 86.5
    half_w_top  = 28.5
    half_w_mid  = 30.5
    # Crown radius
    crown_r     = 5.5

    # Build silhouette as a list of points by walking the perimeter.
    # We'll do: top-left arc -> top edge -> top-right arc -> right side curve
    # -> bottom point -> mirror.
    pts: list[tuple[float, float]] = []

    def add_arc(cx0, cy0, r, a_start, a_end, steps=24):
        for i in range(steps + 1):
            t = i / steps
            a = a_start + (a_end - a_start) * t
            pts.append((cx0 + r * math.cos(a), cy0 + r * math.sin(a)))

    # Left shoulder arc: from top-left flat into the side
    add_arc(cx - half_w_top + crown_r, shoulder_y + crown_r,
            crown_r, math.pi, 1.5 * math.pi)
    # Top edge (straight, center)
    pts.append((cx - half_w_top + crown_r, shoulder_y))
    pts.append((cx + half_w_top - crown_r, shoulder_y))
    # Right shoulder arc
    add_arc(cx + half_w_top - crown_r, shoulder_y + crown_r,
            crown_r, 1.5 * math.pi, 2.0 * math.pi)
    # Right side: gentle outward bow to waist, then sweep to bottom point
    # Use a quadratic-ish approximation by sampling a Bezier from
    # shoulder corner -> waist -> bottom point.
    right_top = (cx + half_w_top, shoulder_y + crown_r)
    right_waist = (cx + half_w_mid, waist_y)
    bottom_point = (cx, bottom_y)

    def cubic_bezier(p0, p1, p2, p3, steps=40):
        out = []
        for i in range(1, steps + 1):
            t = i / steps
            mt = 1 - t
            x = (mt**3) * p0[0] + 3*(mt**2)*t*p1[0] + 3*mt*(t**2)*p2[0] + (t**3)*p3[0]
            y = (mt**3) * p0[1] + 3*(mt**2)*t*p1[1] + 3*mt*(t**2)*p2[1] + (t**3)*p3[1]
            out.append((x, y))
        return out

    # Right side: shoulder -> waist (subtle outward bulge)
    pts.extend(cubic_bezier(
        right_top,
        (right_top[0] + 1.5, right_top[1] + 12),
        (right_waist[0], right_waist[1] - 12),
        right_waist,
    ))
    # Right side: waist -> bottom point (graceful taper)
    pts.extend(cubic_bezier(
        right_waist,
        (right_waist[0] - 1.5, right_waist[1] + 18),
        (bottom_point[0] + 12, bottom_point[1] - 6),
        bottom_point,
    ))
    # Mirror the right side to build the left side
    mirrored: list[tuple[float, float]] = []
    for x, y in reversed(pts):
        mx = 2 * cx - x
        if (mx, y) != (x, y):  # avoid duplicating exact center
            mirrored.append((mx, y))
    pts.extend(mirrored)

    if inset != 0.0:
        # Pull every point toward the visual center (50, 53) by `inset` units.
        ccx, ccy = 50.0, 53.0
        new_pts = []
        for x, y in pts:
            dx = ccx - x
            dy = ccy - y
            d = math.hypot(dx, dy)
            if d == 0:
                new_pts.append((x, y))
                continue
            # Move toward center by `inset` units (in 100-space)
            f = inset / d
            new_pts.append((x + dx * f, y + dy * f))
        pts = new_pts

    return pts


# ---------------------------------------------------------------------------
# 3. PNG render pipeline
# ---------------------------------------------------------------------------

def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def render_logo_png(
    size: int,
    letter: str = "N",
    transparent_bg: bool = True,
    show_grid: bool = True,
    accent_stops=None,
) -> Image.Image:
    """Render the master logo at `size` x `size`.

    Resolution-responsive: at small sizes we shed detail (mesh grid, inner
    ring, scan line, sheen) so the silhouette + lettermark stay legible.
    Same vector geometry, different "level of detail" — like a 3D LOD system.
    """

    if accent_stops is None:
        accent_stops = [VIOLET, BLUE, CYAN]   # tri-color border gradient

    # Level of detail thresholds (output px, before supersampling)
    show_mesh    = show_grid and size >= 96
    show_inner   = size >= 64
    show_scan    = size >= 96
    show_sheen   = size >= 64
    show_halo    = size >= 48

    # Render at 4x supersampled then downsample for crispness
    if size >= 256:
        SS = 4
    elif size >= 64:
        SS = 4
    else:
        SS = 6      # extra for tiny renders so the few features we keep are crisp
    W = size * SS
    H = size * SS

    # ---- Background ----
    if transparent_bg:
        canvas = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    else:
        canvas = Image.new("RGBA", (W, H), NAVY_DEEP + (255,))
    draw = ImageDraw.Draw(canvas)

    # ---- Helpers ----
    def to_px(p):
        return (p[0] / 100.0 * W, p[1] / 100.0 * H)

    def poly_pixels(units_pts):
        return [to_px(p) for p in units_pts]

    # ---- 1. Outer halo glow (very subtle — adds premium "lift") ----
    if show_halo:
        halo = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        halo_draw = ImageDraw.Draw(halo)
        halo_pts = poly_pixels(shield_path_units(inset=-2.0))
        halo_draw.polygon(halo_pts, fill=BLUE + (60,))
        halo = halo.filter(ImageFilter.GaussianBlur(radius=W * 0.04))
        canvas = Image.alpha_composite(canvas, halo)
        draw = ImageDraw.Draw(canvas)

    # ---- 2. Shield body fill (radial dark gradient, mid -> deep) ----
    body_pts_units = shield_path_units(inset=0.0)
    body_pts = poly_pixels(body_pts_units)

    # Build radial gradient inside the shield via a circular mask
    body_mask = Image.new("L", (W, H), 0)
    ImageDraw.Draw(body_mask).polygon(body_pts, fill=255)

    # Radial gradient from highlight near top-left to deep near bottom
    cx_g = 0.42 * W
    cy_g = 0.38 * H
    max_r = math.hypot(W, H) * 0.55
    yy, xx = np.mgrid[0:H, 0:W].astype(np.float32)
    dist = np.sqrt((xx - cx_g) ** 2 + (yy - cy_g) ** 2) / max_r
    dist = np.clip(dist, 0.0, 1.0)
    # Two-stop blend: indigo -> navy_mid -> navy_deep
    t1 = np.clip(dist / 0.5, 0.0, 1.0)
    t2 = np.clip((dist - 0.5) / 0.5, 0.0, 1.0)
    out = np.zeros((H, W, 3), dtype=np.float32)
    for ch in range(3):
        first = INDIGO_DEEP[ch] + (NAVY_MID[ch] - INDIGO_DEEP[ch]) * t1
        second = NAVY_MID[ch] + (NAVY_DEEP[ch] - NAVY_MID[ch]) * t2
        out[..., ch] = np.where(dist < 0.5, first, second)
    out = np.clip(out, 0, 255).astype(np.uint8)
    alpha = np.full((H, W, 1), 255, dtype=np.uint8)
    grad_arr = np.concatenate([out, alpha], axis=-1)
    grad = Image.fromarray(grad_arr, "RGBA")

    # Apply body mask
    body_layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    body_layer.paste(grad, (0, 0), body_mask)
    canvas = Image.alpha_composite(canvas, body_layer)

    # ---- 3. Geometric grid mesh inside shield (clipped) ----
    if show_mesh:
        grid_layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        gd = ImageDraw.Draw(grid_layer)

        # Isometric-leaning grid: three sets of lines at 0deg, 60deg, 120deg
        # so lines form triangles. Visible but restrained.
        spacing = W * 0.058
        line_color = CYAN_BRIGHT + (50,)
        line_w = max(1, int(SS * 0.6))

        for angle_deg in (0, 60, -60):
            a = math.radians(angle_deg)
            dx = math.cos(a + math.pi / 2)
            dy = math.sin(a + math.pi / 2)
            # walk perpendicular offsets
            n = int(W * 1.5 / spacing)
            for i in range(-n, n + 1):
                ox = dx * i * spacing
                oy = dy * i * spacing
                # line center
                cxl = W / 2 + ox
                cyl = H / 2 + oy
                # endpoints (long line in `a` direction)
                length = W * 1.5
                ex1 = cxl + math.cos(a) * length
                ey1 = cyl + math.sin(a) * length
                ex2 = cxl - math.cos(a) * length
                ey2 = cyl - math.sin(a) * length
                gd.line([(ex1, ey1), (ex2, ey2)], fill=line_color, width=line_w)

        # Brighter vertical axis (subtle architecture)
        gd.line([(W * 0.5, H * 0.12), (W * 0.5, H * 0.92)],
                fill=CYAN_BRIGHT + (50,), width=line_w)

        # Small grid intersection dots near the corners of the shield
        for ux, uy in [(34, 26), (66, 26), (34, 60), (66, 60)]:
            px, py = ux / 100 * W, uy / 100 * H
            r = max(2, int(SS * 1.2))
            # outer halo
            gd.ellipse([px - r * 2, py - r * 2, px + r * 2, py + r * 2],
                       fill=CYAN_BRIGHT + (40,))
            gd.ellipse([px - r, py - r, px + r, py + r],
                       fill=CYAN_BRIGHT + (180,))

        # Clip the grid to the shield body
        clipped = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        clipped.paste(grid_layer, (0, 0), body_mask)
        canvas = Image.alpha_composite(canvas, clipped)

    # ---- 4. Outer gradient ring (the brand stroke) ----
    # Build by drawing a thick outline along the shield perimeter using a
    # gradient stroke. We achieve a gradient stroke by drawing many short
    # segments, each colored by interpolated stops.
    ring_layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    rd = ImageDraw.Draw(ring_layer)

    perim = body_pts_units

    def color_for_point(px_unit, py_unit):
        """3-stop diagonal gradient: violet (upper-left), blue (mid),
        cyan (upper-right). Bottom of shield = deeper blue."""
        # Use a diagonal axis going from upper-left to upper-right.
        # We project the point onto the x-axis (essentially the horizontal
        # coordinate, since we want LEFT side violet, RIGHT side cyan).
        # Then bottom-half points get pulled toward "blue" so the very
        # bottom point is the most-saturated brand-blue.
        # Normalize horizontal: 0 at far left, 1 at far right.
        h = (px_unit - 18) / (82 - 18)
        h = max(0.0, min(1.0, h))
        # Vertical influence: 0 at top, 1 at bottom point
        v = (py_unit - 11) / (88 - 11)
        v = max(0.0, min(1.0, v))

        # Top-edge color: violet (h=0) -> cyan (h=1), passing through blue at 0.5
        if h < 0.5:
            top_c = lerp(accent_stops[0], accent_stops[1], h / 0.5)
        else:
            top_c = lerp(accent_stops[1], accent_stops[2], (h - 0.5) / 0.5)
        # As we go down the shield, drift toward unified deep-blue
        deep = lerp(accent_stops[1], (28, 90, 200), 0.35)
        return lerp(top_c, deep, v ** 1.4 * 0.55)

    # Stroke widths: at very small sizes the ring needs to be relatively
    # thicker to read (a "fat-when-small, thin-when-big" curve).
    if size <= 32:
        stroke_w_outer = max(3, int(W * 0.045))
    elif size <= 96:
        stroke_w_outer = max(3, int(W * 0.030))
    else:
        stroke_w_outer = max(3, int(W * 0.022))
    stroke_w_inner = max(1, int(W * 0.006))

    # Outer thick stroke (the bold ring)
    for i in range(1, len(perim)):
        x0, y0 = perim[i - 1]
        x1, y1 = perim[i]
        mx = (x0 + x1) / 2
        my = (y0 + y1) / 2
        c = color_for_point(mx, my)
        rd.line(
            [to_px((x0, y0)), to_px((x1, y1))],
            fill=c + (255,),
            width=stroke_w_outer,
        )
    # close
    x_last, y_last = perim[-1]
    x_first, y_first = perim[0]
    rd.line([to_px(perim[-1]), to_px(perim[0])],
            fill=color_for_point((x_last + x_first) / 2,
                                  (y_last + y_first) / 2) + (255,),
            width=stroke_w_outer)

    # Slight glow halo around the ring
    glow = ring_layer.filter(ImageFilter.GaussianBlur(radius=W * 0.012))
    canvas = Image.alpha_composite(canvas, Image.eval(glow, lambda v: int(v * 0.55)))
    canvas = Image.alpha_composite(canvas, ring_layer)

    # ---- 5. Inner thin "containment ring" — defines premium quality ----
    inner_pts = shield_path_units(inset=4.0)
    inner_pts_px = poly_pixels(inner_pts)
    if show_inner:
        inner_layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        idl = ImageDraw.Draw(inner_layer)

        # Single-color, low-alpha thin stroke for the inner ring -- premium look
        inner_color = CYAN_BRIGHT + (140,)
        for i in range(1, len(inner_pts_px)):
            idl.line([inner_pts_px[i - 1], inner_pts_px[i]],
                     fill=inner_color, width=stroke_w_inner)
        idl.line([inner_pts_px[-1], inner_pts_px[0]],
                 fill=inner_color, width=stroke_w_inner)
        canvas = Image.alpha_composite(canvas, inner_layer)

    # ---- 6. Scan line — the "active monitoring" pulse ----
    # Horizontal thin line crossing the shield at ~38% height; meets the
    # inner ring on both sides with small luminous nodes.
    if show_scan:
        scan_y = 0.355 * H
        scan_layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        sd = ImageDraw.Draw(scan_layer)

        # Find x-extent of the shield interior at scan_y (in unit space)
        target_y_units = scan_y / H * 100
        xs_at_y = []
        for i in range(1, len(inner_pts)):
            x0, y0 = inner_pts[i - 1]
            x1, y1 = inner_pts[i]
            if (y0 - target_y_units) * (y1 - target_y_units) < 0:
                t = (target_y_units - y0) / (y1 - y0)
                xs_at_y.append(x0 + t * (x1 - x0))
        if len(xs_at_y) >= 2:
            x_left = min(xs_at_y) / 100 * W
            x_right = max(xs_at_y) / 100 * W
            n_seg = 60
            for k in range(n_seg):
                t0 = k / n_seg
                t1 = (k + 1) / n_seg
                x0_seg = x_left + (x_right - x_left) * t0 + W * 0.005
                x1_seg = x_left + (x_right - x_left) * t1 - W * 0.005
                mid_t = (t0 + t1) / 2
                curve = 1 - 4 * (mid_t - 0.5) ** 2
                a = int(180 - 100 * curve)
                sd.line([(x0_seg, scan_y), (x1_seg, scan_y)],
                        fill=ACTIVE_GREEN + (a,),
                        width=max(1, int(SS * 0.7)))
            # LED-style markers at endpoints
            node_r = max(2, int(W * 0.009))
            for nx in (x_left, x_right):
                sd.ellipse(
                    [nx - node_r * 3, scan_y - node_r * 3,
                     nx + node_r * 3, scan_y + node_r * 3],
                    fill=ACTIVE_GREEN + (60,),
                )
                sd.ellipse(
                    [nx - node_r * 1.6, scan_y - node_r * 1.6,
                     nx + node_r * 1.6, scan_y + node_r * 1.6],
                    fill=ACTIVE_GREEN + (180,),
                )
                sd.ellipse(
                    [nx - node_r, scan_y - node_r, nx + node_r, scan_y + node_r],
                    fill=(235, 255, 245, 255),
                )
        # Soft glow under the scan line
        scan_glow = scan_layer.filter(ImageFilter.GaussianBlur(radius=W * 0.006))
        canvas = Image.alpha_composite(canvas,
                    Image.eval(scan_glow, lambda v: int(v * 0.7)))
        canvas = Image.alpha_composite(canvas, scan_layer)

    # ---- 7. Lettermark ----
    # Use Segoe UI Black for impact and modern feel.
    font_path = "C:/Windows/Fonts/seguibl.ttf"
    if not os.path.exists(font_path):
        font_path = "C:/Windows/Fonts/arialbd.ttf"
    # Slightly bigger letter at small sizes (legibility), the "title" size
    # at large sizes (refinement).
    if size <= 32:
        letter_ratio = 0.55
    elif size <= 96:
        letter_ratio = 0.48
    else:
        letter_ratio = 0.42
    target_letter_px = int(H * letter_ratio)
    font = ImageFont.truetype(font_path, target_letter_px)

    text_layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    td = ImageDraw.Draw(text_layer)

    # Measure
    bbox = td.textbbox((0, 0), letter, font=font)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    # Center horizontally on shield center (50% width)
    tx = (W - tw) / 2 - bbox[0]
    # The shield's visual center sits ABOVE the geometric center because of
    # the rounded crown / pointed bottom asymmetry. Pull the letter up by
    # ~3% of canvas height so it sits in the perceived optical center.
    ty = (H - th) / 2 - bbox[1] + H * 0.025

    # Soft luminous backdrop behind the letter (only at large sizes)
    if size >= 96:
        glow_letter_layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        gld = ImageDraw.Draw(glow_letter_layer)
        gld.text((tx, ty), letter, font=font, fill=CYAN + (90,))
        glow_letter_layer = glow_letter_layer.filter(
            ImageFilter.GaussianBlur(radius=W * 0.018)
        )
        canvas = Image.alpha_composite(canvas, glow_letter_layer)

    # Main letter: warm white
    td.text((tx, ty), letter, font=font, fill=(245, 248, 255, 255))
    canvas = Image.alpha_composite(canvas, text_layer)

    # ---- 8. Specular highlight (radial bloom upper-left, clipped to body)
    if show_sheen:
        spec = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        spd = ImageDraw.Draw(spec)
        cx_s = int(0.36 * W)
        cy_s = int(0.24 * H)
        r1 = int(W * 0.30)
        r2 = int(W * 0.18)
        spd.ellipse([cx_s - r1, cy_s - r1, cx_s + r1, cy_s + r1],
                    fill=(255, 255, 255, 28))
        spd.ellipse([cx_s - r2, cy_s - r2, cx_s + r2, cy_s + r2],
                    fill=(255, 255, 255, 55))
        spec = spec.filter(ImageFilter.GaussianBlur(radius=W * 0.05))
        spec_clipped = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        spec_clipped.paste(spec, (0, 0), body_mask)
        canvas = Image.alpha_composite(canvas, spec_clipped)

    # Downsample to target size with high quality
    return canvas.resize((size, size), Image.LANCZOS)


# ---------------------------------------------------------------------------
# 4. SVG export
# ---------------------------------------------------------------------------

def render_logo_svg(letter: str = "N") -> str:
    """Return SVG source. ViewBox is 0 0 100 100."""
    pts = shield_path_units()
    inner = shield_path_units(inset=4.0)

    def path_d(points):
        d = f"M {points[0][0]:.3f} {points[0][1]:.3f} "
        for x, y in points[1:]:
            d += f"L {x:.3f} {y:.3f} "
        d += "Z"
        return d

    body_d = path_d(pts)
    inner_d = path_d(inner)

    # Find the y of the scan line and intersect with the inner ring
    scan_y_units = 35.5
    xs = []
    for i in range(1, len(inner)):
        x0, y0 = inner[i - 1]
        x1, y1 = inner[i]
        if (y0 - scan_y_units) * (y1 - scan_y_units) < 0:
            t = (scan_y_units - y0) / (y1 - y0)
            xs.append(x0 + t * (x1 - x0))
    x_left = min(xs) if xs else 25
    x_right = max(xs) if xs else 75

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="1024" height="1024">
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
    <clipPath id="shieldClip">
      <path d="{body_d}"/>
    </clipPath>
    <pattern id="meshGrid" x="0" y="0" width="6" height="5.196" patternUnits="userSpaceOnUse">
      <!-- triangular isometric grid -->
      <line x1="0" y1="0" x2="6" y2="0"
            stroke="rgb({CYAN_BRIGHT[0]},{CYAN_BRIGHT[1]},{CYAN_BRIGHT[2]})"
            stroke-width="0.12" stroke-opacity="0.10"/>
      <line x1="0" y1="0" x2="3" y2="5.196"
            stroke="rgb({CYAN_BRIGHT[0]},{CYAN_BRIGHT[1]},{CYAN_BRIGHT[2]})"
            stroke-width="0.12" stroke-opacity="0.10"/>
      <line x1="6" y1="0" x2="3" y2="5.196"
            stroke="rgb({CYAN_BRIGHT[0]},{CYAN_BRIGHT[1]},{CYAN_BRIGHT[2]})"
            stroke-width="0.12" stroke-opacity="0.10"/>
    </pattern>
  </defs>

  <!-- 1. Outer halo glow -->
  <path d="{body_d}" fill="rgb({BLUE[0]},{BLUE[1]},{BLUE[2]})" fill-opacity="0.25"
        filter="url(#ringHalo)" transform="scale(1.04) translate(-2 -2.1)"/>

  <!-- 2. Body fill -->
  <path d="{body_d}" fill="url(#bodyGrad)"/>

  <!-- 3. Triangular mesh, clipped to shield -->
  <g clip-path="url(#shieldClip)">
    <rect x="0" y="0" width="100" height="100" fill="url(#meshGrid)"/>
    <!-- crosshairs -->
    <line x1="50" y1="16" x2="50" y2="92" stroke="rgb({CYAN_BRIGHT[0]},{CYAN_BRIGHT[1]},{CYAN_BRIGHT[2]})" stroke-width="0.15" stroke-opacity="0.12"/>
    <line x1="18" y1="53" x2="82" y2="53" stroke="rgb({CYAN_BRIGHT[0]},{CYAN_BRIGHT[1]},{CYAN_BRIGHT[2]})" stroke-width="0.15" stroke-opacity="0.12"/>
    <!-- intersection dots -->
    <circle cx="34" cy="30" r="0.55" fill="rgb({CYAN_BRIGHT[0]},{CYAN_BRIGHT[1]},{CYAN_BRIGHT[2]})" fill-opacity="0.6"/>
    <circle cx="66" cy="30" r="0.55" fill="rgb({CYAN_BRIGHT[0]},{CYAN_BRIGHT[1]},{CYAN_BRIGHT[2]})" fill-opacity="0.6"/>
    <circle cx="34" cy="65" r="0.55" fill="rgb({CYAN_BRIGHT[0]},{CYAN_BRIGHT[1]},{CYAN_BRIGHT[2]})" fill-opacity="0.6"/>
    <circle cx="66" cy="65" r="0.55" fill="rgb({CYAN_BRIGHT[0]},{CYAN_BRIGHT[1]},{CYAN_BRIGHT[2]})" fill-opacity="0.6"/>
  </g>

  <!-- 4. Outer ring (gradient stroke) with halo -->
  <path d="{body_d}" fill="none" stroke="url(#ringGrad)" stroke-width="2.2"
        filter="url(#softGlow)" stroke-linejoin="round"/>
  <path d="{body_d}" fill="none" stroke="url(#ringGrad)" stroke-width="2.2"
        stroke-linejoin="round"/>

  <!-- 5. Inner thin containment ring -->
  <path d="{inner_d}" fill="none" stroke="rgb({CYAN_BRIGHT[0]},{CYAN_BRIGHT[1]},{CYAN_BRIGHT[2]})"
        stroke-width="0.55" stroke-opacity="0.55" stroke-linejoin="round"/>

  <!-- 6. Scan line + nodes -->
  <g>
    <line x1="{x_left + 0.5:.2f}" y1="{scan_y_units}" x2="{x_right - 0.5:.2f}" y2="{scan_y_units}"
          stroke="rgb({ACTIVE_GREEN[0]},{ACTIVE_GREEN[1]},{ACTIVE_GREEN[2]})"
          stroke-width="0.42" stroke-opacity="0.85"/>
    <circle cx="{x_left:.2f}" cy="{scan_y_units}" r="1.2" fill="rgb({ACTIVE_GREEN[0]},{ACTIVE_GREEN[1]},{ACTIVE_GREEN[2]})" fill-opacity="0.4"/>
    <circle cx="{x_left:.2f}" cy="{scan_y_units}" r="0.55" fill="white"/>
    <circle cx="{x_right:.2f}" cy="{scan_y_units}" r="1.2" fill="rgb({ACTIVE_GREEN[0]},{ACTIVE_GREEN[1]},{ACTIVE_GREEN[2]})" fill-opacity="0.4"/>
    <circle cx="{x_right:.2f}" cy="{scan_y_units}" r="0.55" fill="white"/>
  </g>

  <!-- 7. Lettermark -->
  <text x="50" y="68"
        font-family="'Segoe UI', 'Helvetica Neue', Arial, sans-serif"
        font-weight="900"
        font-size="42"
        text-anchor="middle"
        fill="rgb(245,248,255)">{letter}</text>

  <!-- 8. Top sheen -->
  <g clip-path="url(#shieldClip)">
    <rect x="0" y="0" width="100" height="48" fill="white" fill-opacity="0.05"/>
  </g>
</svg>
"""
    return svg


# ---------------------------------------------------------------------------
# 5. Variants grid
# ---------------------------------------------------------------------------

def render_variants_grid() -> Image.Image:
    """Premium reference sheet: 6-up variants grid + scale test strip."""
    cell = 460
    pad = 56
    label_h = 86

    cols, rows = 3, 2
    grid_W = pad + cols * cell + (cols - 1) * pad + pad
    grid_H = pad + rows * (cell + label_h) + (rows - 1) * pad + pad

    # Add header band + footer scale strip
    header_h = 120
    scale_strip_h = 220

    W = grid_W
    H = header_h + grid_H + scale_strip_h

    bg = (15, 15, 19, 255)  # matches NetGuard dashboard #0f0f13
    canvas = Image.new("RGBA", (W, H), bg)

    # Subtle dot lattice backdrop
    dots = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    dd = ImageDraw.Draw(dots)
    step = 28
    for y in range(0, H, step):
        for x in range(0, W, step):
            dd.point((x, y), fill=(255, 255, 255, 14))
    canvas = Image.alpha_composite(canvas, dots)

    draw = ImageDraw.Draw(canvas)

    # Fonts
    head_font = ImageFont.truetype("C:/Windows/Fonts/seguibl.ttf", 28)
    sub_font = ImageFont.truetype("C:/Windows/Fonts/segoeuil.ttf", 14)
    label_font = ImageFont.truetype("C:/Windows/Fonts/seguibl.ttf", 22)
    cap_font = ImageFont.truetype("C:/Windows/Fonts/segoeuil.ttf", 13)
    scale_label_font = ImageFont.truetype("C:/Windows/Fonts/segoeuil.ttf", 12)

    # ---- Header ----
    draw.text((pad, 38), "NetGuard Pro", font=head_font, fill=(245, 248, 255, 255))
    draw.text((pad, 78),
              "Brand mark system  /  shield + lettermark  /  per-module variant",
              font=sub_font, fill=(150, 158, 178, 255))
    # right-side meta
    meta = "v1.0  -  master sheet"
    mb = draw.textbbox((0, 0), meta, font=sub_font)
    draw.text((W - pad - (mb[2] - mb[0]), 78),
              meta, font=sub_font, fill=(100, 108, 130, 255))
    # underline rule
    draw.line([(pad, header_h - 8), (W - pad, header_h - 8)],
              fill=(255, 255, 255, 30), width=1)

    # ---- Variants grid ----
    for i, letter in enumerate(VARIANT_LETTERS):
        col = i % cols
        row = i // cols
        x0 = pad + col * (cell + pad)
        y0 = header_h + pad + row * (cell + label_h + pad)

        # Cell background card
        card_bg = Image.new("RGBA", (cell, cell + label_h), (11, 12, 17, 255))
        cb = ImageDraw.Draw(card_bg)
        cb.rectangle([0, 0, cell - 1, cell + label_h - 1],
                     outline=(255, 255, 255, 18), width=1)
        cb.line([(24, cell - 2), (cell - 24, cell - 2)],
                fill=(255, 255, 255, 22), width=1)
        canvas.paste(card_bg, (x0, y0), card_bg)

        # Render the logo
        logo = render_logo_png(cell - 80, letter=letter, transparent_bg=True)
        canvas.alpha_composite(logo, (x0 + 40, y0 + 18))

        # Label
        name = VARIANT_NAMES[letter]
        ld_bbox = draw.textbbox((0, 0), name, font=label_font)
        lw = ld_bbox[2] - ld_bbox[0]
        draw.text((x0 + (cell - lw) / 2, y0 + cell + 8),
                  name, font=label_font, fill=(245, 248, 255, 255))

        # Caption (slug)
        cap = f"netguard-{letter.lower()}"
        cb_bbox = draw.textbbox((0, 0), cap, font=cap_font)
        cw = cb_bbox[2] - cb_bbox[0]
        draw.text((x0 + (cell - cw) / 2, y0 + cell + 42),
                  cap, font=cap_font, fill=(120, 128, 148, 255))

    # ---- Footer scale-test strip ----
    strip_y = header_h + grid_H
    draw.line([(pad, strip_y), (W - pad, strip_y)],
              fill=(255, 255, 255, 30), width=1)
    draw.text((pad, strip_y + 20), "Scale resilience",
              font=head_font, fill=(245, 248, 255, 255))
    draw.text((pad, strip_y + 58),
              "16 / 32 / 64 / 128 / 256 px  -  same vector, same legibility",
              font=sub_font, fill=(150, 158, 178, 255))

    sizes = [256, 128, 64, 32, 16]
    cursor_x = pad
    base_y = strip_y + 110
    sample_h = 110
    for sz in sizes:
        # render at intended size
        sample = render_logo_png(sz, letter="N", transparent_bg=True)
        # paste centered vertically in the row
        py = base_y + (sample_h - sz) // 2
        canvas.alpha_composite(sample, (cursor_x, py))
        # label
        lbl = f"{sz}px"
        lb = draw.textbbox((0, 0), lbl, font=scale_label_font)
        lw = lb[2] - lb[0]
        draw.text((cursor_x + (sz - lw) / 2, base_y + sample_h + 8),
                  lbl, font=scale_label_font, fill=(120, 128, 148, 255))
        cursor_x += sz + 36

    return canvas


# ---------------------------------------------------------------------------
# 6. Main
# ---------------------------------------------------------------------------

def main():
    print("[1/4] Generating SVG vector source...")
    svg = render_logo_svg(letter="N")
    (ROOT / "netguard_logo.svg").write_text(svg, encoding="utf-8")

    print("[2/4] Rendering 1024x1024 master PNG...")
    master = render_logo_png(1024, letter="N", transparent_bg=True)
    master.save(ROOT / "netguard_logo_master.png", "PNG", optimize=True)

    print("[3/4] Rendering 6-up variants grid...")
    grid = render_variants_grid()
    grid.save(ROOT / "netguard_logo_variants.png", "PNG", optimize=True)

    print("[4/4] Done. Files:")
    for f in ["netguard_logo.svg", "netguard_logo_master.png",
              "netguard_logo_variants.png"]:
        p = ROOT / f
        print(f"   {p}  ({p.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
