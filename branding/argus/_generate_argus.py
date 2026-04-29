"""
Argus Panoptes Browser - Brand Asset Generator
==============================================

Renders all PNG / ICO variants of the Argus mark using Pillow primitives.
Matches the hand-written argus_mark.svg design.

Concept:
  - Eye of Argus Panoptes (Greek 100-eyed giant)
  - Central iris with concentric rings + pupil + catchlight
  - 12 satellite eyes around the rim (the 100 eyes, stylized)
  - Sacred-geometry frame (dodecagon + hexagram seal lines)
  - Mint scan-tick = "live watching"

Outputs (all in this directory):
  argus_mark.png            1024x1024  master mark, primary blue iris
  argus_mark_64.png         64x64      pre-rendered favicon-tier size
  argus_mark_256.png        256x256    pre-rendered window-icon size
  argus_normal.png          1024x1024  Normal mode (electric blue)
  argus_private.png         1024x1024  Privacy mode (deep blue)
  argus_vault.png           1024x1024  Vault mode (gold iris)
  argus_wordmark.png        800x200    horizontal wordmark
  argus_splash.png          800x500    splash screen with tagline
  argus_normal.ico          multi-res 16/32/48/64/128/256
  argus_private.ico         multi-res
  argus_vault.ico           multi-res

License: GPL v3. (c) 2026 sxc3030-eng. All artwork original.
"""

from __future__ import annotations

import math
from pathlib import Path
from PIL import Image, ImageDraw, ImageFilter, ImageFont

HERE = Path(__file__).resolve().parent

# -------------------------------------------------------------- palette
BG_DARK         = (10, 14, 20)         # #0a0e14
BG_DARKER       = ( 5,  7, 11)         # #05070b
PRIMARY         = (77, 159, 255)       # #4d9fff
PRIMARY_LIGHT   = (155, 208, 255)      # #9bd0ff
SECONDARY       = (180, 125, 255)      # #b47dff
PRIVATE_DEEP    = (30,  64, 175)       # #1e40af  (Privé mode)
PRIVATE_LIGHT   = (96, 138, 232)
VAULT_GOLD      = (212, 175,  55)      # #d4af37
VAULT_LIGHT     = (255, 224, 130)
MINT            = ( 61, 255, 180)      # #3dffb4
CYAN            = (110, 240, 255)      # #6ef0ff
TEXT_LIGHT      = (220, 239, 255)      # #dcefff
TEXT_DIM        = (188, 220, 255)
RING_DARK       = (26, 38, 56)         # outer dodecagon stroke


# -------------------------------------------------------------- helpers
def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def radial_disc(size, inner, outer):
    """Pre-rendered radial-gradient disc (RGBA)."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    px = img.load()
    cx = cy = size / 2.0
    r_max = size / 2.0
    for y in range(size):
        for x in range(size):
            dx, dy = x - cx, y - cy
            d = math.hypot(dx, dy)
            if d > r_max:
                continue
            t = d / r_max
            c = lerp(inner, outer, t)
            px[x, y] = (*c, 255)
    return img


def radial_iris(size, inner, mid, outer):
    """Three-stop radial: pupil-ish core -> mid -> dark rim."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    px = img.load()
    cx = cy = size / 2.0
    r_max = size / 2.0
    for y in range(size):
        for x in range(size):
            dx, dy = x - cx, y - cy
            d = math.hypot(dx, dy)
            if d > r_max:
                continue
            t = d / r_max
            if t < 0.4:
                c = lerp(inner, mid, t / 0.4)
            else:
                c = lerp(mid, outer, (t - 0.4) / 0.6)
            px[x, y] = (*c, 255)
    return img


def gradient_ring(size, w, color_a, color_b):
    """Stroke a circle with a left-to-right linear gradient."""
    layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    grad = Image.new("RGB", (size, 1))
    gpx = grad.load()
    for x in range(size):
        gpx[x, 0] = lerp(color_a, color_b, x / max(1, size - 1))
    grad = grad.resize((size, size))
    mask = Image.new("L", (size, size), 0)
    md = ImageDraw.Draw(mask)
    pad = w // 2 + 2
    md.ellipse([pad, pad, size - pad, size - pad], outline=255, width=w)
    layer.paste(grad.convert("RGBA"), (0, 0), mask)
    return layer


def gradient_almond(size, color_a, color_b, stroke_w):
    """Stroke an almond/eye shape with a diagonal gradient.
    Almond defined by Bezier-ish via two ellipses intersecting (vesica)."""
    layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    grad = Image.new("RGB", (size, size))
    gpx = grad.load()
    for y in range(size):
        for x in range(size):
            t = (x + y) / (2 * size)
            gpx[x, y] = lerp(color_a, color_b, t)

    # Build mask of the almond ring
    mask = Image.new("L", (size, size), 0)
    md = ImageDraw.Draw(mask)
    cx = cy = size / 2
    half_w = size * 0.305  # almond half-width (200..824 / 1024)
    # vesica piscis: two arcs from circles offset vertically
    # we'll draw as filled ellipse minus thinner ellipse to get a ring
    # almond bounding: from cx-half_w to cx+half_w, height ~= 0.256*size
    half_h = size * 0.128
    md.ellipse([cx - half_w, cy - half_h, cx + half_w, cy + half_h],
               outline=255, width=stroke_w)
    layer.paste(grad.convert("RGBA"), (0, 0), mask)
    return layer


def filled_almond(size, fill):
    """Filled almond shape (eye outline, dark fill)."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    cx = cy = size / 2
    half_w = size * 0.305
    half_h = size * 0.128
    d.ellipse([cx - half_w, cy - half_h, cx + half_w, cy + half_h],
              fill=(*fill, 255))
    return img


def soft_glow(layer, blur=8, opacity=140):
    """Return a blurred glow copy of `layer` for halo effect."""
    g = layer.copy()
    g = g.filter(ImageFilter.GaussianBlur(blur))
    # bump alpha
    a = g.split()[3].point(lambda p: min(255, int(p * opacity / 255)))
    g.putalpha(a)
    return g


# -------------------------------------------------------------- mark
def render_mark(size: int, iris_inner, iris_mid, iris_outer,
                ring_a, ring_b, accent_color=PRIMARY) -> Image.Image:
    """
    Render the full Argus mark at given size with the given iris color set.

    iris_inner -> brightest core
    iris_mid   -> primary tone
    iris_outer -> deep rim
    ring_a/b   -> outer ring gradient (and almond stroke)
    accent_color -> color of the 12 satellite eyes' iris
    """
    S = size
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx = cy = S / 2

    # 1. Backdrop disc (radial dark)
    bg = radial_disc(S, (16, 20, 28), BG_DARKER)
    bg_mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(bg_mask).ellipse([12, 12, S - 12, S - 12], fill=255)
    img.paste(bg, (0, 0), bg_mask)

    # 2. Sacred-geometry dodecagon (12-sided)
    pts = []
    R = S * 0.485
    for i in range(12):
        a = math.radians(i * 30 - 90)
        pts.append((cx + R * math.cos(a), cy + R * math.sin(a)))
    draw.polygon(pts, outline=RING_DARK, width=max(1, S // 512))

    # 3. Outer ring with halo
    ring_w = max(2, int(S * 0.0059))   # ~6 at 1024
    halo_w = max(4, int(S * 0.0137))   # ~14 at 1024
    halo_layer = gradient_ring(S, halo_w, ring_a, ring_b)
    halo_layer = soft_glow(halo_layer, blur=max(2, S // 170), opacity=46)
    img = Image.alpha_composite(img, halo_layer)
    ring_layer = gradient_ring(S, ring_w, ring_a, ring_b)
    img = Image.alpha_composite(img, ring_layer)

    draw = ImageDraw.Draw(img)

    # 4. Twelve satellite eyes
    eye_r_outer = max(6, int(S * 0.033))   # ~34 at 1024
    eye_r_inner = max(2, int(S * 0.0137))  # ~14 at 1024
    eye_dist    = S * 0.41                  # distance from center
    eye_stroke  = max(1, int(S * 0.0029))   # ~3 at 1024
    for i in range(12):
        a = math.radians(i * 30 - 90)
        ex = cx + eye_dist * math.cos(a)
        ey = cy + eye_dist * math.sin(a)
        # almond shell
        shell_w = eye_r_outer
        shell_h = max(3, int(eye_r_outer * 0.59))  # ~20/34
        draw.ellipse([ex - shell_w, ey - shell_h, ex + shell_w, ey + shell_h],
                     fill=BG_DARK, outline=accent_color, width=eye_stroke)
        # iris
        draw.ellipse([ex - eye_r_inner, ey - eye_r_inner,
                      ex + eye_r_inner, ey + eye_r_inner],
                     fill=accent_color)
        # pupil
        pr = max(1, int(eye_r_inner * 0.43))
        draw.ellipse([ex - pr, ey - pr, ex + pr, ey + pr], fill=BG_DARKER)
        # highlight (only at larger sizes)
        if S >= 256:
            hr = max(1, int(eye_r_inner * 0.16))
            draw.ellipse([ex - hr - 3, ey - hr - 3, ex + hr - 3, ey + hr - 3],
                         fill=PRIMARY_LIGHT)

    # 5. Inner cyan containment ring
    inner_r = int(S * 0.349)  # ~358 at 1024
    inner_w = max(1, int(S * 0.0021))  # ~2 at 1024
    # draw with reduced opacity by going through layer
    inner_layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(inner_layer).ellipse(
        [cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r],
        outline=(*CYAN, 140), width=inner_w)
    img = Image.alpha_composite(img, inner_layer)

    # 6. Hexagram seal lines (two triangles, faint)
    if S >= 128:
        hex_layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
        hd = ImageDraw.Draw(hex_layer)
        tri_w = max(1, int(S * 0.0015))
        # up-pointing triangle
        p1 = (cx, cy - S * 0.305)
        p2 = (cx + S * 0.264, cy + S * 0.152)
        p3 = (cx - S * 0.264, cy + S * 0.152)
        hd.line([p1, p2, p3, p1], fill=(*PRIMARY, 90), width=tri_w)
        # down-pointing triangle
        p4 = (cx, cy + S * 0.305)
        p5 = (cx - S * 0.264, cy - S * 0.152)
        p6 = (cx + S * 0.264, cy - S * 0.152)
        hd.line([p4, p5, p6, p4], fill=(*PRIMARY, 90), width=tri_w)
        img = Image.alpha_composite(img, hex_layer)

    draw = ImageDraw.Draw(img)

    # 7. Almond eye outline (with halo)
    almond_stroke_w = max(2, int(S * 0.0059))
    almond_halo_w = max(4, int(S * 0.0137))
    almond_halo = gradient_almond(S, ring_a, ring_b, almond_halo_w)
    almond_halo = soft_glow(almond_halo, blur=max(2, S // 170), opacity=64)
    img = Image.alpha_composite(img, almond_halo)
    almond_fill = filled_almond(S, BG_DARK)
    img = Image.alpha_composite(img, almond_fill)
    almond_ring = gradient_almond(S, ring_a, ring_b, almond_stroke_w)
    img = Image.alpha_composite(img, almond_ring)

    draw = ImageDraw.Draw(img)

    # 8. Iris
    iris_r = int(S * 0.156)  # ~160 at 1024
    iris_disc = radial_iris(iris_r * 2, iris_inner, iris_mid, iris_outer)
    img.paste(iris_disc, (int(cx - iris_r), int(cy - iris_r)), iris_disc)
    draw = ImageDraw.Draw(img)

    # iris striations (concentric)
    for r_frac, op in [(0.144, 110), (0.131, 100), (0.115, 90), (0.0957, 80)]:
        rr = int(S * r_frac)
        layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
        ImageDraw.Draw(layer).ellipse(
            [cx - rr, cy - rr, cx + rr, cy + rr],
            outline=(*PRIMARY_LIGHT, op), width=max(1, S // 700))
        img = Image.alpha_composite(img, layer)

    # radial striation ticks (16) — only at moderate sizes
    if S >= 128:
        tick_layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
        td = ImageDraw.Draw(tick_layer)
        for i in range(16):
            a = math.radians(i * 360 / 16)
            r1 = S * 0.137
            r2 = S * 0.157
            x1 = cx + r1 * math.cos(a)
            y1 = cy + r1 * math.sin(a)
            x2 = cx + r2 * math.cos(a)
            y2 = cy + r2 * math.sin(a)
            td.line([(x1, y1), (x2, y2)],
                    fill=(*TEXT_DIM, 115),
                    width=max(1, int(S * 0.0021)))
        img = Image.alpha_composite(img, tick_layer)

    draw = ImageDraw.Draw(img)

    # 9. Pupil + ring
    pupil_r = int(S * 0.0566)  # ~58 at 1024
    draw.ellipse([cx - pupil_r, cy - pupil_r, cx + pupil_r, cy + pupil_r],
                 fill=BG_DARKER)
    pupil_layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(pupil_layer).ellipse(
        [cx - pupil_r, cy - pupil_r, cx + pupil_r, cy + pupil_r],
        outline=(*ring_a, 178), width=max(1, S // 512))
    img = Image.alpha_composite(img, pupil_layer)
    draw = ImageDraw.Draw(img)

    # 10. Catchlight
    if S >= 64:
        cl_r = max(2, int(S * 0.0137))   # ~14 at 1024
        cl_x = cx - S * 0.0234           # offset
        cl_y = cy - S * 0.0234
        draw.ellipse([cl_x - cl_r, cl_y - cl_r, cl_x + cl_r, cl_y + cl_r],
                     fill=TEXT_LIGHT)
        if S >= 128:
            cl2 = max(1, int(S * 0.0059))
            cl2_x = cx - S * 0.0352
            cl2_y = cy - S * 0.0352
            draw.ellipse([cl2_x - cl2, cl2_y - cl2,
                          cl2_x + cl2, cl2_y + cl2],
                         fill=(255, 255, 255))

    # 11. Mint scan-tick
    if S >= 128:
        scan_layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
        sd = ImageDraw.Draw(scan_layer)
        x1 = S * 0.195
        x2 = S * 0.805
        # gradient line: peak alpha in middle
        steps = 40
        for i in range(steps):
            t = i / (steps - 1)
            xa = x1 + (x2 - x1) * (i / steps)
            xb = x1 + (x2 - x1) * ((i + 1) / steps)
            # bell-shape alpha
            alpha = int(170 * math.sin(math.pi * t))
            sd.line([(xa, cy), (xb, cy)],
                    fill=(*MINT, alpha), width=max(1, int(S * 0.0014)))
        # endpoint dots
        ep_r = max(1, int(S * 0.0059))
        sd.ellipse([x1 - ep_r, cy - ep_r, x1 + ep_r, cy + ep_r],
                   fill=(*MINT, 150))
        sd.ellipse([x2 - ep_r, cy - ep_r, x2 + ep_r, cy + ep_r],
                   fill=(*MINT, 150))
        img = Image.alpha_composite(img, scan_layer)

    return img


# -------------------------------------------------------------- variants
def variant_normal(size):
    """Electric blue eye — normal browsing mode."""
    return render_mark(
        size,
        iris_inner=PRIMARY_LIGHT,
        iris_mid=PRIMARY,
        iris_outer=(30, 42, 77),
        ring_a=PRIMARY,
        ring_b=SECONDARY,
        accent_color=PRIMARY,
    )


def variant_private(size):
    """Deep blue / private mode."""
    return render_mark(
        size,
        iris_inner=PRIVATE_LIGHT,
        iris_mid=PRIVATE_DEEP,
        iris_outer=(12, 18, 48),
        ring_a=PRIVATE_DEEP,
        ring_b=(96, 78, 200),
        accent_color=PRIVATE_LIGHT,
    )


def variant_vault(size):
    """Gold eye — vault / coffre mode."""
    return render_mark(
        size,
        iris_inner=VAULT_LIGHT,
        iris_mid=VAULT_GOLD,
        iris_outer=(80, 60, 16),
        ring_a=VAULT_GOLD,
        ring_b=(240, 200, 80),
        accent_color=VAULT_GOLD,
    )


# -------------------------------------------------------------- wordmark
def find_font(size, mono=True):
    """Try common monospace / geometric fonts; fall back to PIL default."""
    candidates_mono = [
        "consola.ttf",   # Consolas (Windows)
        "consolab.ttf",  # Consolas Bold
        "cour.ttf",      # Courier New
        "courbd.ttf",    # Courier New Bold
        "DejaVuSansMono.ttf",
        "DejaVuSansMono-Bold.ttf",
        "JetBrainsMono-Bold.ttf",
        "FiraCode-Bold.ttf",
    ]
    candidates_sans = [
        "arial.ttf",
        "arialbd.ttf",
        "DejaVuSans-Bold.ttf",
        "Helvetica.ttf",
    ]
    candidates = candidates_mono if mono else candidates_sans
    for name in candidates:
        try:
            return ImageFont.truetype(name, size)
        except (OSError, IOError):
            continue
    return ImageFont.load_default()


def render_wordmark(width=800, height=200):
    """Mark on the left + ARGUS wordmark + tagline."""
    img = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    # background gradient (dark)
    bg = Image.new("RGB", (width, height), BG_DARK)
    bgpx = bg.load()
    for y in range(height):
        for x in range(width):
            cx, cy = width / 2, height / 2
            d = math.hypot(x - cx, y - cy) / math.hypot(cx, cy)
            t = min(1.0, d)
            bgpx[x, y] = lerp((16, 20, 28), BG_DARKER, t)
    img.paste(bg.convert("RGBA"), (0, 0))

    # Mark on the left: render at higher res then downscale
    mark_size = height - 40
    mark = variant_normal(mark_size * 2)
    mark = mark.resize((mark_size, mark_size), Image.LANCZOS)
    img.paste(mark, (20, 20), mark)

    # Wordmark text "ARGUS" with letter-spacing
    txt_x = 60 + mark_size
    txt_y = int(height * 0.30)
    main_font = find_font(78, mono=True)

    # Character-by-character to apply tracking
    letters = "ARGUS"
    spacing = 14
    cur_x = txt_x
    # Build a gradient color per letter (text gradient: light -> purple)
    for i, ch in enumerate(letters):
        t = i / max(1, len(letters) - 1)
        col = lerp(TEXT_LIGHT, SECONDARY, t)
        # draw letter
        d = ImageDraw.Draw(img)
        d.text((cur_x, txt_y), ch, font=main_font, fill=(*col, 255))
        bbox = d.textbbox((0, 0), ch, font=main_font)
        cur_x += (bbox[2] - bbox[0]) + spacing

    # Tagline
    tagline = "CYBERSECURITY  WORKBENCH"
    tag_font = find_font(16, mono=True)
    d = ImageDraw.Draw(img)
    d.text((txt_x + 2, txt_y + 96), tagline, font=tag_font,
           fill=(*CYAN, 190), spacing=6)

    # Mint underbar
    d.line([(txt_x + 2, txt_y + 122), (txt_x + 78, txt_y + 122)],
           fill=(*MINT, 230), width=2)
    return img


# -------------------------------------------------------------- splash
def render_splash(width=800, height=500):
    """Splash screen: backdrop + mark center-top + wordmark + tagline."""
    img = Image.new("RGBA", (width, height), BG_DARK + (255,))
    # subtle radial vignette
    vignette = Image.new("RGBA", (width, height))
    vp = vignette.load()
    cx, cy = width / 2, height / 2
    for y in range(height):
        for x in range(width):
            d = math.hypot(x - cx, y - cy) / math.hypot(cx, cy)
            t = min(1.0, d)
            c = lerp((20, 26, 38), (5, 7, 11), t)
            vp[x, y] = (*c, 255)
    img.paste(vignette, (0, 0))

    # Mark, ~280px, top-centered
    mark_size = 260
    mark = variant_normal(mark_size * 2)
    mark = mark.resize((mark_size, mark_size), Image.LANCZOS)
    mark_x = (width - mark_size) // 2
    mark_y = 50
    img.paste(mark, (mark_x, mark_y), mark)

    # ARGUS wordmark large
    title_font = find_font(72, mono=True)
    letters = "ARGUS"
    spacing = 16
    # measure total width to center
    d = ImageDraw.Draw(img)
    total_w = 0
    widths = []
    for ch in letters:
        bbox = d.textbbox((0, 0), ch, font=title_font)
        w = bbox[2] - bbox[0]
        widths.append(w)
        total_w += w
    total_w += spacing * (len(letters) - 1)
    cur_x = (width - total_w) // 2
    title_y = mark_y + mark_size + 28
    for i, ch in enumerate(letters):
        t = i / max(1, len(letters) - 1)
        col = lerp(TEXT_LIGHT, SECONDARY, t)
        d.text((cur_x, title_y), ch, font=title_font, fill=(*col, 255))
        cur_x += widths[i] + spacing

    # Tagline centered
    tag_font = find_font(20, mono=True)
    tagline = "CYBERSECURITY  WORKBENCH"
    bbox = d.textbbox((0, 0), tagline, font=tag_font)
    tag_w = bbox[2] - bbox[0]
    tag_x = (width - tag_w) // 2
    tag_y = title_y + 88
    d.text((tag_x, tag_y), tagline, font=tag_font, fill=(*CYAN, 220))

    # mint accent under tagline
    bar_w = 80
    d.line([((width - bar_w) // 2, tag_y + 32),
            ((width + bar_w) // 2, tag_y + 32)],
           fill=(*MINT, 230), width=2)

    # subtitle line
    sub_font = find_font(14, mono=True)
    sub = "ARGUS PANOPTES  -  THE 100-EYED WATCHER"
    bbox = d.textbbox((0, 0), sub, font=sub_font)
    sub_w = bbox[2] - bbox[0]
    d.text(((width - sub_w) // 2, tag_y + 50), sub,
           font=sub_font, fill=(*PRIMARY, 160))

    return img


# -------------------------------------------------------------- driver
def render_mark_small(size: int, iris_color, ring_a, ring_b,
                      accent_color) -> Image.Image:
    """Simplified high-contrast mark for favicon-tier sizes (16/32/48).

    Drops: 12 satellite eyes, hexagram seal, scan-tick, striations.
    Keeps: bold gradient ring + bold almond + iris + pupil + catchlight.
    Reads cleanly at 16px because each element is sized to be >= ~2px.
    """
    S = size
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx = cy = S / 2

    # Backdrop disc
    draw.ellipse([1, 1, S - 1, S - 1], fill=BG_DARK)

    # Bold outer ring (gradient)
    ring_w = max(2, S // 8)
    ring_layer = gradient_ring(S, ring_w, ring_a, ring_b)
    img = Image.alpha_composite(img, ring_layer)
    draw = ImageDraw.Draw(img)

    # Iris (slightly smaller relative to canvas to leave breathing room)
    iris_r = max(2, int(S * 0.30))
    draw.ellipse([cx - iris_r, cy - iris_r, cx + iris_r, cy + iris_r],
                 fill=iris_color)

    # Pupil
    pupil_r = max(1, int(S * 0.13))
    draw.ellipse([cx - pupil_r, cy - pupil_r, cx + pupil_r, cy + pupil_r],
                 fill=BG_DARKER)

    # Catchlight
    if S >= 24:
        cl_r = max(1, S // 14)
        cl_x = cx - S * 0.06
        cl_y = cy - S * 0.06
        draw.ellipse([cl_x - cl_r, cl_y - cl_r, cl_x + cl_r, cl_y + cl_r],
                     fill=PRIMARY_LIGHT)

    return img


def small_normal(size):
    return render_mark_small(size, PRIMARY, PRIMARY, SECONDARY, PRIMARY)


def small_private(size):
    return render_mark_small(size, PRIVATE_DEEP, PRIVATE_DEEP,
                             (96, 78, 200), PRIVATE_LIGHT)


def small_vault(size):
    return render_mark_small(size, VAULT_GOLD, VAULT_GOLD,
                             (240, 200, 80), VAULT_LIGHT)


def save_ico(variant_fn, small_fn, out_path: Path):
    """Save multi-resolution ICO with per-size hand-rendered frames.

    Pillow's ICO writer is awkward for per-size custom frames (it tends to
    downscale a single base for all sizes). So we write the ICO format
    directly: a 6-byte header + 16-byte directory entries + concatenated
    PNG-encoded image data. This gives us full control over each frame.

    ICO format: https://en.wikipedia.org/wiki/ICO_(file_format)
    """
    import io
    import struct

    plan = [(16, True), (32, True), (48, True),
            (64, False), (128, False), (256, False)]

    frames = []
    for sz, use_small in plan:
        renderer = small_fn if use_small else variant_fn
        src = renderer(sz * 2)
        img = src.resize((sz, sz), Image.LANCZOS)
        # Encode as PNG (modern ICO supports PNG-encoded frames)
        buf = io.BytesIO()
        img.save(buf, format="PNG", optimize=True)
        frames.append((sz, buf.getvalue()))

    n = len(frames)
    # ICONDIR header (6 bytes): reserved=0, type=1 (icon), count
    out = bytearray()
    out += struct.pack("<HHH", 0, 1, n)

    # Directory entries (16 bytes each), then image data
    data_offset = 6 + 16 * n
    image_blob = bytearray()
    for sz, png_bytes in frames:
        # Width/Height: 0 means 256
        w = 0 if sz == 256 else sz
        h = 0 if sz == 256 else sz
        # ICONDIRENTRY: bWidth, bHeight, bColorCount, bReserved, wPlanes,
        # wBitCount, dwBytesInRes, dwImageOffset
        out += struct.pack(
            "<BBBBHHII",
            w, h, 0, 0,        # color count, reserved
            1, 32,             # color planes, bits per pixel
            len(png_bytes),    # bytes in resource
            data_offset,       # offset
        )
        image_blob += png_bytes
        data_offset += len(png_bytes)
    out += image_blob
    out_path.write_bytes(bytes(out))


def main():
    print(f"[argus] working in {HERE}")

    # 1. Master mark (1024) — defaults to Normal blue
    print("[1/11] argus_mark.png (1024)")
    mark = variant_normal(1024)
    mark.save(HERE / "argus_mark.png", optimize=True)

    # 2. Pre-rendered sizes
    print("[2/11] argus_mark_64.png")
    variant_normal(128).resize((64, 64), Image.LANCZOS).save(
        HERE / "argus_mark_64.png", optimize=True)
    print("[3/11] argus_mark_256.png")
    variant_normal(512).resize((256, 256), Image.LANCZOS).save(
        HERE / "argus_mark_256.png", optimize=True)

    # 3. Mode variants 1024
    print("[4/11] argus_normal.png")
    variant_normal(1024).save(HERE / "argus_normal.png", optimize=True)
    print("[5/11] argus_private.png")
    variant_private(1024).save(HERE / "argus_private.png", optimize=True)
    print("[6/11] argus_vault.png")
    variant_vault(1024).save(HERE / "argus_vault.png", optimize=True)

    # 4. Wordmark
    print("[7/11] argus_wordmark.png")
    render_wordmark(800, 200).save(HERE / "argus_wordmark.png", optimize=True)

    # 5. Splash
    print("[8/11] argus_splash.png")
    render_splash(800, 500).save(HERE / "argus_splash.png", optimize=True)

    # 6. ICO files (multi-res 16/32/48/64/128/256)
    #    Small sizes use the simplified mark; large sizes use the full mark.
    print("[9/11] argus_normal.ico")
    save_ico(variant_normal, small_normal, HERE / "argus_normal.ico")
    print("[10/11] argus_private.ico")
    save_ico(variant_private, small_private, HERE / "argus_private.ico")
    print("[11/11] argus_vault.ico")
    save_ico(variant_vault, small_vault, HERE / "argus_vault.ico")

    print("[argus] DONE — all assets generated.")


if __name__ == "__main__":
    main()
