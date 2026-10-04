"""
Argus icon — Hieratic Cipher edition.

Generates a museum-quality sigil that downsamples cleanly to favicon sizes.
Original SVG-style geometry rendered at 4096px supersample, downsampled with
LANCZOS for crisp edges at 1024 / 256 / 128 / 64 / 32 / 16.

Palette:
  bg     #0a0e14  cyber dark base
  blue   #4d9fff  primary iris
  purple #b47dff  secondary gradient pair
  gold   #d4af37  vault accent (single charged use)
  mint   #3dffb4  scan-line / liveness signal
"""
from __future__ import annotations
import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

HERE = Path(__file__).resolve().parent

# Palette (RGBA)
BG_DEEP = (10, 14, 20, 255)       # #0a0e14
BG_INNER = (18, 26, 38, 255)      # subtle radial lift toward center
BLUE = (77, 159, 255, 255)        # #4d9fff
BLUE_DEEP = (35, 90, 180, 255)
PURPLE = (180, 125, 255, 255)     # #b47dff
PURPLE_DEEP = (110, 70, 180, 255)
GOLD = (212, 175, 55, 255)        # #d4af37
MINT = (61, 255, 180, 255)        # #3dffb4
WHITE_GLINT = (240, 248, 255, 255)
INK = (5, 8, 12, 255)             # near-black pupil

# Working at 4× supersample for crisp downsampling
SUPER = 4
FINAL = 1024
W = FINAL * SUPER

# Convenient center + radii (working scale)
CX, CY = W // 2, W // 2
R_OUTER = int(W * 0.475)            # outer rim
R_DODECAGON = int(W * 0.405)        # 12-sat-eyes radius
R_VESICA = int(W * 0.27)            # central almond half-extent
R_IRIS_OUTER = int(W * 0.205)       # main iris outer rim
R_IRIS_INNER = int(W * 0.155)
R_PUPIL = int(W * 0.063)


def lerp(a: tuple, b: tuple, t: float) -> tuple:
    """Linear interpolation between two RGBA tuples."""
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(4))


def radial_background(img: Image.Image) -> None:
    """Subtle radial lift from BG_DEEP at edges to BG_INNER near center."""
    px = img.load()
    max_d = math.hypot(CX, CY)
    for y in range(W):
        for x in range(W):
            d = math.hypot(x - CX, y - CY) / max_d
            t = 1.0 - min(1.0, d * 1.4)  # taper
            t = max(0.0, t) ** 2
            px[x, y] = lerp(BG_DEEP, BG_INNER, t * 0.55)


def radial_background_fast(img: Image.Image) -> None:
    """Fast version: blurred concentric circle stack instead of per-pixel."""
    glow = Image.new("RGBA", (W, W), BG_DEEP)
    gd = ImageDraw.Draw(glow)
    steps = 60
    for i in range(steps):
        t = i / (steps - 1)
        r = int((1.0 - t) * (W * 0.55))
        c = lerp(BG_DEEP, BG_INNER, (1 - t) * 0.55)
        gd.ellipse([CX - r, CY - r, CX + r, CY + r], fill=c)
    glow = glow.filter(ImageFilter.GaussianBlur(radius=W // 32))
    img.paste(glow, (0, 0))


def stroke_polygon(draw: ImageDraw.ImageDraw, points, color, width: int) -> None:
    pts = list(points) + [points[0]]
    draw.line(pts, fill=color, width=width, joint="curve")


def draw_hexagram(draw: ImageDraw.ImageDraw, cx: int, cy: int, r: int, color, width: int) -> None:
    """Solomon's seal / Star of David — two overlapping triangles."""
    def tri(rotation_deg: float):
        return [
            (cx + r * math.cos(math.radians(rotation_deg + a)),
             cy + r * math.sin(math.radians(rotation_deg + a)))
            for a in (-90, 30, 150)
        ]
    stroke_polygon(draw, tri(0), color, width)
    stroke_polygon(draw, tri(60), color, width)


def draw_dodecagon(draw: ImageDraw.ImageDraw, cx: int, cy: int, r: int, color, width: int) -> list:
    """12-sided polygon, returns vertex list for satellite-eye placement."""
    verts = [
        (cx + r * math.cos(math.radians(-90 + i * 30)),
         cy + r * math.sin(math.radians(-90 + i * 30)))
        for i in range(12)
    ]
    stroke_polygon(draw, verts, color, width)
    return verts


def draw_satellite_eye(draw: ImageDraw.ImageDraw, cx: int, cy: int, r: int) -> None:
    """A small almond-shape eye with iris + pupil. r = half-width."""
    # almond body (vesica piscis approximation via two arcs)
    h = int(r * 0.55)
    # outer dark ring
    draw.ellipse([cx - r, cy - h, cx + r, cy + h], fill=BG_DEEP)
    # iris ring
    ir = int(r * 0.66)
    ih = int(h * 0.85)
    draw.ellipse([cx - ir, cy - ih, cx + ir, cy + ih], fill=BLUE_DEEP)
    # iris bright
    ir2 = int(r * 0.45)
    ih2 = int(h * 0.65)
    draw.ellipse([cx - ir2, cy - ih2, cx + ir2, cy + ih2], fill=BLUE)
    # pupil
    pr = max(2, int(r * 0.18))
    draw.ellipse([cx - pr, cy - pr, cx + pr, cy + pr], fill=INK)
    # tiny catchlight
    cr = max(1, int(r * 0.07))
    draw.ellipse([cx - pr - cr, cy - pr, cx - pr + cr, cy - pr + 2 * cr],
                 fill=WHITE_GLINT)


def draw_central_iris(base: Image.Image) -> None:
    """The master eye — concentric iris with striations + pupil + bloom."""
    draw = ImageDraw.Draw(base, "RGBA")

    # Outer halo (will be blurred separately on a layer)
    halo_layer = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    hd = ImageDraw.Draw(halo_layer)
    for i in range(8, 0, -1):
        rr = R_IRIS_OUTER + i * (W // 200)
        alpha = int(60 - i * 6)
        hd.ellipse([CX - rr, CY - rr, CX + rr, CY + rr],
                   fill=(*BLUE[:3], max(0, alpha)))
    halo_layer = halo_layer.filter(ImageFilter.GaussianBlur(radius=W // 80))
    base.alpha_composite(halo_layer)

    # Iris outer rim — purple→blue gradient via concentric strokes
    layers = 28
    for i in range(layers):
        t = i / (layers - 1)
        rr = int(R_IRIS_OUTER - (R_IRIS_OUTER - R_IRIS_INNER) * t)
        col = lerp(PURPLE_DEEP, BLUE, t)
        draw.ellipse([CX - rr, CY - rr, CX + rr, CY + rr], outline=col, width=W // 350)

    # Iris bright center fill
    draw.ellipse([CX - R_IRIS_INNER, CY - R_IRIS_INNER,
                  CX + R_IRIS_INNER, CY + R_IRIS_INNER],
                 fill=BLUE_DEEP)

    # Iris striations — radial lines from pupil out
    striations = 60
    for i in range(striations):
        ang = math.radians(i * (360 / striations))
        x1 = CX + R_PUPIL * math.cos(ang) * 1.2
        y1 = CY + R_PUPIL * math.sin(ang) * 1.2
        x2 = CX + R_IRIS_INNER * math.cos(ang) * 0.97
        y2 = CY + R_IRIS_INNER * math.sin(ang) * 0.97
        col = BLUE if i % 5 != 0 else lerp(BLUE, GOLD, 0.7)
        draw.line([(x1, y1), (x2, y2)], fill=col, width=max(1, W // 800))

    # Inner iris — slightly brighter ring
    inner_r = int(R_PUPIL * 1.6)
    draw.ellipse([CX - inner_r, CY - inner_r, CX + inner_r, CY + inner_r],
                 outline=lerp(BLUE, MINT, 0.2), width=W // 400)

    # Pupil — true black with soft edge
    draw.ellipse([CX - R_PUPIL, CY - R_PUPIL, CX + R_PUPIL, CY + R_PUPIL], fill=INK)

    # Catchlight on pupil — top-left, signature glint
    cl_r = int(R_PUPIL * 0.32)
    cl_x = CX - int(R_PUPIL * 0.4)
    cl_y = CY - int(R_PUPIL * 0.45)
    draw.ellipse([cl_x - cl_r, cl_y - cl_r, cl_x + cl_r, cl_y + cl_r],
                 fill=WHITE_GLINT)
    cl_r2 = int(cl_r * 0.45)
    draw.ellipse([cl_x - cl_r2 + cl_r, cl_y - cl_r2 + cl_r,
                  cl_x + cl_r2 + cl_r, cl_y + cl_r2 + cl_r],
                 fill=(*WHITE_GLINT[:3], 200))


def draw_vesica_frame(base: Image.Image) -> None:
    """Vesica piscis — two overlapping circles forming the almond around the eye."""
    layer = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    # circles offset horizontally to form the lens shape
    rr = R_VESICA
    offset = int(rr * 0.55)
    sw = max(3, W // 360)
    d.ellipse([CX - rr - offset, CY - rr, CX + rr - offset, CY + rr],
              outline=(*MINT[:3], 110), width=sw)
    d.ellipse([CX - rr + offset, CY - rr, CX + rr + offset, CY + rr],
              outline=(*MINT[:3], 110), width=sw)
    # gentle blur for ethereal quality
    layer = layer.filter(ImageFilter.GaussianBlur(radius=W // 800))
    base.alpha_composite(layer)


def draw_scan_tick(base: Image.Image) -> None:
    """Mint horizontal scan-tick across the iris — 'live watching' signal."""
    layer = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    y = CY - int(W * 0.005)
    half = int(R_IRIS_OUTER * 1.05)
    sw = max(2, W // 600)
    # gradient fade from edges
    steps = 16
    for i in range(steps):
        t = i / (steps - 1)
        x_left = int(CX - half * (1.0 - t * 0.05))
        x_right = int(CX + half * (1.0 - t * 0.05))
        alpha = int(180 * (1 - abs(t - 0.5) * 2))
        d.line([(x_left, y), (x_right, y)], fill=(*MINT[:3], alpha), width=sw)
    layer = layer.filter(ImageFilter.GaussianBlur(radius=W // 1200))
    base.alpha_composite(layer)


def draw_outer_rim(draw: ImageDraw.ImageDraw) -> None:
    """Cyan-to-purple gradient ring at the outer boundary."""
    layers = 36
    for i in range(layers):
        t = i / (layers - 1)
        rr = R_OUTER - i * (W // 1100)
        col = lerp(BLUE, PURPLE, t)
        draw.ellipse([CX - rr, CY - rr, CX + rr, CY + rr], outline=col, width=W // 600)


def draw_gold_micro_marks(draw: ImageDraw.ImageDraw) -> None:
    """Tiny gold tick marks at cardinal positions on the dodecagon — sparing accent."""
    for i in (0, 3, 6, 9):  # 12, 3, 6, 9 o'clock only
        ang = math.radians(-90 + i * 30)
        x = CX + R_DODECAGON * 1.04 * math.cos(ang)
        y = CY + R_DODECAGON * 1.04 * math.sin(ang)
        r = max(3, W // 350)
        draw.ellipse([x - r, y - r, x + r, y + r], fill=GOLD)


def make_full_icon() -> Image.Image:
    img = Image.new("RGBA", (W, W), BG_DEEP)
    radial_background_fast(img)
    draw = ImageDraw.Draw(img, "RGBA")

    # outer rim
    draw_outer_rim(draw)

    # faint hexagram behind everything
    hex_layer = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    hd = ImageDraw.Draw(hex_layer)
    draw_hexagram(hd, CX, CY, int(R_VESICA * 1.05),
                  (*PURPLE[:3], 50), W // 700)
    hex_layer = hex_layer.filter(ImageFilter.GaussianBlur(radius=W // 1000))
    img.alpha_composite(hex_layer)

    # 12-sided lattice + satellite eyes
    verts = draw_dodecagon(draw, CX, CY, R_DODECAGON,
                           (*BLUE[:3], 170), W // 800)
    sat_r = int(W * 0.038)
    for (vx, vy) in verts:
        draw_satellite_eye(draw, int(vx), int(vy), sat_r)

    # micro gold accents on cardinals
    draw_gold_micro_marks(draw)

    # vesica frame
    draw_vesica_frame(img)

    # central master eye
    draw_central_iris(img)

    # scan tick
    draw_scan_tick(img)

    return img


def make_simplified_favicon() -> Image.Image:
    """Stripped-down version for 16/32/48 px — just iris + outer ring + pupil + catchlight."""
    img = Image.new("RGBA", (W, W), BG_DEEP)
    radial_background_fast(img)
    draw = ImageDraw.Draw(img, "RGBA")

    # outer ring
    rr = int(W * 0.46)
    draw.ellipse([CX - rr, CY - rr, CX + rr, CY + rr],
                 outline=BLUE, width=W // 35)

    # iris ring
    R = int(W * 0.36)
    draw.ellipse([CX - R, CY - R, CX + R, CY + R], fill=BLUE_DEEP)
    draw.ellipse([CX - R, CY - R, CX + R, CY + R],
                 outline=PURPLE, width=W // 60)

    # bright iris
    R2 = int(W * 0.27)
    draw.ellipse([CX - R2, CY - R2, CX + R2, CY + R2], fill=BLUE)

    # pupil
    P = int(W * 0.115)
    draw.ellipse([CX - P, CY - P, CX + P, CY + P], fill=INK)

    # catchlight
    cl = int(P * 0.42)
    cx = CX - int(P * 0.42)
    cy = CY - int(P * 0.45)
    draw.ellipse([cx - cl, cy - cl, cx + cl, cy + cl], fill=WHITE_GLINT)

    return img


def downsample(img: Image.Image, size: int) -> Image.Image:
    return img.resize((size, size), Image.Resampling.LANCZOS)


def write_ico(path: Path, full_img: Image.Image, simple_img: Image.Image) -> None:
    """Build a multi-res ICO with the simplified mark at small sizes and full mark at large."""
    sizes = [(16, simple_img), (32, simple_img), (48, simple_img),
             (64, full_img), (128, full_img), (256, full_img)]
    pngs = []
    for sz, src in sizes:
        ds = downsample(src, sz)
        # Save each frame as a PNG-encoded ICO entry via Pillow's ico writer.
        pngs.append(ds)
    # Pillow forces sizes from the base image, so save with the largest as base
    # and pass `sizes` to get correct multi-res. Each frame uses LANCZOS.
    base = downsample(full_img, 256)
    base.save(path, format="ICO",
              sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])


def main() -> None:
    print("Rendering Argus icon (Hieratic Cipher)...")
    full = make_full_icon()
    simple = make_simplified_favicon()

    # Final outputs
    out_full_1024 = downsample(full, 1024)
    out_full_512 = downsample(full, 512)
    out_full_256 = downsample(full, 256)
    out_simple_64 = downsample(simple, 64)
    out_simple_48 = downsample(simple, 48)

    out_full_1024.save(HERE / "argus_canvas_icon.png", optimize=True)
    out_full_512.save(HERE / "argus_canvas_icon_512.png", optimize=True)
    out_full_256.save(HERE / "argus_canvas_icon_256.png", optimize=True)
    out_simple_64.save(HERE / "argus_canvas_icon_simple_64.png", optimize=True)
    out_simple_48.save(HERE / "argus_canvas_icon_simple_48.png", optimize=True)

    # Multi-res .ico (overwrites previous argus_normal.ico — refined edition)
    write_ico(HERE / "argus_canvas.ico", full, simple)

    print("Done.")
    for f in sorted(HERE.glob("argus_canvas*.png")) + sorted(HERE.glob("argus_canvas*.ico")):
        print(f"  {f.name}: {f.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
