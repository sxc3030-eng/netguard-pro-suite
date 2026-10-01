"""NetGuard AI — Icon Generator (.ico)
Generates netguard_icon.ico with multiple sizes for Windows.
Requires: pip install Pillow
"""
from PIL import Image, ImageDraw
import math, os

def draw_shield(draw, size):
    """Draw the NetGuard shield with N lettermark."""
    s = size / 200  # scale factor
    # Shield polygon
    shield = [
        (100*s, 18*s), (162*s, 42*s), (162*s, 100*s),
        (150*s, 132*s), (132*s, 155*s), (100*s, 178*s),
        (68*s, 155*s), (50*s, 132*s), (38*s, 100*s), (38*s, 42*s)
    ]
    # Shield fill (dark)
    draw.polygon(shield, fill=(18, 18, 26))
    # Shield outline gradient approximation (blue → purple)
    lw = max(2, int(3 * s))
    pts = shield + [shield[0]]
    for i in range(len(pts) - 1):
        t = i / (len(pts) - 1)
        r = int(77 + t * (180 - 77))
        g = int(159 + t * (125 - 159))
        b = int(255 + t * (255 - 255))
        draw.line([pts[i], pts[i + 1]], fill=(r, g, b), width=lw)
    # "N" lettermark
    nw = max(2, int(8 * s))
    # Left vertical
    draw.line([(72*s, 70*s), (72*s, 130*s)], fill=(77, 159, 255), width=nw)
    # Diagonal
    draw.line([(72*s, 70*s), (128*s, 130*s)], fill=(130, 140, 255), width=nw)
    # Right vertical
    draw.line([(128*s, 70*s), (128*s, 130*s)], fill=(180, 125, 255), width=nw)
    # Small glow dot center
    cx, cy = int(100*s), int(100*s)
    gr = max(2, int(4*s))
    draw.ellipse([cx-gr, cy-gr, cx+gr, cy+gr], fill=(77, 159, 255, 120))


def create_icon():
    sizes = [16, 24, 32, 48, 64, 128, 256]
    images = []
    for size in sizes:
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        # Dark circle background
        pad = max(0, int(size * 0.02))
        draw.ellipse([pad, pad, size - 1 - pad, size - 1 - pad], fill=(15, 15, 19, 255))
        # Shield
        draw_shield(draw, size)
        images.append(img)

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'netguard_icon.ico')
    images[-1].save(out, format='ICO', sizes=[(s, s) for s in sizes], append_images=images[:-1])
    print(f'[OK] {out}')
    # Also save a PNG for reference
    png_out = out.replace('.ico', '.png')
    images[-1].save(png_out)
    print(f'[OK] {png_out}')


if __name__ == '__main__':
    create_icon()
