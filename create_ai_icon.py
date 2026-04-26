"""NetGuard Pro — AI Assistant Icon Generator (.ico)

Generates netguard_ai_icon.ico — the NetGuard shield with a 4-pointed
sparkle in place of the N lettermark, signalling the AI Assistant window.

Requires: pip install Pillow
"""
from PIL import Image, ImageDraw
import os


def draw_ai_shield(draw, size):
    s = size / 200
    shield = [
        (100*s, 18*s), (162*s, 42*s), (162*s, 100*s),
        (150*s, 132*s), (132*s, 155*s), (100*s, 178*s),
        (68*s, 155*s), (50*s, 132*s), (38*s, 100*s), (38*s, 42*s),
    ]
    draw.polygon(shield, fill=(18, 18, 26))

    lw = max(2, int(3 * s))
    pts = shield + [shield[0]]
    for i in range(len(pts) - 1):
        t = i / (len(pts) - 1)
        r = int(77 + t * (180 - 77))
        g = int(159 + t * (125 - 159))
        b = 255
        draw.line([pts[i], pts[i + 1]], fill=(r, g, b), width=lw)

    cx, cy = 100 * s, 100 * s
    arm = 38 * s
    thick = max(3, int(10 * s))

    draw.line([(cx, cy - arm), (cx, cy + arm)], fill=(77, 159, 255), width=thick)
    draw.line([(cx - arm, cy), (cx + arm, cy)], fill=(180, 125, 255), width=thick)

    diag = arm * 0.62
    diag_thick = max(2, int(6 * s))
    draw.line([(cx - diag, cy - diag), (cx + diag, cy + diag)],
              fill=(61, 255, 180), width=diag_thick)
    draw.line([(cx - diag, cy + diag), (cx + diag, cy - diag)],
              fill=(61, 255, 180), width=diag_thick)

    gr = max(3, int(7 * s))
    draw.ellipse([cx - gr, cy - gr, cx + gr, cy + gr], fill=(255, 255, 255))


def create_icon():
    sizes = [16, 24, 32, 48, 64, 128, 256]
    images = []
    for size in sizes:
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        pad = max(0, int(size * 0.02))
        draw.ellipse([pad, pad, size - 1 - pad, size - 1 - pad], fill=(15, 15, 19, 255))
        draw_ai_shield(draw, size)
        images.append(img)

    here = os.path.dirname(os.path.abspath(__file__))
    out_ico = os.path.join(here, 'netguard_ai_icon.ico')
    images[-1].save(out_ico, format='ICO',
                    sizes=[(s, s) for s in sizes],
                    append_images=images[:-1])
    print(f'[OK] {out_ico}')

    out_png = os.path.join(here, 'netguard_ai_icon.png')
    images[-1].save(out_png)
    print(f'[OK] {out_png}')


if __name__ == '__main__':
    create_icon()
