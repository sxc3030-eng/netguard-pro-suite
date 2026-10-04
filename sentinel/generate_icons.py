"""Generate Optimus Prime themed icons for all SentinelOS agents."""
from PIL import Image, ImageDraw
import os, math, subprocess

ICONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons")
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DESKTOP = os.path.join(os.environ['USERPROFILE'], 'OneDrive', 'Desktop')
os.makedirs(ICONS_DIR, exist_ok=True)

# Optimus Prime palette
RED = (204, 0, 0)
BLUE = (30, 58, 138)
CHROME = (192, 192, 192)
GOLD = (255, 215, 0)
DARK_STEEL = (20, 25, 40)
BORDER_BLUE = (40, 80, 200)

AGENTS = [
    {"key": "netguard",   "symbol": "shield", "color": (77, 159, 255),  "name": "NetGuard AI"},
    {"key": "cleanguard", "symbol": "sweep",  "color": (255, 179, 71),  "name": "CleanGuard Pro"},
    {"key": "mailshield", "symbol": "mail",   "color": (61, 255, 180),  "name": "MailShield Pro"},
    {"key": "vpnguard",   "symbol": "lock",   "color": (0, 212, 255),   "name": "VPN Guard Pro"},
    {"key": "honeypot",   "symbol": "trap",   "color": (255, 107, 107), "name": "HoneyPot Agent"},
    {"key": "fim",        "symbol": "file",   "color": (168, 85, 247),  "name": "FIM Agent"},
    {"key": "strikeback", "symbol": "sword",  "color": (255, 61, 61),   "name": "StrikeBack Agent"},
    {"key": "recorder",   "symbol": "record", "color": (96, 165, 250),  "name": "RecordAgent"},
    {"key": "sentinel",   "symbol": "bell",   "color": (0, 212, 255),   "name": "SentinelOS"},
]

# Script paths for shortcuts
SCRIPTS = {
    "netguard": os.path.join(BASE_DIR, "netguard.py"),
    "cleanguard": os.path.join(BASE_DIR, "cleanguard", "cleanguard.py"),
    "mailshield": os.path.join(BASE_DIR, "mailshield", "mailshield.py"),
    "vpnguard": os.path.join(BASE_DIR, "vpnguard", "vpnguard.py"),
}

def draw_bg(d, cx, cy, s, color):
    for r in range(int(118*s), int(128*s)):
        alpha = max(0, int(35 - (r - 118*s) * 3.5))
        d.ellipse([cx-r, cy-r, cx+r, cy+r], outline=(*color, alpha))
    for r in range(int(110*s), 0, -1):
        ratio = r / (110*s)
        d.ellipse([cx-r, cy-r, cx+r, cy+r], fill=(
            int(DARK_STEEL[0] + 8*(1-ratio)),
            int(DARK_STEEL[1] + 10*(1-ratio)),
            int(DARK_STEEL[2] + 15*(1-ratio)), 255))
    bw = max(2, int(3*s))
    d.ellipse([cx-int(110*s), cy-int(110*s), cx+int(110*s), cy+int(110*s)], outline=(*BORDER_BLUE, 180), width=bw)
    d.ellipse([cx-int(106*s), cy-int(106*s), cx+int(106*s), cy+int(106*s)], outline=(*color, 100), width=max(1, int(1.5*s)))


def draw_shield(d, cx, cy, s, c):
    pts = [(cx, cy-int(55*s)), (cx+int(45*s), cy-int(30*s)), (cx+int(40*s), cy+int(20*s)),
           (cx, cy+int(50*s)), (cx-int(40*s), cy+int(20*s)), (cx-int(45*s), cy-int(30*s))]
    d.polygon(pts, fill=(*c, 160), outline=(*c, 255))
    d.line([(cx-int(15*s), cy), (cx, cy+int(20*s)), (cx+int(25*s), cy-int(20*s))],
           fill=(255,255,255,200), width=max(2, int(4*s)))

def draw_sweep(d, cx, cy, s, c):
    d.arc([cx-int(40*s), cy-int(40*s), cx+int(40*s), cy+int(40*s)], 200, 340, fill=(*c, 255), width=max(3, int(6*s)))
    d.arc([cx-int(55*s), cy-int(30*s), cx+int(55*s), cy+int(50*s)], 220, 320, fill=(*c, 120), width=max(2, int(4*s)))
    d.ellipse([cx-int(8*s), cy-int(8*s), cx+int(8*s), cy+int(8*s)], fill=(*c, 200))

def draw_mail(d, cx, cy, s, c):
    l, r, t, b = cx-int(45*s), cx+int(45*s), cy-int(30*s), cy+int(30*s)
    d.rectangle([l, t, r, b], fill=(*c, 40), outline=(*c, 220), width=max(2, int(3*s)))
    d.line([(l, t), (cx, cy+int(5*s)), (r, t)], fill=(*c, 255), width=max(2, int(3*s)))
    d.ellipse([cx-int(15*s), cy-int(5*s), cx+int(15*s), cy+int(25*s)], fill=(*CHROME, 100), outline=(*CHROME, 180))

def draw_lock(d, cx, cy, s, c):
    bw, bh = int(40*s), int(35*s)
    d.rounded_rectangle([cx-bw//2, cy-int(5*s), cx+bw//2, cy-int(5*s)+bh], radius=int(5*s), fill=(*c, 180), outline=(*c, 255))
    d.arc([cx-int(18*s), cy-int(40*s), cx+int(18*s), cy], 180, 0, fill=(*c, 255), width=max(3, int(5*s)))
    d.ellipse([cx-int(6*s), cy+int(4*s), cx+int(6*s), cy+int(16*s)], fill=(20,25,40,255))

def draw_trap(d, cx, cy, s, c):
    pts = [(cx-int(30*s), cy-int(30*s)), (cx+int(30*s), cy-int(30*s)),
           (cx+int(40*s), cy+int(35*s)), (cx-int(40*s), cy+int(35*s))]
    d.polygon(pts, fill=(*c, 120), outline=(*c, 220))
    d.rounded_rectangle([cx-int(35*s), cy-int(40*s), cx+int(35*s), cy-int(28*s)], radius=int(4*s), fill=(*GOLD, 200))
    for r in range(int(20*s), 0, -1):
        alpha = int(60 * (1 - r/(20*s)))
        d.ellipse([cx-r, cy+int(5*s)-r//2, cx+r, cy+int(5*s)+r//2], fill=(*GOLD, alpha))

def draw_file(d, cx, cy, s, c):
    l, r, t, b = cx-int(30*s), cx+int(30*s), cy-int(45*s), cy+int(40*s)
    fold = int(15*s)
    pts = [(l, t), (r-fold, t), (r, t+fold), (r, b), (l, b)]
    d.polygon(pts, fill=(*c, 60), outline=(*c, 200))
    d.line([(r-fold, t), (r-fold, t+fold), (r, t+fold)], fill=(*c, 200), width=max(1, int(2*s)))
    d.line([(cx-int(12*s), cy+int(5*s)), (cx-int(2*s), cy+int(15*s)), (cx+int(18*s), cy-int(10*s))],
           fill=(*CHROME, 220), width=max(2, int(4*s)))

def draw_sword(d, cx, cy, s, c):
    d.line([(cx, cy-int(55*s)), (cx, cy+int(15*s))], fill=(*CHROME, 240), width=max(3, int(6*s)))
    d.polygon([(cx-int(5*s), cy-int(55*s)), (cx, cy-int(65*s)), (cx+int(5*s), cy-int(55*s))], fill=(*CHROME, 255))
    d.line([(cx-int(25*s), cy+int(15*s)), (cx+int(25*s), cy+int(15*s))], fill=(*GOLD, 255), width=max(3, int(5*s)))
    d.line([(cx, cy+int(15*s)), (cx, cy+int(40*s))], fill=(*c, 220), width=max(4, int(7*s)))
    d.ellipse([cx-int(6*s), cy+int(38*s), cx+int(6*s), cy+int(50*s)], fill=(*GOLD, 240))

def draw_record(d, cx, cy, s, c):
    d.ellipse([cx-int(50*s), cy-int(50*s), cx+int(50*s), cy+int(50*s)], outline=(*c, 200), width=max(3, int(5*s)))
    d.ellipse([cx-int(28*s), cy-int(28*s), cx+int(28*s), cy+int(28*s)], fill=(*RED, 230))
    d.ellipse([cx-int(10*s), cy-int(10*s), cx+int(10*s), cy+int(10*s)], fill=(255,50,50,255))

def draw_bell(d, cx, cy, s, c):
    bell_top, bell_bot = int(cy - 55*s), int(cy + 45*s)
    handle_r = int(10*s)
    d.arc([cx-handle_r, bell_top-int(20*s), cx+handle_r, bell_top-int(2*s)], 180, 0, fill=(*c, 255), width=max(2, int(3*s)))
    body = [(cx-int(28*s), bell_top+int(10*s)), (cx+int(28*s), bell_top+int(10*s)),
            (cx+int(52*s), bell_bot-int(8*s)), (cx-int(52*s), bell_bot-int(8*s))]
    d.polygon(body, fill=(*c, 180), outline=(*c, 255))
    brim_y = bell_bot-int(8*s)
    brim_h = max(3, int(7*s))
    d.rounded_rectangle([cx-int(58*s), brim_y, cx+int(58*s), brim_y+brim_h], radius=max(1,int(3*s)), fill=(*c, 240))
    cr = max(3, int(8*s))
    d.ellipse([cx-cr, brim_y+brim_h+cr+int(2*s)-cr, cx+cr, brim_y+brim_h+cr+int(2*s)+cr], fill=(*GOLD, 255))
    dr = max(5, int(18*s))
    dcx, dcy = cx+int(45*s), cy-int(45*s)
    d.ellipse([dcx-dr, dcy-dr, dcx+dr, dcy+dr], fill=(*RED, 255))

DRAW_FNS = {"shield": draw_shield, "sweep": draw_sweep, "mail": draw_mail, "lock": draw_lock,
            "trap": draw_trap, "file": draw_file, "sword": draw_sword, "record": draw_record, "bell": draw_bell}

sizes = [256, 128, 64, 48, 32, 16]

for agent in AGENTS:
    images = []
    for sz in sizes:
        img = Image.new('RGBA', (sz, sz), (0,0,0,0))
        d = ImageDraw.Draw(img)
        cx, cy = sz/2, sz/2
        s = sz/256
        draw_bg(d, cx, cy, s, agent["color"])
        fn = DRAW_FNS.get(agent["symbol"])
        if fn:
            fn(d, cx, cy, s, agent["color"])
        images.append(img)

    ico_path = os.path.join(ICONS_DIR, f"{agent['key']}.ico")
    images[0].save(ico_path, format='ICO', sizes=[(s,s) for s in sizes], append_images=images[1:])
    print(f"  [OK] {agent['key']}.ico")

    if agent['key'] == 'sentinel':
        desk_ico = os.path.join(DESKTOP, 'SentinelOS.ico')
        images[0].save(desk_ico, format='ICO', sizes=[(s,s) for s in sizes], append_images=images[1:])

# Create desktop shortcuts for main agents
print("\nCreating desktop shortcuts...")
import sys
pythonw = os.path.join(os.path.dirname(sys.executable), 'pythonw.exe')
if not os.path.exists(pythonw):
    pythonw = sys.executable

for agent in AGENTS:
    key = agent["key"]
    if key == "sentinel":
        # Main SentinelOS shortcut — launch cortex
        target = os.path.join(BASE_DIR, "sentinel", "cortex.py")
        ico = os.path.join(ICONS_DIR, "sentinel.ico")
        name = "SentinelOS"
        cwd = os.path.join(BASE_DIR, "sentinel")
    elif key in SCRIPTS:
        target = SCRIPTS[key]
        ico = os.path.join(ICONS_DIR, f"{key}.ico")
        name = agent["name"]
        cwd = os.path.dirname(target)
    else:
        # Agents without standalone scripts (honeypot, fim, strikeback, recorder)
        # Create shortcuts that just open SentinelOS
        continue

    lnk_path = os.path.join(DESKTOP, f"{name}.lnk")
    ps_cmd = f"""
$ws = New-Object -ComObject WScript.Shell
$s = $ws.CreateShortcut('{lnk_path}')
$s.TargetPath = '{pythonw}'
$s.Arguments = '"{target}"'
$s.WorkingDirectory = '{cwd}'
$s.IconLocation = '{ico},0'
$s.Description = '{name} - SentinelOS Security Suite'
$s.WindowStyle = 7
$s.Save()
"""
    result = subprocess.run(['powershell', '-Command', ps_cmd], capture_output=True, text=True)
    if result.returncode == 0:
        print(f"  [OK] {name}.lnk")
    else:
        print(f"  [ERR] {name}: {result.stderr[:100]}")

print("\nDone!")
