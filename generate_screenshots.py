"""Generate dashboard mockup screenshots for the vitrine"""
from PIL import Image, ImageDraw, ImageFont
import os, random

def create_mockup(filename, title, subtitle, color, panels):
    w, h = 800, 500
    img = Image.new('RGB', (w, h), (10, 10, 18))
    draw = ImageDraw.Draw(img)
    try:
        ft = ImageFont.truetype('C:/Windows/Fonts/arialbd.ttf', 18)
        fs = ImageFont.truetype('C:/Windows/Fonts/arial.ttf', 12)
        fv = ImageFont.truetype('C:/Windows/Fonts/consolab.ttf', 28)
        fl = ImageFont.truetype('C:/Windows/Fonts/arial.ttf', 10)
    except:
        ft = fs = fv = fl = ImageFont.load_default()

    # Top bar
    draw.rectangle([0, 0, w, 44], fill=(17, 17, 24))
    draw.rectangle([0, 44, w, 45], fill=color)
    for i, c in enumerate([(255,95,87), (255,189,46), (39,201,63)]):
        draw.ellipse([12+i*18, 15, 24+i*18, 27], fill=c)
    draw.text((80, 13), title, fill=(240, 240, 250), font=ft)
    draw.text((80, 30), subtitle, fill=(120, 120, 150), font=fs)

    # Metric cards
    y = 60
    cw = (w - 60) // 4
    for i, (val, label, cc) in enumerate(panels[:4]):
        x = 15 + i * (cw + 10)
        draw.rounded_rectangle([x, y, x+cw, y+70], radius=8, fill=(20, 20, 32), outline=(40,40,60))
        draw.text((x+15, y+12), val, fill=cc, font=fv)
        draw.text((x+15, y+48), label, fill=(100,100,130), font=fl)

    # Chart
    cy = 150
    draw.rounded_rectangle([15, cy, w//2-5, cy+160], radius=8, fill=(20,20,32), outline=(40,40,60))
    draw.text((30, cy+10), 'Traffic', fill=(150,150,170), font=fs)
    random.seed(hash(title))
    pts = [(30 + i*12, cy + 80 + random.randint(-40, 30)) for i in range(30)]
    for i in range(len(pts)-1):
        draw.line([pts[i], pts[i+1]], fill=color, width=2)

    # Right panel
    draw.rounded_rectangle([w//2+5, cy, w-15, cy+160], radius=8, fill=(20,20,32), outline=(40,40,60))
    draw.text((w//2+20, cy+10), 'Activity', fill=(150,150,170), font=fs)
    for i in range(6):
        bw = random.randint(40, 160)
        by = cy + 35 + i * 20
        draw.rounded_rectangle([w//2+20, by, w//2+20+bw, by+12], radius=3, fill=color)

    # Bottom row
    bot = 330
    labels = ['Threats', 'Protocols', 'Top IPs']
    for i in range(3):
        x = 15 + i * (w//3 - 5)
        draw.rounded_rectangle([x, bot, x + w//3 - 15, bot+150], radius=8, fill=(20,20,32), outline=(40,40,60))
        draw.text((x+15, bot+10), labels[i], fill=(150,150,170), font=fs)
        for j in range(5):
            bw = random.randint(30, 130)
            by = bot + 35 + j * 22
            fc = (color[0], color[1], max(color[2]-40*j, 50))
            draw.rounded_rectangle([x+15, by, x+15+bw, by+14], radius=3, fill=fc)

    os.makedirs('screenshots', exist_ok=True)
    img.save(f'screenshots/{filename}', 'PNG')
    print(f'  [OK] screenshots/{filename}')

mockups = [
    ('netguard_dashboard.png', 'NetGuard AI', 'Dashboard temps reel', (77,159,255),
     [('12,847','Packets/s',(77,159,255)),('342','Blocked',(255,77,106)),('18','Threats',(255,179,71)),('847','Connections',(61,255,180))]),
    ('netguard_analyze.png', 'NetGuard Analyze', 'Analyse approfondie des paquets', (180,125,255),
     [('DPI','Deep Inspect',(180,125,255)),('TLS 1.3','Protocol',(77,159,255)),('SHA256','Hash',(61,255,180)),('JA3','Fingerprint',(255,179,71))]),
    ('netguard_map.png', 'NetGuard Map', 'Carte mondiale des menaces', (255,77,106),
     [('42','Countries',(255,77,106)),('1,203','Geo Blocked',(255,179,71)),('CN','Top Source',(77,159,255)),('US','Top Target',(61,255,180))]),
    ('netguard_history.png', 'NetGuard History', 'Historique des evenements', (255,179,71),
     [('7,421','Events',(255,179,71)),('342','Alerts',(255,77,106)),('30d','Retention',(77,159,255)),('99.2%','Uptime',(61,255,180))]),
    ('netguard_network.png', 'NetGuard Network', 'Scan LAN et peripheriques', (61,255,180),
     [('24','Devices',(61,255,180)),('3','Servers',(77,159,255)),('192.168','Subnet',(180,125,255)),('5','Unknown',(255,77,106))]),
    ('netguard_panels.png', 'NetGuard Panels', 'Vue multi-ecrans detachable', (120,200,255),
     [('4','Panels',(120,200,255)),('Live','Mode',(61,255,180)),('60s','Refresh',(255,179,71)),('FHD','Resolution',(180,125,255))]),
    ('netguard_service.png', 'NetGuard Service', 'Status des services systeme', (100,220,160),
     [('9','Services',(100,220,160)),('8','Running',(61,255,180)),('1','Stopped',(255,77,106)),('99%','Health',(77,159,255))]),
    ('mailshield.png', 'MailShield Pro', 'Client email securise v2.0', (77,159,255),
     [('1,204','Emails',(77,159,255)),('47','Spam',(255,77,106)),('12','Phishing',(255,179,71)),('99.1%','Safe',(61,255,180))]),
    ('cleanguard.png', 'CleanGuard', 'Scanner antimalware', (255,77,106),
     [('24.3GB','Cleaned',(255,77,106)),('7','Threats',(255,179,71)),('12,000','Files',(77,159,255)),('Clean','Status',(61,255,180))]),
    ('sentinel.png', 'Sentinel OS', 'SOAR & Threat Intelligence', (180,125,255),
     [('9','Agents',(180,125,255)),('3','Playbooks',(77,159,255)),('47k','Intel IOCs',(255,179,71)),('Live','Status',(61,255,180))]),
    ('vpnguard.png', 'VPNGuard', 'VPN + WireGuard Manager', (61,255,180),
     [('WG0','Tunnel',(61,255,180)),('3','Peers',(77,159,255)),('51820','Port',(180,125,255)),('Active','Status',(61,255,180))]),
    ('honeypot.png', 'Honeypot', 'Pieges a attaquants', (255,179,71),
     [('5','Traps',(255,179,71)),('127','Caught',(255,77,106)),('SSH','Top Trap',(77,159,255)),('Active','Status',(61,255,180))]),
    ('fim.png', 'FIM', 'File Integrity Monitor', (100,180,255),
     [('2,847','Watched',(100,180,255)),('3','Changed',(255,77,106)),('SHA256','Hash',(180,125,255)),('Secure','Status',(61,255,180))]),
    ('recorder.png', 'Recorder', 'Forensic PCAP Capture', (200,150,255),
     [('4.2GB','Captured',(200,150,255)),('23','Sessions',(77,159,255)),('PCAP','Format',(255,179,71)),('Active','Status',(61,255,180))]),
    ('strikeback.png', 'StrikeBack', 'Reponse active aux attaques', (255,100,100),
     [('47','Blocked',(255,100,100)),('12','Tarpit',(255,179,71)),('5','Decoys',(180,125,255)),('Armed','Status',(61,255,180))]),
]

for m in mockups:
    create_mockup(*m)
print(f'\n=== {len(mockups)} screenshots ===')
