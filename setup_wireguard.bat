@echo off
title NetGuard AI — Configuration WireGuard VPN
echo.
echo  +================================================+
echo  ^|   NetGuard AI — Setup WireGuard VPN           ^|
echo  ^|   Generation des cles et configuration         ^|
echo  +================================================+
echo.

:: Verifier Python
where python >nul 2>&1
if %errorLevel% neq 0 (
    echo  [ERREUR] Python non trouve. Installe Python 3.10+
    pause
    exit /b 1
)

:: Verifier cryptography
echo  [INFO] Verification des dependances Python...
python -c "from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey; print('  [OK] cryptography disponible')" 2>nul
if %errorLevel% neq 0 (
    echo  [INFO] Installation de cryptography...
    pip install cryptography --quiet
)

:: Verifier WireGuard CLI
echo.
where wg >nul 2>&1
if %errorLevel% equ 0 (
    echo  [OK] WireGuard CLI disponible
    wg --version 2>nul
) else (
    if exist "C:\Program Files\WireGuard\wg.exe" (
        echo  [OK] WireGuard trouve dans Program Files
    ) else (
        echo  [INFO] WireGuard CLI non installe (mode fallback Python actif)
        echo         Les cles seront generees via Python cryptography
        echo         Pour le tunnel VPN, installe WireGuard : install_wireguard.bat
    )
)

:: Generer les cles serveur
echo.
echo  [INFO] Generation des cles serveur WireGuard...
set SCRIPT_DIR=%~dp0
python -c "
import sys, os, json
sys.path.insert(0, r'%SCRIPT_DIR%')
os.chdir(r'%SCRIPT_DIR%')

# Create wireguard dir
os.makedirs('wireguard', exist_ok=True)

keyfile = os.path.join('wireguard', 'server_keys.json')
if os.path.exists(keyfile):
    with open(keyfile) as f:
        keys = json.load(f)
    if keys.get('privkey') and keys.get('pubkey'):
        print(f'  [OK] Cles serveur existantes')
        print(f'  PubKey: {keys[\"pubkey\"]}')
        print()
        sys.exit(0)

# Generate new keys
import base64
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
    privkey_obj = X25519PrivateKey.generate()
    privkey = base64.b64encode(privkey_obj.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
    pubkey = base64.b64encode(privkey_obj.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
except ImportError:
    import subprocess
    r = subprocess.run(['wg','genkey'], capture_output=True, text=True)
    privkey = r.stdout.strip()
    r2 = subprocess.run(['wg','pubkey'], input=privkey, capture_output=True, text=True)
    pubkey = r2.stdout.strip()

with open(keyfile, 'w') as f:
    json.dump({'privkey': privkey, 'pubkey': pubkey}, f)
print(f'  [OK] Nouvelles cles generees !')
print(f'  PubKey: {pubkey}')
print()

# Generate server config
config = f'''[Interface]
PrivateKey = {privkey}
Address = 10.66.66.1/24
ListenPort = 51820
DNS = 1.1.1.1, 9.9.9.9
'''
with open(os.path.join('wireguard','wg0.conf'), 'w') as f:
    f.write(config)
print(f'  [OK] Config serveur: wireguard/wg0.conf')
"

echo.
echo  +================================================+
echo  ^|  Setup WireGuard termine !                     ^|
echo  ^|                                                ^|
echo  ^|  Cles serveur : wireguard/server_keys.json     ^|
echo  ^|  Config serveur: wireguard/wg0.conf            ^|
echo  ^|                                                ^|
echo  ^|  Pour ajouter des peers :                      ^|
echo  ^|    1. Lance NetGuard AI (python netguard.py)  ^|
echo  ^|    2. Va dans l'onglet WireGuard               ^|
echo  ^|    3. Ajoute un peer avec un nom               ^|
echo  ^|    4. Copie la config client generee           ^|
echo  +================================================+
echo.
pause
