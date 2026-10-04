#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  SentinelOS v2.0 — Lanceur Linux / macOS
#  Centre de Commandement Cybersecurite
# ═══════════════════════════════════════════════════════════

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SENTINEL_DIR="$SCRIPT_DIR/sentinel"

echo ""
echo "  ============================================"
echo "    SentinelOS v2.0"
echo "    Centre de Commandement Cybersecurite"
echo "  ============================================"
echo ""

# ───────────────────────────────────────────────────
# ETAPE 1 : Verifier si root (recommande, pas obligatoire)
# ───────────────────────────────────────────────────
if [ "$EUID" -ne 0 ] 2>/dev/null || [ "$(id -u)" -ne 0 ] 2>/dev/null; then
    echo "  [!] Pas lance en root/sudo."
    echo "  [INFO] Certaines fonctions (HoneyPot ports < 1024, FIM systeme) necessitent root."
    echo "  [INFO] Relancez avec: sudo $0"
    echo ""
    echo "  [*] Lancement en mode utilisateur..."
    echo ""
else
    echo "  [OK] Droits root confirmes."
fi

# ───────────────────────────────────────────────────
# ETAPE 2 : Verifier Python 3
# ───────────────────────────────────────────────────
PYTHON=""
if command -v python3 &>/dev/null; then
    PYTHON="python3"
elif command -v python &>/dev/null; then
    PYTHON="python"
else
    echo ""
    echo "  [!] Python 3 n'est pas installe."
    echo "      Installez-le :"
    echo "        Ubuntu/Debian : sudo apt install python3 python3-pip python3-venv"
    echo "        Fedora        : sudo dnf install python3 python3-pip"
    echo "        Arch          : sudo pacman -S python python-pip"
    echo "        macOS         : brew install python3"
    echo ""
    exit 1
fi

PY_VERSION=$($PYTHON --version 2>&1)
echo "  [OK] $PY_VERSION detecte ($PYTHON)"

# ───────────────────────────────────────────────────
# ETAPE 3 : Verifier WireGuard (optionnel, pour VPN Guard)
# ───────────────────────────────────────────────────
echo ""
echo "  [*] Verification de WireGuard..."

if command -v wg &>/dev/null; then
    echo "  [OK] WireGuard est installe."
else
    echo "  [!] WireGuard n'est pas installe."
    echo "  [INFO] VPN Guard fonctionnera sans VPN."

    # Tenter l'installation auto
    if command -v apt-get &>/dev/null; then
        echo "  [*] Tentative d'installation (apt)..."
        sudo apt-get install -y wireguard wireguard-tools 2>/dev/null && echo "  [OK] WireGuard installe !" || echo "  [INFO] Installation echouee. Installez manuellement: sudo apt install wireguard"
    elif command -v dnf &>/dev/null; then
        echo "  [*] Tentative d'installation (dnf)..."
        sudo dnf install -y wireguard-tools 2>/dev/null && echo "  [OK] WireGuard installe !" || echo "  [INFO] Installation echouee. Installez manuellement: sudo dnf install wireguard-tools"
    elif command -v pacman &>/dev/null; then
        echo "  [*] Tentative d'installation (pacman)..."
        sudo pacman -S --noconfirm wireguard-tools 2>/dev/null && echo "  [OK] WireGuard installe !" || echo "  [INFO] Installation echouee. Installez manuellement: sudo pacman -S wireguard-tools"
    elif command -v brew &>/dev/null; then
        echo "  [*] Tentative d'installation (brew)..."
        brew install wireguard-tools 2>/dev/null && echo "  [OK] WireGuard installe !" || echo "  [INFO] Installation echouee. Installez manuellement: brew install wireguard-tools"
    else
        echo "  [INFO] Installez WireGuard manuellement: https://www.wireguard.com/install/"
    fi
fi

# ───────────────────────────────────────────────────
# ETAPE 4 : Installer les dependances Python
# ───────────────────────────────────────────────────
echo ""
echo "  [*] Installation des dependances Python..."

# Installer pip si necessaire
$PYTHON -m pip --version &>/dev/null || {
    echo "  [*] Installation de pip..."
    $PYTHON -m ensurepip --upgrade 2>/dev/null || {
        if command -v apt-get &>/dev/null; then
            sudo apt-get install -y python3-pip 2>/dev/null
        fi
    }
}

# Dependances principales
$PYTHON -m pip install --quiet --break-system-packages \
    websockets psutil requests cryptography scapy 2>/dev/null \
|| $PYTHON -m pip install --quiet \
    websockets psutil requests cryptography scapy 2>/dev/null \
|| $PYTHON -m pip install --user --quiet \
    websockets psutil requests cryptography scapy 2>/dev/null

echo "  [OK] Dependances principales installees."

# Dependances optionnelles (GUI)
echo "  [*] Installation des dependances GUI (optionnelles)..."
$PYTHON -m pip install --quiet --break-system-packages \
    pywebview pystray Pillow 2>/dev/null \
|| $PYTHON -m pip install --quiet \
    pywebview pystray Pillow 2>/dev/null \
|| $PYTHON -m pip install --user --quiet \
    pywebview pystray Pillow 2>/dev/null \
|| echo "  [INFO] GUI optionnelle non installee. Le dashboard s'ouvrira dans le navigateur."

# pywebview Linux dependencies
if command -v apt-get &>/dev/null; then
    sudo apt-get install -y python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.1 2>/dev/null \
    || sudo apt-get install -y python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.0 2>/dev/null \
    || true
fi

echo "  [OK] Dependances installees."

# ───────────────────────────────────────────────────
# ETAPE 5 : Lancer SentinelOS
# ───────────────────────────────────────────────────
echo ""
echo "  ============================================"
echo "    Tout est pret ! Lancement de SentinelOS..."
echo "  ============================================"
echo ""
echo "  [*] Le Cortex va demarrer les 6 agents automatiquement :"
echo "      - NetGuard AI           (port 8765)"
echo "      - CleanGuard Pro         (port 8810)"
echo "      - MailShield Pro         (port 8801)"
echo "      - VPN Guard Pro          (port 8820)"
echo "      - HoneyPot Agent         (port 8830)"
echo "      - File Integrity Monitor (port 8840)"
echo ""
echo "  [*] Dashboard unifie sur le port 8900"
echo "  [*] SentinelOS va se lancer dans la barre des taches."
echo "  [*] Double-cliquez l'icone pour ouvrir le dashboard."
echo ""

cd "$SENTINEL_DIR"
$PYTHON "$SENTINEL_DIR/cortex.py"
