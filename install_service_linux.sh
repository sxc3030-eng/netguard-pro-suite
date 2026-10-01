#!/bin/bash
set -e

echo ""
echo " ╔══════════════════════════════════════════════╗"
echo " ║   NetGuard AI — Installation Service Linux ║"
echo " ║   Démarrage automatique via systemd         ║"
echo " ╚══════════════════════════════════════════════╝"
echo ""

# Vérifier les droits root
if [ "$EUID" -ne 0 ]; then
    echo " [ERREUR] Lance ce script avec sudo"
    exit 1
fi

# Trouver Python
PYTHON=$(which python3 2>/dev/null || which python 2>/dev/null)
if [ -z "$PYTHON" ]; then
    echo " [ERREUR] Python non trouvé. Installe python3 d'abord."
    exit 1
fi
echo " [OK] Python : $PYTHON"

# Dossier source
SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/netguard-pro"

# Copier les fichiers
echo " [..] Copie vers $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp -r "$SOURCE_DIR"/*.py "$INSTALL_DIR/" 2>/dev/null || true
cp -r "$SOURCE_DIR"/*.html "$INSTALL_DIR/" 2>/dev/null || true
cp -r "$SOURCE_DIR"/*.json "$INSTALL_DIR/" 2>/dev/null || true
cp -r "$SOURCE_DIR"/*.sh "$INSTALL_DIR/" 2>/dev/null || true
# Copy all sub-modules
for mod in wireguard mailshield cleanguard sentinel vpnguard honeypot fim recorder strikeback; do
    if [ -d "$SOURCE_DIR/$mod" ]; then
        cp -r "$SOURCE_DIR/$mod" "$INSTALL_DIR/"
        echo "   [OK] Module: $mod"
    fi
done
mkdir -p "$INSTALL_DIR/captures"
mkdir -p "$INSTALL_DIR/reports"
mkdir -p "$INSTALL_DIR/backups"
echo " [OK] Fichiers et modules copiés"

# Installer les dépendances
echo " [..] Installation des dépendances..."
pip3 install scapy websockets cryptography Pillow --break-system-packages 2>/dev/null \
    || pip3 install scapy websockets cryptography Pillow
echo " [OK] Dépendances installées"

# Créer le fichier service systemd
cat > /etc/systemd/system/netguard-pro.service << EOF
[Unit]
Description=NetGuard AI — Surveillance réseau temps réel
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$PYTHON $INSTALL_DIR/netguard.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netguard-pro
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
echo " [OK] Service systemd créé"

# Activer et démarrer
systemctl daemon-reload
systemctl enable netguard-pro
systemctl start netguard-pro
sleep 2

# Vérifier le statut
if systemctl is-active --quiet netguard-pro; then
    echo ""
    echo " ╔══════════════════════════════════════════════╗"
    echo " ║  Installation réussie !                     ║"
    echo " ║                                             ║"
    echo " ║  NetGuard AI tourne en arrière-plan.       ║"
    echo " ║  Démarre automatiquement au boot.           ║"
    echo " ║                                             ║"
    echo " ║  Dashboard : netguard_dashboard.html        ║"
    echo " ║  Logs : journalctl -u netguard-pro -f       ║"
    echo " ╚══════════════════════════════════════════════╝"
else
    echo " [ERREUR] Le service n'a pas démarré."
    echo " Vérifier : journalctl -u netguard-pro -n 20"
    exit 1
fi

echo ""
echo " Commandes utiles :"
echo "   sudo systemctl status netguard-pro   # Statut"
echo "   sudo systemctl stop netguard-pro     # Arrêter"
echo "   sudo systemctl restart netguard-pro  # Redémarrer"
echo "   journalctl -u netguard-pro -f        # Logs en direct"
echo "   sudo systemctl disable netguard-pro  # Désactiver au boot"
echo ""
