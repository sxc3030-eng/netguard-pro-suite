#!/bin/bash
set -e

echo ""
echo " +===================================================+"
echo " |  NetGuard AI Suite - Installation Linux Complete  |"
echo " |  Tous les services via systemd                     |"
echo " +===================================================+"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo " [ERREUR] Lance ce script avec sudo"
    exit 1
fi

PYTHON=$(which python3 2>/dev/null || which python 2>/dev/null)
if [ -z "$PYTHON" ]; then
    echo " [ERREUR] Python non trouve. Installe python3 d'abord."
    exit 1
fi
echo " [OK] Python : $PYTHON"

SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/netguard-pro"

# Copy everything
echo " [..] Copie vers $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp -r "$SOURCE_DIR"/*.py "$INSTALL_DIR/" 2>/dev/null || true
cp -r "$SOURCE_DIR"/*.html "$INSTALL_DIR/" 2>/dev/null || true
cp -r "$SOURCE_DIR"/*.json "$INSTALL_DIR/" 2>/dev/null || true
cp -r "$SOURCE_DIR"/*.sh "$INSTALL_DIR/" 2>/dev/null || true
for mod in wireguard mailshield cleanguard sentinel vpnguard honeypot fim recorder strikeback; do
    if [ -d "$SOURCE_DIR/$mod" ]; then
        cp -r "$SOURCE_DIR/$mod" "$INSTALL_DIR/"
        echo "   [OK] Module: $mod"
    fi
done
mkdir -p "$INSTALL_DIR"/{captures,reports,backups}
echo " [OK] Fichiers copies"

# Dependencies
echo " [..] Installation des dependances..."
pip3 install scapy websockets cryptography Pillow --break-system-packages 2>/dev/null \
    || pip3 install scapy websockets cryptography Pillow
echo " [OK] Dependances installees"

# --- Service 1: NetGuard AI (main) ---
cat > /etc/systemd/system/netguard-pro.service << EOF
[Unit]
Description=NetGuard AI - Surveillance reseau temps reel
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
echo " [OK] Service: netguard-pro"

# --- Service 2: MailShield ---
if [ -f "$INSTALL_DIR/mailshield/mailshield.py" ]; then
cat > /etc/systemd/system/netguard-mailshield.service << EOF
[Unit]
Description=MailShield Pro - Secure Email Client
After=network.target netguard-pro.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR/mailshield
ExecStart=$PYTHON $INSTALL_DIR/mailshield/mailshield.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netguard-mailshield
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
echo " [OK] Service: netguard-mailshield"
fi

# --- Service 3: CleanGuard ---
if [ -f "$INSTALL_DIR/cleanguard/cleanguard.py" ]; then
cat > /etc/systemd/system/netguard-cleanguard.service << EOF
[Unit]
Description=CleanGuard - System Cleaner
After=network.target netguard-pro.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR/cleanguard
ExecStart=$PYTHON $INSTALL_DIR/cleanguard/cleanguard.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netguard-cleanguard
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
echo " [OK] Service: netguard-cleanguard"
fi

# --- Service 4: Sentinel OS ---
if [ -f "$INSTALL_DIR/sentinel/cortex.py" ]; then
cat > /etc/systemd/system/netguard-sentinel.service << EOF
[Unit]
Description=Sentinel OS - Threat Intelligence & SOAR
After=network.target netguard-pro.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR/sentinel
ExecStart=$PYTHON $INSTALL_DIR/sentinel/cortex.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netguard-sentinel
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
echo " [OK] Service: netguard-sentinel"
fi

# --- Service 5: VPNGuard ---
if [ -f "$INSTALL_DIR/vpnguard/vpnguard.py" ]; then
cat > /etc/systemd/system/netguard-vpnguard.service << EOF
[Unit]
Description=VPNGuard - VPN Connection Manager
After=network.target netguard-pro.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR/vpnguard
ExecStart=$PYTHON $INSTALL_DIR/vpnguard/vpnguard.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netguard-vpnguard
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
echo " [OK] Service: netguard-vpnguard"
fi

# Enable and start all
systemctl daemon-reload
for svc in netguard-pro netguard-mailshield netguard-cleanguard netguard-sentinel netguard-vpnguard; do
    if [ -f "/etc/systemd/system/${svc}.service" ]; then
        systemctl enable "$svc"
        systemctl start "$svc"
        if systemctl is-active --quiet "$svc"; then
            echo " [RUN] $svc actif"
        else
            echo " [ERR] $svc n'a pas demarre - voir: journalctl -u $svc -n 20"
        fi
    fi
done

echo ""
echo " +===================================================+"
echo " |  Installation terminee !                           |"
echo " |                                                    |"
echo " |  Tous les services demarrent au boot automatique.  |"
echo " |                                                    |"
echo " |  Commandes utiles :                                |"
echo " |  sudo systemctl status netguard-*                  |"
echo " |  journalctl -u netguard-pro -f                     |"
echo " +===================================================+"
echo ""
