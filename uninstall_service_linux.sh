#!/bin/bash
if [ "$EUID" -ne 0 ]; then echo "sudo requis"; exit 1; fi
systemctl stop netguard-pro 2>/dev/null
systemctl disable netguard-pro 2>/dev/null
rm -f /etc/systemd/system/netguard-pro.service
systemctl daemon-reload
echo "[OK] Service NetGuard AI désinstallé."
