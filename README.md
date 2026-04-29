# 🛡️ NetGuard Pro

> Tableau de bord de surveillance réseau en temps réel avec détection et blocage automatique des menaces — conçu pour les réseaux domestiques et la cybersécurité.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-GPL%20v3-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## 📸 Aperçu

NetGuard Pro combine la puissance de **tcpdump/Wireshark** avec un système de blocage automatique, le tout dans un tableau de bord moderne inspiré de Windows 11.

**Ce qu'il fait :**
- 📡 Capture tous les paquets réseau en temps réel (via Scapy)
- 🚫 Bloque automatiquement les menaces au niveau OS (iptables / netsh)
- 📊 Tableau de bord WebSocket live dans le navigateur
- 🔍 Détecte : scan de ports, brute force, SYN flood, DNS tunneling, P2P
- 🌍 Visualise l'origine géographique des connexions suspectes

---

## ⚡ Installation rapide

### Windows
```bash
# 1. Installer Npcap (requis pour la capture)
#    https://npcap.com/#download

# 2. Installer les dépendances Python
pip install scapy websockets

# 3. Double-cliquer sur LANCER_NETGUARD.bat (en tant qu'Administrateur)
```

### Linux
```bash
pip install scapy websockets
sudo python netguard.py
```

---

## 🚀 Utilisation

| Commande | Description |
|----------|-------------|
| `python netguard.py` | Capture réelle + blocage actif |
| `python netguard.py --no-block` | Surveillance uniquement |
| `python netguard.py --interface Wi-Fi` | Interface spécifique |
| `python netguard.py --port 9000` | Port WebSocket personnalisé |

Après le lancement, ouvre `netguard_dashboard.html` dans ton navigateur.

---

## 🔍 Système de détection

| Menace | Seuil | Action |
|--------|-------|--------|
| Scan de ports | > 15 ports / 10s | 🚫 Blocage IP |
| Brute Force SSH/RDP | > 8 tentatives / 30s | 🚫 Blocage IP |
| SYN Flood | > 200 SYN / 5s | 🚫 Blocage IP |
| Plages IP malveillantes | Tor, C&C connus | 🚫 Blocage IP |
| Ports sensibles externes | SSH, RDP, VNC | 🚫 Blocage IP |
| Ports Windows (SMB, SQL) | Tout accès externe | 🚫 Blocage IP |
| P2P / BitTorrent | Ports 6881-6889 | 🚫 Blocage IP |
| DNS Tunneling | > 50 requêtes / 5s | ⚠️ Alerte |

---

## 🔧 Blocage OS

- **Linux** : `iptables -I INPUT -s <IP> -j DROP`
- **Windows** : `netsh advfirewall firewall add rule ...`

Les IPs bloquées sont persistantes jusqu'au redémarrage ou déblocage manuel via le dashboard.

---

## 📁 Structure du projet

```
netguard/
├── netguard.py               # Backend Python principal
├── netguard_dashboard.html   # Interface web (WebSocket)
├── LANCER_NETGUARD.bat       # Lanceur Windows (admin auto)
├── LICENSE                   # GPL v3
└── README.md                 # Ce fichier
```

---

## ⚙️ Configuration

Les seuils de détection sont configurables directement dans `netguard.py` :

```python
port_scan_threshold:    int = 15    # ports différents avant blocage
port_scan_window:       int = 10    # fenêtre de temps (secondes)
brute_force_threshold:  int = 8     # tentatives avant blocage
brute_force_window:     int = 30
syn_flood_threshold:    int = 200   # SYN/sec avant blocage
syn_flood_window:       int = 5
dns_tunnel_threshold:   int = 50    # requêtes DNS/sec (alerte)
```

---

## 🖥️ Prérequis

| Composant | Version |
|-----------|---------|
| Python | 3.8+ |
| scapy | 2.5+ |
| websockets | 11.0+ |
| Npcap (Windows) | Dernière version |

---

## ⚠️ Avertissement légal

NetGuard Pro est conçu pour surveiller **uniquement les réseaux dont vous êtes propriétaire ou pour lesquels vous avez une autorisation explicite**. L'utilisation de cet outil sur des réseaux tiers sans autorisation est illégale. L'auteur décline toute responsabilité pour un usage abusif.

---

## 🤝 Contribuer

Les contributions sont les bienvenues !

1. Fork le projet
2. Crée une branche (`git checkout -b feature/ma-fonctionnalite`)
3. Commit tes changements (`git commit -m 'Ajout de ma fonctionnalité'`)
4. Push la branche (`git push origin feature/ma-fonctionnalite`)
5. Ouvre une Pull Request

---

## 📋 Feuille de route

- [ ] Support IPv6
- [ ] Export des logs en CSV/JSON
- [ ] Notifications (email, Discord webhook)
- [ ] Détection de malware par signature
- [ ] Liste noire GeoIP (bloquer par pays)
- [ ] Interface de configuration graphique
- [ ] Support Docker

---

## 📄 Licence

Ce projet est sous licence **GNU General Public License v3.0** — voir [LICENSE](LICENSE) pour les détails.

---

<div align="center">
  Fait avec ❤️ par <a href="https://github.com/sxc3030-eng">sxc3030-eng</a>
</div>

---

### Method

Architecture-first, AI-paired. Designed and shipped over **2 weeks in March 2026** with **Claude (Opus 4.6)** as paired implementation and audit partner. Each commit is cross-audited: code review, dependency vulnerability scan, threat-model check on the detection rules and OS-level blocking layer (iptables / netsh).

---
