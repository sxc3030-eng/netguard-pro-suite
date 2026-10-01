# Licences des composants tiers — NetGuard AI

NetGuard AI est distribué sous **GPL v3 ou ultérieure** (voir `LICENSE`).

| Composant | Usage | Licence | Note |
|---|---|---|---|
| scapy | capture et analyse de paquets | **GPL v2 (uniquement)** | ⚠ GPLv2-only et GPLv3 ne sont pas compatibles dans un même binaire combiné. Voir « Décisions à prendre » dans `docs/SUPERAUDIT_2026-09-30.md` : relicencier NetGuard en « GPL v2 ou ultérieure », ou isoler scapy dans un processus de capture séparé. |
| Npcap | pilote de capture Windows | Npcap License (propriétaire, gratuit pour usage personnel ; OEM pour redistribution) | **Non redistribué** : l'utilisateur l'installe lui-même depuis npcap.com (boîte de dialogue au premier lancement). |
| websockets | serveur WebSocket du tableau de bord | BSD-3-Clause | |
| psutil | identification des processus, connexions | BSD-3-Clause | |
| pywebview | fenêtre native | BSD-3-Clause | nécessite WebView2 Runtime (Microsoft, EULA WebView2) |
| pystray, Pillow | icône de la barre système | MIT / HPND | |
| geoip2 (MaxMind) | lecture de la base GeoLite2 | Apache-2.0 | |
| GeoLite2 City/ASN (données) | géolocalisation locale | **GeoLite2 EULA** (MaxMind) | **Non redistribuée** dans le paquet : téléchargée par l'utilisateur avec sa propre clé MaxMind (`tools/geoip_update.py`). Attribution requise : « This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com ». |
| d3.js 7.8.5, topojson 3.0.2 | carte mondiale | ISC / BSD-3-Clause | chargés depuis cdnjs avec intégrité SRI |
| world-atlas (TopoJSON) | fond de carte | ISC | chargé depuis jsDelivr |
| Geist Mono, Outfit (polices) | interface | OFL 1.1 | Google Fonts |
| Emerging Threats Open | règles IDS (téléchargées sur demande) | BSD | les règles livrées dans le code sont des réécritures maison (SIDs 9000xxx) |
| Feodo Tracker (abuse.ch) | flux d'IP malveillantes | CC0 | |
| cryptography | chiffrement des sauvegardes et du coffre | Apache-2.0 / BSD | |
| PyQt6 (Argus) | navigateur Argus (hors NetGuard) | GPL v3 / commercial | |

Les versions exactes sont dans `requirements.txt`.
