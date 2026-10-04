# Licences des composants tiers — NetGuard AI

NetGuard AI est distribué sous **GPL v3 ou ultérieure** (voir `LICENSE`).

| Composant | Usage | Licence | Note |
|---|---|---|---|
| scapy | moteur de capture « expert » **optionnel** (non installé par défaut, absent de la version Store) | **GPL v2 (uniquement)** | Depuis le moteur ETW (octobre 2026), scapy n'est plus chargé ni distribué par défaut : le conflit GPLv2-only / GPLv3 ne concerne plus que l'utilisateur qui installe lui-même `requirements-expert.txt`. |
| Npcap | pilote de capture Windows, mode expert **optionnel** seulement | Npcap License (propriétaire) | **Non redistribué et non requis** : le moteur par défaut est ETW (intégré à Windows). |
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
