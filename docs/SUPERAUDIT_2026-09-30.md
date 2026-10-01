# Superaudit NetGuard AI — 2026-09-30

Dépôt : `sxc3030-eng/netguard-pro-suite`, branche de travail `netguard-ai` (créée depuis `feature/ai-window`, commit `b26305e`).
Périmètre : NetGuard (`netguard.py`), serveur de la fenêtre IA (`netguard_ai_server.py`), tableaux de bord HTML, barre système, licence, Mapper Sentinel, packaging Store.
Méthode : quatre audits parallèles (backend, serveur IA + auth, front-end, robustesse Windows + conformité Store) après l'audit mémoire ; chaque constat HIGH re-vérifié à la main avant correction ; tests écrits pour chaque garde ajoutée.

## Bilan

| | Avant | Après |
|---|---|---|
| Tests NetGuard | 47 | **115** (68 nouveaux : mémoire, gardes de blocage, traversée de chemins, serveur HTTP IA) |
| Erreurs de syntaxe JS (7 pages, V8) | 0 | 0 |
| Fichiers sensibles suivis par git | 3 + 47 copies/pcap | 0 (voir « Décisions » pour l'historique) |

Commits sur `netguard-ai` (dans l'ordre) : mémoire → tests mémoire → sécurité backend + IA → front-end → Store/robustesse → hygiène dépôt → renommage → docs.

## 1. Corrigé — sécurité (exploitable depuis le réseau ou une page web)

| Gravité | Constat | Correctif |
|---|---|---|
| HIGH | **Serveur IA : tous les fichiers du dossier servis en HTTP** (`GET /netguard_ai_settings.json` → clés API, `/.netguard_token` → contrôle total du pare-feu), `Access-Control-Allow-Origin: *` sur chaque réponse, et `/api/tool-execute` croyait le champ `decision` du client. N'importe quelle page web ouverte dans le navigateur pouvait bloquer des IP ou lire les clés (DNS rebinding / CSRF vers 127.0.0.1:8770). | Liste blanche de 3 fichiers statiques ; jeton `X-NetGuard-Token` obligatoire sur `/api/*` (jeton WebSocket de NetGuard, ou secret par lancement injecté dans la page) ; Host loopback et Origin vérifiés ; CORS reflété uniquement pour loopback/null ; CSP ; les outils à effet exigent une signature HMAC émise par `/api/chat` pour ce triplet exact (id, outil, entrée). |
| HIGH | **Auto-blocage usurpable jusqu'au verrouillage** : un flood de SYN à source forgée faisait bloquer n'importe quelle IP publique, y compris la liste blanche (8.8.8.8, Cloudflare, Anthropic) ; un geo-bloc « US » posait une règle sur Google DNS ; le détecteur de scan comptait les réponses normales des serveurs vers nos ports éphémères (une page web = 15 ports en 10 s → CDN bloqué). | `block_ip_os` : jamais privée/liste blanche en automatique, limite 20 blocages/min ; scan de ports uniquement sur SYN ; table de flux (ip, port distant, port local) des conversations initiées par nous : les heuristiques de charge utile ne comptent que sur un flux établi, et aucune preuve usurpable ne bloque un serveur avec lequel on dialogue. |
| HIGH | **Suppression / écriture de fichiers arbitraires via WebSocket** : `backup_delete` sans validation (chemin absolu ou `..`), `backup_create` avec nom libre, `generate_report` avec `format="json/../../x.bat"`, `generate_forensic` avec `ip="../../x"`, `update_param` acceptant `__dict__`, `record_dir`, `whitelist`, `can_block`. | Regex + `realpath` confinés au dossier, types/formats de rapport en liste fermée, IP validée, `update_param` limité à 15 réglages scalaires. |
| HIGH | **XSS stocké vers les tableaux de bord** : noms DNS, ville/organisation renvoyées par `ip-api.com` (HTTP clair, modifiable par un attaquant sur le chemin), hostnames PTR, messages de règles IDS, descriptions de menaces, rendus via `innerHTML` sans échappement dans ~25 endroits sur 5 pages. Le jeton WebSocket et `pywebview.api.send_command` sont dans la portée JS : XSS = contrôle du pare-feu et persistance au démarrage. | Assainissement **à la source** (`_safe_str` : plus de `<>"'` ni de caractères de contrôle, une ligne, longueur bornée) sur toutes les chaînes réseau avant qu'elles n'entrent dans l'état ; `esc()` appliqué sur les sinks des 6 pages ; CSV neutralisé contre l'injection de formules. |
| HIGH | Netsh exécuté **sous `STATE.lock` dans le callback de capture** (jusqu'à 10 s par blocage → pertes de paquets, broadcast gelé), code retour jamais vérifié (sans admin, l'interface disait « bloqué » et rien ne l'était). | Worker dédié aux règles OS, code retour vérifié, échecs comptés (`block_failures`) et visibles dans la timeline. |
| MEDIUM | `anomaly_flush` itérait un dict modifié par le thread de capture → `RuntimeError` qui **terminait le processus** en mode headless. | Échange sous verrou puis itération sur la copie ; try/except dans la boucle de diffusion. |
| MEDIUM | Secrets écrits en clair dans `netguard_settings.json` quand le coffre était simplement verrouillé. | Refus avec message `vault_locked`. |
| MEDIUM | Réponses des threads (chargement ET, scan LAN, forensique, backups) **jamais livrées** : `asyncio.get_event_loop()` dans un thread lève sur Python ≥ 3.10. | `_ws_loop()` capturé depuis la boucle du serveur. |
| MEDIUM | Une commande WebSocket malformée (`int("abc")`, JSON non-dict, IP entière) coupait la session. | Coercitions bornées, dispatcher protégé, `_validate_ip` refuse les non-chaînes. |
| MEDIUM | Honeypot impossible à désactiver (ports restaient ouverts) ; une panne des feeds vidait la liste d'IP malveillantes ; `backup_restore` acceptait une chaîne comme liste d'IP (un caractère par entrée). | Corrigés. |
| MEDIUM | Formulaire login/utilisateurs du tableau de bord postait vers `localhost:8080`, **port du honeypot HTTP** (aucun serveur d'authentification n'existe). | Désactivé sauf configuration explicite. |
| MEDIUM | Reconnexion WebSocket : sockets orphelins multipliés, boucle `prompt()` du jeton toutes les 3 s. Jeton `?ng_token=` laissé dans l'URL. | Minuteur unique, nouvel essai à 60 s sans jeton, URL nettoyée. |
| MEDIUM | Serveur IA : corps non limité, types non vérifiés (500), modèle interpolé dans l'URL Google sans liste blanche, clé Google dans l'URL, notes de mémoire multi-lignes permettant de forger des sections injectées dans chaque prompt. | 1 Mo max, 400 propres, liste blanche des modèles, clé en en-tête, notes sur une ligne, verrous et écriture atomique. |
| LOW | SRI absent sur d3/topojson ; `target=_blank` sans `noopener`. | Ajoutés. |

## 2. Corrigé — robustesse et Store

| Constat | Correctif |
|---|---|
| Tout était écrit à côté de `netguard.py` : journal, réglages, jeton, captures, rapports, backups, licence. Sous `Program Files\WindowsApps` (Store) → `PermissionError` **à l'import**, avant `main()` ; en build PyInstaller `--onefile` → réglages perdus à chaque lancement. | `netguard_paths.py` : `RESOURCE_DIR` / `DATA_DIR` (`%LOCALAPPDATA%\NetGuard AI` en build figé ou dossier protégé ; inchangé en développement). Partagé par NetGuard, le serveur IA, Argus, la barre système, la licence et le Mapper. Journal best-effort. |
| Les raccourcis de l'installeur lançaient `--demo` qu'argparse refusait (code 2) : **l'application installée ne démarrait jamais depuis ses raccourcis**. | `--demo` accepté, options inconnues ignorées. |
| Sans Npcap ou sans admin : `sys.exit(1)` dans le thread de capture (ne tue que le thread) → fenêtre ouverte à 0 paquet, sans message. | `capture_error`, `is_admin`, `block_failures` exposés dans l'état et la timeline ; sans admin, blocage désactivé avec avertissement. |
| Règles `NetGuard_*` jamais retirées à la désinstallation. | `--remove-firewall-rules` appelé par le désinstalleur NSIS. |
| Arrêt : réglages sauvegardés seulement sur Ctrl+C ; pcap tronqué à la fermeture. | `atexit`. |
| Port 8765 occupé en headless → trace. | Message et code de sortie 2. |
| Détecteur de « consommateurs Npcap » qui **tuait des processus** (Wireshark, nmap, VPN éligibles) — politique Store 10.2. | Opt-in `npcap_kill_rogue=False`. |
| `wmic` retiré de Windows 11 24H2+ → empreinte machine changée → utilisateur payant verrouillé (« sièges épuisés »). | Repli `Get-CimInstance` puis `MachineGuid` ; sauvegarde de licence atomique. |
| Barre système : `pip install` à l'import (bloque hors ligne, interdit en Store) ; lancement `python netguard.py` faux en build figé. | Dépendances dures ; `self_command()`. |
| Mapper : `makedirs(logs)` après la création du FileHandler → crash au premier lancement. | Corrigé. |
| Aucune politique de confidentialité pour NetGuard (exigence 10.5.1) ; aucun fichier de licences tierces. | `PRIVACY_POLICY_NETGUARD_AI.md`, `THIRD_PARTY_LICENSES.md`, réglage `geo_online_enabled`. |

## 3. Décisions à prendre (non corrigées : relèvent de toi)

1. **Licence GPLv3 vs scapy GPLv2-only.** Les deux ne sont pas compatibles dans un binaire combiné. Options : passer NetGuard en « GPL v2 ou ultérieure », ou isoler la capture scapy dans un processus séparé sous GPLv2. À régler avant soumission ; prévoir aussi des conditions de licence personnalisées dans Partner Center (les Standard Application License Terms du Store ne conviennent pas à la GPL).
2. **Gestion de licence maison vs achat Store.** `license_manager` impose un essai de 30 jours puis un palier « free », avec risque de verrouillage par siège. Un client qui a payé via le Store n'a jamais de clé NGPRO. Pour la version Store : dériver le palier de `StoreContext.GetAppLicenseAsync` (ou tout débloquer) et réserver NGPRO aux ventes directes.
3. **Packaging.** NSIS + tâche planifiée `-RunLevel Highest` + écritures HKLM + `.bat` auto-élevés ne passent pas en MSIX. Il faut un manifeste avec `runFullTrust` + `allowElevation` (justifiés : capture Npcap et règles pare-feu), `StartupTask` pour le démarrage, et une boîte de dialogue au premier lancement pour installer Npcap (non redistribuable). `docs/AUTHENTICODE.md` note un refus Store du 2026-04-03 (signature/éditeur) toujours ouvert.
4. **Mise à jour automatique (Argus).** Téléchargement d'exécutables depuis GitHub : à désactiver dans la version Store (politique 10.8).
5. **Honeypot sur 0.0.0.0** (21/22/23/3389/8080) avec bannières imitant OpenSSH/Apache : à déclarer (capacités réseau) et à documenter ; envisager de lier à l'IP LAN seulement.
6. **ip-api.com en HTTP clair.** Les réponses sont maintenant assainies, mais le canal reste en clair. Options : `geo_online_enabled=false` par défaut dans la version Store (GeoLite2 local + clé MaxMind de l'utilisateur), ou le plan payant HTTPS.
7. **Historique git.** `netguard_users.json`, `netguard_license.json`, `netguard_settings.json` (ton IP publique Vidéotron) sont retirés du suivi mais restent dans l'historique : `git filter-repo` + push forcé + rotation du mot de passe admin avant toute publication publique.
8. **Mapper.** La version de cette branche (648 lignes) est plus ancienne que celle du dépôt Store `NetGuardPro` (1 463 lignes, avec pare-feu par appareil). À réconcilier si tu veux la version complète pour la présentation.

## 4. Non traité (connu, hors périmètre ou à faible impact)

- CSP sur les tableaux de bord pywebview (origine `file://`, risque de casser les pages sans test réel) ; polices Google chargées en ligne.
- `pywebview.api.send_command` expose toutes les commandes au JS de la page : acceptable maintenant que les XSS sont fermées, mais une liste blanche serait plus robuste.
- Regex ET/pcre compilées sans garde ReDoS ; pas de limite de taille sur le téléchargement des règles.
- Pas de limitation de débit sur `scan_lan` / `refresh_threat_feeds` (commandes locales authentifiées).
- Interfaces IPv6 : `iptables` → `ip6tables` corrigé, mais le reste de la logique de blocage est pensé IPv4.
- Tests non couverts : lancement sans Npcap/admin sur une vraie machine, build PyInstaller, `netguard_tray`, désinstallation.

## 5. Pour reproduire la vérification

```bash
cd D:\tmp\netguard-pro-suite
python -m pytest tests/test_netguard_ai_server.py tests/test_netguard_blindage.py tests/test_netguard_memoire.py tests/test_netguard.py tests/test_netguard_vault.py tests/test_sentinel_vault.py -q
python netguard.py --help
```
