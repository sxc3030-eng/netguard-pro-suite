# Superaudit NetGuard AI — 2026-09-30

Dépôt : `sxc3030-eng/netguard-pro-suite`, branche de travail `netguard-ai` (créée depuis `feature/ai-window`, commit `b26305e`).
Périmètre : NetGuard (`netguard.py`), serveur de la fenêtre IA (`netguard_ai_server.py`), tableaux de bord HTML, barre système, licence, Mapper Sentinel, packaging Store.
Méthode : quatre audits parallèles (backend, serveur IA + auth, front-end, robustesse Windows + conformité Store) après l'audit mémoire ; chaque constat HIGH re-vérifié à la main avant correction ; tests écrits pour chaque garde ajoutée.

## Bilan

| | Avant | Après |
|---|---|---|
| Tests NetGuard | 47 | **129** (82 nouveaux : mémoire, gardes de blocage, traversée de chemins, serveur HTTP IA, ReDoS, réglages corrompus, build Store, Mapper) |
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

## 3. Deuxième passe (2026-09-30, « corrige tout ») — ce qui a été fait en plus

| Point | Fait |
|---|---|
| Licence maison vs achat Store | `netguard_paths.is_store_build()` (exe sous WindowsApps ou `NETGUARD_STORE_BUILD=1`) : dans un build Store, licence « pro » gérée par le Store, aucun essai, aucun siège, `license_manager` non chargé. NGPRO reste pour les ventes directes. |
| Packaging MSIX | `packaging/msix/AppxManifest.xml` (runFullTrust, allowElevation, StartupTask, capacités réseau) + `packaging/build_msix.ps1` (PyInstaller onedir → makeappx → signtool). Les logos sont des copies de l'icône : à remplacer par les tailles Store. L'installeur NSIS reste pour la distribution directe (v4.1.0, règles pare-feu retirées à la désinstallation). |
| Npcap / WebView2 absents | Boîtes de dialogue au premier lancement avec lien de téléchargement (Npcap n'est pas redistribuable). |
| Mise à jour automatique Argus | Désactivée dans un build Store. |
| Honeypot | `honeypot_bind` configurable (par défaut `0.0.0.0`, ex. l'IP LAN). |
| ip-api.com en HTTP clair | `geo_online_enabled` par défaut `false` dans un build Store ; les pages carte et réseau respectent le même réglage (plus de requête ipapi.co / ip-api.com / ipwho.is quand il est désactivé). |
| Mapper | Version complète (pare-feu par appareil) portée depuis le dépôt NetGuardPro, avec les correctifs de septembre et une validation IP/port/protocole avant chaque `netsh`. |
| CSP | Politique explicite sur les 6 pages (origines listées, `default-src 'none'`), vérifiée dans le navigateur intégré : 0 violation sur la carte et le tableau de bord. |
| ReDoS | `_safe_compile` sur les règles ET et personnalisées ; téléchargement plafonné à 20 Mo. |
| Travaux UI sans limite | scan LAN, chargement ET, feeds : un à la fois + cooldown. |
| Fichiers secrets lisibles par tout compte local (chmod no-op NTFS) | ACL propriétaire seul (icacls) sur le jeton, la clé de backup et chaque écriture JSON sécurisée. |
| Réglages corrompus | Fichier renommé `.corrupt`, défauts, événement visible ; types validés. |
| Planificateur de sauvegardes inexistant | Implémenté. |
| Divers | Clé AbuseIPDB enfin résolue, Telegram échappé, snapshots sur structures partagées, arrêt propre de l'enregistrement sur erreur disque, interface absente signalée, processus étranger sur 8770 détecté, port de la barre système configurable, `websockets>=14`, build sans réglages réels, JSON borné et données encadrées dans les prompts IA, erreurs de forme fournisseur propres, clé API lue d'abord dans le coffre. |

## 4. Décisions qui restent à toi (non corrigeables par le code)

1. **Licence GPLv3 vs scapy GPLv2-only.** Incompatibles dans un binaire combiné. Options : passer NetGuard en « GPL v2 ou ultérieure », ou isoler la capture scapy dans un processus séparé. Prévoir des conditions de licence personnalisées dans Partner Center.
2. **Historique git.** `netguard_users.json`, `netguard_license.json`, `netguard_settings.json` (ton IP publique) restent dans l'historique. Avant publication publique : changer le mot de passe admin, puis
   ```bash
   pip install git-filter-repo
   git filter-repo --invert-paths --path netguard_users.json --path netguard_license.json --path netguard_settings.json --path captures --path reports --path backups --path netguard_v160.py --path netguard_v160.py.bak
   git push --force --all && git push --force --tags
   ```
   (réécriture destructive : à faire toi-même, après sauvegarde du dépôt).
3. **Soumission Store.** Remplacer les identités du manifeste, fournir les logos aux bonnes tailles, publier la politique de confidentialité à une URL publique, remplir le questionnaire IARC (logiciel de sécurité), régler le refus de signature du 2026-04-03 (`docs/AUTHENTICODE.md`).

## 5. Non traité (faible impact ou impossible sans machine de test)

- `pywebview.api.send_command` expose toutes les commandes au JS de la page : acceptable maintenant que les XSS sont fermées côté serveur et côté pages.
- Polices Google chargées en ligne (CSP les autorise) ; à embarquer pour un mode 100 % hors ligne.
- Blocage pensé IPv4 (ip6tables ajouté, règles netsh acceptent l'IPv6, mais pas de tests IPv6).
- Non testé sur machine réelle : lancement sans Npcap/admin, build PyInstaller/MSIX, barre système, désinstallation.

## 6. Pour reproduire la vérification

```bash
cd D:\tmp\netguard-pro-suite
python -m pytest tests/test_netguard_blindage2.py tests/test_netguard_ai_server.py tests/test_netguard_blindage.py tests/test_netguard_memoire.py tests/test_netguard.py tests/test_netguard_vault.py tests/test_sentinel_vault.py -q
python netguard.py --help
```
