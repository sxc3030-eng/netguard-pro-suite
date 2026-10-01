# Audit mémoire — NetGuard Pro v4.1.0 (futur NetGuard AI)

Dépôt audité : `sxc3030-eng/netguard-pro-suite`, branche `feature/ai-window`, commit `b26305e` (2026-04-30).
C'est la version avec la fenêtre IA (Claude / OpenAI / Gemini), GeoLite2 local, bande passante par IP, traceroute sur la carte. Elle n'a jamais été fusionnée dans `main` ni dans le dépôt Store (`NetGuardPro`, v4.0).
Date : 2026-09-30. Portée : `netguard.py` (4 899 lignes), `netguard_ai_server.py` (1 200), `sentinel/sentinel_mapper.py` (648). Les autres modules (CleanGuard, MailShield, StrikeBack, etc.) sont exclus à ta demande.
Méthode : lecture complète, traçage de chaque structure alimentée par paquet / IP / événement, recherche d'une éviction (del, pop, clear, maxlen, TTL). Chaque cas HIGH a été re-vérifié à la main.

## Résumé

- Ce qui est bien fait : 100 % des `deque` ont un `maxlen`, les clients WebSocket sont nettoyés dans un `finally`, le journal principal tourne (`RotatingFileHandler` 5 Mo × 3), les captures pcap sont plafonnées, GeoLite2 est ouvert une seule fois, le serveur IA ne garde aucun historique côté serveur.
- Le défaut structurel : **une quinzaine de dictionnaires indexés par IP n'ont aucune éviction**, et aucune fonction de purge n'existe pour eux. Sur un poste exposé, la mémoire monte sans redescendre.
- Deux bugs peuvent **tuer le processus ou le serveur WebSocket** (itération de dict sans verrou).
- Un pattern crée **un thread par paquet** dès que la géolocalisation en ligne échoue.

## Priorité 1 — à corriger avant la présentation

| # | Ligne | Problème |
|---|---|---|
| 1 | `netguard.py:3000, 3003, 3007` | **Thread par paquet.** `_fetch_city_async` n'écrit le cache qu'en cas de succès (ligne 760 : « cache untouched so a future packet retries »). Sans GeoLite2, dès qu'ipapi.co (1 000/jour) ou ip-api.com (45/min) renvoient une erreur, ou hors-ligne, **chaque paquet de chaque IP publique lance un nouveau thread** qui bloque jusqu'à 6 s. Les IP bloquées en lancent deux (3000 et 3007). Pilotable par un attaquant avec des SYN à source usurpée. |
| 2 | `netguard.py:2186`, `3233-3234`, `3259` | **Itération de dict sans verrou → crash.** `anomaly_flush` parcourt `_anomaly_accum` pendant que le sniffer y insère (2810, hors verrou). `build_state_message` trie `ip_risk_scores`, `ip_intel`, `ATTACK_CHAINS` qui sont écrits sans verrou par les threads géo/forensique. Résultat : `RuntimeError: dictionary changed size during iteration`. En mode headless, `broadcast_state` (4359) n'a pas de try/except → **le processus se termine**. En mode pywebview, le serveur WebSocket meurt en silence (la carte et le serveur IA perdent leur source), et le tick raté ne vide pas `_anomaly_accum`. |
| 3 | `netguard.py:1866` | `STATE.record_packets` : une liste d'entiers par paquet enregistré, utilisée uniquement pour `len()`. Jamais vidée à la rotation. 60 min à 10 k pps ≈ 1,3 Go. Bonus : la rotation automatique (1871-1874) met `record_active=False` sans rouvrir de fichier, donc elle **arrête** l'enregistrement au lieu de le faire tourner. |
| 4 | `netguard.py:3035-3037` | `bytes_per_ip` et `bytes_per_ip_per_sec` : alimentés à **chaque paquet, source et destination, IP privées incluses**. Les valeurs par seconde sont bornées (deque 60), les clés jamais supprimées. Seul lecteur : un `sorted(...)[:15]` à chaque diffusion, de plus en plus lent. |
| 5 | `netguard.py:3016` | `STATE.active_conns` : `defaultdict(set)` de tous les ports destination jamais vus par IP source. Un scanner y met jusqu'à 65 535 ports. Jamais vidé. |
| 6 | `netguard.py:2825-2827` | `IP_BEHAVIOR_PROFILES` : un profil par IP publique avec `port_counter` / `proto_counter` / `hour_counter` **sans borne** (un scan de ports = 65 535 clés). Jamais évincé. |
| 7 | `netguard.py:2084-2085` | **Un thread + un fichier JSON par menace critique**, sans cooldown. `ja3_check` (2336-2350) lève une menace critique **par ClientHello TLS** correspondant à un JA3 connu ; les règles Suricata critiques par paquet. `reports/` n'est jamais purgé (seul `captures/` l'est), et le serveur IA fait un `stat()` de chaque fichier du dossier à chaque requête (`netguard_ai_server.py:866-878`). |
| 8 | `netguard.py:3129-3151` vs `4367` | La seule purge de `ip_recent_packets` / `ip_first_seen_ts` vit dans `_packets_for_state_msg`, appelée par `build_state_message`, qui en mode headless n'est appelée **que si un client est connecté**. Sans tableau de bord ouvert pendant des jours, ces deux tables grossissent par IP (~2 Ko/IP). |

## Priorité 2 — tables par IP sans éviction

Aucune fonction `prune` / `evict` / `expire` n'existe pour ces structures (recherche faite : seules `_NPCAP_CONSUMERS` et les fichiers pcap sont nettoyés).

| Ligne | Structure | Déclencheur |
|---|---|---|
| 922, 928, 762, 497 | `_geo_cache` (résultats `None` inclus), `_geo_city_cache` | par IP publique, source et destination (via top bandwidth), sauts traceroute |
| 845, 3010 | `STATE.ip_risk_scores` | calculé **à chaque paquet**, IP privées incluses, avec parcours des 100 menaces à chaque appel |
| 806 | `STATE.ip_intel` | par IP géolocalisée |
| 2097-2136 | `_port_scan_tracker`, `_brute_force_tracker`, `_syn_flood_tracker`, `_dns_tracker` | valeurs purgées par fenêtre, **clés jamais supprimées** (liste vide par IP) |
| 2147-2149 | `IP_BASELINES` | 3 × deque(120) par IP, privées incluses |
| 1910 | `STATE.ip_hit_counter` | par IP bloquée, jamais remis à zéro |
| 2218-2245 | `ATTACK_CHAINS` | listes vidées, clés gardées |
| 2340 | `JA3_CACHE` | timestamp stocké mais jamais consulté |
| 2870 | `_CHECKED_IPS` | garde VirusTotal, jamais vidé |
| 2572, 2611 | `ALERT_COOLDOWNS` | une clé par IP × canal |
| 3044 | `STATE.process_per_ip` | par IP |
| 2479 | `VT_CACHE` | TTL stocké mais non appliqué (croissance limitée à 4/min) |
| 2004 | `BLOCKED_IPS` | auto-blocages persistés et **jamais expirés**, chacun avec une règle `netsh advfirewall` permanente ; pilotable par SYN usurpés |

Correctif commun : une fonction `prune_ip_tables(max_age)` appelée depuis `snapshot_traffic` toutes les 60 s sous `STATE.lock`, qui utilise `ip_first_seen_ts` / dernier paquet vu pour supprimer les entrées de toutes ces tables, plus un plafond LRU (~5 000 IP). Pour `BLOCKED_IPS`, stocker `ip → (ts, raison)` et expirer les auto-blocages après N heures en retirant aussi la règle système.

## Priorité 3 — mineur

| Fichier:ligne | Problème |
|---|---|
| `netguard.py:1750-1752` | `_NPCAP_CONSUMERS[exe]["pids"]` grossit par PID tant que l'exe est vu |
| `netguard.py:2521-2522` | `OTX_IOC_IPS |= …` : union cumulative au lieu d'un remplacement |
| `netguard.py:2647, 2651` | thread par menace pour Discord/Telegram, le cooldown est testé **après** le spawn |
| `netguard.py:861, 2527` | `_abuseipdb_check` est du code mort : la clé n'est jamais assignée, aucun appelant |
| `netguard_ai_server.py:597-601, 837-841` | `ai_actions.log` et `ai_audit.log` en append pur, sans rotation |
| `netguard_ai_server.py:61-116` | fichier mémoire IA sans plafond ; les notes sont insérées en **tête** de section mais le lecteur garde `lines[-800:]`, donc ce sont les **plus récentes** qui sautent quand la limite est atteinte (le contraire de ce que dit le commentaire ligne 59) |
| `sentinel_mapper.py:508, 514` | `_saved_positions` / `_saved_labels` indexés par `device_id` venant du JS, jamais purgés, persistés dans `network_map.json` et réécrits en entier à chaque glissement de souris |
| `sentinel_mapper.py:56-67` | `mapper.log` sans rotation ; et `os.makedirs(logs)` arrive **après** la création du `FileHandler` → `FileNotFoundError` au premier lancement sur une installation neuve |
| `sentinel_mapper.py:154-158, 367-376` | sockets fermés seulement sur le chemin succès (CPython les libère quand même) |

## Ce qui est correct (vérifié)

- Tous les `deque` bornés : threats 100, recent_packets 2 000, alertes 100-200, timeline 300, forensic 50, traffic_history 60, ring buffer par IP 4.
- `_anomaly_accum` remis à `{}` chaque seconde (tant que le flush ne meurt pas, voir #2).
- `CLIENTS` : `discard` dans le `finally` + balayage des sockets morts.
- GeoLite2 : lecteurs ouverts une seule fois. pcap : un seul handle, `captures/` plafonné à `record_max_files`.
- Journal principal : `RotatingFileHandler` 5 Mo × 3.
- `THREAT_FEED_IPS` remplacé en bloc à chaque rafraîchissement. `_CONN_CACHE` reconstruit à chaque cycle.
- Serveur IA : pas d'historique serveur (le client renvoie tout), paramètres relus à chaque requête, connexion WebSocket vers NetGuard ouverte/fermée par requête dans un `async with`, `ThreadingMixIn` avec threads daemon.
- Mapper : `devices` remplacé à chaque scan, `ThreadPoolExecutor` dans des `with`, `subprocess.run` avec timeout.

## Plan de correction (ordre)

1. Cache négatif / entrée « en cours » écrite **avant** le spawn, et un seul worker géo avec `queue.Queue` borné (#1).
2. `anomaly_flush` : échange de l'accumulateur sous verrou puis itération sur la copie ; verrou dans `_update_ip_intel` et `_compute_risk_score` ; try/except autour de `snapshot_traffic()` dans `broadcast_state` (#2).
3. `record_packets` → compteur entier ; rotation qui rouvre un fichier (#3).
4. `prune_ip_tables()` toutes les 60 s couvrant #4, #5, #6, #8 et toute la priorité 2.
5. Cooldown par IP avant le rapport forensique + plafond sur `reports/` (#7).
6. Rotation des deux journaux du serveur IA, correction du plafond mémoire IA, purge des positions du Mapper, `makedirs` avant le `FileHandler`.
