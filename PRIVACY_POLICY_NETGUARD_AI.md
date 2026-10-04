# NetGuard AI — Politique de confidentialité

_Dernière mise à jour : 2026-09-30_

NetGuard AI est un logiciel de surveillance et de protection réseau qui s'exécute **entièrement sur votre ordinateur**. Il n'a ni compte utilisateur, ni serveur central, ni télémétrie. Ce document liste **toutes** les connexions sortantes que le logiciel peut faire de lui-même, les données envoyées, et comment les désactiver.

## 1. Ce que NetGuard AI ne collecte pas

- Aucun identifiant d'installation, aucune empreinte matérielle transmise, aucune adresse MAC envoyée.
- Aucune statistique d'utilisation, aucun rapport de plantage automatique, aucun service d'analytique tiers.
- Les paquets capturés, les menaces détectées, les rapports et les captures pcap restent sur votre disque (dossier de données : `%LOCALAPPDATA%\NetGuard AI` pour une installation Store, ou le dossier du programme en version portable).

## 2. Connexions sortantes et comment les couper

| Fonction | Destination | Données envoyées | Par défaut | Désactivation |
|---|---|---|---|---|
| Géolocalisation des IP sur la carte | `ip-api.com` (HTTP) puis `ipapi.co` (HTTPS) | l'adresse IP publique **distante** observée (jamais la vôtre) | activée, seulement si la base locale GeoLite2 est absente | réglage `geo_online_enabled = false`, ou installer la base MaxMind GeoLite2 locale (outil `tools/geoip_update.py`, votre propre clé MaxMind) |
| Flux de menaces publics | `feodotracker.abuse.ch`, `rules.emergingthreats.net` (HTTPS) | aucune donnée personnelle : téléchargement de listes | activée | réglage `threat_feeds_enabled = false` |
| VirusTotal | `www.virustotal.com` (HTTPS) | l'IP distante à vérifier | désactivée (nécessite votre clé API) | ne pas saisir de clé / `virustotal_enabled = false` |
| AbuseIPDB | `api.abuseipdb.com` (HTTPS) | l'IP distante à vérifier | désactivée (clé API) | idem |
| AlienVault OTX | `otx.alienvault.com` (HTTPS) | téléchargement d'indicateurs ; aucune IP envoyée | désactivée (clé API) | idem |
| Alertes Discord / Telegram | l'URL de webhook / l'API Telegram que **vous** configurez | texte de l'alerte (type, IP source, description) | désactivées | retirer le webhook / le jeton |
| Fenêtre IA (assistant) | `api.anthropic.com`, `api.openai.com` ou `generativelanguage.googleapis.com` (HTTPS), selon le fournisseur **que vous choisissez** | vos messages et, quand vous le demandez, un résumé de l'état réseau (IP, ports, menaces, noms de processus) | désactivée (nécessite votre clé API) | ne pas configurer de clé ; chaque action à effet (bloquer une IP, etc.) demande votre approbation explicite |
| Règles IDS en ligne | `rules.emergingthreats.net` (HTTPS) | aucune | sur demande (bouton) | ne pas cliquer |
| Vérification de mise à jour (Argus) | `api.github.com` (HTTPS) | aucune donnée personnelle | activée dans Argus ; **désactivée dans la version Store** (les mises à jour passent par le Store) | réglage Argus |

Remarque : `ip-api.com` ne propose son service gratuit qu'en HTTP clair. Les réponses sont assainies avant affichage, et la base locale GeoLite2 est toujours utilisée en priorité quand elle est présente. Si vous ne voulez aucune requête de géolocalisation en ligne, mettez `geo_online_enabled` à `false`.

## 3. Données écrites localement

- Réglages (`netguard_settings.json`), jeton d'authentification local (`.netguard_token`), journal (`netguard.log`, rotation 5 Mo × 3).
- Captures pcap (`captures/`, plafonnées en nombre), rapports forensiques (`reports/`, plafonnés à 200), sauvegardes chiffrées (`backups/`).
- Clés API : dans le coffre chiffré (DPAPI / AES-GCM) quand il est initialisé ; sinon dans `netguard_ai_settings.json` avec permissions restreintes. Jamais dans les journaux.
- Mémoire de l'assistant IA (`netguard_ai_memory.md`) : notes que vous avez approuvées, plafonnées.

## 4. Pot de miel (honeypot) et captures

Le pot de miel, s'il est activé, écoute sur les ports 21/22/23/3389/8080 et enregistre l'adresse IP et le port des connexions entrantes ainsi que les premiers octets reçus (assainis). Ces données restent locales et servent uniquement à la détection.

## 5. Droits

Vous pouvez supprimer toutes les données en effaçant le dossier de données. La désinstallation retire les règles de pare-feu `NetGuard_*` ajoutées pendant l'utilisation (`--remove-firewall-rules`).

Contact : via le dépôt GitHub du projet.
