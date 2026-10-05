# Moteurs de capture — NetGuard AI

Depuis octobre 2026, NetGuard AI n'a plus besoin de Npcap. La détection (`process_observation`) est indépendante de la source ; trois moteurs l'alimentent.

| Moteur | Prérequis | Ce qu'il voit | Usage |
|---|---|---|---|
| **etw** | Windows 10/11, administrateur | chaque envoi, réception, connexion et acceptation TCP/UDP (IPv4/IPv6), octets, processus propriétaire, requêtes DNS | **par défaut** dès que l'application est élevée ; seul moteur de la version Store |
| **poll** | rien | nouvelles connexions (table du système), processus ; débit global par les compteurs d'interface | repli automatique sans droits administrateur |
| **npcap** | pilote Npcap + scapy | paquets complets : DPI, règles IDS, JA3, entropie, enregistrement pcap | « mode expert », à activer explicitement |

## Choix du moteur

Réglage `capture_engine` (`auto` par défaut) ou variable `NETGUARD_CAPTURE_ENGINE`.

- `auto` sous Windows : `etw` si administrateur, sinon `poll`. Npcap n'est jamais choisi automatiquement, et jamais dans un build Store.
- `auto` sous Linux/macOS : `npcap` (scapy/libpcap) si scapy est présent, sinon `poll`.

Le moteur actif et ses capacités sont diffusés dans l'état (`capture_engine`, `capture_capabilities`) et affichés par une pastille dans le tableau de bord.

## Ce qui change sans paquets bruts

| Fonction | etw | poll |
|---|---|---|
| Entrées/sorties en direct, carte, géolocalisation | oui | connexions seulement |
| Bande passante par IP et par application | oui (octets réels) | non |
| Application propriétaire de chaque flux | oui (PID fourni par le noyau) | oui |
| Blocage IP / pays, flux de menaces, VirusTotal | oui | oui |
| DNS (liste noire, entropie) | oui (fournisseur DNS-Client) | non |
| Scan de ports, force brute | sur les connexions **acceptées** (les SYN refusés ne sont pas vus) | idem |
| DPI, règles IDS/ET, JA3, entropie de charge utile, pcap | non (mode expert) | non |

## Fonctionnement d'ETW

`capture/etw_engine.py` ouvre une session de traçage temps réel privée (`NetGuardAI-Capture`) par ctypes, sans dépendance, et s'abonne à :

- `Microsoft-Windows-Kernel-Network` `{7DD42A49-5329-4832-8DFD-43D979153A88}` : événements 10/11/12/13/15 (TCP IPv4), 26/27/28/29/31 (TCP IPv6), 42/43 (UDP IPv4), 58/59 (UDP IPv6) ;
- `Microsoft-Windows-DNS-Client` `{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}` : événement 3006 (nom demandé).

La session est arrêtée à la fermeture (`atexit`) ; une session orpheline d'un plantage précédent est reprise au démarrage.

## Vérifier

```bash
python tools/smoke_capture.py                 # auto (poll sans admin)
python tools/smoke_capture.py --engine etw    # depuis un terminal administrateur
python -m pytest tests/test_capture_engines.py -q
```

Validation réelle du 2026-10-04 (Windows 11, administrateur) : 877 événements en 10 s, 28 adresses distinctes, octets et processus sur chaque flux, IPv4 et IPv6.
