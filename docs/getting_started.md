# Premiers pas avec NetGuard Pro Suite

Ce guide t'amène d'une installation vide à un premier scan en moins de cinq minutes. Il couvre Windows et Linux, et s'adresse à un utilisateur qui n'a jamais lancé l'outil.

> ℹ️ Info : NetGuard Pro est une suite. Ce guide installe le coeur (sniffer + dashboard + Argus). Pour la configuration du Vault, de l'AI Assistant ou de la licence, voir les guides séparés à la fin.

---

## 1. Prérequis

| Composant | Windows | Linux |
|-----------|---------|-------|
| Python | 3.8+ (3.11 recommandé) | 3.8+ |
| Capture paquets | Npcap (lien direct ci-dessous) | libpcap (`sudo apt install libpcap-dev`) |
| Élévation | Compte Administrateur | sudo |
| Navigateur | Edge / Chrome / Firefox récent | idem |

> ⚠️ Warning : NetGuard a besoin du privilège admin pour capturer des paquets bruts. C'est une contrainte de l'OS, pas un choix de design.

---

## 2. Installation rapide (5 minutes)

### Windows

1. Installe Python 3.11 depuis [python.org](https://www.python.org/downloads/) (coche "Add Python to PATH").
2. Installe **Npcap** depuis [npcap.com/#download](https://npcap.com/#download). Utilise les options par défaut **sauf** : décoche "Restrict Npcap driver's access to Administrators only" si tu veux que les outils non-admin puissent listrer les interfaces. Si tu coches cette case, NetGuard fonctionne quand même mais doit toujours être lancé en admin.
3. Clone le dépôt :
   ```bash
   git clone https://github.com/sxc3030-eng/netguard-pro-suite.git
   cd netguard-pro-suite
   ```
4. Installe les dépendances Python :
   ```bash
   pip install -r requirements.txt
   ```
5. Double-clique sur `LANCER_NETGUARD_ADMIN.bat`. Windows affiche un prompt UAC — accepte.

### Linux

```bash
sudo apt install libpcap-dev python3-pip
git clone https://github.com/sxc3030-eng/netguard-pro-suite.git
cd netguard-pro-suite
pip install -r requirements.txt
sudo python netguard.py
```

> ✅ Tip : sur Linux, `sudo` est plus simple que `setcap`. La doc Scapy permet de retirer le besoin de root via `setcap cap_net_raw,cap_net_admin=eip $(which python3)` si tu en as l'envie.

---

## 3. Premier lancement

Quand `LANCER_NETGUARD_ADMIN.bat` (ou `sudo python netguard.py`) démarre, tu verras dans la console :

```
[netguard] WebSocket server listening on 127.0.0.1:8765
[netguard] Capture thread started on interface: Wi-Fi
[netguard] Open netguard_dashboard.html in your browser
```

Ouvre `netguard_dashboard.html` dans ton navigateur (double-clic depuis l'Explorateur, ou `xdg-open netguard_dashboard.html` sous Linux).

![](imgs/first-launch.png)

> ⚠️ Warning : Au premier lancement Windows, un prompt UAC peut apparaître **une seconde fois** si Npcap a été installé en mode admin-only. C'est attendu. Si l'UAC se répète en boucle après le démarrage, voir `troubleshooting.md` — il s'agit probablement d'un consommateur Npcap fantôme (NetGuard a un détecteur intégré pour ça).

---

## 4. Premier scan — visite guidée du dashboard

Une fois le dashboard ouvert, tu verras plusieurs panneaux. Voici l'ordre dans lequel les regarder.

### 4.1 Bandeau de statut (haut)

![](imgs/first-scan-statbar.png)

- **Paquets capturés** : compteur cumulatif. Si tu vois 0 après 30 secondes de navigation, c'est que la capture ne marche pas (voir `troubleshooting.md` → "Dashboard shows 0 packets").
- **Menaces détectées** : compteur des alertes IDS depuis le démarrage.
- **IPs bloquées** : compteur des IP poussées vers iptables/netsh.

### 4.2 Panneau "Menaces"

Liste les détections actives par règle (port scan, brute force, SYN flood, plages malveillantes, etc.). Chaque ligne est cliquable et expose le payload qui a déclenché la règle.

![](imgs/threats-panel.png)

### 4.3 Tableau des paquets — **avec colonne Process**

C'est la nouveauté de cette release. Chaque ligne du tableau de paquets affiche :

| Colonne | Contenu | Provenance |
|---------|---------|------------|
| Time | Horodatage du paquet | Scapy |
| Src → Dst | IP source → IP destination | Scapy |
| Proto / Port | TCP/UDP/ICMP + port | Scapy |
| Bytes | Taille du paquet | Scapy |
| **Process** | Nom de l'exécutable propriétaire de la connexion | **psutil (nouveau)** |

> ℹ️ Info : la colonne Process utilise `psutil.net_connections()` pour faire correspondre les sockets aux processus locaux. Elle est précise pour les flux sortants depuis ta propre machine. Pour le trafic transit, la colonne sera vide (c'est normal).

Exemple : si tu vois une connexion sortante vers `api.anthropic.com:443` avec `Process: claude.exe`, l'attribution est correcte — c'est l'AI Assistant qui parle au backend.

![](imgs/packets-table-process-column.png)

### 4.4 Panneau "Top Bandwidth par IP"

Affiche les **15 IP** qui consomment le plus de bande passante (en KiB/s, fenêtre glissante de 60 secondes), classées par volume.

![](imgs/top-bandwidth-panel.png)

> ✅ Tip : c'est le panneau le plus utile pour repérer instantanément un téléchargement non identifié, un client BitTorrent oublié, ou une exfiltration suspecte.

### 4.5 Carte mondiale

Géolocalise chaque IP distante via MaxMind GeoLite2 (local) avec fallback ip-api.com. Bleu = autorisé, rouge = bloqué.

---

## 5. Mode Fantôme — vue rapide

Le **Mode Fantôme** fait disparaître la fenêtre dashboard tout en gardant la capture active dans une icône systray. Pratique pour laisser tourner NetGuard en permanence sans qu'il pollue la barre des tâches.

Lancement :

```bash
LANCER_NETGUARD_GHOST.bat
```

Une icône bouclier apparaît dans la zone de notification. Clic droit → menu :
- **Ouvrir dashboard** : restaure la fenêtre principale.
- **Pause capture** : suspend Scapy sans tuer le process.
- **Quitter** : termine proprement (libère le hook iptables).

> ⚠️ Warning : le Mode Fantôme requiert `pystray` et `Pillow`. Si l'icône systray n'apparaît pas, voir `troubleshooting.md`.

---

## 6. Détecteur Npcap fantôme (anti-UAC-loop)

NetGuard surveille toute autre application qui utiliserait Npcap sur ta machine. Si un exe inconnu redémarre 3+ fois en 5 minutes en chargeant `wpcap.dll`, NetGuard le tue automatiquement et logue `[NPCAP] Rogue Npcap consumer:` au niveau CRITICAL.

Le panneau **"Activité système"** du dashboard affiche en temps réel la liste des consommateurs Npcap détectés, avec leur statut (`trusted` / `<n> launches` / `ROGUE`).

![](imgs/npcap-activity-panel.png)

Pour ajouter un exe à la liste blanche permanente, ajoute son chemin absolu dans `netguard_settings.json` :

```json
{
  "npcap_whitelist": [
    "C:\\Program Files\\Wireshark\\Wireshark.exe",
    "C:\\Program Files\\Npcap\\WlanHelper.exe"
  ]
}
```

> ℹ️ Info : NetGuard et python.exe sont auto-whitelistés au démarrage. Tu n'as besoin d'ajouter manuellement que les outils tiers que tu utilises légitimement (Wireshark, OBS, etc.).

---

## 7. Et après ?

Selon ce que tu veux faire ensuite :

| Objectif | Guide |
|----------|-------|
| Stocker tes clés API en sécurité | [secret_vault_user_guide.md](secret_vault_user_guide.md) |
| Activer Argus + l'AI Assistant (Claude/GPT/Gemini) | [ai_assistant_user_guide.md](ai_assistant_user_guide.md) |
| Activer ta licence Pro | [license_activation_guide.md](license_activation_guide.md) |
| Quelque chose ne marche pas | [troubleshooting.md](troubleshooting.md) |

> ✅ Tip : si tu prévois d'utiliser l'AI Assistant, **commence par configurer le Vault**. C'est lui qui gardera tes clés API hors d'atteinte d'un malware sur ta machine.

---

## 8. Désinstallation

Pour retirer proprement :

1. Quitte NetGuard via le menu systray (Mode Fantôme) ou Ctrl+C dans la console.
2. Désinstalle Npcap depuis Panneau de configuration → Programmes (Windows) ou `sudo apt remove libpcap-dev` (Linux).
3. Supprime le dossier cloné `netguard-pro-suite/`.

> ⚠️ Warning : le dossier `argus_data/.secret_vault/` contient le Vault. **Si tu le supprimes, tes secrets sont définitivement perdus.** Voir le guide Vault avant de supprimer.
