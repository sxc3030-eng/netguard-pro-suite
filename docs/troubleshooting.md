# Dépannage — NetGuard Pro Suite

Guide de résolution des problèmes les plus courants. Trie par module : NetGuard, Vault, AI Assistant, Argus, Licence, Mode Fantôme, performance.

> ✅ Tip : avant tout, regarde `netguard.log` à la racine du dépôt — il contient le détail de la dernière session avec timestamps et stack traces.

---

## NetGuard

### Boucle UAC infinie au démarrage / Npcap

**Symptômes** : Windows redemande l'élévation administrateur en boucle, parfois plusieurs fois par minute. Le dashboard ne se charge jamais.

**Cause** : un processus tiers (typiquement un test pytest orphelin, un Wireshark mal fermé, ou un scanner concurrent) garde un handle Npcap ouvert et redémarre en permanence.

**Fix** :

1. Ouvre Task Manager → cherche `python.exe` ou `pytest.exe` qui ne devraient pas être là → End task.
2. Si l'origine est inconnue, regarde la console NetGuard pour le log `[NPCAP] Rogue Npcap consumer:` — il identifie l'exe coupable.
3. NetGuard tue automatiquement le rogue après 3 redémarrages en 5 minutes (détecteur intégré). Mais s'il revient, ajoute son chemin à `netguard_settings.json` → `npcap_whitelist` si c'est légitime, ou désinstalle-le sinon.
4. Si Npcap a été installé en mode "admin-only", c'est lui le coupable. Réinstalle-le **sans cocher** "Restrict Npcap driver's access to Administrators only".

> ⚠️ Warning : ne whitelist pas un exe inconnu. Si tu vois `chrome.exe` ou `svchost.exe` dans la liste, c'est suspect — nor Chrome ni svchost ne devraient charger `wpcap.dll`.

---

### Dashboard affiche 0 paquets

**Symptômes** : NetGuard tourne, le dashboard se charge, mais le compteur de paquets reste à 0 même après 1 minute de navigation Web.

**Diagnostic en cascade** :

1. **Élévation admin manquante.** Console NetGuard affiche `Permission denied: tcpdump`. Lance via `LANCER_NETGUARD_ADMIN.bat` ou `sudo`.
2. **Mauvaise interface.** Lance avec `--interface "Wi-Fi"` (Windows) ou `--interface eth0` (Linux). Pour lister les interfaces dispo : `python -c "from scapy.all import get_if_list; print(get_if_list())"`.
3. **Npcap pas installé** (Windows). Téléchargement : [npcap.com/#download](https://npcap.com/#download).
4. **Pare-feu Windows / antivirus bloque la capture brute.** Ajoute une exception pour `python.exe` dans Windows Defender → Virus & threat protection → Manage settings → Add or remove exclusions.
5. **WebSocket bloqué.** Ouvre la DevTools du navigateur (F12) → onglet Network → cherche une connexion `ws://127.0.0.1:8765`. Si elle est en `pending` ou `failed`, port 8765 est occupé. Lance avec `--port 9000` pour tester.

---

### Performance : CPU / RAM élevés

**Symptômes** : `python.exe` consomme > 50% CPU en continu, RAM monte au-delà de 1 GB.

**Causes possibles & fixes** :

| Cause | Fix |
|-------|-----|
| DPI activé sur trop de protocoles | Settings → Detection → désactive Deep Packet Inspection ou limite-le aux ports 80/443 |
| Rétention logs trop longue | Settings → Logs → réduis "history retention" de 90 à 7 jours |
| Mode `--no-block` désactivé pendant un scan port intense | Lance avec `--no-block` pour suspendre le push iptables et observer seulement |
| Trafic réseau anormalement élevé (>100 Mbps soutenu) | Cible attendue : NetGuard est conçu pour <50 Mbps domestique. Au-delà, considère un mirror SPAN sur un PC dédié |
| AI Assistant ouvert avec contexte massif | Vide l'historique : Argus → AI panel → ⋯ → "Reset conversation" |

> ✅ Tip : le profil "ghost mode" (`LANCER_NETGUARD_GHOST.bat`) consomme typiquement 15-20% de moins parce que le rendu HTML du dashboard n'est pas exécuté.

---

## Secret Vault

### "Invalid master password" — comment ça marche

Le Vault impose un **rate limit** : 3 tentatives de mot de passe maître autorisées par fenêtre de 30 secondes. Au 3ᵉ échec, lockout de **5 minutes** pendant lesquels toute tentative est rejetée immédiatement (sans même appeler Argon2id).

**Fix** :

1. Vérifie la casse de ton mot de passe (majuscule / minuscule).
2. Vérifie que la touche Caps Lock n'est pas active.
3. Patiente 5 minutes si tu vois `VaultLockedError: cooldown active`.
4. Si tu as oublié le mot de passe, **il n'est pas récupérable** — voir [secret_vault_user_guide.md](secret_vault_user_guide.md) → section "Mot de passe maître perdu".

> ⚠️ Warning : pas de recovery key, pas de master override, pas de reset admin. Le Vault est volontairement irrécupérable. Stocke ton mot de passe maître dans un gestionnaire externe.

---

### "Vault dependencies missing"

**Symptôme** : un bandeau jaune dans Argus / NetGuard dit "Vault unavailable. Install missing dependencies."

**Fix** :

```bash
pip install pywin32 keyring argon2-cffi
```

Puis redémarre Argus / NetGuard. Le bandeau disparaît si tout est OK.

> ℹ️ Info : sur Linux/macOS, `pywin32` n'est pas installable — c'est attendu. Le Vault tournera avec Layer 1 (DPAPI) dégradée mais Layers 2 et 3 actifs.

---

### "VaultCorruptedError" au démarrage

**Symptôme** : NetGuard refuse de déverrouiller le Vault et affiche `VaultCorruptedError`.

**Cause** : un blob ciphertext a été modifié — soit par une coupure pendant un `set()`, soit par une corruption disque, soit par un antivirus qui a réécrit le fichier.

**Fix** :

1. Vérifie l'existence de `argus_data/.secret_vault/secret_vault.bin.bak` (backup auto à chaque save réussi).
2. Si oui : `mv secret_vault.bin secret_vault.bin.broken && mv secret_vault.bin.bak secret_vault.bin`.
3. Relance — le Vault doit s'ouvrir avec l'état précédent.
4. Si le `.bak` est aussi corrompu, le Vault est perdu. Re-initialise et re-entre tes clés.

---

## AI Assistant

### "No API key configured"

**Symptôme** : tu envoies un message, l'Assistant répond "No API key configured for provider X".

**Fix** :

1. Argus → 🤖 → ⚙ → Providers → vérifie que la clé est entrée.
2. Si le Vault est déverrouillé, la clé doit y être stockée. Settings → Vault → "Voir audit" → tu dois y voir un `op:set name:anthropic_api_key`.
3. Si tu as configuré la clé via `.env` ou variable d'environnement :
   ```bash
   echo $ANTHROPIC_API_KEY
   ```
   doit retourner ta clé. Sinon, source le fichier `.env` (Windows : redémarre la console, Linux/Mac : `source .env`).

---

### "Tab won't load" dans Argus

**Symptôme** : tu cliques sur un onglet Argus, il reste blanc ou affiche une page d'erreur "ERR_TRACKING_PREVENTION".

**Cause** : Edge Tracking Prevention (héritée par QtWebEngine) bloque certains scripts — typiquement Google sign-in, Stripe checkout, etc.

**Fix** : Argus V3 inclut un bypass automatique pour PyQt6. Si la page reste cassée :

1. Argus → Settings → Privacy → décoche "Strict tracking prevention".
2. Redémarre l'onglet.
3. Si le site reste bloqué, c'est probablement un script interne au site qui détecte un user-agent atypique. Settings → Privacy → "User agent" → choisis "Edge Standard".

---

## Licence

### "Seat exhausted"

**Symptôme** : NetGuard refuse d'activer la licence, message console `[license] ERROR — Seat exhausted (X/X used)`.

**Fix** :

1. Va sur ta page de gestion : `https://netguardpro.com/account` *(placeholder à publier)*.
2. Liste de tes appareils → identifie une machine que tu n'utilises plus.
3. Clique **"Désactiver"** à côté.
4. Reviens sur la machine actuelle, redémarre NetGuard. Le siège libéré est repris.

OU

1. Upgrade ton plan : page de gestion → "Ajouter un PC" → +15$/mois.

Voir [license_activation_guide.md](license_activation_guide.md) pour le détail.

---

### "License signature invalid"

**Symptôme** : `[license] ERROR — License signature invalid`.

**Causes possibles** :

- Tu as édité `netguard_license.json` à la main → ne le fais pas, la signature Ed25519 ne tolère aucune modification.
- Tu as téléchargé le fichier via un proxy d'entreprise qui le réécrit (parfois les anti-malware modifient les JSON).
- Le `LICENSE_PUBLIC_KEY_B64` du `license_manager.py` ne correspond pas à la clé privée du serveur (cas très rare, signal de build).

**Fix** :

1. Re-télécharge le `.lic` original depuis ton compte.
2. Vérifie qu'il n'a pas été modifié avec `sha256sum netguard_license.json` (compare au hash dans l'email d'achat).
3. Si l'erreur persiste, écris à support@netguardpro.com avec le hash et la console output.

---

## Mode Fantôme

### Icône systray manquante

**Symptôme** : tu lances `LANCER_NETGUARD_GHOST.bat`, NetGuard tourne (logs OK) mais aucune icône bouclier n'apparaît dans la zone de notification Windows.

**Causes & fixes** :

1. **`pystray` ou `Pillow` pas installé** :
   ```bash
   pip install pystray Pillow
   ```
2. **Windows cache l'icône.** Settings → Personalization → Taskbar → "Select which icons appear on the taskbar" → active "NetGuard Pro".
3. **Fond d'écran multi-moniteur incorrect.** Glisse un autre programme dans la zone de notification — si lui aussi disparaît, c'est un bug Windows. `explorer.exe /restart`.

---

## Argus

### Argus se lance mais bloque sur "Initializing..."

**Cause** : QtWebEngine attend la fin de la migration du cache profile. Sur PCs lents ou disques saturés, ça peut prendre 30-60 secondes.

**Fix** :

1. Patiente 1 minute pleine.
2. Si toujours bloqué : ferme Argus, supprime `argus_data/normal_cache/` et `argus_data/sandbox/cache/` → relance.
3. Si crash répété : passe en mode safe : `python argus_pyqt.py --reset-profile` (vide tous les profiles persistants — perdras cookies / sessions).

---

### Argus crash avec "QtWebEngineProcess.exe a cessé de fonctionner"

**Cause** : QtWebEngine et certains drivers GPU intégrés Intel se brouillent sous Windows 11.

**Fix** :

1. Mets à jour ton driver GPU (Intel Driver & Support Assistant ou GeForce Experience).
2. Force le rendu logiciel : ajoute en haut de `argus_pyqt.py` (ou via env var) :
   ```bash
   set QTWEBENGINE_CHROMIUM_FLAGS=--disable-gpu --disable-gpu-compositing
   ```
3. Relance Argus.

> ℹ️ Info : le rendu logiciel est plus lent visuellement mais 100% stable sur tout PC.

---

## Performance générale

### Réduire le CPU à long-terme

Combinaison qui marche pour la plupart des PCs :

```bash
python netguard.py --no-block --interface Wi-Fi
```

dans `netguard_settings.json` :

```json
{
  "history_retention_days": 7,
  "dpi_enabled": false,
  "log_level": "WARNING"
}
```

Ferme Argus quand tu ne t'en sers pas — l'AI Assistant et QtWebEngine sont les modules les plus gourmands.

---

### Logs trop volumineux

`netguard.log` peut grossir vite (>100 MB) si tu laisses NetGuard tourner plusieurs jours.

**Fix** :

1. NetGuard tourne en log rotation : `netguard.log.1` est l'archive précédente, écrasée à chaque redémarrage.
2. Pour retirer les anciens : `rm netguard.log.1` (ou Explorer → supprimer).
3. Pour réduire à la source : `netguard_settings.json` → `"log_level": "WARNING"` (au lieu de `"INFO"` ou `"DEBUG"`).

---

## Obtenir de l'aide

Si rien de ce qui précède ne résout ton problème :

1. Capture la console output complète (avec stack trace).
2. Capture les 50 dernières lignes de `netguard.log` (`tail -50 netguard.log`).
3. Note ta plateforme (`python --version`, `uname -a` ou `winver`).
4. Ouvre une issue : [github.com/sxc3030-eng/netguard-pro-suite/issues](https://github.com/sxc3030-eng/netguard-pro-suite/issues).
5. Ou écris à support@netguardpro.com pour les soucis liés à la licence.

> ⚠️ Warning : ne joins **jamais** ton fichier `netguard_license.json` ou le contenu de `secret_vault.bin` à une issue publique. Le support privé est le bon canal pour ces fichiers.

---

## Voir aussi

- [getting_started.md](getting_started.md) — installation et premier lancement
- [secret_vault_user_guide.md](secret_vault_user_guide.md) — Vault en détail
- [ai_assistant_user_guide.md](ai_assistant_user_guide.md) — AI Assistant
- [license_activation_guide.md](license_activation_guide.md) — Licence
