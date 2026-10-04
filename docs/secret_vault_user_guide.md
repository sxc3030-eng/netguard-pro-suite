# Secret Vault — Guide utilisateur

Ce guide explique **comment utiliser** le Secret Vault au quotidien. Pour la spec technique (threat model, architecture, format binaire), voir [secret_vault_spec.md](secret_vault_spec.md).

---

## Pourquoi un Vault ?

Sans Vault, tes clés API (Anthropic, OpenAI, Gemini) traînent en clair dans `netguard_ai_settings.json` ou dans un fichier `.env`. Trois scénarios où ça devient un problème :

1. **Vol de disque ou backup volé.** Un attaquant lit le JSON sans même devoir s'authentifier.
2. **Malware "même utilisateur".** Un programme qui tourne sous ton compte Windows peut lire le JSON sans privilège élevé. C'est le scénario le plus courant — les rançongiciels modernes exfiltrent les clés AI avant de chiffrer.
3. **Sauvegarde cloud par accident.** OneDrive / Dropbox synchronisent ton dossier sans demander, ta clé API se retrouve sur des serveurs tiers.

Le Vault triple-chiffre tes secrets sur disque (DPAPI + Windows Credential Manager + Argon2id master). Sans le mot de passe maître **et** la session Windows déverrouillée **et** la machine d'origine, le contenu est illisible.

---

## Dépendances requises

Le Vault est un module Python optionnel — il ne se charge que si trois paquets sont installés :

```bash
pip install pywin32 keyring argon2-cffi
```

| Paquet | Couche du Vault | Plateforme |
|--------|----------------|------------|
| `pywin32` | Layer 1 (DPAPI) | Windows uniquement |
| `keyring` | Layer 2 (Credential Manager) | Windows + Linux + macOS |
| `argon2-cffi` | Layer 3 (master password KDF) | toutes |

> ℹ️ Info : sur Linux/macOS, Layer 1 (DPAPI) est dégradé. Layers 2 et 3 protègent toujours, mais tu n'as pas la couche supplémentaire "même utilisateur Windows requis". C'est documenté dans la spec, et c'est suffisant pour la plupart des cas.

> ⚠️ Warning : **si une seule de ces dépendances manque**, le Vault refuse de se charger et la suite tombe en mode "plaintext fallback" — un bandeau jaune apparaît dans Argus et NetGuard avec la commande d'install à copier-coller. **Ne l'ignore pas.** Tant que le bandeau est là, tes clés sont en clair.

---

## Configuration initiale (première fois)

1. Lance Argus : `python argus_pyqt.py` ou `LANCER_ARGUS_2.bat`.
2. Clique sur l'icône 🤖 (AI Assistant) dans la barre Argus.
3. Clique sur ⚙ (Settings) en haut du panneau AI.
4. Onglet **"Secret Vault"** → bouton **"Initialiser le Vault"**.
5. Choisis un mot de passe maître. **Il ne sera jamais récupérable.**

![](imgs/vault-init-dialog.png)

### Recommandations pour le mot de passe maître

- **Passphrase plutôt que mot de passe.** 4-6 mots aléatoires (ex. `cathédrale-orange-vélo-cosmos-89-traîneau`) sont plus solides et plus mémorables qu'un `P@ssw0rd!2024`.
- **Stocke-le dans un gestionnaire de mots de passe** (Bitwarden, 1Password, KeePassXC). Le Vault ne sait pas le récupérer si tu l'oublies.
- **Backup papier optionnel.** Imprime-le, mets-le dans un classeur fermé. C'est la seule récupération possible.
- **Évite de le réutiliser.** Si tu as déjà ce mot de passe ailleurs (Gmail, Bitwarden master), choisis-en un autre — il est ici protégé par Argon2id 64 MiB, mais le réutiliser annule l'avantage.

> ✅ Tip : le Vault accepte n'importe quel string > 8 caractères. Aucune politique de complexité imposée — l'entropie est ton problème.

---

## Migration depuis le mode plaintext

Si tu utilisais déjà NetGuard / Argus avec des clés en clair, il y a un chemin de migration en un clic :

1. Settings → Secret Vault → **"Migrer depuis netguard_ai_settings.json"**.
2. Le bouton lit le fichier, identifie chaque clé (Anthropic, OpenAI, Gemini, threat-intel) et l'injecte dans le Vault.
3. Le fichier original est sauvegardé en `netguard_ai_settings.json.pre-vault.bak` au cas où.
4. Le JSON original est réécrit avec un drapeau `"api_key_in_vault": true` et la valeur `api_key` retirée.

![](imgs/vault-migrate-button.png)

### Ce qui est migré

| Source | Destination | Nom dans le Vault |
|--------|-------------|-------------------|
| Clé Anthropic (Claude) | Vault | `anthropic_api_key` |
| Clé OpenAI (GPT) | Vault | `openai_api_key` |
| Clé Gemini | Vault | `gemini_api_key` |
| Token VirusTotal | Vault | `virustotal_token` |
| Token AbuseIPDB | Vault | `abuseipdb_token` |

Plus toute clé tierce nommée selon la convention `<provider>_api_key`.

### Ce qui n'est PAS migré

- Les paramètres non-secrets (modèle Claude par défaut, max_tokens, etc.) restent dans le JSON.
- Les credentials utilisateur (`netguard_users.json`) — c'est un autre système, hashé en scrypt, pas un secret long-terme.
- Les clés `.env` au niveau du dépôt — tu peux les retirer manuellement après migration.

> ✅ Tip : la migration est **idempotente**. Re-cliquer sur le bouton après une migration réussie retourne 0 (aucune clé à migrer) et ne touche à rien.

---

## Usage quotidien

### Déverrouillage en début de session

À l'ouverture d'Argus ou de NetGuard, si le Vault contient des secrets, on te demande le mot de passe maître :

![](imgs/vault-unlock-dialog.png)

Une fois déverrouillé, le Vault reste accessible aux modules de la suite tant que :
- L'application n'est pas fermée.
- Tu ne déclenches pas un verrouillage manuel.
- Tu restes actif (le timer d'inactivité par défaut est de 15 minutes).

### Auto-lock après inactivité

Par défaut, **15 minutes sans appel au Vault** déclenchent un verrouillage automatique. Le prochain accès te redemande le mot de passe maître. Configurable dans Settings → Secret Vault → "Délai d'auto-verrouillage".

> ℹ️ Info : le timer est *paresseux* — il vérifie au prochain appel, pas en arrière-plan. Donc un Vault "déverrouillé depuis 12h" mais inactif est en réalité verrouillé dès qu'on lui parle. C'est par design.

### Verrouillage manuel

- Settings → Secret Vault → bouton **"Verrouiller maintenant"**.
- Ou raccourci clavier `Ctrl+Shift+L` dans Argus.

Ferme aussi Argus complètement si tu pars de ta machine — le Vault est verrouillé en mémoire à la fermeture du process.

### Changer le mot de passe maître

Settings → Secret Vault → **"Changer le mot de passe maître"**. Il faut connaître l'ancien. Le Vault re-chiffre tous les secrets avec la nouvelle clé dérivée, atomiquement.

> ⚠️ Warning : si l'opération est interrompue (kill -9 du process en plein milieu), un fichier `secret_vault.bin.bak` est conservé. Le Vault détectera la corruption au prochain démarrage et te proposera de restaurer le backup.

---

## Mot de passe maître perdu

**Le Vault est irrécupérable par design.** Aucun backdoor. Aucun "code de récupération" caché. Aucune réinitialisation administrateur.

Si tu as perdu ton mot de passe maître :

1. Supprime `argus_data/.secret_vault/secret_vault.bin` (et le `.bak`).
2. Relance Argus → le Vault sera vu comme "non initialisé".
3. Settings → Secret Vault → "Initialiser le Vault" avec un nouveau mot de passe.
4. **Ré-entre toutes tes clés API à la main.**

> ⚠️ Warning : ne perds pas ton mot de passe. Stocke-le dans un gestionnaire externe. C'est la seule chose qui te sépare de tes clés.

---

## FAQ

### "Puis-je partager le Vault entre plusieurs machines ?"

**Non.** La couche keyring (Windows Credential Manager) est *machine-bound* — elle stocke un secret aléatoire de 32 bytes qui n'existe que sur cette machine. Copier `secret_vault.bin` sur un autre PC ne fonctionne pas : le Vault ne pourra pas dériver `KEK_unwrap` sans le keyring local.

Si tu veux la même clé Anthropic sur deux machines :
- Initialise le Vault sur chacune.
- Re-entre la clé manuellement sur les deux.

### "Le Vault se synchronise-t-il dans le cloud ?"

**Non, intentionnellement.** Aucune synchro Dropbox / OneDrive / Google Drive. Le fichier vit dans `argus_data/.secret_vault/` à côté du dépôt. Si ce dossier est dans un cloud sync, le fichier remontera — mais sera inutilisable ailleurs (cf. réponse précédente).

> ✅ Tip : ajoute `argus_data/.secret_vault/` à `.gitignore` (déjà fait dans le dépôt) et exclus-le aussi de tes services de sync — c'est plus propre.

### "Que se passe-t-il si je désinstalle NetGuard ?"

Le Vault reste dans `argus_data/.secret_vault/` jusqu'à ce que tu le supprimes manuellement. Le désinstalleur ne le touche pas — c'est une protection contre la perte accidentelle.

Pour supprimer définitivement : `rm -rf argus_data/.secret_vault/` (ou Explorer → supprimer le dossier).

### "Quelqu'un avec mon mot de passe Windows peut-il déchiffrer mes secrets ?"

**Partiellement, oui.** S'il a ton mot de passe Windows et un accès à ta session, il franchit Layer 1 (DPAPI) et Layer 2 (keyring) gratuitement. **Mais Layer 3 (Argon2id master) tient toujours** — sans ton mot de passe maître, le Vault refuse de s'ouvrir.

C'est exactement le scénario "malware même utilisateur" que le Vault est conçu pour bloquer.

### "Et si `pywin32` n'est pas installé ?"

Le Vault détecte la dépendance manquante et refuse de se charger. Un bandeau jaune dans l'UI affiche la commande exacte à lancer :

```
pip install pywin32 keyring argon2-cffi
```

Tant que le bandeau est là, la suite tourne en **mode plaintext fallback** : tes clés sont lues depuis `.env` ou `netguard_ai_settings.json` directement. C'est fonctionnel mais sans aucune protection. Installe les dépendances dès que possible.

### "Le Vault est-il accessible par d'autres applications ?"

Non. Le Vault est un module Python interne — seuls Argus, NetGuard et FORGE (suite cousine) qui chargent `secret_vault.py` peuvent l'ouvrir. Il n'y a pas d'API REST, pas de socket, pas de service système. Tu ne peux pas faire `vault get anthropic_key` depuis un terminal externe.

### "Puis-je avoir plusieurs Vaults ?"

Pas dans la version actuelle — un seul Vault par installation. Si tu as besoin de séparer les contextes (perso vs. boulot), la solution V1 est de faire deux clones du dépôt avec deux dossiers `argus_data/` distincts.

### "Le journal d'audit, c'est quoi ?"

Chaque appel au Vault (set, get, lock, unlock, change_master) écrit une ligne dans un journal append-only **chiffré dans le Vault lui-même**. Tu peux le consulter via Settings → Secret Vault → "Voir l'audit".

Aucun secret en clair n'y apparaît — uniquement les **noms** des clés et l'**opération**.

> ℹ️ Info : le journal est borné à 5000 entrées. Les plus anciennes sont évincées au fur et à mesure. Suffisant pour ~30 jours d'usage modéré.

---

## Voir aussi

- [secret_vault_spec.md](secret_vault_spec.md) — spec technique complète (threat model + architecture)
- [ai_assistant_user_guide.md](ai_assistant_user_guide.md) — comment l'AI Assistant consomme le Vault
- [troubleshooting.md](troubleshooting.md) — résolution des erreurs Vault courantes
