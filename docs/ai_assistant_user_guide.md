# AI Assistant — Guide utilisateur

L'AI Assistant d'Argus est un panneau latéral conversationnel qui te connecte à **Claude (Anthropic)**, **GPT (OpenAI)** ou **Gemini (Google)** depuis l'intérieur du browser. Il connaît la page que tu regardes, peut analyser le réseau via NetGuard, et propose un mode agent (avec approbation explicite) pour exécuter des actions de cybersécurité.

Tout est en **BYOK** — Bring Your Own Key. Aucun proxy serveur entre toi et le provider.

---

## Ce que fait le panneau

- **Chat contextuel** : discute de la page Web courante, demande un résumé, une analyse de sécurité, une comparaison.
- **Streaming** : Claude et GPT envoient leurs réponses token-par-token. Gemini répond en bloc (limitation Gemini, pas un bug).
- **Slash commands** : injecte URL, sélection de texte, ou screenshot dans ta question d'un seul caractère.
- **Multi-provider** : switch Claude ↔ GPT ↔ Gemini dans le menu déroulant en haut du panneau.
- **Mémoire persistante** : chaque conversation est sauvegardée dans `argus_data/ai_history.json`.

![](imgs/ai-panel-overview.png)

---

## BYOK — où récupérer tes clés

L'Assistant ne fournit **aucune clé** — tu dois en obtenir auprès du provider. Trois liens :

| Provider | URL d'inscription | Format de clé |
|----------|-------------------|---------------|
| Claude (Anthropic) | [console.anthropic.com](https://console.anthropic.com/) → Settings → API Keys | `sk-ant-api03-...` |
| GPT (OpenAI) | [platform.openai.com](https://platform.openai.com/api-keys) | `sk-...` ou `sk-proj-...` |
| Gemini (Google) | [aistudio.google.com](https://aistudio.google.com/apikey) | `AIza...` |

> ⚠️ Warning : chaque provider facture son usage à **ton** compte. Tu paies tes propres tokens. NetGuard ne prend aucune commission, n'a aucun compte intermédiaire, et ne voit pas tes appels.

> ℹ️ Info : tu n'as pas besoin des trois clés. Configure uniquement les providers que tu veux utiliser. Le menu déroulant n'affiche que les providers activés.

---

## Setup — configuration des clés (5 étapes)

1. Lance Argus : `python argus_pyqt.py` ou `LANCER_ARGUS_2.bat`.
2. Clique sur l'icône 🤖 dans la barre Argus pour ouvrir le panneau AI.
3. Clique sur ⚙ (Settings) en haut du panneau.
4. Onglet **"Providers"** → entre les clés des providers que tu veux utiliser.
5. Clique **"Sauvegarder"**. Le panneau redémarre et le menu déroulant en haut affiche les providers configurés.

![](imgs/ai-settings-providers.png)

### Mode Vault (recommandé) vs. mode plaintext

Si le Vault est initialisé et déverrouillé, **les clés y sont stockées automatiquement** au moment du Save. Le fichier `netguard_ai_settings.json` ne contient que les paramètres non-secrets (modèle par défaut, max_tokens, etc.) avec un drapeau `"api_key_in_vault": true`.

Si le Vault n'est pas configuré, les clés vont en clair dans `netguard_ai_settings.json`. Un bandeau jaune apparaît dans le panneau AI pour t'inviter à activer le Vault. Voir [secret_vault_user_guide.md](secret_vault_user_guide.md).

> ✅ Tip : configure le Vault **avant** d'entrer tes clés. Si tu as déjà entré des clés en clair, utilise le bouton "Migrer depuis netguard_ai_settings.json" du Vault — il les déplace en un clic.

---

## Slash commands

Les slash commands injectent du contexte dans ta question sans que tu aies à le copier-coller. Trois disponibles :

| Commande | Effet | Exemple |
|----------|-------|---------|
| `/url` | Injecte l'URL de l'onglet courant | `/url quelle est la posture de sécurité de ce site ?` |
| `/selection` | Injecte le texte sélectionné dans la page | `/selection traduis ce paragraphe en anglais` |
| `/screenshot` | Capture la page entière et l'envoie comme image | `/screenshot que vois-tu de suspect ?` |

### Combinaison

Plusieurs slash commands peuvent être chaînés en début de prompt :

```
/url /selection ce site dit ceci, est-ce cohérent avec son contenu ?
```

L'Assistant reçoit alors un bloc `[Slash context]` qui contient l'URL + la sélection, suivi de ta question.

### Limites

- `/screenshot` capture **uniquement la zone visible** de l'onglet (pas la page complète défilante).
- L'image est plafonnée par Argus pour respecter la limite Qt et la quota provider — ~2 MB max après JPEG.
- Une slash command **doit être en début** de prompt. `hello /url world` n'invoque rien — c'est traité comme du texte normal.
- `/screenshot` consomme des tokens vision : Claude Sonnet 4.5 et GPT-4o le supportent, Gemini aussi. Si tu utilises un modèle text-only, l'Assistant te le signale et la commande échoue.

![](imgs/ai-slash-commands.png)

---

## Streaming des réponses

Par défaut :

| Provider | Streaming | Notes |
|----------|-----------|-------|
| Claude | ✅ Oui (SSE) | Token-par-token, latence ~50ms |
| GPT | ✅ Oui (SSE) | Idem |
| Gemini | ❌ Non | Réponse en bloc — limitation API Google |

Pour désactiver le streaming (utile pour debugger ou loguer la réponse complète) : Settings → Providers → décoche "Activer le streaming".

> ℹ️ Info : pendant que la réponse stream, tu peux interrompre avec ⏹ (bouton Stop) à côté du champ d'envoi. La portion déjà reçue reste dans l'historique.

---

## Switch entre providers

Le menu déroulant en haut du panneau affiche les providers configurés. Switch en cours de conversation ne casse rien — la nouvelle réponse vient du nouveau provider, mais l'historique précédent (de l'autre provider) lui est passé comme contexte.

> ✅ Tip : pratique pour comparer — pose la même question à Claude puis switch sur GPT et envoie "et toi, tu en penses quoi ?".

---

## Mode agent (avec approbation)

L'Assistant peut exécuter des **actions** sur ta machine via un système d'outils. Chaque outil exige ton approbation **avant** exécution.

Outils actuellement disponibles (selon la version) :

- `block_ip(ip)` — pousse une règle iptables/netsh.
- `audit_program(path)` — analyse un binaire local (CleanGuard).
- `audit_network()` — sollicite NetGuard pour un état du réseau.
- `read_logs(file)` — lit un log local (`.log` uniquement, jamais des fichiers user).

Quand l'Assistant veut invoquer un outil, une boîte de dialogue te demande **"Autoriser ?"** avec les arguments visibles. Tu peux :
- **Approuver** une fois.
- **Approuver et mémoriser** pour cette session.
- **Refuser**, l'outil est annulé et l'Assistant en est informé.

![](imgs/ai-agent-approval.png)

> ⚠️ Warning : ne coche **jamais** "approuver et mémoriser" pour des outils que tu ne comprends pas. Le mode agent est puissant — un mauvais prompt peut te coûter une règle iptables qui te bloque toi-même de ta box.

---

## Confidentialité — ce qui sort de ta machine

| Donnée | Sort de ta machine ? | Vers où ? |
|--------|---------------------|-----------|
| Tes prompts | Oui | Vers le provider choisi (Anthropic / OpenAI / Google) |
| URL via `/url` | Oui (dans le prompt) | Idem |
| Texte sélectionné via `/selection` | Oui (dans le prompt) | Idem |
| Screenshot via `/screenshot` | Oui (image dans le prompt) | Idem |
| Tes clés API | Non | Restent dans le Vault local |
| Historique des conversations | Non | Reste dans `argus_data/ai_history.json` |
| État NetGuard | Non | Lu localement, sauf si l'Assistant l'inclut explicitement dans le prompt |

> ℹ️ Info : NetGuard n'a **aucun compte** chez Anthropic, OpenAI ou Google. Tes appels passent directement de ta machine au provider. **Ils sont régis par les Terms of Service du provider, pas par les nôtres.** Lis [console.anthropic.com/legal](https://www.anthropic.com/legal) etc.

> ✅ Tip : pour les conversations sensibles (audit interne, secrets clients), choisis un provider dont tu as déjà signé un BAA / DPA approprié. Anthropic et OpenAI offrent des plans Enterprise avec engagements de non-training.

---

## Performance & coûts

L'AI Assistant facture **côté provider**. Ordre de grandeur (avril 2026) :

- Claude Sonnet 4.7 : ~3$ / million de tokens input, ~15$ / million output.
- GPT-4o : ~2.50$ / million input, ~10$ / million output.
- Gemini 2.5 Pro : ~1.25$ / million input, ~5$ / million output.

Une conversation moyenne (10 échanges, contexte ~50k tokens) coûte de l'ordre de **0.10$ à 1$**. Surveille tes consoles provider pour le détail.

> ℹ️ Info : chaque provider impose un rate-limit. Si tu envoies 30 messages en 30 secondes, l'Assistant t'affiche un 429 explicite. Patiente ou réduis la fréquence.

---

## Voir aussi

- [secret_vault_user_guide.md](secret_vault_user_guide.md) — pour stocker tes clés API en sécurité
- [getting_started.md](getting_started.md) — installation et premier scan
- [troubleshooting.md](troubleshooting.md) — résolution des erreurs courantes (clé absente, panneau qui ne charge pas, etc.)
