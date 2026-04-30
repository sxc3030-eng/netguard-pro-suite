# Licence — Achat & activation

NetGuard Pro Suite est gratuit en version **Starter** (1 PC, fonctionnalités de base). La version **Pro** débloque l'AI Assistant, MailShield, CleanGuard, Sentinel, VPNGuard, Honeypot, FIM, Recorder, StrikeBack, et la rétention 90 jours.

---

## Tarifs

| Forfait | Prix | PCs inclus | Fonctionnalités |
|---------|------|------------|-----------------|
| Starter (gratuit) | 0$ / mois | 1 PC | NetGuard core + dashboard temps réel |
| Pro mensuel | 29$ / mois | 1 PC | Suite complète |
| Pro annuel | 290$ / an | 1 PC | Suite complète, **-17% vs. mensuel** |
| Pro multi-PC | +15$ / mois | par PC additionnel, jusqu'à 5 | identique au Pro |
| Au-delà de 5 PCs | sur devis | — | contact@netguardpro.com |

> ℹ️ Info : 1 license = 1 PC. Si tu veux NetGuard sur ton portable + ton fixe, tu prends Pro avec +15$/mois pour le poste additionnel. Le serveur de licences vérifie le compteur — tu ne peux pas dépasser le nombre de sièges payés.

> ✅ Tip : si tu hésites, prends le mensuel et passe à l'annuel quand tu es sûr — la conversion est gratuite et te crédite le solde.

---

## Où acheter

> ⚠️ Warning : la page de paiement n'est pas encore déployée à la date de rédaction. Le lien sera actif à la sortie publique.

- Page d'achat : `https://netguardpro.com/buy` *(placeholder, à publier)*
- Email contact : contact@netguardpro.com
- Support technique : support@netguardpro.com

---

## Réception du fichier de licence

Après paiement (Stripe / Gumroad), tu reçois un email contenant :

1. Un fichier **`netguard_license.json`** signé Ed25519 — c'est ta licence.
2. Un récapitulatif de tes sièges (1 PC, 2 PCs, etc.).
3. Un lien vers ton "compte" (page d'auto-gestion des appareils).

Conserve l'email — tu peux re-télécharger le `.lic` à tout moment.

![](imgs/license-email.png)

---

## Première activation

1. Quitte NetGuard si l'application tourne.
2. Place le fichier `netguard_license.json` à la **racine du dépôt** (au même niveau que `netguard.py`).
   ```
   netguard-pro-suite/
   ├── netguard_license.json   ← ici
   ├── netguard.py
   └── ...
   ```
3. Relance NetGuard. Au démarrage, le license_manager :
   - vérifie la signature Ed25519,
   - associe la licence à l'**empreinte machine** courante (UUID matériel + nom hôte),
   - envoie un ping au serveur d'activation pour incrémenter le compteur de sièges.
4. Tu vois en console :
   ```
   [license] Activated — Pro tier — 1 of 1 seats used.
   ```

> ✅ Tip : pas besoin de redémarrer le PC. La licence est lue à chaque démarrage NetGuard.

---

## Activer une machine supplémentaire (sièges multiples)

Si tu as un Pro multi-PC (ex. 3 sièges) :

1. Copie le **même** `netguard_license.json` sur la deuxième machine.
2. Place-le à la racine du dépôt cloné sur cette machine.
3. Relance NetGuard. La machine s'identifie auprès du serveur, qui valide qu'il reste un siège libre :
   ```
   [license] Activated — Pro tier — 2 of 3 seats used.
   ```

Si tous les sièges sont déjà pris, tu obtiens :

```
[license] ERROR — Seat exhausted (3/3 used). Deactivate a device first.
```

Voir la section "Désactivation" plus bas.

---

## Voir mes appareils activés

1. Ouvre NetGuard → Settings (engrenage en haut à droite).
2. Onglet **"Licence"** → bouton **"Manage devices"**.
3. La liste affiche pour chaque appareil :
   - Nom hôte (`DESKTOP-A1B2C3`)
   - Date d'activation
   - Date de dernier ping
   - Bouton **"Désactiver"**

![](imgs/license-manage-devices.png)

> ℹ️ Info : "Manage devices" ouvre une page Web vers ton compte, pas une fenêtre locale — la source de vérité est le serveur de licences, pas le client.

---

## Désactiver un appareil (libérer un siège)

Trois chemins pour libérer un siège :

**Depuis le PC à désactiver :**
1. Settings → Licence → bouton **"Désactiver cette machine"**.
2. NetGuard envoie un signal de release au serveur.
3. La machine retombe en mode Starter (gratuit) à la prochaine relance.

**Depuis ton compte Web :**
1. Page de gestion → liste des appareils → bouton **"Désactiver"** à côté du PC concerné.
2. La machine cible reverra son siège libéré au prochain ping (max 24h).

**À distance, si tu n'as plus accès au PC :**
1. Email à support@netguardpro.com avec ton numéro de licence.
2. Le support force la libération en 24-48h.

---

## Migrer vers un nouveau PC

Le pattern recommandé :

1. Sur l'**ancien** PC : Settings → Licence → "Désactiver cette machine".
2. Vérifie sur ton compte que le siège est libre.
3. Sur le **nouveau** PC : copie `netguard_license.json` à la racine du dépôt cloné, relance NetGuard.

> ✅ Tip : tu peux faire la migration en 5 minutes sans contacter le support. Tant que tu désactives proprement avant.

> ⚠️ Warning : si l'ancien PC est cassé / perdu / volé, tu n'as pas accès à "Désactiver cette machine". Utilise alors la page de gestion Web ou écris au support.

---

## Fichier de licence perdu

Si tu as supprimé ton `netguard_license.json` ou perdu l'email :

1. Va sur ton compte : `https://netguardpro.com/account` *(placeholder)*.
2. Connexion via le **mail utilisé à l'achat** (lien magique, pas de mot de passe).
3. Section "Mes licences" → bouton **"Re-télécharger le .lic"**.
4. Re-place le fichier à la racine du dépôt → relance NetGuard.

> ℹ️ Info : ton compte garde toutes tes licences passées — tu peux re-télécharger même 5 ans après l'achat tant que la suite existe.

---

## Remboursements & upgrades de sièges

- **Remboursement** : 14 jours sans condition, écris à billing@netguardpro.com avec ton numéro de licence.
- **Ajout de sièges** : page de gestion Web → "Ajouter un PC" → +15$/mois prorata. Pas de re-téléchargement nécessaire — la même licence s'élargit.
- **Downgrade Pro → Starter** : possible à la fin de la période payée. Tes données restent en place ; seules les fonctionnalités Pro sont désactivées.
- **Upgrade Starter → Pro** : achète une licence Pro, place le `.lic`, redémarre. Pas de migration de données.

> ✅ Tip : pour des questions facturation, billing@netguardpro.com répond en moins de 24h ouvrées.

---

## Mode trial (essai gratuit)

Si tu n'as pas encore acheté, NetGuard accorde un **trial de 30 jours** automatique au premier lancement. Toutes les fonctionnalités Pro sont débloquées pendant cette période. La console affiche :

```
[license] No license found — running in TRIAL mode (29 days left).
```

À la fin du trial, NetGuard tombe en Starter automatiquement (rien ne casse, juste les modules Pro sont coupés). Tu peux passer à Pro à n'importe quel moment.

> ℹ️ Info : un trial est lié à l'empreinte machine. Réinitialiser Windows ou changer de PC redémarre le compteur — c'est par design (pas un bug à exploiter, juste une tolérance).

---

## Voir aussi

- [getting_started.md](getting_started.md) — premier lancement
- [troubleshooting.md](troubleshooting.md) — résolution des erreurs (`Seat exhausted`, signature invalide, etc.)
- Comparatif détaillé Starter vs. Pro : [`netguard_plans.html`](../netguard_plans.html) (à la racine du dépôt)
