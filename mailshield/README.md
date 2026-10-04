<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10+-green?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-orange?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/platform-Windows-lightblue?style=for-the-badge&logo=windows" alt="Platform">
</p>

<h1 align="center">MailShield Pro</h1>
<h3 align="center">Client Email Securise avec Filtrage Intelligent & Protection Anti-Phishing</h3>

<p align="center">
  <b>Partie de l'ecosysteme <a href="#">NetGuard AI</a></b><br>
  Un client email local, securise et intelligent qui filtre, classe et protege vos emails en temps reel.
</p>

---

## Apercu

MailShield Pro est un client email desktop complet construit en Python, avec une interface web moderne (dark mode). Il se connecte directement a vos comptes Gmail, Outlook/Hotmail, Yahoo et iCloud, puis analyse chaque email entrant pour detecter le phishing, les pieces jointes dangereuses et le spam, tout en classant automatiquement vos messages par categorie.

### Pourquoi MailShield Pro ?

- **Zero cloud** - Tout est local sur votre machine. Aucune donnee n'est envoyee a un serveur tiers.
- **Anti-phishing avance** - Detection de spoofing de domaine, liens suspects, urgence artificielle, usurpation de nom.
- **Filtrage intelligent** - 170+ mots-cles predefinies repartis en 6 categories, entierement configurables.
- **Mode sandbox** - Ouvrez les emails suspects en mode protege : scripts, liens et images externes desactives.
- **Connexion simple** - OAuth2 en 1 clic pour Microsoft, assistant guide pour Gmail.

---

## Fonctionnalites

### Gestion des emails
- Synchronisation IMAP multi-comptes (Gmail, Outlook, Yahoo, iCloud)
- Classification automatique : **Principal**, **Social**, **Promotions**, **Notifications**, **Spam**
- Envoi d'emails via SMTP avec support CC/BCC
- Recherche plein texte (sujet, expediteur, contenu)
- Favoris, suppression, deplacement entre categories
- Actualisation automatique configurable (intervalle en secondes)

### Securite & protection

| Fonctionnalite | Description |
|---|---|
| **Detection phishing** | 40 mots-cles, 13 TLDs suspects, 7 marques protegees (PayPal, Google, Microsoft...) |
| **Scan des pieces jointes** | 28 extensions bloquees (.exe, .bat, .vbs...), 14 surveillees (.zip, .docm...) |
| **Mode sandbox** | Liens desactives, scripts supprimes, iframes bloques, images externes supprimees |
| **Score de confiance** | Chaque email recoit un score 0-100% base sur l'expediteur, le contenu et les PJ |
| **Liste noire** | Bloquez des emails ou domaines entiers, import/export en masse |
| **Journal des menaces** | Dashboard avec statistiques, historique et severite des menaces |
| **Anti-spoofing** | Detection d'usurpation de domaine (paypa1.com, g00gle.com...) |
| **Anti-tracking** | Blocage des pixels de tracking et images externes |

### Carnet d'adresses
- Contacts avec groupes (General, Famille, Travail, Amis, VIP)
- Contacts de confiance (bypass les filtres agressifs)
- Auto-completion lors de la composition
- Import / Export CSV
- Blocage d'expediteurs

### Interface
- Theme dark moderne inspire d'Outlook/Gmail
- Bilingue : Francais / English (basculable en 1 clic)
- Responsive (desktop, tablette)
- Raccourcis clavier : `N` nouveau message, `R` actualiser, `Suppr` supprimer
- Notifications toast

---

## Architecture technique

```
mailshield/
  mailshield.py              # Backend Python (1,987 lignes)
  mailshield_dashboard.html  # Interface web (1,673 lignes)
  mailshield_settings.json   # Configuration (12.7 Ko)
  mailshield.db              # Base SQLite (auto-generee)
  mailshield_quarantine/     # PJ en quarantaine
LANCER_MAILSHIELD.bat        # Lanceur Windows
```

### Stack technique

| Composant | Technologie |
|---|---|
| Backend | Python 3.10+ |
| Frontend | HTML5 / CSS3 / JavaScript vanilla |
| Serveur HTTP | `http.server` (stdlib) |
| WebSocket | `websockets` (temps reel) |
| Base de donnees | SQLite3 avec WAL |
| Auth Microsoft | MSAL (OAuth2 / XOAUTH2) |
| Protocoles email | IMAP4 / SMTP |

### Base de donnees (6 tables)

| Table | Description |
|---|---|
| `emails` | Emails stockes (24 colonnes, indexes) |
| `attachments` | Pieces jointes avec scan et quarantaine |
| `contacts` | Carnet d'adresses avec groupes et confiance |
| `contact_groups` | Groupes de contacts |
| `blacklist` | Liste noire (emails + domaines) |
| `threats` | Journal des menaces detectees |

### API REST (30 endpoints)

<details>
<summary><b>GET endpoints (18)</b></summary>

| Route | Description |
|---|---|
| `GET /api/emails?category=&search=&page=` | Liste des emails filtres |
| `GET /api/email/{id}` | Detail d'un email |
| `GET /api/contacts?q=` | Recherche de contacts |
| `GET /api/contacts/groups` | Groupes de contacts |
| `GET /api/contacts/export` | Export CSV des contacts |
| `GET /api/categories/counts` | Compteurs par categorie |
| `GET /api/settings` | Configuration complete |
| `GET /api/settings/filters` | Filtres par mots-cles |
| `GET /api/account/status` | Statut de connexion |
| `GET /api/providers` | Fournisseurs supportes |
| `GET /api/provider/detect?email=` | Detection auto du fournisseur |
| `GET /api/attachment/{id}` | Telechargement PJ |
| `GET /api/blacklist` | Liste noire |
| `GET /api/blacklist/export` | Export liste noire |
| `GET /api/threats?limit=&severity=` | Journal des menaces |
| `GET /api/threats/stats` | Statistiques menaces |
| `GET /api/i18n?lang=` | Traductions |
| `GET /api/i18n/all` | Toutes les langues |

</details>

<details>
<summary><b>POST endpoints (12+)</b></summary>

| Route | Description |
|---|---|
| `POST /api/send` | Envoyer un email |
| `POST /api/sync` | Synchroniser les emails |
| `POST /api/email/delete` | Supprimer un email |
| `POST /api/email/star` | Favori on/off |
| `POST /api/email/move` | Deplacer dans une categorie |
| `POST /api/email/report-spam` | Signaler comme spam + blacklist |
| `POST /api/contacts/add` | Ajouter un contact |
| `POST /api/contacts/import` | Import CSV de contacts |
| `POST /api/quickconnect` | Connexion rapide (Gmail/Yahoo) |
| `POST /api/ms-oauth/connect` | Connexion OAuth2 Microsoft |
| `POST /api/blacklist/add` | Ajouter a la liste noire |
| `POST /api/blacklist/import` | Import en masse |
| `POST /api/phishing/scan` | Analyse phishing d'un email |
| `POST /api/sandbox/toggle` | Activer/desactiver le sandbox |
| `POST /api/settings/update` | Sauvegarder les parametres |

</details>

---

## Installation

### Prerequis

- **Windows 10/11**
- **Python 3.10+** ([python.org](https://python.org))
- Un compte email (Gmail, Outlook/Hotmail, Yahoo ou iCloud)

### Lancement rapide

```bash
# 1. Clonez le repo
git clone https://github.com/votre-repo/netguard-pro.git
cd netguard-pro

# 2. Lancez MailShield
LANCER_MAILSHIELD.bat
```

Le script installe automatiquement les dependances (`websockets`, `msal`) et ouvre le dashboard dans votre navigateur par defaut.

### Installation manuelle

```bash
pip install websockets msal
cd mailshield
python mailshield.py
```

Puis ouvrez **http://127.0.0.1:8800** dans votre navigateur.

---

## Configuration des comptes email

### Microsoft (Hotmail / Outlook / Live)

1. Cliquez sur **"Se connecter avec Microsoft"**
2. Une fenetre de connexion Microsoft s'ouvre
3. Connectez-vous et autorisez l'acces
4. Terminé - OAuth2 securise, aucun mot de passe stocke

### Gmail

1. Cliquez sur **"Se connecter avec Gmail"**
2. Suivez l'assistant en 3 etapes :
   - Activez la verification en 2 etapes sur votre compte Google
   - Generez un mot de passe d'application sur [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
   - Collez le mot de passe de 16 caracteres dans MailShield

### Yahoo / iCloud

Meme principe que Gmail : generez un mot de passe d'application depuis les parametres de securite de votre compte.

---

## Filtrage par mots-cles

MailShield classe automatiquement vos emails grace a **170+ mots-cles** repartis en categories :

| Categorie | Exemples de mots-cles | Nombre |
|---|---|---|
| **Spam** | casino, lottery, viagra, prince, bitcoin gratuit... | 50 |
| **Promotions** | soldes, promo, discount, coupon, newsletter... | 35 |
| **Social** | facebook, instagram, linkedin, friend request... | 32 |
| **Notifications** | confirmation, verification, delivery, invoice... | 37 |
| **Important** | urgent, deadline, meeting, contract... | 17 |

Tous les mots-cles sont **modifiables** dans l'interface (section Filtres) ou directement dans `mailshield_settings.json`.

---

## Detection de phishing

Le moteur anti-phishing analyse chaque email sur **7 criteres** :

1. **TLDs suspects** - .ru, .cn, .tk, .xyz, .buzz, .click... (13 TLDs)
2. **Mots-cles de phishing** - "verify your account", "wire transfer"... (40 termes FR+EN)
3. **Usurpation de domaine** - paypa1.com, g00gle.com, amaz0n.com... (7 marques)
4. **Discordance nom/domaine** - Nom "PayPal" mais domaine @scam.xyz
5. **Liens suspects** - URLs raccourcis (bit.ly, tinyurl), pages de login
6. **Langage d'urgence** - "act now", "24 hours", "derniere chance"
7. **Majuscules excessives** - Sujets en CAPS (technique de spam)

Chaque email recoit un **score de 0 a 100** :

| Score | Severite | Action |
|---|---|---|
| 0-30 | Faible | Aucune |
| 30-50 | Moyenne | Avertissement |
| 50-70 | Haute | Alerte rouge + bouton bloquer |
| 70-100 | Critique | Alerte critique |

---

## Mode Sandbox (Protege)

Activez le mode sandbox via le bouton bouclier dans la toolbar :

- **Scripts** supprimes
- **Liens** desactives et barres (clic = alerte)
- **iFrames** bloques
- **Images externes** bloquees
- **Pixels de tracking** supprimes

Ideal pour ouvrir des emails suspects sans risque.

---

## Securite des pieces jointes

### Extensions bloquees (28)

```
.exe .bat .cmd .com .vbs .vbe .js .jse .wsf .wsh .msi .scr
.pif .cpl .hta .inf .reg .ps1 .psm1 .psd1 .lnk .url .dll .sys
.drv .ocx .crt .cer
```

### Extensions surveillees (14)

```
.zip .rar .7z .tar .gz .iso .img .docm .xlsm .pptm .dotm
.xltm .potm .jar
```

Les pieces jointes sont analysees avec un **score de confiance** et peuvent etre automatiquement mises en quarantaine.

---

## Raccourcis clavier

| Touche | Action |
|---|---|
| `N` | Nouveau message |
| `R` | Actualiser les emails |
| `Suppr` | Supprimer l'email selectionne |

---

## Configuration

Le fichier `mailshield_settings.json` contient toute la configuration :

```json
{
  "accounts": [...],           // Comptes email
  "filter_keywords": {...},    // Mots-cles de filtrage
  "attachment_security": {...},// Securite des PJ
  "categories": {...},         // Categories d'emails
  "interface": {...},          // Preferences d'affichage
  "security": {...},           // Parametres de securite
  "server": {                  // Ports du serveur
    "host": "127.0.0.1",
    "http_port": 8800,
    "ws_port": 8801
  }
}
```

---

## Dependances

| Package | Version | Usage |
|---|---|---|
| `websockets` | 12+ | Communication temps reel |
| `msal` | 1.25+ | OAuth2 Microsoft |

Toutes les autres dependances font partie de la bibliothèque standard Python.

---

## Structure du projet

```
netguard-pro-3.0.0/
  LANCER_MAILSHIELD.bat           # Lanceur Windows
  mailshield/
    mailshield.py                 # Moteur principal (1,987 lignes)
    mailshield_dashboard.html     # Interface web (1,673 lignes)
    mailshield_settings.json      # Configuration
    mailshield.db                 # Base de donnees SQLite
    mailshield_quarantine/        # Dossier de quarantaine
    README.md                     # Ce fichier
```

---

## FAQ

**Q: Mes emails sont-ils envoyes quelque part ?**
Non. Tout reste local sur votre machine. MailShield communique uniquement avec les serveurs IMAP/SMTP de votre fournisseur email.

**Q: Pourquoi Gmail demande un mot de passe d'application ?**
Google a desactive l'authentification par mot de passe normal en 2022. Les mots de passe d'application sont la seule methode supportee pour les applications tierces.

**Q: Pourquoi Hotmail utilise OAuth2 ?**
Microsoft a desactive toute forme d'authentification par mot de passe (y compris les mots de passe d'application) en 2024. OAuth2 est la seule methode qui fonctionne.

**Q: Le mode sandbox protege-t-il contre les virus ?**
Le sandbox desactive les scripts, liens et images externes dans le HTML de l'email. Il ne remplace pas un antivirus, mais empeche les attaques par clic (phishing, drive-by downloads).

**Q: Comment ajouter des mots-cles de filtrage ?**
Interface > Filtres > Selectionnez une categorie > Tapez un mot-cle > Cliquez +

---

## Licence

MIT License - Voir [LICENSE](../LICENSE)

---

<p align="center">
  <b>MailShield Pro</b> fait partie de l'ecosysteme <b>NetGuard AI</b><br>
  <sub>Developpe avec Python, securise par design</sub>
</p>
