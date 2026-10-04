# Guide GitHub — Publier NetGuard AI

## Étape 1 — Créer le dépôt sur GitHub

1. Va sur https://github.com/new
2. Remplis comme ceci :
   - **Repository name** : `netguard-pro`
   - **Description** : `Real-time network monitoring dashboard with automatic threat detection and blocking`
   - **Visibilité** : ✅ Public
   - **NE PAS cocher** "Add a README file" (on a déjà le nôtre)
   - **NE PAS cocher** "Add .gitignore" (on a déjà le nôtre)
   - **License** : None (on a déjà le fichier LICENSE)
3. Clique **Create repository**

---

## Étape 2 — Installer Git sur Windows

1. Va sur https://git-scm.com/download/win
2. Télécharge et installe (options par défaut)
3. Redémarre le cmd/PowerShell après l'installation

---

## Étape 3 — Configurer Git (une seule fois)

Ouvre PowerShell et tape :

```bash
git config --global user.name "sxc3030-eng"
git config --global user.email "ton-email@exemple.com"
```

---

## Étape 4 — Publier le projet

Dans PowerShell, navigue vers ton dossier NetGuard :

```bash
# Remplace le chemin par l'emplacement réel de tes fichiers
cd C:\Users\TonNom\Desktop\netguard

# Initialiser Git
git init

# Ajouter tous les fichiers
git add .

# Premier commit
git commit -m "Initial release - NetGuard AI v1.0"

# Connecter au dépôt GitHub (remplace avec ton URL)
git remote add origin https://github.com/sxc3030-eng/netguard-pro.git

# Publier
git branch -M main
git push -u origin main
```

---

## Étape 5 — Vérifier sur GitHub

Va sur https://github.com/sxc3030-eng/netguard-pro
Tu devrais voir tous tes fichiers et le README affiché automatiquement.

---

## Étape 6 — Ajouter des topics (mots-clés)

Sur la page GitHub de ton projet :
1. Clique sur l'icône ⚙️ à côté de "About"
2. Dans **Topics**, ajoute :
   - `cybersecurity`
   - `network-monitoring`
   - `python`
   - `firewall`
   - `ids`
   - `packet-analysis`
   - `scapy`
   - `windows`
3. Clique **Save changes**

Ça aide les gens à trouver ton projet dans les recherches GitHub.

---

## Pour les mises à jour futures

Chaque fois que tu modifies le code :

```bash
cd C:\Users\TonNom\Desktop\netguard
git add .
git commit -m "Description de ce que t'as changé"
git push
```

---

## URL de ton projet

https://github.com/sxc3030-eng/netguard-pro
