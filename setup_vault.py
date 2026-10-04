"""NetGuard AI Suite — Secret Vault interactive setup.

Run this in YOUR terminal (CMD / PowerShell / Git Bash):

    python setup_vault.py

The script will:
  1. Check that vault deps are installed (argon2-cffi, keyring, pywin32)
  2. Verify whether the vault is already initialised
  3. Prompt you for a master password (typed but NOT echoed)
  4. Initialise the vault on first run / unlock on subsequent runs
  5. Migrate any plaintext secrets from netguard_settings.json + ai_settings.json
  6. Print a summary

Your master password NEVER appears on screen, in logs, or in shell history.
If you forget it, the vault is unrecoverable BY DESIGN — Argon2id has no escrow.

After this runs successfully, you can:
  - Add API keys interactively via:  python -c "from secret_vault import SecretVault; v = SecretVault(); v.unlock(input('master:')); v.set('netguard.anthropic.api_key', input('key:'))"
  - Or use the NetGuard dashboard: Threat Intelligence -> Secret Vault card
  - Or use Argus: AI panel (Ctrl+J) -> gear icon -> Settings
"""
from __future__ import annotations

import getpass
import json
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parent
# SecretVault internally appends "/.secret_vault" to vault_root, so we point
# vault_root at argus_data/ and the real vault lands in argus_data/.secret_vault/
VAULT_ROOT = REPO / "argus_data"
VAULT_DIR = VAULT_ROOT / ".secret_vault"
NG_SETTINGS = REPO / "netguard_settings.json"
AI_SETTINGS = REPO / "argus_data" / "ai_settings.json"


def banner(text: str) -> None:
    print()
    print("=" * 60)
    print(f"  {text}")
    print("=" * 60)


def check_deps() -> bool:
    banner("1/5  Vérification des dépendances")
    missing = []
    try:
        import argon2  # noqa: F401
        print("  [OK] argon2-cffi (Layer 3 master KDF)")
    except ImportError:
        missing.append("argon2-cffi")
        print("  [!!] argon2-cffi MANQUANT")
    try:
        import keyring  # noqa: F401
        print("  [OK] keyring     (Layer 2 Credential Manager)")
    except ImportError:
        missing.append("keyring")
        print("  [!!] keyring     MANQUANT")
    try:
        import win32crypt  # noqa: F401
        print("  [OK] pywin32     (Layer 1 DPAPI)")
    except ImportError:
        if sys.platform == "win32":
            missing.append("pywin32")
            print("  [!!] pywin32     MANQUANT (Windows seulement)")
        else:
            print("  [--] pywin32     non requis hors Windows")
    if missing:
        print()
        print(f"  Installer avec :  pip install {' '.join(missing)}")
        return False
    print()
    print("  Toutes les dépendances présentes.")
    return True


def check_existing_vault() -> bool:
    """Return True if vault already exists."""
    banner("2/5  État du coffre")
    from secret_vault import SecretVault
    v = SecretVault(vault_root=VAULT_ROOT)
    if v.exists():
        print("  Coffre existant détecté.")
        print(f"  Emplacement : {VAULT_DIR}")
        return True
    print("  Aucun coffre — première initialisation.")
    print(f"  Sera créé dans : {VAULT_DIR}")
    return False


def prompt_master(confirm: bool) -> str:
    while True:
        m = getpass.getpass("  Mot de passe maître (8+ caractères) : ")
        if len(m) < 8:
            print("  [!!] Trop court (min 8). Réessaie.")
            continue
        if confirm:
            m2 = getpass.getpass("  Confirme : ")
            if m != m2:
                print("  [!!] Les deux saisies diffèrent. Réessaie.")
                continue
        return m


def init_or_unlock(existing: bool) -> object:
    banner(f"3/5  {'Déverrouillage' if existing else 'Création'} du coffre")
    print()
    if existing:
        print("  Entre ton master password pour déverrouiller.")
    else:
        print("  Choisis un master password — il chiffrera TOUS les secrets")
        print("  de la suite (NetGuard threat-intel + Argus AI keys).")
        print()
        print("  Recommandations :")
        print("    - Phrase de 4+ mots aléatoires (ex. 'cheval bleu mango piano')")
        print("    - OU stocké dans un password manager (1Password, Bitwarden)")
        print("    - PAS de mot du dictionnaire seul")
        print("    - PAS le même que ton mot de passe Windows")
        print()
        print("  ⚠ Si tu l'oublies, le coffre est PERDU (Argon2id sans escrow).")
        print("    Aucun mécanisme de récupération possible — by design.")
        print()
    from secret_vault import SecretVault
    v = SecretVault(vault_root=VAULT_ROOT)
    if not existing:
        master = prompt_master(confirm=True)
        v.init(master)
        print("  [OK] Coffre créé.")
    else:
        for attempt in range(3):
            master = prompt_master(confirm=False)
            try:
                v.unlock(master)
                print("  [OK] Coffre déverrouillé.")
                return v
            except Exception as e:
                print(f"  [!!] Échec : {type(e).__name__}")
                if attempt == 2:
                    print("  3 tentatives échouées. Abort.")
                    sys.exit(1)
                print(f"  Reste {2 - attempt} tentative(s).")
        return v
    v.unlock(master)
    return v


def find_plaintext_secrets() -> list[tuple[str, str, str]]:
    """Return list of (vault_name, source_path, plaintext_value)."""
    found: list[tuple[str, str, str]] = []
    if NG_SETTINGS.exists():
        ng = json.load(open(NG_SETTINGS))
        for k, vault_name in [
            ("virustotal_api_key", "netguard.virustotal.api_key"),
            ("otx_api_key", "netguard.otx.api_key"),
            ("abuseipdb_api_key", "netguard.abuseipdb.api_key"),
            ("discord_webhook_url", "netguard.discord.webhook"),
            ("telegram_bot_token", "netguard.telegram.bot_token"),
        ]:
            v = ng.get(k, "")
            if v:
                found.append((vault_name, str(NG_SETTINGS), v))
    if AI_SETTINGS.exists():
        ai = json.load(open(AI_SETTINGS))
        for k, val in (ai.get("api_keys", {}) or {}).items():
            if val:
                found.append((f"argus.{k}.api_key", str(AI_SETTINGS), val))
    return found


def migrate_plaintext(vault) -> None:
    banner("4/5  Migration des secrets plaintext")
    plaintext = find_plaintext_secrets()
    if not plaintext:
        print("  Aucun secret plaintext détecté. Rien à migrer.")
        return
    print(f"  {len(plaintext)} secret(s) à migrer :")
    for name, src, _ in plaintext:
        print(f"    - {name}  (depuis {Path(src).name})")
    print()
    answer = input("  Migrer maintenant ? [O/n] ").strip().lower()
    if answer in ("n", "no", "non"):
        print("  Migration annulée. Les plaintext restent en place.")
        return
    for name, src, val in plaintext:
        vault.set(name, val)
        print(f"  [OK] {name} migré.")
    # Strip plaintext from settings + backup originals
    if NG_SETTINGS.exists():
        ng = json.load(open(NG_SETTINGS))
        backup = NG_SETTINGS.with_suffix(".pre-vault.bak")
        backup.write_text(json.dumps(ng, indent=2))
        for k in ("virustotal_api_key", "otx_api_key", "abuseipdb_api_key",
                  "discord_webhook_url", "telegram_bot_token"):
            if ng.get(k):
                ng[k] = ""
        json.dump(ng, open(NG_SETTINGS, "w"), indent=2)
        print(f"  [OK] {NG_SETTINGS.name} nettoyé (backup → {backup.name}).")
    if AI_SETTINGS.exists():
        ai = json.load(open(AI_SETTINGS))
        if "api_keys" in ai:
            backup = AI_SETTINGS.with_suffix(".pre-vault.bak")
            backup.write_text(json.dumps(ai, indent=2))
            ai["api_keys"] = {}
            ai["api_key_in_vault"] = True
            json.dump(ai, open(AI_SETTINGS, "w"), indent=2)
            print(f"  [OK] {AI_SETTINGS.name} nettoyé (backup → {backup.name}).")


def summary(vault) -> None:
    banner("5/5  Résumé")
    secrets = vault.list()
    print(f"  Coffre déverrouillé : OUI")
    print(f"  Secrets stockés     : {len(secrets)}")
    if secrets:
        for entry in sorted(secrets, key=lambda e: e.get("name", "")):
            print(f"    - {entry.get('name', '<?>')}")
    print()
    print("  Pour ajouter d'autres clés :")
    print("    1. Lance NetGuard : python netguard.py")
    print("       Dashboard → Threat Intelligence → Secret Vault → Unlock")
    print("    2. Ou Argus : python argus_pyqt.py")
    print("       Panel AI (Ctrl+J) → ⚙ → Saisis tes clés Claude/GPT/Gemini")
    print()
    print("  Le coffre se verrouille automatiquement après 15 min d'inactivité.")
    print("  Pour le déverrouiller à nouveau, relance ce script ou utilise l'UI.")
    vault.lock()
    print("  [OK] Coffre verrouillé après ce setup.")


def main() -> int:
    print()
    print("  NetGuard AI Suite — Secret Vault interactive setup")
    print()
    if not check_deps():
        return 1
    existing = check_existing_vault()
    vault = init_or_unlock(existing)
    if vault is None:
        return 1
    migrate_plaintext(vault)
    summary(vault)
    print()
    print("  Setup terminé. Bonne chasse aux menaces ✓")
    print()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n  Annulé.")
        sys.exit(130)
    except Exception as e:
        print(f"\n  [!!] Erreur fatale : {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
