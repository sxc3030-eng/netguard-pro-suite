"""
NetGuard license keypair generator (Ed25519).

Run ONCE. Stores the private key in tools/keys/ (gitignored), prints the
public key so you can paste it into license_manager.py:LICENSE_PUBLIC_KEY_B64.

The PRIVATE key MUST stay secret — back it up offline, never commit it,
never put it on a customer machine. It only lives on whatever box mints
license keys (your own laptop or a small signing service).
"""
import base64
import os
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("ERROR: install cryptography first  ->  pip install cryptography")
    sys.exit(1)

KEYS_DIR = Path(__file__).resolve().parent / "keys"
PRIV_PATH = KEYS_DIR / "license_ed25519.priv"
PUB_PATH = KEYS_DIR / "license_ed25519.pub"


def main() -> int:
    if PRIV_PATH.exists():
        print(f"Refus: {PRIV_PATH} existe deja.")
        print("Si tu veux vraiment regenerer, supprime ce fichier d'abord")
        print("(ATTENTION: invalidera toutes les licences deja emises).")
        return 1

    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    PRIV_PATH.write_bytes(priv_bytes)
    PUB_PATH.write_bytes(pub_bytes)
    try:
        os.chmod(PRIV_PATH, 0o600)
    except OSError:
        pass

    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    print("OK. Keypair generee.")
    print(f"   priv: {PRIV_PATH}  (0600, sauvegarde-la hors-ligne)")
    print(f"   pub:  {PUB_PATH}")
    print()
    print("Colle ceci dans license_manager.py (LICENSE_PUBLIC_KEY_B64):")
    print()
    print(f'    LICENSE_PUBLIC_KEY_B64 = "{pub_b64}"')
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
